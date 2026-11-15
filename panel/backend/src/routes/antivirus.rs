//! `/api/antivirus/*` (feature 5, contract B-R).
//!
//! Admin routes name their server in the query or body (`server_id`), checked
//! against the caller the way `SITE_CALLER_PREDICATE` checks a site: an
//! administrator of the local box or of a member they registered. Owner routes
//! resolve the site (or the detection's site) through `SITE_CALLER_PREDICATE`,
//! and everything sent to the agent (domain, path, quarantine id, host) comes
//! from those rows, never from the request.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AdminUser, AuthUser, Claims};
use crate::error::{ApiError, agent_error, err, internal_error};
use crate::helpers::SITE_CALLER_PREDICATE;
use crate::services::activity;
use crate::services::agent::AgentHandle;
use crate::services::av_scanner::{self, ScheduleRow};

/// Long proxies (the install only starts a job, but `apt` locks can make the start slow).
const INSTALL_TIMEOUT_SECS: u64 = 300;
const UNINSTALL_TIMEOUT_SECS: u64 = 900;
const NOTE_MAX: usize = 500;

/// Sites the caller may see: their own, or any on a server they administer.
/// `$1` = the caller's id. Same two arms as `SITE_CALLER_PREDICATE`.
const VISIBLE_SITE: &str = "(s.user_id = $1 OR EXISTS (\
    SELECT 1 FROM users u, servers sv WHERE u.id = $1 AND u.role = 'admin' \
    AND sv.id = s.server_id AND (sv.is_local OR sv.user_id = u.id)))";

const SCAN_SELECT: &str = "SELECT sc.id, sc.server_id, sc.site_id, s.domain, sc.trigger, sc.status, \
    sc.files_scanned, sc.files_skipped, sc.files_errors, sc.infected_count, sc.progress_done, \
    sc.progress_total, sc.signatures_version, sc.error, sc.created_at, sc.started_at, sc.completed_at \
    FROM av_scans sc JOIN sites s ON s.id = sc.site_id";

const DETECTION_SELECT: &str = "SELECT d.id, d.scan_id, d.site_id, s.domain, d.file_path, d.signature, \
    d.size, d.sha256, d.status, d.quarantine_id, d.handled_by, d.handled_at, d.created_at, d.last_seen_at \
    FROM av_detections d JOIN sites s ON s.id = d.site_id";

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Scan {
    pub id: Uuid,
    pub server_id: Uuid,
    pub site_id: Uuid,
    pub domain: String,
    pub trigger: String,
    pub status: String,
    pub files_scanned: i64,
    pub files_skipped: i64,
    pub files_errors: i64,
    pub infected_count: i32,
    pub progress_done: Option<i64>,
    pub progress_total: Option<i64>,
    pub signatures_version: Option<i64>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Detection {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub site_id: Uuid,
    pub domain: String,
    pub file_path: String,
    pub signature: String,
    pub size: i64,
    pub sha256: String,
    pub status: String,
    pub quarantine_id: Option<String>,
    pub handled_by: Option<Uuid>,
    pub handled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────
// Access and transitions (pure)
// ──────────────────────────────────────────────────────────────

pub const DETECTION_STATUSES: &[&str] = &["open", "quarantined", "deleted", "ignored", "restored"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quarantine,
    Restore,
    Delete,
    Ignore,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::Quarantine => "quarantine",
            Action::Restore => "restore",
            Action::Delete => "delete",
            Action::Ignore => "ignore",
        }
    }
}

/// What an action does to a detection in `status`: the new status, or why it cannot.
pub fn transition(action: Action, status: &str) -> Result<&'static str, &'static str> {
    match (action, status) {
        (Action::Quarantine, "open" | "restored") => Ok("quarantined"),
        (Action::Restore, "quarantined") => Ok("restored"),
        (Action::Delete, "open" | "restored" | "quarantined") => Ok("deleted"),
        (Action::Ignore, "open" | "restored") => Ok("ignored"),
        (Action::Restore, _) => Err("Only a quarantined file can be restored"),
        (_, "deleted") => Err("This file was already deleted"),
        (_, "ignored") => Err("This detection is ignored"),
        (_, "quarantined") => Err("This file is already in quarantine"),
        _ => Err("This action is not possible on this detection"),
    }
}

/// `POST /scan`: without `site_id`, the whole server, which is for administrators only.
pub fn may_scan(is_admin: bool, site_id: Option<Uuid>) -> bool {
    site_id.is_some() || is_admin
}

/// Quarantine ids are uuids, or `legacy:<name>` for files quarantined before feature 5.
///
/// A legacy name is the file name the old quarantine used: any bytes but `/` and NUL
/// (spaces, non-ASCII, `..` inside a name), not `.` nor `..`, at most 255 bytes. The id
/// arrives percent-decoded by the `Path` extractor and only ever travels to the agent
/// inside a JSON body, never in a URL.
pub fn valid_quarantine_id(id: &str) -> bool {
    if let Some(name) = id.strip_prefix(LEGACY_QUARANTINE_PREFIX) {
        return !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.bytes().any(|b| b == b'/' || b == 0);
    }
    !id.is_empty()
        && id.len() <= 300
        && !id.contains("..")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
}

const LEGACY_QUARANTINE_PREFIX: &str = "legacy:";

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, 500)
}

// ──────────────────────────────────────────────────────────────
// Shared lookups
// ──────────────────────────────────────────────────────────────

/// The agent of a server the caller administers (local box, or a member they registered).
async fn admin_server(state: &AppState, claims: &Claims, server_id: Uuid) -> Result<AgentHandle, ApiError> {
    let ok: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM servers sv, users u WHERE sv.id = $1 AND u.id = $2 AND u.role = 'admin' \
         AND (sv.is_local OR sv.user_id = u.id)",
    )
    .bind(server_id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("antivirus server lookup", e))?;
    if ok.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "Server not found"));
    }
    state
        .agents
        .for_server(server_id)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Server unreachable: {e}")))
}

/// A site the caller may act on: (domain, server_id).
async fn caller_site(state: &AppState, claims: &Claims, site_id: Uuid) -> Result<(String, Uuid), ApiError> {
    let row: Option<(String, Option<Uuid>)> =
        sqlx::query_as(&format!("SELECT s.domain, s.server_id FROM sites s WHERE {SITE_CALLER_PREDICATE}"))
            .bind(site_id)
            .bind(claims.sub)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("antivirus site lookup", e))?;
    match row {
        Some((domain, Some(server_id))) => Ok((domain, server_id)),
        Some((_, None)) => Err(err(StatusCode::CONFLICT, "This site is not associated with a server")),
        None => Err(err(StatusCode::NOT_FOUND, "Site not found")),
    }
}

async fn detection_by_id(state: &AppState, id: Uuid) -> Result<Detection, ApiError> {
    sqlx::query_as::<_, Detection>(&format!("{DETECTION_SELECT} WHERE d.id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("antivirus detection", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Detection not found"))
}

#[allow(clippy::too_many_arguments)]
async fn log(
    state: &AppState,
    claims: &Claims,
    action: &str,
    target_type: Option<&str>,
    target_name: Option<&str>,
    details: Option<&str>,
    server_id: Option<Uuid>,
) {
    activity::log_activity_on_server(
        &state.db,
        claims.sub,
        &claims.email,
        action,
        target_type,
        target_name,
        details,
        None,
        server_id,
        claims.key_id,
    )
    .await;
}

// ──────────────────────────────────────────────────────────────
// Admin routes
// ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ServerQuery {
    pub server_id: Uuid,
}

#[derive(serde::Deserialize)]
pub struct ServerBody {
    pub server_id: Uuid,
}

/// GET /api/antivirus/status?server_id=
pub async fn status(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    let agent = admin_server(&state, &claims, q.server_id).await?;
    let mut v = agent.get("/antivirus/status").await.map_err(|e| agent_error("Antivirus status", e))?;
    let (installed, _) = av_scanner::status_flags(&v);
    let sched = if installed {
        av_scanner::ensure_schedule(&state.db, q.server_id).await
    } else {
        av_scanner::read_schedule(&state.db, q.server_id)
            .await
            .map(|r| r.unwrap_or_else(ScheduleRow::defaults))
    }
    .map_err(|e| internal_error("antivirus schedule", e))?;
    if let Some(o) = v.as_object_mut() {
        o.insert("schedule".into(), sched.to_json(Utc::now()));
    }
    Ok(Json(v))
}

/// POST /api/antivirus/install {server_id} -> {job_id}
pub async fn install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(b): Json<ServerBody>,
) -> Result<Json<Value>, ApiError> {
    let agent = admin_server(&state, &claims, b.server_id).await?;
    let v = agent
        .post_long("/antivirus/install", None, INSTALL_TIMEOUT_SECS)
        .await
        .map_err(|e| agent_error("ClamAV install", e))?;
    log(&state, &claims, "antivirus.install", Some("server"), None, None, Some(b.server_id)).await;
    Ok(Json(v))
}

/// GET /api/antivirus/jobs/{job_id}?server_id=
pub async fn job(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(job_id): Path<String>,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    if !av_scanner::valid_job_id(&job_id) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid job id"));
    }
    let agent = admin_server(&state, &claims, q.server_id).await?;
    let v = agent.get(&format!("/jobs/{job_id}")).await.map_err(|e| agent_error("Antivirus job", e))?;
    Ok(Json(v))
}

/// POST /api/antivirus/uninstall {server_id} -> {ok}
pub async fn uninstall(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(b): Json<ServerBody>,
) -> Result<Json<Value>, ApiError> {
    let agent = admin_server(&state, &claims, b.server_id).await?;
    agent
        .post_long("/antivirus/uninstall", None, UNINSTALL_TIMEOUT_SECS)
        .await
        .map_err(|e| agent_error("ClamAV uninstall", e))?;
    // Nothing can scan there any more: the waiting scans would only fail one by one.
    let _ = sqlx::query(
        "UPDATE av_scans SET status = 'failed', error = 'ClamAV was uninstalled', completed_at = now() \
         WHERE server_id = $1 AND status = 'queued'",
    )
    .bind(b.server_id)
    .execute(&state.db)
    .await;
    log(&state, &claims, "antivirus.uninstall", Some("server"), None, None, Some(b.server_id)).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(serde::Deserialize)]
pub struct MailBody {
    pub server_id: Uuid,
    pub enable: bool,
}

/// POST /api/antivirus/mail {server_id, enable} -> {ok, enabled}
pub async fn mail(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(b): Json<MailBody>,
) -> Result<Json<Value>, ApiError> {
    let agent = admin_server(&state, &claims, b.server_id).await?;
    let v = agent
        .post_long("/antivirus/mail", Some(json!({ "enable": b.enable })), 120)
        .await
        .map_err(|e| agent_error("Mail antivirus", e))?;
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(b.enable);
    log(
        &state,
        &claims,
        "antivirus.mail",
        Some("server"),
        None,
        Some(if enabled { "enabled" } else { "disabled" }),
        Some(b.server_id),
    )
    .await;
    Ok(Json(json!({ "ok": true, "enabled": enabled })))
}

#[derive(serde::Deserialize)]
pub struct ScheduleBody {
    pub server_id: Uuid,
    pub enabled: bool,
    pub hour: i16,
    pub interval_days: i16,
}

/// PUT /api/antivirus/schedule -> schedule
pub async fn put_schedule(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(b): Json<ScheduleBody>,
) -> Result<Json<Value>, ApiError> {
    if !(0..=23).contains(&b.hour) {
        return Err(err(StatusCode::BAD_REQUEST, "Hour must be between 0 and 23"));
    }
    if !(1..=30).contains(&b.interval_days) {
        return Err(err(StatusCode::BAD_REQUEST, "Interval must be between 1 and 30 days"));
    }
    admin_server(&state, &claims, b.server_id).await?;
    let row: ScheduleRow = sqlx::query_as(
        "INSERT INTO av_schedules (server_id, enabled, hour, interval_days, last_run_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (server_id) DO UPDATE SET enabled = EXCLUDED.enabled, hour = EXCLUDED.hour, \
         interval_days = EXCLUDED.interval_days \
         RETURNING enabled, hour, interval_days, last_run_at",
    )
    .bind(b.server_id)
    .bind(b.enabled)
    .bind(b.hour)
    .bind(b.interval_days)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("antivirus schedule", e))?;
    let details = format!(
        "{} at {:02}:00 UTC every {} day(s)",
        if b.enabled { "enabled" } else { "disabled" },
        b.hour,
        b.interval_days
    );
    log(&state, &claims, "antivirus.schedule", Some("server"), None, Some(&details), Some(b.server_id)).await;
    Ok(Json(row.to_json(Utc::now())))
}

/// GET /api/antivirus/quarantine?server_id= -> A-7 list
pub async fn quarantine_list(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    let agent = admin_server(&state, &claims, q.server_id).await?;
    let v = agent.get("/antivirus/quarantine").await.map_err(|e| agent_error("Quarantine", e))?;
    Ok(Json(v))
}

/// POST /api/antivirus/quarantine/{quarantine_id}/delete?server_id= -> {ok}
pub async fn quarantine_delete(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(quarantine_id): Path<String>,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    if !valid_quarantine_id(&quarantine_id) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid quarantine id"));
    }
    let agent = admin_server(&state, &claims, q.server_id).await?;
    agent
        .post("/antivirus/quarantine/delete", Some(json!({ "quarantine_id": quarantine_id })))
        .await
        .map_err(|e| agent_error("Quarantine delete", e))?;
    let _ = sqlx::query(
        "UPDATE av_detections d SET status = 'deleted', handled_by = $3, handled_at = now() \
         FROM sites s WHERE s.id = d.site_id AND s.server_id = $2 \
         AND d.quarantine_id = $1 AND d.status = 'quarantined'",
    )
    .bind(&quarantine_id)
    .bind(q.server_id)
    .bind(claims.sub)
    .execute(&state.db)
    .await;
    log(
        &state,
        &claims,
        "antivirus.delete",
        Some("quarantine"),
        Some(&quarantine_id),
        None,
        Some(q.server_id),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

// ──────────────────────────────────────────────────────────────
// Owner routes
// ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct SiteQuery {
    pub site_id: Uuid,
}

/// GET /api/antivirus/site-status?site_id= -> {installed, responding, last_scan, open_detections}
pub async fn site_status(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(q): Query<SiteQuery>,
) -> Result<Json<Value>, ApiError> {
    let (_domain, server_id) = caller_site(&state, &claims, q.site_id).await?;
    // An agent that cannot answer (offline, without feature 5) reads as "not installed":
    // the site page hides its antivirus controls instead of failing.
    let (installed, responding) = match state.agents.for_server(server_id).await {
        Ok(agent) => av_scanner::agent_status(&agent)
            .await
            .map(|s| av_scanner::status_flags(&s))
            .unwrap_or((false, false)),
        Err(_) => (false, false),
    };
    let last_scan: Option<Scan> =
        sqlx::query_as(&format!("{SCAN_SELECT} WHERE sc.site_id = $1 ORDER BY sc.created_at DESC LIMIT 1"))
            .bind(q.site_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("antivirus last scan", e))?;
    let (open,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM av_detections WHERE site_id = $1 AND status = 'open'")
            .bind(q.site_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| internal_error("antivirus open detections", e))?;
    Ok(Json(json!({
        "installed": installed,
        "responding": responding,
        "last_scan": last_scan,
        "open_detections": open,
    })))
}

#[derive(serde::Deserialize)]
pub struct ScanBody {
    /// Optional with a `site_id`: the site's own server is used (site owners do not pick servers).
    #[serde(default)]
    pub server_id: Option<Uuid>,
    #[serde(default)]
    pub site_id: Option<Uuid>,
}

/// POST /api/antivirus/scan {server_id, site_id?} -> {scan_ids}
pub async fn scan(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(b): Json<ScanBody>,
) -> Result<Json<Value>, ApiError> {
    if !may_scan(claims.role == "admin", b.site_id) {
        return Err(err(StatusCode::FORBIDDEN, "Admin access required"));
    }
    let (server_id, agent, sites): (Uuid, AgentHandle, Vec<(Uuid, String)>) = match b.site_id {
        Some(site_id) => {
            let (domain, server_id) = caller_site(&state, &claims, site_id).await?;
            if b.server_id.is_some_and(|s| s != server_id) {
                return Err(err(StatusCode::BAD_REQUEST, "This site is not on that server"));
            }
            let agent = crate::helpers::agent_for_site_server(&state, Some(server_id), &domain).await?;
            (server_id, agent, vec![(site_id, domain)])
        }
        None => {
            let server_id = b.server_id.ok_or_else(|| err(StatusCode::BAD_REQUEST, "server_id is required"))?;
            let agent = admin_server(&state, &claims, server_id).await?;
            let sites: Vec<(Uuid, String)> =
                sqlx::query_as("SELECT id, domain FROM sites WHERE server_id = $1 ORDER BY domain")
                    .bind(server_id)
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| internal_error("antivirus sites", e))?;
            (server_id, agent, sites)
        }
    };

    let installed = av_scanner::agent_status(&agent)
        .await
        .map(|s| av_scanner::status_flags(&s).0)
        .unwrap_or(false);
    if !installed {
        return Err(err(StatusCode::PRECONDITION_FAILED, "ClamAV is not installed on this server"));
    }

    let mut ids = Vec::with_capacity(sites.len());
    for (site_id, _) in &sites {
        let id = av_scanner::enqueue_scan(&state.db, server_id, *site_id, "manual", Some(claims.sub))
            .await
            .map_err(|e| internal_error("antivirus enqueue", e))?;
        ids.push(id);
    }
    let target = match (b.site_id, sites.first()) {
        (Some(_), Some((_, d))) => d.clone(),
        _ => format!("{} site(s)", sites.len()),
    };
    log(&state, &claims, "antivirus.scan", Some("site"), Some(&target), None, Some(server_id)).await;
    Ok(Json(json!({ "scan_ids": ids })))
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub server_id: Option<Uuid>,
    #[serde(default)]
    pub site_id: Option<Uuid>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// GET /api/antivirus/scans?server_id=&site_id=&limit=50
pub async fn scans(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Scan>>, ApiError> {
    let rows: Vec<Scan> = sqlx::query_as(&format!(
        "{SCAN_SELECT} WHERE {VISIBLE_SITE} \
         AND ($2::uuid IS NULL OR sc.server_id = $2) AND ($3::uuid IS NULL OR sc.site_id = $3) \
         ORDER BY sc.created_at DESC LIMIT $4"
    ))
    .bind(claims.sub)
    .bind(q.server_id)
    .bind(q.site_id)
    .bind(clamp_limit(q.limit))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("antivirus scans", e))?;
    Ok(Json(rows))
}

/// GET /api/antivirus/detections?server_id=&site_id=&status=
pub async fn detections(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Detection>>, ApiError> {
    let status = q.status.as_deref().map(str::trim).filter(|s| !s.is_empty() && *s != "all");
    if let Some(s) = status
        && !DETECTION_STATUSES.contains(&s)
    {
        return Err(err(StatusCode::BAD_REQUEST, "Unknown detection status"));
    }
    let rows: Vec<Detection> = sqlx::query_as(&format!(
        "{DETECTION_SELECT} WHERE {VISIBLE_SITE} \
         AND ($2::uuid IS NULL OR s.server_id = $2) AND ($3::uuid IS NULL OR d.site_id = $3) \
         AND ($4::text IS NULL OR d.status = $4) \
         ORDER BY (d.status = 'open') DESC, d.last_seen_at DESC LIMIT $5"
    ))
    .bind(claims.sub)
    .bind(q.server_id)
    .bind(q.site_id)
    .bind(status)
    .bind(q.limit.unwrap_or(1000).clamp(1, 5000))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("antivirus detections", e))?;
    Ok(Json(rows))
}

/// POST /api/antivirus/detections/{id}/quarantine
pub async fn detection_quarantine(
    state: State<AppState>,
    user: AuthUser,
    id: Path<Uuid>,
) -> Result<Json<Detection>, ApiError> {
    act(state, user, id, Action::Quarantine, None).await
}

/// POST /api/antivirus/detections/{id}/restore
pub async fn detection_restore(
    state: State<AppState>,
    user: AuthUser,
    id: Path<Uuid>,
) -> Result<Json<Detection>, ApiError> {
    act(state, user, id, Action::Restore, None).await
}

/// POST /api/antivirus/detections/{id}/delete
pub async fn detection_delete(
    state: State<AppState>,
    user: AuthUser,
    id: Path<Uuid>,
) -> Result<Json<Detection>, ApiError> {
    act(state, user, id, Action::Delete, None).await
}

/// POST /api/antivirus/detections/{id}/ignore {note?}
pub async fn detection_ignore(
    state: State<AppState>,
    user: AuthUser,
    id: Path<Uuid>,
    body: Bytes,
) -> Result<Json<Detection>, ApiError> {
    let note = if body.iter().all(|b| b.is_ascii_whitespace()) {
        None
    } else {
        let v: Value = serde_json::from_slice(&body).map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid JSON body"))?;
        v.get("note")
            .and_then(|n| n.as_str())
            .map(|n| n.trim().chars().take(NOTE_MAX).collect::<String>())
            .filter(|n| !n.is_empty())
    };
    act(state, user, id, Action::Ignore, note).await
}

async fn act(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    action: Action,
    note: Option<String>,
) -> Result<Json<Detection>, ApiError> {
    let det = detection_by_id(&state, id).await?;
    // Same answer as for a detection that does not exist: another tenant's ids are not confirmed.
    let (domain, server_id) = caller_site(&state, &claims, det.site_id)
        .await
        .map_err(|_| err(StatusCode::NOT_FOUND, "Detection not found"))?;
    let new_status = transition(action, &det.status).map_err(|m| err(StatusCode::CONFLICT, m))?;

    let mut quarantine_id = det.quarantine_id.clone();
    // Agent refusals pass through `agent_error` as they are: 409 `sha256_mismatch`
    // ("The file changed since it was scanned": the detection stays as it is and the
    // user rescans) and 413 (file too large to quarantine) keep their status and message.
    if action != Action::Ignore {
        let agent = crate::helpers::agent_for_site_server(&state, Some(server_id), &domain).await?;
        let ctx = format!("Antivirus {}", action.verb());
        match (action, det.status.as_str()) {
            (Action::Quarantine, _) => {
                let v = agent
                    .post(
                        "/antivirus/quarantine",
                        Some(json!({
                            "domain": domain,
                            "path": det.file_path,
                            "signature": det.signature,
                            "sha256": det.sha256,
                        })),
                    )
                    .await
                    .map_err(|e| agent_error(&ctx, e))?;
                let qid = v.get("quarantine_id").and_then(|q| q.as_str()).unwrap_or("").to_string();
                if !valid_quarantine_id(&qid) {
                    return Err(err(StatusCode::BAD_GATEWAY, "The agent returned an invalid quarantine id"));
                }
                quarantine_id = Some(qid);
            }
            (Action::Restore, _) | (Action::Delete, "quarantined") => {
                let qid = det
                    .quarantine_id
                    .clone()
                    .filter(|q| valid_quarantine_id(q))
                    .ok_or_else(|| err(StatusCode::CONFLICT, "This detection has no quarantine id"))?;
                let path = if action == Action::Restore { "/antivirus/restore" } else { "/antivirus/quarantine/delete" };
                agent
                    .post(path, Some(json!({ "quarantine_id": qid })))
                    .await
                    .map_err(|e| agent_error(&ctx, e))?;
            }
            (Action::Delete, _) => {
                agent
                    .post(
                        "/antivirus/delete",
                        Some(json!({ "domain": domain, "path": det.file_path, "sha256": det.sha256 })),
                    )
                    .await
                    .map_err(|e| agent_error(&ctx, e))?;
            }
            (Action::Ignore, _) => unreachable!(),
        }
    }

    if action == Action::Ignore {
        let mut tx = state.db.begin().await.map_err(|e| internal_error("antivirus ignore", e))?;
        sqlx::query(
            "INSERT INTO av_ignored (site_id, sha256, signature, note, created_by) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (site_id, sha256) DO UPDATE SET signature = EXCLUDED.signature, note = EXCLUDED.note",
        )
        .bind(det.site_id)
        .bind(&det.sha256)
        .bind(&det.signature)
        .bind(&note)
        .bind(claims.sub)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal_error("antivirus ignore", e))?;
        // The same content elsewhere on this site is the same false positive.
        sqlx::query(
            "UPDATE av_detections SET status = 'ignored', handled_by = $3, handled_at = now() \
             WHERE site_id = $1 AND sha256 = $2 AND status IN ('open', 'restored')",
        )
        .bind(det.site_id)
        .bind(&det.sha256)
        .bind(claims.sub)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal_error("antivirus ignore", e))?;
        tx.commit().await.map_err(|e| internal_error("antivirus ignore", e))?;
    } else {
        // The agent already acted: a failed or lost update must not turn into an error
        // for a file that really was moved. Guarded by the status read above, so a scan
        // that closed the row meanwhile is not overwritten; the next full scan fixes the
        // state either way (`closes_unseen`).
        let updated = sqlx::query(
            "UPDATE av_detections SET status = $2, quarantine_id = $3, handled_by = $4, handled_at = now() \
             WHERE id = $1 AND status = ANY($5)",
        )
        .bind(det.id)
        .bind(new_status)
        .bind(&quarantine_id)
        .bind(claims.sub)
        .bind(vec![det.status.clone()])
        .execute(&state.db)
        .await;
        match updated {
            Ok(r) if r.rows_affected() == 1 => {}
            Ok(_) => tracing::error!(
                detection = %det.id,
                "Antivirus {}: the agent acted but the detection changed meanwhile (was '{}'), not updated",
                action.verb(),
                det.status
            ),
            Err(e) => tracing::error!(
                detection = %det.id,
                "Antivirus {}: the agent acted but the detection could not be updated: {e}",
                action.verb()
            ),
        }
    }

    av_scanner::refresh_site_alert(&state.db, det.site_id).await;
    let details = format!("{} ({})", det.file_path, det.signature);
    log(
        &state,
        &claims,
        &format!("antivirus.{}", action.verb()),
        Some("site"),
        Some(&domain),
        Some(&details),
        Some(server_id),
    )
    .await;
    Ok(Json(detection_by_id(&state, id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_transitions() {
        assert_eq!(transition(Action::Quarantine, "open"), Ok("quarantined"));
        assert_eq!(transition(Action::Quarantine, "restored"), Ok("quarantined"));
        assert!(transition(Action::Quarantine, "quarantined").is_err());
        assert_eq!(transition(Action::Restore, "quarantined"), Ok("restored"));
        assert!(transition(Action::Restore, "open").is_err());
        assert!(transition(Action::Restore, "deleted").is_err());
        assert_eq!(transition(Action::Delete, "open"), Ok("deleted"));
        assert_eq!(transition(Action::Delete, "quarantined"), Ok("deleted"));
        assert!(transition(Action::Delete, "deleted").is_err());
        assert_eq!(transition(Action::Ignore, "open"), Ok("ignored"));
        assert!(transition(Action::Ignore, "ignored").is_err());
        assert!(transition(Action::Ignore, "quarantined").is_err());
        assert!(transition(Action::Ignore, "bogus").is_err());
    }

    #[test]
    fn only_admins_scan_a_whole_server() {
        let site = Some(Uuid::new_v4());
        assert!(may_scan(false, site));
        assert!(may_scan(true, site));
        assert!(may_scan(true, None));
        assert!(!may_scan(false, None));
    }

    #[test]
    fn quarantine_ids_are_checked() {
        assert!(valid_quarantine_id("6f9619ff-8b86-d011-b42d-00cf4fc964ff"));
        assert!(valid_quarantine_id("legacy:1731650000_shell.php"));
        assert!(!valid_quarantine_id(""));
        assert!(!valid_quarantine_id("../../etc/passwd"));
        assert!(!valid_quarantine_id("a/b"));
        assert!(!valid_quarantine_id("x..y"));
    }

    #[test]
    fn legacy_quarantine_names_are_any_file_name() {
        // Names the old quarantine really produced.
        assert!(valid_quarantine_id("legacy:..x"));
        assert!(valid_quarantine_id("legacy:a..b.php"));
        assert!(valid_quarantine_id("legacy:1731650000_my shell (1).php"));
        assert!(valid_quarantine_id("legacy:fichier-été_日本.php"));
        assert!(valid_quarantine_id("legacy:.htaccess"));
        assert!(valid_quarantine_id("legacy:a:b"));
        assert!(valid_quarantine_id(&format!("legacy:{}", "a".repeat(255))));
        // Never a path, never the directory itself.
        assert!(!valid_quarantine_id("legacy:"));
        assert!(!valid_quarantine_id("legacy:."));
        assert!(!valid_quarantine_id("legacy:.."));
        assert!(!valid_quarantine_id("legacy:../x"));
        assert!(!valid_quarantine_id("legacy:a/b"));
        assert!(!valid_quarantine_id("legacy:a\0b"));
        assert!(!valid_quarantine_id(&format!("legacy:{}", "a".repeat(256))));
        // 255 bytes, not chars: 128 two-byte chars are 256 bytes.
        assert!(!valid_quarantine_id(&format!("legacy:{}", "é".repeat(128))));
        assert!(valid_quarantine_id(&format!("legacy:{}", "é".repeat(127))));
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(clamp_limit(None), 50);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(10_000)), 500);
    }

    #[test]
    fn visible_site_predicate_has_both_arms() {
        assert!(VISIBLE_SITE.contains("s.user_id = $1"));
        assert!(VISIBLE_SITE.contains("u.role = 'admin'"));
        assert!(VISIBLE_SITE.contains("sv.is_local OR sv.user_id = u.id"));
    }
}
