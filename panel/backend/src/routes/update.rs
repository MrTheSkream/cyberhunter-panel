//! Phase 4 W4: panel self-update + snapshot + fleet admin API.
//!
//! All endpoints admin-gated. Mounted from `routes/mod.rs` under
//! `/api/update/*`, `/api/snapshots/*`, `/api/update/fleet*`.
//!
//! Feature 10: nothing here contacts GitHub or installs anything unless
//! updates are configured (`update_source`), and every release is verified
//! (`release_fetch`) before a snapshot is even taken. The GitHub token never
//! appears in a response: it is written by `PUT /api/update/source` and read
//! back only as `token_set`.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::{err, err_coded, internal_error, ApiError};
use crate::models::{FleetUpdateRun, PanelSnapshot, UpdateChannel};
use crate::services::release_fetch::{self, FetchError, GithubApi, ReleaseApi};
use crate::services::update_source::{self, Actor, SourceStatus};
use crate::services::{panel_snapshot, panel_update, telemetry_collector};
use crate::AppState;

// ── Status & state ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatusResponse {
    #[serde(flatten)]
    pub state: panel_update::UpdateState,
    pub current_version: String,
    pub available_version: Option<String>,
    pub channel: String,
    /// Verdict of the most recent snapshot restore, if one has ever run.
    ///
    /// A restore stops and restarts this process, so its outcome cannot be
    /// returned through the request that started it - the restore writes a
    /// result file and it is surfaced here. Always present after a restore,
    /// including one that aborted partway, so a failed rollback can never look
    /// like no rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_restore: Option<serde_json::Value>,
    /// Verdict of the most recent `update.sh` run, if one has ever run.
    ///
    /// Same reason as `last_restore`: a successful update kills this process, so
    /// the outcome cannot come back through the request that started it. It is
    /// also the ONLY channel for an update that failed *before* the api was
    /// stopped - nothing restarts, so nothing else ever reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_panel_update: Option<serde_json::Value>,
    // ── Feature 10 additions (only additions: panel/mcp reads this) ──
    pub configured: bool,
    pub not_configured_reason: Option<&'static str>,
    pub repo: Option<String>,
    pub token_set: bool,
    pub available_prerelease: bool,
    pub release_notes: Option<String>,
    pub release_url: Option<String>,
    pub checked_at: Option<String>,
    pub last_check_error: Option<String>,
}

/// The stored advertisement, as `GET /api/update/status` reports it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub available_version: Option<String>,
    pub prerelease: bool,
    pub release_notes: Option<String>,
    pub release_url: Option<String>,
}

/// Pure: nothing is advertised while updates are not configured, whatever the
/// database holds, and a version is advertised only while it is newer than
/// the running one.
pub fn advertisement_view(
    configured: bool,
    settings: &HashMap<String, String>,
    current: &str,
) -> Advertisement {
    if !configured {
        return Advertisement::default();
    }
    let available_version = settings
        .get("update_available_version")
        .filter(|v| telemetry_collector::is_newer_release(v, current))
        .cloned();
    if available_version.is_none() {
        return Advertisement::default();
    }
    let non_empty = |k: &str| settings.get(k).filter(|v| !v.is_empty()).cloned();
    Advertisement {
        available_version,
        prerelease: settings.get("update_available_prerelease").map(String::as_str) == Some("true"),
        release_notes: non_empty("update_release_notes"),
        release_url: non_empty("update_release_url"),
    }
}

async fn read_settings(
    state: &AppState,
    keys: &[&str],
) -> Result<HashMap<String, String>, sqlx::Error> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM settings WHERE key = ANY($1)")
            .bind(keys)
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().collect())
}

pub async fn get_status(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<StatusResponse>, ApiError> {
    let s = panel_update::current_state(&state.panel_update_state, &state.db).await;
    let settings = read_settings(
        &state,
        &[
            "update_available_version",
            "update_release_notes",
            "update_release_url",
            "update_available_prerelease",
            "update_checked_at",
            "update_check_error",
            "update_channel",
        ],
    )
    .await
    .map_err(|e| internal_error("update status", e))?;
    let source = update_source::load();
    Ok(Json(build_status(
        s,
        &source,
        &settings,
        panel_snapshot::last_restore_result().await,
        panel_update::last_panel_update_result().await,
    )))
}

pub fn build_status(
    state: panel_update::UpdateState,
    source: &SourceStatus,
    settings: &HashMap<String, String>,
    last_restore: Option<serde_json::Value>,
    last_panel_update: Option<serde_json::Value>,
) -> StatusResponse {
    let current = env!("CARGO_PKG_VERSION");
    let ad = advertisement_view(source.configured, settings, current);
    StatusResponse {
        state,
        current_version: current.to_string(),
        available_version: ad.available_version,
        channel: settings
            .get("update_channel")
            .cloned()
            .unwrap_or_else(|| "stable".into()),
        last_restore,
        last_panel_update,
        configured: source.configured,
        not_configured_reason: source.reason,
        repo: source.repo.clone(),
        token_set: source.token_set,
        available_prerelease: ad.prerelease,
        release_notes: ad.release_notes,
        release_url: ad.release_url,
        checked_at: settings.get("update_checked_at").cloned(),
        last_check_error: settings
            .get("update_check_error")
            .filter(|v| !v.is_empty())
            .cloned(),
    }
}

// ── Update source ────────────────────────────────────────────────────────

/// `PUT /api/update/source`. `Deserialize` only: this body holds the token and
/// must never be printed.
#[derive(Deserialize)]
pub struct SourceInput {
    pub token: String,
    #[serde(default)]
    pub repo: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct SourceResponse {
    pub configured: bool,
    pub not_configured_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub token_set: bool,
}

impl SourceResponse {
    fn from_status(s: &SourceStatus, with_repo: bool) -> Self {
        SourceResponse {
            configured: s.configured,
            not_configured_reason: s.reason,
            repo: if with_repo { s.repo.clone() } else { None },
            token_set: s.token_set,
        }
    }
}

const TOKEN_FORMAT_MSG: &str =
    "Token format is not valid (expected a fine-grained token starting with github_pat_)";
const REPO_FORMAT_MSG: &str = "Repository must look like owner/name";

/// Format checks of `PUT /api/update/source`, in contract order. Pure.
pub fn validate_source_input(token: &str, repo: &str) -> Result<(), ApiError> {
    if !update_source::validate_token(token.trim()) {
        return Err(err_coded(StatusCode::BAD_REQUEST, TOKEN_FORMAT_MSG, "token_format"));
    }
    if !update_source::validate_repo(repo) {
        return Err(err_coded(StatusCode::BAD_REQUEST, REPO_FORMAT_MSG, "repo_format"));
    }
    Ok(())
}

/// The error of the live token test: the two "your input is wrong" cases are
/// 400 here (409 elsewhere), the rest keep their own status.
pub fn source_test_error(e: &FetchError) -> ApiError {
    match e {
        FetchError::TokenInvalid | FetchError::RepoUnreadable => {
            err_coded(StatusCode::BAD_REQUEST, e.message(), e.code())
        }
        _ => e.api_error(),
    }
}

pub async fn put_source(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<SourceInput>,
) -> Result<Json<SourceResponse>, ApiError> {
    let repo = body
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .unwrap_or_else(update_source::current_or_default_repo);
    validate_source_input(&body.token, &repo)?;

    // A real request with this token before anything is written: a token that
    // cannot read the repository is refused, and nothing changes on disk.
    let api = GithubApi::with_token(&body.token).map_err(|e| e.api_error())?;
    if let Err(e) = api.list_releases(&repo, 1).await {
        e.log("Update source test");
        return Err(source_test_error(&e));
    }

    let (repo_w, token_w) = (repo.clone(), body.token.trim().to_string());
    tokio::task::spawn_blocking(move || update_source::write_source(&repo_w, &token_w))
        .await
        .map_err(|e| internal_error("save update source", e))?
        .map_err(|e| internal_error("save update source", e.kind()))?;
    telemetry_collector::delete_setting(&state.db, "update_check_error").await;

    let actor = Actor::from_claims(&claims, &headers);
    update_source::audit(&state.db, &actor, "update.source_set", None, source_set_details(&repo)).await;

    Ok(Json(SourceResponse::from_status(&update_source::load(), true)))
}

/// `details` of `update.source_set`.
pub fn source_set_details(repo: &str) -> serde_json::Value {
    serde_json::json!({ "repo": repo })
}

pub async fn delete_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
) -> Result<Json<SourceResponse>, ApiError> {
    tokio::task::spawn_blocking(update_source::clear_token)
        .await
        .map_err(|e| internal_error("clear update token", e))?
        .map_err(|e| internal_error("clear update token", e.kind()))?;
    telemetry_collector::clear_update_advertisement(&state.db).await;
    let actor = Actor::from_claims(&claims, &headers);
    update_source::audit(&state.db, &actor, "update.token_cleared", None, serde_json::json!({})).await;
    Ok(Json(SourceResponse::from_status(&update_source::load(), false)))
}

// ── Apply update ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ApplyInput {
    pub target_version: String,
}

#[derive(Serialize)]
pub struct ApplyResponse {
    pub accepted: bool,
    pub state: panel_update::UpdateState,
}

/// Why an apply target is refused, or `None` when it is a genuine upgrade.
///
/// Split out of the handler so the rules are unit-testable without a database.
/// The direction rule is the one the comment above [`apply_update`] always
/// claimed and never enforced: matching the advertised row is not enough,
/// because the row can name a release OLDER than the running panel - the
/// operator upgraded by hand and the advertisement had not been reconciled yet.
/// `update.sh` installs whatever tag it is handed, in either direction, so
/// applying such a row silently regressed the panel by several releases.
fn reject_apply_target(target_clean: &str, advertised: &str, current: &str) -> Option<String> {
    if advertised.is_empty() {
        return Some(
            "no update is currently available - run /api/update/manual-check first".to_string(),
        );
    }
    if advertised.trim_start_matches('v') != target_clean {
        return Some(
            "target_version does not match the advertised update - refresh and retry".to_string(),
        );
    }
    if !telemetry_collector::is_newer_release(target_clean, current) {
        return Some(format!(
            "refusing to apply v{target_clean}: this panel already runs v{current}, and this \
             endpoint only moves forward. To go back to an earlier release, restore a snapshot \
             via /api/update/rollback."
        ));
    }
    None
}

fn not_configured() -> ApiError {
    FetchError::NotConfigured.api_error()
}

/// The synchronous checks of `POST /api/update/apply`, steps 1 and 2, in
/// contract order. Pure. "Not configured" comes before anything else.
pub fn apply_precheck(
    configured: bool,
    target_version: &str,
    advertised: &str,
    current: &str,
) -> Result<(), ApiError> {
    if !configured {
        return Err(not_configured());
    }
    let target = target_version.trim();
    if !panel_update::validate_target_version(target) {
        let e = panel_update::OrchestratorError::InvalidTargetVersion(target.to_string());
        return Err(err(StatusCode::BAD_REQUEST, &e.to_string()));
    }
    if let Some(reason) = reject_apply_target(target.trim_start_matches('v'), advertised, current) {
        return Err(err(StatusCode::BAD_REQUEST, &reason));
    }
    Ok(())
}

fn orchestrator_error(context: &str, e: panel_update::OrchestratorError) -> ApiError {
    match e {
        panel_update::OrchestratorError::InvalidTargetVersion(_) => {
            err(StatusCode::BAD_REQUEST, &e.to_string())
        }
        panel_update::OrchestratorError::AlreadyInFlight => {
            err_coded(StatusCode::CONFLICT, &e.to_string(), "update_in_flight")
        }
        panel_update::OrchestratorError::ScriptMissing(_) => {
            err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
        panel_update::OrchestratorError::Snapshot(_)
        | panel_update::OrchestratorError::Spawn(_)
        | panel_update::OrchestratorError::Db(_) => internal_error(context, e),
    }
}

async fn advertised_version(state: &AppState, context: &str) -> Result<String, ApiError> {
    let advertised: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM settings WHERE key = 'update_available_version'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error(context, e))?;
    Ok(advertised.map(|r| r.0).unwrap_or_default())
}

pub async fn apply_update(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<ApplyInput>,
) -> Result<(StatusCode, Json<ApplyResponse>), ApiError> {
    // 1. Not configured: refused before anything else, with no request.
    if !update_source::load().configured {
        return Err(not_configured());
    }
    // 2. Operator can only apply versions the poller has surfaced, and only
    // ones ahead of what is installed. Prevents arbitrary tag jumps +
    // downgrades through this surface (downgrade = rollback to a snapshot,
    // separate route).
    let advertised = advertised_version(&state, "apply update").await?;
    apply_precheck(true, &body.target_version, &advertised, env!("CARGO_PKG_VERSION"))?;

    // 3. Reservation, then the slow part (fetch, verify, snapshot, update.sh)
    // in the background: the vhost cuts /api at 300 s.
    let new_state = panel_update::start_panel_update(
        state.panel_update_state.clone(),
        state.db.clone(),
        body.target_version.clone(),
        Some(claims.email.clone()),
        Actor::from_claims(&claims, &headers),
    )
    .await
    .map_err(|e| orchestrator_error("apply update", e))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ApplyResponse {
            accepted: true,
            state: new_state,
        }),
    ))
}

// ── Manual poll ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ManualCheckResponse {
    pub checked_at: String,
    pub available_version: Option<String>,
    pub prerelease: bool,
}

pub async fn manual_check(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
) -> Result<Json<ManualCheckResponse>, ApiError> {
    if !update_source::load().configured {
        return Err(not_configured());
    }
    let actor = Actor::from_claims(&claims, &headers);
    let outcome = telemetry_collector::check_now(&state.db, &actor)
        .await
        .map_err(|e| e.api_error())?;
    Ok(Json(ManualCheckResponse {
        checked_at: outcome.checked_at,
        available_version: outcome.available_version,
        prerelease: outcome.prerelease,
    }))
}

// ── Rollback ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RollbackInput {
    pub snapshot_id: Uuid,
}

#[derive(Serialize)]
pub struct RollbackResponse {
    pub accepted: bool,
    pub snapshot_id: Uuid,
}

/// Not subject to the update configuration: restoring a snapshot needs no
/// release and no token.
pub async fn rollback(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<RollbackInput>,
) -> Result<(StatusCode, Json<RollbackResponse>), ApiError> {
    let snap: Option<PanelSnapshot> = sqlx::query_as("SELECT * FROM panel_snapshots WHERE id = $1")
        .bind(body.snapshot_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("rollback", e))?;
    panel_update::rollback_to_snapshot(state.panel_update_state.clone(), state.db.clone(), body.snapshot_id)
        .await
        .map_err(|e| match e {
            panel_update::OrchestratorError::Snapshot(
                panel_snapshot::SnapshotError::NotFound(_),
            ) => err(StatusCode::NOT_FOUND, &e.to_string()),
            panel_update::OrchestratorError::Snapshot(
                panel_snapshot::SnapshotError::FileMissing(_),
            ) => err(StatusCode::GONE, &e.to_string()),
            _ => internal_error("rollback", e),
        })?;
    let actor = Actor::from_claims(&claims, &headers);
    update_source::audit(
        &state.db,
        &actor,
        "update.rollback_started",
        None,
        serde_json::json!({
            "snapshot_id": body.snapshot_id,
            "from_version": env!("CARGO_PKG_VERSION"),
            "to_version": snap.map(|s| s.from_version),
        }),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(RollbackResponse {
            accepted: true,
            snapshot_id: body.snapshot_id,
        }),
    ))
}

// ── Channel ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ChannelResponse {
    pub channel: String,
}

pub async fn get_channel(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<ChannelResponse>, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'update_channel'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("get channel", e))?;
    Ok(Json(ChannelResponse {
        channel: row.map(|r| r.0).unwrap_or_else(|| "stable".into()),
    }))
}

#[derive(Deserialize)]
pub struct ChannelInput {
    pub channel: String,
}

pub async fn put_channel(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Json(body): Json<ChannelInput>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let channel = body.channel.trim().to_string();
    UpdateChannel::validate(&channel).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('update_channel', $1) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(&channel)
    .execute(&state.db)
    .await
    .map_err(|e| internal_error("put channel", e))?;
    Ok(Json(ChannelResponse { channel }))
}

// ── Snapshots ────────────────────────────────────────────────────────────

pub async fn list_snapshots_route(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<Vec<PanelSnapshot>>, ApiError> {
    let rows = panel_snapshot::list_snapshots(&state.db)
        .await
        .map_err(|e| internal_error("list snapshots", e))?;
    Ok(Json(rows))
}

pub async fn delete_snapshot_route(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    panel_snapshot::delete_snapshot(&state.db, id)
        .await
        .map_err(|e| match e {
            panel_snapshot::SnapshotError::NotFound(_) => {
                err(StatusCode::NOT_FOUND, &e.to_string())
            }
            _ => internal_error("delete snapshot", e),
        })?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize, Default)]
pub struct CreateSnapshotInput {
    /// Optional human label appended to the `trigger` field.
    #[serde(default)]
    pub label: Option<String>,
}

pub async fn create_snapshot_route(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    body: Option<Json<CreateSnapshotInput>>,
) -> Result<(StatusCode, Json<PanelSnapshot>), ApiError> {
    let _label = body.as_ref().and_then(|b| b.label.clone());
    let meta = panel_snapshot::create_snapshot(
        &state.db,
        panel_snapshot::SnapshotTrigger::Manual,
        Some(claims.email.clone()),
    )
    .await
    .map_err(|e| internal_error("create snapshot", e))?;
    let row: PanelSnapshot =
        sqlx::query_as("SELECT * FROM panel_snapshots WHERE id = $1")
            .bind(meta.id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| internal_error("create snapshot read", e))?;
    Ok((StatusCode::CREATED, Json(row)))
}

// ── Fleet update ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FleetApplyInput {
    pub target_version: String,
    #[serde(default = "default_true")]
    pub halt_on_failure: bool,
    #[serde(default)]
    pub include_panel: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct FleetApplyResponse {
    pub run_id: Uuid,
    pub plan_size: usize,
}

/// The fleet target rule. Agents move to this panel's own version; with
/// `include_panel`, to the advertised update instead, and only when applying
/// it to the panel would pass `reject_apply_target`. Pure.
///
/// With `include_panel`, the panel's own version is refused too: the panel
/// step would reinstall the release it already runs.
pub fn fleet_target_ok(target: &str, include_panel: bool, advertised: &str, current: &str) -> bool {
    let target = target.trim().trim_start_matches('v');
    if include_panel {
        reject_apply_target(target, advertised, current).is_none()
    } else {
        target == current.trim_start_matches('v')
    }
}

fn fleet_target_error(current: &str) -> ApiError {
    err_coded(
        StatusCode::BAD_REQUEST,
        &format!(
            "Fleet target must be this panel's version (v{current}) or, with include_panel, \
             the advertised update"
        ),
        "fleet_target",
    )
}

pub async fn apply_fleet(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<FleetApplyInput>,
) -> Result<(StatusCode, Json<FleetApplyResponse>), ApiError> {
    // 1. Not configured: refused first, with no request.
    if !update_source::load().configured {
        return Err(not_configured());
    }
    // 2. Shape.
    if !panel_update::validate_target_version(&body.target_version) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid target_version (must be vX.Y.Z[-rc.N])",
        ));
    }
    // 3. Agents only ever move to this panel's version, or with the panel to
    // the advertised update - never to an arbitrary tag. The include_panel
    // half also keeps `apply_update`'s direction guard (v2.216.0 audit fix:
    // this path once could downgrade the panel to any valid version).
    let current = env!("CARGO_PKG_VERSION");
    let advertised = advertised_version(&state, "fleet apply (target check)").await?;
    if !fleet_target_ok(&body.target_version, body.include_panel, &advertised, current) {
        return Err(fleet_target_error(current));
    }

    // 4. The agent binaries, fetched and verified now, so a bad release fails
    // this request instead of every server of the plan.
    let tag = release_fetch::release_tag(&body.target_version);
    match tokio::time::timeout(
        release_fetch::FLEET_PREPARE_TIMEOUT,
        release_fetch::prepare_agents(&tag),
    )
    .await
    {
        Ok(Ok(_)) => release_fetch::cleanup_cache(&state.db, false).await,
        Ok(Err(e)) => {
            e.log(&format!("Fleet update to {tag}"));
            return Err(e.api_error());
        }
        Err(_) => {
            let e = FetchError::DownloadFailed("agent release preparation timed out".into());
            e.log(&format!("Fleet update to {tag}"));
            return Err(e.api_error());
        }
    }

    // 5. The plan.
    let plan = panel_update::build_fleet_plan(&state.db, claims.sub, claims.role == "admin", &body.target_version)
        .await
        .map_err(|e| internal_error("fleet plan", e))?;
    if plan.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "no reachable servers needing update - fleet plan is empty",
        ));
    }

    let plan_size = plan.len();
    let run_id = panel_update::create_fleet_run(
        &state.db,
        &body.target_version,
        &plan,
        body.halt_on_failure,
        body.include_panel,
        Some(claims.sub),
    )
    .await
    .map_err(|e| internal_error("fleet create run", e))?;

    let actor = Actor::from_claims(&claims, &headers);
    update_source::audit(
        &state.db,
        &actor,
        "update.fleet_started",
        Some(&tag),
        serde_json::json!({
            "target_version": tag,
            "plan_size": plan_size,
            "include_panel": body.include_panel,
        }),
    )
    .await;

    let pool = state.db.clone();
    let agents = state.agents.clone();
    let target = body.target_version.clone();
    let halt = body.halt_on_failure;
    // Passing the handle is what makes the operator's "include this panel"
    // checkbox do anything - it was persisted and read by nobody until s232.
    let panel_handle = body
        .include_panel
        .then(|| state.panel_update_state.clone());
    tokio::spawn(async move {
        panel_update::execute_fleet_plan(pool, agents, run_id, plan, target, halt, panel_handle, actor)
            .await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(FleetApplyResponse { run_id, plan_size }),
    ))
}

pub async fn get_fleet_run(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FleetUpdateRun>, ApiError> {
    let row: Option<FleetUpdateRun> =
        sqlx::query_as("SELECT * FROM fleet_update_runs WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("fleet run", e))?;
    row.map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "fleet run not found"))
}

pub async fn list_fleet_runs(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Query(_q): Query<HashMap<String, String>>,
) -> Result<Json<Vec<FleetUpdateRun>>, ApiError> {
    let rows: Vec<FleetUpdateRun> = sqlx::query_as(
        "SELECT * FROM fleet_update_runs ORDER BY started_at DESC LIMIT 100",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list fleet runs", e))?;
    Ok(Json(rows))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_input_default_true_helper() {
        assert!(default_true());
    }

    #[test]
    fn channel_validate_through_route_input() {
        // The PUT route uses UpdateChannel::validate; verify it rejects the
        // garbage values a route handler would surface as 400.
        assert!(UpdateChannel::validate("nightly").is_err());
        assert!(UpdateChannel::validate("STABLE").is_err());
        assert!(UpdateChannel::validate("stable").is_ok());
    }

    #[test]
    fn fleet_input_serde_defaults() {
        // halt_on_failure defaults to true, include_panel to false.
        let body: FleetApplyInput =
            serde_json::from_str(r#"{"target_version":"v2.10.0"}"#).unwrap();
        assert!(body.halt_on_failure);
        assert!(!body.include_panel);
    }

    #[test]
    fn apply_refuses_a_target_no_newer_than_the_running_panel() {
        // #98's state: the panel runs 2.52.0, the settings row still advertises
        // 2.49.0, and the UI offers a button to apply it. Matching the row was
        // the only guard, so the apply went through and reinstalled a panel
        // three releases behind.
        let reason = reject_apply_target("2.49.0", "2.49.0", "2.52.0")
            .expect("a lower target must be refused");
        assert!(reason.contains("2.49.0") && reason.contains("2.52.0"));
        assert!(reason.contains("rollback"), "refusal must name the way back");

        // Reinstalling the running version is not an update either.
        assert!(reject_apply_target("2.52.0", "2.52.0", "2.52.0").is_some());
        // ...nor is an rc of the release already installed.
        assert!(reject_apply_target("2.52.0-rc.1", "2.52.0-rc.1", "2.52.0").is_some());
    }

    #[test]
    fn apply_accepts_the_advertised_upgrade_and_nothing_else() {
        assert!(reject_apply_target("2.53.0", "2.53.0", "2.52.0").is_none());
        // Unadvertised tag jump, advertised-but-different tag, no advertisement.
        assert!(reject_apply_target("2.99.0", "2.53.0", "2.52.0").is_some());
        assert!(reject_apply_target("2.53.0", "", "2.52.0").is_some());
    }

    #[test]
    fn fleet_input_serde_overrides() {
        let body: FleetApplyInput = serde_json::from_str(
            r#"{"target_version":"v2.10.0","halt_on_failure":false,"include_panel":true}"#,
        )
        .unwrap();
        assert!(!body.halt_on_failure);
        assert!(body.include_panel);
    }

    // ── Feature 10 ──

    use crate::services::update_source::tests::{temp_dir, KNOWN_TOKEN};

    fn code_of(e: &ApiError) -> (u16, String, String) {
        (
            e.0.as_u16(),
            e.1 .0["code"].as_str().unwrap_or("").to_string(),
            e.1 .0["error"].as_str().unwrap_or("").to_string(),
        )
    }

    #[test]
    fn apply_without_configuration_is_refused_before_anything_else() {
        // Even with a garbage target and nothing advertised, "not configured"
        // is the answer: it comes first.
        let e = apply_precheck(false, "garbage", "", "3.0.0-rc.1").unwrap_err();
        assert_eq!(
            code_of(&e),
            (409, "updates_not_configured".into(), "Updates are not configured".into())
        );
        let e = apply_precheck(false, "v3.0.0-rc.2", "3.0.0-rc.2", "3.0.0-rc.1").unwrap_err();
        assert_eq!(code_of(&e).1, "updates_not_configured");
    }

    #[test]
    fn apply_checks_shape_then_direction_once_configured() {
        let e = apply_precheck(true, "latest", "3.0.0-rc.2", "3.0.0-rc.1").unwrap_err();
        assert_eq!(e.0.as_u16(), 400);
        assert!(code_of(&e).2.contains("invalid target version"));
        let e = apply_precheck(true, "v3.0.0-rc.3", "3.0.0-rc.2", "3.0.0-rc.1").unwrap_err();
        assert_eq!(e.0.as_u16(), 400);
        assert!(apply_precheck(true, "v3.0.0-rc.2", "3.0.0-rc.2", "3.0.0-rc.1").is_ok());
    }

    #[test]
    fn the_in_flight_refusal_is_coded() {
        let e = orchestrator_error("t", panel_update::OrchestratorError::AlreadyInFlight);
        let (status, code, msg) = code_of(&e);
        assert_eq!((status, code.as_str()), (409, "update_in_flight"));
        assert_eq!(msg, panel_update::OrchestratorError::AlreadyInFlight.to_string());
    }

    #[test]
    fn the_fleet_target_rule() {
        let cur = "3.0.0-rc.1";
        assert!(fleet_target_ok("v3.0.0-rc.1", false, "", cur));
        assert!(fleet_target_ok("3.0.0-rc.1", false, "3.0.0-rc.2", cur));
        assert!(!fleet_target_ok("v3.0.0-rc.2", false, "3.0.0-rc.2", cur), "advertised needs include_panel");
        assert!(fleet_target_ok("v3.0.0-rc.2", true, "3.0.0-rc.2", cur));
        assert!(!fleet_target_ok("v3.0.0-rc.3", true, "3.0.0-rc.2", cur), "not the advertised one");
        assert!(!fleet_target_ok("v3.0.0-rc.1", true, "3.0.0-rc.1", cur), "the panel would not move");
        assert!(!fleet_target_ok("v9.0.0", false, "", cur));
        let (status, code, msg) = code_of(&fleet_target_error(cur));
        assert_eq!((status, code.as_str()), (400, "fleet_target"));
        assert_eq!(
            msg,
            "Fleet target must be this panel's version (v3.0.0-rc.1) or, with include_panel, the advertised update"
        );
    }

    #[test]
    fn source_input_formats_are_checked_in_order() {
        let e = validate_source_input("ghp_classic", "not a repo").unwrap_err();
        assert_eq!(
            code_of(&e),
            (
                400,
                "token_format".into(),
                "Token format is not valid (expected a fine-grained token starting with github_pat_)".into()
            )
        );
        let e = validate_source_input(KNOWN_TOKEN, "not a repo").unwrap_err();
        assert_eq!(code_of(&e), (400, "repo_format".into(), "Repository must look like owner/name".into()));
        assert!(validate_source_input(KNOWN_TOKEN, "MrTheSkream/cyberhunter-panel").is_ok());
    }

    #[test]
    fn the_token_test_maps_input_errors_to_400() {
        assert_eq!(code_of(&source_test_error(&FetchError::TokenInvalid)).0, 400);
        assert_eq!(code_of(&source_test_error(&FetchError::RepoUnreadable)).0, 400);
        let (s, c, _) = code_of(&source_test_error(&FetchError::DownloadFailed("h".into())));
        assert_eq!((s, c.as_str()), (502, "download_failed"));
        assert_eq!(code_of(&source_test_error(&FetchError::RateLimited)).0, 503);
    }

    fn settings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn nothing_is_advertised_without_a_configuration() {
        let s = settings(&[
            ("update_available_version", "99.0.0"),
            ("update_release_notes", "notes"),
            ("update_release_url", "https://github.com/o/n/releases/tag/v99.0.0"),
            ("update_available_prerelease", "true"),
        ]);
        assert_eq!(advertisement_view(false, &s, "3.0.0-rc.1"), Advertisement::default());
        let a = advertisement_view(true, &s, "3.0.0-rc.1");
        assert_eq!(a.available_version.as_deref(), Some("99.0.0"));
        assert!(a.prerelease);
        // A stored version that is not newer is no advertisement at all.
        let old = settings(&[("update_available_version", "2.0.0"), ("update_release_notes", "n")]);
        assert_eq!(advertisement_view(true, &old, "3.0.0-rc.1"), Advertisement::default());
    }

    #[test]
    fn status_and_source_responses_never_hold_the_token() {
        let dir = temp_dir();
        let conf = dir.join("update.conf");
        update_source::write_source_at(&conf, "owner/name", KNOWN_TOKEN).unwrap();
        let source = update_source::load_from(&conf);
        assert!(source.configured);

        let status = build_status(
            panel_update::UpdateState::Idle,
            &source,
            &settings(&[("update_checked_at", "t")]),
            None,
            None,
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["configured"], true);
        assert_eq!(json["token_set"], true);
        assert_eq!(json["repo"], "owner/name");
        assert!(json.get("signing_key_id").is_none(), "no signing key any more");
        assert!(json["not_configured_reason"].is_null());
        assert_eq!(json["state"], "idle", "existing fields kept");
        assert!(json.get("current_version").is_some());

        let put = SourceResponse::from_status(&source, true);
        let del = SourceResponse::from_status(&source, false);
        for text in [
            json.to_string(),
            serde_json::to_string(&put).unwrap(),
            serde_json::to_string(&del).unwrap(),
            format!("{put:?}"),
            source_set_details("owner/name").to_string(),
        ] {
            assert!(!text.contains(KNOWN_TOKEN), "{text}");
            assert!(!text.contains("github_pat_"), "{text}");
        }
        assert!(serde_json::to_value(&del).unwrap().get("repo").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_not_configured_status_reports_its_reason_and_nothing_else() {
        let source =
            update_source::evaluate(Err(update_source::ConfError::Invalid("x")), false);
        let status = build_status(
            panel_update::UpdateState::Idle,
            &source,
            &settings(&[("update_available_version", "99.0.0"), ("update_release_url", "u")]),
            None,
            None,
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["configured"], false);
        assert_eq!(json["not_configured_reason"], "no_source");
        assert!(json["available_version"].is_null());
        assert!(json["release_url"].is_null());
        assert!(json["release_notes"].is_null());
        assert_eq!(json["available_prerelease"], false);
    }
}
