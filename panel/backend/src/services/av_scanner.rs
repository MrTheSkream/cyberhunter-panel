//! ClamAV scans of site files (feature 5, contract B-S).
//!
//! One supervised task, three clocks:
//! - every few seconds, the **queue**: per server, one `queued` scan at a time is
//!   started on the agent (`POST /antivirus/scan`, A-5) and its job polled
//!   (`GET /jobs/{id}`, A-6) without blocking the other servers. A 409 (a scan is
//!   already running there) or a 412 (clamd reloading its signatures) puts the
//!   scan back in the queue for a later try.
//! - every minute, **health**: `GET /antivirus/status` per online server; alerts
//!   `av_down` (clamd installed but silent for 10 minutes: mail goes unscanned)
//!   and `av_signatures` (signatures older than 3 days).
//! - every 5 minutes, the **schedule** (`av_schedules`), and every hour the
//!   90-day retention.
//!
//! Scan results become `av_detections`: one open row per (site, path, sha256),
//! files whose sha256 the site ignores create nothing. After each scan the
//! site's `malware` alert is fired or resolved.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::{AgentError, AgentHandle, AgentRegistry};
use crate::services::import_types::{JobPoll, StallClock, classify_job};
use crate::services::notifications;

const TICK: Duration = Duration::from_secs(3);
const HEALTH_EVERY: Duration = Duration::from_secs(60);
const PLAN_EVERY: Duration = Duration::from_secs(5 * 60);
const RETENTION_EVERY: Duration = Duration::from_secs(60 * 60);
const STARTUP_DELAY: Duration = Duration::from_secs(20);
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
/// A scan job that does not move (files done, phase, heartbeat) for this long is failed.
const JOB_STALL: Duration = Duration::from_secs(15 * 60);
/// Delay before a scan the agent could not start yet is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// After a 409 (a scan already runs on the agent), the whole server waits this long:
/// otherwise every tick would claim and bounce the next queued scan of that server.
const BUSY_BACKOFF: Duration = Duration::from_secs(30);
/// Tries for a refusal that should be temporary (412: clamd not responding,
/// transport error). A 409 (another scan running) is retried without limit.
const MAX_TEMPORARY_TRIES: u32 = 15;
const AV_DOWN_AFTER: Duration = Duration::from_secs(10 * 60);
const SIGNATURES_MAX_AGE_DAYS: i64 = 3;
pub const RETENTION_DAYS: i64 = 90;

pub const ALERT_MALWARE: &str = "malware";
pub const ALERT_SIGNATURES: &str = "av_signatures";
pub const ALERT_DOWN: &str = "av_down";

// ──────────────────────────────────────────────────────────────
// Schedule (pure)
// ──────────────────────────────────────────────────────────────

/// Today's slot: today at `hour`:00 UTC (the agent exposes no time zone, the UI says "UTC").
pub fn slot_of_day(now: DateTime<Utc>, hour: i16) -> DateTime<Utc> {
    let h = hour.clamp(0, 23) as u32;
    let d = now.date_naive();
    Utc.from_utc_datetime(&d.and_hms_opt(h, 0, 0).expect("valid hour"))
}

/// Whether the scheduled run of `slot` is still owed, given the last scheduled run.
///
/// A run counts for this slot when it happened after `slot - (interval_days - 1) days - 1 h`:
/// with a daily schedule at 03:00, a run at 02:10 (hour changed) or 03:04 counts for that
/// night; a run delayed to 15:00 still lets the next one happen at 03:00 the next night
/// instead of drifting to 15:00.
fn slot_owed(slot: DateTime<Utc>, interval_days: i16, last_run_at: Option<DateTime<Utc>>) -> bool {
    let interval = interval_days.clamp(1, 30) as i64;
    match last_run_at {
        None => true,
        Some(last) => last < slot - ChronoDuration::days(interval - 1) - ChronoDuration::hours(1),
    }
}

/// B-S: the current hour is at or past `hour` and the last scheduled run is older than
/// the interval (within an hour).
pub fn is_due(now: DateTime<Utc>, hour: i16, interval_days: i16, last_run_at: Option<DateTime<Utc>>) -> bool {
    let slot = slot_of_day(now, hour);
    now >= slot && slot_owed(slot, interval_days, last_run_at)
}

/// When the next scheduled scan should start (`now` when it is already due).
pub fn next_run_at(
    now: DateTime<Utc>,
    enabled: bool,
    hour: i16,
    interval_days: i16,
    last_run_at: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    if !enabled {
        return None;
    }
    if is_due(now, hour, interval_days, last_run_at) {
        return Some(now);
    }
    let today = slot_of_day(now, hour);
    (0..=31)
        .map(|k| today + ChronoDuration::days(k))
        .find(|slot| *slot > now && slot_owed(*slot, interval_days, last_run_at))
}

// ──────────────────────────────────────────────────────────────
// Report -> detections (pure)
// ──────────────────────────────────────────────────────────────

/// One infected file of the agent's report, as it will be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionInput {
    pub file_path: String,
    pub signature: String,
    pub size: i64,
    pub sha256: String,
}

/// The counters of an A-5 report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanReport {
    pub files_scanned: i64,
    pub files_skipped: i64,
    pub files_errors: i64,
    pub signatures_version: Option<i64>,
    pub truncated: bool,
}

pub fn parse_report(report: &Value) -> ScanReport {
    let n = |k: &str| report.get(k).and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    ScanReport {
        files_scanned: n("files_scanned"),
        files_skipped: n("files_skipped"),
        files_errors: n("files_errors"),
        signatures_version: report.get("signatures_version").and_then(|v| v.as_i64()),
        truncated: report.get("truncated").and_then(|v| v.as_bool()).unwrap_or(false),
    }
}

/// Infected files of the report that become detections: well-formed entries under the
/// site's own folder, whose sha256 the site does not ignore, one per (path, sha256).
pub fn plan_detections(report: &Value, domain: &str, ignored: &HashSet<String>) -> Vec<DetectionInput> {
    let root = format!("/var/www/{domain}/");
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for item in report.get("infected").and_then(|v| v.as_array()).into_iter().flatten() {
        let s = |k: &str| item.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let path = s("path");
        let sha = s("sha256").to_ascii_lowercase();
        let signature = s("signature");
        if !path.starts_with(&root) || path.contains('\0') || sha.is_empty() || signature.is_empty() {
            continue;
        }
        if ignored.contains(&sha) {
            continue;
        }
        if !seen.insert((path.clone(), sha.clone())) {
            continue;
        }
        let size = item.get("size").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
        out.push(DetectionInput { file_path: path, signature, size, sha256: sha });
    }
    out
}

/// Open detections that this scan no longer saw can be closed only if the scan saw
/// every file: not truncated, and no file it failed to read.
pub fn closes_unseen(report: &ScanReport) -> bool {
    !report.truncated && report.files_errors == 0
}

// ──────────────────────────────────────────────────────────────
// Shared DB helpers (routes use them too)
// ──────────────────────────────────────────────────────────────

/// B-S: scans left `running` by a previous process can never finish.
pub async fn fail_running_on_startup(pool: &PgPool) {
    match sqlx::query(
        "UPDATE av_scans SET status = 'failed', error = 'Panel restarted', completed_at = now() \
         WHERE status = 'running'",
    )
    .execute(pool)
    .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::info!("Antivirus: {} interrupted scan(s) marked failed", r.rows_affected())
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("Antivirus: could not close interrupted scans: {e}"),
    }
}

/// Queue a scan of one site, or return the one already queued or running for it.
pub async fn enqueue_scan(
    pool: &PgPool,
    server_id: Uuid,
    site_id: Uuid,
    trigger: &str,
    requested_by: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM av_scans WHERE site_id = $1 AND status IN ('queued', 'running') \
         ORDER BY created_at LIMIT 1",
    )
    .bind(site_id)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = existing {
        return Ok(id);
    }
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO av_scans (server_id, site_id, trigger, status, requested_by) \
         VALUES ($1, $2, $3, 'queued', $4) RETURNING id",
    )
    .bind(server_id)
    .bind(site_id)
    .bind(trigger)
    .bind(requested_by)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduleRow {
    pub enabled: bool,
    pub hour: i16,
    pub interval_days: i16,
    pub last_run_at: Option<DateTime<Utc>>,
}

impl ScheduleRow {
    pub fn defaults() -> Self {
        Self { enabled: true, hour: 3, interval_days: 1, last_run_at: None }
    }

    pub fn to_json(&self, now: DateTime<Utc>) -> Value {
        json!({
            "enabled": self.enabled,
            "hour": self.hour,
            "interval_days": self.interval_days,
            "last_run_at": self.last_run_at,
            "next_run_at": next_run_at(now, self.enabled, self.hour, self.interval_days, self.last_run_at),
            "timezone": "UTC",
        })
    }
}

pub async fn read_schedule(pool: &PgPool, server_id: Uuid) -> Result<Option<ScheduleRow>, sqlx::Error> {
    sqlx::query_as("SELECT enabled, hour, interval_days, last_run_at FROM av_schedules WHERE server_id = $1")
        .bind(server_id)
        .fetch_optional(pool)
        .await
}

/// The server's schedule, created with the defaults when missing. A row created here
/// starts its clock now, so installing ClamAV in the afternoon does not scan every site
/// right away: the first scheduled run is the next slot.
pub async fn ensure_schedule(pool: &PgPool, server_id: Uuid) -> Result<ScheduleRow, sqlx::Error> {
    sqlx::query(
        "INSERT INTO av_schedules (server_id, last_run_at) VALUES ($1, now()) ON CONFLICT (server_id) DO NOTHING",
    )
    .bind(server_id)
    .execute(pool)
    .await?;
    Ok(read_schedule(pool, server_id).await?.unwrap_or_else(ScheduleRow::defaults))
}

/// Fire or resolve the site's `malware` alert from its open detections.
///
/// Same shape as the WordPress vulnerability alert (`wordpress::scan_and_store`): to the
/// site's owner, scoped by site, one state key per site.
pub async fn refresh_site_alert(pool: &PgPool, site_id: Uuid) {
    let site: Option<(String, Uuid, i64)> = match sqlx::query_as(
        "SELECT s.domain, s.user_id, \
                (SELECT COUNT(*) FROM av_detections d WHERE d.site_id = s.id AND d.status = 'open') \
         FROM sites s WHERE s.id = $1",
    )
    .bind(site_id)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Antivirus: could not read detections of site {site_id}: {e}");
            return;
        }
    };
    let Some((domain, owner, open)) = site else { return };
    let key = format!("av:{site_id}");
    if open > 0 {
        fire_av_alert(
            pool,
            owner,
            None,
            Some(site_id),
            ALERT_MALWARE,
            &key,
            "critical",
            &format!("Malware found on {domain}"),
            &format!(
                "The antivirus found {open} infected file(s) on {domain}. Open Security > Antivirus \
                 to quarantine, delete or ignore them."
            ),
            12,
        )
        .await;
    } else {
        resolve_av_alert(
            pool,
            owner,
            None,
            Some(site_id),
            ALERT_MALWARE,
            &key,
            &format!("Malware alert resolved: {domain}"),
            &format!("No infected file is left open on {domain}."),
        )
        .await;
    }
}

/// `resolve_alert`, then the acknowledged rows of the same subject too: `resolve_alert`
/// only closes `firing` ones, and an acknowledged alert whose condition is over would
/// otherwise keep muting its return in [`fire_av_alert`].
#[allow(clippy::too_many_arguments)]
async fn resolve_av_alert(
    pool: &PgPool,
    user_id: Uuid,
    server_id: Option<Uuid>,
    site_id: Option<Uuid>,
    alert_type: &str,
    state_key: &str,
    title: &str,
    message: &str,
) {
    notifications::resolve_alert(pool, user_id, server_id, site_id, alert_type, state_key, title, message).await;
    if let Err(e) = sqlx::query(
        "UPDATE alerts SET status = 'resolved', resolved_at = NOW() \
         WHERE user_id = $1 AND server_id IS NOT DISTINCT FROM $2 AND site_id IS NOT DISTINCT FROM $3 \
         AND alert_type = $4 AND state_key = $5 AND status = 'acknowledged'",
    )
    .bind(user_id)
    .bind(server_id)
    .bind(site_id)
    .bind(alert_type)
    .bind(state_key)
    .execute(pool)
    .await
    {
        tracing::warn!("Antivirus: could not close acknowledged '{alert_type}' alerts: {e}");
    }
}

/// Whether an earlier alert of the same subject mutes a new one: only while it is still
/// open (firing or acknowledged) and younger than the window. A resolved alert never
/// does, so a condition that comes back after being fixed is announced again.
pub fn alert_mutes(status: &str, created_at: DateTime<Utc>, now: DateTime<Utc>, within_hours: i64) -> bool {
    matches!(status, "firing" | "acknowledged") && now - created_at < ChronoDuration::hours(within_hours)
}

/// `fire_alert_deduped` for the antivirus alerts, deduplicated on OPEN alerts only.
///
/// `fire_alert_deduped` counts every alert of the window, resolved ones included: a site
/// cleaned and re-infected within 12 hours, or a clamd that came back and fell again,
/// would raise nothing. Same subject as there: `(alert_type, site_id, state_key)`.
#[allow(clippy::too_many_arguments)]
async fn fire_av_alert(
    pool: &PgPool,
    user_id: Uuid,
    server_id: Option<Uuid>,
    site_id: Option<Uuid>,
    alert_type: &str,
    state_key: &str,
    severity: &str,
    title: &str,
    message: &str,
    within_hours: i64,
) {
    let recent: Vec<(String, DateTime<Utc>)> = match sqlx::query_as(
        "SELECT status, created_at FROM alerts \
         WHERE alert_type = $1 AND site_id IS NOT DISTINCT FROM $2 AND state_key = $3 \
         AND status <> 'resolved' AND created_at > NOW() - make_interval(hours => $4::int)",
    )
    .bind(alert_type)
    .bind(site_id)
    .bind(state_key)
    .bind(within_hours.clamp(0, i32::MAX as i64) as i32)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Same direction as `fire_alert_deduped`: a failed read does not mute.
            tracing::warn!("Antivirus: could not read recent '{alert_type}' alerts: {e}");
            Vec::new()
        }
    };
    let now = Utc::now();
    if recent.iter().any(|(status, at)| alert_mutes(status, *at, now, within_hours)) {
        return;
    }
    notifications::fire_alert(pool, user_id, server_id, site_id, alert_type, state_key, severity, title, message)
        .await;
}

/// The human message of an agent refusal (`{"error": "..."}`), without the transport framing.
pub fn agent_refusal(e: &AgentError) -> String {
    match e {
        AgentError::Status(_, body) => serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(String::from))
            .unwrap_or_else(|| body.chars().take(300).collect()),
        other => other.to_string(),
    }
}

// ──────────────────────────────────────────────────────────────
// The task
// ──────────────────────────────────────────────────────────────

struct ActiveScan {
    scan_id: Uuid,
    site_id: Uuid,
    domain: String,
    job_id: String,
    clock: StallClock,
    last_error: Option<String>,
}

#[derive(Default)]
struct Retry {
    not_before: Option<Instant>,
    tries: u32,
}

#[derive(Default)]
struct State {
    /// server_id -> the scan being followed there.
    active: HashMap<Uuid, ActiveScan>,
    /// scan_id -> when it may be tried again.
    retries: HashMap<Uuid, Retry>,
    /// server_id -> since when an installed clamd does not answer.
    down_since: HashMap<Uuid, Instant>,
    /// server_id -> no scan is started there before this (the agent said 409: busy).
    busy_until: HashMap<Uuid, Instant>,
}

pub async fn run(pool: PgPool, agents: AgentRegistry, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Antivirus scanner background task started");
    tokio::select! {
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
        _ = shutdown_rx.recv() => return,
    }

    let mut st = State::default();
    let mut last_health: Option<Instant> = None;
    let mut last_plan: Option<Instant> = None;
    let mut last_retention: Option<Instant> = None;

    loop {
        let now = Instant::now();
        let due = |t: Option<Instant>, every: Duration| t.is_none_or(|t| now.duration_since(t) >= every);

        if due(last_health, HEALTH_EVERY) {
            let plan = due(last_plan, PLAN_EVERY);
            health_and_schedule(&pool, &agents, &mut st, plan).await;
            last_health = Some(now);
            if plan {
                last_plan = Some(now);
            }
        }
        if due(last_retention, RETENTION_EVERY) {
            retention(&pool).await;
            last_retention = Some(now);
        }

        poll_active(&pool, &agents, &mut st).await;
        start_queued(&pool, &agents, &mut st).await;

        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown_rx.recv() => {
                tracing::info!("Antivirus scanner shutting down");
                return;
            }
        }
    }
}

async fn set_failed(pool: &PgPool, scan_id: Uuid, error: &str) {
    if let Err(e) = sqlx::query(
        "UPDATE av_scans SET status = 'failed', error = $2, completed_at = now() WHERE id = $1",
    )
    .bind(scan_id)
    .bind(error)
    .execute(pool)
    .await
    {
        tracing::warn!("Antivirus: could not mark scan {scan_id} failed: {e}");
    }
}

async fn requeue(pool: &PgPool, st: &mut State, scan_id: Uuid, why: &str, limited: bool) {
    let r = st.retries.entry(scan_id).or_default();
    if limited {
        r.tries += 1;
    }
    if limited && r.tries >= MAX_TEMPORARY_TRIES {
        st.retries.remove(&scan_id);
        set_failed(pool, scan_id, why).await;
        return;
    }
    r.not_before = Some(Instant::now() + RETRY_AFTER);
    let _ = sqlx::query(
        "UPDATE av_scans SET status = 'queued', started_at = NULL, agent_job_id = NULL WHERE id = $1 AND status = 'running'",
    )
    .bind(scan_id)
    .execute(pool)
    .await;
}

/// Starts the oldest startable queued scan of every server that has none running.
async fn start_queued(pool: &PgPool, agents: &AgentRegistry, st: &mut State) {
    let queued: Vec<(Uuid, Uuid, Uuid, String)> = match sqlx::query_as(
        "SELECT sc.id, sc.server_id, sc.site_id, s.domain FROM av_scans sc \
         JOIN sites s ON s.id = sc.site_id \
         JOIN servers sv ON sv.id = sc.server_id \
         WHERE sc.status = 'queued' AND sv.status = 'online' \
         ORDER BY sc.created_at",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Antivirus: could not read the scan queue: {e}");
            return;
        }
    };
    if queued.is_empty() {
        return;
    }
    // Servers with a scan `running` in the database that this task does not follow
    // (claimed but not settled): the agent would answer 409 for it. Bounded in age so a
    // row a failed UPDATE left behind cannot block its server forever.
    let running: HashSet<Uuid> = match sqlx::query_as::<_, (Uuid,)>(&format!(
        "SELECT DISTINCT server_id FROM av_scans WHERE status = 'running' \
         AND started_at > now() - INTERVAL '{} seconds'",
        JOB_STALL.as_secs() + 5 * 60
    ))
    .fetch_all(pool)
    .await
    {
        Ok(r) => r.into_iter().map(|(s,)| s).collect(),
        Err(e) => {
            tracing::warn!("Antivirus: could not read running scans: {e}");
            return;
        }
    };
    let now = Instant::now();
    st.busy_until.retain(|_, t| *t > now);
    let mut tried: HashSet<Uuid> = HashSet::new();
    for (scan_id, server_id, site_id, domain) in queued {
        if tried.contains(&server_id)
            || server_blocked(
                st.active.contains_key(&server_id),
                running.contains(&server_id),
                st.busy_until.get(&server_id).copied(),
                now,
            )
        {
            continue;
        }
        if st.retries.get(&scan_id).and_then(|r| r.not_before).is_some_and(|t| t > now) {
            continue;
        }
        tried.insert(server_id);

        let claimed = sqlx::query(
            "UPDATE av_scans SET status = 'running', started_at = now(), error = NULL, \
             progress_done = NULL, progress_total = NULL WHERE id = $1 AND status = 'queued'",
        )
        .bind(scan_id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() == 1)
        .unwrap_or(false);
        if !claimed {
            continue;
        }

        let agent = match agents.for_server(server_id).await {
            Ok(a) => a,
            Err(e) => {
                requeue(pool, st, scan_id, &format!("Server unreachable: {e}"), true).await;
                continue;
            }
        };
        if !crate::routes::is_valid_domain(&domain) {
            set_failed(pool, scan_id, "Invalid site domain").await;
            continue;
        }
        match agent.post("/antivirus/scan", Some(json!({ "domain": domain }))).await {
            Ok(v) => {
                let job_id = v.get("job_id").and_then(|j| j.as_str()).unwrap_or("").to_string();
                if !valid_job_id(&job_id) {
                    set_failed(pool, scan_id, "The agent returned an invalid job id").await;
                    continue;
                }
                let _ = sqlx::query("UPDATE av_scans SET agent_job_id = $2 WHERE id = $1")
                    .bind(scan_id)
                    .bind(&job_id)
                    .execute(pool)
                    .await;
                st.retries.remove(&scan_id);
                tracing::info!("Antivirus: scanning {domain} (job {job_id})");
                st.active.insert(
                    server_id,
                    ActiveScan {
                        scan_id,
                        site_id,
                        domain,
                        job_id,
                        clock: StallClock::new(Instant::now(), JOB_STALL),
                        last_error: None,
                    },
                );
            }
            Err(e) => {
                let why = agent_refusal(&e);
                match start_refusal(&e) {
                    Refusal::Busy => {
                        st.busy_until.insert(server_id, Instant::now() + BUSY_BACKOFF);
                        requeue(pool, st, scan_id, &why, false).await
                    }
                    Refusal::Temporary => requeue(pool, st, scan_id, &why, true).await,
                    Refusal::Final => {
                        st.retries.remove(&scan_id);
                        set_failed(pool, scan_id, &why).await;
                    }
                }
            }
        }
    }
}

/// Whether no new scan may start on a server this tick: one is followed there, one is
/// `running` in the database, or the agent said it was busy less than [`BUSY_BACKOFF`] ago.
fn server_blocked(followed: bool, running_in_db: bool, busy_until: Option<Instant>, now: Instant) -> bool {
    followed || running_in_db || busy_until.is_some_and(|t| t > now)
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// 409: another scan runs on this server; wait for it, without limit.
    Busy,
    /// 412 (clamd reloading its signatures takes 20-40 s), 5xx, transport: a few more tries.
    Temporary,
    /// Any other 4xx (404: no `/var/www/<domain>`, 400): the scan fails.
    Final,
}

fn start_refusal(e: &AgentError) -> Refusal {
    match e {
        AgentError::Status(409, _) => Refusal::Busy,
        AgentError::Status(412, _) => Refusal::Temporary,
        AgentError::Status(code, _) if (400..500).contains(code) => Refusal::Final,
        _ => Refusal::Temporary,
    }
}

pub fn valid_job_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// One poll of every followed scan.
async fn poll_active(pool: &PgPool, agents: &AgentRegistry, st: &mut State) {
    let servers: Vec<Uuid> = st.active.keys().copied().collect();
    for server_id in servers {
        let Some(scan) = st.active.get_mut(&server_id) else { continue };
        let outcome = match agents.for_server(server_id).await {
            Ok(agent) => poll_once(pool, &agent, scan).await,
            Err(e) => {
                scan.last_error = Some(e.to_string());
                None
            }
        };
        let outcome = outcome.or_else(|| {
            scan.clock.stalled(Instant::now()).then(|| {
                Err(match &scan.last_error {
                    Some(e) => format!("No progress for {} minutes (last error: {e})", JOB_STALL.as_secs() / 60),
                    None => format!("No progress for {} minutes", JOB_STALL.as_secs() / 60),
                })
            })
        });
        let Some(outcome) = outcome else { continue };
        let scan = st.active.remove(&server_id).expect("present");
        match outcome {
            Ok(report) => {
                if let Err(e) = finish_scan(pool, &scan, &report).await {
                    tracing::warn!("Antivirus: could not record scan of {}: {e}", scan.domain);
                    set_failed(pool, scan.scan_id, "Could not record the scan result").await;
                }
                refresh_site_alert(pool, scan.site_id).await;
            }
            Err(e) => {
                tracing::warn!("Antivirus: scan of {} failed: {e}", scan.domain);
                set_failed(pool, scan.scan_id, &e).await;
            }
        }
    }
}

/// `Some(Ok(report))` when done, `Some(Err)` when failed, `None` while it runs.
async fn poll_once(pool: &PgPool, agent: &AgentHandle, scan: &mut ActiveScan) -> Option<Result<Value, String>> {
    match agent.get(&format!("/jobs/{}", scan.job_id)).await {
        Ok(v) => match classify_job(&v) {
            JobPoll::Done(report) => Some(Ok(report)),
            JobPoll::Failed(e) => Some(Err(e)),
            JobPoll::Running { phase, bytes_done, bytes_total, updated_at, .. } => {
                scan.last_error = None;
                if scan.clock.observe(Instant::now(), &phase, bytes_done, updated_at) {
                    let _ = sqlx::query("UPDATE av_scans SET progress_done = $2, progress_total = $3 WHERE id = $1")
                        .bind(scan.scan_id)
                        .bind(bytes_done.min(i64::MAX as u64) as i64)
                        .bind(bytes_total.min(i64::MAX as u64) as i64)
                        .execute(pool)
                        .await;
                }
                None
            }
        },
        Err(AgentError::Status(404, _)) => {
            Some(Err("The agent no longer knows this scan (it was probably restarted)".into()))
        }
        Err(e) => {
            scan.last_error = Some(e.to_string());
            None
        }
    }
}

async fn finish_scan(pool: &PgPool, scan: &ActiveScan, report: &Value) -> Result<(), sqlx::Error> {
    let counters = parse_report(report);
    let ignored: HashSet<String> = sqlx::query_as::<_, (String,)>("SELECT sha256 FROM av_ignored WHERE site_id = $1")
        .bind(scan.site_id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(s,)| s.to_ascii_lowercase())
        .collect();
    let detections = plan_detections(report, &scan.domain, &ignored);

    let mut tx = pool.begin().await?;
    for d in &detections {
        sqlx::query(
            "INSERT INTO av_detections (scan_id, site_id, file_path, signature, size, sha256) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (site_id, file_path, sha256) WHERE status = 'open' \
             DO UPDATE SET scan_id = EXCLUDED.scan_id, signature = EXCLUDED.signature, \
                           size = EXCLUDED.size, last_seen_at = now()",
        )
        .bind(scan.scan_id)
        .bind(scan.site_id)
        .bind(&d.file_path)
        .bind(&d.signature)
        .bind(d.size)
        .bind(&d.sha256)
        .execute(&mut *tx)
        .await?;
    }
    if closes_unseen(&counters) {
        // The file is gone or its content changed (a new content is a new detection).
        sqlx::query(
            "UPDATE av_detections SET status = 'deleted', handled_at = now() \
             WHERE site_id = $1 AND status = 'open' AND scan_id <> $2",
        )
        .bind(scan.site_id)
        .bind(scan.scan_id)
        .execute(&mut *tx)
        .await?;
    }
    let note = counters
        .truncated
        .then_some("More than 500 infected files: only the first 500 are listed");
    sqlx::query(
        "UPDATE av_scans SET status = 'completed', completed_at = now(), files_scanned = $2, \
         files_skipped = $3, files_errors = $4, infected_count = $5, signatures_version = $6, error = $7, \
         progress_done = COALESCE(progress_total, progress_done) WHERE id = $1",
    )
    .bind(scan.scan_id)
    .bind(counters.files_scanned)
    .bind(counters.files_skipped)
    .bind(counters.files_errors)
    .bind(detections.len().min(i32::MAX as usize) as i32)
    .bind(counters.signatures_version)
    .bind(note)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(
        "Antivirus: {} scanned, {} file(s), {} infected",
        scan.domain,
        counters.files_scanned,
        detections.len()
    );
    Ok(())
}

/// Status of ClamAV on one agent; `None` when the agent cannot say (older agent, offline).
pub async fn agent_status(agent: &AgentHandle) -> Option<Value> {
    tokio::time::timeout(STATUS_TIMEOUT, agent.get("/antivirus/status")).await.ok()?.ok()
}

pub fn status_flags(status: &Value) -> (bool, bool) {
    let b = |k: &str| status.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    (b("installed"), b("responding"))
}

/// Whether the signature date is older than the alert threshold.
pub fn signatures_stale(status: &Value, now: DateTime<Utc>) -> bool {
    status
        .pointer("/signatures/updated_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|t| now - t.with_timezone(&Utc) > ChronoDuration::days(SIGNATURES_MAX_AGE_DAYS))
}

async fn health_and_schedule(pool: &PgPool, agents: &AgentRegistry, st: &mut State, plan: bool) {
    for member in agents.online_fleet().await {
        let Some(status) = agent_status(&member.agent).await else {
            st.down_since.remove(&member.id);
            continue;
        };
        let (installed, responding) = status_flags(&status);
        if !installed {
            st.down_since.remove(&member.id);
            continue;
        }

        let down_key = format!("{ALERT_DOWN}:{}", member.id);
        if responding {
            if st.down_since.remove(&member.id).is_some() {
                resolve_av_alert(
                    pool,
                    member.user_id,
                    Some(member.id),
                    None,
                    ALERT_DOWN,
                    &down_key,
                    &format!("ClamAV is responding again on {}", member.name),
                    "Mail is scanned for viruses again.",
                )
                .await;
            }
        } else {
            let since = *st.down_since.entry(member.id).or_insert_with(Instant::now);
            if since.elapsed() >= AV_DOWN_AFTER {
                fire_av_alert(
                    pool,
                    member.user_id,
                    Some(member.id),
                    None,
                    ALERT_DOWN,
                    &down_key,
                    "warning",
                    &format!("ClamAV is not responding on {}", member.name),
                    &format!(
                        "ClamAV has not answered for {} minutes on {}. Mail is delivered without virus \
                         scanning and site scans cannot run.",
                        since.elapsed().as_secs() / 60,
                        member.name
                    ),
                    6,
                )
                .await;
            }
        }

        if responding {
            let sig_key = format!("{ALERT_SIGNATURES}:{}", member.id);
            if signatures_stale(&status, Utc::now()) {
                fire_av_alert(
                    pool,
                    member.user_id,
                    Some(member.id),
                    None,
                    ALERT_SIGNATURES,
                    &sig_key,
                    "warning",
                    &format!("ClamAV signatures are out of date on {}", member.name),
                    &format!(
                        "The virus signatures on {} are more than {SIGNATURES_MAX_AGE_DAYS} days old. \
                         Check the clamav-freshclam service.",
                        member.name
                    ),
                    24,
                )
                .await;
            } else if status.pointer("/signatures/updated_at").is_some_and(|v| v.is_string()) {
                resolve_av_alert(
                    pool,
                    member.user_id,
                    Some(member.id),
                    None,
                    ALERT_SIGNATURES,
                    &sig_key,
                    &format!("ClamAV signatures are up to date on {}", member.name),
                    "The virus signatures were updated.",
                )
                .await;
            }
        }

        if plan && responding {
            if let Err(e) = schedule_server(pool, member.id).await {
                tracing::warn!("Antivirus: schedule of {} failed: {e}", member.name);
            }
        }
    }
}

async fn schedule_server(pool: &PgPool, server_id: Uuid) -> Result<(), sqlx::Error> {
    let sched = ensure_schedule(pool, server_id).await?;
    let now = Utc::now();
    if !sched.enabled || !is_due(now, sched.hour, sched.interval_days, sched.last_run_at) {
        return Ok(());
    }
    // Claim the run first, so two passes cannot both queue it.
    let claimed = sqlx::query(
        "UPDATE av_schedules SET last_run_at = $2 WHERE server_id = $1 \
         AND last_run_at IS NOT DISTINCT FROM $3",
    )
    .bind(server_id)
    .bind(now)
    .bind(sched.last_run_at)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if !claimed {
        return Ok(());
    }
    let sites: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM sites WHERE server_id = $1 ORDER BY domain")
        .bind(server_id)
        .fetch_all(pool)
        .await?;
    for (site_id,) in &sites {
        enqueue_scan(pool, server_id, *site_id, "scheduled", None).await?;
    }
    tracing::info!("Antivirus: scheduled scan of {} site(s) on server {server_id}", sites.len());
    Ok(())
}

/// B-M: finished scans are kept 90 days, unless a detection of theirs still needs a
/// decision (open) or can still be restored (quarantined).
async fn retention(pool: &PgPool) {
    let r = sqlx::query(&format!(
        "DELETE FROM av_scans sc WHERE sc.status IN ('completed', 'failed') \
         AND COALESCE(sc.completed_at, sc.created_at) < now() - INTERVAL '{RETENTION_DAYS} days' \
         AND NOT EXISTS (SELECT 1 FROM av_detections d WHERE d.scan_id = sc.id \
                         AND d.status IN ('open', 'quarantined'))"
    ))
    .execute(pool)
    .await;
    if let Err(e) = r {
        tracing::warn!("Antivirus: retention failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn not_due_before_the_hour_due_after_it() {
        let last = Some(at("2026-11-14T03:02:00Z"));
        assert!(!is_due(at("2026-11-15T02:59:00Z"), 3, 1, last));
        assert!(is_due(at("2026-11-15T03:00:00Z"), 3, 1, last));
        assert!(is_due(at("2026-11-15T22:00:00Z"), 3, 1, last));
    }

    #[test]
    fn never_run_is_due_once_the_hour_is_reached() {
        assert!(!is_due(at("2026-11-15T02:00:00Z"), 3, 1, None));
        assert!(is_due(at("2026-11-15T03:05:00Z"), 3, 1, None));
    }

    #[test]
    fn a_run_tonight_is_not_repeated_tonight() {
        let last = Some(at("2026-11-15T03:01:00Z"));
        assert!(!is_due(at("2026-11-15T03:06:00Z"), 3, 1, last));
        assert!(!is_due(at("2026-11-15T23:59:00Z"), 3, 1, last));
    }

    #[test]
    fn a_late_run_does_not_drift_the_schedule() {
        // Panel down at 03:00, run caught up at 15:00: the next one is still 03:00.
        let last = Some(at("2026-11-14T15:00:00Z"));
        assert!(is_due(at("2026-11-15T03:00:00Z"), 3, 1, last));
    }

    #[test]
    fn interval_days_are_honoured_within_an_hour() {
        let last = Some(at("2026-11-13T03:04:00Z"));
        assert!(!is_due(at("2026-11-14T03:10:00Z"), 3, 2, last));
        assert!(is_due(at("2026-11-15T03:00:00Z"), 3, 2, last));
        // Weekly.
        let last = Some(at("2026-11-08T03:00:00Z"));
        assert!(!is_due(at("2026-11-14T03:00:00Z"), 3, 7, last));
        assert!(is_due(at("2026-11-15T03:00:00Z"), 3, 7, last));
    }

    #[test]
    fn moving_the_hour_within_an_hour_does_not_run_twice() {
        // Ran at 03:02, hour moved to 04 the same day: already done tonight.
        assert!(!is_due(at("2026-11-15T04:00:00Z"), 4, 1, Some(at("2026-11-15T03:02:00Z"))));
        // Ran yesterday at 03:02, hour moved to 02: due at 02:00.
        assert!(is_due(at("2026-11-15T02:00:00Z"), 2, 1, Some(at("2026-11-14T03:02:00Z"))));
    }

    #[test]
    fn midnight_and_last_hour_edges() {
        assert!(is_due(at("2026-11-15T00:00:00Z"), 0, 1, Some(at("2026-11-14T00:01:00Z"))));
        assert!(!is_due(at("2026-11-15T22:59:59Z"), 23, 1, Some(at("2026-11-14T23:00:00Z"))));
        assert!(is_due(at("2026-11-15T23:00:00Z"), 23, 1, Some(at("2026-11-14T23:00:00Z"))));
        // Out-of-range values are clamped, never panic.
        assert!(is_due(at("2026-11-15T23:30:00Z"), 99, 0, None));
    }

    #[test]
    fn next_run_is_now_when_due_or_the_next_owed_slot() {
        let now = at("2026-11-15T10:00:00Z");
        assert_eq!(next_run_at(now, false, 3, 1, None), None);
        assert_eq!(next_run_at(now, true, 3, 1, None), Some(now));
        assert_eq!(
            next_run_at(now, true, 3, 1, Some(at("2026-11-15T03:01:00Z"))),
            Some(at("2026-11-16T03:00:00Z"))
        );
        assert_eq!(
            next_run_at(now, true, 3, 3, Some(at("2026-11-15T03:01:00Z"))),
            Some(at("2026-11-18T03:00:00Z"))
        );
        assert_eq!(
            next_run_at(now, true, 14, 1, Some(at("2026-11-14T14:00:00Z"))),
            Some(at("2026-11-15T14:00:00Z"))
        );
    }

    fn report() -> Value {
        json!({
            "domain": "x.tld", "files_scanned": 120, "files_skipped": 2, "files_errors": 0,
            "signatures_version": 27450, "duration_ms": 5000,
            "infected": [
                { "path": "/var/www/x.tld/public/a.php", "signature": "Php.Malware.X", "size": 1234, "sha256": "AA11" },
                { "path": "/var/www/x.tld/public/b.php", "signature": "Eicar-Test-Signature", "size": 68, "sha256": "bb22" },
                { "path": "/var/www/x.tld/public/a.php", "signature": "Php.Malware.X", "size": 1234, "sha256": "aa11" },
                { "path": "/var/www/other.tld/c.php", "signature": "X", "size": 1, "sha256": "cc33" },
                { "path": "/var/www/x.tld/d.php", "signature": "", "size": 1, "sha256": "dd44" },
                { "path": "/var/www/x.tld/e.php", "signature": "Y", "size": -5, "sha256": "ee55" }
            ]
        })
    }

    #[test]
    fn report_maps_to_detections_with_dedupe_and_scope() {
        let d = plan_detections(&report(), "x.tld", &HashSet::new());
        let paths: Vec<&str> = d.iter().map(|x| x.file_path.as_str()).collect();
        assert_eq!(paths, vec!["/var/www/x.tld/public/a.php", "/var/www/x.tld/public/b.php", "/var/www/x.tld/e.php"]);
        assert_eq!(d[0].sha256, "aa11");
        assert_eq!(d[0].size, 1234);
        assert_eq!(d[2].size, 0);
    }

    #[test]
    fn ignored_hashes_create_no_detection() {
        let ignored: HashSet<String> = ["aa11".to_string()].into_iter().collect();
        let d = plan_detections(&report(), "x.tld", &ignored);
        assert!(d.iter().all(|x| x.sha256 != "aa11"));
        assert_eq!(d.len(), 2);
        // A domain that is a prefix of another does not capture its files.
        assert!(plan_detections(&report(), "x.tl", &HashSet::new()).is_empty());
    }

    #[test]
    fn counters_and_closing_rule() {
        let r = parse_report(&report());
        assert_eq!(r, ScanReport { files_scanned: 120, files_skipped: 2, files_errors: 0, signatures_version: Some(27450), truncated: false });
        assert!(closes_unseen(&r));
        assert!(!closes_unseen(&ScanReport { truncated: true, ..r.clone() }));
        assert!(!closes_unseen(&ScanReport { files_errors: 1, ..r }));
        assert_eq!(parse_report(&json!({})), ScanReport::default());
    }

    #[test]
    fn signature_age_and_status_flags() {
        let now = at("2026-11-15T12:00:00Z");
        let fresh = json!({ "installed": true, "responding": true, "signatures": { "updated_at": "2026-11-14T03:00:00Z" } });
        let old = json!({ "signatures": { "updated_at": "2026-11-11T03:00:00Z" } });
        assert!(!signatures_stale(&fresh, now));
        assert!(signatures_stale(&old, now));
        assert!(!signatures_stale(&json!({ "signatures": null }), now));
        assert_eq!(status_flags(&fresh), (true, true));
        assert_eq!(status_flags(&json!({})), (false, false));
    }

    #[test]
    fn job_ids_are_checked_before_use_in_a_path() {
        assert!(valid_job_id("4f1c-aa_9"));
        assert!(!valid_job_id(""));
        assert!(!valid_job_id("../x"));
        assert!(!valid_job_id("a/b"));
    }

    #[test]
    fn start_refusals_are_classified() {
        assert_eq!(start_refusal(&AgentError::Status(409, String::new())), Refusal::Busy);
        assert_eq!(start_refusal(&AgentError::Status(412, String::new())), Refusal::Temporary);
        assert_eq!(start_refusal(&AgentError::Status(404, String::new())), Refusal::Final);
        assert_eq!(start_refusal(&AgentError::Status(502, String::new())), Refusal::Temporary);
        assert_eq!(start_refusal(&AgentError::Connection("x".into())), Refusal::Temporary);
    }

    #[test]
    fn only_open_alerts_inside_the_window_mute_a_new_one() {
        let now = at("2026-11-15T12:00:00Z");
        let an_hour_ago = at("2026-11-15T11:00:00Z");
        assert!(alert_mutes("firing", an_hour_ago, now, 12));
        assert!(alert_mutes("acknowledged", an_hour_ago, now, 12));
        // Cleaned then re-infected within the window: announced again.
        assert!(!alert_mutes("resolved", an_hour_ago, now, 12));
        // Still firing but older than the window: reminded again, as before.
        assert!(!alert_mutes("firing", at("2026-11-14T23:59:00Z"), now, 12));
        assert!(!alert_mutes("bogus", an_hour_ago, now, 12));
    }

    #[test]
    fn a_busy_server_is_left_alone() {
        let now = Instant::now();
        assert!(!server_blocked(false, false, None, now));
        assert!(server_blocked(true, false, None, now));
        assert!(server_blocked(false, true, None, now));
        assert!(server_blocked(false, false, Some(now + BUSY_BACKOFF), now));
        assert!(!server_blocked(false, false, Some(now), now));
    }

    #[test]
    fn agent_refusals_read_as_their_message() {
        let e = AgentError::Status(412, r#"{"error":"ClamAV is not responding"}"#.into());
        assert_eq!(agent_refusal(&e), "ClamAV is not responding");
        assert_eq!(agent_refusal(&AgentError::Status(500, "boom".into())), "boom");
    }
}
