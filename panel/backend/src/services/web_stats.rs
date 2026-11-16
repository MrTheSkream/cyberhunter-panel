//! Per-site web statistics with GoAccess (feature 7, contract B-4).
//!
//! One supervised task: 2 minutes after startup, then every hour, and whenever
//! an install wakes it ([`wake`]), each online server where GoAccess is
//! installed (A-1) gets one pass: its sites, never computed or oldest attempt
//! first, one `POST /stats/run` (A-5) after the other. Servers run in parallel.
//! Each result is upserted into `site_web_stats`; a failure is recorded on the
//! site and never blocks the next one. An unreachable server is skipped until
//! the next cycle.
//!
//! The report itself never goes through this module, and nothing here logs the
//! content of a visitor log or of a report.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::error::agent_message;
use crate::services::agent::{AgentError, AgentHandle, AgentRegistry};

const STARTUP_DELAY: Duration = Duration::from_secs(120);
const EVERY: Duration = Duration::from_secs(60 * 60);
/// A-5 may wait up to 10 minutes for the agent's mutex, download the GeoIP
/// database (2 minutes), then run for up to 15.
pub const RUN_TIMEOUT_SECS: u64 = 28 * 60;
/// Recorded when A-5 did not answer in time. The run is detached on the agent
/// and goes on; the next attempt picks up its result.
pub const TIMED_OUT: &str = "The statistics run did not finish in time";
/// How long the `installed` answer of A-1 is trusted (B-3).
const INSTALLED_TTL: Duration = Duration::from_secs(60);
/// Longest error text kept on a site.
const MAX_ERROR_CHARS: usize = 500;

/// Sites of one server, never attempted first, then the oldest attempt (B-4).
pub const SITES_SQL: &str = "SELECT s.id, s.domain, w.attempted_at FROM sites s \
     LEFT JOIN site_web_stats w ON w.site_id = s.id \
     WHERE s.server_id = $1 \
     ORDER BY w.attempted_at ASC NULLS FIRST, s.domain";

/// Upsert of one attempt: `attempted_at` always moves, `updated_at` only on a
/// success (a failure keeps the date of the last report), `error` is the
/// outcome of this attempt.
pub const UPSERT_SQL: &str = "INSERT INTO site_web_stats (site_id, updated_at, attempted_at, error) \
     VALUES ($1, $2, now(), $3) \
     ON CONFLICT (site_id) DO UPDATE SET \
     updated_at = COALESCE(EXCLUDED.updated_at, site_web_stats.updated_at), \
     attempted_at = now(), error = EXCLUDED.error";

// ──────────────────────────────────────────────────────────────
// A-5 outcome (pure)
// ──────────────────────────────────────────────────────────────

/// What one attempt writes into `site_web_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    /// The last successful run, as reported by the agent (`None` keeps the
    /// stored date).
    pub updated_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

fn clip(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.chars().take(MAX_ERROR_CHARS).collect())
}

/// A 200 answer of A-5. `ok: false` or an `error` is a failure even with a 200.
pub fn record_from_response(v: &Value) -> RunRecord {
    let updated_at = v
        .get("updated_at")
        .and_then(|t| t.as_str())
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc));
    let error = v.get("error").and_then(|e| e.as_str()).and_then(clip);
    let ok = v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
    let error = match (ok, error) {
        (_, Some(e)) => Some(e),
        (true, None) => None,
        (false, None) => Some("Statistics run failed".to_string()),
    };
    RunRecord { updated_at, error }
}

/// What to do with an agent failure of A-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Recorded on the site as its error (404 "No access log", 5xx, network).
    Record(String),
    /// Not about this site: nothing is recorded. 412 (GoAccess gone), 409 (the
    /// agent is busy), 400, or an open circuit (server unreachable).
    Relay,
}

pub fn classify(e: &AgentError) -> Failure {
    match e {
        AgentError::Status(400 | 409 | 412, _) | AgentError::CircuitOpen(_) => Failure::Relay,
        AgentError::Status(_, body) => {
            Failure::Record(clip(&agent_message(body)).unwrap_or_else(|| "Statistics run failed".to_string()))
        }
        AgentError::Request(m) if m.contains("timed out") => Failure::Record(TIMED_OUT.to_string()),
        _ => Failure::Record("The server could not be reached".to_string()),
    }
}

/// `updated_at` of an A-6 `state.json` answer.
pub fn updated_at_from_state(v: &Value) -> Option<DateTime<Utc>> {
    v.get("updated_at")
        .and_then(|t| t.as_str())
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// The record of a failure that is kept on the site.
pub fn record_from_failure(message: String) -> RunRecord {
    RunRecord { updated_at: None, error: Some(message) }
}

// ──────────────────────────────────────────────────────────────
// Order of a pass (pure)
// ──────────────────────────────────────────────────────────────

/// Same order as [`SITES_SQL`], applied again here so the pass does not rest on
/// the database's collation: never attempted first, then the oldest attempt,
/// then the domain. Domains the agent would refuse are dropped.
pub fn pass_order(mut rows: Vec<(Uuid, String, Option<DateTime<Utc>>)>) -> Vec<(Uuid, String)> {
    rows.retain(|(_, d, _)| crate::routes::is_valid_domain(d));
    rows.sort_by(|a, b| match (a.2, b.2) {
        (None, None) => a.1.cmp(&b.1),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.1.cmp(&b.1)),
    });
    rows.into_iter().map(|(id, d, _)| (id, d)).collect()
}

// ──────────────────────────────────────────────────────────────
// One run at a time per site (shared by the scheduler and B-3 refresh)
// ──────────────────────────────────────────────────────────────

static IN_FLIGHT: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Held while a site is being computed; released on drop (also when a refresh
/// is abandoned by its client).
pub struct SiteRunGuard(Uuid);

impl SiteRunGuard {
    pub fn try_claim(site_id: Uuid) -> Option<Self> {
        // The guard is built only once the lock is released: dropping one while
        // holding the lock would deadlock (its `Drop` takes the same lock).
        let claimed = IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner()).insert(site_id);
        claimed.then(|| SiteRunGuard(site_id))
    }
}

impl Drop for SiteRunGuard {
    fn drop(&mut self) {
        IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.0);
    }
}

pub fn is_running(site_id: Uuid) -> bool {
    IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner()).contains(&site_id)
}

// ──────────────────────────────────────────────────────────────
// `installed` per server, cached 60 s (B-3)
// ──────────────────────────────────────────────────────────────

static INSTALLED: LazyLock<Mutex<HashMap<Uuid, (Instant, bool)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `installed` of an A-1 answer: only when the server is supported too.
pub fn installed_from_status(v: &Value) -> bool {
    let supported = v.get("supported").and_then(|s| s.as_bool()).unwrap_or(true);
    supported && v.get("installed").and_then(|s| s.as_bool()).unwrap_or(false)
}

pub fn remember_installed(server_id: Uuid, installed: bool) {
    INSTALLED.lock().unwrap_or_else(|p| p.into_inner()).insert(server_id, (Instant::now(), installed));
}

/// After an install or an uninstall: the next question goes to the agent.
pub fn forget_installed(server_id: Uuid) {
    INSTALLED.lock().unwrap_or_else(|p| p.into_inner()).remove(&server_id);
}

fn cached_installed(server_id: Uuid) -> Option<bool> {
    let map = INSTALLED.lock().unwrap_or_else(|p| p.into_inner());
    map.get(&server_id).filter(|(at, _)| at.elapsed() < INSTALLED_TTL).map(|(_, v)| *v)
}

/// Is GoAccess installed on this server? A-1, cached 60 s. An agent without
/// the stats routes (404) counts as "not installed"; other failures are not
/// cached and are returned.
pub async fn installed(agent: &AgentHandle, server_id: Uuid, use_cache: bool) -> Result<bool, AgentError> {
    if use_cache && let Some(v) = cached_installed(server_id) {
        return Ok(v);
    }
    let v = match agent.get("/stats/status").await {
        Ok(v) => installed_from_status(&v),
        Err(AgentError::Status(404, _)) => false,
        Err(e) => return Err(e),
    };
    remember_installed(server_id, v);
    Ok(v)
}

// ──────────────────────────────────────────────────────────────
// Wake-up after an install (B-2)
// ──────────────────────────────────────────────────────────────

static WAKE_SERVERS: LazyLock<Mutex<Vec<Uuid>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static WAKE: LazyLock<Notify> = LazyLock::new(Notify::new);

/// Ask the scheduler for a pass on this server now. `notify_one` keeps the
/// wake-up when the task is busy, so it is never lost.
pub fn wake(server_id: Uuid) {
    WAKE_SERVERS.lock().unwrap_or_else(|p| p.into_inner()).push(server_id);
    WAKE.notify_one();
}

fn take_woken() -> Vec<Uuid> {
    let mut v = std::mem::take(&mut *WAKE_SERVERS.lock().unwrap_or_else(|p| p.into_inner()));
    v.sort();
    v.dedup();
    v
}

// ──────────────────────────────────────────────────────────────
// Database and one run
// ──────────────────────────────────────────────────────────────

pub async fn record(pool: &PgPool, site_id: Uuid, r: &RunRecord) -> Result<(), sqlx::Error> {
    sqlx::query(UPSERT_SQL).bind(site_id).bind(r.updated_at).bind(&r.error).execute(pool).await?;
    Ok(())
}

/// `(updated_at, error)` of a site, `(None, None)` before its first attempt.
pub async fn load(pool: &PgPool, site_id: Uuid) -> Result<(Option<DateTime<Utc>>, Option<String>), sqlx::Error> {
    let row: Option<(Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as("SELECT updated_at, error FROM site_web_stats WHERE site_id = $1")
            .bind(site_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.unwrap_or((None, None)))
}

/// Compute one site (A-5) and record the outcome. The caller holds the site's
/// [`SiteRunGuard`]. `Err` is a failure that was NOT recorded ([`Failure::Relay`]).
pub async fn run_site(pool: &PgPool, agent: &AgentHandle, site_id: Uuid, domain: &str) -> Result<(), AgentError> {
    let started = Instant::now();
    let rec = match agent.post_long("/stats/run", Some(json!({ "domain": domain })), RUN_TIMEOUT_SECS).await {
        Ok(v) => record_from_response(&v),
        Err(e) => match classify(&e) {
            Failure::Relay => return Err(e),
            Failure::Record(msg) => {
                tracing::warn!("Web stats: run of {domain} failed: {e}");
                let mut rec = record_from_failure(msg);
                if rec.error.as_deref() == Some(TIMED_OUT) {
                    // Not fatal: keep the last success the agent knows of (A-6 state).
                    if let Ok(v) = agent.get(&format!("/stats/{domain}/state")).await {
                        rec.updated_at = updated_at_from_state(&v);
                    }
                }
                rec
            }
        },
    };
    if rec.error.is_some() {
        tracing::info!("Web stats: {domain} failed after {} ms", started.elapsed().as_millis());
    } else {
        tracing::debug!("Web stats: {domain} computed in {} ms", started.elapsed().as_millis());
    }
    if let Err(e) = record(pool, site_id, &rec).await {
        tracing::warn!("Web stats: could not record {domain}: {e}");
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// The task
// ──────────────────────────────────────────────────────────────

static PASSES: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// One pass at a time per server.
struct PassSlot(Uuid);

impl PassSlot {
    fn try_claim(server_id: Uuid) -> Option<Self> {
        let claimed = PASSES.lock().unwrap_or_else(|p| p.into_inner()).insert(server_id);
        claimed.then(|| PassSlot(server_id))
    }
}

impl Drop for PassSlot {
    fn drop(&mut self) {
        PASSES.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.0);
    }
}

pub async fn run(pool: PgPool, agents: AgentRegistry, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Web stats background task started");
    let mut passes = tokio::task::JoinSet::new();
    let mut next = tokio::time::Instant::now() + STARTUP_DELAY;
    loop {
        let servers: Vec<Uuid> = tokio::select! {
            _ = tokio::time::sleep_until(next) => {
                next = tokio::time::Instant::now() + EVERY;
                online_servers(&pool).await
            }
            _ = WAKE.notified() => take_woken(),
            Some(_) = passes.join_next(), if !passes.is_empty() => continue,
            _ = shutdown_rx.recv() => {
                tracing::info!("Web stats task shutting down");
                passes.abort_all();
                return;
            }
        };
        for server_id in servers {
            // A server still busy with its previous pass keeps it.
            let Some(slot) = PassSlot::try_claim(server_id) else { continue };
            let (pool, agents) = (pool.clone(), agents.clone());
            passes.spawn(async move {
                server_pass(&pool, &agents, server_id).await;
                drop(slot);
            });
        }
    }
}

async fn online_servers(pool: &PgPool) -> Vec<Uuid> {
    match sqlx::query_as::<_, (Uuid,)>("SELECT id FROM servers WHERE status = 'online' ORDER BY id").fetch_all(pool).await
    {
        Ok(r) => r.into_iter().map(|(id,)| id).collect(),
        Err(e) => {
            tracing::warn!("Web stats: could not list the servers: {e}");
            Vec::new()
        }
    }
}

async fn server_pass(pool: &PgPool, agents: &AgentRegistry, server_id: Uuid) {
    let agent = match agents.for_server(server_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!("Web stats: server {server_id} skipped ({e})");
            return;
        }
    };
    match installed(&agent, server_id, false).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::debug!("Web stats: server {server_id} skipped ({e})");
            return;
        }
    }
    let rows: Vec<(Uuid, String, Option<DateTime<Utc>>)> =
        match sqlx::query_as(SITES_SQL).bind(server_id).fetch_all(pool).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Web stats: could not list the sites of server {server_id}: {e}");
                return;
            }
        };
    let mut done = 0usize;
    for (site_id, domain) in pass_order(rows) {
        // A site a Refresh is computing right now is left to it.
        let Some(guard) = SiteRunGuard::try_claim(site_id) else { continue };
        let res = run_site(pool, &agent, site_id, &domain).await;
        drop(guard);
        match res {
            Ok(()) => done += 1,
            Err(AgentError::Status(412, _)) => {
                tracing::info!("Web stats: GoAccess is no longer installed on server {server_id}");
                forget_installed(server_id);
                return;
            }
            Err(e @ AgentError::CircuitOpen(_)) => {
                tracing::warn!("Web stats: server {server_id} skipped until the next cycle: {e}");
                return;
            }
            // 409 (agent busy) or 400: left for the next cycle, not recorded.
            Err(e) => tracing::warn!("Web stats: {domain} not computed: {e}"),
        }
    }
    tracing::info!("Web stats: {done} site(s) processed on server {server_id}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn never_attempted_sites_come_first_then_the_oldest() {
        let ids: Vec<Uuid> = (0..6).map(|_| Uuid::new_v4()).collect();
        let rows = vec![
            (ids[0], "recent.tld".to_string(), Some(ts("2026-11-16T10:00:00Z"))),
            (ids[1], "zeta.tld".to_string(), None),
            (ids[2], "old.tld".to_string(), Some(ts("2026-11-16T08:00:00Z"))),
            (ids[3], "alpha.tld".to_string(), None),
            (ids[4], "bad..tld/../x".to_string(), None),
            (ids[5], "also-old.tld".to_string(), Some(ts("2026-11-16T08:00:00Z"))),
        ];
        let order: Vec<String> = pass_order(rows).into_iter().map(|(_, d)| d).collect();
        assert_eq!(order, vec!["alpha.tld", "zeta.tld", "also-old.tld", "old.tld", "recent.tld"]);
    }

    #[test]
    fn the_query_orders_like_the_contract() {
        assert!(SITES_SQL.contains("LEFT JOIN site_web_stats w ON w.site_id = s.id"));
        assert!(SITES_SQL.contains("ORDER BY w.attempted_at ASC NULLS FIRST, s.domain"));
        assert!(SITES_SQL.contains("s.server_id = $1"));
    }

    #[test]
    fn a_success_sets_the_date_and_clears_the_error() {
        let r = record_from_response(&json!({
            "domain": "x.tld", "ok": true, "updated_at": "2026-11-16T10:00:03Z",
            "duration_ms": 4200, "initialized": false, "error": null
        }));
        assert_eq!(r, RunRecord { updated_at: Some(ts("2026-11-16T10:00:03Z")), error: None });
    }

    #[test]
    fn a_failure_keeps_the_last_date_and_records_why() {
        // GoAccess failed: the agent keeps the last success in `updated_at`.
        let r = record_from_response(&json!({
            "domain": "x.tld", "ok": false, "updated_at": "2026-11-15T10:00:00Z", "error": "goaccess exited with 1"
        }));
        assert_eq!(r.updated_at, Some(ts("2026-11-15T10:00:00Z")));
        assert_eq!(r.error.as_deref(), Some("goaccess exited with 1"));
        // `ok: false` without a message is still a failure.
        assert_eq!(record_from_response(&json!({ "ok": false })).error.as_deref(), Some("Statistics run failed"));
        // Overlong messages are cut.
        let long = "e".repeat(2000);
        assert_eq!(record_from_response(&json!({ "ok": false, "error": long })).error.unwrap().len(), 500);
    }

    #[test]
    fn the_upsert_keeps_the_last_success_on_failure() {
        assert!(UPSERT_SQL.contains("ON CONFLICT (site_id) DO UPDATE"));
        assert!(UPSERT_SQL.contains("updated_at = COALESCE(EXCLUDED.updated_at, site_web_stats.updated_at)"));
        assert!(UPSERT_SQL.contains("attempted_at = now()"));
        assert!(UPSERT_SQL.contains("error = EXCLUDED.error"));
        let r = record_from_failure("No access log for this site".into());
        assert_eq!(r.updated_at, None);
        assert_eq!(r.error.as_deref(), Some("No access log for this site"));
    }

    #[test]
    fn agent_failures_are_recorded_or_relayed() {
        let no_log = AgentError::Status(404, r#"{"error":"No access log for this site"}"#.into());
        assert_eq!(classify(&no_log), Failure::Record("No access log for this site".into()));
        let broken = AgentError::Status(500, r#"{"error":"disk full"}"#.into());
        assert_eq!(classify(&broken), Failure::Record("disk full".into()));
        assert_eq!(
            classify(&AgentError::Connection("refused".into())),
            Failure::Record("The server could not be reached".into())
        );
        assert_eq!(
            classify(&AgentError::Request("agent request timed out after 1680s".into())),
            Failure::Record(TIMED_OUT.into())
        );
        assert_eq!(classify(&AgentError::Response("reset".into())), Failure::Record("The server could not be reached".into()));
        assert_eq!(
            updated_at_from_state(&json!({ "updated_at": "2026-11-16T10:00:03Z", "error": null })),
            Some(ts("2026-11-16T10:00:03Z"))
        );
        assert_eq!(updated_at_from_state(&json!({ "updated_at": null, "error": null })), None);
        for code in [400u16, 409, 412] {
            assert_eq!(classify(&AgentError::Status(code, "{}".into())), Failure::Relay);
        }
        assert_eq!(classify(&AgentError::CircuitOpen("open".into())), Failure::Relay);
    }

    #[test]
    fn installed_needs_support_too() {
        assert!(installed_from_status(&json!({ "supported": true, "installed": true })));
        assert!(!installed_from_status(&json!({ "supported": false, "installed": true })));
        assert!(!installed_from_status(&json!({ "supported": true, "installed": false })));
        assert!(!installed_from_status(&json!({})));
    }

    #[test]
    fn the_installed_answer_is_cached_until_forgotten() {
        let s = Uuid::new_v4();
        assert_eq!(cached_installed(s), None);
        remember_installed(s, true);
        assert_eq!(cached_installed(s), Some(true));
        forget_installed(s);
        assert_eq!(cached_installed(s), None);
    }

    /// A refused claim must neither deadlock (the refused guard used to be
    /// dropped while the lock was held) nor release the claim it lost to.
    #[tokio::test]
    async fn a_site_is_computed_once_at_a_time() {
        let body = tokio::task::spawn_blocking(|| {
            let (x, y) = (Uuid::new_v4(), Uuid::new_v4());
            let first = SiteRunGuard::try_claim(x).expect("free");
            assert!(is_running(x));
            assert!(SiteRunGuard::try_claim(x).is_none());
            // Still held by `first` after the refusal.
            assert!(is_running(x));
            let other = SiteRunGuard::try_claim(y).expect("another site is free");
            drop(first);
            assert!(!is_running(x));
            assert!(SiteRunGuard::try_claim(x).is_some());
            drop(other);

            let s = Uuid::new_v4();
            let slot = PassSlot::try_claim(s).expect("free");
            assert!(PassSlot::try_claim(s).is_none());
            drop(slot);
            assert!(PassSlot::try_claim(s).is_some());
        });
        tokio::time::timeout(Duration::from_secs(10), body)
            .await
            .expect("the claims must never block")
            .expect("assertions");
    }

    #[test]
    fn wake_ups_are_queued_once_per_server() {
        let s = Uuid::new_v4();
        wake(s);
        wake(s);
        let woken = take_woken();
        assert_eq!(woken.iter().filter(|id| **id == s).count(), 1);
    }
}
