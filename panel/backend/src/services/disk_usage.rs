//! Per-site disk usage and the `disk_quota` alert (feature 6, contracts B-3 / B-4).
//!
//! One supervised task: shortly after startup, then every 6 hours, every site of
//! every online server is measured by its own agent (`POST /disk-usage`, A-5, one
//! call per server and per 500 domains). Each result is upserted into
//! `site_disk_usage` and the site's `disk_quota` alert is recomputed. A server that
//! cannot be reached is skipped and tried again at the next cycle.
//!
//! The quota is an alert limit only: nothing here ever blocks a site or a write.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{DiskUsage, Site};
use crate::services::agent::{AgentError, AgentHandle, AgentRegistry};
use crate::services::notifications;

pub const ALERT_DISK_QUOTA: &str = "disk_quota";

const STARTUP_DELAY: Duration = Duration::from_secs(90);
const EVERY: Duration = Duration::from_secs(6 * 60 * 60);
/// A-5 accepts at most this many domains per call.
pub const MAX_DOMAINS_PER_CALL: usize = 500;
/// A-5 gives itself 10 minutes for a whole call and serializes calls per agent.
pub const MEASURE_TIMEOUT_SECS: u64 = 11 * 60;

const BYTES_PER_MB: i64 = 1_048_576;

// ──────────────────────────────────────────────────────────────
// Quota and alert decision (pure)
// ──────────────────────────────────────────────────────────────

/// The quota in bytes (MiB based, as everywhere in the panel).
pub fn quota_bytes(quota_mb: i32) -> i64 {
    i64::from(quota_mb) * BYTES_PER_MB
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaLevel {
    /// No quota, no measurement, or under 90 %.
    Ok,
    /// 90 % <= usage < 100 %.
    Warning,
    /// Usage at or over the quota.
    Critical,
}

impl QuotaLevel {
    pub fn severity(self) -> Option<&'static str> {
        match self {
            QuotaLevel::Ok => None,
            QuotaLevel::Warning => Some("warning"),
            QuotaLevel::Critical => Some("critical"),
        }
    }
}

/// B-4: `pct = bytes / (quota_mb * 1048576)`; warning from 0.90, critical from 1.0.
/// Integer arithmetic, so the edges are exact.
pub fn quota_level(bytes: Option<i64>, quota_mb: Option<i32>) -> QuotaLevel {
    let (Some(bytes), Some(quota_mb)) = (bytes, quota_mb) else {
        return QuotaLevel::Ok;
    };
    if quota_mb <= 0 {
        return QuotaLevel::Ok;
    }
    let used = i128::from(bytes.max(0));
    let quota = i128::from(quota_bytes(quota_mb));
    if used >= quota {
        QuotaLevel::Critical
    } else if used * 10 >= quota * 9 {
        QuotaLevel::Warning
    } else {
        QuotaLevel::Ok
    }
}

/// Usage as a whole percentage of the quota, rounded down (99.9 % reads 99 %).
pub fn usage_percent(bytes: i64, quota_mb: i32) -> i64 {
    let quota = i128::from(quota_bytes(quota_mb.max(1)));
    ((i128::from(bytes.max(0)) * 100) / quota).min(i128::from(i64::MAX)) as i64
}

/// What to do with the site's alert, given the severity of its open one (firing or
/// acknowledged) and the level just computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertAction {
    /// The state did not change: nothing is sent again.
    Nothing,
    Fire(&'static str),
    /// The severity changed: the old alert is closed and the new one fired.
    Replace(&'static str),
    Resolve,
}

pub fn alert_action(open_severity: Option<&str>, level: QuotaLevel) -> AlertAction {
    match (open_severity, level.severity()) {
        (None, None) => AlertAction::Nothing,
        (Some(_), None) => AlertAction::Resolve,
        (None, Some(sev)) => AlertAction::Fire(sev),
        (Some(open), Some(sev)) if open == sev => AlertAction::Nothing,
        (Some(_), Some(sev)) => AlertAction::Replace(sev),
    }
}

/// A size in base 1024 with one decimal, without a trailing `.0`: `2.3 GB`, `2 GB`.
pub fn fmt_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes.max(0) as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{} B", bytes.max(0));
    }
    let s = format!("{v:.1}");
    let s = s.strip_suffix(".0").unwrap_or(&s);
    format!("{s} {}", UNITS[unit])
}

/// `(title, message)` of a firing alert.
pub fn alert_text(level: QuotaLevel, domain: &str, bytes: i64, quota_mb: i32) -> (String, String) {
    let used = fmt_size(bytes);
    let quota = fmt_size(quota_bytes(quota_mb));
    match level {
        QuotaLevel::Critical => (
            format!("Disk quota exceeded on {domain} ({used} of {quota})"),
            format!(
                "The files of {domain} use {used}, over its disk quota of {quota}. \
                 Nothing is blocked: the quota is an alert limit."
            ),
        ),
        _ => (
            format!("Disk usage of {domain} at {}% of quota", usage_percent(bytes, quota_mb)),
            format!("The files of {domain} use {used} of its disk quota of {quota}."),
        ),
    }
}

/// Sites grouped by server, in a stable order. Sites without a server or with a
/// domain the agent would refuse are left out.
pub fn group_by_server(sites: &[(Uuid, Option<Uuid>, String)]) -> BTreeMap<Uuid, Vec<(Uuid, String)>> {
    let mut out: BTreeMap<Uuid, Vec<(Uuid, String)>> = BTreeMap::new();
    for (site_id, server_id, domain) in sites {
        let Some(server_id) = server_id else { continue };
        if !crate::routes::is_valid_domain(domain) {
            continue;
        }
        out.entry(*server_id).or_default().push((*site_id, domain.clone()));
    }
    out
}

/// One entry of A-5's `results`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub domain: String,
    pub bytes: Option<i64>,
    pub files: Option<i64>,
    pub error: Option<String>,
}

pub fn parse_results(v: &Value) -> Vec<Measurement> {
    let num = |item: &Value, k: &str| {
        item.get(k).and_then(|x| x.as_u64().map(|n| n.min(i64::MAX as u64) as i64).or_else(|| x.as_i64()))
    };
    v.get("results")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let domain = item.get("domain")?.as_str()?.trim().to_ascii_lowercase();
            let error = item
                .get("error")
                .and_then(|e| e.as_str())
                .map(|e| e.chars().take(300).collect::<String>())
                .filter(|e| !e.trim().is_empty());
            let (bytes, files) = (num(item, "bytes"), num(item, "files"));
            // A result without a size is a failure, whatever it says.
            let error = match (&error, bytes) {
                (None, None) => Some("No size reported".to_string()),
                _ => error,
            };
            Some(Measurement { domain, bytes, files, error })
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────
// One measurement at a time per site
// ──────────────────────────────────────────────────────────────

static IN_FLIGHT: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Sites being measured by this guard; released when it is dropped (also when a
/// request is abandoned by its client).
pub struct MeasureGuard {
    ids: Vec<Uuid>,
}

impl MeasureGuard {
    /// Claims the given sites that no other measurement holds.
    pub fn claim(ids: &[Uuid]) -> Self {
        let mut set = IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        let ids = ids.iter().copied().filter(|id| set.insert(*id)).collect();
        MeasureGuard { ids }
    }

    pub fn holds(&self, id: Uuid) -> bool {
        self.ids.contains(&id)
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

impl Drop for MeasureGuard {
    fn drop(&mut self) {
        let mut set = IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        for id in &self.ids {
            set.remove(id);
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Database
// ──────────────────────────────────────────────────────────────

/// The last measurement of each of these sites.
pub async fn load_disk_usage(db: &PgPool, ids: &[Uuid]) -> HashMap<Uuid, DiskUsage> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let rows: Vec<(Uuid, Option<i64>, Option<i64>, chrono::DateTime<chrono::Utc>, Option<String>)> =
        match sqlx::query_as(
            "SELECT site_id, bytes, files, measured_at, error FROM site_disk_usage WHERE site_id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(db)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Could not read site disk usage: {e}");
                Vec::new()
            }
        };
    rows.into_iter()
        .map(|(id, bytes, files, measured_at, error)| (id, DiskUsage { bytes, files, measured_at, error }))
        .collect()
}

/// Fill the response-only `disk_usage` field of these sites in one query.
pub async fn fill_disk_usage(db: &PgPool, sites: &mut [Site]) {
    let ids: Vec<Uuid> = sites.iter().map(|s| s.id).collect();
    let mut usage = load_disk_usage(db, &ids).await;
    for s in sites.iter_mut() {
        s.disk_usage = usage.remove(&s.id);
    }
}

/// Upsert one result. A failed measurement keeps the last known size (and its
/// date) and only records why it failed.
async fn record(pool: &PgPool, site_id: Uuid, m: &Measurement) -> Result<(), sqlx::Error> {
    if m.error.is_none() {
        sqlx::query(
            "INSERT INTO site_disk_usage (site_id, bytes, files, measured_at, error) \
             VALUES ($1, $2, $3, now(), NULL) \
             ON CONFLICT (site_id) DO UPDATE SET bytes = EXCLUDED.bytes, files = EXCLUDED.files, \
             measured_at = now(), error = NULL",
        )
        .bind(site_id)
        .bind(m.bytes)
        .bind(m.files)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO site_disk_usage (site_id, bytes, files, measured_at, error) \
             VALUES ($1, NULL, NULL, now(), $2) \
             ON CONFLICT (site_id) DO UPDATE SET error = EXCLUDED.error",
        )
        .bind(site_id)
        .bind(&m.error)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Measure these sites of one server (chunks of [`MAX_DOMAINS_PER_CALL`]), record
/// every result and recompute the alerts of the sites that got one. Returns the
/// number of results recorded; the first agent failure stops the remaining chunks.
pub async fn measure_sites(pool: &PgPool, agent: &AgentHandle, sites: &[(Uuid, String)]) -> Result<usize, AgentError> {
    let mut recorded = 0;
    for chunk in sites.chunks(MAX_DOMAINS_PER_CALL) {
        let by_domain: HashMap<String, Uuid> =
            chunk.iter().map(|(id, d)| (d.to_ascii_lowercase(), *id)).collect();
        let domains: Vec<&str> = chunk.iter().map(|(_, d)| d.as_str()).collect();
        let v = agent
            .post_long("/disk-usage", Some(json!({ "domains": domains })), MEASURE_TIMEOUT_SECS)
            .await?;
        for m in parse_results(&v) {
            let Some(site_id) = by_domain.get(&m.domain).copied() else { continue };
            match record(pool, site_id, &m).await {
                Ok(()) => {
                    recorded += 1;
                    refresh_site_alert(pool, site_id).await;
                }
                Err(e) => tracing::warn!("Disk usage: could not record {}: {e}", m.domain),
            }
        }
    }
    Ok(recorded)
}

/// Fire, replace or resolve the site's `disk_quota` alert from its quota and last
/// measurement (B-4). Nothing is sent again while the state does not change.
pub async fn refresh_site_alert(pool: &PgPool, site_id: Uuid) {
    let row: Option<(String, Uuid, Option<i32>, Option<i64>)> = match sqlx::query_as(
        "SELECT s.domain, s.user_id, s.disk_quota_mb, du.bytes FROM sites s \
         LEFT JOIN site_disk_usage du ON du.site_id = s.id WHERE s.id = $1",
    )
    .bind(site_id)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Disk usage: could not read site {site_id}: {e}");
            return;
        }
    };
    let Some((domain, owner, quota_mb, bytes)) = row else { return };
    let key = format!("{ALERT_DISK_QUOTA}:{site_id}");

    let open: Option<(String,)> = match sqlx::query_as(
        "SELECT severity FROM alerts WHERE alert_type = $1 AND site_id = $2 AND state_key = $3 \
         AND status IN ('firing', 'acknowledged') ORDER BY created_at DESC LIMIT 1",
    )
    .bind(ALERT_DISK_QUOTA)
    .bind(site_id)
    .bind(&key)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Unknown state: doing nothing is safer than paging twice.
            tracing::warn!("Disk usage: could not read the open alert of {domain}: {e}");
            return;
        }
    };

    let level = quota_level(bytes, quota_mb);
    match alert_action(open.as_ref().map(|(s,)| s.as_str()), level) {
        AlertAction::Nothing => {}
        AlertAction::Resolve => {
            notifications::resolve_alert(
                pool,
                owner,
                None,
                Some(site_id),
                ALERT_DISK_QUOTA,
                &key,
                &format!("Disk quota alert resolved: {domain}"),
                &format!("The files of {domain} are back under 90% of the disk quota, or the quota was removed."),
            )
            .await;
            close_open_rows(pool, site_id, &key).await;
        }
        AlertAction::Fire(sev) | AlertAction::Replace(sev) => {
            // A change of severity closes the old alert without a "resolved" notice:
            // the condition is not over, only its level changed.
            close_open_rows(pool, site_id, &key).await;
            let (Some(bytes), Some(quota_mb)) = (bytes, quota_mb) else { return };
            let (title, message) = alert_text(level, &domain, bytes, quota_mb);
            notifications::fire_alert(pool, owner, None, Some(site_id), ALERT_DISK_QUOTA, &key, sev, &title, &message)
                .await;
        }
    }
}

/// Close (silently) every open `disk_quota` alert of the site, acknowledged ones
/// included: an acknowledged alert would otherwise keep standing for a state that
/// is over.
async fn close_open_rows(pool: &PgPool, site_id: Uuid, key: &str) {
    if let Err(e) = sqlx::query(
        "UPDATE alerts SET status = 'resolved', resolved_at = NOW() \
         WHERE alert_type = $1 AND site_id = $2 AND state_key = $3 AND status IN ('firing', 'acknowledged')",
    )
    .bind(ALERT_DISK_QUOTA)
    .bind(site_id)
    .bind(key)
    .execute(pool)
    .await
    {
        tracing::warn!("Disk usage: could not close the open quota alerts of site {site_id}: {e}");
    }
}

// ──────────────────────────────────────────────────────────────
// The task
// ──────────────────────────────────────────────────────────────

pub async fn run(pool: PgPool, agents: AgentRegistry, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Disk usage background task started");
    tokio::select! {
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
        _ = shutdown_rx.recv() => return,
    }
    loop {
        cycle(&pool, &agents).await;
        tokio::select! {
            _ = tokio::time::sleep(EVERY) => {}
            _ = shutdown_rx.recv() => {
                tracing::info!("Disk usage task shutting down");
                return;
            }
        }
    }
}

async fn cycle(pool: &PgPool, agents: &AgentRegistry) {
    let sites: Vec<(Uuid, Option<Uuid>, String)> = match sqlx::query_as(
        "SELECT s.id, s.server_id, s.domain FROM sites s JOIN servers sv ON sv.id = s.server_id \
         WHERE sv.status = 'online' ORDER BY s.domain",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Disk usage: could not list the sites: {e}");
            return;
        }
    };
    for (server_id, sites) in group_by_server(&sites) {
        let agent = match agents.for_server(server_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("Disk usage: server {server_id} skipped ({e})");
                continue;
            }
        };
        // Sites a manual refresh is measuring right now are left to it.
        let ids: Vec<Uuid> = sites.iter().map(|(id, _)| *id).collect();
        let guard = MeasureGuard::claim(&ids);
        let todo: Vec<(Uuid, String)> = sites.into_iter().filter(|(id, _)| guard.holds(*id)).collect();
        if todo.is_empty() {
            continue;
        }
        match measure_sites(pool, &agent, &todo).await {
            Ok(n) => tracing::info!("Disk usage: {n} site(s) measured on server {server_id}"),
            Err(AgentError::Status(404, _)) => {
                tracing::debug!("Disk usage: the agent of server {server_id} does not measure disk usage yet")
            }
            Err(e) => tracing::warn!("Disk usage: server {server_id} skipped this cycle: {e}"),
        }
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: i64 = 1024 * 1024 * 1024;

    #[test]
    fn quota_is_mebibytes() {
        assert_eq!(quota_bytes(1), 1_048_576);
        assert_eq!(quota_bytes(2048), 2 * GB);
        // No overflow at the top of the column's range.
        assert_eq!(quota_bytes(i32::MAX), i64::from(i32::MAX) * 1_048_576);
    }

    #[test]
    fn thresholds_are_exact() {
        let q = Some(1000); // 1000 MiB
        let mb = BYTES_PER_MB;
        assert_eq!(quota_level(Some(899 * mb), q), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(900 * mb - 1), q), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(900 * mb), q), QuotaLevel::Warning);
        assert_eq!(quota_level(Some(1000 * mb - 1), q), QuotaLevel::Warning);
        assert_eq!(quota_level(Some(1000 * mb), q), QuotaLevel::Critical);
        assert_eq!(quota_level(Some(5000 * mb), q), QuotaLevel::Critical);
    }

    #[test]
    fn no_quota_or_no_measurement_is_ok() {
        assert_eq!(quota_level(None, Some(10)), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(i64::MAX), None), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(10 * GB), Some(0)), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(-5), Some(1)), QuotaLevel::Ok);
        assert_eq!(quota_level(Some(i64::MAX), Some(i32::MAX)), QuotaLevel::Critical);
    }

    #[test]
    fn the_state_decides_what_is_sent() {
        use AlertAction::*;
        assert_eq!(alert_action(None, QuotaLevel::Ok), Nothing);
        assert_eq!(alert_action(None, QuotaLevel::Warning), Fire("warning"));
        assert_eq!(alert_action(None, QuotaLevel::Critical), Fire("critical"));
        // Unchanged: nothing sent again, acknowledged or not.
        assert_eq!(alert_action(Some("warning"), QuotaLevel::Warning), Nothing);
        assert_eq!(alert_action(Some("critical"), QuotaLevel::Critical), Nothing);
        // Severity change: the old one is closed, the new one fired.
        assert_eq!(alert_action(Some("warning"), QuotaLevel::Critical), Replace("critical"));
        assert_eq!(alert_action(Some("critical"), QuotaLevel::Warning), Replace("warning"));
        // Back under 90 %, quota removed or no size: resolved.
        assert_eq!(alert_action(Some("critical"), QuotaLevel::Ok), Resolve);
        assert_eq!(alert_action(Some("warning"), quota_level(None, Some(1))), Resolve);
        assert_eq!(alert_action(Some("warning"), quota_level(Some(GB), None)), Resolve);
    }

    #[test]
    fn sizes_read_like_the_contract() {
        assert_eq!(fmt_size(0), "0 B");
        assert_eq!(fmt_size(1023), "1023 B");
        assert_eq!(fmt_size(1024), "1 KB");
        assert_eq!(fmt_size(1536), "1.5 KB");
        assert_eq!(fmt_size(2 * GB), "2 GB");
        assert_eq!(fmt_size(GB * 23 / 10), "2.3 GB");
        assert_eq!(fmt_size(3 * 1024 * GB), "3 TB");
    }

    #[test]
    fn titles_match_the_contract() {
        let (t, _) = alert_text(QuotaLevel::Critical, "x.tld", GB * 23 / 10, 2048);
        assert_eq!(t, "Disk quota exceeded on x.tld (2.3 GB of 2 GB)");
        let (t, m) = alert_text(QuotaLevel::Warning, "x.tld", 2048 * BYTES_PER_MB * 92 / 100 + 1, 2048);
        assert_eq!(t, "Disk usage of x.tld at 92% of quota");
        assert!(m.contains("of its disk quota of 2 GB"), "{m}");
        // 99.9 % is not shown as 100 % while it is still a warning.
        assert_eq!(usage_percent(1000 * BYTES_PER_MB - 1, 1000), 99);
    }

    #[test]
    fn sites_are_grouped_by_server() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (s1, s2, s3, s4, s5) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let sites = vec![
            (s1, Some(a), "one.tld".to_string()),
            (s2, Some(b), "two.tld".to_string()),
            (s3, Some(a), "three.tld".to_string()),
            (s4, None, "orphan.tld".to_string()),
            (s5, Some(a), "../etc".to_string()),
        ];
        let g = group_by_server(&sites);
        assert_eq!(g.len(), 2);
        assert_eq!(g[&a], vec![(s1, "one.tld".to_string()), (s3, "three.tld".to_string())]);
        assert_eq!(g[&b], vec![(s2, "two.tld".to_string())]);
    }

    #[test]
    fn agent_results_are_parsed() {
        let v = json!({ "results": [
            { "domain": "A.tld", "bytes": 4096, "files": 3, "error": null },
            { "domain": "gone.tld", "bytes": null, "files": null, "error": "Site directory not found" },
            { "domain": "odd.tld" },
            { "bytes": 1 }
        ]});
        let r = parse_results(&v);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], Measurement { domain: "a.tld".into(), bytes: Some(4096), files: Some(3), error: None });
        assert_eq!(r[1].error.as_deref(), Some("Site directory not found"));
        assert_eq!(r[1].bytes, None);
        assert_eq!(r[2].error.as_deref(), Some("No size reported"));
        assert!(parse_results(&json!({})).is_empty());
    }

    #[test]
    fn a_site_is_measured_once_at_a_time() {
        let (x, y) = (Uuid::new_v4(), Uuid::new_v4());
        let first = MeasureGuard::claim(&[x]);
        assert!(first.holds(x));
        let second = MeasureGuard::claim(&[x, y]);
        assert!(!second.holds(x) && second.holds(y));
        assert!(MeasureGuard::claim(&[x]).is_empty());
        drop(first);
        assert!(MeasureGuard::claim(&[x]).holds(x));
        drop(second);
    }
}
