//! CVE scanner, batch 1 (engine): the background sweeper.
//!
//! Every 30 minutes, for each online server in turn: make sure grype and syft
//! are installed at the versions the agent expects, sync the scan targets
//! (active sites from the database, images and the host system from the
//! agent), refresh the SBOMs that are stale, update the vulnerability database
//! once a day, match the SBOMs that need it and merge the findings into
//! `vuln_findings`. The heavy work runs as agent jobs (`/vulns/*`, polled
//! through `GET /jobs/{id}`); SBOMs never leave the server.
//!
//! One server failing never stops the others: its error is logged, stored in
//! `vuln_server_state.last_error`, and the sweep moves on. A per-server lock in
//! memory keeps the sweeper and the "scan now" button from running two passes
//! on the same server at once.
//!
//! Contract: conception/13-scanner-cve-lot1-contrat.md.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

use crate::services::agent::{AgentError, AgentHandle, AgentRegistry};
use crate::services::av_scanner::valid_job_id;
use crate::services::import_types::{JobPoll, classify_job};
use crate::services::security_hardening::{get_setting_bool, get_setting_i64};

const STARTUP_DELAY: Duration = Duration::from_secs(5 * 60);
const CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);
const JOB_POLL_INTERVAL: Duration = Duration::from_secs(5);
const INSTALL_CAP: Duration = Duration::from_secs(30 * 60);
const DB_UPDATE_CAP: Duration = Duration::from_secs(30 * 60);
const INVENTORY_CAP: Duration = Duration::from_secs(2 * 3600);
const MATCH_CAP: Duration = Duration::from_secs(2 * 3600);
/// A job whose agent fails every poll for this long is given up.
const AGENT_UNREACHABLE_LIMIT: Duration = Duration::from_secs(5 * 60);
/// Targets per match job: a report carries up to 5000 findings per target and
/// an agent response is capped at 50 MB (`services::agent::MAX_RESPONSE_SIZE`).
const MATCH_CHUNK: usize = 5;
/// An SBOM older than this is rebuilt even if its fingerprint did not change.
const SBOM_MAX_AGE_DAYS: i64 = 7;

pub const SETTING_ENABLED: &str = "vuln_scan_enabled";
pub const SETTING_MATCH_HOUR: &str = "vuln_match_hour";
pub const DEFAULT_MATCH_HOUR: i64 = 4;

/// Target kinds this batch inventories. `wordpress` (batch 4) is left alone by
/// the sync so a later batch can own it.
const SYNCED_KINDS: &[&str] = &["site", "image", "system"];

// Column widths of `vuln_findings` / `vuln_targets` (migration 20261201000000).
const W_VULN_ID: usize = 64;
const W_PACKAGE: usize = 256;
const W_VERSION: usize = 128;
const W_PKG_TYPE: usize = 32;
const W_FIXED_VERSION: usize = 128;
const W_REF: usize = 512;
const W_APP_NAME: usize = 128;
const MAX_ALIASES: usize = 32;
const MAX_TEXT: usize = 2048;

// ── Errors and shared state ─────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum PassError {
    /// The panel is shutting down: stop at once, record nothing.
    Shutdown,
    Failed(String),
}

impl From<sqlx::Error> for PassError {
    fn from(e: sqlx::Error) -> Self {
        PassError::Failed(format!("database error: {e}"))
    }
}

static SERVER_LOCKS: LazyLock<Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static QUEUED_SCANS: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// The lock serialising passes on one server (sweeper and "scan now").
fn server_lock(server_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = SERVER_LOCKS.lock().unwrap_or_else(|p| p.into_inner());
    map.entry(server_id).or_default().clone()
}

/// Marks a target as queued for an on-demand scan. False when it already is.
pub fn try_queue_scan(target_id: Uuid) -> bool {
    QUEUED_SCANS.lock().unwrap_or_else(|p| p.into_inner()).insert(target_id)
}

fn unqueue_scan(target_id: Uuid) {
    QUEUED_SCANS.lock().unwrap_or_else(|p| p.into_inner()).remove(&target_id);
}

// ── Pure helpers: wire format ───────────────────────────────────────────

/// Cuts `s` to at most `max` characters, on a character boundary.
pub fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

fn opt_text(v: &Value, key: &str, max: usize) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| clip(s, max))
}

fn opt_f32(v: &Value, key: &str) -> Option<f32> {
    v.get(key).and_then(|x| x.as_f64()).filter(|x| x.is_finite()).map(|x| x as f32)
}

fn parse_time(v: Option<&Value>) -> Option<DateTime<Utc>> {
    v.and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

/// Severity as stored: grype's `negligible` reads as `low`, anything unknown as `unknown`.
pub fn normalize_severity(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" | "negligible" => "low",
        _ => "unknown",
    }
}

pub fn normalize_fix_state(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "fixed" => "fixed",
        "not-fixed" => "not-fixed",
        "wont-fix" => "wont-fix",
        _ => "unknown",
    }
}

/// One CVE found in one component, as the agent reports it (contract `Finding`),
/// already cut to the column widths so the merge key is the stored key.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub version: String,
    pub pkg_type: Option<String>,
    pub location: Option<String>,
    pub severity: String,
    pub cvss: Option<f32>,
    pub kev: bool,
    pub kev_ransomware: bool,
    pub epss: Option<f32>,
    pub epss_percentile: Option<f32>,
    pub risk: Option<f32>,
    pub fix_state: String,
    pub fixed_version: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
}

impl Finding {
    fn key(&self) -> (String, String, String) {
        (self.vuln_id.clone(), self.package.clone(), self.version.clone())
    }
}

/// Reads one finding; `None` when it has no vulnerability id or no package.
pub fn parse_finding(v: &Value) -> Option<Finding> {
    let vuln_id = opt_text(v, "vuln_id", W_VULN_ID)?;
    let package = opt_text(v, "package", W_PACKAGE)?;
    let version = opt_text(v, "version", W_VERSION).unwrap_or_default();
    let mut aliases: Vec<String> = Vec::new();
    if let Some(arr) = v.get("aliases").and_then(|a| a.as_array()) {
        for a in arr.iter().filter_map(|x| x.as_str()) {
            let a = clip(a.trim(), W_VULN_ID);
            if !a.is_empty() && a != vuln_id && !aliases.contains(&a) && aliases.len() < MAX_ALIASES {
                aliases.push(a);
            }
        }
    }
    let flag = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    Some(Finding {
        vuln_id,
        aliases,
        package,
        version,
        pkg_type: opt_text(v, "pkg_type", W_PKG_TYPE),
        location: opt_text(v, "location", MAX_TEXT),
        severity: normalize_severity(v.get("severity").and_then(|x| x.as_str()).unwrap_or("")).to_string(),
        cvss: opt_f32(v, "cvss"),
        kev: flag("kev"),
        kev_ransomware: flag("kev_ransomware"),
        epss: opt_f32(v, "epss"),
        epss_percentile: opt_f32(v, "epss_percentile"),
        risk: opt_f32(v, "risk"),
        fix_state: normalize_fix_state(v.get("fix_state").and_then(|x| x.as_str()).unwrap_or("")).to_string(),
        fixed_version: opt_text(v, "fixed_version", W_FIXED_VERSION),
        title: opt_text(v, "title", MAX_TEXT),
        url: opt_text(v, "url", MAX_TEXT),
    })
}

/// One target's result in a `/vulns/match` report.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    pub target_id: Uuid,
    /// `ok`, `no_sbom` or `error` (anything else is treated as `error`).
    pub status: String,
    pub error: Option<String>,
    pub truncated: bool,
    pub findings: Vec<Finding>,
}

/// Reads a `/vulns/match` report: the database build time and one result per target.
pub fn parse_match_report(v: &Value) -> (Option<DateTime<Utc>>, Vec<MatchResult>) {
    let built = parse_time(v.get("db_built"));
    let mut out = Vec::new();
    for r in v.get("results").and_then(|x| x.as_array()).into_iter().flatten() {
        let Some(target_id) = r.get("target_id").and_then(|x| x.as_str()).and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        let findings = r
            .get("findings")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(parse_finding).collect())
            .unwrap_or_default();
        out.push(MatchResult {
            target_id,
            status: r.get("status").and_then(|x| x.as_str()).unwrap_or("error").to_string(),
            error: opt_text(r, "error", MAX_TEXT),
            truncated: r.get("truncated").and_then(|x| x.as_bool()).unwrap_or(false),
            findings,
        });
    }
    (built, out)
}

/// One target's result in a `/vulns/inventory` report.
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryResult {
    pub target_id: Uuid,
    /// `updated`, `unchanged` or `error`.
    pub status: String,
    pub fingerprint: Option<String>,
    pub sbom_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

pub fn parse_inventory_report(v: &Value) -> Vec<InventoryResult> {
    let mut out = Vec::new();
    for r in v.get("results").and_then(|x| x.as_array()).into_iter().flatten() {
        let Some(target_id) = r.get("target_id").and_then(|x| x.as_str()).and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        out.push(InventoryResult {
            target_id,
            status: r.get("status").and_then(|x| x.as_str()).unwrap_or("error").to_string(),
            fingerprint: opt_text(r, "fingerprint", MAX_TEXT),
            sbom_at: parse_time(r.get("sbom_at")),
            error: opt_text(r, "error", MAX_TEXT),
        });
    }
    out
}

fn bare_version(s: &str) -> &str {
    s.trim().trim_start_matches('v')
}

/// True when `/vulns/status` says a tool is missing, is not at the version the
/// agent itself expects, or the vulnerability database is absent.
pub fn needs_install(status: &Value) -> bool {
    let tool_ok = |name: &str| {
        let t = &status[name];
        if !t["installed"].as_bool().unwrap_or(false) {
            return false;
        }
        match status["expected"][name].as_str() {
            Some(want) => t["version"].as_str().map(bare_version) == Some(bare_version(want)),
            None => true,
        }
    };
    !tool_ok("grype") || !tool_ok("syft") || status.get("db").is_none_or(|d| d.is_null())
}

/// `{grype, syft}` versions as stored in `vuln_server_state.installed_versions`.
fn installed_versions(status: &Value) -> Value {
    json!({ "grype": status["grype"]["version"], "syft": status["syft"]["version"] })
}

// ── Pure helpers: planning ──────────────────────────────────────────────

/// A target the server should have, before it is stored.
#[derive(Debug, Clone, PartialEq)]
pub struct DesiredTarget {
    pub kind: String,
    pub ref_: String,
    pub site_id: Option<Uuid>,
    pub git_deploy_id: Option<Uuid>,
    pub app_name: Option<String>,
    pub exposed: Option<bool>,
    /// Images only: the image id the agent sees now (the stored fingerprint).
    pub image_id: Option<String>,
}

/// A stored target as the sync sees it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ExistingTarget {
    pub id: Uuid,
    pub kind: String,
    #[sqlx(rename = "ref")]
    pub ref_: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct SyncPlan {
    /// Targets to insert or refresh, with "mark for a new inventory".
    pub upserts: Vec<(DesiredTarget, bool)>,
    /// Stored targets the server no longer has.
    pub deletes: Vec<Uuid>,
}

/// Desired targets vs stored targets, keyed on `(kind, ref)`.
///
/// Only the kinds this batch owns are deleted. An image whose id differs from
/// the stored fingerprint is marked for a new inventory.
pub fn plan_target_sync(desired: &[DesiredTarget], existing: &[ExistingTarget]) -> SyncPlan {
    let by_key: HashMap<(&str, &str), &ExistingTarget> =
        existing.iter().map(|e| ((e.kind.as_str(), e.ref_.as_str()), e)).collect();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut plan = SyncPlan::default();
    for d in desired {
        if !seen.insert((d.kind.clone(), d.ref_.clone())) {
            continue;
        }
        let changed = match by_key.get(&(d.kind.as_str(), d.ref_.as_str())) {
            None => true,
            Some(e) => {
                d.kind == "image"
                    && matches!((&e.fingerprint, &d.image_id), (Some(old), Some(new)) if old != new)
            }
        };
        plan.upserts.push((d.clone(), changed));
    }
    for e in existing {
        if SYNCED_KINDS.contains(&e.kind.as_str()) && !seen.contains(&(e.kind.clone(), e.ref_.clone())) {
            plan.deletes.push(e.id);
        }
    }
    plan
}

/// Image targets from `GET /vulns/targets`. `git_ids` maps a git deploy name
/// on this server to its id.
pub fn image_targets_from_agent(v: &Value, git_ids: &HashMap<String, Uuid>) -> Vec<DesiredTarget> {
    let mut out = Vec::new();
    for img in v.get("images").and_then(|x| x.as_array()).into_iter().flatten() {
        let image = img.get("image").and_then(|x| x.as_str()).map(str::trim).unwrap_or("");
        let image_id = img.get("image_id").and_then(|x| x.as_str()).map(str::trim).unwrap_or("");
        if image.is_empty() || image_id.is_empty() || image.chars().count() > W_REF {
            continue;
        }
        let containers: Vec<&Value> =
            img.get("containers").and_then(|x| x.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
        let app_name = containers
            .iter()
            .find_map(|c| c.get("app_name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()))
            .map(|s| clip(s, W_APP_NAME));
        let git_deploy_id = containers
            .iter()
            .find_map(|c| c.get("git_name").and_then(|x| x.as_str()).and_then(|n| git_ids.get(n)).copied());
        let exposed = containers.iter().any(|c| {
            c.get("domain").and_then(|x| x.as_str()).is_some_and(|d| !d.is_empty())
                || c.get("public_port").and_then(|x| x.as_bool()).unwrap_or(false)
        });
        out.push(DesiredTarget {
            kind: "image".into(),
            ref_: image.to_string(),
            site_id: None,
            git_deploy_id,
            app_name,
            exposed: Some(exposed),
            image_id: Some(image_id.to_string()),
        });
    }
    out
}

/// A stored target as inventory and match selection see it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct TargetState {
    pub id: Uuid,
    pub kind: String,
    #[sqlx(rename = "ref")]
    pub ref_: String,
    pub fingerprint: Option<String>,
    pub sbom_at: Option<DateTime<Utc>>,
    pub matched_at: Option<DateTime<Utc>>,
    pub needs_inventory: bool,
}

/// Targets to inventory now, with `force`: marked ones, and ones whose SBOM is
/// missing or older than a week. A stale SBOM is forced, or the agent would
/// answer `unchanged` and it would stay stale.
pub fn select_inventory(targets: &[TargetState], now: DateTime<Utc>) -> Vec<(Uuid, bool)> {
    let max_age = chrono::Duration::days(SBOM_MAX_AGE_DAYS);
    targets
        .iter()
        .filter(|t| SYNCED_KINDS.contains(&t.kind.as_str()))
        .filter_map(|t| {
            let stale = t.sbom_at.is_none_or(|at| now - at > max_age);
            (t.needs_inventory || stale).then_some((t.id, stale))
        })
        .collect()
}

/// The most recent `hour:00` UTC at or before `now`.
fn last_slot(now: DateTime<Utc>, hour: u32) -> DateTime<Utc> {
    let hour = hour.min(23);
    let today = now.date_naive().and_hms_opt(hour, 0, 0).unwrap_or_else(|| now.naive_utc());
    let today = Utc.from_utc_datetime(&today);
    if now >= today { today } else { today - chrono::Duration::days(1) }
}

/// True when the database has not been updated since the last daily slot.
pub fn db_update_due(checked: Option<DateTime<Utc>>, now: DateTime<Utc>, hour: u32) -> bool {
    checked.is_none_or(|c| c < last_slot(now, hour))
}

/// Targets to match: all with an SBOM after a database update (`full`);
/// otherwise those whose SBOM is newer than their last match, never matched, or
/// last matched before the current database (a failed full match is retried).
pub fn select_match(targets: &[TargetState], full: bool, db_checked_at: Option<DateTime<Utc>>) -> Vec<Uuid> {
    targets
        .iter()
        .filter(|t| SYNCED_KINDS.contains(&t.kind.as_str()))
        .filter(|t| match (t.sbom_at, t.matched_at) {
            (None, _) => false,
            (Some(_), _) if full => true,
            (Some(_), None) => true,
            (Some(sbom), Some(matched)) => sbom > matched || db_checked_at.is_some_and(|d| matched < d),
        })
        .map(|t| t.id)
        .collect()
}

/// A stored finding as the merge sees it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ExistingFinding {
    pub id: Uuid,
    pub vuln_id: String,
    pub package: String,
    pub version: String,
    pub resolved: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct MergePlan {
    /// New findings (`first_seen = now`).
    pub insert: Vec<Finding>,
    /// Open findings seen again (`last_seen = now`, fields refreshed).
    pub update: Vec<(Uuid, Finding)>,
    /// Resolved findings that came back (`resolved_at = NULL`, `first_seen = now`, `notified = false`).
    pub reopen: Vec<(Uuid, Finding)>,
    /// Open findings absent from the result (`resolved_at = now`).
    pub resolve: Vec<Uuid>,
}

/// Merges one target's match result into its stored findings.
///
/// Only a complete `ok` result can resolve anything: `error` and `no_sbom`
/// leave everything as it is, and a truncated result (capped at 5000 by the
/// agent) adds and refreshes but does not resolve, since what it lacks may
/// simply be past the cap.
pub fn plan_merge(existing: &[ExistingFinding], result: &MatchResult) -> MergePlan {
    let mut plan = MergePlan::default();
    if result.status != "ok" {
        return plan;
    }
    let by_key: HashMap<(String, String, String), &ExistingFinding> = existing
        .iter()
        .map(|e| ((e.vuln_id.clone(), e.package.clone(), e.version.clone()), e))
        .collect();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    for f in &result.findings {
        let key = f.key();
        if !seen.insert(key.clone()) {
            continue;
        }
        match by_key.get(&key) {
            None => plan.insert.push(f.clone()),
            Some(e) if e.resolved => plan.reopen.push((e.id, f.clone())),
            Some(e) => plan.update.push((e.id, f.clone())),
        }
    }
    if !result.truncated {
        for e in existing {
            if !e.resolved && !seen.contains(&(e.vuln_id.clone(), e.package.clone(), e.version.clone())) {
                plan.resolve.push(e.id);
            }
        }
    }
    plan
}

// ── Agent jobs ──────────────────────────────────────────────────────────

fn agent_failure(what: &str, e: AgentError) -> PassError {
    match e {
        AgentError::Status(404, _) => {
            PassError::Failed(format!("{what}: the agent does not support vulnerability scanning (update the agent)"))
        }
        e => PassError::Failed(format!("{what}: {e}")),
    }
}

/// Starts an agent job and returns its id.
async fn start_job(agent: &AgentHandle, path: &str, body: Option<Value>) -> Result<String, PassError> {
    let v = agent.post(path, body).await.map_err(|e| agent_failure(path, e))?;
    let id = v.get("job_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if !valid_job_id(&id) {
        return Err(PassError::Failed(format!("{path}: the agent returned no valid job id")));
    }
    Ok(id)
}

/// Polls `GET /jobs/{id}` until the job ends, the cap passes or the panel stops.
async fn wait_job(
    agent: &AgentHandle,
    job_id: &str,
    cap: Duration,
    shutdown: &mut Receiver<()>,
) -> Result<Value, PassError> {
    let deadline = Instant::now() + cap;
    // Start of the current run of failed polls: an agent gone for good must not
    // hold the sweep (and every other server) until the cap.
    let mut failing_since: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(JOB_POLL_INTERVAL) => {}
            _ = shutdown.recv() => return Err(PassError::Shutdown),
        }
        match agent.get(&format!("/jobs/{job_id}")).await {
            Ok(v) => {
                failing_since = None;
                match classify_job(&v) {
                    JobPoll::Done(report) => return Ok(report),
                    JobPoll::Failed(e) => return Err(PassError::Failed(e)),
                    JobPoll::Running { .. } => {}
                }
            }
            Err(AgentError::Status(404, _)) => {
                return Err(PassError::Failed(
                    "the agent no longer knows this job (it was probably restarted)".into(),
                ));
            }
            Err(e) => {
                let since = *failing_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= AGENT_UNREACHABLE_LIMIT {
                    return Err(PassError::Failed(format!("the agent stopped answering while the job ran: {e}")));
                }
                tracing::debug!("CVE scanner: polling job {job_id}: {e}");
            }
        }
        if Instant::now() >= deadline {
            return Err(PassError::Failed(format!("the job did not finish within {} minutes", cap.as_secs() / 60)));
        }
    }
}

// ── Database writes ─────────────────────────────────────────────────────

const STATE_VERSIONS_SQL: &str = "INSERT INTO vuln_server_state (server_id, installed_versions, db_built) \
     VALUES ($1, $2, $3) ON CONFLICT (server_id) DO UPDATE SET \
     installed_versions = EXCLUDED.installed_versions, \
     db_built = COALESCE(EXCLUDED.db_built, vuln_server_state.db_built)";

const STATE_DB_CHECKED_SQL: &str = "INSERT INTO vuln_server_state (server_id, db_checked_at, db_built) \
     VALUES ($1, now(), $2) ON CONFLICT (server_id) DO UPDATE SET db_checked_at = now(), \
     db_built = COALESCE(EXCLUDED.db_built, vuln_server_state.db_built)";

const STATE_MATCHED_SQL: &str = "INSERT INTO vuln_server_state (server_id, last_match_at, db_built) \
     VALUES ($1, now(), $2) ON CONFLICT (server_id) DO UPDATE SET last_match_at = now(), \
     db_built = COALESCE(EXCLUDED.db_built, vuln_server_state.db_built)";

const STATE_ERROR_SQL: &str = "INSERT INTO vuln_server_state (server_id, last_error) VALUES ($1, $2) \
     ON CONFLICT (server_id) DO UPDATE SET last_error = EXCLUDED.last_error";

const STATE_DB_CHECKED_AT_SQL: &str = "SELECT db_checked_at FROM vuln_server_state WHERE server_id = $1";

const ACTIVE_SITES_SQL: &str = "SELECT id, domain FROM sites WHERE server_id = $1 AND status = 'active'";

const GIT_DEPLOYS_SQL: &str = "SELECT name, id FROM git_deploys WHERE server_id = $1";

const EXISTING_TARGETS_SQL: &str = "SELECT id, kind, ref, fingerprint FROM vuln_targets WHERE server_id = $1";

const UPSERT_TARGET_SQL: &str = "INSERT INTO vuln_targets \
     (server_id, kind, ref, site_id, git_deploy_id, app_name, exposed, needs_inventory) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE) \
     ON CONFLICT (server_id, kind, ref) DO UPDATE SET site_id = EXCLUDED.site_id, \
     git_deploy_id = EXCLUDED.git_deploy_id, app_name = EXCLUDED.app_name, exposed = EXCLUDED.exposed, \
     needs_inventory = vuln_targets.needs_inventory OR $8";

const DELETE_TARGETS_SQL: &str = "DELETE FROM vuln_targets WHERE server_id = $1 AND id = ANY($2)";

const TARGET_STATES_SQL: &str = "SELECT id, kind, ref, fingerprint, sbom_at, matched_at, needs_inventory \
     FROM vuln_targets WHERE server_id = $1";

const INVENTORY_OK_SQL: &str = "UPDATE vuln_targets SET fingerprint = COALESCE($2, fingerprint), \
     sbom_at = COALESCE($3, sbom_at), needs_inventory = FALSE, last_error = NULL WHERE id = $1";

const TARGET_ERROR_SQL: &str = "UPDATE vuln_targets SET last_error = $2 WHERE id = $1";

const TARGET_NO_SBOM_SQL: &str = "UPDATE vuln_targets SET needs_inventory = TRUE, last_error = $2 WHERE id = $1";

/// A failed inventory keeps the target marked, so its error survives a match of the older SBOM.
const INVENTORY_ERROR_SQL: &str = "UPDATE vuln_targets SET needs_inventory = TRUE, last_error = $2 WHERE id = $1";

const TARGET_MATCHED_SQL: &str = "UPDATE vuln_targets SET matched_at = now(), \
     last_error = CASE WHEN needs_inventory THEN last_error ELSE NULL END WHERE id = $1";

const EXISTING_FINDINGS_SQL: &str = "SELECT id, vuln_id, package, version, (resolved_at IS NOT NULL) AS resolved \
     FROM vuln_findings WHERE target_id = $1";

const INSERT_FINDING_SQL: &str = "INSERT INTO vuln_findings (target_id, aliases, pkg_type, location, severity, \
     cvss, kev, kev_ransomware, epss, epss_percentile, risk, fix_state, fixed_version, title, url, \
     vuln_id, package, version, first_seen, last_seen) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, now(), now()) \
     ON CONFLICT (target_id, vuln_id, package, version) DO UPDATE SET last_seen = now()";

/// `$16` = reopen: a resolved finding that came back counts as new again.
const UPDATE_FINDING_SQL: &str = "UPDATE vuln_findings SET aliases = $2, pkg_type = $3, location = $4, \
     severity = $5, cvss = $6, kev = $7, kev_ransomware = $8, epss = $9, epss_percentile = $10, risk = $11, \
     fix_state = $12, fixed_version = $13, title = $14, url = $15, last_seen = now(), \
     resolved_at = CASE WHEN $16 THEN NULL ELSE resolved_at END, \
     first_seen = CASE WHEN $16 THEN now() ELSE first_seen END, \
     notified = CASE WHEN $16 THEN FALSE ELSE notified END \
     WHERE id = $1";

const RESOLVE_FINDINGS_SQL: &str =
    "UPDATE vuln_findings SET resolved_at = now() WHERE id = ANY($1) AND resolved_at IS NULL";

type PgQuery<'q> = sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>;

/// Binds `$2..=$15` (the finding's descriptive fields) after the caller's `$1`.
fn bind_finding_fields<'q>(q: PgQuery<'q>, f: &'q Finding) -> PgQuery<'q> {
    q.bind(&f.aliases)
        .bind(&f.pkg_type)
        .bind(&f.location)
        .bind(&f.severity)
        .bind(f.cvss)
        .bind(f.kev)
        .bind(f.kev_ransomware)
        .bind(f.epss)
        .bind(f.epss_percentile)
        .bind(f.risk)
        .bind(&f.fix_state)
        .bind(&f.fixed_version)
        .bind(&f.title)
        .bind(&f.url)
}

async fn record_server_error(pool: &PgPool, server_id: Uuid, error: Option<&str>) {
    if let Err(e) = sqlx::query(STATE_ERROR_SQL).bind(server_id).bind(error).execute(pool).await {
        tracing::warn!("CVE scanner: could not record the state of server {server_id}: {e}");
    }
}

async fn load_targets(pool: &PgPool, server_id: Uuid) -> Result<Vec<TargetState>, PassError> {
    Ok(sqlx::query_as(TARGET_STATES_SQL).bind(server_id).fetch_all(pool).await?)
}

// ── Pass steps ──────────────────────────────────────────────────────────

/// Step 2: grype, syft and the database present at the expected versions.
async fn ensure_tools(
    pool: &PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    let status = agent.get("/vulns/status").await.map_err(|e| agent_failure("/vulns/status", e))?;
    if !needs_install(&status) {
        let built = parse_time(status.get("db").and_then(|d| d.get("built")));
        sqlx::query(STATE_VERSIONS_SQL)
            .bind(server_id)
            .bind(installed_versions(&status))
            .bind(built)
            .execute(pool)
            .await?;
        return Ok(());
    }
    tracing::info!("CVE scanner: installing or upgrading grype and syft on server {server_id}");
    let job = start_job(agent, "/vulns/install", None).await?;
    let report = wait_job(agent, &job, INSTALL_CAP, shutdown)
        .await
        .map_err(|e| match e {
            PassError::Failed(m) => PassError::Failed(format!("scanner install failed: {m}")),
            other => other,
        })?;
    let built = parse_time(report.get("db").and_then(|d| d.get("built")));
    sqlx::query(STATE_VERSIONS_SQL)
        .bind(server_id)
        .bind(installed_versions(&report))
        .bind(built)
        .execute(pool)
        .await?;
    // The install ends with a database update.
    if built.is_some() {
        sqlx::query(STATE_DB_CHECKED_SQL).bind(server_id).bind(built).execute(pool).await?;
    }
    Ok(())
}

/// Step 3: stored targets follow the active sites and the agent's images.
/// Nothing is deleted unless both sources answered.
async fn sync_targets(pool: &PgPool, server_id: Uuid, agent: &AgentHandle) -> Result<(), PassError> {
    let discovered = agent.get("/vulns/targets").await.map_err(|e| agent_failure("/vulns/targets", e))?;
    if !discovered.get("images").is_some_and(|i| i.is_array()) {
        return Err(PassError::Failed("/vulns/targets: unexpected answer from the agent".into()));
    }
    let sites: Vec<(Uuid, String)> = sqlx::query_as(ACTIVE_SITES_SQL).bind(server_id).fetch_all(pool).await?;
    let git_ids: HashMap<String, Uuid> =
        sqlx::query_as::<_, (String, Uuid)>(GIT_DEPLOYS_SQL).bind(server_id).fetch_all(pool).await?.into_iter().collect();

    let mut desired: Vec<DesiredTarget> = sites
        .into_iter()
        .filter(|(_, domain)| !domain.is_empty() && domain.chars().count() <= W_REF)
        .map(|(id, domain)| DesiredTarget {
            kind: "site".into(),
            ref_: domain,
            site_id: Some(id),
            git_deploy_id: None,
            app_name: None,
            exposed: Some(true),
            image_id: None,
        })
        .collect();
    desired.extend(image_targets_from_agent(&discovered, &git_ids));
    desired.push(DesiredTarget {
        kind: "system".into(),
        ref_: "system".into(),
        site_id: None,
        git_deploy_id: None,
        app_name: None,
        exposed: None,
        image_id: None,
    });

    let existing: Vec<ExistingTarget> = sqlx::query_as(EXISTING_TARGETS_SQL).bind(server_id).fetch_all(pool).await?;
    let plan = plan_target_sync(&desired, &existing);

    for (d, changed) in &plan.upserts {
        sqlx::query(UPSERT_TARGET_SQL)
            .bind(server_id)
            .bind(&d.kind)
            .bind(&d.ref_)
            .bind(d.site_id)
            .bind(d.git_deploy_id)
            .bind(&d.app_name)
            .bind(d.exposed)
            .bind(*changed)
            .execute(pool)
            .await?;
    }
    if !plan.deletes.is_empty() {
        sqlx::query(DELETE_TARGETS_SQL).bind(server_id).bind(&plan.deletes).execute(pool).await?;
        for id in &plan.deletes {
            if let Err(e) = agent.delete(&format!("/vulns/sbom/{id}")).await {
                tracing::debug!("CVE scanner: could not delete the SBOM of target {id}: {e}");
            }
        }
    }
    Ok(())
}

/// Step 4: one inventory job for the picked targets. Per-target errors are
/// stored on the target; only a failed job fails the pass.
async fn run_inventory(
    pool: &PgPool,
    agent: &AgentHandle,
    targets: &[TargetState],
    picks: &[(Uuid, bool)],
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    let by_id: HashMap<Uuid, &TargetState> = targets.iter().map(|t| (t.id, t)).collect();
    let mut requested: HashSet<Uuid> = HashSet::new();
    let mut items = Vec::new();
    for (id, force) in picks {
        let Some(t) = by_id.get(id) else { continue };
        requested.insert(*id);
        items.push(json!({
            "target_id": id.to_string(),
            "kind": t.kind,
            "ref": t.ref_,
            "previous_fingerprint": t.fingerprint.clone().unwrap_or_default(),
            "force": *force,
        }));
    }
    if items.is_empty() {
        return Ok(());
    }
    let job = start_job(agent, "/vulns/inventory", Some(json!({ "targets": items }))).await?;
    let report = wait_job(agent, &job, INVENTORY_CAP, shutdown).await.map_err(|e| match e {
        PassError::Failed(m) => PassError::Failed(format!("inventory failed: {m}")),
        other => other,
    })?;
    // A job already running for another request can answer: only apply what we asked for.
    for r in parse_inventory_report(&report).into_iter().filter(|r| requested.contains(&r.target_id)) {
        match r.status.as_str() {
            "updated" | "unchanged" => {
                sqlx::query(INVENTORY_OK_SQL)
                    .bind(r.target_id)
                    .bind(&r.fingerprint)
                    .bind(r.sbom_at)
                    .execute(pool)
                    .await?;
            }
            _ => {
                let msg = r.error.unwrap_or_else(|| "inventory failed".into());
                sqlx::query(INVENTORY_ERROR_SQL).bind(r.target_id).bind(&msg).execute(pool).await?;
            }
        }
    }
    Ok(())
}

/// Step 5a: the daily database update; stores its check time and build time.
async fn run_db_update(
    pool: &PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    let job = start_job(agent, "/vulns/db-update", None).await?;
    let report = wait_job(agent, &job, DB_UPDATE_CAP, shutdown).await?;
    let built = parse_time(report.get("built"));
    sqlx::query(STATE_DB_CHECKED_SQL).bind(server_id).bind(built).execute(pool).await?;
    Ok(())
}

/// Writes one target's merge plan in a single transaction.
async fn apply_merge(pool: &PgPool, target_id: Uuid, plan: &MergePlan) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for f in &plan.insert {
        bind_finding_fields(sqlx::query(INSERT_FINDING_SQL).bind(target_id), f)
            .bind(&f.vuln_id)
            .bind(&f.package)
            .bind(&f.version)
            .execute(&mut *tx)
            .await?;
    }
    for (reopen, rows) in [(false, &plan.update), (true, &plan.reopen)] {
        for (id, f) in rows {
            bind_finding_fields(sqlx::query(UPDATE_FINDING_SQL).bind(*id), f)
                .bind(reopen)
                .execute(&mut *tx)
                .await?;
        }
    }
    if !plan.resolve.is_empty() {
        sqlx::query(RESOLVE_FINDINGS_SQL).bind(&plan.resolve).execute(&mut *tx).await?;
    }
    sqlx::query(TARGET_MATCHED_SQL).bind(target_id).execute(&mut *tx).await?;
    tx.commit().await
}

/// Step 5b-6: matches `ids` in chunks of [`MATCH_CHUNK`], one job at a time.
async fn match_targets(
    pool: &PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
    ids: &[Uuid],
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    for chunk in ids.chunks(MATCH_CHUNK) {
        run_match(pool, server_id, agent, chunk, shutdown).await?;
    }
    Ok(())
}

/// One match job for `ids`, then the merge of each result.
async fn run_match(
    pool: &PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
    ids: &[Uuid],
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    if ids.is_empty() {
        return Ok(());
    }
    let requested: HashSet<Uuid> = ids.iter().copied().collect();
    let body = json!({ "target_ids": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>() });
    let job = start_job(agent, "/vulns/match", Some(body)).await?;
    let report = wait_job(agent, &job, MATCH_CAP, shutdown).await.map_err(|e| match e {
        PassError::Failed(m) => PassError::Failed(format!("match failed: {m}")),
        other => other,
    })?;
    let (built, results) = parse_match_report(&report);
    for r in results.into_iter().filter(|r| requested.contains(&r.target_id)) {
        match r.status.as_str() {
            "ok" => {
                let existing: Vec<ExistingFinding> =
                    sqlx::query_as(EXISTING_FINDINGS_SQL).bind(r.target_id).fetch_all(pool).await?;
                let plan = plan_merge(&existing, &r);
                if let Err(e) = apply_merge(pool, r.target_id, &plan).await {
                    tracing::warn!("CVE scanner: could not store the findings of target {}: {e}", r.target_id);
                    sqlx::query(TARGET_ERROR_SQL)
                        .bind(r.target_id)
                        .bind("Could not store the findings")
                        .execute(pool)
                        .await?;
                }
            }
            "no_sbom" => {
                sqlx::query(TARGET_NO_SBOM_SQL)
                    .bind(r.target_id)
                    .bind("No SBOM on the server yet")
                    .execute(pool)
                    .await?;
            }
            _ => {
                let msg = r.error.unwrap_or_else(|| "match failed".into());
                sqlx::query(TARGET_ERROR_SQL).bind(r.target_id).bind(&msg).execute(pool).await?;
            }
        }
    }
    sqlx::query(STATE_MATCHED_SQL).bind(server_id).bind(built).execute(pool).await?;
    Ok(())
}

/// One full pass on one server (steps 2 to 6 of the contract).
async fn sweep_server(
    pool: &PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    ensure_tools(pool, server_id, agent, shutdown).await?;
    sync_targets(pool, server_id, agent).await?;

    let targets = load_targets(pool, server_id).await?;
    let picks = select_inventory(&targets, Utc::now());
    run_inventory(pool, agent, &targets, &picks, shutdown).await?;

    let hour = get_setting_i64(pool, SETTING_MATCH_HOUR, DEFAULT_MATCH_HOUR).await.clamp(0, 23) as u32;
    let checked: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar(STATE_DB_CHECKED_AT_SQL).bind(server_id).fetch_optional(pool).await?;
    let mut full = false;
    let mut db_error = None;
    if db_update_due(checked.flatten(), Utc::now(), hour) {
        match run_db_update(pool, server_id, agent, shutdown).await {
            Ok(()) => full = true,
            Err(PassError::Shutdown) => return Err(PassError::Shutdown),
            // Match with the database already there; the update is retried next pass.
            Err(PassError::Failed(e)) => db_error = Some(e),
        }
    }

    let checked: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar(STATE_DB_CHECKED_AT_SQL).bind(server_id).fetch_optional(pool).await?;
    let targets = load_targets(pool, server_id).await?;
    let ids = select_match(&targets, full, checked.flatten());
    match_targets(pool, server_id, agent, &ids, shutdown).await?;

    match db_error {
        Some(e) => Err(PassError::Failed(format!("database update failed: {e}"))),
        None => Ok(()),
    }
}

/// The background loop, started by `spawn_supervised` in `main.rs`.
pub async fn run(pool: PgPool, agents: AgentRegistry, mut shutdown_rx: Receiver<()>) {
    tracing::info!("CVE scanner background task started");

    tokio::select! {
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
        _ = shutdown_rx.recv() => {
            tracing::info!("CVE scanner shutting down (initial delay)");
            return;
        }
    }

    loop {
        if get_setting_bool(&pool, SETTING_ENABLED, true).await {
            for member in agents.online_fleet().await {
                let lock = server_lock(member.id);
                let Ok(_guard) = lock.try_lock() else {
                    tracing::debug!("CVE scanner: {} is busy with an on-demand scan, skipped", member.name);
                    continue;
                };
                match sweep_server(&pool, member.id, &member.agent, &mut shutdown_rx).await {
                    Ok(()) => record_server_error(&pool, member.id, None).await,
                    Err(PassError::Shutdown) => {
                        tracing::info!("CVE scanner shutting down (during a pass)");
                        return;
                    }
                    Err(PassError::Failed(e)) => {
                        tracing::warn!("CVE scanner: pass failed on {}: {e}", member.name);
                        record_server_error(&pool, member.id, Some(&e)).await;
                    }
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(CHECK_INTERVAL) => {}
            _ = shutdown_rx.recv() => {
                tracing::info!("CVE scanner shutting down");
                return;
            }
        }
    }
}

/// "Scan now" for one target: forced inventory then match, in the background.
/// Waits for the server's lock, so it never overlaps a sweeper pass.
pub async fn scan_target_now(pool: PgPool, agents: AgentRegistry, target_id: Uuid, mut shutdown: Receiver<()>) {
    let outcome = scan_target_inner(&pool, &agents, target_id, &mut shutdown).await;
    unqueue_scan(target_id);
    if let Err(PassError::Failed(e)) = outcome {
        tracing::warn!("CVE scanner: on-demand scan of target {target_id} failed: {e}");
        let _ = sqlx::query(TARGET_ERROR_SQL).bind(target_id).bind(&e).execute(&pool).await;
    }
}

async fn scan_target_inner(
    pool: &PgPool,
    agents: &AgentRegistry,
    target_id: Uuid,
    shutdown: &mut Receiver<()>,
) -> Result<(), PassError> {
    let server_id: Option<Uuid> = sqlx::query_scalar("SELECT server_id FROM vuln_targets WHERE id = $1")
        .bind(target_id)
        .fetch_optional(pool)
        .await?;
    let Some(server_id) = server_id else { return Ok(()) };
    let lock = server_lock(server_id);
    let _guard = tokio::select! {
        g = lock.lock() => g,
        _ = shutdown.recv() => return Err(PassError::Shutdown),
    };
    let agent = agents
        .for_server(server_id)
        .await
        .map_err(|e| PassError::Failed(format!("server unreachable: {e}")))?;
    ensure_tools(pool, server_id, &agent, shutdown).await?;

    let targets: Vec<TargetState> = load_targets(pool, server_id).await?.into_iter().filter(|t| t.id == target_id).collect();
    run_inventory(pool, &agent, &targets, &[(target_id, true)], shutdown).await?;

    let refreshed = load_targets(pool, server_id).await?;
    if refreshed.iter().any(|t| t.id == target_id && t.sbom_at.is_some()) {
        match_targets(pool, server_id, &agent, &[target_id], shutdown).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn finding(vuln: &str, pkg: &str, ver: &str) -> Finding {
        parse_finding(&json!({"vuln_id": vuln, "package": pkg, "version": ver, "severity": "high"})).unwrap()
    }

    fn result(status: &str, truncated: bool, findings: Vec<Finding>) -> MatchResult {
        MatchResult { target_id: Uuid::nil(), status: status.into(), error: None, truncated, findings }
    }

    fn existing(n: u128, vuln: &str, pkg: &str, ver: &str, resolved: bool) -> ExistingFinding {
        ExistingFinding {
            id: Uuid::from_u128(n),
            vuln_id: vuln.into(),
            package: pkg.into(),
            version: ver.into(),
            resolved,
        }
    }

    #[test]
    fn merge_inserts_updates_resolves_and_reopens() {
        let stored = vec![
            existing(1, "CVE-1", "a", "1.0", false), // still present -> update
            existing(2, "CVE-2", "b", "2.0", false), // absent -> resolve
            existing(3, "CVE-3", "c", "3.0", true),  // back -> reopen
            existing(4, "CVE-4", "d", "4.0", true),  // still resolved, absent -> untouched
        ];
        let r = result("ok", false, vec![finding("CVE-1", "a", "1.0"), finding("CVE-3", "c", "3.0"), finding("CVE-9", "z", "9")]);
        let plan = plan_merge(&stored, &r);
        assert_eq!(plan.insert.iter().map(|f| f.vuln_id.as_str()).collect::<Vec<_>>(), ["CVE-9"]);
        assert_eq!(plan.update.iter().map(|(id, _)| *id).collect::<Vec<_>>(), [Uuid::from_u128(1)]);
        assert_eq!(plan.reopen.iter().map(|(id, _)| *id).collect::<Vec<_>>(), [Uuid::from_u128(3)]);
        assert_eq!(plan.resolve, [Uuid::from_u128(2)]);
    }

    #[test]
    fn merge_resolves_nothing_on_error_or_no_sbom() {
        let stored = vec![existing(1, "CVE-1", "a", "1.0", false)];
        for status in ["error", "no_sbom", "something-else"] {
            let plan = plan_merge(&stored, &result(status, false, vec![]));
            assert_eq!(plan, MergePlan::default(), "status {status}");
        }
    }

    #[test]
    fn merge_does_not_resolve_on_truncated_result() {
        let stored = vec![existing(1, "CVE-1", "a", "1.0", false), existing(2, "CVE-2", "b", "1.0", false)];
        let plan = plan_merge(&stored, &result("ok", true, vec![finding("CVE-1", "a", "1.0")]));
        assert_eq!(plan.update.len(), 1);
        assert!(plan.resolve.is_empty());
    }

    #[test]
    fn merge_dedupes_findings_and_empty_ok_resolves_all_open() {
        let r = result("ok", false, vec![finding("CVE-1", "a", "1.0"), finding("CVE-1", "a", "1.0")]);
        assert_eq!(plan_merge(&[], &r).insert.len(), 1);
        let stored = vec![existing(1, "CVE-1", "a", "1.0", false), existing(2, "CVE-2", "a", "1.0", true)];
        assert_eq!(plan_merge(&stored, &result("ok", false, vec![])).resolve, [Uuid::from_u128(1)]);
    }

    #[test]
    fn parse_finding_normalizes_and_clips() {
        let long = "x".repeat(300);
        let f = parse_finding(&json!({
            "vuln_id": "CVE-2021-44228", "aliases": ["GHSA-1", "CVE-2021-44228", "GHSA-1", ""],
            "package": long, "version": "2.14.1", "severity": "Negligible", "cvss": 10.0,
            "kev": true, "kev_ransomware": true, "epss": 0.94, "risk": 97.3,
            "fix_state": "weird", "fixed_version": "2.15.0"
        }))
        .unwrap();
        assert_eq!(f.aliases, ["GHSA-1"]);
        assert_eq!(f.package.chars().count(), W_PACKAGE);
        assert_eq!(f.severity, "low");
        assert_eq!(f.fix_state, "unknown");
        assert!(f.kev && f.kev_ransomware);
        assert_eq!(f.cvss, Some(10.0));
        assert!(parse_finding(&json!({"package": "a"})).is_none());
        assert!(parse_finding(&json!({"vuln_id": "CVE-1", "package": "  "})).is_none());
    }

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("ééé", 2), "éé");
        assert_eq!(clip("ab", 5), "ab");
    }

    #[test]
    fn parse_match_report_reads_results() {
        let id = Uuid::new_v4();
        let (built, results) = parse_match_report(&json!({
            "db_built": "2026-11-19T06:23:00Z",
            "results": [
                {"target_id": id.to_string(), "status": "ok", "truncated": true,
                 "findings": [{"vuln_id": "CVE-1", "package": "a", "version": "1"}, {"package": "no-id"}]},
                {"target_id": "not-a-uuid", "status": "ok"},
                {"target_id": id.to_string(), "status": "error", "error": "boom"}
            ]
        }));
        assert_eq!(built, Some(at("2026-11-19T06:23:00Z")));
        assert_eq!(results.len(), 2);
        assert!(results[0].truncated);
        assert_eq!(results[0].findings.len(), 1);
        assert_eq!(results[1].error.as_deref(), Some("boom"));
    }

    #[test]
    fn parse_inventory_report_reads_results() {
        let id = Uuid::new_v4();
        let r = parse_inventory_report(&json!({"results": [
            {"target_id": id.to_string(), "status": "updated", "fingerprint": "abc",
             "sbom_at": "2026-11-19T06:00:00Z", "packages": 12, "error": null}
        ]}));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].fingerprint.as_deref(), Some("abc"));
        assert_eq!(r[0].sbom_at, Some(at("2026-11-19T06:00:00Z")));
        assert!(r[0].error.is_none());
    }

    #[test]
    fn db_update_due_follows_the_daily_utc_slot() {
        let now = at("2026-11-19T10:00:00Z");
        assert!(db_update_due(None, now, 4));
        assert!(!db_update_due(Some(at("2026-11-19T04:30:00Z")), now, 4));
        assert!(db_update_due(Some(at("2026-11-19T03:59:00Z")), now, 4));
        // Before today's slot, yesterday's slot is the reference.
        let early = at("2026-11-19T02:00:00Z");
        assert!(!db_update_due(Some(at("2026-11-18T05:00:00Z")), early, 4));
        assert!(db_update_due(Some(at("2026-11-18T03:00:00Z")), early, 4));
        // Out-of-range hour is clamped rather than panicking.
        assert!(db_update_due(Some(at("2026-11-18T22:00:00Z")), now, 99));
    }

    fn state(n: u128, kind: &str, sbom: Option<&str>, matched: Option<&str>, needs: bool) -> TargetState {
        TargetState {
            id: Uuid::from_u128(n),
            kind: kind.into(),
            ref_: format!("r{n}"),
            fingerprint: None,
            sbom_at: sbom.map(at),
            matched_at: matched.map(at),
            needs_inventory: needs,
        }
    }

    #[test]
    fn select_inventory_picks_marked_missing_and_stale() {
        let now = at("2026-11-19T10:00:00Z");
        let targets = vec![
            state(1, "site", Some("2026-11-18T10:00:00Z"), None, false), // fresh: skipped
            state(2, "site", Some("2026-11-18T10:00:00Z"), None, true),  // marked: not forced
            state(3, "image", None, None, false),                        // no SBOM: forced
            state(4, "system", Some("2026-11-01T10:00:00Z"), None, false), // stale: forced
            state(5, "wordpress", None, None, true),                     // not this batch
        ];
        assert_eq!(
            select_inventory(&targets, now),
            vec![(Uuid::from_u128(2), false), (Uuid::from_u128(3), true), (Uuid::from_u128(4), true)]
        );
    }

    #[test]
    fn select_match_full_and_incremental() {
        let targets = vec![
            state(1, "site", None, None, true),                                         // no SBOM
            state(2, "site", Some("2026-11-19T05:00:00Z"), None, false),                // never matched
            state(3, "site", Some("2026-11-19T05:00:00Z"), Some("2026-11-19T06:00:00Z"), false), // up to date
            state(4, "site", Some("2026-11-19T07:00:00Z"), Some("2026-11-19T06:00:00Z"), false), // newer SBOM
        ];
        let ids = |v: Vec<Uuid>| v.into_iter().map(|u| u.as_u128()).collect::<Vec<_>>();
        assert_eq!(ids(select_match(&targets, true, None)), [2, 3, 4]);
        assert_eq!(ids(select_match(&targets, false, None)), [2, 4]);
        // Matched before the current database: retried.
        assert_eq!(ids(select_match(&targets, false, Some(at("2026-11-19T06:30:00Z")))), [2, 3, 4]);
    }

    fn desired(kind: &str, r: &str, image_id: Option<&str>) -> DesiredTarget {
        DesiredTarget {
            kind: kind.into(),
            ref_: r.into(),
            site_id: None,
            git_deploy_id: None,
            app_name: None,
            exposed: None,
            image_id: image_id.map(Into::into),
        }
    }

    fn stored(n: u128, kind: &str, r: &str, fp: Option<&str>) -> ExistingTarget {
        ExistingTarget { id: Uuid::from_u128(n), kind: kind.into(), ref_: r.into(), fingerprint: fp.map(Into::into) }
    }

    #[test]
    fn sync_plans_upserts_deletes_and_image_changes() {
        let want = vec![
            desired("site", "a.example", None),
            desired("image", "nginx:1.25", Some("sha256:new")),
            desired("image", "redis:7", Some("sha256:same")),
            desired("image", "redis:7", Some("sha256:dup")), // duplicate key: ignored
            desired("system", "system", None),
        ];
        let have = vec![
            stored(1, "site", "gone.example", None),
            stored(2, "image", "nginx:1.25", Some("sha256:old")),
            stored(3, "image", "redis:7", Some("sha256:same")),
            stored(4, "wordpress", "wp.example", None), // other batch: kept
        ];
        let plan = plan_target_sync(&want, &have);
        let flags: Vec<(&str, bool)> = plan.upserts.iter().map(|(d, c)| (d.ref_.as_str(), *c)).collect();
        assert_eq!(flags, [("a.example", true), ("nginx:1.25", true), ("redis:7", false), ("system", true)]);
        assert_eq!(plan.deletes, [Uuid::from_u128(1)]);
    }

    #[test]
    fn image_targets_read_containers() {
        let git = HashMap::from([("myapp".to_string(), Uuid::from_u128(7))]);
        let v = json!({"images": [
            {"image": "nginx:1.25", "image_id": "sha256:a", "containers": [
                {"name": "c1", "app_name": null, "git_name": "myapp", "domain": null, "public_port": false},
                {"name": "c2", "app_name": "x", "git_name": null, "domain": "x.example.com", "public_port": false}]},
            {"image": "internal:1", "image_id": "sha256:b", "containers": [
                {"name": "c3", "app_name": "y", "domain": "", "public_port": false}]},
            {"image": "no-id:1", "image_id": "", "containers": []}
        ]});
        let t = image_targets_from_agent(&v, &git);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].git_deploy_id, Some(Uuid::from_u128(7)));
        assert_eq!(t[0].app_name.as_deref(), Some("x"));
        assert_eq!(t[0].exposed, Some(true));
        assert_eq!(t[1].exposed, Some(false));
        assert_eq!(t[1].image_id.as_deref(), Some("sha256:b"));
    }

    #[test]
    fn needs_install_compares_with_expected_versions() {
        let ok = json!({"grype": {"installed": true, "version": "0.122.1"},
                        "syft": {"installed": true, "version": "v1.57.2"},
                        "db": {"built": "2026-11-19T06:23:00Z"},
                        "expected": {"grype": "0.122.1", "syft": "1.57.2"}});
        assert!(!needs_install(&ok));
        let mut old = ok.clone();
        old["grype"]["version"] = json!("0.118.0");
        assert!(needs_install(&old));
        let mut missing = ok.clone();
        missing["syft"]["installed"] = json!(false);
        assert!(needs_install(&missing));
        let mut no_db = ok.clone();
        no_db["db"] = Value::Null;
        assert!(needs_install(&no_db));
    }
}
