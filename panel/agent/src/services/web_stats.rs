//! Web statistics with GoAccess (feature 7, contract A-1 to A-9).
//!
//! Debian/Ubuntu only. What the panel owns on the box:
//! - the `goaccess` package;
//! - [`STATS_ROOT`] (root, 0700): one directory per domain (0700) holding the
//!   persistent GoAccess database `db/`, `report.html` (0600) and
//!   `state.json` (0600), plus [`BROWSERS_FILE`] (the panel's uptime checks
//!   are classified as crawlers);
//! - the DB-IP Country Lite database under [`GEOIP_DIR`] (CC BY 4.0).
//!
//! One statistics run at a time per agent, at nice 19 and idle I/O priority.
//! Nothing read from a visitor log is ever written to the agent's journal:
//! GoAccess's own error text only goes to `state.json` and the reply.

use crate::safe_cmd::safe_command;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::time::Instant;

pub const PACKAGE: &str = "goaccess";
pub const STATS_ROOT: &str = "/var/lib/dockpanel/stats";
pub const GEOIP_DIR: &str = "/var/lib/dockpanel/geoip";
pub const GEOIP_PATH: &str = "/var/lib/dockpanel/geoip/dbip-country-lite.mmdb";
pub const GEOIP_META: &str = "/var/lib/dockpanel/geoip/meta.json";
pub const BROWSERS_FILE: &str = "/var/lib/dockpanel/stats/browsers.list";
/// GoAccess `--browsers-file` format: the User-Agent token, a tab, the type.
pub const BROWSERS_BODY: &str = "DockPanel-Uptime\tCrawlers\n";
pub const LOG_DIR: &str = "/var/log/nginx";
/// History kept in the persistent database (12 months).
pub const KEEP_DAYS: u32 = 365;

pub const UNSUPPORTED_MSG: &str = "Not supported on this server";
pub const NOT_INSTALLED_MSG: &str = "Web statistics not installed";
pub const NO_LOG_MSG: &str = "No access log for this site";
pub const NO_REPORT_MSG: &str = "No report yet";
pub const RUN_BUSY_MSG: &str = "Another statistics run is in progress";
const RUNNING_MSG: &str = "A statistics run is in progress, try again later";
const OP_BUSY_MSG: &str = "A web statistics installation, removal or purge is already running";

const INSTALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How long a run waits for its turn before answering 409.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Budget of one A-5 call's GoAccess work (initialisation and normal pass).
const RUN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ERROR_MAX_CHARS: usize = 500;

const GEOIP_URL_BASE: &str = "https://download.db-ip.com/free/dbip-country-lite";
const GEOIP_MIN_BYTES: u64 = 1024 * 1024;
const GEOIP_MAX_BYTES: u64 = 200 * 1024 * 1024;
/// The mmdb metadata section starts with this marker, within the file's last 128 KiB.
const MMDB_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
const MMDB_TAIL: u64 = 128 * 1024;
const GEOIP_MAX_AGE_DAYS: i64 = 31;
const GEOIP_RETRY_HOURS: i64 = 24;
const GEOIP_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// An error with the HTTP status the route answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsErr {
    pub status: u16,
    pub msg: String,
}

impl StatsErr {
    pub fn new(status: u16, msg: impl Into<String>) -> Self {
        Self { status, msg: msg.into() }
    }
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::new(400, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(404, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(409, msg)
    }
    pub fn precondition(msg: impl Into<String>) -> Self {
        Self::new(412, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(500, msg)
    }
}

// ── Pure helpers ────────────────────────────────────────────────────────────

/// `<root>/<domain>`; the caller has validated `domain`.
pub fn domain_dir(root: &Path, domain: &str) -> PathBuf {
    root.join(domain)
}

/// The rotated, compressed logs of `domain` among `names` (file names of the
/// log directory), oldest first: `<d>.access.log.N.gz` by decreasing N.
pub fn gz_logs<I, S>(domain: &str, names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let prefix = format!("{domain}.access.log.");
    let mut found: Vec<(u32, String)> = names
        .into_iter()
        .filter_map(|n| {
            let n = n.as_ref();
            let num = n.strip_prefix(&prefix)?.strip_suffix(".gz")?;
            if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((num.parse().ok()?, n.to_string()))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, n)| n).collect()
}

/// The plain-text inputs of a normal pass: `<d>.access.log.1` then
/// `<d>.access.log`, each only if `exists` says so.
pub fn normal_inputs(log_dir: &Path, domain: &str, exists: impl Fn(&Path) -> bool) -> Vec<String> {
    [format!("{domain}.access.log.1"), format!("{domain}.access.log")]
        .into_iter()
        .map(|n| log_dir.join(n))
        .filter(|p| exists(p))
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

/// What one GoAccess invocation is given, apart from its inputs.
pub struct PassOptions<'a> {
    pub db_path: &'a str,
    pub restore: bool,
    pub geoip: Option<&'a str>,
    pub browsers_file: &'a str,
    pub title: &'a str,
    pub output: &'a str,
}

/// GoAccess's arguments (contract A-5): the inputs (`-` for standard input)
/// first, then the options. Pure, tested.
pub fn goaccess_args(inputs: &[String], o: &PassOptions) -> Vec<String> {
    let mut a: Vec<String> = inputs.to_vec();
    a.push("--log-format=COMBINED".into());
    a.push("--persist".into());
    if o.restore {
        a.push("--restore".into());
    }
    a.push(format!("--db-path={}", o.db_path));
    a.push(format!("--keep-last={KEEP_DAYS}"));
    if let Some(g) = o.geoip {
        a.push(format!("--geoip-database={g}"));
    }
    a.push(format!("--browsers-file={}", o.browsers_file));
    a.push("--no-global-config".into());
    a.push(format!("--html-report-title={}", o.title));
    a.push("-o".into());
    a.push(o.output.into());
    a
}

/// The version in `goaccess --version` (`GoAccess - 1.8.1.`).
pub fn parse_version(out: &str) -> Option<String> {
    let first = out.lines().find(|l| !l.trim().is_empty())?;
    let tok = first.split_whitespace().find(|t| t.starts_with(|c: char| c.is_ascii_digit()))?;
    let v = tok.trim_end_matches('.');
    (!v.is_empty()).then(|| v.to_string())
}

/// `s` cut to `max` characters.
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// `YYYY-MM` of `now` and of the month before.
pub fn geoip_months(now: chrono::DateTime<chrono::Utc>) -> [String; 2] {
    use chrono::Datelike;
    let (y, m) = (now.year(), now.month());
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

pub fn geoip_url(month: &str) -> String {
    format!("{GEOIP_URL_BASE}-{month}.mmdb.gz")
}

/// `meta.json` of the GeoIP database. Dates are RFC 3339 (UTC, seconds).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeoMeta {
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub attempted_at: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn parse_ts(s: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s?).ok().map(|d| d.with_timezone(&chrono::Utc))
}

fn ts(d: chrono::DateTime<chrono::Utc>) -> String {
    d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Should a run try to update the GeoIP database first (A-7)? Not when the
/// last attempt is less than 24 h old; otherwise when the database is missing
/// or more than 31 days old. Pure, tested.
pub fn geoip_due(present: bool, meta: &GeoMeta, now: chrono::DateTime<chrono::Utc>) -> bool {
    if let Some(at) = parse_ts(meta.attempted_at.as_deref()) {
        if now - at < chrono::Duration::hours(GEOIP_RETRY_HOURS) {
            return false;
        }
    }
    if !present {
        return true;
    }
    match parse_ts(meta.updated_at.as_deref()) {
        Some(up) => now - up > chrono::Duration::days(GEOIP_MAX_AGE_DAYS),
        None => true,
    }
}

/// The checks a decompressed database passes before it replaces the current
/// one: its size, and the mmdb metadata marker in its last 128 KiB (`tail`).
pub fn check_mmdb(size: u64, tail: &[u8]) -> Result<(), String> {
    if size < GEOIP_MIN_BYTES {
        return Err(format!("The country database is too small ({size} bytes)"));
    }
    if size > GEOIP_MAX_BYTES {
        return Err(format!("The country database is too large ({size} bytes)"));
    }
    if !tail.windows(MMDB_MARKER.len()).any(|w| w == MMDB_MARKER) {
        return Err("The downloaded file is not an mmdb database".into());
    }
    Ok(())
}

/// `state.json` of a domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunState {
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// Is `db` missing or empty? An initialisation is due then.
pub fn db_is_empty(db: &Path) -> bool {
    match std::fs::read_dir(db) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true,
    }
}

// ── Files ───────────────────────────────────────────────────────────────────

/// Create `dir` (and its parents) and set it to `mode`.
fn ensure_dir(dir: &Path, mode: u32) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(dir)
        .and_then(|_| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)))
        .map_err(|e| format!("Cannot create {}: {e}", dir.display()))
}

/// Atomic write with `mode`.
fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let _ = std::fs::remove_file(&tmp);
    let res = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(content)?;
            f.sync_all()
        })
        .and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Cannot write {}: {e}", path.display()));
    }
    Ok(())
}

/// `STATS_ROOT` (0700) and the browsers file, rewritten when it differs.
fn ensure_stats_root() -> Result<(), String> {
    ensure_dir(Path::new(STATS_ROOT), 0o700)?;
    if std::fs::read_to_string(BROWSERS_FILE).ok().as_deref() != Some(BROWSERS_BODY) {
        write_atomic(Path::new(BROWSERS_FILE), BROWSERS_BODY.as_bytes(), 0o644)?;
    }
    Ok(())
}

pub fn read_state(dir: &Path) -> RunState {
    std::fs::read(dir.join("state.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn read_geo_meta() -> GeoMeta {
    std::fs::read(GEOIP_META).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Remove the per-domain directories under `root` (not the browsers file).
pub fn purge_under(root: &Path) -> Result<usize, String> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("Cannot read {}: {e}", root.display())),
    };
    let mut removed = 0;
    let mut failed: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => failed.push(format!("{}: {e}", entry.file_name().to_string_lossy())),
        }
    }
    if failed.is_empty() {
        Ok(removed)
    } else {
        Err(format!("Removed {removed} site(s), but could not remove {}", failed.join(", ")))
    }
}

/// Number of domain directories under `root`.
pub fn count_sites(root: &Path) -> usize {
    std::fs::read_dir(root)
        .map(|it| it.flatten().filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).count())
        .unwrap_or(0)
}

/// A-9: remove `<root>/<domain>/`. `Ok(true)` when something was removed.
pub fn remove_under(root: &Path, domain: &str) -> Result<bool, String> {
    if !crate::routes::is_valid_domain(domain) {
        return Err(format!("Invalid domain: {domain}"));
    }
    let dir = domain_dir(root, domain);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&dir).map(|_| true).map_err(|e| e.to_string()),
        Ok(_) => std::fs::remove_file(&dir).map(|_| true).map_err(|e| e.to_string()),
        Err(_) => Ok(false),
    }
}

/// A-9: rename `<root>/<old>/` to `<root>/<new>/` when the second does not
/// exist. `Ok(true)` when renamed.
pub fn rename_under(root: &Path, old: &str, new: &str) -> Result<bool, String> {
    if !crate::routes::is_valid_domain(old) || !crate::routes::is_valid_domain(new) {
        return Err("Invalid domain".into());
    }
    let from = domain_dir(root, old);
    let to = domain_dir(root, new);
    if !std::fs::symlink_metadata(&from).map(|m| m.is_dir()).unwrap_or(false) {
        return Ok(false);
    }
    if std::fs::symlink_metadata(&to).is_ok() {
        return Err(format!("{} already exists", to.display()));
    }
    std::fs::rename(&from, &to).map(|_| true).map_err(|e| e.to_string())
}

/// A-9, called by `delete_site`: best effort.
pub fn remove_site_stats(domain: &str) {
    match remove_under(Path::new(STATS_ROOT), domain) {
        Ok(true) => tracing::info!("Removed the web statistics of {domain}"),
        Ok(false) => {}
        Err(e) => tracing::warn!("Could not remove the web statistics of {domain}: {e}"),
    }
}

/// A-9, called by `rename_site`: best effort.
pub fn rename_site_stats(old: &str, new: &str) {
    match rename_under(Path::new(STATS_ROOT), old, new) {
        Ok(true) => tracing::info!("Moved the web statistics of {old} to {new}"),
        Ok(false) => {}
        Err(e) => tracing::warn!("Could not move the web statistics of {old} to {new}: {e}"),
    }
}

// ── System facts ────────────────────────────────────────────────────────────

pub async fn unsupported_reason() -> Option<String> {
    match crate::services::pkg::installer().await {
        Some(crate::services::pkg::Installer::AptGet) => None,
        _ => Some(UNSUPPORTED_MSG.to_string()),
    }
}

pub async fn is_installed() -> bool {
    crate::services::pkg::is_installed(PACKAGE).await
}

/// `goaccess --version`: `Ok(version)` or why it does not run.
async fn goaccess_version() -> Result<String, String> {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        safe_command("goaccess").arg("--version").stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "goaccess --version timed out".to_string())?
    .map_err(|e| format!("goaccess could not run: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match parse_version(&text) {
        Some(v) if out.status.success() => Ok(v),
        _ => Err(format!(
            "goaccess --version failed: {}",
            truncate_chars(String::from_utf8_lossy(&out.stderr).trim(), ERROR_MAX_CHARS)
        )),
    }
}

// ── Locks ───────────────────────────────────────────────────────────────────

/// Held by a statistics run; uninstall and purge take it too.
static RUN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Held by install, uninstall and purge: a second one is a 409.
static OP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Serializes GeoIP downloads (install and runs).
static GEO_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// The domain being computed, read by `status` without waiting.
static RUNNING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn running_domain() -> Option<String> {
    RUNNING.lock().map(|g| g.clone()).unwrap_or(None)
}

struct RunningMark;

impl RunningMark {
    fn set(domain: &str) -> Self {
        if let Ok(mut g) = RUNNING.lock() {
            *g = Some(domain.to_string());
        }
        RunningMark
    }
}

impl Drop for RunningMark {
    fn drop(&mut self) {
        if let Ok(mut g) = RUNNING.lock() {
            *g = None;
        }
    }
}

// ── A-1 status ──────────────────────────────────────────────────────────────

pub async fn status() -> serde_json::Value {
    let unsupported = unsupported_reason().await;
    let supported = unsupported.is_none();
    let installed = supported && is_installed().await;
    let version = if installed { goaccess_version().await.ok() } else { None };
    let meta = read_geo_meta();
    let (sites, data_bytes) = tokio::task::spawn_blocking(|| {
        let root = Path::new(STATS_ROOT);
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let bytes = crate::services::disk_usage::walk(root, deadline).map(|(b, _)| b).unwrap_or(0);
        (count_sites(root), bytes)
    })
    .await
    .unwrap_or((0, 0));
    serde_json::json!({
        "supported": supported,
        "unsupported_reason": unsupported,
        "installed": installed,
        "version": version,
        "geoip": {
            "present": Path::new(GEOIP_PATH).is_file(),
            "updated_at": meta.updated_at,
            "error": meta.error,
        },
        "running": running_domain(),
        "sites": sites,
        "data_bytes": data_bytes,
    })
}

// ── A-2 install / A-3 uninstall / A-4 purge ─────────────────────────────────

/// A-2. Returns the warnings.
pub async fn install() -> Result<Vec<String>, StatsErr> {
    if unsupported_reason().await.is_some() {
        return Err(StatsErr::precondition(UNSUPPORTED_MSG));
    }
    let Ok(_op) = OP_LOCK.try_lock() else {
        return Err(StatsErr::conflict(OP_BUSY_MSG));
    };
    match tokio::time::timeout(INSTALL_TIMEOUT, run_install()).await {
        Ok(r) => r,
        Err(_) => Err(StatsErr::internal("The web statistics installation timed out (5 minutes)")),
    }
}

async fn run_install() -> Result<Vec<String>, StatsErr> {
    let mut warnings = Vec::new();
    crate::services::pkg::install(&[PACKAGE])
        .await
        .map_err(|e| StatsErr::internal(format!("GoAccess install failed: {e}")))?;
    let version = goaccess_version()
        .await
        .map_err(|e| StatsErr::internal(format!("GoAccess was installed but does not run: {e}")))?;
    ensure_stats_root().map_err(StatsErr::internal)?;
    ensure_dir(Path::new(GEOIP_DIR), 0o755).map_err(StatsErr::internal)?;
    if let Err(e) = update_geoip().await {
        warnings.push(format!("The country database could not be downloaded: {e}"));
    }
    tracing::info!("Web statistics installed (GoAccess {version})");
    Ok(warnings)
}

/// A-3. The statistics data and the GeoIP database are kept.
pub async fn uninstall() -> Result<(), StatsErr> {
    if unsupported_reason().await.is_some() {
        return Err(StatsErr::precondition(UNSUPPORTED_MSG));
    }
    let Ok(_op) = OP_LOCK.try_lock() else {
        return Err(StatsErr::conflict(OP_BUSY_MSG));
    };
    let Ok(_run) = RUN_LOCK.try_lock() else {
        return Err(StatsErr::conflict(RUNNING_MSG));
    };
    crate::services::pkg::remove(&[PACKAGE])
        .await
        .map_err(|e| StatsErr::internal(format!("GoAccess removal failed: {e}")))?;
    tracing::info!("Web statistics removed (data kept under {STATS_ROOT})");
    Ok(())
}

/// A-4. Returns the number of site directories removed.
pub async fn purge() -> Result<usize, StatsErr> {
    let Ok(_op) = OP_LOCK.try_lock() else {
        return Err(StatsErr::conflict(OP_BUSY_MSG));
    };
    let Ok(_run) = RUN_LOCK.try_lock() else {
        return Err(StatsErr::conflict(RUNNING_MSG));
    };
    let removed = tokio::task::spawn_blocking(|| purge_under(Path::new(STATS_ROOT)))
        .await
        .map_err(|_| StatsErr::internal("internal error"))?
        .map_err(StatsErr::internal)?;
    tracing::info!("Web statistics data deleted ({removed} site(s))");
    Ok(removed)
}

// ── A-7 GeoIP ───────────────────────────────────────────────────────────────

/// Try the GeoIP update when due (A-7). A failure is recorded in `meta.json`
/// and never blocks the run.
async fn maybe_update_geoip() {
    let due = geoip_due(Path::new(GEOIP_PATH).is_file(), &read_geo_meta(), chrono::Utc::now());
    if due {
        if let Err(e) = update_geoip().await {
            tracing::warn!("Country database update failed: {e}");
        }
    }
}

/// Download, check and install the DB-IP database; `meta.json` records the
/// attempt either way.
async fn update_geoip() -> Result<(), String> {
    let _g = GEO_LOCK.lock().await;
    let now = chrono::Utc::now();
    let mut meta = read_geo_meta();
    let res = download_geoip(now).await;
    meta.attempted_at = Some(ts(now));
    match &res {
        Ok(()) => {
            meta.updated_at = Some(ts(now));
            meta.error = None;
        }
        Err(e) => meta.error = Some(truncate_chars(e, ERROR_MAX_CHARS)),
    }
    if let Ok(body) = serde_json::to_vec_pretty(&meta) {
        if let Err(e) = ensure_dir(Path::new(GEOIP_DIR), 0o755)
            .and_then(|_| write_atomic(Path::new(GEOIP_META), &body, 0o644))
        {
            tracing::warn!("{e}");
        }
    }
    if res.is_ok() {
        tracing::info!("Country database updated");
    }
    res
}

async fn download_geoip(now: chrono::DateTime<chrono::Utc>) -> Result<(), String> {
    ensure_dir(Path::new(GEOIP_DIR), 0o755)?;
    let gz_tmp = PathBuf::from(format!("{GEOIP_PATH}.gz.tmp"));
    let mmdb_tmp = PathBuf::from(format!("{GEOIP_PATH}.new"));
    let res = async {
        fetch_gz(now, &gz_tmp).await?;
        let size = gunzip_capped(&gz_tmp, &mmdb_tmp).await?;
        let tail = read_tail(&mmdb_tmp, MMDB_TAIL)?;
        check_mmdb(size, &tail)?;
        std::fs::set_permissions(&mmdb_tmp, std::fs::Permissions::from_mode(0o644))
            .and_then(|_| std::fs::rename(&mmdb_tmp, GEOIP_PATH))
            .map_err(|e| format!("Cannot install the country database: {e}"))
    }
    .await;
    let _ = std::fs::remove_file(&gz_tmp);
    let _ = std::fs::remove_file(&mmdb_tmp);
    res
}

/// Current month's file, or the previous month's when the first is a 404.
async fn fetch_gz(now: chrono::DateTime<chrono::Utc>, dest: &Path) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let client = reqwest::Client::builder()
        .timeout(GEOIP_HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(20))
        .user_agent("dockpanel-agent")
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let mut last = String::new();
    for month in geoip_months(now) {
        let url = geoip_url(&month);
        let mut resp = client.get(&url).send().await.map_err(|e| format!("Download of {url} failed: {e}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            last = format!("{url} answered 404");
            continue;
        }
        if !resp.status().is_success() {
            return Err(format!("{url} answered {}", resp.status()));
        }
        let mut f = tokio::fs::File::create(dest).await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
        let mut total: u64 = 0;
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("Download of {url} failed: {e}"))? {
            total += chunk.len() as u64;
            if total > GEOIP_MAX_BYTES {
                return Err("The country database download is too large".into());
            }
            f.write_all(&chunk).await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
        }
        f.flush().await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
        return Ok(());
    }
    Err(last)
}

/// `gzip -dc src > dest`, stopped past the size cap. Returns the size.
async fn gunzip_capped(src: &Path, dest: &Path) -> Result<u64, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut child = safe_command("gzip")
        .arg("-dc")
        .arg("--")
        .arg(src)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("gzip could not run: {e}"))?;
    let mut out = child.stdout.take().ok_or("gzip has no output")?;
    let mut f = tokio::fs::File::create(dest).await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
    let copy = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = out.read(&mut buf).await.map_err(|e| format!("gzip: {e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > GEOIP_MAX_BYTES {
                return Err("The country database is too large once decompressed".to_string());
            }
            f.write_all(&buf[..n]).await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
        }
        f.flush().await.map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
        Ok(total)
    };
    let total = match tokio::time::timeout(Duration::from_secs(120), copy).await {
        Ok(r) => r?,
        Err(_) => return Err("Decompressing the country database timed out".into()),
    };
    let status = child.wait().await.map_err(|e| format!("gzip: {e}"))?;
    if !status.success() {
        return Err("The downloaded country database is not a valid gzip file".into());
    }
    Ok(total)
}

fn read_tail(path: &Path, n: u64) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    f.seek(SeekFrom::Start(len.saturating_sub(n))).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

// ── A-5 run ─────────────────────────────────────────────────────────────────

/// A-5 reply.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub domain: String,
    pub updated_at: Option<String>,
    pub duration_ms: u64,
    pub initialized: bool,
    pub error: Option<String>,
}

impl RunOutcome {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": self.domain,
            "ok": self.error.is_none(),
            "updated_at": self.updated_at,
            "duration_ms": self.duration_ms,
            "initialized": self.initialized,
            "error": self.error,
        })
    }
}

/// A-5: compute the statistics of `domain`.
pub async fn run(domain: &str) -> Result<RunOutcome, StatsErr> {
    if !crate::routes::is_valid_domain(domain) {
        return Err(StatsErr::bad("Invalid domain"));
    }
    if !is_installed().await {
        return Err(StatsErr::precondition(NOT_INSTALLED_MSG));
    }
    if normal_inputs(Path::new(LOG_DIR), domain, Path::exists).is_empty() {
        return Err(StatsErr::not_found(NO_LOG_MSG));
    }
    // Detached from the request: a caller that gives up (client timeout)
    // must not kill GoAccess half-way, or a long first run never finishes.
    let domain = domain.to_string();
    tokio::spawn(async move { run_queued(&domain).await })
        .await
        .map_err(|_| StatsErr::internal("internal error"))?
}

async fn run_queued(domain: &str) -> Result<RunOutcome, StatsErr> {
    let Ok(_run) = tokio::time::timeout(QUEUE_TIMEOUT, RUN_LOCK.lock()).await else {
        return Err(StatsErr::conflict(RUN_BUSY_MSG));
    };
    let _mark = RunningMark::set(domain);

    maybe_update_geoip().await;

    let started = Instant::now();
    let dir = domain_dir(Path::new(STATS_ROOT), domain);
    let previous = read_state(&dir);
    let res = match ensure_stats_root().and_then(|_| ensure_dir(&dir, 0o700)) {
        Ok(()) => compute(domain, &dir, started + RUN_TIMEOUT).await,
        Err(e) => Err((false, e)),
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    let (initialized, error) = match res {
        Ok(init) => (init, None),
        Err((init, e)) => (init, Some(truncate_chars(&e, ERROR_MAX_CHARS))),
    };
    let state = RunState {
        updated_at: if error.is_none() { Some(ts(chrono::Utc::now())) } else { previous.updated_at },
        error: error.clone(),
        duration_ms: Some(duration_ms),
    };
    if let Ok(body) = serde_json::to_vec_pretty(&state) {
        if let Err(e) = write_atomic(&dir.join("state.json"), &body, 0o600) {
            tracing::warn!("web stats {domain}: {e}");
        }
    }
    if error.is_some() {
        tracing::warn!("Web statistics of {domain} failed after {duration_ms} ms");
    } else {
        tracing::info!("Web statistics of {domain} updated in {duration_ms} ms");
    }
    Ok(RunOutcome { domain: domain.to_string(), updated_at: state.updated_at, duration_ms, initialized, error })
}

/// Initialisation when due, then the normal pass. `Ok(initialized)`, or
/// `Err((initialized, message))`.
async fn compute(domain: &str, dir: &Path, deadline: Instant) -> Result<bool, (bool, String)> {
    let db = dir.join("db");
    let db_s = db.to_string_lossy().into_owned();
    let initialized = db_is_empty(&db);
    ensure_dir(&db, 0o700).map_err(|e| (initialized, e))?;
    let geoip = Path::new(GEOIP_PATH).is_file().then_some(GEOIP_PATH);

    if initialized {
        let names: Vec<String> = std::fs::read_dir(LOG_DIR)
            .map(|it| it.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        let gz: Vec<String> = gz_logs(domain, &names)
            .into_iter()
            .map(|n| Path::new(LOG_DIR).join(n).to_string_lossy().into_owned())
            .collect();
        if !gz.is_empty() {
            let out = dir.join("init.tmp.html");
            let out_s = out.to_string_lossy().into_owned();
            let args = goaccess_args(
                &["-".to_string()],
                &PassOptions {
                    db_path: &db_s,
                    restore: false,
                    geoip,
                    browsers_file: BROWSERS_FILE,
                    title: domain,
                    output: &out_s,
                },
            );
            let res = run_init(&gz, "goaccess", args, deadline).await;
            let _ = std::fs::remove_file(&out);
            if let Err(e) = res {
                // An empty db makes the next call try the old logs again.
                let _ = std::fs::remove_dir_all(&db);
                return Err((true, format!("Reading the rotated logs failed: {e}")));
            }
        }
    }

    let inputs = normal_inputs(Path::new(LOG_DIR), domain, Path::exists);
    if inputs.is_empty() {
        return Err((initialized, NO_LOG_MSG.to_string()));
    }
    // `--restore` only when there is something to restore.
    let restore = !db_is_empty(&db);
    let tmp = dir.join("report.tmp.html");
    let tmp_s = tmp.to_string_lossy().into_owned();
    let args = goaccess_args(
        &inputs,
        &PassOptions { db_path: &db_s, restore, geoip, browsers_file: BROWSERS_FILE, title: domain, output: &tmp_s },
    );
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = run_goaccess("goaccess", args, Stdio::null(), deadline).await {
        let _ = std::fs::remove_file(&tmp);
        return Err((initialized, e));
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .and_then(|_| std::fs::rename(&tmp, dir.join("report.html")))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            (initialized, format!("Cannot install the report: {e}"))
        })?;
    Ok(initialized)
}

/// `nice -n 19 ionice -c 3 -t <program> <args>`: lowest CPU and idle I/O
/// priority (`-t`: still run when the I/O class cannot be set).
fn low_priority(program: &str) -> tokio::process::Command {
    let mut c = safe_command("nice");
    c.args(["-n", "19", "ionice", "-c", "3", "-t", program]);
    c.kill_on_drop(true);
    c
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn timed_out() -> String {
    format!("GoAccess was stopped after {} minutes", RUN_TIMEOUT.as_secs() / 60)
}

/// One GoAccess run (`program` is `goaccess`, or a stand-in in tests); `Err`
/// carries its exit status and (truncated) stderr.
async fn run_goaccess(program: &str, args: Vec<String>, stdin: Stdio, deadline: Instant) -> Result<(), String> {
    let child = low_priority(program)
        .args(&args)
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("GoAccess could not run: {e}"))?;
    // On timeout the future is dropped with the child: `kill_on_drop` kills it.
    let out = match tokio::time::timeout(remaining(deadline), child.wait_with_output()).await {
        Ok(r) => r.map_err(|e| format!("GoAccess could not run: {e}"))?,
        Err(_) => return Err(timed_out()),
    };
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    let why = why.trim();
    let code = out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into());
    Err(truncate_chars(&format!("GoAccess failed (exit {code}): {why}"), ERROR_MAX_CHARS))
}

/// `zcat <gz...> | goaccess - ...` (oldest file first).
async fn run_init(gz: &[String], program: &str, args: Vec<String>, deadline: Instant) -> Result<(), String> {
    let mut zcat = low_priority("zcat")
        .arg("--")
        .args(gz)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("zcat could not run: {e}"))?;
    let pipe: Stdio = zcat
        .stdout
        .take()
        .ok_or("zcat has no output")?
        .try_into()
        .map_err(|e| format!("zcat output: {e}"))?;
    run_goaccess(program, args, pipe, deadline).await?;
    match tokio::time::timeout(remaining(deadline).max(Duration::from_secs(5)), zcat.wait()).await {
        Ok(Ok(s)) if s.success() => {}
        // A damaged archive is skipped by zcat; what could be read is counted.
        Ok(_) => tracing::warn!("zcat reported an error on a rotated log; the readable ones were counted"),
        Err(_) => return Err(timed_out()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("dp-ws-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn opts<'a>(restore: bool, geoip: Option<&'a str>, output: &'a str) -> PassOptions<'a> {
        PassOptions {
            db_path: "/var/lib/dockpanel/stats/a.tld/db",
            restore,
            geoip,
            browsers_file: BROWSERS_FILE,
            title: "a.tld",
            output,
        }
    }

    #[test]
    fn command_line_with_both_logs_and_geoip() {
        let present = |_: &Path| true;
        let inputs = normal_inputs(Path::new(LOG_DIR), "a.tld", present);
        assert_eq!(inputs, vec!["/var/log/nginx/a.tld.access.log.1", "/var/log/nginx/a.tld.access.log"]);
        let a = goaccess_args(&inputs, &opts(true, Some(GEOIP_PATH), "/var/lib/dockpanel/stats/a.tld/report.tmp.html"));
        assert_eq!(
            a,
            vec![
                "/var/log/nginx/a.tld.access.log.1",
                "/var/log/nginx/a.tld.access.log",
                "--log-format=COMBINED",
                "--persist",
                "--restore",
                "--db-path=/var/lib/dockpanel/stats/a.tld/db",
                "--keep-last=365",
                "--geoip-database=/var/lib/dockpanel/geoip/dbip-country-lite.mmdb",
                "--browsers-file=/var/lib/dockpanel/stats/browsers.list",
                "--no-global-config",
                "--html-report-title=a.tld",
                "-o",
                "/var/lib/dockpanel/stats/a.tld/report.tmp.html",
            ]
        );
    }

    #[test]
    fn command_line_without_missing_files_or_geoip() {
        // Only the current log (no rotation yet).
        let only_current = |p: &Path| !p.to_string_lossy().ends_with(".1");
        let inputs = normal_inputs(Path::new(LOG_DIR), "a.tld", only_current);
        assert_eq!(inputs, vec!["/var/log/nginx/a.tld.access.log"]);
        // Only `.1` (the current log was just rotated away).
        let only_old = |p: &Path| p.to_string_lossy().ends_with(".1");
        assert_eq!(normal_inputs(Path::new(LOG_DIR), "a.tld", only_old), vec!["/var/log/nginx/a.tld.access.log.1"]);
        assert!(normal_inputs(Path::new(LOG_DIR), "a.tld", |_: &Path| false).is_empty());

        let a = goaccess_args(&inputs, &opts(true, None, "/x/report.tmp.html"));
        assert!(!a.iter().any(|s| s.starts_with("--geoip-database")));
        assert_eq!(a[0], "/var/log/nginx/a.tld.access.log");
        assert_eq!(a[1], "--log-format=COMBINED");

        // Initialisation from standard input: `-`, no `--restore`.
        let a = goaccess_args(&["-".to_string()], &opts(false, Some(GEOIP_PATH), "/x/init.tmp.html"));
        assert_eq!(a[0], "-");
        assert!(a.contains(&"--persist".to_string()));
        assert!(!a.contains(&"--restore".to_string()));
        assert_eq!(&a[a.len() - 2..], ["-o", "/x/init.tmp.html"]);
    }

    #[test]
    fn rotated_logs_are_read_oldest_first() {
        let names = [
            "a.tld.access.log",
            "a.tld.access.log.1",
            "a.tld.access.log.2.gz",
            "a.tld.access.log.10.gz",
            "a.tld.access.log.3.gz",
            "a.tld.error.log.2.gz",
            "b.a.tld.access.log.4.gz",
            "xa.tld.access.log.5.gz",
            "a.tld.access.log.x.gz",
            "a.tld.access.log..gz",
            "a.tld.access.log.7.gz.old",
        ];
        assert_eq!(
            gz_logs("a.tld", names),
            vec!["a.tld.access.log.10.gz", "a.tld.access.log.3.gz", "a.tld.access.log.2.gz"]
        );
        assert!(gz_logs("a.tld", ["a.tld.access.log"]).is_empty());
    }

    #[test]
    fn invalid_domains_are_rejected_before_the_disk() {
        let root = tmp();
        std::fs::create_dir_all(root.join("keep")).unwrap();
        for bad in ["", "..", "../etc", "a/b.tld", "nodot", "a..tld", "-a.tld", "a.tld/..", "a.tld\n"] {
            assert!(!crate::routes::is_valid_domain(bad), "{bad:?}");
            assert!(remove_under(&root, bad).is_err(), "{bad:?}");
            assert!(rename_under(&root, bad, "b.tld").is_err(), "{bad:?}");
            assert!(rename_under(&root, "a.tld", bad).is_err(), "{bad:?}");
        }
        assert!(root.join("keep").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn run_rejects_an_invalid_domain_with_400() {
        let e = run("../etc").await.unwrap_err();
        assert_eq!(e, StatsErr::bad("Invalid domain"));
    }

    #[test]
    fn lifecycle_rename_remove_purge() {
        let root = tmp();
        std::fs::create_dir_all(root.join("a.tld/db")).unwrap();
        std::fs::write(root.join("a.tld/report.html"), "x").unwrap();
        std::fs::write(root.join("browsers.list"), BROWSERS_BODY).unwrap();
        assert_eq!(count_sites(&root), 1);

        assert_eq!(rename_under(&root, "a.tld", "b.tld"), Ok(true));
        assert!(root.join("b.tld/report.html").is_file() && !root.join("a.tld").exists());
        // Nothing to move.
        assert_eq!(rename_under(&root, "a.tld", "c.tld"), Ok(false));
        // The destination exists: left alone.
        std::fs::create_dir_all(root.join("c.tld")).unwrap();
        assert!(rename_under(&root, "b.tld", "c.tld").is_err());
        assert!(root.join("b.tld/report.html").is_file());

        assert_eq!(remove_under(&root, "c.tld"), Ok(true));
        assert_eq!(remove_under(&root, "c.tld"), Ok(false));

        std::fs::create_dir_all(root.join("d.tld")).unwrap();
        assert_eq!(purge_under(&root), Ok(2));
        assert_eq!(count_sites(&root), 0);
        assert_eq!(std::fs::read_to_string(root.join("browsers.list")).unwrap(), BROWSERS_BODY);
        assert_eq!(purge_under(&root.join("missing")), Ok(0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn small_helpers() {
        assert_eq!(parse_version("GoAccess - 1.8.1.\nFor more details visit: https://goaccess.io/\n").as_deref(), Some("1.8.1"));
        assert_eq!(parse_version("GoAccess - 1.9.3.\n").as_deref(), Some("1.9.3"));
        assert_eq!(parse_version(""), None);
        assert_eq!(truncate_chars("ééé", 2), "éé");
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(BROWSERS_BODY, "DockPanel-Uptime\tCrawlers\n");

        let root = tmp();
        assert!(db_is_empty(&root.join("db")));
        std::fs::create_dir_all(root.join("db")).unwrap();
        assert!(db_is_empty(&root.join("db")));
        std::fs::write(root.join("db/x.db"), "1").unwrap();
        assert!(!db_is_empty(&root.join("db")));
        assert_eq!(read_state(&root), RunState::default());
        std::fs::write(root.join("state.json"), r#"{"updated_at":"2026-11-16T10:00:03Z","error":null,"duration_ms":4200}"#).unwrap();
        assert_eq!(read_state(&root).duration_ms, Some(4200));
        write_atomic(&root.join("w.json"), b"{}", 0o600).unwrap();
        assert_eq!(std::fs::metadata(root.join("w.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!root.join("w.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc)
    }

    #[test]
    fn geoip_months_and_urls() {
        assert_eq!(geoip_months(at("2026-11-16T10:00:00Z")), ["2026-11", "2026-10"]);
        assert_eq!(geoip_months(at("2027-01-01T00:00:00Z")), ["2027-01", "2026-12"]);
        assert_eq!(geoip_url("2026-11"), "https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz");
    }

    #[test]
    fn geoip_update_rhythm() {
        let now = at("2026-11-16T10:00:00Z");
        let m = |up: Option<&str>, att: Option<&str>| GeoMeta {
            updated_at: up.map(str::to_string),
            attempted_at: att.map(str::to_string),
            error: None,
        };
        // Missing database: due, unless tried in the last 24 h.
        assert!(geoip_due(false, &GeoMeta::default(), now));
        assert!(!geoip_due(false, &m(None, Some("2026-11-16T00:00:00Z")), now));
        assert!(geoip_due(false, &m(None, Some("2026-11-15T09:00:00Z")), now));
        // Fresh database: not due.
        assert!(!geoip_due(true, &m(Some("2026-11-01T03:00:00Z"), Some("2026-11-01T03:00:00Z")), now));
        // Older than 31 days: due, unless the last attempt is recent.
        assert!(geoip_due(true, &m(Some("2026-10-01T03:00:00Z"), Some("2026-10-01T03:00:00Z")), now));
        assert!(!geoip_due(true, &m(Some("2026-10-01T03:00:00Z"), Some("2026-11-16T03:00:00Z")), now));
        // Present but no record of it: due.
        assert!(geoip_due(true, &GeoMeta::default(), now));
    }

    #[test]
    fn mmdb_checks() {
        let mut tail = vec![0u8; 4096];
        tail.extend_from_slice(MMDB_MARKER);
        tail.extend_from_slice(b"metadata");
        assert!(check_mmdb(5 * 1024 * 1024, &tail).is_ok());
        assert!(check_mmdb(1000, &tail).unwrap_err().contains("too small"));
        assert!(check_mmdb(300 * 1024 * 1024, &tail).unwrap_err().contains("too large"));
        assert!(check_mmdb(5 * 1024 * 1024, &[0u8; 4096]).unwrap_err().contains("not an mmdb"));
    }

    /// The `nice`/`ionice` chain, the zcat pipe in the given order, exit
    /// statuses and the timeout, with `tee` and `sh` standing in for GoAccess.
    #[tokio::test]
    async fn process_plumbing() {
        let d = tmp();
        let mut gz = Vec::new();
        for (name, body) in [("old.log", "line from .3\n"), ("new.log", "line from .2\n")] {
            let p = d.join(name);
            std::fs::write(&p, body).unwrap();
            let st = safe_command("gzip").arg(&p).status().await.unwrap();
            assert!(st.success());
            gz.push(format!("{}.gz", p.display()));
        }
        let far = Instant::now() + Duration::from_secs(60);
        let out = d.join("seen.txt");
        run_init(&gz, "tee", vec![out.to_string_lossy().into_owned()], far).await.unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "line from .3\nline from .2\n");

        let e = run_goaccess("sh", vec!["-c".into(), "echo boom >&2; exit 3".into()], Stdio::null(), far)
            .await
            .unwrap_err();
        assert_eq!(e, "GoAccess failed (exit 3): boom");
        let e = run_goaccess("sleep", vec!["5".into()], Stdio::null(), Instant::now() + Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(e.contains("stopped after"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn outcome_json() {
        let o = RunOutcome {
            domain: "a.tld".into(),
            updated_at: Some("2026-11-16T10:00:03Z".into()),
            duration_ms: 4200,
            initialized: false,
            error: None,
        };
        assert_eq!(
            o.to_json(),
            serde_json::json!({"domain":"a.tld","ok":true,"updated_at":"2026-11-16T10:00:03Z","duration_ms":4200,"initialized":false,"error":null})
        );
        let f = RunOutcome { error: Some("GoAccess failed (exit 1): x".into()), ..o };
        assert_eq!(f.to_json()["ok"], false);
    }
}
