//! CVE scanner engine (conception 13, lot 1): install and version check of
//! grype/syft, inventory (SBOM per target), matching, and the grype database.
//!
//! Every syft/grype/find run of this module goes through a transient systemd
//! unit ([`scanner_command`]): a big `node_modules` or grype loading its
//! database would otherwise run inside the agent's own cgroup
//! (`MemoryMax=512M`) and could get the agent killed. The unit gets its own
//! memory cap, the lowest CPU and I/O priority, and HOME/TMPDIR/cache under
//! the scanners directory. Reports are written to files by the scanners
//! (`-o syft-json=<path>`, `-o json=<path>`, `-fprint0 <path>`) and parsed with
//! a streaming reader into typed structs, never into one big `Value`.
//!
//! Work runs as `migration_jobs` jobs (kinds `vuln_install`, `vuln_db_update`,
//! `vuln_inventory`, `vuln_match`, key `"server"`), polled through
//! `GET /jobs/{job_id}`. Same kind while one is running returns the running
//! job's id. Across kinds, two async locks serialize the work: inventory takes
//! [`INVENTORY_LOCK`], install takes it and then [`DB_LOCK`] for writing, so
//! binaries are never replaced under a running scan. [`DB_LOCK`] is a
//! read/write lock over the grype database cache: `grype db update` (the only
//! run allowed to download, see [`scanner_env`]) writes, every grype run that
//! reads the database (match, image report, the security scan's container
//! check) reads. A run that reads the database never downloads one.
//!
//! `grype db update` downloads into `grype-db-download*` under the cache before
//! it moves the database into place. A run killed half way (timeout, agent
//! restart) leaves that dir behind, 3.4 GB each time: [`sweep_scanner_leftovers`]
//! removes the abandoned ones at agent startup and around every db update.

use crate::safe_cmd::{safe_command_unsandboxed, UnsandboxedCommand};
use crate::services::migration_jobs::{self, JobHandle};
use crate::services::{image_scanner, sbom_scanner};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

/// Filesystem whose free space gates install and db update.
const DATA_ROOT: &str = "/var/lib/dockpanel";
pub const SCANNERS_DIR: &str = "/var/lib/dockpanel/scanners";
pub const HOME_DIR: &str = "/var/lib/dockpanel/scanners/home";
pub const TMP_DIR: &str = "/var/lib/dockpanel/scanners/tmp";
pub const CACHE_DIR: &str = "/var/lib/dockpanel/scanners/cache";
pub const SBOM_DIR: &str = "/var/lib/dockpanel/scanners/sboms";
const WWW_ROOT: &str = "/var/www";
const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// Install and db update refuse to run below this much free space. Measured in
/// the lab: the unpacked v6 database is ~3.3 GiB, and an update keeps the old
/// copy until the new one is in place.
const MIN_FREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Findings kept per target (highest `risk` first).
pub const MAX_FINDINGS: usize = 5000;
/// Bound on the `present` key list sent beside a truncated result. A key is
/// ~100 bytes of JSON, so this stays near 3 MB per target, well inside the
/// panel's 50 MB response cap for a match job of 5 targets. Past it the list is
/// left out and the panel resolves nothing for that target, as before.
pub const MAX_PRESENT_KEYS: usize = 30_000;
/// Bound on targets per request.
const MAX_TARGETS: usize = 10_000;

const SYFT_TIMEOUT: Duration = Duration::from_secs(1800);
const MATCH_TIMEOUT: Duration = Duration::from_secs(600);
const DB_UPDATE_TIMEOUT: Duration = Duration::from_secs(900);
const FIND_TIMEOUT: Duration = Duration::from_secs(600);
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// Properties of the transient unit every scanner run gets.
pub const SCANNER_PROPERTIES: [&str; 4] =
    ["MemoryMax=1536M", "Nice=19", "IOSchedulingClass=idle", "CPUQuota=50%"];

/// Site directories syft never reads (the active release is scanned through
/// `current`, so `releases/` only holds older ones).
pub const SITE_EXCLUDES: [&str; 5] = [
    "**/.git/**",
    "**/wp-content/uploads/**",
    "**/cache/**",
    "**/releases/**",
    "**/storage/logs/**",
];

/// Everything but the package database for the `system` target.
pub const SYSTEM_EXCLUDES: [&str; 17] = [
    "./proc/**",
    "./sys/**",
    "./dev/**",
    "./run/**",
    "./var/www/**",
    "./var/lib/docker/**",
    // Docker 29 keeps image layers in the containerd store: without this the
    // OS SBOM picked up every image's own dpkg database (lab, 2026-11-20).
    "./var/lib/containerd/**",
    "./var/lib/lxc/**",
    "./var/lib/lxd/**",
    "./var/lib/dockpanel/**",
    "./home/**",
    "./tmp/**",
    "./root/**",
    "./srv/**",
    "./mnt/**",
    "./media/**",
    "./snap/**",
];

/// File names `find` returns for a site fingerprint; [`is_dependency_file`]
/// then keeps only the right ones (`package.json` and `installed.json` are
/// only meaningful at one place).
const FINGERPRINT_NAMES: [&str; 15] = [
    "composer.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements*.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
    "*.jar",
    "*.war",
    "*.ear",
    "installed.json",
    "package.json",
];

static INVENTORY_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
static DB_LOCK: LazyLock<tokio::sync::RwLock<()>> = LazyLock::new(|| tokio::sync::RwLock::new(()));

// ---------------------------------------------------------------------------
// Transient unit
// ---------------------------------------------------------------------------

/// Environment of a scanner run. `GRYPE_DB_AUTO_UPDATE=false` everywhere but
/// `grype db update`: matching must use the database the daily update put
/// there, never start a 200 MB download on its own.
pub fn scanner_env(auto_update: bool) -> Vec<(&'static str, &'static str)> {
    let mut env = vec![
        ("HOME", HOME_DIR),
        ("TMPDIR", TMP_DIR),
        ("XDG_CACHE_HOME", CACHE_DIR),
        ("GRYPE_DB_CACHE_DIR", image_scanner::GRYPE_DB_CACHE),
        ("GRYPE_CHECK_FOR_APP_UPDATE", "false"),
        ("SYFT_CHECK_FOR_APP_UPDATE", "false"),
    ];
    if !auto_update {
        env.push(("GRYPE_DB_AUTO_UPDATE", "false"));
    }
    env
}

/// A scanner command in its own transient unit, capped and deprioritized.
/// Also the syft of `sbom_scanner::generate_sbom`.
pub(crate) fn scanner_command(binary: &str, auto_update: bool) -> UnsandboxedCommand {
    let mut cmd = safe_command_unsandboxed(binary, &scanner_env(auto_update));
    for p in SCANNER_PROPERTIES {
        cmd.property(p);
    }
    cmd
}

/// How long a grype run that reads the database waits for [`DB_LOCK`]. A db
/// update holds it for minutes: past this the run is skipped, never queued.
pub const DB_READ_WAIT: Duration = Duration::from_secs(30);

/// A database older than this (its `built` date) gets a db update started in
/// the background by the image report. The daily vuln sweeper normally keeps it
/// fresh; this keeps a server that only uses the image scanner (sweeper off)
/// refreshing its database, as grype's own auto update used to.
const IMAGE_DB_REFRESH_HOURS: i64 = 48;

/// Whether a database built at `built` (RFC 3339) is due a refresh. An
/// unreadable date is not: the update would then start on every scan.
pub fn db_refresh_due(built: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match chrono::DateTime::parse_from_rfc3339(built.trim()) {
        Ok(t) => now.signed_duration_since(t.with_timezone(&chrono::Utc)) > chrono::Duration::hours(IMAGE_DB_REFRESH_HOURS),
        Err(_) => false,
    }
}

/// The grype run of an image report and of the security scan's container
/// check: auto update off, report written to `out`. The security scan used to
/// run grype with `GRYPE_DB_CACHE_DIR` alone, so grype downloaded a fresh
/// 3.4 GB database on every scan, past the backend's 60 s, and left it behind
/// in `grype-db-download*` (v3.1.0-rc.4, 2026-11-25).
pub(crate) fn grype_read_command(image: &str, out: &Path, extra: &[&str]) -> UnsandboxedCommand {
    let mut cmd = scanner_command(image_scanner::GRYPE_BIN, false);
    cmd.args([image.to_string(), "-o".to_string(), format!("json={}", out.display()), "-q".to_string()]);
    cmd.args(extra);
    cmd
}

/// One grype report of `image`, written to a file by grype and read back,
/// with auto update off. The caller holds [`DB_LOCK`] for reading.
async fn grype_report_locked(image: &str, extra: &[&str], timeout: Duration) -> Result<String, String> {
    let out = Path::new(TMP_DIR).join(format!("image-{}.json", uuid::Uuid::new_v4()));
    let res = grype_read_command(image, &out, extra).output_with_timeout(timeout).await;
    let report = match res {
        Err(e) => Err(e),
        Ok(r) if !r.status.success() => Err(format!("grype scan failed: {}", stderr_tail(&r, 400))),
        Ok(_) => tokio::fs::read_to_string(&out)
            .await
            .map_err(|e| format!("read grype report: {e}")),
    };
    let _ = std::fs::remove_file(&out);
    report
}

/// Raw grype JSON report of one image (`image_scanner::scan_image`, which the
/// deploy gate calls on every armed Git deploy), in the same capped transient
/// unit as every other scanner run: inside the agent's own 512M cgroup, loading
/// the 3.3 GiB database pinned the agent at its memory limit (lab, 2026-11-20).
///
/// It never downloads. With grype's auto update on, as it used to be, a 180 s
/// scan that started a 3.4 GB download was stopped half way, left the download
/// behind and raced a db update outside [`DB_LOCK`]. Instead no database, or
/// one built more than 48 h ago, starts the `vuln_db_update` job (locked, free
/// space gated, swept), and no database at all is an error that says so: the
/// deploy gate treats it as "scanner unavailable" and goes on.
///
/// The run is a task of its own, so the lock, the unit and the report cleanup
/// finish even when the request that asked is dropped.
pub async fn grype_image_report(image: &str, timeout: Duration) -> Result<String, String> {
    let image = image.to_string();
    tokio::spawn(async move {
        let _db = tokio::time::timeout(DB_READ_WAIT, DB_LOCK.read())
            .await
            .map_err(|_| "the vulnerability database is being updated, scan again in a few minutes".to_string())?;
        ensure_dirs()?;
        match db_status().await {
            None => {
                start_db_update();
                return Err("no vulnerability database yet: an update was started, scan again in a few minutes".into());
            }
            Some(db) if db_refresh_due(&db.built, chrono::Utc::now()) => {
                start_db_update();
            }
            Some(_) => {}
        }
        grype_report_locked(&image, &[], timeout).await
    })
    .await
    .unwrap_or_else(|e| Err(format!("grype task failed: {e}")))
}

/// SPDX JSON SBOM of one image (`sbom_scanner::generate_sbom`), written to a
/// file by syft in the scanners' transient unit. It ran in the agent's own
/// cgroup with no HOME or TMPDIR of its own, so the layers syft unpacks for an
/// image landed in the agent's /tmp and stayed there when the 180 s timeout
/// killed it. A task of its own, like [`grype_image_report`].
pub async fn syft_image_sbom(image: &str, timeout: Duration) -> Result<String, String> {
    let image = image.to_string();
    tokio::spawn(async move {
        ensure_dirs()?;
        let out = Path::new(TMP_DIR).join(format!("sbom-{}.spdx.json", uuid::Uuid::new_v4()));
        let res = scanner_command(sbom_scanner::SYFT_BIN, false)
            .args([image, "-o".to_string(), format!("spdx-json={}", out.display()), "-q".to_string()])
            .output_with_timeout(timeout)
            .await;
        let sbom = match res {
            Err(e) => Err(e),
            Ok(r) if !r.status.success() => Err(format!("syft failed: {}", stderr_tail(&r, 400))),
            Ok(_) => tokio::fs::read_to_string(&out)
                .await
                .map_err(|e| format!("read syft output: {e}")),
        };
        let _ = std::fs::remove_file(&out);
        sbom
    })
    .await
    .unwrap_or_else(|e| Err(format!("syft task failed: {e}")))
}

/// Grype reports of several images for the security scan's container check,
/// `--only-fixed`, never downloading. `Err` for the whole call means grype is
/// not usable right now (no database, db update running): the caller falls
/// back as it does without grype. Each image gets `per_image`, and the images
/// left once `budget` is spent are reported as skipped. A task of its own,
/// like [`grype_image_report`].
pub async fn grype_scan_images(
    images: Vec<String>,
    per_image: Duration,
    budget: Duration,
) -> Result<Vec<(String, Result<String, String>)>, String> {
    tokio::spawn(async move {
        let _db = tokio::time::timeout(DB_READ_WAIT, DB_LOCK.read())
            .await
            .map_err(|_| "vulnerability database update in progress".to_string())?;
        ensure_dirs()?;
        if db_status().await.is_none() {
            return Err("no vulnerability database (the CVE scanner's daily update installs it)".into());
        }
        let started = std::time::Instant::now();
        let mut out = Vec::with_capacity(images.len());
        for image in images {
            let left = budget.saturating_sub(started.elapsed());
            if left < Duration::from_secs(10) {
                out.push((image, Err("skipped: the container scan ran out of time".to_string())));
                continue;
            }
            let r = grype_report_locked(&image, &["--only-fixed"], per_image.min(left)).await;
            out.push((image, r));
        }
        Ok(out)
    })
    .await
    .unwrap_or_else(|e| Err(format!("grype task failed: {e}")))
}

// ---------------------------------------------------------------------------
// Leftovers
// ---------------------------------------------------------------------------

/// Name prefix of the temporary dir `grype db update` downloads into, under
/// the database cache.
pub const DB_DOWNLOAD_PREFIX: &str = "grype-db-download";
/// A download dir nothing has written to for this long is abandoned. A live
/// download writes continuously, and a db update is stopped after
/// [`DB_UPDATE_TIMEOUT`] (15 min). The margin covers a unit started by the
/// previous agent process (units outlive the agent), which [`DB_LOCK`] does
/// not see.
pub const DB_DOWNLOAD_IDLE: Duration = Duration::from_secs(30 * 60);
/// Same rule for the scanners' TMPDIR (reports, the image layers syft and grype
/// unpack as `stereoscope-*`). The longest run there is syft's 30 min.
pub const TMP_IDLE: Duration = Duration::from_secs(2 * 3600);

/// Newest mtime of `path` and of everything under it, symlinks not followed.
/// A download dir's own mtime does not move while the file inside it grows.
fn newest_mtime(path: &Path) -> Option<std::time::SystemTime> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mut newest = meta.modified().ok()?;
    if meta.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                if let Some(t) = newest_mtime(&e.path()) {
                    newest = newest.max(t);
                }
            }
        }
    }
    Some(newest)
}

/// Removes the entries of `dir` whose name `select` accepts and that nothing
/// has written to for `idle`; only dirs when `dirs_only`. A symlink is never
/// removed nor followed. Returns what was removed.
fn sweep_idle(dir: &Path, idle: Duration, dirs_only: bool, select: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return removed };
    let now = std::time::SystemTime::now();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !select(&name) {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() || (dirs_only && !ft.is_dir()) {
            continue;
        }
        let path = e.path();
        let Some(t) = newest_mtime(&path) else { continue };
        if now.duration_since(t).unwrap_or_default() < idle {
            continue;
        }
        let r = if ft.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
        match r {
            Ok(()) => removed.push(path),
            Err(err) => tracing::warn!("could not remove {}: {err}", path.display()),
        }
    }
    removed
}

/// Removes the `grype-db-download*` dirs of `cache` idle for `idle`, and
/// nothing else: not the database (`6/`), not a file or a symlink of that name.
pub fn sweep_stale_db_downloads(cache: &Path, idle: Duration) -> Vec<PathBuf> {
    sweep_idle(cache, idle, true, |n| n.starts_with(DB_DOWNLOAD_PREFIX))
}

/// Removes what scanner runs left in `tmp` that nothing has touched for `idle`.
pub fn sweep_stale_tmp(tmp: &Path, idle: Duration) -> Vec<PathBuf> {
    sweep_idle(tmp, idle, false, |_| true)
}

/// Abandoned database downloads and scanner temporaries. At agent startup, and
/// before and after every db update (under [`DB_LOCK`] for writing, so never a
/// download this process is running; the idle rule covers the others).
pub fn sweep_scanner_leftovers() {
    let db = sweep_stale_db_downloads(Path::new(image_scanner::GRYPE_DB_CACHE), DB_DOWNLOAD_IDLE);
    let tmp = sweep_stale_tmp(Path::new(TMP_DIR), TMP_IDLE);
    for p in db.iter().chain(tmp.iter()) {
        tracing::info!("Removed abandoned scanner leftover {}", p.display());
    }
}

/// Last `n` characters of a process's stderr, for an error message.
fn stderr_tail(out: &std::process::Output, n: usize) -> String {
    let s = String::from_utf8_lossy(&out.stderr);
    let s = s.trim();
    let count = s.chars().count();
    s.chars().skip(count.saturating_sub(n)).collect()
}

fn ensure_dirs() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    for d in [SCANNERS_DIR, HOME_DIR, TMP_DIR, CACHE_DIR, SBOM_DIR, image_scanner::GRYPE_DB_CACHE] {
        std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
    }
    for d in [HOME_DIR, TMP_DIR, CACHE_DIR, SBOM_DIR] {
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn free_bytes() -> u64 {
    crate::services::migration_files::free_bytes(Path::new(DATA_ROOT))
}

/// The refusal install and db update give below [`MIN_FREE_BYTES`].
pub fn check_free_space(free: u64) -> Result<(), String> {
    if free < MIN_FREE_BYTES {
        let gib = free as f64 / (1024.0 * 1024.0 * 1024.0);
        return Err(format!("insufficient disk space: {gib:.1} GiB free, 8 GiB required"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Versions and database
// ---------------------------------------------------------------------------

/// `version` of `grype version -o json` / `syft version -o json`, without `v`.
pub fn parse_version_json(stdout: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let s = v.get("version")?.as_str()?.trim().trim_start_matches('v');
    (!s.is_empty()).then(|| s.to_string())
}

/// `(installed, version)` of a managed binary. The version is the real one,
/// read by running it, not the pinned constant.
async fn binary_version(bin: &str) -> (bool, Option<String>) {
    if tokio::fs::metadata(bin).await.is_err() {
        return (false, None);
    }
    let out = scanner_command(bin, false)
        .args(["version", "-o", "json"])
        .output_with_timeout(PROBE_TIMEOUT)
        .await;
    match out {
        Ok(o) if o.status.success() => (true, parse_version_json(&o.stdout)),
        _ => (true, None),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DbInfo {
    pub built: String,
    pub schema: String,
}

/// `grype db status -o json`: `None` when there is no usable database.
pub fn parse_db_status(stdout: &[u8]) -> Option<DbInfo> {
    let v: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    if v.get("valid").and_then(|x| x.as_bool()) == Some(false) {
        return None;
    }
    let pick = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let built = pick(&["built", "Built"])?;
    let schema = pick(&["schemaVersion", "schema_version", "SchemaVersion"]).unwrap_or_default();
    Some(DbInfo { built, schema })
}

async fn db_status() -> Option<DbInfo> {
    if tokio::fs::metadata(image_scanner::GRYPE_BIN).await.is_err() {
        return None;
    }
    let out = scanner_command(image_scanner::GRYPE_BIN, false)
        .args(["db", "status", "-o", "json"])
        .output_with_timeout(PROBE_TIMEOUT)
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_db_status(&out.stdout)
}

fn status_json(
    grype: (bool, Option<String>),
    syft: (bool, Option<String>),
    db: Option<DbInfo>,
    free: u64,
) -> serde_json::Value {
    serde_json::json!({
        "grype": { "installed": grype.0, "version": grype.1 },
        "syft": { "installed": syft.0, "version": syft.1 },
        "db": db,
        "free_bytes": free,
        "expected": {
            "grype": image_scanner::pinned_version(),
            "syft": sbom_scanner::pinned_version(),
        },
    })
}

/// `GET /vulns/status`, also the report of `vuln_install`.
pub async fn status() -> serde_json::Value {
    // The probes run with HOME/TMPDIR under the scanners dir: make sure they exist.
    let _ = ensure_dirs();
    let (g, s, db) = tokio::join!(
        binary_version(image_scanner::GRYPE_BIN),
        binary_version(sbom_scanner::SYFT_BIN),
        db_status()
    );
    status_json(g, s, db, free_bytes())
}

/// `grype db update` in the transient unit (the one run allowed to download).
async fn run_db_update() -> Result<serde_json::Value, String> {
    check_free_space(free_bytes())?;
    ensure_dirs()?;
    if tokio::fs::metadata(image_scanner::GRYPE_BIN).await.is_err() {
        return Err("grype is not installed".into());
    }
    // Callers hold DB_LOCK for writing: no download of this process is running.
    sweep_scanner_leftovers();
    let before = db_status().await;
    let out = scanner_command(image_scanner::GRYPE_BIN, true)
        .args(["db", "update"])
        .output_with_timeout(DB_UPDATE_TIMEOUT)
        .await;
    // What an update stopped half way leaves is taken by a later sweep, once
    // idle for DB_DOWNLOAD_IDLE (its unit may still be stopping right now).
    sweep_scanner_leftovers();
    let out = out?;
    if !out.status.success() {
        return Err(format!("grype db update failed: {}", stderr_tail(&out, 400)));
    }
    let after = db_status()
        .await
        .ok_or_else(|| "grype db update finished but no valid database is present".to_string())?;
    let updated = before.as_ref().map(|b| b.built != after.built).unwrap_or(true);
    Ok(serde_json::json!({ "built": after.built, "schema": after.schema, "updated": updated }))
}

/// Reinstall `bin` unless it already reports `expected`.
async fn ensure_version<F, Fut>(name: &str, bin: &str, expected: &str, install: F) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    if binary_version(bin).await.1.as_deref() == Some(expected) {
        return Ok(());
    }
    // The installers return early when the binary exists: remove it first.
    match tokio::fs::remove_file(bin).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove {bin}: {e}")),
    }
    install().await?;
    match binary_version(bin).await.1 {
        Some(v) if v == expected => Ok(()),
        Some(v) => Err(format!("{name} {v} installed, {expected} expected")),
        None => Err(format!("{name} was installed but its version could not be read")),
    }
}

async fn run_install() -> Result<serde_json::Value, String> {
    check_free_space(free_bytes())?;
    ensure_dirs()?;
    ensure_version("grype", image_scanner::GRYPE_BIN, image_scanner::pinned_version(), image_scanner::install_grype_binary)
        .await?;
    ensure_version("syft", sbom_scanner::SYFT_BIN, sbom_scanner::pinned_version(), sbom_scanner::install_syft)
        .await?;
    run_db_update().await?;
    Ok(status().await)
}

/// `POST /vulns/install`: job `vuln_install`.
pub fn start_install() -> String {
    migration_jobs::spawn("vuln_install", "server", |h| async move {
        let _inventory = INVENTORY_LOCK.lock().await;
        let _db = DB_LOCK.write().await;
        h.progress("install", 0, 0, "Installing grype and syft");
        run_install().await
    })
}

/// `POST /vulns/db-update`: job `vuln_db_update`.
pub fn start_db_update() -> String {
    migration_jobs::spawn("vuln_db_update", "server", |h| async move {
        let _db = DB_LOCK.write().await;
        h.progress("db_update", 0, 0, "Updating the vulnerability database");
        run_db_update().await
    })
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Site,
    Image,
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InventoryTarget {
    pub target_id: String,
    pub kind: TargetKind,
    pub reference: String,
    pub previous_fingerprint: Option<String>,
    pub force: bool,
}

/// A target id is a UUID in its canonical lowercase hyphenated form: it names
/// the SBOM file and is echoed back, so `{...}`, `urn:uuid:` or simple forms
/// (which `Uuid::parse_str` also accepts) are refused.
pub fn validate_target_id(s: &str) -> Result<String, String> {
    match uuid::Uuid::parse_str(s) {
        Ok(u) if u.hyphenated().to_string() == s => Ok(s.to_string()),
        _ => Err(format!("Invalid target_id: {}", s.chars().take(64).collect::<String>())),
    }
}

/// Same rules as the image scanner, plus no leading `-`.
pub fn valid_image_ref(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 512
        && !r.starts_with('-')
        && r.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == ':' || c == '/' || c == '.' || c == '-' || c == '_' || c == '@'
        })
}

#[derive(Deserialize)]
struct RawInventoryRequest {
    targets: Vec<RawTarget>,
}

#[derive(Deserialize)]
struct RawTarget {
    target_id: String,
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default)]
    previous_fingerprint: Option<String>,
    #[serde(default)]
    force: bool,
}

/// Body of `POST /vulns/inventory`; the error is the 400 message.
pub fn parse_inventory_request(body: &[u8]) -> Result<Vec<InventoryTarget>, String> {
    let raw: RawInventoryRequest =
        serde_json::from_slice(body).map_err(|e| format!("Invalid request body: {e}"))?;
    if raw.targets.len() > MAX_TARGETS {
        return Err(format!("Too many targets (max {MAX_TARGETS})"));
    }
    raw.targets
        .into_iter()
        .map(|t| {
            let target_id = validate_target_id(&t.target_id)?;
            let kind = match t.kind.as_str() {
                "site" => TargetKind::Site,
                "image" => TargetKind::Image,
                "system" => TargetKind::System,
                _ => return Err(format!("Invalid kind for {target_id}")),
            };
            let ok = match kind {
                TargetKind::Site => crate::services::quarantine::valid_domain(&t.reference),
                TargetKind::Image => valid_image_ref(&t.reference),
                TargetKind::System => t.reference == "system",
            };
            if !ok {
                return Err(format!("Invalid ref for {target_id}"));
            }
            Ok(InventoryTarget {
                target_id,
                kind,
                reference: t.reference,
                previous_fingerprint: t.previous_fingerprint,
                force: t.force,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct RawMatchRequest {
    target_ids: Vec<String>,
}

/// Body of `POST /vulns/match`; the error is the 400 message.
pub fn parse_match_request(body: &[u8]) -> Result<Vec<String>, String> {
    let raw: RawMatchRequest =
        serde_json::from_slice(body).map_err(|e| format!("Invalid request body: {e}"))?;
    if raw.target_ids.len() > MAX_TARGETS {
        return Err(format!("Too many targets (max {MAX_TARGETS})"));
    }
    raw.target_ids.iter().map(|s| validate_target_id(s)).collect()
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

pub fn sbom_path(target_id: &str) -> PathBuf {
    Path::new(SBOM_DIR).join(format!("{target_id}.json"))
}

/// Root scanned for a site, and whether it is the active release.
///
/// `<www>/<domain>/current` when it is a symbolic link to a directory INSIDE
/// the site (release layout): returned resolved, so `find` and syft (root,
/// outside the agent sandbox) read exactly the directory checked here even if
/// the link is swapped meanwhile. The link belongs to the site's owner: one
/// pointing at `/` or at another site falls back to the site directory.
pub fn site_root(www: &Path, domain: &str) -> (PathBuf, bool) {
    let site = www.join(domain);
    let current = site.join("current");
    let is_link = std::fs::symlink_metadata(&current)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if is_link {
        if let (Ok(real_site), Ok(real_current)) = (std::fs::canonicalize(&site), std::fs::canonicalize(&current)) {
            if real_current != real_site && real_current.starts_with(&real_site) && real_current.is_dir() {
                return (real_current, true);
            }
        }
    }
    (site, false)
}

/// syft arguments for one target. `source` is `dir:<root>`, `docker:<ref>`
/// or `dir:/`; the SBOM goes to `out`, never to stdout. `active_release`: the
/// site root is a release directory itself, so `**/releases/**` (meant for the
/// older releases next to it) is not excluded.
pub fn syft_args(kind: TargetKind, source: &str, out: &Path, active_release: bool) -> Vec<String> {
    let mut a = vec![
        "scan".to_string(),
        source.to_string(),
        "-o".to_string(),
        format!("syft-json={}", out.display()),
        "-q".to_string(),
    ];
    let excludes: &[&str] = match kind {
        TargetKind::Site => &SITE_EXCLUDES,
        TargetKind::Image => &[],
        TargetKind::System => &SYSTEM_EXCLUDES,
    };
    for e in excludes {
        if active_release && *e == "**/releases/**" {
            continue;
        }
        a.push("--exclude".into());
        a.push((*e).to_string());
    }
    if kind == TargetKind::System {
        // Distro identification (os-release) is not a cataloger: syft does it
        // for every `dir:` source, so the selection keeps it.
        a.push("--select-catalogers".into());
        a.push("dpkg".into());
    }
    a
}

/// `find` arguments listing a site's candidate dependency files: depth 8, no
/// descent into `.git`, `releases` or `wp-content/uploads`, symbolic links
/// never followed (except the root itself, `-H`), NUL-separated paths
/// written to `out`.
pub fn find_args(root: &Path, out: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-H".into(),
        root.display().to_string(),
        "-maxdepth".into(),
        "8".into(),
        "(".into(),
        "-name".into(),
        ".git".into(),
        "-o".into(),
        "-name".into(),
        "releases".into(),
        "-o".into(),
        "-path".into(),
        "*/wp-content/uploads".into(),
        ")".into(),
        "-prune".into(),
        "-o".into(),
        "-type".into(),
        "f".into(),
        "(".into(),
    ];
    for (i, n) in FINGERPRINT_NAMES.iter().enumerate() {
        if i > 0 {
            a.push("-o".into());
        }
        a.push("-name".into());
        a.push((*n).to_string());
    }
    a.push(")".into());
    a.push("-fprint0".into());
    a.push(out.display().to_string());
    a
}

/// True for a path (relative to the site root) whose change means the
/// site's dependencies may have changed.
pub fn is_dependency_file(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    let Some(name) = parts.last().copied() else { return false };
    match name {
        "composer.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "Pipfile.lock"
        | "poetry.lock" | "Gemfile.lock" | "go.sum" | "Cargo.lock" => true,
        "installed.json" => {
            parts.len() >= 3 && parts[parts.len() - 3] == "vendor" && parts[parts.len() - 2] == "composer"
        }
        "package.json" => {
            // node_modules/<pkg>/package.json or node_modules/@scope/<pkg>/package.json
            let n = parts.len();
            (n >= 3 && parts[n - 3] == "node_modules")
                || (n >= 4 && parts[n - 4] == "node_modules" && parts[n - 3].starts_with('@'))
        }
        _ => {
            (name.starts_with("requirements") && name.ends_with(".txt"))
                || name.ends_with(".jar")
                || name.ends_with(".war")
                || name.ends_with(".ear")
        }
    }
}

/// sha256 of the sorted `path\tsize\tmtime` lines, one per line.
pub fn fingerprint_lines(mut lines: Vec<String>) -> String {
    lines.sort();
    let mut h = sha2::Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// Lines of the fingerprint from `find -fprint0` output under `root`: paths
/// made relative, filtered, then sized and dated (without following links).
fn fingerprint_from_find(root: &Path, raw: &[u8]) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let prefix = format!("{}/", root.display());
    let mut lines = Vec::new();
    for rec in raw.split(|b| *b == 0) {
        if rec.is_empty() {
            continue;
        }
        let full = String::from_utf8_lossy(rec);
        let Some(rel) = full.strip_prefix(&prefix) else { continue };
        if !is_dependency_file(rel) {
            continue;
        }
        let Ok(m) = std::fs::symlink_metadata(full.as_ref()) else { continue };
        if !m.file_type().is_file() {
            continue;
        }
        lines.push(format!("{rel}\t{}\t{}", m.len(), m.mtime()));
    }
    lines
}

async fn site_fingerprint(target_id: &str, root: &Path) -> Result<String, String> {
    let out = Path::new(TMP_DIR).join(format!("find-{target_id}"));
    let _ = std::fs::remove_file(&out);
    let res = scanner_command("find", false)
        .args(find_args(root, &out))
        .output_with_timeout(FIND_TIMEOUT)
        .await;
    let raw = std::fs::read(&out);
    let _ = std::fs::remove_file(&out);
    let res = res?;
    if !res.status.success() {
        return Err(format!("listing dependency files failed: {}", stderr_tail(&res, 300)));
    }
    let raw = raw.map_err(|e| format!("read dependency file list: {e}"))?;
    let root = root.to_path_buf();
    let lines = tokio::task::spawn_blocking(move || fingerprint_from_find(&root, &raw))
        .await
        .map_err(|_| "fingerprint task failed".to_string())?;
    Ok(fingerprint_lines(lines))
}

async fn image_fingerprint(reference: &str) -> Result<String, String> {
    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|e| format!("Docker connect failed: {e}"))?;
    docker
        .inspect_image(reference)
        .await
        .map_err(|e| format!("image {reference} not found: {e}"))?
        .id
        .ok_or_else(|| format!("image {reference} has no id"))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn rfc3339(t: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Number of packages (`artifacts`) of a syft-json SBOM, without keeping them.
pub fn count_packages<R: std::io::Read>(r: R) -> Result<u64, String> {
    #[derive(Deserialize)]
    struct Doc {
        #[serde(default, deserialize_with = "null_default")]
        artifacts: Vec<serde::de::IgnoredAny>,
    }
    let d: Doc = serde_json::from_reader(std::io::BufReader::new(r)).map_err(|e| format!("invalid SBOM: {e}"))?;
    Ok(d.artifacts.len() as u64)
}

async fn count_packages_at(path: PathBuf) -> Result<u64, String> {
    tokio::task::spawn_blocking(move || {
        let f = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        count_packages(f)
    })
    .await
    .map_err(|_| "package count task failed".to_string())?
}

#[derive(Debug, Serialize)]
pub struct InventoryResult {
    pub target_id: String,
    pub status: &'static str,
    pub fingerprint: Option<String>,
    pub sbom_at: Option<String>,
    pub packages: Option<u64>,
    pub error: Option<String>,
}

impl InventoryResult {
    fn error(target_id: &str, e: String) -> Self {
        Self {
            target_id: target_id.to_string(),
            status: "error",
            fingerprint: None,
            sbom_at: None,
            packages: None,
            error: Some(e),
        }
    }
}

/// One target: fingerprint, then (unless unchanged) syft into a temporary
/// file of the SBOM directory, renamed over the previous SBOM on success.
/// An errored target reports no fingerprint, so the backend never records
/// one that has no SBOM behind it.
async fn inventory_one(t: &InventoryTarget) -> Result<InventoryResult, String> {
    let mut active_release = false;
    let (fingerprint, source) = match t.kind {
        TargetKind::Site => {
            // A plain directory, never a link (same rule as the antivirus).
            let site = Path::new(WWW_ROOT).join(&t.reference);
            if !std::fs::symlink_metadata(&site).map(|m| m.file_type().is_dir()).unwrap_or(false) {
                return Err(format!("site directory {} not found", site.display()));
            }
            let (root, release) = site_root(Path::new(WWW_ROOT), &t.reference);
            active_release = release;
            (site_fingerprint(&t.target_id, &root).await?, format!("dir:{}", root.display()))
        }
        TargetKind::Image => (image_fingerprint(&t.reference).await?, format!("docker:{}", t.reference)),
        TargetKind::System => {
            let p = PathBuf::from(DPKG_STATUS);
            if !p.is_file() {
                return Err(format!("system inventory needs dpkg ({DPKG_STATUS} not found)"));
            }
            let fp = tokio::task::spawn_blocking(move || file_sha256(&p))
                .await
                .map_err(|_| "fingerprint task failed".to_string())??;
            (fp, "dir:/".to_string())
        }
    };

    let sbom = sbom_path(&t.target_id);
    if !t.force && t.previous_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        if let Ok(m) = std::fs::metadata(&sbom) {
            if m.is_file() {
                let packages = count_packages_at(sbom.clone()).await.ok();
                return Ok(InventoryResult {
                    target_id: t.target_id.clone(),
                    status: "unchanged",
                    fingerprint: Some(fingerprint),
                    sbom_at: m.modified().ok().map(rfc3339),
                    packages,
                    error: None,
                });
            }
        }
    }

    let tmp = Path::new(SBOM_DIR).join(format!("{}.json.tmp", t.target_id));
    let _ = std::fs::remove_file(&tmp);
    let res = scanner_command(sbom_scanner::SYFT_BIN, false)
        .args(syft_args(t.kind, &source, &tmp, active_release))
        .output_with_timeout(SYFT_TIMEOUT)
        .await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if !res.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("syft failed: {}", stderr_tail(&res, 400)));
    }
    let packages = match count_packages_at(tmp.clone()).await {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::rename(&tmp, &sbom) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("store SBOM: {e}"));
    }
    Ok(InventoryResult {
        target_id: t.target_id.clone(),
        status: "updated",
        fingerprint: Some(fingerprint),
        sbom_at: Some(rfc3339(std::time::SystemTime::now())),
        packages: Some(packages),
        error: None,
    })
}

async fn run_inventory(h: &JobHandle, targets: Vec<InventoryTarget>) -> Result<serde_json::Value, String> {
    ensure_dirs()?;
    let syft_present = tokio::fs::metadata(sbom_scanner::SYFT_BIN).await.is_ok();
    let total = targets.len() as u64;
    let mut results = Vec::with_capacity(targets.len());
    for (i, t) in targets.iter().enumerate() {
        h.progress("inventory", i as u64, total, &t.target_id);
        let r = if syft_present {
            inventory_one(t).await
        } else {
            Err("syft is not installed".to_string())
        };
        results.push(r.unwrap_or_else(|e| InventoryResult::error(&t.target_id, e)));
    }
    h.progress("inventory", total, total, "");
    Ok(serde_json::json!({ "results": results }))
}

/// `POST /vulns/inventory`: job `vuln_inventory`.
pub fn start_inventory(targets: Vec<InventoryTarget>) -> String {
    migration_jobs::spawn("vuln_inventory", "server", move |h| async move {
        let _inventory = INVENTORY_LOCK.lock().await;
        run_inventory(&h, targets).await
    })
}

/// `DELETE /vulns/sbom/{target_id}`: an absent SBOM is fine.
pub fn delete_sbom(target_id: &str) -> Result<(), String> {
    match std::fs::remove_file(sbom_path(target_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove SBOM: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// `null` and absent both mean the type's default (grype writes either).
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
struct GrypeDoc {
    #[serde(default, deserialize_with = "null_default")]
    matches: Vec<GrypeMatch>,
}

#[derive(Deserialize, Default)]
struct GrypeMatch {
    #[serde(default, deserialize_with = "null_default")]
    vulnerability: GrypeVuln,
    #[serde(default, rename = "relatedVulnerabilities", deserialize_with = "null_default")]
    related: Vec<GrypeVuln>,
    #[serde(default, deserialize_with = "null_default")]
    artifact: GrypeArtifact,
}

#[derive(Deserialize, Default)]
struct GrypeVuln {
    #[serde(default, deserialize_with = "null_default")]
    id: String,
    #[serde(default, rename = "dataSource", deserialize_with = "null_default")]
    data_source: String,
    #[serde(default, deserialize_with = "null_default")]
    severity: String,
    #[serde(default, deserialize_with = "null_default")]
    description: String,
    #[serde(default, deserialize_with = "null_default")]
    urls: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    cvss: Vec<GrypeCvss>,
    #[serde(default, deserialize_with = "null_default")]
    fix: GrypeFix,
    #[serde(default, rename = "knownExploited", deserialize_with = "null_default")]
    known_exploited: Vec<GrypeKev>,
    #[serde(default, deserialize_with = "null_default")]
    epss: Vec<GrypeEpss>,
    #[serde(default)]
    risk: Option<f64>,
}

#[derive(Deserialize, Default)]
struct GrypeCvss {
    #[serde(default, deserialize_with = "null_default")]
    metrics: GrypeCvssMetrics,
}

#[derive(Deserialize, Default)]
struct GrypeCvssMetrics {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
}

#[derive(Deserialize, Default)]
struct GrypeFix {
    #[serde(default, deserialize_with = "null_default")]
    versions: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    state: String,
}

#[derive(Deserialize, Default)]
struct GrypeKev {
    #[serde(default, rename = "knownRansomwareCampaignUse", deserialize_with = "null_default")]
    ransomware: String,
}

#[derive(Deserialize, Default)]
struct GrypeEpss {
    #[serde(default)]
    epss: Option<f64>,
    #[serde(default)]
    percentile: Option<f64>,
}

#[derive(Deserialize, Default)]
struct GrypeArtifact {
    #[serde(default, deserialize_with = "null_default")]
    name: String,
    #[serde(default, deserialize_with = "null_default")]
    version: String,
    #[serde(default, rename = "type", deserialize_with = "null_default")]
    pkg_type: String,
    #[serde(default, deserialize_with = "null_default")]
    locations: Vec<GrypeLocation>,
}

#[derive(Deserialize, Default)]
struct GrypeLocation {
    #[serde(default, deserialize_with = "null_default")]
    path: String,
}

/// One vulnerable component of a target, as the backend stores it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub version: String,
    pub pkg_type: String,
    pub location: Option<String>,
    pub severity: String,
    pub cvss: Option<f64>,
    pub kev: bool,
    pub kev_ransomware: bool,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub risk: f64,
    pub fix_state: String,
    pub fixed_version: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
}

/// Same mapping as `image_scanner::normalize_severity` (negligible -> low).
pub fn normalize_severity(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" | "negligible" => "low",
        _ => "unknown",
    }
}

fn normalize_fix_state(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "fixed" => "fixed",
        "not-fixed" => "not-fixed",
        "wont-fix" => "wont-fix",
        _ => "unknown",
    }
}

/// First `n` characters (never splits a UTF-8 sequence).
fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn finding_of(m: GrypeMatch) -> Finding {
    let v = &m.vulnerability;
    let all: Vec<&GrypeVuln> = std::iter::once(v).chain(m.related.iter()).collect();

    let vuln_id = if v.id.starts_with("CVE-") {
        v.id.clone()
    } else {
        m.related
            .iter()
            .find(|r| r.id.starts_with("CVE-"))
            .map(|r| r.id.clone())
            .unwrap_or_else(|| v.id.clone())
    };
    let mut aliases: Vec<String> = Vec::new();
    for x in &all {
        let id = x.id.trim();
        if !id.is_empty() && id != vuln_id && !aliases.iter().any(|a| a == id) {
            aliases.push(clip(id, 64));
        }
    }

    // KEV and EPSS: the first entry carrying them (a GHSA usually has them only
    // on its related CVE).
    let kev_list = all.iter().map(|x| &x.known_exploited).find(|k| !k.is_empty());
    let kev = kev_list.is_some();
    let kev_ransomware = kev_list
        .map(|k| k.iter().any(|e| e.ransomware.trim().eq_ignore_ascii_case("known")))
        .unwrap_or(false);
    let epss = all.iter().map(|x| &x.epss).find(|e| !e.is_empty()).and_then(|e| e.first());

    let cvss = all
        .iter()
        .flat_map(|x| x.cvss.iter())
        .filter_map(|c| c.metrics.base_score)
        .filter(|s| s.is_finite())
        .fold(None, |acc: Option<f64>, s| Some(acc.map_or(s, |a| a.max(s))));

    // Severity of the matched record; a distro advisory often says "Unknown"
    // where the related CVE record carries a real one.
    let mut severity = normalize_severity(&v.severity);
    if severity == "unknown" {
        if let Some(s) = m.related.iter().map(|r| normalize_severity(&r.severity)).find(|s| *s != "unknown") {
            severity = s;
        }
    }

    let risk = v
        .risk
        .or_else(|| m.related.iter().find_map(|r| r.risk))
        .filter(|r| r.is_finite())
        .unwrap_or(0.0);

    let description = all.iter().map(|x| x.description.trim()).find(|d| !d.is_empty()).unwrap_or("");
    let url = non_empty(&v.data_source).or_else(|| v.urls.iter().find_map(|u| non_empty(u)));

    Finding {
        vuln_id: clip(&vuln_id, 64),
        aliases,
        package: clip(&m.artifact.name, 256),
        version: clip(&m.artifact.version, 128),
        pkg_type: clip(&m.artifact.pkg_type, 32),
        location: m.artifact.locations.iter().find_map(|l| non_empty(&l.path)),
        severity: severity.to_string(),
        cvss,
        kev,
        kev_ransomware,
        epss: epss.and_then(|e| e.epss),
        epss_percentile: epss.and_then(|e| e.percentile),
        risk,
        fix_state: normalize_fix_state(&v.fix.state).to_string(),
        fixed_version: v.fix.versions.iter().find_map(|f| non_empty(f)).map(|f| clip(&f, 128)),
        title: non_empty(description).map(|d| clip(&d, 300)),
        url,
    }
}

/// `(vuln_id, package, version)`: the backend's unique key of a finding.
pub type FindingKey = (String, String, String);
/// What [`finalize_findings`] returns: findings, truncated, key list.
pub type Finalized = (Vec<Finding>, bool, Option<Vec<FindingKey>>);

/// Highest risk first (then KEV, then CVSS), duplicates on
/// `(vuln_id, package, version)` dropped (the riskiest one is kept), capped at
/// [`MAX_FINDINGS`]. Returns the findings, whether the cap cut any, and on a
/// cut result the key of every finding before the cap (`None` when not cut,
/// or when that list would pass [`MAX_PRESENT_KEYS`]): without it the panel
/// cannot tell a finding past the cap from one that is gone, and never
/// resolves anything on a target that always passes the cap.
pub fn finalize_findings(mut findings: Vec<Finding>) -> Finalized {
    findings.sort_by(|a, b| {
        b.risk
            .total_cmp(&a.risk)
            .then(b.kev.cmp(&a.kev))
            .then(b.cvss.unwrap_or(0.0).total_cmp(&a.cvss.unwrap_or(0.0)))
    });
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    findings.retain(|f| seen.insert((f.vuln_id.clone(), f.package.clone(), f.version.clone())));
    let truncated = findings.len() > MAX_FINDINGS;
    let present = (truncated && findings.len() <= MAX_PRESENT_KEYS).then(|| seen.into_iter().collect());
    findings.truncate(MAX_FINDINGS);
    (findings, truncated, present)
}

/// Read a grype JSON report (`-o json=<file>`) as a stream into findings.
pub fn parse_grype_report<R: std::io::Read>(r: R) -> Result<Finalized, String> {
    let doc: GrypeDoc = serde_json::from_reader(std::io::BufReader::new(r))
        .map_err(|e| format!("invalid grype report: {e}"))?;
    Ok(finalize_findings(doc.matches.into_iter().map(finding_of).collect()))
}

#[derive(Debug, Serialize)]
pub struct MatchResult {
    pub target_id: String,
    pub status: &'static str,
    pub error: Option<String>,
    pub truncated: bool,
    pub findings: Vec<Finding>,
    /// Only on a truncated `ok` result: every key of the complete result, so
    /// the panel can resolve what is gone without the details past the cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub present: Option<Vec<FindingKey>>,
}

async fn match_one(target_id: &str) -> MatchResult {
    let result = |status, error, truncated, findings| MatchResult {
        target_id: target_id.to_string(),
        status,
        error,
        truncated,
        findings,
        present: None,
    };
    let sbom = sbom_path(target_id);
    if !sbom.is_file() {
        return result("no_sbom", None, false, Vec::new());
    }
    let out = Path::new(TMP_DIR).join(format!("match-{target_id}.json"));
    let _ = std::fs::remove_file(&out);
    let res = scanner_command(image_scanner::GRYPE_BIN, false)
        .args([
            format!("sbom:{}", sbom.display()),
            "-o".to_string(),
            format!("json={}", out.display()),
            "-q".to_string(),
        ])
        .output_with_timeout(MATCH_TIMEOUT)
        .await;
    let parsed = match res {
        Err(e) => Err(e),
        Ok(r) if !r.status.success() => Err(format!("grype failed: {}", stderr_tail(&r, 400))),
        Ok(_) => {
            let path = out.clone();
            tokio::task::spawn_blocking(move || {
                let f = std::fs::File::open(&path).map_err(|e| format!("read grype report: {e}"))?;
                parse_grype_report(f)
            })
            .await
            .unwrap_or_else(|_| Err("grype report task failed".to_string()))
        }
    };
    let _ = std::fs::remove_file(&out);
    match parsed {
        Ok((findings, truncated, present)) => MatchResult { present, ..result("ok", None, truncated, findings) },
        Err(e) => result("error", Some(e), false, Vec::new()),
    }
}

async fn run_match(h: &JobHandle, target_ids: Vec<String>) -> Result<serde_json::Value, String> {
    ensure_dirs()?;
    if tokio::fs::metadata(image_scanner::GRYPE_BIN).await.is_err() {
        return Err("grype is not installed".into());
    }
    let db_built = db_status().await.map(|d| d.built);
    let total = target_ids.len() as u64;
    let mut results = Vec::with_capacity(target_ids.len());
    for (i, id) in target_ids.iter().enumerate() {
        h.progress("match", i as u64, total, id);
        results.push(match_one(id).await);
    }
    h.progress("match", total, total, "");
    Ok(serde_json::json!({ "db_built": db_built, "results": results }))
}

/// `POST /vulns/match`: job `vuln_match`.
pub fn start_match(target_ids: Vec<String>) -> String {
    migration_jobs::spawn("vuln_match", "server", move |h| async move {
        let _db = DB_LOCK.read().await;
        run_match(&h, target_ids).await
    })
}

// ---------------------------------------------------------------------------
// Target discovery
// ---------------------------------------------------------------------------

/// A published port is public unless bound to loopback only.
pub fn is_public_binding(ip: Option<&str>) -> bool {
    !matches!(ip.map(str::trim), Some("127.0.0.1") | Some("::1"))
}

/// `(ID, VERSION_ID)` of an os-release file.
pub fn parse_os_release(s: &str) -> (Option<String>, Option<String>) {
    let mut id = None;
    let mut version = None;
    for line in s.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match k.trim() {
            "ID" => id = Some(v),
            "VERSION_ID" => version = Some(v),
            _ => {}
        }
    }
    (id, version)
}

#[derive(Serialize)]
struct ContainerRef {
    name: String,
    app_name: Option<String>,
    git_name: Option<String>,
    stack_id: Option<String>,
    domain: Option<String>,
    public_port: bool,
}

fn container_ref(c: &bollard::models::ContainerSummary, postgres: bool) -> ContainerRef {
    let empty: HashMap<String, String> = HashMap::new();
    let labels = c.labels.as_ref().unwrap_or(&empty);
    let label = |k: &str| labels.get(k).and_then(|v| non_empty(v));
    let name = c
        .names
        .as_ref()
        .and_then(|n| n.first())
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default();
    let git_name = label("dockpanel.git.name");
    let app_name = if postgres {
        Some("panel-postgres".to_string())
    } else {
        label("dockpanel.app.name").or_else(|| {
            if git_name.is_none() {
                name.strip_prefix("dockpanel-app-").and_then(non_empty)
            } else {
                None
            }
        })
    };
    let public_port = c
        .ports
        .as_ref()
        .map(|ps| ps.iter().any(|p| p.public_port.is_some() && is_public_binding(p.ip.as_deref())))
        .unwrap_or(false);
    ContainerRef {
        name,
        app_name,
        git_name,
        stack_id: label("dockpanel.stack_id"),
        domain: label("dockpanel.app.domain"),
        public_port,
    }
}

/// `GET /vulns/targets`: images of the managed containers (running or not)
/// plus the panel's own PostgreSQL, and the host system.
pub async fn discover_targets() -> Result<serde_json::Value, String> {
    use bollard::container::ListContainersOptions;
    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|e| format!("Docker connect failed: {e}"))?;

    let mut filters = HashMap::new();
    filters.insert("label".to_string(), vec!["dockpanel.managed=true".to_string()]);
    let managed = docker
        .list_containers(Some(ListContainersOptions::<String> { all: true, filters, ..Default::default() }))
        .await
        .map_err(|e| format!("Failed to list containers: {e}"))?;

    let mut filters = HashMap::new();
    filters.insert("name".to_string(), vec!["dockpanel-postgres".to_string()]);
    let postgres = docker
        .list_containers(Some(ListContainersOptions::<String> { all: true, filters, ..Default::default() }))
        .await
        .unwrap_or_default();

    let mut seen: HashSet<String> = HashSet::new();
    let mut by_image: BTreeMap<String, Vec<ContainerRef>> = BTreeMap::new();
    let mut add = |c: &bollard::models::ContainerSummary, pg: bool| {
        let Some(image) = c.image.as_deref().and_then(non_empty) else { return };
        if let Some(id) = &c.id {
            if !seen.insert(id.clone()) {
                return;
            }
        }
        by_image.entry(image).or_default().push(container_ref(c, pg));
    };
    for c in &managed {
        add(c, false);
    }
    for c in &postgres {
        let exact = c
            .names
            .as_ref()
            .map(|n| n.iter().any(|n| n.trim_start_matches('/') == "dockpanel-postgres"))
            .unwrap_or(false);
        if exact {
            add(c, true);
        }
    }

    let mut images = Vec::new();
    for (image, containers) in by_image {
        if !valid_image_ref(&image) {
            continue;
        }
        // Resolved the same way the inventory fingerprints it, so an unchanged
        // image never looks changed to the backend.
        let Ok(inspect) = docker.inspect_image(&image).await else { continue };
        let Some(image_id) = inspect.id else { continue };
        images.push(serde_json::json!({ "image": image, "image_id": image_id, "containers": containers }));
    }

    let (os, version) = std::fs::read_to_string("/etc/os-release")
        .map(|s| parse_os_release(&s))
        .unwrap_or((None, None));
    Ok(serde_json::json!({ "images": images, "system": { "os": os, "version": version } }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("testdata/grype-v0.122-report.json");

    fn parse_fixture() -> Finalized {
        parse_grype_report(FIXTURE.as_bytes()).expect("fixture parses")
    }

    fn by_id<'a>(f: &'a [Finding], id: &str, pkg: &str) -> &'a Finding {
        f.iter().find(|x| x.vuln_id == id && x.package == pkg).unwrap_or_else(|| panic!("{id} {pkg} missing"))
    }

    #[test]
    fn ghsa_takes_cve_kev_and_epss_from_related_vulnerabilities() {
        let (f, truncated, present) = parse_fixture();
        assert!(!truncated);
        assert_eq!(present, None, "no key list on a complete result");
        let log4j = by_id(&f, "CVE-2021-44228", "log4j-core");
        assert_eq!(log4j.aliases, vec!["GHSA-jfh8-c2jp-5v3q".to_string()]);
        assert!(log4j.kev);
        assert!(log4j.kev_ransomware);
        assert_eq!(log4j.epss, Some(0.94358));
        assert_eq!(log4j.epss_percentile, Some(0.99957));
        assert_eq!(log4j.cvss, Some(10.0));
        assert_eq!(log4j.risk, 97.3);
        assert_eq!(log4j.severity, "critical");
        assert_eq!(log4j.fix_state, "fixed");
        assert_eq!(log4j.fixed_version.as_deref(), Some("2.15.0"));
        assert_eq!(log4j.version, "2.14.1");
        assert_eq!(log4j.pkg_type, "java-archive");
        assert_eq!(log4j.location.as_deref(), Some("/app/lib/x.jar:log4j-core.jar"));
        assert_eq!(log4j.url.as_deref(), Some("https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"));
        assert!(log4j.title.as_deref().unwrap().starts_with("Remote code injection in Log4j"));
        // Highest risk first.
        assert_eq!(f[0].vuln_id, "CVE-2021-44228");
    }

    #[test]
    fn distro_match_keeps_its_cve_and_reads_cvss_from_related() {
        let (f, ..) = parse_fixture();
        let o = by_id(&f, "CVE-2023-0464", "libssl3");
        assert_eq!(o.severity, "low", "negligible folds into low");
        assert_eq!(o.fix_state, "not-fixed");
        assert_eq!(o.fixed_version, None);
        assert_eq!(o.cvss, Some(7.5), "highest baseScore across related records");
        assert!(!o.kev);
        assert!(!o.kev_ransomware);
        assert_eq!(o.epss, Some(0.0021));
        assert_eq!(o.pkg_type, "deb");
        assert_eq!(o.location.as_deref(), Some("/var/lib/dpkg/status"));
        assert!(o.aliases.is_empty());
        // dataSource empty: first URL.
        assert_eq!(o.url.as_deref(), Some("https://ubuntu.com/security/CVE-2023-0464"));
        // Empty description on the distro record: the related one is used.
        assert_eq!(o.title.as_deref(), Some("A security vulnerability in X.509 policy constraints."));
    }

    #[test]
    fn unknown_severity_and_nulls_are_tolerated() {
        let (f, ..) = parse_fixture();
        let w = by_id(&f, "CVE-2022-1234", "zlib1g");
        assert_eq!(w.fix_state, "wont-fix");
        assert_eq!(w.severity, "high", "unknown on the distro record, high on the related one");
        assert_eq!(w.cvss, None);
        assert_eq!(w.epss, None);
        assert_eq!(w.risk, 0.0);
        assert_eq!(w.location, None);
        assert_eq!(w.title, None);
    }

    #[test]
    fn ghsa_without_cve_keeps_its_own_id() {
        let (f, ..) = parse_fixture();
        let g = by_id(&f, "GHSA-xxxx-yyyy-zzzz", "lodash");
        assert!(g.aliases.is_empty());
        assert_eq!(g.severity, "medium");
        assert_eq!(g.fix_state, "fixed");
        assert_eq!(g.fixed_version.as_deref(), Some("4.17.21"));
        // 300-character title cap, counted in characters.
        assert_eq!(g.title.as_deref().unwrap().chars().count(), 300);
    }

    #[test]
    fn duplicates_are_dropped_keeping_the_riskiest() {
        let (f, ..) = parse_fixture();
        let n = f
            .iter()
            .filter(|x| x.vuln_id == "CVE-2021-44228" && x.package == "log4j-core" && x.version == "2.14.1")
            .count();
        assert_eq!(n, 1);
        assert_eq!(by_id(&f, "CVE-2021-44228", "log4j-core").risk, 97.3);
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn findings_are_capped_at_5000_by_risk() {
        let mk = |i: usize| Finding {
            vuln_id: format!("CVE-2024-{i}"),
            aliases: vec![],
            package: "p".into(),
            version: "1".into(),
            pkg_type: "npm".into(),
            location: None,
            severity: "low".into(),
            cvss: None,
            kev: false,
            kev_ransomware: false,
            epss: None,
            epss_percentile: None,
            risk: i as f64,
            fix_state: "unknown".into(),
            fixed_version: None,
            title: None,
            url: None,
        };
        let (f, truncated, present) = finalize_findings((0..MAX_FINDINGS + 3).map(mk).collect());
        assert!(truncated);
        assert_eq!(f.len(), MAX_FINDINGS);
        assert_eq!(f[0].risk, (MAX_FINDINGS + 2) as f64);
        assert_eq!(f.last().unwrap().risk, 3.0);
        // The key list names every finding, the three cut by the cap included.
        let present = present.expect("a cut result carries its key list");
        assert_eq!(present.len(), MAX_FINDINGS + 3);
        for i in 0..3 {
            assert!(present.contains(&(format!("CVE-2024-{i}"), "p".into(), "1".into())), "cut CVE-2024-{i}");
        }
        let (f, truncated, present) = finalize_findings((0..10).map(mk).collect());
        assert!(!truncated);
        assert_eq!(present, None);
        assert_eq!(f.len(), 10);
        // A key list too big for the response is left out, never sent partial.
        let (_, truncated, present) = finalize_findings((0..MAX_PRESENT_KEYS + 1).map(mk).collect());
        assert!(truncated);
        assert_eq!(present, None);
    }

    /// The wire shape the panel's `parse_present` reads.
    #[test]
    fn match_result_sends_present_as_triples_and_omits_it_when_none() {
        let mut r = MatchResult {
            target_id: "t".into(),
            status: "ok",
            error: None,
            truncated: true,
            findings: vec![],
            present: Some(vec![("CVE-1".into(), "linux-modules".into(), "6.8.0-151".into())]),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["present"], serde_json::json!([["CVE-1", "linux-modules", "6.8.0-151"]]));
        r.present = None;
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("present").is_none(), "no key at all when there is no list");
    }

    #[test]
    fn empty_and_null_reports_parse() {
        assert!(parse_grype_report(&b"{\"matches\": null}"[..]).unwrap().0.is_empty());
        assert!(parse_grype_report(&b"{}"[..]).unwrap().0.is_empty());
        assert!(parse_grype_report(&b"not json"[..]).is_err());
    }

    #[test]
    fn fingerprint_is_order_independent_and_tracks_size_and_mtime() {
        let a = vec!["composer.lock\t10\t100".to_string(), "package-lock.json\t5\t200".to_string()];
        let b = vec!["package-lock.json\t5\t200".to_string(), "composer.lock\t10\t100".to_string()];
        assert_eq!(fingerprint_lines(a.clone()), fingerprint_lines(b));
        let c = vec!["composer.lock\t11\t100".to_string(), "package-lock.json\t5\t200".to_string()];
        assert_ne!(fingerprint_lines(a.clone()), fingerprint_lines(c));
        let d = vec!["composer.lock\t10\t101".to_string(), "package-lock.json\t5\t200".to_string()];
        assert_ne!(fingerprint_lines(a), fingerprint_lines(d));
        // Empty site: a stable value.
        assert_eq!(fingerprint_lines(vec![]), fingerprint_lines(vec![]));
        assert_eq!(fingerprint_lines(vec![]).len(), 64);
    }

    #[test]
    fn dependency_files_are_recognised() {
        for yes in [
            "composer.lock",
            "app/package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "requirements.txt",
            "requirements-dev.txt",
            "Pipfile.lock",
            "poetry.lock",
            "Gemfile.lock",
            "go.sum",
            "Cargo.lock",
            "lib/log4j-core-2.14.1.jar",
            "app.war",
            "app.ear",
            "vendor/composer/installed.json",
            "node_modules/express/package.json",
            "node_modules/@babel/core/package.json",
        ] {
            assert!(is_dependency_file(yes), "should count: {yes}");
        }
        for no in [
            "package.json",
            "node_modules/express/lib/package.json",
            "node_modules/@babel/core/lib/package.json",
            "installed.json",
            "vendor/installed.json",
            "README.md",
            "requirements.md",
            "",
        ] {
            assert!(!is_dependency_file(no), "should not count: {no}");
        }
    }

    #[test]
    fn find_output_is_filtered_and_made_relative() {
        let dir = std::env::temp_dir().join(format!("vulnscan-find-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(dir.join("node_modules/a/lib")).unwrap();
        std::fs::write(dir.join("composer.lock"), "abc").unwrap();
        std::fs::write(dir.join("node_modules/a/package.json"), "{}").unwrap();
        std::fs::write(dir.join("node_modules/a/lib/package.json"), "{}").unwrap();
        let mut raw = Vec::new();
        for p in ["composer.lock", "node_modules/a/package.json", "node_modules/a/lib/package.json", "gone/composer.lock"] {
            raw.extend_from_slice(dir.join(p).display().to_string().as_bytes());
            raw.push(0);
        }
        let mut lines = fingerprint_from_find(&dir, &raw);
        lines.sort();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("composer.lock\t3\t"));
        assert!(lines[1].starts_with("node_modules/a/package.json\t2\t"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn find_args_prune_depth_and_write_to_a_file() {
        let a = find_args(Path::new("/var/www/x.tld/current"), Path::new("/tmp/out"));
        assert_eq!(&a[..4], ["-H", "/var/www/x.tld/current", "-maxdepth", "8"]);
        let prune = a.iter().position(|x| x == "-prune").unwrap();
        for p in [".git", "releases", "*/wp-content/uploads"] {
            assert!(a[..prune].iter().any(|x| x == p), "{p} pruned");
        }
        assert_eq!(&a[a.len() - 2..], ["-fprint0", "/tmp/out"]);
        assert!(!a.iter().any(|x| x.contains('%')), "no specifier-like argument for the unit");
    }

    #[test]
    fn syft_args_per_kind() {
        let out = Path::new("/var/lib/dockpanel/scanners/sboms/x.json.tmp");
        let site = syft_args(TargetKind::Site, "dir:/var/www/a.tld", out, false);
        assert_eq!(
            &site[..5],
            ["scan", "dir:/var/www/a.tld", "-o", "syft-json=/var/lib/dockpanel/scanners/sboms/x.json.tmp", "-q"]
        );
        for e in SITE_EXCLUDES {
            assert!(site.windows(2).any(|w| w[0] == "--exclude" && w[1] == e), "site excludes {e}");
        }
        assert!(!site.iter().any(|x| x == "--select-catalogers"));

        // The active release is itself under releases/: that exclusion would drop everything.
        let release = syft_args(TargetKind::Site, "dir:/var/www/a.tld/releases/7", out, true);
        assert!(!release.iter().any(|x| x == "**/releases/**"));
        for e in SITE_EXCLUDES.iter().filter(|e| **e != "**/releases/**") {
            assert!(release.windows(2).any(|w| w[0] == "--exclude" && w[1] == *e), "release excludes {e}");
        }

        let image = syft_args(TargetKind::Image, "docker:nginx:1.25", out, false);
        assert_eq!(image.len(), 5);
        assert_eq!(image[1], "docker:nginx:1.25");

        let system = syft_args(TargetKind::System, "dir:/", out, false);
        assert_eq!(system[1], "dir:/");
        for e in SYSTEM_EXCLUDES {
            assert!(system.windows(2).any(|w| w[0] == "--exclude" && w[1] == e), "system excludes {e}");
        }
        assert!(system.windows(2).any(|w| w[0] == "--select-catalogers" && w[1] == "dpkg"));
        // Never to stdout.
        for a in [&site, &image, &system] {
            assert!(!a.iter().any(|x| x == "json" || x == "syft-json"));
        }
    }

    #[test]
    fn site_root_prefers_a_live_current_link() {
        let www = std::env::temp_dir().join(format!("vulnscan-www-{}", uuid::Uuid::new_v4().simple()));
        // Plain site.
        std::fs::create_dir_all(www.join("plain.tld")).unwrap();
        assert_eq!(site_root(&www, "plain.tld"), (www.join("plain.tld"), false));
        // Release layout, absolute or relative link: returned resolved.
        std::fs::create_dir_all(www.join("rel.tld/releases/1")).unwrap();
        std::os::unix::fs::symlink(www.join("rel.tld/releases/1"), www.join("rel.tld/current")).unwrap();
        let real = std::fs::canonicalize(www.join("rel.tld/releases/1")).unwrap();
        assert_eq!(site_root(&www, "rel.tld"), (real, true));
        std::fs::create_dir_all(www.join("relr.tld/releases/2")).unwrap();
        std::os::unix::fs::symlink("releases/2", www.join("relr.tld/current")).unwrap();
        let real = std::fs::canonicalize(www.join("relr.tld/releases/2")).unwrap();
        assert_eq!(site_root(&www, "relr.tld"), (real, true));
        // Dangling link: the site dir.
        std::fs::create_dir_all(www.join("dead.tld")).unwrap();
        std::os::unix::fs::symlink(www.join("dead.tld/releases/9"), www.join("dead.tld/current")).unwrap();
        assert_eq!(site_root(&www, "dead.tld"), (www.join("dead.tld"), false));
        // A real directory named current is not the release layout.
        std::fs::create_dir_all(www.join("dir.tld/current")).unwrap();
        assert_eq!(site_root(&www, "dir.tld"), (www.join("dir.tld"), false));
        // The owner's link escaping the site: to /, to another site, to the site itself.
        std::fs::create_dir_all(www.join("evil.tld")).unwrap();
        std::os::unix::fs::symlink("/", www.join("evil.tld/current")).unwrap();
        assert_eq!(site_root(&www, "evil.tld"), (www.join("evil.tld"), false));
        std::fs::create_dir_all(www.join("evil2.tld")).unwrap();
        std::os::unix::fs::symlink("../plain.tld", www.join("evil2.tld/current")).unwrap();
        assert_eq!(site_root(&www, "evil2.tld"), (www.join("evil2.tld"), false));
        std::fs::create_dir_all(www.join("self.tld")).unwrap();
        std::os::unix::fs::symlink(".", www.join("self.tld/current")).unwrap();
        assert_eq!(site_root(&www, "self.tld"), (www.join("self.tld"), false));
        std::fs::remove_dir_all(&www).unwrap();
    }

    #[test]
    fn target_ids_must_be_canonical_uuids() {
        let ok = "3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
        assert_eq!(validate_target_id(ok).unwrap(), ok);
        for bad in [
            "",
            "x",
            "../etc/passwd",
            "3F0C8A2E-1B2C-4D5E-8F90-A1B2C3D4E5F6",
            "3f0c8a2e1b2c4d5e8f90a1b2c3d4e5f6",
            "{3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6}",
            "urn:uuid:3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
            "3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6/../x",
        ] {
            assert!(validate_target_id(bad).is_err(), "should refuse {bad}");
        }
    }

    #[test]
    fn inventory_request_is_validated() {
        let id = "3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
        let body = format!(
            r#"{{"targets":[{{"target_id":"{id}","kind":"site","ref":"example.com","previous_fingerprint":"ab","force":false}},
                {{"target_id":"{id}","kind":"image","ref":"ghcr.io/o/r:1.2"}},
                {{"target_id":"{id}","kind":"system","ref":"system","force":true}}]}}"#
        );
        let t = parse_inventory_request(body.as_bytes()).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].kind, TargetKind::Site);
        assert_eq!(t[0].previous_fingerprint.as_deref(), Some("ab"));
        assert_eq!(t[1].kind, TargetKind::Image);
        assert!(!t[1].force);
        assert!(t[2].force);

        for (kind, r) in [
            ("site", "../etc"),
            ("site", "localhost"),
            ("image", "nginx;rm -rf /"),
            ("image", "-oops"),
            ("system", "/"),
            ("wordpress", "example.com"),
        ] {
            let body = format!(r#"{{"targets":[{{"target_id":"{id}","kind":"{kind}","ref":"{r}"}}]}}"#);
            assert!(parse_inventory_request(body.as_bytes()).is_err(), "should refuse {kind} {r}");
        }
        assert!(parse_inventory_request(b"{}").is_err());
        assert!(parse_inventory_request(br#"{"targets":[{"target_id":"x","kind":"system","ref":"system"}]}"#).is_err());
        assert!(parse_inventory_request(br#"{"targets":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn match_request_is_validated() {
        let id = "3f0c8a2e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
        assert_eq!(parse_match_request(format!(r#"{{"target_ids":["{id}"]}}"#).as_bytes()).unwrap(), vec![id]);
        assert!(parse_match_request(br#"{"target_ids":["nope"]}"#).is_err());
        assert!(parse_match_request(b"[]").is_err());
    }

    #[test]
    fn scanner_env_disables_auto_update_except_for_db_update() {
        let m = scanner_env(false);
        assert!(m.contains(&("GRYPE_DB_AUTO_UPDATE", "false")));
        assert!(m.contains(&("GRYPE_DB_CACHE_DIR", "/var/lib/dockpanel/scanners/grype-db")));
        assert!(m.contains(&("HOME", HOME_DIR)));
        assert!(m.contains(&("TMPDIR", TMP_DIR)));
        assert!(m.contains(&("XDG_CACHE_HOME", CACHE_DIR)));
        assert!(m.contains(&("GRYPE_CHECK_FOR_APP_UPDATE", "false")));
        assert!(m.contains(&("SYFT_CHECK_FOR_APP_UPDATE", "false")));
        let u = scanner_env(true);
        assert!(!u.iter().any(|(k, _)| *k == "GRYPE_DB_AUTO_UPDATE"));
        assert_eq!(
            SCANNER_PROPERTIES,
            ["MemoryMax=1536M", "Nice=19", "IOSchedulingClass=idle", "CPUQuota=50%"]
        );
    }

    #[test]
    fn free_space_gate() {
        assert!(check_free_space(8 * 1024 * 1024 * 1024).is_ok());
        let e = check_free_space(2 * 1024 * 1024 * 1024).unwrap_err();
        assert_eq!(e, "insufficient disk space: 2.0 GiB free, 8 GiB required");
    }

    #[test]
    fn version_and_db_status_are_read_tolerantly() {
        assert_eq!(
            parse_version_json(br#"{"application":"grype","version":"0.122.1","buildDate":"x"}"#).as_deref(),
            Some("0.122.1")
        );
        assert_eq!(parse_version_json(br#"{"version":"v1.57.2"}"#).as_deref(), Some("1.57.2"));
        assert_eq!(parse_version_json(b"grype 0.122.1"), None);
        assert_eq!(
            parse_db_status(br#"{"schemaVersion":"v6.1.10","from":"https://x","built":"2026-11-19T06:23:00Z","path":"/p","valid":true}"#),
            Some(DbInfo { built: "2026-11-19T06:23:00Z".into(), schema: "v6.1.10".into() })
        );
        assert_eq!(parse_db_status(br#"{"built":"2026-11-19T06:23:00Z","valid":false}"#), None);
        assert_eq!(parse_db_status(br#"{"valid":true}"#), None);
        assert_eq!(parse_db_status(b""), None);
        assert_eq!(image_scanner::pinned_version(), "0.122.1");
        assert_eq!(sbom_scanner::pinned_version(), "1.57.2");
    }

    #[test]
    fn status_shape() {
        let v = status_json((true, Some("0.122.1".into())), (false, None), None, 42);
        assert_eq!(v["grype"]["installed"], true);
        assert_eq!(v["grype"]["version"], "0.122.1");
        assert_eq!(v["syft"]["installed"], false);
        assert!(v["syft"]["version"].is_null());
        assert!(v["db"].is_null());
        assert_eq!(v["free_bytes"], 42);
        assert_eq!(v["expected"]["grype"], "0.122.1");
        assert_eq!(v["expected"]["syft"], "1.57.2");
    }

    #[test]
    fn sbom_package_count() {
        assert_eq!(count_packages(&br#"{"artifacts":[{"name":"a"},{"name":"b"}],"source":{}}"#[..]).unwrap(), 2);
        assert_eq!(count_packages(&br#"{"artifacts":null}"#[..]).unwrap(), 0);
        assert!(count_packages(&b"{"[..]).is_err());
    }

    #[test]
    fn public_binding_and_os_release() {
        assert!(is_public_binding(Some("0.0.0.0")));
        assert!(is_public_binding(Some("::")));
        assert!(is_public_binding(None));
        assert!(!is_public_binding(Some("127.0.0.1")));
        assert!(!is_public_binding(Some("::1")));
        let (id, v) = parse_os_release("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n");
        assert_eq!(id.as_deref(), Some("ubuntu"));
        assert_eq!(v.as_deref(), Some("24.04"));
    }

    #[test]
    fn grype_read_command_never_auto_updates_the_database() {
        // The security scan's and the image report's grype: the real argv.
        let cmd = grype_read_command("nginx:1.27", Path::new("/x/r.json"), &["--only-fixed"]);
        let argv = cmd.argv_strings();
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        let (unit, inner) = (&argv[..sep], &argv[sep + 1..]);
        for want in [
            "--setenv=GRYPE_DB_AUTO_UPDATE=false".to_string(),
            "--setenv=GRYPE_DB_CACHE_DIR=/var/lib/dockpanel/scanners/grype-db".to_string(),
            format!("--setenv=HOME={HOME_DIR}"),
            format!("--setenv=TMPDIR={TMP_DIR}"),
            format!("--setenv=XDG_CACHE_HOME={CACHE_DIR}"),
            "--setenv=GRYPE_CHECK_FOR_APP_UPDATE=false".to_string(),
        ] {
            assert!(unit.contains(&want), "missing {want} in {unit:?}");
        }
        assert!(!unit.iter().any(|a| a.starts_with("--setenv=GRYPE_DB_AUTO_UPDATE=") && !a.ends_with("=false")));
        // The agent's own HOME=/root default comes first; ours must come after it.
        let home: Vec<_> = unit.iter().filter(|a| a.starts_with("--setenv=HOME=")).collect();
        assert_eq!(home.last().map(|s| s.as_str()), Some(format!("--setenv=HOME={HOME_DIR}").as_str()));
        for p in SCANNER_PROPERTIES {
            assert!(unit.windows(2).any(|w| w[0] == "-p" && w[1] == p), "missing -p {p}");
        }
        assert_eq!(
            inner,
            [image_scanner::GRYPE_BIN, "nginx:1.27", "-o", "json=/x/r.json", "-q", "--only-fixed"]
        );
    }

    #[test]
    fn image_report_refreshes_a_database_older_than_two_days() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-26T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
        assert!(!db_refresh_due("2026-11-25T04:00:00Z", now));
        assert!(!db_refresh_due("2026-11-24T12:00:01Z", now));
        assert!(db_refresh_due("2026-11-24T11:59:00Z", now));
        assert!(db_refresh_due("2026-11-01T00:00:00+00:00", now));
        // Unreadable: no update started on every scan.
        assert!(!db_refresh_due("", now));
        assert!(!db_refresh_due("yesterday", now));
    }

    fn set_mtime(p: &Path, t: std::time::SystemTime) {
        std::fs::File::open(p).unwrap().set_modified(t).unwrap();
    }

    #[test]
    fn stale_download_sweep_removes_only_idle_download_dirs() {
        let cache = std::env::temp_dir().join(format!("grypefix-cache-{}", uuid::Uuid::new_v4().simple()));
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        let mk = |rel: &str| {
            let d = cache.join(rel);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("vulnerability.db"), b"x").unwrap();
            set_mtime(&d.join("vulnerability.db"), old);
            set_mtime(&d, old);
            d
        };
        let stale = mk("grype-db-download1006640285");
        let stale2 = mk("grype-db-download-2");
        let db = mk("6");
        let other = mk("other-dir");
        let like = mk("xgrype-db-download3");
        // A download still being written: the dir's own mtime is old, the file's is not.
        let live = mk("grype-db-download777");
        std::fs::write(live.join("vulnerability.db"), b"growing").unwrap();
        // A file and a symlink carrying the prefix.
        let file = cache.join("grype-db-download-file");
        std::fs::write(&file, b"f").unwrap();
        set_mtime(&file, old);
        let target = std::env::temp_dir().join(format!("grypefix-target-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep"), b"k").unwrap();
        let link = cache.join("grype-db-download-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut removed = sweep_stale_db_downloads(&cache, Duration::from_secs(1800));
        removed.sort();
        let mut want = vec![stale.clone(), stale2.clone()];
        want.sort();
        assert_eq!(removed, want);
        assert!(!stale.exists() && !stale2.exists());
        for kept in [&db, &other, &like, &live, &file] {
            assert!(kept.exists(), "{} was removed", kept.display());
        }
        assert!(link.symlink_metadata().is_ok(), "the symlink was removed");
        assert!(target.join("keep").exists(), "the sweep followed a symlink");
        assert!(db.join("vulnerability.db").exists());

        // Nothing idle long enough: nothing goes, even with the prefix.
        assert!(sweep_stale_db_downloads(&cache, Duration::from_secs(4 * 3600)).is_empty());
        // A missing cache dir is not an error.
        assert!(sweep_stale_db_downloads(&cache.join("absent"), Duration::ZERO).is_empty());

        std::fs::remove_dir_all(&cache).unwrap();
        std::fs::remove_dir_all(&target).unwrap();
    }

    #[test]
    fn tmp_sweep_keeps_what_is_still_in_use() {
        let tmp = std::env::temp_dir().join(format!("grypefix-tmp-{}", uuid::Uuid::new_v4().simple()));
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        std::fs::create_dir_all(tmp.join("stereoscope-1/layer")).unwrap();
        std::fs::write(tmp.join("stereoscope-1/layer/f"), b"x").unwrap();
        for p in ["stereoscope-1/layer/f", "stereoscope-1/layer", "stereoscope-1"] {
            set_mtime(&tmp.join(p), old);
        }
        std::fs::write(tmp.join("image-old.json"), b"{}").unwrap();
        set_mtime(&tmp.join("image-old.json"), old);
        std::fs::write(tmp.join("match-new.json"), b"{}").unwrap();

        let mut removed = sweep_stale_tmp(&tmp, TMP_IDLE);
        removed.sort();
        assert_eq!(removed, vec![tmp.join("image-old.json"), tmp.join("stereoscope-1")]);
        assert!(tmp.join("match-new.json").exists());
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
