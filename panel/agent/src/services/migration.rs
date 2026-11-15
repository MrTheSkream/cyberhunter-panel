use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use crate::safe_cmd::safe_command;
use crate::services::hestia;
use crate::services::migration_files::{
    compute_disk, free_bytes, index_tar, is_metadata_member, is_unsafe_name, looks_like_tar, normalize_name,
    parse_header, place_dir, ensure_hestia_compat_link, remove_import_dirs, rewrite_root_files, scan_domain_data, site_space_needed, fix_walk,
    DiskReport, EntryKind, IndexEntry, SiteScan, GIB,
};
use crate::services::migration_jobs::JobHandle;

/// Where a URL-fetched archive is staged before analysis - inside the ONE
/// subtree systemd actually grants this unit write access to
/// (`ReadWritePaths=... /var/backups/dockpanel ...`, not the bare
/// `/var/backups/` an operator-copied archive can live under). Landing a new
/// path outside a granted `ReadWritePaths` entry is the exact EROFS class the
/// per-site SFTP jail hit (`/var/dockpanel-sftp` didn't exist yet either).
pub const FETCH_DIR: &str = "/var/backups/dockpanel/migration-fetch";

/// Hard ceiling on a fetched archive's size. Generous for a real cPanel/Plesk/
/// HestiaCP backup, bounded so a misconfigured or hostile URL cannot fill the
/// disk via a response that never ends.
const MAX_FETCH_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB

/// How long a fetch may run before this process gives up on it. Matches
/// `EXTRACT_TIMEOUT_SECS` below - the same "bound the thing that will never
/// finish, not the one that will" reasoning applies to a slow remote host.
const FETCH_TIMEOUT_SECS: u64 = 1800;

/// Download a backup archive from `url` into `dest` (the caller has already
/// validated `dest` sits inside [`FETCH_DIR`] and `url` is not an internal
/// address). Streams to disk with a hard size cap instead of buffering the
/// whole response - a real archive can be many gigabytes - and writes to a
/// `.part` sibling first, renaming into place only once the full response has
/// landed, so a crash or a cap trip never leaves something `analyze()` could
/// mistake for a complete archive.
pub async fn fetch_archive(url: &str, dest: &str) -> Result<u64, String> {
    if let Some(parent) = Path::new(dest).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("Could not create {}: {e}", parent.display()))?;
    }

    let resp = reqwest::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| format!("Fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Fetch failed: HTTP {}", resp.status()));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_FETCH_BYTES {
            return Err(format!(
                "Archive is {} bytes, over the {} GiB fetch limit",
                len,
                MAX_FETCH_BYTES / (1024 * 1024 * 1024)
            ));
        }
    }

    let part_path = format!("{dest}.part");
    let mut file = tokio::fs::File::create(&part_path)
        .await
        .map_err(|e| format!("Could not create {part_path}: {e}"))?;

    let mut stream = resp.bytes_stream();
    let mut written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Fetch failed mid-download: {e}"))?;
        written += chunk.len() as u64;
        if written > MAX_FETCH_BYTES {
            drop(file);
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(format!(
                "Archive exceeded the {} GiB fetch limit and was discarded",
                MAX_FETCH_BYTES / (1024 * 1024 * 1024)
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("Write failed: {e}"))?;
    }
    file.flush().await.map_err(|e| format!("Write failed: {e}"))?;
    drop(file);

    tokio::fs::rename(&part_path, dest)
        .await
        .map_err(|e| format!("Could not finalize {dest}: {e}"))?;

    Ok(written)
}

/// Ceiling on unpacking one backup archive - for the WHOLE attempt, not per `tar`.
///
/// Extraction can run twice: gzip first, then plain tar for an archive that is
/// not gzipped. Giving each its own fresh budget would make the real worst case
/// double this, and the panel's budget - set just above this number on the
/// strength of the name - would then be the one to fire, replacing the sentence
/// below with a contentless "the agent request timed out". So the second attempt
/// gets what is LEFT, and this stays the true ceiling on the call.
///
/// Generous on purpose: since #91 the panel no longer holds an HTTP request open
/// across this, so the only cost of a long extraction is a progress indicator
/// that keeps turning. The number exists to catch the archive that will never
/// finish, not to hurry the one that will.
const EXTRACT_TIMEOUT_SECS: u64 = 1800;

/// Root of every migration's staging (D8, W1-S). Inside `ReadWritePaths`
/// (`/var/lib/dockpanel`) and outside `/tmp`, which is private to this unit
/// (`PrivateTmp=yes`) and lost at every agent restart - the import of a large
/// HestiaCP archive outlives several of those.
pub const STAGING_ROOT: &str = "/var/lib/dockpanel/migration";

/// Validate migration ID format: a UUID (the id `analyze` generates).
fn is_valid_migration_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok() && id.len() == 36
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct MigrationInventory {
    pub id: String,
    pub source: String,
    pub sites: Vec<MigrationSite>,
    pub databases: Vec<MigrationDatabase>,
    pub mail_accounts: Vec<MigrationMailAccount>,
    pub warnings: Vec<String>,
    /// HestiaCP only (W1-A): mode, user, disk, mail domains, FTP... Absent for
    /// the other panels, whose response keeps its historical shape.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub hestia: Option<HestiaInventoryExtra>,
}

#[derive(Serialize, Clone)]
pub struct HestiaInventoryExtra {
    pub mode: String,
    pub hestia_user: String,
    pub archive_bytes: u64,
    pub disk: DiskReport,
    pub mail_domains: Vec<serde_json::Value>,
    pub ftp_accounts: Vec<serde_json::Value>,
    pub cron_jobs: u64,
    pub dns_domains: u64,
}

#[derive(Serialize, Clone)]
pub struct MigrationSite {
    pub domain: String,
    pub doc_root: String,
    pub size_bytes: u64,
    pub runtime: String,
    pub file_count: u64,
    /// `"apache"` / `"nginx"` as the source panel served the domain (feature 4,
    /// decision D3). Only HestiaCP reports it; absent (not serialized) for the
    /// other panels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_server: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub hestia: Option<HestiaSiteExtra>,
}

/// Per-site fields of the HestiaCP inventory (W1-A). No secret: the FTP hash
/// and the TLS key stay in the staging.
#[derive(Serialize, Clone)]
pub struct HestiaSiteExtra {
    pub php_version: Option<String>,
    pub php_version_source: String,
    pub aliases: Vec<String>,
    pub canonical_host: Option<String>,
    pub ssl: serde_json::Value,
    pub force_ssl: bool,
    pub hsts: bool,
    pub ftp_user: Option<String>,
    pub suspended: bool,
    pub doc_root_dir: Option<String>,
    pub custom_nginx_template: Option<String>,
    pub paths_to_fix: Vec<serde_json::Value>,
    pub upload_php_files: u64,
    /// Archive member of the site's files (`web/<d>/domain_data.tar.gz|zst`).
    pub blob: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct MigrationDatabase {
    pub name: String,
    pub file: String,
    pub size_bytes: u64,
    pub engine: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub hestia: Option<HestiaDbExtra>,
}

#[derive(Serialize, Clone)]
pub struct HestiaDbExtra {
    pub charset: String,
    pub db_user: String,
    pub suggested_site: Option<String>,
    pub suggested_via: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct MigrationMailAccount {
    pub email: String,
    pub domain: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub hestia: Option<HestiaMailExtra>,
}

#[derive(Serialize, Clone)]
pub struct HestiaMailExtra {
    pub quota_mb: Option<u64>,
    pub forward_to: Option<String>,
    pub forward_only: bool,
    pub hash_scheme: String,
    pub suspended: bool,
}

// ---------------------------------------------------------------------------
// Staging (W1-S, W1-H)
// ---------------------------------------------------------------------------

/// Staging directory of a migration (validates the id as a UUID). Does not
/// create it.
pub fn staging_dir(migration_id: &str) -> Result<PathBuf, String> {
    if !is_valid_migration_id(migration_id) {
        return Err("Invalid migration ID format".into());
    }
    Ok(Path::new(STAGING_ROOT).join(migration_id))
}

/// `<staging>/meta.json`: `{mode, archive, hestia_user, source, root}`.
#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct StagingMeta {
    /// `lazy` (plain tar, blobs read from the archive) or `full` (extracted).
    pub mode: String,
    pub archive: String,
    #[serde(default)]
    pub hestia_user: String,
    #[serde(default)]
    pub source: String,
    /// Archive root relative to the staging (`""` in lazy mode, `data[/x]` in full).
    #[serde(default)]
    pub root: String,
}

pub fn read_meta(migration_id: &str) -> Result<StagingMeta, String> {
    let dir = staging_dir(migration_id)?;
    let text = std::fs::read_to_string(dir.join("meta.json"))
        .map_err(|_| "migration staging not found (analyze again)".to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("unreadable staging meta: {e}"))
}

/// Directory holding the archive's small files at their member paths: the
/// staging itself in lazy mode, the extracted tree in full mode. W2/W4 read
/// `hestia/`, `conf/` files below this, never below a guessed path.
pub fn archive_root(migration_id: &str) -> Result<PathBuf, String> {
    let dir = staging_dir(migration_id)?;
    let meta = read_meta(migration_id)?;
    if meta.root.is_empty() {
        Ok(dir)
    } else {
        Ok(dir.join(&meta.root))
    }
}

fn read_index(migration_id: &str) -> Result<Vec<IndexEntry>, String> {
    let dir = staging_dir(migration_id)?;
    let text = std::fs::read_to_string(dir.join("index.json"))
        .map_err(|_| "archive index not found (analyze again)".to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("unreadable archive index: {e}"))
}

/// Inventory stored at analysis (`<staging>/inventory.json`, no secret).
pub fn read_inventory(migration_id: &str) -> Result<serde_json::Value, String> {
    let dir = staging_dir(migration_id)?;
    let text = std::fs::read_to_string(dir.join("inventory.json"))
        .map_err(|_| "migration inventory not found (analyze again)".to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("unreadable inventory: {e}"))
}

/// A member name as callers pass it: relative, no `..`, no leading `/`
/// (a leading `./` is tolerated and dropped).
pub fn validate_member(member: &str) -> Result<String, String> {
    if member.is_empty() || member.len() > 4096 || member.contains('\0') || member.contains('\\') {
        return Err("invalid archive member name".into());
    }
    if member.starts_with('/') {
        return Err("archive member must be relative".into());
    }
    let n = normalize_name(member);
    if n.is_empty() || is_unsafe_name(&n) || n.split('/').any(|c| c.is_empty()) {
        return Err("invalid archive member name".into());
    }
    Ok(n)
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("could not write {}: {e}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).map_err(|e| format!("Failed to create {}: {e}", path.display()))?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

fn binary_available(name: &str) -> bool {
    ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .any(|d| Path::new(d).join(name).exists())
}

// ---------------------------------------------------------------------------
// Member readers (W1-H)
// ---------------------------------------------------------------------------

/// A running reader of one archive member: `child.stdout` yields the member
/// decompressed per its suffix; `read` counts the COMPRESSED bytes consumed so
/// far, out of `total` (progress of the blob, D10).
pub struct MemberStream {
    pub child: tokio::process::Child,
    pub read: Arc<AtomicU64>,
    pub total: u64,
}

/// Where a member's bytes are: (file, offset, size).
fn locate_member(migration_id: &str, member: &str) -> Result<(PathBuf, u64, u64), String> {
    let member = validate_member(member)?;
    let meta = read_meta(migration_id)?;
    if meta.mode == "lazy" {
        let idx = read_index(migration_id)?;
        let e = idx
            .iter()
            .find(|e| e.name == member && e.kind == EntryKind::File)
            .ok_or_else(|| format!("{member} is not in the archive"))?;
        Ok((PathBuf::from(&meta.archive), e.offset, e.size))
    } else {
        let path = archive_root(migration_id)?.join(&member);
        let md = std::fs::symlink_metadata(&path).map_err(|_| format!("{member} is not in the archive"))?;
        if !md.file_type().is_file() {
            return Err(format!("{member} is not a regular file"));
        }
        Ok((path, 0, md.len()))
    }
}

/// Size (compressed) of an archive member, for progress and disk checks.
pub fn member_size(migration_id: &str, member: &str) -> Result<u64, String> {
    locate_member(migration_id, member).map(|(_, _, s)| s)
}

/// Decompressor for a member name: `gzip`, `zstd` or `cat`.
fn decompressor_for(member: &str) -> (&'static str, &'static [&'static str]) {
    if member.ends_with(".gz") || member.ends_with(".tgz") {
        ("gzip", &["-dc"])
    } else if member.ends_with(".zst") {
        ("zstd", &["-dcq"])
    } else {
        ("cat", &[])
    }
}

pub async fn open_member(migration_id: &str, member: &str) -> Result<MemberStream, String> {
    let (file, offset, size) = locate_member(migration_id, member)?;
    let (bin, args) = decompressor_for(member);
    if bin == "zstd" && !binary_available("zstd") {
        return Err("install zstd: this archive holds .zst members".into());
    }
    let mut cmd = safe_command(bin);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("could not start {bin}: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let pid = child.id();
    let read = Arc::new(AtomicU64::new(0));
    let counter = read.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let kill = || {
            // A short or failed read must not look like a complete member to
            // the consumer: kill the decompressor so its status says so.
            if let Some(p) = pid {
                unsafe {
                    libc::kill(p as i32, libc::SIGKILL);
                }
            }
        };
        let mut f = match tokio::fs::File::open(&file).await {
            Ok(f) => f,
            Err(_) => return kill(),
        };
        if f.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
            return kill();
        }
        let mut left = size;
        let mut buf = vec![0u8; 256 * 1024];
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = match f.read(&mut buf[..want]).await {
                Ok(0) | Err(_) => return kill(),
                Ok(n) => n,
            };
            if stdin.write_all(&buf[..n]).await.is_err() {
                return; // consumer gone
            }
            left -= n as u64;
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
        let _ = stdin.shutdown().await;
    });
    Ok(MemberStream { child, read, total: size })
}

/// Child whose stdout is one archive member, decompressed per `.gz`/`.zst`;
/// `kill_on_drop`; `member` relative, without `..`, without a leading `/`.
/// A truncated or unreadable member kills the child (non-zero status).
#[cfg_attr(not(test), allow(dead_code))] // contract API (W1-H); W2/W4 use open_member / extract_tar_member_with for byte progress
pub async fn spawn_member_reader(migration_id: &str, member: &str) -> Result<tokio::process::Child, String> {
    open_member(migration_id, member).await.map(|m| m.child)
}

/// Options of [`extract_tar_member_with`] beyond the contract signature.
#[derive(Default, Clone, Debug)]
pub struct ExtractOpts {
    /// `--keep-newer-files` (maildirs, W4).
    pub keep_newer_files: bool,
    /// Anchored excludes, matched in both spellings (`x` and `./x`).
    pub excludes: Vec<String>,
}

/// Streams one archive member into `tar x --no-same-owner` under `dest`.
pub async fn extract_tar_member(
    migration_id: &str,
    member: &str,
    dest: &Path,
    include: &[String],
    strip: u32,
    job: Option<&JobHandle>,
) -> Result<(), String> {
    extract_tar_member_with(migration_id, member, dest, include, strip, job, &ExtractOpts::default()).await
}

/// Pure: the `tar` arguments for an inner archive whose names do (`dot`) or do
/// not start with `./`. GNU tar matches include names literally and counts `.`
/// as a component for `--strip-components`, so both are adjusted here and a
/// caller's `strip=1` means the same thing for either spelling.
pub fn tar_extract_args(dest: &Path, include: &[String], strip: u32, dot: bool, opts: &ExtractOpts) -> Vec<String> {
    let mut a = vec![
        "-x".to_string(),
        "-f".into(),
        "-".into(),
        "-C".into(),
        dest.to_string_lossy().to_string(),
        "--no-same-owner".into(),
        // Mode bits from the archive minus setuid/setgid/sticky (D7), and no
        // chmod the unit's RestrictSUIDSGID= would refuse.
        "--no-same-permissions".into(),
    ];
    if strip > 0 {
        a.push(format!("--strip-components={}", strip + dot as u32));
    }
    if opts.keep_newer_files {
        a.push("--keep-newer-files".into());
        // One "Current ... is newer or same age" line per kept file would
        // otherwise flood stderr on every relaunch of a maildir copy.
        a.push("--warning=no-ignore-newer".into());
    }
    if !opts.excludes.is_empty() {
        a.push("--anchored".into());
        for x in &opts.excludes {
            let x = x.trim_start_matches("./").trim_matches('/');
            a.push(format!("--exclude={x}"));
            a.push(format!("--exclude=./{x}"));
        }
    }
    if !include.is_empty() {
        a.push("--".into());
        for i in include {
            let i = normalize_name(i);
            a.push(if dot { format!("./{i}") } else { i });
        }
    }
    a
}

/// tar's exit 2 caused only by includes absent from the archive is a success
/// for us (a site without `private/`, a mailbox without `.Spam/`).
pub fn tar_failure_is_only_not_found(stderr: &str) -> bool {
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    !lines.is_empty()
        && lines
            .iter()
            .all(|l| l.ends_with("Not found in archive") || l.contains("Exiting with failure status due to previous errors"))
}

pub async fn extract_tar_member_with(
    migration_id: &str,
    member: &str,
    dest: &Path,
    include: &[String],
    strip: u32,
    job: Option<&JobHandle>,
    opts: &ExtractOpts,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    for i in include {
        if i.starts_with('-') || validate_member(i).is_err() {
            return Err("invalid include pattern".into());
        }
    }
    let mut ms = open_member(migration_id, member).await?;
    let mut out = ms.child.stdout.take().ok_or("no stdout")?;
    let mut first = vec![0u8; 512];
    let mut got = 0;
    while got < 512 {
        let n = out.read(&mut first[got..]).await.map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got < 512 {
        let _ = ms.child.wait().await;
        return Err(format!("{member} is empty or not a tar archive"));
    }
    let dot = match parse_header(&first) {
        Ok(Some(h)) => h.name.starts_with("./"),
        Ok(None) => false,
        Err(_) => return Err(format!("{member} is not a tar archive (or is damaged)")),
    };
    std::fs::create_dir_all(dest).map_err(|e| format!("could not create {}: {e}", dest.display()))?;
    let mut tar = safe_command("tar");
    tar.args(tar_extract_args(dest, include, strip, dot, opts))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut tar = tar.spawn().map_err(|e| format!("could not start tar: {e}"))?;
    let mut tin = tar.stdin.take().ok_or("no tar stdin")?;
    let mut stderr = tar.stderr.take().ok_or("no tar stderr")?;
    // Drained to the end (first 64 KiB kept): a stderr pipe left full would
    // stop tar, and with it the whole extraction.
    let err_task = tokio::spawn(async move {
        let mut kept = Vec::new();
        let mut chunk = vec![0u8; 8192];
        while let Ok(n) = stderr.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            if kept.len() < 64 * 1024 {
                kept.extend_from_slice(&chunk[..n.min(64 * 1024 - kept.len())]);
            }
        }
        String::from_utf8_lossy(&kept).into_owned()
    });

    let mut write_ok = tin.write_all(&first).await.is_ok();
    let mut buf = vec![0u8; 256 * 1024];
    let mut last = std::time::Instant::now();
    if let Some(j) = job {
        j.progress("extract", 0, ms.total, member);
    }
    while write_ok {
        let n = out.read(&mut buf).await.map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        write_ok = tin.write_all(&buf[..n]).await.is_ok();
        if let Some(j) = job {
            if last.elapsed() >= std::time::Duration::from_secs(1) {
                last = std::time::Instant::now();
                j.progress("extract", ms.read.load(Ordering::Relaxed), ms.total, member);
            }
        }
    }
    drop(tin);
    let tar_status = tar.wait().await.map_err(|e| format!("tar failed: {e}"))?;
    let tar_err = err_task.await.unwrap_or_default();
    let dec_status = ms.child.wait().await.map_err(|e| format!("decompression failed: {e}"))?;
    if let Some(j) = job {
        j.progress("extract", ms.read.load(Ordering::Relaxed), ms.total, member);
    }
    if !dec_status.success() && write_ok {
        return Err(format!("{member} could not be read or decompressed (truncated or damaged)"));
    }
    if !tar_status.success() && !(tar_status.code() == Some(2) && tar_failure_is_only_not_found(&tar_err)) {
        let first_lines: Vec<&str> = tar_err.lines().take(3).collect();
        return Err(format!("extracting {member} failed: {}", first_lines.join(" | ")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Analysis (W1-A)
// ---------------------------------------------------------------------------

/// Backup format from its member names (`auto`, W1-A).
pub fn detect_source<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    let mut cpanel = false;
    let mut plesk = false;
    for raw in names {
        let n = normalize_name(raw);
        if n == "hestia/user.conf" {
            return Some("hestiacp");
        }
        // cPanel/Plesk archives often nest under one top-level directory.
        let candidates = [n.as_str(), n.split_once('/').map(|(_, r)| r).unwrap_or("")];
        for c in candidates {
            if c == "homedir" || c.starts_with("homedir/") || c == "cp" || c.starts_with("cp/") {
                cpanel = true;
            }
            if c == "domains" || c.starts_with("domains/") {
                plesk = true;
            }
        }
    }
    if cpanel {
        Some("cpanel")
    } else if plesk {
        Some("plesk")
    } else {
        None
    }
}

/// Lists an extracted tree as index entries (full mode), relative to `root`.
fn walk_tree(root: &Path) -> Vec<IndexEntry> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
            let Some(rel) = relative_to(&p, root) else { continue };
            let kind = if md.file_type().is_dir() {
                stack.push(p.clone());
                EntryKind::Dir
            } else if md.file_type().is_file() {
                EntryKind::File
            } else if md.file_type().is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::Other
            };
            out.push(IndexEntry { name: rel, offset: 0, size: if kind == EntryKind::File { md.len() } else { 0 }, kind });
        }
    }
    out
}

/// Extract and analyze a backup file (synchronous form, new id).
pub async fn analyze(backup_path: &str, source: &str) -> Result<MigrationInventory, String> {
    let id = uuid::Uuid::new_v4().to_string();
    analyze_with(&id, backup_path, source, None).await
}

/// Analysis under a given id; `job` receives the progress when the caller runs
/// it as a job (`async: true`).
pub async fn analyze_with(
    id: &str,
    backup_path: &str,
    source: &str,
    job: Option<JobHandle>,
) -> Result<MigrationInventory, String> {
    let staging = staging_dir(id)?;
    create_private_dir(Path::new(STAGING_ROOT))?;
    create_private_dir(&staging)?;
    let result = analyze_inner(id, &staging, backup_path, source, job.as_ref()).await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

async fn analyze_inner(
    id: &str,
    staging: &Path,
    backup_path: &str,
    source: &str,
    job: Option<&JobHandle>,
) -> Result<MigrationInventory, String> {
    let archive_bytes = std::fs::metadata(backup_path).map(|m| m.len()).map_err(|e| format!("Cannot read {backup_path}: {e}"))?;
    let mut head = vec![0u8; 512];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(backup_path).map_err(|e| format!("Cannot open {backup_path}: {e}"))?;
        let n = f.read(&mut head).map_err(|e| format!("Cannot read {backup_path}: {e}"))?;
        head.truncate(n);
    }
    let plain_tar = looks_like_tar(&head);

    if plain_tar {
        if let Some(j) = job {
            j.progress("index", 0, archive_bytes, "listing the archive");
        }
        let path = backup_path.to_string();
        let (index, _dot) = tokio::task::spawn_blocking(move || {
            let mut f = std::fs::File::open(&path).map_err(|e| format!("Cannot open {path}: {e}"))?;
            index_tar(&mut f)
        })
        .await
        .map_err(|e| format!("indexing failed: {e}"))??;
        let detected = detect_source(index.iter().map(|e| e.name.as_str()));
        let resolved = if source == "auto" {
            detected.ok_or_else(|| "Unknown backup format".to_string())?
        } else {
            source
        };
        if resolved == "hestiacp" {
            if detected != Some("hestiacp") {
                return Err("This is not a HestiaCP user backup (no hestia/user.conf)".into());
            }
            return analyze_hestia_lazy(id, staging, backup_path, archive_bytes, index, job).await;
        }
        return analyze_full(id, staging, backup_path, archive_bytes, Some(resolved), source, job).await;
    }
    analyze_full(id, staging, backup_path, archive_bytes, None, source, job).await
}

/// D8 lazy mode: copy the small metadata files into the staging, keep the
/// blobs in the archive.
async fn analyze_hestia_lazy(
    id: &str,
    staging: &Path,
    backup_path: &str,
    archive_bytes: u64,
    index: Vec<IndexEntry>,
    job: Option<&JobHandle>,
) -> Result<MigrationInventory, String> {
    let meta_entries: Vec<IndexEntry> = index.iter().filter(|e| is_metadata_member(e)).cloned().collect();
    let meta_bytes: u64 = meta_entries.iter().map(|e| e.size).sum();
    let staging_free = free_bytes(Path::new(STAGING_ROOT));
    if staging_free < meta_bytes + 64 * 1024 * 1024 {
        return Err(format!(
            "insufficient_disk: the staging needs {} MiB under {STAGING_ROOT}, {} MiB free",
            (meta_bytes + 64 * 1024 * 1024) / (1024 * 1024),
            staging_free / (1024 * 1024)
        ));
    }
    if let Some(j) = job {
        j.progress("metadata", 0, meta_bytes, "copying configuration files");
    }
    let path = backup_path.to_string();
    let dest = staging.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&path).map_err(|e| format!("Cannot open {path}: {e}"))?;
        for e in &meta_entries {
            let target = dest.join(&e.name);
            if let Some(parent) = target.parent() {
                create_private_dir(parent)?;
            }
            f.seek(SeekFrom::Start(e.offset)).map_err(|e| format!("archive seek failed: {e}"))?;
            let mut data = vec![0u8; e.size as usize];
            f.read_exact(&mut data).map_err(|_| format!("archive truncated at {}", e.name))?;
            write_private_file(&target, &data)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("metadata copy failed: {e}"))??;

    let meta = StagingMeta {
        mode: "lazy".into(),
        archive: backup_path.to_string(),
        hestia_user: String::new(),
        source: "hestiacp".into(),
        root: String::new(),
    };
    write_private_file(&staging.join("index.json"), &serde_json::to_vec(&index).unwrap_or_default())?;
    finish_hestia(id, staging, staging, meta, archive_bytes, &index, job).await
}

/// Full extraction (compressed archive, or another panel), with a space check.
async fn analyze_full(
    id: &str,
    staging: &Path,
    backup_path: &str,
    archive_bytes: u64,
    known: Option<&str>,
    source: &str,
    job: Option<&JobHandle>,
) -> Result<MigrationInventory, String> {
    let data = staging.join("data");
    create_private_dir(&data)?;
    let free = free_bytes(&data);
    let need = archive_bytes.saturating_add(GIB);
    if free < need {
        return Err(format!(
            "insufficient_disk: extracting this archive needs at least {:.1} GiB under {STAGING_ROOT}, {:.1} GiB free",
            need as f64 / GIB as f64,
            free as f64 / GIB as f64
        ));
    }
    if let Some(j) = job {
        j.progress("extract", 0, archive_bytes, "extracting the archive");
    }
    tracing::info!("Extracting backup {backup_path} to {}", data.display());
    // Bounded: a corrupt member or a stalled disk would otherwise leave tar
    // waiting forever. `tar xf` recognises gzip/bzip2/xz/zstd by signature.
    let mut cmd = safe_command("tar");
    cmd.args(["xf", backup_path, "-C", &data.to_string_lossy(), "--no-same-owner", "--no-same-permissions"]);
    cmd.kill_on_drop(true);
    let output = match tokio::time::timeout(std::time::Duration::from_secs(EXTRACT_TIMEOUT_SECS), cmd.output()).await {
        Ok(r) => r.map_err(|e| format!("Failed to extract: {e}"))?,
        Err(_) => {
            // A stopped extraction must not leave a partial tree filling the
            // staging: the analysis failed, so no cleanup may ever be asked for.
            let _ = std::fs::remove_dir_all(&data);
            return Err(format!(
                "Extracting {backup_path} exceeded {EXTRACT_TIMEOUT_SECS}s and was stopped. \
                 The archive is either much larger than this server can unpack in that \
                 window, or damaged - check it with `tar tf` and confirm there is free \
                 space under {STAGING_ROOT}."
            ));
        }
    };
    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&data);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("zstd") {
            return Err("install zstd: this archive is zstd-compressed".into());
        }
        return Err(format!("Failed to extract backup: {}", stderr.lines().take(3).collect::<Vec<_>>().join(" | ")));
    }

    let root = find_backup_root(&data.to_string_lossy()).await;
    let root_path = PathBuf::from(&root);
    let detected = if root_path.join("hestia/user.conf").exists() || data.join("hestia/user.conf").exists() {
        Some("hestiacp")
    } else {
        let tree = walk_tree(&root_path);
        detect_source(tree.iter().map(|e| e.name.as_str()))
    };
    let resolved = match (source, known) {
        ("auto", Some(k)) => k,
        ("auto", None) => detected.ok_or_else(|| "Unknown backup format".to_string())?,
        (s, _) => s,
    };
    let rel_root = relative_to(&root_path, staging).unwrap_or_else(|| "data".into());
    let meta = StagingMeta {
        mode: "full".into(),
        archive: backup_path.to_string(),
        hestia_user: String::new(),
        source: resolved.to_string(),
        root: rel_root,
    };
    if resolved == "hestiacp" {
        let hroot = if root_path.join("hestia/user.conf").exists() { root_path.clone() } else { data.clone() };
        let meta = StagingMeta { root: relative_to(&hroot, staging).unwrap_or_else(|| "data".into()), ..meta };
        let index = walk_tree(&hroot);
        return finish_hestia(id, staging, &hroot, meta, archive_bytes, &index, job).await;
    }
    let inventory = match resolved {
        "cpanel" => parse_cpanel(id, &root).await,
        "plesk" => parse_plesk(id, &root).await,
        _ => Err(format!("Unknown source: {resolved}")),
    }?;
    write_private_file(&staging.join("meta.json"), &serde_json::to_vec(&meta).unwrap_or_default())?;
    write_private_file(&staging.join("inventory.json"), &serde_json::to_vec(&inventory).unwrap_or_default())?;
    Ok(inventory)
}

fn read_small(root: &Path, rel: &str) -> Option<String> {
    let p = root.join(rel);
    let md = std::fs::symlink_metadata(&p).ok()?;
    if !md.file_type().is_file() || md.len() > 4 * 1024 * 1024 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn rfc3339(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Inventory of the SSL certificate Hestia kept for a domain (no key material).
fn hestia_ssl_summary(root: &Path, domain: &str) -> serde_json::Value {
    let crt = read_small(root, &format!("web/{domain}/hestia/{domain}.crt"))
        .or_else(|| read_small(root, &format!("web/{domain}/conf/{domain}.crt")));
    let Some(crt) = crt else {
        return serde_json::json!({ "present": false, "issuer": null, "not_after": null, "covers": [], "expired": false });
    };
    match crate::services::ssl::cert_metadata(&crt) {
        Ok(m) => serde_json::json!({
            "present": true,
            "issuer": m.issuer,
            "not_after": rfc3339(m.not_after),
            "covers": m.dns_names,
            "expired": m.not_after <= chrono::Utc::now(),
        }),
        Err(_) => serde_json::json!({ "present": true, "issuer": null, "not_after": null, "covers": [], "expired": false, "unreadable": true }),
    }
}

/// Name fallback of D12: `<user>_<x>` matches the domain `x`, or the only site
/// whose first label is `x`.
pub fn suggest_site_by_name(db: &str, user: &str, domains: &[String]) -> Option<String> {
    let rest = db.strip_prefix(&format!("{user}_")).unwrap_or(db).to_ascii_lowercase();
    if let Some(d) = domains.iter().find(|d| d.eq_ignore_ascii_case(&rest)) {
        return Some(d.clone());
    }
    let by_label: Vec<&String> = domains
        .iter()
        .filter(|d| d.split('.').next().is_some_and(|l| l.eq_ignore_ascii_case(&rest)))
        .collect();
    if by_label.len() == 1 {
        return Some(by_label[0].clone());
    }
    None
}

/// Common tail of both Hestia modes: parse the metadata, scan the blobs, store
/// `meta.json` + `inventory.json`.
async fn finish_hestia(
    id: &str,
    staging: &Path,
    root: &Path,
    mut meta: StagingMeta,
    archive_bytes: u64,
    index: &[IndexEntry],
    job: Option<&JobHandle>,
) -> Result<MigrationInventory, String> {
    let mut warnings: Vec<String> = Vec::new();
    let user = read_small(root, "hestia/user.conf")
        .and_then(|t| {
            t.lines()
                .flat_map(|l| hestia::parse_pairs(l))
                .find(|(k, _)| k == "NAME")
                .map(|(_, v)| v)
        })
        .filter(|u| hestia::is_safe_component(u))
        .or_else(|| {
            Path::new(&meta.archive)
                .file_name()
                .and_then(|f| f.to_str())
                .and_then(|f| f.split('.').next())
                .map(str::to_string)
                .filter(|u| hestia::is_safe_component(u))
        })
        .unwrap_or_default();
    meta.hestia_user = user.clone();
    // Written now, not at the end: the blob scan below goes through
    // `open_member`, which locates members from this file.
    write_private_file(&staging.join("meta.json"), &serde_json::to_vec(&meta).unwrap_or_default())?;

    let file_of = |name: &str| index.iter().find(|e| e.name == name && e.kind == EntryKind::File);
    let second = |prefix: &str| -> Vec<String> {
        let mut v: Vec<String> = index
            .iter()
            .filter_map(|e| e.name.strip_prefix(prefix))
            .filter_map(|r| r.split('/').next())
            .filter(|c| hestia::is_safe_component(c))
            .map(str::to_string)
            .collect();
        v.sort();
        v.dedup();
        v
    };

    // Blobs, and the zstd precondition (W1-S).
    let blob_of = |base: &str| -> Option<&IndexEntry> {
        [".tar.gz", ".tar.zst"].iter().find_map(|ext| file_of(&format!("{base}{ext}")))
    };
    if index.iter().any(|e| e.kind == EntryKind::File && e.name.ends_with(".zst")) && !binary_available("zstd") {
        return Err("install zstd: this archive holds .zst members (apt install zstd)".into());
    }

    let domains: Vec<String> = second("web/").into_iter().filter(|d| crate::routes::is_valid_domain(d)).collect();
    let db_names: Vec<String> = second("db/");

    // One read of each domain_data (D7, D9, D12).
    let blobs: Vec<(String, Option<IndexEntry>)> =
        domains.iter().map(|d| (d.clone(), blob_of(&format!("web/{d}/domain_data")).cloned())).collect();
    let scan_total: u64 = blobs.iter().filter_map(|(_, b)| b.as_ref().map(|b| b.size)).sum();
    let mut scan_done: u64 = 0;
    let mut scans: std::collections::HashMap<String, SiteScan> = std::collections::HashMap::new();
    for (d, blob) in &blobs {
        let Some(blob) = blob else { continue };
        if let Some(j) = job {
            j.progress("scan", scan_done, scan_total, d);
        }
        match open_member(id, &blob.name).await {
            Ok(mut ms) => {
                let out = ms.child.stdout.take();
                let res = match out {
                    Some(out) => {
                        let read = ms.read.clone();
                        let base = scan_done;
                        scan_domain_data(out, &user, &db_names, |_| {
                            if let Some(j) = job {
                                j.progress("scan", base + read.load(Ordering::Relaxed), scan_total, d);
                            }
                        })
                        .await
                    }
                    None => Err("no reader".into()),
                };
                let status = ms.child.wait().await;
                match (res, status) {
                    (Ok(s), Ok(st)) if st.success() => {
                        scans.insert(d.clone(), s);
                    }
                    (Ok(s), _) => {
                        warnings.push(format!("{d}: the files archive looks truncated; analysis may be incomplete"));
                        scans.insert(d.clone(), s);
                    }
                    (Err(e), _) => warnings.push(format!("{d}: the files archive could not be analysed ({e})")),
                }
            }
            Err(e) => warnings.push(format!("{d}: {e}")),
        }
        scan_done += blob.size;
    }

    // Sites.
    let mut sites = Vec::new();
    let mut ftp_accounts = Vec::new();
    let mut blob_sizes = Vec::new();
    for (d, blob) in &blobs {
        let wc = read_small(root, &format!("web/{d}/hestia/web.conf"))
            .or_else(|| read_small(root, &format!("web/{d}/web.conf")))
            .and_then(|t| hestia::parse_web_conf(&t, d));
        let Some(wc) = wc else {
            warnings.push(format!("{d}: no web.conf in the backup, skipped"));
            continue;
        };
        let web_conf_text = read_small(root, &format!("web/{d}/hestia/web.conf")).unwrap_or_default();
        let web_server = hestia_web_server(&web_conf_text, d);
        let (php_version, php_source) = if wc.backend.is_empty() {
            (None, "none".to_string())
        } else if let Some(v) = hestia::php_version_from_backend(&wc.backend) {
            (Some(v), format!("BACKEND:{}", wc.backend))
        } else {
            let found = ["nginx.conf", "apache2.conf", "nginx.ssl.conf", "apache2.ssl.conf"].iter().find_map(|f| {
                read_small(root, &format!("web/{d}/conf/{f}"))
                    .and_then(|t| hestia::php_version_from_conf(&t, d))
                    .map(|v| (v, format!("conf:{f}")))
            });
            match found {
                Some((v, s)) => (Some(v), s),
                None => (None, format!("BACKEND:{}", wc.backend)),
            }
        };
        let canonical = ["nginx.ssl.conf_redirect", "nginx.conf_redirect"]
            .iter()
            .find_map(|f| read_small(root, &format!("web/{d}/conf/{f}")).and_then(|t| hestia::canonical_from_redirect(d, &t)))
            .map(str::to_string);
        let template = if wc.proxy.is_empty() { wc.tpl.clone() } else { wc.proxy.clone() };
        let custom = (!template.is_empty() && template != "default").then(|| template.clone());
        if let Some(t) = &custom {
            warnings.push(format!(
                "{d}: custom nginx template '{t}' is not translated; it will be saved under private/.hestia-import/custom-nginx/"
            ));
        }
        if wc.ssl && !wc.ssl_force {
            warnings.push(format!("{d}: SSL_FORCE=no in HestiaCP (HTTP not redirected to HTTPS)"));
        }
        if wc.ssl && !wc.ssl_hsts {
            warnings.push(format!("{d}: SSL_HSTS=no in HestiaCP (no HSTS header)"));
        }
        if wc.suspended {
            warnings.push(format!("{d}: suspended in HestiaCP"));
        }
        if wc.ftp_users.len() > 1 {
            warnings.push(format!("{d}: {} FTP accounts, only the first one is imported as SFTP", wc.ftp_users.len()));
        }
        if !wc.custom_docroot.is_empty() {
            warnings.push(format!("{d}: custom document root in HestiaCP, the site is imported from public_html"));
        }
        let scan = scans.get(d);
        let doc_root_dir = match scan {
            Some(s) => {
                let dr = s.doc_root_dir();
                match dr {
                    None => warnings.push(format!("{d}: public_html absent from the files archive")),
                    Some("public_html0") => warnings.push(format!("{d}: only public_html0 exists, it becomes the web root")),
                    _ => {}
                }
                dr.map(str::to_string)
            }
            None => Some("public_html".to_string()),
        };
        if blob.is_none() {
            warnings.push(format!("{d}: no domain_data archive, no files to import"));
        }
        let size = blob.as_ref().map(|b| b.size).unwrap_or(0);
        blob_sizes.push(size);
        for (i, u) in wc.ftp_users.iter().enumerate() {
            ftp_accounts.push(serde_json::json!({
                "user": u, "domain": d, "hash_scheme": wc.ftp_schemes.get(i).copied().unwrap_or("none"),
            }));
        }
        sites.push(MigrationSite {
            domain: d.clone(),
            doc_root: format!("web/{d}/domain_data"),
            size_bytes: size,
            runtime: if wc.backend.is_empty() { "static".into() } else { "php".into() },
            file_count: scan.map(|s| s.file_count).unwrap_or(0),
            web_server: Some(web_server.to_string()),
            hestia: Some(HestiaSiteExtra {
                php_version,
                php_version_source: php_source,
                aliases: wc.aliases.clone(),
                canonical_host: canonical,
                ssl: hestia_ssl_summary(root, d),
                force_ssl: wc.ssl_force,
                hsts: wc.ssl_hsts,
                ftp_user: wc.ftp_users.first().cloned(),
                suspended: wc.suspended,
                doc_root_dir,
                custom_nginx_template: custom,
                paths_to_fix: scan
                    .map(|s| s.paths_to_fix.iter().map(|(f, n)| serde_json::json!({ "file": f, "occurrences": n })).collect())
                    .unwrap_or_default(),
                upload_php_files: scan.map(|s| s.upload_php_files()).unwrap_or(0),
                blob: blob.as_ref().map(|b| b.name.clone()),
            }),
        });
    }
    let site_domains: Vec<String> = sites.iter().map(|s| s.domain.clone()).collect();

    // Databases.
    let mut databases = Vec::new();
    for n in &db_names {
        let Some(text) = read_small(root, &format!("db/{n}/hestia/db.conf")) else { continue };
        let Some(line) = text.lines().find(|l| hestia::parse_pairs(l).iter().any(|(k, v)| k == "DB" && v == n)) else {
            continue;
        };
        let pairs = hestia::parse_pairs(line);
        let val = |k: &str| pairs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let ty = val("TYPE").to_ascii_lowercase();
        let engine = if ty.is_empty() || ty == "mysql" { "mariadb" } else { "postgresql" };
        if engine != "mariadb" {
            warnings.push(format!("database {n}: type {ty} is not imported (MariaDB/MySQL only)"));
        }
        let dump = index
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .find(|e| {
                e.name.starts_with(&format!("db/{n}/"))
                    && e.name.split('/').count() == 3
                    && e.name.contains(".sql")
            })
            .cloned();
        if dump.is_none() {
            warnings.push(format!("database {n}: no SQL dump in the backup"));
        }
        let hits: Vec<(&String, &String)> = scans
            .iter()
            .filter_map(|(d, s)| s.db_hits.iter().find(|(db, _)| db == n).map(|(_, f)| (d, f)))
            .collect();
        let (suggested_site, suggested_via) = if hits.len() == 1 {
            (Some(hits[0].0.clone()), Some(hits[0].1.clone()))
        } else if let Some(d) = suggest_site_by_name(n, &user, &site_domains) {
            (Some(d), Some("name".to_string()))
        } else {
            (None, None)
        };
        databases.push(MigrationDatabase {
            name: n.clone(),
            file: dump.as_ref().map(|e| e.name.clone()).unwrap_or_default(),
            size_bytes: dump.as_ref().map(|e| e.size).unwrap_or(0),
            engine: engine.to_string(),
            hestia: Some(HestiaDbExtra {
                charset: hestia::normalize_charset(&val("CHARSET")).unwrap_or_else(|| "utf8mb4".into()),
                db_user: val("DBUSER"),
                suggested_site,
                suggested_via,
            }),
        });
    }

    // Mail.
    let mut mail_domains = Vec::new();
    let mut mail_accounts = Vec::new();
    for d in second("mail/") {
        let Some(mc) = read_small(root, &format!("mail/{d}/hestia/mail.conf")).and_then(|t| hestia::parse_mail_conf(&t, &d)) else {
            continue;
        };
        let accounts = read_small(root, &format!("mail/{d}/hestia/{d}.conf"))
            .map(|t| hestia::parse_mail_accounts(&t))
            .unwrap_or_default();
        let passwd = read_small(root, &format!("mail/{d}/conf/passwd")).map(|t| hestia::passwd_schemes(&t)).unwrap_or_default();
        let maildir = blob_of(&format!("mail/{d}/accounts")).map(|e| e.size).unwrap_or(0);
        mail_domains.push(serde_json::json!({
            "domain": d, "selector": mc.selector, "dkim": mc.dkim, "catch_all": mc.catch_all,
            "accounts": accounts.len(), "aliases": accounts.iter().map(|a| a.aliases.len()).sum::<usize>(),
            "maildir_bytes": maildir,
        }));
        for a in accounts {
            let scheme = if a.hash_scheme == "NONE" {
                passwd.iter().find(|(u, _)| *u == a.account).map(|(_, s)| s.clone()).unwrap_or(a.hash_scheme.clone())
            } else {
                a.hash_scheme.clone()
            };
            mail_accounts.push(MigrationMailAccount {
                email: format!("{}@{d}", a.account),
                domain: d.clone(),
                hestia: Some(HestiaMailExtra {
                    quota_mb: a.quota_mb,
                    forward_to: a.forward_to,
                    forward_only: a.forward_only,
                    hash_scheme: scheme,
                    suspended: a.suspended,
                }),
            });
        }
    }

    let cron_jobs = read_small(root, "cron/cron.conf")
        .map(|t| t.lines().filter(|l| l.contains("JOB=")).count() as u64)
        .unwrap_or(0);
    let dns_domains = second("dns/").len() as u64;
    if cron_jobs > 0 {
        warnings.push(format!("{cron_jobs} cron job(s) in the backup are not imported"));
    }
    if dns_domains > 0 {
        warnings.push(format!("{dns_domains} DNS zone(s) in the backup are not imported"));
    }
    if sites.is_empty() && databases.is_empty() {
        warnings.push("No data found - check that this is a valid HestiaCP backup".to_string());
    }

    let staging_needed = if meta.mode == "lazy" { 64 * 1024 * 1024 } else { 0 };
    let disk = compute_disk(free_bytes(Path::new(STAGING_ROOT)), free_bytes(Path::new("/var/www")), &blob_sizes, staging_needed);
    let inventory = MigrationInventory {
        id: id.to_string(),
        source: "hestiacp".into(),
        sites,
        databases,
        mail_accounts,
        warnings,
        hestia: Some(HestiaInventoryExtra {
            mode: meta.mode.clone(),
            hestia_user: user,
            archive_bytes,
            disk,
            mail_domains,
            ftp_accounts,
            cron_jobs,
            dns_domains,
        }),
    };
    write_private_file(&staging.join("meta.json"), &serde_json::to_vec(&meta).unwrap_or_default())?;
    write_private_file(&staging.join("inventory.json"), &serde_json::to_vec(&inventory).unwrap_or_default())?;
    Ok(inventory)
}

/// Express `path` relative to `root`, for the paths that travel to the importer.
///
/// Everything in a `MigrationInventory` is joined onto the archive root on the
/// import side, and `import_site_files` rejects any source that starts with `/`,
/// so an absolute path here is not merely untidy - it cannot be imported at all.
/// Returns `None` when `path` is not inside `root`, which the caller should
/// report rather than pass on.
fn relative_to(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let rel = rel.to_string_lossy().to_string();
    if rel.is_empty() {
        return None;
    }
    Some(rel)
}

/// Find the actual root of the extracted backup (skip single top-level dir)
async fn find_backup_root(extract_dir: &str) -> String {
    let entries: Vec<_> = std::fs::read_dir(extract_dir)
        .ok()
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();

    // If there's exactly one subdirectory, use it as root
    if entries.len() == 1 {
        let entry = &entries[0];
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            return entry.path().to_string_lossy().to_string();
        }
    }
    extract_dir.to_string()
}

/// Parse a cPanel backup structure
async fn parse_cpanel(id: &str, root: &str) -> Result<MigrationInventory, String> {
    let root = Path::new(root);
    let mut sites = Vec::new();
    let mut databases = Vec::new();
    let mut mail_accounts = Vec::new();
    let mut warnings = Vec::new();

    // 1. Find sites from homedir/
    let homedir = root.join("homedir");
    if homedir.exists() {
        // Main domain: public_html/
        let public_html = homedir.join("public_html");
        if public_html.exists() {
            let (size, count) = dir_stats(&public_html).await;
            let runtime = detect_runtime(&public_html);
            // Try to get the main domain from cp/ config
            let domain = find_cpanel_main_domain(root).unwrap_or_else(|| "main-domain.com".to_string());
            sites.push(MigrationSite {
                domain,
                doc_root: "homedir/public_html".to_string(),
                size_bytes: size,
                runtime,
                file_count: count,
                web_server: None,
                hestia: None,
            });
        }

        // Additional domains from addon_domains or subdomains in homedir/
        for entry in std::fs::read_dir(&homedir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "public_html" || name.starts_with('.') || name == "mail" || name == "etc" || name == "tmp" || name == "logs" || name == "ssl" {
                continue;
            }
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_path = entry.path();
                let (size, count) = dir_stats(&dir_path).await;
                if count > 0 {
                    let runtime = detect_runtime(&dir_path);
                    sites.push(MigrationSite {
                        domain: name.clone(),
                        doc_root: format!("homedir/{name}"),
                        size_bytes: size,
                        runtime,
                        file_count: count,
                        web_server: None,
                hestia: None,
                    });
                }
            }
        }
    } else {
        warnings.push("No homedir/ found in backup".to_string());
    }

    // 2. Find databases from mysql/
    let mysql_dir = root.join("mysql");
    if mysql_dir.exists() {
        for entry in std::fs::read_dir(&mysql_dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".sql") || name.ends_with(".sql.gz") {
                let db_name = name.trim_end_matches(".gz").trim_end_matches(".sql").to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                databases.push(MigrationDatabase {
                    name: db_name,
                    file: format!("mysql/{name}"),
                    size_bytes: size,
                    engine: "mysql".to_string(),
                    hestia: None,
                });
            }
        }
    }

    // Also check for mysql.sql (grants/users dump - skip it, just note)
    if root.join("mysql.sql").exists() {
        warnings.push("mysql.sql (user grants) found but not imported - create DB users manually".to_string());
    }

    // 3. Find mail accounts from etc/
    let etc_dir = root.join("etc");
    if etc_dir.exists() {
        // cPanel stores email accounts in etc/{domain}/shadow or etc/{domain}/passwd
        for domain_entry in std::fs::read_dir(&etc_dir).ok().into_iter().flatten().flatten() {
            if domain_entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let domain = domain_entry.file_name().to_string_lossy().to_string();
                let shadow = domain_entry.path().join("shadow");
                let passwd = domain_entry.path().join("passwd");
                let accounts_file = if shadow.exists() { shadow } else if passwd.exists() { passwd } else { continue };

                if let Ok(content) = std::fs::read_to_string(&accounts_file) {
                    for line in content.lines() {
                        let user = line.split(':').next().unwrap_or("").trim();
                        if !user.is_empty() && user != "root" {
                            mail_accounts.push(MigrationMailAccount {
                                email: format!("{user}@{domain}"),
                                domain: domain.clone(),
                                hestia: None,
                            });
                        }
                    }
                }
            }
        }
    }

    if sites.is_empty() && databases.is_empty() {
        warnings.push("No sites or databases found - backup may be empty or in an unexpected format".to_string());
    }

    Ok(MigrationInventory {
        id: id.to_string(),
        source: "cpanel".to_string(),
        sites,
        databases,
        mail_accounts,
        warnings,
        hestia: None,
    })
}

/// Parse Plesk backup (stub)
async fn parse_plesk(id: &str, root: &str) -> Result<MigrationInventory, String> {
    let root = Path::new(root);
    let mut sites = Vec::new();
    let mut databases = Vec::new();
    let mut warnings = vec!["Plesk import is in beta - some items may not be detected".to_string()];

    // Plesk: look for domains/ directory
    let domains_dir = root.join("domains");
    if domains_dir.exists() {
        for entry in std::fs::read_dir(&domains_dir).ok().into_iter().flatten().flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let domain = entry.file_name().to_string_lossy().to_string();
                let httpdocs = entry.path().join("httpdocs");
                let doc_root = if httpdocs.exists() { httpdocs } else { entry.path() };
                let (size, count) = dir_stats(&doc_root).await;
                let runtime = detect_runtime(&doc_root);
                // Relative to the archive root, like the cPanel parser. Emitting
                // the absolute path put this straight into `import_site_files`'
                // own traversal guard, which rejects anything starting with `/`
                // - so every Plesk site failed at import with "Invalid source
                // directory path".
                let Some(rel_doc_root) = relative_to(&doc_root, root) else {
                    warnings.push(format!("Skipped {domain}: document root is outside the archive"));
                    continue;
                };
                sites.push(MigrationSite {
                    domain,
                    doc_root: rel_doc_root,
                    size_bytes: size,
                    runtime,
                    file_count: count,
                    web_server: None,
                hestia: None,
                });
            }
        }
    }

    // Plesk: look for databases/ directory
    let db_dir = root.join("databases");
    if db_dir.exists() {
        for entry in std::fs::read_dir(&db_dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".sql") || name.ends_with(".sql.gz") {
                let db_name = name.trim_end_matches(".gz").trim_end_matches(".sql").to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                // Carry the directory. `import_database` joins this onto the
                // archive root, so a bare filename resolved one level too high
                // and every Plesk database failed with "SQL file not found".
                databases.push(MigrationDatabase { name: db_name, file: format!("databases/{name}"), size_bytes: size, engine: "mysql".to_string(), hestia: None });
            }
        }
    }

    if sites.is_empty() && databases.is_empty() {
        warnings.push("No data found - check that this is a valid Plesk backup".to_string());
    }

    Ok(MigrationInventory { id: id.to_string(), source: "plesk".to_string(), sites, databases, mail_accounts: vec![], warnings, hestia: None })
}

/// How HestiaCP served `domain`, from its `web.conf`: `"apache"` when the
/// domain has a non-empty `PROXY` template (nginx in front of Apache), else
/// `"nginx"`. Matches the key exactly - `PROXY_EXT` is always set and says
/// nothing about Apache. A line for another domain is ignored.
pub fn hestia_web_server(web_conf: &str, domain: &str) -> &'static str {
    for line in web_conf.lines() {
        let pairs = hestia::parse_pairs(line);
        if let Some((_, d)) = pairs.iter().find(|(k, _)| k == "DOMAIN") {
            if d != domain {
                continue;
            }
        }
        if pairs
            .iter()
            .any(|(k, v)| k == "PROXY" && !v.trim().is_empty())
        {
            return "apache";
        }
    }
    "nginx"
}

/// Try to find the main domain from cPanel config files
fn find_cpanel_main_domain(root: &Path) -> Option<String> {
    // Check cp/ directory for user config
    let cp_dir = root.join("cp");
    if cp_dir.exists() {
        for entry in std::fs::read_dir(&cp_dir).ok()?.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    if line.starts_with("DNS=") || line.starts_with("DOMAIN=") {
                        let domain = line.split('=').nth(1)?.trim().to_string();
                        if !domain.is_empty() { return Some(domain); }
                    }
                }
            }
        }
    }
    // Check userdata/main
    let userdata = root.join("userdata").join("main");
    if userdata.exists() {
        if let Ok(content) = std::fs::read_to_string(&userdata) {
            for line in content.lines() {
                if line.starts_with("main_domain:") {
                    return Some(line.split(':').nth(1)?.trim().to_string());
                }
            }
        }
    }
    None
}

/// Detect runtime from file contents (PHP, static, node, python)
fn detect_runtime(dir: &Path) -> String {
    if dir.join("wp-config.php").exists() || dir.join("index.php").exists() || dir.join("artisan").exists() {
        return "php".to_string();
    }
    if dir.join("package.json").exists() { return "node".to_string(); }
    if dir.join("requirements.txt").exists() || dir.join("manage.py").exists() { return "python".to_string(); }
    "static".to_string()
}

/// Get total size and file count of a directory
async fn dir_stats(dir: &Path) -> (u64, u64) {
    let output = safe_command("du")
        .args(["-sb", &dir.to_string_lossy()])
        .output()
        .await
        .ok();
    let size = output.as_ref()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().next().map(|s| s.parse::<u64>().unwrap_or(0)))
        .unwrap_or(0);

    let count_output = safe_command("find")
        .args([&dir.to_string_lossy().to_string(), "-type", "f"])
        .output()
        .await
        .ok();
    let count = count_output.as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count() as u64)
        .unwrap_or(0);

    (size, count)
}

// ---------------------------------------------------------------------------
// Import of a site's files (W1-I)
// ---------------------------------------------------------------------------

/// Import site files from the staging to /var/www/{domain}/ - synchronous form
/// kept for callers that still send `source_dir` without `mode` (other panels,
/// pre-05 backend). No `--delete`: an initial import never removes files.
pub async fn import_site_files(
    migration_id: &str,
    domain: &str,
    source_dir: &str,
    runtime: &str,
) -> Result<String, String> {
    if !is_valid_migration_id(migration_id) {
        return Err("Invalid migration ID format".into());
    }
    if source_dir.contains("..") || source_dir.starts_with('/') {
        return Err("Invalid source directory path".into());
    }
    if domain.contains("..") || domain.contains('/') || domain.is_empty() {
        return Err("Invalid domain name".into());
    }
    let src = other_panel_source(migration_id, source_dir).await?;
    let dest = crate::services::nginx::document_root_for(&format!("/var/www/{domain}"), runtime);
    rsync_other_panel(&src, Path::new(&dest), false, domain).await?;
    Ok(format!("Copied files to {dest}"))
}

/// Source dir of a non-Hestia site: joined onto the root `analyze` resolved
/// (the same `find_backup_root` call, so the halves cannot disagree).
async fn other_panel_source(migration_id: &str, source_dir: &str) -> Result<PathBuf, String> {
    let data = staging_dir(migration_id)?.join("data");
    let extract_root = find_backup_root(&data.to_string_lossy()).await;
    let source = Path::new(&extract_root).join(source_dir);
    if !source.exists() {
        return Err(format!("Source directory not found: {}", source.display()));
    }
    Ok(source)
}

async fn rsync_other_panel(src: &Path, dest: &Path, force: bool, domain: &str) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("Failed to create {}: {e}", dest.display()))?;
    // Only the panel's exact filler goes, and only when the copied tree has
    // no index.html of its own (it would outrank the site's index.php).
    if crate::services::nginx::placeholder_to_drop(dest, src, domain) {
        let _ = std::fs::remove_file(dest.join("index.html"));
    }
    let mut cmd = safe_command("rsync");
    cmd.arg("-a");
    if force {
        cmd.arg("--delete");
    }
    let output = cmd
        .arg(format!("{}/", src.display()))
        .arg(format!("{}/", dest.display()))
        .output()
        .await
        .map_err(|e| format!("rsync failed: {e}"))?;
    if !output.status.success() {
        let output2 = safe_command("cp")
            .args(["-a", &format!("{}/.", src.display()), &dest.to_string_lossy()])
            .output()
            .await
            .map_err(|e| format!("cp failed: {e}"))?;
        if !output2.status.success() {
            return Err(format!("File copy failed: {}", String::from_utf8_lossy(&output2.stderr)));
        }
    }
    chown_site_tree(dest).await;
    Ok(())
}

/// Ownership `www-data` for everything except `.git`, which stays root's. For
/// node/proxy/python the target IS the site root - the same directory
/// `deploy.rs::clone_or_pull` clones `.git` into, so handing it over would give
/// the app `config`/`hooks/` that deploy runs as root next. `-h`: a symlink is
/// re-owned itself, never its target.
async fn chown_site_tree(dest: &Path) {
    if let Ok(mut entries) = tokio::fs::read_dir(dest).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name() == std::ffi::OsStr::new(".git") {
                continue;
            }
            let _ = safe_command("chown")
                .args(["-hR", "www-data:www-data", &entry.path().to_string_lossy()])
                .output()
                .await;
        }
    }
    let _ = safe_command("chown").args(["-h", "www-data:www-data", &dest.to_string_lossy()]).output().await;
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        let _ = safe_command("chown").args(["-hR", "root:root", &git_dir.to_string_lossy()]).output().await;
        let _ = safe_command("chmod").args(["-R", "go-rwx", &git_dir.to_string_lossy()]).output().await;
    }
}

/// `POST /migration/import-site` (W1-I): validates, then starts the job.
/// `Err` is a 400 (nothing started).
pub fn start_import_site(
    migration_id: &str,
    domain: &str,
    runtime: &str,
    mode: &str,
    source_dir: Option<&str>,
) -> Result<String, String> {
    let meta = read_meta(migration_id)?;
    if !crate::routes::is_valid_domain(domain) {
        return Err("Invalid domain name".into());
    }
    if runtime.is_empty() || runtime.len() > 16 || !runtime.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err("Invalid runtime".into());
    }
    let force = match mode {
        "initial" => false,
        "force" => true,
        _ => return Err("mode must be initial or force".into()),
    };
    let inventory = read_inventory(migration_id)?;
    let site = inventory["sites"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["domain"] == domain))
        .cloned()
        .ok_or_else(|| format!("{domain} is not in this migration's inventory"))?;
    let key = format!("{migration_id}:site:{domain}");
    let id = migration_id.to_string();
    let domain = domain.to_string();
    let runtime = runtime.to_string();
    if meta.source == "hestiacp" {
        Ok(crate::services::migration_jobs::spawn("import-site", &key, move |job| async move {
            import_hestia_site(&id, &meta, &site, &domain, &runtime, force, job).await
        }))
    } else {
        let source_dir = match source_dir {
            Some(s) => s.to_string(),
            None => site["doc_root"].as_str().unwrap_or("").to_string(),
        };
        if source_dir.is_empty() || source_dir.contains("..") || source_dir.starts_with('/') {
            return Err("Invalid source directory path".into());
        }
        Ok(crate::services::migration_jobs::spawn("import-site", &key, move |job| async move {
            job.progress("place", 0, 0, "copying files");
            let src = other_panel_source(&id, &source_dir).await?;
            let dest = crate::services::nginx::document_root_for(&format!("/var/www/{domain}"), &runtime);
            rsync_other_panel(&src, Path::new(&dest), force, &domain).await?;
            let bytes = tokio::task::spawn_blocking({
                let dest = PathBuf::from(&dest);
                move || walk_tree(&dest).iter().map(|e| e.size).sum::<u64>()
            })
            .await
            .unwrap_or(0);
            Ok(serde_json::json!({
                "doc_root_used": source_dir, "private_copied": false, "files_bytes": bytes, "rewritten": [],
                "paths_to_fix": [], "symlinks_out": [], "upload_php_files": 0, "custom_nginx_saved": null,
                "warnings": job.warnings(),
            }))
        }))
    }
}

async fn import_hestia_site(
    migration_id: &str,
    meta: &StagingMeta,
    site: &serde_json::Value,
    domain: &str,
    runtime: &str,
    force: bool,
    job: JobHandle,
) -> Result<serde_json::Value, String> {
    let site_dir = PathBuf::from(format!("/var/www/{domain}"));
    let work = site_dir.join(format!(".import-{}", job.id()));
    let res = import_hestia_site_inner(migration_id, meta, site, domain, runtime, force, &job, &site_dir, &work).await;
    // The work dir never outlives the job, success or not.
    if work.exists() {
        let _ = std::fs::remove_dir_all(&work);
    }
    res
}

#[allow(clippy::too_many_arguments)]
async fn import_hestia_site_inner(
    migration_id: &str,
    meta: &StagingMeta,
    site: &serde_json::Value,
    domain: &str,
    runtime: &str,
    force: bool,
    job: &JobHandle,
    site_dir: &Path,
    work: &Path,
) -> Result<serde_json::Value, String> {
    let blob = site["blob"].as_str().map(str::to_string);
    let blob_size = match &blob {
        Some(b) => member_size(migration_id, b)?,
        None => 0,
    };

    // space
    job.progress("space", 0, blob_size, "checking free space");
    let free = free_bytes(Path::new("/var/www"));
    let need = site_space_needed(blob_size);
    if free < need {
        return Err(format!(
            "insufficient_disk: importing {domain} needs {:.1} GiB free under /var/www, {:.1} GiB available",
            need as f64 / GIB as f64,
            free as f64 / GIB as f64
        ));
    }

    // extract
    std::fs::create_dir_all(site_dir).map_err(|e| format!("could not create {}: {e}", site_dir.display()))?;
    remove_import_dirs(site_dir, None);
    create_private_dir(work)?;
    if let Some(b) = &blob {
        let include: Vec<String> = ["public_html", "public_html0", "private"].iter().map(|s| s.to_string()).collect();
        extract_tar_member(migration_id, b, work, &include, 0, Some(job)).await?;
    } else {
        job.warn(format!("{domain}: no files archive in the backup"));
    }

    // place
    job.progress("place", blob_size, blob_size, "placing files");
    let doc_root = PathBuf::from(crate::services::nginx::document_root_for(&site_dir.to_string_lossy(), runtime));
    let private = site_dir.join("private");
    let doc_used = if work.join("public_html").is_dir() {
        Some("public_html")
    } else if work.join("public_html0").is_dir() {
        job.warn(format!("{domain}: only public_html0 exists, it becomes the web root"));
        Some("public_html0")
    } else {
        job.warn(format!("{domain}: public_html absent from the files archive"));
        None
    };
    let doc_excludes: Vec<&str> = if doc_root == site_dir { vec!["/.import-*", "/private"] } else { vec![] };
    match doc_used {
        Some(d) => {
            place_dir(&work.join(d), &doc_root, force, &doc_excludes, domain).await?;
        }
        None => {
            std::fs::create_dir_all(&doc_root).map_err(|e| format!("could not create {}: {e}", doc_root.display()))?;
        }
    }
    let private_copied = work.join("private").is_dir();
    if private_copied {
        place_dir(&work.join("private"), &private, force, &["/.hestia-import"], domain).await?;
    }

    // Custom nginx template (D7): saved out of the web root, never translated.
    let mut custom_saved: Option<String> = None;
    if let Some(name) = site["custom_nginx_template"].as_str().filter(|n| hestia::is_safe_component(n)) {
        let root = archive_root(migration_id)?;
        let dest = private.join(".hestia-import").join("custom-nginx");
        for ext in ["tpl", "stpl"] {
            let src = root.join(format!("web/{domain}/template/nginx/{name}.{ext}"));
            let is_file = std::fs::symlink_metadata(&src).map(|m| m.file_type().is_file()).unwrap_or(false);
            if is_file {
                std::fs::create_dir_all(&dest).map_err(|e| format!("could not create {}: {e}", dest.display()))?;
                let to = dest.join(format!("{name}.{ext}"));
                std::fs::copy(&src, &to).map_err(|e| format!("could not save the nginx template: {e}"))?;
                if ext == "stpl" || custom_saved.is_none() {
                    custom_saved = Some(to.to_string_lossy().to_string());
                }
            }
        }
        if custom_saved.is_none() {
            job.warn(format!("{domain}: custom nginx template '{name}' not found in the backup"));
        }
    }

    // fix
    job.progress("fix", blob_size, blob_size, "fixing paths and ownership");
    let user = meta.hestia_user.clone();
    let rewritten = if user.is_empty() {
        Vec::new()
    } else {
        rewrite_root_files(&doc_root, &private, &user, domain, doc_used.unwrap_or("public_html"))?
    };
    chown_site_tree(&doc_root).await;
    if private.is_dir() {
        chown_site_tree(&private).await;
    }
    // HestiaCP's web root is `public_html`, ours `public`: code that builds
    // `/var/www/<d>/public_html/...` itself still finds its files.
    let compat_symlink = ensure_hestia_compat_link(site_dir, &doc_root);
    let fix = tokio::task::spawn_blocking({
        let (s, d, p, u) = (site_dir.to_path_buf(), doc_root.clone(), private.clone(), user.clone());
        move || fix_walk(&s, &d, &p, &u)
    })
    .await
    .map_err(|e| format!("fix pass failed: {e}"))?;
    if !fix.symlinks_out.is_empty() {
        job.warn(format!("{domain}: {} symbolic link(s) point outside the site", fix.symlinks_out.len()));
    }
    if !fix.paths_to_fix.is_empty() {
        job.warn(format!("{domain}: {} file(s) still reference /home/{user}/", fix.paths_to_fix.len()));
    }
    Ok(serde_json::json!({
        "doc_root_used": doc_used,
        "private_copied": private_copied,
        "files_bytes": fix.files_bytes,
        "rewritten": rewritten,
        "paths_to_fix": fix.paths_to_fix.iter().map(|(f, n)| serde_json::json!({ "file": f, "occurrences": n })).collect::<Vec<_>>(),
        "symlinks_out": fix.symlinks_out,
        "upload_php_files": fix.upload_php_files,
        "custom_nginx_saved": custom_saved,
        "compat_symlink": compat_symlink,
        "warnings": job.warnings(),
    }))
}

// ---------------------------------------------------------------------------
// SSL certificate from the staging (W1-C)
// ---------------------------------------------------------------------------

/// 422 of `POST /migration/hestia/import-ssl`: `(code, message)`.
pub type SslImportError = (&'static str, String);

/// Installs the certificate Hestia kept for `domain`. The key goes from the
/// staging to `/etc/dockpanel/ssl/<d>/privkey.pem` (0600 at creation) and
/// never into a response, a log or the backend. Every check runs before the
/// first write.
pub async fn hestia_import_ssl(migration_id: &str, domain: &str) -> Result<serde_json::Value, SslImportError> {
    let root = archive_root(migration_id).map_err(|e| ("missing", e))?;
    let read = |ext: &str| -> Option<String> {
        read_small(&root, &format!("web/{domain}/hestia/{domain}.{ext}"))
            .or_else(|| read_small(&root, &format!("web/{domain}/conf/{domain}.{ext}")))
    };
    let crt = read("crt").filter(|c| c.contains("BEGIN CERTIFICATE")).ok_or(("missing", "no certificate for this domain in the backup".to_string()))?;
    let key = read("key").filter(|k| k.contains("PRIVATE KEY")).ok_or(("missing", "no private key for this domain in the backup".to_string()))?;
    let ca = read("ca").unwrap_or_default();
    let mut fullchain = crt.trim_end().to_string();
    fullchain.push('\n');
    if ca.contains("BEGIN CERTIFICATE") {
        fullchain.push_str(ca.trim_end());
        fullchain.push('\n');
    }
    let covers = crate::services::ssl::cert_covers_domain(&fullchain, domain).map_err(|e| ("not_covering", e))?;
    crate::services::ssl::key_matches_cert(&fullchain, &key).map_err(|e| ("mismatch", e))?;
    let meta = crate::services::ssl::cert_metadata(&fullchain).map_err(|e| ("missing", e))?;
    let now = chrono::Utc::now();
    if meta.not_after <= now {
        return Err(("expired", format!("the certificate expired on {}", rfc3339(meta.not_after))));
    }
    let mut warnings = Vec::new();
    let days = (meta.not_after - now).num_days();
    if days < 30 {
        warnings.push(format!("the certificate expires in {days} day(s); automatic renewal will replace it"));
    }
    if let Ok(inv) = read_inventory(migration_id) {
        if let Some(s) = inv["sites"].as_array().and_then(|a| a.iter().find(|s| s["domain"] == domain)) {
            for a in s["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str()) {
                if crate::services::ssl::cert_covers_domain(&fullchain, a).is_err() {
                    warnings.push(format!("{a} is not covered by the imported certificate"));
                }
            }
        }
    }
    let dir = format!("/etc/dockpanel/ssl/{domain}");
    tokio::fs::create_dir_all(&dir).await.map_err(|e| ("missing", format!("could not create {dir}: {e}")))?;
    let cert_path = format!("{dir}/fullchain.pem");
    let key_path = format!("{dir}/privkey.pem");
    tokio::fs::write(&cert_path, &fullchain).await.map_err(|e| ("missing", format!("could not write the certificate: {e}")))?;
    crate::services::ssl::write_key_file(&key_path, &key).await.map_err(|e| ("missing", e))?;
    tracing::info!("Imported the HestiaCP certificate of {domain} (names: {})", covers.join(", "));
    Ok(serde_json::json!({
        "cert_path": cert_path,
        "key_path": key_path,
        "expiry": rfc3339(meta.not_after),
        "covers": meta.dns_names,
        "issuer": meta.issuer,
        "warnings": warnings,
    }))
}

/// Import a SQL dump into a database container
pub async fn import_database(migration_id: &str, sql_file: &str, container_name: &str, db_name: &str, engine: &str, user: &str, password: &str) -> Result<String, String> {
    // Validate migration_id format
    if !is_valid_migration_id(migration_id) {
        return Err("Invalid migration ID format".into());
    }

    // Validate container name - only allow CyberHunter - Panel-managed DB containers
    if !container_name.starts_with("dockpanel-") || container_name.contains('/') || container_name.contains('\0')
        || container_name.len() > 128
        || !container_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("Invalid container name - only CyberHunter - Panel-managed containers are allowed".into());
    }

    // Validate no path traversal in sql_file
    if sql_file.contains("..") || sql_file.starts_with('/') {
        return Err("Invalid SQL file path".into());
    }

    // Same archive-root resolution as `import_site_files` - see the note there.
    let data = staging_dir(migration_id)?.join("data");
    let extract_root = find_backup_root(&data.to_string_lossy()).await;
    let sql_path = format!("{extract_root}/{sql_file}");

    if !Path::new(&sql_path).exists() {
        return Err(format!("SQL file not found: {sql_path}"));
    }

    // Decompress if .gz
    let actual_path = if sql_path.ends_with(".gz") {
        let decompressed = sql_path.trim_end_matches(".gz").to_string();
        let output = safe_command("gunzip")
            .args(["-k", &sql_path])
            .output()
            .await
            .map_err(|e| format!("gunzip failed: {e}"))?;
        if !output.status.success() {
            return Err(format!("Failed to decompress: {}", String::from_utf8_lossy(&output.stderr)));
        }
        decompressed
    } else {
        sql_path.clone()
    };

    // Import into container - use safe argument passing (no shell interpolation)
    let file = std::fs::File::open(&actual_path)
        .map_err(|e| format!("Failed to open SQL file: {e}"))?;

    let password_arg = format!("-p{}", password);
    let mut cmd = safe_command("docker");
    cmd.arg("exec").arg("-i").arg(container_name);

    if engine == "mysql" || engine == "mariadb" {
        cmd.args(["mariadb", "-u", user, &password_arg, db_name]);
    } else {
        cmd.args(["psql", "-U", user, "-d", db_name]);
    }

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        cmd.stdin(std::process::Stdio::from(file)).output(),
    )
    .await
    .map_err(|_| "Database import timed out (600s)".to_string())?
    .map_err(|e| format!("Import command failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Some MySQL warnings are OK - check for actual errors
        if stderr.contains("ERROR") {
            return Err(format!("Database import error: {stderr}"));
        }
    }

    Ok(format!("Imported {db_name} from {sql_file}"))
}

/// Clean up a migration: its jobs (aborted), their work dirs, its staging.
pub async fn cleanup(migration_id: &str) -> Result<(), String> {
    let dir = staging_dir(migration_id)?;
    let cancelled = crate::services::migration_jobs::cancel_migration(migration_id);
    if !cancelled.is_empty() {
        tokio::task::spawn_blocking(move || {
            if let Ok(rd) = std::fs::read_dir("/var/www") {
                for site in rd.flatten() {
                    for j in &cancelled {
                        remove_import_dirs(&site.path(), Some(j));
                    }
                }
            }
        })
        .await
        .ok();
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("Cleanup failed: {e}"))?;
        tracing::info!("Cleaned up migration directory: {}", dir.display());
    }
    // Pre-05 staging location, for migrations analyzed by an older agent.
    let legacy = format!("/tmp/dockpanel-migration-{migration_id}");
    if Path::new(&legacy).exists() {
        let _ = std::fs::remove_dir_all(&legacy);
    }
    Ok(())
}

#[cfg(test)]
mod web_server_tests {
    use super::hestia_web_server;

    #[test]
    fn hestia_proxy_template_means_apache() {
        let conf = "DOMAIN='example.com' IP='192.0.2.1' IP6='' ALIAS='www.example.com' TPL='default' \
                    SSL='yes' BACKEND='PHP-8_2' PROXY='default' PROXY_EXT='jpeg,jpg,png' SUSPENDED='no'\n";
        assert_eq!(hestia_web_server(conf, "example.com"), "apache");
    }

    #[test]
    fn empty_proxy_with_proxy_ext_is_nginx() {
        let conf = "DOMAIN='example.com' TPL='default' BACKEND='PHP-8_2' PROXY='' PROXY_EXT='jpeg,jpg,png,css'\n";
        assert_eq!(hestia_web_server(conf, "example.com"), "nginx");
        let no_key = "DOMAIN='example.com' TPL='default' PROXY_EXT='jpg'\n";
        assert_eq!(hestia_web_server(no_key, "example.com"), "nginx");
        assert_eq!(hestia_web_server("", "example.com"), "nginx");
        assert_eq!(hestia_web_server("garbage without pairs", "example.com"), "nginx");
    }

    #[test]
    fn only_the_domains_own_line_counts() {
        let conf = "DOMAIN='other.com' PROXY='default'\nDOMAIN='example.com' PROXY=''\n";
        assert_eq!(hestia_web_server(conf, "example.com"), "nginx");
        assert_eq!(hestia_web_server(conf, "other.com"), "apache");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detection() {
        assert_eq!(detect_source(["./", "./hestia/", "./hestia/user.conf"]), Some("hestiacp"));
        assert_eq!(detect_source(["hestia/user.conf"]), Some("hestiacp"));
        assert_eq!(detect_source(["backup-1/homedir/public_html/index.php"]), Some("cpanel"));
        assert_eq!(detect_source(["cp/user"]), Some("cpanel"));
        assert_eq!(detect_source(["domains/example.com/httpdocs/x"]), Some("plesk"));
        assert_eq!(detect_source(["random/file"]), None);
        // `hestia/user.conf` nested deeper is not a Hestia user backup.
        assert_eq!(detect_source(["x/y/hestia/user.conf"]), None);
    }

    #[test]
    fn member_paths_are_rejected() {
        assert!(validate_member("/etc/passwd").is_err());
        assert!(validate_member("web/../../etc").is_err());
        assert!(validate_member("..").is_err());
        assert!(validate_member("").is_err());
        assert!(validate_member("a\0b").is_err());
        assert!(validate_member("a//b").is_err());
        assert!(validate_member("a\\b").is_err());
        assert_eq!(validate_member("./web/x/domain_data.tar.gz").unwrap(), "web/x/domain_data.tar.gz");
        assert_eq!(validate_member("db/u_x.y/u_x.y.mysql.sql.gz").unwrap(), "db/u_x.y/u_x.y.mysql.sql.gz");
    }

    #[test]
    fn staging_dir_requires_a_uuid() {
        assert!(staging_dir("../etc").is_err());
        assert!(staging_dir("abc").is_err());
        let id = "0b9d2f43-3c1e-4d55-9a57-1f0e0f6f7a10";
        assert_eq!(staging_dir(id).unwrap(), Path::new(STAGING_ROOT).join(id));
    }

    #[test]
    fn tar_args_adjust_for_dot_prefix() {
        let dest = Path::new("/var/vmail/example.com/info");
        let inc = vec!["info".to_string()];
        let opts = ExtractOpts { keep_newer_files: true, excludes: vec!["logs".into()] };
        let a = tar_extract_args(dest, &inc, 1, true, &opts);
        assert!(a.contains(&"--strip-components=2".to_string()));
        assert!(a.contains(&"./info".to_string()));
        assert!(a.contains(&"--keep-newer-files".to_string()));
        assert!(a.contains(&"--warning=no-ignore-newer".to_string()));
        assert!(a.contains(&"--exclude=logs".to_string()) && a.contains(&"--exclude=./logs".to_string()));
        assert!(a.contains(&"--no-same-owner".to_string()) && a.contains(&"--no-same-permissions".to_string()));
        let b = tar_extract_args(dest, &inc, 1, false, &ExtractOpts::default());
        assert!(b.contains(&"--strip-components=1".to_string()));
        assert_eq!(b.last().unwrap(), "info");
        let c = tar_extract_args(dest, &[], 0, true, &ExtractOpts::default());
        assert!(!c.iter().any(|x| x.starts_with("--strip")));
    }

    #[test]
    fn not_found_only_is_tolerated() {
        assert!(tar_failure_is_only_not_found(
            "tar: ./private: Not found in archive\ntar: Exiting with failure status due to previous errors\n"
        ));
        assert!(!tar_failure_is_only_not_found("tar: x: Cannot open: Permission denied\n"));
        assert!(!tar_failure_is_only_not_found(""));
    }

    #[test]
    fn site_name_fallback() {
        let domains = vec!["101x.example".to_string(), "shop.example.org".to_string(), "shop.example.net".to_string()];
        assert_eq!(suggest_site_by_name("u_101x", "u", &domains).as_deref(), Some("101x.example"));
        assert_eq!(suggest_site_by_name("u_shop.example.org", "u", &domains).as_deref(), Some("shop.example.org"));
        assert_eq!(suggest_site_by_name("u_shop", "u", &domains), None, "ambiguous first label");
        assert_eq!(suggest_site_by_name("u_none", "u", &domains), None);
    }

    async fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut gz = safe_command("gzip");
        gz.arg("-c").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut child = gz.spawn().unwrap();
        let mut sin = child.stdin.take().unwrap();
        let d = data.to_vec();
        let w = tokio::spawn(async move {
            sin.write_all(&d).await.unwrap();
        });
        let out = child.wait_with_output().await.unwrap();
        w.await.unwrap();
        out.stdout
    }

    /// The whole W1 path on a synthetic HestiaCP backup, through the REAL
    /// staging root: analyze (lazy), secrets readers, member reader, extract,
    /// site import job, SSL import, cleanup. It writes under /var/lib/dockpanel,
    /// /var/www and /etc/dockpanel, so it runs only as root inside a container
    /// (the build image), never on a workstation.
    #[tokio::test]
    async fn hestia_end_to_end_in_container() {
        use crate::services::migration_files::test_tar::{build, E};
        let in_container = Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
        if !in_container || unsafe { libc::geteuid() } != 0 || !binary_available("gzip") || !binary_available("tar") {
            return;
        }
        let tag = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let d = format!("w1e2e-{tag}.example");
        let user = "u";
        let ftp_hash_value = "$y$j9T$saltsalt$hashhashhash";
        let mysql_hash_value = "*0123456789ABCDEF0123456789ABCDEF01234567";

        let user_ini = format!("auto_prepend_file = '/home/{user}/web/{d}/public_html/wordfence-waf.php'\n");
        let wp = format!("<?php\ndefine('DB_NAME', 'u_db1');\nrequire '/home/{user}/web/{d}/private/conf.php';\n");
        let inner = build(&[
            E::D("./"),
            E::D("./public_html/"),
            E::F("./public_html/index.php", b"<?php echo 1;"),
            E::F("./public_html/.user.ini", user_ini.as_bytes()),
            E::F("./public_html/wp-config.php", wp.as_bytes()),
            E::F("./public_html/wp-content/uploads/x.php", b"<?php"),
            E::D("./private/"),
            E::F("./private/conf.php", b"<?php"),
            E::D("./logs/"),
            E::F("./logs/a.log", b"log"),
        ]);
        let blob = gzip_bytes(&inner).await;
        let sql = b"CREATE TABLE t (id INT);\n".to_vec();
        let sql_gz = gzip_bytes(&sql).await;

        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![d.clone(), format!("www.{d}")]).unwrap();
        let crt = params.self_signed(&key).unwrap().pem();
        let key_pem = key.serialize_pem();

        let web_conf = format!(
            "DOMAIN='{d}' ALIAS='www.{d}' TPL='default' SSL='yes' SSL_FORCE='yes' FTP_USER='u_ftp' \
             FTP_MD5='{ftp_hash_value}' BACKEND='default' PROXY='default' SUSPENDED='no'\n"
        );
        let apache = format!("SetHandler \"proxy:unix:/run/php/php8.3-fpm-{d}.sock|fcgi://localhost\"\n");
        let redirect = format!("if ($host != \"www.{d}\") {{\n   return 301 $scheme://www.{d}$request_uri;\n}}\n");
        let db_conf = format!("DB='u_db1' DBUSER='u_db1' MD5='{mysql_hash_value}' HOST='localhost' TYPE='mysql' CHARSET='UTF8MB4'\n");
        let mail_conf = format!("DOMAIN='{d}' DKIM='yes' DKIM_SELECTOR='mail' CATCHALL='' SUSPENDED='no'\n");
        let accounts = "ACCOUNT='info' ALIAS='contact' FWD='' FWD_ONLY='no' MD5='{BLF-CRYPT}$2y$05$abcdefghijk' QUOTA='unlimited' SUSPENDED='no'\n";
        let p = |s: &str| s.to_string();
        let names = [
            p("./hestia/user.conf"),
            format!("./web/{d}/hestia/web.conf"),
            format!("./web/{d}/conf/apache2.conf"),
            format!("./web/{d}/conf/nginx.ssl.conf_redirect"),
            format!("./web/{d}/hestia/{d}.crt"),
            format!("./web/{d}/hestia/{d}.key"),
            format!("./web/{d}/domain_data.tar.gz"),
            p("./db/u_db1/hestia/db.conf"),
            p("./db/u_db1/u_db1.mysql.sql.gz"),
            format!("./mail/{d}/hestia/mail.conf"),
            format!("./mail/{d}/hestia/{d}.conf"),
        ];
        let user_conf = format!("NAME='{user}' PACKAGE='default'\n");
        let datas: Vec<&[u8]> = vec![
            user_conf.as_bytes(),
            web_conf.as_bytes(),
            apache.as_bytes(),
            redirect.as_bytes(),
            crt.as_bytes(),
            key_pem.as_bytes(),
            &blob,
            db_conf.as_bytes(),
            &sql_gz,
            mail_conf.as_bytes(),
            accounts.as_bytes(),
        ];
        let mut entries = vec![E::D("./")];
        for (n, data) in names.iter().zip(datas.iter()) {
            entries.push(E::F(n, data));
        }
        let outer = build(&entries);
        let base = std::env::temp_dir().join(format!("w1-e2e-{tag}"));
        std::fs::create_dir_all(&base).unwrap();
        let archive = base.join("u.2026-01-01_00-00-00.tar");
        std::fs::write(&archive, &outer).unwrap();

        // Analyze.
        let id = uuid::Uuid::new_v4().to_string();
        let inv = analyze_with(&id, &archive.to_string_lossy(), "auto", None).await.unwrap();
        let v = serde_json::to_value(&inv).unwrap();
        let text = v.to_string();
        assert!(!text.contains(ftp_hash_value) && !text.contains(mysql_hash_value) && !text.contains("PRIVATE KEY"));
        assert!(!text.contains("$2y$05$abcdefghijk"), "no mail hash in the inventory");
        assert_eq!(v["source"], "hestiacp");
        assert_eq!(v["mode"], "lazy");
        assert_eq!(v["hestia_user"], user);
        let s = &v["sites"][0];
        assert_eq!(s["domain"], d.as_str());
        assert_eq!(s["php_version"], "8.3");
        assert_eq!(s["php_version_source"], "conf:apache2.conf");
        assert_eq!(s["web_server"], "apache");
        assert_eq!(s["canonical_host"], "www");
        assert_eq!(s["aliases"][0], format!("www.{d}"));
        assert_eq!(s["force_ssl"], true);
        assert_eq!(s["hsts"], false);
        assert_eq!(s["ssl"]["present"], true);
        assert_eq!(s["ssl"]["covers"].as_array().unwrap().len(), 2);
        assert_eq!(s["doc_root_dir"], "public_html");
        assert_eq!(s["upload_php_files"], 1, "warnings: {}", v["warnings"]);
        assert_eq!(s["ftp_user"], "u_ftp");
        assert!(s["paths_to_fix"].as_array().unwrap().iter().any(|p| p["file"] == ".user.ini"));
        let db = &v["databases"][0];
        assert_eq!(db["suggested_site"], d.as_str());
        assert_eq!(db["suggested_via"], "wp-config.php");
        assert_eq!(db["charset"], "utf8mb4");
        assert_eq!(db["engine"], "mariadb");
        assert_eq!(v["mail_accounts"][0]["hash_scheme"], "BLF-CRYPT");
        assert_eq!(v["mail_domains"][0]["aliases"], 1);
        assert_eq!(v["ftp_accounts"][0]["hash_scheme"], "yescrypt");
        assert!(v["disk"]["www_free"].as_u64().is_some());
        let staging = staging_dir(&id).unwrap();
        assert!(staging.join(format!("web/{d}/hestia/web.conf")).exists());
        assert!(!staging.join(format!("web/{d}/domain_data.tar.gz")).exists(), "lazy mode never copies blobs");

        // Secret readers (W2/W4).
        let cred = hestia::db_credentials(&id, "u_db1").unwrap();
        assert_eq!(cred.mysql_hash, mysql_hash_value);
        assert_eq!(hestia::ftp_hash(&id, &d), Some(("u_ftp".into(), ftp_hash_value.into())));

        // Member reader: the dump, decompressed, streamed from the archive.
        let child = spawn_member_reader(&id, "db/u_db1/u_db1.mysql.sql.gz").await.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, sql);
        assert!(spawn_member_reader(&id, "../etc/passwd").await.is_err());
        assert!(spawn_member_reader(&id, "db/missing.sql.gz").await.is_err());

        // extract_tar_member with strip=1 on a dot-prefixed inner tar.
        let dest = base.join("x");
        extract_tar_member(&id, &format!("web/{d}/domain_data.tar.gz"), &dest, &["public_html".into()], 1, None)
            .await
            .unwrap();
        assert!(dest.join("index.php").exists());
        assert!(!dest.join("logs").exists() && !dest.join("private").exists());

        // Site import job.
        let job_id = start_import_site(&id, &d, "php", "initial", None).unwrap();
        let mut report = serde_json::Value::Null;
        for _ in 0..500 {
            let j = crate::services::migration_jobs::get(&job_id).unwrap();
            if j["state"] != "running" {
                assert_eq!(j["state"], "done", "{j}");
                report = j["report"].clone();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let site_dir = PathBuf::from(format!("/var/www/{d}"));
        assert!(site_dir.join("public/index.php").exists());
        assert!(site_dir.join("private/conf.php").exists());
        for never in ["logs", "conf", "hestia", "template", "public/logs"] {
            assert!(!site_dir.join(never).exists(), "{never} must never be placed");
        }
        let ini = std::fs::read_to_string(site_dir.join("public/.user.ini")).unwrap();
        assert!(ini.contains(&format!("/var/www/{d}/public/wordfence-waf.php")), "{ini}");
        assert!(site_dir.join("private/.hestia-import/orig/.user.ini").exists());
        assert_eq!(report["rewritten"][0], ".user.ini");
        assert_eq!(report["doc_root_used"], "public_html");
        assert_eq!(report["private_copied"], true);
        assert_eq!(report["upload_php_files"], 1);
        assert!(report["paths_to_fix"].as_array().unwrap().iter().any(|p| p["file"] == "wp-config.php"));
        // HestiaCP layout link, and no panel filler in front of index.php.
        assert_eq!(std::fs::read_link(site_dir.join("public_html")).unwrap(), Path::new("public"));
        assert!(site_dir.join("public_html/index.php").exists());
        assert_eq!(report["compat_symlink"], format!("/var/www/{d}/public_html -> public"));
        assert!(!site_dir.join("public/index.html").exists());
        assert!(
            !std::fs::read_dir(&site_dir).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with(".import-")),
            "work dir removed"
        );
        assert!(start_import_site(&id, "absent.example", "php", "initial", None).is_err());
        assert!(start_import_site(&id, &d, "php", "bogus", None).is_err());

        // SSL import.
        let ssl = hestia_import_ssl(&id, &d).await.unwrap();
        assert_eq!(ssl["covers"].as_array().unwrap().len(), 2);
        assert!(!ssl.to_string().contains("PRIVATE KEY"));
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(ssl["key_path"].as_str().unwrap()).unwrap();
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(format!("/etc/dockpanel/ssl/{d}"));

        // Cleanup.
        cleanup(&id).await.unwrap();
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&site_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// End to end over a synthetic plain-tar Hestia backup, in a temp staging:
    /// index, metadata selection, member reader (gzip) and tar extraction with
    /// the `./` prefix. Runs only where gzip and tar exist (the build image).
    #[tokio::test]
    async fn lazy_member_reader_and_extract() {
        use crate::services::migration_files::test_tar::{build, E};
        if !binary_available("gzip") || !binary_available("tar") {
            return;
        }
        let inner = build(&[
            E::D("./"),
            E::D("./public_html/"),
            E::F("./public_html/index.php", b"<?php echo 1;"),
            E::D("./logs/"),
            E::F("./logs/access.log", b"x"),
        ]);
        let mut gz = safe_command("gzip");
        gz.arg("-c").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut child = gz.spawn().unwrap();
        let mut sin = child.stdin.take().unwrap();
        let data = inner.clone();
        let w = tokio::spawn(async move {
            sin.write_all(&data).await.unwrap();
        });
        let out = child.wait_with_output().await.unwrap();
        w.await.unwrap();
        let blob = out.stdout;
        let outer = build(&[
            E::D("./"),
            E::F("./hestia/user.conf", b"NAME='u'\n"),
            E::F("./web/example.com/domain_data.tar.gz", &blob),
        ]);
        let base = std::env::temp_dir().join(format!("w1-lazy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();
        let archive = base.join("backup.tar");
        std::fs::write(&archive, &outer).unwrap();
        let (index, dot) = index_tar(&mut std::fs::File::open(&archive).unwrap()).unwrap();
        assert!(dot);
        assert_eq!(detect_source(index.iter().map(|e| e.name.as_str())), Some("hestiacp"));
        let b = index.iter().find(|e| e.name == "web/example.com/domain_data.tar.gz").unwrap();
        assert!(!is_metadata_member(b));

        // Member reader on the raw bytes (bypassing staging_dir, which is fixed).
        let mut gzd = safe_command("gzip");
        gzd.arg("-dc").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut dchild = gzd.spawn().unwrap();
        let mut din = dchild.stdin.take().unwrap();
        let slice = outer[b.offset as usize..(b.offset + b.size) as usize].to_vec();
        tokio::spawn(async move {
            din.write_all(&slice).await.unwrap();
        });
        let dout = dchild.wait_with_output().await.unwrap();
        assert_eq!(dout.stdout, inner, "the indexed slice is the whole blob");

        // tar arguments for the dot-prefixed inner archive.
        let dest = base.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let args = tar_extract_args(&dest, &["public_html".into(), "private".into()], 0, true, &ExtractOpts::default());
        let mut tar = safe_command("tar");
        tar.args(&args).stdin(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut t = tar.spawn().unwrap();
        let mut tin = t.stdin.take().unwrap();
        let inner2 = inner.clone();
        tokio::spawn(async move {
            tin.write_all(&inner2).await.unwrap();
        });
        let o = t.wait_with_output().await.unwrap();
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        assert!(o.status.success() || tar_failure_is_only_not_found(&err), "{err}");
        assert!(dest.join("public_html/index.php").exists());
        assert!(!dest.join("logs").exists(), "logs/ is never extracted");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
