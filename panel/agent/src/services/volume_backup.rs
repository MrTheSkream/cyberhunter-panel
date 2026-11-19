//! App data archives: Docker volumes (named or anonymous) and bind mounts of
//! the apps the panel deployed.
//!
//! An archive is a `tar.gz` of the mount's contents, made by a throwaway
//! `alpine` container that mounts the source read-only, optionally encrypted
//! afterwards (`services::encryption`, same format and key as database dumps).
//!
//! Containers that use the data are stopped for the copy (by default) and for
//! the restore (always), and restarted whatever happens: see [`with_stopped`].
//! Every step that can refuse cheaply (validation, the target recheck, the
//! space check, the archive's integrity and passphrase) runs BEFORE anything is
//! stopped, so a refusal never costs the app downtime.
//!
//! The work itself runs in a spawned task: if the panel gives up on the HTTP
//! request half way, the operation still finishes and the containers are still
//! restarted, instead of being abandoned with the request's future.

use std::future::Future;
use std::path::{Path, PathBuf};

use crate::safe_cmd::safe_command;
use crate::services::backup_targets::{
    self, BackupTarget, TargetContainer, TargetKind, is_valid_owner_name, is_valid_volume_name,
};
use crate::services::encryption;

use super::backups::{BackupInfo, compute_file_sha256};

const BACKUP_DIR: &str = "/var/backups/dockpanel/volumes";

/// Why an app data operation failed, mapped by the routes to an HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VbError {
    /// 400: the request names something invalid or not backed up here.
    BadRequest(String),
    /// 404: the archive is not (or no longer) on this host.
    NotFound(String),
    /// 409: an archive of this target was made this very second.
    Conflict(String),
    /// 422: the archive is corrupt, tampered with, or the passphrase is wrong.
    Integrity(String),
    /// 507: not enough free space for the archive.
    NoSpace(String),
    /// 500: anything else.
    Internal(String),
}

impl VbError {
    pub fn message(&self) -> &str {
        match self {
            Self::BadRequest(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::Integrity(m)
            | Self::NoSpace(m)
            | Self::Internal(m) => m,
        }
    }

    /// An error from `services::encryption`: the file's fault (422) or the host's (500).
    fn from_crypto(e: String) -> Self {
        if encryption::is_content_error(&e) { Self::Integrity(e) } else { Self::Internal(e) }
    }
}

impl std::fmt::Display for VbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Validate a backup filename: an archive (`.tar.gz`, or `.tar.gz.enc` once
/// encrypted), no path separator, not hidden (temporaries start with `.`), and
/// only `[A-Za-z0-9_.-]`, which keeps it safe to interpolate into the restore
/// shell below.
pub fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.contains('/')
        && !name.contains("..")
        && !name.starts_with('.')
        && (name.ends_with(".tar.gz") || name.ends_with(".tar.gz.enc"))
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn backup_dir(container_name: &str) -> PathBuf {
    PathBuf::from(format!("{BACKUP_DIR}/{container_name}"))
}

/// What the archiving/restoring container mounts at `/volume`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountRef {
    Volume(String),
    Bind(PathBuf),
}

impl MountRef {
    /// The `-v` argument. Names and paths were validated upstream (volume
    /// name charset; canonical bind path without `:` or `,`).
    pub fn docker_arg(&self, read_only: bool) -> String {
        let src = match self {
            Self::Volume(name) => name.clone(),
            Self::Bind(path) => path.to_string_lossy().to_string(),
        };
        if read_only { format!("{src}:/volume:ro") } else { format!("{src}:/volume") }
    }

    /// The per-resource lock key, shared with the legacy restore lock.
    fn lock_key(&self) -> String {
        match self {
            Self::Volume(name) => format!("volume:{name}"),
            Self::Bind(path) => format!("bind:{}", path.display()),
        }
    }
}

// ── Stop / restart guarantee ────────────────────────────────────────────────

/// Stops and starts containers. A trait so the guarantee below is tested
/// without a Docker daemon.
pub trait ContainerControl: Send + Sync {
    fn stop(&self, id: &str) -> impl Future<Output = Result<(), String>> + Send;
    fn start(&self, id: &str) -> impl Future<Output = Result<(), String>> + Send;
}

/// The real one: `docker stop` / `docker start`.
pub struct DockerCli;

impl ContainerControl for DockerCli {
    async fn stop(&self, id: &str) -> Result<(), String> {
        docker_simple(&["stop", "-t", "60", id], 120).await
    }
    async fn start(&self, id: &str) -> Result<(), String> {
        docker_simple(&["start", id], 120).await
    }
}

async fn docker_simple(args: &[&str], secs: u64) -> Result<(), String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(secs),
        safe_command("docker").args(args).output(),
    )
    .await
    .map_err(|_| format!("docker {} timed out", args[0]))?
    .map_err(|e| format!("docker {}: {e}", args[0]))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// What happened around the work.
#[derive(Debug)]
pub struct StopOutcome<T> {
    pub result: Result<T, VbError>,
    /// Names of the containers this call stopped.
    pub stopped: Vec<String>,
    /// Names of those it started again.
    pub restarted: Vec<String>,
    /// `name: error` for each container it could not start again.
    pub restart_errors: Vec<String>,
}

/// Stop `containers` (in order), run `work`, then start again every container
/// this call stopped, in reverse order, WHATEVER happened: the work failing,
/// the work panicking, or a later stop failing (the work is then not run and
/// the containers already stopped are started again).
///
/// `work` runs in its own task so a panic in it is caught here and cannot skip
/// the restart.
pub async fn with_stopped<C, T, F>(ctl: &C, containers: &[TargetContainer], work: F) -> StopOutcome<T>
where
    C: ContainerControl,
    T: Send + 'static,
    F: Future<Output = Result<T, VbError>> + Send + 'static,
{
    let mut stopped: Vec<&TargetContainer> = Vec::new();
    let mut stop_error = None;
    for c in containers {
        match ctl.stop(&c.id).await {
            Ok(()) => {
                tracing::info!("Stopped container {} for an app data operation", c.name);
                stopped.push(c);
            }
            Err(e) => {
                stop_error = Some(VbError::Internal(format!("Failed to stop container {}: {e}", c.name)));
                break;
            }
        }
    }

    let result = match stop_error {
        Some(e) => Err(e),
        None => match tokio::spawn(work).await {
            Ok(r) => r,
            Err(e) => Err(VbError::Internal(format!("App data operation aborted: {e}"))),
        },
    };

    let mut restarted = Vec::new();
    let mut restart_errors = Vec::new();
    for c in stopped.iter().rev() {
        match ctl.start(&c.id).await {
            Ok(()) => restarted.push(c.name.clone()),
            Err(e) => {
                tracing::error!("Failed to restart container {} after an app data operation: {e}", c.name);
                restart_errors.push(format!("{}: {e}", c.name));
            }
        }
    }
    restarted.reverse();

    StopOutcome {
        result,
        stopped: stopped.iter().map(|c| c.name.clone()).collect(),
        restarted,
        restart_errors,
    }
}

/// Run `fut` in its own task: it then completes even if the caller (an HTTP
/// handler whose client went away) is dropped.
async fn detached<T, F>(fut: F) -> Result<T, VbError>
where
    T: Send + 'static,
    F: Future<Output = Result<T, VbError>> + Send + 'static,
{
    tokio::spawn(fut)
        .await
        .unwrap_or_else(|e| Err(VbError::Internal(format!("App data operation aborted: {e}"))))
}

/// Time budget for tar/decrypt work on an archive of `bytes` bytes (600 s plus
/// 300 s per GiB, capped): the same scale as the encryption it sits beside.
pub fn archive_timeout(bytes: u64) -> std::time::Duration {
    encryption::operation_timeout(bytes)
}

// ── Space ───────────────────────────────────────────────────────────────────

/// Bytes the archive of `source_bytes` of data needs free before it starts:
/// twice the data (the archive, then its encrypted copy beside it).
pub fn space_needed(source_bytes: u64) -> u64 {
    source_bytes.saturating_mul(2)
}

fn free_bytes(dir: &Path) -> Result<u64, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(dir.as_os_str().as_bytes()).map_err(|_| "Invalid directory path".to_string())?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path, `st` a valid out-pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(format!("statvfs {}: {}", dir.display(), std::io::Error::last_os_error()));
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

async fn du_bytes(path: &str) -> Result<u64, String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        safe_command("du").args(["-sb", path]).output(),
    )
    .await
    .map_err(|_| format!("Measuring {path} timed out"))?
    .map_err(|e| format!("Failed to measure {path}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to measure {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("Failed to measure {path}: unreadable du output"))
}

fn check_space(dir: &Path, need: u64, what: &str) -> Result<(), VbError> {
    let free = free_bytes(dir).map_err(VbError::Internal)?;
    if free < need {
        return Err(VbError::NoSpace(format!(
            "Not enough free disk space in {} for {what}: about {need} bytes needed, {free} available",
            dir.display()
        )));
    }
    Ok(())
}

// ── Create ──────────────────────────────────────────────────────────────────

/// A new-style backup request (`kind` present in the body).
#[derive(Debug, Clone)]
pub struct TargetBackupRequest {
    pub kind: TargetKind,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub owner_name: String,
    pub stop_containers: bool,
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TargetBackupInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub encrypted: bool,
    pub kind: TargetKind,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub owner_name: String,
    pub stopped: Vec<String>,
    pub created_at: String,
}

fn check_key(key: &Option<String>) -> Result<Option<String>, VbError> {
    match key.as_deref() {
        None | Some("") => Ok(None),
        Some(k) if k.len() > 1024 => Err(VbError::BadRequest("Encryption key is too long".into())),
        Some(k) => Ok(Some(k.to_string())),
    }
}

/// Archive one current backup target (see `backup_targets`).
pub async fn backup_target(req: TargetBackupRequest) -> Result<TargetBackupInfo, VbError> {
    detached(backup_target_inner(req)).await
}

async fn backup_target_inner(req: TargetBackupRequest) -> Result<TargetBackupInfo, VbError> {
    if !is_valid_owner_name(&req.owner_name) {
        return Err(VbError::BadRequest("Invalid owner name".into()));
    }
    let key = check_key(&req.encryption_key)?;
    match req.kind {
        TargetKind::Volume => {
            if !req.volume_name.as_deref().is_some_and(is_valid_volume_name) {
                return Err(VbError::BadRequest("Invalid volume name".into()));
            }
        }
        TargetKind::Bind => {
            if !req.source_path.as_deref().is_some_and(|p| p.starts_with('/')) {
                return Err(VbError::BadRequest("source_path must be an absolute path".into()));
            }
        }
    }

    // Never archive what the enumeration would not offer.
    let report = backup_targets::enumerate_targets().await.map_err(VbError::Internal)?;
    let target: BackupTarget = backup_targets::find_target(
        &report,
        req.kind,
        req.volume_name.as_deref(),
        req.source_path.as_deref(),
    )
    .cloned()
    .ok_or_else(|| VbError::BadRequest("Not a current backup target of a managed app".into()))?;
    if target.owner_name != req.owner_name {
        return Err(VbError::BadRequest(format!(
            "owner_name does not match this target's owner ({})",
            target.owner_name
        )));
    }
    let mount = match target.kind {
        TargetKind::Volume => MountRef::Volume(target.volume_name.clone().unwrap_or_default()),
        TargetKind::Bind => MountRef::Bind(PathBuf::from(&target.source)),
    };

    let _locks = crate::site_lock::lock_sites(&format!("app-data:{}", target.owner_name), &mount.lock_key()).await;

    let dest_dir = backup_dir(&target.owner_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| VbError::Internal(format!("Failed to create backup dir: {e}")))?;
    let size = du_bytes(&target.source).await.map_err(VbError::Internal)?;
    check_space(&dest_dir, space_needed(size), "this archive")?;

    let filename = backup_targets::archive_name(&target.owner_name, target.kind, &target.slug, chrono::Utc::now());
    let final_path = dest_dir.join(&filename);
    if final_path.exists() || dest_dir.join(format!("{filename}.enc")).exists() {
        return Err(VbError::Conflict("An archive of this data was made this second, retry".into()));
    }

    let to_stop: Vec<TargetContainer> = if req.stop_containers {
        target.containers.iter().filter(|c| c.running).cloned().collect()
    } else {
        Vec::new()
    };

    let timeout = archive_timeout(size);
    let work = tar_into(mount, dest_dir.clone(), filename.clone(), timeout);
    let outcome = with_stopped(&DockerCli, &to_stop, work).await;
    if !outcome.restart_errors.is_empty() {
        // The app is down: that is the failure to report, and a non-200 leaves no archive.
        std::fs::remove_file(&final_path).ok();
        let base = match &outcome.result {
            Ok(()) => "The archive was made".to_string(),
            Err(e) => format!("The backup failed ({e})"),
        };
        return Err(VbError::Internal(format!(
            "{base}, but these containers could not be restarted: {}. The archive was discarded.",
            outcome.restart_errors.join("; ")
        )));
    }
    outcome.result?;

    let (filename, path) = match &key {
        Some(k) => {
            let src = final_path.to_string_lossy().to_string();
            match encryption::encrypt_backup(&src, k).await {
                Ok(enc) => (format!("{filename}.enc"), PathBuf::from(enc)),
                Err(e) => {
                    // Never leave the plaintext behind a failed encrypted backup.
                    std::fs::remove_file(&final_path).ok();
                    return Err(VbError::Internal(format!("Encryption failed: {e}")));
                }
            }
        }
        None => (filename, final_path),
    };

    let size_bytes = std::fs::metadata(&path)
        .map_err(|e| VbError::Internal(format!("Failed to read backup metadata: {e}")))?
        .len();
    let Some(sha256) = compute_file_sha256(&path.to_string_lossy()).await else {
        std::fs::remove_file(&path).ok();
        return Err(VbError::Internal("Failed to hash the archive".into()));
    };

    tracing::info!(
        "App data backup created: {filename} ({size_bytes} bytes, encrypted: {}, stopped: {:?})",
        key.is_some(),
        outcome.stopped
    );
    Ok(TargetBackupInfo {
        filename,
        size_bytes,
        sha256,
        encrypted: key.is_some(),
        kind: target.kind,
        volume_name: target.volume_name.clone(),
        source_path: target.source_path.clone(),
        owner_name: target.owner_name.clone(),
        stopped: outcome.stopped,
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

/// tar the mount into `{dest_dir}/.{filename}.part`, then rename it to
/// `filename`. A crash leaves only the hidden `.part`, which the agent sweeps
/// at startup.
async fn tar_into(
    mount: MountRef,
    dest_dir: PathBuf,
    filename: String,
    timeout: std::time::Duration,
) -> Result<(), VbError> {
    let part = format!(".{filename}.part");
    let part_path = dest_dir.join(&part);
    let dir = dest_dir.to_str().ok_or_else(|| VbError::Internal("Invalid dir".into()))?;
    let output = tokio::time::timeout(
        timeout,
        safe_command("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &mount.docker_arg(true),
                "-v",
                &format!("{dir}:/backup"),
                "alpine:3.19",
                "tar",
                "czf",
                &format!("/backup/{part}"),
                "-C",
                "/volume",
                ".",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            std::fs::remove_file(&part_path).ok();
            return Err(VbError::Internal(format!("Failed to run volume backup: {e}")));
        }
        Err(_) => {
            std::fs::remove_file(&part_path).ok();
            return Err(VbError::Internal(format!(
                "Volume backup timed out after {} seconds",
                timeout.as_secs()
            )));
        }
    };
    if !output.status.success() {
        std::fs::remove_file(&part_path).ok();
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VbError::Internal(format!("Volume backup failed: {}", stderr.trim())));
    }
    std::fs::rename(&part_path, dest_dir.join(&filename)).map_err(|e| {
        std::fs::remove_file(&part_path).ok();
        VbError::Internal(format!("Failed to move the archive into place: {e}"))
    })
}

/// Backup a Docker volume by running a temporary container that mounts
/// the volume and tars its contents.
///
/// The legacy request (`{volume_name, container_name}`), kept with its exact
/// behaviour for an older panel: no stop, no target check, old file name.
pub async fn backup_volume(
    volume_name: &str,
    container_name: &str,
) -> Result<BackupInfo, String> {
    let dest_dir = backup_dir(container_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create backup dir: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("{container_name}-{volume_name}-{timestamp}.tar.gz");
    let filepath = dest_dir.join(&filename);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        safe_command("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{volume_name}:/volume:ro"),
                "-v",
                &format!("{}:/backup", dest_dir.to_str().ok_or("Invalid dir")?),
                "alpine:3.19",
                "tar",
                "czf",
                &format!("/backup/{filename}"),
                "-C",
                "/volume",
                ".",
            ])
            .output(),
    )
    .await
    .map_err(|_| "Volume backup timed out (10 minutes)".to_string())?
    .map_err(|e| format!("Failed to run volume backup: {e}"))?;

    if !output.status.success() {
        std::fs::remove_file(&filepath).ok();
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Volume backup failed: {stderr}"));
    }

    let meta = std::fs::metadata(&filepath)
        .map_err(|e| format!("Failed to read backup metadata: {e}"))?;

    let filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;
    let sha256 = compute_file_sha256(filepath_str).await;

    tracing::info!("Volume backup created: {filename} ({} bytes, hash: {})", meta.len(), sha256.as_deref().unwrap_or("N/A"));

    Ok(BackupInfo {
        filename,
        size_bytes: meta.len(),
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        sha256,
        ..Default::default()
    })
}

// ── Decrypted copies ────────────────────────────────────────────────────────

/// A decrypted archive in a hidden `.part` file next to the encrypted one:
/// removed when dropped (every exit path), swept at startup after a crash.
pub struct PlainTemp {
    pub path: PathBuf,
}

impl PlainTemp {
    /// The file name, for a container that mounts the directory.
    pub fn file_name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    }
}

impl Drop for PlainTemp {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("Failed to remove decrypted archive {}: {e}", self.path.display());
            }
        }
    }
}

/// Check, then decrypt `{dir}/{filename}` (a `.enc`) into a [`PlainTemp`] in
/// the same directory. An app data archive is always encrypted with the
/// integrity tag, so a file without one (or with a wrong tag: tampered, or the
/// wrong passphrase) is refused as [`VbError::Integrity`] before anything else.
pub async fn decrypted_copy(dir: &Path, filename: &str, key: &str) -> Result<PlainTemp, VbError> {
    let src = dir.join(filename);
    match encryption::verify_file(&src, key).await {
        Ok(encryption::TagStatus::Verified) => {}
        Ok(encryption::TagStatus::Legacy) => {
            return Err(VbError::Integrity(
                "This encrypted archive carries no integrity tag, so it cannot be trusted; refusing to restore it"
                    .into(),
            ))
        }
        Err(e) => return Err(VbError::from_crypto(e)),
    }
    let len = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
    check_space(dir, len, "the decrypted archive")?;
    let tmp = PlainTemp { path: dir.join(format!(".{filename}.{:016x}.plain.part", rand::random::<u64>())) };
    encryption::decrypt_file(&src, &tmp.path, key).await.map_err(VbError::from_crypto)?;
    Ok(tmp)
}

/// An archive ready to be read by `tar`: the file itself, or a decrypted copy.
pub struct ReadableArchive {
    /// File name inside the archive's directory.
    pub name: String,
    _plain: Option<PlainTemp>,
}

/// Open `{dir}/{filename}` for reading, decrypting a `.enc` with `key` (shared
/// by verify and drill, so there is one decryption path for app data).
pub async fn readable_archive(dir: &Path, filename: &str, key: Option<&str>) -> Result<ReadableArchive, VbError> {
    if !filename.ends_with(".enc") {
        return Ok(ReadableArchive { name: filename.to_string(), _plain: None });
    }
    let key = key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VbError::BadRequest("Encryption key required for encrypted backup".into()))?;
    let plain = decrypted_copy(dir, filename, key).await?;
    Ok(ReadableArchive { name: plain.file_name(), _plain: Some(plain) })
}

// ── Restore ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RestoreRequest {
    pub kind: TargetKind,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RestoreOutcome {
    pub stopped: Vec<String>,
    pub restarted: Vec<String>,
}

/// Read-only pre-check of an archive on the host, so a corrupt or empty one is
/// refused before any container is stopped. The in-container script below
/// re-checks it before wiping anything.
async fn precheck_archive(path: &Path, timeout: std::time::Duration) -> Result<(), VbError> {
    let out = tokio::time::timeout(
        timeout,
        safe_command("tar").arg("tzf").arg(path).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| VbError::Internal("Reading the archive timed out".into()))?
    .map_err(|e| VbError::Internal(format!("Failed to read the archive: {e}")))?;
    if !out.status.success() {
        return Err(VbError::Integrity("backup archive is corrupt or truncated - data left untouched".into()));
    }
    if out.stdout.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(VbError::Integrity("backup archive is empty - data left untouched".into()));
    }
    Ok(())
}

/// Restore an archive into a volume or a bind directory. The containers that
/// mount it are stopped for the restore and always started again.
pub async fn restore_target(owner_name: String, filename: String, req: RestoreRequest) -> Result<RestoreOutcome, VbError> {
    detached(restore_target_inner(owner_name, filename, req)).await
}

async fn restore_target_inner(owner_name: String, filename: String, req: RestoreRequest) -> Result<RestoreOutcome, VbError> {
    if !is_valid_owner_name(&owner_name) {
        return Err(VbError::BadRequest("Invalid owner name".into()));
    }
    if !is_safe_filename(&filename) {
        return Err(VbError::BadRequest("Invalid backup filename".into()));
    }
    let mount = match req.kind {
        TargetKind::Volume => {
            let name = req.volume_name.clone().unwrap_or_default();
            if !is_valid_volume_name(&name) {
                return Err(VbError::BadRequest("Invalid volume name".into()));
            }
            MountRef::Volume(name)
        }
        TargetKind::Bind => {
            let p = req.source_path.as_deref().unwrap_or_default();
            let path = backup_targets::resolve_restore_path(p, &backup_targets::app_data_roots())
                .map_err(VbError::BadRequest)?;
            MountRef::Bind(path)
        }
    };

    let dir = backup_dir(&owner_name);
    let filepath = dir.join(&filename);
    if !filepath.exists() {
        return Err(VbError::NotFound("Backup file not found".into()));
    }

    let _locks = crate::site_lock::lock_sites(&format!("app-data:{owner_name}"), &mount.lock_key()).await;

    // Everything that can refuse runs before anything is stopped.
    let archive = readable_archive(&dir, &filename, req.encryption_key.as_deref()).await?;
    let len = std::fs::metadata(dir.join(&archive.name)).map(|m| m.len()).unwrap_or(0);
    let timeout = archive_timeout(len);
    precheck_archive(&dir.join(&archive.name), timeout).await?;

    if let MountRef::Bind(path) = &mount {
        std::fs::create_dir_all(path)
            .map_err(|e| VbError::Internal(format!("Failed to create {}: {e}", path.display())))?;
        // Re-check now that it exists: nothing may have swapped a symlink in.
        let again = backup_targets::resolve_restore_path(&path.to_string_lossy(), &backup_targets::app_data_roots())
            .map_err(VbError::BadRequest)?;
        if &again != path {
            return Err(VbError::BadRequest("source_path changed while preparing the restore".into()));
        }
    }

    let report = backup_targets::enumerate_targets().await.map_err(VbError::Internal)?;
    let to_stop: Vec<TargetContainer> = match &mount {
        MountRef::Volume(name) => backup_targets::find_target(&report, TargetKind::Volume, Some(name), None),
        MountRef::Bind(path) => {
            backup_targets::find_target(&report, TargetKind::Bind, None, Some(&path.to_string_lossy()))
        }
    }
    .map(|t| t.containers.iter().filter(|c| c.running).cloned().collect())
    .unwrap_or_default();

    let work = run_restore(mount.clone(), dir.clone(), archive.name.clone(), timeout);
    let outcome = with_stopped(&DockerCli, &to_stop, work).await;
    drop(archive);

    if !outcome.restart_errors.is_empty() {
        let base = match &outcome.result {
            Ok(()) => "The data was restored".to_string(),
            Err(e) => format!("The restore failed ({e})"),
        };
        return Err(VbError::Internal(format!(
            "{base}, but these containers could not be restarted: {}",
            outcome.restart_errors.join("; ")
        )));
    }
    outcome.result?;
    tracing::info!("App data restored: {filename} to {mount:?} (stopped: {:?})", outcome.stopped);
    Ok(RestoreOutcome { stopped: outcome.stopped, restarted: outcome.restarted })
}

/// The restore container. `filename` is the archive inside `dir` (a decrypted
/// temporary for a `.enc`).
async fn run_restore(
    mount: MountRef,
    dir: PathBuf,
    filename: String,
    timeout: std::time::Duration,
) -> Result<(), VbError> {
    let dir_str = dir.to_str().ok_or_else(|| VbError::Internal("Invalid dir".into()))?;
    let output = tokio::time::timeout(
        timeout,
        safe_command("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &mount.docker_arg(false),
                "-v",
                &format!("{dir_str}:/backup:ro"),
                "alpine:3.19",
                "sh",
                "-c",
                // Validate the archive can be read in full BEFORE wiping the live volume.
                // Previously the `rm -rf` ran unconditionally, so a truncated/corrupt/empty
                // backup destroyed the volume and THEN failed the extract - an irreversible
                // drop-then-fail data loss with no rollback. `tar tzf` decompresses and walks
                // the whole archive (catches gzip-CRC/truncation) without touching /volume;
                // only on success do we clear + extract. `filename` is is_safe_filename-
                // validated (alnum + -_. only), or a decrypted temporary named from one,
                // so it is safe to interpolate into the shell.
                //
                // The corruption check above catches a bad archive but NOT a syntactically
                // valid, gzip-CRC-clean archive with zero members - `tar tzf` exits 0 on an
                // empty tar, so the wipe below would still run and leave the volume empty
                // with no rollback. A second, separate `tar tzf | wc -l` re-run (kept apart
                // from the corruption check rather than folded into one pipeline, so an
                // early SIGPIPE on `grep -q`-style short-circuiting can never mask a
                // mid-listing failure as "found a line") requires at least one archive
                // member before the wipe is allowed to proceed.
                &format!("tar tzf /backup/{filename} >/dev/null 2>&1 || {{ echo 'backup archive is corrupt or truncated - volume left untouched' >&2; exit 3; }}; n=$(tar tzf /backup/{filename} 2>/dev/null | wc -l); [ $n -gt 0 ] || {{ echo 'backup archive is empty - volume left untouched' >&2; exit 3; }}; rm -rf /volume/* /volume/..?* /volume/.[!.]* 2>/dev/null; tar xzf /backup/{filename} -C /volume"),
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| VbError::Internal(format!("Volume restore timed out after {} seconds", timeout.as_secs())))?
    .map_err(|e| VbError::Internal(format!("Failed to run volume restore: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if output.status.code() == Some(3) {
            VbError::Integrity(format!("Volume restore failed: {stderr}"))
        } else {
            VbError::Internal(format!("Volume restore failed: {stderr}"))
        });
    }
    Ok(())
}

// ── List / delete ───────────────────────────────────────────────────────────

/// List volume backups for a container.
pub fn list_volume_backups(container_name: &str) -> Result<Vec<BackupInfo>, String> {
    let dir = backup_dir(container_name);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("Read dir error: {e}"))? {
        let entry = entry.map_err(|e| format!("Entry error: {e}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_safe_filename(&name) {
            continue;
        }
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let created = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            })
            .unwrap_or_default();

        backups.push(BackupInfo {
            filename: name,
            size_bytes: size,
            created_at: created,
            sha256: None,
            ..Default::default()
        });
    }

    backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(backups)
}

/// Delete a volume backup file.
pub fn delete_volume_backup(container_name: &str, filename: &str) -> Result<(), String> {
    if !is_safe_filename(filename) {
        return Err("Invalid backup filename".into());
    }

    let filepath = backup_dir(container_name).join(filename);
    if !filepath.exists() {
        return Err("Backup file not found".into());
    }

    std::fs::remove_file(&filepath)
        .map_err(|e| format!("Failed to delete backup: {e}"))?;

    tracing::info!("Volume backup deleted: {filename} for {container_name}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct Fake {
        log: Arc<Mutex<Vec<String>>>,
        fail_stop: Option<String>,
        fail_start: Option<String>,
    }

    impl ContainerControl for Fake {
        async fn stop(&self, id: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("stop {id}"));
            if self.fail_stop.as_deref() == Some(id) { Err("refused".into()) } else { Ok(()) }
        }
        async fn start(&self, id: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(format!("start {id}"));
            if self.fail_start.as_deref() == Some(id) { Err("refused".into()) } else { Ok(()) }
        }
    }

    fn cs(ids: &[&str]) -> Vec<TargetContainer> {
        ids.iter().map(|i| TargetContainer { id: i.to_string(), name: format!("n-{i}"), running: true }).collect()
    }

    fn log(f: &Fake) -> Vec<String> {
        f.log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn containers_are_restarted_after_success() {
        let f = Fake::default();
        let l = f.log.clone();
        let out = with_stopped(&f, &cs(&["a", "b"]), async move {
            l.lock().unwrap().push("work".into());
            Ok::<_, VbError>(7)
        })
        .await;
        assert_eq!(out.result, Ok(7));
        assert_eq!(log(&f), ["stop a", "stop b", "work", "start b", "start a"]);
        assert_eq!(out.stopped, ["n-a", "n-b"]);
        assert_eq!(out.restarted, ["n-a", "n-b"]);
        assert!(out.restart_errors.is_empty());
    }

    #[tokio::test]
    async fn containers_are_restarted_when_the_work_fails() {
        let f = Fake::default();
        let out = with_stopped(&f, &cs(&["a"]), async { Err::<(), _>(VbError::Integrity("bad".into())) }).await;
        assert_eq!(out.result, Err(VbError::Integrity("bad".into())));
        assert_eq!(log(&f), ["stop a", "start a"]);
        assert_eq!(out.restarted, ["n-a"]);
    }

    #[tokio::test]
    async fn containers_are_restarted_when_the_work_panics() {
        let f = Fake::default();
        let out = with_stopped(&f, &cs(&["a", "b"]), async {
            if true {
                panic!("boom");
            }
            Ok::<(), VbError>(())
        })
        .await;
        assert!(matches!(out.result, Err(VbError::Internal(_))));
        assert_eq!(log(&f), ["stop a", "stop b", "start b", "start a"]);
    }

    #[tokio::test]
    async fn a_failed_stop_skips_the_work_and_restarts_the_ones_already_stopped() {
        let f = Fake { fail_stop: Some("b".into()), ..Default::default() };
        let l = f.log.clone();
        let out = with_stopped(&f, &cs(&["a", "b", "c"]), async move {
            l.lock().unwrap().push("work".into());
            Ok::<(), VbError>(())
        })
        .await;
        assert!(matches!(out.result, Err(VbError::Internal(ref m)) if m.contains("n-b")));
        assert_eq!(log(&f), ["stop a", "stop b", "start a"]);
        assert_eq!(out.stopped, ["n-a"]);
    }

    #[tokio::test]
    async fn a_failed_restart_is_reported_and_the_others_still_start() {
        let f = Fake { fail_start: Some("a".into()), ..Default::default() };
        let out = with_stopped(&f, &cs(&["a", "b"]), async { Ok::<(), VbError>(()) }).await;
        assert_eq!(out.result, Ok(()));
        assert_eq!(log(&f), ["stop a", "stop b", "start b", "start a"]);
        assert_eq!(out.restarted, ["n-b"]);
        assert_eq!(out.restart_errors, ["n-a: refused"]);
    }

    #[tokio::test]
    async fn nothing_to_stop_still_runs_the_work() {
        let f = Fake::default();
        let out = with_stopped(&f, &[], async { Ok::<u8, VbError>(1) }).await;
        assert_eq!(out.result, Ok(1));
        assert!(log(&f).is_empty());
    }

    #[test]
    fn filenames() {
        for ok in [
            "demo-v-demo_pgdata-20261119-033005.tar.gz",
            "demo-b-uploads-1a2b3c4d-20261119-033005.tar.gz.enc",
            "app-vol-20250101-000000.tar.gz",
            "my.app-v-my.vol-20261119-033005.tar.gz",
        ] {
            assert!(is_safe_filename(ok), "{ok}");
        }
        for bad in [
            "",
            "../x.tar.gz",
            "a/b.tar.gz",
            ".demo.tar.gz.part",
            ".x.tar.gz",
            "x.tar",
            "x.tar.gz.part",
            "x.enc",
            "a..b.tar.gz",
            "a b.tar.gz",
            "a;rm.tar.gz",
        ] {
            assert!(!is_safe_filename(bad), "{bad}");
        }
    }

    #[test]
    fn mount_refs() {
        assert_eq!(MountRef::Volume("demo_pgdata".into()).docker_arg(true), "demo_pgdata:/volume:ro");
        assert_eq!(
            MountRef::Bind(PathBuf::from("/var/lib/dockpanel/compose/demo/up")).docker_arg(false),
            "/var/lib/dockpanel/compose/demo/up:/volume"
        );
    }

    #[test]
    fn space_is_twice_the_data() {
        assert_eq!(space_needed(10), 20);
        assert_eq!(space_needed(u64::MAX), u64::MAX);
    }

    #[test]
    fn crypto_errors_map_to_422_or_500() {
        assert!(matches!(
            VbError::from_crypto("Backup integrity check failed - the file may be corrupted or tampered with".into()),
            VbError::Integrity(_)
        ));
        assert!(matches!(VbError::from_crypto("Failed to run openssl: x".into()), VbError::Internal(_)));
    }

    fn scratch() -> PathBuf {
        let p = std::env::temp_dir().join(format!("dp-vb-test-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn an_encrypted_archive_is_decrypted_to_a_hidden_temporary_that_goes_away() {
        let d = scratch();
        std::fs::write(d.join("x.tar.gz"), b"not really a tarball but bytes").unwrap();
        encryption::encrypt_file(&d.join("x.tar.gz"), &d.join("x.tar.gz.enc"), "k1").await.unwrap();
        {
            let a = readable_archive(&d, "x.tar.gz.enc", Some("k1")).await.unwrap();
            assert!(a.name.starts_with(".x.tar.gz.enc.") && a.name.ends_with(".plain.part"), "{}", a.name);
            assert_eq!(std::fs::read(d.join(&a.name)).unwrap(), b"not really a tarball but bytes");
        }
        let left: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left.len(), 2, "{left:?}");

        // Wrong passphrase: 422, and nothing left behind.
        let e = readable_archive(&d, "x.tar.gz.enc", Some("k2")).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(_)), "{e:?}");
        // Missing key: 400.
        let e = readable_archive(&d, "x.tar.gz.enc", None).await.err().unwrap();
        assert!(matches!(e, VbError::BadRequest(_)), "{e:?}");
        // A flipped byte: 422.
        let mut b = std::fs::read(d.join("x.tar.gz.enc")).unwrap();
        b[20] ^= 1;
        std::fs::write(d.join("y.tar.gz.enc"), &b).unwrap();
        let e = readable_archive(&d, "y.tar.gz.enc", Some("k1")).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(_)), "{e:?}");
        // Not encrypted at all: 422.
        std::fs::write(d.join("z.tar.gz.enc"), vec![7u8; 4096]).unwrap();
        let e = readable_archive(&d, "z.tar.gz.enc", Some("k1")).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(_)), "{e:?}");
        // Plain archives pass through untouched.
        let a = readable_archive(&d, "x.tar.gz", None).await.unwrap();
        assert_eq!(a.name, "x.tar.gz");
        let left = std::fs::read_dir(&d).unwrap().count();
        assert_eq!(left, 4);
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn an_encrypted_archive_without_integrity_tag_is_refused() {
        let d = scratch();
        let legacy: &[u8] = include_bytes!("../../tests/fixtures/encryption/legacy.sql.enc");
        std::fs::write(d.join("old.tar.gz.enc"), legacy).unwrap();
        let e = readable_archive(&d, "old.tar.gz.enc", Some("fixture-test-passphrase-not-a-secret"))
            .await
            .err()
            .unwrap();
        assert!(matches!(e, VbError::Integrity(ref m) if m.contains("no integrity tag")), "{e:?}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn corrupt_and_empty_archives_are_refused_before_any_stop() {
        let d = scratch();
        std::fs::write(d.join("bad.tar.gz"), b"garbage").unwrap();
        let e = precheck_archive(&d.join("bad.tar.gz"), std::time::Duration::from_secs(30)).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(ref m) if m.contains("corrupt")), "{e:?}");
        // A valid, empty tar.gz.
        let empty = std::process::Command::new("tar")
            .args(["czf", &d.join("empty.tar.gz").to_string_lossy(), "-T", "/dev/null"])
            .status()
            .unwrap();
        assert!(empty.success());
        let e = precheck_archive(&d.join("empty.tar.gz"), std::time::Duration::from_secs(30)).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(ref m) if m.contains("empty")), "{e:?}");
        // A real one.
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("src/f"), b"x").unwrap();
        let ok = std::process::Command::new("tar")
            .args(["czf", &d.join("ok.tar.gz").to_string_lossy(), "-C", &d.join("src").to_string_lossy(), "."])
            .status()
            .unwrap();
        assert!(ok.success());
        precheck_archive(&d.join("ok.tar.gz"), std::time::Duration::from_secs(30)).await.unwrap();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn listing_shows_plain_and_encrypted_archives_but_no_temporaries() {
        // `list_volume_backups` filters with `is_safe_filename`.
        let names = [
            "demo-v-x-20261119-033005.tar.gz",
            "demo-v-x-20261119-033006.tar.gz.enc",
            ".demo-v-x-20261119-033007.tar.gz.part",
            ".demo-v-x-20261119-033006.tar.gz.enc.0123456789abcdef.plain.part",
            "notes.txt",
        ];
        let shown: Vec<_> = names.iter().filter(|n| is_safe_filename(n)).collect();
        assert_eq!(shown, [&names[0], &names[1]]);
    }
}
