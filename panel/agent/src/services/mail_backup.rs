//! Mail backups (lot 3): one archive per mailbox, plus an always-encrypted
//! "config" archive (the panel's manifest of domains, accounts and aliases,
//! the DKIM keys, and the Postfix/Dovecot files kept for reference).
//!
//! Files live in `/var/backups/dockpanel/mail/` (0700, inside the agent's
//! ReadWritePaths, so `/backups/upload` can send them away):
//! * `mail-{domain}-{local_b64url}-{%Y%m%d-%H%M%S}.tar.gz[.enc]`, where the
//!   local part is base64url without padding: `_`, `-`, `.` and `+` in it can
//!   never be confused with the separators, and the archive of `a_b@x.com` is
//!   found by building its exact prefix, never by splitting a name;
//! * `mailcfg-{stamp}.tar.gz.enc`.
//!
//! A mailbox archive holds exactly `{local}/` (the maildir, `dovecot.index*`
//! excluded since Dovecot rebuilds them). It is made hot: maildir delivery is
//! atomic renames (tmp -> new -> cur), so `tar --warning=no-file-changed
//! --ignore-failed-read` and its exit code 1 ("some files changed") are a
//! consistent copy, not a failure.
//!
//! A restore checks that every member is under `{local}/` (no absolute path,
//! no `..`), extracts into a staging directory next to the maildir
//! (`/var/vmail/{domain}/.restore-*`, same filesystem, so every move below is
//! an atomic rename), refuses a symbolic link or a special file in what came
//! out, then merges (default: messages already present, by maildir base name,
//! are kept as they are) or replaces (the current maildir is moved aside and
//! only removed once the new one is in place and owned by vmail), and finally
//! runs `doveadm force-resync`.
//!
//! Plaintext only ever exists as a hidden `.part` file (0600), which the agent
//! sweeps at startup; nothing in here logs a key, a manifest or a hash.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Serialize;

use crate::safe_cmd::safe_command;
use crate::services::backups::compute_file_sha256;
use crate::services::encryption;
use crate::services::volume_backup::{self, PlainTemp, VbError};

pub const MAIL_BACKUP_DIR: &str = "/var/backups/dockpanel/mail";
/// Where the manual mailbox backups went before lot 3 (still listed, restorable
/// and deletable).
pub const LEGACY_MAIL_BACKUP_DIR: &str = "/var/lib/dockpanel/mail-backups";
pub const VMAIL_DIR: &str = "/var/vmail";
const MAX_KEY_LEN: usize = 1024;
/// Largest manifest or zone document read back into memory.
const MAX_DOC_BYTES: u64 = 256 * 1024 * 1024;

// ── Shared with dns_backup ──────────────────────────────────────────────────

/// `%Y%m%d-%H%M%S` (UTC), the stamp `/backups/prune` `stamp_only` expects.
pub fn stamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y%m%d-%H%M%S").to_string()
}

pub fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 15 && b[8] == b'-' && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
}

/// Strip `-{stamp}{suffix}` from the end of `name` for one of `suffixes`.
pub fn strip_stamp_suffix<'a>(name: &'a str, suffixes: &[&str]) -> Option<&'a str> {
    suffixes.iter().find_map(|suf| {
        let rest = name.strip_suffix(suf)?;
        if rest.len() < 16 || !rest.is_char_boundary(rest.len() - 16) {
            return None;
        }
        let (head, tail) = rest.split_at(rest.len() - 16);
        let st = tail.strip_prefix('-')?;
        is_stamp(st).then_some(head)
    })
}

/// A backup file name as the agent writes them: `[A-Za-z0-9._-]`, not hidden
/// (temporaries start with `.`), no `..`, at most 255 bytes.
pub fn is_safe_backup_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// An optional encryption key: empty means none.
pub fn optional_key(k: &Option<String>) -> Result<Option<String>, VbError> {
    match k.as_deref() {
        None | Some("") => Ok(None),
        Some(k) if k.len() > MAX_KEY_LEN => Err(VbError::BadRequest("Encryption key is too long".into())),
        Some(k) => Ok(Some(k.to_string())),
    }
}

/// A key that must be there: the mail config and the DNS snapshot are always
/// encrypted (decision 8), so a request without one is refused before anything
/// on the host is read.
pub fn require_key(k: &Option<String>, what: &str) -> Result<String, VbError> {
    optional_key(k)?.ok_or_else(|| VbError::BadRequest(format!("encryption_key is required: {what} is always encrypted")))
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), VbError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| VbError::Internal(format!("Failed to create {}: {e}", dir.display())))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| VbError::Internal(format!("Failed to secure {}: {e}", dir.display())))
}

/// A hidden `.{name}.part` file (0600) removed on drop unless kept: the only
/// place plaintext lives, and what the startup sweep removes after a crash.
pub struct PartFile {
    pub path: PathBuf,
}

impl PartFile {
    pub fn create(dir: &Path, name: &str) -> Result<Self, VbError> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.join(format!(".{name}.part"));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| VbError::Internal(format!("Failed to create {}: {e}", path.display())))?;
        Ok(Self { path })
    }

    pub fn file(&self) -> Result<std::fs::File, VbError> {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| VbError::Internal(format!("Failed to open {}: {e}", self.path.display())))
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("Failed to remove temporary {}: {e}", self.path.display());
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub encrypted: bool,
}

/// Refuse a name already taken (in clear or encrypted) this very second.
pub fn ensure_free_name(dir: &Path, name: &str) -> Result<(), VbError> {
    if dir.join(name).exists() || dir.join(format!("{name}.enc")).exists() {
        return Err(VbError::Conflict("A backup with this name was made this second, retry".into()));
    }
    Ok(())
}

/// Turn a finished plaintext `.part` into `{dir}/{name}` (no key) or
/// `{dir}/{name}.enc` (key), and describe it.
pub async fn finalize(part: PartFile, dir: &Path, name: &str, key: Option<&str>) -> Result<ArchiveInfo, VbError> {
    let (filename, path) = match key {
        Some(k) => {
            let filename = format!("{name}.enc");
            let dst = dir.join(&filename);
            encryption::encrypt_file(&part.path, &dst, k)
                .await
                .map_err(|e| VbError::Internal(format!("Encryption failed: {e}")))?;
            drop(part);
            (filename, dst)
        }
        None => {
            let dst = dir.join(name);
            std::fs::rename(&part.path, &dst)
                .map_err(|e| VbError::Internal(format!("Failed to move the archive into place: {e}")))?;
            (name.to_string(), dst)
        }
    };
    let size_bytes = std::fs::metadata(&path)
        .map_err(|e| VbError::Internal(format!("Failed to read backup metadata: {e}")))?
        .len();
    let Some(sha256) = compute_file_sha256(&path.to_string_lossy()).await else {
        std::fs::remove_file(&path).ok();
        return Err(VbError::Internal("Failed to hash the archive".into()));
    };
    Ok(ArchiveInfo { filename, size_bytes, sha256, encrypted: key.is_some() })
}

/// The directory holding `filename`: the family's own directory, else the
/// restore inbox `/backups/download` fills (a copy fetched from a remote
/// destination). 404 when it is in neither.
pub fn locate(dir: &Path, filename: &str) -> Result<PathBuf, VbError> {
    if !is_safe_backup_filename(filename) {
        return Err(VbError::BadRequest("Invalid backup filename".into()));
    }
    let inbox = Path::new(crate::services::remote_backup::RESTORE_INBOX);
    for d in [dir, inbox] {
        let md = std::fs::symlink_metadata(d.join(filename));
        if md.is_ok_and(|m| m.file_type().is_file()) {
            return Ok(d.to_path_buf());
        }
    }
    Err(VbError::NotFound("Backup file not found".into()))
}

/// A file ready to be read: itself, or a verified decrypted copy (an encrypted
/// backup must carry a valid integrity tag; the wrong passphrase is a 422).
pub struct Readable {
    pub path: PathBuf,
    _plain: Option<PlainTemp>,
}

pub async fn readable(dir: &Path, filename: &str, key: Option<&str>) -> Result<Readable, VbError> {
    if !filename.ends_with(".enc") {
        return Ok(Readable { path: dir.join(filename), _plain: None });
    }
    let key = key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VbError::BadRequest("encryption_key is required for an encrypted backup".into()))?;
    let plain = volume_backup::decrypted_copy(dir, filename, key).await?;
    Ok(Readable { path: plain.path.clone(), _plain: Some(plain) })
}

/// Read a small document (manifest, zone) into memory.
pub fn read_doc(path: &Path) -> Result<Vec<u8>, VbError> {
    let len = std::fs::metadata(path).map_err(|e| VbError::Internal(format!("Failed to read the backup: {e}")))?.len();
    if len > MAX_DOC_BYTES {
        return Err(VbError::Integrity("The backup document is too large".into()));
    }
    std::fs::read(path).map_err(|e| VbError::Internal(format!("Failed to read the backup: {e}")))
}

/// The visible regular files of `dir` (hidden temporaries and anything else
/// skipped), newest first: `(name, size, modified RFC 3339)`.
pub fn list_files(dir: &Path) -> Vec<(String, u64, String)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<(String, u64, String, std::time::SystemTime)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                return None;
            }
            let md = e.metadata().ok()?;
            if !md.is_file() || e.file_type().ok()?.is_symlink() {
                return None;
            }
            let modified = md.modified().unwrap_or(std::time::UNIX_EPOCH);
            let dt: chrono::DateTime<chrono::Utc> = modified.into();
            Some((name, md.len(), dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true), modified))
        })
        .collect();
    out.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.0.cmp(&a.0)));
    out.into_iter().map(|(n, s, m, _)| (n, s, m)).collect()
}

/// Run a tar (or any short-lived host tool) with a timeout and kill on drop.
async fn run(cmd: &mut tokio::process::Command, timeout: std::time::Duration, what: &str) -> Result<std::process::Output, VbError> {
    tokio::time::timeout(timeout, cmd.kill_on_drop(true).output())
        .await
        .map_err(|_| VbError::Internal(format!("{what} timed out after {} seconds", timeout.as_secs())))?
        .map_err(|e| VbError::Internal(format!("{what} could not run: {e}")))
}

pub fn stderr_of(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).trim().chars().take(500).collect()
}

// ── Names ───────────────────────────────────────────────────────────────────

/// A mail domain as a path component: a valid ASCII (IDN as punycode) domain.
pub fn is_valid_mail_domain(d: &str) -> bool {
    !d.contains("..") && crate::routes::is_valid_domain(d) && d == d.to_ascii_lowercase()
}

/// A local part as a path component and a doveadm user: letters and digits
/// (any script), `.`, `_`, `-`, `+`; not only dots; at most 64 bytes. No `/`,
/// no `*` or `?` (doveadm user masks), no whitespace or control character.
pub fn is_valid_local(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 64
        && l.chars().any(|c| c != '.')
        && l.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

pub fn encode_local(local: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(local.as_bytes())
}

/// The local part a base64url segment encodes, only for the canonical
/// encoding of a valid local part.
pub fn decode_local(s: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()?;
    let local = String::from_utf8(bytes).ok()?;
    (is_valid_local(&local) && encode_local(&local) == s).then_some(local)
}

/// `mail-{domain}-{local_b64url}-`: the name prefix of one mailbox's archives
/// (also the remote retention `name_prefix`).
pub fn mailbox_prefix(domain: &str, local: &str) -> String {
    format!("mail-{domain}-{}-", encode_local(local))
}

pub fn mailbox_archive_name(domain: &str, local: &str, stamp: &str) -> String {
    format!("{}{stamp}.tar.gz", mailbox_prefix(domain, local))
}

const MAILBOX_SUFFIXES: [&str; 2] = [".tar.gz.enc", ".tar.gz"];

/// Whether `name` is an archive of exactly this mailbox (prefix + stamp +
/// suffix). Never parses: the prefix is built from the address.
pub fn is_archive_of(name: &str, domain: &str, local: &str) -> bool {
    let prefix = mailbox_prefix(domain, local);
    name.strip_prefix(&prefix)
        .is_some_and(|rest| MAILBOX_SUFFIXES.iter().any(|s| rest.strip_suffix(s).is_some_and(is_stamp)))
}

/// Every `(domain, local)` a mailbox archive name can be read as. Domains and
/// base64url both contain `-`, so a name may in theory have more than one
/// reading (an IDN TLD such as `xn--p1ai` ends in a label with dashes); the
/// listing reports the address only when exactly one reading remains.
pub fn parse_mailbox_archive_name(name: &str) -> Vec<(String, String)> {
    let Some(rest) = name.strip_prefix("mail-") else { return Vec::new() };
    let Some(middle) = strip_stamp_suffix(rest, &MAILBOX_SUFFIXES) else { return Vec::new() };
    middle
        .match_indices('-')
        .filter_map(|(i, _)| {
            let (d, b) = (&middle[..i], &middle[i + 1..]);
            if !is_valid_mail_domain(d) {
                return None;
            }
            decode_local(b).map(|l| (d.to_string(), l))
        })
        .collect()
}

pub fn config_archive_name(stamp: &str) -> String {
    format!("mailcfg-{stamp}.tar.gz")
}

pub fn is_config_archive_name(name: &str) -> bool {
    name.strip_prefix("mailcfg-")
        .and_then(|r| r.strip_suffix(".tar.gz.enc"))
        .is_some_and(is_stamp)
}

/// A pre-lot-3 manual archive `{user}_{domain}_{unix}.tar.gz` of this address.
pub fn is_legacy_archive_of(name: &str, domain: &str, local: &str) -> bool {
    name.strip_prefix(&format!("{local}_{domain}_"))
        .and_then(|r| r.strip_suffix(".tar.gz"))
        .is_some_and(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
}

// ── Archive contents ────────────────────────────────────────────────────────

/// Check a `tar -t` listing: every member is `{local}`, `{local}/` or under
/// `{local}/`, none absolute, none with a `..` component, at least one.
pub fn check_member_names(listing: &str, local: &str) -> Result<usize, String> {
    let root = format!("{local}/");
    let mut n = 0;
    for name in listing.lines() {
        if name.is_empty() {
            continue;
        }
        if name.starts_with('/') {
            return Err(format!("The archive holds an absolute path ({})", name.chars().take(120).collect::<String>()));
        }
        if name.split('/').any(|c| c == "..") {
            return Err("The archive holds a path with '..'".into());
        }
        if !(name == local || name == root || name.starts_with(&root)) {
            return Err(format!(
                "The archive holds files outside {root} ({}): it is not a backup of this mailbox",
                name.chars().take(120).collect::<String>()
            ));
        }
        n += 1;
    }
    if n == 0 {
        return Err("The archive is empty".into());
    }
    Ok(n)
}

/// After extraction into `staging`: exactly one entry, `{local}`, a directory,
/// and nothing under it but directories and regular files (no symbolic link,
/// no device, no FIFO).
pub fn check_extracted_tree(staging: &Path, local: &str) -> Result<(), String> {
    let top: Vec<String> = std::fs::read_dir(staging)
        .map_err(|e| format!("Failed to read the staging directory: {e}"))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    if top != [local.to_string()] {
        return Err("The archive did not extract to the mailbox directory alone".into());
    }
    for entry in walkdir::WalkDir::new(staging.join(local)).follow_links(false) {
        let entry = entry.map_err(|e| format!("Failed to walk the extracted mailbox: {e}"))?;
        let ft = entry.file_type();
        if ft.is_symlink() {
            return Err("The archive holds a symbolic link: refused".into());
        }
        if !ft.is_dir() && !ft.is_file() {
            return Err("The archive holds a special file: refused".into());
        }
    }
    Ok(())
}

/// The part of a maildir file name that identifies the message: everything
/// before the `:2,FLAGS` info (a flag change renames `id:2,` to `id:2,S`).
pub fn base_of(name: &str) -> &str {
    name.split_once(':').map(|(b, _)| b).unwrap_or(name)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MergeStats {
    /// Messages moved in from the backup.
    pub restored: u64,
    /// Messages of the backup already present (same base name), left as they are.
    pub skipped: u64,
}

fn message_bases(folder: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    for sub in ["cur", "new"] {
        if let Ok(rd) = std::fs::read_dir(folder.join(sub)) {
            for e in rd.flatten() {
                set.insert(base_of(&e.file_name().to_string_lossy()).to_string());
            }
        }
    }
    set
}

fn ensure_dir(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!("{} exists and is not a directory", p.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(p),
        Err(e) => Err(e),
    }
}

/// Merge the maildir tree `src` into `dst` by renames (same filesystem):
/// * a message (file in `cur/` or `new/`) is moved in unless a message with
///   the same base name is already in `cur/` or `new/` of that folder;
/// * `tmp/` is never copied (in-flight deliveries), only created;
/// * any other file (`dovecot-uidlist`, `subscriptions`, ...) is moved in when
///   absent, or when the backup's copy is newer; the current one is kept
///   otherwise. `force-resync` reconciles the indexes afterwards.
pub fn merge_tree(src: &Path, dst: &Path) -> std::io::Result<MergeStats> {
    let mut st = MergeStats::default();
    merge_dir(src, dst, &mut st)?;
    Ok(st)
}

fn merge_dir(src: &Path, dst: &Path, st: &mut MergeStats) -> std::io::Result<()> {
    ensure_dir(dst)?;
    let mut bases: Option<HashSet<String>> = None;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name();
        let name_s = name.to_string_lossy();
        let ft = e.file_type()?;
        let (s, d) = (src.join(&name), dst.join(&name));
        if ft.is_dir() {
            match name_s.as_ref() {
                "tmp" => ensure_dir(&d)?,
                "cur" | "new" => {
                    let set = bases.get_or_insert_with(|| message_bases(dst));
                    merge_messages(&s, &d, set, st)?;
                }
                _ => merge_dir(&s, &d, st)?,
            }
        } else if ft.is_file() {
            merge_plain_file(&s, &d)?;
        }
    }
    Ok(())
}

fn merge_messages(src: &Path, dst: &Path, bases: &mut HashSet<String>, st: &mut MergeStats) -> std::io::Result<()> {
    ensure_dir(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let name = e.file_name();
        let base = base_of(&name.to_string_lossy()).to_string();
        if bases.contains(&base) {
            st.skipped += 1;
            continue;
        }
        std::fs::rename(e.path(), dst.join(&name))?;
        bases.insert(base);
        st.restored += 1;
    }
    Ok(())
}

fn merge_plain_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dst) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::rename(src, dst),
        Err(e) => Err(e),
        Ok(m) if m.is_file() => {
            let newer = std::fs::metadata(src)?.modified()? > m.modified()?;
            if newer { std::fs::rename(src, dst) } else { Ok(()) }
        }
        Ok(_) => Ok(()),
    }
}

// ── Requests ────────────────────────────────────────────────────────────────

/// Body of `POST /mail/archive`. No `Debug`: it carries the key.
#[derive(serde::Deserialize)]
pub struct MailArchiveRequest {
    pub kind: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub local: Option<String>,
    #[serde(default)]
    pub manifest: Option<serde_json::Value>,
    #[serde(default)]
    pub encryption_key: Option<String>,
}

/// Body of `POST /mail/restore`: the lot 3 shape (`kind` present) or the
/// pre-lot-3 one (`{email, file}`). No `Debug`: it carries the key.
#[derive(serde::Deserialize)]
pub struct MailRestoreRequest {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub local: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub encryption_key: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    Merge,
    Replace,
}

impl RestoreMode {
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s {
            None | Some("") | Some("merge") => Some(Self::Merge),
            Some("replace") => Some(Self::Replace),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub domain: String,
    pub local: String,
}

impl Mailbox {
    pub fn new(domain: Option<&str>, local: Option<&str>) -> Result<Self, VbError> {
        let domain = domain.unwrap_or("").trim().to_ascii_lowercase();
        let local = local.unwrap_or("").trim().to_string();
        if !is_valid_mail_domain(&domain) {
            return Err(VbError::BadRequest("Invalid domain".into()));
        }
        if !is_valid_local(&local) {
            return Err(VbError::BadRequest("Invalid local part".into()));
        }
        Ok(Self { domain, local })
    }

    pub fn from_email(email: &str) -> Result<Self, VbError> {
        let (l, d) = email.trim().split_once('@').ok_or_else(|| VbError::BadRequest("Invalid email".into()))?;
        Self::new(Some(d), Some(l))
    }

    pub fn addr(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }

    pub fn domain_dir(&self) -> PathBuf {
        Path::new(VMAIL_DIR).join(&self.domain)
    }

    pub fn maildir(&self) -> PathBuf {
        self.domain_dir().join(&self.local)
    }

    fn lock_key(&self) -> String {
        format!("mail:{}", self.addr())
    }
}

/// What a valid `/mail/archive` body asks for.
pub enum ArchivePlan {
    Mailbox { mailbox: Mailbox, key: Option<String> },
    Config { manifest: serde_json::Value, key: String },
}

/// Validate a `/mail/archive` body without touching the host.
pub fn plan_archive(req: MailArchiveRequest) -> Result<ArchivePlan, VbError> {
    match req.kind.as_str() {
        "mailbox" => Ok(ArchivePlan::Mailbox {
            mailbox: Mailbox::new(req.domain.as_deref(), req.local.as_deref())?,
            key: optional_key(&req.encryption_key)?,
        }),
        "config" => {
            let key = require_key(&req.encryption_key, "the mail config")?;
            let manifest = req.manifest.filter(|m| m.is_object()).ok_or_else(|| VbError::BadRequest("manifest must be a JSON object".into()))?;
            Ok(ArchivePlan::Config { manifest, key })
        }
        _ => Err(VbError::BadRequest("kind must be 'mailbox' or 'config'".into())),
    }
}

/// What a valid `/mail/restore` body asks for.
pub enum RestorePlan {
    Mailbox { mailbox: Mailbox, filename: String, mode: RestoreMode, key: Option<String> },
    Config { filename: String, key: String },
    /// `{email, file}` from a pre-lot-3 panel: `file` is a full path in the
    /// legacy directory or in the new one.
    Legacy { mailbox: Mailbox, dir: PathBuf, filename: String },
}

pub fn plan_restore(req: MailRestoreRequest) -> Result<RestorePlan, VbError> {
    let Some(kind) = req.kind.as_deref() else {
        let mailbox = Mailbox::from_email(req.email.as_deref().unwrap_or(""))?;
        let file = req.file.as_deref().unwrap_or("");
        let (dir, filename) = file.rsplit_once('/').ok_or_else(|| VbError::BadRequest("Invalid backup file path".into()))?;
        if !is_safe_backup_filename(filename) {
            return Err(VbError::BadRequest("Invalid backup file path".into()));
        }
        let owned = match dir {
            LEGACY_MAIL_BACKUP_DIR => is_legacy_archive_of(filename, &mailbox.domain, &mailbox.local),
            MAIL_BACKUP_DIR => is_archive_of(filename, &mailbox.domain, &mailbox.local),
            _ => return Err(VbError::BadRequest("Invalid backup file path".into())),
        };
        if !owned {
            return Err(VbError::BadRequest("This backup is not an archive of this mailbox".into()));
        }
        return Ok(RestorePlan::Legacy { mailbox, dir: PathBuf::from(dir), filename: filename.to_string() });
    };
    let filename = req.filename.unwrap_or_default();
    if !is_safe_backup_filename(&filename) {
        return Err(VbError::BadRequest("Invalid backup filename".into()));
    }
    match kind {
        "mailbox" => {
            let mailbox = Mailbox::new(req.domain.as_deref(), req.local.as_deref())?;
            if !is_archive_of(&filename, &mailbox.domain, &mailbox.local) {
                return Err(VbError::BadRequest("This backup is not an archive of this mailbox".into()));
            }
            let mode = RestoreMode::parse(req.mode.as_deref())
                .ok_or_else(|| VbError::BadRequest("mode must be 'merge' or 'replace'".into()))?;
            let key = optional_key(&req.encryption_key)?;
            if filename.ends_with(".enc") && key.is_none() {
                return Err(VbError::BadRequest("encryption_key is required for an encrypted backup".into()));
            }
            Ok(RestorePlan::Mailbox { mailbox, filename, mode, key })
        }
        "config" => {
            if !is_config_archive_name(&filename) {
                return Err(VbError::BadRequest("Not a mail config backup".into()));
            }
            Ok(RestorePlan::Config { filename, key: require_key(&req.encryption_key, "the mail config")? })
        }
        _ => Err(VbError::BadRequest("kind must be 'mailbox' or 'config'".into())),
    }
}

// ── Host ────────────────────────────────────────────────────────────────────

/// The mail stack counts as installed when both Postfix and Dovecot are.
pub fn mail_stack_present(postfix: bool, dovecot: bool) -> bool {
    postfix && dovecot
}

pub async fn mail_installed() -> bool {
    use crate::services::pkg::is_installed;
    mail_stack_present(is_installed("postfix").await, is_installed("dovecot-imapd").await)
}

/// `skipped` reason of `/mail/archive` for a mailbox without a maildir yet.
pub const NO_MAILDIR: &str = "no_maildir";

/// 404 before a job starts when the maildir does not exist (never received
/// mail, or a wrong address).
pub fn require_maildir(mailbox: &Mailbox) -> Result<(), VbError> {
    match std::fs::symlink_metadata(mailbox.maildir()) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(VbError::BadRequest("The mailbox path is not a directory".into())),
        Err(_) => Err(VbError::NotFound("Mailbox directory not found".into())),
    }
}

// ── Mailbox archive ─────────────────────────────────────────────────────────

/// Archive one mailbox (`tar` of `{local}/`, hot, `dovecot.index*` excluded),
/// optionally encrypted. Shared by the job route and the manual `/mail/backup`.
pub async fn archive_mailbox(mailbox: Mailbox, key: Option<String>) -> Result<ArchiveInfo, VbError> {
    let _lock = crate::site_lock::lock_site(&mailbox.lock_key()).await;
    require_maildir(&mailbox)?;
    let dir = Path::new(MAIL_BACKUP_DIR);
    ensure_private_dir(dir)?;
    let maildir = mailbox.maildir();
    let size = volume_backup::du_bytes(&maildir.to_string_lossy()).await.map_err(VbError::Internal)?;
    volume_backup::check_space(dir, volume_backup::space_needed(size), "this mailbox archive")?;

    let name = mailbox_archive_name(&mailbox.domain, &mailbox.local, &stamp(chrono::Utc::now()));
    ensure_free_name(dir, &name)?;
    let part = PartFile::create(dir, &name)?;
    let domain_dir = mailbox.domain_dir();
    let out = run(
        safe_command("tar")
            .arg("--warning=no-file-changed")
            .arg("--ignore-failed-read")
            .arg("--exclude=dovecot.index*")
            .arg("-czf")
            .arg(&part.path)
            .arg("-C")
            .arg(&domain_dir)
            .arg("--")
            .arg(&mailbox.local),
        volume_backup::archive_timeout(size),
        "Mailbox backup",
    )
    .await?;
    // 1 = "some files differ" (changed or vanished while read): expected on a
    // live maildir. 2 and up is a real failure.
    if !matches!(out.status.code(), Some(0) | Some(1)) {
        return Err(VbError::Internal(format!("Mailbox backup failed: {}", stderr_of(&out))));
    }
    let info = finalize(part, dir, &name, key.as_deref()).await?;
    tracing::info!(
        "Mailbox backed up: {} -> {} ({} bytes, encrypted: {})",
        mailbox.addr(),
        info.filename,
        info.size_bytes,
        info.encrypted
    );
    Ok(info)
}

// ── Config archive ──────────────────────────────────────────────────────────

/// Host files archived with the manifest, for reference only: a restore never
/// writes them back (the panel regenerates Postfix/Dovecot maps with
/// `/mail/sync` and reimports DKIM keys through `/mail/dkim/import`).
const CONFIG_FILES: [&str; 6] = [
    "etc/dockpanel/dkim",
    "etc/dockpanel/opendkim.conf",
    "etc/postfix/main.cf",
    "etc/postfix/master.cf",
    "etc/dovecot/dovecot.conf",
    "etc/dovecot/conf.d/99-dockpanel.conf",
];

pub async fn archive_config(manifest: serde_json::Value, key: String) -> Result<ArchiveInfo, VbError> {
    let _lock = crate::site_lock::lock_site("mail:config").await;
    let dir = Path::new(MAIL_BACKUP_DIR);
    ensure_private_dir(dir)?;
    volume_backup::check_space(dir, 64 * 1024 * 1024, "the mail config archive")?;
    let name = config_archive_name(&stamp(chrono::Utc::now()));
    ensure_free_name(dir, &name)?;

    let token = format!("{:016x}", rand::random::<u64>());
    let manifest_part = PartFile::create(dir, &format!("manifest-{token}"))?;
    {
        use std::io::Write;
        let body = serde_json::to_vec_pretty(&manifest).map_err(|e| VbError::Internal(format!("Failed to encode the manifest: {e}")))?;
        let mut f = manifest_part.file()?;
        f.write_all(&body).map_err(|e| VbError::Internal(format!("Failed to write the manifest: {e}")))?;
        f.sync_all().ok();
    }
    let manifest_member = format!(".manifest-{token}.part");
    let present: Vec<&str> = CONFIG_FILES.iter().copied().filter(|p| Path::new("/").join(p).exists()).collect();

    let part = PartFile::create(dir, &name)?;
    let mut cmd = safe_command("tar");
    cmd.arg("--warning=no-file-changed")
        .arg("--ignore-failed-read")
        .arg(format!("--transform=s,^\\.manifest-{token}\\.part$,manifest.json,"))
        .arg("-czf")
        .arg(&part.path)
        .arg("-C")
        .arg(dir)
        .arg(&manifest_member);
    if !present.is_empty() {
        cmd.arg("-C").arg("/").args(&present);
    }
    let out = run(&mut cmd, std::time::Duration::from_secs(600), "Mail config backup").await?;
    drop(manifest_part);
    if !matches!(out.status.code(), Some(0) | Some(1)) {
        return Err(VbError::Internal(format!("Mail config backup failed: {}", stderr_of(&out))));
    }
    let info = finalize(part, dir, &name, Some(&key)).await?;
    tracing::info!("Mail config backed up: {} ({} bytes)", info.filename, info.size_bytes);
    Ok(info)
}

/// Decrypt a config archive and return its manifest. Nothing on the host is
/// restored from it.
pub async fn read_config_manifest(filename: String, key: String) -> Result<serde_json::Value, VbError> {
    let dir = locate(Path::new(MAIL_BACKUP_DIR), &filename)?;
    let r = readable(&dir, &filename, Some(&key)).await?;
    let out = run(
        safe_command("tar").arg("-xzOf").arg(&r.path).arg("manifest.json"),
        std::time::Duration::from_secs(600),
        "Reading the mail config backup",
    )
    .await?;
    if !out.status.success() {
        return Err(VbError::Integrity("The mail config backup holds no readable manifest".into()));
    }
    if out.stdout.len() as u64 > MAX_DOC_BYTES {
        return Err(VbError::Integrity("The manifest is too large".into()));
    }
    let manifest: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| VbError::Integrity("The manifest of the mail config backup is not valid JSON".into()))?;
    if !manifest.is_object() {
        return Err(VbError::Integrity("The manifest of the mail config backup is not a JSON object".into()));
    }
    Ok(manifest)
}

// ── Mailbox restore ─────────────────────────────────────────────────────────

/// The staging directory of one restore, removed on every exit (it holds the
/// replaced maildir until the end of a successful replace).
struct Staging {
    path: PathBuf,
    /// Set when the previous maildir could not be put back: the staging
    /// directory then holds it (`.previous`) and must survive.
    keep: bool,
}

impl Staging {
    fn create(domain_dir: &Path) -> Result<Self, VbError> {
        use std::os::unix::fs::DirBuilderExt;
        let path = domain_dir.join(format!(".restore-{}-{:08x}", stamp(chrono::Utc::now()), rand::random::<u32>()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| vmail_io_err(&path, e))?;
        Ok(Self { path, keep: false })
    }

    async fn remove(&self) -> Result<(), String> {
        let p = self.path.clone();
        tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&p))
            .await
            .map_err(|e| e.to_string())?
            .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e.to_string()) })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.keep {
            tracing::error!(
                "Mailbox restore staging {} kept: it holds the previous maildir (.previous)",
                self.path.display()
            );
            return;
        }
        if self.path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                tracing::error!("Failed to remove the mail restore staging {}: {e}", self.path.display());
            }
        }
    }
}

/// An I/O error under /var/vmail. EROFS there means the directory did not
/// exist when the agent started (the unit binds `-/var/vmail` read-write only
/// if it exists), which a restart of the agent fixes.
fn vmail_io_err(path: &Path, e: std::io::Error) -> VbError {
    if e.raw_os_error() == Some(libc::EROFS) {
        return VbError::Internal(format!(
            "Failed to create {}: /var/vmail is read-only for the agent (it did not exist when the agent started); restart dockpanel-agent and retry",
            path.display()
        ));
    }
    VbError::Internal(format!("Failed to create {}: {e}", path.display()))
}

async fn chown_vmail(path: &Path) -> Result<(), VbError> {
    let out = run(
        safe_command("chown").arg("-R").arg("vmail:vmail").arg(path),
        std::time::Duration::from_secs(1800),
        "chown vmail",
    )
    .await?;
    if !out.status.success() {
        return Err(VbError::Internal(format!("chown -R vmail:vmail {} failed: {}", path.display(), stderr_of(&out))));
    }
    Ok(())
}

/// Restore `{dir}/{filename}` into `mailbox` (see the module docs).
pub async fn restore_mailbox(
    mailbox: Mailbox,
    dir: PathBuf,
    filename: String,
    mode: RestoreMode,
    key: Option<String>,
) -> Result<serde_json::Value, VbError> {
    let _lock = crate::site_lock::lock_site(&mailbox.lock_key()).await;
    let archive = readable(&dir, &filename, key.as_deref()).await?;
    let len = std::fs::metadata(&archive.path).map(|m| m.len()).unwrap_or(0);
    let timeout = volume_backup::archive_timeout(len);

    // 1. Members: only `{local}/`, nothing absolute, no `..`.
    let listing = run(safe_command("tar").arg("-tzf").arg(&archive.path), timeout, "Reading the mailbox archive").await?;
    if !listing.status.success() {
        return Err(VbError::Integrity("The mailbox archive is corrupt or truncated: nothing was changed".into()));
    }
    check_member_names(&String::from_utf8_lossy(&listing.stdout), &mailbox.local).map_err(VbError::Integrity)?;

    // 2. Room for the extracted mail (heuristic: twice the compressed size).
    let domain_dir = mailbox.domain_dir();
    if !domain_dir.exists() {
        std::fs::create_dir_all(&domain_dir).map_err(|e| vmail_io_err(&domain_dir, e))?;
        chown_vmail(&domain_dir).await?;
    }
    volume_backup::check_space(&domain_dir, len.saturating_mul(2), "the restored mailbox")?;

    // 3. Extract into a staging directory beside the maildir.
    let mut staging = Staging::create(&domain_dir)?;
    let out = run(
        safe_command("tar")
            .arg("-xzf")
            .arg(&archive.path)
            .arg("-C")
            .arg(&staging.path)
            .arg("--no-same-owner")
            .arg("--")
            .arg(&mailbox.local),
        timeout,
        "Extracting the mailbox archive",
    )
    .await?;
    if !out.status.success() {
        return Err(VbError::Integrity(format!("Extracting the mailbox archive failed: {}", stderr_of(&out))));
    }
    drop(archive);
    {
        let (s, l) = (staging.path.clone(), mailbox.local.clone());
        tokio::task::spawn_blocking(move || check_extracted_tree(&s, &l))
            .await
            .map_err(|e| VbError::Internal(e.to_string()))?
            .map_err(VbError::Integrity)?;
    }

    // 4. Merge or replace.
    let maildir = mailbox.maildir();
    let extracted = staging.path.join(&mailbox.local);
    let previous = staging.path.join(".previous");
    let mut warnings: Vec<String> = Vec::new();
    let existed = std::fs::symlink_metadata(&maildir).is_ok();
    let stats = match (mode, existed) {
        (_, false) => {
            std::fs::rename(&extracted, &maildir).map_err(|e| VbError::Internal(format!("Failed to move the mailbox into place: {e}")))?;
            None
        }
        (RestoreMode::Merge, true) => {
            let (s, d) = (extracted.clone(), maildir.clone());
            let st = tokio::task::spawn_blocking(move || merge_tree(&s, &d))
                .await
                .map_err(|e| VbError::Internal(e.to_string()))?
                .map_err(|e| VbError::Internal(format!("Merging the mailbox failed: {e}")))?;
            Some(st)
        }
        (RestoreMode::Replace, true) => {
            std::fs::rename(&maildir, &previous).map_err(|e| VbError::Internal(format!("Failed to move the current mailbox aside: {e}")))?;
            if let Err(e) = std::fs::rename(&extracted, &maildir) {
                // Dovecot may have recreated the maildir in between (a
                // delivery): never delete the previous one then.
                if std::fs::rename(&previous, &maildir).is_err() {
                    staging.keep = true;
                    return Err(VbError::Internal(format!(
                        "Failed to move the restored mailbox into place ({e}); the previous mailbox is kept in {}",
                        previous.display()
                    )));
                }
                return Err(VbError::Internal(format!("Failed to move the restored mailbox into place: {e}")));
            }
            None
        }
    };

    // 5. Ownership. A replace that cannot be owned by vmail is rolled back.
    if let Err(e) = chown_vmail(&maildir).await {
        if mode == RestoreMode::Replace && existed {
            let failed = staging.path.join(".failed");
            let back = std::fs::rename(&maildir, &failed).is_ok() && std::fs::rename(&previous, &maildir).is_ok();
            if !back {
                staging.keep = true;
                return Err(VbError::Internal(format!(
                    "{}; the previous mailbox could not be put back and is kept in {}",
                    e.message(),
                    previous.display()
                )));
            }
        }
        return Err(e);
    }

    // 6. Dovecot's indexes.
    let addr = mailbox.addr();
    match run(
        safe_command("doveadm").args(["force-resync", "-u", &addr, "*"]),
        std::time::Duration::from_secs(900),
        "doveadm force-resync",
    )
    .await
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => warnings.push(format!(
            "doveadm force-resync for {addr} failed (Dovecot rebuilds its indexes on first access): {}",
            stderr_of(&o)
        )),
        Err(e) => warnings.push(format!("doveadm force-resync for {addr} could not run: {}", e.message())),
    }

    if let Err(e) = staging.remove().await {
        warnings.push(format!("Failed to remove the restore staging directory {}: {e}", staging.path.display()));
        tracing::error!("Failed to remove {}: {e}", staging.path.display());
    }
    let messages = {
        let p = maildir.clone();
        tokio::task::spawn_blocking(move || crate::services::hestia_mail::count_messages(&p)).await.unwrap_or(0)
    };
    tracing::info!("Mailbox restored: {addr} from {filename} ({})", mode.as_str());
    let mut v = serde_json::json!({
        "ok": true,
        "mode": mode.as_str(),
        "messages": messages,
        "warnings": warnings,
    });
    if let Some(st) = stats {
        v["restored"] = st.restored.into();
        v["skipped"] = st.skipped.into();
    }
    Ok(v)
}

/// Startup: report the staging directories an interrupted restore left under
/// `/var/vmail/{domain}/.restore-*`. Not removed automatically: a replace
/// interrupted between its two renames keeps the previous maildir there
/// (`.previous`), which only an operator should decide about.
pub fn report_stale_restores() -> usize {
    let mut n = 0;
    let Ok(domains) = std::fs::read_dir(VMAIL_DIR) else { return 0 };
    for d in domains.flatten() {
        let Ok(rd) = std::fs::read_dir(d.path()) else { continue };
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(".restore-") {
                n += 1;
                tracing::warn!(
                    "Leftover mailbox restore staging directory {} (an interrupted restore): check it, then remove it",
                    e.path().display()
                );
            }
        }
    }
    n
}

// ── Listing ─────────────────────────────────────────────────────────────────

/// The new files, `{"filename","size_bytes","modified",...}`.
pub fn list_backups(dir: &Path) -> Vec<serde_json::Value> {
    list_files(dir)
        .into_iter()
        .map(|(name, size, modified)| {
            let mut v = serde_json::json!({
                "filename": name,
                "size_bytes": size,
                "modified": modified,
                "encrypted": name.ends_with(".enc"),
            });
            if is_config_archive_name(&name) {
                v["kind"] = "config".into();
            } else {
                let mut c = parse_mailbox_archive_name(&name);
                if c.len() > 1 {
                    c.retain(|(d, _)| Path::new(VMAIL_DIR).join(d).is_dir());
                }
                v["kind"] = if name.starts_with("mail-") { "mailbox" } else { "other" }.into();
                if let [(d, l)] = c.as_slice() {
                    v["domain"] = d.clone().into();
                    v["local"] = l.clone().into();
                    v["email"] = format!("{l}@{d}").into();
                }
            }
            v
        })
        .collect()
}

/// The pre-lot-3 list shape `{"file","name","email","size"}` read by the
/// current Mail page: the legacy directory, plus the new unencrypted mailbox
/// archives (an encrypted one needs a key that page cannot send).
pub fn list_legacy_shape(new_items: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for (name, size, _) in list_files(Path::new(LEGACY_MAIL_BACKUP_DIR)) {
        if !name.ends_with(".tar.gz") {
            continue;
        }
        let email = legacy_email(&name).unwrap_or_else(|| name.clone());
        out.push(serde_json::json!({
            "file": format!("{LEGACY_MAIL_BACKUP_DIR}/{name}"),
            "name": name,
            "email": email,
            "size": size,
        }));
    }
    for v in new_items {
        let (Some(name), Some(email)) = (v["filename"].as_str(), v["email"].as_str()) else { continue };
        if name.ends_with(".enc") {
            continue;
        }
        out.push(serde_json::json!({
            "file": format!("{MAIL_BACKUP_DIR}/{name}"),
            "name": name,
            "email": email,
            "size": v["size_bytes"],
        }));
    }
    out
}

/// The address of a pre-lot-3 name `{user}_{domain}_{unix}.tar.gz`. The old
/// listing replaced the FIRST `_` with `@`, so `a_b@x.com` read as
/// `a@b_x.com`; a domain never contains `_`, so the LAST one is the split.
pub fn legacy_email(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".tar.gz")?;
    let (head, ts) = stem.rsplit_once('_')?;
    if ts.is_empty() || !ts.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (user, domain) = head.rsplit_once('_')?;
    (!user.is_empty() && is_valid_mail_domain(domain)).then(|| format!("{user}@{domain}"))
}

/// `POST /mail/backups/delete` accepts a full path in either directory.
pub fn deletable_path(file: &str) -> Option<PathBuf> {
    let (dir, name) = file.rsplit_once('/')?;
    if !(dir == LEGACY_MAIL_BACKUP_DIR || dir == MAIL_BACKUP_DIR) || !is_safe_backup_filename(name) {
        return None;
    }
    Some(Path::new(dir).join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ST: &str = "20261119-101010";

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("dp-mailbk-{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn names_round_trip_for_awkward_local_parts() {
        let cases = [
            ("example.com", "a_b"),
            ("example.com", "a-b"),
            ("example.com", "first.last"),
            ("example.com", "user+tag"),
            ("my-site.example.co.uk", "_-_"),
            ("xn--e1afmkfd.xn--p1ai", "a_b"),
            ("xn--bcher-kva.example", "jürgen"),
            ("example.com", "-dash"),
            ("example.com", "a"),
        ];
        for (d, l) in cases {
            let name = mailbox_archive_name(d, l, ST);
            assert!(name.starts_with("mail-") && name.ends_with(&format!("-{ST}.tar.gz")), "{name}");
            assert!(is_safe_backup_filename(&name), "{name}");
            assert!(is_archive_of(&name, d, l));
            assert!(is_archive_of(&format!("{name}.enc"), d, l));
            assert_eq!(parse_mailbox_archive_name(&name), vec![(d.to_string(), l.to_string())], "{name}");
            assert_eq!(decode_local(&encode_local(l)).as_deref(), Some(l));
        }
    }

    #[test]
    fn an_archive_is_never_taken_for_another_mailbox() {
        let n = mailbox_archive_name("example.com", "a_b", ST);
        assert!(!is_archive_of(&n, "example.com", "a"));
        assert!(!is_archive_of(&n, "example.co", "a_b"));
        assert!(!is_archive_of(&n, "b.example.com", "a_b"));
        assert!(!is_archive_of(&format!("{n}.bak"), "example.com", "a_b"));
        assert!(!is_archive_of(&n.replace(ST, "2026111-101010"), "example.com", "a_b"));
        // The old naming: `a_b_example.com_<ts>` was read back as a@b_example.com.
        assert!(is_legacy_archive_of("a_b_example.com_1700000000.tar.gz", "example.com", "a_b"));
        assert!(!is_legacy_archive_of("a_b_example.com_1700000000.tar.gz", "example.com", "a"));
        assert!(!is_legacy_archive_of("a_b_example.com_x.tar.gz", "example.com", "a_b"));
        // A legacy name can be read two ways ("b_example.com" is no valid
        // domain, but the name alone cannot tell): the restore also checks
        // that every archive member is under `{local}/`.
    }

    #[test]
    fn prefix_is_a_valid_remote_retention_prefix() {
        let p = mailbox_prefix("example.com", "a_b");
        assert_eq!(p, "mail-example.com-YV9i-");
        crate::services::remote_backup::validate_name_prefix(&p).unwrap();
    }

    #[test]
    fn non_canonical_or_invalid_segments_do_not_decode() {
        assert_eq!(decode_local("YV9i"), Some("a_b".into()));
        assert_eq!(decode_local("YR"), None); // "a" with non-zero trailing bits: not canonical
        assert_eq!(decode_local("Lg"), None); // "."
        assert_eq!(decode_local(&encode_local("a/b")), None);
        assert_eq!(decode_local(&encode_local("a*")), None);
        assert_eq!(decode_local("YV9i=="), None);
        assert!(parse_mailbox_archive_name("mail-example.com-YV9i-20261119.tar.gz").is_empty());
        assert!(parse_mailbox_archive_name("mailcfg-20261119-101010.tar.gz.enc").is_empty());
    }

    #[test]
    fn validators() {
        for ok in ["a", "a_b", "a.b", "a+b", "a-b", "-a", "jürgen", "0"] {
            assert!(is_valid_local(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a\\b", "a b", "a*", "a?", "a\n", "a@b", &"x".repeat(65)] {
            assert!(!is_valid_local(bad), "{bad:?}");
        }
        for ok in ["example.com", "xn--e1afmkfd.xn--p1ai", "a-b.example"] {
            assert!(is_valid_mail_domain(ok), "{ok}");
        }
        for bad in ["", "Example.com", "a..b", "../etc", "a/b.com", "localhost", "-a.com", "a.com."] {
            assert!(!is_valid_mail_domain(bad), "{bad}");
        }
        for ok in ["mail-a.com-YQ-20261119-101010.tar.gz", "dns-zone-a.com-20261119-101010.json.enc"] {
            assert!(is_safe_backup_filename(ok));
        }
        for bad in ["", ".x.part", "a/b", "../x", "a..b", "a b", "x;rm"] {
            assert!(!is_safe_backup_filename(bad), "{bad}");
        }
        assert!(is_config_archive_name("mailcfg-20261119-101010.tar.gz.enc"));
        assert!(!is_config_archive_name("mailcfg-20261119-101010.tar.gz"));
        assert!(!is_config_archive_name("mailcfg-x.tar.gz.enc"));
    }

    #[test]
    fn member_listing_must_be_the_mailbox_alone() {
        let ok = "a_b/\na_b/cur/\na_b/cur/1700.M1:2,S\na_b/new/\na_b/dovecot-uidlist\n";
        assert_eq!(check_member_names(ok, "a_b"), Ok(5));
        assert!(check_member_names("", "a_b").is_err());
        assert!(check_member_names("a_b/\nother/cur/x\n", "a_b").is_err());
        assert!(check_member_names("a_bc/cur/x\n", "a_b").is_err());
        assert!(check_member_names("/a_b/cur/x\n", "a_b").is_err());
        assert!(check_member_names("a_b/../../etc/passwd\n", "a_b").is_err());
        assert!(check_member_names("./a_b/x\n", "a_b").is_err());
        assert!(check_member_names("a_b/x/..\n", "a_b").is_err());
    }

    #[test]
    fn extracted_tree_refuses_links_and_strays() {
        let s = Scratch::new();
        std::fs::create_dir_all(s.0.join("a/cur")).unwrap();
        std::fs::write(s.0.join("a/cur/m1:2,"), b"x").unwrap();
        assert!(check_extracted_tree(&s.0, "a").is_ok());
        std::os::unix::fs::symlink("/etc/passwd", s.0.join("a/cur/evil")).unwrap();
        assert!(check_extracted_tree(&s.0, "a").unwrap_err().contains("symbolic link"));
        std::fs::remove_file(s.0.join("a/cur/evil")).unwrap();
        std::fs::create_dir(s.0.join("b")).unwrap();
        assert!(check_extracted_tree(&s.0, "a").is_err());
    }

    fn write(p: &Path, body: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn merge_keeps_present_messages_and_adds_missing_ones() {
        let s = Scratch::new();
        let (src, dst) = (s.0.join("src"), s.0.join("dst"));
        // In the backup: m1 unread, m2, a folder with m3, a tmp file, the uidlist.
        write(&src.join("cur/m1:2,"), "old");
        write(&src.join("new/m2"), "two");
        write(&src.join(".Sent/cur/m3:2,S"), "three");
        write(&src.join("tmp/inflight"), "t");
        write(&src.join("dovecot-uidlist"), "backup-uidlist");
        // Now: m1 read since (renamed with a flag), a newer uidlist.
        write(&dst.join("cur/m1:2,S"), "current");
        std::thread::sleep(std::time::Duration::from_millis(20));
        write(&dst.join("dovecot-uidlist"), "current-uidlist");
        let st = merge_tree(&src, &dst).unwrap();
        assert_eq!(st, MergeStats { restored: 2, skipped: 1 });
        assert_eq!(std::fs::read_to_string(dst.join("cur/m1:2,S")).unwrap(), "current");
        assert!(!dst.join("cur/m1:2,").exists(), "a flag change must not duplicate the message");
        assert_eq!(std::fs::read_to_string(dst.join("new/m2")).unwrap(), "two");
        assert_eq!(std::fs::read_to_string(dst.join(".Sent/cur/m3:2,S")).unwrap(), "three");
        assert!(dst.join("tmp").is_dir());
        assert!(!dst.join("tmp/inflight").exists());
        assert_eq!(std::fs::read_to_string(dst.join("dovecot-uidlist")).unwrap(), "current-uidlist");
    }

    #[test]
    fn base_names() {
        assert_eq!(base_of("1700.M1P2.host,S=12,W=13:2,RS"), "1700.M1P2.host,S=12,W=13");
        assert_eq!(base_of("1700.M1P2.host"), "1700.M1P2.host");
    }

    #[test]
    fn archive_bodies_parse_and_plan() {
        let r: MailArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "mailbox", "domain": "A.com", "local": "a_b"})).unwrap();
        match plan_archive(r).ok().unwrap() {
            ArchivePlan::Mailbox { mailbox, key } => {
                assert_eq!(mailbox.addr(), "a_b@a.com");
                assert!(key.is_none());
            }
            ArchivePlan::Config { .. } => panic!("mailbox expected"),
        }
        let r: MailArchiveRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a", "encryption_key": null
        }))
        .unwrap();
        assert!(plan_archive(r).is_ok());
        let r: MailArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "mailbox", "domain": "a.com", "local": "../x"})).unwrap();
        assert!(matches!(plan_archive(r).err().unwrap(), VbError::BadRequest(_)));
        let r: MailArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "zone", "domain": "a.com", "local": "x"})).unwrap();
        assert!(matches!(plan_archive(r).err().unwrap(), VbError::BadRequest(_)));
    }

    #[test]
    fn config_archive_without_key_is_refused() {
        for body in [
            serde_json::json!({"kind": "config", "manifest": {"domains": []}}),
            serde_json::json!({"kind": "config", "manifest": {"domains": []}, "encryption_key": ""}),
            serde_json::json!({"kind": "config", "manifest": {"domains": []}, "encryption_key": null}),
        ] {
            let r: MailArchiveRequest = serde_json::from_value(body).unwrap();
            let e = plan_archive(r).err().unwrap();
            assert!(matches!(&e, VbError::BadRequest(m) if m.contains("always encrypted")), "{e}");
        }
        let r: MailArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "config", "manifest": [1], "encryption_key": "k"})).unwrap();
        assert!(plan_archive(r).is_err());
        let r: MailArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "config", "manifest": {}, "encryption_key": "k"})).unwrap();
        assert!(matches!(plan_archive(r).ok().unwrap(), ArchivePlan::Config { .. }));
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "config", "filename": "mailcfg-20261119-101010.tar.gz.enc"
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).err().unwrap(), VbError::BadRequest(_)));
    }

    #[test]
    fn restore_bodies_parse_and_plan() {
        let name = mailbox_archive_name("a.com", "a_b", ST);
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a_b", "filename": name, "mode": "replace"
        }))
        .unwrap();
        match plan_restore(r).ok().unwrap() {
            RestorePlan::Mailbox { mode, key, .. } => {
                assert_eq!(mode, RestoreMode::Replace);
                assert!(key.is_none());
            }
            _ => panic!("mailbox expected"),
        }
        // merge is the default
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a_b", "filename": name
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).ok().unwrap(), RestorePlan::Mailbox { mode: RestoreMode::Merge, .. }));
        // someone else's archive
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a", "filename": name
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).err().unwrap(), VbError::BadRequest(_)));
        // encrypted without key
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a_b", "filename": format!("{name}.enc")
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).err().unwrap(), VbError::BadRequest(_)));
        // bad mode, traversal
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a_b", "filename": name, "mode": "wipe"
        }))
        .unwrap();
        assert!(plan_restore(r).is_err());
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "mailbox", "domain": "a.com", "local": "a_b", "filename": "../../etc/shadow"
        }))
        .unwrap();
        assert!(plan_restore(r).is_err());
    }

    #[test]
    fn legacy_restore_body_checks_ownership() {
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "email": "a_b@example.com", "file": "/var/lib/dockpanel/mail-backups/a_b_example.com_1700000000.tar.gz"
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).ok().unwrap(), RestorePlan::Legacy { .. }));
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "email": "c@example.com", "file": "/var/lib/dockpanel/mail-backups/a_b_example.com_1700000000.tar.gz"
        }))
        .unwrap();
        assert!(plan_restore(r).is_err());
        let name = mailbox_archive_name("example.com", "c", ST);
        let r: MailRestoreRequest = serde_json::from_value(serde_json::json!({
            "email": "c@example.com", "file": format!("/var/backups/dockpanel/mail/{name}")
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).ok().unwrap(), RestorePlan::Legacy { .. }));
        for file in ["/etc/shadow", "/var/lib/dockpanel/mail-backups/../x.tar.gz", "relative.tar.gz"] {
            let r: MailRestoreRequest =
                serde_json::from_value(serde_json::json!({"email": "c@example.com", "file": file})).unwrap();
            assert!(plan_restore(r).is_err(), "{file}");
        }
    }

    #[test]
    fn mail_presence_decision() {
        assert!(mail_stack_present(true, true));
        assert!(!mail_stack_present(true, false));
        assert!(!mail_stack_present(false, true));
        assert!(!mail_stack_present(false, false));
    }

    #[test]
    fn listing_skips_hidden_and_reads_addresses() {
        let s = Scratch::new();
        let name = mailbox_archive_name("example.com", "a_b", ST);
        std::fs::write(s.0.join(&name), b"x").unwrap();
        std::fs::write(s.0.join("mailcfg-20261119-101010.tar.gz.enc"), b"y").unwrap();
        std::fs::write(s.0.join(".mail-x.part"), b"z").unwrap();
        let items = list_backups(&s.0);
        assert_eq!(items.len(), 2);
        let mb = items.iter().find(|v| v["filename"] == name.as_str()).unwrap();
        assert_eq!(mb["kind"], "mailbox");
        assert_eq!(mb["email"], "a_b@example.com");
        assert_eq!(mb["size_bytes"], 1);
        assert!(mb["modified"].as_str().unwrap().ends_with('Z'));
        let cfg = items.iter().find(|v| v["kind"] == "config").unwrap();
        assert_eq!(cfg["encrypted"], true);
        let legacy = list_legacy_shape(&items);
        assert!(legacy.iter().any(|v| v["email"] == "a_b@example.com"));
    }

    #[test]
    fn legacy_names_read_back_right() {
        assert_eq!(legacy_email("a_b_example.com_1700000000.tar.gz").as_deref(), Some("a_b@example.com"));
        assert_eq!(legacy_email("u_my-site.example.org_1.tar.gz").as_deref(), Some("u@my-site.example.org"));
        assert_eq!(legacy_email("junk.tar.gz"), None);
        assert_eq!(legacy_email("a_example.com_x.tar.gz"), None);
    }

    #[test]
    fn delete_paths() {
        assert!(deletable_path("/var/lib/dockpanel/mail-backups/a_b_x.com_1.tar.gz").is_some());
        assert!(deletable_path("/var/backups/dockpanel/mail/mail-x.com-YQ-20261119-101010.tar.gz").is_some());
        assert!(deletable_path("/var/backups/dockpanel/mail/../x").is_none());
        assert!(deletable_path("/etc/passwd").is_none());
        assert!(deletable_path("/var/backups/dockpanel/mail/.x.part").is_none());
    }

    #[test]
    fn stamps() {
        assert!(is_stamp(ST));
        assert!(!is_stamp("20261119101010"));
        assert_eq!(strip_stamp_suffix("x-20261119-101010.json", &[".json"]), Some("x"));
        assert_eq!(strip_stamp_suffix("x-20261119-101010.json", &[".gz"]), None);
        assert_eq!(stamp(chrono::DateTime::from_timestamp(0, 0).unwrap()), "19700101-000000");
    }

    #[tokio::test]
    async fn finalize_encrypts_and_removes_the_plaintext() {
        let s = Scratch::new();
        let part = PartFile::create(&s.0, "x.tar.gz").unwrap();
        std::fs::write(&part.path, b"secret mail").unwrap();
        let part_path = part.path.clone();
        let info = finalize(part, &s.0, "x.tar.gz", Some("k")).await.unwrap();
        assert_eq!(info.filename, "x.tar.gz.enc");
        assert!(info.encrypted);
        assert_eq!(info.sha256.len(), 64);
        assert!(!part_path.exists());
        assert!(!s.0.join("x.tar.gz").exists());
        assert_eq!(
            encryption::verify_file(&s.0.join("x.tar.gz.enc"), "k").await.unwrap(),
            encryption::TagStatus::Verified
        );
        assert!(matches!(ensure_free_name(&s.0, "x.tar.gz"), Err(VbError::Conflict(_))));
    }
}
