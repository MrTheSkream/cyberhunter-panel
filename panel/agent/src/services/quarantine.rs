//! Quarantine of site files (feature 5, contract A-7), shared by the antivirus
//! and the security scanner's `quarantine_file` fix.
//!
//! Layout: `/var/lib/dockpanel/quarantine/<uuid>/` (0700 root) holding
//! `meta.json` (written first) and `file` (mode 0000). Files quarantined by the
//! old code (`<ts>_<name>` at the root, no metadata) are listed as
//! `legacy:<name>` and cannot be restored.
//!
//! # Path safety
//!
//! The agent is root and the site trees are writable by tenants, so no path is
//! resolved by name and then acted on. From an fd on `/var/www`, every
//! component is opened one at a time with `openat(O_DIRECTORY | O_NOFOLLOW)`,
//! and the leaf is handled with `*at` calls on its parent's fd (`O_NOFOLLOW`,
//! `renameat2(RENAME_NOREPLACE)`, `unlinkat`). A symlink anywhere in the path,
//! or a `..`, is refused. Swapping a directory for a symlink after the check
//! changes nothing: the fd already points at the real directory.
//!
//! Not `openat2(RESOLVE_NO_SYMLINKS)`: the agent unit's `RestrictSUIDSGID=yes`
//! makes systemd's seccomp filter answer `openat2` with ENOSYS (it cannot
//! inspect the mode inside `open_how`).
//!
//! Each `ReadWritePaths` entry is its own bind mount, so moving a file from
//! `/var/www` to `/var/lib/dockpanel` gets EXDEV even on one file system: the
//! copy-then-unlink fallback is the usual path in production.

use crate::services::clamav::AvErr;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const WWW_ROOT: &str = "/var/www";
pub const QUARANTINE_ROOT: &str = "/var/lib/dockpanel/quarantine";
const META: &str = "meta.json";
const FILE: &str = "file";
/// Legacy files above this are listed without a sha256.
const LEGACY_HASH_LIMIT: u64 = 64 * 1024 * 1024;

/// What `meta.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub original_path: String,
    pub domain: String,
    pub uid: u32,
    pub gid: u32,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    pub sha256: String,
    pub size: u64,
    pub signature: Option<String>,
    pub quarantined_at: String,
}

/// Contract A-7 `Item`.
pub fn item_json(id: &str, m: &Meta) -> serde_json::Value {
    serde_json::json!({
        "quarantine_id": id,
        "domain": m.domain,
        "original_path": m.original_path,
        "signature": m.signature,
        "sha256": m.sha256,
        "size": m.size,
        "uid": m.uid,
        "gid": m.gid,
        "mode": m.mode,
        "quarantined_at": m.quarantined_at,
    })
}

/// Domain accepted by the routes (no path traversal possible).
pub fn valid_domain(domain: &str) -> bool {
    !domain.contains("..") && crate::routes::is_valid_domain(domain)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

const OUTSIDE: &str = "The path must be a file inside the site directory, without symbolic links";

// ── Safe resolution ─────────────────────────────────────────────────────────

/// `www/site` as a directory fd, with no symlink below `www` (`site` empty =
/// `www` itself, only for the security scanner's legacy caller).
pub fn open_site(www: &Path, site: &str) -> Result<OwnedFd, AvErr> {
    let www_fd = rustix::fs::open(www, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| AvErr::internal(format!("Cannot open {}: {e}", www.display())))?;
    if site.is_empty() {
        return Ok(www_fd);
    }
    if site.contains('/') || site == "." || site == ".." {
        return Err(AvErr::bad("Invalid domain"));
    }
    open_dir_beneath(&www_fd, Path::new(site)).map_err(|e| match e {
        Errno::NOENT => AvErr::not_found("Site directory not found"),
        _ => AvErr::bad("The site directory is not a plain directory"),
    })
}

/// Open the directory `rel` (plain components only) below `base`, one
/// component at a time, never following a symlink (ELOOP / ENOTDIR on one).
/// The fd can be listed (`O_RDONLY`) and used as a `*at` base. An empty `rel`
/// reopens `base` itself.
pub fn open_dir_beneath(base: &OwnedFd, rel: &Path) -> Result<OwnedFd, Errno> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut cur = rustix::fs::openat(base, ".", flags, Mode::empty())?;
    for c in rel.components() {
        let Component::Normal(name) = c else { return Err(Errno::INVAL) };
        cur = rustix::fs::openat(&cur, name, flags, Mode::empty())?;
    }
    Ok(cur)
}

/// `path` relative to `www/site`, refusing anything but plain components.
pub fn site_relative(www: &Path, site: &str, path: &str) -> Result<PathBuf, AvErr> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(AvErr::bad(OUTSIDE));
    }
    let base = if site.is_empty() { www.to_path_buf() } else { www.join(site) };
    // Component-wise, and before any normalisation: `..` stays visible.
    let rel = p.strip_prefix(&base).map_err(|_| AvErr::bad(OUTSIDE))?;
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(AvErr::bad(OUTSIDE));
    }
    Ok(rel.to_path_buf())
}

/// The parent directory of `rel` (fd, beneath the site, no symlinks) and the
/// leaf name.
pub fn open_parent(site_fd: &OwnedFd, rel: &Path) -> Result<(OwnedFd, OsString), AvErr> {
    let leaf = rel.file_name().ok_or_else(|| AvErr::bad(OUTSIDE))?.to_os_string();
    let parent = rel.parent().unwrap_or(Path::new(""));
    let fd = open_dir_beneath(site_fd, parent).map_err(|e| match e {
        Errno::NOENT => AvErr::not_found("File not found"),
        _ => AvErr::bad(OUTSIDE),
    })?;
    Ok((fd, leaf))
}

/// Metadata of the leaf itself (a symlink is reported as a symlink), `None`
/// when absent.
pub fn leaf_metadata(parent: &OwnedFd, leaf: &OsString) -> Result<Option<std::fs::Metadata>, AvErr> {
    match rustix::fs::openat(parent, leaf.as_os_str(), OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd)
            .metadata()
            .map(Some)
            .map_err(|e| AvErr::internal(format!("stat failed: {e}"))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(AvErr::internal(format!("stat failed: {e}"))),
    }
}

/// Open the leaf for reading; it must be a regular file (never follows a
/// symlink, never blocks on a FIFO).
pub fn open_regular(parent: &OwnedFd, leaf: &OsString) -> Result<std::fs::File, AvErr> {
    let fd = rustix::fs::openat(
        parent,
        leaf.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::NOENT => AvErr::not_found("File not found"),
        Errno::LOOP => AvErr::bad("Not a regular file"),
        e => AvErr::internal(format!("open failed: {e}")),
    })?;
    let f = std::fs::File::from(fd);
    let m = f.metadata().map_err(|e| AvErr::internal(format!("stat failed: {e}")))?;
    if !m.file_type().is_file() {
        return Err(AvErr::bad("Not a regular file"));
    }
    Ok(f)
}

/// Resolve a file of a site: (site-relative path, parent fd, leaf).
fn resolve(www: &Path, site: &str, path: &str) -> Result<(OwnedFd, OsString), AvErr> {
    let rel = site_relative(www, site, path)?;
    let site_fd = open_site(www, site)?;
    open_parent(&site_fd, &rel)
}

/// sha256 (hex) and byte count of everything `r` yields.
pub fn sha256_reader<R: Read>(r: &mut R) -> std::io::Result<(String, u64)> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((hex::encode(h.finalize()), n_total))
}

fn ensure_root(qroot: &Path) -> Result<(), AvErr> {
    std::fs::create_dir_all(qroot).map_err(|e| AvErr::internal(format!("Cannot create the quarantine: {e}")))?;
    std::fs::set_permissions(qroot, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| AvErr::internal(format!("Cannot protect the quarantine: {e}")))
}

fn write_meta(dir: &Path, meta: &Meta, create_new: bool) -> Result<(), AvErr> {
    let body = serde_json::to_vec_pretty(meta).map_err(|e| AvErr::internal(e.to_string()))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).mode(0o600);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut f = opts
        .open(dir.join(META))
        .map_err(|e| AvErr::internal(format!("Cannot write the quarantine metadata: {e}")))?;
    f.write_all(&body)
        .and_then(|_| f.sync_all())
        .map_err(|e| AvErr::internal(format!("Cannot write the quarantine metadata: {e}")))
}

fn read_meta(dir: &Path) -> Option<Meta> {
    let text = std::fs::read_to_string(dir.join(META)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Copy `src` into a new file `name` of `dir_fd` (create-exclusive), used when
/// a rename crosses mounts. A partial copy is removed. Returns the new file
/// (open for writing) so the caller can set owner and mode on the fd.
fn copy_into(src: &mut std::fs::File, dir_fd: &OwnedFd, name: &OsStr, mode: u32) -> std::io::Result<std::fs::File> {
    src.rewind()?;
    let fd = rustix::fs::openat(
        dir_fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map_err(std::io::Error::from)?;
    let mut dst = std::fs::File::from(fd);
    match std::io::copy(src, &mut dst).and_then(|_| dst.sync_all()) {
        Ok(()) => Ok(dst),
        Err(e) => {
            let _ = rustix::fs::unlinkat(dir_fd, name, AtFlags::empty());
            Err(e)
        }
    }
}

// ── Operations (paths injected for tests) ───────────────────────────────────

pub fn quarantine_at(
    qroot: &Path,
    www: &Path,
    site: &str,
    path: &str,
    signature: Option<String>,
) -> Result<serde_json::Value, AvErr> {
    quarantine_impl(qroot, www, site, path, signature, false)
}

/// `force_copy` exercises the cross-mount branch in tests.
fn quarantine_impl(
    qroot: &Path,
    www: &Path,
    site: &str,
    path: &str,
    signature: Option<String>,
    force_copy: bool,
) -> Result<serde_json::Value, AvErr> {
    let (parent, leaf) = resolve(www, site, path)?;
    let mut src = open_regular(&parent, &leaf)?;
    let st = src.metadata().map_err(|e| AvErr::internal(e.to_string()))?;
    let (sha256, size) = sha256_reader(&mut src).map_err(|e| AvErr::internal(format!("read failed: {e}")))?;
    let original_path = if site.is_empty() { www.to_path_buf() } else { www.join(site) }
        .join(site_relative(www, site, path)?)
        .to_string_lossy()
        .into_owned();
    let mut meta = Meta {
        original_path,
        domain: site.to_string(),
        uid: st.uid(),
        gid: st.gid(),
        mode: st.mode() & 0o7777,
        sha256,
        size,
        signature,
        quarantined_at: now_rfc3339(),
    };

    ensure_root(qroot)?;
    let id = uuid::Uuid::new_v4().to_string();
    let dir = qroot.join(&id);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| AvErr::internal(format!("Cannot create the quarantine entry: {e}")))?;
    let cleanup = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
    };
    if let Err(e) = write_meta(&dir, &meta, true) {
        cleanup(&dir);
        return Err(e);
    }
    let dir_fd = match rustix::fs::open(&dir, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            cleanup(&dir);
            return Err(AvErr::internal(format!("Cannot open the quarantine entry: {e}")));
        }
    };
    let renamed = if force_copy {
        Err(Errno::XDEV)
    } else {
        rustix::fs::renameat(&parent, leaf.as_os_str(), &dir_fd, FILE)
    };
    let copied = match renamed {
        Ok(()) => false,
        Err(Errno::XDEV) => {
            // The copy comes from the fd that was hashed, so it is the same
            // inode's content; owner and mode stay those of `st`.
            if let Err(e) = copy_into(&mut src, &dir_fd, OsStr::new(FILE), 0o000) {
                cleanup(&dir);
                return Err(AvErr::internal(format!("Cannot copy the file into the quarantine: {e}")));
            }
            if let Err(e) = rustix::fs::unlinkat(&parent, leaf.as_os_str(), AtFlags::empty()) {
                cleanup(&dir);
                return Err(AvErr::internal(format!("Cannot remove the original file: {e}")));
            }
            true
        }
        Err(e) => {
            cleanup(&dir);
            return Err(AvErr::internal(format!("Cannot move the file into the quarantine: {e}")));
        }
    };
    let qfile = dir.join(FILE);
    // Describe what is really in the quarantine: the content may have been
    // written to between the hash and the move, and a rename may have moved
    // a leaf swapped in meanwhile (then its own owner and mode apply). Read
    // before the chmod to 000.
    let mut changed = false;
    if let Ok(m) = std::fs::symlink_metadata(&qfile) {
        if !copied && (m.dev(), m.ino()) != (st.dev(), st.ino()) {
            meta.uid = m.uid();
            meta.gid = m.gid();
            meta.mode = m.mode() & 0o7777;
            changed = true;
        }
        if let Ok((sha, size)) = std::fs::File::open(&qfile).and_then(|mut f| sha256_reader(&mut f)) {
            if sha != meta.sha256 || size != meta.size {
                meta.sha256 = sha;
                meta.size = size;
                changed = true;
            }
        }
    }
    if changed {
        let _ = write_meta(&dir, &meta, false);
    }
    let _ = std::fs::set_permissions(&qfile, std::fs::Permissions::from_mode(0o000));
    Ok(item_json(&id, &meta))
}

enum QId {
    Entry(String),
    Legacy(String),
}

fn parse_id(id: &str) -> Result<QId, AvErr> {
    if let Some(name) = id.strip_prefix("legacy:") {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." || name.contains('\0') {
            return Err(AvErr::bad("Invalid quarantine id"));
        }
        return Ok(QId::Legacy(name.to_string()));
    }
    let u = uuid::Uuid::parse_str(id).map_err(|_| AvErr::bad("Invalid quarantine id"))?;
    Ok(QId::Entry(u.hyphenated().to_string()))
}

/// Puts a quarantined file back. Returns its path.
pub fn restore_at(qroot: &Path, www: &Path, id: &str) -> Result<String, AvErr> {
    restore_impl(qroot, www, id, false)
}

/// Mode given back on restore: setuid/setgid dropped (the agent unit's
/// `RestrictSUIDSGID=yes` refuses them, and a web file has no use for them).
pub fn restored_mode(mode: u32) -> u32 {
    mode & 0o1777
}

fn restore_impl(qroot: &Path, www: &Path, id: &str, force_copy: bool) -> Result<String, AvErr> {
    let id = match parse_id(id)? {
        QId::Legacy(_) => return Err(AvErr::conflict("No metadata for this file")),
        QId::Entry(id) => id,
    };
    let dir = qroot.join(&id);
    if !dir.is_dir() {
        return Err(AvErr::not_found("Quarantine entry not found"));
    }
    let meta = read_meta(&dir).ok_or_else(|| AvErr::conflict("No metadata for this file"))?;
    // `open_site` refuses a domain with a `/`, `.` or `..`.
    let rel = site_relative(www, &meta.domain, &meta.original_path)?;
    let site_fd = open_site(www, &meta.domain).map_err(|e| match e.status {
        404 => AvErr::conflict("The site directory no longer exists"),
        _ => e,
    })?;
    let (parent, leaf) = open_parent(&site_fd, &rel).map_err(|e| match e.status {
        404 => AvErr::conflict("The original directory no longer exists"),
        _ => e,
    })?;
    if leaf_metadata(&parent, &leaf)?.is_some() {
        return Err(AvErr::conflict("A file already exists at the original path"));
    }
    let qfile = dir.join(FILE);
    let mut src = std::fs::File::open(&qfile).map_err(|e| AvErr::internal(format!("Cannot read the quarantined file: {e}")))?;
    let (sha, _) = sha256_reader(&mut src).map_err(|e| AvErr::internal(format!("read failed: {e}")))?;
    if sha != meta.sha256 {
        return Err(AvErr::conflict("The quarantined file changed (sha256 mismatch)"));
    }
    let mode = restored_mode(meta.mode);
    let dir_fd = rustix::fs::open(&dir, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| AvErr::internal(format!("Cannot open the quarantine entry: {e}")))?;
    // Owner and mode are set while the file is still in the root-only
    // quarantine, so a file never lands back at 000 or root-owned.
    let set_owner_mode = |f: &std::fs::File| -> Result<(), AvErr> {
        std::os::unix::fs::fchown(f, Some(meta.uid), Some(meta.gid))
            .map_err(|e| AvErr::internal(format!("chown failed: {e}")))?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| AvErr::internal(format!("chmod failed: {e}")))
    };
    let renamed = if force_copy {
        Err(Errno::XDEV)
    } else {
        set_owner_mode(&src)?;
        rustix::fs::renameat_with(&dir_fd, FILE, &parent, leaf.as_os_str(), rustix::fs::RenameFlags::NOREPLACE)
    };
    match renamed {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            let _ = src.set_permissions(std::fs::Permissions::from_mode(0o000));
            return Err(AvErr::conflict("A file already exists at the original path"));
        }
        Err(Errno::XDEV) => {
            let dst = copy_into(&mut src, &parent, &leaf, 0o600).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => AvErr::conflict("A file already exists at the original path"),
                _ => AvErr::internal(format!("Cannot restore the file: {e}")),
            })?;
            if let Err(e) = set_owner_mode(&dst) {
                let _ = rustix::fs::unlinkat(&parent, leaf.as_os_str(), AtFlags::empty());
                return Err(e);
            }
        }
        Err(e) => {
            let _ = src.set_permissions(std::fs::Permissions::from_mode(0o000));
            return Err(AvErr::internal(format!("Cannot restore the file: {e}")));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(meta.original_path)
}

/// Deletes a file of a site for good (same path checks).
pub fn delete_at(www: &Path, site: &str, path: &str) -> Result<(), AvErr> {
    let (parent, leaf) = resolve(www, site, path)?;
    match leaf_metadata(&parent, &leaf)? {
        None => return Err(AvErr::not_found("File not found")),
        Some(m) if !m.file_type().is_file() => return Err(AvErr::bad("Not a regular file")),
        Some(_) => {}
    }
    rustix::fs::unlinkat(&parent, leaf.as_os_str(), AtFlags::empty())
        .map_err(|e| AvErr::internal(format!("Cannot delete the file: {e}")))
}

/// Purges one quarantine entry (or a legacy file) for good.
pub fn purge_at(qroot: &Path, id: &str) -> Result<(), AvErr> {
    match parse_id(id)? {
        QId::Entry(id) => {
            let dir = qroot.join(id);
            match std::fs::symlink_metadata(&dir) {
                Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(&dir)
                    .map_err(|e| AvErr::internal(format!("Cannot delete the quarantine entry: {e}"))),
                _ => Err(AvErr::not_found("Quarantine entry not found")),
            }
        }
        QId::Legacy(name) => {
            let p = qroot.join(name);
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_file() => {
                    std::fs::remove_file(&p).map_err(|e| AvErr::internal(format!("Cannot delete the file: {e}")))
                }
                _ => Err(AvErr::not_found("Quarantine entry not found")),
            }
        }
    }
}

/// `<ts>_<name>` of the old quarantine.
fn legacy_parts(name: &str) -> (Option<i64>, &str) {
    match name.split_once('_') {
        Some((ts, rest)) if !ts.is_empty() && ts.chars().all(|c| c.is_ascii_digit()) => (ts.parse().ok(), rest),
        _ => (None, name),
    }
}

pub fn list_at(qroot: &Path) -> Vec<serde_json::Value> {
    let mut out: Vec<(String, serde_json::Value)> = Vec::new();
    for e in std::fs::read_dir(qroot).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        if m.file_type().is_dir() {
            if uuid::Uuid::parse_str(&name).is_err() {
                continue;
            }
            if let Some(meta) = read_meta(&e.path()) {
                out.push((meta.quarantined_at.clone(), item_json(&name, &meta)));
            }
        } else if m.file_type().is_file() {
            let (ts, rest) = legacy_parts(&name);
            let when = ts
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .or_else(|| chrono::DateTime::from_timestamp(m.mtime(), 0))
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default();
            let sha = if m.len() <= LEGACY_HASH_LIMIT {
                std::fs::File::open(e.path())
                    .and_then(|mut f| sha256_reader(&mut f))
                    .map(|(s, _)| s)
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let meta = Meta {
                original_path: rest.to_string(),
                domain: String::new(),
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode() & 0o7777,
                sha256: sha,
                size: m.len(),
                signature: None,
                quarantined_at: when.clone(),
            };
            out.push((when, item_json(&format!("legacy:{name}"), &meta)));
        }
    }
    // Newest first.
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out.into_iter().map(|(_, v)| v).collect()
}

// ── Production entry points ─────────────────────────────────────────────────

pub fn quarantine(domain: &str, path: &str, signature: Option<String>) -> Result<serde_json::Value, AvErr> {
    if !valid_domain(domain) {
        return Err(AvErr::bad("Invalid domain"));
    }
    quarantine_at(Path::new(QUARANTINE_ROOT), Path::new(WWW_ROOT), domain, path, signature)
}

/// The security scanner's caller: any file under `/var/www`, the site being
/// the first directory below it (or `/var/www` itself for a file directly in
/// it). Same symlink rules.
pub fn quarantine_www_path(path: &str) -> Result<serde_json::Value, AvErr> {
    let www = Path::new(WWW_ROOT);
    let rel = site_relative(www, "", path)?;
    let mut comps = rel.components();
    let site = match (comps.next(), comps.next()) {
        (Some(Component::Normal(first)), Some(_)) => first.to_string_lossy().into_owned(),
        _ => String::new(),
    };
    quarantine_at(Path::new(QUARANTINE_ROOT), www, &site, path, None)
}

pub fn restore(id: &str) -> Result<String, AvErr> {
    restore_at(Path::new(QUARANTINE_ROOT), Path::new(WWW_ROOT), id)
}

pub fn delete(domain: &str, path: &str) -> Result<(), AvErr> {
    if !valid_domain(domain) {
        return Err(AvErr::bad("Invalid domain"));
    }
    delete_at(Path::new(WWW_ROOT), domain, path)
}

pub fn purge(id: &str) -> Result<(), AvErr> {
    purge_at(Path::new(QUARANTINE_ROOT), id)
}

pub fn list() -> Vec<serde_json::Value> {
    list_at(Path::new(QUARANTINE_ROOT))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch {
        root: PathBuf,
    }
    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("dp-q-{tag}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("www/a.tld/public")).unwrap();
            std::fs::create_dir_all(root.join("www/b.tld")).unwrap();
            std::fs::create_dir_all(root.join("outside")).unwrap();
            Scratch { root }
        }
        fn www(&self) -> PathBuf {
            self.root.join("www")
        }
        fn q(&self) -> PathBuf {
            self.root.join("q")
        }
        fn p(&self, rel: &str) -> String {
            self.root.join(rel).to_string_lossy().into_owned()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn relative_paths_refuse_traversal_and_other_sites() {
        let www = Path::new("/var/www");
        assert_eq!(site_relative(www, "a.tld", "/var/www/a.tld/public/x.php").unwrap(), PathBuf::from("public/x.php"));
        for bad in [
            "/var/www/a.tld/../b.tld/x.php",
            "/var/www/a.tld/public/../../etc/passwd",
            "/var/www/b.tld/x.php",
            "/var/www/a.tldx/x.php",
            "/var/www/a.tld",
            "/var/www/a.tld/",
            "var/www/a.tld/x",
            "/etc/passwd",
        ] {
            assert_eq!(site_relative(www, "a.tld", bad).unwrap_err().status, 400, "{bad}");
        }
        assert!(valid_domain("a.tld") && !valid_domain("..") && !valid_domain("a..tld") && !valid_domain("a/b.tld"));
    }

    #[test]
    fn symlinks_are_refused_everywhere() {
        let s = Scratch::new("sym");
        std::fs::write(s.root.join("outside/secret"), b"x").unwrap();
        // Directory symlink inside the site pointing outside.
        std::os::unix::fs::symlink(s.root.join("outside"), s.www().join("a.tld/public/link")).unwrap();
        let e = quarantine_at(&s.q(), &s.www(), "a.tld", &s.p("www/a.tld/public/link/secret"), None).unwrap_err();
        assert_eq!(e.status, 400);
        // Leaf symlink.
        std::os::unix::fs::symlink(s.root.join("outside/secret"), s.www().join("a.tld/public/leaf")).unwrap();
        let e = quarantine_at(&s.q(), &s.www(), "a.tld", &s.p("www/a.tld/public/leaf"), None).unwrap_err();
        assert_eq!(e.status, 400);
        assert_eq!(delete_at(&s.www(), "a.tld", &s.p("www/a.tld/public/leaf")).unwrap_err().status, 400);
        // Site root itself a symlink to another site.
        std::fs::write(s.www().join("b.tld/x"), b"x").unwrap();
        std::os::unix::fs::symlink(s.www().join("b.tld"), s.www().join("c.tld")).unwrap();
        let e = quarantine_at(&s.q(), &s.www(), "c.tld", &s.p("www/c.tld/x"), None).unwrap_err();
        assert_eq!(e.status, 400);
        assert!(s.root.join("outside/secret").exists() && s.www().join("b.tld/x").exists());
        // Missing site / file.
        assert_eq!(quarantine_at(&s.q(), &s.www(), "z.tld", &s.p("www/z.tld/x"), None).unwrap_err().status, 404);
        assert_eq!(quarantine_at(&s.q(), &s.www(), "a.tld", &s.p("www/a.tld/nope"), None).unwrap_err().status, 404);
        // A directory is not a regular file.
        assert_eq!(quarantine_at(&s.q(), &s.www(), "a.tld", &s.p("www/a.tld/public"), None).unwrap_err().status, 400);
    }

    #[test]
    fn quarantine_restore_round_trip() {
        let s = Scratch::new("rt");
        let f = s.www().join("a.tld/public/evil.php");
        std::fs::write(&f, b"<?php evil(); ?>").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let _ = std::os::unix::fs::chown(&f, Some(1234), Some(2345));
        let before = std::fs::metadata(&f).unwrap();

        let item = quarantine_at(&s.q(), &s.www(), "a.tld", &f.to_string_lossy(), Some("Php.Test".into())).unwrap();
        assert!(!f.exists());
        let id = item["quarantine_id"].as_str().unwrap().to_string();
        assert_eq!(item["domain"], "a.tld");
        assert_eq!(item["original_path"], f.to_string_lossy().as_ref());
        assert_eq!(item["signature"], "Php.Test");
        assert_eq!(item["size"], 16);
        assert_eq!(item["mode"], 0o640);
        assert_eq!(item["uid"], before.uid());
        assert_eq!(item["sha256"].as_str().unwrap().len(), 64);
        let dir = s.q().join(&id);
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(dir.join("file")).unwrap().mode() & 0o777, 0);
        assert_eq!(std::fs::metadata(s.q()).unwrap().mode() & 0o777, 0o700);
        let meta = read_meta(&dir).unwrap();
        assert_eq!(item_json(&id, &meta), item);

        let listed = list_at(&s.q());
        assert_eq!(listed, vec![item.clone()]);

        // Destination taken: refused, quarantine kept.
        std::fs::write(&f, b"new").unwrap();
        assert_eq!(restore_at(&s.q(), &s.www(), &id).unwrap_err().status, 409);
        std::fs::remove_file(&f).unwrap();

        let path = restore_at(&s.q(), &s.www(), &id).unwrap();
        assert_eq!(path, f.to_string_lossy());
        assert_eq!(std::fs::read(&f).unwrap(), b"<?php evil(); ?>");
        let after = std::fs::metadata(&f).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert!(!dir.exists());
        assert!(list_at(&s.q()).is_empty());
        assert_eq!(restore_at(&s.q(), &s.www(), &id).unwrap_err().status, 404);
    }

    /// The production path: `/var/www` and the quarantine are separate bind
    /// mounts, so both moves are copies.
    #[test]
    fn cross_mount_copy_keeps_owner_and_mode() {
        let s = Scratch::new("copy");
        let f = s.www().join("a.tld/public/evil.php");
        std::fs::write(&f, b"payload").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o6750)).unwrap();
        let _ = std::os::unix::fs::chown(&f, Some(1234), Some(2345));
        let before = std::fs::metadata(&f).unwrap();

        let item = quarantine_impl(&s.q(), &s.www(), "a.tld", &f.to_string_lossy(), None, true).unwrap();
        assert!(!f.exists());
        let id = item["quarantine_id"].as_str().unwrap().to_string();
        assert_eq!(item["uid"], before.uid());
        assert_eq!(item["gid"], before.gid());
        assert_eq!(item["mode"], before.mode() & 0o7777);
        assert_eq!(item["size"], 7);
        let qf = s.q().join(&id).join("file");
        assert_eq!(std::fs::metadata(&qf).unwrap().mode() & 0o7777, 0);
        assert_eq!(read_meta(&s.q().join(&id)).unwrap().uid, before.uid());

        restore_impl(&s.q(), &s.www(), &id, true).unwrap();
        let after = std::fs::metadata(&f).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"payload");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.mode() & 0o7777, 0o0750, "setuid/setgid dropped");
        assert!(!s.q().join(&id).exists());
        assert_eq!(restored_mode(0o4755), 0o755);
        assert_eq!(restored_mode(0o1777), 0o1777);
    }

    #[test]
    fn restore_refuses_a_changed_file_and_purge_removes_it() {
        let s = Scratch::new("sha");
        let f = s.www().join("a.tld/x.js");
        std::fs::write(&f, b"bad").unwrap();
        let item = quarantine_at(&s.q(), &s.www(), "a.tld", &f.to_string_lossy(), None).unwrap();
        let id = item["quarantine_id"].as_str().unwrap();
        assert!(item["signature"].is_null());
        let qf = s.q().join(id).join("file");
        std::fs::set_permissions(&qf, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&qf, b"tampered").unwrap();
        assert_eq!(restore_at(&s.q(), &s.www(), id).unwrap_err().status, 409);
        assert!(!f.exists());
        purge_at(&s.q(), id).unwrap();
        assert!(!s.q().join(id).exists());
        assert_eq!(purge_at(&s.q(), id).unwrap_err().status, 404);
        assert_eq!(purge_at(&s.q(), "../../etc").unwrap_err().status, 400);
        assert_eq!(restore_at(&s.q(), &s.www(), "nope").unwrap_err().status, 400);
    }

    #[test]
    fn legacy_files_are_listed_but_not_restorable() {
        let s = Scratch::new("legacy");
        std::fs::create_dir_all(s.q()).unwrap();
        std::fs::write(s.q().join("1700000000_shell.php"), b"old").unwrap();
        std::fs::create_dir_all(s.q().join("not-a-uuid")).unwrap();
        let l = list_at(&s.q());
        assert_eq!(l.len(), 1);
        assert_eq!(l[0]["quarantine_id"], "legacy:1700000000_shell.php");
        assert_eq!(l[0]["original_path"], "shell.php");
        assert_eq!(l[0]["quarantined_at"], "2023-11-14T22:13:20Z");
        assert!(l[0]["signature"].is_null());
        assert_eq!(l[0]["size"], 3);
        let e = restore_at(&s.q(), &s.www(), "legacy:1700000000_shell.php").unwrap_err();
        assert_eq!((e.status, e.msg.as_str()), (409, "No metadata for this file"));
        assert_eq!(purge_at(&s.q(), "legacy:../x").unwrap_err().status, 400);
        purge_at(&s.q(), "legacy:1700000000_shell.php").unwrap();
        assert!(list_at(&s.q()).is_empty());
    }

    #[test]
    fn delete_removes_only_regular_files_of_the_site() {
        let s = Scratch::new("del");
        let f = s.www().join("a.tld/public/x.php");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(delete_at(&s.www(), "a.tld", &s.p("www/b.tld/../a.tld/public/x.php")).unwrap_err().status, 400);
        delete_at(&s.www(), "a.tld", &f.to_string_lossy()).unwrap();
        assert!(!f.exists());
        assert_eq!(delete_at(&s.www(), "a.tld", &f.to_string_lossy()).unwrap_err().status, 404);
    }

    #[test]
    fn www_level_site_for_the_security_caller() {
        // site "" is www itself: a file directly under it resolves.
        let s = Scratch::new("www");
        std::fs::write(s.www().join("top.php"), b"x").unwrap();
        let item = quarantine_at(&s.q(), &s.www(), "", &s.p("www/top.php"), None).unwrap();
        assert_eq!(item["domain"], "");
        let id = item["quarantine_id"].as_str().unwrap();
        restore_at(&s.q(), &s.www(), id).unwrap();
        assert!(s.www().join("top.php").exists());
    }
}
