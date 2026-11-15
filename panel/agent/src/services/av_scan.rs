//! Antivirus scan of one site (feature 5, contract A-5).
//!
//! The agent walks `/var/www/<domain>` itself and streams each file to clamd
//! over its socket (`INSTREAM`): clamd needs no access to the site tree (its
//! AppArmor profile and the SFTP sites' 0750 directories stay as they are),
//! symlinks are never followed, and files above 25 MB are counted as skipped
//! instead of being silently ignored.
//!
//! Two passes, both on a dedicated thread at idle I/O priority: one counts the
//! regular files (progress total), the second reads them one at a time and
//! hands each to the async side through a channel of one slot, so at most a
//! couple of files are in memory and no path list of the tree is ever held
//! (the agent runs under `MemoryMax=512M`). Directories are opened from the
//! site root fd one component at a time with `O_NOFOLLOW`
//! ([`quarantine::open_dir_beneath`]) and listed from that fd, files are opened
//! relative to it, so a directory swapped for a symlink mid-scan can neither
//! make the agent read nor walk outside the site.

use crate::services::clamav::{self, AvErr, ScanReply};
use crate::services::migration_jobs::{self, JobHandle};
use crate::services::quarantine;
use std::ffi::OsStr;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Files above this are not sent (clamd's `MaxFileSize` is 25M).
pub const MAX_FILE: u64 = 25 * 1024 * 1024;
/// The web canary of `docs/guides/security-hardening.md`: outside any site,
/// excluded anyway.
pub const CANARY: &str = "/var/www/.dockpanel-canary";
pub const MAX_DETECTIONS: usize = 500;
/// How long a file is retried while clamd does not answer (signature reload).
const CLAMD_RETRY_WINDOW: Duration = Duration::from_secs(180);
const CLAMD_RETRY_PAUSE: Duration = Duration::from_secs(5);

static CURRENT: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

fn running(job: &Option<String>) -> bool {
    job.as_ref()
        .and_then(|id| migration_jobs::get(id))
        .map(|s| s["state"] == "running")
        .unwrap_or(false)
}

/// Walk the site whose root fd is `site_fd` (shown as `site_root`) without
/// following symlinks. `f` gets every regular file: its directory's fd, its
/// name there, its full path and its size. Only site-relative paths are kept
/// on the stack (never fds, so a wide tree cannot exhaust descriptors); each
/// directory is reopened from the root with `O_NOFOLLOW` on every component.
/// Unreadable directories are skipped. Returns false when `f` asked to stop.
pub fn walk<F>(site_fd: &OwnedFd, site_root: &Path, exclude: &Path, mut f: F) -> bool
where
    F: FnMut(&OwnedFd, &OsStr, &Path, u64) -> bool,
{
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let Ok(dir_fd) = quarantine::open_dir_beneath(site_fd, &rel) else { continue };
        let Ok(dir) = rustix::fs::Dir::read_from(&dir_fd) else { continue };
        for entry in dir.flatten() {
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            let full = site_root.join(&rel).join(name);
            if full == exclude {
                continue;
            }
            let Ok(st) = rustix::fs::statat(&dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) else {
                continue;
            };
            match rustix::fs::FileType::from_raw_mode(st.st_mode as _) {
                rustix::fs::FileType::Directory => stack.push(rel.join(name)),
                rustix::fs::FileType::RegularFile => {
                    if !f(&dir_fd, name, &full, st.st_size as u64) {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    true
}

/// Number of regular files of the site (pass one).
pub fn count_files(site_fd: &OwnedFd, site_root: &Path, exclude: &Path) -> u64 {
    let mut n = 0u64;
    walk(site_fd, site_root, exclude, |_, _, _, _| {
        n += 1;
        true
    });
    n
}

/// Idle I/O class for the calling thread (best effort, Linux only).
fn set_idle_io_priority() {
    #[cfg(target_os = "linux")]
    unsafe {
        const IOPRIO_WHO_PROCESS: libc::c_int = 1;
        const IOPRIO_CLASS_IDLE: libc::c_int = 3;
        // who = 0: the calling thread.
        libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13);
    }
}

/// One unit of work from the reader thread.
pub enum Item {
    File { path: String, size: u64, sha256: String, data: Vec<u8> },
    Skipped,
    Unreadable { path: String, error: String },
}

/// Read the file `name` of the directory `dir_fd` (shown as `path`) safely:
/// returns `Skipped` above [`MAX_FILE`].
pub fn read_item(dir_fd: &OwnedFd, name: &OsStr, path: &Path) -> Item {
    let shown = path.to_string_lossy().into_owned();
    let unreadable = |e: String| Item::Unreadable { path: shown.clone(), error: e };
    let fd = match rustix::fs::openat(
        dir_fd,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOCTTY
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => return unreadable(format!("cannot open: {e}")),
    };
    let f = std::fs::File::from(fd);
    let m = match f.metadata() {
        Ok(m) => m,
        Err(e) => return unreadable(format!("cannot stat: {e}")),
    };
    if !m.file_type().is_file() {
        return unreadable("no longer a regular file".into());
    }
    if m.len() > MAX_FILE {
        return Item::Skipped;
    }
    let mut data = Vec::with_capacity(m.len() as usize);
    // One byte more than the limit tells a file that grew meanwhile.
    if let Err(e) = f.take(MAX_FILE + 1).read_to_end(&mut data) {
        return unreadable(format!("read failed: {e}"));
    }
    if data.len() as u64 > MAX_FILE {
        return Item::Skipped;
    }
    let sha256 = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&data))
    };
    Item::File { path: shown, size: data.len() as u64, sha256, data }
}

/// Counters and detections of one scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub scanned: u64,
    pub skipped: u64,
    pub errors: u64,
    pub infected: Vec<serde_json::Value>,
    pub truncated: bool,
}

impl Tally {
    pub fn record(&mut self, path: &str, size: u64, sha256: &str, reply: &ScanReply) -> Option<String> {
        match reply {
            ScanReply::Clean => {
                self.scanned += 1;
                None
            }
            ScanReply::Found(sig) => {
                self.scanned += 1;
                if self.infected.len() < MAX_DETECTIONS {
                    self.infected.push(serde_json::json!({
                        "path": path, "signature": sig, "size": size, "sha256": sha256,
                    }));
                } else {
                    self.truncated = true;
                }
                None
            }
            ScanReply::Error(msg) => {
                self.errors += 1;
                Some(format!("{path}: {msg}"))
            }
        }
    }
}

/// Checks, then starts the scan job of `domain`. Returns its id.
pub async fn start(domain: &str) -> Result<String, AvErr> {
    if !quarantine::valid_domain(domain) {
        return Err(AvErr::bad("Invalid domain"));
    }
    let www = Path::new(quarantine::WWW_ROOT);
    // 404 when absent, 400 when it is not a plain directory.
    drop(quarantine::open_site(www, domain)?);
    if !clamav::is_installed().await || !clamav::ping().await {
        return Err(AvErr::precondition("ClamAV is not responding"));
    }
    let mut g = CURRENT.lock().unwrap_or_else(|p| p.into_inner());
    if running(&g) {
        return Err(AvErr::conflict("An antivirus scan is already running on this server"));
    }
    let d = domain.to_string();
    let id = migration_jobs::spawn("av_scan", domain, move |h| async move {
        run(h, www.to_path_buf(), d, PathBuf::from(clamav::socket_path())).await
    });
    *g = Some(id.clone());
    Ok(id)
}

/// The scan itself (paths injected for tests).
pub async fn run(h: JobHandle, www: PathBuf, domain: String, sock: PathBuf) -> Result<serde_json::Value, String> {
    let started = Instant::now();
    let site_root = www.join(&domain);
    let site_fd = quarantine::open_site(&www, &domain).map_err(|e| e.msg)?;
    let signatures_version = clamav::version_at(&sock).await.and_then(|v| v.signatures);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Item>(1);
    let total = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let total_w = total.clone();
    let root = site_root.clone();
    h.progress("scanning", 0, 0, "Counting files");
    std::thread::Builder::new()
        .name("av-scan".into())
        .spawn(move || {
            set_idle_io_priority();
            let exclude = PathBuf::from(CANARY);
            total_w.store(count_files(&site_fd, &root, &exclude), std::sync::atomic::Ordering::Relaxed);
            // Sentinel-free: the channel closing ends the scan.
            walk(&site_fd, &root, &exclude, |dir, name, full, _| {
                tx.blocking_send(read_item(dir, name, full)).is_ok()
            });
        })
        .map_err(|e| format!("Cannot start the scan thread: {e}"))?;

    let mut tally = Tally::default();
    let mut done = 0u64;
    while let Some(item) = rx.recv().await {
        done += 1;
        match item {
            Item::Skipped => tally.skipped += 1,
            Item::Unreadable { path, error } => {
                tally.errors += 1;
                h.warn(format!("{path}: {error}"));
            }
            Item::File { path, size, sha256, data } => {
                // A transport error on one file (reply timeout, connection
                // dropped) is that file's error when clamd still answers
                // PING; only clamd itself being down past the retry window
                // fails the scan.
                let mut first_failure: Option<Instant> = None;
                let reply = loop {
                    match clamav::instream_at(&sock, &data).await {
                        Ok(r) => break Some(r),
                        Err(e) => {
                            if clamav::ping_at(&sock).await {
                                tally.errors += 1;
                                h.warn(format!("{path}: clamd could not scan this file: {e}"));
                                break None;
                            }
                            let since = *first_failure.get_or_insert_with(Instant::now);
                            if since.elapsed() > CLAMD_RETRY_WINDOW {
                                return Err(format!("clamd stopped responding during the scan: {e}"));
                            }
                            h.progress("scanning", done - 1, total_of(&total, done), "Waiting for clamd");
                            tokio::time::sleep(CLAMD_RETRY_PAUSE).await;
                        }
                    }
                };
                if let Some(w) = reply.and_then(|r| tally.record(&path, size, &sha256, &r)) {
                    h.warn(w);
                }
            }
        }
        h.progress("scanning", done, total_of(&total, done), "Scanning");
    }

    Ok(serde_json::json!({
        "domain": domain,
        "files_scanned": tally.scanned,
        "files_skipped": tally.skipped,
        "files_errors": tally.errors,
        "signatures_version": signatures_version,
        "duration_ms": started.elapsed().as_millis() as u64,
        "infected": tally.infected,
        "truncated": tally.truncated,
    }))
}

/// The tree may change between the two passes.
fn total_of(total: &std::sync::atomic::AtomicU64, done: u64) -> u64 {
    total.load(std::sync::atomic::Ordering::Relaxed).max(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dp-avs-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn walk_counts_regular_files_only_and_never_follows_symlinks() {
        let d = scratch("walk");
        let site = d.join("www/a.tld");
        std::fs::create_dir_all(site.join("public/sub")).unwrap();
        std::fs::create_dir_all(d.join("outside")).unwrap();
        std::fs::write(site.join("public/a.php"), b"a").unwrap();
        std::fs::write(site.join("public/sub/b.js"), b"b").unwrap();
        std::fs::write(d.join("outside/c"), b"c").unwrap();
        std::fs::write(d.join("www/canary"), b"c").unwrap();
        std::os::unix::fs::symlink(d.join("outside"), site.join("public/dirlink")).unwrap();
        std::os::unix::fs::symlink(d.join("outside/c"), site.join("public/filelink")).unwrap();
        let fifo = std::ffi::CString::new(site.join("fifo").to_string_lossy().as_bytes()).unwrap();
        unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) };
        let site_fd = quarantine::open_site(&d.join("www"), "a.tld").unwrap();
        assert_eq!(count_files(&site_fd, &site, Path::new(CANARY)), 2);
        // The whole www tree, with an exclusion.
        let www_fd = quarantine::open_site(&d.join("www"), "").unwrap();
        let mut seen = Vec::new();
        walk(&www_fd, &d.join("www"), &d.join("www/canary"), |dir, name, p, size| {
            assert!(matches!(read_item(dir, name, p), Item::File { size: s, .. } if s == size));
            seen.push(p.strip_prefix(&d).unwrap().to_string_lossy().into_owned());
            true
        });
        seen.sort();
        assert_eq!(seen, vec!["www/a.tld/public/a.php", "www/a.tld/public/sub/b.js"]);
        // Stop on request.
        let mut n = 0;
        assert!(!walk(&site_fd, &site, Path::new(CANARY), |_, _, _, _| {
            n += 1;
            false
        }));
        assert_eq!(n, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn walk_does_not_descend_into_a_directory_swapped_for_a_symlink() {
        // open_dir_beneath refuses a symlinked component even when the stack
        // still names it as a directory.
        let d = scratch("swap");
        std::fs::create_dir_all(d.join("a.tld/sub")).unwrap();
        std::fs::create_dir_all(d.join("outside")).unwrap();
        std::fs::write(d.join("outside/secret"), b"x").unwrap();
        let fd = quarantine::open_site(&d, "a.tld").unwrap();
        std::fs::remove_dir(d.join("a.tld/sub")).unwrap();
        std::os::unix::fs::symlink(d.join("outside"), d.join("a.tld/sub")).unwrap();
        assert!(quarantine::open_dir_beneath(&fd, Path::new("sub")).is_err());
        assert_eq!(count_files(&fd, &d.join("a.tld"), Path::new(CANARY)), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn read_item_skips_big_files_and_refuses_symlinked_parents() {
        let d = scratch("read");
        let site = d.join("a.tld");
        std::fs::create_dir_all(site.join("dir")).unwrap();
        std::fs::write(site.join("dir/x"), b"hello").unwrap();
        let big = std::fs::File::create(site.join("big")).unwrap();
        big.set_len(MAX_FILE + 1).unwrap();
        std::fs::create_dir_all(d.join("outside")).unwrap();
        std::fs::write(d.join("outside/y"), b"secret").unwrap();
        std::os::unix::fs::symlink(d.join("outside"), site.join("link")).unwrap();
        std::os::unix::fs::symlink(d.join("outside/y"), site.join("leaf")).unwrap();
        let fd = quarantine::open_site(&d, "a.tld").unwrap();
        let dir = quarantine::open_dir_beneath(&fd, Path::new("dir")).unwrap();
        match read_item(&dir, OsStr::new("x"), &site.join("dir/x")) {
            Item::File { size, sha256, data, path } => {
                assert_eq!(size, 5);
                assert_eq!(data, b"hello");
                assert_eq!(sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
                assert_eq!(path, site.join("dir/x").to_string_lossy());
            }
            _ => panic!("expected a file"),
        }
        assert!(matches!(read_item(&fd, OsStr::new("big"), &site.join("big")), Item::Skipped));
        assert!(matches!(read_item(&fd, OsStr::new("leaf"), &site.join("leaf")), Item::Unreadable { .. }));
        assert!(quarantine::open_dir_beneath(&fd, Path::new("link")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tally_caps_detections() {
        let mut t = Tally::default();
        for i in 0..(MAX_DETECTIONS + 2) {
            t.record(&format!("/p{i}"), 1, "h", &ScanReply::Found("S".into()));
        }
        t.record("/ok", 1, "h", &ScanReply::Clean);
        assert!(t.record("/e", 1, "h", &ScanReply::Error("x ERROR".into())).is_some());
        assert_eq!(t.infected.len(), MAX_DETECTIONS);
        assert!(t.truncated);
        assert_eq!((t.scanned, t.errors), (MAX_DETECTIONS as u64 + 3, 1));
        assert_eq!(t.infected[0]["path"], "/p0");
    }

    /// A fake clamd on a fresh socket: answers PING and VERSION, decodes the
    /// INSTREAM framing for real, flags "EICAR", and drops the connection
    /// without a reply on "BOOM" (a file that makes the scan fail).
    fn fake_clamd() -> (PathBuf, PathBuf) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let sockdir = PathBuf::from(format!("/tmp/dpas{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&sockdir).unwrap();
        let sock = sockdir.join("c.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut cmd = Vec::new();
                    loop {
                        let b = s.read_u8().await.unwrap();
                        if b == 0 {
                            break;
                        }
                        cmd.push(b);
                    }
                    if cmd == b"zPING" {
                        s.write_all(b"PONG\0").await.unwrap();
                        return;
                    }
                    if cmd == b"zVERSION" {
                        s.write_all(b"ClamAV 1.4.3/27450/Sat Nov 15 03:12:00 2026\0").await.unwrap();
                        return;
                    }
                    let mut payload = Vec::new();
                    loop {
                        let n = s.read_u32().await.unwrap() as usize;
                        if n == 0 {
                            break;
                        }
                        let mut buf = vec![0u8; n];
                        s.read_exact(&mut buf).await.unwrap();
                        payload.extend_from_slice(&buf);
                    }
                    if payload.windows(4).any(|w| w == b"BOOM") {
                        return;
                    }
                    let r: &[u8] = if payload.windows(5).any(|w| w == b"EICAR") {
                        b"stream: Eicar-Test-Signature FOUND\0"
                    } else {
                        b"stream: OK\0"
                    };
                    s.write_all(r).await.unwrap();
                });
            }
        });
        (sockdir, sock)
    }

    /// Runs the scan job of `www/<domain>` against `sock` to its end.
    async fn run_job(www: &Path, domain: &str, sock: &Path) -> serde_json::Value {
        let (w, d, sk) = (www.to_path_buf(), domain.to_string(), sock.to_path_buf());
        let id = migration_jobs::spawn("av_scan_test", &www.to_string_lossy(), move |h| async move {
            run(h, w, d, sk).await
        });
        let mut v = serde_json::Value::Null;
        for _ in 0..500 {
            v = migration_jobs::get(&id).unwrap();
            if v["state"] != "running" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        v
    }

    /// End to end against a fake clamd that flags "EICAR".
    #[tokio::test]
    async fn scan_job_reports_detections() {
        let d = scratch("job");
        let www = d.join("www");
        std::fs::create_dir_all(www.join("s.tld/public")).unwrap();
        std::fs::write(www.join("s.tld/public/ok.php"), b"<?php echo 1;").unwrap();
        std::fs::write(www.join("s.tld/public/bad.php"), b"X5O EICAR test").unwrap();
        let big = std::fs::File::create(www.join("s.tld/big.zip")).unwrap();
        big.set_len(MAX_FILE + 10).unwrap();
        let (sockdir, sock) = fake_clamd();
        let v = run_job(&www, "s.tld", &sock).await;
        assert_eq!(v["state"], "done", "{v}");
        let r = &v["report"];
        assert_eq!(r["domain"], "s.tld");
        assert_eq!(r["files_scanned"], 2);
        assert_eq!(r["files_skipped"], 1);
        assert_eq!(r["files_errors"], 0);
        assert_eq!(r["signatures_version"], 27450);
        assert_eq!(r["truncated"], false);
        let inf = r["infected"].as_array().unwrap();
        assert_eq!(inf.len(), 1);
        assert_eq!(inf[0]["path"], www.join("s.tld/public/bad.php").to_string_lossy().as_ref());
        assert_eq!(inf[0]["signature"], "Eicar-Test-Signature");
        assert_eq!(inf[0]["size"], 14);
        assert_eq!(v["bytes_done"], 3);
        assert_eq!(v["bytes_total"], 3);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&sockdir);
    }

    /// One file clamd fails on while it still answers PING: counted as an
    /// error, the scan goes on with the others.
    #[tokio::test]
    async fn one_failing_file_does_not_fail_the_scan() {
        let d = scratch("boom");
        let www = d.join("www");
        std::fs::create_dir_all(www.join("s.tld/public")).unwrap();
        std::fs::write(www.join("s.tld/public/ok.php"), b"<?php echo 1;").unwrap();
        std::fs::write(www.join("s.tld/public/stuck.bin"), b"..BOOM..").unwrap();
        std::fs::write(www.join("s.tld/public/bad.php"), b"X5O EICAR test").unwrap();
        let (sockdir, sock) = fake_clamd();
        let v = run_job(&www, "s.tld", &sock).await;
        assert_eq!(v["state"], "done", "{v}");
        let r = &v["report"];
        assert_eq!(r["files_scanned"], 2);
        assert_eq!(r["files_errors"], 1);
        assert_eq!(r["infected"].as_array().unwrap().len(), 1);
        let warnings = v.to_string();
        assert!(warnings.contains("stuck.bin"), "{v}");
        assert!(!warnings.contains("BOOM"), "no file content in the warning: {v}");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&sockdir);
    }
}
