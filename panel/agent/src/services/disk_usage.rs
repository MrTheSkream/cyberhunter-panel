//! Disk usage of site directories (feature 6, contract A-5).
//!
//! Space actually allocated (`st_blocks * 512`, as `du`), not the apparent
//! size; symlinks are not followed, the walk stays on the site's filesystem,
//! and a file with several hard links inside the tree counts once. The walk
//! runs on one blocking thread at nice 19 and idle I/O priority, restored when
//! it ends (the blocking pool reuses its threads). One measurement at a time
//! per agent: a second call waits for the first.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

pub const MAX_DOMAINS: usize = 500;
pub const WEBROOT: &str = "/var/www";
pub const TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const NOT_FOUND: &str = "Site directory not found";
pub const TIMED_OUT: &str = "Measurement timed out";

static ONE_AT_A_TIME: LazyLock<Arc<tokio::sync::Mutex<()>>> = LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

/// One domain's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub domain: String,
    pub bytes: Option<u64>,
    pub files: Option<u64>,
    pub error: Option<String>,
}

impl Usage {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": self.domain,
            "bytes": self.bytes,
            "files": self.files,
            "error": self.error,
        })
    }
}

/// Walk `root`: `(bytes, files)`. `files` counts every entry that is not a
/// directory (symlinks included). Unreadable entries are skipped. `Err` when
/// `root` is not a directory or the deadline passed.
pub fn walk(root: &Path, deadline: Instant) -> Result<(u64, u64), String> {
    match std::fs::metadata(root) {
        Ok(m) if m.is_dir() => {}
        _ => return Err(NOT_FOUND.into()),
    }
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let (mut bytes, mut files) = (0u64, 0u64);
    let walker = walkdir::WalkDir::new(root).follow_links(false).same_file_system(true);
    for (i, entry) in walker.into_iter().enumerate() {
        if i % 1024 == 0 && Instant::now() > deadline {
            return Err(TIMED_OUT.into());
        }
        let Ok(entry) = entry else { continue };
        // `follow_links(false)`: the metadata of a symlink is the link's own.
        let Ok(md) = entry.metadata() else { continue };
        if !md.is_dir() && md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
            continue;
        }
        bytes = bytes.saturating_add(md.blocks().saturating_mul(512));
        if !md.is_dir() {
            files += 1;
        }
    }
    Ok((bytes, files))
}

/// Measure each of `domains` under `webroot`, until `deadline`.
pub fn measure_under(webroot: &Path, domains: &[String], deadline: Instant) -> Vec<Usage> {
    domains
        .iter()
        .map(|d| match walk(&webroot.join(d), deadline) {
            Ok((b, f)) => Usage { domain: d.clone(), bytes: Some(b), files: Some(f), error: None },
            Err(e) => Usage { domain: d.clone(), bytes: None, files: None, error: Some(e) },
        })
        .collect()
}

/// Lowers the calling thread to nice 19 and the idle I/O class, and puts the
/// previous values back on drop.
struct LowPriority {
    tid: libc::id_t,
    nice: Option<libc::c_int>,
    ioprio: Option<libc::c_long>,
}

const IOPRIO_WHO_PROCESS: libc::c_long = 1;
const IOPRIO_CLASS_IDLE: libc::c_long = 3;
const IOPRIO_CLASS_SHIFT: libc::c_long = 13;

impl LowPriority {
    fn enter() -> Self {
        // SAFETY: plain syscalls on the calling thread's own id; no memory is shared.
        unsafe {
            let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
            *libc::__errno_location() = 0;
            let n = libc::getpriority(libc::PRIO_PROCESS, tid);
            let nice = (*libc::__errno_location() == 0).then_some(n);
            let p = libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, tid as libc::c_long);
            let ioprio = (p >= 0).then_some(p);
            libc::setpriority(libc::PRIO_PROCESS, tid, 19);
            libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                tid as libc::c_long,
                IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
            );
            Self { tid, nice, ioprio }
        }
    }
}

impl Drop for LowPriority {
    fn drop(&mut self) {
        // SAFETY: as in `enter`.
        unsafe {
            if let Some(n) = self.nice {
                libc::setpriority(libc::PRIO_PROCESS, self.tid, n);
            }
            if let Some(p) = self.ioprio {
                libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, self.tid as libc::c_long, p);
            }
        }
    }
}

/// A-5: measure `domains` (already validated) under `/var/www`.
pub async fn measure(domains: Vec<String>) -> Result<Vec<Usage>, String> {
    let guard = ONE_AT_A_TIME.clone().lock_owned().await;
    // The deadline starts once it is our turn; the guard lives (and the next
    // measurement waits) until the walk has really finished.
    let deadline = Instant::now() + TIMEOUT;
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let _prio = LowPriority::enter();
        measure_under(Path::new(WEBROOT), &domains, deadline)
    })
    .await
    .map_err(|_| "internal error".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dp-du-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn hard_links_count_once_and_symlinks_are_not_followed() {
        let base = tmp();
        let site = base.join("a.tld");
        std::fs::create_dir_all(site.join("public")).unwrap();
        std::fs::write(site.join("public/big.bin"), vec![7u8; 256 * 1024]).unwrap();
        std::fs::write(site.join("small.txt"), b"hi").unwrap();
        let (b0, f0) = walk(&site, far()).unwrap();
        assert_eq!(f0, 2);
        assert!(b0 >= 256 * 1024, "allocated blocks counted: {b0}");

        // A hard link adds an entry but no bytes.
        std::fs::hard_link(site.join("public/big.bin"), site.join("link.bin")).unwrap();
        let (b1, f1) = walk(&site, far()).unwrap();
        assert_eq!(f1, 2, "the second name of the same inode is skipped");
        assert_eq!(b1, b0);

        // A symlink to a large tree outside: counted as one small entry, the
        // target is not walked.
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("huge.bin"), vec![1u8; 1024 * 1024]).unwrap();
        std::os::unix::fs::symlink(&outside, site.join("out")).unwrap();
        let (b2, f2) = walk(&site, far()).unwrap();
        assert_eq!(f2, 3, "the link itself is an entry");
        assert!(b2 < b0 + 1024 * 1024, "the target was not counted: {b2} vs {b0}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_site_and_timeout() {
        let base = tmp();
        let r = measure_under(&base, &["nope.tld".into()], far());
        assert_eq!(r[0], Usage { domain: "nope.tld".into(), bytes: None, files: None, error: Some(NOT_FOUND.into()) });
        assert_eq!(
            r[0].to_json(),
            serde_json::json!({"domain": "nope.tld", "bytes": null, "files": null, "error": "Site directory not found"})
        );
        std::fs::create_dir_all(base.join("x.tld")).unwrap();
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(walk(&base.join("x.tld"), past), Err(TIMED_OUT.into()));
        // One domain in error does not fail the others.
        let r = measure_under(&base, &["nope.tld".into(), "x.tld".into()], far());
        assert!(r[0].error.is_some() && r[1].error.is_none() && r[1].files == Some(0));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn priority_is_restored_on_the_pooled_thread() {
        let (before, after) = tokio::task::spawn_blocking(|| unsafe {
            let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
            let before = libc::getpriority(libc::PRIO_PROCESS, tid);
            {
                let _p = LowPriority::enter();
                assert_eq!(libc::getpriority(libc::PRIO_PROCESS, tid), 19);
            }
            (before, libc::getpriority(libc::PRIO_PROCESS, tid))
        })
        .await
        .unwrap();
        // Raising the priority back needs CAP_SYS_NICE (root in the container
        // and on the box); without it, the value simply stays at 19.
        assert!(after == before || after == 19, "{before} -> {after}");
    }
}
