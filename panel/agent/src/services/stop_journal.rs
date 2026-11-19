//! The journal of containers an app data operation stopped and has not yet
//! started again.
//!
//! `volume_backup::with_stopped` restarts what it stopped whatever happens
//! INSIDE the agent, but not if the agent itself dies (SIGKILL, OOM, power
//! loss) with the app stopped. The backend's auto-healer is no answer: it can
//! be disabled and only watches template apps. So each operation writes, BEFORE
//! stopping a container, an entry naming it; the entry goes when the containers
//! are running again; and at startup, before serving anything, the agent starts
//! every container still listed, then empties the journal.
//!
//! One entry per operation (several can run at once on different apps). The
//! file is rewritten atomically (temporary 0600 file, fsync, rename) under an
//! in-process lock, so a crash leaves either the old or the new journal.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Under `/var/lib/dockpanel`, which the agent unit lists in `ReadWritePaths`.
pub const JOURNAL_PATH: &str = "/var/lib/dockpanel/backup-stops.json";

static LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoppedContainer {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopEntry {
    pub op_id: String,
    /// What stopped them, for the log ("backup demo-v-x-...", "restore ...").
    pub operation: String,
    pub started_at: String,
    pub containers: Vec<StoppedContainer>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct JournalFile {
    operations: Vec<StopEntry>,
}

#[derive(Debug, Clone)]
pub struct StopJournal {
    path: PathBuf,
}

impl StopJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The journal the agent uses.
    pub fn system() -> Self {
        Self::new(JOURNAL_PATH)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<JournalFile, String> {
        match std::fs::read(&self.path) {
            Ok(b) if b.is_empty() => Ok(JournalFile::default()),
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("Unreadable stop journal {}: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(JournalFile::default()),
            Err(e) => Err(format!("Failed to read stop journal {}: {e}", self.path.display())),
        }
    }

    fn store(&self, j: &JournalFile) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if j.operations.is_empty() {
            return match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("Failed to clear stop journal {}: {e}", self.path.display())),
            };
        }
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
        let tmp = dir.join(format!(".backup-stops.{:016x}.tmp", rand::random::<u64>()));
        let body = serde_json::to_vec_pretty(j).map_err(|e| format!("Failed to encode stop journal: {e}"))?;
        let write = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = write {
            std::fs::remove_file(&tmp).ok();
            return Err(format!("Failed to write stop journal {}: {e}", self.path.display()));
        }
        Ok(())
    }

    fn update(&self, f: impl FnOnce(&mut JournalFile)) -> Result<(), String> {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut j = self.load()?;
        f(&mut j);
        self.store(&j)
    }

    /// Insert or replace the entry of `entry.op_id`.
    pub fn record(&self, entry: &StopEntry) -> Result<(), String> {
        self.update(|j| {
            j.operations.retain(|e| e.op_id != entry.op_id);
            j.operations.push(entry.clone());
        })
    }

    /// Drop the entry of `op_id` (its containers are running again).
    pub fn remove(&self, op_id: &str) -> Result<(), String> {
        self.update(|j| j.operations.retain(|e| e.op_id != op_id))
    }

    pub fn entries(&self) -> Result<Vec<StopEntry>, String> {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        Ok(self.load()?.operations)
    }

    /// At startup: start every container still listed (`docker start` on a
    /// running one is a no-op), log each, then empty the journal. Returns
    /// `(started, failed)`.
    pub async fn recover<C: super::volume_backup::ContainerControl>(&self, ctl: &C) -> (usize, usize) {
        let entries = match self.entries() {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("{e} - containers stopped by an interrupted backup may still be down");
                return (0, 0);
            }
        };
        let (mut started, mut failed) = (0, 0);
        for entry in &entries {
            for c in &entry.containers {
                match ctl.start(&c.id).await {
                    Ok(()) => {
                        started += 1;
                        tracing::warn!(
                            "Started container {} again: it was stopped by '{}' ({}), which the agent did not finish",
                            c.name, entry.operation, entry.started_at
                        );
                    }
                    Err(e) => {
                        failed += 1;
                        tracing::error!(
                            "Failed to start container {} stopped by the interrupted '{}': {e}",
                            c.name, entry.operation
                        );
                    }
                }
            }
        }
        if !entries.is_empty() {
            if let Err(e) = self.update(|j| j.operations.clear()) {
                tracing::error!("{e}");
            }
        }
        (started, failed)
    }
}

#[cfg(test)]
pub(crate) fn test_journal() -> StopJournal {
    StopJournal::new(
        std::env::temp_dir()
            .join(format!("dp-stopj-{:016x}", rand::random::<u64>()))
            .join("backup-stops.json"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex as StdMutex};

    fn entry(op: &str, ids: &[&str]) -> StopEntry {
        StopEntry {
            op_id: op.into(),
            operation: format!("backup {op}"),
            started_at: "2026-11-19 03:30:00".into(),
            containers: ids.iter().map(|i| StoppedContainer { id: i.to_string(), name: format!("n-{i}") }).collect(),
        }
    }

    #[test]
    fn entries_are_written_replaced_and_removed_atomically() {
        let j = test_journal();
        j.record(&entry("op1", &["a"])).unwrap();
        j.record(&entry("op2", &["b"])).unwrap();
        j.record(&entry("op1", &["a", "c"])).unwrap();
        let e = j.entries().unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e.iter().find(|x| x.op_id == "op1").unwrap().containers.len(), 2);
        let mode = std::fs::metadata(j.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // No temporary left beside it.
        let dir = j.path().parent().unwrap();
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
        j.remove("op1").unwrap();
        assert_eq!(j.entries().unwrap(), vec![entry("op2", &["b"])]);
        j.remove("op2").unwrap();
        assert!(!j.path().exists(), "an empty journal is no file");
        assert!(j.entries().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[derive(Default)]
    struct Fake {
        started: Arc<StdMutex<Vec<String>>>,
        fail: Option<String>,
    }
    impl super::super::volume_backup::ContainerControl for Fake {
        async fn stop(&self, _id: &str) -> Result<(), String> {
            Ok(())
        }
        async fn start(&self, id: &str) -> Result<(), String> {
            self.started.lock().unwrap().push(id.to_string());
            if self.fail.as_deref() == Some(id) { Err("refused".into()) } else { Ok(()) }
        }
    }

    #[tokio::test]
    async fn startup_starts_everything_listed_then_empties_the_journal() {
        let j = test_journal();
        j.record(&entry("op1", &["a", "b"])).unwrap();
        j.record(&entry("op2", &["c"])).unwrap();
        let f = Fake { fail: Some("b".into()), ..Default::default() };
        assert_eq!(j.recover(&f).await, (2, 1));
        assert_eq!(*f.started.lock().unwrap(), ["a", "b", "c"]);
        assert!(j.entries().unwrap().is_empty());
        // Nothing listed: nothing started.
        let f2 = Fake::default();
        assert_eq!(j.recover(&f2).await, (0, 0));
        assert!(f2.started.lock().unwrap().is_empty());
        std::fs::remove_dir_all(j.path().parent().unwrap()).ok();
    }
}
