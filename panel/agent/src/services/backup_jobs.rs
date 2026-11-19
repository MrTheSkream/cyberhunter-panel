//! In-memory jobs for the long mail and DNS backup operations (lot 3).
//!
//! `POST /mail/archive`, `/mail/restore`, `/dns/archive` and `/dns/restore`
//! answer 202 `{"job_id"}` for anything that can outlast the panel's ~60 s
//! agent call, and the panel polls `GET /backup-jobs/{job_id}`, which answers
//! `{"status": "running|done|failed", "result": {...}|null, "error": "..."|null,
//! "error_code": 422|507|...|null}`.
//!
//! The work is a detached tokio task: it goes to the end even when nobody polls
//! any more (the panel gave up, restarted, lost the network). Finished jobs are
//! kept for [`RETENTION_SECS`], running ones until they finish. State is memory
//! only: an agent restart forgets every job and the poll answers 404, which the
//! panel reports as a failure of that target.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{LazyLock, Mutex};

use crate::services::volume_backup::VbError;

/// Finished jobs are kept this long (1 hour), then forgotten.
pub const RETENTION_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Done,
    Failed,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

struct Job {
    kind: String,
    status: JobStatus,
    result: Option<serde_json::Value>,
    error: Option<String>,
    error_code: Option<u16>,
    started_at: u64,
    finished_at: Option<u64>,
}

static JOBS: LazyLock<Mutex<HashMap<String, Job>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|p| p.into_inner())
}

fn prune_at(map: &mut HashMap<String, Job>, t: u64) {
    map.retain(|_, j| match j.finished_at {
        Some(f) => t.saturating_sub(f) < RETENTION_SECS,
        None => true,
    });
}

/// The HTTP status a failed job's error maps to (same table as the routes).
pub fn error_code(e: &VbError) -> u16 {
    match e {
        VbError::BadRequest(_) => 400,
        VbError::NotFound(_) => 404,
        VbError::Conflict(_) => 409,
        VbError::Integrity(_) => 422,
        VbError::NoSpace(_) => 507,
        VbError::Internal(_) => 500,
    }
}

fn finish(id: &str, outcome: Result<serde_json::Value, VbError>) {
    let mut map = jobs();
    let Some(job) = map.get_mut(id) else { return };
    job.finished_at = Some(now());
    match outcome {
        Ok(v) => {
            job.status = JobStatus::Done;
            job.result = Some(v);
        }
        Err(e) => {
            tracing::error!("Backup job {id} ({}) failed: {}", job.kind, e.message());
            job.status = JobStatus::Failed;
            job.error_code = Some(error_code(&e));
            job.error = Some(e.message().to_string());
        }
    }
}

/// Start `fut` as a detached job and return its id. `kind` is a short label
/// for the logs (`mail-archive`, `dns-restore`, ...), never a secret.
pub fn spawn<F>(kind: &str, fut: F) -> String
where
    F: Future<Output = Result<serde_json::Value, VbError>> + Send + 'static,
{
    let id = uuid::Uuid::new_v4().to_string();
    {
        let mut map = jobs();
        prune_at(&mut map, now());
        map.insert(
            id.clone(),
            Job {
                kind: kind.to_string(),
                status: JobStatus::Running,
                result: None,
                error: None,
                error_code: None,
                started_at: now(),
                finished_at: None,
            },
        );
    }
    let job_id = id.clone();
    let task = tokio::spawn(fut);
    // A second task observes the first, so a panic inside the work still ends
    // the job as `failed` instead of leaving it `running` for ever.
    tokio::spawn(async move {
        let outcome = match task.await {
            Ok(r) => r,
            Err(e) => Err(VbError::Internal(format!("Backup job aborted: {e}"))),
        };
        finish(&job_id, outcome);
    });
    id
}

/// The poll body of one job, or `None` when it is unknown (never existed,
/// expired, or the agent restarted since).
pub fn get(id: &str) -> Option<serde_json::Value> {
    let mut map = jobs();
    prune_at(&mut map, now());
    let j = map.get(id)?;
    Some(serde_json::json!({
        "job_id": id,
        "kind": j.kind,
        "status": j.status.as_str(),
        "result": j.result,
        "error": j.error,
        "error_code": j.error_code,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
    }))
}

/// A job id is a UUID: anything else is refused before the map is looked at.
pub fn is_valid_job_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok() && id.len() == 36
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_done(id: &str) -> serde_json::Value {
        for _ in 0..200 {
            let v = get(id).expect("job known");
            if v["status"] != "running" {
                return v;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("job {id} never finished");
    }

    #[tokio::test]
    async fn a_job_runs_then_reports_done_with_its_result() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let id = spawn("test", async move {
            rx.await.ok();
            Ok(serde_json::json!({"filename": "x"}))
        });
        let v = get(&id).unwrap();
        assert_eq!(v["status"], "running");
        assert!(v["result"].is_null());
        assert!(v["error"].is_null());
        tx.send(()).unwrap();
        let v = wait_done(&id).await;
        assert_eq!(v["status"], "done");
        assert_eq!(v["result"]["filename"], "x");
        assert!(v["error"].is_null());
        assert!(v["error_code"].is_null());
    }

    #[tokio::test]
    async fn a_failed_job_carries_its_message_and_http_code() {
        let id = spawn("test", async { Err(VbError::Integrity("Decryption failed".into())) });
        let v = wait_done(&id).await;
        assert_eq!(v["status"], "failed");
        assert_eq!(v["error"], "Decryption failed");
        assert_eq!(v["error_code"], 422);
        assert!(v["result"].is_null());

        let id = spawn("test", async { Err(VbError::NoSpace("full".into())) });
        assert_eq!(wait_done(&id).await["error_code"], 507);
    }

    #[tokio::test]
    async fn a_panicking_job_ends_failed_not_running() {
        let id = spawn("test", async {
            if true {
                panic!("boom");
            }
            Ok(serde_json::Value::Null)
        });
        let v = wait_done(&id).await;
        assert_eq!(v["status"], "failed");
        assert_eq!(v["error_code"], 500);
    }

    /// The job is detached: dropping everything the caller holds does not
    /// cancel it (the panel giving up on the HTTP call).
    #[tokio::test]
    async fn a_job_finishes_without_anyone_polling() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f2 = flag.clone();
        let id = spawn("test", async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            f2.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::Value::Null)
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(get(&id).unwrap()["status"], "done");
    }

    #[test]
    fn finished_jobs_expire_after_an_hour_running_ones_never() {
        let mut map = HashMap::new();
        let mk = |finished_at| Job {
            kind: "t".into(),
            status: JobStatus::Done,
            result: None,
            error: None,
            error_code: None,
            started_at: 0,
            finished_at,
        };
        map.insert("old".to_string(), mk(Some(1000)));
        map.insert("recent".to_string(), mk(Some(1000 + RETENTION_SECS)));
        map.insert("running".to_string(), mk(None));
        prune_at(&mut map, 1000 + RETENTION_SECS + 1);
        assert!(!map.contains_key("old"));
        assert!(map.contains_key("recent"));
        assert!(map.contains_key("running"));
    }

    #[test]
    fn unknown_and_malformed_ids() {
        assert!(get("6f9619ff-8b86-4011-b42d-00c04fc964ff").is_none());
        assert!(is_valid_job_id("6f9619ff-8b86-4011-b42d-00c04fc964ff"));
        assert!(!is_valid_job_id("../etc"));
        assert!(!is_valid_job_id(""));
        assert!(!is_valid_job_id("6f9619ff8b864011b42d00c04fc964ff"));
    }

    #[test]
    fn error_codes() {
        assert_eq!(error_code(&VbError::BadRequest(String::new())), 400);
        assert_eq!(error_code(&VbError::NotFound(String::new())), 404);
        assert_eq!(error_code(&VbError::Conflict(String::new())), 409);
        assert_eq!(error_code(&VbError::Internal(String::new())), 500);
    }
}
