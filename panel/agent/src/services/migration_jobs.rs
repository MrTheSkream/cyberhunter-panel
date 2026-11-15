//! In-memory progress jobs for long migration steps (05-import-hestia, W1-J).
//!
//! A job is a tokio task plus a state row the backend polls through
//! `GET /migration/jobs/{job_id}`. State lives in memory only: an agent restart
//! loses it and the poll answers 404, which the backend treats as a retryable
//! failure (the ledger, not this map, is the durable record).
//!
//! Key convention: `<migration_id>:<item>` (for example
//! `3f0c...:site:example.com`). [`cancel_migration`] - called by `cleanup` -
//! aborts and forgets every job whose key starts with the migration id, so
//! other workstreams should follow it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{LazyLock, Mutex};

/// Finished jobs are kept this long, then forgotten.
const RETENTION_SECS: u64 = 6 * 3600;
/// Bound on the warnings one job can accumulate.
const MAX_WARNINGS: usize = 500;

struct JobState {
    kind: String,
    key: String,
    state: &'static str,
    phase: String,
    bytes_done: u64,
    bytes_total: u64,
    message: String,
    warnings: Vec<String>,
    report: Option<serde_json::Value>,
    error: Option<String>,
    updated_at: u64,
    finished_at: Option<u64>,
    abort: Option<tokio::task::AbortHandle>,
}

static JOBS: LazyLock<Mutex<HashMap<String, JobState>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn jobs() -> std::sync::MutexGuard<'static, HashMap<String, JobState>> {
    JOBS.lock().unwrap_or_else(|p| p.into_inner())
}

fn prune(map: &mut HashMap<String, JobState>) {
    let t = now();
    map.retain(|_, j| match j.finished_at {
        Some(f) => t.saturating_sub(f) < RETENTION_SECS,
        None => true,
    });
}

/// Handle given to a running job to report progress and warnings.
#[derive(Clone)]
pub struct JobHandle {
    id: String,
}

impl JobHandle {
    /// The job's id (also the suffix of its `.import-<id>` work directory).
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn progress(&self, phase: &str, done: u64, total: u64, msg: &str) {
        if let Some(j) = jobs().get_mut(&self.id) {
            j.phase = phase.to_string();
            j.bytes_done = done;
            j.bytes_total = total;
            j.message = msg.to_string();
            j.updated_at = now();
        }
    }

    pub fn warn(&self, w: String) {
        if let Some(j) = jobs().get_mut(&self.id) {
            if j.warnings.len() < MAX_WARNINGS && !j.warnings.contains(&w) {
                j.warnings.push(w);
            }
            j.updated_at = now();
        }
    }

    /// Warnings recorded so far (for the job's own report).
    pub fn warnings(&self) -> Vec<String> {
        jobs().get(&self.id).map(|j| j.warnings.clone()).unwrap_or_default()
    }
}

fn finish(id: &str, result: Result<serde_json::Value, String>) {
    let mut map = jobs();
    if let Some(j) = map.get_mut(id) {
        let t = now();
        match result {
            Ok(report) => {
                j.state = "done";
                j.report = Some(report);
                j.phase = "done".into();
            }
            Err(e) => {
                j.state = "failed";
                j.error = Some(e);
            }
        }
        j.updated_at = t;
        j.finished_at = Some(t);
        j.abort = None;
    }
}

/// Starts a job and returns its id; the same `(kind, key)` already running
/// returns the existing id. Must be called from inside the tokio runtime.
pub fn spawn<F, Fut>(kind: &str, key: &str, f: F) -> String
where
    F: FnOnce(JobHandle) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>> + Send + 'static,
{
    let id = {
        let mut map = jobs();
        prune(&mut map);
        if let Some((id, _)) = map
            .iter()
            .find(|(_, j)| j.state == "running" && j.kind == kind && j.key == key)
        {
            return id.clone();
        }
        let id = uuid::Uuid::new_v4().to_string();
        map.insert(
            id.clone(),
            JobState {
                kind: kind.to_string(),
                key: key.to_string(),
                state: "running",
                phase: "queued".into(),
                bytes_done: 0,
                bytes_total: 0,
                message: String::new(),
                warnings: Vec::new(),
                report: None,
                error: None,
                updated_at: now(),
                finished_at: None,
                abort: None,
            },
        );
        id
    };

    let fut = f(JobHandle { id: id.clone() });
    let work = tokio::spawn(fut);
    if let Some(j) = jobs().get_mut(&id) {
        j.abort = Some(work.abort_handle());
    }
    let sup_id = id.clone();
    // Supervisor: a panic or an abort ends the job as `failed`, never leaves it
    // `running` forever.
    tokio::spawn(async move {
        let result = match work.await {
            Ok(r) => r,
            Err(e) if e.is_cancelled() => Err("job cancelled".into()),
            Err(_) => Err("job panicked".into()),
        };
        finish(&sup_id, result);
    });
    id
}

/// Job state as served by `GET /migration/jobs/{job_id}`.
pub fn get(job_id: &str) -> Option<serde_json::Value> {
    let mut map = jobs();
    prune(&mut map);
    let j = map.get(job_id)?;
    Some(serde_json::json!({
        "job_id": job_id,
        "kind": j.kind,
        "key": j.key,
        "state": j.state,
        "phase": j.phase,
        "bytes_done": j.bytes_done,
        "bytes_total": j.bytes_total,
        "message": j.message,
        "warnings": j.warnings,
        "report": j.report,
        "error": j.error,
        "updated_at": j.updated_at,
    }))
}

/// Aborts and forgets every job of `migration_id` (key prefix). Returns the ids
/// of the jobs that were still running, so the caller can sweep their work dirs.
pub fn cancel_migration(migration_id: &str) -> Vec<String> {
    let prefix = format!("{migration_id}:");
    let mut map = jobs();
    let ids: Vec<String> = map
        .iter()
        .filter(|(_, j)| j.key == migration_id || j.key.starts_with(&prefix))
        .map(|(id, _)| id.clone())
        .collect();
    let mut running = Vec::new();
    for id in ids {
        if let Some(j) = map.remove(&id) {
            if let Some(a) = j.abort {
                a.abort();
                running.push(id);
            }
        }
    }
    running
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_done(id: &str) -> serde_json::Value {
        for _ in 0..200 {
            let v = get(id).unwrap();
            if v["state"] != "running" {
                return v;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("job {id} never finished");
    }

    #[tokio::test]
    async fn job_reports_progress_and_result() {
        let id = spawn("test", "m1:a", |h| async move {
            h.progress("extract", 5, 10, "half");
            h.warn("w1".into());
            h.warn("w1".into());
            Ok(serde_json::json!({ "x": 1 }))
        });
        let v = wait_done(&id).await;
        assert_eq!(v["state"], "done");
        assert_eq!(v["report"]["x"], 1);
        assert_eq!(v["bytes_total"], 10);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
        assert!(v["error"].is_null());
    }

    #[tokio::test]
    async fn same_kind_key_while_running_returns_existing_id() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let a = spawn("test", "m2:a", |_h| async move {
            let _ = rx.await;
            Ok(serde_json::json!({}))
        });
        let b = spawn("test", "m2:a", |_h| async move { Ok(serde_json::json!({})) });
        assert_eq!(a, b);
        let c = spawn("other", "m2:a", |_h| async move { Ok(serde_json::json!({})) });
        assert_ne!(a, c);
        let _ = tx.send(());
        wait_done(&a).await;
    }

    #[tokio::test]
    async fn failure_and_panic_end_as_failed() {
        let id = spawn("test", "m3:a", |_h| async move { Err("boom".to_string()) });
        let v = wait_done(&id).await;
        assert_eq!(v["state"], "failed");
        assert_eq!(v["error"], "boom");
        let id = spawn("test", "m3:b", |_h| async move {
            if true {
                panic!("x");
            }
            Ok(serde_json::json!({}))
        });
        let v = wait_done(&id).await;
        assert_eq!(v["state"], "failed");
    }

    #[tokio::test]
    async fn cancel_migration_removes_its_jobs_only() {
        let a = spawn("test", "m4:x", |_h| async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(serde_json::json!({}))
        });
        let b = spawn("test", "m5:x", |_h| async move { Ok(serde_json::json!({})) });
        let cancelled = cancel_migration("m4");
        assert_eq!(cancelled, vec![a.clone()]);
        assert!(get(&a).is_none());
        assert!(get(&b).is_some());
        assert!(get("nope").is_none());
    }
}
