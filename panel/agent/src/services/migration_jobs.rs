//! In-memory progress jobs for long migration steps (05-import-hestia, W1-J).
//!
//! STEP 0 SKELETON (owner: W1). Signatures fixed by contract W1-J; W1 replaces
//! this whole file with the real implementation.
#![allow(dead_code)]

use std::future::Future;

/// Handle given to a running job to report progress and warnings.
#[derive(Clone)]
pub struct JobHandle {}

impl JobHandle {
    pub fn progress(&self, _phase: &str, _done: u64, _total: u64, _msg: &str) {}
    pub fn warn(&self, _w: String) {}
}

/// Starts a job and returns its id; the same `(kind, key)` already running
/// returns the existing id.
pub fn spawn<F, Fut>(_kind: &str, _key: &str, _f: F) -> String
where
    F: FnOnce(JobHandle) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>> + Send + 'static,
{
    String::new()
}

/// Job state as served by `GET /migration/jobs/{job_id}`.
pub fn get(_job_id: &str) -> Option<serde_json::Value> {
    None
}
