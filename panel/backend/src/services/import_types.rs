//! Types shared by the HestiaCP import executors (05-import-hestia, W5-T).
//!
//! The executors of the other workstreams (`import_db`, `import_mail`,
//! `import_sftp`) take an [`ImportCtx`] and return [`ItemOutcome`]s that the
//! import loop writes to the `migration_items` ledger
//! (`services::migration_ledger`).

use std::time::{Duration, Instant};

use serde_json::Value;

/// Final state of one ledger item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemStatus {
    Done,
    Skipped,
    Warning,
    Failed,
}

/// Result of one import item. `details` never carries a secret (D11).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ItemOutcome {
    pub status: ItemStatus,
    pub message: String,
    pub details: serde_json::Value,
}

impl ItemOutcome {
    pub fn new(status: ItemStatus, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), details: serde_json::json!({}) }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ItemStatus::Failed, message)
    }

    pub fn done(message: impl Into<String>) -> Self {
        Self::new(ItemStatus::Done, message)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(ItemStatus::Warning, message)
    }

    pub fn skipped(message: impl Into<String>) -> Self {
        Self::new(ItemStatus::Skipped, message)
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Whether the item finished (with or without notes).
    pub fn is_success(&self) -> bool {
        matches!(self.status, ItemStatus::Done | ItemStatus::Warning)
    }
}

/// Progress callback: `(step, label, "pending"|"in_progress"|"done"|"error", message)`.
///
/// The one the import loop builds throttles `in_progress` events to one every
/// 2 s per step and redacts the message; terminal events always pass.
pub type ProgressFn = std::sync::Arc<dyn Fn(&str, &str, &str, Option<String>) + Send + Sync>;

/// Everything an executor needs to import one item.
///
/// `force` is set per call: true when the operator listed the item (for mail:
/// any item of the domain) in `force_items`.
#[derive(Clone)]
pub struct ImportCtx {
    pub db: sqlx::PgPool,
    pub agent: crate::services::agent::AgentHandle,
    pub server_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub migration_id: uuid::Uuid,
    pub agent_migration_id: String,
    pub jwt_secret: String,
    pub force: bool,
    pub progress: ProgressFn,
}

impl ImportCtx {
    /// The same context with `force` set for one item.
    pub fn with_force(&self, force: bool) -> Self {
        Self { force, ..self.clone() }
    }
}

// ──────────────────────────────────────────────────────────────
// Agent job polling (W1-J)
// ──────────────────────────────────────────────────────────────

/// How often an agent job is polled.
pub const JOB_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// A job that shows no progress (phase, bytes or `updated_at`) for this long is
/// declared stuck. There is no other ceiling: a 9 GB site copy takes as long as
/// it takes (D10).
pub const JOB_STALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// One poll of `GET /migration/jobs/{id}`, interpreted.
#[derive(Debug, Clone, PartialEq)]
pub enum JobPoll {
    Running { phase: String, bytes_done: u64, bytes_total: u64, message: String, updated_at: i64 },
    Done(Value),
    Failed(String),
}

/// Reads the job document of W1-J.
pub fn classify_job(v: &Value) -> JobPoll {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    match v.get("state").and_then(|x| x.as_str()) {
        Some("done") => {
            let mut report = v.get("report").cloned().filter(|r| !r.is_null()).unwrap_or_else(|| serde_json::json!({}));
            // Job-level warnings join the report's, so the caller sees one list.
            if let Some(w) = v.get("warnings").and_then(|w| w.as_array()).filter(|w| !w.is_empty())
                && let Some(o) = report.as_object_mut()
            {
                let mut all: Vec<Value> =
                    o.get("warnings").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                for x in w {
                    if !all.contains(x) {
                        all.push(x.clone());
                    }
                }
                o.insert("warnings".into(), Value::Array(all));
            }
            JobPoll::Done(report)
        }
        Some("failed") => {
            let e = s("error");
            JobPoll::Failed(if e.is_empty() { "the agent job failed".into() } else { e })
        }
        _ => JobPoll::Running {
            phase: s("phase"),
            bytes_done: n("bytes_done"),
            bytes_total: n("bytes_total"),
            message: s("message"),
            updated_at: v.get("updated_at").and_then(|x| x.as_i64()).unwrap_or(0),
        },
    }
}

/// A job error as the operator reads it. W1 prefixes a disk refusal with
/// `insufficient_disk:`.
pub fn describe_job_error(e: &str) -> String {
    match e.strip_prefix("insufficient_disk:") {
        Some(rest) => format!("Not enough disk space: {}", rest.trim()),
        None => e.to_string(),
    }
}

/// Human progress line: `extract: 1.2 GB / 3.4 GB (35%) - message`.
pub fn progress_message(phase: &str, done: u64, total: u64, message: &str) -> String {
    let mut out = if phase.is_empty() { "working".to_string() } else { phase.to_string() };
    if total > 0 {
        let pct = (done.min(total) as f64 / total as f64 * 100.0).round() as u64;
        out.push_str(&format!(": {} / {} ({pct}%)", fmt_bytes(done), fmt_bytes(total)));
    } else if done > 0 {
        out.push_str(&format!(": {}", fmt_bytes(done)));
    }
    if !message.is_empty() {
        out.push_str(" - ");
        out.push_str(message);
    }
    out
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[i]) }
}

/// Stall detector: progress is any change of phase, bytes or `updated_at`.
#[derive(Debug)]
pub struct StallClock {
    last: Option<(String, u64, i64)>,
    since: Instant,
    limit: Duration,
}

impl StallClock {
    pub fn new(now: Instant, limit: Duration) -> Self {
        Self { last: None, since: now, limit }
    }

    /// Records a sighting; returns true when the job moved.
    pub fn observe(&mut self, now: Instant, phase: &str, bytes_done: u64, updated_at: i64) -> bool {
        let sig = (phase.to_string(), bytes_done, updated_at);
        if self.last.as_ref() != Some(&sig) {
            self.last = Some(sig);
            self.since = now;
            true
        } else {
            false
        }
    }

    pub fn stalled(&self, now: Instant) -> bool {
        now.duration_since(self.since) >= self.limit
    }
}

/// Polls `GET /migration/jobs/{id}` every 3 s, emits progress (the loop's
/// [`ProgressFn`] keeps it to 1 event / 2 s), fails after 15 min without
/// progress or on 404 (the agent restarted and forgot the job: the item is
/// failed and the next run redoes it).
///
/// Transient agent errors (connection refused while the agent restarts, circuit
/// breaker open) do not fail the item by themselves: they count toward the
/// stall window like any other silence.
pub async fn wait_job(ctx: &ImportCtx, job_id: &str, step: &str, label: &str) -> Result<Value, String> {
    poll_job(&ctx.agent, job_id, |msg| (ctx.progress)(step, label, "in_progress", Some(msg))).await
}

/// The polling loop of [`wait_job`], without an [`ImportCtx`] (the analysis
/// job runs before any import exists). `on_progress` gets a line each time the
/// job moves.
pub async fn poll_job<F: FnMut(String)>(
    agent: &crate::services::agent::AgentHandle,
    job_id: &str,
    mut on_progress: F,
) -> Result<Value, String> {
    use crate::services::agent::AgentError;

    if job_id.is_empty()
        || !job_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("the agent returned an invalid job id".into());
    }
    let path = format!("/migration/jobs/{job_id}");
    let mut clock = StallClock::new(Instant::now(), JOB_STALL_TIMEOUT);
    let mut last_error: Option<String> = None;

    loop {
        match agent.get(&path).await {
            Ok(v) => match classify_job(&v) {
                JobPoll::Done(report) => return Ok(report),
                JobPoll::Failed(e) => return Err(describe_job_error(&e)),
                JobPoll::Running { phase, bytes_done, bytes_total, message, updated_at } => {
                    last_error = None;
                    if clock.observe(Instant::now(), &phase, bytes_done, updated_at) {
                        on_progress(progress_message(&phase, bytes_done, bytes_total, &message));
                    }
                }
            },
            Err(AgentError::Status(404, _)) => {
                return Err(
                    "the agent no longer knows this job (it was probably restarted). Run the import again to redo this item."
                        .into(),
                );
            }
            Err(e) => {
                let e = e.to_string();
                if last_error.as_deref() != Some(e.as_str()) {
                    tracing::warn!("Polling agent job {job_id}: {e}");
                }
                last_error = Some(e);
            }
        }
        if clock.stalled(Instant::now()) {
            return Err(match last_error {
                Some(e) => format!(
                    "no progress for {} minutes (last error: {e})",
                    JOB_STALL_TIMEOUT.as_secs() / 60
                ),
                None => format!("no progress for {} minutes", JOB_STALL_TIMEOUT.as_secs() / 60),
            });
        }
        tokio::time::sleep(JOB_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn job_documents_are_classified() {
        let running = json!({ "job_id": "j", "state": "running", "phase": "extract", "bytes_done": 5, "bytes_total": 10, "message": "", "updated_at": 7 });
        assert_eq!(
            classify_job(&running),
            JobPoll::Running { phase: "extract".into(), bytes_done: 5, bytes_total: 10, message: String::new(), updated_at: 7 }
        );
        let done = json!({ "state": "done", "report": { "files_bytes": 3, "warnings": ["a"] }, "warnings": ["a", "b"] });
        match classify_job(&done) {
            JobPoll::Done(r) => {
                assert_eq!(r["files_bytes"], 3);
                assert_eq!(r["warnings"], json!(["a", "b"]));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(classify_job(&json!({ "state": "done", "report": null })), JobPoll::Done(json!({})));
        assert_eq!(
            classify_job(&json!({ "state": "failed", "error": "insufficient_disk" })),
            JobPoll::Failed("insufficient_disk".into())
        );
        assert_eq!(classify_job(&json!({ "state": "failed" })), JobPoll::Failed("the agent job failed".into()));
    }

    #[test]
    fn a_disk_refusal_reads_as_one() {
        assert_eq!(describe_job_error("insufficient_disk: need 3 GB, 1 GB free"), "Not enough disk space: need 3 GB, 1 GB free");
        assert_eq!(describe_job_error("tar failed"), "tar failed");
    }

    #[test]
    fn progress_lines_read_well() {
        assert_eq!(progress_message("extract", 1_200_000_000, 3_400_000_000, ""), "extract: 1.2 GB / 3.4 GB (35%)");
        assert_eq!(progress_message("", 0, 0, ""), "working");
        assert_eq!(progress_message("fix", 2048, 0, "chown"), "fix: 2.0 KB - chown");
        assert_eq!(fmt_bytes(999), "999 B");
    }

    #[test]
    fn a_job_is_stalled_only_after_the_window_without_any_change() {
        let t0 = Instant::now();
        let limit = Duration::from_secs(900);
        let mut c = StallClock::new(t0, limit);
        assert!(c.observe(t0, "extract", 0, 1));
        assert!(!c.observe(t0 + Duration::from_secs(600), "extract", 0, 1));
        assert!(!c.stalled(t0 + Duration::from_secs(899)));
        assert!(c.stalled(t0 + Duration::from_secs(900)));
        // Any change restarts the window: bytes, phase or heartbeat.
        assert!(c.observe(t0 + Duration::from_secs(901), "extract", 1, 1));
        assert!(!c.stalled(t0 + Duration::from_secs(1700)));
        assert!(c.observe(t0 + Duration::from_secs(1702), "extract", 1, 2));
        assert!(c.observe(t0 + Duration::from_secs(1703), "fix", 1, 2));
        assert!(!c.stalled(t0 + Duration::from_secs(2600)));
    }
}
