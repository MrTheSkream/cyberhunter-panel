//! Types shared by the HestiaCP import executors (05-import-hestia, W5-T).
//!
//! Written at step 0 (owner: W5). The executors of the other workstreams
//! (`import_db`, `import_mail`, `import_sftp`) take an [`ImportCtx`] and return
//! [`ItemOutcome`]s that the import loop writes to the `migration_items` ledger.

/// Final state of one ledger item.
#[allow(dead_code)] // step 0: used once the import loop lands (W5)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemStatus {
    Done,
    Skipped,
    Warning,
    Failed,
}

/// Result of one import item. `details` never carries a secret (D11).
#[allow(dead_code)] // step 0: used once the import loop lands (W5)
#[derive(Debug, Clone, serde::Serialize)]
pub struct ItemOutcome {
    pub status: ItemStatus,
    pub message: String,
    pub details: serde_json::Value,
}

#[allow(dead_code)] // step 0: used once the import loop lands (W5)
impl ItemOutcome {
    pub fn new(status: ItemStatus, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), details: serde_json::json!({}) }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ItemStatus::Failed, message)
    }
}

/// Progress callback: `(step, label, "pending"|"in_progress"|"done"|"error", message)`.
#[allow(dead_code)] // step 0: used once the import loop lands (W5)
pub type ProgressFn = std::sync::Arc<dyn Fn(&str, &str, &str, Option<String>) + Send + Sync>;

/// Everything an executor needs to import one item.
#[allow(dead_code)] // step 0: used once the import loop lands (W5)
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

/// Polls `GET /migration/jobs/{id}` every 3 s, emits progress (1 event / 2 s),
/// fails after 15 min without progress or on 404.
///
/// STEP 0 SKELETON (owner: W5).
#[allow(dead_code)]
pub async fn wait_job(
    _ctx: &ImportCtx,
    _job_id: &str,
    _step: &str,
    _label: &str,
) -> Result<serde_json::Value, String> {
    Err("not implemented".into())
}
