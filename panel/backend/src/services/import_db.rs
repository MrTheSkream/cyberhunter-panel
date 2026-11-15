//! HestiaCP database import into the local MariaDB server (05-import-hestia, W2-B).
//!
//! STEP 0 SKELETON (owner: W2). Signature fixed by contract; W2 replaces this
//! whole file with the real implementation.

use uuid::Uuid;

use crate::services::import_types::{ImportCtx, ItemOutcome};

#[allow(dead_code)]
pub async fn import_hestia_db(_ctx: &ImportCtx, _db_name: &str, _site_id: Uuid) -> ItemOutcome {
    ItemOutcome::failed("not implemented")
}
