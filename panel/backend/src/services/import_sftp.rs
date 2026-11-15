//! HestiaCP FTP account import as a panel SFTP account (05-import-hestia, W4-S).
//!
//! STEP 0 SKELETON (owner: W4). Signature fixed by contract; W4 replaces this
//! whole file with the real implementation.

use uuid::Uuid;

use crate::services::import_types::{ImportCtx, ItemOutcome};

#[allow(dead_code)]
pub async fn import_sftp(_ctx: &ImportCtx, _site_id: Uuid, _domain: &str) -> ItemOutcome {
    ItemOutcome::failed("not implemented")
}
