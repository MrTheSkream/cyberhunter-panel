//! HestiaCP mail domain import (05-import-hestia, W4-B).
//!
//! STEP 0 SKELETON (owner: W4). Signature fixed by contract; W4 replaces this
//! whole file with the real implementation.

use crate::services::import_types::{ImportCtx, ItemOutcome};

/// Ledger keys: `mail_domain:<d>`, `mailbox:<email>`, `mail_alias:<src>`, `maildir:<email>`.
#[allow(dead_code)]
pub async fn import_mail_domain(_ctx: &ImportCtx, domain: &str) -> Vec<(String, ItemOutcome)> {
    vec![(format!("mail_domain:{domain}"), ItemOutcome::failed("not implemented"))]
}
