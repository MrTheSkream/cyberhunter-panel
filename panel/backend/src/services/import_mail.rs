//! HestiaCP mail domain import (05-import-hestia, W4-B).
//!
//! One mail domain of the staged backup becomes a panel mail domain, its
//! mailboxes (Hestia's `{BLF-CRYPT}` hashes kept as they are), aliases, DKIM key
//! (selector kept, `mail` on Hestia) and maildirs. Deliberately NOT
//! `routes::mail::create_domain`: that generates a new DKIM key, publishes DNS
//! records and requests a `mail.<d>` certificate - side effects that must not
//! happen before the DNS switch-over.
//!
//! Secrets (mailbox hashes, the DKIM private key) come from the agent's
//! `POST /mail/hestia/secrets` and go only into `mail_domains` /
//! `mail_accounts` (the key encrypted), never into `details`, a message, the
//! progress stream or a log.
//!
//! Ledger: the import loop (W5) only knows the domain item when it calls this;
//! the sub-items (`mailbox:`, `mail_alias:`, `maildir:`) are read here from
//! `migration_items` so a relaunch skips what is already `done`. A row of the
//! panel (domain, mailbox, alias) is modified only when this migration created
//! it: such rows are flagged `created_by_import` in their ledger item's
//! `details` (written as soon as the row exists, and repeated in every outcome).

use std::collections::BTreeSet;

use serde_json::json;
use uuid::Uuid;

use crate::routes::mail::{is_wellformed_address, is_wellformed_address_list};
use crate::services::import_types::{wait_job, ImportCtx, ItemOutcome, ItemStatus};

/// The panel's largest quota (`create_account` clamps to it): "unlimited".
pub const UNLIMITED_QUOTA_MB: i32 = 1_048_576;

/// A hash Dovecot can never match, stored for a disabled mailbox whose own
/// hash cannot even be carried by the sync (never shown, never a password).
const UNUSABLE_HASH: &str = "{CRYPT}*";

#[derive(serde::Deserialize)]
struct Secrets {
    selector: String,
    dkim_private_pem: Option<String>,
    catch_all: Option<String>,
    #[serde(default)]
    accounts: Vec<SecretAccount>,
    #[serde(default)]
    aliases: Vec<SecretAlias>,
}

#[derive(serde::Deserialize, Clone)]
pub struct SecretAccount {
    pub email: String,
    pub hash: String,
    pub scheme: String,
    pub quota_mb: Option<i64>,
    pub forward_to: Option<String>,
    #[serde(default)]
    pub forward_only: bool,
    #[serde(default)]
    pub suspended: bool,
}

#[derive(serde::Deserialize, Clone)]
pub struct SecretAlias {
    pub source: String,
    pub destination: String,
}

/// What a mailbox row will hold. Pure mapping of a Hestia account (tested).
#[derive(Debug, PartialEq, Eq)]
pub struct MailboxPlan {
    pub email: String,
    pub quota_mb: i32,
    pub enabled: bool,
    pub forward_to: Option<String>,
    pub keep_copy: bool,
    /// The hash is stored as is (`true`) or replaced by [`UNUSABLE_HASH`].
    pub hash_kept: bool,
    pub scheme_supported: bool,
    pub warnings: Vec<String>,
}

/// Dovecot field rules the agent's `/mail/sync` enforces on EVERY account
/// (one bad row rejects the whole server's rebuild).
fn hash_is_syncable(h: &str) -> bool {
    !h.is_empty() && h.len() <= 255 && !h.chars().any(|c| matches!(c, ':' | '\n' | '\r' | '\0' | '\t'))
}

/// `schemes` empty = the agent could not tell: assume the scheme is known
/// (never disable every mailbox on an unanswered question), except `UNKNOWN`.
pub fn scheme_supported(scheme: &str, schemes: &[String]) -> bool {
    let s = scheme.trim().to_ascii_uppercase();
    if s.is_empty() || s == "UNKNOWN" {
        return false;
    }
    schemes.is_empty() || schemes.iter().any(|x| x.eq_ignore_ascii_case(&s))
}

pub fn plan_mailbox(acc: &SecretAccount, domain: &str, schemes: &[String]) -> Result<MailboxPlan, String> {
    let email = acc.email.trim().to_ascii_lowercase();
    if !email.ends_with(&format!("@{domain}")) || !is_wellformed_address(&email, "") || email.len() > 255 {
        return Err(format!("{email:?} is not a valid address of {domain}"));
    }
    let mut warnings = Vec::new();
    let supported = scheme_supported(&acc.scheme, schemes);
    let hash_kept = hash_is_syncable(&acc.hash);
    if !supported {
        warnings.push(format!(
            "password scheme {} not supported, set a new password",
            if acc.scheme.trim().is_empty() { "UNKNOWN" } else { acc.scheme.trim() }
        ));
    }
    let quota_mb = match acc.quota_mb {
        Some(q) if q > 0 => q.min(UNLIMITED_QUOTA_MB as i64) as i32,
        _ => UNLIMITED_QUOTA_MB,
    };
    let targets: Vec<String> = acc
        .forward_to
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && *t != email)
        .collect();
    let mut forward_to = None;
    for t in &targets {
        if forward_to.is_none() && is_wellformed_address(t, "") && t.len() <= 255 {
            forward_to = Some(t.clone());
        }
    }
    if targets.len() > 1 {
        warnings.push(format!(
            "{} forward targets in HestiaCP, only the first valid one is kept",
            targets.len()
        ));
    } else if !targets.is_empty() && forward_to.is_none() {
        warnings.push("forward target is not a valid address, forwarding dropped".into());
    }
    let keep_copy = forward_to.is_some() && !acc.forward_only;
    if acc.suspended {
        warnings.push("suspended in HestiaCP, imported disabled".into());
    }
    Ok(MailboxPlan {
        email,
        quota_mb,
        enabled: supported && hash_kept && !acc.suspended,
        forward_to,
        keep_copy,
        hash_kept,
        scheme_supported: supported,
        warnings,
    })
}

fn outcome(status: ItemStatus, message: impl Into<String>, details: serde_json::Value) -> ItemOutcome {
    let mut o = ItemOutcome::new(status, message);
    o.details = details;
    o
}

/// `(status, created_by_import)` of a ledger item of this migration.
async fn ledger(ctx: &ImportCtx, kind: &str, key: &str) -> (Option<String>, bool) {
    let row: Option<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT status, details FROM migration_items WHERE migration_id = $1 AND kind = $2 AND key = $3",
    )
    .bind(ctx.migration_id)
    .bind(kind)
    .bind(key)
    .fetch_optional(&ctx.db)
    .await
    .ok()
    .flatten();
    match row {
        // While the loop runs an item, `ledger::begin` has moved its previous
        // details under `_prior`: the ownership flag is looked for there too,
        // or a retry would take its own mail domain for someone else's.
        Some((s, d)) => {
            let flag = |v: &serde_json::Value| v.get("created_by_import").and_then(|v| v.as_bool());
            let ours = flag(&d).or_else(|| d.get("_prior").and_then(|p| p.get("details")).and_then(flag));
            (Some(s), ours.unwrap_or(false))
        }
        None => (None, false),
    }
}

/// Record, the moment a panel row exists, that this migration created it.
async fn mark_ours(ctx: &ImportCtx, kind: &str, key: &str) {
    let r = sqlx::query(
        "INSERT INTO migration_items (migration_id, kind, key, status, details) \
         VALUES ($1, $2, $3, 'running', '{\"created_by_import\": true}'::jsonb) \
         ON CONFLICT (migration_id, kind, key) DO UPDATE \
         SET details = migration_items.details || '{\"created_by_import\": true}'::jsonb, updated_at = NOW()",
    )
    .bind(ctx.migration_id)
    .bind(kind)
    .bind(key)
    .execute(&ctx.db)
    .await;
    if let Err(e) = r {
        tracing::warn!("Mail import: could not record ownership of {kind}:{key}: {e}");
    }
}

/// A sub-item that already reached a final state is not redone unless forced:
/// rewriting a `warning` mailbox would revert the password / `enabled` the
/// operator set as the warning asked; re-extracting a maildir would bring
/// back deleted messages. `skipped` counts too (the loop may store ours).
fn done_and_not_forced(ctx: &ImportCtx, status: &Option<String>) -> bool {
    !ctx.force && matches!(status.as_deref(), Some("done") | Some("warning") | Some("skipped"))
}

/// Live event under the item's own ledger ref (`<kind>:<key>`), the step id the
/// import loop records the final state with, so the wizard shows one row each.
fn progress(ctx: &ImportCtx, kind: &str, key: &str, label: &str, state: &str, msg: Option<String>) {
    (ctx.progress)(&crate::services::migration_ledger::item_ref(kind, key), label, state, msg);
}

/// Ledger keys: `mail_domain:<d>`, `mailbox:<email>`, `mail_alias:<src>`, `maildir:<email>`.
pub async fn import_mail_domain(ctx: &ImportCtx, domain: &str) -> Vec<(String, ItemOutcome)> {
    let mut out = import_mail_domain_inner(ctx, domain).await;
    // The domain row's outcome REPLACES its ledger details: a failure that
    // returned early (status unavailable, secrets unreadable...) would erase
    // the `created_by_import` flag of a domain this migration created, and
    // every later run - forced or not - would then call it someone else's.
    let d = domain.trim().to_ascii_lowercase();
    let (_, ours) = ledger(ctx, "mail_domain", &d).await;
    if ours {
        keep_ownership_flag(&mut out, &format!("mail_domain:{d}"));
    }
    out
}

/// Pure half of the wrapper above: stamps `created_by_import` on the outcome of `dkey`.
fn keep_ownership_flag(out: &mut [(String, ItemOutcome)], dkey: &str) {
    for (k, o) in out.iter_mut() {
        if k == dkey {
            if !o.details.is_object() {
                o.details = json!({});
            }
            o.details["created_by_import"] = json!(true);
        }
    }
}

async fn import_mail_domain_inner(ctx: &ImportCtx, domain: &str) -> Vec<(String, ItemOutcome)> {
    let domain = domain.trim().to_ascii_lowercase();
    let dkey = format!("mail_domain:{domain}");
    if !crate::routes::is_valid_domain(&domain) {
        return vec![(dkey, ItemOutcome::failed("invalid mail domain name"))];
    }
    progress(ctx, "mail_domain", &domain, &format!("Mail {domain}"), "in_progress", None);

    // (1) The mail server must be there (W5's preflight says so earlier).
    let status = match ctx.agent.get("/mail/status").await {
        Ok(v) => v,
        Err(e) => return vec![(dkey, ItemOutcome::failed(format!("mail status unavailable: {e}")))],
    };
    let installed = status.get("installed").and_then(|v| v.as_bool()).unwrap_or(false)
        || status.pointer("/dovecot/installed").and_then(|v| v.as_bool()).unwrap_or(false);
    if !installed {
        return vec![(dkey, ItemOutcome::failed("mail server not installed"))];
    }
    let schemes: Vec<String> = status
        .get("password_schemes")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase())).collect())
        .unwrap_or_default();

    // (2) Secrets, by reference to the staging. Never logged.
    let secrets: Secrets = match ctx
        .agent
        .post(
            "/mail/hestia/secrets",
            Some(json!({ "migration_id": ctx.agent_migration_id, "domain": domain })),
        )
        .await
        .map_err(|e| e.to_string())
        .and_then(|v| serde_json::from_value(v).map_err(|e| format!("unreadable answer: {e}")))
    {
        Ok(s) => s,
        Err(e) => return vec![(dkey, ItemOutcome::failed(format!("could not read the backup's mail data: {e}")))],
    };

    let mut out: Vec<(String, ItemOutcome)> = Vec::new();
    let mut domain_warnings: Vec<String> = Vec::new();

    // (3) The domain row.
    let catch_all = secrets
        .catch_all
        .as_deref()
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty());
    let catch_all = match catch_all {
        Some(c) if is_wellformed_address(&c, "") => Some(c),
        Some(_) => {
            domain_warnings.push("catch-all address is not valid, not imported".into());
            None
        }
        None => None,
    };
    let selector = if secrets.selector.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !secrets.selector.is_empty()
    {
        secrets.selector.clone()
    } else {
        "mail".to_string()
    };
    let existing: Option<(Uuid,)> =
        match sqlx::query_as("SELECT id FROM mail_domains WHERE domain = $1 AND server_id = $2")
            .bind(&domain)
            .bind(ctx.server_id)
            .fetch_optional(&ctx.db)
            .await
        {
            Ok(r) => r,
            Err(e) => return vec![(dkey, ItemOutcome::failed(format!("database error: {e}")))],
        };
    let (_, domain_ours) = ledger(ctx, "mail_domain", &domain).await;
    let domain_id = match existing {
        Some(_) if !domain_ours => {
            return vec![(
                dkey,
                outcome(
                    ItemStatus::Warning,
                    "exists_not_ours: this mail domain already exists in the panel and was not \
                     created by this import; left unchanged",
                    json!({ "code": "exists_not_ours" }),
                ),
            )];
        }
        // Ours from an earlier attempt: settings the operator may have changed
        // since (catch-all, selector) are only rewritten on a forced re-import.
        Some((id,)) if !ctx.force => id,
        Some((id,)) => {
            let _ = sqlx::query(
                "UPDATE mail_domains SET dkim_selector = $1, catch_all = $2, updated_at = NOW() WHERE id = $3",
            )
            .bind(&selector)
            .bind(&catch_all)
            .bind(id)
            .execute(&ctx.db)
            .await;
            id
        }
        None => {
            let r: Result<(Uuid,), _> = sqlx::query_as(
                "INSERT INTO mail_domains (domain, dkim_selector, catch_all, server_id) \
                 VALUES ($1, $2, $3, $4) RETURNING id",
            )
            .bind(&domain)
            .bind(&selector)
            .bind(&catch_all)
            .bind(ctx.server_id)
            .fetch_one(&ctx.db)
            .await;
            match r {
                Ok((id,)) => {
                    mark_ours(ctx, "mail_domain", &domain).await;
                    id
                }
                Err(e) => return vec![(dkey, ItemOutcome::failed(format!("could not create the mail domain: {e}")))],
            }
        }
    };
    // Maildir root only (`/var/vmail/<d>`): no DNS, no certificate.
    let _ = ctx.agent.post("/mail/domains/configure", Some(json!({ "domain": domain }))).await;

    // (4) DKIM: Hestia's key under Hestia's selector.
    let mut dkim_imported = false;
    match secrets.dkim_private_pem.as_deref() {
        Some(pem) => {
            let r = ctx
                .agent
                .post(
                    "/mail/dkim/import",
                    Some(json!({ "domain": domain, "selector": selector, "private_key_pem": pem })),
                )
                .await;
            match r {
                Ok(v) => {
                    let public = v.get("public_key").and_then(|p| p.as_str());
                    match crate::routes::mail::store_dkim_key(
                        &ctx.db, domain_id, &selector, pem, public, &ctx.jwt_secret,
                    )
                    .await
                    {
                        Ok(()) => dkim_imported = true,
                        Err(e) => domain_warnings.push(format!("DKIM key installed but not recorded: {e}")),
                    }
                }
                Err(e) => domain_warnings.push(format!("DKIM key not imported: {e}")),
            }
        }
        None => domain_warnings.push("no DKIM key in the backup".into()),
    }

    // (5) Mailboxes.
    let mut maildir_accounts: Vec<String> = Vec::new();
    let mut mailbox_emails: BTreeSet<String> = BTreeSet::new();
    for acc in &secrets.accounts {
        let email = acc.email.trim().to_ascii_lowercase();
        mailbox_emails.insert(email.clone());
        let key = format!("mailbox:{email}");
        let (st, ours) = ledger(ctx, "mailbox", &email).await;
        if done_and_not_forced(ctx, &st) {
            out.push((key, outcome(ItemStatus::Skipped, "already imported", json!({ "created_by_import": ours }))));
            maildir_accounts.push(email);
            continue;
        }
        let plan = match plan_mailbox(acc, &domain, &schemes) {
            Ok(p) => p,
            Err(e) => {
                out.push((key, ItemOutcome::failed(e)));
                continue;
            }
        };
        progress(ctx, "mailbox", &plan.email, &format!("Mailbox {}", plan.email), "in_progress", None);
        let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_accounts WHERE email = $1")
            .bind(&plan.email)
            .fetch_optional(&ctx.db)
            .await
            .ok()
            .flatten();
        let hash: &str = if plan.hash_kept { acc.hash.trim() } else { UNUSABLE_HASH };
        let written = match existing {
            Some(_) if !ours => {
                out.push((
                    key,
                    outcome(
                        ItemStatus::Warning,
                        "exists_not_ours: this mailbox already exists in the panel; left unchanged",
                        json!({ "code": "exists_not_ours" }),
                    ),
                ));
                continue;
            }
            Some((id,)) => sqlx::query(
                "UPDATE mail_accounts SET password_hash = $1, quota_mb = $2, enabled = $3, forward_to = $4, \
                 keep_copy = $5, updated_at = NOW() WHERE id = $6",
            )
            .bind(hash)
            .bind(plan.quota_mb)
            .bind(plan.enabled)
            .bind(&plan.forward_to)
            .bind(plan.keep_copy)
            .bind(id)
            .execute(&ctx.db)
            .await
            .map(|_| ()),
            None => {
                let r = sqlx::query(
                    "INSERT INTO mail_accounts (domain_id, email, password_hash, quota_mb, enabled, forward_to, keep_copy) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(domain_id)
                .bind(&plan.email)
                .bind(hash)
                .bind(plan.quota_mb)
                .bind(plan.enabled)
                .bind(&plan.forward_to)
                .bind(plan.keep_copy)
                .execute(&ctx.db)
                .await
                .map(|_| ());
                if r.is_ok() {
                    mark_ours(ctx, "mailbox", &plan.email).await;
                }
                r
            }
        };
        if let Err(e) = written {
            out.push((key, ItemOutcome::failed(format!("could not write the mailbox: {e}"))));
            continue;
        }
        let details = json!({
            "created_by_import": true,
            "enabled": plan.enabled,
            "quota_mb": plan.quota_mb,
            "forward": plan.forward_to.is_some(),
            "keep_copy": plan.keep_copy,
            "scheme": acc.scheme.trim().to_ascii_uppercase(),
            "password": if plan.scheme_supported && plan.hash_kept { "kept" } else { "locked" },
        });
        let status = if plan.warnings.is_empty() { ItemStatus::Done } else { ItemStatus::Warning };
        let message = if plan.warnings.is_empty() { "imported".to_string() } else { plan.warnings.join("; ") };
        out.push((key, outcome(status, message, details)));
        maildir_accounts.push(plan.email);
    }

    // (6) Aliases: one key per source, never a mailbox address.
    let mut alias_count = 0;
    for al in &secrets.aliases {
        let source = al.source.trim().to_ascii_lowercase();
        let destination = al.destination.trim().to_ascii_lowercase().replace(' ', "");
        let key = format!("mail_alias:{source}");
        let (st, ours) = ledger(ctx, "mail_alias", &source).await;
        if done_and_not_forced(ctx, &st) {
            out.push((key, outcome(ItemStatus::Skipped, "already imported", json!({ "created_by_import": ours }))));
            continue;
        }
        if !source.ends_with(&format!("@{domain}"))
            || !is_wellformed_address(&source, "")
            || !is_wellformed_address_list(&destination, "")
            || destination.len() > 255
        {
            out.push((key, ItemOutcome::failed("alias source or destination is not a valid address")));
            continue;
        }
        if mailbox_emails.contains(&source) {
            out.push((key, outcome(ItemStatus::Skipped, "source is a mailbox (its forward)", json!({}))));
            continue;
        }
        let existing: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_aliases WHERE source_email = $1")
            .bind(&source)
            .fetch_all(&ctx.db)
            .await
            .unwrap_or_default();
        let clash: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_accounts WHERE email = $1")
            .bind(&source)
            .fetch_optional(&ctx.db)
            .await
            .ok()
            .flatten();
        if clash.is_some() || (!existing.is_empty() && !ours) {
            out.push((
                key,
                outcome(
                    ItemStatus::Warning,
                    "exists_not_ours: this address already exists in the panel; left unchanged",
                    json!({ "code": "exists_not_ours" }),
                ),
            ));
            continue;
        }
        let r = if existing.is_empty() {
            let r = sqlx::query(
                "INSERT INTO mail_aliases (domain_id, source_email, destination_email) VALUES ($1, $2, $3)",
            )
            .bind(domain_id)
            .bind(&source)
            .bind(&destination)
            .execute(&ctx.db)
            .await;
            if r.is_ok() {
                mark_ours(ctx, "mail_alias", &source).await;
            }
            r
        } else {
            sqlx::query("UPDATE mail_aliases SET destination_email = $1, domain_id = $2 WHERE source_email = $3")
                .bind(&destination)
                .bind(domain_id)
                .bind(&source)
                .execute(&ctx.db)
                .await
        };
        match r {
            Ok(_) => {
                alias_count += 1;
                out.push((key, outcome(ItemStatus::Done, "imported", json!({ "created_by_import": true }))));
            }
            Err(e) => out.push((key, ItemOutcome::failed(format!("could not write the alias: {e}")))),
        }
    }

    // (7) Apply: one rebuild for the whole domain.
    let sync = crate::routes::mail::sync_mail_config_db(&ctx.db, ctx.server_id, &ctx.agent).await;

    // (8) Maildirs, one agent job each.
    for email in &maildir_accounts {
        let key = format!("maildir:{email}");
        let (st, _) = ledger(ctx, "maildir", email).await;
        if done_and_not_forced(ctx, &st) {
            out.push((key, outcome(ItemStatus::Skipped, "already imported", json!({}))));
            continue;
        }
        let Some((local, _)) = email.split_once('@') else { continue };
        progress(ctx, "maildir", email, &format!("Messages of {email}"), "in_progress", Some("copying messages".into()));
        let job = ctx
            .agent
            .post(
                "/mail/hestia/import-maildir",
                Some(json!({ "migration_id": ctx.agent_migration_id, "domain": domain, "account": local })),
            )
            .await;
        let job_id = match job {
            Ok(v) => match v.get("job_id").and_then(|j| j.as_str()) {
                Some(j) => j.to_string(),
                None => {
                    out.push((key, ItemOutcome::failed("agent returned no job id")));
                    continue;
                }
            },
            Err(e) => {
                out.push((key, ItemOutcome::failed(format!("maildir import refused: {e}"))));
                continue;
            }
        };
        // Step id = the ledger item ref, as for every other job (`maildir:<email>`).
        match wait_job(ctx, &job_id, &key, &format!("Messages of {email}")).await {
            Ok(v) => {
                let report = v.get("report").filter(|r| r.is_object()).unwrap_or(&v);
                let details = json!({
                    "bytes": report.get("bytes").cloned().unwrap_or(json!(null)),
                    "messages_estimate": report.get("messages_estimate").cloned().unwrap_or(json!(null)),
                });
                let warns: Vec<String> = v
                    .get("warnings")
                    .and_then(|w| w.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if warns.is_empty() {
                    out.push((key, outcome(ItemStatus::Done, "messages copied", details)));
                } else {
                    out.push((key, outcome(ItemStatus::Warning, warns.join("; "), details)));
                }
            }
            Err(e) => out.push((key, ItemOutcome::failed(format!("maildir import failed: {e}")))),
        }
    }

    let details = json!({
        "created_by_import": true,
        "selector": selector,
        "dkim": dkim_imported,
        "catch_all": catch_all.is_some(),
        "accounts": secrets.accounts.len(),
        "aliases": alias_count,
    });
    let domain_outcome = match sync {
        Err(e) => outcome(ItemStatus::Failed, format!("mail configuration not applied: {e}"), details),
        Ok(()) if domain_warnings.is_empty() => outcome(ItemStatus::Done, "imported", details),
        Ok(()) => outcome(ItemStatus::Warning, domain_warnings.join("; "), details),
    };
    progress(ctx, "mail_domain", &domain, &format!("Mail {domain}"), "done", None);
    let mut all = vec![(dkey, domain_outcome)];
    all.extend(out);
    all
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_early_failure_keeps_the_domain_ours() {
        let mut out = vec![
            ("mail_domain:d.be".to_string(), ItemOutcome::failed("mail status unavailable")),
            ("mailbox:a@d.be".to_string(), ItemOutcome::failed("x")),
        ];
        keep_ownership_flag(&mut out, "mail_domain:d.be");
        assert_eq!(out[0].1.details["created_by_import"], true);
        assert!(out[1].1.details.get("created_by_import").is_none());
    }

    use super::*;

    fn acc(email: &str) -> SecretAccount {
        SecretAccount {
            email: email.into(),
            hash: "{BLF-CRYPT}$2y$05$syntheticsyntheticsynt".into(),
            scheme: "BLF-CRYPT".into(),
            quota_mb: None,
            forward_to: None,
            forward_only: false,
            suspended: false,
        }
    }

    fn schemes() -> Vec<String> {
        vec!["BLF-CRYPT".into(), "SHA512-CRYPT".into(), "ARGON2ID".into()]
    }

    #[test]
    fn unlimited_quota_is_the_panel_maximum_never_the_1024_default() {
        let p = plan_mailbox(&acc("info@d.be"), "d.be", &schemes()).unwrap();
        assert_eq!(p.quota_mb, UNLIMITED_QUOTA_MB);
        let mut a = acc("info@d.be");
        a.quota_mb = Some(500);
        assert_eq!(plan_mailbox(&a, "d.be", &schemes()).unwrap().quota_mb, 500);
        a.quota_mb = Some(5_000_000);
        assert_eq!(plan_mailbox(&a, "d.be", &schemes()).unwrap().quota_mb, UNLIMITED_QUOTA_MB);
    }

    #[test]
    fn fwd_without_fwd_only_keeps_a_copy() {
        let mut a = acc("jim@d.be");
        a.forward_to = Some("jim@example.org".into());
        let p = plan_mailbox(&a, "d.be", &schemes()).unwrap();
        assert_eq!(p.forward_to.as_deref(), Some("jim@example.org"));
        assert!(p.keep_copy);
        a.forward_only = true;
        assert!(!plan_mailbox(&a, "d.be", &schemes()).unwrap().keep_copy);
        // No forward: never a copy flag.
        assert!(!plan_mailbox(&acc("x@d.be"), "d.be", &schemes()).unwrap().keep_copy);
    }

    #[test]
    fn several_forward_targets_keep_the_first_and_warn() {
        let mut a = acc("jim@d.be");
        a.forward_to = Some("a@x.org, b@y.org,jim@d.be".into());
        let p = plan_mailbox(&a, "d.be", &schemes()).unwrap();
        assert_eq!(p.forward_to.as_deref(), Some("a@x.org"));
        assert_eq!(p.warnings.len(), 1);
        a.forward_to = Some("not-an-address".into());
        let p = plan_mailbox(&a, "d.be", &schemes()).unwrap();
        assert_eq!(p.forward_to, None);
        assert!(!p.keep_copy);
    }

    #[test]
    fn enabled_follows_scheme_support_and_suspension() {
        assert!(plan_mailbox(&acc("a@d.be"), "d.be", &schemes()).unwrap().enabled);
        let mut a = acc("a@d.be");
        a.scheme = "SSHA512".into();
        let p = plan_mailbox(&a, "d.be", &schemes()).unwrap();
        assert!(!p.enabled && !p.scheme_supported);
        assert!(p.warnings[0].contains("SSHA512") && p.warnings[0].contains("set a new password"));
        let mut a = acc("a@d.be");
        a.suspended = true;
        assert!(!plan_mailbox(&a, "d.be", &schemes()).unwrap().enabled);
        // An unanswered scheme list is "unknown", not "supports nothing".
        assert!(plan_mailbox(&acc("a@d.be"), "d.be", &[]).unwrap().enabled);
        let mut a = acc("a@d.be");
        a.scheme = "UNKNOWN".into();
        assert!(!plan_mailbox(&a, "d.be", &[]).unwrap().enabled);
    }

    #[test]
    fn a_hash_the_sync_cannot_carry_is_replaced_and_the_box_disabled() {
        let mut a = acc("a@d.be");
        a.hash = "{BLF-CRYPT}bad:hash".into();
        let p = plan_mailbox(&a, "d.be", &schemes()).unwrap();
        assert!(!p.hash_kept && !p.enabled);
        a.hash = String::new();
        assert!(!plan_mailbox(&a, "d.be", &schemes()).unwrap().hash_kept);
    }

    #[test]
    fn addresses_outside_the_domain_or_malformed_are_refused() {
        assert!(plan_mailbox(&acc("a@other.be"), "d.be", &schemes()).is_err());
        assert!(plan_mailbox(&acc("..@d.be"), "d.be", &schemes()).is_err());
        assert!(plan_mailbox(&acc("@d.be"), "d.be", &schemes()).is_err());
        assert_eq!(plan_mailbox(&acc(" Info@D.be "), "d.be", &schemes()).unwrap().email, "info@d.be");
    }

    #[test]
    fn the_secrets_answer_deserialises() {
        let v = json!({
            "selector": "mail", "dkim_private_pem": null, "catch_all": null,
            "accounts": [{ "email": "a@d.be", "hash": "{BLF-CRYPT}x", "scheme": "BLF-CRYPT",
                           "quota_mb": null, "forward_to": null, "forward_only": false, "suspended": false }],
            "aliases": [{ "source": "s@d.be", "destination": "a@d.be" }]
        });
        let s: Secrets = serde_json::from_value(v).unwrap();
        assert_eq!(s.accounts.len(), 1);
        assert_eq!(s.aliases[0].source, "s@d.be");
    }
}
