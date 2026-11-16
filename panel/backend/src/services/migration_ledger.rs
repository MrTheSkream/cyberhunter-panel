//! `migration_items` ledger access (05-import-hestia, W5-D / D10).
//!
//! One row per `(migration, kind, key)`. It is both the resume ledger and the
//! per-item report:
//!
//! - an item whose row is `done` or `warning` (finished, possibly with notes) is
//!   SKIPPED on a re-run without any write, unless the operator forces it through
//!   `force_items` - re-running a file copy or a dump import over a site that went
//!   live would destroy what was written since;
//! - `pending`, `running`, `failed` and `skipped` rows are run again. A `running`
//!   row is one whose process died (backend or agent restart); it was never
//!   finished, so it is redone entirely.
//!
//! The import loop (`routes::migration`) owns the writes: it calls [`begin`]
//! before an item and [`finish`] after it. The executors of the other streams
//! (`import_db`, `import_mail`, `import_sftp`) only READ, through [`get`]
//! and [`prior_state`].
//!
//! Nothing secret is ever written here (D11): [`finish`] passes the message and
//! every string inside `details` through [`redact`], a last line of defence for
//! an executor or an agent error body that would quote a hash or a key.

use std::sync::OnceLock;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::services::import_types::{ItemOutcome, ItemStatus};

/// Ledger kinds (the `kind` column).
pub const KINDS: &[&str] = &[
    "site", "files", "ssl", "php", "sftp", "db", "mail_domain", "mailbox", "mail_alias", "maildir",
    "preflight",
];

/// Statuses that mean "this item finished": skipped on a re-run unless forced.
pub const COMPLETED: &[&str] = &["done", "warning"];

/// Key under which [`begin`] stashes the row's state from before this attempt,
/// so an executor can still read it once the row says `running`.
const PRIOR_KEY: &str = "_prior";

/// One ledger row, as the report serves it.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct LedgerRow {
    pub kind: String,
    pub key: String,
    pub status: String,
    pub message: String,
    pub details: Value,
    pub attempts: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// What the loop does with an item, given its current row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Finished before and not forced: report `skipped`, write nothing.
    Skip,
    /// Never run, unfinished, failed, or forced: run it.
    Run,
}

/// The pure rule of D10.
pub fn decide(previous_status: Option<&str>, forced: bool) -> Decision {
    match previous_status {
        Some(s) if COMPLETED.contains(&s) && !forced => Decision::Skip,
        _ => Decision::Run,
    }
}

/// `"<kind>:<key>"`, the form `force_items` and `import_mail_domain` use.
pub fn item_ref(kind: &str, key: &str) -> String {
    format!("{kind}:{key}")
}

/// Splits `"<kind>:<key>"` on the FIRST colon. `None` for an unknown kind or an
/// empty key.
pub fn parse_item_ref(s: &str) -> Option<(&str, &str)> {
    let (kind, key) = s.split_once(':')?;
    (KINDS.contains(&kind) && !key.trim().is_empty()).then_some((kind, key))
}

/// The ledger text for an outcome status.
pub fn status_str(s: ItemStatus) -> &'static str {
    match s {
        ItemStatus::Done => "done",
        ItemStatus::Skipped => "skipped",
        ItemStatus::Warning => "warning",
        ItemStatus::Failed => "failed",
    }
}

// ──────────────────────────────────────────────────────────────
// Secret redaction (D11)
// ──────────────────────────────────────────────────────────────

fn redaction_rules() -> &'static [(regex::Regex, &'static str)] {
    static RULES: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |p: &str| regex::Regex::new(p).expect("static redaction pattern");
        vec![
            // PEM blocks (private keys, certificates): never useful in a report.
            (r(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----"), "[redacted key]"),
            // An unterminated PEM header (a truncated error body).
            (r(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*"), "[redacted key]"),
            // Dovecot `{SCHEME}hash`.
            (r(r"\{[A-Z][A-Z0-9-]*(?:\.[A-Z0-9-]+)?\}\S+"), "[redacted hash]"),
            // crypt(3): yescrypt, gost-yescrypt, scrypt, sha512/256, bcrypt, md5.
            (r(r"\$(?:y|gy|7|6|5|2[abxy]|1)\$[A-Za-z0-9./$,=-]+"), "[redacted hash]"),
            // mysql_native_password.
            (r(r"\*[0-9A-Fa-f]{40}"), "[redacted hash]"),
        ]
    })
}

/// Masks anything shaped like a password hash or a key.
pub fn redact(s: &str) -> String {
    let mut out = s.to_string();
    for (re, with) in redaction_rules() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *with).into_owned();
        }
    }
    out
}

/// [`redact`] over every string of a JSON value (keys kept).
pub fn redact_json(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact(s)),
        Value::Array(a) => Value::Array(a.iter().map(redact_json).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), redact_json(v))).collect())
        }
        other => other.clone(),
    }
}

// ──────────────────────────────────────────────────────────────
// Reads (also for W2/W4)
// ──────────────────────────────────────────────────────────────

/// The row for one item, if any.
pub async fn get(db: &sqlx::PgPool, migration_id: Uuid, kind: &str, key: &str) -> Option<LedgerRow> {
    sqlx::query_as::<_, LedgerRow>(
        "SELECT kind, key, status, message, details, attempts, updated_at FROM migration_items \
         WHERE migration_id = $1 AND kind = $2 AND key = $3",
    )
    .bind(migration_id)
    .bind(kind)
    .bind(key)
    .fetch_optional(db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("migration ledger read failed for {kind}:{key}: {e}");
        None
    })
}

/// Every row of a migration, in a stable order.
pub async fn list(db: &sqlx::PgPool, migration_id: Uuid) -> Result<Vec<LedgerRow>, sqlx::Error> {
    sqlx::query_as::<_, LedgerRow>(
        "SELECT kind, key, status, message, details, attempts, updated_at FROM migration_items \
         WHERE migration_id = $1 ORDER BY created_at, kind, key",
    )
    .bind(migration_id)
    .fetch_all(db)
    .await
}

/// State of an item BEFORE the attempt now running: `(status, details)`.
///
/// While the loop runs an item its row says `running`; an executor that needs to
/// know whether an earlier attempt of THIS migration got part-way (W2: drop and
/// recreate a partial base) reads this instead. `None` = first attempt.
pub async fn prior_state(
    db: &sqlx::PgPool,
    migration_id: Uuid,
    kind: &str,
    key: &str,
) -> Option<(String, Value)> {
    let row = get(db, migration_id, kind, key).await?;
    let prior = row.details.get(PRIOR_KEY)?;
    let status = prior.get("status")?.as_str()?.to_string();
    Some((status, prior.get("details").cloned().unwrap_or_else(|| json!({}))))
}

// ──────────────────────────────────────────────────────────────
// Writes (import loop only)
// ──────────────────────────────────────────────────────────────

/// Marks an item `running` (attempts + 1), keeping its previous state under
/// `details._prior` for [`prior_state`].
pub async fn begin(db: &sqlx::PgPool, migration_id: Uuid, kind: &str, key: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO migration_items (migration_id, kind, key, status, attempts, started_at, details) \
         VALUES ($1, $2, $3, 'running', 1, NOW(), '{}'::jsonb) \
         ON CONFLICT (migration_id, kind, key) DO UPDATE SET \
           details = jsonb_build_object('_prior', jsonb_build_object( \
               'status', migration_items.status, \
               'details', migration_items.details - '_prior')), \
           status = 'running', attempts = migration_items.attempts + 1, \
           started_at = NOW(), finished_at = NULL, updated_at = NOW()",
    )
    .bind(migration_id)
    .bind(kind)
    .bind(key)
    .execute(db)
    .await
    .map(|_| ())
}

/// Writes an item's result (redacted). A `Skipped` outcome never overwrites a
/// finished row - "already imported" is reported, not recorded.
pub async fn finish(
    db: &sqlx::PgPool,
    migration_id: Uuid,
    kind: &str,
    key: &str,
    outcome: &ItemOutcome,
) -> Result<(), sqlx::Error> {
    write_status(db, migration_id, kind, key, status_str(outcome.status), &outcome.message, &outcome.details)
        .await
}

/// Records an item that could not start yet (e.g. SFTP waiting for its files).
pub async fn set_pending(
    db: &sqlx::PgPool,
    migration_id: Uuid,
    kind: &str,
    key: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    write_status(db, migration_id, kind, key, "pending", message, &json!({})).await
}

async fn write_status(
    db: &sqlx::PgPool,
    migration_id: Uuid,
    kind: &str,
    key: &str,
    status: &str,
    message: &str,
    details: &Value,
) -> Result<(), sqlx::Error> {
    let message = redact(message);
    let mut details = redact_json(details);
    if !details.is_object() {
        details = json!({ "value": details });
    }
    let finished = status != "pending";
    // "Already imported" (skipped) or "waiting" (pending) never replaces a
    // finished result. The row may already say `running` because `begin` ran
    // for this attempt: then its pre-attempt state is put back.
    if status == "skipped" || status == "pending" {
        let restored = sqlx::query(
            "UPDATE migration_items SET status = details->'_prior'->>'status', \
             details = COALESCE(details->'_prior'->'details', '{}'::jsonb), \
             finished_at = NOW(), updated_at = NOW() \
             WHERE migration_id = $1 AND kind = $2 AND key = $3 AND status = 'running' \
               AND details->'_prior'->>'status' IN ('done', 'warning')",
        )
        .bind(migration_id)
        .bind(kind)
        .bind(key)
        .execute(db)
        .await?;
        if restored.rows_affected() > 0 {
            return Ok(());
        }
    }
    sqlx::query(
        "INSERT INTO migration_items (migration_id, kind, key, status, message, details, attempts, finished_at) \
         VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $4 = 'pending' THEN 0 ELSE 1 END, \
                 CASE WHEN $7 THEN NOW() END) \
         ON CONFLICT (migration_id, kind, key) DO UPDATE SET \
           status = $4, message = $5, details = $6, \
           finished_at = CASE WHEN $7 THEN NOW() END, updated_at = NOW() \
         WHERE NOT ($4 IN ('skipped', 'pending') AND migration_items.status IN ('done', 'warning'))",
    )
    .bind(migration_id)
    .bind(kind)
    .bind(key)
    .bind(status)
    .bind(&message)
    .bind(&details)
    .bind(finished)
    .execute(db)
    .await
    .map(|_| ())
}

/// Stores `site_id` in the site item's details as soon as the `sites` row exists,
/// inside the caller's transaction, so a crash right after the INSERT still lets
/// the next run find (and resume) the row it created.
pub async fn stamp_site_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    migration_id: Uuid,
    domain: &str,
    site_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE migration_items SET details = details || jsonb_build_object('site_id', $3::text), \
         updated_at = NOW() WHERE migration_id = $1 AND kind = 'site' AND key = $2",
    )
    .bind(migration_id)
    .bind(domain)
    .bind(site_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// The `site_id` a site item recorded, in this attempt or a previous one.
pub fn site_id_of(row: &LedgerRow) -> Option<Uuid> {
    let from = |v: &Value| v.get("site_id").and_then(|s| s.as_str()).and_then(|s| s.parse().ok());
    from(&row.details).or_else(|| row.details.get(PRIOR_KEY).and_then(|p| p.get("details")).and_then(from))
}

/// Startup sweep: a `running` row has no process left to finish it. It becomes
/// `failed` (redone by the next run; [`prior_state`] then says `failed`).
pub async fn interrupt_running_on_startup(db: &sqlx::PgPool) {
    match sqlx::query(
        "UPDATE migration_items SET status = 'failed', \
         message = 'Interrupted by a panel restart. Run the import again to redo it.', \
         finished_at = NOW(), updated_at = NOW() WHERE status = 'running'",
    )
    .execute(db)
    .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::warn!("Marked {} interrupted migration item(s) as failed", r.rows_affected())
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("migration_items startup sweep failed: {e}"),
    }
}

// ──────────────────────────────────────────────────────────────
// Report
// ──────────────────────────────────────────────────────────────

/// Counts per status. The four contract keys are always present.
pub fn summary(rows: &[LedgerRow]) -> Value {
    let mut s = json!({ "done": 0, "skipped": 0, "warning": 0, "failed": 0, "pending": 0, "running": 0 });
    for r in rows {
        if let Some(n) = s.get_mut(r.status.as_str()).and_then(|v| v.as_i64()) {
            s[r.status.as_str()] = json!(n + 1);
        }
    }
    s
}

/// A row as the report serves it: the internal `_prior` stash removed.
pub fn public_row(row: &LedgerRow) -> Value {
    let mut details = row.details.clone();
    if let Some(o) = details.as_object_mut() {
        o.remove(PRIOR_KEY);
    }
    json!({
        "kind": row.kind, "key": row.key, "status": row.status, "message": row.message,
        "details": details, "attempts": row.attempts, "updated_at": row.updated_at,
    })
}

fn inventory_site<'a>(inventory: Option<&'a Value>, domain: &str) -> Option<&'a Value> {
    inventory?.get("sites")?.as_array()?.iter().find(|s| {
        s.get("domain").and_then(|d| d.as_str()).is_some_and(|d| d.eq_ignore_ascii_case(domain))
    })
}

/// The manual action of an import whose accounts had FTP in HestiaCP while this
/// server has no FTP server yet (feature 6, code `ftp_server_missing`).
pub const FTP_SERVER_MISSING_ACTION: &str = "Install the FTP server (Settings → Services) to restore FTP access";

/// The "what is left for a human" list of the report (W5-R).
pub fn manual_actions(rows: &[LedgerRow], inventory: Option<&Value>) -> Vec<String> {
    let finished = |r: &&LedgerRow| COMPLETED.contains(&r.status.as_str());
    let mut out = Vec::new();

    // DNS: every site that now exists here still resolves to the old server.
    let sites: Vec<&LedgerRow> = rows.iter().filter(|r| r.kind == "site").filter(finished).collect();
    if !sites.is_empty() {
        let names: Vec<String> = sites
            .iter()
            .map(|r| {
                let aliases: Vec<&str> = r
                    .details
                    .get("aliases")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                if aliases.is_empty() { r.key.clone() } else { format!("{} ({})", r.key, aliases.join(", ")) }
            })
            .collect();
        out.push(format!("Point the DNS records of these domains to this server: {}", names.join("; ")));
    }

    for r in rows {
        let d = &r.details;
        match r.kind.as_str() {
            "site" if finished(&r) => {
                if let Some(v) = d.get("php_version").and_then(|v| v.as_str())
                    && crate::routes::sites::LEGACY_PHP_VERSIONS.contains(&v)
                {
                    out.push(format!(
                        "{}: runs PHP {v}, which no longer gets security updates. Plan an upgrade.",
                        r.key
                    ));
                }
                let inv = inventory_site(inventory, &r.key);
                let was = |k: &str| inv.and_then(|s| s.get(k)).and_then(|v| v.as_bool());
                let now = |k: &str| d.get(k).and_then(|v| v.as_bool());
                if was("force_ssl") == Some(false) && now("force_ssl") == Some(true) {
                    out.push(format!("{}: Force SSL is on here but was off in HestiaCP.", r.key));
                }
                if was("hsts") == Some(false) && now("hsts") == Some(true) {
                    out.push(format!("{}: HSTS is on here but was off in HestiaCP.", r.key));
                }
            }
            "files" if finished(&r) => {
                if let Some(paths) = d.get("paths_to_fix").and_then(|p| p.as_array())
                    && !paths.is_empty()
                {
                    let list: Vec<String> = paths
                        .iter()
                        .filter_map(|p| {
                            let f = p.get("file")?.as_str()?;
                            let n = p.get("occurrences").and_then(|n| n.as_u64()).unwrap_or(0);
                            Some(format!("{f} ({n})"))
                        })
                        .collect();
                    out.push(format!(
                        "{}: these files still reference the old HestiaCP paths, check them: {}",
                        r.key,
                        list.join(", ")
                    ));
                }
                if let Some(t) = d.get("custom_nginx_saved").and_then(|v| v.as_str()) {
                    out.push(format!(
                        "{}: the custom HestiaCP nginx template was not translated. It is saved at {t}.",
                        r.key
                    ));
                }
                if let Some(links) = d.get("symlinks_out").and_then(|v| v.as_array())
                    && !links.is_empty()
                {
                    out.push(format!(
                        "{}: {} symbolic link(s) point outside the site and may not work.",
                        r.key,
                        links.len()
                    ));
                }
            }
            "ssl" if r.status == "warning" => out.push(format!(
                "{}: the HestiaCP certificate was not installed ({}). Issue a certificate once DNS points here.",
                r.key, r.message
            )),
            "sftp" if d.get("password").and_then(|v| v.as_str()) == Some("locked") => out.push(format!(
                "{}: the SFTP account is locked. Use Generate password (Reset password on the site's SFTP card).",
                r.key
            )),
            "mailbox" if r.status == "warning" && d.get("enabled").and_then(|v| v.as_bool()) == Some(false) => {
                out.push(format!("{}: mailbox disabled ({}). Set a new password.", r.key, r.message))
            }
            _ => {}
        }
    }
    // Feature 5 (A-H): owned by `import_mail`, one line whatever the number of domains.
    out.extend(crate::services::import_mail::antivirus_manual_action(rows, inventory));
    // Feature 6 (B-5): FTP was ticked on imported accounts, but vsftpd is missing.
    if rows.iter().any(|r| {
        r.kind == "sftp"
            && r.details.get("ftp").and_then(|v| v.as_str()) == Some(crate::services::import_sftp::FTP_SERVER_MISSING)
    }) {
        out.push(FTP_SERVER_MISSING_ACTION.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: &str, key: &str, status: &str, details: Value) -> LedgerRow {
        LedgerRow {
            kind: kind.into(),
            key: key.into(),
            status: status.into(),
            message: String::new(),
            details,
            attempts: 1,
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn finished_items_are_skipped_unless_forced() {
        assert_eq!(decide(Some("done"), false), Decision::Skip);
        assert_eq!(decide(Some("warning"), false), Decision::Skip);
        assert_eq!(decide(Some("done"), true), Decision::Run);
        for s in ["running", "failed", "pending", "skipped"] {
            assert_eq!(decide(Some(s), false), Decision::Run, "{s}");
        }
        assert_eq!(decide(None, false), Decision::Run);
    }

    #[test]
    fn item_refs_split_on_the_first_colon_and_know_their_kinds() {
        assert_eq!(parse_item_ref("db:adm-jim_x"), Some(("db", "adm-jim_x")));
        assert_eq!(parse_item_ref("mailbox:a@d.be"), Some(("mailbox", "a@d.be")));
        assert_eq!(parse_item_ref("mail_alias:x:y"), Some(("mail_alias", "x:y")));
        assert_eq!(parse_item_ref("bogus:x"), None);
        assert_eq!(parse_item_ref("db:"), None);
        assert_eq!(parse_item_ref("db"), None);
        assert_eq!(item_ref("files", "x.tld"), "files:x.tld");
    }

    #[test]
    fn hashes_and_keys_never_survive_redaction() {
        // Synthetic values only.
        let mysql = "*0123456789ABCDEF0123456789ABCDEF01234567";
        let yes = "$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc";
        let bcrypt = "{BLF-CRYPT}$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012";
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkq\n-----END PRIVATE KEY-----";
        let text = format!("user had {mysql} and {yes}; mail {bcrypt}; key {pem} end");
        let out = redact(&text);
        for secret in [mysql, yes, "$2y$05$", "MIIBVgIBADANBgkq", "BLF-CRYPT"] {
            assert!(!out.contains(secret), "{secret} leaked in {out}");
        }
        assert!(out.starts_with("user had [redacted hash]"));
        assert!(out.ends_with(" end"));
        // Ordinary report text is untouched.
        let plain = "Imported 12 tables, collation utf8mb4_unicode_ci, $HOME and {done}";
        assert_eq!(redact(plain), plain);
        let truncated = redact("agent said: -----BEGIN RSA PRIVATE KEY-----\nMIIEow");
        assert!(!truncated.contains("MIIEow"));
    }

    #[test]
    fn redaction_walks_nested_details() {
        let v = json!({ "a": ["ok", { "h": "*0123456789ABCDEF0123456789ABCDEF01234567" }], "n": 3 });
        let r = redact_json(&v);
        assert_eq!(r["a"][0], "ok");
        assert_eq!(r["a"][1]["h"], "[redacted hash]");
        assert_eq!(r["n"], 3);
    }

    #[test]
    fn summary_counts_every_status() {
        let rows = vec![
            row("site", "a", "done", json!({})),
            row("files", "a", "warning", json!({})),
            row("db", "x", "failed", json!({})),
            row("sftp", "a", "pending", json!({})),
        ];
        let s = summary(&rows);
        assert_eq!(s["done"], 1);
        assert_eq!(s["warning"], 1);
        assert_eq!(s["failed"], 1);
        assert_eq!(s["skipped"], 0);
        assert_eq!(s["pending"], 1);
    }

    #[test]
    fn site_id_is_found_in_the_row_or_its_prior_attempt() {
        let id = Uuid::new_v4();
        let now = row("site", "a", "done", json!({ "site_id": id.to_string() }));
        assert_eq!(site_id_of(&now), Some(id));
        let running = row("site", "a", "running", json!({ "_prior": { "status": "failed", "details": { "site_id": id.to_string() } } }));
        assert_eq!(site_id_of(&running), Some(id));
        assert_eq!(site_id_of(&row("site", "a", "failed", json!({}))), None);
        assert!(public_row(&running)["details"].get("_prior").is_none());
    }

    #[test]
    fn manual_actions_name_what_a_human_must_do() {
        let inv = json!({ "sites": [{ "domain": "x.tld", "force_ssl": false, "hsts": true }] });
        let rows = vec![
            row("site", "x.tld", "done", json!({ "aliases": ["www.x.tld"], "php_version": "5.6", "force_ssl": true, "hsts": true })),
            row("site", "gone.tld", "failed", json!({})),
            row("files", "x.tld", "warning", json!({
                "paths_to_fix": [{ "file": "wp-config.php", "occurrences": 2 }],
                "custom_nginx_saved": "/var/www/x.tld/private/.hestia-import/custom-nginx/custom.stpl"
            })),
            row("sftp", "x.tld", "warning", json!({ "password": "locked" })),
            row("mailbox", "a@d.be", "warning", json!({ "enabled": false })),
        ];
        let a = manual_actions(&rows, Some(&inv));
        let all = a.join("\n");
        assert!(a[0].contains("x.tld (www.x.tld)") && !a[0].contains("gone.tld"), "{all}");
        assert!(all.contains("PHP 5.6"));
        assert!(all.contains("Force SSL is on here"));
        assert!(!all.contains("HSTS is on here"));
        assert!(all.contains("wp-config.php (2)"));
        assert!(all.contains("custom-nginx/custom.stpl"));
        assert!(all.contains("SFTP account is locked"));
        assert!(all.contains("a@d.be: mailbox disabled"));
        assert!(!all.contains("Install the FTP server"));
    }

    #[test]
    fn a_missing_ftp_server_is_one_manual_action() {
        let rows = vec![
            row("sftp", "x.tld", "done", json!({ "ftp": "ftp_server_missing" })),
            row("sftp", "y.tld", "skipped", json!({ "ftp": "ftp_server_missing" })),
            row("sftp", "z.tld", "done", json!({ "ftp": "enabled" })),
        ];
        let a = manual_actions(&rows, None);
        let n = a.iter().filter(|l| l.as_str() == FTP_SERVER_MISSING_ACTION).count();
        assert_eq!(n, 1, "{a:?}");
        assert!(manual_actions(&rows[2..], None).iter().all(|l| l != FTP_SERVER_MISSING_ACTION));
    }
}
