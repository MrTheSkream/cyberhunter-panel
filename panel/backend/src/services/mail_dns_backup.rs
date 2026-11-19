//! Mail and DNS backups (Backup Orchestrator, lot 3): what the policy executor
//! and the restore routes share.
//!
//! * the archive names and the remote retention spec of the four families
//!   (`mail-{domain}-{local_b64url}-`, `mailcfg-`, `dns-zone-{zone}-`,
//!   `dns-snapshot-{backend}-`), and the guard that refuses to prune a family
//!   another resource also writes;
//! * the bodies sent to the agent's `/mail/archive`, `/mail/restore`,
//!   `/dns/archive` and `/dns/restore`, and the reading of their answers;
//! * the long-task protocol: those routes answer 202 `{job_id}`, and
//!   `GET /backup-jobs/{job_id}` is polled within a bounded budget;
//!   `{skipped: "not_installed"}` is neither a success nor a failure;
//! * the mail manifest, exported from the panel database: no clear secret ever
//!   enters it (the DKIM private key stays under its `secrets_crypto`
//!   encryption, password hashes are copied as hashes);
//! * the PowerDNS API, read from the `settings` table with a bare pool.

use std::future::Future;
use std::time::Duration;

use base64::Engine;
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::{AgentError, AgentHandle};
use crate::services::backup_policy_executor::{CreatedArchive, PruneSpec};

/// Where the agent writes mail archives (flat, one directory).
pub const MAIL_BACKUP_DIR: &str = "/var/backups/dockpanel/mail";
/// Where the agent writes DNS exports and snapshots (flat, one directory).
pub const DNS_BACKUP_DIR: &str = "/var/backups/dockpanel/dns";

/// The agent's answer when postfix/dovecot or pdns is absent.
pub const NOT_INSTALLED: &str = "not_installed";

/// Budget of the POST that starts a job. The agent answers 202 at once; a zone
/// export answers 200 directly after writing a small file.
pub const START_TIMEOUT_SECS: u64 = 120;

/// Budget of one mailbox archive or DNS snapshot taken by the executor, which
/// runs in the background with no HTTP ceiling. Same figure as app data.
pub const JOB_BUDGET_SECS: u64 = 1800;

/// Budget a restore route waits for its job before answering "still running".
/// The routes sit under the server's 300 s `TimeoutLayer`.
pub const ROUTE_JOB_BUDGET_SECS: u64 = 240;

/// Pause between two `GET /backup-jobs/{id}`.
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Consecutive transport failures tolerated while polling: an agent restart or
/// a dropped connection is not the job failing.
const POLL_MAX_TRANSPORT_ERRORS: u32 = 5;

// ── Names ──────────────────────────────────────────────────────────────────

/// The local part of a mailbox in the archive name: base64url without padding,
/// so a `_` or a `-` in the local part never makes the name ambiguous.
pub fn local_b64url(local: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(local.as_bytes())
}

/// `local@domain` split into `(local, domain)`, both non-empty.
pub fn split_address(email: &str) -> Option<(&str, &str)> {
    let (local, domain) = email.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('/') || domain.contains('/') {
        return None;
    }
    Some((local, domain))
}

/// `mail-{domain}-{local_b64url}`, the name every archive of one mailbox starts with.
pub fn mailbox_family(domain: &str, local: &str) -> String {
    format!("mail-{domain}-{}", local_b64url(local))
}

/// The mailbox archives of one address: `mail-{domain}-{local_b64url}-{stamp}.tar.gz[.enc]`.
/// With `stamp_only` the middle must be the stamp alone, so domain `a.com`
/// never takes the copies of `ab.com`, and local `a` never those of `ab`.
pub fn mailbox_prune_spec(domain: &str, local: &str) -> PruneSpec {
    PruneSpec {
        name_prefix: format!("{}-", mailbox_family(domain, local)),
        suffixes: vec![".tar.gz".to_string(), ".tar.gz.enc".to_string()],
    }
}

/// `mailcfg-{stamp}.tar.gz.enc` (always encrypted; the clear suffix is listed
/// so a copy written otherwise would still fall under retention).
pub fn mail_config_prune_spec() -> PruneSpec {
    PruneSpec {
        name_prefix: "mailcfg-".to_string(),
        suffixes: vec![".tar.gz".to_string(), ".tar.gz.enc".to_string()],
    }
}

/// A zone name as used in file names and rows: no final dot.
pub fn zone_label(zone: &str) -> String {
    zone.trim().trim_end_matches('.').to_string()
}

/// A zone name the panel will put in a file name or an API path: a valid
/// domain (letters, digits, `-`, `.`) once the final dot is removed.
pub fn is_valid_zone(zone: &str) -> bool {
    let z = zone_label(zone);
    crate::routes::is_valid_domain(&z)
}

/// `dns-zone-{zone}`, the name every export of one zone starts with.
pub fn dns_zone_family(zone: &str) -> String {
    format!("dns-zone-{}", zone_label(zone))
}

/// `dns-zone-{zone}-{stamp}.json[.enc]`.
pub fn dns_zone_prune_spec(zone: &str) -> PruneSpec {
    PruneSpec {
        name_prefix: format!("{}-", dns_zone_family(zone)),
        suffixes: vec![".json".to_string(), ".json.enc".to_string()],
    }
}

/// `sqlite` or `pgsql`, the only PowerDNS backends the agent snapshots.
pub fn parse_dns_backend(s: &str) -> Option<&'static str> {
    match s {
        "sqlite" => Some("sqlite"),
        "pgsql" => Some("pgsql"),
        _ => None,
    }
}

/// `dns-snapshot-{backend}-{stamp}.gz.enc` (always encrypted).
pub fn dns_snapshot_prune_spec(backend: &str) -> PruneSpec {
    PruneSpec {
        name_prefix: format!("dns-snapshot-{backend}-"),
        suffixes: vec![".gz".to_string(), ".gz.enc".to_string()],
    }
}

/// A plain file name: no path, no `..`, no NUL.
pub fn is_plain_filename(f: &str) -> bool {
    !f.is_empty() && f.len() <= 255 && !f.contains('/') && !f.contains('\\') && !f.contains("..") && !f.contains('\0')
}

/// The `[A-Za-z0-9._-]` middle of a name is exactly `%Y%m%d-%H%M%S`.
fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 15
        && b[8] == b'-'
        && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
}

/// `true` when `filename` is `<prefix><stamp><suffix>` for one of the spec's
/// suffixes: what the agent's stamp-only prune would count as this family's.
pub fn spec_matches(spec: &PruneSpec, filename: &str) -> bool {
    let Some(rest) = filename.strip_prefix(&spec.name_prefix) else { return false };
    spec.suffixes.iter().any(|suf| rest.strip_suffix(suf.as_str()).is_some_and(is_stamp))
}

// ── Bodies sent to the agent ───────────────────────────────────────────────

/// `merge` (default: copy without overwriting newer mail) or `replace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    Merge,
    Replace,
}

impl RestoreMode {
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s {
            None | Some("merge") => Some(Self::Merge),
            Some("replace") => Some(Self::Replace),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }
}

fn with_key(mut b: serde_json::Value, key: Option<&str>) -> serde_json::Value {
    if let Some(k) = key {
        b["encryption_key"] = serde_json::Value::String(k.to_string());
    }
    b
}

/// `POST /mail/archive` for one mailbox.
pub fn mailbox_archive_body(domain: &str, local: &str, key: Option<&str>) -> serde_json::Value {
    with_key(serde_json::json!({ "kind": "mailbox", "domain": domain, "local": local }), key)
}

/// `POST /mail/archive` for the mail configuration. The key is not optional:
/// the archive carries the DKIM keys and the password hashes.
pub fn mail_config_archive_body(manifest: &serde_json::Value, key: &str) -> serde_json::Value {
    serde_json::json!({ "kind": "config", "manifest": manifest, "encryption_key": key })
}

/// `POST /mail/restore` for one mailbox.
pub fn mailbox_restore_body(
    domain: &str,
    local: &str,
    filename: &str,
    mode: RestoreMode,
    key: Option<&str>,
) -> serde_json::Value {
    with_key(
        serde_json::json!({
            "kind": "mailbox", "domain": domain, "local": local,
            "filename": filename, "mode": mode.as_str(),
        }),
        key,
    )
}

/// `POST /mail/restore` for the configuration: the agent decrypts and hands
/// the manifest back; it restores no file.
pub fn mail_config_restore_body(filename: &str, key: &str) -> serde_json::Value {
    serde_json::json!({ "kind": "config", "filename": filename, "encryption_key": key })
}

/// `POST /dns/archive` for one zone, with the export the panel read from the
/// PowerDNS API. `zone` is the FQDN (final dot).
pub fn dns_zone_archive_body(zone_fqdn: &str, content: &serde_json::Value, key: Option<&str>) -> serde_json::Value {
    with_key(serde_json::json!({ "kind": "zone", "zone": zone_fqdn, "content": content }), key)
}

/// `POST /dns/archive` for the whole PowerDNS database (always encrypted).
pub fn dns_snapshot_archive_body(key: &str) -> serde_json::Value {
    serde_json::json!({ "kind": "snapshot", "encryption_key": key })
}

/// `POST /dns/restore`: `kind` is `zone` or `snapshot`.
pub fn dns_restore_body(kind: &str, filename: &str, key: Option<&str>) -> serde_json::Value {
    with_key(serde_json::json!({ "kind": kind, "filename": filename }), key)
}

// ── The long-task protocol ─────────────────────────────────────────────────

/// What a POST to a job-capable route answered.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentStart {
    /// `{"skipped": "<reason>"}`: the component is not installed.
    Skipped(String),
    /// 202 `{"job_id": "..."}`.
    Job(String),
    /// A direct 200 answer (zone export, config manifest).
    Done(serde_json::Value),
}

/// A job id goes into a URL path: only a UUID-like token is accepted.
pub fn is_valid_job_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

pub fn parse_agent_start(resp: &serde_json::Value) -> Result<AgentStart, String> {
    if let Some(reason) = resp.get("skipped").and_then(|v| v.as_str()) {
        return Ok(AgentStart::Skipped(reason.to_string()));
    }
    if let Some(id) = resp.get("job_id").and_then(|v| v.as_str()) {
        if !is_valid_job_id(id) {
            return Err("the agent answered an invalid job id".to_string());
        }
        return Ok(AgentStart::Job(id.to_string()));
    }
    Ok(AgentStart::Done(resp.clone()))
}

/// The state `GET /backup-jobs/{id}` reports.
#[derive(Debug, Clone, PartialEq)]
pub enum JobState {
    Running,
    Done(serde_json::Value),
    /// The agent's message and the HTTP status it gives the failure
    /// (`error_code`: 422 integrity, 400 validation, 507 disk...), if any.
    Failed(String, Option<u16>),
}

pub fn parse_job_state(resp: &serde_json::Value) -> Result<JobState, String> {
    match resp.get("status").and_then(|v| v.as_str()) {
        Some("running") => Ok(JobState::Running),
        Some("done") => Ok(JobState::Done(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))),
        Some("failed") => Ok(JobState::Failed(
            resp.get("error")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("the agent reported the job as failed without a reason")
                .to_string(),
            resp.get("error_code").and_then(|v| v.as_u64()).and_then(|c| u16::try_from(c).ok()),
        )),
        Some(other) => Err(format!("the agent reported an unknown job status '{other}'")),
        None => Err("the agent's job answer has no status".to_string()),
    }
}

/// Why waiting for a job ended without a result.
#[derive(Debug, Clone, PartialEq)]
pub enum JobWaitError {
    /// The agent says the job failed: its message and its `error_code`.
    Failed(String, Option<u16>),
    /// The budget ran out; the job may still be running on the agent.
    TimedOut,
    /// The agent no longer knows the job (restarted), or kept refusing to answer.
    Lost(String),
}

impl std::fmt::Display for JobWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(e, _) => write!(f, "{e}"),
            Self::TimedOut => write!(f, "still running when the wait budget ran out"),
            Self::Lost(e) => write!(f, "the job was lost: {e}"),
        }
    }
}

/// Poll `fetch` (one `GET /backup-jobs/{id}`) until the job ends or `budget`
/// runs out. A 404 means the agent forgot the job (a restart): it is lost, not
/// worth polling further. A few consecutive transport errors are tolerated.
pub async fn poll_job<F, Fut>(mut fetch: F, budget: Duration, interval: Duration) -> Result<serde_json::Value, JobWaitError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<serde_json::Value, AgentError>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut transport_errors = 0u32;
    loop {
        match fetch().await {
            Ok(resp) => {
                transport_errors = 0;
                match parse_job_state(&resp) {
                    Ok(JobState::Done(v)) => return Ok(v),
                    Ok(JobState::Failed(e, code)) => return Err(JobWaitError::Failed(e, code)),
                    Ok(JobState::Running) => {}
                    Err(e) => return Err(JobWaitError::Lost(e)),
                }
            }
            Err(AgentError::Status(404, _)) | Err(AgentError::NotFound(_)) => {
                return Err(JobWaitError::Lost("the agent no longer knows this job (was it restarted?)".to_string()));
            }
            Err(AgentError::Status(code, body)) if code < 500 => {
                return Err(JobWaitError::Lost(format!("the agent refused the job query ({code}): {}", crate::error::agent_message(&body))));
            }
            Err(e) => {
                transport_errors += 1;
                if transport_errors >= POLL_MAX_TRANSPORT_ERRORS {
                    return Err(JobWaitError::Lost(format!("the agent did not answer {transport_errors} times in a row: {e}")));
                }
            }
        }
        if tokio::time::Instant::now() + interval > deadline {
            return Err(JobWaitError::TimedOut);
        }
        tokio::time::sleep(interval).await;
    }
}

/// The HTTP status a restore route answers when the agent's job failed with
/// `error_code`: the classes the synchronous restores already pass through
/// (validation, missing file, conflict, integrity or passphrase, disk full)
/// keep their status; anything else (500, none) is the agent's failure, 502.
pub fn job_failure_status(error_code: Option<u16>) -> u16 {
    match error_code {
        Some(c @ (400 | 404 | 409 | 422 | 507)) => c,
        _ => 502,
    }
}

/// How a job-capable call ended.
#[derive(Debug, Clone, PartialEq)]
pub enum JobOutcome {
    Skipped(String),
    Done(serde_json::Value),
    /// Budget exhausted; the job id lets the caller (or the UI) keep polling.
    StillRunning(String),
}

/// POST `path`, then follow the job it started for at most `budget`.
/// `Err` carries an operator-readable message.
pub async fn start_and_wait(
    agent: &AgentHandle,
    path: &str,
    body: serde_json::Value,
    budget: Duration,
) -> Result<JobOutcome, String> {
    let resp = agent
        .post_long(path, Some(body), START_TIMEOUT_SECS)
        .await
        .map_err(|e| agent_error_text(&e))?;
    match parse_agent_start(&resp)? {
        AgentStart::Skipped(r) => Ok(JobOutcome::Skipped(r)),
        AgentStart::Done(v) => Ok(JobOutcome::Done(v)),
        AgentStart::Job(id) => match wait_job(agent, &id, budget).await {
            Ok(v) => Ok(JobOutcome::Done(v)),
            Err(JobWaitError::TimedOut) => Ok(JobOutcome::StillRunning(id)),
            Err(e) => Err(e.to_string()),
        },
    }
}

/// Follow job `id` on `agent` for at most `budget`.
pub async fn wait_job(agent: &AgentHandle, id: &str, budget: Duration) -> Result<serde_json::Value, JobWaitError> {
    let job_path = format!("/backup-jobs/{id}");
    poll_job(|| agent.get(&job_path), budget, POLL_INTERVAL).await
}

/// The agent's own sentence for a failed call, for a message the operator reads.
pub fn agent_error_text(e: &AgentError) -> String {
    match e {
        AgentError::Status(code, body) => format!("agent returned {code}: {}", crate::error::agent_message(body)),
        other => other.to_string(),
    }
}

// ── Reading what the agent wrote ───────────────────────────────────────────

/// Read `{filename, size_bytes, sha256, encrypted}` and check the name against
/// the family's spec. `encrypted` must agree with the `.enc` suffix, and when
/// `must_encrypt` a clear file is refused (config and snapshot are always
/// encrypted: shipping one in clear would leak DKIM keys or password hashes).
pub fn parse_created(resp: &serde_json::Value, spec: &PruneSpec, must_encrypt: bool) -> Result<CreatedArchive, String> {
    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if filename.is_empty() {
        return Err("the agent's answer named no file".to_string());
    }
    if !is_plain_filename(&filename) {
        return Err("the agent's answer named an unsafe file".to_string());
    }
    if !spec_matches(spec, &filename) {
        return Err(format!(
            "the agent's file name '{filename}' is not of the form {}<timestamp>{}",
            spec.name_prefix,
            spec.suffixes.join("|")
        ));
    }
    let enc_suffix = filename.ends_with(".enc");
    let encrypted = resp.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
    if encrypted != enc_suffix {
        return Err(format!("the agent's answer says encrypted={encrypted} for '{filename}'"));
    }
    if must_encrypt && !encrypted {
        return Err(format!("the agent wrote '{filename}' unencrypted although it must always be encrypted"));
    }
    Ok(CreatedArchive {
        filename,
        size_bytes: resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64,
        sha256: resp.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        encrypted,
    })
}

/// The backend a DNS snapshot result names.
pub fn parse_snapshot_backend(resp: &serde_json::Value) -> Result<&'static str, String> {
    resp.get("backend")
        .and_then(|v| v.as_str())
        .and_then(parse_dns_backend)
        .ok_or_else(|| "the agent's snapshot answer names no sqlite or pgsql backend".to_string())
}

// ── Mail manifest ──────────────────────────────────────────────────────────

/// Format marker of the manifest, checked on restore.
pub const MANIFEST_FORMAT: &str = "dockpanel-mail-manifest";
pub const MANIFEST_VERSION: u32 = 1;
/// How the DKIM private key is protected inside the manifest: the panel's
/// credential encryption (`secrets_crypto::encrypt_credential`, AES-256-GCM,
/// key derived from JWT_SECRET or SECRETS_ENCRYPTION_KEY), version 1.
pub const DKIM_KEY_SCHEME: &str = "secrets_crypto.credential";
pub const DKIM_KEY_SCHEME_VERSION: u32 = 1;

/// One `mail_domains` row as the manifest needs it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRow {
    pub domain: String,
    pub dkim_selector: String,
    pub dkim_public_key: Option<String>,
    /// As stored: `secrets_crypto` ciphertext, or legacy plaintext PEM.
    pub dkim_private_key: Option<String>,
    pub catch_all: Option<String>,
    pub enabled: bool,
}

/// One `mail_accounts` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountRow {
    pub email: String,
    pub domain: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub quota_mb: i32,
    pub enabled: bool,
    pub forward_to: Option<String>,
    pub keep_copy: bool,
    pub autoresponder_enabled: bool,
    pub autoresponder_subject: Option<String>,
    pub autoresponder_body: Option<String>,
}

/// One `mail_aliases` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AliasRow {
    pub domain: String,
    pub source_email: String,
    pub destination_email: String,
}

/// A stored DKIM private key that is still clear text (written before the
/// column was encrypted).
fn is_clear_pem(v: &str) -> bool {
    v.trim_start().starts_with("-----BEGIN")
}

/// The manifest's form of a stored DKIM private key: always ciphertext. A
/// legacy clear PEM is encrypted first, with the same function the column
/// uses, so the manifest never carries a key in clear.
pub fn dkim_key_for_manifest(stored: Option<&str>, jwt_secret: &str) -> Result<Option<serde_json::Value>, String> {
    let Some(v) = stored.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let enc = if is_clear_pem(v) {
        crate::services::secrets_crypto::encrypt_credential(v, jwt_secret)
            .map_err(|_| "a DKIM key could not be encrypted for the manifest".to_string())?
    } else {
        v.to_string()
    };
    Ok(Some(serde_json::json!({
        "encrypted": enc,
        "scheme": DKIM_KEY_SCHEME,
        "version": DKIM_KEY_SCHEME_VERSION,
    })))
}

/// The manifest of ONE server's mail configuration, exported from the panel
/// database. Rows must already be scoped to that server (`md.server_id`).
pub fn build_mail_manifest(
    server_id: Uuid,
    domains: &[DomainRow],
    accounts: &[AccountRow],
    aliases: &[AliasRow],
    jwt_secret: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value, String> {
    let mut ds = Vec::with_capacity(domains.len());
    for d in domains {
        ds.push(serde_json::json!({
            "domain": d.domain,
            "dkim_selector": d.dkim_selector,
            "dkim_public_key": d.dkim_public_key,
            "dkim_private_key": dkim_key_for_manifest(d.dkim_private_key.as_deref(), jwt_secret)?,
            "catch_all": d.catch_all,
            "enabled": d.enabled,
        }));
    }
    Ok(serde_json::json!({
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "server_id": server_id,
        "created_at": created_at.to_rfc3339(),
        "domains": ds,
        "accounts": accounts.iter().map(|a| serde_json::json!({
            "email": a.email,
            "domain": a.domain,
            "password_hash": a.password_hash,
            "display_name": a.display_name,
            "quota_mb": a.quota_mb,
            "enabled": a.enabled,
            "forward_to": a.forward_to,
            "keep_copy": a.keep_copy,
            "autoresponder_enabled": a.autoresponder_enabled,
            "autoresponder_subject": a.autoresponder_subject,
            "autoresponder_body": a.autoresponder_body,
        })).collect::<Vec<_>>(),
        "aliases": aliases.iter().map(|a| serde_json::json!({
            "domain": a.domain,
            "source_email": a.source_email,
            "destination_email": a.destination_email,
        })).collect::<Vec<_>>(),
    }))
}

/// Read ONE server's mail rows for the manifest. Every read is scoped through
/// `mail_domains.server_id`: a fleet-wide read would copy other hosts' password
/// hashes into this host's archive.
pub async fn load_mail_rows(
    db: &PgPool,
    server_id: Uuid,
) -> Result<(Vec<DomainRow>, Vec<AccountRow>, Vec<AliasRow>), sqlx::Error> {
    let domains: Vec<DomainRow> = sqlx::query_as(
        "SELECT domain, dkim_selector, dkim_public_key, dkim_private_key, catch_all, enabled \
         FROM mail_domains WHERE server_id = $1 ORDER BY domain",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?;
    let accounts: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.email, md.domain, a.password_hash, a.display_name, a.quota_mb, a.enabled, \
                a.forward_to, a.keep_copy, a.autoresponder_enabled, a.autoresponder_subject, a.autoresponder_body \
         FROM mail_accounts a JOIN mail_domains md ON md.id = a.domain_id \
         WHERE md.server_id = $1 ORDER BY a.email",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?;
    let aliases: Vec<AliasRow> = sqlx::query_as(
        "SELECT md.domain, al.source_email, al.destination_email \
         FROM mail_aliases al JOIN mail_domains md ON md.id = al.domain_id \
         WHERE md.server_id = $1 ORDER BY al.source_email",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?;
    Ok((domains, accounts, aliases))
}

/// A manifest read back for a restore, validated field by field: every value
/// goes back into the database and into `/mail/sync`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailManifest {
    pub domains: Vec<ManifestDomain>,
    pub accounts: Vec<ManifestAccount>,
    pub aliases: Vec<ManifestAlias>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestDomain {
    pub domain: String,
    pub dkim_selector: String,
    pub dkim_public_key: Option<String>,
    /// Ciphertext (`DKIM_KEY_SCHEME`), never decrypted by the parser.
    pub dkim_private_key_enc: Option<String>,
    pub catch_all: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestAccount {
    pub email: String,
    pub domain: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub quota_mb: i32,
    pub enabled: bool,
    pub forward_to: Option<String>,
    pub keep_copy: bool,
    pub autoresponder_enabled: bool,
    pub autoresponder_subject: Option<String>,
    pub autoresponder_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestAlias {
    pub domain: String,
    pub source_email: String,
    pub destination_email: String,
}

/// ASCII alphanumeric plus `@ . _ - +`: what the agent's `/mail/sync` accepts.
fn is_mail_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+'))
}

fn is_selector(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn parse_mail_manifest(v: &serde_json::Value) -> Result<MailManifest, String> {
    if v.get("format").and_then(|f| f.as_str()) != Some(MANIFEST_FORMAT) {
        return Err("the archive does not hold a DockPanel mail manifest".to_string());
    }
    let s = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let b = |o: &serde_json::Value, k: &str, d: bool| o.get(k).and_then(|x| x.as_bool()).unwrap_or(d);
    let list = |k: &str| v.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();

    let mut m = MailManifest::default();
    for d in list("domains") {
        let domain = s(&d, "domain").unwrap_or_default().to_ascii_lowercase();
        if !crate::routes::is_valid_domain(&domain) {
            return Err(format!("the manifest names an invalid mail domain '{domain}'"));
        }
        let selector = s(&d, "dkim_selector").unwrap_or_else(|| "dockpanel".to_string());
        if !is_selector(&selector) {
            return Err(format!("the manifest names an invalid DKIM selector for {domain}"));
        }
        let key = d.get("dkim_private_key").filter(|k| !k.is_null());
        let dkim_private_key_enc = match key {
            None => None,
            Some(k) => {
                if k.get("scheme").and_then(|x| x.as_str()) != Some(DKIM_KEY_SCHEME) {
                    return Err(format!("the DKIM key of {domain} uses an unknown protection scheme"));
                }
                let enc = s(k, "encrypted").unwrap_or_default();
                if enc.is_empty() || is_clear_pem(&enc) {
                    return Err(format!("the DKIM key of {domain} is not encrypted in the manifest"));
                }
                Some(enc)
            }
        };
        let catch_all = s(&d, "catch_all").filter(|c| !c.is_empty());
        if let Some(c) = &catch_all {
            if !is_mail_token(c) {
                return Err(format!("the manifest names an invalid catch-all for {domain}"));
            }
        }
        m.domains.push(ManifestDomain {
            domain,
            dkim_selector: selector,
            dkim_public_key: s(&d, "dkim_public_key"),
            dkim_private_key_enc,
            catch_all,
            enabled: b(&d, "enabled", true),
        });
    }
    for a in list("accounts") {
        let email = s(&a, "email").unwrap_or_default().to_ascii_lowercase();
        let Some((_, dom)) = split_address(&email) else {
            return Err(format!("the manifest names an invalid mailbox '{email}'"));
        };
        if !is_mail_token(&email) || !m.domains.iter().any(|d| d.domain == dom) {
            return Err(format!("the manifest names an invalid mailbox '{email}'"));
        }
        let hash = s(&a, "password_hash").unwrap_or_default();
        if hash.is_empty() || hash.len() > 255 {
            return Err(format!("the manifest has no usable password hash for {email}"));
        }
        let forward_to = s(&a, "forward_to").filter(|f| !f.is_empty());
        if let Some(f) = &forward_to {
            if !f.split(',').all(|x| is_mail_token(x.trim())) {
                return Err(format!("the manifest names an invalid forward for {email}"));
            }
        }
        m.accounts.push(ManifestAccount {
            domain: dom.to_string(),
            email: email.clone(),
            password_hash: hash,
            display_name: s(&a, "display_name"),
            quota_mb: a.get("quota_mb").and_then(|x| x.as_i64()).unwrap_or(1024).clamp(0, i32::MAX as i64) as i32,
            enabled: b(&a, "enabled", true),
            forward_to,
            keep_copy: b(&a, "keep_copy", false),
            autoresponder_enabled: b(&a, "autoresponder_enabled", false),
            autoresponder_subject: s(&a, "autoresponder_subject"),
            autoresponder_body: s(&a, "autoresponder_body"),
        });
    }
    for al in list("aliases") {
        let domain = s(&al, "domain").unwrap_or_default().to_ascii_lowercase();
        let src = s(&al, "source_email").unwrap_or_default().to_ascii_lowercase();
        let dst = s(&al, "destination_email").unwrap_or_default();
        if !m.domains.iter().any(|d| d.domain == domain) || !is_mail_token(&src) || !dst.split(',').all(|x| is_mail_token(x.trim())) {
            return Err(format!("the manifest names an invalid alias '{src}'"));
        }
        m.aliases.push(ManifestAlias { domain, source_email: src, destination_email: dst });
    }
    Ok(m)
}

// ── Remote retention guard ─────────────────────────────────────────────────

/// SQL stripping `-{stamp}{suffix}` from a file name, leaving its family.
const FAMILY_SQL: &str =
    "regexp_replace(filename, '-[0-9]{8}-[0-9]{6}\\.(tar\\.gz|json|gz)(\\.enc)?$', '')";

/// `Some(reason)` when another resource writes the same names as `family` to a
/// shared destination: with stamp-only retention, only an EXACT family match
/// can mix two resources' copies.
pub fn family_conflict_reason(family: &str, others: &[&str]) -> Option<String> {
    if others.is_empty() {
        return None;
    }
    Some(format!(
        "remote retention skipped: the file name prefix '{family}-' is also used by {}, so pruning could delete their backups",
        others.join(" and ")
    ))
}

/// Mailbox family on `server_id`: another server holding mail backups of the
/// same family (the same domain can exist on two servers), another mailbox
/// whose name maps to the same family, a site whose domain equals it, or app
/// data with that family (all share the `.tar.gz` suffix).
pub async fn mailbox_prune_conflict(db: &PgPool, server_id: Uuid, domain: &str, local: &str) -> Result<Option<String>, String> {
    let family = mailbox_family(domain, local);
    let own = format!("{local}@{domain}");
    let (other_servers, sites, volumes): (i64, i64, i64) = sqlx::query_as(&format!(
        "SELECT (SELECT COUNT(DISTINCT server_id) FROM mail_backups \
                  WHERE server_id IS DISTINCT FROM $2 AND kind = 'mailbox' AND {FAMILY_SQL} = $1), \
                (SELECT COUNT(*) FROM sites WHERE domain = $1), \
                (SELECT COUNT(*) FROM volume_backups WHERE {FAMILY_SQL} = $1)"
    ))
    .bind(&family)
    .bind(server_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    // `{domain}-{b64}` can in theory equal another (domain, local) pair's when
    // the domain itself carries a `-` label: compared in Rust, over every mailbox.
    let emails: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT a.email, md.server_id FROM mail_accounts a JOIN mail_domains md ON md.id = a.domain_id",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("could not check which mailboxes share the name prefix: {e}"))?;
    let other_mailboxes = emails
        .iter()
        .filter(|(e, sid)| {
            split_address(e).is_some_and(|(l, d)| mailbox_family(d, l) == family)
                && !(e.eq_ignore_ascii_case(&own) && *sid == Some(server_id))
        })
        .count();
    let mut others = Vec::new();
    if other_servers > 0 || other_mailboxes > 0 {
        others.push("another mailbox");
    }
    if sites > 0 {
        others.push("a site");
    }
    if volumes > 0 {
        others.push("app data");
    }
    Ok(family_conflict_reason(&family, &others))
}

/// `mailcfg-` is the same on every server: two servers sending their mail
/// config to one destination would prune each other's copies.
pub async fn mail_config_prune_conflict(db: &PgPool, server_id: Uuid) -> Result<Option<String>, String> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT server_id) FROM mail_backups WHERE kind = 'config' AND server_id IS DISTINCT FROM $1",
    )
    .bind(server_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(family_conflict_reason("mailcfg", if n > 0 { &["the mail config of another server"] } else { &[] }))
}

/// A zone exported from two PowerDNS hosts (the DNS host changed) writes the
/// same names.
pub async fn dns_zone_prune_conflict(db: &PgPool, server_id: Uuid, zone: &str) -> Result<Option<String>, String> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT server_id) FROM dns_backups \
          WHERE kind = 'zone' AND zone = $1 AND server_id IS DISTINCT FROM $2",
    )
    .bind(zone_label(zone))
    .bind(server_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(family_conflict_reason(&dns_zone_family(zone), if n > 0 { &["the same zone on another server"] } else { &[] }))
}

/// `dns-snapshot-{backend}-` is the same on every server.
pub async fn dns_snapshot_prune_conflict(db: &PgPool, server_id: Uuid, backend: &str) -> Result<Option<String>, String> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT server_id) FROM dns_backups \
          WHERE kind = 'snapshot' AND backend = $1 AND server_id IS DISTINCT FROM $2",
    )
    .bind(backend)
    .bind(server_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(family_conflict_reason(
        &format!("dns-snapshot-{backend}"),
        if n > 0 { &["the DNS snapshot of another server"] } else { &[] },
    ))
}

// ── PowerDNS API ───────────────────────────────────────────────────────────

/// The PowerDNS HTTP API as configured in `settings` (`pdns_api_url`, and
/// `pdns_api_key` decrypted). Never logged.
#[derive(Clone)]
pub struct PdnsApi {
    pub url: String,
    pub key: String,
}

/// `Ok(None)` when PowerDNS is not configured in the panel.
pub async fn pdns_api_from_settings(db: &PgPool, jwt_secret: &str) -> Result<Option<PdnsApi>, String> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')")
            .fetch_all(db)
            .await
            .map_err(|e| format!("could not read the PowerDNS settings: {e}"))?;
    let mut url = String::new();
    let mut key_enc = String::new();
    for (k, v) in rows {
        match k.as_str() {
            "pdns_api_url" => url = v,
            "pdns_api_key" => key_enc = v,
            _ => {}
        }
    }
    if url.is_empty() || key_enc.is_empty() {
        return Ok(None);
    }
    let key = crate::services::secrets_crypto::decrypt_credential_or_legacy(&key_enc, jwt_secret);
    Ok(Some(PdnsApi { url: url.trim_end_matches('/').to_string(), key }))
}

/// `settings.pdns_server_id`: the server PowerDNS was installed on. `None`
/// when absent (an install that predates the key) or unreadable as a UUID.
pub async fn pdns_server_id(db: &PgPool) -> Result<Option<Uuid>, String> {
    let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'pdns_server_id'")
        .fetch_optional(db)
        .await
        .map_err(|e| format!("could not read pdns_server_id: {e}"))?;
    Ok(v.and_then(|s| s.trim().parse::<Uuid>().ok()))
}

impl PdnsApi {
    fn client(&self) -> Result<(reqwest::Client, reqwest::header::HeaderMap), String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("could not build the PowerDNS client: {e}"))?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-API-Key",
            reqwest::header::HeaderValue::from_str(&self.key).map_err(|_| "invalid PowerDNS API key".to_string())?,
        );
        headers.insert("Content-Type", reqwest::header::HeaderValue::from_static("application/json"));
        Ok((client, headers))
    }

    fn zones_url(&self) -> String {
        format!("{}/api/v1/servers/localhost/zones", self.url)
    }

    /// Every zone PowerDNS serves, as FQDNs.
    pub async fn list_zones(&self) -> Result<Vec<String>, String> {
        let (client, headers) = self.client()?;
        let resp = client
            .get(self.zones_url())
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("PowerDNS API unreachable: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("PowerDNS API answered {} to the zone list", resp.status().as_u16()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| format!("PowerDNS zone list unreadable: {e}"))?;
        Ok(v.as_array()
            .map(|a| a.iter().filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(str::to_string)).collect())
            .unwrap_or_default())
    }

    /// `GET /zones/{zone}`: the zone with its rrsets.
    pub async fn export_zone(&self, zone_fqdn: &str) -> Result<serde_json::Value, String> {
        let (client, headers) = self.client()?;
        let resp = client
            .get(format!("{}/{zone_fqdn}", self.zones_url()))
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("PowerDNS API unreachable: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("PowerDNS API answered {} for zone {zone_fqdn}", resp.status().as_u16()));
        }
        resp.json().await.map_err(|e| format!("PowerDNS zone {zone_fqdn} unreadable: {e}"))
    }

    /// Put an exported zone back: `POST /zones` with its rrsets. A 409 (the
    /// zone exists) re-adopts it: one `PATCH` replaces every exported rrset
    /// and deletes every rrset the zone has now that the backup does not
    /// (the SOA excepted, it is replaced), so the zone ends up as it was
    /// saved. The SOA serial is left to PowerDNS (`soa_edit_api`): it goes up,
    /// which is what secondaries need to pick the change. Returns
    /// `(readopted, rrsets)`.
    pub async fn apply_zone(&self, content: &serde_json::Value) -> Result<(bool, usize), String> {
        let (create, mut patch, n) = zone_restore_bodies(content)?;
        let zone = create["name"].as_str().unwrap_or_default().to_string();
        let (client, headers) = self.client()?;
        let resp = client
            .post(self.zones_url())
            .headers(headers.clone())
            .json(&create)
            .send()
            .await
            .map_err(|e| format!("PowerDNS API unreachable: {e}"))?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return Ok((false, n));
        }
        if status != 409 {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!("PowerDNS refused to create zone {zone} ({status}): {}", body.chars().take(300).collect::<String>());
            return Err(format!("PowerDNS refused to create zone {zone} ({status})"));
        }
        // What the zone holds now: without it, records added after the backup
        // would survive the restore. No fallback to a replace-only PATCH.
        let current = self
            .export_zone(&zone)
            .await
            .map_err(|e| format!("zone {zone} exists and its current records could not be read: {e}"))?;
        let deletions = zone_rrset_deletions(&patch, &current);
        if let Some(list) = patch.get_mut("rrsets").and_then(|v| v.as_array_mut()) {
            list.extend(deletions);
        }
        let resp = client
            .patch(format!("{}/{zone}", self.zones_url()))
            .headers(headers)
            .json(&patch)
            .send()
            .await
            .map_err(|e| format!("PowerDNS API unreachable: {e}"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!("PowerDNS refused the records of zone {zone} ({status}): {}", body.chars().take(300).collect::<String>());
            return Err(format!("zone {zone} exists and PowerDNS refused to replace its records ({status})"));
        }
        Ok((true, n))
    }
}

/// From a zone export, the `POST /zones` body (selected fields only, never the
/// raw export: `id`, `url`, `serial`... are not accepted on create) and the
/// `PATCH` body replacing every exported rrset. Returns the rrset count too.
pub fn zone_restore_bodies(content: &serde_json::Value) -> Result<(serde_json::Value, serde_json::Value, usize), String> {
    let name = content.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if !is_valid_zone(name) {
        return Err("the zone export names no valid zone".to_string());
    }
    let zone = format!("{}.", zone_label(name));
    let rrsets_in = content.get("rrsets").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut rrsets = Vec::with_capacity(rrsets_in.len());
    for r in &rrsets_in {
        let (Some(rname), Some(rtype)) = (r.get("name").and_then(|v| v.as_str()), r.get("type").and_then(|v| v.as_str())) else {
            return Err("the zone export holds an rrset without a name or a type".to_string());
        };
        let records: Vec<serde_json::Value> = r
            .get("records")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|rec| {
                        rec.get("content").and_then(|c| c.as_str()).map(|c| {
                            serde_json::json!({
                                "content": c,
                                "disabled": rec.get("disabled").and_then(|d| d.as_bool()).unwrap_or(false),
                            })
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        rrsets.push(serde_json::json!({
            "name": rname,
            "type": rtype,
            "ttl": r.get("ttl").and_then(|v| v.as_u64()).unwrap_or(3600),
            "records": records,
        }));
    }
    let kind = match content.get("kind").and_then(|v| v.as_str()) {
        Some(k @ ("Native" | "Master" | "Slave" | "Producer" | "Consumer")) => k,
        _ => "Native",
    };
    let soa_edit_api = content.get("soa_edit_api").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("DEFAULT");
    let create = serde_json::json!({
        "name": zone,
        "kind": kind,
        "nameservers": [],
        "soa_edit_api": soa_edit_api,
        "rrsets": rrsets,
    });
    let patch = serde_json::json!({
        "rrsets": rrsets.iter().map(|r| {
            let mut r = r.clone();
            r["changetype"] = serde_json::Value::String("REPLACE".to_string());
            r
        }).collect::<Vec<_>>(),
    });
    Ok((create, patch, rrsets_in.len()))
}

/// The `DELETE` changes that make a re-adopted zone identical to its backup:
/// one per (name, type) the zone holds now (`current`, a `GET /zones/{zone}`)
/// and the restore `patch` does not replace. Names compare without case and
/// trailing dot; the SOA is never deleted (it is replaced); each pair once,
/// PowerDNS refusing a PATCH that names one twice.
pub fn zone_rrset_deletions(patch: &serde_json::Value, current: &serde_json::Value) -> Vec<serde_json::Value> {
    fn key(r: &serde_json::Value) -> Option<(String, String, String)> {
        let name = r.get("name")?.as_str()?;
        let rtype = r.get("type")?.as_str()?;
        Some((name.trim_end_matches('.').to_ascii_lowercase(), rtype.to_ascii_uppercase(), name.to_string()))
    }
    let kept: std::collections::HashSet<(String, String)> = patch
        .get("rrsets")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(key).map(|(n, t, _)| (n, t)).collect())
        .unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    current
        .get("rrsets")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .filter_map(key)
        .filter(|(n, t, _)| t != "SOA" && !kept.contains(&(n.clone(), t.clone())))
        .filter(|(n, t, _)| seen.insert((n.clone(), t.clone())))
        .map(|(_, t, name)| serde_json::json!({"name": name, "type": t, "changetype": "DELETE"}))
        .collect()
}

/// Track `zone` in `dns_zones` when no row names it yet. `create_zone` writes
/// rows without a server, so the unique index cannot be relied on: an explicit
/// NOT EXISTS on the domain keeps one row per zone. Returns whether a row was
/// added.
pub async fn track_powerdns_zone(db: &PgPool, user_id: Uuid, zone: &str, server_id: Uuid) -> Result<bool, String> {
    let r = sqlx::query(
        "INSERT INTO dns_zones (user_id, domain, provider, server_id) \
         SELECT $1, $2, 'powerdns', $3 \
          WHERE NOT EXISTS (SELECT 1 FROM dns_zones WHERE lower(domain) = lower($2))",
    )
    .bind(user_id)
    .bind(zone_label(zone))
    .bind(server_id)
    .execute(db)
    .await
    .map_err(|e| format!("could not track zone {}: {e}", zone_label(zone)))?;
    Ok(r.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_part_is_encoded_without_padding_or_ambiguity() {
        assert_eq!(local_b64url("a_b"), "YV9i");
        assert_eq!(local_b64url("a"), "YQ");
        assert!(!local_b64url("contact+news").contains('='));
        assert_ne!(mailbox_family("a.com", "a_b"), mailbox_family("a.com", "a-b"));
        assert_eq!(split_address("a_b@a.com"), Some(("a_b", "a.com")));
        assert_eq!(split_address("nobody"), None);
        assert_eq!(split_address("@a.com"), None);
    }

    fn name(spec: &PruneSpec, stamp: &str, suffix: &str) -> String {
        format!("{}{stamp}{suffix}", spec.name_prefix)
    }

    #[test]
    fn the_four_families_keep_apart() {
        let a = mailbox_prune_spec("a.com", "x");
        let ab = mailbox_prune_spec("ab.com", "x");
        assert!(spec_matches(&a, &name(&a, "20261119-030000", ".tar.gz")));
        assert!(spec_matches(&a, &name(&a, "20261119-030000", ".tar.gz.enc")));
        assert!(!spec_matches(&a, &name(&ab, "20261119-030000", ".tar.gz")), "domain a never takes ab");
        // Local part a vs ab on the same domain.
        let la = mailbox_prune_spec("a.com", "a");
        let lab = mailbox_prune_spec("a.com", "ab");
        assert!(!spec_matches(&la, &name(&lab, "20261119-030000", ".tar.gz")), "local a never takes ab");
        assert!(!spec_matches(&lab, &name(&la, "20261119-030000", ".tar.gz")));
        // Config.
        let cfg = mail_config_prune_spec();
        assert!(spec_matches(&cfg, "mailcfg-20261119-030000.tar.gz.enc"));
        assert!(!spec_matches(&cfg, &name(&a, "20261119-030000", ".tar.gz")));
        // Zones a.com vs ab.com and a.com vs a.com.au.
        let za = dns_zone_prune_spec("a.com.");
        assert_eq!(za.name_prefix, "dns-zone-a.com-");
        assert!(spec_matches(&za, "dns-zone-a.com-20261119-030000.json"));
        assert!(spec_matches(&za, "dns-zone-a.com-20261119-030000.json.enc"));
        assert!(!spec_matches(&za, "dns-zone-ab.com-20261119-030000.json"));
        assert!(!spec_matches(&za, "dns-zone-a.com-au-20261119-030000.json"));
        // Snapshot per backend, and a dump never counted as a snapshot.
        let ss = dns_snapshot_prune_spec("sqlite");
        assert!(spec_matches(&ss, "dns-snapshot-sqlite-20261119-030000.gz.enc"));
        assert!(!spec_matches(&ss, "dns-snapshot-pgsql-20261119-030000.gz.enc"));
        assert!(!spec_matches(&ss, "dns-snapshot-sqlite-20261119-030000.sql.gz.enc"));
        // Never a suffix of another family.
        assert!(!spec_matches(&za, "dns-zone-a.com-20261119-030000.tar.gz"));
    }

    #[test]
    fn bodies_carry_the_contract_and_the_key_only_when_given() {
        let b = mailbox_archive_body("a.com", "a_b", None);
        assert_eq!(b, serde_json::json!({"kind":"mailbox","domain":"a.com","local":"a_b"}));
        let b = mailbox_archive_body("a.com", "a_b", Some("k3y-secret"));
        assert_eq!(b["encryption_key"], "k3y-secret");
        let m = serde_json::json!({"format": MANIFEST_FORMAT});
        assert_eq!(
            mail_config_archive_body(&m, "k"),
            serde_json::json!({"kind":"config","manifest":m,"encryption_key":"k"})
        );
        assert_eq!(
            mailbox_restore_body("a.com", "a_b", "mail-a.com-YV9i-20261119-030000.tar.gz", RestoreMode::Merge, None),
            serde_json::json!({"kind":"mailbox","domain":"a.com","local":"a_b",
                "filename":"mail-a.com-YV9i-20261119-030000.tar.gz","mode":"merge"})
        );
        assert_eq!(
            mail_config_restore_body("mailcfg-x.tar.gz.enc", "k"),
            serde_json::json!({"kind":"config","filename":"mailcfg-x.tar.gz.enc","encryption_key":"k"})
        );
        let c = serde_json::json!({"name":"a.com.","rrsets":[]});
        assert_eq!(
            dns_zone_archive_body("a.com.", &c, None),
            serde_json::json!({"kind":"zone","zone":"a.com.","content":c})
        );
        assert_eq!(dns_snapshot_archive_body("k"), serde_json::json!({"kind":"snapshot","encryption_key":"k"}));
        assert_eq!(
            dns_restore_body("snapshot", "f.gz.enc", Some("k")),
            serde_json::json!({"kind":"snapshot","filename":"f.gz.enc","encryption_key":"k"})
        );
        assert_eq!(dns_restore_body("zone", "f.json", None), serde_json::json!({"kind":"zone","filename":"f.json"}));
        assert_eq!(RestoreMode::parse(None), Some(RestoreMode::Merge));
        assert_eq!(RestoreMode::parse(Some("replace")), Some(RestoreMode::Replace));
        assert_eq!(RestoreMode::parse(Some("wipe")), None);
    }

    #[test]
    fn agent_start_answers_are_told_apart() {
        assert_eq!(
            parse_agent_start(&serde_json::json!({"skipped":"not_installed"})).unwrap(),
            AgentStart::Skipped(NOT_INSTALLED.to_string())
        );
        assert_eq!(
            parse_agent_start(&serde_json::json!({"job_id":"0b9e6c1a-5d2f-4a1e-9f00-123456789abc"})).unwrap(),
            AgentStart::Job("0b9e6c1a-5d2f-4a1e-9f00-123456789abc".to_string())
        );
        assert!(parse_agent_start(&serde_json::json!({"job_id":"../../etc"})).is_err());
        let direct = serde_json::json!({"filename":"x"});
        assert_eq!(parse_agent_start(&direct).unwrap(), AgentStart::Done(direct));
        assert_eq!(parse_job_state(&serde_json::json!({"status":"running","result":null})).unwrap(), JobState::Running);
        assert_eq!(
            parse_job_state(&serde_json::json!({"status":"failed","error":"disk full"})).unwrap(),
            JobState::Failed("disk full".to_string(), None)
        );
        assert_eq!(
            parse_job_state(&serde_json::json!({"status":"failed","error":"disk full","error_code":507})).unwrap(),
            JobState::Failed("disk full".to_string(), Some(507))
        );
        assert!(parse_job_state(&serde_json::json!({})).is_err());
    }

    fn scripted(answers: Vec<Result<serde_json::Value, AgentError>>) -> impl FnMut() -> std::future::Ready<Result<serde_json::Value, AgentError>> {
        let mut it = answers.into_iter();
        move || {
            std::future::ready(
                it.next().unwrap_or_else(|| Ok(serde_json::json!({"status":"running"}))),
            )
        }
    }

    #[tokio::test]
    async fn polling_returns_the_result_once_done() {
        let f = scripted(vec![
            Ok(serde_json::json!({"status":"running"})),
            Err(AgentError::Connection("reset".into())),
            Ok(serde_json::json!({"status":"done","result":{"filename":"f"}})),
        ]);
        let v = poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await.unwrap();
        assert_eq!(v, serde_json::json!({"filename":"f"}));
    }

    #[tokio::test]
    async fn polling_reports_a_failed_job() {
        let f = scripted(vec![Ok(serde_json::json!({"status":"failed","error":"integrity check failed"}))]);
        assert_eq!(
            poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await,
            Err(JobWaitError::Failed("integrity check failed".to_string(), None))
        );
        let f = scripted(vec![Ok(serde_json::json!({"status":"failed","error":"The archive holds another mailbox","error_code":422}))]);
        assert_eq!(
            poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await,
            Err(JobWaitError::Failed("The archive holds another mailbox".to_string(), Some(422)))
        );
        let f = scripted(vec![Ok(serde_json::json!({"status":"failed","error":"boom","error_code":null}))]);
        assert_eq!(
            poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await,
            Err(JobWaitError::Failed("boom".to_string(), None))
        );
    }

    #[test]
    fn a_failed_job_keeps_the_status_class_the_agent_gave_it() {
        for c in [400u16, 404, 409, 422, 507] {
            assert_eq!(job_failure_status(Some(c)), c);
        }
        for c in [None, Some(500), Some(503), Some(401), Some(0)] {
            assert_eq!(job_failure_status(c), 502, "{c:?}");
        }
    }

    #[tokio::test]
    async fn polling_gives_up_when_the_budget_runs_out() {
        let f = scripted(vec![]);
        assert_eq!(
            poll_job(f, Duration::from_millis(30), Duration::from_millis(5)).await,
            Err(JobWaitError::TimedOut)
        );
    }

    #[tokio::test]
    async fn polling_stops_on_a_forgotten_job_and_on_repeated_transport_errors() {
        let f = scripted(vec![Err(AgentError::Status(404, "{}".into()))]);
        assert!(matches!(poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await, Err(JobWaitError::Lost(_))));
        let f = scripted((0..6).map(|_| Err(AgentError::Connection("down".into()))).collect());
        assert!(matches!(poll_job(f, Duration::from_secs(5), Duration::from_millis(1)).await, Err(JobWaitError::Lost(_))));
    }

    #[test]
    fn created_files_must_belong_to_their_family_and_say_their_encryption() {
        let spec = mailbox_prune_spec("a.com", "a_b");
        let ok = serde_json::json!({"filename":"mail-a.com-YV9i-20261119-030000.tar.gz","size_bytes":10,"sha256":"ab","encrypted":false});
        assert_eq!(parse_created(&ok, &spec, false).unwrap().size_bytes, 10);
        let other = serde_json::json!({"filename":"mail-ab.com-YV9i-20261119-030000.tar.gz","encrypted":false});
        assert!(parse_created(&other, &spec, false).is_err());
        let lie = serde_json::json!({"filename":"mail-a.com-YV9i-20261119-030000.tar.gz","encrypted":true});
        assert!(parse_created(&lie, &spec, false).is_err());
        let cfg = mail_config_prune_spec();
        let clear = serde_json::json!({"filename":"mailcfg-20261119-030000.tar.gz","encrypted":false});
        assert!(parse_created(&clear, &cfg, true).is_err(), "config is always encrypted");
        let enc = serde_json::json!({"filename":"mailcfg-20261119-030000.tar.gz.enc","encrypted":true});
        assert!(parse_created(&enc, &cfg, true).is_ok());
        let path = serde_json::json!({"filename":"../mailcfg-20261119-030000.tar.gz.enc","encrypted":true});
        assert!(parse_created(&path, &cfg, true).is_err());
        assert_eq!(parse_snapshot_backend(&serde_json::json!({"backend":"pgsql"})).unwrap(), "pgsql");
        assert!(parse_snapshot_backend(&serde_json::json!({"backend":"mysql"})).is_err());
    }

    fn rows() -> (Vec<DomainRow>, Vec<AccountRow>, Vec<AliasRow>) {
        (
            vec![
                DomainRow {
                    domain: "a.com".into(),
                    dkim_selector: "dockpanel".into(),
                    dkim_public_key: Some("MIIBIjAN".into()),
                    dkim_private_key: Some("-----BEGIN PRIVATE KEY-----\nSECRETPEMBODY\n-----END PRIVATE KEY-----".into()),
                    catch_all: None,
                    enabled: true,
                },
                DomainRow {
                    domain: "b.org".into(),
                    dkim_selector: "s1".into(),
                    dkim_public_key: None,
                    dkim_private_key: Some("bm9uY2VjaXBoZXJ0ZXh0".into()),
                    catch_all: Some("all@b.org".into()),
                    enabled: true,
                },
            ],
            vec![AccountRow {
                email: "a_b@a.com".into(),
                domain: "a.com".into(),
                password_hash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA".into(),
                display_name: Some("A".into()),
                quota_mb: 512,
                enabled: true,
                forward_to: None,
                keep_copy: false,
                autoresponder_enabled: false,
                autoresponder_subject: None,
                autoresponder_body: None,
            }],
            vec![AliasRow { domain: "a.com".into(), source_email: "info@a.com".into(), destination_email: "a_b@a.com".into() }],
        )
    }

    #[test]
    fn the_manifest_never_carries_a_clear_key() {
        let (d, a, al) = rows();
        let secret = "0123456789abcdef0123456789abcdef-jwt";
        let m = build_mail_manifest(Uuid::nil(), &d, &a, &al, secret, chrono::Utc::now()).unwrap();
        let text = m.to_string();
        assert!(!text.contains("BEGIN"), "no PEM in the manifest");
        assert!(!text.contains("SECRETPEMBODY"));
        // The legacy clear key was encrypted, with the column's own scheme.
        let enc = m["domains"][0]["dkim_private_key"]["encrypted"].as_str().unwrap();
        assert_eq!(
            crate::services::secrets_crypto::decrypt_credential(enc, secret).unwrap(),
            "-----BEGIN PRIVATE KEY-----\nSECRETPEMBODY\n-----END PRIVATE KEY-----"
        );
        assert_eq!(m["domains"][0]["dkim_private_key"]["scheme"], DKIM_KEY_SCHEME);
        assert_eq!(m["domains"][0]["dkim_private_key"]["version"], DKIM_KEY_SCHEME_VERSION);
        // An already encrypted key is carried as stored.
        assert_eq!(m["domains"][1]["dkim_private_key"]["encrypted"], "bm9uY2VjaXBoZXJ0ZXh0");
        // Hashes as hashes, and nothing named like a clear password.
        assert_eq!(m["accounts"][0]["password_hash"], a[0].password_hash);
        assert!(m["accounts"][0].get("password").is_none());
        assert_eq!(m["format"], MANIFEST_FORMAT);
        // And it reads back.
        let parsed = parse_mail_manifest(&m).unwrap();
        assert_eq!(parsed.domains.len(), 2);
        assert_eq!(parsed.accounts[0].email, "a_b@a.com");
        assert_eq!(parsed.aliases[0].source_email, "info@a.com");
    }

    #[test]
    fn a_manifest_with_a_clear_key_or_a_foreign_mailbox_is_refused() {
        let (d, a, al) = rows();
        let mut m = build_mail_manifest(Uuid::nil(), &d, &a, &al, "s3cr3t-s3cr3t-s3cr3t-s3cr3t-0000", chrono::Utc::now()).unwrap();
        m["domains"][0]["dkim_private_key"]["encrypted"] = serde_json::json!("-----BEGIN PRIVATE KEY-----");
        assert!(parse_mail_manifest(&m).is_err());
        let mut m2 = build_mail_manifest(Uuid::nil(), &d, &a, &al, "s3cr3t-s3cr3t-s3cr3t-s3cr3t-0000", chrono::Utc::now()).unwrap();
        m2["accounts"][0]["email"] = serde_json::json!("x@elsewhere.net");
        assert!(parse_mail_manifest(&m2).is_err());
        assert!(parse_mail_manifest(&serde_json::json!({"domains": []})).is_err());
    }

    #[test]
    fn zone_restore_bodies_keep_only_what_powerdns_accepts() {
        let export = serde_json::json!({
            "id": "a.com.", "url": "/api/v1/servers/localhost/zones/a.com.", "name": "a.com.",
            "kind": "Native", "serial": 2026111901, "soa_edit_api": "DEFAULT", "dnssec": true,
            "rrsets": [
                {"name":"a.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.a.com. h.a.com. 1 10800 3600 604800 3600","disabled":false}],"comments":[]},
                {"name":"a.com.","type":"MX","ttl":300,"records":[{"content":"10 mail.a.com.","disabled":false}]}
            ]
        });
        let (create, patch, n) = zone_restore_bodies(&export).unwrap();
        assert_eq!(n, 2);
        assert_eq!(create["name"], "a.com.");
        assert!(create.get("id").is_none() && create.get("serial").is_none() && create.get("url").is_none());
        assert_eq!(create["rrsets"][1]["records"][0]["content"], "10 mail.a.com.");
        assert!(create["rrsets"][0].get("comments").is_none());
        assert_eq!(patch["rrsets"][1]["changetype"], "REPLACE");
        assert!(zone_restore_bodies(&serde_json::json!({"name":"../x"})).is_err());
    }

    #[test]
    fn a_readopted_zone_loses_the_rrsets_added_after_its_backup() {
        let backup = serde_json::json!({
            "name": "a.com.",
            "rrsets": [
                {"name":"a.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.a.com. h.a.com. 1 10800 3600 604800 3600"}]},
                {"name":"a.com.","type":"MX","ttl":300,"records":[{"content":"10 mail.a.com."}]},
                {"name":"www.a.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.1"}]}
            ]
        });
        let (_, patch, _) = zone_restore_bodies(&backup).unwrap();
        let current = serde_json::json!({
            "name": "a.com.",
            "rrsets": [
                {"name":"a.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.a.com. h.a.com. 7 10800 3600 604800 3600"}]},
                {"name":"A.com.","type":"MX","ttl":300,"records":[{"content":"20 other.a.com."}]},
                {"name":"www.a.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.9"}]},
                {"name":"www.a.com.","type":"AAAA","ttl":300,"records":[{"content":"2001:db8::1"}]},
                {"name":"new.a.com.","type":"TXT","ttl":300,"records":[{"content":"\"x\""}]},
                {"name":"new.a.com.","type":"TXT","ttl":300,"records":[{"content":"\"y\""}]}
            ]
        });
        let del = zone_rrset_deletions(&patch, &current);
        assert_eq!(del, vec![
            serde_json::json!({"name":"www.a.com.","type":"AAAA","changetype":"DELETE"}),
            serde_json::json!({"name":"new.a.com.","type":"TXT","changetype":"DELETE"}),
        ]);
        // The SOA is never deleted, even when the backup has none.
        let no_soa = serde_json::json!({"rrsets": []});
        let del = zone_rrset_deletions(&no_soa, &current);
        assert!(del.iter().all(|d| d["type"] != "SOA"));
        assert_eq!(del.len(), 4);
        // Nothing to delete when the zone already matches.
        assert!(zone_rrset_deletions(&patch, &backup).is_empty());
    }

    #[test]
    fn a_conflict_is_reported_only_when_another_resource_shares_the_family() {
        assert_eq!(family_conflict_reason("mailcfg", &[]), None);
        let r = family_conflict_reason("mail-a.com-YQ", &["a site"]).unwrap();
        assert!(r.contains("mail-a.com-YQ-") && r.contains("a site"));
    }
}
