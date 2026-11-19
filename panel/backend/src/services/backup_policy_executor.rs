//! GAP 1: Backup Policy Executor - runs every 60s, evaluates cron schedules,
//! executes backup_policies across sites, databases, and volumes.

use chrono::{Datelike, Timelike};
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::{AgentHandle, AgentRegistry};
use crate::services::notifications;

/// Row from the policy query.
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct PolicyRow {
    id: Uuid,
    user_id: Uuid,
    server_id: Option<Uuid>,
    name: String,
    backup_sites: bool,
    backup_databases: bool,
    backup_volumes: bool,
    schedule: String,
    destination_id: Option<Uuid>,
    retention_count: i32,
    encrypt: bool,
    verify_after_backup: bool,
    /// Stop the containers that use an app's data while it is archived.
    stop_apps: bool,
    last_run: Option<chrono::DateTime<chrono::Utc>>,
}

/// v1 backup-encryption passphrase: a literal substring of `JWT_SECRET`.
///
/// ⚠ SECURITY (s434): weak by construction - it hands anyone who learns a
/// backup passphrase 32 bytes of the same secret every session token is
/// HMAC-signed with, coupling "one old backup file leaked" to "every session
/// on this install can be forged." Kept ONLY so `derive_backup_encryption_key_for_version`
/// can still decrypt a backup written before v2 existed. Never call this
/// directly and never use it for a new encrypt - see
/// [`crate::services::secrets_crypto::derive_backup_encryption_key_v2`] for
/// the current derivation and the full account of what was wrong with this one.
fn derive_backup_encryption_key_v1(jwt_secret: &str) -> String {
    format!("backup-enc-{}", &jwt_secret[..32.min(jwt_secret.len())])
}

/// The backup-encryption key version every NEW encrypted backup is written
/// with. Bump this - and add a new `vN` derivation plus a match arm in
/// [`derive_backup_encryption_key_for_version`] - if the derivation ever
/// needs to change again. Never repurpose an existing version number: a
/// `database_backups.encryption_key_version` row is a permanent record of
/// which derivation actually produced that file, and reusing a number would
/// make a past backup silently unrestorable rather than restorable-by-version.
pub const CURRENT_BACKUP_KEY_VERSION: i16 = 2;

/// Derive the symmetric passphrase used to encrypt AND decrypt policy-driven
/// DB backups, for a SPECIFIC recorded version.
///
/// This is the SINGLE SOURCE OF TRUTH for the derivation. The encrypt side
/// (`execute_policy`) and the decrypt side (`routes::backup_orchestrator::restore_db_backup`)
/// previously derived the key from two DIFFERENT, incompatible sources - restore read a
/// `backup_destinations.encryption_key` column that nothing ever writes - so every
/// encrypted DB backup was permanently unrestorable and DR was silently broken in encrypted
/// mode (lesson #70: resolve by the value that actually produced the artifact, not a
/// re-derived phantom). Keyed on the process JWT secret (`config.jwt_secret`, == the
/// `JWT_SECRET` env the executor is handed), so both sides agree byte-for-byte - PROVIDED
/// both sides ask for the same `version`. Restore reads `database_backups.encryption_key_version`
/// (written at encrypt time) rather than assuming [`CURRENT_BACKUP_KEY_VERSION`], so a backup
/// written under an older derivation stays restorable after the derivation changes.
pub fn derive_backup_encryption_key_for_version(version: i16, jwt_secret: &str) -> String {
    match version {
        1 => derive_backup_encryption_key_v1(jwt_secret),
        // Unknown/future version numbers fall through to the current
        // derivation rather than panicking - a corrupt or downgraded-reader
        // scenario then fails LOUDLY (openssl rejects the wrong passphrase)
        // instead of crashing the executor.
        _ => crate::services::secrets_crypto::derive_backup_encryption_key_v2(jwt_secret),
    }
}

/// The passphrase a NEW encrypted backup is written with - always
/// [`CURRENT_BACKUP_KEY_VERSION`]. Restoring an EXISTING backup must call
/// [`derive_backup_encryption_key_for_version`] with that row's own recorded
/// version instead of this function.
pub fn derive_backup_encryption_key(jwt_secret: &str) -> String {
    derive_backup_encryption_key_for_version(CURRENT_BACKUP_KEY_VERSION, jwt_secret)
}

// ── Run history: per-target errors ─────────────────────────────────────────

/// One problem met during a policy run, as stored in `backup_policy_runs.errors`
/// and shown per target in the UI's "Run history".
///
/// `kind` names the leg or the step (`site`, `database`, `volume`, `upload`,
/// `listing`, `owner`, `retention`), `subject` the target it concerns (a domain,
/// a database name, a container), `message` what went wrong. Messages are built
/// from agent and database errors only, never from a request body or the
/// destination payload, and they go through [`clean_message`] before storage.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RunError {
    pub kind: &'static str,
    pub subject: String,
    pub message: String,
}

/// Longest message kept per error. A dump's stderr can be pages long, and the
/// run row is read back in a list.
const MAX_ERROR_MESSAGE_CHARS: usize = 500;

/// Redact the given secrets from `msg` and cap its length.
///
/// The executor holds database passwords and the backup passphrase while it
/// builds these messages. Nothing it formats is supposed to contain them, but an
/// agent error that echoes its input would, so they are scrubbed rather than
/// trusted to be absent.
pub fn clean_message(msg: &str, secrets: &[&str]) -> String {
    let mut out = msg.to_string();
    for s in secrets {
        // A short secret would turn unrelated text into stars and leak its own
        // length; anything under 4 characters is not worth redacting by value.
        if s.len() >= 4 {
            out = out.replace(s, "[redacted]");
        }
    }
    if out.chars().count() > MAX_ERROR_MESSAGE_CHARS {
        out = out.chars().take(MAX_ERROR_MESSAGE_CHARS).collect::<String>() + "...";
    }
    out
}

/// The errors of one run, plus the secrets their messages must never carry.
#[derive(Default)]
struct RunLog {
    errors: Vec<RunError>,
    secrets: Vec<String>,
}

impl RunLog {
    fn push(&mut self, kind: &'static str, subject: impl Into<String>, message: impl AsRef<str>) {
        let secrets: Vec<&str> = self.secrets.iter().map(String::as_str).collect();
        self.errors.push(RunError {
            kind,
            subject: subject.into(),
            message: clean_message(message.as_ref(), &secrets),
        });
    }
}

/// Final status of a run.
///
/// "success" only when nothing at all went wrong: no failed target, no copy left
/// off the destination, and no recorded error. A run that took every backup but
/// could not, say, enforce remote retention or list a server's apps is not a
/// clean success, and showing it green is the silence this history exists to
/// end. "partial" when at least one backup was taken, "failed" otherwise.
pub fn compute_run_status(successes: i32, failures: i32, upload_failures: i32, error_count: usize) -> &'static str {
    if failures == 0 && upload_failures == 0 && error_count == 0 {
        "success"
    } else if successes > 0 {
        "partial"
    } else {
        "failed"
    }
}

/// The policy's `last_error`: the first error of the run, with a count of the
/// others. `None` when the run recorded no error.
pub fn summarize_errors(errors: &[RunError]) -> Option<String> {
    let first = errors.first()?;
    let mut s = format!("{} {}: {}", first.kind, first.subject, first.message);
    if errors.len() > 1 {
        s.push_str(&format!(" (and {} more)", errors.len() - 1));
    }
    Some(s)
}

// ── Remote retention ────────────────────────────────────────────────────────

/// Agent-side budget for a prune: listing then deleting over SFTP is several
/// ssh round trips, more than plain `post`'s 60 seconds allows on a slow link.
pub const PRUNE_TIMEOUT_SECS: u64 = 300;

/// What the agent's `/backups/prune` may delete for one resource: names equal to
/// `name_prefix` + `[A-Za-z0-9._-]*` + one of `suffixes`.
///
/// Uploads land flat in the destination directory under their local file name,
/// so the prefix is the only thing telling one resource's copies from another's.
/// It always ends with the `-` the agent puts between the resource name and the
/// timestamp: site `a` prunes `a-…`, which a backup of site `ab` (`ab-…`) never
/// matches.
#[derive(Debug, Clone, PartialEq)]
pub struct PruneSpec {
    pub name_prefix: String,
    pub suffixes: Vec<String>,
}

/// A site archive is `{domain}-{%Y%m%d-%H%M%S}.tar.gz`
/// (agent `services/backups.rs`). Site archives are never encrypted.
pub fn site_prune_spec(domain: &str) -> PruneSpec {
    PruneSpec {
        name_prefix: format!("{domain}-"),
        suffixes: vec![".tar.gz".to_string()],
    }
}

/// A database dump is `{db_name}-{%Y%m%d-%H%M%S}.sql.gz` for MySQL/MariaDB and
/// PostgreSQL, `.archive.gz` for MongoDB (agent `services/database_backup.rs`),
/// plus `.enc` when the policy encrypts (agent `routes/database_backup.rs`).
/// Both the plain and the encrypted form are listed, so turning Encrypt on or off
/// does not leave the copies taken under the other setting outside retention.
pub fn database_prune_spec(db_name: &str, engine: &str) -> PruneSpec {
    let base = match engine {
        "mongo" | "mongodb" => ".archive.gz",
        _ => ".sql.gz",
    };
    PruneSpec {
        name_prefix: format!("{db_name}-"),
        suffixes: vec![base.to_string(), format!("{base}.enc")],
    }
}

/// Body of `POST /backups/prune`.
///
/// `domain` is the field the agent's prune has always taken. It is the domain
/// for a site and deliberately EMPTY for a database: an agent that predates
/// `name_prefix` would otherwise prune `{domain}-*.tar.gz`, and a database named
/// `wp` would take the archives of a site `wp-shop.com`. With an empty domain
/// such an agent matches nothing, and the missing `deleted` in its answer is
/// recorded as a retention error.
pub fn prune_body(destination: &serde_json::Value, domain: &str, spec: &PruneSpec, retention: i32) -> serde_json::Value {
    serde_json::json!({
        "destination": destination,
        "domain": domain,
        "retention": retention,
        "name_prefix": spec.name_prefix,
        "suffixes": spec.suffixes,
        // Only `<prefix><%Y%m%d-%H%M%S><suffix>` is a candidate: a site
        // `a.com-b.org` or a volume archive `{container}-{volume}-{ts}` never
        // matches the prefix of `a.com`.
        "stamp_only": true,
    })
}

/// Read the agent's prune answer. It must carry an integer `deleted`; anything
/// else (an agent without SFTP or `name_prefix` support answers `pruned` and a
/// `message`) means retention was not enforced and is returned as the error.
pub fn parse_prune_response(resp: &serde_json::Value) -> Result<u64, String> {
    match resp.get("deleted").and_then(|v| v.as_u64()) {
        Some(n) => Ok(n),
        None => {
            let detail = resp
                .get("message")
                .or_else(|| resp.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("the agent's answer has no 'deleted' count");
            Err(format!("remote retention not confirmed by the agent: {detail}"))
        }
    }
}

/// Of `names`, the ones whose files would start with `prefix`.
///
/// Every resource of a family names its files `{name}-{timestamp}{suffix}`, so a
/// name is caught by `prefix` when `{name}-` starts with it. The resource being
/// pruned matches itself; any OTHER match (a second site with the same domain on
/// another server, a site `a.com-b.org` next to `a.com`, a container named like
/// the site) means its copies would be counted and deleted with ours.
pub fn names_sharing_prefix(prefix: &str, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| format!("{n}-").starts_with(prefix))
        .cloned()
        .collect()
}

/// `Some(reason)` when a site's prefix also matches another resource's copies.
///
/// Fleet-wide on purpose: destinations are shared by every policy and schedule,
/// so any site or volume archive on any server can sit next to this one. Volume
/// archives (`{container}-{volume}-{ts}.tar.gz`) share the `.tar.gz` suffix.
pub async fn site_prune_conflict(db: &PgPool, domain: &str) -> Result<Option<String>, String> {
    let spec = site_prune_spec(domain);
    // An app data archive `{owner}-{v|b}-{slug}-{stamp}.tar.gz` whose family
    // `{owner}-{v|b}-{slug}` equals this domain is, to the stamp-only prune, a
    // copy of this site: same prefix, same stamp shape, same suffix. Each server
    // holding such a family counts as one more resource of that name.
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT domain::text FROM sites WHERE left(domain || '-', length($1)) = $1 \
         UNION ALL \
         SELECT DISTINCT ON (server_id) regexp_replace(filename, '-[0-9]{8}-[0-9]{6}\\.tar\\.gz(\\.enc)?$', '') \
           FROM volume_backups \
          WHERE regexp_replace(filename, '-[0-9]{8}-[0-9]{6}\\.tar\\.gz(\\.enc)?$', '') = $2",
    )
    .bind(&spec.name_prefix)
    .bind(domain)
    .fetch_all(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(conflict_reason(domain, &spec, &names))
}

/// `Some(reason)` when another database has the same name (they are unique per
/// owner only): their dumps carry identical names on a shared destination.
/// Database names allow neither `-` nor `.`, so no other name can extend ours.
pub async fn database_prune_conflict(db: &PgPool, db_name: &str, engine: &str) -> Result<Option<String>, String> {
    let spec = database_prune_spec(db_name, engine);
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name::text FROM databases WHERE left(name || '-', length($1)) = $1",
    )
    .bind(&spec.name_prefix)
    .fetch_all(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(conflict_reason(db_name, &spec, &names))
}

/// With `stamp_only`, the agent deletes only `<prefix><stamp><suffix>`, so a
/// longer name sharing the prefix (`a.com-b.org` next to `a.com`) never mixes
/// with ours. What remains is an exact duplicate: the same domain on two
/// servers, or the same database name for two owners, writes identical file
/// names to a shared destination.
fn conflict_reason(own: &str, spec: &PruneSpec, names: &[String]) -> Option<String> {
    let own_count = names.iter().filter(|n| n.as_str() == own).count();
    if own_count <= 1 {
        return None;
    }
    Some(format!(
        "remote retention skipped: the file name prefix '{}' also matches the backups of          another resource also named '{own}', so pruning could delete them",
        spec.name_prefix
    ))
}

// ── App data (Docker volumes and bind mounts) ───────────────────────────────

/// Budget of one app data archive taken by the policy executor: stopping the
/// containers, `du`, tar of the whole volume or directory, encryption, then the
/// restart. An app's data can weigh gigabytes, which plain `post`'s 60 seconds
/// never covered. The executor runs in the background (no HTTP ceiling), so the
/// only cost of headroom is how long a stuck agent holds this policy's run.
pub const APP_DATA_BACKUP_TIMEOUT_SECS: u64 = 1800;

/// Budget of an app data create or restore started from the UI. These routes sit
/// under the server's 300 s `TimeoutLayer` and nginx's `proxy_read_timeout 300s`,
/// so waiting longer would only turn our own timeout into a bodyless 504. Same
/// reasoning as `agent::DB_RESTORE_TIMEOUT_SECS`.
pub const APP_DATA_ROUTE_TIMEOUT_SECS: u64 = 270;

/// What one backup target is: a Docker volume (named or anonymous) or a bind
/// mount under the app data directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    Volume,
    Bind,
}

impl MountKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "volume" => Some(Self::Volume),
            "bind" => Some(Self::Bind),
            _ => None,
        }
    }

    /// The value of `volume_backups.mount_type` and of the agent's `kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Volume => "volume",
            Self::Bind => "bind",
        }
    }

    /// The letter the agent puts in the archive name: `{owner}-{v|b}-{slug}-{ts}`.
    pub fn letter(self) -> &'static str {
        match self {
            Self::Volume => "v",
            Self::Bind => "b",
        }
    }
}

/// One entry of the agent's `GET /backup-targets`.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupTarget {
    pub kind: MountKind,
    /// The Docker volume name (kind volume only).
    pub volume_name: Option<String>,
    /// The bind mount's host directory (kind bind only).
    pub source_path: Option<String>,
    /// Stable owner of the data: template container, compose project, Git app.
    pub owner_name: String,
    /// The agent's slug, used verbatim in the archive name. Never re-derived
    /// here: a slug computed twice in two languages is a prune that misses.
    pub slug: String,
    pub app_type: String,
    pub stack_id: Option<String>,
    /// Ids of the containers that mount the target. Informational only: a
    /// container id changes every time the container is recreated.
    pub container_ids: Vec<String>,
    /// Names of the containers the agent will stop for this target: the ones
    /// it reports running (or does not say). They are recorded as expectedly
    /// stopped for the call, so the auto-healer leaves them alone.
    pub stop_names: Vec<String>,
}

impl BackupTarget {
    /// `<owner>/<slug>`, the subject of this target's run errors.
    pub fn subject(&self) -> String {
        format!("{}/{}", self.owner_name, self.slug)
    }

    /// What `volume_backups.volume_name` holds: the volume's name, or the slug
    /// for a bind mount.
    pub fn row_volume_name(&self) -> &str {
        match self.kind {
            MountKind::Volume => self.volume_name.as_deref().unwrap_or(&self.slug),
            MountKind::Bind => &self.slug,
        }
    }
}

/// The targets of one server, plus the entries that could not be read.
#[derive(Debug, Default, PartialEq)]
pub struct ParsedTargets {
    pub targets: Vec<BackupTarget>,
    /// `(subject, reason)` of each entry this code refuses. Each one is a
    /// counted failure: data the agent says exists and that we do not archive.
    pub invalid: Vec<(String, String)>,
    /// How many mounts the agent left out on purpose (docker.sock, /etc, ...).
    /// Not errors.
    pub excluded: usize,
}

/// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, the agent's own rule for `owner_name`.
/// It becomes a directory name on the agent and a file name prefix at the
/// destination, so it is checked again here.
pub fn is_valid_owner_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Docker's own rule for a volume name: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, at most 255.
pub fn is_valid_volume_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= 255 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A slug is `[A-Za-z0-9_.-]`, never `.` or `..`.
pub fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The directories whose bind mounts are app data. Same three prefixes the
/// agent confines both backup and restore to.
pub const APP_DATA_PREFIXES: [&str; 3] = [
    "/var/lib/dockpanel/apps/",
    "/var/lib/dockpanel/compose/",
    "/var/lib/dockpanel/git-data/",
];

/// A bind source the panel will ask the agent to archive or overwrite: an
/// absolute path strictly under one of [`APP_DATA_PREFIXES`], with no `.` or
/// `..` component and no NUL. The agent canonicalizes and checks again; this
/// is so the panel never even sends anything else.
pub fn is_valid_bind_source(p: &str) -> bool {
    if p.contains('\0') || p.len() > 4096 {
        return false;
    }
    let Some(rest) = APP_DATA_PREFIXES.iter().find_map(|pre| p.strip_prefix(pre)) else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    !rest.is_empty() && rest.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Read the agent's `GET /backup-targets` answer.
///
/// `Err` when it is not the expected shape at all (no `targets` list, which is
/// also what the old `/apps/{id}/volumes` answer `{"volumes": ...}` looks like):
/// the caller records it as a failure to list, never as "no app data". An
/// individual entry that is unusable lands in `invalid`, each one a failure.
pub fn parse_backup_targets(resp: &serde_json::Value) -> Result<ParsedTargets, String> {
    let Some(list) = resp.get("targets").and_then(|v| v.as_array()) else {
        return Err("the agent's answer to GET /backup-targets has no 'targets' list".to_string());
    };
    let mut out = ParsedTargets {
        excluded: resp.get("excluded").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        ..Default::default()
    };
    for (i, t) in list.iter().enumerate() {
        let s = |k: &str| t.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let owner = s("owner_name").unwrap_or_default();
        let slug = s("slug").unwrap_or_default();
        let subject = if owner.is_empty() && slug.is_empty() {
            format!("target #{}", i + 1)
        } else {
            format!("{owner}/{slug}")
        };
        let reject = |out: &mut ParsedTargets, why: &str| out.invalid.push((subject.clone(), why.to_string()));

        let Some(kind) = s("kind").as_deref().and_then(MountKind::parse) else {
            reject(&mut out, "the agent listed a target of an unknown kind");
            continue;
        };
        if !is_valid_owner_name(&owner) {
            reject(&mut out, "the agent listed a target with an invalid owner name");
            continue;
        }
        if !is_valid_slug(&slug) {
            reject(&mut out, "the agent listed a target with an invalid slug");
            continue;
        }
        let volume_name = s("volume_name");
        let source_path = s("source_path");
        match kind {
            MountKind::Volume if !volume_name.as_deref().is_some_and(is_valid_volume_name) => {
                reject(&mut out, "the agent listed a volume without a valid volume name");
                continue;
            }
            MountKind::Bind if !source_path.as_deref().is_some_and(is_valid_bind_source) => {
                reject(&mut out, "the agent listed a bind mount outside the app data directories");
                continue;
            }
            _ => {}
        }
        let container_ids = t
            .get("containers")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let stop_names = t
            .get("containers")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter(|c| c.get("running").and_then(|v| v.as_bool()) != Some(false))
                    .filter_map(|c| c.get("name").and_then(|v| v.as_str()))
                    .map(|n| n.trim_start_matches('/').to_string())
                    .filter(|n| !n.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        out.targets.push(BackupTarget {
            kind,
            volume_name: if kind == MountKind::Volume { volume_name } else { None },
            source_path: if kind == MountKind::Bind { source_path } else { None },
            owner_name: owner,
            slug,
            app_type: s("app_type").unwrap_or_default(),
            stack_id: s("stack_id").filter(|v| !v.is_empty()),
            container_ids,
            stop_names,
        });
    }
    Ok(out)
}

/// Body of `POST /volume-backups/create` for one target.
///
/// `encryption_key` is left out entirely when the archive is not to be
/// encrypted; it is the passphrase, and is never logged.
pub fn app_data_create_body(t: &BackupTarget, stop_containers: bool, encryption_key: Option<&str>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "kind": t.kind.as_str(),
        "volume_name": t.volume_name,
        "source_path": t.source_path,
        "owner_name": t.owner_name,
        "stop_containers": stop_containers,
    });
    if let Some(k) = encryption_key {
        b["encryption_key"] = serde_json::Value::String(k.to_string());
    }
    b
}

/// Body of `POST /volume-backups/{owner}/restore/{filename}` for one row.
/// For a bind mount `volume_name` (which holds the slug in the row) is sent as
/// null: the agent restores the bind from `source_path` only.
pub fn app_data_restore_body(
    kind: MountKind,
    volume_name: &str,
    source_path: Option<&str>,
    encryption_key: Option<&str>,
) -> serde_json::Value {
    let mut b = match kind {
        MountKind::Volume => serde_json::json!({
            "kind": "volume",
            "volume_name": volume_name,
            "source_path": null,
        }),
        MountKind::Bind => serde_json::json!({
            "kind": "bind",
            "volume_name": null,
            "source_path": source_path,
        }),
    };
    if let Some(k) = encryption_key {
        b["encryption_key"] = serde_json::Value::String(k.to_string());
    }
    b
}

/// The passphrase of an existing app data archive: only for an encrypted row,
/// derived with the row's OWN recorded version (see
/// [`derive_backup_encryption_key_for_version`]).
pub fn row_encryption_key(encrypted: bool, key_version: i16, jwt_secret: &str) -> Option<String> {
    encrypted.then(|| derive_backup_encryption_key_for_version(key_version, jwt_secret))
}

/// Budget of `/backups/verify/volume`: an encrypted archive is first checked
/// and decrypted to a temporary file, then listed. Always called detached (the
/// verifier service, or a task spawned by the Verify button).
pub const APP_DATA_VERIFY_TIMEOUT_SECS: u64 = 900;

/// Body of `/backups/verify/volume` and `/backups/drill/volume` for one row:
/// `{container_name, filename}`, plus `encryption_key` (from the row's own key
/// version) when the archive is encrypted.
pub fn volume_check_body(
    container_name: &str,
    filename: &str,
    encrypted: bool,
    key_version: i16,
    jwt_secret: &str,
) -> serde_json::Value {
    let mut b = serde_json::json!({
        "container_name": container_name,
        "filename": filename,
    });
    if let Some(k) = row_encryption_key(encrypted, key_version, jwt_secret) {
        b["encryption_key"] = serde_json::Value::String(k);
    }
    b
}

/// What the agent reports about an archive it just wrote.
#[derive(Debug, Clone, PartialEq)]
pub struct CreatedArchive {
    pub filename: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub encrypted: bool,
}

/// Read the agent's answer to `POST /volume-backups/create`.
///
/// The file name must be a plain name of this target's family
/// (`{owner}-{v|b}-{slug}-...tar.gz[.enc]`): retention, the upload path and
/// restore all derive from it. `encrypted` is the agent's word, checked
/// against the `.enc` suffix, never inferred from what was asked.
pub fn parse_app_data_create_response(resp: &serde_json::Value, t: &BackupTarget) -> Result<CreatedArchive, String> {
    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if filename.is_empty() {
        return Err("the agent's answer named no archive file".to_string());
    }
    if filename.contains('/') || filename.contains("..") || filename.contains('\0') {
        return Err("the agent's answer named an unsafe archive file".to_string());
    }
    let prefix = volume_prune_spec(&t.owner_name, t.kind, &t.slug).name_prefix;
    let enc_suffix = filename.ends_with(".tar.gz.enc");
    if !filename.starts_with(&prefix) || !(enc_suffix || filename.ends_with(".tar.gz")) {
        return Err(format!("the agent's archive name '{filename}' is not of the form {prefix}<timestamp>.tar.gz[.enc]"));
    }
    let encrypted = resp.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
    if encrypted != enc_suffix {
        return Err(format!("the agent's answer says encrypted={encrypted} for '{filename}'"));
    }
    Ok(CreatedArchive {
        filename,
        size_bytes: resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64,
        sha256: resp.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        encrypted,
    })
}

/// `{owner}-{v|b}-{slug}`, the name every archive of one target starts with.
pub fn app_data_family(owner: &str, kind: MountKind, slug: &str) -> String {
    format!("{owner}-{}-{slug}", kind.letter())
}

/// App data archives are `{owner}-{v|b}-{slug}-{%Y%m%d-%H%M%S}.tar.gz`, plus
/// `.enc` when encrypted. Both forms are listed, like database dumps, so turning
/// Encrypt on or off leaves no copy outside retention. With `stamp_only`, owner
/// `a` never takes owner `ab`'s copies, and slug `data` never takes `data-old`'s.
pub fn volume_prune_spec(owner: &str, kind: MountKind, slug: &str) -> PruneSpec {
    PruneSpec {
        name_prefix: format!("{}-", app_data_family(owner, kind, slug)),
        suffixes: vec![".tar.gz".to_string(), ".tar.gz.enc".to_string()],
    }
}

/// `Some(reason)` when another resource writes the same file names as this
/// target to a shared destination: the same family on another server (two
/// servers running a compose project of the same name), or a site whose domain
/// equals the family (`a-v-x.com` archives `a-v-x.com-<stamp>.tar.gz`).
pub fn app_data_conflict_reason(family: &str, sites_with_that_name: i64, other_servers: i64) -> Option<String> {
    if sites_with_that_name == 0 && other_servers == 0 {
        return None;
    }
    let who = match (sites_with_that_name > 0, other_servers > 0) {
        (true, true) => "a site and app data on another server",
        (true, false) => "a site",
        _ => "app data on another server",
    };
    Some(format!(
        "remote retention skipped: the file name prefix '{family}-' is also used by {who}, so pruning could delete their backups"
    ))
}

async fn app_data_prune_conflict(db: &PgPool, server_id: Uuid, family: &str) -> Result<Option<String>, String> {
    let (sites, others): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM sites WHERE domain = $1), \
                (SELECT COUNT(DISTINCT server_id) FROM volume_backups \
                  WHERE server_id IS DISTINCT FROM $2 \
                    AND regexp_replace(filename, '-[0-9]{8}-[0-9]{6}\\.tar\\.gz(\\.enc)?$', '') = $1)",
    )
    .bind(family)
    .bind(server_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("could not check which backups share the name prefix: {e}"))?;
    Ok(app_data_conflict_reason(family, sites, others))
}

// ── Destination ─────────────────────────────────────────────────────────────

/// A policy's off-site destination, resolved once per run.
///
/// # Why this exists
///
/// `destination_id` was selected by the policy query, carried on [`PolicyRow`]
/// under an `#[allow(dead_code)]`, and **never read**. Meanwhile the Backup
/// Orchestrator's policy form offers a Destination dropdown, the schema gives
/// `database_backups` and `volume_backups` a `destination_id` and an `uploaded`
/// column, and the All-Backups table renders a `remote` badge from `uploaded`.
///
/// So every policy-driven backup stayed on the machine it was protecting, the
/// badge could never light for a policy row, and the operator had chosen an
/// off-site destination and been shown no indication it was ignored. A backup
/// that only exists on the disk it is insuring is not a backup.
///
/// The sibling path - `backup_scheduler`, which runs per-site schedules - was
/// described here as having "uploaded correctly all along". That was wrong, and
/// wrong in a way this comment helped preserve: it had the same missing decrypt
/// this path did, so both were posting ciphertext as the credential while Test
/// Connection went on reporting success. Both now go through
/// `agent_destination_payload`. What remains true is the rest - this path shares
/// the scheduler's retry ladder and its refusal to record a backup whose upload
/// failed.
struct ResolvedDestination {
    id: Uuid,
    /// The destination config with `type` folded in, exactly as the agent's
    /// `/backups/upload` handler expects it.
    payload: serde_json::Value,
}

/// `Ok(None)` when the policy has no destination; `Err` when it names one that
/// cannot be used (deleted, or unreadable), which leaves the run's backups on
/// this server and is recorded as an error of the run.
async fn resolve_destination(db: &PgPool, policy: &PolicyRow) -> Result<Option<ResolvedDestination>, String> {
    let Some(id) = policy.destination_id else {
        return Ok(None);
    };

    let row: Result<Option<(String, serde_json::Value)>, _> =
        sqlx::query_as("SELECT dtype, config FROM backup_destinations WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await;

    // Distinguish "deleted" from "we couldn't ask". Both end in local-only
    // backups, but they are different faults and collapsing them would send an
    // operator hunting for a destination that is still perfectly there.
    let (dtype, config) = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::error!(
                "Policy '{}': destination {id} no longer exists - backups will stay on this server",
                policy.name
            );
            return Err(format!("destination {id} no longer exists - backups stay on this server"));
        }
        Err(e) => {
            tracing::error!(
                "Policy '{}': could not read destination {id} ({e}) - backups will stay on this server",
                policy.name
            );
            return Err(format!("could not read destination {id} ({e}) - backups stay on this server"));
        }
    };

    Ok(Some(ResolvedDestination {
        id,
        payload: crate::routes::backup_destinations::agent_destination_payload(&dtype, &config),
    }))
}

/// Push one finished backup file off the box.
///
/// `Ok` only when the bytes actually landed; `Err` carries the last attempt's
/// error. Mirrors `backup_scheduler`'s ladder (5s / 15s / 30s) rather than
/// inventing a second retry policy, so the two paths fail the same way.
///
/// Remote retention for what this uploads is enforced by
/// [`enforce_remote_retention`] for site archives, database dumps and app data
/// archives (volumes and bind mounts).
async fn upload_to_destination(
    agent: &AgentHandle,
    dest: &ResolvedDestination,
    filepath: &str,
    label: &str,
) -> Result<(), String> {
    let body = serde_json::json!({ "filepath": filepath, "destination": dest.payload });

    let delays = [5u64, 15, 30];
    let mut last_err = String::new();

    for (attempt, delay) in delays.iter().enumerate() {
        // See the sibling call in `backup_scheduler`: plain `post` caps the call at
        // 60s while the agent budgets 600s for the same upload, so a slow-but-fine
        // transfer was reported as a failure three times over - and here that also
        // trips `destination_down`, which skips off-siting for every remaining site,
        // database and volume in the run and raises an incident saying the backups
        // "exist only on this server" about backups that had just been uploaded.
        match agent
            .post_long("/backups/upload", Some(body.clone()), 660)
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                if attempt < delays.len() - 1 {
                    tracing::warn!("Upload attempt {} failed for {label}: {last_err} - retrying in {delay}s", attempt + 1);
                    tokio::time::sleep(std::time::Duration::from_secs(*delay)).await;
                }
            }
        }
    }

    tracing::error!("Upload failed for {label} after {} attempts: {last_err}", delays.len());
    Err(format!("upload failed after {} attempts: {last_err}", delays.len()))
}

/// Ask the agent to keep only the `retention` newest copies of one resource at
/// the destination. Returns how many were deleted.
///
/// Refuses to prune when the prefix also matches another resource's copies (see
/// [`site_prune_conflict`]): skipping retention is recoverable, deleting someone
/// else's backups is not.
async fn enforce_remote_retention(
    db: &PgPool,
    agent: &AgentHandle,
    dest: &ResolvedDestination,
    target: RetentionTarget<'_>,
    retention: i32,
) -> Result<u64, String> {
    let (spec, domain_field, conflict) = match target {
        RetentionTarget::Site { domain } => (site_prune_spec(domain), domain, site_prune_conflict(db, domain).await?),
        RetentionTarget::Database { db_name, engine } => (
            database_prune_spec(db_name, engine),
            "",
            database_prune_conflict(db, db_name, engine).await?,
        ),
        // Empty `domain` for the same reason as a database: an agent without
        // `name_prefix` must match nothing rather than `{domain}-*.tar.gz`.
        RetentionTarget::AppData { server_id, owner, kind, slug } => (
            volume_prune_spec(owner, kind, slug),
            "",
            app_data_prune_conflict(db, server_id, &app_data_family(owner, kind, slug)).await?,
        ),
    };
    if let Some(reason) = conflict {
        return Err(reason);
    }
    let body = prune_body(&dest.payload, domain_field, &spec, retention);
    match agent.post_long("/backups/prune", Some(body), PRUNE_TIMEOUT_SECS).await {
        Ok(resp) => parse_prune_response(&resp),
        Err(e) => Err(format!("prune request failed: {e}")),
    }
}

#[derive(Clone, Copy)]
enum RetentionTarget<'a> {
    Site { domain: &'a str },
    Database { db_name: &'a str, engine: &'a str },
    AppData { server_id: Uuid, owner: &'a str, kind: MountKind, slug: &'a str },
}

/// Run the backup policy executor loop - checks every 60 seconds for due policies.
/// Fleet-wide policy query, so it takes the REGISTRY. Each leg resolves its own host:
/// sites and databases per ROW (via `sites.server_id`, which is NOT NULL), volumes per
/// POLICY (their subject list comes from the agent, so there is no row to read).
///
/// Left local, the volume leg was the worst shape in the codebase: it enumerated the
/// PANEL's containers, tarred the PANEL's volumes, stamped each row with the member's
/// `server_id`, and reported success - with no failure path at all. s298's correctly
/// scoped `auto_healer` then refused to prune those rows, because they claimed to
/// belong to another host, so retention was enforced on nothing.
pub async fn run(db: PgPool, agents: AgentRegistry, jwt_secret: String, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Backup policy executor started");

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = tick(&db, &agents, &jwt_secret).await {
                    tracing::error!("Backup policy executor error: {e}");
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Backup policy executor shutting down gracefully");
                break;
            }
        }
    }
}

/// Track last stale-backup check to avoid spamming (once per hour).
static LAST_STALE_CHECK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

async fn tick(db: &PgPool, agents: &AgentRegistry, jwt_secret: &str) -> Result<(), String> {
    let now = chrono::Utc::now();

    // Fetch all enabled policies
    let policies: Vec<PolicyRow> = sqlx::query_as(
        "SELECT id, user_id, server_id, name, backup_sites, backup_databases, backup_volumes, \
         schedule, destination_id, retention_count, encrypt, verify_after_backup, stop_apps, last_run \
         FROM backup_policies WHERE enabled = TRUE"
    )
    .fetch_all(db).await.map_err(|e| e.to_string())?;

    for policy in &policies {
        // Check if cron matches current time
        if !cron_matches_now(&policy.schedule, &now) {
            continue;
        }

        // Prevent double-runs within 90 seconds
        if let Some(last_run) = policy.last_run {
            if (now - last_run).num_seconds() < 90 {
                continue;
            }
        }

        tracing::info!("Executing backup policy '{}' ({})", policy.name, policy.id);
        execute_policy(db, agents, policy, jwt_secret).await;
    }

    // Record backup storage metric for growth tracking. SUM(BIGINT) returns
    // NUMERIC in postgres - cast to bigint so sqlx can decode into i64.
    let total_storage: Option<(i64,)> = sqlx::query_as(
        "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM ( \
            SELECT size_bytes FROM backups UNION ALL \
            SELECT size_bytes FROM database_backups UNION ALL \
            SELECT size_bytes FROM volume_backups \
        ) t"
    ).fetch_one(db).await.ok();
    if let Some((bytes,)) = total_storage {
        let _ = sqlx::query(
            "INSERT INTO system_logs (level, source, message) VALUES ('info', 'backup_storage', $1)"
        ).bind(format!("{}", bytes)).execute(db).await;
    }

    // Proactive backup freshness alerting - once per hour
    let now_ts = now.timestamp();
    let last_check = LAST_STALE_CHECK.load(std::sync::atomic::Ordering::Relaxed);
    if now_ts - last_check >= 3600 {
        LAST_STALE_CHECK.store(now_ts, std::sync::atomic::Ordering::Relaxed);

        let stale: Vec<(String,)> = sqlx::query_as(
            "SELECT s.domain FROM sites s WHERE s.status = 'active' \
             AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id = s.id AND b.created_at > NOW() - INTERVAL '48 hours' \
                             AND (b.destination_id IS NULL OR b.uploaded))"
        ).fetch_all(db).await.unwrap_or_default();

        if !stale.is_empty() {
            let domains: Vec<&str> = stale.iter().map(|s| s.0.as_str()).collect();
            notifications::notify_panel(db, None,
                &format!("{} site(s) have stale backups", stale.len()),
                &format!("These sites have no backup in 48+ hours: {}", domains.join(", ")),
                "warning", "backup", Some("/backup-orchestrator")
            ).await;
            tracing::warn!("Stale backup alert: {} sites without recent backups", stale.len());
        }
    }

    Ok(())
}

/// Open this run's history row. `None` (logged) when it cannot be written: the
/// backups still run, and the policy's own `last_status`/`last_error` still say
/// how they went.
async fn start_run(db: &PgPool, policy: &PolicyRow) -> Option<Uuid> {
    match sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO backup_policy_runs (policy_id, status) VALUES ($1, 'running') RETURNING id"
    )
    .bind(policy.id)
    .fetch_one(db)
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::error!("Policy '{}': could not open a run history row: {e}", policy.name);
            None
        }
    }
}

async fn execute_policy(db: &PgPool, agents: &AgentRegistry, policy: &PolicyRow, jwt_secret: &str) {
    let mut successes = 0;
    let mut failures = 0;
    let mut log = RunLog::default();

    let run_id = start_run(db, policy).await;

    // Resolved once, not per file: a policy backing up forty sites must not run
    // forty identical destination lookups. A destination that is named but
    // unusable leaves every backup of the run local, which the run must say.
    let destination = match resolve_destination(db, policy).await {
        Ok(d) => d,
        Err(e) => {
            log.push("upload", "destination", e);
            None
        }
    };

    // A failed upload counts as a FAILURE (so the policy reports partial/failed
    // and the backup_failure alert fires) but the local file is still recorded.
    // The reasons are the sha256 integrity chain, which a missing row breaks for
    // every backup after it, and retention, which enumerates rows and can never
    // reap a file no row names.
    //
    // `backup_scheduler` used to drop the row entirely and this comment used to
    // name that divergence. It no longer exists: the scheduler records the
    // archive local-only and fails the run afterwards, so both writers now agree
    // that an archive on disk gets a row whatever happened to the upload.
    let mut upload_failures = 0;

    // Circuit breaker. Each upload retries three times with 5s/15s/30s backoff,
    // so a destination that is simply DOWN would cost ~50 seconds PER FILE - a
    // policy covering forty sites would sit in one 60-second tick for half an
    // hour, starving every other policy behind it. The first exhausted retry
    // ladder is enough evidence: stop dialling for the rest of this run and let
    // the next scheduled run try again from scratch.
    let mut destination_down = false;

    // Remote retention trouble reaches system_log once per run, not once per
    // resource; each occurrence is still a run error of its own.
    let mut remote_prune_warned = false;

    // Get encryption key if encrypt is enabled. Use the shared derivation (single source of
    // truth) keyed on the jwt_secret passed into the executor - which equals the
    // state.config.jwt_secret the restore path uses - NOT a separate std::env read that could
    // drift from it. This is what makes an encrypted backup actually restorable.
    let encryption_key: Option<String> = if policy.encrypt {
        Some(derive_backup_encryption_key(jwt_secret))
    } else {
        None
    };
    if let Some(k) = &encryption_key {
        log.secrets.push(k.clone());
    }

    // The key reaches database dumps and app data archives (volumes and bind
    // mounts), and nothing else - the agent has no encryption path for a site
    // archive, so there is nowhere to send it. Say so per run rather than letting
    // the flag imply cover it does not give: a site archive is the whole webroot,
    // and since v2.34.0 it also carries a dump of every database attached to that
    // site, which means an encrypted policy ships an encrypted copy of that data
    // and an unencrypted one to the same destination.
    if policy.encrypt && policy.backup_sites {
        tracing::warn!(
            "Policy '{}': encryption does not cover site archives - this policy's site archives are stored and uploaded unencrypted",
            policy.name
        );
    }

    // Backup sites
    if policy.backup_sites {
        // `server_id` rides along: a site is archived on the host that holds its
        // files. NOT NULL, so there is no ambiguous case to default.
        //
        // A failed query used to read as "this owner has no sites" and the run
        // went green over nothing.
        let sites: Vec<(Uuid, String, Uuid)> = match sqlx::query_as(
            "SELECT id, domain, server_id FROM sites WHERE user_id = $1"
        )
        .bind(policy.user_id)
        .fetch_all(db).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("Policy '{}': could not list sites: {e}", policy.name);
                failures += 1;
                log.push("listing", "sites", format!("could not list sites: {e}"));
                Vec::new()
            }
        };

        for (site_id, domain, site_server_id) in &sites {
            // Resolve THIS site's host. Never fall back to local: archiving a member's
            // site against the panel's own /var/www either fails every night for ever,
            // or - where the same domain legally exists on both hosts - silently tars
            // the wrong machine's files and prunes the member's real off-site copies.
            let agent = match agents.for_server(*site_server_id).await {
                Ok(a) => a,
                Err(e) => {
                    failures += 1;
                    tracing::warn!(
                        "Policy '{}': skipping site {domain} - its server {site_server_id} \
                         is unreachable ({e}). Not archiving it on another host.",
                        policy.name
                    );
                    log.push("site", domain.as_str(), format!("server {site_server_id} is unreachable: {e}"));
                    continue;
                }
            };
            let agent = &agent;
            // WITH the site's databases - a policy-driven backup that omitted
            // them would reintroduce, on the automated path, exactly the gap
            // v2.34.0 closed on the manual one.
            let site_dbs = crate::routes::backups::site_database_specs(db, jwt_secret, *site_id).await;
            let db_expected = site_dbs.expected() as i32;
            // The request carries these databases' passwords; any error the
            // agent echoes back must not carry them into the run history.
            for spec in &site_dbs.specs {
                if let Some(pw) = spec.get("password").and_then(|v| v.as_str()) {
                    log.secrets.push(pw.to_string());
                }
            }
            let agent_body = serde_json::json!({ "databases": site_dbs.specs });

            let mut result = agent.post(&format!("/backups/{domain}/create"), Some(agent_body.clone())).await;
            // Retry once on failure
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                result = agent.post(&format!("/backups/{domain}/create"), Some(agent_body)).await;
            }
            match result {
                Ok(resp) => {
                    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                    // A 200 without a file name names no archive: recording it
                    // would file a row no restore or upload can ever use.
                    if filename.is_empty() {
                        failures += 1;
                        tracing::error!("Policy '{}': site backup for {domain} returned no file name", policy.name);
                        log.push("site", domain.as_str(), "the agent's answer named no archive file");
                        continue;
                    }
                    let size_bytes = resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64;

                    // Same read the database and volume branches below already do
                    // off their own agent responses. This branch had the field in
                    // scope and never looked at it, so a site archived by a policy
                    // carried no integrity hash while its db and volume siblings
                    // in this very function did (#114). Read before the upload, as
                    // they do.
                    let sha256_hash = resp
                        .get("sha256")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let previous_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                        "SELECT sha256_hash FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1"
                    ).bind(site_id).fetch_optional(db).await.unwrap_or(None).flatten();

                    let mut uploaded = false;
                    if let (Some(dest), false) = (&destination, destination_down) {
                        let filepath = format!("/var/backups/dockpanel/{domain}/{filename}");
                        match upload_to_destination(agent, dest, &filepath, &format!("site {domain}")).await {
                            Ok(()) => {
                                uploaded = true;
                                // Enforce remote retention too, or the destination grows
                                // without bound. S3 and SFTP alike, keyed on this site's
                                // exact file name prefix. A failure here is NOT a failed
                                // backup - the archive was taken and shipped - but it is
                                // an error of the run, and it reaches system_log once.
                                if let Err(e) = enforce_remote_retention(
                                    db, agent, dest, RetentionTarget::Site { domain }, policy.retention_count,
                                ).await {
                                    if !remote_prune_warned {
                                        remote_prune_warned = true;
                                        crate::services::system_log::log_event(
                                            db,
                                            "warning",
                                            "backup_policy_executor",
                                            &format!("Policy '{}': remote retention was not enforced", policy.name),
                                            Some(&clean_message(&e, &[])),
                                        ).await;
                                    }
                                    log.push("retention", domain.as_str(), e);
                                }
                            }
                            Err(e) => {
                                upload_failures += 1;
                                destination_down = true;
                                log.push("upload", domain.as_str(), e);
                            }
                        }
                    } else if destination.is_some() {
                        // Breaker already open - count it, don't dial.
                        upload_failures += 1;
                        log.push("upload", domain.as_str(), "not uploaded: the destination failed earlier in this run");
                    }

                    // A backup the panel cannot record is a backup the operator
                    // cannot find or restore: every list and restore path keys off
                    // this row. Discarding the Result reported the run green over
                    // an archive that exists on disk and nowhere in the product.
                    // The realistic trigger is not "the database is down" - it is
                    // deleting a backup destination mid-run, which makes every
                    // remaining insert in that run a foreign-key violation.
                    match sqlx::query(
                        "INSERT INTO backups (site_id, filename, size_bytes, destination_id, uploaded, databases_included, databases_expected, sha256_hash, previous_hash) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
                    )
                    .bind(site_id).bind(filename).bind(size_bytes)
                    .bind(destination.as_ref().map(|d| d.id)).bind(uploaded)
                    .bind(resp.get("databases_included").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0) as i32)
                    .bind(db_expected)
                    .bind(if sha256_hash.is_empty() { None } else { Some(&sha256_hash) })
                    .bind(previous_hash.as_deref())
                    .execute(db).await {
                        Ok(_) => successes += 1,
                        Err(e) => {
                            tracing::error!("Policy '{}': site backup for {domain} was created but could not be recorded: {e}", policy.name);
                            failures += 1;
                            log.push("site", domain.as_str(), format!("archive created but could not be recorded: {e}"));
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Policy '{}': site backup failed for {domain} (after retry): {e}", policy.name);
                    failures += 1;
                    log.push("site", domain.as_str(), format!("backup failed (after retry): {e}"));
                }
            }
        }
    }

    // Backup databases
    if policy.backup_databases {
        // `server_id` comes free from the join this query already makes - the same
        // shape `create_db_backup` uses. Without it the panel `docker exec`s whatever
        // answers to `dockpanel-db-{name}` on ITS OWN host, and that name is unique
        // only per owner, so the dump can be another tenant's database entirely.
        //
        // LEFT JOIN both owner tables + COALESCE, same pattern as databases.rs's
        // list()/get() - a plain `JOIN sites` here silently dropped every
        // stack-owned database (site_id IS NULL for those rows since v2.242.0's
        // standalone-DB-for-stacks ship), so they got zero backup coverage,
        // scheduled or manual, with no error anywhere in the chain.
        let databases: Vec<(Uuid, String, String, String, String, Option<Uuid>, String)> = match sqlx::query_as(
            "SELECT d.id, d.name, d.engine, d.db_user, d.db_password_enc, \
             COALESCE(s.server_id, st.server_id), d.kind \
             FROM databases d \
             LEFT JOIN sites s ON d.site_id = s.id \
             LEFT JOIN docker_stacks st ON d.stack_id = st.id \
             WHERE COALESCE(s.user_id, st.user_id) = $1"
        )
        .bind(policy.user_id)
        .fetch_all(db).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("Policy '{}': could not list databases: {e}", policy.name);
                failures += 1;
                log.push("listing", "databases", format!("could not list databases: {e}"));
                Vec::new()
            }
        };

        for (db_id, db_name, engine, user, password_enc, db_server_id, kind) in &databases {
            let Some(db_server_id) = *db_server_id else {
                failures += 1;
                tracing::warn!(
                    "Policy '{}': skipping database {db_name} - its owner (site or \
                     stack) row has no server_id.",
                    policy.name
                );
                log.push("database", db_name.as_str(), "its owner (site or stack) has no server");
                continue;
            };
            let agent = match agents.for_server(db_server_id).await {
                Ok(a) => a,
                Err(e) => {
                    failures += 1;
                    tracing::warn!(
                        "Policy '{}': skipping database {db_name} - its server \
                         {db_server_id} is unreachable ({e}).",
                        policy.name
                    );
                    log.push("database", db_name.as_str(), format!("server {db_server_id} is unreachable: {e}"));
                    continue;
                }
            };
            let agent = &agent;
            let password = crate::services::secrets_crypto::decrypt_credential_or_legacy(password_enc, jwt_secret);
            log.secrets.push(password.clone());
            let container_name = crate::routes::databases::container_ref(kind, db_name);
            let body = serde_json::json!({
                "container_name": container_name,
                "db_name": db_name,
                "db_type": engine,
                "user": user,
                "password": password,
                "encryption_key": encryption_key,
            });

            let mut result = agent.post("/db-backups/dump", Some(body.clone())).await;
            // Retry once on failure
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                result = agent.post("/db-backups/dump", Some(body)).await;
            }
            match result {
                Ok(resp) => {
                    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if filename.is_empty() {
                        failures += 1;
                        tracing::error!("Policy '{}': DB backup for {db_name} returned no file name", policy.name);
                        log.push("database", db_name.as_str(), "the agent's answer named no dump file");
                        continue;
                    }
                    let size_bytes = resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
                    let encrypted = encryption_key.is_some();

                    let sha256_hash = resp.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let previous_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                        "SELECT sha256_hash FROM database_backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 1"
                    ).bind(db_id).fetch_optional(db).await.unwrap_or(None).flatten();

                    let mut uploaded = false;
                    if let (Some(dest), false) = (&destination, destination_down) {
                        // `database_backup::backup_dir` nests per database:
                        // /var/backups/dockpanel/databases/<db_name>/<filename>.
                        let filepath = format!("/var/backups/dockpanel/databases/{db_name}/{filename}");
                        match upload_to_destination(agent, dest, &filepath, &format!("database {db_name}")).await {
                            Ok(()) => {
                                uploaded = true;
                                // Dumps used to accumulate at the destination for ever:
                                // the agent's prune only knew site archives. Same rule as
                                // the site leg - a retention error, not a failed backup.
                                if let Err(e) = enforce_remote_retention(
                                    db, agent, dest,
                                    RetentionTarget::Database { db_name, engine },
                                    policy.retention_count,
                                ).await {
                                    let e = clean_message(&e, &[password.as_str()]);
                                    if !remote_prune_warned {
                                        remote_prune_warned = true;
                                        crate::services::system_log::log_event(
                                            db,
                                            "warning",
                                            "backup_policy_executor",
                                            &format!("Policy '{}': remote retention was not enforced", policy.name),
                                            Some(&e),
                                        ).await;
                                    }
                                    log.push("retention", db_name.as_str(), e);
                                }
                            }
                            Err(e) => {
                                upload_failures += 1;
                                destination_down = true;
                                log.push("upload", db_name.as_str(), clean_message(&e, &[password.as_str()]));
                            }
                        }
                    } else if destination.is_some() {
                        upload_failures += 1;
                        log.push("upload", db_name.as_str(), "not uploaded: the destination failed earlier in this run");
                    }

                    match sqlx::query(
                        "INSERT INTO database_backups (database_id, server_id, filename, size_bytes, db_type, db_name, encrypted, encryption_key_version, policy_id, destination_id, uploaded, sha256_hash, previous_hash, chain_valid) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, TRUE)"
                    )
                    .bind(db_id).bind(db_server_id).bind(&filename).bind(size_bytes)
                    .bind(engine).bind(db_name).bind(encrypted).bind(CURRENT_BACKUP_KEY_VERSION).bind(policy.id)
                    .bind(destination.as_ref().map(|d| d.id)).bind(uploaded)
                    .bind(if sha256_hash.is_empty() { None } else { Some(&sha256_hash) })
                    .bind(previous_hash.as_deref())
                    .execute(db).await {
                        Ok(_) => successes += 1,
                        Err(e) => {
                            tracing::error!("Policy '{}': DB backup for {db_name} was created but could not be recorded: {e}", policy.name);
                            failures += 1;
                            log.push("database", db_name.as_str(), format!("dump created but could not be recorded: {e}"));
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Policy '{}': DB backup failed for {db_name} (after retry): {e}", policy.name);
                    failures += 1;
                    log.push("database", db_name.as_str(), clean_message(&format!("backup failed (after retry): {e}"), &[password.as_str()]));
                }
            }
        }
    }

    // Backup volumes (Docker app volumes). This is an admin-only capability - the
    // direct create_volume_backup endpoint is AdminUser, and the enumeration below is
    // fleet-wide with NO per-user scoping. Policy CRUD is now admin-gated, but guard
    // the executor too so any legacy non-admin-owned policy cannot drive volume backups.
    //
    // Only asked when the policy wants volumes. A failed lookup is not "not an
    // admin": it is an error of its own, and either way the leg is skipped with a
    // recorded reason instead of a journal-only warning.
    let owner_is_admin: bool = if policy.backup_volumes {
        match sqlx::query_scalar::<_, bool>("SELECT role = 'admin' FROM users WHERE id = $1")
            .bind(policy.user_id)
            .fetch_optional(db)
            .await
        {
            Ok(Some(is_admin)) => is_admin,
            Ok(None) => {
                log.push("owner", "volumes", "the policy's owner no longer exists - volume backup skipped");
                false
            }
            Err(e) => {
                tracing::error!("Policy '{}': could not read the owner's role: {e}", policy.name);
                log.push("owner", "volumes", format!("could not read the owner's role ({e}) - volume backup skipped"));
                false
            }
        }
    } else {
        false
    };
    if policy.backup_volumes && !owner_is_admin && !log.errors.iter().any(|e| e.kind == "owner") {
        tracing::warn!("Policy '{}': skipping volume backup - owner is not an admin", policy.name);
        log.push("owner", "volumes", "the policy's owner is not an admin - volume backup skipped");
    }
    if policy.backup_volumes && owner_is_admin { 'vol: {
        // Volumes have no per-row host to read: the subject list comes from asking an
        // agent for its containers, so the POLICY's server decides which agent. When
        // the policy names none - the only thing the UI can currently produce, since
        // the policy form has no server picker - resolve the local server EXPLICITLY
        // and record that id, rather than writing the policy's NULL through.
        //
        // Recording the server actually reached (not `policy.server_id`) is the whole
        // point: the two used to differ, which is what made `auto_healer` refuse to
        // prune these rows for ever.
        let vol_server_id = match policy.server_id {
            Some(sid) => Some(sid),
            None => agents.local_server_id().await,
        };
        let Some(vol_server_id) = vol_server_id else {
            tracing::warn!(
                "Policy '{}': skipping volume backup - no server on the policy and the \
                 local server id is not yet known (setup incomplete).",
                policy.name
            );
            failures += 1;
            log.push("volume", "volumes", "no server on the policy and the local server is not known yet (setup incomplete)");
            break 'vol;
        };
        let agent = match agents.for_server(vol_server_id).await {
            Ok(a) => a,
            Err(e) => {
                failures += 1;
                tracing::warn!(
                    "Policy '{}': skipping volume backup - server {vol_server_id} is \
                     unreachable ({e}). Not tarring another host's volumes under its name.",
                    policy.name
                );
                log.push("volume", "volumes", format!("server {vol_server_id} is unreachable: {e}"));
                break 'vol;
            }
        };
        let agent = &agent;
        // What to archive comes from the agent's GET /backup-targets: every
        // volume (named or anonymous) and every bind mount under the app data
        // directories, of every managed container (template, compose, Git),
        // deduplicated by the agent. The old walk over `/apps` and
        // `/apps/{id}/volumes` read a field that answer never had and saw no
        // compose or Git app at all, so it archived nothing, in green.
        let parsed = match agent.get("/backup-targets").await {
            Ok(resp) => match parse_backup_targets(&resp) {
                Ok(p) => p,
                Err(e) => {
                    failures += 1;
                    tracing::error!("Policy '{}': the app data targets of server {vol_server_id} could not be read: {e}", policy.name);
                    log.push("listing", "backup-targets", e);
                    break 'vol;
                }
            },
            Err(e) => {
                failures += 1;
                tracing::error!("Policy '{}': could not list the app data of server {vol_server_id}: {e}", policy.name);
                log.push("listing", "backup-targets", format!("could not list the app data to back up: {e}"));
                break 'vol;
            }
        };
        if parsed.excluded > 0 {
            tracing::info!(
                "Policy '{}': {} mount(s) left out by the agent (outside the app data directories)",
                policy.name, parsed.excluded
            );
        }
        for (subject, why) in &parsed.invalid {
            failures += 1;
            tracing::error!("Policy '{}': app data target {subject} skipped: {why}", policy.name);
            log.push("volume", subject.clone(), why);
        }

        for target in &parsed.targets {
            let subject = target.subject();
            let body = app_data_create_body(target, policy.stop_apps, encryption_key.as_deref());

            // One retry, and only when the request never reached the agent. After
            // a timeout or an agent error the first attempt may still be running,
            // with the app stopped, and a refusal (400, 507) would not change.
            //
            // With stop_apps the agent stops the target's running containers for
            // the copy: they are recorded as expectedly stopped around the call,
            // or the auto-healer would restart them in the middle of it.
            let stops: &[String] = if policy.stop_apps { &target.stop_names } else { &[] };
            let ledger = crate::services::expected_stops::DbBackupStops { pool: db, server_id: vol_server_id };
            let result = crate::services::expected_stops::guard_backup_stops(&ledger, stops, async {
                let mut result = agent
                    .post_long("/volume-backups/create", Some(body.clone()), APP_DATA_BACKUP_TIMEOUT_SECS)
                    .await;
                if matches!(result, Err(crate::services::agent::AgentError::Connection(_))) {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    result = agent
                        .post_long("/volume-backups/create", Some(body), APP_DATA_BACKUP_TIMEOUT_SECS)
                        .await;
                }
                result
            }).await;
            let resp = match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Policy '{}': app data backup failed for {subject}: {e}", policy.name);
                    failures += 1;
                    log.push("volume", subject, format!("backup failed: {e}"));
                    continue;
                }
            };
            let archive = match parse_app_data_create_response(&resp, target) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("Policy '{}': app data backup for {subject}: {e}", policy.name);
                    failures += 1;
                    log.push("volume", subject, e);
                    continue;
                }
            };
            // Asked to encrypt and handed back a clear archive: the policy's
            // promise was not kept. The file is recorded (it exists, retention
            // must see it) but not shipped off-site, and the backup counts as
            // failed rather than as a success.
            let encryption_broken = encryption_key.is_some() && !archive.encrypted;
            if encryption_broken {
                tracing::error!("Policy '{}': the agent stored {subject} unencrypted although the policy encrypts", policy.name);
                log.push("volume", subject.clone(), "the archive was stored unencrypted although the policy encrypts - not uploaded");
            }

            let row_volume_name = target.row_volume_name();
            let previous_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                "SELECT sha256_hash FROM volume_backups \
                 WHERE server_id = $1 AND container_name = $2 AND mount_type = $3 AND volume_name = $4 \
                   AND source_path IS NOT DISTINCT FROM $5 \
                 ORDER BY created_at DESC LIMIT 1"
            )
            .bind(vol_server_id).bind(&target.owner_name).bind(target.kind.as_str())
            .bind(row_volume_name).bind(target.source_path.as_deref())
            .fetch_optional(db).await.unwrap_or(None).flatten();

            let mut uploaded = false;
            if encryption_broken {
                // Never upload a clear copy of data the policy says to encrypt.
            } else if let (Some(dest), false) = (&destination, destination_down) {
                // `volume_backup::backup_dir` nests per owner:
                // /var/backups/dockpanel/volumes/<owner>/<filename>.
                let filepath = format!("/var/backups/dockpanel/volumes/{}/{}", target.owner_name, archive.filename);
                match upload_to_destination(agent, dest, &filepath, &format!("app data {subject}")).await {
                    Ok(()) => {
                        uploaded = true;
                        // Same rule as sites and databases: a retention error, not
                        // a failed backup.
                        if let Err(e) = enforce_remote_retention(
                            db, agent, dest,
                            RetentionTarget::AppData {
                                server_id: vol_server_id,
                                owner: &target.owner_name,
                                kind: target.kind,
                                slug: &target.slug,
                            },
                            policy.retention_count,
                        ).await {
                            if !remote_prune_warned {
                                remote_prune_warned = true;
                                crate::services::system_log::log_event(
                                    db,
                                    "warning",
                                    "backup_policy_executor",
                                    &format!("Policy '{}': remote retention was not enforced", policy.name),
                                    Some(&clean_message(&e, &[])),
                                ).await;
                            }
                            log.push("retention", subject.clone(), e);
                        }
                    }
                    Err(e) => {
                        upload_failures += 1;
                        destination_down = true;
                        log.push("upload", subject.clone(), e);
                    }
                }
            } else if destination.is_some() {
                upload_failures += 1;
                log.push("upload", subject.clone(), "not uploaded: the destination failed earlier in this run");
            }

            // `container_id` keeps the first container that mounts the target, as
            // information only: it changes whenever the container is recreated, so
            // nothing (chain, retention, restore) is keyed on it.
            let container_id: String = target.container_ids.first().map(|s| s.chars().take(64).collect()).unwrap_or_default();
            match sqlx::query(
                "INSERT INTO volume_backups (container_id, container_name, server_id, volume_name, filename, size_bytes, policy_id, destination_id, uploaded, sha256_hash, previous_hash, chain_valid, \
                 mount_type, source_path, stack_id, encrypted, encryption_key_version) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, $12, $13, $14, $15, $16)"
            )
            .bind(&container_id).bind(&target.owner_name).bind(vol_server_id)
            .bind(row_volume_name).bind(&archive.filename).bind(archive.size_bytes).bind(policy.id)
            .bind(destination.as_ref().map(|d| d.id)).bind(uploaded)
            .bind(if archive.sha256.is_empty() { None } else { Some(&archive.sha256) })
            .bind(previous_hash.as_deref())
            .bind(target.kind.as_str()).bind(target.source_path.as_deref()).bind(target.stack_id.as_deref())
            .bind(archive.encrypted).bind(CURRENT_BACKUP_KEY_VERSION)
            .execute(db).await {
                Ok(_) if encryption_broken => failures += 1,
                Ok(_) => successes += 1,
                Err(e) => {
                    tracing::error!("Policy '{}': app data backup for {subject} was created but could not be recorded: {e}", policy.name);
                    failures += 1;
                    log.push("volume", subject, format!("archive created but could not be recorded: {e}"));
                }
            }
        }
    }}

    // An upload failure is NOT a backup failure - the file exists locally, and it
    // is counted in `successes` because it was taken. It IS a disaster-recovery
    // failure, though, and reporting the run as a clean success would be exactly
    // the silence this change exists to remove. So it degrades the status and
    // raises the alert, while the counts keep meaning "backups taken". Any other
    // recorded error (retention, listing, owner) degrades it the same way.
    let total_attempted = successes + failures;
    let errors = log.errors;
    let status = compute_run_status(successes, failures, upload_failures, errors.len());
    let last_error = summarize_errors(&errors);
    let errors_json = serde_json::to_value(&errors).unwrap_or_else(|_| serde_json::json!([]));

    if let Some(run_id) = run_id {
        if let Err(e) = sqlx::query(
            "UPDATE backup_policy_runs SET finished_at = NOW(), status = $2, successes = $3, \
             failures = $4, upload_failures = $5, errors = $6 WHERE id = $1"
        )
        .bind(run_id).bind(status).bind(successes).bind(failures).bind(upload_failures)
        .bind(&errors_json)
        .execute(db).await
        {
            tracing::error!("Policy '{}': could not close run history row {run_id}: {e}", policy.name);
        }
    }

    if let Err(e) = sqlx::query(
        "UPDATE backup_policies SET last_run = NOW(), last_status = $2, last_error = $3, updated_at = NOW() WHERE id = $1"
    )
    .bind(policy.id).bind(status).bind(last_error.as_deref())
    .execute(db).await
    {
        tracing::error!("Policy '{}': could not record the run's status: {e}", policy.name);
    }

    tracing::info!(
        "Policy '{}' completed: {successes} successes, {failures} failures, \
         {upload_failures} not uploaded off-site, {} error(s) recorded (status: {status})",
        policy.name,
        errors.len()
    );

    // How to describe a run that took its backups but couldn't get them off the
    // box. Kept in one place so the incident, the alert and the log agree.
    let trouble = |kind: &str| -> String {
        match (failures, upload_failures) {
            (0, 0) => format!(
                "All {successes} {kind} were taken, but the run recorded {} error(s): {}",
                errors.len(),
                last_error.as_deref().unwrap_or("see the policy's run history")
            ),
            (0, u) => format!(
                "{u} of {successes} {kind} could not be uploaded to the configured destination - \
                 they exist only on this server."
            ),
            (f, 0) => format!("{f} {kind} failed out of {total_attempted} total"),
            (f, u) => format!(
                "{f} {kind} failed out of {total_attempted} total, and {u} more could not be \
                 uploaded off-site."
            ),
        }
    };

    // GAP 10: If backup failures, create managed incident
    if failures > 0 || upload_failures > 0 {
        let _ = sqlx::query(
            "INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page, auto_created) \
             VALUES ($1, $2, 'investigating', 'major', $3, FALSE, TRUE)"
        )
        .bind(policy.user_id)
        .bind(if failures > 0 {
            format!("Backup policy '{}' had failures", policy.name)
        } else {
            format!("Backup policy '{}' could not reach its destination", policy.name)
        })
        .bind(trouble("backup(s)"))
        .execute(db).await;
    }

    // Fire alert on failure, and on any recorded error: a run that is not a
    // success must not stay silent.
    if failures > 0 || upload_failures > 0 || !errors.is_empty() {
        notifications::fire_alert(
            db, policy.user_id, policy.server_id, None,
            "backup_failure",
            "",
            // An off-site copy that didn't happen is serious but recoverable on the
            // next run, and the data is still on disk. Don't page at the same
            // urgency as "the backup did not happen at all".
            if failures > 0 { "critical" } else { "warning" },
            &if failures > 0 {
                format!("Backup policy '{}' failed", policy.name)
            } else if upload_failures > 0 {
                format!("Backup policy '{}' kept its backups on this server", policy.name)
            } else {
                format!("Backup policy '{}' completed with errors", policy.name)
            },
            &trouble("backup(s)"),
        ).await;
    }

    // GAP 2: If verify_after_backup, trigger verification for newly created backups
    if policy.verify_after_backup && successes > 0 {
        tracing::info!("Policy '{}': triggering post-backup verification", policy.name);
        // The backup_verifier service will pick these up on its next cycle
        // since they'll be unverified backups created in the last 7 days
    }
}

/// Simple cron matcher (5 fields: minute hour day month weekday).
fn cron_matches_now(schedule: &str, now: &chrono::DateTime<chrono::Utc>) -> bool {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }

    let checks = [
        (fields[0], now.minute() as i32),
        (fields[1], now.hour() as i32),
        (fields[2], now.day() as i32),
        (fields[3], now.month() as i32),
        (fields[4], now.weekday().num_days_from_sunday() as i32),
    ];

    checks.iter().all(|(field, value)| field_matches(field, *value))
}

fn field_matches(field: &&str, value: i32) -> bool {
    let field = *field;
    if field == "*" {
        return true;
    }

    // Step: */N
    if let Some(step) = field.strip_prefix("*/") {
        if let Ok(n) = step.parse::<i32>() {
            return n > 0 && value % n == 0;
        }
    }

    // List: 1,5,10
    for part in field.split(',') {
        // Range: 1-5
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<i32>(), end.parse::<i32>()) {
                if value >= s && value <= e {
                    return true;
                }
            }
        } else if let Ok(v) = part.parse::<i32>() {
            if v == value {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // s248 / lesson #70: encrypt (execute_policy) and decrypt (restore_db_backup) MUST derive
    // the backup key from the same single source of truth. These pin that derivation so the two
    // sides can never drift back into the incompatible-key bug that made encrypted restores 400.
    #[test]
    fn backup_key_derivation_is_stable() {
        let jwt = "abcdefghijklmnopqrstuvwxyz0123456789EXTRA";
        let k = derive_backup_encryption_key(jwt);
        assert_eq!(derive_backup_encryption_key(jwt), k, "same jwt_secret must derive the same key every time");
    }

    #[test]
    fn backup_key_derivation_handles_short_secret() {
        // Must not panic on a secret shorter than 32 bytes - v1's own
        // 32.min(len) guard existed for exactly this; HKDF has no such limit,
        // but the guard against a panic on short input still matters.
        let _ = derive_backup_encryption_key("short");
    }

    #[test]
    fn encrypt_and_restore_derive_identical_key() {
        // The encrypt and decrypt paths both call THIS one function, so identical input →
        // identical output is the guarantee that an encrypted backup is restorable.
        let secret = "the-process-jwt-secret-value-000000000000";
        assert_eq!(
            derive_backup_encryption_key(secret),
            derive_backup_encryption_key(secret),
        );
    }

    // ── s434: versioned derivation, migration safety ───────────────────────

    #[test]
    fn version_1_reproduces_the_exact_legacy_format() {
        // A backup written before s434 has encryption_key_version = 1 (the
        // migration's DEFAULT). Restore must reproduce EXACTLY what v1 wrote,
        // byte for byte, or every pre-existing encrypted backup becomes
        // permanently unrestorable the moment this ships.
        let jwt = "abcdefghijklmnopqrstuvwxyz0123456789EXTRA";
        assert_eq!(
            derive_backup_encryption_key_for_version(1, jwt),
            "backup-enc-abcdefghijklmnopqrstuvwxyz012345",
        );
        // And the short-secret shape v1's own 32.min(len) guard existed for.
        assert_eq!(derive_backup_encryption_key_for_version(1, "short"), "backup-enc-short");
    }

    #[test]
    fn current_version_constant_matches_the_default_derivation() {
        let jwt = "some-jwt-secret";
        assert_eq!(
            derive_backup_encryption_key_for_version(CURRENT_BACKUP_KEY_VERSION, jwt),
            derive_backup_encryption_key(jwt),
            "derive_backup_encryption_key must always mean 'the CURRENT version', \
             or a new encrypt and a version-aware restore of that same backup would disagree",
        );
    }

    #[test]
    fn version_1_and_version_2_derive_different_keys() {
        // THE property this whole migration exists for: the old (leaky) and
        // new (safe) derivations must not collide, or restore could silently
        // decrypt with the wrong-but-matching key.
        let jwt = "same-jwt-secret-both-versions";
        assert_ne!(
            derive_backup_encryption_key_for_version(1, jwt),
            derive_backup_encryption_key_for_version(2, jwt),
        );
    }

    #[test]
    fn unknown_version_falls_through_to_current_not_a_panic() {
        // A row from a future/downgraded reader naming a version this build
        // doesn't recognise must not crash the executor - it should derive
        // SOME key (which will then correctly fail to decrypt, a loud and
        // recoverable failure) rather than panic and take the whole run down.
        let jwt = "some-jwt-secret";
        let result = std::panic::catch_unwind(|| derive_backup_encryption_key_for_version(99, jwt));
        assert!(result.is_ok(), "an unrecognised version must not panic");
    }

    // ── Run history: status, errors, serialization ─────────────────────────

    #[test]
    fn status_is_success_only_without_any_problem() {
        assert_eq!(compute_run_status(3, 0, 0, 0), "success");
        // Nothing to back up and nothing went wrong stays a success.
        assert_eq!(compute_run_status(0, 0, 0, 0), "success");
    }

    #[test]
    fn a_recorded_error_alone_degrades_the_status() {
        // Every backup taken, but e.g. remote retention failed: not green.
        assert_eq!(compute_run_status(3, 0, 0, 1), "partial");
        // Nothing taken and an error recorded (listing failed, owner not admin).
        assert_eq!(compute_run_status(0, 0, 0, 1), "failed");
    }

    #[test]
    fn failures_and_upload_failures_keep_their_meaning() {
        assert_eq!(compute_run_status(2, 1, 0, 1), "partial");
        assert_eq!(compute_run_status(2, 0, 2, 2), "partial");
        assert_eq!(compute_run_status(0, 4, 0, 4), "failed");
    }

    #[test]
    fn run_errors_serialize_as_kind_subject_message() {
        let errors = vec![
            RunError { kind: "listing", subject: "apps".into(), message: "not a list".into() },
            RunError { kind: "retention", subject: "a.com".into(), message: "x".into() },
        ];
        let v = serde_json::to_value(&errors).unwrap();
        assert_eq!(
            v,
            serde_json::json!([
                { "kind": "listing", "subject": "apps", "message": "not a list" },
                { "kind": "retention", "subject": "a.com", "message": "x" },
            ])
        );
        // An empty run serializes to the column's default.
        assert_eq!(serde_json::to_value(Vec::<RunError>::new()).unwrap(), serde_json::json!([]));
    }

    #[test]
    fn last_error_summarizes_the_first_error_and_counts_the_rest() {
        assert_eq!(summarize_errors(&[]), None);
        let one = vec![RunError { kind: "site", subject: "a.com".into(), message: "boom".into() }];
        assert_eq!(summarize_errors(&one).as_deref(), Some("site a.com: boom"));
        let mut three = one.clone();
        three.push(RunError { kind: "upload", subject: "b.com".into(), message: "x".into() });
        three.push(RunError { kind: "upload", subject: "c.com".into(), message: "y".into() });
        assert_eq!(summarize_errors(&three).as_deref(), Some("site a.com: boom (and 2 more)"));
    }

    #[test]
    fn messages_are_redacted_and_capped() {
        let m = clean_message("dump failed: password=hunter2secret rejected", &["hunter2secret"]);
        assert!(!m.contains("hunter2secret"), "{m}");
        assert!(m.contains("[redacted]"));
        let long = "x".repeat(2000);
        let m = clean_message(&long, &[]);
        assert!(m.chars().count() <= MAX_ERROR_MESSAGE_CHARS + 3);
        // A multi-byte message is cut on a char boundary, not mid-codepoint.
        let m = clean_message(&"é".repeat(2000), &[]);
        assert!(m.ends_with("..."));
    }

    #[test]
    fn run_log_scrubs_its_secrets_on_push() {
        let mut log = RunLog::default();
        log.secrets.push("the-backup-passphrase".into());
        log.push("database", "wp", "openssl said: the-backup-passphrase is wrong");
        assert!(!log.errors[0].message.contains("the-backup-passphrase"));
    }

    // ── Remote retention: prefixes and suffixes ────────────────────────────

    #[test]
    fn site_prefix_ends_with_the_separator() {
        let a = site_prune_spec("a");
        let ab = site_prune_spec("ab");
        assert_eq!(a.name_prefix, "a-");
        assert_eq!(a.suffixes, vec![".tar.gz".to_string()]);
        // Site "a" must never catch site "ab"'s archives.
        assert!(!"ab-20261119-020000.tar.gz".starts_with(&a.name_prefix));
        assert!("ab-20261119-020000.tar.gz".starts_with(&ab.name_prefix));
        assert!("a-20261119-020000.tar.gz".starts_with(&a.name_prefix));
    }

    #[test]
    fn database_suffixes_follow_the_engine_and_cover_encryption() {
        let pg = database_prune_spec("wp", "postgres");
        assert_eq!(pg.name_prefix, "wp-");
        assert_eq!(pg.suffixes, vec![".sql.gz".to_string(), ".sql.gz.enc".to_string()]);
        let my = database_prune_spec("wp", "mariadb");
        assert_eq!(my.suffixes, vec![".sql.gz".to_string(), ".sql.gz.enc".to_string()]);
        let mongo = database_prune_spec("app", "mongodb");
        assert_eq!(mongo.suffixes, vec![".archive.gz".to_string(), ".archive.gz.enc".to_string()]);
        // "wp" does not catch "wpx".
        assert!(!"wpx-20261119-020000.sql.gz".starts_with(&pg.name_prefix));
    }

    #[test]
    fn prune_body_carries_the_new_contract_and_an_empty_domain_for_databases() {
        let dest = serde_json::json!({ "type": "sftp", "host": "h" });
        let b = prune_body(&dest, "", &database_prune_spec("wp", "postgres"), 7);
        assert_eq!(b["domain"], "");
        assert_eq!(b["retention"], 7);
        assert_eq!(b["name_prefix"], "wp-");
        assert_eq!(b["stamp_only"], true);
        assert_eq!(b["suffixes"], serde_json::json!([".sql.gz", ".sql.gz.enc"]));
        assert_eq!(b["destination"], dest);
        let s = prune_body(&dest, "a.com", &site_prune_spec("a.com"), 3);
        assert_eq!(s["domain"], "a.com");
        assert_eq!(s["name_prefix"], "a.com-");
    }

    #[test]
    fn prune_response_must_confirm_a_deleted_count() {
        assert_eq!(parse_prune_response(&serde_json::json!({ "deleted": 2 })), Ok(2));
        assert_eq!(parse_prune_response(&serde_json::json!({ "deleted": 0 })), Ok(0));
        // What an agent without the new contract answers for SFTP.
        let old = serde_json::json!({ "pruned": 0, "message": "Automatic pruning is not supported" });
        let e = parse_prune_response(&old).unwrap_err();
        assert!(e.contains("not supported"), "{e}");
        // The old S3 answer has no `deleted` either.
        assert!(parse_prune_response(&serde_json::json!({ "pruned": 1, "total": 3 })).is_err());
    }

    #[test]
    fn prefix_sharing_detects_other_resources_only() {
        let names = vec!["a".to_string(), "ab".to_string(), "a-b.com".to_string()];
        // "a-" is a prefix of "a-" (itself) and "a-b.com-": two resources.
        assert_eq!(names_sharing_prefix("a-", &names), vec!["a".to_string(), "a-b.com".to_string()]);
        assert_eq!(names_sharing_prefix("ab-", &names), vec!["ab".to_string()]);

        let spec = site_prune_spec("ab");
        assert_eq!(conflict_reason("ab", &spec, &names), None);
        let spec = site_prune_spec("a");
        // stamp_only: a-b.com's archives never match a's prefix, so no conflict.
        assert_eq!(conflict_reason("a", &spec, &names), None);
        let twice = vec!["a".to_string(), "a".to_string()];
        let r = conflict_reason("a", &spec, &twice).expect("the same domain twice conflicts");
        assert!(r.contains("named 'a'"), "{r}");
        // Same name twice (same domain on two servers, same db name for two owners).
        let dup = vec!["wp".to_string(), "wp".to_string()];
        assert!(conflict_reason("wp", &database_prune_spec("wp", "postgres"), &dup).is_some());
        assert_eq!(conflict_reason("wp", &database_prune_spec("wp", "postgres"), &["wp".to_string()]), None);
    }

    // ── App data: GET /backup-targets, bodies, retention, key version ──────

    /// The bind mount directory of the fixture below.
    const DEMO_BIND_DIR: &str = "/var/lib/dockpanel/compose/demo/uploads";

    fn targets_fixture() -> serde_json::Value {
        serde_json::json!({
            "targets": [
                {"kind":"volume","volume_name":"demo_pgdata","source_path":null,
                 "source":"/var/lib/docker/volumes/demo_pgdata/_data","owner_name":"demo",
                 "slug":"demo_pgdata","app_type":"compose","stack_id":"st-1",
                 "containers":[{"id":"abc","name":"demo-db-1","running":true}]},
                {"kind":"bind","volume_name":null,
                 "source_path":"/var/lib/dockpanel/compose/demo/uploads",
                 "source":"/var/lib/dockpanel/compose/demo/uploads","owner_name":"demo",
                 "slug":"uploads-1a2b3c4d","app_type":"compose","stack_id":null,
                 "containers":[{"id":"def","name":"demo-app-1","running":true},
                               {"id":"ghi","name":"demo-worker-1","running":false}]}
            ],
            "excluded": [{"container":"demo-app-1","source":"/etc/localtime","reason":"bind outside the app data directories"}]
        })
    }

    #[test]
    fn backup_targets_are_parsed_with_their_kind_owner_and_slug() {
        let p = parse_backup_targets(&targets_fixture()).unwrap();
        assert!(p.invalid.is_empty(), "{:?}", p.invalid);
        assert_eq!(p.excluded, 1, "an excluded mount is counted, not an error");
        assert_eq!(p.targets.len(), 2);
        let v = &p.targets[0];
        assert_eq!(v.kind, MountKind::Volume);
        assert_eq!(v.volume_name.as_deref(), Some("demo_pgdata"));
        assert_eq!(v.source_path, None);
        assert_eq!(v.subject(), "demo/demo_pgdata");
        assert_eq!(v.row_volume_name(), "demo_pgdata");
        assert_eq!(v.stack_id.as_deref(), Some("st-1"));
        assert_eq!(v.container_ids, vec!["abc".to_string()]);
        assert_eq!(v.stop_names, vec!["demo-db-1".to_string()]);
        let b = &p.targets[1];
        assert_eq!(b.kind, MountKind::Bind);
        assert_eq!(b.volume_name, None);
        assert_eq!(b.source_path.as_deref(), Some(DEMO_BIND_DIR));
        assert_eq!(b.row_volume_name(), "uploads-1a2b3c4d", "a bind row stores its slug as volume_name");
        assert_eq!(b.stack_id, None);
        assert_eq!(b.container_ids.len(), 2);
        // Only the running container is stopped by the agent, so only it is protected.
        assert_eq!(b.stop_names, vec!["demo-app-1".to_string()]);
    }

    #[test]
    fn an_unreadable_targets_answer_is_an_error_not_an_empty_list() {
        // The old /apps/{id}/volumes shape (regression C1): no `targets` list.
        let old = serde_json::json!({"volumes":[{"source":"/var/lib/docker/volumes/x/_data","type":"volume"}]});
        assert!(parse_backup_targets(&old).is_err());
        assert!(parse_backup_targets(&serde_json::json!([])).is_err());
        assert!(parse_backup_targets(&serde_json::json!({"targets": "nope"})).is_err());
        assert!(parse_backup_targets(&serde_json::Value::Null).is_err());
    }

    #[test]
    fn no_target_at_all_is_a_clean_success() {
        let p = parse_backup_targets(&serde_json::json!({"targets": [], "excluded": []})).unwrap();
        assert!(p.targets.is_empty() && p.invalid.is_empty());
        // Nothing to back up, nothing went wrong: the run's counters stay 0/0.
        assert_eq!(compute_run_status(0, 0, 0, 0), "success");
    }

    #[test]
    fn a_failed_target_degrades_the_run() {
        // One target archived, one failed: partial. The only target failed: failed.
        assert_eq!(compute_run_status(1, 1, 0, 1), "partial");
        assert_eq!(compute_run_status(0, 1, 0, 1), "failed");
        // Listing failed (GET /backup-targets): one failure, one error.
        assert_eq!(compute_run_status(0, 1, 0, 1), "failed");
    }

    #[test]
    fn unusable_entries_are_counted_never_skipped() {
        let resp = serde_json::json!({"targets": [
            {"kind":"tmpfs","owner_name":"a","slug":"x"},
            {"kind":"volume","volume_name":"ok","owner_name":"../etc","slug":"x"},
            {"kind":"volume","volume_name":"ok","owner_name":"a","slug":"x/y"},
            {"kind":"volume","volume_name":null,"owner_name":"a","slug":"v"},
            {"kind":"bind","source_path":"/etc","owner_name":"a","slug":"etc-12345678"},
            {"kind":"bind","source_path":"/var/lib/dockpanel/apps/a/../../../etc","owner_name":"a","slug":"etc-12345678"},
            {},
            {"kind":"volume","volume_name":"good","owner_name":"a","slug":"good"}
        ]});
        let p = parse_backup_targets(&resp).unwrap();
        assert_eq!(p.targets.len(), 1);
        assert_eq!(p.invalid.len(), 7, "{:?}", p.invalid);
        assert_eq!(p.invalid[6].0, "target #7", "an entry with no name still has a subject");
        assert_eq!(p.invalid[0].0, "a/x");
    }

    #[test]
    fn name_validators_follow_the_contract() {
        assert!(is_valid_owner_name("demo"));
        assert!(is_valid_owner_name("my.app_1-x"));
        assert!(!is_valid_owner_name(""));
        assert!(!is_valid_owner_name("-x"));
        assert!(!is_valid_owner_name(".x"));
        assert!(!is_valid_owner_name("a/b"));
        assert!(!is_valid_owner_name(&"a".repeat(129)));
        assert!(is_valid_owner_name(&"a".repeat(128)));
        assert!(is_valid_volume_name(&"v".repeat(255)));
        assert!(!is_valid_volume_name(&"v".repeat(256)));
        assert!(!is_valid_volume_name("_v"));
        assert!(!is_valid_slug(".."));
        assert!(!is_valid_slug(""));
        assert!(is_valid_slug("uploads-1a2b3c4d"));
        assert!(is_valid_bind_source("/var/lib/dockpanel/compose/demo/uploads"));
        assert!(is_valid_bind_source("/var/lib/dockpanel/git-data/app/data/"));
        assert!(is_valid_bind_source("/var/lib/dockpanel/apps/wp"));
        assert!(!is_valid_bind_source("/var/lib/dockpanel/apps/"));
        assert!(!is_valid_bind_source("/var/lib/dockpanel/apps"));
        assert!(!is_valid_bind_source("/var/lib/dockpanel/appsx/y"));
        assert!(!is_valid_bind_source("/var/lib/dockpanel/apps/a/../b"));
        assert!(!is_valid_bind_source("/var/lib/dockpanel/apps/a//b"));
        assert!(!is_valid_bind_source("/etc"));
        assert!(!is_valid_bind_source("var/lib/dockpanel/apps/a"));
    }

    fn sample_target(kind: MountKind) -> BackupTarget {
        let p = parse_backup_targets(&targets_fixture()).unwrap();
        p.targets.into_iter().find(|t| t.kind == kind).unwrap()
    }

    #[test]
    fn create_body_carries_the_contract_with_and_without_encryption() {
        let v = sample_target(MountKind::Volume);
        assert_eq!(
            app_data_create_body(&v, true, None),
            serde_json::json!({"kind":"volume","volume_name":"demo_pgdata","source_path":null,
                               "owner_name":"demo","stop_containers":true})
        );
        let b = sample_target(MountKind::Bind);
        assert_eq!(
            app_data_create_body(&b, false, Some("k3y-passphrase")),
            serde_json::json!({"kind":"bind","volume_name":null,
                               "source_path":"/var/lib/dockpanel/compose/demo/uploads",
                               "owner_name":"demo","stop_containers":false,
                               "encryption_key":"k3y-passphrase"})
        );
    }

    #[test]
    fn restore_body_carries_the_contract_with_and_without_encryption() {
        assert_eq!(
            app_data_restore_body(MountKind::Volume, "demo_pgdata", None, None),
            serde_json::json!({"kind":"volume","volume_name":"demo_pgdata","source_path":null})
        );
        assert_eq!(
            app_data_restore_body(MountKind::Bind, "uploads-1a2b3c4d", Some(DEMO_BIND_DIR), Some("pw")),
            serde_json::json!({"kind":"bind","volume_name":null,
                               "source_path":"/var/lib/dockpanel/compose/demo/uploads",
                               "encryption_key":"pw"})
        );
    }

    #[test]
    fn a_row_is_decrypted_with_its_own_key_version() {
        let jwt = "abcdefghijklmnopqrstuvwxyz0123456789EXTRA";
        assert_eq!(row_encryption_key(false, 2, jwt), None, "a clear archive gets no key");
        assert_eq!(row_encryption_key(true, 2, jwt), Some(derive_backup_encryption_key(jwt)));
        assert_eq!(
            row_encryption_key(true, 1, jwt).as_deref(),
            Some("backup-enc-abcdefghijklmnopqrstuvwxyz012345"),
            "a v1 row must get the v1 key, not the current one"
        );
        assert_eq!(CURRENT_BACKUP_KEY_VERSION, 2, "new app data archives are written with v2");
    }

    #[test]
    fn verify_and_drill_bodies_carry_the_key_only_for_an_encrypted_row() {
        let jwt = "abcdefghijklmnopqrstuvwxyz0123456789EXTRA";
        assert_eq!(
            volume_check_body("demo", "demo-v-db-20261119-020000.tar.gz", false, 2, jwt),
            serde_json::json!({"container_name":"demo","filename":"demo-v-db-20261119-020000.tar.gz"})
        );
        let b = volume_check_body("demo", "demo-v-db-20261119-020000.tar.gz.enc", true, 1, jwt);
        assert_eq!(b["encryption_key"], "backup-enc-abcdefghijklmnopqrstuvwxyz012345");
        let b = volume_check_body("demo", "demo-v-db-20261119-020000.tar.gz.enc", true, 2, jwt);
        assert_eq!(b["encryption_key"].as_str(), Some(derive_backup_encryption_key(jwt).as_str()));
    }

    /// What the agent's `stamp_only` prune accepts: exactly
    /// `<prefix><%Y%m%d-%H%M%S><suffix>`.
    fn stamp_only_matches(spec: &PruneSpec, name: &str) -> bool {
        let Some(rest) = name.strip_prefix(&spec.name_prefix) else { return false };
        spec.suffixes.iter().any(|suf| {
            rest.strip_suffix(suf.as_str()).is_some_and(|stamp| {
                let b = stamp.as_bytes();
                b.len() == 15
                    && b[8] == b'-'
                    && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
            })
        })
    }

    #[test]
    fn app_data_prune_spec_keeps_owners_and_slugs_apart() {
        let a = volume_prune_spec("a", MountKind::Volume, "data");
        assert_eq!(a.name_prefix, "a-v-data-");
        assert_eq!(a.suffixes, vec![".tar.gz".to_string(), ".tar.gz.enc".to_string()]);
        assert!(stamp_only_matches(&a, "a-v-data-20261119-020000.tar.gz"));
        assert!(stamp_only_matches(&a, "a-v-data-20261119-020000.tar.gz.enc"));
        // Owner "ab" is never caught by owner "a": the prefix differs.
        let ab = volume_prune_spec("ab", MountKind::Volume, "data");
        assert_eq!(ab.name_prefix, "ab-v-data-");
        assert!(!stamp_only_matches(&a, "ab-v-data-20261119-020000.tar.gz"));
        // Slug "data-old" STARTS with a's prefix; only stamp_only keeps it out.
        assert!("a-v-data-old-20261119-020000.tar.gz".starts_with(&a.name_prefix));
        assert!(!stamp_only_matches(&a, "a-v-data-old-20261119-020000.tar.gz"));
        let old = volume_prune_spec("a", MountKind::Volume, "data-old");
        assert!(stamp_only_matches(&old, "a-v-data-old-20261119-020000.tar.gz"));
        // A volume and a bind with the same slug are distinct families.
        let b = volume_prune_spec("a", MountKind::Bind, "data");
        assert_eq!(b.name_prefix, "a-b-data-");
        assert!(!stamp_only_matches(&b, "a-v-data-20261119-020000.tar.gz"));
        // The body sent to the agent: empty domain, stamp_only, both suffixes.
        let body = prune_body(&serde_json::json!({"type":"sftp"}), "", &a, 5);
        assert_eq!(body["domain"], "");
        assert_eq!(body["name_prefix"], "a-v-data-");
        assert_eq!(body["suffixes"], serde_json::json!([".tar.gz", ".tar.gz.enc"]));
        assert_eq!(body["stamp_only"], true);
        assert_eq!(body["retention"], 5);
    }

    #[test]
    fn app_data_retention_conflicts_with_a_site_or_another_server_only() {
        assert_eq!(app_data_conflict_reason("a-v-data", 0, 0), None);
        let r = app_data_conflict_reason("a-v-x.com", 1, 0).unwrap();
        assert!(r.contains("'a-v-x.com-'") && r.contains("a site"), "{r}");
        let r = app_data_conflict_reason("demo-v-db", 0, 1).unwrap();
        assert!(r.contains("another server"), "{r}");
        assert!(app_data_conflict_reason("f", 2, 3).is_some());
    }

    #[test]
    fn create_response_must_name_an_archive_of_this_target() {
        let v = sample_target(MountKind::Volume);
        let ok = serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.tar.gz.enc",
            "size_bytes": 42, "sha256":"ab12", "encrypted": true, "kind":"volume",
            "volume_name":"demo_pgdata","source_path":null,"owner_name":"demo","stopped":["demo-db-1"]});
        let a = parse_app_data_create_response(&ok, &v).unwrap();
        assert_eq!(a.filename, "demo-v-demo_pgdata-20261119-020000.tar.gz.enc");
        assert_eq!((a.size_bytes, a.sha256.as_str(), a.encrypted), (42, "ab12", true));

        let clear = serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.tar.gz","encrypted":false});
        assert!(!parse_app_data_create_response(&clear, &v).unwrap().encrypted);
        // `encrypted` missing on a clear archive reads as false.
        let clear = serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.tar.gz"});
        assert!(!parse_app_data_create_response(&clear, &v).unwrap().encrypted);

        for bad in [
            serde_json::json!({}),
            serde_json::json!({"filename":""}),
            serde_json::json!({"filename":"../demo-v-demo_pgdata-20261119-020000.tar.gz"}),
            serde_json::json!({"filename":"other-v-demo_pgdata-20261119-020000.tar.gz"}),
            serde_json::json!({"filename":"demo-b-demo_pgdata-20261119-020000.tar.gz"}),
            serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.zip"}),
            // The flag and the suffix disagree.
            serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.tar.gz","encrypted":true}),
            serde_json::json!({"filename":"demo-v-demo_pgdata-20261119-020000.tar.gz.enc","encrypted":false}),
        ] {
            assert!(parse_app_data_create_response(&bad, &v).is_err(), "{bad}");
        }
    }
}
