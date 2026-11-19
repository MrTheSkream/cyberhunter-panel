//! "Restore sites and databases from remote backups" (lot 2, step 2.6).
//!
//! After the panel itself is back on a new machine (step 2.5), its database
//! lists every site and database backup with the destination it was sent to,
//! but the files are on the old machine's disk. For each LOCAL site and
//! database whose latest backup is on a remote destination, this pass:
//!
//! 1. recreates the database containers that do not exist on this machine
//!    (same name, engine, port and password as the row), so the dumps have
//!    somewhere to go;
//! 2. downloads the archive through the agent (`/backups/list` on the file
//!    name, `/backups/download` into the restore inbox), checks it against the
//!    row's sha256 (an encrypted dump whose recorded hash is the plaintext's,
//!    as older agents wrote it, is a warning: the HMAC of its decryption
//!    checks it at the restore), and moves it where the existing restore expects it
//!    (`/var/backups/dockpanel/<domain>/` or `.../databases/<db>/`);
//! 3. restores it with the same agent calls as the existing restore routes;
//! 4. reports per item (`restored`, `failed`, `skipped`).
//!
//! Sites first (their archives carry their databases), then the database
//! dumps, except one older than a site archive restored in this pass that
//! carried it. App data volumes (lot 1), mail and DNS (lot 3) have their own
//! restores: docs/guides/disaster-recovery.md gives the order.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::AgentHandle;
use crate::services::dr_restore::{self, agent_message};

pub const REPORT_PATH: &str = "/var/lib/dockpanel/dr-rehydrate.json";
const BACKUP_ROOT: &str = "/var/backups/dockpanel";
const RESTORE_TIMEOUT_SECS: u64 = 1800;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Item {
    /// site, database
    pub kind: &'static str,
    pub name: String,
    pub filename: Option<String>,
    pub destination: Option<String>,
    /// restored, failed, skipped
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Report {
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub items: Vec<Item>,
    pub restored: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl Report {
    fn count(&mut self) {
        self.restored = self.items.iter().filter(|i| i.status == "restored").count();
        self.failed = self.items.iter().filter(|i| i.status == "failed").count();
        self.skipped = self.items.iter().filter(|i| i.status == "skipped").count();
    }
}

static REPORT: Mutex<Option<Report>> = Mutex::new(None);
static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_running() -> bool {
    RUNNING.load(std::sync::atomic::Ordering::SeqCst)
}

/// The report in memory, else the last one written to disk.
pub fn report() -> Option<serde_json::Value> {
    if let Some(r) = REPORT.lock().ok().and_then(|g| g.clone()) {
        return serde_json::to_value(r).ok();
    }
    serde_json::from_str(&std::fs::read_to_string(REPORT_PATH).ok()?).ok()
}

pub struct RunGuard(());

impl RunGuard {
    pub fn acquire() -> Option<RunGuard> {
        use std::sync::atomic::Ordering;
        RUNNING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| RunGuard(()))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn publish(r: &Report) {
    if let Ok(mut g) = REPORT.lock() {
        *g = Some(r.clone());
    }
}

// ── Pure decisions ──────────────────────────────────────────────────────────

/// A latest backup, as the decision needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Latest {
    pub filename: String,
    pub uploaded: bool,
    pub destination_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Why a latest backup is not fetched from a destination, or `None` when it is.
pub fn remote_skip_reason(l: &Latest) -> Option<&'static str> {
    if !l.uploaded {
        return Some("its latest backup was never sent to a remote destination");
    }
    if l.destination_id.is_none() {
        return Some("the destination of its latest backup no longer exists");
    }
    None
}

/// A file name the agent wrote and may take back: no path, no traversal.
pub fn plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..")
}

/// What a downloaded file's sha256 says against the one its backup row
/// recorded: `Ok(None)` when they agree (or nothing was recorded), an error
/// when a plaintext file differs, and `Ok(Some(warning))` when an ENCRYPTED
/// dump (`.enc`) differs. Agents before the fix recorded the sha256 of the
/// plaintext dump for an encrypted one, so on those rows a mismatch says
/// nothing about the file. Its integrity is then checked by the agent at the
/// restore itself: `/db-backups/.../restore` checks the HMAC tag of the whole
/// `.enc` before decrypting, and refuses a corrupted or tampered file (422).
/// A legacy `.enc` (encrypted before the tag existed) has no tag: the agent
/// decrypts it unverified and logs a warning, which the item's warning says.
pub fn checksum_verdict(filename: &str, recorded: Option<&str>, got: &str) -> Result<Option<String>, String> {
    let Some(want) = recorded.filter(|s| !s.is_empty()) else { return Ok(None) };
    if got.eq_ignore_ascii_case(want) {
        return Ok(None);
    }
    if filename.ends_with(".enc") {
        return Ok(Some(format!(
            "the downloaded sha256 {got} differs from the one recorded ({want}); older agents recorded the hash of the              unencrypted dump for an encrypted one, so the file is checked instead by the integrity tag (HMAC) of its              decryption at the restore (a dump encrypted before that tag existed has none: the agent then decrypts it              unverified and logs it)"
        )));
    }
    Err(format!("checksum mismatch: downloaded sha256 {got}, the backup row says {want}"))
}

/// Where the existing restore reads a site archive and a database dump.
pub fn site_backup_path(domain: &str, filename: &str) -> PathBuf {
    Path::new(BACKUP_ROOT).join(domain).join(filename)
}

pub fn db_backup_path(db_name: &str, filename: &str) -> PathBuf {
    Path::new(BACKUP_ROOT).join("databases").join(db_name).join(filename)
}

/// Whether a database dump is superseded by a site archive restored in this
/// pass: the site archive carried databases and is at least as recent.
pub fn superseded_by_site(dump_at: DateTime<Utc>, site_archive: Option<(DateTime<Utc>, bool)>) -> bool {
    matches!(site_archive, Some((at, carried)) if carried && at >= dump_at)
}

// ── The pass ────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SiteRow {
    site_id: Uuid,
    domain: String,
    filename: String,
    uploaded: bool,
    destination_id: Option<Uuid>,
    destination_name: Option<String>,
    created_at: DateTime<Utc>,
    databases_included: i32,
    sha256_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbRow {
    database_id: Uuid,
    site_id: Option<Uuid>,
    db_name: String,
    filename: String,
    uploaded: bool,
    destination_id: Option<Uuid>,
    destination_name: Option<String>,
    created_at: DateTime<Utc>,
    db_type: String,
    encrypted: bool,
    encryption_key_version: i16,
    sha256_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbDef {
    name: String,
    engine: String,
    db_password_enc: String,
    port: Option<i32>,
    stack_id: Option<Uuid>,
    kind: String,
}

/// Run the pass. The caller holds the [`RunGuard`].
pub async fn run(db: PgPool, handle: AgentHandle, local_server_id: Uuid, jwt_secret: String, _guard: RunGuard) {
    let mut report = Report { started_at: Utc::now(), finished_at: None, items: Vec::new(), restored: 0, failed: 0, skipped: 0 };
    publish(&report);
    let agent = &handle;

    let recreated = recreate_missing_containers(&db, &handle, local_server_id, &jwt_secret, &mut report).await;
    publish(&report);

    // ── Sites ──
    let sites: Vec<SiteRow> = match sqlx::query_as(
        "SELECT DISTINCT ON (b.site_id) b.site_id, s.domain, b.filename, b.uploaded, b.destination_id, \
                d.name AS destination_name, b.created_at, b.databases_included, b.sha256_hash \
         FROM backups b JOIN sites s ON s.id = b.site_id LEFT JOIN backup_destinations d ON d.id = b.destination_id \
         WHERE s.server_id = $1 \
         ORDER BY b.site_id, b.created_at DESC",
    )
    .bind(local_server_id)
    .fetch_all(&db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            report.items.push(Item { kind: "site", name: "*".into(), filename: None, destination: None, status: "failed", detail: format!("could not list the site backups: {e}") });
            Vec::new()
        }
    };
    let mut restored_sites: Vec<(Uuid, DateTime<Utc>, bool)> = Vec::new();
    for s in sites {
        let latest = Latest { filename: s.filename.clone(), uploaded: s.uploaded, destination_id: s.destination_id, created_at: s.created_at };
        let mut item = Item { kind: "site", name: s.domain.clone(), filename: Some(s.filename.clone()), destination: s.destination_name.clone(), status: "skipped", detail: String::new() };
        if let Some(why) = remote_skip_reason(&latest) {
            item.detail = why.into();
        } else {
            let target = site_backup_path(&s.domain, &s.filename);
            match fetch(&db, agent, s.destination_id, &s.filename, s.sha256_hash.as_deref(), &target).await {
                Err(e) => {
                    item.status = "failed";
                    item.detail = e;
                }
                Ok(note) => match restore_site(&db, &handle, &jwt_secret, s.site_id, &s.domain, &s.filename).await {
                    Ok(d) => {
                        item.status = "restored";
                        item.detail = format!("{note}{d}");
                        restored_sites.push((s.site_id, s.created_at, s.databases_included > 0));
                    }
                    Err(e) => {
                        item.status = "failed";
                        item.detail = format!("{note}{e}");
                    }
                },
            }
        }
        report.items.push(item);
        report.count();
        publish(&report);
    }

    // ── Databases ──
    let dbs: Vec<DbRow> = match sqlx::query_as(
        "SELECT DISTINCT ON (b.database_id) b.database_id, dd.site_id, b.db_name, b.filename, b.uploaded, b.destination_id, \
                d.name AS destination_name, b.created_at, b.db_type, b.encrypted, b.encryption_key_version, b.sha256_hash \
         FROM database_backups b JOIN databases dd ON dd.id = b.database_id \
         LEFT JOIN backup_destinations d ON d.id = b.destination_id \
         WHERE b.server_id = $1 \
         ORDER BY b.database_id, b.created_at DESC",
    )
    .bind(local_server_id)
    .fetch_all(&db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            report.items.push(Item { kind: "database", name: "*".into(), filename: None, destination: None, status: "failed", detail: format!("could not list the database backups: {e}") });
            Vec::new()
        }
    };
    for b in dbs {
        let latest = Latest { filename: b.filename.clone(), uploaded: b.uploaded, destination_id: b.destination_id, created_at: b.created_at };
        let mut item = Item { kind: "database", name: b.db_name.clone(), filename: Some(b.filename.clone()), destination: b.destination_name.clone(), status: "skipped", detail: String::new() };
        let site_archive = b.site_id.and_then(|sid| restored_sites.iter().find(|(id, _, _)| *id == sid).map(|(_, at, c)| (*at, *c)));
        if let Some(why) = remote_skip_reason(&latest) {
            item.detail = why.into();
        } else if superseded_by_site(b.created_at, site_archive) {
            item.detail = "the site archive restored above is more recent and carried this database".into();
        } else {
            let target = db_backup_path(&b.db_name, &b.filename);
            match fetch(&db, agent, b.destination_id, &b.filename, b.sha256_hash.as_deref(), &target).await {
                Err(e) => {
                    item.status = "failed";
                    item.detail = e;
                }
                Ok(note) => match restore_database(&db, &handle, &jwt_secret, &b).await {
                    Ok(()) => {
                        item.status = "restored";
                        item.detail = format!("{note}restored");
                    }
                    Err(e) => {
                        item.status = "failed";
                        item.detail = format!("{note}{e}");
                    }
                },
            }
        }
        if let Some(n) = recreated.iter().find(|n| **n == b.db_name) {
            item.detail = format!("container {n} recreated; {}", item.detail);
        }
        report.items.push(item);
        report.count();
        publish(&report);
    }

    report.finished_at = Some(Utc::now());
    report.count();
    publish(&report);
    match serde_json::to_vec_pretty(&report) {
        Ok(body) => {
            if let Err(e) = std::fs::write(REPORT_PATH, body) {
                tracing::error!("Rehydration: could not write {REPORT_PATH}: {e}");
            }
        }
        Err(e) => tracing::error!("Rehydration: could not serialise the report: {e}"),
    }
    tracing::info!(
        "Rehydration from remote backups finished: restored={} failed={} skipped={}",
        report.restored,
        report.failed,
        report.skipped
    );
}

/// Make sure `target` holds the archive: kept when already there with the
/// right hash, else downloaded and moved into place. Returns a note for the report.
async fn fetch(
    db: &PgPool,
    agent: &AgentHandle,
    destination_id: Option<Uuid>,
    filename: &str,
    sha256: Option<&str>,
    target: &Path,
) -> Result<String, String> {
    if !plain_file_name(filename) {
        return Err(format!("refusing the file name '{filename}'"));
    }
    if target.is_file() {
        return Ok("already on this machine; ".into());
    }
    let dest_id = destination_id.ok_or("no destination")?;
    let row: Option<(String, serde_json::Value)> = sqlx::query_as("SELECT dtype, config FROM backup_destinations WHERE id = $1")
        .bind(dest_id)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("could not read the destination: {e}"))?;
    let (dtype, config) = row.ok_or("the destination no longer exists")?;
    let payload = crate::routes::backup_destinations::agent_destination_payload(&dtype, &config);
    let (path, _size, got) = dr_restore::download(agent, &payload, filename, filename).await?;
    let warning = match checksum_verdict(filename, sha256, &got) {
        Ok(w) => w,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };
    if let Some(w) = &warning {
        tracing::warn!("Rehydration: {filename}: {w}");
    }
    let parent = target.parent().ok_or("no parent directory")?;
    if let Err(e) = std::fs::create_dir_all(parent) {
        let _ = std::fs::remove_file(&path);
        return Err(format!("cannot create {}: {e}", parent.display()));
    }
    if let Err(e) = std::fs::rename(&path, target) {
        let _ = std::fs::remove_file(&path);
        return Err(format!("cannot move the download to {}: {e}", target.display()));
    }
    Ok(match warning {
        Some(w) => format!("downloaded; WARNING: {w}; "),
        None => "downloaded; ".into(),
    })
}

async fn restore_site(
    db: &PgPool,
    agent: &AgentHandle,
    jwt_secret: &str,
    site_id: Uuid,
    domain: &str,
    filename: &str,
) -> Result<String, String> {
    let site_dbs = crate::routes::backups::site_database_specs(db, jwt_secret, site_id).await;
    let body = serde_json::json!({ "databases": site_dbs.specs });
    let outcome = match agent.post_long(&format!("/backups/{domain}/restore/{filename}"), Some(body), RESTORE_TIMEOUT_SECS).await {
        Ok(v) => Ok(v),
        Err(crate::services::agent::AgentError::Status(code, body)) => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(r) if r.get("files_restored").is_some() => Ok(r),
            _ => Err(agent_message(&crate::services::agent::AgentError::Status(code, body))),
        },
        Err(e) => Err(agent_message(&e)),
    }?;
    let files = outcome.get("files_restored").and_then(|v| v.as_bool()).unwrap_or(true);
    let dbs: Vec<String> = outcome
        .get("databases_restored")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let db_errors: Vec<String> = outcome
        .get("databases_failed")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|f| {
                    let name = f.get("db_name").and_then(|v| v.as_str()).unwrap_or("?");
                    let why = f.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
                    format!("{name}: {why}")
                })
                .collect()
        })
        .unwrap_or_default();
    if !files {
        return Err("the agent did not restore the files".into());
    }
    if !db_errors.is_empty() {
        return Err(format!("files restored, but databases failed: {}", db_errors.join("; ")));
    }
    Ok(if dbs.is_empty() { "files restored".into() } else { format!("files and databases ({}) restored", dbs.join(", ")) })
}

async fn restore_database(db: &PgPool, agent: &AgentHandle, jwt_secret: &str, b: &DbRow) -> Result<(), String> {
    if !plain_file_name(&b.db_name) {
        return Err("invalid database name".into());
    }
    let creds: Option<(String, String, String)> =
        sqlx::query_as("SELECT db_user, db_password_enc, kind FROM databases WHERE id = $1")
            .bind(b.database_id)
            .fetch_optional(db)
            .await
            .map_err(|e| format!("could not read the database: {e}"))?;
    let (user, password_enc, kind) = creds.ok_or("the database no longer exists")?;
    let password = zeroize::Zeroizing::new(crate::services::secrets_crypto::decrypt_credential_or_legacy(&password_enc, jwt_secret));
    let encryption_key = b.encrypted.then(|| {
        zeroize::Zeroizing::new(crate::services::backup_policy_executor::derive_backup_encryption_key_for_version(
            b.encryption_key_version,
            jwt_secret,
        ))
    });
    let body = serde_json::json!({
        "container_name": crate::routes::databases::container_ref(&kind, &b.db_name),
        "db_type": b.db_type,
        "user": user,
        "password": password.as_str(),
        "encryption_key": encryption_key.as_ref().map(|k| k.as_str()),
    });
    agent
        .post_long(&format!("/db-backups/{}/restore/{}", b.db_name, b.filename), Some(body), RESTORE_TIMEOUT_SECS)
        .await
        .map(|_| ())
        .map_err(|e| agent_message(&e))
}

/// Recreate the container of every local container-kind database that does
/// not exist here. Returns the names recreated.
async fn recreate_missing_containers(
    db: &PgPool,
    agent: &AgentHandle,
    local_server_id: Uuid,
    jwt_secret: &str,
    report: &mut Report,
) -> Vec<String> {
    let defs: Vec<DbDef> = match sqlx::query_as(
        "SELECT d.name, d.engine, d.db_password_enc, d.port, d.stack_id, d.kind FROM databases d \
         LEFT JOIN sites s ON s.id = d.site_id LEFT JOIN docker_stacks st ON st.id = d.stack_id \
         WHERE d.kind = 'container' \
           AND ((s.id IS NOT NULL AND s.server_id = $1) OR (s.id IS NULL AND st.server_id = $1)) \
         ORDER BY d.name",
    )
    .bind(local_server_id)
    .fetch_all(db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            report.items.push(Item { kind: "database", name: "*".into(), filename: None, destination: None, status: "failed", detail: format!("could not list the databases: {e}") });
            return Vec::new();
        }
    };
    if defs.is_empty() {
        return Vec::new();
    }
    let existing: Vec<String> = match agent.get("/databases").await {
        Ok(v) => v
            .as_array()
            .map(|a| a.iter().filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_string)).collect())
            .unwrap_or_default(),
        Err(e) => {
            report.items.push(Item { kind: "database", name: "*".into(), filename: None, destination: None, status: "failed", detail: format!("could not list the database containers: {}", agent_message(&e)) });
            return Vec::new();
        }
    };
    let mut recreated = Vec::new();
    for d in defs {
        let container = crate::routes::databases::container_ref(&d.kind, &d.name);
        if existing.iter().any(|n| *n == container) {
            continue;
        }
        let Some(port) = d.port else {
            report.items.push(Item { kind: "database", name: d.name.clone(), filename: None, destination: None, status: "failed", detail: "its container is missing and the row has no port to recreate it on".into() });
            continue;
        };
        let password = zeroize::Zeroizing::new(crate::services::secrets_crypto::decrypt_credential_or_legacy(&d.db_password_enc, jwt_secret));
        let body = serde_json::json!({
            "name": d.name,
            "engine": d.engine,
            "password": password.as_str(),
            "port": port,
            "stack_id": d.stack_id.map(|id| id.to_string()),
        });
        match agent.post_long("/databases", Some(body), 300).await {
            Ok(v) => {
                let cid = v.get("container_id").and_then(|c| c.as_str()).unwrap_or("").to_string();
                if let Err(e) = sqlx::query("UPDATE databases SET container_id = $1 WHERE name = $2").bind(&cid).bind(&d.name).execute(db).await {
                    tracing::warn!("Rehydration: container of {} recreated but its id not recorded: {e}", d.name);
                }
                tracing::info!("Rehydration: recreated the container of database {}", d.name);
                recreated.push(d.name);
            }
            Err(e) => {
                report.items.push(Item { kind: "database", name: d.name.clone(), filename: None, destination: None, status: "failed", detail: format!("its container is missing and could not be recreated: {}", agent_message(&e)) });
            }
        }
    }
    recreated
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 19, h, 0, 0).unwrap()
    }

    #[test]
    fn only_a_latest_backup_that_went_off_site_is_fetched() {
        let up = Latest { filename: "a.tar.gz".into(), uploaded: true, destination_id: Some(Uuid::nil()), created_at: at(1) };
        assert_eq!(remote_skip_reason(&up), None);
        assert!(remote_skip_reason(&Latest { uploaded: false, ..up.clone() }).is_some());
        assert!(remote_skip_reason(&Latest { destination_id: None, ..up }).is_some());
    }

    #[test]
    fn file_names_and_paths_stay_under_the_backup_root() {
        assert!(plain_file_name("example.com-20261119-030000.tar.gz"));
        for bad in ["", "../x", "a/b", "..", "a b", "x\0"] {
            assert!(!plain_file_name(bad), "{bad:?}");
        }
        assert_eq!(
            site_backup_path("example.com", "f.tar.gz"),
            PathBuf::from("/var/backups/dockpanel/example.com/f.tar.gz")
        );
        assert_eq!(db_backup_path("wp", "d.sql.gz"), PathBuf::from("/var/backups/dockpanel/databases/wp/d.sql.gz"));
    }

    #[test]
    fn a_checksum_mismatch_fails_a_plain_file_and_warns_on_an_encrypted_one() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        assert_eq!(checksum_verdict("wp.sql.gz", Some(&a), &a.to_uppercase()), Ok(None));
        assert_eq!(checksum_verdict("wp.sql.gz", None, &a), Ok(None));
        assert_eq!(checksum_verdict("wp.sql.gz", Some(""), &a), Ok(None));
        let e = checksum_verdict("wp.sql.gz", Some(&a), &b).unwrap_err();
        assert!(e.contains("checksum mismatch"), "{e}");
        assert!(checksum_verdict("example.com.tar.gz", Some(&a), &b).is_err());
        let w = checksum_verdict("wp.sql.gz.enc", Some(&a), &b).unwrap().expect("a warning");
        assert!(w.contains("HMAC") && w.contains(&a) && w.contains(&b), "{w}");
        assert_eq!(checksum_verdict("wp.sql.gz.enc", Some(&a), &a), Ok(None));
    }

    #[test]
    fn a_dump_older_than_a_restored_site_archive_that_carried_it_is_skipped() {
        assert!(superseded_by_site(at(1), Some((at(2), true))));
        assert!(superseded_by_site(at(2), Some((at(2), true))));
        assert!(!superseded_by_site(at(3), Some((at(2), true))), "a newer dump wins");
        assert!(!superseded_by_site(at(1), Some((at(2), false))), "an archive without databases does not");
        assert!(!superseded_by_site(at(1), None));
    }
}
