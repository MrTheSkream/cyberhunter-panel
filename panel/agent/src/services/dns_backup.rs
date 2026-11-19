//! DNS backups (lot 3): one JSON export per zone (made by the panel through
//! the PowerDNS API, stored here), and an always-encrypted snapshot of the
//! whole PowerDNS database, which is the only copy of DNSSEC keys.
//!
//! Files live in `/var/backups/dockpanel/dns/` (0700):
//! * `dns-zone-{zone without trailing dot}-{%Y%m%d-%H%M%S}.json[.enc]`;
//! * `dns-snapshot-{sqlite|pgsql}-{stamp}.gz.enc`: sqlite = an online
//!   `.backup` copy (consistent while PowerDNS writes), checked with
//!   `PRAGMA integrity_check`, gzipped; pgsql = `pg_dump -Fc` of the pdns
//!   database in the panel's PostgreSQL container, gzipped as well so every
//!   snapshot has the same shape.
//!
//! The backend is read from `pdns.conf` (`launch=` and `gsqlite3-database=`
//! only: the database password in that file is never read). The sqlite file is
//! under `/var/lib/powerdns`, outside the agent's ReadWritePaths: reading it
//! (WAL mode needs the `-shm` file) and installing a restored copy go through
//! `safe_command_unsandboxed`. PowerDNS is restarted after a restore whatever
//! happened.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use crate::services::mail_backup::{
    self as common, ArchiveInfo, PartFile, ensure_free_name, ensure_private_dir, finalize, is_safe_backup_filename,
    locate, optional_key, readable, require_key, stamp, stderr_of, strip_stamp_suffix,
};
use crate::services::volume_backup::{self, VbError};

pub const DNS_BACKUP_DIR: &str = "/var/backups/dockpanel/dns";
pub const PDNS_CONF: &str = "/etc/powerdns/pdns.conf";
const PG_CONTAINER: &str = "dockpanel-postgres";
/// The panel's PostgreSQL, as the PowerDNS installer writes it into pdns.conf.
const PANEL_PG_PORT: &str = "5450";
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3600);

// ── Backend detection ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdnsBackend {
    Sqlite { database: PathBuf },
    Pgsql { dbname: String, user: String },
}

impl PdnsBackend {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => "sqlite",
            Self::Pgsql { .. } => "pgsql",
        }
    }
}

fn is_safe_db_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.contains("..")
        && p.len() <= 255
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
}

fn is_pg_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Read the backend from the text of pdns.conf (and of its include-dir files,
/// concatenated). Only `launch`, `gsqlite3-database`, `gpgsql-host`,
/// `gpgsql-port`, `gpgsql-dbname` and `gpgsql-user` are looked at.
pub fn detect_backend(conf: &str) -> Result<PdnsBackend, String> {
    let mut launch: Vec<String> = Vec::new();
    let (mut db, mut host, mut port, mut dbname, mut user) = (None, None, None, None, None);
    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim().to_string());
        match k {
            "launch" => launch = split_launch(&v),
            "launch+" => launch.extend(split_launch(&v)),
            "gsqlite3-database" => db = Some(v),
            "gpgsql-host" => host = Some(v),
            "gpgsql-port" => port = Some(v),
            "gpgsql-dbname" => dbname = Some(v),
            "gpgsql-user" => user = Some(v),
            _ => {}
        }
    }
    let sqlite = launch.iter().any(|m| m == "gsqlite3");
    let pgsql = launch.iter().any(|m| m == "gpgsql");
    match (sqlite, pgsql) {
        (true, true) => Err("PowerDNS launches both gsqlite3 and gpgsql: no single database to snapshot".into()),
        (true, false) => {
            let database = db.ok_or("gsqlite3-database is not set in pdns.conf")?;
            if !is_safe_db_path(&database) {
                return Err("gsqlite3-database in pdns.conf is not a plain absolute path".into());
            }
            Ok(PdnsBackend::Sqlite { database: PathBuf::from(database) })
        }
        (false, true) => {
            let host = host.unwrap_or_default();
            if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") || port.as_deref() != Some(PANEL_PG_PORT) {
                return Err("PowerDNS does not use the panel's PostgreSQL container: its database cannot be snapshotted here".into());
            }
            let dbname = dbname.unwrap_or_default();
            let user = user.unwrap_or_default();
            if !is_pg_ident(&dbname) || !is_pg_ident(&user) {
                return Err("gpgsql-dbname or gpgsql-user in pdns.conf is missing or unusual".into());
            }
            Ok(PdnsBackend::Pgsql { dbname, user })
        }
        (false, false) => Err(format!(
            "Unsupported PowerDNS backend (launch={}): only gsqlite3 and gpgsql can be snapshotted",
            launch.join(",")
        )),
    }
}

fn split_launch(v: &str) -> Vec<String> {
    v.split(',')
        .map(|m| m.trim().split(':').next().unwrap_or("").to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// The text of pdns.conf plus its `include-dir` `*.conf` files, or `None` when
/// pdns.conf does not exist (PowerDNS not installed).
pub fn load_pdns_conf(path: &Path) -> Option<String> {
    let main = std::fs::read_to_string(path).ok()?;
    let mut text = main.clone();
    let include = main.lines().filter_map(|l| l.trim().strip_prefix("include-dir=")).last().map(|s| s.trim().to_string());
    if let Some(dir) = include {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut names: Vec<PathBuf> =
                rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")).collect();
            names.sort();
            for p in names {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    text.push('\n');
                    text.push_str(&t);
                }
            }
        }
    }
    Some(text)
}

pub fn pdns_installed() -> bool {
    Path::new(PDNS_CONF).is_file()
}

fn current_backend() -> Result<PdnsBackend, VbError> {
    let conf = load_pdns_conf(Path::new(PDNS_CONF)).ok_or_else(|| VbError::Internal("pdns.conf could not be read".into()))?;
    detect_backend(&conf).map_err(VbError::BadRequest)
}

// ── Names ───────────────────────────────────────────────────────────────────

/// A zone as the panel names it (`a.com.` or `a.com`): lowercase, without the
/// final dot, a valid domain.
pub fn normalize_zone(z: &str) -> Result<String, VbError> {
    let z = z.trim().to_ascii_lowercase();
    let z = z.strip_suffix('.').unwrap_or(&z).to_string();
    if z.contains("..") || !crate::routes::is_valid_domain(&z) {
        return Err(VbError::BadRequest("Invalid zone".into()));
    }
    Ok(z)
}

pub fn zone_archive_name(zone: &str, stamp: &str) -> String {
    format!("dns-zone-{zone}-{stamp}.json")
}

/// The zone (without the final dot) of a zone backup name.
pub fn parse_zone_archive_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("dns-zone-")?;
    let zone = strip_stamp_suffix(rest, &[".json.enc", ".json"])?;
    normalize_zone(zone).ok().filter(|z| z == zone)
}

pub fn snapshot_name(backend: &str, stamp: &str) -> String {
    format!("dns-snapshot-{backend}-{stamp}.gz")
}

/// The backend of a snapshot name (always encrypted: `.gz.enc`).
pub fn parse_snapshot_name(name: &str) -> Option<&'static str> {
    let rest = name.strip_prefix("dns-snapshot-")?;
    let head = strip_stamp_suffix(rest, &[".gz.enc"])?;
    match head {
        "sqlite" => Some("sqlite"),
        "pgsql" => Some("pgsql"),
        _ => None,
    }
}

// ── Requests ────────────────────────────────────────────────────────────────

/// Body of `POST /dns/archive`. No `Debug`: it carries the key.
#[derive(serde::Deserialize)]
pub struct DnsArchiveRequest {
    pub kind: String,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    #[serde(default)]
    pub encryption_key: Option<String>,
}

/// Body of `POST /dns/restore`. No `Debug`: it carries the key.
#[derive(serde::Deserialize)]
pub struct DnsRestoreRequest {
    pub kind: String,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub encryption_key: Option<String>,
}

pub enum DnsArchivePlan {
    Zone { zone: String, content: serde_json::Value, key: Option<String> },
    Snapshot { key: String },
}

pub enum DnsRestorePlan {
    Zone { filename: String, key: Option<String> },
    Snapshot { filename: String, backend: &'static str, key: String },
}

pub fn plan_archive(req: DnsArchiveRequest) -> Result<DnsArchivePlan, VbError> {
    match req.kind.as_str() {
        "zone" => {
            let zone = normalize_zone(req.zone.as_deref().unwrap_or(""))?;
            let content = req.content.filter(|c| c.is_object()).ok_or_else(|| VbError::BadRequest("content must be a JSON object".into()))?;
            Ok(DnsArchivePlan::Zone { zone, content, key: optional_key(&req.encryption_key)? })
        }
        "snapshot" => Ok(DnsArchivePlan::Snapshot { key: require_key(&req.encryption_key, "the DNS snapshot")? }),
        _ => Err(VbError::BadRequest("kind must be 'zone' or 'snapshot'".into())),
    }
}

pub fn plan_restore(req: DnsRestoreRequest) -> Result<DnsRestorePlan, VbError> {
    let filename = req.filename.unwrap_or_default();
    if !is_safe_backup_filename(&filename) {
        return Err(VbError::BadRequest("Invalid backup filename".into()));
    }
    match req.kind.as_str() {
        "zone" => {
            if parse_zone_archive_name(&filename).is_none() {
                return Err(VbError::BadRequest("Not a DNS zone backup".into()));
            }
            let key = optional_key(&req.encryption_key)?;
            if filename.ends_with(".enc") && key.is_none() {
                return Err(VbError::BadRequest("encryption_key is required for an encrypted backup".into()));
            }
            Ok(DnsRestorePlan::Zone { filename, key })
        }
        "snapshot" => {
            let backend = parse_snapshot_name(&filename).ok_or_else(|| VbError::BadRequest("Not a DNS snapshot".into()))?;
            Ok(DnsRestorePlan::Snapshot { filename, backend, key: require_key(&req.encryption_key, "the DNS snapshot")? })
        }
        _ => Err(VbError::BadRequest("kind must be 'zone' or 'snapshot'".into())),
    }
}

// ── Zones ───────────────────────────────────────────────────────────────────

/// Store the panel's export of one zone. Short: answered directly.
pub async fn archive_zone(zone: String, content: serde_json::Value, key: Option<String>) -> Result<ArchiveInfo, VbError> {
    let dir = Path::new(DNS_BACKUP_DIR);
    ensure_private_dir(dir)?;
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "format": 1,
        "zone": format!("{zone}."),
        "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "content": content,
    }))
    .map_err(|e| VbError::Internal(format!("Failed to encode the zone: {e}")))?;
    volume_backup::check_space(dir, (body.len() as u64).saturating_mul(3) + 1024 * 1024, "the zone backup")?;
    let name = zone_archive_name(&zone, &stamp(chrono::Utc::now()));
    ensure_free_name(dir, &name)?;
    let part = PartFile::create(dir, &name)?;
    {
        use std::io::Write;
        let mut f = part.file()?;
        f.write_all(&body).map_err(|e| VbError::Internal(format!("Failed to write the zone backup: {e}")))?;
    }
    let info = finalize(part, dir, &name, key.as_deref()).await?;
    tracing::info!("DNS zone backed up: {zone} -> {} ({} bytes)", info.filename, info.size_bytes);
    Ok(info)
}

/// Read a zone backup back: `{"zone": "a.com.", "content": {...}}`. The panel
/// re-applies it through the PowerDNS API.
pub async fn read_zone(filename: String, key: Option<String>) -> Result<serde_json::Value, VbError> {
    let expected = parse_zone_archive_name(&filename).ok_or_else(|| VbError::BadRequest("Not a DNS zone backup".into()))?;
    let dir = locate(Path::new(DNS_BACKUP_DIR), &filename)?;
    let r = readable(&dir, &filename, key.as_deref()).await?;
    let doc: serde_json::Value = serde_json::from_slice(&common::read_doc(&r.path)?)
        .map_err(|_| VbError::Integrity("The zone backup is not valid JSON".into()))?;
    let (Some(zone), Some(content)) = (doc.get("zone").and_then(|z| z.as_str()), doc.get("content")) else {
        return Err(VbError::Integrity("The zone backup has no zone or content".into()));
    };
    if normalize_zone(zone).ok().as_deref() != Some(expected.as_str()) {
        return Err(VbError::Integrity("The zone backup holds another zone than its name says".into()));
    }
    Ok(serde_json::json!({ "zone": zone, "content": content }))
}

// ── Snapshot ────────────────────────────────────────────────────────────────

/// `sqlite3` on our own private copy: `immutable=1` (no lock, no -wal/-shm
/// created beside it), sandboxed. Returns the first output line.
async fn sqlite_query_private(path: &Path, sql: &str) -> Result<String, VbError> {
    let uri = format!("file:{}?immutable=1", path.display());
    let out = tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        safe_command("sqlite3").arg(&uri).arg(sql).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| VbError::Internal("sqlite3 timed out".into()))?
    .map_err(|e| VbError::Internal(format!("sqlite3 could not run: {e}")))?;
    if !out.status.success() {
        return Err(VbError::Integrity(format!("The DNS database copy cannot be read: {}", stderr_of(&out))));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").trim().to_string())
}

async fn integrity_ok(path: &Path) -> Result<(), VbError> {
    let first = sqlite_query_private(path, "PRAGMA integrity_check;").await?;
    if first != "ok" {
        return Err(VbError::Integrity(format!(
            "The DNS database copy fails its integrity check: {}",
            first.chars().take(200).collect::<String>()
        )));
    }
    Ok(())
}

/// gzip `src` into `dst` (an existing 0600 part file), streaming.
async fn gzip_into(src: &Path, dst: &PartFile) -> Result<(), VbError> {
    let out = tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        safe_command("gzip")
            .arg("-c")
            .arg(src)
            .stdout(Stdio::from(dst.file()?))
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| VbError::Internal("gzip timed out".into()))?
    .map_err(|e| VbError::Internal(format!("gzip could not run: {e}")))?;
    if !out.status.success() {
        return Err(VbError::Internal(format!("gzip failed: {}", stderr_of(&out))));
    }
    Ok(())
}

async fn gunzip_into(src: &Path, dst: &PartFile) -> Result<(), VbError> {
    let out = tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        safe_command("gzip")
            .arg("-dc")
            .arg(src)
            .stdout(Stdio::from(dst.file()?))
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| VbError::Internal("gunzip timed out".into()))?
    .map_err(|e| VbError::Internal(format!("gunzip could not run: {e}")))?;
    if !out.status.success() {
        return Err(VbError::Integrity(format!("The DNS snapshot is not a valid gzip stream: {}", stderr_of(&out))));
    }
    Ok(())
}

/// Copy the live PowerDNS database into `raw` (an existing empty 0600 file).
async fn dump_backend(backend: &PdnsBackend, raw: &PartFile) -> Result<(), VbError> {
    match backend {
        PdnsBackend::Sqlite { database } => {
            // Online backup API: a consistent copy while PowerDNS writes. Run
            // outside the sandbox because /var/lib/powerdns is read-only in
            // it and a WAL-mode reader must be able to use the -shm file.
            // `mode=ro`: nothing is ever written to the live database.
            let uri = format!("file:{}?mode=ro", database.display());
            let out = safe_command_unsandboxed("sqlite3", &[])
                .arg(&uri)
                .arg(format!(".backup '{}'", raw.path.display()))
                .output_with_timeout(SNAPSHOT_TIMEOUT)
                .await
                .map_err(VbError::Internal)?;
            if !out.status.success() {
                return Err(VbError::Internal(format!("sqlite3 .backup failed: {}", stderr_of(&out))));
            }
            integrity_ok(&raw.path).await
        }
        PdnsBackend::Pgsql { dbname, user } => {
            // Local socket inside the container: no password involved.
            let out = tokio::time::timeout(
                SNAPSHOT_TIMEOUT,
                safe_command("docker")
                    .args(["exec", PG_CONTAINER, "pg_dump", "-U", user, "-Fc", dbname])
                    .stdout(Stdio::from(raw.file()?))
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .map_err(|_| VbError::Internal("pg_dump timed out".into()))?
            .map_err(|e| VbError::Internal(format!("pg_dump could not run: {e}")))?;
            if !out.status.success() {
                return Err(VbError::Internal(format!("pg_dump of the PowerDNS database failed: {}", stderr_of(&out))));
            }
            check_pg_magic(&raw.path)
        }
    }
}

fn check_pg_magic(path: &Path) -> Result<(), VbError> {
    use std::io::Read;
    let mut head = [0u8; 5];
    let ok = std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok() && &head == b"PGDMP";
    if ok { Ok(()) } else { Err(VbError::Integrity("The PowerDNS dump is not a pg_dump custom-format archive".into())) }
}

/// Snapshot the whole PowerDNS database (job).
pub async fn take_snapshot(key: String) -> Result<serde_json::Value, VbError> {
    let _lock = crate::site_lock::lock_site("dns:snapshot").await;
    let backend = current_backend()?;
    let dir = Path::new(DNS_BACKUP_DIR);
    ensure_private_dir(dir)?;
    let need = match &backend {
        PdnsBackend::Sqlite { database } => std::fs::metadata(database)
            .map_err(|e| VbError::Internal(format!("Cannot read {}: {e}", database.display())))?
            .len()
            .saturating_mul(3),
        PdnsBackend::Pgsql { .. } => 256 * 1024 * 1024,
    };
    volume_backup::check_space(dir, need, "the DNS snapshot")?;
    let name = snapshot_name(backend.name(), &stamp(chrono::Utc::now()));
    ensure_free_name(dir, &name)?;

    let raw = PartFile::create(dir, &format!("snapshot-raw-{:016x}", rand::random::<u64>()))?;
    dump_backend(&backend, &raw).await?;
    let gz = PartFile::create(dir, &name)?;
    gzip_into(&raw.path, &gz).await?;
    drop(raw);
    let info = finalize(gz, dir, &name, Some(&key)).await?;
    tracing::info!("DNS snapshot ({}) taken: {} ({} bytes)", backend.name(), info.filename, info.size_bytes);
    let mut v = serde_json::to_value(&info).map_err(|e| VbError::Internal(e.to_string()))?;
    v["backend"] = backend.name().into();
    Ok(v)
}

async fn systemctl_pdns(action: &str) -> Result<(), String> {
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        safe_command("systemctl").args([action, "pdns"]).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| format!("systemctl {action} pdns timed out"))?
    .map_err(|e| format!("systemctl {action} pdns could not run: {e}"))?;
    if !out.status.success() {
        return Err(format!("systemctl {action} pdns failed: {}", stderr_of(&out)));
    }
    Ok(())
}

async fn unsandboxed(binary: &str, args: &[&str], what: &str) -> Result<(), VbError> {
    let out = safe_command_unsandboxed(binary, &[])
        .args(args)
        .output_with_timeout(SNAPSHOT_TIMEOUT)
        .await
        .map_err(VbError::Internal)?;
    if !out.status.success() {
        return Err(VbError::Internal(format!("{what} failed: {}", stderr_of(&out))));
    }
    Ok(())
}

/// Install the checked copy `raw` as the live sqlite database (PowerDNS is
/// stopped). The previous database is kept as `{db}.before-restore` and put
/// back if the new one cannot be installed or does not pass its check.
async fn install_sqlite(raw: &Path, database: &Path) -> Result<(), VbError> {
    let db = database.to_string_lossy().to_string();
    let staged = format!("{db}.restore-new");
    let before = format!("{db}.before-restore");
    let raw_s = raw.to_string_lossy().to_string();
    let had_previous = database.exists();
    if had_previous {
        unsandboxed("cp", &["-a", "--", &db, &before], "Keeping a copy of the current DNS database").await?;
    }
    unsandboxed("install", &["-o", "pdns", "-g", "pdns", "-m", "0640", "--", &raw_s, &staged], "Installing the DNS database")
        .await?;
    // A WAL left by the old database would be replayed into the new one.
    unsandboxed("rm", &["-f", "--", &format!("{db}-wal"), &format!("{db}-shm")], "Removing the old WAL").await?;
    unsandboxed("mv", &["-f", "--", &staged, &db], "Moving the DNS database into place").await?;
    let uri = format!("file:{db}?mode=ro");
    let check = safe_command_unsandboxed("sqlite3", &[])
        .arg(&uri)
        .arg("PRAGMA integrity_check;")
        .output_with_timeout(SNAPSHOT_TIMEOUT)
        .await
        .map_err(VbError::Internal)?;
    let first = String::from_utf8_lossy(&check.stdout).lines().next().unwrap_or("").trim().to_string();
    if !check.status.success() || first != "ok" {
        if had_previous {
            unsandboxed("mv", &["-f", "--", &before, &db], "Putting the previous DNS database back").await?;
        }
        return Err(VbError::Integrity("The installed DNS database failed its integrity check; the previous one was put back".into()));
    }
    Ok(())
}

async fn pg_restore(raw: &Path, dbname: &str, user: &str) -> Result<(), VbError> {
    let file = std::fs::File::open(raw).map_err(|e| VbError::Internal(format!("Failed to open the dump: {e}")))?;
    let out = tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        safe_command("docker")
            .args([
                "exec", "-i", PG_CONTAINER, "pg_restore", "-U", user, "--clean", "--if-exists", "--single-transaction",
                "--no-owner", "-d", dbname,
            ])
            .stdin(Stdio::from(file))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| VbError::Internal("pg_restore timed out".into()))?
    .map_err(|e| VbError::Internal(format!("pg_restore could not run: {e}")))?;
    if !out.status.success() {
        return Err(VbError::Internal(format!(
            "pg_restore of the PowerDNS database failed (single transaction: nothing was changed): {}",
            stderr_of(&out)
        )));
    }
    Ok(())
}

/// Restore the whole PowerDNS database from a snapshot (job). Every check that
/// can refuse (passphrase, integrity, gzip, sqlite integrity, dump format)
/// runs before PowerDNS is stopped; once stopped, it is started again on every
/// path.
pub async fn restore_snapshot(filename: String, snapshot_backend: &'static str, key: String) -> Result<serde_json::Value, VbError> {
    let _lock = crate::site_lock::lock_site("dns:snapshot").await;
    let backend = current_backend()?;
    if backend.name() != snapshot_backend {
        return Err(VbError::BadRequest(format!(
            "This snapshot comes from a {snapshot_backend} PowerDNS backend, the server now uses {}",
            backend.name()
        )));
    }
    let dir = locate(Path::new(DNS_BACKUP_DIR), &filename)?;
    let r = readable(&dir, &filename, Some(&key)).await?;
    let gz_len = std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0);
    let work = Path::new(DNS_BACKUP_DIR);
    ensure_private_dir(work)?;
    volume_backup::check_space(work, gz_len.saturating_mul(8), "the decompressed DNS snapshot")?;
    let raw = PartFile::create(work, &format!("snapshot-restore-{:016x}", rand::random::<u64>()))?;
    gunzip_into(&r.path, &raw).await?;
    drop(r);
    match &backend {
        PdnsBackend::Sqlite { .. } => {
            integrity_ok(&raw.path).await?;
            sqlite_query_private(&raw.path, "SELECT count(*) FROM domains;")
                .await
                .map_err(|_| VbError::Integrity("The snapshot is not a PowerDNS database (no domains table)".into()))?;
        }
        PdnsBackend::Pgsql { .. } => check_pg_magic(&raw.path)?,
    }

    systemctl_pdns("stop").await.map_err(VbError::Internal)?;
    let outcome = match &backend {
        PdnsBackend::Sqlite { database } => install_sqlite(&raw.path, database).await,
        PdnsBackend::Pgsql { dbname, user } => pg_restore(&raw.path, dbname, user).await,
    };
    let started = systemctl_pdns("start").await;
    outcome?;
    if let Err(e) = started {
        return Err(VbError::Internal(format!("The DNS database was restored but PowerDNS did not start: {e}")));
    }
    tracing::info!("DNS snapshot restored ({}) from {filename}", backend.name());
    Ok(serde_json::json!({ "ok": true, "backend": backend.name(), "pdns_restarted": true }))
}

// ── Listing ─────────────────────────────────────────────────────────────────

pub fn list_backups(dir: &Path) -> Vec<serde_json::Value> {
    common::list_files(dir)
        .into_iter()
        .map(|(name, size, modified)| {
            let mut v = serde_json::json!({
                "filename": name,
                "size_bytes": size,
                "modified": modified,
                "encrypted": name.ends_with(".enc"),
            });
            if let Some(z) = parse_zone_archive_name(&name) {
                v["kind"] = "zone".into();
                v["zone"] = format!("{z}.").into();
            } else if let Some(b) = parse_snapshot_name(&name) {
                v["kind"] = "snapshot".into();
                v["backend"] = b.into();
            } else {
                v["kind"] = "other".into();
            }
            v
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ST: &str = "20261119-101010";

    #[test]
    fn backend_from_the_installers_sqlite_conf() {
        let conf = "# CyberHunter - Panel PowerDNS configuration (SQLite backend)\nlaunch=gsqlite3\ngsqlite3-database=/var/lib/powerdns/pdns.sqlite3\n\napi=yes\napi-key=SECRET\n";
        assert_eq!(
            detect_backend(conf),
            Ok(PdnsBackend::Sqlite { database: PathBuf::from("/var/lib/powerdns/pdns.sqlite3") })
        );
    }

    #[test]
    fn backend_from_the_installers_pgsql_conf() {
        let conf = "launch=gpgsql\ngpgsql-host=127.0.0.1\ngpgsql-port=5450\ngpgsql-dbname=pdns\ngpgsql-user=dockpanel\ngpgsql-password=s3cr$t\n";
        let b = detect_backend(conf).unwrap();
        assert_eq!(b, PdnsBackend::Pgsql { dbname: "pdns".into(), user: "dockpanel".into() });
        // The password is never part of what detection returns.
        assert!(!format!("{b:?}").contains("s3cr"));
    }

    #[test]
    fn backend_detection_edge_cases() {
        assert!(detect_backend("launch=gsqlite3,gpgsql\ngsqlite3-database=/x.db\n").is_err());
        assert!(detect_backend("launch=bind\n").unwrap_err().contains("Unsupported"));
        assert!(detect_backend("").is_err());
        assert!(detect_backend("launch=gsqlite3\n").is_err());
        assert!(detect_backend("launch=gsqlite3\ngsqlite3-database=relative.db\n").is_err());
        assert!(detect_backend("launch=gsqlite3\ngsqlite3-database=/a/../b.db\n").is_err());
        assert!(detect_backend("launch=gsqlite3\ngsqlite3-database=/a b.db\n").is_err());
        assert!(detect_backend("# launch=gpgsql\nlaunch = gsqlite3\ngsqlite3-database = /var/lib/powerdns/pdns.sqlite3\n").is_ok());
        assert!(detect_backend("launch=\nlaunch+=gsqlite3:main\ngsqlite3-database=/d.db\n").is_ok());
        // pgsql somewhere else than the panel's container
        assert!(detect_backend("launch=gpgsql\ngpgsql-host=db.example.com\ngpgsql-port=5450\ngpgsql-dbname=pdns\ngpgsql-user=u\n").is_err());
        assert!(detect_backend("launch=gpgsql\ngpgsql-host=127.0.0.1\ngpgsql-port=5432\ngpgsql-dbname=pdns\ngpgsql-user=u\n").is_err());
        assert!(detect_backend("launch=gpgsql\ngpgsql-host=127.0.0.1\ngpgsql-port=5450\ngpgsql-dbname=pdns;drop\ngpgsql-user=u\n").is_err());
    }

    #[test]
    fn include_dir_is_read() {
        let d = std::env::temp_dir().join(format!("dp-pdns-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(d.join("pdns.d")).unwrap();
        std::fs::write(d.join("pdns.conf"), format!("include-dir={}\n", d.join("pdns.d").display())).unwrap();
        std::fs::write(d.join("pdns.d/b.conf"), "launch=gsqlite3\ngsqlite3-database=/var/lib/powerdns/x.sqlite3\n").unwrap();
        let text = load_pdns_conf(&d.join("pdns.conf")).unwrap();
        assert_eq!(detect_backend(&text).unwrap().name(), "sqlite");
        assert!(load_pdns_conf(&d.join("absent.conf")).is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn zone_names() {
        assert_eq!(normalize_zone("Example.COM.").unwrap(), "example.com");
        assert_eq!(normalize_zone("1.168.192.in-addr.arpa").unwrap(), "1.168.192.in-addr.arpa");
        assert_eq!(normalize_zone("xn--e1afmkfd.xn--p1ai.").unwrap(), "xn--e1afmkfd.xn--p1ai");
        for bad in ["", ".", "../etc", "a..b", "a/b.com", "a b.com", "com"] {
            assert!(normalize_zone(bad).is_err(), "{bad}");
        }
        for z in ["example.com", "my-zone.example", "xn--e1afmkfd.xn--p1ai"] {
            let n = zone_archive_name(z, ST);
            assert!(is_safe_backup_filename(&n));
            assert_eq!(parse_zone_archive_name(&n).as_deref(), Some(z));
            assert_eq!(parse_zone_archive_name(&format!("{n}.enc")).as_deref(), Some(z));
        }
        assert!(parse_zone_archive_name("dns-zone--20261119-101010.json").is_none());
        assert!(parse_zone_archive_name("dns-zone-a.com-2026.json").is_none());
    }

    #[test]
    fn snapshot_names() {
        assert_eq!(parse_snapshot_name(&format!("{}.enc", snapshot_name("sqlite", ST))), Some("sqlite"));
        assert_eq!(parse_snapshot_name(&format!("{}.enc", snapshot_name("pgsql", ST))), Some("pgsql"));
        assert_eq!(parse_snapshot_name(&snapshot_name("pgsql", ST)), None, "a snapshot is always encrypted");
        assert_eq!(parse_snapshot_name("dns-snapshot-mysql-20261119-101010.gz.enc"), None);
    }

    #[test]
    fn bodies_parse_and_plan() {
        let r: DnsArchiveRequest = serde_json::from_value(serde_json::json!({
            "kind": "zone", "zone": "a.com.", "content": {"rrsets": []}, "encryption_key": null
        }))
        .unwrap();
        assert!(matches!(plan_archive(r).ok().unwrap(), DnsArchivePlan::Zone { ref zone, key: None, .. } if zone == "a.com"));
        let r: DnsArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "zone", "zone": "a.com.", "content": "x"})).unwrap();
        assert!(plan_archive(r).is_err());
        let r: DnsArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "zone", "zone": "../x", "content": {}})).unwrap();
        assert!(plan_archive(r).is_err());
        let r: DnsRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "zone", "filename": zone_archive_name("a.com", ST)
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).ok().unwrap(), DnsRestorePlan::Zone { .. }));
        let r: DnsRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "zone", "filename": format!("{}.enc", zone_archive_name("a.com", ST))
        }))
        .unwrap();
        assert!(plan_restore(r).is_err(), "encrypted zone without key");
        let r: DnsRestoreRequest =
            serde_json::from_value(serde_json::json!({"kind": "zone", "filename": "../../etc/shadow"})).unwrap();
        assert!(plan_restore(r).is_err());
    }

    #[test]
    fn snapshot_without_key_is_refused() {
        for body in [
            serde_json::json!({"kind": "snapshot"}),
            serde_json::json!({"kind": "snapshot", "encryption_key": ""}),
        ] {
            let r: DnsArchiveRequest = serde_json::from_value(body).unwrap();
            let e = plan_archive(r).err().unwrap();
            assert!(matches!(&e, VbError::BadRequest(m) if m.contains("always encrypted")), "{e}");
        }
        let r: DnsRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "snapshot", "filename": format!("{}.enc", snapshot_name("sqlite", ST))
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).err().unwrap(), VbError::BadRequest(_)));
        let r: DnsRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "snapshot", "filename": format!("{}.enc", snapshot_name("sqlite", ST)), "encryption_key": "k"
        }))
        .unwrap();
        assert!(matches!(plan_restore(r).ok().unwrap(), DnsRestorePlan::Snapshot { backend: "sqlite", .. }));
        let r: DnsArchiveRequest =
            serde_json::from_value(serde_json::json!({"kind": "snapshot", "encryption_key": "k"})).unwrap();
        assert!(matches!(plan_archive(r).ok().unwrap(), DnsArchivePlan::Snapshot { .. }));
    }

    #[test]
    fn pg_magic() {
        let d = std::env::temp_dir().join(format!("dp-pgm-{:016x}", rand::random::<u64>()));
        std::fs::write(&d, b"PGDMP\x01\x0e").unwrap();
        assert!(check_pg_magic(&d).is_ok());
        std::fs::write(&d, b"SQLite format 3").unwrap();
        assert!(check_pg_magic(&d).is_err());
        std::fs::remove_file(&d).ok();
    }

    #[test]
    fn listing_kinds() {
        let d = std::env::temp_dir().join(format!("dp-dnsl-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(zone_archive_name("a.com", ST)), b"{}").unwrap();
        std::fs::write(d.join(format!("{}.enc", snapshot_name("pgsql", ST))), b"x").unwrap();
        std::fs::write(d.join(".dns-snapshot-x.part"), b"x").unwrap();
        let items = list_backups(&d);
        assert_eq!(items.len(), 2);
        assert!(items.iter().any(|v| v["kind"] == "zone" && v["zone"] == "a.com." && v["encrypted"] == false));
        assert!(items.iter().any(|v| v["kind"] == "snapshot" && v["backend"] == "pgsql" && v["encrypted"] == true));
        std::fs::remove_dir_all(&d).ok();
    }

    #[tokio::test]
    async fn zone_round_trip_on_disk_format() {
        // The stored document wraps the panel's content with its zone.
        let d = std::env::temp_dir().join(format!("dp-dnsz-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        let part = PartFile::create(&d, "z.json").unwrap();
        std::fs::write(&part.path, br#"{"format":1,"zone":"a.com.","content":{"rrsets":[]}}"#).unwrap();
        let info = finalize(part, &d, "z.json", Some("k")).await.unwrap();
        let r = readable(&d, &info.filename, Some("k")).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&common::read_doc(&r.path).unwrap()).unwrap();
        assert_eq!(doc["content"]["rrsets"], serde_json::json!([]));
        drop(r);
        let e = readable(&d, &info.filename, Some("wrong")).await.err().unwrap();
        assert!(matches!(e, VbError::Integrity(_)), "wrong passphrase is a 422");
        std::fs::remove_dir_all(&d).ok();
    }
}
