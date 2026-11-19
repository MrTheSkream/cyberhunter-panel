//! Off-site disaster recovery snapshots (lot 2, steps 2.3 and 2.4).
//!
//! # What leaves the server
//!
//! A panel snapshot ([`panel_snapshot::create_snapshot`], trigger `scheduled`)
//! re-packed WITHOUT `binaries/` and `frontend/` (a restore reinstalls the same
//! version instead), with `metadata.json` enriched (`kind`, `format`,
//! `install_id`, `arch`), compressed by `tar -czf -` and encrypted IN FLUX with
//! age to one X25519 recipient, straight into
//! `/var/backups/dockpanel/dr-outbox/` (0700 directory, 0600 files):
//!
//! ```text
//! cyberhunter-dr-{install_id}-{%Y%m%d-%H%M%S}.tar.gz.age     the archive
//! cyberhunter-dr-{install_id}-{%Y%m%d-%H%M%S}.manifest.json  plaintext manifest, no secret
//! ```
//!
//! Both are sent through the agent's `/backups/upload` to
//! `<destination base>/cyberhunter-dr/<install_id>/` (the destination's
//! `path_prefix` / `remote_path` is extended, see [`dr_destination_payload`]),
//! the `remote_retention` newest of each kind are kept by `/backups/prune`, and
//! the outbox is emptied at the start and at the end of every run.
//!
//! # install_id
//!
//! The id of the `servers` row with `is_local = true`: created once at install,
//! carried by the database dump, so it survives a restore and names the same
//! installation on every archive. A fresh machine gets a new one until the old
//! database is restored onto it.
//!
//! # The recovery key
//!
//! The server generates an age X25519 identity at enrolment, stores ONLY the
//! public key and its fingerprint (`dr_recipients`), and hands the identity to
//! the caller once. It never goes to disk, argv, an environment variable or a
//! log; the copies this module makes are [`Zeroizing`]. A compromised server
//! therefore cannot read the archives it already sent.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use age::secrecy::ExposeSecret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::services::agent::AgentRegistry;
use crate::services::backup_policy_executor::{self as bpe, PruneSpec};
use crate::services::notifications;
use crate::services::panel_snapshot::{self, SnapshotTrigger};

/// Where the encrypted archive and its manifest wait for their upload.
pub const DR_OUTBOX: &str = "/var/backups/dockpanel/dr-outbox";
/// Plaintext staging of the re-packed snapshot (0700, removed on every path).
const DR_STAGING_PARENT: &str = "/var/backups/dockpanel/.dr-staging";
/// Sub-directory of every destination that holds the off-site snapshots.
pub const DR_REMOTE_DIR: &str = "cyberhunter-dr";
/// Copies of the SFTP keys that live outside /etc/dockpanel, so the snapshot
/// (which carries /etc/dockpanel) carries them too.
pub const BACKUP_KEYS_DIR: &str = "/etc/dockpanel/backup-keys";
/// Version of the archive layout and of the manifest.
pub const DR_FORMAT: u32 = 1;
/// No successful off-site copy for this long raises an alert.
pub const STALE_AFTER_HOURS: i64 = 48;
/// An alert is repeated at most this often while the condition lasts.
const ALERT_REPEAT_HOURS: i64 = 24;
/// Mirrors the column defaults of the migration.
#[allow(dead_code)]
pub const DEFAULT_SCHEDULE: &str = "30 3 * * *";
#[allow(dead_code)]
pub const DEFAULT_REMOTE_RETENTION: i32 = 14;

// ── Recovery key (age X25519) ───────────────────────────────────────────────

/// A freshly generated recovery key. `identity_file` is the only copy of the
/// secret: it is returned to the operator once and dropped (zeroized).
pub struct GeneratedKey {
    pub public_key: String,
    pub fingerprint: String,
    pub identity_file: Zeroizing<String>,
}

/// Generate an identity, in the format `age-keygen` writes (so `age -d -i
/// <file>` opens the archives without the panel).
pub fn generate_recovery_key(now: DateTime<Utc>) -> GeneratedKey {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret = identity.to_string();
    let identity_file = Zeroizing::new(format!(
        "# created: {}\n# public key: {public_key}\n{}\n",
        now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        secret.expose_secret()
    ));
    GeneratedKey { fingerprint: fingerprint(&public_key), public_key, identity_file }
}

/// `sha256:` + hex SHA-256 of the recipient string (`age1...`). Identifies a
/// key in logs, rows and manifests without revealing anything.
pub fn fingerprint(public_key: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(public_key.trim().as_bytes())))
}

/// Encrypt `input` to the recipient `public_key`, streaming (64 KiB chunks,
/// each authenticated). Returns the output writer once the age stream is
/// finished.
pub fn encrypt_stream<R: Read, W: Write>(public_key: &str, mut input: R, output: W) -> Result<W, String> {
    let recipient: age::x25519::Recipient =
        public_key.trim().parse().map_err(|e| format!("invalid age recipient: {e}"))?;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| format!("age encryptor: {e}"))?;
    let mut writer = encryptor.wrap_output(output).map_err(|e| format!("age header: {e}"))?;
    std::io::copy(&mut input, &mut writer).map_err(|e| format!("encrypting: {e}"))?;
    writer.finish().map_err(|e| format!("finishing the age stream: {e}"))
}

/// Parse an identity file (the text [`generate_recovery_key`] returned): the
/// first `AGE-SECRET-KEY-1` line, comments ignored. The error never quotes it.
#[allow(dead_code)] // the restore (step 2.5) and the tests
pub fn parse_identity(identity_file: &str) -> Result<age::x25519::Identity, String> {
    let line = identity_file
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .ok_or_else(|| "no AGE-SECRET-KEY line in the recovery key".to_string())?;
    line.parse::<age::x25519::Identity>()
        .map_err(|_| "the recovery key is not a valid age X25519 identity".to_string())
}

/// Decrypt an age stream with an identity file, streaming. A wrong key, a
/// tampered or truncated stream is an error (a truncation surfaces at the end
/// of the stream, so the caller must treat the output as void on `Err`).
/// Used by the tests here and by the restore (step 2.5).
#[allow(dead_code)] // the restore (step 2.5) and the tests
pub fn decrypt_stream<R: Read, W: Write>(identity_file: &str, input: R, mut output: W) -> Result<u64, String> {
    let identity = parse_identity(identity_file)?;
    let decryptor = age::Decryptor::new(input).map_err(|e| format!("not an age file: {e}"))?;
    if decryptor.is_scrypt() {
        return Err("the archive is passphrase-encrypted, not encrypted to a recovery key".into());
    }
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| format!("cannot decrypt with this recovery key: {e}"))?;
    std::io::copy(&mut reader, &mut output).map_err(|e| format!("decrypting: {e}"))
}

// ── Names, remote layout, retention ─────────────────────────────────────────

/// `cyberhunter-dr-{install_id}-`: every archive and manifest of this
/// installation, and nothing else, starts with it.
pub fn name_prefix(install_id: Uuid) -> String {
    format!("cyberhunter-dr-{install_id}-")
}

fn stamp(at: &DateTime<Utc>) -> String {
    at.format("%Y%m%d-%H%M%S").to_string()
}

pub fn archive_name(install_id: Uuid, at: &DateTime<Utc>) -> String {
    format!("{}{}.tar.gz.age", name_prefix(install_id), stamp(at))
}

/// The manifest is named on the SAME stamp, not `<archive>.manifest.json`: the
/// agent's `stamp_only` prune requires exactly `<prefix><stamp><suffix>`.
pub fn manifest_name(install_id: Uuid, at: &DateTime<Utc>) -> String {
    format!("{}{}.manifest.json", name_prefix(install_id), stamp(at))
}

/// One prune per suffix: `/backups/prune` keeps the N newest per call, so the
/// archives and the manifests are counted separately.
pub fn dr_prune_specs(install_id: Uuid) -> [PruneSpec; 2] {
    [
        PruneSpec { name_prefix: name_prefix(install_id), suffixes: vec![".tar.gz.age".into()] },
        PruneSpec { name_prefix: name_prefix(install_id), suffixes: vec![".manifest.json".into()] },
    ]
}

/// `cyberhunter-dr/<install_id>`, relative to the destination's base.
pub fn remote_subdir(install_id: Uuid) -> String {
    format!("{DR_REMOTE_DIR}/{install_id}")
}

/// The agent payload of a destination, re-based on
/// `<base>/cyberhunter-dr/<install_id>`.
///
/// The agent writes `<path_prefix>/<file name>` (S3) and
/// `<remote_path>/<file name>` (SFTP, default `/backups`, every missing
/// ancestor created) and lists, downloads and prunes under the same base. So
/// extending that one field puts the upload, the listing and the prune in the
/// sub-directory, with no agent change.
pub fn dr_destination_payload(payload: &serde_json::Value, install_id: Uuid) -> serde_json::Value {
    let mut out = payload.clone();
    let sub = remote_subdir(install_id);
    let dtype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(obj) = out.as_object_mut() {
        match dtype {
            "s3" => {
                let base = payload.get("path_prefix").and_then(|v| v.as_str()).unwrap_or("").trim_matches('/');
                let p = if base.is_empty() { sub } else { format!("{base}/{sub}") };
                obj.insert("path_prefix".into(), serde_json::Value::String(p));
            }
            "sftp" => {
                let base = payload.get("remote_path").and_then(|v| v.as_str()).unwrap_or("/backups");
                let base = base.trim_end_matches('/');
                obj.insert("remote_path".into(), serde_json::Value::String(format!("{base}/{sub}")));
            }
            _ => {}
        }
    }
    out
}

// ── Manifest and archive metadata ───────────────────────────────────────────

/// The plaintext manifest sent next to each archive. Lists what a restore
/// needs to choose and check an archive BEFORE decrypting it, and nothing
/// secret: no key, no path on this server, no operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DrManifest {
    pub format: u32,
    pub kind: String,
    pub install_id: Uuid,
    pub from_version: String,
    pub arch: String,
    pub created_at: String,
    pub snapshot_id: Uuid,
    /// File name of the `.tar.gz.age` this manifest describes.
    pub archive: String,
    /// Size of the `.tar.gz.age`.
    pub size_bytes: u64,
    /// SHA-256 of the `.tar.gz.age` (the ciphertext).
    pub sha256: String,
    pub recipient_fingerprint: String,
}

/// The keys the manifest has, exactly. Pinned by a test.
#[allow(dead_code)] // pinned by a test; the restore checks manifests against it
pub const MANIFEST_KEYS: &[&str] = &[
    "arch",
    "archive",
    "created_at",
    "format",
    "from_version",
    "install_id",
    "kind",
    "recipient_fingerprint",
    "sha256",
    "size_bytes",
    "snapshot_id",
];

/// Merge the DR fields into the snapshot's own `metadata.json` (kept
/// one key per line: `restore-snapshot.sh` reads it with sed).
pub fn enrich_metadata(existing: &str, install_id: Uuid, arch: &str) -> Result<String, String> {
    let mut v: serde_json::Value =
        serde_json::from_str(existing).map_err(|e| format!("snapshot metadata.json is not JSON: {e}"))?;
    let obj = v.as_object_mut().ok_or("snapshot metadata.json is not an object")?;
    obj.insert("kind".into(), "dr".into());
    obj.insert("format".into(), DR_FORMAT.into());
    obj.insert("install_id".into(), install_id.to_string().into());
    obj.insert("arch".into(), arch.into());
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

// ── Archive build (blocking) ────────────────────────────────────────────────

/// SHA-256 and byte count of what goes through it.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Create `path` 0600, refusing an existing file or symlink.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// `tar -czf - .` of `staging`, encrypted to `public_key` into `out` (created
/// 0600 under a `.part` name, renamed when complete). Returns (size, sha256)
/// of the ciphertext.
pub fn encrypt_dir_to(staging: &Path, public_key: &str, out: &Path) -> Result<(u64, String), String> {
    let part = out.with_file_name(format!(
        ".{}.part",
        out.file_name().and_then(|n| n.to_str()).unwrap_or("archive")
    ));
    let _ = std::fs::remove_file(&part);
    let result = (|| {
        let file = create_private(&part).map_err(|e| format!("cannot create {}: {e}", part.display()))?;
        let sink = HashingWriter { inner: std::io::BufWriter::new(file), hasher: Sha256::new(), written: 0 };

        let mut child = std::process::Command::new("tar")
            .arg("-C")
            .arg(staging)
            .args(["-czf", "-", "."])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start tar: {e}"))?;
        let stdout = child.stdout.take().ok_or("tar has no stdout")?;
        let encrypted = encrypt_stream(public_key, stdout, sink);
        let status = child.wait().map_err(|e| format!("tar: {e}"))?;
        let mut sink = encrypted?;
        if !status.success() {
            return Err(format!("tar exited with {status}: the archive is incomplete"));
        }
        sink.flush().map_err(|e| format!("writing the archive: {e}"))?;
        let HashingWriter { inner, hasher, written } = sink;
        let file = inner.into_inner().map_err(|e| format!("writing the archive: {e}"))?;
        file.sync_all().map_err(|e| format!("syncing the archive: {e}"))?;
        Ok((written, hex::encode(hasher.finalize())))
    })();
    match result {
        Ok(r) => {
            std::fs::rename(&part, out).map_err(|e| format!("cannot rename the archive: {e}"))?;
            Ok(r)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Unpack a local snapshot into `staging` without `binaries/` and `frontend/`,
/// enrich its metadata, and encrypt it to `out`.
pub fn build_dr_archive(
    snapshot: &Path,
    staging: &Path,
    install_id: Uuid,
    public_key: &str,
    out: &Path,
) -> Result<(u64, String), String> {
    let _ = std::fs::remove_dir_all(staging);
    make_private_dir(staging).map_err(|e| format!("cannot create {}: {e}", staging.display()))?;
    let result = (|| {
        let status = std::process::Command::new("tar")
            .arg("-C")
            .arg(staging)
            .arg("-xzf")
            .arg(snapshot)
            // Anchored: only the top-level trees. Unanchored, `frontend` would
            // also drop any `etc/.../frontend` and the archive would lose files.
            .args(["--anchored", "--exclude=./binaries", "--exclude=./frontend"])
            .status()
            .map_err(|e| format!("cannot start tar: {e}"))?;
        if !status.success() {
            return Err(format!("unpacking the snapshot failed: tar exited with {status}"));
        }
        if !staging.join("db").join("dump.sql.gz").is_file() {
            return Err("the snapshot has no db/dump.sql.gz".into());
        }
        let meta_path = staging.join("metadata.json");
        let existing = std::fs::read_to_string(&meta_path).map_err(|e| format!("snapshot metadata.json: {e}"))?;
        let enriched = enrich_metadata(&existing, install_id, std::env::consts::ARCH)?;
        std::fs::write(&meta_path, enriched).map_err(|e| format!("writing metadata.json: {e}"))?;
        encrypt_dir_to(staging, public_key, out)
    })();
    let _ = std::fs::remove_dir_all(staging);
    result
}

/// Empty the outbox (and create it 0700). Called at the start and the end of
/// every run, so nothing waits there between runs.
pub fn purge_outbox(dir: &Path) -> Result<u32, String> {
    make_private_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut removed = 0;
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        let r = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        r.map_err(|e| format!("cannot remove {}: {e}", p.display()))?;
        removed += 1;
    }
    Ok(removed)
}

// ── Decryption to a file (restore, step 2.5) ────────────────────────────────

/// SHA-256 and byte count of what is read through it.
struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    read: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.read += n as u64;
        Ok(n)
    }
}

/// What [`decrypt_file_to`] produced.
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedFile {
    /// Size and SHA-256 of the ciphertext that was read (to compare with the manifest).
    pub cipher_size: u64,
    pub cipher_sha256: String,
    /// Size and SHA-256 of the plaintext `.tar.gz` that was written.
    pub size: u64,
    pub sha256: String,
}

/// Decrypt the age file `input` into `out`, streaming: created 0600 under a
/// hidden `.part` name, renamed only once the age stream has authenticated to
/// its end. Both sides are hashed on the way. On any error the partial output
/// is removed and nothing is left at `out`.
pub fn decrypt_file_to(identity_file: &str, input: &Path, out: &Path) -> Result<DecryptedFile, String> {
    let part = out.with_file_name(format!(
        ".{}.part",
        out.file_name().and_then(|n| n.to_str()).unwrap_or("restore")
    ));
    let _ = std::fs::remove_file(&part);
    let result = (|| {
        let file = std::fs::File::open(input).map_err(|e| format!("cannot open {}: {e}", input.display()))?;
        let mut reader = HashingReader { inner: std::io::BufReader::new(file), hasher: Sha256::new(), read: 0 };
        let file = create_private(&part).map_err(|e| format!("cannot create {}: {e}", part.display()))?;
        let mut sink = HashingWriter { inner: std::io::BufWriter::new(file), hasher: Sha256::new(), written: 0 };
        decrypt_stream(identity_file, &mut reader, &mut sink)?;
        // Anything after the last authenticated chunk still counts in the
        // ciphertext hash, so it cannot pass the manifest check unnoticed.
        std::io::copy(&mut reader, &mut std::io::sink()).map_err(|e| format!("reading the archive: {e}"))?;
        sink.flush().map_err(|e| format!("writing the decrypted archive: {e}"))?;
        let HashingWriter { inner, hasher, written } = sink;
        let file = inner.into_inner().map_err(|e| format!("writing the decrypted archive: {e}"))?;
        file.sync_all().map_err(|e| format!("syncing the decrypted archive: {e}"))?;
        Ok(DecryptedFile {
            cipher_size: reader.read,
            cipher_sha256: hex::encode(reader.hasher.finalize()),
            size: written,
            sha256: hex::encode(hasher.finalize()),
        })
    })();
    match result {
        Ok(r) => {
            std::fs::rename(&part, out).map_err(|e| {
                let _ = std::fs::remove_file(&part);
                format!("cannot rename the decrypted archive: {e}")
            })?;
            Ok(r)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

// ── SFTP keys into /etc/dockpanel/backup-keys ───────────────────────────────

/// One SFTP key to copy so the snapshot carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyCopy {
    pub destination_id: Uuid,
    pub destination_name: String,
    pub source: String,
    pub target: PathBuf,
}

/// The SFTP destinations whose `key_path` is outside `/etc/dockpanel`. A
/// relative path or one with `..` is skipped (and reported by the caller).
pub fn key_copy_plan(destinations: &[(Uuid, String, String, serde_json::Value)], keys_dir: &Path) -> (Vec<KeyCopy>, Vec<String>) {
    let mut plan = Vec::new();
    let mut skipped = Vec::new();
    for (id, name, dtype, config) in destinations {
        if dtype != "sftp" {
            continue;
        }
        let Some(key) = config.get("key_path").and_then(|v| v.as_str()).map(str::trim).filter(|k| !k.is_empty()) else {
            continue;
        };
        if key.starts_with("/etc/dockpanel/") {
            continue;
        }
        if !key.starts_with('/') || key.split('/').any(|s| s == "..") {
            skipped.push(format!("destination '{name}': key_path is not a plain absolute path, not copied"));
            continue;
        }
        plan.push(KeyCopy {
            destination_id: *id,
            destination_name: name.clone(),
            source: key.to_string(),
            target: keys_dir.join(format!("{id}.key")),
        });
    }
    (plan, skipped)
}

/// Copy one key 0600 to its target. A key under /root or /home is invisible
/// to the API (`ProtectHome=yes`): it is then copied by a transient unit of
/// PID 1 (`install`), with only the two paths on its command line.
async fn copy_key(k: &KeyCopy) -> Result<(), String> {
    let tmp = k.target.with_extension("key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let direct = (|| -> std::io::Result<()> {
        let bytes = Zeroizing::new(std::fs::read(&k.source)?);
        let mut f = create_private(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    if let Err(e) = direct {
        let _ = std::fs::remove_file(&tmp);
        let hidden = ["/root/", "/home/", "/run/user/"].iter().any(|p| k.source.starts_with(p));
        if !hidden {
            return Err(format!("cannot read {}: {e}", k.source));
        }
        let status = tokio::process::Command::new("systemd-run")
            .args(["--quiet", "--wait", "--collect", "--service-type=exec"])
            .arg(format!("--unit=dockpanel-dr-keycopy-{}", Uuid::new_v4()))
            .args(["install", "-m", "0600", "-o", "root", "-g", "root", "-T", "--"])
            .arg(&k.source)
            .arg(&tmp)
            .status()
            .await
            .map_err(|e| format!("cannot start systemd-run: {e}"))?;
        if !status.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("cannot copy {}: install exited with {status}", k.source));
        }
    }
    std::fs::rename(&tmp, &k.target).map_err(|e| format!("cannot place {}: {e}", k.target.display()))
}

/// Copy every planned key, write `index.json` (which destination, which
/// original path: the restore puts them back), drop copies of keys no longer
/// planned. Returns the warnings; nothing here stops the run.
async fn sync_backup_keys(db: &PgPool) -> Vec<String> {
    let keys_dir = Path::new(BACKUP_KEYS_DIR);
    let rows: Vec<(Uuid, String, String, serde_json::Value)> =
        match sqlx::query_as("SELECT id, name, dtype, config FROM backup_destinations").fetch_all(db).await {
            Ok(r) => r,
            Err(e) => return vec![format!("could not list destinations to copy SFTP keys: {e}")],
        };
    let (plan, mut warnings) = key_copy_plan(&rows, keys_dir);
    if plan.is_empty() && !keys_dir.exists() {
        return warnings;
    }
    if let Err(e) = make_private_dir(keys_dir) {
        warnings.push(format!("cannot create {BACKUP_KEYS_DIR}: {e}"));
        return warnings;
    }
    let mut index = Vec::new();
    for k in &plan {
        match copy_key(k).await {
            Ok(()) => index.push(serde_json::json!({
                "destination_id": k.destination_id,
                "destination_name": k.destination_name,
                "original_key_path": k.source,
                "file": k.target.file_name().and_then(|n| n.to_str()).unwrap_or_default(),
            })),
            Err(e) => warnings.push(format!("SFTP key of destination '{}' not copied: {e}", k.destination_name)),
        }
    }
    let keep: Vec<PathBuf> = plan.iter().map(|k| k.target.clone()).collect();
    if let Ok(rd) = std::fs::read_dir(keys_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "key") && !keep.contains(&p) {
                if let Err(err) = std::fs::remove_file(&p) {
                    warnings.push(format!("cannot remove stale key copy {}: {err}", p.display()));
                }
            }
        }
    }
    let index_path = keys_dir.join("index.json");
    let tmp = keys_dir.join(".index.json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let written = create_private(&tmp)
        .and_then(|mut f| f.write_all(serde_json::to_string_pretty(&index).unwrap_or_default().as_bytes()))
        .and_then(|_| std::fs::rename(&tmp, &index_path));
    if let Err(e) = written {
        warnings.push(format!("cannot write {}: {e}", index_path.display()));
    }
    warnings
}

// ── Schedule and alert ──────────────────────────────────────────────────────

/// Whether the off-site copy is overdue: enabled, and neither a successful
/// upload nor the moment it was enabled is within [`STALE_AFTER_HOURS`] (so
/// turning it on does not alert before the first run had a chance).
pub fn offsite_stale(
    enabled: bool,
    enabled_at: Option<DateTime<Utc>>,
    last_success: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if !enabled {
        return false;
    }
    let reference = match (enabled_at, last_success) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return true,
    };
    now - reference > chrono::Duration::hours(STALE_AFTER_HOURS)
}

/// Whether the scheduler starts a run now: enabled, the cron matches this
/// minute, and the last run did not start within the last 90 seconds.
pub fn schedule_due(enabled: bool, schedule: &str, last_run_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    enabled
        && bpe::cron_matches_now(schedule, &now)
        && last_run_at.is_none_or(|t| (now - t).num_seconds() >= 90)
}

/// A schedule the scheduler can run: exactly 5 valid fields, each value within
/// its field's range (minute 0-59, hour 0-23, day 1-31, month 1-12, weekday
/// 0-7). A value out of range would be accepted by a format check and then
/// never fire, which shows up only as the 48 h overdue alert.
pub fn valid_schedule(s: &str) -> bool {
    const BOUNDS: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];
    let fields: Vec<&str> = s.split_whitespace().collect();
    fields.len() == 5
        && crate::routes::git_deploys::is_valid_cron(s)
        && fields.iter().zip(BOUNDS).all(|(f, b)| cron_field_in_bounds(f, b))
}

fn cron_field_in_bounds(field: &str, (lo, hi): (u32, u32)) -> bool {
    let within = |v: &str| v.parse::<u32>().is_ok_and(|n| n >= lo && n <= hi);
    field.split(',').filter(|p| !p.is_empty()).all(|part| {
        if part == "*" {
            true
        } else if let Some(step) = part.strip_prefix("*/") {
            step.parse::<u32>().is_ok_and(|n| n >= 1 && n <= hi.max(1))
        } else if let Some((a, b)) = part.split_once('-') {
            within(a) && within(b) && a.parse::<u32>().ok() <= b.parse::<u32>().ok()
        } else {
            within(part)
        }
    })
}

// ── Database rows ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DrSettings {
    pub enabled: bool,
    pub schedule: String,
    pub destination_ids: Vec<Uuid>,
    pub remote_retention: i32,
    #[serde(skip)]
    #[allow(dead_code)]
    pub active_recipient_id: Option<Uuid>,
    pub enabled_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    #[serde(skip)]
    pub last_alert_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DrRecipient {
    pub id: Uuid,
    pub public_key: String,
    pub fingerprint: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DrRemoteSnapshot {
    pub id: Uuid,
    pub snapshot_id: Option<Uuid>,
    pub destination_id: Option<Uuid>,
    pub destination_name: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub remote_key: Option<String>,
    pub filename: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub recipient_fingerprint: String,
    pub from_version: String,
    pub created_at: DateTime<Utc>,
    pub uploaded_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct EligibleDestination {
    pub id: Uuid,
    pub name: String,
    pub dtype: String,
}

const SETTINGS_COLS: &str = "enabled, schedule, destination_ids, remote_retention, active_recipient_id, \
     enabled_at, last_run_at, last_status, last_error, last_alert_at, updated_at";

pub async fn load_settings(db: &PgPool) -> Result<DrSettings, sqlx::Error> {
    // The migration inserts the row; recreate it if someone deleted it.
    sqlx::query("INSERT INTO dr_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING").execute(db).await?;
    sqlx::query_as(&format!("SELECT {SETTINGS_COLS} FROM dr_settings WHERE id = 1")).fetch_one(db).await
}

pub async fn active_recipient(db: &PgPool) -> Result<Option<DrRecipient>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.id, r.public_key, r.fingerprint, r.created_by, r.created_at, r.retired_at \
         FROM dr_settings s JOIN dr_recipients r ON r.id = s.active_recipient_id \
         WHERE s.id = 1 AND r.retired_at IS NULL",
    )
    .fetch_optional(db)
    .await
}

/// The id of the local server row: this installation's `install_id`.
pub async fn install_id(db: &PgPool) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM servers WHERE is_local = TRUE LIMIT 1").fetch_optional(db).await
}

/// Destinations the local agent may send to: unbound, or bound to this server.
pub async fn eligible_destinations(db: &PgPool) -> Result<Vec<EligibleDestination>, sqlx::Error> {
    sqlx::query_as(
        "SELECT bd.id, bd.name, bd.dtype FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id \
         WHERE bd.server_id IS NULL OR s.is_local ORDER BY bd.name",
    )
    .fetch_all(db)
    .await
}

pub async fn last_success_at(db: &PgPool) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    sqlx::query_scalar("SELECT MAX(uploaded_at) FROM dr_remote_snapshots WHERE status = 'uploaded'")
        .fetch_one(db)
        .await
}

/// Everything the "Disaster recovery" card shows. Never the identity.
#[derive(Debug, Serialize)]
pub struct DrStatus {
    pub install_id: Option<Uuid>,
    pub settings: DrSettings,
    pub recipient: Option<DrRecipient>,
    pub retired_recipients: Vec<DrRecipient>,
    pub destinations: Vec<EligibleDestination>,
    pub remote_snapshots: Vec<DrRemoteSnapshot>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub stale: bool,
    pub running: bool,
}

pub async fn load_status(db: &PgPool) -> Result<DrStatus, sqlx::Error> {
    let settings = load_settings(db).await?;
    let recipient = active_recipient(db).await?;
    let retired_recipients = sqlx::query_as(
        "SELECT id, public_key, fingerprint, created_by, created_at, retired_at FROM dr_recipients \
         WHERE retired_at IS NOT NULL ORDER BY retired_at DESC LIMIT 20",
    )
    .fetch_all(db)
    .await?;
    let remote_snapshots = sqlx::query_as(
        "SELECT r.id, r.snapshot_id, r.destination_id, d.name AS destination_name, r.status, r.error, r.remote_key, \
                r.filename, r.size_bytes, r.sha256, r.recipient_fingerprint, r.from_version, r.created_at, \
                r.uploaded_at, r.deleted_at \
         FROM dr_remote_snapshots r LEFT JOIN backup_destinations d ON d.id = r.destination_id \
         ORDER BY r.created_at DESC LIMIT 50",
    )
    .fetch_all(db)
    .await?;
    let last_success_at = last_success_at(db).await?;
    let stale = offsite_stale(settings.enabled, settings.enabled_at, last_success_at, Utc::now());
    Ok(DrStatus {
        install_id: install_id(db).await?,
        settings,
        recipient,
        retired_recipients,
        destinations: eligible_destinations(db).await?,
        remote_snapshots,
        last_success_at,
        stale,
        running: is_running(),
    })
}

/// Store a new recipient and make it the active one, retiring the previous
/// one, in one transaction. `rotate = false` refuses when one is active.
pub async fn enroll_recipient(
    db: &PgPool,
    public_key: &str,
    fingerprint: &str,
    created_by: &str,
    rotate: bool,
) -> Result<(DrRecipient, Option<String>), EnrollError> {
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO dr_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING").execute(&mut *tx).await?;
    // Serialize concurrent enrolments on the settings row.
    sqlx::query("SELECT id FROM dr_settings WHERE id = 1 FOR UPDATE").execute(&mut *tx).await?;
    let previous: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, fingerprint FROM dr_recipients WHERE retired_at IS NULL LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    match (&previous, rotate) {
        (Some(_), false) => return Err(EnrollError::AlreadyEnrolled),
        (None, true) => return Err(EnrollError::NothingToRotate),
        _ => {}
    }
    if let Some((id, _)) = &previous {
        sqlx::query("UPDATE dr_recipients SET retired_at = NOW() WHERE id = $1").bind(id).execute(&mut *tx).await?;
    }
    let row: DrRecipient = sqlx::query_as(
        "INSERT INTO dr_recipients (public_key, fingerprint, created_by) VALUES ($1, $2, $3) \
         RETURNING id, public_key, fingerprint, created_by, created_at, retired_at",
    )
    .bind(public_key)
    .bind(fingerprint)
    .bind(created_by)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE dr_settings SET active_recipient_id = $1, updated_at = NOW() WHERE id = 1")
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((row, previous.map(|(_, f)| f)))
}

#[derive(Debug)]
pub enum EnrollError {
    AlreadyEnrolled,
    NothingToRotate,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for EnrollError {
    fn from(e: sqlx::Error) -> Self {
        EnrollError::Db(e)
    }
}

// ── The run ─────────────────────────────────────────────────────────────────

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Held for the duration of a run; scheduler and "Run now" share it.
pub struct RunGuard(());

impl RunGuard {
    pub fn acquire() -> Option<RunGuard> {
        RUNNING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| RunGuard(()))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Why a configuration cannot run, or `None` when it can.
pub fn not_runnable_reason(settings: &DrSettings, recipient: Option<&DrRecipient>) -> Option<&'static str> {
    if recipient.is_none() {
        return Some("Set up a recovery key first");
    }
    if settings.destination_ids.is_empty() {
        return Some("Choose at least one destination");
    }
    None
}

/// The final status of a run from its per-destination results and warnings.
pub fn run_status(uploaded: usize, failed: usize, warnings: usize) -> &'static str {
    match (uploaded, failed, warnings) {
        (0, _, _) => "failed",
        (_, 0, 0) => "success",
        _ => "partial",
    }
}

async fn finish_run(db: &PgPool, status: &str, messages: &[String]) {
    let mut error = messages.join("; ");
    if error.len() > 4000 {
        let mut cut = 4000;
        while !error.is_char_boundary(cut) {
            cut -= 1;
        }
        error.truncate(cut);
    }
    let error = if error.is_empty() { None } else { Some(error) };
    if let Err(e) = sqlx::query("UPDATE dr_settings SET last_status = $1, last_error = $2 WHERE id = 1")
        .bind(status)
        .bind(&error)
        .execute(db)
        .await
    {
        tracing::error!("Off-site snapshot: could not record the run status: {e}");
    }
    match status {
        "success" => tracing::info!("Off-site snapshot run finished: success"),
        _ => {
            tracing::warn!("Off-site snapshot run finished: {status}: {}", error.as_deref().unwrap_or(""));
            if status == "failed" {
                notifications::notify_panel(
                    db,
                    None,
                    "Off-site panel snapshot failed",
                    error.as_deref().unwrap_or("The off-site panel snapshot failed"),
                    "warning",
                    "backup",
                    Some("/telemetry?tab=updates#disaster-recovery"),
                )
                .await;
            }
        }
    }
}

/// Upload with the retry ladder of the backup executor (5s / 15s / 30s).
async fn upload_with_retries(agents: &AgentRegistry, payload: &serde_json::Value, filepath: &str) -> Result<(), String> {
    let body = serde_json::json!({ "filepath": filepath, "destination": payload });
    let delays = [5u64, 15, 30];
    let mut last = String::new();
    for (attempt, delay) in delays.iter().enumerate() {
        match agents.local().post_long("/backups/upload", Some(body.clone()), 660).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                last = e.to_string();
                if attempt < delays.len() - 1 {
                    tracing::warn!("Off-site snapshot upload attempt {} failed: {last} - retrying in {delay}s", attempt + 1);
                    tokio::time::sleep(std::time::Duration::from_secs(*delay)).await;
                }
            }
        }
    }
    Err(format!("upload failed after {} attempts: {last}", delays.len()))
}

/// The key the agent lists for `filename` under the DR base, which proves the
/// object is there and is what `/backups/download` takes back.
async fn remote_key_of(agents: &AgentRegistry, payload: &serde_json::Value, filename: &str) -> Result<String, String> {
    let resp = agents
        .local()
        .post_long("/backups/list", Some(serde_json::json!({ "destination": payload, "prefix": filename })), 300)
        .await
        .map_err(|e| format!("listing after upload failed: {e}"))?;
    resp.get("objects")
        .and_then(|o| o.as_array())
        .and_then(|objs| {
            objs.iter()
                .find(|o| o.get("name").and_then(|n| n.as_str()) == Some(filename))
                .and_then(|o| o.get("key").and_then(|k| k.as_str()).map(str::to_string))
        })
        .ok_or_else(|| format!("{filename} is not listed at the destination after its upload"))
}


/// What a run built, ready to ship.
struct Built {
    install_id: Uuid,
    settings: DrSettings,
    recipient_fingerprint: String,
    snapshot_id: Uuid,
    from_version: String,
    archive_name: String,
    archive_path: PathBuf,
    manifest_path: PathBuf,
    size_bytes: u64,
    sha256: String,
}

/// Run one off-site snapshot. The caller holds the [`RunGuard`].
pub async fn run_once(db: &PgPool, agents: &AgentRegistry, operator: Option<String>, _guard: &RunGuard) {
    if let Err(e) = sqlx::query(
        "UPDATE dr_settings SET last_run_at = NOW(), last_status = 'running', last_error = NULL WHERE id = 1",
    )
    .execute(db)
    .await
    {
        tracing::error!("Off-site snapshot: could not stamp the run start: {e}");
    }

    let outbox = Path::new(DR_OUTBOX);
    // A crashed run can leave plaintext staging behind: sweep it first.
    if let Err(e) = purge_outbox(Path::new(DR_STAGING_PARENT)) {
        finish_run(db, "failed", &[format!("cannot sweep the staging directory: {e}")]).await;
        return;
    }
    if let Err(e) = purge_outbox(outbox) {
        finish_run(db, "failed", &[format!("cannot prepare the outbox: {e}")]).await;
        return;
    }

    let mut messages: Vec<String> = Vec::new();
    let built = match prepare(db, operator, &mut messages).await {
        Ok(b) => b,
        Err(e) => {
            messages.push(e);
            if let Err(e) = purge_outbox(outbox) {
                messages.push(format!("outbox not emptied: {e}"));
            }
            finish_run(db, "failed", &messages).await;
            return;
        }
    };
    let (uploaded, failed) = ship(db, agents, &built, &mut messages).await;
    if let Err(e) = purge_outbox(outbox) {
        messages.push(format!("outbox not emptied: {e}"));
    }
    let warnings = messages.len().saturating_sub(failed);
    finish_run(db, run_status(uploaded, failed, warnings), &messages).await;
}

async fn prepare(db: &PgPool, operator: Option<String>, messages: &mut Vec<String>) -> Result<Built, String> {
    let settings = load_settings(db).await.map_err(|e| format!("cannot read the settings: {e}"))?;
    let recipient = active_recipient(db).await.map_err(|e| format!("cannot read the recovery key: {e}"))?;
    if let Some(reason) = not_runnable_reason(&settings, recipient.as_ref()) {
        return Err(reason.to_string());
    }
    let Some(recipient) = recipient else { return Err("Set up a recovery key first".into()) };
    let install_id = install_id(db)
        .await
        .map_err(|e| format!("cannot read the local server: {e}"))?
        .ok_or("no local server row (is_local): install_id unknown")?;

    // Before the snapshot, so /etc/dockpanel already holds the copies.
    messages.extend(sync_backup_keys(db).await);

    let meta = panel_snapshot::create_snapshot(db, SnapshotTrigger::Scheduled, operator)
        .await
        .map_err(|e| format!("panel snapshot failed: {e}"))?;

    let now = Utc::now();
    let archive_name = archive_name(install_id, &now);
    let archive_path = Path::new(DR_OUTBOX).join(&archive_name);
    make_private_dir(Path::new(DR_STAGING_PARENT)).map_err(|e| format!("cannot create {DR_STAGING_PARENT}: {e}"))?;
    let staging = Path::new(DR_STAGING_PARENT).join(meta.id.to_string());
    let (snapshot_path, pk, out) = (meta.file_path.clone(), recipient.public_key.clone(), archive_path.clone());
    let (size_bytes, sha256) =
        tokio::task::spawn_blocking(move || build_dr_archive(&snapshot_path, &staging, install_id, &pk, &out))
            .await
            .map_err(|e| format!("archive task failed: {e}"))??;

    let manifest = DrManifest {
        format: DR_FORMAT,
        kind: "dr".into(),
        install_id,
        from_version: meta.from_version.clone(),
        arch: std::env::consts::ARCH.into(),
        created_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        snapshot_id: meta.id,
        archive: archive_name.clone(),
        size_bytes,
        sha256: sha256.clone(),
        recipient_fingerprint: recipient.fingerprint.clone(),
    };
    let manifest_path = Path::new(DR_OUTBOX).join(manifest_name(install_id, &now));
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    create_private(&manifest_path)
        .and_then(|mut f| f.write_all(&json).and_then(|_| f.sync_all()))
        .map_err(|e| format!("cannot write the manifest: {e}"))?;

    tracing::info!(
        "Off-site snapshot archive {archive_name} built ({size_bytes} bytes, sha256 {}, recipient {})",
        &sha256[..16.min(sha256.len())],
        recipient.fingerprint
    );
    Ok(Built {
        install_id,
        settings,
        recipient_fingerprint: recipient.fingerprint,
        snapshot_id: meta.id,
        from_version: meta.from_version,
        archive_name,
        archive_path,
        manifest_path,
        size_bytes,
        sha256,
    })
}

async fn record_remote(db: &PgPool, b: &Built, destination_id: Option<Uuid>, outcome: Result<&str, &str>) {
    let (status, key, error) = match outcome {
        Ok(key) => ("uploaded", Some(key), None),
        Err(e) => ("failed", None, Some(e)),
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO dr_remote_snapshots \
           (snapshot_id, destination_id, status, error, remote_key, filename, size_bytes, sha256, \
            recipient_fingerprint, from_version, uploaded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $3 = 'uploaded' THEN NOW() END)",
    )
    .bind(b.snapshot_id)
    .bind(destination_id)
    .bind(status)
    .bind(error)
    .bind(key)
    .bind(&b.archive_name)
    .bind(b.size_bytes as i64)
    .bind(&b.sha256)
    .bind(&b.recipient_fingerprint)
    .bind(&b.from_version)
    .execute(db)
    .await
    {
        tracing::error!("Off-site snapshot: could not record the upload row: {e}");
    }
}

/// Send the archive and its manifest to every destination, then enforce the
/// remote retention. Returns (destinations uploaded, destinations failed).
async fn ship(db: &PgPool, agents: &AgentRegistry, b: &Built, messages: &mut Vec<String>) -> (usize, usize) {
    let (mut uploaded, mut failed) = (0, 0);
    let archive = b.archive_path.to_string_lossy().to_string();
    let manifest = b.manifest_path.to_string_lossy().to_string();
    for dest_id in &b.settings.destination_ids {
        let row: Result<Option<(String, String, serde_json::Value)>, _> = sqlx::query_as(
            "SELECT bd.name, bd.dtype, bd.config FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id \
             WHERE bd.id = $1 AND (bd.server_id IS NULL OR s.is_local)",
        )
        .bind(dest_id)
        .fetch_optional(db)
        .await;
        let (name, dtype, config) = match row {
            Ok(Some(r)) => r,
            Ok(None) => {
                let e = format!("destination {dest_id} no longer exists or is not reachable from this server");
                record_remote(db, b, None, Err(&e)).await;
                messages.push(e);
                failed += 1;
                continue;
            }
            Err(e) => {
                let e = format!("cannot read destination {dest_id}: {e}");
                record_remote(db, b, None, Err(&e)).await;
                messages.push(e);
                failed += 1;
                continue;
            }
        };
        let payload = dr_destination_payload(
            &crate::routes::backup_destinations::agent_destination_payload(&dtype, &config),
            b.install_id,
        );

        let sent = async {
            upload_with_retries(agents, &payload, &archive).await?;
            upload_with_retries(agents, &payload, &manifest).await.map_err(|e| format!("manifest: {e}"))?;
            remote_key_of(agents, &payload, &b.archive_name).await
        }
        .await;
        let key = match sent {
            Ok(k) => k,
            Err(e) => {
                let e = format!("destination '{name}': {e}");
                tracing::error!("Off-site snapshot: {e}");
                record_remote(db, b, Some(*dest_id), Err(&e)).await;
                messages.push(e);
                failed += 1;
                continue;
            }
        };
        record_remote(db, b, Some(*dest_id), Ok(&key)).await;
        uploaded += 1;
        tracing::info!("Off-site snapshot {} uploaded to '{name}' as {key}", b.archive_name);

        // Remote retention: one prune per suffix (the agent keeps N per call).
        let retention = b.settings.remote_retention.max(1);
        let mut pruned_ok = true;
        for spec in dr_prune_specs(b.install_id) {
            let body = bpe::prune_body(&payload, "", &spec, retention);
            let res = match agents.local().post_long("/backups/prune", Some(body), bpe::PRUNE_TIMEOUT_SECS).await {
                Ok(resp) => bpe::parse_prune_response(&resp),
                Err(e) => Err(format!("prune request failed: {e}")),
            };
            if let Err(e) = res {
                pruned_ok = false;
                messages.push(format!("destination '{name}': remote retention ({}): {e}", spec.suffixes.join(",")));
            }
        }
        if pruned_ok {
            if let Err(e) = sqlx::query(
                "UPDATE dr_remote_snapshots SET deleted_at = NOW() \
                 WHERE destination_id = $1 AND status = 'uploaded' AND deleted_at IS NULL \
                   AND id NOT IN (SELECT id FROM dr_remote_snapshots \
                                  WHERE destination_id = $1 AND status = 'uploaded' AND deleted_at IS NULL \
                                  ORDER BY uploaded_at DESC LIMIT $2)",
            )
            .bind(dest_id)
            .bind(retention as i64)
            .execute(db)
            .await
            {
                messages.push(format!("destination '{name}': could not record the pruned copies: {e}"));
            }
        }
    }
    (uploaded, failed)
}

// ── Scheduler ───────────────────────────────────────────────────────────────

/// Whether to (re)send the overdue alert: stale, and not alerted within
/// [`ALERT_REPEAT_HOURS`].
pub fn alert_due(stale: bool, last_alert_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    stale && last_alert_at.is_none_or(|t| now - t >= chrono::Duration::hours(ALERT_REPEAT_HOURS))
}

/// Background task: start the scheduled run, raise the 48 h alert.
pub async fn run(db: PgPool, agents: AgentRegistry, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Off-site panel snapshot scheduler started");
    // A run killed while building its archive leaves the decrypted snapshot in
    // the staging directory: remove it now rather than at the next run.
    match purge_outbox(Path::new(DR_STAGING_PARENT)) {
        Ok(0) => {}
        Ok(n) => tracing::warn!("Off-site snapshot: removed {n} leftover staging item(s) of an interrupted run"),
        Err(e) => tracing::error!("Off-site snapshot: cannot sweep the staging directory: {e}"),
    }
    // A restart during a run leaves `running` behind; no run survives a restart.
    if !is_running() {
        if let Err(e) = sqlx::query(
            "UPDATE dr_settings SET last_status = 'failed',              last_error = 'Interrupted: the panel restarted during the off-site snapshot'              WHERE id = 1 AND last_status = 'running'",
        )
        .execute(&db)
        .await
        {
            tracing::error!("Off-site snapshot: could not clear an interrupted run: {e}");
        }
    }
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => tick(&db, &agents).await,
            _ = shutdown_rx.recv() => {
                tracing::info!("Off-site panel snapshot scheduler shutting down");
                break;
            }
        }
    }
}

async fn tick(db: &PgPool, agents: &AgentRegistry) {
    let settings = match load_settings(db).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Off-site snapshot scheduler: cannot read the settings: {e}");
            return;
        }
    };
    let now = Utc::now();
    if schedule_due(settings.enabled, &settings.schedule, settings.last_run_at, now) {
        match RunGuard::acquire() {
            Some(guard) => {
                let (db, agents) = (db.clone(), agents.clone());
                tokio::spawn(async move {
                    run_once(&db, &agents, None, &guard).await;
                });
            }
            None => tracing::warn!("Off-site snapshot: scheduled run skipped, a run is already in progress"),
        }
    }

    let last_success = match last_success_at(db).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Off-site snapshot scheduler: cannot read the last upload: {e}");
            return;
        }
    };
    let stale = offsite_stale(settings.enabled, settings.enabled_at, last_success, now);
    if alert_due(stale, settings.last_alert_at, now) {
        notifications::notify_panel(
            db,
            None,
            "No off-site panel snapshot in the last 48 hours",
            "No off-site copy of the panel (database and /etc/dockpanel) reached a destination in the last 48 hours. \
             Check Disaster recovery on the Telemetry page.",
            "warning",
            "backup",
            Some("/telemetry?tab=updates#disaster-recovery"),
        )
        .await;
        tracing::warn!("Off-site snapshot: no successful off-site copy in the last {STALE_AFTER_HOURS} hours");
        if let Err(e) = sqlx::query("UPDATE dr_settings SET last_alert_at = NOW() WHERE id = 1").execute(db).await {
            tracing::error!("Off-site snapshot: could not record the alert: {e}");
        }
    } else if !stale && settings.last_alert_at.is_some() {
        if let Err(e) = sqlx::query("UPDATE dr_settings SET last_alert_at = NULL WHERE id = 1").execute(db).await {
            tracing::error!("Off-site snapshot: could not clear the alert: {e}");
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dp-dr-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Deterministic pseudo-random bytes (xorshift), so the stream does not
    /// compress and is not a run of zeros.
    struct Noise {
        state: u64,
        left: u64,
    }
    impl Read for Noise {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(self.left) as usize;
            for b in &mut buf[..n] {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                *b = self.state as u8;
            }
            self.left -= n as u64;
            Ok(n)
        }
    }

    struct HashSink(Sha256, u64);
    impl Write for HashSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            self.1 += buf.len() as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn encrypt_bytes(pk: &str, data: &[u8]) -> Vec<u8> {
        encrypt_stream(pk, data, Vec::new()).unwrap()
    }

    #[test]
    fn generated_key_is_an_age_identity_whose_public_half_is_stored() {
        let k = generate_recovery_key(Utc::now());
        assert!(k.public_key.starts_with("age1"));
        assert!(k.identity_file.starts_with("# created: "));
        assert!(k.identity_file.contains(&format!("# public key: {}\n", k.public_key)));
        let id = parse_identity(&k.identity_file).unwrap();
        assert_eq!(id.to_public().to_string(), k.public_key);
        assert_eq!(k.fingerprint, fingerprint(&k.public_key));
        // The stored half carries nothing of the secret.
        assert!(!k.public_key.contains("AGE-SECRET-KEY"));
        assert!(!k.fingerprint.contains("AGE-SECRET-KEY"));
    }

    #[test]
    fn fingerprint_is_stable_prefixed_sha256_of_the_recipient() {
        let fp = fingerprint("age1abc");
        assert_eq!(fp, fingerprint("  age1abc\n"));
        assert_eq!(fp, format!("sha256:{}", hex::encode(Sha256::digest(b"age1abc"))));
        assert_eq!(fp.len(), "sha256:".len() + 64);
        assert_ne!(fp, fingerprint("age1abd"));
    }

    #[test]
    fn a_large_file_round_trips_through_age_in_flux() {
        let dir = tmp("big");
        let plain = dir.join("plain.bin");
        let enc = dir.join("plain.bin.age");
        // 64 MiB plus an odd tail: over a thousand 64 KiB chunks, the last partial.
        let size = 64 * 1024 * 1024 + 12_345;
        {
            let mut f = std::fs::File::create(&plain).unwrap();
            std::io::copy(&mut Noise { state: 0x9e37_79b9_7f4a_7c15, left: size }, &mut f).unwrap();
        }
        let mut expected = HashSink(Sha256::new(), 0);
        std::io::copy(&mut std::fs::File::open(&plain).unwrap(), &mut expected).unwrap();

        let k = generate_recovery_key(Utc::now());
        let out = std::io::BufWriter::new(std::fs::File::create(&enc).unwrap());
        encrypt_stream(&k.public_key, std::fs::File::open(&plain).unwrap(), out).unwrap().flush().unwrap();
        assert!(std::fs::metadata(&enc).unwrap().len() > size);

        let mut got = HashSink(Sha256::new(), 0);
        let n = decrypt_stream(&k.identity_file, std::io::BufReader::new(std::fs::File::open(&enc).unwrap()), &mut got)
            .unwrap();
        assert_eq!(n, size);
        assert_eq!(got.1, size);
        assert_eq!(got.0.finalize(), expected.0.finalize());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_wrong_recovery_key_is_refused() {
        let right = generate_recovery_key(Utc::now());
        let wrong = generate_recovery_key(Utc::now());
        let ct = encrypt_bytes(&right.public_key, b"panel snapshot");
        let mut out = Vec::new();
        let e = decrypt_stream(&wrong.identity_file, &ct[..], &mut out).unwrap_err();
        assert!(e.contains("cannot decrypt"), "{e}");
        assert!(out.is_empty());
        assert!(!e.contains("AGE-SECRET-KEY"), "an error never quotes the key");
        assert!(decrypt_stream("not a key", &ct[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn a_truncated_or_tampered_archive_is_refused() {
        let k = generate_recovery_key(Utc::now());
        let mut data = vec![0u8; 200_000];
        Noise { state: 7, left: 200_000 }.read_exact(&mut data).unwrap();
        let ct = encrypt_bytes(&k.public_key, &data);
        let mut ok = Vec::new();
        decrypt_stream(&k.identity_file, &ct[..], &mut ok).unwrap();
        assert_eq!(ok, data);

        // Every cut is detected once the reader is drained: inside the last
        // chunk, mid-file, and right after the header.
        // The payload starts after the header, and each 64 KiB chunk is 65 536 +
        // 16 bytes: also cut exactly on chunk boundaries, the case the final-
        // chunk flag of the age stream exists for.
        let payload_start = ct.len() - (200_000 + 16 * 4) - 16; // nonce (16) + 4 chunks
        let mut cuts = vec![ct.len() - 1, ct.len() - 100, ct.len() / 2, 300];
        cuts.extend((1..=3).map(|k| payload_start + 16 + 65_552 * k));
        for cut in cuts {
            let r = decrypt_stream(&k.identity_file, &ct[..cut], &mut Vec::new());
            assert!(r.is_err(), "a stream cut at {cut} of {} must be refused", ct.len());
        }
        let mut tampered = ct.clone();
        let i = tampered.len() - 50;
        tampered[i] ^= 0x01;
        assert!(decrypt_stream(&k.identity_file, &tampered[..], &mut Vec::new()).is_err());
    }

    fn sample_manifest() -> (DrManifest, GeneratedKey) {
        let k = generate_recovery_key(Utc::now());
        let id = Uuid::new_v4();
        let at = Utc.with_ymd_and_hms(2026, 11, 20, 3, 30, 0).unwrap();
        (
            DrManifest {
                format: DR_FORMAT,
                kind: "dr".into(),
                install_id: id,
                from_version: "3.0.0-rc.4".into(),
                arch: "x86_64".into(),
                created_at: at.to_rfc3339(),
                snapshot_id: Uuid::new_v4(),
                archive: archive_name(id, &at),
                size_bytes: 123,
                sha256: "ab".repeat(32),
                recipient_fingerprint: k.fingerprint.clone(),
            },
            k,
        )
    }

    #[test]
    fn the_manifest_has_exactly_its_keys_and_no_secret() {
        let (m, k) = sample_manifest();
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, MANIFEST_KEYS);
        let text = serde_json::to_string(&m).unwrap();
        assert!(!text.contains("AGE-SECRET-KEY"));
        let secret_line = k.identity_file.lines().find(|l| l.starts_with("AGE-SECRET-KEY")).unwrap();
        assert!(!text.to_uppercase().contains(&secret_line[16..40]));
        assert!(!text.contains(&k.public_key), "not even the public key, the fingerprint is enough");
        for word in ["secret", "password", "token", "private", "identity", "jwt", "passphrase", "/etc/", "/var/"] {
            assert!(!text.to_lowercase().contains(word), "the manifest mentions '{word}'");
        }
        assert_eq!(v["format"], 1);
        assert_eq!(v["kind"], "dr");
        assert_eq!(serde_json::from_str::<DrManifest>(&text).unwrap(), m);
    }

    #[test]
    fn names_carry_the_install_id_and_a_prunable_stamp() {
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 11, 20, 3, 30, 5).unwrap();
        assert_eq!(archive_name(id, &at), "cyberhunter-dr-11111111-2222-3333-4444-555555555555-20261120-033005.tar.gz.age");
        assert_eq!(manifest_name(id, &at), "cyberhunter-dr-11111111-2222-3333-4444-555555555555-20261120-033005.manifest.json");
        let [a, m] = dr_prune_specs(id);
        assert_eq!(a.name_prefix, name_prefix(id));
        assert_eq!(a.suffixes, vec![".tar.gz.age".to_string()]);
        assert_eq!(m.suffixes, vec![".manifest.json".to_string()]);
        // What the agent's stamp_only prune requires: exactly the 15-character
        // stamp between the prefix and the suffix, for both kinds.
        for (spec, name) in [(&a, archive_name(id, &at)), (&m, manifest_name(id, &at))] {
            let mid = name.strip_prefix(&spec.name_prefix).unwrap().strip_suffix(spec.suffixes[0].as_str()).unwrap();
            assert_eq!(mid, "20261120-033005");
        }
        assert!(archive_name(id, &at).strip_suffix(".manifest.json").is_none());
        assert!(manifest_name(id, &at).strip_suffix(".tar.gz.age").is_none());
        let body = bpe::prune_body(&serde_json::json!({"type": "s3"}), "", &a, 14);
        assert_eq!(body["stamp_only"], true);
        assert_eq!(body["domain"], "");
        assert_eq!(body["retention"], 14);
        assert_eq!(body["name_prefix"], "cyberhunter-dr-11111111-2222-3333-4444-555555555555-");
        assert_eq!(body["suffixes"], serde_json::json!([".tar.gz.age"]));
    }

    #[test]
    fn the_destination_is_rebased_on_the_dr_subdirectory() {
        let id = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let s3 = dr_destination_payload(&serde_json::json!({"type": "s3", "bucket": "b", "path_prefix": "/panel/"}), id);
        assert_eq!(s3["path_prefix"], "panel/cyberhunter-dr/11111111-2222-3333-4444-555555555555");
        assert_eq!(s3["bucket"], "b");
        let s3_root = dr_destination_payload(&serde_json::json!({"type": "s3"}), id);
        assert_eq!(s3_root["path_prefix"], "cyberhunter-dr/11111111-2222-3333-4444-555555555555");
        let sftp = dr_destination_payload(&serde_json::json!({"type": "sftp", "remote_path": "/srv/bk/"}), id);
        assert_eq!(sftp["remote_path"], "/srv/bk/cyberhunter-dr/11111111-2222-3333-4444-555555555555");
        let sftp_default = dr_destination_payload(&serde_json::json!({"type": "sftp"}), id);
        assert_eq!(sftp_default["remote_path"], "/backups/cyberhunter-dr/11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn metadata_is_enriched_one_key_per_line() {
        let id = Uuid::new_v4();
        let out = enrich_metadata(r#"{"snapshot_id":"x","from_version":"3.0.0","trigger":"scheduled"}"#, id, "aarch64").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["kind"], "dr");
        assert_eq!(v["format"], 1);
        assert_eq!(v["arch"], "aarch64");
        assert_eq!(v["install_id"], id.to_string());
        assert_eq!(v["from_version"], "3.0.0");
        assert!(out.lines().any(|l| l.trim().starts_with("\"from_version\": \"3.0.0\"")));
        assert!(enrich_metadata("[]", id, "x").is_err());
    }

    #[test]
    fn only_sftp_keys_outside_etc_dockpanel_are_copied() {
        let (a, b, c, d, e) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let rows = vec![
            (a, "root key".to_string(), "sftp".to_string(), serde_json::json!({"key_path": "/root/.ssh/id_ed25519"})),
            (b, "inside".to_string(), "sftp".to_string(), serde_json::json!({"key_path": "/etc/dockpanel/keys/k"})),
            (c, "password".to_string(), "sftp".to_string(), serde_json::json!({"password": "x"})),
            (d, "bucket".to_string(), "s3".to_string(), serde_json::json!({"key_path": "/root/x"})),
            (e, "odd".to_string(), "sftp".to_string(), serde_json::json!({"key_path": "/opt/../root/k"})),
        ];
        let (plan, skipped) = key_copy_plan(&rows, Path::new("/etc/dockpanel/backup-keys"));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].destination_id, a);
        assert_eq!(plan[0].source, "/root/.ssh/id_ed25519");
        assert_eq!(plan[0].target, PathBuf::from(format!("/etc/dockpanel/backup-keys/{a}.key")));
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("odd"));
    }

    #[test]
    fn the_schedule_fires_once_at_its_minute() {
        let at = Utc.with_ymd_and_hms(2026, 11, 20, 3, 30, 10).unwrap();
        assert!(schedule_due(true, DEFAULT_SCHEDULE, None, at));
        assert!(!schedule_due(false, DEFAULT_SCHEDULE, None, at));
        assert!(!schedule_due(true, DEFAULT_SCHEDULE, None, at + chrono::Duration::minutes(1)));
        assert!(!schedule_due(true, DEFAULT_SCHEDULE, Some(at - chrono::Duration::seconds(30)), at));
        assert!(schedule_due(true, DEFAULT_SCHEDULE, Some(at - chrono::Duration::days(1)), at));
        assert!(valid_schedule(DEFAULT_SCHEDULE));
        assert!(valid_schedule("*/15 * * * 1-5"));
        assert!(!valid_schedule("30 3 * *"));
        assert!(!valid_schedule("0 30 3 * * *"));
        assert!(!valid_schedule("a b c d e"));
        // In format, out of range: would never fire.
        assert!(!valid_schedule("61 3 * * *"));
        assert!(!valid_schedule("30 24 * * *"));
        assert!(!valid_schedule("30 3 0 * *"));
        assert!(!valid_schedule("30 3 * 13 *"));
        assert!(!valid_schedule("30 3 * * 8"));
        assert!(!valid_schedule("30 5-3 * * *"));
        assert!(valid_schedule("0,30 0-23 1-31 1-12 0-7"));
    }

    #[test]
    fn the_48_hour_alert() {
        let now = Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap();
        let h = |n: i64| Some(now - chrono::Duration::hours(n));
        assert!(!offsite_stale(false, h(100), None, now), "disabled never alerts");
        assert!(!offsite_stale(true, h(1), None, now), "just enabled: grace period");
        assert!(offsite_stale(true, h(49), None, now), "enabled 49 h ago, never uploaded");
        assert!(!offsite_stale(true, h(200), h(47), now));
        assert!(offsite_stale(true, h(200), h(49), now));
        assert!(!offsite_stale(true, h(10), h(100), now), "re-enabled recently");
        assert!(offsite_stale(true, None, None, now));
        assert!(alert_due(true, None, now));
        assert!(!alert_due(true, h(3), now), "repeated at most once a day");
        assert!(alert_due(true, h(24), now));
        assert!(!alert_due(false, None, now));
    }

    #[test]
    fn run_status_from_results() {
        assert_eq!(run_status(0, 0, 0), "failed");
        assert_eq!(run_status(0, 2, 0), "failed");
        assert_eq!(run_status(2, 0, 0), "success");
        assert_eq!(run_status(1, 1, 0), "partial");
        assert_eq!(run_status(1, 0, 1), "partial");
    }

    #[test]
    fn a_run_needs_a_key_and_a_destination_and_runs_alone() {
        let mut s = DrSettings {
            enabled: true,
            schedule: DEFAULT_SCHEDULE.into(),
            destination_ids: vec![],
            remote_retention: DEFAULT_REMOTE_RETENTION,
            active_recipient_id: None,
            enabled_at: None,
            last_run_at: None,
            last_status: None,
            last_error: None,
            last_alert_at: None,
            updated_at: Utc::now(),
        };
        let r = DrRecipient {
            id: Uuid::new_v4(),
            public_key: "age1x".into(),
            fingerprint: "sha256:x".into(),
            created_by: None,
            created_at: Utc::now(),
            retired_at: None,
        };
        assert!(not_runnable_reason(&s, None).is_some());
        assert!(not_runnable_reason(&s, Some(&r)).is_some());
        s.destination_ids.push(Uuid::new_v4());
        assert!(not_runnable_reason(&s, Some(&r)).is_none());

        let g = RunGuard::acquire().expect("first run");
        assert!(is_running());
        assert!(RunGuard::acquire().is_none(), "a second run is refused while one runs");
        drop(g);
        assert!(!is_running());
    }

    #[test]
    fn a_recipient_row_serializes_no_secret_field() {
        let r = DrRecipient {
            id: Uuid::new_v4(),
            public_key: "age1x".into(),
            fingerprint: "sha256:x".into(),
            created_by: Some("a@b".into()),
            created_at: Utc::now(),
            retired_at: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["created_at", "created_by", "fingerprint", "id", "public_key", "retired_at"]);
    }

    #[cfg(unix)]
    #[test]
    fn the_dr_archive_drops_binaries_and_frontend_and_is_encrypted() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        let dir = tmp("archive");
        let src = dir.join("src");
        for d in ["binaries", "frontend/dist", "db", "etc/ssl", "etc/deploy-keys/frontend"] {
            std::fs::create_dir_all(src.join(d)).unwrap();
        }
        std::fs::write(src.join("binaries/dockpanel-api"), b"ELF").unwrap();
        std::fs::write(src.join("frontend/dist/index.html"), b"<html>").unwrap();
        std::fs::write(src.join("db/dump.sql.gz"), b"gz").unwrap();
        std::fs::write(src.join("etc/deploy-keys/frontend/id"), b"k").unwrap();
        std::fs::write(src.join("etc/deploy-keys/binaries"), b"k").unwrap();
        std::fs::write(src.join("etc/api.env"), b"JWT_SECRET=s3cr3t-value\n").unwrap();
        std::fs::write(src.join("metadata.json"), br#"{"snapshot_id":"s","from_version":"3.0.0"}"#).unwrap();
        let snap = dir.join("panel-snapshot.tar.gz");
        assert!(Command::new("tar").arg("-C").arg(&src).arg("-czf").arg(&snap).arg(".").status().unwrap().success());

        let k = generate_recovery_key(Utc::now());
        let id = Uuid::new_v4();
        let out = dir.join("out.tar.gz.age");
        let staging = dir.join("staging");
        let (size, sha) = build_dr_archive(&snap, &staging, id, &k.public_key, &out).unwrap();
        assert!(!staging.exists(), "staging is swept");
        assert!(!dir.join(".out.tar.gz.age.part").exists());
        assert_eq!(std::fs::metadata(&out).unwrap().len(), size);
        assert_eq!(hex::encode(Sha256::digest(std::fs::read(&out).unwrap())), sha);
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        let raw = std::fs::read(&out).unwrap();
        assert!(raw.starts_with(b"age-encryption.org/v1"));

        let tgz = dir.join("plain.tar.gz");
        decrypt_stream(&k.identity_file, std::fs::File::open(&out).unwrap(), std::fs::File::create(&tgz).unwrap()).unwrap();
        let list = Command::new("tar").arg("-tzf").arg(&tgz).output().unwrap();
        let list = String::from_utf8_lossy(&list.stdout);
        assert!(list.contains("db/dump.sql.gz") && list.contains("etc/api.env"), "{list}");
        for l in list.lines() {
            assert!(!l.starts_with("./binaries") && !l.starts_with("./frontend"), "{list}");
        }
        // Only the top-level trees go: a nested `frontend` or `binaries` stays.
        assert!(list.contains("./etc/deploy-keys/frontend/id"), "{list}");
        assert!(list.contains("./etc/deploy-keys/binaries"), "{list}");
        let x = dir.join("x");
        std::fs::create_dir_all(&x).unwrap();
        assert!(Command::new("tar").arg("-C").arg(&x).arg("-xzf").arg(&tgz).status().unwrap().success());
        let meta: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(x.join("metadata.json")).unwrap()).unwrap();
        assert_eq!(meta["kind"], "dr");
        assert_eq!(meta["install_id"], id.to_string());
        assert_eq!(meta["from_version"], "3.0.0");
        assert_eq!(meta["arch"], std::env::consts::ARCH);

        // A snapshot without its database dump is not shipped.
        let bad_src = dir.join("bad");
        std::fs::create_dir_all(&bad_src).unwrap();
        std::fs::write(bad_src.join("metadata.json"), b"{}").unwrap();
        let bad = dir.join("bad.tar.gz");
        assert!(Command::new("tar").arg("-C").arg(&bad_src).arg("-czf").arg(&bad).arg(".").status().unwrap().success());
        let out2 = dir.join("out2.tar.gz.age");
        assert!(build_dr_archive(&bad, &staging, id, &k.public_key, &out2).is_err());
        assert!(!out2.exists());

        // The outbox purge empties the directory and leaves it 0700.
        let outbox = dir.join("outbox");
        std::fs::create_dir_all(outbox.join("sub")).unwrap();
        std::fs::write(outbox.join("a.age"), b"x").unwrap();
        assert_eq!(purge_outbox(&outbox).unwrap(), 2);
        assert_eq!(std::fs::read_dir(&outbox).unwrap().count(), 0);
        assert_eq!(std::fs::metadata(&outbox).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
