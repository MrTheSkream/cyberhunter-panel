//! Restore of an off-site disaster recovery snapshot (lot 2, step 2.5).
//!
//! Shared by the panel ("Restore from remote snapshot", `routes::dr_restore`)
//! and the command line of a freshly installed machine (`dockpanel-api dr
//! restore`, `cli_dr`). Both go through the LOCAL agent:
//!
//! 1. `/backups/list` + `/backups/download` of the plaintext manifest
//!    (`cyberhunter-dr-{install_id}-{stamp}.manifest.json`), checked against the
//!    archive asked for, this version and this architecture BEFORE the archive
//!    itself is fetched;
//! 2. `/backups/download` of the `.tar.gz.age` into the 0700 restore inbox; the
//!    agent's SHA-256 of what it wrote must be the manifest's;
//! 3. decryption in flux ([`dr_snapshot::decrypt_file_to`]) into
//!    `dr-restore-{snapshot_id}.tar.gz` (0600), the ciphertext hashed again on
//!    the way; the `.age` is removed;
//! 4. [`panel_snapshot::launch_restore_unit`] in mode `dr` with the plaintext
//!    SHA-256: `restore-snapshot.sh` re-checks version and arch before stopping
//!    anything, and deletes the decrypted tarball on every exit path.
//!
//! The recovery key travels as a [`Zeroizing`] string from the request body or
//! the identity file to the age decryptor, and nowhere else: not argv, not an
//! environment variable, not a log line, not a file.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::services::agent::{AgentError, AgentHandle};
use crate::services::dr_snapshot::{self as dr, DrManifest, DR_FORMAT};
use crate::services::panel_snapshot::{self, RestoreMode};

/// Where the agent's `/backups/download` writes (agent `RESTORE_INBOX`).
pub const RESTORE_INBOX: &str = "/var/backups/dockpanel/restore-inbox";
/// The agent's own download budget is 1800 s: wait longer than it does.
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 1900;
/// A manifest is a few hundred bytes; anything big is not one.
const MANIFEST_MAX_BYTES: u64 = 64 * 1024;

/// `cyberhunter-dr-{uuid}-{%Y%m%d-%H%M%S}.tar.gz.age` -> (install_id, stamp).
pub fn parse_archive_name(name: &str) -> Option<(Uuid, String)> {
    let rest = name.strip_prefix("cyberhunter-dr-")?.strip_suffix(".tar.gz.age")?;
    if rest.len() != 36 + 1 + 15 {
        return None;
    }
    let (id, stamp) = rest.split_at(36);
    let stamp = stamp.strip_prefix('-')?;
    let id = Uuid::parse_str(id).ok()?;
    let ok = stamp.len() == 15
        && stamp.char_indices().all(|(i, c)| if i == 8 { c == '-' } else { c.is_ascii_digit() });
    ok.then(|| (id, stamp.to_string()))
}

/// The manifest file name of an archive (same stamp, see `dr_snapshot::manifest_name`).
pub fn manifest_name_for(archive: &str) -> Option<String> {
    let (id, stamp) = parse_archive_name(archive)?;
    Some(format!("{}{stamp}.manifest.json", dr::name_prefix(id)))
}

/// Everything a manifest must say before its archive is even downloaded.
pub fn validate_manifest(m: &DrManifest, archive: &str, version: &str, arch: &str) -> Result<(), String> {
    let (install_id, _) = parse_archive_name(archive).ok_or("not an off-site snapshot archive name")?;
    if m.kind != "dr" {
        return Err(format!("the manifest is not an off-site snapshot one (kind '{}')", m.kind));
    }
    if m.format != DR_FORMAT {
        return Err(format!("unsupported archive format {} (this version reads format {DR_FORMAT})", m.format));
    }
    if m.archive != archive {
        return Err(format!("the manifest describes {}, not {archive}", m.archive));
    }
    if m.install_id != install_id {
        return Err("the manifest's install id does not match the archive name".into());
    }
    if m.sha256.len() != 64 || !m.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("the manifest carries no valid sha256".into());
    }
    if m.from_version != version {
        return Err(format!(
            "version mismatch: this snapshot was taken by version {} and this machine runs {version}. \
             Install version {} first (DOCKPANEL_VERSION=v{} bash install.sh)",
            m.from_version, m.from_version, m.from_version
        ));
    }
    if m.arch != arch {
        return Err(format!(
            "architecture mismatch: this snapshot was taken on {} and this machine is {arch}",
            m.arch
        ));
    }
    Ok(())
}

/// The agent's report of a download must be the manifest's object.
pub fn check_download(m: &DrManifest, size: u64, sha256: &str) -> Result<(), String> {
    if !sha256.eq_ignore_ascii_case(&m.sha256) {
        return Err(format!(
            "checksum mismatch: the downloaded archive has sha256 {sha256}, the manifest says {}. \
             The archive is damaged or was replaced: nothing was restored",
            m.sha256
        ));
    }
    if size != m.size_bytes {
        return Err(format!("size mismatch: downloaded {size} bytes, the manifest says {}", m.size_bytes));
    }
    Ok(())
}

/// The recovery key must be the one the snapshot was encrypted to. Compares
/// fingerprints of the public half; the error never quotes the key.
pub fn identity_matches(identity: &str, recipient_fingerprint: &str) -> Result<(), String> {
    let id = dr::parse_identity(identity)?;
    let fp = dr::fingerprint(&id.to_public().to_string());
    if fp != recipient_fingerprint {
        return Err(format!(
            "this recovery key does not match the key the snapshot was encrypted to (expected {recipient_fingerprint}, \
             the pasted key is {fp})"
        ));
    }
    Ok(())
}

/// The message an agent error carries, without the transport noise.
pub fn agent_message(e: &AgentError) -> String {
    if let AgentError::Status(code, body) = e {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(m) = v.get("error").or_else(|| v.get("message")).and_then(|m| m.as_str()) {
                return format!("{m} (agent {code})");
            }
        }
    }
    e.to_string()
}

// ── Progress of the panel-side restore ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub archive: String,
    pub snapshot_id: Option<Uuid>,
    /// downloading, verifying, decrypting, starting, handed_off, failed
    pub phase: &'static str,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub error: Option<String>,
}

static PROGRESS: Mutex<Option<Progress>> = Mutex::new(None);

pub fn progress() -> Option<Progress> {
    PROGRESS.lock().map(|p| p.clone()).unwrap_or(None)
}

pub fn set_progress(p: Option<Progress>) {
    if let Ok(mut g) = PROGRESS.lock() {
        *g = p;
    }
}

fn update_phase(phase: &'static str, snapshot_id: Option<Uuid>, error: Option<String>) {
    if let Ok(mut g) = PROGRESS.lock() {
        if let Some(p) = g.as_mut() {
            p.phase = phase;
            p.updated_at = Utc::now();
            if snapshot_id.is_some() {
                p.snapshot_id = snapshot_id;
            }
            p.error = error;
        }
    }
}

/// Reports where a restore stands, to the panel's progress or the terminal.
pub trait Reporter {
    fn phase(&self, phase: &'static str, detail: &str);
}

/// The panel's reporter: the in-memory progress the card polls.
pub struct PanelReporter;

impl Reporter for PanelReporter {
    fn phase(&self, phase: &'static str, _detail: &str) {
        update_phase(phase, None, None);
    }
}

// ── Fetch, verify, decrypt, launch ──────────────────────────────────────────

/// The listed key of `filename` under the destination's DR directory.
pub async fn remote_key(agent: &AgentHandle, payload: &serde_json::Value, filename: &str) -> Result<String, String> {
    let resp = agent
        .post_long("/backups/list", Some(serde_json::json!({ "destination": payload, "prefix": filename })), 300)
        .await
        .map_err(|e| format!("listing the destination failed: {}", agent_message(&e)))?;
    resp.get("objects")
        .and_then(|o| o.as_array())
        .and_then(|objs| {
            objs.iter()
                .find(|o| o.get("name").and_then(|n| n.as_str()) == Some(filename))
                .and_then(|o| o.get("key").and_then(|k| k.as_str()).map(str::to_string))
        })
        .ok_or_else(|| format!("{filename} is not at this destination"))
}

/// One object of a listing.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Listed {
    pub name: String,
    pub size: u64,
    pub modified: Option<String>,
}

/// The archives and manifests listed under the DR directory of `install_id`.
pub async fn list_remote(agent: &AgentHandle, payload: &serde_json::Value, install_id: Uuid) -> Result<Vec<Listed>, String> {
    let resp = agent
        .post_long(
            "/backups/list",
            Some(serde_json::json!({ "destination": payload, "prefix": dr::name_prefix(install_id) })),
            300,
        )
        .await
        .map_err(|e| format!("listing the destination failed: {}", agent_message(&e)))?;
    let mut out: Vec<Listed> = resp
        .get("objects")
        .and_then(|o| o.as_array())
        .map(|objs| {
            objs.iter()
                .filter_map(|o| {
                    Some(Listed {
                        name: o.get("name")?.as_str()?.to_string(),
                        size: o.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                        modified: o.get("modified").and_then(|m| m.as_str()).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(out)
}

/// Download `filename` into the inbox under `target`. Returns (path, size, sha256).
pub async fn download(
    agent: &AgentHandle,
    payload: &serde_json::Value,
    filename: &str,
    target: &str,
) -> Result<(PathBuf, u64, String), String> {
    let key = remote_key(agent, payload, filename).await?;
    let resp = agent
        .post_long(
            "/backups/download",
            Some(serde_json::json!({ "destination": payload, "key": key, "target_name": target })),
            DOWNLOAD_TIMEOUT_SECS,
        )
        .await
        .map_err(|e| format!("downloading {filename} failed: {}", agent_message(&e)))?;
    let path = resp.get("path").and_then(|p| p.as_str()).ok_or("the agent named no downloaded file")?;
    let size = resp.get("size").and_then(|s| s.as_u64()).ok_or("the agent reported no size")?;
    let sha = resp.get("sha256").and_then(|s| s.as_str()).ok_or("the agent reported no sha256")?;
    let path = PathBuf::from(path);
    // The agent writes into its inbox only; a path anywhere else is refused.
    if path.parent() != Some(Path::new(RESTORE_INBOX)) {
        return Err(format!("the agent wrote {} outside the restore inbox", path.display()));
    }
    Ok((path, size, sha.to_string()))
}

/// Fetch and check the manifest of `archive`.
pub async fn fetch_manifest(agent: &AgentHandle, payload: &serde_json::Value, archive: &str) -> Result<DrManifest, String> {
    let name = manifest_name_for(archive).ok_or_else(|| format!("{archive} is not an off-site snapshot archive name"))?;
    let target = format!("dr-manifest-{}.json", Uuid::new_v4());
    let (path, size, _) = download(agent, payload, &name, &target).await?;
    let text = if size > MANIFEST_MAX_BYTES {
        Err(format!("{name} is {size} bytes, not a manifest"))
    } else {
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read the manifest: {e}"))
    };
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::warn!("Off-site restore: could not remove {}: {e}", path.display());
    }
    serde_json::from_str::<DrManifest>(&text?).map_err(|e| format!("{name} is not a valid manifest: {e}"))
}

/// A decrypted archive ready for `restore-snapshot.sh`.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub snapshot_id: Uuid,
    pub tarball: PathBuf,
    pub sha256: String,
}

/// Steps 1 to 3: manifest, download, checksum, decryption.
pub async fn fetch_and_decrypt(
    agent: &AgentHandle,
    payload: &serde_json::Value,
    archive: &str,
    identity: &Zeroizing<String>,
    reporter: &(dyn Reporter + Sync),
) -> Result<Prepared, String> {
    reporter.phase("downloading", "fetching the manifest");
    let manifest = fetch_manifest(agent, payload, archive).await?;
    validate_manifest(&manifest, archive, env!("CARGO_PKG_VERSION"), std::env::consts::ARCH)?;
    identity_matches(identity, &manifest.recipient_fingerprint)?;

    reporter.phase("downloading", "fetching the encrypted archive");
    let (age_path, size, sha) = download(agent, payload, archive, archive).await?;
    reporter.phase("verifying", "checking the archive against its manifest");
    if let Err(e) = check_download(&manifest, size, &sha) {
        remove_quietly(&age_path);
        return Err(e);
    }

    reporter.phase("decrypting", "decrypting the archive");
    let snapshot_id = manifest.snapshot_id;
    let out = Path::new(RESTORE_INBOX).join(format!("dr-restore-{snapshot_id}.tar.gz"));
    let (key, input, output) = (identity.clone(), age_path.clone(), out.clone());
    let decrypted = tokio::task::spawn_blocking(move || dr::decrypt_file_to(&key, &input, &output))
        .await
        .map_err(|e| format!("decryption task failed: {e}"));
    remove_quietly(&age_path);
    let decrypted = decrypted??;
    if !decrypted.cipher_sha256.eq_ignore_ascii_case(&manifest.sha256) {
        remove_quietly(&out);
        return Err("the archive changed between its download and its decryption: nothing was restored".into());
    }
    Ok(Prepared { snapshot_id, tarball: out, sha256: decrypted.sha256 })
}

fn remove_quietly(p: &Path) {
    if let Err(e) = std::fs::remove_file(p) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("Off-site restore: could not remove {}: {e}", p.display());
        }
    }
}

/// Step 4: hand the decrypted archive to `restore-snapshot.sh` (mode dr). On
/// failure to start, the decrypted archive is removed.
pub async fn launch(p: &Prepared, operator: Option<&str>) -> Result<(), String> {
    let r = panel_snapshot::launch_restore_unit(p.snapshot_id, &p.tarball, &p.sha256, operator, RestoreMode::Dr)
        .await
        .map_err(|e| format!("could not start the restore: {e}"));
    if r.is_err() {
        remove_quietly(&p.tarball);
    }
    r
}

// ── Destination file of the command line ───────────────────────────────────

/// The destination as the command line reads it: the agent payload, the
/// install id to look under, and which secret is still to be typed.
#[derive(Debug, Clone, PartialEq)]
pub struct DestinationSpec {
    pub payload: serde_json::Value,
    pub install_id: Option<Uuid>,
    /// `secret_key` (S3) or `password` (SFTP) when the file omits it.
    pub missing_secret: Option<&'static str>,
}

/// Parse the destination file of `dockpanel-api dr list|restore` (format in
/// docs/guides/disaster-recovery.md). Unknown keys are refused, so a typo is
/// not silently a different destination.
pub fn parse_destination_file(text: &str) -> Result<DestinationSpec, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("the destination file is not JSON: {e}"))?;
    let obj = v.as_object().ok_or("the destination file must be a JSON object")?;
    let dtype = obj.get("type").and_then(|t| t.as_str()).ok_or("the destination file needs \"type\": \"s3\" or \"sftp\"")?;
    let allowed: &[&str] = match dtype {
        "s3" => &["type", "bucket", "region", "endpoint", "access_key", "secret_key", "path_prefix", "install_id"],
        "sftp" => &["type", "host", "port", "username", "password", "key_path", "remote_path", "install_id"],
        other => return Err(format!("unsupported destination type '{other}' (s3 or sftp)")),
    };
    if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unknown key '{k}' for a {dtype} destination"));
    }
    let need = |k: &str| -> Result<(), String> {
        match obj.get(k).and_then(|x| x.as_str()) {
            Some(s) if !s.trim().is_empty() => Ok(()),
            _ => Err(format!("the {dtype} destination needs \"{k}\"")),
        }
    };
    let install_id = match obj.get("install_id") {
        None | Some(serde_json::Value::Null) => None,
        Some(x) => Some(
            x.as_str()
                .and_then(|s| Uuid::parse_str(s.trim()).ok())
                .ok_or("\"install_id\" must be a UUID")?,
        ),
    };
    let mut payload = v.clone();
    if let Some(p) = payload.as_object_mut() {
        p.remove("install_id");
    }
    let missing_secret = match dtype {
        "s3" => {
            for k in ["bucket", "endpoint", "access_key"] {
                need(k)?;
            }
            if obj.get("secret_key").and_then(|x| x.as_str()).is_some_and(|s| !s.is_empty()) {
                None
            } else {
                Some("secret_key")
            }
        }
        _ => {
            for k in ["host", "username"] {
                need(k)?;
            }
            if let Some(p) = obj.get("port") {
                if !p.as_u64().is_some_and(|n| (1..=65535).contains(&n)) {
                    return Err("\"port\" must be a number between 1 and 65535".into());
                }
            }
            let has = |k: &str| obj.get(k).and_then(|x| x.as_str()).is_some_and(|s| !s.is_empty());
            if has("password") || has("key_path") {
                None
            } else {
                Some("password")
            }
        }
    };
    Ok(DestinationSpec { payload, install_id, missing_secret })
}

/// Whether a secret-bearing file may be read: not readable or writable by
/// group or others.
#[cfg(unix)]
pub fn private_enough(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is readable by other users (mode {:o}): run `chmod 600 {}` first",
            path.display(),
            meta.mode() & 0o777,
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn private_enough(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e";

    fn archive() -> String {
        format!("cyberhunter-dr-{ID}-20261119-033000.tar.gz.age")
    }

    fn manifest() -> DrManifest {
        DrManifest {
            format: DR_FORMAT,
            kind: "dr".into(),
            install_id: Uuid::parse_str(ID).unwrap(),
            from_version: "2.47.3".into(),
            arch: "x86_64".into(),
            created_at: "2026-11-19T03:30:00Z".into(),
            snapshot_id: Uuid::nil(),
            archive: archive(),
            size_bytes: 1234,
            sha256: "a".repeat(64),
            recipient_fingerprint: "sha256:00".into(),
        }
    }

    #[test]
    fn archive_names_parse_and_give_their_manifest() {
        let (id, stamp) = parse_archive_name(&archive()).unwrap();
        assert_eq!(id.to_string(), ID);
        assert_eq!(stamp, "20261119-033000");
        assert_eq!(
            manifest_name_for(&archive()).unwrap(),
            format!("cyberhunter-dr-{ID}-20261119-033000.manifest.json")
        );
        // The same names as the producer.
        let at = Utc.with_ymd_and_hms(2026, 11, 19, 3, 30, 0).unwrap();
        let uid = Uuid::parse_str(ID).unwrap();
        assert_eq!(dr::archive_name(uid, &at), archive());
        assert_eq!(Some(dr::manifest_name(uid, &at)), manifest_name_for(&archive()));
        for bad in [
            "cyberhunter-dr-x.tar.gz.age",
            &format!("cyberhunter-dr-{ID}-20261119-033000.tar.gz"),
            &format!("cyberhunter-dr-{ID}-2026111a-033000.tar.gz.age"),
            &format!("cyberhunter-dr-{ID}-20261119-033000/../x.tar.gz.age"),
            &format!("../cyberhunter-dr-{ID}-20261119-033000.tar.gz.age"),
        ] {
            assert!(parse_archive_name(bad).is_none(), "{bad}");
        }
    }

    use chrono::TimeZone;

    #[test]
    fn the_manifest_is_checked_against_the_archive_the_version_and_the_arch() {
        let m = manifest();
        assert!(validate_manifest(&m, &archive(), "2.47.3", "x86_64").is_ok());
        let e = validate_manifest(&m, &archive(), "2.48.0", "x86_64").unwrap_err();
        assert!(e.contains("version mismatch") && e.contains("DOCKPANEL_VERSION=v2.47.3"), "{e}");
        assert!(validate_manifest(&m, &archive(), "2.47.3", "aarch64").unwrap_err().contains("architecture"));
        let other = format!("cyberhunter-dr-{ID}-20261118-033000.tar.gz.age");
        assert!(validate_manifest(&m, &other, "2.47.3", "x86_64").unwrap_err().contains("describes"));
        let mut k = manifest();
        k.kind = "manual".into();
        assert!(validate_manifest(&k, &archive(), "2.47.3", "x86_64").is_err());
        let mut f = manifest();
        f.format = DR_FORMAT + 1;
        assert!(validate_manifest(&f, &archive(), "2.47.3", "x86_64").is_err());
        let mut s = manifest();
        s.sha256 = "zz".into();
        assert!(validate_manifest(&s, &archive(), "2.47.3", "x86_64").is_err());
        let mut i = manifest();
        i.install_id = Uuid::nil();
        assert!(validate_manifest(&i, &archive(), "2.47.3", "x86_64").is_err());
    }

    #[test]
    fn a_download_must_match_the_manifest_sha256_and_size() {
        let m = manifest();
        assert!(check_download(&m, 1234, &"A".repeat(64)).is_ok());
        assert!(check_download(&m, 1234, &"b".repeat(64)).unwrap_err().contains("checksum mismatch"));
        assert!(check_download(&m, 1, &"a".repeat(64)).unwrap_err().contains("size mismatch"));
    }

    #[test]
    fn the_recovery_key_must_be_the_snapshots_and_is_never_quoted() {
        let k = dr::generate_recovery_key(Utc::now());
        assert!(identity_matches(&k.identity_file, &k.fingerprint).is_ok());
        let other = dr::generate_recovery_key(Utc::now());
        let e = identity_matches(&k.identity_file, &other.fingerprint).unwrap_err();
        assert!(!e.contains("AGE-SECRET-KEY"), "{e}");
        let e = identity_matches("AGE-SECRET-KEY-1NOTAKEY", &k.fingerprint).unwrap_err();
        assert!(!e.contains("NOTAKEY"), "{e}");
    }

    #[test]
    fn decrypt_file_to_round_trips_hashes_and_refuses_a_wrong_key() {
        let dir = std::env::temp_dir().join(format!("dr-restore-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let k = dr::generate_recovery_key(Utc::now());
        let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let cipher = dr::encrypt_stream(&k.public_key, &plain[..], Vec::new()).unwrap();
        let input = dir.join("a.tar.gz.age");
        std::fs::write(&input, &cipher).unwrap();
        let out = dir.join("a.tar.gz");
        let d = dr::decrypt_file_to(&k.identity_file, &input, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
        use sha2::{Digest, Sha256};
        assert_eq!(d.sha256, hex::encode(Sha256::digest(&plain)));
        assert_eq!(d.cipher_sha256, hex::encode(Sha256::digest(&cipher)));
        assert_eq!((d.size, d.cipher_size), (plain.len() as u64, cipher.len() as u64));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Wrong key, truncated stream: an error and nothing left behind.
        let other = dr::generate_recovery_key(Utc::now());
        let out2 = dir.join("b.tar.gz");
        assert!(dr::decrypt_file_to(&other.identity_file, &input, &out2).is_err());
        assert!(!out2.exists());
        std::fs::write(&input, &cipher[..cipher.len() - 100]).unwrap();
        assert!(dr::decrypt_file_to(&k.identity_file, &input, &out2).is_err());
        assert!(!out2.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "no .part file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destination_files_are_parsed_strictly() {
        let s3 = parse_destination_file(&format!(
            r#"{{"type":"s3","bucket":"b","region":"us-east-1","endpoint":"https://s3.example","access_key":"AK","secret_key":"SK","path_prefix":"p","install_id":"{ID}"}}"#
        ))
        .unwrap();
        assert_eq!(s3.install_id.unwrap().to_string(), ID);
        assert_eq!(s3.missing_secret, None);
        assert!(s3.payload.get("install_id").is_none(), "install_id is not sent to the agent");
        assert_eq!(s3.payload["secret_key"], "SK");
        let no_secret = parse_destination_file(r#"{"type":"s3","bucket":"b","endpoint":"e","access_key":"AK"}"#).unwrap();
        assert_eq!(no_secret.missing_secret, Some("secret_key"));
        let sftp = parse_destination_file(r#"{"type":"sftp","host":"h","port":22,"username":"u","key_path":"/root/k"}"#).unwrap();
        assert_eq!(sftp.missing_secret, None);
        let sftp_pw = parse_destination_file(r#"{"type":"sftp","host":"h","username":"u"}"#).unwrap();
        assert_eq!(sftp_pw.missing_secret, Some("password"));
        for bad in [
            "not json",
            "[]",
            r#"{"type":"ftp"}"#,
            r#"{"type":"s3","bucket":"b","endpoint":"e"}"#,
            r#"{"type":"s3","bucket":"b","endpoint":"e","access_key":"a","secretkey":"typo"}"#,
            r#"{"type":"sftp","host":"h","username":"u","port":70000}"#,
            r#"{"type":"sftp","host":"h","username":"u","install_id":"nope"}"#,
        ] {
            assert!(parse_destination_file(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn agent_errors_are_reduced_to_their_message() {
        let e = AgentError::Status(404, r#"{"error":"Remote object not found"}"#.into());
        assert_eq!(agent_message(&e), "Remote object not found (agent 404)");
    }
}
