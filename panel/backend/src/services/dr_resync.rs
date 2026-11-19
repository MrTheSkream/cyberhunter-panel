//! Resynchronise `dr_remote_snapshots` with what the destinations hold (lot 2,
//! VM acceptance).
//!
//! The off-site snapshot is taken DURING its run, so the database it carries
//! has no row for itself, nor for any copy made after it. After a restore (new
//! machine, or "Restore from remote snapshot" in the panel) the Disaster
//! recovery card listed none of the archives that are actually at the
//! destinations, and offered neither their download nor their restore.
//!
//! This pass lists `<base>/cyberhunter-dr/<install_id>/` of every configured
//! destination through the agent (`/backups/list`), and:
//! - for an archive no row records as uploaded there, reads its plaintext
//!   manifest and inserts the row (`created_at`/`uploaded_at` from the
//!   manifest, so the 48 h alert and the retention order stay true);
//! - marks `deleted_at` on a recorded copy the listing no longer shows (pruned
//!   or removed at the destination), except when the listing is empty while
//!   copies are recorded: that is reported, not acted on.
//!
//! It runs in the post-restore pass (marker `vhost-rebuild.pending`, after the
//! SFTP key paths are re-pointed) and at the start of every off-site run. A
//! steady state costs one listing per destination and no download.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::AgentHandle;
use crate::services::dr_restore::{self, agent_message};
use crate::services::dr_snapshot::{self as dr, DrManifest};

/// One archive listed at a destination: its file name and the key
/// `/backups/download` takes back.
#[derive(Debug, Clone, PartialEq)]
pub struct ListedArchive {
    pub name: String,
    pub key: String,
}

/// The archives (`.tar.gz.age`) of `install_id` in a `/backups/list` answer.
pub fn listed_archives(resp: &serde_json::Value, install_id: Uuid) -> Vec<ListedArchive> {
    let prefix = dr::name_prefix(install_id);
    let mut out: Vec<ListedArchive> = resp
        .get("objects")
        .and_then(|o| o.as_array())
        .map(|objs| {
            objs.iter()
                .filter_map(|o| {
                    let name = o.get("name")?.as_str()?;
                    let key = o.get("key")?.as_str()?;
                    let ours = name.starts_with(&prefix)
                        && dr_restore::parse_archive_name(name).is_some_and(|(id, _)| id == install_id);
                    ours.then(|| ListedArchive { name: name.to_string(), key: key.to_string() })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    out
}

/// What to change for one destination: the listed archives no row records,
/// and the recorded copies no longer listed. An empty listing while copies
/// are recorded changes nothing (`Err`): a listing that came back empty by
/// mistake must not wipe the card.
pub fn plan(listed: &[ListedArchive], recorded: &[String]) -> Result<(Vec<ListedArchive>, Vec<String>), String> {
    if listed.is_empty() && !recorded.is_empty() {
        return Err(format!(
            "the destination lists no off-site snapshot while {} copies are recorded there; nothing was marked as removed",
            recorded.len()
        ));
    }
    let missing = listed.iter().filter(|l| !recorded.iter().any(|r| *r == l.name)).cloned().collect();
    let vanished = recorded.iter().filter(|r| !listed.iter().any(|l| l.name == **r)).cloned().collect();
    Ok((missing, vanished))
}

/// Whether a manifest really describes `archive` of `install_id`, and when it
/// was made. The version is NOT checked: an older archive is still a copy the
/// card must list (its restore is refused later, with the reason).
pub fn manifest_row(m: &DrManifest, archive: &str, install_id: Uuid) -> Result<DateTime<Utc>, String> {
    if m.kind != "dr" {
        return Err(format!("the manifest of {archive} is not an off-site snapshot manifest (kind {})", m.kind));
    }
    if m.archive != archive {
        return Err(format!("the manifest next to {archive} describes {}", m.archive));
    }
    if m.install_id != install_id {
        return Err(format!("the manifest of {archive} names another installation ({})", m.install_id));
    }
    if m.sha256.len() != 64 || !m.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("the manifest of {archive} has no valid sha256"));
    }
    DateTime::parse_from_rfc3339(&m.created_at)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| format!("the manifest of {archive} has no valid date ({}): {e}", m.created_at))
}

/// What a resynchronisation did, for the logs, the run status and the
/// post-restore report.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResyncReport {
    /// Destinations listed successfully.
    pub destinations: usize,
    /// Copies added (`<destination>: <archive>`).
    pub added: Vec<String>,
    /// Copies no longer at their destination, marked removed.
    pub removed: Vec<String>,
    pub errors: Vec<String>,
    /// (snapshot id of the manifest, archive) of every copy added or already
    /// recorded, to name the archive a restore came from.
    #[serde(skip)]
    pub archives: Vec<(Uuid, String)>,
}

impl ResyncReport {
    /// The archive whose manifest names `snapshot_id`, if one was seen.
    pub fn archive_of(&self, snapshot_id: Uuid) -> Option<&str> {
        self.archives.iter().find(|(id, _)| *id == snapshot_id).map(|(_, a)| a.as_str())
    }
}

/// Resynchronise every destination of the DR settings.
pub async fn resync(db: &PgPool, agent: &AgentHandle) -> ResyncReport {
    let mut report = ResyncReport::default();
    let install_id = match dr::install_id(db).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            report.errors.push("no local server row (is_local): install_id unknown".into());
            return report;
        }
        Err(e) => {
            report.errors.push(format!("cannot read the local server: {e}"));
            return report;
        }
    };
    let settings = match dr::load_settings(db).await {
        Ok(s) => s,
        Err(e) => {
            report.errors.push(format!("cannot read the settings: {e}"));
            return report;
        }
    };
    for dest_id in &settings.destination_ids {
        if let Err(e) = resync_destination(db, agent, install_id, *dest_id, &mut report).await {
            report.errors.push(e);
        }
    }
    // Copies recorded before this pass also name their snapshot.
    if let Ok(rows) = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT snapshot_id, filename FROM dr_remote_snapshots WHERE snapshot_id IS NOT NULL AND status = 'uploaded'",
    )
    .fetch_all(db)
    .await
    {
        report.archives.extend(rows);
    }
    for e in &report.errors {
        tracing::warn!("Off-site snapshot resync: {e}");
    }
    if !report.added.is_empty() || !report.removed.is_empty() {
        tracing::info!(
            "Off-site snapshot resync: {} copies added, {} marked removed",
            report.added.len(),
            report.removed.len()
        );
    }
    report
}

async fn resync_destination(
    db: &PgPool,
    agent: &AgentHandle,
    install_id: Uuid,
    dest_id: Uuid,
    report: &mut ResyncReport,
) -> Result<(), String> {
    let row: Option<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT bd.name, bd.dtype, bd.config FROM backup_destinations bd LEFT JOIN servers s ON bd.server_id = s.id \
         WHERE bd.id = $1 AND (bd.server_id IS NULL OR s.is_local)",
    )
    .bind(dest_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("cannot read destination {dest_id}: {e}"))?;
    let (name, dtype, config) =
        row.ok_or_else(|| format!("destination {dest_id} no longer exists or is not reachable from this server"))?;
    let payload = dr::dr_destination_payload(
        &crate::routes::backup_destinations::agent_destination_payload(&dtype, &config),
        install_id,
    );
    let resp = agent
        .post_long(
            "/backups/list",
            Some(serde_json::json!({ "destination": payload, "prefix": dr::name_prefix(install_id) })),
            300,
        )
        .await
        .map_err(|e| format!("destination '{name}': listing failed: {}", agent_message(&e)))?;
    let listed = listed_archives(&resp, install_id);
    report.destinations += 1;

    let recorded: Vec<String> = sqlx::query_scalar(
        "SELECT filename FROM dr_remote_snapshots \
         WHERE destination_id = $1 AND status = 'uploaded' AND deleted_at IS NULL",
    )
    .bind(dest_id)
    .fetch_all(db)
    .await
    .map_err(|e| format!("destination '{name}': cannot read its recorded copies: {e}"))?;

    let (missing, vanished) = plan(&listed, &recorded).map_err(|e| format!("destination '{name}': {e}"))?;

    if !vanished.is_empty() {
        sqlx::query(
            "UPDATE dr_remote_snapshots SET deleted_at = NOW() \
             WHERE destination_id = $1 AND status = 'uploaded' AND deleted_at IS NULL AND filename = ANY($2)",
        )
        .bind(dest_id)
        .bind(&vanished)
        .execute(db)
        .await
        .map_err(|e| format!("destination '{name}': cannot mark the removed copies: {e}"))?;
        report.removed.extend(vanished.iter().map(|v| format!("{name}: {v}")));
    }

    for archive in missing {
        let manifest = match dr_restore::fetch_manifest(agent, &payload, &archive.name).await {
            Ok(m) => m,
            Err(e) => {
                report.errors.push(format!("destination '{name}': {}: {e}", archive.name));
                continue;
            }
        };
        let at = match manifest_row(&manifest, &archive.name, install_id) {
            Ok(at) => at,
            Err(e) => {
                report.errors.push(format!("destination '{name}': {e}"));
                continue;
            }
        };
        let inserted = sqlx::query(
            "INSERT INTO dr_remote_snapshots \
               (snapshot_id, destination_id, status, remote_key, filename, size_bytes, sha256, \
                recipient_fingerprint, from_version, created_at, uploaded_at) \
             SELECT (SELECT id FROM panel_snapshots WHERE id = $1), $2, 'uploaded', $3, $4, $5, $6, $7, $8, $9, $9 \
             WHERE NOT EXISTS (SELECT 1 FROM dr_remote_snapshots \
                               WHERE destination_id = $2 AND filename = $4 AND status = 'uploaded' AND deleted_at IS NULL)",
        )
        .bind(manifest.snapshot_id)
        .bind(dest_id)
        .bind(&archive.key)
        .bind(&archive.name)
        .bind(manifest.size_bytes as i64)
        .bind(&manifest.sha256)
        .bind(&manifest.recipient_fingerprint)
        .bind(&manifest.from_version)
        .bind(at)
        .execute(db)
        .await;
        match inserted {
            Ok(r) if r.rows_affected() > 0 => {
                report.added.push(format!("{name}: {}", archive.name));
                report.archives.push((manifest.snapshot_id, archive.name.clone()));
            }
            Ok(_) => {}
            Err(e) => report.errors.push(format!("destination '{name}': {}: cannot record it: {e}", archive.name)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::parse_str("0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e").unwrap()
    }

    fn archive(stamp: &str) -> String {
        format!("cyberhunter-dr-{}-{stamp}.tar.gz.age", id())
    }

    fn manifest(archive: &str) -> DrManifest {
        DrManifest {
            format: dr::DR_FORMAT,
            kind: "dr".into(),
            install_id: id(),
            from_version: "2.47.3".into(),
            arch: "x86_64".into(),
            created_at: "2026-11-19T03:30:12Z".into(),
            snapshot_id: Uuid::nil(),
            archive: archive.into(),
            size_bytes: 1234,
            sha256: "ab".repeat(32),
            recipient_fingerprint: "fp".into(),
        }
    }

    #[test]
    fn only_this_installations_archives_are_listed_with_their_key() {
        let other = Uuid::new_v4();
        let resp = serde_json::json!({ "objects": [
            { "name": archive("20261119-033012"), "key": "panel/cyberhunter-dr/x/a", "size": 10 },
            { "name": format!("cyberhunter-dr-{}-20261119-033012.manifest.json", id()), "key": "m", "size": 1 },
            { "name": format!("cyberhunter-dr-{other}-20261119-033012.tar.gz.age"), "key": "o", "size": 1 },
            { "name": archive("20261118-033012"), "size": 10 },
            { "name": "notes.txt", "key": "n" },
        ]});
        let l = listed_archives(&resp, id());
        assert_eq!(l, vec![ListedArchive { name: archive("20261119-033012"), key: "panel/cyberhunter-dr/x/a".into() }]);
        assert!(listed_archives(&serde_json::json!({}), id()).is_empty());
    }

    #[test]
    fn the_plan_adds_what_is_listed_and_removes_what_is_gone() {
        let a = ListedArchive { name: archive("20261119-033012"), key: "ka".into() };
        let b = ListedArchive { name: archive("20261120-033012"), key: "kb".into() };
        let (missing, vanished) = plan(&[a.clone(), b.clone()], &[a.name.clone(), archive("20261101-033012")]).unwrap();
        assert_eq!(missing, vec![b.clone()]);
        assert_eq!(vanished, vec![archive("20261101-033012")]);
        // Fresh database after a restore: everything listed is added.
        let (missing, vanished) = plan(&[a.clone(), b.clone()], &[]).unwrap();
        assert_eq!(missing.len(), 2);
        assert!(vanished.is_empty());
        // A steady state changes nothing.
        let (missing, vanished) = plan(&[a.clone()], &[a.name.clone()]).unwrap();
        assert!(missing.is_empty() && vanished.is_empty());
        // An empty listing never wipes the recorded copies.
        assert!(plan(&[], &[a.name]).is_err());
        assert_eq!(plan(&[], &[]).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn a_manifest_must_describe_this_archive_of_this_installation() {
        let name = archive("20261119-033012");
        let at = manifest_row(&manifest(&name), &name, id()).unwrap();
        assert_eq!(at.to_rfc3339(), "2026-11-19T03:30:12+00:00");
        // An older version is still listed.
        assert!(manifest_row(&DrManifest { from_version: "1.0.0".into(), ..manifest(&name) }, &name, id()).is_ok());
        assert!(manifest_row(&manifest(&archive("20261118-033012")), &name, id()).is_err());
        assert!(manifest_row(&DrManifest { install_id: Uuid::new_v4(), ..manifest(&name) }, &name, id()).is_err());
        assert!(manifest_row(&DrManifest { kind: "panel".into(), ..manifest(&name) }, &name, id()).is_err());
        assert!(manifest_row(&DrManifest { sha256: "xyz".into(), ..manifest(&name) }, &name, id()).is_err());
        assert!(manifest_row(&DrManifest { created_at: "yesterday".into(), ..manifest(&name) }, &name, id()).is_err());
    }

    #[test]
    fn the_report_names_the_archive_of_a_snapshot() {
        let s = Uuid::new_v4();
        let r = ResyncReport { archives: vec![(s, archive("20261119-033012"))], ..Default::default() };
        assert_eq!(r.archive_of(s), Some(archive("20261119-033012").as_str()));
        assert_eq!(r.archive_of(Uuid::nil()), None);
        // The internal list does not leak into the report written to disk.
        assert!(!serde_json::to_string(&r).unwrap().contains("archives"));
    }
}
