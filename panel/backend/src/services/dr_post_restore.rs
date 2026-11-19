//! What the api does at its first start after an off-site restore (lot 2,
//! step 2.5, decisions 12 and 13).
//!
//! `restore-snapshot.sh` (mode dr) leaves `/var/lib/dockpanel/vhost-rebuild.pending`
//! behind: the archive carries the database and /etc/dockpanel, but no nginx
//! vhost. At startup, when the marker is there, this pass:
//!
//! 1. re-points the `key_path` of SFTP destinations at the key copies the
//!    archive carried (`/etc/dockpanel/backup-keys/index.json`), copied to
//!    [`SFTP_KEYS_DIR`] (outside `backup-keys/`, whose files the off-site run
//!    sweeps when no destination points outside /etc/dockpanel any more);
//! 2. moves to the primary address every local site whose declared address
//!    (`sites.ip_id`) is not on this machine (decision 13);
//! 3. rebuilds the vhost of every local site from the database, puts the
//!    disabled ones back to disabled;
//! 4. runs `nginx -t`, then reloads nginx when it passes;
//! 5. writes the report `/var/lib/dockpanel/vhost-rebuild.json` (atomically),
//!    then removes the marker. A pass that cannot reach the agent writes its
//!    report and KEEPS the marker, so the next start tries again.
//!
//! The panel's own certificate (/etc/letsencrypt) is not in the archive: it is
//! issued again by certbot once the DNS points at the new machine (decision 12,
//! docs/guides/disaster-recovery.md).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::Site;
use crate::services::agent::{AgentClient, AgentHandle};
use crate::services::dr_restore::agent_message;
use crate::services::dr_snapshot::BACKUP_KEYS_DIR;

pub const MARKER: &str = "/var/lib/dockpanel/vhost-rebuild.pending";
pub const REPORT: &str = "/var/lib/dockpanel/vhost-rebuild.json";
/// Where restored SFTP keys live from now on.
pub const SFTP_KEYS_DIR: &str = "/etc/dockpanel/sftp-keys";

// ── Pure planning ───────────────────────────────────────────────────────────

/// A site as the plan needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteAddr {
    pub site_id: Uuid,
    pub domain: String,
    pub ip_id: Option<Uuid>,
}

/// One site moved to the primary address.
#[derive(Debug, Clone, PartialEq)]
pub struct Remap {
    pub site_id: Uuid,
    pub domain: String,
    /// The declared address that is not on this machine (or the id when the
    /// row itself is gone).
    pub from: String,
}

/// The sites whose declared address is not assigned on this machine.
/// `declared` maps `server_ips.id` to its address; `on_host` lists the
/// addresses the agent sees on the interfaces.
pub fn remap_plan(sites: &[SiteAddr], declared: &[(Uuid, String)], on_host: &[String]) -> Vec<Remap> {
    sites
        .iter()
        .filter_map(|s| {
            let id = s.ip_id?;
            match declared.iter().find(|(d, _)| *d == id) {
                Some((_, ip)) if on_host.iter().any(|h| h == ip) => None,
                Some((_, ip)) => Some(Remap { site_id: s.site_id, domain: s.domain.clone(), from: ip.clone() }),
                None => Some(Remap { site_id: s.site_id, domain: s.domain.clone(), from: format!("address {id}") }),
            }
        })
        .collect()
}

/// One entry of `backup-keys/index.json` (written by the off-site run).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KeyIndexEntry {
    pub destination_id: Uuid,
    #[serde(default)]
    pub destination_name: String,
    pub original_key_path: String,
    pub file: String,
}

/// A destination as the rewrite needs it: id, name, type, current key_path.
#[derive(Debug, Clone, PartialEq)]
pub struct DestKey {
    pub id: Uuid,
    pub name: String,
    pub dtype: String,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyRewrite {
    #[serde(skip)]
    pub destination_id: Uuid,
    pub destination: String,
    pub from: String,
    pub to: String,
    #[serde(skip)]
    pub source: PathBuf,
}

/// Which destinations to re-point, and what is skipped (with the reason).
/// Only an SFTP destination whose `key_path` is still the one the copy was
/// made from, and only a copy file that is a plain name present in `keys_dir`.
pub fn key_rewrite_plan(
    index: &[KeyIndexEntry],
    dests: &[DestKey],
    keys_dir: &Path,
    target_dir: &Path,
    exists: &dyn Fn(&Path) -> bool,
) -> (Vec<KeyRewrite>, Vec<String>) {
    let mut plan = Vec::new();
    let mut skipped = Vec::new();
    for e in index {
        let plain = !e.file.is_empty()
            && e.file.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            && !e.file.contains("..");
        if !plain {
            skipped.push(format!("key copy '{}' has an invalid file name, not used", e.file));
            continue;
        }
        let Some(d) = dests.iter().find(|d| d.id == e.destination_id) else {
            skipped.push(format!("destination '{}' no longer exists: its key copy is not used", e.destination_name));
            continue;
        };
        if d.dtype != "sftp" {
            continue;
        }
        if d.key_path.as_deref() != Some(e.original_key_path.as_str()) {
            skipped.push(format!("destination '{}': key_path changed since the copy, left as it is", d.name));
            continue;
        }
        let source = keys_dir.join(&e.file);
        if !exists(&source) {
            skipped.push(format!("destination '{}': the key copy {} is missing, key_path left as it is", d.name, source.display()));
            continue;
        }
        plan.push(KeyRewrite {
            destination_id: d.id,
            destination: d.name.clone(),
            from: e.original_key_path.clone(),
            to: target_dir.join(format!("{}.key", d.id)).to_string_lossy().to_string(),
            source,
        });
    }
    (plan, skipped)
}

// ── Report ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteResult {
    pub domain: String,
    /// rebuilt, failed, skipped
    pub status: String,
    pub remapped_from: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Check {
    pub ok: bool,
    #[serde(alias = "detail")]
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReloadResult {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyPathResult {
    pub destination: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RebuildReport {
    /// The off-site snapshot whose restore asked for this pass (marker content).
    pub snapshot_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub ok: bool,
    pub sites: Vec<SiteResult>,
    pub rebuilt: usize,
    pub remapped: usize,
    pub failed: usize,
    pub nginx_test: Option<Check>,
    pub reload: Option<ReloadResult>,
    pub key_paths: Vec<KeyPathResult>,
    pub errors: Vec<String>,
}

impl RebuildReport {
    fn new(snapshot_id: Option<String>) -> Self {
        let now = Utc::now();
        RebuildReport {
            snapshot_id,
            started_at: now,
            finished_at: now,
            ok: false,
            sites: Vec::new(),
            rebuilt: 0,
            remapped: 0,
            failed: 0,
            nginx_test: None,
            reload: None,
            key_paths: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Counters and verdict from the per-site lines and the nginx checks.
    pub fn finish(&mut self) {
        self.finished_at = Utc::now();
        self.rebuilt = self.sites.iter().filter(|s| s.status == "rebuilt").count();
        self.failed = self.sites.iter().filter(|s| s.status == "failed").count();
        self.remapped = self.sites.iter().filter(|s| s.remapped_from.is_some()).count();
        self.ok = self.failed == 0
            && self.errors.is_empty()
            && self.nginx_test.as_ref().is_some_and(|c| c.ok)
            && self.reload.as_ref().is_some_and(|r| r.ok);
    }
}

/// Write `report` to `path` atomically (temporary file, 0600, rename).
pub fn write_report(path: &Path, report: &RebuildReport) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot place {}: {e}", path.display()))
}

pub fn read_report() -> Option<RebuildReport> {
    serde_json::from_str(&std::fs::read_to_string(REPORT).ok()?).ok()
}

pub fn pending() -> bool {
    Path::new(MARKER).exists()
}

// ── The pass ────────────────────────────────────────────────────────────────

/// Called once at startup: does nothing unless the marker is there.
pub async fn run_if_pending(db: PgPool, agent: AgentClient, local_server_id: Uuid) {
    let Ok(marker) = std::fs::read_to_string(MARKER) else { return };
    let snapshot_id = Some(marker.trim().to_string()).filter(|s| !s.is_empty());
    tracing::info!("Off-site restore: rebuilding the site configurations (marker {MARKER} present)");
    let report = rebuild(&db, &AgentHandle::Local(agent), local_server_id, snapshot_id).await;
    if let Err(e) = write_report(Path::new(REPORT), &report) {
        tracing::error!("Off-site restore: the vhost rebuild report could not be written: {e}");
        return;
    }
    let agent_unreachable = report.errors.iter().any(|e| e.starts_with(AGENT_UNREACHABLE));
    if agent_unreachable {
        tracing::error!("Off-site restore: the agent never answered; the rebuild is retried at the next start");
        return;
    }
    if let Err(e) = std::fs::remove_file(MARKER) {
        tracing::error!("Off-site restore: could not remove {MARKER}: {e}");
    }
    tracing::info!(
        "Off-site restore: vhosts rebuilt={} remapped={} failed={} ok={}",
        report.rebuilt,
        report.remapped,
        report.failed,
        report.ok
    );
}

const AGENT_UNREACHABLE: &str = "the agent did not answer";

async fn wait_for_agent(agent: &AgentHandle) -> Result<serde_json::Value, String> {
    let mut last = String::new();
    for _ in 0..30 {
        match agent.get("/system/ips").await {
            Ok(v) => return Ok(v),
            Err(e) => last = agent_message(&e),
        }
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    }
    Err(format!("{AGENT_UNREACHABLE} within 2 minutes: {last}"))
}

async fn rebuild(db: &PgPool, agent: &AgentHandle, local_server_id: Uuid, snapshot_id: Option<String>) -> RebuildReport {
    let mut report = RebuildReport::new(snapshot_id);

    rewrite_key_paths(db, &mut report).await;

    let ips = match wait_for_agent(agent).await {
        Ok(v) => v,
        Err(e) => {
            report.errors.push(e);
            report.finish();
            return report;
        }
    };
    let on_host: Vec<String> = ips
        .get("ips")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.get("ip").and_then(|i| i.as_str()).map(str::to_string)).collect())
        .unwrap_or_default();

    let sites: Vec<Site> = match sqlx::query_as::<_, Site>(
        "SELECT * FROM sites WHERE server_id = $1 OR server_id IS NULL ORDER BY domain",
    )
    .bind(local_server_id)
    .fetch_all(db)
    .await
    {
        Ok(s) => s,
        Err(e) => {
            report.errors.push(format!("could not read the sites: {e}"));
            report.finish();
            return report;
        }
    };
    let declared: Vec<(Uuid, String)> = match sqlx::query_as("SELECT id, ip FROM server_ips").fetch_all(db).await {
        Ok(r) => r,
        Err(e) => {
            report.errors.push(format!("could not read the declared addresses: {e}"));
            Vec::new()
        }
    };
    let addrs: Vec<SiteAddr> =
        sites.iter().map(|s| SiteAddr { site_id: s.id, domain: s.domain.clone(), ip_id: s.ip_id }).collect();
    let remaps = remap_plan(&addrs, &declared, &on_host);

    let handle = agent;
    for mut site in sites {
        let mut result = SiteResult { domain: site.domain.clone(), status: "rebuilt".into(), remapped_from: None, detail: None };
        if let Some(r) = remaps.iter().find(|r| r.site_id == site.id) {
            match sqlx::query("UPDATE sites SET ip_id = NULL WHERE id = $1").bind(site.id).execute(db).await {
                Ok(_) => {
                    site.ip_id = None;
                    result.remapped_from = Some(r.from.clone());
                    tracing::warn!("Off-site restore: {} moved to the primary address ({} is not on this machine)", site.domain, r.from);
                }
                Err(e) => {
                    result.status = "failed".into();
                    result.detail = Some(format!("its address {} is not on this machine and it could not be moved: {e}", r.from));
                    report.sites.push(result);
                    continue;
                }
            }
        }
        let bind = crate::services::server_ips::nginx_bind_ip(db, &site).await;
        let body = crate::routes::sites::build_nginx_body(&site, bind.as_deref());
        match handle.put(&format!("/nginx/sites/{}", site.domain), body).await {
            Ok(_) => {
                if !site.enabled {
                    match handle.post(&format!("/nginx/sites/{}/disable", site.domain), None).await {
                        Ok(_) => result.detail = Some("disabled, as in the panel".into()),
                        Err(e) => {
                            result.status = "failed".into();
                            result.detail = Some(format!("rebuilt but could not be put back to disabled: {}", agent_message(&e)));
                        }
                    }
                }
            }
            Err(e) => {
                result.status = "failed".into();
                result.detail = Some(agent_message(&e));
            }
        }
        report.sites.push(result);
    }

    match agent.post("/nginx/test", None).await {
        Ok(v) => {
            let ok = v.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
            let output = v.get("output").and_then(|s| s.as_str()).unwrap_or("").to_string();
            report.nginx_test = Some(Check { ok, output });
            if ok {
                report.reload = Some(match agent.post("/nginx/reload", None).await {
                    Ok(_) => ReloadResult { ok: true, detail: "nginx reloaded".into() },
                    Err(e) => ReloadResult { ok: false, detail: agent_message(&e) },
                });
            } else {
                report.reload = Some(ReloadResult { ok: false, detail: "not reloaded: nginx -t failed".into() });
            }
        }
        Err(e) => report.errors.push(format!("nginx -t could not be run: {}", agent_message(&e))),
    }
    report.finish();
    report
}

async fn rewrite_key_paths(db: &PgPool, report: &mut RebuildReport) {
    let index_path = Path::new(BACKUP_KEYS_DIR).join("index.json");
    let index: Vec<KeyIndexEntry> = match std::fs::read_to_string(&index_path) {
        Ok(t) => match serde_json::from_str(&t) {
            Ok(i) => i,
            Err(e) => {
                report.errors.push(format!("{} is not valid: {e}", index_path.display()));
                return;
            }
        },
        Err(_) => return, // no SFTP key was copied: nothing to do
    };
    let rows: Vec<(Uuid, String, String, serde_json::Value)> =
        match sqlx::query_as("SELECT id, name, dtype, config FROM backup_destinations").fetch_all(db).await {
            Ok(r) => r,
            Err(e) => {
                report.errors.push(format!("could not read the destinations to restore their SFTP keys: {e}"));
                return;
            }
        };
    let dests: Vec<DestKey> = rows
        .into_iter()
        .map(|(id, name, dtype, config)| DestKey {
            id,
            name,
            dtype,
            key_path: config.get("key_path").and_then(|k| k.as_str()).map(str::to_string),
        })
        .collect();
    let (plan, skipped) = key_rewrite_plan(&index, &dests, Path::new(BACKUP_KEYS_DIR), Path::new(SFTP_KEYS_DIR), &|p| p.is_file());
    for s in skipped {
        tracing::warn!("Off-site restore: {s}");
        report.errors.push(s);
    }
    if plan.is_empty() {
        return;
    }
    if let Err(e) = make_private_dir(Path::new(SFTP_KEYS_DIR)) {
        report.errors.push(format!("cannot create {SFTP_KEYS_DIR}: {e}"));
        return;
    }
    for k in plan {
        if let Err(e) = copy_private(&k.source, Path::new(&k.to)) {
            report.errors.push(format!("destination '{}': the key could not be copied: {e}", k.destination));
            continue;
        }
        match sqlx::query(
            "UPDATE backup_destinations SET config = jsonb_set(config, '{key_path}', to_jsonb($1::text)), updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(&k.to)
        .bind(k.destination_id)
        .execute(db)
        .await
        {
            Ok(_) => {
                tracing::info!("Off-site restore: destination '{}' now uses the restored key {}", k.destination, k.to);
                report.key_paths.push(KeyPathResult { destination: k.destination, from: k.from, to: k.to });
            }
            Err(e) => report.errors.push(format!("destination '{}': key_path not updated: {e}", k.destination)),
        }
    }
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

/// Copy a key 0600 (temporary file then rename).
fn copy_private(from: &Path, to: &Path) -> std::io::Result<()> {
    let tmp = to.with_extension("key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let bytes = zeroize::Zeroizing::new(std::fs::read(from)?);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let r = (|| {
        use std::io::Write;
        let mut f = o.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, to)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn only_sites_whose_address_is_gone_are_moved_to_the_primary() {
        let sites = vec![
            SiteAddr { site_id: u(1), domain: "primary.test".into(), ip_id: None },
            SiteAddr { site_id: u(2), domain: "kept.test".into(), ip_id: Some(u(10)) },
            SiteAddr { site_id: u(3), domain: "gone.test".into(), ip_id: Some(u(11)) },
            SiteAddr { site_id: u(4), domain: "orphan.test".into(), ip_id: Some(u(12)) },
        ];
        let declared = vec![(u(10), "203.0.113.10".to_string()), (u(11), "198.51.100.7".to_string())];
        let on_host = vec!["203.0.113.10".to_string(), "192.0.2.5".to_string()];
        let plan = remap_plan(&sites, &declared, &on_host);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], Remap { site_id: u(3), domain: "gone.test".into(), from: "198.51.100.7".into() });
        assert_eq!(plan[1].site_id, u(4));
        assert!(plan[1].from.starts_with("address "));
        // Nothing on the host at all: every declared site moves, primary ones never.
        let all = remap_plan(&sites, &declared, &[]);
        assert_eq!(all.iter().map(|r| r.site_id).collect::<Vec<_>>(), vec![u(2), u(3), u(4)]);
    }

    #[test]
    fn key_paths_are_rewritten_only_for_the_sftp_destination_they_were_copied_from() {
        let index = vec![
            KeyIndexEntry { destination_id: u(1), destination_name: "a".into(), original_key_path: "/root/.ssh/a".into(), file: format!("{}.key", u(1)) },
            KeyIndexEntry { destination_id: u(2), destination_name: "b".into(), original_key_path: "/root/.ssh/b".into(), file: format!("{}.key", u(2)) },
            KeyIndexEntry { destination_id: u(3), destination_name: "c".into(), original_key_path: "/root/.ssh/c".into(), file: "../../etc/shadow".into() },
            KeyIndexEntry { destination_id: u(4), destination_name: "d".into(), original_key_path: "/root/.ssh/d".into(), file: format!("{}.key", u(4)) },
            KeyIndexEntry { destination_id: u(5), destination_name: "e".into(), original_key_path: "/root/.ssh/e".into(), file: format!("{}.key", u(5)) },
        ];
        let kp = |s: &str| Option::<String>::from(s.to_string());
        let dests = vec![
            DestKey { id: u(1), name: "a".into(), dtype: "sftp".into(), key_path: kp("/root/.ssh/a") },
            DestKey { id: u(2), name: "b".into(), dtype: "sftp".into(), key_path: kp("/root/.ssh/changed") },
            DestKey { id: u(3), name: "c".into(), dtype: "sftp".into(), key_path: kp("/root/.ssh/c") },
            DestKey { id: u(5), name: "e".into(), dtype: "sftp".into(), key_path: kp("/root/.ssh/e") },
        ];
        let keys = Path::new("/etc/dockpanel/backup-keys");
        let target = Path::new("/etc/dockpanel/sftp-keys");
        let missing = keys.join(format!("{}.key", u(5)));
        let (plan, skipped) = key_rewrite_plan(&index, &dests, keys, target, &|p| p != missing.as_path());
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].destination_id, u(1));
        assert_eq!(plan[0].from, "/root/.ssh/a");
        assert_eq!(plan[0].to, format!("/etc/dockpanel/sftp-keys/{}.key", u(1)));
        assert_eq!(plan[0].source, keys.join(format!("{}.key", u(1))));
        // Outside backup-keys/, which the off-site run sweeps.
        assert!(!plan[0].to.starts_with(BACKUP_KEYS_DIR));
        assert_eq!(skipped.len(), 4, "{skipped:?}");
        assert!(skipped.iter().any(|s| s.contains("changed since")));
        assert!(skipped.iter().any(|s| s.contains("invalid file name")));
        assert!(skipped.iter().any(|s| s.contains("no longer exists")));
        assert!(skipped.iter().any(|s| s.contains("missing")));
    }

    #[test]
    fn the_report_is_ok_only_when_every_site_and_nginx_passed() {
        let mut r = RebuildReport::new(Some("x".into()));
        r.sites.push(SiteResult { domain: "a".into(), status: "rebuilt".into(), remapped_from: Some("198.51.100.7".into()), detail: None });
        r.nginx_test = Some(Check { ok: true, output: String::new() });
        r.reload = Some(ReloadResult { ok: true, detail: String::new() });
        r.finish();
        assert!(r.ok);
        assert_eq!((r.rebuilt, r.remapped, r.failed), (1, 1, 0));
        r.sites.push(SiteResult { domain: "b".into(), status: "failed".into(), remapped_from: None, detail: Some("php 7.4 missing".into()) });
        r.finish();
        assert!(!r.ok);
        assert_eq!(r.failed, 1);
        let mut n = RebuildReport::new(None);
        n.nginx_test = Some(Check { ok: false, output: "emerg".into() });
        n.finish();
        assert!(!n.ok, "a failing nginx -t is not ok");
    }

    #[test]
    fn the_report_is_written_atomically_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("dr-post-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("vhost-rebuild.json");
        let mut r = RebuildReport::new(Some("abc".into()));
        r.finish();
        write_report(&p, &r).unwrap();
        let back: RebuildReport = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back, r);
        assert!(!dir.join("vhost-rebuild.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
