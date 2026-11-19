//! What app data the panel can back up: the volumes and bind mounts of the
//! containers it deployed (one-click templates, compose stacks, Git deploys).
//!
//! The enumeration is the single authority for "may this path be archived":
//! `/volume-backups/create` re-derives the list and refuses anything that is not
//! on it, so the panel can never ask the agent to tar an arbitrary host path.
//!
//! Everything that decides (classification, de-duplication, naming, validators)
//! is a pure function over plain data, tested without a Docker daemon; the
//! Docker call that feeds it is kept thin ([`enumerate_targets`]).
//!
//! A bind mount is included only when its CANONICAL path (symlinks resolved)
//! stays strictly under one of the app data roots (`/var/lib/dockpanel/apps`,
//! `/compose`, `/git-data`). Everything else a container mounts (the Docker
//! socket, tmpfs, `/etc/localtime`, a symlink that leads out of the roots, a
//! source that no longer exists) is reported in `excluded` with its reason,
//! never silently dropped.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// The directories app data may be bind-mounted from. A bind outside them is
/// not app data (or is something the panel did not create) and is excluded.
pub const APP_DATA_ROOTS: [&str; 3] = [
    "/var/lib/dockpanel/apps",
    "/var/lib/dockpanel/compose",
    "/var/lib/dockpanel/git-data",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Volume,
    Bind,
}

impl TargetKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "volume" => Some(Self::Volume),
            "bind" => Some(Self::Bind),
            _ => None,
        }
    }
    /// The letter in the archive name (`{owner}-{v|b}-{slug}-{stamp}`).
    pub fn letter(self) -> char {
        match self {
            Self::Volume => 'v',
            Self::Bind => 'b',
        }
    }
}

/// One mount of one container, as Docker reports it.
#[derive(Debug, Clone)]
pub struct RawMount {
    /// `volume`, `bind`, `tmpfs`, `npipe`, ...
    pub typ: String,
    pub name: Option<String>,
    pub source: Option<String>,
}

/// The verdict on one mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountClass {
    /// A named or anonymous Docker volume. `source` is Docker's mountpoint
    /// (`/var/lib/docker/volumes/{name}/_data`), used to measure it.
    Volume { name: String, source: String },
    /// A bind mount whose canonical path is strictly under an app data root.
    Bind { canonical: PathBuf },
    Excluded(String),
}

pub const REASON_OUTSIDE: &str = "bind outside the app data directories";
pub const REASON_ESCAPE: &str = "symlink escapes the app data directories";
pub const REASON_SOCKET: &str = "Docker socket";
pub const REASON_TMPFS: &str = "tmpfs mount (not persistent)";
pub const REASON_NPIPE: &str = "named pipe";
pub const REASON_MISSING: &str = "source does not exist";
pub const REASON_NOT_DIR: &str = "bind source is not a directory";
pub const REASON_ROOT: &str = "bind covers a whole app data directory, not one app";
pub const REASON_BAD_CHARS: &str = "path contains a character Docker cannot mount (':' or ',')";
pub const REASON_BAD_VOLUME: &str = "invalid volume name";
pub const REASON_NO_MOUNTPOINT: &str = "volume has no local mountpoint";
pub const REASON_BAD_OWNER: &str = "the app name cannot be used as a backup directory name";

fn is_socket_path(p: &str) -> bool {
    p.ends_with("/docker.sock") || p == "docker.sock"
}

/// Canonicalize the app data roots that exist on this host. A root that does
/// not exist cannot contain anything, so it is simply left out.
pub fn app_data_roots() -> Vec<PathBuf> {
    APP_DATA_ROOTS
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect()
}

/// Strictly under one of `roots` (component-wise), not equal to it.
fn under_roots(p: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| p.starts_with(r) && p != r.as_path())
}

/// Classify one mount. `roots` must already be canonical ([`app_data_roots`]).
pub fn classify_mount(m: &RawMount, roots: &[PathBuf]) -> MountClass {
    match m.typ.as_str() {
        "volume" => {
            let Some(name) = m.name.as_deref().filter(|n| is_valid_volume_name(n)) else {
                return MountClass::Excluded(REASON_BAD_VOLUME.into());
            };
            let source = m.source.clone().unwrap_or_default();
            // `enumerate_targets` fills an empty source from the volume itself
            // (`fill_volume_sources`); still empty means truly no local path.
            if source.is_empty() {
                return MountClass::Excluded(REASON_NO_MOUNTPOINT.into());
            }
            MountClass::Volume { name: name.to_string(), source }
        }
        "bind" => {
            let src = m.source.as_deref().unwrap_or_default();
            if src.is_empty() {
                return MountClass::Excluded(REASON_MISSING.into());
            }
            if is_socket_path(src) {
                return MountClass::Excluded(REASON_SOCKET.into());
            }
            let canonical = match std::fs::canonicalize(src) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return MountClass::Excluded(REASON_MISSING.into())
                }
                Err(e) => return MountClass::Excluded(format!("cannot resolve source: {e}")),
            };
            let c_str = canonical.to_string_lossy();
            if is_socket_path(&c_str) {
                return MountClass::Excluded(REASON_SOCKET.into());
            }
            if !under_roots(&canonical, roots) {
                if roots.iter().any(|r| canonical == *r) {
                    return MountClass::Excluded(REASON_ROOT.into());
                }
                // Lexically inside a root but canonically outside: a symlink
                // (the bind itself or a parent) leads out of the app data.
                let lexical = Path::new(src);
                if under_roots(lexical, roots) {
                    return MountClass::Excluded(REASON_ESCAPE.into());
                }
                return MountClass::Excluded(REASON_OUTSIDE.into());
            }
            if c_str.contains(':') || c_str.contains(',') || c_str.contains('\n') {
                return MountClass::Excluded(REASON_BAD_CHARS.into());
            }
            match std::fs::metadata(&canonical) {
                Ok(md) if md.is_dir() => MountClass::Bind { canonical },
                Ok(_) => MountClass::Excluded(REASON_NOT_DIR.into()),
                Err(_) => MountClass::Excluded(REASON_MISSING.into()),
            }
        }
        "tmpfs" => MountClass::Excluded(REASON_TMPFS.into()),
        "npipe" => MountClass::Excluded(REASON_NPIPE.into()),
        other => MountClass::Excluded(format!("unsupported mount type '{other}'")),
    }
}

/// A Docker volume name: `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, at most 255 bytes
/// (Docker's own rule). Replaces the generic `is_valid_name`, which refused the
/// `.` and anything past 64 characters that compose-scoped names can carry.
pub fn is_valid_volume_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 255
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The name of the directory archives of one app live in, and the first part
/// of every archive name: `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, and no `..`
/// (the backup paths refuse `..` anywhere, so an owner holding one could be
/// archived but never encrypted, restored or deleted).
pub fn is_valid_owner_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        && !name.contains("..")
}

fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') { c } else { '_' })
        .collect();
    // No `..` in an archive name (see `is_valid_owner_name`).
    while out.contains("..") {
        out = out.replace("..", "_.");
    }
    out
}

fn hex8(data: &str) -> String {
    let d = Sha256::digest(data.as_bytes());
    hex::encode(&d[..4])
}

fn truncate(s: &str, max: usize) -> String {
    // `sanitize` output is ASCII, so byte slicing is safe.
    s[..s.len().min(max)].to_string()
}

/// Slug of a volume: its name, sanitized, at most 64 characters. A longer name
/// keeps 55 characters plus `-` and 8 hex of its sha256, so two long names that
/// share a prefix still get distinct (and stable) archive names.
pub fn volume_slug(name: &str) -> String {
    let s = sanitize(name);
    if s.len() <= 64 {
        s
    } else {
        format!("{}-{}", truncate(&s, 55), hex8(name))
    }
}

/// Slug of a bind: its last path component, sanitized, at most 40 characters,
/// then `-` and 8 hex of sha256(canonical path). Stable for a given path.
pub fn bind_slug(canonical: &Path) -> String {
    let last = canonical
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "bind".to_string());
    format!("{}-{}", truncate(&last, 40), hex8(&canonical.to_string_lossy()))
}

/// `{owner}-{v|b}-{slug}-` : the prefix every archive of one target shares,
/// which is also the remote-retention `name_prefix`.
pub fn archive_prefix(owner: &str, kind: TargetKind, slug: &str) -> String {
    format!("{owner}-{}-{slug}-", kind.letter())
}

/// `{owner}-{v|b}-{slug}-{%Y%m%d-%H%M%S}.tar.gz` (`.enc` is appended once encrypted).
pub fn archive_name(owner: &str, kind: TargetKind, slug: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{}{}.tar.gz", archive_prefix(owner, kind, slug), now.format("%Y%m%d-%H%M%S"))
}

/// A container as the enumeration needs it.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub running: bool,
    pub labels: HashMap<String, String>,
    pub mounts: Vec<RawMount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetContainer {
    pub id: String,
    pub name: String,
    pub running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupTarget {
    pub kind: TargetKind,
    pub volume_name: Option<String>,
    /// Canonical path of a bind; `None` for a volume.
    pub source_path: Option<String>,
    /// What gets archived on the host: the bind's canonical path or the
    /// volume's mountpoint.
    pub source: String,
    pub owner_name: String,
    pub slug: String,
    pub app_type: String,
    pub stack_id: Option<String>,
    pub containers: Vec<TargetContainer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedMount {
    pub container: String,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TargetsReport {
    pub targets: Vec<BackupTarget>,
    pub excluded: Vec<ExcludedMount>,
}

/// Which app a managed container belongs to: `(app_type, owner_name, stack_id)`.
/// `None` for a managed container that is not an app (database containers,
/// sidecars, the reverse proxy, mail): those are backed up by other means or
/// hold no app data, and stopping them is not this module's business.
pub fn app_identity(name: &str, labels: &HashMap<String, String>) -> Option<(String, String, Option<String>)> {
    if labels.get("dockpanel.managed").map(String::as_str) != Some("true") {
        return None;
    }
    let stack_id = labels.get("dockpanel.stack_id").cloned();
    if labels.get("dockpanel.type").map(String::as_str) == Some("git") {
        let owner = labels.get("dockpanel.git.name")?.clone();
        return Some(("git".into(), owner, None));
    }
    match labels.get("dockpanel.app.template").map(String::as_str) {
        Some("compose") => Some((
            "compose".into(),
            super::compose::stack_scope(stack_id.as_deref()),
            stack_id,
        )),
        Some(_) => Some(("template".into(), name.to_string(), stack_id)),
        None => None,
    }
}

/// Build the report from the containers: classify every mount, then
/// de-duplicate by (kind, volume name | canonical source) so data shared by
/// several services is archived once, listing every container that mounts it.
/// The first container (by name) to mount a target decides its owner.
pub fn build_targets(mut containers: Vec<ContainerInfo>, roots: &[PathBuf]) -> TargetsReport {
    containers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    let mut targets: BTreeMap<(TargetKind, String), BackupTarget> = BTreeMap::new();
    let mut excluded = Vec::new();

    for c in &containers {
        let Some((app_type, owner, stack_id)) = app_identity(&c.name, &c.labels) else {
            continue;
        };
        let owner_ok = is_valid_owner_name(&owner);
        for m in &c.mounts {
            let shown_source = m
                .source
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| m.name.clone().filter(|n| !n.is_empty()))
                // A tmpfs has neither a source nor a name.
                .unwrap_or_else(|| format!("({} mount)", m.typ));
            let class = classify_mount(m, roots);
            let (kind, key, volume_name, source_path, source, slug) = match class {
                MountClass::Excluded(reason) => {
                    excluded.push(ExcludedMount { container: c.name.clone(), source: shown_source, reason });
                    continue;
                }
                MountClass::Volume { name, source } => {
                    let slug = volume_slug(&name);
                    (TargetKind::Volume, name.clone(), Some(name), None, source, slug)
                }
                MountClass::Bind { canonical } => {
                    let p = canonical.to_string_lossy().to_string();
                    (TargetKind::Bind, p.clone(), None, Some(p.clone()), p, bind_slug(&canonical))
                }
            };
            if !owner_ok {
                excluded.push(ExcludedMount {
                    container: c.name.clone(),
                    source: shown_source,
                    reason: REASON_BAD_OWNER.into(),
                });
                continue;
            }
            let entry = targets.entry((kind, key)).or_insert_with(|| BackupTarget {
                kind,
                volume_name,
                source_path,
                source,
                owner_name: owner.clone(),
                slug,
                app_type: app_type.clone(),
                stack_id: stack_id.clone(),
                containers: Vec::new(),
            });
            if !entry.containers.iter().any(|x| x.id == c.id) {
                entry.containers.push(TargetContainer { id: c.id.clone(), name: c.name.clone(), running: c.running });
            }
        }
    }

    let mut targets: Vec<BackupTarget> = targets.into_values().collect();
    targets.sort_by(|a, b| {
        (a.owner_name.as_str(), a.kind, a.slug.as_str()).cmp(&(b.owner_name.as_str(), b.kind, b.slug.as_str()))
    });
    TargetsReport { targets, excluded }
}

/// The current target matching `(kind, volume_name | source_path)`, if any.
/// A bind `source_path` is canonicalized before comparing.
pub fn find_target<'a>(
    report: &'a TargetsReport,
    kind: TargetKind,
    volume_name: Option<&str>,
    source_path: Option<&str>,
) -> Option<&'a BackupTarget> {
    match kind {
        TargetKind::Volume => {
            let name = volume_name?;
            report.targets.iter().find(|t| t.kind == kind && t.volume_name.as_deref() == Some(name))
        }
        TargetKind::Bind => {
            let p = std::fs::canonicalize(source_path?).ok()?;
            let p = p.to_string_lossy();
            report.targets.iter().find(|t| t.kind == kind && t.source_path.as_deref() == Some(&*p))
        }
    }
}

/// Where a bind restore may write: `source_path` re-canonicalized and confined
/// strictly under the app data roots. The directory may be gone (that is when
/// a restore is needed): the deepest existing ancestor is canonicalized and the
/// rest must be plain components, so neither `..` nor a symlink can lead out.
/// The caller creates the returned directory if it does not exist.
pub fn resolve_restore_path(source_path: &str, roots: &[PathBuf]) -> Result<PathBuf, String> {
    let p = Path::new(source_path);
    if !p.is_absolute() {
        return Err("source_path must be an absolute path".into());
    }
    if source_path.contains(':') || source_path.contains(',') || source_path.contains('\n') {
        return Err(REASON_BAD_CHARS.to_string());
    }
    // Refuse `..` anywhere outright (`components()` already drops `.`).
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("source_path contains '..' components".into());
    }
    let mut existing = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(_) => {
                let Some(name) = existing.file_name().map(|n| n.to_os_string()) else {
                    return Err("source_path has no existing ancestor".into());
                };
                rest.push(name);
                if !existing.pop() {
                    return Err("source_path has no existing ancestor".into());
                }
            }
        }
    }
    let mut out = std::fs::canonicalize(&existing).map_err(|e| format!("cannot resolve source_path: {e}"))?;
    for comp in rest.iter().rev() {
        match Path::new(comp).components().next() {
            Some(Component::Normal(_)) => out.push(comp),
            _ => return Err("source_path contains '..' or '.' components".into()),
        }
    }
    if !under_roots(&out, roots) {
        return Err("source_path is outside the app data directories".into());
    }
    let s = out.to_string_lossy();
    if s.contains(':') || s.contains(',') || s.contains('\n') {
        return Err(REASON_BAD_CHARS.to_string());
    }
    Ok(out)
}

/// List the managed containers through Docker and build the report.
pub async fn enumerate_targets() -> Result<TargetsReport, String> {
    use bollard::container::ListContainersOptions;
    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|e| format!("Docker connect failed: {e}"))?;
    let mut filters = HashMap::new();
    filters.insert("label", vec!["dockpanel.managed=true"]);
    let list = docker
        .list_containers(Some(ListContainersOptions { all: true, filters, ..Default::default() }))
        .await
        .map_err(|e| format!("Failed to list containers: {e}"))?;

    let containers = list
        .into_iter()
        .filter_map(|c| {
            let id = c.id?;
            let name = c
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| id.clone());
            let running = matches!(c.state.as_deref(), Some("running") | Some("restarting"));
            let mounts = c
                .mounts
                .unwrap_or_default()
                .into_iter()
                .map(|m| RawMount {
                    typ: m.typ.map(|t| t.to_string()).unwrap_or_default(),
                    name: m.name,
                    // Docker 29 lists an anonymous volume with `Source: ""`.
                    source: m.source.filter(|s| !s.is_empty()),
                })
                .collect();
            Some(ContainerInfo { id, name, running, labels: c.labels.unwrap_or_default(), mounts })
        })
        .collect::<Vec<_>>();

    let mut containers = containers;
    let mut mountpoints = HashMap::new();
    for name in volumes_without_source(&containers) {
        match docker.inspect_volume(&name).await {
            Ok(v) if !v.mountpoint.is_empty() => {
                mountpoints.insert(name, v.mountpoint);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to inspect volume {name}: {e}"),
        }
    }
    fill_volume_sources(&mut containers, &mountpoints, Path::new(DOCKER_VOLUMES_DIR));
    Ok(build_targets(containers, &app_data_roots()))
}

/// Where Docker keeps local volumes, the last resort for a volume's path.
const DOCKER_VOLUMES_DIR: &str = "/var/lib/docker/volumes";

/// Names of the volumes listed without a source (anonymous ones, on Docker 29).
pub fn volumes_without_source(containers: &[ContainerInfo]) -> Vec<String> {
    let mut v: Vec<String> = containers
        .iter()
        .flat_map(|c| c.mounts.iter())
        .filter(|m| m.typ == "volume" && m.source.as_deref().is_none_or(str::is_empty))
        .filter_map(|m| m.name.clone())
        .filter(|n| is_valid_volume_name(n))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Give each volume listed without a source its path: the `Mountpoint` of
/// `docker volume inspect` (`mountpoints`), else `{volumes_dir}/{name}/_data`
/// when that exists. A volume found by neither stays without a source, and
/// is excluded as having no local mountpoint.
pub fn fill_volume_sources(
    containers: &mut [ContainerInfo],
    mountpoints: &HashMap<String, String>,
    volumes_dir: &Path,
) {
    for m in containers.iter_mut().flat_map(|c| c.mounts.iter_mut()) {
        if m.typ != "volume" || !m.source.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        let Some(name) = m.name.as_deref().filter(|n| is_valid_volume_name(n)) else {
            continue;
        };
        m.source = mountpoints.get(name).cloned().or_else(|| {
            let p = volumes_dir.join(name).join("_data");
            p.is_dir().then(|| p.to_string_lossy().to_string())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("dp-targets-{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&p).unwrap();
            Scratch(std::fs::canonicalize(&p).unwrap())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fake `/var/lib/dockpanel` with the three roots, plus an outside dir.
    fn layout() -> (Scratch, Vec<PathBuf>) {
        let s = Scratch::new();
        for r in ["apps", "compose", "git-data", "outside"] {
            std::fs::create_dir_all(s.0.join(r)).unwrap();
        }
        let roots = ["apps", "compose", "git-data"].iter().map(|r| s.0.join(r)).collect();
        (s, roots)
    }

    fn bind(src: &Path) -> RawMount {
        RawMount { typ: "bind".into(), name: None, source: Some(src.to_string_lossy().to_string()) }
    }

    fn excluded(c: MountClass) -> String {
        match c {
            MountClass::Excluded(r) => r,
            other => panic!("expected an exclusion, got {other:?}"),
        }
    }

    /// The seam with Docker: `enumerate_targets` classifies on bollard's
    /// mount type rendered as a string. If that rendering ever changed, every
    /// mount would be "unsupported" and a policy would succeed with 0 targets.
    #[test]
    fn bollard_mount_types_render_as_classify_expects() {
        use bollard::service::MountPointTypeEnum as T;
        assert_eq!(T::BIND.to_string(), "bind");
        assert_eq!(T::VOLUME.to_string(), "volume");
        assert_eq!(T::TMPFS.to_string(), "tmpfs");
        assert_eq!(T::NPIPE.to_string(), "npipe");
    }

    /// Docker 29.1: an anonymous volume is listed with `Source: ""` and its
    /// name; the path comes from inspect, else from the volumes directory.
    #[test]
    fn anonymous_volumes_listed_without_source_get_their_path() {
        let s = Scratch::new();
        let anon = "3f1b9c0e5a7d2b4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d";
        std::fs::create_dir_all(s.0.join(anon).join("_data")).unwrap();
        let tpl = labels(&[("dockpanel.managed", "true"), ("dockpanel.app.template", "wordpress")]);
        let raw = |name: &str| RawMount { typ: "volume".into(), name: Some(name.into()), source: Some(String::new()) };
        let mut cs = vec![ContainerInfo {
            id: "1".into(),
            name: "wp".into(),
            running: true,
            labels: tpl,
            mounts: vec![raw(anon), raw("inspected"), raw("nowhere")],
        }];
        assert_eq!(volumes_without_source(&cs), [anon, "inspected", "nowhere"]);
        let mp = HashMap::from([("inspected".to_string(), "/srv/docker/volumes/inspected/_data".to_string())]);
        fill_volume_sources(&mut cs, &mp, &s.0);
        let r = build_targets(cs, &[]);
        let srcs: Vec<_> = r.targets.iter().map(|t| (t.volume_name.clone().unwrap(), t.source.clone())).collect();
        assert!(srcs.contains(&(anon.to_string(), s.0.join(anon).join("_data").to_string_lossy().to_string())));
        assert!(srcs.contains(&("inspected".to_string(), "/srv/docker/volumes/inspected/_data".to_string())));
        assert_eq!(r.targets.len(), 2);
        // Found by neither: excluded, and shown by its name, not an empty source.
        assert_eq!(r.excluded.len(), 1);
        assert_eq!(r.excluded[0].source, "nowhere");
        assert_eq!(r.excluded[0].reason, REASON_NO_MOUNTPOINT);
    }

    #[test]
    fn binds_under_each_root_are_included() {
        let (s, roots) = layout();
        for r in ["apps/wp/html", "compose/demo/uploads", "git-data/site/data"] {
            let d = s.0.join(r);
            std::fs::create_dir_all(&d).unwrap();
            assert_eq!(classify_mount(&bind(&d), &roots), MountClass::Bind { canonical: d });
        }
    }

    #[test]
    fn binds_outside_the_roots_are_excluded() {
        let (s, roots) = layout();
        assert_eq!(excluded(classify_mount(&bind(&s.0.join("outside")), &roots)), REASON_OUTSIDE);
        assert_eq!(excluded(classify_mount(&bind(Path::new("/etc")), &roots)), REASON_OUTSIDE);
        // The root itself is every app's data, not one app's.
        assert_eq!(excluded(classify_mount(&bind(&s.0.join("apps")), &roots)), REASON_ROOT);
        // A sibling whose name only starts like a root is not under it.
        std::fs::create_dir_all(s.0.join("apps2/x")).unwrap();
        assert_eq!(excluded(classify_mount(&bind(&s.0.join("apps2/x")), &roots)), REASON_OUTSIDE);
    }

    #[test]
    fn the_docker_socket_tmpfs_and_npipe_are_excluded() {
        let (_s, roots) = layout();
        for p in ["/var/run/docker.sock", "/run/docker.sock"] {
            assert_eq!(excluded(classify_mount(&bind(Path::new(p)), &roots)), REASON_SOCKET);
        }
        let t = RawMount { typ: "tmpfs".into(), name: None, source: None };
        assert_eq!(excluded(classify_mount(&t, &roots)), REASON_TMPFS);
        let n = RawMount { typ: "npipe".into(), name: None, source: Some("x".into()) };
        assert_eq!(excluded(classify_mount(&n, &roots)), REASON_NPIPE);
    }

    #[test]
    fn a_symlink_that_escapes_the_roots_is_excluded() {
        let (s, roots) = layout();
        let link = s.0.join("apps/evil");
        symlink(s.0.join("outside"), &link).unwrap();
        assert_eq!(excluded(classify_mount(&bind(&link), &roots)), REASON_ESCAPE);
        // A parent directory that is a symlink is caught the same way.
        let link2 = s.0.join("compose/stack");
        symlink("/etc", &link2).unwrap();
        assert_eq!(excluded(classify_mount(&bind(&link2.join("ssl")), &roots)), REASON_ESCAPE);
        // A symlink to the socket is the socket.
        std::fs::write(s.0.join("outside/docker.sock"), b"").unwrap();
        let link3 = s.0.join("apps/sock");
        symlink(s.0.join("outside/docker.sock"), &link3).unwrap();
        assert_eq!(excluded(classify_mount(&bind(&link3), &roots)), REASON_SOCKET);
    }

    #[test]
    fn a_symlink_that_stays_inside_is_included_under_its_canonical_path() {
        let (s, roots) = layout();
        let real = s.0.join("apps/real");
        std::fs::create_dir_all(&real).unwrap();
        let link = s.0.join("apps/alias");
        symlink(&real, &link).unwrap();
        assert_eq!(classify_mount(&bind(&link), &roots), MountClass::Bind { canonical: real });
    }

    #[test]
    fn a_missing_source_or_a_file_is_excluded() {
        let (s, roots) = layout();
        assert_eq!(excluded(classify_mount(&bind(&s.0.join("apps/gone")), &roots)), REASON_MISSING);
        let f = s.0.join("apps/file.conf");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(excluded(classify_mount(&bind(&f), &roots)), REASON_NOT_DIR);
        let none = RawMount { typ: "bind".into(), name: None, source: None };
        assert_eq!(excluded(classify_mount(&none, &roots)), REASON_MISSING);
    }

    #[test]
    fn named_and_anonymous_volumes_are_included() {
        let roots = vec![];
        let anon = "3f1b9c0e5a7d2b4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d";
        for name in ["demo_pgdata", anon, "a.b-c_d"] {
            let m = RawMount {
                typ: "volume".into(),
                name: Some(name.into()),
                source: Some(format!("/var/lib/docker/volumes/{name}/_data")),
            };
            assert_eq!(
                classify_mount(&m, &roots),
                MountClass::Volume { name: name.into(), source: format!("/var/lib/docker/volumes/{name}/_data") }
            );
        }
        let bad = RawMount { typ: "volume".into(), name: Some("../x".into()), source: Some("/x".into()) };
        assert_eq!(excluded(classify_mount(&bad, &roots)), REASON_BAD_VOLUME);
        let remote = RawMount { typ: "volume".into(), name: Some("nfs".into()), source: None };
        assert_eq!(excluded(classify_mount(&remote, &roots)), REASON_NO_MOUNTPOINT);
    }

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn compose_labels(stack: &str) -> HashMap<String, String> {
        labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.app.template", "compose"),
            ("dockpanel.stack_id", stack),
        ])
    }

    fn vol(name: &str) -> RawMount {
        RawMount { typ: "volume".into(), name: Some(name.into()), source: Some(format!("/v/{name}/_data")) }
    }

    #[test]
    fn shared_mounts_are_deduplicated_and_list_every_container() {
        let (s, roots) = layout();
        let up = s.0.join("compose/demo/uploads");
        std::fs::create_dir_all(&up).unwrap();
        let containers = vec![
            ContainerInfo {
                id: "b2".into(),
                name: "dockpanel-compose-demo-web".into(),
                running: false,
                labels: compose_labels("demo"),
                mounts: vec![vol("demo_pgdata"), bind(&up)],
            },
            ContainerInfo {
                id: "a1".into(),
                name: "dockpanel-compose-demo-db".into(),
                running: true,
                labels: compose_labels("demo"),
                mounts: vec![vol("demo_pgdata"), bind(&up), bind(Path::new("/usr"))],
            },
        ];
        let r = build_targets(containers, &roots);
        assert_eq!(r.targets.len(), 2, "{r:?}");
        for t in &r.targets {
            assert_eq!(t.owner_name, "demo");
            assert_eq!(t.app_type, "compose");
            assert_eq!(t.stack_id.as_deref(), Some("demo"));
            let names: Vec<_> = t.containers.iter().map(|c| c.name.as_str()).collect();
            assert_eq!(names, ["dockpanel-compose-demo-db", "dockpanel-compose-demo-web"]);
        }
        let v = r.targets.iter().find(|t| t.kind == TargetKind::Volume).unwrap();
        assert_eq!(v.volume_name.as_deref(), Some("demo_pgdata"));
        assert_eq!(v.source_path, None);
        assert_eq!(v.slug, "demo_pgdata");
        let b = r.targets.iter().find(|t| t.kind == TargetKind::Bind).unwrap();
        assert_eq!(b.source_path.as_deref(), Some(&*up.to_string_lossy()));
        assert_eq!(b.source, up.to_string_lossy());
        assert_eq!(r.excluded.len(), 1);
        assert_eq!(r.excluded[0].container, "dockpanel-compose-demo-db");
        assert_eq!(r.excluded[0].source, "/usr");
        assert_eq!(r.excluded[0].reason, REASON_OUTSIDE);
    }

    #[test]
    fn owners_come_from_the_app_kind_and_non_apps_are_skipped() {
        let git = labels(&[("dockpanel.managed", "true"), ("dockpanel.type", "git"), ("dockpanel.git.name", "site")]);
        assert_eq!(app_identity("dockpanel-git-site", &git), Some(("git".into(), "site".into(), None)));
        let tpl = labels(&[("dockpanel.managed", "true"), ("dockpanel.app.template", "wordpress")]);
        assert_eq!(app_identity("dockpanel-wp", &tpl), Some(("template".into(), "dockpanel-wp".into(), None)));
        // Compose: the stack scope, the same token that prefixes its volumes.
        let c = compose_labels("0b5e-41aa-9c3f-77d2e1f0a9b8");
        assert_eq!(app_identity("x", &c).unwrap().1, "0b5e41aa9c3f");
        // Database containers, sidecars, unmanaged: not apps.
        let db = labels(&[("dockpanel.managed", "true"), ("dockpanel.db.name", "x")]);
        assert_eq!(app_identity("db", &db), None);
        let side = labels(&[("dockpanel.managed", "true"), ("dockpanel.sidecar_of", "x")]);
        assert_eq!(app_identity("s", &side), None);
        let unmanaged = labels(&[("dockpanel.app.template", "wordpress")]);
        assert_eq!(app_identity("u", &unmanaged), None);
    }

    #[test]
    fn an_owner_unfit_for_a_directory_name_is_excluded_not_dropped() {
        let git = labels(&[("dockpanel.managed", "true"), ("dockpanel.type", "git"), ("dockpanel.git.name", "a..b")]);
        let r = build_targets(
            vec![ContainerInfo { id: "1".into(), name: "g".into(), running: true, labels: git, mounts: vec![vol("data")] }],
            &[],
        );
        assert!(r.targets.is_empty());
        assert_eq!(r.excluded[0].reason, REASON_BAD_OWNER);
    }

    #[test]
    fn slugs_and_names() {
        assert_eq!(volume_slug("demo_pgdata"), "demo_pgdata");
        assert_eq!(volume_slug("my.vol"), "my.vol");
        // Dot runs never survive (the backup paths refuse `..`).
        assert!(!volume_slug("a..b").contains(".."));
        assert!(!volume_slug("a...b").contains(".."));
        let long = "x".repeat(200);
        let s = volume_slug(&long);
        assert_eq!(s.len(), 64);
        assert_eq!(s, volume_slug(&long), "stable");
        assert_ne!(s, volume_slug(&format!("{long}y")), "distinct past the cut");

        let p = Path::new("/var/lib/dockpanel/compose/demo/uploads");
        let b = bind_slug(p);
        assert_eq!(b, bind_slug(p), "stable");
        assert!(b.starts_with("uploads-"));
        assert_eq!(b.len(), "uploads-".len() + 8);
        assert_ne!(b, bind_slug(Path::new("/var/lib/dockpanel/apps/x/uploads")));
        let odd = bind_slug(Path::new("/var/lib/dockpanel/apps/x/with space"));
        assert!(odd.starts_with("with_space-"));
        let longc = bind_slug(&Path::new("/var/lib/dockpanel/apps").join("y".repeat(90)));
        assert_eq!(longc.len(), 40 + 1 + 8);

        let now = chrono::DateTime::parse_from_rfc3339("2026-11-19T03:30:05Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(archive_name("demo", TargetKind::Volume, "demo_pgdata", now), "demo-v-demo_pgdata-20261119-033005.tar.gz");
        assert_eq!(archive_prefix("demo", TargetKind::Bind, "uploads-1a2b3c4d"), "demo-b-uploads-1a2b3c4d-");
    }

    #[test]
    fn validators() {
        assert!(is_valid_volume_name("demo_pgdata"));
        assert!(is_valid_volume_name("a.b-c_d"));
        assert!(is_valid_volume_name(&"a".repeat(255)));
        assert!(!is_valid_volume_name(&"a".repeat(256)));
        for bad in ["", ".x", "_x", "-x", "a/b", "a b", "a:b", "é"] {
            assert!(!is_valid_volume_name(bad), "{bad}");
        }
        assert!(is_valid_owner_name("demo"));
        assert!(is_valid_owner_name("dockpanel-my.app_1"));
        assert!(is_valid_owner_name(&"a".repeat(128)));
        assert!(!is_valid_owner_name(&"a".repeat(129)));
        for bad in ["", ".x", "a/b", "a..b", "..", "a b", "-x"] {
            assert!(!is_valid_owner_name(bad), "{bad}");
        }
        assert_eq!(TargetKind::parse("volume"), Some(TargetKind::Volume));
        assert_eq!(TargetKind::parse("bind"), Some(TargetKind::Bind));
        assert_eq!(TargetKind::parse("tmpfs"), None);
    }

    #[test]
    fn restore_paths_are_confined() {
        let (s, roots) = layout();
        let existing = s.0.join("compose/demo/uploads");
        std::fs::create_dir_all(&existing).unwrap();
        assert_eq!(resolve_restore_path(&existing.to_string_lossy(), &roots).unwrap(), existing);
        // Gone (the usual restore case): resolved through the existing ancestor.
        let gone = s.0.join("compose/demo/new/deeper");
        assert_eq!(resolve_restore_path(&gone.to_string_lossy(), &roots).unwrap(), gone);
        // Traversal, outside, the root itself, relative, odd characters.
        let up = format!("{}/compose/demo/../../outside", s.0.display());
        assert!(resolve_restore_path(&up, &roots).is_err());
        let up_gone = format!("{}/compose/nothere/../../outside", s.0.display());
        assert!(resolve_restore_path(&up_gone, &roots).is_err());
        assert!(resolve_restore_path(&s.0.join("outside/x").to_string_lossy(), &roots).is_err());
        assert!(resolve_restore_path(&s.0.join("apps").to_string_lossy(), &roots).is_err());
        assert!(resolve_restore_path("relative/path", &roots).is_err());
        assert!(resolve_restore_path(&format!("{}/apps/a:b", s.0.display()), &roots).is_err());
        // A symlink inside a root that leads out is followed, then refused.
        let link = s.0.join("apps/esc");
        symlink(s.0.join("outside"), &link).unwrap();
        assert!(resolve_restore_path(&link.join("data").to_string_lossy(), &roots).is_err());
        assert!(resolve_restore_path(&link.to_string_lossy(), &roots).is_err());
    }

    #[test]
    fn find_target_matches_kind_and_identity() {
        let (s, roots) = layout();
        let up = s.0.join("apps/x/data");
        std::fs::create_dir_all(&up).unwrap();
        let tpl = labels(&[("dockpanel.managed", "true"), ("dockpanel.app.template", "wordpress")]);
        let r = build_targets(
            vec![ContainerInfo { id: "1".into(), name: "x".into(), running: true, labels: tpl, mounts: vec![vol("x_db"), bind(&up)] }],
            &roots,
        );
        assert!(find_target(&r, TargetKind::Volume, Some("x_db"), None).is_some());
        assert!(find_target(&r, TargetKind::Volume, Some("other"), None).is_none());
        assert!(find_target(&r, TargetKind::Bind, None, Some(&up.to_string_lossy())).is_some());
        // Same data under a non-canonical spelling.
        let alt = format!("{}/apps/x/./data", s.0.display());
        assert!(find_target(&r, TargetKind::Bind, None, Some(&alt)).is_some());
        // A bind path is not a volume name and vice versa.
        assert!(find_target(&r, TargetKind::Bind, None, Some("/etc")).is_none());
        assert!(find_target(&r, TargetKind::Volume, None, Some(&up.to_string_lossy())).is_none());
    }

    #[test]
    fn an_excluded_tmpfs_shows_a_label_not_an_empty_source() {
        let tpl = labels(&[("dockpanel.managed", "true"), ("dockpanel.app.template", "redis")]);
        let tmpfs = RawMount { typ: "tmpfs".into(), name: None, source: Some(String::new()) };
        let r = build_targets(
            vec![ContainerInfo { id: "1".into(), name: "x".into(), running: true, labels: tpl, mounts: vec![tmpfs] }],
            &[],
        );
        assert_eq!(r.excluded.len(), 1);
        assert_eq!(r.excluded[0].source, "(tmpfs mount)");
    }
}
