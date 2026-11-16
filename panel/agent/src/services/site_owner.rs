//! Who owns a site's files (feature 6, contract A-7).
//!
//! A site without SFTP belongs to `www-data:www-data`. Once SFTP is enabled,
//! `sftp_accounts::provision` re-owns `/var/www/<domain>` to the site's own
//! account (`sftp<uid>:sftpg<gid>` or a custom name), and the PHP-FPM pool runs
//! under that identity. Every routine that used to `chown -R www-data:www-data`
//! a site tree (CMS install, WordPress updates, deploy, backup restore, staging,
//! the Hestia import...) silently took the files away from that account, so
//! neither SFTP nor FTP could write them any more. They now ask [`site_owner`]
//! and re-own through [`chown_site_tree`] / [`chown_site_tree_as`].
//!
//! Reading the owner has to happen BEFORE anything that can recreate the site
//! root (a restore's `create_dir_all`, an `rsync -a` that copies the source
//! root's owner onto the target): callers that do such a step read the owner
//! first and pass it to the `_as` variants.
//!
//! Every chown is `-hR` with numeric ids (a symlink is re-owned itself, never
//! its target) and is refused unless the path stays under `/var/www/<domain>`.

use crate::safe_cmd::{safe_command, safe_command_sync, safe_command_sync_unsandboxed, safe_command_unsandboxed};
use std::path::{Component, Path, PathBuf};

/// `www-data:www-data` on Debian and Ubuntu.
pub const WWW_DATA: (u32, u32) = (33, 33);

/// How many paths one `chown` invocation receives (each escape is a
/// `systemd-run`, so the children of a directory go in as few calls as possible).
const CHUNK: usize = 200;

#[cfg(not(test))]
fn webroot() -> PathBuf {
    PathBuf::from("/var/www")
}
#[cfg(test)]
fn webroot() -> PathBuf {
    std::env::temp_dir().join("dockpanel-site-owner-tests").join("www")
}

/// `/var/www/<domain>` (a temp tree under tests).
pub fn site_root(domain: &str) -> PathBuf {
    webroot().join(domain)
}

/// Owner of a site's files: the uid/gid of `/var/www/<domain>`, or
/// `www-data` (33, 33) when the directory is absent.
///
/// A root-owned site root is not an owner: `deploy.rs` keeps the root of a
/// git-deployed site `root:<group> 3775` on purpose, and a restore or an
/// installer may have just created it as root. Then the SFTP owner marker that
/// names the domain decides, else `www-data`.
pub fn site_owner(domain: &str) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    if !is_plain_domain(domain) {
        return WWW_DATA;
    }
    let stat = std::fs::metadata(site_root(domain)).ok().filter(|m| m.is_dir()).map(|m| (m.uid(), m.gid()));
    resolve_owner(stat, || marker_owner(domain))
}

/// The decision of [`site_owner`] (pure, tested).
pub fn resolve_owner(stat: Option<(u32, u32)>, marker: impl FnOnce() -> Option<(u32, u32)>) -> (u32, u32) {
    match stat {
        None => WWW_DATA,
        Some((uid, gid)) if uid != 0 => (uid, gid),
        Some(_) => marker().unwrap_or(WWW_DATA),
    }
}

/// uid/gid of the SFTP account whose owner marker names `domain`, if it still
/// exists in `/etc/passwd`.
fn marker_owner(domain: &str) -> Option<(u32, u32)> {
    let dir = std::fs::read_dir(crate::services::sftp_accounts::OWNER_MARKER_DIR).ok()?;
    let uid = dir.flatten().find_map(|e| {
        let name = e.file_name().to_string_lossy().into_owned();
        let uid: u32 = name.strip_suffix(".owner")?.parse().ok()?;
        let body = std::fs::read_to_string(e.path()).ok()?;
        crate::services::sftp_accounts::marker_names_domain(&body, domain).then_some(uid)
    })?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd_gid_of(&passwd, uid).map(|gid| (uid, gid))
}

/// Primary gid of `uid` in a passwd file body (pure, tested).
pub fn passwd_gid_of(passwd: &str, uid: u32) -> Option<u32> {
    passwd.lines().find_map(|l| {
        let e = crate::services::sftp_accounts::parse_passwd_line(l)?;
        (e.uid >= 0 && e.uid as u32 == uid && e.gid >= 0).then_some(e.gid as u32)
    })
}

fn is_plain_domain(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.contains("..")
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Lexical guard (pure, tested): `path` is absolute, has no `..`, and lies
/// under `root` (the site root itself included).
pub fn check_under(root: &Path, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("{} contains '..'", path.display()));
    }
    if !path.starts_with(root) {
        return Err(format!("{} is outside {}", path.display(), root.display()));
    }
    Ok(())
}

/// [`check_under`], plus the filesystem: the parent of `path` must resolve
/// (symlinks followed) inside the resolved site root, so a symlinked
/// intermediate directory cannot redirect the chown elsewhere. `path` itself
/// may be a symlink: `-h` re-owns the link, not its target.
fn guard(root: &Path, path: &Path) -> Result<(), String> {
    check_under(root, path)?;
    if path == root {
        return Ok(());
    }
    let real_root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    if let Some(parent) = path.parent() {
        let real_parent = std::fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        if !real_parent.starts_with(&real_root) {
            return Err(format!("{} resolves outside {}", path.display(), root.display()));
        }
    }
    Ok(())
}

/// `chown -hR uid:gid <paths...>` argv (pure, tested).
pub fn chown_args(owner: (u32, u32), paths: &[PathBuf]) -> Vec<String> {
    let mut v = vec!["-hR".to_string(), format!("{}:{}", owner.0, owner.1)];
    v.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    v
}

async fn run_chown(args: &[String]) -> Result<(), String> {
    // The escape first (contract A-7); a box (or a test container) without
    // systemd-run falls back to the sandboxed chown, which can write /var/www.
    let out = match safe_command_unsandboxed("chown", &[]).args(args).output().await {
        Ok(o) => o,
        Err(_) => safe_command("chown").args(args).output().await.map_err(|e| format!("chown could not run: {e}"))?,
    };
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("chown failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn run_chown_sync(args: &[String]) -> Result<(), String> {
    let out = match safe_command_sync_unsandboxed("chown", &[]).args(args).output() {
        Ok(o) => o,
        Err(_) => safe_command_sync("chown").args(args).output().map_err(|e| format!("chown could not run: {e}"))?,
    };
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("chown failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Guarded argv batches for `paths`, all under `domain`'s site root.
fn batches(domain: &str, paths: &[PathBuf], owner: (u32, u32)) -> Result<Vec<Vec<String>>, String> {
    if !is_plain_domain(domain) {
        return Err(format!("Invalid domain: {domain}"));
    }
    let root = site_root(domain);
    for p in paths {
        guard(&root, p)?;
    }
    Ok(paths.chunks(CHUNK).map(|c| chown_args(owner, c)).collect())
}

/// `chown -hR` `path` to the site's current owner ([`site_owner`] read now).
pub async fn chown_site_tree(domain: &str, path: &Path) -> Result<(), String> {
    chown_site_tree_as(domain, path, site_owner(domain)).await
}

/// `chown -hR` `path` to `owner`, read by the caller before a step that could
/// recreate the site root.
pub async fn chown_site_tree_as(domain: &str, path: &Path, owner: (u32, u32)) -> Result<(), String> {
    chown_paths_as(domain, &[path.to_path_buf()], owner).await
}

/// `chown -hR` several paths of one site to `owner`, in as few calls as possible.
pub async fn chown_paths_as(domain: &str, paths: &[PathBuf], owner: (u32, u32)) -> Result<(), String> {
    for args in batches(domain, paths, owner)? {
        run_chown(&args).await?;
    }
    Ok(())
}

/// `chown -h` `path` alone (not recursive) to `owner`, same guard.
pub async fn chown_self_as(domain: &str, path: &Path, owner: (u32, u32)) -> Result<(), String> {
    let mut args = batches(domain, &[path.to_path_buf()], owner)?.remove(0);
    args[0] = "-h".into();
    run_chown(&args).await
}

/// Children of `dir` except `.git` (sorted, for a stable argv).
pub fn children_except_git(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name() != std::ffi::OsStr::new(".git"))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Hand everything in `dir` except `.git` to `owner`, then make `.git` root's
/// and private: the application must never own the repository that root's
/// next deploy runs git (and its hooks) against. `dir` itself is left alone.
pub async fn hand_over_except_git(domain: &str, dir: &Path, owner: (u32, u32)) -> Result<(), String> {
    let children = children_except_git(dir);
    let res = if children.is_empty() { Ok(()) } else { chown_paths_as(domain, &children, owner).await };
    let git = dir.join(".git");
    if git.exists() {
        let g = git.to_string_lossy();
        let _ = safe_command("chown").args(["-hR", "root:root", &g]).output().await;
        let _ = safe_command("chmod").args(["-R", "go-rwx", &g]).output().await;
    }
    res
}

/// Blocking twin of [`hand_over_except_git`], for the synchronous callers
/// (`app_process::create_app_service`).
pub fn hand_over_except_git_blocking(domain: &str, dir: &Path, owner: (u32, u32)) -> Result<(), String> {
    let children = children_except_git(dir);
    let mut res = Ok(());
    if !children.is_empty() {
        match batches(domain, &children, owner) {
            Ok(all) => {
                for args in all {
                    if let Err(e) = run_chown_sync(&args) {
                        res = Err(e);
                        break;
                    }
                }
            }
            Err(e) => res = Err(e),
        }
    }
    let git = dir.join(".git");
    if git.exists() {
        let g = git.to_string_lossy();
        let _ = safe_command_sync("chown").args(["-hR", "root:root", &g]).output();
        let _ = safe_command_sync("chmod").args(["-R", "go-rwx", &g]).output();
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_resolution() {
        // Absent directory: www-data, the marker is not even asked.
        assert_eq!(resolve_owner(None, || panic!("not asked")), WWW_DATA);
        // A real owner wins.
        assert_eq!(resolve_owner(Some((30001, 30001)), || panic!("not asked")), (30001, 30001));
        assert_eq!(resolve_owner(Some((33, 33)), || None), WWW_DATA);
        // Root-owned root (deploy layout, fresh restore): marker, else www-data.
        assert_eq!(resolve_owner(Some((0, 33)), || Some((30002, 30002))), (30002, 30002));
        assert_eq!(resolve_owner(Some((0, 0)), || None), WWW_DATA);
    }

    #[test]
    fn absent_site_falls_back_to_www_data() {
        assert_eq!(site_owner("dp-absent-site.invalid"), WWW_DATA);
        assert_eq!(site_owner("../etc"), WWW_DATA);
        assert_eq!(site_owner(""), WWW_DATA);
    }

    #[test]
    fn existing_non_root_site_reports_its_owner() {
        use std::os::unix::fs::MetadataExt;
        let d = "dp-owner-stat.invalid";
        let root = site_root(d);
        std::fs::create_dir_all(&root).unwrap();
        let md = std::fs::metadata(&root).unwrap();
        let got = site_owner(d);
        if md.uid() != 0 {
            assert_eq!(got, (md.uid(), md.gid()));
        } else {
            // Running as root: the directory is root-owned, so no marker -> www-data
            // (or the owner of a marker naming this test domain, which none does).
            assert_eq!(got, WWW_DATA);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn passwd_gid_lookup() {
        let p = "root:x:0:0:root:/root:/bin/bash\nsftp30001:x:30001:30005::/var/dockpanel-sftp/a.tld:/usr/sbin/nologin\n";
        assert_eq!(passwd_gid_of(p, 30001), Some(30005));
        assert_eq!(passwd_gid_of(p, 30002), None);
    }

    #[test]
    fn path_guard() {
        let root = Path::new("/var/www/a.tld");
        assert!(check_under(root, Path::new("/var/www/a.tld")).is_ok());
        assert!(check_under(root, Path::new("/var/www/a.tld/public/x.php")).is_ok());
        assert!(check_under(root, Path::new("/var/www/a.tld/../b.tld")).is_err());
        assert!(check_under(root, Path::new("/var/www/a.tld.evil/x")).is_err(), "component prefix only");
        assert!(check_under(root, Path::new("/var/www/b.tld")).is_err());
        assert!(check_under(root, Path::new("/etc/passwd")).is_err());
        assert!(check_under(root, Path::new("public/x")).is_err());
    }

    #[test]
    fn guard_refuses_a_symlinked_parent_leading_out() {
        let d = "dp-owner-guard.invalid";
        let root = site_root(d);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("public")).unwrap();
        let outside = std::env::temp_dir().join("dockpanel-site-owner-outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"x").unwrap();
        let _ = std::fs::remove_file(root.join("escape"));
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        assert!(guard(&root, &root.join("public")).is_ok());
        // The link itself is fine (-h re-owns the link, not the target)...
        assert!(guard(&root, &root.join("escape")).is_ok());
        // ...but nothing reached THROUGH it.
        assert!(guard(&root, &root.join("escape/secret")).is_err());
        assert!(batches("dp-owner-guard.invalid", &[root.join("escape/secret")], WWW_DATA).is_err());
        assert!(batches("../x", &[root.join("public")], WWW_DATA).is_err());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn argv_is_numeric_and_does_not_follow_links() {
        let a = chown_args((30001, 30002), &[PathBuf::from("/var/www/a.tld/public")]);
        assert_eq!(a, vec!["-hR", "30001:30002", "/var/www/a.tld/public"]);
        let many: Vec<PathBuf> = (0..450).map(|i| site_root("a.tld").join(format!("f{i}"))).collect();
        std::fs::create_dir_all(site_root("a.tld")).unwrap();
        let b = batches("a.tld", &many, WWW_DATA).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b.iter().map(|v| v.len() - 2).sum::<usize>(), 450);
    }

    #[test]
    fn children_skip_git() {
        let d = "dp-owner-children.invalid";
        let root = site_root(d);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::write(root.join(".env"), b"x").unwrap();
        let c = children_except_git(&root);
        assert_eq!(c, vec![root.join(".env"), root.join("public")]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
