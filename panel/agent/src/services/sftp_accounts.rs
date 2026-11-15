//! Per-site SFTP accounts (GH #108).
//!
//! Each SFTP-enabled site gets its own Linux uid/gid (allocated by the panel,
//! `sites.sftp_uid`/`sftp_gid`), which becomes the REAL owner of
//! `/var/www/{domain}` - the actual per-tenant isolation. A separate jail tree
//! under `/var/dockpanel-sftp/{domain}` is the OpenSSH `ChrootDirectory`
//! (root-owned, as OpenSSH requires); its one `content/` subdirectory is
//! bind-mounted (a dedicated systemd `.mount` unit, not `/etc/fstab`) onto the
//! real, UNMOVED `/var/www/{domain}` - no nginx/PHP-FPM/WP-CLI/CMS-installer
//! path anywhere else in the codebase ever needs to change. Membership in the
//! shared `SFTP_GROUP` is what scopes sshd's one `Match` block to these users;
//! it is created once and never touched again after the first site enables.
//!
//! `useradd`/`groupadd`/`chown`/`usermod` all run via `safe_command_unsandboxed`
//! (the `systemd-run` escape, same as the `vmail` user in `routes/mail.rs`) -
//! `/etc/passwd`/`shadow`/`group` sit outside the agent's own `ReadWritePaths`.

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use sha_crypt::{PasswordHasher, ShaCrypt};

/// The shared secondary group every per-site SFTP user is a member of.
/// `Match Group` in the sshd drop-in scopes the chroot to exactly this group -
/// created once, by name (no fixed gid needed; useradd/sshd both accept names).
pub const SFTP_GROUP: &str = "sftp_sites";

const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/99-dockpanel-sftp.conf";

/// Where the panel records which domain owns an allocated uid - read by
/// [`crate::services::ownership::sftp_user`] before any teardown touches a
/// real Linux account. Kept outside both the chroot jail and `/var/www` so
/// the SFTP user's own session can never reach or edit it.
pub const OWNER_MARKER_DIR: &str = "/etc/dockpanel/sftp-owners";

pub fn sftp_username(uid: i32) -> String {
    format!("sftp{uid}")
}

pub fn sftp_groupname(gid: i32) -> String {
    format!("sftpg{gid}")
}

// --- import-hestia (05) W4-S: custom SFTP account names ---

/// System and service accounts a custom SFTP name may never take, even when
/// absent from this box's `/etc/passwd` (a package installed later would
/// collide with a jailed tenant account of the same name).
const RESERVED_USERNAMES: &[&str] = &[
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
    "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "nogroup", "sshd",
    "messagebus", "syslog", "systemd-network", "systemd-resolve", "systemd-timesync",
    "_apt", "nginx", "apache", "apache2", "httpd", "postfix", "postdrop", "dovecot",
    "dovenull", "vmail", "opendkim", "rspamd", "redis", "mysql", "mariadb", "postgres",
    "docker", "ftp", "sftp", "admin", "administrator", "dockpanel", "cyberhunter",
    "clamav", "bind", "named", "pdns", "fail2ban", "ubuntu", "debian", "operator",
    SFTP_GROUP,
];

/// `^[a-z_][a-z0-9_.-]{0,31}$` - the shape every Linux tool accepts as an
/// account name (D6), checked by hand rather than by a regex dependency.
pub fn is_valid_custom_username(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-'))
}

/// Why a requested SFTP name cannot be used for `uid`, decided without
/// touching the system (pure, tested). `None` = acceptable so far; the caller
/// still asks `getent`.
pub fn username_static_conflict(name: &str, uid: i32) -> Option<&'static str> {
    if !is_valid_custom_username(name) {
        return Some("invalid");
    }
    if RESERVED_USERNAMES.contains(&name) {
        return Some("reserved");
    }
    // `sftp<digits>` and `sftpg<digits>` are the panel's own namespace: only
    // this uid's own default name is allowed, never another allocation's.
    for prefix in ["sftpg", "sftp"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
                return if prefix == "sftp" && rest == uid.to_string() { None } else { Some("panel_namespace") };
            }
        }
    }
    None
}

/// Does `getent <db> <name>` know this name?
async fn getent_has(db: &str, name: &str) -> bool {
    safe_command("getent")
        .args([db, name])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Why [`provision`] refused: a name problem the caller can fix (400 / 409),
/// or a provisioning failure (500).
#[derive(Debug)]
pub enum ProvisionError {
    InvalidUsername(String),
    UsernameTaken(String),
    Failed(String),
}

impl From<String> for ProvisionError {
    fn from(e: String) -> Self {
        ProvisionError::Failed(e)
    }
}

/// Account name of `uid` (the owner marker's `User=`, else `sftp<uid>`).
pub fn account_name(uid: i32) -> String {
    crate::services::ownership::sftp_account_name(uid)
}

/// Resolve and check the account name `provision` will create.
async fn resolve_username(uid: i32, requested: Option<&str>) -> Result<String, ProvisionError> {
    let default = sftp_username(uid);
    let name = match requested.map(str::trim).filter(|n| !n.is_empty()) {
        None => return Ok(default),
        Some(n) if n == default => return Ok(default),
        Some(n) => n.to_string(),
    };
    match username_static_conflict(&name, uid) {
        Some("invalid") => {
            return Err(ProvisionError::InvalidUsername(format!(
                "Invalid SFTP username {name:?}: lowercase letters, digits, '_', '.', '-', \
                 starting with a letter or '_', at most 32 characters"
            )))
        }
        Some(why) => {
            return Err(ProvisionError::UsernameTaken(format!(
                "SFTP username {name:?} is not available ({why})"
            )))
        }
        None => {}
    }
    if getent_has("passwd", &name).await || getent_has("group", &name).await {
        return Err(ProvisionError::UsernameTaken(format!(
            "SFTP username {name:?} already exists on this server"
        )));
    }
    Ok(name)
}

/// The owner marker body: whole-line `Domain=` (read by
/// [`crate::services::ownership::sftp_user`]) and `User=`.
pub fn owner_marker_body(domain: &str, username: &str) -> String {
    format!("Domain={domain}\nUser={username}\n")
}

/// `$<id>$...` crypt(3) hash accepted by [`set_password_hash`], with the
/// scheme name reported back. Pure (tested); the value itself is never logged.
pub fn crypt_hash_scheme(hash: &str) -> Result<&'static str, String> {
    if hash.is_empty() || hash.len() > 255 {
        return Err("hash length out of range".into());
    }
    if hash.bytes().any(|c| matches!(c, b':' | b' ' | b'\n' | b'\r' | b'\t' | b'\0')) {
        return Err("hash contains a forbidden character".into());
    }
    let rest = hash.strip_prefix('$').ok_or("not a crypt(3) hash")?;
    let (id, body) = rest.split_once('$').ok_or("not a crypt(3) hash")?;
    let scheme = match id {
        "y" => "yescrypt",
        "gy" => "gost-yescrypt",
        "7" => "scrypt",
        "6" => "sha512crypt",
        "5" => "sha256crypt",
        "2a" | "2b" | "2x" | "2y" => "bcrypt",
        "1" => "md5crypt",
        _ => return Err("unknown crypt(3) scheme".into()),
    };
    if body.is_empty()
        || !body
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'/' | b'$' | b',' | b'=' | b'-'))
    {
        return Err("malformed crypt(3) hash".into());
    }
    Ok(scheme)
}

/// Why a hash could not be applied. Either way the account stays locked.
#[derive(Debug)]
pub enum HashApplyError {
    /// The platform's crypt(3) cannot verify this scheme (or the hash is malformed).
    Unsupported(String),
    Failed(String),
}

/// Does this box's crypt(3) know the hash's scheme? Asked through Perl's
/// `crypt`, which is libc's/libxcrypt's - the very function PAM calls. The
/// hash goes on stdin, never in argv. `None` = could not tell (no Perl).
async fn platform_supports_hash(hash: &str) -> Option<bool> {
    use tokio::io::AsyncWriteExt;
    const PROBE: &str = r#"my $h = <STDIN>; chomp $h; my ($id) = $h =~ /^\$([^\$]+)\$/; my $r = crypt("probe", $h); exit((defined $r && defined $id && index($r, "\$$id\$") == 0) ? 0 : 3);"#;
    let mut child = safe_command("perl")
        .args(["-e", PROBE])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("{hash}\n").as_bytes()).await;
    }
    let status = tokio::time::timeout(std::time::Duration::from_secs(20), child.wait()).await.ok()?.ok()?;
    match status.code() {
        Some(0) => Some(true),
        Some(3) => Some(false),
        _ => None,
    }
}

/// Lock `uid`'s account (`usermod -L`). Best-effort, logged.
pub async fn lock_account(uid: i32) {
    let username = account_name(uid);
    match safe_command_unsandboxed("usermod", &[]).args(["-L", &username]).output().await {
        Ok(o) if o.status.success() => {}
        Ok(o) => tracing::warn!("usermod -L {username} failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => tracing::warn!("usermod -L {username} failed to run: {e}"),
    }
}

/// Apply an existing crypt(3) hash (a HestiaCP `FTP_MD5`, yescrypt `$y$`) to
/// `uid`'s account with `chpasswd -e`.
///
/// The `<user>:<hash>` line reaches `chpasswd` on its stdin through a 0600
/// file under `/var/lib/dockpanel` (root only), never as an argument: the
/// privileged escape ([`safe_command_unsandboxed`]) cannot pass a pipe, and an
/// argument would sit in the transient unit's command line. The file is
/// removed whatever the outcome. The hash is never logged.
pub async fn set_password_hash(uid: i32, crypt_hash: &str) -> Result<(), HashApplyError> {
    crypt_hash_scheme(crypt_hash).map_err(HashApplyError::Unsupported)?;
    if platform_supports_hash(crypt_hash).await == Some(false) {
        return Err(HashApplyError::Unsupported(
            "this server's crypt(3) cannot verify the hash scheme".into(),
        ));
    }
    let username = account_name(uid);
    let dir = std::path::Path::new("/var/lib/dockpanel/sftp-chpasswd");
    std::fs::create_dir_all(dir).map_err(|e| HashApplyError::Failed(format!("create {}: {e}", dir.display())))?;
    let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let path = dir.join(format!("{}.in", uuid::Uuid::new_v4().simple()));
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        f.write_all(format!("{username}:{crypt_hash}\n").as_bytes())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&path);
        return Err(HashApplyError::Failed(format!("could not stage the hash: {e}")));
    }
    let path_s = path.to_string_lossy().to_string();
    let out = safe_command_unsandboxed("sh", &[])
        .args(["-c", "exec chpasswd -e < \"$1\"", "sh", &path_s])
        .output()
        .await;
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(HashApplyError::Failed(format!(
            "chpasswd -e failed for {username}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))),
        Err(e) => Err(HashApplyError::Failed(format!("chpasswd failed to run: {e}"))),
    }
}
// --- end import-hestia (05) ---

fn jail_root(domain: &str) -> String {
    format!("/var/dockpanel-sftp/{domain}")
}

fn jail_content_dir(domain: &str) -> String {
    format!("{}/content", jail_root(domain))
}

pub fn owner_marker_path(uid: i32) -> String {
    format!("{OWNER_MARKER_DIR}/{uid}.owner")
}

/// Compute the systemd unit name for `content_dir`'s bind mount via
/// `systemd-escape`, rather than hand-rolling systemd's path-escaping rules
/// (`-` -> `\x2d` etc.) - a `.mount` unit's filename MUST exactly match the
/// escaped `Where=` path or systemd will not track the mount against it.
async fn mount_unit_name(content_dir: &str) -> Result<String, String> {
    let output = safe_command("systemd-escape")
        .args(["--path", "--suffix=mount", content_dir])
        .output()
        .await
        .map_err(|e| format!("systemd-escape failed to run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemd-escape failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Provision the SFTP account for `domain`: shared group (once), per-site
/// user+group, the jail tree, the bind-mount unit, and re-owns the site's real
/// content directory. Idempotent on the group/sshd-group-membership steps;
/// NOT idempotent on the user/mount-unit steps (`enable_sftp` on the backend
/// already no-ops when `sftp_enabled` is already true, so this only ever runs
/// once per site).
///
/// `requested_username` (05-import-hestia D6): a custom account name instead
/// of `sftp<uid>`, checked by [`resolve_username`] before anything is created
/// and recorded in the owner marker for every later operation.
pub async fn provision(
    domain: &str,
    uid: i32,
    gid: i32,
    requested_username: Option<&str>,
) -> Result<(), ProvisionError> {
    let username = resolve_username(uid, requested_username).await?;
    provision_as(domain, uid, gid, username).await.map_err(ProvisionError::Failed)
}

async fn provision_as(domain: &str, uid: i32, gid: i32, username: String) -> Result<(), String> {
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");
    if !std::path::Path::new(&site_dir).exists() {
        return Err(format!("{site_dir} does not exist - cannot enable SFTP"));
    }

    // 1. Shared secondary group - idempotent, ignore "already exists".
    let _ = safe_command_unsandboxed("groupadd", &[])
        .args([SFTP_GROUP])
        .output()
        .await;

    // 2. Per-site primary group, then the user itself. Both are genuinely new
    // per site - a failure here must be a real error, not swallowed.
    let out = safe_command_unsandboxed("groupadd", &[])
        .args(["-g", &gid.to_string(), &groupname])
        .output()
        .await
        .map_err(|e| format!("groupadd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "groupadd {groupname} (gid {gid}) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let jail = jail_root(domain);
    let out = safe_command_unsandboxed("useradd", &[])
        .args([
            "-u",
            &uid.to_string(),
            "-g",
            &groupname,
            "-G",
            SFTP_GROUP,
            "-d",
            &jail,
            "-s",
            "/usr/sbin/nologin",
            &username,
        ])
        .output()
        .await
        .map_err(|e| format!("useradd failed to run: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        // Roll back the group we just created - a half-provisioned site (group
        // present, no user) is worse than none, since a retry's groupadd would
        // then fail on "already exists" and mask the real problem.
        let _ = safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await;
        return Err(format!("useradd {username} (uid {uid}) failed: {stderr}"));
    }

    // 3. Jail tree: root-owned boundary (OpenSSH requires this, not
    // configurable), empty content/ mountpoint. `/var/dockpanel-sftp` is a
    // brand-new top-level directory this feature creates on first use, so a
    // plain `std::fs::create_dir_all` here hits the same EROFS the vmail
    // directory does in `routes/mail.rs`: ProtectSystem=strict namespaces the
    // agent's writable set at unit START, and a path that did not exist then
    // is not in it regardless of what ReadWritePaths later gets updated to
    // say - only the systemd-run escape can create it live. (Live-verified on
    // a fresh VPS: the plain std::fs call failed with exactly this error
    // before this fix.)
    let content_dir = jail_content_dir(domain);
    let out = safe_command_unsandboxed("mkdir", &[])
        .args(["-p", &content_dir])
        .output()
        .await
        .map_err(|e| format!("mkdir failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to create jail tree {content_dir}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let _ = safe_command_unsandboxed("chown", &[]).args(["root:root", &jail]).output().await;
    let _ = safe_command_unsandboxed("chmod", &[]).args(["0755", &jail]).output().await;

    // 4. Bind-mount content/ onto the REAL, unmoved site directory.
    let unit_name = mount_unit_name(&content_dir).await?;
    let unit = format!(
        "[Unit]\n\
         Description=CyberHunter - Panel SFTP jail content mount: {domain}\n\
         \n\
         [Mount]\n\
         What={site_dir}\n\
         Where={content_dir}\n\
         Type=none\n\
         Options=bind\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let unit_path = format!("/etc/systemd/system/{unit_name}");
    if let Err(e) = std::fs::write(&unit_path, &unit) {
        return Err(format!("Failed to write mount unit {unit_path}: {e}"));
    }
    let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
    let out = safe_command("systemctl")
        .args(["enable", "--now", &unit_name])
        .output()
        .await
        .map_err(|e| format!("Failed to start {unit_name}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to start {unit_name}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // 5. The actual isolation: re-own the real site directory. PHP-FPM's pool
    // is re-pointed at this same identity by the caller (`put_site`, driven by
    // `pool_user`/`pool_group` on the next vhost rebuild - the backend sends
    // those the moment `sftp_enabled` flips true).
    let out = safe_command_unsandboxed("chown", &[])
        .args(["-R", &format!("{username}:{groupname}"), &site_dir])
        .output()
        .await
        .map_err(|e| format!("chown failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -R {username}:{groupname} {site_dir} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // 6. Owner marker - written last, only once every step above has actually
    // succeeded, so a marker on disk is never a promise this function did not
    // keep.
    if let Err(e) = std::fs::create_dir_all(OWNER_MARKER_DIR) {
        return Err(format!("Failed to create {OWNER_MARKER_DIR}: {e}"));
    }
    if let Err(e) = std::fs::write(owner_marker_path(uid), owner_marker_body(domain, &username)) {
        return Err(format!("Failed to write owner marker for uid {uid}: {e}"));
    }

    ensure_sshd_dropin().await?;

    tracing::info!("SFTP provisioned for {domain}: user={username} uid={uid} gid={gid}");
    Ok(())
}

/// Tear down everything [`provision`] created. `last_sftp_site` tells us
/// whether to also remove the shared sshd drop-in - the caller (the backend)
/// derives this from the `sites` table, not from re-scanning this box, since
/// the DB is the source of truth for how many sites still have SFTP enabled.
pub async fn deprovision(domain: &str, uid: i32, gid: i32, last_sftp_site: bool) -> Result<(), String> {
    if !crate::services::ownership::sftp_user(uid, domain).may_delete() {
        return Err(format!(
            "uid {uid} does not carry an owner marker naming {domain} - refusing to tear down \
             an account this agent cannot prove belongs to this site"
        ));
    }

    // Read from the marker BEFORE it is removed below (custom names, D6).
    let username = account_name(uid);
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");

    // 1. Detach the bind mount FIRST - a chown while the site dir is still
    // mounted into the jail is safe either way (the mount is transparent to
    // path-based tools), but tearing down in this order means a failure here
    // leaves the account still enabled rather than half-disabled.
    let content_dir = jail_content_dir(domain);
    if let Ok(unit_name) = mount_unit_name(&content_dir).await {
        let unit_path = format!("/etc/systemd/system/{unit_name}");
        if std::path::Path::new(&unit_path).exists() {
            let _ = safe_command("systemctl").args(["stop", &unit_name]).output().await;
            let _ = safe_command("systemctl").args(["disable", &unit_name]).output().await;
            let _ = std::fs::remove_file(&unit_path);
            let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
        }
    }

    // 2. Revert the real content back to the shared identity every other site
    // uses. The caller updates `sftp_enabled = false` and rebuilds the vhost
    // (reverting the PHP-FPM pool) in the SAME transition - order between
    // this and that rebuild does not matter, since both converge on
    // `www-data` and neither reads the other's intermediate state.
    if std::path::Path::new(&site_dir).exists() {
        let _ = safe_command_unsandboxed("chown", &[])
            .args(["-R", "www-data:www-data", &site_dir])
            .output()
            .await;
    }

    // 3. Remove the jail scaffolding - this is agent-created infrastructure,
    // never site data (the real content lived at `site_dir` the whole time).
    // Same unsandboxed-escape requirement as creation (see provision()).
    let jail = jail_root(domain);
    let out = safe_command_unsandboxed("rm", &[]).args(["-rf", &jail]).output().await;
    match out {
        Ok(o) if !o.status.success() => tracing::warn!(
            "Failed to remove jail tree {jail}: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("Failed to remove jail tree {jail}: {e}"),
        Ok(_) => {}
    }

    // 3.5. Stop this domain's PHP-FPM pool entirely - removed, not merely
    // reverted, and RELOADED before any process is killed.
    //
    // Live-verified this is the actual fix step 4's `pkill` alone is not:
    // killing the pool's workers does not stop the php-fpm MASTER (running
    // as root, unaffected by `pkill -u <uid>`) from immediately respawning
    // new ones under the same uid per `pm.start_servers`/`pm.min_spare_
    // servers` in the pool config that is STILL ON DISK - a pkill-then-
    // userdel sequence lost this race every time, new worker PIDs appearing
    // between the two calls. Only removing the pool file itself and
    // reloading stops the master from wanting workers under this identity
    // at all. Every caller converges on this domain having NO SFTP-owned
    // pool afterward regardless of what it separately does next: `disable`'s
    // vhost rebuild recreates a fresh www-data pool moments later; site
    // deletion's own later pool-file removal (`nginx.rs::delete_site`) finds
    // nothing left and is a no-op, exactly like every other `if path.exists()`
    // step there already tolerates.
    for &version in crate::services::php_pool::PHP_VERSIONS {
        let pool_path = format!("/etc/php/{version}/fpm/pool.d/{}.conf", domain.replace('.', "_"));
        if std::path::Path::new(&pool_path).exists() {
            if let Err(e) = std::fs::remove_file(&pool_path) {
                tracing::warn!("Failed to remove PHP-FPM pool {pool_path} before SFTP teardown: {e}");
            }
            if let Err(e) = crate::services::nginx::reload_php_fpm(version).await {
                tracing::warn!("Failed to reload php{version}-fpm before SFTP teardown: {e}");
            }
        }
    }

    // 4. Kill anything still running as this uid, THEN remove the account.
    //
    // Live-verified twice, via two DIFFERENT callers: `userdel` refuses to
    // remove a uid with a running process, and the PHP-FPM pool's own
    // workers are still alive under it at this point unless the caller
    // happened to revert+reload the pool first. The `disable` path does that
    // (as a necessary step in its own right - the pool must go back to
    // www-data regardless), which was enough to unblock userdel there. Site
    // DELETION's teardown only ever *removes the pool config file*
    // (`nginx.rs::delete_site`, no reload) - deleting the file does not stop
    // an already-running worker, so the exact same "account still exists
    // after teardown reports success" failure reproduced through that path
    // with no shared code to have fixed it in one place. Rather than adding
    // a third caller-side ordering requirement (or trusting a fourth one
    // later gets it right), this function no longer depends on the caller
    // having cleared the uid's processes at all: `pkill -9 -u` first, THEN
    // userdel, makes deprovision() correct on its own regardless of what
    // else is or isn't still running under this identity.
    let _ = safe_command_unsandboxed("pkill", &[]).args(["-9", "-u", &uid.to_string()]).output().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Best-effort (matching every other cleanup step above), but LOGGED - a
    // swallowed failure here previously meant "disabled"/"deleted" could
    // report success while the OS account and its group were still present.
    match safe_command_unsandboxed("userdel", &[]).args([&username]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "userdel {username} failed (account may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("userdel {username} failed to run: {e}"),
        Ok(_) => {}
    }
    match safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "groupdel {groupname} failed (group may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("groupdel {groupname} failed to run: {e}"),
        Ok(_) => {}
    }
    let _ = std::fs::remove_file(owner_marker_path(uid));

    if last_sftp_site {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        let _ = reload_sshd_validated().await;
    }

    tracing::info!("SFTP deprovisioned for {domain}: user={username}");
    Ok(())
}

/// Set (or reset) `domain`'s SFTP password. Hashes in-process (glibc
/// SHA-512-crypt via `sha-crypt`) rather than piping plaintext through
/// `chpasswd`'s stdin - the shared `UnsandboxedCommand` primitive every
/// privileged call here goes through has no stdin support today, and a hash
/// (unlike plaintext) is not sensitive to pass as a `usermod -p` argument;
/// that is the entire reason hashing exists.
pub async fn set_password(uid: i32, plaintext: &str) -> Result<(), String> {
    let username = account_name(uid);
    // NOT `ShaCrypt::hash_password()` - its auto-generated salt is
    // `password_hash`'s generic RECOMMENDED_SALT_LEN (16 RAW BYTES), which
    // base64-encodes to 22 characters. SHA-crypt's own spec caps the salt at
    // 16 base64 CHARACTERS; glibc's crypt() (what PAM actually calls to
    // verify a login) truncates an over-long salt to that limit when
    // recomputing the hash, so it silently computes a DIFFERENT digest than
    // the one stored - authentication then fails for every correct password,
    // forever. Live-verified on a fresh VPS: a hash made with the default
    // 16-byte/22-char salt round-tripped through Rust's own crypt.crypt()
    // check as WRONG. 12 raw bytes base64-encodes to exactly 16 characters
    // (12*8/6 = 16, no truncation needed by any spec-compliant verifier).
    let salt: [u8; 12] = {
        use rand::Rng;
        rand::rng().random()
    };
    let hash = ShaCrypt::default()
        .hash_password_with_salt(plaintext.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {e}"))?;
    let out = safe_command_unsandboxed("usermod", &[])
        .args(["-p", hash.as_str(), &username])
        .output()
        .await
        .map_err(|e| format!("usermod failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "usermod -p failed for {username}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Write the sshd `Match Group` drop-in if it is not already present, then
/// validate and reload - never the bare `restart_sshd`/no-validation path
/// `services::security`'s existing SSH-hardening functions use today, since
/// that path has no `sshd -t` gate anywhere and a malformed Match block would
/// otherwise lock out SSH access on reload with no warning.
async fn ensure_sshd_dropin() -> Result<(), String> {
    if std::path::Path::new(SSHD_DROPIN).exists() {
        return Ok(());
    }
    let block = format!(
        "# Managed by CyberHunter - Panel - per-site SFTP jails (GH #108). Do not edit by hand;\n\
         # regenerated the next time a site's SFTP account is enabled/disabled.\n\
         Match Group {SFTP_GROUP}\n\
         \tChrootDirectory %h\n\
         \tForceCommand internal-sftp\n\
         \tAllowTcpForwarding no\n\
         \tX11Forwarding no\n"
    );
    if let Err(e) = std::fs::write(SSHD_DROPIN, &block) {
        return Err(format!("Failed to write {SSHD_DROPIN}: {e}"));
    }
    if let Err(e) = reload_sshd_validated().await {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        return Err(e);
    }
    Ok(())
}

/// `sshd -t` then `systemctl reload sshd` - reload, not restart, so an
/// unrelated config change never drops a live SSH session. On a failed
/// validation the caller is responsible for removing whatever it just wrote;
/// this function only ever validates the config CURRENTLY on disk.
async fn reload_sshd_validated() -> Result<(), String> {
    let test = safe_command("sshd").args(["-t"]).output().await
        .map_err(|e| format!("sshd -t failed to run: {e}"))?;
    if !test.status.success() {
        return Err(format!(
            "sshd config invalid after SFTP drop-in change: {}",
            String::from_utf8_lossy(&test.stderr)
        ));
    }
    // `ssh` on Debian/Ubuntu, `sshd` on RHEL; `try-reload-or-restart` is a
    // no-op when a socket-activated sshd is idle (the next connection reads
    // the new drop-in anyway) instead of failing with "unit not active".
    let unit = crate::services::security::ssh_service_unit();
    let out = safe_command("systemctl").args(["try-reload-or-restart", unit]).output().await
        .map_err(|e| format!("systemctl reload sshd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl reload sshd failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha_crypt::PasswordVerifier;

    // ── Custom names and hash import (05-import-hestia W4-S) ───────────

    #[test]
    fn hestia_ftp_names_are_valid_custom_usernames() {
        for ok in ["adm-x_site", "adm-x_site1", "_svc", "a", "a.b-c_d9"] {
            assert!(is_valid_custom_username(ok), "{ok}");
        }
        let long = "a".repeat(33);
        for bad in ["", "Adm", "9abc", "-abc", ".abc", "a b", "a:b", "a/b", "a$", long.as_str()] {
            assert!(!is_valid_custom_username(bad), "{bad:?}");
        }
        assert!(is_valid_custom_username(&"a".repeat(32)));
    }

    #[test]
    fn reserved_names_and_the_panel_namespace_are_refused() {
        assert_eq!(username_static_conflict("root", 2001), Some("reserved"));
        assert_eq!(username_static_conflict("www-data", 2001), Some("reserved"));
        assert_eq!(username_static_conflict("vmail", 2001), Some("reserved"));
        assert_eq!(username_static_conflict("sftp2002", 2001), Some("panel_namespace"));
        assert_eq!(username_static_conflict("sftpg2001", 2001), Some("panel_namespace"));
        assert_eq!(username_static_conflict("sftp2001", 2001), None, "the uid's own default");
        assert_eq!(username_static_conflict("sftpuser", 2001), None, "not digits: an ordinary name");
        assert_eq!(username_static_conflict("adm-jim_x", 2001), None);
        assert_eq!(username_static_conflict("Bad", 2001), Some("invalid"));
    }

    #[test]
    fn the_owner_marker_keeps_the_domain_line_and_names_the_user() {
        let body = owner_marker_body("x.tld", "adm-jim_x");
        assert!(body.lines().any(|l| l == "Domain=x.tld"));
        assert_eq!(crate::services::ownership::marker_user(&body).as_deref(), Some("adm-jim_x"));
    }

    #[test]
    fn crypt_hashes_are_classified_by_scheme() {
        // Synthetic shapes only - not real hashes.
        assert_eq!(crypt_hash_scheme("$y$j9T$abcdefgh$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./ab"), Ok("yescrypt"));
        assert_eq!(crypt_hash_scheme("$6$saltsalt$abc./XYZ"), Ok("sha512crypt"));
        assert_eq!(crypt_hash_scheme("$6$rounds=5000$saltsalt$abc"), Ok("sha512crypt"));
        assert_eq!(crypt_hash_scheme("$2y$10$abcdefghijklmnopqrstuv"), Ok("bcrypt"));
        assert_eq!(crypt_hash_scheme("$1$salt$abc"), Ok("md5crypt"));
        assert_eq!(crypt_hash_scheme("$gy$j9T$a$b"), Ok("gost-yescrypt"));
        for bad in [
            "", "plain", "$9$x$y", "$y$", "$y$a b", "$y$a:b", "$y$a\nb", "*", "!$6$a$b",
            "{BLF-CRYPT}$2y$10$abc",
        ] {
            assert!(crypt_hash_scheme(bad).is_err(), "{bad:?}");
        }
        assert!(crypt_hash_scheme(&format!("$6${}", "a".repeat(260))).is_err());
    }

    /// The live-verified bug this pins: `$6$rounds=5000$8mwPPcuR8m7wfnYuiMKDK.$...`
    /// (a real hash this code produced before the fix) has a 22-character
    /// salt field. glibc's crypt() - what PAM actually calls to check a
    /// login - truncates a SHA-crypt salt to 16 characters when recomputing
    /// the hash to verify against, so an over-long salt makes EVERY future
    /// login attempt recompute a different digest than the one stored: not a
    /// crash, not an error anywhere, just permanent, silent authentication
    /// failure for a password that is actually correct. `hash_password()`'s
    /// auto-generated salt is `password_hash`'s generic
    /// `RECOMMENDED_SALT_LEN` (16 RAW bytes -> 22 base64 characters); this
    /// must never be used for a SHA-crypt hash a real `usermod -p` is going
    /// to store.
    #[test]
    fn the_generated_salt_is_at_most_sixteen_characters() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"irrelevant-test-password", &salt)
            .expect("hashing a test password must succeed");
        let fields: Vec<&str> = hash.as_str().split('$').collect();
        // ["", "6", ("rounds=N" |) salt, digest] - salt is always the
        // second-to-last field regardless of whether rounds= is present.
        let salt_field = fields[fields.len() - 2];
        assert!(
            salt_field.len() <= 16,
            "salt field '{salt_field}' is {} characters - glibc's crypt() will \
             truncate it on verify and every login will fail",
            salt_field.len()
        );
    }

    /// The actual property that matters: a hash this code produces must
    /// verify correctly via the SAME crate used to produce it (a necessary
    /// but not sufficient check - the salt-length assertion above is what
    /// catches the specific cross-implementation gap with glibc, since this
    /// crate happily verifies its OWN over-long-salt hashes without
    /// truncating, which is exactly why the bug was invisible to this check
    /// alone).
    #[test]
    fn a_produced_hash_verifies_against_the_password_that_made_it() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"a-real-looking-password-123", &salt)
            .expect("hashing must succeed");
        ShaCrypt::default()
            .verify_password(b"a-real-looking-password-123", &hash)
            .expect("the password that produced this hash must verify against it");
        assert!(
            ShaCrypt::default()
                .verify_password(b"a-different-password", &hash)
                .is_err(),
            "a wrong password must not verify"
        );
    }
}
