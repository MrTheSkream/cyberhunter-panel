//! FTP server (feature 6): vsftpd with mandatory FTPS, reusing each site's
//! SFTP account (same Linux user, same password, same chroot).
//!
//! Debian/Ubuntu only. What the panel owns on the box:
//! - `/etc/vsftpd.conf`, rewritten whole ([`render_conf`]); the distro's file
//!   is kept once as `/etc/vsftpd.conf.dockpanel.bak`;
//! - `/etc/pam.d/dockpanel-ftp` ([`PAM_BODY`]): the distro's `vsftpd` PAM file
//!   goes through `pam_shells`, which refuses the sites' `/usr/sbin/nologin`;
//! - `/etc/dockpanel/ftp-users`, the whitelist (`userlist_deny=NO`): only the
//!   accounts of sites with FTP ticked may log in. The backend holds the list
//!   and sends it whole; vsftpd reads it at each connection;
//! - `/etc/dockpanel/ftp/{cert,key}.pem`, a self-signed certificate, only when
//!   the panel host has no Let's Encrypt certificate (otherwise vsftpd points
//!   at `/etc/letsencrypt/live/<host>/` directly and follows its renewals);
//! - `/etc/fail2ban/jail.d/dockpanel-vsftpd.conf` when fail2ban is installed.
//!
//! `/etc` is read-only inside the agent's sandbox: files there go through
//! [`crate::services::apache::write_file`], which falls back to the
//! unsandboxed escape. `/etc/vsftpd.conf` is deliberately NOT a
//! `ReadWritePaths` entry: every installer `mkdir -p`s those entries, which
//! would turn it into a directory.

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use crate::services::sftp_accounts::{self, PasswdEntry};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

pub const UNIT: &str = "vsftpd";
pub const PACKAGE: &str = "vsftpd";
pub const CONF: &str = "/etc/vsftpd.conf";
pub const CONF_BAK: &str = "/etc/vsftpd.conf.dockpanel.bak";
pub const PAM_SERVICE: &str = "dockpanel-ftp";
pub const PAM_FILE: &str = "/etc/pam.d/dockpanel-ftp";
pub const CERT_DIR: &str = "/etc/dockpanel/ftp";
pub const SELF_CERT: &str = "/etc/dockpanel/ftp/cert.pem";
pub const SELF_KEY: &str = "/etc/dockpanel/ftp/key.pem";
pub const USERS_FILE: &str = "/etc/dockpanel/ftp-users";
pub const JAIL_FILE: &str = "/etc/fail2ban/jail.d/dockpanel-vsftpd.conf";
pub const LOG_FILE: &str = "/var/log/vsftpd.log";
pub const CONTROL_PORT: u16 = 21;
pub const PASV_MIN: u16 = 12000;
pub const PASV_MAX: u16 = 12100;
/// Panel-allocated SFTP uids start here.
pub const MIN_UID: i32 = 30000;
pub const UNSUPPORTED_MSG: &str = "Not supported on this server";
pub const NOT_INSTALLED_MSG: &str = "FTP server not installed";
const INSTALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(120);

/// Contract A-2. No `pam_shells`: the sites' accounts have a nologin shell.
/// `pam_listfile` on `/etc/ftpusers` keeps root and the system accounts out.
pub const PAM_BODY: &str = "# Managed by CyberHunter - Panel (FTP server).\n\
auth    required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed\n\
@include common-auth\n\
@include common-account\n\
session required pam_loginuid.so\n";

/// Contract A-2, step 8.
pub const JAIL_BODY: &str = "# Managed by CyberHunter - Panel (FTP server).\n\
[vsftpd]\n\
enabled = true\n\
port = 21,12000:12100\n\
filter = vsftpd\n\
logpath = /var/log/vsftpd.log\n\
maxretry = 5\n\
findtime = 600\n\
bantime = 3600\n";

/// An error with the HTTP status the route answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpErr {
    pub status: u16,
    pub msg: String,
}

impl FtpErr {
    pub fn new(status: u16, msg: impl Into<String>) -> Self {
        Self { status, msg: msg.into() }
    }
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::new(400, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(409, msg)
    }
    pub fn precondition(msg: impl Into<String>) -> Self {
        Self::new(412, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(500, msg)
    }
}

// ── Pure helpers ────────────────────────────────────────────────────────────

/// `/etc/vsftpd.conf` (07-ftp-quotas.md §2). vsftpd accepts neither inline
/// comments nor spaces around `=`, so the design's annotations live here:
/// - `chroot_local_user`: the jail is the account's home,
///   `/var/dockpanel-sftp/<domain>` (root:root 0755); files go in `content/`,
///   hence `allow_writeable_chroot=NO`;
/// - `userlist_*`: whitelist, only sites with FTP ticked;
/// - `force_local_*_ssl`: FTPS is mandatory (explicit AUTH TLS on port 21);
/// - `require_ssl_reuse=NO`: FileZilla often fails otherwise;
/// - passive ports 12000-12100, as HestiaCP;
/// - `seccomp_sandbox=NO`: known vsftpd 3.0.5 crashes with TLS on recent kernels;
/// - `secure_chroot_dir`: Debian's own default, created by its unit.
///
/// Without IPv6 on the box (`ipv6 == false`), `listen_ipv6=YES` cannot bind:
/// a plain IPv4 listener is used instead.
pub fn render_conf(cert: &str, key: &str, pasv_address: Option<IpAddr>, ipv6: bool) -> String {
    let mut lines: Vec<String> = vec![
        "# Managed by CyberHunter - Panel (FTP server). Rewritten on every install or repair.".into(),
    ];
    let (listen, listen_v6) = if ipv6 { ("NO", "YES") } else { ("YES", "NO") };
    let settings: Vec<(&str, String)> = vec![
        ("listen", listen.into()),
        ("listen_ipv6", listen_v6.into()),
        ("anonymous_enable", "NO".into()),
        ("local_enable", "YES".into()),
        ("write_enable", "YES".into()),
        ("local_umask", "022".into()),
        ("chroot_local_user", "YES".into()),
        ("allow_writeable_chroot", "NO".into()),
        ("secure_chroot_dir", "/var/run/vsftpd/empty".into()),
        ("userlist_enable", "YES".into()),
        ("userlist_deny", "NO".into()),
        ("userlist_file", USERS_FILE.into()),
        ("pam_service_name", PAM_SERVICE.into()),
        ("ssl_enable", "YES".into()),
        ("force_local_logins_ssl", "YES".into()),
        ("force_local_data_ssl", "YES".into()),
        ("ssl_tlsv1", "NO".into()),
        ("ssl_sslv2", "NO".into()),
        ("ssl_sslv3", "NO".into()),
        ("require_ssl_reuse", "NO".into()),
        ("ssl_ciphers", "HIGH".into()),
        ("rsa_cert_file", cert.into()),
        ("rsa_private_key_file", key.into()),
        ("pasv_enable", "YES".into()),
        ("pasv_min_port", PASV_MIN.to_string()),
        ("pasv_max_port", PASV_MAX.to_string()),
    ];
    for (k, v) in settings {
        lines.push(format!("{k}={v}"));
    }
    if let Some(ip) = pasv_address {
        lines.push(format!("pasv_address={ip}"));
    }
    for (k, v) in [
        ("xferlog_enable", "YES"),
        ("dual_log_enable", "YES"),
        ("vsftpd_log_file", LOG_FILE),
        ("seccomp_sandbox", "NO"),
    ] {
        lines.push(format!("{k}={v}"));
    }
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// A setting of a vsftpd.conf body (last occurrence wins, as in vsftpd).
pub fn conf_value(conf: &str, key: &str) -> Option<String> {
    conf.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().to_string())
        .last()
}

/// `pasv_address` of the request: absent/empty = none; an IPv4 address
/// otherwise (vsftpd's PASV reply only carries IPv4).
pub fn parse_pasv_address(v: Option<&str>) -> Result<Option<IpAddr>, String> {
    let Some(s) = v.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match s.parse::<IpAddr>() {
        Ok(ip @ IpAddr::V4(_)) => Ok(Some(ip)),
        Ok(IpAddr::V6(_)) => Err("pasv_address must be an IPv4 address".into()),
        Err(_) => Err(format!("Invalid pasv_address: {s}")),
    }
}

/// Trimmed names, duplicates dropped, order kept.
pub fn normalize_users(users: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in users {
        let t = u.trim().to_string();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// The whitelist file body: one name per line.
pub fn render_whitelist(users: &[String]) -> String {
    let mut s = String::new();
    for u in users {
        s.push_str(u);
        s.push('\n');
    }
    s
}

/// Names of a whitelist file body.
pub fn parse_whitelist(body: &str) -> Vec<String> {
    body.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()
}

/// Names in `old` that are not in `new` (to disconnect).
pub fn removed_users(old: &[String], new: &[String]) -> Vec<String> {
    old.iter().filter(|o| !new.contains(o)).cloned().collect()
}

/// Members of a `getent group` line (`name:x:gid:a,b`).
pub fn group_members(line: &str) -> Vec<String> {
    line.trim_end()
        .split(':')
        .nth(3)
        .map(|m| m.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

/// May `name` be on the FTP whitelist? Contract A-4: the account exists, its
/// uid is >= 30000, it is in `sftp_sites`, and the panel's owner marker for
/// its uid exists and names this account. Pure, tested; `Err` is the reason.
pub fn check_user(
    name: &str,
    entry: Option<&PasswdEntry>,
    sftp_members: &[String],
    marker: Option<&str>,
) -> Result<(), String> {
    if !sftp_accounts::is_valid_custom_username(name) {
        return Err("invalid account name".into());
    }
    let Some(e) = entry else {
        return Err("no such account".into());
    };
    if e.uid < MIN_UID {
        return Err(format!("uid {} is below {MIN_UID}", e.uid));
    }
    if !sftp_members.iter().any(|m| m == name) {
        return Err(format!("not a member of {}", sftp_accounts::SFTP_GROUP));
    }
    let Some(body) = marker else {
        return Err("no panel owner marker for this uid".into());
    };
    let marked = crate::services::ownership::marker_user(body).unwrap_or_else(|| sftp_accounts::sftp_username(e.uid));
    if marked != name {
        return Err("the panel owner marker names another account".into());
    }
    Ok(())
}

/// Does `ss -ltnH` show a listener on `port`? Pure, tested.
pub fn listens_on(ss: &str, port: u16) -> bool {
    let want = port.to_string();
    ss.lines().any(|l| {
        l.split_whitespace()
            .nth(3)
            .and_then(|local| local.rsplit_once(':'))
            .is_some_and(|(_, p)| p == want)
    })
}

/// A hostname usable as a certificate CN (`[A-Za-z0-9.-]`), else `None`.
pub fn sanitize_cn(h: &str) -> Option<String> {
    let h = h.trim();
    (!h.is_empty() && h.len() <= 64 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .then(|| h.to_string())
}

/// `letsencrypt` for a certificate under `/etc/letsencrypt`, else `self_signed`.
pub fn cert_kind(cert_path: &str) -> &'static str {
    if cert_path.starts_with("/etc/letsencrypt/") { "letsencrypt" } else { "self_signed" }
}

// ── System facts ────────────────────────────────────────────────────────────

pub async fn unsupported_reason() -> Option<String> {
    match crate::services::pkg::installer().await {
        Some(crate::services::pkg::Installer::AptGet) => None,
        _ => Some(UNSUPPORTED_MSG.to_string()),
    }
}

pub async fn is_installed() -> bool {
    crate::services::pkg::is_installed(PACKAGE).await
}

pub async fn is_active() -> bool {
    tokio::time::timeout(
        Duration::from_secs(10),
        safe_command("systemctl").args(["is-active", "--quiet", UNIT]).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success())
    .unwrap_or(false)
}

async fn systemctl(args: &[&str]) -> Result<(), String> {
    match tokio::time::timeout(SYSTEMCTL_TIMEOUT, safe_command("systemctl").args(args).output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(()),
        Ok(Ok(o)) => Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("systemctl {} could not run: {e}", args.join(" "))),
        Err(_) => Err(format!("systemctl {} timed out", args.join(" "))),
    }
}

async fn listening_on_control_port() -> bool {
    match tokio::time::timeout(Duration::from_secs(10), safe_command("ss").args(["-ltnH"]).output()).await {
        Ok(Ok(o)) => listens_on(&String::from_utf8_lossy(&o.stdout), CONTROL_PORT),
        _ => false,
    }
}

/// Last lines of the unit's journal, for an install failure.
async fn journal_tail() -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(15),
        safe_command("journalctl").args(["-u", UNIT, "-n", "15", "--no-pager", "-o", "cat"]).output(),
    )
    .await;
    let mut s = match out {
        Ok(Ok(o)) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    };
    if s.len() > 1500 {
        let cut = s.len() - 1500;
        let cut = (cut..s.len()).find(|i| s.is_char_boundary(*i)).unwrap_or(s.len());
        s = s[cut..].to_string();
    }
    s
}

fn ipv6_available() -> bool {
    Path::new("/proc/net/if_inet6").exists()
}

fn host_cn() -> String {
    crate::services::panel_tls::panel_server_name()
        .and_then(|h| sanitize_cn(&h))
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok().and_then(|h| sanitize_cn(&h)))
        .unwrap_or_else(|| "localhost".to_string())
}

pub fn whitelist() -> Vec<String> {
    std::fs::read_to_string(USERS_FILE).map(|b| parse_whitelist(&b)).unwrap_or_default()
}

async fn passwd_entry(name: &str) -> Option<PasswdEntry> {
    let out = safe_command("getent").args(["passwd", name]).output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    sftp_accounts::parse_passwd_line(String::from_utf8_lossy(&out.stdout).lines().next()?)
}

async fn sftp_group_members() -> Vec<String> {
    match safe_command("getent").args(["group", sftp_accounts::SFTP_GROUP]).output().await {
        Ok(o) if o.status.success() => {
            group_members(String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or(""))
        }
        _ => Vec::new(),
    }
}

/// Contract A-4 checks on every name; the first failure is a 400 naming it.
pub async fn validate_users(users: &[String]) -> Result<(), FtpErr> {
    if users.is_empty() {
        return Ok(());
    }
    let members = sftp_group_members().await;
    for name in users {
        let entry = if sftp_accounts::is_valid_custom_username(name) { passwd_entry(name).await } else { None };
        let marker = entry
            .as_ref()
            .and_then(|e| std::fs::read_to_string(sftp_accounts::owner_marker_path(e.uid)).ok());
        if let Err(why) = check_user(name, entry.as_ref(), &members, marker.as_deref()) {
            return Err(FtpErr::bad(format!("{name} cannot use FTP: {why}")));
        }
    }
    Ok(())
}

// ── File writes ─────────────────────────────────────────────────────────────

/// Atomic 0600 root write under `/etc/dockpanel` (a `ReadWritePaths` entry).
fn write_private(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    }
    let tmp = format!("{path}.tmp");
    let _ = std::fs::remove_file(&tmp);
    let res = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(content.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Cannot write {path}: {e}"));
    }
    Ok(())
}

/// Serializes whitelist rewrites (install and `PUT /ftp/users`).
static USERS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Rewrite the whitelist; returns the names it held before.
async fn write_whitelist(users: &[String]) -> Result<Vec<String>, String> {
    let _g = USERS_LOCK.lock().await;
    let old = whitelist();
    write_private(USERS_FILE, &render_whitelist(users))?;
    Ok(old)
}

/// Disconnect `name`'s FTP sessions (its vsftpd processes only, not SFTP).
async fn kick(name: &str) {
    // Exit 1 just means no session was open.
    let _ = safe_command_unsandboxed("pkill", &[]).args(["-u", name, "-x", "vsftpd"]).output().await;
}

/// vsftpd's log must exist before fail2ban accepts a jail reading it.
fn ensure_log_file() {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(LOG_FILE);
}

/// Write the fail2ban jail (also called by the fail2ban installer when vsftpd
/// is already there). The caller reloads or restarts fail2ban.
pub async fn write_fail2ban_jail() -> Result<(), String> {
    ensure_log_file();
    crate::services::apache::write_file(JAIL_FILE, JAIL_BODY).await
}

async fn fail2ban_reload() -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(60), safe_command("fail2ban-client").arg("reload").output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(()),
        Ok(Ok(o)) => Err(format!("fail2ban-client reload failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Ok(Err(e)) => Err(format!("fail2ban-client could not run: {e}")),
        Err(_) => Err("fail2ban-client reload timed out".into()),
    }
}

/// The certificate vsftpd presents: the panel's Let's Encrypt pair, or a
/// self-signed one (RSA 2048, 10 years, CN = host name), kept across repairs.
async fn prepare_certificate() -> Result<(String, String), String> {
    if let Some(pair) = crate::services::panel_tls::panel_tls_paths() {
        return Ok(pair);
    }
    let usable = std::fs::read_to_string(SELF_CERT)
        .ok()
        .is_some_and(|c| crate::services::ssl::cert_metadata(&c).is_ok())
        && Path::new(SELF_KEY).exists();
    if !usable {
        std::fs::create_dir_all(CERT_DIR).map_err(|e| format!("Cannot create {CERT_DIR}: {e}"))?;
        let cert_tmp = format!("{SELF_CERT}.tmp");
        let key_tmp = format!("{SELF_KEY}.tmp");
        let subj = format!("/CN={}", host_cn());
        let out = tokio::time::timeout(
            Duration::from_secs(120),
            safe_command("openssl")
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", &subj, "-keyout",
                    &key_tmp, "-out", &cert_tmp,
                ])
                .output(),
        )
        .await
        .map_err(|_| "openssl timed out".to_string())?
        .map_err(|e| format!("openssl could not run: {e}"))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&key_tmp);
            let _ = std::fs::remove_file(&cert_tmp);
            return Err(format!(
                "Self-signed certificate generation failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_tmp, std::fs::Permissions::from_mode(0o600))
            .and_then(|_| std::fs::set_permissions(&cert_tmp, std::fs::Permissions::from_mode(0o644)))
            .and_then(|_| std::fs::rename(&key_tmp, SELF_KEY))
            .and_then(|_| std::fs::rename(&cert_tmp, SELF_CERT))
            .map_err(|e| format!("Cannot install the self-signed certificate: {e}"))?;
    }
    Ok((SELF_CERT.to_string(), SELF_KEY.to_string()))
}

// ── A-1 status ──────────────────────────────────────────────────────────────

fn cert_json() -> serde_json::Value {
    let conf = std::fs::read_to_string(CONF).unwrap_or_default();
    let Some(path) = conf_value(&conf, "rsa_cert_file") else {
        return serde_json::Value::Null;
    };
    let meta = std::fs::read_to_string(&path).ok().and_then(|c| crate::services::ssl::cert_metadata(&c).ok());
    serde_json::json!({
        "kind": cert_kind(&path),
        "subject": meta.as_ref().and_then(|m| m.dns_names.first().cloned()),
        "expires_at": meta.as_ref().map(|m| m.not_after.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    })
}

pub async fn status() -> serde_json::Value {
    let unsupported = unsupported_reason().await;
    let supported = unsupported.is_none();
    let installed = supported && is_installed().await;
    if !installed {
        return serde_json::json!({
            "supported": supported,
            "unsupported_reason": unsupported,
            "installed": false,
            "running": false,
            "cert": null,
            "ports": null,
            "firewall": null,
            "fail2ban_jail": null,
            "users": null,
        });
    }
    let firewall = match crate::services::firewall::tcp_open(CONTROL_PORT, PASV_MIN, PASV_MAX).await {
        None => "none",
        Some(true) => "open",
        Some(false) => "closed",
    };
    serde_json::json!({
        "supported": true,
        "unsupported_reason": null,
        "installed": true,
        "running": is_active().await,
        "cert": cert_json(),
        "ports": { "control": CONTROL_PORT, "passive_min": PASV_MIN, "passive_max": PASV_MAX },
        "firewall": firewall,
        "fail2ban_jail": Path::new(JAIL_FILE).exists(),
        "users": whitelist().len(),
    })
}

// ── A-2 install / A-3 uninstall ─────────────────────────────────────────────

/// Held by an install or an uninstall: a second one is a 409.
static OP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const BUSY_MSG: &str = "An FTP server installation or removal is already running";

/// A-2. Returns the warnings.
pub async fn install(users: &[String], pasv_address: Option<&str>) -> Result<Vec<String>, FtpErr> {
    if unsupported_reason().await.is_some() {
        return Err(FtpErr::precondition(UNSUPPORTED_MSG));
    }
    let Ok(_op) = OP_LOCK.try_lock() else {
        return Err(FtpErr::conflict(BUSY_MSG));
    };
    let pasv = parse_pasv_address(pasv_address).map_err(FtpErr::bad)?;
    let users = normalize_users(users);
    // Every name is checked before anything is installed.
    validate_users(&users).await?;
    match tokio::time::timeout(INSTALL_TIMEOUT, run_install(&users, pasv)).await {
        Ok(r) => r,
        Err(_) => Err(FtpErr::internal("The FTP server installation timed out (5 minutes)")),
    }
}

async fn run_install(users: &[String], pasv: Option<IpAddr>) -> Result<Vec<String>, FtpErr> {
    let mut warnings = Vec::new();

    // 1. Package.
    crate::services::pkg::install(&[PACKAGE])
        .await
        .map_err(|e| FtpErr::internal(format!("vsftpd install failed: {e}")))?;

    // 2. PAM service.
    crate::services::apache::write_file(PAM_FILE, PAM_BODY).await.map_err(FtpErr::internal)?;

    // 3. Certificate.
    let (cert, key) = prepare_certificate().await.map_err(FtpErr::internal)?;

    // 4. Configuration, the distro's original kept once.
    let previous = std::fs::read_to_string(CONF).ok();
    if let Some(prev) = &previous {
        if !Path::new(CONF_BAK).exists() {
            crate::services::apache::write_file(CONF_BAK, prev).await.map_err(FtpErr::internal)?;
        }
    }
    let conf = render_conf(&cert, &key, pasv, ipv6_available());
    crate::services::apache::write_file(CONF, &conf).await.map_err(FtpErr::internal)?;

    // 5. Whitelist.
    write_whitelist(users).await.map_err(FtpErr::internal)?;

    // 6. Service. `restart`, not `enable --now`: the package's postinst
    // already started vsftpd on the stock configuration.
    ensure_log_file();
    let started = async {
        systemctl(&["enable", UNIT]).await?;
        systemctl(&["restart", UNIT]).await?;
        for _ in 0..20 {
            if is_active().await && listening_on_control_port().await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err("vsftpd is not listening on port 21".to_string())
    }
    .await;
    if let Err(e) = started {
        let tail = journal_tail().await;
        let _ = systemctl(&["stop", UNIT]).await;
        let restored = match &previous {
            Some(p) => crate::services::apache::write_file(CONF, p).await,
            None => crate::services::apache::remove_file(CONF).await,
        };
        if let Err(r) = restored {
            tracing::error!("ftp: restoring {CONF} failed: {r}");
        }
        let detail = if tail.is_empty() { e } else { format!("{e}. Journal: {tail}") };
        return Err(FtpErr::internal(format!("vsftpd did not start: {detail}")));
    }

    // 7. Firewall: failures are warnings.
    if !crate::services::firewall::allow_tcp(&CONTROL_PORT.to_string()).await {
        warnings.push(format!("Could not open port {CONTROL_PORT}/tcp in the firewall"));
    }
    if !crate::services::firewall::allow_tcp_range(PASV_MIN, PASV_MAX).await {
        warnings.push(format!("Could not open the passive ports {PASV_MIN}-{PASV_MAX}/tcp in the firewall"));
    }
    crate::services::firewall::reload().await;

    // 8. fail2ban jail.
    if crate::services::pkg::is_installed("fail2ban").await {
        match write_fail2ban_jail().await {
            Ok(()) => {
                if let Err(e) = fail2ban_reload().await {
                    warnings.push(format!("The fail2ban jail was written but not loaded: {e}"));
                }
            }
            Err(e) => warnings.push(format!("Could not write the fail2ban jail: {e}")),
        }
    }

    tracing::info!("FTP server installed ({} account(s) allowed)", users.len());
    Ok(warnings)
}

/// A-3.
pub async fn uninstall() -> Result<(), FtpErr> {
    if unsupported_reason().await.is_some() {
        return Err(FtpErr::precondition(UNSUPPORTED_MSG));
    }
    let Ok(_op) = OP_LOCK.try_lock() else {
        return Err(FtpErr::conflict(BUSY_MSG));
    };
    let _ = systemctl(&["stop", UNIT]).await;
    let _ = systemctl(&["disable", UNIT]).await;
    crate::services::pkg::remove(&[PACKAGE])
        .await
        .map_err(|e| FtpErr::internal(format!("vsftpd removal failed: {e}")))?;

    if !crate::services::firewall::remove_port(&CONTROL_PORT.to_string(), "tcp").await {
        tracing::warn!("ftp: could not remove the firewall rule for {CONTROL_PORT}/tcp");
    }
    if !crate::services::firewall::remove_tcp_range(PASV_MIN, PASV_MAX).await {
        tracing::warn!("ftp: could not remove the firewall rule for {PASV_MIN}-{PASV_MAX}/tcp");
    }
    crate::services::firewall::reload().await;

    if Path::new(JAIL_FILE).exists() {
        crate::services::apache::remove_file(JAIL_FILE).await.map_err(FtpErr::internal)?;
        if let Err(e) = fail2ban_reload().await {
            tracing::warn!("ftp: {e}");
        }
    }
    crate::services::apache::remove_file(PAM_FILE).await.map_err(FtpErr::internal)?;
    if Path::new(CERT_DIR).exists() {
        std::fs::remove_dir_all(CERT_DIR).map_err(|e| FtpErr::internal(format!("Cannot remove {CERT_DIR}: {e}")))?;
    }
    {
        let _g = USERS_LOCK.lock().await;
        match std::fs::remove_file(USERS_FILE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(FtpErr::internal(format!("Cannot remove {USERS_FILE}: {e}"))),
        }
    }
    tracing::info!("FTP server removed");
    Ok(())
}

// ── A-4 whitelist ───────────────────────────────────────────────────────────

/// A-4. Returns how many names were written and who was disconnected.
pub async fn set_users(users: &[String]) -> Result<(usize, Vec<String>), FtpErr> {
    if !is_installed().await {
        return Err(FtpErr::precondition(NOT_INSTALLED_MSG));
    }
    let users = normalize_users(users);
    validate_users(&users).await?;
    let old = write_whitelist(&users).await.map_err(FtpErr::internal)?;
    let kicked = removed_users(&old, &users);
    for name in &kicked {
        kick(name).await;
    }
    Ok((users.len(), kicked))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(uid: i32) -> PasswdEntry {
        PasswdEntry { uid, gid: uid, home: "/var/dockpanel-sftp/a.tld".into() }
    }

    #[test]
    fn conf_rendering() {
        let c = render_conf("/etc/dockpanel/ftp/cert.pem", "/etc/dockpanel/ftp/key.pem", None, true);
        for line in c.lines().filter(|l| !l.starts_with('#')) {
            let (k, v) = line.split_once('=').expect("key=value");
            assert!(!k.contains(char::is_whitespace) && !v.contains(char::is_whitespace), "{line}");
            assert!(!line.contains('#'), "no inline comment: {line}");
        }
        for want in [
            "listen=NO",
            "listen_ipv6=YES",
            "anonymous_enable=NO",
            "chroot_local_user=YES",
            "allow_writeable_chroot=NO",
            "userlist_deny=NO",
            "userlist_file=/etc/dockpanel/ftp-users",
            "pam_service_name=dockpanel-ftp",
            "force_local_logins_ssl=YES",
            "force_local_data_ssl=YES",
            "ssl_tlsv1=NO",
            "require_ssl_reuse=NO",
            "rsa_cert_file=/etc/dockpanel/ftp/cert.pem",
            "rsa_private_key_file=/etc/dockpanel/ftp/key.pem",
            "pasv_min_port=12000",
            "pasv_max_port=12100",
            "vsftpd_log_file=/var/log/vsftpd.log",
            "seccomp_sandbox=NO",
        ] {
            assert!(c.lines().any(|l| l == want), "missing {want}\n{c}");
        }
        assert!(!c.contains("pasv_address"));
        let c = render_conf("/a", "/b", Some("203.0.113.7".parse().unwrap()), false);
        assert!(c.lines().any(|l| l == "pasv_address=203.0.113.7"));
        assert!(c.lines().any(|l| l == "listen=YES") && c.lines().any(|l| l == "listen_ipv6=NO"));
        assert_eq!(conf_value(&c, "rsa_cert_file").as_deref(), Some("/a"));
        assert_eq!(conf_value("#rsa_cert_file=/x\nrsa_cert_file=/y\n", "rsa_cert_file").as_deref(), Some("/y"));
    }

    #[test]
    fn pasv_address_validation() {
        assert_eq!(parse_pasv_address(None), Ok(None));
        assert_eq!(parse_pasv_address(Some("  ")), Ok(None));
        assert_eq!(parse_pasv_address(Some("203.0.113.7")), Ok(Some("203.0.113.7".parse().unwrap())));
        assert!(parse_pasv_address(Some("2001:db8::1")).is_err());
        assert!(parse_pasv_address(Some("1.2.3.4\nlisten=YES")).is_err());
    }

    #[test]
    fn whitelist_round_trip_and_diff() {
        let users = normalize_users(&[" sftp30001".into(), "adm-jim_jeuxx".into(), "sftp30001".into()]);
        assert_eq!(users, vec!["sftp30001", "adm-jim_jeuxx"]);
        let body = render_whitelist(&users);
        assert_eq!(body, "sftp30001\nadm-jim_jeuxx\n");
        assert_eq!(parse_whitelist(&body), users);
        assert_eq!(render_whitelist(&[]), "");
        let old = vec!["a".to_string(), "b".into(), "c".into()];
        assert_eq!(removed_users(&old, &["b".into()]), vec!["a", "c"]);
        assert!(removed_users(&[], &["b".into()]).is_empty());
    }

    #[test]
    fn user_checks() {
        let members = group_members("sftp_sites:x:1001:sftp30001,adm-jim_jeuxx\n");
        assert_eq!(members, vec!["sftp30001", "adm-jim_jeuxx"]);
        assert!(group_members("sftp_sites:x:1001:\n").is_empty());
        let marker_default = "Domain=a.tld\n";
        let marker_custom = "Domain=b.tld\nUser=adm-jim_jeuxx\n";
        assert!(check_user("sftp30001", Some(&entry(30001)), &members, Some(marker_default)).is_ok());
        assert!(check_user("adm-jim_jeuxx", Some(&entry(30002)), &members, Some(marker_custom)).is_ok());
        assert!(check_user("root", Some(&entry(0)), &members, Some(marker_default)).is_err());
        assert!(check_user("Bad Name", None, &members, None).is_err());
        assert!(check_user("ghost", None, &members, None).unwrap_err().contains("no such account"));
        assert!(check_user("sftp29999", Some(&entry(29999)), &["sftp29999".into()], Some(marker_default))
            .unwrap_err()
            .contains("below"));
        assert!(check_user("sftp30003", Some(&entry(30003)), &members, Some(marker_default))
            .unwrap_err()
            .contains("sftp_sites"));
        assert!(check_user("sftp30001", Some(&entry(30001)), &members, None).unwrap_err().contains("marker"));
        // The marker of this uid names someone else.
        assert!(check_user("adm-jim_jeuxx", Some(&entry(30002)), &members, Some(marker_default)).is_err());
    }

    #[test]
    fn ss_parsing() {
        let ss = "LISTEN 0 32 *:21 *:*\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n";
        assert!(listens_on(ss, 21));
        assert!(listens_on("LISTEN 0 32 [::]:21 [::]:*\n", 21));
        assert!(!listens_on("LISTEN 0 32 0.0.0.0:2121 0.0.0.0:*\nLISTEN 0 32 0.0.0.0:22 0.0.0.0:*\n", 21));
        assert!(!listens_on("", 21));
    }

    #[test]
    fn small_helpers() {
        assert_eq!(sanitize_cn("panel.example.com\n").as_deref(), Some("panel.example.com"));
        assert_eq!(sanitize_cn("a/CN=evil"), None);
        assert_eq!(sanitize_cn(""), None);
        assert_eq!(cert_kind("/etc/letsencrypt/live/x/fullchain.pem"), "letsencrypt");
        assert_eq!(cert_kind(SELF_CERT), "self_signed");
        assert!(PAM_BODY.contains("pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed"));
        assert!(!PAM_BODY.contains("pam_shells"));
        assert!(JAIL_BODY.contains("[vsftpd]\nenabled = true\nport = 21,12000:12100\nfilter = vsftpd\n"));
        assert!(JAIL_BODY.contains("logpath = /var/log/vsftpd.log\nmaxretry = 5\nfindtime = 600\nbantime = 3600\n"));
    }

    #[test]
    fn private_write_is_0600_and_atomic() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dp-ftp-{}", uuid::Uuid::new_v4().simple()));
        let p = dir.join("ftp-users");
        let ps = p.to_str().unwrap();
        write_private(ps, "a\n").unwrap();
        write_private(ps, "b\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "b\n");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!dir.join("ftp-users.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
