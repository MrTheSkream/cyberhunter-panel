//! Per-site PHP-FPM pool driven by the panel's "PHP settings" card.
//!
//! Contract: `conception/02-php-contrats.md` §A1. The panel sends every
//! effective value (defaults included) in [`PhpPool`]; the agent knows no PHP
//! defaults of its own. When `SiteConfig.php_pool` is absent the legacy writer
//! (`services::nginx::write_php_pool_config`) runs instead, byte-for-byte as
//! before.
//!
//! Split in two halves on purpose:
//! - pure: [`validate_php_pool`] and [`render_php_pool`] - everything that
//!   decides what lands in the file, tested below without a box;
//! - effectful: [`apply_php_pool`] - backup, atomic write, `php-fpm<ver> -t`,
//!   restore on failure, directories, reload.

use crate::safe_cmd::safe_command;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Every PHP version a pool may exist for (same list as `routes::php`).
pub const PHP_VERSIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4", "8.5"];

/// Directory the per-pool `error_log` files live in. The PHP errors viewer
/// (`routes::nginx::php_errors`) reads `{PHP_FPM_LOG_DIR}/{pool}.error.log`.
pub const PHP_FPM_LOG_DIR: &str = "/var/log/php-fpm";

/// Functions blocked when `disable_shell` is set (decision D2).
const SHELL_FUNCTIONS: &str = "exec,system,passthru,shell_exec,proc_open,popen";

/// Keys that only move through the isolation / shell switches (or never). An
/// admin's free-form `extra` line must not be able to reopen what isolation
/// closes, load code, or redirect mail/logs.
const FORBIDDEN_KEYS: &[&str] = &[
    "extension",
    "zend_extension",
    "open_basedir",
    "disable_functions",
    "disable_classes",
    "auto_prepend_file",
    "auto_append_file",
    "sendmail_path",
    "error_log",
    "upload_tmp_dir",
    "session.save_path",
    "user_ini.filename",
    "doc_root",
    "include_path",
];

/// `SiteConfig.php_pool` - see the contract §A1 for the wire example.
/// `values` keys rendered as `php_admin_value[...]` (locked against the site's
/// own `ini_set` / `set_time_limit` / `.user.ini`), like the legacy pool did.
const ADMIN_VALUE_KEYS: &[&str] = &[
    "memory_limit",
    "upload_max_filesize",
    "post_max_size",
    "max_execution_time",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhpPool {
    /// `php_value[k] = v` lines (`php_admin_value` for [`ADMIN_VALUE_KEYS`]).
    /// A BTreeMap so the rendered file is stable.
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    /// open_basedir + per-site tmp/sessions + sendmail `-f noreply@<d>`.
    #[serde(default)]
    pub isolation: bool,
    /// `php_admin_value[disable_functions]` = shell functions.
    #[serde(default)]
    pub disable_shell: bool,
    /// "ondemand" | "dynamic" | "static"
    pub pm: String,
    pub max_children: u32,
    pub max_requests: u32,
    pub idle_timeout_s: u32,
    pub request_terminate_timeout_s: u32,
    /// Admin free-form directives, rendered as `php_value[k] = v` in order.
    #[serde(default)]
    pub extra: Vec<(String, String)>,
}

/// Pool name for a domain - dots become underscores (same rule everywhere).
pub fn pool_name(domain: &str) -> String {
    domain.replace('.', "_")
}

/// `^[a-z][a-z0-9_.]{0,63}$`
fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    key.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Shared character rules for a directive value (pool and php.ini editor):
/// ≤ 256 characters, none of `\n \r [ ] ; "` (nor any other control char).
pub fn validate_value(key: &str, value: &str) -> Result<(), String> {
    if value.chars().count() > 256 {
        return Err(format!("Value for {key} is longer than 256 characters"));
    }
    if value
        .chars()
        .any(|c| matches!(c, '[' | ']' | ';' | '"') || c.is_control())
    {
        return Err(format!(
            "Value for {key} contains a forbidden character (newline, [, ], ; or \")"
        ));
    }
    Ok(())
}

/// Validate a directive key (pool `values` and `extra`).
fn validate_key(key: &str) -> Result<(), String> {
    if !is_valid_key(key) {
        return Err(format!("Invalid PHP directive name: {key:?}"));
    }
    if FORBIDDEN_KEYS.contains(&key) {
        return Err(format!(
            "PHP directive {key} cannot be set here (it is managed by the isolation settings)"
        ));
    }
    Ok(())
}

/// Defence in depth: the panel validates too, but nothing reaches the pool
/// file unless it passes here.
pub fn validate_php_pool(pool: &PhpPool) -> Result<(), String> {
    for (k, v) in pool.values.iter().chain(pool.extra.iter().map(|(k, v)| (k, v))) {
        validate_key(k)?;
        validate_value(k, v)?;
    }
    if !matches!(pool.pm.as_str(), "ondemand" | "dynamic" | "static") {
        return Err(format!("Invalid pm mode {:?} (ondemand, dynamic or static)", pool.pm));
    }
    let in_range = |name: &str, v: u32, lo: u32, hi: u32| {
        if v < lo || v > hi {
            Err(format!("{name} must be between {lo} and {hi}"))
        } else {
            Ok(())
        }
    };
    in_range("max_children", pool.max_children, 1, 1000)?;
    in_range("max_requests", pool.max_requests, 0, 100_000)?;
    in_range("idle_timeout_s", pool.idle_timeout_s, 1, 3600)?;
    in_range("request_terminate_timeout_s", pool.request_terminate_timeout_s, 0, 86_400)?;
    Ok(())
}

/// Render the pool file. Pure: the caller validates first.
pub fn render_php_pool(
    domain: &str,
    php_version: &str,
    pool: &PhpPool,
    user: &str,
    group: &str,
) -> String {
    let name = pool_name(domain);
    let mut out = format!(
        "[{name}]\n\
         user = {user}\n\
         group = {group}\n\
         listen = /run/php/php{php_version}-fpm-{name}.sock\n\
         listen.owner = {user}\n\
         listen.group = {group}\n\
         listen.mode = 0660\n\
         \n\
         pm = {pm}\n\
         pm.max_children = {mc}\n",
        pm = pool.pm,
        mc = pool.max_children,
    );
    match pool.pm.as_str() {
        "ondemand" => {
            out.push_str(&format!("pm.process_idle_timeout = {}s\n", pool.idle_timeout_s));
        }
        "dynamic" => {
            // Same derivation as the legacy writer.
            out.push_str(&format!(
                "pm.start_servers = {}\npm.min_spare_servers = 1\npm.max_spare_servers = {}\n",
                std::cmp::min(2, pool.max_children),
                std::cmp::min(3, pool.max_children),
            ));
        }
        _ => {} // static: nothing more
    }
    out.push_str(&format!("pm.max_requests = {}\n", pool.max_requests));
    out.push_str(&format!(
        "request_terminate_timeout = {}s\n\n",
        pool.request_terminate_timeout_s
    ));

    // The plan caps are admin values, as in the legacy pool: `ini_set`,
    // `set_time_limit` and `.user.ini` cannot raise them. Everything else is
    // a plain `php_value` the site may override.
    for (k, v) in &pool.values {
        let kind = if ADMIN_VALUE_KEYS.contains(&k.as_str()) { "php_admin_value" } else { "php_value" };
        out.push_str(&format!("{kind}[{k}] = {v}\n"));
    }
    for (k, v) in &pool.extra {
        out.push_str(&format!("php_value[{k}] = {v}\n"));
    }
    out.push('\n');

    if pool.isolation {
        let site = format!("/var/www/{domain}");
        out.push_str(&format!(
            "php_admin_value[open_basedir] = {site}/:/tmp/:/usr/share/php/\n\
             php_admin_value[upload_tmp_dir] = {site}/tmp\n\
             php_admin_value[session.save_path] = {site}/tmp\n\
             php_admin_value[session.gc_probability] = 1\n\
             php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f noreply@{domain}\n"
        ));
    }
    if pool.disable_shell {
        out.push_str(&format!("php_admin_value[disable_functions] = {SHELL_FUNCTIONS}\n"));
    }
    out.push_str(&format!(
        "php_admin_value[error_log] = {PHP_FPM_LOG_DIR}/{name}.error.log\n\
         php_admin_flag[log_errors] = on\n"
    ));
    out
}

/// Serialises pool AND php.ini writes box-wide: `php-fpm -t` reads every
/// pool and the php.ini, so two saves at once would otherwise test (and
/// blame) each other's file.
pub static FPM_CONFIG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Run `php-fpm<ver> -t`. `Ok(output)` when the whole FPM config is valid, else
/// the combined stdout/stderr (FPM prints its verdict on stderr).
pub async fn test_fpm_config(php_version: &str) -> Result<String, String> {
    let bin = format!("php-fpm{php_version}");
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        safe_command(&bin).arg("-t").output(),
    )
    .await;
    match run {
        Err(_) => Err(format!("{bin} -t timed out")),
        Ok(Err(e)) => Err(format!("Could not run {bin} -t: {e}")),
        Ok(Ok(o)) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stderr),
                String::from_utf8_lossy(&o.stdout)
            )
            .trim()
            .to_string();
            if o.status.success() {
                Ok(text)
            } else {
                Err(if text.is_empty() { format!("{bin} -t failed") } else { text })
            }
        }
    }
}

/// `systemctl <action> php<ver>-fpm` under this family's unit name.
pub async fn fpm_systemctl(php_version: &str, action: &str) -> Result<(), String> {
    let unit = crate::services::pkg::service_name(&format!("php{php_version}-fpm")).await;
    let out = safe_command("systemctl")
        .args([action, &unit])
        .output()
        .await
        .map_err(|e| format!("Failed to {action} {unit}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {action} {unit} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Put `previous` back at `path` (tmp + rename), or remove `path` if there was
/// nothing before. Returns whether a previous file was restored.
pub fn restore_file(path: &str, previous: Option<&str>) -> bool {
    match previous {
        Some(prev) => {
            let tmp = format!("{path}.dockpanel.restore");
            let ok = std::fs::write(&tmp, prev)
                .and_then(|_| std::fs::rename(&tmp, path))
                .is_ok();
            if !ok {
                std::fs::remove_file(&tmp).ok();
                tracing::error!("Failed to restore the previous file at {path}");
            }
            ok
        }
        None => {
            std::fs::remove_file(path).ok();
            false
        }
    }
}

/// `chown -h user:group path` - best-effort, logged. `-h` (lchown): if the
/// path was swapped for a symlink after our checks, only the link changes
/// owner, never what it points at.
async fn chown_nofollow(path: &str, user: &str, group: &str) {
    match safe_command("chown").args(["-h", &format!("{user}:{group}"), path]).output().await {
        Ok(o) if o.status.success() => {}
        Ok(o) => tracing::warn!(
            "chown -h {user}:{group} {path} failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => tracing::warn!("chown -h {user}:{group} {path} failed: {e}"),
    }
}

/// What a root-managed path must be before the agent chmods/chowns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Dir,
    File,
}

/// Pure verdict on an `lstat` result (`None` = the path does not exist).
/// `Ok(true)`: exists and is the expected kind; `Ok(false)`: absent;
/// `Err`: a symlink or the wrong kind - refused, never followed (the site
/// user controls `/var/www/<domain>` and could plant a link to `/etc/shadow`).
fn check_kind(path: &str, file_type: Option<std::fs::FileType>, expect: Expect) -> Result<bool, String> {
    let Some(ft) = file_type else { return Ok(false) };
    if ft.is_symlink() {
        return Err(format!("Refusing to manage {path}: it is a symbolic link"));
    }
    match expect {
        Expect::Dir if !ft.is_dir() => Err(format!("Refusing to manage {path}: it is not a directory")),
        Expect::File if !ft.is_file() => Err(format!("Refusing to manage {path}: it is not a regular file")),
        _ => Ok(true),
    }
}

/// [`check_kind`] on the live path (`symlink_metadata`, i.e. `lstat`).
fn lstat_check(path: &str, expect: Expect) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => check_kind(path, Some(m.file_type()), expect),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => check_kind(path, None, expect),
        Err(e) => Err(format!("Cannot inspect {path}: {e}")),
    }
}

/// Open `path` without following a final symlink (`O_NOFOLLOW`), so the
/// chmod below is an `fchmod` on what we actually checked.
fn open_nofollow(path: &str, opts: &mut std::fs::OpenOptions, extra: i32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | extra).open(path)
}

/// Per-pool error log. PHP opens it from the WORKER (the pool user), so a
/// root-owned directory alone means nothing is ever written: pre-create the
/// file (never truncated) and hand it to the pool user on every apply - the
/// owner changes when SFTP is enabled/disabled. `Err` only for a symlink or
/// non-regular file; plain I/O trouble is logged and skipped as before.
async fn prepare_error_log(log: &str, user: &str, group: &str) -> Result<(), String> {
    if let Err(e) = std::fs::create_dir_all(PHP_FPM_LOG_DIR) {
        tracing::warn!("Could not create {PHP_FPM_LOG_DIR}: {e}");
        return Ok(());
    }
    lstat_check(log, Expect::File)?;
    let file = match open_nofollow(log, std::fs::OpenOptions::new().create(true).append(true), 0) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!("Refusing to manage {log}: it is a symbolic link"));
        }
        Err(e) => {
            tracing::warn!("Could not create {log}: {e}");
            return Ok(());
        }
    };
    let meta = file.metadata().map_err(|e| format!("Cannot inspect {log}: {e}"))?;
    check_kind(log, Some(meta.file_type()), Expect::File)?;
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o640)).ok();
    drop(file);
    chown_nofollow(log, user, group).await;
    Ok(())
}

/// `/var/www/<domain>/tmp` for isolation (uploads + sessions), 0700, owned by
/// the pool user. Same refusal rules as [`prepare_error_log`].
async fn prepare_site_tmp(tmp_dir: &str, user: &str, group: &str) -> Result<(), String> {
    if !lstat_check(tmp_dir, Expect::Dir)? {
        if let Err(e) = std::fs::create_dir_all(tmp_dir) {
            tracing::warn!("Could not create {tmp_dir}: {e}");
            return Ok(());
        }
    }
    lstat_check(tmp_dir, Expect::Dir)?;
    let dir = match open_nofollow(tmp_dir, std::fs::OpenOptions::new().read(true), libc::O_DIRECTORY) {
        Ok(d) => d,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
            return Err(format!("Refusing to manage {tmp_dir}: it is not a plain directory"));
        }
        Err(e) => {
            tracing::warn!("Could not open {tmp_dir}: {e}");
            return Ok(());
        }
    };
    use std::os::unix::fs::PermissionsExt;
    dir.set_permissions(std::fs::Permissions::from_mode(0o700)).ok();
    drop(dir);
    chown_nofollow(tmp_dir, user, group).await;
    Ok(())
}

/// What [`apply_php_pool`] replaced, so the caller can undo it if a later
/// step (vhost write, `nginx -t`, reload) fails: the backend rolls its DB
/// back on any agent error, and the pool must follow.
#[must_use = "restore() it if the rest of the site update fails"]
#[derive(Debug)]
pub struct PoolRollback {
    php_version: String,
    pool_path: String,
    previous: Option<String>,
}

impl PoolRollback {
    /// Put the previous pool file back (or remove the new one if there was
    /// none) and reload FPM. Returns whether a previous pool was restored.
    pub async fn restore(self) -> bool {
        let restored = {
            let _guard = FPM_CONFIG_LOCK.lock().await;
            restore_file(&self.pool_path, self.previous.as_deref())
        };
        if let Err(e) = fpm_systemctl(&self.php_version, "reload").await {
            tracing::warn!("{e} (after rolling back {})", self.pool_path);
        }
        tracing::info!(
            "Rolled back PHP-FPM pool {} ({})",
            self.pool_path,
            if restored { "previous pool restored" } else { "new pool removed" }
        );
        restored
    }
}

/// Write, test and load the pool for `domain`.
///
/// `Ok(None)`: no Debian `pool.d` tree for this version (RHEL family, or the
/// version is not installed) - skipped, exactly like the legacy writer.
/// `Ok(Some(rollback))`: pool written, `-t` passed, directories prepared, FPM
/// reloaded; `rollback` undoes the pool write if the caller's next steps fail.
/// `Err(msg)`: invalid pool, a symlinked/odd tmp dir or error log, or a `-t`
/// failure; the previous pool file is back (or the new one removed).
///
/// Removing the same pool from OTHER versions is a separate step
/// ([`remove_pool_from_other_versions`]) the caller runs once the vhost points
/// at this version, so a failed vhost write never strands the site.
pub async fn apply_php_pool(
    domain: &str,
    php_version: &str,
    pool: &PhpPool,
    user: &str,
    group: &str,
) -> Result<Option<PoolRollback>, String> {
    validate_php_pool(pool)?;
    let pool_dir = format!("/etc/php/{php_version}/fpm/pool.d");
    if !std::path::Path::new(&pool_dir).exists() {
        return Ok(None);
    }
    let name = pool_name(domain);
    let pool_path = format!("{pool_dir}/{name}.conf");
    let rendered = render_php_pool(domain, php_version, pool, user, group);

    let _guard = FPM_CONFIG_LOCK.lock().await;

    // Directories first: a refusal (symlink) must leave the pool untouched.
    prepare_error_log(&format!("{PHP_FPM_LOG_DIR}/{name}.error.log"), user, group).await?;
    if pool.isolation {
        prepare_site_tmp(&format!("/var/www/{domain}/tmp"), user, group).await?;
    }

    // Backup: kept in memory for the restore, and on disk for the window
    // between write and verdict, in case the agent dies inside it. Not
    // `*.conf`, so FPM never includes it; removed once the verdict is in so
    // nothing that lists pool.d (diagnostics) mistakes it for a pool.
    let previous = std::fs::read_to_string(&pool_path).ok();
    let backup = format!("{pool_path}.dockpanel.bak");
    if let Some(ref prev) = previous {
        if let Err(e) = std::fs::write(&backup, prev) {
            tracing::warn!("Could not back up {pool_path}: {e}");
        }
    }

    let tmp = format!("{pool_path}.dockpanel.tmp");
    if let Err(e) = std::fs::write(&tmp, &rendered).and_then(|_| std::fs::rename(&tmp, &pool_path)) {
        std::fs::remove_file(&tmp).ok();
        return Err(format!("Failed to write FPM pool config: {e}"));
    }

    let verdict = test_fpm_config(php_version).await;
    if let Err(output) = verdict {
        let restored = restore_file(&pool_path, previous.as_deref());
        if restored || previous.is_none() {
            std::fs::remove_file(&backup).ok();
        }
        tracing::warn!("php-fpm{php_version} -t rejected the pool for {domain}: {output}");
        return Err(format!(
            "PHP-FPM configuration test failed: {output}{}",
            if restored { " (the previous pool was restored)" } else { "" }
        ));
    }

    std::fs::remove_file(&backup).ok();

    // -t passed: a reload failure is not fatal here - the caller waits for the
    // per-site socket and stays on the shared pool if it never appears.
    if let Err(e) = fpm_systemctl(php_version, "reload").await {
        tracing::warn!("{e} (pool for {domain} applies on next restart)");
    }
    tracing::info!(
        "PHP-FPM pool written: {pool_path} (user={user}, pm={}, children={})",
        pool.pm,
        pool.max_children
    );
    Ok(Some(PoolRollback {
        php_version: php_version.to_string(),
        pool_path,
        previous,
    }))
}

/// After a version change, the old version must not keep serving a pool of
/// the same name: remove `/etc/php/<other>/fpm/pool.d/<pool>.conf` (and its
/// backup) and reload each version that had one.
pub async fn remove_pool_from_other_versions(domain: &str, keep_version: &str) {
    let name = pool_name(domain);
    for &v in PHP_VERSIONS.iter().filter(|&&v| v != keep_version) {
        let path = format!("/etc/php/{v}/fpm/pool.d/{name}.conf");
        std::fs::remove_file(format!("{path}.dockpanel.bak")).ok();
        if std::path::Path::new(&path).exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("Failed to remove stale PHP pool {path}: {e}");
                continue;
            }
            tracing::info!("Removed stale PHP pool {path} (site now on PHP {keep_version})");
            if let Err(e) = fpm_systemctl(v, "reload").await {
                tracing::warn!("{e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's A1 example.
    fn a1() -> PhpPool {
        serde_json::from_value(serde_json::json!({
            "values": {
                "memory_limit": "256M", "upload_max_filesize": "128M", "post_max_size": "136M",
                "max_execution_time": "60", "max_input_time": "60", "max_input_vars": "4000",
                "display_errors": "Off", "error_reporting": "E_ALL & ~E_DEPRECATED & ~E_STRICT",
                "date.timezone": "Europe/Paris", "short_open_tag": "Off", "allow_url_fopen": "On",
                "session.gc_maxlifetime": "1440"
            },
            "isolation": true,
            "disable_shell": true,
            "pm": "ondemand",
            "max_children": 8,
            "max_requests": 4000,
            "idle_timeout_s": 10,
            "request_terminate_timeout_s": 90,
            "extra": [["opcache.memory_consumption", "256"]]
        }))
        .unwrap()
    }

    const A1_RENDERED: &str = "[example_com]
user = www-data
group = www-data
listen = /run/php/php8.3-fpm-example_com.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 10s
pm.max_requests = 4000
request_terminate_timeout = 90s

php_value[allow_url_fopen] = On
php_value[date.timezone] = Europe/Paris
php_value[display_errors] = Off
php_value[error_reporting] = E_ALL & ~E_DEPRECATED & ~E_STRICT
php_admin_value[max_execution_time] = 60
php_value[max_input_time] = 60
php_value[max_input_vars] = 4000
php_admin_value[memory_limit] = 256M
php_admin_value[post_max_size] = 136M
php_value[session.gc_maxlifetime] = 1440
php_value[short_open_tag] = Off
php_admin_value[upload_max_filesize] = 128M
php_value[opcache.memory_consumption] = 256

php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/
php_admin_value[upload_tmp_dir] = /var/www/example.com/tmp
php_admin_value[session.save_path] = /var/www/example.com/tmp
php_admin_value[session.gc_probability] = 1
php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f noreply@example.com
php_admin_value[disable_functions] = exec,system,passthru,shell_exec,proc_open,popen
php_admin_value[error_log] = /var/log/php-fpm/example_com.error.log
php_admin_flag[log_errors] = on
";

    fn render(p: &PhpPool) -> String {
        render_php_pool("example.com", "8.3", p, "www-data", "www-data")
    }

    #[test]
    fn a1_example_renders_exactly() {
        let p = a1();
        validate_php_pool(&p).unwrap();
        assert_eq!(render(&p), A1_RENDERED);
    }

    #[test]
    fn every_value_and_extra_is_a_php_value_line() {
        let out = render(&a1());
        for (k, v) in &a1().values {
            let kind = if ADMIN_VALUE_KEYS.contains(&k.as_str()) { "php_admin_value" } else { "php_value" };
            assert!(out.contains(&format!("\n{kind}[{k}] = {v}\n")), "{k}");
        }
        assert!(out.contains("\nphp_value[opcache.memory_consumption] = 256\n"));
    }

    #[test]
    fn root_managed_paths_refuse_symlinks_and_wrong_kinds() {
        let base = std::env::temp_dir().join(format!("php_pool_kind_{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("tmp");
        let file = base.join("x.error.log");
        let link_dir = base.join("link_dir");
        let link_file = base.join("link_file");
        let dangling = base.join("dangling");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&file, "").unwrap();
        std::os::unix::fs::symlink(&dir, &link_dir).unwrap();
        std::os::unix::fs::symlink(&file, &link_file).unwrap();
        std::os::unix::fs::symlink(base.join("nowhere"), &dangling).unwrap();
        let s = |p: &std::path::Path| p.to_str().unwrap().to_string();

        assert_eq!(lstat_check(&s(&dir), Expect::Dir), Ok(true));
        assert_eq!(lstat_check(&s(&file), Expect::File), Ok(true));
        assert_eq!(lstat_check(&s(&base.join("absent")), Expect::Dir), Ok(false));
        assert_eq!(lstat_check(&s(&base.join("absent")), Expect::File), Ok(false));
        // A symlink is refused even when it points at the expected kind.
        assert!(lstat_check(&s(&link_dir), Expect::Dir).unwrap_err().contains("symbolic link"));
        assert!(lstat_check(&s(&link_file), Expect::File).unwrap_err().contains("symbolic link"));
        assert!(lstat_check(&s(&dangling), Expect::File).unwrap_err().contains("symbolic link"));
        // Wrong kind.
        assert!(lstat_check(&s(&file), Expect::Dir).unwrap_err().contains("not a directory"));
        assert!(lstat_check(&s(&dir), Expect::File).unwrap_err().contains("not a regular file"));
        // open_nofollow refuses the final symlink instead of following it.
        let err = open_nofollow(&s(&link_file), std::fs::OpenOptions::new().append(true), 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn plan_caps_are_admin_values_and_the_rest_are_not() {
        let out = render(&a1());
        for k in ADMIN_VALUE_KEYS {
            assert!(out.contains(&format!("\nphp_admin_value[{k}] = ")), "{k} must be locked");
            assert!(!out.contains(&format!("\nphp_value[{k}] = ")), "{k} must not be overridable");
        }
        assert!(out.contains("\nphp_value[max_input_time] = 60\n"));
        assert!(out.contains("\nphp_value[display_errors] = Off\n"));
    }

    #[test]
    fn isolation_off_drops_the_four_isolation_lines_but_keeps_error_log() {
        let mut p = a1();
        p.isolation = false;
        p.disable_shell = false;
        let out = render(&p);
        for k in ["open_basedir", "upload_tmp_dir", "session.save_path", "sendmail_path", "disable_functions"] {
            assert!(!out.contains(&format!("[{k}]")), "{k} should be absent");
        }
        assert!(out.contains("php_admin_value[error_log] = /var/log/php-fpm/example_com.error.log\n"));
        assert!(out.contains("php_admin_flag[log_errors] = on\n"));
    }

    #[test]
    fn error_log_path_is_the_one_the_viewer_reads() {
        // routes::nginx::php_errors reads /var/log/php-fpm/{pool_name}.error.log
        let out = render_php_pool("a.b-c.example.org", "8.4", &a1(), "u", "g");
        assert!(out.contains("php_admin_value[error_log] = /var/log/php-fpm/a_b-c_example_org.error.log\n"));
    }

    #[test]
    fn disable_shell_alone() {
        let mut p = a1();
        p.isolation = false;
        let out = render(&p);
        assert!(out.contains(
            "php_admin_value[disable_functions] = exec,system,passthru,shell_exec,proc_open,popen\n"
        ));
        assert!(!out.contains("open_basedir"));
    }

    #[test]
    fn pm_variants() {
        let mut p = a1();
        p.pm = "dynamic".into();
        p.max_children = 1;
        let out = render(&p);
        assert!(out.contains(
            "pm = dynamic\npm.max_children = 1\npm.start_servers = 1\npm.min_spare_servers = 1\npm.max_spare_servers = 1\npm.max_requests = 4000\n"
        ));
        assert!(!out.contains("process_idle_timeout"));

        p.max_children = 8;
        assert!(render(&p).contains("pm.start_servers = 2\npm.min_spare_servers = 1\npm.max_spare_servers = 3\n"));

        p.pm = "static".into();
        let out = render(&p);
        assert!(out.contains("pm = static\npm.max_children = 8\npm.max_requests = 4000\n"));
        assert!(!out.contains("spare") && !out.contains("idle"));

        p.pm = "ondemand".into();
        assert!(render(&p).contains("pm.max_children = 8\npm.process_idle_timeout = 10s\npm.max_requests = 4000\n"));
    }

    #[test]
    fn terminate_timeout_zero_is_rendered_as_disabled() {
        let mut p = a1();
        p.request_terminate_timeout_s = 0;
        assert!(render(&p).contains("request_terminate_timeout = 0s\n"));
    }

    #[test]
    fn injection_attempts_are_rejected() {
        for bad in ["256M\nphp_admin_value[open_basedir] = /", "1\r", "a]b", "a[b", "x;y", "\"q\"", "a\0b"] {
            let mut p = a1();
            p.values.insert("memory_limit".into(), bad.into());
            assert!(validate_php_pool(&p).is_err(), "value {bad:?} accepted");
            let mut p = a1();
            p.extra = vec![("max_input_nesting_level".into(), bad.into())];
            assert!(validate_php_pool(&p).is_err(), "extra value {bad:?} accepted");
        }
        let long = "a".repeat(257);
        let mut p = a1();
        p.values.insert("memory_limit".into(), long);
        assert!(validate_php_pool(&p).is_err());
        let mut p = a1();
        p.values.insert("memory_limit".into(), "a".repeat(256));
        assert!(validate_php_pool(&p).is_ok());
    }

    #[test]
    fn bad_keys_are_rejected() {
        let too_long = "a".repeat(65);
        for bad in ["", "Memory_limit", "1abc", "a b", "a]", "a[b", "a=b", "a;b", too_long.as_str()] {
            let mut p = a1();
            p.extra = vec![(bad.to_string(), "1".into())];
            assert!(validate_php_pool(&p).is_err(), "key {bad:?} accepted");
        }
        let mut p = a1();
        p.extra = vec![("a".repeat(64), "1".into())];
        assert!(validate_php_pool(&p).is_ok());
    }

    #[test]
    fn forbidden_extra_keys_are_rejected() {
        for &k in FORBIDDEN_KEYS {
            let mut p = a1();
            p.extra = vec![(k.to_string(), "x".into())];
            assert!(validate_php_pool(&p).is_err(), "extra {k} accepted");
            let mut p = a1();
            p.values.insert(k.to_string(), "x".into());
            assert!(validate_php_pool(&p).is_err(), "values {k} accepted");
        }
    }

    #[test]
    fn pool_bounds() {
        let check = |f: &dyn Fn(&mut PhpPool), ok: bool| {
            let mut p = a1();
            f(&mut p);
            assert_eq!(validate_php_pool(&p).is_ok(), ok);
        };
        check(&|p| p.pm = "adaptive".into(), false);
        check(&|p| p.max_children = 0, false);
        check(&|p| p.max_children = 1000, true);
        check(&|p| p.max_children = 1001, false);
        check(&|p| p.max_requests = 0, true);
        check(&|p| p.max_requests = 100_001, false);
        check(&|p| p.idle_timeout_s = 0, false);
        check(&|p| p.idle_timeout_s = 3601, false);
        check(&|p| p.request_terminate_timeout_s = 86_400, true);
        check(&|p| p.request_terminate_timeout_s = 86_401, false);
    }
}
