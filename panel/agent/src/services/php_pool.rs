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

/// Every PHP version the panel knows, oldest first. THE single source: the
/// install routes (`routes::php`), the IaC export, the vhost writer and the
/// pool cleanup all derive from it.
pub const PHP_VERSIONS: &[&str] = &["5.6", "7.4", "8.1", "8.2", "8.3", "8.4", "8.5"];

/// End-of-life versions kept only to host imported legacy sites (D2): no
/// security updates, Debian/Ubuntu only (deb.sury.org / ppa:ondrej/php), never
/// picked as a default.
pub const LEGACY_PHP_VERSIONS: &[&str] = &["5.6", "7.4"];

/// True for an end-of-life version from [`LEGACY_PHP_VERSIONS`].
pub fn is_legacy(version: &str) -> bool {
    LEGACY_PHP_VERSIONS.contains(&version)
}

/// INI directives introduced after PHP 5.6, with the version that brought
/// them (php.net ini list / changelogs). A key ending in `*` is a prefix.
/// Only consulted for legacy versions: an unknown `php_value` is not a
/// `php-fpm -t` error, but every worker start logs "Unable to set php_value",
/// and the directive silently does nothing - so it is not emitted at all.
const INI_SINCE: &[(&str, &str)] = &[
    // 7.0
    ("zend.assertions", "7.0"),
    ("assert.exception", "7.0"),
    ("pcre.jit", "7.0"),
    ("session.lazy_write", "7.0"),
    ("opcache.file_cache*", "7.0"),
    ("opcache.huge_code_pages", "7.0"),
    ("opcache.validate_permission", "7.0"), // 7.0.14
    ("opcache.validate_root", "7.0"),       // 7.0.14
    // 7.1
    ("hard_timeout", "7.1"),
    ("zend.signal_check", "7.1"),
    ("url_rewriter.hosts", "7.1"),
    ("session.sid_length", "7.1"),
    ("session.sid_bits_per_character", "7.1"),
    ("session.trans_sid_tags", "7.1"),
    ("session.trans_sid_hosts", "7.1"),
    ("opcache.opt_debug_level", "7.1"),
    // 7.2 / 7.3
    ("sqlite3.defensive", "7.2"), // 7.2.17 / 7.3.4
    ("session.cookie_samesite", "7.3"),
    ("syslog.*", "7.3"),
    ("mbstring.regex_stack_limit", "7.3"),
    // 7.4
    ("mbstring.regex_retry_limit", "7.4"),
    ("zend.exception_ignore_args", "7.4"),
    ("unserialize_max_depth", "7.4"),
    ("opcache.preload", "7.4"),
    ("opcache.preload_user", "7.4"),
    ("opcache.cache_id", "7.4"),
    ("ffi.*", "7.4"),
    // 8.x
    ("opcache.jit*", "8.0"),
    ("opcache.record_warnings", "8.0"),
    ("zend.exception_string_param_max_len", "8.0"),
    ("max_multipart_body_parts", "8.0"), // 8.0.28 / 8.1.16 / 8.2.3
    ("fiber.stack_size", "8.1"),
    ("mysqli.local_infile_directory", "8.1"),
    ("error_log_mode", "8.2"),
    ("mail.mixed_lf_and_crlf", "8.2"),
    ("memory_hard_limit_percent", "8.2"),
    ("zend.max_allowed_stack_size", "8.3"),
    ("zend.reserved_stack_size", "8.3"),
    ("mail.cr_lf_mode", "8.4"),
    ("opcache.file_cache_read_only", "8.5"),
    ("session.cookie_partitioned", "8.5"),
];

/// INI directives removed between 5.6 and 7.4, with the removing version
/// (they still exist on 5.6; on 7.4 they are unknown).
const INI_REMOVED: &[(&str, &str)] = &[
    ("asp_tags", "7.0"),
    ("always_populate_raw_post_data", "7.0"),
    ("opcache.load_comments", "7.0"),
    ("xsl.security_prefs", "7.0"),
    ("session.hash_function", "7.1"),
    ("session.hash_bits_per_character", "7.1"),
    ("session.entropy_file", "7.1"),
    ("session.entropy_length", "7.1"),
    ("opcache.fast_shutdown", "7.2"),
    ("sql.safe_mode", "7.2"),
    ("opcache.inherited_hack", "7.3"),
];

/// `"7.4"` -> `(7, 4)`.
fn major_minor(v: &str) -> Option<(u32, u32)> {
    let (a, b) = v.split_once('.')?;
    let b = b.split('.').next()?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn ini_table_matches(pattern: &str, key: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => pattern == key,
    }
}

/// Pure: may `key` be written as a `php_value` / `php_admin_value` in a pool
/// of `php_version`? Always `true` for non-legacy versions (8.x pools are
/// rendered exactly as before); for 5.6 / 7.4, `false` for a directive that
/// version does not know (introduced later, or removed earlier). Keys absent
/// from both tables pass through: the admin's free-form `extra` cannot be
/// checked exhaustively.
pub fn ini_key_supported(php_version: &str, key: &str) -> bool {
    if !is_legacy(php_version) {
        return true;
    }
    let Some(ver) = major_minor(php_version) else { return true };
    let introduced_later = INI_SINCE
        .iter()
        .any(|(k, since)| ini_table_matches(k, key) && major_minor(since).is_some_and(|s| ver < s));
    let removed_already = INI_REMOVED
        .iter()
        .any(|(k, removed)| ini_table_matches(k, key) && major_minor(removed).is_some_and(|r| ver >= r));
    !(introduced_later || removed_already)
}

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

/// The `open_basedir` of a site's pool. One definition for isolation and for
/// the always-on rule below.
pub fn open_basedir_value(domain: &str) -> String {
    format!("/var/www/{domain}/:/tmp/:/usr/share/php/")
}

/// Short open tags for the legacy versions (D2). Sites imported on 5.6 / 7.4
/// were written for hosts where `short_open_tag` was On; with it Off a `<?`
/// block is plain text and the file ends in "Parse error: unexpected end of
/// file". Pools of those versions therefore get it On, locked like the plan
/// caps - unless the pool sets `short_open_tag` itself (`values` or `extra`),
/// which wins. 8.x pools never get this line.
pub const LEGACY_SHORT_OPEN_TAG_LINE: &str = "php_admin_value[short_open_tag] = On\n";

fn legacy_short_open_tag_line(php_version: &str, pool: &PhpPool) -> Option<&'static str> {
    let explicit = pool.values.contains_key("short_open_tag")
        || pool.extra.iter().any(|(k, _)| k == "short_open_tag");
    (is_legacy(php_version) && !explicit).then_some(LEGACY_SHORT_OPEN_TAG_LINE)
}

/// Render the pool file. Pure: the caller validates first.
///
/// EVERY pool gets `open_basedir`, whatever its user and the `isolation` flag:
/// Apache mode can be made to hand a request to any pool's socket
/// (RewriteRule [H=]), and `open_basedir` is what makes that pool refuse a
/// script outside its own site tree. An explicit `open_basedir` in the pool's
/// values wins; the line is never emitted twice.
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
    // a plain `php_value` the site may override. On a legacy version a
    // directive that PHP does not know is left out ([`ini_key_supported`]).
    let supported = |k: &str| ini_key_supported(php_version, k);
    for (k, v) in pool.values.iter().filter(|(k, _)| supported(k.as_str())) {
        let kind = if ADMIN_VALUE_KEYS.contains(&k.as_str()) { "php_admin_value" } else { "php_value" };
        out.push_str(&format!("{kind}[{k}] = {v}\n"));
    }
    for (k, v) in pool.extra.iter().filter(|(k, _)| supported(k.as_str())) {
        out.push_str(&format!("php_value[{k}] = {v}\n"));
    }
    out.push('\n');

    let explicit_ob = pool.values.contains_key("open_basedir")
        || pool.extra.iter().any(|(k, _)| k == "open_basedir");
    if !explicit_ob {
        out.push_str(&format!(
            "php_admin_value[open_basedir] = {}\n",
            open_basedir_value(domain)
        ));
    }
    if let Some(line) = legacy_short_open_tag_line(php_version, pool) {
        out.push_str(line);
    }
    if pool.isolation {
        let site = format!("/var/www/{domain}");
        out.push_str(&format!(
            "php_admin_value[upload_tmp_dir] = {site}/tmp\n\
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

/// Pure: the text of an existing panel-managed pool file with the default
/// `open_basedir` added, or `None` when nothing should change - the file
/// already has an `open_basedir` line, is not one the panel wrote (the section
/// name must equal the file stem, the socket must be this version's
/// `php<ver>-fpm-<stem>.sock`, the stem must turn back into a valid domain), or
/// it is the distro `www.conf`.
pub fn pool_text_with_open_basedir(stem: &str, php_version: &str, text: &str) -> Option<String> {
    if stem == "www" || stem.is_empty() {
        return None;
    }
    let domain = stem.replace('_', ".");
    if !crate::routes::is_valid_domain(&domain) || pool_name(&domain) != stem {
        return None;
    }
    let first = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with(';'))?;
    if first != format!("[{stem}]") {
        return None;
    }
    let socket = format!("listen = /run/php/php{php_version}-fpm-{stem}.sock");
    if !text.lines().any(|l| l.trim() == socket) {
        return None;
    }
    let has_ob = text.lines().any(|l| {
        let t = l.trim();
        !t.starts_with(';') && t.contains("open_basedir")
    });
    if has_ob {
        return None;
    }
    let mut out = text.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "php_admin_value[open_basedir] = {}\n",
        open_basedir_value(&domain)
    ));
    Some(out)
}

/// Startup reconciliation: pools written before every pool carried
/// `open_basedir` get the default line added, then each affected php-fpm
/// version is tested and reloaded once. Idempotent; unmanaged files and the
/// distro `www.conf` are never touched. A version whose `php-fpm -t` fails
/// afterwards is put back as it was.
pub async fn reconcile_open_basedir() {
    let _guard = FPM_CONFIG_LOCK.lock().await;
    let versions: Vec<String> = std::fs::read_dir("/etc/php")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .collect();
    for ver in versions {
        let dir = format!("/etc/php/{ver}/fpm/pool.d");
        let mut changed: Vec<(String, String)> = Vec::new(); // (path, previous text)
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".conf") else { continue };
            let path = format!("{dir}/{name}");
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if !meta.is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Some(new_text) = pool_text_with_open_basedir(stem, &ver, &text) else { continue };
            let domain = stem.replace('_', ".");
            if !std::path::Path::new(&format!("/var/www/{domain}")).is_dir() {
                tracing::warn!("open_basedir reconciliation: skipping {path}, /var/www/{domain} not found");
                continue;
            }
            let tmp = format!("{path}.tmp");
            let written = std::fs::write(&tmp, &new_text).and_then(|_| std::fs::rename(&tmp, &path));
            match written {
                Ok(()) => changed.push((path, text)),
                Err(e) => {
                    std::fs::remove_file(&tmp).ok();
                    tracing::warn!("open_basedir reconciliation: cannot write {path}: {e}");
                }
            }
        }
        if changed.is_empty() {
            continue;
        }
        if let Err(e) = test_fpm_config(&ver).await {
            tracing::warn!("open_basedir reconciliation: php-fpm{ver} -t failed, reverting {} pool(s): {e}", changed.len());
            for (path, prev) in &changed {
                let _ = std::fs::write(path, prev);
            }
            continue;
        }
        tracing::info!("open_basedir added to {} PHP-FPM pool(s) of PHP {ver}", changed.len());
        let _ = crate::services::nginx::reload_php_fpm(&ver).await;
    }
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
    fn every_pool_gets_exactly_one_open_basedir() {
        let ob = "php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/\n";
        let mut p = a1();
        for (user, iso) in [("www-data", false), ("sftp_x", false), ("www-data", true), ("sftp_x", true)] {
            p.isolation = iso;
            let out = render_php_pool("example.com", "8.3", &p, user, user);
            assert_eq!(out.matches("open_basedir").count(), 1, "{user} {iso}: {out}");
            assert!(out.contains(ob));
        }
        // Isolation on is byte-identical to the pinned rendering.
        p.isolation = true;
        assert_eq!(render(&p), A1_RENDERED);
        // Isolation off: the same file minus the isolation-only lines.
        p.isolation = false;
        let off = render(&p);
        assert!(off.contains(ob) && !off.contains("upload_tmp_dir") && !off.contains("sendmail_path"));
    }

    #[test]
    fn an_explicit_open_basedir_wins_and_is_not_doubled() {
        let mut p = a1();
        p.values.insert("open_basedir".into(), "/srv/x/".into());
        for iso in [false, true] {
            p.isolation = iso;
            let out = render_php_pool("example.com", "8.3", &p, "www-data", "www-data");
            assert_eq!(out.matches("open_basedir").count(), 1, "{out}");
            assert!(out.contains("[open_basedir] = /srv/x/"));
            assert!(!out.contains("/var/www/example.com/:/tmp/"));
        }
    }

    const OLD_POOL: &str = "[example_com]\nuser = www-data\ngroup = www-data\nlisten = /run/php/php8.3-fpm-example_com.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\n\npm = dynamic\nphp_admin_value[memory_limit] = 256M\n";

    #[test]
    fn reconciliation_adds_the_line_once_to_managed_pools_only() {
        let new = pool_text_with_open_basedir("example_com", "8.3", OLD_POOL).unwrap();
        assert_eq!(
            new,
            format!("{OLD_POOL}php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/\n")
        );
        // Idempotent.
        assert_eq!(pool_text_with_open_basedir("example_com", "8.3", &new), None);
        // Missing trailing newline is handled.
        let nonl = OLD_POOL.trim_end();
        assert!(pool_text_with_open_basedir("example_com", "8.3", nonl).unwrap().contains("memory_limit] = 256M\nphp_admin_value[open_basedir]"));
        // Already has one (even an explicit different one): untouched.
        let own = format!("{OLD_POOL}php_admin_value[open_basedir] = /srv/\n");
        assert_eq!(pool_text_with_open_basedir("example_com", "8.3", &own), None);
        // A commented line does not count.
        let commented = format!("{OLD_POOL};php_admin_value[open_basedir] = /srv/\n");
        assert!(pool_text_with_open_basedir("example_com", "8.3", &commented).is_some());
        // Distro and foreign files: never.
        assert_eq!(pool_text_with_open_basedir("www", "8.3", "[www]\nuser = www-data\nlisten = /run/php/php8.3-fpm.sock\n"), None);
        assert_eq!(pool_text_with_open_basedir("example_com", "8.2", OLD_POOL), None, "socket of another version");
        assert_eq!(pool_text_with_open_basedir("other_com", "8.3", OLD_POOL), None, "section name differs from the file");
        assert_eq!(pool_text_with_open_basedir("bad name", "8.3", OLD_POOL), None);
        assert_eq!(pool_text_with_open_basedir("example_com", "8.3", ""), None);
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
    fn isolation_off_drops_the_isolation_lines_but_keeps_error_log_and_open_basedir() {
        let mut p = a1();
        p.isolation = false;
        p.disable_shell = false;
        let out = render(&p);
        assert!(out.contains("php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/
"));
        for k in ["upload_tmp_dir", "session.save_path", "sendmail_path", "disable_functions"] {
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
        assert_eq!(out.matches("open_basedir").count(), 1);
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

    #[test]
    fn version_lists_and_is_legacy() {
        assert_eq!(PHP_VERSIONS, &["5.6", "7.4", "8.1", "8.2", "8.3", "8.4", "8.5"]);
        assert_eq!(LEGACY_PHP_VERSIONS, &["5.6", "7.4"]);
        for v in LEGACY_PHP_VERSIONS {
            assert!(PHP_VERSIONS.contains(v), "{v} must be offered");
        }
        assert!(is_legacy("5.6") && is_legacy("7.4"));
        for v in ["8.1", "8.2", "8.3", "8.4", "8.5", "7.3", "", "5.6.40"] {
            assert!(!is_legacy(v), "{v}");
        }
        // Oldest first, no duplicates.
        let mut sorted: Vec<(u32, u32)> = PHP_VERSIONS.iter().map(|v| major_minor(v).unwrap()).collect();
        let before = sorted.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, before);
    }

    #[test]
    fn ini_filter_is_the_identity_for_every_non_legacy_version() {
        for &v in PHP_VERSIONS.iter().filter(|v| !is_legacy(v)) {
            for (k, _) in INI_SINCE.iter().chain(INI_REMOVED.iter()) {
                let key = k.replace('*', "_x");
                assert!(ini_key_supported(v, &key), "{v} {key}");
            }
        }
    }

    #[test]
    fn ini_filter_per_legacy_version() {
        // 5.6: everything newer goes, what 7.x removed stays.
        for k in ["session.cookie_samesite", "zend.exception_ignore_args", "opcache.jit",
                  "opcache.jit_buffer_size", "session.sid_length", "opcache.file_cache",
                  "opcache.preload", "zend.assertions", "syslog.ident", "error_log_mode"] {
            assert!(!ini_key_supported("5.6", k), "5.6 {k}");
        }
        for k in ["session.hash_function", "always_populate_raw_post_data", "asp_tags",
                  "max_input_vars", "memory_limit", "opcache.memory_consumption", "date.timezone",
                  "session.gc_maxlifetime", "short_open_tag", "mbstring.func_overload"] {
            assert!(ini_key_supported("5.6", k), "5.6 {k}");
        }
        // 7.4: 7.x additions stay, 8.x additions and 7.x removals go.
        for k in ["session.cookie_samesite", "zend.exception_ignore_args", "session.sid_length",
                  "opcache.preload", "opcache.file_cache", "max_input_vars", "track_errors"] {
            assert!(ini_key_supported("7.4", k), "7.4 {k}");
        }
        for k in ["opcache.jit", "opcache.jit_buffer_size", "session.hash_function",
                  "always_populate_raw_post_data", "opcache.fast_shutdown", "fiber.stack_size",
                  "zend.max_allowed_stack_size"] {
            assert!(!ini_key_supported("7.4", k), "7.4 {k}");
        }
        // A key in neither table passes (extra is free-form).
        assert!(ini_key_supported("5.6", "some.unknown_key"));
    }

    #[test]
    fn panel_defaults_render_identically_on_legacy_versions() {
        // Every key the PHP settings card sends exists in 5.6 and 7.4: the
        // pinned rendering only differs by the socket's version.
        for v in ["5.6", "7.4"] {
            let out = render_php_pool("example.com", v, &a1(), "www-data", "www-data");
            assert_eq!(out, A1_RENDERED.replace("php8.3-fpm", &format!("php{v}-fpm")), "{v}");
        }
    }

    #[test]
    fn legacy_versions_get_short_open_tag_unless_the_pool_sets_it() {
        let mut p = a1();
        p.values.remove("short_open_tag");
        let line = "php_admin_value[short_open_tag] = On\n";
        for v in LEGACY_PHP_VERSIONS {
            let out = render_php_pool("example.com", v, &p, "www-data", "www-data");
            assert_eq!(out.matches("short_open_tag").count(), 1, "{v}: {out}");
            assert!(out.contains(&format!("/usr/share/php/\n{line}")), "{v}: {out}");
        }
        // 8.x: never, and the rendering is the pinned one minus the Off line.
        for &v in PHP_VERSIONS.iter().filter(|v| !is_legacy(v)) {
            let out = render_php_pool("example.com", v, &p, "www-data", "www-data");
            assert!(!out.contains("short_open_tag"), "{v}: {out}");
        }
        assert_eq!(render(&p), A1_RENDERED.replace("php_value[short_open_tag] = Off\n", ""));
        // An explicit value (values or extra) wins: one line, theirs.
        for v in LEGACY_PHP_VERSIONS {
            let out = render_php_pool("example.com", v, &a1(), "www-data", "www-data");
            assert_eq!(out.matches("short_open_tag").count(), 1, "{v}");
            assert!(out.contains("php_value[short_open_tag] = Off\n") && !out.contains(line));
            let mut q = p.clone();
            q.extra.push(("short_open_tag".into(), "Off".into()));
            let out = render_php_pool("example.com", v, &q, "www-data", "www-data");
            assert_eq!(out.matches("short_open_tag").count(), 1, "{v}");
            assert!(!out.contains(line));
        }
    }

    fn with_new_and_removed_extras() -> PhpPool {
        let mut p = a1();
        p.extra = [
            ("session.cookie_samesite", "Lax"),
            ("opcache.jit", "tracing"),
            ("session.hash_function", "1"),
            ("zend.exception_ignore_args", "On"),
            ("opcache.jit_buffer_size", "64M"),
            ("max_input_nesting_level", "64"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        p.values.insert("session.sid_length".into(), "48".into());
        p
    }

    fn extra_block(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    #[test]
    fn legacy_pools_drop_unknown_directives_in_order() {
        let p = with_new_and_removed_extras();
        let r = |v: &str| render_php_pool("example.com", v, &p, "www-data", "www-data");

        let out56 = r("5.6");
        assert!(out56.contains(&extra_block(&[
            "php_admin_value[upload_max_filesize] = 128M",
            "php_value[session.hash_function] = 1",
            "php_value[max_input_nesting_level] = 64",
            "",
        ])), "{out56}");
        for k in ["cookie_samesite", "opcache.jit", "exception_ignore_args", "sid_length"] {
            assert!(!out56.contains(k), "5.6 {k}");
        }

        let out74 = r("7.4");
        assert!(out74.contains("php_value[session.sid_length] = 48\n"));
        assert!(out74.contains(&extra_block(&[
            "php_admin_value[upload_max_filesize] = 128M",
            "php_value[session.cookie_samesite] = Lax",
            "php_value[zend.exception_ignore_args] = On",
            "php_value[max_input_nesting_level] = 64",
            "",
        ])), "{out74}");
        for k in ["opcache.jit", "hash_function"] {
            assert!(!out74.contains(k), "7.4 {k}");
        }
    }

    #[test]
    fn php83_keeps_every_directive_byte_for_byte() {
        // Before the legacy filter, render_php_pool wrote every `values` entry
        // then every `extra` entry unconditionally. Rebuild that block by hand
        // and require it verbatim in the 8.3 output.
        let p = with_new_and_removed_extras();
        let out = render(&p);
        let mut expected = String::new();
        for (k, v) in &p.values {
            let kind = if ADMIN_VALUE_KEYS.contains(&k.as_str()) { "php_admin_value" } else { "php_value" };
            expected.push_str(&format!("{kind}[{k}] = {v}\n"));
        }
        for (k, v) in &p.extra {
            expected.push_str(&format!("php_value[{k}] = {v}\n"));
        }
        expected.push('\n');
        assert!(out.contains(&format!("request_terminate_timeout = 90s\n\n{expected}php_admin_value[open_basedir]")), "{out}");
        // And the pinned A1 rendering is untouched.
        assert_eq!(render(&a1()), A1_RENDERED);
    }
}
