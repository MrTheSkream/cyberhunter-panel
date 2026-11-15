//! Apache behind nginx, per site (feature 4: ".htaccess").
//!
//! nginx stays in front of every site: it owns 80/443 and the per-site IP, TLS
//! and ACME, the WAF, bot protection, rate limits, headers, gzip and the access
//! log (statistics, bandwidth, fail2ban). A PHP site in `web_server = "apache"`
//! mode has nginx serve its static files and hand everything else to Apache on
//! the loopback ([`LISTEN_ADDR`]), where Apache reads `.htaccess` and sends PHP
//! to the SAME per-site PHP-FPM pool the nginx mode uses.
//!
//! Everything that decides what goes into a file is a pure function here
//! (`render_apache_vhost`, the global config bodies, the alias patchers, the
//! timeout choice), so it is testable without a box. The side effects - writing
//! a vhost, `apache2ctl configtest`, reloading - are thin wrappers below them.
//!
//! Debian/Ubuntu only. The RHEL family's `httpd` is not supported yet and every
//! entry point refuses it with [`UNSUPPORTED_MSG`] instead of half-working.

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use std::time::Duration;

/// The only address Apache ever listens on. 8080, 8443 and 8880 belong to the
/// panel and Traefik, and 8081 to PowerDNS's HTTP API (`install_powerdns`
/// writes `webserver-port=8081`). The configure step still checks that
/// nothing else holds this port and refuses with a clear message.
pub const LISTEN_ADDR: &str = "127.0.0.1:8091";
/// The port half of [`LISTEN_ADDR`], for the "is it free" probe.
pub const LISTEN_PORT: u16 = 8091;
/// What nginx's `proxy_pass` points at in Apache mode.
pub const UPSTREAM: &str = "http://127.0.0.1:8091";

/// First line of every file the panel writes under /etc/apache2.
pub const MANAGED_HEADER: &str = "# Managed by CyberHunter - Panel. Do not edit by hand.";

/// Where per-site Apache vhosts live (written directly, no a2ensite).
pub const SITES_DIR: &str = "/etc/apache2/sites-enabled";
/// Per-site Apache error logs.
pub const LOG_DIR: &str = "/var/log/apache2";
/// The systemd unit (Debian).
pub const UNIT: &str = "apache2";

pub const PORTS_CONF_PATH: &str = "/etc/apache2/ports.conf";
/// The panel's global Apache conf. The `zz-` prefix is load-bearing: Debian
/// enables `security.conf` (`ServerTokens OS`, `ServerSignature On`) from the
/// same conf-enabled directory, and the last directive read wins, so a file
/// sorted before it would have its `ServerTokens Prod` silently overridden.
pub const GLOBAL_CONF_NAME: &str = "zz-cyberhunter";
pub const GLOBAL_CONF_PATH: &str = "/etc/apache2/conf-available/zz-cyberhunter.conf";
pub const GLOBAL_CONF_ENABLED: &str = "/etc/apache2/conf-enabled/zz-cyberhunter.conf";

/// Modules the vhosts need. `alias` carries the catch-all's `Redirect 404`.
pub const MODULES: &[&str] = &[
    "mpm_event",
    "proxy",
    "proxy_fcgi",
    "rewrite",
    "remoteip",
    "headers",
    "expires",
    "setenvif",
    "alias",
];

/// The refusal every Apache entry point gives on the RHEL family.
pub const UNSUPPORTED_MSG: &str = "Apache mode is not supported on RHEL yet";
/// Machine-readable code of the 409 `put_site` answers when Apache is absent.
pub const NOT_INSTALLED_CODE: &str = "apache_not_installed";
/// Machine-readable code of the refusal on an unsupported OS.
pub const UNSUPPORTED_CODE: &str = "apache_unsupported";

/// Default for both the Apache `ProxyTimeout` and nginx's `proxy_read_timeout`
/// when the site's pool says nothing.
pub const DEFAULT_TIMEOUT_S: u32 = 300;
/// Apache refuses a `LimitRequestBody` above 2 GiB - 1.
pub const MAX_REQUEST_BODY: u64 = 2_147_483_647;

/// Root of the directories files are staged in before an unsandboxed
/// `install` places them (same pattern as pdns.conf: the agent's own mount
/// namespace may not have /etc/apache2 writable when Apache was installed
/// after the agent started). Nothing ever removes this root itself: each
/// call stages under a name of its own (see [`stage_path`]) and removes only
/// that, so concurrent calls never delete each other's files.
const STAGE_DIR: &str = "/var/lib/dockpanel/apache-stage";
/// Sub-directory of [`STAGE_DIR`] for single files staged by [`write_file`].
/// Separate from the per-call global-config directories.
const FILE_STAGE_DIR: &str = "/var/lib/dockpanel/apache-stage/files";

static STAGE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A staging name unique to this call: `<parent>/<kind>-<pid>-<seq>`. The
/// pid keeps two agent processes (an old one still finishing during a
/// restart) apart; the counter keeps concurrent calls in one process apart.
fn stage_path(parent: &str, kind: &str) -> String {
    let seq = STAGE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{parent}/{kind}-{}-{seq}", std::process::id())
}

// ── Mode selection ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebServer {
    Nginx,
    Apache,
}

/// Validate a `web_server` value. Absent means nginx (contract A1).
pub fn parse_web_server(value: Option<&str>) -> Result<WebServer, String> {
    match value {
        None | Some("nginx") => Ok(WebServer::Nginx),
        Some("apache") => Ok(WebServer::Apache),
        Some(other) => {
            let shown: String = other
                .chars()
                .filter(|c| !c.is_control())
                .take(32)
                .collect();
            Err(format!(
                "Invalid web_server '{shown}': use \"nginx\" or \"apache\""
            ))
        }
    }
}

/// Whether a site is served through Apache. Only PHP sites can be; any other
/// runtime is treated as nginx whatever `web_server` says (contract A1).
pub fn uses_apache(runtime: &str, web_server: Option<&str>) -> bool {
    runtime == "php" && web_server == Some("apache")
}

/// `web_server` for a re-render that was not told the mode (certificate
/// paths that rebuild the vhost from a partial description): the explicit
/// value if any, else "apache" when this domain has a panel-managed Apache
/// vhost on disk. Without this, issuing or renewing a certificate silently
/// moved an Apache site back to plain nginx.
pub fn infer_web_server(domain: &str, explicit: Option<&str>) -> Option<String> {
    if let Some(v) = explicit {
        return Some(v.to_string());
    }
    is_managed_vhost(&vhost_path(domain)).then(|| "apache".to_string())
}

// ── Paths ───────────────────────────────────────────────────────────────

pub fn vhost_path(domain: &str) -> String {
    format!("{SITES_DIR}/{domain}.conf")
}

pub fn error_log_path(domain: &str) -> String {
    format!("{LOG_DIR}/{domain}.error.log")
}

/// The directory both nginx (`root {{ root }}/{{ domain }}/public`) and Apache
/// serve for a PHP site.
pub fn document_root(root: Option<&str>, domain: &str) -> String {
    crate::services::nginx::document_root_for(
        &format!("{}/{domain}", root.unwrap_or("/var/www")),
        "php",
    )
}

/// True when `path` is a file this panel wrote (first line is the header).
pub fn is_managed_vhost(path: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c.starts_with(MANAGED_HEADER))
        .unwrap_or(false)
}

/// Domains that currently have a panel-managed Apache vhost.
pub fn managed_domains() -> Vec<String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(SITES_DIR).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(domain) = name.strip_suffix(".conf") else {
            continue;
        };
        if is_managed_vhost(&entry.path().to_string_lossy()) {
            out.push(domain.to_string());
        }
    }
    out.sort();
    out
}

// ── Pure rendering ──────────────────────────────────────────────────────

/// Timeout for one PHP request, in seconds: the pool's
/// `request_terminate_timeout`, else its `max_execution_time`, else 300.
/// Used for Apache's `ProxyTimeout` and nginx's `proxy_read_timeout` alike, so
/// the two hops in front of PHP give up at the same moment.
pub fn request_timeout_s(pool: Option<&crate::services::php_pool::PhpPool>) -> u32 {
    if let Some(p) = pool {
        if p.request_terminate_timeout_s > 0 {
            return p.request_terminate_timeout_s;
        }
        if let Some(n) = p
            .values
            .get("max_execution_time")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
        {
            return n;
        }
    }
    DEFAULT_TIMEOUT_S
}

/// The `ProxyTimeout` of a panel-managed vhost body (`None` for a file the
/// panel did not write, or one without the directive).
pub fn proxy_timeout_in_vhost(content: &str) -> Option<u32> {
    if !content.starts_with(MANAGED_HEADER) {
        return None;
    }
    content.lines().find_map(|l| {
        l.trim()
            .strip_prefix("ProxyTimeout ")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
    })
}

/// The `ProxyTimeout` currently in `domain`'s managed Apache vhost, for an
/// nginx re-render that does not know the site's pool (certificate issue or
/// renewal): without it nginx fell back to 300 s while Apache kept the site's
/// own value.
pub fn existing_vhost_timeout(domain: &str) -> Option<u32> {
    std::fs::read_to_string(vhost_path(domain))
        .ok()
        .and_then(|c| proxy_timeout_in_vhost(&c))
}

/// `LimitRequestBody` for an upload limit in MB, capped at Apache's maximum.
/// 0 MB means "no limit" for nginx's `client_max_body_size` and for Apache.
pub fn limit_request_body(max_upload_mb: u32) -> u64 {
    (u64::from(max_upload_mb) * 1_048_576).min(MAX_REQUEST_BODY)
}

/// Everything one Apache vhost is made of.
pub struct ApacheVhost<'a> {
    pub domain: &'a str,
    /// Extra names, the same as the nginx `server_name` beyond the domain.
    pub aliases: &'a [String],
    pub document_root: &'a str,
    /// The pool socket `put_site` resolved, `unix:/run/php/...sock` or bare.
    pub php_socket: &'a str,
    pub timeout_s: u32,
    pub max_upload_mb: u32,
}

/// A path that is safe to place unquoted in an Apache directive.
fn is_safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("..")
        && path.len() <= 4096
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
}

// ── What a customer's .htaccess may do (contract A3) ───────────────────────
//
// THREAT. Every site's pool socket is reachable by the one Apache user, so a
// directive in a tenant's .htaccess that makes Apache proxy to ANOTHER site's
// `unix:/run/php/...sock` would run that tenant's request in the other
// tenant's PHP-FPM pool. `AllowOverride All` allowed exactly that through
// `SetHandler`/`AddHandler "proxy:unix:<other>.sock|fcgi://localhost"`, also
// when wrapped in `<Files>`/`<FilesMatch>`/`<If>`.
//
// WHAT WAS TRIED (Apache 2.4.58, Ubuntu 24.04, two real php-fpm pools):
//  - `<Proxy>` / `<ProxyMatch>` access rules (`<Proxy "*"> Require all
//    denied`, with or without an allow for the site's own worker, in the
//    vhost or globally, with or without a ProxyPass): NOT ENFORCED. The
//    sections are only walked for requests that are already proxy requests
//    at translate/map_to_storage time (ProxyPass, ProxyPassMatch). A handler
//    forced afterwards (SetHandler/AddHandler/RewriteRule [H=]) never goes
//    through them, so even the site's own legitimate PHP request ran under a
//    deny-all `<Proxy>`. Emitting one would be false assurance, so none is
//    emitted.
//  - Restricting what .htaccess may set: EFFECTIVE. The vhost's own
//    `<FilesMatch "\.php$"> SetHandler ...` is server config and is not
//    subject to AllowOverride, so PHP keeps working while the tenant loses
//    SetHandler, AddHandler, Action, SetInputFilter, ... in every context.
//
// WHAT IS DONE. No FileInfo category (it bundles SetHandler/AddHandler with
// the harmless rest). The categories that carry none of the handler-mapping
// directives are granted whole, and the harmless FileInfo directives that real
// applications use are re-added one by one with `AllowOverrideList`.
// `Nonfatal=Override` turns a refused directive into a logged warning instead
// of a 500, so a migrated site whose .htaccess carries a stray handler line
// (cPanel `AddHandler application/x-httpd-ea-php74 .php`, Drupal's
// `SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006`) keeps working
// with that line ignored. Containers (`<IfModule>`, `<Files>`, `<FilesMatch>`,
// `<If>`, `<Limit>`) stay allowed: a bare `AllowOverride None` plus a list
// refuses them and breaks every WordPress .htaccess.
//
// KNOWN LIMIT. `RewriteRule ... [H=proxy:unix:<other>.sock|fcgi://localhost]`
// (and `[P]` to a TCP `fcgi://` URL) cannot be refused by any Apache
// configuration while RewriteRule itself is allowed, and WordPress, Laravel,
// Joomla and Drupal all need RewriteRule. What stops it in practice is the
// pool: the request's script path is inside THIS site's tree, outside the other
// pool's `open_basedir`, so the other pool answers "No input file specified".
// The vhost default `Options +SymLinksIfOwnerMatch -FollowSymLinks` refuses a
// symlink owned by this site's user whose target belongs to another user (403).
// mod_rewrite accepts either option. .htaccess MAY switch FollowSymLinks back
// on (`Options=` lists it): Drupal and many migrated sites ship
// `Options +FollowSymLinks` and a 500 there is not acceptable. Residual risk:
// a tenant who does that plus `[H=]` can only run scripts that already exist
// in the other site's tree, under that site's own `open_basedir` (pools under
// a dedicated user always carry one, see `php_pool::render_php_pool`).

/// `AllowOverride` arguments: categories whose directives cannot map a handler.
/// `Options=` lists what `Options` may turn on or off from .htaccess (no
/// ExecCGI, no Includes). No `FileInfo`, no `All`.
const ALLOW_OVERRIDE: &str = "AuthConfig Limit Indexes \
Options=FollowSymLinks,SymLinksIfOwnerMatch,Indexes,MultiViews Nonfatal=Override";

/// The FileInfo directives re-allowed one by one (`AllowOverrideList`):
/// rewriting, redirects, error documents, headers, content types and
/// encodings, environment. Deliberately absent: SetHandler, AddHandler, Action,
/// AddInputFilter, SetInputFilter.
const ALLOW_OVERRIDE_LIST: &[&str] = &[
    "RewriteEngine", "RewriteBase", "RewriteCond", "RewriteRule", "RewriteOptions",
    "Redirect", "RedirectMatch", "RedirectPermanent", "RedirectTemp",
    "ErrorDocument",
    "Header", "RequestHeader",
    "AddType", "ForceType", "RemoveType", "RemoveHandler",
    "AddDefaultCharset", "AddCharset", "RemoveCharset",
    "AddEncoding", "RemoveEncoding", "AddLanguage", "RemoveLanguage", "LanguagePriority",
    "FileETag", "MultiviewsMatch",
    "SetEnv", "SetEnvIf", "SetEnvIfNoCase", "BrowserMatch", "BrowserMatchNoCase",
    "UnsetEnv", "PassEnv",
    "SetOutputFilter", "AddOutputFilter", "AddOutputFilterByType",
];

/// Render `/etc/apache2/sites-enabled/<domain>.conf` (contract A3).
///
/// Every value is validated here, at the choke point, rather than trusted from
/// the caller: the file is root-owned config, and a newline or a quote in a
/// name or path would let it carry directives of its own.
pub fn render_apache_vhost(v: &ApacheVhost) -> Result<String, String> {
    if !crate::routes::is_valid_domain(v.domain) {
        return Err("Invalid domain for the Apache vhost".into());
    }
    for alias in v.aliases {
        if !crate::routes::is_valid_domain(alias) {
            return Err(format!(
                "Invalid alias for the Apache vhost: {}",
                alias.chars().filter(|c| !c.is_control()).take(64).collect::<String>()
            ));
        }
    }
    if !is_safe_path(v.document_root) {
        return Err("Invalid document root for the Apache vhost".into());
    }
    let socket = v.php_socket.strip_prefix("unix:").unwrap_or(v.php_socket);
    if !is_safe_path(socket) || !socket.ends_with(".sock") {
        return Err("Invalid PHP-FPM socket for the Apache vhost".into());
    }
    let timeout = if v.timeout_s == 0 {
        DEFAULT_TIMEOUT_S
    } else {
        v.timeout_s.min(86_400)
    };

    let mut aliases: Vec<&str> = Vec::new();
    for a in v.aliases {
        if a != v.domain && !aliases.contains(&a.as_str()) {
            aliases.push(a);
        }
    }

    let domain = v.domain;
    let root = v.document_root;
    let mut out = String::new();
    out.push_str(MANAGED_HEADER);
    out.push('\n');
    out.push_str(&format!("<VirtualHost {LISTEN_ADDR}>\n"));
    out.push_str(&format!("    ServerName {domain}\n"));
    if !aliases.is_empty() {
        out.push_str(&format!("    ServerAlias {}\n", aliases.join(" ")));
    }
    out.push_str(&format!("    DocumentRoot {root}\n"));
    out.push_str(&format!("    <Directory {root}>\n"));
    out.push_str(&format!("        AllowOverride {ALLOW_OVERRIDE}\n"));
    out.push_str(&format!(
        "        AllowOverrideList {}\n",
        ALLOW_OVERRIDE_LIST.join(" ")
    ));
    out.push_str("        Options +SymLinksIfOwnerMatch -FollowSymLinks -Indexes -ExecCGI -Includes\n");
    out.push_str("        Require all granted\n");
    out.push_str("    </Directory>\n");
    out.push_str("    <FilesMatch \"^\\.(ht|user\\.ini)\">\n");
    out.push_str("        Require all denied\n");
    out.push_str("    </FilesMatch>\n");
    out.push_str("    <FilesMatch \"\\.php$\">\n");
    out.push_str(&format!(
        "        SetHandler \"proxy:unix:{socket}|fcgi://localhost\"\n"
    ));
    out.push_str("    </FilesMatch>\n");
    out.push_str(&format!("    ProxyTimeout {timeout}\n"));
    out.push_str(&format!(
        "    LimitRequestBody {}\n",
        limit_request_body(v.max_upload_mb)
    ));
    out.push_str(&format!("    ErrorLog {}\n", error_log_path(domain)));
    out.push_str("    CustomLog /dev/null common\n");
    out.push_str("</VirtualHost>\n");
    Ok(out)
}

/// The names in an nginx config's first `server_name` line, minus `domain`.
/// The Apache vhost answers for exactly what nginx forwards to it.
pub fn aliases_in_nginx_config(conf: &str, domain: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in conf.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("server_name ") {
            for name in rest.trim_end_matches(';').split_whitespace() {
                if name != domain && !out.iter().any(|n| n == name) {
                    out.push(name.to_string());
                }
            }
            break;
        }
    }
    out
}

/// Add `alias` to an Apache vhost's `ServerAlias` line (or create the line
/// right after `ServerName`). `None` when the vhost has no `ServerName` line or
/// the alias is invalid; the content unchanged when it is already there.
pub fn vhost_with_alias_added(content: &str, alias: &str) -> Option<String> {
    if !crate::routes::is_valid_domain(alias) {
        return None;
    }
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let name_line = lines
        .iter()
        .position(|l| l.trim_start().starts_with("ServerName "))?;
    if lines[name_line].split_whitespace().nth(1) == Some(alias) {
        return Some(content.to_string());
    }
    if let Some(i) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("ServerAlias "))
    {
        let names: Vec<&str> = lines[i].split_whitespace().skip(1).collect();
        if names.contains(&alias) {
            return Some(content.to_string());
        }
        let line = format!("{} {alias}", lines[i].trim_end());
        lines[i] = line;
    } else {
        lines.insert(name_line + 1, format!("    ServerAlias {alias}"));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

/// Remove `alias` from an Apache vhost's `ServerAlias` line, dropping the line
/// when it becomes empty. The content unchanged when the alias is absent.
pub fn vhost_with_alias_removed(content: &str, alias: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.trim_start().starts_with("ServerAlias ") {
            let kept: Vec<&str> = line
                .split_whitespace()
                .skip(1)
                .filter(|n| *n != alias)
                .collect();
            if !kept.is_empty() {
                out.push(format!("    ServerAlias {}", kept.join(" ")));
            }
            continue;
        }
        out.push(line.to_string());
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

// ── Global configuration (contract A4) ──────────────────────────────────

/// `/etc/apache2/ports.conf`: the loopback port and nothing else. Apache must
/// never take 80/443 from nginx, nor listen on a public address.
pub fn ports_conf() -> String {
    format!(
        "{MANAGED_HEADER}\n\
         # Apache sits behind nginx and listens on the loopback only.\n\
         Listen {LISTEN_ADDR}\n"
    )
}

/// `/etc/apache2/conf-available/zz-cyberhunter.conf`.
///
/// The catch-all vhost matters: with `000-default` disabled, Apache would treat
/// the FIRST site vhost on 127.0.0.1:8091 as the default for every unknown Host
/// and serve another tenant's site. conf-enabled is included before
/// sites-enabled, so this one is the first and answers 404.
pub fn global_conf() -> String {
    format!(
        "{MANAGED_HEADER}\n\
         # The visitor's address comes from nginx, which is the only client.\n\
         RemoteIPHeader X-Real-IP\n\
         RemoteIPInternalProxy 127.0.0.1\n\
         # nginx terminated TLS: tell PHP the request was HTTPS.\n\
         SetEnvIf X-Forwarded-Proto \"^https$\" HTTPS=on\n\
         ServerTokens Prod\n\
         ServerSignature Off\n\
         \n\
         # Catch-all for names no site claims: 404, never another site.\n\
         <VirtualHost {LISTEN_ADDR}>\n\
         \x20   ServerName default.invalid\n\
         \x20   Redirect 404 /\n\
         \x20   CustomLog /dev/null common\n\
         </VirtualHost>\n"
    )
}

/// Shell script that applies the global configuration from files staged in
/// `stage`. Idempotent, run as root outside the agent's sandbox. Exits non-zero
/// with the reason on stderr; Apache is only (re)started once its config test
/// passed and the port is known to be free.
///
/// `scripts/setup.sh::configure_apache` performs the same steps.
pub fn configure_script(stage: &str) -> String {
    let mods = MODULES.join(" ");
    format!(
        r#"set -u
S='{stage}'
fail() {{ echo "$*" >&2; exit 1; }}
[ -x /usr/sbin/apache2 ] || fail "Apache is not installed"
mkdir -p /etc/apache2/conf-available {LOG_DIR} || fail "Cannot create the Apache directories"
install -m 644 "$S/ports.conf" {PORTS_CONF_PATH} || fail "Cannot write {PORTS_CONF_PATH}"
install -m 644 "$S/{GLOBAL_CONF_NAME}.conf" {GLOBAL_CONF_PATH} || fail "Cannot write {GLOBAL_CONF_PATH}"
a2dissite -q 000-default >/dev/null 2>&1 || true
a2dismod -q -f mpm_prefork mpm_worker >/dev/null 2>&1 || true
for f in /etc/apache2/mods-enabled/php*.load; do
    [ -e "$f" ] || continue
    a2dismod -q -f "$(basename "$f" .load)" >/dev/null 2>&1 || true
done
a2enmod -q {mods} >/dev/null || fail "a2enmod failed"
a2disconf -q other-vhosts-access-log >/dev/null 2>&1 || true
a2enconf -q {GLOBAL_CONF_NAME} >/dev/null || fail "a2enconf {GLOBAL_CONF_NAME} failed"
holder=$(ss -ltnpH 'sport = :{LISTEN_PORT}' 2>/dev/null | grep -v '"apache2"' || true)
[ -z "$holder" ] || fail "Port {LISTEN_PORT} is already in use by another program: $holder"
out=$(apache2ctl configtest 2>&1) || fail "Apache configuration test failed: $out"
systemctl unmask --runtime {UNIT}.service >/dev/null 2>&1 || true
systemctl enable {UNIT}.service >/dev/null 2>&1 || true
systemctl reload-or-restart {UNIT}.service || fail "Apache did not start: $(systemctl status {UNIT}.service --no-pager 2>&1 | tail -n 5)"
"#
    )
}

/// True when every piece of the global configuration is in place. Read-only.
pub fn global_config_ok() -> bool {
    let p = std::path::Path::new;
    let read = |f: &str| std::fs::read_to_string(f).unwrap_or_default();
    if read(PORTS_CONF_PATH) != ports_conf() || read(GLOBAL_CONF_PATH) != global_conf() {
        return false;
    }
    if !p(GLOBAL_CONF_ENABLED).exists()
        || p("/etc/apache2/sites-enabled/000-default.conf").exists()
        || p("/etc/apache2/mods-enabled/mpm_prefork.load").exists()
        || p("/etc/apache2/mods-enabled/mpm_worker.load").exists()
    {
        return false;
    }
    if !MODULES
        .iter()
        .all(|m| p(&format!("/etc/apache2/mods-enabled/{m}.load")).exists())
    {
        return false;
    }
    let php_module = std::fs::read_dir("/etc/apache2/mods-enabled")
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("php") && n.ends_with(".load")
        });
    !php_module
}

// ── Side effects ────────────────────────────────────────────────────────

/// `Some(reason)` when Apache mode cannot be used on this box at all.
pub async fn unsupported_reason() -> Option<String> {
    match crate::services::pkg::installer().await {
        Some(crate::services::pkg::Installer::AptGet) => None,
        Some(_) => Some(UNSUPPORTED_MSG.to_string()),
        None => Some(
            "Apache mode needs a Debian or Ubuntu server with apt (no package manager found)"
                .to_string(),
        ),
    }
}

/// Whether the Debian `apache2` package is installed. Deliberately not the
/// directory: `/etc/apache2` is in the agent unit's `ReadWritePaths`, and the
/// installers pre-create every directory listed there, so it exists on every
/// box, RHEL included.
pub async fn is_installed() -> bool {
    std::path::Path::new("/usr/sbin/apache2").exists()
        && crate::services::pkg::is_installed("apache2").await
}

pub async fn is_active() -> bool {
    tokio::time::timeout(
        Duration::from_secs(30),
        safe_command("systemctl")
            .args(["is-active", "--quiet", UNIT])
            .output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success())
    .unwrap_or(false)
}

async fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        safe_command("systemctl").args(args).output(),
    )
    .await
    .map_err(|_| format!("systemctl {} timed out", args.join(" ")))?
    .map_err(|e| format!("systemctl {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Write the global configuration and (re)start Apache on the loopback.
/// Idempotent: safe on a box that is already configured.
pub async fn apply_global_config() -> Result<(), String> {
    // A directory of this call's own: two repairs racing (two Apache-mode
    // `put_site` at once on a drifted box) must not delete each other's files,
    // and a `write_file` staging next to it must not lose its file either.
    let stage = stage_path(STAGE_DIR, "global");
    std::fs::create_dir_all(&stage).map_err(|e| format!("Cannot stage the Apache config: {e}"))?;
    let staged = (|| -> std::io::Result<()> {
        std::fs::write(format!("{stage}/ports.conf"), ports_conf())?;
        std::fs::write(format!("{stage}/{GLOBAL_CONF_NAME}.conf"), global_conf())?;
        Ok(())
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(format!("Cannot stage the Apache config: {e}"));
    }
    let result = tokio::time::timeout(
        Duration::from_secs(180),
        safe_command_unsandboxed("sh", &[])
            .args(["-c", &configure_script(&stage)])
            .output(),
    )
    .await;
    let _ = std::fs::remove_dir_all(&stage);
    let out = result
        .map_err(|_| "Configuring Apache timed out".to_string())?
        .map_err(|e| format!("Configuring Apache failed: {e}"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(msg.trim().chars().take(600).collect());
    }
    Ok(())
}

// ── An Apache the panel does not manage ─────────────────────────────────

/// Machine-readable code of the refusal when Apache is already installed and
/// managed outside the panel (409). Distinct from [`NOT_INSTALLED_CODE`], which
/// the UI answers by offering the installer.
pub const FOREIGN_CODE: &str = "apache_foreign";

/// `sites-enabled` entries the Debian package itself ships. Their presence
/// says nothing about an admin's own use: a box right after `apt install
/// apache2` (or after a failed fresh install by the panel) has `000-default`.
const STOCK_SITES: &[&str] = &["000-default.conf", "default-ssl.conf"];

/// Why an Apache the panel did not configure must be left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalConfigError {
    /// Apache is installed and managed outside the panel: never reconfigured.
    Foreign(String),
    /// Anything else (package, staging, config test, start).
    Failed(String),
}

impl std::fmt::Display for GlobalConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Foreign(m) | Self::Failed(m) => f.write_str(m),
        }
    }
}

/// True when the host part of an `addr:port` (ss's local address, or an
/// Apache `Listen` argument) is the loopback.
fn is_loopback_host(host: &str) -> bool {
    let host = host.split('%').next().unwrap_or(host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.starts_with("127.") || host == "::1" || host == "localhost"
}

/// Non-loopback addresses Apache listens on, from `ss -ltnpH` output. Only
/// lines whose process is `apache2` count.
pub fn public_apache_listeners(ss_output: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in ss_output.lines() {
        if !line.contains("\"apache2\"") {
            continue;
        }
        let Some(local) = line.split_whitespace().nth(3) else {
            continue;
        };
        let host = local.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        if !is_loopback_host(host) && !out.iter().any(|a| a == local) {
            out.push(local.to_string());
        }
    }
    out
}

/// Non-loopback `Listen` directives of a ports.conf (`Listen 80`, `Listen
/// 0.0.0.0:443 https`, `Listen [::]:80`). For when `ss` cannot name the
/// listening process (no `-p` information inside the agent's sandbox).
pub fn public_listens_in_ports_conf(ports_conf: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in ports_conf.lines() {
        let mut words = line.split_whitespace();
        if !words.next().is_some_and(|w| w.eq_ignore_ascii_case("Listen")) {
            continue;
        }
        let Some(arg) = words.next() else { continue };
        let host = arg.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        if !is_loopback_host(host) && !out.iter().any(|a| a == arg) {
            out.push(arg.to_string());
        }
    }
    out
}

/// `Some(reason)` when the installed Apache is one the admin set up and
/// manages: its ports.conf is not the panel's and it serves sites of its own
/// (`own_sites`: `sites-enabled` entries that are neither stock nor written by
/// the panel), or it listens on a non-loopback address. Pure.
pub fn foreign_apache_reason(
    ports_conf: Option<&str>,
    own_sites: &[String],
    ss_output: &str,
    active: bool,
) -> Option<String> {
    let managed = ports_conf.is_some_and(|c| c.starts_with(MANAGED_HEADER));
    let mut public = public_apache_listeners(ss_output);
    if !managed && active {
        for l in public_listens_in_ports_conf(ports_conf.unwrap_or("")) {
            if !public.contains(&l) {
                public.push(l);
            }
        }
    }
    let tail = "The panel only uses an Apache it configured itself (loopback only, \
                behind nginx) and will not reconfigure or remove this one. Keep PHP \
                sites on nginx, or retire this Apache yourself before using Apache mode.";
    if !public.is_empty() {
        return Some(format!(
            "Apache is already installed and managed outside the panel: it listens on {}. {tail}",
            public.join(", ")
        ));
    }
    if !managed && !own_sites.is_empty() {
        return Some(format!(
            "Apache is already installed and managed outside the panel: it serves sites of its own ({}). {tail}",
            own_sites.join(", ")
        ));
    }
    None
}

/// `sites-enabled/*.conf` entries that are neither stock nor panel-managed.
fn own_sites() -> Vec<String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(SITES_DIR).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".conf") || STOCK_SITES.contains(&name.as_str()) {
            continue;
        }
        if !is_managed_vhost(&entry.path().to_string_lossy()) {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// [`foreign_apache_reason`] for this box. Read-only.
pub async fn foreign_apache() -> Option<String> {
    let ports = std::fs::read_to_string(PORTS_CONF_PATH).ok();
    let ss = tokio::time::timeout(
        Duration::from_secs(15),
        safe_command("ss").args(["-ltnpH"]).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();
    let active = is_active().await;
    foreign_apache_reason(ports.as_deref(), &own_sites(), &ss, active)
}

/// Make sure an installed Apache carries the panel's global configuration
/// before a site uses it; repairs it when something drifted. An Apache the
/// admin manages themselves is never touched ([`GlobalConfigError::Foreign`]).
pub async fn ensure_global_config() -> Result<(), GlobalConfigError> {
    if global_config_ok() && is_active().await {
        return Ok(());
    }
    if let Some(why) = foreign_apache().await {
        return Err(GlobalConfigError::Foreign(why));
    }
    tracing::info!("Apache global configuration missing or drifted - applying it");
    apply_global_config().await.map_err(GlobalConfigError::Failed)
}

/// Undo what a fresh install left behind when its configuration failed: the
/// package stays installed but stopped and off at boot rather than running on
/// a default config. Unmask first: `disable` refuses a masked unit, which
/// left the old `disable --now` doing nothing. Best-effort, each step logged.
async fn park_fresh_install() {
    let unit = format!("{UNIT}.service");
    for args in [
        ["unmask", "--runtime", unit.as_str()].as_slice(),
        ["disable", unit.as_str()].as_slice(),
        ["stop", unit.as_str()].as_slice(),
    ] {
        if let Err(e) = systemctl(args).await {
            tracing::warn!("Rolling back the Apache install: {e}");
        }
    }
}

/// Install Apache (contract A4): the unit is masked for the duration of the
/// package transaction so the package's own start can never bind port 80, the
/// configuration is written and tested, and only then is Apache started.
/// On a box that already has Apache it (re)applies the panel's configuration,
/// unless that Apache is managed outside the panel ([`GlobalConfigError::Foreign`]).
pub async fn install() -> Result<(), GlobalConfigError> {
    use GlobalConfigError::Failed;
    if let Some(why) = unsupported_reason().await {
        return Err(Failed(why));
    }
    let fresh = !is_installed().await;
    if fresh {
        systemctl(&["mask", "--runtime", &format!("{UNIT}.service")])
            .await
            .map_err(Failed)?;
        crate::services::pkg::refresh_index().await;
        if let Err(e) = crate::services::pkg::install(&["apache2"]).await {
            let _ = systemctl(&["unmask", "--runtime", &format!("{UNIT}.service")]).await;
            return Err(Failed(format!("Apache install failed: {e}")));
        }
    } else if let Some(why) = foreign_apache().await {
        return Err(GlobalConfigError::Foreign(why));
    }
    if let Err(e) = apply_global_config().await {
        // A package this call just installed is parked (see
        // `park_fresh_install`). An Apache that was already serving sites is
        // left running: the configure script only restarts it after a passing
        // config test, so it still runs the last good one.
        if fresh {
            park_fresh_install().await;
        }
        return Err(Failed(e));
    }
    Ok(())
}

/// `apache2ctl configtest`, outside the sandbox: apache2ctl wants to create
/// its run directory under /run, which the agent's namespace keeps read-only.
pub async fn configtest() -> Result<(), String> {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        safe_command_unsandboxed("apache2ctl", &[])
            .arg("configtest")
            .output(),
    )
    .await
    .map_err(|_| "apache2ctl configtest timed out".to_string())?
    .map_err(|e| format!("apache2ctl configtest: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Err(text.trim().chars().take(600).collect())
    }
}

/// Reload Apache (starting it if it is stopped).
pub async fn reload() -> Result<(), String> {
    systemctl(&["reload-or-restart", UNIT]).await
}

/// Atomically write a file under /etc/apache2. Falls back to an unsandboxed
/// `install` when the agent's namespace has the tree read-only (Apache was
/// installed after the agent started and `-/etc/apache2` was skipped).
pub async fn write_file(path: &str, content: &str) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    let direct = std::fs::write(&tmp, content).and_then(|_| std::fs::rename(&tmp, path));
    match direct {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(30) => {
            std::fs::remove_file(&tmp).ok();
            std::fs::create_dir_all(FILE_STAGE_DIR)
                .map_err(|e| format!("Cannot stage {path}: {e}"))?;
            // Unique per call: two domains written at once must not share it.
            let staged = stage_path(FILE_STAGE_DIR, "file");
            std::fs::write(&staged, content).map_err(|e| format!("Cannot stage {path}: {e}"))?;
            let out = safe_command_unsandboxed("install", &[])
                .args(["-m", "644", &staged, path])
                .output()
                .await;
            let _ = std::fs::remove_file(&staged);
            match out {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(format!(
                    "Failed to write {path}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => Err(format!("Failed to write {path}: {e}")),
            }
        }
        Err(e) => {
            std::fs::remove_file(&tmp).ok();
            Err(format!("Failed to write {path}: {e}"))
        }
    }
}

/// Remove a file under /etc/apache2 (same read-only fallback as [`write_file`]).
pub async fn remove_file(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) if e.raw_os_error() == Some(30) => {
            let out = safe_command_unsandboxed("rm", &[])
                .args(["-f", path])
                .output()
                .await
                .map_err(|e| format!("Failed to remove {path}: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!("Failed to remove {path}"))
            }
        }
        Err(e) => Err(format!("Failed to remove {path}: {e}")),
    }
}

/// Put back what a vhost path held before (or remove it), then reload.
pub async fn restore_vhost(path: &str, previous: Option<&str>) -> bool {
    let restored = match previous {
        Some(prev) => write_file(path, prev).await.is_ok(),
        None => remove_file(path).await.is_ok(),
    };
    if let Err(e) = reload().await {
        tracing::warn!("Apache reload after restoring {path} failed: {e}");
    }
    restored
}

/// The Apache vhost state before `put_site` changed it, to put back when a
/// later step (nginx) fails.
pub struct ApacheRollback {
    pub path: String,
    pub previous: Option<String>,
}

impl ApacheRollback {
    pub async fn restore(self) -> bool {
        restore_vhost(&self.path, self.previous.as_deref()).await
    }
}

/// Why [`apply_vhost`] did not apply.
#[derive(Debug)]
pub enum ApplyError {
    /// `apache2ctl configtest` refused the configuration (a 400).
    Rejected(String),
    /// Writing or reloading failed (a 500).
    Failed(String),
}

/// Write a site's Apache vhost, test it and reload Apache (contract A3/A5).
/// On any failure the previous file is put back and Apache is left as it
/// was. On success returns what to restore if a later step fails.
pub async fn apply_vhost(domain: &str, rendered: &str) -> Result<ApacheRollback, ApplyError> {
    let path = vhost_path(domain);
    let previous = std::fs::read_to_string(&path).ok();
    write_file(&path, rendered).await.map_err(ApplyError::Failed)?;
    if let Err(e) = configtest().await {
        let back = match previous.as_deref() {
            Some(p) => write_file(&path, p).await.is_ok(),
            None => remove_file(&path).await.is_ok(),
        };
        return Err(ApplyError::Rejected(format!(
            "Apache config test failed: {e}{}",
            if back { " (the previous Apache configuration was restored)" } else { "" }
        )));
    }
    if let Err(e) = reload().await {
        let rb = ApacheRollback { path, previous };
        rb.restore().await;
        return Err(ApplyError::Failed(format!(
            "Apache config valid but reload failed: {e}"
        )));
    }
    Ok(ApacheRollback { path, previous })
}

/// Remove a domain's panel-managed Apache vhost (if any) and reload. Returns
/// whether there was one. Best-effort on reload.
pub async fn remove_site_vhost(domain: &str) -> Result<bool, String> {
    let path = vhost_path(domain);
    if !std::path::Path::new(&path).exists() {
        return Ok(false);
    }
    if !is_managed_vhost(&path) {
        tracing::warn!("Leaving {path} in place: it was not written by the panel");
        return Ok(false);
    }
    remove_file(&path).await?;
    if let Err(e) = reload().await {
        tracing::warn!("Apache reload after removing {path} failed: {e}");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::php_pool::PhpPool;

    fn vhost<'a>(aliases: &'a [String]) -> ApacheVhost<'a> {
        ApacheVhost {
            domain: "example.com",
            aliases,
            document_root: "/var/www/example.com/public",
            php_socket: "unix:/run/php/php8.3-fpm-example_com.sock",
            timeout_s: 120,
            max_upload_mb: 64,
        }
    }

    fn pool(rtt: u32, met: Option<&str>) -> PhpPool {
        let mut v = serde_json::json!({
            "values": {}, "isolation": true, "disable_shell": true, "pm": "ondemand",
            "max_children": 8, "max_requests": 4000, "idle_timeout_s": 10,
            "request_terminate_timeout_s": rtt, "extra": []
        });
        if let Some(m) = met {
            v["values"]["max_execution_time"] = serde_json::json!(m);
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn web_server_values() {
        assert_eq!(parse_web_server(None), Ok(WebServer::Nginx));
        assert_eq!(parse_web_server(Some("nginx")), Ok(WebServer::Nginx));
        assert_eq!(parse_web_server(Some("apache")), Ok(WebServer::Apache));
        for bad in ["", "Apache", "httpd", "apache\n", "nginx "] {
            assert!(parse_web_server(Some(bad)).is_err(), "{bad:?}");
        }
        let e = parse_web_server(Some("x\ny")).unwrap_err();
        assert!(!e.contains('\n'));
    }

    #[test]
    fn only_php_sites_use_apache() {
        assert!(uses_apache("php", Some("apache")));
        assert!(!uses_apache("php", Some("nginx")));
        assert!(!uses_apache("php", None));
        for rt in ["static", "proxy", "node", "python"] {
            assert!(!uses_apache(rt, Some("apache")), "{rt}");
        }
    }

    #[test]
    fn renders_the_contract_vhost() {
        let out = render_apache_vhost(&vhost(&[])).unwrap();
        let expected = "\
# Managed by CyberHunter - Panel. Do not edit by hand.
<VirtualHost 127.0.0.1:8091>
    ServerName example.com
    DocumentRoot /var/www/example.com/public
    <Directory /var/www/example.com/public>
        AllowOverride AuthConfig Limit Indexes Options=FollowSymLinks,SymLinksIfOwnerMatch,Indexes,MultiViews Nonfatal=Override
        AllowOverrideList RewriteEngine RewriteBase RewriteCond RewriteRule RewriteOptions Redirect RedirectMatch RedirectPermanent RedirectTemp ErrorDocument Header RequestHeader AddType ForceType RemoveType RemoveHandler AddDefaultCharset AddCharset RemoveCharset AddEncoding RemoveEncoding AddLanguage RemoveLanguage LanguagePriority FileETag MultiviewsMatch SetEnv SetEnvIf SetEnvIfNoCase BrowserMatch BrowserMatchNoCase UnsetEnv PassEnv SetOutputFilter AddOutputFilter AddOutputFilterByType
        Options +SymLinksIfOwnerMatch -FollowSymLinks -Indexes -ExecCGI -Includes
        Require all granted
    </Directory>
    <FilesMatch \"^\\.(ht|user\\.ini)\">
        Require all denied
    </FilesMatch>
    <FilesMatch \"\\.php$\">
        SetHandler \"proxy:unix:/run/php/php8.3-fpm-example_com.sock|fcgi://localhost\"
    </FilesMatch>
    ProxyTimeout 120
    LimitRequestBody 67108864
    ErrorLog /var/log/apache2/example.com.error.log
    CustomLog /dev/null common
</VirtualHost>
";
        assert_eq!(out, expected);
    }

    #[test]
    fn aliases_become_one_server_alias_line() {
        let aliases = vec!["www.example.com".to_string(), "example.org".to_string(), "example.com".to_string(), "www.example.com".to_string()];
        let out = render_apache_vhost(&vhost(&aliases)).unwrap();
        assert!(out.contains("    ServerName example.com\n    ServerAlias www.example.com example.org\n    DocumentRoot"));
        assert_eq!(out.matches("ServerAlias").count(), 1);
    }

    #[test]
    fn bare_socket_and_timeouts() {
        let mut v = vhost(&[]);
        v.php_socket = "/run/php/php8.3-fpm.sock";
        v.timeout_s = 0;
        v.max_upload_mb = 0;
        let out = render_apache_vhost(&v).unwrap();
        assert!(out.contains("proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"));
        assert!(out.contains("ProxyTimeout 300\n"));
        assert!(out.contains("LimitRequestBody 0\n"));
    }

    #[test]
    fn upload_limit_is_capped_at_apaches_maximum() {
        assert_eq!(limit_request_body(1), 1_048_576);
        assert_eq!(limit_request_body(2047), 2047 * 1_048_576);
        assert_eq!(limit_request_body(2048), MAX_REQUEST_BODY);
        assert_eq!(limit_request_body(u32::MAX), MAX_REQUEST_BODY);
    }

    #[test]
    fn injection_is_refused() {
        let bad_alias = vec!["evil.com\n    Include /etc/shadow".to_string()];
        assert!(render_apache_vhost(&vhost(&bad_alias)).is_err());
        let quote_alias = vec!["a\"b.com".to_string()];
        assert!(render_apache_vhost(&vhost(&quote_alias)).is_err());

        let mut v = vhost(&[]);
        v.domain = "example.com\nInclude x";
        assert!(render_apache_vhost(&v).is_err());

        for root in ["/var/www/x y", "/var/www/a\"b", "/var/www/a\nb", "relative/x", "/var/www/../etc", "/var/www/a>b"] {
            let mut v = vhost(&[]);
            v.document_root = root;
            assert!(render_apache_vhost(&v).is_err(), "{root:?}");
        }
        for sock in ["unix:/run/php/a|b.sock", "unix:/run/php/a\".sock", "unix:/run/php/x.socket", "unix:/run/../x.sock", "unix:/run/php/a b.sock"] {
            let mut v = vhost(&[]);
            v.php_socket = sock;
            assert!(render_apache_vhost(&v).is_err(), "{sock:?}");
        }
    }

    /// The `AllowOverride` / `AllowOverrideList` lines of a rendered vhost.
    fn override_lines(out: &str) -> (String, Vec<String>) {
        let ao = out
            .lines()
            .find_map(|l| l.trim().strip_prefix("AllowOverride "))
            .expect("AllowOverride line")
            .to_string();
        let list = out
            .lines()
            .find_map(|l| l.trim().strip_prefix("AllowOverrideList "))
            .expect("AllowOverrideList line")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        (ao, list)
    }

    #[test]
    fn htaccess_cannot_map_a_handler() {
        let out = render_apache_vhost(&vhost(&[])).unwrap();
        let (ao, list) = override_lines(&out);
        // No category that bundles SetHandler/AddHandler, and not "All".
        let cats: Vec<&str> = ao.split_whitespace().collect();
        for banned in ["All", "FileInfo"] {
            assert!(!cats.contains(&banned), "{banned} in {ao:?}");
        }
        for needed in ["AuthConfig", "Limit", "Indexes", "Nonfatal=Override"] {
            assert!(cats.contains(&needed), "{needed} missing from {ao:?}");
        }
        // Options may not switch on CGI or SSI from .htaccess.
        let opts = cats.iter().find_map(|c| c.strip_prefix("Options=")).expect("Options=");
        assert!(!opts.contains("ExecCGI") && !opts.contains("Includes"), "{opts}");
        assert!(opts.split(',').any(|o| o == "FollowSymLinks"), "{opts}");
        assert!(out.contains("Options +SymLinksIfOwnerMatch -FollowSymLinks -Indexes -ExecCGI -Includes
"));
        // None of the directives that map a handler is re-allowed.
        for banned in ["SetHandler", "AddHandler", "Action", "AddInputFilter", "SetInputFilter", "ProxyPass", "ProxyPassMatch"] {
            assert!(!list.iter().any(|d| d == banned), "{banned} must not be overridable");
        }
        // Directives the common CMS .htaccess files rely on stay possible.
        for needed in [
            "RewriteEngine", "RewriteBase", "RewriteCond", "RewriteRule", "Redirect", "RedirectMatch",
            "ErrorDocument", "Header", "AddType", "AddDefaultCharset", "SetEnvIf",
        ] {
            assert!(list.iter().any(|d| d == needed), "{needed} missing from the override list");
        }
        // `Require`, `Order`, `Allow`, `Deny`, `DirectoryIndex`, `Expires*`,
        // `Options` come with the AuthConfig/Limit/Indexes/Options categories.
        assert!(out.contains("        AllowOverride AuthConfig Limit Indexes Options="));
        assert!(!out.contains("AllowOverride All"));
    }

    #[test]
    fn the_only_proxy_target_is_the_sites_own_socket() {
        let a = render_apache_vhost(&vhost(&[])).unwrap();
        let mut other = vhost(&[]);
        other.domain = "other.org";
        other.document_root = "/var/www/other.org/public";
        other.php_socket = "/run/php/php8.3-fpm-other_org.sock";
        let b = render_apache_vhost(&other).unwrap();

        // Exactly one proxy: handler, and it is this site's socket.
        for (out, mine, theirs) in [
            (&a, "php8.3-fpm-example_com.sock", "php8.3-fpm-other_org.sock"),
            (&b, "php8.3-fpm-other_org.sock", "php8.3-fpm-example_com.sock"),
        ] {
            assert_eq!(out.matches("proxy:").count(), 1, "{out}");
            assert_eq!(out.matches(".sock").count(), 1, "{out}");
            assert!(out.contains(&format!("SetHandler \"proxy:unix:/run/php/{mine}|fcgi://localhost\"")));
            assert!(!out.contains(theirs));
        }
        // The handler lives in server config (the vhost), never in a place a
        // .htaccess override list could be asked to cover.
        let (_, list) = override_lines(&a);
        assert!(!list.iter().any(|d| d.contains("Handler") && d != "RemoveHandler" || d.contains("Proxy")));
        // `<Proxy>` sections are not enforced for handler-forced proxying
        // (verified on Apache 2.4.58): none is emitted to avoid false assurance.
        assert!(!a.contains("<Proxy") && !a.contains("<ProxyMatch"));
    }

    #[test]
    fn timeout_follows_the_pool() {
        assert_eq!(request_timeout_s(None), 300);
        assert_eq!(request_timeout_s(Some(&pool(90, Some("600")))), 90);
        assert_eq!(request_timeout_s(Some(&pool(0, Some("600")))), 600);
        assert_eq!(request_timeout_s(Some(&pool(0, Some("0")))), 300);
        assert_eq!(request_timeout_s(Some(&pool(0, Some("abc")))), 300);
        assert_eq!(request_timeout_s(Some(&pool(0, None))), 300);
    }

    #[test]
    fn document_root_matches_the_nginx_template() {
        assert_eq!(document_root(None, "example.com"), "/var/www/example.com/public");
        assert_eq!(document_root(Some("/var/www"), "example.com"), "/var/www/example.com/public");
    }

    #[test]
    fn aliases_are_read_from_the_nginx_server_name() {
        let conf = "server {\n    listen 80;\n    server_name example.com www.example.com alias.org;\n}\nserver {\n    server_name other.com;\n}\n";
        assert_eq!(aliases_in_nginx_config(conf, "example.com"), vec!["www.example.com", "alias.org"]);
        assert!(aliases_in_nginx_config("server_name example.com;", "example.com").is_empty());
        assert!(aliases_in_nginx_config("", "example.com").is_empty());
    }

    #[test]
    fn alias_patching_round_trips() {
        let base = render_apache_vhost(&vhost(&[])).unwrap();
        let one = vhost_with_alias_added(&base, "www.example.com").unwrap();
        assert!(one.contains("    ServerName example.com\n    ServerAlias www.example.com\n"));
        let two = vhost_with_alias_added(&one, "example.org").unwrap();
        assert!(two.contains("    ServerAlias www.example.com example.org\n"));
        assert_eq!(vhost_with_alias_added(&two, "example.org").unwrap(), two);
        assert_eq!(vhost_with_alias_added(&two, "example.com").unwrap(), two);
        assert!(vhost_with_alias_added(&two, "bad\nalias.com").is_none());
        assert!(vhost_with_alias_added("no server name here\n", "a.com").is_none());

        let back = vhost_with_alias_removed(&two, "www.example.com");
        assert!(back.contains("    ServerAlias example.org\n"));
        let gone = vhost_with_alias_removed(&back, "example.org");
        assert_eq!(gone, base);
        assert_eq!(vhost_with_alias_removed(&base, "nothing.com"), base);
    }

    #[test]
    fn global_config_binds_the_loopback_only() {
        let ports = ports_conf();
        let listens: Vec<&str> = ports.lines().filter(|l| l.trim_start().starts_with("Listen")).collect();
        assert_eq!(listens, vec!["Listen 127.0.0.1:8091"]);
        assert!(!ports.contains(":80\n") && !ports.contains("443"));

        let conf = global_conf();
        for needle in [
            "RemoteIPHeader X-Real-IP\n",
            "RemoteIPInternalProxy 127.0.0.1\n",
            "SetEnvIf X-Forwarded-Proto \"^https$\" HTTPS=on\n",
            "ServerTokens Prod\n",
            "ServerSignature Off\n",
            "<VirtualHost 127.0.0.1:8091>\n    ServerName default.invalid\n    Redirect 404 /\n",
        ] {
            assert!(conf.contains(needle), "{needle:?}");
        }
        assert!(!conf.contains("Listen"));
    }

    #[test]
    fn configure_script_tests_before_it_starts_apache() {
        let s = configure_script("/var/lib/dockpanel/apache-stage");
        let pos = |n: &str| s.find(n).unwrap_or_else(|| panic!("missing {n:?}"));
        assert!(pos("install -m 644 \"$S/ports.conf\"") < pos("apache2ctl configtest"));
        assert!(pos("a2dissite -q 000-default") < pos("apache2ctl configtest"));
        assert!(pos("a2enmod -q mpm_event proxy proxy_fcgi rewrite remoteip headers expires setenvif alias") < pos("apache2ctl configtest"));
        assert!(pos("sport = :8091") < pos("reload-or-restart"));
        assert!(pos("apache2ctl configtest") < pos("systemctl unmask --runtime apache2.service"));
        assert!(pos("systemctl unmask --runtime") < pos("reload-or-restart apache2.service"));
        assert!(s.contains("a2dismod -q -f mpm_prefork mpm_worker"));
        assert!(s.contains("/etc/apache2/mods-enabled/php*.load"));
        assert!(s.contains("a2enconf -q zz-cyberhunter"));
    }

    /// setup.sh writes the same two files on a fresh box. If they differed,
    /// `global_config_ok` would rewrite them at the first Apache site, which
    /// works but means setup.sh shipped a config nobody tested.
    #[test]
    fn setup_sh_writes_the_same_global_config() {
        let setup = include_str!("../../../../scripts/setup.sh").replace('\r', "");
        assert!(setup.contains(&ports_conf()), "setup.sh ports.conf differs");
        assert!(setup.contains(&global_conf()), "setup.sh zz-cyberhunter.conf differs");
        assert!(setup.contains(&format!("a2enmod -q {} >/dev/null", MODULES.join(" "))));
        assert!(setup.contains("systemctl mask --runtime apache2.service"));
        assert!(setup.contains("a2enconf -q zz-cyberhunter"));
        assert!(setup.contains("sport = :8091"));
    }

    #[test]
    fn staging_names_are_unique_per_call_and_apart_from_the_global_dirs() {
        let a = stage_path(FILE_STAGE_DIR, "file");
        let b = stage_path(FILE_STAGE_DIR, "file");
        assert_ne!(a, b);
        assert!(a.starts_with("/var/lib/dockpanel/apache-stage/files/file-"));
        let g1 = stage_path(STAGE_DIR, "global");
        let g2 = stage_path(STAGE_DIR, "global");
        assert_ne!(g1, g2);
        assert!(g1.starts_with("/var/lib/dockpanel/apache-stage/global-"));
        // Removing a global dir never removes the file staging directory.
        assert!(!FILE_STAGE_DIR.starts_with(&format!("{g1}/")));
        assert_ne!(g1, STAGE_DIR);
    }

    #[test]
    fn proxy_timeout_is_read_from_a_managed_vhost_only() {
        let body = render_apache_vhost(&vhost(&[])).unwrap();
        assert_eq!(proxy_timeout_in_vhost(&body), Some(120));
        let foreign = body.replacen(MANAGED_HEADER, "# mine", 1);
        assert_eq!(proxy_timeout_in_vhost(&foreign), None);
        let none = body.replace("    ProxyTimeout 120\n", "");
        assert_eq!(proxy_timeout_in_vhost(&none), None);
        assert_eq!(proxy_timeout_in_vhost(&body.replace("ProxyTimeout 120", "ProxyTimeout 0")), None);
    }

    #[test]
    fn apache_listeners_from_ss() {
        let ss = "\
LISTEN 0 511 127.0.0.1:8091 0.0.0.0:* users:((\"apache2\",pid=10,fd=3))
LISTEN 0 511 [::1]:8091 [::]:* users:((\"apache2\",pid=10,fd=4))
LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=11,fd=6))
";
        assert!(public_apache_listeners(ss).is_empty());
        let public = "\
LISTEN 0 511 *:80 *:* users:((\"apache2\",pid=10,fd=3))
LISTEN 0 511 0.0.0.0:8443 0.0.0.0:* users:((\"apache2\",pid=10,fd=4))
LISTEN 0 511 [::]:80 [::]:* users:((\"apache2\",pid=10,fd=5))
LISTEN 0 511 *:80 *:* users:((\"apache2\",pid=12,fd=3))
";
        assert_eq!(public_apache_listeners(public), vec!["*:80", "0.0.0.0:8443", "[::]:80"]);
    }

    #[test]
    fn listen_directives_from_ports_conf() {
        let stock = "# If you just change the port...\nListen 80\n\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n";
        assert_eq!(public_listens_in_ports_conf(stock), vec!["80", "443"]);
        assert!(public_listens_in_ports_conf(&ports_conf()).is_empty());
        assert!(public_listens_in_ports_conf("Listen [::1]:8091\nlisten 127.0.0.2:81\n").is_empty());
        assert_eq!(public_listens_in_ports_conf("Listen 0.0.0.0:8443 https\n"), vec!["0.0.0.0:8443"]);
    }

    #[test]
    fn foreign_apache_is_detected_and_ours_or_stock_is_not() {
        let stock_ports = "Listen 80\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n";
        let ours = ports_conf();
        let loopback = "LISTEN 0 511 127.0.0.1:8091 0.0.0.0:* users:((\"apache2\",pid=1,fd=3))\n";
        let public = "LISTEN 0 511 *:80 *:* users:((\"apache2\",pid=1,fd=3))\n";
        let none: Vec<String> = Vec::new();
        let own = vec!["shop.example.conf".to_string()];

        // Fresh box / package just installed / failed fresh install (stopped).
        assert_eq!(foreign_apache_reason(None, &none, "", false), None);
        assert_eq!(foreign_apache_reason(Some(stock_ports), &none, "", false), None);
        // The panel's own config, running or drifted (stopped), own sites or not.
        assert_eq!(foreign_apache_reason(Some(&ours), &none, loopback, true), None);
        assert_eq!(foreign_apache_reason(Some(&ours), &own, "", false), None);

        // The admin's Apache: own sites behind a ports.conf that is not ours.
        let r = foreign_apache_reason(Some(stock_ports), &own, "", false).unwrap();
        assert!(r.contains("shop.example.conf") && r.contains("outside the panel"), "{r}");
        // ... or listening on a public address (seen by ss, or by ports.conf
        // when ss cannot name the process and Apache is running).
        let r = foreign_apache_reason(Some(stock_ports), &none, public, true).unwrap();
        assert!(r.contains("*:80"), "{r}");
        assert!(foreign_apache_reason(Some(&ours), &none, public, true).is_some());
        let r = foreign_apache_reason(Some(stock_ports), &none, "", true).unwrap();
        assert!(r.contains("80, 443"), "{r}");
        assert!(!r.contains('\n') && !r.contains('\u{2014}'));
    }

    #[test]
    fn setup_sh_leaves_a_foreign_apache_alone_and_parks_a_failed_fresh_install() {
        let setup = include_str!("../../../../scripts/setup.sh").replace('\r', "");
        let start = setup.find("install_apache() {").expect("install_apache");
        let body = &setup[start..];
        let body = &body[..body.find("\n}\n").expect("end of install_apache")];
        assert!(body.contains("elif apache_is_foreign; then"));
        let pos = |n: &str| body.find(n).unwrap_or_else(|| panic!("missing {n:?}"));
        let unmask = body.rfind("systemctl unmask --runtime apache2.service").unwrap();
        assert!(unmask < pos("systemctl disable apache2.service"));
        assert!(pos("systemctl disable apache2.service") < pos("systemctl stop apache2.service"));
        assert!(!body.contains("disable --now"));
    }

    #[test]
    fn no_em_dash_in_generated_files() {
        let all = format!("{}{}{}{}", ports_conf(), global_conf(), configure_script("/x"), render_apache_vhost(&vhost(&[])).unwrap());
        assert!(!all.contains('\u{2014}'));
    }
}
