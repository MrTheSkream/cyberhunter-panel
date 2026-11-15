use crate::routes::nginx::SiteConfig;
use std::sync::Arc;
use tera::{Context, Tera};
use crate::safe_cmd::safe_command;

pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// The directory nginx will actually serve for a site, given its runtime.
///
/// This is not the site directory. Every template renders
/// `root {{ root }}/{{ domain }}/public` for the static and PHP runtimes, and
/// only the runtimes that proxy to a process are served from the site directory
/// itself. It lives here because two callers need the same answer and used to
/// disagree: `put_site` created the `public` subdirectory, while the migration
/// importer copied the imported site's files one level above it and then
/// deleted `public` on its way past - so every import produced a vhost whose
/// document root did not exist.
/// The one sentence that identifies the filler page as ours.
///
/// It is a constant rather than a literal at each site because the page is
/// WRITTEN when a site is created and READ back when a git deploy has to decide
/// whether a document root holds a real site or only our own filler. A deploy
/// that adopted a page it merely guessed was ours would delete an operator's
/// file, so the writer and the reader have to be the same string by
/// construction rather than by anyone remembering to update both.
pub const PLACEHOLDER_MARKER: &str = "Site is ready. Upload your files to replace this page.";

/// The filler page written into a new site's document root.
pub fn placeholder_page(domain: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><title>{domain}</title></head>\
         <body><h1>Welcome to {domain}</h1>\
         <p>{PLACEHOLDER_MARKER}</p></body></html>"
    )
}

/// Whether `path` is a file the panel itself wrote as filler.
///
/// Keyed on content, never on the name. `index.html` is the most ordinary
/// filename there is and an operator's own upload must never be mistaken for
/// ours; a file that cannot be read is, deliberately, not ours.
pub fn is_placeholder_page(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .map(|body| body.contains(PLACEHOLDER_MARKER))
        .unwrap_or(false)
}

pub fn document_root_for(site_dir: &str, runtime: &str) -> String {
    match runtime {
        "proxy" | "node" | "python" => site_dir.to_string(),
        _ => format!("{site_dir}/public"),
    }
}

/// The directory nginx actually reads site vhosts from, given which
/// convention this box's nginx package uses.
///
/// Debian/Ubuntu's nginx package ships `sites-available`/`sites-enabled`, and
/// `nginx.conf` includes only the latter. The RHEL family's nginx package has
/// **neither directory** - its `nginx.conf` includes `conf.d/*.conf` instead -
/// which `setup.sh::configure_nginx` already detects (`[ -d
/// /etc/nginx/sites-enabled ]`) when it places the PANEL's own vhost. Every
/// SITE vhost writer used to hardcode the Debian path independently instead of
/// sharing that same detection, so on a real RHEL box `/etc/nginx/sites-enabled`
/// never existed and every write failed `ENOENT` - no site of any runtime had
/// ever been creatable there.
///
/// Split from [`sites_dir`] the same way [`vhost_target_between`] is split
/// from [`vhost_target`]: the decision itself takes a plain bool, so a test
/// can exercise both conventions without needing nginx installed at all - a
/// bare `cargo test` runner has neither directory, which would make a version
/// that probed the filesystem directly pass or fail by accident of the
/// environment rather than by the code being right.
pub fn sites_dir_for(uses_sites_enabled: bool) -> &'static str {
    if uses_sites_enabled {
        "/etc/nginx/sites-enabled"
    } else {
        "/etc/nginx/conf.d"
    }
}

/// The directory nginx actually reads site vhosts from on THIS box.
pub fn sites_dir() -> &'static str {
    sites_dir_for(std::path::Path::new("/etc/nginx/sites-enabled").is_dir())
}

/// The directory a parked (disabled) site's vhost lives in, apart from the
/// live one - or the SAME directory as [`sites_dir_for`] when this box's
/// nginx has no separate one (the RHEL family). A caller scanning both
/// directories for a reference must skip the second scan when this returns
/// the same path as `sites_dir_for`, or it double-counts every match.
pub fn parked_dir_for(uses_sites_enabled: bool) -> &'static str {
    if uses_sites_enabled {
        "/etc/nginx/sites-available"
    } else {
        sites_dir_for(false)
    }
}

/// The directory a parked (disabled) site's vhost lives in on THIS box.
pub fn parked_dir() -> &'static str {
    parked_dir_for(std::path::Path::new("/etc/nginx/sites-enabled").is_dir())
}

/// Whether this box actually serves `domain` over HTTPS.
///
/// The panel used to assume it always did, and printed `https://` links and
/// monitor URLs on that assumption. That is wrong in two ordinary situations:
/// an operator terminating TLS at an external reverse proxy, whose origin
/// serves plain HTTP (issue #96), and any app or site whose certificate step
/// was skipped - including one where the deploy said so on screen.
///
/// The answer is not a guess. The agent wrote the vhost, and its own template
/// emits a `listen …443 ssl` line only when a certificate is in place, so the
/// file on disk is the record of what is being served. Traefik keeps the same
/// record in its dynamic route config, and is asked first because when it is
/// the proxy for a domain there is no nginx vhost to read.
pub fn domain_is_https(domain: &str) -> bool {
    if let Some(tls) = crate::services::traefik::route_is_tls(domain) {
        return tls;
    }
    let config_path = format!("{}/{domain}.conf", sites_dir());
    let Ok(config) = std::fs::read_to_string(&config_path) else {
        return false;
    };
    config.lines().any(|line| {
        let line = line.trim();
        line.starts_with("listen ") && line.contains("443") && line.contains("ssl")
    })
}

/// The two places a site's vhost can live, and which one a write reaches.
///
/// Disabling a site does not remove its vhost. It parks the real body beside the
/// live path and leaves a stub in its place, so nginx keeps answering on the
/// name while serving nothing. Only the live file is ever read by nginx, which
/// makes the choice between the two the difference between a site being on the
/// internet and not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VhostTarget {
    /// Nothing is parked for this domain, so the write goes into service.
    Live(String),
    /// The operator took this domain offline. Refresh the parked body and leave
    /// the stub serving; nginx never reads this path, so no reload is owed.
    Parked(String),
}

impl VhostTarget {
    pub fn path(&self) -> &str {
        match self {
            VhostTarget::Live(p) | VhostTarget::Parked(p) => p,
        }
    }

    /// True when the write reaches nginx - so a config test and a reload are
    /// owed, and only then may the caller say the site was configured.
    pub fn is_live(&self) -> bool {
        matches!(self, VhostTarget::Live(_))
    }
}

/// The listener and certificate directives of a rendered vhost, deduplicated and
/// indented ready to drop into another server block.
///
/// **The defect this closes, and it is the whole feature.** The maintenance
/// response written when a site is disabled hardcoded `listen 80;`, while every
/// template binds the server's own address whenever the panel knows it -
/// `listen 203.0.113.10:80;`. nginx attaches each server block to the listening
/// socket its directives name, and selects a name among the servers attached to
/// the socket a connection actually arrived on. So the maintenance block sat on
/// the wildcard socket and was never consulted for a request arriving on the
/// server's address: **the disabled site went on serving its own content, with
/// the panel reporting it disabled and the agent reporting success.**
///
/// Copying the addresses out of the body being parked, rather than naming them
/// here, means the response answers on exactly what the site answered on and
/// keeps doing so when the templates change. The certificate lines come too,
/// because a `listen …443 ssl` without them is a configuration nginx refuses -
/// and a site with a certificate has to be able to say it is disabled over
/// HTTPS, which is the only scheme its visitors are redirected to.
pub fn listener_lines(vhost: &str) -> String {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = String::new();
    for line in vhost.lines() {
        let t = line.trim();
        let wanted = t.starts_with("listen ")
            || t.starts_with("ssl_certificate ")
            || t.starts_with("ssl_certificate_key ");
        if wanted && !seen.contains(&t) {
            seen.push(t);
            out.push_str("    ");
            out.push_str(t);
            out.push('\n');
        }
    }
    out
}

/// Decide between an in-service path and a parked one.
///
/// Split from the domain-to-paths half so the decision itself is reachable from
/// a test: everything it depends on arrives as an argument except the single
/// filesystem question it exists to ask.
///
/// **The defect this closes.** Five writers rendered a complete vhost and each
/// named the in-service path directly. So an ordinary settings change - PHP
/// version, WAF mode, CSP, cache toggle, custom nginx, a git deploy, exposing a
/// container, provisioning a certificate - replaced the stub with a working
/// vhost and reloaded, putting a site the operator had deliberately taken
/// offline back on the internet, while the panel went on displaying it as
/// disabled. The unattended certificate-renewal loop did the same with nobody
/// watching. None of the five is a choke point the others pass through, so the
/// decision lives here rather than in any one of them.
///
/// It also repairs a second defect by construction. Re-enabling restores the
/// body frozen at the moment the site went offline, so every setting changed in
/// between was silently reverted - and a site that gained a certificate while
/// offline came back on plain HTTP, because the frozen body has no TLS listener.
/// Keeping the parked copy current means what comes back is the site as it is.
pub fn vhost_target_between(in_service: &str, parked: &str) -> VhostTarget {
    if std::path::Path::new(parked).exists() {
        VhostTarget::Parked(parked.to_string())
    } else {
        VhostTarget::Live(in_service.to_string())
    }
}

/// The in-service path and the parked path for a domain, given which
/// convention this box's nginx package uses. Split out for the same
/// filesystem-independence reason as [`sites_dir_for`].
///
/// The parked path only has to satisfy one property: nginx must never include
/// it. On Debian that's `sites-available` (nginx only reads `sites-enabled`);
/// the RHEL family has no such second directory, so the live and parked paths
/// share `conf.d`, distinguished by the `.disabled` suffix - nginx's own
/// `include conf.d/*.conf` cannot match a name ending in `.disabled`.
pub fn vhost_paths_for(domain: &str, uses_sites_enabled: bool) -> (String, String) {
    let dir = sites_dir_for(uses_sites_enabled);
    if uses_sites_enabled {
        (
            format!("{dir}/{domain}.conf"),
            format!("/etc/nginx/sites-available/{domain}.conf.disabled"),
        )
    } else {
        (
            format!("{dir}/{domain}.conf"),
            format!("{dir}/{domain}.conf.disabled"),
        )
    }
}

/// The in-service path and the parked path for a domain, in that order.
///
/// One spelling, because three call sites building these names by hand is how
/// the parked file ended up with no reader outside the pair that wrote it.
pub fn vhost_paths(domain: &str) -> (String, String) {
    vhost_paths_for(domain, std::path::Path::new("/etc/nginx/sites-enabled").is_dir())
}

/// Where a freshly rendered vhost for `domain` must be written on this box.
pub fn vhost_target(domain: &str) -> VhostTarget {
    let (in_service, parked) = vhost_paths(domain);
    vhost_target_between(&in_service, &parked)
}

/// Undo a vhost write: put `previous` back if there was one, otherwise remove the
/// file we just created. Returns whether a previous config was restored.
///
/// Every writer that replaces `/etc/nginx/sites-enabled/{domain}.conf` and then
/// validates must funnel its failure path through here. A bare `remove_file` is
/// only correct when the writer knows the path held nothing beforehand - and none
/// of the three writers knew that. `nginx -t` is a whole-server check, so an
/// unrelated broken vhost anywhere on the box fails it, and the site being edited
/// paid for it with its own configuration file.
pub fn restore_or_remove(config_path: &str, previous: Option<&str>) -> bool {
    match previous {
        Some(prev) => {
            // Restore through the same tmp+rename dance the write used, so a crash
            // mid-restore cannot leave a truncated vhost behind.
            let tmp_path = format!("{config_path}.restore");
            let ok = std::fs::write(&tmp_path, prev)
                .and_then(|_| std::fs::rename(&tmp_path, config_path))
                .is_ok();
            if !ok {
                std::fs::remove_file(&tmp_path).ok();
                tracing::error!(
                    "Failed to restore the previous nginx config at {config_path} \
                     ({} bytes) - this domain may now have no vhost",
                    prev.len()
                );
            }
            ok
        }
        None => {
            std::fs::remove_file(config_path).ok();
            false
        }
    }
}

/// Sentence appended to an error so the operator learns whether the previous
/// configuration survived. Saying nothing is what let the old behaviour stay
/// invisible for as long as it did.
pub fn restore_note(restored: bool) -> &'static str {
    if restored {
        " (the previous configuration for this domain was restored)"
    } else {
        ""
    }
}

/// The line that identifies the static branch, in BOTH templates. One constant,
/// because this string being written twice is what produced the v2.68.2 defect
/// below: the decision tested it one way and the insertion another.
const STATIC_INDEX: &str = "index index.html index.htm;";

/// The denies the static branch of both templates carries.
///
/// Each block is paired with the marker that proves it is ALREADY present, so a
/// vhost patched by an earlier version gains only what it lacks instead of a
/// duplicated block. v2.68.0/.1/.2 answered "what population does this fix reach"
/// wrongly three times in a row; this is that question asked of the retrofit's own
/// prior output, which is the one place it had not been asked.
///
/// The rendered layout is not byte-identical to a fresh render and does not need
/// to be: the template emits its denies after `location / { try_files … }` while
/// these land straight after the index line, and regex locations win over prefix
/// locations regardless of order. Order does not change what is served.
const STATIC_DENIES: &[(&str, &str)] = &[
    (
        "location ~ /\\.(?!well-known)",
        "\n\
        \x20   # Retrofitted: a site switched from php to static keeps its application\n\
        \x20   # source in the same docroot. Every deny here exists in the php presets.\n\
        \x20   location ~ /\\.(?!well-known) {\n\
        \x20       deny all;\n\
        \x20   }\n",
    ),
    (
        "location ~ \\.php$",
        "\n\
        \x20   location ~ \\.php$ {\n\
        \x20       deny all;\n\
        \x20   }\n",
    ),
    (
        "location ~ ^/sites/.*/private/",
        "\n\
        \x20   # drupal's private file store: no dot segment and no .php suffix, so\n\
        \x20   # neither deny above covers it.\n\
        \x20   location ~ ^/sites/.*/private/ {\n\
        \x20       deny all;\n\
        \x20   }\n",
    ),
];

/// Decide whether a vhost needs any deny it does not have, and return the patched
/// body if so.
///
/// Pure, so the decision is testable without a box: the caller does the I/O and
/// the `nginx -t` gate. A vhost qualifies when it renders the STATIC branch and
/// carries no FastCGI handler - a php vhost already has these denies inside its
/// preset branch. Returns `None` when nothing is missing, which is what makes the
/// migration idempotent.
///
/// ⚠ The candidacy test and the insertion test must be the SAME test. They were
/// not: candidacy asked `body.contains(STATIC_INDEX)` (a substring, anywhere) and
/// insertion asked `line.trim() == STATIC_INDEX` (a whole line). An index line
/// carrying a trailing comment satisfied the first and never the second, so the
/// file was rewritten with zero denies added - and the caller, which keys its
/// success log on the write rather than on the content, reported that vhost as
/// retrofitted. A false green on an unprotected site, repeating every restart.
pub fn patch_static_vhost(body: &str) -> Option<String> {
    if !body.lines().any(|line| line.trim() == STATIC_INDEX) || body.contains("fastcgi_pass") {
        return None;
    }
    let missing: String = STATIC_DENIES
        .iter()
        .filter(|(marker, _)| !body.contains(marker))
        .map(|(_, block)| *block)
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(
        body.lines()
            .map(|line| {
                if line.trim() == STATIC_INDEX {
                    format!("{line}\n{missing}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Retrofit the static branch's denies onto site vhosts already on disk.
///
/// v2.68.0 fixed the TEMPLATE. A template reaches a site only when something
/// re-renders its vhost, and nothing re-renders on upgrade - so a site already
/// switched from php to static keeps serving `wp-config.php`, `.env` and
/// `.git/config` as plain text after its operator has updated. v2.68.1 put the
/// retrofit in `scripts/update.sh`, and that reaches the PANEL host only: the
/// script's own header records that an agent-only box never runs it (it syncs a
/// git repo, dumps a postgres container, replaces the API - an agent box has
/// none of that), so a fleet member's sites stayed exposed. The agent owns
/// `/etc/nginx/sites-enabled` on every box it runs on, panel and member alike,
/// which makes this the only place the fix reaches the whole population.
///
/// Scoped by what the vhost IS: the static branch's `index index.html
/// index.htm;` and no FastCGI handler. A php vhost already carries these denies
/// inside its preset branch. Idempotent, and it declines to run at all if the
/// server's config is ALREADY failing `nginx -t` - that check is whole-server,
/// so one unrelated broken vhost would otherwise make this revert edits it made
/// correctly and blame itself for a fault it did not cause.
pub async fn retrofit_static_denies() {
    let dir = std::path::Path::new(sites_dir());
    let Ok(entries) = std::fs::read_dir(dir) else { return };

    let mut candidates: Vec<(std::path::PathBuf, String, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("dockpanel-panel.conf") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else { continue };
        let Some(patched) = patch_static_vhost(&body) else { continue };
        candidates.push((path, body, patched));
    }

    if candidates.is_empty() {
        return;
    }

    // Refuse to touch anything on a box whose nginx is already unhappy.
    match test_config().await {
        Ok(out) if out.success => {}
        _ => {
            tracing::warn!(
                "Skipping the static-vhost deny retrofit on {} vhost(s): nginx -t already fails, \
                 so a post-edit check could not tell my change from the existing fault",
                candidates.len()
            );
            return;
        }
    }

    let mut written: Vec<(std::path::PathBuf, String)> = Vec::new();
    for (path, previous, patched) in &candidates {
        let tmp = path.with_extension("conf.retrofit");
        if std::fs::write(&tmp, patched)
            .and_then(|_| std::fs::rename(&tmp, path))
            .is_ok()
        {
            written.push((path.clone(), previous.clone()));
        } else {
            std::fs::remove_file(&tmp).ok();
            tracing::warn!("Could not retrofit denies onto {}", path.display());
        }
    }
    if written.is_empty() {
        return;
    }

    match test_config().await {
        Ok(out) if out.success => {
            let names: Vec<String> = written
                .iter()
                .map(|(p, _)| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                .collect();
            tracing::info!(
                "Retrofitted dotfile/.php denies onto {} static vhost(s): {}",
                written.len(),
                names.join(", ")
            );
            reload().await.ok();
        }
        _ => {
            for (path, previous) in &written {
                restore_or_remove(&path.to_string_lossy(), Some(previous));
            }
            tracing::error!(
                "nginx -t rejected the static-vhost deny retrofit - all {} file(s) reverted, \
                 sites untouched",
                written.len()
            );
        }
    }
}

/// Bring every site's redirects and password protection up to date (D4).
///
/// Two repairs, both idempotent: an auth file still in the pre-D4 format
/// (`location X { auth_basic ... }`, which left PHP unprotected) is rewritten
/// at `server` level, and a vhost lacking the `include` for a redirects or
/// auth file that exists gets it at the template's place. Vhosts written
/// before the templates carried these lines lost them at their last re-render.
///
/// Unlike [`retrofit_static_denies`] this runs even when `nginx -t` already
/// fails: a legacy auth file protecting `/` (duplicate `location /`) is itself
/// a cause of that failure, and converting it is the fix. Whatever the
/// outcome, the post-edit `nginx -t` decides: pass, one reload; fail, every
/// file put back as it was.
pub async fn reconcile_site_access() {
    use crate::services::site_access as sa;

    // 05-import-hestia (D9): managed Apache vhosts written before `ExecCGI`
    // joined `Options=` are updated here, at agent start, the same way. Run
    // from this existing startup step so the shared `main.rs` stays as is.
    crate::services::apache::reconcile_vhost_overrides().await;

    let mut domains: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for dir in [sa::REDIRECTS_DIR, sa::AUTH_DIR] {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(d) = name.strip_suffix(".conf") {
                if crate::routes::is_valid_domain(d) {
                    domains.insert(d.to_string());
                }
            }
        }
    }

    // (path, previous, new)
    let mut changes: Vec<(String, String, String)> = Vec::new();
    for d in &domains {
        let auth = sa::auth_file(d);
        if let Ok(body) = std::fs::read_to_string(&auth) {
            if let Some(converted) = sa::convert_legacy_auth(d, &body) {
                changes.push((auth, body, converted));
            }
        }
        let target = vhost_target(d);
        let Ok(vhost) = std::fs::read_to_string(target.path()) else { continue };
        match sa::ensure_includes(&vhost, d, sa::SiteIncludes::on_disk(d)) {
            Ok(Some(patched)) => changes.push((target.path().to_string(), vhost, patched)),
            Ok(None) => {}
            Err(sa::NoAnchor) => tracing::warn!(
                "{} has redirects or password protection but its vhost {} has no access_log line to place the include by; re-save the site to apply them",
                d,
                target.path()
            ),
        }
    }
    if changes.is_empty() {
        return;
    }

    let was_valid = matches!(test_config().await, Ok(ref o) if o.success);
    let mut written: Vec<(String, String)> = Vec::new();
    for (path, previous, new) in &changes {
        match sa::write_atomic(path, new) {
            Ok(()) => written.push((path.clone(), previous.clone())),
            Err(e) => tracing::warn!("Could not update {path}: {e}"),
        }
    }
    if written.is_empty() {
        return;
    }

    match test_config().await {
        Ok(out) if out.success => {
            let names: Vec<&str> = written.iter().map(|(p, _)| p.as_str()).collect();
            tracing::info!(
                "Updated redirects/password protection for {} file(s): {}",
                written.len(),
                names.join(", ")
            );
            reload().await.ok();
        }
        other => {
            for (path, previous) in &written {
                sa::restore_file(path, Some(previous));
            }
            let why = match other {
                Ok(out) => out.stderr,
                Err(e) => e.to_string(),
            };
            tracing::warn!(
                "nginx -t rejected the redirects/password-protection update - all {} file(s) reverted (nginx -t {} before the update): {}",
                written.len(),
                if was_valid { "passed" } else { "already failed" },
                why.trim()
            );
        }
    }
}

/// Detect the server's primary (non-loopback, non-docker) interface IP for nginx listen directives.
/// Returns empty string if detection fails (templates fall back to wildcard listen).
pub fn detect_bind_ip() -> String {
    use std::net::UdpSocket;
    // Connect to a public IP (doesn't actually send data) to find the outbound interface
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip().to_string();
                if ip != "127.0.0.1" {
                    return ip;
                }
            }
        }
    }
    String::new()
}

/// Shape check for `SiteConfig::bind_ip`: `"primary"` → `Ok(None)`, an IPv4
/// → `Ok(Some(ip))`, anything else → `Err`. Whether the address is actually
/// assigned on the host is the caller's question (`put_site` asks it); the
/// renderer only needs the shape, since the value lands in a `listen` line.
pub fn validate_bind_ip(value: &str) -> Result<Option<std::net::Ipv4Addr>, String> {
    if value == "primary" {
        return Ok(None);
    }
    value
        .parse::<std::net::Ipv4Addr>()
        .map(Some)
        .map_err(|_| format!("bind_ip must be an IPv4 address or \"primary\", got {value:?}"))
}

/// The explicit IPv4 an existing vhost listens on, if any - the first
/// `listen A.B.C.D:port` line. `[::]:80`, bare `listen 80;` and the like are
/// not an explicit IPv4 and are skipped. Reads through [`listener_lines`] so
/// it sees exactly the lines the disable/enable path copies.
pub fn vhost_bind_ip(vhost: &str) -> Option<std::net::Ipv4Addr> {
    listener_lines(vhost).lines().find_map(|l| {
        let rest = l.trim().strip_prefix("listen ")?;
        let addr = rest.split(|c: char| c.is_whitespace() || c == ';').next()?;
        let (host, _port) = addr.rsplit_once(':')?;
        host.parse().ok()
    })
}

/// Decide which IP a vhost listens on. Pure, so every branch is testable:
///
/// 1. `requested` = an IPv4 → it; = `"primary"` → `detected`;
/// 2. `requested` absent → the IP already written in the existing vhost, if
///    it is still in `assigned` (internal re-renders - certificate upload,
///    renewal, Docker app, git deploy - must not move a site back to the
///    primary IP);
/// 3. otherwise `detected` (empty string = wildcard `listen 80`).
pub fn resolve_bind_ip(
    requested: Option<&str>,
    existing_vhost: Option<&str>,
    assigned: &[std::net::Ipv4Addr],
    detected: &str,
) -> String {
    match requested {
        Some("primary") => detected.to_string(),
        Some(ip) => ip.to_string(),
        None => existing_vhost
            .and_then(vhost_bind_ip)
            .filter(|ip| assigned.contains(ip))
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| detected.to_string()),
    }
}

/// [`resolve_bind_ip`] with the system lookups filled in. The host's
/// addresses are only enumerated when the existing vhost names an IP other
/// than the detected one - the common case costs no extra process.
fn bind_ip_for(domain: &str, config: &SiteConfig) -> String {
    let detected = detect_bind_ip();
    if config.bind_ip.is_some() {
        return resolve_bind_ip(config.bind_ip.as_deref(), None, &[], &detected);
    }
    let existing = std::fs::read_to_string(vhost_target(domain).path()).ok();
    let assigned: Vec<std::net::Ipv4Addr> = match existing.as_deref().and_then(vhost_bind_ip) {
        Some(ip) if ip.to_string() != detected => crate::services::server_ips::host_addrs_sync()
            .map(|a| a.into_iter().map(|a| a.ip).collect())
            .unwrap_or_else(|e| {
                tracing::warn!("{e} - {domain} falls back to the primary IP");
                Vec::new()
            }),
        _ => Vec::new(),
    };
    resolve_bind_ip(None, existing.as_deref(), &assigned, &detected)
}

/// Initialize Tera templates with embedded nginx templates.
pub fn init_templates() -> Arc<Tera> {
    let mut tera = Tera::default();

    tera.add_raw_template("http.conf", include_str!("../templates/nginx/http.conf"))
        .expect("Failed to load http.conf template");

    tera.add_raw_template("https.conf", include_str!("../templates/nginx/https.conf"))
        .expect("Failed to load https.conf template");

    tera.add_raw_template("proxy.conf", include_str!("../templates/nginx/proxy.conf"))
        .expect("Failed to load proxy.conf template");

    Arc::new(tera)
}

/// Validate a filesystem path value used in nginx config (root, ssl_cert, ssl_key).
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains("..")
        && !path.contains('\0')
        && path.starts_with('/')
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
}

/// Allowed nginx directives that can appear in custom_nginx config.
const ALLOWED_NGINX_DIRECTIVES: &[&str] = &[
    "client_max_body_size",
    "gzip",
    "gzip_types",
    "gzip_min_length",
    "proxy_read_timeout",
    "proxy_connect_timeout",
    "proxy_send_timeout",
    "send_timeout",
    "keepalive_timeout",
    "server_tokens",
    "add_header",
    "expires",
    "tcp_nodelay",
    "tcp_nopush",
    "sendfile",
    "types_hash_max_size",
];

/// Dangerous nginx directive prefixes/keywords (case-insensitive).
const DANGEROUS_DIRECTIVES: &[&str] = &[
    "lua_",
    "perl_",
    "proxy_pass",
    "return",
    "rewrite",
    "access_log",
    "error_log",
    "load_module",
    "include",
    "alias",
];

/// Validate custom nginx directives. Rejects dangerous content and only allows whitelisted directives.
fn validate_custom_nginx(custom: &str) -> Result<(), String> {
    if custom.trim().is_empty() {
        return Ok(());
    }

    // Reject block-escape characters
    if custom.contains('{') || custom.contains('}') {
        return Err("Custom nginx config must not contain '{' or '}' (server block escape)".into());
    }

    for line in custom.lines() {
        let line_trimmed = line.trim();

        // Skip empty lines
        if line_trimmed.is_empty() {
            continue;
        }

        // Reject comment-only lines (comment injection)
        if line_trimmed.starts_with('#') {
            return Err("Custom nginx config must not contain comment lines starting with '#'".into());
        }

        // nginx separates statements with ';', so a single LINE can carry many
        // directives. Validating only the first token let an attacker smuggle a
        // dangerous directive past the whitelist, e.g.
        //   "sendfile on; access_log /var/www/victim/public/shell.php;"
        // (leading token 'sendfile' is allowed, the chained access_log was never
        // inspected → cross-tenant log-poisoning file-write/RCE). Split on ';'
        // and validate EVERY statement independently.
        for stmt in line_trimmed.split(';') {
            let trimmed = stmt.trim();

            if trimmed.is_empty() {
                continue;
            }

            // A statement must not start a comment either.
            if trimmed.starts_with('#') {
                return Err("Custom nginx config must not contain comment lines starting with '#'".into());
            }

            // Check for dangerous directives (case-insensitive)
            let lower = trimmed.to_lowercase();
            for dangerous in DANGEROUS_DIRECTIVES {
                if lower.starts_with(dangerous) {
                    return Err(format!(
                        "Custom nginx config contains forbidden directive: {dangerous}"
                    ));
                }
            }

            // Extract the directive name (first word of the statement)
            let directive = trimmed
                .split(|c: char| c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_lowercase();

            if directive.is_empty() {
                continue;
            }

            if !ALLOWED_NGINX_DIRECTIVES.contains(&directive.as_str()) {
                return Err(format!(
                    "Custom nginx directive '{}' is not in the allowed list. Allowed: {}",
                    directive,
                    ALLOWED_NGINX_DIRECTIVES.join(", ")
                ));
            }

            if let Some(reason) = ALREADY_SET_BY_THE_TEMPLATE
                .iter()
                .find(|(name, _)| *name == directive)
                .map(|(_, reason)| *reason)
            {
                return Err(format!(
                    "The site's own configuration already sets '{directive}' - nginx refuses a \
                     duplicate and the whole site would fail to load. {reason}"
                ));
            }
        }
    }

    Ok(())
}

/// Directives the site template already writes at SERVER level, which nginx
/// refuses to see twice in one context.
///
/// The custom block is injected into that same `server { … }`, so accepting one
/// of these produced a configuration nginx rejects - the save came back as a
/// bare `nginx -t` error naming a duplicate the operator could not see, on the
/// most obvious thing anyone types into this box. Worse, a unit test asserted
/// that `client_max_body_size 20m;` was valid input, so the validator was
/// pinned accepting exactly what breaks.
///
/// Derived rather than guessed, and the derivation matters: `add_header` and
/// `gzip_types` are also emitted there and do NOT collide (nginx appends both),
/// and `expires` is emitted only inside `location` blocks, which is a different
/// context. Measured against a real nginx - see the tests below, which assert
/// the whole set both ways.
const ALREADY_SET_BY_THE_TEMPLATE: &[(&str, &str)] = &[
    (
        "client_max_body_size",
        "Change the site's maximum upload size instead - that is the control that writes it.",
    ),
    ("gzip", "Compression is already enabled for every site."),
    (
        "gzip_min_length",
        "Compression is already enabled for every site, with a 256-byte floor.",
    ),
];

/// Defense-in-depth: strip characters that would break out of an
/// `add_header Name "<value>" always;` directive. The backend already rejects
/// these (routes/mod.rs::is_safe_header_value), but the agent renders the value
/// into a root-owned nginx config, so it sanitizes again at this render choke
/// point - any future/legacy caller that forwards an unvalidated CSP /
/// Permissions-Policy value cannot inject nginx directives.
fn sanitize_header_value(v: &str) -> String {
    v.chars()
        .filter(|c| !matches!(c, '"' | '\\' | '\n' | '\r' | '\0' | '{' | '}'))
        .collect()
}

/// Validate a PHP-FPM socket path.
fn is_safe_php_socket(socket: &str) -> bool {
    socket.starts_with("unix:/")
        && socket.ends_with(".sock")
        && !socket.contains("..")
        && !socket.contains('\0')
        && socket[5..] // skip "unix:" prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
}

/// Render the appropriate nginx config for a site.
///
/// The site's redirects and password-protection includes are emitted when
/// their files exist on disk (see [`crate::services::site_access`]), so every
/// re-render keeps them. The rendering itself is
/// [`render_site_config_including`], which is pure.
pub fn render_site_config(
    templates: &Tera,
    domain: &str,
    config: &SiteConfig,
) -> Result<String, tera::Error> {
    render_site_config_with(templates, domain, config, None)
}

/// [`render_site_config`], with the Apache-mode `proxy_read_timeout` taken
/// from `apache_timeout_s` when the description carries no `php_pool` (a
/// certificate re-render rebuilds the site from a partial description; the
/// caller reads the value from the site's managed Apache vhost so the two
/// hops keep giving up at the same moment). Ignored in nginx mode and when a
/// pool is present, so those render exactly as [`render_site_config`].
pub fn render_site_config_with(
    templates: &Tera,
    domain: &str,
    config: &SiteConfig,
    apache_timeout_s: Option<u32>,
) -> Result<String, tera::Error> {
    let includes = crate::services::site_access::SiteIncludes::on_disk(domain);
    let resolved = with_aliases_from_disk(domain, config);
    render_site_config_including(
        templates,
        domain,
        resolved.as_ref().unwrap_or(config),
        apache_timeout_s,
        includes,
    )
}

/// `aliases: None` means "keep the names the vhost on disk serves"
/// (05-import-hestia W3-V): this is where they are read, from the file the
/// render will replace (the parked body of a disabled site). `None` back when
/// the description already carries its aliases or the vhost has none.
pub fn with_aliases_from_disk(domain: &str, config: &SiteConfig) -> Option<SiteConfig> {
    if config.aliases.is_some() {
        return None;
    }
    let existing = std::fs::read_to_string(vhost_target(domain).path()).ok()?;
    let aliases = crate::services::apache::aliases_in_nginx_config(&existing, domain);
    if aliases.is_empty() {
        return None;
    }
    let mut c = config.clone();
    c.aliases = Some(aliases);
    Some(c)
}

/// [`render_site_config_with`] with the per-site includes given rather than
/// looked up: no filesystem access. Both includes go right above the serving
/// block's `access_log` line (the 443 block with SSL), outside every runtime
/// branch; with neither, the output is byte-identical to the templates
/// without them.
pub fn render_site_config_including(
    templates: &Tera,
    domain: &str,
    config: &SiteConfig,
    apache_timeout_s: Option<u32>,
    includes: crate::services::site_access::SiteIncludes,
) -> Result<String, tera::Error> {
    // Validate fields that get inserted into nginx config
    if let Some(ref root) = config.root {
        if !is_safe_path(root) {
            return Err(tera::Error::msg("Invalid root path"));
        }
    }
    if let Some(ref socket) = config.php_socket {
        if !is_safe_php_socket(socket) {
            return Err(tera::Error::msg("Invalid PHP socket path"));
        }
    }
    if let Some(ref cert) = config.ssl_cert {
        if !is_safe_path(cert) {
            return Err(tera::Error::msg("Invalid SSL certificate path"));
        }
    }
    if let Some(ref key) = config.ssl_key {
        if !is_safe_path(key) {
            return Err(tera::Error::msg("Invalid SSL key path"));
        }
    }
    if let Some(ref b) = config.bind_ip {
        validate_bind_ip(b).map_err(tera::Error::msg)?;
    }

    let mut ctx = Context::new();
    ctx.insert("domain", domain);
    ctx.insert("root", config.root.as_deref().unwrap_or("/var/www"));
    let bind_ip = bind_ip_for(domain, config);
    ctx.insert("bind_ip", &bind_ip);
    ctx.insert("runtime", &config.runtime);
    ctx.insert("inc_redirects", &includes.redirects);
    ctx.insert("inc_auth", &includes.auth);

    // Resource limits
    let rate_limit = config.rate_limit.unwrap_or(0);
    ctx.insert("rate_limit", &rate_limit);
    let max_upload_mb = config.max_upload_mb.unwrap_or(64);
    ctx.insert("max_upload_mb", &max_upload_mb);

    // Custom nginx directives - validate before inserting
    if let Some(ref custom) = config.custom_nginx {
        validate_custom_nginx(custom).map_err(tera::Error::msg)?;
    }
    ctx.insert("custom_nginx", &config.custom_nginx.as_deref().unwrap_or(""));

    // Apache behind nginx (PHP sites only; anything else is nginx). Always in
    // the context: the templates test it in a condition.
    let apache_mode = crate::services::apache::uses_apache(
        &config.runtime,
        config.web_server.as_deref(),
    );
    ctx.insert("apache_mode", &apache_mode);
    ctx.insert("apache_upstream", crate::services::apache::UPSTREAM);
    let apache_read_timeout = match (config.php_pool.as_ref(), apache_timeout_s) {
        (None, Some(t)) if apache_mode && t > 0 => t.min(86_400),
        (pool, _) => crate::services::apache::request_timeout_s(pool),
    };
    ctx.insert("apache_read_timeout", &apache_read_timeout);

    // FastCGI cache (PHP sites only). Not used in Apache mode: nginx does not
    // talk FastCGI there. The setting itself is kept by the panel.
    let fastcgi_cache =
        config.fastcgi_cache.unwrap_or(false) && config.runtime == "php" && !apache_mode;
    ctx.insert("fastcgi_cache", &fastcgi_cache);

    // Redis object cache (PHP sites only)
    let redis_cache = config.redis_cache.unwrap_or(false) && config.runtime == "php";
    ctx.insert("redis_cache", &redis_cache);
    ctx.insert("redis_db", &config.redis_db.unwrap_or(0));

    // WAF (ModSecurity)
    let waf_enabled = config.waf_enabled.unwrap_or(false);
    ctx.insert("waf_enabled", &waf_enabled);
    ctx.insert("waf_mode", &config.waf_mode.as_deref().unwrap_or("detection"));

    // CSP and security headers
    // Rendered verbatim into `add_header ... "<value>" always;` - sanitize so a
    // stray `"`/`\`/brace cannot break out of the quoted argument and inject
    // directives (backend also validates via is_safe_header_value).
    let csp_safe = sanitize_header_value(config.csp_policy.as_deref().unwrap_or(""));
    let perms_safe = sanitize_header_value(
        config.permissions_policy.as_deref().unwrap_or("camera=(), microphone=(), geolocation=()"),
    );
    ctx.insert("csp_policy", &csp_safe);
    ctx.insert("permissions_policy", &perms_safe);

    // Bot protection
    ctx.insert("bot_protection", &config.bot_protection.as_deref().unwrap_or("off"));

    let ssl = config.ssl.unwrap_or(false);
    ctx.insert("ssl", &ssl);

    // 05-import-hestia (W3-V / W3-F). Every fragment is "" when its setting is
    // absent, so an existing site renders byte for byte as before.
    use crate::services::vhost_extras as vx;
    let aliases = vx::validate_aliases(domain, config.aliases.as_deref().unwrap_or(&[]))
        .map_err(tera::Error::msg)?;
    let alias_names: String = aliases.iter().map(|a| format!(" {a}")).collect();
    ctx.insert("server_alias_names", &alias_names);
    let target = vx::canonical_target(domain, config.canonical_host.as_deref(), &aliases)
        .map_err(tera::Error::msg)?;
    let force_ssl = config.force_ssl.unwrap_or(true);
    ctx.insert("force_ssl", &force_ssl);
    ctx.insert("hsts", &config.hsts.unwrap_or(true));
    let canonical_block = match target.as_deref() {
        None => String::new(),
        Some(t) if ssl && force_ssl => vx::canonical_block_https(t),
        Some(t) => vx::canonical_block_any_scheme(t),
    };
    ctx.insert("canonical_block", &canonical_block);
    ctx.insert("redirect_host", target.as_deref().unwrap_or("$host"));
    let (plain, acme) = if ssl && !force_ssl {
        (vx::plain_listeners(&bind_ip), vx::acme_block())
    } else {
        (String::new(), "")
    };
    ctx.insert("plain_listeners", &plain);
    ctx.insert("acme_block", acme);
    let no_exec = vx::validate_no_exec_dirs(config.php_no_exec_dirs.as_deref().unwrap_or(&[]))
        .map_err(tera::Error::msg)?;
    let no_exec_block = if config.runtime == "php" { vx::no_exec_block(&no_exec) } else { String::new() };
    ctx.insert("no_exec_block", &no_exec_block);

    if ssl {
        ctx.insert(
            "ssl_cert",
            config
                .ssl_cert
                .as_deref()
                .unwrap_or(&format!("/etc/dockpanel/ssl/{domain}/fullchain.pem")),
        );
        ctx.insert(
            "ssl_key",
            config
                .ssl_key
                .as_deref()
                .unwrap_or(&format!("/etc/dockpanel/ssl/{domain}/privkey.pem")),
        );
    }

    match config.runtime.as_str() {
        "proxy" | "node" | "python" => {
            ctx.insert("proxy_port", &config.proxy_port.unwrap_or(3000));
            // Node/Python use same proxy template as "proxy" runtime
            ctx.insert("runtime", &"proxy");
            if ssl {
                templates.render("https.conf", &ctx)
            } else {
                templates.render("proxy.conf", &ctx)
            }
        }
        "php" => {
            ctx.insert(
                "php_socket",
                config
                    .php_socket
                    .as_deref()
                    .unwrap_or("unix:/run/php/php-fpm.sock"),
            );
            ctx.insert("php_preset", &config.php_preset.as_deref().unwrap_or("generic"));
            // Per-site PHP settings: align nginx's FastCGI read timeout with
            // the pool's request_terminate_timeout. 0 = no line (legacy, or
            // FPM-side timeout disabled), so an absent php_pool renders
            // byte-identically to before.
            let read_timeout = config
                .php_pool
                .as_ref()
                .map(|p| p.request_terminate_timeout_s)
                .unwrap_or(0);
            ctx.insert("fastcgi_read_timeout", &read_timeout);
            if ssl {
                templates.render("https.conf", &ctx)
            } else {
                templates.render("http.conf", &ctx)
            }
        }
        _ => {
            // Static site
            if ssl {
                templates.render("https.conf", &ctx)
            } else {
                templates.render("http.conf", &ctx)
            }
        }
    }
}

/// Write a per-site PHP-FPM pool config with resource limits.
///
/// Debian-shaped layout only (`/etc/php/{version}/fpm/pool.d`) - the RHEL
/// family has no per-version pool directory to write into (one `php-fpm`
/// package serves whichever stream is active), so this never runs there in
/// practice: `nginx.rs::put_site()` only calls it for a socket path that
/// resolved to the Debian shape in the first place. If that ever changes,
/// this early return keeps a RHEL call a no-op (degrading to the shared
/// pool) rather than an error.
pub fn write_php_pool_config(
    domain: &str,
    php_version: &str,
    memory_mb: u32,
    max_workers: u32,
    pool_owner: Option<(&str, &str)>,
) -> Result<(), String> {
    let pool_dir = format!("/etc/php/{php_version}/fpm/pool.d");
    if !std::path::Path::new(&pool_dir).exists() {
        return Ok(()); // Debian pool.d tree absent (RHEL, or PHP not installed) - skip silently
    }

    // Sanitize domain for use as pool name (replace dots with underscores)
    let pool_name = domain.replace('.', "_");

    // SFTP-enabled sites own their content under their own uid/gid (see
    // `services::sftp_accounts`), so the pool that reads/writes it must run as
    // that same identity - `www-data` would lose write access the moment the
    // site's directory is re-chowned. `None` (every non-SFTP site, the common
    // case) keeps the original shared identity.
    let (user, group) = pool_owner.unwrap_or(("www-data", "www-data"));

    let config = legacy_php_pool_config(domain, &pool_name, php_version, memory_mb, max_workers, user, group);

    let pool_path = format!("{pool_dir}/{pool_name}.conf");
    std::fs::write(&pool_path, &config)
        .map_err(|e| format!("Failed to write FPM pool config: {e}"))?;

    tracing::info!("PHP-FPM pool config written: {pool_path} (user={user}, workers={max_workers}, memory={memory_mb}M)");
    Ok(())
}

/// The legacy pool body (no `php_pool` in the request). Pure, and pinned by a
/// test, so the per-site PHP settings work cannot change it by accident.
fn legacy_php_pool_config(
    domain: &str,
    pool_name: &str,
    php_version: &str,
    memory_mb: u32,
    max_workers: u32,
    user: &str,
    group: &str,
) -> String {
    // Every pool carries open_basedir (same value as `php_pool`).
    let open_basedir = format!(
        "php_admin_value[open_basedir] = {}\n",
        crate::services::php_pool::open_basedir_value(domain)
    );
    format!(
        r#"[{pool_name}]
user = {user}
group = {group}
listen = /run/php/php{php_version}-fpm-{pool_name}.sock
listen.owner = {user}
listen.group = {group}
listen.mode = 0660

pm = dynamic
pm.max_children = {max_workers}
pm.start_servers = {start}
pm.min_spare_servers = 1
pm.max_spare_servers = {spare}
pm.max_requests = 500

php_admin_value[memory_limit] = {memory_mb}M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[max_execution_time] = 300
{open_basedir}"#,
        start = std::cmp::min(2, max_workers),
        spare = std::cmp::min(3, max_workers),
    )
}

/// Reload PHP-FPM for a given version.
pub async fn reload_php_fpm(php_version: &str) -> Result<(), String> {
    let service = format!("php{php_version}-fpm");
    let output = safe_command("systemctl")
        .args(["reload", &service])
        .output()
        .await
        .map_err(|e| format!("Failed to reload {service}: {e}"))?;

    if output.status.success() {
        tracing::info!("{service} reloaded");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Not fatal - pool config will apply on next restart
        tracing::warn!("{service} reload failed (will apply on restart): {stderr}");
        Ok(())
    }
}

/// Run `nginx -t` to test configuration.
pub async fn test_config() -> Result<CmdOutput, std::io::Error> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        safe_command("nginx").arg("-t").output(),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "nginx -t timed out"))??;

    Ok(CmdOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Reload nginx gracefully.
pub async fn reload() -> Result<(), String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        safe_command("nginx").args(["-s", "reload"]).output(),
    )
    .await
    .map_err(|_| "Nginx reload timed out".to_string())?
    .map_err(|e| format!("Failed to execute nginx: {e}"))?;

    if output.status.success() {
        tracing::info!("Nginx reloaded successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Nginx reload failed: {stderr}");
        Err(format!("Nginx reload failed: {stderr}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── where a rendered vhost lands - s317 / v2.74.0 ───────────────────
    //
    // These exercise the DECISION, not the two names it chooses between. It was
    // extracted precisely so it could be reached from here: while it lived
    // inline in five writers there was nothing a test could hold.

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dockpanel-vhost-target-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn a_site_with_nothing_parked_is_written_into_service() {
        let dir = scratch("live");
        let in_service = dir.join("a.example.conf");
        let parked = dir.join("a.example.conf.disabled");
        std::fs::write(&in_service, "server {}").unwrap();

        let target = vhost_target_between(in_service.to_str().unwrap(), parked.to_str().unwrap());

        assert_eq!(target.path(), in_service.to_str().unwrap());
        assert!(target.is_live(), "a live site still owes nginx a test and a reload");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_parked_body_takes_the_write_and_the_site_stays_offline() {
        let dir = scratch("parked");
        let in_service = dir.join("b.example.conf");
        let parked = dir.join("b.example.conf.disabled");
        std::fs::write(&in_service, "return 503;").unwrap();
        std::fs::write(&parked, "server { listen 80; }").unwrap();

        let target = vhost_target_between(in_service.to_str().unwrap(), parked.to_str().unwrap());

        // The invariant the whole fix exists for: the render does not replace
        // whatever is answering for this name.
        assert_ne!(target.path(), in_service.to_str().unwrap());
        assert_eq!(target.path(), parked.to_str().unwrap());
        assert!(
            !target.is_live(),
            "nothing went into service, so no reload is owed and none may be claimed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_stub_is_left_alone_even_when_the_parked_body_is_empty() {
        // An empty file is still a parked body. Keying on content rather than
        // existence would have made a truncated backup look like a live site.
        let dir = scratch("empty");
        let in_service = dir.join("d.example.conf");
        let parked = dir.join("d.example.conf.disabled");
        std::fs::write(&in_service, "return 503;").unwrap();
        std::fs::write(&parked, "").unwrap();

        let target = vhost_target_between(in_service.to_str().unwrap(), parked.to_str().unwrap());

        assert!(!target.is_live());
        assert_eq!(target.path(), parked.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_maintenance_response_answers_where_the_site_answered() {
        // The exact shape the templates emit when the panel knows its address.
        // A stub naming `listen 80` is attached to a different socket and is
        // never consulted, which is how disabling a site did nothing at all.
        let vhost = "server {\n    listen 203.0.113.10:80;\n    listen [::]:80;\n    server_name a.example;\n    root /var/www/a.example/public;\n}\n";
        let l = listener_lines(vhost);
        assert!(l.contains("listen 203.0.113.10:80;"), "the site's own address must come across: {l}");
        assert!(l.contains("listen [::]:80;"));
        assert!(!l.contains("server_name"), "only listeners and certificates travel");
        assert!(!l.contains("root "));
    }

    #[test]
    fn a_tls_site_can_still_say_it_is_disabled_over_https() {
        // `listen …443 ssl` without a certificate is a config nginx refuses, so
        // the certificate lines have to travel with the listener.
        let vhost = "server {\n    listen 203.0.113.10:80;\n    server_name a.example;\n}\nserver {\n    listen 203.0.113.10:443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate /etc/ssl/a/fullchain.pem;\n    ssl_certificate_key /etc/ssl/a/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n}\n";
        let l = listener_lines(vhost);
        assert!(l.contains("listen 203.0.113.10:443 ssl;"));
        assert!(l.contains("ssl_certificate /etc/ssl/a/fullchain.pem;"));
        assert!(l.contains("ssl_certificate_key /etc/ssl/a/privkey.pem;"));
        // Everything else about TLS has a working default; carrying it would be
        // copying the site rather than its doorway.
        assert!(!l.contains("ssl_protocols"));
    }

    #[test]
    fn a_repeated_listener_is_emitted_once() {
        // Both server blocks of the https template carry `listen [::]:80`, and
        // nginx refuses a server block that names the same address twice.
        let vhost = "server {\n    listen [::]:80;\n}\nserver {\n    listen [::]:80;\n}\n";
        assert_eq!(listener_lines(vhost).matches("listen [::]:80;").count(), 1);
    }

    #[test]
    fn both_paths_come_from_one_function_so_they_cannot_drift() {
        // The writer that parks a body and every writer that has to notice it
        // read the same two names from here.
        let (in_service, parked) = vhost_paths_for("c.example", true);
        assert!(in_service.ends_with("/sites-enabled/c.example.conf"));
        assert!(parked.ends_with("/sites-available/c.example.conf.disabled"));
        assert_ne!(in_service, parked);
    }

    #[test]
    fn the_rhel_family_has_no_second_directory_so_both_paths_share_conf_d() {
        // RHEL's nginx package ships neither sites-available nor sites-enabled;
        // this is the branch that was missing entirely, and every site write on
        // that family failed ENOENT until it existed.
        let (in_service, parked) = vhost_paths_for("c.example", false);
        assert_eq!(in_service, "/etc/nginx/conf.d/c.example.conf");
        assert_eq!(parked, "/etc/nginx/conf.d/c.example.conf.disabled");
        assert_ne!(in_service, parked);
        // nginx's own `include conf.d/*.conf` cannot match the parked name.
        assert!(!parked.ends_with(".conf"), "the parked name must fall outside nginx's own glob");
    }

    // ── static-vhost deny retrofit - s311 / v2.68.2 ─────────────────────
    //
    // The defect these guard against is not "the denies are missing from the
    // template" (v2.68.0 fixed that and a pin suite covers it). It is that a
    // template fix does not reach a vhost already written, and the site that
    // most needs it - one switched from php to static - is exactly a vhost
    // already written.

    const STATIC_VHOST: &str = "server {\n    listen 80;\n    server_name a.example;\n    root /var/www/a.example/public;\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n";

    #[test]
    fn retrofit_patches_a_static_vhost_once_and_only_once() {
        let patched = patch_static_vhost(STATIC_VHOST).expect("a static vhost is a candidate");
        assert!(patched.contains("location ~ /\\.(?!well-known)"));
        assert!(patched.contains("location ~ \\.php$"));
        assert!(patched.contains("location ~ ^/sites/.*/private/"));
        // The site must keep working: the original serving block survives.
        assert!(patched.contains("try_files $uri $uri/ =404;"));
        assert!(patched.contains("root /var/www/a.example/public;"));
        // Idempotent - a second pass is not a candidate at all.
        assert!(patch_static_vhost(&patched).is_none());
        // Exactly one insertion, not one per line.
        assert_eq!(patched.matches("deny all;").count(), 3);
    }

    #[test]
    fn retrofit_adds_only_the_deny_an_earlier_version_missed() {
        // The reach question asked of this function's OWN prior output. A box
        // patched by v2.68.2 carries two denies; v2.68.3 adds a third. It must
        // gain exactly that one and duplicate neither of the others - the shape
        // that made a template fix, then a panel-only fix, each reach the wrong
        // population.
        let v2682 = patch_static_vhost(STATIC_VHOST).expect("candidate");
        let stale = v2682.replace(
            "\n    # drupal's private file store: no dot segment and no .php suffix, so\n    # neither deny above covers it.\n    location ~ ^/sites/.*/private/ {\n        deny all;\n    }\n",
            "",
        );
        assert!(!stale.contains("sites/.*/private"), "fixture must model a v2.68.2 body");
        assert_eq!(stale.matches("deny all;").count(), 2);

        let upgraded = patch_static_vhost(&stale).expect("a two-deny body is still a candidate");
        assert_eq!(upgraded.matches("deny all;").count(), 3);
        assert_eq!(upgraded.matches("location ~ /\\.(?!well-known)").count(), 1);
        assert_eq!(upgraded.matches("location ~ \\.php$").count(), 1);
        assert_eq!(upgraded.matches("location ~ ^/sites/.*/private/").count(), 1);
        assert!(patch_static_vhost(&upgraded).is_none());
    }

    #[test]
    fn retrofit_never_returns_a_body_it_added_nothing_to() {
        // The caller logs "Retrofitted … onto <file>" on any successful WRITE, not
        // on content. So a Some(_) carrying zero denies is a false green on an
        // unprotected vhost, repeating every restart. It happened: candidacy asked
        // `contains(index…)` (substring) and insertion asked `trim() ==` (whole
        // line), and a trailing comment satisfied one and never the other.
        let commented = STATIC_VHOST.replace(
            "    index index.html index.htm;\n",
            "    index index.html index.htm; # set by hand\n",
        );
        assert!(commented.contains("index index.html index.htm;"), "substring still present");
        assert!(
            !commented.lines().any(|l| l.trim() == "index index.html index.htm;"),
            "…but no whole line matches - the two predicates disagree on this input",
        );

        // Whatever the verdict, it may never be "changed, with nothing added".
        for body in [&commented, &STATIC_VHOST.to_string()] {
            if let Some(out) = patch_static_vhost(body) {
                assert!(
                    out.contains("deny all;"),
                    "returned a patched body with no deny in it",
                );
            }
        }
    }

    #[test]
    fn retrofit_skips_a_php_vhost() {
        // A php vhost carries the denies in its preset branch already, and its
        // `.php` location is a HANDLER - denying it would stop the site dead.
        let php = "server {\n    index index.html index.htm;\n    location ~ \\.php$ {\n        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n    }\n}\n";
        assert!(patch_static_vhost(php).is_none());
    }

    #[test]
    fn retrofit_skips_a_vhost_that_is_not_static() {
        // A proxy vhost has no static index line; nothing to key on, nothing to do.
        let proxy = "server {\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n";
        assert!(patch_static_vhost(proxy).is_none());
    }

    // ── custom_nginx per-statement validation - s241 C2 ─────────────────

    #[test]
    fn custom_nginx_blocks_semicolon_chained_directive() {
        // The whole-line-token bypass: a whitelisted leading directive must not
        // let a dangerous directive ride along after ';'.
        assert!(validate_custom_nginx("sendfile on; access_log /var/www/victim/public/shell.php;").is_err());
        assert!(validate_custom_nginx("gzip on; return 301 https://evil$request_uri;").is_err());
        assert!(validate_custom_nginx("add_header X y; proxy_pass http://169.254.169.254/;").is_err());
        assert!(validate_custom_nginx("client_max_body_size 10m; error_log /tmp/x;").is_err());
    }

    #[test]
    fn custom_nginx_allows_benign_statements() {
        assert!(validate_custom_nginx("proxy_read_timeout 120s;").is_ok());
        assert!(validate_custom_nginx("gzip_types text/css application/json;").is_ok());
        assert!(validate_custom_nginx("add_header X-Frame-Options SAMEORIGIN;").is_ok());
        assert!(validate_custom_nginx("").is_ok());
        // Block-escape and comment injection still rejected.
        assert!(validate_custom_nginx("location / { root /etc; }").is_err());
        assert!(validate_custom_nginx("# sneaky").is_err());
    }

    /// This test used to assert the OPPOSITE - that `client_max_body_size 20m;`
    /// is valid input - which pinned the validator accepting the single most
    /// obvious thing an operator types here, and nginx then refused the whole
    /// site with `"client_max_body_size" directive is duplicate`. The site
    /// template writes it at server level and the custom block lands in that
    /// same server block.
    #[test]
    fn custom_nginx_refuses_what_the_template_already_sets() {
        for stmt in [
            "client_max_body_size 20m;",
            "gzip on;",
            "gzip_min_length 512;",
            // Case and leading whitespace must not smuggle one past.
            "  Client_Max_Body_Size 50m;",
            // Nor may it ride behind a statement that is fine on its own.
            "proxy_read_timeout 60s; gzip off;",
        ] {
            let e = validate_custom_nginx(stmt).expect_err(stmt);
            assert!(e.contains("already sets"), "{stmt} -> {e}");
        }
    }

    /// The other half, and the reason the list is three names rather than the
    /// six the template emits: these ARE written by the template too, and nginx
    /// accepts them a second time - `add_header` and `gzip_types` append, and
    /// `expires` appears only inside `location` blocks, a different context.
    /// Refusing them would take away working configuration.
    #[test]
    fn custom_nginx_still_allows_what_the_template_emits_without_colliding() {
        assert!(validate_custom_nginx("add_header X-Extra 1;").is_ok());
        assert!(validate_custom_nginx("gzip_types application/wasm;").is_ok());
        assert!(validate_custom_nginx("expires 1d;").is_ok());
    }

    // ── header-value sanitization - s241 C1 (agent defense-in-depth) ────

    #[test]
    fn header_sanitize_strips_breakout_chars() {
        assert_eq!(sanitize_header_value("default-src 'self'; script-src 'self'"), "default-src 'self'; script-src 'self'");
        // Quote / backslash / braces removed so they can't close the add_header arg.
        assert_eq!(sanitize_header_value("x\" always; location /p { }"), "x always; location /p  ");
        assert!(!sanitize_header_value("a\"b\\c{d}").contains('"'));
        assert!(!sanitize_header_value("a\"b\\c{d}").contains('\\'));
    }

    // ── multi-IP: which address a vhost listens on ─────────────────────

    const VHOST_ON_11: &str = "server {
    listen 192.168.250.11:80;
    listen [::]:80;
    server_name a.lab;
}
server {
    listen 192.168.250.11:443 ssl;
    listen [::]:443 ssl;
    ssl_certificate /x;
}
";
    const VHOST_WILDCARD: &str = "server {
    listen 80;
    listen [::]:80;
}
";

    fn v4(s: &str) -> std::net::Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn bind_ip_shape_validation() {
        assert_eq!(validate_bind_ip("primary"), Ok(None));
        assert_eq!(validate_bind_ip("192.168.250.11"), Ok(Some(v4("192.168.250.11"))));
        for bad in ["", "Primary", "1.2.3", "1.2.3.4:80", "::1", "1.2.3.4; include /etc/passwd", "01.2.3.4"] {
            assert!(validate_bind_ip(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn existing_vhost_ip_is_parsed_from_listen_lines() {
        assert_eq!(vhost_bind_ip(VHOST_ON_11), Some(v4("192.168.250.11")));
        assert_eq!(vhost_bind_ip(VHOST_WILDCARD), None);
        assert_eq!(vhost_bind_ip("server { listen [::]:443 ssl; }"), None);
    }

    #[test]
    fn explicit_ip_wins() {
        let ip = resolve_bind_ip(Some("192.168.250.12"), Some(VHOST_ON_11), &[], "192.168.250.10");
        assert_eq!(ip, "192.168.250.12");
    }

    #[test]
    fn primary_means_detected() {
        let ip = resolve_bind_ip(Some("primary"), Some(VHOST_ON_11), &[v4("192.168.250.11")], "192.168.250.10");
        assert_eq!(ip, "192.168.250.10");
    }

    #[test]
    fn absent_keeps_the_existing_vhost_ip_while_it_is_assigned() {
        let assigned = [v4("192.168.250.10"), v4("192.168.250.11")];
        let ip = resolve_bind_ip(None, Some(VHOST_ON_11), &assigned, "192.168.250.10");
        assert_eq!(ip, "192.168.250.11");
    }

    #[test]
    fn absent_falls_back_to_detected() {
        // IP gone from the host.
        let ip = resolve_bind_ip(None, Some(VHOST_ON_11), &[v4("192.168.250.10")], "192.168.250.10");
        assert_eq!(ip, "192.168.250.10");
        // No vhost yet.
        assert_eq!(resolve_bind_ip(None, None, &[], "192.168.250.10"), "192.168.250.10");
        // Wildcard vhost.
        assert_eq!(resolve_bind_ip(None, Some(VHOST_WILDCARD), &[], "192.168.250.10"), "192.168.250.10");
        // Nothing detected → empty → template's wildcard listen.
        assert_eq!(resolve_bind_ip(None, None, &[], ""), "");
    }
}

#[cfg(test)]
mod php_settings_tests {
    use super::*;

    #[test]
    fn legacy_pool_has_exactly_one_open_basedir_for_every_user() {
        for user in ["www-data", "sftp_x"] {
            let out = legacy_php_pool_config("example.com", "example_com", "8.3", 256, 5, user, user);
            assert_eq!(out.matches("open_basedir").count(), 1);
            assert!(out.ends_with(
                "php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/\n"
            ));
        }
    }

    /// The legacy pool body, pinned byte for byte: a request without
    /// `php_pool` must keep producing exactly this.
    #[test]
    fn legacy_pool_body_is_unchanged() {
        let out = legacy_php_pool_config("example.com", "example_com", "8.3", 256, 5, "www-data", "www-data");
        assert_eq!(
            out,
            "[example_com]
user = www-data
group = www-data
listen = /run/php/php8.3-fpm-example_com.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500

php_admin_value[memory_limit] = 256M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[max_execution_time] = 300
php_admin_value[open_basedir] = /var/www/example.com/:/tmp/:/usr/share/php/
"
        );
    }

    fn php_site(ssl: bool, pool: Option<u32>) -> SiteConfig {
        let mut v = serde_json::json!({
            "runtime": "php",
            "root": "/var/www",
            "php_socket": "unix:/run/php/php8.3-fpm-example_com.sock",
            "ssl": ssl,
            "ssl_cert": "/etc/dockpanel/ssl/example.com/fullchain.pem",
            "ssl_key": "/etc/dockpanel/ssl/example.com/privkey.pem",
            "bind_ip": "192.0.2.10",
        });
        if let Some(t) = pool {
            v["php_pool"] = serde_json::json!({
                "values": {}, "isolation": true, "disable_shell": true, "pm": "ondemand",
                "max_children": 8, "max_requests": 4000, "idle_timeout_s": 10,
                "request_terminate_timeout_s": t, "extra": []
            });
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn read_timeout_follows_the_pool_in_both_templates() {
        let t = init_templates();
        for ssl in [false, true] {
            let out = render_site_config(&t, "example.com", &php_site(ssl, Some(90))).unwrap();
            assert!(
                out.contains("        fastcgi_buffer_size 32k;\n        fastcgi_read_timeout 90s;\n"),
                "ssl={ssl}"
            );
            assert_eq!(out.matches("fastcgi_read_timeout").count(), 1);
        }
    }

    #[test]
    fn no_pool_or_zero_timeout_renders_no_read_timeout_line() {
        let t = init_templates();
        for ssl in [false, true] {
            for pool in [None, Some(0)] {
                let out = render_site_config(&t, "example.com", &php_site(ssl, pool)).unwrap();
                assert!(!out.contains("fastcgi_read_timeout"), "ssl={ssl} pool={pool:?}");
                // The line after the buffer size is what it always was.
                let after = out.split("fastcgi_buffer_size 32k;").nth(1).unwrap();
                assert!(after.starts_with("\n        }") || after.starts_with("\n\n"), "{after:.40}");
            }
        }
    }

    /// The templates as they were before `fastcgi_read_timeout` was added.
    fn templates_without_read_timeout() -> Tera {
        let strip = |t: &str| {
            let t = t.replace('\r', "");
            let line = "{% if fastcgi_read_timeout > 0 %}        fastcgi_read_timeout {{ fastcgi_read_timeout }}s;\n{% endif %}";
            assert!(t.contains(line));
            t.replace(line, "")
        };
        let mut tera = Tera::default();
        tera.add_raw_template("http.conf", &strip(include_str!("../templates/nginx/http.conf"))).unwrap();
        tera.add_raw_template("https.conf", &strip(include_str!("../templates/nginx/https.conf"))).unwrap();
        tera.add_raw_template("proxy.conf", include_str!("../templates/nginx/proxy.conf")).unwrap();
        tera
    }

    #[test]
    fn absent_pool_renders_byte_identically_to_the_old_templates() {
        let new = init_templates();
        let old = templates_without_read_timeout();
        for ssl in [false, true] {
            let a = render_site_config(&new, "example.com", &php_site(ssl, None)).unwrap();
            let b = render_site_config(&old, "example.com", &php_site(ssl, None)).unwrap();
            assert_eq!(a, b, "ssl={ssl}");
        }
    }

    // ── web_server = "apache" (feature 4) ───────────────────────────────

    /// The templates as they were before the Apache branch was added.
    fn templates_without_apache_branch() -> Tera {
        let strip = |t: &str| {
            let t = t.replace('\r', "");
            let start = t
                .find("{% elif runtime == \"php\" and apache_mode %}")
                .expect("apache branch");
            let end = start + t[start..].find("{% elif runtime == \"php\" %}").expect("php branch");
            format!("{}{}", &t[..start], &t[end..])
        };
        let mut tera = Tera::default();
        tera.add_raw_template("http.conf", &strip(include_str!("../templates/nginx/http.conf"))).unwrap();
        tera.add_raw_template("https.conf", &strip(include_str!("../templates/nginx/https.conf"))).unwrap();
        tera.add_raw_template("proxy.conf", include_str!("../templates/nginx/proxy.conf")).unwrap();
        tera
    }

    fn with(mut c: SiteConfig, f: impl FnOnce(&mut SiteConfig)) -> SiteConfig {
        f(&mut c);
        c
    }

    #[test]
    fn absent_or_nginx_web_server_renders_byte_identically_to_the_pre_apache_templates() {
        let new = init_templates();
        let old = templates_without_apache_branch();
        let presets = [None, Some("wordpress"), Some("laravel"), Some("drupal"), Some("magento"), Some("generic")];
        for ssl in [false, true] {
            for pool in [None, Some(90)] {
                for preset in presets {
                    for cache in [false, true] {
                        for ws in [None, Some("nginx")] {
                            let c = with(php_site(ssl, pool), |c| {
                                c.php_preset = preset.map(str::to_string);
                                c.fastcgi_cache = Some(cache);
                                c.web_server = ws.map(str::to_string);
                            });
                            let a = render_site_config(&new, "example.com", &c).unwrap();
                            let b = render_site_config(&old, "example.com", &c).unwrap();
                            assert_eq!(a, b, "ssl={ssl} pool={pool:?} preset={preset:?} cache={cache} ws={ws:?}");
                        }
                    }
                }
            }
            // Other runtimes ignore web_server, "apache" included.
            for rt in ["static", "proxy", "node"] {
                for ws in [None, Some("nginx"), Some("apache")] {
                    let c = with(php_site(ssl, None), |c| {
                        c.runtime = rt.to_string();
                        c.proxy_port = Some(3000);
                        c.web_server = ws.map(str::to_string);
                    });
                    let plain = with(c.clone(), |c| c.web_server = None);
                    let a = render_site_config(&new, "example.com", &c).unwrap();
                    let b = render_site_config(&old, "example.com", &plain).unwrap();
                    assert_eq!(a, b, "ssl={ssl} rt={rt} ws={ws:?}");
                }
            }
        }
    }

    fn apache_site(ssl: bool, pool: Option<u32>) -> SiteConfig {
        with(php_site(ssl, pool), |c| c.web_server = Some("apache".to_string()))
    }

    #[test]
    fn apache_mode_hands_php_to_apache_in_both_templates() {
        let t = init_templates();
        for ssl in [false, true] {
            let out = render_site_config(&t, "example.com", &apache_site(ssl, None)).unwrap();
            for needle in [
                "    root /var/www/example.com/public;\n",
                "    location ~ /\\.(?!well-known) {\n        deny all;\n    }\n",
                "    location ~* \\.(?:jpe?g|png|gif|webp|avif|svg|ico|css|js|mjs|map|woff2?|ttf|otf|eot|txt|xml|pdf|mp4|webm|mp3|ogg|zip|gz)$ {\n        try_files $uri @apache;\n        expires 30d;\n    }\n",
                "    location / {\n        try_files /nonexistent @apache;\n    }\n",
                "    location @apache {\n        proxy_pass http://127.0.0.1:8091;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_read_timeout 300s;\n    }\n",
                "access_log /var/log/nginx/example.com.access.log;",
                "error_log /var/log/nginx/example.com.error.log;",
                "client_max_body_size 64m;",
                ":80;\n",
            ] {
                assert!(out.contains(needle), "ssl={ssl} missing {needle:?}\n{out}");
            }
            // No PHP handled by nginx itself, no preset, and not the static
            // marker the static-deny retrofit and update.sh key on.
            for absent in ["fastcgi_pass", "index index.html index.htm;", "index index.php", "access_log off", "fastcgi_cache"] {
                assert!(!out.contains(absent), "ssl={ssl} has {absent:?}");
            }
            if ssl {
                assert!(out.contains(":443 ssl;\n"));
                assert!(out.contains("ssl_certificate /etc/dockpanel/ssl/example.com/fullchain.pem;"));
                assert!(out.contains("return 301 https://$host$request_uri;"));
            } else {
                assert!(out.contains("location /.well-known/acme-challenge/"));
            }
        }
    }

    #[test]
    fn apache_mode_ignores_presets_and_the_fastcgi_cache() {
        let t = init_templates();
        let base = render_site_config(&t, "example.com", &apache_site(true, None)).unwrap();
        for preset in ["wordpress", "magento", "drupal"] {
            let c = with(apache_site(true, None), |c| {
                c.php_preset = Some(preset.to_string());
                c.fastcgi_cache = Some(true);
            });
            assert_eq!(render_site_config(&t, "example.com", &c).unwrap(), base, "{preset}");
        }
    }

    #[test]
    fn apache_timeout_override_applies_only_to_an_apache_site_without_a_pool() {
        let t = init_templates();
        for ssl in [false, true] {
            // Certificate re-render: no pool, the Apache vhost says 90.
            let out = render_site_config_with(&t, "example.com", &apache_site(ssl, None), Some(90)).unwrap();
            assert!(out.contains("        proxy_read_timeout 90s;\n"), "ssl={ssl}");
            // A pool in the description wins over the override.
            let out = render_site_config_with(&t, "example.com", &apache_site(ssl, Some(45)), Some(90)).unwrap();
            assert!(out.contains("        proxy_read_timeout 45s;\n"), "ssl={ssl}");
            // nginx mode is byte-identical with or without an override.
            for pool in [None, Some(90)] {
                let c = php_site(ssl, pool);
                assert_eq!(
                    render_site_config_with(&t, "example.com", &c, Some(77)).unwrap(),
                    render_site_config(&t, "example.com", &c).unwrap(),
                    "ssl={ssl} pool={pool:?}"
                );
            }
        }
    }

    #[test]
    fn apache_mode_read_timeout_follows_the_pool() {
        let t = init_templates();
        for ssl in [false, true] {
            let out = render_site_config(&t, "example.com", &apache_site(ssl, Some(90))).unwrap();
            assert!(out.contains("        proxy_read_timeout 90s;\n"), "ssl={ssl}");
        }
    }

    // ── redirects / password-protection includes (D4) ───────────────────

    const INCLUDES_FRAGMENT: &str = "{% if inc_redirects %}    include /etc/nginx/redirects/{{ domain }}.conf;
{% endif %}{% if inc_auth %}    include /etc/nginx/auth/{{ domain }}.conf;
{% endif %}";

    /// The templates as they were before the includes were added.
    fn templates_without_includes() -> Tera {
        let strip = |t: &str| {
            let t = t.replace('\r', "");
            assert!(t.contains(INCLUDES_FRAGMENT));
            t.replace(INCLUDES_FRAGMENT, "")
        };
        let mut tera = Tera::default();
        tera.add_raw_template("http.conf", &strip(include_str!("../templates/nginx/http.conf"))).unwrap();
        tera.add_raw_template("https.conf", &strip(include_str!("../templates/nginx/https.conf"))).unwrap();
        tera.add_raw_template("proxy.conf", &strip(include_str!("../templates/nginx/proxy.conf"))).unwrap();
        tera
    }

    /// One config per template branch: php presets (nginx), apache mode,
    /// static, proxy, node, python.
    fn every_branch(ssl: bool) -> Vec<(String, SiteConfig)> {
        let mut out = Vec::new();
        for preset in ["generic", "wordpress", "laravel", "magento"] {
            out.push((format!("php/{preset}"), with(php_site(ssl, Some(60)), |c| c.php_preset = Some(preset.into()))));
        }
        out.push(("apache".into(), apache_site(ssl, None)));
        for rt in ["static", "proxy", "node", "python"] {
            out.push((rt.into(), with(php_site(ssl, None), |c| {
                c.runtime = rt.to_string();
                c.proxy_port = Some(3000);
            })));
        }
        out
    }

    use crate::services::site_access::SiteIncludes;
    const BOTH: SiteIncludes = SiteIncludes { redirects: true, auth: true };

    #[test]
    fn without_include_files_rendering_is_byte_identical_to_before() {
        let new = init_templates();
        let old = templates_without_includes();
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                let a = render_site_config_including(&new, "example.com", &c, None, SiteIncludes::default()).unwrap();
                let b = render_site_config_including(&old, "example.com", &c, None, BOTH).unwrap();
                assert_eq!(a, b, "ssl={ssl} {name}");
            }
        }
    }

    #[test]
    fn includes_land_in_the_serving_block_of_every_branch() {
        let t = init_templates();
        let block = "    include /etc/nginx/redirects/example.com.conf;
    include /etc/nginx/auth/example.com.conf;
    access_log /var/log/nginx/example.com.access.log;
";
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                let out = render_site_config_including(&t, "example.com", &c, None, BOTH).unwrap();
                assert_eq!(out.matches(block).count(), 1, "ssl={ssl} {name}
{out}");
                assert_eq!(out.matches("include /etc/nginx/auth/").count(), 1, "ssl={ssl} {name}");
                assert_eq!(out.matches("include /etc/nginx/redirects/").count(), 1, "ssl={ssl} {name}");
                // Inside the last server block, which is the 443 one with SSL;
                // the :80 redirect-only block never gets them.
                let last_server = out.rfind("
server {").unwrap();
                assert!(out.find("include /etc/nginx/").unwrap() > last_server, "ssl={ssl} {name}");
                if ssl {
                    assert!(out[last_server..].contains(":443 ssl;"), "ssl={ssl} {name}");
                    assert!(!out[..last_server].contains("include /etc/nginx/"), "ssl={ssl} {name}");
                }
                // Only one of the two.
                for one in [SiteIncludes { redirects: true, auth: false }, SiteIncludes { redirects: false, auth: true }] {
                    let out = render_site_config_including(&t, "example.com", &c, None, one).unwrap();
                    assert_eq!(out.contains("include /etc/nginx/redirects/example.com.conf;"), one.redirects);
                    assert_eq!(out.contains("include /etc/nginx/auth/example.com.conf;"), one.auth);
                }
            }
        }
    }

    #[test]
    fn inserting_into_a_live_vhost_gives_what_the_template_renders() {
        let t = init_templates();
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                let bare = render_site_config_including(&t, "example.com", &c, None, SiteIncludes::default()).unwrap();
                for want in [BOTH, SiteIncludes { redirects: true, auth: false }, SiteIncludes { redirects: false, auth: true }] {
                    let rendered = render_site_config_including(&t, "example.com", &c, None, want).unwrap();
                    let inserted = crate::services::site_access::ensure_includes(&bare, "example.com", want)
                        .unwrap()
                        .unwrap();
                    assert_eq!(inserted, rendered, "ssl={ssl} {name} {want:?}");
                    assert_eq!(
                        crate::services::site_access::ensure_includes(&rendered, "example.com", want),
                        Ok(None)
                    );
                }
            }
        }
    }

    #[test]
    fn no_template_sets_auth_basic_and_acme_stays_reachable() {
        for t in [
            include_str!("../templates/nginx/http.conf"),
            include_str!("../templates/nginx/https.conf"),
            include_str!("../templates/nginx/proxy.conf"),
        ] {
            assert!(!t.contains("auth_basic"));
            assert!(t.contains("location /.well-known/acme-challenge/"));
        }
    }

    // ── 05-import-hestia W3: aliases, canonical, no-exec, Force SSL / HSTS ──

    /// Every W3 fragment and what it was before (the step-0 templates).
    const W3_FRAGMENTS: &[(&str, &str)] = &[
        ("{{ server_alias_names }}", ""),
        ("{{ canonical_block }}", ""),
        ("{{ no_exec_block }}", ""),
        ("{{ plain_listeners }}", ""),
        ("{{ acme_block }}", ""),
        ("{{ redirect_host }}", "$host"),
        ("{% if force_ssl %}", ""),
        ("{% endif %}# HTTPS server", "# HTTPS server"),
        ("{% if hsts %}", ""),
        (
            "always;\n{% endif %}    add_header X-Content-Type-Options",
            "always;\n    add_header X-Content-Type-Options",
        ),
    ];

    /// The templates as they were before the W3 fragments were added.
    fn templates_without_w3() -> Tera {
        let strip = |t: &str| {
            let mut t = t.replace('\r', "");
            for (a, b) in W3_FRAGMENTS {
                t = t.replace(a, b);
            }
            assert!(!t.contains("force_ssl") && !t.contains("canonical") && !t.contains("no_exec"));
            t
        };
        let mut tera = Tera::default();
        tera.add_raw_template("http.conf", &strip(include_str!("../templates/nginx/http.conf"))).unwrap();
        tera.add_raw_template("https.conf", &strip(include_str!("../templates/nginx/https.conf"))).unwrap();
        tera.add_raw_template("proxy.conf", &strip(include_str!("../templates/nginx/proxy.conf"))).unwrap();
        tera
    }

    fn render(t: &Tera, c: &SiteConfig) -> String {
        render_site_config_including(t, "example.com", c, None, SiteIncludes::default()).unwrap()
    }

    #[test]
    fn absent_w3_settings_render_byte_identically_to_the_step0_templates() {
        let new = init_templates();
        let old = templates_without_w3();
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                assert_eq!(render(&new, &c), render(&old, &c), "ssl={ssl} {name}");
                // The explicit defaults are the same as absent.
                let explicit = with(c.clone(), |c| {
                    c.aliases = Some(vec![]);
                    c.php_no_exec_dirs = Some(vec![]);
                    c.force_ssl = Some(true);
                    c.hsts = Some(true);
                });
                assert_eq!(render(&new, &explicit), render(&old, &c), "ssl={ssl} {name} explicit");
            }
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn aliases_are_in_every_server_block() {
        let t = init_templates();
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                let c = with(c, |c| c.aliases = Some(names(&["www.example.com", "example.org"])));
                let out = render(&t, &c);
                let blocks = out.matches("\nserver {").count();
                assert_eq!(
                    out.matches("    server_name example.com www.example.com example.org;\n").count(),
                    blocks,
                    "ssl={ssl} {name}\n{out}"
                );
            }
        }
    }

    #[test]
    fn canonical_host_is_one_redirect_and_acme_stays_reachable() {
        let t = init_templates();
        let www = |c: SiteConfig| {
            with(c, |c| {
                c.aliases = Some(names(&["www.example.com"]));
                c.canonical_host = Some("www".into());
            })
        };
        // HTTP only: one 301 keeping the scheme, ACME exempt, every runtime.
        for (name, c) in every_branch(false) {
            let out = render(&t, &www(c));
            assert!(out.contains("    if ($host != \"www.example.com\") { set $ch_canonical 1; }\n"), "{name}");
            assert!(out.contains("acme-challenge/\") { set $ch_canonical 0; }"), "{name}");
            assert!(out.contains("return 301 $scheme://www.example.com$request_uri;"), "{name}");
        }
        // HTTPS forced: :80 goes straight to the canonical https URL (a single
        // 301 for any name), :443 redirects the other names.
        for (name, c) in every_branch(true) {
            let out = render(&t, &www(c));
            let (port80, port443) = out.split_at(out.find("# HTTPS server").unwrap());
            assert!(port80.contains("location /.well-known/acme-challenge/"), "{name}");
            assert!(port80.contains("return 301 https://www.example.com$request_uri;"), "{name}");
            assert!(!port80.contains("$host$request_uri"), "{name}");
            assert!(port443.contains(
                "    server_name example.com www.example.com;\n    if ($host != \"www.example.com\") { return 301 https://www.example.com$request_uri; }\n"
            ), "{name}\n{out}");
            // Apex works the same way.
            let apex = with(www(every_branch(true).remove(0).1), |c| c.canonical_host = Some("apex".into()));
            assert!(render(&t, &apex).contains("return 301 https://example.com$request_uri;"));
        }
    }

    #[test]
    fn a_canonical_host_that_is_not_served_is_refused() {
        let t = init_templates();
        let c = with(php_site(true, None), |c| c.canonical_host = Some("www".into()));
        assert!(render_site_config_including(&t, "example.com", &c, None, SiteIncludes::default()).is_err());
        let c = with(php_site(true, None), |c| c.canonical_host = Some("other".into()));
        assert!(render_site_config_including(&t, "example.com", &c, None, SiteIncludes::default()).is_err());
        let c = with(php_site(true, None), |c| c.aliases = Some(names(&["bad name"])));
        assert!(render_site_config_including(&t, "example.com", &c, None, SiteIncludes::default()).is_err());
        let c = with(php_site(true, None), |c| c.php_no_exec_dirs = Some(names(&["/a/../b"])));
        assert!(render_site_config_including(&t, "example.com", &c, None, SiteIncludes::default()).is_err());
    }

    #[test]
    fn force_ssl_off_serves_both_ports_from_one_block() {
        let t = init_templates();
        for (name, c) in every_branch(true) {
            let base = render(&t, &c);
            let c = with(c, |c| c.force_ssl = Some(false));
            let out = render(&t, &c);
            assert_eq!(out.matches("\nserver {").count() + usize::from(out.starts_with("server {")), 1, "{name}\n{out}");
            for l in ["    listen 192.0.2.10:443 ssl;\n", "    listen 192.0.2.10:80;\n", "    listen [::]:80;\n"] {
                assert!(out.contains(l), "{name} missing {l:?}");
            }
            assert!(!out.contains("return 301 https://"), "{name}");
            assert!(out.contains("    location /.well-known/acme-challenge/ {\n        root /var/www/acme;\n    }\n"), "{name}");
            // The serving block keeps everything else (HSTS included).
            assert_eq!(out.contains("Strict-Transport-Security"), base.contains("Strict-Transport-Security"));
            // With a canonical host the redirect keeps the scheme and spares ACME.
            let canon = with(c, |c| {
                c.aliases = Some(names(&["www.example.com"]));
                c.canonical_host = Some("apex".into());
            });
            let out = render(&t, &canon);
            assert!(out.contains("return 301 $scheme://example.com$request_uri;"), "{name}");
            assert!(out.contains("acme-challenge/\") { set $ch_canonical 0; }"), "{name}");
        }
    }

    #[test]
    fn hsts_off_drops_only_the_header() {
        let t = init_templates();
        for (name, c) in every_branch(true) {
            let on = render(&t, &c);
            let off = render(&t, &with(c, |c| c.hsts = Some(false)));
            let line = "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n";
            assert!(on.contains(line), "{name}");
            assert_eq!(off, on.replace(line, ""), "{name}");
        }
    }

    #[test]
    fn no_exec_block_comes_before_every_php_and_asset_location() {
        let t = init_templates();
        let dirs = names(&["/wp-content/uploads", "/uploads"]);
        for ssl in [false, true] {
            for (name, c) in every_branch(ssl) {
                let out = render(&t, &with(c.clone(), |c| c.php_no_exec_dirs = Some(dirs.clone())));
                let block = "    location ~* ^(?:/wp-content/uploads|/uploads)/.*\\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$) {\n        return 403;\n    }\n";
                if c.runtime != "php" {
                    assert!(!out.contains("PHP execution blocked"), "ssl={ssl} {name}");
                    continue;
                }
                let at = out.find(block).unwrap_or_else(|| panic!("ssl={ssl} {name}\n{out}"));
                assert_eq!(out.matches(block).count(), 1);
                // First regex location of the serving block: before `\.php$`,
                // the dotfile deny, preset assets and Apache's static regex.
                let first_regex = out.find("    location ~").unwrap();
                assert_eq!(first_regex, at, "ssl={ssl} {name}");
                if let Some(php) = out.find("location ~ \\.php$") {
                    assert!(at < php);
                }
            }
        }
    }
}
