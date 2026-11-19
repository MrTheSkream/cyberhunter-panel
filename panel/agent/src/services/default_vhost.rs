//! The server nginx answers with when no site claims the requested name.
//!
//! Without one, nginx falls back to the first vhost on the address: an unknown
//! name, or the name of a deleted site, receives that site's certificate and
//! content. nginx picks a default server per listen ADDRESS, so a single
//! wildcard block is not enough once sites bind an explicit IP. The address list
//! is therefore derived from the running configuration every time, never
//! accumulated: it only names addresses some site already uses, which means this
//! file opens no new socket and a plain reload is always enough.

use crate::safe_cmd::safe_command;
use std::collections::BTreeSet;
use std::time::Duration;

/// File name, for the scanners that walk the sites directory: on the RHEL family
/// that directory is `conf.d`, so they would otherwise take this for a site.
pub const DEFAULT_VHOST_FILE: &str = "dockpanel-default-vhost.conf";
const DEFAULT_VHOST_PATH: &str = "/etc/nginx/conf.d/dockpanel-default-vhost.conf";

/// Serializes the read, write, test and restore sequence.
static SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One listen address. `host` is empty for the IPv4 wildcard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ListenAddr {
    host: String,
    port: u16,
}

impl ListenAddr {
    fn spec(&self) -> String {
        if self.host.is_empty() {
            self.port.to_string()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Listen {
    addr: Option<ListenAddr>,
    ssl: bool,
    default_server: bool,
    quic: bool,
}

#[derive(Debug, Default)]
struct ServerBlock {
    listens: Vec<Listen>,
    names: Vec<String>,
}

/// Addresses that get a catch-all, by protocol.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    http: BTreeSet<ListenAddr>,
    https: BTreeSet<ListenAddr>,
}

/// Normalize the address of a `listen` directive. `None` for what cannot or need
/// not be covered: unix sockets, host names, and loopback, which no outside
/// client can reach and where local tools such as stub_status often live.
fn parse_listen_addr(value: &str) -> Option<ListenAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if value.starts_with("unix:") {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let ip: Ipv6Addr = host.parse().ok()?;
        if ip.is_loopback() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => 80,
            None => return None,
        };
        return Some(ListenAddr { host: ip.to_string(), port });
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => match value.parse::<u16>() {
            Ok(p) => ("", p),
            Err(_) => (value, 80),
        },
    };
    if host.is_empty() || host == "*" || host == "0.0.0.0" {
        return Some(ListenAddr { host: String::new(), port });
    }
    let ip: Ipv4Addr = host.parse().ok()?;
    if ip.is_loopback() {
        return None;
    }
    Some(ListenAddr { host: ip.to_string(), port })
}

fn parse_listen(args: &[String]) -> Listen {
    let mut listen = Listen {
        addr: args.first().and_then(|a| parse_listen_addr(a)),
        ..Listen::default()
    };
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "ssl" => listen.ssl = true,
            "default_server" | "default" => listen.default_server = true,
            "quic" => listen.quic = true,
            _ => {}
        }
    }
    listen
}

/// Split nginx configuration text into words and the `;`, `{`, `}` separators,
/// dropping comments and honoring quotes (a CSP header or an inline error page
/// may contain any of those characters).
fn tokenize(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if matches!(c, ';' | '{' | '}') {
            tokens.push(c.to_string());
            i += 1;
        } else if c == '"' || c == '\'' {
            let mut word = String::new();
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                word.push(chars[i]);
                i += 1;
            }
            i += 1;
            tokens.push(word);
        } else {
            let mut word = String::new();
            while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], ';' | '{' | '}') {
                // `${name}` is a variable, not a block.
                if chars[i] == '$' && chars.get(i + 1) == Some(&'{') {
                    while i < chars.len() && chars[i] != '}' {
                        word.push(chars[i]);
                        i += 1;
                    }
                }
                if i < chars.len() {
                    word.push(chars[i]);
                    i += 1;
                }
            }
            tokens.push(word);
        }
    }
    tokens
}

/// The HTTP `server` blocks of one configuration file. A file included from
/// `http {}` has its servers at the top level, so both depths count; `stream`
/// and `mail` servers do not.
fn parse_servers(text: &str) -> Vec<ServerBlock> {
    let mut servers = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut current: Option<ServerBlock> = None;

    for token in tokenize(text) {
        match token.as_str() {
            "{" => {
                let name = words.first().cloned().unwrap_or_default();
                let at_http_level = stack.is_empty() || (stack.len() == 1 && stack[0] == "http");
                if name == "server" && at_http_level {
                    current = Some(ServerBlock::default());
                }
                stack.push(name);
                words.clear();
            }
            "}" => {
                let closed = stack.pop();
                let at_http_level = stack.is_empty() || (stack.len() == 1 && stack[0] == "http");
                if closed.as_deref() == Some("server") && at_http_level {
                    servers.extend(current.take());
                }
                words.clear();
            }
            ";" => {
                if stack.last().map(String::as_str) == Some("server") {
                    if let (Some(block), Some(name)) = (current.as_mut(), words.first()) {
                        match name.as_str() {
                            "listen" => block.listens.push(parse_listen(&words[1..])),
                            "server_name" => block.names.extend(words[1..].iter().cloned()),
                            _ => {}
                        }
                    }
                }
                words.clear();
            }
            _ => words.push(token),
        }
    }
    servers
}

/// The servers of an `nginx -T` dump, leaving out the catch-all itself: it must
/// follow the sites, never keep an address alive on its own.
fn servers_in_dump(dump: &str) -> Vec<ServerBlock> {
    let mut servers = Vec::new();
    let mut section = String::new();
    let mut skip = false;
    for line in dump.lines() {
        if let Some(path) = line.strip_prefix("# configuration file ").and_then(|l| l.strip_suffix(':')) {
            if !skip {
                servers.extend(parse_servers(&section));
            }
            section.clear();
            skip = path == DEFAULT_VHOST_PATH;
            continue;
        }
        section.push_str(line);
        section.push('\n');
    }
    if !skip {
        servers.extend(parse_servers(&section));
    }
    servers
}

/// A block an administrator meant to answer for any name or for a bare IP: the
/// panel on a custom port 80/443 without a domain, for instance. An IP in
/// `server_name` counts because a browser sends no SNI for an IP address, so a
/// rejecting catch-all would refuse that connection before the name is read.
fn answers_any_name(block: &ServerBlock) -> bool {
    block.names.is_empty()
        || block
            .names
            .iter()
            .any(|n| n == "_" || n.is_empty() || n.parse::<std::net::IpAddr>().is_ok())
}

fn plan(servers: &[ServerBlock]) -> Plan {
    let mut plan = Plan::default();
    let mut taken: BTreeSet<ListenAddr> = BTreeSet::new();
    for block in servers {
        let any_name = answers_any_name(block);
        for listen in &block.listens {
            let Some(addr) = listen.addr.as_ref().filter(|_| !listen.quic) else { continue };
            match (addr.port, listen.ssl) {
                (80, false) => plan.http.insert(addr.clone()),
                (443, true) => plan.https.insert(addr.clone()),
                _ => continue,
            };
            // A second default_server on one address is a fatal nginx error.
            if listen.default_server || any_name {
                taken.insert(addr.clone());
            }
        }
    }
    plan.http.retain(|a| !taken.contains(a));
    plan.https.retain(|a| !taken.contains(a));
    plan
}

/// `ssl_reject_handshake` arrived in nginx 1.19.4.
fn supports_reject_handshake(version_output: &str) -> bool {
    let Some(rest) = version_output.split("nginx/").nth(1) else { return false };
    let numbers: Vec<u32> = rest
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or_default()
        .split('.')
        .filter_map(|n| n.parse().ok())
        .collect();
    match numbers.as_slice() {
        [major, minor, patch, ..] => (*major, *minor, *patch) >= (1, 19, 4),
        _ => false,
    }
}

/// The file's content, or `None` when no address needs covering. A `server`
/// block without a `listen` would bind `*:80`, so empty blocks are left out.
fn render(plan: &Plan, reject_handshake: bool) -> Option<String> {
    let mut out = String::new();
    if !plan.http.is_empty() {
        out.push_str("server {\n");
        for addr in &plan.http {
            out.push_str(&format!("    listen {} default_server;\n", addr.spec()));
        }
        // The ACME location stays: a certificate request can name an alias that
        // the site's vhost only gains once the certificate has been issued.
        out.push_str(
            "    server_name _;\n    access_log off;\n\n    \
             location ^~ /.well-known/acme-challenge/ {\n        root /var/www/acme;\n    }\n\n    \
             location / {\n        return 444;\n    }\n}\n",
        );
    }
    if reject_handshake && !plan.https.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("server {\n");
        for addr in &plan.https {
            out.push_str(&format!("    listen {} ssl default_server;\n", addr.spec()));
        }
        // ssl_protocols: the default server of a socket can decide the protocols
        // offered to every site on it. `return` answers a client that completed
        // the handshake with a known SNI and then sent an unknown Host.
        out.push_str(
            "    server_name _;\n    access_log off;\n\n    \
             ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_reject_handshake on;\n\n    return 444;\n}\n",
        );
    }
    if out.is_empty() {
        None
    } else {
        Some(format!("# Managed by the panel agent. Rewritten automatically: do not edit.\n{out}"))
    }
}

async fn nginx_output(arg: &str) -> Option<std::process::Output> {
    tokio::time::timeout(Duration::from_secs(30), safe_command("nginx").arg(arg).output())
        .await
        .ok()?
        .ok()
}

/// Bring the catch-all in line with the running configuration, without reloading.
/// Returns whether the file changed. Any failure leaves the previous file in
/// place and the sites untouched.
pub async fn sync() -> bool {
    let _guard = SYNC_LOCK.lock().await;

    // `nginx -T` fails on an invalid configuration: a fault that is not ours, and
    // one the check below could not tell apart from a fault of this file.
    let Some(dump) = nginx_output("-T").await.filter(|o| o.status.success()) else {
        tracing::debug!("Default vhost not updated: nginx -T did not succeed");
        return false;
    };
    let dump = String::from_utf8_lossy(&dump.stdout);
    let version = nginx_output("-v").await.map(|o| String::from_utf8_lossy(&o.stderr).to_string());
    let reject_handshake = version.as_deref().is_some_and(supports_reject_handshake);

    let plan = plan(&servers_in_dump(&dump));
    if !reject_handshake && !plan.https.is_empty() {
        tracing::warn!(
            "This nginx is older than 1.19.4 and cannot reject a TLS handshake: \
             unknown names on port 443 still reach the first site"
        );
    }
    let desired = render(&plan, reject_handshake);
    let current = std::fs::read_to_string(DEFAULT_VHOST_PATH).ok();
    if desired == current {
        return false;
    }

    let written = match &desired {
        Some(body) => {
            let tmp = format!("{DEFAULT_VHOST_PATH}.new");
            let result = std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, DEFAULT_VHOST_PATH));
            if result.is_err() {
                std::fs::remove_file(&tmp).ok();
            }
            result
        }
        None => std::fs::remove_file(DEFAULT_VHOST_PATH),
    };
    if let Err(e) = written {
        tracing::warn!("Could not update the default vhost: {e}");
        return false;
    }

    match super::nginx::test_config().await {
        Ok(out) if out.success => {
            tracing::info!("Default vhost updated for the addresses in use");
            true
        }
        _ => {
            super::nginx::restore_or_remove(DEFAULT_VHOST_PATH, current.as_deref());
            tracing::error!("nginx -t rejected the default vhost: previous file restored, sites untouched");
            false
        }
    }
}

/// Startup entry point: new installs and updated servers both pass through here.
pub async fn reconcile() {
    if sync().await {
        super::nginx::reload().await.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_of(conf: &str) -> Plan {
        plan(&parse_servers(conf))
    }

    fn specs(set: &BTreeSet<ListenAddr>) -> Vec<String> {
        set.iter().map(ListenAddr::spec).collect()
    }

    /// The listeners observed on the VM where the defect was reported.
    const SITE: &str = "server {\n    listen 192.168.250.15:80;\n    listen [::]:80;\n    server_name app.example;\n}\n\
        server {\n    listen 192.168.250.15:443 ssl;\n    listen [::]:443 ssl;\n    server_name app.example;\n}\n";

    #[test]
    fn every_address_in_use_is_covered() {
        let p = plan_of(SITE);
        assert_eq!(specs(&p.http), ["192.168.250.15:80", "[::]:80"]);
        assert_eq!(specs(&p.https), ["192.168.250.15:443", "[::]:443"]);
    }

    #[test]
    fn an_ip_added_later_is_covered_and_a_removed_one_is_dropped() {
        let more = format!("{SITE}server {{\n    listen 192.168.250.16:443 ssl;\n    server_name b.example;\n}}\n");
        assert!(specs(&plan_of(&more).https).contains(&"192.168.250.16:443".to_string()));
        assert!(!specs(&plan_of(SITE).https).contains(&"192.168.250.16:443".to_string()));
    }

    #[test]
    fn the_output_answers_unknown_names_as_specified() {
        let out = render(&plan_of(SITE), true).unwrap();
        for line in [
            "listen 192.168.250.15:80 default_server;",
            "listen [::]:80 default_server;",
            "listen 192.168.250.15:443 ssl default_server;",
            "listen [::]:443 ssl default_server;",
            "ssl_reject_handshake on;",
            "ssl_protocols TLSv1.2 TLSv1.3;",
        ] {
            assert!(out.contains(line), "missing {line}: {out}");
        }
        assert_eq!(out.matches("return 444;").count(), 2, "both ports close the connection");
    }

    #[test]
    fn acme_challenges_stay_reachable_on_port_80() {
        let out = render(&plan_of(SITE), true).unwrap();
        let acme = out.find("location ^~ /.well-known/acme-challenge/").expect("acme location");
        assert!(out[acme..].contains("root /var/www/acme;"));
        // A server-level return would run before any location is chosen.
        let http = &out[..out.find("ssl_reject_handshake").unwrap()];
        assert!(http.contains("location / {\n        return 444;"), "{http}");
    }

    #[test]
    fn the_panel_port_is_never_touched() {
        let p = plan_of("server {\n    listen 8443 ssl;\n    server_name _;\n}\n");
        assert_eq!(p, Plan::default());
        assert_eq!(render(&p, true), None, "no address means no file, not an empty server");
    }

    #[test]
    fn wildcard_spellings_are_one_address() {
        let p = plan_of(
            "server { listen 80; server_name a.example; }\n\
             server { listen *:80; server_name b.example; }\n\
             server { listen 0.0.0.0:80; server_name c.example; }\n",
        );
        assert_eq!(specs(&p.http), ["80"]);
    }

    #[test]
    fn an_existing_default_server_is_left_alone() {
        let conf = format!("{SITE}server {{\n    listen [::]:443 ssl default_server;\n    server_name own.example;\n}}\n");
        let p = plan_of(&conf);
        assert_eq!(specs(&p.https), ["192.168.250.15:443"]);
        assert_eq!(specs(&p.http), ["192.168.250.15:80", "[::]:80"]);
    }

    #[test]
    fn intended_access_by_ip_is_preserved() {
        for name in ["_", "203.0.113.10", "\"\""] {
            let conf = format!("{SITE}server {{\n    listen 192.168.250.15:443 ssl;\n    server_name {name};\n}}\n");
            let p = plan_of(&conf);
            assert_eq!(specs(&p.https), ["[::]:443"], "server_name {name}");
        }
        let nameless = format!("{SITE}server {{\n    listen 192.168.250.15:80;\n}}\n");
        assert_eq!(specs(&plan_of(&nameless).http), ["[::]:80"]);
    }

    #[test]
    fn loopback_unix_and_host_names_are_not_covered() {
        let p = plan_of(
            "server { listen 127.0.0.1:80; server_name status.local; }\n\
             server { listen [::1]:80; server_name status.local; }\n\
             server { listen unix:/run/x.sock; server_name s.local; }\n\
             server { listen localhost:80; server_name s.local; }\n",
        );
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn plain_443_and_quic_do_not_get_a_tls_catch_all() {
        let p = plan_of(
            "server { listen 443; server_name plain.example; }\n\
             server { listen 203.0.113.9:443 quic; server_name q.example; }\n",
        );
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn certbot_comments_and_listen_options_are_understood() {
        let p = plan_of(
            "server {\n    server_name panel.example;\n    listen [::]:443 ssl ipv6only=on; # managed by Certbot\n    \
             listen 10.0.0.5:443 ssl http2; # managed by Certbot\n    # listen 10.0.0.6:443 ssl;\n}\n",
        );
        assert_eq!(specs(&p.https), ["10.0.0.5:443", "[::]:443"]);
    }

    #[test]
    fn braces_and_semicolons_inside_strings_do_not_derail_the_parser() {
        let p = plan_of(
            "server {\n    listen 80;\n    server_name a.example;\n    \
             add_header Content-Security-Policy \"default-src 'self'; } { script-src 'none'\" always;\n    \
             return 503 '<style>a{color:#111}</style>';\n    set $x ${host}y;\n}\n\
             server {\n    listen 203.0.113.7:80;\n    server_name b.example;\n}\n",
        );
        assert_eq!(specs(&p.http), ["80", "203.0.113.7:80"]);
    }

    #[test]
    fn listen_inside_a_location_or_stream_block_is_not_a_site() {
        let p = plan_of(
            "stream {\n    server {\n        listen 203.0.113.1:443 ssl;\n    }\n}\n\
             mail {\n    server {\n        listen 203.0.113.2:80;\n    }\n}\n\
             http {\n    server {\n        listen 203.0.113.3:80;\n        server_name a.example;\n    }\n}\n",
        );
        assert_eq!(specs(&p.http), ["203.0.113.3:80"]);
        assert!(p.https.is_empty());
    }

    #[test]
    fn the_catch_all_does_not_keep_its_own_addresses_alive() {
        let dump = format!(
            "# configuration file /etc/nginx/nginx.conf:\nhttp {{\n}}\n\n\
             # configuration file {DEFAULT_VHOST_PATH}:\nserver {{\n    listen 198.51.100.1:80 default_server;\n    server_name _;\n}}\n\n\
             # configuration file /etc/nginx/sites-enabled/a.conf:\n{SITE}"
        );
        let p = plan(&servers_in_dump(&dump));
        assert_eq!(specs(&p.http), ["192.168.250.15:80", "[::]:80"], "own stale address dropped, own default ignored");
    }

    #[test]
    fn old_nginx_keeps_port_80_and_never_gets_the_unknown_directive() {
        for v in ["nginx version: nginx/1.18.0 (Ubuntu)", "nginx version: nginx/1.19.3", "garbage"] {
            assert!(!supports_reject_handshake(v), "{v}");
        }
        for v in ["nginx version: nginx/1.19.4", "nginx version: nginx/1.24.0 (Ubuntu)", "nginx version: nginx/1.26.3"] {
            assert!(supports_reject_handshake(v), "{v}");
        }
        let out = render(&plan_of(SITE), false).unwrap();
        assert!(!out.contains("ssl_reject_handshake"));
        assert!(!out.contains(":443"));
        assert!(out.contains("listen [::]:80 default_server;"));
    }

    #[test]
    fn rendering_is_stable_so_an_unchanged_set_writes_nothing() {
        assert_eq!(render(&plan_of(SITE), true), render(&plan_of(SITE), true));
    }
}
