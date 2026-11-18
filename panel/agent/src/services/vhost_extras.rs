//! Vhost extras (05-import-hestia W3-V / W3-F): aliases, canonical host, PHP
//! no-exec folders, per-site Force SSL / HSTS.
//!
//! Everything here is pure: validation, the fragments the nginx templates and
//! the Apache vhost insert, the `server_name` rewrite used by the alias
//! endpoints and the recovery of these settings from a vhost already on disk
//! (the certificate doors re-render a site from a partial description).
//!
//! Absent settings render nothing: every fragment is then the empty string, so
//! an existing site's vhost stays byte for byte what it was.

use crate::routes::is_valid_domain;

/// Most aliases a site may carry (contract W3-V).
pub const MAX_ALIASES: usize = 20;
/// Most PHP no-exec folders a site may carry.
pub const MAX_NO_EXEC_DIRS: usize = 20;
/// Extensions that run as PHP somewhere (php, php5, php7, phtml, ...).
const PHP_EXT_RE: &str = r"\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$)";
/// First line of the nginx no-exec block; also how a vhost on disk is read back.
const NO_EXEC_MARKER: &str = "    # PHP execution blocked in:";
/// Comment of the serving block when HTTPS is not forced.
const NOT_FORCED_MARKER: &str = "    # HTTPS is not forced: this block also answers on port 80";

/// Validated aliases: each a domain, never the site's own name, no duplicate
/// (case-insensitive), at most [`MAX_ALIASES`]. Order is kept.
pub fn validate_aliases(domain: &str, aliases: &[String]) -> Result<Vec<String>, String> {
    if aliases.len() > MAX_ALIASES {
        return Err(format!("A site can have at most {MAX_ALIASES} aliases"));
    }
    let mut out: Vec<String> = Vec::new();
    for a in aliases {
        let a = a.trim();
        if !is_valid_domain(a) {
            return Err(format!("Invalid alias: {}", printable(a)));
        }
        if a.eq_ignore_ascii_case(domain) {
            return Err(format!("{a} is the site's own domain, not an alias"));
        }
        if out.iter().any(|o| o.eq_ignore_ascii_case(a)) {
            return Err(format!("Duplicate alias: {a}"));
        }
        out.push(a.to_string());
    }
    Ok(out)
}

/// The name the canonical host redirects to: `www.<domain>` for `"www"`,
/// `<domain>` for `"apex"`. It must be one of the served names (the domain or
/// an alias), else the redirect would loop or point at nothing.
pub fn canonical_target(
    domain: &str,
    canonical: Option<&str>,
    aliases: &[String],
) -> Result<Option<String>, String> {
    let target = match canonical {
        None => return Ok(None),
        Some("www") => format!("www.{domain}"),
        Some("apex") => domain.to_string(),
        Some(other) => {
            return Err(format!(
                "canonical_host must be \"www\" or \"apex\", not {}",
                printable(other)
            ))
        }
    };
    let served = target == domain || aliases.iter().any(|a| a.eq_ignore_ascii_case(&target));
    if !served {
        return Err(format!(
            "The canonical host {target} is not served by this site: add it as an alias first"
        ));
    }
    Ok(Some(target))
}

/// Validated no-exec folders: `^/[A-Za-z0-9_./-]*$`, no `..`, no `//`, the
/// trailing slash removed, `/` alone refused (it would block every PHP file),
/// no duplicate, at most [`MAX_NO_EXEC_DIRS`].
pub fn validate_no_exec_dirs(dirs: &[String]) -> Result<Vec<String>, String> {
    if dirs.len() > MAX_NO_EXEC_DIRS {
        return Err(format!("At most {MAX_NO_EXEC_DIRS} folders can block PHP execution"));
    }
    let mut out: Vec<String> = Vec::new();
    for d in dirs {
        let ok_chars = d.starts_with('/')
            && d.chars().all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c));
        if !ok_chars || d.contains("..") || d.contains("//") {
            return Err(format!("Invalid folder for the PHP execution block: {}", printable(d)));
        }
        let d = d.trim_end_matches('/');
        if d.is_empty() {
            return Err("The site root cannot be a PHP no-exec folder".into());
        }
        if !out.iter().any(|o| o == d) {
            out.push(d.to_string());
        }
    }
    Ok(out)
}

/// The path regex shared by nginx (`~*`) and Apache (`(?i)`): any file with a
/// PHP extension, at any depth under one of `dirs`, also as a path prefix
/// (`/uploads/x.php/y`). Dots are escaped; nothing else in a validated folder
/// is a regex metacharacter.
pub fn no_exec_regex(dirs: &[String]) -> String {
    let alts: Vec<String> = dirs.iter().map(|d| d.replace('.', r"\.")).collect();
    format!("^(?:{})/.*{PHP_EXT_RE}", alts.join("|"))
}

/// The nginx block (D9), placed before every other regex location of the
/// serving block so it wins. Empty for no folder.
pub fn no_exec_block(dirs: &[String]) -> String {
    if dirs.is_empty() {
        return String::new();
    }
    format!(
        "{NO_EXEC_MARKER} {}\n    location ~* {} {{\n        return 403;\n    }}\n\n",
        dirs.join(" "),
        no_exec_regex(dirs)
    )
}

/// The Apache second layer: `<LocationMatch>` in server config cannot be
/// relaxed by a `.htaccess`. Empty for no folder.
pub fn apache_no_exec_block(dirs: &[String]) -> String {
    if dirs.is_empty() {
        return String::new();
    }
    format!(
        "    <LocationMatch \"(?i){}\">\n        Require all denied\n    </LocationMatch>\n",
        no_exec_regex(dirs)
    )
}

/// The canonical redirect of a block that serves plain HTTP (no certificate,
/// or HTTPS not forced): every other name goes to `target` with the request's
/// own scheme, except the ACME challenge, which stays reachable on port 80 for
/// every name (D4).
pub fn canonical_block_any_scheme(target: &str) -> String {
    format!(
        "    # Canonical host: every other name is redirected to {target}\n\
         \x20   set $ch_canonical 0;\n\
         \x20   if ($host != \"{target}\") {{ set $ch_canonical 1; }}\n\
         \x20   if ($uri ~ \"^/\\.well-known/acme-challenge/\") {{ set $ch_canonical 0; }}\n\
         \x20   if ($ch_canonical) {{ return 301 $scheme://{target}$request_uri; }}\n"
    )
}

/// The canonical redirect of the `:443` block when HTTPS is forced: the `:80`
/// block already sends every name straight to `https://<target>`, so a
/// non-canonical name costs one 301 either way.
pub fn canonical_block_https(target: &str) -> String {
    format!("    if ($host != \"{target}\") {{ return 301 https://{target}$request_uri; }}\n")
}

/// The `:80` listeners added to the serving block when HTTPS is not forced
/// (the redirect-only block is then not rendered at all, so password
/// protection, WAF and rate limits apply on both ports).
pub fn plain_listeners(bind_ip: &str) -> String {
    let v4 = if bind_ip.is_empty() {
        "    listen 80;\n".to_string()
    } else {
        format!("    listen {bind_ip}:80;\n")
    };
    format!("{v4}    listen [::]:80;\n{NOT_FORCED_MARKER}\n")
}

/// The ACME location of the serving block when it also answers on port 80.
pub fn acme_block() -> &'static str {
    "    # ACME challenge for Let's Encrypt\n    location /.well-known/acme-challenge/ {\n        root /var/www/acme;\n    }\n\n"
}

/// Directives of a proxied site that streams: nginx neither holds the response
/// nor spools the request body. Also how a vhost on disk is read back.
pub const PROXY_STREAMING_LINES: &str =
    "        proxy_buffering off;\n        proxy_request_buffering off;\n";
/// `X-Forwarded-For` value of a site whose app trusts it: the connecting address
/// only, so a client cannot prepend a forged entry.
pub const STRICT_FORWARDED_FOR: &str = "$remote_addr";
/// Historical value: the client's own header, extended.
pub const APPENDED_FORWARDED_FOR: &str = "$proxy_add_x_forwarded_for";

/// The name of the per-site Permissions-Policy variable (a domain's dots and
/// hyphens are not valid in an nginx variable name).
pub fn permissions_variable(domain: &str) -> String {
    format!("ch_sec_pp_{}", domain.replace(['.', '-'], "_"))
}

/// `map` blocks giving each default security header of a proxied site an empty
/// value (nginx then omits it) when the application already sent that header.
/// `add_header` alone would send both, and for `Referrer-Policy` the browser
/// keeps the last one: the panel's default would overrule a stricter app.
pub fn upstream_header_maps(domain: &str, permissions_policy: &str) -> String {
    let one = |upstream: &str, var: &str, value: &str| {
        format!("map $upstream_http_{upstream} ${var} {{\n    \"\" \"{value}\";\n    default \"\";\n}}\n")
    };
    [
        one("strict_transport_security", "ch_sec_hsts", "max-age=31536000; includeSubDomains"),
        one("x_content_type_options", "ch_sec_nosniff", "nosniff"),
        one("x_frame_options", "ch_sec_frame", "SAMEORIGIN"),
        one("referrer_policy", "ch_sec_referrer", "strict-origin-when-cross-origin"),
        one("permissions_policy", &permissions_variable(domain), permissions_policy),
    ]
    .concat()
        + "\n"
}

/// `server_name` lines of `vhost` that name `domain` first, rewritten to
/// `server_name <domain> <aliases...>;`. `None` when no line names the domain.
pub fn rewrite_server_names(vhost: &str, domain: &str, aliases: &[String]) -> Option<String> {
    let mut names = domain.to_string();
    for a in aliases {
        names.push(' ');
        names.push_str(a);
    }
    let mut found = false;
    let mut out = String::with_capacity(vhost.len() + 64);
    for line in vhost.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        let indent_len = body.len() - body.trim_start().len();
        let t = body.trim();
        if let Some(rest) = t.strip_prefix("server_name ") {
            let first = rest.trim_end_matches(';').split_whitespace().next();
            if first == Some(domain) && t.ends_with(';') {
                found = true;
                out.push_str(&body[..indent_len]);
                out.push_str(&format!("server_name {names};"));
                if line.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
        }
        out.push_str(line);
    }
    found.then_some(out)
}

/// What a vhost written by this panel says about the settings above.
#[derive(Debug, Default, PartialEq)]
pub struct Recovered {
    pub aliases: Vec<String>,
    pub canonical_host: Option<String>,
    pub php_no_exec_dirs: Vec<String>,
    /// `Some(false)` only when the vhost says HTTPS is not forced.
    pub force_ssl: Option<bool>,
    /// `Some(false)` only for a TLS vhost without the HSTS header.
    pub hsts: Option<bool>,
    /// `Some(true)` only when the vhost streams.
    pub proxy_streaming: Option<bool>,
    /// `Some(true)` only when the vhost replaces `X-Forwarded-For`.
    pub proxy_strict_client_ip: Option<bool>,
}

/// Read the settings back from a vhost on disk, for a re-render that comes
/// with a partial description (certificate doors). Anything not recognised is
/// left at "absent", which renders as before.
pub fn recover_from_vhost(vhost: &str, domain: &str) -> Recovered {
    let aliases = crate::services::apache::aliases_in_nginx_config(vhost, domain);
    let www = format!("www.{domain}");
    let mut canonical_host = None;
    for line in vhost.lines() {
        let t = line.trim();
        let target = t
            .find("return 301 ")
            .map(|i| &t[i + "return 301 ".len()..])
            .and_then(|r| r.strip_prefix("https://").or_else(|| r.strip_prefix("$scheme://")))
            .and_then(|r| r.split("$request_uri").next());
        match target {
            Some(t) if t == www => canonical_host = Some("www".to_string()),
            Some(t) if t == domain => canonical_host = Some("apex".to_string()),
            _ => continue,
        }
        break;
    }
    let php_no_exec_dirs = vhost
        .lines()
        .find_map(|l| l.strip_prefix(NO_EXEC_MARKER))
        .map(|r| r.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let tls = vhost.contains("ssl_certificate ");
    Recovered {
        aliases,
        canonical_host,
        php_no_exec_dirs,
        force_ssl: vhost.contains(NOT_FORCED_MARKER).then_some(false),
        hsts: (tls && !vhost.contains("Strict-Transport-Security")).then_some(false),
        proxy_streaming: vhost.contains(PROXY_STREAMING_LINES).then_some(true),
        proxy_strict_client_ip: vhost
            .contains(&format!("proxy_set_header X-Forwarded-For {STRICT_FORWARDED_FOR};"))
            .then_some(true),
    }
}

/// At most 64 printable characters of a refused value, for an error message.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn aliases_are_validated() {
        assert_eq!(validate_aliases("x.tld", &v(&["www.x.tld", "y.tld"])).unwrap(), v(&["www.x.tld", "y.tld"]));
        assert!(validate_aliases("x.tld", &v(&["x.tld"])).is_err());
        assert!(validate_aliases("x.tld", &v(&["www.x.tld", "WWW.x.tld"])).is_err());
        assert!(validate_aliases("x.tld", &v(&["bad name.tld"])).is_err());
        assert!(validate_aliases("x.tld", &v(&["a.tld;\n include /etc/x"])).is_err());
        let many: Vec<String> = (0..21).map(|i| format!("a{i}.tld")).collect();
        assert!(validate_aliases("x.tld", &many).is_err());
        assert!(validate_aliases("x.tld", &many[..20]).is_ok());
    }

    #[test]
    fn canonical_target_must_be_served() {
        let a = v(&["www.x.tld"]);
        assert_eq!(canonical_target("x.tld", Some("www"), &a).unwrap().as_deref(), Some("www.x.tld"));
        assert_eq!(canonical_target("x.tld", Some("apex"), &a).unwrap().as_deref(), Some("x.tld"));
        assert_eq!(canonical_target("x.tld", Some("apex"), &[]).unwrap().as_deref(), Some("x.tld"));
        assert_eq!(canonical_target("x.tld", None, &a).unwrap(), None);
        assert!(canonical_target("x.tld", Some("www"), &[]).is_err());
        assert!(canonical_target("x.tld", Some("other"), &a).is_err());
    }

    #[test]
    fn no_exec_dirs_are_validated_and_normalised() {
        assert_eq!(validate_no_exec_dirs(&v(&["/uploads/", "/wp-content/uploads", "/uploads"])).unwrap(), v(&["/uploads", "/wp-content/uploads"]));
        for bad in ["uploads", "/a/../b", "/a b", "/a\"b", "/a{b", "/", "//x", "/a\n", "/a;b"] {
            assert!(validate_no_exec_dirs(&v(&[bad])).is_err(), "{bad:?}");
        }
        assert!(validate_no_exec_dirs(&[]).unwrap().is_empty());
    }

    #[test]
    fn the_no_exec_regex_covers_the_dangerous_paths() {
        let r = no_exec_regex(&v(&["/uploads", "/sites/default/files", "/wp-content/up.loads"]));
        assert_eq!(
            r,
            r"^(?:/uploads|/sites/default/files|/wp-content/up\.loads)/.*\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$)"
        );
        // `/uploads/x.php`, `/uploads/x.jpg/x.php` (PATH_INFO trick) and
        // `/Uploads/x.PHP` all match: `.*` spans folders and nginx `~*` /
        // Apache `(?i)` make the match case-insensitive.
        let nginx = no_exec_block(&v(&["/uploads"]));
        assert_eq!(
            nginx,
            "    # PHP execution blocked in: /uploads\n    location ~* ^(?:/uploads)/.*\\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$) {\n        return 403;\n    }\n\n"
        );
        assert_eq!(
            apache_no_exec_block(&v(&["/uploads"])),
            "    <LocationMatch \"(?i)^(?:/uploads)/.*\\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$)\">\n        Require all denied\n    </LocationMatch>\n"
        );
        assert_eq!(no_exec_block(&[]), "");
        assert_eq!(apache_no_exec_block(&[]), "");
        // A light model of the regex on the three contract paths.
        let hits = |p: &str| {
            let p = p.to_ascii_lowercase();
            let Some(rest) = p.strip_prefix("/uploads/") else { return false };
            ["php", "php5", "php7", "phtml", "pht", "phps", "phar"].iter().any(|e| {
                let ext = format!(".{e}");
                rest.match_indices(&ext).any(|(i, _)| {
                    let after = &rest[i + ext.len()..];
                    after.is_empty() || after.starts_with('/')
                })
            })
        };
        assert!(hits("/uploads/x.php"));
        assert!(hits("/uploads/x.jpg/x.php"));
        assert!(hits("/Uploads/x.PHP"));
        assert!(!hits("/uploads/x.jpg"));
    }

    #[test]
    fn canonical_blocks_keep_acme_reachable() {
        let b = canonical_block_any_scheme("www.x.tld");
        assert!(b.contains("if ($host != \"www.x.tld\") { set $ch_canonical 1; }"));
        assert!(b.contains("if ($uri ~ \"^/\\.well-known/acme-challenge/\") { set $ch_canonical 0; }"));
        assert!(b.contains("return 301 $scheme://www.x.tld$request_uri;"));
        assert_eq!(
            canonical_block_https("x.tld"),
            "    if ($host != \"x.tld\") { return 301 https://x.tld$request_uri; }\n"
        );
    }

    #[test]
    fn server_names_are_rewritten_on_every_block() {
        let conf = "server {\n    server_name x.tld;\n}\nserver {\n    server_name x.tld www.x.tld;\n}\nserver {\n    server_name other.tld;\n}\n";
        let out = rewrite_server_names(conf, "x.tld", &v(&["www.x.tld", "y.tld"])).unwrap();
        assert_eq!(out.matches("server_name x.tld www.x.tld y.tld;").count(), 2);
        assert!(out.contains("server_name other.tld;"));
        let back = rewrite_server_names(&out, "x.tld", &[]).unwrap();
        assert_eq!(back.matches("server_name x.tld;\n").count(), 2);
        assert!(rewrite_server_names("server {}\n", "x.tld", &[]).is_none());
    }

    #[test]
    fn settings_are_recovered_from_a_rendered_vhost() {
        let t = crate::services::nginx::init_templates();
        let mut c: crate::routes::nginx::SiteConfig = serde_json::from_value(serde_json::json!({
            "runtime": "php", "root": "/var/www", "php_socket": "unix:/run/php/php8.3-fpm.sock",
            "ssl": true, "ssl_cert": "/etc/dockpanel/ssl/x.tld/fullchain.pem",
            "ssl_key": "/etc/dockpanel/ssl/x.tld/privkey.pem", "bind_ip": "192.0.2.10",
            "aliases": ["www.x.tld"], "canonical_host": "www", "php_no_exec_dirs": ["/uploads"],
            "force_ssl": false, "hsts": false
        }))
        .unwrap();
        let includes = crate::services::site_access::SiteIncludes::default();
        let out = crate::services::nginx::render_site_config_including(&t, "x.tld", &c, None, includes).unwrap();
        let r = recover_from_vhost(&out, "x.tld");
        assert_eq!(r.aliases, v(&["www.x.tld"]));
        assert_eq!(r.canonical_host.as_deref(), Some("www"));
        assert_eq!(r.php_no_exec_dirs, v(&["/uploads"]));
        assert_eq!(r.force_ssl, Some(false));
        assert_eq!(r.hsts, Some(false));
        // Defaults read back as absent.
        c.aliases = None;
        c.canonical_host = None;
        c.php_no_exec_dirs = None;
        c.force_ssl = None;
        c.hsts = None;
        let out = crate::services::nginx::render_site_config_including(&t, "x.tld", &c, None, includes).unwrap();
        assert_eq!(recover_from_vhost(&out, "x.tld"), Recovered::default());
    }
}
