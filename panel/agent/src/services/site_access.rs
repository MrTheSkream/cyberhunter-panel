//! Per-site redirects and password protection (D4).
//!
//! Each site may own three data files beside its vhost:
//! `/etc/nginx/redirects/<d>.conf`, `/etc/nginx/auth/<d>.conf` and
//! `/etc/nginx/htpasswd/<d>`. The vhost reaches the first two through an
//! `include` that the TEMPLATES emit whenever the file exists, so a re-render
//! (PHP version, SSL, Apache switch, WAF, rename...) keeps them. Before this,
//! the screens spliced the `include` in by hand and every re-render dropped it
//! without a word.
//!
//! Password protection is applied at `server` level through a variable rather
//! than in `location` blocks: a `location /admin` does not see `/admin/x.php`
//! (the `\.php$` regex location wins), and protecting `/` collided with the
//! template's own `location /`.
//!
//! Everything here is pure except the small file helpers at the bottom.

pub const REDIRECTS_DIR: &str = "/etc/nginx/redirects";
pub const AUTH_DIR: &str = "/etc/nginx/auth";
pub const HTPASSWD_DIR: &str = "/etc/nginx/htpasswd";

/// First line of every auth file this agent writes.
pub const AUTH_HEADER: &str =
    "# Password protection - managed by CyberHunter - Panel. Do not edit by hand.";

pub fn redirects_file(domain: &str) -> String {
    format!("{REDIRECTS_DIR}/{domain}.conf")
}

pub fn auth_file(domain: &str) -> String {
    format!("{AUTH_DIR}/{domain}.conf")
}

pub fn htpasswd_file(domain: &str) -> String {
    format!("{HTPASSWD_DIR}/{domain}")
}

/// The include directives as the templates spell them (without indentation).
pub fn redirects_include(domain: &str) -> String {
    format!("include {};", redirects_file(domain))
}

pub fn auth_include(domain: &str) -> String {
    format!("include {};", auth_file(domain))
}

/// Which per-site include files a vhost render must reference. The renderer
/// takes these as plain booleans; [`SiteIncludes::on_disk`] is the one place
/// that asks the filesystem.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SiteIncludes {
    pub redirects: bool,
    pub auth: bool,
}

impl SiteIncludes {
    pub fn on_disk(domain: &str) -> Self {
        SiteIncludes {
            redirects: std::path::Path::new(&redirects_file(domain)).is_file(),
            auth: std::path::Path::new(&auth_file(domain)).is_file(),
        }
    }
}

// ── protected paths ──────────────────────────────────────────────────

/// Validate a path entered on the protection screen and normalise it (an
/// empty path means `/`; trailing slashes are dropped, so `/admin/` and
/// `/admin` are the same protection).
///
/// Refused: anything not starting with `/`, whitespace, `;`, braces, quotes
/// and backslashes. The path ends up inside a double-quoted nginx string
/// holding a PCRE, and a backslash does not survive both layers intact.
pub fn normalize_protect_path(path: &str) -> Result<String, &'static str> {
    let path = if path.is_empty() { "/" } else { path };
    if !path.starts_with('/')
        || path.contains(|c: char| {
            c.is_whitespace() || c.is_control() || matches!(c, ';' | '{' | '}' | '"' | '\'' | '\\')
        })
    {
        return Err("Invalid path format");
    }
    let trimmed = path.trim_end_matches('/');
    Ok(if trimmed.is_empty() { "/".to_string() } else { trimmed.to_string() })
}

/// Escape PCRE metacharacters. Braces and backslashes never reach here (see
/// [`normalize_protect_path`]) but are escaped anyway.
fn escape_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(c, '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The regex matching a normalised path and everything below it.
fn path_regex(path: &str) -> String {
    if path == "/" {
        "^/".to_string()
    } else {
        format!("^{}(/|$)", escape_regex(path))
    }
}

/// Render the auth file for `domain` protecting `paths` (already normalised).
/// No paths: the header alone, a valid empty include (the vhost may still
/// reference the file, so it must keep existing).
pub fn render_auth_conf(domain: &str, paths: &[String]) -> String {
    let mut out = String::new();
    out.push_str(AUTH_HEADER);
    out.push('\n');
    if paths.is_empty() {
        return out;
    }
    out.push_str("set $cyb_auth off;\n");
    for p in paths {
        out.push_str(&format!(
            "if ($uri ~ \"{}\") {{ set $cyb_auth \"Restricted\"; }}\n",
            path_regex(p)
        ));
    }
    out.push_str("if ($uri ~ \"^/\\.well-known/acme-challenge/\") { set $cyb_auth off; }\n");
    out.push_str("auth_basic $cyb_auth;\n");
    out.push_str(&format!("auth_basic_user_file {};\n", htpasswd_file(domain)));
    out
}

/// True for an auth file in the pre-D4 format (`location X { auth_basic ... }`).
pub fn is_legacy_auth(content: &str) -> bool {
    content.lines().any(|l| l.trim_start().starts_with("location "))
}

/// The protected paths an auth file names, normalised and deduplicated, in
/// file order. Reads both the current format and the legacy `location` one.
pub fn parse_auth_paths(content: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: String| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("location ") {
            // Legacy: `location /admin {`
            let Some(token) = rest.split_whitespace().next() else { continue };
            match normalize_protect_path(token) {
                Ok(p) => push(p),
                Err(_) => tracing::warn!("Dropping protected path {token:?}: not a valid path any more"),
            }
        } else if t.starts_with("if ($uri ~ \"") && t.contains("set $cyb_auth \"Restricted\"") {
            let rest = &t["if ($uri ~ \"".len()..];
            let Some(end) = rest.find("\") {") else { continue };
            let re = &rest[..end];
            let Some(re) = re.strip_prefix('^') else { continue };
            let re = re.strip_suffix("(/|$)").unwrap_or(re);
            let mut path = String::with_capacity(re.len());
            let mut chars = re.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(n) = chars.next() {
                        path.push(n);
                    }
                } else {
                    path.push(c);
                }
            }
            match normalize_protect_path(&path) {
                Ok(p) => push(p),
                Err(_) => tracing::warn!("Dropping protected path {path:?}: not a valid path any more"),
            }
        }
    }
    out
}

/// The auth file in the current format, or `None` when it already is.
pub fn convert_legacy_auth(domain: &str, content: &str) -> Option<String> {
    if !is_legacy_auth(content) {
        return None;
    }
    Some(render_auth_conf(domain, &parse_auth_paths(content)))
}

// ── redirects ────────────────────────────────────────────────────────

/// The source path of one redirect rule line (`location = /x { return ... }`).
pub fn redirect_source(line: &str) -> Option<&str> {
    line.trim().strip_prefix("location = ")?.split(' ').next()
}

// ── include insertion into a live vhost ──────────────────────────────

/// Why [`ensure_includes`] could not place an include.
#[derive(Debug, PartialEq, Eq)]
pub struct NoAnchor;

/// Add the include lines `want` asks for and `vhost` lacks, at the place the
/// templates put them: immediately before the serving block's
/// `access_log /var/log/nginx/<d>.access.log;` (redirects before auth). That
/// line is emitted once, by the serving server block only (443 with SSL),
/// never by the :80 redirect block, so this cannot land in the wrong block.
///
/// `Ok(None)`: nothing to add. `Err(NoAnchor)`: something is missing but the
/// vhost has no anchor line (hand-written), so nothing is changed.
pub fn ensure_includes(
    vhost: &str,
    domain: &str,
    want: SiteIncludes,
) -> Result<Option<String>, NoAnchor> {
    let r_inc = redirects_include(domain);
    let a_inc = auth_include(domain);
    let has = |needle: &str| vhost.lines().any(|l| l.trim() == needle);
    let add_r = want.redirects && !has(&r_inc);
    let add_a = want.auth && !has(&a_inc);
    if !add_r && !add_a {
        return Ok(None);
    }
    let anchor = format!("access_log /var/log/nginx/{domain}.access.log;");
    let lines: Vec<&str> = vhost.split_inclusive('\n').collect();
    let Some(anchor_idx) = lines.iter().rposition(|l| l.trim() == anchor) else {
        return Err(NoAnchor);
    };
    // An auth include already right above the anchor: redirects go above it,
    // which keeps the template's order.
    let auth_idx = (0..anchor_idx).rev().find(|&i| lines[i].trim() == a_inc);
    let mut out = String::with_capacity(vhost.len() + 96);
    for (i, line) in lines.iter().enumerate() {
        if add_r && Some(i) == auth_idx.filter(|_| !add_a) {
            out.push_str(&format!("    {r_inc}\n"));
        }
        if i == anchor_idx {
            if add_r && (add_a || auth_idx.is_none()) {
                out.push_str(&format!("    {r_inc}\n"));
            }
            if add_a {
                out.push_str(&format!("    {a_inc}\n"));
            }
        }
        out.push_str(line);
    }
    Ok(Some(out))
}

// ── file helpers ─────────────────────────────────────────────────────

/// Write through tmp + rename in the same directory, keeping the mode of the
/// file being replaced (nginx workers must still be able to read htpasswd).
pub fn write_atomic(path: &str, content: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.cyb-tmp");
    let perms = std::fs::metadata(path).map(|m| m.permissions()).ok();
    let res = std::fs::write(&tmp, content)
        .and_then(|_| match perms {
            Some(p) => std::fs::set_permissions(&tmp, p),
            None => Ok(()),
        })
        .and_then(|_| std::fs::rename(&tmp, path));
    if res.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    res
}

/// Put a file back as it was: its previous content, or absent.
pub fn restore_file(path: &str, previous: Option<&str>) {
    let res = match previous {
        Some(prev) => write_atomic(path, prev),
        None => match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    };
    if let Err(e) = res {
        tracing::error!("Could not restore {path}: {e}");
    }
}

/// What a file was before a change.
#[derive(Debug)]
enum Before {
    Absent,
    Content(String),
    /// Exists but could not be read: never written by us, never removed.
    Unreadable,
}

/// The contents of a set of files before a change, so it can be undone.
#[derive(Debug, Default)]
pub struct Snapshot(Vec<(String, Before)>);

impl Snapshot {
    pub fn take(paths: &[&str]) -> Self {
        Snapshot(
            paths
                .iter()
                .map(|p| {
                    let before = match std::fs::read_to_string(p) {
                        Ok(c) => Before::Content(c),
                        Err(_) if !std::path::Path::new(p).exists() => Before::Absent,
                        Err(e) => {
                            tracing::warn!("Could not read {p}: {e}");
                            Before::Unreadable
                        }
                    };
                    (p.to_string(), before)
                })
                .collect(),
        )
    }

    /// The previous content; `None` when the file was absent or unreadable.
    pub fn previous(&self, path: &str) -> Option<&str> {
        match self.0.iter().find(|(p, _)| p == path) {
            Some((_, Before::Content(c))) => Some(c),
            _ => None,
        }
    }

    pub fn restore(&self) {
        for (path, before) in &self.0 {
            match before {
                Before::Content(c) => restore_file(path, Some(c)),
                Before::Absent => restore_file(path, None),
                Before::Unreadable => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn auth_file_renders_the_server_level_format() {
        let out = render_auth_conf("example.com", &s(&["/admin", "/"]));
        assert_eq!(
            out,
            format!(
                "{AUTH_HEADER}\n\
                 set $cyb_auth off;\n\
                 if ($uri ~ \"^/admin(/|$)\") {{ set $cyb_auth \"Restricted\"; }}\n\
                 if ($uri ~ \"^/\") {{ set $cyb_auth \"Restricted\"; }}\n\
                 if ($uri ~ \"^/\\.well-known/acme-challenge/\") {{ set $cyb_auth off; }}\n\
                 auth_basic $cyb_auth;\n\
                 auth_basic_user_file /etc/nginx/htpasswd/example.com;\n"
            )
        );
        // The ACME exemption comes after every protected path.
        let acme = out.find("acme-challenge").unwrap();
        assert!(out.rfind("Restricted").unwrap() < acme);
        assert!(!out.contains("location"));
    }

    #[test]
    fn no_paths_renders_a_valid_empty_include() {
        assert_eq!(render_auth_conf("example.com", &[]), format!("{AUTH_HEADER}\n"));
        assert!(parse_auth_paths(&render_auth_conf("example.com", &[])).is_empty());
    }

    #[test]
    fn regex_metacharacters_are_escaped_and_round_trip() {
        let paths = s(&["/", "/wp-admin", "/a.b+c(d)[e]|f*g?h^i$j", "/x/y.php"]);
        let out = render_auth_conf("example.com", &paths);
        assert!(out.contains(r#"if ($uri ~ "^/a\.b\+c\(d\)\[e\]\|f\*g\?h\^i\$j(/|$)")"#), "{out}");
        assert!(out.contains(r#"if ($uri ~ "^/x/y\.php(/|$)")"#), "{out}");
        assert_eq!(parse_auth_paths(&out), paths);
    }

    #[test]
    fn paths_are_validated_and_normalised() {
        assert_eq!(normalize_protect_path("").unwrap(), "/");
        assert_eq!(normalize_protect_path("/").unwrap(), "/");
        assert_eq!(normalize_protect_path("//").unwrap(), "/");
        assert_eq!(normalize_protect_path("/admin/").unwrap(), "/admin");
        assert_eq!(normalize_protect_path("/admin").unwrap(), "/admin");
        for bad in ["admin", "/a b", "/a;b", "/a{", "/a}", "/a\"", "/a'", "/a\\b", "/a\nb", "/a\rb", "/a\tb"] {
            assert!(normalize_protect_path(bad).is_err(), "{bad:?}");
        }
    }

    const LEGACY: &str = "location /admin {\n    auth_basic \"Restricted\";\n    auth_basic_user_file /etc/nginx/htpasswd/example.com;\n    try_files $uri $uri/ =404;\n}\nlocation /private/ {\n    auth_basic \"Restricted\";\n    auth_basic_user_file /etc/nginx/htpasswd/example.com;\n    try_files $uri $uri/ =404;\n}\nlocation / {\n    auth_basic \"Restricted\";\n    auth_basic_user_file /etc/nginx/htpasswd/example.com;\n    try_files $uri $uri/ =404;\n}\n";

    #[test]
    fn both_formats_are_listed() {
        assert_eq!(parse_auth_paths(LEGACY), s(&["/admin", "/private", "/"]));
        let new = render_auth_conf("example.com", &s(&["/admin", "/private", "/"]));
        assert_eq!(parse_auth_paths(&new), s(&["/admin", "/private", "/"]));
        // The ACME exemption is not a protected path.
        assert!(!parse_auth_paths(&new).iter().any(|p| p.contains("well-known")));
    }

    #[test]
    fn legacy_auth_is_converted_once() {
        assert!(is_legacy_auth(LEGACY));
        let converted = convert_legacy_auth("example.com", LEGACY).unwrap();
        assert_eq!(converted, render_auth_conf("example.com", &s(&["/admin", "/private", "/"])));
        assert!(!is_legacy_auth(&converted));
        assert_eq!(convert_legacy_auth("example.com", &converted), None);
    }

    #[test]
    fn redirect_source_is_read_from_a_rule() {
        assert_eq!(redirect_source("location = /old { return 301 /new; }"), Some("/old"));
        assert_eq!(redirect_source("# comment"), None);
    }

    const SSL_VHOST: &str = "server {\n    listen 80;\n    server_name example.com;\n    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n\nserver {\n    listen 443 ssl;\n    server_name example.com;\n    root /var/www/example.com/public;\n\n    access_log /var/log/nginx/example.com.access.log;\n    error_log /var/log/nginx/example.com.error.log;\n}\n";

    #[test]
    fn includes_go_above_the_serving_blocks_access_log() {
        let both = SiteIncludes { redirects: true, auth: true };
        let out = ensure_includes(SSL_VHOST, "example.com", both).unwrap().unwrap();
        assert!(out.contains(
            "    include /etc/nginx/redirects/example.com.conf;\n    include /etc/nginx/auth/example.com.conf;\n    access_log /var/log/nginx/example.com.access.log;\n"
        ));
        // Not in the :80 redirect block.
        let http_block = &out[..out.find("listen 443").unwrap()];
        assert!(!http_block.contains("include"));
        // Idempotent.
        assert_eq!(ensure_includes(&out, "example.com", both), Ok(None));
    }

    #[test]
    fn a_missing_include_is_added_in_template_order() {
        let auth_only = ensure_includes(SSL_VHOST, "example.com", SiteIncludes { redirects: false, auth: true })
            .unwrap()
            .unwrap();
        let both = ensure_includes(&auth_only, "example.com", SiteIncludes { redirects: true, auth: true })
            .unwrap()
            .unwrap();
        let direct = ensure_includes(SSL_VHOST, "example.com", SiteIncludes { redirects: true, auth: true })
            .unwrap()
            .unwrap();
        assert_eq!(both, direct);
    }

    #[test]
    fn nothing_wanted_or_no_anchor() {
        assert_eq!(ensure_includes(SSL_VHOST, "example.com", SiteIncludes::default()), Ok(None));
        let hand = "server {\n    listen 80;\n}\n";
        assert_eq!(
            ensure_includes(hand, "example.com", SiteIncludes { redirects: true, auth: false }),
            Err(NoAnchor)
        );
        // An include already present (the old hand-splice, end of the block) counts.
        let spliced = SSL_VHOST.replacen(
            "    error_log /var/log/nginx/example.com.error.log;\n",
            "    error_log /var/log/nginx/example.com.error.log;\n    include /etc/nginx/auth/example.com.conf;\n",
            1,
        );
        assert_eq!(
            ensure_includes(&spliced, "example.com", SiteIncludes { redirects: false, auth: true }),
            Ok(None)
        );
    }
}
