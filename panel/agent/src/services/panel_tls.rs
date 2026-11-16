//! The panel's own host name and Let's Encrypt certificate, shared by the
//! services that present TLS under that name (mail: Postfix/Dovecot; FTP:
//! vsftpd). Moved out of `routes/mail.rs` so both read the same rule.

use std::path::Path;

/// The first `server_name` of the panel's own nginx vhost, if any.
pub fn panel_server_name() -> Option<String> {
    for conf in &[
        "/etc/nginx/sites-enabled/dockpanel-panel.conf",
        "/etc/nginx/conf.d/dockpanel-panel.conf",
    ] {
        if let Ok(content) = std::fs::read_to_string(conf) {
            if let Some(name) = server_name_of(&content) {
                return Some(name);
            }
        }
    }
    None
}

/// First usable `server_name` of an nginx vhost body (pure, tested).
pub fn server_name_of(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("server_name ") {
            let name = rest.trim_end_matches(';').trim();
            if !name.is_empty() && name != "_" {
                if let Some(first) = name.split_whitespace().next() {
                    return Some(first.to_string());
                }
            }
        }
    }
    None
}

/// The panel's own Let's Encrypt certificate, when this box has one for the
/// host the panel is served on: `(fullchain.pem, privkey.pem)`. Without it,
/// Dovecot and Postfix fall back to the distro's self-signed snakeoil (which
/// any IMAP client that verifies its peer refuses, Roundcube among them) and
/// vsftpd to a self-signed certificate of its own.
pub fn panel_tls_paths() -> Option<(String, String)> {
    let host = panel_server_name()?;
    let dir = format!("/etc/letsencrypt/live/{host}");
    let cert = format!("{dir}/fullchain.pem");
    let key = format!("{dir}/privkey.pem");
    (Path::new(&cert).exists() && Path::new(&key).exists()).then_some((cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_parsing() {
        let v = "server {\n    listen 443 ssl;\n    server_name panel.example.com www.panel.example.com;\n}\n";
        assert_eq!(server_name_of(v).as_deref(), Some("panel.example.com"));
        assert_eq!(server_name_of("server_name _;\n"), None);
        assert_eq!(server_name_of("listen 80;\n"), None);
    }
}
