//! How a site's account can actually connect: FTPS (vsftpd) and SFTP (sshd).
//!
//! Read-only facts for the site's "SFTP / FTP Access" card, read from the
//! live configuration rather than assumed. The card used to print
//! `<domain> / 22` for everyone, but on a server where `sftp_sites` is key-only
//! the password from "Reset Password" never works on port 22, and FTPS listens
//! on 21 with mandatory explicit TLS.
//!
//! - SFTP: `sshd -T -C user=<name>,...` gives the effective configuration for
//!   that account, `Match Group sftp_sites` blocks included. The port and
//!   whether password login is accepted come from there. If sshd cannot answer,
//!   `password_login` is `null` (unknown), never a guessed `true`.
//! - FTPS: the vsftpd package, the allow-list (`/etc/dockpanel/ftp-users`) and
//!   `vsftpd.conf` (ports, certificate).

use std::time::Duration;

use crate::safe_cmd::safe_command;
use crate::services::{ftp, sftp_accounts};

/// The client address handed to `sshd -T`. It comes from TEST-NET-3
/// (RFC 5737), so a `Match Address 127.0.0.1` or LAN-only block does not
/// change the answer a real outside client gets.
pub const PROBE_ADDR: &str = "203.0.113.1";
pub const PROBE_HOST: &str = "client.invalid";
const SSHD_T_TIMEOUT: Duration = Duration::from_secs(10);

/// What `sshd -T` says about one account (pure result of [`parse_sshd_t`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshFacts {
    /// Ports sshd listens on, in config order. `sshd -T` always prints at
    /// least one.
    pub ports: Vec<u16>,
    /// Can this account log in with its password alone (password or
    /// keyboard-interactive through PAM)?
    pub password_login: bool,
}

/// The value of `key` in `sshd -T` output (keys are lowercase there).
fn sshd_value<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines().find_map(|l| {
        let (k, v) = l.trim().split_once(char::is_whitespace)?;
        (k == key).then(|| v.trim())
    })
}

/// Does one `AuthenticationMethods` list (`publickey,password`, `password`,
/// `keyboard-interactive:pam`) let the account in with no key, using the
/// methods sshd has enabled?
fn list_is_password_only(list: &str, password: bool, kbd: bool) -> bool {
    !list.is_empty()
        && list.split(',').all(|m| match m.split(':').next().unwrap_or("") {
            "password" => password,
            "keyboard-interactive" => kbd,
            _ => false,
        })
}

/// Parse `sshd -T` output. Pure, tested.
pub fn parse_sshd_t(out: &str) -> Option<SshFacts> {
    let ports: Vec<u16> = out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("port "))
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    if ports.is_empty() {
        return None;
    }
    let yes = |key: &str| sshd_value(out, key).is_some_and(|v| v.eq_ignore_ascii_case("yes"));
    let password = yes("passwordauthentication");
    // Keyboard-interactive only asks for the password through PAM.
    let kbd = (yes("kbdinteractiveauthentication") || yes("challengeresponseauthentication")) && yes("usepam");
    let password_login = match sshd_value(out, "authenticationmethods") {
        None | Some("any") => password || kbd,
        Some(lists) => lists.split_whitespace().any(|l| list_is_password_only(l, password, kbd)),
    };
    Some(SshFacts { ports, password_login })
}

/// The `-C` connection spec for `sshd -T`, or `None` for a name that could
/// add its own criteria (a comma or `=` in it would).
pub fn connection_spec(username: &str) -> Option<String> {
    sftp_accounts::is_valid_custom_username(username)
        .then(|| format!("user={username},host={PROBE_HOST},addr={PROBE_ADDR}"))
}

async fn sshd_facts(username: &str) -> Result<SshFacts, String> {
    let spec = connection_spec(username).ok_or("invalid account name")?;
    let out = tokio::time::timeout(SSHD_T_TIMEOUT, safe_command("sshd").args(["-T", "-C", &spec]).output())
        .await
        .map_err(|_| "sshd -T timed out".to_string())?
        .map_err(|e| format!("sshd -T failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!("sshd -T failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    parse_sshd_t(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| "sshd -T printed no port".to_string())
}

/// The SFTP half of the answer. `ssh_port_fallback` is the port read from
/// the sshd_config files, used only when `sshd -T` cannot answer.
pub fn sftp_json(facts: Result<&SshFacts, &str>, ssh_port_fallback: u16) -> serde_json::Value {
    match facts {
        Ok(f) => serde_json::json!({
            "port": f.ports[0],
            "ports": f.ports,
            "password_login": f.password_login,
            "error": null,
        }),
        Err(e) => serde_json::json!({
            "port": ssh_port_fallback,
            "ports": [ssh_port_fallback],
            "password_login": null,
            "error": e,
        }),
    }
}

/// The FTPS half, from the vsftpd.conf body and the allow-list. Pure, tested.
/// `cert_names` are the DNS names of the certificate vsftpd presents.
pub fn ftps_json(
    installed: bool,
    running: bool,
    allowed: bool,
    conf: &str,
    cert_path: Option<&str>,
    cert_names: &[String],
) -> serde_json::Value {
    if !installed {
        return serde_json::json!({ "installed": false, "running": false, "allowed": false });
    }
    let port = |key: &str, default: u16| ftp::conf_value(conf, key).and_then(|v| v.parse::<u16>().ok()).unwrap_or(default);
    serde_json::json!({
        "installed": true,
        "running": running,
        "allowed": allowed,
        "port": port("listen_port", ftp::CONTROL_PORT),
        "passive_min": port("pasv_min_port", ftp::PASV_MIN),
        "passive_max": port("pasv_max_port", ftp::PASV_MAX),
        "cert_hostname": cert_names.first(),
        "cert_kind": cert_path.map(ftp::cert_kind),
    })
}

/// GET /sftp/sites/{domain}/access-info?username=
pub async fn access_info(username: &str) -> Result<serde_json::Value, String> {
    if connection_spec(username).is_none() {
        return Err("invalid account name".into());
    }
    let (ssh_port, _, _) = crate::services::security::parse_ssh_config().await;
    let ssh = sshd_facts(username).await;
    if let Err(e) = &ssh {
        tracing::warn!("access-info: cannot read the effective sshd config for {username}: {e}");
    }

    let installed = ftp::unsupported_reason().await.is_none() && ftp::is_installed().await;
    let ftps = if installed {
        let conf = std::fs::read_to_string(ftp::CONF).unwrap_or_default();
        let cert_path = ftp::conf_value(&conf, "rsa_cert_file");
        let names = cert_path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|pem| crate::services::ssl::cert_metadata(&pem).ok())
            .map(|m| m.dns_names)
            .unwrap_or_default();
        let allowed = ftp::whitelist().iter().any(|u| u == username);
        ftps_json(true, ftp::is_active().await, allowed, &conf, cert_path.as_deref(), &names)
    } else {
        ftps_json(false, false, false, "", None, &[])
    };

    Ok(serde_json::json!({
        "username": username,
        "sftp": sftp_json(ssh.as_ref().map_err(String::as_str), ssh_port),
        "ftps": ftps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shape of real `sshd -T` output on Ubuntu 24.04 (trimmed).
    const KEY_ONLY: &str = "port 22\nusepam yes\npasswordauthentication no\n\
        kbdinteractiveauthentication no\nauthenticationmethods any\nchrootdirectory %h\n";

    #[test]
    fn key_only_group_says_no_password() {
        let f = parse_sshd_t(KEY_ONLY).unwrap();
        assert_eq!(f.ports, vec![22]);
        assert!(!f.password_login);
    }

    #[test]
    fn password_allowed() {
        let f = parse_sshd_t("port 2222\npasswordauthentication yes\nauthenticationmethods any\n").unwrap();
        assert_eq!(f.ports, vec![2222]);
        assert!(f.password_login);
    }

    #[test]
    fn keyboard_interactive_counts_only_through_pam() {
        let kbd = "port 22\npasswordauthentication no\nkbdinteractiveauthentication yes\nusepam yes\n";
        assert!(parse_sshd_t(kbd).unwrap().password_login);
        let no_pam = "port 22\npasswordauthentication no\nkbdinteractiveauthentication yes\nusepam no\n";
        assert!(!parse_sshd_t(no_pam).unwrap().password_login);
        // Older OpenSSH name for the same switch.
        let old = "port 22\npasswordauthentication no\nchallengeresponseauthentication yes\nusepam yes\n";
        assert!(parse_sshd_t(old).unwrap().password_login);
    }

    #[test]
    fn authentication_methods_can_still_demand_a_key() {
        let both = "port 22\npasswordauthentication yes\nauthenticationmethods publickey,password\n";
        assert!(!parse_sshd_t(both).unwrap().password_login);
        let either = "port 22\npasswordauthentication yes\nauthenticationmethods publickey password\n";
        assert!(parse_sshd_t(either).unwrap().password_login);
        let pam_sub = "port 22\nkbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods keyboard-interactive:pam\n";
        assert!(parse_sshd_t(pam_sub).unwrap().password_login);
        // `password` listed but switched off.
        let off = "port 22\npasswordauthentication no\nauthenticationmethods password\n";
        assert!(!parse_sshd_t(off).unwrap().password_login);
    }

    #[test]
    fn several_ports_and_garbage() {
        let f = parse_sshd_t("port 22\nport 2222\npasswordauthentication no\n").unwrap();
        assert_eq!(f.ports, vec![22, 2222]);
        assert!(parse_sshd_t("").is_none());
        assert!(parse_sshd_t("passwordauthentication yes\n").is_none());
        // Keys are matched whole, not by prefix.
        let f = parse_sshd_t("port 22\npasswordauthenticationx yes\n").unwrap();
        assert!(!f.password_login);
    }

    #[test]
    fn connection_spec_refuses_injection() {
        assert_eq!(
            connection_spec("sftp30001").as_deref(),
            Some("user=sftp30001,host=client.invalid,addr=203.0.113.1")
        );
        assert!(connection_spec("adm-jim_jeuxx").is_some());
        assert!(connection_spec("a,addr=127.0.0.1").is_none());
        assert!(connection_spec("a=b").is_none());
        assert!(connection_spec("").is_none());
        assert!(connection_spec("Root").is_none());
    }

    #[test]
    fn unknown_sshd_answer_is_null_not_true() {
        let v = sftp_json(Err("sshd -T failed"), 2222);
        assert_eq!(v["port"], 2222);
        assert!(v["password_login"].is_null());
        let f = parse_sshd_t(KEY_ONLY).unwrap();
        let v = sftp_json(Ok(&f), 2222);
        assert_eq!(v["port"], 22);
        assert_eq!(v["password_login"], false);
    }

    #[test]
    fn ftps_reads_ports_and_certificate() {
        let conf = ftp::render_conf("/etc/letsencrypt/live/panel.example/fullchain.pem", "/k", None, false);
        let v = ftps_json(
            true,
            true,
            true,
            &conf,
            Some("/etc/letsencrypt/live/panel.example/fullchain.pem"),
            &["panel.example".to_string()],
        );
        assert_eq!(v["port"], 21);
        assert_eq!(v["passive_min"], 12000);
        assert_eq!(v["passive_max"], 12100);
        assert_eq!(v["cert_hostname"], "panel.example");
        assert_eq!(v["cert_kind"], "letsencrypt");
        assert_eq!(v["allowed"], true);

        let v = ftps_json(true, false, false, "listen_port=2121\npasv_min_port=40000\n", None, &[]);
        assert_eq!(v["port"], 2121);
        assert_eq!(v["passive_min"], 40000);
        assert_eq!(v["passive_max"], 12100);
        assert!(v["cert_hostname"].is_null());

        let v = ftps_json(false, false, false, "", None, &[]);
        assert_eq!(v, serde_json::json!({ "installed": false, "running": false, "allowed": false }));
    }
}
