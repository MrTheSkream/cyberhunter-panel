//! The agent's own systemd unit - one source, reconciled at startup.
//!
//! # Why this module exists
//!
//! `panel/agent/dockpanel-agent.service` is the unit. `setup.sh` and `update.sh`
//! deploy it by copying that exact file, and both derive their pre-`mkdir` list
//! from its `ReadWritePaths=` line rather than mirroring it (s269). A third
//! installer did not: `install-agent.sh` hand-wrote its own unit into a
//! heredoc, and that copy - the one every fleet member in existence is running -
//! set systemd's four headline protection switches - new-privileges, system,
//! home and private-tmp - to off, declared no writable path list whatsoever, and
//! omitted eight further hardening directives the real unit sets, under a
//! comment reading "Create systemd service (matching local agent hardening)".
//! It matched nothing. Every remote box the panel manages ran the agent with no
//! sandbox from s253 to s271.
//!
//! The disabled values are described here rather than quoted, deliberately:
//! `tests/sandbox-paths-pin-e2e.sh` greps the installer sources for them, and a
//! check that matches its own explanation cannot fail.
//!
//! # Why fixing install-agent.sh is not enough (lesson #97a)
//!
//! `install-agent.sh` runs exactly once, at install time, and is served *by the
//! panel* out of the frontend root. Changing it changes what a **new** fleet
//! member gets and nothing else, and `agent-self-update.sh` swaps only the
//! binary - it has never touched the unit. So a corrected installer would have
//! reached no box that already exists, which is precisely the shape that kept
//! the Roundcube fix from arriving for seven sessions.
//!
//! The delivery mechanism that *does* already reach every box is the binary
//! itself, on a six-hourly self-update. So the unit rides the binary:
//! [`AGENT_UNIT`] is `include_str!`'d from the same file the installers copy -
//! the discipline `agent-self-update.sh` states in its own header, "compiled
//! into dockpanel-agent so it cannot drift from the binary that invokes it" -
//! and [`heal_agent_unit`] reconciles the on-disk unit against it at startup.
//!
//! # Why this cannot brick the fleet
//!
//! Writing a hardened unit over an unhardened one is the one change here that
//! could take a whole fleet offline at its next restart, so three things guard
//! it, in order:
//!
//! 1. **The directories are created first.** An UNPREFIXED `ReadWritePaths=`
//!    entry that does not exist fails the namespace mount and the unit does not
//!    start at all (`/etc/apt` did exactly this to every RPM-family box, s264).
//!    `/etc/nginx` is unprefixed and an agent-only box has no nginx, so the
//!    list is derived and created before the unit is swapped - never mirrored.
//! 2. **PID1 is asked whether it accepted the file.** After `daemon-reload`,
//!    `systemctl show -p LoadError` reports what systemd actually thinks of the
//!    unit rather than what we hope; a non-empty `LoadError` restores the
//!    previous bytes verbatim and reloads again.
//! 3. **Nothing is restarted here.** The new sandbox applies at the next start,
//!    which the self-update performs anyway. An agent that restarted itself out
//!    of its own cgroup would be unable to observe its own failure.

use crate::safe_cmd::safe_command;
use std::path::Path;

/// The canonical unit, compiled in from the file the installers deploy.
///
/// **The single source of this unit's contents.** Nothing else may spell it
/// out - `install-agent.sh` doing so for eighteen releases is the whole reason
/// this module exists.
pub const AGENT_UNIT: &str = include_str!("../../dockpanel-agent.service");

/// Where systemd reads the agent's unit from on every install path.
const UNIT_PATH: &str = "/etc/systemd/system/dockpanel-agent.service";

/// Directories the unit's `ReadWritePaths=` names, with any `-` prefix stripped.
///
/// Mirrors `agent_rwp_dirs()` in `setup.sh`/`update.sh`, against the same source
/// text, so the three installers cannot disagree about which directories a
/// working sandbox needs.
pub fn read_write_paths(unit: &str) -> Vec<&str> {
    unit.lines()
        .filter_map(|l| l.strip_prefix("ReadWritePaths="))
        .flat_map(|v| v.split_whitespace())
        .map(|p| p.strip_prefix('-').unwrap_or(p))
        .filter(|p| p.starts_with('/'))
        .collect()
}

/// The `-`-prefixed (optional) entries of `ReadWritePaths=`, prefix stripped.
pub fn optional_read_write_paths(unit: &str) -> Vec<&str> {
    unit.lines()
        .filter_map(|l| l.strip_prefix("ReadWritePaths="))
        .flat_map(|v| v.split_whitespace())
        .filter_map(|p| p.strip_prefix('-'))
        .filter(|p| p.starts_with('/'))
        .collect()
}

/// Bring the on-disk unit up to the compiled-in one.
///
/// Runs at agent startup, so an ordinary binary update is all it takes - which
/// is the point: this is the only path that reaches a box installed by an older
/// `install-agent.sh`. No-op when the bytes already match, which is every panel
/// box (`setup.sh` copies the same file) and every fleet member from the second
/// boot onward.
pub async fn heal_agent_unit() {
    // Only ever reconcile a unit that is already there. Writing one where none
    // exists would mean installing the agent as a service on a box that chose
    // to run it some other way.
    if !Path::new(UNIT_PATH).exists() {
        return;
    }
    let Ok(current) = std::fs::read_to_string(UNIT_PATH) else {
        return;
    };
    if current == AGENT_UNIT {
        return;
    }

    // Guard 1 - the namespace mount. Must happen BEFORE the unit is swapped:
    // an unprefixed entry that is missing at start makes the agent unstartable,
    // and by then there is no agent left to fix it.
    let optional = optional_read_write_paths(AGENT_UNIT);
    for dir in read_write_paths(AGENT_UNIT) {
        if !Path::new(dir).exists() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                // A `-`-prefixed entry that is missing does not stop the unit
                // from starting (systemd skips it), and the agent's own sandbox
                // usually cannot create it under a read-only /etc. Refusing the
                // swap for it would block every future heal on that box.
                if optional.contains(&dir) {
                    tracing::warn!("agent unit heal: could not create optional {dir}: {e} - continuing");
                    continue;
                }
                tracing::warn!("agent unit heal: could not create {dir}: {e} - not swapping the unit");
                return;
            }
        }
    }

    if let Err(e) = std::fs::write(UNIT_PATH, AGENT_UNIT) {
        tracing::warn!("agent unit heal: could not write {UNIT_PATH}: {e}");
        return;
    }
    let _ = safe_command("systemctl").arg("daemon-reload").output().await;

    // Guard 2 - ask PID1 what it made of the file, rather than assuming the
    // write succeeded means the unit is loadable.
    let load_error = safe_command("systemctl")
        .args(["show", "dockpanel-agent", "-p", "LoadError", "--value"])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    if !load_error.is_empty() {
        tracing::error!(
            "agent unit heal: systemd rejected the new unit ({load_error}) - restoring the previous one"
        );
        let _ = std::fs::write(UNIT_PATH, &current);
        let _ = safe_command("systemctl").arg("daemon-reload").output().await;
        return;
    }

    // Guard 3 - deliberately no restart. See the module header.
    tracing::info!(
        "Healed {UNIT_PATH} to the compiled-in unit (sandbox + ReadWritePaths); \
         it takes effect at the next agent restart"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardening the fleet spent eighteen releases without. Spelled here as
    /// separate needles rather than as a copy of the unit, so this test pins the
    /// PROPERTY and not the file's current formatting.
    #[test]
    fn compiled_unit_is_the_hardened_one() {
        for directive in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "RestrictNamespaces=~user",
        ] {
            assert!(
                AGENT_UNIT.contains(directive),
                "the compiled-in unit lost {directive} - install-agent.sh's unit \
                 disabled exactly these, and this module exists to stop that shipping again"
            );
        }
        assert!(
            !AGENT_UNIT.contains("ProtectSystem=no"),
            "the compiled-in unit turns the sandbox off"
        );
    }

    /// A fleet member keeps its token and central URL in agent.env; a panel box
    /// has no such file. The `-` prefix is what lets one unit serve both, and
    /// dropping it would make the panel box refuse to start.
    #[test]
    fn env_file_is_optional_not_required() {
        assert!(
            AGENT_UNIT.contains("EnvironmentFile=-/etc/dockpanel/agent.env"),
            "a fleet member reads AGENT_TOKEN/DOCKPANEL_CENTRAL_URL from agent.env, \
             and the `-` prefix is what keeps the panel box (which has no such file) starting"
        );
    }

    #[test]
    fn read_write_paths_strips_the_optional_prefix() {
        let paths = read_write_paths(AGENT_UNIT);
        assert!(paths.contains(&"/etc/nginx"), "unprefixed entries must be listed");
        assert!(
            paths.contains(&"/etc/apt"),
            "a `-`-prefixed entry still needs its directory created; the prefix \
             only means systemd tolerates it missing at start"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with('-')),
            "the `-` prefix must be stripped before these are handed to mkdir"
        );
    }

    #[test]
    fn hestia_import_paths_are_writable() {
        // 05-import-hestia (W1-S): staging under /var/lib/dockpanel/migration,
        // site files in /var/www, maildirs in /var/vmail, the local MariaDB's
        // config under /etc/mysql. A missing entry is EROFS at import time.
        let paths = read_write_paths(AGENT_UNIT);
        for p in ["/var/lib/dockpanel", "/var/www", "/var/vmail", "/etc/mysql"] {
            assert!(paths.contains(&p), "{p} must be in ReadWritePaths");
        }
        assert!(
            crate::services::migration::STAGING_ROOT.starts_with("/var/lib/dockpanel/"),
            "the staging must stay inside a ReadWritePaths entry"
        );
    }

    #[test]
    fn clamav_paths_are_writable_and_optional() {
        // Feature 5: clamd.conf, the Rspamd antivirus file, the quarantine.
        let paths = read_write_paths(AGENT_UNIT);
        for p in ["/etc/clamav", "/etc/rspamd", "/var/lib/dockpanel", "/etc/systemd/system"] {
            assert!(paths.contains(&p), "{p} must be in ReadWritePaths");
        }
        // Absent until the package is installed: must be `-`-prefixed, or a box
        // without ClamAV/Rspamd could not start the agent.
        for p in ["-/etc/clamav", "-/etc/rspamd"] {
            assert!(
                AGENT_UNIT.lines().any(|l| l.starts_with("ReadWritePaths=") && l.split_whitespace().any(|w| w.ends_with(p) || w == p)),
                "{p} must carry the `-` prefix"
            );
        }
        assert!(crate::services::quarantine::QUARANTINE_ROOT.starts_with("/var/lib/dockpanel/"));
        assert!(crate::services::clamav::SOCKET_DROPIN.starts_with("/etc/systemd/system/"));
    }

    #[test]
    fn user_terminal_unit_dir_is_writable_and_the_sandbox_is_intact() {
        // Feature 9: the tmux user unit lives in /etc/systemd/user. That one
        // optional entry is added; the user's shell is started by PID 1
        // (systemd-run --uid), so the sandbox itself does not move.
        assert!(
            AGENT_UNIT
                .lines()
                .any(|l| l.starts_with("ReadWritePaths=") && l.split_whitespace().any(|w| w == "-/etc/systemd/user")),
            "-/etc/systemd/user must be in ReadWritePaths, with the `-` prefix"
        );
        assert!(optional_read_write_paths(AGENT_UNIT).contains(&"/etc/systemd/user"));
        assert!(read_write_paths(AGENT_UNIT).contains(&"/opt"), "/opt holds /opt/dockpanel-uterm");
        assert!(crate::services::user_terminal::UTERM_DIR.starts_with("/opt/"));
        assert!(crate::services::user_terminal::TMUX_UNIT_PATH.starts_with("/etc/systemd/user/"));
        for directive in ["ProtectHome=yes", "NoNewPrivileges=yes", "ProtectSystem=strict"] {
            assert!(AGENT_UNIT.contains(directive), "{directive} must stay");
        }
        for widened in ["ProtectHome=no", "ProtectHome=read-only", "NoNewPrivileges=no", "/home", "/run/user"] {
            assert!(
                !AGENT_UNIT.lines().any(|l| !l.starts_with('#') && l.contains(widened)),
                "the unit must not grant {widened}"
            );
        }
    }

    #[test]
    fn ftp_paths_are_writable_and_never_a_file() {
        // Feature 6: the PAM service file, the whitelist, the certificate, the
        // fail2ban jail and the vsftpd log.
        let paths = read_write_paths(AGENT_UNIT);
        for p in ["/etc/pam.d", "/etc/dockpanel", "/etc/fail2ban", "/var/log"] {
            assert!(paths.contains(&p), "{p} must be in ReadWritePaths");
        }
        assert!(
            AGENT_UNIT.lines().any(|l| l.starts_with("ReadWritePaths=") && l.split_whitespace().any(|w| w == "-/etc/pam.d")),
            "-/etc/pam.d must carry the `-` prefix"
        );
        for f in [
            crate::services::ftp::USERS_FILE,
            crate::services::ftp::SELF_CERT,
            crate::services::ftp::SELF_KEY,
        ] {
            assert!(f.starts_with("/etc/dockpanel/"), "{f} must stay under /etc/dockpanel");
        }
        assert!(crate::services::ftp::PAM_FILE.starts_with("/etc/pam.d/"));
        // heal_agent_unit and setup.sh/update.sh `mkdir -p` every entry: a file
        // path listed here would become a directory (vsftpd.conf would break the
        // package). Every entry must be a directory.
        assert!(!paths.contains(&crate::services::ftp::CONF), "/etc/vsftpd.conf must not be an RWP entry");
        for p in &paths {
            let last = p.rsplit('/').next().unwrap_or("");
            assert!(
                !last.ends_with(".conf") && !last.ends_with(".cnf") && !last.ends_with(".pem"),
                "{p} looks like a file: every ReadWritePaths entry is mkdir -p'd"
            );
        }
    }
}
