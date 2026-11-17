//! User terminal (09): a shell as a non-root Linux user, attached to a
//! persistent tmux session where `claude` runs.
//!
//! Design: `conception/09-terminal-utilisateur.md`; contract: sections A-1 to
//! A-8 of `conception/09-terminal-utilisateur-contrats.md`.
//!
//! # Why the shell is started through `systemd-run`
//!
//! The agent runs sandboxed (`ProtectHome=yes`, `ProtectSystem=strict`,
//! `NoNewPrivileges=yes`). A shell forked from it inherits all of that: no real
//! `/home`, no `/run/user`, and no `sudo`. So the pty child does not drop
//! privileges itself: it execs `systemd-run --pty --uid=<login>`, which asks
//! PID 1 for a transient unit. That unit lives outside the agent's namespace,
//! does not inherit `NoNewPrivileges`, and `systemd-run` relays its pty (and
//! `SIGWINCH`) to ours. The sandbox of the agent itself is not weakened.
//!
//! # Why the user-visible files are under `/opt/dockpanel-uterm`
//!
//! The design placed them under `/etc/dockpanel`, but `setup.sh` creates that
//! directory `0700` (it holds `agent.token`, `api.env`, `secret.key`), so the
//! Linux user could neither exec `uterm-attach` nor read `tmux.conf`. Widening
//! `/etc/dockpanel` is not an option. `/opt` is already in the agent's
//! `ReadWritePaths` and world-traversable, so the files live in a dedicated
//! `0755` directory there. Every path is one constant below.
//!
//! # What is never logged
//!
//! Terminal content, tickets and the start command never reach a log line.
//! The audit lines carry the actor, the IP, the login, the unit, a duration and
//! a cause.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use tokio::io::unix::AsyncFd;

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};

// ── Paths and names ─────────────────────────────────────────────────────

/// Scope prefix of a user-terminal ticket: `@user:<login>`.
pub const USER_SCOPE_PREFIX: &str = "@user:";

/// Directory of the files the Linux user must read or exec (see module doc).
pub const UTERM_DIR: &str = "/opt/dockpanel-uterm";
pub const UTERM_BIN_DIR: &str = "/opt/dockpanel-uterm/bin";
pub const TMUX_CONF_PATH: &str = "/opt/dockpanel-uterm/tmux.conf";
pub const ATTACH_PATH: &str = "/opt/dockpanel-uterm/bin/uterm-attach";
pub const AUTOSTART_SCRIPT_PATH: &str = "/opt/dockpanel-uterm/bin/uterm-autostart";
/// One `<login>.autostart` file per linked account.
pub const AUTOSTART_DIR: &str = "/opt/dockpanel-uterm/autostart";
/// The user unit, common to everyone, enabled per linked login.
pub const TMUX_UNIT_PATH: &str = "/etc/systemd/user/dockpanel-tmux.service";
pub const TMUX_UNIT_NAME: &str = "dockpanel-tmux.service";
/// Logins this agent prepared, for the panic button.
pub const REGISTRY_PATH: &str = "/var/lib/dockpanel/user-terminals.json";
/// The agent's existing append-only audit directory.
const AUDIT_DIR: &str = "/var/lib/dockpanel/audit";
const RECORDING_DIR: &str = "/var/lib/dockpanel/recordings";
/// Staging for files written through the unsandboxed fallback.
const STAGE_DIR: &str = "/var/lib/dockpanel/run";

/// Transient connection units: `dockpanel-uterm-<login>-<8 hex>`.
pub const UNIT_PREFIX: &str = "dockpanel-uterm-";
pub const SLICE: &str = "dockpanel-uterm.slice";
/// The tmux session name, shared by the unit and the scripts.
#[allow(dead_code)] // read by the tests, which pin it in the unit and the scripts
pub const SESSION_NAME: &str = "claude";

/// Per-connection hard limit (the 30 min of the other shells does not apply).
pub const CONNECTION_LIMIT: Duration = Duration::from_secs(12 * 3600);
/// Simultaneous connections per login.
pub const MAX_CONNECTIONS_PER_LOGIN: usize = 4;
/// Largest accepted input frame.
pub const MAX_INPUT_FRAME: usize = 64 * 1024;
/// Input received before the pty has produced its first byte is held back,
/// at most this long and this much (see `run_session`).
pub const INPUT_HOLD_LIMIT: Duration = Duration::from_secs(5);
pub const MAX_HELD_INPUT: usize = 256 * 1024;
/// Most `jti` remembered at once.
pub const MAX_JTI: usize = 10_000;
/// Longest accepted start command.
pub const MAX_AUTOSTART_CHARS: usize = 200;

// ── Host files (A-6). setup.sh writes the same bytes; a test compares. ──

pub const TMUX_CONF: &str = r#"# CyberHunter Panel user terminal. Managed file: the agent rewrites it.
set -g default-terminal "tmux-256color"
set -as terminal-features ",xterm-256color:RGB:clipboard:usstyle"
set -g set-clipboard on
set -g mouse on
set -g window-size latest
set -g history-limit 50000
set -g escape-time 10
set -g focus-events on
# Right-click pastes in the panel: no tmux menu, or the pasted keys pick its entries.
unbind -n MouseDown3Pane
unbind -n M-MouseDown3Pane
unbind -n MouseDown3Status
unbind -n M-MouseDown3Status
unbind -n MouseDown3StatusLeft
unbind -n M-MouseDown3StatusLeft
source-file -q ~/.tmux.conf
"#;

pub const TMUX_UNIT: &str = r#"# CyberHunter Panel user terminal. Managed file: the agent rewrites it.
[Unit]
Description=CyberHunter Panel persistent tmux session

[Service]
Type=forking
ExecStart=/usr/bin/tmux -f /opt/dockpanel-uterm/tmux.conf -S %t/dockpanel-tmux.sock new-session -d -s claude -c %h
ExecStartPost=/opt/dockpanel-uterm/bin/uterm-autostart
ExecStop=/usr/bin/tmux -S %t/dockpanel-tmux.sock kill-server
Restart=on-failure

[Install]
WantedBy=default.target
"#;

pub const UTERM_ATTACH: &str = r#"#!/bin/sh
# CyberHunter Panel user terminal: attach this connection to the persistent
# tmux session. Managed file: the agent rewrites it.
systemctl --user start dockpanel-tmux.service || echo "dockpanel: could not start the tmux session" >&2
exec tmux -S "$XDG_RUNTIME_DIR/dockpanel-tmux.sock" attach -t claude
"#;

pub const UTERM_AUTOSTART: &str = r#"#!/bin/sh
# CyberHunter Panel user terminal: type the configured start command into the
# new tmux session. Managed file: the agent rewrites it.
f="/opt/dockpanel-uterm/autostart/${USER}.autostart"
[ -r "$f" ] || exit 0
line=$(head -n 1 "$f")
[ -n "$line" ] || exit 0
sock="$XDG_RUNTIME_DIR/dockpanel-tmux.sock"
tmux -S "$sock" send-keys -t claude -l -- "$line" || exit 0
tmux -S "$sock" send-keys -t claude Enter || true
exit 0
"#;

/// Every host file with its mode, in the order they are written.
pub fn host_files() -> [(&'static str, &'static str, u32); 4] {
    [
        (TMUX_CONF_PATH, TMUX_CONF, 0o644),
        (TMUX_UNIT_PATH, TMUX_UNIT, 0o644),
        (ATTACH_PATH, UTERM_ATTACH, 0o755),
        (AUTOSTART_SCRIPT_PATH, UTERM_AUTOSTART, 0o755),
    ]
}

// ── Login validation (A-5) ──────────────────────────────────────────────

/// `^[a-z_][a-z0-9_-]{0,31}$`
pub fn is_valid_login(login: &str) -> bool {
    let b = login.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// One `passwd` entry, plus whether its home exists (checked outside the
/// agent's namespace, since `/home` is hidden from it).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub home_exists: bool,
}

/// A-5. Pure: every input is passed in. `expected_uid` is the uid of the
/// ticket or of the mapping; `None` skips that one check (the `check` route,
/// which reports the uid rather than asserting it).
pub fn validate_login(
    entry: Option<&PasswdEntry>,
    shells: &[String],
    groups: &[String],
    expected_uid: Option<u32>,
) -> Result<(), Vec<String>> {
    let Some(e) = entry else {
        return Err(vec!["Linux user not found".into()]);
    };
    let mut reasons = Vec::new();
    if e.uid == 0 {
        reasons.push("root is not allowed".to_string());
    } else if e.uid < 1000 {
        reasons.push("UID below 1000 is a system account".to_string());
    } else if e.uid >= 60000 {
        reasons.push("UID 60000 and above is not allowed".to_string());
    }
    if let Some(want) = expected_uid {
        if want != e.uid {
            reasons.push("UID does not match the linked account".to_string());
        }
    }
    if groups.iter().any(|g| g == "sftp_sites") {
        reasons.push("Site accounts (sftp_sites) are not allowed".to_string());
    }
    let shell_listed = shells.iter().any(|s| s == &e.shell);
    if e.shell.is_empty()
        || !shell_listed
        || e.shell.ends_with("nologin")
        || e.shell.ends_with("false")
    {
        reasons.push("Login shell is not valid".to_string());
    }
    if !e.home_exists {
        reasons.push("Home directory does not exist".to_string());
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

/// The entries of `/etc/shells`.
pub fn parse_shells(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn cstr_to_string(p: *const libc::c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// `getpwnam_r`, so NSS sources other than `/etc/passwd` are honoured and no
/// static buffer is shared between threads. `home_exists` is left false.
pub fn lookup_passwd(login: &str) -> Option<PasswdEntry> {
    let name = CString::new(login).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(PasswdEntry {
        name: cstr_to_string(pwd.pw_name),
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: cstr_to_string(pwd.pw_dir),
        shell: cstr_to_string(pwd.pw_shell),
        home_exists: false,
    })
}

fn group_name(gid: libc::gid_t) -> Option<String> {
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 64 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(cstr_to_string(grp.gr_name))
}

/// Every group of `login`: the primary one and the supplementary ones, so a
/// site account is caught whether `sftp_sites` is its primary group or not.
pub fn group_names(login: &str, primary_gid: u32) -> Vec<String> {
    let Ok(name) = CString::new(login) else {
        return Vec::new();
    };
    let mut n: libc::c_int = 64;
    let mut gids: Vec<libc::gid_t> = vec![0; n as usize];
    loop {
        let mut count = gids.len() as libc::c_int;
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), primary_gid, gids.as_mut_ptr(), &mut count) };
        if rc >= 0 {
            gids.truncate(count.max(0) as usize);
            break;
        }
        n = if count as usize > gids.len() { count } else { n * 2 };
        if n > 65536 {
            break;
        }
        gids.resize(n as usize, 0);
    }
    let mut names: Vec<String> = gids.into_iter().filter_map(group_name).collect();
    if let Some(primary) = group_name(primary_gid) {
        if !names.contains(&primary) {
            names.push(primary);
        }
    }
    names
}

/// `test -d <home>` outside the namespace (`ProtectHome=yes` hides `/home`).
async fn home_exists(home: &str) -> bool {
    if home.is_empty() || !home.starts_with('/') {
        return false;
    }
    match safe_command_unsandboxed("test", &[])
        .args(["-d", home])
        .output_with_timeout(Duration::from_secs(15))
        .await
    {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Look up `login` and run [`validate_login`] on what the system says.
async fn check_login(login: &str, expected_uid: Option<u32>) -> (Option<PasswdEntry>, Result<(), Vec<String>>) {
    let mut entry = lookup_passwd(login);
    let mut groups = Vec::new();
    if let Some(e) = entry.as_mut() {
        e.home_exists = home_exists(&e.home).await;
        groups = group_names(login, e.gid);
    }
    let shells = std::fs::read_to_string("/etc/shells")
        .map(|t| parse_shells(&t))
        .unwrap_or_default();
    let verdict = validate_login(entry.as_ref(), &shells, &groups, expected_uid);
    (entry, verdict)
}

// ── Support detection ───────────────────────────────────────────────────

/// `systemd 255 (255.4-1ubuntu8)` → 255.
pub fn parse_systemd_version(text: &str) -> Option<u32> {
    let first = text.lines().next()?;
    let mut words = first.split_whitespace();
    if words.next()? != "systemd" {
        return None;
    }
    let num: String = words.next()?.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// Debian and Ubuntu (and their derivatives) with systemd 248 or later.
pub fn is_supported(os_id: Option<&str>, os_id_like: Option<&str>, systemd: Option<u32>) -> bool {
    let debian_family = |v: &str| v.split_whitespace().any(|w| w == "debian" || w == "ubuntu");
    let family = os_id.is_some_and(debian_family) || os_id_like.is_some_and(debian_family);
    family && systemd.is_some_and(|v| v >= 248)
}

async fn supported_here() -> bool {
    let id = crate::services::pkg::os_release_value("ID").await;
    let like = crate::services::pkg::os_release_value("ID_LIKE").await;
    let version = tokio::time::timeout(
        Duration::from_secs(10),
        safe_command("systemctl").arg("--version").kill_on_drop(true).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .and_then(|o| parse_systemd_version(&String::from_utf8_lossy(&o.stdout)));
    is_supported(id.as_deref(), like.as_deref(), version)
}

fn tmux_installed() -> bool {
    Path::new("/usr/bin/tmux").exists() || Path::new("/bin/tmux").exists()
}

// ── systemctl helpers ───────────────────────────────────────────────────

/// `systemctl --user -M <login>@ <args>`: the ONE place that talks to a
/// user's manager, so the transport can be swapped if the VM says so.
async fn user_systemctl(login: &str, args: &[&str], timeout: Duration) -> Result<std::process::Output, String> {
    if !is_valid_login(login) {
        return Err("invalid login".into());
    }
    let machine = format!("{login}@");
    tokio::time::timeout(
        timeout,
        safe_command("systemctl")
            .args(["--user", "-M", &machine])
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("systemctl --user for {login} timed out"))?
    .map_err(|e| format!("systemctl could not be run: {e}"))
}

async fn system_systemctl(args: &[&str], timeout: Duration) -> Result<std::process::Output, String> {
    tokio::time::timeout(
        timeout,
        safe_command("systemctl").args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "systemctl timed out".to_string())?
    .map_err(|e| format!("systemctl could not be run: {e}"))
}

fn stdout_trim(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

async fn tmux_session_running(login: &str) -> bool {
    user_systemctl(login, &["is-active", TMUX_UNIT_NAME], Duration::from_secs(5))
        .await
        .map(|o| stdout_trim(&o) == "active")
        .unwrap_or(false)
}

async fn unit_active(unit: &str) -> bool {
    system_systemctl(&["is-active", unit], Duration::from_secs(5))
        .await
        .map(|o| matches!(stdout_trim(&o).as_str(), "active" | "activating" | "reloading" | "deactivating"))
        .unwrap_or(false)
}

/// Linger: the marker file logind keeps, readable inside the sandbox.
fn linger_enabled(login: &str) -> bool {
    Path::new("/var/lib/systemd/linger").join(login).exists()
}

/// `sudo -l -n -U <login>` as root, outside the sandbox.
async fn sudo_nopasswd(login: &str) -> bool {
    match safe_command_unsandboxed("sudo", &[])
        .args(["-l", "-n", "-U", login])
        .output_with_timeout(Duration::from_secs(15))
        .await
    {
        Ok(o) => sudo_output_has_nopasswd(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => false,
    }
}

pub fn sudo_output_has_nopasswd(out: &str) -> bool {
    out.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains("NOPASSWD"))
}

// ── The systemd-run line (A-1) ──────────────────────────────────────────

/// `$` → `$$`: systemd expands `$VAR` in the `ExecStart=` that systemd-run
/// builds from its trailing argv. Same rule as `safe_command_unsandboxed`.
pub fn escape_dollar(arg: &str) -> String {
    arg.replace('$', "$$")
}

/// `dockpanel-uterm-<login>-<8 hex>`
pub fn unit_name(login: &str, suffix: u32) -> String {
    format!("{UNIT_PREFIX}{login}-{suffix:08x}")
}

/// The login a connection unit belongs to, or `None` when the name is not one
/// of ours. Exact, unlike a glob: `dockpanel-uterm-bob-*` also matches the
/// units of the login `bob-x`.
pub fn unit_login(unit: &str) -> Option<&str> {
    let rest = unit.strip_prefix(UNIT_PREFIX)?;
    let rest = rest.strip_suffix(".service").unwrap_or(rest);
    let (login, hex) = rest.rsplit_once('-')?;
    if hex.len() != 8 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) || !is_valid_login(login) {
        return None;
    }
    Some(login)
}

/// What the transient unit is started with.
pub struct UnitSpec<'a> {
    pub login: &'a str,
    pub uid: u32,
    pub home: &'a str,
    pub shell: &'a str,
    pub unit: &'a str,
}

/// Arguments of `systemd-run` (program name excluded). The options are
/// D-Bus properties and are passed verbatim; the command after `--` is the
/// unit's `ExecStart=`, so it is the part whose `$` is escaped.
pub fn systemd_run_args(spec: &UnitSpec<'_>, command: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "--quiet".into(),
        "--collect".into(),
        "--pty".into(),
        format!("--uid={}", spec.login),
        format!("--unit={}", spec.unit),
        format!("--slice={SLICE}"),
        format!("--working-directory={}", spec.home),
    ];
    for (k, val) in [
        ("HOME", spec.home.to_string()),
        ("USER", spec.login.to_string()),
        ("LOGNAME", spec.login.to_string()),
        ("SHELL", spec.shell.to_string()),
        ("XDG_RUNTIME_DIR", format!("/run/user/{}", spec.uid)),
        ("TERM", "xterm-256color".to_string()),
        ("COLORTERM", "truecolor".to_string()),
        ("LANG", "C.UTF-8".to_string()),
        ("PATH", "/usr/local/bin:/usr/bin:/bin".to_string()),
    ] {
        v.push(format!("--setenv={k}={val}"));
    }
    v.push("--".into());
    v.extend(command.iter().map(|a| escape_dollar(a)));
    v
}

fn systemd_run_path() -> &'static str {
    if Path::new("/usr/bin/systemd-run").exists() {
        "/usr/bin/systemd-run"
    } else {
        "/bin/systemd-run"
    }
}

// ── Single-use tickets (A-1) ────────────────────────────────────────────

/// `jti` already presented, kept until their `exp`.
pub struct JtiCache {
    seen: HashMap<String, u64>,
    cap: usize,
}

impl JtiCache {
    pub fn new(cap: usize) -> Self {
        Self { seen: HashMap::new(), cap }
    }

    /// True the first time a `jti` is presented, false on a replay. Full
    /// (after purging the expired ones) means refuse: fail closed.
    pub fn accept(&mut self, jti: &str, exp: u64, now: u64) -> bool {
        if jti.is_empty() || jti.len() > 128 {
            return false;
        }
        self.seen.retain(|_, e| *e > now);
        if self.seen.contains_key(jti) || self.seen.len() >= self.cap {
            return false;
        }
        self.seen.insert(jti.to_string(), exp);
        true
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

static JTI_CACHE: LazyLock<Mutex<JtiCache>> = LazyLock::new(|| Mutex::new(JtiCache::new(MAX_JTI)));

// ── Origin (A-1) ────────────────────────────────────────────────────────

/// `host[:port]` of a `Host` header; brackets kept for IPv6.
fn split_host_port(h: &str) -> Option<(&str, Option<u16>)> {
    if h.starts_with('[') {
        let end = h.find(']')?;
        let (host, rest) = h.split_at(end + 1);
        if rest.is_empty() {
            return Some((host, None));
        }
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host, Some(port)));
    }
    match h.split_once(':') {
        None => Some((h, None)),
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
    }
}

/// The `Origin` must be present and name the same host AND port as `Host`.
/// Default ports are normalised (`https://x` equals `x:443`).
pub fn origin_matches_host(origin: Option<&str>, host: Option<&str>) -> bool {
    let (Some(origin), Some(host)) = (origin, host) else {
        return false;
    };
    let Ok(url) = url::Url::parse(origin.trim()) else {
        return false;
    };
    let default = match url.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return false,
    };
    let Some(o_host) = url.host_str() else {
        return false;
    };
    let o_port = url.port().unwrap_or(default);
    let Some((h_host, h_port)) = split_host_port(host.trim()) else {
        return false;
    };
    o_host.eq_ignore_ascii_case(h_host) && o_port == h_port.unwrap_or(default)
}

// ── UTF-8 output with carry (A-1) ───────────────────────────────────────

/// Decodes pty output without breaking a character cut between two reads.
#[derive(Default)]
pub struct Utf8Decoder {
    pending: Vec<u8>,
}

impl Utf8Decoder {
    /// Decode `input` after what was held back. An incomplete sequence at the
    /// end is kept for the next call; an invalid one becomes U+FFFD.
    pub fn decode(&mut self, input: &[u8]) -> String {
        let mut data = std::mem::take(&mut self.pending);
        data.extend_from_slice(input);
        let mut out = String::with_capacity(data.len());
        let mut rest: &[u8] = &data;
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    out.push_str(s);
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                    match e.error_len() {
                        Some(n) => {
                            out.push('\u{FFFD}');
                            rest = &rest[valid + n..];
                        }
                        None => {
                            self.pending = rest[valid..].to_vec();
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// What is still held back, flushed lossily (end of stream).
    pub fn finish(&mut self) -> String {
        if self.pending.is_empty() {
            String::new()
        } else {
            String::from_utf8_lossy(&std::mem::take(&mut self.pending)).into_owned()
        }
    }
}

// ── Input: complete writes (A-1) ────────────────────────────────────────

/// One non-blocking write attempt. `WouldBlock` and `Interrupted` are allowed.
pub trait PtyWrite {
    fn try_write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
}

struct FdWriter(i32);

impl PtyWrite for FdWriter {
    fn try_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.0, buf.as_ptr() as *const _, buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// Write all of `data`, across partial writes, `EINTR` and `EAGAIN`.
/// `wait` is awaited after `EAGAIN` (the fd's writability in production).
pub async fn write_all_pty<W, F, Fut>(w: &mut W, data: &[u8], mut wait: F) -> std::io::Result<()>
where
    W: PtyWrite,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let mut rest = data;
    while !rest.is_empty() {
        match w.try_write(rest) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "pty accepted no bytes")),
            Ok(n) => rest = &rest[n.min(rest.len())..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait().await?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ── WebSocket frames (protocol identical to the other terminals) ────────

#[derive(Debug, PartialEq)]
pub enum Frame {
    Input(String),
    Resize(u16, u16),
    Ignore,
}

pub fn parse_frame(text: &str) -> Frame {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(cmd) => match cmd.get("type").and_then(|t| t.as_str()) {
            Some("input") => match cmd.get("data").and_then(|d| d.as_str()) {
                Some(d) => Frame::Input(d.to_string()),
                None => Frame::Ignore,
            },
            Some("resize") => {
                let c = cmd.get("cols").and_then(|c| c.as_u64()).unwrap_or(80).clamp(1, 1000) as u16;
                let r = cmd.get("rows").and_then(|r| r.as_u64()).unwrap_or(24).clamp(1, 1000) as u16;
                Frame::Resize(c, r)
            }
            _ => Frame::Ignore,
        },
        Err(_) => Frame::Input(text.to_string()),
    }
}

/// Start command of A-3: at most 200 characters, no control character.
/// Empty means "no command".
pub fn validate_autostart(cmd: Option<&str>) -> Result<Option<String>, String> {
    let Some(c) = cmd else { return Ok(None) };
    if c.chars().any(|ch| ch.is_control()) {
        return Err("The start command must be a single line without control characters".into());
    }
    if c.chars().count() > MAX_AUTOSTART_CHARS {
        return Err("The start command is limited to 200 characters".into());
    }
    let t = c.trim();
    Ok(if t.is_empty() { None } else { Some(t.to_string()) })
}

// ── Registry of prepared logins ─────────────────────────────────────────

pub fn parse_registry(text: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("logins").and_then(|l| l.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|l| is_valid_login(l))
        .map(String::from)
        .collect()
}

pub fn load_registry(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path).map(|t| parse_registry(&t)).unwrap_or_default()
}

/// Add `login` (idempotent), atomically.
pub fn add_to_registry(path: &Path, login: &str) -> std::io::Result<()> {
    let mut logins = load_registry(path);
    if logins.iter().any(|l| l == login) {
        return Ok(());
    }
    logins.push(login.to_string());
    logins.sort();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::json!({ "logins": logins }).to_string())?;
    std::fs::rename(&tmp, path)
}

/// Every host file present and the login prepared by this agent.
fn is_prepared(login: &str) -> bool {
    host_files().iter().all(|(p, _, _)| Path::new(p).exists())
        && load_registry(Path::new(REGISTRY_PATH)).iter().any(|l| l == login)
}

// ── Audit (existing format: ts \t severity \t event \t actor \t ip \t details) ──

fn clean_field(s: &str) -> String {
    let c: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if c.trim().is_empty() { "-".into() } else { c }
}

pub fn audit_line(ts: &str, severity: &str, event: &str, actor: &str, ip: &str, details: &str) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        clean_field(ts),
        clean_field(severity),
        clean_field(event),
        clean_field(actor),
        clean_field(ip),
        clean_field(details)
    )
}

fn audit(severity: &str, event: &str, actor: &str, ip: &str, details: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(AUDIT_DIR);
    let now = chrono::Utc::now();
    let path = format!("{AUDIT_DIR}/audit-{}.log", now.format("%Y-%m-%d"));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", audit_line(&now.to_rfc3339(), severity, event, actor, ip, details));
    }
    tracing::info!(target: "terminal_audit", event, actor, ip, details, "user terminal");
}

#[derive(serde::Serialize, Debug, PartialEq)]
pub struct AuditEvent {
    pub timestamp: String,
    pub severity: String,
    pub event: String,
    pub actor: String,
    pub ip: String,
    pub details: String,
}

pub fn parse_audit_line(line: &str) -> Option<AuditEvent> {
    let f: Vec<&str> = line.splitn(6, '\t').collect();
    if f.len() != 6 || !f[2].starts_with("user_terminal.") {
        return None;
    }
    Some(AuditEvent {
        timestamp: f[0].into(),
        severity: f[1].into(),
        event: f[2].into(),
        actor: f[3].into(),
        ip: f[4].into(),
        details: f[5].into(),
    })
}

/// The `user_terminal.*` lines of the audit directory, newest first.
pub fn read_events(dir: &Path, limit: usize) -> Vec<AuditEvent> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".log"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let mut out = Vec::new();
    for f in files.iter().rev() {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for line in text.lines().rev() {
            if let Some(ev) = parse_audit_line(line) {
                out.push(ev);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

pub fn events(limit: Option<usize>) -> Vec<AuditEvent> {
    read_events(Path::new(AUDIT_DIR), limit.unwrap_or(100).clamp(1, 1000))
}

// ── Live connections ────────────────────────────────────────────────────

#[allow(dead_code)] // `unit` is kept for diagnostics
struct ConnEntry {
    id: u64,
    unit: String,
    login: String,
    pid: i32,
    killed: bool,
}

static CONNECTIONS: Mutex<Vec<ConnEntry>> = Mutex::new(Vec::new());
static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

fn connections() -> std::sync::MutexGuard<'static, Vec<ConnEntry>> {
    CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner())
}

/// A reserved per-login slot, released on drop whatever the exit path.
struct ConnGuard {
    id: u64,
}

impl ConnGuard {
    /// Reserve a slot for `login`, or `None` when it already has the maximum.
    fn reserve(login: &str, unit: &str) -> Option<Self> {
        let mut conns = connections();
        if conns.iter().filter(|c| c.login == login).count() >= MAX_CONNECTIONS_PER_LOGIN {
            return None;
        }
        let id = CONN_SEQ.fetch_add(1, Ordering::Relaxed);
        conns.push(ConnEntry { id, unit: unit.to_string(), login: login.to_string(), pid: 0, killed: false });
        Some(Self { id })
    }

    fn set_pid(&self, pid: i32) {
        if let Some(c) = connections().iter_mut().find(|c| c.id == self.id) {
            c.pid = pid;
        }
    }

    fn killed(&self) -> bool {
        connections().iter().any(|c| c.id == self.id && c.killed)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        connections().retain(|c| c.id != self.id);
    }
}

/// The global terminal slot `ws_handler` took, released on drop.
struct SlotGuard;

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let _ = crate::routes::terminal::ACTIVE_TERMINALS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            Some(v.saturating_sub(1))
        });
    }
}

// ── Kill (A-4) ──────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct KillResult {
    pub connections_killed: u32,
    pub sessions_stopped: u32,
}

async fn list_connection_units() -> Option<Vec<String>> {
    let pattern = format!("{UNIT_PREFIX}*");
    let out = system_systemctl(
        &["list-units", "--all", "--plain", "--no-legend", "--full", "--type=service", &pattern],
        Duration::from_secs(3),
    )
    .await
    .ok()?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|u| unit_login(u).is_some())
            .map(String::from)
            .collect(),
    )
}

/// Mark the live connections (all, or those of `login`) as killed and return
/// their `systemd-run` pids. Called before anything is signalled, so a handler
/// that sees its pty die reports `cause=killed`.
pub fn mark_killed(login: Option<&str>) -> Vec<i32> {
    connections()
        .iter_mut()
        .filter(|c| login.is_none_or(|l| c.login == l))
        .map(|c| {
            c.killed = true;
            c.pid
        })
        .collect()
}

/// Stop the connection units (all, or those of `login`) and, with
/// `stop_sessions`, the tmux session of each prepared login (or of `login`).
pub async fn kill(stop_sessions: bool, login: Option<&str>) -> KillResult {
    let login = login.filter(|l| is_valid_login(l));
    // Mark first, so each handler reports `killed` rather than `closed`.
    let pids = mark_killed(login);

    let units: Vec<String> = list_connection_units()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|u| login.is_none_or(|l| unit_login(u) == Some(l)))
        .collect();
    let mut stop: Vec<String> = units.clone();
    if login.is_none() {
        stop.push(format!("{UNIT_PREFIX}*.service"));
    }
    // `--no-block` and short timeouts: the panic caller waits about 15 s in
    // total, and PID 1 finishes the stop (cgroup kill) on its own.
    if !stop.is_empty() {
        let mut args: Vec<&str> = vec!["stop", "--no-block"];
        args.extend(stop.iter().map(String::as_str));
        if let Err(e) = system_systemctl(&args, Duration::from_secs(5)).await {
            tracing::warn!("user terminal kill: {e}");
        }
    }
    for pid in &pids {
        if *pid > 0 {
            unsafe {
                libc::kill(*pid, libc::SIGTERM);
            }
        }
    }

    let mut sessions_stopped = 0u32;
    if stop_sessions {
        let mut logins = load_registry(Path::new(REGISTRY_PATH));
        if let Some(l) = login {
            logins.retain(|x| x == l);
            if logins.is_empty() {
                logins.push(l.to_string());
            }
        }
        // In parallel, each bounded, so the whole kill stays well under 15 s.
        let tasks: Vec<_> = logins
            .into_iter()
            .map(|l| {
                tokio::spawn(async move {
                    let r = user_systemctl(&l, &["stop", TMUX_UNIT_NAME], Duration::from_secs(6)).await;
                    (l, r)
                })
            })
            .collect();
        for t in tasks {
            match t.await {
                Ok((_, Ok(o))) if o.status.success() => sessions_stopped += 1,
                Ok((l, Ok(_))) => tracing::warn!("user terminal kill: could not stop the tmux session of {l}"),
                Ok((_, Err(e))) => tracing::warn!("user terminal kill: {e}"),
                Err(_) => {}
            }
        }
    }

    let result = KillResult {
        connections_killed: units.len().max(pids.len()) as u32,
        sessions_stopped,
    };
    tracing::warn!(
        "user terminals killed: {} connection(s), {} session(s) stopped",
        result.connections_killed,
        result.sessions_stopped
    );
    result
}

// ── Check (A-2) and prepare (A-3) ───────────────────────────────────────

pub async fn check(login: &str) -> serde_json::Value {
    let supported = supported_here().await;
    let (entry, verdict) = check_login(login, None).await;
    let mut reasons = verdict.err().unwrap_or_default();
    if !supported {
        reasons.insert(0, "Not supported on this server".into());
    }
    let session_running = if entry.is_some() { tmux_session_running(login).await } else { false };
    let sudo = if entry.is_some() { sudo_nopasswd(login).await } else { false };
    serde_json::json!({
        "supported": supported,
        "ok": supported && reasons.is_empty(),
        "reasons": reasons,
        "uid": entry.as_ref().map(|e| e.uid),
        "home": entry.as_ref().map(|e| e.home.clone()),
        "shell": entry.as_ref().map(|e| e.shell.clone()),
        "tmux_installed": tmux_installed(),
        "prepared": is_prepared(login),
        "linger": linger_enabled(login),
        "session_running": session_running,
        "sudo_nopasswd": sudo,
    })
}

pub enum PrepareError {
    BadRequest(String),
    Refused(Vec<String>),
    Unsupported,
    Failed(String),
}

/// Write `content` at `path` with `mode` unless it is already there. Falls
/// back to `install` outside the sandbox when the path is read-only (as
/// `/etc/systemd/user` is until the agent restarts with the healed unit).
async fn install_file(path: &str, content: &str, mode: u32) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::read(path).ok().as_deref() == Some(content.as_bytes()) {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        return Ok(false);
    }
    let parent = Path::new(path).parent().map(|p| p.to_path_buf());
    if let Some(dir) = &parent {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = format!("{path}.dockpanel-tmp");
    let direct = std::fs::write(&tmp, content)
        .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)))
        .and_then(|_| std::fs::rename(&tmp, path));
    match direct {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::EROFS) || e.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&tmp);
            std::fs::create_dir_all(STAGE_DIR).map_err(|e| format!("Cannot stage {path}: {e}"))?;
            let staged = format!("{STAGE_DIR}/uterm-{:08x}", rand::random::<u32>());
            std::fs::write(&staged, content).map_err(|e| format!("Cannot stage {path}: {e}"))?;
            let mode_s = format!("{mode:o}");
            let out = safe_command_unsandboxed("install", &[])
                .args(["-D", "-m", &mode_s, &staged, path])
                .output_with_timeout(Duration::from_secs(30))
                .await;
            let _ = std::fs::remove_file(&staged);
            match out {
                Ok(o) if o.status.success() => Ok(true),
                Ok(o) => Err(format!("Failed to write {path}: {}", String::from_utf8_lossy(&o.stderr).trim())),
                Err(e) => Err(format!("Failed to write {path}: {e}")),
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(format!("Failed to write {path}: {e}"))
        }
    }
}

fn ensure_dir(dir: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {dir}: {e}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("Cannot chmod {dir}: {e}"))
}

pub async fn prepare(login: &str, uid: u32, autostart: Option<&str>) -> Result<Vec<String>, PrepareError> {
    if !is_valid_login(login) {
        return Err(PrepareError::BadRequest("Invalid Linux login".into()));
    }
    let autostart = validate_autostart(autostart).map_err(PrepareError::BadRequest)?;
    if !supported_here().await {
        return Err(PrepareError::Unsupported);
    }
    let (_, verdict) = check_login(login, Some(uid)).await;
    verdict.map_err(PrepareError::Refused)?;
    let mut warnings = Vec::new();

    // 1. tmux.
    if !tmux_installed() {
        crate::services::pkg::install(&["tmux"])
            .await
            .map_err(|e| PrepareError::Failed(format!("Could not install tmux: {e}")))?;
    }

    // 2. Host files.
    for dir in [UTERM_DIR, UTERM_BIN_DIR, AUTOSTART_DIR] {
        ensure_dir(dir, 0o755).map_err(PrepareError::Failed)?;
    }
    for (path, content, mode) in host_files() {
        install_file(path, content, mode).await.map_err(PrepareError::Failed)?;
    }

    // 3. Start command.
    let autostart_file = format!("{AUTOSTART_DIR}/{login}.autostart");
    match &autostart {
        Some(cmd) => {
            install_file(&autostart_file, &format!("{cmd}\n"), 0o644)
                .await
                .map_err(PrepareError::Failed)?;
        }
        None => {
            if let Err(e) = std::fs::remove_file(&autostart_file) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(PrepareError::Failed(format!("Cannot remove {autostart_file}: {e}")));
                }
            }
        }
    }

    // 4. Linger, then wait for the user manager. `/run/user` is hidden from
    // the agent (`ProtectHome=yes`), so ask PID 1 instead of stat-ing it.
    let linger = safe_command_unsandboxed("loginctl", &[])
        .args(["enable-linger", login])
        .output_with_timeout(Duration::from_secs(30))
        .await
        .map_err(PrepareError::Failed)?;
    if !linger.status.success() {
        return Err(PrepareError::Failed(format!(
            "loginctl enable-linger failed: {}",
            String::from_utf8_lossy(&linger.stderr).trim()
        )));
    }
    let manager = format!("user@{uid}.service");
    let mut up = false;
    for _ in 0..20 {
        // Exactly `active`: while `activating`, the user bus may not exist yet.
        let state = system_systemctl(&["is-active", &manager], Duration::from_secs(5))
            .await
            .map(|o| stdout_trim(&o))
            .unwrap_or_default();
        if state == "active" {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if !up {
        return Err(PrepareError::Failed(format!("{manager} did not start within 10 s")));
    }

    // 5. Enable the tmux unit for this login (no start: first connection or boot).
    for args in [&["daemon-reload"][..], &["enable", TMUX_UNIT_NAME][..]] {
        let o = user_systemctl(login, args, Duration::from_secs(30))
            .await
            .map_err(PrepareError::Failed)?;
        if !o.status.success() {
            return Err(PrepareError::Failed(format!(
                "systemctl --user {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            )));
        }
    }

    // 6. Registry.
    add_to_registry(Path::new(REGISTRY_PATH), login)
        .map_err(|e| PrepareError::Failed(format!("Cannot update {REGISTRY_PATH}: {e}")))?;

    if sudo_nopasswd(login).await {
        warnings.push("This user can run sudo without a password: a panel session alone gives root".into());
    }
    tracing::info!("user terminal prepared for {login}");
    Ok(warnings)
}

// ── The WebSocket branch (A-1) ──────────────────────────────────────────

#[derive(Deserialize)]
struct UserTicket {
    sub: String,
    purpose: String,
    exp: u64,
    scope: Option<String>,
    uid: Option<u32>,
    jti: Option<String>,
    record: Option<bool>,
}

fn refuse(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Called by `ws_handler` after its ticket check, for a `@user:` scope only.
/// The global slot `ws_handler` took is released here on every refusal.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    raw_ticket: String,
    key: String,
    headers: HeaderMap,
    cols: Option<u16>,
    rows: Option<u16>,
    ws: WebSocketUpgrade,
) -> Response {
    let slot = SlotGuard;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub"]);
    validation.validate_exp = true;
    let claims = match jsonwebtoken::decode::<UserTicket>(
        &raw_ticket,
        &jsonwebtoken::DecodingKey::from_secret(key.as_bytes()),
        &validation,
    ) {
        Ok(d) if d.claims.purpose == "terminal" => d.claims,
        _ => return refuse(StatusCode::UNAUTHORIZED, "Unauthorized"),
    };
    let (Some(ticket_uid), Some(jti)) = (claims.uid, claims.jti.as_deref()) else {
        return refuse(StatusCode::UNAUTHORIZED, "Unauthorized");
    };
    // Burnt at first presentation, whatever happens next.
    let fresh = JTI_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .accept(jti, claims.exp, now_secs());
    if !fresh {
        return refuse(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    let login = match claims.scope.as_deref().and_then(|s| s.strip_prefix(USER_SCOPE_PREFIX)) {
        Some(l) if is_valid_login(l) => l.to_string(),
        _ => return refuse(StatusCode::BAD_REQUEST, "Invalid Linux login"),
    };
    if !origin_matches_host(header(&headers, "origin"), header(&headers, "host")) {
        return refuse(StatusCode::FORBIDDEN, "Origin not allowed");
    }
    let (entry, verdict) = check_login(&login, Some(ticket_uid)).await;
    if let Err(reasons) = verdict {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": reasons.join("; "), "reasons": reasons })),
        )
            .into_response();
    }
    let Some(entry) = entry else {
        return refuse(StatusCode::FORBIDDEN, "Linux user not found");
    };
    if !is_prepared(&login) {
        return refuse(StatusCode::PRECONDITION_FAILED, "User terminal is not prepared for this account");
    }
    let unit = unit_name(&login, rand::random::<u32>());
    let Some(conn) = ConnGuard::reserve(&login, &unit) else {
        return refuse(StatusCode::CONFLICT, "Too many connections for this account");
    };

    let ctx = SessionCtx {
        actor: claims.sub,
        ip: header(&headers, "x-real-ip").unwrap_or("-").to_string(),
        login,
        entry,
        unit,
        record: claims.record.unwrap_or(false),
        cols: cols.unwrap_or(80).clamp(1, 1000),
        rows: rows.unwrap_or(24).clamp(1, 1000),
    };
    ws.on_upgrade(move |socket| run_session(socket, ctx, slot, conn))
}

struct SessionCtx {
    actor: String,
    ip: String,
    login: String,
    entry: PasswdEntry,
    unit: String,
    record: bool,
    cols: u16,
    rows: u16,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Cause {
    Closed,
    WsLost,
    Killed,
    Timeout,
}

impl Cause {
    fn as_str(self) -> &'static str {
        match self {
            Cause::Closed => "closed",
            Cause::WsLost => "ws_lost",
            Cause::Killed => "killed",
            Cause::Timeout => "timeout",
        }
    }
}

/// Close code sent when the shell side ended on its own (tmux detach, or the
/// shell exited): the page then stops reconnecting instead of reattaching.
pub const CLOSE_DETACHED: u16 = 4000;

/// The close frame for the end of a connection. Only a pty that ended by
/// itself, and was not killed, gets the distinct `4000 "detached"`; a kill, the
/// 12-hour limit or a client close keep the plain close, so the page reconnects
/// (or was the one closing).
fn close_frame(pty_ended: bool, killed: bool) -> Option<CloseFrame> {
    (pty_ended && !killed).then(|| CloseFrame { code: CLOSE_DETACHED, reason: "detached".into() })
}

fn set_winsize(fd: i32, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// New pty, fork, and exec `program args` in the child with the pty as its
/// controlling terminal. Everything the child needs is allocated BEFORE the
/// fork; after it, only async-signal-safe calls. No setuid, no prctl: the
/// privilege change is PID 1's, through `systemd-run --uid`.
fn spawn_pty(program: &str, args: &[String], cols: u16, rows: u16) -> Result<(OwnedFd, i32), String> {
    let master = rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
        .map_err(|e| format!("openpt: {e}"))?;
    rustix::pty::grantpt(&master).map_err(|e| format!("grantpt: {e}"))?;
    rustix::pty::unlockpt(&master).map_err(|e| format!("unlockpt: {e}"))?;
    let slave = rustix::pty::ptsname(&master, Vec::with_capacity(256)).map_err(|e| format!("ptsname: {e}"))?;
    set_winsize(master.as_raw_fd(), cols, rows);
    unsafe {
        let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        if fl < 0 || libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err("fcntl O_NONBLOCK failed".into());
        }
    }

    let prog = CString::new(program).map_err(|_| "program path contains NUL".to_string())?;
    let mut argv_c = vec![prog.clone()];
    for a in args {
        argv_c.push(CString::new(a.as_str()).map_err(|_| "argument contains NUL".to_string())?);
    }
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let env_c: Vec<CString> = ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm-256color", "LANG=C.UTF-8"]
        .iter()
        .map(|s| CString::new(*s).unwrap_or_default())
        .collect();
    let mut env_p: Vec<*const libc::c_char> = env_c.iter().map(|c| c.as_ptr()).collect();
    env_p.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid == 0 {
        unsafe {
            libc::setsid();
            let fd = libc::open(slave.as_ptr(), libc::O_RDWR);
            if fd < 0 {
                libc::_exit(1);
            }
            libc::ioctl(fd, libc::TIOCSCTTY as _, 0);
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            // Close everything above stderr: the master, sockets, the token.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
                for f in 3..65536 {
                    libc::close(f);
                }
            }
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            libc::clearenv();
            libc::execve(prog.as_ptr(), argv_p.as_ptr(), env_p.as_ptr());
            libc::_exit(127);
        }
    }
    Ok((master, pid))
}

async fn read_loop(afd: Arc<AsyncFd<OwnedFd>>, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let mut guard = match afd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };
        let res = guard.try_io(|inner| {
            let n = unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // EIO: the child side is gone.
            Ok(Err(_)) => break,
            Err(_would_block) => {}
        }
    }
}

/// Send the input held while the pty was silent, in order. `false` when the
/// writer is gone.
async fn flush_held(in_tx: &tokio::sync::mpsc::Sender<Vec<u8>>, held: &mut Vec<Vec<u8>>) -> bool {
    for data in held.drain(..) {
        if in_tx.send(data).await.is_err() {
            return false;
        }
    }
    true
}

async fn write_loop(afd: Arc<AsyncFd<OwnedFd>>, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let mut w = FdWriter(afd.get_ref().as_raw_fd());
    while let Some(data) = rx.recv().await {
        let wait = || {
            let afd = afd.clone();
            async move {
                let mut g = afd.writable().await?;
                g.clear_ready();
                Ok(())
            }
        };
        if write_all_pty(&mut w, &data, wait).await.is_err() {
            break;
        }
    }
}

/// Poll `waitpid(WNOHANG)` for up to `limit`.
async fn reap_within(pid: i32, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid || r < 0 {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn open_recording(ctx: &SessionCtx) -> Option<std::fs::File> {
    use std::io::Write;
    if !ctx.record {
        return None;
    }
    let _ = std::fs::create_dir_all(RECORDING_DIR);
    let path = format!("{RECORDING_DIR}/{}.cast", uuid::Uuid::new_v4());
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).ok()?;
    let header = serde_json::json!({
        "version": 2,
        "width": ctx.cols,
        "height": ctx.rows,
        "timestamp": chrono::Utc::now().timestamp(),
        "env": { "TERM": "xterm-256color", "SHELL": ctx.entry.shell },
        "title": format!("{}@{}{}", ctx.actor, USER_SCOPE_PREFIX, ctx.login),
    });
    let _ = writeln!(f, "{header}");
    Some(f)
}

async fn run_session(mut socket: WebSocket, ctx: SessionCtx, _slot: SlotGuard, conn: ConnGuard) {
    let started = std::time::Instant::now();
    let existing = tmux_session_running(&ctx.login).await;
    let base = format!("login={} unit={}", ctx.login, ctx.unit);
    audit(
        "info",
        if existing { "user_terminal.attach" } else { "user_terminal.session_created" },
        &ctx.actor,
        &ctx.ip,
        &base,
    );

    let spec = UnitSpec {
        login: &ctx.login,
        uid: ctx.entry.uid,
        home: &ctx.entry.home,
        shell: &ctx.entry.shell,
        unit: &ctx.unit,
    };
    let args = systemd_run_args(&spec, &[ATTACH_PATH]);
    let (master, pid) = match spawn_pty(systemd_run_path(), &args, ctx.cols, ctx.rows) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("user terminal for {}: {e}", ctx.login);
            let _ = socket.send(Message::Text("Failed to open the user terminal".into())).await;
            audit("warning", "user_terminal.detach", &ctx.actor, &ctx.ip, &format!("{base} duration_secs=0 cause=closed"));
            return;
        }
    };
    conn.set_pid(pid);
    crate::routes::terminal::register_terminal(pid, false);
    let raw_fd = master.as_raw_fd();

    let afd = match AsyncFd::new(master) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            tracing::warn!("user terminal for {}: AsyncFd: {e}", ctx.login);
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            reap_within(pid, Duration::from_secs(2)).await;
            crate::routes::terminal::forget_terminal(pid);
            return;
        }
    };
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let reader = tokio::spawn(read_loop(afd.clone(), out_tx));
    let writer = tokio::spawn(write_loop(afd.clone(), in_rx));

    let mut recording = open_recording(&ctx);
    let mut decoder = Utf8Decoder::default();
    let deadline = tokio::time::Instant::now() + CONNECTION_LIMIT;
    // The pty reached EOF: tmux detached or the shell exited. Still audited as
    // `closed` (the contract's causes), but told apart in the close frame.
    let mut pty_ended = false;
    // Input is held until the pty speaks. Bytes written into the pty before
    // the unit has its tty settled are echoed back by the line discipline;
    // `systemd-run --pty` reads that echo, which ends its "ignore the initial
    // hangup" grace, and the hangup PID 1 then does on the tty when it starts
    // the unit tears its forwarder down for good: the connection stays open
    // and silent while tmux runs unseen. The first byte we read comes from
    // tmux drawing the screen, after that hangup, so input is safe from then
    // on. A typist (or a page restoring a draft) who is quick is enough to
    // hit it; the bound keeps a silent pty from holding input for ever.
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut held_bytes = 0usize;
    let mut pty_spoke = false;
    let hold_until = tokio::time::Instant::now() + INPUT_HOLD_LIMIT;

    let cause = loop {
        tokio::select! {
            _ = tokio::time::sleep_until(hold_until), if !pty_spoke => {
                pty_spoke = true;
                if !flush_held(&in_tx, &mut held).await {
                    break Cause::Closed;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = socket.send(Message::Text(
                    "\r\n\x1b[1;33mConnection limit reached (12 hours). Reconnect to continue: the session is still running.\x1b[0m\r\n".into()
                )).await;
                break Cause::Timeout;
            }
            data = out_rx.recv() => {
                let (text, end) = match data {
                    Some(d) => (decoder.decode(&d), false),
                    None => (decoder.finish(), true),
                };
                if !pty_spoke && !text.is_empty() {
                    pty_spoke = true;
                    if !flush_held(&in_tx, &mut held).await {
                        break Cause::Closed;
                    }
                }
                if !text.is_empty() {
                    if let Some(f) = recording.as_mut() {
                        use std::io::Write;
                        let ev = serde_json::json!([started.elapsed().as_secs_f64(), "o", text]);
                        let _ = writeln!(f, "{ev}");
                    }
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break Cause::WsLost;
                    }
                }
                if end {
                    pty_ended = true;
                    break Cause::Closed;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(t))) => match parse_frame(&t) {
                        Frame::Input(data) => {
                            if data.len() > MAX_INPUT_FRAME {
                                tracing::warn!("user terminal for {}: input frame over 64 KiB dropped", ctx.login);
                            } else if !pty_spoke {
                                if held_bytes + data.len() <= MAX_HELD_INPUT {
                                    held_bytes += data.len();
                                    held.push(data.into_bytes());
                                } else {
                                    tracing::warn!("user terminal for {}: early input over 256 KiB dropped", ctx.login);
                                }
                            } else if in_tx.send(data.into_bytes()).await.is_err() {
                                break Cause::Closed;
                            }
                        }
                        Frame::Resize(c, r) => set_winsize(raw_fd, c, r),
                        Frame::Ignore => {}
                    },
                    Some(Ok(Message::Close(_))) => break Cause::Closed,
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break Cause::WsLost,
                }
            }
        }
    };

    // End of connection: SIGTERM to systemd-run, then stop the unit if it is
    // still there after 2 s. The tmux server lives in user@<uid>.service and
    // is not touched.
    drop(in_tx);
    writer.abort();
    reader.abort();
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let reaped = reap_within(pid, Duration::from_secs(2)).await;
    if unit_active(&ctx.unit).await {
        let _ = system_systemctl(&["stop", &ctx.unit], Duration::from_secs(20)).await;
    }
    if !reaped {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || unsafe {
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
            }),
        )
        .await;
    }
    crate::routes::terminal::forget_terminal(pid);
    drop(afd);

    let killed = conn.killed();
    let cause = if killed { Cause::Killed } else { cause };
    audit(
        "info",
        "user_terminal.detach",
        &ctx.actor,
        &ctx.ip,
        &format!("{base} duration_secs={} cause={}", started.elapsed().as_secs(), cause.as_str()),
    );
    let _ = socket.send(Message::Close(close_frame(pty_ended, killed))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(uid: u32, shell: &str, home_exists: bool) -> PasswdEntry {
        PasswdEntry {
            name: "bastien".into(),
            uid,
            gid: uid,
            home: "/home/bastien".into(),
            shell: shell.into(),
            home_exists,
        }
    }

    fn shells() -> Vec<String> {
        parse_shells("# /etc/shells\n/bin/sh\n/bin/bash\n/usr/bin/zsh\n/usr/sbin/nologin\n/bin/false\n")
    }

    fn reasons(r: Result<(), Vec<String>>) -> Vec<String> {
        r.err().unwrap_or_default()
    }

    #[test]
    fn a_normal_user_is_accepted() {
        let e = entry(1000, "/bin/bash", true);
        assert_eq!(validate_login(Some(&e), &shells(), &["bastien".into(), "sudo".into()], Some(1000)), Ok(()));
        assert_eq!(validate_login(Some(&e), &shells(), &[], None), Ok(()));
    }

    #[test]
    fn every_refusal_reason() {
        assert_eq!(reasons(validate_login(None, &shells(), &[], None)), ["Linux user not found"]);
        assert_eq!(reasons(validate_login(Some(&entry(0, "/bin/bash", true)), &shells(), &[], None)), ["root is not allowed"]);
        assert_eq!(
            reasons(validate_login(Some(&entry(999, "/bin/bash", true)), &shells(), &[], None)),
            ["UID below 1000 is a system account"]
        );
        assert_eq!(
            reasons(validate_login(Some(&entry(65534, "/bin/bash", true)), &shells(), &[], None)),
            ["UID 60000 and above is not allowed"]
        );
        assert_eq!(
            reasons(validate_login(Some(&entry(60000, "/bin/bash", true)), &shells(), &[], None)),
            ["UID 60000 and above is not allowed"]
        );
        assert_eq!(
            reasons(validate_login(Some(&entry(1001, "/bin/bash", true)), &shells(), &[], Some(1000))),
            ["UID does not match the linked account"]
        );
        assert_eq!(
            reasons(validate_login(Some(&entry(1000, "/bin/bash", true)), &shells(), &["sftp_sites".into()], None)),
            ["Site accounts (sftp_sites) are not allowed"]
        );
        for bad_shell in ["/usr/sbin/nologin", "/bin/false", "/bin/fish", ""] {
            assert_eq!(
                reasons(validate_login(Some(&entry(1000, bad_shell, true)), &shells(), &[], None)),
                ["Login shell is not valid"],
                "{bad_shell:?}"
            );
        }
        assert_eq!(
            reasons(validate_login(Some(&entry(1000, "/bin/bash", false)), &shells(), &[], None)),
            ["Home directory does not exist"]
        );
    }

    #[test]
    fn reasons_accumulate() {
        let r = reasons(validate_login(Some(&entry(0, "/usr/sbin/nologin", false)), &shells(), &["sftp_sites".into()], Some(1000)));
        assert_eq!(r.len(), 5, "{r:?}");
    }

    #[test]
    fn login_format() {
        for ok in ["bastien", "_svc", "a", "b-x_1", &"a".repeat(32)] {
            assert!(is_valid_login(ok), "{ok}");
        }
        for bad in ["", "Root", "1abc", "a b", "a$b", "a/b", "a@b", "-a", &"a".repeat(33), "bob:x"] {
            assert!(!is_valid_login(bad), "{bad}");
        }
    }

    #[test]
    fn systemd_run_line() {
        let unit = unit_name("bastien", 0xdead_beef);
        assert_eq!(unit, "dockpanel-uterm-bastien-deadbeef");
        let spec = UnitSpec { login: "bastien", uid: 1000, home: "/home/bastien", shell: "/bin/bash", unit: &unit };
        let a = systemd_run_args(&spec, &[ATTACH_PATH]);
        let has = |s: &str| a.iter().any(|x| x == s);
        for want in [
            "--quiet",
            "--collect",
            "--pty",
            "--uid=bastien",
            "--unit=dockpanel-uterm-bastien-deadbeef",
            "--slice=dockpanel-uterm.slice",
            "--working-directory=/home/bastien",
            "--setenv=HOME=/home/bastien",
            "--setenv=USER=bastien",
            "--setenv=LOGNAME=bastien",
            "--setenv=SHELL=/bin/bash",
            "--setenv=XDG_RUNTIME_DIR=/run/user/1000",
            "--setenv=TERM=xterm-256color",
            "--setenv=COLORTERM=truecolor",
            "--setenv=LANG=C.UTF-8",
            "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
        ] {
            assert!(has(want), "missing {want} in {a:?}");
        }
        let sep = a.iter().position(|x| x == "--").expect("separator");
        assert_eq!(&a[sep + 1..], [ATTACH_PATH]);
        // No privilege option that would bring NoNewPrivileges back.
        assert!(!a.iter().any(|x| x.contains("NoNewPrivileges")));
    }

    #[test]
    fn dollars_in_the_command_are_escaped() {
        let spec = UnitSpec { login: "bob", uid: 1001, home: "/home/bob", shell: "/bin/sh", unit: "u" };
        let a = systemd_run_args(&spec, &["/bin/echo", "$HOME", "a$$b"]);
        let sep = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], ["/bin/echo", "$$HOME", "a$$$$b"]);
        assert_eq!(escape_dollar("$6$salt$hash"), "$$6$$salt$$hash");
    }

    #[test]
    fn unit_login_is_exact() {
        assert_eq!(unit_login("dockpanel-uterm-bob-0123abcd.service"), Some("bob"));
        assert_eq!(unit_login("dockpanel-uterm-bob-x-0123abcd.service"), Some("bob-x"));
        assert_eq!(unit_login("dockpanel-uterm-bob-x-0123abcd"), Some("bob-x"));
        assert_eq!(unit_login("dockpanel-uterm-bob-xyz.service"), None);
        assert_eq!(unit_login("dockpanel-tmux.service"), None);
        assert_eq!(unit_login("dockpanel-uterm--0123abcd.service"), None);
    }

    #[test]
    fn jti_is_single_use_and_purged() {
        let mut c = JtiCache::new(3);
        assert!(c.accept("a", 160, 100));
        assert!(!c.accept("a", 160, 101), "replay must be refused");
        assert!(c.accept("b", 160, 101));
        assert!(c.accept("c", 160, 101));
        assert!(!c.accept("d", 160, 101), "full cache fails closed");
        // After expiry the entries are purged: room again, and the old jti
        // is no longer remembered (its ticket is expired anyway).
        assert!(c.accept("d", 300, 161));
        assert_eq!(c.len(), 1);
        assert!(!c.accept("", 300, 161));
        assert!(!c.accept(&"x".repeat(129), 300, 161));
    }

    #[test]
    fn origin_check() {
        let ok = |o: &str, h: &str| origin_matches_host(Some(o), Some(h));
        assert!(ok("https://panel.example.com", "panel.example.com"));
        assert!(ok("https://Panel.Example.com", "panel.example.com"));
        assert!(ok("https://panel.example.com", "panel.example.com:443"));
        assert!(ok("https://203.0.113.5:8443", "203.0.113.5:8443"));
        assert!(ok("http://[::1]:8080", "[::1]:8080"));
        // Absent, other host, other port.
        assert!(!origin_matches_host(None, Some("panel.example.com")));
        assert!(!origin_matches_host(Some("https://panel.example.com"), None));
        assert!(!ok("https://evil.example.com", "panel.example.com"));
        assert!(!ok("https://panel.example.com.evil.net", "panel.example.com"));
        assert!(!ok("https://203.0.113.5:9443", "203.0.113.5:8443"));
        assert!(!ok("https://203.0.113.5:8443", "203.0.113.5"));
        assert!(!ok("http://panel.example.com", "panel.example.com:443"));
        assert!(!ok("null", "panel.example.com"));
        assert!(!ok("file:///etc/passwd", "panel.example.com"));
    }

    #[test]
    fn utf8_carry_for_a_split_emoji() {
        let emoji = "😀".as_bytes(); // 4 bytes
        for cut in 1..=3 {
            let mut d = Utf8Decoder::default();
            let mut first = b"ab".to_vec();
            first.extend_from_slice(&emoji[..cut]);
            let mut second = emoji[cut..].to_vec();
            second.extend_from_slice(b"cd");
            let a = d.decode(&first);
            let b = d.decode(&second);
            assert_eq!(a, "ab", "cut after {cut} byte(s)");
            assert_eq!(format!("{a}{b}"), "ab😀cd", "cut after {cut} byte(s)");
            assert_eq!(d.finish(), "");
        }
    }

    #[test]
    fn utf8_invalid_sequence_becomes_replacement() {
        let mut d = Utf8Decoder::default();
        assert_eq!(d.decode(b"a\xffb"), "a\u{FFFD}b");
        assert_eq!(d.decode(b"\xc3\x28"), "\u{FFFD}(");
        // A truncated sequence at the very end is flushed lossily.
        assert_eq!(d.decode(b"x\xe2\x82"), "x");
        assert_eq!(d.finish(), "\u{FFFD}");
    }

    /// Accepts at most 7 bytes per call, and says EAGAIN or EINTR now and then.
    struct Stingy {
        out: Vec<u8>,
        calls: usize,
        blocked: usize,
    }

    impl PtyWrite for Stingy {
        fn try_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls % 3 == 0 {
                self.blocked += 1;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            if self.calls % 5 == 0 {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(7);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    #[test]
    fn a_200_line_paste_is_written_whole() {
        let paste: String = (1..=200).map(|i| format!("line {i:03} {}\n", "x".repeat(i % 40))).collect();
        // Bracketed paste, cut into 16 KiB frames like the page does.
        let framed = format!("\x1b[200~{paste}\x1b[201~");
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let w = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut w = Stingy { out: Vec::new(), calls: 0, blocked: 0 };
                let mut waits = 0usize;
                for chunk in framed.as_bytes().chunks(16 * 1024) {
                    write_all_pty(&mut w, chunk, || {
                        waits += 1;
                        async { Ok(()) }
                    })
                    .await
                    .unwrap();
                }
                assert_eq!(waits, w.blocked, "every EAGAIN waits for writability");
                w
            })
            .await
            .expect("write_all_pty must not hang")
        });
        assert_eq!(w.out, framed.as_bytes());
        assert!(w.blocked > 0);
        assert_eq!(String::from_utf8(w.out).unwrap().lines().filter(|l| l.contains("line ")).count(), 200);
    }

    #[test]
    fn a_wait_error_aborts_the_write() {
        struct Never;
        impl PtyWrite for Never {
            fn try_write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let r = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                write_all_pty(&mut Never, b"abc", || async { Err(std::io::Error::other("closed")) }),
            )
            .await
        });
        assert!(r.expect("must not hang").is_err());
    }

    #[test]
    fn detach_gets_its_own_close_frame() {
        let f = close_frame(true, false).expect("a detach sends a close frame");
        assert_eq!(f.code, CLOSE_DETACHED);
        assert_eq!(f.reason.as_str(), "detached");
        assert!(close_frame(true, true).is_none(), "a kill is not a detach");
        assert!(close_frame(false, false).is_none(), "client close, timeout: plain close");
    }

    #[test]
    fn frames() {
        assert_eq!(parse_frame(r#"{"type":"input","data":"ls\r"}"#), Frame::Input("ls\r".into()));
        assert_eq!(parse_frame(r#"{"type":"resize","cols":120,"rows":40}"#), Frame::Resize(120, 40));
        assert_eq!(parse_frame(r#"{"type":"resize","cols":0,"rows":99999}"#), Frame::Resize(1, 1000));
        assert_eq!(parse_frame(r#"{"type":"ping"}"#), Frame::Ignore);
        assert_eq!(parse_frame("echo hi\r"), Frame::Input("echo hi\r".into()));
    }

    #[test]
    fn autostart_validation() {
        assert_eq!(validate_autostart(None), Ok(None));
        assert_eq!(validate_autostart(Some("claude")), Ok(Some("claude".into())));
        assert_eq!(validate_autostart(Some("  ")), Ok(None));
        assert!(validate_autostart(Some("claude\nrm -rf ~")).is_err());
        assert!(validate_autostart(Some("a\x1bb")).is_err());
        assert!(validate_autostart(Some(&"é".repeat(200))).is_ok());
        assert!(validate_autostart(Some(&"a".repeat(201))).is_err());
    }

    #[test]
    fn systemd_version_and_support() {
        assert_eq!(parse_systemd_version("systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT"), Some(255));
        assert_eq!(parse_systemd_version("systemd 247 (247.3-7)"), Some(247));
        assert_eq!(parse_systemd_version("garbage"), None);
        assert!(is_supported(Some("ubuntu"), Some("debian"), Some(255)));
        assert!(is_supported(Some("debian"), None, Some(252)));
        assert!(is_supported(Some("linuxmint"), Some("ubuntu debian"), Some(249)));
        assert!(!is_supported(Some("debian"), None, Some(247)));
        assert!(!is_supported(Some("rocky"), Some("rhel centos fedora"), Some(252)));
        assert!(!is_supported(Some("ubuntu"), None, None));
    }

    #[test]
    fn sudo_nopasswd_detection() {
        assert!(sudo_output_has_nopasswd("User bob may run:\n    (ALL) NOPASSWD: ALL\n"));
        assert!(!sudo_output_has_nopasswd("User bob may run:\n    (ALL : ALL) ALL\n"));
        assert!(!sudo_output_has_nopasswd(""));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dp-uterm-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn registry_is_idempotent() {
        let d = scratch("registry");
        let p = d.join("user-terminals.json");
        assert!(load_registry(&p).is_empty());
        add_to_registry(&p, "bob").unwrap();
        add_to_registry(&p, "alice").unwrap();
        add_to_registry(&p, "bob").unwrap();
        assert_eq!(load_registry(&p), ["alice", "bob"]);
        assert_eq!(parse_registry(r#"{"logins":["ok","Bad!",3]}"#), ["ok"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn audit_lines_round_trip_and_events_are_newest_first() {
        let line = audit_line("2026-11-16T10:00:00Z", "info", "user_terminal.attach", "a@b.c", "1.2.3.4", "login=bob\tunit=x\n");
        assert_eq!(line.matches('\t').count(), 5, "no field may add a column");
        let ev = parse_audit_line(&line).unwrap();
        assert_eq!(ev.event, "user_terminal.attach");
        assert_eq!(ev.details, "login=bob unit=x ");
        assert!(parse_audit_line("ts\tinfo\tterminal.start\ta\t-\tdomain=x").is_none());

        let d = scratch("audit");
        std::fs::write(
            d.join("audit-2026-11-15.log"),
            format!("{}\nts\tinfo\tterminal.start\ta\t-\td\n", audit_line("t1", "info", "user_terminal.session_created", "a", "-", "x")),
        )
        .unwrap();
        std::fs::write(
            d.join("audit-2026-11-16.log"),
            format!(
                "{}\n{}\n",
                audit_line("t2", "info", "user_terminal.attach", "a", "-", "x"),
                audit_line("t3", "info", "user_terminal.detach", "a", "-", "cause=closed")
            ),
        )
        .unwrap();
        std::fs::write(d.join("other.txt"), "t9\tinfo\tuser_terminal.attach\ta\t-\tx\n").unwrap();
        let all: Vec<String> = read_events(&d, 10).into_iter().map(|e| e.timestamp).collect();
        assert_eq!(all, ["t3", "t2", "t1"]);
        assert_eq!(read_events(&d, 2).len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn per_login_connection_limit() {
        let login = "limit-test-user";
        let guards: Vec<_> = (0..MAX_CONNECTIONS_PER_LOGIN)
            .map(|i| ConnGuard::reserve(login, &unit_name(login, i as u32)).expect("slot"))
            .collect();
        assert!(ConnGuard::reserve(login, "x").is_none(), "a fifth connection is refused");
        assert!(ConnGuard::reserve("other-login-test", "y").is_some(), "other logins are not affected");
        drop(guards);
        assert!(ConnGuard::reserve(login, "z").is_some(), "slots are released on drop");
    }

    /// Extract a heredoc body `<<'MARK'` … `MARK` from setup.sh.
    fn heredoc<'a>(script: &'a str, mark: &str) -> Option<String> {
        let open = format!("<<'{mark}'");
        let mut lines = script.lines();
        lines.find(|l| l.trim_end().ends_with(&open))?;
        let mut body = String::new();
        for l in lines {
            if l == mark {
                return Some(body);
            }
            body.push_str(l);
            body.push('\n');
        }
        None
    }

    /// A-6: setup.sh writes the very bytes the agent writes.
    #[test]
    fn setup_sh_writes_the_same_host_files() {
        let script = include_str!("../../../../scripts/setup.sh").replace('\r', "");
        for (mark, content, path) in [
            ("DP_UTERM_TMUX_CONF", TMUX_CONF, TMUX_CONF_PATH),
            ("DP_UTERM_TMUX_UNIT", TMUX_UNIT, TMUX_UNIT_PATH),
            ("DP_UTERM_ATTACH", UTERM_ATTACH, ATTACH_PATH),
            ("DP_UTERM_AUTOSTART", UTERM_AUTOSTART, AUTOSTART_SCRIPT_PATH),
        ] {
            let body = heredoc(&script, mark).unwrap_or_else(|| panic!("setup.sh has no heredoc {mark}"));
            assert_eq!(body, content, "setup.sh's {mark} differs from the agent's constant");
            assert!(script.contains(path), "setup.sh does not write {path}");
        }
        assert!(script.contains("pkg_install tmux"), "setup.sh must install tmux");
    }

    /// The unit and the scripts agree on the paths and the session name.
    #[test]
    fn host_files_are_consistent() {
        assert!(TMUX_UNIT.contains(&format!("-f {TMUX_CONF_PATH}")));
        assert!(TMUX_UNIT.contains(&format!("ExecStartPost={AUTOSTART_SCRIPT_PATH}")));
        assert!(TMUX_UNIT.contains(&format!("-s {SESSION_NAME} ")));
        assert!(UTERM_ATTACH.contains(&format!("attach -t {SESSION_NAME}")));
        assert!(UTERM_ATTACH.contains(TMUX_UNIT_NAME));
        assert!(UTERM_AUTOSTART.contains(AUTOSTART_DIR));
        assert!(TMUX_CONF.contains("set -g set-clipboard on"));
        assert!(TMUX_CONF.contains("set -g window-size latest"));
        for (p, _, _) in host_files() {
            assert!(!p.starts_with("/etc/dockpanel/"), "{p}: /etc/dockpanel is 0700, the user cannot read it");
        }
    }
}
