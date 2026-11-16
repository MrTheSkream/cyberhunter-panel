//! ClamAV (feature 5): installation, clamd settings, state, and the clamd
//! socket client (`PING`, `VERSION`, `INSTREAM`).
//!
//! Debian/Ubuntu only. clamd is its own systemd service (`clamav-daemon`), so
//! its ~1.5 GB of signatures never count against the agent's `MemoryMax`.
//!
//! The socket protocol is spoken directly over `tokio::net::UnixStream`, with a
//! timeout on every operation: clamd stalls for 20-40 s while it reloads its
//! signatures (`ConcurrentDatabaseReload no`), and a scan must wait rather
//! than hang.
//!
//! Files under `/etc/clamav` and `/etc/rspamd` are written through
//! [`crate::services::apache::write_file`], which falls back to an unsandboxed
//! `install` when the directory did not exist at agent start (the unit's `-`
//! prefixed `ReadWritePaths` entry is then ignored until the next restart).

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use crate::services::migration_jobs::{self, JobHandle};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const CLAMD_CONF: &str = "/etc/clamav/clamd.conf";
/// clamd's socket on Ubuntu 24.04 when `LocalSocket` cannot be read.
pub const DEFAULT_SOCKET: &str = "/run/clamav/clamd.ctl";
pub const DB_DIR: &str = "/var/lib/clamav";
pub const UNIT: &str = "clamav-daemon";
pub const SOCKET_UNIT: &str = "clamav-daemon.socket";
pub const FRESHCLAM_UNIT: &str = "clamav-freshclam";
/// Drop-in that sets the socket mode when systemd socket activation owns it.
pub const SOCKET_DROPIN_DIR: &str = "/etc/systemd/system/clamav-daemon.socket.d";
pub const SOCKET_DROPIN: &str = "/etc/systemd/system/clamav-daemon.socket.d/cyberhunter.conf";
pub const RSPAMD_AV_CONF: &str = "/etc/rspamd/local.d/antivirus.conf";
pub const RSPAMD_LOCAL_D: &str = "/etc/rspamd/local.d";
pub const PACKAGES: &[&str] = &["clamav-daemon", "clamav-freshclam"];
pub const REMOVE_PACKAGES: &[&str] = &["clamav-daemon", "clamav-freshclam", "clamav"];
pub const UNSUPPORTED_MSG: &str = "Not supported on this server";

/// clamd settings the panel owns, replaced in place in `clamd.conf` (the
/// Debian file already carries most of these keys; appending would duplicate
/// them).
pub const SETTINGS: &[(&str, &str)] = &[
    ("MaxThreads", "2"),
    ("MaxFileSize", "25M"),
    ("MaxScanSize", "100M"),
    ("StreamMaxLength", "26M"),
    // Debian ships `EnableVersionCommand false` (clamav 1.5): without VERSION the
    // panel cannot show the signature version and date.
    ("EnableVersionCommand", "yes"),
    ("ConcurrentDatabaseReload", "no"),
    ("LocalSocketMode", "660"),
    ("LocalSocketGroup", "clamav"),
];

/// Refusal threshold. A "2 GB" VM reports about 1.9-1.95 GiB of `MemTotal`
/// (the kernel keeps its share), so the test is on 1.8 GB, not on 2 GiB.
pub const MIN_RAM_BYTES: u64 = 1_800_000_000;
/// Warning threshold, same tolerance for a "4 GB" box.
pub const WARN_RAM_BYTES: u64 = 3_600_000_000;
pub const RAM_REFUSAL: &str = "ClamAV needs at least 2 GB of RAM";
pub const RAM_WARNING: &str = "Less than 4 GB of RAM: ClamAV uses about 1.5 GB";

/// INSTREAM chunk size.
pub const CHUNK: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SIMPLE_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Reply to one file (at most 25 MB). Long enough for a big archive, short
/// enough that one stuck file cannot hold a scan for long: after it the scan
/// checks clamd with `PING` and moves on.
pub const SCAN_REPLY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REPLY: usize = 4096;
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(120);

// ── Errors shared by the antivirus modules ─────────────────────────────────

/// An error with the HTTP status the route must answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvErr {
    pub status: u16,
    pub msg: String,
    /// Machine-readable `code` of the JSON error, when the contract has one.
    pub code: Option<&'static str>,
}

impl AvErr {
    pub fn new(status: u16, msg: impl Into<String>) -> Self {
        Self { status, msg: msg.into(), code: None }
    }
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::new(400, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(404, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(409, msg)
    }
    pub fn precondition(msg: impl Into<String>) -> Self {
        Self::new(412, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(500, msg)
    }
}

// ── Pure helpers ────────────────────────────────────────────────────────────

/// `clamd.conf` with [`SETTINGS`] applied: the first active line of each key
/// is replaced in place, later duplicates are dropped, missing keys are
/// appended. Comments are left alone. Keys match case-insensitively.
pub fn apply_settings(conf: &str) -> String {
    let mut done = vec![false; SETTINGS.len()];
    let mut out: Vec<String> = Vec::new();
    for line in conf.lines() {
        let t = line.trim_start();
        let key = t.split_whitespace().next().unwrap_or("");
        let idx = if t.starts_with('#') || key.is_empty() {
            None
        } else {
            SETTINGS.iter().position(|(k, _)| k.eq_ignore_ascii_case(key))
        };
        match idx {
            Some(i) if done[i] => {}
            Some(i) => {
                done[i] = true;
                out.push(format!("{} {}", SETTINGS[i].0, SETTINGS[i].1));
            }
            None => out.push(line.to_string()),
        }
    }
    if done.iter().any(|d| !d) {
        out.push("# Set by CyberHunter - Panel".to_string());
        for (i, (k, v)) in SETTINGS.iter().enumerate() {
            if !done[i] {
                out.push(format!("{k} {v}"));
            }
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// `LocalSocket` of a `clamd.conf`, `/var/run` folded onto `/run`.
pub fn socket_from_conf(conf: &str) -> Option<String> {
    conf.lines().find_map(|l| {
        let t = l.trim();
        if t.starts_with('#') {
            return None;
        }
        let mut it = t.split_whitespace();
        let k = it.next()?;
        if !k.eq_ignore_ascii_case("LocalSocket") {
            return None;
        }
        let v = it.next()?;
        if !v.starts_with('/') {
            return None;
        }
        Some(match v.strip_prefix("/var/run/") {
            Some(rest) => format!("/run/{rest}"),
            None => v.to_string(),
        })
    })
}

/// The socket clamd listens on (from `clamd.conf`, else [`DEFAULT_SOCKET`]).
pub fn socket_path() -> String {
    std::fs::read_to_string(CLAMD_CONF)
        .ok()
        .and_then(|c| socket_from_conf(&c))
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string())
}

/// What `VERSION` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// `ClamAV 1.4.3`.
    pub engine: String,
    /// Signature database version, absent before the first download.
    pub signatures: Option<u64>,
    /// Database build time as printed by clamd (ctime, server local time).
    pub db_time: Option<chrono::NaiveDateTime>,
}

/// Parse `ClamAV 1.4.3/27450/Sat Nov 15 03:12:00 2026` (also `ClamAV 1.4.3`
/// alone, and ctime's double space before a single-digit day).
pub fn parse_version(s: &str) -> Option<VersionInfo> {
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    let mut parts = s.splitn(3, '/');
    let engine = parts.next()?.trim().to_string();
    if !engine.starts_with("ClamAV") {
        return None;
    }
    let signatures = parts.next().and_then(|v| v.trim().parse::<u64>().ok());
    let db_time = parts.next().and_then(|d| {
        // The weekday is dropped: chrono rejects one that does not match the
        // date, and it carries no information.
        let norm = d.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
        chrono::NaiveDateTime::parse_from_str(&norm, "%b %d %H:%M:%S %Y").ok()
    });
    Some(VersionInfo { engine, signatures, db_time })
}

/// Server local time (what clamd prints) to RFC 3339 UTC.
pub fn local_to_utc_rfc3339(t: chrono::NaiveDateTime) -> String {
    use chrono::TimeZone;
    let utc = chrono::Local
        .from_local_datetime(&t)
        .earliest()
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc.from_utc_datetime(&t));
    utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Result of one `INSTREAM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanReply {
    Clean,
    Found(String),
    Error(String),
}

/// `stream: OK`, `stream: <sig> FOUND`, `... ERROR`.
pub fn parse_scan_reply(raw: &str) -> ScanReply {
    let s = raw.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if let Some(head) = s.strip_suffix(" FOUND") {
        let sig = head.rsplit_once(": ").map(|(_, sig)| sig).unwrap_or(head);
        return ScanReply::Found(sig.trim().to_string());
    }
    if s.ends_with("ERROR") {
        return ScanReply::Error(s.to_string());
    }
    if s.ends_with(": OK") || s == "OK" {
        return ScanReply::Clean;
    }
    ScanReply::Error(format!("unexpected reply: {s}"))
}

/// The INSTREAM byte stream for `data`: the command, 4-byte big-endian
/// length-prefixed chunks of at most [`CHUNK`] bytes, a zero-length end.
pub fn instream_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = vec![b"zINSTREAM\0".to_vec()];
    for c in data.chunks(CHUNK) {
        let mut f = Vec::with_capacity(4 + c.len());
        f.extend_from_slice(&(c.len() as u32).to_be_bytes());
        f.extend_from_slice(c);
        frames.push(f);
    }
    frames.push(0u32.to_be_bytes().to_vec());
    frames
}

/// `MemTotal` of `/proc/meminfo`, in bytes.
pub fn parse_meminfo_total(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

pub fn total_ram_bytes() -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| parse_meminfo_total(&t))
}

/// `Err(refusal)` under [`MIN_RAM_BYTES`], `Ok(Some(warning))` under
/// [`WARN_RAM_BYTES`]. Unknown RAM is not a refusal.
pub fn ram_check(total: Option<u64>) -> Result<Option<&'static str>, &'static str> {
    match total {
        Some(t) if t < MIN_RAM_BYTES => Err(RAM_REFUSAL),
        Some(t) if t < WARN_RAM_BYTES => Ok(Some(RAM_WARNING)),
        _ => Ok(None),
    }
}

/// `systemctl show -p MemoryCurrent --value`: `[not set]`, `infinity` and
/// u64::MAX mean "no figure".
pub fn parse_memory_current(v: &str) -> Option<u64> {
    match v.trim().parse::<u64>() {
        Ok(n) if n != u64::MAX => Some(n),
        _ => None,
    }
}

/// How many of `main`, `daily`, `bytecode` (`.cvd` or `.cld`) are in `dir`.
pub fn db_files_present(dir: &Path) -> usize {
    ["main", "daily", "bytecode"]
        .iter()
        .filter(|b| {
            ["cvd", "cld"].iter().any(|ext| {
                std::fs::metadata(dir.join(format!("{b}.{ext}")))
                    .map(|m| m.is_file() && m.len() > 0)
                    .unwrap_or(false)
            })
        })
        .count()
}

/// `/etc/rspamd/local.d/antivirus.conf` (06-clamav.md §3).
pub fn render_rspamd_antivirus(socket: &str) -> String {
    format!(
        "# Managed by CyberHunter - Panel. Do not edit by hand.\n\
clamav {{\n  \
type = \"clamav\";\n  \
servers = \"{socket}\";\n  \
action = \"reject\";\n  \
scan_mime_parts = true;\n  \
max_size = 26214400;\n  \
symbol = \"CLAM_VIRUS\";\n  \
message = '${{SCANNER}}: virus found: \"${{VIRUS}}\"';\n\
}}\n"
    )
}

pub const SOCKET_DROPIN_BODY: &str =
    "# Managed by CyberHunter - Panel.\n[Socket]\nSocketMode=0660\nSocketGroup=clamav\n";

// ── clamd socket client ─────────────────────────────────────────────────────

async fn connect(sock: &Path) -> std::io::Result<UnixStream> {
    match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(sock)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect to clamd timed out")),
    }
}

async fn write_all_t(s: &mut UnixStream, buf: &[u8], t: Duration) -> std::io::Result<()> {
    match tokio::time::timeout(t, s.write_all(buf)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write to clamd timed out")),
    }
}

/// Read one reply: up to a NUL or EOF, bounded in size and time.
async fn read_reply(s: &mut UnixStream, t: Duration) -> std::io::Result<String> {
    let fut = async {
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(p) = buf[..n].iter().position(|b| *b == 0) {
                out.extend_from_slice(&buf[..p]);
                break;
            }
            out.extend_from_slice(&buf[..n]);
            if out.len() > MAX_REPLY {
                break;
            }
        }
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&out).into_owned())
    };
    match tokio::time::timeout(t, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "clamd reply timed out")),
    }
}

async fn simple_command(sock: &Path, cmd: &str) -> std::io::Result<String> {
    let mut s = connect(sock).await?;
    write_all_t(&mut s, format!("z{cmd}\0").as_bytes(), SIMPLE_TIMEOUT).await?;
    read_reply(&mut s, SIMPLE_TIMEOUT).await
}

/// `PING` answered `PONG` within 3 s.
pub async fn ping_at(sock: &Path) -> bool {
    matches!(simple_command(sock, "PING").await, Ok(r) if r.trim() == "PONG")
}

pub async fn ping() -> bool {
    ping_at(Path::new(&socket_path())).await
}

pub async fn version_at(sock: &Path) -> Option<VersionInfo> {
    simple_command(sock, "VERSION").await.ok().and_then(|r| parse_version(&r))
}

pub async fn version() -> Option<VersionInfo> {
    version_at(Path::new(&socket_path())).await
}

/// Send `data` through `INSTREAM`. An `Err` is a transport failure (clamd
/// down, reloading, timed out): the caller may retry. A clamd `ERROR` reply is
/// `Ok(ScanReply::Error)`.
pub async fn instream_at(sock: &Path, data: &[u8]) -> std::io::Result<ScanReply> {
    let mut s = connect(sock).await?;
    for frame in instream_frames(data) {
        write_all_t(&mut s, &frame, WRITE_TIMEOUT).await?;
    }
    let reply = read_reply(&mut s, SCAN_REPLY_TIMEOUT).await?;
    if reply.trim().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "clamd closed the connection"));
    }
    Ok(parse_scan_reply(&reply))
}

// ── System facts ────────────────────────────────────────────────────────────

pub async fn unsupported_reason() -> Option<String> {
    match crate::services::pkg::installer().await {
        Some(crate::services::pkg::Installer::AptGet) => None,
        _ => Some(UNSUPPORTED_MSG.to_string()),
    }
}

pub async fn is_installed() -> bool {
    crate::services::pkg::is_installed("clamav-daemon").await
}

pub async fn is_active(unit: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(10),
        safe_command("systemctl").args(["is-active", "--quiet", unit]).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success())
    .unwrap_or(false)
}

async fn systemctl(args: &[&str]) -> Result<(), String> {
    match tokio::time::timeout(SYSTEMCTL_TIMEOUT, safe_command("systemctl").args(args).output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(()),
        Ok(Ok(o)) => Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("systemctl {} could not run: {e}", args.join(" "))),
        Err(_) => Err(format!("systemctl {} timed out", args.join(" "))),
    }
}

async fn unit_exists(unit: &str) -> bool {
    match tokio::time::timeout(
        Duration::from_secs(10),
        safe_command("systemctl").args(["list-unit-files", unit, "--no-legend"]).output(),
    )
    .await
    {
        Ok(Ok(o)) => String::from_utf8_lossy(&o.stdout).split_whitespace().next() == Some(unit),
        _ => false,
    }
}

async fn memory_current() -> Option<u64> {
    let out = tokio::time::timeout(
        Duration::from_secs(10),
        safe_command("systemctl").args(["show", UNIT, "-p", "MemoryCurrent", "--value"]).output(),
    )
    .await
    .ok()?
    .ok()?;
    parse_memory_current(&String::from_utf8_lossy(&out.stdout))
}

/// Mail server installed by the panel (same evidence as `mail_status`'s
/// `configured`: Postfix plus the panel's main.cf marker).
pub async fn mail_installed() -> bool {
    crate::services::pkg::is_installed("postfix").await
        && std::fs::read_to_string("/etc/postfix/main.cf")
            .map(|c| c.contains("DockPanel mail configuration"))
            .unwrap_or(false)
}

pub async fn rspamd_installed() -> bool {
    crate::services::pkg::is_installed("rspamd").await
}

pub fn mail_enabled() -> bool {
    Path::new(RSPAMD_AV_CONF).exists()
}

// ── Install job bookkeeping ─────────────────────────────────────────────────

static INSTALL_JOB: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

fn running(job: &Option<String>) -> Option<String> {
    let id = job.as_ref()?;
    let state = migration_jobs::get(id)?;
    (state["state"] == "running").then(|| id.clone())
}

/// Id of the install job still running, if any.
pub fn current_install_job() -> Option<String> {
    let g = INSTALL_JOB.lock().unwrap_or_else(|p| p.into_inner());
    running(&g)
}

// ── A-1 status ──────────────────────────────────────────────────────────────

pub async fn status() -> serde_json::Value {
    let unsupported = unsupported_reason().await;
    let supported = unsupported.is_none();
    let installed = supported && is_installed().await;
    let is_running = installed && is_active(UNIT).await;
    let ver = if installed { version().await } else { None };
    let responding = ver.is_some() || (installed && ping().await);
    let memory = if is_running { memory_current().await } else { None };
    let signatures = ver.as_ref().and_then(|v| {
        v.signatures.map(|n| {
            serde_json::json!({
                "version": n,
                "updated_at": v.db_time.map(local_to_utc_rfc3339),
            })
        })
    });
    serde_json::json!({
        "supported": supported,
        "unsupported_reason": unsupported,
        "installed": installed,
        "running": is_running,
        "responding": responding,
        "version": ver.as_ref().map(|v| v.engine.clone()),
        "signatures": signatures,
        "memory_bytes": memory,
        "total_ram_bytes": total_ram_bytes(),
        "mail": {
            "enabled": mail_enabled(),
            "rspamd_installed": rspamd_installed().await,
            "mail_installed": mail_installed().await,
        },
        "install_job": current_install_job(),
    })
}

// ── A-2 install ─────────────────────────────────────────────────────────────

/// Checks, then starts the install job. Returns its id.
pub async fn start_install() -> Result<String, AvErr> {
    if unsupported_reason().await.is_some() {
        return Err(AvErr::precondition(UNSUPPORTED_MSG));
    }
    let warning = ram_check(total_ram_bytes()).map_err(AvErr::precondition)?;
    let mut g = INSTALL_JOB.lock().unwrap_or_else(|p| p.into_inner());
    if running(&g).is_some() {
        return Err(AvErr::conflict("A ClamAV installation is already running"));
    }
    let id = migration_jobs::spawn("clamav_install", "server", move |h| async move {
        if let Some(w) = warning {
            h.warn(w.to_string());
        }
        run_install(h).await
    });
    *g = Some(id.clone());
    Ok(id)
}

const SIGNATURE_WAIT: Duration = Duration::from_secs(15 * 60);
const PING_WAIT: Duration = Duration::from_secs(5 * 60);

async fn run_install(h: JobHandle) -> Result<serde_json::Value, String> {
    h.progress("packages", 0, 1, "Installing clamav-daemon and clamav-freshclam");
    crate::services::pkg::install(PACKAGES)
        .await
        .map_err(|e| format!("ClamAV install failed: {e}"))?;
    h.progress("packages", 1, 1, "Packages installed");

    // freshclam's own service downloads the first database and holds the
    // lock; running freshclam by hand would only fight it.
    let _ = systemctl(&["enable", FRESHCLAM_UNIT]).await;
    if !is_active(FRESHCLAM_UNIT).await {
        if let Err(e) = systemctl(&["start", FRESHCLAM_UNIT]).await {
            h.warn(e);
        }
    }
    let started = std::time::Instant::now();
    loop {
        let n = db_files_present(Path::new(DB_DIR));
        h.progress("signatures", n as u64, 3, "Waiting for the first signature download");
        if n >= 3 {
            break;
        }
        if started.elapsed() > SIGNATURE_WAIT {
            return Err(
                "The signature database was not downloaded within 15 minutes (check clamav-freshclam)".into(),
            );
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    h.progress("configure", 0, 1, "Writing clamd settings");
    let conf = std::fs::read_to_string(CLAMD_CONF).map_err(|e| format!("Cannot read {CLAMD_CONF}: {e}"))?;
    let new_conf = apply_settings(&conf);
    if new_conf != conf {
        crate::services::apache::write_file(CLAMD_CONF, &new_conf).await?;
    }
    let socket_unit = unit_exists(SOCKET_UNIT).await;
    if socket_unit {
        std::fs::create_dir_all(SOCKET_DROPIN_DIR)
            .and_then(|_| std::fs::write(SOCKET_DROPIN, SOCKET_DROPIN_BODY))
            .map_err(|e| format!("Cannot write {SOCKET_DROPIN}: {e}"))?;
        systemctl(&["daemon-reload"]).await?;
    }
    h.progress("configure", 1, 1, "clamd configured");

    h.progress("start", 0, 1, "Starting clamd");
    let _ = systemctl(&["enable", UNIT]).await;
    if socket_unit {
        // A socket unit cannot be restarted under an active service.
        let _ = systemctl(&["stop", UNIT]).await;
        if let Err(e) = systemctl(&["restart", SOCKET_UNIT]).await {
            h.warn(e);
        }
        systemctl(&["start", UNIT]).await?;
    } else {
        systemctl(&["restart", UNIT]).await?;
    }
    h.progress("start", 1, 1, "clamd started");

    let sock = socket_path();
    let started = std::time::Instant::now();
    loop {
        h.progress(
            "verify",
            started.elapsed().as_secs(),
            PING_WAIT.as_secs(),
            "Waiting for clamd to load its signatures",
        );
        if ping_at(Path::new(&sock)).await {
            break;
        }
        if started.elapsed() > PING_WAIT {
            return Err("clamd did not answer PING within 5 minutes after starting".into());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let v = version_at(Path::new(&sock)).await;
    let total = PING_WAIT.as_secs();
    h.progress("verify", total, total, "ClamAV is ready");
    Ok(serde_json::json!({
        "version": v.as_ref().map(|v| v.engine.clone()),
        "signatures_version": v.as_ref().and_then(|v| v.signatures),
    }))
}

// ── A-3 uninstall ───────────────────────────────────────────────────────────

pub async fn uninstall() -> Result<(), AvErr> {
    if unsupported_reason().await.is_some() {
        return Err(AvErr::precondition(UNSUPPORTED_MSG));
    }
    if current_install_job().is_some() {
        return Err(AvErr::conflict("A ClamAV installation is running"));
    }
    // Mail first: Rspamd must stop asking a clamd that is about to vanish.
    disable_mail_quiet().await.map_err(AvErr::internal)?;
    if Path::new(SOCKET_DROPIN).exists() {
        let _ = std::fs::remove_file(SOCKET_DROPIN);
        let _ = std::fs::remove_dir(SOCKET_DROPIN_DIR);
        let _ = systemctl(&["daemon-reload"]).await;
    }
    crate::services::pkg::remove(REMOVE_PACKAGES)
        .await
        .map_err(|e| AvErr::internal(format!("ClamAV removal failed: {e}")))?;
    // The quarantine (/var/lib/dockpanel/quarantine) is kept on purpose.
    Ok(())
}

// ── A-4 mail antivirus ──────────────────────────────────────────────────────

/// Rspamd's system user: `_rspamd` on Debian/Ubuntu, `rspamd` elsewhere.
async fn rspamd_user() -> Option<String> {
    for u in ["_rspamd", "rspamd"] {
        let ok = safe_command("getent")
            .args(["passwd", u])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(u.to_string());
        }
    }
    None
}

async fn in_group(user: &str, group: &str) -> bool {
    safe_command("id")
        .args(["-nG", user])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().any(|g| g == group))
        .unwrap_or(false)
}

/// Make sure `/etc/rspamd/local.d` exists (unsandboxed when /etc/rspamd was
/// created after the agent started).
async fn ensure_local_d() -> Result<(), String> {
    if Path::new(RSPAMD_LOCAL_D).is_dir() {
        return Ok(());
    }
    match std::fs::create_dir_all(RSPAMD_LOCAL_D) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(30) => {
            let out = safe_command_unsandboxed("install", &[])
                .args(["-d", "-m", "755", RSPAMD_LOCAL_D])
                .output()
                .await
                .map_err(|e| format!("Cannot create {RSPAMD_LOCAL_D}: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!("Cannot create {RSPAMD_LOCAL_D}: {}", String::from_utf8_lossy(&out.stderr).trim()))
            }
        }
        Err(e) => Err(format!("Cannot create {RSPAMD_LOCAL_D}: {e}")),
    }
}

async fn configtest() -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(60), safe_command("rspamadm").arg("configtest").output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(()),
        Ok(Ok(o)) => {
            let mut msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if msg.is_empty() {
                msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
            }
            msg.truncate(400);
            Err(msg)
        }
        Ok(Err(e)) => Err(format!("rspamadm could not run: {e}")),
        Err(_) => Err("rspamadm configtest timed out".into()),
    }
}

/// Removes the Rspamd file if present and reloads; no precondition (used by
/// uninstall).
async fn disable_mail_quiet() -> Result<(), String> {
    if !Path::new(RSPAMD_AV_CONF).exists() {
        return Ok(());
    }
    crate::services::apache::remove_file(RSPAMD_AV_CONF).await?;
    if let Err(e) = systemctl(&["reload", "rspamd"]).await {
        tracing::warn!("antivirus: {e}");
    }
    Ok(())
}

/// A-4. Returns whether mail scanning is now enabled.
pub async fn set_mail(enable: bool) -> Result<bool, AvErr> {
    if !mail_installed().await {
        return Err(AvErr::precondition("The mail server is not installed"));
    }
    if !rspamd_installed().await {
        return Err(AvErr::precondition("Rspamd is not installed (Mail > Spam Filter)"));
    }
    if !enable {
        disable_mail_quiet().await.map_err(AvErr::internal)?;
        return Ok(mail_enabled());
    }
    if !is_installed().await || !ping().await {
        return Err(AvErr::precondition("ClamAV is not responding"));
    }

    // Rspamd reads the socket as a member of the `clamav` group (mode 660).
    let mut restart = false;
    if let Some(user) = rspamd_user().await {
        if !in_group(&user, "clamav").await {
            let out = safe_command_unsandboxed("usermod", &[])
                .args(["-aG", "clamav", &user])
                .output()
                .await
                .map_err(|e| AvErr::internal(format!("usermod could not run: {e}")))?;
            if !out.status.success() {
                return Err(AvErr::internal(format!(
                    "Could not add {user} to the clamav group: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            restart = true;
        }
    } else {
        tracing::warn!("antivirus: no rspamd system user found, group membership not set");
    }

    ensure_local_d().await.map_err(AvErr::internal)?;
    let previous = std::fs::read_to_string(RSPAMD_AV_CONF).ok();
    let content = render_rspamd_antivirus(&socket_path());
    crate::services::apache::write_file(RSPAMD_AV_CONF, &content)
        .await
        .map_err(AvErr::internal)?;
    // A new group membership only reaches a restarted process.
    let action = if restart { "restart" } else { "reload" };
    let rollback = async {
        match &previous {
            Some(p) => crate::services::apache::write_file(RSPAMD_AV_CONF, p).await,
            None => crate::services::apache::remove_file(RSPAMD_AV_CONF).await,
        }
    };
    check_activate_or_rollback(configtest(), systemctl(&[action, "rspamd"]), rollback).await?;
    Ok(mail_enabled())
}

/// Runs `check`, then `activate`; when either fails, runs `rollback` (put the
/// previous file back, or remove it) and returns the error. Futures are lazy:
/// `activate` does nothing unless `check` passed, `rollback` unless one failed.
async fn check_activate_or_rollback(
    check: impl std::future::Future<Output = Result<(), String>>,
    activate: impl std::future::Future<Output = Result<(), String>>,
    rollback: impl std::future::Future<Output = Result<(), String>>,
) -> Result<(), AvErr> {
    let err = match check.await {
        Err(e) => format!("Rspamd rejected the antivirus configuration: {e}"),
        Ok(()) => match activate.await {
            Ok(()) => return Ok(()),
            Err(e) => e,
        },
    };
    if let Err(r) = rollback.await {
        tracing::error!("antivirus: rollback of {RSPAMD_AV_CONF} failed: {r}");
    }
    Err(AvErr::internal(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_CONF: &str = "#Automatically Generated by clamav-daemon postinst\n\
LocalSocket /var/run/clamav/clamd.ctl\n\
FixStaleSocket true\n\
LocalSocketGroup clamav\n\
LocalSocketMode 666\n\
# MaxThreads 50 is the default\n\
MaxThreads 12\n\
MaxFileSize 25M\n\
StreamMaxLength 25M\n\
maxthreads 4\n\
MaxScanSize 100M\n\
EnableVersionCommand false\n";

    #[test]
    fn settings_replace_in_place_drop_duplicates_and_append_missing() {
        let out = apply_settings(UBUNTU_CONF);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "LocalSocket /var/run/clamav/clamd.ctl");
        assert_eq!(lines[3], "LocalSocketGroup clamav");
        assert_eq!(lines[4], "LocalSocketMode 660");
        assert_eq!(lines[5], "# MaxThreads 50 is the default", "comments are kept");
        assert_eq!(lines[6], "MaxThreads 2");
        assert_eq!(lines[8], "StreamMaxLength 26M");
        assert_eq!(out.matches("MaxThreads 2").count(), 1);
        assert!(!out.to_lowercase().contains("maxthreads 4"), "duplicate dropped");
        assert!(out.ends_with("ConcurrentDatabaseReload no\n"), "missing key appended");
        assert!(out.contains("EnableVersionCommand yes") && !out.contains("EnableVersionCommand false"));
        for (k, v) in SETTINGS {
            let n = out.lines().filter(|l| !l.starts_with('#') && l.split_whitespace().next() == Some(k)).count();
            assert_eq!(n, 1, "{k} once");
            assert!(out.contains(&format!("{k} {v}")));
        }
        assert_eq!(apply_settings(&out), out, "idempotent");
    }

    #[test]
    fn socket_is_read_from_the_conf() {
        assert_eq!(socket_from_conf(UBUNTU_CONF).as_deref(), Some("/run/clamav/clamd.ctl"));
        assert_eq!(socket_from_conf("#LocalSocket /x\nLocalSocket /tmp/c.sock\n").as_deref(), Some("/tmp/c.sock"));
        assert_eq!(socket_from_conf("TCPSocket 3310\n"), None);
    }

    #[test]
    fn version_parsing() {
        let v = parse_version("ClamAV 1.4.3/27450/Sat Nov 15 03:12:00 2026\n").unwrap();
        assert_eq!(v.engine, "ClamAV 1.4.3");
        assert_eq!(v.signatures, Some(27450));
        assert_eq!(
            v.db_time,
            Some(chrono::NaiveDate::from_ymd_opt(2026, 11, 15).unwrap().and_hms_opt(3, 12, 0).unwrap())
        );
        let v = parse_version("ClamAV 1.4.3/27440/Wed Nov  5 09:01:02 2026\0").unwrap();
        assert_eq!(v.db_time.unwrap().format("%d %H").to_string(), "05 09");
        let v = parse_version("ClamAV 1.4.3").unwrap();
        assert_eq!((v.signatures, v.db_time), (None, None));
        assert!(parse_version("UNKNOWN COMMAND").is_none());
        assert!(local_to_utc_rfc3339(v_time()).ends_with('Z'));
    }

    fn v_time() -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 1, 2).unwrap().and_hms_opt(3, 4, 5).unwrap()
    }

    #[test]
    fn scan_replies() {
        assert_eq!(parse_scan_reply("stream: OK\0"), ScanReply::Clean);
        assert_eq!(
            parse_scan_reply("stream: Win.Test.EICAR_HDB-1 FOUND\0"),
            ScanReply::Found("Win.Test.EICAR_HDB-1".into())
        );
        assert!(matches!(parse_scan_reply("INSTREAM size limit exceeded. ERROR"), ScanReply::Error(_)));
        assert!(matches!(parse_scan_reply("garbage"), ScanReply::Error(_)));
    }

    #[test]
    fn instream_framing() {
        let data = vec![7u8; CHUNK + 10];
        let f = instream_frames(&data);
        assert_eq!(f[0], b"zINSTREAM\0");
        assert_eq!(&f[1][..4], &(CHUNK as u32).to_be_bytes());
        assert_eq!(f[1].len(), CHUNK + 4);
        assert_eq!(&f[2][..4], &10u32.to_be_bytes());
        assert_eq!(f[3], vec![0, 0, 0, 0]);
        assert_eq!(instream_frames(b"").len(), 2, "empty file: command + terminator");
    }

    /// A fake clamd: decodes the INSTREAM framing for real and answers FOUND
    /// when the payload contains "EICAR".
    #[tokio::test]
    async fn instream_against_a_fake_clamd() {
        let dir = std::path::PathBuf::from(format!("/tmp/dpav{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("c.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut sizes_seen = Vec::new();
            for _ in 0..3 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut cmd = Vec::new();
                loop {
                    let b = s.read_u8().await.unwrap();
                    if b == 0 {
                        break;
                    }
                    cmd.push(b);
                }
                if cmd == b"zPING" {
                    s.write_all(b"PONG\0").await.unwrap();
                    continue;
                }
                assert_eq!(cmd, b"zINSTREAM");
                let mut payload = Vec::new();
                loop {
                    let n = s.read_u32().await.unwrap() as usize;
                    if n == 0 {
                        break;
                    }
                    assert!(n <= CHUNK);
                    sizes_seen.push(n);
                    let mut buf = vec![0u8; n];
                    s.read_exact(&mut buf).await.unwrap();
                    payload.extend_from_slice(&buf);
                }
                let reply: &[u8] = if payload.windows(5).any(|w| w == b"EICAR") {
                    b"stream: Eicar-Test-Signature FOUND\0"
                } else {
                    b"stream: OK\0"
                };
                s.write_all(reply).await.unwrap();
            }
            sizes_seen
        });
        assert!(ping_at(&sock).await);
        let mut big = vec![b'a'; 3 * CHUNK + 1];
        big.extend_from_slice(b"EICAR");
        assert_eq!(instream_at(&sock, &big).await.unwrap(), ScanReply::Found("Eicar-Test-Signature".into()));
        assert_eq!(instream_at(&sock, b"hello").await.unwrap(), ScanReply::Clean);
        let sizes = server.await.unwrap();
        assert_eq!(sizes, vec![CHUNK, CHUNK, CHUNK, 6, 5]);
        // Nobody listening: a transport error, not a scan result.
        let _ = std::fs::remove_file(&sock);
        assert!(instream_at(&sock, b"x").await.is_err());
        assert!(!ping_at(&sock).await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ram_and_memory_parsing() {
        assert_eq!(parse_meminfo_total("MemTotal:        8130000 kB\nMemFree: 1 kB\n"), Some(8_325_120_000));
        // A "2 GB" VM (~1.94 GiB) is accepted with a warning.
        assert_eq!(ram_check(Some(2_030_000_000)), Ok(Some(RAM_WARNING)));
        assert_eq!(ram_check(Some(1_000_000_000)), Err(RAM_REFUSAL));
        assert_eq!(ram_check(Some(8_000_000_000)), Ok(None));
        assert_eq!(ram_check(None), Ok(None));
        assert_eq!(parse_memory_current("1450000000\n"), Some(1_450_000_000));
        assert_eq!(parse_memory_current("[not set]"), None);
        assert_eq!(parse_memory_current("18446744073709551615"), None);
        assert_eq!(parse_memory_current("infinity"), None);
    }

    #[test]
    fn db_files_detection() {
        let dir = std::env::temp_dir().join(format!("dp-clamdb-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(db_files_present(&dir), 0);
        std::fs::write(dir.join("main.cvd"), b"x").unwrap();
        std::fs::write(dir.join("daily.cld"), b"x").unwrap();
        std::fs::write(dir.join("bytecode.cvd"), b"").unwrap();
        assert_eq!(db_files_present(&dir), 2, "an empty file is not a database");
        std::fs::write(dir.join("bytecode.cvd"), b"x").unwrap();
        assert_eq!(db_files_present(&dir), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rspamd_activation_failure_rolls_back() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let rolled = AtomicU32::new(0);
        let activated = AtomicU32::new(0);
        let rb = || async {
            rolled.fetch_add(1, Ordering::SeqCst);
            Ok::<(), String>(())
        };
        let act = |r: Result<(), String>| async {
            activated.fetch_add(1, Ordering::SeqCst);
            r
        };
        // All good: no rollback.
        check_activate_or_rollback(async { Ok(()) }, act(Ok(())), rb()).await.unwrap();
        assert_eq!((activated.load(Ordering::SeqCst), rolled.load(Ordering::SeqCst)), (1, 0));
        // configtest fails: not activated, rolled back.
        let e = check_activate_or_rollback(async { Err("bad".into()) }, act(Ok(())), rb()).await.unwrap_err();
        assert_eq!((e.status, e.msg.as_str()), (500, "Rspamd rejected the antivirus configuration: bad"));
        assert_eq!((activated.load(Ordering::SeqCst), rolled.load(Ordering::SeqCst)), (1, 1));
        // reload fails after a good configtest: rolled back too, error kept.
        let e = check_activate_or_rollback(async { Ok(()) }, act(Err("systemctl reload rspamd failed: x".into())), rb())
            .await
            .unwrap_err();
        assert_eq!((e.status, e.msg.as_str()), (500, "systemctl reload rspamd failed: x"));
        assert_eq!((activated.load(Ordering::SeqCst), rolled.load(Ordering::SeqCst)), (2, 2));
    }

    #[test]
    fn rspamd_conf_rendering() {
        let c = render_rspamd_antivirus("/run/clamav/clamd.ctl");
        let expected_body = "clamav {\n  type = \"clamav\";\n  servers = \"/run/clamav/clamd.ctl\";\n  \
action = \"reject\";\n  scan_mime_parts = true;\n  max_size = 26214400;\n  symbol = \"CLAM_VIRUS\";\n  \
message = '${SCANNER}: virus found: \"${VIRUS}\"';\n}\n";
        assert!(c.ends_with(expected_body), "{c}");
        assert!(c.starts_with('#'));
    }
}
