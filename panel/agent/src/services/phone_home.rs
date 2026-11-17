use crate::services::cpu_sampler::CpuSampler;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use std::time::Duration;

/// Configuration for phone-home mode (remote agent connecting to central API).
#[derive(Clone)]
pub struct PhoneHomeConfig {
    pub central_url: String,
    pub server_token: String,
    pub server_id: String,
    /// SHA-256 hex fingerprint of the agent's TLS cert. Sent in every checkin
    /// so the central panel can pin it (Trust On First Use). Populated by
    /// `main.rs` after loading the cert; `None` keeps backward compatibility
    /// with older panels that don't know about pinning.
    pub cert_fingerprint: Option<String>,
}

impl PhoneHomeConfig {
    /// Read from environment variables. Returns None if not configured.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("DOCKPANEL_CENTRAL_URL").ok()?;
        let token = std::env::var("DOCKPANEL_SERVER_TOKEN").ok()?;
        let id = std::env::var("DOCKPANEL_SERVER_ID").ok()?;

        if url.is_empty() || token.is_empty() || id.is_empty() {
            return None;
        }

        Some(Self {
            central_url: url.trim_end_matches('/').to_string(),
            server_token: token,
            server_id: id,
            cert_fingerprint: None,
        })
    }
}

/// Collect system info for checkin payload.
///
/// `cpu` supplies the CPU figure. This function used to build a `System::new_all()`
/// and read `global_cpu_usage()` off it, which reports the delta between the
/// constructor's refresh and `refresh_all()`'s - a window consisting almost
/// entirely of this function's own walk of `/proc`. Measured on an idle 12-core
/// box whose true usage was 4.5%, that pattern returned anywhere from 4.5% to
/// 22.1% across consecutive runs; on a single-core box the self-inflicted share
/// is twelve times larger. The value lands in `servers.cpu_usage`, which the
/// Servers page displays and the alert engine compares against CPU thresholds,
/// so a fabricated number there fires (or withholds) real alerts.
fn collect_system_info(cpu: &CpuSampler) -> serde_json::Value {
    // Only what the payload reads: the CPU list (for its length) and memory.
    // Refreshing processes here is what corrupted the CPU figure above, and
    // nothing in the payload needs them.
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(MemoryRefreshKind::everything()),
    );
    sys.refresh_memory();

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let root_disk = disks
        .iter()
        .find(|d| d.mount_point() == std::path::Path::new("/"));
    let disk_total_gb = root_disk
        .map(|d| (d.total_space() as f64 / 1_073_741_824.0).round() as i64)
        .unwrap_or(0);
    let (disk_used_gb, disk_usage_pct) = root_disk
        .map(|d| {
            let total = d.total_space();
            let used = total - d.available_space();
            (
                (used as f64 / 1_073_741_824.0).round() as i64,
                if total > 0 { (used as f32 / total as f32) * 100.0 } else { 0.0 },
            )
        })
        .unwrap_or((0, 0.0));

    serde_json::json!({
        "server_id": "",  // filled by caller
        "os_info": System::long_os_version().unwrap_or_default(),
        "hostname": System::host_name().unwrap_or_default(),
        "cpu_cores": sys.cpus().len(),
        "ram_mb": (sys.total_memory() / 1_048_576) as i64,
        "disk_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "disk_usage_pct": disk_usage_pct,
        "agent_version": env!("CARGO_PKG_VERSION"),
        // Live metrics
        "cpu_usage": cpu.usage(),
        "mem_used_mb": (sys.used_memory() / 1_048_576) as i64,
        "uptime_secs": System::uptime(),
        // Replay prevention: server rejects requests >120s old
        "timestamp": chrono::Utc::now().timestamp(),
    })
}

/// The single rule for the server token (shared with the release downloads,
/// `release_verify::panel_url_is_secure`): `https://`, or plain `http://` only
/// to the loopback (`127.0.0.1`, `::1`, `localhost`).
fn panel_url_is_secure(url: &str) -> bool {
    crate::services::release_verify::panel_url_is_secure(url)
}

/// The panel URL is plain http to a non-loopback host: nothing was sent.
#[derive(Debug, PartialEq, Eq)]
struct InsecurePanelUrl;

/// A client for the panel that never follows a redirect. reqwest keeps the
/// `Authorization` header across a redirect that stays on the same host and
/// port, so `https://panel:8443` answering with a redirect to
/// `http://panel:8443` would otherwise put the token on the wire in the clear,
/// after the URL check below had already passed. The panel answers these
/// endpoints itself; a redirect is never expected. Same client as the release
/// downloads.
fn panel_client() -> Result<reqwest::Client, String> {
    crate::services::release_verify::http_client().map_err(|e| e.to_string())
}

/// Every request this file makes with the server token goes through here. The
/// URL is checked BEFORE the credential is attached; an insecure one yields no
/// request at all (never a request without the token, which would still leak
/// the payload and fail anyway).
fn authed_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    server_token: &str,
) -> Result<reqwest::RequestBuilder, InsecurePanelUrl> {
    if !panel_url_is_secure(url) {
        return Err(InsecurePanelUrl);
    }
    Ok(client
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {server_token}")))
}

#[derive(Debug)]
enum CheckinError {
    /// Refused before any network activity.
    InsecureUrl,
    Http(reqwest::Error),
}

/// POST one check-in. Returns the panel's status, or why nothing was sent.
async fn checkin(
    client: &reqwest::Client,
    checkin_url: &str,
    server_token: &str,
    info: &serde_json::Value,
) -> Result<reqwest::StatusCode, CheckinError> {
    let req = authed_request(client, reqwest::Method::POST, checkin_url, server_token)
        .map_err(|_| CheckinError::InsecureUrl)?;
    let resp = req
        .json(info)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(CheckinError::Http)?;
    Ok(resp.status())
}

/// Run the phone-home loop: periodically POST system info to central API.
pub async fn run(config: PhoneHomeConfig, cpu: CpuSampler) {
    // Every request below carries the server token. Over plain http to another
    // host it would travel in the clear, so such a URL disables phone-home
    // entirely: the check is made once, here, so the refusal is logged once
    // per process instead of on every tick, and no loop is ever started.
    if !panel_url_is_secure(&config.central_url) {
        tracing::error!(
            "Phone-home DISABLED: DOCKPANEL_CENTRAL_URL ({}) is not https, and this agent never \
             sends its server token over plain http except to the loopback. Set an https:// \
             panel URL in the agent's environment and restart it.",
            config.central_url
        );
        return;
    }

    let client = match panel_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Phone-home disabled: could not build the HTTP client: {e}");
            return;
        }
    };

    tracing::info!(
        "Phone-home enabled: server_id={}, central={}",
        config.server_id,
        config.central_url
    );

    // Initial delay to let the agent fully start
    tokio::time::sleep(Duration::from_secs(5)).await;

    // There is no command poller here any more (s305). Every fleet member ran
    // one: it asked the panel for queued commands every five seconds and mapped
    // each to a local HTTP call. The panel could only ever queue ONE of the
    // eleven actions this side accepted, and that one named a route this agent
    // does not serve - so in the whole life of the feature no member could
    // execute anything, and the queue was empty everywhere. What it did carry
    // was a forwarder that pasted a caller-supplied string straight into a
    // request path against a loopback listener serving the WHOLE agent API.
    // Reconciling the two vocabularies - the obvious one-line "fix" - would have
    // switched that on rather than off. Per-host work goes through the panel's
    // own per-server resolver, which authenticates, checks ownership and calls
    // the agent's real route directly.

    // Spawn auto-update checker (every 6 hours)
    let update_config = config.clone();
    let update_client = client.clone();
    tokio::spawn(async move {
        auto_update_loop(update_config, update_client).await;
    });

    let checkin_url = format!("{}/api/agent/checkin", config.central_url);

    loop {
        let mut info = collect_system_info(&cpu);
        info["server_id"] = serde_json::json!(config.server_id);
        if let Some(fp) = &config.cert_fingerprint {
            info["cert_fingerprint"] = serde_json::json!(fp);
        }

        match checkin(&client, &checkin_url, &config.server_token, &info).await {
            Ok(status) if status.is_success() => tracing::debug!("Phone-home checkin OK"),
            Ok(status) => tracing::warn!("Phone-home checkin failed: HTTP {status}"),
            // Unreachable after the startup check above; kept so the loop can
            // never fall back to sending the token anyway.
            Err(CheckinError::InsecureUrl) => {
                tracing::error!("Phone-home checkin refused: the panel URL is not https");
                return;
            }
            Err(CheckinError::Http(e)) => tracing::warn!("Phone-home checkin error: {e}"),
        }

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Ask the panel every 6 hours whether this agent should move, and if so hand
/// the work to the SAME updater the panel-driven fleet path uses.
///
/// This loop used to download and swap the binary itself. It checksummed the
/// download (fail-closed, to its credit) but then: never verified the new binary
/// afterwards, wrote a `.bak` that nothing in the tree ever read back, staged
/// through `/tmp` so the rename was cross-device wherever `/tmp` is a tmpfs, and
/// restarted itself from inside its own cgroup. `scripts/agent-self-update.sh`
/// already does every one of those correctly, installs only a binary the agent
/// checked against the release's `checksums.txt` (`release_verify`), health-verifies the result, rolls back when it
/// does not come up, and is pinned by tests. So the timer goes through it, and
/// nothing in this file touches a binary any more (s233).
async fn auto_update_loop(config: PhoneHomeConfig, client: reqwest::Client) {
    let version_url = format!("{}/api/agent/version", config.central_url);
    let current_version = env!("CARGO_PKG_VERSION");

    // Wait an hour before the first check, so a box that has just been updated
    // is not immediately asked to move again.
    tokio::time::sleep(Duration::from_secs(3600)).await;

    loop {
        match fetch_target(&client, &version_url, &config.server_token).await {
            // Strictly newer only: an older or equal target is never installed
            // through this channel (going back is a reinstall by hand).
            Ok(Some(target))
                if crate::routes::panel_update::is_upgrade(&target, current_version) =>
            {
                // A failed update leaves this agent's version unchanged, so the
                // comparison above stays true for ever. Without this check, a
                // target that cannot come up on this box would make the timer
                // repeat the whole destructive sequence - download, swap,
                // restart, failed health poll, roll back, restart again -
                // indefinitely and unattended. Worse, the rollback restarts this
                // process, so the loop would resume at its INITIAL delay rather
                // than the 6-hour one, repeating roughly hourly on every box in
                // the fleet. An operator-driven fleet run is not blocked by this;
                // only the unattended path refuses.
                if let Some(why) =
                    crate::routes::panel_update::target_already_failed_destructively(&target)
                {
                    tracing::warn!(
                        "Agent auto-update: NOT retrying {target} - an earlier attempt already \
                         replaced this binary and had to roll back ({why}). Staying on \
                         {current_version}. Fix the release, or start a fleet update from the \
                         panel to override this."
                    );
                } else {
                    tracing::info!(
                        "Panel target is {target}, running {current_version} - starting self-update"
                    );
                    if let Err(e) =
                        crate::routes::panel_update::start_agent_self_update(&target).await
                    {
                        tracing::warn!("Agent self-update did not start: {e}");
                    }
                }
            }
            Ok(Some(target)) => {
                tracing::info!(
                    "Agent auto-update: panel target {target} is not newer than v{current_version}; nothing to do"
                );
            }
            Ok(None) => {
                tracing::info!("Agent auto-update: not enabled by the panel");
            }
            Err(e) => {
                tracing::warn!("Agent auto-update check failed: {e}");
            }
        }

        // Jitter. Unlike the panel-driven fleet path - which the orchestrator
        // serialises - every agent runs this timer independently, so a fleet
        // restarted together would otherwise check in together and then all pull
        // the release from the panel at the same moment.
        let jitter = rand::random::<u64>() % 1800;
        tokio::time::sleep(Duration::from_secs(6 * 3600 + jitter)).await;
    }
}

/// Ask the panel what version this agent should be running.
///
/// `Ok(None)` means "nothing to do": the panel returns a null target when the
/// operator has not enabled agent auto-update, or when the update channel is on
/// hold. That is how the OFF switch reaches a box - an agent is never trusted to
/// decide for itself that it should update.
///
/// **The status check before `.json()` is the entire point of this function.**
/// It used to be absent, and an error body is still valid JSON: a 401
/// deserialised cleanly, the missing version field fell back to the running
/// version, the two compared equal, and the loop reported "up to date" at debug
/// level - below the unit's own log level. A permanently dead auth path was
/// therefore indistinguishable in the journal from a healthy fleet, for four
/// releases (s233).
async fn fetch_target(
    client: &reqwest::Client,
    version_url: &str,
    server_token: &str,
) -> Result<Option<String>, String> {
    let resp = authed_request(client, reqwest::Method::GET, version_url, server_token)
        .map_err(|_| "the panel URL is not https; the token is not sent".to_string())?
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(body
        .get("target_version")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}


#[cfg(test)]
mod tests {
    /// The periodic update check must never swap a binary itself again.
    ///
    /// It used to: it downloaded the asset, hashed it, wrote a backup nothing
    /// ever read, and renamed over its own running executable - with no health
    /// check afterwards and no rollback. `scripts/agent-self-update.sh` does all
    /// of that correctly and is pinned by its own tests, so the only thing this
    /// file may do is ASK the panel and hand a version string to the shared
    /// launcher.
    ///
    /// The forbidden fragments are assembled rather than written out, because
    /// this test greps its own file (the source-pin prose trap).
    #[test]
    fn the_update_check_delegates_the_swap_and_never_performs_one() {
        let src = include_str!("phone_home.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for bad in [
            concat!("std::fs::", "rename"),
            concat!("current_", "exe()"),
            concat!("sha2::", "Sha256"),
            concat!("std::process::", "exit"),
        ] {
            assert!(
                !code.contains(bad),
                "the update check must not do its own binary swap, found: {bad}"
            );
        }

        // And it must go through the one shared, tested launcher.
        assert!(
            code.contains("start_agent_self_update("),
            "the check must hand the work to the shared launcher"
        );
        // The status of the version response has to be inspected before its body
        // is trusted: an error body is valid JSON, and reading it as a version
        // answer is what made a dead auth path look like a healthy fleet.
        assert!(
            code.contains("if !status.is_success()"),
            "a non-2xx must never be parsed as a version answer"
        );
        // The request must carry the agent's credential.
        assert!(
            code.contains("format!(\"Bearer {server_token}\")"),
            "the version query must authenticate"
        );
    }

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn https_remote_gets_the_token() {
        let client = panel_client().unwrap();
        for url in [
            "https://panel.example.com/api/agent/checkin",
            "https://panel.example.com:8443/api/agent/version",
        ] {
            let req = authed_request(&client, reqwest::Method::POST, url, "tok")
                .expect("https must be allowed")
                .build()
                .unwrap();
            assert_eq!(req.url().as_str(), url);
            assert_eq!(req.headers()[reqwest::header::AUTHORIZATION], "Bearer tok");
        }
    }

    #[test]
    fn http_remote_is_refused_before_any_request_exists() {
        let client = panel_client().unwrap();
        for url in [
            "http://panel.example.com/api/agent/checkin",
            "http://10.0.0.5:3080/api/agent/version",
            "http://127.0.0.2/api/agent/checkin",
            "http://localhost.example.com/api/agent/checkin",
            "ftp://panel.example.com/x",
            "",
        ] {
            assert_eq!(
                authed_request(&client, reqwest::Method::GET, url, "tok").err(),
                Some(InsecurePanelUrl),
                "{url}"
            );
        }
    }

    /// Unroutable host (TEST-NET-1): if a request were attempted, these would
    /// come back with a connect error after a timeout, not the refusal at once.
    #[tokio::test]
    async fn http_remote_checkin_and_version_poll_send_nothing() {
        let client = panel_client().unwrap();
        let info = serde_json::json!({"server_id": "s"});
        let t = std::time::Instant::now();
        let r = checkin(&client, "http://192.0.2.1/api/agent/checkin", "tok", &info).await;
        assert!(matches!(r, Err(CheckinError::InsecureUrl)), "{r:?}");
        let v = fetch_target(&client, "http://192.0.2.1/api/agent/version", "tok").await;
        assert!(v.unwrap_err().contains("not https"));
        assert!(t.elapsed() < Duration::from_secs(2), "nothing may hit the network");
    }

    /// Accept one connection on the loopback, return the raw request head,
    /// answer 200 with `body`.
    async fn one_shot_server(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read the head, then the whole body (Content-Length), so the
            // socket is never closed with unread data (which may reset it).
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "client closed before the end of the head");
                buf.extend_from_slice(&chunk[..n]);
            };
            let body_len = String::from_utf8_lossy(&buf[..head_end])
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + body_len {
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "client closed before the end of the body");
                buf.extend_from_slice(&chunk[..n]);
            }
            buf.truncate(head_end);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn http_loopback_checkin_is_sent_with_the_token() {
        let (base, server) = one_shot_server("{}").await;
        let client = panel_client().unwrap();
        let info = serde_json::json!({"server_id": "s"});
        let status = checkin(&client, &format!("{base}/api/agent/checkin"), "tok", &info)
            .await
            .expect("loopback http must be sent");
        assert!(status.is_success());
        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("post /api/agent/checkin "), "{head}");
        assert!(head.contains("authorization: bearer tok\r\n"), "{head}");
    }

    #[tokio::test]
    async fn http_loopback_version_poll_is_sent_with_the_token() {
        let (base, server) = one_shot_server(r#"{"target_version":"v9.9.9"}"#).await;
        let client = panel_client().unwrap();
        let target = fetch_target(&client, &format!("{base}/api/agent/version"), "tok")
            .await
            .expect("loopback http must be sent");
        assert_eq!(target.as_deref(), Some("v9.9.9"));
        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /api/agent/version "), "{head}");
        assert!(head.contains("authorization: bearer tok\r\n"), "{head}");
    }

    /// No request in this file may attach the token by hand: they all go
    /// through `authed_request`, which checks the URL first. And `run` refuses
    /// an insecure URL before it spawns either loop.
    #[test]
    fn the_token_is_attached_in_one_checked_place_only() {
        let src = include_str!("phone_home.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let prod = &code[..code.find(concat!("#[cfg(", "test)]")).unwrap()];
        assert_eq!(prod.matches(concat!("header(reqwest::header::", "AUTHORIZATION")).count(), 1);
        assert!(!prod.contains(concat!("\"Author", "ization\"")));
        assert!(!prod.contains(concat!("reqwest::Client::", "new()")));
        let run = &prod[prod.find("pub async fn run(").unwrap()..];
        let guard = run.find("if !panel_url_is_secure(&config.central_url)").unwrap();
        assert!(guard < run.find("tokio::spawn(").unwrap());
        assert!(guard < run.find("checkin(&client").unwrap());
    }
}
