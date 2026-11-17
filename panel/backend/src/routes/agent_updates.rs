//! What version should a remote agent be running?
//!
//! ## What this used to be, and why it never worked (s233, measured)
//!
//! This endpoint answered with three fields - `version`, `download_url` and
//! `checksum` - read from three `settings` rows. **Nothing in the repo ever
//! wrote those rows.** They were accepted by the admin settings allowlist and
//! by nothing else: no seed, no migration, no installer, no release step, no UI
//! field, no doc. So `download_url` was null on every install that has ever
//! existed, and the agent's updater refused with "No download URL provided".
//!
//! It also required `AuthUser` - a signed user JWT - from a caller that
//! structurally cannot hold one: an agent has a random hex token from its
//! `servers` row. So it 401'd on every request since v2.10.0. The mount comment
//! above the route in `routes/mod.rs` claimed the opposite ("uses Bearer token
//! from servers table"), which is a large part of why this survived review.
//!
//! And the failure was invisible: the agent read `.json()` without checking the
//! status, an error body is valid JSON, the missing `version` field fell back to
//! the agent's own version, and the loop concluded it was up to date.
//!
//! ## What it is now
//!
//! One field, `target_version`, and no download plumbing at all.
//! `scripts/agent-self-update.sh` derives the architecture, the asset URL and
//! the expected digest **on the box** from the release's own `checksums.txt` -
//! so `agent_download_url` and `agent_checksum` were never merely unwritten,
//! they were unnecessary. A single scalar URL could not have been correct for a
//! mixed amd64/arm64 fleet anyway.
//!
//! `null` means "do nothing", and is the answer whenever the operator has not
//! switched agent auto-update on, the update channel is on hold, updates are
//! not configured on this panel, or the calling agent is older than the
//! signed-release series. The switch is enforced HERE rather than on the
//! agent, because there is no panel→agent configuration push: an agent only
//! ever learns things by asking.
//!
//! ## Feature 10: agents download from this panel
//!
//! `GET /api/agent/release/{tag}/{name}` serves the release files an agent
//! needs (`checksums.txt`, its signature, the agent binaries) from this
//! panel's verified cache, fetching them from GitHub on demand. The GitHub
//! token stays here: an agent never sees it, and verifies the signature itself.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use uuid::Uuid;

use crate::auth::{agent_rate_limit, authenticate_agent};
use crate::error::{err_coded, internal_error, ApiError};
use crate::services::panel_update::{agent_can_verify_signed, agent_target_is_upgrade};
use crate::services::release_fetch::{self, FetchError};
use crate::services::update_source;
use crate::AppState;

/// GET /api/agent/version - the version the calling agent should be running.
///
/// Authenticated with the agent's own `servers`-table token.
pub async fn latest_version(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let server_id = authenticate_agent(&state, &headers).await?;
    agent_rate_limit(&state, server_id)?;

    let target = if update_source::load().configured {
        let agent_version: Option<String> =
            sqlx::query_scalar("SELECT agent_version FROM servers WHERE id = $1")
                .bind(server_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| internal_error("agent target", e))?
                .flatten();
        if agent_can_verify_signed(agent_version.as_deref()) {
            // Forward only: an agent already at or past the panel's release is
            // told nothing, never pointed back at an older one.
            resolve_agent_target(&state)
                .await?
                .filter(|t| agent_target_is_upgrade(agent_version.as_deref(), t))
        } else {
            None
        }
    } else {
        None
    };
    Ok(Json(serde_json::json!({ "target_version": target })))
}

// ── Release files for agents ─────────────────────────────────────────────

/// Resolve the `{tag}` of a release request and check it is offered: the
/// panel's own version (alias `current`), or the target of an unfinished
/// fleet run. Pure.
pub fn offered_tag(requested: &str, current: &str, unfinished_targets: &[String]) -> Option<String> {
    let panel_tag = release_fetch::release_tag(current);
    let tag = if requested == "current" {
        panel_tag.clone()
    } else if release_fetch::is_release_tag(requested) {
        requested.to_string()
    } else {
        return None;
    };
    let offered = tag == panel_tag
        || unfinished_targets
            .iter()
            .any(|t| release_fetch::release_tag(t) == tag);
    offered.then_some(tag)
}

pub fn agent_file_allowed(name: &str) -> bool {
    release_fetch::AGENT_RELEASE_FILES.contains(&name)
}

fn not_offered() -> ApiError {
    err_coded(
        StatusCode::FORBIDDEN,
        "This release is not offered to agents",
        "release_not_offered",
    )
}

/// GET /api/agent/release/{tag}/{name} - a verified release file, for an agent.
///
/// Authenticated with the agent's own `servers`-table token. Sends the file
/// from the verified cache (preparing it on demand), never a GitHub address
/// and never the GitHub token.
pub async fn release_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tag, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let server_id: Uuid = authenticate_agent(&state, &headers).await?;
    agent_rate_limit(&state, server_id)?;

    let unfinished: Vec<String> = sqlx::query_scalar(
        "SELECT target_version FROM fleet_update_runs WHERE finished_at IS NULL",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("agent release", e))?;
    let tag = offered_tag(&tag, env!("CARGO_PKG_VERSION"), &unfinished).ok_or_else(not_offered)?;
    if !agent_file_allowed(&name) {
        return Err(FetchError::FileUnknown.api_error());
    }

    let fetch = async {
        let p = release_fetch::prepare_full(&tag, &[]).await?;
        if !matches!(name.as_str(), release_fetch::CHECKSUMS_NAME | release_fetch::MINISIG_NAME) {
            if !p.manifest.contains(&name) {
                return Err(FetchError::FileUnknown);
            }
            release_fetch::prepare_full(&tag, &[name.as_str()]).await?;
        }
        Ok(p.dir.join(&name))
    };
    let path = match tokio::time::timeout(std::time::Duration::from_secs(300), fetch).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            e.log(&format!("Agent release {tag}/{name}"));
            return Err(e.api_error());
        }
        Err(_) => {
            let e = FetchError::DownloadFailed("agent release preparation timed out".into());
            e.log(&format!("Agent release {tag}/{name}"));
            return Err(e.api_error());
        }
    };

    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| FetchError::FileUnknown.api_error())?;
    let len = file
        .metadata()
        .await
        .map_err(|e| internal_error("agent release", e))?
        .len();
    let stream = futures::stream::unfold(file, |mut f| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(buf)), f))
            }
            Err(e) => Some((Err(e), f)),
        }
    });
    let mut resp = Response::new(Body::from_stream(stream));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&tag) {
        h.insert("x-release-tag", v);
    }
    Ok(resp)
}

/// `None` = the agent must not update itself.
///
/// The target is the release **this panel is running**, never "the newest tag on
/// GitHub": an agent should not get ahead of the panel that drives it, and the
/// release workflow builds the agent assets from the same tag, so the asset is
/// guaranteed to exist for a version the panel itself is on.
async fn resolve_agent_target(state: &AppState) -> Result<Option<String>, ApiError> {
    let setting = |key: &'static str| async move {
        sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await
            .map(|r| r.map(|v| v.0))
            .map_err(|e| internal_error("agent target", e))
    };

    // Opt-in, and off unless explicitly switched on. Seeded 'false'.
    if setting("agent_auto_update_enabled").await?.as_deref() != Some("true") {
        return Ok(None);
    }

    // `hold` is the operator saying "nothing moves". It has to win over the
    // auto-update switch, or the one control that stops a fleet mid-incident
    // would not actually stop it.
    if setting("update_channel").await?.as_deref() == Some("hold") {
        return Ok(None);
    }

    Ok(Some(format!("v{}", env!("CARGO_PKG_VERSION"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_get_the_panel_release_or_an_unfinished_fleet_target() {
        let cur = "3.0.0-rc.2";
        assert_eq!(offered_tag("current", cur, &[]).as_deref(), Some("v3.0.0-rc.2"));
        assert_eq!(offered_tag("v3.0.0-rc.2", cur, &[]).as_deref(), Some("v3.0.0-rc.2"));
        assert_eq!(offered_tag("v3.0.0-rc.5", cur, &[]), None);
        let runs = vec!["3.0.0-rc.5".to_string()];
        assert_eq!(offered_tag("v3.0.0-rc.5", cur, &runs).as_deref(), Some("v3.0.0-rc.5"));
        for bad in ["3.0.0-rc.2", "latest", "vv3.0.0-rc.2", "v3.0.0-rc.2/..", "..", ""] {
            assert_eq!(offered_tag(bad, cur, &runs), None, "{bad}");
        }
        let (status, body) = not_offered();
        assert_eq!(status.as_u16(), 403);
        assert_eq!(body.0["code"], "release_not_offered");
        assert_eq!(body.0["error"], "This release is not offered to agents");
    }

    #[test]
    fn agents_get_only_their_own_files() {
        for ok in [
            "checksums.txt",
            "checksums.txt.minisig",
            "cyberhunter-agent-linux-amd64",
            "cyberhunter-agent-linux-arm64",
        ] {
            assert!(agent_file_allowed(ok), "{ok}");
        }
        for no in [
            "cyberhunter-api-linux-amd64",
            "cyberhunter-source.tar.gz",
            "cyberhunter-frontend.tar.gz",
            "../checksums.txt",
            "update-token",
        ] {
            assert!(!agent_file_allowed(no), "{no}");
        }
        let (status, body) = FetchError::FileUnknown.api_error();
        assert_eq!(status.as_u16(), 404);
        assert_eq!(body.0["code"], "release_file_unknown");
    }

    /// The panel advertises its OWN crate version as the agent's target, so the
    /// two crates must ship the same version or the panel names a tag whose
    /// agent asset was never built. Nothing else in the tree enforces this -
    /// they were equal by convention only (s233).
    #[test]
    fn the_agent_and_api_crates_ship_the_same_version() {
        let ver = |toml: &str| {
            toml.lines()
                .find(|l| l.trim_start().starts_with("version"))
                .and_then(|l| l.split('"').nth(1))
                .map(str::to_string)
                .expect("no version in Cargo.toml")
        };
        let api = ver(include_str!("../../Cargo.toml"));
        let agent = ver(include_str!("../../../agent/Cargo.toml"));
        assert_eq!(
            api, agent,
            "dockpanel-api {api} would advertise v{api} as the agent target, \
             but dockpanel-agent is {agent} - that tag has no agent asset"
        );
    }

    /// The three retired keys must not come back: a reader with no writer
    /// anywhere is what made this endpoint answer null on every install that has
    /// ever existed.
    ///
    /// The key names are assembled rather than written out, because this test
    /// greps its own file and a literal would match itself - the source-pin
    /// prose trap, which caught this very test on its first run.
    #[test]
    fn the_dead_settings_keys_are_gone_from_the_reader_and_both_allowlists() {
        let here = include_str!("agent_updates.rs");
        let settings = include_str!("settings.rs");
        let keys = [
            concat!("agent_", "download_url"),
            concat!("agent_", "checksum"),
            concat!("agent_", "latest_version"),
        ];
        for key in keys {
            let quoted = format!("\"{key}\"");
            assert!(
                !settings.contains(&quoted),
                "{key} is still allowlisted in settings.rs - the update AND the \
                 import allowlist must both drop it"
            );
            // Prose may name them; code may not.
            for line in here.lines() {
                let l = line.trim_start();
                if l.starts_with("//") {
                    continue;
                }
                assert!(!l.contains(&quoted), "{key} is still read here: {l}");
            }
        }
    }
}
