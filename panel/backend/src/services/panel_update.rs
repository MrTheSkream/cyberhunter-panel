//! Phase 4 W4: panel self-update orchestrator.
//!
//! Lifts `scripts/update.sh`'s SSH-only flow into a panel-UI-driven action.
//! Does NOT reimplement the binary swap or rollback - those live in
//! `update.sh` (its binary-swap + `.bak` rollback path) and are battle-tested.
//! The orchestrator's job is:
//!
//!   1. Fetch and verify the release (signature, tag, SHA-256) into the
//!      release cache via [`super::release_fetch`]. Nothing else happens
//!      unless that passed.
//!   2. Create a persistent snapshot via [`super::panel_snapshot`].
//!   3. Shell out to the `update.sh` **of that verified release**, with
//!      `INSTALL_FROM_RELEASE=1`, `DOCKPANEL_VERSION=<tag>` and
//!      `CYBERHUNTER_RELEASE_DIR=<release dir>`: the script installs files that
//!      were already verified, and re-checks only their SHA-256.
//!   4. Track state in two places:
//!      - In-process `Arc<RwLock<UpdateState>>` for fast guards against
//!        concurrent applies within one process lifetime.
//!      - `panel_snapshots` rows in the DB for cross-restart truth (the
//!        api process dies mid-swap when update.sh restarts services).
//!   5. On the next process boot, [`finalize_pending_on_startup`] closes
//!      out any in-flight rows by writing `to_version =
//!      CARGO_PKG_VERSION`. Equal `from_version`/`to_version` ⇒ rollback
//!      happened.
//!
//! Out of scope here:
//!   - In-flight rollback is `update.sh`'s `.bak` restore - orchestrator
//!     doesn't touch it.
//!   - Operator-triggered rollback from a snapshot is
//!     [`rollback_to_snapshot`] - restores binaries + DB + /etc/dockpanel (never the update source)
//!     and bounces services. Routes/UI gate this behind a destructive
//!     confirm.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::PanelSnapshot;
use crate::services::panel_snapshot::{self, SnapshotTrigger};
use crate::services::release_fetch;
use crate::services::update_source::{self, Actor};

/// The oldest agent that fetches its release from this panel and checks it
/// against the release's `checksums.txt` itself. An older agent would fetch
/// its update from somewhere else on its own, so the fleet refuses it.
pub const MIN_PANEL_RELEASE_AGENT_VERSION: &str = "3.0.0-rc.1";

/// `true` when an agent reporting `version` fetches its release from this
/// panel. Unknown or unparseable versions do not.
pub fn agent_fetches_from_panel(version: Option<&str>) -> bool {
    match version.map(str::trim) {
        Some(v) if validate_target_version(v) => {
            crate::services::telemetry_collector::release_key(v.trim_start_matches('v'))
                >= crate::services::telemetry_collector::release_key(MIN_PANEL_RELEASE_AGENT_VERSION)
        }
        _ => false,
    }
}

/// `true` only when an agent reporting `agent_version` would move FORWARD to
/// `target`. Agents are never walked back (or re-sent the same release)
/// through the panel: going back is a reinstall by hand with install-agent.sh.
/// An unknown version is not an upgrade either.
pub fn agent_target_is_upgrade(agent_version: Option<&str>, target: &str) -> bool {
    use crate::services::telemetry_collector::release_key;
    match agent_version.map(str::trim) {
        Some(v) if validate_target_version(v) && validate_target_version(target.trim()) => {
            release_key(target.trim().trim_start_matches('v')) > release_key(v.trim_start_matches('v'))
        }
        _ => false,
    }
}

/// Whether a server belongs in a fleet plan for `target`: unknown or
/// unparseable versions stay in (the per-server refusal then names them),
/// a known version stays in only when `target` is newer.
pub fn fleet_plan_includes(agent_version: Option<&str>, target: &str) -> bool {
    match agent_version.map(str::trim) {
        Some(v) if validate_target_version(v) => agent_target_is_upgrade(Some(v), target),
        _ => true,
    }
}

/// The per-server refusal for an agent that is already at or past `target`.
pub fn non_upgrade_refusal(agent_version: Option<&str>, target: &str) -> Option<String> {
    if agent_target_is_upgrade(agent_version, target) {
        return None;
    }
    let running = match agent_version {
        Some(v) if !v.trim().is_empty() => format!("v{}", v.trim().trim_start_matches('v')),
        _ => "an unknown version".to_string(),
    };
    Some(format!(
        "This agent runs {running}; v{} is not newer, so it is not sent. To go back to an older \
         release, reinstall the agent with install-agent.sh.",
        target.trim().trim_start_matches('v')
    ))
}

/// The per-server refusal for an agent too old to fetch its release from
/// this panel.
pub fn legacy_agent_refusal(version: Option<&str>) -> Option<String> {
    if agent_fetches_from_panel(version) {
        return None;
    }
    let running = match version {
        Some(v) if !v.trim().is_empty() => format!("v{}", v.trim().trim_start_matches('v')),
        _ => "an unknown version".to_string(),
    };
    Some(format!(
        "This agent runs {running}, older than {MIN_PANEL_RELEASE_AGENT_VERSION}, and cannot \
         fetch its update from this panel. Reinstall it with install-agent.sh."
    ))
}

/// A snapshot row is considered "in flight" if it has `to_version IS NULL`
/// and was created within this window. Older rows that never finalized are
/// dead and don't block new applies.
///
/// Manual snapshots are excluded everywhere this predicate is used: they are
/// taken on demand and legitimately keep `to_version` NULL forever (see the
/// `panel_snapshots` migration), so treating them as unfinalized updates made
/// a safety snapshot look like an update in progress - and let the
/// abandoned-sweep below stamp them `to_version = 'abandoned'`, which
/// `current_state` then reported as a successful update to "abandoned".
const IN_FLIGHT_WINDOW_MIN: i64 = 15;

/// Maximum length of the captured `update.sh` stdout tail kept in memory
/// for the in-process state.
const LOG_TAIL_MAX: usize = 64;

/// Where `update.sh` records what actually happened.
///
/// This file is the ONLY honest channel for the local update path, and the
/// reason is structural: `update.sh` re-execs itself into a PID1-owned transient
/// unit with `exec systemd-run` and no `--wait`, so the child spawned below exits
/// **0 within milliseconds** - measured at ~29 ms against an update that ran
/// 54 s. That zero describes the handoff, never the work.
///
/// The agent side learned this at s232 and reads `last-agent-update.json`; the
/// restore path learned it at s231 and reads `last-restore.json`. The local
/// panel path was the sibling call site that never got it, so a run that failed
/// *before* the api was stopped left no trace anywhere the operator could see:
/// no restart came to carry a verdict, this process had already observed a
/// successful exit, and the UI sat on a frozen `last_log_line` until the
/// 15-minute in-flight window lapsed.
const PANEL_UPDATE_RESULT_PATH: &str = "/var/lib/dockpanel/last-panel-update.json";

/// How long to keep watching for `update.sh`'s verdict after the detached
/// handoff. Matches the `child.wait` budget: an update that has not reported
/// within 15 minutes is covered by the in-flight window and the boot-time
/// finalizer instead.
const RESULT_WATCH_SECS: u64 = 900;

/// The verdict `update.sh` left behind, if any. Permissive by construction -
/// a half-written or absent file must read as "no verdict", never as a failure.
pub async fn last_panel_update_result() -> Option<serde_json::Value> {
    let raw = tokio::fs::read_to_string(PANEL_UPDATE_RESULT_PATH).await.ok()?;
    serde_json::from_str(&raw).ok()
}

/// `Some(false)` only when the updater explicitly recorded a failure for a run
/// that finished at or after `since`.
///
/// The `since` bound is what stops a verdict from a *previous* update being read
/// as this one's: the file is overwritten in place, so without it every new run
/// would inherit the last one's outcome until it wrote its own.
async fn panel_update_verdict_since(since: DateTime<Utc>) -> Option<(bool, String, String)> {
    verdict_from_value(&last_panel_update_result().await?, since)
}

/// The parsing half, split out so it can be tested against the exact bytes
/// `update.sh` writes rather than against a hand-written approximation of them.
/// The two halves of this channel are in different languages and different
/// repositories of habit; a test that invents its own fixture pins the invention.
fn verdict_from_value(
    v: &serde_json::Value,
    since: DateTime<Utc>,
) -> Option<(bool, String, String)> {
    let finished = v.get("finished_at").and_then(|f| f.as_str())?;
    let finished: DateTime<Utc> = finished.parse().ok()?;
    // One second of slack: the file carries whole seconds, so a run that starts
    // and fails inside the same second would otherwise be discarded.
    if finished + chrono::Duration::seconds(1) < since {
        return None;
    }
    let ok = v.get("ok").and_then(|o| o.as_bool())?;
    let stage = v.get("stage").and_then(|s| s.as_str()).unwrap_or("unknown");
    let detail = v
        .get("detail")
        .and_then(|d| d.as_str())
        .unwrap_or("no detail recorded");
    Some((ok, stage.to_string(), detail.to_string()))
}

// ── State ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdateState {
    /// No update is currently running.
    Idle,
    /// `update.sh` is executing. The orchestrator may not survive long
    /// enough to transition out of this (the api binary swap will kill
    /// this process), so the DB row is the durable signal.
    InFlight {
        target_version: String,
        snapshot_id: Uuid,
        started_at: DateTime<Utc>,
        last_log_line: Option<String>,
    },
    /// Reconstructed at request-time from the snapshot row when the api
    /// reboots into the new version. `from_version != to_version`.
    Succeeded {
        from_version: String,
        to_version: String,
        completed_at: DateTime<Utc>,
    },
    /// `update.sh`'s in-flight `.bak` rollback fired and the api came back
    /// on the original binary. `from_version == to_version`.
    RolledBack {
        attempted_version: String,
        snapshot_id: Uuid,
        completed_at: DateTime<Utc>,
    },
    /// Orchestrator failed before `update.sh` could run (download, signature,
    /// checksum, snapshot error, missing script, etc.). `reason` is the
    /// contract message for a release failure, and `code` its stable code.
    Failed {
        reason: String,
        at: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
}

pub type UpdateStateHandle = Arc<RwLock<UpdateState>>;

pub fn new_state_handle() -> UpdateStateHandle {
    Arc::new(RwLock::new(UpdateState::Idle))
}

// ── Validation ───────────────────────────────────────────────────────────

/// Accepts `vX.Y.Z`, `X.Y.Z`, `vX.Y.Z-rc.N`, `X.Y.Z-rc.N`. No other shapes.
/// Hand-rolled instead of pulling in `regex` for one expression.
pub fn validate_target_version(v: &str) -> bool {
    let v = v.trim_start_matches('v');
    let (core, suffix) = match v.split_once('-') {
        Some((c, s)) => (c, Some(s)),
        None => (v, None),
    };

    let core_parts: Vec<&str> = core.split('.').collect();
    if core_parts.len() != 3 {
        return false;
    }
    for p in &core_parts {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }

    if let Some(s) = suffix {
        let Some(n) = s.strip_prefix("rc.") else {
            return false;
        };
        if n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum OrchestratorError {
    InvalidTargetVersion(String),
    AlreadyInFlight,
    ScriptMissing(String),
    Snapshot(panel_snapshot::SnapshotError),
    Spawn(std::io::Error),
    Db(sqlx::Error),
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrchestratorError::InvalidTargetVersion(v) => {
                write!(f, "invalid target version: {v}")
            }
            OrchestratorError::AlreadyInFlight => write!(
                f,
                "another update is already in flight (check /api/update/status)"
            ),
            OrchestratorError::ScriptMissing(p) => {
                write!(f, "update script not found at {p}")
            }
            OrchestratorError::Snapshot(e) => write!(f, "snapshot failed: {e}"),
            OrchestratorError::Spawn(e) => write!(f, "failed to spawn update.sh: {e}"),
            OrchestratorError::Db(e) => write!(f, "db error: {e}"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<panel_snapshot::SnapshotError> for OrchestratorError {
    fn from(e: panel_snapshot::SnapshotError) -> Self {
        OrchestratorError::Snapshot(e)
    }
}

impl From<sqlx::Error> for OrchestratorError {
    fn from(e: sqlx::Error) -> Self {
        OrchestratorError::Db(e)
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Resolve the current state. In-memory `Idle` may be a lie if a prior
/// process died mid-update; we cross-check the DB for an in-flight row
/// before returning Idle.
pub async fn current_state(handle: &UpdateStateHandle, pool: &PgPool) -> UpdateState {
    {
        let s = handle.read().await;
        if !matches!(*s, UpdateState::Idle) {
            return s.clone();
        }
    }

    // In-memory state says idle. Check DB for an unfinalized in-flight row.
    // Manual snapshots never carry a `to_version`, so they must be excluded or
    // taking a safety snapshot would masquerade as an update in progress.
    let cutoff = Utc::now() - chrono::Duration::minutes(IN_FLIGHT_WINDOW_MIN);
    if let Ok(Some(snap)) = sqlx::query_as::<_, PanelSnapshot>(
        "SELECT * FROM panel_snapshots \
         WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(cutoff)
    .fetch_optional(pool)
    .await
    {
        let target = parse_target_from_trigger(&snap.trigger).unwrap_or_default();
        return UpdateState::InFlight {
            target_version: target,
            snapshot_id: snap.id,
            started_at: snap.created_at,
            last_log_line: None,
        };
    }

    // Most recent finalized snapshot tells us if the last completed update
    // succeeded or rolled back (read-only summary for UI).
    if let Ok(Some(snap)) = sqlx::query_as::<_, PanelSnapshot>(
        "SELECT * FROM panel_snapshots \
         WHERE to_version IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    {
        let from = snap.from_version.clone();
        let to = snap.to_version.clone().unwrap_or_default();
        let attempted = parse_target_from_trigger(&snap.trigger).unwrap_or_else(|| to.clone());
        if to == from && attempted != from {
            return UpdateState::RolledBack {
                attempted_version: attempted,
                snapshot_id: snap.id,
                completed_at: snap.created_at,
            };
        }
        if to != from {
            // The row is stamped by whichever binary happened to boot after the
            // swap - which is ~30s BEFORE update.sh's health check decides
            // whether the new build is actually good. On a rollback the new api
            // starts, writes to_version = itself ("succeeded"), and only then
            // fails its health check and gets replaced by the old binary; the
            // row is already finalized, so nothing revisits it and the panel
            // reported a successful update to a version it is demonstrably not
            // running. Verified on a lab box: state=succeeded to_version=2.11.3
            // alongside current_version=2.11.2 in the SAME response.
            //
            // The running binary is ground truth, so correct the record at the
            // read site rather than trusting the stamp. No schema change, no new
            // state variant - this is what `RolledBack` already means.
            let running = env!("CARGO_PKG_VERSION");
            if to != running {
                return UpdateState::RolledBack {
                    attempted_version: to,
                    snapshot_id: snap.id,
                    completed_at: snap.created_at,
                };
            }
            return UpdateState::Succeeded {
                from_version: from,
                to_version: to,
                completed_at: snap.created_at,
            };
        }
    }

    UpdateState::Idle
}

/// `last_log_line` while the release is fetched and verified.
pub const PREPARING_LOG_LINE: &str = "Downloading and verifying release";

/// Start the panel-self-update flow.
///
/// Synchronous part, so the operator gets a real 4xx now:
///   1. validate `target_version`;
///   2. reserve the in-flight slot (in-process and DB).
///
/// Then everything slow runs in a background task, because the panel vhost
/// cuts `/api` at 300 s and a download plus the snapshot can exceed it:
///   3. fetch and verify the release (`release_fetch::prepare`); on failure the
///      state becomes `Failed { code }` and **no snapshot is taken**;
///   4. snapshot with trigger=pre-update:<target>;
///   5. spawn the `update.sh` of the verified release, detached (process group
///      of its own so SIGTERM to the api during the binary swap does not
///      propagate up), and stream its output into `last_log_line`.
///
/// Returns the reserved InFlight state; progress is observed via
/// `current_state` polling.
pub async fn start_panel_update(
    handle: UpdateStateHandle,
    pool: PgPool,
    target_version: String,
    operator: Option<String>,
    actor: Actor,
) -> Result<UpdateState, OrchestratorError> {
    let target_version = target_version.trim().to_string();
    if !validate_target_version(&target_version) {
        return Err(OrchestratorError::InvalidTargetVersion(target_version));
    }

    // Concurrent-apply guard (in-process + DB).
    //
    // TOCTOU fix (v2.216.0 audit): the guard used to be read-check-then-later-write,
    // with `create_snapshot`'s multi-minute pipeline (binary copy, pg_dump, tar,
    // sha256) running entirely inside the gap - two requests arriving within that
    // window (a double-click, a client retry, two admin sessions) both passed the
    // check and both spawned their own `create_snapshot` + detached `update.sh`.
    // Reserve InFlight atomically under ONE write-lock acquisition, before any
    // async work starts, so a second caller sees it immediately. The reservation
    // uses a nil snapshot_id until the real snapshot exists; on any failure
    // before update.sh runs the reservation is released (to `Failed`) so a
    // legitimate retry isn't locked out by this call's own failed attempt.
    let reserved_at = Utc::now();
    let reserved = UpdateState::InFlight {
        target_version: target_version.clone(),
        snapshot_id: Uuid::nil(),
        started_at: reserved_at,
        last_log_line: Some(PREPARING_LOG_LINE.to_string()),
    };
    {
        let mut s = handle.write().await;
        if matches!(*s, UpdateState::InFlight { .. }) {
            return Err(OrchestratorError::AlreadyInFlight);
        }
        *s = reserved.clone();
    }
    let cutoff = Utc::now() - chrono::Duration::minutes(IN_FLIGHT_WINDOW_MIN);
    // Same exclusion as `current_state`: a manual snapshot is not an update, so
    // it must not lock out the one thing an operator does right after taking it.
    let in_flight_count: Result<(i64,), sqlx::Error> = sqlx::query_as(
        "SELECT COUNT(*) FROM panel_snapshots \
         WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1",
    )
    .bind(cutoff)
    .fetch_one(&pool)
    .await;
    match in_flight_count {
        Ok((n,)) if n > 0 => {
            *handle.write().await = UpdateState::Idle;
            return Err(OrchestratorError::AlreadyInFlight);
        }
        Ok(_) => {}
        Err(e) => {
            *handle.write().await = UpdateState::Idle;
            return Err(OrchestratorError::Db(e));
        }
    }

    tokio::spawn(run_panel_update(
        handle,
        pool,
        target_version,
        operator,
        actor,
        reserved_at,
    ));
    Ok(reserved)
}

/// Record a failure that happened before `update.sh` ran: state, log, journal.
async fn fail_before_updater(
    handle: &UpdateStateHandle,
    pool: &PgPool,
    actor: &Actor,
    tag: &str,
    stage: &str,
    code: Option<&str>,
    reason: String,
) {
    tracing::error!("Panel update to {tag} failed at stage '{stage}': {reason}");
    *handle.write().await = UpdateState::Failed {
        reason: reason.clone(),
        at: Utc::now(),
        code: code.map(str::to_string),
    };
    update_source::audit(
        pool,
        actor,
        "update.apply_failed",
        Some(tag),
        apply_failed_details(tag, stage, code, &reason),
    )
    .await;
}

/// `details` of `update.apply_failed`.
pub fn apply_failed_details(
    tag: &str,
    stage: &str,
    code: Option<&str>,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "from_version": env!("CARGO_PKG_VERSION"),
        "to_version": tag.trim_start_matches('v'),
        "stage": stage,
        "code": code,
        "reason": reason,
    })
}

/// The background half of [`start_panel_update`].
async fn run_panel_update(
    handle: UpdateStateHandle,
    pool: PgPool,
    target_version: String,
    operator: Option<String>,
    actor: Actor,
    started_at: DateTime<Utc>,
) {
    let tag = release_fetch::release_tag(&target_version);

    // 3. Fetch and verify. Nothing below runs unless every file passed.
    let prepared = match release_fetch::panel_files() {
        Ok(files) => {
            let refs: Vec<&str> = files.iter().map(String::as_str).collect();
            match tokio::time::timeout(
                release_fetch::PREPARE_TIMEOUT,
                release_fetch::prepare(&tag, &refs),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(release_fetch::FetchError::DownloadFailed(
                    "release preparation timed out".into(),
                )),
            }
        }
        Err(e) => Err(e),
    };
    let release_dir = match prepared {
        Ok(dir) => dir,
        Err(e) => {
            e.log(&format!("Panel update to {tag}"));
            fail_before_updater(
                &handle,
                &pool,
                &actor,
                &tag,
                e.stage(),
                Some(e.code()),
                e.message().to_string(),
            )
            .await;
            return;
        }
    };
    release_fetch::cleanup_cache(&pool, false).await;

    let script = release_fetch::update_script_path(&release_dir);
    if !script.exists() {
        let e = OrchestratorError::ScriptMissing(script.display().to_string());
        fail_before_updater(&handle, &pool, &actor, &tag, "updater", None, e.to_string()).await;
        return;
    }

    // 4. Snapshot, only now that the release is known good.
    let meta = match panel_snapshot::create_snapshot(
        &pool,
        SnapshotTrigger::PreUpdate {
            target_version: target_version.clone(),
        },
        operator.clone(),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            let e = OrchestratorError::from(e);
            fail_before_updater(&handle, &pool, &actor, &tag, "updater", None, e.to_string()).await;
            return;
        }
    };

    *handle.write().await = UpdateState::InFlight {
        target_version: target_version.clone(),
        snapshot_id: meta.id,
        started_at,
        last_log_line: None,
    };

    // 5. Spawn the verified update.sh. Detached process group so systemctl
    // stop of dockpanel-api (issued by update.sh) doesn't propagate SIGTERM to
    // the script itself. PID1 reaps when complete.
    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .env("INSTALL_FROM_RELEASE", "1")
        // `vX.Y.Z`: the release tag, exactly the directory name below. The
        // poller stores the advertised version with the `v` stripped, so it is
        // re-added at this boundary (it was once passed bare, and every
        // self-update aborted before any binary was swapped).
        .env("DOCKPANEL_VERSION", &tag)
        .env("CYBERHUNTER_RELEASE_DIR", &release_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let reason = OrchestratorError::Spawn(e).to_string();
            finalize_failed_update(&pool, &handle, meta.id).await;
            fail_before_updater(&handle, &pool, &actor, &tag, "updater", None, reason).await;
            return;
        }
    };
    update_source::audit(
        &pool,
        &actor,
        "update.apply_started",
        Some(&tag),
        serde_json::json!({
            "from_version": env!("CARGO_PKG_VERSION"),
            "to_version": tag.trim_start_matches('v'),
            "snapshot_id": meta.id,
        }),
    )
    .await;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    stream_update_output(handle.clone(), stdout, stderr).await;
    // We may not reach here - update.sh kills the api midway. If we do, log
    // the exit status so the operator sees it in journals. A NON-zero exit
    // here is still real information: the script (or PID1) refused outright,
    // so nothing is running and the update definitively did not happen. A
    // ZERO exit means only that the work was handed off -
    // it is never "the work succeeded", because `exec systemd-run` without
    // `--wait` returns the moment PID1 accepts the job (lesson #49).
    let handed_off = match tokio::time::timeout(
        Duration::from_secs(RESULT_WATCH_SECS),
        child.wait(),
    )
    .await
    {
        Ok(Ok(status)) => {
            tracing::info!("update.sh (target {tag}) child exited with {status}");
            if status.success() {
                true
            } else {
                tracing::error!(
                    "update.sh (target {tag}) could not start ({status}) - \
                     panel left on the previous version"
                );
                false
            }
        }
        Ok(Err(e)) => {
            tracing::warn!("update.sh wait failed: {e}");
            false
        }
        Err(_) => {
            tracing::warn!("update.sh wait timed out after 15min");
            false
        }
    };

    // Ask the updater what happened, rather than the process that launched
    // it. If the update SUCCEEDS this loop never finishes: update.sh stops
    // dockpanel-api, which is the process running this task, and the next
    // boot's `finalize_pending_on_startup` closes the row. The case being
    // rescued is the opposite one - a failure BEFORE the api is stopped,
    // where no restart will ever come to close anything.
    let mut verdict = None;
    if handed_off {
        let deadline = std::time::Instant::now() + Duration::from_secs(RESULT_WATCH_SECS);
        while std::time::Instant::now() < deadline {
            if let Some(v) = panel_update_verdict_since(started_at).await {
                verdict = Some(v);
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    let failure = match &verdict {
        // Recorded success while this process is somehow still alive. Leave
        // the row alone: the restart is what proves a version change, and
        // `finalize_pending_on_startup` reads it from the running binary.
        Some((true, _, _)) => {
            tracing::info!("update.sh (target {tag}) recorded success; awaiting restart");
            None
        }
        Some((false, stage, detail)) => {
            tracing::error!("update.sh (target {tag}) FAILED at stage '{stage}': {detail}");
            Some(format!("update.sh failed at stage '{stage}': {detail}"))
        }
        // No verdict and no restart. Either PID1 refused the handoff, or the
        // updater died so hard it could not even write its own result file.
        // Both leave the panel on the version it started on, and both leave
        // a row that nothing else will ever close.
        None => {
            tracing::error!(
                "update.sh (target {tag}) left no verdict and this process \
                 was never restarted - treating the update as failed"
            );
            Some("update.sh left no verdict".to_string())
        }
    };
    if let Some(reason) = failure {
        finalize_failed_update(&pool, &handle, meta.id).await;
        update_source::audit(
            &pool,
            &actor,
            "update.apply_failed",
            Some(&tag),
            apply_failed_details(&tag, "updater", None, &reason),
        )
        .await;
    }
}

/// Close out an update that did not land: drop back to Idle and stamp the row
/// so it stops reading as in-flight.
///
/// Finalising `to_version` to the version we are STILL running is what
/// `current_state` already reads as "attempted <target>, still on <current>"
/// (`RolledBack`). Without it the operator was left staring at an in-flight
/// update until the 15-minute window lapsed, with the real error only in the
/// transient unit's journal.
async fn finalize_failed_update(
    pool: &PgPool,
    handle: &UpdateStateHandle,
    snapshot_id: Uuid,
) {
    *handle.write().await = UpdateState::Idle;
    let current = env!("CARGO_PKG_VERSION");
    if let Err(e) = sqlx::query(
        "UPDATE panel_snapshots SET to_version = $1 WHERE id = $2 AND to_version IS NULL",
    )
    .bind(current)
    .bind(snapshot_id)
    .execute(pool)
    .await
    {
        tracing::warn!("failed to finalize failed-update snapshot: {e}");
    }
}

/// Stream `update.sh` stdout + stderr into the handle's `last_log_line`.
/// This loop exits when both pipes hit EOF - typically because the api
/// process is being killed by `systemctl stop dockpanel-api`.
async fn stream_update_output(
    handle: UpdateStateHandle,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
) {
    let stdout_task = stdout.map(|s| {
        let h = handle.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(s).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if line.is_empty() {
                    continue;
                }
                update_last_log(&h, &line).await;
                tracing::info!(target: "panel_update", "{line}");
            }
        })
    });
    let stderr_task = stderr.map(|s| {
        let h = handle.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(s).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if line.is_empty() {
                    continue;
                }
                update_last_log(&h, &line).await;
                tracing::warn!(target: "panel_update", "{line}");
            }
        })
    });
    if let Some(t) = stdout_task {
        let _ = t.await;
    }
    if let Some(t) = stderr_task {
        let _ = t.await;
    }
}

async fn update_last_log(handle: &UpdateStateHandle, line: &str) {
    let truncated = if line.len() > LOG_TAIL_MAX * 4 {
        line.chars().take(LOG_TAIL_MAX * 4).collect::<String>()
    } else {
        line.to_string()
    };
    let mut s = handle.write().await;
    if let UpdateState::InFlight { last_log_line, .. } = &mut *s {
        *last_log_line = Some(truncated);
    }
}

fn parse_target_from_trigger(trigger: &str) -> Option<String> {
    trigger.strip_prefix("pre-update:").map(|s| s.to_string())
}

/// Operator-triggered rollback. Validates the snapshot, then hands the whole
/// restore - stop services, database, binaries, /etc, start services - to a
/// detached PID1-owned unit and returns.
///
/// It CANNOT be awaited. The first thing the restore does is stop the api
/// process this code is running in, so there is no "after" in which to observe
/// it from here; the outcome is read back from
/// [`panel_snapshot::last_restore_result`] once the panel is up again.
///
/// This shape is the fix, not an implementation detail. Until v2.11.5 the
/// restore ran INLINE in the request handler, which meant:
///   * it competed with the panel's own 300s HTTP timeout (`main.rs` TimeoutLayer
///     and nginx `proxy_read_timeout`) - a restore measured at 394.9s on a lab
///     box, so the future was dropped mid-flight;
///   * dropping it broke the `gunzip | psql` pipe, which psql read as a normal
///     end of input and exited 0 for, so the failure was recorded as a success;
///   * the database was left with 1 of 92 tables while the panel reported the
///     rollback had worked.
/// Both halves are now closed: the work is detached (so nothing cancels it) and
/// the database stage is atomic and verified (so it cannot half-apply).
pub async fn rollback_to_snapshot(
    handle: UpdateStateHandle,
    pool: PgPool,
    snapshot_id: Uuid,
    operator: Option<String>,
) -> Result<(), OrchestratorError> {
    // Concurrent-apply guard (v2.216.0 audit): rollback used to carry NO check
    // against an update already in flight, so `/api/update/rollback` could race
    // update.sh's binary swap against restore-snapshot.sh's binary swap on the
    // same files. Same reservation pattern as start_panel_update - held for the
    // duration of the restore, since a rollback in progress must equally block a
    // fresh apply.
    {
        let mut s = handle.write().await;
        if matches!(*s, UpdateState::InFlight { .. }) {
            return Err(OrchestratorError::AlreadyInFlight);
        }
        *s = UpdateState::InFlight {
            target_version: format!("rollback:{snapshot_id}"),
            snapshot_id,
            started_at: Utc::now(),
            last_log_line: None,
        };
    }
    // Everything cheap is validated synchronously so the operator gets a real
    // 4xx now rather than a 202 and a result file to go hunting for. The row,
    // the file on disk and its sha256 are all checked inside spawn_restore.
    let result = panel_snapshot::spawn_restore(&pool, snapshot_id, operator.as_deref()).await;
    if result.is_err() {
        // Validation failed before any file operation started (NotFound/FileMissing/
        // hash mismatch) - release the reservation. A restore that got past
        // validation and is genuinely running detached is expected to end the
        // process (binary swap) or resolve via finalize_pending_on_startup; this
        // early-failure branch is the only one still in-process to release from.
        *handle.write().await = UpdateState::Idle;
    }
    result?;
    Ok(())
}

/// At process startup, close out any in-flight snapshot rows by writing
/// `to_version = CARGO_PKG_VERSION`. Equal `from_version`/`to_version`
/// indicates an in-flight rollback by `update.sh`; differing values are a
/// successful apply.
pub async fn finalize_pending_on_startup(pool: &PgPool) {
    let cutoff = Utc::now() - chrono::Duration::minutes(IN_FLIGHT_WINDOW_MIN);
    let pending: Result<Vec<PanelSnapshot>, _> = sqlx::query_as(
        "SELECT * FROM panel_snapshots \
         WHERE to_version IS NULL AND trigger <> 'manual' AND created_at > $1 \
         ORDER BY created_at ASC",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await;

    let pending = match pending {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("finalize_pending: read failed: {e}");
            return;
        }
    };

    let current_version = env!("CARGO_PKG_VERSION").to_string();
    for snap in &pending {
        let result = sqlx::query("UPDATE panel_snapshots SET to_version = $1 WHERE id = $2")
            .bind(&current_version)
            .bind(snap.id)
            .execute(pool)
            .await;
        match result {
            Ok(_) => {
                let rolled_back = current_version == snap.from_version;
                if rolled_back {
                    tracing::warn!(
                        "Snapshot {} finalized as rolled-back (process restarted on \
                         pre-update version {})",
                        snap.id,
                        current_version
                    );
                } else {
                    tracing::info!(
                        "Snapshot {} finalized as succeeded ({} -> {})",
                        snap.id,
                        snap.from_version,
                        current_version
                    );
                }
                // The result is observed here, after the restart, with no
                // request behind it: journal it under the snapshot's operator.
                if let Some(target) = parse_target_from_trigger(&snap.trigger) {
                    let actor = Actor::System(
                        snap.operator.clone().unwrap_or_else(|| "system".to_string()),
                    );
                    let tag = release_fetch::release_tag(&target);
                    let (action, details) = if rolled_back {
                        let reason = last_panel_update_result()
                            .await
                            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
                            .unwrap_or_else(|| "the updater restored the previous version".into());
                        (
                            "update.rolled_back",
                            serde_json::json!({
                                "from_version": snap.from_version,
                                "attempted_version": tag.trim_start_matches('v'),
                                "reason": reason,
                            }),
                        )
                    } else {
                        (
                            "update.apply_succeeded",
                            serde_json::json!({
                                "from_version": snap.from_version,
                                "to_version": current_version,
                            }),
                        )
                    };
                    update_source::audit(pool, &actor, action, Some(&tag), details).await;
                }
            }
            Err(e) => {
                tracing::warn!("finalize_pending: row {} update failed: {e}", snap.id);
            }
        }
    }

    // A new binary stamps its row "succeeded" as soon as it boots, which is
    // before update.sh's health check: when that check then fails, update.sh
    // restores the old binary and this boot finds a recent row naming a
    // version it is not running. Restamp it (what `current_state` already
    // reports at read time) and journal the rollback; the restamp is what
    // keeps this from firing twice.
    if let Ok(stamped) = sqlx::query_as::<_, PanelSnapshot>(
        "SELECT * FROM panel_snapshots \
         WHERE trigger LIKE 'pre-update:%' AND to_version IS NOT NULL \
           AND to_version <> 'abandoned' AND from_version = $1 AND to_version <> $1 \
           AND created_at > $2",
    )
    .bind(&current_version)
    .bind(cutoff)
    .fetch_all(pool)
    .await
    {
        for snap in stamped {
            if sqlx::query("UPDATE panel_snapshots SET to_version = $1 WHERE id = $2")
                .bind(&current_version)
                .bind(snap.id)
                .execute(pool)
                .await
                .is_err()
            {
                continue;
            }
            let attempted = snap.to_version.clone().unwrap_or_default();
            tracing::warn!(
                "Snapshot {} re-finalized as rolled-back: {attempted} booted, then {current_version} was restored",
                snap.id
            );
            let reason = last_panel_update_result()
                .await
                .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
                .unwrap_or_else(|| "the updater restored the previous version".into());
            let actor = Actor::System(snap.operator.clone().unwrap_or_else(|| "system".to_string()));
            update_source::audit(
                pool,
                &actor,
                "update.rolled_back",
                Some(&release_fetch::release_tag(&attempted)),
                serde_json::json!({
                    "from_version": snap.from_version,
                    "attempted_version": attempted,
                    "reason": reason,
                }),
            )
            .await;
        }
    }

    // Mark older, abandoned in-flight rows with a sentinel so they don't
    // perpetually block /api/update/apply. Manual snapshots are exempt - they
    // are never in flight, and stamping one 'abandoned' made it the newest
    // finalized row, which `current_state` reads as a completed update from the
    // running version to a version literally called "abandoned".
    if let Err(e) = sqlx::query(
        "UPDATE panel_snapshots SET to_version = 'abandoned' \
         WHERE to_version IS NULL AND trigger <> 'manual' AND created_at <= $1",
    )
    .bind(cutoff)
    .execute(pool)
    .await
    {
        tracing::warn!("finalize_pending: abandoned-sweep failed: {e}");
    }
}

// ── Fleet (§4.5) ─────────────────────────────────────────────────────────
//
// Operator-initiated rolling update across the user's remote agents.
// Walks plan in order (oldest agent_version first; reachability gate
// excludes servers `last_seen_at > 5 min stale`), POSTs to each agent's
// `/panel/update`, polls `/panel/update/status` until terminal, records
// per-server progress in `fleet_update_runs.progress` JSONB. Halts on
// first failure unless `force_continue: true`.
//
// Per design memo §3.D5: `include_panel: false` default - fleet rolls
// first, panel itself last with a separate explicit click.

use serde::Deserialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPlanRow {
    pub server_id: Uuid,
    pub name: String,
    pub agent_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProgressRow {
    pub server_id: Uuid,
    pub status: String, // "pending" | "updating" | "succeeded" | "failed" | "skipped"
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
}

/// Build the ordered plan: oldest version first, ties broken by
/// `last_seen_at desc`. Skips servers staler than 5 minutes (the
/// reachability gate). Skips servers already at target_version.
///
/// `is_admin` widens `user_id = $1` to the whole fleet, mirroring
/// `routes/servers.rs::list`'s and `routes/dashboard.rs`'s own established
/// convention that `servers.user_id` names whoever registered the row, not a
/// tenant boundary - an admin (the only caller `apply_fleet` accepts) sees the
/// whole fleet. Without this (v2.216.0 audit finding), a fleet-wide update run
/// silently skipped every server a DIFFERENT admin had registered, with
/// nothing in the response indicating the plan was incomplete.
pub async fn build_fleet_plan(
    pool: &PgPool,
    user_id: Uuid,
    is_admin: bool,
    target_version: &str,
) -> Result<Vec<FleetPlanRow>, sqlx::Error> {
    let target_clean = target_version.trim_start_matches('v').to_string();
    // NOT ordered in SQL: `agent_version` is text, so postgres would sort it
    // lexicographically and put 2.9.0 AFTER 2.10.0 - i.e. it would roll the
    // newest box first and call it the oldest. Ordering happens below, on
    // parsed numeric components.
    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, agent_version FROM servers \
         WHERE ($2 OR user_id = $1) \
           AND last_seen_at > NOW() - INTERVAL '5 minutes' \
           AND is_local = false \
         ORDER BY last_seen_at DESC",
    )
    .bind(user_id)
    .bind(is_admin)
    .fetch_all(pool)
    .await?;

    let mut plan: Vec<FleetPlanRow> = rows
        .into_iter()
        // Already at the target, or past it: nothing to do, and never a
        // downgrade (`fleet_plan_includes`).
        .filter(|(_, _, v)| fleet_plan_includes(v.as_deref(), &target_clean))
        .map(|(server_id, name, agent_version)| FleetPlanRow {
            server_id,
            name,
            agent_version,
        })
        .collect();

    // Oldest first, unknown version first (a box that has never reported one is
    // the most suspect). `last_seen_at DESC` from the query is preserved within
    // a version by the stable sort.
    plan.sort_by_key(|r| semver_key(r.agent_version.as_deref()));
    Ok(plan)
}

/// Sortable numeric key for a `X.Y.Z` (optionally `v`-prefixed) version.
/// `None` sorts first. Anything unparseable sorts with whatever it parsed,
/// which keeps a malformed row from jumping to the end of the queue.
pub(crate) fn semver_key(v: Option<&str>) -> (u8, u64, u64, u64) {
    let Some(v) = v else {
        return (0, 0, 0, 0);
    };
    let core = v.trim_start_matches('v');
    let core = core.split('-').next().unwrap_or(core);
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        1,
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// Create a new fleet_update_runs row and return its id. The caller
/// then spawns a background task that walks the plan via
/// [`execute_fleet_plan`].
pub async fn create_fleet_run(
    pool: &PgPool,
    target_version: &str,
    plan: &[FleetPlanRow],
    halt_on_failure: bool,
    include_panel: bool,
    started_by: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let plan_json = serde_json::to_value(plan).unwrap_or(serde_json::json!([]));
    let initial_progress: Vec<FleetProgressRow> = plan
        .iter()
        .map(|p| FleetProgressRow {
            server_id: p.server_id,
            status: "pending".into(),
            duration_ms: None,
            error: None,
        })
        .collect();
    let progress_json = serde_json::to_value(&initial_progress).unwrap_or(serde_json::json!([]));

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO fleet_update_runs \
            (target_version, plan, progress, halt_on_failure, include_panel, started_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(target_version)
    .bind(plan_json)
    .bind(progress_json)
    .bind(halt_on_failure)
    .bind(include_panel)
    .bind(started_by)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Walk the plan, POST `/panel/update` to each agent, poll status until
/// terminal, record per-server progress. Writes terminal `outcome` field
/// on completion. Long-running - spawn as a tokio task.
#[allow(clippy::too_many_arguments)]
pub async fn execute_fleet_plan(
    pool: PgPool,
    agents: crate::services::agent::AgentRegistry,
    run_id: Uuid,
    plan: Vec<FleetPlanRow>,
    target_version: String,
    halt_on_failure: bool,
    include_panel: Option<UpdateStateHandle>,
    actor: Actor,
) {
    let mut progress: Vec<FleetProgressRow> = plan
        .iter()
        .map(|p| FleetProgressRow {
            server_id: p.server_id,
            status: "pending".into(),
            duration_ms: None,
            error: None,
        })
        .collect();

    let mut any_failed = false;
    let mut halted = false;

    for (idx, row) in plan.iter().enumerate() {
        if halted {
            progress[idx].status = "skipped".into();
            continue;
        }
        let started = std::time::Instant::now();
        progress[idx].status = "updating".into();
        let _ = persist_progress(&pool, run_id, &progress).await;

        let result = update_one_server(
            &agents,
            row.server_id,
            row.agent_version.as_deref(),
            &target_version,
        )
        .await;
        let elapsed_ms = started.elapsed().as_millis() as i64;
        progress[idx].duration_ms = Some(elapsed_ms);

        match result {
            Ok(()) => {
                progress[idx].status = "succeeded".into();
            }
            Err(e) => {
                progress[idx].status = "failed".into();
                progress[idx].error = Some(e.to_string());
                any_failed = true;
                if halt_on_failure {
                    halted = true;
                }
            }
        }
        let _ = persist_progress(&pool, run_id, &progress).await;
    }

    let outcome = if !any_failed {
        "success"
    } else if halted {
        "halted"
    } else {
        "partial"
    };

    let _ = sqlx::query(
        "UPDATE fleet_update_runs SET finished_at = NOW(), outcome = $1 WHERE id = $2",
    )
    .bind(outcome)
    .bind(run_id)
    .execute(&pool)
    .await;

    tracing::info!("Fleet update run {run_id} completed with outcome {outcome}");
    let tag = release_fetch::release_tag(&target_version);
    update_source::audit(
        &pool,
        &actor,
        "update.fleet_finished",
        Some(&tag),
        serde_json::json!({ "target_version": tag, "outcome": outcome }),
    )
    .await;

    // `include_panel` (design memo §3.D5: fleet rolls first, the panel itself
    // last) was stored on the run row and read by nothing - the operator's
    // checkbox has been inert since v2.10.0. Honour it now, and only when every
    // member actually made it: updating the panel on top of a half-rolled fleet
    // is the one ordering the design explicitly rules out.
    if let Some(handle) = include_panel {
        if any_failed {
            tracing::warn!(
                "Fleet run {run_id}: include_panel was requested but the fleet did not \
                 fully succeed ({outcome}) - leaving the panel on its current version"
            );
            return;
        }
        // The release was prepared for the agents already; the panel's own
        // preparation reuses that cache and fetches only its own files.
        let operator = Some(actor.email().to_string());
        match start_panel_update(handle, pool.clone(), target_version.clone(), operator, actor).await {
            Ok(_) => tracing::info!(
                "Fleet run {run_id}: fleet complete, panel self-update to {target_version} started"
            ),
            Err(e) => tracing::error!(
                "Fleet run {run_id}: fleet complete but the panel self-update could not start: {e}"
            ),
        }
    }
}

async fn persist_progress(
    pool: &PgPool,
    run_id: Uuid,
    progress: &[FleetProgressRow],
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_value(progress).unwrap_or(serde_json::json!([]));
    sqlx::query("UPDATE fleet_update_runs SET progress = $1 WHERE id = $2")
        .bind(json)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// POST `/panel/update` to a remote agent, then wait for the agent to actually
/// be RUNNING the target version. Returns Ok only on that observation.
///
/// It used to return Ok as soon as the agent's own `/panel/update/status` said
/// `"succeeded"`. That state is process-local and was being set from the exit
/// status of `systemd-run`, which returns 0 the instant PID1 accepts the job -
/// so on the s232 two-box lab the panel recorded a fleet member as **succeeded
/// in 5.1s** while that member never moved off 2.11.2 and its updater aborted a
/// second later. A restart is a step, not an outcome (lesson #49); the only
/// honest evidence that an update landed is the version the agent reports for
/// itself afterwards, which is what the W4 design §4.5 specified in the first
/// place ("Polls `/health` for the new version").
async fn update_one_server(
    agents: &crate::services::agent::AgentRegistry,
    server_id: Uuid,
    agent_version: Option<&str>,
    target_version: &str,
) -> Result<(), String> {
    let handle = agents
        .for_server(server_id)
        .await
        .map_err(|e| format!("agent handle: {e}"))?;

    // Normalise to the `vX.Y.Z` release-tag spelling at this boundary, exactly
    // as `start_panel_update` does for the local path. The operator's input is
    // free text and `validate_target_version` accepts both spellings, so a bare
    // `2.11.4` once reached the remote agent verbatim and became a release
    // address with no `v`, which does not exist - the update failed before
    // any swap. The local path was repaired in v2.11.3; this sibling call site
    // was missed. Release tags are always `v`-prefixed, so the prefix is
    // re-added here whatever the operator typed.
    let normalized = format!("v{}", target_version.trim_start_matches('v'));
    let payload = Some(serde_json::json!({ "target_version": normalized }));
    // An agent older than the 3.0.0-rc.1 series would not fetch its update
    // from this panel but from elsewhere, unverified: refuse it here,
    // before any request reaches it.
    if let Some(refusal) = legacy_agent_refusal(agent_version) {
        return Err(refusal);
    }
    // Forward only: the agent refuses a non-upgrade itself, and the panel does
    // not even ask.
    if let Some(refusal) = non_upgrade_refusal(agent_version, &normalized) {
        return Err(refusal);
    }
    if let Err(e) = handle.post("/panel/update", payload).await {
        let raw = e.to_string();
        // Agents before 2.11.8 could only run the PANEL updater, which is not
        // present on an agent-only box - so they refuse with this exact message
        // and there is nothing the panel can do about it remotely. Say what to
        // do instead of handing the operator a path that does not exist.
        if raw.contains("update script not found") {
            return Err(format!(
                "this agent is too old to be updated from the panel (it looks for the panel \
                 updater, which agent-only boxes do not have). Re-run install-agent.sh on it \
                 once to reach 2.11.8+, after which fleet updates work - original error: {raw}"
            ));
        }
        return Err(format!("POST /panel/update: {raw}"));
    }

    // Total budget ~10 min: the remote agent downloads a ~21MB binary, restarts,
    // and has to come back up.
    let target_clean = target_version.trim_start_matches('v').to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    let mut last_seen_version = String::new();

    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;

        // GROUND TRUTH first. `/health` is served by whichever binary is
        // actually running, so it cannot report a version that is not installed.
        // Connection errors are expected here - the agent restarts itself
        // partway through - and are never treated as failure.
        if let Ok(health) = handle.get("/health").await {
            if let Some(v) = health.get("version").and_then(|v| v.as_str()) {
                last_seen_version = v.to_string();
                if v.trim_start_matches('v') == target_clean {
                    return Ok(());
                }
            }
        }

        // Then the agent's own report, which is only trusted when it says
        // something went WRONG - a claim it can make honestly, unlike success.
        // (After the restart this also surfaces the updater's on-disk verdict,
        // which is the only record that survives the process that wrote it.)
        if let Ok(resp) = handle.get("/panel/update/status").await {
            let state = resp.get("state").and_then(|s| s.as_str()).unwrap_or("");
            if state == "failed" || state == "rolled_back" {
                return Err(format!(
                    "agent reported {state}: {}",
                    resp.get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unspecified")
                ));
            }
        }
    }

    Err(format!(
        "timed out after 10min - agent still reports version {}, wanted {target_clean}",
        if last_seen_version.is_empty() {
            "nothing".into()
        } else {
            last_seen_version
        }
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `update.sh` as it will actually be shipped. Read from the repo rather
    /// than embedded, because unlike the restore procedure this one is deployed
    /// as a file and invoked by path.
    const UPDATE_SH: &str = include_str!("../../../../scripts/update.sh");

    /// The verdict file has to exist on both ends or it is not a channel.
    ///
    /// `update.sh` re-execs into a transient unit with `exec systemd-run` and no
    /// `--wait`, so the child this service waits on exits 0 in milliseconds
    /// while the real update runs for minutes. An update that fails BEFORE the
    /// api is stopped therefore has no other way to report: no restart comes to
    /// carry a verdict, and the exit status belongs to systemd-run.
    #[test]
    fn the_updater_and_the_orchestrator_agree_on_where_the_verdict_lives() {
        assert!(
            UPDATE_SH.contains("last-panel-update.json"),
            "update.sh must record its outcome somewhere that outlives it"
        );
        assert!(
            PANEL_UPDATE_RESULT_PATH.ends_with("last-panel-update.json"),
            "the orchestrator must read the file update.sh writes"
        );
    }

    /// Every exit path, not just the ones someone remembered to instrument.
    /// A `set -e` abort, a SIGTERM and a failed curl all have to leave a verdict
    /// behind, which is what an EXIT trap is for.
    #[test]
    fn the_updater_writes_a_verdict_from_a_trap() {
        assert!(
            UPDATE_SH.contains("trap _dockpanel_on_exit EXIT"),
            "the verdict must be written from an EXIT trap, not only from the happy path"
        );
        assert!(
            UPDATE_SH.contains("_dockpanel_write_result true \"complete\""),
            "a successful update must record success"
        );
        assert!(
            UPDATE_SH.contains("_dockpanel_write_result false \"rollback\""),
            "an in-flight rollback must be distinguishable from a clean success"
        );
    }

    /// The detached unit must outlive the api it is about to stop.
    ///
    /// `--wait` would block systemd-run inside the very cgroup being killed, and
    /// `--pipe` (which implies `--wait`) would additionally wire the unit's
    /// stdout to a process about to die - so the updater would take SIGPIPE on
    /// its next log line, in the middle of the binary swap. Neither is the fix
    /// for reading the outcome; the result file is.
    ///
    /// Counts EXECUTABLE lines only. The script explains at length why it does
    /// not use these flags, and a negative pin that reads raw source fails the
    /// moment someone documents the thing it pins - the comment naming the trap
    /// would itself trip the assertion.
    #[test]
    fn the_updater_does_not_try_to_wait_on_its_own_detached_unit() {
        assert!(
            UPDATE_SH.contains("exec systemd-run"),
            "the updater must escape the api's control group"
        );
        let code: Vec<&str> = UPDATE_SH
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        for forbidden in ["--wait", "--pipe"] {
            let offender = code.iter().find(|l| l.contains(forbidden));
            assert!(
                offender.is_none(),
                "{forbidden} would tie the detached unit's life to the api being \
                 stopped: {}",
                offender.unwrap_or(&"")
            );
        }
    }

    /// A zero exit from the handoff must never be promoted to a success claim.
    /// This is lesson #49, and the agent side has carried the same pin since
    /// s232 - the local path is the sibling call site that had never got it.
    #[test]
    fn a_zero_exit_from_the_handoff_is_not_a_successful_update() {
        let src = include_str!("panel_update.rs");
        assert!(
            src.contains("never \"the work succeeded\""),
            "the reason a zero exit proves nothing must stay written down next to the code"
        );
        // The failure finalizer must be reachable from the verdict, not only
        // from the child's status - that is the whole defect.
        assert!(
            src.contains("panel_update_verdict_since"),
            "the outcome must be read from the updater's own record"
        );
    }

    /// Captured verbatim from a real `update.sh` run - a non-root invocation
    /// that aborted at the preflight check, so nothing hand-instrumented wrote
    /// it. Using the updater's own bytes is the point: the writer is shell and
    /// the reader is Rust, and a fixture invented on the Rust side would pin the
    /// invention rather than the contract.
    const REAL_VERDICT: &str = r#"{"target_version":"v2.47.4","ok":false,"stage":"preflight","detail":"update aborted at stage 'preflight' with exit code 1","finished_at":"2026-07-28T17:33:32Z"}"#;

    #[test]
    fn the_orchestrator_can_read_what_the_updater_actually_writes() {
        let v: serde_json::Value =
            serde_json::from_str(REAL_VERDICT).expect("update.sh must emit valid JSON");
        let before = "2026-07-28T17:30:00Z".parse::<DateTime<Utc>>().unwrap();
        let (ok, stage, detail) =
            verdict_from_value(&v, before).expect("a verdict from after the run must be read");
        assert!(!ok, "a failed update must read as failed");
        assert_eq!(stage, "preflight");
        assert!(detail.contains("exit code 1"), "the detail must survive: {detail}");
    }

    /// A verdict left by a PREVIOUS run must not be read as this one's. The file
    /// is overwritten in place, so without a lower bound every new update would
    /// inherit the last one's outcome until it wrote its own - and the outcome
    /// it would inherit is a FAILURE that finalises the row and drops the state
    /// back to Idle while the real update is still running.
    #[test]
    fn a_stale_verdict_is_not_attributed_to_a_new_run() {
        let v: serde_json::Value = serde_json::from_str(REAL_VERDICT).unwrap();
        let long_after = "2026-07-28T18:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert!(
            verdict_from_value(&v, long_after).is_none(),
            "a verdict finished before the run started is not this run's"
        );
    }

    /// Absent or half-written files must read as "no verdict yet", never as a
    /// failure - the orchestrator polls this while an update is in flight, and
    /// a torn read must not finalise a running update as failed.
    #[test]
    fn a_missing_or_torn_verdict_is_not_a_failure() {
        let since = Utc::now();
        for junk in [
            serde_json::json!({}),
            serde_json::json!({"ok": false}),
            serde_json::json!({"finished_at": "not-a-date", "ok": false}),
            serde_json::json!({"finished_at": "2026-07-28T17:33:32Z"}),
        ] {
            assert!(
                verdict_from_value(&junk, since).is_none(),
                "incomplete verdict must not read as a failure: {junk}"
            );
        }
    }

    #[test]
    fn target_version_regex_accepts_canonical_shapes() {
        assert!(validate_target_version("v2.10.0"));
        assert!(validate_target_version("2.10.0"));
        assert!(validate_target_version("v2.10.0-rc.1"));
        assert!(validate_target_version("2.10.0-rc.12"));
        assert!(validate_target_version("v10.20.30"));
    }

    #[test]
    fn target_version_regex_rejects_garbage() {
        assert!(!validate_target_version(""));
        assert!(!validate_target_version("v"));
        assert!(!validate_target_version("v2"));
        assert!(!validate_target_version("v2.10"));
        assert!(!validate_target_version("v2.10.0.1"));
        assert!(!validate_target_version("v2.10.0-alpha"));
        assert!(!validate_target_version("v2.10.0-rc"));
        assert!(!validate_target_version("v2.10.0-rc."));
        assert!(!validate_target_version("v2.10.0-rc.a"));
        assert!(!validate_target_version("v2.10.0 "));
        assert!(!validate_target_version("2.10.0; rm -rf /"));
        assert!(!validate_target_version("latest"));
    }

    #[test]
    fn parse_target_from_trigger_matches_pre_update() {
        assert_eq!(
            parse_target_from_trigger("pre-update:v2.10.0"),
            Some("v2.10.0".into())
        );
        assert_eq!(
            parse_target_from_trigger("pre-update:v2.10.0-rc.1"),
            Some("v2.10.0-rc.1".into())
        );
        assert_eq!(parse_target_from_trigger("manual"), None);
        let uuid = Uuid::new_v4();
        assert_eq!(
            parse_target_from_trigger(&format!("fleet:{uuid}")),
            None
        );
    }

    #[test]
    fn fleet_plan_orders_by_semver_not_lexicographically() {
        // The bug this replaces: postgres sorting `agent_version` as text puts
        // "2.9.0" AFTER "2.10.0", so the rolling update starts with the NEWEST
        // box while claiming to start with the oldest.
        let mut vs = vec![
            Some("2.10.0"),
            Some("v2.9.0"),
            None,
            Some("2.11.7"),
            Some("2.9.10"),
        ];
        vs.sort_by_key(|v| semver_key(*v));
        assert_eq!(
            vs,
            vec![
                None,
                Some("v2.9.0"),
                Some("2.9.10"),
                Some("2.10.0"),
                Some("2.11.7")
            ]
        );
    }

    #[test]
    fn semver_key_tolerates_junk_without_reordering_the_queue() {
        assert_eq!(semver_key(None), (0, 0, 0, 0));
        assert_eq!(semver_key(Some("v2.11.7-rc.3")), (1, 2, 11, 7));
        assert_eq!(semver_key(Some("garbage")), (1, 0, 0, 0));
        assert_eq!(semver_key(Some("2.11")), (1, 2, 11, 0));
    }

    /// `settings::recording_coverage` decides which fleet members will obey the
    /// terminal-recording toggle by comparing this key against the release that
    /// began honouring the signed `record` claim. Two edges matter and both are
    /// easy to get backwards: the release itself must count as covered, and a
    /// server that has never checked in (no version) must count as NOT covered -
    /// reporting an unverified member as covered is the exact claim the endpoint
    /// exists to stop the UI making.
    #[test]
    fn recording_gate_boundary_sorts_the_way_coverage_depends_on() {
        let gate = semver_key(Some("2.46.0"));

        assert!(semver_key(Some("2.45.1")) < gate, "an older agent is not covered");
        assert!(semver_key(Some("2.9.0")) < gate, "2.9 < 2.46 numerically, not lexicographically");
        assert!(semver_key(None) < gate, "a server that never checked in is not covered");
        assert!(semver_key(Some("unknown")) < gate, "an unparseable version is not covered");

        assert!(semver_key(Some("2.46.0")) >= gate, "the gate release itself is covered");
        assert!(semver_key(Some("2.46.1")) >= gate, "a newer patch is covered");
        assert!(semver_key(Some("v2.47.0")) >= gate, "a v-prefixed newer release is covered");
        assert!(semver_key(Some("2.100.0")) >= gate, "2.100 > 2.46 numerically");
    }

    /// The fleet orchestrator must decide "updated" from what the agent is
    /// RUNNING, not from what it says about itself - the agent's own state was
    /// being set from the exit status of the process that merely launched the
    /// update, and reported success 124ms in (lesson #49, measured s232).
    #[test]
    fn update_one_server_confirms_from_ground_truth() {
        let src = include_str!("panel_update.rs");
        let body = &src[src.find("async fn update_one_server").unwrap()..];
        let body = &body[..body.find("// ── Tests").unwrap_or(body.len())];
        assert!(
            body.contains("handle.get(\"/health\")"),
            "must read the version the agent is actually running"
        );
        let ok_at = body.find("return Ok(())").expect("no success path");
        let health_at = body.find("handle.get(\"/health\")").unwrap();
        assert!(
            health_at < ok_at,
            "the only success path must be downstream of the health probe"
        );
        // Negative control: the exact line that shipped.
        assert!(
            !body.contains("\"succeeded\" => return Ok(())"),
            "a self-reported state string is not evidence an update landed"
        );
    }

    #[test]
    fn only_agents_that_fetch_from_the_panel_are_updated() {
        assert!(agent_fetches_from_panel(Some("3.0.0-rc.1")));
        assert!(agent_fetches_from_panel(Some("v3.0.0-rc.2")));
        assert!(agent_fetches_from_panel(Some("3.0.0")));
        assert!(agent_fetches_from_panel(Some("3.1.4")));
        assert!(!agent_fetches_from_panel(Some("2.242.1")));
        assert!(!agent_fetches_from_panel(Some("3.0.0-beta")));
        assert!(!agent_fetches_from_panel(Some("garbage")));
        assert!(!agent_fetches_from_panel(Some("")));
        assert!(!agent_fetches_from_panel(None));

        assert_eq!(
            legacy_agent_refusal(Some("2.242.1")).unwrap(),
            "This agent runs v2.242.1, older than 3.0.0-rc.1, and cannot fetch its update \
             from this panel. Reinstall it with install-agent.sh."
        );
        assert!(legacy_agent_refusal(None).unwrap().contains("an unknown version"));
        assert!(legacy_agent_refusal(Some("3.0.0-rc.1")).is_none());
    }

    /// Agents only move forward through the panel: older or equal targets
    /// are neither planned, nor sent, nor advertised.
    #[test]
    fn agents_are_never_sent_backwards() {
        assert!(agent_target_is_upgrade(Some("3.0.0-rc.1"), "v3.0.0-rc.2"));
        assert!(agent_target_is_upgrade(Some("v3.0.0-rc.9"), "3.0.0"));
        assert!(!agent_target_is_upgrade(Some("3.0.0-rc.2"), "v3.0.0-rc.2"));
        assert!(!agent_target_is_upgrade(Some("3.0.0"), "v3.0.0-rc.5"));
        assert!(!agent_target_is_upgrade(Some("3.1.0"), "v3.0.9"));
        assert!(!agent_target_is_upgrade(None, "v3.0.0"));
        assert!(!agent_target_is_upgrade(Some("garbage"), "v3.0.0"));
        assert!(!agent_target_is_upgrade(Some("3.0.0"), "latest"));

        assert!(fleet_plan_includes(None, "3.0.0"));
        assert!(fleet_plan_includes(Some("garbage"), "3.0.0"));
        assert!(fleet_plan_includes(Some("2.242.1"), "3.0.0"));
        assert!(!fleet_plan_includes(Some("3.0.0"), "3.0.0"));
        assert!(!fleet_plan_includes(Some("v3.0.1"), "3.0.0"));

        let r = non_upgrade_refusal(Some("3.0.1"), "v3.0.0").unwrap();
        assert!(r.contains("v3.0.1") && r.contains("v3.0.0") && r.contains("install-agent.sh"), "{r}");
        assert!(non_upgrade_refusal(Some("3.0.0-rc.1"), "v3.0.0").is_none());

        let src = include_str!("panel_update.rs");
        let body = &src[src.find("async fn update_one_server").unwrap()..];
        let guard = body.find("non_upgrade_refusal(agent_version").unwrap();
        let post = body.find("handle.post(\"/panel/update\"").unwrap();
        assert!(guard < post, "the downgrade refusal must come before the request");
        let agents = include_str!("../routes/agent_updates.rs");
        assert!(agents.contains(".filter(|t| agent_target_is_upgrade(agent_version.as_deref(), t))"));
    }

    /// The refusal of a legacy agent must come before any request to it.
    #[test]
    fn a_legacy_agent_is_refused_before_the_update_request() {
        let src = include_str!("panel_update.rs");
        let body = &src[src.find("async fn update_one_server").unwrap()..];
        let refusal = body.find("legacy_agent_refusal(agent_version)").unwrap();
        let post = body.find("handle.post(\"/panel/update\"").unwrap();
        assert!(refusal < post);
    }

    #[test]
    fn a_failed_state_carries_its_code() {
        let s = UpdateState::Failed {
            reason: "Checksum check failed, nothing was installed".into(),
            at: Utc::now(),
            code: Some("checksum_failed".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["state"], "failed");
        assert_eq!(v["code"], "checksum_failed");
        let s = UpdateState::Failed { reason: "x".into(), at: Utc::now(), code: None };
        assert!(serde_json::to_value(&s).unwrap().get("code").is_none());
    }

    #[test]
    fn apply_failed_details_hold_no_url() {
        let d = apply_failed_details("v3.0.0-rc.2", "verify", Some("checksum_failed"), "Checksum check failed, nothing was installed");
        assert_eq!(d["to_version"], "3.0.0-rc.2");
        assert_eq!(d["stage"], "verify");
        assert!(!d.to_string().contains("https://"));
    }

    #[tokio::test]
    async fn idle_state_handle_starts_idle() {
        let handle = new_state_handle();
        let s = handle.read().await;
        assert!(matches!(*s, UpdateState::Idle));
    }
}
