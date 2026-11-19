//! Restore from an off-site disaster recovery snapshot (lot 2, steps 2.5, 2.6).
//!
//! Every route is admin-only.
//!
//! - `GET  /api/dr/remote-snapshots/{id}/download`  the `.tar.gz.age` as it is, streamed
//! - `POST /api/dr/remote-snapshots/{id}/restore`   `{identity}` -> 202 `{started, archive, install_id}`
//! - `GET  /api/dr/restore`                          progress, last verdict, vhost rebuild, rehydration
//! - `POST /api/dr/rehydrate`                        -> 202 `{started}`: sites and databases from remote backups
//!
//! The recovery key arrives in the body of the restore request (TLS), is held
//! in a `Zeroizing` string by the background task that decrypts the archive,
//! and is dropped (zeroed) with it. It is never stored, logged, put in argv or
//! in an environment variable; only fingerprints are logged.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::AdminUser;
use crate::error::{err, internal_error, ApiError};
use crate::services::dr_restore::{self as rs, PanelReporter, Progress};
use crate::services::agent::AgentHandle;
use crate::services::dr_snapshot as dr;
use crate::services::panel_update::UpdateState;
use crate::services::{activity, dr_post_restore, dr_rehydrate, panel_snapshot, security_hardening};
use crate::AppState;

/// A remote copy the panel can fetch: uploaded, not pruned, destination still there.
struct RemoteCopy {
    filename: String,
    sha256: String,
    size_bytes: i64,
    from_version: String,
    recipient_fingerprint: String,
    payload: serde_json::Value,
}

async fn remote_copy(state: &AppState, id: Uuid) -> Result<RemoteCopy, ApiError> {
    let row: Option<(String, String, i64, String, String, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT r.filename, r.sha256, r.size_bytes, r.from_version, r.recipient_fingerprint, d.dtype, d.config \
         FROM dr_remote_snapshots r LEFT JOIN backup_destinations d ON d.id = r.destination_id \
         WHERE r.id = $1 AND r.status = 'uploaded' AND r.deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("dr remote copy", e))?;
    let (filename, sha256, size_bytes, from_version, recipient_fingerprint, dtype, config) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "Remote snapshot not found, or no longer kept at its destination"))?;
    let (Some(dtype), Some(config)) = (dtype, config) else {
        return Err(err(StatusCode::CONFLICT, "The destination of this remote snapshot no longer exists"));
    };
    let (install_id, _) = rs::parse_archive_name(&filename)
        .ok_or_else(|| err(StatusCode::CONFLICT, "This row does not name an off-site snapshot archive"))?;
    let payload = dr::dr_destination_payload(
        &crate::routes::backup_destinations::agent_destination_payload(&dtype, &config),
        install_id,
    );
    Ok(RemoteCopy { filename, sha256, size_bytes, from_version, recipient_fingerprint, payload })
}

/// GET /api/dr/remote-snapshots/{id}/download - the encrypted archive, as it
/// is at the destination (it can only be opened with the recovery key).
pub async fn download_remote(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let copy = remote_copy(&state, id).await?;
    let target = format!("dl-{}-{}", Uuid::new_v4().simple(), copy.filename);
    let (path, size, sha) = rs::download(&AgentHandle::Local(state.agents.local().clone()), &copy.payload, &copy.filename, &target)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e))?;
    let file = tokio::fs::File::open(&path).await;
    // The open descriptor keeps the bytes; the inbox entry goes now, whatever happens.
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::warn!("Off-site snapshot download: could not remove {}: {e}", path.display());
    }
    let file = file.map_err(|e| internal_error("dr download open", e))?;
    if let Err(e) = rs::check_download(
        &dr::DrManifest {
            format: dr::DR_FORMAT,
            kind: "dr".into(),
            install_id: Uuid::nil(),
            from_version: copy.from_version.clone(),
            arch: String::new(),
            created_at: String::new(),
            snapshot_id: Uuid::nil(),
            archive: copy.filename.clone(),
            size_bytes: copy.size_bytes as u64,
            sha256: copy.sha256.clone(),
            recipient_fingerprint: copy.recipient_fingerprint.clone(),
        },
        size,
        &sha,
    ) {
        return Err(err(StatusCode::BAD_GATEWAY, &e));
    }

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dr.download", Some("dr"), Some(&copy.filename),
        None, ip.as_deref(), claims.key_id,
    )
    .await;
    security_hardening::audit_log(
        &state.db, "dr.download", Some(&claims.email), ip.as_deref(), Some("dr"), Some(&copy.filename),
        Some(&format!("{size} bytes, sha256 {sha}")), None, "warning", claims.key_id,
    )
    .await;

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
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", copy.filename)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

#[derive(Deserialize)]
pub struct RestoreInput {
    identity: String,
}

/// POST /api/dr/remote-snapshots/{id}/restore - download, verify, decrypt
/// and restore this off-site snapshot onto this machine (mode dr). The panel
/// stops and restarts; the card follows `GET /api/dr/restore`.
pub async fn restore_remote(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RestoreInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let key = Zeroizing::new(body.identity);
    let copy = remote_copy(&state, id).await?;
    let version = env!("CARGO_PKG_VERSION");
    if copy.from_version != version {
        return Err(err(
            StatusCode::CONFLICT,
            &format!(
                "This snapshot was taken by version {} and this panel runs {version}: install version {} first",
                copy.from_version, copy.from_version
            ),
        ));
    }
    rs::identity_matches(&key, &copy.recipient_fingerprint).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    if rs::progress().is_some_and(|p| !matches!(p.phase, "failed" | "handed_off")) {
        return Err(err(StatusCode::CONFLICT, "A restore from a remote snapshot is already in progress"));
    }
    {
        let mut s = state.panel_update_state.write().await;
        if matches!(*s, UpdateState::InFlight { .. }) {
            return Err(err(StatusCode::CONFLICT, "An update or a restore is already in progress"));
        }
        *s = UpdateState::InFlight {
            target_version: format!("dr-restore:{}", copy.filename),
            snapshot_id: id,
            started_at: Utc::now(),
            last_log_line: None,
        };
    }
    let now = Utc::now();
    rs::set_progress(Some(Progress {
        archive: copy.filename.clone(),
        snapshot_id: None,
        phase: "downloading",
        started_at: now,
        updated_at: now,
        error: None,
    }));

    let ip = crate::routes::client_ip(&headers);
    let details = format!("archive {} (key {})", copy.filename, copy.recipient_fingerprint);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dr.restore", Some("dr"), Some(&copy.filename),
        Some(&details), ip.as_deref(), claims.key_id,
    )
    .await;
    security_hardening::audit_log(
        &state.db, "dr.restore", Some(&claims.email), ip.as_deref(), Some("dr"), Some(&copy.filename),
        Some(&details), None, "critical", claims.key_id,
    )
    .await;
    // The fingerprint of the recovery key (checked against the archive's
    // recipient above), never the key.
    tracing::warn!(
        "Off-site restore of {} requested by {} (recovery key fingerprint {})",
        copy.filename,
        claims.email,
        copy.recipient_fingerprint
    );

    let (agents, handle, operator, archive) =
        (state.agents.clone(), state.panel_update_state.clone(), claims.email.clone(), copy.filename.clone());
    let payload = copy.payload;
    tokio::spawn(async move {
        let name = archive.clone();
        let result = async move {
            let prepared = rs::fetch_and_decrypt(&AgentHandle::Local(agents.local().clone()), &payload, &name, &key, &PanelReporter).await?;
            // Not needed any more: zeroed now rather than at the end of the task.
            drop(key);
            rs::set_progress(rs::progress().map(|mut p| {
                p.snapshot_id = Some(prepared.snapshot_id);
                p.phase = "starting";
                p.updated_at = Utc::now();
                p
            }));
            rs::launch(&prepared, Some(&operator)).await?;
            Ok::<Uuid, String>(prepared.snapshot_id)
        }
        .await;
        match result {
            Ok(snapshot_id) => {
                tracing::info!("Off-site restore of {archive} handed to restore-snapshot.sh (snapshot {snapshot_id})");
                rs::set_progress(rs::progress().map(|mut p| {
                    p.phase = "handed_off";
                    p.updated_at = Utc::now();
                    p
                }));
            }
            Err(e) => {
                tracing::error!("Off-site restore of {archive} failed before anything changed: {e}");
                rs::set_progress(rs::progress().map(|mut p| {
                    p.phase = "failed";
                    p.error = Some(e);
                    p.updated_at = Utc::now();
                    p
                }));
                *handle.write().await = UpdateState::Idle;
            }
        }
    });
    let install_id = rs::parse_archive_name(&copy.filename).map(|(id, _)| id.to_string());
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "started": true, "archive": copy.filename, "install_id": install_id })),
    ))
}

/// GET /api/dr/restore - where a remote restore stands, the last verdict of
/// restore-snapshot.sh, the vhost rebuild report and the rehydration report.
pub async fn restore_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "progress": rs::progress(),
        "last_restore": panel_snapshot::last_restore_result().await,
        "vhost_rebuild_pending": dr_post_restore::pending(),
        "vhost_rebuild": dr_post_restore::read_report(),
        "rehydrate_running": dr_rehydrate::is_running(),
        "rehydrate": dr_rehydrate::report(),
    })))
}

/// POST /api/dr/rehydrate - restore every local site and database whose
/// latest backup is on a remote destination. In the background; the card
/// follows `GET /api/dr/restore`.
pub async fn rehydrate(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let local = state
        .agents
        .local_server_id()
        .await
        .ok_or_else(|| err(StatusCode::CONFLICT, "The local server is not registered yet"))?;
    let Some(guard) = dr_rehydrate::RunGuard::acquire() else {
        return Err(err(StatusCode::CONFLICT, "Sites and databases are already being restored"));
    };
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dr.rehydrate", Some("dr"), Some("remote backups"),
        None, ip.as_deref(), claims.key_id,
    )
    .await;
    security_hardening::audit_log(
        &state.db, "dr.rehydrate", Some(&claims.email), ip.as_deref(), Some("dr"), Some("remote backups"),
        None, None, "warning", claims.key_id,
    )
    .await;
    // The pass only touches rows of the local server; it acts through that server's handle.
    let agent = state.agents.for_server(local).await.map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;
    let (db, secret) = (state.db.clone(), state.config.jwt_secret.clone());
    tokio::spawn(dr_rehydrate::run(db, agent, local, secret, guard));
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "started": true }))))
}

#[cfg(test)]
mod tests {
    /// Every handler is behind `AdminUser` and routed; the key is never
    /// logged nor handed to a process.
    #[test]
    fn every_route_is_admin_only_and_the_key_stays_in_memory() {
        let src = include_str!("dr_restore.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let handlers: Vec<&str> = code.split("pub async fn ").skip(1).collect();
        assert_eq!(handlers.len(), 4);
        let routes = include_str!("mod.rs");
        for h in handlers {
            let name = &h[..h.find('(').unwrap()];
            let sig = &h[..h.find('{').unwrap()];
            assert!(sig.contains("AdminUser("), "{name} is not behind AdminUser");
            assert!(routes.contains(&format!("dr_restore::{name})")), "{name} is not routed");
        }
        for line in code.lines().filter(|l| l.contains("tracing::") || l.contains("log_activity") || l.contains("audit_log")) {
            assert!(!line.contains("identity") && !line.contains("key)") && !line.contains("&key"), "{line}");
        }
        assert!(!code.contains("--setenv"));
        assert!(code.contains("Zeroizing::new(body.identity)"), "the key is wrapped as soon as it is read");
        // Its fingerprint is what the log says, after the key was checked against it.
        let check = code.find("rs::identity_matches(&key, &copy.recipient_fingerprint)").unwrap();
        let logged = code.find("(recovery key fingerprint {})").expect("the fingerprint is logged");
        assert!(check < logged);
        assert!(code[logged..logged + 200].contains("copy.recipient_fingerprint"));
    }
}
