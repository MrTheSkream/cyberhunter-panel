//! Agent-side endpoints for per-site SFTP accounts (GH #108). Thin: all the
//! actual provisioning/teardown logic lives in `services::sftp_accounts`, so
//! this file is only request validation + response shaping, matching every
//! other route module here.

use axum::{
    extract::Path,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use super::{is_valid_domain, AppState};
use crate::services::sftp_accounts;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Deserialize)]
struct EnableRequest {
    uid: i32,
    gid: i32,
    /// Custom account name (05-import-hestia D6); absent = `sftp<uid>`.
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize)]
struct DisableRequest {
    uid: i32,
    gid: i32,
    /// Whether this was the last SFTP-enabled site on the box - decided by
    /// the backend from the `sites` table, never re-derived here.
    last_sftp_site: bool,
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    uid: i32,
    password: String,
}

/// POST /sftp/sites/{domain}/enable
async fn enable(
    Path(domain): Path<String>,
    Json(body): Json<EnableRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    // Detached task: a client that gives up (backend timeout) drops this
    // handler's future, and a provision cancelled mid-way would skip its own
    // rollback. The spawned task always runs to completion or to its undo.
    let task_domain = domain.clone();
    let done = tokio::spawn(async move {
        sftp_accounts::provision(&task_domain, body.uid, body.gid, body.username.as_deref()).await
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("SFTP enable task failed: {e}")))?
    .map_err(|e| match e {
            sftp_accounts::ProvisionError::InvalidUsername(m) => {
                coded(StatusCode::BAD_REQUEST, &m, "invalid_username")
            }
            sftp_accounts::ProvisionError::UsernameTaken(m) => {
                coded(StatusCode::CONFLICT, &m, "username_taken")
            }
            sftp_accounts::ProvisionError::Failed(m) => err(StatusCode::INTERNAL_SERVER_ERROR, &m),
        })?;
    // The account's own uid/gid: a resumed leftover may live under another
    // uid than the one requested, and the backend must record that one.
    Ok(Json(serde_json::json!({
        "ok": true,
        "username": done.username,
        "uid": done.uid,
        "gid": done.gid,
        "resumed": done.resumed,
    })))
}

/// POST /sftp/sites/{domain}/disable
async fn disable(
    Path(domain): Path<String>,
    Json(body): Json<DisableRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    sftp_accounts::deprovision(&domain, body.uid, body.gid, body.last_sftp_site)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /sftp/sites/{domain}/password
async fn set_password(
    Path(domain): Path<String>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    if body.password.len() < 12 {
        return Err(err(StatusCode::BAD_REQUEST, "Password must be at least 12 characters"));
    }
    sftp_accounts::set_password(body.uid, &body.password)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sftp/sites/{domain}/enable", post(enable))
        .route("/sftp/sites/{domain}/disable", post(disable))
        .route("/sftp/sites/{domain}/password", post(set_password))
        // --- import-hestia (05) ---
        .route("/sftp/sites/{domain}/password-hash", post(set_password_hash))
        // --- end import-hestia (05) ---
}

// --- import-hestia (05) ---
fn coded(status: StatusCode, msg: &str, code: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg, "code": code })))
}

#[derive(Deserialize)]
struct SetPasswordHashRequest {
    uid: i32,
    migration_id: String,
}

/// POST /sftp/sites/{domain}/password-hash (contract W4-S)
///
/// Applies the HestiaCP FTP hash of `domain` to the SFTP account of `uid`.
/// The agent reads the hash itself from the migration staging (by reference):
/// it never travels through the backend, a response or a log. Any failure
/// leaves the account locked (`usermod -L`); the operator then uses the
/// existing "Reset password".
async fn set_password_hash(
    Path(domain): Path<String>,
    Json(body): Json<SetPasswordHashRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    // The uid must be proven to be this domain's account before its password
    // is touched - the same fail-closed marker as teardown.
    if !crate::services::ownership::sftp_user(body.uid, &domain).may_delete() {
        return Err(coded(
            StatusCode::CONFLICT,
            &format!("uid {} is not the SFTP account of {domain}", body.uid),
            "not_owner",
        ));
    }
    let Some((_ftp_user, hash)) = crate::services::hestia::ftp_hash(&body.migration_id, &domain) else {
        sftp_accounts::lock_account(body.uid).await;
        return Err(coded(
            StatusCode::NOT_FOUND,
            "No FTP password hash for this domain in the backup",
            "no_hash",
        ));
    };
    let scheme = sftp_accounts::crypt_hash_scheme(&hash).unwrap_or("unknown");
    match sftp_accounts::set_password_hash(body.uid, &hash).await {
        Ok(()) => {
            tracing::info!("SFTP password hash applied for {domain} (uid {}, scheme {scheme})", body.uid);
            Ok(Json(serde_json::json!({ "ok": true, "scheme": scheme })))
        }
        Err(sftp_accounts::HashApplyError::Unsupported(why)) => {
            sftp_accounts::lock_account(body.uid).await;
            tracing::warn!("SFTP password hash for {domain} not applied (account locked): {why}");
            Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": format!("password hash not usable on this server: {why}"),
                    "code": "unsupported_scheme",
                    "scheme": scheme,
                })),
            ))
        }
        Err(sftp_accounts::HashApplyError::Failed(why)) => {
            sftp_accounts::lock_account(body.uid).await;
            tracing::warn!("SFTP password hash for {domain} not applied (account locked): {why}");
            Err(coded(StatusCode::INTERNAL_SERVER_ERROR, &why, "apply_failed"))
        }
    }
}
// --- end import-hestia (05) ---
