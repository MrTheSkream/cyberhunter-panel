//! Off-site disaster recovery snapshots: configuration API (lot 2, 2.3/2.4).
//!
//! Every route is admin-only. The recovery key (an age X25519 identity) is
//! returned ONCE, by `POST /api/dr/recipient`, with `Cache-Control: no-store`;
//! the server keeps only its public half and fingerprint, and no other route
//! can return it. The work itself lives in `services::dr_snapshot`.
//!
//! - `GET  /api/dr`            status (`DrStatus`)
//! - `PUT  /api/dr/settings`   `{enabled, schedule, destination_ids, remote_retention}` -> status
//! - `POST /api/dr/recipient`  `{rotate}` -> 201 `{recipient, identity, previous_fingerprint}`
//! - `POST /api/dr/run`        -> 202 `{started: true}` (409 when a run is in progress)

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::{err, internal_error, ApiError};
use crate::services::dr_snapshot::{self as dr, DrRecipient, DrStatus, EnrollError, RunGuard};
use crate::services::{activity, security_hardening};
use crate::AppState;

/// GET /api/dr - settings, recovery key fingerprint, recent remote copies.
pub async fn get_status(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<DrStatus>, ApiError> {
    dr::load_status(&state.db).await.map(Json).map_err(|e| internal_error("dr status", e))
}

#[derive(Deserialize)]
pub struct SettingsInput {
    pub enabled: bool,
    pub schedule: String,
    pub destination_ids: Vec<Uuid>,
    pub remote_retention: i32,
}

/// PUT /api/dr/settings
pub async fn put_settings(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<SettingsInput>,
) -> Result<Json<DrStatus>, ApiError> {
    let schedule = body.schedule.split_whitespace().collect::<Vec<_>>().join(" ");
    if !dr::valid_schedule(&schedule) {
        return Err(err(StatusCode::BAD_REQUEST, "Schedule must be a 5-field cron expression (minute hour day month weekday)"));
    }
    if !(1..=365).contains(&body.remote_retention) {
        return Err(err(StatusCode::BAD_REQUEST, "Keep remote copies must be between 1 and 365"));
    }
    let mut ids: Vec<Uuid> = Vec::new();
    for id in &body.destination_ids {
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    let eligible = dr::eligible_destinations(&state.db).await.map_err(|e| internal_error("dr destinations", e))?;
    if let Some(bad) = ids.iter().find(|id| !eligible.iter().any(|d| d.id == **id)) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Destination {bad} does not exist or is not reachable from this server"),
        ));
    }
    if body.enabled {
        let recipient = dr::active_recipient(&state.db).await.map_err(|e| internal_error("dr recipient", e))?;
        if recipient.is_none() {
            return Err(err(StatusCode::BAD_REQUEST, "Set up a recovery key before enabling off-site panel snapshots"));
        }
        if ids.is_empty() {
            return Err(err(StatusCode::BAD_REQUEST, "Choose at least one destination before enabling off-site panel snapshots"));
        }
    }

    dr::load_settings(&state.db).await.map_err(|e| internal_error("dr settings", e))?;
    sqlx::query(
        "UPDATE dr_settings SET \
           enabled_at = CASE WHEN $1 AND NOT enabled THEN NOW() WHEN $1 THEN enabled_at ELSE NULL END, \
           enabled = $1, schedule = $2, destination_ids = $3, remote_retention = $4, updated_at = NOW() \
         WHERE id = 1",
    )
    .bind(body.enabled)
    .bind(&schedule)
    .bind(&ids)
    .bind(body.remote_retention)
    .execute(&state.db)
    .await
    .map_err(|e| internal_error("dr settings update", e))?;

    let details = format!(
        "enabled={} schedule='{schedule}' destinations={} keep={}",
        body.enabled,
        ids.len(),
        body.remote_retention
    );
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dr.settings", Some("dr"), Some("off-site snapshots"),
        Some(&details), ip.as_deref(), claims.key_id,
    )
    .await;
    security_hardening::audit_log(
        &state.db, "dr.settings", Some(&claims.email), ip.as_deref(), Some("dr"), Some("off-site snapshots"),
        Some(&details), None, "warning", claims.key_id,
    )
    .await;

    dr::load_status(&state.db).await.map(Json).map_err(|e| internal_error("dr status", e))
}

#[derive(Deserialize, Default)]
pub struct RecipientInput {
    #[serde(default)]
    pub rotate: bool,
}

/// The one response that carries the identity. Serialized straight into the
/// response body (no intermediate `serde_json::Value` copy).
#[derive(Serialize)]
struct EnrolledResponse<'a> {
    recipient: &'a DrRecipient,
    identity: &'a str,
    previous_fingerprint: Option<&'a str>,
}

/// POST /api/dr/recipient - generate the recovery key; `rotate` replaces the
/// active one (kept, retired, for the history).
pub async fn enroll_recipient(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    body: Option<Json<RecipientInput>>,
) -> Result<impl IntoResponse, ApiError> {
    let rotate = body.map(|Json(b)| b.rotate).unwrap_or(false);
    // Generated before the transaction, dropped (zeroized) when this returns.
    let key = dr::generate_recovery_key(chrono::Utc::now());
    let (recipient, previous) =
        match dr::enroll_recipient(&state.db, &key.public_key, &key.fingerprint, &claims.email, rotate).await {
            Ok(r) => r,
            Err(EnrollError::AlreadyEnrolled) => {
                return Err(err(StatusCode::CONFLICT, "A recovery key is already set up: rotate it instead"));
            }
            Err(EnrollError::NothingToRotate) => {
                return Err(err(StatusCode::CONFLICT, "There is no recovery key to rotate: set one up first"));
            }
            Err(EnrollError::Db(e)) => return Err(internal_error("dr enroll", e)),
        };

    // Fingerprints only, never the key.
    let action = if previous.is_some() { "dr.recovery_key.rotate" } else { "dr.recovery_key.create" };
    let details = match &previous {
        Some(p) => format!("fingerprint {} (replaces {p})", recipient.fingerprint),
        None => format!("fingerprint {}", recipient.fingerprint),
    };
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, action, Some("dr"), Some("recovery key"),
        Some(&details), ip.as_deref(), claims.key_id,
    )
    .await;
    security_hardening::audit_log(
        &state.db, action, Some(&claims.email), ip.as_deref(), Some("dr"), Some("recovery key"),
        Some(&details), None, "critical", claims.key_id,
    )
    .await;
    tracing::info!("Disaster recovery key enrolled by {}: {details}", claims.email);

    let body = Json(EnrolledResponse {
        recipient: &recipient,
        identity: key.identity_file.as_str(),
        previous_fingerprint: previous.as_deref(),
    })
    .into_response();
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
        body,
    ))
}

/// POST /api/dr/run - start an off-site snapshot now, in the background (it
/// outlives the request timeout); the card polls `GET /api/dr`.
pub async fn run_now(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let settings = dr::load_settings(&state.db).await.map_err(|e| internal_error("dr settings", e))?;
    let recipient = dr::active_recipient(&state.db).await.map_err(|e| internal_error("dr recipient", e))?;
    if let Some(reason) = dr::not_runnable_reason(&settings, recipient.as_ref()) {
        return Err(err(StatusCode::BAD_REQUEST, reason));
    }
    let Some(guard) = RunGuard::acquire() else {
        return Err(err(StatusCode::CONFLICT, "An off-site snapshot is already running"));
    };

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dr.run", Some("dr"), Some("off-site snapshots"),
        None, ip.as_deref(), claims.key_id,
    )
    .await;

    let (db, agents, operator) = (state.db.clone(), state.agents.clone(), claims.email.clone());
    tokio::spawn(async move {
        dr::run_once(&db, &agents, Some(operator), &guard).await;
    });
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "started": true }))))
}

#[cfg(test)]
mod tests {
    /// Every handler of this file is behind `AdminUser`, and every one is
    /// routed. Source-level, like the other route pins of this crate.
    #[test]
    fn every_dr_route_is_admin_only() {
        let src = include_str!("dr.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let handlers: Vec<&str> = code
            .split("pub async fn ")
            .skip(1)
            .collect();
        assert_eq!(handlers.len(), 4, "four handlers expected");
        for h in handlers {
            let name = &h[..h.find('(').unwrap()];
            let sig = &h[..h.find('{').unwrap()];
            assert!(sig.contains("AdminUser("), "{name} is not behind AdminUser");
            let routes = include_str!("mod.rs");
            assert!(routes.contains(&format!("dr::{name})")), "{name} is not routed");
        }
    }

    /// The identity appears in exactly one response, and is never logged.
    #[test]
    fn the_identity_is_returned_once_and_never_logged() {
        let src = include_str!("dr.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert_eq!(code.matches("identity_file").count(), 1, "the identity leaves through one response only");
        assert!(code.contains("no-store"));
        for line in code.lines().filter(|l| l.contains("tracing::") || l.contains("log_activity") || l.contains("audit_log")) {
            assert!(!line.contains("identity"), "a log line mentions the identity: {line}");
        }
        let service = include_str!("../services/dr_snapshot.rs");
        let service = &service[..service.find("#[cfg(test)]").unwrap()];
        for line in service.lines().filter(|l| l.contains("tracing::")) {
            assert!(!line.contains("identity") && !line.contains("expose_secret"), "a log line mentions the identity: {line}");
        }
        // Nothing writes the identity to disk or hands it to a process.
        assert_eq!(service.matches("expose_secret").count(), 1, "the one formatting into the zeroized file text");
        assert!(!service.contains("--setenv"));
    }
}
