//! User terminal (09): the agent-token routes A-2 to A-4 and the event route
//! of B-6. The WebSocket itself (A-1) is the `@user:` branch of
//! `/terminal/ws`, in `routes/terminal.rs`.

use axum::{
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use super::AppState;
use crate::services::user_terminal::{self, PrepareError};

type ApiErr = (StatusCode, Json<serde_json::Value>);

/// Every refusal carries `reasons` too, so the backend reads one shape.
fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg, "reasons": [msg] })))
}

#[derive(Deserialize)]
struct CheckQuery {
    login: Option<String>,
}

/// GET /terminal/user/check?login=<login>
async fn check(Query(q): Query<CheckQuery>) -> Result<Json<serde_json::Value>, ApiErr> {
    let login = q.login.unwrap_or_default();
    if !user_terminal::is_valid_login(&login) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid Linux login"));
    }
    Ok(Json(user_terminal::check(&login).await))
}

#[derive(Deserialize)]
struct PrepareBody {
    login: String,
    uid: u32,
    #[serde(default)]
    autostart_command: Option<String>,
}

/// POST /terminal/user/prepare
async fn prepare(Json(body): Json<PrepareBody>) -> Result<Json<serde_json::Value>, ApiErr> {
    match user_terminal::prepare(&body.login, body.uid, body.autostart_command.as_deref()).await {
        Ok(warnings) => Ok(Json(serde_json::json!({ "ok": true, "warnings": warnings }))),
        Err(PrepareError::BadRequest(m)) => Err(err(StatusCode::BAD_REQUEST, &m)),
        Err(PrepareError::Refused(reasons)) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": reasons.join("; "), "reasons": reasons })),
        )),
        Err(PrepareError::Unsupported) => Err(err(StatusCode::PRECONDITION_FAILED, "Not supported on this server")),
        Err(PrepareError::Failed(m)) => {
            tracing::warn!("user terminal prepare for {}: {m}", body.login);
            Err(err(StatusCode::INTERNAL_SERVER_ERROR, &m))
        }
    }
}

#[derive(Deserialize)]
struct KillBody {
    #[serde(default)]
    stop_sessions: bool,
    #[serde(default)]
    login: Option<String>,
}

/// POST /terminal/user/kill
async fn kill(Json(body): Json<KillBody>) -> Result<Json<serde_json::Value>, ApiErr> {
    if let Some(l) = body.login.as_deref() {
        if !user_terminal::is_valid_login(l) {
            return Err(err(StatusCode::BAD_REQUEST, "Invalid Linux login"));
        }
    }
    let r = user_terminal::kill(body.stop_sessions, body.login.as_deref()).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "connections_killed": r.connections_killed,
        "sessions_stopped": r.sessions_stopped,
    })))
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

/// GET /terminal/user/events?limit= - `user_terminal.*` audit lines, newest first.
async fn events(Query(q): Query<EventsQuery>) -> Json<serde_json::Value> {
    let events = tokio::task::spawn_blocking(move || user_terminal::events(q.limit))
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "events": events }))
}

/// Under the agent-token middleware (merged before `auth_middleware` in main.rs).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/terminal/user/check", get(check))
        .route("/terminal/user/prepare", post(prepare))
        .route("/terminal/user/kill", post(kill))
        .route("/terminal/user/events", get(events))
}
