//! Web statistics with GoAccess (feature 7, contracts B-2 and B-3).
//!
//! Server routes `/api/web-stats/*` (admin): the server is named by `server_id`
//! (query or body) and defaults to the local box; the caller must administer it,
//! as for the FTP routes.
//!
//! Site routes `/api/sites/{id}/stats/*`: the rights of the site page (admin of
//! its server, reseller of its owner, owner). Anybody else gets 404, as for a
//! site that does not exist.
//!
//! The state route is `GET /api/sites/{id}/stats/state`: `GET /api/sites/{id}/stats`
//! already serves the "Recent traffic" block (`sites::site_stats`).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AdminUser, AuthUser, Claims};
use crate::error::{ApiError, agent_error, agent_message, err, internal_error};
use crate::routes::is_valid_domain;
use crate::services::activity;
use crate::services::agent::{AgentError, AgentHandle};
use crate::services::web_stats;

/// The agent gives the install 5 minutes in total.
const INSTALL_TIMEOUT_SECS: u64 = 330;
const UNINSTALL_TIMEOUT_SECS: u64 = 330;
const PURGE_TIMEOUT_SECS: u64 = 330;
/// How long a Refresh waits for its run before answering `running: true`;
/// under the 300 s `TimeoutLayer` of every route.
const REFRESH_WAIT: std::time::Duration = std::time::Duration::from_secs(280);

/// B-3: the sandbox keeps the report's scripts away from the panel even when
/// the response is opened directly in a tab.
pub const REPORT_CSP: &str = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; \
     style-src 'unsafe-inline'; img-src data:; font-src data:";

// ──────────────────────────────────────────────────────────────
// Server lookup (same rules as the FTP routes)
// ──────────────────────────────────────────────────────────────

/// The requested server, or the local box.
async fn resolve_server_id(state: &AppState, server_id: Option<Uuid>) -> Result<Uuid, ApiError> {
    if let Some(id) = server_id {
        return Ok(id);
    }
    if let Some(id) = state.agents.local_server_id().await
        && !id.is_nil()
    {
        return Ok(id);
    }
    let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM servers WHERE is_local LIMIT 1")
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("web stats local server", e))?;
    row.map(|(id,)| id).ok_or_else(|| err(StatusCode::NOT_FOUND, "Server not found"))
}

/// The agent of a server the caller administers (local box, or a member they registered).
async fn admin_server(state: &AppState, claims: &Claims, server_id: Uuid) -> Result<AgentHandle, ApiError> {
    let ok: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM servers sv, users u WHERE sv.id = $1 AND u.id = $2 AND u.role = 'admin' \
         AND (sv.is_local OR sv.user_id = u.id)",
    )
    .bind(server_id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("web stats server lookup", e))?;
    if ok.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "Server not found"));
    }
    state
        .agents
        .for_server(server_id)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Server unreachable: {e}")))
}

async fn log(state: &AppState, claims: &Claims, action: &str, details: Option<&str>, server_id: Uuid) {
    activity::log_activity_on_server(
        &state.db,
        claims.sub,
        &claims.email,
        action,
        Some("server"),
        None,
        details,
        None,
        Some(server_id),
        claims.key_id,
    )
    .await;
}

/// Install failures carry the package manager's output: the administrator
/// needs it, so a 5xx is relayed with its message.
fn long_op_error(context: &str, e: AgentError) -> ApiError {
    match e {
        AgentError::Status(code, ref body) if code >= 500 => {
            let msg: String = agent_message(body).chars().take(2000).collect();
            tracing::warn!(agent_status = code, "{context} failed");
            err(StatusCode::BAD_GATEWAY, &format!("{context} failed: {msg}"))
        }
        e => agent_error(context, e),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct ServerQuery {
    pub server_id: Option<Uuid>,
}

/// The body of install / uninstall / purge; an empty body means the local box.
fn server_from_body(raw: &[u8]) -> Result<Option<Uuid>, ApiError> {
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }
    let q: ServerQuery = serde_json::from_slice(raw)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Body must be JSON: {\"server_id\"?: string}"))?;
    Ok(q.server_id)
}

// ──────────────────────────────────────────────────────────────
// B-2 server routes
// ──────────────────────────────────────────────────────────────

/// GET /api/web-stats/status?server_id= -> A-1
pub async fn status(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, q.server_id).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let v = agent.get("/stats/status").await.map_err(|e| agent_error("Web statistics status", e))?;
    web_stats::remember_installed(server_id, web_stats::installed_from_status(&v));
    Ok(Json(v))
}

/// POST /api/web-stats/install {server_id?} -> A-2 `{ok, warnings}`, then the
/// first pass on that server starts right away.
pub async fn install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, server_from_body(&raw)?).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let res = agent.post_long("/stats/install", None, INSTALL_TIMEOUT_SECS).await;
    web_stats::forget_installed(server_id);
    let v = res.map_err(|e| long_op_error("Web statistics install", e))?;
    web_stats::wake(server_id);
    log(&state, &claims, "web_stats.install", None, server_id).await;
    Ok(Json(v))
}

/// POST /api/web-stats/uninstall {server_id?} -> A-3 `{ok}`. The data is kept.
pub async fn uninstall(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, server_from_body(&raw)?).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let res = agent.post_long("/stats/uninstall", None, UNINSTALL_TIMEOUT_SECS).await;
    web_stats::forget_installed(server_id);
    let v = res.map_err(|e| long_op_error("Web statistics uninstall", e))?;
    log(&state, &claims, "web_stats.uninstall", None, server_id).await;
    Ok(Json(v))
}

/// POST /api/web-stats/purge {server_id?} -> A-4 `{ok, removed}`, then the
/// `site_web_stats` rows of that server's sites are deleted.
pub async fn purge(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, server_from_body(&raw)?).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let v = agent
        .post_long("/stats/purge", None, PURGE_TIMEOUT_SECS)
        .await
        .map_err(|e| long_op_error("Web statistics purge", e))?;
    sqlx::query("DELETE FROM site_web_stats WHERE site_id IN (SELECT id FROM sites WHERE server_id = $1)")
        .bind(server_id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("web stats purge", e))?;
    let removed = v.get("removed").and_then(|r| r.as_u64()).unwrap_or(0);
    log(&state, &claims, "web_stats.purge", Some(&format!("{removed} site(s)")), server_id).await;
    Ok(Json(v))
}

// ──────────────────────────────────────────────────────────────
// B-3 site routes
// ──────────────────────────────────────────────────────────────

/// Roles of a client account its reseller may act on (same list as the site
/// quota routes).
const RESELLER_CLIENT_ROLES: &[&str] = &["user", "client", "suspended"];

/// `(domain, server_id)` of a site the caller may see: admin of its server,
/// reseller of its owner, or its owner. Roles are read from the database,
/// never from the token. Every refusal is the 404 of a missing site.
async fn site_for_caller(state: &AppState, claims: &Claims, id: Uuid) -> Result<(String, Option<Uuid>), ApiError> {
    let row: Option<(String, Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT s.domain, s.server_id, \
           EXISTS (SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' \
                   AND sv.id = s.server_id AND (sv.is_local OR sv.user_id = u.id)) \
           OR EXISTS (SELECT 1 FROM users o, users r WHERE o.id = s.user_id AND r.id = $2 \
                   AND r.role = 'reseller' AND o.reseller_id = r.id AND o.role = ANY($3)) \
           OR s.user_id = $2 \
         FROM sites s WHERE s.id = $1",
    )
    .bind(id)
    .bind(claims.sub)
    .bind(RESELLER_CLIENT_ROLES)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("web stats site lookup", e))?;
    match row {
        Some((domain, server_id, true)) => {
            if !is_valid_domain(&domain) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid site domain"));
            }
            Ok((domain, server_id))
        }
        _ => Err(err(StatusCode::NOT_FOUND, "Site not found")),
    }
}

/// The body of the state and refresh routes.
pub fn state_body(
    installed: bool,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    error: Option<String>,
    running: bool,
) -> Value {
    json!({ "installed": installed, "updated_at": updated_at, "error": error, "running": running })
}

async fn site_state(state: &AppState, agent: &AgentHandle, server_id: Uuid, id: Uuid) -> Result<Value, ApiError> {
    let installed = web_stats::installed(agent, server_id, true)
        .await
        .map_err(|e| agent_error("Web statistics status", e))?;
    let (updated_at, error) = web_stats::load(&state.db, id).await.map_err(|e| internal_error("web stats state", e))?;
    Ok(state_body(installed, updated_at, error, web_stats::is_running(id)))
}

/// GET /api/sites/{id}/stats/state -> {installed, updated_at, error, running}
pub async fn site_stats_state(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let (domain, server_id) = site_for_caller(&state, &claims, id).await?;
    let agent = crate::helpers::agent_for_site_server(&state, server_id, &domain).await?;
    let server_id = server_id.unwrap_or_default();
    Ok(Json(site_state(&state, &agent, server_id, id).await?))
}

/// POST /api/sites/{id}/stats/refresh -> same body as the state route.
///
/// Runs A-5 for this site now and records the outcome. One run at a time per
/// site, shared with the scheduler: 429 while one is running. A failure of the
/// run itself (no access log, GoAccess error, network) is recorded and comes
/// back in `error`; 412 (not installed), 409 (agent busy) and 400 are relayed.
/// A run still going after [`REFRESH_WAIT`] answers `running: true` and is
/// recorded when it ends.
pub async fn refresh_site_stats(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let (domain, server_id) = site_for_caller(&state, &claims, id).await?;
    let guard = web_stats::SiteRunGuard::try_claim(id)
        .ok_or_else(|| err(StatusCode::TOO_MANY_REQUESTS, "A statistics run is already running for this site"))?;
    let agent = crate::helpers::agent_for_site_server(&state, server_id, &domain).await?;
    let server_id = server_id.unwrap_or_default();
    // The run goes on in its own task, holding the site's lock, and records its
    // outcome even if this request stops waiting: a run can queue and last far
    // longer than the 300 s every route gets.
    let task = {
        let (db, agent) = (state.db.clone(), agent.clone());
        tokio::spawn(async move {
            let res = web_stats::run_site(&db, &agent, id, &domain).await;
            drop(guard);
            res
        })
    };
    match tokio::time::timeout(REFRESH_WAIT, task).await {
        // Still running: the body says so (`running: true`).
        Err(_) => {}
        Ok(Err(e)) => return Err(internal_error("web stats refresh", e)),
        Ok(Ok(Ok(()))) => web_stats::remember_installed(server_id, true),
        Ok(Ok(Err(e))) => {
            if matches!(e, AgentError::Status(412, _)) {
                web_stats::remember_installed(server_id, false);
            }
            return Err(agent_error("Web statistics run", e));
        }
    }
    Ok(Json(site_state(&state, &agent, server_id, id).await?))
}

/// The response of the report route: the raw HTML with the B-3 headers.
pub fn report_response(domain: &str, html: Vec<u8>) -> Response {
    let mut resp = html.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(REPORT_CSP));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{domain}-stats.html\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    resp
}

/// GET /api/sites/{id}/stats/report -> the GoAccess report (A-6), or 404 "No report yet".
pub async fn site_stats_report(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let (domain, server_id) = site_for_caller(&state, &claims, id).await?;
    let agent = crate::helpers::agent_for_site_server(&state, server_id, &domain).await?;
    let (html, _) = agent
        .get_bytes(&format!("/stats/{domain}/report"))
        .await
        .map_err(|e| match e {
            AgentError::Status(404, _) => err(StatusCode::NOT_FOUND, "No report yet"),
            e => agent_error("Web statistics report", e),
        })?;
    Ok(report_response(&domain, html))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_means_the_local_server() {
        assert_eq!(server_from_body(b"").unwrap(), None);
        assert_eq!(server_from_body(b"{}").unwrap(), None);
        let id = Uuid::new_v4();
        assert_eq!(server_from_body(format!("{{\"server_id\":\"{id}\"}}").as_bytes()).unwrap(), Some(id));
        assert!(server_from_body(b"nope").is_err());
    }

    #[test]
    fn the_report_carries_exactly_the_contract_headers() {
        let resp = report_response("jeuxx.org", b"<html>x</html>".to_vec());
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(
            h[header::CONTENT_SECURITY_POLICY],
            "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             img-src data:; font-src data:"
        );
        assert_eq!(h[header::CONTENT_DISPOSITION], "attachment; filename=\"jeuxx.org-stats.html\"");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    }

    #[test]
    fn the_state_body_has_the_contract_shape() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-11-16T10:00:03Z").unwrap().with_timezone(&chrono::Utc);
        let v = state_body(true, Some(t), None, false);
        assert_eq!(v["installed"], true);
        assert_eq!(v["updated_at"], "2026-11-16T10:00:03Z");
        assert!(v["error"].is_null());
        assert_eq!(v["running"], false);
        assert_eq!(v.as_object().unwrap().len(), 4);
        let v = state_body(false, None, Some("No access log for this site".into()), true);
        assert!(v["updated_at"].is_null());
        assert_eq!(v["error"], "No access log for this site");
    }
}
