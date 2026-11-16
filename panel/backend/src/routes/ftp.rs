//! `/api/ftp/*`: the vsftpd server of a machine (feature 6, contract B-2).
//!
//! Admin routes: the server is named by `server_id` (query or body) and defaults to
//! the local box; the caller must administer it (the local box, or a member they
//! registered), as for the antivirus routes. The per-site FTP switch lives with
//! the other site routes (`sites::set_ftp`).
//!
//! The whitelist (`/etc/dockpanel/ftp-users`, A-4) is owned by the panel: it is
//! always rewritten whole from the database by [`sync_ftp_users`].

use std::sync::LazyLock;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AdminUser, Claims};
use crate::error::{ApiError, agent_error, agent_message, err, internal_error};
use crate::models::Site;
use crate::services::activity;
use crate::services::agent::{AgentError, AgentHandle};
use crate::services::server_ips::DeclaredIp;

/// The agent gives the install 5 minutes in total.
const INSTALL_TIMEOUT_SECS: u64 = 330;
const UNINSTALL_TIMEOUT_SECS: u64 = 330;
const USERS_TIMEOUT_SECS: u64 = 60;

/// The message the agent and this panel use when vsftpd is missing (A-4 412).
pub const NOT_INSTALLED: &str = "FTP server not installed";

// ──────────────────────────────────────────────────────────────
// Whitelist sync (shared by the site switch, disable_sftp, site deletion, import)
// ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FtpSyncError {
    /// A-4 answered 412: vsftpd is not installed on that server. The boxes stay
    /// ticked in the database and are written at the next install.
    NotInstalled,
    Agent(AgentError),
    Db(sqlx::Error),
}

impl std::fmt::Display for FtpSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "{NOT_INSTALLED}"),
            Self::Agent(e) => write!(f, "{e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl FtpSyncError {
    /// As an API error: 412 for a missing vsftpd, the agent's own refusal otherwise.
    pub fn into_api(self, context: &str) -> ApiError {
        match self {
            Self::NotInstalled => err(StatusCode::PRECONDITION_FAILED, NOT_INSTALLED),
            Self::Agent(e) => agent_error(context, e),
            Self::Db(e) => internal_error(context, e),
        }
    }
}

/// Serializes "read the list, send it": two concurrent switches must not leave
/// the older list on the server.
static SYNC_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// The account names of the sites of `server_id` that have FTP ticked and an SFTP
/// account, sorted and without duplicates.
pub async fn ftp_user_names(pool: &PgPool, server_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    let sites: Vec<Site> = sqlx::query_as(
        "SELECT * FROM sites WHERE server_id = $1 AND ftp_enabled AND sftp_enabled ORDER BY domain",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(user_list(&sites))
}

/// Pure part of [`ftp_user_names`].
pub fn user_list(sites: &[Site]) -> Vec<String> {
    let mut names: Vec<String> = sites
        .iter()
        .filter(|s| s.ftp_enabled && s.sftp_enabled && s.sftp_uid.is_some())
        .map(crate::routes::sites::sftp_account_name)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Rewrite the server's FTP whitelist from the database (A-4) through `agent`
/// (the agent of `server_id`).
pub async fn sync_ftp_users(pool: &PgPool, agent: &AgentHandle, server_id: Uuid) -> Result<Value, FtpSyncError> {
    let _guard = SYNC_LOCK.lock().await;
    let users = ftp_user_names(pool, server_id).await.map_err(FtpSyncError::Db)?;
    match agent.put_long("/ftp/users", json!({ "users": users }), USERS_TIMEOUT_SECS).await {
        Ok(v) => Ok(v),
        Err(AgentError::Status(412, _)) => Err(FtpSyncError::NotInstalled),
        Err(e) => Err(FtpSyncError::Agent(e)),
    }
}

// ──────────────────────────────────────────────────────────────
// Passive address
// ──────────────────────────────────────────────────────────────

/// The `pasv_address` vsftpd needs behind NAT: the public address declared for
/// the server's primary IP (feature 1), only when it differs from that IP.
pub fn pasv_address(declared: &[DeclaredIp], agent_primary: Option<&str>) -> Option<String> {
    let primary = agent_primary.map(str::trim).filter(|p| !p.is_empty())?;
    let row = declared.iter().find(|d| d.ip.trim() == primary)?;
    let public = row.public_ip.as_deref().map(str::trim).filter(|p| !p.is_empty())?;
    (public != primary).then(|| public.to_string())
}

async fn pasv_address_for(pool: &PgPool, agent: &AgentHandle, server_id: Uuid) -> Option<String> {
    let primary = crate::routes::mail::agent_primary_ip(agent).await;
    primary.as_ref()?;
    let declared: Vec<DeclaredIp> =
        match sqlx::query_as("SELECT id, ip, public_ip, ptr FROM server_ips WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("FTP install: could not read the addresses of server {server_id}: {e}");
                return None;
            }
        };
    pasv_address(&declared, primary.as_deref())
}

// ──────────────────────────────────────────────────────────────
// Server lookup
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
        .map_err(|e| internal_error("ftp local server", e))?;
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
    .map_err(|e| internal_error("ftp server lookup", e))?;
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

/// Install and uninstall failures carry the end of the unit's journal (A-2): the
/// administrator needs it, so a 5xx is relayed with its message rather than
/// replaced by an incident reference.
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

// ──────────────────────────────────────────────────────────────
// Routes
// ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
pub struct ServerQuery {
    pub server_id: Option<Uuid>,
}

/// GET /api/ftp/status?server_id= -> A-1
pub async fn status(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Query(q): Query<ServerQuery>,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, q.server_id).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let v = agent.get("/ftp/status").await.map_err(|e| agent_error("FTP status", e))?;
    Ok(Json(v))
}

/// The body of install / uninstall; an empty body means the local box.
fn server_from_body(raw: &[u8]) -> Result<Option<Uuid>, ApiError> {
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }
    let q: ServerQuery = serde_json::from_slice(raw)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Body must be JSON: {\"server_id\"?: string}"))?;
    Ok(q.server_id)
}

/// POST /api/ftp/install {server_id?} -> A-2 `{ok, warnings}`
pub async fn install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, server_from_body(&raw)?).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let users = ftp_user_names(&state.db, server_id).await.map_err(|e| internal_error("ftp users", e))?;
    let pasv = pasv_address_for(&state.db, &agent, server_id).await;
    let v = agent
        .post_long("/ftp/install", Some(json!({ "users": users, "pasv_address": pasv })), INSTALL_TIMEOUT_SECS)
        .await
        .map_err(|e| long_op_error("FTP server install", e))?;
    let details = format!("{} FTP account(s){}", users.len(), if pasv.is_some() { ", passive address set" } else { "" });
    log(&state, &claims, "ftp.install", Some(&details), server_id).await;
    Ok(Json(v))
}

/// POST /api/ftp/uninstall {server_id?} -> A-3 `{ok}`. The sites' FTP boxes are kept.
pub async fn uninstall(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let server_id = resolve_server_id(&state, server_from_body(&raw)?).await?;
    let agent = admin_server(&state, &claims, server_id).await?;
    let v = agent
        .post_long("/ftp/uninstall", None, UNINSTALL_TIMEOUT_SECS)
        .await
        .map_err(|e| long_op_error("FTP server uninstall", e))?;
    log(&state, &claims, "ftp.uninstall", None, server_id).await;
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(ip: &str, public: Option<&str>) -> DeclaredIp {
        DeclaredIp { id: Uuid::new_v4(), ip: ip.into(), public_ip: public.map(str::to_string), ptr: None }
    }

    #[test]
    fn passive_address_only_behind_nat() {
        let declared = vec![ip("10.0.0.5", Some("203.0.113.7")), ip("203.0.113.9", None), ip("10.0.0.6", Some(" "))];
        assert_eq!(pasv_address(&declared, Some("10.0.0.5")).as_deref(), Some("203.0.113.7"));
        // Public address of the box itself, or none declared: nothing to set.
        assert_eq!(pasv_address(&declared, Some("203.0.113.9")), None);
        assert_eq!(pasv_address(&declared, Some("10.0.0.6")), None);
        assert_eq!(pasv_address(&[ip("1.2.3.4", Some("1.2.3.4"))], Some("1.2.3.4")), None);
        // Unknown primary: never guess.
        assert_eq!(pasv_address(&declared, Some("10.0.0.99")), None);
        assert_eq!(pasv_address(&declared, None), None);
    }

    #[test]
    fn empty_body_means_the_local_server() {
        assert_eq!(server_from_body(b"").unwrap(), None);
        assert_eq!(server_from_body(b"  \n").unwrap(), None);
        assert_eq!(server_from_body(b"{}").unwrap(), None);
        let id = Uuid::new_v4();
        assert_eq!(server_from_body(format!("{{\"server_id\":\"{id}\"}}").as_bytes()).unwrap(), Some(id));
        assert!(server_from_body(b"nope").is_err());
    }

    #[test]
    fn not_installed_is_a_412() {
        let (code, body) = FtpSyncError::NotInstalled.into_api("x");
        assert_eq!(code, StatusCode::PRECONDITION_FAILED);
        assert_eq!(body.0["error"], NOT_INSTALLED);
    }
}
