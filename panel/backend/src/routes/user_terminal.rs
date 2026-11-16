//! Feature 9: the user terminal - a non-root shell, as a linked Linux user,
//! attached to a persistent tmux session (conception/09-terminal-utilisateur.md,
//! contracts B-3 to B-6).
//!
//! Everything here is NEW code beside `routes/terminal.rs`, which stays
//! byte-for-byte unchanged: the `@server` and site shells keep their own ticket
//! route (`ws_token`). The only things this module shares with it are the
//! public lockdown reader (`terminals_locked_down`) and the agent's signing key.
//!
//! Routes:
//! - `GET    /api/terminal/user/token` - one-shot ticket for `@user:<login>` (B-3)
//! - `GET    /api/terminal/user/me` - menu/page availability, never a ticket (B-4)
//! - `GET    /api/terminal/user/accounts` - admin accounts and their mapping (B-4)
//! - `PUT    /api/terminal/user/accounts/{user_id}` - link / relink (B-4)
//! - `DELETE /api/terminal/user/accounts/{user_id}` - unlink (B-4)
//! - `GET    /api/terminal/user/accounts/{user_id}/check` - agent check relay (B-4)
//! - `GET    /api/security/user-terminal-events` - agent audit relay (B-6)

use std::collections::HashMap;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{bearer_token, read_cookie, AdminUser, AuthUser, Claims, AMR_MFA};
use crate::error::{agent_error, err, err_coded, internal_error, ApiError};
use crate::routes::auth::{require_enrolment_proof, EnrolmentProof};
use crate::services::agent::{AgentError, AgentHandle};
use crate::services::security_hardening;
use crate::AppState;

/// Ticket scope prefix. The agent's `ws_handler` takes its `@user:` branch only
/// for scopes that start with this.
pub const USER_SCOPE_PREFIX: &str = "@user:";

/// The refusal code for a session that has not proven a second factor.
pub const CODE_MFA_REQUIRED: &str = "mfa_required";

/// A ticket's lifetime. Same as `ws_token`'s, and the agent also keeps each
/// `jti` until `exp`, so the ticket is single-use within it.
const TICKET_TTL_SECS: i64 = 60;

/// Prepare (A-3) may install tmux and wait for `/run/user/<uid>`.
const PREPARE_TIMEOUT_SECS: u64 = 180;

/// Kill (A-4) bound: an emergency control must answer, and must never hang the
/// caller (lockdown, panic, settings save) on a wedged agent.
const KILL_TIMEOUT_SECS: u64 = 15;

/// Longest start command accepted (A-3 enforces the same bound).
const MAX_AUTOSTART_LEN: usize = 200;

// ---------------------------------------------------------------------------
// The decision (B-3), pure and unit-tested
// ---------------------------------------------------------------------------

/// Everything `user_ticket_decision` reads, gathered before it runs so the
/// decision itself does no I/O.
#[derive(Debug, Clone, Default)]
pub struct TicketContext {
    /// `terminals_locked_down`: an active lockdown that reaches terminals.
    pub locked_down: bool,
    /// `user_terminal_disabled = "true"`.
    pub disabled: bool,
    /// The request targets the panel host (no foreign `X-Server-Id`).
    pub local: bool,
    /// `claims.key_id` is set: a `dp_` API key.
    pub api_key: bool,
    /// The claims came from the `token` cookie (no `Authorization` header).
    pub session_cookie: bool,
    /// `claims.imp_by` is set: "login as user".
    pub impersonating: bool,
    /// The role read from `users` NOW, not the one frozen in the JWT.
    pub db_role: Option<String>,
    /// `claims.amr`.
    pub amr: Option<String>,
    /// A `user_linux_accounts` row exists for `claims.sub`.
    pub linked: bool,
}

/// Why a ticket (or a mapping route) is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    LockedDown,
    Disabled,
    NotLocal,
    BrowserSessionRequired,
    AdminRequired,
    MfaRequired,
    NotLinked,
}

impl Denial {
    pub fn status(self) -> StatusCode {
        match self {
            Denial::LockedDown => StatusCode::SERVICE_UNAVAILABLE,
            Denial::Disabled => StatusCode::FORBIDDEN,
            Denial::NotLocal => StatusCode::NOT_IMPLEMENTED,
            Denial::BrowserSessionRequired => StatusCode::FORBIDDEN,
            Denial::AdminRequired => StatusCode::FORBIDDEN,
            Denial::MfaRequired => StatusCode::FORBIDDEN,
            Denial::NotLinked => StatusCode::NOT_FOUND,
        }
    }

    /// Machine-readable code, carried as `code` in the error body and in `/me`.
    pub fn code(self) -> &'static str {
        match self {
            Denial::LockedDown => "lockdown",
            Denial::Disabled => "user_terminal_disabled",
            Denial::NotLocal => "not_local",
            Denial::BrowserSessionRequired => "browser_session_required",
            Denial::AdminRequired => "admin_required",
            Denial::MfaRequired => CODE_MFA_REQUIRED,
            Denial::NotLinked => "not_linked",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Denial::LockedDown => {
                "System is in lockdown mode. Terminal access is disabled until an \
                 administrator unlocks the panel (Security → Lockdown)."
            }
            Denial::Disabled => "User terminal is disabled",
            Denial::NotLocal => {
                "The user terminal runs on the panel host only. Switch back to the \
                 panel server to use it."
            }
            Denial::BrowserSessionRequired => "A browser session is required",
            Denial::AdminRequired => "Admin access required",
            Denial::MfaRequired => {
                "Sign in again with two-factor authentication to use the user terminal"
            }
            Denial::NotLinked => "No Linux account is linked to your panel account",
        }
    }

    pub fn to_api_error(self) -> ApiError {
        err_coded(self.status(), self.message(), self.code())
    }
}

/// Points 4 and 6 of B-3, shared by the mapping routes (B-4): a real browser
/// session (no `dp_` key, the cookie, no impersonation) that proved a second
/// factor.
pub fn session_gate(ctx: &TicketContext) -> Result<(), Denial> {
    if ctx.api_key || !ctx.session_cookie || ctx.impersonating {
        return Err(Denial::BrowserSessionRequired);
    }
    if ctx.amr.as_deref() != Some(AMR_MFA) {
        return Err(Denial::MfaRequired);
    }
    Ok(())
}

/// May this caller have a `@user:` ticket? Order and codes are the contract's
/// (B-3): lockdown 503, switch 403, non-local 501, browser session 403, role
/// re-read from the database 403, `amr` 403 `mfa_required`, mapping 404.
pub fn user_ticket_decision(ctx: &TicketContext) -> Result<(), Denial> {
    if ctx.locked_down {
        return Err(Denial::LockedDown);
    }
    if ctx.disabled {
        return Err(Denial::Disabled);
    }
    if !ctx.local {
        return Err(Denial::NotLocal);
    }
    if ctx.api_key || !ctx.session_cookie || ctx.impersonating {
        return Err(Denial::BrowserSessionRequired);
    }
    if ctx.db_role.as_deref() != Some("admin") {
        return Err(Denial::AdminRequired);
    }
    if ctx.amr.as_deref() != Some(AMR_MFA) {
        return Err(Denial::MfaRequired);
    }
    if !ctx.linked {
        return Err(Denial::NotLinked);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The ticket
// ---------------------------------------------------------------------------

/// A linked account, as the ticket and the agent need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub linux_user: String,
    pub uid: u32,
    pub record: bool,
}

/// The claims of a `@user:` ticket (A-1): those of `ws_token`'s ticket plus
/// `uid` and `jti`.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserTerminalTicket {
    pub sub: String,
    pub purpose: String,
    pub exp: usize,
    pub record: bool,
    pub scope: String,
    pub uid: u32,
    pub jti: String,
}

pub fn build_ticket(email: &str, mapping: &Mapping, now: i64) -> UserTerminalTicket {
    UserTerminalTicket {
        sub: email.to_string(),
        purpose: "terminal".to_string(),
        exp: (now + TICKET_TTL_SECS) as usize,
        record: mapping.record,
        scope: format!("{USER_SCOPE_PREFIX}{}", mapping.linux_user),
        uid: mapping.uid,
        jti: Uuid::new_v4().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Context gathering
// ---------------------------------------------------------------------------

/// The claims came from the `token` cookie: `AuthUser` prefers a Bearer
/// header, so a cookie merely being present proves nothing while one is sent.
fn has_session_cookie(headers: &HeaderMap) -> bool {
    bearer_token(headers).is_none() && read_cookie(headers, "token").is_some()
}

/// `X-Server-Id` absent, or naming the panel host.
async fn targets_local(state: &AppState, headers: &HeaderMap) -> bool {
    let requested = headers
        .get("x-server-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v.trim()).ok());
    match requested {
        None => true,
        Some(sid) => match state.agents.local_server_id().await {
            Some(local) => local == sid,
            // No local row yet: nothing to disagree with (require_local_agent_scope).
            None => true,
        },
    }
}

async fn user_terminal_disabled(state: &AppState) -> Result<bool, ApiError> {
    // Read directly rather than through `get_setting_bool`, which answers its
    // default on a database error - for a kill switch that would fail open.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'user_terminal_disabled'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("user terminal switch", e))?;
    Ok(row.map(|r| r.0 == "true").unwrap_or(false))
}

async fn load_mapping(state: &AppState, user_id: Uuid) -> Result<Option<Mapping>, ApiError> {
    let row: Option<(String, i32, bool)> = sqlx::query_as(
        "SELECT linux_user, uid, record FROM user_linux_accounts WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("user terminal mapping", e))?;
    Ok(row.map(|(linux_user, uid, record)| Mapping {
        linux_user,
        uid: uid.max(0) as u32,
        record,
    }))
}

/// Gather the whole B-3 context for this caller.
async fn gather(
    state: &AppState,
    claims: &Claims,
    headers: &HeaderMap,
) -> Result<(TicketContext, Option<Mapping>), ApiError> {
    let locked_down = crate::routes::terminal::terminals_locked_down(&state.db).await;
    let disabled = user_terminal_disabled(state).await?;
    let local = targets_local(state, headers).await;
    let db_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("user terminal role", e))?;
    let mapping = load_mapping(state, claims.sub).await?;

    let ctx = TicketContext {
        locked_down,
        disabled,
        local,
        api_key: claims.key_id.is_some(),
        session_cookie: has_session_cookie(headers),
        impersonating: claims.imp_by.is_some(),
        db_role: db_role.map(|r| r.0),
        amr: claims.amr.clone(),
        linked: mapping.is_some(),
    };
    Ok((ctx, mapping))
}

/// Points 4 and 6 only, for the mapping routes.
fn require_session_gate(claims: &Claims, headers: &HeaderMap) -> Result<(), ApiError> {
    let ctx = TicketContext {
        api_key: claims.key_id.is_some(),
        session_cookie: has_session_cookie(headers),
        impersonating: claims.imp_by.is_some(),
        amr: claims.amr.clone(),
        ..Default::default()
    };
    session_gate(&ctx).map_err(Denial::to_api_error)
}

fn local_agent(state: &AppState) -> AgentHandle {
    AgentHandle::Local(state.agents.local().clone())
}

// ---------------------------------------------------------------------------
// B-3: GET /api/terminal/user/token
// ---------------------------------------------------------------------------

/// GET /api/terminal/user/token - `{ "token", "login" }`.
///
/// `AuthUser`, not `AdminUser`: the role is decided by `user_ticket_decision`
/// from the database, in the contract's order, and every refusal is audited.
pub async fn user_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    AuthUser(claims): AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip = crate::routes::client_ip(&headers);
    let (ctx, mapping) = gather(&state, &claims, &headers).await?;

    if let Err(denial) = user_ticket_decision(&ctx) {
        security_hardening::audit_log(
            &state.db,
            "user_terminal.denied",
            Some(&claims.email),
            ip.as_deref(),
            Some("user_terminal"),
            mapping.as_ref().map(|m| m.linux_user.as_str()),
            Some(denial.code()),
            None,
            "warning",
            claims.key_id,
        )
        .await;
        return Err(denial.to_api_error());
    }

    // The decision passed, so a mapping exists.
    let mapping = mapping.ok_or_else(|| Denial::NotLinked.to_api_error())?;

    let agent = local_agent(&state);
    let ticket = build_ticket(&claims.email, &mapping, chrono::Utc::now().timestamp());
    let token = encode(
        &Header::default(),
        &ticket,
        &EncodingKey::from_secret(agent.token().await.as_bytes()),
    )
    .map_err(|e| internal_error("user terminal ticket", e))?;

    // Never the ticket itself.
    let details = format!(
        "login={} uid={} record={}",
        mapping.linux_user, mapping.uid, mapping.record
    );
    security_hardening::audit_log(
        &state.db,
        "user_terminal.ticket",
        Some(&claims.email),
        ip.as_deref(),
        Some("user_terminal"),
        Some(&mapping.linux_user),
        Some(&details),
        None,
        "info",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "token": token,
        "login": mapping.linux_user,
    })))
}

// ---------------------------------------------------------------------------
// B-4: GET /api/terminal/user/me
// ---------------------------------------------------------------------------

/// GET /api/terminal/user/me -
/// `{ "linked", "login", "available", "reason", "code" }`.
///
/// Open to every session (the menu polls it), so it is not audited. `available`
/// is `user_ticket_decision` without minting anything. `reason` is `null` when
/// available, the literal `"mfa_required"` in that case, and an English
/// sentence otherwise; `code` is always the machine-readable denial code.
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
    AuthUser(claims): AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (ctx, mapping) = gather(&state, &claims, &headers).await?;
    Ok(Json(me_body(&ctx, mapping.as_ref())))
}

fn me_body(ctx: &TicketContext, mapping: Option<&Mapping>) -> serde_json::Value {
    let decision = user_ticket_decision(ctx);
    let (reason, code) = match decision {
        Ok(()) => (None, None),
        Err(Denial::MfaRequired) => (Some(CODE_MFA_REQUIRED), Some(CODE_MFA_REQUIRED)),
        Err(d) => (Some(d.message()), Some(d.code())),
    };
    serde_json::json!({
        "linked": mapping.is_some(),
        "login": mapping.map(|m| m.linux_user.clone()),
        "available": decision.is_ok(),
        "reason": reason,
        "code": code,
    })
}

// ---------------------------------------------------------------------------
// B-4: mapping CRUD
// ---------------------------------------------------------------------------

/// Same shape as the agent's own check (A-2): `^[a-z_][a-z0-9_-]{0,31}$`.
pub fn valid_login(login: &str) -> bool {
    let b = login.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    let first_ok = b[0].is_ascii_lowercase() || b[0] == b'_';
    first_ok
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Normalise a start command: blank means none; at most 200 characters, one
/// line, no control character (A-3's own rule, answered here first).
pub fn normalise_autostart(cmd: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(raw) = cmd else { return Ok(None) };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_AUTOSTART_LEN {
        return Err("Start command must be at most 200 characters");
    }
    if trimmed.chars().any(char::is_control) {
        return Err("Start command must be a single line without control characters");
    }
    Ok(Some(trimmed.to_string()))
}

fn account_json(
    user_id: Uuid,
    email: &str,
    role: &str,
    m: Option<(&str, i32, Option<&str>, bool, chrono::DateTime<chrono::Utc>)>,
) -> serde_json::Value {
    match m {
        Some((linux_user, uid, autostart, record, updated_at)) => serde_json::json!({
            "user_id": user_id,
            "email": email,
            "role": role,
            "linux_user": linux_user,
            "uid": uid,
            "autostart_command": autostart,
            "record": record,
            "updated_at": updated_at,
        }),
        None => serde_json::json!({
            "user_id": user_id,
            "email": email,
            "role": role,
            "linux_user": null,
            "uid": null,
            "autostart_command": null,
            "record": null,
            "updated_at": null,
        }),
    }
}

type AccountRow = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<i32>,
    Option<String>,
    Option<bool>,
    Option<chrono::DateTime<chrono::Utc>>,
);

fn row_json(r: &AccountRow) -> serde_json::Value {
    let mapping = match (&r.3, r.4, r.6, r.7) {
        (Some(lu), Some(uid), Some(rec), Some(at)) => {
            Some((lu.as_str(), uid, r.5.as_deref(), rec, at))
        }
        _ => None,
    };
    account_json(r.0, &r.1, &r.2, mapping)
}

const ACCOUNTS_SELECT: &str = "SELECT u.id, u.email, u.role, m.linux_user, m.uid, \
     m.autostart_command, m.record, m.updated_at \
     FROM users u LEFT JOIN user_linux_accounts m ON m.user_id = u.id";

/// GET /api/terminal/user/accounts - a bare JSON array of accounts.
///
/// Every admin account, plus any non-admin that still has a mapping (one that
/// lost the role): such a row opens nothing (B-3 point 5) but must stay
/// visible so it can be unlinked.
pub async fn list_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    AdminUser(claims): AdminUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_session_gate(&claims, &headers)?;
    let rows: Vec<AccountRow> = sqlx::query_as(&format!(
        "{ACCOUNTS_SELECT} WHERE u.role = 'admin' OR m.user_id IS NOT NULL ORDER BY u.email"
    ))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("user terminal accounts", e))?;
    let accounts: Vec<serde_json::Value> = rows.iter().map(row_json).collect();
    Ok(Json(serde_json::Value::Array(accounts)))
}

fn default_autostart() -> Option<String> {
    Some("claude".to_string())
}

#[derive(Deserialize)]
pub struct PutAccountBody {
    pub linux_user: String,
    /// Absent: `"claude"`. `null` or blank: no start command.
    #[serde(default = "default_autostart")]
    pub autostart_command: Option<String>,
    #[serde(default)]
    pub record: bool,
    #[serde(default)]
    pub proof: EnrolmentProof,
}

#[derive(Deserialize, Default)]
pub struct DeleteAccountBody {
    #[serde(default)]
    pub proof: EnrolmentProof,
}

/// An agent 4xx carrying `reasons` (A-2/A-3 refusals) is relayed as
/// `{ "error", "reasons" }` with its status; anything else goes through
/// `agent_error`.
fn agent_refusal(context: &str, e: AgentError) -> ApiError {
    if let AgentError::Status(code, ref body) = e {
        if (400..500).contains(&code) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(reasons) = v.get("reasons").filter(|r| r.is_array()) {
                    let msg = v
                        .get("error")
                        .and_then(|m| m.as_str())
                        .unwrap_or("The agent refused this Linux user");
                    return (
                        StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
                        Json(serde_json::json!({ "error": msg, "reasons": reasons })),
                    );
                }
            }
        }
    }
    agent_error(context, e)
}

fn refusal_with_reasons(msg: &str, reasons: serde_json::Value) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg, "reasons": reasons })),
    )
}

/// Verify the caller's proof (password or TOTP), against the CALLER's account.
async fn require_proof(
    state: &AppState,
    claims: &Claims,
    proof: &EnrolmentProof,
) -> Result<(), ApiError> {
    let user: crate::models::User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|e| internal_error("user terminal proof", e))?;
    require_enrolment_proof(state, claims, &user, proof).await
}

/// PUT /api/terminal/user/accounts/{user_id} -
/// `{ "ok": true, "account": {...}, "check": <A-2>, "warnings": [...] }`.
pub async fn put_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    AdminUser(claims): AdminUser,
    Path(user_id): Path<Uuid>,
    Json(body): Json<PutAccountBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_session_gate(&claims, &headers)?;

    let login = body.linux_user.trim().to_string();
    if !valid_login(&login) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid Linux user name"));
    }
    let autostart = normalise_autostart(body.autostart_command.as_deref())
        .map_err(|m| err(StatusCode::BAD_REQUEST, m))?;

    require_proof(&state, &claims, &body.proof).await?;

    let target: Option<(String, String)> =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("user terminal target", e))?;
    let (target_email, target_role) =
        target.ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;
    if target_role != "admin" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Only administrator accounts can be linked to a Linux user",
        ));
    }

    let taken: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM user_linux_accounts WHERE linux_user = $1 AND user_id <> $2",
    )
    .bind(&login)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("user terminal mapping", e))?;
    if taken.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "This Linux user is already linked to another panel account",
        ));
    }
    let previous = load_mapping(&state, user_id).await?;

    let agent = local_agent(&state);

    // A-2: the agent's verdict on this login. `login` is validated above, so
    // it is safe in the query string.
    let check = agent
        .get(&format!("/terminal/user/check?login={login}"))
        .await
        .map_err(|e| agent_refusal("user terminal check", e))?;
    let reasons = check
        .get("reasons")
        .cloned()
        .filter(|r| r.is_array())
        .unwrap_or_else(|| serde_json::json!([]));
    if check.get("supported").and_then(|v| v.as_bool()) == Some(false) {
        return Err(refusal_with_reasons("Not supported on this server", reasons));
    }
    if check.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(refusal_with_reasons("This Linux user cannot be linked", reasons));
    }
    let uid = check
        .get("uid")
        .and_then(|v| v.as_u64())
        .filter(|u| (1000..60000).contains(u))
        .ok_or_else(|| {
            err(
                StatusCode::BAD_GATEWAY,
                "The agent did not return a usable uid for this Linux user",
            )
        })?;

    // A-3: idempotent preparation.
    let prepared = agent
        .post_long(
            "/terminal/user/prepare",
            Some(serde_json::json!({
                "login": login,
                "uid": uid,
                "autostart_command": autostart,
            })),
            PREPARE_TIMEOUT_SECS,
        )
        .await
        .map_err(|e| agent_refusal("user terminal prepare", e))?;
    let warnings = prepared
        .get("warnings")
        .cloned()
        .filter(|w| w.is_array())
        .unwrap_or_else(|| serde_json::json!([]));

    // `autostart_command` is bound explicitly, so `None` stays NULL instead of
    // taking the column default.
    let saved: Result<(chrono::DateTime<chrono::Utc>,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO user_linux_accounts \
           (user_id, linux_user, uid, autostart_command, record, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (user_id) DO UPDATE SET linux_user = EXCLUDED.linux_user, \
           uid = EXCLUDED.uid, autostart_command = EXCLUDED.autostart_command, \
           record = EXCLUDED.record, updated_at = now() \
         RETURNING updated_at",
    )
    .bind(user_id)
    .bind(&login)
    .bind(uid as i32)
    .bind(&autostart)
    .bind(body.record)
    .bind(claims.sub)
    .fetch_one(&state.db)
    .await;
    let (updated_at,) = match saved {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref d)) if d.is_unique_violation() => {
            return Err(err(
                StatusCode::CONFLICT,
                "This Linux user is already linked to another panel account",
            ));
        }
        Err(e) => return Err(internal_error("user terminal mapping save", e)),
    };

    // Relinked to a different login: the old login's open connections must
    // not outlive the mapping that authorised them.
    if let Some(prev) = previous.filter(|p| p.linux_user != login) {
        spawn_kill_user_terminals(&state, Some(prev.linux_user), false, "mapping changed");
    }

    let details = format!(
        "panel_user={target_email} login={login} uid={uid} record={} autostart={}",
        body.record,
        if autostart.is_some() { "set" } else { "none" }
    );
    security_hardening::audit_log(
        &state.db,
        "user_terminal.mapping_set",
        Some(&claims.email),
        crate::routes::client_ip(&headers).as_deref(),
        Some("user_terminal"),
        Some(&login),
        Some(&details),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "account": account_json(
            user_id,
            &target_email,
            &target_role,
            Some((&login, uid as i32, autostart.as_deref(), body.record, updated_at)),
        ),
        "check": check,
        "warnings": warnings,
    })))
}

/// DELETE /api/terminal/user/accounts/{user_id}, body `{ "proof": {...} }` -
/// `{ "ok": true, "connections_killed": n | null, "warning"?: str }`.
///
/// The linger and the tmux session are left in place (B-4).
pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    AdminUser(claims): AdminUser,
    Path(user_id): Path<Uuid>,
    body: Option<Json<DeleteAccountBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_session_gate(&claims, &headers)?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    require_proof(&state, &claims, &body.proof).await?;

    let mapping = load_mapping(&state, user_id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "No Linux account is linked to this user"))?;

    // A-4 for this login, connections only. An unreachable agent must not keep
    // the mapping alive: without it no new ticket can be minted, which is the
    // part the panel controls.
    let (connections_killed, warning) =
        match kill_user_terminals(&state, Some(&mapping.linux_user), false).await {
            Ok(v) => (v.get("connections_killed").and_then(|n| n.as_u64()), None),
            Err(e) => {
                tracing::warn!("user terminal unlink: kill failed: {e}");
                (
                    None,
                    Some(
                        "The mapping was removed, but open connections of this Linux user \
                         could not be closed (agent unreachable).",
                    ),
                )
            }
        };

    sqlx::query("DELETE FROM user_linux_accounts WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("user terminal unlink", e))?;

    security_hardening::audit_log(
        &state.db,
        "user_terminal.mapping_removed",
        Some(&claims.email),
        crate::routes::client_ip(&headers).as_deref(),
        Some("user_terminal"),
        Some(&mapping.linux_user),
        Some(&format!("panel_user_id={user_id}")),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    let mut resp = serde_json::json!({ "ok": true, "connections_killed": connections_killed });
    if let Some(w) = warning {
        resp["warning"] = serde_json::json!(w);
    }
    Ok(Json(resp))
}

/// GET /api/terminal/user/accounts/{user_id}/check - the agent's A-2 answer for
/// the registered login, relayed unchanged.
pub async fn check_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    AdminUser(claims): AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_session_gate(&claims, &headers)?;
    let mapping = load_mapping(&state, user_id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "No Linux account is linked to this user"))?;
    // Stored logins were validated on the way in; check again before building a path.
    if !valid_login(&mapping.linux_user) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid Linux user name"));
    }
    let check = local_agent(&state)
        .get(&format!("/terminal/user/check?login={}", mapping.linux_user))
        .await
        .map_err(|e| agent_refusal("user terminal check", e))?;
    Ok(Json(check))
}

// ---------------------------------------------------------------------------
// B-5: cuts
// ---------------------------------------------------------------------------

/// A-4 on the local agent, bounded. `login: None` means every login.
pub async fn kill_user_terminals(
    state: &AppState,
    login: Option<&str>,
    stop_sessions: bool,
) -> Result<serde_json::Value, AgentError> {
    let agent = local_agent(state);
    let call = agent.post_long(
        "/terminal/user/kill",
        Some(serde_json::json!({ "stop_sessions": stop_sessions, "login": login })),
        KILL_TIMEOUT_SECS,
    );
    match tokio::time::timeout(Duration::from_secs(KILL_TIMEOUT_SECS + 5), call).await {
        Ok(r) => r,
        Err(_) => Err(AgentError::Request(format!(
            "user terminal kill timed out after {KILL_TIMEOUT_SECS}s"
        ))),
    }
}

/// Fire-and-forget A-4, for callers that must not wait on the agent
/// (lockdown activation, the settings switch, a relink).
pub fn spawn_kill_user_terminals(
    state: &AppState,
    login: Option<String>,
    stop_sessions: bool,
    why: &'static str,
) {
    let state = state.clone();
    tokio::spawn(async move {
        match kill_user_terminals(&state, login.as_deref(), stop_sessions).await {
            Ok(v) => tracing::info!(
                "user terminals cut ({why}): {} connection(s)",
                v.get("connections_killed").and_then(|n| n.as_u64()).unwrap_or(0)
            ),
            // An agent predating the user terminal has none to cut.
            Err(AgentError::Status(404, _)) => {
                tracing::debug!("user terminal kill ({why}): agent has no such route")
            }
            Err(e) => tracing::warn!("user terminal kill ({why}) failed: {e}"),
        }
    });
}

/// The user-terminal count in a `kill-terminals` answer (A-4: a recent agent
/// adds `user_terminals_killed`), whether given as a number or as A-4's own
/// object.
pub fn user_terminals_in(v: &serde_json::Value) -> Option<u64> {
    let f = v.get("user_terminals_killed")?;
    f.as_u64()
        .or_else(|| f.get("connections_killed").and_then(|n| n.as_u64()))
}

/// The panic's `user_terminals_killed`: the local `kill-terminals` count plus
/// the A-4 call's `connections_killed`; `None` when neither answered.
pub fn combine_user_kills(from_kill_terminals: Option<u64>, from_a4: Option<u64>) -> Option<u64> {
    match (from_kill_terminals, from_a4) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    }
}

// ---------------------------------------------------------------------------
// B-6: GET /api/security/user-terminal-events?limit=
// ---------------------------------------------------------------------------

pub fn clamp_limit(raw: Option<&String>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(100)
        .clamp(1, 500)
}

/// GET /api/security/user-terminal-events?limit= - the agent's
/// `user_terminal.*` audit lines (`GET /terminal/user/events`), relayed.
pub async fn events(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = clamp_limit(params.get("limit"));
    let v = local_agent(&state)
        .get(&format!("/terminal/user/events?limit={limit}"))
        .await
        .map_err(|e| agent_error("user terminal events", e))?;
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context that passes every check.
    fn ok_ctx() -> TicketContext {
        TicketContext {
            locked_down: false,
            disabled: false,
            local: true,
            api_key: false,
            session_cookie: true,
            impersonating: false,
            db_role: Some("admin".into()),
            amr: Some("mfa".into()),
            linked: true,
        }
    }

    fn denial(ctx: TicketContext) -> Denial {
        user_ticket_decision(&ctx).unwrap_err()
    }

    #[test]
    fn a_linked_mfa_admin_browser_session_passes() {
        assert_eq!(user_ticket_decision(&ok_ctx()), Ok(()));
    }

    #[test]
    fn each_refusal_has_its_contract_status() {
        let cases: Vec<(TicketContext, Denial, u16)> = vec![
            (TicketContext { locked_down: true, ..ok_ctx() }, Denial::LockedDown, 503),
            (TicketContext { disabled: true, ..ok_ctx() }, Denial::Disabled, 403),
            (TicketContext { local: false, ..ok_ctx() }, Denial::NotLocal, 501),
            (TicketContext { api_key: true, ..ok_ctx() }, Denial::BrowserSessionRequired, 403),
            (TicketContext { session_cookie: false, ..ok_ctx() }, Denial::BrowserSessionRequired, 403),
            (TicketContext { impersonating: true, ..ok_ctx() }, Denial::BrowserSessionRequired, 403),
            (TicketContext { db_role: Some("user".into()), ..ok_ctx() }, Denial::AdminRequired, 403),
            (TicketContext { db_role: Some("reseller".into()), ..ok_ctx() }, Denial::AdminRequired, 403),
            (TicketContext { db_role: None, ..ok_ctx() }, Denial::AdminRequired, 403),
            (TicketContext { amr: None, ..ok_ctx() }, Denial::MfaRequired, 403),
            (TicketContext { amr: Some("pwd".into()), ..ok_ctx() }, Denial::MfaRequired, 403),
            (TicketContext { amr: Some("oauth".into()), ..ok_ctx() }, Denial::MfaRequired, 403),
            (TicketContext { linked: false, ..ok_ctx() }, Denial::NotLinked, 404),
        ];
        for (ctx, want, status) in cases {
            let got = denial(ctx.clone());
            assert_eq!(got, want, "{ctx:?}");
            assert_eq!(got.status().as_u16(), status, "{ctx:?}");
        }
    }

    #[test]
    fn checks_run_in_contract_order() {
        // Everything wrong at once: each fix reveals the next check in order.
        let mut ctx = TicketContext {
            locked_down: true,
            disabled: true,
            local: false,
            api_key: true,
            session_cookie: false,
            impersonating: true,
            db_role: Some("user".into()),
            amr: None,
            linked: false,
        };
        let order = [
            Denial::LockedDown,
            Denial::Disabled,
            Denial::NotLocal,
            Denial::BrowserSessionRequired,
            Denial::AdminRequired,
            Denial::MfaRequired,
            Denial::NotLinked,
        ];
        for want in order {
            assert_eq!(denial(ctx.clone()), want);
            match want {
                Denial::LockedDown => ctx.locked_down = false,
                Denial::Disabled => ctx.disabled = false,
                Denial::NotLocal => ctx.local = true,
                Denial::BrowserSessionRequired => {
                    ctx.api_key = false;
                    ctx.session_cookie = true;
                    ctx.impersonating = false;
                }
                Denial::AdminRequired => ctx.db_role = Some("admin".into()),
                Denial::MfaRequired => ctx.amr = Some("mfa".into()),
                Denial::NotLinked => ctx.linked = true,
            }
        }
        assert_eq!(user_ticket_decision(&ctx), Ok(()));
    }

    #[test]
    fn a_dp_key_is_refused_even_for_a_linked_mfa_admin() {
        // A stolen `dp_` key - even the admin's own - never gets a ticket.
        let ctx = TicketContext { api_key: true, session_cookie: false, amr: None, ..ok_ctx() };
        assert_eq!(denial(ctx), Denial::BrowserSessionRequired);
    }

    #[test]
    fn the_jwt_role_is_not_trusted() {
        // db_role is what the database says now; a demoted admin is refused.
        let ctx = TicketContext { db_role: Some("user".into()), ..ok_ctx() };
        assert_eq!(denial(ctx), Denial::AdminRequired);
    }

    #[test]
    fn denial_bodies_carry_message_and_code() {
        let e = Denial::MfaRequired.to_api_error();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert_eq!(e.1 .0["code"], "mfa_required");
        let e = Denial::Disabled.to_api_error();
        assert_eq!(e.1 .0["error"], "User terminal is disabled");
        let e = Denial::BrowserSessionRequired.to_api_error();
        assert_eq!(e.1 .0["error"], "A browser session is required");
        let e = Denial::NotLinked.to_api_error();
        assert_eq!(e.1 .0["error"], "No Linux account is linked to your panel account");
        // Never the code that sends the frontend to /login.
        for d in [
            Denial::LockedDown,
            Denial::Disabled,
            Denial::NotLocal,
            Denial::BrowserSessionRequired,
            Denial::AdminRequired,
            Denial::MfaRequired,
            Denial::NotLinked,
        ] {
            assert_ne!(d.code(), crate::error::CODE_SESSION_INVALID);
            assert!(!d.message().contains('\u{2014}'), "no em dash in UI text");
        }
    }

    #[test]
    fn session_gate_checks_only_points_4_and_6() {
        let ctx = TicketContext {
            locked_down: true,
            disabled: true,
            local: false,
            db_role: None,
            linked: false,
            ..ok_ctx()
        };
        assert_eq!(session_gate(&ctx), Ok(()));
        assert_eq!(
            session_gate(&TicketContext { impersonating: true, ..ok_ctx() }),
            Err(Denial::BrowserSessionRequired)
        );
        assert_eq!(
            session_gate(&TicketContext { api_key: true, ..ok_ctx() }),
            Err(Denial::BrowserSessionRequired)
        );
        assert_eq!(
            session_gate(&TicketContext { amr: Some("pwd".into()), ..ok_ctx() }),
            Err(Denial::MfaRequired)
        );
    }

    #[test]
    fn session_cookie_means_cookie_without_bearer() {
        use axum::http::{header, HeaderValue};
        let mut h = HeaderMap::new();
        assert!(!has_session_cookie(&h));
        h.insert(header::COOKIE, HeaderValue::from_static("a=b; token=JWT"));
        assert!(has_session_cookie(&h));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer OTHER"));
        assert!(!has_session_cookie(&h), "claims came from the Bearer, not the cookie");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("token_admin=JWT"));
        assert!(!has_session_cookie(&h));
    }

    #[test]
    fn ticket_carries_scope_uid_jti_and_a_60s_expiry() {
        let m = Mapping { linux_user: "bastien".into(), uid: 1000, record: false };
        let now = 1_800_000_000;
        let t = build_ticket("admin@example.com", &m, now);
        assert_eq!(t.sub, "admin@example.com");
        assert_eq!(t.purpose, "terminal");
        assert_eq!(t.scope, "@user:bastien");
        assert!(t.scope.starts_with(USER_SCOPE_PREFIX));
        assert_eq!(t.uid, 1000);
        assert!(!t.record, "record is the mapping's, false by default");
        assert_eq!(t.exp, (now + 60) as usize);
        let jti = Uuid::parse_str(&t.jti).unwrap();
        assert_eq!(jti.get_version_num(), 4);
        // A fresh jti every time.
        assert_ne!(build_ticket("a", &m, now).jti, build_ticket("a", &m, now).jti);
        // `record` follows the mapping.
        let rec = Mapping { record: true, ..m };
        assert!(build_ticket("a", &rec, now).record);
    }

    #[test]
    fn ticket_verifies_with_the_agent_key_and_has_every_claim() {
        let m = Mapping { linux_user: "bastien".into(), uid: 1001, record: false };
        let now = chrono::Utc::now().timestamp();
        let t = build_ticket("admin@example.com", &m, now);
        let tok = encode(&Header::default(), &t, &EncodingKey::from_secret(b"agent-key")).unwrap();
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.set_required_spec_claims(&["exp", "sub"]);
        let back = jsonwebtoken::decode::<serde_json::Value>(
            &tok,
            &jsonwebtoken::DecodingKey::from_secret(b"agent-key"),
            &v,
        )
        .unwrap()
        .claims;
        for k in ["sub", "purpose", "exp", "record", "scope", "uid", "jti"] {
            assert!(back.get(k).is_some(), "missing claim {k}");
        }
        assert_eq!(back["uid"], 1001);
        assert!(jsonwebtoken::decode::<serde_json::Value>(
            &tok,
            &jsonwebtoken::DecodingKey::from_secret(b"other"),
            &v
        )
        .is_err());
    }

    #[test]
    fn me_reports_availability_and_the_reason() {
        let m = Mapping { linux_user: "bastien".into(), uid: 1000, record: false };
        let v = me_body(&ok_ctx(), Some(&m));
        assert_eq!(v["linked"], true);
        assert_eq!(v["login"], "bastien");
        assert_eq!(v["available"], true);
        assert!(v["reason"].is_null() && v["code"].is_null());

        let v = me_body(&TicketContext { amr: Some("pwd".into()), ..ok_ctx() }, Some(&m));
        assert_eq!(v["available"], false);
        assert_eq!(v["reason"], "mfa_required");
        assert_eq!(v["code"], "mfa_required");

        let v = me_body(&TicketContext { linked: false, ..ok_ctx() }, None);
        assert_eq!(v["linked"], false);
        assert!(v["login"].is_null());
        assert_eq!(v["available"], false);
        assert_eq!(v["code"], "not_linked");
        assert_eq!(v["reason"], "No Linux account is linked to your panel account");
    }

    #[test]
    fn login_validation_matches_the_agent_regex() {
        for ok in ["bastien", "_svc", "a", "a-b_c9", &"a".repeat(32)] {
            assert!(valid_login(ok), "{ok}");
        }
        for bad in [
            "", "Root", "9abc", "-x", "a b", "a/b", "a;b", "a?login=root", "é", &"a".repeat(33),
            "a\n", "a.b",
        ] {
            assert!(!valid_login(bad), "{bad:?}");
        }
    }

    #[test]
    fn autostart_is_normalised_and_bounded() {
        assert_eq!(normalise_autostart(None), Ok(None));
        assert_eq!(normalise_autostart(Some("  ")), Ok(None));
        assert_eq!(normalise_autostart(Some(" claude ")), Ok(Some("claude".into())));
        assert!(normalise_autostart(Some(&"x".repeat(200))).is_ok());
        assert!(normalise_autostart(Some(&"x".repeat(201))).is_err());
        assert!(normalise_autostart(Some("claude\nrm -rf ~")).is_err());
        assert!(normalise_autostart(Some("claude\u{7}")).is_err());
    }

    #[test]
    fn put_body_defaults_and_explicit_null() {
        let b: PutAccountBody = serde_json::from_str(r#"{"linux_user":"bastien"}"#).unwrap();
        assert_eq!(b.autostart_command.as_deref(), Some("claude"));
        assert!(!b.record);
        assert!(b.proof.code.is_none() && b.proof.current_password.is_none());
        let b: PutAccountBody = serde_json::from_str(
            r#"{"linux_user":"bastien","autostart_command":null,"record":true,"proof":{"code":"123456"}}"#,
        )
        .unwrap();
        assert!(b.autostart_command.is_none(), "explicit null stays null");
        assert!(b.record);
        assert_eq!(b.proof.code.as_deref(), Some("123456"));
        let d: DeleteAccountBody =
            serde_json::from_str(r#"{"proof":{"current_password":"x"}}"#).unwrap();
        assert_eq!(d.proof.current_password.as_deref(), Some("x"));
    }

    #[test]
    fn agent_refusals_with_reasons_are_relayed() {
        let e = agent_refusal(
            "t",
            AgentError::Status(
                403,
                r#"{"error":"Login refused","reasons":["root is not allowed"]}"#.into(),
            ),
        );
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert_eq!(e.1 .0["error"], "Login refused");
        assert_eq!(e.1 .0["reasons"][0], "root is not allowed");
        // Without reasons it is an ordinary agent error.
        let e = agent_refusal("t", AgentError::Status(400, r#"{"error":"Invalid login"}"#.into()));
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert!(e.1 .0.get("reasons").is_none());
    }

    #[test]
    fn panic_user_kill_counts_combine() {
        assert_eq!(combine_user_kills(None, None), None);
        assert_eq!(combine_user_kills(Some(2), None), Some(2));
        assert_eq!(combine_user_kills(None, Some(0)), Some(0));
        assert_eq!(combine_user_kills(Some(2), Some(1)), Some(3));
        assert_eq!(user_terminals_in(&serde_json::json!({"user_terminals_killed": 3})), Some(3));
        assert_eq!(
            user_terminals_in(&serde_json::json!({"user_terminals_killed": {"connections_killed": 2}})),
            Some(2)
        );
        assert_eq!(user_terminals_in(&serde_json::json!({"killed": 4})), None);
    }

    #[test]
    fn events_limit_is_clamped() {
        assert_eq!(clamp_limit(None), 100);
        assert_eq!(clamp_limit(Some(&"0".to_string())), 1);
        assert_eq!(clamp_limit(Some(&"50".to_string())), 50);
        assert_eq!(clamp_limit(Some(&"100000".to_string())), 500);
        assert_eq!(clamp_limit(Some(&"5&login=root".to_string())), 100);
    }

    #[test]
    fn migration_constrains_uid_and_seeds_the_switch() {
        let sql = include_str!("../../migrations/20261123000000_user_terminal.sql");
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS user_linux_accounts"));
        assert!(sql.contains("CHECK (uid >= 1000 AND uid < 60000)"));
        assert!(sql.contains("linux_user text NOT NULL UNIQUE"));
        assert!(sql.contains("record boolean NOT NULL DEFAULT false"));
        assert!(sql.contains("REFERENCES users(id) ON DELETE CASCADE"));
        assert!(sql.contains("('user_terminal_disabled', 'false')"));
        assert!(sql.contains("ON CONFLICT (key) DO NOTHING"));
    }

    #[test]
    fn the_switch_is_a_settable_key() {
        assert!(crate::routes::settings::ALLOWED_KEYS.contains(&"user_terminal_disabled"));
    }

    // ── amr: one test per sign-in path (B-2) ──

    fn user(totp: bool) -> crate::models::User {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "email": "admin@example.com",
            "password_hash": "",
            "role": "admin",
            "email_verified": true,
            "totp_enabled": totp,
            "created_at": chrono::Utc::now(),
            "updated_at": chrono::Utc::now(),
        }))
        .expect("User test fixture")
    }

    fn amr_of(method: crate::auth::AuthMethod) -> Option<String> {
        crate::routes::auth::session_claims(&user(false), method, 1_800_000_000, "j".into()).amr
    }

    #[test]
    fn amr_password_sign_in_is_pwd() {
        assert_eq!(amr_of(crate::auth::AuthMethod::Password).as_deref(), Some("pwd"));
        // The password door passes Password, and only after the TOTP branch.
        let src = include_str!("auth.rs");
        assert!(src.contains("issue_session(&state, &user, &headers, AuthMethod::Password)"));
    }

    #[test]
    fn amr_two_factor_verify_is_mfa() {
        assert_eq!(amr_of(crate::auth::AuthMethod::Mfa).as_deref(), Some("mfa"));
        let src = include_str!("auth.rs");
        assert!(src.contains("issue_session(&state, &user, &headers, AuthMethod::Mfa)"));
    }

    #[test]
    fn amr_passkey_sign_in_is_mfa() {
        let src = include_str!("passkeys.rs");
        assert!(src.contains("issue_session_pub(&state, &user, &headers, crate::auth::AuthMethod::Mfa)"));
    }

    #[test]
    fn amr_oauth_sign_in_is_oauth() {
        assert_eq!(amr_of(crate::auth::AuthMethod::OAuth).as_deref(), Some("oauth"));
        let src = include_str!("oauth.rs");
        assert!(src.contains("crate::auth::AuthMethod::OAuth"));
    }

    #[test]
    fn session_claims_are_an_ordinary_two_hour_session() {
        let u = user(true);
        let c = crate::routes::auth::session_claims(
            &u,
            crate::auth::AuthMethod::Mfa,
            1_800_000_000,
            "jti-1".into(),
        );
        assert_eq!(c.sub, u.id);
        assert_eq!(c.exp - c.iat, 7200);
        assert_eq!(c.jti.as_deref(), Some("jti-1"));
        assert!(c.key_id.is_none() && c.imp_by.is_none() && c.imp_email.is_none());
    }

    #[test]
    fn ws_token_is_unchanged_byte_for_byte() {
        // Design §9: the existing ticket route must not move. Fingerprint of
        // `ws_token` (from its signature to the next item's doc comment),
        // taken on `main` before feature 9.
        use sha2::{Digest, Sha256};
        let src = include_str!("terminal.rs").replace('\r', "");
        let start = src.find("pub async fn ws_token(").expect("ws_token present");
        let end = src.find("/// A share's stated lifetime").expect("marker present");
        let digest = hex::encode(Sha256::digest(src[start..end].as_bytes()));
        assert_eq!(
            digest,
            "2bb03d3b1a835ec927cd3154c1f863cc90f9545dca641899dc24b3625868872d"
        );
    }

    #[test]
    fn impersonation_sessions_carry_no_amr() {
        let src = include_str!("impersonation.rs");
        assert!(src.contains("imp_by: Some(claims.sub),"));
        assert!(src.contains("amr: None,"));
    }
}
