//! "Login as user" - an administrator opens a session AS another account
//! (feature 3, conception/03-login-as-user.md, contracts in
//! conception/03-login-as-user-contrats.md).
//!
//! The shape, and the one property everything here protects:
//!
//! - `start` mints a 1 h session JWT for the TARGET (`sub`/`email`/`role` are
//!   the target's, read from the database) carrying `imp_by`/`imp_email` = the
//!   admin. Every ownership check in the panel keys off `sub`, so that session
//!   sees exactly what the target sees, and nothing more.
//! - The admin's own cookie is set aside, verbatim, in `token_admin`, scoped to
//!   `Path=/api/auth/impersonate` so the browser only ever sends it to `stop`.
//! - `stop` revokes the target session and puts the admin's ORIGINAL cookie
//!   back after re-validating it. It never signs a new admin token: a stolen
//!   impersonation token is worth exactly the target account, never an admin
//!   session, because `imp_by` is not a credential - it is only a label.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Response},
    Json,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

use crate::auth::{
    bearer_token, decode_session_jwt, read_cookie, session_jwt_from_headers, AdminUser, AuthUser,
    Claims,
};
use crate::error::{err, internal_error, ApiError};
use crate::routes::auth::{cookie_secure_flag, enforce_panel_ip_allowlist};
use crate::services::{activity, security_hardening};
use crate::AppState;

/// Lifetime of an impersonation session. Not extendable: there is no refresh.
pub const IMPERSONATION_TTL_SECS: i64 = 3600;

/// Name of the cookie holding the admin's own, untouched session token.
pub const ADMIN_STASH_COOKIE: &str = "token_admin";

/// The only path the browser sends `token_admin` to (it covers `/stop`).
pub const ADMIN_STASH_PATH: &str = "/api/auth/impersonate";

// ── Pure decisions (unit-tested below) ──────────────────────────────────

/// Decide whether `caller` may start acting as the user `target_id`, whose
/// database role is `target_role` (`None` = no such user).
///
/// `is_browser_cookie_session` must be true only when the session that
/// authenticated this request IS the `token` cookie: a JWT cookie present and
/// no `Authorization` header (which `AuthUser` would have preferred). It is the
/// cookie that gets stashed, so it must be the admin's real session.
///
/// Order is the contract's (B1): session kind, nesting, self, existence, then
/// the target's role. The nesting refusal is also the defense-in-depth asked
/// for in B4 (an impersonation session never holds the admin role anyway).
pub fn check_start_allowed(
    caller: &Claims,
    is_browser_cookie_session: bool,
    target_id: Uuid,
    target_role: Option<&str>,
) -> Result<(), ApiError> {
    if caller.key_id.is_some() || !is_browser_cookie_session {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Logging in as another user requires a browser session",
        ));
    }
    if caller.imp_by.is_some() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Already logged in as another user - return to your account first",
        ));
    }
    if target_id == caller.sub {
        return Err(err(StatusCode::BAD_REQUEST, "Cannot log in as yourself"));
    }
    match target_role {
        None => Err(err(StatusCode::NOT_FOUND, "User not found")),
        Some("admin") => Err(err(
            StatusCode::FORBIDDEN,
            "Cannot log in as another administrator",
        )),
        Some("suspended") => Err(err(
            StatusCode::FORBIDDEN,
            "Cannot log in as a suspended account",
        )),
        Some(_) => Ok(()),
    }
}

/// Whether the stashed admin token (`token_admin`, already signature- and
/// expiry-checked by `decode_session_jwt`) may be handed back as the session
/// of the admin `imp_by` who started this impersonation.
///
/// Same checks `AuthUser` makes (blacklist, global revocation, expiry), plus:
/// it must belong to that very admin, be an ordinary JWT session (no nested
/// `imp_by`, no API key, a `jti` so it stays revocable), and the account must
/// still be an administrator in the database - not merely in the token.
pub fn admin_stash_acceptable(
    stash: &Claims,
    imp_by: Uuid,
    now: i64,
    sessions_revoked_at: Option<i64>,
    blacklisted: bool,
    db_role: Option<&str>,
) -> bool {
    stash.sub == imp_by
        && stash.imp_by.is_none()
        && stash.key_id.is_none()
        && stash.jti.is_some()
        && stash.role == "admin"
        && db_role == Some("admin")
        && !blacklisted
        && sessions_revoked_at.is_none_or(|ts| stash.iat as i64 >= ts)
        && (stash.exp as i64) > now
}

/// `(admin id, admin email)` when the request's session JWT is an
/// impersonation session. Signature and expiry are verified so a forged token
/// cannot stamp attribution on rows written before authentication (failed
/// logins and the like); everything else is left to `AuthUser`.
pub fn impersonator_from_headers(jwt_secret: &str, headers: &HeaderMap) -> Option<(Uuid, String)> {
    let token = session_jwt_from_headers(headers)?;
    let claims = decode_session_jwt(jwt_secret, &token)?;
    claims
        .imp_by
        .map(|id| (id, claims.imp_email.unwrap_or_default()))
}

/// The `token` session cookie, same attributes as `issue_session_pub`.
pub fn session_cookie(token: &str, max_age: i64, secure_flag: &str) -> String {
    format!("token={token}; Path=/; HttpOnly{secure_flag}; SameSite=Lax; Max-Age={max_age}")
}

/// The `token_admin` cookie: Strict and path-scoped so it travels only to
/// `POST /api/auth/impersonate/stop`, never with ordinary requests.
pub fn admin_stash_cookie(value: &str, max_age: i64, secure_flag: &str) -> String {
    format!(
        "{ADMIN_STASH_COOKIE}={value}; Path={ADMIN_STASH_PATH}; HttpOnly{secure_flag}; SameSite=Strict; Max-Age={max_age}"
    )
}

/// A 200 JSON response carrying every cookie as its own `Set-Cookie` header.
/// Appended, not inserted: a header array part would keep only the last one.
fn with_cookies(cookies: Vec<String>, body: serde_json::Value) -> Response {
    let headers: Vec<_> = cookies.into_iter().map(|c| (header::SET_COOKIE, c)).collect();
    (StatusCode::OK, AppendHeaders(headers), Json(body)).into_response()
}

// ── Handlers ────────────────────────────────────────────────────────────

/// POST /api/users/{id}/impersonate - start acting as user `id` (admin only).
pub async fn start(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let admin_cookie = read_cookie(&headers, "token").filter(|v| !v.is_empty());
    let is_browser_cookie_session = admin_cookie.is_some() && bearer_token(&headers).is_none();

    let target: Option<(String, String)> =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("impersonate lookup", e))?;

    check_start_allowed(
        &claims,
        is_browser_cookie_session,
        id,
        target.as_ref().map(|(_, role)| role.as_str()),
    )?;
    let (Some((target_email, target_role)), Some(admin_cookie)) = (target, admin_cookie) else {
        // Unreachable: check_start_allowed refused both cases above.
        return Err(err(StatusCode::NOT_FOUND, "User not found"));
    };

    // A door that mints a session, like every other one.
    enforce_panel_ip_allowlist(&state.db, &headers).await?;
    // Lockdown keeps non-admins out of the panel; acting as one would bypass it.
    if crate::services::security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::FORBIDDEN, "Panel is in lockdown: logging in as a user is disabled"));
    }

    let now = chrono::Utc::now().timestamp();
    let expires_at = now + IMPERSONATION_TTL_SECS;
    let jti = Uuid::new_v4().to_string();
    let target_claims = Claims {
        sub: id,
        email: target_email.clone(),
        role: target_role.clone(),
        iat: now as usize,
        exp: expires_at as usize,
        jti: Some(jti.clone()),
        key_id: None,
        imp_by: Some(claims.sub),
        imp_email: Some(claims.email.clone()),
    };
    let token = encode(
        &Header::default(),
        &target_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| internal_error("impersonate token", e))?;

    // NOT best-effort, unlike the login doors: every revocation path (the
    // target suspended or deleted, the admin demoted - revoke_all_user_sessions)
    // reaches a session only through its row. No row, no cookie.
    let ip = crate::routes::client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    sqlx::query(
        "INSERT INTO user_sessions (user_id, jti, ip_address, user_agent, impersonator_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&jti)
    .bind(&ip)
    .bind(&user_agent)
    .bind(claims.sub)
    .execute(&state.db)
    .await
    .map_err(|e| internal_error("impersonate session", e))?;

    let until = chrono::DateTime::from_timestamp(expires_at as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires_at.to_string());
    let details = format!("as {target_email} ({target_role}) until {until}");
    security_hardening::audit_log(
        &state.db, "impersonate.start", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&target_email), Some(&details), None, "warning", None,
    ).await;
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.impersonate",
        Some("user"), Some(&target_email), Some(&details), ip.as_deref(), None,
    ).await;
    tracing::info!("Admin {} is now acting as {}", claims.email, target_email);

    let secure = cookie_secure_flag(&headers);
    let admin_remaining = (claims.exp as i64 - now).max(1);
    Ok(with_cookies(
        vec![
            session_cookie(&token, IMPERSONATION_TTL_SECS, secure),
            admin_stash_cookie(&admin_cookie, admin_remaining, secure),
        ],
        serde_json::json!({
            "user": { "id": id, "email": target_email, "role": target_role },
            "impersonated_by": { "id": claims.sub, "email": claims.email },
            "expires_at": expires_at,
        }),
    ))
}

/// POST /api/auth/impersonate/stop - end the impersonation and return to the
/// admin's own session when it is still valid.
pub async fn stop(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(imp_by) = claims.imp_by else {
        return Err(err(StatusCode::BAD_REQUEST, "Not logged in as another user"));
    };
    Ok(end_impersonation(&state, &claims, imp_by, &headers).await)
}

/// Shared by `stop` and by `logout` during an impersonation session (B2).
///
/// Note: `token_admin` is path-scoped to `/api/auth/impersonate`, so a call
/// arriving through `/api/auth/logout` never carries it and always answers
/// `restored: false` - the cookie is still cleared.
pub(crate) async fn end_impersonation(
    state: &AppState,
    claims: &Claims,
    imp_by: Uuid,
    headers: &HeaderMap,
) -> Response {
    // 1. The impersonation token dies first, whatever happens next.
    if let Some(ref jti) = claims.jti {
        state.token_blacklist.write().await.insert(jti.clone());
        if let Err(e) = sqlx::query(
            "INSERT INTO token_blacklist (jti, expires_at) VALUES ($1, NOW() + INTERVAL '2 hours') ON CONFLICT DO NOTHING",
        )
        .bind(jti)
        .execute(&state.db)
        .await
        {
            tracing::error!("impersonation stop: persist blacklist failed: {e}");
        }
        if let Err(e) = sqlx::query("DELETE FROM user_sessions WHERE jti = $1")
            .bind(jti)
            .execute(&state.db)
            .await
        {
            tracing::error!("impersonation stop: delete session row failed: {e}");
        }
    }

    // 2. Hand back the admin's ORIGINAL cookie if it still passes - never a
    //    freshly signed one.
    let restored = match read_cookie(headers, ADMIN_STASH_COOKIE).filter(|v| !v.is_empty()) {
        Some(raw) => validate_admin_stash(state, &raw, imp_by).await.map(|left| (raw, left)),
        None => None,
    };

    let secure = cookie_secure_flag(headers);
    let mut cookies = vec![match &restored {
        Some((raw, left)) => session_cookie(raw, *left, secure),
        None => session_cookie("", 0, secure),
    }];
    cookies.push(admin_stash_cookie("", 0, secure));

    // 3. Logged as the admin (like the start), not as "admin acting as user".
    let admin_email = claims.imp_email.clone().unwrap_or_default();
    let ip = crate::routes::client_ip(headers);
    let details = format!("restored: {}", restored.is_some());
    activity::IMPERSONATOR
        .scope(None, async {
            security_hardening::audit_log(
                &state.db, "impersonate.stop", Some(&admin_email), ip.as_deref(),
                Some("user"), Some(&claims.email), Some(&details), None, "info", None,
            ).await;
            activity::log_activity(
                &state.db, imp_by, &admin_email, "user.impersonate.stop",
                Some("user"), Some(&claims.email), Some(&details), ip.as_deref(), None,
            ).await;
        })
        .await;

    with_cookies(cookies, serde_json::json!({ "restored": restored.is_some() }))
}

/// Decode and re-validate the stashed admin token. `Some(seconds left)` when it
/// may be restored as-is.
async fn validate_admin_stash(state: &AppState, raw: &str, imp_by: Uuid) -> Option<i64> {
    let stash = decode_session_jwt(&state.config.jwt_secret, raw)?;
    let blacklisted = match stash.jti {
        Some(ref jti) => state.token_blacklist.read().await.contains(jti),
        None => false,
    };
    let revoked_at = *state.sessions_revoked_at.read().await;
    let db_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = $1")
        .bind(stash.sub)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let now = chrono::Utc::now().timestamp();
    admin_stash_acceptable(
        &stash,
        imp_by,
        now,
        revoked_at,
        blacklisted,
        db_role.as_ref().map(|(r,)| r.as_str()),
    )
    .then(|| stash.exp as i64 - now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const NOW: i64 = 1_800_000_000;

    fn admin() -> Claims {
        Claims {
            sub: Uuid::new_v4(),
            email: "admin@example.com".into(),
            role: "admin".into(),
            exp: (NOW + 3000) as usize,
            iat: (NOW - 100) as usize,
            jti: Some("admin-jti".into()),
            key_id: None,
            imp_by: None,
            imp_email: None,
        }
    }

    fn status(r: Result<(), ApiError>) -> Option<StatusCode> {
        r.err().map(|e| e.0)
    }

    // ── check_start_allowed ──

    #[test]
    fn an_admin_browser_session_may_act_as_a_user() {
        let a = admin();
        for role in ["user", "client", "reseller"] {
            assert!(check_start_allowed(&a, true, Uuid::new_v4(), Some(role)).is_ok(), "{role}");
        }
    }

    #[test]
    fn an_api_key_or_non_cookie_session_is_refused_400() {
        let mut a = admin();
        assert_eq!(status(check_start_allowed(&a, false, Uuid::new_v4(), Some("user"))), Some(StatusCode::BAD_REQUEST));
        a.key_id = Some(Uuid::new_v4());
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), Some("user"))), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn nesting_is_refused_400() {
        let mut a = admin();
        a.imp_by = Some(Uuid::new_v4());
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), Some("user"))), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn self_is_refused_400() {
        let a = admin();
        assert_eq!(status(check_start_allowed(&a, true, a.sub, Some("admin"))), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn another_admin_or_a_suspended_account_is_refused_403() {
        let a = admin();
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), Some("admin"))), Some(StatusCode::FORBIDDEN));
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), Some("suspended"))), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn an_unknown_target_is_404() {
        let a = admin();
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), None)), Some(StatusCode::NOT_FOUND));
    }

    #[test]
    fn the_session_kind_is_checked_before_the_target() {
        // An API key must not learn whether an id exists.
        let mut a = admin();
        a.key_id = Some(Uuid::new_v4());
        assert_eq!(status(check_start_allowed(&a, true, Uuid::new_v4(), None)), Some(StatusCode::BAD_REQUEST));
    }

    // ── admin_stash_acceptable ──

    #[test]
    fn the_admins_own_live_token_is_restorable() {
        let a = admin();
        assert!(admin_stash_acceptable(&a, a.sub, NOW, None, false, Some("admin")));
        assert!(admin_stash_acceptable(&a, a.sub, NOW, Some(NOW - 100), false, Some("admin")));
    }

    #[test]
    fn a_token_of_someone_else_is_never_restored() {
        let a = admin();
        assert!(!admin_stash_acceptable(&a, Uuid::new_v4(), NOW, None, false, Some("admin")));
    }

    #[test]
    fn a_demoted_or_deleted_admin_is_not_restored() {
        let a = admin();
        assert!(!admin_stash_acceptable(&a, a.sub, NOW, None, false, Some("user")));
        assert!(!admin_stash_acceptable(&a, a.sub, NOW, None, false, Some("suspended")));
        assert!(!admin_stash_acceptable(&a, a.sub, NOW, None, false, None));
        let mut stale = admin();
        stale.role = "user".into();
        assert!(!admin_stash_acceptable(&stale, stale.sub, NOW, None, false, Some("admin")));
    }

    #[test]
    fn a_revoked_or_expired_token_is_not_restored() {
        let a = admin();
        assert!(!admin_stash_acceptable(&a, a.sub, NOW, None, true, Some("admin")), "blacklisted");
        assert!(!admin_stash_acceptable(&a, a.sub, NOW, Some(NOW), false, Some("admin")), "revoke-all after iat");
        assert!(!admin_stash_acceptable(&a, a.sub, NOW + 3000, None, false, Some("admin")), "expired");
    }

    #[test]
    fn an_impersonation_or_api_key_or_jti_less_token_is_not_restored() {
        let mut nested = admin();
        nested.imp_by = Some(Uuid::new_v4());
        assert!(!admin_stash_acceptable(&nested, nested.sub, NOW, None, false, Some("admin")));
        let mut key = admin();
        key.key_id = Some(Uuid::new_v4());
        assert!(!admin_stash_acceptable(&key, key.sub, NOW, None, false, Some("admin")));
        let mut no_jti = admin();
        no_jti.jti = None;
        assert!(!admin_stash_acceptable(&no_jti, no_jti.sub, NOW, None, false, Some("admin")));
    }

    // ── cookies ──

    #[test]
    fn the_session_cookie_matches_the_login_cookie() {
        assert_eq!(
            session_cookie("abc", 3600, ""),
            "token=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
        );
        assert_eq!(
            session_cookie("", 0, "; Secure"),
            "token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn the_admin_stash_cookie_is_strict_and_scoped_to_the_return_route() {
        let c = admin_stash_cookie("xyz", 1234, "; Secure");
        assert_eq!(
            c,
            "token_admin=xyz; Path=/api/auth/impersonate; HttpOnly; Secure; SameSite=Strict; Max-Age=1234"
        );
        assert_eq!(
            admin_stash_cookie("", 0, ""),
            "token_admin=; Path=/api/auth/impersonate; HttpOnly; SameSite=Strict; Max-Age=0"
        );
        // The stop route lives under the cookie's path, so the browser sends it there.
        assert!("/api/auth/impersonate/stop".starts_with(ADMIN_STASH_PATH));
    }

    #[test]
    fn both_cookies_are_sent_as_separate_headers() {
        let r = with_cookies(vec!["a=1".into(), "b=2".into()], serde_json::json!({}));
        let all: Vec<_> = r.headers().get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(all, vec!["a=1", "b=2"]);
    }

    // ── middleware attribution ──

    fn signed(c: &Claims, secret: &str) -> String {
        encode(&Header::default(), c, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
    }

    fn live(mut c: Claims) -> Claims {
        let now = chrono::Utc::now().timestamp();
        c.iat = now as usize;
        c.exp = (now + 600) as usize;
        c
    }

    #[test]
    fn an_impersonation_cookie_names_the_admin() {
        let admin_id = Uuid::new_v4();
        let mut c = live(admin());
        c.role = "user".into();
        c.imp_by = Some(admin_id);
        c.imp_email = Some("admin@example.com".into());
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&format!("token={}", signed(&c, "s"))).unwrap());
        assert_eq!(
            impersonator_from_headers("s", &h),
            Some((admin_id, "admin@example.com".to_string()))
        );
        // A forged token (wrong key) attributes nothing.
        assert_eq!(impersonator_from_headers("other", &h), None);
    }

    #[test]
    fn an_ordinary_session_or_api_key_names_nobody() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&format!("token={}", signed(&live(admin()), "s"))).unwrap());
        assert_eq!(impersonator_from_headers("s", &h), None);
        let mut k = HeaderMap::new();
        k.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer dp_xyz"));
        assert_eq!(impersonator_from_headers("s", &k), None);
    }
}
