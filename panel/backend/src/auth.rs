use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{err, err_coded, ApiError, CODE_SESSION_INVALID};
use crate::services::agent::AgentHandle;
use crate::AppState;

/// The caller has no usable session - the only refusal in this codebase that
/// entitles the frontend to navigate someone to `/login`.
///
/// Every such refusal is minted here rather than inline, so that "which 401s
/// mean *log in again*" is a question with one answer in one place instead of a
/// property to be re-derived from seven call sites. A handler's own 401 must
/// never use this: by the time a handler runs, this extractor has already
/// accepted the session, so the thing being refused there is a credential the
/// caller just presented, not the session itself.
///
/// The agent-token refusals at the bottom of this file are deliberately NOT
/// minted here - an agent is not a browser and has no session to lose.
fn session_invalid(msg: &str) -> ApiError {
    err_coded(StatusCode::UNAUTHORIZED, msg, CODE_SESSION_INVALID)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    /// JWT ID for token blacklisting on logout.
    #[serde(default)]
    pub jti: Option<String>,
    /// The `api_keys.id` this session authenticated with, so a request made
    /// through a `dp_` key (an MCP tool call, a CLI invocation) is attributable
    /// in the audit trail instead of looking identical to a browser session.
    /// `None` on the JWT path (`#[serde(default)]` so tokens issued before this
    /// field existed still decode). See `log_activity`/`audit_log` call sites.
    #[serde(default)]
    pub key_id: Option<Uuid>,
    /// Set when an administrator is acting as this user ("login as user",
    /// `routes/impersonation.rs`): the admin's `users.id`. `sub`/`email`/`role`
    /// are the impersonated user's, so every ownership check sees exactly what
    /// that user sees. `None` on every ordinary session (`#[serde(default)]`
    /// so tokens issued before this field existed still decode).
    #[serde(default)]
    pub imp_by: Option<Uuid>,
    /// The acting administrator's email, for display and the audit trail.
    #[serde(default)]
    pub imp_email: Option<String>,
    /// How this session was authenticated (feature 9, user terminal): `"mfa"`
    /// after `/auth/2fa/verify` or a passkey sign-in, `"pwd"` after a password
    /// sign-in without TOTP, `"oauth"` after an identity provider. `None` for a
    /// `dp_` API key, an impersonation session, and every session minted
    /// before this field existed (`#[serde(default)]`, so they still decode).
    /// See [`AuthMethod`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<String>,
}

/// The `amr` value a session-minting door stamps into [`Claims`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Password alone (the account has no TOTP).
    Password,
    /// A second factor was proven: TOTP / recovery code, or a passkey.
    Mfa,
    /// An external identity provider, without the panel's own TOTP step.
    OAuth,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Password => "pwd",
            AuthMethod::Mfa => "mfa",
            AuthMethod::OAuth => "oauth",
        }
    }
}

/// The value of [`Claims::amr`] that proves a second factor in this session.
pub const AMR_MFA: &str = "mfa";

/// Refuse an action that would give an administrator acting as another user
/// lasting access to, or control over the security of, that account (feature 3,
/// decision D4): password, 2FA, passkeys, API keys, session revocation, data
/// exports, team invitations. Call it first thing in the handler.
pub fn deny_if_impersonating(claims: &Claims) -> Result<(), ApiError> {
    if claims.imp_by.is_some() {
        return Err(err_coded(
            StatusCode::FORBIDDEN,
            "Not available while logged in as another user",
            crate::error::CODE_IMPERSONATION_FORBIDDEN,
        ));
    }
    Ok(())
}

/// The value of cookie `name` in the request's `Cookie` header(s), if any.
///
/// Exact name match: `token_admin=` is not `token=`.
pub fn read_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .find_map(|s| s.trim().strip_prefix(prefix.as_str()).map(|v| v.to_string()))
}

/// The `Authorization: Bearer` value, if any.
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

/// The session JWT the request presents, with the same precedence as
/// `AuthUser`: a Bearer token first, then the `token` cookie. A `dp_` API key
/// is not a JWT and yields `None` (it is never an impersonation session).
pub fn session_jwt_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    match bearer_token(headers) {
        Some(b) if b.starts_with("dp_") => None,
        Some(b) => Some(b),
        None => read_cookie(headers, "token"),
    }
}

/// Decode a session JWT, checking signature and expiry only (no blacklist, no
/// revocation - that is `AuthUser`'s job). `None` if it does not verify.
pub fn decode_session_jwt(secret: &str, token: &str) -> Option<Claims> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 0;
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .ok()
        .map(|d| d.claims)
}

/// JWT extractor - reads token from Authorization header or `token` cookie.
pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try Authorization: Bearer <token> first
        let bearer_token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t.to_string());

        // A `dp_`-prefixed bearer token is a long-lived API key (routes/api_keys.rs),
        // not a session JWT - authenticate it against `api_keys` directly. Trying to
        // `decode::<Claims>` it below would always fail, so without this branch every
        // API key request would 401 as "Invalid or expired token" for the wrong
        // reason and this scaffold would stay unwired, exactly as FEATURES.md's
        // "Withdrawn Claims" section already documents it.
        if let Some(key) = bearer_token.as_deref().filter(|t| t.starts_with("dp_")) {
            return authenticate_api_key(state, key).await.map(AuthUser);
        }

        let token = bearer_token.clone().or_else(|| {
                // Fall back to cookie
                parts
                    .headers
                    .get(header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookies| {
                        cookies
                            .split(';')
                            .find_map(|s| s.trim().strip_prefix("token=").map(|v| v.to_string()))
                    })
            })
            .ok_or_else(|| session_invalid("Authentication required"))?;

        // CSRF protection: cookie-based auth on mutating methods requires X-Requested-With header.
        // Bearer token auth (API keys) is exempt since it cannot be sent by cross-origin forms.
        if bearer_token.is_none() {
            let method = &parts.method;
            if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
                let has_custom_header = parts
                    .headers
                    .get("x-requested-with")
                    .is_some();
                if !has_custom_header {
                    return Err(err(StatusCode::FORBIDDEN, "Missing CSRF header"));
                }
            }
        }

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0;

        let claims = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| session_invalid("Invalid or expired token"))?
        .claims;

        // Check token blacklist (revoked JTIs)
        if let Some(ref jti) = claims.jti {
            let blacklist = state.token_blacklist.read().await;
            if blacklist.contains(jti) {
                return Err(session_invalid("Token has been revoked"));
            }
        }

        // Check global session revocation (revoke_all_sessions)
        {
            let revoked_at = state.sessions_revoked_at.read().await;
            if let Some(ts) = *revoked_at {
                if (claims.iat as i64) < ts {
                    return Err(session_invalid("Session revoked. Please log in again."));
                }
            }
        }

        // A suspended account's token must not authenticate. A pre-suspension token
        // carries the old role and is killed by the blacklist sweep on suspend; this
        // is defense-in-depth against any suspended-role token ever being minted (the
        // login/2FA/OAuth paths also reject "suspended" up front).
        if claims.role == "suspended" {
            return Err(err(StatusCode::FORBIDDEN, "Account suspended"));
        }

        Ok(AuthUser(claims))
    }
}

/// Authenticate a `dp_`-prefixed API key (routes/api_keys.rs) and build the same
/// `Claims` shape a JWT would, so it works for free on every `AuthUser`-gated
/// handler. Unlike a JWT, a key has no `jti` of its own and is never on the
/// per-token blacklist - it is revoked by deleting the `api_keys` row (or, for
/// the global "revoke all sessions" / Panic Button controls below, by having
/// been minted before that revocation fired: see the `created_at` check).
///
/// Failures here deliberately do NOT use `session_invalid()` - that marker
/// means "the caller has no usable *session*" and its own doc comment says the
/// same of the agent-token refusals below: a key is not a browser session that
/// can be lost, so a bad key gets a plain 401 like `authenticate_agent` does,
/// not the marker that tells a frontend to redirect to `/login`.
async fn authenticate_api_key(state: &AppState, key: &str) -> Result<Claims, ApiError> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let row: Option<(Uuid, Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, user_id, created_at FROM api_keys WHERE key_hash = $1",
    )
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| crate::error::internal_error("api_key lookup", e))?;

    let (key_id, user_id, created_at) =
        row.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    // Parity with the JWT path's own revocation check (above) - "Revoke all
    // sessions" and the Panic Button both promise a total logout, and a key
    // minted before that moment fired is exactly the credential class an
    // incident responder reaching for either control means to kill. A key
    // rotated (or newly minted) AFTER the revocation naturally has a fresh
    // `created_at` and keeps working, same as a JWT from a fresh login would.
    {
        let revoked_at = state.sessions_revoked_at.read().await;
        if revoked_at.is_some_and(|ts| created_at.timestamp() < ts) {
            return Err(err(StatusCode::UNAUTHORIZED, "Key revoked. Mint a new one."));
        }
    }

    let user: Option<(String, String)> =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| crate::error::internal_error("api_key user lookup", e))?;

    let (email, role) =
        user.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    // Parity with the JWT path's own post-decode check (this file, below) - an
    // account suspended after a key was minted must not keep authenticating.
    if role == "suspended" {
        return Err(err(StatusCode::FORBIDDEN, "Account suspended"));
    }

    // Best-effort bookkeeping - a failed UPDATE must not fail the request that
    // is itself proof the key still works.
    let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
        .bind(key_id)
        .execute(&state.db)
        .await;

    let now = chrono::Utc::now().timestamp() as usize;
    Ok(Claims {
        sub: user_id,
        email,
        role,
        key_id: Some(key_id),
        // An API key has no session lifetime of its own - it lives until its
        // `api_keys` row is deleted (or the revocation check above fires).
        // `exp` still has to be a value in the future because nothing
        // downstream re-checks how this Claims was built; it is never
        // re-validated against a signature, so this is not a forgeable
        // expiry, just a field every consumer of `Claims` expects.
        exp: now + 315_360_000, // ~10 years
        iat: now,
        jti: None,
        // An API key is never an impersonation session.
        imp_by: None,
        imp_email: None,
        // An API key proves no interactive authentication at all.
        amr: None,
    })
}

/// Admin-only JWT extractor - extracts Claims then verifies role == "admin".
pub struct AdminUser(pub Claims);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Propagate the inner rejection verbatim - flattening it to a generic
        // 401 hid "Missing CSRF header" (403) and "Invalid or expired token"
        // behind "Authentication required" on every admin endpoint, which sends
        // clients debugging a stale session instead of the real cause.
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;

        if claims.role != "admin" {
            return Err(err(StatusCode::FORBIDDEN, "Admin access required"));
        }

        Ok(AdminUser(claims))
    }
}

/// Reseller-or-admin JWT extractor - allows role == "admin" OR role == "reseller".
/// Used for endpoints accessible to both admins and resellers.
pub struct ResellerUser(pub Claims);

impl FromRequestParts<AppState> for ResellerUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Same rationale as AdminUser: keep the inner rejection intact.
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;

        if claims.role != "admin" && claims.role != "reseller" {
            return Err(err(StatusCode::FORBIDDEN, "Admin or reseller access required"));
        }

        Ok(ResellerUser(claims))
    }
}

/// Server scope extractor - reads `X-Server-Id` header to determine which server
/// the request targets. Falls back to the local server if the header is absent.
///
/// Usage in handlers:
/// ```
/// async fn my_handler(
///     State(state): State<AppState>,
///     AuthUser(claims): AuthUser,
///     ServerScope(server_id, agent): ServerScope,
/// ) -> Result<..., ApiError> { ... }
/// ```
pub struct ServerScope(pub Uuid, pub AgentHandle);

impl FromRequestParts<AppState> for ServerScope {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract JWT claims to verify server ownership
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t.to_string())
            .or_else(|| {
                parts.headers.get(header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookies| {
                        cookies.split(';').find_map(|s| s.trim().strip_prefix("token=").map(|v| v.to_string()))
                    })
            });

        let user_id = if let Some(ref tok) = token {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            validation.validate_exp = true;
            validation.leeway = 0;
            jsonwebtoken::decode::<Claims>(
                tok,
                &jsonwebtoken::DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
                &validation,
            )
            .ok()
            .map(|data| data.claims.sub)
        } else {
            None
        };

        // Read X-Server-Id header
        let server_id = parts
            .headers
            .get("x-server-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok());

        match server_id {
            Some(sid) => {
                // Verify server belongs to the authenticated user
                let uid = user_id.ok_or_else(|| {
                    session_invalid("Authentication required when X-Server-Id is provided")
                })?;

                let owns: Option<(Uuid,)> = sqlx::query_as(
                    "SELECT id FROM servers WHERE id = $1 AND user_id = $2",
                )
                .bind(sid)
                .bind(uid)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Server lookup failed"))?;

                if owns.is_none() {
                    return Err(err(StatusCode::FORBIDDEN, "Server not found or access denied"));
                }

                // Resolve agent for this server
                let agent = state
                    .agents
                    .for_server(sid)
                    .await
                    .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;
                Ok(ServerScope(sid, agent))
            }
            None => {
                // Default to local server
                let local_id = state
                    .agents
                    .local_server_id()
                    .await
                    .ok_or_else(|| {
                        err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Local server not yet registered",
                        )
                    })?;
                let agent = AgentHandle::Local(state.agents.local().clone());
                Ok(ServerScope(local_id, agent))
            }
        }
    }
}

/// Authenticate an AGENT-originated request from its `servers` row token, and
/// return the server's id.
///
/// This is a different credential from every extractor above: an agent holds a
/// random hex string issued at install time (`install-agent.sh`), not a signed
/// user JWT, so `AuthUser` can never accept one. Hash-based lookup first, with a
/// plaintext fallback for rows predating the hashing migration.
///
/// It lives here, as the single implementation, because it used to live in
/// `routes/agent_commands.rs` while `routes/agent_updates.rs` guarded the very
/// same class of caller with `AuthUser` - so `/api/agent/version` demanded a JWT
/// from a caller that structurally cannot hold one and 401'd on every request
/// for four releases. One copy, used by every agent route (s233).
pub async fn authenticate_agent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Uuid, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Missing authorization"))?;

    let token_hash = crate::helpers::hash_agent_token(token);
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM servers WHERE agent_token_hash = $1")
            .bind(&token_hash)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| crate::error::internal_error("unknown", e))?;

    if let Some(r) = row {
        return Ok(r.0);
    }

    // Fallback: plaintext lookup for pre-migration rows.
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM servers WHERE agent_token = $1 AND agent_token_hash IS NULL")
            .bind(token)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| crate::error::internal_error("unknown", e))?;

    row.map(|r| r.0)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Invalid token"))
}

/// Per-server rate limit shared by the agent routes: 120 requests/minute.
/// Returns `Err(429)` when exceeded.
pub fn agent_rate_limit(state: &AppState, server_id: Uuid) -> Result<(), ApiError> {
    let mut limits = state
        .agent_rate_limits
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    let entry = limits.entry(server_id).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= 60 {
        *entry = (1, now);
        return Ok(());
    }
    entry.0 += 1;
    if entry.0 > 120 {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
    }
    Ok(())
}

#[cfg(test)]
mod session_marker_tests {
    use super::*;

    fn body(e: &ApiError) -> serde_json::Value {
        e.1 .0.clone()
    }

    #[test]
    fn session_invalid_is_a_401_carrying_the_marker() {
        let e = session_invalid("Invalid or expired token");
        assert_eq!(e.0, StatusCode::UNAUTHORIZED);
        assert_eq!(body(&e)["code"], CODE_SESSION_INVALID);
        assert_eq!(body(&e)["error"], "Invalid or expired token");
    }

    /// The sentence must survive alongside the marker. The whole defect being
    /// repaired is a client that had the status and threw the sentence away.
    #[test]
    fn the_sentence_is_not_replaced_by_the_marker() {
        let e = session_invalid("Session revoked. Please log in again.");
        assert_eq!(body(&e)["error"], "Session revoked. Please log in again.");
    }

    /// An agent presenting a bad token is not a browser losing a session, and
    /// must not be able to make the client navigate a human to /login.
    #[test]
    fn a_plain_401_carries_no_marker() {
        let e = err(StatusCode::UNAUTHORIZED, "Invalid token");
        assert_eq!(e.0, StatusCode::UNAUTHORIZED);
        assert!(body(&e).get("code").is_none());
    }
}

#[cfg(test)]
mod impersonation_helper_tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn claims(imp_by: Option<Uuid>) -> Claims {
        Claims {
            sub: Uuid::new_v4(),
            email: "client@example.com".into(),
            role: "user".into(),
            exp: 2_000_000_000,
            iat: 1_000_000_000,
            jti: Some("j".into()),
            key_id: None,
            imp_by,
            imp_email: imp_by.map(|_| "admin@example.com".to_string()),
            amr: None,
        }
    }

    #[test]
    fn deny_passes_an_ordinary_session() {
        assert!(deny_if_impersonating(&claims(None)).is_ok());
    }

    #[test]
    fn deny_refuses_an_impersonation_session_with_the_contract_body() {
        let e = deny_if_impersonating(&claims(Some(Uuid::new_v4()))).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert_eq!(e.1 .0["code"], "impersonation_forbidden");
        assert_eq!(e.1 .0["error"], "Not available while logged in as another user");
    }

    #[test]
    fn claims_without_the_new_fields_still_decode() {
        let json = r#"{"sub":"00000000-0000-0000-0000-000000000001","email":"a@b","role":"admin","exp":1,"iat":1}"#;
        let c: Claims = serde_json::from_str(json).unwrap();
        assert!(c.imp_by.is_none() && c.imp_email.is_none());
        assert!(c.amr.is_none(), "a pre-amr session decodes with amr = None");
    }

    #[test]
    fn amr_is_omitted_when_absent_and_round_trips_when_set() {
        let mut c = claims(None);
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("amr").is_none(), "None must not be serialised");
        c.amr = Some(AuthMethod::Mfa.as_str().to_string());
        let tok = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &c,
            &jsonwebtoken::EncodingKey::from_secret(b"s"),
        )
        .unwrap();
        assert_eq!(decode_session_jwt("s", &tok).unwrap().amr.as_deref(), Some("mfa"));
    }

    #[test]
    fn auth_method_values_are_the_contract_strings() {
        assert_eq!(AuthMethod::Password.as_str(), "pwd");
        assert_eq!(AuthMethod::Mfa.as_str(), "mfa");
        assert_eq!(AuthMethod::OAuth.as_str(), "oauth");
        assert_eq!(AMR_MFA, AuthMethod::Mfa.as_str());
    }

    #[test]
    fn read_cookie_matches_the_exact_name() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("token_admin=AAA; token=BBB"));
        assert_eq!(read_cookie(&h, "token").as_deref(), Some("BBB"));
        assert_eq!(read_cookie(&h, "token_admin").as_deref(), Some("AAA"));
        assert_eq!(read_cookie(&h, "missing"), None);
    }

    #[test]
    fn session_jwt_prefers_bearer_and_ignores_api_keys() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("token=COOKIE"));
        assert_eq!(session_jwt_from_headers(&h).as_deref(), Some("COOKIE"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer JWT"));
        assert_eq!(session_jwt_from_headers(&h).as_deref(), Some("JWT"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer dp_abc"));
        assert_eq!(session_jwt_from_headers(&h), None);
    }

    #[test]
    fn decode_session_jwt_checks_the_signature() {
        let c = claims(Some(Uuid::new_v4()));
        let tok = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &c,
            &jsonwebtoken::EncodingKey::from_secret(b"secret-one"),
        )
        .unwrap();
        assert_eq!(decode_session_jwt("secret-one", &tok).unwrap().imp_by, c.imp_by);
        assert!(decode_session_jwt("secret-two", &tok).is_none());
    }
}
