use crate::safe_cmd::safe_command;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use futures::stream::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::auth::AuthUser;
use crate::auth::Claims;
use crate::auth::ServerScope;
use crate::error::{internal_error, err, agent_error, paginate, ApiError};
use crate::models::Site;

/// `SELECT s.*` over [`crate::helpers::SITE_CALLER_PREDICATE`] - the full-row read
/// used by every per-site handler in this module. Built once; the predicate itself
/// is shared with the five other modules that resolve a site by caller.
static SITE_FOR_CALLER_ALL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("SELECT s.* FROM sites s WHERE {}", crate::helpers::SITE_CALLER_PREDICATE)
});
use crate::routes::is_valid_domain;
use crate::routes::reseller_dashboard::check_reseller_quota;
use crate::services::domain_claim;

/// Effective per-user site-creation ceiling per hour, shared by every handler
/// that writes a `sites` row so they cannot drift apart. `security_site_rate_limit`
/// holds the count; 0 means no limit. Absent row falls back to the seeded default of 3.
///
/// Visible to the crate since v2.110.0, when the staging module became the third
/// caller. It was private while two of the four site-creating handlers lived in
/// this file, which is precisely why the third one - in another module, and
/// therefore unable to call this even had its author looked - was written with a
/// ceiling of its own: none.
///
/// `role` is the session's: an impersonation session carries the impersonated
/// user's, so an administrator acting as a tenant is held to the tenant's ceiling.
pub(crate) async fn site_rate_limit(pool: &sqlx::PgPool, role: &str) -> i64 {
    let configured =
        crate::services::security_hardening::get_setting_i64(pool, "security_site_rate_limit", 3)
            .await;
    site_rate_ceiling(role, configured)
}

/// An administrator deploying a fleet of apps is not who this ceiling is for.
fn site_rate_ceiling(role: &str, configured: i64) -> i64 {
    if role == "admin" || configured <= 0 {
        i64::MAX
    } else {
        configured
    }
}

/// What the server hosting a site reports about the app behind its reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamState {
    Up,
    Down,
    Unknown,
}

/// The local port nginx forwards this site to, for the runtimes that have one.
fn upstream_port(runtime: &str, proxy_port: Option<i32>) -> Option<i32> {
    proxy_port.filter(|_| matches!(runtime, "proxy" | "node" | "python"))
}

fn upstream_state_from_agent(answer: Option<&serde_json::Value>) -> UpstreamState {
    match answer.and_then(|v| v.get("reachable")).and_then(|v| v.as_bool()) {
        Some(true) => UpstreamState::Up,
        Some(false) => UpstreamState::Down,
        None => UpstreamState::Unknown,
    }
}

/// Ask the agent of the server hosting the site, since `127.0.0.1` means that
/// machine. An agent that is unreachable, or too old to know the probe, leaves
/// the state unknown: that says nothing about the app.
async fn probe_upstream(
    state: &AppState,
    server_id: Option<Uuid>,
    domain: &str,
    port: i32,
) -> UpstreamState {
    let Ok(agent) = crate::helpers::agent_for_site_server(state, server_id, domain).await else {
        return UpstreamState::Unknown;
    };
    let path = format!("/system/upstream-probe?port={port}");
    let answer = tokio::time::timeout(std::time::Duration::from_secs(5), agent.get(&path)).await;
    match answer {
        Ok(Ok(v)) => upstream_state_from_agent(Some(&v)),
        _ => upstream_state_from_agent(None),
    }
}

/// `public_status` is the answer to the request sent to the public domain, `None`
/// when none came back. With a running app that only means the domain does not
/// resolve from here yet, which is not a fault of the site.
fn site_is_healthy(upstream: Option<UpstreamState>, public_status: Option<u16>) -> bool {
    match (upstream, public_status) {
        (Some(UpstreamState::Down), _) => false,
        (Some(UpstreamState::Up), None) => true,
        (_, Some(status)) => status < 500,
        (_, None) => false,
    }
}

/// A site whose app is stopped serves only 502s, whatever its certificate and
/// backups look like, so the score cannot stay out of the red band.
fn score_with_upstream(score: i32, upstream: Option<UpstreamState>) -> i32 {
    match upstream {
        Some(UpstreamState::Down) => (score - 40).min(40),
        _ => score,
    }
}

fn upstream_report(port: i32, state: UpstreamState) -> serde_json::Value {
    let (name, message) = match state {
        UpstreamState::Up => ("up", format!("The app is accepting connections on 127.0.0.1:{port}")),
        UpstreamState::Down => ("down", format!("Nothing is accepting connections on 127.0.0.1:{port}")),
        UpstreamState::Unknown => ("unknown", "The server could not be asked about the app".to_string()),
    };
    serde_json::json!({ "port": port, "state": name, "message": message })
}

/// Atomically reserve one site slot against the site owner's reseller quota. The
/// conditional UPDATE ... RETURNING closes the check-then-increment TOCTOU. Returns
/// Ok(true) if a slot was reserved (release it on a later failure), Ok(false) if the
/// user has no reseller (nothing to enforce), or Err(403) if the quota is exhausted.
/// Mirrors databases::reserve_reseller_db_slot.
async fn reserve_reseller_site_slot(state: &AppState, user_id: uuid::Uuid) -> Result<bool, ApiError> {
    let reserved: Option<i32> = sqlx::query_scalar(
        "UPDATE reseller_profiles SET used_sites = used_sites + 1, updated_at = NOW() \
         WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL) \
           AND (max_sites IS NULL OR used_sites < max_sites) \
         RETURNING 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("reserve reseller site quota", e))?;

    if reserved.is_some() {
        return Ok(true);
    }
    let has_profile: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT rp.user_id FROM reseller_profiles rp \
         WHERE rp.user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("reserve reseller site quota", e))?;

    if has_profile.is_some() {
        return Err(err(StatusCode::FORBIDDEN, "Reseller site quota exceeded"));
    }
    Ok(false)
}

/// Release a reserved site slot (compensating decrement) on a later failure.
async fn release_reseller_site_slot(state: &AppState, user_id: uuid::Uuid) {
    let _ = sqlx::query(
        "UPDATE reseller_profiles SET used_sites = GREATEST(used_sites - 1, 0), updated_at = NOW() \
         WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)",
    )
    .bind(user_id)
    .execute(&state.db)
    .await;
}
use crate::services::activity;
use crate::services::extensions::fire_event;
use crate::services::notifications;
use crate::services::security_hardening;
use crate::AppState;

/// The agent release in which a domain rename began carrying the site's backup
/// trees with it. Before it, the archives stayed on disk under the old name
/// while the panel kept listing rows that no longer resolved to a file.
const BACKUP_CARRY_MIN_AGENT: &str = "2.142.0";

/// A single provisioning step event.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ProvisionStep {
    pub step: String,
    pub label: String,
    pub status: String, // "pending", "in_progress", "done", "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Helper: emit a provisioning step to the broadcast channel + history.
fn emit_step(
    logs: &Arc<Mutex<HashMap<Uuid, (Vec<ProvisionStep>, broadcast::Sender<ProvisionStep>, Instant)>>>,
    site_id: Uuid,
    step: &str,
    label: &str,
    status: &str,
    message: Option<String>,
) {
    let ev = ProvisionStep {
        step: step.into(),
        label: label.into(),
        status: status.into(),
        message,
    };
    if let Ok(mut map) = logs.lock() {
        if let Some((history, tx, _)) = map.get_mut(&site_id) {
            history.push(ev.clone());
            let _ = tx.send(ev);
        }
    }
}

/// Store a credential CyberHunter - Panel generated on the user's behalf into the site's
/// auto-created vault.
///
/// Encrypts with `secrets::get_encryption_key` - the same derivation the Secrets
/// Manager decrypts with, so the value is actually retrievable in the UI rather
/// than merely written somewhere.
///
/// Best-effort by design: provisioning must not fail because bookkeeping did.
/// But every failure is logged at error level, because the failure mode this
/// exists to kill (s252 F3) was a password generated, handed to wp-cli, and
/// dropped on the floor beside an empty vault - with nothing said anywhere.
async fn store_site_secret(
    pool: &sqlx::PgPool,
    jwt_secret: &str,
    vault_id: Uuid,
    key: &str,
    value: &str,
    description: &str,
) -> bool {
    let enc_key = crate::routes::secrets::get_encryption_key(jwt_secret);
    let encrypted = match crate::services::secrets_crypto::encrypt(value, &enc_key) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Auto-vault: could not encrypt '{key}': {e}");
            return false;
        }
    };

    match sqlx::query(
        "INSERT INTO secrets (vault_id, key, encrypted_value, description, secret_type, updated_by) \
         VALUES ($1, $2, $3, $4, 'password', 'dockpanel') \
         ON CONFLICT (vault_id, key) DO UPDATE SET \
           encrypted_value = EXCLUDED.encrypted_value, \
           description = EXCLUDED.description, \
           version = secrets.version + 1, \
           updated_at = NOW()",
    )
    .bind(vault_id)
    .bind(key)
    .bind(&encrypted)
    .bind(description)
    .execute(pool)
    .await
    {
        Ok(_) => true,
        Err(e) => {
            tracing::error!("Auto-vault: could not store '{key}': {e}");
            false
        }
    }
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(serde::Deserialize)]
pub struct CreateSiteRequest {
    pub domain: String,
    pub runtime: Option<String>,
    pub proxy_port: Option<i32>,
    pub php_version: Option<String>,
    pub php_preset: Option<String>,
    /// Start command for node/python runtimes (e.g., "npm start", "gunicorn app:app")
    pub app_command: Option<String>,
    // One-click CMS install
    pub cms: Option<String>,
    pub site_title: Option<String>,
    pub admin_email: Option<String>,
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
    /// The `server_ips` row the vhost listens on. Absent/null = the primary address.
    /// Must belong to the server the site is created on.
    pub ip_id: Option<Uuid>,
    /// `nginx` or `apache` (feature 4). Absent = `apache` for a PHP site (D1);
    /// always forced to `nginx` for every other runtime. See [`resolve_create_web_server`].
    pub web_server: Option<String>,
}

/// GET /api/sites - List all sites for the current user.
///
/// Scoped to the caller, with no role branch, and every per-site read below is
/// the same. That is the single ownership axis the `client` role rests on - an
/// account that OWNS the row passes all of it natively. See `list_for_admin`
/// for the one read that is allowed to look past it, and why it had to exist.
pub async fn list(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, _agent): ServerScope,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<Site>>, ApiError> {
    let (limit, offset) = paginate(params.limit, params.offset);

    let sites: Vec<Site> = sqlx::query_as(
        "SELECT * FROM sites WHERE user_id = $1 AND server_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(claims.sub)
    .bind(server_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list sites", e))?;

    let mut sites = sites;
    crate::services::server_ips::fill_bind_ips(&state.db, &mut sites).await;
    crate::services::disk_usage::fill_disk_usage(&state.db, &mut sites).await;

    Ok(Json(sites))
}

/// One site as an admin sees it on the all-sites view, with its owner resolved.
///
/// Deliberately NOT [`Site`]. `Site` is `#[derive(FromRow)]` over `SELECT *` and
/// is bound at three dozen call sites in this crate; a field with no matching
/// column breaks every one of them at runtime, and a struct that carried an
/// owner would sooner or later be handed to a per-site handler that must keep
/// asking "is this yours?". This projection holds only what the list renders,
/// so it cannot be mistaken for a site the caller may act on.
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct AdminSiteRow {
    pub id: Uuid,
    pub domain: String,
    pub runtime: String,
    pub status: String,
    pub enabled: bool,
    pub ssl_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub parent_site_id: Option<Uuid>,
    pub user_id: Uuid,
    pub owner_email: Option<String>,
    pub owner_role: Option<String>,
    /// Multi-IP, as on [`Site`]: the declared address id and its IP (null = primary).
    pub ip_id: Option<Uuid>,
    pub bind_ip: Option<String>,
    /// Feature 6, as on [`Site`].
    pub ftp_enabled: bool,
    pub disk_quota_mb: Option<i32>,
    #[sqlx(skip)]
    pub disk_usage: Option<crate::models::DiskUsage>,
}

/// GET /api/admin/sites - every site on this server, with its owner. Admin only.
///
/// **This route exists because `transfer` was a one-way door.** Ownership is one
/// axis and `list` above is scoped to the caller with no role branch - so the
/// moment an admin handed a site to a client, the row left their list, `get_one`
/// answered 404, and the Transfer control, which is rendered only on the site's
/// own page, became unreachable. There was no way back through the panel at all,
/// while `docs/guides/roles-and-ownership.md` promised the opposite in print.
/// Reported from the field on #51 by the operator who had just used the feature.
///
/// It is a READ, and only a read - this route lists, and nothing more. What it is
/// no longer doing is standing in for the capability: when it shipped, seeing a
/// site and handing it back was the whole of what an administrator could do with
/// one they did not own, and the operator it was built for said that was not
/// enough on a server he is responsible for. Acting on those sites is now decided
/// by [`crate::helpers::SITE_CALLER_PREDICATE`], one predicate shared by every
/// per-site handler, which admits the owner or an administrator of the machine
/// the site runs on.
///
/// This read stays a narrow projection anyway. A caller that may act on a site
/// asks for it by id through the ordinary handlers; nothing needs a list row it
/// can mistake for an actionable site.
pub async fn list_for_admin(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(server_id, _agent): ServerScope,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<AdminSiteRow>>, ApiError> {
    let (limit, offset) = paginate(params.limit, params.offset);

    let sites: Vec<AdminSiteRow> = sqlx::query_as(
        "SELECT s.id, s.domain, s.runtime, s.status, s.enabled, s.ssl_enabled, \
                s.created_at, s.parent_site_id, s.user_id, \
                u.email AS owner_email, u.role AS owner_role, \
                s.ip_id, si.ip AS bind_ip, s.ftp_enabled, s.disk_quota_mb \
         FROM sites s LEFT JOIN users u ON u.id = s.user_id \
         LEFT JOIN server_ips si ON si.id = s.ip_id \
         WHERE s.server_id = $1 ORDER BY s.created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(server_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list sites for admin", e))?;

    let mut sites = sites;
    let ids: Vec<Uuid> = sites.iter().map(|s| s.id).collect();
    let mut usage = crate::services::disk_usage::load_disk_usage(&state.db, &ids).await;
    for s in sites.iter_mut() {
        s.disk_usage = usage.remove(&s.id);
    }

    Ok(Json(sites))
}

/// POST /api/sites - Create a new site.
pub async fn create(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, agent): ServerScope,
    headers: HeaderMap,
    Json(body): Json<CreateSiteRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Feature 9: Block site creation during lockdown
    if security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "System is in lockdown mode"));
    }

    // Feature 3: Rate limit site creation (max N per user per hour).
    // `security_site_rate_limit` is a COUNT, not a flag: the migration seeds it
    // '3', but until v2.46.0 it was read with get_setting_bool, so '3' != "true"
    // read as false and the limit became 999 - the seed disabled the very
    // feature it configures, on every install that ran the migration. 0 = off.
    {
        let max_sites: i64 = site_rate_limit(&state.db, &claims.role).await;
        let recent: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sites WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'"
        )
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
        if recent.0 >= max_sites {
            // Feature 4: Record as suspicious event
            let _ = security_hardening::record_suspicious_event(
                &state.db, "site.rate_limit_hit", Some(&claims.email), None,
                Some(&format!("User tried to create site #{} in 1 hour", recent.0 + 1)),
            ).await;
            return Err(err(StatusCode::TOO_MANY_REQUESTS,
                &format!("Site creation rate limit: max {max_sites} sites per hour. \
                          An administrator can change this in Settings > Account > Security Hardening \
                          (\"Site Creation Rate Limit\"); set it to 0 to remove the limit.")));
        }
    }

    // Format, reserved and every ownership check, in one call - see
    // services::domain_claim. `body.domain` is not used past this point; the
    // normalised form is what gets stored and sent to the agent.
    let domain = domain_claim::ensure_claimable(
        &state.db,
        &state.agents,
        &body.domain,
        &headers,
        domain_claim::Holder::New,
        &claims.role,
    )
    .await?;

    let runtime = body.runtime.as_deref().unwrap_or("static");
    if !["static", "php", "proxy", "node", "python"].contains(&runtime) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Runtime must be static, php, proxy, node, or python",
        ));
    }

    if runtime == "proxy" && body.proxy_port.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "proxy_port is required for proxy runtime",
        ));
    }

    // Validate an explicitly-supplied proxy port. Unvalidated, it (a) renders as
    // `proxy_pass http://127.0.0.1:<port>` → loopback SSRF into internal
    // services, and (b) is fed to the auto-firewall `ufw deny <port>/tcp`, which
    // would clobber a global allow rule (e.g. deny 443 → box-wide outage).
    // Auto-allocated node/python ports (chosen below from a free 5000-5999 slot)
    // are inherently safe and skip this.
    if let Some(port) = body.proxy_port {
        if !is_safe_proxy_port(port) {
            return Err(err(StatusCode::BAD_REQUEST,
                "proxy_port must be between 1024 and 65535 and not a reserved/system port"));
        }
        let taken: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM sites WHERE proxy_port = $1 AND server_id = $2 AND user_id <> $3",
        )
        .bind(port)
        .bind(server_id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("proxy port check", e))?;
        if taken.is_some() {
            return Err(err(StatusCode::CONFLICT,
                "That port is already in use by another site on this server"));
        }
    }

    // Node/Python require app_command
    if (runtime == "node" || runtime == "python") && body.app_command.as_ref().map_or(true, |c| c.trim().is_empty()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "app_command is required for node/python runtime",
        ));
    }

    // Validate app_command: reject shell injection, newlines, and non-whitelisted prefixes
    if let Some(ref cmd) = body.app_command {
        if cmd.contains('\n') || cmd.contains('\r') || cmd.contains('\0') {
            return Err(err(StatusCode::BAD_REQUEST, "app_command must not contain newlines or null bytes"));
        }
        let forbidden = ['`', '$', '|', ';', '&', '<', '>', '\\', '!', '{', '}'];
        if cmd.chars().any(|c| forbidden.contains(&c)) {
            return Err(err(StatusCode::BAD_REQUEST, "app_command contains forbidden characters"));
        }
        if cmd.contains("..") {
            return Err(err(StatusCode::BAD_REQUEST, "app_command must not contain '..'"));
        }
        if cmd.len() > 1024 {
            return Err(err(StatusCode::BAD_REQUEST, "app_command too long"));
        }
        // Whitelist allowed command prefixes per runtime
        if runtime == "node" {
            let valid = cmd.starts_with("node ") || cmd.starts_with("npm ")
                || cmd.starts_with("npx ") || cmd.starts_with("yarn ")
                || cmd.starts_with("pnpm ") || !cmd.contains(' ');
            if !valid {
                return Err(err(StatusCode::BAD_REQUEST,
                    "app_command for node must start with node/npm/npx/yarn/pnpm or be a bare filename"));
            }
        } else if runtime == "python" {
            let valid = cmd.starts_with("python") || cmd.starts_with("gunicorn ")
                || cmd.starts_with("uvicorn ") || cmd.starts_with("flask ")
                || cmd.starts_with("django") || !cmd.contains(' ');
            if !valid {
                return Err(err(StatusCode::BAD_REQUEST,
                    "app_command for python must start with python/gunicorn/uvicorn/flask/django or be a bare filename"));
            }
        }
    }

    if let Some(ref preset) = body.php_preset {
        if !["generic", "laravel", "wordpress", "drupal", "joomla", "symfony", "codeigniter", "magento"].contains(&preset.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "php_preset must be one of: generic, laravel, wordpress, drupal, joomla, symfony, codeigniter, magento",
            ));
        }
    }

    // Feature 4: which web server serves the site. Validated before any write.
    let web_server = resolve_create_web_server(runtime, body.web_server.as_deref())
        .map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;

    // Domain uniqueness - sites, git deploys AND Docker apps - was checked by
    // `domain_claim::ensure_claimable` above, before any of this work started.

    // Multi-IP: the address must be declared on THIS server. Choosing one is an
    // administrator's decision (addresses are server inventory, not tenant data).
    let bind_ip: String = match body.ip_id {
        None => crate::services::server_ips::bind_ip_value(None),
        Some(ip_id) => {
            if claims.role != "admin" {
                return Err(err(StatusCode::FORBIDDEN, "Only an administrator can choose a site's IP address"));
            }
            let row = crate::services::server_ips::declared_ip_on_server(&state.db, ip_id, server_id)
                .await
                .map_err(|e| internal_error("site ip check", e))?
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "That IP address is not declared on this server"))?;
            crate::services::server_ips::bind_ip_value(Some(&row.ip))
        }
    };

    // Check reseller quota before creating site
    check_reseller_quota(&state.db, claims.sub, "sites").await?;

    // Check reseller server isolation: user under a reseller can only use allocated servers
    let user_reseller: Option<(Option<uuid::Uuid>,)> = sqlx::query_as(
        "SELECT reseller_id FROM users WHERE id = $1"
    ).bind(claims.sub).fetch_optional(&state.db).await
        .map_err(|e| internal_error("reseller check", e))?;
    if let Some((Some(rid),)) = user_reseller {
        let allowed: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM reseller_servers WHERE reseller_id = $1 AND server_id = $2"
        ).bind(rid).bind(server_id).fetch_optional(&state.db).await
            .map_err(|e| internal_error("reseller server check", e))?;
        if allowed.is_none() {
            return Err(err(StatusCode::FORBIDDEN, "This server is not allocated to your reseller account"));
        }
    }

    // What the host itself holds in the automatic range: the panel's own rows
    // know nothing of a container or service it did not create.
    let auto_port = (runtime == "node" || runtime == "python") && body.proxy_port.is_none();
    let host_ports: Vec<i32> = if auto_port {
        let reply = agent
            .get("/system/ports-in-use?from=5000&to=5999")
            .await
            .map_err(|e| agent_error("Port allocation", e))?;
        reply["ports"]
            .as_array()
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "The server did not report its ports in use"))?
            .iter()
            .filter_map(|p| p.as_i64().map(|p| p as i32))
            .collect()
    } else {
        Vec::new()
    };

    // Insert site with status "creating" inside a transaction
    let mut tx = state.db.begin().await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Transaction start failed: {e}")))?;

    // Auto-allocate port for node/python runtimes
    let effective_proxy_port = if auto_port {
        // Find the first free port in the 5000-5999 range, on THIS server. The
        // uniqueness index behind it is `idx_sites_proxy_port_server`, scoped the
        // same way; while it was global, this first-fit picked 5000 on every
        // server whose own set was empty and the INSERT below rejected it as a
        // duplicate domain.
        let site_ports: Vec<i32> = sqlx::query_scalar(
            "SELECT proxy_port FROM sites WHERE proxy_port BETWEEN 5000 AND 5999 AND server_id = $1",
        )
        .bind(server_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| internal_error("create sites", e))?;
        Some(first_free_site_port(&site_ports, &host_ports).ok_or_else(|| {
            err(StatusCode::CONFLICT, "No free port is left between 5000 and 5999 on this server")
        })?)
    } else {
        body.proxy_port
    };

    // D9: every new PHP site starts with PHP execution blocked in the usual
    // upload folders. Other runtimes run no PHP, so they get nothing.
    let php_no_exec_dirs: Option<Vec<String>> = (runtime == "php").then(default_php_no_exec_dirs);

    let site: Site = sqlx::query_as(
        "INSERT INTO sites (user_id, server_id, domain, runtime, status, proxy_port, php_version, php_preset, app_command, ip_id, web_server, php_no_exec_dirs) \
         VALUES ($1, $2, $3, $4, 'creating', $5, $6, $7, $8, $9, $10, $11) RETURNING *",
    )
    .bind(claims.sub)
    .bind(server_id)
    .bind(&domain)
    .bind(runtime)
    .bind(effective_proxy_port)
    .bind(&body.php_version)
    .bind(body.php_preset.as_deref().unwrap_or("generic"))
    .bind(&body.app_command)
    .bind(body.ip_id)
    .bind(web_server)
    .bind(&php_no_exec_dirs)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        // Two unique indexes can reject this INSERT and they mean opposite things
        // to the operator. Collapsing both into "Domain already exists" sent
        // whoever hit the port one to go and look at DNS.
        if msg.contains("idx_sites_proxy_port_server") {
            err(
                StatusCode::CONFLICT,
                "That proxy port is already in use on this server",
            )
        } else if msg.contains("duplicate key") || msg.contains("unique") {
            err(StatusCode::CONFLICT, "Domain already exists")
        } else {
            err(StatusCode::INTERNAL_SERVER_ERROR, &msg)
        }
    })?;

    // Create provisioning log channel. This is the entry that carries the
    // generated CMS admin password on its "credentials" step, so the owner
    // recorded here is what keeps it from any other account.
    crate::helpers::register_provision_log(
        &state.provision_logs,
        &state.deploy_owners,
        site.id,
        claims.sub,
        64,
    );
    let logs = state.provision_logs.clone();
    let site_id = site.id;

    emit_step(&logs, site_id, "nginx", "Configuring web server", "in_progress", None);

    // Build agent request body
    let mut agent_body = serde_json::json!({
        "runtime": runtime,
    });

    if let Some(port) = effective_proxy_port {
        agent_body["proxy_port"] = serde_json::json!(port);
    }
    if let Some(ref cmd) = body.app_command {
        agent_body["app_command"] = serde_json::json!(cmd);
    }
    if let Some(ref php) = body.php_version {
        // Backend can't know the target server's distro; this Debian-shaped string is
        // a VERSION CARRIER, not a literal path - the agent resolves the real socket
        // (Debian or RHEL's unversioned one) via services::pkg::resolve_php_fpm_socket
        // before ever touching a filesystem path.
        agent_body["php_socket"] = serde_json::json!(format!("unix:/run/php/php{php}-fpm.sock"));
    }
    if let Some(ref preset) = body.php_preset {
        agent_body["php_preset"] = serde_json::json!(preset);
    }
    agent_body["fastcgi_cache"] = serde_json::json!(false);
    agent_body["redis_cache"] = serde_json::json!(false);
    agent_body["redis_db"] = serde_json::json!(0);
    agent_body["waf_enabled"] = serde_json::json!(false);
    agent_body["waf_mode"] = serde_json::json!("detection");
    agent_body["bind_ip"] = serde_json::json!(bind_ip);
    // An agent without Apache answers 409 `apache_not_installed`; `agent_error`
    // relays it with its code and the open transaction drops the row.
    agent_body["web_server"] = serde_json::json!(web_server);
    if let Some(pool) = crate::routes::php_settings::php_pool_for_site(&site) {
        agent_body["php_pool"] = pool;
    }
    // import-hestia W3-V/W3-F: the same optional keys every rebuild sends.
    apply_vhost_extras(&mut agent_body, &site);

    // Atomically reserve the reseller site-quota slot BEFORE the agent creates the
    // nginx vhost - closes the check-then-increment TOCTOU without orphaning an nginx
    // config on a quota-race (the open tx below rolls back the uncommitted site row if
    // this rejects). The early check_reseller_quota above is a fast-path UX pre-check.
    let site_slot_reserved = reserve_reseller_site_slot(&state, claims.sub).await?;

    // Call agent to create nginx config
    let agent_path = format!("/nginx/sites/{}", body.domain);
    match agent.put(&agent_path, agent_body).await {
        Ok(_) => {
            emit_step(&logs, site_id, "nginx", "Configuring web server", "done", None);

            // Agent succeeded - commit the transaction so the site record is persisted
            // (background tasks like monitors, backups, SSL need the site to exist)
            if let Err(e) = tx.commit().await {
                if site_slot_reserved {
                    release_reseller_site_slot(&state, claims.sub).await;
                }
                return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Transaction commit failed: {e}")));
            }

            // Update status to active
            sqlx::query(
                "UPDATE sites SET status = 'active', updated_at = NOW() \
                 WHERE id = $1 AND status = 'creating'"
            )
                .bind(site.id)
                .execute(&state.db)
                .await
                .map_err(|e| internal_error("create sites", e))?;

            let updated: Site = sqlx::query_as("SELECT * FROM sites WHERE id = $1")
                .bind(site.id)
                .fetch_one(&state.db)
                .await
                .map_err(|e| internal_error("create sites", e))?;

            // GAP 50: Block direct external access to proxy port (only allow localhost via nginx)
            if let Some(port) = effective_proxy_port {
                let _ = agent.post("/security/firewall/rules", Some(serde_json::json!({
                    "port": port as u16,
                    "proto": "tcp",
                    "action": "deny",
                    "from": null
                }))).await;
                tracing::info!("Auto-firewall: blocked external access to port {port} for {}", body.domain);
            }

            tracing::info!("Site created: {} ({})", body.domain, runtime);
            // Multi-IP: an automatic same-named mail domain now follows this site's address.
            crate::routes::mail::resync_if_mail_follows(&state, server_id, &[&domain], &agent).await;
            let ip = crate::routes::client_ip(&headers);
            activity::log_activity(
                &state.db, claims.sub, &claims.email, "site.create",
                Some("site"), Some(&body.domain), Some(runtime), ip.as_deref(),
                claims.key_id,
            ).await;

            // Panel notification
            notifications::notify_panel(&state.db, Some(claims.sub), &format!("Site created: {}", body.domain), &format!("New {} site is now active", runtime), "info", "site", Some(&format!("/sites/{}", site.id))).await;

            fire_event(&state.db, "site.created", serde_json::json!({
                "site_id": site.id, "domain": site.domain, "runtime": site.runtime,
            }));

            // Reseller site counter already incremented atomically by the reserve above.

            // NOTE: Auto-monitor creation disabled - on fresh installs without DNS
            // configured, auto-created monitors immediately show "down" which confuses
            // new users. Users can create monitors manually when ready.

            // Auto-create backup schedule for every new site (daily 3 AM, 7 retention)
            {
                let backup_db = state.db.clone();
                let backup_site_id = site.id;
                tokio::spawn(async move {
                    let _ = sqlx::query(
                        "INSERT INTO backup_schedules (site_id, schedule, retention_count, enabled) \
                         VALUES ($1, '0 3 * * *', 7, true) ON CONFLICT (site_id) DO NOTHING"
                    ).bind(backup_site_id).execute(&backup_db).await;
                    tracing::info!("Auto-backup: created daily schedule for new site");
                });
            }

            // GAP 6: Auto-create secrets vault for the site.
            //
            // Created INLINE (not in a spawned task) so its id is available to the
            // CMS installer below. Until v2.28.0 this was fire-and-forget, and the
            // CMS task raced it - which is part of why the auto-generated admin
            // password was never stored anywhere and the vault sat empty (F3).
            let site_vault_id: Option<Uuid> = sqlx::query_scalar(
                "INSERT INTO secret_vaults (user_id, name, description, site_id) \
                 VALUES ($1, $2, $3, $4) RETURNING id"
            )
            .bind(claims.sub)
            .bind(format!("{} secrets", body.domain))
            .bind(format!("Auto-created vault for {}", body.domain))
            .bind(site.id)
            .fetch_optional(&state.db)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Auto-vault: could not create vault for {}: {e}", body.domain);
                None
            });
            if site_vault_id.is_some() {
                tracing::info!("Auto-vault: created for {}", body.domain);
            }

            // GAP 15: Auto-create paused uptime monitor (activates after SSL provisioning)
            {
                let mon_db = state.db.clone();
                let mon_site_id = site.id;
                let mon_user_id = claims.sub;
                let mon_domain = body.domain.clone();
                tokio::spawn(async move {
                    let url = format!("https://{mon_domain}");
                    let _ = sqlx::query(
                        "INSERT INTO monitors (user_id, site_id, url, name, check_interval, status, enabled, monitor_type) \
                         VALUES ($1, $2, $3, $4, 60, 'pending', FALSE, 'http') ON CONFLICT DO NOTHING"
                    )
                    .bind(mon_user_id).bind(mon_site_id)
                    .bind(&url).bind(&mon_domain)
                    .execute(&mon_db).await;
                    tracing::info!("Auto-monitor: created (paused) for {mon_domain}");
                });
            }

            // GAP 4: Auto-create status page component if status page is enabled
            {
                let sp_db = state.db.clone();
                let _sp_site_id = site.id;
                let sp_user_id = claims.sub;
                let sp_domain = body.domain.clone();
                tokio::spawn(async move {
                    let enabled: Option<(bool,)> = match sqlx::query_as(
                        "SELECT enabled FROM status_page_config WHERE user_id = $1"
                    ).bind(sp_user_id).fetch_optional(&sp_db).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("DB error checking status page config for auto-component: {e}");
                            None
                        }
                    };

                    if enabled.map(|(e,)| e).unwrap_or(false) {
                        let _ = sqlx::query(
                            "INSERT INTO status_page_components (user_id, name, description, group_name) \
                             VALUES ($1, $2, $3, 'Sites')"
                        )
                        .bind(sp_user_id).bind(&sp_domain)
                        .bind(format!("Auto-created for {sp_domain}"))
                        .execute(&sp_db).await;
                        tracing::info!("Auto-component: created status page component for {sp_domain}");
                    }
                });
            }

            // Auto-DNS: create A record if user has a DNS zone for this domain
            {
                let dns_domain = body.domain.clone();
                let dns_db = state.db.clone();
                let dns_logs = logs.clone();
                let dns_user_id = claims.sub;
                // The host this site is being created ON. Auto-DNS must publish
                // THIS machine's address, not the panel's - see
                // `helpers::public_ip_for_server`. Here the two agree only on a
                // single-box install; on a fleet the record used to point every
                // member's site at the panel, which made the site unreachable at
                // the very name the form had just claimed for it.
                let dns_server_id = server_id;
                // Multi-IP: the address THIS site listens on (public_ip → ip →
                // the server's primary public address).
                let dns_ip_id = body.ip_id;
                tokio::spawn(async move {
                    // Extract parent domain
                    let parts: Vec<&str> = dns_domain.splitn(3, '.').collect();
                    let parent = if parts.len() >= 3 {
                        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
                    } else {
                        dns_domain.clone()
                    };

                    let zone: Option<(String, Option<String>, Option<String>, Option<String>)> = match sqlx::query_as(
                        "SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2"
                    ).bind(&parent).bind(dns_user_id).fetch_optional(&dns_db).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("DB error fetching DNS zone for auto-DNS on site create: {e}");
                            None
                        }
                    };

                    if let Some((provider, cf_zone_id, cf_api_token, cf_api_email)) = zone {
                        let Some(server_ip) =
                            crate::services::server_ips::site_dns_address(&dns_db, Some(dns_server_id), dns_ip_id).await
                        else {
                            // Refusing is the whole point: an A record naming the
                            // wrong machine is worse than no record, because it
                            // resolves and answers.
                            emit_step(&dns_logs, site_id, "dns", "Creating DNS record", "failed", Some("could not determine this server's public address".to_string()));
                            return;
                        };

                        if provider == "cloudflare" {
                            if let (Some(zid), Some(tok)) = (cf_zone_id, cf_api_token) {
                                let client = reqwest::Client::new();
                                let headers = crate::helpers::cf_headers(&tok, cf_api_email.as_deref());
                                let _ = client.post(&format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records"))
                                    .headers(headers)
                                    .json(&serde_json::json!({"type":"A","name":dns_domain,"content":server_ip,"proxied":true,"ttl":1}))
                                    .send().await;
                                tracing::info!("Auto-DNS: created A record {dns_domain} → {server_ip}");
                                emit_step(&dns_logs, site_id, "dns", "Creating DNS record", "done", None);
                            }
                        } else if provider == "powerdns" {
                            let pdns: Vec<(String, String)> = sqlx::query_as(
                                "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')"
                            ).fetch_all(&dns_db).await.unwrap_or_default();
                            let purl = pdns.iter().find(|(k,_)| k == "pdns_api_url").map(|(_,v)| v.clone());
                            let pkey_enc = pdns.iter().find(|(k,_)| k == "pdns_api_key").map(|(_,v)| v.clone());
                            if let (Some(url), Some(key_enc)) = (purl, pkey_enc) {
                                let key = crate::services::secrets_crypto::decrypt_credential_from_env(&key_enc);
                                let zfqdn = if parent.ends_with('.') { parent.clone() } else { format!("{parent}.") };
                                let _ = reqwest::Client::new()
                                    .patch(&format!("{url}/api/v1/servers/localhost/zones/{zfqdn}"))
                                    .header("X-API-Key", &key)
                                    .json(&serde_json::json!({"rrsets":[{"name":format!("{dns_domain}."),"type":"A","ttl":300,"changetype":"REPLACE","records":[{"content":server_ip,"disabled":false}]}]}))
                                    .send().await;
                                tracing::info!("Auto-DNS (PowerDNS): created A record {dns_domain} → {server_ip}");
                                emit_step(&dns_logs, site_id, "dns", "Creating DNS record", "done", None);
                            }
                        }
                    }
                });
            }

            // Decided up front because the SSL task's outcome channel below has to
            // be handed to whichever branch owns the terminal step.
            let cms_type = body.cms.as_deref().unwrap_or("");
            let needs_db = matches!(cms_type, "wordpress" | "laravel" | "drupal" | "joomla" | "codeigniter");
            let needs_install = matches!(cms_type, "wordpress" | "laravel" | "drupal" | "joomla" | "symfony" | "codeigniter");

            // Auto-SSL: try to provision Let's Encrypt cert in background.
            //
            // Resolve the ACME contact BEFORE spawning. A contact address in a
            // reserved TLD (the operator registered the panel as e.g.
            // admin@box.test) makes Let's Encrypt refuse the account, so every
            // order fails - and before s253 that failed four times in total
            // silence: nothing in the UI, nothing in journalctl, then a permanent
            // give-up. Resolving here lets the real reason become a visible step.
            let acme_contact =
                crate::routes::ssl::resolve_acme_contact(&state.db, &claims.email).await;
            let ssl_agent = agent.clone();
            let ssl_db = state.db.clone();
            let ssl_domain = body.domain.clone();
            let ssl_email = match acme_contact {
                Ok(addr) => addr,
                Err(reason) => {
                    tracing::warn!("Auto-SSL skipped for {}: {reason}", body.domain);
                    emit_step(&logs, site_id, "ssl", "SSL certificate", "error", Some(reason));
                    String::new()
                }
            };
            let ssl_runtime = runtime.to_string();
            // Version carrier, not a literal path - see the comment on the create-site call site.
            let ssl_php_socket = body.php_version.as_ref().map(|v| format!("unix:/run/php/php{v}-fpm.sock"));
            let ssl_proxy_port = body.proxy_port;
            let ssl_php_preset = body.php_preset.clone();
            let ssl_web_server = web_server;
            let ssl_root_path: Option<String> = None; // default root
            let ssl_logs = logs.clone();
            // Lets the terminal step below report what actually happened instead
            // of asserting success on a timer (s252 F2).
            let (ssl_tx, ssl_rx) = tokio::sync::oneshot::channel::<bool>();
            let mut ssl_tx = Some(ssl_tx);
            tokio::spawn(async move {
                // Empty means the contact could not be resolved above; the reason
                // has already been emitted as a step, so don't burn four retries
                // against an order the CA is certain to refuse.
                if ssl_email.is_empty() {
                    if let Some(tx) = ssl_tx.take() {
                        let _ = tx.send(false);
                    }
                    return;
                }
                // Retry SSL with backoff: 3s, 30s, 2m, 5m
                let delays = [3u64, 30, 120, 300];
                for (i, delay) in delays.iter().enumerate() {
                    tokio::time::sleep(Duration::from_secs(*delay)).await;
                    emit_step(&ssl_logs, site_id, "ssl", "Provisioning SSL certificate", "in_progress", None);
                    let mut ssl_body = serde_json::json!({
                        "email": ssl_email,
                        "runtime": ssl_runtime,
                        "php_socket": ssl_php_socket,
                        "proxy_port": ssl_proxy_port,
                        "web_server": ssl_web_server,
                    });
                    if let Some(ref preset) = ssl_php_preset {
                        ssl_body["php_preset"] = serde_json::json!(preset);
                    }
                    if let Some(ref root) = ssl_root_path {
                        ssl_body["root"] = serde_json::json!(root);
                    }
                    match ssl_agent.post(&format!("/ssl/provision/{ssl_domain}"), Some(ssl_body)).await {
                        Ok(result) => {
                            tracing::info!("Auto-SSL provisioned for {ssl_domain} (attempt {})", i + 1);
                            emit_step(&ssl_logs, site_id, "ssl", "Provisioning SSL certificate", "done", None);

                            // The body above carries the runtime, the root and the
                            // PHP socket, but NOT the per-site limits or the
                            // hardening fields - and the agent re-renders the whole
                            // vhost from it. This task retries with delays, so a
                            // limit the operator sets between creation and a later
                            // attempt is published and then silently dropped.
                            // Cheaper to put the row back than to keep this body in
                            // step with every column `build_nginx_body` renders.
                            crate::routes::ssl::rebuild_vhost_for_site(&ssl_db, &ssl_agent, site_id).await;

                            // Parse cert details from agent response
                            let ssl_expiry = result
                                .get("expiry")
                                .and_then(|v| v.as_str())
                                .and_then(crate::helpers::parse_agent_cert_expiry);
                            let cert_path = result.get("cert_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let key_path = result.get("key_path").and_then(|v| v.as_str()).unwrap_or("").to_string();

                            // Update site DB record with SSL status.
                            //
                            // ⚠ This statement recorded FOUR columns while the two
                            // deliberate issuance doors record their provenance too, so a
                            // site whose certificate arrived automatically at creation
                            // carried a NULL profile that the cooldown and margin helpers
                            // then read. The set-comparison pin (ssl-controls C1/C3) exists
                            // to keep this path and the upload path in step, and it could
                            // not see the gap because it compares this statement against
                            // the upload, not against the doors in `routes/ssl.rs`.
                            //
                            // This door is always HTTP-01 (`/ssl/provision/{domain}`,
                            // one identifier), so the subject is the site's own domain and
                            // it is never a wildcard.
                            let _ = sqlx::query(
                                "UPDATE sites SET ssl_enabled = true, ssl_cert_path = $1, ssl_key_path = $2, \
                                 ssl_expiry = $3, ssl_profile = NULL, \
                                 ssl_challenge = 'http-01', ssl_cert_subject = $5, ssl_wildcard = FALSE, \
                                 ssl_dns_zone_id = NULL, updated_at = NOW() WHERE id = $4"
                            )
                            .bind(&cert_path)
                            .bind(&key_path)
                            .bind(ssl_expiry)
                            .bind(site_id)
                            .bind(&ssl_domain)
                            .execute(&ssl_db)
                            .await;

                            // Activate paused monitors now that SSL is working
                            let _ = sqlx::query(
                                "UPDATE monitors SET enabled = TRUE WHERE site_id = $1 AND enabled = FALSE AND status = 'pending'"
                            )
                            .bind(site_id)
                            .execute(&ssl_db)
                            .await;

                            if let Some(tx) = ssl_tx.take() {
                                let _ = tx.send(true);
                            }
                            return; // Success, stop retrying
                        }
                        Err(e) => {
                            if i == delays.len() - 1 {
                                // Last attempt failed. Say WHY - this used to read
                                // "Skipped", which described neither the four
                                // attempts that had just happened nor their cause.
                                tracing::info!("Auto-SSL failed for {ssl_domain} after {} attempts: {e}", i + 1);
                                emit_step(&ssl_logs, site_id, "ssl", "SSL certificate", "error",
                                    Some(format!(
                                        "Could not issue a certificate after {} attempts: {e}. \
                                         The site is served over HTTP; open the site's SSL section to retry.",
                                        i + 1
                                    )));
                                if let Some(tx) = ssl_tx.take() {
                                    let _ = tx.send(false);
                                }
                            } else {
                                tracing::info!("Auto-SSL attempt {} for {ssl_domain} failed, retrying in {}s", i + 1, delays[i + 1]);
                            }
                        }
                    }
                }

                // If no CMS install, this is the final step - emit complete
                // (For WordPress, the WP task emits complete)
            });

            // One-click CMS/framework install
            if needs_install {
                let cms_agent = agent.clone();
                let cms_domain = body.domain.clone();
                let cms_db = state.db.clone();
                let cms_name = cms_type.to_string();
                let cms_label = match cms_type {
                    "wordpress" => "WordPress",
                    "laravel" => "Laravel",
                    "drupal" => "Drupal",
                    "joomla" => "Joomla",
                    "symfony" => "Symfony",
                    "codeigniter" => "CodeIgniter",
                    _ => cms_type,
                }.to_string();
                let cms_title = body.site_title.clone().unwrap_or_else(|| body.domain.clone());
                let cms_email = body.admin_email.clone().unwrap_or_else(|| "admin@example.com".to_string());
                let cms_user = body.admin_user.clone().unwrap_or_else(|| "admin".to_string());
                // Whether WE generated this password decides whether the user has
                // any other copy of it. If they typed one, don't echo it back.
                let cms_pass_generated = body.admin_password.is_none();
                let cms_pass = body.admin_password.clone().unwrap_or_else(|| {
                    use rand::Rng;
                    let mut rng = rand::rng();
                    (0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char).collect()
                });
                let cms_admin_user = cms_user.clone();
                let cms_vault_id = site_vault_id;
                let cms_logs = logs.clone();
                let cms_jwt_secret = state.config.jwt_secret.clone();

                tokio::spawn(async move {
                    let db_name = cms_domain.replace('.', "_").replace('-', "_");
                    let db_user_name = db_name.clone();
                    let db_password: String = {
                        use rand::Rng;
                        let mut rng = rand::rng();
                        (0..20).map(|_| rng.sample(rand::distr::Alphanumeric) as char).collect()
                    };

                    // 1. Create database (if needed)
                    let mut db_host = String::new();
                    if needs_db {
                        emit_step(&cms_logs, site_id, "database", "Creating MySQL database", "in_progress", None);

                        let db_result = cms_agent.post("/databases", Some(serde_json::json!({
                            "engine": "mysql",
                            "name": db_name,
                            "password": db_password,
                        }))).await;

                        let (host, db_port, db_container_id) = match db_result {
                            Ok(resp) => {
                                let port = resp.get("port").and_then(|v| v.as_u64()).unwrap_or(3306) as u16;
                                let cid = resp.get("container_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                emit_step(&cms_logs, site_id, "database", "Creating MySQL database", "done", None);
                                (format!("127.0.0.1:{port}"), port as i32, cid)
                            }
                            Err(e) => {
                                tracing::error!("{cms_label} DB creation failed for {cms_domain}: {e}");
                                emit_step(&cms_logs, site_id, "database", "Creating MySQL database", "error",
                                    Some(format!("Database creation failed: {e}")));
                                emit_step(&cms_logs, site_id, "complete", "Provisioning failed", "error", None);
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                cms_logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&site_id);
                                return;
                            }
                        };
                        db_host = host;

                        let encrypted_db_password = crate::services::secrets_crypto::encrypt_credential(&db_password, &cms_jwt_secret)
                            .unwrap_or_else(|_| db_password.clone());
                        // The site id is already in hand - this used to resolve it
                        // again from the domain, and `sites.domain` is unique only
                        // per server (`idx_sites_domain_server`). On a fleet holding
                        // the same domain twice the subquery could attach this
                        // database - credentials included - to the OTHER host's site
                        // row, i.e. to a different owner's account. If it matched no
                        // row at all the NOT NULL insert simply failed into the
                        // `let _`, leaving a running container with no row: an
                        // orphan the retention sweep can never see.
                        let _ = sqlx::query(
                            "INSERT INTO databases (site_id, engine, name, db_user, db_password_enc, container_id, port) \
                             VALUES ($1, 'mysql', $2, $3, $4, $5, $6) \
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(site_id)
                        .bind(&db_name)
                        .bind(&db_user_name)
                        .bind(&encrypted_db_password)
                        .bind(&db_container_id)
                        .bind(db_port)
                        .execute(&cms_db)
                        .await;

                        emit_step(&cms_logs, site_id, "db_init", "Waiting for database engine", "in_progress", None);
                        // Wait for MariaDB to be fully ready (TCP connects before MySQL is ready)
                        for _attempt in 1..=20 {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let php_check = safe_command("php")
                                .args(["-r", "try { new PDO(getenv('DSN'), getenv('DB_USER'), getenv('DB_PASS')); echo 'OK'; } catch(Exception $e) { echo 'FAIL'; }"])
                                .env("DSN", format!("mysql:host={db_host};dbname={db_name}"))
                                .env("DB_USER", &db_user_name)
                                .env("DB_PASS", &db_password)
                                .output()
                                .await;
                            if let Ok(out) = php_check {
                                if String::from_utf8_lossy(&out.stdout).contains("OK") {
                                    break;
                                }
                            }
                        }
                        emit_step(&cms_logs, site_id, "db_init", "Database engine ready", "done", None);
                    }

                    // 2. Install CMS/framework
                    let mut install_ok = true;
                    emit_step(&cms_logs, site_id, "install", &format!("Installing {cms_label}"), "in_progress", None);

                    // Install at the scheme the site can actually serve RIGHT NOW.
                    //
                    // Auto-SSL is still running in a task beside this one and may
                    // yet fail - DNS not pointed at the box is the ordinary first
                    // site. Committing WordPress to the secure URL regardless used
                    // to leave it 302ing to a scheme with no certificate, i.e.
                    // dead on both, while the panel called it active. Plain HTTP
                    // always works; the promotion below moves it across the moment
                    // there is a certificate to move it to.
                    let install_result = if cms_name == "wordpress" {
                        cms_agent.post(&format!("/wordpress/{cms_domain}/install"), Some(serde_json::json!({
                            "url": format!("http://{cms_domain}"),
                            "title": cms_title,
                            "admin_user": cms_user,
                            "admin_pass": cms_pass,
                            "admin_email": cms_email,
                            "db_name": db_name,
                            "db_user": db_user_name,
                            "db_pass": db_password,
                            "db_host": db_host,
                        }))).await
                    } else {
                        cms_agent.post(&format!("/cms/{cms_domain}/install"), Some(serde_json::json!({
                            "cms": cms_name,
                            "title": cms_title,
                            "admin_user": cms_user,
                            "admin_pass": cms_pass,
                            "admin_email": cms_email,
                            "db_name": db_name,
                            "db_user": db_user_name,
                            "db_pass": db_password,
                            "db_host": db_host,
                        }))).await
                    };

                    match install_result {
                        Ok(_) => {
                            tracing::info!("{cms_label} installed on {cms_domain}");
                            emit_step(&cms_logs, site_id, "install", &format!("Installing {cms_label}"), "done", None);

                            // Take custody of the credentials we just generated.
                            // The form says "Auto-generated if blank", so a user who
                            // takes that at its word has no other copy - before
                            // v2.28.0 the password went to wp-cli and nowhere else,
                            // locking them out of the site they had just made.
                            if let Some(vault_id) = cms_vault_id {
                                let stored_pass = store_site_secret(
                                    &cms_db, &cms_jwt_secret, vault_id,
                                    &format!("{cms_name}_admin_password"),
                                    &cms_pass,
                                    &format!("{cms_label} admin password for {cms_domain}"),
                                ).await;
                                store_site_secret(
                                    &cms_db, &cms_jwt_secret, vault_id,
                                    &format!("{cms_name}_admin_user"),
                                    &cms_admin_user,
                                    &format!("{cms_label} admin username for {cms_domain}"),
                                ).await;
                                if needs_db {
                                    store_site_secret(
                                        &cms_db, &cms_jwt_secret, vault_id,
                                        "database_password", &db_password,
                                        &format!("Database password for {db_name}"),
                                    ).await;
                                }

                                // Reveal a password we generated exactly once, at
                                // the moment it is created. It is also in the vault,
                                // so this is convenience, not the system of record -
                                // and the provisioning stream is owner-scoped
                                // (provision_log checks user_id).
                                if stored_pass && cms_pass_generated {
                                    emit_step(
                                        &cms_logs, site_id, "credentials",
                                        &format!("{cms_label} admin credentials"), "done",
                                        Some(format!(
                                            "Username {cms_admin_user} · password {cms_pass} - \
                                             saved to the \"{cms_domain} secrets\" vault. \
                                             Copy it now; this is the only time it is shown here."
                                        )),
                                    );
                                } else if stored_pass {
                                    emit_step(
                                        &cms_logs, site_id, "credentials",
                                        &format!("{cms_label} admin credentials"), "done",
                                        Some(format!(
                                            "Saved to the \"{cms_domain} secrets\" vault."
                                        )),
                                    );
                                } else {
                                    emit_step(
                                        &cms_logs, site_id, "credentials",
                                        &format!("{cms_label} admin credentials"), "error",
                                        Some("Could not be saved to the site vault - \
                                              reset the admin password from the site's tools.".into()),
                                    );
                                }
                            }

                            // Auto-create WordPress system cron
                            if cms_name == "wordpress" {
                                let cron_db = cms_db.clone();
                                let cron_domain = cms_domain.clone();
                                let cron_site_id = site_id;
                                tokio::spawn(async move {
                                    // No `> /dev/null 2>&1`: the agent's cron
                                    // filter blocks "> /dev/", and this row is
                                    // INSERTed straight into the database
                                    // without passing through that filter - so
                                    // the product was writing a job its own
                                    // guard rejects, and every later cron sync
                                    // failed for the whole box. cron discards
                                    // output on its own when MAILTO is empty;
                                    // the redirect bought nothing.
                                    let command = format!("cd /var/www/{cron_domain}/public && php wp-cron.php");
                                    let _ = sqlx::query(
                                        "INSERT INTO crons (site_id, label, command, schedule, enabled) \
                                         VALUES ($1, 'WordPress Cron', $2, '*/15 * * * *', true)"
                                    )
                                    .bind(cron_site_id)
                                    .bind(&command)
                                    .execute(&cron_db)
                                    .await;
                                    tracing::info!("Auto-cron: created WordPress cron for {cron_domain}");
                                });
                            }
                        }
                        Err(e) => {
                            tracing::error!("{cms_label} install failed for {cms_domain}: {e}");
                            install_ok = false;
                            emit_step(&cms_logs, site_id, "install", &format!("Installing {cms_label}"), "error",
                                Some(format!("{cms_label} install failed: {e}")));
                        }
                    }

                    // The terminal step must report what happened. It used to say
                    // "Site ready / done" unconditionally - including for an
                    // install that had just failed on the line above (s252 F2).
                    //
                    // It also has to account for SSL, which is the half of F2 that
                    // bites most often: the CMS installs fine, auto-SSL doesn't, and
                    // "Site ready" over a site with no HTTPS is the same false claim
                    // in a different costume. Bounded wait - the site is genuinely
                    // usable meanwhile, so past the bound we say HTTPS is still in
                    // progress rather than guessing either way.
                    let ssl_outcome = tokio::time::timeout(Duration::from_secs(45), ssl_rx).await;
                    if install_ok {
                        match ssl_outcome {
                            Ok(Ok(true)) => {
                                // The certificate can land while the install is
                                // still running, and at that moment there is no
                                // WordPress whose URL the agent could move. Ask
                                // again now that there is; it is a no-op if the
                                // agent already did it during provisioning.
                                let promoted = if cms_name == "wordpress" {
                                    cms_agent
                                        .post(&format!("/wordpress/{cms_domain}/promote-https"), None)
                                        .await
                                        .map_err(|e| e.to_string())
                                } else {
                                    Ok(serde_json::Value::Null)
                                };
                                match promoted {
                                    Ok(_) => {
                                        emit_step(&cms_logs, site_id, "complete", "Site ready", "done", None);
                                    }
                                    // HTTPS is live and nginx redirects to it, but
                                    // the site's own links still say HTTP. Saying
                                    // "ready" here would be the same false claim
                                    // this step was rebuilt to stop making.
                                    Err(e) => {
                                        tracing::warn!(
                                            "Canonical URL promotion failed for {cms_domain}: {e}"
                                        );
                                        emit_step(
                                            &cms_logs, site_id, "complete",
                                            &format!("{cms_label} installed - HTTPS live, site still set to HTTP"),
                                            "error",
                                            Some(format!(
                                                "The certificate is installed, but the site's address \
                                                 could not be switched to HTTPS: {e}. Update the site \
                                                 address in {cms_label} settings."
                                            )),
                                        );
                                    }
                                }
                            }
                            Ok(Ok(false)) => {
                                emit_step(
                                    &cms_logs, site_id, "complete",
                                    &format!("{cms_label} installed - HTTPS not configured"), "error",
                                    Some("The site is served over HTTP. See the SSL step above for \
                                          the reason, and retry from the site's SSL section.".into()),
                                );
                            }
                            _ => {
                                emit_step(
                                    &cms_logs, site_id, "complete",
                                    &format!("{cms_label} installed - HTTPS still in progress"), "done",
                                    Some("CyberHunter - Panel is still trying to issue a certificate. \
                                          The site's SSL section shows the result.".into()),
                                );
                            }
                        }
                    } else {
                        emit_step(
                            &cms_logs, site_id, "complete",
                            &format!("Site created - {cms_label} install failed"), "error",
                            Some("The site and its database exist, but the application was not \
                                  installed. See the failed step above.".into()),
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    cms_logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&site_id);
                });
            } else {
                // Non-CMS site: the terminal step reports the SSL outcome rather
                // than assuming it. This used to sleep a flat 12s and declare
                // "Site ready / done" - while Auto-SSL was still retrying at 30s,
                // 120s and 300s behind that success claim, and often never
                // succeeded at all (s252 F2).
                let final_logs = logs.clone();
                tokio::spawn(async move {
                    // Bound the wait: the full retry ladder runs ~7.5 minutes and
                    // nobody should watch a spinner that long for a site which is
                    // already serving. Past the bound we say HTTPS is still in
                    // progress, which is true, rather than that it is done.
                    match tokio::time::timeout(Duration::from_secs(75), ssl_rx).await {
                        Ok(Ok(true)) => {
                            emit_step(&final_logs, site_id, "complete", "Site ready", "done", None);
                        }
                        Ok(Ok(false)) => {
                            emit_step(
                                &final_logs, site_id, "complete",
                                "Site created - HTTPS not configured", "error",
                                Some("The site is served over HTTP. Open the site's SSL section \
                                      for the reason and to retry.".into()),
                            );
                        }
                        // Sender dropped, or we ran out of patience: SSL is still
                        // in flight or its task went away. Either way, unknown.
                        _ => {
                            emit_step(
                                &final_logs, site_id, "complete",
                                "Site created - HTTPS still in progress", "done",
                                Some("CyberHunter - Panel is still trying to issue a certificate. \
                                      The site's SSL section shows the result.".into()),
                            );
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    final_logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&site_id);
                });
            }

            let mut updated = updated;
            crate::services::server_ips::fill_bind_ip(&state.db, &mut updated).await;
            let warning = updated.php_version.as_deref().and_then(legacy_php_warning);
            Ok((StatusCode::CREATED, Json(site_json_with_warning(&updated, warning)?)))
        }
        Err(e) => {
            // Agent call failed - roll back the transaction (INSERT is undone)
            tracing::error!("Agent error creating site {}: {e}", body.domain);

            crate::services::system_log::log_event(
                &state.db,
                "error",
                "api",
                &format!("Site creation failed: {}", body.domain),
                Some(&e.to_string()),
            ).await;

            // tx is dropped here, automatically rolling back the INSERT
            drop(tx);
            // Release the reseller quota slot reserved just before the agent call.
            if site_slot_reserved {
                release_reseller_site_slot(&state, claims.sub).await;
            }

            emit_step(&logs, site_id, "nginx", "Configuring web server", "error",
                Some(format!("Agent error: {e}")));
            emit_step(&logs, site_id, "complete", "Provisioning failed", "error", None);

            // Clean up provision log after delay
            let cleanup_logs = logs.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                cleanup_logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&site_id);
            });

            Err(agent_error("Site configuration", e))
        }
    }
}

/// GET /api/sites/{id}/provision-log - SSE stream of provisioning steps.
pub async fn provision_log(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, axum::BoxError>>>, ApiError> {
    // Verify ownership
    let exists: Option<(Uuid,)> = sqlx::query_as(
        &format!("SELECT s.id FROM sites s WHERE {}", crate::helpers::SITE_CALLER_PREDICATE)
    )
    .bind(id).bind(claims.sub)
    .fetch_optional(&state.db).await
    .map_err(|e| internal_error("provision log", e))?;

    if exists.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "Site not found"));
    }

    // The `sites` row check above is kept as well as the per-key owner check
    // below: this is the one stream that deliberately carries a credential, and
    // it is worth two independent reasons to refuse rather than one.
    let (snapshot, rx) = crate::helpers::open_provision_log(
        &state.provision_logs,
        &state.deploy_owners,
        id,
        claims.sub,
        "No active provisioning for this site",
    )?;

    // First yield snapshot events, then stream live updates
    let snapshot_stream = futures::stream::iter(
        snapshot.into_iter().map(|step| {
            let data = serde_json::to_string(&step).unwrap_or_default();
            Ok(Event::default().data(data))
        })
    );

    let live_stream = BroadcastStream::new(rx)
        .filter_map(|result| async {
            match result {
                Ok(step) => {
                    let data = serde_json::to_string(&step).ok()?;
                    Some(Ok(Event::default().data(data)))
                }
                Err(_) => None,
            }
        });

    // The underlying channel closes (and this stream ends) once the job
    // finishes and its map entry is dropped - but a job in progress at
    // shutdown time can still run well past the graceful-drain window, so
    // race it against the panel's own shutdown signal too.
    let stream = snapshot_stream
        .chain(live_stream)
        .take_until(crate::helpers::shutdown_signal_fut(&state));

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}

/// GET /api/sites/{id} - Get site details.
pub async fn get_one(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Site>, ApiError> {
    // The two arms of [`crate::helpers::site_domain_for_caller`], for the whole
    // row rather than the domain. This is the read the site's own page makes, so
    // it is what decides whether an administrator can open a site at all - and
    // until now it could not, which left the operator who had just handed a site
    // to a client with a page that answered 404 and a control that lived only on
    // it (#51).
    let site: Site = sqlx::query_as(&SITE_FOR_CALLER_ALL)
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("get_one sites", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    let mut site = site;
    crate::services::server_ips::fill_bind_ip(&state.db, &mut site).await;
    crate::services::disk_usage::fill_disk_usage(&state.db, std::slice::from_mut(&mut site)).await;
    Ok(Json(site))
}

/// PHP versions this panel will accept from a client.
///
/// One list for both handlers below, where there were two identical literals.
/// It is still a second copy of the agent's own `ALLOWED_VERSIONS`, and
/// deliberately so - this side has to reject a bad version before it spawns
/// anything, and cannot ask an agent that may be a release behind. The
/// frontend no longer carries a third and fourth copy: both pickers read the
/// live list from `GET /api/php/versions`, which is the agent's answer for the
/// server the site actually runs on.
pub(crate) const PHP_VERSIONS: &[&str] = &["5.6", "7.4", "8.1", "8.2", "8.3", "8.4", "8.5"];

/// End-of-life versions kept for imported sites (import-hestia W3-P). Accepted
/// everywhere `PHP_VERSIONS` is, but every door that selects one answers with a
/// `warning` (see [`legacy_php_warning`]).
pub(crate) const LEGACY_PHP_VERSIONS: &[&str] = &["5.6", "7.4"];

/// The warning a create / switch response carries for an end-of-life version.
pub(crate) fn legacy_php_warning(version: &str) -> Option<String> {
    let v = version.trim();
    LEGACY_PHP_VERSIONS
        .contains(&v)
        .then(|| format!("PHP {v} reached end of life and gets no security updates"))
}

/// A site as the API returns it, plus an optional top-level `warning` key.
/// The site's own fields stay flat, so a client reading `Site` is unaffected.
fn site_json_with_warning(site: &Site, warning: Option<String>) -> Result<serde_json::Value, ApiError> {
    let mut v = serde_json::to_value(site).map_err(|e| internal_error("serialize site", e))?;
    if let Some(w) = warning {
        v["warning"] = serde_json::json!(w);
    }
    Ok(v)
}

/// PUT /api/sites/{id}/php - Switch PHP version for a site.
#[derive(serde::Deserialize)]
pub struct SwitchPhpRequest {
    pub version: String,
}

pub async fn switch_php(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SwitchPhpRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let version = body.version.trim();

    if !PHP_VERSIONS.contains(&version) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Invalid PHP version. Allowed: {}", PHP_VERSIONS.join(", ")),
        ));
    }

    let site: Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("switch php", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if site.runtime != "php" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "PHP version can only be changed on PHP sites",
        ));
    }

    // Rebuild the FULL vhost from current config with only php_version changed.
    // A hand-rolled partial body would silently drop the site's WAF / CSP /
    // Permissions-Policy / bot-protection on every PHP switch.
    let mut updated_site = site.clone();
    updated_site.php_version = Some(version.to_string());
    let agent_body = build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref());

    let agent_path = format!("/nginx/sites/{}", site.domain);
    agent
        .put(&agent_path, agent_body)
        .await
        .map_err(|e| agent_error("Nginx update", e))?;

    let updated: Site = sqlx::query_as(
        "UPDATE sites SET php_version = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(version)
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("switch php", e))?;

    tracing::info!("PHP version switched to {} for {}", version, site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.php_switch",
        Some("site"), Some(&site.domain), Some(version), None,
        claims.key_id,
    ).await;

    let mut updated = updated;
    crate::services::server_ips::fill_bind_ip(&state.db, &mut updated).await;
    Ok(Json(site_json_with_warning(&updated, legacy_php_warning(version))?))
}

/// The runtimes this switch will move a site BETWEEN - deliberately only two.
///
/// `proxy`, `node` and `python` are excluded, and not for caution's sake: they
/// are a different shape of change. Each needs a `proxy_port`, node/python
/// additionally need an `app_command` that `create_site` puts through a
/// per-runtime prefix whitelist, and - the part that actually bites - the agent's
/// `document_root_for` (`agent/src/services/nginx.rs:52`) maps those three to the
/// site directory itself while `static` and `php` BOTH map to `{site_dir}/public`.
/// So static⇄php is purely a vhost rebuild, whereas anything involving a proxying
/// runtime is a vhost rebuild PLUS moving the document root out from under files
/// the operator already put there. Issue #99 asked for html→PHP and was answered
/// with exactly this half; the other half is a separate feature, not a longer
/// version of this list.
const SWITCHABLE_RUNTIMES: &[&str] = &["static", "php"];

/// PUT /api/sites/{id}/runtime - Switch a site between the static and PHP runtimes.
#[derive(serde::Deserialize)]
pub struct SwitchRuntimeRequest {
    pub runtime: String,
    /// Required when switching TO php. Ignored when switching to static.
    pub php_version: Option<String>,
}

pub async fn switch_runtime(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SwitchRuntimeRequest>,
) -> Result<Json<Site>, ApiError> {
    let target = body.runtime.trim();

    if !SWITCHABLE_RUNTIMES.contains(&target) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Runtime can only be switched between {}. Changing to or from a proxying \
                 runtime moves the document root and is not supported here.",
                SWITCHABLE_RUNTIMES.join(" and ")
            ),
        ));
    }

    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("switch runtime", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if !SWITCHABLE_RUNTIMES.contains(&site.runtime.as_str()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "This site runs the '{}' runtime. Only {} sites can be switched.",
                site.runtime,
                SWITCHABLE_RUNTIMES.join(" and ")
            ),
        ));
    }

    if site.runtime == target {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Site is already running the '{target}' runtime"),
        ));
    }

    // A PHP target needs a version, and it must be stated rather than guessed: a
    // site that was PHP once still carries its old `php_version`, and silently
    // reusing it would switch the operator onto a version they never chose on
    // this trip through the control.
    let php_version = if target == "php" {
        let version = body
            .php_version
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "php_version is required when switching to the PHP runtime",
                )
            })?;
        if !PHP_VERSIONS.contains(&version) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                &format!("Invalid PHP version. Allowed: {}", PHP_VERSIONS.join(", ")),
            ));
        }
        Some(version.to_string())
    } else {
        None
    };

    // Rebuild the FULL vhost with only the runtime (and its PHP version) changed,
    // for the same reason `switch_php` does: a hand-rolled partial body drops the
    // site's WAF / CSP / Permissions-Policy / bot-protection.
    //
    // The agent side needs no new code. `put_site` already refuses a PHP version
    // the server does not have (with the message that offers to install it),
    // writes the per-site FPM pool, reloads PHP-FPM, and only re-points nginx once
    // the pool socket actually exists - the fail-safe that stops a switch from
    // 502-ing the site, which is the failure the reporter had already hit by hand.
    let mut updated_site = site.clone();
    updated_site.runtime = target.to_string();
    updated_site.php_version = php_version.clone();
    let agent_body = build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref());

    let agent_path = format!("/nginx/sites/{}", site.domain);
    agent
        .put(&agent_path, agent_body)
        .await
        .map_err(|e| agent_error("Nginx update", e))?;

    // Only after the vhost is actually live. A failed agent write above leaves the
    // row describing what is really being served.
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET runtime = $1, php_version = $2, updated_at = NOW() \
         WHERE id = $3 RETURNING *",
    )
    .bind(target)
    .bind(php_version.as_deref())
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("switch runtime", e))?;

    tracing::info!(
        "Runtime switched {} -> {} for {}",
        site.runtime,
        target,
        site.domain
    );
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "site.runtime_switch",
        Some("site"),
        Some(&site.domain),
        Some(&match php_version.as_deref() {
            Some(v) => format!("{} -> {} {}", site.runtime, target, v),
            None => format!("{} -> {}", site.runtime, target),
        }),
        None,
        claims.key_id,
    )
    .await;

    let mut updated = updated;
    crate::services::server_ips::fill_bind_ip(&state.db, &mut updated).await;
    Ok(Json(updated))
}

/// The two values `sites.web_server` accepts (feature 4, CHECK constraint in
/// `20261118000000_web_server.sql`).
pub(crate) const WEB_SERVERS: &[&str] = &["nginx", "apache"];

/// Validate a `web_server` value from a request body, returning its canonical
/// `'static` form. Unknown values are a 400 everywhere they are accepted.
pub(crate) fn parse_web_server(value: &str) -> Result<&'static str, String> {
    let v = value.trim();
    WEB_SERVERS
        .iter()
        .copied()
        .find(|w| *w == v)
        .ok_or_else(|| format!("web_server must be one of: {}", WEB_SERVERS.join(", ")))
}

/// The web server a NEW site is created with (B3 of `04-apache-contrats.md`).
///
/// - an explicit value is validated first, whatever the runtime, so a typo is
///   reported rather than silently ignored;
/// - a PHP site takes the requested value, or `apache` when none is given (D1);
/// - every other runtime is forced to `nginx`: Apache only ever fronts PHP.
pub(crate) fn resolve_create_web_server(
    runtime: &str,
    requested: Option<&str>,
) -> Result<&'static str, String> {
    let requested = requested.map(parse_web_server).transpose()?;
    if runtime == "php" {
        Ok(requested.unwrap_or("apache"))
    } else {
        Ok("nginx")
    }
}

#[derive(serde::Deserialize)]
pub struct SwitchWebServerRequest {
    pub web_server: String,
}

/// PUT /api/sites/{id}/web-server - Switch a PHP site between nginx alone and
/// nginx + Apache (B4 of `04-apache-contrats.md`).
///
/// Owner or administrator of the site's server, through the same
/// `SITE_FOR_CALLER_ALL` predicate as `switch_php`. The column is updated inside
/// a transaction and committed only once the agent has accepted the rebuilt
/// vhost, so a refusal (409 `apache_not_installed`, a failed `configtest`, ...)
/// leaves the row describing what is really served. `fastcgi_cache` is kept
/// as-is: the agent ignores it in Apache mode, and it is back in effect on the
/// way back to nginx.
///
/// Response: `{ "web_server": "nginx" | "apache" }`. Asking for the current
/// value is a no-op that answers the same shape without touching the agent.
pub async fn switch_web_server(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SwitchWebServerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let target = parse_web_server(&body.web_server).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;

    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("switch web server", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    if site.runtime != "php" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Only PHP sites can choose their web server",
        ));
    }

    if site.web_server == target {
        return Ok(Json(serde_json::json!({ "web_server": target })));
    }

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;
    let bind_ip = crate::services::server_ips::nginx_bind_ip(&state.db, &site).await;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal_error("switch web server", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET web_server = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(target)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("switch web server", e))?;

    // Full vhost from the updated row, like every other rebuild path. On error
    // the transaction is dropped (rolled back) and the agent's refusal, code
    // included, reaches the caller.
    agent
        .put(
            &format!("/nginx/sites/{}", site.domain),
            build_nginx_body(&updated, bind_ip.as_deref()),
        )
        .await
        .map_err(|e| agent_error("Web server switch", e))?;

    tx.commit()
        .await
        .map_err(|e| internal_error("switch web server", e))?;

    tracing::info!("Web server switched {} -> {} for {}", site.web_server, target, site.domain);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "site.web_server",
        Some("site"),
        Some(&site.domain),
        Some(&format!("{} -> {}", site.web_server, target)),
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "web_server": target })))
}

/// GET /api/php/versions - List available PHP versions (proxy to agent).
pub async fn php_versions(
    State(_state): State<AppState>,
    AuthUser(_claims): AuthUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent
        .get("/php/versions")
        .await
        .map_err(|e| agent_error("Site agent operation", e))?;

    Ok(Json(result))
}

/// POST /api/php/install - Install a PHP version (admin only).
///
/// Accepted, not performed: returns `202 { install_id }` and streams the outcome
/// over the same `/api/services/install/{id}/log` SSE the Services page already
/// uses. Installing a PHP version can mean adding deb.sury.org or a module
/// stream and then unpacking fifteen packages, which is minutes - comfortably
/// past the panel's own 300s `TimeoutLayer`, never mind Cloudflare - so holding
/// the request open could only ever produce a timeout for the installs that
/// needed the most time.
#[derive(serde::Deserialize)]
pub struct InstallPhpRequest {
    pub version: String,
}

pub async fn php_install(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<InstallPhpRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if claims.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, "Admin only"));
    }

    // Reject here as well as on the agent. The agent is the authority, but this
    // side spawns and answers 202 before it has heard from anything, so an
    // unchecked version would be reported as "started" and only contradicted
    // later, inside a log the caller has to go and read.
    if !PHP_VERSIONS.contains(&body.version.as_str()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Invalid PHP version. Allowed: {}", PHP_VERSIONS.join(", ")),
        ));
    }

    crate::routes::system::install_service_with_log(
        &state,
        agent,
        claims.sub,
        &claims.email,
        &format!("PHP {}", body.version),
        "/php/install",
        Some(serde_json::json!({ "version": body.version })),
    )
    .await
}

/// POST /api/php/uninstall - Uninstall a specific PHP version (admin only).
///
/// Accepted and logged, like the install: same 202 + `install_id`, same SSE.
pub async fn php_uninstall(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<InstallPhpRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if claims.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, "Admin only"));
    }

    if !PHP_VERSIONS.contains(&body.version.as_str()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Invalid PHP version. Allowed: {}", PHP_VERSIONS.join(", ")),
        ));
    }

    // Same inversion the install had, in the other direction: the agent budgets
    // 300s for the purge and its `apt-get autoremove` afterwards, and this side
    // was giving it 60. The purge is not cancelled by that - only the account of
    // it is, which is worse for a destructive operation than for an additive one.
    crate::routes::system::install_service_with_log(
        &state,
        agent,
        claims.sub,
        &claims.email,
        &format!("PHP {} (uninstall)", body.version),
        "/php/uninstall",
        Some(serde_json::json!({ "version": body.version })),
    )
    .await
}

/// PUT /api/sites/{id}/limits - Update per-site resource limits.
#[derive(serde::Deserialize)]
pub struct UpdateLimitsRequest {
    pub rate_limit: Option<i32>,
    pub max_upload_mb: Option<i32>,
    pub php_memory_mb: Option<i32>,
    pub php_max_workers: Option<i32>,
    pub custom_nginx: Option<String>,
    /// NULL = unlimited. Mirrors `rate_limit`'s convention: the settings form
    /// always echoes this back on save, so its absence means "unlimited" the
    /// same way an unset `rate_limit` means "no rate limit" - never "leave
    /// whatever was there".
    pub bandwidth_quota_mb: Option<i32>,
}

pub async fn update_limits(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateLimitsRequest>,
) -> Result<Json<Site>, ApiError> {
    let site: Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("update limits", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if let Some(rl) = body.rate_limit {
        if rl < 1 || rl > 10000 {
            return Err(err(StatusCode::BAD_REQUEST, "Rate limit must be between 1 and 10000"));
        }
    }
    let max_upload = body.max_upload_mb.unwrap_or(site.max_upload_mb);
    if max_upload < 1 || max_upload > 10240 {
        return Err(err(StatusCode::BAD_REQUEST, "Max upload must be between 1 and 10240 MB"));
    }
    let php_memory = body.php_memory_mb.unwrap_or(site.php_memory_mb);
    if php_memory < 32 || php_memory > 4096 {
        return Err(err(StatusCode::BAD_REQUEST, "PHP memory must be between 32 and 4096 MB"));
    }
    let php_workers = body.php_max_workers.unwrap_or(site.php_max_workers);
    if php_workers < 1 || php_workers > 100 {
        return Err(err(StatusCode::BAD_REQUEST, "PHP workers must be between 1 and 100"));
    }

    if let Some(ref custom) = body.custom_nginx {
        if !custom.is_empty() {
            super::is_safe_nginx_config(custom)
                .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        }
    }

    if let Some(q) = body.bandwidth_quota_mb
        && q < 1
    {
        return Err(err(StatusCode::BAD_REQUEST, "Bandwidth quota must be at least 1 MB"));
    }

    // A quota edit that lifts a site out of over-quota territory (raised the
    // cap, or removed it) shouldn't leave the site disabled until the
    // traffic_accounting_scheduler's next tick (up to 5 minutes) notices -
    // recover it here, in the same request, when that's now the case.
    let recovering = if site.bandwidth_suspended_at.is_some() {
        match body.bandwidth_quota_mb {
            None => true,
            Some(q) => {
                let year_month = chrono::Utc::now().format("%Y-%m").to_string();
                let used: i64 = sqlx::query_scalar(
                    "SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2",
                )
                .bind(id)
                .bind(&year_month)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .unwrap_or(0);
                used <= (q as i64) * 1024 * 1024
            }
        }
    } else {
        false
    };
    let new_enabled = if recovering { true } else { site.enabled };
    let new_suspended_at: Option<chrono::DateTime<chrono::Utc>> =
        if recovering { None } else { site.bandwidth_suspended_at };

    let custom_nginx = body.custom_nginx.as_deref();
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET rate_limit = $1, max_upload_mb = $2, php_memory_mb = $3, php_max_workers = $4, \
         custom_nginx = $5, bandwidth_quota_mb = $6, enabled = $7, bandwidth_suspended_at = $8, \
         updated_at = NOW() WHERE id = $9 RETURNING *",
    )
    .bind(body.rate_limit)
    .bind(max_upload)
    .bind(php_memory)
    .bind(php_workers)
    .bind(custom_nginx)
    .bind(body.bandwidth_quota_mb)
    .bind(new_enabled)
    .bind(new_suspended_at)
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("update limits", e))?;

    // Rebuild the FULL vhost from the post-update site (includes the new limits +
    // custom_nginx AND the site's WAF/CSP/Permissions-Policy/bot-protection that
    // a hand-rolled partial body used to drop).
    let agent_body = build_nginx_body(&updated, crate::services::server_ips::nginx_bind_ip(&state.db, &updated).await.as_deref());

    let agent_path = format!("/nginx/sites/{}", site.domain);
    agent
        .put(&agent_path, agent_body)
        .await
        .map_err(|e| agent_error("Resource limits", e))?;

    if recovering {
        if let Err(e) = agent.post(&format!("/nginx/sites/{}/enable", site.domain), None).await {
            tracing::warn!(
                "Bandwidth quota update: failed to re-enable {} at the agent after lifting suspension: {e}",
                site.domain
            );
        } else {
            activity::log_activity(
                &state.db, claims.sub, &claims.email, "site.bandwidth_suspension_lifted",
                Some("site"), Some(&site.domain), Some("quota raised or removed"), None,
                claims.key_id,
            ).await;
        }
    }

    tracing::info!("Resource limits updated for {}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.limits",
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    let mut updated = updated;
    crate::services::server_ips::fill_bind_ip(&state.db, &mut updated).await;
    Ok(Json(updated))
}

/// GET /api/sites/{id}/bandwidth-usage - current-month bytes used against
/// quota, suspension state, and up to 12 months of history for the usage chart.
pub async fn bandwidth_usage(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("bandwidth usage", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    let year_month = chrono::Utc::now().format("%Y-%m").to_string();
    let used_this_month: i64 = sqlx::query_scalar(
        "SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2",
    )
    .bind(id)
    .bind(&year_month)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("bandwidth usage", e))?
    .unwrap_or(0i64);

    let history: Vec<(String, i64)> = sqlx::query_as(
        "SELECT year_month, bytes_used FROM site_traffic_usage WHERE site_id = $1 \
         ORDER BY year_month DESC LIMIT 12",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("bandwidth usage", e))?;

    Ok(Json(serde_json::json!({
        "quota_mb": site.bandwidth_quota_mb,
        "used_bytes_this_month": used_this_month,
        "suspended_at": site.bandwidth_suspended_at,
        "year_month": year_month,
        "history": history.into_iter()
            .map(|(ym, b)| serde_json::json!({ "year_month": ym, "bytes_used": b }))
            .collect::<Vec<_>>(),
    })))
}

/// DELETE /api/sites/{id} - Delete a site and all associated resources.
pub async fn remove(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("remove sites", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    // Every destructive step below names this site by DOMAIN and runs on whichever host
    // this handle points at. Taking the handle from the caller's selection meant a site on
    // a fleet member had its databases, its firewall rule, its Redis index and its webroot
    // aimed at the panel host instead - and the firewall arm is the one step that is not
    // domain-namespaced, so it could match an unrelated rule there. The row names the host.
    let agent =
        crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    // Pre-delete backup: snapshot the site BEFORE anything destructive runs.
    //
    // This used to sit forty lines further down, AFTER `DELETE /nginx/sites/{domain}`
    // - whose agent handler does `remove_dir_all("/var/www/{domain}")` - and after the
    // database containers were destroyed. `create_backup` opens with
    // `if !site_root.exists() { return Err(...) }`, so by the time it ran the site root
    // was always gone: the call returned an error 100% of the time, and `let _ =`
    // discarded it. The "backup before permanent deletion" had never written a byte on
    // this path, and the comment above it said it had.
    //
    // It is still best-effort - a failed snapshot must not strand a site the operator
    // asked to delete - but a failure is now LOGGED rather than swallowed, and the
    // databases are included, since they are still alive at this point.
    let predelete_dbs = crate::routes::backups::site_databases(&state, id).await;
    match agent
        .post(
            &format!("/backups/{}/create", site.domain),
            Some(serde_json::json!({
                "reason": "pre-delete",
                "databases": predelete_dbs.specs,
            })),
        )
        .await
    {
        Ok(info) => tracing::info!(
            "Pre-delete backup for {} created: {}",
            site.domain,
            info.get("filename").and_then(|v| v.as_str()).unwrap_or("(unnamed)")
        ),
        Err(e) => tracing::warn!(
            "Pre-delete backup for {} FAILED - continuing with deletion: {e}",
            site.domain
        ),
    }

    // Remove database containers before CASCADE deletes the records.
    //
    // The NAME is selected alongside the container id, and rows without a
    // container are carried too: a dump directory is keyed by the database name
    // and exists whether or not anything is still running. Selecting only the
    // container id meant this handler did not even hold the value the dump purge
    // needs, which is why site deletion left every dump on disk.
    let databases: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT name, container_id FROM databases WHERE site_id = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for (_, container_id) in &databases {
        let Some(container_id) = container_id.as_deref().filter(|c| !c.is_empty()) else {
            continue;
        };
        if let Err(e) = agent.delete(&format!("/databases/{container_id}")).await {
            tracing::warn!("Failed to remove database container {container_id}: {e}");
        }
    }

    // Databases on the shared local MariaDB (05-import-hestia D1) have no
    // container: their schema and user are dropped through the agent, or they
    // would outlive the site on the shared server.
    let local_dbs: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, db_user FROM databases WHERE site_id = $1 AND kind = 'local'",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (name, db_user) in &local_dbs {
        let body = serde_json::json!({ "db_user": db_user, "drop_user_if_unused": true });
        if let Err(e) = agent
            .post(&format!("/localdb/databases/{}/drop", urlencoding::encode(name)), Some(body))
            .await
        {
            tracing::warn!("Failed to drop local database {name}: {e}");
        }
    }

    // GAP 50: Remove firewall rule for proxy port on site deletion
    if let Some(port) = site.proxy_port {
        // Get current firewall rules and find the matching rule number to delete
        if let Ok(fw_status) = agent.get("/security/firewall").await {
            if let Some(rules) = fw_status.get("rules").and_then(|v| v.as_array()) {
                for rule in rules {
                    let rule_port = rule.get("port").and_then(|v| v.as_str()).unwrap_or("");
                    let rule_action = rule.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    if rule_port == format!("{port}/tcp") && rule_action.to_lowercase().contains("deny") {
                        if let Some(num) = rule.get("number").and_then(|v| v.as_u64()) {
                            let _ = agent.delete(&format!("/security/firewall/rules/{num}")).await;
                            tracing::info!("Auto-firewall: removed deny rule for port {port}");
                        }
                    }
                }
            }
        }
    }

    // Flush Redis DB for this site if Redis cache was enabled
    if site.redis_cache {
        agent.post(
            &format!("/nginx/sites/{}/redis/purge", site.domain),
            Some(serde_json::json!({ "redis_db": site.redis_db })),
        ).await.map_err(|e| tracing::warn!("Best-effort Redis purge failed for {}: {e}", site.domain)).ok();
    }

    // Tear down the SFTP account (if any) BEFORE the site directory itself is
    // removed below - detaching the bind mount and reverting ownership on a
    // directory that is about to be deleted anyway is redundant work, but it
    // keeps `deprovision`'s contract simple (it always leaves the box in a
    // fully-reverted state) rather than growing a delete-vs-disable branch.
    //
    // FTP first (feature 6): out of the whitelist, open FTP sessions cut, so no
    // vsftpd process of the account is left for `userdel` to trip over.
    // Best-effort, like the SFTP teardown: the site is going away regardless.
    if site.ftp_enabled {
        let _ = sqlx::query("UPDATE sites SET ftp_enabled = false WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await;
        if let Some(server_id) = site.server_id {
            match crate::routes::ftp::sync_ftp_users(&state.db, &agent, server_id).await {
                Ok(_) | Err(crate::routes::ftp::FtpSyncError::NotInstalled) => {}
                Err(e) => tracing::warn!("FTP teardown failed for {} during site deletion - continuing: {e}", site.domain),
            }
        }
    }
    if site.sftp_enabled
        && let (Some(uid), Some(gid)) = (site.sftp_uid, site.sftp_gid)
    {
        let last_sftp_site: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sites WHERE sftp_enabled = true AND id != $1",
        )
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap_or((1,)); // fail toward NOT removing the shared sshd drop-in
        if let Err(e) = agent.post(
            &format!("/sftp/sites/{}/disable", site.domain),
            Some(serde_json::json!({
                "uid": uid, "gid": gid, "last_sftp_site": last_sftp_site.0 == 0,
            })),
        ).await {
            tracing::warn!("SFTP teardown failed for {} during site deletion - continuing: {e}", site.domain);
        }
    }

    // Remove nginx config + SSL + PHP pool + site files + logs
    let agent_path = format!("/nginx/sites/{}", site.domain);
    agent.delete(&agent_path).await
        .map_err(|e| agent_error("Site removal", e))?;

    // Remove cron entries from system crontab before CASCADE deletes DB records
    let crons: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM crons WHERE site_id = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for (cron_id,) in &crons {
        if let Err(e) = agent.delete(&format!("/crons/remove/{cron_id}")).await {
            tracing::warn!("Failed to remove crontab entry {cron_id}: {e}");
        }
    }

    // Close the incidents of this site's monitors while their names are known.
    crate::services::deploy_incidents::retire_app_monitors(
        &state.db,
        site.user_id,
        Some(&site.domain),
        Some(id),
        None,
    )
    .await;

    // Delete monitors linked to this site (FK is SET NULL, not CASCADE)
    sqlx::query("DELETE FROM monitors WHERE site_id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .ok();

    // Clean up status page components matching this domain.
    //
    // Scoped to the owner. `status_page_components.name` is free text with no
    // unique constraint, and the owning module's own delete keys on
    // `id = $1 AND user_id = $2` (incidents.rs) - this statement had dropped
    // both, so deleting a site removed every OTHER account's component that
    // happened to carry the same name, taking its monitor links with it through
    // the ON DELETE CASCADE and logging nothing against the actor.
    sqlx::query("DELETE FROM status_page_components WHERE name = $1 AND user_id = $2")
        .bind(&site.domain)
        .bind(claims.sub)
        .execute(&state.db)
        .await
        .ok();

    // (The pre-delete backup used to be here - see the note above the version that
    // now runs before the destructive steps.)

    // Delete from DB (CASCADE removes databases, backups, crons, etc.)
    sqlx::query("DELETE FROM sites WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("remove sites", e))?;

    // Take each database's dumps with it, now that the cascade has removed the
    // rows that would otherwise answer the "is this name still in use" question
    // about themselves.
    //
    // ⛔ THE ORDER IS THE GUARD. Above this line every one of these names is
    // still claimed - by the very row being deleted - so the probe answers
    // "shared", nothing is purged, and the log reads like a correct decision.
    // There is no error, no failing request and no symptom; the only evidence
    // would be the dumps still on disk. This is pinned.
    for (name, _) in &databases {
        crate::routes::databases::purge_dumps_if_unclaimed(
            &state, &agent, name, site.server_id,
        ).await;
    }

    // Decrement reseller site counter
    let _ = sqlx::query(
        "UPDATE reseller_profiles SET used_sites = GREATEST(used_sites - 1, 0), updated_at = NOW() \
         WHERE user_id = (SELECT reseller_id FROM users WHERE id = $1 AND reseller_id IS NOT NULL)"
    ).bind(claims.sub).execute(&state.db).await;

    tracing::info!("Site deleted: {}", site.domain);
    // Multi-IP: an automatic same-named mail domain falls back to the primary address.
    if let Some(sid) = site.server_id {
        crate::routes::mail::resync_if_mail_follows(&state, sid, &[&site.domain], &agent).await;
    }
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.delete",
        Some("site"), Some(&site.domain), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "site.delete", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "critical",
        claims.key_id,
    ).await;

    // Panel notification
    // Deliberately unlinked: every other site notification carries
    // `/sites/{id}`, but this one's subject no longer exists. `main.tsx`'s
    // catch-all route sends an unresolvable path to the Dashboard without
    // saying why, so a link here would be a control that silently lies about
    // where it is taking you. A notification with no link renders as plain text.
    notifications::notify_panel(&state.db, Some(claims.sub), &format!("Site deleted: {}", site.domain), "Site and all associated resources have been removed", "info", "site", None).await;

    fire_event(&state.db, "site.deleted", serde_json::json!({
        "domain": &site.domain,
    }));

    // Auto-cleanup DNS record (best-effort, don't fail the delete)
    {
        let dns_domain = site.domain.clone();
        let dns_db = state.db.clone();
        let dns_user = claims.sub;
        // The host this site actually ran on. The cleanup below deletes a record
        // only when its content matches this address, so reading the PANEL's
        // address here meant a fleet member's record never matched and outlived
        // the site - a dangling A record still resolving to a machine that no
        // longer serves the name, which is a subdomain-takeover surface and not
        // merely untidy.
        let dns_server_id = site.server_id;
        let dns_ip_id = site.ip_id;
        tokio::spawn(async move {
            // Extract parent domain
            let parts: Vec<&str> = dns_domain.splitn(3, '.').collect();
            let parent = if parts.len() >= 3 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                dns_domain.clone()
            };

            let zone: Option<(String, Option<String>, Option<String>, Option<String>)> = match sqlx::query_as(
                "SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2"
            ).bind(&parent).bind(dns_user).fetch_optional(&dns_db).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("DB error fetching DNS zone for auto-cleanup on site delete: {e}");
                    None
                }
            };

            if let Some((provider, cf_zone_id, cf_api_token, cf_api_email)) = zone {
                let Some(server_ip) =
                    crate::services::server_ips::site_dns_address(&dns_db, dns_server_id, dns_ip_id).await
                else {
                    tracing::warn!("Auto-DNS cleanup: could not resolve the public address of the server {dns_domain} lived on - leaving the record in place rather than deleting one that may belong to another host");
                    return;
                };

                if provider == "cloudflare" {
                    if let (Some(zid), Some(tok)) = (cf_zone_id, cf_api_token) {
                        let client = reqwest::Client::new();
                        let headers = crate::helpers::cf_headers(&tok, cf_api_email.as_deref());
                        // Find the A record for this domain
                        if let Ok(resp) = client.get(&format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records?type=A&name={dns_domain}"))
                            .headers(headers.clone()).send().await {
                            if let Ok(data) = resp.json::<serde_json::Value>().await {
                                if let Some(records) = data.get("result").and_then(|r| r.as_array()) {
                                    for record in records {
                                        if let (Some(rid), Some(content)) = (record.get("id").and_then(|v| v.as_str()), record.get("content").and_then(|v| v.as_str())) {
                                            if content == server_ip {
                                                let _ = client.delete(&format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records/{rid}"))
                                                    .headers(headers.clone()).send().await;
                                                tracing::info!("Auto-DNS cleanup: deleted A record {dns_domain}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if provider == "powerdns" {
                    let pdns: Vec<(String, String)> = sqlx::query_as(
                        "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')"
                    ).fetch_all(&dns_db).await.unwrap_or_default();
                    let purl = pdns.iter().find(|(k,_)| k == "pdns_api_url").map(|(_,v)| v.clone());
                    let pkey_enc = pdns.iter().find(|(k,_)| k == "pdns_api_key").map(|(_,v)| v.clone());
                    if let (Some(url), Some(key_enc)) = (purl, pkey_enc) {
                        let key = crate::services::secrets_crypto::decrypt_credential_from_env(&key_enc);
                        let zfqdn = if parent.ends_with('.') { parent } else { format!("{parent}.") };
                        let _ = reqwest::Client::new()
                            .patch(&format!("{url}/api/v1/servers/localhost/zones/{zfqdn}"))
                            .header("X-API-Key", &key)
                            .json(&serde_json::json!({"rrsets":[{"name":format!("{dns_domain}."),"type":"A","ttl":300,"changetype":"DELETE","records":[]}]}))
                            .send().await;
                        tracing::info!("Auto-DNS cleanup (PowerDNS): deleted A record {dns_domain}");
                    }
                }
            }
        });
    }

    Ok(Json(serde_json::json!({ "ok": true, "domain": site.domain })))
}

// ──────────────────────────────────────────────────────────────
// Redirect Rules (proxy to agent)
// ──────────────────────────────────────────────────────────────

/// Helper: resolve a site this caller may act on, and return its domain.
///
/// Now one line over [`crate::helpers::site_domain_for_caller`], which is shared
/// with the five modules that each carried their own copy of this query. Read the
/// rules there - in particular why only the admin arm is scoped by server.
async fn site_domain(state: &AppState, site_id: Uuid, claims: &Claims) -> Result<String, ApiError> {
    crate::helpers::site_domain_for_caller(state, site_id, claims).await
}

/// GET /api/sites/{id}/redirects - List redirects.
pub async fn list_redirects(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .get(&format!("/nginx/redirects/{domain}"))
        .await
        .map_err(|e| agent_error("Redirects", e))?;
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
pub struct AddRedirectBody {
    pub source: String,
    pub target: String,
    #[serde(default = "default_301")]
    pub redirect_type: String,
}

fn default_301() -> String {
    "301".to_string()
}

/// POST /api/sites/{id}/redirects - Add a redirect.
pub async fn add_redirect(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<AddRedirectBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate source: must start with / and contain no shell metacharacters
    if !body.source.starts_with('/') || body.source.contains(|c: char| matches!(c, ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' | '\n' | '\r' | '\0')) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid redirect source: must start with / and contain no shell metacharacters"));
    }
    // Validate target: must be a valid URL (http/https) or a valid path (starts with /)
    if !(body.target.starts_with("http://") || body.target.starts_with("https://") || body.target.starts_with('/')) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid redirect target: must be a URL (http/https) or path (starts with /)"));
    }
    if body.target.contains(|c: char| matches!(c, ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' | '\n' | '\r' | '\0')) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid redirect target: contains shell metacharacters"));
    }

    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .post(
            "/nginx/redirects/add",
            Some(serde_json::json!({
                "domain": domain,
                "source": body.source,
                "target": body.target,
                "redirect_type": body.redirect_type,
            })),
        )
        .await
        .map_err(|e| agent_error("Redirects", e))?;
    Ok(Json(result))
}

/// POST /api/sites/{id}/redirects/remove - Remove a redirect.
pub async fn remove_redirect(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .post(
            &format!("/nginx/redirects/{domain}/remove"),
            Some(body),
        )
        .await
        .map_err(|e| agent_error("Redirects", e))?;
    Ok(Json(result))
}

// ──────────────────────────────────────────────────────────────
// Password Protection (proxy to agent)
// ──────────────────────────────────────────────────────────────

/// GET /api/sites/{id}/password-protect - List protected paths.
pub async fn list_protected(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .get(&format!("/nginx/password-protect/{domain}"))
        .await
        .map_err(|e| agent_error("Password protection", e))?;
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
pub struct PasswordProtectBody {
    pub path: String,
    pub username: String,
    pub password: String,
}

/// POST /api/sites/{id}/password-protect - Enable password protection.
pub async fn add_password_protect(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<PasswordProtectBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate path: no directory traversal, no shell metacharacters
    if body.path.contains("..") || body.path.contains(|c: char| matches!(c, ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' | '\n' | '\r' | '\0')) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid path: must not contain '..' or shell metacharacters"));
    }
    // Validate username: alphanumeric + underscore/hyphen only
    if body.username.is_empty() || !body.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid username: must be alphanumeric (underscores and hyphens allowed)"));
    }

    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .post(
            "/nginx/password-protect",
            Some(serde_json::json!({
                "domain": domain,
                "path": body.path,
                "username": body.username,
                "password": body.password,
            })),
        )
        .await
        .map_err(|e| agent_error("Password protection", e))?;
    Ok(Json(result))
}

/// POST /api/sites/{id}/password-protect/remove - Remove password protection.
pub async fn remove_password_protect(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .post(
            &format!("/nginx/password-protect/{domain}/remove"),
            Some(body),
        )
        .await
        .map_err(|e| agent_error("Password protection", e))?;
    Ok(Json(result))
}

// ──────────────────────────────────────────────────────────────
// Domain Aliases (proxy to agent)
// ──────────────────────────────────────────────────────────────

/// GET /api/sites/{id}/aliases - List domain aliases.
pub async fn list_aliases(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .get(&format!("/nginx/aliases/{domain}"))
        .await
        .map_err(|e| agent_error("Domain aliases", e))?;
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
pub struct AddAliasBody {
    pub alias: String,
}

/// POST /api/sites/{id}/aliases - Add a domain alias.
pub async fn add_alias(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<AddAliasBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_valid_domain(&body.alias) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid alias: must be a valid domain name"));
    }

    // This handler needs the host as a VALUE, not just as a handle, so it reads
    // the row rather than going through the domain-only resolver. Taking the id
    // from the caller's selection meant the collision check below ran against one
    // machine while the alias was written on another. The whole row is read
    // because the alias list itself may live in it (import-hestia D4).
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("add alias", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let domain = site.domain.clone();

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &domain).await?;
    // An alias becomes an nginx `server_name` on the caller's own vhost. Without
    // this guard any tenant could attach ANOTHER tenant's (or the panel's own)
    // live domain as an alias and hijack its traffic / intercept its ACME
    // HTTP-01 challenge. Reject reserved domains and any domain already served
    // by a site or git deployment on this server.
    let alias = ensure_domain_available(&state, &body.alias, &headers, &claims.role).await?;

    // The current list: the column when the database manages it, the vhost's
    // own names otherwise.
    let existing: Vec<String> = match site.aliases {
        Some(ref a) => a.clone(),
        None => read_agent_aliases(&agent, &domain)
            .await
            .map_err(|e| agent_error("Domain aliases", e))?,
    };
    validate_new_alias(&alias, &domain, &existing).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;

    let result = agent
        .post(
            "/nginx/aliases/add",
            Some(serde_json::json!({
                "domain": domain,
                "alias": alias,
            })),
        )
        .await
        .map_err(|e| agent_error("Domain aliases", e))?;

    // The column becomes managed: what the agent now serves is the list.
    let mut expected = existing;
    expected.push(alias.clone());
    let (stored, warning) = store_alias_list(&state, &agent, &site, expected).await;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.alias.add",
        Some("site"), Some(&domain), Some(&alias), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(alias_response(result, stored, warning)))
}

/// After the agent changed a site's aliases, read its list back and store it in
/// `sites.aliases` (the column becomes managed, D4). `expected` is the list the
/// change should have produced; it is used when the read-back fails and the
/// column was already managed, so a stale column cannot revert the change on
/// the next rebuild. Returns the stored list and a warning when nothing could
/// be stored (the column then stays as it was and the agent keeps the vhost's
/// own names).
async fn store_alias_list(
    state: &AppState,
    agent: &crate::services::agent::AgentHandle,
    site: &Site,
    expected: Vec<String>,
) -> (Option<Vec<String>>, Option<String>) {
    let list = match read_agent_aliases(agent, &site.domain).await {
        Ok(live) if aliases_storable(&site.domain, &live) => live,
        Ok(_) | Err(_) if site.aliases.is_some() && aliases_storable(&site.domain, &expected) => expected,
        Ok(_) => {
            return (
                site.aliases.clone(),
                Some("The vhost serves names the panel cannot manage; the alias list is left to the vhost".into()),
            );
        }
        Err(e) => {
            tracing::warn!("Could not read back the aliases of {}: {e}", site.domain);
            return (
                site.aliases.clone(),
                Some("The alias list could not be read back from the server; it will be recorded on the next change".into()),
            );
        }
    };
    if let Err(e) = sqlx::query("UPDATE sites SET aliases = $1, updated_at = NOW() WHERE id = $2")
        .bind(&list)
        .bind(site.id)
        .execute(&state.db)
        .await
    {
        tracing::warn!("Could not record the aliases of {}: {e}", site.domain);
        return (site.aliases.clone(), Some("The alias list could not be recorded".into()));
    }
    (Some(list), None)
}

/// The agent's answer, plus the recorded list and an optional warning.
fn alias_response(
    result: serde_json::Value,
    stored: Option<Vec<String>>,
    warning: Option<String>,
) -> serde_json::Value {
    let mut out = if result.is_object() { result } else { serde_json::json!({ "ok": true }) };
    if let Some(list) = stored {
        out["aliases"] = serde_json::json!(list);
    }
    if let Some(w) = warning {
        out["warning"] = serde_json::json!(w);
    }
    out
}

/// POST /api/sites/{id}/aliases/remove - Remove a domain alias.
///
/// Removing the name the canonical redirect points at (`canonical_host = www`
/// and alias `www.<domain>`) first clears `canonical_host` and rebuilds the
/// vhost - otherwise every request would be redirected to a name the site no
/// longer serves - then removes the alias. The response says so in `warning`.
pub async fn remove_alias(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let alias = body
        .get("alias")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if alias.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Alias required"));
    }

    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("remove alias", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let domain = site.domain.clone();
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &domain).await?;

    let removes_canonical_target = site.canonical_host.as_deref() == Some("www")
        && alias.eq_ignore_ascii_case(&canonical_target(&domain, "www"));
    let mut site = site;
    let mut warning: Option<String> = None;
    if removes_canonical_target {
        let mut tx = state.db.begin().await.map_err(|e| internal_error("remove alias", e))?;
        let updated: Site = sqlx::query_as(
            "UPDATE sites SET canonical_host = NULL, updated_at = NOW() WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| internal_error("remove alias", e))?;
        rebuild_then_commit(&state, &agent, tx, &updated, "Canonical host reset").await?;
        warning = Some(format!(
            "{alias} was the canonical host: the redirect to it has been removed"
        ));
        site = updated;
    }

    let result = agent
        .post(
            &format!("/nginx/aliases/{domain}/remove"),
            Some(serde_json::json!({ "alias": alias })),
        )
        .await
        .map_err(|e| agent_error("Domain aliases", e))?;

    let expected: Vec<String> = site
        .aliases
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|a| !a.eq_ignore_ascii_case(&alias))
        .collect();
    let (stored, store_warning) = store_alias_list(&state, &agent, &site, expected).await;
    let warning = match (warning, store_warning) {
        (Some(a), Some(b)) => Some(format!("{a}. {b}")),
        (a, b) => a.or(b),
    };

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.alias.remove",
        Some("site"), Some(&domain), Some(&alias), ip.as_deref(),
        claims.key_id,
    ).await;

    let mut out = alias_response(result, stored, warning);
    if removes_canonical_target {
        out["canonical_host"] = serde_json::Value::Null;
    }
    Ok(Json(out))
}

// ──────────────────────────────────────────────────────────────
// Access Logs, Traffic Stats, PHP Errors, Health Check
// ──────────────────────────────────────────────────────────────

/// GET /api/sites/{id}/access-logs - View nginx access/error logs for a site.
pub async fn access_logs(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let lines = params.get("lines").unwrap_or(&"200".to_string()).clone();
    let log_type = params.get("type").unwrap_or(&"access".to_string()).clone();
    let path = format!(
        "/nginx/site-logs/{}?lines={}&log_type={}",
        domain, lines, log_type
    );
    let result = agent
        .get(&path)
        .await
        .map_err(|e| agent_error("Site logs", e))?;
    Ok(Json(result))
}

/// GET /api/sites/{id}/stats - Basic traffic stats from access log.
pub async fn site_stats(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .get(&format!("/nginx/site-stats/{domain}"))
        .await
        .map_err(|e| agent_error("Site stats", e))?;
    Ok(Json(result))
}

/// GET /api/sites/{id}/php-errors - View PHP-FPM error log for a site.
pub async fn php_errors(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent
        .get(&format!("/nginx/php-errors/{domain}"))
        .await
        .map_err(|e| agent_error("PHP errors", e))?;
    Ok(Json(result))
}

/// GET /api/sites/{id}/health - Check if site is responding.
pub async fn health_check(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let domain = site_domain(&state, id, &claims).await?;

    // Check if site has SSL, and what it proxies to
    let row: Option<(bool, String, Option<i32>, Option<Uuid>)> =
        sqlx::query_as("SELECT ssl_enabled, runtime, proxy_port, server_id FROM sites WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let (ssl_enabled, runtime, proxy_port, server_id) =
        row.unwrap_or((false, String::new(), None, None));

    let port = upstream_port(&runtime, proxy_port);
    let upstream = match port {
        Some(p) => Some(probe_upstream(&state, server_id, &domain, p).await),
        None => None,
    };
    let upstream_json = port.zip(upstream).map(|(p, s)| upstream_report(p, s));

    let url = if ssl_enabled {
        format!("https://{domain}")
    } else {
        format!("http://{domain}")
    };

    let start = std::time::Instant::now();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    match client.get(&url).send().await {
        Ok(resp) => {
            let elapsed = start.elapsed().as_millis() as u32;
            let status = resp.status().as_u16();
            Ok(Json(serde_json::json!({
                "healthy": site_is_healthy(upstream, Some(status)),
                "status": status,
                "response_time_ms": elapsed,
                "url": url,
                "upstream": upstream_json,
            })))
        }
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u32;
            Ok(Json(serde_json::json!({
                "healthy": site_is_healthy(upstream, None),
                "status": 0,
                "response_time_ms": elapsed,
                "error": format!("{e}"),
                "url": url,
                "upstream": upstream_json,
            })))
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Composite Health Summary
// ──────────────────────────────────────────────────────────────

/// GET /api/sites/{id}/health-summary - Composite site health score.
pub async fn health_summary(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = &state.db;

    // Verify ownership
    #[allow(clippy::type_complexity)]
    let site: Option<(String, bool, Option<chrono::DateTime<chrono::Utc>>, String, Option<i32>, Option<Uuid>)> = sqlx::query_as(
        &format!("SELECT s.domain, s.ssl_enabled, s.ssl_expiry, s.runtime, s.proxy_port, s.server_id FROM sites s WHERE {}", crate::helpers::SITE_CALLER_PREDICATE)
    ).bind(id).bind(claims.sub).fetch_optional(db).await
        .map_err(|e| internal_error("health summary", e))?;

    let (domain, ssl_enabled, ssl_expiry, runtime, proxy_port, server_id) = site.ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    // The app behind the reverse proxy, asked directly: no monitor is needed for this
    let port = upstream_port(&runtime, proxy_port);
    let upstream = match port {
        Some(p) => Some(probe_upstream(&state, server_id, &domain, p).await),
        None => None,
    };

    let now = chrono::Utc::now();

    // SSL status
    let ssl_days_until_expiry = ssl_expiry.map(|exp| (exp - now).num_days());

    // Backup freshness
    let last_backup: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
        "SELECT created_at FROM backups WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1"
    ).bind(id).fetch_optional(db).await
        .map_err(|e| internal_error("health summary backup check", e))?;
    let backup_hours_since = last_backup.map(|(t,)| (now - t).num_hours());

    // Uptime: latest monitor status + response time
    let monitor: Option<(String, Option<i32>, bool)> = sqlx::query_as(
        "SELECT status, last_response_time, enabled FROM monitors WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1"
    ).bind(id).fetch_optional(db).await
        .map_err(|e| internal_error("health summary monitor check", e))?;
    let (monitor_status, response_time, monitor_enabled) = monitor
        .map(|(s, r, e)| (Some(s), r, e))
        .unwrap_or((None, None, false));

    // Compute score 0-100
    let mut score: i32 = 100;

    // No SSL: -25
    if !ssl_enabled {
        score -= 25;
    } else if let Some(days) = ssl_days_until_expiry {
        // SSL expiring in <7 days: -15, <30 days: -5
        if days < 0 {
            score -= 25; // expired
        } else if days < 7 {
            score -= 15;
        } else if days < 30 {
            score -= 5;
        }
    }

    // Stale backup: no backup in 48h: -20, no backup at all: -30
    match backup_hours_since {
        None => score -= 30,
        Some(h) if h > 48 => score -= 20,
        Some(h) if h > 24 => score -= 10,
        _ => {}
    }

    // Monitor down: -20, slow response (>2s): -10
    if let Some(ref status) = monitor_status {
        if status == "down" {
            score -= 20;
        }
    }
    if let Some(rt) = response_time {
        if rt > 5000 {
            score -= 15;
        } else if rt > 2000 {
            score -= 10;
        } else if rt > 1000 {
            score -= 5;
        }
    }

    // No monitor at all or disabled: -5
    if monitor_status.is_none() || !monitor_enabled {
        score -= 5;
    }

    score = score_with_upstream(score, upstream).max(0);

    Ok(Json(serde_json::json!({
        "domain": domain,
        "ssl_status": {
            "enabled": ssl_enabled,
            "days_until_expiry": ssl_days_until_expiry,
        },
        "backup_freshness": {
            "last_backup": last_backup.map(|(t,)| t),
            "hours_since": backup_hours_since,
        },
        "uptime": {
            "status": monitor_status,
            "response_time_ms": response_time,
            "monitor_enabled": monitor_enabled,
        },
        "upstream": port.zip(upstream).map(|(p, s)| upstream_report(p, s)),
        "score": score,
    })))
}

// ──────────────────────────────────────────────────────────────
// Site Cloning
// ──────────────────────────────────────────────────────────────

/// POST /api/sites/{id}/clone - Clone site to a new domain.
pub async fn clone_site(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, agent): ServerScope,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let target_domain = body.get("domain").and_then(|v| v.as_str())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Target domain required"))?;

    if !is_valid_domain(target_domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid target domain format"));
    }

    // Get source site
    let source: Option<Site> = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id).bind(claims.sub).fetch_optional(&state.db).await
        .map_err(|e| internal_error("clone site", e))?;
    let source = source.ok_or_else(|| err(StatusCode::NOT_FOUND, "Source site not found"))?;

    // A clone is ONE agent operation: `/nginx/clone-site` reads the source
    // docroot and writes the target docroot on the same box. So unlike the other
    // handlers in this family the fix is not "dispatch from the row" - the target
    // is genuinely a new site on the selected server, and the source is genuinely
    // wherever it already lives. When those differ there is no host that can do
    // the job, and the old code asked the SELECTED one, which has no such
    // docroot. Everything expensive is already committed by the time the agent
    // says so: the reseller quota slot is reserved and the `sites` row inserted
    // before the call, so the caller was left owning a registered,
    // quota-consuming site whose files never arrived.
    //
    // Refuse up front instead. Copying a docroot between machines is a feature
    // (it needs a transfer), not something to fake by pointing at the wrong disk.
    if source.server_id != Some(server_id) {
        return Err(err(
            StatusCode::CONFLICT,
            "This site lives on a different server. Select that server to clone it - \
             cloning across servers is not supported yet.",
        ));
    }

    // clone_site creates a brand-new site and must enforce the SAME admission
    // controls create() does - otherwise it is a create() with none of the
    // guards: it bypassed lockdown, the per-hour rate limit, the reseller quota,
    // the reserved-domain block, and the cross-table (git_deploys) uniqueness
    // check, letting a tenant mass-create sites during a lockdown and even
    // overwrite another tenant's git-deployed domain.
    if security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "System is in lockdown mode"));
    }
    {
        let max_sites: i64 = site_rate_limit(&state.db, &claims.role).await;
        let recent: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sites WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'",
        )
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
        if recent.0 >= max_sites {
            return Err(err(StatusCode::TOO_MANY_REQUESTS,
                &format!("Site creation rate limit: max {max_sites} sites per hour. \
                          An administrator can change this in Settings > Account > Security Hardening \
                          (\"Site Creation Rate Limit\"); set it to 0 to remove the limit.")));
        }
    }
    let target_domain = &ensure_domain_available(&state, target_domain, &headers, &claims.role).await?;
    // Atomically reserve the reseller site-quota slot AFTER the (fallible) domain checks
    // so a rejected clone cannot leak a quota slot; this mirrors create(), where the
    // reserve is the last pre-check before the mutation. Release it if the INSERT fails;
    // if a later agent step fails the site row persists and legitimately holds the slot.
    let clone_slot_reserved = reserve_reseller_site_slot(&state, claims.sub).await?;

    // Multi-IP: the clone listens where its source does when both are on the
    // same server; an address belongs to one server, so a clone onto another
    // host starts on that host's primary address. Row and vhost get the same value.
    let clone_ip_id: Option<Uuid> = if source.server_id == Some(server_id) { source.ip_id } else { None };
    let clone_bind_ip: String = match clone_ip_id {
        None => crate::services::server_ips::bind_ip_value(None),
        Some(ip_id) => crate::services::server_ips::bind_ip_value(
            crate::services::server_ips::declared_ip(&state.db, ip_id)
                .await
                .map_err(|e| internal_error("clone site ip", e))?
                .map(|row| row.ip)
                .as_deref(),
        ),
    };
    let clone_ip_id = if clone_bind_ip == crate::services::server_ips::PRIMARY { None } else { clone_ip_id };

    // Create new site record
    let new_site: Site = match sqlx::query_as::<_, Site>(
        // import-hestia: the no-exec folders and the SSL options describe the
        // site's content and policy, so they follow the clone. Aliases, the
        // canonical host and the SFTP name belong to the SOURCE's names and
        // account, so they never do.
        "INSERT INTO sites (user_id, server_id, domain, runtime, status, php_version, root_path, rate_limit, max_upload_mb, php_memory_mb, php_max_workers, php_preset, app_command, ip_id, php_settings, php_isolation, php_disable_shell, web_server, php_no_exec_dirs, force_ssl, hsts) \
         VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) RETURNING *"
    )
    .bind(claims.sub)
    .bind(server_id)
    .bind(target_domain)
    .bind(&source.runtime)
    .bind(&source.php_version)
    .bind(&source.root_path)
    .bind(source.rate_limit)
    .bind(source.max_upload_mb)
    .bind(source.php_memory_mb)
    .bind(source.php_max_workers)
    .bind(&source.php_preset)
    .bind(&source.app_command)
    .bind(clone_ip_id)
    .bind(&source.php_settings)
    .bind(source.php_isolation)
    .bind(source.php_disable_shell)
    .bind(&source.web_server)
    .bind(&source.php_no_exec_dirs)
    .bind(source.force_ssl)
    .bind(source.hsts)
    .fetch_one(&state.db).await
    {
        Ok(s) => s,
        Err(e) => {
            if clone_slot_reserved {
                release_reseller_site_slot(&state, claims.sub).await;
            }
            let msg = e.to_string();
            return Err(if msg.contains("duplicate") || msg.contains("unique") {
                err(StatusCode::CONFLICT, "A site with this domain already exists")
            } else {
                internal_error("clone site", e)
            });
        }
    };

    // Clone files via agent
    agent.post("/nginx/clone-site", Some(serde_json::json!({
        "source_domain": source.domain,
        "target_domain": target_domain,
    }))).await.map_err(|e| agent_error("Clone", e))?;

    // Set up nginx for new site
    let mut nginx_body = serde_json::json!({
        "runtime": source.runtime,
        "root": "/var/www",
    });
    if let Some(port) = source.proxy_port {
        nginx_body["proxy_port"] = serde_json::json!(port);
    }
    if let Some(ref php) = source.php_version {
        // Version carrier, not a literal path - see the comment on the create-site call site.
        nginx_body["php_socket"] = serde_json::json!(format!("unix:/run/php/php{php}-fpm.sock"));
    }
    if let Some(ref preset) = source.php_preset {
        nginx_body["php_preset"] = serde_json::json!(preset);
    }
    nginx_body["fastcgi_cache"] = serde_json::json!(source.fastcgi_cache);
    nginx_body["redis_cache"] = serde_json::json!(source.redis_cache);
    nginx_body["redis_db"] = serde_json::json!(source.redis_db);
    nginx_body["waf_enabled"] = serde_json::json!(source.waf_enabled);
    nginx_body["waf_mode"] = serde_json::json!(source.waf_mode);
    nginx_body["bind_ip"] = serde_json::json!(clone_bind_ip);
    nginx_body["web_server"] = serde_json::json!(new_site.web_server);
    if let Some(pool) = crate::routes::php_settings::php_pool_for_site(&new_site) {
        nginx_body["php_pool"] = pool;
    }
    apply_vhost_extras(&mut nginx_body, &new_site);

    agent.put(&format!("/nginx/sites/{target_domain}"), nginx_body).await
        .map_err(|e| agent_error("Nginx config", e))?;

    activity::log_activity(&state.db, claims.sub, &claims.email, "site.clone",
        Some("site"), Some(target_domain), Some(&source.domain), None, claims.key_id).await;

    // Reseller site counter already incremented atomically by the reserve above.

    fire_event(&state.db, "site.created", serde_json::json!({
        "site_id": new_site.id, "domain": target_domain, "runtime": &source.runtime, "cloned_from": &source.domain,
    }));

    // Auto-create backup schedule for cloned site (daily 3 AM, 7 retention)
    {
        let backup_db = state.db.clone();
        let backup_site_id = new_site.id;
        tokio::spawn(async move {
            let _ = sqlx::query(
                "INSERT INTO backup_schedules (site_id, schedule, retention_count, enabled) \
                 VALUES ($1, '0 3 * * *', 7, true) ON CONFLICT (site_id) DO NOTHING"
            ).bind(backup_site_id).execute(&backup_db).await;
            tracing::info!("Auto-backup: created daily schedule for cloned site");
        });
    }

    // Auto-create secrets vault for the cloned site
    {
        let vault_db = state.db.clone();
        let vault_site_id = new_site.id;
        let vault_user_id = claims.sub;
        let vault_domain = target_domain.to_string();
        tokio::spawn(async move {
            let _ = sqlx::query(
                "INSERT INTO secret_vaults (user_id, name, description, site_id) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
            )
            .bind(vault_user_id)
            .bind(format!("{vault_domain} secrets"))
            .bind(format!("Auto-created vault for {vault_domain}"))
            .bind(vault_site_id)
            .execute(&vault_db).await;
            tracing::info!("Auto-vault: created for cloned site {vault_domain}");
        });
    }

    // Auto-create status page component if status page is enabled
    {
        let sp_db = state.db.clone();
        let sp_user_id = claims.sub;
        let sp_domain = target_domain.to_string();
        tokio::spawn(async move {
            let enabled: Option<(bool,)> = match sqlx::query_as(
                "SELECT enabled FROM status_page_config WHERE user_id = $1"
            ).bind(sp_user_id).fetch_optional(&sp_db).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("DB error checking status page config for cloned site auto-component: {e}");
                    None
                }
            };

            if enabled.map(|(e,)| e).unwrap_or(false) {
                let _ = sqlx::query(
                    "INSERT INTO status_page_components (user_id, name, description, group_name) \
                     VALUES ($1, $2, $3, 'Sites')"
                )
                .bind(sp_user_id).bind(&sp_domain)
                .bind(format!("Auto-created for {sp_domain}"))
                .execute(&sp_db).await;
                tracing::info!("Auto-component: created status page component for cloned site {sp_domain}");
            }
        });
    }

    crate::routes::mail::resync_if_mail_follows(&state, server_id, &[target_domain], &agent).await;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "ok": true, "site_id": new_site.id, "domain": target_domain }))))
}

// ──────────────────────────────────────────────────────────────
// Custom SSL Upload
// ──────────────────────────────────────────────────────────────

/// Record a certificate installed outside the ACME doors (an operator upload,
/// or one carried over by the Hestia import, W5). The single statement both
/// write - see the comments in [`upload_ssl`] for why each column is set the
/// way it is: paths and expiry keep a known value over a missing one, the ACME
/// provenance columns are cleared because the installed certificate is no
/// longer the one they describe.
pub(crate) async fn record_uploaded_ssl(
    db: &sqlx::PgPool,
    site_id: Uuid,
    cert_path: Option<&str>,
    key_path: Option<&str>,
    expiry: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sites SET ssl_enabled = true, ssl_cert_path = COALESCE($1, ssl_cert_path), \
         ssl_key_path = COALESCE($2, ssl_key_path), ssl_expiry = COALESCE($3, ssl_expiry), \
         ssl_profile = NULL, \
         ssl_challenge = NULL, ssl_cert_subject = NULL, ssl_wildcard = NULL, \
         ssl_dns_zone_id = NULL, \
         ssl_renewal_at = NULL, ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $4",
    )
    .bind(cert_path)
    .bind(key_path)
    .bind(expiry)
    .bind(site_id)
    .execute(db)
    .await?;
    Ok(())
}

/// POST /api/sites/{id}/ssl/upload - Upload custom SSL certificate.
pub async fn upload_ssl(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;

    let mut agent_body = body.clone();
    agent_body["domain"] = serde_json::json!(domain);

    let uploaded = agent.post("/ssl/upload", Some(agent_body)).await
        .map_err(|e| agent_error("SSL upload", e))?;

    // Record WHAT was installed, not merely THAT something was.
    //
    // This wrote `ssl_enabled = true` and nothing else, while the ACME path
    // (`provision`, above) writes `ssl_cert_path`, `ssl_key_path` and
    // `ssl_expiry` in one statement. The three columns it skipped are the only
    // ones anything downstream reads, and every one of those readers filters on
    // `ssl_expiry IS NOT NULL`: the Dashboard SSL tile, `alert_engine`'s
    // `check_ssl_expiry` ladder, and `auto_healer::auto_renew_ssl`. So an
    // operator-supplied certificate was invisible to the countdown, to the
    // pager and to the healer alike - and the certificate list, which reads
    // the same NULL, called it OK. An uploaded certificate is precisely the
    // kind nobody renews for you; it was the one class the panel watched least.
    //
    // The agent hands back the paths it wrote. The expiry needs one more
    // question, asked of the route every agent has carried since the beginning
    // rather than of a new field only a fresh agent would return - this fix has
    // to reach installs whose agent nobody has updated.
    let cert_path = uploaded.get("cert_path").and_then(|v| v.as_str()).map(str::to_string);
    let key_path = uploaded.get("key_path").and_then(|v| v.as_str()).map(str::to_string);
    // Prefer the expiry the upload itself reported: it describes the certificate
    // that was just written, needs no second round trip, and cannot fail
    // separately from the write it belongs to. The `/ssl/status` call behind it is
    // the compatibility path for an agent older than this release - every agent
    // has carried that route since the beginning, so the fix reaches installs
    // nobody has updated.
    let expiry = uploaded
        .get("expiry")
        .and_then(|v| v.as_str())
        .and_then(crate::helpers::parse_agent_cert_expiry);
    let expiry = match expiry {
        Some(e) => Some(e),
        None => match agent.get(&format!("/ssl/status/{domain}")).await {
            Ok(status) => status
                .get("not_after")
                .and_then(|v| v.as_str())
                .and_then(crate::helpers::parse_agent_cert_expiry),
            Err(e) => {
                tracing::warn!("Uploaded certificate for {domain} is installed, but its expiry could not be read back: {e}");
                None
            }
        },
    };
    if expiry.is_none() {
        tracing::warn!("Uploaded certificate for {domain} stored with no new expiry - the previous value is kept rather than cleared, so the site stays visible to the expiry ladder and the auto-healer");
    }

    // The profile column describes how the PANEL ordered the certificate that used
    // to be here, and this upload replaced it. Both renewal doors feed that value
    // back to the agent, and the auto-healer reads it for the renewal margin and
    // the ARI cooldown, so leaving it in place applies a retired certificate's
    // terms to whatever the operator just installed. Cleared, not preserved:
    // absent means the next order resolves its own profile, which is what an
    // uploaded certificate honestly implies. Unlike its three siblings this one
    // is NOT wrapped in COALESCE - for those, keeping a known value beats erasing
    // it, and here the stored value is precisely what has stopped being true.
    if let Err(e) = record_uploaded_ssl(&state.db, id, cert_path.as_deref(), key_path.as_deref(), expiry).await {
        tracing::warn!("Failed to record uploaded certificate for site {id}: {e}");
    }

    // Re-render the FULL vhost from the site's DB config - the same compensation
    // every other SSL path already performs.
    //
    // The agent's `/ssl/upload` handler receives only {domain, certificate,
    // private_key} and has to invent the other nineteen fields of the SiteConfig it
    // renders, so it writes a vhost with WAF off, bot-protection off, no CSP, no
    // Permissions-Policy, no custom_nginx, default rate limits - and, because it
    // cannot know the site's PHP version, an unversioned `php-fpm.sock` that exists
    // on no modern Debian or Ubuntu. So uploading a certificate did not merely strip
    // a hardened site's security directives (with the panel's own toggles still
    // reading ON, since the DB row is untouched): on a PHP site it took the site
    // OFF THE AIR with a 502.
    //
    // v2.18.0 introduced this compensation for exactly this reason and applied it to
    // provision, renew and force-renew. Upload is the fourth sibling and was missed -
    // a fix to one instance of a pattern owes a grep for the pattern.
    crate::routes::ssl::rebuild_vhost_after_ssl(&state, &agent, id).await;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(&state.db, claims.sub, &claims.email, "ssl.upload",
        Some("site"), Some(&domain), None, ip.as_deref(), claims.key_id).await;
    crate::services::security_hardening::audit_log(
        &state.db, "ssl.upload", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&domain), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ──────────────────────────────────────────────────────────────
// PHP Extensions Manager
// ──────────────────────────────────────────────────────────────

/// GET /api/php/extensions/{version} - List PHP extensions.
pub async fn php_extensions(
    State(_state): State<AppState>,
    AuthUser(_claims): AuthUser,
    ServerScope(_server_id, agent): ServerScope,
    Path(version): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get(&format!("/php/extensions/{version}")).await
        .map_err(|e| agent_error("PHP extensions", e))?;
    Ok(Json(result))
}

/// POST /api/php/extensions/install - Install a PHP extension.
pub async fn install_php_extension(
    State(_state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Installing a PHP extension is a system/package-level op on the shared server,
    // admin-only exactly like its version-management siblings php_install/php_uninstall.
    if claims.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, "Admin only"));
    }
    agent.post("/php/extensions/install", Some(body)).await
        .map_err(|e| agent_error("PHP extension", e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ──────────────────────────────────────────────────────────────
// Environment Variables
// ──────────────────────────────────────────────────────────────

/// GET /api/sites/{id}/env - Read environment variables.
pub async fn get_env_vars(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    let result = agent.get(&format!("/nginx/env/{domain}")).await
        .map_err(|e| agent_error("Env vars", e))?;
    Ok(Json(result))
}

/// PUT /api/sites/{id}/env - Write environment variables.
pub async fn set_env_vars(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, agent) = crate::helpers::site_agent_for_caller(&state, id, &claims).await?;
    agent.put(&format!("/nginx/env/{domain}"), body).await
        .map_err(|e| agent_error("Env vars", e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// PUT /api/sites/{id}/domain - Rename a site's domain.
pub async fn rename_domain(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get current site
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("rename domain", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    // ⚠ The scope binding this replaces was spelled `_server_id` and was NOT unused -
    // the underscore silenced the warning while the value was still being passed to
    // the claim check below. Renaming a domain rewrites this site's vhost, so both
    // the check and the write have to name the host the row does.
    let agent =
        crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;
    let requested = body.get("new_domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    // Format, reserved, and every owner - including Docker apps, whose domain the
    // panel could not see before and which the agent's 8-step rename below would
    // have walked straight over (it checks that the SOURCE vhost exists and never
    // that the DESTINATION is free).
    let new_domain = domain_claim::ensure_claimable(
        &state.db,
        &state.agents,
        &requested,
        &headers,
        domain_claim::Holder::Site(id),
        &claims.role,
    )
    .await?;

    if new_domain == domain_claim::normalise(&site.domain) {
        return Err(err(StatusCode::BAD_REQUEST, "New domain is the same as current domain"));
    }

    // Call agent to rename nginx config, site dir, logs
    let old_domain = site.domain.clone();

    // An agent older than the carry release renames the vhost, the webroot, the
    // certificates, the logs, the pools and the jail - and silently leaves every
    // backup tree behind under the old name. It answers success either way, so
    // there is nothing in the response to notice. Refuse instead, and only for a
    // site that actually has archives to lose: a site with none renames on any
    // agent, which is what keeps a mid-upgrade fleet usable.
    let backup_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backups WHERE site_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    let agent_carries_backups = if backup_rows > 0 {
        let reported = agent
            .get("/health")
            .await
            .ok()
            .and_then(|v| v.get("version").and_then(|s| s.as_str()).map(str::to_string));
        let carries = crate::services::panel_update::semver_key(reported.as_deref())
            >= crate::services::panel_update::semver_key(Some(BACKUP_CARRY_MIN_AGENT));
        if !carries {
            return Err(err(
                StatusCode::PRECONDITION_FAILED,
                &format!(
                    "This site has {backup_rows} backup(s) and the agent on its server reports \
                     {}, which does not move a site's archives when the domain changes - they \
                     would be left on disk under {old_domain} where nothing can restore them. \
                     Update that server's agent to {BACKUP_CARRY_MIN_AGENT} or later, then \
                     rename.",
                    reported.as_deref().unwrap_or("an unknown version"),
                ),
            ));
        }
        true
    } else {
        false
    };

    agent.post(
        &format!("/nginx/sites/{}/rename", old_domain),
        Some(serde_json::json!({ "new_domain": new_domain })),
    ).await.map_err(|e| agent_error("Domain rename", e))?;

    // Update site record.
    //
    // ⛔ `ssl_cert_path`/`ssl_key_path` MUST move with the domain. The agent has
    // just renamed `/etc/dockpanel/ssl/{old}` to `{new}` (or copied it, when the
    // directory is shared), and this statement used to write the domain alone -
    // so a renamed site kept a path naming a directory it no longer uses, for
    // ever, since no renewal door rewrites the column either. That is not
    // cosmetic: `build_nginx_body` sends `ssl_cert_path` verbatim to the agent on
    // the next full vhost rebuild, so an unrelated later edit re-pointed nginx at
    // a directory that is gone.
    //
    // ⚠ Scoped to the site's OWN directory on purpose. A site whose certificate
    // is a DNS-01 wildcard has `ssl_cert_path` naming the ZONE, which the agent
    // does not touch on rename and which must not be rewritten to the new name -
    // that path is correct exactly as it stands. The `LIKE` therefore matches
    // only a path under the OLD domain's own directory.
    sqlx::query(
        "UPDATE sites SET domain = $1, \
         ssl_cert_path = CASE WHEN ssl_cert_path LIKE $3 \
             THEN '/etc/dockpanel/ssl/' || $1 || '/fullchain.pem' ELSE ssl_cert_path END, \
         ssl_key_path = CASE WHEN ssl_key_path LIKE $4 \
             THEN '/etc/dockpanel/ssl/' || $1 || '/privkey.pem' ELSE ssl_key_path END, \
         aliases = CASE WHEN aliases IS NULL THEN NULL ELSE ARRAY( \
             SELECT CASE WHEN right(a, length($5) + 1) = '.' || $5 \
                 THEN left(a, length(a) - length($5)) || $1 ELSE a END \
             FROM unnest(aliases) AS a \
             WHERE a <> $1) END, \
         updated_at = NOW() WHERE id = $2",
    )
        .bind(&new_domain)
        .bind(id)
        .bind(format!("/etc/dockpanel/ssl/{old_domain}/%"))
        .bind(format!("/etc/dockpanel/ssl/{old_domain}/%"))
        // Managed aliases follow the rename the agent applied to the vhost
        // (`www.<old>` becomes `www.<new>`), so `canonical_host = www` still
        // names a served host and the next rebuild is not refused.
        .bind(&old_domain)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("rename domain", e))?;

    // The agent renamed each archive's `{old}-` prefix to `{new}-` as part of the
    // carry, so the rows have to follow or every filename in them names a file
    // that is no longer there. Both sides derive the same prefix from the same
    // two domains, so this is a mirror of the move rather than a guess about it.
    if agent_carries_backups {
        let renamed_rows = sqlx::query(
            "UPDATE backups SET filename = $1 || substring(filename from $3) \
             WHERE site_id = $2 AND filename LIKE $4",
        )
        .bind(format!("{new_domain}-"))
        .bind(id)
        .bind(old_domain.len() as i32 + 2)
        .bind(format!("{old_domain}-%"))
        .execute(&state.db)
        .await;
        match renamed_rows {
            Ok(r) => tracing::info!(
                "Rename {old_domain} to {new_domain}: re-prefixed {} backup row(s)",
                r.rows_affected()
            ),
            Err(e) => tracing::error!(
                "Rename {old_domain} to {new_domain}: the archives moved but their rows could \
                 not be re-prefixed ({e}). Every backup row for this site now names a file that \
                 is not there."
            ),
        }

        // The carry is the one step of the rename whose success the panel can
        // check from the outside, and the check is version-independent: if
        // anything is still listed under the old name, something was left behind.
        match agent.get(&format!("/backups/{old_domain}/list")).await {
            Ok(v) => {
                // The agent answers this one with a bare array, not an object
                // wrapping a `backups` key. Reading a key that is not there
                // would make this check report "nothing left behind" for every
                // input it will ever see.
                let left = v.as_array().map(|a| a.len()).unwrap_or(0);
                if left > 0 {
                    tracing::error!(
                        "Rename {old_domain} to {new_domain} completed, but the agent still \
                         lists {left} backup(s) under {old_domain} - the carry did not take \
                         everything and those archives are unreachable from the panel."
                    );
                }
            }
            Err(e) => tracing::warn!(
                "Could not confirm the backup carry for {old_domain}: {e}"
            ),
        }
    }

    // Update monitors linked to this site.
    //
    // Keep whatever scheme the monitor already had. This used to rebuild the URL
    // as `https://{new_domain}` unconditionally, which is not a rename - it also
    // switched the monitor onto a scheme nobody asked it to check. That is wrong
    // for a site with no certificate, and it is not recoverable from
    // `sites.ssl_enabled` either, because a monitor's URL is editable by hand
    // from the Monitors screen. A domain rename should change the domain.
    sqlx::query(
        "UPDATE monitors SET name = $1, \
         url = CASE WHEN url LIKE 'http://%' THEN 'http://' || $1 ELSE 'https://' || $1 END \
         WHERE site_id = $2",
    )
    .bind(&new_domain)
    .bind(id)
    .execute(&state.db)
    .await
    .ok();

    // Update status page components - the mutating twin of the unscoped delete
    // in `remove`, and the same fix: without `user_id` a rename renamed every
    // other account's component that shared the old domain string.
    sqlx::query("UPDATE status_page_components SET name = $1 WHERE name = $2 AND user_id = $3")
        .bind(&new_domain)
        .bind(&old_domain)
        .bind(claims.sub)
        .execute(&state.db)
        .await
        .ok();

    tracing::info!("Domain renamed: {old_domain} → {new_domain}");
    // Multi-IP: the old name's automatic mail domain loses its site, the new
    // name's gains one - both change sending address.
    if let Some(sid) = site.server_id {
        crate::routes::mail::resync_if_mail_follows(&state, sid, &[&old_domain, &new_domain], &agent).await;
    }
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.rename_domain",
        Some("site"), Some(&new_domain), Some(&old_domain), None,
        claims.key_id,
    ).await;

    notifications::notify_panel(&state.db, Some(claims.sub),
        &format!("Domain renamed: {old_domain} → {new_domain}"),
        "Site domain has been updated", "info", "site", Some(&format!("/sites/{id}")),
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "old_domain": old_domain,
        "new_domain": new_domain,
    })))
}

/// PUT /api/sites/{id}/toggle - Enable or disable a site without deleting it.
pub async fn toggle_enabled(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("toggle site", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let enabled = body.get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'enabled' boolean field"))?;

    if enabled == site.enabled {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "enabled": enabled,
            "message": if enabled { "Site is already enabled" } else { "Site is already disabled" },
        })));
    }

    // Call agent to enable/disable the nginx config
    let action = if enabled { "enable" } else { "disable" };
    agent.post(
        &format!("/nginx/sites/{}/{action}", site.domain),
        None,
    ).await.map_err(|e| agent_error("Toggle site", e))?;

    // Update DB. A manual re-enable also clears bandwidth_suspended_at: without
    // this, `traffic_accounting_scheduler` would see a lingering suspended_at
    // and treat the site as still under active bandwidth suspension (never
    // re-checking its quota), even though a human just turned it back on. A
    // manual disable leaves the flag untouched - that path never sets it.
    sqlx::query(
        "UPDATE sites SET enabled = $1, bandwidth_suspended_at = CASE WHEN $1 THEN NULL ELSE bandwidth_suspended_at END, \
         updated_at = NOW() WHERE id = $2",
    )
        .bind(enabled)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("toggle site", e))?;

    let action_label = if enabled { "enabled" } else { "disabled" };
    tracing::info!("Site {} {action_label}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("site.{action_label}"),
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    notifications::notify_panel(&state.db, Some(claims.sub),
        &format!("Site {action_label}: {}", site.domain),
        &format!("Site has been {action_label}"), "info", "site", Some(&format!("/sites/{id}")),
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "enabled": enabled,
    })))
}

/// PUT /api/sites/{id}/fastcgi-cache - Toggle FastCGI cache for a PHP site.
pub async fn toggle_fastcgi_cache(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("toggle fastcgi cache", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if site.runtime != "php" {
        return Err(err(StatusCode::BAD_REQUEST, "FastCGI cache is only available for PHP sites"));
    }

    let enabled = body.get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'enabled' boolean field"))?;

    if enabled == site.fastcgi_cache {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "fastcgi_cache": enabled,
            "message": if enabled { "FastCGI cache is already enabled" } else { "FastCGI cache is already disabled" },
        })));
    }

    // Rebuild the FULL vhost with only fastcgi_cache changed - a hand-rolled
    // partial body used to drop the site's WAF/CSP/Permissions-Policy/bot-protection.
    let mut updated_site = site.clone();
    updated_site.fastcgi_cache = enabled;
    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref()),
    ).await.map_err(|e| agent_error("FastCGI cache", e))?;

    // Update DB
    sqlx::query("UPDATE sites SET fastcgi_cache = $1, updated_at = NOW() WHERE id = $2")
        .bind(enabled)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("toggle fastcgi cache", e))?;

    let action = if enabled { "enabled" } else { "disabled" };
    tracing::info!("FastCGI cache {action} for {}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("site.fastcgi_cache.{action}"),
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    notifications::notify_panel(&state.db, Some(claims.sub),
        &format!("FastCGI cache {action}: {}", site.domain),
        &format!("FastCGI cache has been {action}"), "info", "site", Some(&format!("/sites/{id}")),
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "fastcgi_cache": enabled,
    })))
}

/// POST /api/sites/{id}/fastcgi-cache/purge - Purge FastCGI cache for a site.
pub async fn purge_fastcgi_cache(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("purge fastcgi cache", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if !site.fastcgi_cache {
        return Err(err(StatusCode::BAD_REQUEST, "FastCGI cache is not enabled for this site"));
    }

    agent.post(
        &format!("/nginx/sites/{}/cache/purge", site.domain),
        None,
    ).await.map_err(|e| agent_error("Purge cache", e))?;

    tracing::info!("FastCGI cache purged for {}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        "site.fastcgi_cache.purge",
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "message": format!("FastCGI cache purged for {}", site.domain),
    })))
}

/// PUT /api/sites/{id}/redis-cache - Toggle Redis object cache for a PHP site.
pub async fn toggle_redis_cache(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("toggle redis cache", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if site.runtime != "php" {
        return Err(err(StatusCode::BAD_REQUEST, "Redis object cache is only available for PHP sites"));
    }

    let enabled = body.get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'enabled' boolean field"))?;

    if enabled == site.redis_cache {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "redis_cache": enabled,
            "message": if enabled { "Redis cache is already enabled" } else { "Redis cache is already disabled" },
        })));
    }

    // Assign unique Redis DB number (0-15) when enabling
    let redis_db = if enabled {
        let used: Vec<(i32,)> = sqlx::query_as(
            "SELECT redis_db FROM sites WHERE redis_cache = true AND id != $1"
        )
        .bind(id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal_error("redis db allocation", e))?;

        let used_dbs: std::collections::HashSet<i32> = used.into_iter().map(|(db,)| db).collect();
        (1..=15).find(|n| !used_dbs.contains(n))
            .ok_or_else(|| err(StatusCode::CONFLICT, "All Redis DB slots (1-15) are in use"))?
    } else {
        0
    };

    // Configure Redis on the agent
    if enabled {
        agent.post(
            &format!("/nginx/sites/{}/redis/enable", site.domain),
            Some(serde_json::json!({
                "redis_db": redis_db,
                "php_preset": site.php_preset,
            })),
        ).await.map_err(|e| agent_error("Redis cache enable", e))?;
    } else {
        agent.post(
            &format!("/nginx/sites/{}/redis/disable", site.domain),
            None,
        ).await.map_err(|e| agent_error("Redis cache disable", e))?;
    }

    // Rebuild the FULL vhost with only redis settings changed - a hand-rolled
    // partial body used to drop the site's WAF/CSP/Permissions-Policy/bot-protection.
    let mut updated_site = site.clone();
    updated_site.redis_cache = enabled;
    updated_site.redis_db = redis_db;
    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref()),
    ).await.map_err(|e| agent_error("Redis nginx config", e))?;

    // Update DB
    sqlx::query("UPDATE sites SET redis_cache = $1, redis_db = $2, updated_at = NOW() WHERE id = $3")
        .bind(enabled)
        .bind(redis_db)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("toggle redis cache", e))?;

    let action = if enabled { "enabled" } else { "disabled" };
    tracing::info!("Redis cache {action} for {} (db: {redis_db})", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("site.redis_cache.{action}"),
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    notifications::notify_panel(&state.db, Some(claims.sub),
        &format!("Redis cache {action}: {}", site.domain),
        &format!("Redis object cache has been {action} (DB {redis_db})"), "info", "site", Some(&format!("/sites/{id}")),
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "redis_cache": enabled,
        "redis_db": redis_db,
    })))
}

/// POST /api/sites/{id}/redis-cache/purge - Flush Redis cache for a site.
pub async fn purge_redis_cache(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("purge redis cache", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    if !site.redis_cache {
        return Err(err(StatusCode::BAD_REQUEST, "Redis cache is not enabled for this site"));
    }

    agent.post(
        &format!("/nginx/sites/{}/redis/purge", site.domain),
        Some(serde_json::json!({ "redis_db": site.redis_db })),
    ).await.map_err(|e| agent_error("Purge Redis", e))?;

    tracing::info!("Redis cache purged for {} (db: {})", site.domain, site.redis_db);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        "site.redis_cache.purge",
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "message": format!("Redis cache purged for {}", site.domain),
    })))
}

/// POST /api/sites/{id}/sftp/enable - Provision a per-site SFTP account.
///
/// The one explicit, operator-triggered step that re-owns an existing site's
/// content directory (see `panel/agent/src/services/sftp_accounts.rs`) - no
/// site is ever migrated without this being clicked. `sftp_uid`/`sftp_gid`
/// come from `sftp_id_seq`, an atomic Postgres sequence rather than a
/// `MAX(sftp_uid)+1` read (which races under concurrent enables).
///
/// Optional JSON body `{username?: string}` (D6): a custom account name instead
/// of `sftp<uid>`. An empty body - or no body at all - keeps the default. The
/// body is read as raw bytes because a client may POST with a JSON content
/// type and nothing in it, which `Option<Json<_>>` would refuse.
pub async fn enable_sftp(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    raw_body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if crate::services::security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "System is in lockdown mode"));
    }

    // Parse and validate the requested name before anything is allocated.
    let requested: Option<String> = if raw_body.iter().all(|b| b.is_ascii_whitespace()) {
        None
    } else {
        let parsed: serde_json::Value = serde_json::from_slice(&raw_body)
            .map_err(|_| err(StatusCode::BAD_REQUEST, "Body must be JSON: {\"username\"?: string}"))?;
        match parsed.get("username") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) if s.trim().is_empty() => None,
            Some(serde_json::Value::String(s)) => Some(s.trim().to_string()),
            Some(_) => return Err(err(StatusCode::BAD_REQUEST, "'username' must be a string")),
        }
    };
    if let Some(ref name) = requested {
        validate_sftp_username(name).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    }

    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("enable sftp", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    if site.sftp_enabled {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "sftp_enabled": true,
            "username": sftp_account_name(&site),
            "message": "SFTP is already enabled for this site",
        })));
    }

    // Unique in the panel (the partial unique index backs this up); the agent
    // separately checks the box's own passwd/group databases.
    if let Some(ref name) = requested {
        let taken: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM sites WHERE sftp_username = $1 AND id <> $2",
        )
        .bind(name)
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("enable sftp", e))?;
        if taken.is_some() {
            return Err(crate::error::err_coded(
                StatusCode::CONFLICT,
                &format!("The SFTP username '{name}' is already used by another site"),
                "username_taken",
            ));
        }
    }

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let (uid, gid) = reserve_sftp_ids(&state.db, &site)
        .await
        .map_err(|e| internal_error("allocate sftp uid", e))?;

    let mut enable_body = serde_json::json!({ "uid": uid, "gid": gid });
    if let Some(ref name) = requested {
        enable_body["username"] = serde_json::json!(name);
    }
    let enabled = agent.post(
        &format!("/sftp/sites/{}/enable", site.domain),
        Some(enable_body),
    ).await.map_err(|e| match e {
        // `agent_error` relays only a fixed set of codes; this one the SFTP
        // card branches on, so it is carried here.
        crate::services::agent::AgentError::Status(409, ref b) if b.contains("username_taken") => {
            crate::error::err_coded(
                StatusCode::CONFLICT,
                "That SFTP username already exists on the server",
                "username_taken",
            )
        }
        e => agent_error("SFTP enable", e),
    })?;
    // A resumed own leftover may live under another uid than the one asked.
    let (uid, gid) = sftp_ids_from_agent(&enabled, uid, gid);

    // Store the custom name ONLY when the agent says it created that account.
    // An agent that predates custom names ignores the field and creates
    // `sftp<uid>`; recording the requested name then would hand the PHP pool
    // to a user that does not exist.
    let mut warning: Option<String> = None;
    let stored_username: Option<String> = match requested {
        Some(ref name) if enabled.get("username").and_then(|v| v.as_str()) == Some(name.as_str()) => {
            Some(name.clone())
        }
        Some(_) => {
            warning = Some(format!(
                "This server does not support custom SFTP usernames yet: the account was created as sftp{uid}"
            ));
            None
        }
        None => None,
    };

    sqlx::query(
        "UPDATE sites SET sftp_enabled = true, sftp_uid = $1, sftp_gid = $2, sftp_username = $3, \
         updated_at = NOW() WHERE id = $4",
    )
        .bind(uid)
        .bind(gid)
        .bind(&stored_username)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("enable sftp", e))?;

    // Rebuild the vhost so the PHP-FPM pool picks up the new owner - mirrors
    // the redis toggle's own "rebuild the FULL vhost" step, for the same
    // reason (a hand-rolled partial body would drop WAF/CSP/bot-protection).
    let mut updated_site = site.clone();
    updated_site.sftp_enabled = true;
    updated_site.sftp_uid = Some(uid);
    updated_site.sftp_gid = Some(gid);
    updated_site.sftp_username = stored_username;
    let username = sftp_account_name(&updated_site);
    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref()),
    ).await.map_err(|e| agent_error("SFTP nginx/pool rebuild", e))?;

    let ip = crate::routes::client_ip(&headers);
    tracing::info!("SFTP enabled for {} (uid={uid}, user={username})", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.sftp.enabled",
        Some("site"), Some(&site.domain), Some(&username), ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "site.sftp.enabled", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    let mut out = serde_json::json!({ "ok": true, "sftp_enabled": true, "username": username });
    if let Some(w) = warning {
        out["warning"] = serde_json::json!(w);
    }
    Ok(Json(out))
}

/// The uid/gid `site`'s SFTP account is created under: the ones already on
/// the row (an earlier enable attempt, or a disabled account), else a fresh
/// `nextval('sftp_id_seq')` RECORDED ON THE ROW BEFORE the agent is called
/// (`sftp_enabled` stays false). A retry after a failed enable therefore asks
/// for the very same uid, which is what lets the agent recognise its own
/// leftover and resume it instead of creating a second account. The
/// `COALESCE` keeps a concurrent reservation's ids (one sequence value lost
/// at worst, never two uids for one site).
pub(crate) async fn reserve_sftp_ids(db: &sqlx::PgPool, site: &Site) -> Result<(i32, i32), sqlx::Error> {
    if let (Some(uid), Some(gid)) = (site.sftp_uid, site.sftp_gid) {
        return Ok((uid, gid));
    }
    let (allocated,): (i32,) = sqlx::query_as("SELECT nextval('sftp_id_seq')::int").fetch_one(db).await?;
    sqlx::query_as(
        "UPDATE sites SET sftp_uid = COALESCE(sftp_uid, $1), sftp_gid = COALESCE(sftp_gid, sftp_uid, $1), \
         updated_at = NOW() WHERE id = $2 RETURNING sftp_uid, sftp_gid",
    )
    .bind(allocated)
    .bind(site.id)
    .fetch_one(db)
    .await
}

/// The uid/gid the agent says the account lives under (a resumed leftover
/// keeps its own); an agent that predates the fields answers neither, and
/// the requested ones stand.
pub(crate) fn sftp_ids_from_agent(enabled: &serde_json::Value, uid: i32, gid: i32) -> (i32, i32) {
    let field = |k: &str| enabled.get(k).and_then(|v| v.as_i64()).and_then(|v| i32::try_from(v).ok());
    match (field("uid"), field("gid")) {
        (Some(u), Some(g)) => (u, g),
        _ => (uid, gid),
    }
}

/// POST /api/sites/{id}/sftp/disable - Tear down a site's SFTP account and
/// revert its content directory back to the shared `www-data` identity.
pub async fn disable_sftp(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("disable sftp", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    if !site.sftp_enabled {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "sftp_enabled": false,
            "message": "SFTP is already disabled for this site",
        })));
    }
    let (uid, gid) = (
        site.sftp_uid.ok_or_else(|| internal_error("disable sftp", sqlx::Error::RowNotFound))?,
        site.sftp_gid.ok_or_else(|| internal_error("disable sftp", sqlx::Error::RowNotFound))?,
    );

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    // FTP goes first (feature 6): the account leaves the whitelist and its FTP
    // sessions are cut before the account is removed. A missing vsftpd (412) has
    // nothing to cut; any other failure stops here with the box still ticked.
    if site.ftp_enabled {
        ftp_off_before_sftp_removal(&state, &agent, &site).await?;
    }

    let last_sftp_site: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sites WHERE sftp_enabled = true AND id != $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .unwrap_or((1,)); // fail toward NOT removing the shared sshd drop-in

    // Revert the PHP-FPM pool (and reload it) BEFORE tearing down the SFTP
    // account - live-verified this ordering matters: `userdel` refuses to
    // remove a uid with a running process, and the OLD pool's workers are
    // still alive under the SFTP uid at this point. `php-fpm reload` starts
    // fresh www-data-owned workers and gracefully stops the old ones, so by
    // the time the agent's disable endpoint runs, nothing is running as the
    // uid it is about to delete. The other order (userdel first) silently
    // failed the account/group removal every time, with no error surfaced
    // anywhere - `deprovision()`'s userdel/groupdel calls are themselves
    // best-effort (matching every other cleanup step in that function), so
    // the failure produced a clean "disabled" response over a half-torn-down
    // box.
    let mut updated_site = site.clone();
    updated_site.sftp_enabled = false;
    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref()),
    ).await.map_err(|e| agent_error("SFTP nginx/pool revert", e))?;

    agent.post(
        &format!("/sftp/sites/{}/disable", site.domain),
        Some(serde_json::json!({ "uid": uid, "gid": gid, "last_sftp_site": last_sftp_site.0 == 0 })),
    ).await.map_err(|e| agent_error("SFTP disable", e))?;

    // The custom name (D6) goes with the account: a later enable starts over.
    sqlx::query("UPDATE sites SET sftp_enabled = false, sftp_username = NULL, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("disable sftp", e))?;

    let ip = crate::routes::client_ip(&headers);
    tracing::info!("SFTP disabled for {}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.sftp.disabled",
        Some("site"), Some(&site.domain), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "site.sftp.disabled", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "sftp_enabled": false })))
}

/// POST /api/sites/{id}/sftp/reset-password - Generate a fresh SFTP password.
///
/// Always generates, never accepts an operator-supplied value - matching
/// `databases.rs::reset_password`'s pattern. No column stores it: a Linux
/// account's password can be set again with no prior knowledge, so once this
/// response leaves the panel, the plaintext is gone from every system that
/// isn't the operator's own clipboard.
pub async fn reset_sftp_password(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("reset sftp password", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    if !site.sftp_enabled {
        return Err(err(StatusCode::BAD_REQUEST, "SFTP is not enabled for this site"));
    }
    let uid = site.sftp_uid.ok_or_else(|| internal_error("reset sftp password", sqlx::Error::RowNotFound))?;

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;
    let password = uuid::Uuid::new_v4().to_string();

    agent.post(
        &format!("/sftp/sites/{}/password", site.domain),
        Some(serde_json::json!({ "uid": uid, "password": password })),
    ).await.map_err(|e| agent_error("SFTP password reset", e))?;

    let ip = crate::routes::client_ip(&headers);
    tracing::info!("SFTP password reset for {}", site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.sftp.password_reset",
        Some("site"), Some(&site.domain), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "site.sftp.password_reset", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "password": password })))
}

// ── Feature 6: FTP (FTPS) and disk quotas ────────────────────────────────

/// Untick FTP and resync the whitelist before the site's SFTP account goes away
/// (`disable_sftp`). A 412 (vsftpd not installed) or a 404 (an agent without the
/// FTP routes) has no session to cut and passes; any other failure puts the box
/// back and is returned.
async fn ftp_off_before_sftp_removal(
    state: &AppState,
    agent: &crate::services::agent::AgentHandle,
    site: &Site,
) -> Result<(), ApiError> {
    use crate::routes::ftp::{FtpSyncError, sync_ftp_users};
    let Some(server_id) = site.server_id else { return Ok(()) };
    sqlx::query("UPDATE sites SET ftp_enabled = false, updated_at = NOW() WHERE id = $1")
        .bind(site.id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("disable ftp", e))?;
    match sync_ftp_users(&state.db, agent, server_id).await {
        Ok(_) | Err(FtpSyncError::NotInstalled) => Ok(()),
        Err(FtpSyncError::Agent(crate::services::agent::AgentError::Status(404, _))) => Ok(()),
        Err(e) => {
            let _ = sqlx::query("UPDATE sites SET ftp_enabled = true WHERE id = $1")
                .bind(site.id)
                .execute(&state.db)
                .await;
            Err(e.into_api("FTP whitelist"))
        }
    }
}

#[derive(serde::Deserialize)]
pub struct FtpToggleRequest {
    pub enabled: bool,
}

/// POST /api/sites/{id}/ftp {enabled} -> {ftp_enabled}
///
/// Same rights and lockdown check as `enable_sftp`. FTP reuses the site's SFTP
/// account (same name, same password), so SFTP must be enabled first. The column
/// is written, then the server's whole whitelist is sent (A-4); if the agent
/// refuses, the column gets its old value back and the refusal is returned.
pub async fn set_ftp(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<FtpToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use crate::routes::ftp::{FtpSyncError, sync_ftp_users};

    if crate::services::security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "System is in lockdown mode"));
    }
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("set ftp", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    if body.enabled && !site.sftp_enabled {
        return Err(err(StatusCode::PRECONDITION_FAILED, "Enable SFTP first"));
    }
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;
    let server_id = site
        .server_id
        .ok_or_else(|| err(StatusCode::CONFLICT, "This site is not associated with a server"))?;

    sqlx::query("UPDATE sites SET ftp_enabled = $1, updated_at = NOW() WHERE id = $2")
        .bind(body.enabled)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("set ftp", e))?;

    let username = sftp_account_name(&site);
    match sync_ftp_users(&state.db, &agent, server_id).await {
        Ok(v) => {
            // The agent leaves out names it cannot validate instead of failing
            // the whole list; if the one just ticked is among them, say why.
            let rejected = v["skipped"].as_array().and_then(|a| {
                a.iter()
                    .find(|s| s["user"].as_str() == Some(username.as_str()))
                    .map(|s| s["reason"].as_str().unwrap_or("This account cannot use FTP").to_string())
            });
            if let (true, Some(reason)) = (body.enabled, rejected) {
                let _ = sqlx::query("UPDATE sites SET ftp_enabled = $1 WHERE id = $2")
                    .bind(site.ftp_enabled)
                    .bind(id)
                    .execute(&state.db)
                    .await;
                return Err(err(StatusCode::BAD_REQUEST, &reason));
            }
        }
        // Unticking with no FTP server: there is nothing to cut, the box just goes.
        Err(FtpSyncError::NotInstalled) if !body.enabled => {}
        Err(e) => {
            let _ = sqlx::query("UPDATE sites SET ftp_enabled = $1 WHERE id = $2")
                .bind(site.ftp_enabled)
                .bind(id)
                .execute(&state.db)
                .await;
            return Err(e.into_api("FTP whitelist"));
        }
    }

    let action = if body.enabled { "site.ftp.enabled" } else { "site.ftp.disabled" };
    let ip = crate::routes::client_ip(&headers);
    tracing::info!("FTP {} for {}", if body.enabled { "enabled" } else { "disabled" }, site.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, action,
        Some("site"), Some(&site.domain), Some(&username), ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, action, Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ftp_enabled": body.enabled })))
}

/// Who may do what with a site's disk quota (B-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotaCaller {
    /// An administrator of the site's server (the `SITE_CALLER_PREDICATE` admin arm).
    pub admin: bool,
    /// The reseller of the site owner's account.
    pub reseller: bool,
    pub owner: bool,
}

impl QuotaCaller {
    /// Setting the quota: admin or the owner's reseller. The owner sees the
    /// quota but cannot change it (403); anybody else does not see the site (404).
    pub fn may_set(self) -> Result<(), StatusCode> {
        if self.admin || self.reseller {
            Ok(())
        } else if self.owner {
            Err(StatusCode::FORBIDDEN)
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    /// Measuring now: admin, owner, or the owner's reseller.
    pub fn may_measure(self) -> bool {
        self.admin || self.reseller || self.owner
    }
}

/// Roles of a client account its reseller may act on. Same list as
/// `reseller_dashboard::RESELLER_MANAGEABLE_ROLES`: an admin or reseller account
/// that happens to carry a reseller's id never becomes theirs.
const QUOTA_RESELLER_CLIENT_ROLES: &[&str] = &["user", "client", "suspended"];

/// `(domain, server_id, caller rights)` of a site; roles are read from the
/// database, never from the token.
async fn quota_caller(
    state: &AppState,
    claims: &Claims,
    id: Uuid,
) -> Result<Option<(String, Option<Uuid>, QuotaCaller)>, ApiError> {
    let row: Option<(String, Option<Uuid>, bool, bool, bool)> = sqlx::query_as(
        "SELECT s.domain, s.server_id, \
           EXISTS (SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' \
                   AND sv.id = s.server_id AND (sv.is_local OR sv.user_id = u.id)), \
           EXISTS (SELECT 1 FROM users o, users r WHERE o.id = s.user_id AND r.id = $2 \
                   AND r.role = 'reseller' AND o.reseller_id = r.id AND o.role = ANY($3)), \
           s.user_id = $2 \
         FROM sites s WHERE s.id = $1",
    )
    .bind(id)
    .bind(claims.sub)
    .bind(QUOTA_RESELLER_CLIENT_ROLES)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("site quota lookup", e))?;
    Ok(row.map(|(domain, server_id, admin, reseller, owner)| (domain, server_id, QuotaCaller { admin, reseller, owner })))
}

/// The `quota_mb` of a request: `None` (unlimited) or 1 ..= i32::MAX MiB.
pub(crate) fn parse_quota_mb(v: Option<i64>) -> Result<Option<i32>, &'static str> {
    match v {
        None => Ok(None),
        Some(n) if n > 0 && n <= i64::from(i32::MAX) => Ok(Some(n as i32)),
        Some(_) => Err("quota_mb must be a positive number of MB, or null for unlimited"),
    }
}

#[derive(serde::Deserialize)]
pub struct DiskQuotaRequest {
    #[serde(default)]
    pub quota_mb: Option<i64>,
}

/// PUT /api/sites/{id}/disk-quota {quota_mb: n | null} -> {disk_quota_mb}
///
/// Admin, or the reseller of the site owner's account. The alert is recomputed
/// right away from the last measurement.
pub async fn set_disk_quota(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<DiskQuotaRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, _server_id, caller) = quota_caller(&state, &claims, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    match caller.may_set() {
        Ok(()) => {}
        Err(StatusCode::FORBIDDEN) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "Only an administrator or the account's reseller can change the disk quota",
            ));
        }
        Err(_) => return Err(err(StatusCode::NOT_FOUND, "Site not found")),
    }
    let quota = parse_quota_mb(body.quota_mb).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;

    sqlx::query("UPDATE sites SET disk_quota_mb = $1, updated_at = NOW() WHERE id = $2")
        .bind(quota)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("set disk quota", e))?;
    crate::services::disk_usage::refresh_site_alert(&state.db, id).await;

    let details = match quota {
        Some(mb) => format!("{mb} MB"),
        None => "unlimited".to_string(),
    };
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.disk_quota.updated",
        Some("site"), Some(&domain), Some(&details), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "disk_quota_mb": quota })))
}

/// POST /api/sites/{id}/disk-usage/refresh -> {disk_usage}
///
/// Measures this site now (A-5), records the result, recomputes the alert.
/// Admin, owner, or the owner's reseller. One measurement at a time per site:
/// 429 while one (manual or scheduled) is running.
pub async fn refresh_disk_usage(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use crate::services::disk_usage::{MeasureGuard, load_disk_usage, measure_sites};

    let (domain, server_id, _caller) = quota_caller(&state, &claims, id)
        .await?
        .filter(|(_, _, c)| c.may_measure())
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid site domain"));
    }
    let guard = MeasureGuard::claim(&[id]);
    if guard.is_empty() {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "A measurement is already running for this site"));
    }
    let agent = crate::helpers::agent_for_site_server(&state, server_id, &domain).await?;
    measure_sites(&state.db, &agent, &[(id, domain)])
        .await
        .map_err(|e| agent_error("Disk usage", e))?;
    drop(guard);

    let usage = load_disk_usage(&state.db, &[id]).await.remove(&id);
    Ok(Json(serde_json::json!({ "disk_usage": usage })))
}

/// PUT /api/sites/{id}/waf - Toggle WAF and set mode for a site.
pub async fn toggle_waf(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("toggle waf", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let enabled = body.get("enabled").and_then(|v| v.as_bool())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'enabled' boolean"))?;
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("detection");

    if mode != "detection" && mode != "prevention" {
        return Err(err(StatusCode::BAD_REQUEST, "Mode must be 'detection' or 'prevention'"));
    }

    // Configure WAF on agent
    if enabled {
        agent.post(
            &format!("/nginx/sites/{}/waf/configure", site.domain),
            Some(serde_json::json!({ "mode": mode })),
        ).await.map_err(|e| agent_error("WAF configure", e))?;
    }

    // Rebuild the FULL vhost with only WAF settings changed - a hand-rolled
    // partial body used to drop the site's CSP/Permissions-Policy/bot-protection.
    let mut updated_site = site.clone();
    updated_site.waf_enabled = enabled;
    updated_site.waf_mode = mode.to_string();
    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref()),
    ).await.map_err(|e| agent_error("WAF nginx config", e))?;

    // Update DB
    sqlx::query("UPDATE sites SET waf_enabled = $1, waf_mode = $2, updated_at = NOW() WHERE id = $3")
        .bind(enabled)
        .bind(mode)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("toggle waf", e))?;

    let action = if enabled { format!("enabled ({mode})") } else { "disabled".to_string() };
    tracing::info!("WAF {action} for {}", site.domain);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("site.waf.{}", if enabled { "enabled" } else { "disabled" }),
        Some("site"), Some(&site.domain), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db,
        &format!("site.waf.{}", if enabled { "enabled" } else { "disabled" }),
        Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    notifications::notify_panel(&state.db, Some(claims.sub),
        &format!("WAF {action}: {}", site.domain),
        &format!("Web Application Firewall has been {action}"), "info", "site", Some(&format!("/sites/{id}")),
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "waf_enabled": enabled,
        "waf_mode": mode,
    })))
}

/// GET /api/sites/{id}/waf/logs - Get recent WAF events for a site.
pub async fn waf_logs(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("waf logs", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let result = agent
        .get(&format!("/nginx/sites/{}/waf/logs?limit=50", site.domain))
        .await
        .map_err(|e| agent_error("WAF logs", e))?;

    Ok(Json(result))
}

/// POST /api/sites/{id}/optimize-images - Convert site images to WebP/AVIF.
pub async fn optimize_images(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("optimize images", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let format = body.get("format").and_then(|v| v.as_str()).unwrap_or("webp");
    let quality = body.get("quality").and_then(|v| v.as_u64()).unwrap_or(80);

    if format != "webp" && format != "avif" {
        return Err(err(StatusCode::BAD_REQUEST, "Format must be 'webp' or 'avif'"));
    }

    let result = agent
        .post_long(
            &format!("/nginx/sites/{}/optimize-images", site.domain),
            // The agent cannot know where this site's files are without the
            // runtime: node/python/proxy serve from the site root, static and php
            // from `public/`. Without it the scan hardcoded `public/`.
            Some(serde_json::json!({
                "format": format,
                "quality": quality,
                "runtime": site.runtime,
            })),
            300,
        )
        .await
        .map_err(|e| agent_error("Image optimization", e))?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        "site.optimize_images",
        Some("site"), Some(&site.domain), Some(format), None,
        claims.key_id,
    ).await;

    Ok(Json(result))
}

/// Reserved/system/panel ports a user-supplied `proxy_port` must never be.
/// Choosing one enables loopback SSRF (`proxy_pass http://127.0.0.1:<port>`)
/// into internal services AND lets the auto-firewall `ufw deny <port>/tcp`
/// clobber a global allow rule (e.g. deny 443 → box-wide HTTPS outage).
fn is_safe_proxy_port(port: i32) -> bool {
    // 3081: MCP server. 5450: the panel's PostgreSQL. 8091, 8092: internal Apache.
    const RESERVED: [i32; 24] = [
        22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379,
        27017, 11211, 3080, 3081, 5450, 8091, 8092, 8443, 9443, 2019,
    ];
    (1024..=65535).contains(&port) && !RESERVED.contains(&port)
}

/// Shared new-domain guard for clone_site and add_alias.
///
/// This used to hold the checks itself, with a comment saying it existed "so the
/// guard set create() enforces cannot drift" - while `create()` did not call it
/// and six other domain-introducing paths did not exist as far as it knew. The
/// checks now live in [`crate::services::domain_claim`], which every path calls,
/// and this is the thin adapter for the two callers that pass a `&AppState`.
async fn ensure_domain_available(
    state: &AppState,
    domain: &str,
    headers: &HeaderMap,
    claimant_role: &str,
) -> Result<String, ApiError> {
    domain_claim::ensure_claimable(
        &state.db,
        &state.agents,
        domain,
        headers,
        domain_claim::Holder::New,
        claimant_role,
    )
    .await
}

/// Build the full nginx agent body from a Site model. Shared by all config-rebuild paths.
///
/// `bind_ip` is an explicit argument, not read from the row, so that no rebuild
/// path can forget it: a vhost re-rendered without the site's address would move
/// an IP-bound site back to the primary address on its next SSL renewal. Callers
/// get it from [`crate::services::server_ips::nginx_bind_ip`] - the declared
/// address, or `"primary"`. `None` (the address could not be read) omits the key,
/// and the agent then keeps the address already written in the vhost.
pub(crate) fn build_nginx_body(site: &crate::models::Site, bind_ip: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "runtime": site.runtime,
        "fastcgi_cache": site.fastcgi_cache,
        "redis_cache": site.redis_cache,
        "redis_db": site.redis_db,
        "waf_enabled": site.waf_enabled,
        "waf_mode": site.waf_mode,
        "rate_limit": site.rate_limit,
        "max_upload_mb": site.max_upload_mb,
        "php_memory_mb": site.php_memory_mb,
        "php_max_workers": site.php_max_workers,
        "csp_policy": site.csp_policy,
        "permissions_policy": site.permissions_policy,
        "bot_protection": site.bot_protection,
        // Feature 4 (B2): always sent. The agent ignores it for non-PHP runtimes.
        "web_server": site.web_server,
    });
    if let Some(ref preset) = site.php_preset {
        body["php_preset"] = serde_json::json!(preset);
    }
    if let Some(ref custom) = site.custom_nginx {
        body["custom_nginx"] = serde_json::json!(custom);
    }
    if let Some(ref php) = site.php_version {
        // Version carrier, not a literal path - see the comment on the create-site call site.
        body["php_socket"] = serde_json::json!(format!("unix:/run/php/php{php}-fpm.sock"));
    }
    if site.ssl_enabled {
        body["ssl"] = serde_json::json!(true);
        if let Some(ref cert) = site.ssl_cert_path {
            body["ssl_cert"] = serde_json::json!(cert);
        }
        if let Some(ref key) = site.ssl_key_path {
            body["ssl_key"] = serde_json::json!(key);
        }
    }
    if site.runtime == "proxy" || site.runtime == "node" || site.runtime == "python" {
        body["proxy_port"] = serde_json::json!(site.proxy_port);
    }
    if site.sftp_enabled
        && let (Some(_), Some(gid)) = (site.sftp_uid, site.sftp_gid)
    {
        // Backend and agent are separate binaries - this naming convention is
        // duplicated (not shared code) on the agent side in
        // `services::sftp_accounts::{sftp_username, sftp_groupname}`, which is
        // the one place that actually creates these Linux accounts. Keep the
        // two definitions byte-for-byte identical; a drift here means the
        // panel tells the wrong pool owner to a `write_php_pool_config` call
        // that already succeeded under a different name. A custom name (D6)
        // is stored only once the agent confirmed it created that account.
        body["pool_user"] = serde_json::json!(sftp_account_name(site));
        body["pool_group"] = serde_json::json!(format!("sftpg{gid}"));
    }
    if let Some(ip) = bind_ip {
        body["bind_ip"] = serde_json::json!(ip);
    }
    // Per-site PHP pool (A1 of conception/02-php-contrats.md) - the single
    // constructor, also used by the hand-built create/clone/staging/import bodies.
    if let Some(pool) = crate::routes::php_settings::php_pool_for_site(site) {
        body["php_pool"] = pool;
    }
    apply_vhost_extras(&mut body, site);
    body
}

/// The import-hestia (05) vhost keys, shared by [`build_nginx_body`] and the
/// hand-built bodies (create, clone, staging) so no path can send a different set.
///
/// `aliases`, `canonical_host` and `php_no_exec_dirs` travel only when the row
/// holds a value: absent means "keep what the vhost has" for aliases (D4) and
/// "none" for the other two, which is the agent's byte-identical rendering.
/// `force_ssl` and `hsts` ALWAYS travel - the columns are NOT NULL and default
/// to the historical behaviour, so sending them is never a change by itself.
pub(crate) fn apply_vhost_extras(body: &mut serde_json::Value, site: &Site) {
    if let Some(ref aliases) = site.aliases {
        body["aliases"] = serde_json::json!(aliases);
    }
    if let Some(ref canonical) = site.canonical_host {
        body["canonical_host"] = serde_json::json!(canonical);
    }
    if let Some(ref dirs) = site.php_no_exec_dirs {
        body["php_no_exec_dirs"] = serde_json::json!(dirs);
    }
    body["force_ssl"] = serde_json::json!(site.force_ssl);
    body["hsts"] = serde_json::json!(site.hsts);
    body["proxy_streaming"] = serde_json::json!(site.proxy_streaming);
    body["proxy_strict_client_ip"] = serde_json::json!(site.proxy_strict_client_ip);
}

/// First port of the automatic range that no site row, listener or container
/// holds, and that a user could not be refused as a proxy target.
fn first_free_site_port(site_ports: &[i32], host_ports: &[i32]) -> Option<i32> {
    (5000..=5999).find(|p| {
        is_safe_proxy_port(*p) && !site_ports.contains(p) && !host_ports.contains(p)
    })
}

/// The Linux account that owns the site's SFTP chroot and PHP-FPM pool: the
/// custom name (D6) when one was confirmed by the agent, else the historical
/// `sftp<uid>`. Only meaningful while `sftp_enabled`; with no uid recorded it
/// answers `sftp` + nothing, which no caller sends.
pub(crate) fn sftp_account_name(site: &Site) -> String {
    match site.sftp_username.as_deref() {
        Some(name) if !name.is_empty() => name.to_string(),
        // Same convention as the agent's `sftp_accounts::sftp_username`.
        _ => {
            let uid = site.sftp_uid.unwrap_or_default();
            format!("sftp{uid}")
        }
    }
}

// ── import-hestia (05): validators ───────────────────────────────────────

/// Upload folders where PHP execution is blocked by default (D9). Written to
/// every new PHP site, and applied to an existing one by `{dirs: "defaults"}`.
pub(crate) const DEFAULT_PHP_NO_EXEC_DIRS: &[&str] = &[
    "/wp-content/uploads",
    "/sites/default/files",
    "/storage/app/public",
    "/uploads",
    "/upload",
];

fn default_php_no_exec_dirs() -> Vec<String> {
    DEFAULT_PHP_NO_EXEC_DIRS.iter().map(|d| d.to_string()).collect()
}

/// Most entries a site may carry, for no-exec folders and for aliases alike
/// (the agent enforces the same ceiling).
const MAX_VHOST_LIST: usize = 20;

/// Normalise and validate a no-exec folder list. Each entry is a URL path
/// matching `^/[A-Za-z0-9_./-]*$`, without `..`, its trailing slashes removed.
/// `/` alone is refused: it would answer 403 to every PHP file of the site.
/// Duplicates are refused case-insensitively, since the nginx block is `~*`.
pub(crate) fn validate_no_exec_dirs(dirs: &[String]) -> Result<Vec<String>, String> {
    if dirs.len() > MAX_VHOST_LIST {
        return Err(format!("At most {MAX_VHOST_LIST} folders"));
    }
    let mut out: Vec<String> = Vec::with_capacity(dirs.len());
    for raw in dirs {
        let d = raw.trim();
        if !d.starts_with('/') {
            return Err(format!("Invalid folder '{d}': must start with /"));
        }
        if !d.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')) {
            return Err(format!("Invalid folder '{d}': only letters, digits, _ . / - are allowed"));
        }
        if d.contains("..") {
            return Err(format!("Invalid folder '{d}': must not contain '..'"));
        }
        if d.contains("//") {
            return Err(format!("Invalid folder '{d}': must not contain '//'"));
        }
        let normalised = d.trim_end_matches('/');
        if normalised.is_empty() {
            return Err("The site root '/' cannot be a no-exec folder: it would block all PHP".into());
        }
        if out.iter().any(|o| o.eq_ignore_ascii_case(normalised)) {
            return Err(format!("Duplicate folder '{normalised}'"));
        }
        out.push(normalised.to_string());
    }
    Ok(out)
}

/// The host a canonical mode redirects to.
fn canonical_target(domain: &str, mode: &str) -> String {
    if mode == "www" { format!("www.{domain}") } else { domain.to_string() }
}

/// Validate a canonical-host choice against the names the site serves
/// (`domain` + `aliases`). `None` clears it. The target must be served, or
/// every request would be redirected to a host this vhost does not answer.
fn validate_canonical_host(domain: &str, mode: Option<&str>, aliases: &[String]) -> Result<Option<String>, String> {
    let Some(mode) = mode else { return Ok(None) };
    if mode != "www" && mode != "apex" {
        return Err("canonical_host must be \"www\", \"apex\" or null".into());
    }
    let target = canonical_target(domain, mode);
    if target != domain && !aliases.iter().any(|a| a.eq_ignore_ascii_case(&target)) {
        return Err(format!("{target} is not served by this site: add it as an alias first"));
    }
    Ok(Some(mode.to_string()))
}

/// Validate an alias about to be added (already normalised by the domain-claim
/// guard): a domain, not the site's own name, not already present, and room
/// left under the ceiling.
fn validate_new_alias(alias: &str, domain: &str, existing: &[String]) -> Result<(), String> {
    if !is_valid_domain(alias) {
        return Err("Invalid alias: must be a valid domain name".into());
    }
    if alias.eq_ignore_ascii_case(domain) {
        return Err("An alias cannot be the site's own domain".into());
    }
    if existing.iter().any(|a| a.eq_ignore_ascii_case(alias)) {
        return Err(format!("{alias} is already an alias of this site"));
    }
    if existing.len() >= MAX_VHOST_LIST {
        return Err(format!("At most {MAX_VHOST_LIST} aliases per site"));
    }
    Ok(())
}

/// Whether a list read back from the agent may become the authoritative
/// `sites.aliases` column. Once stored it is sent on EVERY rebuild and the
/// agent refuses an invalid list with 400, so a list that would not pass the
/// agent's own checks is never stored (the column then stays unmanaged).
fn aliases_storable(domain: &str, aliases: &[String]) -> bool {
    aliases.len() <= MAX_VHOST_LIST
        && aliases.iter().all(|a| is_valid_domain(a) && !a.eq_ignore_ascii_case(domain))
        && aliases.iter().enumerate().all(|(i, a)| !aliases[..i].iter().any(|b| b.eq_ignore_ascii_case(a)))
}

/// Names reserved for system or service accounts: never a site's SFTP name.
const RESERVED_SFTP_NAMES: &[&str] = &[
    "root", "daemon", "bin", "sys", "www-data", "nginx", "postfix", "dovecot", "vmail",
    "opendkim", "mysql", "postgres", "redis", "nobody", "sshd", "ubuntu", "debian", "admin",
];

/// Validate a custom SFTP account name (D6 / W4-S): `^[a-z_][a-z0-9_.-]{0,31}$`,
/// not reserved, and not of the default `sftp<digits>` shape (nor the group's
/// `sftpg<digits>`), which belongs to the uid-numbered accounts.
pub(crate) fn validate_sftp_username(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if !first_ok || !rest_ok || name.len() > 32 {
        return Err("Invalid username: 1 to 32 characters, lowercase letters, digits, _ . -, starting with a letter or _".into());
    }
    if RESERVED_SFTP_NAMES.contains(&name) {
        return Err(format!("'{name}' is reserved"));
    }
    for prefix in ["sftpg", "sftp"] {
        if let Some(rest) = name.strip_prefix(prefix)
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit())
        {
            return Err(format!("'{name}' is the default naming; choose another name or leave it empty"));
        }
    }
    Ok(())
}

/// GET the agent's live alias list for a domain (`{aliases: [..]}`).
async fn read_agent_aliases(
    agent: &crate::services::agent::AgentHandle,
    domain: &str,
) -> Result<Vec<String>, crate::services::agent::AgentError> {
    let res = agent.get(&format!("/nginx/aliases/{domain}")).await?;
    Ok(res
        .get("aliases")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default())
}

/// PUT /api/sites/{id}/security-headers - Update CSP and Permissions-Policy.
pub async fn update_security_headers(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("security headers", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let csp = body.get("csp_policy").and_then(|v| v.as_str()).map(|s| s.to_string());
    let perms = body.get("permissions_policy").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Validate CSP (max 4KB, no nginx directive injection). Both values render
    // verbatim into `add_header ... "<value>" always;`, so a `"` (or `\`/brace)
    // would break out of the quoted argument and inject arbitrary root-run nginx
    // directives (location/alias/access_log/proxy_pass). is_safe_header_value
    // keeps `;` (a real CSP needs it) but rejects the break-out characters.
    if let Some(ref csp_val) = csp {
        if csp_val.len() > 4096 {
            return Err(err(StatusCode::BAD_REQUEST, "CSP policy must be under 4KB"));
        }
        if !crate::routes::is_safe_header_value(csp_val) {
            return Err(err(StatusCode::BAD_REQUEST, "CSP policy contains invalid characters"));
        }
    }
    if let Some(ref perms_val) = perms {
        if perms_val.len() > 2048 {
            return Err(err(StatusCode::BAD_REQUEST, "Permissions-Policy must be under 2KB"));
        }
        if !crate::routes::is_safe_header_value(perms_val) {
            return Err(err(StatusCode::BAD_REQUEST, "Permissions-Policy contains invalid characters"));
        }
    }

    // Update DB
    sqlx::query("UPDATE sites SET csp_policy = $1, permissions_policy = $2, updated_at = NOW() WHERE id = $3")
        .bind(&csp)
        .bind(&perms)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("security headers", e))?;

    // Rebuild nginx with updated headers
    let mut updated_site = site.clone();
    updated_site.csp_policy = csp.clone();
    updated_site.permissions_policy = perms.clone();
    let agent_body = build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref());

    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        agent_body,
    ).await.map_err(|e| agent_error("Security headers nginx config", e))?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        "site.security_headers",
        Some("site"), Some(&site.domain), None, None,
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "csp_policy": csp,
        "permissions_policy": perms,
    })))
}

/// PUT /api/sites/{id}/bot-protection - Toggle bot protection mode.
pub async fn toggle_bot_protection(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: crate::models::Site = sqlx::query_as(
        SITE_FOR_CALLER_ALL.as_str(),
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("bot protection", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("off");
    if !["off", "rate-limit", "challenge", "block"].contains(&mode) {
        return Err(err(StatusCode::BAD_REQUEST, "Mode must be 'off', 'rate-limit', 'challenge', or 'block'"));
    }

    // Update DB
    sqlx::query("UPDATE sites SET bot_protection = $1, updated_at = NOW() WHERE id = $2")
        .bind(mode)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("bot protection", e))?;

    // Rebuild nginx with bot protection
    let mut updated_site = site.clone();
    updated_site.bot_protection = mode.to_string();
    let agent_body = build_nginx_body(&updated_site, crate::services::server_ips::nginx_bind_ip(&state.db, &updated_site).await.as_deref());

    agent.put(
        &format!("/nginx/sites/{}", site.domain),
        agent_body,
    ).await.map_err(|e| agent_error("Bot protection nginx config", e))?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("site.bot_protection.{mode}"),
        Some("site"), Some(&site.domain), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db,
        &format!("site.bot_protection.{mode}"),
        Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "bot_protection": mode,
    })))
}

#[derive(serde::Deserialize)]
pub struct TransferSiteRequest {
    /// The new owner, by email. Email rather than id because the operator doing
    /// this is reading a list of people, not a list of UUIDs.
    pub email: String,
}

/// The tables that keep their own copy of `user_id` beside a `site_id`.
///
/// Derived, not remembered: these are every table in the schema carrying BOTH
/// columns. Everything else a site owns - `databases`, `crons`, `backups`,
/// `ssl_certificates` - reaches its owner THROUGH `site_id`, so it follows the
/// transfer with no statement of its own. Getting this list wrong is the failure
/// mode that matters: a row left behind keeps the previous owner able to see and
/// act on part of a site they no longer hold, and nothing would report it.
const OWNERSHIP_DENORMALIZED_TABLES: [&str; 4] =
    ["alerts", "monitors", "secret_vaults", "whmcs_service_map"];

/// POST /api/sites/{id}/transfer - hand a site to another account. Admin only.
///
/// The point of the whole `client` design (GitHub #51). CyberHunter - Panel has exactly one
/// ownership axis, `sites.user_id`, and 108 ownership-scoped reads that all say
/// `WHERE user_id = $1`. Moving the row therefore moves the site completely, and
/// every one of those reads keeps working without being touched - which is why
/// this is a transfer rather than an access-control list. An ACL would have had
/// to widen all 108, keep 57 `claims.sub` INSERTs in step, and get two name-keyed
/// cleanups right whose own comments record that they already shipped a
/// cross-account delete once.
///
/// ⚠ Transfer is EXCLUSIVE: the previous owner loses the site, **including when
/// the previous owner is an admin**. This comment used to claim the role itself
/// kept an administrator's view of a transferred site, and that was never true:
/// `list` and every per-site read in this file are `WHERE user_id = $1` with no
/// role branch, so a transferring admin lost the row from their list and got 404
/// from `get_one`. Because the Transfer control was rendered only on the site's
/// own page, the handover had no way back through the panel at all.
/// `list_for_admin` is that way back; this handler needed no change, because its
/// own lookup below is by id and is deliberately not ownership-filtered.
///
/// One transaction, because a half-transferred site is worse than a failed one:
/// the row would answer to the new owner while its alerts and secret vaults still
/// answered to the old one.
pub async fn transfer(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<TransferSiteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if claims.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, "Admin only"));
    }

    let site: Option<(Uuid, String, Uuid)> =
        sqlx::query_as("SELECT id, domain, user_id FROM sites WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("load site", e))?;
    let (site_id, domain, previous_owner) =
        site.ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    let email = body.email.trim().to_ascii_lowercase();
    let recipient: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, role FROM users WHERE lower(email) = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("load recipient", e))?;
    let (new_owner, new_owner_role) =
        recipient.ok_or_else(|| err(StatusCode::NOT_FOUND, "No account with that email"))?;

    if new_owner == previous_owner {
        return Err(err(
            StatusCode::CONFLICT,
            "That account already owns this site",
        ));
    }
    // A suspended account must not be handed a live site: `auth.rs` rejects its
    // every request, so the site would land somewhere nobody can reach.
    if new_owner_role == "suspended" {
        return Err(err(
            StatusCode::CONFLICT,
            "That account is suspended. Restore it before transferring a site to it.",
        ));
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal_error("begin transfer", e))?;

    // ⚠ A STAGING ENVIRONMENT IS A SECOND `sites` ROW, AND IT USED TO STAY BEHIND.
    //
    // `staging::create` inserts one (`routes/staging.rs:168`) carrying
    // `parent_site_id` (20260312700000_staging_sites.sql:2) and the CREATOR's
    // `user_id`. This statement was `WHERE id = $2`, so the clone did not move with
    // its parent - and the previous owner kept, on a site they no longer hold: the
    // staging domain in their Sites list, a `www-data` shell inside a full copy of
    // the new owner's document root (`wp-config.php` and its database credentials
    // included), and the push-to-production control, which writes that copy OVER
    // the new owner's live site. A departed owner with a WRITE into the new owner's
    // production is the worst version of the failure this handler's own comment
    // names: "a row left behind keeps the previous owner able to see and act on
    // part of a site they no longer hold, and nothing would report it."
    //
    // Staging cannot nest - `staging::create` refuses a parent that is itself
    // staging (`staging.rs:106`) - so one `OR parent_site_id` is the whole tree,
    // not the first level of one.
    let moved_ids: Vec<Uuid> = sqlx::query_as::<_, (Uuid,)>(
        "UPDATE sites SET user_id = $1 WHERE id = $2 OR parent_site_id = $2 RETURNING id",
    )
    .bind(new_owner)
    .bind(site_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| internal_error("transfer site", e))?
    .into_iter()
    .map(|(id,)| id)
    .collect();

    let mut moved = serde_json::Map::new();
    for table in OWNERSHIP_DENORMALIZED_TABLES {
        // The table name comes from a const array in this file and never from a
        // request, so the format! cannot carry anything an caller supplied.
        //
        // Keyed on the ids the UPDATE above actually moved, not on `site_id = $2`:
        // the staging row's alerts, monitors and vaults belong to the staging site,
        // and scoping this to the parent alone would move the parent's dependents
        // while leaving the child's with the departed owner - the same split this
        // fix exists to close, one level down.
        let n = sqlx::query(&format!(
            "UPDATE {table} SET user_id = $1 WHERE site_id = ANY($2)"
        ))
        .bind(new_owner)
        .bind(&moved_ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal_error("transfer dependent rows", e))?
        .rows_affected();
        moved.insert(table.to_string(), serde_json::json!(n));
    }

    tx.commit()
        .await
        .map_err(|e| internal_error("commit transfer", e))?;

    crate::services::activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "site.transfer",
        Some("site"),
        Some(&domain),
        Some(&format!("{previous_owner} -> {new_owner} ({email})")),
        crate::routes::client_ip(&headers).as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        "site.transfer",
        Some(&claims.email),
        crate::routes::client_ip(&headers).as_deref(),
        Some("site"),
        Some(&domain),
        Some(&format!("{previous_owner} -> {new_owner} ({email})")),
        None,
        "critical",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "domain": domain,
        "previous_owner": previous_owner,
        "new_owner": new_owner,
        "dependent_rows_moved": moved,
    })))
}

// ──────────────────────────────────────────────────────────────
// Multi-IP: the address a site listens on (conception/01-multi-ip.md §5.2)
// ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct SetSiteIpRequest {
    /// `null` = the server's primary address.
    pub ip_id: Option<Uuid>,
}

/// PUT /api/sites/{id}/ip - Move a site to another address of its own server.
///
/// Row → full vhost rebuild on the site's host → (best-effort) the panel-managed
/// A record follows when it named the old address → a same-named mail domain in
/// automatic mode follows too (mail sync + SPF `ip4:`), as HestiaCP's
/// `v-change-web-domain-ip` rebuilds the mail domain. Admin only: addresses are
/// server inventory.
///
/// The row is written first so the rebuild reads one source of truth, and put
/// back if the agent refuses (an address no longer on the interface is a 400
/// from the agent) - the row must never claim an address the vhost does not use.
pub async fn set_ip(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SetSiteIpRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let site: Site = sqlx::query_as(&SITE_FOR_CALLER_ALL)
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("site ip", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;

    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;
    let Some(server_id) = site.server_id else {
        return Err(err(StatusCode::CONFLICT, "This site is not associated with a server"));
    };

    let new_row = match body.ip_id {
        None => None,
        Some(ip_id) => Some(
            crate::services::server_ips::declared_ip_on_server(&state.db, ip_id, server_id)
                .await
                .map_err(|e| internal_error("site ip", e))?
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "That IP address is not declared on this site's server"))?,
        ),
    };

    if site.ip_id == body.ip_id {
        let mut site = site;
        crate::services::server_ips::fill_bind_ip(&state.db, &mut site).await;
        return Ok(Json(serde_json::to_value(site).unwrap_or_default()));
    }

    // Resolved BEFORE the write: the DNS follow-up replaces only a record that
    // still names the address this site is leaving.
    let old_public = crate::services::server_ips::site_dns_address(&state.db, site.server_id, site.ip_id).await;
    let old_label = match site.ip_id {
        Some(old) => crate::services::server_ips::declared_ip(&state.db, old)
            .await
            .ok()
            .flatten()
            .map(|r| r.ip)
            .unwrap_or_else(|| old.to_string()),
        None => crate::services::server_ips::PRIMARY.to_string(),
    };

    let updated: Site = sqlx::query_as("UPDATE sites SET ip_id = $1, updated_at = NOW() WHERE id = $2 RETURNING *")
        .bind(body.ip_id)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| internal_error("site ip", e))?;

    let bind_ip = crate::services::server_ips::bind_ip_value(new_row.as_ref().map(|r| r.ip.as_str()));
    let agent_path = format!("/nginx/sites/{}", site.domain);
    if let Err(e) = agent.put(&agent_path, build_nginx_body(&updated, Some(&bind_ip))).await {
        if let Err(re) = sqlx::query("UPDATE sites SET ip_id = $1, updated_at = NOW() WHERE id = $2")
            .bind(site.ip_id)
            .bind(id)
            .execute(&state.db)
            .await
        {
            tracing::error!("Site {}: the agent refused the address change and the row could not be put back: {re}", site.domain);
        }
        return Err(agent_error("Site IP change", e));
    }

    let new_public = crate::services::server_ips::site_dns_address(&state.db, site.server_id, updated.ip_id).await;

    // A same-named mail domain in automatic mode sends from the site's address,
    // so it moves with it. Read now (cheap) so the DNS task knows whether SPF moves.
    let mail_follows: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_domains WHERE server_id = $1 AND domain = lower($2) AND send_ip_id IS NULL)",
    )
    .bind(server_id)
    .bind(&site.domain)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    // The vhost change is applied and stays applied; a mail rebuild that did not
    // take is reported to the operator as `mail_warning` on the response rather
    // than failing a request whose primary effect succeeded.
    let mut mail_warning: Option<String> = None;
    if mail_follows {
        match crate::routes::mail::sync_mail_config_report(&state, server_id, &agent).await {
            Ok(report) => {
                let send_ip = new_row.as_ref().map(|r| r.ip.as_str());
                if let Some(p) = report.send_ip_problem(send_ip) {
                    mail_warning = Some(format!("The site moved, but its mail domain's sending address did not follow: {p}"));
                }
            }
            Err((status, msg)) => {
                let m = msg.0.get("error").and_then(|e| e.as_str()).unwrap_or("mail sync refused").to_string();
                tracing::warn!("Site {}: mail sync after the address change was refused ({status}): {m}", site.domain);
                mail_warning = Some(format!("The site moved, but mail was not re-synced: {m}"));
            }
        }
    }

    if let (Some(old), Some(new)) = (old_public, new_public) {
        if old != new {
            let db = state.db.clone();
            let owner = site.user_id;
            let domain = site.domain.clone();
            tokio::spawn(async move {
                let a = replace_site_dns_records(&db, owner, &domain, "A", |c| swap_a_content(c, &old, &new)).await;
                tracing::info!("Site IP change: {a} A record(s) for {domain} moved {old} → {new}");
                if mail_follows {
                    let spf = replace_site_dns_records(&db, owner, &domain, "TXT", |c| swap_spf_ip4(c, &old, &new)).await;
                    tracing::info!("Site IP change: {spf} SPF record(s) for {domain} moved {old} → {new}");
                }
            });
        }
    }

    let new_label = new_row.as_ref().map(|r| r.ip.clone()).unwrap_or_else(|| crate::services::server_ips::PRIMARY.to_string());
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.ip.change",
        Some("site"), Some(&site.domain), Some(&format!("{old_label} → {new_label}")), ip.as_deref(),
        claims.key_id,
    ).await;

    let mut updated = updated;
    crate::services::server_ips::fill_bind_ip(&state.db, &mut updated).await;
    let mut out = serde_json::to_value(&updated).map_err(|e| internal_error("site ip", e))?;
    if let Some(w) = mail_warning {
        out["mail_warning"] = serde_json::json!(w);
    }
    Ok(Json(out))
}

/// `A` content swap: the record moves only if it names the old address.
fn swap_a_content(content: &str, old: &str, new: &str) -> Option<String> {
    (content.trim() == old).then(|| new.to_string())
}

/// SPF swap: replace the `ip4:<old>` mechanism (any qualifier) with `ip4:<new>`,
/// keeping everything else the operator wrote. `None` when there is nothing to
/// change. Quoting (as PowerDNS stores TXT) is preserved.
fn swap_spf_ip4(content: &str, old: &str, new: &str) -> Option<String> {
    let trimmed = content.trim();
    let quoted = trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"');
    let inner = if quoted { &trimmed[1..trimmed.len() - 1] } else { trimmed };
    if !inner.starts_with("v=spf1") {
        return None;
    }
    let mut changed = false;
    let terms: Vec<String> = inner
        .split_whitespace()
        .map(|t| {
            let (qual, rest) = match t.chars().next() {
                Some(q @ ('+' | '-' | '~' | '?')) => (q.to_string(), &t[1..]),
                _ => (String::new(), t),
            };
            if rest == format!("ip4:{old}") || rest == format!("ip4:{old}/32") {
                changed = true;
                format!("{qual}ip4:{new}")
            } else {
                t.to_string()
            }
        })
        .collect();
    if !changed {
        return None;
    }
    let joined = terms.join(" ");
    Some(if quoted { format!("\"{joined}\"") } else { joined })
}

/// Rewrite the `rtype` records named `domain` in the owner's panel-managed zone
/// (Cloudflare or PowerDNS - the same two providers site creation publishes to),
/// through `swap`. Best-effort; returns how many records changed. A zone the
/// panel does not manage is left alone - the UI warns about that case.
async fn replace_site_dns_records<F>(
    db: &sqlx::PgPool,
    owner: Uuid,
    domain: &str,
    rtype: &str,
    swap: F,
) -> usize
where
    F: Fn(&str) -> Option<String>,
{
    let parts: Vec<&str> = domain.splitn(3, '.').collect();
    let parent = if parts.len() >= 3 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    };

    let zone: Option<(String, Option<String>, Option<String>, Option<String>)> = match sqlx::query_as(
        "SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2"
    ).bind(&parent).bind(owner).fetch_optional(db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("DB error fetching DNS zone for the address change of {domain}: {e}");
            None
        }
    };
    let Some((provider, cf_zone_id, cf_api_token, cf_api_email)) = zone else {
        return 0;
    };

    let mut changed = 0usize;
    if provider == "cloudflare" {
        let (Some(zid), Some(tok)) = (cf_zone_id, cf_api_token) else { return 0 };
        let client = reqwest::Client::new();
        let headers = crate::helpers::cf_headers(&tok, cf_api_email.as_deref());
        let Ok(resp) = client
            .get(format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records?type={rtype}&name={domain}"))
            .headers(headers.clone())
            .send()
            .await
        else {
            return 0;
        };
        let Ok(data) = resp.json::<serde_json::Value>().await else { return 0 };
        for record in data.get("result").and_then(|r| r.as_array()).cloned().unwrap_or_default() {
            let (Some(rid), Some(content)) = (
                record.get("id").and_then(|v| v.as_str()),
                record.get("content").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if let Some(new_content) = swap(content) {
                let ok = client
                    .patch(format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records/{rid}"))
                    .headers(headers.clone())
                    .json(&serde_json::json!({ "content": new_content }))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
                if ok {
                    changed += 1;
                }
            }
        }
    } else if provider == "powerdns" {
        let pdns: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')"
        ).fetch_all(db).await.unwrap_or_default();
        let purl = pdns.iter().find(|(k, _)| k == "pdns_api_url").map(|(_, v)| v.clone());
        let pkey_enc = pdns.iter().find(|(k, _)| k == "pdns_api_key").map(|(_, v)| v.clone());
        let (Some(url), Some(key_enc)) = (purl, pkey_enc) else { return 0 };
        let key = crate::services::secrets_crypto::decrypt_credential_from_env(&key_enc);
        let zfqdn = if parent.ends_with('.') { parent.clone() } else { format!("{parent}.") };
        let client = reqwest::Client::new();
        let Ok(resp) = client
            .get(format!("{url}/api/v1/servers/localhost/zones/{zfqdn}"))
            .header("X-API-Key", &key)
            .send()
            .await
        else {
            return 0;
        };
        let Ok(zone) = resp.json::<serde_json::Value>().await else { return 0 };
        let name = format!("{domain}.");
        let rrset = zone
            .get("rrsets")
            .and_then(|r| r.as_array())
            .and_then(|sets| {
                sets.iter()
                    .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(name.as_str())
                        && s.get("type").and_then(|v| v.as_str()) == Some(rtype))
                    .cloned()
            });
        let Some(rrset) = rrset else { return 0 };
        let ttl = rrset.get("ttl").and_then(|v| v.as_u64()).unwrap_or(300);
        let mut records: Vec<serde_json::Value> = Vec::new();
        for r in rrset.get("records").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let content = r.get("content").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let disabled = r.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let content = match swap(&content) {
                Some(c) => {
                    changed += 1;
                    c
                }
                None => content,
            };
            records.push(serde_json::json!({ "content": content, "disabled": disabled }));
        }
        if changed > 0 {
            let ok = client
                .patch(format!("{url}/api/v1/servers/localhost/zones/{zfqdn}"))
                .header("X-API-Key", &key)
                .json(&serde_json::json!({"rrsets":[{"name": name, "type": rtype, "ttl": ttl, "changetype": "REPLACE", "records": records}]}))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if !ok {
                changed = 0;
            }
        }
    }
    changed
}

// --- import-hestia (05) ---
// Per-site vhost options (contract W3-V / W3-F). Each handler: owner or admin,
// UPDATE in a transaction, full vhost rebuild from the updated row, commit only
// once the agent accepted it.

/// Rebuild the vhost from `updated` and commit `tx` only if the agent accepted
/// it; otherwise roll back and relay the agent's refusal.
async fn rebuild_then_commit(
    state: &AppState,
    agent: &crate::services::agent::AgentHandle,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    updated: &Site,
    context: &str,
) -> Result<(), ApiError> {
    let bind_ip = crate::services::server_ips::nginx_bind_ip(&state.db, updated).await;
    if let Err(e) = agent
        .put(&format!("/nginx/sites/{}", updated.domain), build_nginx_body(updated, bind_ip.as_deref()))
        .await
    {
        let _ = tx.rollback().await;
        return Err(agent_error(context, e));
    }
    tx.commit().await.map_err(|e| internal_error(context, e))
}

/// The site the caller may act on, with its agent.
async fn site_and_agent_for_caller(
    state: &AppState,
    id: Uuid,
    claims: &Claims,
    context: &str,
) -> Result<(Site, crate::services::agent::AgentHandle), ApiError> {
    let site: Site = sqlx::query_as(SITE_FOR_CALLER_ALL.as_str())
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error(context, e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))?;
    let agent = crate::helpers::agent_for_site_server(state, site.server_id, &site.domain).await?;
    Ok((site, agent))
}

/// PUT /api/sites/{id}/canonical-host - `{canonical_host: "www"|"apex"|null}`.
///
/// The target (`www.<domain>` or `<domain>`) must be served by the site. When
/// the alias list is not yet managed (`aliases` NULL) and `www` is asked for,
/// the vhost's live list is read and stored in the same transaction.
pub async fn set_canonical_host(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mode: Option<String> = match body.get("canonical_host") {
        None => return Err(err(StatusCode::BAD_REQUEST, "Missing 'canonical_host' (\"www\", \"apex\" or null)")),
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.trim().to_ascii_lowercase()),
        Some(_) => return Err(err(StatusCode::BAD_REQUEST, "canonical_host must be \"www\", \"apex\" or null")),
    };

    let (site, agent) = site_and_agent_for_caller(&state, id, &claims, "set canonical host").await?;

    // Only `www` needs the alias list; `apex` and `null` are always valid.
    let mut aliases_to_store: Option<Vec<String>> = None;
    let served: Vec<String> = if mode.as_deref() == Some("www") {
        match site.aliases {
            Some(ref a) => a.clone(),
            None => {
                let live = read_agent_aliases(&agent, &site.domain)
                    .await
                    .map_err(|e| agent_error("Domain aliases", e))?;
                if aliases_storable(&site.domain, &live) {
                    aliases_to_store = Some(live.clone());
                }
                live
            }
        }
    } else {
        Vec::new()
    };
    let canonical = validate_canonical_host(&site.domain, mode.as_deref(), &served)
        .map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;

    let mut tx = state.db.begin().await.map_err(|e| internal_error("set canonical host", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET canonical_host = $1, aliases = COALESCE($2, aliases), updated_at = NOW() \
         WHERE id = $3 RETURNING *",
    )
    .bind(&canonical)
    .bind(&aliases_to_store)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("set canonical host", e))?;
    rebuild_then_commit(&state, &agent, tx, &updated, "Canonical host").await?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.canonical_host",
        Some("site"), Some(&site.domain), Some(canonical.as_deref().unwrap_or("none")), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "canonical_host": canonical })))
}

/// PUT /api/sites/{id}/php-no-exec - `{dirs: ["/..."] | null | "defaults"}`.
///
/// `"defaults"` applies [`DEFAULT_PHP_NO_EXEC_DIRS`]; `null` and `[]` both
/// clear the list (stored as NULL, rendered as nothing).
pub async fn set_php_no_exec(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let dirs: Option<Vec<String>> = match body.get("dirs") {
        None => return Err(err(StatusCode::BAD_REQUEST, "Missing 'dirs' (a list of folders, null, or \"defaults\")")),
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if s == "defaults" => Some(default_php_no_exec_dirs()),
        Some(serde_json::Value::Array(items)) => {
            let mut raw = Vec::with_capacity(items.len());
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Each folder must be a string"))?;
                raw.push(s.to_string());
            }
            let v = validate_no_exec_dirs(&raw).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
            if v.is_empty() { None } else { Some(v) }
        }
        Some(_) => return Err(err(StatusCode::BAD_REQUEST, "'dirs' must be a list of folders, null, or \"defaults\"")),
    };

    let (site, agent) = site_and_agent_for_caller(&state, id, &claims, "set php no-exec").await?;

    let mut tx = state.db.begin().await.map_err(|e| internal_error("set php no-exec", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET php_no_exec_dirs = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&dirs)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("set php no-exec", e))?;
    rebuild_then_commit(&state, &agent, tx, &updated, "PHP no-exec folders").await?;

    let ip = crate::routes::client_ip(&headers);
    let details = dirs.as_ref().map(|d| d.join(", ")).unwrap_or_else(|| "none".into());
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.php_no_exec",
        Some("site"), Some(&site.domain), Some(&details), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "php_no_exec_dirs": dirs })))
}

/// PUT /api/sites/{id}/ssl-options - `{force_ssl: bool, hsts: bool}`.
///
/// Either key may be omitted to keep its current value; at least one is required.
pub async fn set_ssl_options(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    fn flag(body: &serde_json::Value, key: &str) -> Result<Option<bool>, ApiError> {
        match body.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("'{key}' must be a boolean"))),
        }
    }
    let force_ssl = flag(&body, "force_ssl")?;
    let hsts = flag(&body, "hsts")?;
    if force_ssl.is_none() && hsts.is_none() {
        return Err(err(StatusCode::BAD_REQUEST, "Send 'force_ssl' and/or 'hsts'"));
    }

    let (site, agent) = site_and_agent_for_caller(&state, id, &claims, "set ssl options").await?;
    let force_ssl = force_ssl.unwrap_or(site.force_ssl);
    let hsts = hsts.unwrap_or(site.hsts);

    let mut tx = state.db.begin().await.map_err(|e| internal_error("set ssl options", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET force_ssl = $1, hsts = $2, updated_at = NOW() WHERE id = $3 RETURNING *",
    )
    .bind(force_ssl)
    .bind(hsts)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("set ssl options", e))?;
    rebuild_then_commit(&state, &agent, tx, &updated, "SSL options").await?;

    let ip = crate::routes::client_ip(&headers);
    let details = format!("force_ssl={force_ssl}, hsts={hsts}");
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.ssl_options",
        Some("site"), Some(&site.domain), Some(&details), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "force_ssl": force_ssl, "hsts": hsts })))
}
// --- end import-hestia (05) ---

/// PUT /api/sites/{id}/proxy-options - `{proxy_streaming: bool,
/// proxy_strict_client_ip: bool}`. Either key may be omitted to keep its value.
pub async fn set_proxy_options(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    fn flag(body: &serde_json::Value, key: &str) -> Result<Option<bool>, ApiError> {
        match body.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("'{key}' must be a boolean"))),
        }
    }
    let streaming = flag(&body, "proxy_streaming")?;
    let strict_ip = flag(&body, "proxy_strict_client_ip")?;
    if streaming.is_none() && strict_ip.is_none() {
        return Err(err(StatusCode::BAD_REQUEST, "Send 'proxy_streaming' and/or 'proxy_strict_client_ip'"));
    }

    let (site, agent) = site_and_agent_for_caller(&state, id, &claims, "set proxy options").await?;
    if !["proxy", "node", "python"].contains(&site.runtime.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, "Proxy options apply to proxy, node and python sites"));
    }
    let streaming = streaming.unwrap_or(site.proxy_streaming);
    let strict_ip = strict_ip.unwrap_or(site.proxy_strict_client_ip);

    let mut tx = state.db.begin().await.map_err(|e| internal_error("set proxy options", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET proxy_streaming = $1, proxy_strict_client_ip = $2, updated_at = NOW() \
         WHERE id = $3 RETURNING *",
    )
    .bind(streaming)
    .bind(strict_ip)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("set proxy options", e))?;
    rebuild_then_commit(&state, &agent, tx, &updated, "Proxy options").await?;

    let ip = crate::routes::client_ip(&headers);
    let details = format!("proxy_streaming={streaming}, proxy_strict_client_ip={strict_ip}");
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.proxy_options",
        Some("site"), Some(&site.domain), Some(&details), ip.as_deref(),
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true, "proxy_streaming": streaming, "proxy_strict_client_ip": strict_ip,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_admin_is_not_held_to_the_site_creation_ceiling() {
        assert_eq!(site_rate_ceiling("admin", 3), i64::MAX);
    }

    #[test]
    fn every_other_role_keeps_the_configured_ceiling() {
        // An impersonation session carries the impersonated user's role, so it
        // lands here whoever is really behind it.
        for role in ["user", "reseller", "client", "developer", "viewer"] {
            assert_eq!(site_rate_ceiling(role, 3), 3, "{role}");
            assert_eq!(site_rate_ceiling(role, 0), i64::MAX, "0 still means no limit for {role}");
            assert_eq!(site_rate_ceiling(role, -1), i64::MAX, "{role}");
        }
    }

    #[test]
    fn only_sites_nginx_proxies_to_a_port_have_an_upstream() {
        for runtime in ["proxy", "node", "python"] {
            assert_eq!(upstream_port(runtime, Some(3000)), Some(3000), "{runtime}");
            assert_eq!(upstream_port(runtime, None), None, "{runtime}");
        }
        for runtime in ["static", "php"] {
            assert_eq!(upstream_port(runtime, Some(3000)), None, "{runtime}");
        }
    }

    #[test]
    fn the_agents_answer_decides_the_upstream_state() {
        let up = serde_json::json!({ "port": 3000, "reachable": true });
        let down = serde_json::json!({ "port": 3000, "reachable": false });
        assert_eq!(upstream_state_from_agent(Some(&up)), UpstreamState::Up);
        assert_eq!(upstream_state_from_agent(Some(&down)), UpstreamState::Down);
        // An agent that cannot be asked says nothing about the app.
        assert_eq!(upstream_state_from_agent(None), UpstreamState::Unknown);
        assert_eq!(
            upstream_state_from_agent(Some(&serde_json::json!({}))),
            UpstreamState::Unknown
        );
    }

    #[test]
    fn a_stopped_app_is_unhealthy_whatever_the_public_side_answers() {
        for public in [None, Some(200), Some(502)] {
            assert!(!site_is_healthy(Some(UpstreamState::Down), public), "{public:?}");
        }
    }

    #[test]
    fn an_unresolved_domain_does_not_condemn_a_running_app() {
        assert!(site_is_healthy(Some(UpstreamState::Up), None));
        assert!(site_is_healthy(Some(UpstreamState::Up), Some(200)));
        assert!(!site_is_healthy(Some(UpstreamState::Up), Some(502)));
    }

    #[test]
    fn without_an_upstream_verdict_the_public_check_decides_as_before() {
        for upstream in [None, Some(UpstreamState::Unknown)] {
            assert!(site_is_healthy(upstream, Some(200)));
            assert!(site_is_healthy(upstream, Some(404)));
            assert!(!site_is_healthy(upstream, Some(500)));
            assert!(!site_is_healthy(upstream, None));
        }
    }

    #[test]
    fn a_stopped_app_lands_the_score_in_the_red_band() {
        assert_eq!(score_with_upstream(65, Some(UpstreamState::Down)), 25);
        assert!(score_with_upstream(100, Some(UpstreamState::Down)) < 50);
    }

    #[test]
    fn only_a_stopped_app_moves_the_score() {
        for upstream in [None, Some(UpstreamState::Up), Some(UpstreamState::Unknown)] {
            assert_eq!(score_with_upstream(65, upstream), 65);
        }
    }

    #[test]
    fn the_upstream_report_states_what_was_probed() {
        let report = upstream_report(3000, UpstreamState::Down);
        assert_eq!(report["port"], 3000);
        assert_eq!(report["state"], "down");
        assert_eq!(upstream_report(3000, UpstreamState::Up)["state"], "up");
        assert_eq!(upstream_report(3000, UpstreamState::Unknown)["state"], "unknown");
    }

    #[test]
    fn automatic_ports_skip_what_the_host_holds() {
        assert_eq!(first_free_site_port(&[], &[]), Some(5000));
        assert_eq!(first_free_site_port(&[5000], &[5001]), Some(5002));
        // 5439 and 5440 are published by database containers.
        let sites: Vec<i32> = (5000..5439).filter(|p| *p != 5432).collect();
        assert_eq!(first_free_site_port(&sites, &[5439, 5440]), Some(5441));
        // 5432 is a reserved port, never handed out.
        let sites: Vec<i32> = (5000..5432).collect();
        assert_eq!(first_free_site_port(&sites, &[]), Some(5433));
        let all: Vec<i32> = (5000..=5999).collect();
        assert_eq!(first_free_site_port(&all, &[]), None);
    }

    // ── feature 6: disk quota rights and values ──────────────────────────

    #[test]
    fn only_admins_and_resellers_set_a_quota() {
        let c = |admin, reseller, owner| QuotaCaller { admin, reseller, owner };
        assert_eq!(c(true, false, false).may_set(), Ok(()));
        assert_eq!(c(false, true, false).may_set(), Ok(()));
        assert_eq!(c(true, false, true).may_set(), Ok(()), "an admin who owns the site");
        assert_eq!(c(false, false, true).may_set(), Err(StatusCode::FORBIDDEN));
        assert_eq!(c(false, false, false).may_set(), Err(StatusCode::NOT_FOUND));
        // Measuring is open to the owner too.
        assert!(c(false, false, true).may_measure());
        assert!(c(false, true, false).may_measure());
        assert!(!c(false, false, false).may_measure());
    }

    #[test]
    fn quota_values_are_positive_mebibytes_or_unlimited() {
        assert_eq!(parse_quota_mb(None), Ok(None));
        assert_eq!(parse_quota_mb(Some(2048)), Ok(Some(2048)));
        assert_eq!(parse_quota_mb(Some(i64::from(i32::MAX))), Ok(Some(i32::MAX)));
        assert!(parse_quota_mb(Some(0)).is_err());
        assert!(parse_quota_mb(Some(-1)).is_err());
        assert!(parse_quota_mb(Some(i64::from(i32::MAX) + 1)).is_err());
    }

    // ── multi-IP: the DNS follow-up of an address change ─────────────────

    #[test]
    fn an_a_record_moves_only_when_it_names_the_old_address() {
        assert_eq!(swap_a_content("10.0.0.1", "10.0.0.1", "10.0.0.2").as_deref(), Some("10.0.0.2"));
        assert_eq!(swap_a_content("104.16.0.1", "10.0.0.1", "10.0.0.2"), None);
    }

    #[test]
    fn spf_keeps_the_operators_terms_and_swaps_only_the_old_ip4() {
        assert_eq!(
            swap_spf_ip4("v=spf1 a mx ip4:10.0.0.1 include:sendgrid.net ~all", "10.0.0.1", "10.0.0.2").as_deref(),
            Some("v=spf1 a mx ip4:10.0.0.2 include:sendgrid.net ~all")
        );
        assert_eq!(
            swap_spf_ip4("\"v=spf1 a mx +ip4:10.0.0.1/32 ~all\"", "10.0.0.1", "10.0.0.2").as_deref(),
            Some("\"v=spf1 a mx +ip4:10.0.0.2 ~all\"")
        );
        assert_eq!(swap_spf_ip4("v=spf1 a mx ip4:10.0.0.10 ~all", "10.0.0.1", "10.0.0.2"), None);
        assert_eq!(swap_spf_ip4("google-site-verification=x", "10.0.0.1", "10.0.0.2"), None);
    }

    #[test]
    fn the_vhost_body_always_names_an_address() {
        let site: Site = serde_json::from_str(r#"{
            "id": "00000000-0000-0000-0000-000000000000", "user_id": "00000000-0000-0000-0000-000000000000", "server_id": null, "domain": "a.example",
            "runtime": "static", "status": "active", "proxy_port": null, "php_version": null,
            "root_path": null, "ssl_enabled": false, "ssl_cert_path": null, "ssl_key_path": null,
            "ssl_expiry": null, "ssl_profile": null, "ssl_renewal_at": null, "ssl_renewal_checked_at": null,
            "ssl_challenge": null, "ssl_cert_subject": null, "ssl_wildcard": null, "ssl_dns_zone_id": null,
            "rate_limit": null, "max_upload_mb": 64, "php_memory_mb": 256, "php_max_workers": 5,
            "custom_nginx": null, "php_preset": null, "app_command": null, "parent_site_id": null,
            "synced_at": null, "enabled": true, "fastcgi_cache": false, "redis_cache": false, "redis_db": 0,
            "waf_enabled": false, "waf_mode": "detection", "csp_policy": null, "permissions_policy": null,
            "bot_protection": "off", "bandwidth_quota_mb": null, "bandwidth_suspended_at": null,
            "sftp_enabled": false, "sftp_uid": null, "sftp_gid": null,
            "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
            "ip_id": null
        }"#)
        .unwrap();
        assert_eq!(build_nginx_body(&site, Some("primary"))["bind_ip"], "primary");
        assert_eq!(build_nginx_body(&site, Some("192.0.2.107"))["bind_ip"], "192.0.2.107");
        // A failed read omits the key so the agent keeps the vhost's own address.
        assert!(build_nginx_body(&site, None).get("bind_ip").is_none());

        // Non-PHP site: no php_pool (agent keeps its legacy behaviour).
        assert!(build_nginx_body(&site, None).get("php_pool").is_none());
        // PHP site: the full effective pool is always sent.
        let mut php = site.clone();
        php.runtime = "php".into();
        php.php_version = Some("8.3".into());
        php.php_settings = serde_json::json!({});
        php.php_isolation = true;
        php.php_disable_shell = true;
        let body = build_nginx_body(&php, Some("primary"));
        assert_eq!(body["php_pool"], crate::routes::php_settings::php_pool_json(
            &crate::routes::php_settings::PhpRow::of(&php)));
        assert_eq!(body["php_pool"]["values"]["post_max_size"], "72M");
        assert_eq!(body["php_pool"]["isolation"], true);
        // Legacy (migrated) PHP site: only memory + overrides reach the agent,
        // and the B1 response claims no code default for inherited keys.
        let mut legacy = php.clone();
        legacy.php_settings = serde_json::json!({ "legacy": true, "values": { "max_execution_time": "300" } });
        let body = build_nginx_body(&legacy, Some("primary"));
        assert_eq!(body["php_pool"]["values"], serde_json::json!({ "memory_limit": "256M", "max_execution_time": "300" }));
        let r = crate::routes::php_settings::response_json(&legacy, true);
        assert_eq!(r["legacy"], true);
        assert_eq!(r["inherits_global"].as_array().unwrap().len(), 10);
        assert!(r["defaults"].get("date.timezone").is_none());
        assert!(r["effective"].get("date.timezone").is_none());
        assert_eq!(r["defaults"]["memory_limit"], "256M");
        let r = crate::routes::php_settings::response_json(&php, false);
        assert_eq!(r["legacy"], false);
        assert_eq!(r["inherits_global"], serde_json::json!([]));
        assert_eq!(r["defaults"].as_object().unwrap().len(), 12);
        // PHP runtime without a version: no socket, so no pool either.
        php.php_version = None;
        assert!(build_nginx_body(&php, None).get("php_pool").is_none());

        // Feature 4 (B2): the stored web server always travels. A row read
        // without the column (older JSON fixture) defaults to nginx.
        assert_eq!(site.web_server, "nginx");
        assert_eq!(build_nginx_body(&site, None)["web_server"], "nginx");
        let mut apache = php.clone();
        apache.web_server = "apache".into();
        assert_eq!(build_nginx_body(&apache, Some("primary"))["web_server"], "apache");

        // import-hestia (05): the fixture predates the new columns. The two
        // flags default to the historical rendering and always travel; the
        // three lists travel only when the row holds one.
        assert!(site.force_ssl && site.hsts);
        let body = build_nginx_body(&site, None);
        assert_eq!(body["force_ssl"], true);
        assert_eq!(body["hsts"], true);
        assert!(body.get("aliases").is_none());
        assert!(body.get("canonical_host").is_none());
        assert!(body.get("php_no_exec_dirs").is_none());
        let mut extra = site.clone();
        extra.aliases = Some(vec!["www.a.example".into()]);
        extra.canonical_host = Some("www".into());
        extra.php_no_exec_dirs = Some(vec!["/uploads".into()]);
        extra.force_ssl = false;
        extra.hsts = false;
        let body = build_nginx_body(&extra, None);
        assert_eq!(body["aliases"], serde_json::json!(["www.a.example"]));
        assert_eq!(body["canonical_host"], "www");
        assert_eq!(body["php_no_exec_dirs"], serde_json::json!(["/uploads"]));
        assert_eq!(body["force_ssl"], false);
        assert_eq!(body["hsts"], false);
        // An empty managed list is still sent: it means "no aliases", not "keep".
        extra.aliases = Some(vec![]);
        assert_eq!(build_nginx_body(&extra, None)["aliases"], serde_json::json!([]));

        // SFTP pool owner: the default name, or the confirmed custom one.
        let mut sftp = php.clone();
        sftp.sftp_enabled = true;
        sftp.sftp_uid = Some(5001);
        sftp.sftp_gid = Some(5001);
        let body = build_nginx_body(&sftp, None);
        assert_eq!(body["pool_user"], "sftp5001");
        assert_eq!(body["pool_group"], "sftpg5001");
        sftp.sftp_username = Some("adm-jim_x".into());
        let body = build_nginx_body(&sftp, None);
        assert_eq!(body["pool_user"], "adm-jim_x");
        assert_eq!(body["pool_group"], "sftpg5001");
        assert!(site.sftp_username.is_none());
        assert!(build_nginx_body(&site, None).get("pool_user").is_none());
    }

    #[test]
    fn legacy_php_versions_are_accepted_with_a_warning() {
        for v in LEGACY_PHP_VERSIONS {
            assert!(PHP_VERSIONS.contains(v));
            assert!(legacy_php_warning(v).unwrap().contains("end of life"));
        }
        assert_eq!(
            legacy_php_warning("5.6").as_deref(),
            Some("PHP 5.6 reached end of life and gets no security updates")
        );
        assert!(legacy_php_warning("8.3").is_none());
        assert!(legacy_php_warning("7.3").is_none());
    }

    #[test]
    fn no_exec_dirs_are_validated_and_normalised() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The defaults pass their own validator unchanged.
        let d = default_php_no_exec_dirs();
        assert_eq!(validate_no_exec_dirs(&d).unwrap(), d);
        assert_eq!(d.len(), 5);
        // Trailing slashes are dropped; a doubled slash is refused.
        assert!(validate_no_exec_dirs(&s(&["/uploads/", "/a/b//"])).is_err());
        assert_eq!(validate_no_exec_dirs(&s(&["/uploads/", "/media/files"])).unwrap(), s(&["/uploads", "/media/files"]));
        assert_eq!(validate_no_exec_dirs(&Vec::new()).unwrap(), Vec::<String>::new());
        // Refused: relative, traversal, bad characters, the root, duplicates.
        assert!(validate_no_exec_dirs(&s(&["uploads"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/a/../b"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/up loads"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/up;loads"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/uploads", "/uploads/"])).is_err());
        assert!(validate_no_exec_dirs(&s(&["/Uploads", "/uploads"])).is_err());
        // At most 20.
        let many: Vec<String> = (0..21).map(|i| format!("/d{i}")).collect();
        assert!(validate_no_exec_dirs(&many).is_err());
        assert!(validate_no_exec_dirs(&many[..20]).is_ok());
    }

    #[test]
    fn canonical_host_must_be_served() {
        let www = vec!["www.a.example".to_string()];
        assert_eq!(validate_canonical_host("a.example", None, &[]), Ok(None));
        assert_eq!(validate_canonical_host("a.example", Some("apex"), &[]), Ok(Some("apex".into())));
        assert_eq!(validate_canonical_host("a.example", Some("www"), &www), Ok(Some("www".into())));
        assert!(validate_canonical_host("a.example", Some("www"), &[]).is_err());
        assert!(validate_canonical_host("a.example", Some("www"), &["b.example".into()]).is_err());
        assert!(validate_canonical_host("a.example", Some("other"), &www).is_err());
        assert_eq!(canonical_target("a.example", "www"), "www.a.example");
        assert_eq!(canonical_target("a.example", "apex"), "a.example");
    }

    #[test]
    fn new_aliases_are_validated() {
        let existing = vec!["www.a.example".to_string()];
        assert!(validate_new_alias("b.example", "a.example", &existing).is_ok());
        assert!(validate_new_alias("a.example", "a.example", &existing).is_err());
        assert!(validate_new_alias("www.a.example", "a.example", &existing).is_err());
        assert!(validate_new_alias("not a domain", "a.example", &existing).is_err());
        let full: Vec<String> = (0..20).map(|i| format!("n{i}.example")).collect();
        assert!(validate_new_alias("b.example", "a.example", &full).is_err());
        // What may become the managed column.
        assert!(aliases_storable("a.example", &existing));
        assert!(aliases_storable("a.example", &[]));
        assert!(!aliases_storable("a.example", &["a.example".into()]));
        assert!(!aliases_storable("a.example", &["x.example".into(), "X.example".into()]));
        assert!(!aliases_storable("a.example", &["_".into()]));
        let too_many: Vec<String> = (0..21).map(|i| format!("n{i}.example")).collect();
        assert!(!aliases_storable("a.example", &too_many));
    }

    #[test]
    fn sftp_usernames_are_validated() {
        let longest = "a".repeat(32);
        let too_long = "a".repeat(33);
        for ok in ["adm-jim_x", "_svc", "a", "jim.doe", "sftp", "sftpuser", "sftp1a", longest.as_str()] {
            assert!(validate_sftp_username(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in ["", "1abc", "-abc", "Abc", "ab c", "ab@c", too_long.as_str(), "root", "www-data",
                    "admin", "sftp1", "sftp5001", "sftpg12"] {
            assert!(validate_sftp_username(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn sftp_account_name_prefers_the_confirmed_custom_name() {
        let mut site: Site = serde_json::from_str(r#"{
            "id": "00000000-0000-0000-0000-000000000000", "user_id": "00000000-0000-0000-0000-000000000000",
            "server_id": null, "domain": "a.example", "runtime": "php", "status": "active",
            "proxy_port": null, "php_version": "8.3", "root_path": null, "ssl_enabled": false,
            "ssl_cert_path": null, "ssl_key_path": null, "ssl_expiry": null, "ssl_profile": null,
            "ssl_renewal_at": null, "ssl_renewal_checked_at": null, "ssl_challenge": null,
            "ssl_cert_subject": null, "ssl_wildcard": null, "ssl_dns_zone_id": null, "rate_limit": null,
            "max_upload_mb": 64, "php_memory_mb": 256, "php_max_workers": 5, "custom_nginx": null,
            "php_preset": null, "app_command": null, "parent_site_id": null, "synced_at": null,
            "enabled": true, "fastcgi_cache": false, "redis_cache": false, "redis_db": 0,
            "waf_enabled": false, "waf_mode": "detection", "csp_policy": null, "permissions_policy": null,
            "bot_protection": "off", "bandwidth_quota_mb": null, "bandwidth_suspended_at": null,
            "sftp_enabled": true, "sftp_uid": 7, "sftp_gid": 7,
            "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z", "ip_id": null
        }"#)
        .unwrap();
        assert_eq!(sftp_account_name(&site), "sftp7");
        site.sftp_username = Some(String::new());
        assert_eq!(sftp_account_name(&site), "sftp7");
        site.sftp_username = Some("adm-jim_x".into());
        assert_eq!(sftp_account_name(&site), "adm-jim_x");
    }

    #[test]
    fn web_server_values_are_validated() {
        assert_eq!(parse_web_server("nginx"), Ok("nginx"));
        assert_eq!(parse_web_server(" apache "), Ok("apache"));
        assert!(parse_web_server("httpd").is_err());
        assert!(parse_web_server("Apache").is_err());
        assert!(parse_web_server("").is_err());
    }

    #[test]
    fn a_new_site_gets_apache_only_when_it_runs_php() {
        // D1: PHP defaults to apache, nginx stays possible.
        assert_eq!(resolve_create_web_server("php", None), Ok("apache"));
        assert_eq!(resolve_create_web_server("php", Some("nginx")), Ok("nginx"));
        assert_eq!(resolve_create_web_server("php", Some("apache")), Ok("apache"));
        // Every other runtime is forced to nginx, even when apache is asked for.
        for rt in ["static", "proxy", "node", "python"] {
            assert_eq!(resolve_create_web_server(rt, None), Ok("nginx"));
            assert_eq!(resolve_create_web_server(rt, Some("apache")), Ok("nginx"));
        }
        // An unknown value is refused for every runtime, never ignored.
        assert!(resolve_create_web_server("php", Some("lighttpd")).is_err());
        assert!(resolve_create_web_server("static", Some("lighttpd")).is_err());
    }

    // ── proxy_port validation - s241 H4 (SSRF + firewall-clobber DoS) ────

    #[test]
    fn proxy_port_rejects_reserved_and_out_of_range() {
        // Reserved / system / panel ports are rejected (would enable loopback
        // SSRF and let the auto-firewall `ufw deny` clobber a global allow).
        for p in [22, 25, 80, 443, 3306, 5432, 6379, 3080, 3081, 5450, 8091, 8092, 8443, 9443] {
            assert!(!is_safe_proxy_port(p), "port {p} must be rejected");
        }
        // Out-of-range rejected.
        assert!(!is_safe_proxy_port(80));
        assert!(!is_safe_proxy_port(1023));
        assert!(!is_safe_proxy_port(70000));
        assert!(!is_safe_proxy_port(-1));
        // Ordinary high app ports are accepted (incl. the 5000-5999 app range).
        assert!(is_safe_proxy_port(8080));
        assert!(is_safe_proxy_port(3000));
        assert!(is_safe_proxy_port(5001));
        assert!(is_safe_proxy_port(65535));
    }
}
