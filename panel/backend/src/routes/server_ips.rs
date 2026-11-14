//! Multi-IP: the IPv4 addresses of a server (conception/01-multi-ip.md §5.1,
//! contract `conception/01-multi-ip-contrats.md` §B).
//!
//! Admin-only, scoped to the server named by `X-Server-Id` (`ServerScope`). The
//! panel's rows (`server_ips`) are the inventory sites and mail domains point at;
//! the agent (`/system/ips`) is the truth about what is actually on the
//! interface. The list merges the two:
//!
//! * `on_system` / `is_primary` come from the agent. When the agent cannot be
//!   asked, both read `false` and the list still answers — this is an inventory
//!   page, and an unreachable box is exactly when an operator needs to see what
//!   is declared on it. The DB `managed` value is shown as stored in that case.
//! * `managed` comes from the agent when it reports the address (it owns
//!   `60-dockpanel.yaml`), else from the row.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::auth::{AdminUser, ServerScope};
use crate::error::{agent_error, err, internal_error, ApiError};
use crate::models::ServerIpRow;
use crate::services::activity;
use crate::services::agent::AgentHandle;
use crate::AppState;

/// `ServerIp` of the contract.
#[derive(Debug, Serialize)]
pub struct ServerIpDto {
    pub id: Uuid,
    pub server_id: Uuid,
    pub ip: String,
    pub prefix: i16,
    pub interface: Option<String>,
    pub public_ip: Option<String>,
    pub ptr: Option<String>,
    pub ptr_checked_at: Option<DateTime<Utc>>,
    pub managed: bool,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub site_count: i64,
    pub mail_domain_count: i64,
    pub on_system: bool,
    pub is_primary: bool,
}

/// One entry of the agent's `GET /system/ips` (contract §A1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemIp {
    pub ip: String,
    #[serde(default = "default_prefix")]
    pub prefix: i16,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub primary: bool,
}

fn default_prefix() -> i16 {
    32
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SystemIps {
    #[serde(default)]
    pub primary: Option<String>,
    #[serde(default)]
    pub ips: Vec<SystemIp>,
}

impl SystemIps {
    fn find(&self, ip: &str) -> Option<&SystemIp> {
        self.ips.iter().find(|s| s.ip == ip)
    }
}

async fn system_ips(agent: &AgentHandle) -> Result<SystemIps, crate::services::agent::AgentError> {
    let v = agent.get("/system/ips").await?;
    serde_json::from_value(v).map_err(|e| crate::services::agent::AgentError::Parse(e.to_string()))
}

/// Merge a row with its usage counts and the agent's view.
fn to_dto(row: ServerIpRow, site_count: i64, mail_domain_count: i64, system: Option<&SystemIps>) -> ServerIpDto {
    let live = system.and_then(|s| s.find(&row.ip));
    let is_primary = match (system, live) {
        (Some(s), Some(l)) => l.primary || s.primary.as_deref() == Some(row.ip.as_str()),
        (Some(s), None) => s.primary.as_deref() == Some(row.ip.as_str()),
        _ => false,
    };
    ServerIpDto {
        managed: live.map(|l| l.managed).unwrap_or(row.managed),
        on_system: live.is_some(),
        is_primary,
        id: row.id,
        server_id: row.server_id,
        ip: row.ip,
        prefix: row.prefix,
        interface: row.interface,
        public_ip: row.public_ip,
        ptr: row.ptr,
        ptr_checked_at: row.ptr_checked_at,
        label: row.label,
        created_at: row.created_at,
        site_count,
        mail_domain_count,
    }
}

/// The agent's `added` flag on `POST /system/ips`. Absent = false: rolling back
/// an address we cannot prove we added could take a live one off the host.
fn added_by_call(v: &serde_json::Value) -> bool {
    v.get("added").and_then(|a| a.as_bool()).unwrap_or(false)
}

/// Addresses on the interface that no row declares yet (`discover`).
fn undeclared(system: &SystemIps, declared: &[String]) -> Vec<SystemIp> {
    system
        .ips
        .iter()
        .filter(|s| !declared.iter().any(|d| d == &s.ip))
        .map(|s| SystemIp {
            primary: s.primary || system.primary.as_deref() == Some(s.ip.as_str()),
            ..s.clone()
        })
        .collect()
}

/// A usable host IPv4 address: rejects loopback, unspecified, broadcast,
/// multicast and link-local, which nginx or Postfix could never usefully bind.
fn valid_ipv4(s: &str) -> Option<String> {
    let ip: Ipv4Addr = s.trim().parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_link_local() {
        return None;
    }
    Some(ip.to_string())
}

fn valid_interface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Normalise an optional label: trimmed, empty → None, at most 100 characters.
fn clean_label(s: Option<&str>) -> Result<Option<String>, ApiError> {
    match s.map(str::trim).filter(|l| !l.is_empty()) {
        None => Ok(None),
        Some(l) if l.chars().count() > 100 => Err(err(StatusCode::BAD_REQUEST, "label must be at most 100 characters")),
        Some(l) if l.chars().any(char::is_control) => Err(err(StatusCode::BAD_REQUEST, "label must not contain control characters")),
        Some(l) => Ok(Some(l.to_string())),
    }
}

/// Normalise an optional public address: empty → None, else a valid IPv4.
fn clean_public_ip(s: Option<&str>) -> Result<Option<String>, ApiError> {
    match s.map(str::trim).filter(|p| !p.is_empty()) {
        None => Ok(None),
        Some(p) => valid_ipv4(p)
            .map(Some)
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "public_ip must be a valid IPv4 address")),
    }
}

/// A PTR answer, cleaned: no trailing dot, `None` for empty.
fn clean_ptr(v: &serde_json::Value) -> Option<String> {
    v.get("ptr")
        .and_then(|p| p.as_str())
        .map(|p| p.trim().trim_end_matches('.').to_string())
        .filter(|p| !p.is_empty() && p.len() <= 253)
}

async fn read_ptr(agent: &AgentHandle, ip: &str) -> Result<Option<String>, crate::services::agent::AgentError> {
    agent.get(&format!("/system/ips/{ip}/ptr")).await.map(|v| clean_ptr(&v))
}

async fn usage_counts(db: &sqlx::PgPool, id: Uuid) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM sites WHERE ip_id = $1), \
                (SELECT COUNT(*) FROM mail_domains WHERE send_ip_id = $1)",
    )
    .bind(id)
    .fetch_one(db)
    .await
}

async fn row_on_server(db: &sqlx::PgPool, id: Uuid, server_id: Uuid) -> Result<ServerIpRow, ApiError> {
    sqlx::query_as("SELECT * FROM server_ips WHERE id = $1 AND server_id = $2")
        .bind(id)
        .bind(server_id)
        .fetch_optional(db)
        .await
        .map_err(|e| internal_error("server ip", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "IP address not found"))
}

/// One row as the contract's `ServerIp`, agent asked best-effort.
async fn dto_for(db: &sqlx::PgPool, agent: &AgentHandle, row: ServerIpRow) -> Result<ServerIpDto, ApiError> {
    let (sites, mail) = usage_counts(db, row.id).await.map_err(|e| internal_error("server ip", e))?;
    let system = system_ips(agent).await.ok();
    Ok(to_dto(row, sites, mail, system.as_ref()))
}

// ── handlers ────────────────────────────────────────────────────────────

/// GET /api/server-ips
pub async fn list(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
) -> Result<Json<Vec<ServerIpDto>>, ApiError> {
    let rows: Vec<(ServerIpRow, i64, i64)> = {
        #[derive(sqlx::FromRow)]
        struct Counted {
            #[sqlx(flatten)]
            row: ServerIpRow,
            site_count: i64,
            mail_domain_count: i64,
        }
        let counted: Vec<Counted> = sqlx::query_as(
            "SELECT si.*, \
                (SELECT COUNT(*) FROM sites s WHERE s.ip_id = si.id) AS site_count, \
                (SELECT COUNT(*) FROM mail_domains md WHERE md.send_ip_id = si.id) AS mail_domain_count \
             FROM server_ips si WHERE si.server_id = $1 ORDER BY si.created_at",
        )
        .bind(server_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal_error("list server ips", e))?;
        counted.into_iter().map(|c| (c.row, c.site_count, c.mail_domain_count)).collect()
    };

    let system = match system_ips(&agent).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!("Server IPs for {server_id}: agent could not be asked ({e}) — on_system/is_primary reported false");
            None
        }
    };

    Ok(Json(
        rows.into_iter()
            .map(|(row, s, m)| to_dto(row, s, m, system.as_ref()))
            .collect(),
    ))
}

/// GET /api/server-ips/discover — addresses on the interface not yet declared.
pub async fn discover(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
) -> Result<Json<Vec<SystemIp>>, ApiError> {
    let system = system_ips(&agent).await.map_err(|e| agent_error("Discover server IPs", e))?;
    let declared: Vec<String> = sqlx::query_scalar("SELECT ip FROM server_ips WHERE server_id = $1")
        .bind(server_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal_error("discover server ips", e))?;
    Ok(Json(undeclared(&system, &declared)))
}

#[derive(Deserialize)]
pub struct CreateServerIpRequest {
    pub ip: String,
    pub prefix: Option<i16>,
    pub interface: Option<String>,
    pub label: Option<String>,
    pub public_ip: Option<String>,
    #[serde(default)]
    pub add_to_system: bool,
}

/// POST /api/server-ips — declare an address already on the interface, or put it
/// there first (`add_to_system: true`, agent `POST /system/ips`). Reads its PTR.
pub async fn create(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    headers: HeaderMap,
    Json(body): Json<CreateServerIpRequest>,
) -> Result<(StatusCode, Json<ServerIpDto>), ApiError> {
    let ip = valid_ipv4(&body.ip).ok_or_else(|| err(StatusCode::BAD_REQUEST, "ip must be a valid IPv4 address"))?;
    if let Some(p) = body.prefix {
        if !(8..=32).contains(&p) {
            return Err(err(StatusCode::BAD_REQUEST, "prefix must be between 8 and 32"));
        }
    }
    let interface = body.interface.as_deref().map(str::trim).filter(|i| !i.is_empty());
    if let Some(i) = interface {
        if !valid_interface(i) {
            return Err(err(StatusCode::BAD_REQUEST, "interface must match [a-zA-Z0-9._-] (at most 32 characters)"));
        }
    }
    let label = clean_label(body.label.as_deref())?;
    let public_ip = clean_public_ip(body.public_ip.as_deref())?;

    // Before touching the interface: a second declaration would otherwise put
    // the address on the box and only then fail on the UNIQUE constraint.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM server_ips WHERE server_id = $1 AND ip = $2)")
        .bind(server_id)
        .bind(&ip)
        .fetch_one(&state.db)
        .await
        .map_err(|e| internal_error("create server ip", e))?;
    if exists {
        return Err(err(StatusCode::CONFLICT, "This IP address is already declared on this server"));
    }

    let (entry, added_by_us) = if body.add_to_system {
        // Only what the operator gave: the agent defaults the rest, and a forced
        // `/32` would make adopting an address already on the host as `/24` fail.
        let mut req = serde_json::json!({ "ip": ip });
        if let Some(p) = body.prefix {
            req["prefix"] = serde_json::json!(p);
        }
        if let Some(i) = interface {
            req["interface"] = serde_json::json!(i);
        }
        // 4xx refusals (invalid input, interface not defined in netplan → 409)
        // pass through `agent_error` with the agent's own message.
        let v = agent.post("/system/ips", Some(req)).await.map_err(|e| agent_error("Add server IP", e))?;
        // `added` is true only when THIS call ran `ip addr add`; an address the
        // host already had is adopted, and must never be removed on rollback.
        let added = added_by_call(&v);
        let entry: SystemIp = serde_json::from_value(v).unwrap_or(SystemIp {
            ip: ip.clone(),
            prefix: body.prefix.unwrap_or(32),
            interface: interface.map(str::to_string),
            managed: true,
            primary: false,
        });
        (entry, added)
    } else {
        let system = system_ips(&agent).await.map_err(|e| agent_error("Read server IPs", e))?;
        let entry = system.find(&ip).cloned().ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "This IP address is not present on the server. Declare one listed by discovery, or add it to the system.",
            )
        })?;
        let primary = entry.primary || system.primary.as_deref() == Some(ip.as_str());
        (SystemIp { primary, ..entry }, false)
    };

    let (ptr, ptr_checked_at) = match read_ptr(&agent, &ip).await {
        Ok(p) => (p, Some(Utc::now())),
        Err(e) => {
            tracing::warn!("PTR of {ip} could not be read: {e}");
            (None, None)
        }
    };

    let row: Result<ServerIpRow, sqlx::Error> = sqlx::query_as(
        "INSERT INTO server_ips (server_id, ip, prefix, interface, public_ip, ptr, ptr_checked_at, managed, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
    )
    .bind(server_id)
    .bind(&ip)
    .bind(entry.prefix)
    .bind(entry.interface.as_deref().or(interface))
    .bind(&public_ip)
    .bind(&ptr)
    .bind(ptr_checked_at)
    .bind(entry.managed)
    .bind(&label)
    .fetch_one(&state.db)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            // Undo what this request put on the interface, so a failed declaration
            // never leaves an address the panel does not know about.
            if added_by_us {
                if let Err(de) = agent.delete(&format!("/system/ips/{ip}")).await {
                    tracing::error!("Declaring {ip} failed and it could not be removed from the system again: {de}");
                }
            }
            return Err(if e.to_string().contains("duplicate key") {
                err(StatusCode::CONFLICT, "This IP address is already declared on this server")
            } else {
                internal_error("create server ip", e)
            });
        }
    };

    let caller_ip = crate::routes::client_ip(&headers);
    let details = if added_by_us {
        "added to the system"
    } else if body.add_to_system {
        "already on the system, adopted"
    } else {
        "declared"
    };
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "server_ip.add",
        Some("server_ip"), Some(&ip), Some(details), caller_ip.as_deref(), claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "server_ip.add", Some(&claims.email), caller_ip.as_deref(),
        Some("server_ip"), Some(&ip), Some(details), None, "warning", claims.key_id,
    ).await;

    let system = SystemIps { primary: entry.primary.then(|| ip.clone()), ips: vec![entry] };
    Ok((StatusCode::CREATED, Json(to_dto(row, 0, 0, Some(&system)))))
}

#[derive(Deserialize)]
pub struct UpdateServerIpRequest {
    /// Absent = unchanged; `null` or `""` = cleared.
    #[serde(default, deserialize_with = "crate::routes::secrets::explicit_option")]
    pub label: Option<Option<String>>,
    /// Absent = unchanged; `null` or `""` = cleared (the address is its own
    /// public address again).
    #[serde(default, deserialize_with = "crate::routes::secrets::explicit_option")]
    pub public_ip: Option<Option<String>>,
}

/// PUT /api/server-ips/{id} — label and public address (NAT).
///
/// A changed `public_ip` changes what the DNS tabs and checks expect; records
/// already published in a managed zone are not rewritten here.
pub async fn update(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateServerIpRequest>,
) -> Result<Json<ServerIpDto>, ApiError> {
    let current = row_on_server(&state.db, id, server_id).await?;

    let label = match &body.label {
        None => current.label.clone(),
        Some(v) => clean_label(v.as_deref())?,
    };
    let public_ip = match &body.public_ip {
        None => current.public_ip.clone(),
        Some(v) => clean_public_ip(v.as_deref())?,
    };

    let row: ServerIpRow = sqlx::query_as(
        "UPDATE server_ips SET label = $1, public_ip = $2 WHERE id = $3 AND server_id = $4 RETURNING *",
    )
    .bind(&label)
    .bind(&public_ip)
    .bind(id)
    .bind(server_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("update server ip", e))?;

    let caller_ip = crate::routes::client_ip(&headers);
    let details = format!(
        "label={} public_ip={}",
        label.as_deref().unwrap_or("-"),
        public_ip.as_deref().unwrap_or("-")
    );
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "server_ip.update",
        Some("server_ip"), Some(&row.ip), Some(&details), caller_ip.as_deref(), claims.key_id,
    ).await;

    Ok(Json(dto_for(&state.db, &agent, row).await?))
}

/// POST /api/server-ips/{id}/refresh-ptr — re-read the PTR; a changed PTR is a
/// changed HELO, so the server's mail configuration is re-synced.
pub async fn refresh_ptr(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ServerIpDto>, ApiError> {
    let current = row_on_server(&state.db, id, server_id).await?;
    let ptr = read_ptr(&agent, &current.ip).await.map_err(|e| agent_error("Read PTR", e))?;

    let row: ServerIpRow = sqlx::query_as(
        "UPDATE server_ips SET ptr = $1, ptr_checked_at = NOW() WHERE id = $2 AND server_id = $3 RETURNING *",
    )
    .bind(&ptr)
    .bind(id)
    .bind(server_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("refresh ptr", e))?;

    if row.ptr != current.ptr {
        tracing::info!("PTR of {} changed ({:?} → {:?}) — re-syncing mail", row.ip, current.ptr, row.ptr);
        // Best-effort: the PTR is stored either way; a refused rebuild is logged.
        if let Err((status, msg)) = crate::routes::mail::sync_mail_config(&state, server_id, &agent).await {
            tracing::warn!("Mail sync after the PTR change of {} was refused ({status}): {:?}", row.ip, msg.0);
        }
    }

    Ok(Json(dto_for(&state.db, &agent, row).await?))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    pub remove_from_system: bool,
}

/// The 409 body when an address is still used.
async fn in_use_error(db: &sqlx::PgPool, id: Uuid) -> Option<ApiError> {
    let sites: Vec<String> = sqlx::query_scalar("SELECT domain FROM sites WHERE ip_id = $1 ORDER BY domain")
        .bind(id)
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mail_domains: Vec<String> =
        sqlx::query_scalar("SELECT domain FROM mail_domains WHERE send_ip_id = $1 ORDER BY domain")
            .bind(id)
            .fetch_all(db)
            .await
            .unwrap_or_default();
    if sites.is_empty() && mail_domains.is_empty() {
        return None;
    }
    Some((
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "This IP address is still used. Move these sites and mail domains to another address first.",
            "sites": sites,
            "mail_domains": mail_domains,
        })),
    ))
}

/// DELETE /api/server-ips/{id}?remove_from_system=true|false
///
/// Refused (409, naming the users) while any site or mail domain points at it.
/// `remove_from_system=true` also takes a panel-managed address off the
/// interface (one the system owns is only undeclared); the agent still refuses
/// (409) the primary address. The row is deleted inside a transaction that
/// commits only after the agent agreed, so the two never disagree.
pub async fn remove(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    Path(id): Path<Uuid>,
    Query(q): Query<DeleteQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = row_on_server(&state.db, id, server_id).await?;
    if let Some(e) = in_use_error(&state.db, id).await {
        return Err(e);
    }

    let mut tx = state.db.begin().await.map_err(|e| internal_error("delete server ip", e))?;
    if let Err(e) = sqlx::query("DELETE FROM server_ips WHERE id = $1 AND server_id = $2")
        .bind(id)
        .bind(server_id)
        .execute(&mut *tx)
        .await
    {
        drop(tx);
        // A site or mail domain was attached between the check and the delete.
        if let Some(conflict) = in_use_error(&state.db, id).await {
            return Err(conflict);
        }
        return Err(internal_error("delete server ip", e));
    }

    // Only a panel-managed address is ever taken off the interface; for one the
    // system owns (DHCP, cloud-init, another tool) the flag only undeclares it.
    // The agent's live answer wins over the stored flag, as in the list.
    let managed = if q.remove_from_system {
        match system_ips(&agent).await {
            Ok(s) => s.find(&row.ip).map(|l| l.managed).unwrap_or(false),
            Err(_) => row.managed,
        }
    } else {
        false
    };
    let mut removed_from_system = false;
    if q.remove_from_system && managed {
        agent
            .delete(&format!("/system/ips/{}", row.ip))
            .await
            .map_err(|e| agent_error("Remove server IP", e))?;
        removed_from_system = true;
    }

    tx.commit().await.map_err(|e| internal_error("delete server ip", e))?;

    let caller_ip = crate::routes::client_ip(&headers);
    let details = if removed_from_system { "removed from the system" } else { "undeclared" };
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "server_ip.remove",
        Some("server_ip"), Some(&row.ip), Some(details), caller_ip.as_deref(), claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "server_ip.remove", Some(&claims.email), caller_ip.as_deref(),
        Some("server_ip"), Some(&row.ip), Some(details), None, "warning", claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ip: &str, managed: bool) -> ServerIpRow {
        ServerIpRow {
            id: Uuid::nil(),
            server_id: Uuid::nil(),
            ip: ip.into(),
            prefix: 32,
            interface: Some("eth0".into()),
            public_ip: None,
            ptr: None,
            ptr_checked_at: None,
            managed,
            label: None,
            created_at: Utc::now(),
        }
    }

    fn system() -> SystemIps {
        serde_json::from_value(serde_json::json!({
            "primary": "192.168.250.10",
            "ips": [
                { "ip": "192.168.250.10", "prefix": 24, "interface": "eth0", "managed": false, "primary": true },
                { "ip": "192.168.250.13", "prefix": 32, "interface": "eth0", "managed": true, "primary": false }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn the_list_merges_the_agents_view() {
        let s = system();
        let p = to_dto(row("192.168.250.10", false), 2, 1, Some(&s));
        assert!(p.on_system && p.is_primary && !p.managed);
        assert_eq!((p.site_count, p.mail_domain_count), (2, 1));
        // The agent owns `managed`: it is what reads 60-dockpanel.yaml.
        let m = to_dto(row("192.168.250.13", false), 0, 0, Some(&s));
        assert!(m.on_system && !m.is_primary && m.managed);
        let gone = to_dto(row("192.168.250.14", true), 0, 0, Some(&s));
        assert!(!gone.on_system && !gone.is_primary && gone.managed);
    }

    #[test]
    fn an_unreachable_agent_reports_nothing_live() {
        let d = to_dto(row("192.168.250.10", true), 0, 0, None);
        assert!(!d.on_system && !d.is_primary && d.managed);
    }

    #[test]
    fn discovery_lists_only_undeclared_addresses() {
        let found = undeclared(&system(), &["192.168.250.13".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].ip, "192.168.250.10");
        assert!(found[0].primary);
    }

    #[test]
    fn only_bindable_ipv4_addresses_are_accepted() {
        assert_eq!(valid_ipv4(" 192.0.2.107 ").as_deref(), Some("192.0.2.107"));
        for bad in ["", "::1", "127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "169.254.1.1", "1.2.3", "a.b.c.d"] {
            assert!(valid_ipv4(bad).is_none(), "{bad} must be refused");
        }
        assert!(valid_interface("ens3") && valid_interface("eth0.100") && !valid_interface("eth0;rm"));
    }

    #[test]
    fn labels_and_public_addresses_are_normalised() {
        assert_eq!(clean_label(Some("  ")).unwrap(), None);
        assert_eq!(clean_label(Some(" web ")).unwrap().as_deref(), Some("web"));
        assert!(clean_label(Some(&"x".repeat(101))).is_err());
        assert_eq!(clean_public_ip(Some("")).unwrap(), None);
        assert!(clean_public_ip(Some("not-an-ip")).is_err());
    }

    #[test]
    fn a_ptr_answer_is_cleaned() {
        assert_eq!(clean_ptr(&serde_json::json!({"ip": "1.2.3.4", "ptr": "mail2.example.fr."})).as_deref(), Some("mail2.example.fr"));
        assert_eq!(clean_ptr(&serde_json::json!({"ip": "1.2.3.4", "ptr": null})), None);
    }

    #[test]
    fn only_an_address_this_call_added_is_rolled_back() {
        assert!(added_by_call(&serde_json::json!({"ip": "1.2.3.4", "added": true})));
        assert!(!added_by_call(&serde_json::json!({"ip": "1.2.3.4", "added": false})));
        assert!(!added_by_call(&serde_json::json!({"ip": "1.2.3.4"})));
    }

    #[test]
    fn the_update_body_tells_absent_from_null() {
        let b: UpdateServerIpRequest = serde_json::from_str(r#"{"label": null}"#).unwrap();
        assert_eq!(b.label, Some(None));
        assert_eq!(b.public_ip, None);
    }
}
