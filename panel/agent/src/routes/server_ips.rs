//! `/system/ips` — list, add and remove the server's IPv4 addresses, and read
//! their PTR. See `services::server_ips` for the runtime / persistence split.

use axum::{
    extract::Path,
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use super::AppState;
use crate::services::server_ips::{self as sip, HostAddr};

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// Add and delete each read the netplan file, change the system and rewrite
/// the file: two of them interleaved would lose one change. Serialised here.
static IP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Serialize)]
struct IpEntry {
    ip: String,
    prefix: u8,
    interface: String,
    managed: bool,
    primary: bool,
    /// POST only: true when this call ran `ip addr add`, false when it
    /// adopted an address already on the host. Absent from GET.
    #[serde(skip_serializing_if = "Option::is_none")]
    added: Option<bool>,
}

fn entry(a: &HostAddr, managed: &sip::Managed, primary: Option<Ipv4Addr>) -> IpEntry {
    IpEntry {
        ip: a.ip.to_string(),
        prefix: a.prefix,
        interface: a.interface.clone(),
        managed: sip::managed_find(managed, a.ip).is_some(),
        primary: primary == Some(a.ip),
        added: None,
    }
}

/// GET /system/ips
async fn list_ips() -> Result<Json<serde_json::Value>, ApiErr> {
    let addrs = sip::host_addrs()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    // An unreadable netplan file must not hide the inventory: list everything
    // as unmanaged and say so in the log.
    let managed = sip::read_managed().unwrap_or_else(|e| {
        tracing::warn!("{e} — listing every address as unmanaged");
        sip::Managed::new()
    });
    let primary = sip::primary_ip();
    let ips: Vec<IpEntry> = addrs.iter().map(|a| entry(a, &managed, primary)).collect();
    Ok(Json(serde_json::json!({
        "primary": primary.map(|p| p.to_string()),
        "ips": ips,
    })))
}

#[derive(Deserialize)]
struct AddIpRequest {
    ip: String,
    /// Signed and wide on purpose: an out-of-range value must reach the
    /// validation below and get a 400, not a deserialisation 422.
    #[serde(default)]
    prefix: Option<i64>,
    #[serde(default)]
    interface: Option<String>,
}

fn parse_ip(s: &str) -> Result<Ipv4Addr, ApiErr> {
    s.trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid IPv4 address"))
}

/// POST /system/ips — `{ip, prefix?=32, interface?=<default route device>}`.
///
/// An address already on the host is *adopted* (written to our netplan file
/// without `ip addr add`), using the interface and prefix it actually has; an
/// explicit interface/prefix that disagrees with them is a 400. Adopting the
/// primary IP is refused (409): it belongs to the interface's own config.
async fn add_ip(Json(body): Json<AddIpRequest>) -> Result<Json<IpEntry>, ApiErr> {
    let ip = parse_ip(&body.ip)?;
    sip::validate_new_ip(ip).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;

    let req_prefix: Option<u8> = match body.prefix {
        None => None,
        Some(p) if (8..=32).contains(&p) => Some(p as u8),
        Some(_) => return Err(err(StatusCode::BAD_REQUEST, "prefix must be between 8 and 32")),
    };
    let req_iface = match body.interface.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(i) => {
            if !sip::is_valid_iface_name(i) || !sip::link_names().iter().any(|l| l == i) {
                return Err(err(StatusCode::BAD_REQUEST, "Unknown or invalid network interface"));
            }
            Some(i.to_string())
        }
        None => None,
    };

    let _guard = IP_LOCK.lock().await;

    let primary = sip::primary_ip();
    if primary == Some(ip) {
        return Err(err(
            StatusCode::CONFLICT,
            "This is the server's primary IP; it is managed by the interface's own configuration",
        ));
    }

    let addrs = sip::host_addrs()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    let (iface, prefix, added_now) = match addrs.iter().find(|a| a.ip == ip) {
        Some(existing) => {
            if req_iface.as_deref().is_some_and(|i| i != existing.interface) {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    &format!("{ip} is already assigned on {}", existing.interface),
                ));
            }
            if req_prefix.is_some_and(|p| p != existing.prefix) {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    &format!("{ip} is already assigned with prefix /{}", existing.prefix),
                ));
            }
            (existing.interface.clone(), existing.prefix, false)
        }
        None => {
            let iface = match req_iface {
                Some(i) => i,
                None => sip::default_route_iface()
                    .await
                    .filter(|i| sip::is_valid_iface_name(i))
                    .ok_or_else(|| {
                        err(StatusCode::BAD_REQUEST, "No default route: specify the interface")
                    })?,
            };
            (iface, req_prefix.unwrap_or(32), true)
        }
    };

    // Read before changing anything, so a corrupt file fails the request
    // with the system untouched.
    let previous = sip::read_netplan_raw().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let mut managed = sip::parse_netplan(previous.as_deref().unwrap_or(""))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    // Filed under the interface's existing netplan definition ID so netplan
    // merges it (see `resolve_definition_id`). No existing definition: refuse
    // rather than create a competing one, before touching the system.
    let Some(def_id) = sip::definition_id_for(&iface) else {
        return Err(err(
            StatusCode::CONFLICT,
            &format!("interface {iface} is not defined in netplan; refusing to create a competing definition"),
        ));
    };

    if added_now {
        sip::ip_addr("add", ip, prefix, &iface)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    }
    let undo_addr = || async {
        if added_now {
            if let Err(e) = sip::ip_addr("del", ip, prefix, &iface).await {
                tracing::error!("rollback: {e}");
            }
        }
    };

    sip::managed_add(&mut managed, &def_id, ip, prefix);
    let rendered = sip::render_netplan_for_host(&managed);
    if let Err(e) = sip::write_netplan_raw(rendered.as_deref()).await {
        undo_addr().await;
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to write {}: {e}", sip::NETPLAN_PATH)));
    }
    if let Err(e) = sip::netplan_generate().await {
        if let Err(re) = sip::write_netplan_raw(previous.as_deref()).await {
            tracing::error!("rollback of {} failed: {re}", sip::NETPLAN_PATH);
        }
        // Regenerate /run from the restored files, as the delete path does.
        if let Err(re) = sip::netplan_generate().await {
            tracing::error!("netplan generate after rollback failed: {re}");
        }
        undo_addr().await;
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("netplan generate rejected the configuration (restored): {e}"),
        ));
    }

    tracing::info!(
        "Server IP {ip}/{prefix} on {iface} {} and persisted in {}",
        if added_now { "added" } else { "adopted" },
        sip::NETPLAN_PATH
    );
    Ok(Json(IpEntry {
        ip: ip.to_string(),
        prefix,
        interface: iface,
        managed: true,
        primary: false,
        added: Some(added_now),
    }))
}

/// DELETE /system/ips/{ip} — only for an address in our netplan file, never
/// the primary. The file is rewritten and validated first, then the address
/// is removed from the interface; a failure at either step restores the file.
async fn delete_ip(Path(ip): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    let ip = parse_ip(&ip)?;
    let _guard = IP_LOCK.lock().await;

    let previous = sip::read_netplan_raw().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let mut managed = sip::parse_netplan(previous.as_deref().unwrap_or(""))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    if let Some(reason) = sip::delete_refusal(ip, sip::primary_ip(), &managed) {
        return Err(err(StatusCode::CONFLICT, reason));
    }
    let (m_iface, m_prefix) = sip::managed_find(&managed, ip).unwrap_or_default();

    sip::managed_remove(&mut managed, ip);
    let rendered = sip::render_netplan_for_host(&managed);
    let restore = || async {
        if let Err(re) = sip::write_netplan_raw(previous.as_deref()).await {
            tracing::error!("rollback of {} failed: {re}", sip::NETPLAN_PATH);
        }
    };
    if let Err(e) = sip::write_netplan_raw(rendered.as_deref()).await {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to write {}: {e}", sip::NETPLAN_PATH)));
    }
    if let Err(e) = sip::netplan_generate().await {
        restore().await;
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("netplan generate rejected the configuration (restored): {e}"),
        ));
    }

    // Remove it from the interface it is really on (the file may be stale).
    let on_system = sip::host_addrs()
        .await
        .ok()
        .and_then(|a| a.into_iter().find(|a| a.ip == ip));
    if let Some(a) = on_system {
        if let Err(e) = sip::ip_addr("del", ip, a.prefix, &a.interface).await {
            restore().await;
            let _ = sip::netplan_generate().await;
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &e));
        }
    } else {
        tracing::info!("{ip} ({m_iface}/{m_prefix}) was already absent from the interface");
    }

    tracing::info!("Server IP {ip} removed from the system and from {}", sip::NETPLAN_PATH);
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /system/ips/{ip}/ptr — `{ip, ptr}`; `ptr` is null when there is none.
async fn get_ptr(Path(ip): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    let ip = parse_ip(&ip)?;
    let ptr = sip::ptr_lookup(ip).await;
    Ok(Json(serde_json::json!({ "ip": ip.to_string(), "ptr": ptr })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/system/ips", get(list_ips).post(add_ip))
        .route("/system/ips/{ip}", delete(delete_ip))
        .route("/system/ips/{ip}/ptr", get(get_ptr))
}
