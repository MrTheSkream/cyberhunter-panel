//! Server IPv4 inventory and management — the DockPanel equivalent of
//! HestiaCP's `v-add-sys-ip` / `v-delete-sys-ip`.
//!
//! Two layers, deliberately kept apart:
//!
//! * **Runtime** — `ip addr add/del`, which takes effect immediately and
//!   without touching any other address (no link bounce, no `netplan apply`,
//!   which can drop a remote server off the network).
//! * **Persistence** — [`NETPLAN_PATH`], a netplan file that holds *only* the
//!   addresses the panel itself added. netplan merges every file of
//!   `/etc/netplan` by definition id, so the interface's own definition
//!   (cloud-init DHCP, an installer-written static config, `60-hestia.yaml`…)
//!   is left untouched and our addresses are appended to it at boot. The file
//!   is validated with `netplan generate` and never applied.
//!
//! Addresses that are on the host but absent from our file are "unmanaged":
//! they are listed and usable, but the panel never removes them.
//!
//! The agent runs under `ProtectSystem=strict` and `/etc/netplan` is not in
//! the unit's `ReadWritePaths`, so the file is staged under `/var/lib/dockpanel`
//! and moved into place from outside the sandbox (the precedent is
//! `routes/server_utils.rs::write_authorized_keys`). `netplan generate` writes
//! under `/run`, which is read-only in the sandbox too, so it runs unsandboxed
//! as well. Reading the file and `ip addr` work fine inside the sandbox.

use crate::safe_cmd::{safe_command, safe_command_sync, safe_command_unsandboxed};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The only netplan file this module ever writes. A constant so the pure
/// functions below can be tested without touching the system.
pub const NETPLAN_PATH: &str = "/etc/netplan/60-dockpanel.yaml";

/// Header written at the top of [`NETPLAN_PATH`].
const NETPLAN_HEADER: &str = "# Added by DockPanel (Server IPs). Do not edit by hand: the panel rewrites this file.\n";

/// One IPv4 address assigned on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub interface: String,
}

/// Managed addresses as stored in [`NETPLAN_PATH`]: interface → `ip/prefix` list.
/// A `BTreeMap` so the rendered file is stable whatever the insertion order.
pub type Managed = BTreeMap<String, Vec<String>>;

// ── Pure helpers ────────────────────────────────────────────────────────

/// Interfaces whose addresses are never offered as site / mail IPs: the
/// Docker bridges and the veth ends of containers. Their addresses are
/// `scope global` like any other, but binding a vhost or Postfix to one makes
/// no sense and listing them in the panel only invites mistakes.
fn is_container_interface(name: &str) -> bool {
    name.starts_with("docker") || name.starts_with("br-") || name.starts_with("veth")
}

/// Parse `ip -o -4 addr show scope global`.
///
/// Each line looks like
/// `2: eth0    inet 192.168.250.10/24 brd 192.168.250.255 scope global eth0\ ...`
/// — field 1 is the device (possibly `name@peer` for veth-like links), field 3
/// the CIDR. Container interfaces are dropped (see [`is_container_interface`]).
pub fn parse_ip_addr_output(out: &str) -> Vec<HostAddr> {
    let mut addrs = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[2] != "inet" {
            continue;
        }
        let iface = fields[1].split('@').next().unwrap_or("").trim_end_matches(':');
        if iface.is_empty() || is_container_interface(iface) {
            continue;
        }
        let Some((ip, prefix)) = parse_cidr(fields[3]) else { continue };
        addrs.push(HostAddr { ip, prefix, interface: iface.to_string() });
    }
    addrs
}

/// `"1.2.3.4/24"` → `(1.2.3.4, 24)`. A bare address is taken as `/32`.
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    match s.split_once('/') {
        Some((ip, p)) => {
            let ip: Ipv4Addr = ip.parse().ok()?;
            let p: u8 = p.parse().ok()?;
            (p <= 32).then_some((ip, p))
        }
        None => Some((s.parse().ok()?, 32)),
    }
}

/// The device of the default route, from `ip -o -4 route show default`
/// (`default via 192.168.250.1 dev eth0 proto static`).
pub fn parse_default_route_dev(out: &str) -> Option<String> {
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"default") {
            continue;
        }
        if let Some(pos) = fields.iter().position(|f| *f == "dev") {
            if let Some(dev) = fields.get(pos + 1) {
                return Some(dev.to_string());
            }
        }
    }
    None
}

/// Interface name shape accepted from a request: `^[A-Za-z0-9._-]{1,15}$`
/// (15 = IFNAMSIZ - 1). `.` and `..` match the character class but are
/// refused — and the name must additionally be one of the host's real links,
/// which the caller checks against the enumerated list.
pub fn is_valid_iface_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s != "."
        && s != ".."
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Addresses that can never be a server's own unicast address.
pub fn validate_new_ip(ip: Ipv4Addr) -> Result<(), String> {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
    {
        return Err(format!("{ip} is not a usable unicast IPv4 address"));
    }
    Ok(())
}

/// A DNS hostname as Postfix and the PTR answer use it: labels of
/// `[A-Za-z0-9-]`, 1..=63 chars, not starting/ending with `-`, total ≤ 253.
/// A single trailing dot is tolerated by [`normalize_hostname`], not here.
pub fn is_valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Strip a trailing dot, lowercase, and validate. `None` for anything that is
/// not a plain hostname (error lines from `dig`, empty output, …).
pub fn normalize_hostname(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    is_valid_hostname(&s).then_some(s)
}

/// First valid hostname in `dig +short -x` output.
pub fn parse_dig_ptr(out: &str) -> Option<String> {
    out.lines().find_map(normalize_hostname)
}

/// Parse [`NETPLAN_PATH`]. Only `network.ethernets.<iface>.addresses` is
/// read; anything else in the file is ignored (and dropped on the next write —
/// the file is ours). An empty file parses as no managed addresses.
pub fn parse_netplan(text: &str) -> Result<Managed, String> {
    let mut managed = Managed::new();
    if text.trim().is_empty() {
        return Ok(managed);
    }
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| format!("invalid YAML in {NETPLAN_PATH}: {e}"))?;
    let Some(eths) = doc
        .get("network")
        .and_then(|n| n.get("ethernets"))
        .and_then(|e| e.as_mapping())
    else {
        return Ok(managed);
    };
    for (iface, def) in eths {
        let Some(iface) = iface.as_str() else { continue };
        let addrs: Vec<String> = def
            .get("addresses")
            .and_then(|a| a.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| parse_cidr(s).map(|(ip, p)| format!("{ip}/{p}")))
                    .collect()
            })
            .unwrap_or_default();
        if !addrs.is_empty() {
            managed.insert(iface.to_string(), addrs);
        }
    }
    Ok(managed)
}

/// Render [`NETPLAN_PATH`]. `None` when nothing is managed: the caller then
/// **removes the file** rather than writing an empty `ethernets:` — an absent
/// file is unambiguous for every netplan version, an empty mapping is not
/// guaranteed to be.
///
/// No `dhcp4`, `gateway` or `routes` keys: the interface's own definition
/// (another file) keeps those, netplan merges the address lists.
pub fn render_netplan(managed: &Managed, with_renderer: bool) -> Option<String> {
    let mut out = String::from(NETPLAN_HEADER);
    out.push_str("network:\n  version: 2\n");
    if with_renderer {
        out.push_str("  renderer: networkd\n");
    }
    out.push_str("  ethernets:\n");
    let mut any = false;
    for (iface, addrs) in managed {
        if addrs.is_empty() {
            continue;
        }
        any = true;
        out.push_str(&format!("    {iface}:\n      addresses:\n"));
        for a in addrs {
            out.push_str(&format!("        - \"{a}\"\n"));
        }
    }
    any.then_some(out)
}

/// The netplan definition ID our addresses must be filed under for `iface`.
///
/// netplan merges files **by definition ID**, not by kernel name. If the
/// interface is defined as `lan: {match: {macaddress: …}, set-name: eth0}`
/// and we wrote `eth0:`, networkd would get two `.network` files for the same
/// link and the lexically first (ours, `10-netplan-eth0`) would win at boot —
/// the link would keep only our /32s and lose its own addresses and gateway.
/// So: scan the other files (`files`, already in lexical order, ours
/// excluded) for an `ethernets` definition whose ID equals `iface`, or whose
/// `set-name` or `match.name` equals it exactly (globs ignored), or whose
/// `match.macaddress` equals `mac` (case-insensitive). First match wins.
/// `None` when no file defines the interface: the caller refuses, because a
/// bare definition of our own could take the link over at reboot (another
/// renderer, or networkd picking our lone .network file). Unparseable files
/// are skipped.
pub fn resolve_definition_id(files: &[(String, String)], iface: &str, mac: Option<&str>) -> Option<String> {
    let mac = mac.map(|m| m.trim().to_ascii_lowercase()).filter(|m| !m.is_empty());
    for (_, text) in files {
        let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else { continue };
        let Some(eths) = doc
            .get("network")
            .and_then(|n| n.get("ethernets"))
            .and_then(|e| e.as_mapping())
        else {
            continue;
        };
        for (id, def) in eths {
            let Some(id) = id.as_str() else { continue };
            let set_name = def.get("set-name").and_then(|v| v.as_str());
            let m = def.get("match");
            let match_name = m.and_then(|m| m.get("name")).and_then(|v| v.as_str());
            let match_mac = m
                .and_then(|m| m.get("macaddress"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase());
            let hit = id == iface
                || set_name == Some(iface)
                || match_name == Some(iface)
                || (mac.is_some() && match_mac.is_some() && match_mac == mac);
            if hit {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Whether our file may say `renderer: networkd`: only when every other
/// file's global renderer, and every ethernet definition's own renderer, is
/// absent or `networkd`. Otherwise the key is omitted (netplan then keeps
/// whatever the interface's own definition chose).
pub fn renderer_networkd_ok(files: &[(String, String)]) -> bool {
    let ok = |v: Option<&serde_yaml_ng::Value>| v.and_then(|r| r.as_str()).is_none_or(|r| r == "networkd");
    files.iter().all(|(_, text)| {
        let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else { return true };
        let Some(net) = doc.get("network") else { return true };
        if !ok(net.get("renderer")) {
            return false;
        }
        net.get("ethernets")
            .and_then(|e| e.as_mapping())
            .is_none_or(|eths| eths.values().all(|d| ok(d.get("renderer"))))
    })
}

/// Add `ip/prefix` under `iface`. Any previous entry for the same IP (on any
/// interface) is replaced, so the file never lists one address twice.
pub fn managed_add(managed: &mut Managed, iface: &str, ip: Ipv4Addr, prefix: u8) {
    managed_remove(managed, ip);
    let list = managed.entry(iface.to_string()).or_default();
    list.push(format!("{ip}/{prefix}"));
    list.sort_by_key(|c| parse_cidr(c).map(|(ip, _)| ip));
}

/// Remove `ip` wherever it is. Returns whether it was present. Interfaces left
/// with no address disappear from the map.
pub fn managed_remove(managed: &mut Managed, ip: Ipv4Addr) -> bool {
    let mut found = false;
    for addrs in managed.values_mut() {
        let before = addrs.len();
        addrs.retain(|c| parse_cidr(c).map(|(a, _)| a) != Some(ip));
        found |= addrs.len() != before;
    }
    managed.retain(|_, v| !v.is_empty());
    found
}

/// Where `ip` is managed: `(interface, prefix)`.
pub fn managed_find(managed: &Managed, ip: Ipv4Addr) -> Option<(String, u8)> {
    managed.iter().find_map(|(iface, addrs)| {
        addrs.iter().find_map(|c| match parse_cidr(c) {
            Some((a, p)) if a == ip => Some((iface.clone(), p)),
            _ => None,
        })
    })
}

/// Why `DELETE /system/ips/{ip}` must refuse (409), or `None` when allowed:
/// never the primary, never an address the panel did not add.
pub fn delete_refusal(ip: Ipv4Addr, primary: Option<Ipv4Addr>, managed: &Managed) -> Option<&'static str> {
    if primary == Some(ip) {
        return Some("The server's primary IP cannot be removed");
    }
    if managed_find(managed, ip).is_none() {
        return Some(
            "This IP was not added by the panel (absent from 60-dockpanel.yaml); it is not removed from the system",
        );
    }
    None
}

// ── System access ───────────────────────────────────────────────────────

/// Every global IPv4 on the host (container interfaces excluded).
pub async fn host_addrs() -> Result<Vec<HostAddr>, String> {
    let out = safe_command("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()
        .await
        .map_err(|e| format!("failed to run ip addr: {e}"))?;
    if !out.status.success() {
        return Err(format!("ip addr failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(parse_ip_addr_output(&String::from_utf8_lossy(&out.stdout)))
}

/// Blocking sibling of [`host_addrs`], for the (synchronous) vhost renderer.
pub fn host_addrs_sync() -> Result<Vec<HostAddr>, String> {
    let out = safe_command_sync("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()
        .map_err(|e| format!("failed to run ip addr: {e}"))?;
    if !out.status.success() {
        return Err(format!("ip addr failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(parse_ip_addr_output(&String::from_utf8_lossy(&out.stdout)))
}

/// The primary IP: the source address of the default route, the same value
/// the vhost renderer binds to when no explicit IP is given.
pub fn primary_ip() -> Option<Ipv4Addr> {
    crate::services::nginx::detect_bind_ip().parse().ok()
}

/// Device of the default IPv4 route.
pub async fn default_route_iface() -> Option<String> {
    let out = safe_command("ip")
        .args(["-o", "-4", "route", "show", "default"])
        .output()
        .await
        .ok()?;
    parse_default_route_dev(&String::from_utf8_lossy(&out.stdout))
}

/// Names of the host's network links, read from `/sys/class/net`.
pub fn link_names() -> Vec<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Raw content of [`NETPLAN_PATH`]; `None` when the file does not exist.
pub fn read_netplan_raw() -> Result<Option<String>, String> {
    match std::fs::read_to_string(NETPLAN_PATH) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {NETPLAN_PATH}: {e}")),
    }
}

/// Managed addresses currently persisted.
pub fn read_managed() -> Result<Managed, String> {
    parse_netplan(&read_netplan_raw()?.unwrap_or_default())
}

/// Every `/etc/netplan/*.yaml` except ours, in lexical order (netplan's own
/// order), as `(file name, content)`. Unreadable files are skipped.
pub fn foreign_netplan_files() -> Vec<(String, String)> {
    let ours = std::path::Path::new(NETPLAN_PATH).file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut names: Vec<String> = std::fs::read_dir("/etc/netplan")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".yaml") && n != ours)
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
        .into_iter()
        .filter_map(|n| std::fs::read_to_string(format!("/etc/netplan/{n}")).ok().map(|t| (n, t)))
        .collect()
}

/// MAC address of a link, from `/sys/class/net/<iface>/address`.
pub fn iface_mac(iface: &str) -> Option<String> {
    if !is_valid_iface_name(iface) {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// [`resolve_definition_id`] against the live `/etc/netplan` and `/sys`.
pub fn definition_id_for(iface: &str) -> Option<String> {
    resolve_definition_id(&foreign_netplan_files(), iface, iface_mac(iface).as_deref())
}

/// [`render_netplan`] with the renderer decision taken from the live files.
pub fn render_netplan_for_host(managed: &Managed) -> Option<String> {
    render_netplan(managed, renderer_networkd_ok(&foreign_netplan_files()))
}

async fn run_unsandboxed(binary: &str, args: &[&str]) -> Result<(), String> {
    let out = safe_command_unsandboxed(binary, &[])
        .args(args)
        .output()
        .await
        .map_err(|e| format!("could not run {binary}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{binary} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Put `content` at [`NETPLAN_PATH`] (mode 600, root:root), or remove the
/// file when `content` is `None`. Atomic: installed under a `.tmp` name
/// (which netplan ignores — it only reads `*.yaml`) then renamed.
pub async fn write_netplan_raw(content: Option<&str>) -> Result<(), String> {
    let Some(content) = content else {
        return run_unsandboxed("rm", &["-f", NETPLAN_PATH]).await;
    };
    let staging = format!("/var/lib/dockpanel/.netplan-dockpanel.{}", uuid::Uuid::new_v4().simple());
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|e| format!("could not stage the netplan file: {e}"))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("could not stage the netplan file: {e}"))?;
    }
    let tmp = format!("{NETPLAN_PATH}.tmp");
    let installed = run_unsandboxed(
        "install",
        &["-D", "-m", "600", "-o", "root", "-g", "root", &staging, &tmp],
    )
    .await;
    let _ = std::fs::remove_file(&staging);
    installed?;
    if let Err(e) = run_unsandboxed("mv", &["-f", &tmp, NETPLAN_PATH]).await {
        let _ = run_unsandboxed("rm", &["-f", &tmp]).await;
        return Err(e);
    }
    Ok(())
}

/// `netplan generate` — validates every file of `/etc/netplan` and renders the
/// backend config under `/run`, without applying anything. If `netplan` is not
/// installed at all (non-netplan distro) this is an error: the address would
/// not survive a reboot and the caller must not report success.
pub async fn netplan_generate() -> Result<(), String> {
    run_unsandboxed("netplan", &["generate"]).await
}

/// `ip addr add|del <ip>/<prefix> dev <iface>` (separate arguments, no shell).
pub async fn ip_addr(op: &str, ip: Ipv4Addr, prefix: u8, iface: &str) -> Result<(), String> {
    let cidr = format!("{ip}/{prefix}");
    let out = safe_command("ip")
        .args(["addr", op, &cidr, "dev", iface])
        .output()
        .await
        .map_err(|e| format!("failed to run ip addr {op}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ip addr {op} {cidr} dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Where systemd-resolved lists the real upstream servers (the stub file
/// `/etc/resolv.conf` only names 127.0.0.53).
const UPSTREAM_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";

/// Upstream nameservers from a resolv.conf, skipping loopback stubs.
pub fn upstream_nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver")).then(|| it.next()).flatten()
        })
        .filter(|ns| ns.parse::<std::net::IpAddr>().is_ok_and(|a| !a.is_loopback()))
        .map(str::to_string)
        .collect()
}

/// Reverse DNS of `ip` as the outside world sees it. `None` when there is no
/// PTR (Postfix then keeps `$myhostname` as HELO).
///
/// The local stub (systemd-resolved, 127.0.0.53) must NOT be asked: it
/// synthesizes the machine's own hostname for every address configured on
/// it, so each IP of the server would "have" the local hostname as PTR and
/// that would become its HELO. `dig` therefore asks the upstream servers from
/// [`UPSTREAM_RESOLV_CONF`] directly (in order), and falls back to the
/// default resolver only when that file is absent (no systemd-resolved).
/// `getent` is not used for the same reason (it goes through the stub and
/// `/etc/hosts`).
pub async fn ptr_lookup(ip: Ipv4Addr) -> Option<String> {
    let ip_s = ip.to_string();
    let servers = match tokio::fs::read_to_string(UPSTREAM_RESOLV_CONF).await {
        Ok(t) => upstream_nameservers(&t).into_iter().map(Some).collect::<Vec<_>>(),
        Err(_) => vec![None],
    };
    let timeout = std::time::Duration::from_secs(8);
    for server in servers {
        let mut cmd = safe_command("dig");
        cmd.args(["+short", "+time=3", "+tries=2", "-x", &ip_s]);
        if let Some(ns) = &server {
            cmd.arg(format!("@{ns}"));
        }
        match tokio::time::timeout(timeout, cmd.output()).await {
            // A server that answered (even "no PTR") is authoritative enough.
            Ok(Ok(out)) if out.status.success() => return parse_dig_ptr(&String::from_utf8_lossy(&out.stdout)),
            Ok(Ok(_)) => tracing::warn!("dig -x {ip} via {server:?} failed, trying the next server"),
            Ok(Err(e)) => {
                tracing::warn!("dig -x {ip} could not run: {e}");
                return None;
            }
            Err(_) => tracing::warn!("dig -x {ip} via {server:?} timed out"),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    const IP_OUT: &str = "\
2: eth0    inet 192.168.250.10/24 brd 192.168.250.255 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.250.11/24 brd 192.168.250.255 scope global secondary eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.250.13/32 scope global eth0\\       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
4: br-1a2b3c    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-1a2b3c\\       valid_lft forever preferred_lft forever
5: ens4@if9    inet 10.0.0.2/8 scope global ens4\\       valid_lft forever preferred_lft forever
";

    #[test]
    fn ip_addr_output_is_parsed_and_container_bridges_dropped() {
        let addrs = parse_ip_addr_output(IP_OUT);
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], HostAddr { ip: ip("192.168.250.10"), prefix: 24, interface: "eth0".into() });
        assert_eq!(addrs[2].prefix, 32);
        assert_eq!(addrs[3].interface, "ens4");
        assert!(addrs.iter().all(|a| a.interface != "docker0" && !a.interface.starts_with("br-")));
    }

    #[test]
    fn default_route_device() {
        assert_eq!(
            parse_default_route_dev("default via 192.168.250.1 dev eth0 proto static metric 100\n"),
            Some("eth0".into())
        );
        assert_eq!(parse_default_route_dev(""), None);
    }

    #[test]
    fn interface_names() {
        assert!(is_valid_iface_name("eth0"));
        assert!(is_valid_iface_name("ens3.100"));
        assert!(is_valid_iface_name("enp0s31f6"));
        assert!(!is_valid_iface_name(""));
        assert!(!is_valid_iface_name("."));
        assert!(!is_valid_iface_name(".."));
        assert!(!is_valid_iface_name("eth0;reboot"));
        assert!(!is_valid_iface_name("eth0 dev lo"));
        assert!(!is_valid_iface_name("a234567890123456"));
    }

    #[test]
    fn unusable_addresses_are_refused() {
        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1", "0.1.2.3", "240.0.0.1"] {
            assert!(validate_new_ip(ip(bad)).is_err(), "{bad} accepted");
        }
        for good in ["192.0.2.107", "192.168.250.13", "10.0.0.1"] {
            assert!(validate_new_ip(ip(good)).is_ok(), "{good} refused");
        }
    }

    #[test]
    fn ptr_parsing() {
        assert_eq!(parse_dig_ptr("mail2.Example.fr.\n"), Some("mail2.example.fr".into()));
        assert_eq!(parse_dig_ptr(""), None);
        assert_eq!(parse_dig_ptr(";; connection timed out; no servers could be reached\n"), None);
        assert_eq!(
            upstream_nameservers(
                "# x\nnameserver 127.0.0.53\nnameserver 1.1.1.1\nnameserver ::1\nnameserver 2001:4860:4860::8888\nsearch lan\n"
            ),
            vec!["1.1.1.1".to_string(), "2001:4860:4860::8888".to_string()]
        );
        assert!(upstream_nameservers("nameserver 127.0.0.53\n").is_empty());
        assert!(is_valid_hostname("mail.example.fr"));
        assert!(!is_valid_hostname("-bad.example"));
        assert!(!is_valid_hostname("bad..example"));
        assert!(!is_valid_hostname("a b"));
        assert!(!is_valid_hostname("x\n-o smtpd_milters=evil"));
    }

    #[test]
    fn netplan_add_renders_stable_file() {
        let mut m = Managed::new();
        managed_add(&mut m, "eth0", ip("192.168.250.14"), 32);
        managed_add(&mut m, "eth0", ip("192.168.250.13"), 32);
        let text = render_netplan(&m, true).unwrap();
        assert!(text.starts_with("# Added by DockPanel"));
        assert!(text.contains("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n      addresses:\n        - \"192.168.250.13/32\"\n        - \"192.168.250.14/32\"\n"));
        // Round trip.
        assert_eq!(parse_netplan(&text).unwrap(), m);
        // Adding the same IP again (even with another prefix/iface) never duplicates it.
        managed_add(&mut m, "eth1", ip("192.168.250.13"), 24);
        assert_eq!(managed_find(&m, ip("192.168.250.13")), Some(("eth1".into(), 24)));
        let text2 = render_netplan(&m, true).unwrap();
        assert_eq!(text2.matches("192.168.250.13").count(), 1);
    }

    #[test]
    fn netplan_remove_and_empty() {
        let mut m = Managed::new();
        managed_add(&mut m, "eth0", ip("192.168.250.13"), 32);
        assert!(!managed_remove(&mut m, ip("192.168.250.99")));
        assert!(managed_remove(&mut m, ip("192.168.250.13")));
        assert!(m.is_empty());
        // Nothing managed → no file (the caller removes it).
        assert_eq!(render_netplan(&m, true), None);
        assert!(parse_netplan("").unwrap().is_empty());
        assert!(parse_netplan("network:\n  version: 2\n").unwrap().is_empty());
    }

    #[test]
    fn delete_refuses_primary_and_unmanaged() {
        let mut m = Managed::new();
        managed_add(&mut m, "eth0", ip("192.168.250.13"), 32);
        let primary = Some(ip("192.168.250.10"));
        // Primary: refused even if it somehow appeared in our file.
        assert!(delete_refusal(ip("192.168.250.10"), primary, &m).is_some());
        let mut with_primary = m.clone();
        managed_add(&mut with_primary, "eth0", ip("192.168.250.10"), 24);
        assert!(delete_refusal(ip("192.168.250.10"), primary, &with_primary).is_some());
        // Unmanaged (installer / cloud-init / Hestia address): refused.
        assert!(delete_refusal(ip("192.168.250.11"), primary, &m).is_some());
        // Managed: allowed, also when the primary is unknown.
        assert_eq!(delete_refusal(ip("192.168.250.13"), primary, &m), None);
        assert_eq!(delete_refusal(ip("192.168.250.13"), None, &m), None);
    }

    #[test]
    fn netplan_parses_foreign_shapes() {
        // Hestia-style file, unquoted addresses, other keys ignored.
        let text = "network:\n  version: 2\n  ethernets:\n    ens3:\n      dhcp4: false\n      addresses:\n        - 192.0.2.107/32\n        - 192.0.2.108/32\n";
        let m = parse_netplan(text).unwrap();
        assert_eq!(m["ens3"], vec!["192.0.2.107/32".to_string(), "192.0.2.108/32".to_string()]);
        assert_eq!(managed_find(&m, ip("192.0.2.108")), Some(("ens3".into(), 32)));
        assert!(parse_netplan("network: [unclosed").is_err());
    }

    // ── definition ID: the key netplan merges on ───────────────────────

    fn files(list: &[&str]) -> Vec<(String, String)> {
        list.iter().enumerate().map(|(i, t)| (format!("{i:02}.yaml"), t.to_string())).collect()
    }

    /// The lab VM, as the Ubuntu autoinstaller writes it.
    const LAB: &str = "network:\n  version: 2\n  ethernets:\n    lan:\n      match:\n        macaddress: \"00:15:5d:fa:00:10\"\n      set-name: eth0\n      addresses:\n        - 192.168.250.10/24\n        - 192.168.250.11/24\n      routes:\n        - to: default\n          via: 192.168.250.1\n";
    /// OVH/cloud-init style (prod).
    const PROD: &str = "network:\n    version: 2\n    ethernets:\n        ens3:\n            dhcp4: true\n            match:\n                macaddress: fa:16:3e:aa:bb:cc\n            set-name: ens3\n";

    #[test]
    fn definition_id_lab_matches_by_mac_and_set_name() {
        // By set-name.
        assert_eq!(resolve_definition_id(&files(&[LAB]), "eth0", None).as_deref(), Some("lan"));
        // By MAC alone (case-insensitive), even if set-name differed.
        let renamed = LAB.replace("set-name: eth0", "set-name: wan0");
        assert_eq!(resolve_definition_id(&files(&[&renamed]), "eth0", Some("00:15:5D:FA:00:10")).as_deref(), Some("lan"));
    }

    #[test]
    fn definition_id_prod_and_plain_key() {
        assert_eq!(resolve_definition_id(&files(&[PROD]), "ens3", Some("fa:16:3e:aa:bb:cc")).as_deref(), Some("ens3"));
        let plain = "network:\n  version: 2\n  ethernets:\n    enp1s0:\n      dhcp4: true\n";
        assert_eq!(resolve_definition_id(&files(&[plain]), "enp1s0", None).as_deref(), Some("enp1s0"));
        // match.name exact counts, globs do not.
        let by_name = "network:\n  ethernets:\n    uplink:\n      match:\n        name: ens5\n";
        assert_eq!(resolve_definition_id(&files(&[by_name]), "ens5", None).as_deref(), Some("uplink"));
        let glob = "network:\n  ethernets:\n    any:\n      match:\n        name: \"en*\"\n";
        assert_eq!(resolve_definition_id(&files(&[glob]), "ens5", None), None);
    }

    #[test]
    fn definition_id_first_file_wins_and_fallback() {
        let other = "network:\n  ethernets:\n    second:\n      set-name: eth0\n";
        assert_eq!(resolve_definition_id(&files(&[LAB, other]), "eth0", None).as_deref(), Some("lan"));
        assert_eq!(resolve_definition_id(&files(&[other, LAB]), "eth0", None).as_deref(), Some("second"));
        // Nothing matches (or broken YAML) → None: the add is refused.
        assert_eq!(resolve_definition_id(&files(&[PROD, "network: [x"]), "eth1", Some("00:00:00:00:00:01")), None);
        assert_eq!(resolve_definition_id(&[], "eth0", None), None);
    }

    #[test]
    fn renderer_only_when_everything_is_networkd() {
        assert!(renderer_networkd_ok(&files(&[LAB, PROD])));
        assert!(renderer_networkd_ok(&files(&["network:\n  renderer: networkd\n  ethernets: {}\n"])));
        assert!(!renderer_networkd_ok(&files(&[LAB, "network:\n  renderer: NetworkManager\n"])));
        assert!(!renderer_networkd_ok(&files(&["network:\n  ethernets:\n    e:\n      renderer: NetworkManager\n"])));
        let mut m = Managed::new();
        managed_add(&mut m, "lan", ip("192.168.250.13"), 32);
        let with = render_netplan(&m, true).unwrap();
        let without = render_netplan(&m, false).unwrap();
        assert!(with.contains("  renderer: networkd\n"));
        assert!(!without.contains("renderer"));
        // Only addresses under the existing ID: no match/set-name copied.
        assert!(with.contains("    lan:\n      addresses:\n        - \"192.168.250.13/32\"\n"));
        assert!(!with.contains("set-name") && !with.contains("match"));
    }
}
