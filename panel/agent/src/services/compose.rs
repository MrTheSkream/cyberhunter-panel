//! Compose-stack deployment.
//!
//! This is not `docker compose`. Each service is created directly through the
//! Docker API so the same sandboxing the panel applies to template apps
//! (`no-new-privileges`, `cap_drop: ALL`, a confined bind prefix) applies here
//! too. What that hand-rolled path has to reproduce deliberately is everything
//! `docker compose` would have done for free - and until v2.54.0 it reproduced
//! almost none of it:
//!
//! * **A network.** Services were created with no `networking_config` at all, so
//!   every one landed on the default bridge, where container-name DNS does not
//!   exist. `postgresql://app:pw@database:5432` could not resolve, and every
//!   multi-service package the panel ships died on boot. A stack now gets its
//!   own bridge and each service is attached under its compose service key as a
//!   network alias - the name its siblings actually write in their config.
//! * **A namespace.** Container and volume names came straight off the service
//!   key, so the `db` service of three different packages all wanted
//!   `dockpanel-compose-db` and the second package to be deployed failed on a
//!   name conflict. Both are now scoped by stack.
//! * **`command`, `depends_on` and long-form `ports`.** All three were parsed
//!   away silently by a struct that did not declare them, which turned a
//!   `messenger:consume` worker into a second copy of the web server.
//!
//! A stack whose services cannot see each other looks exactly like a crashing
//! image, which is why this went out believing itself healthy: `deploy_service`
//! reported `running` on the strength of `create` + `start` returning `Ok`.
//! It now waits for the container to still be up and hands back the log tail
//! when it is not.

use bollard::container::{
    Config, CreateContainerOptions, LogOutput, LogsOptions, NetworkingConfig, StartContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::EndpointSettings;
use bollard::network::CreateNetworkOptions;
use bollard::Docker;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio_stream::StreamExt;

/// Parsed docker-compose service definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeService {
    /// The compose service key (`services:` map key). This - not the container
    /// name - is what sibling services resolve, so it is registered as a
    /// network alias and must survive parsing intact.
    pub key: String,
    /// The Docker container name. Scoped by stack so two packages that both
    /// define a `db` service can coexist on one host.
    pub name: String,
    pub image: String,
    pub ports: Vec<PortMapping>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<String>,
    pub restart: String,
    /// Names this service answers to on the stack network.
    pub aliases: Vec<String>,
    /// `command:` override, in exec form. `None` keeps the image's own CMD.
    pub command: Option<Vec<String>>,
    /// Service keys this one declares a dependency on - used for start order.
    pub depends_on: Vec<String>,
    /// Author-supplied labels. `dockpanel.*` keys are stripped during parsing:
    /// the panel's own labels decide what is managed and which stack a
    /// container belongs to, and a compose file must not be able to claim
    /// either. Everything else is passed through, which is how a pasted Traefik
    /// label block reaches Docker.
    pub labels: HashMap<String, String>,
    /// Whether the compose file declared `user:`, `healthcheck:` or
    /// `entrypoint:` for this service - this deployer has no field for any
    /// of the three, so they are read here ONLY to say so; `deploy_service`
    /// silently ignores them same as before. `compose_validate` is the
    /// reader: a stack that says "valid" while quietly dropping a directive
    /// the author wrote is the honesty gap these three exist to close.
    /// [[project_dockpanel_tech_debt_p185]] carry I.
    pub user_ignored: bool,
    pub healthcheck_ignored: bool,
    pub entrypoint_ignored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host: u16,
    pub container: u16,
    pub protocol: String,
    /// Loopback address the port is published on, without brackets.
    #[serde(default = "default_host_ip")]
    pub host_ip: String,
}

/// Where a mapping that names no address is published.
const DEFAULT_HOST_IP: &str = "127.0.0.1";

fn default_host_ip() -> String {
    DEFAULT_HOST_IP.to_string()
}

#[derive(Debug, Serialize)]
pub struct ComposeDeployResult {
    pub services: Vec<ServiceDeployResult>,
    /// The network every service was attached to, so callers can report it.
    pub network: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceDeployResult {
    pub name: String,
    pub container_id: String,
    pub status: String,
    pub error: Option<String>,
}

/// Raw docker-compose YAML structure (partial - covers common fields).
///
/// `BTreeMap`, not `HashMap`: iteration order over a `HashMap` is randomised
/// per process, so the same YAML deployed twice used to start its services in a
/// different order each time.
#[derive(Deserialize)]
struct ComposeFile {
    services: Option<BTreeMap<String, ServiceDef>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ServiceDef {
    image: Option<String>,
    ports: Option<Vec<serde_yaml_ng::Value>>,
    environment: Option<EnvironmentDef>,
    volumes: Option<Vec<String>>,
    restart: Option<String>,
    container_name: Option<String>,
    command: Option<CommandDef>,
    depends_on: Option<DependsOnDef>,
    labels: Option<LabelsDef>,
    // Dangerous fields - parsed so we can explicitly reject them
    privileged: Option<bool>,
    network_mode: Option<String>,
    pid: Option<String>,
    ipc: Option<String>,
    cap_add: Option<Vec<String>>,
    devices: Option<Vec<String>>,
    security_opt: Option<Vec<String>>,
    // Read-only-to-warn: this deployer has no field for any of these three,
    // so `deploy_service` never sees them - they exist here purely so
    // `compose_validate` can tell the author their compose file's directive
    // will be silently dropped, rather than saying "valid" over it.
    user: Option<serde_yaml_ng::Value>,
    healthcheck: Option<serde_yaml_ng::Value>,
    entrypoint: Option<serde_yaml_ng::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EnvironmentDef {
    Map(HashMap<String, serde_yaml_ng::Value>),
    List(Vec<String>),
}

impl Default for EnvironmentDef {
    fn default() -> Self {
        EnvironmentDef::Map(HashMap::new())
    }
}

/// `command:` accepts a shell string or an exec-form list.
#[derive(Deserialize)]
#[serde(untagged)]
enum CommandDef {
    Shell(String),
    Exec(Vec<String>),
}

/// `depends_on:` accepts a plain list or the long form with conditions. Only
/// the keys matter here - the conditions describe health gates this deployer
/// does not implement, and claiming otherwise would be worse than ignoring them.
#[derive(Deserialize)]
#[serde(untagged)]
enum DependsOnDef {
    List(Vec<String>),
    Map(BTreeMap<String, serde_yaml_ng::Value>),
}

/// `labels:` accepts a map or a list of `key=value` strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum LabelsDef {
    Map(BTreeMap<String, serde_yaml_ng::Value>),
    List(Vec<String>),
}

/// The Docker network a stack's services share.
pub fn stack_network_name(stack_id: Option<&str>) -> String {
    format!("dockpanel-stack-{}", stack_scope(stack_id))
}

/// Short, filesystem- and DNS-safe scope token derived from the stack id.
pub(crate) fn stack_scope(stack_id: Option<&str>) -> String {
    match stack_id {
        Some(id) => {
            let cleaned: String = id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(12)
                .collect();
            if cleaned.is_empty() {
                "adhoc".to_string()
            } else {
                cleaned
            }
        }
        None => "adhoc".to_string(),
    }
}

/// Parse a docker-compose.yml string into a list of services.
///
/// `stack_id` scopes the container names. It is threaded through parsing rather
/// than applied at deploy time so the preview the operator approves names the
/// containers the deploy will actually create.
pub fn parse_compose(yaml: &str, stack_id: Option<&str>) -> Result<Vec<ComposeService>, String> {
    let compose: ComposeFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| format!("Invalid YAML: {e}"))?;

    let services = compose
        .services
        .ok_or("No 'services' key found in compose file")?;

    let scope = stack_scope(stack_id);
    let mut result = Vec::new();

    for (name, def) in &services {
        // Reject dangerous Docker options that could escape container isolation
        if def.privileged == Some(true) {
            return Err(format!("Service '{name}': privileged mode is not allowed"));
        }
        if let Some(ref mode) = def.network_mode {
            if mode == "host" || mode.starts_with("container:") {
                return Err(format!("Service '{name}': network_mode '{mode}' is not allowed"));
            }
        }
        if let Some(ref pid) = def.pid {
            if pid == "host" {
                return Err(format!("Service '{name}': pid mode 'host' is not allowed"));
            }
        }
        if let Some(ref ipc) = def.ipc {
            if ipc == "host" {
                return Err(format!("Service '{name}': ipc mode 'host' is not allowed"));
            }
        }
        if let Some(ref caps) = def.cap_add {
            let dangerous = ["SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN", "ALL"];
            for cap in caps {
                if dangerous.iter().any(|d| cap.to_uppercase() == *d) {
                    return Err(format!("Service '{name}': capability '{cap}' is not allowed"));
                }
            }
        }
        if def.devices.is_some() {
            return Err(format!("Service '{name}': device mounts are not allowed"));
        }
        // `security_opt` was parsed into ServiceDef but never read here - the
        // comment above claimed every dangerous field was "parsed so we can
        // explicitly reject them," which was true for every field but this
        // one. The backend's own `validate_compose_yaml` (routes/mod.rs)
        // already rejects the same shape before a request reaches the agent,
        // but the agent must not rely on that alone: it is a second machine
        // reachable over its own HTTP API, and a gap in either layer should
        // not depend on the other layer having no gap of its own. Same rule,
        // same wording, as the backend's check - `unconfined` disables
        // seccomp/AppArmor confinement entirely; `no-new-privileges:true`
        // (what this deployer sets by default, below) is unaffected.
        // [[project_dockpanel_tech_debt_p185]] carry I.
        if let Some(ref opts) = def.security_opt {
            for opt in opts {
                if opt.to_lowercase().contains("unconfined") {
                    return Err(format!("Service '{name}': security_opt '{opt}' is not allowed"));
                }
            }
        }

        let image = match &def.image {
            Some(img) => img.clone(),
            None => {
                // Skip services with build: context (we don't support building images)
                continue;
            }
        };

        // Parse ports
        let ports = parse_ports(name, &def.ports)?;

        // Parse environment
        let environment = match &def.environment {
            Some(EnvironmentDef::Map(map)) => map
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_yaml_ng::Value::String(s) => s.clone(),
                        serde_yaml_ng::Value::Number(n) => n.to_string(),
                        serde_yaml_ng::Value::Bool(b) => b.to_string(),
                        _ => format!("{v:?}"),
                    };
                    (k.clone(), val)
                })
                .collect(),
            Some(EnvironmentDef::List(list)) => list
                .iter()
                .filter_map(|entry| {
                    let (k, v) = entry.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect(),
            None => HashMap::new(),
        };

        let volumes = def.volumes.clone().unwrap_or_default();
        let restart = def.restart.clone().unwrap_or_else(|| "no".into());

        // The container name is ours; the names the *stack* resolves are the
        // service key and whatever `container_name` the author wrote. Honouring
        // an author-chosen container_name as the real Docker name is what let
        // one stack collide with another, so it becomes an alias instead.
        let container_name = format!("dockpanel-compose-{scope}-{name}");
        let mut aliases = vec![name.clone()];
        if let Some(ref explicit) = def.container_name {
            if explicit != name {
                aliases.push(explicit.clone());
            }
        }

        let command = match &def.command {
            Some(CommandDef::Exec(list)) => Some(list.clone()),
            Some(CommandDef::Shell(s)) => Some(split_shell_command(s)),
            None => None,
        };

        let depends_on = match &def.depends_on {
            Some(DependsOnDef::List(list)) => list.clone(),
            Some(DependsOnDef::Map(map)) => map.keys().cloned().collect(),
            None => Vec::new(),
        };

        // `dockpanel.*` is the panel's namespace. A compose file that could set
        // `dockpanel.managed` or `dockpanel.stack_id` would be able to hide a
        // container from the panel or attach it to somebody else's stack.
        let labels: HashMap<String, String> = match &def.labels {
            Some(LabelsDef::Map(map)) => map
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_yaml_ng::Value::String(s) => s.clone(),
                        serde_yaml_ng::Value::Number(n) => n.to_string(),
                        serde_yaml_ng::Value::Bool(b) => b.to_string(),
                        _ => String::new(),
                    };
                    (k.clone(), val)
                })
                .collect(),
            Some(LabelsDef::List(list)) => list
                .iter()
                .filter_map(|entry| {
                    let (k, v) = entry.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect(),
            None => HashMap::new(),
        };
        let labels: HashMap<String, String> = labels
            .into_iter()
            .filter(|(k, _)| !k.starts_with("dockpanel."))
            .collect();

        result.push(ComposeService {
            key: name.clone(),
            name: container_name,
            image,
            ports,
            environment,
            volumes,
            restart,
            aliases,
            command,
            depends_on,
            labels,
            user_ignored: def.user.is_some(),
            healthcheck_ignored: def.healthcheck.is_some(),
            entrypoint_ignored: def.entrypoint.is_some(),
        });
    }

    if result.is_empty() {
        return Err("No deployable services found (all services require build context?)".into());
    }

    check_published_ports(&result)?;

    Ok(order_by_dependencies(result))
}

/// Split a shell-form `command:` into argv, honouring simple quoting.
///
/// Compose hands a shell string to the image's entrypoint verbatim; the Docker
/// API wants argv. Anything with real shell syntax in it (pipes, redirection,
/// substitution) is passed through `sh -c` rather than mangled into words.
fn split_shell_command(cmd: &str) -> Vec<String> {
    if cmd.contains(['|', '>', '<', '&', ';', '$', '`']) {
        return vec!["sh".to_string(), "-c".to_string(), cmd.to_string()];
    }

    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for c in cmd.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Stable topological order over `depends_on`, so a database is created before
/// the service that connects to it.
///
/// Cycles and dangling references are not errors here - compose files in the
/// wild carry both, and refusing to deploy over one would be a worse outcome
/// than starting in declaration order. Anything unresolved is appended in the
/// order it was declared.
fn order_by_dependencies(services: Vec<ComposeService>) -> Vec<ComposeService> {
    let known: HashSet<&str> = services.iter().map(|s| s.key.as_str()).collect();
    let mut pending: Vec<&ComposeService> = services.iter().collect();
    let mut placed: HashSet<String> = HashSet::new();
    let mut order: Vec<String> = Vec::new();

    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|svc| {
            let ready = svc
                .depends_on
                .iter()
                .all(|d| !known.contains(d.as_str()) || placed.contains(d));
            if ready {
                placed.insert(svc.key.clone());
                order.push(svc.key.clone());
            }
            !ready
        });
        if pending.len() == before {
            // A cycle: emit the rest in declaration order and stop.
            for svc in &pending {
                order.push(svc.key.clone());
            }
            break;
        }
    }

    let mut by_key: BTreeMap<String, ComposeService> =
        services.into_iter().map(|s| (s.key.clone(), s)).collect();
    order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect()
}

/// The most host ports one compose file may publish. Docker runs a proxy per
/// published port, so a typo in a range must not become 60 000 processes.
const MAX_PUBLISHED_PORTS: usize = 1024;

/// Read a service's `ports:` into the mappings Docker will be asked to publish.
///
/// Every entry is either published exactly as written or refused here. Parsing
/// is what `validate`, `parse` and every deploy door share, so a refusal reaches
/// all of them; an entry skipped here is a service that deploys "successfully"
/// with a port nobody can reach.
///
/// Accepted: `container`, `host:container`, `ip:host:container`, `[ipv6]:host:container`,
/// each side optionally a range of equal length, an optional `/tcp`, `/udp` or `/sctp`,
/// and the long form (`target`, `published`, `host_ip`, `protocol`).
fn parse_ports(
    service: &str,
    ports_val: &Option<Vec<serde_yaml_ng::Value>>,
) -> Result<Vec<PortMapping>, String> {
    let ports = match ports_val {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };

    let mut result = Vec::new();

    for port in ports {
        let spec = match port {
            // Long form - `- target: 80` / `published: 8080` / `protocol: tcp`.
            // This is what `docker compose config` emits, so a file that has been
            // through any compose tooling arrives in this shape.
            serde_yaml_ng::Value::Mapping(map) => long_form_port(map),
            serde_yaml_ng::Value::String(s) => short_form_port(s),
            serde_yaml_ng::Value::Number(n) => short_form_port(&n.to_string()),
            _ => Err("is not a port mapping".to_string()),
        };
        let expanded = spec.and_then(PortSpec::expand).map_err(|reason| {
            format!("Service '{service}': port '{}' {reason}", port_label(port))
        })?;
        result.extend(expanded);
    }

    Ok(result)
}

/// One `ports:` entry, before its ranges are expanded.
struct PortSpec {
    host_ip: String,
    host: (u16, u16),
    container: (u16, u16),
    protocol: String,
}

impl PortSpec {
    fn expand(self) -> Result<Vec<PortMapping>, String> {
        let count = usize::from(self.host.1 - self.host.0) + 1;
        if count != usize::from(self.container.1 - self.container.0) + 1 {
            return Err(
                "must map the same number of ports on the host and in the container".to_string(),
            );
        }
        if count > MAX_PUBLISHED_PORTS {
            return Err(format!("publishes {count} ports, at most {MAX_PUBLISHED_PORTS} are allowed"));
        }
        Ok((self.host.0..=self.host.1)
            .zip(self.container.0..=self.container.1)
            .map(|(host, container)| PortMapping {
                host,
                container,
                protocol: self.protocol.clone(),
                host_ip: self.host_ip.clone(),
            })
            .collect())
    }
}

/// How an entry is named in a refusal: as the author wrote it.
fn port_label(port: &serde_yaml_ng::Value) -> String {
    match port {
        serde_yaml_ng::Value::String(s) => s.clone(),
        other => serde_yaml_ng::to_string(other)
            .map(|s| s.trim().replace('\n', ", "))
            .unwrap_or_else(|_| "?".to_string()),
    }
}

fn short_form_port(entry: &str) -> Result<PortSpec, String> {
    let (mapping, protocol) = match entry.rsplit_once('/') {
        Some((mapping, protocol)) => (mapping, protocol),
        None => (entry, "tcp"),
    };

    // A bracketed address is taken off first: its colons are not separators.
    let (bracketed, rest) = match mapping.strip_prefix('[') {
        Some(tail) => {
            let (ip, rest) = tail
                .split_once(']')
                .ok_or("has an IPv6 address with unbalanced brackets")?;
            let rest = rest
                .strip_prefix(':')
                .ok_or("must give a port after the bracketed IPv6 address")?;
            (Some(ip), rest)
        }
        None => (None, mapping),
    };

    let parts: Vec<&str> = rest.split(':').collect();
    let (ip, host, container) = match (bracketed, parts.as_slice()) {
        (Some(ip), [port]) => (Some(ip), *port, *port),
        (Some(ip), [host, container]) => (Some(ip), *host, *container),
        (None, [port]) => (None, *port, *port),
        // `127.0.0.1:8080` names an address and one port, not two ports.
        (None, [ip, port]) if ip.contains('.') => (Some(*ip), *port, *port),
        (None, [host, container]) => (None, *host, *container),
        (None, [ip, host, container]) => (Some(*ip), *host, *container),
        (None, _) => return Err("has an IPv6 address that must be written in brackets".to_string()),
        (Some(_), _) => return Err("has too many ':' separators".to_string()),
    };
    if host.is_empty() {
        return Err("has no host port, publishing on a random port is not supported".to_string());
    }

    Ok(PortSpec {
        host_ip: match ip {
            Some(ip) => loopback_address(ip)?,
            None => default_host_ip(),
        },
        host: port_range(host)?,
        container: port_range(container)?,
        protocol: port_protocol(protocol)?,
    })
}

fn long_form_port(map: &serde_yaml_ng::Mapping) -> Result<PortSpec, String> {
    let text = |key: &str| -> Result<Option<String>, String> {
        match map.get(serde_yaml_ng::Value::String(key.to_string())) {
            None | Some(serde_yaml_ng::Value::Null) => Ok(None),
            Some(serde_yaml_ng::Value::String(s)) => Ok(Some(s.clone())),
            Some(serde_yaml_ng::Value::Number(n)) => Ok(Some(n.to_string())),
            Some(_) => Err(format!("has an invalid '{key}' value")),
        }
    };

    let target = text("target")?.ok_or("has no 'target' container port")?;
    let published = text("published")?.unwrap_or_else(|| target.clone());
    Ok(PortSpec {
        host_ip: match text("host_ip")? {
            Some(ip) => loopback_address(&ip)?,
            None => default_host_ip(),
        },
        host: port_range(&published)?,
        container: port_range(&target)?,
        protocol: port_protocol(&text("protocol")?.unwrap_or_else(|| "tcp".to_string()))?,
    })
}

/// `8000` or `8000-8010`, as inclusive bounds.
fn port_range(text: &str) -> Result<(u16, u16), String> {
    let number = |n: &str| -> Result<u16, String> {
        n.parse::<u16>()
            .ok()
            .filter(|p| *p > 0 && n.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| format!("has '{n}' where a port between 1 and 65535 is required"))
    };
    match text.split_once('-') {
        None => number(text).map(|p| (p, p)),
        Some((first, last)) => {
            let (first, last) = (number(first)?, number(last)?);
            if first > last {
                return Err(format!("has the reversed range '{text}'"));
            }
            Ok((first, last))
        }
    }
}

fn port_protocol(protocol: &str) -> Result<String, String> {
    let lower = protocol.to_ascii_lowercase();
    if matches!(lower.as_str(), "tcp" | "udp" | "sctp") {
        Ok(lower)
    } else {
        Err(format!("has the unsupported protocol '{protocol}' (use tcp, udp or sctp)"))
    }
}

/// The address a mapping asked for, which has to be a loopback one.
///
/// Stacks are reached through the panel's reverse proxy, and Docker's published
/// ports bypass the host firewall. `0.0.0.0:80:80` used to be quietly narrowed
/// to `127.0.0.1`; honouring it would open the port to the internet, so it is
/// refused and the author is told what to write instead.
fn loopback_address(ip: &str) -> Result<String, String> {
    let addr: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("has the invalid address '{ip}'"))?;
    if !addr.is_loopback() {
        return Err(format!(
            "binds to '{ip}', which is not a loopback address. Stack ports are published on \
             127.0.0.1 or ::1 only: attach a domain to reach the service from outside"
        ));
    }
    Ok(addr.to_string())
}

/// Refuse what Docker could only fail on at start, once containers are running:
/// one host port claimed twice anywhere in the file.
fn check_published_ports(services: &[ComposeService]) -> Result<(), String> {
    let total: usize = services.iter().map(|s| s.ports.len()).sum();
    if total > MAX_PUBLISHED_PORTS {
        return Err(format!(
            "This compose file publishes {total} ports, at most {MAX_PUBLISHED_PORTS} are allowed"
        ));
    }

    let mut claimed: HashMap<(&str, u16, &str), &str> = HashMap::new();
    for svc in services {
        for pm in &svc.ports {
            let key = (pm.host_ip.as_str(), pm.host, pm.protocol.as_str());
            if let Some(owner) = claimed.insert(key, svc.key.as_str()) {
                return Err(format!(
                    "Service '{}': host port {}/{} on {} is already published by service '{owner}'",
                    svc.key, pm.host, pm.protocol, pm.host_ip
                ));
            }
        }
    }
    Ok(())
}

/// Docker's `PortBindings` and `ExposedPorts` for a service's mappings.
#[allow(clippy::type_complexity)]
fn port_bindings_for(
    ports: &[PortMapping],
) -> (
    HashMap<String, Option<Vec<bollard::service::PortBinding>>>,
    HashMap<String, HashMap<(), ()>>,
) {
    let mut port_bindings = HashMap::new();
    let mut exposed_ports = HashMap::new();
    for pm in ports {
        let container_port = format!("{}/{}", pm.container, pm.protocol);
        // One container port may be published on several addresses.
        port_bindings
            .entry(container_port.clone())
            .or_insert_with(|| Some(Vec::new()))
            .get_or_insert_with(Vec::new)
            .push(bollard::service::PortBinding {
                host_ip: Some(pm.host_ip.clone()),
                host_port: Some(pm.host.to_string()),
            });
        exposed_ports.insert(container_port, HashMap::new());
    }
    (port_bindings, exposed_ports)
}

/// The published port a domain should front when the request names none.
///
/// The vhost proxies to `127.0.0.1`, so a port published on another loopback
/// address is not one it can reach.
pub fn default_expose_port(services: &[ComposeService]) -> Option<u16> {
    services
        .iter()
        .flat_map(|s| &s.ports)
        .find(|p| p.host_ip == DEFAULT_HOST_IP)
        .map(|p| p.host)
}

/// Create the stack's bridge network if it does not already exist.
///
/// Labelled with the stack id so teardown can prove the network is ours before
/// removing it, in the shape [`crate::services::ownership`] applies to files.
pub(crate) async fn ensure_stack_network(docker: &Docker, network: &str, stack_id: Option<&str>) -> Result<(), String> {
    if docker.inspect_network::<String>(network, None).await.is_ok() {
        return Ok(());
    }

    let mut labels = HashMap::from([("dockpanel.managed", "true")]);
    if let Some(sid) = stack_id {
        labels.insert("dockpanel.stack_id", sid);
    }

    docker
        .create_network(CreateNetworkOptions {
            name: network,
            driver: "bridge",
            labels,
            ..Default::default()
        })
        .await
        .map_err(|e| format!("Failed to create stack network {network}: {e}"))?;

    tracing::info!("Created Docker network: {network}");
    Ok(())
}

/// Remove a stack's network once its containers are gone.
///
/// Best effort by design: Docker refuses to remove a network that still has
/// endpoints, which is the correct answer when something is still attached.
pub async fn remove_stack_network(stack_id: Option<&str>) {
    let network = stack_network_name(stack_id);
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(_) => return,
    };

    // Only remove a network this stack owns. A network we did not label is a
    // network we did not create.
    match docker.inspect_network::<String>(&network, None).await {
        Ok(info) => {
            let ours = info
                .labels
                .as_ref()
                .and_then(|l| l.get("dockpanel.managed"))
                .map(|v| v == "true")
                .unwrap_or(false);
            if !ours {
                tracing::warn!("Not removing network {network}: no dockpanel.managed label");
                return;
            }
        }
        Err(_) => return,
    }

    if let Err(e) = docker.remove_network(&network).await {
        tracing::warn!("Could not remove stack network {network}: {e}");
    } else {
        tracing::info!("Removed Docker network: {network}");
    }
}

/// Deploy all services from a parsed compose file.
/// If `stack_id` is provided, all containers get a `dockpanel.stack_id` label.
pub async fn deploy_compose(
    services: &[ComposeService],
    stack_id: Option<&str>,
) -> ComposeDeployResult {
    let network = stack_network_name(stack_id);

    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(e) => {
            return ComposeDeployResult {
                services: services
                    .iter()
                    .map(|s| ServiceDeployResult {
                        name: s.name.clone(),
                        container_id: String::new(),
                        status: "failed".into(),
                        error: Some(format!("Docker connect failed: {e}")),
                    })
                    .collect(),
                network,
            };
        }
    };

    if let Err(e) = ensure_stack_network(&docker, &network, stack_id).await {
        return ComposeDeployResult {
            services: services
                .iter()
                .map(|s| ServiceDeployResult {
                    name: s.name.clone(),
                    container_id: String::new(),
                    status: "failed".into(),
                    error: Some(e.clone()),
                })
                .collect(),
            network,
        };
    }

    let mut results = Vec::new();

    for svc in services {
        match deploy_service(&docker, svc, stack_id, &network).await {
            Ok(container_id) => {
                results.push(ServiceDeployResult {
                    name: svc.name.clone(),
                    container_id,
                    status: "running".into(),
                    error: None,
                });
            }
            Err(DeployFailure { container_id, error }) => {
                results.push(ServiceDeployResult {
                    name: svc.name.clone(),
                    container_id,
                    status: "failed".into(),
                    error: Some(error),
                });
            }
        }
    }

    ComposeDeployResult {
        services: results,
        network,
    }
}

/// A service that did not come up. `container_id` is populated when the
/// container was created but did not stay running, so the caller can still
/// point the operator at it.
struct DeployFailure {
    container_id: String,
    error: String,
}

impl From<String> for DeployFailure {
    fn from(error: String) -> Self {
        DeployFailure {
            container_id: String::new(),
            error,
        }
    }
}

/// Resolve a named volume to a stack-scoped one.
///
/// Compose namespaces volumes by project; this used to pass the bare name
/// through, so two stacks built from the same package silently shared one
/// database volume - and since each deploy mints a fresh password, the second
/// stack was handed credentials the existing cluster did not have.
///
/// A volume that already exists under the bare name is left alone. Renaming it
/// would not move the data, it would only hide it, and a stack that was working
/// before an upgrade must keep working after one.
async fn scoped_volume(docker: &Docker, scope: &str, vol: &str) -> String {
    let scoped = format!("{scope}_{vol}");
    if docker.inspect_volume(&scoped).await.is_ok() {
        return scoped;
    }
    if docker.inspect_volume(vol).await.is_ok() {
        tracing::info!("Reusing existing volume '{vol}' for this stack (not renaming - the data is in it)");
        return vol.to_string();
    }
    scoped
}

async fn deploy_service(
    docker: &Docker,
    svc: &ComposeService,
    stack_id: Option<&str>,
    network: &str,
) -> Result<String, DeployFailure> {
    // Pull image (with timeout to prevent hanging on Docker daemon issues)
    let mut pull_error: Option<String> = None;
    let pull_result = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        let mut pull = docker.create_image(
            Some(CreateImageOptions {
                from_image: svc.image.as_str(),
                ..Default::default()
            }),
            None,
            super::docker_apps::registry_credentials_for(&svc.image),
        );
        while let Some(result) = pull.next().await {
            if let Err(e) = result {
                // Keep the first pull error: `create_container` will fail with
                // "No such image", which points at the wrong thing.
                tracing::warn!("Image pull warning for {}: {e}", svc.image);
                if pull_error.is_none() {
                    pull_error = Some(e.to_string());
                }
            }
        }
    }).await;
    if pull_result.is_err() {
        return Err(format!("Image pull timed out for {}", svc.image).into());
    }

    // Build env vars
    let env_list: Vec<String> = svc
        .environment
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    // Port bindings
    let (port_bindings, exposed_ports) = port_bindings_for(&svc.ports);

    // Volume binds - validate that host paths are under the allowed prefix
    // and block mounting the Docker socket.
    let mut binds: Vec<String> = Vec::new();
    const ALLOWED_BIND_PREFIX: &str = "/var/lib/dockpanel/compose/";
    const BLOCKED_PATHS: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];
    let scope = stack_scope(stack_id);

    for vol in &svc.volumes {
        if !vol.contains(':') {
            // Shorthand `- /data`: compose would create an anonymous volume.
            // Passing it through as a bind is not possible and silently
            // dropping it loses the persistence the author asked for, so say so.
            tracing::warn!(
                "Service {}: volume '{}' has no host side - anonymous volumes are not supported, \
                 declare a named volume (e.g. 'data:{}') to persist it",
                svc.key,
                vol,
                vol
            );
            continue;
        }
        // Extract host path (everything before the first ':')
        let host_path = vol.split(':').next().unwrap_or("");

        // Named volumes (no leading / or .) - scope them to this stack.
        if !host_path.starts_with('/') && !host_path.starts_with('.') {
            let rest = &vol[host_path.len()..];
            let scoped = scoped_volume(docker, &scope, host_path).await;
            binds.push(format!("{scoped}{rest}"));
            continue;
        }

        // Resolve symlinks and canonicalize the path to prevent symlink-based escapes
        let resolved = std::fs::canonicalize(host_path)
            .map_err(|_| format!("Volume mount path does not exist or is inaccessible: {}", host_path))?;
        let resolved_str = resolved.to_string_lossy();

        // Block docker socket
        for blocked in BLOCKED_PATHS {
            if resolved_str == *blocked {
                return Err(format!(
                    "Blocked volume mount: {} is not allowed",
                    host_path
                ).into());
            }
        }

        // Only allow paths under the sanctioned prefix
        if !resolved_str.starts_with(ALLOWED_BIND_PREFIX) {
            return Err(format!(
                "Blocked volume mount: host path '{}' must be under {}",
                host_path, ALLOWED_BIND_PREFIX
            ).into());
        }

        // Reject path traversal attempts
        if host_path.contains("..") {
            return Err(format!(
                "Blocked volume mount: path traversal not allowed in '{}'",
                host_path
            ).into());
        }

        // TOCTOU fix: use the resolved (canonicalized) path in the actual mount,
        // not the original user-supplied path which could be a symlink.
        let container_path = vol.split(':').nth(1).unwrap_or("");
        let options = vol.split(':').nth(2);
        let mut bind = format!("{}:{}", resolved_str, container_path);
        if let Some(opts) = options {
            bind = format!("{}:{}", bind, opts);
        }
        binds.push(bind);
    }

    // Restart policy
    let restart_policy = match svc.restart.as_str() {
        "always" => bollard::service::RestartPolicyNameEnum::ALWAYS,
        "unless-stopped" => bollard::service::RestartPolicyNameEnum::UNLESS_STOPPED,
        "on-failure" => bollard::service::RestartPolicyNameEnum::ON_FAILURE,
        _ => bollard::service::RestartPolicyNameEnum::NO,
    };

    let host_config = bollard::service::HostConfig {
        port_bindings: if port_bindings.is_empty() {
            None
        } else {
            Some(port_bindings)
        },
        binds: if binds.is_empty() { None } else { Some(binds) },
        restart_policy: Some(bollard::service::RestartPolicy {
            name: Some(restart_policy),
            ..Default::default()
        }),
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        cap_drop: Some(vec!["ALL".to_string()]),
        cap_add: Some(vec![
            "CHOWN".to_string(),
            "SETUID".to_string(),
            "SETGID".to_string(),
            "NET_BIND_SERVICE".to_string(),
            "DAC_OVERRIDE".to_string(),
            "FOWNER".to_string(),
            "SETFCAP".to_string(),
        ]),
        ..Default::default()
    };

    // Attach to the stack network under the compose service key. Without this
    // the container lands on the default bridge, where the name its siblings
    // were configured with does not resolve.
    let mut endpoints = HashMap::new();
    endpoints.insert(
        network.to_string(),
        EndpointSettings {
            aliases: Some(svc.aliases.clone()),
            ..Default::default()
        },
    );

    let config = Config {
        image: Some(svc.image.clone()),
        cmd: svc.command.clone(),
        env: if env_list.is_empty() {
            None
        } else {
            Some(env_list)
        },
        exposed_ports: if exposed_ports.is_empty() {
            None
        } else {
            Some(exposed_ports)
        },
        host_config: Some(host_config),
        networking_config: Some(NetworkingConfig {
            endpoints_config: endpoints,
        }),
        labels: Some({
            // Author labels first, ours second: the panel's namespace wins even
            // if the filter above were ever loosened.
            let mut labels = svc.labels.clone();
            labels.extend([
                ("dockpanel.managed".to_string(), "true".to_string()),
                ("dockpanel.app.template".to_string(), "compose".to_string()),
                ("dockpanel.app.name".to_string(), svc.name.clone()),
                ("dockpanel.compose.service".to_string(), svc.key.clone()),
            ]);
            if let Some(sid) = stack_id {
                labels.insert("dockpanel.stack_id".to_string(), sid.to_string());
            }
            labels
        }),
        ..Default::default()
    };

    let container = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        docker.create_container(
            Some(CreateContainerOptions {
                name: svc.name.as_str(),
                platform: None,
            }),
            config,
        ),
    )
    .await
    .map_err(|_| DeployFailure::from(format!("Create container timed out for {}", svc.name)))?
    .map_err(|e| {
        let hint = pull_error
            .as_ref()
            .map(|p| format!(" (image pull reported: {p})"))
            .unwrap_or_default();
        DeployFailure::from(format!("Failed to create container {}: {e}{hint}", svc.name))
    })?;

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        docker.start_container(&container.id, None::<StartContainerOptions<String>>),
    )
    .await
    .map_err(|_| DeployFailure::from(format!("Start container timed out for {}", svc.name)))?
    .map_err(|e| DeployFailure {
        container_id: container.id.clone(),
        error: format!("Failed to start container {}: {e}", svc.name),
    })?;

    // `start` returning Ok means the process was launched, not that it lived.
    // A service that exits on a bad config or an unreachable dependency used to
    // be reported as "running" and the operator was told the stack deployed.
    confirm_running(docker, &container.id, &svc.key).await?;

    tracing::info!(
        "Compose service deployed: {} (key={}, image={}, network={})",
        svc.name,
        svc.key,
        svc.image,
        network
    );

    Ok(container.id)
}

/// Wait for a just-started container to still be up, and explain it if not.
///
/// Polls rather than sleeping a fixed interval: a healthy container passes on
/// the first check, and only a failing one pays the full wait.
async fn confirm_running(docker: &Docker, container_id: &str, key: &str) -> Result<(), DeployFailure> {
    const CHECKS: [u64; 4] = [500, 1500, 3000, 5000];
    let mut last_state = String::from("unknown");

    for (i, delay_ms) in CHECKS.iter().enumerate() {
        tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;

        let state = match docker.inspect_container(container_id, None).await {
            Ok(info) => info.state,
            Err(e) => {
                return Err(DeployFailure {
                    container_id: container_id.to_string(),
                    error: format!("Service '{key}' could not be inspected after start: {e}"),
                })
            }
        };

        let running = state.as_ref().and_then(|s| s.running).unwrap_or(false);
        if running {
            return Ok(());
        }

        last_state = state
            .as_ref()
            .and_then(|s| s.status.as_ref())
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "exited".to_string());

        let exit_code = state.as_ref().and_then(|s| s.exit_code).unwrap_or(0);

        // A container that is restarting may yet settle; one that has exited
        // for good will not, so stop waiting on it immediately.
        if last_state != "restarting" || i == CHECKS.len() - 1 {
            let logs = tail_logs(docker, container_id).await;
            return Err(DeployFailure {
                container_id: container_id.to_string(),
                error: format!(
                    "Service '{key}' started and then {last_state} (exit code {exit_code}). Last output:\n{logs}"
                ),
            });
        }
    }

    Err(DeployFailure {
        container_id: container_id.to_string(),
        error: format!("Service '{key}' did not stay running (state: {last_state})"),
    })
}

/// Last few lines of a container's output, for a failure message.
async fn tail_logs(docker: &Docker, container_id: &str) -> String {
    let mut stream = docker.logs(
        container_id,
        Some(LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: "20".to_string(),
            ..Default::default()
        }),
    );

    let mut out = String::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(LogOutput::StdOut { message })
            | Ok(LogOutput::StdErr { message })
            | Ok(LogOutput::Console { message }) => {
                out.push_str(&String::from_utf8_lossy(&message));
            }
            Ok(_) => {}
            Err(_) => break,
        }
        if out.len() > 4000 {
            break;
        }
    }

    if out.trim().is_empty() {
        "(no output)".to_string()
    } else {
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_SERVICE: &str = r#"
services:
  app:
    image: myapp:1
    depends_on:
      - database
    environment:
      DATABASE_URL: postgresql://app:pw@database:5432/app
    ports:
      - "8085:80"
  database:
    image: postgres:16-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
"#;

    #[test]
    fn service_key_is_kept_and_becomes_a_network_alias() {
        let services = parse_compose(TWO_SERVICE, Some("abc123def456")).unwrap();
        let db = services.iter().find(|s| s.key == "database").unwrap();
        // The alias is what `postgresql://...@database:5432` resolves against.
        assert!(db.aliases.contains(&"database".to_string()));
    }

    #[test]
    fn container_names_are_scoped_by_stack() {
        let a = parse_compose(TWO_SERVICE, Some("aaaaaaaa-1111")).unwrap();
        let b = parse_compose(TWO_SERVICE, Some("bbbbbbbb-2222")).unwrap();
        let name_a = &a.iter().find(|s| s.key == "database").unwrap().name;
        let name_b = &b.iter().find(|s| s.key == "database").unwrap().name;
        // Two stacks built from the same package must not want one name.
        assert_ne!(name_a, name_b);
        assert!(name_a.starts_with("dockpanel-compose-"));
    }

    #[test]
    fn networks_are_scoped_by_stack() {
        assert_ne!(
            stack_network_name(Some("aaaaaaaa-1111")),
            stack_network_name(Some("bbbbbbbb-2222"))
        );
    }

    #[test]
    fn an_author_chosen_container_name_becomes_an_alias_not_the_docker_name() {
        let yaml = r#"
services:
  web:
    image: nginx:alpine
    container_name: my-web
"#;
        let services = parse_compose(yaml, Some("abc123")).unwrap();
        let web = &services[0];
        assert_ne!(web.name, "my-web");
        assert!(web.aliases.contains(&"my-web".to_string()));
        assert!(web.aliases.contains(&"web".to_string()));
    }

    #[test]
    fn dependencies_order_the_deploy() {
        let services = parse_compose(TWO_SERVICE, Some("abc123")).unwrap();
        let db_at = services.iter().position(|s| s.key == "database").unwrap();
        let app_at = services.iter().position(|s| s.key == "app").unwrap();
        assert!(db_at < app_at, "database must be created before app");
    }

    #[test]
    fn a_dependency_cycle_still_deploys() {
        let yaml = r#"
services:
  a:
    image: x:1
    depends_on: [b]
  b:
    image: y:1
    depends_on: [a]
"#;
        let services = parse_compose(yaml, None).unwrap();
        assert_eq!(services.len(), 2);
    }

    #[test]
    fn long_form_ports_are_published() {
        let yaml = r#"
services:
  web:
    image: nginx:alpine
    ports:
      - target: 80
        published: 8080
        protocol: tcp
"#;
        let services = parse_compose(yaml, None).unwrap();
        assert_eq!(services[0].ports.len(), 1);
        assert_eq!(services[0].ports[0].host, 8080);
        assert_eq!(services[0].ports[0].container, 80);
    }

    #[test]
    fn command_survives_parsing() {
        let yaml = r#"
services:
  worker:
    image: myapp:1
    command: php /app/bin/console messenger:consume --all
"#;
        let services = parse_compose(yaml, None).unwrap();
        let cmd = services[0].command.as_ref().expect("command must survive");
        assert_eq!(cmd[0], "php");
        assert!(cmd.iter().any(|a| a == "messenger:consume"));
    }

    #[test]
    fn a_shell_command_goes_through_sh_rather_than_being_mangled() {
        let argv = split_shell_command("sh -c 'echo hi' | tee /tmp/x");
        assert_eq!(argv[0], "sh");
        assert_eq!(argv[1], "-c");
    }

    #[test]
    fn depends_on_long_form_is_understood() {
        let yaml = r#"
services:
  app:
    image: x:1
    depends_on:
      database:
        condition: service_healthy
  database:
    image: postgres:16-alpine
"#;
        let services = parse_compose(yaml, None).unwrap();
        let app = services.iter().find(|s| s.key == "app").unwrap();
        assert_eq!(app.depends_on, vec!["database".to_string()]);
    }

    #[test]
    fn author_labels_survive_but_the_panel_namespace_does_not() {
        let yaml = r#"
services:
  web:
    image: nginx:alpine
    labels:
      traefik.enable: "true"
      dockpanel.managed: "false"
      dockpanel.stack_id: somebody-elses-stack
"#;
        let services = parse_compose(yaml, Some("abc123")).unwrap();
        let labels = &services[0].labels;
        assert_eq!(labels.get("traefik.enable"), Some(&"true".to_string()));
        // A compose file must not be able to hide a container from the panel or
        // attach it to another stack.
        assert!(labels.keys().all(|k| !k.starts_with("dockpanel.")));
    }

    #[test]
    fn dangerous_options_are_still_rejected() {
        let yaml = r#"
services:
  bad:
    image: x:1
    privileged: true
"#;
        assert!(parse_compose(yaml, None).is_err());
    }

    /// `security_opt` was parsed into `ServiceDef` but the rejection loop
    /// never read it - every OTHER dangerous field above it in the same
    /// struct was checked, this one silently was not. Positive control
    /// alongside it: `no-new-privileges:true` (what this deployer sets by
    /// default for every service it creates) must stay allowed, or the fix
    /// would reject the panel's own hardening default.
    /// [[project_dockpanel_tech_debt_p185]] carry I.
    #[test]
    fn security_opt_unconfined_is_rejected_but_hardening_opts_are_not() {
        let unconfined = r#"
services:
  bad:
    image: x:1
    security_opt:
      - seccomp:unconfined
"#;
        assert!(
            parse_compose(unconfined, None).is_err(),
            "seccomp:unconfined must be rejected - it disables the syscall filter entirely"
        );

        let apparmor_unconfined = r#"
services:
  bad:
    image: x:1
    security_opt:
      - apparmor:unconfined
"#;
        assert!(
            parse_compose(apparmor_unconfined, None).is_err(),
            "apparmor:unconfined must be rejected - it disables AppArmor confinement entirely"
        );

        let hardened = r#"
services:
  fine:
    image: x:1
    security_opt:
      - no-new-privileges:true
"#;
        assert!(
            parse_compose(hardened, None).is_ok(),
            "no-new-privileges:true is a hardening option, not a dangerous one, and must stay allowed"
        );
    }

    /// This deployer has no field for `user:`/`healthcheck:`/`entrypoint:` -
    /// `compose_validate` reads these three flags to warn the author instead
    /// of silently dropping their directive while saying "valid".
    /// [[project_dockpanel_tech_debt_p185]] carry I.
    #[test]
    fn user_healthcheck_and_entrypoint_are_flagged_as_ignored_when_declared() {
        let yaml = r#"
services:
  full:
    image: x:1
    user: "1000:1000"
    healthcheck:
      test: ["CMD", "true"]
    entrypoint: ["/bin/sh"]
"#;
        let services = parse_compose(yaml, None).expect("parses");
        let svc = &services[0];
        assert!(svc.user_ignored, "user: was declared and must be flagged");
        assert!(svc.healthcheck_ignored, "healthcheck: was declared and must be flagged");
        assert!(svc.entrypoint_ignored, "entrypoint: was declared and must be flagged");
    }

    /// Positive control for the arm above: a service that declares NONE of
    /// the three must not be flagged, or the fix would warn on every stack.
    #[test]
    fn user_healthcheck_and_entrypoint_are_not_flagged_when_absent() {
        let yaml = r#"
services:
  plain:
    image: x:1
"#;
        let services = parse_compose(yaml, None).expect("parses");
        let svc = &services[0];
        assert!(!svc.user_ignored);
        assert!(!svc.healthcheck_ignored);
        assert!(!svc.entrypoint_ignored);
    }

    fn ports_of(entries: &str) -> Result<Vec<PortMapping>, String> {
        let yaml = format!("services:\n  web:\n    image: nginx:alpine\n    ports:\n{entries}");
        parse_compose(&yaml, None).map(|mut s| s.remove(0).ports)
    }

    fn refusal(entries: &str) -> String {
        match ports_of(entries) {
            Ok(p) => panic!("expected a refusal for {entries:?}, got {p:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_bracketed_ipv6_loopback_is_published_on_that_address() {
        let ports = ports_of("      - \"[::1]:8080:80\"\n").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!((ports[0].host, ports[0].container), (8080, 80));
        assert_eq!(ports[0].host_ip, "::1");
        assert_eq!(ports[0].protocol, "tcp");
        let (bindings, _) = port_bindings_for(&ports);
        let binding = bindings["80/tcp"].as_ref().unwrap();
        assert_eq!(binding[0].host_ip.as_deref(), Some("::1"));
    }

    #[test]
    fn the_written_ipv4_loopback_reaches_docker() {
        let ports = ports_of("      - \"127.0.0.2:8080:80\"\n").unwrap();
        let (bindings, _) = port_bindings_for(&ports);
        let binding = bindings["80/tcp"].as_ref().unwrap();
        assert_eq!(binding[0].host_ip.as_deref(), Some("127.0.0.2"));
    }

    #[test]
    fn a_port_range_publishes_every_port_in_it() {
        let ports = ports_of("      - \"8000-8010:8000-8010\"\n").unwrap();
        assert_eq!(ports.len(), 11);
        assert_eq!((ports[0].host, ports[0].container), (8000, 8000));
        assert_eq!((ports[10].host, ports[10].container), (8010, 8010));
    }

    #[test]
    fn ranges_combine_with_an_address_a_shift_and_a_protocol() {
        let ports = ports_of("      - \"[::1]:9000-9001:80-81/udp\"\n").unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!((ports[1].host, ports[1].container), (9001, 81));
        assert!(ports.iter().all(|p| p.host_ip == "::1" && p.protocol == "udp"));
    }

    #[test]
    fn a_long_form_range_and_address_are_published() {
        let ports = ports_of(
            "      - target: \"80-81\"\n        published: \"8080-8081\"\n        host_ip: \"::1\"\n",
        )
        .unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!((ports[1].host, ports[1].container), (8081, 81));
        assert_eq!(ports[1].host_ip, "::1");
    }

    #[test]
    fn one_container_port_can_be_published_on_both_loopbacks() {
        let ports =
            ports_of("      - \"127.0.0.1:8080:80\"\n      - \"[::1]:8080:80\"\n").unwrap();
        let (bindings, exposed) = port_bindings_for(&ports);
        assert_eq!(exposed.len(), 1);
        let binding = bindings["80/tcp"].as_ref().unwrap();
        assert_eq!(binding.len(), 2, "the second mapping must not replace the first");
    }

    #[test]
    fn plain_forms_keep_working_on_the_default_loopback() {
        let ports =
            ports_of("      - \"8080:80\"\n      - 9090\n      - \"127.0.0.1:7070:70/udp\"\n").unwrap();
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().all(|p| p.host_ip == "127.0.0.1"));
        assert_eq!((ports[1].host, ports[1].container), (9090, 9090));
        assert_eq!(ports[2].protocol, "udp");
    }

    #[test]
    fn every_form_that_cannot_be_published_is_refused_by_name() {
        for (entry, needle) in [
            ("\"8000-8010:80\"", "same number of ports"),
            ("\"8000-8001:80-82\"", "same number of ports"),
            ("\"80:8000-8001\"", "same number of ports"),
            ("\"8010-8000:80-90\"", "range"),
            ("\"70000:80\"", "1 and 65535"),
            ("\"0:80\"", "1 and 65535"),
            ("\"${PORT}:80\"", "${PORT}"),
            ("\"abc\"", "abc"),
            ("\"8080:80/icmp\"", "protocol"),
            ("\"127.0.0.1::80\"", "host port"),
            ("\"::1:8080:80\"", "brackets"),
            ("\"[::1:8080:80\"", "brackets"),
            ("\"[nope]:8080:80\"", "address"),
            ("\"1-40000:1-40000\"", "at most"),
            ("true", "true"),
        ] {
            let e = refusal(&format!("      - {entry}\n"));
            assert!(e.contains("'web'"), "{entry}: the service is named in {e:?}");
            assert!(e.contains(needle), "{entry}: expected {needle:?} in {e:?}");
        }
    }

    #[test]
    fn an_address_outside_loopback_is_refused_rather_than_narrowed() {
        for entry in ["\"0.0.0.0:8080:80\"", "\"[::]:8080:80\"", "\"192.0.2.10:8080:80\""] {
            let e = refusal(&format!("      - {entry}\n"));
            assert!(e.contains("loopback"), "{entry}: {e}");
        }
        let e = refusal("      - target: 80\n        published: 8080\n        host_ip: 0.0.0.0\n");
        assert!(e.contains("loopback"), "{e}");
    }

    #[test]
    fn a_long_form_entry_that_cannot_be_published_is_refused() {
        for entry in [
            "      - published: 8080\n",
            "      - target: 80\n        published: \"${PORT}\"\n",
            "      - target: 80\n        published: \"8000-8010\"\n",
            "      - target: 80\n        protocol: icmp\n",
        ] {
            refusal(entry);
        }
    }

    #[test]
    fn the_same_host_port_published_twice_is_refused_across_services() {
        let yaml = "services:\n  a:\n    image: nginx:1\n    ports:\n      - \"8080:80\"\n  b:\n    image: nginx:1\n    ports:\n      - \"8070-8090:70-90\"\n";
        let e = parse_compose(yaml, None).unwrap_err();
        assert!(e.contains("8080"), "{e}");
        // Different protocol or address: no collision.
        ports_of("      - \"8080:80\"\n      - \"8080:80/udp\"\n      - \"[::1]:8080:80\"\n").unwrap();
    }

    #[test]
    fn a_domain_is_fronted_on_a_port_nginx_can_reach() {
        let yaml = "services:\n  web:\n    image: nginx:1\n    ports:\n      - \"[::1]:8081:81\"\n      - \"8082:82\"\n";
        let services = parse_compose(yaml, None).unwrap();
        assert_eq!(default_expose_port(&services), Some(8082));

        let yaml = "services:\n  web:\n    image: nginx:1\n    ports:\n      - \"[::1]:8081:81\"\n";
        let services = parse_compose(yaml, None).unwrap();
        assert_eq!(default_expose_port(&services), None);
    }
}
