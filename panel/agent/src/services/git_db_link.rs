//! A managed database LINKED to a Git Deploy.
//!
//! WHY THIS EXISTS. A managed database runs as `dockpanel-db-{name}` on the
//! shared `dockpanel-db` bridge, which has inter-container communication
//! disabled (H2: a compromised tenant DB must not reach a neighbour's), and
//! publishes its port on the host's `127.0.0.1` only. A Git Deploy container
//! runs on Docker's default bridge. So the app could reach the database by NO
//! route: `127.0.0.1` inside the container is the container itself, the
//! `dockpanel-db` network is ICC-off and the app is not on it, and the default
//! bridge has no name resolution. The form and the guide still told users to
//! "use a database under Databases".
//!
//! THE DESIGN. One dedicated network per linked deployment,
//! `dockpanel-link-{name}`, holding exactly two things: that deployment's app
//! container and the one database it is linked to, which answers there under
//! the stable alias [`DB_ALIAS`] (`db`). ICC is on - it has to be, that is the
//! whole point - and that is safe ONLY because the network is single-purpose:
//!
//!   * The panel proves the deployment and the database belong to the same
//!     account before it ever names the database here (`git_deploys.rs`,
//!     `resolve_linked_database`), at save time and again at every deploy.
//!   * This module enforces the membership rule on its own side: on every
//!     reconcile, anything attached to the network that is neither this
//!     deployment's container nor the linked database is disconnected. Two
//!     tenants can therefore never share an ICC-on network through this path,
//!     whatever a future caller sends.
//!   * The network is `internal`: it has no gateway, so it can never become a
//!     container's default route - which matters for the database, whose
//!     `127.0.0.1` port publish Docker programs on the endpoint that carries
//!     the default gateway. The app keeps its egress and its published port on
//!     the default bridge, exactly as before.
//!
//! IDEMPOTENT BY CONSTRUCTION. [`reconcile`] turns whatever is on the box into
//! the desired state - create, re-point to another database, or tear down - so
//! the same call serves a first deploy, a redeploy, a relink and an unlink. The
//! app container also carries [`LINK_DB_LABEL`], which is what
//! [`reattach_all`] reads at agent start to re-attach anything a daemon
//! restart, a recreated network or a recreated database container dropped.
//!
//! LINKED SERVICES. The same network also carries the panel-managed template
//! apps (`dockpanel-app-{app}`) a deployment declares as LINKED SERVICES, each
//! under the DNS alias the deployment chose (a mail catcher as `mailpit`, a
//! cache as `redis`, ...). A deployment may have a database, services, both or
//! neither: the network exists while at least one is declared and is torn down
//! when none is. The rules are the database's:
//!
//!   * Only an app whose `dockpanel.user.id` label is the deployment's owner may
//!     join ([`verify_service_identity`]), proven by name AND labels at every
//!     reconcile - never by a stored container id, so a recreated app (update,
//!     image change, env edit) is found again under its stable name.
//!   * Membership stays exact: [`plan_membership`] keeps the declared members
//!     with the declared aliases, re-attaches a member whose alias changed, and
//!     disconnects everything else. Disconnecting is the ONLY thing done to a
//!     service; it is never stopped or removed here.
//!   * The app container records its services in [`LINK_SERVICES_LABEL`] (and
//!     the owner they were proven against in [`LINK_OWNER_LABEL`]), which is
//!     what [`reattach_all`] replays at agent start.

use bollard::Docker;
use bollard::container::ListContainersOptions;
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, DisconnectNetworkOptions};
use std::collections::HashMap;

/// The name the linked database answers to on the link network.
pub const DB_ALIAS: &str = "db";

/// On the link network: the deployment it belongs to.
pub const LINK_LABEL: &str = "dockpanel.git.link";

/// On the link network AND on the app container: the database container's id.
/// Docker labels are immutable, so a re-pointed link is a recreated network.
pub const LINK_DB_LABEL: &str = "dockpanel.git.link.db";

/// On the app container: the linked services, `alias=app,alias=app`.
pub const LINK_SERVICES_LABEL: &str = "dockpanel.git.link.services";

/// On the app container: the owner the linked services were proven against.
pub const LINK_OWNER_LABEL: &str = "dockpanel.git.link.owner";

/// The most services one deployment may link. A link network is a
/// single-purpose private network, not a place to assemble a fleet.
pub const MAX_LINKED_SERVICES: usize = 8;

/// The container name prefix `docker_apps::deploy_app` gives a template app.
pub const APP_CONTAINER_PREFIX: &str = "dockpanel-app-";

/// The network a deployment named `name` is linked through.
pub fn link_network_name(name: &str) -> String {
    format!("dockpanel-link-{name}")
}

/// Every link network starts with this - `docker_apps` keeps them out of the
/// primary slot when it recreates a linked service.
pub const LINK_NETWORK_PREFIX: &str = "dockpanel-link-";

/// A panel-managed app a deploy asks to have linked, as the panel stored it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct LinkedServiceRequest {
    /// The app's name: its container is `dockpanel-app-{app_name}`. The stable
    /// reference - a container id changes every time the app is recreated.
    pub app_name: String,
    /// The DNS name the app answers to on the link network.
    pub alias: String,
}

/// An RFC 1123 DNS label, lowercase: what an alias must be to resolve.
pub fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The app-name rule `routes::is_valid_name` applies when the app is deployed.
pub fn is_app_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Shape check for the services of one deploy, before Docker is asked anything.
/// `db_linked`: the alias `db` belongs to the linked database.
pub fn validate_services(
    services: &[LinkedServiceRequest],
    db_linked: bool,
    owner: Option<&str>,
) -> Result<(), String> {
    if services.is_empty() {
        return Ok(());
    }
    if services.len() > MAX_LINKED_SERVICES {
        return Err(format!(
            "At most {MAX_LINKED_SERVICES} linked services per deployment"
        ));
    }
    if !owner.is_some_and(|o| uuid::Uuid::parse_str(o).is_ok()) {
        return Err("linked_services requires the deployment's owner (link_owner)".to_string());
    }
    let mut aliases = std::collections::HashSet::new();
    let mut apps = std::collections::HashSet::new();
    for s in services {
        if !is_app_name(&s.app_name) {
            return Err(format!("Invalid linked service app name: {:?}", s.app_name));
        }
        if !is_dns_label(&s.alias) {
            return Err(format!(
                "Invalid alias {:?}: lowercase letters, digits and '-', 1-63 characters, not \
                 starting or ending with '-'",
                s.alias
            ));
        }
        if db_linked && s.alias == DB_ALIAS {
            return Err(format!(
                "The alias {DB_ALIAS:?} is the linked database's; pick another for {}",
                s.app_name
            ));
        }
        if !aliases.insert(s.alias.as_str()) {
            return Err(format!("The alias {:?} is used twice", s.alias));
        }
        if !apps.insert(s.app_name.as_str()) {
            return Err(format!("The app {} is linked twice", s.app_name));
        }
    }
    Ok(())
}

/// `alias=app,alias=app` - the value of [`LINK_SERVICES_LABEL`]. Neither side
/// can hold `=` or `,` once [`validate_services`] has passed.
pub fn encode_services(services: &[LinkedServiceRequest]) -> String {
    services
        .iter()
        .map(|s| format!("{}={}", s.alias, s.app_name))
        .collect::<Vec<_>>()
        .join(",")
}

/// The inverse of [`encode_services`]. Malformed entries are dropped: this
/// reads a label back at agent start, and a bad entry must not hide the rest.
pub fn decode_services(label: &str) -> Vec<LinkedServiceRequest> {
    label
        .split(',')
        .filter_map(|pair| {
            let (alias, app) = pair.split_once('=')?;
            (is_dns_label(alias) && is_app_name(app)).then(|| LinkedServiceRequest {
                app_name: app.to_string(),
                alias: alias.to_string(),
            })
        })
        .collect()
}

/// Is the container `(container_name, labels)` the panel app `app_name`, owned
/// by `owner`? The same two-sided proof as [`verify_db_identity`]: the name
/// says which app, the labels say it is a template app the panel deployed,
/// and the owner label says whose.
pub fn verify_service_identity(
    container_name: &str,
    labels: Option<&HashMap<String, String>>,
    app_name: &str,
    owner: &str,
) -> Result<(), String> {
    let expected = format!("{APP_CONTAINER_PREFIX}{app_name}");
    if container_name.trim_start_matches('/') != expected {
        return Err(format!(
            "The linked service's container is {container_name}, not {expected}. Nothing was \
             linked."
        ));
    }
    let l = labels.ok_or_else(|| format!("{expected} carries no labels; refusing to link it"))?;
    if l.get("dockpanel.managed").map(String::as_str) != Some("true")
        || l.get("dockpanel.app.template").is_none_or(|t| t.is_empty())
        || l.get("dockpanel.type").is_some()
    {
        return Err(format!(
            "{expected} is not an app deployed by CyberHunter - Panel; refusing to link it"
        ));
    }
    if l.get("dockpanel.user.id").map(String::as_str) != Some(owner) {
        return Err(format!(
            "{expected} does not belong to this deployment's owner; refusing to link it"
        ));
    }
    Ok(())
}

/// A linked service, once proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedService {
    /// Full container id, as found NOW - never stored.
    pub id: String,
    pub alias: String,
}

/// Prove the requested app exists on this server and belongs to `owner`.
pub async fn verify_service(
    docker: &Docker,
    req: &LinkedServiceRequest,
    owner: &str,
) -> Result<VerifiedService, String> {
    let container = format!("{APP_CONTAINER_PREFIX}{}", req.app_name);
    let info = docker.inspect_container(&container, None).await.map_err(|e| {
        format!(
            "The linked service {container} is not on this server ({e}). Nothing was changed. \
             Unlink it from this deployment, or deploy the app again under that name."
        )
    })?;
    verify_service_identity(
        info.name.as_deref().unwrap_or_default(),
        info.config.as_ref().and_then(|c| c.labels.as_ref()),
        &req.app_name,
        owner,
    )?;
    Ok(VerifiedService {
        id: info.id.unwrap_or(container),
        alias: req.alias.clone(),
    })
}

/// Prove every requested service, in order. The first refusal wins.
pub async fn verify_services(
    docker: &Docker,
    reqs: &[LinkedServiceRequest],
    owner: Option<&str>,
) -> Result<Vec<VerifiedService>, String> {
    if reqs.is_empty() {
        return Ok(Vec::new());
    }
    let owner = owner.ok_or("linked services require the deployment's owner")?;
    let mut out = Vec::with_capacity(reqs.len());
    for r in reqs {
        out.push(verify_service(docker, r, owner).await?);
    }
    Ok(out)
}

/// One container found on a link network, as [`plan_membership`] sees it.
#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub labels: Option<HashMap<String, String>>,
    /// Its aliases ON THIS NETWORK.
    pub aliases: Vec<String>,
}

/// What [`reconcile`] does to the membership of a link network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkStep {
    Disconnect(String),
    Attach {
        container: String,
        alias: Option<String>,
    },
}

/// Do two container ids name the same container (one may be a prefix)?
fn same_container(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && (a == b || a.starts_with(b) || b.starts_with(a))
}

/// The pure membership plan for `name`'s link network.
///
/// Wanted: the database under [`DB_ALIAS`] and each service under its alias.
/// A wanted member already there with its alias is left alone; one there under
/// another alias is disconnected and re-attached (Docker aliases are fixed per
/// endpoint); one missing is attached. This deployment's own containers stay
/// (they are attached by the deploy itself). Everything else is disconnected.
/// Disconnects come first, so a re-attach never collides with its old endpoint.
pub fn plan_membership(
    name: &str,
    members: &[Member],
    db: Option<&VerifiedDb>,
    services: &[VerifiedService],
) -> Vec<LinkStep> {
    let wanted: Vec<(&str, &str)> = db
        .map(|d| (d.id.as_str(), DB_ALIAS))
        .into_iter()
        .chain(services.iter().map(|s| (s.id.as_str(), s.alias.as_str())))
        .collect();
    let mut satisfied = vec![false; wanted.len()];
    let mut disconnect = Vec::new();
    for m in members {
        if let Some(i) = wanted.iter().position(|(id, _)| same_container(&m.id, id)) {
            if m.aliases.iter().any(|a| a == wanted[i].1) {
                satisfied[i] = true;
            } else {
                disconnect.push(LinkStep::Disconnect(m.id.clone()));
            }
        } else if !may_stay(&m.id, m.labels.as_ref(), name, None) {
            disconnect.push(LinkStep::Disconnect(m.id.clone()));
        }
    }
    let attach = wanted
        .iter()
        .zip(satisfied)
        .filter(|(_, done)| !done)
        .map(|((id, alias), _)| LinkStep::Attach {
            container: id.to_string(),
            alias: Some(alias.to_string()),
        });
    disconnect.into_iter().chain(attach).collect()
}

/// The database a deploy asks to be linked to, as the panel identified it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LinkedDbRequest {
    /// The id the panel recorded when it created the database.
    pub container_id: String,
    /// `databases.name` - the container must be `dockpanel-db-{name}` AND carry
    /// `dockpanel.db.name={name}`, so an id that now names something else is
    /// refused rather than wired into somebody's app.
    pub name: String,
}

/// Shape check for the request, before Docker is asked anything.
pub fn validate_request(req: &LinkedDbRequest) -> Result<(), &'static str> {
    let id_ok = (12..=64).contains(&req.container_id.len())
        && req.container_id.chars().all(|c| c.is_ascii_hexdigit());
    if !id_ok {
        return Err("Invalid linked_db.container_id");
    }
    let name_ok = !req.name.is_empty()
        && req.name.len() <= 63
        && req
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !name_ok {
        return Err("Invalid linked_db.name");
    }
    Ok(())
}

/// Labels written on a link network when it is created.
pub fn network_labels(name: &str, db_id: &str) -> HashMap<String, String> {
    HashMap::from([
        ("dockpanel.managed".to_string(), "true".to_string()),
        (LINK_LABEL.to_string(), name.to_string()),
        (LINK_DB_LABEL.to_string(), db_id.to_string()),
    ])
}

/// Is a network carrying `labels` this deployment's link network? A network we
/// did not label is a network we did not create, and is never removed.
pub fn network_is_ours(labels: Option<&HashMap<String, String>>, name: &str) -> bool {
    labels
        .map(|l| {
            l.get("dockpanel.managed").map(String::as_str) == Some("true")
                && l.get(LINK_LABEL).map(String::as_str) == Some(name)
        })
        .unwrap_or(false)
}

/// Does the existing link network point at another database than `db_id`?
pub fn points_elsewhere(labels: Option<&HashMap<String, String>>, db_id: &str) -> bool {
    labels
        .and_then(|l| l.get(LINK_DB_LABEL))
        .map(String::as_str)
        != Some(db_id)
}

/// Is the container `(container_name, labels)` the managed database `db_name`?
pub fn verify_db_identity(
    container_name: &str,
    labels: Option<&HashMap<String, String>>,
    db_name: &str,
) -> Result<(), String> {
    let expected = format!("dockpanel-db-{db_name}");
    if container_name.trim_start_matches('/') != expected {
        return Err(format!(
            "The linked database's container is {container_name}, not {expected}. Nothing was \
             linked. Re-select the database on this deployment."
        ));
    }
    let l = labels.ok_or_else(|| format!("{expected} carries no labels; refusing to link it"))?;
    if l.get("dockpanel.managed").map(String::as_str) != Some("true")
        || l.get("dockpanel.db.name").map(String::as_str) != Some(db_name)
    {
        return Err(format!(
            "{expected} is not a database managed by CyberHunter - Panel; refusing to link it"
        ));
    }
    Ok(())
}

/// May the container carrying `labels` stay on `name`'s link network?
///
/// Exactly two kinds of member are allowed: this deployment's own container
/// (including its blue-green stand-in, which carries the same labels), and the
/// linked database itself. Everything else is disconnected on reconcile.
pub fn may_stay(
    container_id: &str,
    labels: Option<&HashMap<String, String>>,
    name: &str,
    db_id: Option<&str>,
) -> bool {
    if let Some(db) = db_id
        && (container_id == db || container_id.starts_with(db) || db.starts_with(container_id))
    {
        return true;
    }
    labels
        .map(|l| {
            l.get("dockpanel.type").map(String::as_str) == Some("git")
                && l.get("dockpanel.git.name").map(String::as_str) == Some(name)
                && l.get(super::ownership::GIT_KIND_LABEL).map(String::as_str) == Some("deploy")
        })
        .unwrap_or(false)
}

/// The database container this deploy is linked to, once proven.
#[derive(Debug, Clone)]
pub struct VerifiedDb {
    /// Full container id.
    pub id: String,
}

/// Prove the requested container is the managed database the panel named.
pub async fn verify_db(docker: &Docker, req: &LinkedDbRequest) -> Result<VerifiedDb, String> {
    let info = docker
        .inspect_container(&req.container_id, None)
        .await
        .map_err(|e| {
            format!(
                "The linked database dockpanel-db-{} is not on this server ({e}). Nothing was \
             changed. Check it under Databases, or unlink it from this deployment.",
                req.name
            )
        })?;
    verify_db_identity(
        info.name.as_deref().unwrap_or_default(),
        info.config.as_ref().and_then(|c| c.labels.as_ref()),
        &req.name,
    )?;
    Ok(VerifiedDb {
        id: info.id.unwrap_or_else(|| req.container_id.clone()),
    })
}

/// Is `container` attached to `network` right now?
async fn is_attached(docker: &Docker, container: &str, network: &str) -> bool {
    docker
        .inspect_container(container, None)
        .await
        .ok()
        .and_then(|c| c.network_settings)
        .and_then(|ns| ns.networks)
        .map(|nets| nets.contains_key(network))
        .unwrap_or(false)
}

/// Connect `container` to `network`, with `alias` if given. Already-attached is
/// success: this is called on every deploy and on every agent start.
pub async fn attach(
    docker: &Docker,
    network: &str,
    container: &str,
    alias: Option<&str>,
) -> Result<(), String> {
    if is_attached(docker, container, network).await {
        return Ok(());
    }
    let endpoint_config = bollard::models::EndpointSettings {
        aliases: alias.map(|a| vec![a.to_string()]),
        ..Default::default()
    };
    docker
        .connect_network(
            network,
            ConnectNetworkOptions {
                container,
                endpoint_config,
            },
        )
        .await
        .map_err(|e| format!("Failed to attach {container} to {network}: {e}"))
}

/// Disconnect everything from a link network we own and remove it.
async fn remove_network(docker: &Docker, network: &str, attached: &[String]) -> Result<(), String> {
    for cid in attached {
        let _ = docker
            .disconnect_network(
                network,
                DisconnectNetworkOptions {
                    container: cid.as_str(),
                    force: true,
                },
            )
            .await;
    }
    docker
        .remove_network(network)
        .await
        .map_err(|e| format!("Failed to remove {network}: {e}"))?;
    tracing::info!("Removed link network {network}");
    Ok(())
}

/// Every container attached to `network`, running OR NOT.
///
/// `inspect_network`'s `Containers` lists only live endpoints, so a container
/// that is created or stopped - attached in its own config, joining the moment
/// it starts - is invisible there. Found by the real-Docker drill below: a
/// created-but-not-started stranger survived the membership check. The
/// `network` filter on a full container listing reads each container's own
/// config, so the union of both is the real membership.
async fn attached_ids(
    docker: &Docker,
    network: &str,
    net: &bollard::models::Network,
) -> Vec<String> {
    let mut ids: Vec<String> = net
        .containers
        .as_ref()
        .map(|c| c.keys().cloned().collect())
        .unwrap_or_default();
    let filters = HashMap::from([("network", vec![network])]);
    if let Ok(listed) = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
    {
        for id in listed.into_iter().filter_map(|c| c.id) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

async fn create_network(
    docker: &Docker,
    network: &str,
    name: &str,
    db_id: &str,
) -> Result<(), String> {
    let labels = network_labels(name, db_id);
    docker
        .create_network(CreateNetworkOptions {
            name: network.to_string(),
            driver: "bridge".to_string(),
            // No gateway, so never a container's default route - see the module doc.
            internal: true,
            labels,
            options: HashMap::from([(
                "com.docker.network.bridge.enable_icc".to_string(),
                "true".to_string(),
            )]),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("Failed to create link network {network}: {e}"))?;
    tracing::info!("Created link network {network} (internal, single deployment {name})");
    Ok(())
}

/// Every container on `network` with its labels and its aliases there.
async fn members(
    docker: &Docker,
    network: &str,
    net: &bollard::models::Network,
) -> Vec<Member> {
    let mut out = Vec::new();
    for id in attached_ids(docker, network, net).await {
        let info = docker.inspect_container(&id, None).await.ok();
        let labels = info
            .as_ref()
            .and_then(|c| c.config.as_ref())
            .and_then(|c| c.labels.clone());
        let aliases = info
            .as_ref()
            .and_then(|c| c.network_settings.as_ref())
            .and_then(|ns| ns.networks.as_ref())
            .and_then(|n| n.get(network))
            .and_then(|ep| ep.aliases.clone())
            .unwrap_or_default();
        out.push(Member {
            id,
            labels,
            aliases,
        });
    }
    out
}

/// Bring `name`'s link network to the desired state and return its name.
///
/// * nothing declared (`db = None`, no services) - a link network left by an
///   earlier deploy is torn down (the unlink case, and every deploy of a
///   deployment that never had one, where it is a single failed inspect).
///   Tearing down disconnects the members; it never touches them otherwise.
/// * a database and/or services - the network exists, labelled for THIS
///   database (or for none), with the database attached under [`DB_ALIAS`],
///   each service under its alias, and nothing else on it but this
///   deployment's own containers ([`plan_membership`]). The app is attached by
///   the caller, between create and start of the container it is about to run.
///
/// Called before anything destructive in `deploy_or_update`, so a refusal here
/// (a database or a service that is not what the panel said, a network that is
/// not ours) leaves the running app exactly as it was.
pub async fn reconcile(
    docker: &Docker,
    name: &str,
    db: Option<&VerifiedDb>,
    services: &[VerifiedService],
) -> Result<Option<String>, String> {
    let network = link_network_name(name);
    let existing = docker.inspect_network::<String>(&network, None).await.ok();

    if let Some(ref net) = existing
        && !network_is_ours(net.labels.as_ref(), name)
    {
        return Err(format!(
            "A Docker network named {network} exists and was not created for this deployment; \
             refusing to use or remove it. Nothing was changed."
        ));
    }

    if db.is_none() && services.is_empty() {
        if let Some(net) = existing {
            remove_network(
                docker,
                &network,
                &attached_ids(docker, &network, &net).await,
            )
            .await?;
        }
        return Ok(None);
    }

    // The database label is "" when only services are linked.
    let db_key = db.map(|d| d.id.as_str()).unwrap_or("");
    let current = match existing {
        Some(ref net) if points_elsewhere(net.labels.as_ref(), db_key) => {
            // Re-pointed at another database (or none). Labels are immutable,
            // so the network is rebuilt; the plan below re-attaches the
            // services and the caller re-attaches the app.
            remove_network(docker, &network, &attached_ids(docker, &network, net).await).await?;
            create_network(docker, &network, name, db_key).await?;
            Vec::new()
        }
        Some(ref net) => members(docker, &network, net).await,
        None => {
            create_network(docker, &network, name, db_key).await?;
            Vec::new()
        }
    };

    for step in plan_membership(name, &current, db, services) {
        match step {
            LinkStep::Disconnect(cid) => {
                tracing::warn!("Disconnecting {cid} from link network {network}");
                let _ = docker
                    .disconnect_network(
                        &network,
                        DisconnectNetworkOptions {
                            container: cid.as_str(),
                            force: true,
                        },
                    )
                    .await;
            }
            LinkStep::Attach { container, alias } => {
                attach(docker, &network, &container, alias.as_deref()).await?;
            }
        }
    }
    Ok(Some(network))
}

/// Tear down every link network a database container is attached to. Called
/// by `database::remove_database` before the container goes - Docker would
/// detach it anyway, but the network would then be left holding the app alone,
/// and the app's next deploy is the only thing that would ever notice.
///
/// A network that also carries linked services is kept: only the database is
/// disconnected, so the app keeps reaching its services. The next deploy (the
/// panel has unlinked the database by then - `ON DELETE SET NULL`) rebuilds it
/// for services only.
pub async fn release_for_database(docker: &Docker, db_container_id: &str) {
    let Ok(info) = docker.inspect_container(db_container_id, None).await else {
        return;
    };
    let nets: Vec<String> = info
        .network_settings
        .and_then(|ns| ns.networks)
        .map(|n| n.keys().cloned().collect())
        .unwrap_or_default();
    for network in nets
        .into_iter()
        .filter(|n| n.starts_with("dockpanel-link-"))
    {
        let Ok(net) = docker.inspect_network::<String>(&network, None).await else {
            continue;
        };
        let owner = net.labels.as_ref().and_then(|l| l.get(LINK_LABEL)).cloned();
        match owner {
            Some(name) if network_is_ours(net.labels.as_ref(), &name) => {
                let ids = attached_ids(docker, &network, &net).await;
                let mut carries_services = false;
                for cid in &ids {
                    if same_container(cid, db_container_id) {
                        continue;
                    }
                    let labels = docker
                        .inspect_container(cid, None)
                        .await
                        .ok()
                        .and_then(|c| c.config)
                        .and_then(|c| c.labels);
                    if !may_stay(cid, labels.as_ref(), &name, None) {
                        carries_services = true;
                    }
                }
                let outcome = if carries_services {
                    docker
                        .disconnect_network(
                            &network,
                            DisconnectNetworkOptions {
                                container: db_container_id,
                                force: true,
                            },
                        )
                        .await
                        .map_err(|e| e.to_string())
                } else {
                    remove_network(docker, &network, &ids).await
                };
                if let Err(e) = outcome {
                    tracing::warn!("Database removal: could not release {network}: {e}");
                }
            }
            _ => {}
        }
    }
}

/// Re-attach every linked deployment after an agent start.
///
/// Docker persists attachments across restarts, so on most starts this finds
/// nothing to do. It exists for the cases where something did drop: a network
/// removed by hand or by a `docker network prune`, or a database container that
/// was recreated (new id - the app then stays unlinked and says so in the log,
/// because the panel must re-prove the link on the next deploy).
pub async fn reattach_all() {
    let Ok(docker) = Docker::connect_with_local_defaults() else {
        return;
    };
    // Linked to a database, to services, or both: one listing per label,
    // merged by id.
    let mut apps: Vec<bollard::models::ContainerSummary> = Vec::new();
    for label in [LINK_DB_LABEL, LINK_SERVICES_LABEL] {
        let filters = HashMap::from([("label", vec![label])]);
        if let Ok(found) = docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
        {
            for c in found {
                if !apps.iter().any(|a| a.id == c.id) {
                    apps.push(c);
                }
            }
        }
    }
    for app in apps {
        let Some(labels) = app.labels.as_ref() else {
            continue;
        };
        let (Some(name), Some(app_id)) = (labels.get("dockpanel.git.name"), app.id.as_deref())
        else {
            continue;
        };
        if labels
            .get(super::ownership::GIT_KIND_LABEL)
            .map(String::as_str)
            != Some("deploy")
        {
            continue; // a preview is never linked; never act on one that claims to be
        }
        let db = match labels.get(LINK_DB_LABEL).filter(|id| !id.is_empty()) {
            None => None,
            Some(db_id) => {
                let db_name = match docker.inspect_container(db_id, None).await {
                    Ok(db) => db
                        .config
                        .and_then(|c| c.labels)
                        .and_then(|l| l.get("dockpanel.db.name").cloned()),
                    Err(_) => None,
                };
                let Some(db_name) = db_name else {
                    tracing::warn!(
                        "Linked database {db_id} of git deploy {name} is gone; leaving it \
                         unlinked until its next deploy"
                    );
                    continue;
                };
                let req = LinkedDbRequest {
                    container_id: db_id.clone(),
                    name: db_name,
                };
                match verify_db(&docker, &req).await {
                    Ok(db) => Some(db),
                    Err(e) => {
                        tracing::warn!("Could not re-attach git deploy {name}: {e}");
                        continue;
                    }
                }
            }
        };
        // Each service is re-proved against the owner recorded at deploy. One
        // that is gone or changed hands is left out (and therefore evicted),
        // the others are kept.
        let owner = labels.get(LINK_OWNER_LABEL).map(String::as_str);
        let mut services = Vec::new();
        for req in labels
            .get(LINK_SERVICES_LABEL)
            .map(|l| decode_services(l))
            .unwrap_or_default()
        {
            match owner {
                Some(o) => match verify_service(&docker, &req, o).await {
                    Ok(s) => services.push(s),
                    Err(e) => tracing::warn!(
                        "Linked service {} of git deploy {name} left out: {e}",
                        req.app_name
                    ),
                },
                None => tracing::warn!(
                    "Git deploy {name} records linked services but no owner; leaving them \
                     unlinked until its next deploy"
                ),
            }
        }
        if db.is_none() && services.is_empty() {
            continue; // nothing provable; the next deploy decides
        }
        let result = async {
            let network = reconcile(&docker, name, db.as_ref(), &services)
                .await?
                .unwrap_or_default();
            attach(&docker, &network, app_id, None).await
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("Could not re-attach git deploy {name} to its links: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn link_network_is_named_per_deployment() {
        assert_eq!(link_network_name("shop"), "dockpanel-link-shop");
        assert_ne!(link_network_name("shop"), link_network_name("shop-2"));
    }

    #[test]
    fn only_a_network_labelled_for_this_deployment_is_ours() {
        let ours = network_labels("shop", "abc");
        assert!(network_is_ours(Some(&ours), "shop"));
        assert!(
            !network_is_ours(Some(&ours), "shop-2"),
            "another deployment's network"
        );
        assert!(
            !network_is_ours(None, "shop"),
            "an unlabelled network is nobody's to remove"
        );
        let unmanaged = labels(&[(LINK_LABEL, "shop")]);
        assert!(
            !network_is_ours(Some(&unmanaged), "shop"),
            "managed=true is required too"
        );
    }

    #[test]
    fn a_relink_to_another_database_rebuilds_the_network() {
        let net = network_labels("shop", "aaa");
        assert!(!points_elsewhere(Some(&net), "aaa"));
        assert!(points_elsewhere(Some(&net), "bbb"));
        assert!(points_elsewhere(None, "aaa"));
    }

    #[test]
    fn db_identity_requires_name_and_labels_to_agree() {
        let good = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.db.name", "shopdb"),
        ]);
        assert!(verify_db_identity("/dockpanel-db-shopdb", Some(&good), "shopdb").is_ok());
        // An id the panel holds that now names another container.
        assert!(verify_db_identity("/dockpanel-git-shop", Some(&good), "shopdb").is_err());
        // Right name, but not one of ours.
        let stranger = labels(&[("dockpanel.db.name", "shopdb")]);
        assert!(verify_db_identity("/dockpanel-db-shopdb", Some(&stranger), "shopdb").is_err());
        let other_db = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.db.name", "other"),
        ]);
        assert!(verify_db_identity("/dockpanel-db-shopdb", Some(&other_db), "shopdb").is_err());
        assert!(verify_db_identity("/dockpanel-db-shopdb", None, "shopdb").is_err());
    }

    #[test]
    fn only_this_deployment_and_its_database_may_stay_on_the_link() {
        let app = labels(&[
            ("dockpanel.type", "git"),
            ("dockpanel.git.name", "shop"),
            (crate::services::ownership::GIT_KIND_LABEL, "deploy"),
        ]);
        assert!(may_stay("c1", Some(&app), "shop", Some("dbid")));
        assert!(
            may_stay("dbid", None, "shop", Some("dbid")),
            "the linked database itself"
        );
        // Another tenant's app, another deployment's app, a preview, a stranger.
        let other = labels(&[
            ("dockpanel.type", "git"),
            ("dockpanel.git.name", "blog"),
            (crate::services::ownership::GIT_KIND_LABEL, "deploy"),
        ]);
        assert!(!may_stay("c2", Some(&other), "shop", Some("dbid")));
        let preview = labels(&[
            ("dockpanel.type", "git"),
            ("dockpanel.git.name", "shop"),
            (crate::services::ownership::GIT_KIND_LABEL, "preview"),
        ]);
        assert!(
            !may_stay("c3", Some(&preview), "shop", Some("dbid")),
            "a preview never joins"
        );
        assert!(!may_stay("c4", None, "shop", Some("dbid")));
        assert!(
            !may_stay("otherdb", None, "shop", Some("dbid")),
            "a second database"
        );
    }

    /// The whole link, against a REAL Docker daemon, through the same bollard
    /// calls a deploy makes: a managed-looking DB, a created-but-not-started app
    /// attached before start (the `create_and_start` order), `db` resolving from
    /// the app, a stranger evicted on reconcile, and `reconcile(None)` removing
    /// the network. Disposable names only (`dockpanel-db-lnkdbtest*`,
    /// `dockpanel-link-lnkdbtest*`), all removed whatever the outcome.
    #[tokio::test]
    #[ignore = "creates real containers and a real network; run with cargo test -p dockpanel-agent git_db_link -- --ignored --nocapture"]
    async fn a_linked_app_resolves_db_and_unlink_removes_the_network() {
        use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};
        use bollard::exec::{CreateExecOptions, StartExecResults};
        use tokio_stream::StreamExt;

        let docker = Docker::connect_with_local_defaults().expect("docker connect");
        let tag = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
        let db_name = format!("lnkdbtest{tag}");
        let deploy = format!("lnkdbtest-{tag}");
        let db_container = format!("dockpanel-db-{db_name}");
        let app_container = format!("dockpanel-git-{deploy}");
        let stranger = format!("lnkdbtest-stranger-{tag}");

        let mk = |labels: HashMap<String, String>| Config {
            image: Some("alpine:latest".to_string()),
            cmd: Some(vec!["sleep".to_string(), "120".to_string()]),
            labels: Some(labels),
            ..Default::default()
        };
        let db_labels = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.db.name", &db_name),
        ]);
        let app_labels = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.type", "git"),
            ("dockpanel.git.name", &deploy),
            (crate::services::ownership::GIT_KIND_LABEL, "deploy"),
        ]);

        let result = async {
            let db = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: db_container.as_str(),
                        platform: None,
                    }),
                    mk(db_labels),
                )
                .await
                .map_err(|e| format!("create db: {e}"))?;
            docker
                .start_container::<String>(&db.id, None)
                .await
                .map_err(|e| e.to_string())?;

            let req = LinkedDbRequest {
                container_id: db.id.clone(),
                name: db_name.clone(),
            };
            let verified = verify_db(&docker, &req).await?;
            let network = reconcile(&docker, &deploy, Some(&verified), &[])
                .await?
                .ok_or_else(|| "no network".to_string())?;
            let net = docker
                .inspect_network::<String>(&network, None)
                .await
                .map_err(|e| e.to_string())?;
            if net.internal != Some(true) {
                return Err("link network is not internal".to_string());
            }

            // create -> attach -> start, as create_and_start does.
            let app = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: app_container.as_str(),
                        platform: None,
                    }),
                    mk(app_labels),
                )
                .await
                .map_err(|e| format!("create app: {e}"))?;
            attach(&docker, &network, &app.id, None).await?;
            attach(&docker, &network, &app.id, None).await?; // idempotent
            docker
                .start_container::<String>(&app.id, None)
                .await
                .map_err(|e| e.to_string())?;

            let exec = docker
                .create_exec(
                    &app.id,
                    CreateExecOptions {
                        cmd: Some(vec!["nslookup", "db"]),
                        attach_stdout: Some(true),
                        attach_stderr: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| e.to_string())?;
            if let StartExecResults::Attached { mut output, .. } = docker
                .start_exec(&exec.id, None)
                .await
                .map_err(|e| e.to_string())?
            {
                while output.next().await.is_some() {}
            }
            let code = docker
                .inspect_exec(&exec.id)
                .await
                .map_err(|e| e.to_string())?
                .exit_code;
            if code != Some(0) {
                return Err(format!("`db` did not resolve from the app (exit {code:?})"));
            }

            // A container that does not belong is evicted on the next reconcile.
            let s = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: stranger.as_str(),
                        platform: None,
                    }),
                    mk(HashMap::new()),
                )
                .await
                .map_err(|e| e.to_string())?;
            attach(&docker, &network, &s.id, None).await?;
            reconcile(&docker, &deploy, Some(&verified), &[]).await?;
            if is_attached(&docker, &s.id, &network).await {
                return Err("a stranger stayed on the link network".to_string());
            }
            if !is_attached(&docker, &app.id, &network).await
                || !is_attached(&docker, &db.id, &network).await
            {
                return Err("reconcile evicted a legitimate member".to_string());
            }

            // Unlink removes the network.
            reconcile(&docker, &deploy, None, &[]).await?;
            if docker
                .inspect_network::<String>(&network, None)
                .await
                .is_ok()
            {
                return Err("unlink left the network behind".to_string());
            }
            Ok::<(), String>(())
        }
        .await;

        for c in [&app_container, &db_container, &stranger] {
            let _ = docker
                .remove_container(
                    c,
                    Some(RemoveContainerOptions {
                        v: true,
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
        }
        let _ = docker.remove_network(&link_network_name(&deploy)).await;
        result.expect("linked database drill");
    }

    #[test]
    fn request_shape_is_checked_before_docker_is_asked() {
        let ok = LinkedDbRequest {
            container_id: "a".repeat(64),
            name: "shop_db".into(),
        };
        assert!(validate_request(&ok).is_ok());
        let bad_id = LinkedDbRequest {
            container_id: "../../x".into(),
            name: "shop".into(),
        };
        assert!(validate_request(&bad_id).is_err());
        let bad_name = LinkedDbRequest {
            container_id: "a".repeat(12),
            name: "x; rm".into(),
        };
        assert!(validate_request(&bad_name).is_err());
        let empty = LinkedDbRequest {
            container_id: "a".repeat(12),
            name: String::new(),
        };
        assert!(validate_request(&empty).is_err());
    }

    fn svc(app: &str, alias: &str) -> LinkedServiceRequest {
        LinkedServiceRequest {
            app_name: app.into(),
            alias: alias.into(),
        }
    }

    const OWNER: &str = "6f1c1f0e-8f4a-4b7e-9a51-2c1d1f6c0a01";

    #[test]
    fn linked_service_aliases_are_dns_labels_unique_capped_and_not_db() {
        let ok = [svc("mailpit", "mailpit"), svc("redis-1", "cache")];
        assert!(validate_services(&ok, true, Some(OWNER)).is_ok());
        assert!(validate_services(&[], true, None).is_ok(), "none is always fine");
        let long = "a".repeat(64);
        for bad in ["", "Mailpit", "-x", "x-", "a_b", "a.b", long.as_str()] {
            assert!(
                validate_services(&[svc("mailpit", bad)], false, Some(OWNER)).is_err(),
                "{bad:?} is not a DNS label"
            );
        }
        assert!(
            validate_services(&[svc("pg", "db")], true, Some(OWNER)).is_err(),
            "`db` is the linked database's"
        );
        assert!(
            validate_services(&[svc("pg", "db")], false, Some(OWNER)).is_ok(),
            "`db` is free when no database is linked"
        );
        assert!(
            validate_services(&[svc("a", "x"), svc("b", "x")], false, Some(OWNER)).is_err(),
            "duplicate alias"
        );
        assert!(
            validate_services(&[svc("a", "x"), svc("a", "y")], false, Some(OWNER)).is_err(),
            "same app twice"
        );
        let many: Vec<_> = (0..=MAX_LINKED_SERVICES)
            .map(|i| svc(&format!("a{i}"), &format!("s{i}")))
            .collect();
        assert!(validate_services(&many, false, Some(OWNER)).is_err(), "capped");
        assert!(
            validate_services(&[svc("../x", "x")], false, Some(OWNER)).is_err(),
            "app name"
        );
        assert!(
            validate_services(&ok, false, None).is_err(),
            "an owner is required to prove anything"
        );
        assert!(validate_services(&ok, false, Some("root")).is_err());
    }

    #[test]
    fn the_services_label_round_trips_and_ignores_garbage() {
        let list = vec![svc("mailpit", "mailpit"), svc("redis_1", "cache")];
        let label = encode_services(&list);
        assert_eq!(label, "mailpit=mailpit,cache=redis_1");
        assert_eq!(decode_services(&label), list);
        assert_eq!(
            decode_services("x=,=y,BAD=a,ok=app,junk"),
            vec![svc("app", "ok")]
        );
        assert!(decode_services("").is_empty());
    }

    #[test]
    fn service_identity_requires_name_template_label_and_owner() {
        let good = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.app.template", "mailpit"),
            ("dockpanel.app.name", "mailpit"),
            ("dockpanel.user.id", OWNER),
        ]);
        assert!(
            verify_service_identity("/dockpanel-app-mailpit", Some(&good), "mailpit", OWNER)
                .is_ok()
        );
        // The name says another app.
        assert!(
            verify_service_identity("/dockpanel-app-other", Some(&good), "mailpit", OWNER)
                .is_err()
        );
        // Another owner's app: the whole point.
        assert!(
            verify_service_identity(
                "/dockpanel-app-mailpit",
                Some(&good),
                "mailpit",
                "00000000-0000-0000-0000-000000000000"
            )
            .is_err()
        );
        // No owner label at all (an app deployed before the label existed).
        let unowned = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.app.template", "mailpit"),
        ]);
        assert!(
            verify_service_identity("/dockpanel-app-mailpit", Some(&unowned), "mailpit", OWNER)
                .is_err()
        );
        // Not a template app: a git deploy dressed up by name.
        let git = labels(&[
            ("dockpanel.managed", "true"),
            ("dockpanel.type", "git"),
            ("dockpanel.app.template", "x"),
            ("dockpanel.user.id", OWNER),
        ]);
        assert!(
            verify_service_identity("/dockpanel-app-mailpit", Some(&git), "mailpit", OWNER)
                .is_err()
        );
        let unmanaged = labels(&[
            ("dockpanel.app.template", "mailpit"),
            ("dockpanel.user.id", OWNER),
        ]);
        assert!(
            verify_service_identity("/dockpanel-app-mailpit", Some(&unmanaged), "mailpit", OWNER)
                .is_err()
        );
        assert!(verify_service_identity("/dockpanel-app-mailpit", None, "mailpit", OWNER).is_err());
    }

    fn member(id: &str, l: Option<HashMap<String, String>>, aliases: &[&str]) -> Member {
        Member {
            id: id.into(),
            labels: l,
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn app_labels(name: &str, kind: &str) -> HashMap<String, String> {
        labels(&[
            ("dockpanel.type", "git"),
            ("dockpanel.git.name", name),
            (crate::services::ownership::GIT_KIND_LABEL, kind),
        ])
    }

    fn attach_step(id: &str, alias: &str) -> LinkStep {
        LinkStep::Attach {
            container: id.into(),
            alias: Some(alias.into()),
        }
    }

    fn vsvc(id: &str, alias: &str) -> VerifiedService {
        VerifiedService {
            id: id.into(),
            alias: alias.into(),
        }
    }

    #[test]
    fn plan_keeps_declared_members_attaches_missing_ones_and_evicts_the_rest() {
        let db = VerifiedDb { id: "dbid".into() };
        let services = vec![vsvc("mp1", "mailpit"), vsvc("rd1", "cache")];
        let current = vec![
            member("app1", Some(app_labels("shop", "deploy")), &[]),
            member("dbid", None, &["db"]),
            member("mp1", None, &["mailpit", "mp1"]),
            member("stranger", None, &["mailpit"]),
            member("preview", Some(app_labels("shop", "preview")), &[]),
            member("other", Some(app_labels("blog", "deploy")), &[]),
        ];
        let plan = plan_membership("shop", &current, Some(&db), &services);
        assert_eq!(
            plan,
            vec![
                LinkStep::Disconnect("stranger".into()),
                LinkStep::Disconnect("preview".into()),
                LinkStep::Disconnect("other".into()),
                attach_step("rd1", "cache"),
            ],
            "the app, the db and mailpit stay; a stranger (even one claiming the alias), a \
             preview and another deployment go; the missing service is attached"
        );
    }

    #[test]
    fn plan_reattaches_a_service_whose_alias_changed() {
        let services = vec![vsvc("mp1", "smtp")];
        let current = vec![member("mp1", None, &["mailpit"])];
        assert_eq!(
            plan_membership("shop", &current, None, &services),
            vec![LinkStep::Disconnect("mp1".into()), attach_step("mp1", "smtp")]
        );
    }

    #[test]
    fn plan_finds_a_recreated_service_by_its_new_id_and_evicts_an_unlinked_one() {
        // The app was recreated (update / env edit): new id, the old endpoint
        // is gone with the old container. The plan attaches the new one.
        let services = vec![vsvc("mp2", "mailpit")];
        let current = vec![member("app1", Some(app_labels("shop", "deploy")), &[])];
        assert_eq!(
            plan_membership("shop", &current, None, &services),
            vec![attach_step("mp2", "mailpit")]
        );
        // Unlinked: still on the network, no longer declared - disconnected.
        let current = vec![
            member("app1", Some(app_labels("shop", "deploy")), &[]),
            member("mp2", None, &["mailpit"]),
        ];
        assert_eq!(
            plan_membership("shop", &current, None, &[]),
            vec![LinkStep::Disconnect("mp2".into())]
        );
    }

    #[test]
    fn plan_attaches_the_database_under_db_and_matches_id_prefixes() {
        let db = VerifiedDb {
            id: "dbid0123456789".into(),
        };
        assert_eq!(
            plan_membership("shop", &[], Some(&db), &[]),
            vec![attach_step("dbid0123456789", DB_ALIAS)]
        );
        let current = vec![member("dbid012345", None, &["db"])];
        assert!(plan_membership("shop", &current, Some(&db), &[]).is_empty());
    }

    #[test]
    fn a_services_only_network_is_labelled_for_no_database() {
        let net = network_labels("shop", "");
        assert!(!points_elsewhere(Some(&net), ""), "services only, still services only");
        assert!(points_elsewhere(Some(&net), "dbid"), "a database linked later rebuilds it");
        let with_db = network_labels("shop", "dbid");
        assert!(points_elsewhere(Some(&with_db), ""), "unlinking the database rebuilds it");
    }

    async fn exec_ok(docker: &Docker, container: &str, cmd: &[&str]) -> Result<bool, String> {
        use bollard::exec::{CreateExecOptions, StartExecResults};
        use tokio_stream::StreamExt;
        let exec = docker
            .create_exec(
                container,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        if let StartExecResults::Attached { mut output, .. } = docker
            .start_exec(&exec.id, None)
            .await
            .map_err(|e| e.to_string())?
        {
            while output.next().await.is_some() {}
        }
        Ok(docker
            .inspect_exec(&exec.id)
            .await
            .map_err(|e| e.to_string())?
            .exit_code
            == Some(0))
    }

    /// `nc -z host port` from `container`, retried while the target starts.
    async fn reachable(docker: &Docker, container: &str, host: &str, port: &str) -> bool {
        for _ in 0..20 {
            if exec_ok(docker, container, &["nc", "-z", "-w", "2", host, port])
                .await
                .unwrap_or(false)
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        false
    }

    /// LINKED SERVICES against a REAL Docker daemon: a mailpit template app
    /// (`axllent/mailpit`, SMTP on 1025) linked as `mailpit`, reachable with
    /// `nc -z mailpit 1025` from the app container; still reachable after the
    /// app is redeployed (new container), after `docker restart` of mailpit,
    /// after mailpit is RECREATED through the real `docker_apps::update_env`
    /// path, and after it is removed and redeployed under the same name; an
    /// alias change takes effect; and unlinking leaves mailpit running.
    /// Needs `axllent/mailpit:latest` and `alpine:latest` locally. Disposable
    /// names only (`*svclnk*`), all removed whatever the outcome.
    #[tokio::test]
    #[ignore = "creates real containers and a real network; run with cargo test -p dockpanel-agent git_db_link -- --ignored --nocapture"]
    async fn a_linked_mailpit_stays_reachable_across_redeploys_restarts_and_recreates() {
        use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};

        let docker = Docker::connect_with_local_defaults().expect("docker connect");
        let tag = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
        let app_name = format!("svclnk{tag}");
        let deploy = format!("svclnk-{tag}");
        let mailpit_container = format!("{APP_CONTAINER_PREFIX}{app_name}");
        let git_container = format!("dockpanel-git-{deploy}");
        let network = link_network_name(&deploy);
        let owner = uuid::Uuid::new_v4().to_string();

        async fn remove(docker: &Docker, c: &str) {
            let _ = docker
                .remove_container(
                    c,
                    Some(RemoveContainerOptions {
                        v: true,
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
        }

        async fn create_mailpit(
            docker: &Docker,
            container: &str,
            app_name: &str,
            owner: &str,
        ) -> Result<String, String> {
            let c = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: container,
                        platform: None,
                    }),
                    Config {
                        image: Some("axllent/mailpit:latest".to_string()),
                        labels: Some(labels(&[
                            ("dockpanel.managed", "true"),
                            ("dockpanel.app.template", "mailpit"),
                            ("dockpanel.app.name", app_name),
                            ("dockpanel.user.id", owner),
                        ])),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| format!("create mailpit: {e}"))?;
            docker
                .start_container::<String>(&c.id, None)
                .await
                .map_err(|e| e.to_string())?;
            Ok(c.id)
        }

        // One deploy, as `deploy_or_update` does it: prove, reconcile, then
        // create -> attach -> start a NEW app container.
        async fn deploy_app(
            docker: &Docker,
            deploy: &str,
            git_container: &str,
            req: &[LinkedServiceRequest],
            owner: &str,
        ) -> Result<String, String> {
            let services = verify_services(docker, req, Some(owner)).await?;
            let net = reconcile(docker, deploy, None, &services)
                .await?
                .ok_or("no network")?;
            remove(docker, git_container).await;
            let c = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: git_container,
                        platform: None,
                    }),
                    Config {
                        image: Some("alpine:latest".to_string()),
                        cmd: Some(vec!["sleep".to_string(), "300".to_string()]),
                        labels: Some(labels(&[
                            ("dockpanel.managed", "true"),
                            ("dockpanel.type", "git"),
                            ("dockpanel.git.name", deploy),
                            (crate::services::ownership::GIT_KIND_LABEL, "deploy"),
                        ])),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| format!("create app: {e}"))?;
            attach(docker, &net, &c.id, None).await?;
            docker
                .start_container::<String>(&c.id, None)
                .await
                .map_err(|e| e.to_string())?;
            Ok(c.id)
        }

        let req = vec![svc(&app_name, "mailpit")];
        let result = async {
            let mp = create_mailpit(&docker, &mailpit_container, &app_name, &owner).await?;
            if verify_services(&docker, &req, Some("00000000-0000-0000-0000-000000000000"))
                .await
                .is_ok()
            {
                return Err("another owner's deploy could link this mailpit".to_string());
            }

            let app = deploy_app(&docker, &deploy, &git_container, &req, &owner).await?;
            if !reachable(&docker, &app, "mailpit", "1025").await {
                return Err("nc -z mailpit 1025 failed after the first deploy".to_string());
            }
            println!("ok: nc -z mailpit 1025 after the first deploy");
            let endpoint_id = |c: String| {
                let docker = &docker;
                let network = &network;
                async move {
                    docker
                        .inspect_container(&c, None)
                        .await
                        .ok()
                        .and_then(|i| i.network_settings)
                        .and_then(|ns| ns.networks)
                        .and_then(|n| n.get(network).cloned())
                        .and_then(|ep| ep.endpoint_id)
                }
            };
            let first_endpoint = endpoint_id(mp.clone()).await;

            // Redeploy: a NEW app container, same declaration.
            let app = deploy_app(&docker, &deploy, &git_container, &req, &owner).await?;
            if !reachable(&docker, &app, "mailpit", "1025").await {
                return Err("mailpit unreachable after the app redeployed".to_string());
            }
            // An identical redeploy must not churn the service's endpoint: the
            // plan reads the real aliases and leaves a satisfied member alone.
            if first_endpoint.is_none() || endpoint_id(mp.clone()).await != first_endpoint {
                return Err("an identical redeploy disconnected and re-attached mailpit".to_string());
            }
            println!("ok: reachable after the app redeployed, mailpit's endpoint untouched");

            // Restart of the service: Docker keeps the endpoint and alias.
            docker
                .restart_container(&mp, None)
                .await
                .map_err(|e| e.to_string())?;
            if !reachable(&docker, &app, "mailpit", "1025").await {
                return Err("mailpit unreachable after docker restart".to_string());
            }
            println!("ok: reachable after docker restart of mailpit");

            // Recreate through the REAL template-app path (env edit): new id,
            // the link network and alias come back via plan_recreate_networks,
            // and the default bridge stays the primary.
            let mp2 = crate::services::docker_apps::update_env(&mp, HashMap::new()).await?;
            if mp2 == mp {
                return Err("update_env did not recreate the container".to_string());
            }
            if !reachable(&docker, &app, "mailpit", "1025").await {
                return Err("mailpit unreachable after update_env recreated it".to_string());
            }
            let mode = docker
                .inspect_container(&mp2, None)
                .await
                .map_err(|e| e.to_string())?
                .host_config
                .and_then(|h| h.network_mode)
                .unwrap_or_default();
            if mode.starts_with(LINK_NETWORK_PREFIX) {
                return Err(format!("the recreated service runs with network mode {mode}"));
            }
            println!("ok: reachable after update_env recreated mailpit (network mode {mode})");

            // Removed and deployed again under the same name: not attached any
            // more, until the next reconcile (the next deploy, or agent start).
            remove(&docker, &mp2).await;
            let mp3 = create_mailpit(&docker, &mailpit_container, &app_name, &owner).await?;
            if is_attached(&docker, &mp3, &network).await {
                return Err("a brand-new container cannot already be linked".to_string());
            }
            let app = deploy_app(&docker, &deploy, &git_container, &req, &owner).await?;
            if !reachable(&docker, &app, "mailpit", "1025").await {
                return Err("mailpit unreachable after redeploy of a recreated app".to_string());
            }
            println!("ok: reachable again after mailpit was removed, redeployed, and the app deployed");

            // A changed alias takes effect.
            let renamed = vec![svc(&app_name, "smtp")];
            let app = deploy_app(&docker, &deploy, &git_container, &renamed, &owner).await?;
            if !reachable(&docker, &app, "smtp", "1025").await {
                return Err("new alias smtp does not resolve".to_string());
            }
            if exec_ok(&docker, &app, &["nslookup", "mailpit"]).await? {
                return Err("the old alias still resolves".to_string());
            }
            println!("ok: alias change mailpit -> smtp");

            // Unlink everything (= the deploy removed): the network is
            // removed, mailpit is disconnected and still running.
            reconcile(&docker, &deploy, None, &[]).await?;
            if docker.inspect_network::<String>(&network, None).await.is_ok() {
                return Err("unlink left the network behind".to_string());
            }
            let running = docker
                .inspect_container(&mp3, None)
                .await
                .map_err(|e| format!("mailpit was removed: {e}"))?
                .state
                .and_then(|s| s.running);
            if running != Some(true) {
                return Err("unlinking stopped mailpit".to_string());
            }
            println!("ok: unlink removed the network, mailpit still running");
            Ok::<(), String>(())
        }
        .await;

        remove(&docker, &git_container).await;
        remove(&docker, &mailpit_container).await;
        let _ = docker.remove_network(&network).await;
        result.expect("linked services drill");
    }
}
