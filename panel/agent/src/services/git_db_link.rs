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

use bollard::container::ListContainersOptions;
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, DisconnectNetworkOptions};
use bollard::Docker;
use std::collections::HashMap;

/// The name the linked database answers to on the link network.
pub const DB_ALIAS: &str = "db";

/// On the link network: the deployment it belongs to.
pub const LINK_LABEL: &str = "dockpanel.git.link";

/// On the link network AND on the app container: the database container's id.
/// Docker labels are immutable, so a re-pointed link is a recreated network.
pub const LINK_DB_LABEL: &str = "dockpanel.git.link.db";

/// The network a deployment named `name` is linked through.
pub fn link_network_name(name: &str) -> String {
    format!("dockpanel-link-{name}")
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
        && req.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
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
    labels.and_then(|l| l.get(LINK_DB_LABEL)).map(String::as_str) != Some(db_id)
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
    pub db_name: String,
}

/// Prove the requested container is the managed database the panel named.
pub async fn verify_db(docker: &Docker, req: &LinkedDbRequest) -> Result<VerifiedDb, String> {
    let info = docker.inspect_container(&req.container_id, None).await.map_err(|e| {
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
        db_name: req.name.clone(),
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
        .connect_network(network, ConnectNetworkOptions { container, endpoint_config })
        .await
        .map_err(|e| format!("Failed to attach {container} to {network}: {e}"))
}

/// Disconnect everything from a link network we own and remove it.
async fn remove_network(docker: &Docker, network: &str, attached: &[String]) -> Result<(), String> {
    for cid in attached {
        let _ = docker
            .disconnect_network(network, DisconnectNetworkOptions { container: cid.as_str(), force: true })
            .await;
    }
    docker
        .remove_network(network)
        .await
        .map_err(|e| format!("Failed to remove {network}: {e}"))?;
    tracing::info!("Removed link network {network}");
    Ok(())
}

fn attached_ids(net: &bollard::models::Network) -> Vec<String> {
    net.containers
        .as_ref()
        .map(|c| c.keys().cloned().collect())
        .unwrap_or_default()
}

async fn create_network(docker: &Docker, network: &str, name: &str, db_id: &str) -> Result<(), String> {
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

/// Bring `name`'s link network to the desired state and return its name.
///
/// * `desired = None` - no database is linked: a link network left by an
///   earlier deploy is torn down (the unlink case, and every deploy of a
///   deployment that never had one, where it is a single failed inspect).
/// * `desired = Some(db)` - the network exists, labelled for THIS database,
///   with the database attached under [`DB_ALIAS`], and nothing else on it but
///   this deployment's own containers. The app is attached by the caller,
///   between create and start of the container it is about to run.
///
/// Called before anything destructive in `deploy_or_update`, so a refusal here
/// (a database that is not what the panel said, a network that is not ours)
/// leaves the running app exactly as it was.
pub async fn reconcile(
    docker: &Docker,
    name: &str,
    desired: Option<&VerifiedDb>,
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

    let Some(db) = desired else {
        if let Some(net) = existing {
            remove_network(docker, &network, &attached_ids(&net)).await?;
        }
        return Ok(None);
    };

    match existing {
        Some(ref net) if points_elsewhere(net.labels.as_ref(), &db.id) => {
            // Re-pointed at another database. Labels are immutable, so the
            // network is rebuilt; the app is re-attached by the caller.
            remove_network(docker, &network, &attached_ids(net)).await?;
            create_network(docker, &network, name, &db.id).await?;
        }
        Some(ref net) => {
            // Same database. Enforce the membership rule before going on.
            for cid in attached_ids(net) {
                let labels = docker
                    .inspect_container(&cid, None)
                    .await
                    .ok()
                    .and_then(|c| c.config)
                    .and_then(|c| c.labels);
                if !may_stay(&cid, labels.as_ref(), name, Some(&db.id)) {
                    tracing::warn!("Disconnecting stray container {cid} from link network {network}");
                    let _ = docker
                        .disconnect_network(&network, DisconnectNetworkOptions { container: cid.as_str(), force: true })
                        .await;
                }
            }
        }
        None => create_network(docker, &network, name, &db.id).await?,
    }

    attach(docker, &network, &db.id, Some(DB_ALIAS)).await?;
    Ok(Some(network))
}

/// Tear down every link network a database container is attached to. Called
/// by `database::remove_database` before the container goes - Docker would
/// detach it anyway, but the network would then be left holding the app alone,
/// and the app's next deploy is the only thing that would ever notice.
pub async fn release_for_database(docker: &Docker, db_container_id: &str) {
    let Ok(info) = docker.inspect_container(db_container_id, None).await else {
        return;
    };
    let nets: Vec<String> = info
        .network_settings
        .and_then(|ns| ns.networks)
        .map(|n| n.keys().cloned().collect())
        .unwrap_or_default();
    for network in nets.into_iter().filter(|n| n.starts_with("dockpanel-link-")) {
        let Ok(net) = docker.inspect_network::<String>(&network, None).await else {
            continue;
        };
        let owner = net.labels.as_ref().and_then(|l| l.get(LINK_LABEL)).cloned();
        match owner {
            Some(name) if network_is_ours(net.labels.as_ref(), &name) => {
                if let Err(e) = remove_network(docker, &network, &attached_ids(&net)).await {
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
    let filters = HashMap::from([("label", vec![LINK_DB_LABEL])]);
    let Ok(apps) = docker
        .list_containers(Some(ListContainersOptions { all: true, filters, ..Default::default() }))
        .await
    else {
        return;
    };
    for app in apps {
        let Some(labels) = app.labels.as_ref() else { continue };
        let (Some(name), Some(db_id), Some(app_id)) = (
            labels.get("dockpanel.git.name"),
            labels.get(LINK_DB_LABEL),
            app.id.as_deref(),
        ) else {
            continue;
        };
        if labels.get(super::ownership::GIT_KIND_LABEL).map(String::as_str) != Some("deploy") {
            continue; // a preview is never linked; never act on one that claims to be
        }
        let db_name = match docker.inspect_container(db_id, None).await {
            Ok(db) => db
                .config
                .and_then(|c| c.labels)
                .and_then(|l| l.get("dockpanel.db.name").cloned()),
            Err(_) => None,
        };
        let Some(db_name) = db_name else {
            tracing::warn!(
                "Linked database {db_id} of git deploy {name} is gone; leaving it unlinked \
                 until its next deploy"
            );
            continue;
        };
        let req = LinkedDbRequest { container_id: db_id.clone(), name: db_name };
        let result = async {
            let db = verify_db(&docker, &req).await?;
            let network = reconcile(&docker, name, Some(&db)).await?.unwrap_or_default();
            attach(&docker, &network, app_id, None).await
        }
        .await;
        if let Err(e) = result {
            tracing::warn!("Could not re-attach git deploy {name} to its database: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
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
        assert!(!network_is_ours(Some(&ours), "shop-2"), "another deployment's network");
        assert!(!network_is_ours(None, "shop"), "an unlabelled network is nobody's to remove");
        let unmanaged = labels(&[(LINK_LABEL, "shop")]);
        assert!(!network_is_ours(Some(&unmanaged), "shop"), "managed=true is required too");
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
        let good = labels(&[("dockpanel.managed", "true"), ("dockpanel.db.name", "shopdb")]);
        assert!(verify_db_identity("/dockpanel-db-shopdb", Some(&good), "shopdb").is_ok());
        // An id the panel holds that now names another container.
        assert!(verify_db_identity("/dockpanel-git-shop", Some(&good), "shopdb").is_err());
        // Right name, but not one of ours.
        let stranger = labels(&[("dockpanel.db.name", "shopdb")]);
        assert!(verify_db_identity("/dockpanel-db-shopdb", Some(&stranger), "shopdb").is_err());
        let other_db = labels(&[("dockpanel.managed", "true"), ("dockpanel.db.name", "other")]);
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
        assert!(may_stay("dbid", None, "shop", Some("dbid")), "the linked database itself");
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
        assert!(!may_stay("c3", Some(&preview), "shop", Some("dbid")), "a preview never joins");
        assert!(!may_stay("c4", None, "shop", Some("dbid")));
        assert!(!may_stay("otherdb", None, "shop", Some("dbid")), "a second database");
    }

    #[test]
    fn request_shape_is_checked_before_docker_is_asked() {
        let ok = LinkedDbRequest { container_id: "a".repeat(64), name: "shop_db".into() };
        assert!(validate_request(&ok).is_ok());
        let bad_id = LinkedDbRequest { container_id: "../../x".into(), name: "shop".into() };
        assert!(validate_request(&bad_id).is_err());
        let bad_name = LinkedDbRequest { container_id: "a".repeat(12), name: "x; rm".into() };
        assert!(validate_request(&bad_name).is_err());
        let empty = LinkedDbRequest { container_id: "a".repeat(12), name: String::new() };
        assert!(validate_request(&empty).is_err());
    }
}
