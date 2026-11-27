//! The panel half of a Git Deploy's LINKED SERVICES.
//!
//! A linked service is a panel-managed template app (`dockpanel-app-{name}`,
//! for example a mailpit mail catcher) that the deployment's app reaches by a
//! DNS alias of its choosing (`mailpit`) on the deployment's dedicated link
//! network - the same network a linked database answers on as `db` (see
//! `git_db_link`). The agent half is `panel/agent/src/services/git_db_link.rs`,
//! LINKED SERVICES.
//!
//!   * **Ownership, strictly.** An app is linkable only by the account whose id
//!     it carries in its `dockpanel.user.id` label (stamped by `deploy_app`),
//!     on the server the deployment runs on. An app with no owner label is
//!     nobody's and is refused. Checked when the link is saved - through the
//!     agent of the DEPLOYMENT's server, never the caller's switcher - and
//!     again by the agent at every deploy, which proves the container's name
//!     and labels against the deployment's owner before attaching anything.
//!   * **A stable reference.** Rows store the app's NAME, not a container id: a
//!     template app is recreated (new id) by every update, image change and
//!     environment edit.
//!   * **Never for a preview**, exactly like the linked database.
//!   * **Nothing injected.** Unlike a database there are no credentials to hand
//!     over: the app is told the alias (in the form, and in the guide), and the
//!     user sets `EMAIL_HOST=mailpit` themselves.

use sqlx::PgPool;
use uuid::Uuid;

/// Must match the agent's `git_db_link::MAX_LINKED_SERVICES`.
pub(crate) const MAX_LINKED_SERVICES: usize = 8;

/// The container name prefix `docker_apps::deploy_app` gives a template app.
pub(crate) const APP_CONTAINER_PREFIX: &str = "dockpanel-app-";

/// One linked service, as stored and as sent on the wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkedService {
    /// The app's name (its container is `dockpanel-app-{app_name}`). The wire
    /// also accepts the container name; it is stored without the prefix.
    pub app_name: String,
    /// The DNS name the app answers to on the link network.
    pub alias: String,
}

fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_app_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Normalise and validate what the wire sent: app names without the container
/// prefix, aliases trimmed and lowercased, every alias a DNS label, unique, not
/// `db` while a database is linked, no app twice, at most
/// [`MAX_LINKED_SERVICES`]. `db_linked` is the deployment's FINAL state after
/// this request, so linking a database onto a deployment whose service already
/// answers as `db` is refused too.
pub(crate) fn normalize(
    input: &[LinkedService],
    db_linked: bool,
) -> Result<Vec<LinkedService>, String> {
    if input.len() > MAX_LINKED_SERVICES {
        return Err(format!(
            "At most {MAX_LINKED_SERVICES} linked services per deployment"
        ));
    }
    let mut out: Vec<LinkedService> = Vec::with_capacity(input.len());
    for s in input {
        let app = s.app_name.trim();
        let app = app.strip_prefix(APP_CONTAINER_PREFIX).unwrap_or(app);
        let alias = s.alias.trim().to_ascii_lowercase();
        if !is_app_name(app) {
            return Err(format!("Invalid linked service app name: {:?}", s.app_name));
        }
        if !is_dns_label(&alias) {
            return Err(format!(
                "Invalid alias {:?} for {app}: lowercase letters, digits and '-', 1-63 \
                 characters, not starting or ending with '-'",
                s.alias
            ));
        }
        if db_linked && alias == crate::services::git_db_link::DB_HOST {
            return Err(format!(
                "The alias \"db\" is the linked database's; pick another alias for {app}"
            ));
        }
        if out.iter().any(|o| o.alias == alias) {
            return Err(format!("The alias {alias:?} is used twice"));
        }
        if out.iter().any(|o| o.app_name == app) {
            return Err(format!("The app {app} is linked twice"));
        }
        out.push(LinkedService {
            app_name: app.to_string(),
            alias,
        });
    }
    Ok(out)
}

/// Would linking a database collide with an alias already stored?
pub(crate) fn db_alias_conflict(stored: &[LinkedService]) -> Option<String> {
    stored
        .iter()
        .find(|s| s.alias == crate::services::git_db_link::DB_HOST)
        .map(|s| {
            format!(
                "The linked service {} answers as \"db\", which a linked database needs. Give \
                 it another alias first.",
                s.app_name
            )
        })
}

/// The owner a `/apps` entry carries, if any (`docker_apps::app_owner`).
fn owner_of(app: &serde_json::Value) -> Option<Uuid> {
    app.get("user_id")?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// The template apps `owner` may link, from the agent's `/apps` listing:
/// named `dockpanel-app-*`, carrying `owner` in their owner label.
pub(crate) fn owned_apps(apps: &serde_json::Value, owner: Uuid) -> Vec<serde_json::Value> {
    apps.as_array()
        .into_iter()
        .flatten()
        .filter(|a| owner_of(a) == Some(owner))
        .filter_map(|a| {
            let container = a.get("name")?.as_str()?;
            let app_name = container.strip_prefix(APP_CONTAINER_PREFIX)?;
            if !is_app_name(app_name) {
                return None;
            }
            Some(serde_json::json!({
                "app_name": app_name,
                "container_name": container,
                "template": a.get("template").cloned().unwrap_or(serde_json::Value::Null),
                "status": a.get("status").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect()
}

/// Save-time check against the listing. An app that exists but belongs to
/// someone else answers exactly like one that does not exist.
pub(crate) fn check_owned(
    apps: &serde_json::Value,
    services: &[LinkedService],
    owner: Uuid,
) -> Result<(), String> {
    let mine = owned_apps(apps, owner);
    for s in services {
        if !mine
            .iter()
            .any(|a| a.get("app_name").and_then(|v| v.as_str()) == Some(s.app_name.as_str()))
        {
            return Err(format!(
                "App {} not found among your apps on this deployment's server",
                s.app_name
            ));
        }
    }
    Ok(())
}

/// [`check_owned`], asking the agent of the deployment's own server.
pub(crate) async fn check_linkable(
    agents: &crate::services::agent::AgentRegistry,
    server_id: Uuid,
    services: &[LinkedService],
    owner: Uuid,
) -> Result<(), String> {
    if services.is_empty() {
        return Ok(());
    }
    let agent = agents
        .for_server(server_id)
        .await
        .map_err(|e| format!("Could not reach this deployment's server to check its apps: {e}"))?;
    let apps = agent
        .get("/apps")
        .await
        .map_err(|e| format!("Could not list this deployment's server's apps: {e}"))?;
    check_owned(&apps, services, owner)
}

/// The stored column (`GIT_DEPLOY_SELECT`'s `linked_services`), parsed.
pub(crate) fn from_column(v: &serde_json::Value) -> Vec<LinkedService> {
    serde_json::from_value(v.clone()).unwrap_or_default()
}

/// The subquery `GIT_DEPLOY_SELECT` and [`load_json`] read the links through.
pub(crate) const LINKED_SERVICES_JSON: &str = "COALESCE((SELECT jsonb_agg(jsonb_build_object(\
     'app_name', ls.app_name, 'alias', ls.alias) ORDER BY ls.alias) \
     FROM git_deploy_linked_services ls WHERE ls.deploy_id = d.id), '[]'::jsonb)";

/// The links of one deployment, as the API returns them.
pub(crate) async fn load_json(db: &PgPool, deploy_id: Uuid) -> serde_json::Value {
    sqlx::query_scalar::<_, serde_json::Value>(&format!(
        "SELECT {LINKED_SERVICES_JSON} FROM git_deploys d WHERE d.id = $1"
    ))
    .bind(deploy_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| serde_json::json!([]))
}

/// Replace a deployment's links with `services`, atomically.
pub(crate) async fn replace(
    db: &PgPool,
    deploy_id: Uuid,
    services: &[LinkedService],
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM git_deploy_linked_services WHERE deploy_id = $1")
        .bind(deploy_id)
        .execute(&mut *tx)
        .await?;
    for s in services {
        sqlx::query(
            "INSERT INTO git_deploy_linked_services (deploy_id, app_name, alias) VALUES ($1, $2, $3)",
        )
        .bind(deploy_id)
        .bind(&s.app_name)
        .bind(&s.alias)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// An app was removed from `server_id`: no deployment there links it any more.
/// The agent has already dropped its endpoints with the container; this keeps
/// the next deploy from refusing over an app that is gone.
pub(crate) async fn forget_app(db: &PgPool, server_id: Uuid, container_name: &str) {
    let app = container_name
        .strip_prefix(APP_CONTAINER_PREFIX)
        .unwrap_or(container_name);
    if let Err(e) = sqlx::query(
        "DELETE FROM git_deploy_linked_services ls USING git_deploys d \
         WHERE ls.deploy_id = d.id AND d.server_id = $1 AND ls.app_name = $2",
    )
    .bind(server_id)
    .bind(app)
    .execute(db)
    .await
    {
        tracing::warn!("Could not unlink removed app {app} from its Git Deploys: {e}");
    }
}

/// The deploy for a link, as `build_deploy_body` sends it.
pub(crate) struct ServiceLinks<'a> {
    pub owner: Uuid,
    pub services: &'a [LinkedService],
}

/// Write `linked_services` + `link_owner` onto the agent's deploy body.
pub(crate) fn agent_fields(body: &mut serde_json::Value, links: &ServiceLinks<'_>) {
    if links.services.is_empty() {
        return;
    }
    body["linked_services"] = serde_json::json!(links.services);
    body["link_owner"] = serde_json::json!(links.owner.to_string());
}

/// Did the agent confirm the services it was asked to link? An agent that
/// predates the field ignores it and deploys anyway.
pub(crate) fn confirmed(requested: bool, agent_response: &serde_json::Value) -> Result<(), String> {
    if !requested {
        return Ok(());
    }
    match agent_response
        .get("linked_services_network")
        .and_then(|v| v.as_str())
    {
        Some(n) if !n.is_empty() => Ok(()),
        _ => Err(
            "The container was deployed but its server's agent did not attach the linked \
             services (it predates linked services), so the app cannot reach them by alias. \
             Update that server's agent, then deploy again."
                .to_string(),
        ),
    }
}

/// [`confirmed`] applied to the agent call, like `git_db_link::require_confirmed`.
pub(crate) fn require_confirmed(
    requested: bool,
    outcome: Result<serde_json::Value, crate::services::agent::AgentError>,
) -> Result<serde_json::Value, crate::services::agent::AgentError> {
    let value = outcome?;
    confirmed(requested, &value).map_err(crate::services::agent::AgentError::Response)?;
    Ok(value)
}

/// A compose deploy does not go through `/git/deploy`, so it would run
/// WITHOUT the linked services. Refused instead, with the way out.
pub(crate) fn compose_refusal(services: &[LinkedService]) -> Option<String> {
    (!services.is_empty()).then(|| {
        "This deployment has linked services, and its repository holds a compose file: a \
         compose deploy does not attach linked services. Remove the compose file (the \
         Dockerfile build supports them), or unlink the services."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(app: &str, alias: &str) -> LinkedService {
        LinkedService {
            app_name: app.into(),
            alias: alias.into(),
        }
    }

    #[test]
    fn aliases_are_normalised_and_validated() {
        let got = normalize(&[s(" dockpanel-app-mailpit ", " MailPit ")], false).unwrap();
        assert_eq!(got, vec![s("mailpit", "mailpit")], "prefix stripped, alias lowercased");
        let long = "a".repeat(64);
        for bad in ["", "-x", "x-", "a_b", "a.b", "a b", long.as_str()] {
            assert!(normalize(&[s("mailpit", bad)], false).is_err(), "{bad:?}");
        }
        assert!(normalize(&[s("../etc", "x")], false).is_err());
        assert!(normalize(&[], true).unwrap().is_empty());
    }

    #[test]
    fn db_is_reserved_only_while_a_database_is_linked() {
        assert!(normalize(&[s("pg", "db")], true).is_err());
        assert!(normalize(&[s("pg", "db")], false).is_ok());
        assert!(db_alias_conflict(&[s("pg", "db")]).is_some());
        assert!(db_alias_conflict(&[s("mailpit", "mailpit")]).is_none());
    }

    #[test]
    fn duplicates_and_too_many_are_refused() {
        assert!(normalize(&[s("a", "x"), s("b", "x")], false).is_err());
        assert!(normalize(&[s("a", "x"), s("dockpanel-app-a", "y")], false).is_err());
        let many: Vec<_> = (0..=MAX_LINKED_SERVICES)
            .map(|i| s(&format!("a{i}"), &format!("s{i}")))
            .collect();
        assert!(normalize(&many, false).is_err());
        assert!(normalize(&many[..MAX_LINKED_SERVICES], false).is_ok());
    }

    #[test]
    fn only_the_owners_template_apps_are_linkable() {
        let me = Uuid::new_v4();
        let them = Uuid::new_v4();
        let apps = serde_json::json!([
            { "name": "dockpanel-app-mailpit", "user_id": me.to_string(), "template": "mailpit" },
            { "name": "dockpanel-app-theirs", "user_id": them.to_string(), "template": "mailpit" },
            { "name": "dockpanel-app-legacy", "template": "redis" },
            { "name": "some-compose-svc", "user_id": me.to_string(), "template": "compose" },
        ]);
        let mine = owned_apps(&apps, me);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0]["app_name"], "mailpit");
        assert!(check_owned(&apps, &[s("mailpit", "mailpit")], me).is_ok());
        let theirs = check_owned(&apps, &[s("theirs", "mail")], me).unwrap_err();
        let missing = check_owned(&apps, &[s("nope", "mail")], me).unwrap_err();
        assert_eq!(
            theirs.replace("theirs", "X"),
            missing.replace("nope", "X"),
            "another owner's app answers exactly like a missing one"
        );
        assert!(
            check_owned(&apps, &[s("legacy", "cache")], me).is_err(),
            "an app with no owner label is nobody's"
        );
        assert!(check_owned(&apps, &[s("mailpit", "m")], them).is_err());
    }

    #[test]
    fn the_agent_gets_the_services_and_the_owner_and_must_confirm_them() {
        let owner = Uuid::new_v4();
        let list = vec![s("mailpit", "mailpit")];
        let mut body = serde_json::json!({});
        agent_fields(&mut body, &ServiceLinks { owner, services: &[] });
        assert!(body.get("linked_services").is_none(), "nothing sent when none");
        agent_fields(&mut body, &ServiceLinks { owner, services: &list });
        assert_eq!(body["linked_services"][0]["app_name"], "mailpit");
        assert_eq!(body["linked_services"][0]["alias"], "mailpit");
        assert_eq!(body["link_owner"], owner.to_string());

        assert!(confirmed(false, &serde_json::json!({})).is_ok());
        assert!(confirmed(true, &serde_json::json!({ "container_id": "x" })).is_err());
        assert!(
            confirmed(
                true,
                &serde_json::json!({ "linked_services_network": "dockpanel-link-shop" })
            )
            .is_ok()
        );
    }

    #[test]
    fn a_compose_deploy_with_services_is_refused_not_run_unlinked() {
        assert!(compose_refusal(&[]).is_none());
        assert!(compose_refusal(&[s("mailpit", "mailpit")]).is_some());
    }

    #[test]
    fn the_stored_column_parses_and_garbage_reads_as_none() {
        let v = serde_json::json!([{ "app_name": "mailpit", "alias": "mailpit" }]);
        assert_eq!(from_column(&v), vec![s("mailpit", "mailpit")]);
        assert!(from_column(&serde_json::Value::Null).is_empty());
    }
}
