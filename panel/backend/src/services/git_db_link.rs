//! The panel half of a Git Deploy's LINKED DATABASE.
//!
//! The agent half (`panel/agent/src/services/git_db_link.rs`) builds a
//! dedicated, single-deployment Docker network on which the database answers
//! as `db`. This half decides WHETHER a deployment may be linked to a database
//! and WHAT the app is told about it:
//!
//!   * **Ownership, strictly.** A database is linkable only by the account that
//!     owns it (through its site or its stack - `chk_databases_owner`), on the
//!     server the deployment runs on, and only if it is a container the agent
//!     can attach. The admin-widened predicate `databases::list` uses to SHOW a
//!     tenant's database to an administrator is deliberately not used here:
//!     seeing a database is not owning it, and a link puts the app and the
//!     database on one network with inter-container communication enabled.
//!     Checked when the link is saved AND again at every deploy, because a
//!     site can change hands between the two.
//!   * **Credentials stay sealed at rest.** The password is decrypted from
//!     `databases.db_password_enc` at deploy time, merged into the environment
//!     sent to the agent, and never written to `git_deploys.env_vars` (a plain
//!     JSONB column that previews clone) nor to the encrypted history snapshot.
//!   * **The user's own value wins.** Every injected variable is added only if
//!     the deployment's environment does not already define it.
//!   * **Never for a preview.** A preview runs whatever branch was pushed; the
//!     preview path passes no link, and the agent refuses one for that scope.

use sqlx::PgPool;
use uuid::Uuid;

/// The alias the database answers to on the link network. Must match the
/// agent's `git_db_link::DB_ALIAS`.
pub(crate) const DB_HOST: &str = "db";

/// A database proven linkable and opened for one deploy.
#[derive(Clone)]
pub(crate) struct LinkedDb {
    pub container_id: String,
    pub name: String,
    pub engine: String,
    pub db_user: String,
    pub password: String,
}

/// `(id, name, engine, db_user, db_password_enc, container_id, kind, imported_hash)`
type LinkRow = (
    Uuid,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    bool,
);

/// The one ownership predicate, shared by the save-time check and the
/// deploy-time load so the two can never disagree.
const LINKABLE_SELECT: &str = "SELECT d.id, d.name, d.engine, d.db_user, d.db_password_enc, \
     d.container_id, d.kind, d.imported_hash \
     FROM databases d \
     LEFT JOIN sites s ON d.site_id = s.id \
     LEFT JOIN docker_stacks st ON d.stack_id = st.id \
     WHERE d.id = $1 \
     AND COALESCE(s.user_id, st.user_id) = $2 \
     AND COALESCE(s.server_id, st.server_id) = $3";

/// What the wire said about `database_id` on a create or an update.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkChange {
    /// Key absent: keep whatever is stored.
    Keep,
    /// Key sent as `""`: unlink.
    Clear,
    /// Key sent with an id: link to that database.
    Set(Uuid),
}

/// Three states on the wire, the same contract as every clearable field on
/// this API (see `clearable-fields-pin-e2e.sh`): absent keeps, `""` clears, a
/// value sets. An unparseable id is refused rather than read as "clear".
pub(crate) fn parse_change(raw: Option<&str>) -> Result<LinkChange, &'static str> {
    match raw.map(str::trim) {
        None => Ok(LinkChange::Keep),
        Some("") => Ok(LinkChange::Clear),
        Some(v) => Uuid::parse_str(v)
            .map(LinkChange::Set)
            .map_err(|_| "database_id must be the id of one of your databases, or empty to unlink"),
    }
}

/// Why a row the owner query found still cannot be linked, if it cannot.
fn refusal(row: &LinkRow) -> Option<String> {
    let (_, name, engine, _, _, container_id, kind, imported_hash) = row;
    if kind != "container" {
        return Some(format!(
            "{name} lives on the server's shared local MariaDB, not in a container, so it \
             cannot be linked to a Git Deploy."
        ));
    }
    if *imported_hash {
        return Some(format!(
            "{name}'s password is only known as the hash it was imported with. Reset its \
             password under Databases, then link it."
        ));
    }
    if container_id
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .is_none()
    {
        return Some(format!(
            "{name} has no container recorded, so it cannot be linked."
        ));
    }
    if !matches!(engine.as_str(), "postgres" | "mysql" | "mariadb") {
        return Some(format!(
            "{name} uses an engine ({engine}) that cannot be linked."
        ));
    }
    None
}

async fn fetch(
    db: &PgPool,
    database_id: Uuid,
    user_id: Uuid,
    server_id: Uuid,
) -> Result<Option<LinkRow>, sqlx::Error> {
    sqlx::query_as(LINKABLE_SELECT)
        .bind(database_id)
        .bind(user_id)
        .bind(server_id)
        .fetch_optional(db)
        .await
}

/// Save-time check: may `user_id` link `database_id` to a deployment on
/// `server_id`? A database that exists but belongs to someone else answers
/// exactly like one that does not exist, so the check discloses nothing.
pub(crate) async fn check_linkable(
    db: &PgPool,
    database_id: Uuid,
    user_id: Uuid,
    server_id: Uuid,
) -> Result<(), String> {
    let row = fetch(db, database_id, user_id, server_id)
        .await
        .map_err(|e| format!("Could not check the database: {e}"))?
        .ok_or_else(|| {
            "Database not found among your databases on this deployment's server".to_string()
        })?;
    match refusal(&row) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

/// Deploy-time load. `None` when nothing is linked. An error means a link is
/// stored but can no longer be honoured - the deploy is refused rather than
/// started without its database.
pub(crate) async fn load(
    db: &PgPool,
    database_id: Option<Uuid>,
    user_id: Uuid,
    server_id: Uuid,
    jwt_secret: &str,
) -> Result<Option<LinkedDb>, String> {
    let Some(id) = database_id else {
        return Ok(None);
    };
    let row = fetch(db, id, user_id, server_id)
        .await
        .map_err(|e| format!("Could not read the linked database: {e}"))?
        .ok_or_else(|| {
            "The linked database is no longer one of this account's databases on this server. \
             Unlink it or pick another under the deployment's settings."
                .to_string()
        })?;
    if let Some(why) = refusal(&row) {
        return Err(why);
    }
    let (_, name, engine, db_user, password_enc, container_id, _, _) = row;
    let password =
        crate::services::secrets_crypto::decrypt_credential_or_legacy(&password_enc, jwt_secret);
    Ok(Some(LinkedDb {
        container_id: container_id.unwrap_or_default().trim().to_string(),
        name,
        engine,
        db_user,
        password,
    }))
}

/// The variables a linked app is given. The port is the ENGINE's own
/// (5432/3306) - `databases.port` is the host-published one, which is not
/// reachable from inside a container at all.
pub(crate) fn injected_env(link: &LinkedDb) -> Vec<(String, String)> {
    let user = urlencoding::encode(&link.db_user).into_owned();
    let pass = urlencoding::encode(&link.password).into_owned();
    let (scheme, port, prefix) = match link.engine.as_str() {
        "mysql" | "mariadb" => ("mysql", "3306", "MYSQL"),
        _ => ("postgresql", "5432", "PG"),
    };
    let url = format!("{scheme}://{user}:{pass}@{DB_HOST}:{port}/{}", link.name);
    let mut vars = vec![
        ("DATABASE_URL".to_string(), url),
        ("DB_HOST".to_string(), DB_HOST.to_string()),
        ("DB_PORT".to_string(), port.to_string()),
        ("DB_NAME".to_string(), link.name.clone()),
        ("DB_USER".to_string(), link.db_user.clone()),
        ("DB_PASSWORD".to_string(), link.password.clone()),
    ];
    if prefix == "PG" {
        vars.extend([
            ("PGHOST".to_string(), DB_HOST.to_string()),
            ("PGPORT".to_string(), port.to_string()),
            ("PGDATABASE".to_string(), link.name.clone()),
            ("PGUSER".to_string(), link.db_user.clone()),
            ("PGPASSWORD".to_string(), link.password.clone()),
        ]);
    } else {
        vars.extend([
            ("MYSQL_HOST".to_string(), DB_HOST.to_string()),
            ("MYSQL_PORT".to_string(), port.to_string()),
            ("MYSQL_DATABASE".to_string(), link.name.clone()),
            ("MYSQL_USER".to_string(), link.db_user.clone()),
            ("MYSQL_PASSWORD".to_string(), link.password.clone()),
        ]);
    }
    vars
}

/// Merge the injected variables into an environment OBJECT (the output of
/// `git_deploys::env_object`), never overwriting a key the user set - not even
/// to an empty value, which is a deliberate choice on their part.
pub(crate) fn merge_env(env: &mut serde_json::Value, link: &LinkedDb) {
    let Some(obj) = env.as_object_mut() else {
        return;
    };
    for (k, v) in injected_env(link) {
        obj.entry(k).or_insert(serde_json::Value::String(v));
    }
}

/// The `linked_db` object the agent's `POST /git/deploy` reads.
pub(crate) fn agent_field(link: &LinkedDb) -> serde_json::Value {
    serde_json::json!({ "container_id": link.container_id, "name": link.name })
}

/// Did the agent confirm the link it was asked for? An agent that predates the
/// field ignores it and deploys anyway, so success alone proves nothing.
pub(crate) fn confirmed(requested: bool, agent_response: &serde_json::Value) -> Result<(), String> {
    if !requested {
        return Ok(());
    }
    match agent_response
        .get("linked_db_network")
        .and_then(|v| v.as_str())
    {
        Some(n) if !n.is_empty() => Ok(()),
        _ => Err(
            "The container was deployed but its server's agent did not attach the linked \
             database (it predates linked databases), so the app cannot reach `db`. Update \
             that server's agent, then deploy again."
                .to_string(),
        ),
    }
}

/// A compose-file deploy goes through the compose engine, not `/git/deploy`,
/// so it would silently run WITHOUT the linked database. Refused instead, with
/// the way out.
pub(crate) fn compose_refusal(database_id: Option<Uuid>) -> Option<String> {
    database_id.map(|_| {
        "This deployment has a linked database, and its repository holds a compose file: a \
         compose deploy does not attach linked databases. Remove the compose file (the \
         Dockerfile build supports the link), or unlink the database."
            .to_string()
    })
}

/// [`confirmed`], applied to the agent call itself, so every deploy door turns
/// an unconfirmed link into the SAME failure path a refused deploy takes.
pub(crate) fn require_confirmed(
    requested: bool,
    outcome: Result<serde_json::Value, crate::services::agent::AgentError>,
) -> Result<serde_json::Value, crate::services::agent::AgentError> {
    let value = outcome?;
    confirmed(requested, &value).map_err(crate::services::agent::AgentError::Response)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(engine: &str, user: &str, pw: &str) -> LinkedDb {
        LinkedDb {
            container_id: "abc123abc123".into(),
            name: "shop".into(),
            engine: engine.into(),
            db_user: user.into(),
            password: pw.into(),
        }
    }

    #[test]
    fn wire_shape_is_absent_keeps_empty_clears_value_sets() {
        assert_eq!(parse_change(None), Ok(LinkChange::Keep));
        assert_eq!(parse_change(Some("")), Ok(LinkChange::Clear));
        assert_eq!(parse_change(Some("  ")), Ok(LinkChange::Clear));
        let id = Uuid::new_v4();
        assert_eq!(parse_change(Some(&id.to_string())), Ok(LinkChange::Set(id)));
        assert!(
            parse_change(Some("not-a-uuid")).is_err(),
            "garbage must not read as unlink"
        );
    }

    #[test]
    fn postgres_url_uses_the_alias_and_the_engine_port_with_credentials_encoded() {
        let env: HashMap<_, _> = injected_env(&link("postgres", "shop", "p@ss:w/rd"))
            .into_iter()
            .collect();
        assert_eq!(
            env["DATABASE_URL"],
            "postgresql://shop:p%40ss%3Aw%2Frd@db:5432/shop"
        );
        assert_eq!(env["PGHOST"], "db");
        assert_eq!(env["PGPORT"], "5432");
        assert_eq!(
            env["PGPASSWORD"], "p@ss:w/rd",
            "the discrete variable is NOT url-encoded"
        );
        assert!(!env.contains_key("MYSQL_HOST"));
    }

    #[test]
    fn mysql_and_mariadb_get_a_mysql_url_on_3306() {
        for engine in ["mysql", "mariadb"] {
            let env: HashMap<_, _> = injected_env(&link(engine, "shop", "x"))
                .into_iter()
                .collect();
            assert_eq!(env["DATABASE_URL"], "mysql://shop:x@db:3306/shop");
            assert_eq!(env["MYSQL_HOST"], "db");
            assert!(!env.contains_key("PGHOST"));
        }
    }

    #[test]
    fn a_variable_the_user_set_is_never_overwritten() {
        let mut env = serde_json::json!({ "DATABASE_URL": "postgres://mine", "DB_HOST": "" });
        merge_env(&mut env, &link("postgres", "shop", "secret"));
        assert_eq!(env["DATABASE_URL"], "postgres://mine");
        assert_eq!(
            env["DB_HOST"], "",
            "an explicit empty value is still the user's choice"
        );
        assert_eq!(env["PGPASSWORD"], "secret", "an absent key is filled in");
    }

    #[test]
    fn a_compose_deploy_with_a_link_is_refused_not_run_unlinked() {
        assert!(compose_refusal(None).is_none());
        assert!(compose_refusal(Some(Uuid::new_v4())).is_some());
    }

    #[test]
    fn a_link_the_agent_did_not_confirm_is_a_failure() {
        assert!(confirmed(false, &serde_json::json!({})).is_ok());
        assert!(confirmed(true, &serde_json::json!({ "container_id": "x" })).is_err());
        assert!(
            confirmed(
                true,
                &serde_json::json!({ "linked_db_network": "dockpanel-link-shop" })
            )
            .is_ok()
        );
    }

    #[test]
    fn unlinkable_rows_are_refused_with_a_reason() {
        let base: LinkRow = (
            Uuid::nil(),
            "shop".into(),
            "postgres".into(),
            "shop".into(),
            "enc".into(),
            Some("abc".into()),
            "container".into(),
            false,
        );
        assert!(refusal(&base).is_none());
        let mut local = base.clone();
        local.6 = "local".into();
        assert!(
            refusal(&local).is_some(),
            "shared local MariaDB has no container to attach"
        );
        let mut hashed = base.clone();
        hashed.7 = true;
        assert!(
            refusal(&hashed).is_some(),
            "an imported hash is not a usable password"
        );
        let mut no_container = base.clone();
        no_container.5 = None;
        assert!(refusal(&no_container).is_some());
    }

    use std::collections::HashMap;
}
