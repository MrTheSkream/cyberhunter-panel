//! What an open incident means for deployments, and what happens to the
//! incidents of an application that is removed.
//!
//! The deploy doors used to count every active major or critical incident on the
//! panel, whoever owned it and whatever it was about. One monitor left behind by a
//! deleted application was enough to stop every deployment of every account.

use sqlx::PgPool;
use uuid::Uuid;

/// Who asked for the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployTrigger {
    /// An operator pressed Deploy. Often the very fix for the outage.
    Operator,
    /// A webhook or the scheduler: nobody is there to judge the moment.
    Unattended,
}

/// Does this URL point at `domain`? Compares the host only, so a monitor on a
/// path or a port of the application counts, and `app.example.com` does not
/// answer for `myapp.example.com`.
pub fn url_targets_domain(url: &str, domain: &str) -> bool {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rfind('@').map_or(authority, |at| &authority[at + 1..]);
    let host = host.split(':').next().unwrap_or_default();
    !domain.is_empty() && host.eq_ignore_ascii_case(domain)
}

/// Should this active major or critical incident of the deployment's owner hold
/// the deployment back?
///
/// - An incident an operator declared is a deliberate freeze: yes.
/// - One the panel opened by itself only concerns what its monitor watches. It
///   holds back the unattended deployments of that application, never another
///   application, and never the operator deploying the repair.
///
/// `monitors` is the owner's monitors as `(name, url)`. An incident whose monitor
/// is gone matches none of them, so an orphan holds nothing back.
pub fn incident_blocks_deploy(
    title: &str,
    auto_created: bool,
    monitors: &[(String, String)],
    domain: Option<&str>,
    trigger: DeployTrigger,
) -> bool {
    if !auto_created {
        return true;
    }
    trigger == DeployTrigger::Unattended
        && domain.is_some_and(|d| {
            monitors
                .iter()
                .any(|(name, url)| format!("{name} is down") == title && url_targets_domain(url, d))
        })
}

/// The gate every deploy door goes through. Fails open, like the count it replaces.
pub async fn deploy_blocked(
    db: &PgPool,
    owner: Uuid,
    domain: Option<&str>,
    trigger: DeployTrigger,
) -> bool {
    let incidents: Vec<(String, bool)> = sqlx::query_as(
        "SELECT title, auto_created FROM managed_incidents \
         WHERE user_id = $1 \
         AND status NOT IN ('resolved', 'postmortem') \
         AND severity IN ('critical', 'major')",
    )
    .bind(owner)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if incidents.is_empty() {
        return false;
    }

    let monitors: Vec<(String, String)> =
        sqlx::query_as("SELECT name, url FROM monitors WHERE user_id = $1 AND enabled = TRUE")
            .bind(owner)
            .fetch_all(db)
            .await
            .unwrap_or_default();

    incidents
        .iter()
        .any(|(title, auto)| incident_blocks_deploy(title, *auto, &monitors, domain, trigger))
}

/// Was this incident opened by the panel about the application being removed?
/// Exact titles only: a container whose name is a prefix of another's must not
/// close its neighbour's incident.
pub fn incident_belongs_to_app(
    title: &str,
    monitor_names: &[String],
    container: Option<&str>,
) -> bool {
    monitor_names.iter().any(|name| format!("{name} is down") == title)
        || container.is_some_and(|c| {
            title == format!("Container '{c}' is exited")
                || title == format!("Container '{c}' is dead")
                || title.starts_with(&format!("Auto-healer exhausted: {c} keeps crashing on "))
        })
}

/// Delete the monitors of a removed application and close the incidents the panel
/// opened about it. Best effort: the application is already gone.
pub async fn retire_app_monitors(
    db: &PgPool,
    owner: Uuid,
    domain: Option<&str>,
    site_id: Option<Uuid>,
    container: Option<&str>,
) {
    let monitors: Vec<(Uuid, String, String, Option<Uuid>)> =
        sqlx::query_as("SELECT id, name, url, site_id FROM monitors WHERE user_id = $1")
            .bind(owner)
            .fetch_all(db)
            .await
            .unwrap_or_default();

    let (ids, names): (Vec<Uuid>, Vec<String>) = monitors
        .into_iter()
        .filter(|(_, _, url, monitor_site)| {
            (site_id.is_some() && *monitor_site == site_id)
                || domain.is_some_and(|d| url_targets_domain(url, d))
        })
        .map(|(id, name, _, _)| (id, name))
        .unzip();

    if !ids.is_empty()
        && let Err(e) = sqlx::query("DELETE FROM monitors WHERE id = ANY($1)")
            .bind(&ids)
            .execute(db)
            .await
    {
        tracing::warn!("Failed to delete the monitors of a removed application: {e}");
    }

    let incidents: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, title FROM managed_incidents \
         WHERE user_id = $1 AND auto_created AND status NOT IN ('resolved', 'postmortem')",
    )
    .bind(owner)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    for (id, title) in incidents {
        if !incident_belongs_to_app(&title, &names, container) {
            continue;
        }
        let _ = sqlx::query(
            "INSERT INTO incident_updates (incident_id, status, message, author_email) \
             VALUES ($1, 'resolved', 'Closed automatically: the application was removed', 'system')",
        )
        .bind(id)
        .execute(db)
        .await;
        let _ = sqlx::query(
            "UPDATE managed_incidents SET status = 'resolved', resolved_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(db)
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(name: &str, url: &str) -> (String, String) {
        (name.to_string(), url.to_string())
    }

    #[test]
    fn a_monitor_url_targets_its_host_and_nothing_else() {
        assert!(url_targets_domain("https://app.example.com", "app.example.com"));
        assert!(url_targets_domain("http://APP.example.com:8080/health?x=1", "app.example.com"));
        assert!(url_targets_domain("app.example.com", "app.example.com"));
        assert!(!url_targets_domain("https://myapp.example.com", "app.example.com"));
        assert!(!url_targets_domain("https://app.example.com.evil.test", "app.example.com"));
        assert!(!url_targets_domain("https://example.com/app.example.com", "app.example.com"));
        assert!(!url_targets_domain("https://app.example.com", ""));
    }

    #[test]
    fn the_incident_of_one_application_does_not_stop_another() {
        let monitors = vec![monitor("shop (shop.example.com)", "https://shop.example.com")];
        for trigger in [DeployTrigger::Operator, DeployTrigger::Unattended] {
            assert!(!incident_blocks_deploy(
                "shop (shop.example.com) is down",
                true,
                &monitors,
                Some("blog.example.com"),
                trigger,
            ));
        }
    }

    #[test]
    fn an_orphan_incident_stops_nothing() {
        for trigger in [DeployTrigger::Operator, DeployTrigger::Unattended] {
            assert!(!incident_blocks_deploy(
                "deleted (deleted.example.com) is down",
                true,
                &[],
                Some("deleted.example.com"),
                trigger,
            ));
        }
    }

    #[test]
    fn an_applications_own_outage_only_holds_back_unattended_deploys() {
        let monitors = vec![monitor("shop", "https://shop.example.com")];
        let blocks = |trigger| {
            incident_blocks_deploy("shop is down", true, &monitors, Some("shop.example.com"), trigger)
        };
        assert!(blocks(DeployTrigger::Unattended));
        assert!(!blocks(DeployTrigger::Operator), "the operator may deploy the repair");
    }

    #[test]
    fn a_declared_incident_freezes_the_owners_deployments() {
        for trigger in [DeployTrigger::Operator, DeployTrigger::Unattended] {
            assert!(incident_blocks_deploy("Database migration", false, &[], None, trigger));
        }
    }

    #[test]
    fn only_the_removed_applications_incidents_are_closed() {
        let names = vec!["shop (shop.example.com)".to_string()];
        let belongs = |title| incident_belongs_to_app(title, &names, Some("dockpanel-git-shop"));

        assert!(belongs("shop (shop.example.com) is down"));
        assert!(belongs("Container 'dockpanel-git-shop' is exited"));
        assert!(belongs("Container 'dockpanel-git-shop' is dead"));
        assert!(belongs("Auto-healer exhausted: dockpanel-git-shop keeps crashing on vps"));

        assert!(!belongs("blog (blog.example.com) is down"));
        assert!(!belongs("Container 'dockpanel-git-shop-2' is exited"));
        assert!(!belongs("Auto-healer exhausted: dockpanel-git-shop-2 keeps crashing on vps"));
    }
}
