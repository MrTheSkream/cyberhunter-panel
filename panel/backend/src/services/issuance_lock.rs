//! Une émission de certificat à la fois par site, côté panel.
//!
//! Défaut observé en rc.4 : `POST /api/sites` lance une émission automatique
//! en tâche de fond, et un `POST /api/sites/{id}/ssl` envoyé pendant ce temps
//! plaçait une seconde commande ACME pour le même domaine. Les deux se
//! marchaient dessus sur l'agent, et la seconde finissait en 422.
//!
//! Chaque porte d'émission ou de renouvellement d'un site (émission auto à la
//! création, `ssl::provision`, `ssl::provision_dns01`, `ssl::renew_for_site`,
//! et les renouvellements sans opérateur de l'auto-healer et du scanner) prend
//! ce verrou AVANT d'appeler l'agent et le garde jusqu'à la reconstruction du
//! vhost depuis la base.
//!
//! Clé : l'id du site. `sites.domain` n'est unique que par serveur, et deux
//! lignes de sites distinctes ne partagent jamais un vhost, alors que l'id ne
//! peut pas désigner deux sites.
//!
//! ⚠ Jamais pris à l'intérieur de `ssl::renew_over_dns01` : trois appelants
//! qui tiennent déjà ce verrou l'appellent, et il n'est pas réentrant.
//!
//! Le verrou ne vaut que pour ce processus. Un seul panel parle à un agent
//! donné ; l'agent sérialise de son côté (`site_lock::hold_site`), ce qui
//! couvre aussi les émissions qui ne passent pas par le panel (CLI).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use uuid::Uuid;

/// Ce qu'une demande arrivée pendant une émission attend au plus.
pub const ISSUANCE_WAIT: Duration = Duration::from_secs(90);

type Registry = StdMutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>;

static LOCKS: OnceLock<Registry> = OnceLock::new();

fn entry(site_id: Uuid) -> Arc<AsyncMutex<()>> {
    // Le mutex std ne protège qu'une insertion/lecture de HashMap, jamais un
    // `.await` : tenu quelques nanosecondes.
    let mut map = LOCKS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    map.entry(site_id)
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// Tenu pendant toute une émission ; la libère quand il est lâché.
#[must_use = "le verrou est rendu dès que la garde est lâchée"]
pub struct IssuanceGuard {
    _guard: OwnedMutexGuard<()>,
}

/// Pourquoi une demande n'a pas pu commencer son émission.
#[derive(Debug, PartialEq, Eq)]
pub enum Blocked {
    /// Une autre émission tient encore le site au bout de l'attente.
    InProgress,
    /// L'émission attendue a abouti : le site a son certificat.
    AlreadyIssued,
}

/// Prendre le verrou d'émission du site en attendant au plus `wait`, puis
/// demander à `already_issued` si l'émission qu'on vient d'attendre a déjà
/// fait le travail. `already_issued` relit l'état APRÈS le verrou, jamais
/// avant : c'est la relecture qui transforme une seconde commande ACME en un
/// 409 sans appel à l'agent.
///
/// `wait == Duration::ZERO` n'attend pas du tout (portes sans opérateur : elles
/// réessaient au passage suivant).
pub async fn begin<F, Fut>(
    site_id: Uuid,
    wait: Duration,
    already_issued: F,
) -> Result<IssuanceGuard, Blocked>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = bool>,
{
    let lock = entry(site_id);
    let guard = if wait.is_zero() {
        lock.try_lock_owned().map_err(|_| Blocked::InProgress)?
    } else {
        tokio::time::timeout(wait, lock.lock_owned())
            .await
            .map_err(|_| Blocked::InProgress)?
    };
    if already_issued().await {
        return Err(Blocked::AlreadyIssued);
    }
    Ok(IssuanceGuard { _guard: guard })
}

/// La réponse d'une porte interactive dont l'attente a expiré.
pub fn in_progress_error(domain: &str) -> crate::error::ApiError {
    crate::error::err_coded(
        axum::http::StatusCode::CONFLICT,
        &format!(
            "A certificate for {domain} is already being issued. Wait for that issuance to \
             finish, then reload the SSL section."
        ),
        crate::error::CODE_SSL_ISSUANCE_IN_PROGRESS,
    )
}

/// `ssl_enabled` relu en base, pour la relecture après le verrou. Une erreur
/// de lecture vaut « pas encore » : la porte continue comme avant ce verrou.
pub async fn ssl_enabled_now(pool: &sqlx::PgPool, site_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT ssl_enabled FROM sites WHERE id = $1")
        .bind(site_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn never() -> impl Future<Output = bool> {
        async { false }
    }

    #[tokio::test]
    async fn a_second_request_waits_for_the_first_then_proceeds() {
        let site = Uuid::new_v4();
        let first = begin(site, ISSUANCE_WAIT, never).await.expect("premier verrou");

        let waiter = tokio::spawn(async move {
            begin(site, Duration::from_secs(5), never).await.map(|_| ())
        });
        // La seconde demande attend tant que la première tient le verrou.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished(), "la seconde demande n'a pas attendu");

        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("la seconde demande est restée bloquée après la libération")
            .unwrap();
        assert_eq!(second, Ok(()));
    }

    #[tokio::test]
    async fn a_request_that_outwaits_its_budget_is_in_progress_and_checks_nothing() {
        let site = Uuid::new_v4();
        let _held = begin(site, ISSUANCE_WAIT, never).await.unwrap();

        let asked = Arc::new(AtomicBool::new(false));
        let a = asked.clone();
        let out = begin(site, Duration::from_millis(50), move || async move {
            a.store(true, Ordering::SeqCst);
            false
        })
        .await;
        assert!(matches!(out, Err(Blocked::InProgress)));
        // Rien n'est relu ni lancé quand le verrou n'a pas été obtenu.
        assert!(!asked.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn zero_wait_does_not_queue() {
        let site = Uuid::new_v4();
        let _held = begin(site, ISSUANCE_WAIT, never).await.unwrap();
        let out = tokio::time::timeout(
            Duration::from_millis(500),
            begin(site, Duration::ZERO, never),
        )
        .await
        .expect("une attente nulle a fait la queue");
        assert!(matches!(out, Err(Blocked::InProgress)));
    }

    #[tokio::test]
    async fn the_state_is_reread_after_the_wait_and_a_finished_issuance_wins() {
        let site = Uuid::new_v4();
        let issued = Arc::new(AtomicBool::new(false));

        let first = begin(site, ISSUANCE_WAIT, never).await.unwrap();
        let i = issued.clone();
        let waiter = tokio::spawn(async move {
            begin(site, Duration::from_secs(5), move || async move {
                i.load(Ordering::SeqCst)
            })
            .await
            .map(|_| ())
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // La première émission aboutit pendant que la seconde attend.
        issued.store(true, Ordering::SeqCst);
        drop(first);

        let out = waiter.await.unwrap();
        assert_eq!(out, Err(Blocked::AlreadyIssued));
        // Et la relecture refusée a rendu le verrou.
        assert!(begin(site, Duration::ZERO, never).await.is_ok());
    }

    #[tokio::test]
    async fn different_sites_do_not_wait_for_each_other() {
        let _a = begin(Uuid::new_v4(), ISSUANCE_WAIT, never).await.unwrap();
        assert!(begin(Uuid::new_v4(), Duration::ZERO, never).await.is_ok());
    }

    #[test]
    fn the_timeout_answer_is_a_coded_409() {
        let (status, body) = in_progress_error("example.com");
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(body.0["code"], "ssl_issuance_in_progress");
        let msg = body.0["error"].as_str().unwrap();
        assert!(msg.contains("example.com"));
        assert!(!msg.contains('\u{2014}'), "pas de tiret cadratin dans un message d'API");
    }
}
