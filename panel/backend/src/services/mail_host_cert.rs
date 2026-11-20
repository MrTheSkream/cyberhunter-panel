//! Certificat `mail.<domaine>` d'un domaine mail, présenté par SNI (conception 14).
//!
//! Émission et renouvellement automatiques (D9), appelés par l'auto-healer
//! (`auto_renew_mail_host_certs`, même interrupteur que les sites) et par le
//! bouton « Retry now » (`POST /api/mail/domains/{id}/host-cert/retry`, `force`).
//!
//! Pour un domaine à traiter :
//! - verrou `issuance_lock` sur l'id du domaine mail (D5) : un passage à la fois ;
//! - garde DNS `dns_gate_for(server, "mail.<d>")`, TOUJOURS appliquée, même avec
//!   `force` : un nom qui ne pointe pas ici passe en `pending_dns` sans aucune
//!   commande ACME, ce qui ménage les limites d'échec de Let's Encrypt ;
//! - sinon `POST /mail/tls/issue { domain, email }` sur l'agent du serveur du
//!   domaine, qui émet `mail.<d>` sans toucher à aucun vhost et reconstruit le SNI.
//!
//! `host_cert_checked_at` est mis à jour à chaque passage. Le message d'erreur
//! enregistré est court et ne contient jamais de secret.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::services::agent::{AgentError, AgentHandle, AgentRegistry};
use crate::services::notifications;

pub const STATUS_NONE: &str = "none";
pub const STATUS_PENDING_DNS: &str = "pending_dns";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_IMPORTED: &str = "imported";
pub const STATUS_FAILED: &str = "failed";

/// `none` / `pending_dns` : au plus une vérification par heure.
const CHECK_EVERY_HOURS: i64 = 1;
/// `failed` : nouvel essai au bout de 6 h.
const FAILED_RETRY_HOURS: i64 = 6;
/// `active` / `imported` : renouvellement à moins de 30 jours de l'expiration.
const RENEW_BEFORE_DAYS: i64 = 30;
/// `active` / `imported` sans expiration connue : un nouvel essai par jour.
const UNKNOWN_EXPIRY_RECHECK_HOURS: i64 = 24;
/// Longueur maximale du message d'erreur enregistré.
const ERROR_MAX_CHARS: usize = 200;

/// L'état exposé par l'API (liste, fiche, retry).
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct HostCertState {
    pub host_cert_status: String,
    pub host_cert_expiry: Option<DateTime<Utc>>,
    pub host_cert_error: Option<String>,
}

#[derive(Debug)]
pub enum ProcessError {
    /// Aucune ligne `mail_domains` avec cet id.
    NotFound,
    /// Le domaine n'est rattaché à aucun serveur.
    NoServer,
    /// L'agent du serveur du domaine est injoignable : rien n'est tenté ailleurs.
    AgentUnavailable(String),
    Db(String),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "mail domain not found"),
            Self::NoServer => write!(f, "mail domain is not associated with a server"),
            Self::AgentUnavailable(e) => write!(f, "server unreachable: {e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

/// Faut-il traiter ce domaine maintenant ? (D9, pur)
///
/// - domaine actif uniquement, même avec `force` ;
/// - `none`, `pending_dns` (et tout état inconnu) : au plus une fois par heure ;
/// - `failed` : nouvel essai après 6 h ;
/// - `active`, `imported` : renouvellement si l'expiration est à moins de 30 jours
///   (ou inconnue) ;
/// - `force` ignore ces délais (bouton « Retry now »), jamais la garde DNS, qui
///   est appliquée ensuite par [`process_one`].
pub fn needs_processing(
    status: &str,
    expiry: Option<DateTime<Utc>>,
    checked_at: Option<DateTime<Utc>>,
    enabled: bool,
    now: DateTime<Utc>,
    force: bool,
) -> bool {
    if !enabled {
        return false;
    }
    if force {
        return true;
    }
    let checked_since = |hours: i64| {
        checked_at.is_none_or(|t| now - t >= chrono::Duration::hours(hours))
    };
    match status {
        STATUS_ACTIVE | STATUS_IMPORTED => match expiry {
            // Un renouvellement qui échoue passe en `failed` ; tant qu'il est
            // dû, une vérification par heure au plus.
            Some(e) => {
                e - now < chrono::Duration::days(RENEW_BEFORE_DAYS) && checked_since(CHECK_EVERY_HOURS)
            }
            // Expiration inconnue (réponse de l'agent sans `expiry` lisible) :
            // une fois par jour, jamais une commande ACME par heure.
            None => checked_since(UNKNOWN_EXPIRY_RECHECK_HOURS),
        },
        STATUS_FAILED => checked_since(FAILED_RETRY_HOURS),
        STATUS_NONE | STATUS_PENDING_DNS => checked_since(CHECK_EVERY_HOURS),
        // Un état inconnu (la contrainte CHECK l'interdit) se comporte comme `none`.
        _ => checked_since(CHECK_EVERY_HOURS),
    }
}

/// Le message court enregistré pour un échec de l'agent (pur).
///
/// Le corps d'erreur de `/mail/tls/issue` est `{ "error": "...", "code": "..." }` :
/// on garde `code: error`, tronqué. Un corps qui n'a pas cette forme n'est pas
/// recopié (il pourrait contenir n'importe quoi) : seul le statut HTTP est gardé.
pub fn short_agent_error(err: &AgentError) -> String {
    let msg = match err {
        AgentError::Status(code, body) => {
            let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
            let error = parsed
                .as_ref()
                .and_then(|v| v.get("error"))
                .and_then(|e| e.as_str())
                .map(str::trim)
                .filter(|e| !e.is_empty());
            let code_s = parsed
                .as_ref()
                .and_then(|v| v.get("code"))
                .and_then(|c| c.as_str())
                .filter(|c| !c.is_empty());
            match (code_s, error) {
                (Some(c), Some(e)) => format!("{c}: {e}"),
                (None, Some(e)) => e.to_string(),
                (Some(c), None) => c.to_string(),
                (None, None) => format!("agent returned HTTP {code}"),
            }
        }
        AgentError::Connection(_) | AgentError::Request(_) | AgentError::CircuitOpen(_) => {
            "agent unreachable".to_string()
        }
        AgentError::Response(_) | AgentError::Parse(_) => "unreadable agent response".to_string(),
        AgentError::NotFound(_) => "agent route not found (agent too old?)".to_string(),
    };
    truncate_chars(&msg, ERROR_MAX_CHARS)
}

/// The agent was not reached (server offline, circuit open, connection or
/// request failure): not an answer about the certificate (pure).
pub fn is_transport_error(err: &AgentError) -> bool {
    matches!(
        err,
        AgentError::Connection(_) | AgentError::Request(_) | AgentError::CircuitOpen(_)
    )
}

async fn touch_checked(pool: &PgPool, id: Uuid) -> Result<(), ProcessError> {
    sqlx::query("UPDATE mail_domains SET host_cert_checked_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| ProcessError::Db(e.to_string()))
}

fn truncate_chars(s: &str, max: usize) -> String {
    let one_line: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if one_line.chars().count() <= max {
        one_line
    } else {
        let mut t: String = one_line.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Clé de dédoublonnage de l'alerte d'échec, propre à chaque domaine mail : les
/// alertes de l'hôte mail n'ont pas de `site_id`, donc la clé seule distingue
/// deux domaines (`alerts.state_key` est en VARCHAR(100) : 17 + 36 caractères).
pub fn failure_state_key(mail_domain_id: Uuid) -> String {
    format!("{}:{mail_domain_id}", notifications::ssl_renewal_key::MAIL_HOST_FAILED)
}

type Row = (String, Option<Uuid>, bool, String, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>);

async fn load(pool: &PgPool, id: Uuid) -> Result<Row, ProcessError> {
    sqlx::query_as::<_, Row>(
        "SELECT domain, server_id, enabled, host_cert_status, host_cert_expiry, \
         host_cert_checked_at, host_cert_error FROM mail_domains WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ProcessError::Db(e.to_string()))?
    .ok_or(ProcessError::NotFound)
}

fn state_of(row: &Row) -> HostCertState {
    HostCertState {
        host_cert_status: row.3.clone(),
        host_cert_expiry: row.4,
        host_cert_error: row.6.clone(),
    }
}

/// Écrit l'état et `host_cert_checked_at = NOW()`. `expiry` : `Some` remplace
/// l'expiration, `None` la garde (un certificat encore valide reste affiché
/// pendant `pending_dns` ou `failed`).
async fn write_state(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    expiry: Option<DateTime<Utc>>,
    error: Option<&str>,
) -> Result<HostCertState, ProcessError> {
    sqlx::query_as::<_, HostCertState>(
        "UPDATE mail_domains SET host_cert_status = $1, \
         host_cert_expiry = COALESCE($2, host_cert_expiry), host_cert_error = $3, \
         host_cert_checked_at = NOW(), updated_at = NOW() WHERE id = $4 \
         RETURNING host_cert_status, host_cert_expiry, host_cert_error",
    )
    .bind(status)
    .bind(expiry)
    .bind(error)
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ProcessError::Db(e.to_string()))?
    .ok_or(ProcessError::NotFound)
}

/// Qui reçoit l'alerte, et dont l'adresse sert de contact ACME : le propriétaire
/// du site du même nom sur ce serveur s'il existe, sinon le premier
/// administrateur. Le même choix que les sites : `resolve_acme_contact` replie
/// ensuite sur `acme_contact_email` quand l'adresse n'est pas utilisable.
async fn contact_user(pool: &PgPool, server_id: Uuid, domain: &str) -> Option<(Uuid, String)> {
    let owner: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.email FROM sites s JOIN users u ON u.id = s.user_id \
         WHERE s.server_id = $1 AND lower(s.domain) = $2 LIMIT 1",
    )
    .bind(server_id)
    .bind(domain)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if owner.is_some() {
        return owner;
    }
    sqlx::query_as(
        "SELECT id, email FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Traiter un domaine mail : D9 complet pour ce domaine.
///
/// Renvoie l'état après le passage. Un domaine qui n'est pas à traiter, ou dont
/// le verrou est déjà tenu, est renvoyé tel quel, sans écriture.
pub async fn process_one(
    pool: &PgPool,
    agents: &AgentRegistry,
    mail_domain_id: Uuid,
    force: bool,
) -> Result<HostCertState, ProcessError> {
    let row = load(pool, mail_domain_id).await?;
    let (_, server_id, enabled, status, expiry, checked_at, _) = &row;
    if !needs_processing(status, *expiry, *checked_at, *enabled, Utc::now(), force) {
        return Ok(state_of(&row));
    }
    let server_id = server_id.ok_or(ProcessError::NoServer)?;
    let agent = agents
        .for_server(server_id)
        .await
        .map_err(|e| ProcessError::AgentUnavailable(e.to_string()))?;
    process_with_agent(pool, &agent, mail_domain_id, server_id, force).await
}

async fn process_with_agent(
    pool: &PgPool,
    agent: &AgentHandle,
    mail_domain_id: Uuid,
    server_id: Uuid,
    force: bool,
) -> Result<HostCertState, ProcessError> {
    // Un passage à la fois par domaine mail (D5). Pas d'attente : l'auto-healer
    // réessaie au tour suivant, et le bouton renvoie l'état courant.
    let Ok(_issuance) =
        crate::services::issuance_lock::begin(mail_domain_id, Duration::ZERO, || async { false }).await
    else {
        tracing::info!("Mail host certificate: another issuance for mail domain {mail_domain_id} is running, skipped");
        return Ok(state_of(&load(pool, mail_domain_id).await?));
    };

    // Relu sous le verrou : un passage concurrent a pu le traiter.
    let row = load(pool, mail_domain_id).await?;
    let (domain, _, enabled, status, expiry, checked_at, _) = &row;
    if !needs_processing(status, *expiry, *checked_at, *enabled, Utc::now(), force) {
        return Ok(state_of(&row));
    }
    let domain = domain.clone();
    let host = format!("mail.{domain}");
    let was_valid = matches!(status.as_str(), STATUS_ACTIVE | STATUS_IMPORTED);

    // Garde DNS : toujours, même avec `force`.
    if crate::helpers::dns_gate_for(pool, server_id, &host).await == crate::helpers::DnsGate::Skip {
        if crate::helpers::dns_gate_should_log(mail_domain_id) {
            tracing::info!(
                "Mail host certificate: {host} does not resolve to this server - waiting for DNS \
                 (no ACME order placed, checked again later)"
            );
        }
        return write_state(pool, mail_domain_id, STATUS_PENDING_DNS, None, None).await;
    }

    let Some((user_id, user_email)) = contact_user(pool, server_id, &domain).await else {
        tracing::warn!("Mail host certificate: no account to use as ACME contact for {host}");
        return write_state(pool, mail_domain_id, STATUS_FAILED, None, Some("no ACME contact account")).await;
    };
    let email = match crate::routes::ssl::resolve_acme_contact(pool, &user_email).await {
        Ok(e) => e,
        Err(_) => {
            let msg = "no usable ACME contact address (set Settings > SSL > ACME contact email)";
            let state = write_state(pool, mail_domain_id, STATUS_FAILED, None, Some(msg)).await?;
            alert_failure(pool, user_id, server_id, mail_domain_id, &host, msg, was_valid).await;
            return Ok(state);
        }
    };

    tracing::info!("Mail host certificate: issuing {host}");
    let result = agent
        .post_long(
            "/mail/tls/issue",
            Some(serde_json::json!({ "domain": domain, "email": email })),
            crate::routes::ssl::DNS01_ORDER_TIMEOUT_SECS,
        )
        .await;

    match result {
        Ok(v) => {
            let new_expiry = v
                .get("expiry")
                .and_then(|x| x.as_str())
                .and_then(crate::helpers::parse_agent_cert_expiry);
            let state = write_state(pool, mail_domain_id, STATUS_ACTIVE, new_expiry, None).await?;
            tracing::info!("Mail host certificate: {host} issued");
            notifications::resolve_alert(
                pool,
                user_id,
                Some(server_id),
                None,
                "ssl_renewal_failure",
                &failure_state_key(mail_domain_id),
                &format!("Mail certificate recovered: {host}"),
                &format!("The certificate for the mail host {host} was issued successfully."),
            )
            .await;
            Ok(state)
        }
        // The server did not answer: nothing is known about the certificate, so
        // the state is kept (no `failed`, no alert, no 6 h backoff). Only the
        // check time moves, which spaces the next attempt by an hour.
        Err(e) if is_transport_error(&e) => {
            tracing::info!("Mail host certificate: {host} skipped - its server did not answer ({})", short_agent_error(&e));
            touch_checked(pool, mail_domain_id).await?;
            Err(ProcessError::AgentUnavailable(short_agent_error(&e)))
        }
        Err(e) => {
            let msg = short_agent_error(&e);
            tracing::warn!("Mail host certificate: issuing {host} failed: {msg}");
            let state = write_state(pool, mail_domain_id, STATUS_FAILED, None, Some(&msg)).await?;
            alert_failure(pool, user_id, server_id, mail_domain_id, &host, &msg, was_valid).await;
            Ok(state)
        }
    }
}

async fn alert_failure(
    pool: &PgPool,
    user_id: Uuid,
    server_id: Uuid,
    mail_domain_id: Uuid,
    host: &str,
    msg: &str,
    was_valid: bool,
) {
    notifications::fire_alert_deduped(
        pool,
        user_id,
        Some(server_id),
        None,
        "ssl_renewal_failure",
        &failure_state_key(mail_domain_id),
        if was_valid { "critical" } else { "warning" },
        &format!("Mail certificate failed: {host}"),
        &format!(
            "CyberHunter - Panel could not issue the certificate for the mail host {host}: {msg}. \
             Mail clients connecting to {host} receive the panel's certificate instead. \
             It is retried automatically every 6 hours, or now from the mail domain's page."
        ),
        12,
    )
    .await;
}

/// L'étape de l'auto-healer : tous les domaines mail actifs qui sont dus (D9).
/// Un serveur injoignable est sauté : jamais d'émission par un autre hôte.
pub async fn auto_renew_mail_host_certs(pool: &PgPool, agents: &AgentRegistry) {
    let rows: Vec<(Uuid, Uuid, String, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = match sqlx::query_as(
        "SELECT md.id, md.server_id, md.host_cert_status, md.host_cert_expiry, md.host_cert_checked_at \
         FROM mail_domains md JOIN servers sv ON sv.id = md.server_id \
         WHERE md.enabled = TRUE AND (sv.is_local OR sv.status <> 'offline') ORDER BY md.domain",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("Mail host certificates: could not list mail domains: {e}");
            return;
        }
    };
    let now = Utc::now();
    for (id, server_id, status, expiry, checked_at) in rows {
        if !needs_processing(&status, expiry, checked_at, true, now, false) {
            continue;
        }
        let agent = match agents.for_server(server_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(
                    "Mail host certificates: server {server_id} unreachable ({e}) - skipped this cycle"
                );
                continue;
            }
        };
        if let Err(e) = process_with_agent(pool, &agent, id, server_id, false).await {
            tracing::warn!("Mail host certificate for mail domain {id}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-20T12:00:00Z").unwrap().with_timezone(&Utc)
    }
    fn ago(h: i64) -> Option<DateTime<Utc>> {
        Some(now() - chrono::Duration::hours(h))
    }
    fn in_days(d: i64) -> Option<DateTime<Utc>> {
        Some(now() + chrono::Duration::days(d))
    }

    #[test]
    fn a_disabled_domain_is_never_processed_even_forced() {
        for s in [STATUS_NONE, STATUS_PENDING_DNS, STATUS_FAILED, STATUS_ACTIVE, STATUS_IMPORTED] {
            assert!(!needs_processing(s, None, None, false, now(), false), "{s}");
            assert!(!needs_processing(s, None, None, false, now(), true), "{s} forced");
        }
    }

    #[test]
    fn none_and_pending_dns_are_checked_at_most_hourly() {
        for s in [STATUS_NONE, STATUS_PENDING_DNS] {
            assert!(needs_processing(s, None, None, true, now(), false), "{s} never checked");
            assert!(!needs_processing(s, None, ago(0), true, now(), false), "{s} just checked");
            assert!(!needs_processing(s, None, Some(now() - chrono::Duration::minutes(59)), true, now(), false));
            assert!(needs_processing(s, None, ago(1), true, now(), false), "{s} an hour ago");
        }
    }

    #[test]
    fn failed_is_retried_after_six_hours() {
        assert!(!needs_processing(STATUS_FAILED, None, ago(1), true, now(), false));
        assert!(!needs_processing(STATUS_FAILED, None, ago(5), true, now(), false));
        assert!(needs_processing(STATUS_FAILED, None, ago(6), true, now(), false));
        assert!(needs_processing(STATUS_FAILED, None, None, true, now(), false));
    }

    #[test]
    fn active_and_imported_renew_inside_thirty_days() {
        for s in [STATUS_ACTIVE, STATUS_IMPORTED] {
            assert!(!needs_processing(s, in_days(60), ago(24), true, now(), false), "{s} far");
            assert!(!needs_processing(s, in_days(31), None, true, now(), false), "{s} 31 days");
            assert!(needs_processing(s, in_days(29), None, true, now(), false), "{s} 29 days");
            assert!(needs_processing(s, in_days(-1), None, true, now(), false), "{s} expired");
            // Expiration inconnue : une fois par jour, pas à chaque heure.
            assert!(needs_processing(s, None, None, true, now(), false), "{s} unknown expiry");
            assert!(!needs_processing(s, None, ago(2), true, now(), false), "{s} unknown expiry, 2 h");
            assert!(needs_processing(s, None, ago(24), true, now(), false), "{s} unknown expiry, 24 h");
            // Dû, mais vérifié il y a 10 min : pas avant l'heure.
            assert!(!needs_processing(s, in_days(10), Some(now() - chrono::Duration::minutes(10)), true, now(), false));
        }
    }

    #[test]
    fn force_ignores_every_delay() {
        assert!(needs_processing(STATUS_PENDING_DNS, None, ago(0), true, now(), true));
        assert!(needs_processing(STATUS_FAILED, None, ago(0), true, now(), true));
        assert!(needs_processing(STATUS_ACTIVE, in_days(80), ago(0), true, now(), true));
        assert!(needs_processing(STATUS_IMPORTED, in_days(80), ago(0), true, now(), true));
    }

    #[test]
    fn an_unknown_status_behaves_like_none() {
        assert!(needs_processing("weird", None, None, true, now(), false));
        assert!(!needs_processing("weird", None, ago(0), true, now(), false));
    }

    #[test]
    fn the_agent_error_body_becomes_code_and_message() {
        let e = AgentError::Status(
            502,
            r#"{"error":"order for mail.a.example.test failed","code":"acme_failed"}"#.into(),
        );
        assert_eq!(short_agent_error(&e), "acme_failed: order for mail.a.example.test failed");
        let e = AgentError::Status(400, r#"{"error":"bad name"}"#.into());
        assert_eq!(short_agent_error(&e), "bad name");
    }

    #[test]
    fn a_body_of_another_shape_is_not_copied() {
        let e = AgentError::Status(500, "-----BEGIN PRIVATE KEY----- whatever".into());
        assert_eq!(short_agent_error(&e), "agent returned HTTP 500");
        let e = AgentError::Connection("tcp connect to 10.0.0.1 refused".into());
        assert_eq!(short_agent_error(&e), "agent unreachable");
    }

    #[test]
    fn an_unreachable_agent_is_not_a_certificate_failure() {
        assert!(is_transport_error(&AgentError::Connection("refused".into())));
        assert!(is_transport_error(&AgentError::CircuitOpen("open".into())));
        assert!(is_transport_error(&AgentError::Request("timeout".into())));
        assert!(!is_transport_error(&AgentError::Status(502, "{}".into())));
        assert!(!is_transport_error(&AgentError::NotFound("old agent".into())));
    }

    #[test]
    fn the_message_is_short_and_on_one_line() {
        let long = "x".repeat(500);
        let e = AgentError::Status(502, format!(r#"{{"error":"{long}\nnext","code":"acme_failed"}}"#));
        let m = short_agent_error(&e);
        assert_eq!(m.chars().count(), ERROR_MAX_CHARS);
        assert!(!m.contains('\n'));
    }

    #[test]
    fn the_failure_key_is_per_domain_and_fits_the_column() {
        let a = failure_state_key(Uuid::new_v4());
        let b = failure_state_key(Uuid::new_v4());
        assert_ne!(a, b);
        assert!(a.starts_with(notifications::ssl_renewal_key::MAIL_HOST_FAILED));
        assert!(a.len() <= 100);
    }
}
