use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser, Claims, ServerScope};
use crate::error::{internal_error, err, agent_error, ApiError};
use crate::routes::sites::ProvisionStep;
use crate::services::activity;
use crate::services::agent::AgentHandle;
use crate::AppState;

// ── Data types ──────────────────────────────────────────────────────────

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MailDomain {
    pub id: Uuid,
    pub domain: String,
    pub dkim_selector: String,
    pub dkim_public_key: Option<String>,
    pub catch_all: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Multi-IP: the forced send address. `null` = automatic (the same-named
    /// site's address, else the primary address).
    pub send_ip_id: Option<Uuid>,
    /// The address mail actually leaves from; `null` = the primary address.
    /// Response-only - filled by [`fill_send_ips`], never a column.
    #[sqlx(default)]
    pub effective_send_ip: Option<String>,
    /// `"forced"` | `"site"` | `"primary"`. Response-only, see [`fill_send_ips`].
    #[sqlx(default)]
    pub send_ip_source: String,
    /// Certificate of `mail.<domain>` presented by SNI (conception 14, D4):
    /// `none` | `pending_dns` | `active` | `imported` | `failed`.
    pub host_cert_status: String,
    pub host_cert_expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// Short reason of the last failure, never a secret.
    pub host_cert_error: Option<String>,
}

/// Fill the response-only send-address fields, with the one resolution the
/// mail sync and the DNS records use (`services::server_ips`).
async fn fill_send_ips(db: &sqlx::PgPool, domains: &mut [MailDomain]) {
    let ids: Vec<Uuid> = domains.iter().map(|d| d.id).collect();
    let rows = crate::services::server_ips::mail_ip_rows_by_ids(db, &ids)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Could not resolve mail send addresses: {e}");
            Vec::new()
        });
    for d in domains.iter_mut() {
        let send = match rows.iter().find(|r| r.id == d.id) {
            Some(r) => r.send_ip(),
            None => crate::services::server_ips::resolve_send_ip(None, None),
        };
        d.effective_send_ip = send.ip.as_ref().map(|ip| ip.ip.clone());
        d.send_ip_source = send.source.as_str().to_string();
    }
}

/// The projection every `MailDomain` read uses.
const MAIL_DOMAIN_COLUMNS: &str =
    "id, domain, dkim_selector, dkim_public_key, catch_all, enabled, created_at, send_ip_id, \
     host_cert_status, host_cert_expiry, host_cert_error";

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MailAccount {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub quota_mb: i32,
    pub enabled: bool,
    pub forward_to: Option<String>,
    /// With `forward_to`: the mailbox also keeps a copy (05-import-hestia W4-B).
    #[sqlx(default)]
    pub keep_copy: bool,
    pub autoresponder_enabled: bool,
    pub autoresponder_subject: Option<String>,
    pub autoresponder_body: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MailAlias {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub source_email: String,
    pub destination_email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    /// Multi-IP: force a send address. Absent/null = automatic.
    pub send_ip_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct SetSendIpRequest {
    /// `null` = automatic.
    pub send_ip_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct UpdateDomainRequest {
    pub catch_all: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    pub quota_mb: Option<i32>,
}

#[derive(serde::Deserialize)]
pub struct UpdateAccountRequest {
    pub password: Option<String>,
    pub display_name: Option<String>,
    pub quota_mb: Option<i32>,
    pub enabled: Option<bool>,
    pub forward_to: Option<String>,
    /// Forward AND keep a copy in this mailbox.
    pub keep_copy: Option<bool>,
    pub autoresponder_enabled: Option<bool>,
    pub autoresponder_subject: Option<String>,
    pub autoresponder_body: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CreateAliasRequest {
    pub source_email: String,
    pub destination_email: String,
}

// ── Mail server status + installation ────────────────────────────────────

/// GET /api/mail/status
pub async fn mail_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/status").await
        .map_err(|e| agent_error("Mail status", e))?;
    Ok(Json(result))
}

/// POST /api/mail/install - Returns 202 + install_id for SSE progress tracking.
pub async fn mail_install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let install_id = Uuid::new_v4();

    crate::helpers::register_provision_log(
        &state.provision_logs,
        &state.deploy_owners,
        install_id,
        claims.sub,
        32,
    );

    let logs = state.provision_logs.clone();
    let db = state.db.clone();
    let sync_state = state.clone();
    let user_id = claims.sub;
    let email = claims.email.clone();
    let key_id = claims.key_id;

    tokio::spawn(async move {
        let emit = |step: &str, label: &str, status: &str, msg: Option<String>| {
            let ev = ProvisionStep {
                step: step.into(), label: label.into(), status: status.into(), message: msg,
            };
            if let Ok(mut map) = logs.lock() {
                if let Some((history, tx, _)) = map.get_mut(&install_id) {
                    history.push(ev.clone());
                    let _ = tx.send(ev);
                }
            }
        };

        emit("install", "Installing mail server", "in_progress", None);

        // `post_long`, not `post`. This installs six apt packages and then restarts three
        // services; the default 60s budget is shorter than the work on any ordinary
        // uplink, so the operator was told the install had FAILED while apt carried on
        // underneath and finished. Reported as the second half of #110: the box ends up
        // half-installed, and the status banner then reports "installed but not running".
        match agent.post_long("/mail/install", None, 900).await {
            Ok(_) => {
                emit("install", "Installing mail server", "done", None);

                // Rebuild the maps the installer just armed against.
                //
                // Every OTHER writer of mail state syncs; the installer was the one
                // path that did not, so a box that re-ran it kept whatever the map
                // file already held - on any box upgrading past v2.106.0, nothing -
                // and stayed unprotected until its next mailbox or domain change.
                //
                // The 202 went out before this task started, so there is no response
                // left to carry a failure. It has to surface as a step, and that is
                // also why the CONFLICT precondition (mail domains naming no server)
                // is reported rather than fatal here: the install itself succeeded,
                // and the operator's remedy is to assign those domains and retry.
                emit("sync", "Applying mail configuration", "in_progress", None);
                match sync_mail_config(&sync_state, server_id, &agent).await {
                    Ok(()) => emit("sync", "Applying mail configuration", "done", None),
                    Err(e) => {
                        let reason = e
                            .1
                             .0
                            .get("error")
                            .and_then(|m| m.as_str())
                            .unwrap_or("the panel could not apply it")
                            .to_string();
                        tracing::warn!(
                            "Mail server installed on {server_id}, but its configuration was \
                             not applied: {reason}"
                        );
                        emit(
                            "sync",
                            "Applying mail configuration",
                            "error",
                            Some(format!(
                                "Mail server installed, but its configuration was not applied: \
                                 {reason} Mail stays as it was until this is resolved or the \
                                 next mailbox or domain change re-applies it."
                            )),
                        );
                    }
                }

                emit("complete", "Mail server installed", "done", None);
                activity::log_activity(
                    &db, user_id, &email, "mail.server.install",
                    Some("mail"), None, None, None, key_id,
                ).await;
                tracing::info!("Mail server installed");
            }
            Err(e) => {
                emit("install", "Installing mail server", "error", Some(format!("{e}")));
                emit("complete", "Install failed", "error", None);
                tracing::error!("Mail server install failed: {e}");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&install_id);
    });

    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({
        "install_id": install_id,
        "message": "Mail server installation started",
    }))))
}

/// POST /api/mail/uninstall - Uninstall mail server (admin only).
pub async fn mail_uninstall(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let install_id = Uuid::new_v4();

    crate::helpers::register_provision_log(
        &state.provision_logs,
        &state.deploy_owners,
        install_id,
        claims.sub,
        32,
    );

    let logs = state.provision_logs.clone();
    let db = state.db.clone();
    let user_id = claims.sub;
    let email = claims.email.clone();
    let key_id = claims.key_id;

    tokio::spawn(async move {
        let emit = |step: &str, label: &str, status: &str, msg: Option<String>| {
            let ev = ProvisionStep {
                step: step.into(), label: label.into(), status: status.into(), message: msg,
            };
            if let Ok(mut map) = logs.lock() {
                if let Some((history, tx, _)) = map.get_mut(&install_id) {
                    history.push(ev.clone());
                    let _ = tx.send(ev);
                }
            }
        };

        emit("uninstall", "Uninstalling mail server", "in_progress", None);

        match agent.post_long("/mail/uninstall", None, 900).await {
            Ok(_) => {
                emit("uninstall", "Uninstalling mail server", "done", None);
                emit("complete", "Mail server uninstalled", "done", None);
                activity::log_activity(
                    &db, user_id, &email, "mail.server.uninstall",
                    Some("mail"), None, None, None, key_id,
                ).await;
                tracing::info!("Mail server uninstalled");
            }
            Err(e) => {
                emit("uninstall", "Uninstalling mail server", "error", Some(format!("{e}")));
                emit("complete", "Uninstall failed", "error", None);
                tracing::error!("Mail server uninstall failed: {e}");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&install_id);
    });

    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({
        "install_id": install_id,
        "message": "Mail server uninstall started",
    }))))
}

// ── Domain routes ───────────────────────────────────────────────────────

/// GET /api/mail/domains - the mail domains on the server in scope.
///
/// This read had no server term and no ownership term of any kind: it returned
/// every mail domain in the installation to every administrator, including those
/// on a fleet member somebody else registered. The page therefore listed rows the
/// handlers behind it now refuse - [`MAIL_DOMAIN_CALLER_PREDICATE`] draws that
/// line for every per-domain route, and the list that feeds them drew none.
///
/// TWO BRANCHES, and they authorise differently on purpose - the house pattern
/// from `sites::list` versus `sites::list_for_admin`, where OWNERSHIP authorises
/// and the server term only SCOPES.
///
/// * **Administrator**: unchanged from before. `ServerScope` has already proved
///   the caller owns the server it names (`SELECT id FROM servers WHERE id = $1
///   AND user_id = $2`), so the server term is the authorisation for this branch.
/// * **Site owner** (GitHub #106): the same ownership test
///   [`MAIL_DOMAIN_CALLER_PREDICATE`] applies per row, inlined because a list has
///   no `{id}` to bind. It is deliberately NOT scoped by `$1`. `ServerScope`'s
///   header-absent branch resolves the LOCAL server with no ownership check, and
///   a non-administrator never sends the header, so constraining this branch by
///   `$1` would blank the list for a client whose site is on a fleet member -
///   while all eight per-domain handlers, which resolve the host from the ROW,
///   would happily serve them. The list must agree with the handlers behind it.
///
/// ⚠ The `OR` between the branches is parenthesised, and that is load-bearing.
/// `AND` binds tighter than `OR` in SQL, so the previous shape
/// (`server_id = $1 OR server_id IS NULL`) would have silently attached any
/// appended `AND <owner term>` to the second disjunct alone.
///
/// ⚠ `server_id IS NULL` stays visible, deliberately, for the same reason the
/// predicate admits it. `20260807000000_sleep_and_destination_server_scope.sql`
/// backfills those rows, so on a migrated install there are none; but its final
/// `NOT NULL` is guarded and skipped when an install has no local server row to
/// backfill from, so the column can still hold one. A row that names no server is
/// not a row belonging to another operator - it belongs to nobody, there is
/// nothing here to test it against, and hiding it would remove it from the only
/// screen that can see it while `sync_mail_config` keeps refusing every rebuild in
/// the installation because it exists. Listed, it reaches the handlers, which
/// answer 409 naming the problem instead of 404 naming nothing.
pub async fn list_domains(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, _agent): ServerScope,
) -> Result<Json<Vec<MailDomain>>, ApiError> {
    let domains: Vec<MailDomain> = sqlx::query_as(
        "SELECT md.id, md.domain, md.dkim_selector, md.dkim_public_key, md.catch_all, \
         md.enabled, md.created_at, md.send_ip_id, md.host_cert_status, md.host_cert_expiry, \
         md.host_cert_error FROM mail_domains md WHERE (\
         EXISTS (SELECT 1 FROM users u WHERE u.id = $2 AND u.role = 'admin') \
         AND (md.server_id = $1 OR md.server_id IS NULL)) \
         OR (EXISTS (\
         SELECT 1 FROM sites s WHERE s.server_id = md.server_id \
         AND lower(s.domain) = md.domain AND s.user_id = $2) \
         AND NOT EXISTS (\
         SELECT 1 FROM sites s2 WHERE s2.server_id = md.server_id \
         AND lower(s2.domain) = md.domain AND s2.user_id <> $2)) \
         ORDER BY md.domain LIMIT 500",
    )
    .bind(server_id)
    .bind(claims.sub)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list domains", e))?;

    let mut domains = domains;
    fill_send_ips(&state.db, &mut domains).await;

    Ok(Json(domains))
}

/// POST /api/mail/domains
pub async fn create_domain(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<MailDomain>), ApiError> {
    let domain = body.domain.trim().to_lowercase();
    if !crate::routes::is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain name"));
    }

    // Multi-IP: a forced send address must be declared on the server the domain
    // is created on - checked before the agent generates anything.
    if let Some(ip_id) = body.send_ip_id {
        crate::services::server_ips::declared_ip_on_server(&state.db, ip_id, server_id)
            .await
            .map_err(|e| internal_error("create domain", e))?
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "That IP address is not declared on this server"))?;
    }

    // Generate DKIM keys via agent
    let dkim_result = agent
        .post("/mail/dkim/generate", Some(serde_json::json!({ "domain": domain, "selector": "dockpanel" })))
        .await;

    let (private_key, public_key) = match dkim_result {
        Ok(resp) => (
            resp.get("private_key").and_then(|v| v.as_str()).map(String::from),
            resp.get("public_key").and_then(|v| v.as_str()).map(String::from),
        ),
        Err(e) => {
            tracing::warn!("DKIM generation failed for {domain}: {e}");
            (None, None)
        }
    };

    // Encrypt the DKIM private key before storing
    let encrypted_private_key = if let Some(ref pk) = private_key {
        Some(crate::services::secrets_crypto::encrypt_credential(pk, &state.config.jwt_secret)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Encryption failed: {e}")))?)
    } else {
        None
    };

    // ⚠ `server_id` is written HERE and nowhere else, and this is the only handler
    // in the module where the caller's selection is the right authority: creation
    // is the moment the operator CHOOSES a host, and until this row exists there is
    // no row to derive one from. Every sibling handler derives it from the row.
    //
    // The column was never bound before. `mail_domains.server_id` has no DEFAULT
    // and is nullable, so every mail domain created through the panel since the
    // multi-server migration was stored naming no server at all - which left the
    // server switcher as the only thing deciding where a domain's mailboxes went,
    // and left `idx_mail_domains_domain_server` unable to reject a duplicate
    // (Postgres treats NULLs as distinct, and the old global UNIQUE on `domain` was
    // dropped by that same migration, so the CONFLICT arm below could not fire).
    let mail_domain: MailDomain = sqlx::query_as(&format!(
        "INSERT INTO mail_domains (domain, dkim_private_key, dkim_public_key, server_id, send_ip_id) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {MAIL_DOMAIN_COLUMNS}",
    ))
    .bind(&domain)
    .bind(&encrypted_private_key)
    .bind(&public_key)
    .bind(server_id)
    .bind(body.send_ip_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") {
            err(StatusCode::CONFLICT, "Domain already exists")
        } else {
            internal_error("create domain", e)
        }
    })?;

    // Configure Postfix/Dovecot via agent
    let _ = agent
        .post("/mail/domains/configure", Some(serde_json::json!({ "domain": domain })))
        .await;

    // Rebuild the maps now, not at the first mailbox change: the sync is what
    // publishes this domain's send transport (multi-IP §4.4), so a domain created
    // with - or following a site on - a non-primary address would otherwise send
    // from the primary one until something unrelated triggered a sync.
    // Best-effort, like configure above: the row exists and is reported either way.
    if let Err((status, msg)) = sync_mail_config(&state, server_id, &agent).await {
        tracing::warn!("Mail sync after creating {domain} was refused ({status}): {:?}", msg.0);
    }

    // ── Auto-DNS: create MX, A, SPF, DMARC, DKIM records ─────────────────
    //
    // `server_id` travels with the domain into the background task. It is the
    // value that was just written onto the row above, so the records describe the
    // machine the mailboxes were actually created on - not whichever box this
    // process happens to run on, which is what `detect_public_ip` answered and
    // what published a member's A record pointing at the panel.
    let dns_domain = domain.clone();
    let dns_dkim_pub = public_key.clone();
    let dns_db = state.db.clone();
    let dns_agent = agent.clone();
    let dns_user = claims.sub;
    let dns_email = claims.email.clone();
    let dns_server = server_id;
    tokio::spawn(async move {
        if let Err(e) = auto_create_mail_dns(
            &dns_db, &dns_agent, dns_user, &dns_email,
            &dns_domain, dns_server, dns_dkim_pub.as_deref(),
        ).await {
            tracing::warn!("Auto-DNS for mail domain {dns_domain} failed: {e}");
        }
    });

    // ── Say who this just handed the mailboxes to ────────────────────────
    //
    // The claim system is DIRECTIONAL and only one direction was guarded.
    // `may_claim_mail_held` stops a site being pointed at a name whose mail
    // already exists; nothing stops mail being created over a name a site
    // already holds - `ensure_claimable` is not called from this module at all.
    // Since #106 derives mailbox control from site ownership, this INSERT is now
    // an entitlement-granting write: the moment the row lands, whoever owns the
    // same-named site on this server holds every mailbox and every password hash
    // on it.
    //
    // That is the intended flow - it is how an operator gives a customer their
    // mail - so this must NOT refuse. `ensure_claimable` verbatim would 409 the
    // ordinary "site first, mail after" pairing that the entitlement is built
    // around. What was missing is that the grant was SILENT. It is now named in
    // the activity record the operator can actually read, and in the log.
    let grantee: Option<(String,)> = sqlx::query_as(
        "SELECT u.email FROM sites s JOIN users u ON u.id = s.user_id \
         WHERE s.server_id = $1 AND lower(s.domain) = $2 AND u.role <> 'admin' LIMIT 1",
    )
    .bind(server_id)
    .bind(&domain)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if let Some((ref who,)) = grantee {
        tracing::info!(
            "Mail domain {domain} created over a site owned by {who} - that account now \
             manages its mailboxes (GitHub #106)"
        );
    }

    let ip = crate::routes::client_ip(&headers);

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.domain.create",
        Some("mail"), Some(&domain),
        grantee.as_ref().map(|(w,)| w.as_str()), ip.as_deref(), claims.key_id,
    ).await;

    crate::services::security_hardening::audit_log(
        &state.db,
        "mail.domain.create",
        Some(&claims.email),
        ip.as_deref(),
        Some("mail"),
        Some(&domain),
        grantee.as_ref().map(|(w,)| w.as_str()),
        None,
        "warning",
        claims.key_id,
    ).await;

    let mut mail_domain = mail_domain;
    fill_send_ips(&state.db, std::slice::from_mut(&mut mail_domain)).await;
    Ok((StatusCode::CREATED, Json(mail_domain)))
}

/// PUT /api/mail/domains/{id}
pub async fn update_domain(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateDomainRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // WHICH DOMAIN and WHICH HOST both come from the row now. The read also grew an
    // authorisation term it never had: `SELECT domain FROM mail_domains WHERE id = $1`
    // asked nothing about who was calling, so `ServerScope`'s header check was the
    // entire boundary. Resolving before any write means an un-scoped or unreachable
    // host is refused with nothing half-applied behind it.
    let (domain, server_id, agent) = mail_domain_agent_for_caller(&state, id, &claims).await?;

    if let Some(catch_all) = &body.catch_all {
        if !catch_all.is_empty() && !is_wellformed_address(catch_all, "/") {
            return Err(err(StatusCode::BAD_REQUEST, "Invalid catch-all email address"));
        }
        sqlx::query("UPDATE mail_domains SET catch_all = $1, updated_at = NOW() WHERE id = $2")
            .bind(if catch_all.is_empty() { None } else { Some(catch_all.as_str()) })
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update domain", e))?;
    }

    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE mail_domains SET enabled = $1, updated_at = NOW() WHERE id = $2")
            .bind(enabled)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update domain", e))?;
    }

    // Push the catch_all/enabled change into Postfix/Dovecot - previously written to the DB only,
    // so disabling a domain or setting a catch-all had no effect until an unrelated account change.
    sync_mail_config(&state, server_id, &agent).await?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.domain.update",
        Some("mail"), Some(&domain), None, None, claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// PUT /api/mail/domains/{id}/send-ip - force a send address, or `null` for automatic.
///
/// The address must be declared on the domain's OWN server (the row's, not the
/// switcher's). Applied by a mail sync, which publishes the per-domain transport
/// and HELO. The panel-managed SPF record is not rewritten here: the DNS tab and
/// dns-check report the new expected `ip4:` value.
pub async fn set_send_ip(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SetSendIpRequest>,
) -> Result<Json<MailDomain>, ApiError> {
    let (domain, server_id, agent) = mail_domain_agent_for_caller(&state, id, &claims).await?;

    let label = match body.send_ip_id {
        None => "automatic".to_string(),
        Some(ip_id) => {
            crate::services::server_ips::declared_ip_on_server(&state.db, ip_id, server_id)
                .await
                .map_err(|e| internal_error("mail send ip", e))?
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "That IP address is not declared on this mail domain's server"))?
                .ip
        }
    };

    let mut row: MailDomain = sqlx::query_as(&format!(
        "UPDATE mail_domains SET send_ip_id = $1, updated_at = NOW() WHERE id = $2 RETURNING {MAIL_DOMAIN_COLUMNS}"
    ))
    .bind(body.send_ip_id)
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("mail send ip", e))?;

    let report = sync_mail_config_report(&state, server_id, &agent).await?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.domain.send_ip",
        Some("mail"), Some(&domain), Some(&label), ip.as_deref(), claims.key_id,
    ).await;

    fill_send_ips(&state.db, std::slice::from_mut(&mut row)).await;

    // An explicit change must not report success when it did not take. The row
    // is KEPT (it is the operator's stated intent and the next successful sync
    // applies it) and the request answers 502 saying so - rolling back would need
    // a second sync that could fail the same way and leave the two disagreeing.
    if let Some(problem) = report.send_ip_problem(row.effective_send_ip.as_deref()) {
        return Err(err(
            StatusCode::BAD_GATEWAY,
            &format!("The sending address was saved, but it is not in effect: {problem}"),
        ));
    }
    Ok(Json(row))
}

/// POST /api/mail/domains/{id}/host-cert/retry - issue `mail.<domain>` now
/// (conception 14, D9/D11 "Retry now").
///
/// The same authorisation as every other write on a mail domain
/// ([`mail_domain_agent_for_caller`], admin only). The delay between two attempts
/// is ignored; the DNS gate is NOT: a `mail.<d>` that does not point here ends in
/// `pending_dns` without any ACME order.
pub async fn retry_host_cert(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<Json<crate::services::mail_host_cert::HostCertState>, ApiError> {
    use crate::services::mail_host_cert::{self as host_cert, ProcessError};

    let (domain, _server_id, _agent) = mail_domain_agent_for_caller(&state, id, &claims).await?;

    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM mail_domains WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("mail host cert retry", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Domain not found"))?;
    if !enabled {
        return Err(err(StatusCode::CONFLICT, "This mail domain is disabled"));
    }

    let result = host_cert::process_one(&state.db, &state.agents, id, true)
        .await
        .map_err(|e| match e {
            ProcessError::NotFound => err(StatusCode::NOT_FOUND, "Domain not found"),
            ProcessError::NoServer => err(StatusCode::CONFLICT, "This mail domain is not associated with a server"),
            ProcessError::AgentUnavailable(_) => err(StatusCode::BAD_GATEWAY, "The mail domain's server is unreachable"),
            ProcessError::Db(e) => internal_error("mail host cert retry", e),
        })?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.domain.host_cert_retry",
        Some("mail"), Some(&domain), Some(&result.host_cert_status), ip.as_deref(), claims.key_id,
    ).await;

    Ok(Json(result))
}

/// DELETE /api/mail/domains/{id}
pub async fn delete_domain(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Resolved before the row is gone, because the row is the only thing that knows
    // which host to strip the domain from. Sending `/mail/domains/remove` to the
    // switcher's host instead deleted a DKIM key on a machine that never had one and
    // left the real host still accepting the domain's mail.
    let (domain, server_id, agent) = mail_domain_agent_for_caller(&state, id, &claims).await?;

    // Fetch DKIM selector before deletion (needed for DNS cleanup)
    let dkim_info: Option<(String,)> = sqlx::query_as(
        "SELECT dkim_selector FROM mail_domains WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let dkim_selector = dkim_info.map(|d| d.0).unwrap_or_else(|| "dockpanel".to_string());

    // Remove from Postfix/Dovecot via agent
    let _ = agent
        .post("/mail/domains/remove", Some(serde_json::json!({ "domain": domain })))
        .await;

    sqlx::query("DELETE FROM mail_domains WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("delete domain", e))?;

    // Rebuild Postfix/Dovecot maps from the remaining rows so the deleted domain's mailboxes
    // stop authenticating and receiving immediately - the agent's /mail/domains/remove only drops
    // the DKIM key and defers map cleanup to this sync, which delete_domain previously never called.
    // `server_id` was captured above: the row it came from no longer exists.
    sync_mail_config(&state, server_id, &agent).await?;

    // ── Auto-DNS cleanup: delete MX, A, SPF, DMARC, DKIM records ─────────
    let dns_domain = domain.clone();
    let dns_db = state.db.clone();
    let dns_user = claims.sub;
    tokio::spawn(async move {
        if let Err(e) = auto_delete_mail_dns(
            &dns_db, dns_user, &dns_domain, &dkim_selector,
        ).await {
            tracing::warn!("Auto-DNS cleanup for mail domain {dns_domain} failed: {e}");
        }
    });

    let ip = crate::routes::client_ip(&headers);

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.domain.delete",
        Some("mail"), Some(&domain), None, ip.as_deref(), claims.key_id,
    ).await;

    crate::services::security_hardening::audit_log(
        &state.db,
        "mail.domain.delete",
        Some(&claims.email),
        ip.as_deref(),
        Some("mail"),
        Some(&domain),
        None,
        None,
        "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/mail/domains/{id}/dns - Required DNS records for email
pub async fn domain_dns(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // The same read the two DNS-verification endpoints use, so the tab that tells
    // you what to create and the checks that tell you whether you created it can
    // never describe two different domains. It also asks the question this handler
    // never asked: whether this caller may see the domain at all. Its own inline
    // `WHERE id = $1` answered only that the row exists.
    let (domain, selector, dkim_pub, server_id) =
        mail_domain_identity(&state.db, id, &claims).await?;

    // The MAIL DOMAIN'S HOST's public address - not this process's, and not the
    // agent's hostname.
    //
    // This endpoint used to read `/system/info`'s `hostname` field into a variable
    // called `server_ip` and publish it as an address, so it told operators to
    // create `A mail.example.com → my-server` and the invalid SPF value
    // `v=spf1 a mx ip4:my-server ~all`. Fixing that to `detect_public_ip` made the
    // value an address but still the WRONG one for a domain on a fleet member: it
    // is the panel's, so the tab instructed the operator to point their mail
    // domain at a machine that does not run their mail.
    //
    // A `None` here is not a write, so it does not have to refuse - but it must not
    // substitute this box either, because an operator following the instruction
    // would create the wrong record by hand and it would resolve and answer. Fall
    // back to the placeholder the endpoint already used when it could not detect an
    // address: it says "put an address here" and names no machine at all.
    //
    // Multi-IP: the apex A record names the same-named site's address and SPF the
    // address this domain sends from (services::server_ips). Each falls back to
    // the placeholder on its own.
    let (a_ip, spf_ip) =
        crate::services::server_ips::mail_dns_addresses_for(&state.db, server_id, &domain).await;
    let placeholder = |ip: Option<String>| {
        ip.filter(|ip| !ip.is_empty()).unwrap_or_else(|| "your-server-ip".to_string())
    };
    let (a_ip, spf_ip) = (placeholder(a_ip), placeholder(spf_ip));

    let records: Vec<serde_json::Value> = crate::services::prerequisites::mail::mail_records_for(
        &domain,
        &selector,
        dkim_pub.as_deref(),
        &a_ip,
        &spf_ip,
    )
    .into_iter()
    .map(|r| {
        serde_json::json!({
            "type": r.record_type,
            "name": r.fqdn,
            "content": r.value,
            "description": r.purpose.unwrap_or_default(),
        })
    })
    .collect();

    // Multi-IP: where this domain's mail leaves from, and the PTR (= HELO)
    // receivers will see for it. `ip`/`ptr` null = the primary address, whose
    // PTR is not known to the panel unless that address is declared.
    let send = crate::services::server_ips::mail_ip_rows_by_ids(&state.db, &[id])
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .map(|r| r.send_ip())
        .unwrap_or_else(|| crate::services::server_ips::resolve_send_ip(None, None));

    Ok(Json(serde_json::json!({
        "domain": domain,
        "records": records,
        "send_ip": {
            "ip": send.ip.as_ref().map(|i| i.ip.clone()),
            "source": send.source.as_str(),
            "ptr": send.ip.as_ref().and_then(|i| i.helo()),
        },
    })))
}

// ── Account routes ──────────────────────────────────────────────────────

/// GET /api/mail/domains/{id}/accounts
///
/// The mailboxes are listed only after the DOMAIN has been resolved through
/// [`MAIL_DOMAIN_CALLER_PREDICATE`]. `mail_accounts` has no server column and no
/// owner column - it reaches both only through `domain_id` - so the domain is the
/// only place this question can be asked, and the bare `WHERE domain_id = $1` here
/// asked it nowhere: any administrator could enumerate the mailboxes of any
/// domain on any machine in the fleet by id.
///
/// Resolving first rather than joining the predicate into the list query is
/// deliberate. A joined query would answer an unauthorised caller with an empty
/// list, which reads as "this domain has no mailboxes" - the failure that looks
/// like success. This way an invisible domain 404s, exactly as the mutating
/// handlers already do.
pub async fn list_accounts(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(domain_id): Path<Uuid>,
) -> Result<Json<Vec<MailAccount>>, ApiError> {
    mail_domain_identity(&state.db, domain_id, &claims).await?;

    let accounts: Vec<MailAccount> = sqlx::query_as(
        "SELECT id, domain_id, email, display_name, quota_mb, enabled, forward_to, keep_copy, \
         autoresponder_enabled, autoresponder_subject, autoresponder_body, created_at \
         FROM mail_accounts WHERE domain_id = $1 ORDER BY email",
    )
    .bind(domain_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list accounts", e))?;

    Ok(Json(accounts))
}

/// POST /api/mail/domains/{id}/accounts
pub async fn create_account(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(domain_id): Path<Uuid>,
    Json(body): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<MailAccount>), ApiError> {
    // The domain's own row decides both whether this caller may add a mailbox to it
    // and which host the mailbox is created on. The existence check that used to
    // stand here answered neither: it asked only `WHERE id = $1`, so any
    // administrator could create a mailbox under any other administrator's domain,
    // and the credential was then written to whichever host the switcher named.
    let (domain, server_id, agent) =
        mail_domain_agent_for_caller(&state, domain_id, &claims).await?;

    let email = body.email.trim().to_lowercase();
    if !email.ends_with(&format!("@{domain}")) {
        return Err(err(StatusCode::BAD_REQUEST, &format!("Email must end with @{domain}")));
    }
    if !is_wellformed_address(&email, "") {
        return Err(err(StatusCode::BAD_REQUEST, "Email address contains invalid characters"));
    }

    if body.password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }

    // Hash in a scheme THIS server's Dovecot can verify - Argon2id where it is
    // built in, bcrypt where it is not. Hashing in a scheme the verifier does
    // not know produces an account that is created successfully and can never
    // be opened. "THIS server" now means the domain's host: asking the switcher's
    // agent could read Argon2id support off a Debian box and write the credential
    // to a Rocky one that cannot verify it.
    let schemes = agent_password_schemes(&agent).await;
    let password_hash = dovecot_password_hash_for(&body.password, &schemes)
        .map_err(|e| internal_error("hash mail password", e))?;

    // Clamp quota to a sane range (1 MB .. 1 TB): 0/negative would write `storage=0M` / a garbage
    // rule into the Dovecot userdb; an unbounded value silently removes the quota.
    let quota = body.quota_mb.unwrap_or(1024).clamp(1, 1_048_576);

    let account: MailAccount = sqlx::query_as(
        "INSERT INTO mail_accounts (domain_id, email, password_hash, display_name, quota_mb) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, domain_id, email, display_name, quota_mb, enabled, forward_to, keep_copy, \
         autoresponder_enabled, autoresponder_subject, autoresponder_body, created_at",
    )
    .bind(domain_id)
    .bind(&email)
    .bind(&password_hash)
    .bind(&body.display_name)
    .bind(quota)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") {
            err(StatusCode::CONFLICT, "Email account already exists")
        } else {
            internal_error("create account", e)
        }
    })?;

    // Sync with Postfix/Dovecot via agent
    sync_mail_config(&state, server_id, &agent).await?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.account.create",
        Some("mail"), Some(&email), None, None, claims.key_id,
    ).await;

    Ok((StatusCode::CREATED, Json(account)))
}

/// PUT /api/mail/domains/{domain_id}/accounts/{id}
pub async fn update_account(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((domain_id, account_id)): Path<(Uuid, Uuid)>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateAccountRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // The mailbox reaches its host through the domain that owns it. This is the
    // sharpest of the account handlers: it can REPLACE a password hash, and the
    // rebuild that follows used to carry every mailbox in the installation to
    // whichever box the browser had selected.
    let (email, server_id, agent) =
        mail_account_agent_for_caller(&state, domain_id, account_id, &claims).await?;

    if let Some(password) = &body.password {
        if password.len() < 8 {
            return Err(err(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
        }
        // Same scheme selection as creation - a password CHANGE that reverts to
        // Argon2id on a box that cannot verify it locks the user out of a
        // mailbox that was working (#92b: count the call sites).
        let schemes = agent_password_schemes(&agent).await;
        let hash = dovecot_password_hash_for(password, &schemes)
            .map_err(|e| internal_error("hash mail password", e))?;
        sqlx::query("UPDATE mail_accounts SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&hash)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(name) = &body.display_name {
        sqlx::query("UPDATE mail_accounts SET display_name = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(quota) = body.quota_mb {
        // Clamp to a sane range (1 MB .. 1 TB) - 0/negative writes a broken Dovecot quota rule.
        sqlx::query("UPDATE mail_accounts SET quota_mb = $1, updated_at = NOW() WHERE id = $2")
            .bind(quota.clamp(1, 1_048_576))
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE mail_accounts SET enabled = $1, updated_at = NOW() WHERE id = $2")
            .bind(enabled)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(forward) = &body.forward_to {
        if !forward.is_empty() && !is_wellformed_address(forward, "") {
            return Err(err(StatusCode::BAD_REQUEST, "Invalid forwarding email address"));
        }
        sqlx::query("UPDATE mail_accounts SET forward_to = $1, updated_at = NOW() WHERE id = $2")
            .bind(if forward.is_empty() { None } else { Some(forward.as_str()) })
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(keep) = body.keep_copy {
        sqlx::query("UPDATE mail_accounts SET keep_copy = $1, updated_at = NOW() WHERE id = $2")
            .bind(keep)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(ar_enabled) = body.autoresponder_enabled {
        sqlx::query("UPDATE mail_accounts SET autoresponder_enabled = $1, updated_at = NOW() WHERE id = $2")
            .bind(ar_enabled)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(subject) = &body.autoresponder_subject {
        sqlx::query("UPDATE mail_accounts SET autoresponder_subject = $1, updated_at = NOW() WHERE id = $2")
            .bind(subject)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    if let Some(ar_body) = &body.autoresponder_body {
        sqlx::query("UPDATE mail_accounts SET autoresponder_body = $1, updated_at = NOW() WHERE id = $2")
            .bind(ar_body)
            .bind(account_id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update account", e))?;
    }

    sync_mail_config(&state, server_id, &agent).await?;

    let ip = crate::routes::client_ip(&headers);

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.account.update",
        Some("mail"), Some(&email), None, ip.as_deref(), claims.key_id,
    ).await;

    crate::services::security_hardening::audit_log(
        &state.db,
        "mail.account.update",
        Some(&claims.email),
        ip.as_deref(),
        Some("mail"),
        Some(&email),
        None,
        None,
        "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/mail/domains/{domain_id}/accounts/{id}
pub async fn delete_account(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((domain_id, account_id)): Path<(Uuid, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Resolved before the DELETE, so the host is taken from the row while the row
    // still exists - and so a mailbox on a machine this administrator does not
    // operate is refused rather than removed.
    let (email, server_id, agent) =
        mail_account_agent_for_caller(&state, domain_id, account_id, &claims).await?;

    sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
        .bind(account_id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("delete account", e))?;

    sync_mail_config(&state, server_id, &agent).await?;

    let ip = crate::routes::client_ip(&headers);

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.account.delete",
        Some("mail"), Some(&email), None, ip.as_deref(), claims.key_id,
    ).await;

    crate::services::security_hardening::audit_log(
        &state.db,
        "mail.account.delete",
        Some(&claims.email),
        ip.as_deref(),
        Some("mail"),
        Some(&email),
        None,
        None,
        "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Alias routes ────────────────────────────────────────────────────────

/// GET /api/mail/domains/{id}/aliases
///
/// Same reasoning as [`list_accounts`], against `mail_aliases`: resolve the domain
/// through the shared predicate first so an invisible domain 404s, then list. An
/// alias row exposes a forwarding destination, which is a real mailbox address
/// belonging to whoever runs that domain.
pub async fn list_aliases(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(domain_id): Path<Uuid>,
) -> Result<Json<Vec<MailAlias>>, ApiError> {
    mail_domain_identity(&state.db, domain_id, &claims).await?;

    let aliases: Vec<MailAlias> = sqlx::query_as(
        "SELECT id, domain_id, source_email, destination_email, created_at \
         FROM mail_aliases WHERE domain_id = $1 ORDER BY source_email",
    )
    .bind(domain_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list aliases", e))?;

    Ok(Json(aliases))
}

/// POST /api/mail/domains/{id}/aliases
pub async fn create_alias(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(domain_id): Path<Uuid>,
    Json(body): Json<CreateAliasRequest>,
) -> Result<(StatusCode, Json<MailAlias>), ApiError> {
    // This handler previously read no row at all - it INSERTed straight against the
    // `{id}` path segment and let the foreign key decide whether the domain existed.
    // So it asked neither whether the caller may write to that domain nor which host
    // the resulting alias map belongs on. Resolving the domain answers both.
    let (domain, server_id, agent) =
        mail_domain_agent_for_caller(&state, domain_id, &claims).await?;

    let source = body.source_email.trim().to_lowercase();
    let destination = body.destination_email.trim().to_lowercase();

    // The alias source must belong to the domain it is being filed under.
    //
    // Nothing checked this. `create_account` has always required `@{domain}` on the
    // address it creates; the alias path took `source_email` verbatim from the body
    // and stored it against whatever `{id}` was in the path. `mail_sync_payload`
    // then emits it into that server's Postfix virtual-alias map keyed on the
    // ADDRESS, and Postfix applies an alias to any address it accepts - so an alias
    // filed under a domain the caller may write to could redirect mail addressed to
    // a DIFFERENT domain on the same host, to any destination. The row's own
    // `domain_id` said one thing and the map said another, and the map is what runs.
    //
    // Rejected at the door for the same reason `is_valid_mail_address` is: the
    // agent's sync is all-or-nothing, and the callers discard its result.
    if !source.ends_with(&format!("@{domain}")) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Alias source must end with @{domain}"),
        ));
    }
    if !is_wellformed_address(&source, "") {
        return Err(err(StatusCode::BAD_REQUEST, "Alias source contains invalid characters"));
    }
    // Destination may be a comma-separated list of targets (matches the agent's
    // alias validation) - so every ELEMENT is checked, not the string as a whole.
    if !is_wellformed_address_list(&destination, "") {
        return Err(err(StatusCode::BAD_REQUEST, "Alias destination contains invalid characters"));
    }

    let alias: MailAlias = sqlx::query_as(
        "INSERT INTO mail_aliases (domain_id, source_email, destination_email) \
         VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(domain_id)
    .bind(&source)
    .bind(&destination)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") {
            err(StatusCode::CONFLICT, "Alias already exists")
        } else {
            internal_error("create alias", e)
        }
    })?;

    sync_mail_config(&state, server_id, &agent).await?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.alias.create",
        Some("mail"), Some(&alias.source_email), Some(&alias.destination_email), None, claims.key_id,
    ).await;

    Ok((StatusCode::CREATED, Json(alias)))
}

/// DELETE /api/mail/domains/{domain_id}/aliases/{id}
pub async fn delete_alias(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((domain_id, alias_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Scoping the alias to the {domain_id} path segment - otherwise a mismatched (domain, alias)
    // pair would delete an alias belonging to a different domain - is now carried by the shared
    // resolver's `md.id = $1` term over the join, alongside the authorisation and host questions
    // the previous read did not ask at all.
    let (source, server_id, agent) =
        mail_alias_agent_for_caller(&state, domain_id, alias_id, &claims).await?;

    sqlx::query("DELETE FROM mail_aliases WHERE id = $1 AND domain_id = $2")
        .bind(alias_id)
        .bind(domain_id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("delete alias", e))?;

    sync_mail_config(&state, server_id, &agent).await?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.alias.delete",
        Some("mail"), Some(&source), None, None, claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Mail queue ──────────────────────────────────────────────────────────

/// GET /api/mail/queue
pub async fn get_queue(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Return empty queue if mail server isn't installed (avoids 502 spam on dashboard)
    let result = match agent.get("/mail/queue").await {
        Ok(v) => v,
        Err(_) => serde_json::json!({ "queue": [], "count": 0 }),
    };

    Ok(Json(result))
}

/// POST /api/mail/queue/flush
pub async fn flush_queue(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent
        .post("/mail/queue/flush", None)
        .await
        .map_err(|e| agent_error("Flush mail queue", e))?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.queue.flush",
        Some("mail"), None, None, None, claims.key_id,
    ).await;

    Ok(Json(result))
}

/// DELETE /api/mail/queue/{id}
pub async fn delete_queued(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Path(queue_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent
        .post("/mail/queue/delete", Some(serde_json::json!({ "id": queue_id })))
        .await
        .map_err(|e| agent_error("Delete queued message", e))?;

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.queue.delete",
        Some("mail"), Some(&queue_id), None, None, claims.key_id,
    ).await;

    Ok(Json(result))
}

// ── Auto-DNS helpers for mail domains ───────────────────────────────────

/// Extract the parent/root domain from a subdomain.
/// e.g. "mail.example.com" → "example.com", "example.com" → "example.com"
fn extract_parent_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() > 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        domain.to_string()
    }
}

// A local `detect_public_ip()` used to sit here, forwarding verbatim to
// `crate::helpers::detect_public_ip`. It is gone rather than re-signatured: its
// only effect was to make a call site read "the server's IP" when the function
// underneath answers "THIS PROCESS's IP", and that ambiguity is precisely the
// defect - every mail path that wanted a host's address got the panel's. A name
// that has to be looked up to know which machine it means is worse than no name,
// so the one caller now spells `helpers::public_ip_for_server` in full, and the
// server it is asking about is visible in the argument.

/// Build Cloudflare API headers from credentials.
fn cf_headers(token: &str, email: Option<&str>) -> reqwest::header::HeaderMap {
    crate::helpers::cf_headers(token, email)
}

/// Auto-create DNS records (MX, A, SPF, DMARC, DKIM) for a new mail domain.
/// Runs in a background task - errors are logged, not returned to the user.
///
/// `server_id` is the host the domain was created on, carried in from
/// `create_domain` where the operator chose it. It is what the A record and the
/// SPF `ip4:` term resolve to; without it this function published the PANEL's
/// address for a domain on a fleet member, which is a record that resolves,
/// answers, and points mail at a machine that never sees it.
/// Whether a mail host's certificate may be issued over what is already at
/// `/etc/dockpanel/ssl/{domain}/fullchain.pem`.
///
/// Separated from every lookup so it can be exercised without a pool, an agent
/// or a mail domain - the reason the decision underneath had never been tested.
#[derive(Debug, PartialEq, Eq)]
pub enum MailCertVerdict {
    /// Nothing there loses names. Issue.
    Issue,
    /// Issuing would replace a certificate covering more than the mail host.
    Refuse(MailCertBlocker),
}

/// What occupies the certificate file, in the words the operator is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailCertBlocker {
    /// A CyberHunter - Panel-issued DNS-01 certificate that also covers subdomains.
    Wildcard,
    /// A certificate CyberHunter - Panel did not issue (uploaded, commercial, Origin CA).
    Foreign,
}

/// Decide whether issuing a mail-host certificate would destroy names.
///
/// A mail host genuinely needs a certificate, and the agent route that issues one
/// writes `fullchain.pem` unconditionally. That path is not the mail host's
/// private property: a site of the same name reads it, and so does a DNS-01
/// **wildcard**, which `routes/ssl.rs` stores under the ZONE APEX - the very name
/// a mail domain is normally created at. Issuing a single-name HTTP-01
/// certificate over that file replaces one covering `*.example.com` with one
/// covering `example.com` alone, and every sibling vhost (`app.`, `www.`,
/// `staging.`) reading that same file starts serving a certificate that does not
/// cover it. The vhost repair below this call cannot help: it restores the site's
/// CONFIGURATION, and what was lost is the file the configuration points at.
///
/// ⚠ **Two inputs, and neither is redundant.** `foreign_issuer` cannot see the
/// case that leads the harm: `foreign_cert_issuer` collapses *ours* and *we could
/// not tell* into one `None` (`helpers.rs`), so an LE-issued wildcard answers
/// `None`. The columns cannot see the other case: an uploaded commercial or
/// Origin-CA certificate carries no `ssl_wildcard` and no `ssl_challenge` of ours.
/// Each covers exactly what the other is blind to, which is why this takes both.
///
/// `Issue` deliberately includes the ordinary shape the mail entitlement is built
/// on - a site and its mailboxes sharing one name, holding a single-name
/// certificate that a re-issue merely refreshes. Refusing that would break the
/// documented "set the mail up first, add the website after" order.
pub fn mail_cert_verdict(
    ssl_enabled: bool,
    ssl_wildcard: Option<bool>,
    ssl_challenge: Option<&str>,
    foreign_issuer: Option<&str>,
) -> MailCertVerdict {
    // A site not serving TLS has no certificate here to lose. The issuer probe
    // is not consulted in this state on purpose: a stale file left behind by a
    // revoked certificate is not something the operator is still serving.
    if !ssl_enabled {
        return MailCertVerdict::Issue;
    }

    if ssl_wildcard == Some(true) || ssl_challenge == Some("dns-01") {
        return MailCertVerdict::Refuse(MailCertBlocker::Wildcard);
    }

    if foreign_issuer.is_some() {
        return MailCertVerdict::Refuse(MailCertBlocker::Foreign);
    }

    MailCertVerdict::Issue
}

/// Issue the mail host's certificate, unless doing so would destroy one.
///
/// Both auto-DNS providers reached this through byte-identical blocks. They are
/// one function now: a guard applied to one leg and not the other is the
/// sibling-call drift this project has shipped three times, and the two legs
/// differ in nothing but the provider that got them here.
async fn provision_mail_host_cert(
    db: &sqlx::PgPool,
    agent: &AgentHandle,
    user_id: uuid::Uuid,
    user_email: &str,
    domain: &str,
    server_id: uuid::Uuid,
) {
    // Wait briefly for DNS propagation before attempting ACME HTTP-01
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let site: Option<(uuid::Uuid, uuid::Uuid, bool, Option<bool>, Option<String>)> =
        sqlx::query_as(
            "SELECT id, user_id, ssl_enabled, ssl_wildcard, ssl_challenge \
             FROM sites WHERE lower(domain) = lower($1) AND server_id = $2",
        )
        .bind(domain)
        .bind(server_id)
        .fetch_optional(db)
        .await
        .unwrap_or(None);

    // ⛔ ASKED FOR EVERY MAIL HOST, not only for one that owns a site row - and
    //    that placement is the whole repair. The issuer question used to live
    //    INSIDE the `if let` below, so it read as "this door asks" while asking
    //    nothing at all for a domain with no `sites` row. That is not a rare
    //    shape: `domain_claim::find_occupant` guarantees a Compose stack's domain
    //    can never own a `sites` row, and a Docker app's cannot either - so for
    //    exactly the population with no other protection here, the check that
    //    looked present was absent, and the order below replaced whatever was on
    //    disk.
    //
    //    Still skipped when the ROW already settles it: a wildcard or a DNS-01
    //    site is decided from its columns alone, and this is a round trip to the
    //    box. With no row there is nothing to settle it, so the file is asked.
    let settled_by_row = match &site {
        Some((_, _, ssl_enabled, ssl_wildcard, ssl_challenge)) => {
            !(*ssl_enabled
                && *ssl_wildcard != Some(true)
                && ssl_challenge.as_deref() != Some("dns-01"))
        }
        None => false,
    };
    let foreign = if settled_by_row {
        None
    } else {
        crate::helpers::foreign_cert_issuer(agent, domain).await
    };

    let site_id_for_names = site.as_ref().map(|(id, ..)| *id);
    let site_ssl_before = site.as_ref().map(|(_, _, enabled, ..)| *enabled).unwrap_or(false);
    if let Some((site_id, site_owner, ssl_enabled, ssl_wildcard, ssl_challenge)) = site {
        if let MailCertVerdict::Refuse(blocker) = mail_cert_verdict(
            ssl_enabled,
            ssl_wildcard,
            ssl_challenge.as_deref(),
            foreign.as_deref(),
        ) {
            announce_mail_cert_conflict(db, domain, Some(site_id), site_owner, server_id, blocker).await;
            return;
        }
    } else if foreign.is_some() {
        // No `sites` row exists for this domain (a Compose stack or Docker app
        // claimed it - `domain_claim::find_occupant` guarantees a `sites` row
        // can never coexist with one). `announce_mail_cert_conflict` used to
        // take a non-optional site id and owner, so this branch could only log
        // a warning and had no alert to raise. `site_id` is now `Option`, and
        // the caller's own `user_id` (the admin who configured mail for this
        // domain) stands in as the alert's owner - a real id from the call
        // chain, not an invented one.
        announce_mail_cert_conflict(db, domain, None, user_id, server_id, MailCertBlocker::Foreign)
            .await;
        return;
    }

    // One issuance per site at a time (`services::issuance_lock`, conception 14
    // D5): `/ssl/provision/{domain}` writes the same-named site's certificate and
    // vhost, so it is held from the order to `rebuild_vhost_for_domain` below,
    // as `routes/sites.rs` does for the auto-SSL at creation. "Already issued"
    // means only "the issuance we waited for gave the site its certificate": a
    // site that already served TLS before we waited is refreshed as before.
    let _issuance = match site_id_for_names {
        Some(site_id) => match crate::services::issuance_lock::begin(
            site_id,
            crate::services::issuance_lock::ISSUANCE_WAIT,
            || async move {
                !site_ssl_before && crate::services::issuance_lock::ssl_enabled_now(db, site_id).await
            },
        )
        .await
        {
            Ok(guard) => Some(guard),
            Err(blocked) => {
                tracing::info!(
                    "Auto-SSL (mail): {domain} not provisioned - the same-named site's issuance \
                     lock is held ({blocked:?})"
                );
                return;
            }
        },
        None => None,
    };

    let mut body = serde_json::json!({
        "email": user_email,
        "runtime": "static",
    });
    // A website of the same name keeps its other names (`www.`, aliases) on the
    // re-issued certificate, as on every other HTTP-01 door (05 W3-S); without
    // a site row the mail host is a single name. Not DNS-gated: this runs right
    // after the panel itself wrote the records, where a resolver cache could
    // still answer the old value, and the operator just asked for it.
    let full_site: Option<crate::models::Site> = match site_id_for_names {
        Some(id) => sqlx::query_as("SELECT * FROM sites WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .unwrap_or(None),
        None => None,
    };
    if let Some(ref s) = full_site {
        crate::helpers::add_http01_names(agent, s, &mut body).await;
    }
    match crate::helpers::post_http01_order(agent, &format!("/ssl/provision/{domain}"), body).await {
        Ok(_) => {
            tracing::info!("Auto-SSL (mail): provisioned certificate for {domain}");
            // ⛔ The agent does not patch a vhost for a certificate - it
            // re-renders the whole file from what we just sent, and what we
            // sent is `runtime: "static"` with no root, no limits and no
            // hardening. That is the right body for a mail host and a
            // catastrophe for a WEBSITE of the same name, which is an
            // ordinary shape: you host example.com and you add mail for
            // example.com. Measured on a box at s398 - the site was
            // re-rendered static, answered 403 to every PHP request and lost
            // its `limit_req_zone`, while the panel went on reporting
            // `runtime = php` with all its limits set.
            //
            // Nothing above can be narrowed to avoid this: the mail host
            // genuinely needs a certificate and the agent route that issues
            // one always rewrites the vhost. So put the site's real
            // configuration back afterwards, exactly as the four SSL doors in
            // `routes/ssl.rs` already do for their own writes.
            crate::routes::ssl::rebuild_vhost_for_domain(db, agent, domain, server_id).await;
        }
        Err(e) => tracing::warn!("Auto-SSL (mail): failed for {domain}: {e} - provision manually"),
    }
}

/// Tell the operator a certificate was deliberately NOT issued.
///
/// Silence here would be the worst outcome: the mail host simply has no
/// certificate, which looks exactly like the ACME failure the `Err` arm above
/// reports, and the operator would have no way to tell a refusal that protected
/// their wildcard from a network error they should retry.
async fn announce_mail_cert_conflict(
    db: &sqlx::PgPool,
    domain: &str,
    site_id: Option<uuid::Uuid>,
    site_owner: uuid::Uuid,
    server_id: uuid::Uuid,
    blocker: MailCertBlocker,
) {
    let because = match blocker {
        MailCertBlocker::Wildcard => format!(
            "the site {domain} holds a DNS-01 certificate that also covers its \
             subdomains. Issuing a single-name certificate for the mail host \
             would replace it, and every subdomain reading the same file would \
             start serving a certificate that does not cover it"
        ),
        MailCertBlocker::Foreign => format!(
            "the certificate installed for {domain} was not issued by CyberHunter - Panel. \
             Issuing over it would destroy a certificate somebody installed \
             deliberately"
        ),
    };

    tracing::warn!("Auto-SSL (mail): declined to provision for {domain} - {because}");

    // No `sites` row for a Compose stack or Docker app domain, so there is no
    // SSL tab to send the operator to - that instruction is specific to the
    // `site_id.is_some()` population.
    let remedy = if site_id.is_some() {
        "If the mail host needs one of its own, issue it deliberately from the site's SSL tab, \
         where the consequences are shown before anything is replaced."
    } else {
        "If the mail host needs one of its own, replace the certificate deliberately at its \
         source (the Compose stack or template that manages it) - CyberHunter - Panel will not do it \
         automatically."
    };

    crate::services::notifications::fire_alert_deduped(
        db,
        site_owner,
        Some(server_id),
        site_id,
        "ssl_renewal_failure",
        crate::services::notifications::ssl_renewal_key::MAIL_HOST_CONFLICT,
        "warning",
        &format!("Mail certificate not issued: {domain}"),
        &format!(
            "CyberHunter - Panel did not issue a certificate for the mail host {domain}, because \
             {because}. Mail for this domain will use the certificate already installed. \
             {remedy}"
        ),
        12,
    )
    .await;
}

async fn auto_create_mail_dns(
    db: &sqlx::PgPool,
    agent: &AgentHandle,
    user_id: uuid::Uuid,
    user_email: &str,
    domain: &str,
    server_id: uuid::Uuid,
    dkim_public_key: Option<&str>,
) -> Result<(), String> {
    let parent = extract_parent_domain(domain);

    // Look up DNS zone for the parent domain
    let zone: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2"
    )
    .bind(&parent)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;

    let (provider, cf_zone_id, cf_api_token, cf_api_email) = match zone {
        Some(z) => z,
        None => {
            tracing::info!("No DNS zone found for {parent} - skipping auto-DNS for mail domain {domain}");
            return Ok(());
        }
    };

    // A WRITE, so a host we cannot resolve stops it. Every record below is derived
    // from this one value: the A record IS it, and the SPF `ip4:` term authorises
    // it to send. Substituting this process's address would not fail - it would
    // publish a record that resolves and answers on the wrong machine, so mail for
    // the domain is delivered nowhere and SPF authorises a host that never sends
    // it. That is strictly worse than the domain having no records at all, which
    // is a visible, fixable state the DNS tab already reports.
    // Multi-IP: A = the same-named site's address, SPF = the send address.
    let (a_ip, spf_ip) =
        crate::services::server_ips::mail_dns_addresses_for(db, Some(server_id), domain).await;
    let (server_ip, spf_ip) = match (a_ip, spf_ip) {
        (Some(a), Some(spf)) if !a.is_empty() && !spf.is_empty() => (a, spf),
        _ => {
            // The whole set is refused, not just the two records that carry the
            // address. MX names the apex and DKIM/DMARC only mean anything once
            // mail can reach it, and the auto-SSL step below issues over HTTP-01
            // against that same apex A record - a partial publish would leave a
            // domain advertising a mail host that resolves to nothing, plus a
            // certificate failure, which is harder to read than nothing at all.
            return Err(format!(
                "no public address is recorded for server {server_id} (it may not have checked \
                 in yet), so NO DNS records were published for {domain} - create them by hand \
                 from the domain's DNS tab once the server reports an address"
            ));
        }
    };

    // THE record set - the same one the DNS tab shows and the prerequisite check
    // verifies.
    //
    // This used to be spelled inline here and again in `domain_dns`, and the two
    // had drifted apart: this path published `A <domain>` with `MX → <domain>` and
    // `v=spf1 ip4:… -all`, while the tab described `A mail.<domain>` with
    // `MX → mail.<domain>` and `v=spf1 a mx ip4:… ~all`, under a DKIM selector this
    // path hardcoded to `dockpanel` regardless of the stored column. Two different
    // mail topologies from one product. Now there is one.
    let selector = crate::services::prerequisites::mail::DEFAULT_DKIM_SELECTOR;
    let records =
        crate::services::prerequisites::mail::mail_records_for(domain, selector, dkim_public_key, &server_ip, &spf_ip);

    if provider == "cloudflare" {
        let (zone_id, token) = match (cf_zone_id, cf_api_token) {
            (Some(z), Some(t)) => (z, t),
            _ => return Err("Cloudflare zone missing zone_id or token".into()),
        };

        let client = reqwest::Client::new();
        let headers = cf_headers(&token, cf_api_email.as_deref());
        let cf_url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");

        for record in &records {
            // MX priority is a separate field in the Cloudflare API, not part of
            // the content string.
            let (content, priority) = if record.record_type == "MX" {
                let mut parts = record.value.splitn(2, ' ');
                let pri: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(10);
                (parts.next().unwrap_or(&record.value).to_string(), Some(pri))
            } else {
                (record.value.clone(), None)
            };

            let mut body = serde_json::json!({
                "type": record.record_type,
                "name": record.fqdn,
                "content": content,
                "ttl": 1,
                // Every mail record must be DNS-only: SMTP cannot traverse the
                // Cloudflare proxy, so an orange-clouded mail host is unreachable.
                "proxied": false,
            });
            if let Some(pri) = priority {
                body["priority"] = serde_json::json!(pri);
            }

            let _ = client.post(&cf_url).headers(headers.clone()).json(&body).send().await;
            tracing::info!(
                "Auto-DNS (mail): created {} record {} for {domain}",
                record.record_type,
                record.fqdn
            );
        }

        // ── Auto-SSL: provision certificate for the mail domain ───────────
        provision_mail_host_cert(db, agent, user_id, user_email, domain, server_id).await;
    } else if provider == "powerdns" {
        // Get PowerDNS settings
        let pdns: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')"
        ).fetch_all(db).await.unwrap_or_default();
        let pdns_url = pdns.iter().find(|(k,_)| k == "pdns_api_url").map(|(_,v)| v.clone());
        let pdns_key_enc = pdns.iter().find(|(k,_)| k == "pdns_api_key").map(|(_,v)| v.clone());

        let (url, key) = match (pdns_url, pdns_key_enc) {
            (Some(u), Some(k)) => (u, crate::services::secrets_crypto::decrypt_credential_from_env(&k)),
            _ => return Err("PowerDNS not configured".into()),
        };

        let client = reqwest::Client::new();
        let zone_fqdn = if parent.ends_with('.') { parent.clone() } else { format!("{parent}.") };

        // Same record set as the Cloudflare branch above, in PowerDNS's rrset
        // shape: names are fully qualified with a trailing dot, MX priority stays
        // inside the content string, and TXT values must arrive quoted.
        let rrsets: Vec<serde_json::Value> = records
            .iter()
            .map(|record| {
                let name = format!("{}.", record.fqdn);
                let content = if record.record_type == "TXT" {
                    format!("\"{}\"", record.value)
                } else if record.record_type == "MX" {
                    // "10 mail.example.com" → "10 mail.example.com."
                    match record.value.rsplit_once(' ') {
                        Some((pri, host)) => format!("{pri} {host}."),
                        None => record.value.clone(),
                    }
                } else {
                    record.value.clone()
                };
                serde_json::json!({
                    "name": name, "type": record.record_type, "ttl": 300, "changetype": "REPLACE",
                    "records": [{ "content": content, "disabled": false }]
                })
            })
            .collect();

        // Check the URL is PowerDNS, then require its exact PATCH answer
        // (204): another service on the port must not pass for success.
        let result: Result<(), crate::services::pdns_api::PdnsApiError> = async {
            crate::services::pdns_api::verify_server(&client, &url, &key).await?;
            let resp = client
                .patch(&format!("{url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .header("X-API-Key", &key)
                .json(&serde_json::json!({ "rrsets": rrsets }))
                .send()
                .await
                .map_err(|e| crate::services::pdns_api::PdnsApiError::Transport(e.to_string()))?;
            let (status, text) = crate::services::pdns_api::read_response(resp).await;
            crate::services::pdns_api::check_patch(status, &text)
        }.await;

        match result {
            Ok(()) => {
                tracing::info!("Auto-DNS (mail/PowerDNS): created all records for {domain}");
            }
            Err(e) => return Err(e.to_string()),
        }

        // ── Auto-SSL for PowerDNS ────────────────────────────────────────
        provision_mail_host_cert(db, agent, user_id, user_email, domain, server_id).await;
    }

    Ok(())
}

/// Auto-delete all DNS records for a removed mail domain.
/// Runs in a background task - errors are logged, not returned to the user.
async fn auto_delete_mail_dns(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    domain: &str,
    dkim_selector: &str,
) -> Result<(), String> {
    let parent = extract_parent_domain(domain);

    let zone: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT provider, cf_zone_id, cf_api_token, cf_api_email FROM dns_zones WHERE domain = $1 AND user_id = $2"
    )
    .bind(&parent)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;

    let (provider, cf_zone_id, cf_api_token, cf_api_email) = match zone {
        Some(z) => z,
        None => {
            tracing::info!("No DNS zone found for {parent} - skipping DNS cleanup for mail domain {domain}");
            return Ok(());
        }
    };

    if provider == "cloudflare" {
        let (zone_id, token) = match (cf_zone_id, cf_api_token) {
            (Some(z), Some(t)) => (z, t),
            _ => return Err("Cloudflare zone missing zone_id or token".into()),
        };

        let client = reqwest::Client::new();
        let headers = cf_headers(&token, cf_api_email.as_deref());

        // Collect all record names we need to clean up. These mirror exactly what
        // `auto_create_mail_dns` publishes (apex A + MX + SPF, _dmarc, DKIM) -
        // keep the two lists in step, or removing a domain leaves records behind.
        let names_to_check = vec![
            domain.to_string(),
            format!("_dmarc.{domain}"),
            format!("{dkim_selector}._domainkey.{domain}"),
        ];

        for name in &names_to_check {
            // Query all record types for this name (A, MX, TXT, CNAME, etc.)
            let list_url = format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={name}&per_page=50"
            );
            if let Ok(resp) = client.get(&list_url).headers(headers.clone()).send().await {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(records) = data.get("result").and_then(|r| r.as_array()) {
                        for record in records {
                            if let Some(rid) = record.get("id").and_then(|v| v.as_str()) {
                                let del_url = format!(
                                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}"
                                );
                                let _ = client.delete(&del_url).headers(headers.clone()).send().await;
                                let rtype = record.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                tracing::info!("Auto-DNS cleanup (mail): deleted {rtype} record for {name}");
                            }
                        }
                    }
                }
            }
        }
    } else if provider == "powerdns" {
        let pdns: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')"
        ).fetch_all(db).await.unwrap_or_default();
        let pdns_url = pdns.iter().find(|(k,_)| k == "pdns_api_url").map(|(_,v)| v.clone());
        let pdns_key_enc = pdns.iter().find(|(k,_)| k == "pdns_api_key").map(|(_,v)| v.clone());

        if let (Some(url), Some(key_enc)) = (pdns_url, pdns_key_enc) {
            let key = crate::services::secrets_crypto::decrypt_credential_from_env(&key_enc);
            let zone_fqdn = if parent.ends_with('.') { parent.clone() } else { format!("{parent}.") };
            let domain_fqdn = format!("{domain}.");
            let dmarc_fqdn = format!("_dmarc.{domain}.");
            let dkim_fqdn = format!("{dkim_selector}._domainkey.{domain}.");

            let rrsets = serde_json::json!({
                "rrsets": [
                    { "name": &domain_fqdn, "type": "A", "changetype": "DELETE" },
                    { "name": &domain_fqdn, "type": "MX", "changetype": "DELETE" },
                    { "name": &domain_fqdn, "type": "TXT", "changetype": "DELETE" },
                    { "name": &dmarc_fqdn, "type": "TXT", "changetype": "DELETE" },
                    { "name": &dkim_fqdn, "type": "TXT", "changetype": "DELETE" },
                ]
            });

            let client = reqwest::Client::new();
            let result: Result<(), crate::services::pdns_api::PdnsApiError> = async {
                crate::services::pdns_api::verify_server(&client, &url, &key).await?;
                let resp = client
                    .patch(&format!("{url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                    .header("X-API-Key", &key)
                    .json(&rrsets)
                    .send()
                    .await
                    .map_err(|e| crate::services::pdns_api::PdnsApiError::Transport(e.to_string()))?;
                let (status, text) = crate::services::pdns_api::read_response(resp).await;
                crate::services::pdns_api::check_patch(status, &text)
            }.await;

            match result {
                Ok(()) => tracing::info!("Auto-DNS cleanup (mail/PowerDNS): deleted all records for {domain}"),
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    Ok(())
}

// ── Rspamd spam filter ───────────────────────────────────────────────────

/// POST /api/mail/rspamd/install
pub async fn rspamd_install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post_long("/mail/rspamd/install", None, 900).await
        .map_err(|e| agent_error("Rspamd", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.rspamd_install", None, None, None, None, claims.key_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/mail/rspamd/status
pub async fn rspamd_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/rspamd/status").await
        .map_err(|e| agent_error("Rspamd", e))?;
    Ok(Json(result))
}

/// POST /api/mail/rspamd/toggle
pub async fn rspamd_toggle(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/rspamd/toggle", Some(body)).await
        .map_err(|e| agent_error("Rspamd", e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Webmail (Roundcube) ─────────────────────────────────────────────────

/// POST /api/mail/webmail/install
pub async fn webmail_install(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.post_long("/mail/webmail/install", Some(body), 900).await
        .map_err(|e| agent_error("Webmail", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.webmail_install", None, None, None, None, claims.key_id).await;
    Ok(Json(result))
}

/// GET /api/mail/webmail/status
pub async fn webmail_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/webmail/status").await
        .map_err(|e| agent_error("Webmail", e))?;
    Ok(Json(result))
}

/// POST /api/mail/webmail/remove
pub async fn webmail_remove(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/webmail/remove", None).await
        .map_err(|e| agent_error("Webmail", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.webmail_remove", None, None, None, None, claims.key_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── SMTP Relay ──────────────────────────────────────────────────────────

/// POST /api/mail/relay/configure
pub async fn relay_configure(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/relay/configure", Some(body)).await
        .map_err(|e| agent_error("SMTP relay", e))?;
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.relay_configure", None, None, None, ip.as_deref(), claims.key_id).await;
    crate::services::security_hardening::audit_log(
        &state.db, "mail.relay_configure", Some(&claims.email), ip.as_deref(), None, None, None, None, "warning", claims.key_id,
    ).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/mail/relay/status
pub async fn relay_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/relay/status").await
        .map_err(|e| agent_error("SMTP relay", e))?;
    Ok(Json(result))
}

/// POST /api/mail/relay/remove
pub async fn relay_remove(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/relay/remove", None).await
        .map_err(|e| agent_error("SMTP relay", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.relay_remove", None, None, None, None, claims.key_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── DNS Verification ─────────────────────────────────────────────────────

/// Load a mail domain's identity for the read paths, and decide in the same query
/// whether this caller may see it.
///
/// Two questions, one row, because they have the same answer source. The identity
/// half (name, DKIM selector, public key) is what the DNS tab and the two
/// verification endpoints describe. The authorisation half is
/// [`MAIL_DOMAIN_CALLER_PREDICATE`], the same predicate every mutating handler in
/// this module resolves through - these reads were the ones that never did, so a
/// domain an administrator could not touch was still one they could read the full
/// configuration of, by id.
///
/// It also returns the domain's HOST, which is the value the DNS paths were
/// missing entirely: they described the panel's address for a domain that may live
/// anywhere in the fleet. `Option<Uuid>` and not `Uuid` - the predicate admits a
/// row that names no server (see its comment), and a read must not turn that into
/// a 404 for a domain that plainly exists. Each caller decides what an unknown
/// host means for what it is reporting.
///
/// Unlike [`mail_domain_agent_for_caller`] this resolves NO agent, and that is the
/// point: a read must not fail because the host is unreachable. Reporting a
/// domain's DNS while its server is down is exactly when an operator needs it.
async fn mail_domain_identity(
    db: &sqlx::PgPool,
    id: Uuid,
    claims: &Claims,
) -> Result<(String, String, Option<String>, Option<Uuid>), ApiError> {
    let row: Option<(String, Option<String>, Option<String>, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT md.domain, md.dkim_selector, md.dkim_public_key, md.server_id \
         FROM mail_domains md WHERE {MAIL_DOMAIN_CALLER_PREDICATE}"
    ))
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("mail domain", e))?;

    let (domain, selector, dkim_pub, server_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "Domain not found"))?;
    Ok((
        domain,
        selector.unwrap_or_else(|| {
            crate::services::prerequisites::mail::DEFAULT_DKIM_SELECTOR.to_string()
        }),
        dkim_pub,
        server_id,
    ))
}

/// GET /api/mail/domains/{id}/dns-check - Verify DNS records are propagated.
///
/// # What this used to prove, and didn't
///
/// This endpoint predates the prerequisite layer and checked only that records of
/// the right *kind* existed. MX passed on any MX at all - including a Google
/// Workspace one, i.e. exactly the configuration under which this server's mail is
/// never delivered. SPF passed on any `v=spf1` string, so a domain publishing
/// `include:sendgrid.net -all` - which explicitly forbids this server - reported a
/// pass. DKIM passed on `contains("p=")` without ever comparing our key. The A
/// record was not checked at all.
///
/// An operator could therefore be shown "All DNS records verified" for a domain
/// whose mail was being rejected. It now delegates to
/// `prerequisites::mail::check_mail_dns_published`, which compares against the
/// records we actually publish, while keeping this response shape so the existing
/// Mail DNS tab keeps working.
pub async fn dns_check(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, selector, dkim_pub, server_id) =
        mail_domain_identity(&state.db, id, &claims).await?;

    // Compare against the address of the machine this domain's mail RUNS ON.
    //
    // With `detect_public_ip_cached` this compared every domain against the
    // PANEL's address, so a correctly configured domain on a fleet member - A
    // record and SPF both naming its own host, exactly what that host needs -
    // failed both checks and was reported as broken. The endpoint's whole purpose
    // is to stop certifying a state that does not match reality, and it was
    // certifying the reverse for every domain not on this box.
    //
    // An unresolvable host degrades to the empty string ON PURPOSE rather than
    // erroring: `check_mail_dns_published` already treats that as "we could not
    // determine the expected address" and returns Unknown/Info, which the
    // projection below renders as `unknown` on every record. A single-box install
    // is unaffected - the helper detects the local address outbound, exactly as
    // this line used to - and a member with no recorded address gets an honest
    // "we can't tell" instead of a confident, wrong "misconfigured".
    //
    // Multi-IP: the apex is checked against the site's address, SPF against the
    // send address - the same pair the DNS tab and auto-DNS use.
    let (a_ip, spf_ip) =
        crate::services::server_ips::mail_dns_addresses_for(&state.db, server_id, &domain).await;
    let (a_ip, spf_ip) = (a_ip.unwrap_or_default(), spf_ip.unwrap_or_default());

    let verdict = crate::services::prerequisites::mail::check_mail_dns_published_for(
        &domain,
        &selector,
        dkim_pub.as_deref(),
        &a_ip,
        &spf_ip,
    )
    .await;

    // Project the structured verdict onto the legacy per-record shape.
    let records = match &verdict.remediation {
        Some(crate::services::prerequisites::Remediation::DnsRecords { records }) => records.clone(),
        // Satisfied (or undeterminable) results carry no remediation; re-derive the
        // set so the tab always lists every record rather than going blank.
        _ => crate::services::prerequisites::mail::mail_records_for(
            &domain,
            &selector,
            dkim_pub.as_deref(),
            &a_ip,
            &spf_ip,
        ),
    };

    let all_satisfied = verdict.state == crate::services::prerequisites::PrereqState::Satisfied;

    let checks: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            // `present` is None only when the lookup itself couldn't run - report
            // that as unknown, never as a failure.
            let status = match r.present {
                Some(true) => "pass",
                Some(false) => "fail",
                None if all_satisfied => "pass",
                None => "unknown",
            };
            serde_json::json!({
                "type": label_for(r),
                "status": status,
                "host": r.fqdn,
                "value": r.value,
                "description": r.purpose.clone().unwrap_or_default(),
            })
        })
        .collect();

    let pass_count = checks.iter().filter(|c| c["status"] == "pass").count();

    Ok(Json(serde_json::json!({
        "domain": domain,
        "checks": checks,
        "pass_count": pass_count,
        "total": checks.len(),
        "all_pass": pass_count == checks.len(),
        // The structured verdict, for surfaces that render the guidance layer
        // properly rather than the legacy pass/fail list.
        "prereq": verdict,
    })))
}

/// The short name the DNS tab shows for a record - "SPF" reads better than "TXT".
fn label_for(r: &crate::services::prerequisites::DnsRecordHint) -> &'static str {
    if r.value.starts_with("v=spf1") {
        "SPF"
    } else if r.value.starts_with("v=DMARC1") {
        "DMARC"
    } else if r.value.starts_with("v=DKIM1") {
        "DKIM"
    } else if r.record_type == "MX" {
        "MX"
    } else {
        "A"
    }
}

/// GET /api/mail/domains/{id}/preflight - The mail domain's prerequisites.
///
/// Same host, same `None` handling and same reasoning as [`dns_check`] - this is
/// the structured face of the identical evaluation, and the two must not disagree
/// about which machine the domain is expected to point at.
pub async fn preflight(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (domain, selector, dkim_pub, server_id) =
        mail_domain_identity(&state.db, id, &claims).await?;
    let (a_ip, spf_ip) =
        crate::services::server_ips::mail_dns_addresses_for(&state.db, server_id, &domain).await;

    let checks = crate::services::prerequisites::mail::evaluate_for(
        &domain,
        &selector,
        dkim_pub.as_deref(),
        &a_ip.unwrap_or_default(),
        &spf_ip.unwrap_or_default(),
    )
    .await;

    Ok(Json(serde_json::json!({ "domain": domain, "checks": checks })))
}

// ── Mail Logs & Storage (agent proxies) ──────────────────────────────────

/// GET /api/mail/logs - Parse mail.log for recent activity and stats.
pub async fn mail_logs(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/logs").await
        .map_err(|e| agent_error("Mail logs", e))?;
    Ok(Json(result))
}

/// GET /api/mail/storage - Get storage usage for all mailboxes.
pub async fn mail_storage(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/storage").await
        .map_err(|e| agent_error("Mail storage", e))?;
    Ok(Json(result))
}

// ── Blacklist / Reputation Check ────────────────────────────────────────

/// GET /api/mail/blacklist-check - Check a server's IP against email blacklists.
///
/// Reputation belongs to the ADDRESS THAT SENDS THE MAIL, so this asks about the
/// server in scope - the one whose mail queue, logs and storage the rest of this
/// page is showing - not about the process answering the request. On the panel's
/// own box those are the same address, which is why the difference never showed;
/// on a fleet member they never are, and the widget was reporting this box's
/// listings under a member's mail page. A member with a genuinely blacklisted IP
/// read as clean, which is the direction that costs deliverability silently.
///
/// `ServerScope` supplies the host and, with it, the ownership check this handler
/// had none of: it verifies the caller owns the server named in `X-Server-Id`, and
/// resolves to the local box when no header is sent.
pub async fn blacklist_check(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(server_id, _agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    // No address, no check. There is nothing to substitute here - a DNSBL answer
    // about a DIFFERENT machine is not a weaker answer, it is an answer to a
    // question nobody asked, and it would be rendered as this server's reputation.
    // Refusing is also not a regression on a single-box install: the helper detects
    // the local address outbound exactly as this line used to, so the only new
    // failure is a member that has not reported an address yet, which previously
    // produced a confidently wrong "clean".
    let Some(ip) = crate::helpers::public_ip_for_server(&state.db, Some(server_id))
        .await
        .filter(|ip| !ip.is_empty())
    else {
        return Err(err(
            StatusCode::CONFLICT,
            "No public address is recorded for this server yet, so its blacklist status \
             cannot be checked. It is reported by the agent at check-in.",
        ));
    };

    // Reverse the IP for DNSBL lookup
    let reversed: String = ip.split('.').rev().collect::<Vec<_>>().join(".");

    let blacklists = vec![
        ("zen.spamhaus.org", "Spamhaus"),
        ("bl.spamcop.net", "SpamCop"),
        ("b.barracudacentral.org", "Barracuda"),
        ("dnsbl.sorbs.net", "SORBS"),
        ("spam.dnsbl.sorbs.net", "SORBS Spam"),
        ("cbl.abuseat.org", "CBL"),
        ("dnsbl-1.uceprotect.net", "UCEPROTECT L1"),
        ("psbl.surriel.com", "PSBL"),
    ];

    // A DNSxL says "listed" with an A record and "not listed" with NXDOMAIN, so the
    // bare `is_ok()` this used to be scored every resolver outage, timeout, transport
    // failure and retired zone as a clean bill of health. That is the same
    // confidently-wrong "clean" the missing-address branch above was repaired for,
    // arriving by the other road, and it is the worse of the two: the operator is told
    // the server is not on Spamhaus at the moment the panel has in fact asked nobody,
    // and the per-zone detail is hidden exactly when the verdict is worthless.
    //
    // Two things are needed to tell "asked and told no" from "could not ask".
    //
    // First, read the ANSWER rather than merely whether one arrived. RFC 5782 §2.1
    // puts listings in 127.0.0.0/8, and the large zones answer a refused, rate-limited
    // or unauthenticated query with 127.255.255.0/24 - which is an A record, so
    // `is_ok()` scores a refusal as a LISTING. Calling a refusal "on Spamhaus" is the
    // same lie pointing the other way, and it is the one that would have an operator
    // rebuilding a mail server that was never blacklisted.
    //
    // Second, probe each zone with a query whose correct answer is known in advance.
    // RFC 5782 §5 requires every DNSxL to list the standard test address, so the
    // reversed form of it below must come back as a listing from any zone that is
    // reachable and willing to answer us.
    // When it does not, this zone told us nothing about this IP and the subject lookup
    // carries no information whatever it returned. That test needs no io::ErrorKind
    // introspection, which getaddrinfo does not report portably anyway.
    //
    // `Some(true)` = the zone answered with a listing; `Some(false)` = the zone
    // answered "not listed"; `None` = the zone refused us or could not be reached.
    async fn ask(host: String) -> Option<bool> {
        let Ok(addrs) = tokio::net::lookup_host(host).await else {
            return Some(false);
        };
        let (mut listing, mut refusal) = (false, false);
        for addr in addrs {
            if let std::net::IpAddr::V4(v4) = addr.ip() {
                let o = v4.octets();
                if o[0] == 127 {
                    if o[1] == 255 && o[2] == 255 {
                        refusal = true;
                    } else {
                        listing = true;
                    }
                }
            }
        }
        match (listing, refusal) {
            (true, _) => Some(true),
            (false, true) => None,
            (false, false) => Some(false),
        }
    }

    let mut results = Vec::new();
    for (rbl, name) in &blacklists {
        // The control and the subject go out together: the pair is one measurement and
        // sequencing them would only double the wall clock of a page load.
        let (subject, control) = tokio::join!(
            ask(format!("{reversed}.{rbl}:0")),
            ask(format!("2.0.0.127.{rbl}:0")),
        );

        // A confirmed listing needs no control: an answer inside the listing range is
        // positive evidence about THIS address, and discarding it because the zone's
        // test entry did not come back would hide a real blacklisting. The control is
        // only what licenses the OTHER direction - reading NXDOMAIN as "not listed"
        // rather than as "nobody answered".
        let (checked, listed) = match (subject, control) {
            (Some(true), _) => (true, Some(true)),
            (Some(false), Some(true)) => (true, Some(false)),
            _ => (false, None),
        };
        results.push(serde_json::json!({
            "rbl": rbl,
            "name": name,
            "checked": checked,
            "listed": match listed {
                Some(v) => serde_json::Value::Bool(v),
                None => serde_json::Value::Null,
            },
        }));
    }

    let listed_count = results.iter().filter(|r| r["listed"].as_bool() == Some(true)).count();
    let checked_count = results.iter().filter(|r| r["checked"].as_bool() == Some(true)).count();

    // A single confirmed listing is real evidence and outranks any number of zones we
    // could not reach. "clean" is reserved for the case where every zone was actually
    // asked - anything less is `unknown`, which the card must not paint green.
    let status = if listed_count > 0 {
        "listed"
    } else if checked_count == results.len() {
        "clean"
    } else {
        "unknown"
    };

    Ok(Json(serde_json::json!({
        "ip": ip,
        "results": results,
        "listed_count": listed_count,
        "checked_count": checked_count,
        "total_count": results.len(),
        "status": status,
        // Kept for wire compatibility, and now it means what it says: a `clean` of
        // false no longer implies a listing, so no consumer may infer one from it.
        "clean": status == "clean",
    })))
}

// ── Rate Limiting ───────────────────────────────────────────────────────

/// POST /api/mail/rate-limit/set
pub async fn rate_limit_set(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/rate-limit/set", Some(body)).await
        .map_err(|e| agent_error("Rate limit", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.rate_limit_set", None, None, None, None, claims.key_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/mail/rate-limit/status
pub async fn rate_limit_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/rate-limit/status").await
        .map_err(|e| agent_error("Rate limit", e))?;
    Ok(Json(result))
}

/// POST /api/mail/rate-limit/remove
pub async fn rate_limit_remove(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/rate-limit/remove", None).await
        .map_err(|e| agent_error("Rate limit", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.rate_limit_remove", None, None, None, None, claims.key_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Mailbox Backup/Restore ──────────────────────────────────────────────

/// POST /api/mail/backup
///
/// The agent's manual archive now uses the policy naming under
/// /var/backups/dockpanel/mail. When its answer names an archive of the
/// requested mailbox, the archive is recorded in `mail_backups` (no policy,
/// on the server in scope, where it was written) so it can be restored from
/// the "Mailbox backups" list like a policy archive.
pub async fn mailbox_backup(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(scope_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use crate::services::mail_dns_backup as mdb;
    let email = body.get("email").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let mut result = agent.post_long("/mail/backup", Some(body), mdb::START_TIMEOUT_SECS).await
        .map_err(|e| agent_error("Mailbox backup", e))?;
    if let Ok(mdb::AgentStart::Job(id)) = mdb::parse_agent_start(&result) {
        result = mdb::wait_job(&agent, &id, std::time::Duration::from_secs(mdb::ROUTE_JOB_BUDGET_SECS))
            .await
            .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Mailbox backup failed: {e}")))?;
    }
    if let Some((local, domain)) = mdb::split_address(&email) {
        if let Ok(a) = mdb::parse_created(&result, &mdb::mailbox_prune_spec(domain, local), false) {
            if let Err(e) = sqlx::query(
                "INSERT INTO mail_backups (server_id, kind, mail_domain, mailbox, filename, size_bytes, encrypted, sha256_hash) \
                 VALUES ($1, 'mailbox', $2, $3, $4, $5, $6, $7)",
            )
            .bind(scope_server_id).bind(domain).bind(local).bind(&a.filename).bind(a.size_bytes).bind(a.encrypted)
            .bind(if a.sha256.is_empty() { None } else { Some(&a.sha256) })
            .execute(&state.db).await
            {
                tracing::warn!("Mailbox backup of {email} written but not recorded: {e}");
            }
        }
    }
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.backup", None, None, None, None, claims.key_id).await;
    Ok(Json(result))
}

/// POST /api/mail/restore
pub async fn mailbox_restore(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.post("/mail/restore", Some(body)).await
        .map_err(|e| agent_error("Mailbox restore", e))?;
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.restore", None, None, None, None, claims.key_id).await;
    Ok(Json(result))
}

/// GET /api/mail/backups
pub async fn mailbox_backups(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/backups").await
        .map_err(|e| agent_error("Mailbox backups", e))?;
    Ok(Json(result))
}

/// POST /api/mail/backups/delete
pub async fn mailbox_backup_delete(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/backups/delete", Some(body)).await
        .map_err(|e| agent_error("Delete backup", e))?;
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.backup_delete", None, None, None, ip.as_deref(), claims.key_id).await;
    crate::services::security_hardening::audit_log(
        &state.db, "mail.backup_delete", Some(&claims.email), ip.as_deref(), None, None, None, None, "warning", claims.key_id,
    ).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Mail backups from the Backup Orchestrator (lot 3) ───────────────────

/// One `mail_backups` row a restore reads.
#[derive(sqlx::FromRow)]
struct MailBackupRef {
    server_id: Option<Uuid>,
    kind: String,
    mail_domain: Option<String>,
    mailbox: Option<String>,
    filename: String,
    encrypted: bool,
    encryption_key_version: i16,
}

/// A `mail_backups` row, only when it lives on a server this administrator
/// runs (this machine, or a server they added). The role is read from the
/// DATABASE, as `restore_volume_backup` does.
async fn mail_backup_for_caller(state: &AppState, id: Uuid, claims: &Claims) -> Result<MailBackupRef, ApiError> {
    sqlx::query_as::<_, MailBackupRef>(
        "SELECT mb.server_id, mb.kind, mb.mail_domain, mb.mailbox, mb.filename, mb.encrypted, mb.encryption_key_version \
           FROM mail_backups mb WHERE mb.id = $1 AND EXISTS (\
             SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' \
             AND sv.id = mb.server_id AND (sv.is_local OR sv.user_id = u.id))",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("read mail backup", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Mail backup not found"))
}

/// The agent's refusals said truthfully: a bad request, a wrong passphrase or a
/// damaged archive (422) and a full disk (507) keep their status and message.
fn mail_restore_agent_error(context: &str, e: crate::services::agent::AgentError) -> ApiError {
    use crate::services::agent::AgentError;
    match e {
        AgentError::Status(code @ (400 | 409 | 422 | 507), ref body) => {
            let msg = crate::error::agent_message(body);
            tracing::warn!(agent_status = code, error = %msg, "{context}");
            err(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY), &msg)
        }
        other => agent_error(context, other),
    }
}

/// What putting a manifest back into the database did.
#[derive(Default, serde::Serialize)]
pub(crate) struct ReinsertReport {
    pub domains_added: Vec<String>,
    pub accounts_added: Vec<String>,
    pub aliases_added: usize,
    pub dkim_imported: Vec<String>,
    pub warnings: Vec<String>,
}

/// Put back, from a mail manifest, the domains, mailboxes and aliases that no
/// longer exist on `server_id`. Never through `create_domain`, which generates
/// a DKIM key, publishes DNS records and provisions a certificate: the rows
/// are inserted as they were, the maildir root is created
/// (`/mail/domains/configure`, no DNS, no certificate), and the DKIM key of a
/// domain that was ADDED is reinstalled from the manifest through
/// `/mail/dkim/import`. An existing domain keeps its live key. `only_email`
/// restricts the work to one mailbox (and its domain).
///
/// The caller rebuilds the maps with `/mail/sync` afterwards.
pub(crate) async fn reinsert_from_manifest(
    db: &sqlx::PgPool,
    server_id: Uuid,
    manifest: &crate::services::mail_dns_backup::MailManifest,
    only_email: Option<&str>,
    agent: &AgentHandle,
    jwt_secret: &str,
) -> Result<ReinsertReport, ApiError> {
    let mut report = ReinsertReport::default();
    let only_domain = only_email.and_then(|e| e.rsplit_once('@').map(|(_, d)| d.to_string()));

    for d in &manifest.domains {
        if only_domain.as_deref().is_some_and(|od| od != d.domain) {
            continue;
        }
        let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_domains WHERE domain = $1 AND server_id = $2")
            .bind(&d.domain).bind(server_id)
            .fetch_optional(db).await
            .map_err(|e| internal_error("restore mail domain", e))?;
        if existing.is_some() {
            continue;
        }
        // `server_id` is always bound: a domain naming no server would make
        // every later `/mail/sync` refuse fleet-wide.
        let (domain_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO mail_domains (domain, dkim_selector, dkim_public_key, catch_all, enabled, server_id) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(&d.domain).bind(&d.dkim_selector).bind(&d.dkim_public_key)
        .bind(&d.catch_all).bind(d.enabled).bind(server_id)
        .fetch_one(db).await
        .map_err(|e| internal_error("restore mail domain", e))?;
        report.domains_added.push(d.domain.clone());

        if let Err(e) = agent.post("/mail/domains/configure", Some(serde_json::json!({ "domain": d.domain }))).await {
            report.warnings.push(format!("{}: the maildir root could not be created: {e}", d.domain));
        }

        let Some(enc) = &d.dkim_private_key_enc else {
            report.warnings.push(format!("{}: no DKIM key in the backup", d.domain));
            continue;
        };
        let pem = match crate::services::secrets_crypto::decrypt_credential(enc, jwt_secret) {
            Ok(p) => p,
            Err(_) => {
                report.warnings.push(format!(
                    "{}: the DKIM key in the backup cannot be decrypted with this panel's key",
                    d.domain
                ));
                continue;
            }
        };
        match agent
            .post(
                "/mail/dkim/import",
                Some(serde_json::json!({ "domain": d.domain, "selector": d.dkim_selector, "private_key_pem": pem })),
            )
            .await
        {
            Ok(v) => {
                let public = v.get("public_key").and_then(|p| p.as_str()).or(d.dkim_public_key.as_deref());
                match store_dkim_key(db, domain_id, &d.dkim_selector, &pem, public, jwt_secret).await {
                    Ok(()) => report.dkim_imported.push(d.domain.clone()),
                    Err(e) => report.warnings.push(format!("{}: DKIM key installed but not recorded: {e}", d.domain)),
                }
            }
            Err(e) => report.warnings.push(format!(
                "{}: the DKIM key could not be reinstalled: {}",
                d.domain,
                crate::services::mail_dns_backup::agent_error_text(&e)
            )),
        }
    }

    for a in &manifest.accounts {
        if only_email.is_some_and(|o| !o.eq_ignore_ascii_case(&a.email)) {
            continue;
        }
        let domain_id: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_domains WHERE domain = $1 AND server_id = $2")
            .bind(&a.domain).bind(server_id)
            .fetch_optional(db).await
            .map_err(|e| internal_error("restore mail account", e))?;
        let Some((domain_id,)) = domain_id else {
            report.warnings.push(format!("{}: its domain is not on this server", a.email));
            continue;
        };
        // `mail_accounts.email` is unique across the fleet: an address that
        // now lives elsewhere is reported, not moved.
        let r = sqlx::query(
            "INSERT INTO mail_accounts (domain_id, email, password_hash, display_name, quota_mb, enabled, forward_to, \
             keep_copy, autoresponder_enabled, autoresponder_subject, autoresponder_body) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 \
              WHERE NOT EXISTS (SELECT 1 FROM mail_accounts WHERE lower(email) = lower($2))",
        )
        .bind(domain_id).bind(&a.email).bind(&a.password_hash).bind(&a.display_name).bind(a.quota_mb)
        .bind(a.enabled).bind(&a.forward_to).bind(a.keep_copy).bind(a.autoresponder_enabled)
        .bind(&a.autoresponder_subject).bind(&a.autoresponder_body)
        .execute(db).await
        .map_err(|e| internal_error("restore mail account", e))?;
        if r.rows_affected() > 0 {
            report.accounts_added.push(a.email.clone());
        }
    }

    if only_email.is_none() {
        for al in &manifest.aliases {
            let domain_id: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM mail_domains WHERE domain = $1 AND server_id = $2")
                .bind(&al.domain).bind(server_id)
                .fetch_optional(db).await
                .map_err(|e| internal_error("restore mail alias", e))?;
            let Some((domain_id,)) = domain_id else { continue };
            let r = sqlx::query(
                "INSERT INTO mail_aliases (domain_id, source_email, destination_email) \
                 SELECT $1, $2, $3 WHERE NOT EXISTS ( \
                   SELECT 1 FROM mail_aliases WHERE source_email = $2 AND destination_email = $3)",
            )
            .bind(domain_id).bind(&al.source_email).bind(&al.destination_email)
            .execute(db).await
            .map_err(|e| internal_error("restore mail alias", e))?;
            report.aliases_added += r.rows_affected() as usize;
        }
    }
    Ok(report)
}

/// Read the manifest of a config archive through the agent (it decrypts and
/// hands it back; it restores no file).
async fn fetch_manifest(
    agent: &AgentHandle,
    filename: &str,
    key: &str,
) -> Result<crate::services::mail_dns_backup::MailManifest, ApiError> {
    use crate::services::mail_dns_backup as mdb;
    let resp = agent
        .post_long("/mail/restore", Some(mdb::mail_config_restore_body(filename, key)), mdb::START_TIMEOUT_SECS)
        .await
        .map_err(|e| mail_restore_agent_error("Read mail config backup", e))?;
    if resp.get("skipped").is_some() {
        return Err(err(StatusCode::CONFLICT, "The mail server is not installed on this server"));
    }
    let manifest = resp.get("manifest").ok_or_else(|| err(StatusCode::BAD_GATEWAY, "The agent returned no manifest"))?;
    mdb::parse_mail_manifest(manifest).map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &e))
}

/// Rebuild the server's maps after rows were put back. Only a rebuild the
/// agent applied counts: Dovecot must know a mailbox before its mail is
/// re-indexed for it.
async fn sync_after_restore(state: &AppState, server_id: Uuid, agent: &AgentHandle) -> Result<(), ApiError> {
    match sync_mail_config_report(state, server_id, agent).await? {
        SyncReport::Applied(_) => Ok(()),
        SyncReport::GatherFailed(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("The mail configuration could not be gathered: {e}"))),
        SyncReport::AgentFailed(e) => Err(err(StatusCode::BAD_GATEWAY, &format!("The mail configuration could not be applied: {}", agent_failure_text(&e)))),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct MailRestoreRequest {
    /// `merge` (default: mail newer than the backup is kept) or `replace`.
    pub mode: Option<String>,
}

/// POST /api/mail/backups/{id}/restore - Restore one mailbox from a
/// `mail_backups` row, on the server that holds the archive.
///
/// When the mailbox's account no longer exists, it is recreated first from
/// the newest config backup of that server (original password hash), and the
/// maps are rebuilt. Answers 200 with the agent's result, or 202
/// `{status: "running", job_id, server_id}` when the restore outlives this
/// request (follow it with GET /api/backup-orchestrator/backup-jobs/...).
pub async fn restore_mail_backup(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MailRestoreRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use crate::services::backup_policy_executor as bpe;
    use crate::services::mail_dns_backup as mdb;

    let mode = mdb::RestoreMode::parse(req.mode.as_deref())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "mode must be 'merge' or 'replace'"))?;
    let row = mail_backup_for_caller(&state, id, &claims).await?;
    if row.kind != "mailbox" {
        return Err(err(StatusCode::BAD_REQUEST, "This backup is the mail config; use Restore all mail"));
    }
    let (Some(domain), Some(local)) = (row.mail_domain.clone(), row.mailbox.clone()) else {
        return Err(err(StatusCode::CONFLICT, "This backup names no mailbox"));
    };
    if !mdb::is_plain_filename(&row.filename) || !crate::routes::is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid backup path"));
    }
    let email = format!("{local}@{domain}");
    let agent = crate::helpers::agent_for_site_server(&state, row.server_id, &domain).await?;
    let Some(server_id) = row.server_id else {
        return Err(err(StatusCode::CONFLICT, "This backup has no server"));
    };

    // The account must exist for Dovecot to take the mail back.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_accounts a JOIN mail_domains md ON md.id = a.domain_id \
          WHERE lower(a.email) = lower($1) AND md.server_id = $2)",
    )
    .bind(&email).bind(server_id)
    .fetch_one(&state.db).await
    .map_err(|e| internal_error("restore mailbox", e))?;
    let mut account_recreated = false;
    if !exists {
        let cfg: Option<(String, bool, i16)> = sqlx::query_as(
            "SELECT filename, encrypted, encryption_key_version FROM mail_backups \
              WHERE server_id = $1 AND kind = 'config' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(server_id)
        .fetch_optional(&state.db).await
        .map_err(|e| internal_error("restore mailbox", e))?;
        let Some((cfg_file, cfg_enc, cfg_ver)) = cfg else {
            return Err(err(
                StatusCode::CONFLICT,
                "This mailbox no longer exists and no mail config backup of this server can recreate it",
            ));
        };
        let key = bpe::row_encryption_key(cfg_enc, cfg_ver, &state.config.jwt_secret)
            .ok_or_else(|| err(StatusCode::CONFLICT, "The mail config backup is not encrypted; refusing to read it"))?;
        let manifest = fetch_manifest(&agent, &cfg_file, &key).await?;
        if !manifest.accounts.iter().any(|a| a.email.eq_ignore_ascii_case(&email)) {
            return Err(err(StatusCode::CONFLICT, "This mailbox no longer exists and the latest mail config backup does not describe it"));
        }
        let report = reinsert_from_manifest(&state.db, server_id, &manifest, Some(&email), &agent, &state.config.jwt_secret).await?;
        account_recreated = report.accounts_added.iter().any(|a| a.eq_ignore_ascii_case(&email));
        if !account_recreated {
            return Err(err(StatusCode::CONFLICT, &format!(
                "The mailbox could not be recreated: {}",
                report.warnings.join("; ")
            )));
        }
        sync_after_restore(&state, server_id, &agent).await?;
    }

    let key = bpe::row_encryption_key(row.encrypted, row.encryption_key_version, &state.config.jwt_secret);
    let body = mdb::mailbox_restore_body(&domain, &local, &row.filename, mode, key.as_deref());
    let start = agent.post_long("/mail/restore", Some(body), mdb::START_TIMEOUT_SECS).await
        .map_err(|e| mail_restore_agent_error("Mailbox restore", e))?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.backup_restore",
        Some("mail"), Some(&email), Some(&row.filename), ip.as_deref(), claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "mail.backup_restore", Some(&claims.email), ip.as_deref(),
        Some("mail"), Some(&email), Some(mode.as_str()), None, "warning", claims.key_id,
    ).await;

    let result = match mdb::parse_agent_start(&start).map_err(|e| err(StatusCode::BAD_GATEWAY, &e))? {
        mdb::AgentStart::Skipped(_) => {
            return Err(err(StatusCode::CONFLICT, "The mail server is not installed on this server"));
        }
        mdb::AgentStart::Done(v) => v,
        mdb::AgentStart::Job(job_id) => {
            match mdb::wait_job(&agent, &job_id, std::time::Duration::from_secs(mdb::ROUTE_JOB_BUDGET_SECS)).await {
                Ok(v) => v,
                Err(mdb::JobWaitError::TimedOut) => {
                    return Ok((StatusCode::ACCEPTED, Json(serde_json::json!({
                        "status": "running",
                        "job_id": job_id,
                        "server_id": server_id,
                        "message": "The restore is still running on the server.",
                    }))));
                }
                Err(mdb::JobWaitError::Failed(msg, code)) => {
                    // The agent classed the failure (422 integrity or passphrase,
                    // 400 validation, 507 disk...): same status and message as the
                    // synchronous restores give.
                    return Err(match mdb::job_failure_status(code) {
                        502 => err(StatusCode::BAD_GATEWAY, &format!("Mailbox restore failed: {msg}")),
                        c => err(StatusCode::from_u16(c).unwrap_or(StatusCode::BAD_GATEWAY), &msg),
                    });
                }
                Err(e) => return Err(err(StatusCode::BAD_GATEWAY, &format!("Mailbox restore failed: {e}"))),
            }
        }
    };
    Ok((StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "mode": mode.as_str(),
        "messages": result.get("messages").cloned().unwrap_or(serde_json::Value::Null),
        "account_recreated": account_recreated,
    }))))
}

/// POST /api/mail/backups/{id}/restore-all - From a config backup: put back
/// the domains, mailboxes and aliases that are missing on its server (no
/// certificate, no DNS change), reinstall the DKIM keys of the domains put
/// back, rebuild the maps, then restore every mailbox of the manifest from its
/// newest backup on that server, one by one (merge), in the background.
///
/// Answers 202 once the configuration is back: restoring every mailbox can
/// take far longer than a request may. The outcome lands in the system log and
/// in the panel notifications.
pub async fn restore_all_mail(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use crate::services::backup_policy_executor as bpe;
    use crate::services::mail_dns_backup as mdb;

    let row = mail_backup_for_caller(&state, id, &claims).await?;
    if row.kind != "config" {
        return Err(err(StatusCode::BAD_REQUEST, "Restore all mail starts from a mail config backup"));
    }
    if !mdb::is_plain_filename(&row.filename) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid backup path"));
    }
    let agent = crate::helpers::agent_for_site_server(&state, row.server_id, "mail config").await?;
    let Some(server_id) = row.server_id else {
        return Err(err(StatusCode::CONFLICT, "This backup has no server"));
    };
    let key = bpe::row_encryption_key(row.encrypted, row.encryption_key_version, &state.config.jwt_secret)
        .ok_or_else(|| err(StatusCode::CONFLICT, "The mail config backup is not encrypted; refusing to read it"))?;
    let manifest = fetch_manifest(&agent, &row.filename, &key).await?;
    let report = reinsert_from_manifest(&state.db, server_id, &manifest, None, &agent, &state.config.jwt_secret).await?;
    sync_after_restore(&state, server_id, &agent).await?;

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "mail.backup_restore_all",
        Some("mail"), None, Some(&row.filename), ip.as_deref(), claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "mail.backup_restore_all", Some(&claims.email), ip.as_deref(),
        Some("mail"), None, Some(&row.filename), None, "warning", claims.key_id,
    ).await;

    let mailboxes = manifest.accounts.len();
    let db = state.db.clone();
    let jwt = state.config.jwt_secret.clone();
    let user = claims.sub;
    let accounts: Vec<String> = manifest.accounts.iter().map(|a| a.email.clone()).collect();
    tokio::spawn(async move {
        let mut restored = 0usize;
        let mut problems: Vec<String> = Vec::new();
        for email in &accounts {
            let Some((local, domain)) = mdb::split_address(email) else { continue };
            let latest: Result<Option<(String, bool, i16)>, _> = sqlx::query_as(
                "SELECT filename, encrypted, encryption_key_version FROM mail_backups \
                  WHERE server_id = $1 AND kind = 'mailbox' AND mail_domain = $2 AND mailbox = $3 \
                  ORDER BY created_at DESC LIMIT 1",
            )
            .bind(server_id).bind(domain).bind(local)
            .fetch_optional(&db).await;
            let (file, enc, ver) = match latest {
                Ok(Some(r)) => r,
                Ok(None) => {
                    problems.push(format!("{email}: no backup"));
                    continue;
                }
                Err(e) => {
                    problems.push(format!("{email}: {e}"));
                    continue;
                }
            };
            let key = bpe::row_encryption_key(enc, ver, &jwt);
            let body = mdb::mailbox_restore_body(domain, local, &file, mdb::RestoreMode::Merge, key.as_deref());
            match mdb::start_and_wait(&agent, "/mail/restore", body, std::time::Duration::from_secs(mdb::JOB_BUDGET_SECS)).await {
                Ok(mdb::JobOutcome::Done(_)) => restored += 1,
                Ok(mdb::JobOutcome::Skipped(r)) => problems.push(format!("{email}: skipped ({r})")),
                Ok(mdb::JobOutcome::StillRunning(id)) => problems.push(format!("{email}: still running (job {id})")),
                Err(e) => problems.push(format!("{email}: {e}")),
            }
        }
        let (level, title) = if problems.is_empty() {
            ("info", format!("All mail restored: {restored} mailbox(es)"))
        } else {
            ("warning", format!("Mail restore finished: {restored} of {} mailbox(es) restored", accounts.len()))
        };
        let details = problems.join("\n");
        crate::services::system_log::log_event(
            &db, level, "mail_restore", &title, if details.is_empty() { None } else { Some(&details) },
        ).await;
        crate::services::notifications::notify_panel(
            &db, Some(user), &title,
            if problems.is_empty() { "Every mailbox of the backup was restored." } else { details.as_str() },
            level, "backup", Some("/mail"),
        ).await;
    });

    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({
        "started": true,
        "message": format!("Mail configuration restored. {mailboxes} mailbox(es) are being restored in the background."),
        "domains_added": report.domains_added,
        "accounts_added": report.accounts_added,
        "aliases_added": report.aliases_added,
        "dkim_imported": report.dkim_imported,
        "warnings": report.warnings,
        "mailboxes": mailboxes,
    }))))
}

// ── TLS Enforcement ─────────────────────────────────────────────────────

/// GET /api/mail/tls/status
pub async fn tls_status(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = agent.get("/mail/tls/status").await
        .map_err(|e| agent_error("TLS status", e))?;
    Ok(Json(result))
}

/// POST /api/mail/tls/enforce
pub async fn tls_enforce(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    agent.post("/mail/tls/enforce", Some(body)).await
        .map_err(|e| agent_error("TLS enforce", e))?;
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(&state.db, claims.sub, &claims.email, "mail.tls_enforce", None, None, None, ip.as_deref(), claims.key_id).await;
    crate::services::security_hardening::audit_log(
        &state.db, "mail.tls_enforce", Some(&claims.email), ip.as_deref(), None, None, None, None, "warning", claims.key_id,
    ).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// The one predicate that decides whether a caller may act on a mail domain.
///
/// Binds `$1` = the mail domain id, `$2` = the caller's own id - the same two
/// parameters, in the same order, as [`crate::helpers::SITE_CALLER_PREDICATE`],
/// so a query that joins another table onto `mail_domains` can add its own bind
/// as `$3` and drop this in unchanged.
///
/// There are TWO ways to satisfy it: administer the machine the row names, or
/// own the site of the same name on that machine. `mail_domains` still has no
/// `user_id` column (`migrations/20260315200000_mail_management.sql`) - the
/// second arm answers ownership through `sites`, which is what GitHub #106 asks
/// for and is documented on the arm itself below.
///
/// On the administrator arm, `is_local` is this box and `sv.user_id` is a member
/// this same administrator registered. So an administrator reaches every mail
/// domain on the hardware they operate and none on a machine somebody else
/// added - the same line `SITE_CALLER_PREDICATE`'s admin arm draws.
///
/// Before this, the mail handlers drew no line whatsoever. Each loaded its row
/// with a bare `WHERE id = $1` and the only thing standing between an
/// administrator and another administrator's fleet member was `ServerScope`'s
/// check on the `X-Server-Id` request header. Removing that extractor without
/// putting this in its place would have WIDENED the surface while appearing to
/// narrow it.
///
/// ⚠ A row naming NO server is admitted DELIBERATELY, and it is not a hole - but
/// it now sits INSIDE the administrator arm rather than in front of both, because
/// as a free-standing disjunct it carried no caller term at all and would have
/// admitted every site owner in the installation the moment the second arm
/// existed. It is still admitted for an administrator, and it must stay that way:
/// admitting it hands the row to [`crate::helpers::agent_for_site_server`], which
/// refuses it by name with a 409 that says what is wrong, and
/// [`sync_mail_config`]'s precondition counts exactly these rows and tells the
/// operator to backfill them. Excluding it would collapse both into "Domain not
/// found" - a 404 for a domain that plainly exists, read as "already cleaned up".
///
/// ⚠ The role is read from `users.role` in the DATABASE, not from `claims.role`
/// in the token, for the reason spelled out on `SITE_CALLER_PREDICATE`: a JWT
/// keeps asserting whatever role it was minted with until it expires, so a
/// demoted account would keep administering mail for the rest of its session.
/// That mattered more once the handlers stopped taking an admin-only extractor:
/// the token no longer decides anything here, the database does.
///
/// ── The site-owner arm (GitHub #106) ────────────────────────────────────
///
/// A mail domain is also reachable by the account that owns the SITE of the same
/// name on the SAME server. `mail_domains` has no owner column, so the site is
/// where the ownership question is answered; this is the entitlement itself.
///
/// **The server term is not a hardening nicety - it is the whole boundary.**
/// `sites` is unique on `(domain, server_id)` and NOT on domain, and
/// `mail_domains` likewise. Without it, an administrator creating a mail domain
/// on ANY machine in the fleet hands every mailbox on it to whichever account
/// happens to hold a site of that name on some other machine. With it, both
/// sides are keyed identically and the join is 1:1 - which is exactly the
/// same-name-same-host pairing `may_claim_mail_held` is written around.
/// Consequence worth stating rather than discovering: a domain whose website and
/// mailboxes live on DIFFERENT hosts stays administrator-only.
///
/// **`lower(s.domain)` compares, and the second clause is why that is safe.**
/// `mail_domains.domain` is lowercased by its only writer; `sites.domain` only
/// has been since the domain-claim module landed, so legacy rows may hold mixed
/// case. Folding one side alone would let two rows differing only in case both
/// match - so the arm additionally requires that NO OTHER account owns a
/// case-variant of the name on that server. One owner, or nobody: it fails
/// CLOSED on exactly the legacy data that could otherwise widen it.
///
/// A normalising migration was considered and deliberately REJECTED. The unique
/// index is on the raw column, so lowercasing in bulk raises a duplicate key on
/// precisely the installs that have the problem - and a failed migration aborts
/// startup. `sites.domain` is also the on-disk vhost key, which SQL cannot
/// rename. The quantifier below costs two clauses and touches no rows.
///
/// ⚠ Site ownership alone authorises; there is deliberately no role term on this
/// arm. Ownership of the row IS the grant, exactly as it is for the site itself,
/// and adding one would leave the same state reachable through a role that lacks
/// it. What a non-administrator may not do is CREATE the pairing - that is
/// `may_claim_mail_held`'s job, and it refuses every non-admin, not just clients.
const MAIL_DOMAIN_CALLER_PREDICATE: &str = "md.id = $1 AND (EXISTS (\
    SELECT 1 FROM users u WHERE u.id = $2 AND u.role = 'admin' AND (\
    md.server_id IS NULL OR EXISTS (\
    SELECT 1 FROM servers sv WHERE sv.id = md.server_id \
    AND (sv.is_local OR sv.user_id = u.id)))) \
    OR (EXISTS (\
    SELECT 1 FROM sites s WHERE s.server_id = md.server_id \
    AND lower(s.domain) = md.domain AND s.user_id = $2) \
    AND NOT EXISTS (\
    SELECT 1 FROM sites s2 WHERE s2.server_id = md.server_id \
    AND lower(s2.domain) = md.domain AND s2.user_id <> $2)))";

/// Resolve a mail domain the caller may act on, AND the agent for the host it is
/// actually configured on.
///
/// "Which server did the browser have selected" and "which server is this mail
/// domain on" are different questions. Every mutating handler in this module used
/// to answer the first, because `ServerScope` was sitting in its argument list and
/// the row's own `server_id` was never read. The row is the authority.
///
/// Returns the domain name, the server it names, and a handle to that server. A
/// host that will not resolve is REFUSED rather than quietly replaced with this
/// one - see [`crate::helpers::agent_for_site_server`], the single choke point
/// every mail dispatch now funnels through.
async fn mail_domain_agent_for_caller(
    state: &AppState,
    domain_id: Uuid,
    claims: &Claims,
) -> Result<(String, Uuid, AgentHandle), ApiError> {
    let row: Option<(String, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT md.domain, md.server_id FROM mail_domains md WHERE {MAIL_DOMAIN_CALLER_PREDICATE}"
    ))
    .bind(domain_id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("resolve mail domain for caller", e))?;

    let (domain, server_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "Domain not found"))?;

    let agent = crate::helpers::agent_for_site_server(state, server_id, &domain).await?;
    let Some(server_id) = server_id else {
        // Unreachable today - `agent_for_site_server` refuses a `None` server_id
        // above. Written as a branch rather than an `unwrap` so that if that
        // refusal is ever softened, this becomes a 409 instead of a panic.
        return Err(err(
            StatusCode::CONFLICT,
            "This mail domain is not associated with a server",
        ));
    };
    Ok((domain, server_id, agent))
}

/// Resolve a mailbox the caller may act on, and the host of the domain it belongs to.
///
/// `mail_accounts` carries no server of its own; it reaches one only through
/// `mail_accounts.domain_id → mail_domains.server_id`, which is what the join is
/// for. Keeping `md.id = $1` from the shared predicate against the `{domain_id}`
/// path segment also preserves the pairing check the previous
/// `WHERE id = $1 AND domain_id = $2` queries made: a mismatched
/// (domain, account) pair still resolves to nothing and still 404s.
///
/// Returns the mailbox address, the server, and its agent.
async fn mail_account_agent_for_caller(
    state: &AppState,
    domain_id: Uuid,
    account_id: Uuid,
    claims: &Claims,
) -> Result<(String, Uuid, AgentHandle), ApiError> {
    let row: Option<(String, String, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT a.email, md.domain, md.server_id FROM mail_accounts a \
         JOIN mail_domains md ON md.id = a.domain_id \
         WHERE a.id = $3 AND {MAIL_DOMAIN_CALLER_PREDICATE}"
    ))
    .bind(domain_id)
    .bind(claims.sub)
    .bind(account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("resolve mail account for caller", e))?;

    let (email, domain, server_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "Account not found"))?;

    let agent = crate::helpers::agent_for_site_server(state, server_id, &domain).await?;
    let Some(server_id) = server_id else {
        return Err(err(
            StatusCode::CONFLICT,
            "This mail domain is not associated with a server",
        ));
    };
    Ok((email, server_id, agent))
}

/// Resolve an alias the caller may act on, and the host of the domain it belongs to.
/// Same shape and same reasoning as [`mail_account_agent_for_caller`], against
/// `mail_aliases`. Returns the alias source address, the server, and its agent.
async fn mail_alias_agent_for_caller(
    state: &AppState,
    domain_id: Uuid,
    alias_id: Uuid,
    claims: &Claims,
) -> Result<(String, Uuid, AgentHandle), ApiError> {
    let row: Option<(String, String, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT al.source_email, md.domain, md.server_id FROM mail_aliases al \
         JOIN mail_domains md ON md.id = al.domain_id \
         WHERE al.id = $3 AND {MAIL_DOMAIN_CALLER_PREDICATE}"
    ))
    .bind(domain_id)
    .bind(claims.sub)
    .bind(alias_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("resolve mail alias for caller", e))?;

    let (source, domain, server_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "Alias not found"))?;

    let agent = crate::helpers::agent_for_site_server(state, server_id, &domain).await?;
    let Some(server_id) = server_id else {
        return Err(err(
            StatusCode::CONFLICT,
            "This mail domain is not associated with a server",
        ));
    };
    Ok((source, server_id, agent))
}

/// Collect the mail configuration THAT ONE SERVER hosts, in the shape
/// `/mail/sync` consumes.
///
/// The three reads used to have no `WHERE` clause of any kind. `mail_accounts`
/// and `mail_aliases` still have no server column of their own, so they reach one
/// the only way they can - through `mail_domains.server_id` on the domain that
/// owns them.
///
/// Separated from [`sync_mail_config`] so that a database failure while gathering
/// stays distinguishable from the safety precondition, which must never be
/// swallowed. Only the precondition is fatal to the request.
///
/// Multi-IP: each domain also carries `send_ip` + `helo` (resolved here - the
/// agent does no resolution), and the root carries `primary_helo`. Only the agent
/// knows which address is its primary one, so `agent_primary` is its answer to
/// `GET /system/ips`, or `None` when that could not be asked.
async fn mail_sync_payload(
    db: &sqlx::PgPool,
    server_id: Uuid,
    agent_primary: Option<&str>,
) -> Result<serde_json::Value, sqlx::Error> {
    // Same rows as `SELECT domain, enabled, catch_all FROM mail_domains WHERE
    // server_id = $1 ORDER BY domain`, plus what the send-address resolution needs.
    let domains = crate::services::server_ips::mail_ip_rows_for_server(db, server_id).await?;

    let declared: Vec<crate::services::server_ips::DeclaredIp> =
        sqlx::query_as("SELECT id, ip, public_ip, ptr FROM server_ips WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(db)
            .await?;

    let accounts: Vec<SyncAccountRow> = sqlx::query_as(
        "SELECT a.email, a.password_hash, a.quota_mb, a.enabled, a.forward_to, a.keep_copy \
         FROM mail_accounts a JOIN mail_domains md ON md.id = a.domain_id \
         WHERE md.server_id = $1 ORDER BY a.email",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?;

    let aliases: Vec<(String, String)> = sqlx::query_as(
        "SELECT al.source_email, al.destination_email \
         FROM mail_aliases al JOIN mail_domains md ON md.id = al.domain_id \
         WHERE md.server_id = $1 ORDER BY al.source_email",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?;

    Ok(build_sync_payload(&domains, &accounts, &aliases, &declared, agent_primary))
}

/// `(email, password_hash, quota_mb, enabled, forward_to, keep_copy)`.
type SyncAccountRow = (String, String, i32, bool, Option<String>, bool);

/// The `/mail/sync` body from already-loaded rows. Pure, so the shape the agent
/// consumes is pinned by unit tests.
fn build_sync_payload(
    domains: &[crate::services::server_ips::MailIpRow],
    accounts: &[SyncAccountRow],
    aliases: &[(String, String)],
    declared: &[crate::services::server_ips::DeclaredIp],
    agent_primary: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "domains": domains.iter().map(|d| {
            let (send_ip, helo) =
                crate::services::server_ips::sync_send_fields(&d.send_ip(), agent_primary);
            serde_json::json!({
                "domain": d.domain, "enabled": d.enabled, "catch_all": d.catch_all,
                "send_ip": send_ip, "helo": helo,
            })
        }).collect::<Vec<_>>(),
        "accounts": accounts.iter().map(|(email, hash, quota, enabled, fwd, keep_copy)| serde_json::json!({
            "email": email, "password_hash": hash, "quota_mb": quota, "enabled": enabled, "forward_to": fwd,
            "keep_copy": keep_copy,
        })).collect::<Vec<_>>(),
        "aliases": aliases.iter().map(|(src, dst)| serde_json::json!({
            "source": src, "destination": dst
        })).collect::<Vec<_>>(),
        "primary_helo": crate::services::server_ips::primary_helo(declared, agent_primary),
    })
}

/// The agent's primary address (`GET /system/ips` → `primary`), best-effort.
/// `None` on an agent that predates multi-IP or cannot be asked: the payload then
/// still names each domain's address explicitly, and only `primary_helo` is lost.
pub(crate) async fn agent_primary_ip(agent: &AgentHandle) -> Option<String> {
    match agent.get("/system/ips").await {
        Ok(v) => v.get("primary").and_then(|p| p.as_str()).map(str::to_string),
        Err(e) => {
            tracing::debug!("Could not read the agent's primary address: {e}");
            None
        }
    }
}

/// Rebuild ONE server's Postfix/Dovecot maps from the rows that name that server.
///
/// # What it used to send, and to whom
///
/// This took only an agent handle and read every mail row in the installation -
/// `SELECT domain, enabled, catch_all FROM mail_domains` with no `WHERE`, and the
/// same for `mail_accounts` and `mail_aliases`. Two defects compounded. The
/// payload was fleet-wide, so every mailbox's `password_hash` and `forward_to`
/// and every alias in the whole panel were written into one host's maps. And the
/// destination was the caller's `X-Server-Id` header, so an edit made with member
/// B showing in the server switcher published member A's tenants' mailbox
/// credentials onto B, and made B authenticate those mailboxes and accept mail for
/// domains it does not host. A credential disclosure onto a machine that must
/// never hold it, plus a mail-interception primitive, from a dropdown.
///
/// The server id now comes from the row being edited, and the rows now come from
/// that same server.
///
/// # Why an un-scoped domain stops the whole rebuild
///
/// `mail_domains.server_id` is NULLABLE - the multi-server migration set
/// `NOT NULL` on `sites`, `docker_stacks` and `git_deploys` and left this column
/// alone - and its one-time backfill only ever touched rows that existed when the
/// migration ran.
///
/// `/mail/sync` REBUILDS the maps; it does not merge into them. So a filtered
/// payload that omits an un-scoped domain does not merely fail to update that
/// domain - if the domain happens to live on the target box, the rebuild DELETES
/// its mailboxes from Postfix and Dovecot. And nothing here can tell whether it
/// does: a `NULL` server_id is not evidence of the local box, it is the absence of
/// evidence, and guessing a host is exactly what this whole change exists to stop.
///
/// So the rebuild refuses while any such row exists, loudly, rather than shipping
/// a subset that silently prunes live mailboxes. That is a precondition on the
/// DATA, not on the request, which is why it is fatal where an unreachable agent
/// is not: the caller can fix it (assign the domains), and until they do there is
/// no safe payload to send to any host in the fleet.
pub(crate) async fn sync_mail_config_report(
    state: &AppState,
    server_id: Uuid,
    agent: &AgentHandle,
) -> Result<SyncReport, ApiError> {
    sync_mail_config_report_db(&state.db, server_id, agent).await
}

/// [`sync_mail_config_report`] from a bare pool - the only part of the state
/// it reads. Used by the HestiaCP import executor, which has no `AppState`.
pub(crate) async fn sync_mail_config_report_db(
    db: &sqlx::PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
) -> Result<SyncReport, ApiError> {
    let unscoped: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mail_domains WHERE server_id IS NULL")
            .fetch_one(db)
            .await
            .map_err(|e| internal_error("count unscoped mail domains", e))?;

    if unscoped > 0 {
        tracing::error!(
            "Refusing to rebuild mail maps on server {server_id}: {unscoped} mail domain(s) \
             name no server. A rebuild that omits them would delete their mailboxes from \
             whichever box actually hosts them, and nothing here can tell which box that is. \
             Backfill mail_domains.server_id."
        );
        return Err(err(
            StatusCode::CONFLICT,
            &format!(
                "{unscoped} mail domain(s) are not assigned to a server, so mail configuration \
                 cannot be applied to any server without risking the removal of live mailboxes. \
                 The change was saved. Assign every mail domain to a server, then retry."
            ),
        ));
    }

    // Everything past the precondition stays best-effort, exactly as it was when
    // every call site spelled `let _ = sync_mail_config(…)`. A transient database
    // blip or an agent that is down must not turn a saved change into a 500 - it
    // never did, and widening that here would be a behaviour change hiding inside
    // a security fix.
    let agent_primary = agent_primary_ip(agent).await;
    let payload = match mail_sync_payload(db, server_id, agent_primary.as_deref()).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Mail sync for server {server_id}: gathering configuration failed: {e}");
            return Ok(SyncReport::GatherFailed(e.to_string()));
        }
    };

    match agent.post("/mail/sync", Some(payload)).await {
        Ok(v) => Ok(SyncReport::Applied(v)),
        Err(e) => {
            tracing::warn!("Mail sync for server {server_id}: agent rejected the rebuild: {e}");
            Ok(SyncReport::AgentFailed(e))
        }
    }
}

/// What a mail rebuild past its precondition came to. Every caller that only
/// needs "best-effort" goes through [`sync_mail_config`]; the two handlers whose
/// whole purpose is the sending address (`set_send_ip`, the site's
/// `set_ip`) read it to tell the operator when it did not take.
pub(crate) enum SyncReport {
    /// The agent answered; its body (`ip_transports: {applied, skipped}`).
    Applied(serde_json::Value),
    GatherFailed(String),
    AgentFailed(crate::services::agent::AgentError),
}

impl SyncReport {
    /// `None` when the per-domain sending address `send_ip` is in effect;
    /// `Some(reason)` when it is not. `send_ip: None` (primary) only needs the
    /// sync itself to have succeeded.
    pub(crate) fn send_ip_problem(&self, send_ip: Option<&str>) -> Option<String> {
        match self {
            SyncReport::GatherFailed(e) => Some(format!("the mail configuration could not be gathered: {e}")),
            SyncReport::AgentFailed(e) => Some(agent_failure_text(e)),
            SyncReport::Applied(v) => {
                let t = v.get("ip_transports");
                let applied = t.and_then(|t| t.get("applied")).and_then(|a| a.as_bool());
                let skipped: Vec<String> = t
                    .and_then(|t| t.get("skipped"))
                    .and_then(|s| s.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if applied == Some(false) {
                    return Some("the agent did not apply the per-domain sending addresses".to_string());
                }
                match send_ip {
                    Some(ip) if skipped.iter().any(|s| s == ip) => Some(format!(
                        "the agent skipped the sending address {ip} (it is not present on the server's interface)"
                    )),
                    _ => None,
                }
            }
        }
    }
}

/// The agent's own sentence for a failed call, for a message the operator reads.
fn agent_failure_text(e: &crate::services::agent::AgentError) -> String {
    match e {
        crate::services::agent::AgentError::Status(code, body) => {
            let msg = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(str::to_string))
                .unwrap_or_else(|| body.chars().take(300).collect());
            format!("agent returned {code}: {msg}")
        }
        other => other.to_string(),
    }
}

/// Best-effort rebuild: the precondition is still fatal, everything after it
/// is logged and swallowed, exactly as before multi-IP.
pub(crate) async fn sync_mail_config(
    state: &AppState,
    server_id: Uuid,
    agent: &AgentHandle,
) -> Result<(), ApiError> {
    sync_mail_config_report(state, server_id, agent).await.map(|_| ())
}

/// Record an imported DKIM key on its domain row: the private half encrypted
/// exactly as `create_domain` stores a generated one (same column, so the
/// credential re-encryption sweep already covers it).
pub(crate) async fn store_dkim_key(
    db: &sqlx::PgPool,
    domain_id: Uuid,
    selector: &str,
    private_pem: &str,
    public_key: Option<&str>,
    jwt_secret: &str,
) -> Result<(), String> {
    let enc = crate::services::secrets_crypto::encrypt_credential(private_pem, jwt_secret)
        .map_err(|_| "encryption failed".to_string())?;
    sqlx::query(
        "UPDATE mail_domains SET dkim_private_key = $1, dkim_public_key = $2, dkim_selector = $3, \
         updated_at = NOW() WHERE id = $4",
    )
    .bind(&enc)
    .bind(public_key)
    .bind(selector)
    .bind(domain_id)
    .execute(db)
    .await
    .map(|_| ())
    .map_err(|e| format!("database error: {e}"))
}

/// [`sync_mail_config`] from a bare pool, reporting whether the agent applied
/// the rebuild (the import executor records it).
pub(crate) async fn sync_mail_config_db(
    db: &sqlx::PgPool,
    server_id: Uuid,
    agent: &AgentHandle,
) -> Result<(), String> {
    match sync_mail_config_report_db(db, server_id, agent).await {
        Ok(SyncReport::Applied(_)) => Ok(()),
        Ok(SyncReport::GatherFailed(e)) => Err(format!("the mail configuration could not be gathered: {e}")),
        Ok(SyncReport::AgentFailed(e)) => Err(agent_failure_text(&e)),
        Err((status, body)) => Err(format!(
            "mail sync refused ({status}): {}",
            body.0.get("error").and_then(|m| m.as_str()).unwrap_or("")
        )),
    }
}

/// Multi-IP: a mail domain in automatic mode sends from the address of the
/// same-named site, so creating, deleting or renaming that site changes where
/// its mail leaves from. Re-sync the server when any of `domains` names such a
/// mail domain. Best-effort: logged, never an error for the site operation.
pub(crate) async fn resync_if_mail_follows(
    state: &AppState,
    server_id: Uuid,
    domains: &[&str],
    agent: &AgentHandle,
) {
    let names: Vec<String> = domains.iter().map(|d| d.trim().to_lowercase()).collect();
    let follows: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_domains WHERE server_id = $1 AND domain = ANY($2) AND send_ip_id IS NULL)",
    )
    .bind(server_id)
    .bind(&names)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);
    if !follows {
        return;
    }
    match sync_mail_config_report(state, server_id, agent).await {
        Ok(r) => {
            if let Some(p) = r.send_ip_problem(None) {
                tracing::warn!("Mail sync after a site change on {names:?}: {p}");
            }
        }
        Err((status, msg)) => tracing::warn!("Mail sync after a site change on {names:?} was refused ({status}): {:?}", msg.0),
    }
}

/// Accept only the address character set the agent's `sync_config` accepts (ASCII alphanumeric
/// plus `@ . _ - +`, and any char in `extra_allowed`). Anything outside it makes the agent reject
/// the ENTIRE sync batch - and because callers discard the sync result, one bad row would silently
/// freeze all future Postfix/Dovecot updates. Rejecting at the door (400) surfaces the error to the
/// operator instead of wedging mail provisioning. (s236 mail-surface audit.)
fn is_valid_mail_address(addr: &str, extra_allowed: &str) -> bool {
    !addr.is_empty()
        && addr.len() <= 255
        && addr.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+') || extra_allowed.contains(c)
        })
}

/// [`is_valid_mail_address`] plus the structure the address must actually have.
///
/// **The character-set check above tests the WHOLE STRING for non-emptiness, not
/// the local part**, and that one gap is the root of two separate defects. Both
/// were measured, not theorised:
///
/// * `"@example.com"` passes. The agent writes account lines into
///   `virtual_mailbox_maps` BEFORE catch-all lines (`agent/routes/mail.rs:1035`
///   then `:1045`), and both key on the literal string `@example.com`. `postmap`
///   keeps the FIRST entry and reports the collision on stderr, which the agent
///   discards (`let _ = safe_command("postmap")`). So creating that mailbox
///   silently VOIDS the domain's catch-all - a setting only an administrator can
///   write - and returns 201 with no warning on any surface.
/// * `"..@example.com"` passes. The agent builds `/var/vmail/{domain}/{local}`
///   (`:1105`), so the maildir resolves to `/var/vmail`, one level ABOVE the
///   domain directory, and the `chown -R` beside it then walks the whole tree on
///   every sync. `domain_configure` (`:932`) rejects a component containing `..`
///   - that guard was simply never applied to the half of the path the local part
///   supplies. (Depth is capped at one level: `/` is outside the character set.)
///
/// Both doors are administrator-only today and open to a site's owner under
/// GitHub #106, which is why this lands with that change rather than after it.
///
/// The rule is deliberately narrow - non-empty local part, non-empty domain,
/// exactly one `@`, and a local part that is not made only of dots. It refuses
/// the three degenerate forms that are path components or map keys and nothing
/// else, so it cannot reject a mailbox an install already has.
pub(crate) fn is_wellformed_address(addr: &str, extra_allowed: &str) -> bool {
    if !is_valid_mail_address(addr, extra_allowed) || addr.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        // "." and ".." are directory entries, not mailboxes; "" is a map key.
        && local.chars().any(|c| c != '.')
}

/// Every element of a comma-separated destination list must be a real address.
///
/// `is_valid_mail_address(dest, ",")` accepted `"root,a@b.com"` and
/// `"a@b.com,root"` because it only ever asked whether the STRING contained an
/// `@` somewhere - so a bare local name rode along beside a valid address and was
/// written into `virtual_alias_maps` verbatim. Checking per element is the only
/// form of the question that means anything for a list.
pub(crate) fn is_wellformed_address_list(list: &str, extra_allowed: &str) -> bool {
    !list.trim().is_empty()
        && list
            .split(',')
            .all(|e| is_wellformed_address(e.trim(), extra_allowed))
}

/// Hash a mailbox password for Dovecot using Argon2id.
///
/// Returns the credential in Dovecot's `{ARGON2ID}` scheme form, e.g.
/// `{ARGON2ID}$argon2id$v=19$m=...,t=...,p=...$salt$hash`, which Dovecot (>= 2.3.11) verifies
/// natively and which is the same Argon2id KDF the panel uses for its own user accounts.
///
/// The previous implementation emitted a single unsalted-round `SHA512(salt || password)` hex
/// digest labelled `{SHA512-CRYPT}`. That was neither a real crypt(3) SHA-512 hash - so
/// Dovecot's SHA512-CRYPT verifier rejected it for *every* password, breaking all mailbox login
/// (IMAP/POP/SMTP-AUTH/webmail) - nor an adequate password KDF. Confirmed live with `doveadm
/// pw -t` during the s236 mail-surface audit; see the `dovecot_hash_*` tests below.
fn dovecot_password_hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};

    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(format!("{{ARGON2ID}}{phc}"))
}

/// Hash a mailbox password in a scheme the TARGET BOX's Dovecot can verify.
///
/// **The version check in `dovecot_password_hash`'s doc comment is wrong in the
/// way that matters: Argon2 is a BUILD OPTION, not a version.** Rocky 9.8 ships
/// Dovecot 2.3.16 - past the ">= 2.3.11" that comment cites - compiled without
/// libsodium, so `doveadm pw -l` lists no ARGON2ID and every login fails with
/// `Unknown scheme ARGON2ID` while the panel reports the account created
/// successfully. That is s259's unopenable mailbox on a different family
/// (measured on Rocky 9.8, s268).
///
/// So the scheme is chosen from what the agent reports its Dovecot supports,
/// not from what we would prefer:
///
/// * `ARGON2ID` when available - unchanged on Debian/Ubuntu, which is every
///   install that works today, so nobody is downgraded.
/// * `BLF-CRYPT` (bcrypt) otherwise. It is a real password KDF, present in
///   every Dovecot build in the scheme list measured on both families, and
///   `doveadm pw`-compatible.
///
/// An empty `supported` means the agent could not tell (Dovecot not installed
/// yet, `doveadm` missing). That is treated as "keep the strong default"
/// rather than "supports nothing" - hashing is not the place to guess a
/// downgrade, and accounts created before the mail stack exists are re-synced
/// once it does.
fn dovecot_password_hash_for(
    password: &str,
    supported: &[String],
) -> Result<String, argon2::password_hash::Error> {
    let knows = |s: &str| supported.iter().any(|x| x.eq_ignore_ascii_case(s));
    if supported.is_empty() || knows("ARGON2ID") {
        return dovecot_password_hash(password);
    }
    Ok(format!("{{BLF-CRYPT}}{}", bcrypt_crypt(password)))
}

/// A `$2y$` bcrypt credential, the payload Dovecot's `BLF-CRYPT` scheme reads.
fn bcrypt_crypt(password: &str) -> String {
    // Cost 10 matches Dovecot's own `doveadm pw -s BLF-CRYPT` default.
    bcrypt::hash(password, 10).unwrap_or_default()
}

/// Ask the agent which password schemes its Dovecot can verify.
///
/// Failure to ask is not failure to know something important: an unreachable
/// agent returns an empty list, and [`dovecot_password_hash_for`] keeps the
/// strong default in that case.
pub(crate) async fn agent_password_schemes(agent: &crate::services::agent::AgentHandle) -> Vec<String> {
    agent
        .get("/mail/status")
        .await
        .ok()
        .and_then(|v| {
            v.get("password_schemes").and_then(|s| {
                s.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase()))
                        .collect::<Vec<_>>()
                })
            })
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod address_shape_tests {
    use super::{is_valid_mail_address, is_wellformed_address, is_wellformed_address_list};

    /// ⚠ THE ARM THIS MODULE EXISTS FOR. Both of these were ACCEPTED before, and
    /// each produced a concrete effect that was measured, not argued:
    ///
    /// * `@d` - the account line and the domain's catch-all line become the SAME
    ///   `virtual_mailbox_maps` key. `postmap` keeps whichever was written first
    ///   (accounts are), and the agent discards its duplicate-entry warning, so
    ///   creating the mailbox silently deleted an administrator-only setting.
    /// * `..@d` - the agent joins the local part into
    ///   `/var/vmail/{domain}/{local}`, which resolves one level ABOVE the domain
    ///   directory, and `chown -R` then walks the whole tree on every sync.
    ///
    /// If this test ever goes green on those inputs again, both are back.
    #[test]
    fn the_degenerate_local_parts_are_refused() {
        for addr in ["@example.com", ".@example.com", "..@example.com", "...@example.com"] {
            assert!(
                !is_wellformed_address(addr, ""),
                "{addr:?} must be refused: an empty or all-dots local part is a path \
                 component and a map key, not a mailbox"
            );
            // The control that gives the assertion above its meaning: the OLD
            // check passes every one of them, so this is a real change in
            // behaviour and not a test that was always going to be green.
            assert!(
                is_valid_mail_address(addr, ""),
                "{addr:?} must still satisfy the character-set check - if it does \
                 not, this test has stopped measuring the gap it was written for"
            );
        }
    }

    /// The other half: refusing the degenerate forms must not refuse real mail.
    /// A rule that rejected ordinary addresses would be caught in production, but
    /// only after an install had already failed to sync.
    #[test]
    fn ordinary_addresses_are_still_accepted() {
        for addr in [
            "user@example.com",
            "first.last@example.com",
            "user+tag@example.com",
            "u@example.com",
            "under_score-dash@sub.example.co.uk",
            "0@1.com",
            // A local part containing dots beside other characters is fine - it
            // is only a path component problem when it is NOTHING but dots.
            "a..b@example.com",
            ".leading@example.com",
            "trailing.@example.com",
        ] {
            assert!(is_wellformed_address(addr, ""), "{addr:?} must still be accepted");
        }
    }

    #[test]
    fn the_structural_rules_hold() {
        // No '@' at all, more than one '@', empty domain.
        for addr in ["nobody", "a@b.com@c.com", "user@", "@", ""] {
            assert!(!is_wellformed_address(addr, ""), "{addr:?} must be refused");
        }
        // The character set is still enforced through this door.
        assert!(!is_wellformed_address("usér@example.com", ""));
        assert!(!is_wellformed_address("a/b@example.com", ""));
        // ...unless the caller allows the character, as the catch-all door does.
        assert!(is_wellformed_address("a/b@example.com", "/"));
    }

    /// A list is checked ELEMENT BY ELEMENT. Checking the string as a whole is
    /// what let a bare local name ride along beside a valid address and reach
    /// `virtual_alias_maps` verbatim.
    #[test]
    fn every_element_of_a_destination_list_must_be_an_address() {
        assert!(is_wellformed_address_list("a@b.com", ""));
        assert!(is_wellformed_address_list("a@b.com,c@d.com", ""));
        assert!(is_wellformed_address_list(" a@b.com , c@d.com ", ""));

        // Both orders - the old check accepted each, because it only ever asked
        // whether an '@' appeared SOMEWHERE in the string.
        assert!(!is_wellformed_address_list("root,a@b.com", ""));
        assert!(!is_wellformed_address_list("a@b.com,root", ""));
        assert!(!is_wellformed_address_list("a@b.com,@b.com", ""));
        assert!(!is_wellformed_address_list("", ""));
        assert!(!is_wellformed_address_list(",", ""));
    }
}

#[cfg(test)]
mod tests {
    use super::dovecot_password_hash;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    #[test]
    fn dovecot_hash_is_argon2id_scheme_and_verifies() {
        let pw = "correct horse battery staple";
        let stored = dovecot_password_hash(pw).unwrap();

        // Dovecot scheme label + PHC string (exactly what gets written to the dovecot users file).
        assert!(
            stored.starts_with("{ARGON2ID}$argon2id$"),
            "expected an {{ARGON2ID}} PHC credential, got: {stored}"
        );

        // The PHC after the scheme label must verify against the password - the same check
        // Dovecot's ARGON2ID scheme performs (confirmed live with `doveadm pw -t`, s236 audit).
        let phc = stored.strip_prefix("{ARGON2ID}").unwrap();
        let parsed = PasswordHash::new(phc).expect("credential is a valid PHC string");
        assert!(
            Argon2::default().verify_password(pw.as_bytes(), &parsed).is_ok(),
            "correct password must verify"
        );
        assert!(
            Argon2::default().verify_password(b"wrong password", &parsed).is_err(),
            "wrong password must be rejected"
        );
    }

    #[test]
    fn dovecot_hash_uses_a_random_salt() {
        let a = dovecot_password_hash("same-password").unwrap();
        let b = dovecot_password_hash("same-password").unwrap();
        assert_ne!(a, b, "each hash must use a fresh random salt");
    }
}

#[cfg(test)]
mod mail_cert_verdict_tests {
    use super::{mail_cert_verdict, MailCertBlocker, MailCertVerdict};

    // The ordinary shape the mail entitlement is BUILT on: one name, one
    // single-name certificate, mail added beside the website. A re-issue here
    // refreshes exactly the names that were already there, so refusing it would
    // break the documented order rather than protect anything.
    #[test]
    fn ordinary_same_name_site_still_gets_its_certificate() {
        assert_eq!(
            mail_cert_verdict(true, Some(false), Some("http-01"), None),
            MailCertVerdict::Issue
        );
    }

    // The case that leads the harm, and the one the issuer probe is blind to:
    // `foreign_cert_issuer` answers None for an LE-issued wildcard, so this
    // verdict has to come from the columns or it does not come at all.
    #[test]
    fn a_wildcard_is_refused_even_though_the_issuer_looks_like_ours() {
        assert_eq!(
            mail_cert_verdict(true, Some(true), Some("dns-01"), None),
            MailCertVerdict::Refuse(MailCertBlocker::Wildcard)
        );
    }

    // `ssl_wildcard` is three-state on purpose (the column is nullable), so a
    // DNS-01 row that never recorded the flag must still refuse.
    #[test]
    fn dns01_alone_refuses_when_the_wildcard_flag_was_never_recorded() {
        assert_eq!(
            mail_cert_verdict(true, None, Some("dns-01"), None),
            MailCertVerdict::Refuse(MailCertBlocker::Wildcard)
        );
    }

    // The case the columns are blind to: an uploaded commercial or Origin-CA
    // certificate carries no ssl_wildcard and no ssl_challenge of ours.
    #[test]
    fn a_foreign_certificate_is_refused_on_the_issuer_alone() {
        assert_eq!(
            mail_cert_verdict(true, Some(false), Some("http-01"), Some("DigiCert Inc")),
            MailCertVerdict::Refuse(MailCertBlocker::Foreign)
        );
    }

    // Neither input alone is sufficient - this is the pair that proves it. Drop
    // the columns and the wildcard case passes; drop the issuer and the foreign
    // case passes. Both directions are asserted above; this pins that the two
    // are not the same test written twice.
    #[test]
    fn the_two_inputs_catch_different_cases() {
        // wildcard, no foreign issuer -> caught only by the columns
        assert!(matches!(
            mail_cert_verdict(true, Some(true), None, None),
            MailCertVerdict::Refuse(MailCertBlocker::Wildcard)
        ));
        // foreign issuer, no wildcard columns -> caught only by the issuer
        assert!(matches!(
            mail_cert_verdict(true, None, None, Some("Let's Encrypt")),
            MailCertVerdict::Refuse(MailCertBlocker::Foreign)
        ));
    }

    // A site not serving TLS has nothing here to lose, so the mail host gets its
    // certificate. This is the still-member direction: a guard that refused here
    // would leave a mail host permanently without a certificate on every install
    // where the website is plain HTTP.
    #[test]
    fn a_site_not_serving_tls_does_not_block_the_mail_host() {
        assert_eq!(
            mail_cert_verdict(false, Some(true), Some("dns-01"), Some("DigiCert Inc")),
            MailCertVerdict::Issue
        );
    }
}

#[cfg(test)]
mod send_ip_payload_tests {
    use super::build_sync_payload;
    use crate::services::server_ips::{DeclaredIp, MailIpRow};
    use uuid::Uuid;

    fn row(domain: &str, forced: Option<(&str, Option<&str>)>, site: Option<Option<(&str, Option<&str>)>>) -> MailIpRow {
        let (f_id, f_ip, f_ptr) = match forced {
            Some((ip, ptr)) => (Some(Uuid::from_u128(1)), Some(ip.to_string()), ptr.map(str::to_string)),
            None => (None, None, None),
        };
        let (has_site, s_id, s_ip, s_ptr) = match site {
            None => (false, None, None, None),
            Some(None) => (true, None, None, None),
            Some(Some((ip, ptr))) => (true, Some(Uuid::from_u128(2)), Some(ip.to_string()), ptr.map(str::to_string)),
        };
        MailIpRow {
            id: Uuid::new_v4(),
            domain: domain.into(),
            enabled: true,
            catch_all: None,
            f_id,
            f_ip,
            f_public_ip: None,
            f_ptr,
            has_site,
            s_id,
            s_ip,
            s_public_ip: None,
            s_ptr,
        }
    }

    #[test]
    fn each_domain_carries_its_send_address_and_helo() {
        let domains = vec![
            row("a.lab", None, Some(Some(("192.168.250.11", Some("a-mail.lab"))))),
            row("b.lab", Some(("192.168.250.12", None)), None),
            row("c.lab", None, None),
            row("d.lab", None, Some(None)),
        ];
        let declared = vec![DeclaredIp {
            id: Uuid::from_u128(9),
            ip: "192.168.250.10".into(),
            public_ip: None,
            ptr: Some("srv.lab.".into()),
        }];
        let p = build_sync_payload(&domains, &[], &[], &declared, Some("192.168.250.10"));
        let d = p["domains"].as_array().unwrap();
        assert_eq!(d[0]["send_ip"], "192.168.250.11");
        assert_eq!(d[0]["helo"], "a-mail.lab");
        assert_eq!(d[1]["send_ip"], "192.168.250.12");
        assert!(d[1]["helo"].is_null());
        for i in [2, 3] {
            assert!(d[i]["send_ip"].is_null() && d[i]["helo"].is_null());
        }
        // Unchanged fields still there for the agent.
        assert_eq!(d[0]["domain"], "a.lab");
        assert_eq!(d[0]["enabled"], true);
        assert_eq!(p["primary_helo"], "srv.lab");
    }

    #[test]
    fn without_the_agents_primary_there_is_no_global_helo() {
        let p = build_sync_payload(&[row("a.lab", Some(("10.0.0.2", None)), None)], &[], &[], &[], None);
        assert!(p["primary_helo"].is_null());
        assert_eq!(p["domains"][0]["send_ip"], "10.0.0.2");
    }

    /// 05-import-hestia W4-B: the agent needs `keep_copy` beside `forward_to`
    /// to write `email -> email,forward` instead of a forward-only row.
    #[test]
    fn each_account_carries_its_keep_copy_flag() {
        let accounts = vec![
            ("a@d.be".to_string(), "{X}h".to_string(), 10, true, Some("x@o.org".to_string()), true),
            ("b@d.be".to_string(), "{X}h".to_string(), 10, true, Some("y@o.org".to_string()), false),
        ];
        let p = build_sync_payload(&[], &accounts, &[], &[], None);
        assert_eq!(p["accounts"][0]["forward_to"], "x@o.org");
        assert_eq!(p["accounts"][0]["keep_copy"], true);
        assert_eq!(p["accounts"][1]["keep_copy"], false);
    }
}

#[cfg(test)]
mod sync_report_tests {
    use super::SyncReport;
    use crate::services::agent::AgentError;

    #[test]
    fn a_skipped_or_unapplied_sending_address_is_a_problem() {
        let ok = SyncReport::Applied(serde_json::json!({"ip_transports": {"applied": true, "skipped": ["10.0.0.9"]}}));
        assert!(ok.send_ip_problem(Some("10.0.0.2")).is_none());
        assert!(ok.send_ip_problem(Some("10.0.0.9")).unwrap().contains("10.0.0.9"));
        assert!(ok.send_ip_problem(None).is_none());
        let not = SyncReport::Applied(serde_json::json!({"ip_transports": {"applied": false, "skipped": []}}));
        assert!(not.send_ip_problem(None).is_some());
        // An agent that predates the field reports nothing to complain about.
        assert!(SyncReport::Applied(serde_json::json!({"ok": true})).send_ip_problem(Some("10.0.0.2")).is_none());
    }

    #[test]
    fn the_agents_own_sentence_reaches_the_operator() {
        let r = SyncReport::AgentFailed(AgentError::Status(
            500,
            r#"{"error": "Mail configuration synced, but the per-domain sending IPs were not applied: postfix check failed"}"#.into(),
        ));
        assert!(r.send_ip_problem(Some("10.0.0.2")).unwrap().contains("per-domain sending IPs were not applied"));
    }
}
