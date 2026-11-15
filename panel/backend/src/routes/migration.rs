use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use futures::stream::StreamExt;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::auth::{AuthUser, ServerScope};
use crate::error::{internal_error, err, require_admin, ApiError};
use crate::routes::sites::ProvisionStep;
use crate::services::activity;
use crate::services::import_site::{self, ItemRunner, RunCounts, SiteChoice, SiteEnv};
use crate::services::import_types::{ImportCtx, ItemOutcome, ItemStatus, ProgressFn};
use crate::services::migration_ledger as ledger;
use crate::AppState;

// ──────────────────────────────────────────────────────────────
// Request / Response types
// ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AnalyzeRequest {
    /// A path already on the server's disk. Mutually exclusive with `url` -
    /// exactly one of the two must be set.
    #[serde(default)]
    pub path: String,
    pub source: Option<String>, // "cpanel", "plesk", "hestiacp"
    /// Fetch the archive from this URL instead of requiring the operator SFTP
    /// it up first (previously the only path - `Migration.tsx` said exactly
    /// that). The agent downloads it into the same `/var/backups/` tree a
    /// manually-placed archive already had to live under, then analysis
    /// proceeds exactly as before.
    pub url: Option<String>,
}

/// `POST /api/migration/{id}/import` (W5-R). Every field is optional so a bare
/// `{"retry": true}` replays the stored selection. Unknown fields (the old
/// `doc_root` / `runtime` per site) are ignored: those come from the inventory.
#[derive(serde::Deserialize, serde::Serialize, Default, Clone, Debug)]
pub struct ImportRequest {
    #[serde(default)]
    pub default_php_version: Option<String>,
    #[serde(default)]
    pub sites: Option<Vec<SiteChoice>>,
    #[serde(default)]
    pub databases: Option<Vec<ImportDbItem>>,
    #[serde(default)]
    pub mail_domains: Option<Vec<String>>,
    /// `"<kind>:<key>"` items to redo even though they are finished.
    #[serde(default)]
    pub force_items: Vec<String>,
    #[serde(default)]
    pub retry: bool,
}

impl ImportRequest {
    fn is_empty(&self) -> bool {
        let none = |n: Option<usize>| n.unwrap_or(0) == 0;
        none(self.sites.as_ref().map(Vec::len))
            && none(self.databases.as_ref().map(Vec::len))
            && none(self.mail_domains.as_ref().map(Vec::len))
    }
}

/// The web server an imported site is created with (B5 / D3 of
/// `conception/04-apache-contrats.md`).
///
/// Read from the inventory the AGENT produced at analysis time and the panel
/// stored, never from the import request: `ImportSiteItem` is client JSON, while
/// `sites[].web_server` is what the agent's HestiaCP parser found in the
/// domain's `web.conf` (`"apache"` when it had a `PROXY` key). Only a PHP site
/// can be `apache`; a domain the inventory does not describe, or a panel whose
/// parser does not report the field, gets `nginx` (the historical behaviour).
pub(crate) fn imported_web_server(
    inventory: Option<&serde_json::Value>,
    domain: &str,
    runtime: &str,
) -> &'static str {
    if runtime != "php" {
        return "nginx";
    }
    let found = inventory
        .and_then(|inv| inv.get("sites"))
        .and_then(|s| s.as_array())
        .and_then(|sites| {
            sites.iter().find(|s| {
                s.get("domain")
                    .and_then(|d| d.as_str())
                    .is_some_and(|d| d.eq_ignore_ascii_case(domain))
            })
        })
        .and_then(|s| s.get("web_server"))
        .and_then(|w| w.as_str());
    match found {
        Some("apache") => "apache",
        _ => "nginx",
    }
}

/// Whether Apache is installed on the import target, from the agent's
/// `/services/install-status`. Only an explicit `apache.installed: true` counts:
/// an older agent that does not report Apache, an unsupported OS (RHEL), or an
/// unreachable agent all mean "not usable here".
pub(crate) fn apache_installed_in(install_status: Option<&serde_json::Value>) -> bool {
    install_status
        .and_then(|s| s.get("apache"))
        .and_then(|a| a.get("installed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The web server a domain is actually created with, and the warning to record
/// when the one HestiaCP used cannot be honoured here.
///
/// A domain detected as `apache` on a server without Apache used to fail its
/// vhost write (409 `apache_not_installed` / 400 `apache_unsupported`) and be
/// skipped, losing the whole site. It is imported in nginx mode instead, and
/// said so per domain - the operator must know its `.htaccess` rules are not
/// read until Apache is installed and the site switched (D1: never silent).
pub(crate) fn import_web_server(
    detected: &'static str,
    apache_installed: bool,
    domain: &str,
) -> (&'static str, Option<String>) {
    if detected == "apache" && !apache_installed {
        (
            "nginx",
            Some(format!(
                "{domain} used Apache in HestiaCP; imported in nginx mode because Apache is not installed here. Install Apache and switch the site to keep its .htaccess rules."
            )),
        )
    } else {
        (detected, None)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct ImportDbItem {
    /// The dump file and the engine come from the inventory: `file` / `engine`
    /// sent by an older page are ignored.
    pub name: String,
    /// Which site this database belongs to.
    ///
    /// A `databases` row cannot exist without one. Absent: the analysis'
    /// `suggested_site` (D12), else the only site of the selection; otherwise
    /// the database is refused rather than guessed at.
    #[serde(default)]
    pub site_domain: Option<String>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct Migration {
    pub id: Uuid,
    pub user_id: Uuid,
    pub server_id: Option<Uuid>,
    pub source: String,
    pub status: String,
    pub backup_path: String,
    pub inventory: Option<serde_json::Value>,
    pub selected_items: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ──────────────────────────────────────────────────────────────
// Helper: reuse the same emit_step from sites.rs provision logs
// ──────────────────────────────────────────────────────────────

fn emit_step(
    logs: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Uuid, (Vec<ProvisionStep>, broadcast::Sender<ProvisionStep>, Instant)>>>,
    id: Uuid,
    step: &str,
    label: &str,
    status: &str,
    message: Option<String>,
) {
    let ev = ProvisionStep {
        step: step.into(),
        label: label.into(),
        status: status.into(),
        message,
    };
    if let Ok(mut map) = logs.lock() {
        if let Some((history, tx, touched)) = map.get_mut(&id) {
            // One history entry per step (its latest state): a 9 GB copy emits
            // an event every few seconds for an hour, and the snapshot a
            // reconnecting page receives must not grow with it.
            match history.iter_mut().find(|h| h.step == ev.step) {
                Some(h) => *h = ev.clone(),
                None => history.push(ev.clone()),
            }
            // The hourly sweep in `main.rs` evicts by this instant: a live,
            // multi-hour import keeps it fresh so its stream is never detached.
            *touched = Instant::now();
            let _ = tx.send(ev);
        }
    }
}

// ──────────────────────────────────────────────────────────────
// POST /api/migration/analyze
// ──────────────────────────────────────────────────────────────

/// Panel-side budget for the agent's analyze call.
///
/// Deliberately LONGER than the agent's own extraction budget
/// (`EXTRACT_TIMEOUT_SECS` in the agent's `services::migration`) so that when a
/// giant archive runs out of time it is the *agent* that says so - naming the
/// archive and the budget - instead of this side winning the race and reporting
/// a contentless "agent request timed out". A caller timeout shorter than the
/// callee's does not bound anything the callee did not already bound; it only
/// replaces a real diagnosis with a generic one.
const ANALYZE_AGENT_TIMEOUT_SECS: u64 = 1860;

/// Panel-side budget for the agent's URL-fetch call, same "60s longer than the
/// agent's own ceiling" shape as [`ANALYZE_AGENT_TIMEOUT_SECS`] above - the
/// agent's `FETCH_TIMEOUT_SECS` is 1800s.
const FETCH_AGENT_TIMEOUT_SECS: u64 = 1860;

/// Best-effort archive extension for a URL-fetched file's on-disk name -
/// cosmetic only. The agent's own extractor tries gzip then plain tar
/// regardless of what this names it, so a wrong guess here fails exactly the
/// same way a wrong guess in a manually-copied filename already would; this
/// only makes a failure message that echoes the path read like a real backup
/// name instead of a bare UUID.
/// The source recorded on the row after analysis: the agent's verdict
/// (`inventory.source`) when it names a known panel, else what was asked for.
pub(crate) fn detected_source(inventory: &serde_json::Value, requested: &str) -> String {
    match inventory.get("source").and_then(|s| s.as_str()) {
        Some(s @ ("cpanel" | "plesk" | "hestiacp")) => s.to_string(),
        _ => requested.to_string(),
    }
}

fn fetch_archive_extension(url: &str) -> &'static str {
    let lower = url.split(['?', '#']).next().unwrap_or(url).to_ascii_lowercase();
    if lower.ends_with(".zip") {
        ".zip"
    } else if lower.ends_with(".tar") {
        ".tar"
    } else {
        ".tar.gz"
    }
}

/// How long to wait for an imported database's engine to start answering.
///
/// A fresh `mariadb:11` initialises its data directory behind a bootstrap server
/// that refuses the application user, so "is the container running" is not "is
/// the database usable". Generous, because the cost of waiting is a slower
/// import and the cost of not waiting is an `Access denied` that sends the
/// operator after a password that was always correct.
const ENGINE_READY_TIMEOUT_SECS: u64 = 120;

/// Analyze a panel backup (cPanel/Plesk/HestiaCP).
///
/// **Accepted, not performed.** Walking a cPanel archive is minutes of work for
/// any real account, and every gateway between the browser and this handler
/// gives up long before that: Cloudflare at 100s, the nginx `setup.sh` writes at
/// `proxy_read_timeout 300s`, and this panel's own `TimeoutLayer` at 300s - all
/// of them shorter than the agent call below. Running the analysis inline
/// therefore *guaranteed* a 524/504 for precisely the archives the wizard exists
/// to import (#91), and raising any one of those numbers would only move the
/// size at which it breaks.
///
/// So the row is inserted `analyzing`, the agent call moves to a spawned task,
/// and this returns `202` immediately. The verdict lands in the row - `analyzed`
/// with an inventory, or `failed` carrying the agent's real message - which is
/// what `GET /api/migration/{id}` serves. That row is the durable part: it
/// outlives the request, the tab, and a reload. It does not outlive the process,
/// which is what `finalize_analyzing_on_startup` below exists to close out.
pub async fn analyze(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, agent): ServerScope,
    Json(body): Json<AnalyzeRequest>,
) -> Result<(StatusCode, Json<Migration>), ApiError> {
    require_admin(&claims.role)?;
    let path = body.path.trim().to_string();
    let url = body
        .url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string);

    if path.is_empty() && url.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "A backup path, or a URL to fetch it from, is required",
        ));
    }
    if !path.is_empty() && url.is_some() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Provide either a path or a URL, not both",
        ));
    }
    if let Some(ref u) = url {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Only http:// and https:// URLs are supported",
            ));
        }
    }

    let source = body.source.as_deref().unwrap_or("auto");
    if !["auto", "cpanel", "plesk", "hestiacp"].contains(&source) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Source must be auto, cpanel, plesk, or hestiacp",
        ));
    }

    // A URL fetch doesn't know its final on-disk path until the download
    // completes, but `backup_path` is populated from the moment the row
    // exists (every other reader of this table assumes that). Compute it
    // deterministically now instead - it doubles as the exact destination the
    // agent is told to write the file to.
    let resolved_path = if let Some(ref u) = url {
        format!(
            "/var/backups/dockpanel/migration-fetch/{}{}",
            Uuid::new_v4(),
            fetch_archive_extension(u)
        )
    } else {
        path.clone()
    };

    // Create migration record (status = analyzing)
    let migration: Migration = sqlx::query_as(
        "INSERT INTO migrations (user_id, server_id, source, status, backup_path) \
         VALUES ($1, $2, $3, 'analyzing', $4) RETURNING *",
    )
    .bind(claims.sub)
    .bind(server_id)
    .bind(source)
    .bind(&resolved_path)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("analyze", e))?;

    let db = state.db.clone();
    let migration_id = migration.id;
    let user_id = claims.sub;
    let email = claims.email.clone();
    let key_id = claims.key_id;
    let path_owned = resolved_path.clone();
    let source_owned = source.to_string();

    tokio::spawn(async move {
        // A URL fetch happens first - a failure here is recorded the exact
        // same way an analyze failure already is below, so the operator sees
        // one consistent "failed, here's why" in the row instead of this
        // request hanging on a slow remote host (the same reasoning that
        // moved analyze itself off the request/response cycle, see the doc
        // comment above).
        if let Some(fetch_url) = url {
            if let Err(e) = agent
                .post_long(
                    "/migration/fetch",
                    Some(serde_json::json!({ "url": fetch_url, "dest": path_owned.clone() })),
                    FETCH_AGENT_TIMEOUT_SECS,
                )
                .await
            {
                tracing::error!("Migration {migration_id}: fetch failed: {e}");
                let _ = sqlx::query(
                    "UPDATE migrations SET status = 'failed', result = $1, updated_at = NOW() \
                     WHERE id = $2",
                )
                .bind(serde_json::json!({ "error": format!("Could not fetch the archive: {e}") }))
                .bind(migration_id)
                .execute(&db)
                .await;
                return;
            }
        }

        let agent_body = serde_json::json!({
            "path": path_owned.clone(),
            "source": source_owned.clone(),
        });

        match agent
            .post_long(
                "/migration/analyze",
                Some(agent_body),
                ANALYZE_AGENT_TIMEOUT_SECS,
            )
            .await
        {
            Ok(inventory) => {
                // `auto` is resolved by the agent: the row records what the
                // archive actually is, so the list and the import loop never
                // see `auto` again.
                let detected = detected_source(&inventory, &source_owned);
                if let Err(e) = sqlx::query(
                    "UPDATE migrations SET status = 'analyzed', inventory = $1, source = $3, \
                     updated_at = NOW() WHERE id = $2",
                )
                .bind(&inventory)
                .bind(migration_id)
                .bind(&detected)
                .execute(&db)
                .await
                {
                    // The work is done and the panel cannot say so. Leaving the
                    // row 'analyzing' would poll forever, so record the failure
                    // that the operator can actually act on.
                    tracing::error!("Migration {migration_id}: inventory write failed: {e}");
                    let _ = sqlx::query(
                        "UPDATE migrations SET status = 'failed', result = $1, updated_at = NOW() \
                         WHERE id = $2",
                    )
                    .bind(serde_json::json!({
                        "error": format!("Analysis finished but its result could not be saved: {e}")
                    }))
                    .bind(migration_id)
                    .execute(&db)
                    .await;
                    return;
                }

                tracing::info!(
                    "Migration analyzed: {} (source: {})",
                    path_owned,
                    detected
                );
                activity::log_activity(
                    &db,
                    user_id,
                    &email,
                    "migration.analyze",
                    Some("migration"),
                    Some(&path_owned),
                    Some(&detected),
                    None,
                    key_id,
                )
                .await;
            }
            Err(e) => {
                // There is no HTTP response left to shape this into, so the
                // agent's own sentence goes into the row verbatim and the poller
                // reads it out of `result.error`. This is now the ONLY place the
                // reason for a failed analysis is ever recorded - #90 was that
                // reason being replaced by a generic one on the way out.
                tracing::error!("Migration {migration_id}: analysis failed: {e}");
                let _ = sqlx::query(
                    "UPDATE migrations SET status = 'failed', result = $1, updated_at = NOW() \
                     WHERE id = $2",
                )
                .bind(serde_json::json!({ "error": e.to_string() }))
                .bind(migration_id)
                .execute(&db)
                .await;
            }
        }
    });

    Ok((StatusCode::ACCEPTED, Json(migration)))
}

/// Close out analyses that were in flight when the process died.
///
/// The analysis runs in a `tokio::spawn`, so a restart takes it with no chance
/// to write its own verdict - and an `analyzing` row with nothing left to
/// finish it is a spinner the operator can never clear. Same shape, and the same
/// remedy, as `panel_update::finalize_pending_on_startup`: on boot, nothing is
/// running, so every row still claiming to be is stale by definition.
///
/// `importing` rows are swept too, for the same reason and by the same argument
/// - that path has always spawned, so it has always had this hole.
pub async fn finalize_analyzing_on_startup(pool: &sqlx::PgPool) {
    // Two statuses, two different truths, so two sentences. Analysis only reads
    // the archive, so an interrupted one leaves nothing behind and starting again
    // is the whole remedy. An import MUTATES as it goes - it writes nginx vhosts,
    // `sites` rows and database containers one selection at a time - so an
    // interrupted one has done part of the work, and telling the operator to run
    // it again would be telling them to re-import over what already landed.
    // Saying "nothing was left half-done" over that row would be false.
    let sweeps: [(&str, &str); 2] = [
        (
            "analyzing",
            "The panel restarted while this archive was being analysed. Nothing was \
             changed on the server - analysis only reads - so run it again.",
        ),
        // An import is item by item (`migration_items`): what finished is kept
        // and skipped by the next run, what was running is redone (D10).
        (
            "importing",
            "The panel restarted part-way through this import. Run it again: the \
             items already imported are kept and skipped, the interrupted ones are redone.",
        ),
    ];
    crate::services::migration_ledger::interrupt_running_on_startup(pool).await;

    for (status, message) in sweeps {
        let result = sqlx::query(
            "UPDATE migrations SET status = 'failed', \
             result = COALESCE(result, '{}'::jsonb) || $1::jsonb, updated_at = NOW() \
             WHERE status = $2",
        )
        .bind(serde_json::json!({ "error": message }))
        .bind(status)
        .execute(pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => tracing::warn!(
                "Closed out {} migration(s) left '{status}' by a previous process",
                r.rows_affected()
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!("finalize_analyzing_on_startup: '{status}' sweep failed: {e}"),
        }
    }
}

// ──────────────────────────────────────────────────────────────
// GET /api/migration/{id}
// ──────────────────────────────────────────────────────────────

/// Get a single migration record.
pub async fn get_one(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Migration>, ApiError> {
    require_admin(&claims.role)?;
    let migration: Migration = sqlx::query_as(
        "SELECT * FROM migrations WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("get_one migration", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Migration not found"))?;

    Ok(Json(migration))
}

// ──────────────────────────────────────────────────────────────
// GET /api/migration
// ──────────────────────────────────────────────────────────────

/// List all migrations for the current user.
pub async fn list(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<Vec<Migration>>, ApiError> {
    require_admin(&claims.role)?;
    let migrations: Vec<Migration> = sqlx::query_as(
        "SELECT * FROM migrations WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(claims.sub)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list migration", e))?;

    Ok(Json(migrations))
}

// ──────────────────────────────────────────────────────────────
// POST /api/migration/{id}/import
// ──────────────────────────────────────────────────────────────

/// Start (or resume) importing the selected items of an analysed migration.
///
/// **Relaunchable, item by item (D10).** Every site, file copy, certificate,
/// SFTP account, database and mail item is one row of `migration_items`. A row
/// already `done`/`warning` is skipped without any write unless the operator
/// lists it in `force_items`; a `running` (interrupted) or `failed` row is
/// redone. So the same call serves the first import, a "Retry failed" (`retry:
/// true` replays the stored selection) and a forced re-import of one item, and
/// it is accepted from `analyzed`, `done` and `failed`.
///
/// **The destination is the row's, not the picker's.** Everything below writes
/// to one specific machine: it publishes vhosts for live customer domains,
/// claims those domains, inserts `sites` rows that name their host for good,
/// and copies files staged by the analyse step on the host that step ran
/// against - which is why `analyze` records the server on the row. Reading the
/// destination from the caller's server selection would publish vhosts on a
/// machine that must not serve them while the staged archive sits on another.
///
/// **Inventory, not request.** `runtime`, aliases, canonical host, web server,
/// the default PHP version and database files come from the inventory the agent
/// produced and the panel stored; the request only selects, chooses a database's
/// site, and overrides the PHP version (whitelisted).
pub async fn import(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ImportRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require_admin(&claims.role)?;

    // Gated at the entry point rather than in the loop: a lockdown declared
    // mid-import should not tear down a run already in flight. Deliberately
    // without the per-hour site ceiling: a bulk import is the operator asking for
    // exactly that, from a source they named.
    if crate::services::security_hardening::is_locked_down(&state.db).await {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "System is in lockdown mode"));
    }

    let migration: Migration = sqlx::query_as("SELECT * FROM migrations WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("import", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Migration not found"))?;

    let inventory = migration
        .inventory
        .clone()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "This migration has no analysis to import from"))?;
    if !IMPORTABLE_STATUSES.contains(&migration.status.as_str()) {
        return Err(err(
            StatusCode::CONFLICT,
            &format!("Migration is '{}': an import can start from analyzed, done or failed", migration.status),
        ));
    }

    // Both halves of the destination come from the row. Resolved BEFORE the
    // status moves: a migration refused here has not started. A row naming no
    // server is refused rather than guessed at.
    let server_id = migration.server_id.ok_or_else(|| {
        tracing::warn!("Refusing to import migration {id}: its row names no server");
        err(StatusCode::CONFLICT, "This migration is not associated with a server")
    })?;
    let agent =
        crate::helpers::agent_for_site_server(&state, Some(server_id), &migration.backup_path).await?;

    let agent_migration_id = inventory
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "Migration inventory missing agent ID"))?;

    // `retry` with nothing selected replays the stored selection.
    let mut body = body;
    if body.retry && body.is_empty() {
        let stored = migration
            .selected_items
            .as_ref()
            .map(selection_from_stored)
            .unwrap_or_default();
        if stored.is_empty() {
            return Err(err(StatusCode::BAD_REQUEST, "There is no previous selection to retry"));
        }
        let force_items = std::mem::take(&mut body.force_items);
        body = ImportRequest { force_items, retry: true, ..stored };
    }
    let plan = validate_selection(&inventory, &body).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    if plan.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Select at least one site, database or mail domain to import"));
    }

    // Claimed atomically: two tabs pressing Import cannot start two loops.
    let selected = serde_json::to_value(plan.as_stored()).unwrap_or_default();
    let claimed: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE migrations SET status = 'importing', selected_items = $1, updated_at = NOW() \
         WHERE id = $2 AND status IN ('analyzed', 'done', 'failed') AND inventory IS NOT NULL RETURNING id",
    )
    .bind(&selected)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("import", e))?;
    if claimed.is_none() {
        return Err(err(StatusCode::CONFLICT, "An import of this migration is already running"));
    }

    // Registered only once nothing above can still bail. 512: one import emits
    // several events per item (W5-F).
    crate::helpers::register_provision_log(&state.provision_logs, &state.deploy_owners, id, claims.sub, 512);

    let ctx = ImportCtx {
        db: state.db.clone(),
        agent,
        server_id,
        user_id: claims.sub,
        migration_id: id,
        agent_migration_id,
        jwt_secret: state.config.jwt_secret.clone(),
        force: false,
        progress: progress_fn(state.provision_logs.clone(), id),
    };
    let run = RunInputs {
        plan,
        inventory,
        // The claim reads the Host header (`is_reserved_domain_for`) and asks
        // every fleet member whether a Docker app holds the domain.
        headers,
        role: claims.role.clone(),
        agents: state.agents.clone(),
        email: claims.email.clone(),
        key_id: claims.key_id,
        source: migration.source.clone(),
    };
    let logs = state.provision_logs.clone();

    tokio::spawn(async move {
        run_import(&ctx, &run).await;
        emit_step(&logs, id, "complete", "Migration complete", "done", None);
        tracing::info!("Migration {id} import finished");
        // Keep the log channel alive for 60s so the frontend can catch up.
        tokio::time::sleep(Duration::from_secs(60)).await;
        logs.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    });

    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "migration_id": id }))))
}

/// Statuses an import (or re-run) can start from (W5-D).
pub(crate) const IMPORTABLE_STATUSES: &[&str] = &["analyzed", "done", "failed"];

/// The validated selection of one run.
#[derive(Debug, Default, Clone)]
pub(crate) struct ImportPlan {
    pub default_php_version: Option<String>,
    pub sites: Vec<SiteChoice>,
    pub databases: Vec<ImportDbItem>,
    pub mail_domains: Vec<String>,
    pub force_items: std::collections::HashSet<String>,
}

impl ImportPlan {
    fn is_empty(&self) -> bool {
        self.sites.is_empty() && self.databases.is_empty() && self.mail_domains.is_empty()
    }

    /// What `migrations.selected_items` keeps (for `retry`). No forced item:
    /// a retry never re-forces by itself.
    fn as_stored(&self) -> ImportRequest {
        ImportRequest {
            default_php_version: self.default_php_version.clone(),
            sites: Some(self.sites.clone()),
            databases: Some(self.databases.clone()),
            mail_domains: Some(self.mail_domains.clone()),
            force_items: Vec::new(),
            retry: false,
        }
    }
}

fn inventory_names<'a>(inventory: &'a serde_json::Value, list: &str, field: &str) -> Vec<&'a str> {
    inventory
        .get(list)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.get(field).and_then(|d| d.as_str())).collect())
        .unwrap_or_default()
}

fn valid_php(v: &str) -> bool {
    crate::routes::sites::PHP_VERSIONS.contains(&v)
}

/// Checks the request against the stored inventory. Everything selected must
/// be something the analysis found; PHP versions are whitelisted.
pub(crate) fn validate_selection(inventory: &serde_json::Value, body: &ImportRequest) -> Result<ImportPlan, String> {
    let mut plan = ImportPlan::default();

    if let Some(v) = body.default_php_version.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        if !valid_php(v) {
            return Err(format!("Unsupported PHP version {v}"));
        }
        plan.default_php_version = Some(v.to_string());
    }

    let site_names = inventory_names(inventory, "sites", "domain");
    let mut seen = std::collections::HashSet::new();
    for s in body.sites.iter().flatten() {
        let d = s.domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some(found) = site_names.iter().find(|n| n.eq_ignore_ascii_case(&d)) else {
            return Err(format!("{d} is not a site of this archive"));
        };
        if !seen.insert(d.clone()) {
            continue;
        }
        let php_version = s.php_version.as_deref().map(str::trim).filter(|v| !v.is_empty());
        if let Some(v) = php_version
            && !valid_php(v)
        {
            return Err(format!("Unsupported PHP version {v} for {d}"));
        }
        plan.sites.push(SiteChoice {
            domain: found.to_ascii_lowercase(),
            php_version: php_version.map(str::to_string),
            options: s.options.clone(),
        });
    }

    let db_names = inventory_names(inventory, "databases", "name");
    let mut seen = std::collections::HashSet::new();
    for d in body.databases.iter().flatten() {
        if !db_names.contains(&d.name.as_str()) {
            return Err(format!("{} is not a database of this archive", d.name));
        }
        if seen.insert(d.name.clone()) {
            plan.databases.push(ImportDbItem {
                name: d.name.clone(),
                site_domain: d
                    .site_domain
                    .as_deref()
                    .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty()),
            });
        }
    }

    let mail_names = inventory_names(inventory, "mail_domains", "domain");
    for m in body.mail_domains.iter().flatten() {
        let m = m.trim().to_ascii_lowercase();
        if !mail_names.iter().any(|n| n.eq_ignore_ascii_case(&m)) {
            return Err(format!("{m} is not a mail domain of this archive"));
        }
        if !plan.mail_domains.contains(&m) {
            plan.mail_domains.push(m);
        }
    }

    for f in &body.force_items {
        let Some((kind, key)) = ledger::parse_item_ref(f.trim()) else {
            return Err(format!("Invalid item to force: {f}"));
        };
        plan.force_items.insert(ledger::item_ref(kind, key));
    }
    Ok(plan)
}

/// Reads `migrations.selected_items`: the current shape (an [`ImportRequest`])
/// or the historical `{"sites": ["d"], "databases": ["n"]}`.
pub(crate) fn selection_from_stored(v: &serde_json::Value) -> ImportRequest {
    if let Ok(r) = serde_json::from_value::<ImportRequest>(v.clone()) {
        return r;
    }
    let names = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    ImportRequest {
        sites: Some(
            names("sites")
                .into_iter()
                .map(|domain| SiteChoice { domain, php_version: None, options: Default::default() })
                .collect(),
        ),
        databases: Some(
            names("databases")
                .into_iter()
                .map(|name| ImportDbItem { name, site_domain: None })
                .collect(),
        ),
        ..Default::default()
    }
}

/// What the spawned run needs besides the [`ImportCtx`].
struct RunInputs {
    plan: ImportPlan,
    inventory: serde_json::Value,
    headers: axum::http::HeaderMap,
    role: String,
    agents: crate::services::agent::AgentRegistry,
    email: String,
    key_id: Option<Uuid>,
    source: String,
}

type Logs = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<Uuid, (Vec<ProvisionStep>, broadcast::Sender<ProvisionStep>, Instant)>>,
>;

/// Minimum spacing of `in_progress` events for one step (D10: 1 event / 2 s).
const PROGRESS_THROTTLE: Duration = Duration::from_secs(2);

/// Pure throttle rule: terminal events always pass; an `in_progress` event of a
/// step passes when the previous one is at least [`PROGRESS_THROTTLE`] old.
pub(crate) fn progress_passes(status: &str, last: Option<Instant>, now: Instant) -> bool {
    status != "in_progress" || last.is_none_or(|t| now.duration_since(t) >= PROGRESS_THROTTLE)
}

/// The [`ProgressFn`] of a run: throttled, redacted, into the SSE log.
fn progress_fn(logs: Logs, id: Uuid) -> ProgressFn {
    let last: std::sync::Mutex<std::collections::HashMap<String, Instant>> = Default::default();
    std::sync::Arc::new(move |step: &str, label: &str, status: &str, message: Option<String>| {
        let now = Instant::now();
        {
            let mut map = last.lock().unwrap_or_else(|e| e.into_inner());
            if !progress_passes(status, map.get(step).copied(), now) {
                return;
            }
            if status == "in_progress" {
                map.insert(step.to_string(), now);
            } else {
                map.remove(step);
            }
        }
        emit_step(&logs, id, step, label, status, message.map(|m| ledger::redact(&m)));
    })
}

/// The import loop: preflight, sites, databases, mail, then the verdict.
async fn run_import(ctx: &ImportCtx, inp: &RunInputs) {
    let id = ctx.migration_id;
    let plan = &inp.plan;
    let inventory = &inp.inventory;
    let hestia = inventory.get("source").and_then(|s| s.as_str()) == Some("hestiacp");
    let runner = ItemRunner::new(ctx, &plan.force_items);

    // ── preflight (always re-evaluated, never gated) ──────────
    let apache_installed =
        apache_installed_in(ctx.agent.get("/services/install-status").await.ok().as_ref());
    let needs_apache = plan.sites.iter().any(|s| {
        imported_web_server(Some(inventory), &s.domain, site_runtime(inventory, &s.domain)) == "apache"
    });
    if needs_apache {
        let o = if apache_installed {
            ItemOutcome::done("Apache is installed")
        } else {
            ItemOutcome::warning("Apache is not installed: Apache sites are imported in nginx mode")
        };
        record_preflight(&runner, "apache", "Apache", &o).await;
    }
    let mut local_db_ready = true;
    if hestia && !plan.databases.is_empty() {
        let st = ctx.agent.get("/localdb/status").await.ok();
        let (ok, o) = local_db_outcome(st.as_ref());
        local_db_ready = ok;
        record_preflight(&runner, "mariadb_local", "Local MariaDB server", &o).await;
    }
    let mut mail_ready = true;
    if !plan.mail_domains.is_empty() {
        let st = ctx.agent.get("/mail/status").await.ok();
        mail_ready = st.as_ref().and_then(|s| s.get("installed")).and_then(|b| b.as_bool()).unwrap_or(false);
        let o = if mail_ready {
            ItemOutcome::done("Mail server installed")
        } else {
            ItemOutcome::failed("The mail server is not installed: install it from Mail, then retry")
        };
        record_preflight(&runner, "mail", "Mail server", &o).await;
    }

    // ── sites ─────────────────────────────────────────────────
    let env = SiteEnv {
        run: &runner,
        agents: &inp.agents,
        headers: &inp.headers,
        role: &inp.role,
        inventory,
        hestia,
        apache_installed,
        default_php_version: plan.default_php_version.as_deref(),
        php_ready: Default::default(),
    };
    let mut site_ids: Vec<(String, Uuid)> = Vec::new();
    for choice in &plan.sites {
        if let Some(sid) = import_site::import_site(&env, choice).await {
            site_ids.push((choice.domain.clone(), sid));
        }
    }

    // ── databases ─────────────────────────────────────────────
    for db_item in &plan.databases {
        let name = db_item.name.as_str();
        let label = format!("Database {name}");
        let inv_db = inventory_database(inventory, name).cloned().unwrap_or_default();
        let wanted = db_item
            .site_domain
            .clone()
            .or_else(|| inv_db.get("suggested_site").and_then(|s| s.as_str()).map(|s| s.to_ascii_lowercase()));
        let site_id = resolve_db_site(ctx, wanted.as_deref(), &site_ids, plan.sites.len()).await;
        runner
            .run("db", name, &label, |forced| async move {
                let site_id = match site_id {
                    Ok(sid) => sid,
                    Err(msg) => return ItemOutcome::failed(msg),
                };
                if hestia {
                    if !local_db_ready {
                        return ItemOutcome::failed(
                            "The local MariaDB server is not installed: install it from the wizard, then retry",
                        );
                    }
                    crate::services::import_db::import_hestia_db(&ctx.with_force(forced), name, site_id).await
                } else {
                    import_container_db(ctx, &inv_db, name, site_id).await
                }
            })
            .await;
    }

    // ── mail ──────────────────────────────────────────────────
    for domain in &plan.mail_domains {
        import_mail(&runner, ctx, domain, mail_ready).await;
    }

    // ── verdict ───────────────────────────────────────────────
    let counts = runner.counts();
    let rows = ledger::list(&ctx.db, id).await.unwrap_or_default();
    let result = result_counters(&rows, counts);
    let _ = sqlx::query("UPDATE migrations SET status = 'done', result = $1, updated_at = NOW() WHERE id = $2")
        .bind(&result)
        .bind(id)
        .execute(&ctx.db)
        .await;
    activity::log_activity(
        &ctx.db,
        ctx.user_id,
        &inp.email,
        "migration.import",
        Some("migration"),
        Some(&inp.source),
        None,
        None,
        inp.key_id,
    )
    .await;
}

fn site_runtime<'a>(inventory: &'a serde_json::Value, domain: &str) -> &'a str {
    import_site::inventory_site(inventory, domain)
        .and_then(|s| s.get("runtime"))
        .and_then(|r| r.as_str())
        .unwrap_or("static")
}

fn inventory_database<'a>(inventory: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    inventory
        .get("databases")?
        .as_array()?
        .iter()
        .find(|d| d.get("name").and_then(|n| n.as_str()) == Some(name))
}

/// Preflight rows are rewritten on every run (they describe the server now).
async fn record_preflight(runner: &ItemRunner<'_>, key: &str, label: &str, o: &ItemOutcome) {
    let ctx = runner.ctx;
    if let Err(e) = ledger::finish(&ctx.db, ctx.migration_id, "preflight", key, o).await {
        tracing::warn!("Migration {}: preflight {key} not recorded: {e}", ctx.migration_id);
    }
    let status = match o.status {
        ItemStatus::Failed => "error",
        ItemStatus::Warning => "warning",
        _ => "done",
    };
    (ctx.progress)(&ledger::item_ref("preflight", key), label, status, Some(o.message.clone()));
}

/// `GET /localdb/status` read for the preflight: `(usable, outcome)`.
pub(crate) fn local_db_outcome(status: Option<&serde_json::Value>) -> (bool, ItemOutcome) {
    let b = |k: &str| status.and_then(|s| s.get(k)).and_then(|v| v.as_bool()).unwrap_or(false);
    match (status.is_some(), b("installed"), b("running")) {
        (false, _, _) => (false, ItemOutcome::failed("Could not ask the server about its local MariaDB")),
        (true, false, _) => (
            false,
            ItemOutcome::failed("The local MariaDB server is not installed: install it from the wizard, then retry"),
        ),
        (true, true, false) => (false, ItemOutcome::failed("The local MariaDB server is installed but not running")),
        (true, true, true) => (true, ItemOutcome::done("Local MariaDB server ready")),
    }
}

/// Which site a database belongs to: the operator's choice, else the analysis'
/// suggestion, else the only site of the selection. Looked up among this run's
/// sites, then any site of this migration's ledger, then the caller's existing
/// sites (so "sites first, databases later" works across runs).
async fn resolve_db_site(
    ctx: &ImportCtx,
    wanted: Option<&str>,
    this_run: &[(String, Uuid)],
    selected_sites: usize,
) -> Result<Uuid, String> {
    match wanted {
        Some(d) => {
            if let Some((_, sid)) = this_run.iter().find(|(dom, _)| dom == d) {
                return Ok(*sid);
            }
            if let Some(row) = ledger::get(&ctx.db, ctx.migration_id, "site", d).await
                && let Some(sid) = ledger::site_id_of(&row)
            {
                return Ok(sid);
            }
            crate::helpers::site_id_for_owned_domain(&ctx.db, d, ctx.user_id).await.ok_or_else(|| {
                format!("Its site {d} is not in this import and does not exist on this account. Nothing was created.")
            })
        }
        None => match (this_run, selected_sites) {
            ([(_, sid)], 1) => Ok(*sid),
            ([], _) => Err(
                "A database has to belong to a site, and no site of this import exists. Choose its site and retry. Nothing was created."
                    .into(),
            ),
            _ => Err(
                "The archive does not say which site owns it. Choose its site in the wizard and retry. Nothing was created."
                    .into(),
            ),
        },
    }
}

/// One mail domain: the executor (W4) returns several items; the whole call is
/// skipped only when every item of the domain is finished and none is forced.
async fn import_mail(runner: &ItemRunner<'_>, ctx: &ImportCtx, domain: &str, mail_ready: bool) {
    let label = format!("Mail {domain}");
    if !mail_ready {
        runner
            .run("mail_domain", domain, &label, |_| async {
                ItemOutcome::failed("The mail server is not installed: install it from Mail, then retry")
            })
            .await;
        return;
    }
    let rows = ledger::list(&ctx.db, ctx.migration_id).await.unwrap_or_default();
    let mine: Vec<&ledger::LedgerRow> = rows.iter().filter(|r| mail_row_of(r, domain)).collect();
    let forced = runner.forced.iter().any(|f| {
        ledger::parse_item_ref(f).is_some_and(|(k, key)| mail_key_of(k, key, domain))
    });
    let domain_done = mine
        .iter()
        .any(|r| r.kind == "mail_domain" && ledger::COMPLETED.contains(&r.status.as_str()));
    let all_done = domain_done && mine.iter().all(|r| ledger::COMPLETED.contains(&r.status.as_str()));
    if all_done && !forced {
        let _ = runner.gate("mail_domain", domain, &label).await; // reports "skipped", writes nothing
        return;
    }
    if let Err(e) = ledger::begin(&ctx.db, ctx.migration_id, "mail_domain", domain).await {
        tracing::warn!("Migration {}: could not mark mail_domain:{domain} running: {e}", ctx.migration_id);
    }
    (ctx.progress)(&ledger::item_ref("mail_domain", domain), &label, "in_progress", None);

    let outcomes = crate::services::import_mail::import_mail_domain(&ctx.with_force(forced), domain).await;
    let mut domain_recorded = false;
    let mut worst = ItemStatus::Done;
    for (item, outcome) in &outcomes {
        let Some((kind, key)) = ledger::parse_item_ref(item) else {
            tracing::warn!("Migration {}: mail executor returned an unknown item {item}", ctx.migration_id);
            continue;
        };
        domain_recorded |= kind == "mail_domain" && key == domain;
        worst = worse(worst, outcome.status);
        let item_label = match kind {
            "mail_domain" => label.clone(),
            "mailbox" => format!("Mailbox {key}"),
            "mail_alias" => format!("Mail alias {key}"),
            "maildir" => format!("Messages of {key}"),
            _ => key.to_string(),
        };
        runner.record(kind, key, &item_label, outcome).await;
    }
    if !domain_recorded {
        let o = match worst {
            ItemStatus::Failed => ItemOutcome::failed("Some items of this mail domain failed"),
            ItemStatus::Warning => ItemOutcome::warning("Imported with warnings"),
            _ => ItemOutcome::done("Imported"),
        };
        runner.record("mail_domain", domain, &label, &o).await;
    }
}

fn worse(a: ItemStatus, b: ItemStatus) -> ItemStatus {
    let rank = |s: ItemStatus| match s {
        ItemStatus::Done | ItemStatus::Skipped => 0,
        ItemStatus::Warning => 1,
        ItemStatus::Failed => 2,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// Whether a ledger item belongs to a mail domain: the domain row itself, or a
/// mailbox / alias / maildir whose address is `@<domain>`.
pub(crate) fn mail_key_of(kind: &str, key: &str, domain: &str) -> bool {
    match kind {
        "mail_domain" => key.eq_ignore_ascii_case(domain),
        "mailbox" | "mail_alias" | "maildir" => key
            .rsplit_once('@')
            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(domain)),
        _ => false,
    }
}

fn mail_row_of(r: &ledger::LedgerRow, domain: &str) -> bool {
    mail_key_of(&r.kind, &r.key, domain)
}

/// `migrations.result`: the historical keys, as counters only (W5-R), plus this
/// run's counters.
pub(crate) fn result_counters(rows: &[ledger::LedgerRow], run: RunCounts) -> serde_json::Value {
    let count = |kind: &str, statuses: &[&str]| {
        rows.iter().filter(|r| r.kind == kind && statuses.contains(&r.status.as_str())).count()
    };
    serde_json::json!({
        "sites_imported": count("site", &["done", "warning"]),
        "sites_skipped": count("site", &["skipped"]),
        "databases_imported": count("db", &["done", "warning"]),
        "databases_failed": count("db", &["failed"]),
        "errors": rows.iter().filter(|r| r.status == "failed").count(),
        "warnings": rows.iter().filter(|r| r.status == "warning").count(),
        "run": run,
    })
}

/// Database import into a fresh container (cPanel / Plesk archives): the
/// historical path, kept as is (the HestiaCP path is `import_db`, W2).
async fn import_container_db(
    ctx: &ImportCtx,
    inv_db: &serde_json::Value,
    db_name: &str,
    site_id: Uuid,
) -> ItemOutcome {
    let db = &ctx.db;
    let agent = &ctx.agent;
    let id = ctx.migration_id;
    let engine = inv_db.get("engine").and_then(|e| e.as_str()).unwrap_or("mysql").to_string();
    let Some(sql_file) = inv_db.get("file").and_then(|f| f.as_str()) else {
        return ItemOutcome::failed("The analysis did not record a dump file for this database");
    };
    let step = ledger::item_ref("db", db_name);

    let password = Uuid::new_v4().to_string().replace('-', "");
    let (range_start, range_end) = match engine.as_str() {
        "mysql" | "mariadb" => (3307, 3400),
        _ => (5433, 5500),
    };
    let port_row: Option<(i32,)> = sqlx::query_as(
        "SELECT s.port FROM generate_series($1::int, $2::int) AS s(port) \
         WHERE s.port NOT IN (SELECT port FROM databases WHERE port IS NOT NULL) LIMIT 1",
    )
    .bind(range_start)
    .bind(range_end)
    .fetch_optional(db)
    .await
    .unwrap_or(None);
    let Some((port,)) = port_row else {
        return ItemOutcome::failed(format!("No available port for database {db_name}"));
    };

    // Row first: `idx_databases_port_unique` settles a concurrent port pick
    // before Docker is ever asked to bind it twice.
    let encrypted_password = crate::services::secrets_crypto::encrypt_credential(&password, &ctx.jwt_secret)
        .unwrap_or_else(|_| password.clone());
    let inserted = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO databases (site_id, engine, name, db_user, db_password_enc, container_id, port) \
         VALUES ($1, $2, $3, $4, $5, '', $6) \
         ON CONFLICT ON CONSTRAINT databases_site_name_unique DO NOTHING RETURNING id",
    )
    .bind(site_id)
    .bind(&engine)
    .bind(db_name)
    .bind(db_name)
    .bind(&encrypted_password)
    .bind(port)
    .fetch_optional(db)
    .await;
    let db_id = match inserted {
        Ok(Some((rid,))) => rid,
        Ok(None) => return ItemOutcome::failed(format!("Database {db_name} already exists on that site - not imported.")),
        Err(e) if e.to_string().contains("idx_databases_port_unique") => {
            return ItemOutcome::failed(format!(
                "Port {port} for database {db_name} was claimed by a concurrent operation - not imported. Retry."
            ));
        }
        Err(e) => return ItemOutcome::failed(format!("Could not record database {db_name}: {e}")),
    };

    let create_body = serde_json::json!({ "name": db_name, "engine": engine, "password": password, "port": port });
    let (container_id, container_name) = match agent.post("/databases", Some(create_body)).await {
        Ok(resp) => (
            resp.get("container_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            resp.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        ),
        Err(e) => {
            let _ = sqlx::query("DELETE FROM databases WHERE id = $1").bind(db_id).execute(db).await;
            return ItemOutcome::failed(format!("Database container creation failed for {db_name}: {e}"));
        }
    };
    if let Err(e) = sqlx::query("UPDATE databases SET container_id = $1 WHERE id = $2")
        .bind(&container_id)
        .bind(db_id)
        .execute(db)
        .await
    {
        tracing::error!("Migration {id}: database {db_name} created but its container_id was not recorded: {e}");
    }

    // A fresh `mariadb:11` refuses the application user while it bootstraps:
    // wait for it to answer rather than report a credentials error for a timing one.
    (ctx.progress)(&step, &format!("Database {db_name}"), "in_progress", Some("Waiting for the engine".into()));
    let probe = serde_json::json!({
        "container": container_name, "engine": engine, "database": db_name,
        "user": db_name, "password": password, "sql": "SELECT 1",
    });
    let deadline = Instant::now() + Duration::from_secs(ENGINE_READY_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if agent.post("/databases/query", Some(probe.clone())).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let import_body = serde_json::json!({
        "migration_id": ctx.agent_migration_id, "sql_file": sql_file, "container_name": container_name,
        "db_name": db_name, "engine": engine, "user": db_name, "password": password,
    });
    match agent.post_long("/migration/import-database", Some(import_body), CONTAINER_DB_IMPORT_TIMEOUT_SECS).await {
        Ok(_) => ItemOutcome::done("Imported").with_details(serde_json::json!({ "port": port, "engine": engine })),
        Err(e) => ItemOutcome::failed(format!("SQL import failed for {db_name}: {e}")),
    }
}

/// Budget of the historical synchronous dump import (container databases). The
/// spawned loop is not under any HTTP timeout, so this only bounds a wedged call.
const CONTAINER_DB_IMPORT_TIMEOUT_SECS: u64 = 3600;

// ──────────────────────────────────────────────────────────────
// GET /api/migration/{id}/progress - SSE stream
// ──────────────────────────────────────────────────────────────

/// SSE stream of migration import progress.
pub async fn progress(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, axum::BoxError>>>, ApiError> {
    require_admin(&claims.role)?;
    // Verify ownership
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM migrations WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("progress", e))?;

    if exists.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "Migration not found"));
    }

    // As in sites::provision_log, the row check above is kept alongside the
    // per-key owner check.
    let (snapshot, rx) = crate::helpers::open_provision_log(
        &state.provision_logs,
        &state.deploy_owners,
        id,
        claims.sub,
        "No active import for this migration",
    )?;

    // First yield snapshot events, then stream live updates
    let snapshot_stream = futures::stream::iter(snapshot.into_iter().map(|step| {
        let data = serde_json::to_string(&step).unwrap_or_default();
        Ok(Event::default().data(data))
    }));

    let live_stream = BroadcastStream::new(rx).filter_map(|result| async {
        match result {
            Ok(step) => {
                let data = serde_json::to_string(&step).ok()?;
                Some(Ok(Event::default().data(data)))
            }
            Err(_) => None,
        }
    });

    // The underlying channel closes (and this stream ends) once the import
    // finishes and its map entry is dropped - but an import in progress at
    // shutdown time can still run well past the graceful-drain window, so
    // race it against the panel's own shutdown signal too.
    let stream = snapshot_stream
        .chain(live_stream)
        .take_until(crate::helpers::shutdown_signal_fut(&state));

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}

// ──────────────────────────────────────────────────────────────
// DELETE /api/migration/{id}
// ──────────────────────────────────────────────────────────────

/// Delete a migration record and clean up temp files.
///
/// The staging directory this cleans up is on the host that unpacked the archive,
/// which the row names - so that is where the cleanup goes, rather than wherever
/// the server picker happens to be pointing. Sent to any other machine the call
/// succeeds and does nothing: no staging directory exists there under this id, so
/// the agent has nothing to delete and says so cheerfully, while the real
/// extracted copy - a whole cPanel account's files - stays on disk with the panel
/// record that could have found it now deleted.
pub async fn remove(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let migration: Migration = sqlx::query_as(
        "SELECT * FROM migrations WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("remove migration", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Migration not found"))?;

    // Ask agent to clean up extracted temp files (best-effort)
    let agent_migration_id = migration
        .inventory
        .as_ref()
        .and_then(|inv| inv.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cleanup_body = serde_json::json!({
        "migration_id": agent_migration_id,
    });

    // An unresolvable host is not fatal here, and that is the one place this
    // differs from the import. The record is panel state: it has to stay deletable
    // after the machine that staged it has been decommissioned, or a fleet
    // shrinking by one server leaves rows nobody can ever clear. So the cleanup is
    // skipped and said out loud - the files are named as still being there - rather
    // than aimed at a host that never had them, which is the outcome that looks
    // like success and is not one.
    match crate::helpers::agent_for_site_server(&state, migration.server_id, &migration.backup_path)
        .await
    {
        Ok(agent) => {
            if let Err(e) = agent.post("/migration/cleanup", Some(cleanup_body)).await {
                tracing::warn!("Migration cleanup agent call failed for {id}: {e}");
            }
        }
        Err(_) => tracing::warn!(
            "Migration {id}: deleting the record without cleaning up - the server it was \
             staged on could not be resolved, so the extracted files remain on that host"
        ),
    }

    // Delete from DB. Scoped by user_id like every other statement in this file
    // (get_one, list, import's fetch, and the SELECT just above this DELETE) -
    // this was the one exception, relying entirely on that preceding SELECT's
    // ownership check still being valid, with no intervening await that could
    // invalidate it today. Scoping it directly matches the file's own discipline
    // and removes the dependency on that ordering never changing.
    sqlx::query("DELETE FROM migrations WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(claims.sub)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("remove migration", e))?;

    // Remove any lingering provision log channel
    crate::helpers::forget_provision_log(&state.provision_logs, &state.deploy_owners, id);

    tracing::info!("Migration deleted: {id}");
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "migration.delete",
        Some("migration"),
        None,
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// --- import-hestia (05) ---

async fn owned_migration(state: &AppState, id: Uuid, user: Uuid) -> Result<Migration, ApiError> {
    sqlx::query_as("SELECT * FROM migrations WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("migration", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Migration not found"))
}

/// GET /api/migration/{id}/report - the ledger, per item, with a summary and
/// the manual actions left (W5-R). Durable: it survives the end of the SSE
/// stream, a page reload and a panel restart.
pub async fn report(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let migration = owned_migration(&state, id, claims.sub).await?;
    let rows = ledger::list(&state.db, id).await.map_err(|e| internal_error("report", e))?;
    Ok(Json(serde_json::json!({
        "status": migration.status,
        "summary": ledger::summary(&rows),
        "items": rows.iter().map(ledger::public_row).collect::<Vec<_>>(),
        "manual_actions": ledger::manual_actions(&rows, migration.inventory.as_ref()),
    })))
}

#[derive(serde::Deserialize)]
pub struct PreflightQuery {
    /// Comma-separated PHP versions the wizard currently selects (overrides and
    /// default), on top of those the inventory names.
    #[serde(default)]
    pub php: Option<String>,
}

/// PHP versions an import of these sites needs, from the inventory and the
/// wizard's current choices, deduplicated and whitelisted.
pub(crate) fn php_needed(inventory: Option<&serde_json::Value>, extra: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let from_inv = inventory
        .and_then(|i| i.get("sites"))
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .filter(|s| s.get("runtime").and_then(|r| r.as_str()) == Some("php"))
        .filter_map(|s| s.get("php_version").and_then(|v| v.as_str()));
    let from_query = extra.unwrap_or("").split(',').map(str::trim);
    for v in from_inv.chain(from_query) {
        if valid_php(v) && !out.iter().any(|o| o == v) {
            out.push(v.to_string());
        }
    }
    out
}

/// GET /api/migration/{id}/preflight - what the target server is missing for
/// this import (W5-R): local MariaDB, mail server, PHP versions, Apache, disk.
pub async fn preflight(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<PreflightQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let migration = owned_migration(&state, id, claims.sub).await?;
    let agent = crate::helpers::agent_for_site_server(&state, migration.server_id, &migration.backup_path).await?;

    let (localdb, mail, php, install) = tokio::join!(
        agent.get("/localdb/status"),
        agent.get("/mail/status"),
        agent.get("/php/versions"),
        agent.get("/services/install-status"),
    );
    let localdb = localdb.ok();
    let b = |v: Option<&serde_json::Value>, k: &str| v.and_then(|s| s.get(k)).and_then(|x| x.as_bool()).unwrap_or(false);
    let mail = mail.ok();
    let installed_php: Vec<String> = php
        .ok()
        .and_then(|v| v.get("versions").and_then(|a| a.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter(|x| x.get("installed").and_then(|b| b.as_bool()).unwrap_or(false))
        .filter_map(|x| x.get("version").and_then(|s| s.as_str()).map(str::to_string))
        .collect();
    let needed = php_needed(migration.inventory.as_ref(), q.php.as_deref());
    let missing: Vec<&String> = needed.iter().filter(|v| !installed_php.contains(v)).collect();
    let legacy: Vec<&String> = needed.iter().filter(|v| ledger::LEGACY_PHP_VERSIONS.contains(&v.as_str())).collect();
    let schemes: Vec<String> = mail
        .as_ref()
        .and_then(|m| m.get("password_schemes"))
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase())).collect())
        .unwrap_or_default();
    let disk = migration
        .inventory
        .as_ref()
        .and_then(|i| i.get("disk"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    Ok(Json(serde_json::json!({
        "mariadb_local": {
            "installed": b(localdb.as_ref(), "installed"),
            "running": b(localdb.as_ref(), "running"),
            "version": localdb.as_ref().and_then(|s| s.get("version")).cloned().unwrap_or(serde_json::Value::Null),
            "reachable": localdb.is_some(),
        },
        "mail": { "installed": b(mail.as_ref(), "installed"), "schemes": schemes },
        "php": { "installed": installed_php, "missing_for_selection": missing, "legacy": legacy },
        "apache": { "installed": apache_installed_in(install.ok().as_ref()) },
        "disk": disk,
    })))
}
// --- end import-hestia (05) ---

#[cfg(test)]
mod web_server_tests {
    use super::{apache_installed_in, import_web_server, imported_web_server};

    #[test]
    fn an_apache_domain_falls_back_to_nginx_with_a_warning_when_apache_is_missing() {
        assert_eq!(import_web_server("apache", true, "a.example"), ("apache", None));
        assert_eq!(import_web_server("nginx", false, "b.example"), ("nginx", None));
        let (ws, warning) = import_web_server("apache", false, "a.example");
        assert_eq!(ws, "nginx");
        assert_eq!(
            warning.as_deref(),
            Some(
                "a.example used Apache in HestiaCP; imported in nginx mode because Apache is not installed here. Install Apache and switch the site to keep its .htaccess rules."
            )
        );
    }

    #[test]
    fn only_an_explicit_installed_true_counts_as_apache_installed() {
        let yes = serde_json::json!({ "apache": { "installed": true, "running": true, "supported": true } });
        let no = serde_json::json!({ "apache": { "installed": false, "supported": false } });
        let old_agent = serde_json::json!({ "redis": { "installed": true } });
        assert!(apache_installed_in(Some(&yes)));
        assert!(!apache_installed_in(Some(&no)));
        assert!(!apache_installed_in(Some(&old_agent)));
        assert!(!apache_installed_in(None));
    }

    #[test]
    fn an_apache_hestia_domain_is_imported_in_apache_mode() {
        let inv = serde_json::json!({
            "id": "m1",
            "sites": [
                { "domain": "a.example", "runtime": "php", "web_server": "apache" },
                { "domain": "b.example", "runtime": "php", "web_server": "nginx" },
                { "domain": "c.example", "runtime": "php" },
                { "domain": "d.example", "runtime": "static", "web_server": "apache" }
            ]
        });
        assert_eq!(imported_web_server(Some(&inv), "a.example", "php"), "apache");
        assert_eq!(imported_web_server(Some(&inv), "A.Example", "php"), "apache");
        assert_eq!(imported_web_server(Some(&inv), "b.example", "php"), "nginx");
        // Field absent (non-HestiaCP parser): historical nginx.
        assert_eq!(imported_web_server(Some(&inv), "c.example", "php"), "nginx");
        // Only PHP can be apache, whatever the inventory says.
        assert_eq!(imported_web_server(Some(&inv), "d.example", "static"), "nginx");
        // Unknown domain or no inventory: nginx.
        assert_eq!(imported_web_server(Some(&inv), "zz.example", "php"), "nginx");
        assert_eq!(imported_web_server(None, "a.example", "php"), "nginx");
    }
}

#[cfg(test)]
mod import_loop_tests {
    use super::*;
    use serde_json::json;

    fn inv() -> serde_json::Value {
        json!({
            "id": "m1", "source": "hestiacp",
            "sites": [
                { "domain": "x.tld", "runtime": "php", "php_version": "8.3" },
                { "domain": "old.tld", "runtime": "php", "php_version": null },
                { "domain": "s.tld", "runtime": "static" }
            ],
            "databases": [{ "name": "adm_x", "file": "db/adm_x/adm_x.mysql.sql.gz", "engine": "mariadb" }],
            "mail_domains": [{ "domain": "d.be" }]
        })
    }

    fn req(v: serde_json::Value) -> ImportRequest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn the_selection_must_come_from_the_inventory() {
        let p = validate_selection(&inv(), &req(json!({
            "default_php_version": "8.3",
            "sites": [{ "domain": "X.TLD.", "php_version": "8.4", "doc_root": "ignored", "runtime": "node" }, { "domain": "x.tld" }],
            "databases": [{ "name": "adm_x", "site_domain": "X.tld", "file": "../../etc/passwd" }],
            "mail_domains": ["D.be"],
            "force_items": ["db:adm_x"]
        })))
        .unwrap();
        assert_eq!(p.sites.len(), 1);
        assert_eq!(p.sites[0].domain, "x.tld");
        assert_eq!(p.sites[0].php_version.as_deref(), Some("8.4"));
        assert_eq!(p.databases[0].site_domain.as_deref(), Some("x.tld"));
        assert_eq!(p.mail_domains, vec!["d.be"]);
        assert!(p.force_items.contains("db:adm_x"));

        for bad in [
            json!({ "sites": [{ "domain": "evil.tld" }] }),
            json!({ "sites": [{ "domain": "x.tld", "php_version": "4.4" }] }),
            json!({ "default_php_version": "8.3; rm -rf /" }),
            json!({ "databases": [{ "name": "other" }] }),
            json!({ "mail_domains": ["other.be"] }),
            json!({ "force_items": ["nope:x"] }),
        ] {
            assert!(validate_selection(&inv(), &req(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_retry_replays_the_stored_selection_in_either_shape() {
        let p = validate_selection(&inv(), &req(json!({ "sites": [{ "domain": "x.tld", "php_version": "8.4" }] }))).unwrap();
        let stored = serde_json::to_value(p.as_stored()).unwrap();
        assert!(stored["force_items"].as_array().is_some_and(|f| f.is_empty()));
        let back = selection_from_stored(&stored);
        assert_eq!(back.sites.unwrap()[0].php_version.as_deref(), Some("8.4"));
        // Rows written before the ledger existed.
        let old = selection_from_stored(&json!({ "sites": ["x.tld"], "databases": ["adm_x"] }));
        assert!(!old.is_empty());
        assert_eq!(old.sites.unwrap()[0].domain, "x.tld");
        assert_eq!(old.databases.unwrap()[0].name, "adm_x");
        assert!(ImportRequest::default().is_empty());
    }

    #[test]
    fn in_progress_events_are_throttled_terminal_ones_never() {
        let t = Instant::now();
        assert!(progress_passes("in_progress", None, t));
        assert!(!progress_passes("in_progress", Some(t), t + Duration::from_millis(1500)));
        assert!(progress_passes("in_progress", Some(t), t + Duration::from_secs(2)));
        for s in ["done", "error", "warning", "skipped", "pending"] {
            assert!(progress_passes(s, Some(t), t), "{s}");
        }
    }

    #[test]
    fn the_local_mariadb_preflight_names_what_is_missing() {
        assert!(!local_db_outcome(None).0);
        let (ok, o) = local_db_outcome(Some(&json!({ "installed": false })));
        assert!(!ok && o.message.contains("not installed"));
        assert!(!local_db_outcome(Some(&json!({ "installed": true, "running": false }))).0);
        assert!(local_db_outcome(Some(&json!({ "installed": true, "running": true }))).0);
    }

    #[test]
    fn mail_items_belong_to_their_domain() {
        assert!(mail_key_of("mail_domain", "D.be", "d.be"));
        assert!(mail_key_of("mailbox", "a@d.be", "d.be"));
        assert!(mail_key_of("maildir", "a@D.BE", "d.be"));
        assert!(!mail_key_of("mailbox", "a@xd.be", "d.be"));
        assert!(!mail_key_of("mail_alias", "a@d.be.evil", "d.be"));
        assert!(!mail_key_of("db", "d.be", "d.be"));
    }

    #[test]
    fn preflight_lists_the_php_versions_the_selection_needs() {
        let n = php_needed(Some(&inv()), Some("8.4, 8.3,bogus"));
        assert!(n.contains(&"8.3".to_string()) && n.contains(&"8.4".to_string()));
        assert!(!n.iter().any(|v| v == "bogus"));
        assert_eq!(n.iter().filter(|v| *v == "8.3").count(), 1);
    }

    #[test]
    fn auto_is_replaced_by_the_detected_source() {
        assert_eq!(detected_source(&json!({ "source": "hestiacp" }), "auto"), "hestiacp");
        assert_eq!(detected_source(&json!({}), "cpanel"), "cpanel");
        assert_eq!(detected_source(&json!({ "source": "weird" }), "auto"), "auto");
    }

    #[test]
    fn the_result_keeps_the_historical_keys_as_counters() {
        let row = |kind: &str, status: &str| ledger::LedgerRow {
            kind: kind.into(),
            key: "k".into(),
            status: status.into(),
            message: String::new(),
            details: json!({}),
            attempts: 1,
            updated_at: chrono::Utc::now(),
        };
        let rows = vec![row("site", "done"), row("site", "skipped"), row("db", "failed"), row("files", "warning")];
        let r = result_counters(&rows, RunCounts { done: 1, skipped: 2, warning: 0, failed: 1 });
        assert_eq!(r["sites_imported"], 1);
        assert_eq!(r["sites_skipped"], 1);
        assert_eq!(r["databases_failed"], 1);
        assert_eq!(r["errors"], 1);
        assert_eq!(r["warnings"], 1);
        assert_eq!(r["run"]["skipped"], 2);
    }
}
