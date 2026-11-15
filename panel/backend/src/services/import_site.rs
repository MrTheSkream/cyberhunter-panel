//! Per-site steps of the import loop (05-import-hestia, W5-F).
//!
//! For each selected site, in this order, each step one ledger item:
//!
//! 1. `site:<d>`  - claim of the domain and of every imported alias, PHP version
//!    (`php:<v>`, installed on demand), the `sites` row (web server from `PROXY`,
//!    aliases, canonical host, Force SSL / HSTS, PHP no-exec dirs) and the vhost,
//!    without SSL yet;
//! 2. `files:<d>` - `POST /migration/import-site` (agent job, polled by
//!    [`wait_job`]): `public_html` to the web root, `private/` beside it;
//! 3. `ssl:<d>`   - the HestiaCP certificate, installed by the agent from the
//!    staging (the key never transits through here), then the vhost again;
//!    expired or refused = Warning, site kept on HTTP;
//! 4. `sftp:<d>`  - [`import_sftp`] (W4), only once the files are in place.
//!
//! The `runtime`, aliases, canonical host, web server and default PHP version
//! come from the STORED inventory, never from the request; the request only
//! selects and overrides the PHP version and the options.

use std::collections::HashSet;
use std::sync::Mutex;

use axum::http::HeaderMap;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::services::agent::{AgentError, AgentRegistry};
use crate::services::domain_claim::{ensure_claimable, Holder};
use crate::services::import_sftp::import_sftp;
use crate::services::import_types::{wait_job, ImportCtx, ItemOutcome, ItemStatus};
use crate::services::migration_ledger::{self as ledger, Decision, LEGACY_PHP_VERSIONS};

/// `POST /php/install` budget (W5-F step 2: up to 10 min of apt).
pub const PHP_INSTALL_TIMEOUT_SECS: u64 = 700;

/// PHP execution is blocked in these folders for every imported PHP site (D9).
/// Mirrors W3's default list (`POST /api/sites`), not in this branch yet.
pub const DEFAULT_PHP_NO_EXEC_DIRS: &[&str] =
    &["/wp-content/uploads", "/sites/default/files", "/storage/app/public", "/uploads", "/upload"];

/// Hard ceiling on aliases per site (W3-V).
pub const MAX_ALIASES: usize = 20;

/// Budget of `POST /migration/import-site` when the agent copies before it
/// answers (no job id). A job-based agent answers at once.
pub const SYNC_FILE_COPY_TIMEOUT_SECS: u64 = 4 * 3600;

// ──────────────────────────────────────────────────────────────
// Selection (request side)
// ──────────────────────────────────────────────────────────────

/// Per-site switches of the wizard. Absent = default (the archive's value).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct SiteOptions {
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub aliases: Option<bool>,
    #[serde(default)]
    pub canonical: Option<bool>,
    #[serde(default)]
    pub sftp: Option<bool>,
    #[serde(default)]
    pub force_ssl: Option<bool>,
    #[serde(default)]
    pub hsts: Option<bool>,
}

/// One selected site, validated by the route (domain in the inventory, PHP
/// version on the whitelist).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SiteChoice {
    pub domain: String,
    #[serde(default)]
    pub php_version: Option<String>,
    #[serde(default)]
    pub options: SiteOptions,
}

// ──────────────────────────────────────────────────────────────
// Item runner: ledger gate + record + progress + run counters
// ──────────────────────────────────────────────────────────────

/// Counters of THIS run (what `migrations.result` keeps).
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct RunCounts {
    pub done: usize,
    pub skipped: usize,
    pub warning: usize,
    pub failed: usize,
}

/// Wraps every item of a run: [`ItemRunner::gate`] before, [`ItemRunner::record`] after.
pub struct ItemRunner<'a> {
    pub ctx: &'a ImportCtx,
    pub forced: &'a HashSet<String>,
    counts: Mutex<RunCounts>,
}

impl<'a> ItemRunner<'a> {
    pub fn new(ctx: &'a ImportCtx, forced: &'a HashSet<String>) -> Self {
        Self { ctx, forced, counts: Mutex::new(RunCounts::default()) }
    }

    pub fn counts(&self) -> RunCounts {
        *self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn count(&self, s: ItemStatus) {
        let mut c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        match s {
            ItemStatus::Done => c.done += 1,
            ItemStatus::Skipped => c.skipped += 1,
            ItemStatus::Warning => c.warning += 1,
            ItemStatus::Failed => c.failed += 1,
        }
    }

    pub fn is_forced(&self, kind: &str, key: &str) -> bool {
        self.forced.contains(&ledger::item_ref(kind, key))
    }

    /// `None`: finished before and not forced - reported as skipped, nothing
    /// written. `Some(forced)`: the row now says `running`; run the item.
    pub async fn gate(&self, kind: &str, key: &str, label: &str) -> Option<bool> {
        let forced = self.is_forced(kind, key);
        let prev = ledger::get(&self.ctx.db, self.ctx.migration_id, kind, key).await;
        let step = ledger::item_ref(kind, key);
        if ledger::decide(prev.as_ref().map(|r| r.status.as_str()), forced) == Decision::Skip {
            self.count(ItemStatus::Skipped);
            (self.ctx.progress)(&step, label, "skipped", Some("Already imported".into()));
            return None;
        }
        if let Err(e) = ledger::begin(&self.ctx.db, self.ctx.migration_id, kind, key).await {
            tracing::warn!("Migration {}: could not mark {step} running: {e}", self.ctx.migration_id);
        }
        (self.ctx.progress)(&step, label, "in_progress", None);
        Some(forced)
    }

    /// Writes the outcome to the ledger, counts it and emits its terminal event.
    pub async fn record(&self, kind: &str, key: &str, label: &str, outcome: &ItemOutcome) {
        if let Err(e) = ledger::finish(&self.ctx.db, self.ctx.migration_id, kind, key, outcome).await {
            tracing::error!(
                "Migration {}: could not record {kind}:{key}: {e}",
                self.ctx.migration_id
            );
        }
        self.count(outcome.status);
        let status = match outcome.status {
            ItemStatus::Done => "done",
            ItemStatus::Warning => "warning",
            ItemStatus::Skipped => "skipped",
            ItemStatus::Failed => "error",
        };
        let msg = (!outcome.message.is_empty()).then(|| outcome.message.clone());
        (self.ctx.progress)(&ledger::item_ref(kind, key), label, status, msg);
    }

    /// Gate + run + record in one call, for steps with no data to hand on.
    pub async fn run<F, Fut>(&self, kind: &str, key: &str, label: &str, f: F) -> Option<ItemOutcome>
    where
        F: FnOnce(bool) -> Fut,
        Fut: std::future::Future<Output = ItemOutcome>,
    {
        let forced = self.gate(kind, key, label).await?;
        let outcome = f(forced).await;
        self.record(kind, key, label, &outcome).await;
        Some(outcome)
    }
}

// ──────────────────────────────────────────────────────────────
// Site executor
// ──────────────────────────────────────────────────────────────

/// What a site import needs besides the [`ImportCtx`].
pub struct SiteEnv<'a> {
    pub run: &'a ItemRunner<'a>,
    pub agents: &'a AgentRegistry,
    pub headers: &'a HeaderMap,
    pub role: &'a str,
    pub inventory: &'a Value,
    /// HestiaCP archive: aliases, canonical host, SSL, SFTP and the job-based
    /// file copy apply. Other panels keep the historical behaviour.
    pub hestia: bool,
    pub apache_installed: bool,
    pub default_php_version: Option<&'a str>,
    /// PHP versions already ensured in this run (17 sites on 8.3 = one check).
    pub php_ready: Mutex<HashSet<String>>,
}

pub fn inventory_site<'v>(inventory: &'v Value, domain: &str) -> Option<&'v Value> {
    inventory.get("sites")?.as_array()?.iter().find(|s| {
        s.get("domain").and_then(|d| d.as_str()).is_some_and(|d| d.eq_ignore_ascii_case(domain))
    })
}

fn str_of<'v>(v: &'v Value, k: &str) -> Option<&'v str> {
    v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty())
}

/// Aliases from the inventory: valid domains, not the site itself, no
/// duplicate, at most [`MAX_ALIASES`]. Lowercased.
pub fn sanitize_aliases(raw: Option<&Value>, domain: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in raw.and_then(|v| v.as_array()).into_iter().flatten() {
        let Some(a) = a.as_str() else { continue };
        let a = a.trim().trim_end_matches('.').to_ascii_lowercase();
        if a.is_empty() || a == domain || out.contains(&a) || !crate::routes::is_valid_domain(&a) {
            continue;
        }
        if out.len() == MAX_ALIASES {
            break;
        }
        out.push(a);
    }
    out
}

/// The canonical host that can actually be served: `www` needs `www.<d>` among
/// the aliases kept. Returns the value and an optional warning.
pub fn effective_canonical(
    wanted: Option<&str>,
    domain: &str,
    aliases: &[String],
) -> (Option<&'static str>, Option<String>) {
    match wanted {
        Some("www") => {
            if aliases.iter().any(|a| *a == format!("www.{domain}")) {
                (Some("www"), None)
            } else {
                (None, Some(format!(
                    "www.{domain} is not served here, so the redirect to it was not set up"
                )))
            }
        }
        Some("apex") => (Some("apex"), None),
        _ => (None, None),
    }
}

/// The PHP version to use: request override > inventory > wizard default.
pub fn pick_php_version<'a>(
    override_v: Option<&'a str>,
    inventory_v: Option<&'a str>,
    default_v: Option<&'a str>,
) -> Option<&'a str> {
    override_v.or(inventory_v).or(default_v)
}

/// Is this agent-job report one that a human should look at?
pub fn files_report_has_notes(report: &Value) -> bool {
    let non_empty = |k: &str| report.get(k).and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty());
    non_empty("warnings")
        || non_empty("paths_to_fix")
        || non_empty("symlinks_out")
        || str_of(report, "custom_nginx_saved").is_some()
        || report.get("doc_root_used").and_then(|v| v.as_str()) == Some("public_html0")
}

/// The keys of the W1-I report kept in the ledger (all names, counts, paths).
fn files_details(report: &Value) -> Value {
    let mut d = json!({});
    for k in [
        "doc_root_used", "private_copied", "files_bytes", "rewritten", "paths_to_fix", "symlinks_out",
        "upload_php_files", "custom_nginx_saved", "warnings",
    ] {
        if let Some(v) = report.get(k) {
            d[k] = v.clone();
        }
    }
    d
}

async fn site_row_exists(db: &sqlx::PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sites WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .map(|n| n > 0)
        .unwrap_or(false)
}

/// Writes the vhost from the stored row (`build_nginx_body`, W3).
async fn write_vhost(ctx: &ImportCtx, site_id: Uuid) -> Result<(), String> {
    let site: crate::models::Site = sqlx::query_as("SELECT * FROM sites WHERE id = $1")
        .bind(site_id)
        .fetch_one(&ctx.db)
        .await
        .map_err(|e| format!("could not read the site row: {e}"))?;
    let bind = crate::services::server_ips::nginx_bind_ip(&ctx.db, &site).await;
    let body = crate::routes::sites::build_nginx_body(&site, bind.as_deref());
    ctx.agent
        .put(&format!("/nginx/sites/{}", site.domain), body)
        .await
        .map(|_| ())
        .map_err(|e| ledger::redact(&e.to_string()))
}

/// Same statement as `upload_ssl` / W3's `sites::record_uploaded_ssl`, which is
/// not in this branch yet: an imported certificate is an uploaded one
/// (`ssl_challenge` NULL), renewable by the existing auto-renewal (D3).
async fn record_imported_ssl(
    db: &sqlx::PgPool,
    site_id: Uuid,
    cert_path: Option<&str>,
    key_path: Option<&str>,
    expiry: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sites SET ssl_enabled = true, ssl_cert_path = COALESCE($1, ssl_cert_path), \
         ssl_key_path = COALESCE($2, ssl_key_path), ssl_expiry = COALESCE($3, ssl_expiry), \
         ssl_profile = NULL, \
         ssl_challenge = NULL, ssl_cert_subject = NULL, ssl_wildcard = NULL, \
         ssl_dns_zone_id = NULL, \
         ssl_renewal_at = NULL, ssl_renewal_checked_at = NULL, updated_at = NOW() WHERE id = $4",
    )
    .bind(cert_path)
    .bind(key_path)
    .bind(expiry)
    .bind(site_id)
    .execute(db)
    .await
    .map(|_| ())
}

/// Ensures a PHP version is installed (`php:<v>` item). `Err` = not usable.
pub async fn ensure_php(env: &SiteEnv<'_>, version: &str) -> Result<(), String> {
    let ctx = env.run.ctx;
    let label = format!("PHP {version}");
    let ready = |env: &SiteEnv<'_>| {
        env.php_ready.lock().unwrap_or_else(|e| e.into_inner()).insert(version.to_string());
    };
    if env.php_ready.lock().unwrap_or_else(|e| e.into_inner()).contains(version) {
        return Ok(());
    }
    let Some(_forced) = env.run.gate("php", version, &label).await else {
        ready(env);
        return Ok(());
    };
    let installed = match ctx.agent.get("/php/versions").await {
        Ok(v) => v
            .get("versions")
            .and_then(|a| a.as_array())
            .is_some_and(|a| {
                a.iter().any(|x| {
                    x.get("version").and_then(|s| s.as_str()) == Some(version)
                        && x.get("installed").and_then(|b| b.as_bool()).unwrap_or(false)
                })
            }),
        Err(e) => {
            let o = ItemOutcome::failed(format!("could not list the installed PHP versions: {e}"));
            env.run.record("php", version, &label, &o).await;
            return Err(o.message);
        }
    };
    let legacy = LEGACY_PHP_VERSIONS.contains(&version);
    let outcome = if installed {
        ItemOutcome::done(format!("PHP {version} already installed"))
    } else {
        (ctx.progress)(
            &ledger::item_ref("php", version),
            &label,
            "in_progress",
            Some(format!("Installing PHP {version} (can take several minutes)")),
        );
        match ctx
            .agent
            .post_long("/php/install", Some(json!({ "version": version })), PHP_INSTALL_TIMEOUT_SECS)
            .await
        {
            Ok(r) if r.get("success").and_then(|b| b.as_bool()) == Some(false) => ItemOutcome::failed(
                str_of(&r, "message").unwrap_or("PHP install failed").to_string(),
            ),
            Ok(_) => ItemOutcome::done(format!("PHP {version} installed")),
            Err(e) => ItemOutcome::failed(format!("PHP {version} install failed: {e}")),
        }
    };
    let outcome = if outcome.is_success() && legacy {
        ItemOutcome::warning(format!(
            "{}. PHP {version} reached end of life and gets no security updates.",
            outcome.message
        ))
    } else {
        outcome
    };
    env.run.record("php", version, &label, &outcome).await;
    if outcome.is_success() {
        ready(env);
        Ok(())
    } else {
        Err(outcome.message)
    }
}

/// Imports one site. Returns its `sites.id` when a row exists for it (created
/// now or by an earlier run of this migration), so the databases can attach.
pub async fn import_site(env: &SiteEnv<'_>, choice: &SiteChoice) -> Option<Uuid> {
    let ctx = env.run.ctx;
    let domain = choice.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = format!("Site {domain}");
    let Some(inv) = inventory_site(env.inventory, &domain) else {
        env.run
            .record("site", &domain, &label, &ItemOutcome::failed("This domain is not in the analysed archive"))
            .await;
        return None;
    };

    // ── 1. site row + vhost ───────────────────────────────────
    let (site_id, vhost_ok) = match env.run.gate("site", &domain, &label).await {
        None => {
            let row = ledger::get(&ctx.db, ctx.migration_id, "site", &domain).await?;
            let id = ledger::site_id_of(&row)?;
            if !site_row_exists(&ctx.db, id).await {
                tracing::warn!(
                    "Migration {}: {domain} was imported but its site row is gone; nothing more is done for it",
                    ctx.migration_id
                );
                return None;
            }
            (id, row.details.get("vhost").and_then(|v| v.as_bool()).unwrap_or(true))
        }
        Some(_forced) => {
            let (outcome, sid, vhost_ok) = create_site(env, &domain, inv, choice).await;
            env.run.record("site", &domain, &label, &outcome).await;
            match sid {
                Some(id) if outcome.is_success() => (id, vhost_ok),
                // Failed after the row landed: keep it for the databases, but
                // stop here (the next run resumes this row).
                other => return other,
            }
        }
    };

    // ── 2. files (agent job) ──────────────────────────────────
    let runtime = str_of(inv, "runtime").unwrap_or("static");
    let files_label = format!("Files of {domain}");
    if let Some(forced) = env.run.gate("files", &domain, &files_label).await {
        let outcome = import_files(env, &domain, inv, runtime, forced, &files_label).await;
        // A site whose files are missing is not active; one whose copy now
        // succeeded (and whose vhost is in place) is again.
        let status_sql = match (outcome.is_success(), vhost_ok) {
            (true, true) => Some("UPDATE sites SET status = 'active', updated_at = NOW() WHERE id = $1 AND status = 'error'"),
            (false, _) => Some("UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1"),
            (true, false) => None,
        };
        if let Some(sql) = status_sql {
            let _ = sqlx::query(sql).bind(site_id).execute(&ctx.db).await;
        }
        env.run.record("files", &domain, &files_label, &outcome).await;
    }

    if !env.hestia {
        return Some(site_id);
    }

    // ── 3. SSL from the archive ───────────────────────────────
    let ssl_present = inv.get("ssl").and_then(|s| s.get("present")).and_then(|b| b.as_bool()).unwrap_or(false);
    if choice.options.ssl.unwrap_or(true) && ssl_present && vhost_ok {
        let ssl_label = format!("Certificate of {domain}");
        env.run
            .run("ssl", &domain, &ssl_label, |_| import_ssl(ctx, site_id, &domain, inv))
            .await;
    }

    // ── 4. SFTP (after the files) ─────────────────────────────
    if choice.options.sftp.unwrap_or(true) && str_of(inv, "ftp_user").is_some() {
        let sftp_label = format!("SFTP of {domain}");
        let files_done = ledger::get(&ctx.db, ctx.migration_id, "files", &domain)
            .await
            .is_some_and(|r| ledger::COMPLETED.contains(&r.status.as_str()));
        if files_done {
            let forced_ctx = |f: bool| ctx.with_force(f);
            env.run
                .run("sftp", &domain, &sftp_label, |f| {
                    let c = forced_ctx(f);
                    let d = domain.clone();
                    async move { import_sftp(&c, site_id, &d).await }
                })
                .await;
        } else {
            let msg = "Waits for the file copy to finish";
            let _ = ledger::set_pending(&ctx.db, ctx.migration_id, "sftp", &domain, msg).await;
            (ctx.progress)(&ledger::item_ref("sftp", &domain), &sftp_label, "pending", Some(msg.into()));
        }
    }

    Some(site_id)
}

/// Step 1. Returns `(outcome, site_id if a row exists, vhost written)`.
async fn create_site(
    env: &SiteEnv<'_>,
    domain: &str,
    inv: &Value,
    choice: &SiteChoice,
) -> (ItemOutcome, Option<Uuid>, bool) {
    let ctx = env.run.ctx;
    let opts = &choice.options;
    let mut warnings: Vec<String> = Vec::new();
    let runtime = str_of(inv, "runtime").unwrap_or("static").to_string();

    // A row created by an earlier attempt of THIS migration is resumed; any other
    // row for the domain is someone else's and is never touched.
    let ours = match ledger::get(&ctx.db, ctx.migration_id, "site", domain).await.and_then(|r| ledger::site_id_of(&r)) {
        Some(id) if site_row_exists(&ctx.db, id).await => Some(id),
        _ => None,
    };
    if ours.is_none() {
        let taken: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM sites WHERE lower(domain) = $1 LIMIT 1")
            .bind(domain)
            .fetch_optional(&ctx.db)
            .await
            .unwrap_or(None);
        if taken.is_some() {
            return (
                ItemOutcome::skipped(format!("A site for {domain} already exists in the panel; it was left unchanged")),
                None,
                false,
            );
        }
    }
    let holder = ours.map(Holder::Site).unwrap_or(Holder::New);

    let claim = move |name: String| {
        async move {
            ensure_claimable(&ctx.db, env.agents, &name, env.headers, holder, env.role)
                .await
                .map_err(|(_, reason)| {
                    reason.get("error").and_then(|v| v.as_str()).unwrap_or("domain not available").to_string()
                })
        }
    };
    let domain = match claim(domain.to_string()).await {
        Ok(d) => d,
        Err(detail) => return (ItemOutcome::skipped(format!("Not imported: {detail}")), ours, false),
    };

    // Aliases and canonical host (HestiaCP only; other panels do not record them).
    let mut aliases: Option<Vec<String>> = None;
    let mut canonical: Option<&'static str> = None;
    if env.hestia {
        let mut kept = Vec::new();
        if opts.aliases.unwrap_or(true) {
            for a in sanitize_aliases(inv.get("aliases"), &domain) {
                match claim(a.clone()).await {
                    Ok(a) => kept.push(a),
                    Err(detail) => warnings.push(format!("Alias {a} omitted: {detail}")),
                }
            }
        }
        if opts.canonical.unwrap_or(true) {
            let (c, w) = effective_canonical(str_of(inv, "canonical_host"), &domain, &kept);
            canonical = c;
            warnings.extend(w);
        }
        aliases = Some(kept);
    }

    // PHP version, installed before the vhost needs its socket.
    let mut php_version: Option<String> = None;
    let mut needs_config: Option<String> = None;
    if runtime == "php" {
        let picked = pick_php_version(
            choice.php_version.as_deref(),
            str_of(inv, "php_version"),
            env.default_php_version,
        )
        .map(str::to_string);
        let picked = match picked {
            Some(v) => Some(v),
            // Other panels never record a version: the historical choice, the
            // first running PHP-FPM of the server.
            None if !env.hestia => first_running_php(ctx).await,
            None => None,
        };
        match picked {
            None if env.hestia => {
                return (
                    ItemOutcome::failed(
                        "HestiaCP used its default PHP version and none was chosen: pick one in the wizard",
                    ),
                    ours,
                    false,
                );
            }
            None => {
                needs_config = Some(
                    "no running PHP-FPM version was found on this server - install one and set it from the site's PHP Version control after import".into(),
                );
            }
            Some(v) if !crate::routes::sites::PHP_VERSIONS.contains(&v.as_str()) => {
                return (ItemOutcome::failed(format!("PHP {v} is not supported by this panel")), ours, false);
            }
            Some(v) => {
                if let Err(e) = ensure_php(env, &v).await {
                    return (ItemOutcome::failed(format!("PHP {v} is not available: {e}")), ours, false);
                }
                if LEGACY_PHP_VERSIONS.contains(&v.as_str()) {
                    warnings.push(format!("PHP {v} gets no security updates"));
                }
                php_version = Some(v);
            }
        }
    } else if runtime != "static" {
        needs_config = Some(format!(
            "{runtime} sites need a port and start command, which can't be detected from the backup - set them from the site's Settings after import"
        ));
    }

    let (web_server, ws_warning) = crate::routes::migration::import_web_server(
        crate::routes::migration::imported_web_server(Some(env.inventory), &domain, &runtime),
        env.apache_installed,
        &domain,
    );
    warnings.extend(ws_warning);

    let inv_bool = |k: &str| inv.get(k).and_then(|b| b.as_bool()).unwrap_or(true);
    let force_ssl = opts.force_ssl.unwrap_or_else(|| inv_bool("force_ssl"));
    let hsts = opts.hsts.unwrap_or_else(|| inv_bool("hsts"));
    let no_exec: Option<Vec<String>> = (runtime == "php" && env.hestia)
        .then(|| DEFAULT_PHP_NO_EXEC_DIRS.iter().map(|s| s.to_string()).collect());
    let status = if needs_config.is_some() { "error" } else { "active" };

    // The row, with its site_id stamped in the ledger in the same transaction.
    let site_id = match write_site_row(
        ctx, ours, &domain, &runtime, status, web_server, php_version.as_deref(), aliases.as_deref(),
        canonical, force_ssl, hsts, no_exec.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return (ItemOutcome::failed(format!("Could not record the site: {e}")), ours, false),
    };

    let mut details = json!({
        "site_id": site_id.to_string(), "runtime": runtime, "web_server": web_server,
        "php_version": php_version, "aliases": aliases, "canonical_host": canonical,
        "force_ssl": force_ssl, "hsts": hsts, "php_no_exec_dirs": no_exec, "vhost": false,
    });

    if let Some(reason) = needs_config {
        warnings.push(format!("Imported without a vhost: {reason}"));
        details["warnings"] = json!(warnings);
        return (ItemOutcome::warning(warnings.join(". ")).with_details(details), Some(site_id), false);
    }
    if let Err(e) = write_vhost(ctx, site_id).await {
        let _ = sqlx::query("UPDATE sites SET status = 'error', updated_at = NOW() WHERE id = $1")
            .bind(site_id)
            .execute(&ctx.db)
            .await;
        return (
            ItemOutcome::failed(format!("The vhost was refused: {e}")).with_details(details),
            Some(site_id),
            false,
        );
    }
    details["vhost"] = json!(true);
    details["warnings"] = json!(warnings);
    let outcome = if warnings.is_empty() {
        ItemOutcome::done("Site created")
    } else {
        ItemOutcome::warning(warnings.join(". "))
    };
    (outcome.with_details(details), Some(site_id), true)
}

#[allow(clippy::too_many_arguments)]
async fn write_site_row(
    ctx: &ImportCtx,
    ours: Option<Uuid>,
    domain: &str,
    runtime: &str,
    status: &str,
    web_server: &str,
    php_version: Option<&str>,
    aliases: Option<&[String]>,
    canonical: Option<&str>,
    force_ssl: bool,
    hsts: bool,
    no_exec: Option<&[String]>,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = ctx.db.begin().await?;
    let id = match ours {
        Some(id) => {
            sqlx::query(
                "UPDATE sites SET runtime = $2, status = $3, web_server = $4, php_version = $5, \
                 aliases = $6, canonical_host = $7, force_ssl = $8, hsts = $9, php_no_exec_dirs = $10, \
                 updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(runtime)
            .bind(status)
            .bind(web_server)
            .bind(php_version)
            .bind(aliases)
            .bind(canonical)
            .bind(force_ssl)
            .bind(hsts)
            .bind(no_exec)
            .execute(&mut *tx)
            .await?;
            id
        }
        None => {
            // `server_id` is the migration row's: the vhost, the claim and the
            // file copy all name that one machine.
            let (id,): (Uuid,) = sqlx::query_as(
                "INSERT INTO sites (user_id, server_id, domain, runtime, status, web_server, php_version, \
                 aliases, canonical_host, force_ssl, hsts, php_no_exec_dirs) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
            )
            .bind(ctx.user_id)
            .bind(ctx.server_id)
            .bind(domain)
            .bind(runtime)
            .bind(status)
            .bind(web_server)
            .bind(php_version)
            .bind(aliases)
            .bind(canonical)
            .bind(force_ssl)
            .bind(hsts)
            .bind(no_exec)
            .fetch_one(&mut *tx)
            .await?;
            id
        }
    };
    ledger::stamp_site_id(&mut tx, ctx.migration_id, domain, id).await?;
    tx.commit().await?;
    Ok(id)
}

async fn first_running_php(ctx: &ImportCtx) -> Option<String> {
    let resp = ctx.agent.get("/php/versions").await.ok()?;
    resp.get("versions")?
        .as_array()?
        .iter()
        .find(|v| {
            v.get("installed").and_then(|b| b.as_bool()).unwrap_or(false)
                && v.get("fpm_running").and_then(|b| b.as_bool()).unwrap_or(false)
        })
        .and_then(|v| v.get("version")?.as_str().map(str::to_string))
}

/// Step 2: the agent copies the files in a job; this waits for it.
async fn import_files(
    env: &SiteEnv<'_>,
    domain: &str,
    inv: &Value,
    runtime: &str,
    forced: bool,
    label: &str,
) -> ItemOutcome {
    let ctx = &env.run.ctx.with_force(forced);
    let mut body = json!({
        "migration_id": ctx.agent_migration_id,
        "domain": domain,
        "runtime": runtime,
        // `force` (rsync --delete) only when the operator asked for it (D10).
        "mode": if ctx.force { "force" } else { "initial" },
    });
    if !env.hestia
        && let Some(d) = str_of(inv, "doc_root")
    {
        body["source_dir"] = json!(d);
    }
    // A W1 agent answers 202 + job id at once; an older one copies before it
    // answers, hence the long budget (this runs in the spawned loop, under no
    // HTTP timeout).
    let resp = match ctx.agent.post_long("/migration/import-site", Some(body), SYNC_FILE_COPY_TIMEOUT_SECS).await {
        Ok(r) => r,
        Err(e) => return ItemOutcome::failed(format!("File import could not start: {e}")),
    };
    let report = match str_of(&resp, "job_id") {
        Some(job) => match wait_job(ctx, job, &ledger::item_ref("files", domain), label).await {
            Ok(r) => r,
            Err(e) => return ItemOutcome::failed(format!("File import failed: {e}")),
        },
        // An agent that copies synchronously answered with the result itself.
        None => resp,
    };
    let details = files_details(&report);
    if files_report_has_notes(&report) {
        let mut notes: Vec<String> = report
            .get("warnings")
            .and_then(|w| w.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if notes.is_empty() {
            notes.push("Files copied; see the manual actions".into());
        }
        ItemOutcome::warning(notes.join(". ")).with_details(details)
    } else {
        ItemOutcome::done("Files copied").with_details(details)
    }
}

/// Step 3: certificate from the archive (W1-C), then the vhost with SSL.
async fn import_ssl(ctx: &ImportCtx, site_id: Uuid, domain: &str, inv: &Value) -> ItemOutcome {
    let ssl = inv.get("ssl").cloned().unwrap_or_else(|| json!({}));
    if ssl.get("expired").and_then(|b| b.as_bool()) == Some(true) {
        return ItemOutcome::warning("The HestiaCP certificate has expired; the site is served over HTTP")
            .with_details(json!({ "not_after": ssl.get("not_after") }));
    }
    let resp = match ctx
        .agent
        .post(
            "/migration/hestia/import-ssl",
            Some(json!({ "migration_id": ctx.agent_migration_id, "domain": domain })),
        )
        .await
    {
        Ok(r) => r,
        Err(AgentError::Status(422, body)) => {
            let v: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
            let code = str_of(&v, "code").unwrap_or("refused").to_string();
            let why = str_of(&v, "error").unwrap_or("certificate refused").to_string();
            return ItemOutcome::warning(format!("Certificate not installed ({code}): {why}; the site is served over HTTP"))
                .with_details(json!({ "code": code }));
        }
        Err(e) => {
            return ItemOutcome::warning(format!("Certificate not installed: {e}; the site is served over HTTP"));
        }
    };
    let expiry = str_of(&resp, "expiry")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    if let Err(e) =
        record_imported_ssl(&ctx.db, site_id, str_of(&resp, "cert_path"), str_of(&resp, "key_path"), expiry).await
    {
        return ItemOutcome::warning(format!("Certificate installed but not recorded: {e}"));
    }
    let details = json!({
        "expiry": resp.get("expiry"), "covers": resp.get("covers"), "issuer": resp.get("issuer"),
        "warnings": resp.get("warnings"),
    });
    if let Err(e) = write_vhost(ctx, site_id).await {
        // Back to the HTTP vhost that worked a moment ago.
        let _ = sqlx::query("UPDATE sites SET ssl_enabled = false, updated_at = NOW() WHERE id = $1")
            .bind(site_id)
            .execute(&ctx.db)
            .await;
        let _ = write_vhost(ctx, site_id).await;
        return ItemOutcome::warning(format!("The vhost with SSL was refused ({e}); the site is served over HTTP"))
            .with_details(details);
    }
    let notes: Vec<String> = resp
        .get("warnings")
        .and_then(|w| w.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if notes.is_empty() {
        ItemOutcome::done("Certificate installed").with_details(details)
    } else {
        ItemOutcome::warning(notes.join(". ")).with_details(details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_cleaned_before_anything_is_claimed() {
        let raw = json!(["www.x.tld", "WWW.X.TLD.", "x.tld", "", "bad domain", 7, "shop.x.tld"]);
        assert_eq!(sanitize_aliases(Some(&raw), "x.tld"), vec!["www.x.tld", "shop.x.tld"]);
        let many: Vec<String> = (0..30).map(|i| format!("a{i}.x.tld")).collect();
        assert_eq!(sanitize_aliases(Some(&json!(many)), "x.tld").len(), MAX_ALIASES);
        assert!(sanitize_aliases(None, "x.tld").is_empty());
    }

    #[test]
    fn a_www_canonical_needs_the_www_alias() {
        let www = vec!["www.x.tld".to_string()];
        assert_eq!(effective_canonical(Some("www"), "x.tld", &www), (Some("www"), None));
        let (c, w) = effective_canonical(Some("www"), "x.tld", &[]);
        assert_eq!(c, None);
        assert!(w.unwrap().contains("www.x.tld"));
        assert_eq!(effective_canonical(Some("apex"), "x.tld", &www), (Some("apex"), None));
        assert_eq!(effective_canonical(None, "x.tld", &www), (None, None));
        assert_eq!(effective_canonical(Some("other"), "x.tld", &www), (None, None));
    }

    #[test]
    fn php_version_override_beats_inventory_beats_default() {
        assert_eq!(pick_php_version(Some("8.4"), Some("5.6"), Some("8.3")), Some("8.4"));
        assert_eq!(pick_php_version(None, Some("5.6"), Some("8.3")), Some("5.6"));
        assert_eq!(pick_php_version(None, None, Some("8.3")), Some("8.3"));
        assert_eq!(pick_php_version(None, None, None), None);
    }

    #[test]
    fn a_files_report_with_notes_is_a_warning() {
        assert!(!files_report_has_notes(&json!({ "doc_root_used": "public_html", "warnings": [], "paths_to_fix": [] })));
        assert!(files_report_has_notes(&json!({ "paths_to_fix": [{ "file": "wp-config.php", "occurrences": 1 }] })));
        assert!(files_report_has_notes(&json!({ "custom_nginx_saved": "/var/www/x/private/.hestia-import/custom-nginx/a.stpl" })));
        assert!(files_report_has_notes(&json!({ "doc_root_used": "public_html0" })));
        assert!(files_report_has_notes(&json!({ "symlinks_out": ["x -> /etc"] })));
        let d = files_details(&json!({ "files_bytes": 5, "unknown": "dropped" }));
        assert_eq!(d, json!({ "files_bytes": 5 }));
    }

    #[test]
    fn site_options_default_to_the_archive() {
        let c: SiteChoice = serde_json::from_value(json!({ "domain": "x.tld" })).unwrap();
        assert!(c.options.ssl.is_none() && c.php_version.is_none());
        let c: SiteChoice = serde_json::from_value(json!({
            "domain": "x.tld", "php_version": "5.6", "options": { "ssl": false, "hsts": false }
        }))
        .unwrap();
        assert_eq!(c.options.ssl, Some(false));
        assert_eq!(c.options.hsts, Some(false));
        assert_eq!(c.options.aliases, None);
    }
}
