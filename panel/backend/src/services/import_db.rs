//! HestiaCP database import into the local MariaDB server (05-import-hestia, W2-B).
//!
//! Order (contract W2-B): the `databases` row (`kind='local'`, `imported_hash=true`,
//! `db_password_enc=''`) is written first, then the agent job
//! `POST /localdb/hestia/import` runs and is followed with `wait_job`; the row is
//! removed again when the job fails and the row did not exist before. The hash
//! never passes through here: the agent reads it from the staging itself.

use uuid::Uuid;

use crate::services::import_types::{wait_job, ImportCtx, ItemOutcome, ItemStatus};

/// Same rule as the agent (`local_mariadb::is_valid_local_user`): the user name
/// comes from the inventory, i.e. from an untrusted archive.
fn is_valid_local_ident(n: &str, max: usize) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        && !n.contains("..")
}

/// The inventory entry of one database: `(db_user, file)`.
fn inventory_entry(inventory: &serde_json::Value, db_name: &str) -> Option<(String, Option<String>)> {
    let entry = inventory
        .get("databases")?
        .as_array()?
        .iter()
        .find(|d| d.get("name").and_then(|n| n.as_str()) == Some(db_name))?;
    let user = entry
        .get("db_user")
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
        .unwrap_or(db_name)
        .to_string();
    let file = entry.get("file").and_then(|f| f.as_str()).map(str::to_string);
    Some((user, file))
}

/// Split an agent job error `code: message` (`exists_not_ours`, `already_imported`).
fn job_error_code(e: &str) -> Option<&'static str> {
    ["exists_not_ours", "already_imported"]
        .into_iter()
        .find(|c| e.contains(&format!("{c}:")))
}

/// Ledger detail written for a successful import: names and counts only.
fn success_details(report: &serde_json::Value, db_user: &str) -> serde_json::Value {
    serde_json::json!({
        "tables": report.get("tables").cloned().unwrap_or(serde_json::Value::Null),
        "collation_rewritten": report.get("collation_rewritten").and_then(|v| v.as_bool()).unwrap_or(false),
        "created_db": report.get("created_db").and_then(|v| v.as_bool()).unwrap_or(false),
        "created_user": report.get("created_user").and_then(|v| v.as_bool()).unwrap_or(false),
        "db_user": db_user,
    })
}

/// The contract's `replace` rule (W2-B) without `force`: an earlier attempt of
/// this item in this migration was left `running` (process died) or `failed`.
/// A failure because the base was someone else's (`exists_not_ours`) never
/// turns into a licence to drop it on the next run.
fn replace_allowed(prior: Option<(&str, &serde_json::Value)>) -> bool {
    match prior {
        Some(("running", _)) => true,
        Some(("failed", d)) => d.get("code").and_then(|c| c.as_str()) != Some("exists_not_ours"),
        _ => false,
    }
}

fn outcome(status: ItemStatus, message: impl Into<String>, details: serde_json::Value) -> ItemOutcome {
    ItemOutcome { status, message: message.into(), details }
}

pub async fn import_hestia_db(ctx: &ImportCtx, db_name: &str, site_id: Uuid) -> ItemOutcome {
    if !is_valid_local_ident(db_name, 64) {
        return ItemOutcome::failed(format!("{db_name}: database name not supported by the local server"));
    }
    let step = format!("db:{db_name}");
    let label = format!("Database {db_name}");
    (ctx.progress)(&step, &label, "in_progress", None);

    // Inventory (stored at analysis, no secret in it): db user and dump member.
    let inventory: Option<serde_json::Value> =
        match sqlx::query_scalar::<_, Option<serde_json::Value>>("SELECT inventory FROM migrations WHERE id = $1")
            .bind(ctx.migration_id)
            .fetch_optional(&ctx.db)
            .await
        {
            Ok(v) => v.flatten(),
            Err(e) => return ItemOutcome::failed(format!("cannot read the migration: {e}")),
        };
    let Some((db_user, file)) = inventory.as_ref().and_then(|i| inventory_entry(i, db_name)) else {
        return ItemOutcome::failed(format!("{db_name} is not in the analysed archive"));
    };
    if !is_valid_local_ident(&db_user, 80) {
        return ItemOutcome::failed(format!("{db_name}: database user name not supported by the local server"));
    }

    // The target site must be on the import's server.
    let site_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sites WHERE id = $1 AND server_id IS NOT DISTINCT FROM $2)",
    )
    .bind(site_id)
    .bind(ctx.server_id)
    .fetch_one(&ctx.db)
    .await
    .unwrap_or(false);
    if !site_ok {
        return ItemOutcome::failed("target site not found on this server");
    }

    // While this runs the loop has marked the row `running`; the state of the
    // attempt BEFORE this one is the ledger's prior state (W5-D).
    let prior = crate::services::migration_ledger::prior_state(&ctx.db, ctx.migration_id, "db", db_name).await;
    let retry = ctx.force || replace_allowed(prior.as_ref().map(|(s, d)| (s.as_str(), d)));

    // A local database of that name on this server: ours only on a retry of this
    // item for the same site. Otherwise it is never touched.
    let existing: Option<(Uuid, Option<Uuid>)> = match sqlx::query_as(
        "SELECT d.id, d.site_id FROM databases d JOIN sites s ON s.id = d.site_id \
         WHERE d.kind = 'local' AND d.name = $1 AND s.server_id IS NOT DISTINCT FROM $2",
    )
    .bind(db_name)
    .bind(ctx.server_id)
    .fetch_optional(&ctx.db)
    .await
    {
        Ok(v) => v,
        Err(e) => return ItemOutcome::failed(format!("cannot read databases: {e}")),
    };
    let (row_id, row_created) = match existing {
        Some((id, sid)) if retry && sid == Some(site_id) => (id, false),
        Some(_) => {
            return outcome(
                ItemStatus::Failed,
                format!("a local database {db_name} already exists in the panel and was not created by this import"),
                serde_json::json!({ "code": "exists_not_ours" }),
            )
        }
        None => {
            let inserted: Result<Uuid, _> = sqlx::query_scalar(
                "INSERT INTO databases (site_id, name, engine, db_user, db_password_enc, container_id, port, kind, imported_hash) \
                 VALUES ($1, $2, 'mariadb', $3, '', NULL, NULL, 'local', true) RETURNING id",
            )
            .bind(site_id)
            .bind(db_name)
            .bind(&db_user)
            .fetch_one(&ctx.db)
            .await;
            match inserted {
                Ok(id) => (id, true),
                Err(e) => return ItemOutcome::failed(format!("cannot record the database: {e}")),
            }
        }
    };

    let body = serde_json::json!({
        "migration_id": ctx.agent_migration_id,
        "db_name": db_name,
        "replace": retry,
        "file": file,
    });
    let result = match ctx.agent.post("/localdb/hestia/import", Some(body)).await {
        Ok(v) => match v.get("job_id").and_then(|j| j.as_str()) {
            Some(job_id) => wait_job(ctx, job_id, &step, &label).await,
            None => Err("the agent did not start the import job".to_string()),
        },
        Err(e) => Err(format!("the agent refused the import: {e}")),
    };

    match result {
        Ok(v) => {
            let report = v.get("report").filter(|r| r.is_object()).unwrap_or(&v);
            let warnings: Vec<String> = report
                .get("warnings")
                .and_then(|w| w.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let details = success_details(report, &db_user);
            if !row_created {
                let _ = sqlx::query("UPDATE databases SET db_user = $1 WHERE id = $2")
                    .bind(&db_user)
                    .bind(row_id)
                    .execute(&ctx.db)
                    .await;
            }
            (ctx.progress)(&step, &label, "done", None);
            if warnings.is_empty() {
                outcome(ItemStatus::Done, "imported", details)
            } else {
                outcome(ItemStatus::Warning, warnings.join("; "), details)
            }
        }
        Err(e) => {
            if row_created {
                let _ = sqlx::query("DELETE FROM databases WHERE id = $1").bind(row_id).execute(&ctx.db).await;
            }
            (ctx.progress)(&step, &label, "error", Some(e.clone()));
            let details = match job_error_code(&e) {
                Some(c) => serde_json::json!({ "code": c, "db_user": db_user }),
                None => serde_json::json!({ "db_user": db_user }),
            };
            outcome(ItemStatus::Failed, e, details)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_entry_reads_names_only() {
        let inv = serde_json::json!({ "databases": [
            { "name": "adm-jim_x", "file": "db/adm-jim_x/adm-jim_x.mysql.sql.gz", "db_user": "adm-jim_u" },
            { "name": "adm-jim_y.be" }
        ]});
        let (u, f) = inventory_entry(&inv, "adm-jim_x").unwrap();
        assert_eq!(u, "adm-jim_u");
        assert_eq!(f.as_deref(), Some("db/adm-jim_x/adm-jim_x.mysql.sql.gz"));
        let (u, f) = inventory_entry(&inv, "adm-jim_y.be").unwrap();
        assert_eq!(u, "adm-jim_y.be", "the user defaults to the database name");
        assert!(f.is_none());
        assert!(inventory_entry(&inv, "other").is_none());
    }

    #[test]
    fn local_identifiers() {
        assert!(is_valid_local_ident("Adm-Jim_shop.be", 64));
        assert!(!is_valid_local_ident("a..b", 64));
        assert!(!is_valid_local_ident("_a", 64));
        assert!(!is_valid_local_ident("a`b", 64));
        assert!(!is_valid_local_ident(&"a".repeat(65), 64));
    }

    #[test]
    fn replace_follows_the_prior_attempt_never_a_foreign_base() {
        let none = serde_json::json!({});
        assert!(!replace_allowed(None), "first attempt");
        assert!(replace_allowed(Some(("running", &none))), "process died mid-import");
        assert!(replace_allowed(Some(("failed", &serde_json::json!({ "db_user": "u" })))));
        let foreign = serde_json::json!({ "code": "exists_not_ours" });
        assert!(!replace_allowed(Some(("failed", &foreign))), "someone else's base");
        assert!(!replace_allowed(Some(("done", &none))));
        assert!(!replace_allowed(Some(("skipped", &none))));
    }

    #[test]
    fn job_error_codes() {
        assert_eq!(job_error_code("exists_not_ours: database x already exists"), Some("exists_not_ours"));
        assert_eq!(job_error_code("already_imported: x"), Some("already_imported"));
        assert_eq!(job_error_code("SQL import failed"), None);
    }

    #[test]
    fn details_never_carry_a_secret() {
        let report = serde_json::json!({ "tables": 12, "collation_rewritten": true, "created_db": true,
                                         "created_user": true, "mysql_hash": "*SECRET", "password": "x" });
        let d = success_details(&report, "u");
        let s = d.to_string();
        assert!(!s.contains("SECRET") && !s.contains("password"), "{s}");
        assert_eq!(d["tables"], 12);
        assert_eq!(d["db_user"], "u");
    }
}
