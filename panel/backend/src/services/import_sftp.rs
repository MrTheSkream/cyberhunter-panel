//! HestiaCP FTP account import as a panel SFTP account (05-import-hestia, W4-S).
//!
//! The site's SFTP account keeps the HestiaCP `FTP_USER` name (D6) and its
//! yescrypt password: the agent applies the hash itself from the staging
//! (`POST /sftp/sites/{d}/password-hash`, by reference), so it never passes
//! through the backend. Called by the import loop AFTER the site's files are in
//! place (enabling SFTP re-owns the site directory and the PHP pool).

use serde_json::json;
use uuid::Uuid;

use crate::services::agent::AgentError;
use crate::services::import_types::{ImportCtx, ItemOutcome, ItemStatus};

/// D6 / W4-S rule, shared with `enable_sftp`: `^[a-z_][a-z0-9_.-]{0,31}$`,
/// not a reserved system name, not of the generated `sftp<digits>` /
/// `sftpg<digits>` shape. The agent also refuses existing system accounts
/// (409 `username_taken`).
pub fn is_valid_sftp_username(name: &str) -> bool {
    crate::routes::sites::validate_sftp_username(name).is_ok()
}

/// `(ftp_user, number of FTP users of the domain)` from the stored inventory.
pub fn ftp_user_from_inventory(inventory: &serde_json::Value, domain: &str) -> (Option<String>, usize) {
    let from_site = inventory
        .get("sites")
        .and_then(|s| s.as_array())
        .and_then(|a| a.iter().find(|s| s.get("domain").and_then(|d| d.as_str()) == Some(domain)))
        .and_then(|s| s.get("ftp_user"))
        .and_then(|u| u.as_str())
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let accounts: Vec<String> = inventory
        .get("ftp_accounts")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter(|f| f.get("domain").and_then(|d| d.as_str()) == Some(domain))
                .filter_map(|f| f.get("user").and_then(|u| u.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // A Hestia `FTP_USER` may list several users, `:`-separated.
    let first = from_site.or_else(|| accounts.first().cloned());
    let first_split = first.as_deref().map(|f| f.split([':', ',']).map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>());
    let n = first_split.as_ref().map(|v| v.len()).unwrap_or(0).max(accounts.len());
    (first_split.and_then(|v| v.first().map(|s| s.to_string())), n)
}

fn outcome(status: ItemStatus, message: impl Into<String>, details: serde_json::Value) -> ItemOutcome {
    let mut o = ItemOutcome::new(status, message);
    o.details = details;
    o
}

fn agent_code(e: &AgentError) -> Option<(u16, String)> {
    match e {
        AgentError::Status(code, body) => {
            let c = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(str::to_string))
                .unwrap_or_default();
            Some((*code, c))
        }
        _ => None,
    }
}

/// Did the agent refuse the requested NAME (409 `username_taken` / 400
/// `invalid_username`)? Anything else - a provisioning failure - is not a
/// reason to try another name.
fn name_refused(e: &AgentError) -> bool {
    match agent_code(e) {
        Some((409, c)) => c.is_empty() || c == "username_taken",
        Some((400, c)) => c.is_empty() || c == "invalid_username",
        _ => false,
    }
}

pub async fn import_sftp(ctx: &ImportCtx, site_id: Uuid, domain: &str) -> ItemOutcome {
    let site: crate::models::Site = match sqlx::query_as("SELECT * FROM sites WHERE id = $1")
        .bind(site_id)
        .fetch_optional(&ctx.db)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return ItemOutcome::failed("site not found"),
        Err(e) => return ItemOutcome::failed(format!("database error: {e}")),
    };
    if site.sftp_enabled {
        return ItemOutcome::new(ItemStatus::Skipped, "SFTP already enabled for this site");
    }
    if site.domain != domain {
        return ItemOutcome::failed("site and domain do not match");
    }

    let inventory: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT inventory FROM migrations WHERE id = $1")
            .bind(ctx.migration_id)
            .fetch_optional(&ctx.db)
            .await
            .ok()
            .flatten()
            .flatten();
    let (hestia_user, n_users) = inventory
        .as_ref()
        .map(|i| ftp_user_from_inventory(i, domain))
        .unwrap_or((None, 0));
    let Some(hestia_user) = hestia_user else {
        return ItemOutcome::new(ItemStatus::Skipped, "no FTP account for this domain in the backup");
    };
    let mut warnings: Vec<String> = Vec::new();
    if n_users > 1 {
        warnings.push(format!("{n_users} FTP users in HestiaCP, only {hestia_user} is imported"));
    }

    // Name: Hestia's, unless invalid or already used in the panel.
    let wanted = hestia_user.to_ascii_lowercase();
    let mut custom = if !is_valid_sftp_username(&wanted) {
        warnings.push(format!("FTP user name {hestia_user} cannot be an SFTP name, sftp<uid> used"));
        None
    } else {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM sites WHERE sftp_username = $1 AND id <> $2)",
        )
            .bind(&wanted)
            .bind(site_id)
            .fetch_one(&ctx.db)
            .await
            .unwrap_or(true);
        if taken {
            warnings.push(format!("SFTP name {wanted} already used in the panel, sftp<uid> used"));
            None
        } else {
            Some(wanted)
        }
    };

    // The same uid/gid as this site's previous attempt (recorded on the row
    // before the agent call): a retry then asks the agent for the very
    // account it may have left behind, which it resumes instead of refusing.
    let (uid, gid) = match crate::routes::sites::reserve_sftp_ids(&ctx.db, &site).await {
        Ok(ids) => ids,
        Err(e) => return ItemOutcome::failed(format!("could not allocate an SFTP uid: {e}")),
    };
    let path = format!("/sftp/sites/{domain}/enable");
    let mut r = ctx
        .agent
        .post(&path, Some(json!({ "uid": uid, "gid": gid, "username": custom })))
        .await;
    // Fall back to `sftp<uid>` only on a genuine refusal of the NAME (decided
    // by the agent before it creates anything): another site's or a system
    // account (409), or a name this server rejects (400). Our own leftover
    // is resumed by the agent and never answers 409. The fallback keeps the
    // same uid, so it can never add a second account beside a first one.
    if let (Err(e), Some(name)) = (&r, &custom)
        && name_refused(e)
    {
        warnings.push(format!("SFTP name {name} refused by the server ({e}), sftp<uid> used"));
        custom = None;
        r = ctx.agent.post(&path, Some(json!({ "uid": uid, "gid": gid }))).await;
    }
    let enabled = match r {
        Ok(v) => v,
        Err(e) => return ItemOutcome::failed(format!("SFTP enable failed: {e}")),
    };
    let (uid, gid) = crate::routes::sites::sftp_ids_from_agent(&enabled, uid, gid);
    // Keep the custom name ONLY when the agent says it created that account
    // (same rule as `enable_sftp`): an agent that ignores the field creates
    // `sftp<uid>`, and the PHP pool must not be handed to a missing user.
    if let Some(name) = custom.clone()
        && enabled.get("username").and_then(|v| v.as_str()) != Some(name.as_str())
    {
        warnings.push(format!("SFTP name {name} not supported by this server, sftp{uid} used"));
        custom = None;
    }

    if let Err(e) = sqlx::query(
        "UPDATE sites SET sftp_enabled = true, sftp_uid = $1, sftp_gid = $2, sftp_username = $3, \
         updated_at = NOW() WHERE id = $4",
    )
    .bind(uid)
    .bind(gid)
    .bind(&custom)
    .bind(site_id)
    .execute(&ctx.db)
    .await
    {
        return ItemOutcome::failed(format!("SFTP enabled on the server but not recorded: {e}"));
    }

    // PHP pool under the new owner (full vhost rebuild, as `enable_sftp`).
    let mut updated = site.clone();
    updated.sftp_enabled = true;
    updated.sftp_uid = Some(uid);
    updated.sftp_gid = Some(gid);
    updated.sftp_username = custom.clone();
    let username = crate::routes::sites::sftp_account_name(&updated);
    let bind_ip = crate::services::server_ips::nginx_bind_ip(&ctx.db, &updated).await;
    // `pool_user` = the account actually created (custom name, D6), as on every rebuild.
    let body = crate::routes::sites::build_nginx_body(&updated, bind_ip.as_deref());
    if let Err(e) = ctx.agent.put(&format!("/nginx/sites/{domain}"), body).await {
        warnings.push(format!("vhost not rebuilt for the SFTP owner, PHP may not write the files: {e}"));
    }

    // Password: Hestia's hash, applied by the agent from the staging.
    let pw = ctx
        .agent
        .post(
            &format!("/sftp/sites/{domain}/password-hash"),
            Some(json!({ "uid": uid, "migration_id": ctx.agent_migration_id })),
        )
        .await;
    let password = match pw {
        Ok(_) => "kept",
        Err(e) => {
            let why = match agent_code(&e) {
                Some((_, c)) if c == "unsupported_scheme" => "the HestiaCP password hash is not usable on this server".to_string(),
                Some((_, c)) if c == "no_hash" => "no password hash in the backup".to_string(),
                _ => e.to_string(),
            };
            warnings.push(format!(
                "SFTP account locked ({why}): use \"Generate password\" (Reset password on the site's SFTP card)"
            ));
            "locked"
        }
    };

    let details = json!({ "sftp_username": username, "hestia_user": hestia_user, "password": password });
    if warnings.is_empty() {
        outcome(ItemStatus::Done, "SFTP account imported", details)
    } else {
        outcome(ItemStatus::Warning, warnings.join("; "), details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rule() {
        assert!(is_valid_sftp_username("adm-jim_x"));
        assert!(is_valid_sftp_username("_a.b-c9"));
        let long = "a".repeat(33);
        for bad in ["", "Adm", "1abc", "-x", "a b", "a:b", long.as_str()] {
            assert!(!is_valid_sftp_username(bad), "{bad:?}");
        }
        assert!(!is_valid_sftp_username("sftp12") && !is_valid_sftp_username("sftpg3"));
        assert!(is_valid_sftp_username("sftpuser") && is_valid_sftp_username("sftp"));
        assert!(!is_valid_sftp_username("root") && !is_valid_sftp_username("www-data"));
    }

    #[test]
    fn only_a_refused_name_falls_back_to_the_default() {
        let st = |c: u16, b: &str| AgentError::Status(c, b.to_string());
        assert!(name_refused(&st(409, r#"{"error":"x","code":"username_taken"}"#)));
        assert!(name_refused(&st(400, r#"{"error":"x","code":"invalid_username"}"#)));
        assert!(name_refused(&st(409, "not json")), "an older agent without codes");
        // A provisioning failure (rolled back by the agent) is retried as is,
        // never with another name: that is how a second account appeared.
        assert!(!name_refused(&st(500, r#"{"error":"sshd reload failed"}"#)));
        assert!(!name_refused(&st(409, r#"{"error":"x","code":"not_owner"}"#)));
    }

    #[test]
    fn the_agents_uid_wins_over_the_requested_one() {
        use crate::routes::sites::sftp_ids_from_agent;
        assert_eq!(sftp_ids_from_agent(&json!({ "ok": true, "uid": 30000, "gid": 30000 }), 30008, 30008), (30000, 30000));
        assert_eq!(sftp_ids_from_agent(&json!({ "ok": true, "username": "sftp30008" }), 30008, 30008), (30008, 30008));
        assert_eq!(sftp_ids_from_agent(&json!({ "uid": "x", "gid": 1 }), 7, 7), (7, 7));
    }

    #[test]
    fn the_ftp_user_comes_from_the_inventory() {
        let inv = json!({
            "sites": [{ "domain": "x.tld", "ftp_user": "adm-jim_x" }, { "domain": "y.tld", "ftp_user": null }],
            "ftp_accounts": [{ "user": "adm-jim_x", "domain": "x.tld", "hash_scheme": "yescrypt" }]
        });
        assert_eq!(ftp_user_from_inventory(&inv, "x.tld"), (Some("adm-jim_x".into()), 1));
        assert_eq!(ftp_user_from_inventory(&inv, "y.tld"), (None, 0));
        assert_eq!(ftp_user_from_inventory(&inv, "z.tld"), (None, 0));
        let multi = json!({ "sites": [{ "domain": "x.tld", "ftp_user": "adm-jim_a:adm-jim_b" }] });
        assert_eq!(ftp_user_from_inventory(&multi, "x.tld"), (Some("adm-jim_a".into()), 2));
        let only_accounts = json!({ "ftp_accounts": [{ "user": "u1", "domain": "x.tld" }, { "user": "u2", "domain": "x.tld" }] });
        assert_eq!(ftp_user_from_inventory(&only_accounts, "x.tld"), (Some("u1".into()), 2));
    }
}
