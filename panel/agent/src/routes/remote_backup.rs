use axum::{
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use super::AppState;
use crate::services::remote_backup;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Deserialize)]
pub struct UploadRequest {
    pub filepath: String,
    pub destination: DestinationConfig,
}

#[derive(Deserialize)]
pub struct DestinationConfig {
    #[serde(rename = "type")]
    pub dtype: String,
    // S3/R2 fields
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub path_prefix: Option<String>,
    // SFTP fields
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub remote_path: Option<String>,
}

#[derive(Deserialize)]
pub struct TestRequest {
    pub destination: DestinationConfig,
}

/// Body of `/backups/prune`.
///
/// The original body - `{destination, domain, retention}` - is still accepted
/// and still means "keep the `retention` newest `<domain>-<stamp>.tar.gz`".
/// `name_prefix` replaces the domain-derived `<domain>-` prefix, `suffixes`
/// replaces the `.tar.gz` default; one of `name_prefix` and `domain` is required.
#[derive(Deserialize)]
pub struct PruneRequest {
    pub destination: DestinationConfig,
    #[serde(default)]
    pub domain: Option<String>,
    pub retention: usize,
    #[serde(default)]
    pub name_prefix: Option<String>,
    #[serde(default)]
    pub suffixes: Option<Vec<String>>,
}

/// Body of `/backups/list`. `prefix` is relative to the destination's base
/// (`path_prefix` for S3, `remote_path` for SFTP).
#[derive(Deserialize)]
pub struct ListRequest {
    pub destination: DestinationConfig,
    #[serde(default)]
    pub prefix: Option<String>,
    /// S3 page size (1 to 1000). Only useful to exercise pagination in a lab.
    #[serde(default)]
    pub page_size: Option<u32>,
}

/// Body of `/backups/download`.
#[derive(Deserialize)]
pub struct DownloadRequest {
    pub destination: DestinationConfig,
    pub key: String,
    pub target_name: String,
}

/// Body of `/backups/delete`.
#[derive(Deserialize)]
pub struct DeleteRequest {
    pub destination: DestinationConfig,
    pub key: String,
}

/// POST /backups/upload - Upload a local backup file to a remote destination.
async fn upload(
    Json(body): Json<UploadRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    // Validate filepath. The prefix check alone is a LEXICAL, not a resolved,
    // guard -- "/var/backups/dockpanel/../../etc/shadow" satisfies
    // starts_with() and the OS resolves the ".." on open, same shape as
    // git_build.rs's is_valid_dockerfile/is_valid_build_context reject
    // elsewhere in this crate. ProtectSystem=strict blocks writes outside the
    // agent's ReadWritePaths allowlist, not reads, so an unguarded path here
    // would be arbitrary root-readable-file exfiltration to an
    // attacker-supplied S3/SFTP destination, not merely a write bypass.
    if !body.filepath.starts_with("/var/backups/dockpanel/") || body.filepath.contains("..") {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid backup filepath"));
    }

    match body.destination.dtype.as_str() {
        "s3" => {
            let bucket = body.destination.bucket.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing bucket"))?;
            let region = body.destination.region.as_deref().unwrap_or("us-east-1");
            let endpoint = body.destination.endpoint.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing endpoint"))?;
            let access_key = body.destination.access_key.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing access_key"))?;
            let secret_key = body.destination.secret_key.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing secret_key"))?;
            let prefix = body.destination.path_prefix.as_deref().unwrap_or("");

            let url = remote_backup::upload_s3(
                &body.filepath, bucket, region, endpoint, access_key, secret_key, prefix,
            )
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

            Ok(Json(serde_json::json!({ "success": true, "url": url })))
        }
        "sftp" => {
            let host = body.destination.host.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing host"))?;
            let port = body.destination.port.unwrap_or(22);
            let username = body.destination.username.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing username"))?;
            let remote_path = body.destination.remote_path.as_deref().unwrap_or("/backups");

            let dest = remote_backup::upload_sftp(
                &body.filepath,
                host,
                port,
                username,
                body.destination.password.as_deref(),
                body.destination.key_path.as_deref(),
                remote_path,
            )
            .await
            .map_err(|e| {
                // The same rule `test_destination` states below, applied to the
                // path that matters more. A scheduled upload runs unattended, so
                // the redacted body IS the whole message an operator ever gets:
                // v2.99.0 taught the test handler to answer a precondition as a
                // 4xx and left this one answering 5xx, which means the nightly
                // failure still reads "your agent broke" on a working agent.
                let status = if e == remote_backup::SSHPASS_MISSING {
                    StatusCode::FAILED_DEPENDENCY
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                err(status, &e)
            })?;

            Ok(Json(serde_json::json!({ "success": true, "destination": dest })))
        }
        other => Err(err(StatusCode::BAD_REQUEST, &format!("Unknown destination type: {other}"))),
    }
}

/// POST /backups/test-destination - Test connection to a remote destination.
async fn test_destination(
    Json(body): Json<TestRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    match body.destination.dtype.as_str() {
        "s3" => {
            let bucket = body.destination.bucket.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing bucket"))?;
            let region = body.destination.region.as_deref().unwrap_or("us-east-1");
            let endpoint = body.destination.endpoint.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing endpoint"))?;
            let access_key = body.destination.access_key.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing access_key"))?;
            let secret_key = body.destination.secret_key.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing secret_key"))?;

            // Same defaults the upload handler applies, so the test probes the
            // location the backups will actually go to rather than the bucket root.
            let prefix = body.destination.path_prefix.as_deref().unwrap_or("");

            remote_backup::test_s3(bucket, region, endpoint, access_key, secret_key, prefix)
                .await
                .map_err(|e| err(StatusCode::BAD_GATEWAY, &e))?;

            Ok(Json(serde_json::json!({ "success": true, "message": "S3 connection successful" })))
        }
        "sftp" => {
            let host = body.destination.host.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing host"))?;
            let port = body.destination.port.unwrap_or(22);
            let username = body.destination.username.as_deref()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing username"))?;
            let remote_path = body.destination.remote_path.as_deref().unwrap_or("/backups");

            remote_backup::test_sftp(
                host, port, username,
                body.destination.password.as_deref(),
                body.destination.key_path.as_deref(),
                remote_path,
            )
            .await
            .map_err(|e| {
                // A missing package on this box is a precondition the caller can
                // act on, not the agent falling over. The panel keeps the body of
                // a 4xx and replaces the body of a 5xx with an incident id, so
                // answering 5xx here is what discards the remedy.
                let status = if e == remote_backup::SSHPASS_MISSING {
                    StatusCode::FAILED_DEPENDENCY
                } else {
                    StatusCode::BAD_GATEWAY
                };
                err(status, &e)
            })?;

            Ok(Json(serde_json::json!({ "success": true, "message": "SFTP connection successful" })))
        }
        other => Err(err(StatusCode::BAD_REQUEST, &format!("Unknown type: {other}"))),
    }
}

/// A destination resolved for the list / download / delete / prune routes.
///
/// `upload` and `test_destination` above resolve their own fields inline and
/// are left as they are; these four share one resolution so the base each of
/// them treats as "the destination" is the same one, and the same one
/// `upload_s3` / `upload_sftp` write under.
enum Remote<'a> {
    S3 {
        bucket: &'a str,
        region: &'a str,
        endpoint: &'a str,
        access_key: &'a str,
        secret_key: &'a str,
        /// `path_prefix` without surrounding `/`, plus `/`, or empty.
        key_prefix: String,
    },
    Sftp {
        host: &'a str,
        port: u16,
        username: &'a str,
        password: Option<&'a str>,
        key_path: Option<&'a str>,
        /// `remote_path` (default `/backups`) without trailing `/`.
        dir: String,
    },
}

impl Remote<'_> {
    /// Every key of this destination starts with this.
    fn key_prefix(&self) -> String {
        match self {
            Remote::S3 { key_prefix, .. } => key_prefix.clone(),
            Remote::Sftp { dir, .. } => format!("{dir}/"),
        }
    }
}

fn resolve(d: &DestinationConfig) -> Result<Remote<'_>, ApiErr> {
    match d.dtype.as_str() {
        "s3" => Ok(Remote::S3 {
            bucket: d.bucket.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing bucket"))?,
            region: d.region.as_deref().unwrap_or("us-east-1"),
            endpoint: d.endpoint.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing endpoint"))?,
            access_key: d.access_key.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing access_key"))?,
            secret_key: d.secret_key.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing secret_key"))?,
            key_prefix: remote_backup::s3_key_prefix(d.path_prefix.as_deref().unwrap_or("")),
        }),
        "sftp" => Ok(Remote::Sftp {
            host: d.host.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing host"))?,
            port: d.port.unwrap_or(22),
            username: d.username.as_deref().ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing username"))?,
            password: d.password.as_deref(),
            key_path: d.key_path.as_deref(),
            dir: remote_backup::sftp_dir(d.remote_path.as_deref().unwrap_or("/backups")),
        }),
        other => Err(err(StatusCode::BAD_REQUEST, &format!("Unknown destination type: {other}"))),
    }
}

/// Status for a failure reported by the remote side.
///
/// Same rule as `test_destination`: a precondition the caller can act on is a
/// 4xx, because the panel keeps a 4xx body and replaces a 5xx body with an
/// incident reference.
fn remote_err(e: String) -> ApiErr {
    let status = if e == remote_backup::SSHPASS_MISSING {
        StatusCode::FAILED_DEPENDENCY
    } else if e.starts_with(remote_backup::DOWNLOAD_TOO_LARGE) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_GATEWAY
    };
    err(status, &e)
}

fn bad_request(e: String) -> ApiErr {
    err(StatusCode::BAD_REQUEST, &e)
}

/// List the objects directly under the destination's base (plus `prefix`).
async fn list_remote(remote: &Remote<'_>, sub: &str, page_size: Option<u32>) -> Result<Vec<remote_backup::RemoteObject>, String> {
    match remote {
        Remote::S3 { bucket, region, endpoint, access_key, secret_key, key_prefix } => {
            remote_backup::list_s3(
                bucket, region, endpoint, access_key, secret_key,
                &format!("{key_prefix}{sub}"),
                page_size,
            )
            .await
        }
        Remote::Sftp { host, port, username, password, key_path, dir } => {
            // `sub` = "<sub/dir>/<name start>": list the directory, filter names.
            let (dir_part, name_part) = match sub.rfind('/') {
                Some(i) => (&sub[..i], &sub[i + 1..]),
                None => ("", sub),
            };
            let target = if dir_part.is_empty() { dir.clone() } else { format!("{dir}/{dir_part}") };
            let objects =
                remote_backup::list_sftp(host, *port, username, *password, *key_path, &target).await?;
            Ok(objects.into_iter().filter(|o| o.name.starts_with(name_part)).collect())
        }
    }
}

async fn delete_remote(remote: &Remote<'_>, key: &str) -> Result<(), String> {
    match remote {
        Remote::S3 { bucket, region, endpoint, access_key, secret_key, .. } => {
            remote_backup::delete_s3(bucket, region, endpoint, access_key, secret_key, key).await
        }
        Remote::Sftp { host, port, username, password, key_path, .. } => {
            remote_backup::delete_sftp(host, *port, username, *password, *key_path, key).await
        }
    }
}

/// POST /backups/list - List the objects at a destination.
///
/// Direct children only, on both backends (`delimiter=/` for S3, one `ls` for
/// SFTP), S3 paginated to the end.
async fn list_objects(
    Json(body): Json<ListRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let sub = body.prefix.as_deref().unwrap_or("");
    remote_backup::validate_list_prefix(sub).map_err(bad_request)?;
    if let Some(n) = body.page_size {
        if !(1..=1000).contains(&n) {
            return Err(err(StatusCode::BAD_REQUEST, "page_size must be between 1 and 1000"));
        }
    }
    let remote = resolve(&body.destination)?;
    let objects = list_remote(&remote, sub, body.page_size).await.map_err(remote_err)?;
    Ok(Json(serde_json::json!({ "objects": objects })))
}

/// POST /backups/download - Fetch one object into the restore inbox.
///
/// Written to a hidden 0600 partial file in the 0700 inbox, hashed, then renamed
/// to `<inbox>/<target_name>`; the partial file is removed on every failure path.
async fn download(
    Json(body): Json<DownloadRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    remote_backup::validate_target_name(&body.target_name).map_err(bad_request)?;
    let remote = resolve(&body.destination)?;
    remote_backup::validate_key_under(&body.key, &remote.key_prefix()).map_err(bad_request)?;

    let inbox = std::path::Path::new(remote_backup::RESTORE_INBOX);
    remote_backup::prepare_inbox(inbox).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let part = remote_backup::create_part_file(inbox, &body.target_name)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    match &remote {
        Remote::S3 { bucket, region, endpoint, access_key, secret_key, .. } => {
            remote_backup::download_s3(bucket, region, endpoint, access_key, secret_key, &body.key, &part.path).await
        }
        Remote::Sftp { host, port, username, password, key_path, .. } => {
            remote_backup::download_sftp(host, *port, username, *password, *key_path, &body.key, &part.path).await
        }
    }
    .map_err(remote_err)?;

    let done = remote_backup::finalize_download(part, inbox, &body.target_name)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    tracing::info!("Downloaded {} to {} ({} bytes, sha256 {})", body.key, done.path, done.size, done.sha256);
    Ok(Json(serde_json::json!(done)))
}

/// POST /backups/delete - Delete one object under the destination's prefix.
async fn delete_object(
    Json(body): Json<DeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let remote = resolve(&body.destination)?;
    remote_backup::validate_key_under(&body.key, &remote.key_prefix()).map_err(bad_request)?;
    delete_remote(&remote, &body.key).await.map_err(remote_err)?;
    tracing::info!("Deleted remote object {}", body.key);
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// The name prefix, suffixes and legacy flag a prune body asks for, validated.
fn prune_selector(body: &PruneRequest) -> Result<(String, Vec<String>, bool), String> {
    let (prefix, legacy) = match (&body.name_prefix, &body.domain) {
        // With a name_prefix the domain is ignored, including an empty one (the
        // backend sends `"domain": ""` for database dumps).
        (Some(p), _) => (p.clone(), false),
        (None, Some(d)) if !d.is_empty() => (format!("{d}-"), true),
        _ => return Err("Missing name_prefix or domain".to_string()),
    };
    remote_backup::validate_name_prefix(&prefix)?;
    let suffixes = body.suffixes.clone().unwrap_or_else(|| vec![".tar.gz".to_string()]);
    remote_backup::validate_suffixes(&suffixes)?;
    Ok((prefix, suffixes, legacy))
}

/// POST /backups/prune - Delete old remote backups, keep N newest.
///
/// S3 and SFTP. Only names `<name_prefix><[A-Za-z0-9._-]+><suffix>` directly
/// under the destination's base are candidates (see
/// `remote_backup::prune_name_matches`); everything else is never deleted.
///
/// A listing failure is a 502. A deletion failure is NOT: the run continues,
/// and the answer is a 200 carrying `failed`, `errors` and a `message` - the
/// backend's callers already turn a `message` into a warning event, while a 5xx
/// body would be replaced by an incident reference and the counts lost.
async fn prune(
    Json(body): Json<PruneRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let (prefix, suffixes, legacy) = prune_selector(&body).map_err(bad_request)?;
    let remote = resolve(&body.destination)?;
    let key_prefix = remote.key_prefix();

    // S3 narrows the listing server-side with the name prefix; SFTP filters.
    let objects = list_remote(&remote, &prefix, None).await.map_err(remote_err)?;
    let (kept, to_delete) =
        remote_backup::select_for_prune(objects, &prefix, &suffixes, body.retention, legacy);

    let mut deleted = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for o in &to_delete {
        // Belt and braces: a listed key is built under the base, but nothing is
        // deleted that the delete route itself would refuse.
        if let Err(e) = remote_backup::validate_key_under(&o.key, &key_prefix) {
            errors.push(format!("{}: {e}", o.name));
            continue;
        }
        match delete_remote(&remote, &o.key).await {
            Ok(()) => deleted += 1,
            Err(e) => {
                tracing::warn!("Failed to prune {}: {e}", o.key);
                errors.push(format!("{}: {e}", o.name));
            }
        }
    }

    tracing::info!(
        "Pruned {deleted} remote backup(s) matching '{prefix}' ({} kept, {} failed)",
        kept.len(),
        errors.len()
    );

    let mut resp = serde_json::json!({
        "deleted": deleted,
        "pruned": deleted,
        "kept": kept.len(),
        "total": kept.len() + to_delete.len(),
        "failed": errors.len(),
    });
    if !errors.is_empty() {
        resp["message"] = serde_json::Value::String(format!(
            "{} of {} old remote backups could not be deleted: {}",
            errors.len(),
            to_delete.len(),
            errors.join("; ")
        ));
        resp["errors"] = serde_json::json!(errors);
    }
    Ok(Json(resp))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/backups/upload", post(upload))
        .route("/backups/test-destination", post(test_destination))
        .route("/backups/prune", post(prune))
        .route("/backups/list", post(list_objects))
        .route("/backups/download", post(download))
        .route("/backups/delete", post(delete_object))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3_dest(prefix: &str) -> DestinationConfig {
        serde_json::from_value(serde_json::json!({
            "type": "s3", "bucket": "b", "endpoint": "https://s3.example", "access_key": "AK",
            "secret_key": "SK", "path_prefix": prefix
        }))
        .unwrap()
    }

    /// The body every caller in the backend sends today must still parse and
    /// still mean "<domain>-*.tar.gz, keep N".
    #[test]
    fn legacy_prune_body_still_parses_and_keeps_its_meaning() {
        let body: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3", "bucket": "b", "endpoint": "https://e", "access_key": "a", "secret_key": "s" },
            "domain": "example.com",
            "retention": 7
        }))
        .unwrap();
        assert_eq!(body.retention, 7);
        let (prefix, suffixes, legacy) = prune_selector(&body).unwrap();
        assert_eq!(prefix, "example.com-");
        assert_eq!(suffixes, vec![".tar.gz".to_string()]);
        assert!(legacy);
    }

    #[test]
    fn name_prefix_replaces_the_domain_prefix() {
        let body: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "sftp", "host": "h", "username": "u" },
            "domain": "example.com",
            "name_prefix": "cyberhunter-dr-",
            "suffixes": [".tar.gz.age", ".manifest.json"],
            "retention": 14
        }))
        .unwrap();
        let (prefix, suffixes, legacy) = prune_selector(&body).unwrap();
        assert_eq!(prefix, "cyberhunter-dr-");
        assert_eq!(suffixes.len(), 2);
        assert!(!legacy);
    }

    /// Exactly what the backend sends for a database dump.
    #[test]
    fn backend_database_prune_body_is_accepted() {
        let body: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3", "bucket": "b", "endpoint": "https://e", "access_key": "a", "secret_key": "s" },
            "domain": "",
            "retention": 5,
            "name_prefix": "appdb-",
            "suffixes": [".sql.gz", ".sql.gz.enc"]
        }))
        .unwrap();
        let (prefix, suffixes, legacy) = prune_selector(&body).unwrap();
        assert_eq!(prefix, "appdb-");
        assert_eq!(suffixes, vec![".sql.gz".to_string(), ".sql.gz.enc".to_string()]);
        assert!(!legacy);
        assert_eq!(body.retention, 5);
    }

    #[test]
    fn bad_prune_selectors_are_refused() {
        for np in ["", "a/b", "..", "x..y", "../etc"] {
            let body: PruneRequest = serde_json::from_value(serde_json::json!({
                "destination": { "type": "s3" }, "name_prefix": np, "retention": 1
            }))
            .unwrap();
            assert!(prune_selector(&body).is_err(), "name_prefix {np:?} must be refused");
        }
        let neither: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3" }, "retention": 1
        }))
        .unwrap();
        assert!(prune_selector(&neither).is_err());
        // Legacy body with an empty domain would have meant the prefix "-".
        let empty_domain: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3" }, "domain": "", "retention": 1
        }))
        .unwrap();
        assert!(prune_selector(&empty_domain).is_err());
        let empty_suffixes: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3" }, "name_prefix": "db-", "suffixes": [], "retention": 1
        }))
        .unwrap();
        assert!(prune_selector(&empty_suffixes).is_err());
        // A domain carrying a separator is refused like a name_prefix would be.
        let slashed: PruneRequest = serde_json::from_value(serde_json::json!({
            "destination": { "type": "s3" }, "domain": "a/b", "retention": 1
        }))
        .unwrap();
        assert!(prune_selector(&slashed).is_err());
    }

    /// download/delete compare the key against the SAME base upload writes to.
    #[test]
    fn key_prefix_matches_the_upload_base() {
        assert_eq!(resolve(&s3_dest("/backups/")).ok().unwrap().key_prefix(), "backups/");
        assert_eq!(resolve(&s3_dest("")).ok().unwrap().key_prefix(), "");
        let sftp: DestinationConfig = serde_json::from_value(serde_json::json!({
            "type": "sftp", "host": "h", "username": "u"
        }))
        .unwrap();
        assert_eq!(resolve(&sftp).ok().unwrap().key_prefix(), "/backups/");
        let sftp2: DestinationConfig = serde_json::from_value(serde_json::json!({
            "type": "sftp", "host": "h", "username": "u", "remote_path": "/srv/bk/"
        }))
        .unwrap();
        assert_eq!(resolve(&sftp2).ok().unwrap().key_prefix(), "/srv/bk/");
    }

    #[test]
    fn remote_errors_keep_actionable_ones_in_the_4xx_range() {
        assert_eq!(remote_err(remote_backup::SSHPASS_MISSING.to_string()).0, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(
            remote_err(format!("{} (1 bytes)", remote_backup::DOWNLOAD_TOO_LARGE)).0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(remote_err("S3 list failed: HTTP 403".into()).0, StatusCode::BAD_GATEWAY);
    }
}
