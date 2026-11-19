use axum::{
    extract::Path,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};

use super::{is_valid_name, AppState};
use crate::services::{backups::BackupInfo, database_backup, encryption};

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(serde::Deserialize)]
pub struct DumpRequest {
    pub container_name: String,
    pub db_name: String,
    pub db_type: String,
    pub user: String,
    pub password: String,
    pub encryption_key: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct RestoreRequest {
    pub container_name: String,
    pub db_type: String,
    pub user: String,
    pub password: String,
    pub encryption_key: Option<String>,
}

/// Who the dump/restore talks to. `container_name == "local"` is the shared local
/// MariaDB server (05-import-hestia): root through the socket, the body's
/// `user`/`password` are ignored (a local user may hold dots), MySQL engines only.
fn check_target(container: &str, db_type: &str, user: &str, password: &str) -> Result<(), ApiErr> {
    if container == database_backup::LOCAL_CONTAINER {
        if !matches!(db_type, "mysql" | "mariadb") {
            return Err(err(StatusCode::BAD_REQUEST, "The local server only holds MariaDB databases"));
        }
        return Ok(());
    }
    if !is_valid_name(container) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid container name"));
    }
    if !is_valid_name(user) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid user name"));
    }
    if password.contains('\0') || password.contains('\n') || password.contains('\r') || password.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid password"));
    }
    Ok(())
}

/// A failed decryption is the FILE's fault (tampered with, truncated, wrong
/// passphrase) -> 422, so the panel relays the sentence; anything else (I/O,
/// openssl) stays a 500.
fn decrypt_status(e: &str) -> StatusCode {
    if encryption::is_content_error(e) {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// POST /db-backups/dump - Dump a database.
async fn dump(
    Json(req): Json<DumpRequest>,
) -> Result<Json<BackupInfo>, ApiErr> {
    // The dump-directory predicate, shared with every other door onto that
    // directory so one module decides what a dump directory may be called. It is a
    // superset of the generic validator, so nothing this door used to accept is
    // refused now. The container and user names below keep the generic validator:
    // different populations, both derived by the panel, neither naming a directory.
    if !database_backup::is_dump_dir_name(&req.db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }
    check_target(&req.container_name, &req.db_type, &req.user, &req.password)?;

    let mut info = match req.db_type.as_str() {
        "mysql" | "mariadb" => {
            database_backup::dump_mysql(&req.container_name, &req.db_name, &req.user, &req.password)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        }
        "postgres" | "postgresql" => {
            database_backup::dump_postgres(&req.container_name, &req.db_name, &req.user, &req.password)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        }
        "mongo" | "mongodb" => {
            database_backup::dump_mongo(&req.container_name, &req.db_name)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        }
        _ => return Err(err(StatusCode::BAD_REQUEST, "Unsupported database type")),
    };

    // Encrypt if key provided
    if let Some(key) = &req.encryption_key {
        if !key.is_empty() {
            let filepath = database_backup::get_backup_path(&req.db_name, &info.filename)
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
            let enc_path = encryption::encrypt_backup(&filepath, key)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
            describe_encrypted(&mut info, std::path::Path::new(&enc_path))
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
        }
    }

    Ok(Json(info))
}

/// Point `info` at the encrypted file that replaced the plaintext dump: its
/// name, its size and ITS sha256. The hash the dump function computed is the
/// plaintext's, a file that no longer exists; recorded as is, every later
/// check of the stored file (the off-site rehydration compares the download
/// with it) would fail. Same rule as app data archives: the hash describes the
/// file kept. A hash that cannot be computed is an error, never the stale one.
async fn describe_encrypted(info: &mut BackupInfo, enc_path: &std::path::Path) -> Result<(), String> {
    let meta = std::fs::metadata(enc_path).map_err(|e| format!("Encrypted file: {e}"))?;
    let sha256 = crate::services::backups::compute_file_sha256(&enc_path.to_string_lossy())
        .await
        .ok_or("Failed to hash the encrypted dump")?;
    info.filename = format!("{}.enc", info.filename);
    info.size_bytes = meta.len();
    info.sha256 = Some(sha256);
    Ok(())
}

/// GET /db-backups/{db_name}/list - List database backups.
async fn list(
    Path(db_name): Path<String>,
) -> Result<Json<Vec<BackupInfo>>, ApiErr> {
    if !database_backup::is_dump_dir_name(&db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }

    let list = database_backup::list_db_backups(&db_name)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(list))
}

/// DELETE /db-backups/{db_name}/{filename} - Delete a database backup.
async fn remove(
    Path((db_name, filename)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !database_backup::is_dump_dir_name(&db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }

    database_backup::delete_db_backup(&db_name, &filename)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "success": true })))
}

/// POST /db-backups/{db_name}/restore/{filename} - Restore a database from backup.
async fn restore(
    Path((db_name, filename)): Path<(String, String)>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !database_backup::is_dump_dir_name(&db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }
    check_target(&req.container_name, &req.db_type, &req.user, &req.password)?;

    // Resolve and validate backup file path
    let filepath = database_backup::get_backup_path(&db_name, &filename)
        .map_err(|e| err(StatusCode::NOT_FOUND, &e))?;

    // If the file is encrypted, decrypt it first
    let restore_path = if filepath.ends_with(".enc") {
        let key = req.encryption_key.as_deref()
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Encryption key required for encrypted backup"))?;
        if key.is_empty() {
            return Err(err(StatusCode::BAD_REQUEST, "Encryption key required for encrypted backup"));
        }
        encryption::decrypt_backup(&filepath, key)
            .await
            .map_err(|e| err(decrypt_status(&e), &e))?
    } else {
        filepath.clone()
    };

    let result = match req.db_type.as_str() {
        "mysql" | "mariadb" => {
            database_backup::restore_mysql(
                &req.container_name, &db_name, &req.user, &req.password, &restore_path,
            ).await
        }
        "postgres" | "postgresql" => {
            database_backup::restore_postgres(
                &req.container_name, &db_name, &req.user, &req.password, &restore_path,
            ).await
        }
        "mongo" | "mongodb" => {
            database_backup::restore_mongo(
                &req.container_name, &db_name, &restore_path,
            ).await
        }
        _ => Err("Unsupported database type".to_string()),
    };

    // Clean up decrypted temp file if we created one
    if restore_path != filepath {
        std::fs::remove_file(&restore_path).ok();
    }

    // ⛔ 422, not 500, and the difference is the whole diagnosis. Everything that fails
    // here fails because of the FILE the caller named - a dump that is truncated, was
    // never gzipped, targets a different engine, or contains SQL the database rejects.
    // That is a caller-fixable answer, and the panel only preserves an agent's sentence
    // for 4xx (`error.rs`'s `agent_error`): a 5xx is replaced with "Operation failed.
    // Reference: {uuid}". Returning 500 here meant psql's "relation already exists" -
    // the one line that says what to do next - was minted into an incident id and
    // thrown away, on both this route's callers.
    result.map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "db_name": db_name,
        "filename": filename,
        "db_type": req.db_type,
    })))
}

/// GET /db-backups/{db_name}/{filename}/path - Get filesystem path for upload.
async fn get_path(
    Path((db_name, filename)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !database_backup::is_dump_dir_name(&db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }

    let path = database_backup::get_backup_path(&db_name, &filename)
        .map_err(|e| err(StatusCode::NOT_FOUND, &e))?;
    Ok(Json(serde_json::json!({ "path": path })))
}

/// DELETE /db-backups/{db_name} - drop a dump directory nothing owns any more.
///
/// Whether it is unowned is the PANEL's question: the name is unique only per
/// site, so the same directory can serve two live databases. This end answers
/// only for what it did.
async fn purge(Path(db_name): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    if !database_backup::is_dump_dir_name(&db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }
    let report = database_backup::purge_dir(&db_name)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({
        "removed": report.removed,
        "kept": report.kept,
        "dir_removed": report.dir_removed,
    })))
}

/// DELETE /db-backups/dump - the same door, for the one database name that
/// collides with this router's own static segment.
///
/// `dump` is a legal database name, so the static route has to carry the delete
/// verb or that one name answers 405. But a static path captures nothing while
/// `purge` asks for a path parameter, so registering `purge` there traded the
/// 405 for a 500: axum rejects the request with `MissingPathParams` before the
/// handler runs. This supplies the segment the URL cannot.
///
/// Delegating rather than re-implementing keeps the name validation on exactly
/// one path - there is a pin counting those call sites.
async fn purge_dump() -> Result<Json<serde_json::Value>, ApiErr> {
    purge(Path("dump".to_string())).await
}

pub fn router() -> Router<AppState> {
    Router::new()
        // ⚠ Both verbs on the STATIC path. A static segment wins the match outright,
        // so registering the purge only on the parameter path leaves `DELETE
        // /db-backups/dump` answering 405 - and `dump` is a legal database name.
        .route("/db-backups/dump", post(dump).delete(purge_dump))
        .route("/db-backups/{db_name}", delete(purge))
        .route("/db-backups/{db_name}/list", get(list))
        .route("/db-backups/{db_name}/{filename}", delete(remove))
        .route("/db-backups/{db_name}/{filename}/path", get(get_path))
        .route("/db-backups/{db_name}/restore/{filename}", post(restore))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_archive_or_passphrase_is_422_and_a_host_failure_500() {
        assert_eq!(
            decrypt_status("Backup integrity check failed - the file may be corrupted or tampered with"),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(decrypt_status("Decryption failed: bad decrypt"), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(decrypt_status("Not an encrypted backup (missing OpenSSL salt header)"), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(decrypt_status("Failed to run openssl: not found"), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The recorded sha256 of an encrypted dump is the `.enc` file's, not the
    /// plaintext's the dump function computed before the encryption.
    #[tokio::test]
    async fn an_encrypted_dump_is_described_by_the_hash_of_the_encrypted_file() {
        let dir = std::env::temp_dir().join(format!("dbb-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("wp-20261119-030000.sql.gz");
        let enc = dir.join("wp-20261119-030000.sql.gz.enc");
        std::fs::write(&plain, b"-- a dump that is long enough to be encrypted\nSELECT 1;\n").unwrap();
        let plain_sha = crate::services::backups::compute_file_sha256(&plain.to_string_lossy()).await.unwrap();
        encryption::encrypt_file(&plain, &enc, "a-test-passphrase").await.unwrap();
        let enc_sha = crate::services::backups::compute_file_sha256(&enc.to_string_lossy()).await.unwrap();

        let mut info = BackupInfo {
            filename: "wp-20261119-030000.sql.gz".into(),
            size_bytes: 1,
            sha256: Some(plain_sha.clone()),
            ..Default::default()
        };
        describe_encrypted(&mut info, &enc).await.unwrap();
        assert_eq!(info.filename, "wp-20261119-030000.sql.gz.enc");
        assert_eq!(info.size_bytes, std::fs::metadata(&enc).unwrap().len());
        assert_eq!(info.sha256.as_deref(), Some(enc_sha.as_str()));
        assert_ne!(enc_sha, plain_sha);

        // A file that cannot be read is an error, and the stale hash is not kept.
        let mut gone = BackupInfo { filename: "x.sql.gz".into(), sha256: Some(plain_sha), ..Default::default() };
        assert!(describe_encrypted(&mut gone, &dir.join("missing.enc")).await.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
