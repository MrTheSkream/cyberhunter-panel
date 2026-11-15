//! `/localdb/*` routes: shared local MariaDB server (05-import-hestia W2-A).
//!
//! Every handler works as root through the socket; the SQL is built by
//! `services::local_mariadb` from validated identifiers only. No response, log
//! line or job report carries a password or a `mysql_native_password` hash.

use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use super::AppState;
use crate::services::local_mariadb as ldb;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

fn err_code(status: StatusCode, msg: &str, code: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg, "code": code })))
}

pub fn router() -> Router<AppState> {
    // Leftover `ch_tmp_%` accounts (agent killed mid-query) are swept once the
    // server answers; MariaDB may start after the agent, hence the retrying task.
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(ldb::startup_sweep());
    }
    Router::new()
        .route("/localdb/status", get(status))
        .route("/localdb/install", post(install))
        .route("/localdb/databases", post(create_database))
        .route("/localdb/databases/{name}/drop", post(drop_database))
        .route("/localdb/databases/{name}/password", post(set_password))
        .route("/localdb/query", post(query))
        .route("/localdb/config", post(set_config))
        .route("/localdb/hestia/import", post(hestia_import))
}

async fn require_running() -> Result<(), ApiErr> {
    if ldb::is_running().await {
        Ok(())
    } else {
        Err(err_code(
            StatusCode::CONFLICT,
            "The local MariaDB server is not installed or not running",
            "local_db_not_installed",
        ))
    }
}

/// GET /localdb/status
async fn status() -> Json<serde_json::Value> {
    Json(ldb::status().await)
}

/// POST /localdb/install (idempotent; the backend calls it with `post_long` 900 s).
async fn install() -> Result<Json<serde_json::Value>, ApiErr> {
    match ldb::install().await {
        Ok((version, notes)) => Ok(Json(serde_json::json!({
            "success": true,
            "message": if notes.is_empty() { "MariaDB is installed and running".to_string() } else { notes },
            "version": version,
        }))),
        Err(e) => Err(err(StatusCode::UNPROCESSABLE_ENTITY, &e)),
    }
}

#[derive(Deserialize)]
struct CreateReq {
    name: String,
    db_user: String,
    charset: Option<String>,
    password: Option<String>,
    password_hash: Option<String>,
}

/// POST /localdb/databases
async fn create_database(Json(b): Json<CreateReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    let cred = match (&b.password, &b.password_hash) {
        (Some(p), None) => ldb::Credential::Password(p),
        (None, Some(h)) => ldb::Credential::NativeHash(h),
        _ => return Err(err(StatusCode::BAD_REQUEST, "Give exactly one of password or password_hash")),
    };
    require_running().await?;
    match ldb::create_database(&b.name, &b.db_user, b.charset.as_deref(), cred).await {
        Ok(()) => {
            tracing::info!("local MariaDB: database {} created", b.name);
            Ok(Json(serde_json::json!({ "created_db": true, "created_user": true })))
        }
        Err(ldb::CreateError::Invalid(m)) => Err(err(StatusCode::BAD_REQUEST, &m)),
        Err(ldb::CreateError::Conflict(m)) => Err(err_code(StatusCode::CONFLICT, &m, "exists")),
        Err(ldb::CreateError::Failed(m)) => Err(err(StatusCode::UNPROCESSABLE_ENTITY, &m)),
    }
}

#[derive(Deserialize)]
struct DropReq {
    db_user: String,
    #[serde(default = "yes")]
    drop_user_if_unused: bool,
}

fn yes() -> bool {
    true
}

/// POST /localdb/databases/{name}/drop
async fn drop_database(Path(name): Path<String>, Json(b): Json<DropReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    if !ldb::is_valid_local_name(&name) || !ldb::is_valid_local_user(&b.db_user) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database or user name"));
    }
    require_running().await?;
    let (dropped_db, dropped_user) = ldb::drop_database(&name, &b.db_user, b.drop_user_if_unused)
        .await
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    tracing::info!("local MariaDB: database {name} dropped (user dropped: {dropped_user})");
    Ok(Json(serde_json::json!({ "success": true, "dropped_db": dropped_db, "dropped_user": dropped_user })))
}

#[derive(Deserialize)]
struct PasswordReq {
    db_user: String,
    new_password: String,
}

/// POST /localdb/databases/{name}/password
async fn set_password(Path(name): Path<String>, Json(b): Json<PasswordReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    if !ldb::is_valid_local_name(&name) || !ldb::is_valid_local_user(&b.db_user) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database or user name"));
    }
    require_running().await?;
    ldb::set_password(&name, &b.db_user, &b.new_password)
        .await
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Deserialize)]
struct QueryReq {
    database: String,
    sql: String,
}

/// POST /localdb/query (same answer shape as `POST /databases/query`).
async fn query(Json(b): Json<QueryReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    if b.sql.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Query is empty"));
    }
    if b.sql.len() > 10_000 {
        return Err(err(StatusCode::BAD_REQUEST, "Query too long (max 10KB)"));
    }
    if !ldb::is_valid_local_name(&b.database) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }
    require_running().await?;
    let r = ldb::query(b.database, b.sql).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    Ok(Json(serde_json::json!({
        "columns": r.columns,
        "rows": r.rows,
        "row_count": r.row_count,
        "execution_time_ms": r.execution_time_ms,
        "truncated": r.truncated,
    })))
}

#[derive(Deserialize)]
struct ConfigReq {
    sql_mode: Option<String>,
}

/// POST /localdb/config: `sql_mode` (null = MariaDB defaults), then restart.
async fn set_config(Json(b): Json<ConfigReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    if let Some(m) = &b.sql_mode {
        if !ldb::is_valid_sql_mode(m) {
            return Err(err(StatusCode::BAD_REQUEST, "sql_mode must match ^[A-Z0-9_,]*$"));
        }
    }
    ldb::set_sql_mode(b.sql_mode.as_deref())
        .await
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    tracing::info!("local MariaDB: sql_mode set to {:?}", b.sql_mode);
    Ok(Json(serde_json::json!({ "success": true, "sql_mode": b.sql_mode })))
}

#[derive(Deserialize)]
struct ImportReq {
    migration_id: String,
    db_name: String,
    #[serde(default)]
    replace: bool,
    /// Inventory `file`; used only when it is one of the two Hestia member names.
    file: Option<String>,
}

/// POST /localdb/hestia/import -> 202 `{job_id}`
async fn hestia_import(Json(b): Json<ImportReq>) -> Result<(StatusCode, Json<serde_json::Value>), ApiErr> {
    if !ldb::is_valid_local_name(&b.db_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid database name"));
    }
    crate::services::migration::staging_dir(&b.migration_id).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    require_running().await?;
    // W1 convention: job keys are `<migration_id>:<item>`, item = `db:<name>`.
    let key = format!("{}:db:{}", b.migration_id, b.db_name);
    let req = ldb::ImportRequest { migration_id: b.migration_id, db_name: b.db_name, replace: b.replace, file: b.file };
    let job_id = crate::services::migration_jobs::spawn("localdb_import", &key, move |job| ldb::hestia_import(req, job));
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "job_id": job_id }))))
}
