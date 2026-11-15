//! `/localdb/*` routes: shared local MariaDB server (05-import-hestia W2-A).
//!
//! STEP 0 SKELETON (owner: W2). Every route answers 501 until W2 replaces this
//! whole file with the real handlers.

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use super::{not_implemented, AppState};

pub fn router() -> Router<AppState> {
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

async fn status() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn install() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn create_database() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn drop_database() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn set_password() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn query() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn set_config() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}

async fn hestia_import() -> (StatusCode, Json<serde_json::Value>) {
    not_implemented()
}
