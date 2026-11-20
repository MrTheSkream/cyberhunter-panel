//! CVE scanner routes (conception 13, lot 1). Long work answers `{job_id}` at
//! once and is polled through `GET /jobs/{job_id}`; the result is the job's
//! `report`.
//!
//! Errors are `{ "error": "..." }` with 400/500: bodies are parsed by hand so
//! a malformed one answers JSON too, not axum's text.

use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};

use super::AppState;
use crate::services::vuln_scanner;

type Reply = (StatusCode, Json<serde_json::Value>);

fn ok(v: serde_json::Value) -> Reply {
    (StatusCode::OK, Json(v))
}

fn err(status: StatusCode, msg: impl Into<String>) -> Reply {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn job(id: String) -> Reply {
    ok(serde_json::json!({ "job_id": id }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vulns/status", get(status))
        .route("/vulns/install", post(install))
        .route("/vulns/db-update", post(db_update))
        .route("/vulns/targets", get(targets))
        .route("/vulns/inventory", post(inventory))
        .route("/vulns/match", post(match_targets))
        .route("/vulns/sbom/{target_id}", delete(delete_sbom))
}

/// GET /vulns/status
async fn status() -> Reply {
    ok(vuln_scanner::status().await)
}

/// POST /vulns/install: install or upgrade grype and syft, then update the database.
async fn install() -> Reply {
    job(vuln_scanner::start_install())
}

/// POST /vulns/db-update
async fn db_update() -> Reply {
    job(vuln_scanner::start_db_update())
}

/// GET /vulns/targets: images of the managed containers and the host system.
async fn targets() -> Reply {
    match vuln_scanner::discover_targets().await {
        Ok(v) => ok(v),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// POST /vulns/inventory
async fn inventory(body: Bytes) -> Reply {
    match vuln_scanner::parse_inventory_request(&body) {
        Ok(targets) => job(vuln_scanner::start_inventory(targets)),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

/// POST /vulns/match
async fn match_targets(body: Bytes) -> Reply {
    match vuln_scanner::parse_match_request(&body) {
        Ok(ids) => job(vuln_scanner::start_match(ids)),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

/// DELETE /vulns/sbom/{target_id}: the SBOM of a target that is gone.
async fn delete_sbom(Path(target_id): Path<String>) -> Reply {
    let id = match vuln_scanner::validate_target_id(&target_id) {
        Ok(id) => id,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    match vuln_scanner::delete_sbom(&id) {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_json_with_the_status() {
        let (st, Json(v)) = err(StatusCode::BAD_REQUEST, "Invalid target_id: x");
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(v, serde_json::json!({ "error": "Invalid target_id: x" }));
        let (st, Json(v)) = job("abc".into());
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v, serde_json::json!({ "job_id": "abc" }));
    }

    #[tokio::test]
    async fn bad_bodies_answer_400_json() {
        let (st, Json(v)) = inventory(Bytes::from_static(b"{nope")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().starts_with("Invalid request body"));
        let (st, _) = match_targets(Bytes::from_static(br#"{"target_ids":["../x"]}"#)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = delete_sbom(Path("../../etc/passwd".to_string())).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
}
