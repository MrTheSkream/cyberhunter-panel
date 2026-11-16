//! Web statistics routes (feature 7, contract A-1 to A-6).
//!
//! Errors are `{ "error": "..." }` with 400/404/409/412/500. Bodies are parsed
//! by hand so a malformed one answers JSON too, not axum's text.

use axum::{
    body::Bytes,
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use super::{is_valid_domain, AppState};
use crate::services::web_stats::{self, StatsErr};

type Reply = (StatusCode, Json<serde_json::Value>);

fn fail(e: StatsErr) -> Reply {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(serde_json::json!({ "error": e.msg })))
}

fn ok(v: serde_json::Value) -> Reply {
    (StatusCode::OK, Json(v))
}

fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, Reply> {
    serde_json::from_slice(body).map_err(|e| fail(StatsErr::bad(format!("Invalid request body: {e}"))))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/stats/status", get(status))
        .route("/stats/install", post(install))
        .route("/stats/uninstall", post(uninstall))
        .route("/stats/purge", post(purge))
        .route("/stats/run", post(run))
        .route("/stats/{domain}/report", get(report))
        .route("/stats/{domain}/state", get(state))
}

/// GET /stats/status (A-1)
async fn status() -> Reply {
    ok(web_stats::status().await)
}

/// POST /stats/install (A-2)
async fn install() -> Reply {
    match web_stats::install().await {
        Ok(warnings) => ok(serde_json::json!({ "ok": true, "warnings": warnings })),
        Err(e) => fail(e),
    }
}

/// POST /stats/uninstall (A-3)
async fn uninstall() -> Reply {
    match web_stats::uninstall().await {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => fail(e),
    }
}

/// POST /stats/purge (A-4)
async fn purge() -> Reply {
    match web_stats::purge().await {
        Ok(removed) => ok(serde_json::json!({ "ok": true, "removed": removed })),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct RunBody {
    domain: String,
}

/// POST /stats/run (A-5). A GoAccess failure is a 200 with `ok: false`.
async fn run(body: Bytes) -> Reply {
    let b: RunBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match web_stats::run(&b.domain).await {
        Ok(o) => ok(o.to_json()),
        Err(e) => fail(e),
    }
}

/// GET /stats/{domain}/report (A-6)
async fn report(Path(domain): Path<String>) -> Response {
    if !is_valid_domain(&domain) {
        return fail(StatsErr::bad("Invalid domain")).into_response();
    }
    let path = web_stats::domain_dir(std::path::Path::new(web_stats::STATS_ROOT), &domain).join("report.html");
    match tokio::fs::read(&path).await {
        Ok(html) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fail(StatsErr::not_found(web_stats::NO_REPORT_MSG)).into_response()
        }
        Err(e) => fail(StatsErr::internal(format!("Cannot read the report: {e}"))).into_response(),
    }
}

/// GET /stats/{domain}/state (A-6)
async fn state(Path(domain): Path<String>) -> Reply {
    if !is_valid_domain(&domain) {
        return fail(StatsErr::bad("Invalid domain"));
    }
    let dir = web_stats::domain_dir(std::path::Path::new(web_stats::STATS_ROOT), &domain);
    ok(state_json(&dir))
}

/// `state.json` as stored, or `{ "updated_at": null, "error": null }`.
fn state_json(dir: &std::path::Path) -> serde_json::Value {
    std::fs::read(dir.join("state.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({ "updated_at": null, "error": null }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_and_errors() {
        let b: RunBody = parse(&Bytes::from_static(br#"{"domain":"a.tld"}"#)).ok().unwrap();
        assert_eq!(b.domain, "a.tld");
        let (st, Json(v)) = parse::<RunBody>(&Bytes::from_static(b"{}")).err().unwrap();
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().starts_with("Invalid request body"));
        let (st, Json(v)) = fail(StatsErr::precondition(web_stats::NOT_INSTALLED_MSG));
        assert_eq!(st, StatusCode::PRECONDITION_FAILED);
        assert_eq!(v, serde_json::json!({"error": "Web statistics not installed"}));
        let (st, _) = fail(StatsErr::conflict(web_stats::RUN_BUSY_MSG));
        assert_eq!(st, StatusCode::CONFLICT);
    }

    #[test]
    fn state_defaults() {
        let d = std::env::temp_dir().join(format!("dp-wsr-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(state_json(&d), serde_json::json!({"updated_at": null, "error": null}));
        std::fs::write(d.join("state.json"), r#"{"updated_at":"2026-11-16T10:00:03Z","error":null,"duration_ms":4200}"#)
            .unwrap();
        assert_eq!(state_json(&d)["duration_ms"], 4200);
        let _ = std::fs::remove_dir_all(&d);
    }
}
