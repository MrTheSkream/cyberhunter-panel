//! Antivirus routes (feature 5, contract A-1 to A-7), plus the neutral
//! `GET /jobs/{job_id}` over `migration_jobs`.
//!
//! Errors are always `{ "error": "..." }` with 400/404/409/412/500: bodies are
//! parsed by hand so a malformed one answers JSON too, not axum's text.

use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use super::AppState;
use crate::services::clamav::{self, AvErr};
use crate::services::{av_scan, quarantine};

type Reply = (StatusCode, Json<serde_json::Value>);

fn fail(e: AvErr) -> Reply {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(serde_json::json!({ "error": e.msg })))
}

fn ok(v: serde_json::Value) -> Reply {
    (StatusCode::OK, Json(v))
}

fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, Reply> {
    serde_json::from_slice(body).map_err(|e| fail(AvErr::bad(format!("Invalid request body: {e}"))))
}

/// Blocking file work (hashing, moving) off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, AvErr> + Send + 'static) -> Result<T, AvErr> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(AvErr::internal("internal error")))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/antivirus/status", get(status))
        .route("/antivirus/install", post(install))
        .route("/antivirus/uninstall", post(uninstall))
        .route("/antivirus/mail", post(mail))
        .route("/antivirus/scan", post(scan))
        .route("/antivirus/quarantine", get(quarantine_list).post(quarantine_file))
        .route("/antivirus/restore", post(restore))
        .route("/antivirus/delete", post(delete_file))
        .route("/antivirus/quarantine/delete", post(quarantine_delete))
        .route("/jobs/{job_id}", get(job_status))
}

/// GET /antivirus/status (A-1)
async fn status() -> Reply {
    ok(clamav::status().await)
}

/// POST /antivirus/install (A-2)
async fn install() -> Reply {
    match clamav::start_install().await {
        Ok(id) => ok(serde_json::json!({ "job_id": id })),
        Err(e) => fail(e),
    }
}

/// POST /antivirus/uninstall (A-3)
async fn uninstall() -> Reply {
    match clamav::uninstall().await {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct MailBody {
    enable: bool,
}

/// POST /antivirus/mail (A-4)
async fn mail(body: Bytes) -> Reply {
    let b: MailBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match clamav::set_mail(b.enable).await {
        Ok(enabled) => ok(serde_json::json!({ "ok": true, "enabled": enabled })),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct ScanBody {
    domain: String,
}

/// POST /antivirus/scan (A-5)
async fn scan(body: Bytes) -> Reply {
    let b: ScanBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let domain = b.domain.trim().to_ascii_lowercase();
    match av_scan::start(&domain).await {
        Ok(id) => ok(serde_json::json!({ "job_id": id })),
        Err(e) => fail(e),
    }
}

/// GET /jobs/{job_id} (A-6): same JSON as `GET /migration/jobs/{job_id}`.
async fn job_status(Path(job_id): Path<String>) -> Reply {
    match crate::services::migration_jobs::get(&job_id) {
        Some(v) => ok(v),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "job not found", "code": "job_not_found" })),
        ),
    }
}

#[derive(Deserialize)]
struct FileBody {
    domain: String,
    path: String,
    #[serde(default)]
    signature: Option<String>,
}

/// POST /antivirus/quarantine (A-7)
async fn quarantine_file(body: Bytes) -> Reply {
    let b: FileBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let domain = b.domain.trim().to_ascii_lowercase();
    let signature = b.signature.map(|s| s.chars().filter(|c| !c.is_control()).take(256).collect::<String>());
    match blocking(move || quarantine::quarantine(&domain, &b.path, signature)).await {
        Ok(item) => ok(serde_json::json!({ "quarantine_id": item["quarantine_id"].clone(), "item": item })),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct IdBody {
    quarantine_id: String,
}

/// POST /antivirus/restore (A-7)
async fn restore(body: Bytes) -> Reply {
    let b: IdBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match blocking(move || quarantine::restore(&b.quarantine_id)).await {
        Ok(path) => ok(serde_json::json!({ "ok": true, "path": path })),
        Err(e) => fail(e),
    }
}

/// POST /antivirus/delete (A-7)
async fn delete_file(body: Bytes) -> Reply {
    let b: FileBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let domain = b.domain.trim().to_ascii_lowercase();
    match blocking(move || quarantine::delete(&domain, &b.path)).await {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => fail(e),
    }
}

/// POST /antivirus/quarantine/delete (A-7)
async fn quarantine_delete(body: Bytes) -> Reply {
    let b: IdBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match blocking(move || quarantine::purge(&b.quarantine_id)).await {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => fail(e),
    }
}

/// GET /antivirus/quarantine (A-7)
async fn quarantine_list() -> Reply {
    match blocking(|| Ok(quarantine::list())).await {
        Ok(items) => ok(serde_json::Value::Array(items)),
        Err(e) => fail(e),
    }
}
