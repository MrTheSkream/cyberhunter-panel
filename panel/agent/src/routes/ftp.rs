//! FTP server routes (feature 6, contract A-1 to A-4).
//!
//! Errors are `{ "error": "..." }` with 400/409/412/500. Bodies are parsed by
//! hand so a malformed one answers JSON too, not axum's text.

use axum::{
    body::Bytes,
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;

use super::AppState;
use crate::services::ftp::{self, FtpErr};

type Reply = (StatusCode, Json<serde_json::Value>);

fn fail(e: FtpErr) -> Reply {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(serde_json::json!({ "error": e.msg })))
}

fn ok(v: serde_json::Value) -> Reply {
    (StatusCode::OK, Json(v))
}

fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, Reply> {
    serde_json::from_slice(body).map_err(|e| fail(FtpErr::bad(format!("Invalid request body: {e}"))))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ftp/status", get(status))
        .route("/ftp/install", post(install))
        .route("/ftp/uninstall", post(uninstall))
        .route("/ftp/users", put(set_users))
}

/// GET /ftp/status (A-1)
async fn status() -> Reply {
    ok(ftp::status().await)
}

#[derive(Deserialize)]
struct InstallBody {
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    pasv_address: Option<String>,
}

/// POST /ftp/install (A-2)
async fn install(body: Bytes) -> Reply {
    // An empty body is a repair with no account allowed yet.
    let b: InstallBody = if body.iter().all(u8::is_ascii_whitespace) {
        InstallBody { users: Vec::new(), pasv_address: None }
    } else {
        match parse(&body) {
            Ok(b) => b,
            Err(r) => return r,
        }
    };
    match ftp::install(&b.users, b.pasv_address.as_deref()).await {
        Ok(warnings) => ok(serde_json::json!({ "ok": true, "warnings": warnings })),
        Err(e) => fail(e),
    }
}

/// POST /ftp/uninstall (A-3)
async fn uninstall() -> Reply {
    match ftp::uninstall().await {
        Ok(()) => ok(serde_json::json!({ "ok": true })),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct UsersBody {
    users: Vec<String>,
}

/// PUT /ftp/users (A-4)
async fn set_users(body: Bytes) -> Reply {
    let b: UsersBody = match parse(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match ftp::set_users(&b.users).await {
        Ok((written, kicked)) => ok(serde_json::json!({ "ok": true, "written": written, "kicked": kicked })),
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies() {
        let b: InstallBody = parse(&Bytes::from_static(br#"{"users":["sftp30001"],"pasv_address":null}"#)).ok().unwrap();
        assert_eq!(b.users, vec!["sftp30001"]);
        assert!(b.pasv_address.is_none());
        let b: InstallBody = parse(&Bytes::from_static(b"{}")).ok().unwrap();
        assert!(b.users.is_empty());
        let (st, Json(v)) = parse::<UsersBody>(&Bytes::from_static(b"{")).err().unwrap();
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().starts_with("Invalid request body"));
        let (st, Json(v)) = fail(FtpErr::precondition(ftp::NOT_INSTALLED_MSG));
        assert_eq!(st, StatusCode::PRECONDITION_FAILED);
        assert_eq!(v, serde_json::json!({"error": "FTP server not installed"}));
    }
}
