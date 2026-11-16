//! `POST /disk-usage` (feature 6, contract A-5).

use axum::{body::Bytes, http::StatusCode, routing::post, Json, Router};
use serde::Deserialize;

use super::{is_valid_domain, AppState};
use crate::services::disk_usage::{self, MAX_DOMAINS};

type Reply = (StatusCode, Json<serde_json::Value>);

fn bad(msg: String) -> Reply {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/disk-usage", post(measure))
}

#[derive(Deserialize)]
struct Body {
    domains: Vec<String>,
}

/// The validated domain list, or the 400 message (pure, tested).
fn validate(domains: Vec<String>) -> Result<Vec<String>, String> {
    if domains.len() > MAX_DOMAINS {
        return Err(format!("Too many domains (at most {MAX_DOMAINS})"));
    }
    // Echoed back unchanged in `results[].domain`, so the caller can match them.
    if let Some(d) = domains.iter().find(|d| !is_valid_domain(d)) {
        return Err(format!("Invalid domain: {d}"));
    }
    Ok(domains)
}

async fn measure(body: Bytes) -> Reply {
    let b: Body = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad(format!("Invalid request body: {e}")),
    };
    let domains = match validate(b.domains) {
        Ok(d) => d,
        Err(e) => return bad(e),
    };
    match disk_usage::measure(domains).await {
        Ok(results) => (
            StatusCode::OK,
            Json(serde_json::json!({ "results": results.iter().map(|u| u.to_json()).collect::<Vec<_>>() })),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert_eq!(validate(vec!["jeuxx.org".into()]), Ok(vec!["jeuxx.org".to_string()]));
        assert!(validate(vec![" jeuxx.org".into()]).is_err());
        assert!(validate(vec!["../etc".into()]).unwrap_err().starts_with("Invalid domain"));
        assert!(validate(vec!["a.tld/x".into()]).is_err());
        assert!(validate(vec!["x.tld".into(); MAX_DOMAINS]).is_ok());
        assert!(validate(vec!["x.tld".into(); MAX_DOMAINS + 1]).unwrap_err().starts_with("Too many"));
        assert_eq!(validate(vec![]), Ok(vec![]));
    }
}
