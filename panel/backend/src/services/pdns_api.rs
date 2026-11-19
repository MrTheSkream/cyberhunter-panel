//! Shared guard for every call the panel makes to the PowerDNS HTTP API.
//!
//! The stored `pdns_api_url` is just a host:port. When PowerDNS is stopped and
//! another service (an app container running nginx, say) holds that port, it
//! answers 200/201 to anything, and a plain `status().is_success()` check
//! believes it: phantom `dns_zones` rows, records reported as created that
//! exist nowhere. This module refuses those false successes in two ways:
//!
//! - [`verify_server`] asks `GET /api/v1/servers/localhost` and requires the
//!   JSON PowerDNS answers there (`daemon_type == "authoritative"`). A success
//!   is cached for [`VERIFY_TTL`] per (URL, key fingerprint) so it does not
//!   double every call.
//! - The `check_*` functions validate each operation's response strictly,
//!   from the status and body alone (pure, unit tested below): the exact
//!   status PowerDNS uses for that operation, plus the body shape when it has
//!   one.
//!
//! The API key is never logged nor put in a message: the cache keys on a
//! truncated SHA-256 of it.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Operator message when the URL answered, but not as PowerDNS.
pub const NOT_POWERDNS_MSG: &str = "The PowerDNS API URL did not answer as PowerDNS. Another service may hold its port. Reinstall PowerDNS or fix the API URL in Settings.";

/// How long a successful [`verify_server`] probe is trusted.
pub const VERIFY_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdnsApiError {
    /// Something answered at the URL, but not as PowerDNS would.
    NotPowerDns,
    /// The request did not complete (connection refused, timeout...).
    Transport(String),
    /// PowerDNS itself refused the request (a real error status, e.g. 422).
    Rejected { status: u16, body: String },
}

impl std::fmt::Display for PdnsApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PdnsApiError::NotPowerDns => f.write_str(NOT_POWERDNS_MSG),
            PdnsApiError::Transport(e) => write!(f, "PowerDNS API error: {e}"),
            PdnsApiError::Rejected { body, .. } => write!(f, "PowerDNS error: {body}"),
        }
    }
}

impl std::error::Error for PdnsApiError {}

/// Outcome of a zone creation that PowerDNS accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneCreated {
    Created,
    /// 409: the zone already exists in PowerDNS; the panel may still track it.
    AlreadyExists,
}

fn parse_json(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body).ok()
}

/// A status that is not the expected one: a success-family answer (or a
/// redirect) means something other than PowerDNS answered; anything else is a
/// real PowerDNS refusal, reported as before.
fn unexpected(status: u16, body: &str) -> PdnsApiError {
    if (200..400).contains(&status) {
        PdnsApiError::NotPowerDns
    } else {
        PdnsApiError::Rejected { status, body: body.to_string() }
    }
}

/// `GET /api/v1/servers/localhost`: 200 + `daemon_type == "authoritative"`.
/// 401/403 and 5xx are PowerDNS answers (wrong key, server error); a 404 on
/// this path, which PowerDNS always serves, means another service.
pub fn check_server_info(status: u16, body: &str) -> Result<(), PdnsApiError> {
    if status == 200 {
        let ok = parse_json(body)
            .map(|v| {
                v.get("type").and_then(|t| t.as_str()) == Some("Server")
                    && v.get("daemon_type").and_then(|t| t.as_str()) == Some("authoritative")
            })
            .unwrap_or(false);
        return if ok { Ok(()) } else { Err(PdnsApiError::NotPowerDns) };
    }
    if status == 404 {
        return Err(PdnsApiError::NotPowerDns);
    }
    Err(unexpected(status, body))
}

/// `POST /zones`: 201 + JSON whose `name` is the requested zone FQDN; 409
/// (zone already in PowerDNS) stays accepted.
pub fn check_create_zone(status: u16, body: &str, zone_fqdn: &str) -> Result<ZoneCreated, PdnsApiError> {
    match status {
        201 => {
            let name_ok = parse_json(body)
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|n| n.eq_ignore_ascii_case(zone_fqdn)))
                .unwrap_or(false);
            if name_ok { Ok(ZoneCreated::Created) } else { Err(PdnsApiError::NotPowerDns) }
        }
        409 => Ok(ZoneCreated::AlreadyExists),
        _ => Err(unexpected(status, body)),
    }
}

/// `PATCH /zones/{zone}` (rrsets): exactly 204, no body.
pub fn check_patch(status: u16, body: &str) -> Result<(), PdnsApiError> {
    if status == 204 { Ok(()) } else { Err(unexpected(status, body)) }
}

/// `DELETE /zones/{zone}`: 204; 404 (already absent) stays accepted.
pub fn check_delete_zone(status: u16, body: &str) -> Result<(), PdnsApiError> {
    if status == 204 || status == 404 { Ok(()) } else { Err(unexpected(status, body)) }
}

/// `GET /zones/{zone}`: 200 + JSON object with an `rrsets` array. Returns the
/// parsed zone.
pub fn check_get_zone(status: u16, body: &str) -> Result<serde_json::Value, PdnsApiError> {
    if status != 200 {
        return Err(unexpected(status, body));
    }
    match parse_json(body) {
        Some(v) if v.get("rrsets").map(|r| r.is_array()).unwrap_or(false) => Ok(v),
        _ => Err(PdnsApiError::NotPowerDns),
    }
}

/// `GET /zones`: 200 + JSON array. No caller lists zones from PowerDNS today
/// (the panel lists its own `dns_zones` rows); kept so a future caller gets
/// the strict check too.
#[allow(dead_code)]
pub fn check_list_zones(status: u16, body: &str) -> Result<Vec<serde_json::Value>, PdnsApiError> {
    if status != 200 {
        return Err(unexpected(status, body));
    }
    match parse_json(body) {
        Some(serde_json::Value::Array(a)) => Ok(a),
        _ => Err(PdnsApiError::NotPowerDns),
    }
}

/// Status and body of a response, for the `check_*` functions.
pub async fn read_response(resp: reqwest::Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

/// Non-reversible fingerprint of the key, for the cache only.
fn key_fingerprint(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(&digest[..8])
}

/// Whether a success recorded at `verified_at` is still trusted at `now`.
fn cache_fresh(verified_at: Instant, now: Instant) -> bool {
    now.checked_duration_since(verified_at)
        .map(|age| age < VERIFY_TTL)
        .unwrap_or(false)
}

type VerifyCache = Mutex<HashMap<(String, String), Instant>>;

fn verify_cache() -> &'static VerifyCache {
    static CACHE: OnceLock<VerifyCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_hit(url: &str, fp: &str, now: Instant) -> bool {
    let map = verify_cache().lock().unwrap_or_else(|p| p.into_inner());
    map.get(&(url.to_string(), fp.to_string()))
        .map(|at| cache_fresh(*at, now))
        .unwrap_or(false)
}

fn cache_store(url: &str, fp: &str, now: Instant) {
    let mut map = verify_cache().lock().unwrap_or_else(|p| p.into_inner());
    map.retain(|_, at| cache_fresh(*at, now));
    map.insert((url.to_string(), fp.to_string()), now);
}

/// Check that `url` is a PowerDNS authoritative server before talking to it.
/// Only successes are cached.
pub async fn verify_server(client: &reqwest::Client, url: &str, key: &str) -> Result<(), PdnsApiError> {
    let fp = key_fingerprint(key);
    if cache_hit(url, &fp, Instant::now()) {
        return Ok(());
    }
    let resp = client
        .get(format!("{url}/api/v1/servers/localhost"))
        .header("X-API-Key", key)
        .send()
        .await
        .map_err(|e| PdnsApiError::Transport(e.to_string()))?;
    let (status, body) = read_response(resp).await;
    check_server_info(status, &body)?;
    cache_store(url, &fp, Instant::now());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_JSON: &str = r#"{"type":"Server","id":"localhost","daemon_type":"authoritative","version":"4.8.3","url":"/api/v1/servers/localhost","config_url":"/api/v1/servers/localhost/config{/config_setting}","zones_url":"/api/v1/servers/localhost/zones{/zone}"}"#;
    const NGINX_HTML: &str = "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body></body></html>";

    #[test]
    fn server_info_accepts_powerdns() {
        assert_eq!(check_server_info(200, SERVER_JSON), Ok(()));
    }

    #[test]
    fn server_info_refuses_other_services() {
        assert_eq!(check_server_info(200, NGINX_HTML), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(200, r#"{"type":"Server","daemon_type":"recursor"}"#), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(200, r#"{"status":"ok"}"#), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(200, "[]"), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(204, ""), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(301, ""), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_server_info(404, "Not Found"), Err(PdnsApiError::NotPowerDns));
    }

    #[test]
    fn server_info_keeps_real_powerdns_errors() {
        assert!(matches!(check_server_info(401, "Unauthorized"), Err(PdnsApiError::Rejected { status: 401, .. })));
        assert!(matches!(check_server_info(500, "boom"), Err(PdnsApiError::Rejected { status: 500, .. })));
    }

    #[test]
    fn create_zone_accepts_powerdns() {
        let body = r#"{"id":"example.com.","name":"example.com.","kind":"Native","rrsets":[]}"#;
        assert_eq!(check_create_zone(201, body, "example.com."), Ok(ZoneCreated::Created));
        assert_eq!(check_create_zone(409, r#"{"error":"Conflict"}"#, "example.com."), Ok(ZoneCreated::AlreadyExists));
    }

    #[test]
    fn create_zone_refuses_false_successes() {
        assert_eq!(check_create_zone(201, "{}", "example.com."), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_create_zone(201, r#"{"name":"other.com."}"#, "example.com."), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_create_zone(201, NGINX_HTML, "example.com."), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_create_zone(200, NGINX_HTML, "example.com."), Err(PdnsApiError::NotPowerDns));
    }

    #[test]
    fn create_zone_keeps_real_errors() {
        assert!(matches!(
            check_create_zone(422, r#"{"error":"bad"}"#, "example.com."),
            Err(PdnsApiError::Rejected { status: 422, .. })
        ));
    }

    #[test]
    fn patch_requires_exactly_204() {
        assert_eq!(check_patch(204, ""), Ok(()));
        assert_eq!(check_patch(200, NGINX_HTML), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_patch(201, ""), Err(PdnsApiError::NotPowerDns));
        assert!(matches!(check_patch(422, "RRset invalid"), Err(PdnsApiError::Rejected { status: 422, .. })));
    }

    #[test]
    fn delete_zone_accepts_204_and_404_only() {
        assert_eq!(check_delete_zone(204, ""), Ok(()));
        assert_eq!(check_delete_zone(404, ""), Ok(()));
        assert_eq!(check_delete_zone(200, NGINX_HTML), Err(PdnsApiError::NotPowerDns));
        assert!(matches!(check_delete_zone(500, "x"), Err(PdnsApiError::Rejected { status: 500, .. })));
    }

    #[test]
    fn get_zone_requires_rrsets_array() {
        let zone = check_get_zone(200, r#"{"name":"example.com.","rrsets":[{"name":"example.com.","type":"A"}]}"#).unwrap();
        assert_eq!(zone["rrsets"].as_array().unwrap().len(), 1);
        assert_eq!(check_get_zone(200, NGINX_HTML), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_get_zone(200, r#"{"rrsets":"no"}"#), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_get_zone(204, ""), Err(PdnsApiError::NotPowerDns));
        assert!(matches!(check_get_zone(404, "Not Found"), Err(PdnsApiError::Rejected { status: 404, .. })));
    }

    #[test]
    fn list_zones_requires_array() {
        assert_eq!(check_list_zones(200, r#"[{"name":"a."}]"#).unwrap().len(), 1);
        assert_eq!(check_list_zones(200, "{}"), Err(PdnsApiError::NotPowerDns));
        assert_eq!(check_list_zones(200, NGINX_HTML), Err(PdnsApiError::NotPowerDns));
    }

    #[test]
    fn not_powerdns_message_is_the_operator_one() {
        let msg = PdnsApiError::NotPowerDns.to_string();
        assert_eq!(msg, NOT_POWERDNS_MSG);
        assert!(!msg.contains('\u{2014}'));
    }

    #[test]
    fn fingerprint_does_not_reveal_key() {
        let fp = key_fingerprint("super-secret-key");
        assert_eq!(fp.len(), 16);
        assert!(!fp.contains("super"));
        assert_ne!(fp, key_fingerprint("other-key"));
        assert_eq!(fp, key_fingerprint("super-secret-key"));
    }

    #[test]
    fn cache_expires_after_ttl() {
        let t0 = Instant::now();
        assert!(cache_fresh(t0, t0));
        assert!(cache_fresh(t0, t0 + Duration::from_secs(59)));
        assert!(!cache_fresh(t0, t0 + VERIFY_TTL));
        assert!(!cache_fresh(t0 + Duration::from_secs(1), t0));
    }

    #[test]
    fn cache_is_per_url_and_key() {
        let now = Instant::now();
        let url = "http://test-cache-unique.invalid:1";
        let fp = key_fingerprint("k1");
        assert!(!cache_hit(url, &fp, now));
        cache_store(url, &fp, now);
        assert!(cache_hit(url, &fp, now));
        assert!(!cache_hit(url, &key_fingerprint("k2"), now));
        assert!(!cache_hit("http://other.invalid:1", &fp, now));
        assert!(!cache_hit(url, &fp, now + VERIFY_TTL));
    }
}
