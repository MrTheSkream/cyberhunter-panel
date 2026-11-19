use crate::safe_cmd::safe_command;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser};
use crate::error::{ApiError, err, internal_error, require_admin, upstream_error};
use crate::services::activity;
use crate::services::pdns_api::{self, PdnsApiError};
use crate::AppState;

const CF_API: &str = "https://api.cloudflare.com/client/v4";

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct DnsZone {
    pub id: Uuid,
    pub user_id: Uuid,
    pub domain: String,
    pub provider: String,
    pub cf_zone_id: Option<String>,
    #[serde(skip_serializing)]
    pub cf_api_token: Option<String>,
    #[serde(skip_serializing)]
    pub cf_api_email: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
pub struct CreateZoneRequest {
    pub domain: String,
    pub provider: Option<String>, // "cloudflare" (default) or "powerdns"
    pub cf_zone_id: Option<String>,
    pub cf_api_token: Option<String>,
    pub cf_api_email: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct CreateRecordRequest {
    #[serde(rename = "type")]
    pub rtype: String,
    pub name: String,
    pub content: String,
    pub ttl: Option<u32>,
    pub proxied: Option<bool>,
    pub priority: Option<u16>,
}

#[derive(serde::Deserialize)]
pub struct UpdateRecordRequest {
    #[serde(rename = "type")]
    pub rtype: String,
    pub name: String,
    pub content: String,
    pub ttl: Option<u32>,
    pub proxied: Option<bool>,
    pub priority: Option<u16>,
}

/// Helper: load a zone by id. DNS management is admin-only (every handler calls
/// `require_admin`), so any admin may manage any zone - we no longer scope by
/// `user_id` (that scoping made the admin-gated read endpoints unusable on a zone
/// created by a different admin).
async fn get_zone(state: &AppState, zone_id: Uuid) -> Result<DnsZone, ApiError> {
    sqlx::query_as::<_, DnsZone>(
        "SELECT * FROM dns_zones WHERE id = $1",
    )
    .bind(zone_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("unknown", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "DNS zone not found"))
}

// ── Cloudflare helpers ──────────────────────────────────────────────────

fn cf_client(token: &str, email: Option<&str>) -> Result<(reqwest::Client, reqwest::header::HeaderMap), ApiError> {
    let client = reqwest::Client::new();
    let mut headers = crate::helpers::cf_headers(token, email);
    if headers.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid Cloudflare credentials"));
    }
    headers.insert(
        "Content-Type",
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    Ok((client, headers))
}

// ── PowerDNS helpers ────────────────────────────────────────────────────

/// Get PowerDNS settings from DB.
async fn pdns_settings(state: &AppState) -> Result<(String, String), ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM settings WHERE key IN ('pdns_api_url', 'pdns_api_key')",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("unknown", e))?;

    let mut url = String::new();
    let mut key_enc = String::new();
    for (k, v) in rows {
        match k.as_str() {
            "pdns_api_url" => url = v,
            "pdns_api_key" => key_enc = v,
            _ => {}
        }
    }

    if url.is_empty() || key_enc.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "PowerDNS not configured. Set API URL and API Key in Settings.",
        ));
    }

    // Decrypt the API key (with legacy plaintext fallback)
    let key = crate::services::secrets_crypto::decrypt_credential_or_legacy(&key_enc, &state.config.jwt_secret);

    Ok((url, key))
}

/// Build reqwest client for PowerDNS API.
fn pdns_client(api_key: &str) -> Result<(reqwest::Client, reqwest::header::HeaderMap), ApiError> {
    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-API-Key",
        reqwest::header::HeaderValue::from_str(api_key)
            .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid PowerDNS API key"))?,
    );
    headers.insert(
        "Content-Type",
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    Ok((client, headers))
}

/// Settings + client, then check the URL really is PowerDNS
/// ([`pdns_api::verify_server`], cached 60 s) before the first call.
async fn pdns_connect(
    state: &AppState,
) -> Result<(String, reqwest::Client, reqwest::header::HeaderMap), ApiError> {
    let (pdns_url, pdns_key) = pdns_settings(state).await?;
    let (client, headers) = pdns_client(&pdns_key)?;
    pdns_api::verify_server(&client, &pdns_url, &pdns_key)
        .await
        .map_err(|e| pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed"))?;
    Ok((pdns_url, client, headers))
}

/// Map a [`PdnsApiError`] to the route's answer. Something other than
/// PowerDNS answering is always a 502 with the operator message; a real
/// PowerDNS refusal keeps each handler's previous status and message.
fn pdns_error(e: PdnsApiError, rejected_status: StatusCode, rejected_msg: &str) -> ApiError {
    match e {
        PdnsApiError::NotPowerDns => {
            tracing::warn!("PowerDNS API URL answered, but not as PowerDNS");
            err(StatusCode::BAD_GATEWAY, pdns_api::NOT_POWERDNS_MSG)
        }
        PdnsApiError::Transport(msg) => upstream_error("PowerDNS API", msg),
        PdnsApiError::Rejected { status, body } => {
            tracing::warn!("PowerDNS error ({status}): {body}");
            err(rejected_status, rejected_msg)
        }
    }
}

/// Zone read before a PATCH. A real PowerDNS error leaves the merge base
/// empty, as before; an answer that is not PowerDNS's is refused.
async fn pdns_zone_or_empty(resp: reqwest::Response) -> Result<serde_json::Value, ApiError> {
    let (status, body_text) = pdns_api::read_response(resp).await;
    match pdns_api::check_get_zone(status, &body_text) {
        Ok(zone) => Ok(zone),
        Err(PdnsApiError::Rejected { .. }) => Ok(serde_json::Value::Null),
        Err(e) => Err(pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed")),
    }
}

/// PATCH of rrsets: exactly 204. A real refusal stays a 422 as before.
async fn pdns_patch_result(resp: reqwest::Response) -> Result<(), ApiError> {
    let (status, body_text) = pdns_api::read_response(resp).await;
    pdns_api::check_patch(status, &body_text)
        .map_err(|e| pdns_error(e, StatusCode::UNPROCESSABLE_ENTITY, "PowerDNS rejected the record"))
}

/// Ensure domain ends with a dot (FQDN) for PowerDNS.
fn fqdn(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    }
}

/// Strip trailing dot from FQDN for display.
fn strip_dot(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

/// A DNS name/domain is safe to pass as a POSITIONAL `dig` argument only if dig cannot
/// parse it as an option: non-empty, no leading '-'/'+', and a conservative charset.
/// `allow_underscore` covers query names like `_dmarc` / `_acme-challenge`.
pub(crate) fn is_safe_dig_arg(s: &str, allow_underscore: bool) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.starts_with('+')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || (allow_underscore && c == '_')
        })
}

/// Create a synthetic record ID for PowerDNS records (name|type|content).
fn pdns_record_id(name: &str, rtype: &str, content: &str) -> String {
    // URL-safe: hex-encode the composite key
    hex::encode(format!("{}\0{}\0{}", name, rtype, content))
}

/// Parse a synthetic PowerDNS record ID back to (name, type, content).
fn pdns_parse_record_id(id: &str) -> Result<(String, String, String), ApiError> {
    let bytes = hex::decode(id).map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid record ID"))?;
    let s = String::from_utf8(bytes).map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid record ID"))?;
    let parts: Vec<&str> = s.splitn(3, '\0').collect();
    if parts.len() != 3 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid record ID"));
    }
    Ok((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()))
}

/// Flatten PowerDNS rrsets into individual records matching the Cloudflare format.
fn pdns_flatten_records(rrsets: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    for rrset in rrsets {
        let name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let ttl = rrset.get("ttl").and_then(|v| v.as_u64()).unwrap_or(3600);

        // Skip SOA and internal records
        if rtype == "SOA" {
            continue;
        }

        let recs = rrset.get("records").and_then(|v| v.as_array());
        if let Some(recs) = recs {
            for rec in recs {
                let content = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let disabled = rec.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false);
                if disabled {
                    continue;
                }

                // Extract priority from MX/SRV content (PowerDNS includes it in content)
                let (priority, clean_content) = if rtype == "MX" {
                    let parts: Vec<&str> = content.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        (parts[0].parse::<u16>().ok(), parts[1].to_string())
                    } else {
                        (None, content.to_string())
                    }
                } else {
                    (None, content.to_string())
                };

                records.push(serde_json::json!({
                    "id": pdns_record_id(name, rtype, content),
                    "type": rtype,
                    "name": strip_dot(name),
                    "content": strip_dot(&clean_content),
                    "ttl": ttl,
                    "priority": priority,
                }));
            }
        }
    }
    records
}

// ── Route handlers ──────────────────────────────────────────────────────

/// GET /api/dns/zones - List DNS zones.
pub async fn list_zones(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    require_admin(&claims.role)?;
    let zones: Vec<DnsZone> = sqlx::query_as(
        "SELECT * FROM dns_zones ORDER BY domain LIMIT 500",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list zones", e))?;

    let result: Vec<serde_json::Value> = zones
        .iter()
        .map(|z| {
            serde_json::json!({
                "id": z.id,
                "domain": z.domain,
                "provider": z.provider,
                "cf_zone_id": z.cf_zone_id,
                "created_at": z.created_at,
            })
        })
        .collect();

    Ok(Json(result))
}

/// POST /api/dns/zones - Add a DNS zone.
pub async fn create_zone(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(body): Json<CreateZoneRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require_admin(&claims.role)?;
    let provider = body.provider.as_deref().unwrap_or("cloudflare");

    let domain = body.domain.trim();
    if domain.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Domain is required"));
    }
    if !crate::routes::is_valid_domain(domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain name"));
    }

    match provider {
        "cloudflare" => {
            let cf_zone_id = body.cf_zone_id.as_deref().unwrap_or("").trim();
            let cf_api_token = body.cf_api_token.as_deref().unwrap_or("").trim();
            if cf_zone_id.is_empty() || cf_api_token.is_empty() {
                return Err(err(StatusCode::BAD_REQUEST, "Cloudflare Zone ID and API token are required"));
            }
            // CF zone IDs are 32-char lowercase hex; validate to keep untrusted input
            // out of the Cloudflare API URL path.
            if cf_zone_id.len() != 32 || !cf_zone_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid Cloudflare Zone ID"));
            }

            // Validate CF credentials
            let (client, headers) = cf_client(cf_api_token, body.cf_api_email.as_deref())?;
            let resp = client
                .get(&format!("{CF_API}/zones/{cf_zone_id}"))
                .headers(headers)
                .send()
                .await
                .map_err(|e| upstream_error("Cloudflare API", e))?;

            let cf_resp: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| upstream_error("Cloudflare response", e))?;

            if !cf_resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let errors = cf_resp.get("errors").cloned().unwrap_or_default();
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    &format!("Cloudflare rejected credentials: {errors}"),
                ));
            }

            // Encrypt the Cloudflare API token at rest (mirrors the pdns_api_key /
            // smtp_password pattern). Read paths decrypt via `helpers::cf_headers`.
            let cf_token_enc = crate::services::secrets_crypto::encrypt_credential(
                cf_api_token, &state.config.jwt_secret,
            ).map_err(|e| internal_error("encrypt cf token", e))?;
            let zone: DnsZone = sqlx::query_as(
                "INSERT INTO dns_zones (user_id, domain, provider, cf_zone_id, cf_api_token, cf_api_email) \
                 VALUES ($1, $2, 'cloudflare', $3, $4, $5) RETURNING *",
            )
            .bind(claims.sub)
            .bind(domain)
            .bind(cf_zone_id)
            .bind(&cf_token_enc)
            .bind(body.cf_api_email.as_deref().map(|s| s.trim()))
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate") {
                    err(StatusCode::CONFLICT, "Zone already exists")
                } else {
                    internal_error("create zone", e)
                }
            })?;

            tracing::info!("DNS zone added (cloudflare): {} by {}", zone.domain, claims.email);
            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.zone.create",
                Some("dns"), Some(&zone.domain), None, None, claims.key_id,
            ).await;

            Ok((StatusCode::CREATED, Json(serde_json::json!({
                "id": zone.id,
                "domain": zone.domain,
                "provider": zone.provider,
                "cf_zone_id": zone.cf_zone_id,
                "created_at": zone.created_at,
            }))))
        }
        "powerdns" => {
            // Checked before the INSERT below: a URL that does not answer as
            // PowerDNS must not leave a phantom `dns_zones` row.
            let (pdns_url, client, headers) = pdns_connect(&state).await?;
            let zone_fqdn = fqdn(domain);

            // Create zone in PowerDNS
            let pdns_body = serde_json::json!({
                "name": zone_fqdn,
                "kind": "Native",
                "nameservers": [],
                "soa_edit_api": "DEFAULT",
            });

            let resp = client
                .post(&format!("{pdns_url}/api/v1/servers/localhost/zones"))
                .headers(headers.clone())
                .json(&pdns_body)
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            // 201 with our zone's name = created; 409 = zone already exists in
            // PowerDNS, we can still track it. Any other "success" is refused.
            let (status, body_text) = pdns_api::read_response(resp).await;
            let created = pdns_api::check_create_zone(status, &body_text, &zone_fqdn)
                .map_err(|e| pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed"))?;

            // A 409 carries no zone to check, so read the zone back: an impostor
            // answering 409 must not get a `dns_zones` row either.
            if created == pdns_api::ZoneCreated::AlreadyExists {
                let resp = client
                    .get(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                    .headers(headers)
                    .send()
                    .await
                    .map_err(|e| upstream_error("PowerDNS API", e))?;
                let (status, body_text) = pdns_api::read_response(resp).await;
                pdns_api::check_get_zone(status, &body_text)
                    .map_err(|e| pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed"))?;
            }

            let zone: DnsZone = sqlx::query_as(
                "INSERT INTO dns_zones (user_id, domain, provider) \
                 VALUES ($1, $2, 'powerdns') RETURNING *",
            )
            .bind(claims.sub)
            .bind(domain)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate") {
                    err(StatusCode::CONFLICT, "Zone already exists")
                } else {
                    internal_error("create zone", e)
                }
            })?;

            tracing::info!("DNS zone added (powerdns): {} by {}", zone.domain, claims.email);
            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.zone.create",
                Some("dns"), Some(&zone.domain), Some("powerdns"), None, claims.key_id,
            ).await;

            Ok((StatusCode::CREATED, Json(serde_json::json!({
                "id": zone.id,
                "domain": zone.domain,
                "provider": "powerdns",
                "created_at": zone.created_at,
            }))))
        }
        _ => Err(err(StatusCode::BAD_REQUEST, "Unsupported provider. Use 'cloudflare' or 'powerdns'.")),
    }
}

/// DELETE /api/dns/zones/{id} - Remove a DNS zone.
pub async fn delete_zone(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    // If PowerDNS, delete the zone from the authoritative server FIRST and fail closed:
    // only drop our tracking row once the zone is actually gone, so a transient PowerDNS
    // error can't orphan an authoritative zone (panel says deleted, server still answers).
    if zone.provider == "powerdns" {
        let (pdns_url, client, headers) = pdns_connect(&state).await?;
        let zone_fqdn = fqdn(&zone.domain);
        let resp = client
            .delete(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
            .headers(headers)
            .send()
            .await
            .map_err(|e| upstream_error("PowerDNS delete zone", e))?;
        // 204 = deleted; 404 = already absent - both are acceptable end states.
        let (st, body_text) = pdns_api::read_response(resp).await;
        pdns_api::check_delete_zone(st, &body_text).map_err(|e| {
            tracing::warn!("PowerDNS delete-zone refused ({})", zone.domain);
            pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed; zone not deleted")
        })?;
    }

    sqlx::query("DELETE FROM dns_zones WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("delete zone", e))?;

    tracing::info!("DNS zone removed: {}", zone.domain);

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/dns/zones/{id}/records - List DNS records.
pub async fn list_records(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    match zone.provider.as_str() {
        "cloudflare" => {
            let token = zone.cf_api_token.as_deref().unwrap_or("");
            let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

            let resp = client
                .get(&format!(
                    "{CF_API}/zones/{}/dns_records?per_page=100&order=type",
                    zone.cf_zone_id.as_deref().unwrap_or("")
                ))
                .headers(headers)
                .send()
                .await
                .map_err(|e| upstream_error("Cloudflare API", e))?;

            let cf_resp: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| upstream_error("Cloudflare response", e))?;

            if !cf_resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err(err(StatusCode::BAD_GATEWAY, "Failed to fetch DNS records from Cloudflare"));
            }

            let records = cf_resp.get("result").cloned().unwrap_or(serde_json::json!([]));
            Ok(Json(serde_json::json!({
                "records": records,
                "domain": zone.domain,
                "provider": "cloudflare",
            })))
        }
        "powerdns" => {
            let (pdns_url, client, headers) = pdns_connect(&state).await?;
            let zone_fqdn = fqdn(&zone.domain);

            let resp = client
                .get(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers)
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            let (status, body_text) = pdns_api::read_response(resp).await;
            let pdns_resp = pdns_api::check_get_zone(status, &body_text)
                .map_err(|e| pdns_error(e, StatusCode::BAD_GATEWAY, "PowerDNS request failed"))?;

            let rrsets = pdns_resp.get("rrsets").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let records = pdns_flatten_records(&rrsets);

            Ok(Json(serde_json::json!({
                "records": records,
                "domain": zone.domain,
                "provider": "powerdns",
            })))
        }
        _ => Err(err(StatusCode::BAD_REQUEST, "Unknown DNS provider")),
    }
}

/// POST /api/dns/zones/{id}/records - Create a DNS record.
pub async fn create_record(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateRecordRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    let allowed_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"];
    if !allowed_types.contains(&body.rtype.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, &format!("Unsupported record type: {}", body.rtype)));
    }

    match zone.provider.as_str() {
        "cloudflare" => {
            let token = zone.cf_api_token.as_deref().unwrap_or("");
            let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

            let mut cf_body = serde_json::json!({
                "type": body.rtype,
                "name": body.name,
                "content": body.content,
                "ttl": body.ttl.unwrap_or(1),
            });

            if ["A", "AAAA", "CNAME"].contains(&body.rtype.as_str()) {
                cf_body["proxied"] = serde_json::json!(body.proxied.unwrap_or(false));
            }
            if body.rtype == "MX" {
                cf_body["priority"] = serde_json::json!(body.priority.unwrap_or(10));
            }

            let resp = client
                .post(&format!("{CF_API}/zones/{}/dns_records", zone.cf_zone_id.as_deref().unwrap_or("")))
                .headers(headers)
                .json(&cf_body)
                .send()
                .await
                .map_err(|e| upstream_error("Cloudflare API", e))?;

            let cf_resp: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| upstream_error("Cloudflare response", e))?;

            if !cf_resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let errors = cf_resp.get("errors").cloned().unwrap_or_default();
                return Err(err(StatusCode::UNPROCESSABLE_ENTITY, &format!("Cloudflare error: {errors}")));
            }

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.create",
                Some("dns"), Some(&zone.domain), Some(&format!("{} {}", body.rtype, body.name)), None, claims.key_id,
            ).await;

            Ok((StatusCode::CREATED, Json(cf_resp.get("result").cloned().unwrap_or_default())))
        }
        "powerdns" => {
            let (pdns_url, client, headers) = pdns_connect(&state).await?;
            let zone_fqdn = fqdn(&zone.domain);
            let ttl = body.ttl.unwrap_or(3600);

            // Build the record name as FQDN
            let rec_name = if body.name == "@" || body.name == zone.domain {
                zone_fqdn.clone()
            } else if body.name.ends_with(&zone.domain) {
                fqdn(&body.name)
            } else {
                fqdn(&format!("{}.{}", body.name, zone.domain))
            };

            // PowerDNS includes priority in content for MX
            let content = if body.rtype == "MX" {
                format!("{} {}", body.priority.unwrap_or(10), fqdn(&body.content))
            } else if body.rtype == "CNAME" || body.rtype == "NS" {
                fqdn(&body.content)
            } else {
                body.content.clone()
            };

            // First, get existing records for this name+type to merge
            let get_resp = client
                .get(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers.clone())
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            let mut existing_records: Vec<serde_json::Value> = Vec::new();
            let zone_data = pdns_zone_or_empty(get_resp).await?;
            if let Some(rrsets) = zone_data.get("rrsets").and_then(|v| v.as_array()) {
                for rrset in rrsets {
                    let rr_name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let rr_type = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if rr_name == rec_name && rr_type == body.rtype {
                        if let Some(recs) = rrset.get("records").and_then(|v| v.as_array()) {
                            existing_records = recs.clone();
                        }
                        break;
                    }
                }
            }

            // Add the new record
            existing_records.push(serde_json::json!({
                "content": content,
                "disabled": false,
            }));

            let patch_body = serde_json::json!({
                "rrsets": [{
                    "name": rec_name,
                    "type": body.rtype,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": existing_records,
                }]
            });

            let resp = client
                .patch(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers)
                .json(&patch_body)
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            pdns_patch_result(resp).await?;

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.create",
                Some("dns"), Some(&zone.domain), Some(&format!("{} {}", body.rtype, body.name)), None, claims.key_id,
            ).await;

            Ok((StatusCode::CREATED, Json(serde_json::json!({
                "id": pdns_record_id(&rec_name, &body.rtype, &content),
                "type": body.rtype,
                "name": strip_dot(&rec_name),
                "content": strip_dot(&body.content),
                "ttl": ttl,
            }))))
        }
        _ => Err(err(StatusCode::BAD_REQUEST, "Unknown DNS provider")),
    }
}

/// PUT /api/dns/zones/{id}/records/{record_id} - Update a DNS record.
pub async fn update_record(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((id, record_id)): Path<(Uuid, String)>,
    Json(body): Json<UpdateRecordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    if record_id.is_empty() || record_id.len() > 256 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid record ID"));
    }

    match zone.provider.as_str() {
        "cloudflare" => {
            // CF record IDs are 32-char lowercase hex, same as cf_zone_id (line ~290).
            // record_id is interpolated unescaped into the outbound URL below - without
            // this check a "../../../zones/OTHER/dns_records/RECID"-shaped id (percent-
            // encoded to survive the reverse proxy) reroutes the request, carrying this
            // zone's own decrypted token, to an arbitrary Cloudflare API path.
            if record_id.len() != 32 || !record_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid record ID"));
            }
            let token = zone.cf_api_token.as_deref().unwrap_or("");
            let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

            let mut cf_body = serde_json::json!({
                "type": body.rtype,
                "name": body.name,
                "content": body.content,
                "ttl": body.ttl.unwrap_or(1),
            });

            if ["A", "AAAA", "CNAME"].contains(&body.rtype.as_str()) {
                cf_body["proxied"] = serde_json::json!(body.proxied.unwrap_or(false));
            }
            if body.rtype == "MX" {
                cf_body["priority"] = serde_json::json!(body.priority.unwrap_or(10));
            }

            let resp = client
                .put(&format!(
                    "{CF_API}/zones/{}/dns_records/{record_id}",
                    zone.cf_zone_id.as_deref().unwrap_or("")
                ))
                .headers(headers)
                .json(&cf_body)
                .send()
                .await
                .map_err(|e| upstream_error("Cloudflare API", e))?;

            let cf_resp: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| upstream_error("Cloudflare response", e))?;

            if !cf_resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let errors = cf_resp.get("errors").cloned().unwrap_or_default();
                return Err(err(StatusCode::UNPROCESSABLE_ENTITY, &format!("Cloudflare error: {errors}")));
            }

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.update",
                Some("dns"), Some(&zone.domain), Some(&format!("{} {}", body.rtype, body.name)), None, claims.key_id,
            ).await;

            Ok(Json(cf_resp.get("result").cloned().unwrap_or_default()))
        }
        "powerdns" => {
            let (pdns_url, client, headers) = pdns_connect(&state).await?;
            let zone_fqdn = fqdn(&zone.domain);

            // Parse the old record from the ID
            let (old_name, old_type, old_content) = pdns_parse_record_id(&record_id)?;
            let ttl = body.ttl.unwrap_or(3600);

            // Build new record name
            let new_name = if body.name == "@" || body.name == zone.domain {
                zone_fqdn.clone()
            } else if body.name.ends_with(&zone.domain) {
                fqdn(&body.name)
            } else {
                fqdn(&format!("{}.{}", body.name, zone.domain))
            };

            let new_content = if body.rtype == "MX" {
                format!("{} {}", body.priority.unwrap_or(10), fqdn(&body.content))
            } else if body.rtype == "CNAME" || body.rtype == "NS" {
                fqdn(&body.content)
            } else {
                body.content.clone()
            };

            // Get current rrsets for the old name+type
            let get_resp = client
                .get(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers.clone())
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            let zone_data = pdns_zone_or_empty(get_resp).await?;
            let rrsets = zone_data.get("rrsets").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            let mut patch_rrsets: Vec<serde_json::Value> = Vec::new();

            // If name+type changed, delete old and create new
            if old_name != new_name || old_type != body.rtype {
                // Remove old record from its rrset
                let mut old_records: Vec<serde_json::Value> = Vec::new();
                for rrset in &rrsets {
                    let rr_name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let rr_type = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if rr_name == old_name && rr_type == old_type {
                        if let Some(recs) = rrset.get("records").and_then(|v| v.as_array()) {
                            for rec in recs {
                                let c = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                                if c != old_content {
                                    old_records.push(rec.clone());
                                }
                            }
                        }
                        break;
                    }
                }

                if old_records.is_empty() {
                    patch_rrsets.push(serde_json::json!({
                        "name": old_name,
                        "type": old_type,
                        "changetype": "DELETE",
                    }));
                } else {
                    patch_rrsets.push(serde_json::json!({
                        "name": old_name,
                        "type": old_type,
                        "ttl": ttl,
                        "changetype": "REPLACE",
                        "records": old_records,
                    }));
                }

                // Add to new rrset
                let mut new_records: Vec<serde_json::Value> = Vec::new();
                for rrset in &rrsets {
                    let rr_name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let rr_type = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if rr_name == new_name && rr_type == body.rtype {
                        if let Some(recs) = rrset.get("records").and_then(|v| v.as_array()) {
                            new_records = recs.clone();
                        }
                        break;
                    }
                }
                new_records.push(serde_json::json!({ "content": new_content, "disabled": false }));

                patch_rrsets.push(serde_json::json!({
                    "name": new_name,
                    "type": body.rtype,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": new_records,
                }));
            } else {
                // Same name+type, just replace content in the rrset
                let mut records: Vec<serde_json::Value> = Vec::new();
                for rrset in &rrsets {
                    let rr_name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let rr_type = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if rr_name == old_name && rr_type == old_type {
                        if let Some(recs) = rrset.get("records").and_then(|v| v.as_array()) {
                            for rec in recs {
                                let c = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                                if c == old_content {
                                    records.push(serde_json::json!({ "content": new_content, "disabled": false }));
                                } else {
                                    records.push(rec.clone());
                                }
                            }
                        }
                        break;
                    }
                }

                if records.is_empty() {
                    records.push(serde_json::json!({ "content": new_content, "disabled": false }));
                }

                patch_rrsets.push(serde_json::json!({
                    "name": new_name,
                    "type": body.rtype,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": records,
                }));
            }

            let resp = client
                .patch(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers)
                .json(&serde_json::json!({ "rrsets": patch_rrsets }))
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            pdns_patch_result(resp).await?;

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.update",
                Some("dns"), Some(&zone.domain), Some(&format!("{} {}", body.rtype, body.name)), None, claims.key_id,
            ).await;

            Ok(Json(serde_json::json!({
                "id": pdns_record_id(&new_name, &body.rtype, &new_content),
                "type": body.rtype,
                "name": strip_dot(&new_name),
                "content": strip_dot(&body.content),
                "ttl": ttl,
            })))
        }
        _ => Err(err(StatusCode::BAD_REQUEST, "Unknown DNS provider")),
    }
}

/// DELETE /api/dns/zones/{id}/records/{record_id} - Delete a DNS record.
pub async fn delete_record(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((id, record_id)): Path<(Uuid, String)>,
    req_headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;
    let ip = crate::routes::client_ip(&req_headers);

    if record_id.is_empty() || record_id.len() > 256 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid record ID"));
    }

    match zone.provider.as_str() {
        "cloudflare" => {
            // Same discipline as update_record - CF record IDs are 32-char lowercase
            // hex; record_id is unescaped in the outbound URL below.
            if record_id.len() != 32 || !record_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid record ID"));
            }
            let token = zone.cf_api_token.as_deref().unwrap_or("");
            let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

            let resp = client
                .delete(&format!(
                    "{CF_API}/zones/{}/dns_records/{record_id}",
                    zone.cf_zone_id.as_deref().unwrap_or("")
                ))
                .headers(headers)
                .send()
                .await
                .map_err(|e| upstream_error("Cloudflare API", e))?;

            let cf_resp: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| upstream_error("Cloudflare response", e))?;

            if !cf_resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let errors = cf_resp.get("errors").cloned().unwrap_or_default();
                return Err(err(StatusCode::UNPROCESSABLE_ENTITY, &format!("Cloudflare error: {errors}")));
            }

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.delete",
                Some("dns"), Some(&zone.domain), None, ip.as_deref(), claims.key_id,
            ).await;

            crate::services::security_hardening::audit_log(
                &state.db, "dns.record.delete", Some(&claims.email), ip.as_deref(),
                Some("dns"), Some(&zone.domain), None, None, "warning", claims.key_id,
            ).await;

            Ok(Json(serde_json::json!({ "ok": true })))
        }
        "powerdns" => {
            let (pdns_url, client, headers) = pdns_connect(&state).await?;
            let zone_fqdn = fqdn(&zone.domain);

            let (rec_name, rec_type, rec_content) = pdns_parse_record_id(&record_id)?;

            // Get current rrset
            let get_resp = client
                .get(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers.clone())
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            let zone_data = pdns_zone_or_empty(get_resp).await?;
            let rrsets = zone_data.get("rrsets").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            let mut remaining: Vec<serde_json::Value> = Vec::new();
            for rrset in &rrsets {
                let rr_name = rrset.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let rr_type = rrset.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if rr_name == rec_name && rr_type == rec_type {
                    if let Some(recs) = rrset.get("records").and_then(|v| v.as_array()) {
                        for rec in recs {
                            let c = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                            if c != rec_content {
                                remaining.push(rec.clone());
                            }
                        }
                    }
                    break;
                }
            }

            let changetype = if remaining.is_empty() { "DELETE" } else { "REPLACE" };

            let mut patch_rrset = serde_json::json!({
                "name": rec_name,
                "type": rec_type,
                "changetype": changetype,
            });

            if changetype == "REPLACE" {
                patch_rrset["ttl"] = serde_json::json!(3600);
                patch_rrset["records"] = serde_json::json!(remaining);
            }

            let resp = client
                .patch(&format!("{pdns_url}/api/v1/servers/localhost/zones/{zone_fqdn}"))
                .headers(headers)
                .json(&serde_json::json!({ "rrsets": [patch_rrset] }))
                .send()
                .await
                .map_err(|e| upstream_error("PowerDNS API", e))?;

            pdns_patch_result(resp).await?;

            activity::log_activity(
                &state.db, claims.sub, &claims.email, "dns.record.delete",
                Some("dns"), Some(&zone.domain), None, ip.as_deref(), claims.key_id,
            ).await;

            crate::services::security_hardening::audit_log(
                &state.db, "dns.record.delete", Some(&claims.email), ip.as_deref(),
                Some("dns"), Some(&zone.domain), None, None, "warning", claims.key_id,
            ).await;

            Ok(Json(serde_json::json!({ "ok": true })))
        }
        _ => Err(err(StatusCode::BAD_REQUEST, "Unknown DNS provider")),
    }
}

/// POST /api/dns/propagation - Check DNS propagation across multiple public resolvers.
pub async fn check_propagation(
    State(_state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;

    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "name required"))?;
    let rtype = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("A");

    // Reject anything dig could parse as an option (leading -/+) or that escapes the
    // conservative DNS charset. See is_safe_dig_arg + its unit test.
    if !is_safe_dig_arg(name, true) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid DNS name"));
    }
    let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"];
    if !valid_types.contains(&rtype) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid record type"));
    }

    let resolvers: &[(&str, &str)] = &[
        ("8.8.8.8", "Google"),
        ("1.1.1.1", "Cloudflare"),
        ("9.9.9.9", "Quad9"),
        ("208.67.222.222", "OpenDNS"),
        ("8.26.56.26", "Comodo"),
    ];

    let mut results = Vec::new();

    for (ip, label) in resolvers {
        let output = safe_command("dig")
            .args([
                &format!("@{ip}"),
                "+short",
                "+time=3",
                "+tries=1",
                rtype,
                name,
            ])
            .output()
            .await;

        let value = output
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        results.push(serde_json::json!({
            "resolver": ip,
            "label": label,
            "value": if value.is_empty() { "No response".to_string() } else { value.clone() },
            "found": !value.is_empty(),
        }));
    }

    let propagated = results
        .iter()
        .filter(|r| r["found"].as_bool() == Some(true))
        .count();

    Ok(Json(serde_json::json!({
        "name": name,
        "type": rtype,
        "results": results,
        "propagated": propagated,
        "total": resolvers.len(),
        "fully_propagated": propagated == resolvers.len(),
    })))
}

// ── DNS Health Check ────────────────────────────────────────────────────

async fn run_dig(domain: &str, rtype: &str) -> String {
    safe_command("dig")
        .args(["+short", "+time=3", "+tries=1", rtype, domain])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// POST /api/dns/health-check - Run DNS health checks on a domain.
pub async fn dns_health_check(
    State(_state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "domain required"))?;

    // Reject anything dig could parse as an option, or that escapes the DNS charset.
    if domain.len() > 253 || !is_safe_dig_arg(domain, false) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }

    let mut checks = Vec::new();

    // 1. SOA record
    let soa = run_dig(domain, "SOA").await;
    checks.push(serde_json::json!({
        "check": "SOA Record",
        "status": if !soa.is_empty() { "pass" } else { "fail" },
        "detail": if soa.is_empty() { "No SOA record found".to_string() } else { soa },
    }));

    // 2. NS records
    let ns = run_dig(domain, "NS").await;
    let ns_count = ns.lines().filter(|l| !l.is_empty()).count();
    checks.push(serde_json::json!({
        "check": "NS Records",
        "status": if ns_count >= 2 { "pass" } else if ns_count == 1 { "warn" } else { "fail" },
        "detail": format!("{} nameserver(s) found", ns_count),
    }));

    // 3. A record exists
    let a = run_dig(domain, "A").await;
    checks.push(serde_json::json!({
        "check": "A Record",
        "status": if !a.is_empty() { "pass" } else { "info" },
        "detail": if a.is_empty() { "No A record - domain won't resolve to an IP".to_string() } else { a },
    }));

    // 4. MX record
    let mx = run_dig(domain, "MX").await;
    checks.push(serde_json::json!({
        "check": "MX Record",
        "status": if !mx.is_empty() { "pass" } else { "info" },
        "detail": if mx.is_empty() { "No MX record - domain can't receive email".to_string() } else { mx },
    }));

    // 5. SPF
    let txt = run_dig(domain, "TXT").await;
    let has_spf = txt.contains("v=spf1");
    checks.push(serde_json::json!({
        "check": "SPF Record",
        "status": if has_spf { "pass" } else { "warn" },
        "detail": if has_spf { "SPF configured" } else { "No SPF record - email authentication missing" },
    }));

    // 6. DNSSEC
    let dnssec_output = safe_command("dig")
        .args(["+dnssec", "+short", "DNSKEY", domain])
        .output()
        .await;
    let has_dnssec = dnssec_output
        .ok()
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    checks.push(serde_json::json!({
        "check": "DNSSEC",
        "status": if has_dnssec { "pass" } else { "info" },
        "detail": if has_dnssec { "DNSSEC is active" } else { "DNSSEC not configured (optional)" },
    }));

    let pass_count = checks.iter().filter(|c| c["status"] == "pass").count();
    let fail_count = checks.iter().filter(|c| c["status"] == "fail").count();

    Ok(Json(serde_json::json!({
        "domain": domain,
        "checks": checks,
        "pass": pass_count,
        "fail": fail_count,
        "total": checks.len(),
    })))
}

// ── DNSSEC Status ───────────────────────────────────────────────────────

/// GET /api/dns/zones/{id}/dnssec - Get DNSSEC status for a zone.
pub async fn dnssec_status(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    if zone.provider != "cloudflare" {
        return Ok(Json(serde_json::json!({
            "supported": false,
            "message": "DNSSEC management only available for Cloudflare zones",
        })));
    }

    let token = zone.cf_api_token.as_deref().unwrap_or("");
    let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

    let resp = client
        .get(&format!(
            "{CF_API}/zones/{}/dnssec",
            zone.cf_zone_id.as_deref().unwrap_or("")
        ))
        .headers(headers)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;
    let result = data.get("result").cloned().unwrap_or(serde_json::json!({}));
    let status = result
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Ok(Json(serde_json::json!({
        "supported": true,
        "status": status,
        "active": status == "active",
        "ds_record": result.get("ds").cloned(),
        "key_tag": result.get("key_tag").cloned(),
        "algorithm": result.get("algorithm").cloned(),
    })))
}

// ── DNS Changelog ───────────────────────────────────────────────────────

/// GET /api/dns/zones/{id}/changelog - Get DNS change history.
pub async fn dns_changelog(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    let entries: Vec<(String, String, Option<String>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT action, COALESCE(user_email, ''), details, created_at FROM activity_logs \
             WHERE action LIKE 'dns.%' AND target_name = $1 ORDER BY created_at DESC LIMIT 50",
        )
        .bind(&zone.domain)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal_error("dns changelog", e))?;

    let logs: Vec<serde_json::Value> = entries
        .iter()
        .map(|(action, email, details, time)| {
            serde_json::json!({
                "action": action,
                "user": email,
                "details": details,
                "time": time,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "entries": logs })))
}

// ── DNS Analytics ───────────────────────────────────────────────────────

/// GET /api/dns/zones/{id}/analytics - Get DNS query analytics (Cloudflare only).
pub async fn dns_analytics(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    if zone.provider != "cloudflare" {
        return Ok(Json(serde_json::json!({
            "supported": false,
            "message": "Analytics only available for Cloudflare zones",
        })));
    }

    let token = zone.cf_api_token.as_deref().unwrap_or("");
    let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

    // Fetch DNS analytics for last 24 hours
    let since = (chrono::Utc::now() - chrono::Duration::hours(24))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let until = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let resp = client
        .get(&format!(
            "{CF_API}/zones/{}/dns_analytics/report?since={since}&until={until}&metrics=queryCount,responseTimeAvg&dimensions=queryType",
            zone.cf_zone_id.as_deref().unwrap_or("")
        ))
        .headers(headers)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    let status = resp.status();
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    if !status.is_success() {
        // Analytics API might not be available on free plans
        return Ok(Json(serde_json::json!({
            "supported": true,
            "available": false,
            "message": "DNS analytics not available (may require paid Cloudflare plan)",
        })));
    }

    let result = data
        .get("result")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let totals = result
        .get("totals")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let rows = result
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let total_queries = totals
        .get("queryCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let avg_response = totals
        .get("responseTimeAvg")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let by_type: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let dims = r.get("dimensions").and_then(|v| v.as_array());
            let metrics = r.get("metrics").and_then(|v| v.as_array());
            serde_json::json!({
                "type": dims.and_then(|d| d.first()).and_then(|v| v.as_str()).unwrap_or(""),
                "queries": metrics.and_then(|m| m.first()).and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "supported": true,
        "available": true,
        "total_queries": total_queries,
        "avg_response_ms": (avg_response * 1000.0).round() / 1000.0,
        "by_type": by_type,
        "period": "24h",
    })))
}

// ── Cloudflare Zone Settings ───────────────────────────────────────────

/// GET /api/dns/zones/{id}/cf/settings - Get Cloudflare zone settings.
pub async fn cf_zone_settings(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    if zone.provider != "cloudflare" {
        return Ok(Json(serde_json::json!({
            "supported": false,
            "message": "Settings management only available for Cloudflare zones",
        })));
    }

    let token = zone.cf_api_token.as_deref().unwrap_or("");
    let zone_id = zone.cf_zone_id.as_deref().unwrap_or("");
    let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

    // Fetch multiple settings in parallel
    let settings_keys = ["security_level", "development_mode", "ssl", "always_use_https", "min_tls_version"];
    let mut results = serde_json::Map::new();

    for key in &settings_keys {
        let resp = client
            .get(&format!("{CF_API}/zones/{zone_id}/settings/{key}"))
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

        if let Some(result) = data.get("result") {
            if let Some(value) = result.get("value") {
                results.insert(key.to_string(), value.clone());
            }
        }
    }

    Ok(Json(serde_json::json!({
        "supported": true,
        "settings": results,
    })))
}

/// PUT /api/dns/zones/{id}/cf/settings - Update a Cloudflare zone setting.
pub async fn cf_update_setting(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    req_headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;
    let ip = crate::routes::client_ip(&req_headers);

    if zone.provider != "cloudflare" {
        return Err(err(StatusCode::BAD_REQUEST, "Only available for Cloudflare zones"));
    }

    let setting = body.get("setting").and_then(|v| v.as_str())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'setting' field"))?;
    let value = body.get("value")
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing 'value' field"))?;

    // Whitelist allowed settings
    const ALLOWED: &[&str] = &[
        "security_level", "development_mode", "ssl", "always_use_https", "min_tls_version",
    ];
    if !ALLOWED.contains(&setting) {
        return Err(err(StatusCode::BAD_REQUEST, &format!(
            "Setting '{setting}' not allowed. Allowed: {}", ALLOWED.join(", ")
        )));
    }

    // Validate values
    match setting {
        "security_level" => {
            let v = value.as_str().unwrap_or("");
            if !["off", "essentially_off", "low", "medium", "high", "under_attack"].contains(&v) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid security_level value"));
            }
        }
        "development_mode" => {
            if !value.is_string() || !["on", "off"].contains(&value.as_str().unwrap_or("")) {
                return Err(err(StatusCode::BAD_REQUEST, "development_mode must be 'on' or 'off'"));
            }
        }
        "ssl" => {
            let v = value.as_str().unwrap_or("");
            if !["off", "flexible", "full", "strict"].contains(&v) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid ssl value. Use: off, flexible, full, strict"));
            }
        }
        "always_use_https" => {
            if !value.is_string() || !["on", "off"].contains(&value.as_str().unwrap_or("")) {
                return Err(err(StatusCode::BAD_REQUEST, "always_use_https must be 'on' or 'off'"));
            }
        }
        "min_tls_version" => {
            let v = value.as_str().unwrap_or("");
            if !["1.0", "1.1", "1.2", "1.3"].contains(&v) {
                return Err(err(StatusCode::BAD_REQUEST, "Invalid min_tls_version. Use: 1.0, 1.1, 1.2, 1.3"));
            }
        }
        _ => {}
    }

    let token = zone.cf_api_token.as_deref().unwrap_or("");
    let zone_id = zone.cf_zone_id.as_deref().unwrap_or("");
    let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

    let resp = client
        .patch(&format!("{CF_API}/zones/{zone_id}/settings/{setting}"))
        .headers(headers)
        .json(&serde_json::json!({ "value": value }))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    let status = resp.status();
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    if !status.is_success() {
        let cf_err = data.get("errors")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown Cloudflare error");
        return Err(err(StatusCode::BAD_GATEWAY, cf_err));
    }

    tracing::info!("CF setting updated: {setting}={value} for zone {}", zone.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("dns.cf.setting.{setting}"),
        Some("dns_zone"), Some(&zone.domain), None, ip.as_deref(), claims.key_id,
    ).await;

    crate::services::security_hardening::audit_log(
        &state.db, &format!("dns.cf.setting.{setting}"), Some(&claims.email), ip.as_deref(),
        Some("dns_zone"), Some(&zone.domain), None, None, "warning", claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "setting": setting,
        "value": value,
    })))
}

// ── Cloudflare Cache Purge ─────────────────────────────────────────────

/// POST /api/dns/zones/{id}/cf/cache/purge - Purge Cloudflare cache.
pub async fn cf_purge_cache(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;
    let zone = get_zone(&state, id).await?;

    if zone.provider != "cloudflare" {
        return Err(err(StatusCode::BAD_REQUEST, "Cache purge only available for Cloudflare zones"));
    }

    let token = zone.cf_api_token.as_deref().unwrap_or("");
    let zone_id = zone.cf_zone_id.as_deref().unwrap_or("");
    let (client, headers) = cf_client(token, zone.cf_api_email.as_deref())?;

    // Build purge request: either purge_everything or specific files
    let purge_body = if let Some(files) = body.get("files").and_then(|f| f.as_array()) {
        if files.is_empty() || files.len() > 30 {
            return Err(err(StatusCode::BAD_REQUEST, "Provide 1-30 URLs to purge"));
        }
        serde_json::json!({ "files": files })
    } else {
        serde_json::json!({ "purge_everything": true })
    };

    let resp = client
        .post(&format!("{CF_API}/zones/{zone_id}/purge_cache"))
        .headers(headers)
        .json(&purge_body)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    let status = resp.status();
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e.to_string()))?;

    if !status.is_success() {
        let cf_err = data.get("errors")
            .and_then(|e| e.as_array())
            .and_then(|a| a.first())
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("Cloudflare cache purge failed");
        return Err(err(StatusCode::BAD_GATEWAY, cf_err));
    }

    let purge_type = if body.get("files").is_some() { "selective" } else { "full" };
    tracing::info!("CF cache purge ({purge_type}) for zone {}", zone.domain);
    activity::log_activity(
        &state.db, claims.sub, &claims.email,
        &format!("dns.cf.cache.purge.{purge_type}"),
        Some("dns_zone"), Some(&zone.domain), None, None, claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "purge_type": purge_type,
    })))
}

#[cfg(test)]
mod tests {
    use super::is_safe_dig_arg;

    #[test]
    fn dig_arg_rejects_option_injection() {
        // A leading dash/plus would let dig parse the value as an option (e.g. -f<file>).
        assert!(!is_safe_dig_arg("-fFILE", true));
        assert!(!is_safe_dig_arg("+short", true));
        assert!(!is_safe_dig_arg("-x", false));
        assert!(!is_safe_dig_arg("", true));
        // Escaping the charset (spaces, slashes, shell metachars) is rejected.
        assert!(!is_safe_dig_arg("a b", true));
        assert!(!is_safe_dig_arg("a/b", true));
        assert!(!is_safe_dig_arg("a;b", true));
        // Underscore only where allowed (query names vs health-check domains).
        assert!(is_safe_dig_arg("_dmarc.example.com", true));
        assert!(!is_safe_dig_arg("_dmarc.example.com", false));
        // Normal names pass.
        assert!(is_safe_dig_arg("example.com", true));
        assert!(is_safe_dig_arg("sub.example.com", false));
        assert!(is_safe_dig_arg("mail-1.example.com", false));
    }
}

// ── DNS backups from the Backup Orchestrator (lot 3) ────────────────────

#[derive(sqlx::FromRow)]
struct DnsBackupRef {
    server_id: Option<Uuid>,
    kind: String,
    zone: Option<String>,
    backend: Option<String>,
    filename: String,
    encrypted: bool,
    encryption_key_version: i16,
}

/// POST /api/dns/backups/{id}/restore - Restore one zone, or the whole
/// PowerDNS database, from a `dns_backups` row, on the server that holds it.
///
/// * zone: the agent decrypts and hands back the export; it is re-applied
///   through the PowerDNS API (`POST /zones` with its rrsets; when the zone
///   exists, 409, it is re-adopted and its rrsets are replaced), and the zone
///   is tracked in `dns_zones` again if it was not.
/// * snapshot: the agent replaces the database (sqlite or pgsql) and restarts
///   PowerDNS; every zone it then serves is tracked in `dns_zones`. Answers 202
///   `{status: "running", job_id, server_id}` when it outlives this request.
pub async fn restore_dns_backup(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use crate::services::backup_policy_executor as bpe;
    use crate::services::mail_dns_backup as mdb;

    // Scoped to the servers this administrator runs; role read from the DATABASE.
    let row: DnsBackupRef = sqlx::query_as(
        "SELECT dnb.server_id, dnb.kind, dnb.zone, dnb.backend, dnb.filename, dnb.encrypted, dnb.encryption_key_version \
           FROM dns_backups dnb WHERE dnb.id = $1 AND EXISTS (\
             SELECT 1 FROM users u, servers sv WHERE u.id = $2 AND u.role = 'admin' \
             AND sv.id = dnb.server_id AND (sv.is_local OR sv.user_id = u.id))",
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("read dns backup", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "DNS backup not found"))?;
    if !mdb::is_plain_filename(&row.filename) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid backup path"));
    }
    let label = row.zone.clone().unwrap_or_else(|| "DNS database".to_string());
    let agent = crate::helpers::agent_for_site_server(&state, row.server_id, &label).await?;
    let Some(server_id) = row.server_id else {
        return Err(err(StatusCode::CONFLICT, "This backup has no server"));
    };
    let key = bpe::row_encryption_key(row.encrypted, row.encryption_key_version, &state.config.jwt_secret);
    let ip = crate::routes::client_ip(&headers);
    let refuse = |e: crate::services::agent::AgentError| -> ApiError {
        use crate::services::agent::AgentError;
        match e {
            AgentError::Status(code @ (400 | 409 | 422 | 507), ref body) => err(
                StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
                &crate::error::agent_message(body),
            ),
            other => crate::error::agent_error("DNS restore", other),
        }
    };

    activity::log_activity(
        &state.db, claims.sub, &claims.email, "dns.backup_restore",
        Some("dns"), Some(&label), Some(&row.filename), ip.as_deref(), claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "dns.backup_restore", Some(&claims.email), ip.as_deref(),
        Some("dns"), Some(&label), Some(&row.kind), None, "warning", claims.key_id,
    ).await;

    match row.kind.as_str() {
        "zone" => {
            let Some(zone) = row.zone.clone().filter(|z| mdb::is_valid_zone(z)) else {
                return Err(err(StatusCode::CONFLICT, "This backup names no valid zone"));
            };
            let api = mdb::pdns_api_from_settings(&state.db, &state.config.jwt_secret).await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
                .ok_or_else(|| err(StatusCode::CONFLICT, "PowerDNS not configured. Set API URL and API Key in Settings."))?;
            let resp = agent
                .post_long("/dns/restore", Some(mdb::dns_restore_body("zone", &row.filename, key.as_deref())), mdb::START_TIMEOUT_SECS)
                .await
                .map_err(refuse)?;
            if resp.get("skipped").is_some() {
                return Err(err(StatusCode::CONFLICT, "PowerDNS is not installed on this server"));
            }
            let content = resp.get("content").ok_or_else(|| err(StatusCode::BAD_GATEWAY, "The agent returned no zone"))?;
            // The export must be the zone this row names: the file is read on
            // the agent, the name is checked here before anything is applied.
            let exported = content.get("name").and_then(|v| v.as_str()).map(mdb::zone_label).unwrap_or_default();
            if !exported.eq_ignore_ascii_case(&zone) {
                return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "The backup file holds another zone than its record says"));
            }
            let (readopted, rrsets) = api.apply_zone(content).await.map_err(|e| err(StatusCode::BAD_GATEWAY, &e))?;
            mdb::track_powerdns_zone(&state.db, claims.sub, &zone, server_id).await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
            Ok((StatusCode::OK, Json(serde_json::json!({
                "ok": true, "kind": "zone", "zone": zone, "readopted": readopted, "rrsets": rrsets,
            }))))
        }
        "snapshot" => {
            let key = key.ok_or_else(|| err(StatusCode::CONFLICT, "This DNS snapshot is not encrypted; refusing to restore it"))?;
            let start = agent
                .post_long("/dns/restore", Some(mdb::dns_restore_body("snapshot", &row.filename, Some(&key))), mdb::START_TIMEOUT_SECS)
                .await
                .map_err(refuse)?;
            match mdb::parse_agent_start(&start).map_err(|e| err(StatusCode::BAD_GATEWAY, &e))? {
                mdb::AgentStart::Skipped(_) => {
                    return Err(err(StatusCode::CONFLICT, "PowerDNS is not installed on this server"));
                }
                mdb::AgentStart::Done(_) => {}
                mdb::AgentStart::Job(job_id) => {
                    match mdb::wait_job(&agent, &job_id, std::time::Duration::from_secs(mdb::ROUTE_JOB_BUDGET_SECS)).await {
                        Ok(_) => {}
                        Err(mdb::JobWaitError::TimedOut) => {
                            return Ok((StatusCode::ACCEPTED, Json(serde_json::json!({
                                "status": "running",
                                "job_id": job_id,
                                "server_id": server_id,
                                "message": "The DNS restore is still running on the server.",
                            }))));
                        }
                        Err(mdb::JobWaitError::Failed(msg, code)) => {
                            // The agent classed the failure (422 integrity or passphrase,
                            // 400 validation, 507 disk...): same status and message as the
                            // synchronous restores give.
                            return Err(match mdb::job_failure_status(code) {
                                502 => err(StatusCode::BAD_GATEWAY, &format!("DNS restore failed: {msg}")),
                                c => err(StatusCode::from_u16(c).unwrap_or(StatusCode::BAD_GATEWAY), &msg),
                            });
                        }
                        Err(e) => return Err(err(StatusCode::BAD_GATEWAY, &format!("DNS restore failed: {e}"))),
                    }
                }
            }
            // Track every zone the restored database serves.
            let mut zones_tracked = 0usize;
            if let Ok(Some(api)) = mdb::pdns_api_from_settings(&state.db, &state.config.jwt_secret).await {
                match api.list_zones().await {
                    Ok(zones) => {
                        for z in zones.iter().filter(|z| mdb::is_valid_zone(z)) {
                            match mdb::track_powerdns_zone(&state.db, claims.sub, z, server_id).await {
                                Ok(true) => zones_tracked += 1,
                                Ok(false) => {}
                                Err(e) => tracing::warn!("DNS restore: {e}"),
                            }
                        }
                    }
                    Err(e) => tracing::warn!("DNS restore: the restored zones could not be listed: {e}"),
                }
            }
            Ok((StatusCode::OK, Json(serde_json::json!({
                "ok": true, "kind": "snapshot", "backend": row.backend, "zones_tracked": zones_tracked,
            }))))
        }
        _ => Err(err(StatusCode::CONFLICT, "This backup has an unknown kind")),
    }
}
