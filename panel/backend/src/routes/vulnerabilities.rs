//! `/api/vulnerabilities/*` (CVE scanner, batch 1: read API and on-demand scan).
//!
//! Access: an administrator sees every target; any other role sees only the
//! `site` targets of sites it owns (`sites.user_id`). Every query that returns
//! targets or findings goes through [`VISIBLE_TARGET`]. Settings are admin only.
//!
//! Contract: conception/13-scanner-cve-lot1-contrat.md.

use std::cmp::Ordering;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AuthUser, Claims};
use crate::error::{ApiError, err, internal_error, paginate, require_admin};
use crate::services::security_hardening::{get_setting_bool, get_setting_i64};
use crate::services::vuln_sweeper;

/// Visibility of a target `t`. `$1` = the caller is an administrator, `$2` = the caller's id.
pub const VISIBLE_TARGET: &str = "($1::bool OR (t.kind = 'site' AND EXISTS (\
    SELECT 1 FROM sites s WHERE s.id = t.site_id AND s.user_id = $2)))";

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "unknown"];
const KINDS: &[&str] = &["site", "image", "system", "wordpress"];

/// SQL twin of [`rank_cmp`]: KEV first, then risk, then severity, then newest.
const ORDER_SQL: &str = "f.kev DESC, f.risk DESC NULLS LAST, \
    CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
    f.first_seen DESC, f.id";

const FINDING_SELECT: &str = "SELECT f.id, f.target_id, f.vuln_id, f.aliases, f.package, f.version, f.pkg_type, \
    f.location, f.severity, f.cvss, f.kev, f.kev_ransomware, f.epss, f.epss_percentile, f.risk, f.fix_state, \
    f.fixed_version, f.title, f.url, f.first_seen, f.last_seen, f.resolved_at, \
    t.kind AS t_kind, t.ref AS t_ref, t.server_id AS t_server_id, sv.name AS t_server_name, \
    t.site_id AS t_site_id, t.app_name AS t_app_name, t.git_deploy_id AS t_git_deploy_id, t.exposed AS t_exposed \
    FROM vuln_findings f JOIN vuln_targets t ON t.id = f.target_id JOIN servers sv ON sv.id = t.server_id";

/// List filters, `$3..=$9`, after the visibility predicate's `$1`/`$2`.
const LIST_FILTERS: &str = "($3::text IS NULL OR f.severity = $3) \
    AND ($4::bool IS NULL OR f.kev = $4) \
    AND ($5::text IS NULL OR t.kind = $5) \
    AND ($6::uuid IS NULL OR t.server_id = $6) \
    AND ($7::uuid IS NULL OR t.id = $7) \
    AND ($8::bool IS NULL OR (f.fix_state = 'fixed') = $8) \
    AND ($9::bool OR f.resolved_at IS NULL)";

const TARGET_SELECT: &str = "SELECT t.id, t.kind, t.ref, t.server_id, sv.name AS server_name, t.site_id, \
    t.app_name, t.git_deploy_id, t.exposed, t.fingerprint, t.sbom_at, t.matched_at, t.needs_inventory, t.last_error \
    FROM vuln_targets t JOIN servers sv ON sv.id = t.server_id";

const SUMMARY_TOTALS_SQL: &str = "SELECT \
    COUNT(*) FILTER (WHERE f.kev), \
    COUNT(*) FILTER (WHERE f.severity = 'critical'), \
    COUNT(*) FILTER (WHERE f.severity = 'high'), \
    COUNT(*) FILTER (WHERE f.severity = 'medium'), \
    COUNT(*) FILTER (WHERE f.severity = 'low'), \
    COUNT(*) FILTER (WHERE f.fix_state = 'fixed') \
    FROM vuln_findings f JOIN vuln_targets t ON t.id = f.target_id WHERE f.resolved_at IS NULL AND ";

const SUMMARY_TARGETS_SQL: &str = "SELECT t.id, t.kind, t.ref, t.server_id, t.site_id, t.app_name, t.git_deploy_id, \
    t.sbom_at, t.matched_at, t.last_error, \
    COUNT(f.id) FILTER (WHERE f.kev) AS kev, \
    COUNT(f.id) FILTER (WHERE f.severity = 'critical') AS critical, \
    COUNT(f.id) FILTER (WHERE f.severity = 'high') AS high, \
    COUNT(f.id) FILTER (WHERE f.severity = 'medium') AS medium, \
    COUNT(f.id) FILTER (WHERE f.severity = 'low') AS low \
    FROM vuln_targets t LEFT JOIN vuln_findings f ON f.target_id = t.id AND f.resolved_at IS NULL WHERE ";

const SUMMARY_SERVERS_SQL: &str = "SELECT st.server_id, st.db_built, st.last_match_at, st.last_error \
    FROM vuln_server_state st WHERE $1::bool OR st.server_id IN (SELECT t.server_id FROM vuln_targets t WHERE ";

// ── Rows ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FindingRow {
    pub id: Uuid,
    pub target_id: Uuid,
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub version: String,
    pub pkg_type: Option<String>,
    pub location: Option<String>,
    pub severity: String,
    pub cvss: Option<f32>,
    pub kev: bool,
    pub kev_ransomware: bool,
    pub epss: Option<f32>,
    pub epss_percentile: Option<f32>,
    pub risk: Option<f32>,
    pub fix_state: String,
    pub fixed_version: Option<String>,
    pub title: Option<String>,
    pub url: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub t_kind: String,
    pub t_ref: String,
    pub t_server_id: Uuid,
    pub t_server_name: String,
    pub t_site_id: Option<Uuid>,
    pub t_app_name: Option<String>,
    pub t_git_deploy_id: Option<Uuid>,
    pub t_exposed: Option<bool>,
}

impl FindingRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "target_id": self.target_id,
            "vuln_id": self.vuln_id,
            "aliases": self.aliases,
            "package": self.package,
            "version": self.version,
            "pkg_type": self.pkg_type,
            "location": self.location,
            "severity": self.severity,
            "cvss": self.cvss,
            "kev": self.kev,
            "kev_ransomware": self.kev_ransomware,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "risk": self.risk,
            "fix_state": self.fix_state,
            "fixed_version": self.fixed_version,
            "title": self.title,
            "url": self.url,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "resolved_at": self.resolved_at,
            "target": {
                "id": self.target_id,
                "kind": self.t_kind,
                "ref": self.t_ref,
                "server_id": self.t_server_id,
                "server_name": self.t_server_name,
                "site_id": self.t_site_id,
                "app_name": self.t_app_name,
                "git_deploy_id": self.t_git_deploy_id,
                "exposed": self.t_exposed,
            },
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    kind: String,
    #[sqlx(rename = "ref")]
    ref_: String,
    server_id: Uuid,
    server_name: String,
    site_id: Option<Uuid>,
    app_name: Option<String>,
    git_deploy_id: Option<Uuid>,
    exposed: Option<bool>,
    fingerprint: Option<String>,
    sbom_at: Option<DateTime<Utc>>,
    matched_at: Option<DateTime<Utc>>,
    needs_inventory: bool,
    last_error: Option<String>,
}

impl TargetRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.kind,
            "ref": self.ref_,
            "server_id": self.server_id,
            "server_name": self.server_name,
            "site_id": self.site_id,
            "app_name": self.app_name,
            "git_deploy_id": self.git_deploy_id,
            "exposed": self.exposed,
            "fingerprint": self.fingerprint,
            "sbom_at": self.sbom_at,
            "matched_at": self.matched_at,
            "needs_inventory": self.needs_inventory,
            "last_error": self.last_error,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SummaryTargetRow {
    id: Uuid,
    kind: String,
    #[sqlx(rename = "ref")]
    ref_: String,
    server_id: Uuid,
    site_id: Option<Uuid>,
    app_name: Option<String>,
    git_deploy_id: Option<Uuid>,
    sbom_at: Option<DateTime<Utc>>,
    matched_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    kev: i64,
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
}

// ── Pure helpers ────────────────────────────────────────────────────────

pub fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// KEV first, then `risk` descending (missing last), then severity, then newest `first_seen`.
pub fn rank_cmp(a: &FindingRow, b: &FindingRow) -> Ordering {
    b.kev
        .cmp(&a.kev)
        .then_with(|| match (a.risk, b.risk) {
            (Some(x), Some(y)) => y.partial_cmp(&x).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
        .then_with(|| b.first_seen.cmp(&a.first_seen))
}

pub fn sort_findings(rows: &mut [FindingRow]) {
    rows.sort_by(rank_cmp);
}

/// Query string of `GET /api/vulnerabilities`. Taken as text so an empty value
/// (`?kev=`) reads as "no filter" and a bad one gets a JSON 400.
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    pub severity: Option<String>,
    pub kev: Option<String>,
    pub kind: Option<String>,
    pub server_id: Option<String>,
    pub target_id: Option<String>,
    pub fixable: Option<String>,
    pub include_resolved: Option<String>,
    pub limit: Option<String>,
    pub offset: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct Filters {
    pub severity: Option<String>,
    pub kev: Option<bool>,
    pub kind: Option<String>,
    pub server_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub fixable: Option<bool>,
    pub include_resolved: bool,
    pub limit: i64,
    pub offset: i64,
}

fn present(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn bool_param(name: &str, v: &Option<String>) -> Result<Option<bool>, ApiError> {
    match present(v) {
        None => Ok(None),
        Some("true" | "1") => Ok(Some(true)),
        Some("false" | "0") => Ok(Some(false)),
        Some(_) => Err(err(StatusCode::BAD_REQUEST, &format!("Invalid {name} (true or false)"))),
    }
}

fn uuid_param(name: &str, v: &Option<String>) -> Result<Option<Uuid>, ApiError> {
    present(v)
        .map(|s| Uuid::parse_str(s).map_err(|_| err(StatusCode::BAD_REQUEST, &format!("Invalid {name}"))))
        .transpose()
}

fn int_param(name: &str, v: &Option<String>) -> Result<Option<i64>, ApiError> {
    present(v)
        .map(|s| s.parse::<i64>().map_err(|_| err(StatusCode::BAD_REQUEST, &format!("Invalid {name}"))))
        .transpose()
}

fn listed(name: &str, v: &Option<String>, allowed: &[&str]) -> Result<Option<String>, ApiError> {
    match present(v) {
        None => Ok(None),
        Some(s) => {
            let s = s.to_ascii_lowercase();
            if allowed.contains(&s.as_str()) {
                Ok(Some(s))
            } else {
                Err(err(StatusCode::BAD_REQUEST, &format!("Invalid {name} ({})", allowed.join(", "))))
            }
        }
    }
}

/// Validates the list filters against the allow-lists.
pub fn parse_filters(q: &ListQuery) -> Result<Filters, ApiError> {
    let (limit, offset) = paginate(int_param("limit", &q.limit)?, int_param("offset", &q.offset)?);
    Ok(Filters {
        severity: listed("severity", &q.severity, SEVERITIES)?,
        kev: bool_param("kev", &q.kev)?,
        kind: listed("kind", &q.kind, KINDS)?,
        server_id: uuid_param("server_id", &q.server_id)?,
        target_id: uuid_param("target_id", &q.target_id)?,
        fixable: bool_param("fixable", &q.fixable)?,
        include_resolved: bool_param("include_resolved", &q.include_resolved)?.unwrap_or(false),
        limit,
        offset,
    })
}

fn is_admin(claims: &Claims) -> bool {
    claims.role == "admin"
}

/// The target if the caller may see it; 404 otherwise (no existence oracle).
async fn visible_target(state: &AppState, claims: &Claims, id: Uuid) -> Result<TargetRow, ApiError> {
    sqlx::query_as::<_, TargetRow>(&format!("{TARGET_SELECT} WHERE t.id = $3 AND {VISIBLE_TARGET}"))
        .bind(is_admin(claims))
        .bind(claims.sub)
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("vulnerability target", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Target not found"))
}

// ── Routes ──────────────────────────────────────────────────────────────

/// GET /api/vulnerabilities
pub async fn list(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let f = parse_filters(&q)?;
    let rows: Vec<FindingRow> = sqlx::query_as(&format!(
        "{FINDING_SELECT} WHERE {VISIBLE_TARGET} AND {LIST_FILTERS} ORDER BY {ORDER_SQL} LIMIT $10 OFFSET $11"
    ))
    .bind(is_admin(&claims))
    .bind(claims.sub)
    .bind(&f.severity)
    .bind(f.kev)
    .bind(&f.kind)
    .bind(f.server_id)
    .bind(f.target_id)
    .bind(f.fixable)
    .bind(f.include_resolved)
    .bind(f.limit)
    .bind(f.offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list vulnerabilities", e))?;
    let (total,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM vuln_findings f JOIN vuln_targets t ON t.id = f.target_id \
         WHERE {VISIBLE_TARGET} AND {LIST_FILTERS}"
    ))
    .bind(is_admin(&claims))
    .bind(claims.sub)
    .bind(&f.severity)
    .bind(f.kev)
    .bind(&f.kind)
    .bind(f.server_id)
    .bind(f.target_id)
    .bind(f.fixable)
    .bind(f.include_resolved)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("count vulnerabilities", e))?;
    Ok(Json(json!({
        "items": rows.iter().map(FindingRow::to_json).collect::<Vec<_>>(),
        "total": total,
    })))
}

/// GET /api/vulnerabilities/summary
pub async fn summary(State(state): State<AppState>, AuthUser(claims): AuthUser) -> Result<Json<Value>, ApiError> {
    let admin = is_admin(&claims);
    let (kev, critical, high, medium, low, fixable): (i64, i64, i64, i64, i64, i64) =
        sqlx::query_as(&format!("{SUMMARY_TOTALS_SQL}{VISIBLE_TARGET}"))
            .bind(admin)
            .bind(claims.sub)
            .fetch_one(&state.db)
            .await
            .map_err(|e| internal_error("vulnerability totals", e))?;
    let targets: Vec<SummaryTargetRow> =
        sqlx::query_as(&format!("{SUMMARY_TARGETS_SQL}{VISIBLE_TARGET} GROUP BY t.id ORDER BY t.kind, t.ref"))
            .bind(admin)
            .bind(claims.sub)
            .fetch_all(&state.db)
            .await
            .map_err(|e| internal_error("vulnerability targets", e))?;
    let servers: Vec<(Uuid, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as(&format!("{SUMMARY_SERVERS_SQL}{VISIBLE_TARGET}) ORDER BY st.server_id"))
            .bind(admin)
            .bind(claims.sub)
            .fetch_all(&state.db)
            .await
            .map_err(|e| internal_error("vulnerability servers", e))?;
    Ok(Json(json!({
        "totals": { "kev": kev, "critical": critical, "high": high, "medium": medium, "low": low, "fixable": fixable },
        "targets": targets.iter().map(|t| json!({
            "id": t.id, "kind": t.kind, "ref": t.ref_, "server_id": t.server_id, "site_id": t.site_id,
            "app_name": t.app_name, "git_deploy_id": t.git_deploy_id, "kev": t.kev, "critical": t.critical,
            "high": t.high, "medium": t.medium, "low": t.low, "sbom_at": t.sbom_at,
            "matched_at": t.matched_at, "last_error": t.last_error,
        })).collect::<Vec<_>>(),
        // A server's own error can concern targets the caller does not own.
        "servers": servers.iter().map(|(id, built, matched, error)| json!({
            "server_id": id, "db_built": built, "last_match_at": matched,
            "last_error": if admin { error.clone() } else { None },
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct TargetQuery {
    pub include_resolved: Option<String>,
}

/// GET /api/vulnerabilities/targets/{id}
pub async fn target_detail(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<TargetQuery>,
) -> Result<Json<Value>, ApiError> {
    let include_resolved = bool_param("include_resolved", &q.include_resolved)?.unwrap_or(false);
    let target = visible_target(&state, &claims, id).await?;
    let mut findings: Vec<FindingRow> =
        sqlx::query_as(&format!("{FINDING_SELECT} WHERE f.target_id = $1 AND ($2::bool OR f.resolved_at IS NULL)"))
            .bind(id)
            .bind(include_resolved)
            .fetch_all(&state.db)
            .await
            .map_err(|e| internal_error("vulnerability target findings", e))?;
    sort_findings(&mut findings);
    Ok(Json(json!({
        "target": target.to_json(),
        "findings": findings.iter().map(FindingRow::to_json).collect::<Vec<_>>(),
    })))
}

/// POST /api/vulnerabilities/targets/{id}/scan -> 202 {"queued": true}
pub async fn scan_target(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let target = visible_target(&state, &claims, id).await?;
    if !get_setting_bool(&state.db, vuln_sweeper::SETTING_ENABLED, true).await {
        return Err(err(StatusCode::CONFLICT, "Vulnerability scanning is disabled"));
    }
    sqlx::query("UPDATE vuln_targets SET needs_inventory = TRUE WHERE id = $1")
        .bind(target.id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("queue vulnerability scan", e))?;
    if vuln_sweeper::try_queue_scan(target.id) {
        tokio::spawn(vuln_sweeper::scan_target_now(
            state.db.clone(),
            state.agents.clone(),
            target.id,
            state.shutdown_tx.subscribe(),
        ));
    }
    Ok((StatusCode::ACCEPTED, Json(json!({ "queued": true }))))
}

/// GET /api/vulnerabilities/settings (admin)
pub async fn get_settings(State(state): State<AppState>, AuthUser(claims): AuthUser) -> Result<Json<Value>, ApiError> {
    require_admin(&claims.role)?;
    let enabled = get_setting_bool(&state.db, vuln_sweeper::SETTING_ENABLED, true).await;
    let match_hour =
        get_setting_i64(&state.db, vuln_sweeper::SETTING_MATCH_HOUR, vuln_sweeper::DEFAULT_MATCH_HOUR).await.clamp(0, 23);
    Ok(Json(json!({ "enabled": enabled, "match_hour": match_hour })))
}

#[derive(Debug, Deserialize)]
pub struct SettingsBody {
    pub enabled: bool,
    pub match_hour: i64,
}

/// PUT /api/vulnerabilities/settings (admin)
pub async fn put_settings(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(body): Json<SettingsBody>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&claims.role)?;
    if !(0..=23).contains(&body.match_hour) {
        return Err(err(StatusCode::BAD_REQUEST, "match_hour must be 0..=23"));
    }
    let enabled = if body.enabled { "true" } else { "false" };
    let hour = body.match_hour.to_string();
    for (key, value) in [(vuln_sweeper::SETTING_ENABLED, enabled), (vuln_sweeper::SETTING_MATCH_HOUR, hour.as_str())] {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("save vulnerability scanner setting", e))?;
    }
    Ok(Json(json!({ "enabled": body.enabled, "match_hour": body.match_hour })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kev: bool, risk: Option<f32>, severity: &str, first_seen: &str) -> FindingRow {
        FindingRow {
            id: Uuid::new_v4(),
            target_id: Uuid::nil(),
            vuln_id: format!("{kev}-{risk:?}-{severity}-{first_seen}"),
            aliases: vec![],
            package: "p".into(),
            version: "1".into(),
            pkg_type: None,
            location: None,
            severity: severity.into(),
            cvss: None,
            kev,
            kev_ransomware: false,
            epss: None,
            epss_percentile: None,
            risk,
            fix_state: "unknown".into(),
            fixed_version: None,
            title: None,
            url: None,
            first_seen: DateTime::parse_from_rfc3339(first_seen).unwrap().with_timezone(&Utc),
            last_seen: Utc::now(),
            resolved_at: None,
            t_kind: "site".into(),
            t_ref: "a.example".into(),
            t_server_id: Uuid::nil(),
            t_server_name: "local".into(),
            t_site_id: None,
            t_app_name: None,
            t_git_deploy_id: None,
            t_exposed: Some(true),
        }
    }

    #[test]
    fn sort_puts_kev_then_risk_then_severity_then_newest() {
        let mut rows = vec![
            row(false, Some(50.0), "critical", "2026-11-01T00:00:00Z"),
            row(false, None, "critical", "2026-11-01T00:00:00Z"),
            row(true, Some(10.0), "low", "2026-11-01T00:00:00Z"),
            row(false, Some(90.0), "medium", "2026-11-01T00:00:00Z"),
            row(false, Some(50.0), "high", "2026-11-01T00:00:00Z"),
            row(false, Some(50.0), "high", "2026-11-05T00:00:00Z"),
        ];
        sort_findings(&mut rows);
        let got: Vec<(bool, Option<f32>, &str, u32)> = rows
            .iter()
            .map(|r| (r.kev, r.risk, r.severity.as_str(), chrono::Datelike::day(&r.first_seen)))
            .collect();
        assert_eq!(
            got,
            [
                (true, Some(10.0), "low", 1),
                (false, Some(90.0), "medium", 1),
                (false, Some(50.0), "critical", 1),
                (false, Some(50.0), "high", 5),
                (false, Some(50.0), "high", 1),
                (false, None, "critical", 1),
            ]
        );
    }

    fn q(pairs: &[(&str, &str)]) -> ListQuery {
        let mut q = ListQuery::default();
        for (k, v) in pairs {
            let v = Some(v.to_string());
            match *k {
                "severity" => q.severity = v,
                "kev" => q.kev = v,
                "kind" => q.kind = v,
                "server_id" => q.server_id = v,
                "target_id" => q.target_id = v,
                "fixable" => q.fixable = v,
                "include_resolved" => q.include_resolved = v,
                "limit" => q.limit = v,
                "offset" => q.offset = v,
                _ => unreachable!(),
            }
        }
        q
    }

    #[test]
    fn filters_treat_empty_values_as_absent() {
        let f = parse_filters(&q(&[("severity", ""), ("kev", ""), ("server_id", " "), ("limit", "")])).unwrap();
        assert_eq!(f.severity, None);
        assert_eq!(f.kev, None);
        assert_eq!(f.server_id, None);
        assert!(!f.include_resolved);
        assert_eq!((f.limit, f.offset), (100, 0));
    }

    #[test]
    fn filters_accept_allow_listed_values() {
        let id = Uuid::new_v4();
        let f = parse_filters(&q(&[
            ("severity", "Critical"),
            ("kev", "true"),
            ("kind", "image"),
            ("target_id", &id.to_string()),
            ("fixable", "0"),
            ("include_resolved", "1"),
            ("limit", "5000"),
        ]))
        .unwrap();
        assert_eq!(f.severity.as_deref(), Some("critical"));
        assert_eq!(f.kev, Some(true));
        assert_eq!(f.kind.as_deref(), Some("image"));
        assert_eq!(f.target_id, Some(id));
        assert_eq!(f.fixable, Some(false));
        assert!(f.include_resolved);
        assert_eq!(f.limit, 200);
    }

    #[test]
    fn filters_reject_values_outside_the_allow_lists() {
        for bad in [
            q(&[("severity", "'; DROP TABLE x; --")]),
            q(&[("kind", "container")]),
            q(&[("kev", "yes")]),
            q(&[("server_id", "not-a-uuid")]),
            q(&[("offset", "x")]),
        ] {
            let e = parse_filters(&bad).unwrap_err();
            assert_eq!(e.0, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn severity_sql_order_matches_rank() {
        for (i, s) in SEVERITIES.iter().enumerate() {
            assert_eq!(severity_rank(s) as usize, i);
            assert!(ORDER_SQL.contains(&format!("WHEN '{s}' THEN {i}")) || *s == "unknown");
        }
    }
}
