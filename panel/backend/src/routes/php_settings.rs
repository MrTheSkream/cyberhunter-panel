//! Per-site PHP settings — `conception/02-php-contrats.md` (A1 for the payload
//! sent to the agent, B1–B4 for the API).
//!
//! Storage: `sites.php_settings` (JSONB, overrides only:
//! `{ "values": {...}, "pool": {...}, "extra": [[k, v], ...] }`),
//! `php_isolation`, `php_disable_shell`, plus the pre-existing columns
//! `php_memory_mb` (memory_limit), `php_max_workers` (pm.max_children) and
//! `max_upload_mb` (default upload_max_filesize). `memory_limit` and
//! `max_children` live ONLY in their columns — never in the JSONB — so the
//! Limits form and this card can never shadow each other.
//!
//! Every `SiteConfig` sent for a PHP site carries `php_pool`, built by
//! [`php_pool_for_site`] / [`php_pool_json`] — the single constructor. The
//! builder is infallible on purpose: it runs from SSL renewal, the auto-healer
//! and the security scanner, so a malformed stored value is dropped (default
//! used) rather than allowed to fail an unrelated rebuild.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::auth::{AdminUser, AuthUser, ServerScope};
use crate::error::{agent_error, err, internal_error, ApiError};
use crate::models::Site;
use crate::services::activity;
use crate::AppState;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Size,
    Int,
    Bool,
    Choice,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Size => "size",
            Kind::Int => "int",
            Kind::Bool => "bool",
            Kind::Choice => "choice",
        }
    }
}

pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    /// Size: MB. Int: raw value. Unused for bool/choice.
    pub min: i64,
    pub max: i64,
}

/// The 12 settings of B1, in display order.
pub const FIELDS: &[Field] = &[
    Field { key: "memory_limit", label: "Memory limit", kind: Kind::Size, min: 32, max: 4096 },
    Field { key: "upload_max_filesize", label: "Max upload file size", kind: Kind::Size, min: 1, max: 2048 },
    Field { key: "post_max_size", label: "Max POST size", kind: Kind::Size, min: 1, max: 2048 },
    Field { key: "max_execution_time", label: "Max execution time (s)", kind: Kind::Int, min: 0, max: 3600 },
    Field { key: "max_input_time", label: "Max input time (s)", kind: Kind::Int, min: -1, max: 3600 },
    Field { key: "max_input_vars", label: "Max input vars", kind: Kind::Int, min: 1000, max: 100000 },
    Field { key: "display_errors", label: "Display errors", kind: Kind::Bool, min: 0, max: 0 },
    Field { key: "error_reporting", label: "Error reporting", kind: Kind::Choice, min: 0, max: 0 },
    Field { key: "date.timezone", label: "Timezone", kind: Kind::Choice, min: 0, max: 0 },
    Field { key: "short_open_tag", label: "Short open tag", kind: Kind::Bool, min: 0, max: 0 },
    Field { key: "allow_url_fopen", label: "Allow URL fopen", kind: Kind::Bool, min: 0, max: 0 },
    Field { key: "session.gc_maxlifetime", label: "Session lifetime (s)", kind: Kind::Int, min: 60, max: 604800 },
];

pub const ERROR_REPORTING_PRODUCTION: &str = "E_ALL & ~E_DEPRECATED & ~E_STRICT";

/// (value, label, alias accepted on input)
pub const ERROR_REPORTING_CHOICES: &[(&str, &str, &str)] = &[
    (ERROR_REPORTING_PRODUCTION, "Production", "production"),
    ("E_ALL", "Development", "development"),
    ("E_ERROR | E_PARSE", "Silent", "silent"),
];

pub const DEFAULT_TIMEZONE: &str = "Europe/Paris";

/// Curated IANA list (no chrono-tz dependency).
pub const TIMEZONES: &[&str] = &[
    "UTC",
    "Europe/Paris", "Europe/London", "Europe/Dublin", "Europe/Lisbon", "Europe/Madrid",
    "Europe/Brussels", "Europe/Amsterdam", "Europe/Luxembourg", "Europe/Monaco", "Europe/Zurich",
    "Europe/Berlin", "Europe/Rome", "Europe/Vienna", "Europe/Prague", "Europe/Warsaw",
    "Europe/Budapest", "Europe/Copenhagen", "Europe/Stockholm", "Europe/Oslo", "Europe/Helsinki",
    "Europe/Athens", "Europe/Bucharest", "Europe/Istanbul", "Europe/Kyiv", "Europe/Moscow",
    "Africa/Casablanca", "Africa/Algiers", "Africa/Tunis", "Africa/Cairo", "Africa/Dakar",
    "Africa/Abidjan", "Africa/Lagos", "Africa/Nairobi", "Africa/Johannesburg",
    "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix",
    "America/Los_Angeles", "America/Anchorage", "America/Toronto", "America/Vancouver",
    "America/Mexico_City", "America/Bogota", "America/Lima", "America/Caracas",
    "America/Santiago", "America/Sao_Paulo", "America/Argentina/Buenos_Aires",
    "America/Martinique", "America/Guadeloupe", "America/Cayenne",
    "Asia/Jerusalem", "Asia/Riyadh", "Asia/Dubai", "Asia/Tehran", "Asia/Karachi",
    "Asia/Kolkata", "Asia/Bangkok", "Asia/Jakarta", "Asia/Singapore", "Asia/Manila",
    "Asia/Hong_Kong", "Asia/Shanghai", "Asia/Seoul", "Asia/Tokyo",
    "Australia/Perth", "Australia/Brisbane", "Australia/Sydney", "Australia/Melbourne",
    "Pacific/Auckland", "Pacific/Noumea", "Pacific/Tahiti", "Pacific/Honolulu",
    "Indian/Reunion", "Indian/Mayotte", "Indian/Mauritius",
];

/// Keys an admin may never set through `extra` (A1): the security keys move
/// only through isolation / disable_shell, and the loaders are code execution.
pub const FORBIDDEN_EXTRA_KEYS: &[&str] = &[
    "extension", "zend_extension", "open_basedir", "disable_functions", "disable_classes",
    "auto_prepend_file", "auto_append_file", "sendmail_path", "error_log", "upload_tmp_dir",
    "session.save_path", "user_ini.filename", "doc_root", "include_path",
];

pub const MAX_EXTRA_ENTRIES: usize = 50;
pub const PM_MODES: &[&str] = &["ondemand", "dynamic", "static"];

/// `sites` column defaults (migration 20260312500000).
pub const COLUMN_DEFAULT_MEMORY_MB: i32 = 256;
pub const COLUMN_DEFAULT_MAX_WORKERS: i32 = 5;
pub const COLUMN_DEFAULT_MAX_UPLOAD_MB: i32 = 64;

/// The 8 php.ini keys the global editor (A2/A3) may set.
pub const INI_KEYS: &[&str] = &[
    "memory_limit", "max_execution_time", "max_input_time", "upload_max_filesize",
    "post_max_size", "display_errors", "error_reporting", "date.timezone",
];
pub const INI_CONTENT_MAX_BYTES: usize = 512 * 1024;

// ── pool bounds ────────────────────────────────────────────────────────────
// max_children follows `update_limits` (1–100) so the Limits form can always
// echo back what this card wrote; the agent itself accepts up to 1000.
const MAX_CHILDREN: (i64, i64) = (1, 100);
const MAX_REQUESTS: (i64, i64) = (0, 100_000);
const IDLE_TIMEOUT: (i64, i64) = (1, 3600);
const TERMINATE_TIMEOUT: (i64, i64) = (0, 86_400);

const DEFAULT_MAX_REQUESTS: i64 = 4000;
const DEFAULT_IDLE_S: i64 = 10;

fn field(key: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.key == key)
}

/// The row columns the PHP pool is computed from.
#[derive(Clone, Copy)]
pub struct PhpRow<'a> {
    pub settings: &'a Value,
    pub isolation: bool,
    pub disable_shell: bool,
    pub memory_mb: i32,
    pub max_workers: i32,
    pub max_upload_mb: i32,
}

impl<'a> PhpRow<'a> {
    pub fn of(site: &'a Site) -> Self {
        PhpRow {
            settings: &site.php_settings,
            isolation: site.php_isolation,
            disable_shell: site.php_disable_shell,
            memory_mb: site.php_memory_mb,
            max_workers: site.php_max_workers,
            max_upload_mb: site.max_upload_mb,
        }
    }
}

/// What a brand-new row holds (column defaults). Used by the importer, which
/// sends the vhost before the row exists.
pub static NEW_ROW_SETTINGS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| json!({}));

pub fn new_row() -> PhpRow<'static> {
    PhpRow {
        settings: &NEW_ROW_SETTINGS,
        isolation: true,
        disable_shell: true,
        memory_mb: COLUMN_DEFAULT_MEMORY_MB,
        max_workers: COLUMN_DEFAULT_MAX_WORKERS,
        max_upload_mb: COLUMN_DEFAULT_MAX_UPLOAD_MB,
    }
}

// ── normalisation / validation ─────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

fn ferr(field: &str, message: impl Into<String>) -> FieldError {
    FieldError { field: field.to_string(), message: message.into() }
}

/// "256M" / "2G" (case-insensitive) → MB. Nothing else.
pub fn size_mb(raw: &str) -> Option<i64> {
    let s = raw.trim().to_ascii_uppercase();
    let (num, mult) = if let Some(n) = s.strip_suffix('M') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('G') {
        (n, 1024)
    } else {
        return None;
    };
    if num.is_empty() || num.len() > 6 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse::<i64>().ok().map(|n| n * mult)
}

/// Validate one of the 12 keys and return its canonical form.
pub fn normalize_value(key: &str, raw: &str) -> Result<String, FieldError> {
    let f = field(key).ok_or_else(|| ferr(key, format!("Unknown PHP setting '{key}'")))?;
    let raw = raw.trim();
    match f.kind {
        Kind::Size => {
            let mb = size_mb(raw).ok_or_else(|| {
                ferr(key, format!("{} must be a size like 256M", f.label))
            })?;
            if mb < f.min || mb > f.max {
                return Err(ferr(key, format!("{} must be between {}M and {}M", f.label, f.min, f.max)));
            }
            Ok(format!("{mb}M"))
        }
        Kind::Int => {
            let n: i64 = raw
                .parse()
                .map_err(|_| ferr(key, format!("{} must be a whole number", f.label)))?;
            if n < f.min || n > f.max {
                return Err(ferr(key, format!("{} must be between {} and {}", f.label, f.min, f.max)));
            }
            Ok(n.to_string())
        }
        Kind::Bool => match raw.to_ascii_lowercase().as_str() {
            "on" | "1" | "true" | "yes" => Ok("On".into()),
            "off" | "0" | "false" | "no" => Ok("Off".into()),
            _ => Err(ferr(key, format!("{} must be On or Off", f.label))),
        },
        Kind::Choice => {
            if key == "error_reporting" {
                ERROR_REPORTING_CHOICES
                    .iter()
                    .find(|(v, _, alias)| *v == raw || alias.eq_ignore_ascii_case(raw))
                    .map(|(v, _, _)| v.to_string())
                    .ok_or_else(|| ferr(key, "Error reporting must be one of the predefined levels"))
            } else {
                TIMEZONES
                    .iter()
                    .find(|tz| **tz == raw)
                    .map(|tz| tz.to_string())
                    .ok_or_else(|| ferr(key, format!("Unsupported timezone '{raw}'")))
            }
        }
    }
}

fn extra_key_ok(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.')
}

/// A1 character rules for a value written verbatim into the pool file.
pub fn safe_ini_value(v: &str) -> bool {
    // Same as the agent's `validate_value`: any control char (\n, \r, \t, NUL…) refused.
    v.len() <= 256 && !v.chars().any(|c| matches!(c, '[' | ']' | ';' | '"') || c.is_control())
}

pub fn validate_extra_entry(k: &str, v: &str) -> Result<(), FieldError> {
    if !extra_key_ok(k) {
        return Err(ferr("extra", format!("Invalid directive name '{k}'")));
    }
    if FORBIDDEN_EXTRA_KEYS.contains(&k) {
        return Err(ferr("extra", format!("'{k}' cannot be set as an extra directive")));
    }
    if field(k).is_some() {
        return Err(ferr("extra", format!("'{k}' is a managed setting — set it in the form above")));
    }
    if !safe_ini_value(v) {
        return Err(ferr(
            "extra",
            format!("Value of '{k}' must be at most 256 characters without line breaks, [ ] ; or \""),
        ));
    }
    Ok(())
}

pub fn validate_extra(entries: &[(String, String)]) -> Result<(), FieldError> {
    if entries.len() > MAX_EXTRA_ENTRIES {
        return Err(ferr("extra", format!("At most {MAX_EXTRA_ENTRIES} extra directives")));
    }
    let mut seen = std::collections::HashSet::new();
    for (k, v) in entries {
        validate_extra_entry(k, v)?;
        if !seen.insert(k.as_str()) {
            return Err(ferr("extra", format!("Directive '{k}' is listed twice")));
        }
    }
    Ok(())
}

// ── stored overrides (defensive reads) ─────────────────────────────────────

/// Stored per-site overrides, re-validated: an invalid stored value is
/// dropped (the default applies) rather than sent to the agent.
/// `memory_limit` is never read from here — it lives in `php_memory_mb`.
pub fn stored_values(settings: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(obj) = settings.get("values").and_then(Value::as_object) {
        for (k, v) in obj {
            if k == "memory_limit" {
                continue;
            }
            if let Some(s) = v.as_str()
                && let Ok(norm) = normalize_value(k, s)
            {
                out.insert(k.clone(), norm);
            }
        }
    }
    out
}

pub fn stored_extra(settings: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(arr) = settings.get("extra").and_then(Value::as_array) {
        for e in arr {
            let (Some(k), Some(v)) = (
                e.get(0).and_then(Value::as_str),
                e.get(1).and_then(Value::as_str),
            ) else {
                continue;
            };
            if out.len() < MAX_EXTRA_ENTRIES
                && validate_extra_entry(k, v).is_ok()
                && !out.iter().any(|(ek, _)| ek == k)
            {
                out.push((k.to_string(), v.to_string()));
            }
        }
    }
    out
}

fn stored_pool_int(settings: &Value, key: &str, (lo, hi): (i64, i64)) -> Option<i64> {
    settings
        .get("pool")
        .and_then(|p| p.get(key))
        .and_then(Value::as_i64)
        .filter(|n| *n >= lo && *n <= hi)
}

fn stored_pm(settings: &Value) -> Option<String> {
    settings
        .get("pool")
        .and_then(|p| p.get("pm"))
        .and_then(Value::as_str)
        .filter(|s| PM_MODES.contains(s))
        .map(str::to_string)
}

/// D1 / C bis: a site that existed before this feature carries
/// `"legacy": true` in its JSONB. Its pool only sets `memory_limit` plus the
/// keys explicitly overridden in `values`; every other key is inherited from
/// the global php.ini, exactly as the pre-feature pool did. Only an admin can
/// clear the flag (`PUT {legacy: false}`), never set it.
pub fn is_legacy(settings: &Value) -> bool {
    settings.get("legacy").and_then(Value::as_bool) == Some(true)
}

// ── defaults / effective values ────────────────────────────────────────────

/// B1 defaults. `memory_limit`'s default is the column default (256M): the
/// site's own `php_memory_mb` is its value, not its default. Upload follows
/// the nginx limit `max_upload_mb` (not clamped to the 2048 form bound —
/// bounds apply to overrides only, and `update_limits` allows up to 10240).
pub fn defaults(max_upload_mb: i32) -> BTreeMap<String, String> {
    let upload = i64::from(max_upload_mb.max(1));
    let mut d = BTreeMap::new();
    d.insert("memory_limit".into(), format!("{COLUMN_DEFAULT_MEMORY_MB}M"));
    d.insert("upload_max_filesize".into(), format!("{upload}M"));
    d.insert("post_max_size".into(), format!("{}M", upload + 8));
    d.insert("max_execution_time".into(), "60".into());
    d.insert("max_input_time".into(), "60".into());
    d.insert("max_input_vars".into(), "4000".into());
    d.insert("display_errors".into(), "Off".into());
    d.insert("error_reporting".into(), ERROR_REPORTING_PRODUCTION.into());
    d.insert("date.timezone".into(), DEFAULT_TIMEZONE.into());
    d.insert("short_open_tag".into(), "Off".into());
    d.insert("allow_url_fopen".into(), "On".into());
    d.insert("session.gc_maxlifetime".into(), "1440".into());
    d
}

/// Values applied to the pool: overrides on top of defaults, memory from the
/// column, post_max_size never below upload_max_filesize.
///
/// Legacy rows ([`is_legacy`]): no code defaults — only memory_limit, the
/// stored overrides and, when upload is overridden but post is not, the
/// derived post_max_size (a post inherited from php.ini could be below the
/// upload the site asked for). Every other key is absent = global php.ini.
pub fn effective_values(row: &PhpRow) -> BTreeMap<String, String> {
    let stored = stored_values(row.settings);
    let legacy = is_legacy(row.settings);
    let mut eff = if legacy { BTreeMap::new() } else { defaults(row.max_upload_mb) };
    for (k, v) in &stored {
        eff.insert(k.clone(), v.clone());
    }
    eff.insert("memory_limit".into(), format!("{}M", row.memory_mb.max(1)));
    let Some(upload) = eff.get("upload_max_filesize").and_then(|s| size_mb(s)) else {
        return eff; // legacy row with upload inherited: post stays as stored / inherited
    };
    if !stored.contains_key("post_max_size") {
        eff.insert("post_max_size".into(), format!("{}M", upload + 8));
    } else {
        let post = eff.get("post_max_size").and_then(|s| size_mb(s)).unwrap_or(0);
        if post < upload {
            eff.insert("post_max_size".into(), format!("{upload}M"));
        }
    }
    eff
}

/// Keys of the 12 not sent to the agent (legacy rows only): they come from
/// the global php.ini of the site's PHP version.
pub fn inherits_global(eff: &BTreeMap<String, String>) -> Vec<&'static str> {
    FIELDS.iter().map(|f| f.key).filter(|k| !eff.contains_key(*k)).collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pool {
    pub pm: String,
    pub max_children: i64,
    pub max_requests: i64,
    pub idle_timeout_s: i64,
    pub request_terminate_timeout_s: i64,
}

impl Pool {
    fn to_json(&self) -> Value {
        json!({
            "pm": self.pm,
            "max_children": self.max_children,
            "max_requests": self.max_requests,
            "idle_timeout_s": self.idle_timeout_s,
            "request_terminate_timeout_s": self.request_terminate_timeout_s,
        })
    }
}

/// Default request_terminate_timeout: max_execution_time + 30. For
/// max_execution_time = 0 (unlimited) the literal formula would kill every
/// request after 30 s, so the cap becomes the highest allowed
/// max_execution_time + 30 instead (also keeps nginx's fastcgi_read_timeout
/// non-zero).
pub fn default_terminate(max_execution_time: i64) -> i64 {
    if max_execution_time <= 0 { 3600 + 30 } else { max_execution_time + 30 }
}

pub fn effective_pool(row: &PhpRow, eff: &BTreeMap<String, String>) -> Pool {
    // max_execution_time inherited from php.ini (legacy row): unknown, so the
    // derived terminate uses the widest cap rather than guessing 60 s.
    let met: i64 = eff.get("max_execution_time").and_then(|s| s.parse().ok()).unwrap_or(0);
    Pool {
        pm: stored_pm(row.settings).unwrap_or_else(|| "ondemand".into()),
        max_children: i64::from(row.max_workers).clamp(MAX_CHILDREN.0, MAX_CHILDREN.1),
        max_requests: stored_pool_int(row.settings, "max_requests", MAX_REQUESTS).unwrap_or(DEFAULT_MAX_REQUESTS),
        idle_timeout_s: stored_pool_int(row.settings, "idle_timeout_s", IDLE_TIMEOUT).unwrap_or(DEFAULT_IDLE_S),
        request_terminate_timeout_s: stored_pool_int(row.settings, "request_terminate_timeout_s", TERMINATE_TIMEOUT)
            .unwrap_or_else(|| default_terminate(met)),
    }
}

/// THE `php_pool` constructor (A1): full effective values, defaults included —
/// except for legacy rows, whose `values` omit the keys inherited from the
/// global php.ini (C bis).
pub fn php_pool_json(row: &PhpRow) -> Value {
    let eff = effective_values(row);
    let pool = effective_pool(row, &eff);
    let extra: Vec<Value> = stored_extra(row.settings)
        .into_iter()
        .map(|(k, v)| json!([k, v]))
        .collect();
    json!({
        "values": eff,
        "isolation": row.isolation,
        "disable_shell": row.disable_shell,
        "pm": pool.pm,
        "max_children": pool.max_children,
        "max_requests": pool.max_requests,
        "idle_timeout_s": pool.idle_timeout_s,
        "request_terminate_timeout_s": pool.request_terminate_timeout_s,
        "extra": extra,
    })
}

/// Whether the agent writes an FPM pool for this site: a PHP-runtime site
/// with a version (the same condition that makes `build_nginx_body` send
/// `php_socket`).
pub fn is_php_site(site: &Site) -> bool {
    site.runtime == "php" && site.php_version.is_some()
}

/// `php_pool` for a `SiteConfig`, or `None` (legacy behaviour) for non-PHP sites.
pub fn php_pool_for_site(site: &Site) -> Option<Value> {
    is_php_site(site).then(|| php_pool_json(&PhpRow::of(site)))
}

// ── B1 response ────────────────────────────────────────────────────────────

pub fn fields_json() -> Value {
    let list: Vec<Value> = FIELDS
        .iter()
        .map(|f| {
            let mut o = json!({ "key": f.key, "label": f.label, "kind": f.kind.as_str() });
            match f.kind {
                Kind::Size | Kind::Int => {
                    o["min"] = json!(f.min);
                    o["max"] = json!(f.max);
                }
                Kind::Choice if f.key == "error_reporting" => {
                    o["choices"] = ERROR_REPORTING_CHOICES
                        .iter()
                        .map(|(v, l, _)| json!({ "value": v, "label": l }))
                        .collect();
                }
                Kind::Choice => {
                    o["choices"] = TIMEZONES.iter().map(|tz| json!({ "value": tz, "label": tz })).collect();
                }
                Kind::Bool => {}
            }
            o
        })
        .collect();
    Value::Array(list)
}

pub fn response_json(site: &Site, can_admin: bool) -> Value {
    let row = PhpRow::of(site);
    let mut values = stored_values(row.settings);
    if row.memory_mb != COLUMN_DEFAULT_MEMORY_MB {
        values.insert("memory_limit".into(), format!("{}M", row.memory_mb));
    }
    let eff = effective_values(&row);
    let pool = effective_pool(&row, &eff);
    let extra: Vec<Value> = stored_extra(row.settings).into_iter().map(|(k, v)| json!([k, v])).collect();
    let legacy = is_legacy(row.settings);
    // Legacy: resetting a key re-inherits php.ini, so no code default is
    // claimed for anything but memory_limit (column default).
    let mut defs = defaults(row.max_upload_mb);
    if legacy {
        defs.retain(|k, _| k == "memory_limit");
    }
    json!({
        "php_version": site.php_version,
        "can_admin": can_admin,
        "legacy": legacy,
        "inherits_global": inherits_global(&eff),
        "values": values,
        "effective": eff,
        "defaults": defs,
        "fields": fields_json(),
        "isolation": row.isolation,
        "disable_shell": row.disable_shell,
        "pool": pool.to_json(),
        "extra": extra,
    })
}

// ── B2 update (pure) ───────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum UpdateError {
    /// 403 — an owner sent an admin-only field.
    Forbidden(String),
    /// 400 `{error, field}`.
    Invalid(FieldError),
}

impl From<FieldError> for UpdateError {
    fn from(e: FieldError) -> Self {
        UpdateError::Invalid(e)
    }
}

#[derive(Debug, PartialEq)]
pub struct Applied {
    pub settings: Value,
    pub isolation: bool,
    pub disable_shell: bool,
    pub memory_mb: i32,
    pub max_workers: i32,
}

const TOP_LEVEL_KEYS: &[&str] = &["values", "isolation", "disable_shell", "pool", "extra", "legacy"];

/// Owner may send only `values`; any other top-level key is admin-only (403).
pub fn forbidden_field(body: &Map<String, Value>, is_admin: bool) -> Option<String> {
    if is_admin {
        return None;
    }
    body.keys().find(|k| k.as_str() != "values").cloned()
}

fn as_text(field: &str, v: &Value) -> Result<String, FieldError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(if *b { "On".into() } else { "Off".into() }),
        _ => Err(ferr(field, "Value must be a string")),
    }
}

fn int_in(field: &str, v: &Value, (lo, hi): (i64, i64)) -> Result<i64, FieldError> {
    v.as_i64()
        .filter(|n| *n >= lo && *n <= hi)
        .ok_or_else(|| ferr(field, format!("Must be a whole number between {lo} and {hi}")))
}

/// Apply a B2 body to the current row. Pure: no I/O, all validation here.
pub fn apply_update(row: &PhpRow, body: &Map<String, Value>, is_admin: bool) -> Result<Applied, UpdateError> {
    if let Some(f) = forbidden_field(body, is_admin) {
        return Err(UpdateError::Forbidden(f));
    }
    if let Some(k) = body.keys().find(|k| !TOP_LEVEL_KEYS.contains(&k.as_str())) {
        return Err(ferr(k, format!("Unknown field '{k}'")).into());
    }

    let mut values = stored_values(row.settings);
    let mut pool: Map<String, Value> = Map::new();
    if let Some(pm) = stored_pm(row.settings) {
        pool.insert("pm".into(), json!(pm));
    }
    for (k, b) in [("max_requests", MAX_REQUESTS), ("idle_timeout_s", IDLE_TIMEOUT), ("request_terminate_timeout_s", TERMINATE_TIMEOUT)] {
        if let Some(n) = stored_pool_int(row.settings, k, b) {
            pool.insert(k.into(), json!(n));
        }
    }
    let mut extra = stored_extra(row.settings);
    let mut memory_mb = row.memory_mb;
    let mut max_workers = row.max_workers;
    let mut isolation = row.isolation;
    let mut disable_shell = row.disable_shell;
    // Preserved across every PUT; only an admin `legacy: false` clears it.
    let mut legacy = is_legacy(row.settings);
    if let Some(v) = body.get("legacy") {
        if v.as_bool() != Some(false) {
            return Err(ferr("legacy", "legacy can only be set to false (switch to panel defaults)").into());
        }
        legacy = false;
    }

    let mut touched_sizes = false;
    if let Some(v) = body.get("values") {
        let obj = v.as_object().ok_or_else(|| ferr("values", "values must be an object"))?;
        for (k, v) in obj {
            if field(k).is_none() {
                return Err(ferr(k, format!("Unknown PHP setting '{k}'")).into());
            }
            if k == "upload_max_filesize" || k == "post_max_size" {
                touched_sizes = true;
            }
            if v.is_null() {
                if k == "memory_limit" {
                    memory_mb = COLUMN_DEFAULT_MEMORY_MB;
                } else {
                    values.remove(k);
                }
                continue;
            }
            let norm = normalize_value(k, &as_text(k, v)?)?;
            if k == "memory_limit" {
                memory_mb = size_mb(&norm).unwrap_or(i64::from(COLUMN_DEFAULT_MEMORY_MB)) as i32;
            } else {
                values.insert(k.clone(), norm);
            }
        }
    }
    if touched_sizes {
        // Legacy row with upload inherited from php.ini: unknown, not checked.
        let upload = values
            .get("upload_max_filesize")
            .and_then(|s| size_mb(s))
            .or((!legacy).then(|| i64::from(row.max_upload_mb.max(1))));
        if let (Some(upload), Some(post)) = (upload, values.get("post_max_size").and_then(|s| size_mb(s)))
            && post < upload
        {
            return Err(ferr("post_max_size", "Max POST size must be at least the max upload file size").into());
        }
    }

    if let Some(v) = body.get("isolation") {
        isolation = v.as_bool().ok_or_else(|| ferr("isolation", "isolation must be true or false"))?;
    }
    if let Some(v) = body.get("disable_shell") {
        disable_shell = v.as_bool().ok_or_else(|| ferr("disable_shell", "disable_shell must be true or false"))?;
    }
    if let Some(v) = body.get("pool") {
        let obj = v.as_object().ok_or_else(|| ferr("pool", "pool must be an object"))?;
        for (k, v) in obj {
            let name = format!("pool.{k}");
            match k.as_str() {
                "pm" => {
                    if v.is_null() {
                        pool.remove("pm");
                    } else {
                        let pm = v.as_str().filter(|s| PM_MODES.contains(s)).ok_or_else(|| {
                            ferr(&name, "pm must be ondemand, dynamic or static")
                        })?;
                        pool.insert("pm".into(), json!(pm));
                    }
                }
                "max_children" => {
                    max_workers = if v.is_null() {
                        COLUMN_DEFAULT_MAX_WORKERS
                    } else {
                        int_in(&name, v, MAX_CHILDREN)? as i32
                    };
                }
                "max_requests" | "idle_timeout_s" | "request_terminate_timeout_s" => {
                    let bounds = match k.as_str() {
                        "max_requests" => MAX_REQUESTS,
                        "idle_timeout_s" => IDLE_TIMEOUT,
                        _ => TERMINATE_TIMEOUT,
                    };
                    if v.is_null() {
                        pool.remove(k);
                    } else {
                        pool.insert(k.clone(), json!(int_in(&name, v, bounds)?));
                    }
                }
                _ => return Err(ferr(&name, format!("Unknown pool field '{k}'")).into()),
            }
        }
    }
    if let Some(v) = body.get("extra") {
        let arr = v.as_array().ok_or_else(|| ferr("extra", "extra must be a list of [key, value] pairs"))?;
        let mut list = Vec::with_capacity(arr.len());
        for e in arr {
            let pair = e.as_array().filter(|p| p.len() == 2);
            let (Some(k), Some(val)) = (
                pair.and_then(|p| p[0].as_str()),
                pair.and_then(|p| p[1].as_str()),
            ) else {
                return Err(ferr("extra", "Each extra directive must be a [key, value] pair of strings").into());
            };
            list.push((k.trim().to_string(), val.trim().to_string()));
        }
        validate_extra(&list)?;
        extra = list;
    }

    let mut settings = Map::new();
    if legacy {
        settings.insert("legacy".into(), json!(true));
    }
    if !values.is_empty() {
        settings.insert("values".into(), json!(values));
    }
    if !pool.is_empty() {
        settings.insert("pool".into(), Value::Object(pool));
    }
    if !extra.is_empty() {
        settings.insert(
            "extra".into(),
            Value::Array(extra.into_iter().map(|(k, v)| json!([k, v])).collect()),
        );
    }
    Ok(Applied { settings: Value::Object(settings), isolation, disable_shell, memory_mb, max_workers })
}

fn update_error(e: UpdateError) -> ApiError {
    match e {
        UpdateError::Forbidden(f) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only an administrator can change this setting", "field": f })),
        ),
        UpdateError::Invalid(fe) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": fe.message, "field": fe.field })),
        ),
    }
}

// ── handlers ───────────────────────────────────────────────────────────────

async fn site_for_caller(state: &AppState, id: Uuid, claims: &crate::auth::Claims) -> Result<Site, ApiError> {
    sqlx::query_as::<_, Site>(&format!(
        "SELECT s.* FROM sites s WHERE {}",
        crate::helpers::SITE_CALLER_PREDICATE
    ))
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("php settings", e))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Site not found"))
}

/// GET /api/sites/{id}/php-settings — owner or admin (B1).
pub async fn get_site_php_settings(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let site = site_for_caller(&state, id, &claims).await?;
    Ok(Json(response_json(&site, claims.role == "admin")))
}

/// PUT /api/sites/{id}/php-settings — owner: `values` only; admin: all (B2).
///
/// Columns are written inside a transaction, the agent rebuilds vhost + pool
/// from the updated row, and the transaction commits only if the agent
/// accepted it (a failed `php-fpm -t` leaves the database untouched).
pub async fn put_site_php_settings(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let obj = body
        .as_object()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Body must be a JSON object"))?;
    let site = site_for_caller(&state, id, &claims).await?;
    let is_admin = claims.role == "admin";
    if let Some(f) = forbidden_field(obj, is_admin) {
        return Err(update_error(UpdateError::Forbidden(f)));
    }
    if !is_php_site(&site) {
        return Err(err(StatusCode::BAD_REQUEST, "PHP settings only apply to PHP sites"));
    }
    let applied = apply_update(&PhpRow::of(&site), obj, is_admin).map_err(update_error)?;
    let agent = crate::helpers::agent_for_site_server(&state, site.server_id, &site.domain).await?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal_error("php settings tx", e))?;
    let updated: Site = sqlx::query_as(
        "UPDATE sites SET php_settings = $1, php_isolation = $2, php_disable_shell = $3, \
         php_memory_mb = $4, php_max_workers = $5, updated_at = NOW() WHERE id = $6 RETURNING *",
    )
    .bind(&applied.settings)
    .bind(applied.isolation)
    .bind(applied.disable_shell)
    .bind(applied.memory_mb)
    .bind(applied.max_workers)
    .bind(site.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal_error("php settings update", e))?;

    let bind_ip = crate::services::server_ips::nginx_bind_ip(&state.db, &updated).await;
    agent
        .put(
            &format!("/nginx/sites/{}", site.domain),
            crate::routes::sites::build_nginx_body(&updated, bind_ip.as_deref()),
        )
        .await
        .map_err(|e| agent_error("PHP settings", e))?; // tx dropped → rolled back

    tx.commit().await.map_err(|e| internal_error("php settings commit", e))?;

    let changed: Vec<String> = obj
        .iter()
        .flat_map(|(k, v)| match (k.as_str(), v.as_object()) {
            ("values", Some(m)) | ("pool", Some(m)) => m.keys().cloned().collect::<Vec<_>>(),
            _ => vec![k.clone()],
        })
        .collect();
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "site.php_settings",
        Some("site"), Some(&site.domain), Some(&changed.join(", ")), None,
        claims.key_id,
    )
    .await;

    Ok(Json(response_json(&updated, is_admin)))
}

fn checked_version(version: &str) -> Result<&str, ApiError> {
    let v = version.trim();
    if crate::routes::sites::PHP_VERSIONS.contains(&v) {
        Ok(v)
    } else {
        Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Invalid PHP version. Allowed: {}", crate::routes::sites::PHP_VERSIONS.join(", ")),
        ))
    }
}

/// Validate an A3 body: exactly one of `content` (≤ 512 KiB) / `values`
/// (keys among the 8 of A2, A1 character rules).
pub fn validate_ini_body(body: &Value) -> Result<Value, FieldError> {
    let obj = body.as_object().ok_or_else(|| ferr("content", "Body must be a JSON object"))?;
    if let Some(k) = obj.keys().find(|k| k.as_str() != "content" && k.as_str() != "values") {
        return Err(ferr(k, format!("Unknown field '{k}'")));
    }
    match (obj.get("content"), obj.get("values")) {
        (Some(c), None) => {
            let c = c.as_str().ok_or_else(|| ferr("content", "content must be a string"))?;
            if c.len() > INI_CONTENT_MAX_BYTES {
                return Err(ferr("content", "php.ini must be at most 512 KiB"));
            }
            Ok(json!({ "content": c }))
        }
        (None, Some(v)) => {
            let m = v.as_object().ok_or_else(|| ferr("values", "values must be an object"))?;
            if m.is_empty() {
                return Err(ferr("values", "No value to change"));
            }
            let mut out = Map::new();
            for (k, v) in m {
                if !INI_KEYS.contains(&k.as_str()) {
                    return Err(ferr(k, format!("'{k}' cannot be edited here")));
                }
                let s = as_text(k, v)?;
                let s = s.trim();
                if s.is_empty() || !safe_ini_value(s) {
                    return Err(ferr(k, "Value must be at most 256 characters without line breaks, [ ] ; or \""));
                }
                out.insert(k.clone(), json!(s));
            }
            Ok(json!({ "values": out }))
        }
        _ => Err(ferr("content", "Send either content or values")),
    }
}

/// GET /api/php/ini/{version} — admin (B3, proxies A2).
pub async fn get_php_ini(
    State(_state): State<AppState>,
    AdminUser(_claims): AdminUser,
    ServerScope(_server_id, agent): ServerScope,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let v = checked_version(&version)?;
    let res = agent
        .get(&format!("/php/ini/{v}"))
        .await
        .map_err(|e| agent_error("Read php.ini", e))?;
    Ok(Json(res))
}

/// PUT /api/php/ini/{version} — admin (B3, proxies A3). The agent tests the
/// file and restarts FPM, so this gets a long budget.
pub async fn put_php_ini(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    ServerScope(server_id, agent): ServerScope,
    Path(version): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let v = checked_version(&version)?.to_string();
    let payload = validate_ini_body(&body).map_err(|fe| update_error(UpdateError::Invalid(fe)))?;
    let details = match payload.get("values").and_then(Value::as_object) {
        Some(m) => m.keys().cloned().collect::<Vec<_>>().join(", "),
        None => "raw content".to_string(),
    };
    let res = agent
        .put_long(&format!("/php/ini/{v}"), payload, 120)
        .await
        .map_err(|e| agent_error("Update php.ini", e))?;
    activity::log_activity_on_server(
        &state.db, claims.sub, &claims.email, "php.ini_update",
        Some("php"), Some(&v), Some(&details), None, Some(server_id), claims.key_id,
    )
    .await;
    Ok(Json(res))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(settings: &Value) -> PhpRow<'_> {
        PhpRow { settings, isolation: true, disable_shell: true, memory_mb: 256, max_workers: 5, max_upload_mb: 64 }
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn default_new_site_pool() {
        let s = json!({});
        let p = php_pool_json(&row(&s));
        assert_eq!(p["values"]["memory_limit"], "256M");
        assert_eq!(p["values"]["upload_max_filesize"], "64M");
        assert_eq!(p["values"]["post_max_size"], "72M");
        assert_eq!(p["values"]["max_execution_time"], "60");
        assert_eq!(p["values"]["max_input_time"], "60");
        assert_eq!(p["values"]["max_input_vars"], "4000");
        assert_eq!(p["values"]["display_errors"], "Off");
        assert_eq!(p["values"]["error_reporting"], ERROR_REPORTING_PRODUCTION);
        assert_eq!(p["values"]["date.timezone"], "Europe/Paris");
        assert_eq!(p["values"]["short_open_tag"], "Off");
        assert_eq!(p["values"]["allow_url_fopen"], "On");
        assert_eq!(p["values"]["session.gc_maxlifetime"], "1440");
        assert_eq!(p["values"].as_object().unwrap().len(), 12);
        assert_eq!(p["isolation"], true);
        assert_eq!(p["disable_shell"], true);
        assert_eq!(p["pm"], "ondemand");
        assert_eq!(p["max_children"], 5);
        assert_eq!(p["max_requests"], 4000);
        assert_eq!(p["idle_timeout_s"], 10);
        assert_eq!(p["request_terminate_timeout_s"], 90);
        assert_eq!(p["extra"], json!([]));
    }

    #[test]
    fn overrides_and_derived_values() {
        let s = json!({ "values": { "upload_max_filesize": "128M", "max_execution_time": "120",
            "memory_limit": "999M", "bogus": "x", "display_errors": "maybe" },
            "pool": { "pm": "static", "max_requests": 10, "idle_timeout_s": 999999 },
            "extra": [["opcache.memory_consumption", "256"], ["extension", "evil.so"], ["bad"]] });
        let mut r = row(&s);
        r.memory_mb = 512;
        r.max_workers = 8;
        let p = php_pool_json(&r);
        // memory comes from the column only
        assert_eq!(p["values"]["memory_limit"], "512M");
        assert_eq!(p["values"]["upload_max_filesize"], "128M");
        assert_eq!(p["values"]["post_max_size"], "136M");
        // invalid stored value dropped → default
        assert_eq!(p["values"]["display_errors"], "Off");
        assert!(p["values"].get("bogus").is_none());
        assert_eq!(p["pm"], "static");
        assert_eq!(p["max_children"], 8);
        assert_eq!(p["max_requests"], 10);
        assert_eq!(p["idle_timeout_s"], 10); // out of range → default
        assert_eq!(p["request_terminate_timeout_s"], 150);
        assert_eq!(p["extra"], json!([["opcache.memory_consumption", "256"]]));
    }

    #[test]
    fn post_never_below_upload_and_unlimited_execution() {
        let s = json!({ "values": { "post_max_size": "16M", "max_execution_time": "0" } });
        let p = php_pool_json(&row(&s));
        assert_eq!(p["values"]["post_max_size"], "64M");
        assert_eq!(p["request_terminate_timeout_s"], 3630);
        // nginx upload above the 2048 form bound is still honoured as a default
        let e = json!({});
        let mut r = row(&e);
        r.max_upload_mb = 5000;
        assert_eq!(php_pool_json(&r)["values"]["upload_max_filesize"], "5000M");
        r.max_upload_mb = 0;
        assert_eq!(php_pool_json(&r)["values"]["upload_max_filesize"], "1M");
    }

    #[test]
    fn legacy_rows_and_non_php_sites() {
        let s = json!({});
        let mut r = row(&s);
        r.isolation = false;
        r.disable_shell = false;
        let p = php_pool_json(&r);
        assert_eq!(p["isolation"], false);
        assert_eq!(p["disable_shell"], false);
        let n = new_row();
        assert!(n.isolation && n.disable_shell);
        assert_eq!(php_pool_json(&n)["values"]["upload_max_filesize"], "64M");
    }

    #[test]
    fn normalisation_rules() {
        assert_eq!(normalize_value("memory_limit", "512m").unwrap(), "512M");
        assert_eq!(normalize_value("memory_limit", " 2G ").unwrap(), "2048M");
        assert!(normalize_value("memory_limit", "16M").is_err());
        assert!(normalize_value("memory_limit", "5G").is_err());
        assert!(normalize_value("memory_limit", "512").is_err());
        assert!(normalize_value("memory_limit", "512K").is_err());
        assert!(normalize_value("memory_limit", "-1M").is_err());
        assert!(normalize_value("memory_limit", "256é").is_err());
        assert!(normalize_value("memory_limit", "２５６Ｍ").is_err());
        assert!(normalize_value("memory_limit", "M").is_err());
        assert!(normalize_value("memory_limit", "").is_err());
        // A hand-edited stored non-ASCII value must not panic the builder.
        let s = json!({ "values": { "upload_max_filesize": "128é", "post_max_size": "２Ｇ" } });
        assert_eq!(php_pool_json(&row(&s))["values"]["upload_max_filesize"], "64M");
        assert!(normalize_value("upload_max_filesize", "0M").is_err());
        assert_eq!(normalize_value("max_input_time", "-1").unwrap(), "-1");
        assert!(normalize_value("max_input_time", "-2").is_err());
        assert!(normalize_value("max_execution_time", "3601").is_err());
        assert!(normalize_value("max_execution_time", "1.5").is_err());
        assert!(normalize_value("max_input_vars", "999").is_err());
        assert!(normalize_value("session.gc_maxlifetime", "604801").is_err());
        assert_eq!(normalize_value("display_errors", "on").unwrap(), "On");
        assert_eq!(normalize_value("allow_url_fopen", "0").unwrap(), "Off");
        assert!(normalize_value("short_open_tag", "maybe").is_err());
        assert_eq!(normalize_value("error_reporting", "development").unwrap(), "E_ALL");
        assert_eq!(normalize_value("error_reporting", "E_ERROR | E_PARSE").unwrap(), "E_ERROR | E_PARSE");
        assert!(normalize_value("error_reporting", "E_ALL;").is_err());
        assert_eq!(normalize_value("date.timezone", "UTC").unwrap(), "UTC");
        assert!(normalize_value("date.timezone", "Mars/Olympus").is_err());
        let e = normalize_value("nope", "1").unwrap_err();
        assert_eq!(e.field, "nope");
    }

    #[test]
    fn extra_rules() {
        assert!(validate_extra_entry("opcache.enable", "1").is_ok());
        assert!(validate_extra_entry("Opcache.enable", "1").is_err());
        assert!(validate_extra_entry("1abc", "1").is_err());
        assert!(validate_extra_entry("a-b", "1").is_err());
        assert!(validate_extra_entry(&"a".repeat(65), "1").is_err());
        for k in FORBIDDEN_EXTRA_KEYS {
            assert!(validate_extra_entry(k, "x").is_err(), "{k} must be refused");
        }
        assert!(validate_extra_entry("memory_limit", "1G").is_err());
        for bad in ["a\nb", "a\rb", "a\tb", "a\0b", "[x]", "a;b", "a\"b", &"x".repeat(257)] {
            assert!(validate_extra_entry("foo.bar", bad).is_err(), "{bad:?}");
        }
        let dup = vec![("a.b".to_string(), "1".to_string()), ("a.b".to_string(), "2".to_string())];
        assert!(validate_extra(&dup).is_err());
        let many: Vec<(String, String)> = (0..51).map(|i| (format!("k{i}"), "1".to_string())).collect();
        assert!(validate_extra(&many).is_err());
    }

    #[test]
    fn owner_may_send_values_only() {
        assert_eq!(forbidden_field(&obj(json!({ "values": {} })), false), None);
        assert_eq!(forbidden_field(&obj(json!({ "values": {}, "isolation": false })), false), Some("isolation".into()));
        assert_eq!(forbidden_field(&obj(json!({ "pool": {} })), false), Some("pool".into()));
        assert_eq!(forbidden_field(&obj(json!({ "extra": [] })), false), Some("extra".into()));
        assert_eq!(forbidden_field(&obj(json!({ "anything": 1 })), false), Some("anything".into()));
        assert_eq!(forbidden_field(&obj(json!({ "isolation": false, "pool": {} })), true), None);

        let s = json!({});
        let e = apply_update(&row(&s), &obj(json!({ "disable_shell": false })), false).unwrap_err();
        assert_eq!(e, UpdateError::Forbidden("disable_shell".into()));
    }

    #[test]
    fn apply_owner_values() {
        let s = json!({ "values": { "display_errors": "On" } });
        let a = apply_update(&row(&s), &obj(json!({ "values": {
            "memory_limit": "1G", "upload_max_filesize": "128m", "display_errors": null, "max_input_vars": 5000
        } })), false)
        .unwrap();
        assert_eq!(a.memory_mb, 1024);
        assert_eq!(a.max_workers, 5);
        assert!(a.isolation && a.disable_shell);
        assert_eq!(a.settings, json!({ "values": { "upload_max_filesize": "128M", "max_input_vars": "5000" } }));

        // memory_limit null → column default
        let mut r = row(&s);
        r.memory_mb = 900;
        let a = apply_update(&r, &obj(json!({ "values": { "memory_limit": null } })), false).unwrap();
        assert_eq!(a.memory_mb, 256);
    }

    #[test]
    fn apply_rejections_carry_the_field() {
        let s = json!({});
        let r = row(&s);
        let field_of = |b: Value| match apply_update(&r, &obj(b), true).unwrap_err() {
            UpdateError::Invalid(fe) => fe.field,
            other => panic!("{other:?}"),
        };
        assert_eq!(field_of(json!({ "values": { "memory_limit": "8000M" } })), "memory_limit");
        assert_eq!(field_of(json!({ "values": { "upload_max_filesize": "128M", "post_max_size": "100M" } })), "post_max_size");
        // post below the nginx-derived upload default
        assert_eq!(field_of(json!({ "values": { "post_max_size": "32M" } })), "post_max_size");
        assert_eq!(field_of(json!({ "values": { "foo": "1" } })), "foo");
        assert_eq!(field_of(json!({ "values": [] })), "values");
        assert_eq!(field_of(json!({ "isolation": "yes" })), "isolation");
        assert_eq!(field_of(json!({ "pool": { "pm": "fast" } })), "pool.pm");
        assert_eq!(field_of(json!({ "pool": { "max_children": 0 } })), "pool.max_children");
        assert_eq!(field_of(json!({ "pool": { "max_children": 101 } })), "pool.max_children");
        assert_eq!(field_of(json!({ "pool": { "idle_timeout_s": 0 } })), "pool.idle_timeout_s");
        assert_eq!(field_of(json!({ "pool": { "zzz": 1 } })), "pool.zzz");
        assert_eq!(field_of(json!({ "extra": [["disable_functions", ""]] })), "extra");
        assert_eq!(field_of(json!({ "extra": [["a.b"]] })), "extra");
        assert_eq!(field_of(json!({ "other": 1 })), "other");
    }

    #[test]
    fn apply_admin_fields() {
        let s = json!({ "pool": { "max_requests": 10 }, "extra": [["a.b", "1"]] });
        let a = apply_update(&row(&s), &obj(json!({
            "isolation": false, "disable_shell": false,
            "pool": { "pm": "dynamic", "max_children": 12, "max_requests": null, "request_terminate_timeout_s": 600 },
            "extra": [[" opcache.enable ", "1"]]
        })), true)
        .unwrap();
        assert!(!a.isolation && !a.disable_shell);
        assert_eq!(a.max_workers, 12);
        assert_eq!(a.settings, json!({
            "pool": { "pm": "dynamic", "request_terminate_timeout_s": 600 },
            "extra": [["opcache.enable", "1"]]
        }));
        // untouched admin parts survive an owner edit
        let a2 = apply_update(&row(&s), &obj(json!({ "values": { "max_input_vars": "2000" } })), false).unwrap();
        assert_eq!(a2.settings["pool"], json!({ "max_requests": 10 }));
        assert_eq!(a2.settings["extra"], json!([["a.b", "1"]]));
    }

    fn legacy_seed() -> Value {
        // Exactly what migration 20261115000000 writes for an existing PHP site.
        json!({ "legacy": true,
            "values": { "max_execution_time": "300", "upload_max_filesize": "64M", "post_max_size": "64M" },
            "pool": { "pm": "dynamic", "max_requests": 500, "request_terminate_timeout_s": 0 } })
    }

    #[test]
    fn legacy_payload_omits_non_overridden_keys() {
        let s = legacy_seed();
        let mut r = row(&s);
        r.memory_mb = 512;
        r.isolation = false;
        r.disable_shell = false;
        let p = php_pool_json(&r);
        assert_eq!(p["values"], json!({
            "memory_limit": "512M", "max_execution_time": "300",
            "upload_max_filesize": "64M", "post_max_size": "64M"
        }));
        assert_eq!(p["pm"], "dynamic");
        assert_eq!(p["max_requests"], 500);
        assert_eq!(p["request_terminate_timeout_s"], 0);

        // memory only when nothing is overridden; terminate cap without a known max_execution_time
        let bare = json!({ "legacy": true });
        let p = php_pool_json(&row(&bare));
        assert_eq!(p["values"], json!({ "memory_limit": "256M" }));
        assert_eq!(p["request_terminate_timeout_s"], 3630);

        // upload overridden alone → post derived, not inherited
        let up = json!({ "legacy": true, "values": { "upload_max_filesize": "128M" } });
        assert_eq!(php_pool_json(&row(&up))["values"]["post_max_size"], "136M");

        let site_like = json!({ "legacy": true, "values": { "display_errors": "On" } });
        let eff = effective_values(&row(&site_like));
        let inh = inherits_global(&eff);
        assert_eq!(inh.len(), 10);
        assert!(!inh.contains(&"memory_limit") && !inh.contains(&"display_errors"));
        assert!(inh.contains(&"date.timezone"));
        // non-legacy rows inherit nothing
        let e = json!({});
        assert!(inherits_global(&effective_values(&row(&e))).is_empty());
    }

    #[test]
    fn legacy_preserved_on_owner_put() {
        let s = legacy_seed();
        let a = apply_update(&row(&s), &obj(json!({ "values": { "max_execution_time": null, "display_errors": "On" } })), false)
            .unwrap();
        assert_eq!(a.settings["legacy"], true);
        assert_eq!(a.settings["values"], json!({ "upload_max_filesize": "64M", "post_max_size": "64M", "display_errors": "On" }));
        // owner may not touch the flag
        let e = apply_update(&row(&s), &obj(json!({ "legacy": false })), false).unwrap_err();
        assert_eq!(e, UpdateError::Forbidden("legacy".into()));
        // post below an inherited (unknown) upload is not refused on a legacy row
        let bare = json!({ "legacy": true });
        assert!(apply_update(&row(&bare), &obj(json!({ "values": { "post_max_size": "8M" } })), false).is_ok());
        // admin edits without the flag keep it too
        let a = apply_update(&row(&s), &obj(json!({ "isolation": true })), true).unwrap();
        assert_eq!(a.settings["legacy"], true);
    }

    #[test]
    fn admin_can_clear_legacy() {
        let s = legacy_seed();
        let a = apply_update(&row(&s), &obj(json!({ "legacy": false })), true).unwrap();
        assert!(a.settings.get("legacy").is_none());
        // the seeded overrides stay; other keys now get panel defaults
        assert_eq!(a.settings["values"]["max_execution_time"], "300");
        let p = php_pool_json(&row(&a.settings));
        assert_eq!(p["values"].as_object().unwrap().len(), 12);
        assert_eq!(p["values"]["date.timezone"], "Europe/Paris");
        // the flag can never be set through the API
        let e = json!({});
        let field_of = |b: Value| match apply_update(&row(&e), &obj(b), true).unwrap_err() {
            UpdateError::Invalid(fe) => fe.field,
            other => panic!("{other:?}"),
        };
        assert_eq!(field_of(json!({ "legacy": true })), "legacy");
        assert_eq!(field_of(json!({ "legacy": "no" })), "legacy");
    }

    #[test]
    fn non_legacy_unchanged() {
        let s = json!({ "values": { "max_execution_time": "300" } });
        let p = php_pool_json(&row(&s));
        assert_eq!(p["values"].as_object().unwrap().len(), 12);
        assert_eq!(p["values"]["max_input_vars"], "4000");
        let a = apply_update(&row(&s), &obj(json!({ "values": { "display_errors": "On" } })), false).unwrap();
        assert!(a.settings.get("legacy").is_none());
        // a stored `legacy: false` / non-bool is not legacy
        assert!(!is_legacy(&json!({ "legacy": false })));
        assert!(!is_legacy(&json!({ "legacy": "true" })));
    }

    #[test]
    fn fields_describe_the_twelve_settings() {
        let f = fields_json();
        let arr = f.as_array().unwrap();
        assert_eq!(arr.len(), 12);
        assert_eq!(arr[0]["key"], "memory_limit");
        assert_eq!(arr[0]["kind"], "size");
        assert_eq!(arr[0]["min"], 32);
        assert_eq!(arr[7]["choices"].as_array().unwrap().len(), 3);
        assert!(arr[8]["choices"].as_array().unwrap().iter().any(|c| c["value"] == "Europe/Paris"));
        assert!(arr[6].get("min").is_none());
    }

    #[test]
    fn ini_body_rules() {
        assert!(validate_ini_body(&json!({ "content": "[PHP]\n" })).is_ok());
        assert!(validate_ini_body(&json!({ "content": "x".repeat(INI_CONTENT_MAX_BYTES + 1) })).is_err());
        assert!(validate_ini_body(&json!({ "content": "a", "values": {} })).is_err());
        assert!(validate_ini_body(&json!({})).is_err());
        assert_eq!(
            validate_ini_body(&json!({ "values": { "memory_limit": " 512M " } })).unwrap(),
            json!({ "values": { "memory_limit": "512M" } })
        );
        assert!(validate_ini_body(&json!({ "values": { "extension": "x.so" } })).is_err());
        assert!(validate_ini_body(&json!({ "values": { "memory_limit": "1\nextension=x" } })).is_err());
        assert!(validate_ini_body(&json!({ "values": {} })).is_err());
        assert!(validate_ini_body(&json!({ "values": { "memory_limit": "1M" }, "x": 1 })).is_err());
    }
}
