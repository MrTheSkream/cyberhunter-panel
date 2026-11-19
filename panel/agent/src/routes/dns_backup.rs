//! Lot 3 DNS backup routes, plus the job poll shared with the mail routes.
//!
//! * `POST /dns/archive`: `kind: zone` answers 200 with the file, `kind:
//!   snapshot` 202 `{job_id}`;
//! * `POST /dns/restore`: `kind: zone` answers 200 `{zone, content}`, `kind:
//!   snapshot` 202 `{job_id}`;
//! * `GET /dns/backups`: `{files: [...]}`;
//! * `GET /backup-jobs/{job_id}`: `{status, result, error, error_code}`.
//!
//! When PowerDNS is not installed every POST answers 200
//! `{"skipped": "not_installed"}` (after body validation), never a job.

use axum::{
    extract::{DefaultBodyLimit, Path},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use super::AppState;
use crate::services::backup_jobs;
use crate::services::dns_backup::{self, DnsArchivePlan, DnsArchiveRequest, DnsRestorePlan, DnsRestoreRequest};
use crate::services::volume_backup::VbError;

type ApiErr = (StatusCode, Json<serde_json::Value>);
type Reply = Result<(StatusCode, Json<serde_json::Value>), ApiErr>;

/// Zone exports and manifests can exceed axum's 2 MB default.
pub const BACKUP_BODY_LIMIT: usize = 64 * 1024 * 1024;

pub fn status_of(e: &VbError) -> StatusCode {
    StatusCode::from_u16(backup_jobs::error_code(e)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn vb_err(e: VbError) -> ApiErr {
    (status_of(&e), Json(serde_json::json!({ "error": e.message() })))
}

pub fn skipped() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({ "skipped": "not_installed" })))
}

pub fn accepted(job_id: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "job_id": job_id })))
}

pub fn ok_json<T: serde::Serialize>(v: T) -> Reply {
    let v = serde_json::to_value(v).map_err(|e| vb_err(VbError::Internal(e.to_string())))?;
    Ok((StatusCode::OK, Json(v)))
}

/// POST /dns/archive
async fn archive(Json(req): Json<DnsArchiveRequest>) -> Reply {
    let plan = dns_backup::plan_archive(req).map_err(vb_err)?;
    if !dns_backup::pdns_installed() {
        return Ok(skipped());
    }
    match plan {
        DnsArchivePlan::Zone { zone, content, key } => {
            ok_json(dns_backup::archive_zone(zone, content, key).await.map_err(vb_err)?)
        }
        DnsArchivePlan::Snapshot { key } => Ok(accepted(backup_jobs::spawn("dns-snapshot", async move {
            dns_backup::take_snapshot(key).await
        }))),
    }
}

/// POST /dns/restore
async fn restore(Json(req): Json<DnsRestoreRequest>) -> Reply {
    let plan = dns_backup::plan_restore(req).map_err(vb_err)?;
    if !dns_backup::pdns_installed() {
        return Ok(skipped());
    }
    match plan {
        DnsRestorePlan::Zone { filename, key } => ok_json(dns_backup::read_zone(filename, key).await.map_err(vb_err)?),
        DnsRestorePlan::Snapshot { filename, backend, key } => {
            // Cheap refusals before the job: the file must be here.
            crate::services::mail_backup::locate(std::path::Path::new(dns_backup::DNS_BACKUP_DIR), &filename)
                .map_err(vb_err)?;
            Ok(accepted(backup_jobs::spawn("dns-restore", async move {
                dns_backup::restore_snapshot(filename, backend, key).await
            })))
        }
    }
}

/// GET /dns/backups
async fn list() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "files": dns_backup::list_backups(std::path::Path::new(dns_backup::DNS_BACKUP_DIR)),
        "installed": dns_backup::pdns_installed(),
    }))
}

/// GET /backup-jobs/{job_id}
async fn job(Path(job_id): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    if !backup_jobs::is_valid_job_id(&job_id) {
        return Err(vb_err(VbError::BadRequest("Invalid job id".into())));
    }
    backup_jobs::get(&job_id)
        .map(Json)
        .ok_or_else(|| vb_err(VbError::NotFound("Unknown job (finished more than an hour ago, or the agent restarted)".into())))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dns/archive", post(archive).layer(DefaultBodyLimit::max(BACKUP_BODY_LIMIT)))
        .route("/dns/restore", post(restore))
        .route("/dns/backups", get(list))
        .route("/backup-jobs/{job_id}", get(job))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses() {
        assert_eq!(status_of(&VbError::Integrity("x".into())), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(status_of(&VbError::NoSpace("x".into())), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(status_of(&VbError::BadRequest("x".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(&VbError::NotFound("x".into())), StatusCode::NOT_FOUND);
    }

    #[test]
    fn skipped_shape() {
        let (s, Json(v)) = skipped();
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v, serde_json::json!({"skipped": "not_installed"}));
    }

    /// A body error is a 400 before the host is looked at, installed or not.
    #[tokio::test]
    async fn invalid_bodies_are_400() {
        let e = archive(Json(serde_json::from_value(serde_json::json!({"kind": "snapshot"})).unwrap())).await.err().unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        let e = restore(Json(serde_json::from_value(serde_json::json!({"kind": "zone", "filename": "/etc/passwd"})).unwrap()))
            .await
            .err()
            .unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn job_poll() {
        assert_eq!(job(Path("nope".into())).await.err().unwrap().0, StatusCode::BAD_REQUEST);
        assert_eq!(
            job(Path("6f9619ff-8b86-4011-b42d-00c04fc964ff".into())).await.err().unwrap().0,
            StatusCode::NOT_FOUND
        );
        let id = backup_jobs::spawn("t", async { Ok(serde_json::json!({"ok": true})) });
        let v = job(Path(id)).await.unwrap().0;
        assert!(v["status"] == "running" || v["status"] == "done");
    }
}
