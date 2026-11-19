use axum::{
    extract::Path,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};

use super::{is_valid_name, AppState};
use crate::services::{
    backup_targets::{self, TargetKind, TargetsReport, is_valid_owner_name},
    volume_backup::{self, VbError},
};

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// The status of an app data failure. 422 is the file's fault (corrupt,
/// tampered with, wrong passphrase): the panel relays a 4xx sentence to the
/// operator, while a 5xx becomes an incident id.
fn status_of(e: &VbError) -> StatusCode {
    match e {
        VbError::BadRequest(_) => StatusCode::BAD_REQUEST,
        VbError::NotFound(_) => StatusCode::NOT_FOUND,
        VbError::Conflict(_) => StatusCode::CONFLICT,
        VbError::Integrity(_) => StatusCode::UNPROCESSABLE_ENTITY,
        VbError::NoSpace(_) => StatusCode::INSUFFICIENT_STORAGE,
        VbError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn vb_err(e: VbError) -> ApiErr {
    err(status_of(&e), e.message())
}

/// GET /backup-targets - The volumes and bind mounts of the managed apps that
/// can be backed up, and the mounts that cannot, with the reason.
async fn targets() -> Result<Json<TargetsReport>, ApiErr> {
    let report = backup_targets::enumerate_targets()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(report))
}

/// Both request shapes. New: `kind` present. Legacy: `{volume_name,
/// container_name}`, behaviour unchanged.
#[derive(serde::Deserialize)]
pub struct VolumeBackupRequest {
    pub kind: Option<String>,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub owner_name: Option<String>,
    pub container_name: Option<String>,
    pub stop_containers: Option<bool>,
    pub encryption_key: Option<String>,
}

/// POST /volume-backups/create - Backup a Docker volume or a bind mount.
async fn create(
    Json(req): Json<VolumeBackupRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let Some(kind) = req.kind.as_deref() else {
        return create_legacy(req).await;
    };
    let kind = TargetKind::parse(kind).ok_or_else(|| err(StatusCode::BAD_REQUEST, "kind must be 'volume' or 'bind'"))?;
    let owner_name = req
        .owner_name
        .filter(|o| !o.is_empty())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "owner_name required"))?;
    let info = volume_backup::backup_target(volume_backup::TargetBackupRequest {
        kind,
        volume_name: req.volume_name,
        source_path: req.source_path,
        owner_name,
        stop_containers: req.stop_containers.unwrap_or(true),
        encryption_key: req.encryption_key,
    })
    .await
    .map_err(vb_err)?;
    Ok(Json(serde_json::to_value(info).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?))
}

async fn create_legacy(req: VolumeBackupRequest) -> Result<Json<serde_json::Value>, ApiErr> {
    let volume_name = req.volume_name.unwrap_or_default();
    let container_name = req.container_name.unwrap_or_default();
    if volume_name.is_empty() || container_name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "volume_name and container_name required"));
    }
    // Validate names to prevent injection / path traversal
    if !is_valid_name(&volume_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid volume name"));
    }
    if !is_valid_name(&container_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid container name"));
    }

    let info = volume_backup::backup_volume(&volume_name, &container_name)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::to_value(info).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?))
}

/// GET /volume-backups/{owner_name}/list - List volume backups.
async fn list(
    Path(container_name): Path<String>,
) -> Result<Json<Vec<crate::services::backups::BackupInfo>>, ApiErr> {
    if !is_valid_owner_name(&container_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid container name"));
    }
    let list = volume_backup::list_volume_backups(&container_name)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(list))
}

/// New: `{kind, volume_name | source_path, encryption_key?}`. Legacy:
/// `{volume_name}`, which is `kind: volume`.
#[derive(serde::Deserialize)]
pub struct VolumeRestoreRequest {
    pub kind: Option<String>,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub encryption_key: Option<String>,
}

/// POST /volume-backups/{owner_name}/restore/{filename} - Restore an app data archive.
async fn restore(
    Path((container_name, filename)): Path<(String, String)>,
    Json(req): Json<VolumeRestoreRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let kind = match req.kind.as_deref() {
        None => TargetKind::Volume,
        Some(k) => TargetKind::parse(k).ok_or_else(|| err(StatusCode::BAD_REQUEST, "kind must be 'volume' or 'bind'"))?,
    };
    let outcome = volume_backup::restore_target(
        container_name,
        filename.clone(),
        volume_backup::RestoreRequest {
            kind,
            volume_name: req.volume_name,
            source_path: req.source_path,
            encryption_key: req.encryption_key,
        },
    )
    .await
    .map_err(|e| {
        // The panel serves the operator this list from its own DB and the
        // archive lives on a different host, so "gone since you were shown
        // it" is the expected disagreement, not an agent fault. As a 5xx it
        // arrived as an incident id, and a retry produced a fresh id and no
        // new information. Same for a corrupt archive or a wrong passphrase
        // (422): the sentence is what the operator needs.
        let status = match &e {
            VbError::NotFound(_) => StatusCode::NOT_FOUND,
            VbError::BadRequest(_) => StatusCode::BAD_REQUEST,
            VbError::Integrity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            other => status_of(other),
        };
        err(status, e.message())
    })?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "success": true,
        "filename": filename,
        "stopped": outcome.stopped,
        "restarted": outcome.restarted,
    })))
}

/// DELETE /volume-backups/{owner_name}/{filename} - Delete a volume backup.
async fn remove(
    Path((container_name, filename)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_owner_name(&container_name) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid container name"));
    }
    volume_backup::delete_volume_backup(&container_name, &filename).map_err(|e| {
        let status = if e == "Backup file not found" {
            StatusCode::NOT_FOUND
        } else if e == "Invalid backup filename" {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        err(status, &e)
    })?;
    Ok(Json(serde_json::json!({ "success": true })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/backup-targets", get(targets))
        .route("/volume-backups/create", post(create))
        .route("/volume-backups/{container_name}/list", get(list))
        .route("/volume-backups/{container_name}/restore/{filename}", post(restore))
        .route("/volume-backups/{container_name}/{filename}", delete(remove))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_and_new_create_bodies_parse() {
        let old: VolumeBackupRequest =
            serde_json::from_value(serde_json::json!({"volume_name": "pgdata", "container_name": "app"})).unwrap();
        assert!(old.kind.is_none());
        assert_eq!(old.volume_name.as_deref(), Some("pgdata"));
        assert_eq!(old.container_name.as_deref(), Some("app"));

        let new: VolumeBackupRequest = serde_json::from_value(serde_json::json!({
            "kind": "bind", "source_path": "/var/lib/dockpanel/compose/demo/uploads",
            "owner_name": "demo", "stop_containers": false, "encryption_key": "k"
        }))
        .unwrap();
        assert_eq!(new.kind.as_deref(), Some("bind"));
        assert_eq!(new.stop_containers, Some(false));
        assert_eq!(new.encryption_key.as_deref(), Some("k"));

        // stop_containers defaults to true (decision 1) when omitted.
        let v: VolumeBackupRequest =
            serde_json::from_value(serde_json::json!({"kind": "volume", "volume_name": "x", "owner_name": "o"})).unwrap();
        assert_eq!(v.stop_containers.unwrap_or(true), true);
    }

    /// The exact bodies the backend sends: absent key, explicit nulls.
    #[test]
    fn backend_bodies_with_nulls_parse() {
        let v: VolumeBackupRequest = serde_json::from_value(serde_json::json!({
            "kind": "volume", "volume_name": "demo_pgdata", "source_path": null,
            "owner_name": "demo", "stop_containers": true
        }))
        .unwrap();
        assert_eq!(v.source_path, None);
        assert_eq!(v.encryption_key, None);
        let b: VolumeBackupRequest = serde_json::from_value(serde_json::json!({
            "kind": "bind", "volume_name": null, "source_path": "/var/lib/dockpanel/compose/demo/uploads",
            "owner_name": "demo", "stop_containers": false, "encryption_key": "k"
        }))
        .unwrap();
        assert_eq!(b.volume_name, None);
        let r: VolumeRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "bind", "volume_name": null, "source_path": "/var/lib/dockpanel/apps/x/data"
        }))
        .unwrap();
        assert_eq!(r.volume_name, None);
        assert_eq!(r.encryption_key, None);
    }

    #[test]
    fn old_and_new_restore_bodies_parse() {
        let old: VolumeRestoreRequest = serde_json::from_value(serde_json::json!({"volume_name": "pgdata"})).unwrap();
        assert!(old.kind.is_none());
        let new: VolumeRestoreRequest = serde_json::from_value(serde_json::json!({
            "kind": "bind", "source_path": "/var/lib/dockpanel/apps/x/data", "encryption_key": "k"
        }))
        .unwrap();
        assert_eq!(new.kind.as_deref(), Some("bind"));
        assert_eq!(new.source_path.as_deref(), Some("/var/lib/dockpanel/apps/x/data"));
    }

    #[test]
    fn statuses() {
        assert_eq!(status_of(&VbError::Integrity("x".into())), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(status_of(&VbError::NoSpace("x".into())), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(status_of(&VbError::NotFound("x".into())), StatusCode::NOT_FOUND);
        assert_eq!(status_of(&VbError::BadRequest("x".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(&VbError::Conflict("x".into())), StatusCode::CONFLICT);
        assert_eq!(status_of(&VbError::Internal("x".into())), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// A refusal of the request itself answers before any Docker call.
    #[tokio::test]
    async fn invalid_requests_are_refused_before_touching_docker() {
        let e = restore(
            Path(("demo".into(), "../etc.tar.gz".into())),
            Json(VolumeRestoreRequest { kind: None, volume_name: Some("x".into()), source_path: None, encryption_key: None }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        let e = restore(
            Path(("a..b".into(), "x.tar.gz".into())),
            Json(VolumeRestoreRequest { kind: None, volume_name: Some("x".into()), source_path: None, encryption_key: None }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        let e = restore(
            Path(("demo".into(), "x.tar.gz".into())),
            Json(VolumeRestoreRequest { kind: Some("bind".into()), volume_name: None, source_path: Some("/etc".into()), encryption_key: None }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        let e = restore(
            Path(("demo".into(), "never-there-20000101-000000.tar.gz".into())),
            Json(VolumeRestoreRequest { kind: None, volume_name: Some("x".into()), source_path: None, encryption_key: None }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(e.0, StatusCode::NOT_FOUND);
        let e = create(Json(VolumeBackupRequest {
            kind: Some("tmpfs".into()),
            volume_name: None,
            source_path: None,
            owner_name: Some("demo".into()),
            container_name: None,
            stop_containers: None,
            encryption_key: None,
        }))
        .await
        .err()
        .unwrap();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
    }
}
