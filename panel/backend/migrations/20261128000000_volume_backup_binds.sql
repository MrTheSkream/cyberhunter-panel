-- App data backups: Docker volumes AND bind mounts (Backup Orchestrator, lot 1).
--
-- A row of `volume_backups` now describes one backup target as the agent's
-- GET /backup-targets lists it:
--   * container_name  the stable owner of the data (template container name,
--                     compose project, Git deployment name), not a container;
--   * volume_name     the Docker volume name, or the slug of a bind mount;
--   * mount_type      'volume' (named or anonymous volume) or 'bind';
--   * source_path     the bind mount's host directory (NULL for a volume);
--   * stack_id        the compose stack the data belongs to, when there is one;
--   * encryption_key_version  which derivation produced the passphrase of an
--                     encrypted archive. Restore recomputes the key with THIS
--                     version, never with the current one. Rows written before
--                     this migration were never encrypted, so the default only
--                     matters for the column to be NOT NULL.
--
-- `backup_policies.stop_apps`: stop the containers that use the data while it
-- is archived (on by default), so a database living in a volume is copied in a
-- consistent state.
--
-- `volume_name` is widened to TEXT: Docker accepts volume names up to 255
-- characters and the agent validates that length, while the column was
-- VARCHAR(200), so a long compose volume name would have failed at INSERT
-- after its archive was taken.
--
-- Single transaction, IF NOT EXISTS throughout.

BEGIN;

ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS mount_type TEXT NOT NULL DEFAULT 'volume';
ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS source_path TEXT;
ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS stack_id TEXT;
ALTER TABLE volume_backups ADD COLUMN IF NOT EXISTS encryption_key_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE volume_backups ALTER COLUMN volume_name TYPE TEXT;

-- Retention partitions and the integrity chain both key on this identity.
CREATE INDEX IF NOT EXISTS idx_volume_backups_target
    ON volume_backups(server_id, container_name, mount_type, volume_name, created_at DESC);

ALTER TABLE backup_policies ADD COLUMN IF NOT EXISTS stop_apps BOOLEAN NOT NULL DEFAULT TRUE;

COMMIT;
