-- `dr_settings.last_status = 'restored'` (lot 2, VM acceptance).
--
-- The off-site snapshot is taken DURING its run: the database it carries says
-- `last_status = 'running'`. After a restore from it (new machine, or "Restore
-- from remote snapshot" in the panel), the first start used to turn that
-- 'running' into 'failed / Interrupted', a run that never ran on this machine.
-- The post-restore pass now records 'restored' instead, with the archive name.
--
-- A separate migration, not an edit of 20261130000000: sqlx refuses to start
-- when an applied migration's checksum changed, and that one is applied on
-- every server (and in every archive) of this lot.

BEGIN;

ALTER TABLE dr_settings DROP CONSTRAINT IF EXISTS dr_settings_last_status_check;
ALTER TABLE dr_settings ADD CONSTRAINT dr_settings_last_status_check
    CHECK (last_status IS NULL OR last_status IN ('running', 'success', 'partial', 'failed', 'restored'));

COMMIT;
