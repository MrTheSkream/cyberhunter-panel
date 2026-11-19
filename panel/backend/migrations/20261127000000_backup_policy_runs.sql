-- Run history for backup policies ("Run history" in the Backup Orchestrator).
--
-- `backup_policies.last_status` only ever said how the LAST run ended, and a
-- failed target left no trace of which one or why. Each execution now writes
-- one row here with its counters and the per-target errors, and the policy
-- keeps the summary of its last run's errors in `last_error` (NULL on success).
--
-- Single transaction so the table and the column land together. IF NOT EXISTS
-- throughout: a later step of the backup work declares the same objects.

BEGIN;

CREATE TABLE IF NOT EXISTS backup_policy_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES backup_policies(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    -- running, success, partial, failed
    status TEXT NOT NULL DEFAULT 'running',
    successes INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    upload_failures INTEGER NOT NULL DEFAULT 0,
    -- [{"kind": "site|database|volume|upload|listing|owner|retention", "subject": "...", "message": "..."}]
    errors JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_backup_policy_runs_policy_started
    ON backup_policy_runs(policy_id, started_at DESC);

ALTER TABLE backup_policies ADD COLUMN IF NOT EXISTS last_error TEXT;

COMMIT;
