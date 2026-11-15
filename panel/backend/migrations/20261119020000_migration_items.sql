-- 05-import-hestia (W5-D): per-item import ledger and report.
CREATE TABLE IF NOT EXISTS migration_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  migration_id UUID NOT NULL REFERENCES migrations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,   -- site | files | ssl | php | sftp | db | mail_domain | mailbox | mail_alias | maildir | preflight
  key TEXT NOT NULL,    -- domain, database name, address
  status TEXT NOT NULL CHECK (status IN ('pending','running','done','skipped','warning','failed')),
  message TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  attempts INT NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (migration_id, kind, key));
CREATE INDEX IF NOT EXISTS idx_migration_items_migration ON migration_items(migration_id);
