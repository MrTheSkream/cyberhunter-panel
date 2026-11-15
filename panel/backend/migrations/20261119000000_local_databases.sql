-- 05-import-hestia (W2-D): shared local MariaDB server, `kind='local'`.
-- Existing rows default to 'container' and keep their current behaviour.
ALTER TABLE databases ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'container' CHECK (kind IN ('container','local'));
ALTER TABLE databases ADD COLUMN IF NOT EXISTS imported_hash BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE databases ADD CONSTRAINT chk_databases_local_shape CHECK
  (kind = 'container' OR (port IS NULL AND container_id IS NULL AND stack_id IS NULL AND site_id IS NOT NULL AND engine = 'mariadb'));
