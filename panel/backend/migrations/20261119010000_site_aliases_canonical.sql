-- 05-import-hestia (W3-V / W3-F): persistent aliases, canonical host, PHP no-exec
-- dirs, per-site Force SSL / HSTS. NULL / true defaults render existing vhosts
-- byte for byte as today.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS aliases TEXT[];                -- NULL = not managed by the database
ALTER TABLE sites ADD COLUMN IF NOT EXISTS canonical_host TEXT CHECK (canonical_host IN ('www','apex'));
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_no_exec_dirs TEXT[];       -- NULL = none
ALTER TABLE sites ADD COLUMN IF NOT EXISTS force_ssl BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS hsts BOOLEAN NOT NULL DEFAULT true;
