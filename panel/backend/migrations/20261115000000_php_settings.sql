ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_settings JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_isolation BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_disable_shell BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ALTER COLUMN php_isolation SET DEFAULT true;
ALTER TABLE sites ALTER COLUMN php_disable_shell SET DEFAULT true;

-- D1 : les sites PHP existants gardent exactement le pool qu'ils avaient (valeurs autrefois en dur
-- dans l'agent), enregistrées comme réglages propres du site : rien ne change pour eux à la
-- prochaine reconstruction du vhost, et chaque valeur peut être ramenée au défaut depuis la fiche.
-- `legacy: true` : seules ces surcharges (+ memory_limit) sont envoyées au pool, les autres clés
-- restent héritées du php.ini global comme avant ; un admin lève le drapeau (« panel defaults »).
UPDATE sites
SET php_settings = '{"legacy": true,
                     "values": {"max_execution_time": "300", "upload_max_filesize": "64M", "post_max_size": "64M"},
                     "pool": {"pm": "dynamic", "max_requests": 500, "request_terminate_timeout_s": 0}}'::jsonb
WHERE runtime = 'php' AND php_settings = '{}'::jsonb;
