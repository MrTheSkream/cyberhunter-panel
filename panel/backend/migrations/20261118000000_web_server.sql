-- Feature 4 (conception/04-apache-htaccess.md): per-site web server for PHP sites.
-- 'nginx' = the historical behaviour (nginx talks to PHP-FPM directly).
-- 'apache' = nginx in front, Apache on 127.0.0.1:8091 behind it, reading .htaccess.
-- Every existing row stays 'nginx': nothing changes without an explicit action.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS web_server TEXT NOT NULL DEFAULT 'nginx'
  CHECK (web_server IN ('nginx','apache'));
