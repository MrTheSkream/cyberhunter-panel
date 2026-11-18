-- Per-site reverse proxy options. False renders the historical vhost directives.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS proxy_streaming BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS proxy_strict_client_ip BOOLEAN NOT NULL DEFAULT false;
