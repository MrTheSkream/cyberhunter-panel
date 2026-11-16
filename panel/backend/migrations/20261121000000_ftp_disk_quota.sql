-- Fonctionnalité 6 : FTP (FTPS) et quotas disque par site.
-- Voir conception/07-ftp-quotas.md et 07-ftp-quotas-contrats.md (B-1).

ALTER TABLE sites ADD COLUMN IF NOT EXISTS ftp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS disk_quota_mb integer NULL CHECK (disk_quota_mb IS NULL OR disk_quota_mb > 0);

CREATE TABLE IF NOT EXISTS site_disk_usage (
  site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  bytes bigint NULL,
  files bigint NULL,
  measured_at timestamptz NOT NULL DEFAULT now(),
  error text NULL
);
