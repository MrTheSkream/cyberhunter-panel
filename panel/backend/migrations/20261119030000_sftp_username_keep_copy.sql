-- 05-import-hestia (W4-S / W4-B): custom SFTP account name, forward + local copy.
-- NULL / false defaults keep current behaviour (sftp<uid>, forward without copy).
ALTER TABLE sites ADD COLUMN IF NOT EXISTS sftp_username TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_sftp_username ON sites(sftp_username) WHERE sftp_username IS NOT NULL;
ALTER TABLE mail_accounts ADD COLUMN IF NOT EXISTS keep_copy BOOLEAN NOT NULL DEFAULT false;
