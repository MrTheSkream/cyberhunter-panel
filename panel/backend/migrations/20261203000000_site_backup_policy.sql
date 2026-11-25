-- Site archives taken by a backup policy now record which policy took them.
--
-- `database_backups`, `volume_backups`, `mail_backups` and `dns_backups` have
-- carried `policy_id` since they were created, and the retention sweep prunes
-- them per policy. `backups` (site archives) never did, so the only local prune
-- a site archive could get was the per-site schedule sweep: a site covered by a
-- policy alone kept every archive it was ever given.
--
-- Rows written before this migration keep a NULL policy_id - which policy took
-- them cannot be recovered - and stay under the per-site schedule sweep only.
ALTER TABLE backups ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES backup_policies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_backups_policy_site ON backups(policy_id, site_id, created_at DESC);
