-- The environment each deployment ran with, so a rollback restores it with the image.
-- Encrypted like every other stored credential. NULL on entries older than this column.
ALTER TABLE git_deploy_history ADD COLUMN IF NOT EXISTS env_snapshot TEXT;
