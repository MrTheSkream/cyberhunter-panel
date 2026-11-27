-- A Git Deploy can be LINKED to one managed database (see
-- panel/backend/src/services/git_db_link.rs and the agent's
-- services/git_db_link.rs). On deploy the agent puts the app and that database
-- on a dedicated per-deployment network where the database answers as `db`,
-- and the panel injects DATABASE_URL (plus per-engine variables) unless the
-- deployment's own environment already sets them.
--
-- ON DELETE SET NULL: deleting the database (or the site / stack that owns it)
-- unlinks the deployment instead of deleting it. The agent tears the link
-- network down when the database container is removed, and the next deploy
-- runs without the injected variables.
ALTER TABLE git_deploys
    ADD COLUMN IF NOT EXISTS database_id UUID REFERENCES databases(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_git_deploys_database_id
    ON git_deploys(database_id) WHERE database_id IS NOT NULL;
