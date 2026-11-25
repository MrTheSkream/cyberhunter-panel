-- A proxy site can follow a Git Deploy: `sites.git_deploy_id` names the deploy
-- whose `host_port` the site's vhost proxies to.
--
-- Until now an existing site moved onto a Git Deploy only by hand:
-- `UPDATE sites SET proxy_port = <host_port>` and then a vhost re-render. The
-- site keeps its own vhost (bound IP, aliases, certificate, canonical/HSTS);
-- only its upstream changes. `PUT /api/sites/{id}/git-deploy` writes this
-- column and copies the deploy's port into `proxy_port` in the same
-- transaction, so every reader of `proxy_port` (SSL renewal, auto-healer,
-- security scanner, drift) keeps rendering the right upstream.
--
-- ON DELETE SET NULL: deleting the deploy leaves the site and its vhost in
-- place, still holding the port (the Git Deploy allocator skips ports a site
-- holds, so another deploy cannot inherit that traffic).
ALTER TABLE sites
    ADD COLUMN IF NOT EXISTS git_deploy_id UUID REFERENCES git_deploys(id) ON DELETE SET NULL;

-- One site per deploy. `idx_sites_proxy_port_server` already implies it (both
-- sites would hold the same port on the same server), but this one says why.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_git_deploy_id
    ON sites(git_deploy_id) WHERE git_deploy_id IS NOT NULL;
