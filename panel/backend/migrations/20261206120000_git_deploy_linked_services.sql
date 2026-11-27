-- LINKED SERVICES of a Git Deploy (see panel/backend/src/services/git_service_link.rs
-- and the agent's services/git_db_link.rs, LINKED SERVICES). On deploy the
-- agent puts each declared panel app (`dockpanel-app-{app_name}`, a template
-- app such as mailpit) on the deployment's dedicated link network, where it
-- answers under `alias` - the same network a linked database answers on as `db`.
--
-- A child table rather than a column: a deployment may link several apps, each
-- with its own alias, and both must be unique per deployment.
--
-- `app_name`, not a container id: a template app is RECREATED by every update,
-- image change or environment edit, and gets a new id each time; its name (and
-- so its container name) is what stays. Template apps have no table of their own
-- to reference - the container's labels are their record - so there is no FK
-- to the app; `docker_apps::remove_app` deletes the rows naming an app it
-- removes, and the agent re-proves the app's identity and owner at every deploy.
--
-- ON DELETE CASCADE: deleting the deployment deletes its links (the agent
-- removes the link network with the deployment's container; the linked apps
-- are only disconnected, never touched).
CREATE TABLE IF NOT EXISTS git_deploy_linked_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deploy_id UUID NOT NULL REFERENCES git_deploys(id) ON DELETE CASCADE,
    app_name TEXT NOT NULL
        CHECK (app_name ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
    alias TEXT NOT NULL
        CHECK (alias ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (deploy_id, alias),
    UNIQUE (deploy_id, app_name)
);

CREATE INDEX IF NOT EXISTS idx_git_deploy_linked_services_app
    ON git_deploy_linked_services(app_name);
