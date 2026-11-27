#!/usr/bin/env bash
#
# Regression pin for the GIT DEPLOY LINKED DATABASE.
#
# WHAT HAPPENED. A managed database runs as `dockpanel-db-{name}` on the shared
# `dockpanel-db` bridge, which has inter-container communication disabled (H2),
# and publishes its port on the host's 127.0.0.1 only. A Git Deploy container
# runs on Docker's default bridge with no network option. So a Git Deploy app
# could reach a managed database by NO route - not the host's 127.0.0.1 (inside
# a container that is the container), not the ICC-off `dockpanel-db` network
# (the app is not on it), not by container name (the default bridge has no
# name resolution) - while the Git Deploy form and the guide both told users to
# "use a database under Databases". Verified in production, with real apps
# (Next.js + drizzle, Astro, both PostgreSQL) waiting on it.
#
# THE FIX, and the six ways a naive version of it is worse than the bug:
#
#   1. ISOLATION. The obvious patch - put the app on `dockpanel-db`, or turn
#      ICC back on - puts every tenant's database on one ICC-on network. The
#      link is a DEDICATED, `internal` network per deployment, holding only
#      that deployment's containers and its one database; anything else found
#      attached is disconnected on every reconcile.
#   2. OWNERSHIP. Only a database the deployment's own account owns, on the
#      deployment's own server, can be linked - re-proved at EVERY deploy, not
#      only at save, and never through the admin-widened predicate the
#      Databases list uses to SHOW a tenant's database to an administrator.
#   3. PREVIEWS. A preview runs any pushed branch and inherits the parent's
#      env. It must never get the production database's network or its
#      credentials: the panel withholds the link, and the agent refuses one for
#      any scope but `deploy`.
#   4. CREDENTIALS AT REST. The password is decrypted at deploy time and merged
#      into the request to the agent only - never written into
#      `git_deploys.env_vars` (plain JSONB, cloned by previews) nor into the
#      encrypted history snapshot, and never baked into a Nixpacks image.
#   5. ORDER. Proving the database and preparing the network are the steps
#      that can refuse, so they run BEFORE the old container is stopped; the
#      app joins the network between create and start (blue-green: before the
#      health check), so a build that cannot reach its database fails while
#      the old one is still serving.
#   6. VERSION SKEW. An agent that predates the field drops it silently and
#      deploys anyway. The agent confirms the link in its response and the
#      panel fails a link it does not see confirmed.
#
# Pure source analysis: no box, no network, no build, no Docker daemon.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_LINK=panel/agent/src/services/git_db_link.rs
GIT_SVC=panel/agent/src/services/git_build.rs
GIT_ROUTE=panel/agent/src/routes/git_build.rs
DB_SVC=panel/agent/src/services/database.rs
AGENT_MAIN=panel/agent/src/main.rs
PANEL_LINK=panel/backend/src/services/git_db_link.rs
BACKEND=panel/backend/src/routes/git_deploys.rs
UI=panel/frontend/src/pages/GitDeploys.tsx
GUIDE=docs/guides/git-deploy.md
DBGUIDE=docs/guides/databases.md
MIG=$(ls panel/backend/migrations/*_git_deploy_linked_database.sql 2>/dev/null | head -1)

for f in "$AGENT_LINK" "$GIT_SVC" "$GIT_ROUTE" "$DB_SVC" "$AGENT_MAIN" "$PANEL_LINK" "$BACKEND" "$UI" "$GUIDE" "$DBGUIDE"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
[ -n "$MIG" ] || { echo "missing the git_deploy_linked_database migration"; exit 1; }

# Strip line comments only (the narrow, safe stripper - see git-deploy-volumes-pin).
code() { sed 's://.*$::' "$1"; }
flat() { code "$1" | tr -d ' \t\n'; }

LINK_CODE=$(code "$AGENT_LINK");  LINK_FLAT=$(flat "$AGENT_LINK")
SVC_CODE=$(code "$GIT_SVC");      SVC_FLAT=$(flat "$GIT_SVC")
ROUTE_FLAT=$(flat "$GIT_ROUTE")
DB_CODE=$(code "$DB_SVC");        DB_FLAT=$(flat "$DB_SVC")
MAIN_FLAT=$(flat "$AGENT_MAIN")
PANEL_FLAT=$(flat "$PANEL_LINK")
BACKEND_CODE=$(code "$BACKEND");  BACKEND_FLAT=$(flat "$BACKEND")
UI_FLAT=$(flat "$UI")

has() { # has <label> <haystack> <needle>
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" ;; esac
}
hasnt() {
  case "$2" in *"$3"*) bad "$1" ;; *) ok "$1" ;; esac
}

echo "§0 the subjects parse (a truncated subject must not read as a clean sweep)"
for fn in reconcile verify_db attach release_for_database reattach_all may_stay network_is_ours; do
  has "agent git_db_link::$fn is defined" "$LINK_FLAT" "fn${fn}("
done
for fn in deploy_or_update create_and_start blue_green_update cleanup_container; do
  has "agent git_build::$fn is defined" "$SVC_FLAT" "fn${fn}("
done
for fn in load check_linkable injected_env merge_env require_confirmed parse_change; do
  has "panel git_db_link::$fn is defined" "$PANEL_FLAT" "fn${fn}("
done
has "panel build_deploy_body is defined" "$BACKEND_FLAT" "fnbuild_deploy_body("

echo
echo "§1 isolation: a dedicated, internal, single-deployment network - never a shared ICC-on one"
has "the link network is named per deployment" "$LINK_FLAT" 'format!("dockpanel-link-{name}")'
has "the link network is created internal (no gateway, never a default route)" "$LINK_FLAT" 'internal:true,'
has "the link network is labelled for its deployment" "$LINK_FLAT" '(LINK_LABEL.to_string(),name.to_string())'
has "reconcile refuses a same-named network that is not ours" "$LINK_FLAT" 'ifletSome(refnet)=existing&&!network_is_ours(net.labels.as_ref(),name)'
has "reconcile disconnects anything that may not stay" "$LINK_FLAT" 'elseif!may_stay(&m.id,m.labels.as_ref(),name,None){disconnect.push(LinkStep::Disconnect(m.id.clone()));'
has "may_stay admits only this deployment's deploy-kind containers" "$LINK_FLAT" '==Some("deploy")'
hasnt "the app is never put on the shared dockpanel-db network" "$SVC_FLAT" '"dockpanel-db"'
has "the database is attached under the stable alias" "$LINK_FLAT" '.map(|d|(d.id.as_str(),DB_ALIAS))'
has "the alias is db" "$LINK_FLAT" 'pubconstDB_ALIAS:&str="db";'
has "the DB container's identity is checked (name AND labels)" "$LINK_FLAT" 'verify_db_identity(info.name.as_deref()'

echo
echo "§2 ownership: strict owner, same server, container kind - at save AND at deploy"
has "owner predicate is the strict one" "$PANEL_FLAT" 'ANDCOALESCE(s.user_id,st.user_id)=$2'
has "server predicate is the deployment's server" "$PANEL_FLAT" 'ANDCOALESCE(s.server_id,st.server_id)=$3'
hasnt "the admin-widened visibility predicate is NOT used" "$PANEL_FLAT" "u.role='admin'"
has "a shared local MariaDB row is refused" "$PANEL_FLAT" 'ifkind!="container"'
has "an imported-hash row is refused" "$PANEL_FLAT" 'if*imported_hash'
has "create checks the link against the caller's server" "$BACKEND_FLAT" 'check_linkable(&state.db,db_id,claims.sub,server_id)'
has "update re-checks against the deployment's own server" "$BACKEND_FLAT" 'claims.sub,deploy_server_id,)'
LOADS=$(printf '%s' "$BACKEND_FLAT" | grep -o 'git_db_link::load(' | wc -l)
if [ "$LOADS" -ge 3 ]; then ok "the link is re-proved at deploy time on every door ($LOADS loads)"; else bad "fewer than 3 deploy doors load the link ($LOADS)"; fi
has "deploy-time load binds the ROW's owner and server" "$BACKEND_FLAT" 'config.database_id,config.user_id,config.server_id,'
has "migration unlinks (SET NULL) rather than cascading a delete" "$(tr -d ' \n' < "$MIG")" 'REFERENCESdatabases(id)ONDELETESETNULL'

echo
echo "§3 previews never get the linked database"
has "agent route refuses a link for any scope but deploy" "$ROUTE_FLAT" 'ifletSome(reflink)=body.linked_db{ifscope!=ownership::GitScope::Deploy{'
has "agent only reconciles a link in the Deploy space" "$SVC_FLAT" 'letlink_network=ifscope==ownership::GitScope::Deploy{'
has "the panel's preview deploy passes no link" "$BACKEND_FLAT" 'scope:"preview",volumes:&[],linked_db:None,'
has "teardown only touches the link of a Deploy-scope name" "$SVC_FLAT" 'ifscope==ownership::GitScope::Deploy&&letErr(e)=super::git_db_link::reconcile(&docker,name,None,&[])'

echo
echo "§4 order: refusals before anything destructive; app joins before it starts"
REC_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'super::git_db_link::reconcile(&docker, name, verified.as_ref(), &services)' | head -1 | cut -d: -f1)
STOP_AT=$(printf '%s\n' "$SVC_CODE" | grep -n '\.stop_container(&container_id, Some(StopContainerOptions { t: 10 }))' | head -1 | cut -d: -f1)
if [ -n "$REC_AT" ] && [ -n "$STOP_AT" ] && [ "$REC_AT" -lt "$STOP_AT" ]; then
  ok "the link is settled (line $REC_AT) before the old container is stopped (line $STOP_AT)"
else
  bad "the link is no longer settled before the old container is stopped (reconcile=$REC_AT stop=$STOP_AT)"
fi
CAS=$(printf '%s\n' "$SVC_CODE" | awk '/^async fn create_and_start\(/,/^}/')
C_CREATE=$(printf '%s\n' "$CAS" | grep -n '\.create_container(' | head -1 | cut -d: -f1)
C_ATTACH=$(printf '%s\n' "$CAS" | grep -n 'git_db_link::attach(docker, network, &container.id, None)' | head -1 | cut -d: -f1)
C_START=$(printf '%s\n' "$CAS" | grep -n '\.start_container(&container.id' | head -1 | cut -d: -f1)
if [ -n "$C_CREATE" ] && [ -n "$C_ATTACH" ] && [ -n "$C_START" ] && [ "$C_CREATE" -lt "$C_ATTACH" ] && [ "$C_ATTACH" -lt "$C_START" ]; then
  ok "create_and_start: create -> attach -> start"
else
  bad "create_and_start ordering broken (create=$C_CREATE attach=$C_ATTACH start=$C_START)"
fi
BG=$(printf '%s\n' "$SVC_CODE" | awk '/^async fn blue_green_update\(/,/^}/')
B_ATTACH=$(printf '%s\n' "$BG" | grep -n 'git_db_link::attach(docker, network, &new_container.id, None)' | head -1 | cut -d: -f1)
B_START=$(printf '%s\n' "$BG" | grep -n '\.start_container(&new_container.id' | head -1 | cut -d: -f1)
B_HEALTH=$(printf '%s\n' "$BG" | grep -n 'health_check_port(temp_port' | head -1 | cut -d: -f1)
if [ -n "$B_ATTACH" ] && [ -n "$B_START" ] && [ -n "$B_HEALTH" ] && [ "$B_ATTACH" -lt "$B_START" ] && [ "$B_START" -lt "$B_HEALTH" ]; then
  ok "blue-green: the stand-in is attached before it starts and before the health check"
else
  bad "blue-green attach ordering broken (attach=$B_ATTACH start=$B_START health=$B_HEALTH)"
fi
CALLS=$(printf '%s' "$SVC_FLAT" | grep -o 'host_config,link_network.as_deref(),)' | wc -l)
if [ "$CALLS" -ge 2 ]; then ok "both create_and_start call sites pass the link ($CALLS)"; else bad "a create_and_start call site lost the link ($CALLS)"; fi
has "blue_green_update is handed the link" "$SVC_FLAT" '&host_config,link_network.as_deref(),).await;'
has "blue-green is still gated on volumes only - a linked DB does not block it" "$SVC_FLAT" 'ifhas_nginx&&volumes.is_empty(){'

echo
echo "§5 deletion of either side detaches and removes the network"
has "deleting the deployment removes its link network" "$SVC_FLAT" 'super::git_db_link::reconcile(&docker,name,None,&[])'
RD=$(printf '%s\n' "$DB_CODE" | awk '/^pub async fn remove_database\(/,/^}/')
R_REL=$(printf '%s\n' "$RD" | grep -n 'git_db_link::release_for_database(&docker, container_id)' | head -1 | cut -d: -f1)
R_RM=$(printf '%s\n' "$RD" | grep -n '\.remove_container(' | head -1 | cut -d: -f1)
if [ -n "$R_REL" ] && [ -n "$R_RM" ] && [ "$R_REL" -lt "$R_RM" ]; then
  ok "removing a database releases its link networks first, while it can still name them"
else
  bad "remove_database no longer releases link networks before removal (release=$R_REL remove=$R_RM)"
fi
has "release only removes link networks this agent labelled" "$LINK_FLAT" 'Some(name)ifnetwork_is_ours(net.labels.as_ref(),&name)=>'

echo
echo "§6 agent restarts re-attach idempotently"
has "the agent re-attaches links at start" "$MAIN_FLAT" 'tokio::spawn(services::git_db_link::reattach_all());'
has "the app container records its linked database" "$SVC_FLAT" 'labels.insert(super::git_db_link::LINK_DB_LABEL.to_string(),db.id.clone());'
has "attach treats already-attached as success" "$LINK_FLAT" 'ifis_attached(docker,container,network).await{returnOk(());}'

echo
echo "§7 credentials stay sealed at rest and the user's own value wins"
has "the merge happens only in the body sent to the agent" "$BACKEND_FLAT" 'ifletSome(link)=b.linked_db{crate::services::git_db_link::merge_env(&mutbody["env"],link);'
has "merge never overwrites a key the user set" "$PANEL_FLAT" 'obj.entry(k).or_insert('
has "the password is decrypted from the sealed column" "$PANEL_FLAT" 'decrypt_credential_or_legacy(&password_enc,jwt_secret)'
hasnt "the agent is never sent the password in linked_db" "$PANEL_FLAT" '"password":'
NIX=$(printf '%s\n' "$BACKEND_CODE" | awk '/^fn nixpacks_build_body\(/,/^}/')
case "$NIX" in *linked_db*|*merge_env*|*DATABASE_URL*) bad "nixpacks_build_body would bake the linked credentials into image layers" ;; *) ok "nixpacks_build_body never sees the linked credentials" ;; esac
hasnt "no SQL writes DATABASE_URL into git_deploys" "$BACKEND_FLAT" "DATABASE_URL'"
has "the URL uses the engine's own port, not the host-published one" "$PANEL_FLAT" '("postgresql","5432","PG")'
has "credentials in the URL are percent-encoded" "$PANEL_FLAT" 'urlencoding::encode(&link.password)'

COMPOSE=$(printf '%s' "$BACKEND_FLAT" | grep -o 'git_db_link::compose_refusal(config.database_id)' | wc -l)
if [ "$COMPOSE" -ge 2 ]; then ok "both compose doors refuse a linked deploy instead of running it unlinked ($COMPOSE)"; else bad "a compose door would run a linked deploy without its database ($COMPOSE)"; fi

echo
echo "§8 version skew: a link the agent did not confirm fails the deploy"
CONF=$(printf '%s' "$BACKEND_FLAT" | grep -o 'git_db_link::require_confirmed(' | wc -l)
if [ "$CONF" -ge 3 ]; then ok "the attended deploy doors require confirmation ($CONF)"; else bad "fewer than 3 doors require the agent's confirmation ($CONF)"; fi
has "the agent confirms the link it made" "$ROUTE_FLAT" 'response["linked_db_network"]='

echo
echo "§9 wire shape: absent keeps, \"\" unlinks, an id links"
has "update writes the link through an explicit change flag" "$BACKEND_FLAT" 'database_id=CASEWHEN$24THEN$25ELSEdatabase_idEND'
has "the form always sends the field, empty included" "$UI_FLAT" 'database_id:formDatabaseId,'
hasnt "the form never sends null for an empty picker" "$UI_FLAT" 'database_id:formDatabaseId||null'

echo
echo "§10 unit tests exist where a mistake would otherwise be silent"
for t in only_a_network_labelled_for_this_deployment_is_ours a_relink_to_another_database_rebuilds_the_network \
         db_identity_requires_name_and_labels_to_agree only_this_deployment_and_its_database_may_stay_on_the_link \
         request_shape_is_checked_before_docker_is_asked a_linked_app_resolves_db_and_unlink_removes_the_network; do
  has "agent unit test: $t" "$LINK_FLAT" "fn${t}("
done
for t in wire_shape_is_absent_keeps_empty_clears_value_sets postgres_url_uses_the_alias_and_the_engine_port_with_credentials_encoded \
         a_variable_the_user_set_is_never_overwritten a_link_the_agent_did_not_confirm_is_a_failure \
         unlinkable_rows_are_refused_with_a_reason a_compose_deploy_with_a_link_is_refused_not_run_unlinked; do
  has "panel unit test: $t" "$PANEL_FLAT" "fn${t}("
done
has "panel unit test: a_linked_database_reaches_the_agent_and_the_env_without_touching_the_column" "$BACKEND_FLAT" 'fna_linked_database_reaches_the_agent_and_the_env_without_touching_the_column('

echo
echo "§11 the guides say what the product does"
grep -q '^## Linked database' "$GUIDE" && ok "git-deploy.md has a Linked database section" || bad "git-deploy.md has no Linked database section"
grep -qi 'preview.*never.*linked database\|linked database.*never.*preview' "$GUIDE" && ok "git-deploy.md says previews never get the linked database" || bad "git-deploy.md does not say previews never get the linked database"
grep -qi 'Git Deploy' "$DBGUIDE" && grep -qi 'link' "$DBGUIDE" && ok "databases.md explains linking to a Git Deploy" || bad "databases.md does not explain linking to a Git Deploy"
if grep -q 'use a database under Databases' "$GUIDE"; then bad "git-deploy.md still sends users to an unreachable database"; else ok "git-deploy.md no longer sends users to an unreachable database"; fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
