#!/usr/bin/env bash
#
# Regression pin for the GIT DEPLOY LINKED SERVICES.
#
# WHAT HAPPENED. A Next.js app deployed from Git also needed a mail catcher
# (Mailpit, run as an app from Apps, SMTP on 1025). It had no stable way to
# reach it. The template app sits on Docker's default bridge (no name
# resolution), its address there changes on every restart, and the per-deploy
# link network PR #8 built for the linked database evicts anything that is
# not the app or its database on every deploy.
#
# THE FIX: the same `dockpanel-link-<deploy>` network carries declared panel
# apps under a DNS alias, beside the database or on its own. The ways a naive
# version of it is worse than the bug:
#
#   1. OWNERSHIP. Linking puts two containers on an ICC-on network. Only an app
#      whose owner label is the deployment's owner, on the deployment's own
#      server, may join. The panel checks at save time, through THAT server's
#      agent. The agent re-checks at every deploy, by container name and labels,
#      never by a stored container id.
#   2. EXACT MEMBERSHIP. The reconcile still evicts everything not declared.
#      A declared service must keep its alias, so a changed alias is
#      re-attached rather than silently ignored by "already attached".
#   3. TEARDOWN ONLY WHEN NOTHING IS DECLARED. A services-only deployment
#      keeps its network. Deleting a linked database no longer removes a network
#      that still carries services.
#   4. RECREATES. A template app is recreated (new id) by every update, image
#      change and env edit. It must come back on the link network with its alias,
#      and the internal, gateway-less link network must never become its primary
#      network. A link network that has vanished must not block the app's update.
#   5. PREVIEWS never get the links. The panel withholds them and the agent
#      refuses them.
#   6. VERSION SKEW. An agent that predates the field drops it silently. The
#      agent confirms, and the panel fails a deploy it does not see confirmed.
#   7. ALIASES. Lowercase DNS labels, unique, capped, and `db` is reserved while
#      a database is linked, checked in both directions.
#
# Pure source analysis: no box, no network, no build, no Docker daemon. The
# real-Docker drill is the agent's ignored test
# `a_linked_mailpit_stays_reachable_across_redeploys_restarts_and_recreates`.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_LINK=panel/agent/src/services/git_db_link.rs
GIT_SVC=panel/agent/src/services/git_build.rs
GIT_ROUTE=panel/agent/src/routes/git_build.rs
APPS_SVC=panel/agent/src/services/docker_apps.rs
PANEL_SVC=panel/backend/src/services/git_service_link.rs
BACKEND=panel/backend/src/routes/git_deploys.rs
BACKEND_APPS=panel/backend/src/routes/docker_apps.rs
ROUTER=panel/backend/src/routes/mod.rs
UI=panel/frontend/src/pages/GitDeploys.tsx
GUIDE=docs/guides/git-deploy.md
APIREF=docs/api-reference.md
MIG=$(ls panel/backend/migrations/*_git_deploy_linked_services.sql 2>/dev/null | head -1)

for f in "$AGENT_LINK" "$GIT_SVC" "$GIT_ROUTE" "$APPS_SVC" "$PANEL_SVC" "$BACKEND" "$BACKEND_APPS" "$ROUTER" "$UI" "$GUIDE" "$APIREF"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
[ -n "$MIG" ] || { echo "missing the git_deploy_linked_services migration"; exit 1; }

# Strip line comments only (the narrow, safe stripper - see git-deploy-volumes-pin).
code() { sed 's://.*$::' "$1"; }
flat() { code "$1" | tr -d ' \t\n'; }
# The non-test half of a Rust file.
prod() { awk '/^#\[cfg\(test\)\]/{exit} {print}' "$1" | sed 's://.*$::'; }

LINK_FLAT=$(flat "$AGENT_LINK"); LINK_PROD=$(prod "$AGENT_LINK")
SVC_CODE=$(code "$GIT_SVC");     SVC_FLAT=$(flat "$GIT_SVC")
ROUTE_FLAT=$(flat "$GIT_ROUTE")
APPS_FLAT=$(flat "$APPS_SVC")
PANEL_FLAT=$(flat "$PANEL_SVC")
BACKEND_FLAT=$(flat "$BACKEND")
BAPPS_FLAT=$(flat "$BACKEND_APPS")
ROUTER_FLAT=$(flat "$ROUTER")
UI_FLAT=$(flat "$UI")
MIG_FLAT=$(tr -d ' \n' < "$MIG")

has() { # has <label> <haystack> <needle>
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" ;; esac
}
hasnt() {
  case "$2" in *"$3"*) bad "$1" ;; *) ok "$1" ;; esac
}
count_ge() { # count_ge <label> <haystack> <needle> <min>
  local n
  n=$(printf '%s' "$2" | grep -oF "$3" | wc -l)
  if [ "$n" -ge "$4" ]; then ok "$1 ($n)"; else bad "$1 (found $n, want >= $4)"; fi
}

echo "§0 the subjects parse (a truncated subject must not read as a clean sweep)"
for fn in plan_membership verify_service_identity verify_service verify_services validate_services \
          encode_services decode_services reconcile reattach_all release_for_database; do
  has "agent git_db_link::$fn is defined" "$LINK_FLAT" "fn${fn}("
done
for fn in normalize db_alias_conflict owned_apps check_owned check_linkable replace forget_app \
          agent_fields confirmed require_confirmed compose_refusal load_json; do
  has "panel git_service_link::$fn is defined" "$PANEL_FLAT" "fn${fn}("
done
has "plan_recreate_networks is defined" "$APPS_FLAT" "fnplan_recreate_networks("
has "the picker endpoint is defined" "$BACKEND_FLAT" "pubasyncfnlinkable_services("

echo
echo "§1 ownership: the deployment owner's own template apps, same server - at save AND at deploy"
has "agent: the container name is the app's" "$LINK_FLAT" 'letexpected=format!("{APP_CONTAINER_PREFIX}{app_name}");'
has "agent: only a panel-managed template app" "$LINK_FLAT" 'l.get("dockpanel.app.template").is_none_or(|t|t.is_empty())'
has "agent: never a git deploy or other typed container" "$LINK_FLAT" '||l.get("dockpanel.type").is_some()'
has "agent: the owner label must be the deployment's owner" "$LINK_FLAT" 'ifl.get("dockpanel.user.id").map(String::as_str)!=Some(owner){'
has "agent: services are looked up by name, never by a stored id" "$LINK_FLAT" 'letcontainer=format!("{APP_CONTAINER_PREFIX}{}",req.app_name);'
has "panel: only apps carrying the caller as owner are offered or accepted" "$PANEL_FLAT" '.filter(|a|owner_of(a)==Some(owner))'
has "panel: another owner's app answers like a missing one" "$PANEL_FLAT" '"App{}notfoundamongyourappsonthisdeployment'"'"'sserver"'
has "panel: the check asks the agent of the given server" "$PANEL_FLAT" '.for_server(server_id)'
has "create checks against the caller's server" "$BACKEND_FLAT" 'check_linkable(&state.agents,server_id,&linked_services,claims.sub)'
has "update checks against the deployment's own server" "$BACKEND_FLAT" 'check_linkable(&state.agents,deploy_server_id,&list,claims.sub)'
count_ge "every deploy door sends the ROW's owner" "$BACKEND_FLAT" 'ServiceLinks{owner:config.user_id,services:&service_list}' 3
has "the automatic rollback sends it too" "$BACKEND_FLAT" 'owner:monitor_owner,services:&monitor_service_list,'
has "the agent route requires the owner with any service" "$LINK_FLAT" 'if!owner.is_some_and(|o|uuid::Uuid::parse_str(o).is_ok()){'
has "the picker is filtered to the caller" "$BACKEND_FLAT" 'owned_apps(&apps,claims.sub)'

echo
echo "§2 aliases: DNS labels, unique, capped, and db reserved in both directions"
has "agent: db is the linked database's" "$LINK_FLAT" 'ifdb_linked&&s.alias==DB_ALIAS{'
has "agent: duplicate aliases refused" "$LINK_FLAT" 'if!aliases.insert(s.alias.as_str()){'
has "agent: cap" "$LINK_FLAT" 'pubconstMAX_LINKED_SERVICES:usize=8;'
has "panel: same cap" "$PANEL_FLAT" 'pub(crate)constMAX_LINKED_SERVICES:usize=8;'
has "panel: db refused while a database is linked" "$PANEL_FLAT" 'ifdb_linked&&alias==crate::services::git_db_link::DB_HOST{'
has "update validates against the FINAL database state" "$BACKEND_FLAT" 'normalize(list,db_linked_after)'
has "update refuses linking a database onto a stored db alias" "$BACKEND_FLAT" 'git_service_link::db_alias_conflict(&stored)'
has "create validates against the database just decided" "$BACKEND_FLAT" 'database_id.is_some(),).map_err(|m|err(StatusCode::BAD_REQUEST,&m))?;'
has "migration: alias is a DNS label" "$MIG_FLAT" "CHECK(alias~'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\$')"
has "migration: alias unique per deployment" "$MIG_FLAT" 'UNIQUE(deploy_id,alias)'
has "migration: app unique per deployment" "$MIG_FLAT" 'UNIQUE(deploy_id,app_name)'

echo
echo "§3 previews never get linked services"
has "agent route refuses services for any scope but deploy" "$ROUTE_FLAT" 'if!body.linked_services.is_empty(){ifscope!=ownership::GitScope::Deploy{'
has "agent route validates them before anything runs" "$ROUTE_FLAT" 'git_db_link::validate_services(&body.linked_services,body.linked_db.is_some(),body.link_owner.as_deref(),)'
has "the panel's preview deploy passes no services" "$BACKEND_FLAT" 'scope:"preview",volumes:&[],linked_db:None,linked_services:None,'
has "services are reconciled in the Deploy space only" "$SVC_FLAT" 'letlink_network=ifscope==ownership::GitScope::Deploy{'

echo
echo "§4 reconcile: one plan for the whole membership, teardown only when nothing is declared"
has "the network goes only when neither a database nor a service is declared" "$LINK_FLAT" 'ifdb.is_none()&&services.is_empty(){'
has "a services-only network is labelled for no database" "$LINK_FLAT" 'letdb_key=db.map(|d|d.id.as_str()).unwrap_or("");'
has "reconcile executes the pure plan" "$LINK_FLAT" 'forstepinplan_membership(name,&current,db,services){'
has "a declared member with the wrong alias is re-attached" "$LINK_FLAT" 'ifm.aliases.iter().any(|a|a==wanted[i].1){satisfied[i]=true;}else{disconnect.push(LinkStep::Disconnect(m.id.clone()));}'
has "anything undeclared is still evicted" "$LINK_FLAT" 'elseif!may_stay(&m.id,m.labels.as_ref(),name,None){'
has "disconnects come before attaches" "$LINK_FLAT" 'disconnect.into_iter().chain(attach).collect()'
VER_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'verify_services(&docker, linked_services, link_owner)' | head -1 | cut -d: -f1)
STOP_AT=$(printf '%s\n' "$SVC_CODE" | grep -n '\.stop_container(&container_id, Some(StopContainerOptions { t: 10 }))' | head -1 | cut -d: -f1)
if [ -n "$VER_AT" ] && [ -n "$STOP_AT" ] && [ "$VER_AT" -lt "$STOP_AT" ]; then
  ok "services are proven (line $VER_AT) before the old container is stopped (line $STOP_AT)"
else
  bad "services are no longer proven before the old container is stopped (verify=$VER_AT stop=$STOP_AT)"
fi
has "the deploy reconciles the database AND the services together" "$SVC_FLAT" 'super::git_db_link::reconcile(&docker,name,verified.as_ref(),&services).await?'
case "$LINK_PROD" in
  *remove_container\(*|*stop_container\(*|*restart_container\(*) bad "the link code stops, restarts or removes a container" ;;
  *) ok "the link code never stops, restarts or removes a container - it only (dis)connects" ;;
esac

echo
echo "§5 unlink, app removal, deployment and database deletion"
has "removing an app forgets its links" "$BAPPS_FLAT" 'crate::services::git_service_link::forget_app(&state.db,server_id,name).await;'
has "forget_app is scoped to the server the app was removed from" "$PANEL_FLAT" 'WHEREls.deploy_id=d.idANDd.server_id=$1ANDls.app_name=$2'
has "deleting the deployment cascades its links" "$MIG_FLAT" 'REFERENCESgit_deploys(id)ONDELETECASCADE'
has "deleting the deployment removes the network" "$SVC_FLAT" 'super::git_db_link::reconcile(&docker,name,None,&[])'
has "deleting a database keeps a network that still carries services" "$LINK_FLAT" 'letoutcome=ifcarries_services{'
has "links are replaced atomically" "$PANEL_FLAT" 'letmuttx=db.begin().await?;'

echo
echo "§6 recreated services rejoin; agent restarts replay"
has "a link network is never the recreated container's primary" "$APPS_FLAT" '.filter(|m|m!="bridge"&&!is_link(m)&&endpoints.contains_key(m))'
has "...nor the fallback primary" "$APPS_FLAT" '.find(|n|*n!="bridge"&&!is_link(n))'
has "with only the bridge as primary, link networks still come back by connect" "$APPS_FLAT" 'connect:endpoints.into_iter().filter(|(n,_)|is_link(n)).collect(),'
has "a vanished link network does not block the app's update" "$APPS_FLAT" 'ifnetwork.starts_with(super::git_db_link::LINK_NETWORK_PREFIX)&&docker.inspect_network::<String>(&network,None).await.is_err()'
count_ge "every verifying recreate path can drop it" "$APPS_FLAT" 'networks.verify(&docker).await?;' 3
has "the app container records its services" "$SVC_FLAT" 'super::git_db_link::LINK_SERVICES_LABEL.to_string(),super::git_db_link::encode_services(linked_services),'
has "...and the owner they were proven against" "$SVC_FLAT" 'super::git_db_link::LINK_OWNER_LABEL.to_string(),'
has "reattach_all finds services-only deployments too" "$LINK_FLAT" 'forlabelin[LINK_DB_LABEL,LINK_SERVICES_LABEL]{'
has "reattach_all re-proves each service against the recorded owner" "$LINK_FLAT" 'Some(o)=>matchverify_service(&docker,&req,o).await{'

echo
echo "§7 version skew and compose"
count_ge "the attended deploy doors require the services confirmation" "$BACKEND_FLAT" 'git_service_link::require_confirmed(' 3
has "the agent confirms the services it linked" "$ROUTE_FLAT" 'response["linked_services_network"]='
count_ge "both compose doors refuse a deploy with services" "$BACKEND_FLAT" 'git_service_link::compose_refusal(&crate::services::git_service_link::from_column(&config.linked_services))' 2

echo
echo "§8 wire shape and UI"
has "absent keeps, a list (empty included) replaces" "$BACKEND_FLAT" 'letservices_change=matchbody.linked_services.as_deref(){Some(list)=>'
has "every Git Deploy object carries the stored list" "$BACKEND_FLAT" "ASlinked_services"
has "the select uses the shared subquery" "$BACKEND_FLAT" 'GIT_DEPLOY_SELECT.contains(crate::services::git_service_link::LINKED_SERVICES_JSON)'
has "the picker route is registered" "$ROUTER_FLAT" '.route("/api/git-deploys/linkable-services",get(git_deploys::linkable_services))'
has "the form always sends the list" "$UI_FLAT" 'linked_services:formServices'
has "the form offers the caller's linkable apps" "$UI_FLAT" 'api.get<LinkableApp[]>("/git-deploys/linkable-services")'
has "the form has a Linked Services section" "$UI_FLAT" '>LinkedServices</label>'

echo
echo "§9 unit tests exist where a mistake would otherwise be silent"
for t in linked_service_aliases_are_dns_labels_unique_capped_and_not_db the_services_label_round_trips_and_ignores_garbage \
         service_identity_requires_name_template_label_and_owner plan_keeps_declared_members_attaches_missing_ones_and_evicts_the_rest \
         plan_reattaches_a_service_whose_alias_changed plan_finds_a_recreated_service_by_its_new_id_and_evicts_an_unlinked_one \
         a_services_only_network_is_labelled_for_no_database a_linked_mailpit_stays_reachable_across_redeploys_restarts_and_recreates; do
  has "agent unit test: $t" "$LINK_FLAT" "fn${t}("
done
has "agent unit test: a_linked_service_comes_back_on_its_link_network_but_never_through_it" "$APPS_FLAT" 'fna_linked_service_comes_back_on_its_link_network_but_never_through_it('
for t in aliases_are_normalised_and_validated db_is_reserved_only_while_a_database_is_linked duplicates_and_too_many_are_refused \
         only_the_owners_template_apps_are_linkable the_agent_gets_the_services_and_the_owner_and_must_confirm_them \
         a_compose_deploy_with_services_is_refused_not_run_unlinked; do
  has "panel unit test: $t" "$PANEL_FLAT" "fn${t}("
done
has "panel unit test: linked_services_reach_the_agent_with_the_owner_and_alongside_a_database" "$BACKEND_FLAT" 'fnlinked_services_reach_the_agent_with_the_owner_and_alongside_a_database('

echo
echo "§10 the guides say what the product does"
grep -q '^## Linked services' "$GUIDE" && ok "git-deploy.md has a Linked services section" || bad "git-deploy.md has no Linked services section"
grep -q '^### Previews never get linked services' "$GUIDE" && ok "git-deploy.md says previews never get linked services" || bad "git-deploy.md does not say previews never get linked services"
grep -q '^### When the link is (re)applied' "$GUIDE" && ok "git-deploy.md says when the link is restored" || bad "git-deploy.md does not say when the link is restored"
grep -q 'EMAIL_HOST=mailpit' "$GUIDE" && ok "git-deploy.md shows the Mailpit example" || bad "git-deploy.md has no Mailpit example"
grep -q '"linked_services"' "$APIREF" && grep -q 'linkable-services' "$APIREF" && ok "api-reference.md documents linked_services and the picker" || bad "api-reference.md does not document linked_services"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
