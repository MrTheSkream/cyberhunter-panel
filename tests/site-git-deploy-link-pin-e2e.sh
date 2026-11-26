#!/usr/bin/env bash
# site-git-deploy-link-pin-e2e.sh - a proxy site follows a Git Deploy
#
# THE SENTENCE THIS SUITE EXISTS TO PROVE:
#
#   "An existing reverse proxy site can be moved onto a Git Deploy, or onto
#    another local port, through the API - keeping its own vhost (bound IP,
#    aliases, certificate, canonical/HSTS) - and the port it proxies to stays
#    the port the deploy's container really publishes, for as long as the link
#    holds, without anyone editing the database."
#
# Before this, each migration of a hand-made app onto Git Deploy (radorz.com,
# origins, licence, preprod.cyberhunter.fr, cyberhunter.fr) needed
# `UPDATE sites SET proxy_port = <host_port>` by hand, then a call to
# PUT /proxy-options only to make the panel re-render the vhost. A Git Deploy
# cannot take a domain a site holds, and deleting the site to free it would lose
# its IP, aliases, certificate and canonical/HSTS settings.
#
# The mutations this suite must survive:
#   - the link resolved at render time instead of copied into `proxy_port`
#     (SSL renewal, auto-healer, scanner and drift read the row directly);
#   - the deploy looked up by the CALLER instead of the site's owner (an
#     administrator could point a client's site at their own app);
#   - a deploy WITH a domain accepted (its blue-green updates move the
#     container to a port only its own vhost learns);
#   - any code path starting to UPDATE git_deploys.host_port (the copy would
#     go stale silently);
#   - the Git Deploy allocator handing a new deploy a port a site still holds;
#   - a linked site transferred to another owner while it still serves the
#     previous owner's container.
#
#   §A  schema: the link column and its one-site-per-deploy index
#   §B  routes are registered
#   §C  the link writes proxy_port and re-renders in one transaction
#   §D  what may be linked: owner, server, no domain, safe port, proxy runtime
#   §E  the manual port route
#   §F  the copy cannot go stale: nothing updates git_deploys.host_port
#   §G  the Git Deploy side: allocator and domain guard
#   §H  transfer refuses a linked site
#   §I  the UI
#
# Pure source analysis: no box, no network, no build.
# No pipes into `grep -q` (SIGPIPE under pipefail): every arm uses a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

SITES=panel/backend/src/routes/sites.rs
GITD=panel/backend/src/routes/git_deploys.rs
ROUTES=panel/backend/src/routes/mod.rs
MODELS=panel/backend/src/models.rs
MIG=$(ls panel/backend/migrations/*_site_git_deploy_link.sql 2>/dev/null | head -1)
CARD=panel/frontend/src/components/SiteUpstreamCard.tsx
DETAIL=panel/frontend/src/pages/SiteDetail.tsx

for f in "$SITES" "$GITD" "$ROUTES" "$MODELS" "$CARD" "$DETAIL"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Comments out, code intact (see site-disabled-stays-offline-pin-e2e.sh for why
# the naive block-comment regex is wrong).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
has()   { grep -qE -- "$2" <<< "$1"; }
# One function's body, bounded by its own closing brace in column 0.
fn_body() { awk -v pat="$1" '$0 ~ pat {f=1} f {print} f && /^\}/ {exit}' <<< "$2"; }
before() {
  local body="$1" first="$2" second="$3" a b
  a=$(grep -nE -- "$first" <<< "$body" | head -1 | cut -d: -f1)
  b=$(grep -nE -- "$second" <<< "$body" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

SITES_S=$(code "$SITES")
GITD_S=$(code "$GITD")
ROUTES_S=$(code "$ROUTES")
MODELS_S=$(code "$MODELS")

echo "── §A schema ──"
if [ -z "$MIG" ]; then
  bad "A1 no *_site_git_deploy_link.sql migration"
else
  MIG_S=$(grep -v '^\s*--' "$MIG")
  has "$MIG_S" 'ADD COLUMN IF NOT EXISTS git_deploy_id UUID REFERENCES git_deploys\(id\) ON DELETE SET NULL' \
    && ok "A1 sites.git_deploy_id references git_deploys and is cleared, not cascaded, when the deploy goes" \
    || bad "A1 sites.git_deploy_id is missing or would delete the site with its deploy"
  has "$MIG_S" 'CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_git_deploy_id' \
    && has "$MIG_S" 'WHERE git_deploy_id IS NOT NULL' \
    && ok "A2 one site per Git Deploy (partial unique index)" \
    || bad "A2 two sites could follow the same Git Deploy"
fi
SITE_STRUCT=$(awk '/pub struct Site \{/{f=1} f{print} f&&/^\}/{exit}' <<< "$MODELS_S")
has "$SITE_STRUCT" '#\[sqlx\(default\)\]' && has "$SITE_STRUCT" 'pub git_deploy_id: Option<Uuid>' \
  && ok "A3 the Site model carries git_deploy_id" \
  || bad "A3 the Site model does not read git_deploy_id"

echo "── §B routes ──"
has "$ROUTES_S" '"/api/sites/\{id\}/proxy-port", put\(sites::set_proxy_port\)' \
  && ok "B1 PUT /api/sites/{id}/proxy-port is routed" \
  || bad "B1 PUT /api/sites/{id}/proxy-port is not routed"
has "$ROUTES_S" '"/api/sites/\{id\}/git-deploy", get\(sites::get_git_deploy_link\)\.put\(sites::set_git_deploy\)' \
  && ok "B2 GET and PUT /api/sites/{id}/git-deploy are routed" \
  || bad "B2 /api/sites/{id}/git-deploy is not routed"

echo "── §C the link is materialised and re-rendered in one transaction ──"
APPLY=$(fn_body '^async fn apply_upstream' "$SITES_S")
if [ -z "$APPLY" ]; then
  bad "C SKIPPED: could not bound apply_upstream"
else
  has "$APPLY" 'UPDATE sites SET proxy_port = \$1, git_deploy_id = \$2' \
    && ok "C1 the deploy's port is copied into proxy_port with the link, in one statement" \
    || bad "C1 the link does not write proxy_port - SSL renewal and the healer would render the old port"
  has "$APPLY" 'fetch_one\(&mut \*tx\)' && before "$APPLY" 'UPDATE sites SET proxy_port' 'rebuild_then_commit\(' \
    && ok "C2 the row is written inside the transaction that commits only once the agent accepted the vhost" \
    || bad "C2 the upstream is committed without (or before) the vhost rebuild"
  has "$APPLY" 'upstream_update_error\(' \
    && ok "C3 a port held by another site answers 409, not a 500" \
    || bad "C3 the uniqueness violation is not mapped"
fi
REBUILD=$(fn_body '^async fn rebuild_then_commit' "$SITES_S")
has "$REBUILD" 'nginx_bind_ip\(' && has "$REBUILD" 'build_nginx_body\(updated, bind_ip' \
  && ok "C4 the rebuild keeps the site's bound IP (and every other vhost field of the row)" \
  || bad "C4 the rebuild does not carry the bound IP - an IP-bound site would move to the primary address"
ERRMAP=$(fn_body '^fn upstream_update_error' "$SITES_S")
has "$ERRMAP" 'idx_sites_proxy_port_server' && has "$ERRMAP" 'StatusCode::CONFLICT' \
  && ok "C5 idx_sites_proxy_port_server maps to CONFLICT" \
  || bad "C5 idx_sites_proxy_port_server is not mapped to CONFLICT"

echo "── §D what may be linked ──"
SETGD=$(fn_body '^pub async fn set_git_deploy' "$SITES_S")
if [ -z "$SETGD" ]; then
  bad "D SKIPPED: could not bound set_git_deploy"
else
  has "$SETGD" 'site_and_agent_for_caller\(' \
    && ok "D1 the site is resolved through the owner-or-admin gate" \
    || bad "D1 set_git_deploy does not gate the site on its caller"
  has "$SETGD" 'WHERE d\.id = \$1 AND d\.user_id = \$2' && has "$SETGD" '\.bind\(site\.user_id\)' \
    && ok "D2 the deploy must belong to the SITE's owner, not merely to the caller" \
    || bad "D2 the deploy is not scoped to the site's owner - an admin could point a client's site at another tenant's app"
  before "$SETGD" 'link_refusal\(' 'apply_upstream\(' \
    && ok "D3 the refusal is decided before anything is written" \
    || bad "D3 link_refusal is not consulted before the write"
  has "$SETGD" 'upstream_runtime_refusal\(' \
    && ok "D4 only a proxy site may be linked" \
    || bad "D4 set_git_deploy does not check the runtime"
  has "$SETGD" '"site\.git_deploy_link"' && has "$SETGD" '"site\.git_deploy_unlink"' \
    && ok "D5 link and unlink are both written to the activity log" \
    || bad "D5 link or unlink leaves no activity entry"
fi
REFUSE=$(fn_body '^fn link_refusal' "$SITES_S")
if [ -z "$REFUSE" ]; then
  bad "D SKIPPED: could not bound link_refusal"
else
  has "$REFUSE" 'same_server\(' \
    && ok "D6 a deploy on another server is refused" || bad "D6 the server is not compared"
  has "$REFUSE" 'deploy\.domain' && has "$REFUSE" 'StatusCode::CONFLICT' \
    && ok "D7 a deploy with its own domain is refused (blue-green would strand the site)" \
    || bad "D7 a deploy with a domain can be linked"
  has "$REFUSE" 'is_safe_proxy_port\(deploy\.host_port\)' \
    && ok "D8 the deploy's port is held to the proxy-port rules" \
    || bad "D8 the deploy's port is not checked by is_safe_proxy_port"
fi
SAME=$(fn_body '^fn same_server' "$SITES_S")
has "$SAME" 'None => deploy\.server_is_local' \
  && ok "D9 a site row with no server matches the local server only" \
  || bad "D9 a NULL site server is not normalised to the local server"
RT=$(fn_body '^fn upstream_runtime_refusal' "$SITES_S")
has "$RT" 'runtime == "proxy"' && ! has "$RT" '"node"|"python"' \
  && ok "D10 node and python sites are not offered (their port is their app service's)" \
  || bad "D10 upstream_runtime_refusal accepts more than proxy"

echo "── §E the manual port route ──"
SETPP=$(fn_body '^pub async fn set_proxy_port' "$SITES_S")
if [ -z "$SETPP" ]; then
  bad "E SKIPPED: could not bound set_proxy_port"
else
  has "$SETPP" 'is_safe_proxy_port\(port\)' \
    && ok "E1 the typed port goes through is_safe_proxy_port" || bad "E1 the typed port is not validated"
  has "$SETPP" 'site_and_agent_for_caller\(' \
    && ok "E2 owner-or-admin gate" || bad "E2 set_proxy_port does not gate the site on its caller"
  has "$SETPP" 'site\.git_deploy_id\.is_some\(\)' \
    && ok "E3 refused while the site follows a Git Deploy" \
    || bad "E3 a typed port can overwrite a link"
  has "$SETPP" 'FROM git_deploys d' && has "$SETPP" 'git_previews' \
    && ok "E4 a port a Git Deploy or preview publishes cannot be typed" \
    || bad "E4 a typed port can reach a Git Deploy's container without the link's checks"
  has "$SETPP" 'apply_upstream\(&state, &agent, &site, port, None' \
    && ok "E5 the manual route writes through the same transaction as the link" \
    || bad "E5 set_proxy_port writes the port some other way"
  has "$SETPP" '"site\.proxy_port"' \
    && ok "E6 the change is written to the activity log" || bad "E6 no activity entry for a port change"
fi

echo "── §F the copy cannot go stale ──"
BACKEND_RS=$(find panel/backend/src -name '*.rs' | sort)
[ "$(wc -w <<< "$BACKEND_RS")" -ge 20 ] \
  && ok "F0 enumerated $(wc -w <<< "$BACKEND_RS") backend source files" \
  || bad "F0 the backend enumeration came back with $(wc -w <<< "$BACKEND_RS") files - F1 would be vacuous"
writers=""
for f in $BACKEND_RS; do
  # Any UPDATE of git_deploys whose SET list names host_port.
  if perl -0777 -ne 'exit(!(/UPDATE\s+git_deploys\s+SET[^"]*?\bhost_port\s*=/s))' <<< "$(code "$f")"; then
    writers="$writers$f "
  fi
done
[ -z "$writers" ] \
  && ok "F1 nothing updates git_deploys.host_port after INSERT, so the copied port cannot go stale" \
  || bad "F1 git_deploys.host_port is now updated in: $writers- linked sites must be re-synced there"

echo "── §G the Git Deploy side ──"
CREATE=$(fn_body '^pub async fn create' "$GITD_S")
has "$CREATE" 'UNION SELECT proxy_port FROM sites WHERE server_id = \$1' \
  && ok "G1 the 7000-7999 allocator skips ports a site still proxies to" \
  || bad "G1 a new deploy can be handed a port a site (maybe another tenant's) still serves"
UPDATE=$(fn_body '^pub async fn update' "$GITD_S")
has "$UPDATE" 'FROM sites WHERE git_deploy_id = \$1' && before "$UPDATE" 'FROM sites WHERE git_deploy_id' 'domain_claim::ensure_claimable' \
  && ok "G2 a deploy a site follows cannot take a domain (checked before the claim)" \
  || bad "G2 a followed deploy can gain a domain and turn blue-green"

echo "── §H transfer ──"
TRANSFER=$(fn_body '^pub async fn transfer' "$SITES_S")
has "$TRANSFER" 'git_deploy_id IS NOT NULL' && before "$TRANSFER" 'git_deploy_id IS NOT NULL' 'UPDATE sites SET user_id' \
  && ok "H1 a linked site (or its staging) is refused before ownership moves" \
  || bad "H1 a linked site can be transferred while serving its previous owner's container"

echo "── §I UI ──"
CARD_S=$(cat "$CARD" 2>/dev/null)
has "$CARD_S" '/sites/\$\{siteId\}/git-deploy' && has "$CARD_S" '/sites/\$\{siteId\}/proxy-port' \
  && ok "I1 the upstream card drives both routes" || bad "I1 the upstream card does not call both routes"
DETAIL_S=$(cat "$DETAIL" 2>/dev/null)
has "$DETAIL_S" 'site\.runtime === "proxy" && \(' && has "$DETAIL_S" '<SiteUpstreamCard' \
  && ok "I2 the site page shows it for reverse proxy sites" || bad "I2 the site page does not render the upstream card"

echo
echo "PASS $PASS / FAIL $FAIL"
[ "$FAIL" -eq 0 ]
