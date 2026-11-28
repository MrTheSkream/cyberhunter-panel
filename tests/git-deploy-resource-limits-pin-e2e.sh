#!/usr/bin/env bash
#
# Regression pin for the GIT DEPLOY RESOURCE LIMITS on update.
#
# WHAT HAPPENED. `PUT /api/git-deploys/{id}` wrote the two limits bare:
#
#       memory_mb = $8,
#       cpu_percent = $9,
#
# with `memory_mb: Option<i32>` / `cpu_percent: Option<i32>` on the request. A
# PUT that omitted them bound NULL, and NULL is "no limit". The Git Deploy form
# does not send either key, so EVERY save from the form - editing an env var,
# linking a service - silently removed the memory and CPU limits the deploy had
# been created with through the API, and the next deploy ran unconstrained. Every
# other column of the same UPDATE already kept its stored value when absent.
#
# THE FIX. Three states on the wire, like `database_id` beside them:
#
#       key absent      -> Option::None        -> change flag false -> keep
#       key sent null   -> Some(None)          -> change flag true  -> NULL (cleared)
#       key sent n      -> Some(Some(n))       -> change flag true  -> n
#
# The request fields are `Option<Option<i32>>` through the shared
# `secrets::explicit_option` helper, and the SQL is
# `CASE WHEN $flag THEN $value ELSE column END` - never a COALESCE, which can
# set a value but never clear one (see clearable-fields-pin §1).
#
# THE AUDIT. Every other column of the UPDATE is pinned below as keeping its
# stored value when absent: a COALESCE / CASE-COALESCE self-guard, a change
# flag, or (tls_mode / tls_certificate_id) a value the handler resolves from the
# stored row before binding.
#
# Pure source analysis: no box, no build. The deserialization itself is pinned by
# the backend unit tests named in §2.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

BACKEND=panel/backend/src/routes/git_deploys.rs
SECRETS=panel/backend/src/routes/secrets.rs
UI=panel/frontend/src/pages/GitDeploys.tsx
APIREF=docs/api-reference.md

for f in "$BACKEND" "$SECRETS" "$UI" "$APIREF"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

code() { sed 's://.*$::' "$1"; }
flat() { code "$1" | tr -d ' \t\n'; }

BACKEND_FLAT=$(flat "$BACKEND")
SECRETS_FLAT=$(flat "$SECRETS")
# The form's create/update payload alone - the GitDeploy type above it names both keys.
UI_PAYLOAD=$(code "$UI" | awk '/const payload = \{/{on=1} on{print} on&&/^    \};/{exit}' | tr -d ' \t\n')

has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1" ;; *) ok "$1" ;; esac; }

# The UpdateRequest struct alone, so a field of CreateRequest cannot satisfy it.
UPDATE_REQ=$(code "$BACKEND" | awk '/^pub struct UpdateRequest \{/{on=1} on{print} on&&/^\}/{exit}' | tr -d ' \t\n')
# The update handler's UPDATE statement alone.
UPDATE_SQL=$(code "$BACKEND" | awk '/"UPDATE git_deploys SET/{on=1} on{print} on&&/RETURNING \*"/{exit}' | tr -d ' \t\n\\')
# The update handler's bind chain, from that statement to its fetch.
UPDATE_BINDS=$(code "$BACKEND" | awk '/"UPDATE git_deploys SET/{on=1} on&&/\.bind\(/{print} on&&/\.fetch_one\(/{exit}' | tr -d ' \t\n')

echo "§0 the subjects parse (a truncated subject must not read as a clean sweep)"
[ -n "$UPDATE_REQ" ] && ok "UpdateRequest found" || bad "UpdateRequest not found"
[ -n "$UPDATE_SQL" ] && ok "the update's UPDATE statement found" || bad "the update's UPDATE statement not found"
n_binds=$(printf '%s' "$UPDATE_BINDS" | grep -o '\.bind(' | wc -l)
[ "$n_binds" -eq 27 ] && ok "the update binds 27 placeholders" || bad "the update binds $n_binds placeholders, want 27"
has "the double-option helper exists" "$SECRETS_FLAT" 'pub(crate)fnexplicit_option<'"'"'de,D,T>(de:D)->Result<Option<Option<T>>,D::Error>'

echo
echo "§1 the request tells absent from explicit null"
has "memory_mb is a double option" "$UPDATE_REQ" '#[serde(default,deserialize_with="crate::routes::secrets::explicit_option")]pubmemory_mb:Option<Option<i32>>,'
has "cpu_percent is a double option" "$UPDATE_REQ" '#[serde(default,deserialize_with="crate::routes::secrets::explicit_option")]pubcpu_percent:Option<Option<i32>>,'
hasnt "memory_mb is not a plain Option on update" "$UPDATE_REQ" 'pubmemory_mb:Option<i32>,'
hasnt "cpu_percent is not a plain Option on update" "$UPDATE_REQ" 'pubcpu_percent:Option<i32>,'

echo
echo "§2 the deserialization is unit-tested"
for t in an_update_that_omits_the_limits_leaves_them_alone an_explicit_null_clears_a_limit \
         a_number_sets_a_limit_and_each_limit_is_independent a_limit_that_is_not_a_number_is_refused; do
  has "unit test $t" "$BACKEND_FLAT" "fn${t}()"
done

echo
echo "§3 the SQL keeps a stored limit unless the key was sent"
has "memory_mb is written only under its change flag" "$UPDATE_SQL" 'memory_mb=CASEWHEN$26THEN$8ELSEmemory_mbEND,'
has "cpu_percent is written only under its change flag" "$UPDATE_SQL" 'cpu_percent=CASEWHEN$27THEN$9ELSEcpu_percentEND,'
hasnt "memory_mb is not bound bare (the defect)" "$UPDATE_SQL" 'memory_mb=$8,'
hasnt "cpu_percent is not bound bare (the defect)" "$UPDATE_SQL" 'cpu_percent=$9,'
hasnt "memory_mb is not COALESCEd (that could never clear it)" "$UPDATE_SQL" 'COALESCE($8,memory_mb)'
hasnt "cpu_percent is not COALESCEd (that could never clear it)" "$UPDATE_SQL" 'COALESCE($9,cpu_percent)'
has "the value binds are the flattened option" "$UPDATE_BINDS" '.bind(body.memory_mb.flatten()).bind(body.cpu_percent.flatten())'
has "the change flags are bound last, as \$26 and \$27" "$UPDATE_BINDS" '.bind(database_change).bind(database_id).bind(body.memory_mb.is_some()).bind(body.cpu_percent.is_some())'

echo
echo "§4 audit: every other column of the same UPDATE keeps its stored value when absent"
for col in repo_url:1 branch:2 dockerfile:3 container_port:4 domain:5 env_vars:6 auto_deploy:7 \
           build_args:13 build_context:14 github_token:15 deploy_protected:17 preview_ttl_hours:18 volumes:21; do
  c=${col%%:*}; n=${col##*:}
  has "$c = COALESCE(\$$n, $c)" "$UPDATE_SQL" "${c}=COALESCE(\$${n},${c}),"
done
for col in ssl_email:10 pre_build_cmd:11 post_deploy_cmd:12 deploy_cron:16; do
  c=${col%%:*}; n=${col##*:}
  has "$c: '' clears, absent keeps" "$UPDATE_SQL" "${c}=CASEWHEN\$${n}=''THENNULLELSECOALESCE(\$${n},${c})END,"
done
has "database_id under its change flag" "$UPDATE_SQL" 'database_id=CASEWHEN$24THEN$25ELSEdatabase_idEND,'
has "tls_mode is bound from the resolved mode" "$UPDATE_SQL" 'tls_mode=$19,'
has "...which falls back to the stored mode when absent" "$BACKEND_FLAT" 'letmode=requested_mode.unwrap_or(previous_mode);'
has "...the stored mode is read from the row" "$BACKEND_FLAT" 'letprevious_mode=effective_tls_mode(cur_tls_mode.as_deref(),cur_ssl_email.as_deref());'
has "tls_certificate_id is bound from the resolved certificate" "$UPDATE_SQL" 'tls_certificate_id=$20,'
has "...which falls back to the stored alias when absent" "$BACKEND_FLAT" 'None=>cur_alias.clone().ok_or_else(||{'
# Derived, not enumerated: any column assigned a bare placeholder other than the
# two resolved TLS values is a new instance of this defect.
bare=$(printf '%s' "$UPDATE_SQL" | grep -oE '[a-z_]+=\$[0-9]+,' | grep -vE '^(tls_mode=\$19|tls_certificate_id=\$20),$' | tr '\n' ' ')
[ -z "$bare" ] && ok "no other column is assigned a bare placeholder" || bad "bare placeholder assignments: $bare"

echo
echo "§5 the form and the docs"
[ -n "$UI_PAYLOAD" ] && ok "the form's payload found" || bad "the form's payload not found"
has "...and it is the update payload" "$UI_PAYLOAD" 'linked_services:formServices'
hasnt "the form does not send memory_mb (absent means keep)" "$UI_PAYLOAD" 'memory_mb'
hasnt "the form does not send cpu_percent (absent means keep)" "$UI_PAYLOAD" 'cpu_percent'
grep -q '`null` to remove' "$APIREF" && grep -q 'memory_mb' "$APIREF" \
  && ok "api-reference.md says how to keep and clear a limit on update" \
  || bad "api-reference.md does not document the limits on update"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
