#!/usr/bin/env bash
#
# Regression pin for "a policy archives every app data target, with no way to
# leave one out". Seen on a live box: two Git Deploys each carried a 3.4 GB
# regenerable `downloads` bind mount, so every nightly run wrote 2 x 3.4 GB of
# encrypted archives, multiplied by retention.
#
#   A  The exclusions live on the policy (`excluded_targets TEXT[]`) in a NEW
#      migration that sorts after every one already released or pending.
#
#   B  The executor reads the column (a PolicyRow field missing from the
#      SELECT fails every tick at runtime, not at compile time), splits the
#      agent's targets by exact `<owner>/<slug>` match, and archives only the
#      kept ones. An excluded target is neither a success nor a failure: it
#      must not go through `log.push` (which degrades the run status) or
#      `failures += 1`.
#
#   C  The API validates entries, and an update that does not mention the field
#      leaves it alone (COALESCE), like every other field of that UPDATE.
#
#   D  The form's target list comes from the server the executor reaches, not
#      the page's X-Server-Id, and the form keeps the current exclusions when
#      that list cannot be loaded.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

B=panel/backend/src
MIGDIR=panel/backend/migrations
EXEC=$B/services/backup_policy_executor.rs
ROUTES=$B/routes/backup_orchestrator.rs
MOD=$B/routes/mod.rs
FE=panel/frontend/src/pages/BackupOrchestrator.tsx
MIG=$(ls $MIGDIR/*_backup_policy_excluded_targets.sql 2>/dev/null | head -1)
for f in "$EXEC" "$ROUTES" "$MOD" "$FE"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
[ -n "$MIG" ] || { echo "missing $MIGDIR/*_backup_policy_excluded_targets.sql"; exit 1; }

# Strip // comments so a comment quoting the code cannot satisfy an arm.
strip() { sed 's://.*::' "$1"; }
EXEC_SRC=$(strip "$EXEC")
ROUTES_SRC=$(strip "$ROUTES")
# The volume leg of execute_policy, from its guard to the mail and DNS legs.
VOL_LEG=$(sed -n '/if policy.backup_volumes && owner_is_admin/,/Mail and DNS (lot 3)/p' "$EXEC" | sed 's://.*::')

echo "── A. the column, in a new migration ──"

name=$(basename "$MIG")
# 20261204120000 / 20261204120100 are pending PRs; this one must sort after them.
if [[ "$name" > "20261204120100_zzz.sql" ]]; then
  ok "$name sorts after every released or pending migration"
else
  bad "$name does not sort after 20261204120100 - it would collide with pending migrations"
fi
if [[ "$name" =~ ^[0-9]{14}_[a-z0-9_]+\.sql$ ]]; then
  ok "$name follows YYYYMMDDHHMMSS_description.sql"
else
  bad "$name does not follow YYYYMMDDHHMMSS_description.sql"
fi
if sed 's/--.*$//' "$MIG" | grep -qE "ALTER TABLE backup_policies ADD COLUMN IF NOT EXISTS excluded_targets TEXT\[\] NOT NULL DEFAULT '\{\}'"; then
  ok "backup_policies.excluded_targets is TEXT[] NOT NULL DEFAULT '{}' (existing policies exclude nothing)"
else
  bad "the migration no longer adds excluded_targets TEXT[] NOT NULL DEFAULT '{}'"
fi

echo "── B. the executor skips excluded targets, and only those ──"

if grep -qE 'excluded_targets: Vec<String>' <<<"$(sed -n '/^struct PolicyRow/,/^}/p' "$EXEC")"; then
  ok "PolicyRow carries excluded_targets"
else
  bad "PolicyRow has no excluded_targets field"
fi
if grep -qE 'backup_mail, backup_dns, excluded_targets, last_run' <<<"$EXEC_SRC"; then
  ok "the tick SELECT reads excluded_targets (a missing column fails every tick at runtime)"
else
  bad "the tick SELECT does not read excluded_targets"
fi
if grep -qE 'select_targets\(&parsed\.targets, &policy\.excluded_targets\)' <<<"$VOL_LEG"; then
  ok "the volume leg splits the agent's targets by the policy's exclusions"
else
  bad "the volume leg no longer calls select_targets on the policy's exclusions"
fi
if grep -qE 'for target in selection\.kept' <<<"$VOL_LEG"; then
  ok "only the kept targets are archived"
else
  bad "the archive loop does not iterate selection.kept"
fi
if grep -qE 'for target in &?parsed\.targets' <<<"$VOL_LEG"; then
  bad "the archive loop still iterates every listed target"
else
  ok "no loop archives parsed.targets directly"
fi
# Between the split and the archive loop: no failure, no run error.
SKIP_BLOCK=$(sed -n '/let selection = select_targets/,/for target in selection.kept/p' <<<"$VOL_LEG")
if [ -n "$SKIP_BLOCK" ] && ! grep -qE 'failures \+= 1|log\.push' <<<"$SKIP_BLOCK"; then
  ok "an excluded target is neither counted as a failure nor pushed as a run error"
else
  bad "the exclusion block counts a failure or pushes a run error (degrades the run status)"
fi
if grep -qE 'log_event' <<<"$SKIP_BLOCK"; then
  ok "excluded targets are recorded in the system log"
else
  bad "excluded targets are no longer recorded anywhere"
fi
FN_SELECT=$(sed -n '/^pub fn select_targets/,/^}/p' "$EXEC")
if grep -qE '\*e == subject' <<<"$FN_SELECT" && ! grep -qE 'starts_with|contains\(' <<<"$FN_SELECT"; then
  ok "matching is exact on <owner>/<slug> - no prefix match can take a sibling mount"
else
  bad "select_targets no longer matches exactly on the subject"
fi
FN_KEY=$(sed -n '/^pub fn is_valid_target_key/,/^}/p' "$EXEC")
if grep -qE 'split_once\(./.\)' <<<"$FN_KEY" && grep -q 'is_valid_owner_name(owner)' <<<"$FN_KEY" && grep -q 'is_valid_slug(slug)' <<<"$FN_KEY"; then
  ok "a key is one '/' between a valid owner name and a valid slug"
else
  bad "is_valid_target_key no longer checks owner and slug on either side of one '/'"
fi
if grep -qE 'pub const MAX_EXCLUDED_TARGETS: usize = [0-9]+;' <<<"$EXEC_SRC"; then
  ok "the number of exclusions is capped"
else
  bad "MAX_EXCLUDED_TARGETS is gone"
fi
for t in a_target_key_is_owner_slash_slug_and_nothing_else \
         excluded_targets_are_checked_deduplicated_and_capped \
         an_excluded_target_is_skipped_and_only_that_one \
         an_exclusion_naming_no_current_target_is_stale_not_a_failure; do
  if grep -qE "fn $t\(" "$EXEC"; then ok "unit test $t is present"; else bad "unit test $t was removed"; fi
done

echo "── C. the API validates, and an update without the field keeps it ──"

if grep -qE 'excluded_targets = COALESCE\(\$[0-9]+, excluded_targets\)' <<<"$ROUTES_SRC"; then
  ok "PUT keeps excluded_targets when the body omits it (COALESCE)"
else
  bad "PUT assigns excluded_targets unconditionally - an edit that omits it would wipe the list"
fi
if grep -qE 'stop_apps, backup_mail, backup_dns, excluded_targets\)' <<<"$ROUTES_SRC"; then
  ok "POST writes excluded_targets"
else
  bad "POST no longer inserts excluded_targets"
fi
n_param=$(grep -cE 'excluded_targets_param\(req\.excluded_targets' <<<"$ROUTES_SRC")
if [ "$n_param" -ge 2 ]; then
  ok "create and update both validate excluded_targets ($n_param call sites)"
else
  bad "excluded_targets is validated on $n_param of the two write paths"
fi
if grep -qE 'normalize_excluded_targets' <<<"$(sed -n '/^fn excluded_targets_param/,/^}/p' "$ROUTES")" \
   && grep -qE 'BAD_REQUEST' <<<"$(sed -n '/^fn excluded_targets_param/,/^}/p' "$ROUTES")"; then
  ok "an invalid entry is a 400"
else
  bad "excluded_targets_param no longer answers 400 on an invalid entry"
fi

echo "── D. the form lists the executor's server and keeps what it cannot load ──"

if grep -qE '"/api/backup-orchestrator/policies/targets", get\(backup_orchestrator::list_policy_targets\)' "$MOD"; then
  ok "GET /api/backup-orchestrator/policies/targets is routed"
else
  bad "the policy targets listing is not routed"
fi
FN_LIST=$(sed -n '/^pub async fn list_policy_targets/,/^}/p' "$ROUTES" | sed 's://.*::')
if grep -q 'require_admin' <<<"$FN_LIST"; then
  ok "the listing is admin only, like the volume leg"
else
  bad "the listing lost its admin gate"
fi
if grep -q 'local_server_id' <<<"$FN_LIST" && ! grep -q 'ServerScope' <<<"$FN_LIST"; then
  ok "the listing resolves the policy's server, else the local one - never X-Server-Id"
else
  bad "the listing no longer resolves the server the way the executor does"
fi
if grep -qE 'WHERE id = \$1 AND user_id = \$2' <<<"$FN_LIST"; then
  ok "another owner's policy is not readable through the listing"
else
  bad "the listing reads a policy without checking its owner"
fi
if grep -q "Données d'applications exclues" "$FE"; then
  ok "the policy form has the \"Données d'applications exclues\" section"
else
  bad "the exclusion section is gone from the policy form"
fi
if grep -qE 'excluded_targets: p\.excluded_targets' "$FE"; then
  ok "editing a policy starts from its current exclusions (sent back unchanged if the list fails)"
else
  bad "openEditPolicy does not load excluded_targets - a save would clear them"
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
