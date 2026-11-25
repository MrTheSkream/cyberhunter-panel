#!/usr/bin/env bash
#
# Regression pin for "the policy archives rc.2 could not see" - 132 site
# archives on a live box, taken by a backup policy before
# 20261203000000_site_backup_policy.sql gave `backups` a policy_id.
#
#   A  rc.2 prunes site archives two ways: a per-site schedule prunes rows with
#      `policy_id IS NULL`, a policy prunes rows with its own id. Every archive a
#      policy took before rc.2 reads NULL, so on a site with no per-site schedule
#      neither sweep reached it and the disk kept filling.
#
#   B  The fix must NOT be a blanket UPDATE: the manual route and the per-site
#      schedule write NULL on purpose, and a manual archive is column-for-column
#      identical to a legacy policy archive with no destination. Handing it to
#      a policy would let that policy's retention delete it. The backfill
#      (20261203000100) attributes a row only on run-history evidence.
#
#   C  Every path a policy takes a site archive by must keep writing policy_id,
#      or the leak reopens for new rows.
#
# Pure source analysis: no box, no network, no build. The migration's SQL itself
# was exercised against a throwaway Postgres 16 with every migration applied.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

B=panel/backend/src
MIGDIR=panel/backend/migrations
EXEC=$B/services/backup_policy_executor.rs
SCHED=$B/services/backup_scheduler.rs
HEALER=$B/services/auto_healer.rs
R_BACKUPS=$B/routes/backups.rs
R_SITES=$B/routes/sites.rs
R_DEPLOY=$B/routes/deploy.rs
R_GIT=$B/routes/git_deploys.rs
ORIG=$MIGDIR/20261203000000_site_backup_policy.sql
MIG=$(ls $MIGDIR/*_site_backup_policy_backfill.sql 2>/dev/null | head -1)
for f in "$EXEC" "$SCHED" "$HEALER" "$R_BACKUPS" "$R_SITES" "$R_DEPLOY" "$R_GIT" "$ORIG"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
[ -n "$MIG" ] || { echo "missing $MIGDIR/*_site_backup_policy_backfill.sql"; exit 1; }

# Strip // comments (Rust) and -- comments (SQL) so a header, or a comment
# quoting the old query, cannot satisfy an arm.
strip()    { sed 's://.*::' "$1"; }
stripsql() { sed 's/--.*$//' "$1"; }
# Match on a captured copy, never on a pipe (lesson #51: SIGPIPE under pipefail).
sq() { local f=$1; shift; grep -q "$@" <<<"$(strip "$f")"; }
SQL=$(stripsql "$MIG")
has() { grep -qE "$1" <<<"$SQL"; }

echo "── A. the backfill is a new migration after the one already applied ──"

name=$(basename "$MIG")
if [[ "$name" > "$(basename "$ORIG")" ]]; then
  ok "$name sorts after $(basename "$ORIG")"
else
  bad "$name does not sort after $(basename "$ORIG") - sqlx would refuse or skip it"
fi
if [[ "$name" =~ ^[0-9]{14}_[a-z0-9_]+\.sql$ ]]; then
  ok "$name follows YYYYMMDDHHMMSS_description.sql"
else
  bad "$name does not follow YYYYMMDDHHMMSS_description.sql"
fi
if git rev-parse -q --verify 'v3.1.0-rc.2^{commit}' >/dev/null 2>&1; then
  if git diff --quiet v3.1.0-rc.2 -- "$ORIG"; then
    ok "20261203000000 is byte-identical to the rc.2 release (already applied in prod)"
  else
    bad "20261203000000 was edited after rc.2 - sqlx checksums an applied migration"
  fi
else
  ok "rc.2 tag not present in this clone - edit check skipped"
fi

echo "── B. the backfill only attributes on run-history evidence ──"

if has 'UPDATE backups'; then
  if grep -A3 'UPDATE backups' <<<"$SQL" | grep -qE 'FROM attributed'; then
    ok "the UPDATE is driven by the attributed set, not a blanket SET"
  else
    bad "UPDATE backups is not restricted to the attributed set"
  fi
else
  bad "the backfill no longer updates backups"
fi
if grep -A8 'UPDATE backups' <<<"$SQL" | grep -qE 'b\.policy_id IS NULL'; then
  ok "only NULL rows are ever filled (idempotent, never re-attributes)"
else
  bad "the UPDATE can overwrite a policy_id already set"
fi
has 'r\.finished_at IS NOT NULL' \
  && ok "only FINISHED runs count as evidence (an open run proves nothing)" \
  || bad "an unfinished run window can attribute rows"
has 'b\.created_at BETWEEN r\.started_at AND r\.finished_at' \
  && ok "a row is matched to the run whose window contains it" \
  || bad "the run-window match is gone"
if grep -A3 'NOT EXISTS' <<<"$SQL" | grep -qE 'FROM backup_schedules bs' \
   && has 'bs\.retention_count > 0'; then
  ok "sites with a per-site schedule are left to the schedule's own sweep"
else
  bad "sites with a per-site schedule are no longer excluded"
fi
if has "e->>'kind' = 'site'" && has "e->>'subject' = s\.domain"; then
  ok "a run that failed on the site cannot claim a row written during it"
else
  bad "a run's 'site' error for the domain no longer excludes the row"
fi
if has "e->>'kind' = 'listing' AND e->>'subject' = 'sites'"; then
  ok "a run that could not list the owner's sites cannot claim a row"
else
  bad "a run's 'listing sites' error no longer excludes its window"
fi
# Count EVERY row of the site in the window - an rc.2 policy row already has its
# policy_id, so counting only NULL rows would hand a manual archive beside it to
# the policy.
cnt=$(grep -A4 'SELECT COUNT(\*) FROM backups o' <<<"$SQL")
if grep -q 'o.created_at BETWEEN r.started_at AND r.finished_at' <<<"$cnt" \
   && ! grep -q 'o.policy_id' <<<"$cnt" && has '\) = 1'; then
  ok "attributed only when it is the site's ONLY row in the window, whatever its policy_id"
else
  bad "the one-row-per-window rule is gone or counts only NULL rows"
fi
has 'HAVING COUNT\(DISTINCT policy_id\) = 1' \
  && ok "a row two policies could have taken stays NULL" \
  || bad "an ambiguous row can be handed to one of two policies"
has 'p\.backup_sites' && has 'p\.user_id = s\.user_id' \
  && ok "only a policy that covers the site (backup_sites, same owner) is a candidate" \
  || bad "the coverage predicate (backup_sites, owner) is gone"
if grep -A12 'UPDATE backups' <<<"$SQL" | grep -q 'p.retention_count > 0'; then
  ok "attribution mirrors the sweep's retention_count > 0"
else
  bad "a row can be handed to a policy the sweep never prunes"
fi
if has '_sqlx_migrations'; then
  bad "the backfill reads sqlx's bookkeeping table"
else
  ok "the backfill does not depend on sqlx's bookkeeping table"
fi
has "to_regclass\('public\.backup_policy_runs'\) IS NULL" \
  && ok "guarded on the run history existing" \
  || bad "no guard on backup_policy_runs existing"

echo "── C. every policy site archive is written with its policy_id ──"

ins_all=$(for f in $(find $B -name '*.rs'); do strip "$f" | grep -c 'INSERT INTO backups (' | sed "s|^|$f:|"; done | awk -F: '$2>0')
n_ins=$(awk -F: '{s+=$2} END {print s+0}' <<<"$ins_all")
if [ "$n_ins" -eq 3 ]; then
  ok "three writers of backups rows: $(cut -d: -f1 <<<"$ins_all" | xargs -n1 basename | tr '\n' ' ')"
else
  bad "backups has $n_ins writers, want 3 (manual, schedule, policy): $ins_all"
fi
if [ "$(strip "$EXEC" | grep -c 'INSERT INTO backups (')" -eq 1 ] \
   && sq "$EXEC" -E 'INSERT INTO backups \(site_id, filename, size_bytes, destination_id, uploaded, databases_included, databases_expected, sha256_hash, previous_hash, policy_id\)'; then
  ok "the executor's only site INSERT carries policy_id"
else
  bad "the executor's site INSERT no longer carries policy_id"
fi
if strip "$EXEC" | grep -A12 'INSERT INTO backups (' | grep -q '\.bind(policy\.id)'; then
  ok "the executor binds policy.id into it"
else
  bad "the executor no longer binds policy.id into the site INSERT"
fi
if sq "$EXEC" -E 'prune_recorded_site_archives\($' && strip "$EXEC" | grep -A2 -E 'prune_recorded_site_archives\($' | grep -q 'Some(policy.id)'; then
  ok "the executor prunes the site by its own policy_id right after recording"
else
  bad "the executor's post-insert prune is not scoped to Some(policy.id)"
fi
# No run-now path: execute_policy is private and called from tick() alone.
calls=$(strip "$EXEC" | grep -c 'execute_policy(db, agents, policy, jwt_secret)')
if [ "$calls" -eq 1 ] && ! grep -rq 'execute_policy' --include='*.rs' "$B/routes"; then
  ok "execute_policy is reached only from the scheduled tick (no run-now path)"
else
  bad "execute_policy gained another caller ($calls in the executor) - check it writes policy_id"
fi
for f in "$R_BACKUPS" "$SCHED"; do
  if strip "$f" | grep 'INSERT INTO backups (' | grep -q 'policy_id'; then
    bad "$(basename "$f") now writes policy_id - its NULL is what puts it in the schedule bucket"
  else
    ok "$(basename "$f") writes NULL policy_id on purpose (manual / per-site schedule)"
  fi
done
for f in "$R_DEPLOY" "$R_GIT" "$R_SITES"; do
  if sq "$f" 'INSERT INTO backups'; then
    bad "$(basename "$f") now records site archives - the backfill's writer census is stale"
  else
    ok "$(basename "$f") pre-deploy / pre-delete archives write no backups row"
  fi
done

echo "── D. the two sweeps the backfill feeds ──"

# Production code only: the healer's own unit test quotes both queries.
HEALER_CODE=$(strip "$HEALER" | awk '/#\[cfg\(test\)\]/{exit} {print}')
if grep -qF 'FROM backups WHERE site_id = $1 AND policy_id IS NULL' <<<"$HEALER_CODE"; then
  ok "the per-site schedule sweep prunes only policy_id IS NULL"
else
  bad "the per-site schedule sweep no longer filters policy_id IS NULL"
fi
if grep -B2 -F 'FROM backups WHERE policy_id = $1' <<<"$HEALER_CODE" | grep -q 'PARTITION BY site_id'; then
  ok "the policy sweep prunes its own site archives per site"
else
  bad "the policy sweep no longer prunes backups WHERE policy_id = \$1 per site"
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
