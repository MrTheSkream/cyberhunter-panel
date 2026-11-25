#!/usr/bin/env bash
#
# Regression pin for "the site archive the panel gave up on" - seen on a live
# v3.0.0 install, where it filled a 77 GB disk to 98 % in four days.
#
#   A  Every site archive (`POST /backups/{domain}/create`) went through plain
#      `post`, capped at 60 s, while the agent gives the same request 300 s of
#      tar plus 600 s per database dump. A 1.8 GB archive takes longer than a
#      minute: the panel recorded "agent request timed out after 60s" while the
#      agent finished the archive.
#
#   B  The policy executor then retried - unconditionally - and the retry wrote a
#      second complete archive ~65 s after the first. Neither was registered, so
#      nothing ever pruned them: ~7 GB a night for two sites, until volume backups
#      failed with 507 for want of disk.
#
#   C  Site archives were written straight to their final name, 0644, so a tar
#      the agent's own timeout cut short left a truncated archive under a name
#      every listing treats as good, readable by the www-data every hosted site's
#      PHP runs as (every database dump beside it is 0600).
#
#   D  Local retention of site archives existed only for per-site schedules, on
#      the auto-healer's own 24 h clock: a site held retention+1 archives between
#      a backup and the next sweep, and a site covered by a policy alone - its
#      rows carried no policy_id - was never pruned locally at all.
#
#   E  Nothing looked at archives on disk that no row names.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

B=panel/backend/src
AG_CLIENT=$B/services/agent.rs
EXEC=$B/services/backup_policy_executor.rs
SCHED=$B/services/backup_scheduler.rs
HEALER=$B/services/auto_healer.rs
R_BACKUPS=$B/routes/backups.rs
R_SITES=$B/routes/sites.rs
R_DEPLOY=$B/routes/deploy.rs
R_GIT=$B/routes/git_deploys.rs
AGENT=panel/agent/src/services/backups.rs
MIG=$(ls panel/backend/migrations/*_site_backup_policy.sql 2>/dev/null | head -1)
for f in "$AG_CLIENT" "$EXEC" "$SCHED" "$HEALER" "$R_BACKUPS" "$R_SITES" "$R_DEPLOY" "$R_GIT" "$AGENT"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip // line comments so this header, or a comment quoting the old call,
# cannot satisfy an arm.
strip() { sed 's://.*::' "$1"; }
# `grep -q` on a pipe closes it early, which under pipefail fails the
# pipeline through sed's SIGPIPE (lesson #51) - so match on a captured copy.
sq() { local f=$1; shift; grep -q "$@" <<<"$(strip "$f")"; }

echo "── A. every site archive uses the long-op call ──"

# No `.post(` within three lines before a `/backups/{…}/create` path, anywhere in
# the backend. The path is built inline at four sites and into a variable at
# three; both shapes are covered below.
hits=$(for f in $(find $B -name '*.rs'); do
  strip "$f" | grep -n -B3 '"/backups/{[^"]*}/create"' | grep -E '\.post\(' | grep -v post_long | sed "s|^|$f:|"
done)
if [ -z "$hits" ]; then
  ok "no /backups/{domain}/create is reached through the 60 s post"
else
  bad "a site archive still goes through plain post: $hits"
fi

for pair in "$EXEC:2" "$SCHED:1" "$R_BACKUPS:1" "$R_DEPLOY:1" "$R_GIT:2"; do
  f=${pair%:*}; want=${pair##*:}
  got=$(strip "$f" | grep -c 'SITE_BACKUP_TIMEOUT_SECS')
  if [ "$got" -ge "$want" ]; then
    ok "$(basename "$f") passes SITE_BACKUP_TIMEOUT_SECS ($got)"
  else
    bad "$(basename "$f") uses SITE_BACKUP_TIMEOUT_SECS $got time(s), want $want"
  fi
done

for f in "$EXEC" "$SCHED" "$R_BACKUPS"; do
  if strip "$f" | grep -A2 -E 'post_long\(&(agent_path|create_path)' | grep -c -- 'SITE_BACKUP_TIMEOUT_SECS' >/dev/null; then
    ok "$(basename "$f") sends its create path through post_long with the site budget"
  else
    bad "$(basename "$f") no longer sends its create path through post_long(…, SITE_BACKUP_TIMEOUT_SECS)"
  fi
done

if strip "$R_SITES" | grep -A10 'post_long(' | grep -c -- 'SITE_BACKUP_PREDELETE_TIMEOUT_SECS' >/dev/null; then
  ok "the pre-delete snapshot uses its own bounded long-op budget"
else
  bad "the pre-delete snapshot no longer uses SITE_BACKUP_PREDELETE_TIMEOUT_SECS"
fi

site_budget=$(grep -oE 'pub const SITE_BACKUP_TIMEOUT_SECS: u64 = [0-9]+' "$AG_CLIENT" | grep -oE '[0-9]+$')
pre_budget=$(grep -oE 'pub const SITE_BACKUP_PREDELETE_TIMEOUT_SECS: u64 = [0-9]+' "$AG_CLIENT" | grep -oE '[0-9]+$')
tar_budget=$(grep -oE 'pub const TAR_TIMEOUT_SECS: u64 = [0-9]+' "$AGENT" | grep -oE '[0-9]+$')
dump_budget=$(grep -oE 'from_secs\(600\)' panel/agent/src/services/database_backup.rs | head -1 | grep -oE '[0-9]+')
if [ -n "$site_budget" ] && [ -n "$tar_budget" ] && [ -n "$dump_budget" ] \
   && [ "$site_budget" -ge $((tar_budget + 5 * dump_budget)) ]; then
  ok "site budget ${site_budget}s covers the agent's tar (${tar_budget}s) plus five dumps (${dump_budget}s each)"
else
  bad "site budget '${site_budget:-?}' no longer covers tar '${tar_budget:-?}' + 5 x dump '${dump_budget:-?}'"
fi
if [ -n "$pre_budget" ] && [ "$pre_budget" -gt 60 ] && [ "$pre_budget" -lt 300 ]; then
  ok "pre-delete budget ${pre_budget}s is above 60 s and under the 300 s route ceiling"
else
  bad "pre-delete budget '${pre_budget:-?}' must sit strictly between 60 and 300"
fi

echo "── B. a retry never follows an ambiguous failure ──"

if strip "$EXEC" | grep -B2 -A6 'site_backup_retryable(e)' | grep -c -- 'retried = true' >/dev/null; then
  ok "the executor retries a site backup only behind site_backup_retryable"
else
  bad "the executor's site retry is no longer gated by site_backup_retryable"
fi
if strip "$EXEC" | grep -E 'if result\.is_err\(\) \{' -A3 | grep -c -- '/create' >/dev/null; then
  bad "an unconditional 'if result.is_err()' retry of the site archive is back"
else
  ok "no unconditional retry of the site archive"
fi
fn_body=$(strip "$AG_CLIENT" | awk '/pub fn site_backup_retryable/,/^}/')
if grep -q 'AgentError::Request(m) => m.contains("the operation never started")' <<<"$fn_body"; then
  ok "a Request error is retryable only when the operation never started"
else
  bad "site_backup_retryable treats some timed-out Request as retryable"
fi
if grep -q 'AgentError::Status(code, _) => !matches!(code, 408 | 502..=504 | 520..=527)' <<<"$fn_body"; then
  ok "a gateway status (a proxy that stopped waiting) is not retried"
else
  bad "site_backup_retryable retries a 502/504/524 - a remote timeout in disguise"
fi
if grep -qE 'AgentError::Response\(_\).*=> false' <<<"$fn_body"; then
  ok "a broken response is not retried (the agent may have written the archive)"
else
  bad "site_backup_retryable retries a broken response"
fi

echo "── C. the agent publishes only finished, private archives ──"

body=$(strip "$AGENT" | awk '/^pub async fn create_backup/,/^}/')
if grep -A2 '"czf".into(),' <<<"$body" | grep -q 'part_str.into()'; then
  ok "tar writes into the hidden temporary, not the final name"
else
  bad "tar writes straight to the final archive name again"
fi
if grep -q 'std::fs::rename(&part, &filepath)' <<<"$body" && grep -q 'part_guard.disarm()' <<<"$body"; then
  ok "the archive is renamed into place, and only then is the cleanup guard disarmed"
else
  bad "create_backup no longer renames the finished temporary into place behind its guard"
fi
if grep -q 'create_private_file(&part)' <<<"$body" && grep -q 'set_private(&part)' <<<"$body"; then
  ok "the temporary is created 0600 and re-asserted 0600 before publishing"
else
  bad "the archive is no longer created / kept 0600"
fi
if strip "$AGENT" | awk '/^fn create_private_file/,/^}/' | grep -c -- 'opts.mode(0o600)' >/dev/null \
   && strip "$AGENT" | awk '/^fn create_private_file/,/^}/' | grep -c -- 'create_new(true)' >/dev/null; then
  ok "create_private_file opens exclusively with mode 0600"
else
  bad "create_private_file lost create_new(true) or mode(0o600)"
fi
if sq "$AGENT" 'dir.join(format!(".{filename}.part"))'; then
  ok "the temporary is .{name}.part - the shape remove_stale_partials sweeps"
else
  bad "the temporary is no longer named .{name}.part"
fi
if grep -q 'from_secs(TAR_TIMEOUT_SECS)' <<<"$body"; then
  ok "tar's timeout is the published TAR_TIMEOUT_SECS the panel budget derives from"
else
  bad "tar's timeout is no longer TAR_TIMEOUT_SECS"
fi
if grep -q 'remove_file(&filepath)' <<<"$body"; then
  bad "create_backup deletes the final name on failure again - it should never have written it"
else
  ok "no failure path touches the final archive name"
fi

echo "── D. local retention: by policy, right after recording ──"

if [ -n "$MIG" ] && grep -q 'ALTER TABLE backups ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES backup_policies(id) ON DELETE SET NULL' "$MIG"; then
  ok "backups carries policy_id ($(basename "$MIG"))"
else
  bad "no migration adds backups.policy_id"
fi
if sq "$EXEC" 'INSERT INTO backups (.*policy_id)'; then
  ok "the executor records which policy took the archive"
else
  bad "the executor's site INSERT no longer writes policy_id"
fi
ins=$(strip "$EXEC" | grep -n 'INSERT INTO backups (.*policy_id)' | head -1 | cut -d: -f1)
ret=$(strip "$EXEC" | grep -n '^ *prune_recorded_site_archives($' | head -1 | cut -d: -f1)
if [ -n "$ins" ] && [ -n "$ret" ] && [ "$ret" -gt "$ins" ]; then
  ok "the executor prunes AFTER recording the new archive (line $ret > $ins), not before"
else
  bad "the executor does not prune after its INSERT (insert ${ins:-?}, prune ${ret:-?})"
fi
# The orphan sweep must run for a site whose backup FAILED - those are the sites
# whose archives piled up, and they never reach the success arm. It sits after
# the error arm's "backup failed" log, outside the match.
failed=$(strip "$EXEC" | grep -n 'format!("backup failed ({when}): {e}")' | head -1 | cut -d: -f1)
sweep=$(strip "$EXEC" | grep -nF 'sweep_unrecorded_site_archives(db, agent, *site_id' | tail -1 | cut -d: -f1)
if [ -n "$failed" ] && [ -n "$sweep" ] && [ "$sweep" -gt "$failed" ]; then
  ok "unrecorded archives are swept after the failure arm too (line $sweep > $failed)"
else
  bad "the orphan sweep no longer runs for a failed site backup (failed ${failed:-?}, sweep ${sweep:-?})"
fi
if sq "$SCHED" 'enforce_local_site_retention(db, &agent, row.site_id, &row.domain, None, row.retention_count)'; then
  ok "per-site schedules prune right after recording too"
else
  bad "backup_scheduler no longer prunes after recording"
fi
if sq "$EXEC" 'WHERE site_id = \$1 AND policy_id = \$2'; then
  ok "a policy prunes its own archives of the site"
else
  bad "the executor's prune is no longer scoped to the policy"
fi
if sq "$HEALER" 'FROM backups WHERE policy_id = \$1'; then
  ok "the daily sweep prunes policy site archives as a backstop"
else
  bad "the daily sweep no longer covers policy site archives"
fi

echo "── E. archives on disk that no row names ──"

plan=$(strip "$EXEC" | awk '/^pub fn plan_site_orphans/,/^}/')
if grep -q 'cutoff.is_some_and(|c| stamp < c)' <<<"$plan"; then
  ok "only an unrecorded archive outside the site's retention window is deleted"
else
  bad "plan_site_orphans' deletion rule changed"
fi
# The window ranks unrecorded archives too, or a site with no row is never bounded.
if grep -q 'on_disk.iter().map(|(n, _)| n.as_str())' <<<"$plan"; then
  ok "the window is ranked over every archive on disk, recorded or not"
else
  bad "the retention window counts recorded archives only - a site with no row is unbounded again"
fi
if grep -q 'ORPHAN_GRACE_SECS' <<<"$plan"; then
  ok "the rest are reported only after a grace period"
else
  bad "plan_site_orphans reports without a grace period"
fi
if sq "$EXEC" 'orphan_summary(&site_orphans)'; then
  ok "the executor reports what it kept, once per run"
else
  bad "the executor no longer reports unrecorded archives"
fi

echo "── F. the unit tests that drive the above exist ──"
for t in \
  "$EXEC:fn a_site_backup_is_retried_only_when_no_archive_can_be_in_flight" \
  "$EXEC:fn the_site_backup_budget_covers_the_agents_own_ceiling" \
  "$EXEC:fn a_site_archive_stamp_is_read_from_its_own_name_only" \
  "$EXEC:fn unrecorded_archives_older_than_retention_are_deleted_the_rest_reported" \
  "$EXEC:fn nothing_is_deleted_while_the_window_is_not_full" \
  "$EXEC:fn a_site_with_no_recorded_archive_is_still_bounded" \
  "$AGENT:fn the_archive_lands_private_and_leaves_no_temporary" \
  "$AGENT:fn a_temporary_that_already_exists_is_refused"; do
  f=${t%%:*}; name=${t#*:}
  if grep -q "$name" "$f"; then ok "$(basename "$f"): ${name#fn }"; else bad "$(basename "$f") lost ${name#fn }"; fi
done

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
