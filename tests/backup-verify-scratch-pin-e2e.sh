#!/usr/bin/env bash
#
# Regression pin for two database backup verification defects seen on a live
# v3.1.0-rc.2 install.
#
#   A  The verifier's scratch `mariadb:11` / `postgres:16-alpine` containers were
#      removed with `docker rm -f` and no `-v`. Both images declare a VOLUME for
#      their data directory, so every verification left an anonymous volume
#      behind: 51 of them (12-168 MB each, 7.5 GB) in five days, created at the
#      verifier's 6-hourly ticks. The database drill had the same shape.
#
#   B  Nothing removed a scratch container an interrupted verify or drill left.
#
#   C  An encrypted policy dump (`*.sql.gz.enc`) was piped straight to `zcat`:
#      verify never decrypted, so every encrypted database "failed to restore"
#      and raised "Backup verification failed". The panel did not even send the
#      passphrase. The drill had the same defect.
#
#   D  Verify went through plain `post`, capped at 60 s, while the agent gives
#      the engine 40 s to start and the restore 120 s.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

A=panel/agent/src
B=panel/backend/src
VERIFY=$A/services/backup_verify.rs
DRILL=$A/services/backup_drill.rs
R_VERIFY=$A/routes/backup_verify.rs
R_DRILL=$A/routes/backup_drill.rs
MAIN=$A/main.rs
EXEC=$B/services/backup_policy_executor.rs
VERIFIER=$B/services/backup_verifier.rs
DSCHED=$B/services/drill_scheduler.rs
ORCH=$B/routes/backup_orchestrator.rs
for f in "$VERIFY" "$DRILL" "$R_VERIFY" "$R_DRILL" "$MAIN" "$EXEC" "$VERIFIER" "$DSCHED" "$ORCH"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip // line comments so this header, or a comment quoting the old call,
# cannot satisfy an arm.
strip() { sed 's://.*::' "$1"; }
# `grep -q` on a pipe closes it early, which under pipefail fails the
# pipeline through sed's SIGPIPE (lesson #51) - so match on a captured copy.
sq() { local f=$1; shift; grep -q "$@" <<<"$(strip "$f")"; }

echo "── A. scratch containers go with their anonymous volumes ──"

if sq "$VERIFY" '\["rm", "-f", "-v", container_name\]'; then
  ok "scratch_rm_args removes the container with -v"
else
  bad "scratch_rm_args no longer passes -v - every verify leaks a data volume again"
fi
for f in "$VERIFY" "$DRILL"; do
  # `["rm", "-f", &x]`: a container removal with no -v (`["volume", "rm", ...]` is not one).
  hits=$(strip "$f" | grep -nF '["rm", "-f", &')
  if [ -z "$hits" ]; then
    ok "$(basename "$f") has no docker rm -f without -v"
  else
    bad "$(basename "$f") removes a container without -v: $hits"
  fi
done
if [ "$(strip "$VERIFY" | grep -c 'remove_scratch_container(&container_name)')" -ge 1 ]; then
  ok "verify_db_backup cleans up through remove_scratch_container"
else
  bad "verify_db_backup no longer cleans up through remove_scratch_container"
fi
if [ "$(strip "$DRILL" | grep -c 'remove_scratch_container(&container_name)')" -ge 2 ]; then
  ok "the database and site drills clean up through remove_scratch_container"
else
  bad "a drill no longer cleans up through remove_scratch_container"
fi

echo "── B. leftovers are swept at startup ──"

if sq "$MAIN" 'backup_verify::sweep_scratch_leftovers()'; then
  ok "main.rs sweeps scratch leftovers"
else
  bad "main.rs no longer sweeps scratch leftovers"
fi
main=$(strip "$MAIN")
sweep_line=$(grep -n 'sweep_scratch_leftovers' <<<"$main" | head -1 | cut -d: -f1)
serve_line=$(grep -nE 'axum::serve|\.serve\(' <<<"$main" | head -1 | cut -d: -f1)
if [ -n "$sweep_line" ] && [ -n "$serve_line" ] && [ "$sweep_line" -lt "$serve_line" ]; then
  ok "the sweep runs before the agent serves (no check in progress can be swept)"
else
  bad "the sweep is not before the first serve (sweep=${sweep_line:-none} serve=${serve_line:-none})"
fi
if sq "$VERIFY" 'SCRATCH_CONTAINER_PREFIXES: \[&str; 2\] = \["dockpanel-verify-", "dockpanel-drill-"\]'; then
  ok "the sweep matches only the verify and drill prefixes"
else
  bad "the sweep's prefixes changed"
fi
if sq "$VERIFY" 'volume", "prune' || sq "$VERIFY" 'system", "prune'; then
  bad "verify prunes volumes it cannot attribute to itself"
else
  ok "no blanket docker volume prune"
fi

echo "── C. encrypted dumps are decrypted before the restore ──"

if grep -A5 'pub async fn verify_db_backup(' "$VERIFY" | grep -q 'encryption_key: Option<&str>'; then
  ok "verify_db_backup takes the passphrase"
else
  bad "verify_db_backup takes no passphrase"
fi
if grep -A5 'pub async fn drill_db_backup(' "$DRILL" | grep -q 'encryption_key: Option<&str>'; then
  ok "drill_db_backup takes the passphrase"
else
  bad "drill_db_backup takes no passphrase"
fi
for f in "$VERIFY" "$DRILL"; do
  if sq "$f" 'open_dump(&dir, filename, encryption_key)'; then
    ok "$(basename "$f") opens the dump through open_dump"
  else
    bad "$(basename "$f") no longer opens the dump through open_dump"
  fi
done
body=$(awk '/pub\(crate\) async fn open_dump\(/,/^}/' "$VERIFY")
if grep -q 'encryption::verify_file' <<<"$body" && grep -q 'encryption::decrypt_file' <<<"$body"; then
  ok "open_dump checks the integrity tag, then decrypts"
else
  bad "open_dump no longer checks the tag and decrypts"
fi
if grep -q '\.dec-{:016x}\.part' <<<"$body"; then
  ok "the decrypted copy is a hidden .part (swept at startup, never listed)"
else
  bad "the decrypted copy is no longer a hidden .part"
fi
for f in "$R_VERIFY" "$R_DRILL"; do
  if grep -A6 -E 'pub struct (VerifyDbRequest|DrillDbRequest)' "$f" | grep -q 'pub encryption_key: Option<String>'; then
    ok "$(basename "$f") accepts encryption_key for a database"
  else
    bad "$(basename "$f") drops the database encryption_key"
  fi
done

if sq "$EXEC" 'pub fn db_check_body('; then
  ok "db_check_body builds the verify/drill body"
else
  bad "db_check_body is gone"
fi
# The verifier derives a key for volumes too, so it needs two: volumes and dumps.
for pair in "$VERIFIER:2" "$DSCHED:1" "$ORCH:2"; do
  f=${pair%:*}; want=${pair##*:}
  got=$(strip "$f" | grep -cE 'db_check_body\(|row_encryption_key\(\*encrypted')
  if [ "$got" -ge "$want" ]; then
    ok "$(basename "$f") sends the row's passphrase ($got)"
  else
    bad "$(basename "$f") sends the passphrase $got time(s), want $want"
  fi
done
for f in "$VERIFIER" "$DSCHED" "$ORCH"; do
  hits=$(strip "$f" | grep -nE 'SELECT .*db_type.*(FROM database_backups|db_name, filename)' | grep -v 'encryption_key_version')
  if [ -z "$hits" ]; then
    ok "$(basename "$f") reads encrypted + encryption_key_version with every dump it checks"
  else
    bad "$(basename "$f") selects a dump to check without its key version: $hits"
  fi
done

echo "── D. verify is not cut short at 60 s ──"

hits=$(for f in $(find $B -name '*.rs'); do
  strip "$f" | grep -n '\.post("/backups/verify/database"' | sed "s|^|$f:|"
done)
if [ -z "$hits" ]; then
  ok "no /backups/verify/database goes through the 60 s post"
else
  bad "verify/database still goes through plain post: $hits"
fi
got=$(for f in "$VERIFIER" "$ORCH"; do strip "$f"; done | grep -c 'DB_VERIFY_TIMEOUT_SECS')
if [ "$got" -ge 2 ]; then
  ok "both verify callers pass DB_VERIFY_TIMEOUT_SECS ($got)"
else
  bad "DB_VERIFY_TIMEOUT_SECS used $got time(s), want 2"
fi

echo "── E. the unit tests that drive the above exist ──"
for t in \
  "$VERIFY:fn scratch_rm_removes_anonymous_volumes" \
  "$VERIFY:fn scratch_names_keeps_only_ours" \
  "$VERIFY:fn open_dump_reads_a_plain_dump_in_place" \
  "$VERIFY:fn open_dump_decrypts_an_encrypted_dump_to_a_hidden_temporary" \
  "$VERIFY:fn open_dump_wrong_key_is_a_failed_integrity_check" \
  "$VERIFY:fn open_dump_tampered_file_is_a_failed_integrity_check" \
  "$VERIFY:fn open_dump_without_key_is_refused_not_verified" \
  "$VERIFY:fn open_dump_accepts_a_legacy_untagged_dump_like_restore_does" \
  "$EXEC:fn db_check_body_carries_the_rows_own_key_only_when_encrypted"; do
  f=${t%%:*}; name=${t#*:}
  if grep -q "$name" "$f"; then ok "$(basename "$f"): ${name#fn }"; else bad "$(basename "$f") lost ${name#fn }"; fi
done

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
