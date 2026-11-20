#!/usr/bin/env bash
# vuln-scanner-backend-pin-e2e.sh - CVE scanner, batch 1 (engine), backend side
#
# Contract: conception/13-scanner-cve-lot1-contrat.md. This suite freezes the
# parts of the backend that a later batch, or a well-meant cleanup, could
# quietly undo:
#
#   §A  the migration: three tables, their keys, checks and cascades, the two
#       default settings, and no `vuln_exceptions` yet (that is batch 2).
#   §B  the sweeper is registered under `spawn_supervised`, walks the fleet one
#       server at a time, records a server's failure and moves on, and gives
#       way to the shutdown broadcast while it waits on an agent job.
#   §C  the merge resolves NOTHING on an `error` or `no_sbom` result (a failed
#       match must not mark every CVE of a target as fixed), nor on a truncated
#       one, and stays the only writer of `resolved_at`.
#   §D  a non-administrator only ever sees the `site` targets of its own sites:
#       every handler in the route block goes through the shared visibility
#       predicate or `require_admin`; the settings PUT is admin only.
#   §E  no alert is raised in this batch (alerts are batch 2).
#   §F  SQL stays parameterised: only constants are formatted into queries, and
#       list filters go through allow-lists.
#
# Pure source analysis: no box, no network, no build.
#
# NO PIPES INTO `grep -q` - under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

MIG=panel/backend/migrations/20261201000000_vuln_scanner.sql
SWEEPER=panel/backend/src/services/vuln_sweeper.rs
ROUTES=panel/backend/src/routes/vulnerabilities.rs
SERVICES_MOD=panel/backend/src/services/mod.rs
ROUTES_MOD=panel/backend/src/routes/mod.rs
MAIN=panel/backend/src/main.rs

for f in "$MIG" "$SWEEPER" "$ROUTES" "$SERVICES_MOD" "$ROUTES_MOD" "$MAIN"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Extracts one top-level Rust fn body (from its signature to the first `}` in
# column 0). `$1` = file, `$2` = regex for the signature line.
# The regex goes through the environment: `awk -v` would eat its backslashes.
body() { RE="$2" awk '$0 ~ ENVIRON["RE"] {i=1} i{print} i && /^}$/{exit}' "$1" 2>/dev/null; }

echo "== §A  the migration: tables, keys, checks, cascades, defaults =="

MIGSQL=$(cat "$MIG" 2>/dev/null)
# Each table's own block, so a key asserted on one cannot be satisfied by another.
block() { awk -v t="$1" '$0 ~ "CREATE TABLE IF NOT EXISTS "t" \\(" {i=1} i{print} i && /^\);$/{exit}' "$MIG" 2>/dev/null; }
TARGETS=$(block vuln_targets); FINDINGS=$(block vuln_findings); STATE=$(block vuln_server_state)

NT=$(grep -c . <<< "$TARGETS"); NF=$(grep -c . <<< "$FINDINGS"); NS=$(grep -c . <<< "$STATE")
if [ "$NT" -ge 15 ] && [ "$NF" -ge 25 ] && [ "$NS" -ge 6 ]; then
  ok "A1-control the three table blocks were extracted ($NT / $NF / $NS lines)"
else
  bad "A1-control table blocks extracted - $NT / $NF / $NS lines (the extractor or the migration broke)"
fi

if ! grep -qE 'vuln_exceptions' <<< "$MIGSQL"; then
  ok "A2 no vuln_exceptions table in batch 1 (exceptions are batch 2)"
else
  bad "A2 vuln_exceptions appeared in the batch-1 migration"
fi

if grep -qE 'UNIQUE \(server_id, kind, ref\)' <<< "$TARGETS"; then
  ok "A3 vuln_targets is unique on (server_id, kind, ref) - the sync upserts on it"
else
  bad "A3 vuln_targets must be UNIQUE (server_id, kind, ref)"
fi

if grep -qE 'UNIQUE \(target_id, vuln_id, package, version\)' <<< "$FINDINGS" \
   && grep -qE 'vuln_id VARCHAR\(64\) NOT NULL' <<< "$FINDINGS" \
   && grep -qE 'package VARCHAR\(256\) NOT NULL' <<< "$FINDINGS" \
   && grep -qE 'version VARCHAR\(128\) NOT NULL' <<< "$FINDINGS"; then
  ok "A4 vuln_findings is unique on (target_id, vuln_id, package, version), every key column NOT NULL"
else
  bad "A4 vuln_findings key: UNIQUE (target_id, vuln_id, package, version) with NOT NULL key columns (a NULL key never conflicts)"
fi

if grep -qE "CHECK \(kind IN \('site', 'image', 'system', 'wordpress'\)\)" <<< "$TARGETS"; then
  ok "A5 the target kind is checked against site/image/system/wordpress"
else
  bad "A5 vuln_targets.kind CHECK list changed"
fi

if grep -qE "CHECK \(severity IN \('critical', 'high', 'medium', 'low', 'unknown'\)\)" <<< "$FINDINGS" \
   && grep -qE "CHECK \(fix_state IN \('fixed', 'not-fixed', 'wont-fix', 'unknown'\)\)" <<< "$FINDINGS"; then
  ok "A6 severity and fix_state are checked against their allow-lists"
else
  bad "A6 vuln_findings severity / fix_state CHECK lists changed"
fi

if grep -qE 'server_id UUID NOT NULL REFERENCES servers\(id\) ON DELETE CASCADE' <<< "$TARGETS" \
   && grep -qE 'site_id UUID NULL REFERENCES sites\(id\) ON DELETE CASCADE' <<< "$TARGETS" \
   && grep -qE 'git_deploy_id UUID NULL REFERENCES git_deploys\(id\) ON DELETE SET NULL' <<< "$TARGETS" \
   && grep -qE 'target_id UUID NOT NULL REFERENCES vuln_targets\(id\) ON DELETE CASCADE' <<< "$FINDINGS" \
   && grep -qE 'server_id UUID PRIMARY KEY REFERENCES servers\(id\) ON DELETE CASCADE' <<< "$STATE"; then
  ok "A7 cascades: server and site delete their targets, a git deploy only unlinks, a target takes its findings"
else
  bad "A7 foreign keys / cascades of the three tables changed"
fi

if grep -qE 'needs_inventory BOOLEAN NOT NULL DEFAULT TRUE' <<< "$TARGETS" \
   && grep -qE 'notified BOOLEAN NOT NULL DEFAULT FALSE' <<< "$FINDINGS" \
   && grep -qE 'resolved_at TIMESTAMPTZ NULL' <<< "$FINDINGS"; then
  ok "A8 a new target starts marked for inventory; a finding starts open and not notified"
else
  bad "A8 needs_inventory / notified / resolved_at defaults changed"
fi

MISSING_COLS=""
for col in db_built db_checked_at last_match_at last_error installed_versions; do
  grep -qE "^\s+$col " <<< "$STATE" || MISSING_COLS="$MISSING_COLS $col"
done
if [ -z "$MISSING_COLS" ]; then
  ok "A9 vuln_server_state carries db_built, db_checked_at, last_match_at, last_error, installed_versions"
else
  bad "A9 vuln_server_state lacks:$MISSING_COLS"
fi

if grep -qE "INSERT INTO settings \(key, value\) VALUES \('vuln_scan_enabled', 'true'\) ON CONFLICT \(key\) DO NOTHING" <<< "$MIGSQL" \
   && grep -qE "INSERT INTO settings \(key, value\) VALUES \('vuln_match_hour', '4'\) ON CONFLICT \(key\) DO NOTHING" <<< "$MIGSQL"; then
  ok "A10 defaults vuln_scan_enabled=true and vuln_match_hour=4, never overwriting an operator's value"
else
  bad "A10 default settings must be inserted with ON CONFLICT DO NOTHING"
fi

echo
echo "== §B  the sweeper is registered, walks the fleet, survives a server, yields to shutdown =="

if grep -qE '^pub mod vuln_sweeper;' "$SERVICES_MOD" && grep -qE '^pub mod vulnerabilities;' "$ROUTES_MOD"; then
  ok "B1 services::vuln_sweeper and routes::vulnerabilities are declared"
else
  bad "B1 pub mod vuln_sweeper / pub mod vulnerabilities missing"
fi

if grep -qE 'spawn_supervised\("vuln_sweeper", &shutdown_tx, move \|rx\| services::vuln_sweeper::run\(' "$MAIN"; then
  ok "B2 main.rs starts the sweeper under spawn_supervised (restarted on panic, given the shutdown receiver)"
else
  bad "B2 the sweeper must be started by spawn_supervised(\"vuln_sweeper\", ...) in main.rs"
fi

RUN=$(body "$SWEEPER" '^pub async fn run\(')
NRUN=$(grep -c . <<< "$RUN")
if [ "$NRUN" -ge 25 ]; then
  ok "B3-control run body extracted - $NRUN lines"
else
  bad "B3-control run body extracted - only $NRUN lines (the extractor broke)"
fi

if grep -qE 'const STARTUP_DELAY: Duration = Duration::from_secs\(5 \* 60\);' "$SWEEPER" \
   && grep -qE 'const CHECK_INTERVAL: Duration = Duration::from_secs\(30 \* 60\);' "$SWEEPER" \
   && grep -qE 'STARTUP_DELAY' <<< "$RUN" && grep -qE 'CHECK_INTERVAL' <<< "$RUN"; then
  ok "B4 first pass after 5 minutes, then every 30 minutes"
else
  bad "B4 startup delay 5 min / interval 30 min changed or unused"
fi

if grep -qE 'agents\.online_fleet\(\)' <<< "$RUN" \
   && grep -qE 'get_setting_bool\(&pool, SETTING_ENABLED, true\)' <<< "$RUN"; then
  ok "B5 each pass is gated on vuln_scan_enabled and walks agents.online_fleet()"
else
  bad "B5 the pass must check vuln_scan_enabled and iterate online_fleet()"
fi

# One server's failure is recorded and the loop goes on: the Failed arm records
# and does not return, and no `?` propagates out of the fleet loop.
FAILED_ARM=$(awk '/Err\(PassError::Failed\(e\)\) => \{/{i=1} i{print} i && /^ +\}$/{exit}' <<< "$RUN")
if grep -qE 'record_server_error\(&pool, member\.id, Some\(&e\)\)' <<< "$FAILED_ARM" \
   && ! grep -qE 'return' <<< "$FAILED_ARM" \
   && ! grep -qE '\)\?' <<< "$RUN"; then
  ok "B6 a failed server is logged, stored in last_error, and the sweep moves to the next server"
else
  bad "B6 a server failure must be recorded without leaving the fleet loop - arm was: $FAILED_ARM"
fi

if grep -qE 'let Ok\(_guard\) = lock\.try_lock\(\) else' <<< "$RUN"; then
  ok "B7 the sweeper skips a server whose lock is held (an on-demand scan is running), never blocks on it"
else
  bad "B7 the sweeper must try_lock the per-server lock"
fi

WAIT=$(body "$SWEEPER" '^async fn wait_job\(')
if grep -qE '_ = shutdown\.recv\(\) => return Err\(PassError::Shutdown\)' <<< "$WAIT" \
   && grep -qE 'tokio::select!' <<< "$WAIT"; then
  ok "B8 waiting on an agent job gives way to the shutdown broadcast"
else
  bad "B8 wait_job must select on shutdown.recv() while it polls"
fi

SCAN_NOW=$(body "$SWEEPER" '^async fn scan_target_inner\(')
if grep -qE 'g = lock\.lock\(\) => g' <<< "$SCAN_NOW"; then
  ok "B9 the on-demand scan waits for the same per-server lock (no two passes on one server)"
else
  bad "B9 scan_target_inner must take the per-server lock"
fi

echo
echo "== §C  the merge resolves nothing on error / no_sbom / truncated =="

MERGE=$(body "$SWEEPER" '^pub fn plan_merge\(')
NMERGE=$(grep -c . <<< "$MERGE")
if [ "$NMERGE" -ge 20 ]; then
  ok "C1-control plan_merge body extracted - $NMERGE lines"
else
  bad "C1-control plan_merge body extracted - only $NMERGE lines (the extractor broke)"
fi

GUARD_LINE=$(grep -nE 'if result\.status != "ok" \{' <<< "$MERGE" | head -1 | cut -d: -f1)
RETURN_LINE=$(grep -nE '^\s+return plan;' <<< "$MERGE" | head -1 | cut -d: -f1)
RESOLVE_LINE=$(grep -nE 'plan\.resolve\.push' <<< "$MERGE" | head -1 | cut -d: -f1)
if [ -n "$GUARD_LINE" ] && [ -n "$RETURN_LINE" ] && [ -n "$RESOLVE_LINE" ] \
   && [ "$GUARD_LINE" -lt "$RETURN_LINE" ] && [ "$RETURN_LINE" -lt "$RESOLVE_LINE" ] \
   && [ $((RETURN_LINE - GUARD_LINE)) -le 1 ]; then
  ok "C2 any status but ok returns an empty plan (line $GUARD_LINE) before anything is resolved (line $RESOLVE_LINE)"
else
  bad "C2 the non-ok guard must return the empty plan before any resolve - guard=${GUARD_LINE:-none} return=${RETURN_LINE:-none} resolve=${RESOLVE_LINE:-none}"
fi

if grep -qE 'if !result\.truncated \{' <<< "$MERGE"; then
  ok "C3 a truncated result (capped at 5000) does not resolve what it lacks"
else
  bad "C3 resolution must be skipped on a truncated result"
fi

TEST_ERR=$(awk '/fn merge_resolves_nothing_on_error_or_no_sbom\(/{i=1} i{print} i && /^    }$/{exit}' "$SWEEPER")
if grep -qE '"error"' <<< "$TEST_ERR" && grep -qE '"no_sbom"' <<< "$TEST_ERR" \
   && grep -qE 'MergePlan::default\(\)' <<< "$TEST_ERR"; then
  ok "C4 a unit test asserts an empty plan for error and no_sbom"
else
  bad "C4 the unit test merge_resolves_nothing_on_error_or_no_sbom is missing or no longer covers both statuses"
fi

# resolved_at is written in exactly two places: set by the resolve statement,
# cleared by the reopen branch of the update - both fed by plan_merge alone.
N_SET=$(grep -cE 'SET resolved_at = now\(\)' "$SWEEPER")
N_USE=$(grep -cE 'RESOLVE_FINDINGS_SQL' "$SWEEPER")
APPLY=$(body "$SWEEPER" '^async fn apply_merge\(')
if [ "$N_SET" -eq 1 ] && [ "$N_USE" -eq 2 ] && grep -qE 'RESOLVE_FINDINGS_SQL' <<< "$APPLY"; then
  ok "C5 the only statement that resolves findings is run from apply_merge (the plan's writer)"
else
  bad "C5 resolved_at must only be set by RESOLVE_FINDINGS_SQL inside apply_merge - set=$N_SET uses=$N_USE"
fi

MATCH=$(body "$SWEEPER" '^async fn run_match\(')
NOSBOM_ARM=$(awk '/"no_sbom" => \{/{i=1} i{print} i && /^ +\}$/{exit}' <<< "$MATCH")
if [ -n "$NOSBOM_ARM" ] && ! grep -qE 'plan_merge|apply_merge' <<< "$NOSBOM_ARM"; then
  ok "C6 a no_sbom result only marks the target for a new inventory, it never reaches the merge writer"
else
  bad "C6 the no_sbom arm of run_match must not merge - arm was: ${NOSBOM_ARM:-missing}"
fi

echo
echo "== §D  non-administrators only see their own sites =="

VIS=$(awk '/^pub const VISIBLE_TARGET: &str =/{i=1} i{print} i && /;$/{exit}' "$ROUTES")
if grep -qE '\$1::bool OR \(t\.kind = .site. AND EXISTS' <<< "$VIS" \
   && grep -qE 's\.id = t\.site_id AND s\.user_id = \$2' <<< "$VIS"; then
  ok "D1 VISIBLE_TARGET: administrator, or a site target whose site the caller owns"
else
  bad "D1 the visibility predicate changed - was: $VIS"
fi

ISADMIN=$(body "$ROUTES" '^fn is_admin\(')
if grep -qE 'claims\.role == "admin"' <<< "$ISADMIN"; then
  ok "D2 the predicate's \$1 comes from claims.role == \"admin\", not from the request"
else
  bad "D2 is_admin must read the role from the claims"
fi

# The handler set is DERIVED from the route block, so a new handler joins the
# check by being routed.
HANDLERS=$(grep -oE 'vulnerabilities::[a-z_]+' "$ROUTES_MOD" | sed 's/vulnerabilities:://' | sort -u)
NH=$(grep -c . <<< "$HANDLERS")
if [ "$NH" -ge 6 ]; then
  ok "D3-control $NH handlers derived from the route block"
else
  bad "D3-control only $NH handlers derived from routes/mod.rs (the derivation broke)"
fi
UNGUARDED=""
for h in $HANDLERS; do
  HB=$(body "$ROUTES" "^pub async fn $h\\(")
  if [ -z "$HB" ]; then UNGUARDED="$UNGUARDED $h(missing)"; continue; fi
  grep -qE 'AuthUser\(claims\)' <<< "$HB" || { UNGUARDED="$UNGUARDED $h(no-AuthUser)"; continue; }
  grep -qE 'VISIBLE_TARGET|visible_target\(|require_admin\(' <<< "$HB" || UNGUARDED="$UNGUARDED $h"
done
if [ -z "$UNGUARDED" ]; then
  ok "D4 every routed handler authenticates and goes through VISIBLE_TARGET, visible_target() or require_admin()"
else
  bad "D4 handlers without the visibility predicate or require_admin:$UNGUARDED"
fi

if grep -qE '"/api/vulnerabilities/settings", get\(vulnerabilities::get_settings\)\.put\(vulnerabilities::put_settings\)' "$ROUTES_MOD"; then
  ok "D5-control the settings route binds PUT to put_settings"
else
  bad "D5-control the settings route no longer binds PUT to put_settings"
fi
PUT=$(body "$ROUTES" '^pub async fn put_settings\(')
ADMIN_LINE=$(grep -nE 'require_admin\(&claims\.role\)\?;' <<< "$PUT" | head -1 | cut -d: -f1)
WRITE_LINE=$(grep -nE 'sqlx::query' <<< "$PUT" | head -1 | cut -d: -f1)
if [ -n "$ADMIN_LINE" ] && [ -n "$WRITE_LINE" ] && [ "$ADMIN_LINE" -lt "$WRITE_LINE" ]; then
  ok "D6 PUT settings calls require_admin (line $ADMIN_LINE) before it writes (line $WRITE_LINE)"
else
  bad "D6 PUT settings must require_admin before writing - admin=${ADMIN_LINE:-none} write=${WRITE_LINE:-none}"
fi

SCAN=$(body "$ROUTES" '^pub async fn scan_target\(')
VT_LINE=$(grep -nE 'visible_target\(&state, &claims, id\)' <<< "$SCAN" | head -1 | cut -d: -f1)
SPAWN_LINE=$(grep -nE 'tokio::spawn' <<< "$SCAN" | head -1 | cut -d: -f1)
if [ -n "$VT_LINE" ] && [ -n "$SPAWN_LINE" ] && [ "$VT_LINE" -lt "$SPAWN_LINE" ] \
   && grep -qE 'StatusCode::ACCEPTED' <<< "$SCAN"; then
  ok "D7 scan now: the target is checked visible (owner or admin) before the scan is queued; answers 202"
else
  bad "D7 scan_target must check visibility before spawning, and answer 202"
fi

echo
echo "== §E  no alert in batch 1 =="

if grep -qE 'fire_alert' panel/backend/src/routes/image_scans.rs; then
  ok "E1-control the alert call pattern is still found where it exists (image_scans.rs)"
else
  bad "E1-control fire_alert no longer found in image_scans.rs - E2 may be vacuous"
fi
if ! grep -qE 'fire_alert|notifications::' "$SWEEPER" "$ROUTES"; then
  ok "E2 neither the sweeper nor the routes raise an alert (alerts are batch 2)"
else
  bad "E2 an alert call appeared in the batch-1 files"
fi
if ! grep -rqE '"vuln_scan"' panel/backend/src; then
  ok "E3 no vuln_scan alert type registered yet"
else
  bad "E3 a vuln_scan alert type appeared in batch 1"
fi

echo
echo "== §F  parameterised SQL and allow-listed filters =="

# Every format! that builds a query only interpolates UPPER_CASE constants.
FMT=$(perl -0777 -ne 'while (/query(?:_as|_scalar)?(?:::<[^>]*>)?\(\s*&format!\(\s*"([^"]*)"/gs) { print "$1\n" }' "$ROUTES" "$SWEEPER")
NFMT=$(grep -c . <<< "$FMT")
LOWER=$(grep -oE '\{[^}]*\}' <<< "$FMT" | grep -vE '^\{[A-Z_]+\}$' | sort -u | tr '\n' ' ')
if [ "$NFMT" -ge 5 ]; then
  ok "F1-control $NFMT formatted queries found"
else
  bad "F1-control only $NFMT formatted queries found (the extractor broke)"
fi
if [ -z "${LOWER// /}" ]; then
  ok "F2 formatted queries interpolate constants only; every value is a bind"
else
  bad "F2 a formatted query interpolates a non-constant: $LOWER"
fi

PF=$(body "$ROUTES" '^pub fn parse_filters\(')
if grep -qE 'listed\("severity", &q\.severity, SEVERITIES\)' <<< "$PF" \
   && grep -qE 'listed\("kind", &q\.kind, KINDS\)' <<< "$PF" \
   && grep -qE "const SEVERITIES: &\[&str\] = &\[\"critical\", \"high\", \"medium\", \"low\", \"unknown\"\];" "$ROUTES"; then
  ok "F3 severity and kind filters go through allow-lists"
else
  bad "F3 severity / kind filters must be checked against SEVERITIES / KINDS"
fi

echo
printf 'vuln-scanner-backend: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
