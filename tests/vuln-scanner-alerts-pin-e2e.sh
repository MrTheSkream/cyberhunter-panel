#!/usr/bin/env bash
# vuln-scanner-alerts-pin-e2e.sh - CVE scanner, batch 2 (alerts and exceptions), backend
#
# Contract: conception/13-scanner-cve-lots2-5-contrat.md, "Lot 2". This suite
# freezes what a later change could quietly undo:
#
#   §A  the migration: vuln_exceptions (one per target and CVE, a bounded
#       reason, cascades), vuln_targets.alerted_at, the default threshold.
#   §B  the threshold: KEV, or critical/high with a fix; `critical_any` adds
#       unfixed criticals; an active exception never counts. One SQL predicate
#       for "active exception", shared by the sweeper and the routes.
#   §C  the alert: one per target and per 24 hours, through try_fire_alert
#       (never an incident), marked notified only when recorded, resolved for
#       every user holding it once nothing is above the threshold, never able
#       to fail the merge or the pass.
#   §D  the API: exceptions are admin only and bounded to 90 days, accepting
#       re-evaluates the alert, accepted CVEs leave the list and the summary
#       (the summary keeps the target), the threshold setting is allow-listed.
#   §E  the vocabulary: vuln_scan is suppressible; no WordPress target kind.
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

MIG=panel/backend/migrations/20261202000000_vuln_exceptions.sql
SWEEPER=panel/backend/src/services/vuln_sweeper.rs
ROUTES=panel/backend/src/routes/vulnerabilities.rs
ROUTES_MOD=panel/backend/src/routes/mod.rs
NOTIF=panel/backend/src/services/notifications.rs

for f in "$MIG" "$SWEEPER" "$ROUTES" "$ROUTES_MOD" "$NOTIF"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# One top-level Rust item body, from its signature to the first `}` in column 0.
body() { RE="$2" awk '$0 ~ ENVIRON["RE"] {i=1} i{print} i && /^}$/{exit}' "$1" 2>/dev/null; }
# One `const NAME: &str = ...;` declaration, possibly over several lines.
const_of() { awk -v n="$2" '$0 ~ "const "n": &str =" {i=1} i{print} i && /;$/{exit}' "$1" 2>/dev/null; }
lines() { grep -c . <<< "$1"; }

echo "== §A  the migration =="

EXC=$(awk '/CREATE TABLE IF NOT EXISTS vuln_exceptions \(/{i=1} i{print} i && /^\);$/{exit}' "$MIG")
if [ "$(lines "$EXC")" -ge 9 ]; then
  ok "A1-control the vuln_exceptions block was extracted ($(lines "$EXC") lines)"
else
  bad "A1-control vuln_exceptions block extracted - $(lines "$EXC") lines (the extractor or the migration broke)"
fi

if grep -qE 'UNIQUE \(target_id, vuln_id\)' <<< "$EXC" \
   && grep -qE 'vuln_id VARCHAR\(64\) NOT NULL' <<< "$EXC"; then
  ok "A2 one exception per (target_id, vuln_id), the key NOT NULL - the accept route upserts on it"
else
  bad "A2 vuln_exceptions must be UNIQUE (target_id, vuln_id) with a NOT NULL vuln_id"
fi

if grep -qE 'reason TEXT NOT NULL CHECK \(char_length\(reason\) BETWEEN 1 AND 500\)' <<< "$EXC" \
   && grep -qE 'expires_at TIMESTAMPTZ NOT NULL' <<< "$EXC"; then
  ok "A3 a reason of 1 to 500 characters and an expiry are mandatory (no open-ended exception)"
else
  bad "A3 reason CHECK 1..500 and expires_at NOT NULL changed"
fi

if grep -qE 'target_id UUID NOT NULL REFERENCES vuln_targets\(id\) ON DELETE CASCADE' <<< "$EXC" \
   && grep -qE 'created_by UUID NULL REFERENCES users\(id\) ON DELETE SET NULL' <<< "$EXC"; then
  ok "A4 an exception goes with its target; deleting its author keeps it (created_by set NULL)"
else
  bad "A4 vuln_exceptions foreign keys / cascades changed"
fi

if grep -qE 'ALTER TABLE vuln_targets ADD COLUMN IF NOT EXISTS alerted_at TIMESTAMPTZ NULL;' "$MIG" \
   && grep -qE "INSERT INTO settings \(key, value\) VALUES \('vuln_alert_min', 'kev_and_fixable_high'\) ON CONFLICT \(key\) DO NOTHING;" "$MIG"; then
  ok "A5 vuln_targets.alerted_at added; default threshold kev_and_fixable_high, never overwriting a stored one"
else
  bad "A5 alerted_at column or the vuln_alert_min default (ON CONFLICT DO NOTHING) missing"
fi

echo
echo "== §B  the threshold =="

ABOVE=$(body "$SWEEPER" '^pub fn above_threshold\(')
if [ "$(lines "$ABOVE")" -ge 6 ]; then
  ok "B1-control above_threshold body extracted ($(lines "$ABOVE") lines)"
else
  bad "B1-control above_threshold body extracted - $(lines "$ABOVE") lines (the extractor broke)"
fi
EXC_LINE=$(grep -nE 'if f\.excepted \{' <<< "$ABOVE" | head -1 | cut -d: -f1)
RET_LINE=$(grep -nE '^\s+return false;' <<< "$ABOVE" | head -1 | cut -d: -f1)
if [ -n "$EXC_LINE" ] && [ -n "$RET_LINE" ] && [ $((RET_LINE - EXC_LINE)) -eq 1 ]; then
  ok "B2 an excepted CVE returns false before any rule is read (line $EXC_LINE)"
else
  bad "B2 above_threshold must return false first for an excepted CVE - excepted=${EXC_LINE:-none} return=${RET_LINE:-none}"
fi
if grep -qE 'matches!\(f\.severity\.as_str\(\), "critical" \| "high"\) && f\.fix_state == "fixed"' <<< "$ABOVE" \
   && grep -qE 'f\.kev \|\| fixable_high \|\| \(min == AlertMin::CriticalAny && f\.severity == "critical"\)' <<< "$ABOVE"; then
  ok "B3 KEV, or critical/high with a fix; critical_any only adds criticals without a fix"
else
  bad "B3 the threshold rule changed - body was: $ABOVE"
fi

ACT=$(const_of "$SWEEPER" ACTIVE_EXCEPTION)
if grep -qE 'e\.target_id = f\.target_id AND e\.vuln_id = f\.vuln_id AND e\.expires_at > now\(\)' <<< "$ACT"; then
  ok "B4 ACTIVE_EXCEPTION: same target, same CVE, not expired"
else
  bad "B4 ACTIVE_EXCEPTION predicate changed - was: $ACT"
fi
LOADF=$(body "$SWEEPER" '^async fn load_alert_findings\(')
if grep -qE '\{ACTIVE_EXCEPTION\} AS excepted' <<< "$LOADF" && grep -qE 'f\.resolved_at IS NULL' <<< "$LOADF"; then
  ok "B5 the alert decision reads open findings with the shared exception predicate"
else
  bad "B5 load_alert_findings must select {ACTIVE_EXCEPTION} AS excepted over open findings"
fi

TESTS=$(awk '/^#\[cfg\(test\)\]/{i=1} i{print}' "$SWEEPER")
MISSING_T=""
for t in threshold_default_is_kev_or_fixable_critical_high threshold_critical_any_adds_unfixed_criticals_only \
         threshold_never_counts_an_excepted_cve candidates_skip_notified_and_below_threshold_and_sort_kev_first \
         alert_window_is_24_hours alert_text_lists_twenty_lines_then_the_rest alert_text_warning_singular_clipped_and_without_markup; do
  grep -qE "fn $t\(" <<< "$TESTS" || MISSING_T="$MISSING_T $t"
done
if [ -z "$MISSING_T" ]; then
  ok "B6 the pure alert functions keep their unit tests (threshold, candidates, window, text)"
else
  bad "B6 unit tests missing:$MISSING_T"
fi

echo
echo "== §C  the alert path =="

EVAL=$(body "$SWEEPER" '^async fn evaluate_alert_inner\(')
if [ "$(lines "$EVAL")" -ge 40 ]; then
  ok "C1-control evaluate_alert_inner body extracted ($(lines "$EVAL") lines)"
else
  bad "C1-control evaluate_alert_inner body extracted - $(lines "$EVAL") lines (the extractor broke)"
fi

if grep -qE 'if !candidates\.is_empty\(\) && alert_due\(target\.alerted_at, Utc::now\(\)\) \{' <<< "$EVAL" \
   && grep -qE 'const ALERT_WINDOW_HOURS: i64 = 24;' "$SWEEPER" \
   && grep -qE 'now - at > chrono::Duration::hours\(ALERT_WINDOW_HOURS\)' <<< "$(body "$SWEEPER" '^pub fn alert_due\(')"; then
  ok "C2 at most one alert per target and per 24 hours (alerted_at), only when there are candidates"
else
  bad "C2 the fire must be gated on candidates and alert_due(alerted_at) with a 24-hour window"
fi

FIRE=$(perl -0777 -ne 'while (/notifications::try_fire_alert\s*(\((?:[^()]++|(?1))*\))/gs) { my $c = $1; $c =~ s/\s+/ /g; print "$c\n"; }' <<< "$EVAL")
if [ "$(lines "$FIRE")" -eq 1 ] && grep -qE 'Some\(target\.server_id\)' <<< "$FIRE" \
   && grep -qE 'ALERT_TYPE' <<< "$FIRE" && grep -qE '&key' <<< "$FIRE" \
   && grep -qE 'let key = alert_state_key\(target_id\);' <<< "$EVAL" \
   && grep -qE '^pub const ALERT_TYPE: &str = "vuln_scan";' "$SWEEPER"; then
  ok "C3 one try_fire_alert call: type vuln_scan, key vuln:<target_id>, scoped to the target's server"
else
  bad "C3 the fire call changed - was: $FIRE"
fi

if ! grep -qE 'alert_engine::|INSERT INTO [a-z_]*incidents|fire_alert_with_retry|fire_alert_deduped' "$SWEEPER"; then
  ok "C4 never the alert engine, never an incident: a CVE alert can not block a deployment"
else
  bad "C4 the sweeper reaches the alert engine or writes an incident"
fi

DELIV_LINE=$(grep -nE 'if delivered > 0 \{' <<< "$EVAL" | head -1 | cut -d: -f1)
MARK_LINE=$(grep -nE 'MARK_NOTIFIED_SQL' <<< "$EVAL" | head -1 | cut -d: -f1)
OK_LINE=$(grep -nE 'Ok\(true\) => delivered \+= 1,' <<< "$EVAL" | head -1 | cut -d: -f1)
if [ -n "$DELIV_LINE" ] && [ -n "$MARK_LINE" ] && [ -n "$OK_LINE" ] && [ "$OK_LINE" -lt "$DELIV_LINE" ] \
   && [ "$DELIV_LINE" -lt "$MARK_LINE" ] && grep -qE 'TARGET_ALERTED_SQL' <<< "$EVAL"; then
  ok "C5 candidates are marked notified (and alerted_at stamped) only after at least one alert was recorded"
else
  bad "C5 notified must be set inside 'if delivered > 0' - ok=${OK_LINE:-none} gate=${DELIV_LINE:-none} mark=${MARK_LINE:-none}"
fi

if grep -qE 'const W_ALERT_TITLE: usize = 200;' "$SWEEPER" \
   && grep -qE 'clip\(&format!\("\{n\} new \{noun\} on \{\}", plain\(target_ref\)\), W_ALERT_TITLE\)' <<< "$(body "$SWEEPER" '^pub fn alert_text\(')" \
   && grep -qE 'const ALERT_MAX_LINES: usize = 20;' "$SWEEPER"; then
  ok "C6 the title fits alerts.title VARCHAR(200) (a ref is up to 512), 20 lines at most, markup stripped"
else
  bad "C6 the alert title must be clipped to W_ALERT_TITLE = 200 and the list capped at 20 lines"
fi

if grep -qE 'if !still_above_threshold\(&rows, min\) \{' <<< "$EVAL" \
   && grep -qE 'resolve_target_alert\(pool, target_id, &target\.ref_\)' <<< "$EVAL"; then
  ok "C7 the alert resolves once nothing open is above the threshold outside exceptions"
else
  bad "C7 evaluate_alert_inner must resolve when !still_above_threshold"
fi

RES=$(body "$SWEEPER" '^async fn resolve_target_alert\(')
if grep -qE 'FIRING_USERS_SQL' <<< "$RES" && grep -qE 'notifications::resolve_alert\(' <<< "$RES" \
   && grep -qE "status = 'firing'" <<< "$(const_of "$SWEEPER" FIRING_USERS_SQL)"; then
  ok "C8 the resolve reaches every user holding a firing row, not today's recipient list"
else
  bad "C8 resolve_target_alert must resolve for the users of FIRING_USERS_SQL"
fi

WRAP=$(body "$SWEEPER" '^pub async fn evaluate_target_alert\(')
MATCH=$(body "$SWEEPER" '^async fn run_match\(')
ELSE_BLOCK=$(awk '/\} else \{/{i=1} i{print} i && /^ +\}$/{exit}' <<< "$MATCH")
if grep -qE 'if let Err\(e\) = evaluate_alert_inner\(pool, target_id\)\.await' <<< "$WRAP" \
   && grep -qE 'tracing::warn!' <<< "$WRAP" \
   && grep -qE 'evaluate_target_alert\(pool, r\.target_id\)\.await;' <<< "$ELSE_BLOCK" \
   && ! grep -qE 'evaluate_target_alert\([^)]*\)\.await\?' "$SWEEPER"; then
  ok "C9 the alert runs after a stored ok merge only, logs its errors and can not fail the merge or the pass"
else
  bad "C9 evaluate_target_alert must log its errors and be called (without ?) in the else branch of apply_merge"
fi

if grep -qE 'let owner = if target\.kind == "site" \{ target\.site_owner \} else \{ None \};' <<< "$EVAL" \
   && grep -qE 'ALERT_ADMINS_SQL' <<< "$EVAL" \
   && grep -qE "SELECT id FROM users WHERE role = 'admin'" <<< "$(const_of "$SWEEPER" ALERT_ADMINS_SQL)"; then
  ok "C10 recipients: every administrator, plus the site's owner for a site target"
else
  bad "C10 recipients changed (administrators, plus the owner of a site target)"
fi

RUN=$(body "$SWEEPER" '^pub async fn run\(')
SWEEP=$(body "$SWEEPER" '^async fn sweep_server\(')
if grep -qE 'resolve_orphan_alerts\(&pool\)\.await;' <<< "$RUN" \
   && grep -qE 'catch_up_alerts\(pool, server_id\)\.await;' <<< "$SWEEP"; then
  ok "C11 alerts of removed targets are resolved each pass; alerts held by the window catch up without waiting a day"
else
  bad "C11 run must call resolve_orphan_alerts and sweep_server catch_up_alerts"
fi

ORPH=$(body "$SWEEPER" '^async fn resolve_orphan_alerts\(')
if grep -qE 'sqlx::query\(ACK_RESOLVE_SQL\)\.bind\(ALERT_TYPE\)\.bind\(&key\)' <<< "$RES" \
   && grep -qE 'ACK_ORPHAN_RESOLVE_SQL' <<< "$ORPH" \
   && grep -qE "state_key = \\\$2 AND status = 'acknowledged'" <<< "$(const_of "$SWEEPER" ACK_RESOLVE_SQL)"; then
  ok "C12 an acknowledged alert is closed too (resolve_alert only closes firing rows), scoped to its key"
else
  bad "C12 resolve_target_alert and resolve_orphan_alerts must also close acknowledged rows of the key"
fi

echo
echo "== §D  the API =="

if grep -qE '"/api/vulnerabilities/\{finding_id\}/accept", post\(vulnerabilities::accept_exception\)\.delete\(vulnerabilities::remove_exception\)' "$ROUTES_MOD"; then
  ok "D1-control the exception route binds POST and DELETE"
else
  bad "D1-control /api/vulnerabilities/{finding_id}/accept no longer routed to accept_exception / remove_exception"
fi

for h in accept_exception remove_exception; do
  HB=$(body "$ROUTES" "^pub async fn $h\\(")
  A=$(grep -nE 'require_admin\(&claims\.role\)\?;' <<< "$HB" | head -1 | cut -d: -f1)
  Q=$(grep -nE 'sqlx::query|state\.db\.begin' <<< "$HB" | head -1 | cut -d: -f1)
  if [ -n "$A" ] && [ -n "$Q" ] && [ "$A" -lt "$Q" ]; then
    ok "D2 $h requires an administrator (line $A) before touching the database (line $Q)"
  else
    bad "D2 $h must require_admin before any query - admin=${A:-none} query=${Q:-none}"
  fi
done

ACC=$(body "$ROUTES" '^pub async fn accept_exception\(')
V=$(grep -nE 'validate_exception\(&body, Utc::now\(\)\)' <<< "$ACC" | head -1 | cut -d: -f1)
U=$(grep -nE 'ACCEPT_SQL' <<< "$ACC" | head -1 | cut -d: -f1)
C=$(grep -nE 'tx\.commit\(\)' <<< "$ACC" | head -1 | cut -d: -f1)
R=$(grep -nE 'vuln_sweeper::resolve_target_alert_if_clear\(&state\.db, row\.target_id\)\.await;' <<< "$ACC" | head -1 | cut -d: -f1)
if [ -n "$V" ] && [ -n "$U" ] && [ -n "$C" ] && [ -n "$R" ] && [ "$V" -lt "$U" ] && [ "$C" -lt "$R" ] \
   && grep -qE 'ACCEPT_RENOTIFY_SQL' <<< "$ACC" && grep -qE 'StatusCode::CREATED' <<< "$ACC"; then
  ok "D3 accept: validated, upserted with re-notification on expiry, committed, then the alert re-evaluated; 201"
else
  bad "D3 accept order broken - validate=${V:-none} upsert=${U:-none} commit=${C:-none} resolve=${R:-none}"
fi

VAL=$(body "$ROUTES" '^pub fn validate_exception\(')
if grep -qE 'pub const EXCEPTION_MAX_DAYS: i64 = 90;' "$ROUTES" \
   && grep -qE 'if expires_at <= now \{' <<< "$VAL" \
   && grep -qE 'if expires_at > now \+ chrono::Duration::days\(EXCEPTION_MAX_DAYS\) \{' <<< "$VAL" \
   && grep -qE 'const EXCEPTION_REASON_MAX: usize = 500;' "$ROUTES"; then
  ok "D4 expires_at must fall in ]now, now + 90 days], the reason 1 to 500 characters"
else
  bad "D4 validate_exception bounds changed"
fi

if grep -qE 'ON CONFLICT \(target_id, vuln_id\) DO UPDATE SET reason = EXCLUDED\.reason, expires_at = EXCLUDED\.expires_at' <<< "$(const_of "$ROUTES" ACCEPT_SQL)"; then
  ok "D5 accepting again replaces the exception (upsert on target and CVE)"
else
  bad "D5 ACCEPT_SQL must upsert on (target_id, vuln_id)"
fi

NEXCL=$(grep -cE '\(\$10::bool OR NOT \{ACTIVE_EXCEPTION\}\)' "$ROUTES")
NSUMX=$(grep -cE '\(\$3::bool OR NOT \{ACTIVE_EXCEPTION\}\)' "$ROUTES")
if [ "$NEXCL" -ge 5 ] && [ "$NSUMX" -eq 2 ]; then
  ok "D6 every list query ($NEXCL) and both summary counts hide accepted CVEs unless include_accepted"
else
  bad "D6 accepted-CVE exclusion missing - list queries=$NEXCL (want >= 5), summary=$NSUMX (want 2)"
fi

SUMT=$(perl -0777 -ne 'print $1 if /(\{SUMMARY_TARGETS_SQL\}.*?GROUP BY t\.id)/s' "$ROUTES")
XL=$(grep -nE 'NOT \{ACTIVE_EXCEPTION\}' <<< "$SUMT" | head -1 | cut -d: -f1)
WL=$(grep -nE 'WHERE \{VISIBLE_TARGET\}' <<< "$SUMT" | head -1 | cut -d: -f1)
if [ -n "$XL" ] && [ -n "$WL" ] && [ "$XL" -le "$WL" ] \
   && grep -qE 'AND f\.resolved_at IS NULL ";$' <<< "$(const_of "$ROUTES" SUMMARY_TARGETS_SQL)"; then
  ok "D7 the summary excludes accepted CVEs in the LEFT JOIN, so a fully accepted target still shows (as clean)"
else
  bad "D7 the summary exclusion must sit in the join condition, before WHERE"
fi

PUT=$(body "$ROUTES" '^pub async fn put_settings\(')
if grep -qE 'AlertMin::parse\(s\)\.ok_or_else' <<< "$PUT" \
   && grep -qE 'Self::ALL\.into_iter\(\)\.find\(\|m\| m\.as_str\(\) == s\.trim\(\)\)' "$SWEEPER" \
   && grep -qE '"alert_min": alert_min\.as_str\(\)' <<< "$(body "$ROUTES" '^pub async fn get_settings\(')"; then
  ok "D8 alert_min is read back and only the two allow-listed values can be stored"
else
  bad "D8 alert_min must go through AlertMin::parse in PUT and be returned by GET"
fi

if grep -qE '"created_by_email": if admin \{ self\.acc_email\.clone\(\) \} else \{ None \},' "$ROUTES" \
   && grep -qE "const GROUP_BY: &\[&str\] = &\[\"vuln\"\];" "$ROUTES"; then
  ok "D9 who accepted a CVE is shown to administrators only; group_by is allow-listed"
else
  bad "D9 created_by_email masking or the group_by allow-list changed"
fi

echo
echo "== §E  vocabulary =="

BACK=$(sed -n '/^pub const SUPPRESSIBLE_ALERT_TYPES: &\[&str\] = &\[/,/^\];/p' "$NOTIF")
if [ "$(grep -cE '^\s*"[a-z_]+",' <<< "$BACK")" -ge 15 ] && grep -qE '^    "vuln_scan",$' <<< "$BACK"; then
  ok "E1 vuln_scan is a suppressible alert type (alert-controls A4 does not read the sweeper)"
else
  bad "E1 vuln_scan missing from SUPPRESSIBLE_ALERT_TYPES (or the list was not extracted)"
fi
if [ "$(printf 'vuln:%s' 00000000-0000-0000-0000-000000000000 | wc -c)" -le 100 ] \
   && grep -qE 'const ALERT_KEY_PREFIX: &str = "vuln:";' "$SWEEPER"; then
  ok "E2 the state key vuln:<uuid> fits alerts.state_key VARCHAR(100)"
else
  bad "E2 the alert state key prefix changed"
fi
if ! grep -qiE 'wordpress' "$SWEEPER" "$ROUTES" "$MIG"; then
  ok "E3 no WordPress target kind in batch 2 (batch 4 dropped)"
else
  bad "E3 a WordPress mention came back in the batch-2 files"
fi

echo
printf 'vuln-scanner-alerts: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
