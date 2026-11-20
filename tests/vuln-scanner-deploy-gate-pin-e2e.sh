#!/usr/bin/env bash
# vuln-scanner-deploy-gate-pin-e2e.sh - CVE scanner, batch 5 (deploy gate)
#
# What this pins (conception/13-scanner-cve-lots2-5-contrat.md, "Lot 5"):
#
#   §A  the agent's image scan marks KEV, on the match or on a related record,
#       and counts it over every match (before the 500-entry cap)
#   §B  the backend: a `kev` gate level that reads the KEV count only, the
#       default still `none`, `#[serde(default)]` for an older agent, the count
#       stored and read back by the soft gate of the other doors
#   §C  every Git path that BUILDS an image and then runs it scans the built
#       image after the build and before `/git/deploy`, and a refusal returns
#       before the running container is touched. The paths are DERIVED (any
#       function that posts to `/git/build`), not listed, so a new build path
#       joins the census by existing.
#   §D  a scanner that is missing or fails never refuses a deploy
#   §E  the migration
#
# Never put the row loop on the right-hand side of a pipe: the counters would
# die in the subshell and the suite would report a stale PASS.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  CVE scanner deploy gate - source pins (batch 5)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
has()   { grep -qF -- "$2" <<< "$1"; }
hasre() { grep -qE -- "$2" <<< "$1"; }

AIS=panel/agent/src/services/image_scanner.rs
SCANS=panel/backend/src/routes/image_scans.rs
GIT=panel/backend/src/routes/git_deploys.rs
MIG=panel/backend/migrations/20261202000100_image_scan_kev.sql

for f in "$AIS" "$SCANS" "$GIT"; do
  [ -f "$f" ] || { echo "  FATAL: $f missing - wrong tree?"; exit 1; }
done

# Body of a top-level fn, up to the next top-level item.
body() {
  perl -0777 -ne 'if (/^(?:pub(?:\(crate\))? )?(?:async )?fn \Q'"$2"'\E[<(].*?(?=^(?:pub(?:\(crate\))? )?(?:async )?fn |^#\[cfg\(test\)\]|\z)/ms) { print $& }' "$1"
}

# ── §A agent ────────────────────────────────────────────────────────────────
echo "── §A the agent's image scan reads KEV ──"
ARES=$(perl -0777 -ne 'print $& if /pub struct ImageScanResult \{.*?\n\}/s' "$AIS")
AVUL=$(perl -0777 -ne 'print $& if /pub struct Vuln \{.*?\n\}/s' "$AIS")
if has "$ARES" "pub kev_count: u32,"; then ok "A1 ImageScanResult carries kev_count"; else bad "A1 ImageScanResult carries kev_count"; fi
if has "$AVUL" "pub kev: bool,"; then ok "A2 Vuln carries kev"; else bad "A2 Vuln carries kev"; fi

AMATCH=$(perl -0777 -ne 'print $& if /struct GrypeMatch \{.*?\n\}/s' "$AIS")
if hasre "$AMATCH" '#\[serde\(default, rename = "relatedVulnerabilities"\)\]' \
   && hasre "$AMATCH" 'related: Option<Vec<GrypeKevCarrier>>'; then
  ok "A3 relatedVulnerabilities is read, optional and lenient (its own carrier struct)"
else
  bad "A3 relatedVulnerabilities must be read with serde(default) into a lenient carrier - a strict parse fails the scan, and a failed scan lets the deploy through"
fi
AVULN=$(perl -0777 -ne 'print $& if /struct GrypeVuln \{.*?\n\}/s' "$AIS")
ACARR=$(perl -0777 -ne 'print $& if /struct GrypeKevCarrier \{.*?\n\}/s' "$AIS")
if has "$AVULN" 'rename = "knownExploited"' && has "$ACARR" 'rename = "knownExploited"'; then
  ok "A4 knownExploited is read on the match and on each related record"
else
  bad "A4 knownExploited must be read on both the match and the related records (a GHSA carries KEV only on its related CVE)"
fi
AKEV=$(body "$AIS" match_is_kev)
if has "$AKEV" "m.vulnerability.known_exploited" && has "$AKEV" "m.related" && has "$AKEV" ".any("; then
  ok "A5 match_is_kev: own record OR any related record"
else
  bad "A5 match_is_kev no longer checks both the match and every related record"
fi
APARSE=$(body "$AIS" parse_grype_output)
NPARSE=$(printf '%s\n' "$APARSE" | grep -c . || true)
if [ "$NPARSE" -ge 30 ]; then ok "A6-control parse_grype_output extracted - $NPARSE lines"; else bad "A6-control parse_grype_output extracted - only $NPARSE lines (the extractor broke)"; fi
L_COUNT=$(grep -nF "kev_count += 1" <<< "$APARSE" | head -1 | cut -d: -f1)
L_CAP=$(grep -nF "vulnerabilities.len() < 500" <<< "$APARSE" | head -1 | cut -d: -f1)
if [ -n "$L_COUNT" ] && [ -n "$L_CAP" ] && [ "$L_COUNT" -lt "$L_CAP" ]; then
  ok "A6 kev_count is counted before the stored list is capped at 500"
else
  bad "A6 kev_count must be counted before the 500 cap (count line ${L_COUNT:-none}, cap line ${L_CAP:-none})"
fi
for t in reads_kev_on_the_match_and_on_related_vulnerabilities kev_count_is_taken_before_the_stored_list_is_capped; do
  if grep -qE "fn $t\(" "$AIS"; then ok "A7 agent unit test $t exists"; else bad "A7 agent unit test $t is gone"; fi
done

# ── §B backend ──────────────────────────────────────────────────────────────
echo
echo "── §B the backend gate level and its data ──"
VG=$(body "$SCANS" valid_gate)
if has "$VG" '"none" | "kev" | "critical" | "high" | "medium"'; then
  ok "B1 valid_gate accepts none|kev|critical|high|medium"
else
  bad "B1 valid_gate must accept exactly none|kev|critical|high|medium"
fi
if grep -qF '"Invalid deploy_gate (none|kev|critical|high|medium)"' "$SCANS"; then
  ok "B2 the PUT settings error names the kev level"
else
  bad "B2 the PUT settings error no longer lists the accepted levels"
fi
ET=$(body "$SCANS" exceeds_threshold)
if hasre "$ET" '"kev" => r\.kev_count > 0,'; then ok "B3 exceeds_threshold: kev refuses on kev_count > 0"; else bad "B3 exceeds_threshold has no kev arm reading kev_count"; fi
SEVLINES=$(grep -E '^\s*"(critical|high|medium)" =>' <<< "$ET" || true)
if grep -q kev <<< "$SEVLINES"; then
  bad "B4 a severity level reads KEV - the existing levels must not change"
else
  ok "B4 critical/high/medium keep reading severities only"
fi
RS=$(body "$SCANS" read_settings)
if has "$RS" 'let mut gate = "none".to_string();'; then ok "B5 the gate still defaults to none (decision 4)"; else bad "B5 the gate default moved off none"; fi
BRES=$(perl -0777 -ne 'print $& if /pub struct ImageScanResult \{.*?\n\}/s' "$SCANS")
BVUL=$(perl -0777 -ne 'print $& if /pub struct Vuln \{.*?\n\}/s' "$SCANS")
if hasre "$BRES" '#\[serde\(default\)\][[:space:]]*$' && perl -0777 -ne 'exit(/#\[serde\(default\)\]\s*\n\s*pub kev_count: u32,/ ? 0 : 1)' <<< "$BRES"; then
  ok "B6 ImageScanResult.kev_count is #[serde(default)] (older agent)"
else
  bad "B6 ImageScanResult.kev_count must be #[serde(default)] - an older agent's report would fail to parse"
fi
if perl -0777 -ne 'exit(/#\[serde\(default\)\]\s*\n\s*pub kev: bool,/ ? 0 : 1)' <<< "$BVUL"; then
  ok "B7 Vuln.kev is #[serde(default)]"
else
  bad "B7 Vuln.kev must be #[serde(default)]"
fi
STORE=$(body "$SCANS" scan_and_store)
if has "$STORE" "unknown_count, kev_count, vulnerabilities)" && has "$STORE" ".bind(result.kev_count as i32)"; then
  ok "B8 scan_and_store stores kev_count (bound parameter)"
else
  bad "B8 scan_and_store does not store kev_count"
fi
PGI=$(body "$SCANS" preflight_gate_image)
if has "$PGI" "unknown_count, kev_count" && has "$PGI" "kev_count: kev.max(0) as u32"; then
  ok "B9 the soft gate of the other doors reads kev_count back, so the kev level works there too"
else
  bad "B9 preflight_gate_image ignores kev_count - the kev level would never refuse a template, compose or stack deploy"
fi
for t in kev_gate_reads_the_kev_count_only result_from_an_older_agent_has_no_kev built_image_verdict; do
  if grep -qE "fn $t\(" "$SCANS"; then ok "B10 backend unit test $t exists"; else bad "B10 backend unit test $t is gone"; fi
done
if grep -qF 'assert!(valid_gate("kev"));' "$SCANS"; then ok "B11 validates_gate covers kev"; else bad "B11 validates_gate does not cover kev"; fi

# ── §C every Git build path gates before it runs ────────────────────────────
echo
echo "── §C the built image is judged after the build and before /git/deploy ──"
CENSUS=$(python3 - "$GIT" <<'PYEOF'
import re, sys
src = open(sys.argv[1]).read()
src = re.sub(r"^\s*//.*$", "", src, flags=re.M)        # prose is not code
starts = [(m.start(), m.group(1)) for m in re.finditer(r"^(?:pub(?:\(crate\))? )?(?:async )?fn (\w+)", src, re.M)]
starts.append((len(src), None))
for (a, name), (b, _) in zip(starts, starts[1:]):
    body = src[a:b]
    builds = [m.end() for m in re.finditer(r'post_long\("/git/(?:build|nixpacks-build)"', body)]
    if not builds:
        continue
    deploys = [m.start() for m in re.finditer(r'post_long\("/git/deploy"', body)]
    gates = [m.start() for m in re.finditer(r"built_image_refusal\(", body)]
    last_build = max(builds)
    first_deploy = min(deploys) if deploys else -1
    ordered = any(last_build < g < first_deploy for g in gates) if first_deploy >= 0 else False
    # The refusal branch: from the gate call to its `return;`, no /git/deploy.
    branch_ok = False
    for g in gates:
        r = body.find("return;", g)
        if r != -1 and "/git/deploy" not in body[g:r] and "status = 'failed'" in body[g:r]:
            branch_ok = True
    print(f"{name}|{len(builds)}|{len(deploys)}|{len(gates)}|{int(ordered)}|{int(branch_ok)}")
PYEOF
)
PATHS_N=0
while IFS='|' read -r fn nb nd ng ord br; do
  [ -z "$fn" ] && continue
  PATHS_N=$((PATHS_N+1))
  if [ "$nd" -ge 1 ] && [ "$ng" -eq 1 ] && [ "$ord" -eq 1 ]; then
    ok "C1 $fn: gate called once, after the build and before /git/deploy"
  else
    bad "C1 $fn builds an image ($nb build call(s)) and runs it ($nd deploy call(s)) but the gate is called $ng time(s), ordered=$ord - a built image would replace the container unjudged"
  fi
  if [ "$br" -eq 1 ]; then
    ok "C2 $fn: a refusal marks the deploy failed and returns before /git/deploy"
  else
    bad "C2 $fn: the refusal branch does not mark failure and return before /git/deploy - the previous container is not protected"
  fi
done <<< "$CENSUS"
# Floor: spawn_deploy_task, trigger_deploy_task, handle_preview_deploy.
if [ "$PATHS_N" -eq 3 ]; then
  ok "C3 exactly 3 Git build paths found (manual/webhook/approval, scheduled, preview)"
else
  bad "C3 expected 3 Git build paths, found $PATHS_N - a path was added or the census broke; update deliberately"
fi
SDT=$(body "$GIT" spawn_deploy_task)
if has "$SDT" 'emit("scan", label, status, msg)'; then
  ok "C4 the interactive path shows the scan as its own step in the live deploy log"
else
  bad "C4 spawn_deploy_task no longer reports the scan step in the deploy log"
fi
for fn in spawn_deploy_task trigger_deploy_task; do
  B=$(body "$GIT" "$fn")
  SEG=$(perl -0777 -ne 'print $1 if /built_image_refusal\((.*?)return;/s' <<< "$B")
  if has "$SEG" "record_failed_history(" && has "$SEG" 'notify_panel(' && has "$SEG" '"failure"'; then
    ok "C5 $fn: a refusal is recorded in history, notified and reported to GitHub"
  else
    bad "C5 $fn: a refusal must be recorded in history, notified (notify_panel) and set the GitHub status to failure - an unattended deploy has no one watching the log"
  fi
done
RB=$(body "$GIT" rollback)
if [ -n "$RB" ] && ! has "$RB" "built_image_refusal("; then
  ok "C6 rollback is not gated (it restores an image that ran before)"
else
  bad "C6 rollback calls the build gate, or could not be extracted - gating the remedy would block it"
fi
DOC=$(perl -0777 -ne 'print $& if /\/\/\/ The CVE deploy gate for an image a Git deploy has just built\..*?async fn built_image_refusal/s' "$GIT")
if has "$DOC" "Rollbacks are not gated" && has "$DOC" "before \`/git/deploy\`"; then
  ok "C7 the helper documents where it runs and why rollbacks are exempt"
else
  bad "C7 built_image_refusal lost its documentation of the insertion point or the rollback exemption"
fi

# ── §D a scanner failure never blocks ───────────────────────────────────────
echo
echo "── §D a missing or failing scanner never refuses a deploy ──"
GBI=$(body "$SCANS" gate_built_image)
ERRARM=$(perl -0777 -ne 'print $1 if /Err\(e\) => \{(.*?)\n        \}/s' <<< "$GBI")
if has "$GBI" "scan_and_store(pool, server_id, agent, image)" && has "$ERRARM" "BuiltImageGate::Skipped(" && ! has "$ERRARM" "Refused"; then
  ok "D1 gate_built_image scans now and maps a scan error to Skipped, never Refused"
else
  bad "D1 gate_built_image must scan the built image and turn a scan error into Skipped - a scanner outage would block deploys"
fi
if has "$ERRARM" "tracing::warn!"; then ok "D2 a skipped scan is logged"; else bad "D2 a skipped scan is not logged"; fi
AG=$(body "$SCANS" armed_gate)
if hasre "$AG" 'Err\(e\) => \{' && has "$AG" "None" && has "$AG" 'gate != "none"'; then
  ok "D3 armed_gate: off by default, and a settings read error counts as off"
else
  bad "D3 armed_gate must return None for gate none and for a settings read error"
fi
BIR=$(body "$GIT" built_image_refusal)
SKIP=$(perl -0777 -ne 'print $1 if /BuiltImageGate::Skipped\(why\) => \{(.*?)\}/s' <<< "$BIR")
if hasre "$SKIP" '^[[:space:]]*None[[:space:]]*$' && ! hasre "$SKIP" '^[[:space:]]*Some\(why\)[[:space:]]*$'; then
  ok "D4 built_image_refusal lets a Skipped scan through"
else
  bad "D4 built_image_refusal refuses on a Skipped scan"
fi
if has "$BIR" "armed_gate(db).await?"; then
  ok "D5 with the gate off (the default) no scan runs and no agent call is made"
else
  bad "D5 built_image_refusal must ask armed_gate first, so a gate set to none costs nothing"
fi

# ── §E migration ────────────────────────────────────────────────────────────
echo
echo "── §E the migration ──"
if [ -f "$MIG" ] && grep -qE 'ALTER TABLE image_scan_findings' "$MIG" \
   && grep -qE 'ADD COLUMN IF NOT EXISTS kev_count INT NOT NULL DEFAULT 0;' "$MIG"; then
  ok "E1 image_scan_findings.kev_count INT NOT NULL DEFAULT 0, idempotent"
else
  bad "E1 the kev_count migration is missing or changed shape"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
