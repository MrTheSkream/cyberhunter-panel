#!/usr/bin/env bash
# vuln-scanner-ui-pin-e2e.sh - CVE scanner, batch 3: the interface
#
# Conception 13 (conception/13-scanner-cve-lots2-5-contrat.md, "Lot 3"). The
# backend of batches 1 and 2 finds CVEs on sites, Docker images and systems,
# accepts exceptions and raises `vuln_scan` alerts. This suite pins the SPA half:
#
#   §A  the page is reachable: route, menu row open to every role (the API
#       filters by owner), command palette, breadcrumb
#   §B  the page calls the API it was written against, with Group by CVE on by
#       default and boolean filters sent only when ticked (`kev=false` would
#       mean "not exploited", not "any")
#   §C  Accept and Remove exception are admin only, and the expiry picker cannot
#       offer a date the API refuses (90 days at most, 30 by default)
#   §D  the badge: one summary request per page, shared by every row, linking to
#       `/vulnerabilities?target_id=`, silent when the API refuses; present on
#       SiteDetail, Apps (beside the historical image badge) and GitDeploys
#   §E  the `vuln_scan` alert type in both frontend vocabularies, the scanner
#       settings card, and the `kev` level of the deploy gate (batch 5)
#   §F  the data attribution, and no em dash in any file this batch touched
#
# Pure source analysis: no box, no network, no build. Every arm emits exactly
# one ok or bad, so the published total is stable.
#
# NO PIPES INTO `grep -q` - under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm uses a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

FE=panel/frontend/src
PAGE=$FE/pages/Vulnerabilities.tsx
BADGE=$FE/components/VulnBadge.tsx
MAIN=$FE/main.tsx
NAV=$FE/data/navItems.ts
PALETTE=$FE/components/CommandPalette.tsx
ATLAS=$FE/components/AtlasLayout.tsx
SETTINGS=$FE/pages/Settings.tsx
ALERTS=$FE/pages/Alerts.tsx
SITE=$FE/pages/SiteDetail.tsx
APPS=$FE/pages/Apps.tsx
GIT=$FE/pages/GitDeploys.tsx
FILES=("$PAGE" "$BADGE" "$MAIN" "$NAV" "$PALETTE" "$ATLAS" "$SETTINGS" "$ALERTS" "$SITE" "$APPS" "$GIT")

missing=""
for f in "${FILES[@]}"; do [ -f "$f" ] || missing="$missing $f"; done
if [ -z "$missing" ]; then
  ok "control: every subject file exists (${#FILES[@]})"
else
  bad "control: missing subject files:$missing"
fi

P=$(cat "$PAGE" 2>/dev/null)
B=$(cat "$BADGE" 2>/dev/null)
# Call chains are split across lines (`api` / `.get(...)`): flattened copies.
PF=$(tr -s ' \n' ' ' <<< "$P")
BF=$(tr -s ' \n' ' ' <<< "$B")
NP=$(grep -c . <<< "$P")
if [ "$NP" -ge 300 ]; then
  ok "control: Vulnerabilities.tsx read - $NP lines"
else
  bad "control: Vulnerabilities.tsx read - only $NP lines (the reader broke or the page shrank)"
fi

echo "== §A  route, menu, palette, breadcrumb =="

M=$(cat "$MAIN" 2>/dev/null)
if grep -qE 'const Vulnerabilities = lazyRetry\(\(\) => import\("\./pages/Vulnerabilities"\)\)' <<< "$M"; then
  ok "A1 main.tsx lazy-loads pages/Vulnerabilities"
else
  bad "A1 main.tsx lazy-loads pages/Vulnerabilities"
fi
if grep -qE '<Route path="/vulnerabilities" element=\{<Vulnerabilities />\} />' <<< "$M"; then
  ok "A2 /vulnerabilities is routed"
else
  bad "A2 /vulnerabilities is routed"
fi

N=$(cat "$NAV" 2>/dev/null)
HOSTING=$(awk '/key: "hosting"/{i=1} i{print} i && /^  },/{exit}' <<< "$N")
ROW=$(grep -E 'to: "/vulnerabilities"' <<< "$HOSTING")
if grep -qE 'label: "Vulnerabilities"' <<< "$ROW"; then
  ok "A3 the hosting group has a Vulnerabilities row"
else
  bad "A3 the hosting group has a Vulnerabilities row - got: ${ROW:-none}"
fi
if [ -n "$ROW" ] && ! grep -qE 'adminOnly|resellerVisible|resellerOnly|requiresUserTerminal' <<< "$ROW"; then
  ok "A4 the row is open to every role (the API filters by owner)"
else
  bad "A4 the row is open to every role - got: ${ROW:-none}"
fi
if grep -qE 'to: "/settings".*adminOnly: true' <<< "$N"; then
  ok "A5-control /settings is still adminOnly, so A4 distinguishes something"
else
  bad "A5-control /settings is no longer adminOnly - A4 proves nothing"
fi
if grep -qE '\{ id: "vulnerabilities", label: "Vulnerabilities",.*path: "/vulnerabilities", category: "Hosting"' "$PALETTE"; then
  ok "A6 the command palette offers /vulnerabilities under Hosting"
else
  bad "A6 the command palette offers /vulnerabilities under Hosting"
fi
if grep -qE '^ *vulnerabilities: "Vulnerabilities",' "$ATLAS"; then
  ok "A7 the breadcrumb names the page"
else
  bad "A7 the breadcrumb names the page"
fi
if grep -qE 'className="page-header-title">Vulnerabilities<' <<< "$P"; then
  ok "A8 the page title is Vulnerabilities"
else
  bad "A8 the page title is Vulnerabilities"
fi

echo
echo "== §B  API calls and default grouping =="

if grep -qE 'api ?\.get<VulnList>\(`/vulnerabilities\?\$\{query\}`\)' <<< "$PF"; then
  ok "B1 the list is GET /vulnerabilities?<filters>"
else
  bad "B1 the list is GET /vulnerabilities?<filters>"
fi
NSUM=$(grep -rhoE '"/vulnerabilities/summary"' "$FE" | wc -l)
if [ "$NSUM" -eq 1 ] && grep -qE 'api ?\.get<VulnSummary>\("/vulnerabilities/summary"\)' <<< "$BF"; then
  ok "B2 /vulnerabilities/summary is requested in one place only (useVulnSummary)"
else
  bad "B2 /vulnerabilities/summary must be requested only by useVulnSummary - found $NSUM call sites"
fi
if grep -qE 'api\.post\(`/vulnerabilities/targets/\$\{id\}/scan`, \{\}\)' <<< "$P" && grep -qE '"Scan queued"' <<< "$P"; then
  ok "B3 Scan now is POST /vulnerabilities/targets/{id}/scan, answered Scan queued"
else
  bad "B3 Scan now is POST /vulnerabilities/targets/{id}/scan, answered Scan queued"
fi
if grep -qE 'api\.post\(`/vulnerabilities/\$\{item\.id\}/accept`, \{ reason: trimmed, expires_at: expires \}\)' <<< "$P"; then
  ok "B4 Accept is POST /vulnerabilities/{finding_id}/accept {reason, expires_at}"
else
  bad "B4 Accept is POST /vulnerabilities/{finding_id}/accept {reason, expires_at}"
fi
if grep -qE 'api\.delete\(`/vulnerabilities/\$\{item\.id\}/accept`\)' <<< "$P"; then
  ok "B5 Remove exception is DELETE /vulnerabilities/{finding_id}/accept"
else
  bad "B5 Remove exception is DELETE /vulnerabilities/{finding_id}/accept"
fi
if grep -qE 'const groupByCve = params\.get\("group"\) !== "none";' <<< "$P" \
   && grep -qE 'if \(groupByCve\) q\.set\("group_by", "vuln"\);' <<< "$P"; then
  ok "B6 group_by=vuln is sent unless the URL says group=none (on by default)"
else
  bad "B6 group_by=vuln must be the default"
fi
if grep -qE '^const PAGE_SIZE = 100;' <<< "$P" && grep -qE 'q\.set\("limit", String\(PAGE_SIZE\)\)' <<< "$P"; then
  ok "B7 pages of 100"
else
  bad "B7 pages of 100"
fi
NBOOL=0
for k in kev fixable include_accepted include_resolved; do
  grep -qE "q\.set\(\"$k\", \"true\"\);" <<< "$P" && NBOOL=$((NBOOL+1))
done
if [ "$NBOOL" -eq 4 ] && ! grep -qE 'q\.set\("(kev|fixable|include_accepted|include_resolved)", "false"' <<< "$P"; then
  ok "B8 the four boolean filters are sent only as true"
else
  bad "B8 the four boolean filters are sent only as true - $NBOOL/4 found"
fi
NURL=0
for k in severity kev kind server_id target_id fixable include_accepted include_resolved group page; do
  grep -qE "params\.get\(\"$k\"\)" <<< "$P" && NURL=$((NURL+1))
done
if [ "$NURL" -eq 10 ]; then
  ok "B9 every filter lives in the URL (target_id included, for the badges)"
else
  bad "B9 every filter lives in the URL - $NURL/10 read from search params"
fi

echo
echo "== §C  Accept is admin only, 90 days at most =="

if grep -qE 'const isAdmin = user\?\.role === "admin";' <<< "$P"; then
  ok "C1 isAdmin is the admin role"
else
  bad "C1 isAdmin is the admin role"
fi
GATE=$(grep -n '{isAdmin && !item.resolved_at && (' <<< "$P" | head -1 | cut -d: -f1)
ACC=$(grep -n 'onClick={() => setAcceptFor(item)}' <<< "$P" | head -1 | cut -d: -f1)
REM=$(grep -n 'onClick={() => setRemoveFor(item)}' <<< "$P" | head -1 | cut -d: -f1)
if [ -n "$GATE" ] && [ -n "$ACC" ] && [ -n "$REM" ] \
   && [ "$ACC" -gt "$GATE" ] && [ "$ACC" -lt $((GATE+10)) ] \
   && [ "$REM" -gt "$GATE" ] && [ "$REM" -lt $((GATE+10)) ] \
   && [ "$(grep -c 'setAcceptFor(item)' <<< "$P")" -eq 1 ] && [ "$(grep -c 'setRemoveFor(item)' <<< "$P")" -eq 1 ]; then
  ok "C2 the only Accept and Remove exception buttons sit under the isAdmin gate (line $GATE)"
else
  bad "C2 Accept/Remove must be under isAdmin - gate=${GATE:-none} accept=${ACC:-none} remove=${REM:-none}"
fi
if grep -qE '^const MAX_ACCEPT_DAYS = 90;' <<< "$P" && grep -qE '^const DEFAULT_ACCEPT_DAYS = 30;' <<< "$P"; then
  ok "C3 90 days at most, 30 by default"
else
  bad "C3 90 days at most, 30 by default"
fi
if grep -qE 'const maxDay = dateInputValue\(addDays\(MAX_ACCEPT_DAYS\)\);' <<< "$P" && grep -qE 'max=\{maxDay\}' <<< "$P" \
   && grep -qE 'useState\(\(\) => dateInputValue\(addDays\(DEFAULT_ACCEPT_DAYS\)\)\)' <<< "$P"; then
  ok "C4 the date picker is bounded by the ceiling and starts at the default"
else
  bad "C4 the date picker is bounded by the ceiling and starts at the default"
fi
if grep -qE 'Math\.min\(ts, now \+ MAX_ACCEPT_DAYS \* DAY_MS' <<< "$P" && grep -qE 'ts <= now\) return null' <<< "$P"; then
  ok "C5 the expiry sent is capped inside ]now, now + 90 days]"
else
  bad "C5 the expiry sent is capped inside ]now, now + 90 days]"
fi
if grep -qE 'maxLength=\{500\}' <<< "$P" && grep -qE 'const valid = trimmed\.length > 0 && trimmed\.length <= 500 && dayInRange;' <<< "$P"; then
  ok "C6 a reason is mandatory (1 to 500 characters)"
else
  bad "C6 a reason is mandatory (1 to 500 characters)"
fi

echo
echo "== §D  the badge =="

if grep -qE 'to=\{`/vulnerabilities\?target_id=\$\{encodeURIComponent\(target\.id\)\}`\}' <<< "$B"; then
  ok "D1 the badge links to /vulnerabilities?target_id=<id>"
else
  bad "D1 the badge links to /vulnerabilities?target_id=<id>"
fi
if grep -qE 'if \(!state\.loaded \|\| state\.failed\) return null;' <<< "$B" \
   && grep -qE '\.catch\(\(\) => \{' <<< "$B"; then
  ok "D2 a refused or failed summary hides the badge instead of breaking the page"
else
  bad "D2 a refused or failed summary hides the badge instead of breaking the page"
fi
NLAB=0
for l in 'exploited`' '"Not scanned"' '"Clean"' 'C / \$\{t\.high\}H`'; do
  grep -qE "$l" <<< "$B" && NLAB=$((NLAB+1))
done
if [ "$NLAB" -eq 4 ]; then
  ok "D3 the badge says N exploited, NC / NH, Clean or Not scanned"
else
  bad "D3 the badge texts - $NLAB/4 found"
fi
if grep -qE 'onClick=\{\(e\) => e\.stopPropagation\(\)\}' <<< "$B"; then
  ok "D4 the badge link does not trigger the clickable row under it"
else
  bad "D4 the badge link does not trigger the clickable row under it"
fi
for pair in "SiteDetail:$SITE" "Apps:$APPS" "GitDeploys:$GIT"; do
  name=${pair%%:*}; f=${pair#*:}
  C=$(cat "$f" 2>/dev/null)
  if grep -qE '^import VulnBadge, \{ useVulnSummary \} from "\.\./components/VulnBadge";' <<< "$C" \
     && [ "$(grep -c 'useVulnSummary(' <<< "$C")" -eq 1 ] && grep -qE '<VulnBadge$' <<< "$C"; then
    ok "D5 $name renders the badge from one useVulnSummary() per page"
  else
    bad "D5 $name renders the badge from one useVulnSummary() per page"
  fi
done
if grep -qE 't\.kind === "site" && t\.site_id === site\.id' "$SITE"; then
  ok "D6 SiteDetail matches its site target by site_id"
else
  bad "D6 SiteDetail matches its site target by site_id"
fi
if grep -qE 't\.kind === "image" && t\.ref === app\.image && \(!activeServer \|\| t\.server_id === activeServer\.id\)' "$APPS"; then
  ok "D7 Apps matches the image target by ref on the active server"
else
  bad "D7 Apps matches the image target by ref on the active server"
fi
if grep -qE 't\.kind === "image" && t\.git_deploy_id === d\.id' "$GIT"; then
  ok "D8 GitDeploys matches the image target by git_deploy_id"
else
  bad "D8 GitDeploys matches the image target by git_deploy_id"
fi
if grep -qE 'openScanDrawer\(app\.image!\)' "$APPS"; then
  ok "D9-control the historical image scan badge of Apps is still there"
else
  bad "D9-control the historical image scan badge of Apps disappeared"
fi
SCLASS=$(awk '/const scanSeverityClass = /{i=1} i{print} i && /^  };/{exit}' "$APPS")
NCLS=0
for c in 'bg-danger-500/15 text-danger-400' 'bg-warn-500/15 text-warn-400' 'bg-warn-500/10 text-warn-500' 'bg-accent-500/10 text-accent-400' 'bg-rust-500/15 text-rust-400' 'bg-dark-700 text-dark-300'; do
  grep -qF "$c" <<< "$SCLASS" && grep -qF "$c" <<< "$B" && NCLS=$((NCLS+1))
done
if [ "$NCLS" -eq 6 ]; then
  ok "D10 the badge uses the six colours of scanSeverityClass"
else
  bad "D10 the badge uses the six colours of scanSeverityClass - $NCLS/6 shared"
fi

echo
echo "== §E  alert type, settings, deploy gate =="

FRONT=$(sed -n '/^const SUPPRESSIBLE_ALERT_TYPES: { key: string; label: string }\[\] = \[/,/^\];/p' "$SETTINGS")
if grep -qE '\{ key: "vuln_scan", label: "Vulnerability scan" \},' <<< "$FRONT"; then
  ok "E1 Settings can mute vuln_scan (Vulnerability scan)"
else
  bad "E1 Settings can mute vuln_scan (Vulnerability scan)"
fi
LABELS=$(sed -n '/^const TYPE_LABELS: Record<string, string> = {/,/^};/p' "$ALERTS")
if grep -qE '^ *vuln_scan: "Vulnerability scan",' <<< "$LABELS"; then
  ok "E2 Alerts labels vuln_scan (Vulnerability scan)"
else
  bad "E2 Alerts labels vuln_scan (Vulnerability scan)"
fi
GATESEL=$(awk '/value=\{s\.deploy_gate\}/{i=1} i{print} i && /<\/select>/{exit}' "$SETTINGS")
ORDER=$(grep -oE '<option value="[a-z]+"' <<< "$GATESEL" | sed -E 's/.*"([a-z]+)"/\1/' | tr '\n' ' ')
if [ "$ORDER" = "none kev critical high medium " ] && grep -qE '<option value="kev">Actively exploited \(KEV\)</option>' <<< "$GATESEL"; then
  ok "E3 the deploy gate offers none, kev (Actively exploited), critical, high, medium"
else
  bad "E3 the deploy gate levels - got: ${ORDER:-none}"
fi
CARD=$(awk '/^function VulnScannerSettings\(/{i=1} i{print} i && /^}$/{exit}' "$SETTINGS")
if grep -qE 'api\.get<Partial<VulnScannerSettingsState>>\("/vulnerabilities/settings"\)' <<< "$CARD" \
   && grep -qE 'api\.put\("/vulnerabilities/settings", \{' <<< "$CARD" \
   && grep -qE 'alert_min: next\.alert_min,' <<< "$CARD" && grep -qE 'match_hour: next\.match_hour,' <<< "$CARD"; then
  ok "E4 the Vulnerability scanner card reads and writes the whole settings body"
else
  bad "E4 the Vulnerability scanner card reads and writes the whole settings body"
fi
if grep -qE '\{ value: "kev_and_fixable_high", label: "Actively exploited, or critical/high with a fix" \}' "$SETTINGS" \
   && grep -qE '\{ value: "critical_any", label: "Also every critical" \}' "$SETTINGS" \
   && grep -qE 'Daily match hour \(UTC\)' <<< "$CARD" && grep -qE '<VulnScannerSettings setMessage=\{setMessage\} />' "$SETTINGS"; then
  ok "E5 the card is rendered with Enabled, Daily match hour (UTC) and both alert thresholds"
else
  bad "E5 the card is rendered with Enabled, Daily match hour (UTC) and both alert thresholds"
fi

echo
echo "== §F  attribution and typography =="

if grep -qF 'Vulnerability data: Anchore grype database (NVD, GitHub Security Advisories, distribution advisories), CISA KEV, FIRST EPSS.' <<< "$P"; then
  ok "F1 the data sources are credited under the table"
else
  bad "F1 the data sources are credited under the table"
fi
EMDASH=$'\xe2\x80\x94'
DASHED=""
for f in "${FILES[@]}" "$0"; do
  [ -f "$f" ] && grep -qF "$EMDASH" "$f" && DASHED="$DASHED $f"
done
if [ -z "$DASHED" ]; then
  ok "F2 no em dash in the $(( ${#FILES[@]} + 1 )) files of this batch"
else
  bad "F2 em dash found in:$DASHED"
fi
if grep -qE '<th scope="col"' <<< "$P" && grep -qE 'aria-expanded=\{open\}' <<< "$P" && grep -qE '<caption className="sr-only">' <<< "$P"; then
  ok "F3 the table has header cells, a caption and labelled expanders"
else
  bad "F3 the table has header cells, a caption and labelled expanders"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
