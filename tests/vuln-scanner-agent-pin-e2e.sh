#!/usr/bin/env bash
# vuln-scanner-agent-pin-e2e.sh - CVE scanner, lot 1, agent side
# (conception/13-scanner-cve-lot1-contrat.md, sections "Agent").
#
#   §A  Every syft/grype/find run of services/vuln_scanner.rs goes through a
#       transient systemd unit capped at MemoryMax=1536M, Nice=19,
#       IOSchedulingClass=idle, CPUQuota=50%: the agent itself runs under
#       MemoryMax=512M, and grype loading its database or syft walking a big
#       node_modules inside the agent's cgroup would get the agent killed.
#       The install reuses image_scanner::install_grype_binary, which does
#       NOT prime `grype db update` inside the agent's cgroup (the legacy
#       install_grype still does, for the historical image-scan route only).
#   §B  Matching runs with GRYPE_DB_AUTO_UPDATE=false (only `grype db update`
#       may download the ~200 MB database), and every report is written to a
#       file by the scanner (-o syft-json=<path>, -o json=<path>, -fprint0),
#       never read back from stdout.
#   §C  Jobs: one of each kind at a time (key "server"), inventory serialized
#       by its own lock, match and db update by another, install by both.
#   §D  grype v0.122.1 / syft v1.57.2 pinned, constants still private `const`
#       (scanner-supply-chain-and-credential-perms-pin-e2e.sh anchors on it);
#       install removes a binary of the wrong version before reinstalling.
#   §E  Reading grype: KEV / EPSS are taken from relatedVulnerabilities too (a
#       GHSA carries them only on its related CVE), dedup on
#       (vuln_id, package, version), cap 5000.
#   §F  Side fix: security_scanner.rs's container_vuln check runs the managed
#       grype (image_scanner::GRYPE_BIN) with its database cache, not a
#       `grype` on PATH that never exists.
#   §G  Wiring: safe_cmd's property() lands before `--`; routes registered
#       under the auth middleware.
#
# Pure source analysis: no box, no network, no build.
#
# NO PIPES INTO `grep -q` - under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code. Every arm greps a
# here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

VS=panel/agent/src/services/vuln_scanner.rs
VR=panel/agent/src/routes/vulns.rs
IS=panel/agent/src/services/image_scanner.rs
SB=panel/agent/src/services/sbom_scanner.rs
SS=panel/agent/src/services/security_scanner.rs
SAFE=panel/agent/src/safe_cmd.rs
MAIN=panel/agent/src/main.rs
RMOD=panel/agent/src/routes/mod.rs
SMOD=panel/agent/src/services/mod.rs

for f in "$VS" "$VR" "$IS" "$SB" "$SS" "$SAFE" "$MAIN" "$RMOD" "$SMOD"; do
  [ -f "$f" ] || { echo "MISSING SUBJECT FILE: $f"; exit 1; }
done

# Production code only: stops at a `#[cfg(test)]` line directly followed by
# `mod ` (the real test module), then drops comment lines. Reads text on stdin.
strip() {
  awk '
    held == 1 { if ($0 ~ /^mod /) { exit } print heldline; held = 0 }
    /^#\[cfg[(]test\)\]$/ { held = 1; heldline = $0; next }
    { print }
  ' | grep -vE '^[[:space:]]*(///|//!|//|\*|/\*)'
}
# One top-level fn (signature anchored by the caller's regex) out of a text.
fnof() { awk -v re="$2" '$0 ~ re {i=1} i {print} i && /^}$/ {exit}' <<< "$1"; }
has()  { grep -qF -- "$2" <<< "$1"; }
hasre(){ grep -qE -- "$2" <<< "$1"; }
cnt()  { grep -cF -- "$2" <<< "$1" || true; }

VSC=$(strip < "$VS")
VRC=$(strip < "$VR")
ISC=$(strip < "$IS")
SBC=$(strip < "$SB")
SSC=$(strip < "$SS")
SAFEC=$(strip < "$SAFE")

echo "== controls: the extractors see real code =="
N=$(grep -c . <<< "$VSC")
if [ "$N" -ge 500 ]; then ok "C1 vuln_scanner.rs production code extracted - $N lines"
else bad "C1 vuln_scanner.rs production code extracted - only $N lines (extractor broke)"; fi
if has "$VSC" "mod tests"; then bad "C2 strip() leaked the test module into production code"
else ok "C2 strip() stops at the test module"; fi
SCMD=$(fnof "$VSC" '^fn scanner_command[(]')
SENV=$(fnof "$VSC" '^pub fn scanner_env[(]')
MONE=$(fnof "$VSC" '^async fn match_one[(]')
IONE=$(fnof "$VSC" '^async fn inventory_one[(]')
FOF=$(fnof "$VSC" '^fn finding_of[(]')
for pair in "SCMD:scanner_command:4" "SENV:scanner_env:8" "MONE:match_one:20" "IONE:inventory_one:40" "FOF:finding_of:40"; do
  v="${pair%%:*}"; rest="${pair#*:}"; name="${rest%%:*}"; min="${rest##*:}"
  n=$(grep -c . <<< "${!v}")
  if [ "$n" -ge "$min" ]; then ok "C3 $name body extracted - $n lines"
  else bad "C3 $name body extracted - only $n lines (extractor or signature changed)"; fi
done

echo "== §A  scanners run in a capped, deprioritized transient unit =="

# The arm as a function so the planted control below tests the arm itself.
arm_properties() {
  local src="$1" p miss=""
  for p in 'MemoryMax=1536M' 'Nice=19' 'IOSchedulingClass=idle' 'CPUQuota=50%'; do
    has "$(grep -E 'SCANNER_PROPERTIES' -A2 <<< "$src")" "\"$p\"" || miss="$miss $p"
  done
  printf '%s' "$miss"
}
MISS=$(arm_properties "$VSC")
if [ -z "$MISS" ]; then ok "A1 SCANNER_PROPERTIES holds MemoryMax=1536M, Nice=19, IOSchedulingClass=idle, CPUQuota=50%"
else bad "A1 SCANNER_PROPERTIES is missing:$MISS"; fi
PLANT=$(printf 'pub const SCANNER_PROPERTIES: [&str; 3] =\n    ["MemoryMax=1536M", "IOSchedulingClass=idle", "CPUQuota=50%%"];\n')
if [ -n "$(arm_properties "$PLANT")" ]; then ok "A1-control the arm fires on a planted list without Nice=19"
else bad "A1-control the arm stays green on a planted list without Nice=19"; fi

if has "$SCMD" "safe_command_unsandboxed(binary, &scanner_env(auto_update))" \
   && has "$SCMD" "for p in SCANNER_PROPERTIES" && has "$SCMD" "cmd.property(p)"; then
  ok "A2 scanner_command builds the unsandboxed unit and applies every property"
else
  bad "A2 scanner_command no longer applies SCANNER_PROPERTIES to an unsandboxed unit"
fi

# Negative: no sandboxed spawn at all in the module (a bare safe_command or a
# tokio Command would run syft/grype inside the agent's 512M cgroup).
arm_sandboxed() { grep -nE '(^|[^_a-z])safe_command[(]|Command::new[(]' <<< "$1" || true; }
HITS=$(arm_sandboxed "$VSC")
if [ -z "$HITS" ]; then ok "A3 vuln_scanner.rs spawns nothing outside the transient unit"
else bad "A3 vuln_scanner.rs spawns a process in the agent's own cgroup: $HITS"; fi
if [ -n "$(arm_sandboxed 'let o = safe_command(GRYPE_BIN).args(["x"]);')" ]; then
  ok "A3-control the arm fires on a planted safe_command(GRYPE_BIN)"
else bad "A3-control the arm misses a planted safe_command(GRYPE_BIN)"; fi

N_SC=$(cnt "$VSC" "scanner_command(")
if [ "$N_SC" -ge 6 ]; then ok "A4 scanner_command used by every run ($N_SC call sites incl. definition)"
else bad "A4 only $N_SC scanner_command sites - a run bypasses it"; fi
if has "$VSC" ".output().await"; then bad "A5 a scanner run has no timeout (.output().await)"
else ok "A5 no bare .output().await: every run goes through output_with_timeout"; fi
for pair in "SYFT_TIMEOUT:1800" "MATCH_TIMEOUT:600" "DB_UPDATE_TIMEOUT:900"; do
  c="${pair%%:*}"; s="${pair##*:}"
  if hasre "$VSC" "^const $c: Duration = Duration::from_secs[(]$s\);"; then ok "A6 $c is ${s}s"
  else bad "A6 $c is no longer ${s}s"; fi
done
for e in 'HOME", HOME_DIR' 'TMPDIR", TMP_DIR' 'XDG_CACHE_HOME", CACHE_DIR' 'GRYPE_DB_CACHE_DIR", image_scanner::GRYPE_DB_CACHE' 'GRYPE_CHECK_FOR_APP_UPDATE", "false"' 'SYFT_CHECK_FOR_APP_UPDATE", "false"'; do
  if has "$SENV" "(\"$e)"; then ok "A7 scanner env sets ${e%%\"*}"
  else bad "A7 scanner env no longer sets ${e%%\"*}"; fi
done
if hasre "$VSC" '^pub const HOME_DIR: &str = "/var/lib/dockpanel/scanners/home";' \
   && hasre "$VSC" '^pub const TMP_DIR: &str = "/var/lib/dockpanel/scanners/tmp";' \
   && hasre "$VSC" '^pub const CACHE_DIR: &str = "/var/lib/dockpanel/scanners/cache";'; then
  ok "A8 HOME/TMPDIR/XDG_CACHE_HOME live under /var/lib/dockpanel/scanners"
else bad "A8 scanner HOME/TMPDIR/cache moved out of /var/lib/dockpanel/scanners"; fi

RINST=$(fnof "$VSC" '^async fn run_install[(]')
if has "$RINST" "image_scanner::install_grype_binary" && ! grep -qE 'image_scanner::install_grype[),]' <<< "$RINST"; then
  ok "A9 install uses install_grype_binary (no db priming in the agent cgroup)"
else bad "A9 run_install reuses install_grype, which primes the db inside the agent cgroup"; fi

echo "== §B  no database download while matching, reports by file =="
B1TXT=$(grep -A2 -F 'if !auto_update {' <<< "$SENV" || true)
if has "$B1TXT" '("GRYPE_DB_AUTO_UPDATE", "false")'; then
  ok "B1 GRYPE_DB_AUTO_UPDATE=false unless auto_update is asked"
else bad "B1 GRYPE_DB_AUTO_UPDATE=false is gone from scanner_env"; fi
if has "$MONE" "scanner_command(image_scanner::GRYPE_BIN, false)"; then ok "B2 match runs grype with auto update off"
else bad "B2 match no longer runs grype with auto update off"; fi
DBU=$(fnof "$VSC" '^async fn run_db_update[(]')
if has "$DBU" "scanner_command(image_scanner::GRYPE_BIN, true)" && has "$DBU" '"db", "update"'; then
  ok "B3 only run_db_update allows the download"
else bad "B3 run_db_update no longer runs grype db update with auto update on"; fi
N_AU=$(grep -cE 'scanner_command\([^)]*, true\)' <<< "$VSC" || true)
if [ "$N_AU" -eq 1 ]; then ok "B4 exactly one scanner run with auto update on"
else bad "B4 $N_AU scanner runs with auto update on (expected 1)"; fi
SARGS=$(fnof "$VSC" '^pub fn syft_args[(]')
if has "$SARGS" 'format!("syft-json={}", out.display())'; then ok "B5 syft writes its SBOM to a file (-o syft-json=<path>)"
else bad "B5 syft no longer writes -o syft-json=<path>"; fi
if has "$MONE" 'format!("json={}", out.display())'; then ok "B6 grype writes its report to a file (-o json=<path>)"
else bad "B6 grype no longer writes -o json=<path>"; fi
if has "$(fnof "$VSC" '^pub fn find_args[(]')" '"-fprint0".into()'; then ok "B7 find writes its list to a file (-fprint0)"
else bad "B7 find no longer writes -fprint0"; fi
for pair in "MONE:match_one" "IONE:inventory_one"; do
  v="${pair%%:*}"; name="${pair##*:}"
  if has "${!v}" ".stdout"; then bad "B8 $name reads the scanner's stdout"
  else ok "B8 $name never reads the scanner's stdout"; fi
done
if has "$MONE" "parse_grype_report(f)" && has "$VSC" "serde_json::from_reader(std::io::BufReader::new(r))"; then
  ok "B9 the grype report is streamed from the file into typed structs"
else bad "B9 the grype report is no longer streamed from the file"; fi
if has "$IONE" '.json.tmp' && has "$IONE" 'std::fs::rename(&tmp, &sbom)'; then
  ok "B10 the SBOM is written to a temporary file then renamed"
else bad "B10 the SBOM is no longer written atomically (tmp + rename)"; fi
if has "$(fnof "$VSC" '^pub fn syft_args[(]')" '"--select-catalogers".into()' && has "$VSC" '"./var/lib/docker/**",'; then
  ok "B11 the system SBOM selects dpkg and excludes container/site trees"
else bad "B11 the system SBOM lost --select-catalogers or its exclusions"; fi
SROOT=$(fnof "$VSC" '^pub fn site_root[(]')
if has "$SROOT" "real_current.starts_with(&real_site)" && has "$SROOT" "return (real_current, true);"; then
  ok "B12 a site's current link is followed only inside the site, and scanned resolved"
else bad "B12 site_root no longer confines current to the site (the owner's link would aim root-run syft anywhere)"; fi
if has "$(fnof "$VSC" '^pub fn syft_args[(]')" 'if active_release && *e == "**/releases/**"'; then
  ok "B13 the active release is not excluded by **/releases/**"
else bad "B13 **/releases/** is applied to the active release too (it would exclude everything)"; fi
if has "$IONE" "std::fs::symlink_metadata(&site).map(|m| m.file_type().is_dir())"; then
  ok "B14 the site directory must be a real directory, not a link"
else bad "B14 inventory accepts a site directory that is a link"; fi

echo "== §C  job kinds and locks =="
for pair in "start_install:vuln_install" "start_db_update:vuln_db_update" "start_inventory:vuln_inventory" "start_match:vuln_match"; do
  f="${pair%%:*}"; k="${pair##*:}"
  if has "$(fnof "$VSC" "^pub fn $f[(]")" "migration_jobs::spawn(\"$k\", \"server\""; then ok "C4 $f spawns job $k on key server"
  else bad "C4 $f no longer spawns $k on key server"; fi
done
for pair in "start_inventory:INVENTORY_LOCK" "start_match:DB_LOCK" "start_db_update:DB_LOCK" "start_install:INVENTORY_LOCK" "start_install:DB_LOCK"; do
  f="${pair%%:*}"; l="${pair##*:}"
  if has "$(fnof "$VSC" "^pub fn $f[(]")" "$l.lock().await"; then ok "C5 $f holds $l"
  else bad "C5 $f no longer holds $l"; fi
done
INST=$(fnof "$VSC" '^pub fn start_install[(]')
if [ "$(grep -nF 'INVENTORY_LOCK.lock()' <<< "$INST" | cut -d: -f1)" -lt "$(grep -nF 'DB_LOCK.lock()' <<< "$INST" | cut -d: -f1)" ]; then
  ok "C6 install takes the inventory lock before the db lock (no lock-order inversion)"
else bad "C6 install takes the two locks in the wrong order"; fi
if has "$(fnof "$VSC" '^async fn run_install[(]')" "check_free_space(free_bytes())?" && has "$DBU" "check_free_space(free_bytes())?"; then
  ok "C7 install and db update refuse below the free-space floor"
else bad "C7 install or db update no longer checks free space"; fi
if has "$VSC" '"insufficient disk space: {gib:.1} GiB free, 8 GiB required"' && hasre "$VSC" '^const MIN_FREE_BYTES: u64 = 8 \* 1024 \* 1024 \* 1024;'; then
  ok "C8 8 GiB floor (unpacked db ~3.3 GiB, kept twice during an update)"
else bad "C8 free-space floor or its message changed"; fi
if has "$VSC" '"./var/lib/containerd/**",' && has "$VSC" '"./var/lib/docker/**",'; then
  ok "C9 OS SBOM excludes the Docker and containerd image stores (no image dpkg db in the OS target)"
else bad "C9 the OS SBOM would read container image layers again"; fi

echo "== §D  pinned versions, real version checked =="
if hasre "$ISC" '^const GRYPE_VERSION: &str = "v0\.122\.1";'; then ok "D1 grype pinned to v0.122.1 (private const)"
else bad "D1 GRYPE_VERSION is not a private const v0.122.1"; fi
if hasre "$SBC" '^const SYFT_VERSION: &str = "v1\.57\.2";'; then ok "D2 syft pinned to v1.57.2 (private const)"
else bad "D2 SYFT_VERSION is not a private const v1.57.2"; fi
EV=$(fnof "$VSC" '^async fn ensure_version<')
RM=$(grep -nF 'tokio::fs::remove_file(bin)' <<< "$EV" | head -1 | cut -d: -f1)
IN=$(grep -nF 'install().await?' <<< "$EV" | head -1 | cut -d: -f1)
if [ -n "$RM" ] && [ -n "$IN" ] && [ "$RM" -lt "$IN" ]; then ok "D3 a wrong-version binary is removed before the installer runs"
else bad "D3 ensure_version no longer removes the binary before installing (the installers return early when it exists)"; fi
if [ "$(cnt "$EV" "binary_version(bin).await")" -ge 2 ]; then ok "D4 the real version is read before and after install"
else bad "D4 the installed version is not re-read after install"; fi
if has "$(fnof "$VSC" '^async fn binary_version[(]')" '.args(["version", "-o", "json"])'; then ok "D5 version read from \`<bin> version -o json\`"
else bad "D5 the version probe changed"; fi

echo "== §E  reading grype =="
if has "$FOF" "std::iter::once(v).chain(m.related.iter())"; then ok "E1 vulnerability and relatedVulnerabilities are read together"
else bad "E1 relatedVulnerabilities are no longer chained with the vulnerability"; fi
if has "$FOF" "all.iter().map(|x| &x.known_exploited).find(|k| !k.is_empty())"; then ok "E2 KEV is taken from the first record carrying it, related included"
else bad "E2 KEV is no longer looked up in relatedVulnerabilities"; fi
if has "$FOF" "all.iter().map(|x| &x.epss).find(|e| !e.is_empty())"; then ok "E3 EPSS is taken from the first record carrying it, related included"
else bad "E3 EPSS is no longer looked up in relatedVulnerabilities"; fi
if has "$FOF" 'eq_ignore_ascii_case("known")'; then ok "E4 ransomware flag from knownRansomwareCampaignUse == Known"
else bad "E4 kev_ransomware no longer reads knownRansomwareCampaignUse"; fi
if has "$FOF" '.find(|r| r.id.starts_with("CVE-"))'; then ok "E5 a GHSA is reported under its related CVE id"
else bad "E5 vuln_id no longer prefers the related CVE id"; fi
if has "$VSC" 'rename = "relatedVulnerabilities"' && has "$VSC" 'rename = "knownExploited"' && has "$VSC" 'rename = "knownRansomwareCampaignUse"'; then
  ok "E6 the grype JSON field names are mapped"
else bad "E6 a grype JSON field name mapping is gone"; fi
if hasre "$VSC" '^pub const MAX_FINDINGS: usize = 5000;' && has "$(fnof "$VSC" '^pub fn finalize_findings[(]')" "findings.truncate(MAX_FINDINGS);"; then
  ok "E7 findings capped at 5000 per target"
else bad "E7 the 5000-finding cap is gone"; fi
if has "$(fnof "$VSC" '^pub fn finalize_findings[(]')" "seen.insert((f.vuln_id.clone(), f.package.clone(), f.version.clone()))"; then
  ok "E8 dedup on (vuln_id, package, version) - the backend's unique key"
else bad "E8 dedup key changed"; fi
if [ -f panel/agent/src/services/testdata/grype-v0.122-report.json ] && \
   grep -qF '"knownRansomwareCampaignUse": "Known"' panel/agent/src/services/testdata/grype-v0.122-report.json; then
  ok "E9 the grype fixture carries KEV on a related record"
else bad "E9 the grype fixture is missing or lost its related KEV"; fi

echo "== §F  security_scanner runs the managed grype =="
SCV=$(fnof "$SSC" '^async fn scan_container_vulnerabilities[(]')
if [ "$(grep -c . <<< "$SCV")" -ge 30 ]; then ok "F0-control scan_container_vulnerabilities body extracted"
else bad "F0-control scan_container_vulnerabilities body not extracted"; fi
if has "$SCV" "safe_command(crate::services::image_scanner::GRYPE_BIN)" && has "$SCV" '.env("GRYPE_DB_CACHE_DIR", crate::services::image_scanner::GRYPE_DB_CACHE)'; then
  ok "F1 container_vuln runs image_scanner::GRYPE_BIN with GRYPE_DB_CACHE_DIR"
else bad "F1 container_vuln no longer runs the managed grype with its db cache"; fi
if has "$SCV" 'safe_command("grype")'; then bad "F2 container_vuln calls a grype on PATH again"
else ok "F2 no grype-on-PATH call left"; fi
if hasre "$ISC" '^pub const GRYPE_BIN: &str = "/var/lib/dockpanel/scanners/grype";'; then ok "F3 GRYPE_BIN is shared from image_scanner"
else bad "F3 GRYPE_BIN is no longer exported by image_scanner"; fi

echo "== §G  wiring =="
PROP=$(fnof "$SAFEC" '^    pub fn property[(]')
if has "$PROP" '.position(|a| a == "--")' && has "$PROP" 'self.argv.insert(sep, std::ffi::OsString::from("-p"));'; then
  ok "G1 UnsandboxedCommand::property inserts -p before the separator"
else bad "G1 property() no longer inserts before the -- separator"; fi
if grep -qF 'fn property_lands_before_the_separator_and_unit_arg_still_follows_it' "$SAFE"; then ok "G2 property() has its unit test"
else bad "G2 property()'s unit test is gone"; fi
L_V=$(grep -nF '.merge(routes::vulns::router())' "$MAIN" | head -1 | cut -d: -f1)
L_A=$(grep -nF 'routes::auth_middleware))' "$MAIN" | head -1 | cut -d: -f1)
if [ -n "$L_V" ] && [ -n "$L_A" ] && [ "$L_V" -lt "$L_A" ]; then ok "G3 vulns routes merged before the auth middleware layer"
else bad "G3 vulns routes missing or merged after the auth layer (unauthenticated)"; fi
if grep -qxF 'pub mod vulns; // CVE scanner (13)' "$RMOD" && grep -qxF 'pub mod vuln_scanner; // CVE scanner (13)' "$SMOD"; then
  ok "G4 one-line module registrations"
else bad "G4 module registration lines changed"; fi
for r in '"/vulns/status", get(status)' '"/vulns/install", post(install)' '"/vulns/db-update", post(db_update)' \
         '"/vulns/targets", get(targets)' '"/vulns/inventory", post(inventory)' '"/vulns/match", post(match_targets)' \
         '"/vulns/sbom/{target_id}", delete(delete_sbom)'; do
  if has "$VRC" ".route($r)"; then ok "G5 route ${r%%,*}"
  else bad "G5 route ${r%%,*} is gone"; fi
done
if has "$(fnof "$VSC" '^pub fn validate_target_id[(]')" "u.hyphenated().to_string() == s"; then
  ok "G6 target_id must be a canonical UUID (it names the SBOM file)"
else bad "G6 target_id validation no longer insists on the canonical form"; fi

echo
printf 'PASS %d  FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
