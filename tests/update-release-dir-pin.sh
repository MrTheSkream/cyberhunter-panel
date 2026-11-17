#!/usr/bin/env bash
# Pins for 10 (mises a jour depuis l'interface), contract B-4, B-6 and B-8:
# the shell side of an update installs ONLY files the panel binary has already
# verified, and re-checks their SHA-256 itself before touching the box.
#
#   §1  update.sh: release mode needs CYBERHUNTER_RELEASE_DIR, downloads
#       nothing, re-checks every file, keeps the strings the backend pins.
#   §2  update.sh's verification block, EXECUTED against a fake release:
#       a good release passes, a tampered byte / a missing entry / a malformed
#       manifest / a missing file each stops it.
#   §3  setup.sh's local-release install, EXECUTED the same way.
#   §4  install-agent.sh downloads from the panel, SHA-256 mandatory.
#   §5  bash -n on every script work stream B touches (and shellcheck, errors
#       only, when it is installed).
#
# Static, runs anywhere with bash (Git Bash included). No root, no network.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

UPD=scripts/update.sh
SETUP=scripts/setup.sh
IAGENT=scripts/install-agent.sh

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Shell code with full-line comments blanked (line numbers kept).
code_lines() { awk '/^[[:space:]]*#/ { print ""; next } { print }' "$1"; }
has_code()   { local f="$1"; shift; [ "$(code_lines "$f" | grep -c "$@" 2>/dev/null || true)" -gt 0 ]; }
code_lineno() { local f="$1"; shift; code_lines "$f" | grep -n "$@" 2>/dev/null | head -1 | cut -d: -f1 || true; }

for f in "$UPD" "$SETUP" "$IAGENT"; do
    [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "── 1. update.sh: release mode installs only a verified release directory ──"
MSG='Release updates are started from the panel (Telemetry, Updates). To update by hand, build from source.'
if has_code "$UPD" -F "error \"$MSG\""; then
    ok "release mode without CYBERHUNTER_RELEASE_DIR stops with the contract's message"
else
    bad "update.sh does not refuse release mode without CYBERHUNTER_RELEASE_DIR (message missing)"
fi
if has_code "$UPD" -F -e '--setenv=CYBERHUNTER_RELEASE_DIR='; then
    ok "the systemd-run re-exec carries CYBERHUNTER_RELEASE_DIR"
else
    bad "the re-exec drops CYBERHUNTER_RELEASE_DIR - the detached run would refuse every panel update"
fi
for gone in 'git fetch' 'raw.githubusercontent' 'api.github.com' 'releases/download' \
            'GITHUB_REPO' 'DOCKPANEL_NO_SELF_REFRESH' 'SELF_REFRESHED' 'dp_fetch'; do
    # The whole file, comments included: none of these has a reason to be named.
    if grep -qF -- "$gone" "$UPD"; then
        bad "update.sh still mentions '$gone'"
    else
        ok "update.sh does not mention '$gone'"
    fi
done
if has_code "$UPD" -E 'sha256sum' && has_code "$UPD" -E 'checksums\.txt' \
   && has_code "$UPD" -F 'CHECKSUMS="$RELEASE_DIR/checksums.txt"'; then
    ok "update.sh re-checks SHA-256 against the release directory's checksums.txt"
else
    bad "update.sh does not re-check SHA-256 against \$CYBERHUNTER_RELEASE_DIR/checksums.txt"
fi
VERIFY_LN=$(code_lineno "$UPD" -F '_dockpanel_stage="verify"')
BACKUP_LN=$(code_lineno "$UPD" -F '_dockpanel_stage="db-backup"')
STOP_LN=$(code_lineno "$UPD" -F 'systemctl stop dockpanel-agent dockpanel-api')
if [ -n "$VERIFY_LN" ] && [ -n "$BACKUP_LN" ] && [ -n "$STOP_LN" ] \
   && [ "$VERIFY_LN" -lt "$BACKUP_LN" ] && [ "$VERIFY_LN" -lt "$STOP_LN" ]; then
    ok "the verify stage (l.$VERIFY_LN) runs before the database dump (l.$BACKUP_LN) and the service stop (l.$STOP_LN)"
else
    bad "the verify stage is missing or comes after a change to the box (verify=$VERIFY_LN dump=$BACKUP_LN stop=$STOP_LN)"
fi
for asset in 'cyberhunter-agent-linux-${DL_ARCH}' 'cyberhunter-api-linux-${DL_ARCH}' \
             'cyberhunter-cli-linux-${DL_ARCH}' 'cyberhunter-mcp-linux-${DL_ARCH}' \
             'cyberhunter-frontend.tar.gz'; do
    if has_code "$UPD" -F "verify_release_file \"$asset\""; then
        ok "update.sh verifies $asset"
    else
        bad "update.sh installs $asset without verifying it (or under another name)"
    fi
done
if has_code "$UPD" -E 'dockpanel-(agent|api|cli|mcp)-linux-'; then
    bad "update.sh still names an old asset (dockpanel-*-linux-*)"
else
    ok "update.sh names no old asset (dockpanel-*-linux-*)"
fi
# The scripts copy for SSH use lands only after the health checks, right before
# the success verdict.
HEALTH_LN=$(code_lineno "$UPD" -F 'log "Health checks passed"')
COPY_LN=$(code_lineno "$UPD" -F 'cp -a "$REPO_DIR/scripts/." /opt/dockpanel/scripts/')
DONE_LN=$(code_lineno "$UPD" -F '_dockpanel_write_result true "complete"')
if [ -n "$HEALTH_LN" ] && [ -n "$COPY_LN" ] && [ -n "$DONE_LN" ] \
   && [ "$HEALTH_LN" -lt "$COPY_LN" ] && [ "$COPY_LN" -lt "$DONE_LN" ]; then
    ok "/opt/dockpanel/scripts is refreshed after the health checks and before the success verdict"
else
    bad "/opt/dockpanel/scripts refresh is missing or misplaced (health=$HEALTH_LN copy=$COPY_LN complete=$DONE_LN)"
fi
# The strings the backend's own tests pin (panel/backend/src/services/panel_update.rs).
for s in 'last-panel-update.json' 'trap _dockpanel_on_exit EXIT' \
         '_dockpanel_write_result true "complete"' '_dockpanel_write_result false "rollback"' \
         'exec systemd-run'; do
    if grep -qF -- "$s" "$UPD"; then ok "update.sh keeps '$s'"; else bad "update.sh lost '$s' (pinned by the backend tests)"; fi
done
for flag in '--wait' '--pipe'; do
    if has_code "$UPD" -F -e "$flag"; then
        bad "update.sh uses $flag on a code line - the detached unit would die with the api"
    else
        ok "no code line of update.sh uses $flag"
    fi
done

echo "── 2. update.sh's verification block, executed against a fake release ──"
# Extracted from the script itself, so this tests the shipped code, not a copy.
VBLOCK=$(awk '/^# ── Release mode: re-check every file against checksums.txt/ {on=1}
              on && /^# ── Backup database before upgrade/ {exit}
              on {print}' "$UPD")
if [ -z "$VBLOCK" ] || ! printf '%s\n' "$VBLOCK" | grep -c 'verify_release_file' >/dev/null; then
    bad "could not extract the verification block from update.sh - section 2 is measuring nothing"
else
    ok "the verification block was extracted from update.sh"
    printf '%s\n' "$VBLOCK" > "$TMP/vblock.sh"

    case "$(uname -m)" in
        x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH=amd64 ;;
    esac
    make_release() { # make_release <dir>
        local d="$1" b
        mkdir -p "$d"
        for b in agent api cli mcp; do
            { printf '\177ELF'; head -c 64 /dev/urandom; } > "$d/cyberhunter-$b-linux-$ARCH"
        done
        printf 'frontend' > "$d/cyberhunter-frontend.tar.gz"
        printf 'source' > "$d/cyberhunter-source.tar.gz"
        (cd "$d" && sha256sum cyberhunter-* | sed 's/ \*/  /' | LC_ALL=C sort -k2 > checksums.txt)
    }
    # run_vblock <release dir> ; prints PASS or REFUSE
    run_vblock() {
        if INSTALL_FROM_RELEASE=1 CYBERHUNTER_RELEASE_DIR="$1" DOCKPANEL_VERSION=v9.9.9 bash -c '
            set -euo pipefail
            log() { :; }; warn() { :; }; error() { echo "ERR: $1" >&2; }
            STAGE_DIR=""
            . "'"$TMP"'/vblock.sh"
            [ -n "$STAGE_DIR" ] && [ -f "$STAGE_DIR/dockpanel-api-new" ] && rm -rf "$STAGE_DIR"
        ' >"$TMP/out" 2>&1; then echo PASS; else echo REFUSE; fi
    }
    expect() { # expect <label> <want> <dir>
        local got; got=$(run_vblock "$3")
        if [ "$got" = "$2" ]; then ok "$1 -> $got"; else bad "$1 -> $got (expected $2): $(tail -1 "$TMP/out")"; fi
    }

    make_release "$TMP/good";    expect "an intact release"                       PASS   "$TMP/good"
    make_release "$TMP/tamper";  printf 'X' >> "$TMP/tamper/cyberhunter-api-linux-$ARCH"
                                 expect "one byte appended to the api binary"     REFUSE "$TMP/tamper"
    make_release "$TMP/noentry"; grep -v "cyberhunter-cli-linux-$ARCH" "$TMP/noentry/checksums.txt" > "$TMP/noentry/c" \
                                 && mv "$TMP/noentry/c" "$TMP/noentry/checksums.txt"
                                 expect "no checksums entry for the cli"          REFUSE "$TMP/noentry"
    make_release "$TMP/nofile";  rm -f "$TMP/nofile/cyberhunter-mcp-linux-$ARCH"
                                 expect "the mcp binary missing from the release" REFUSE "$TMP/nofile"
    make_release "$TMP/crlf";    sed -i 's/$/\r/' "$TMP/crlf/checksums.txt"
                                 expect "a CRLF manifest"                         REFUSE "$TMP/crlf"
    make_release "$TMP/onesp";   sed -i 's/  / /' "$TMP/onesp/checksums.txt"
                                 expect "a manifest with one space"               REFUSE "$TMP/onesp"
    make_release "$TMP/nosums";  rm -f "$TMP/nosums/checksums.txt"
                                 expect "no checksums.txt at all"                 REFUSE "$TMP/nosums"
    make_release "$TMP/badsrc";  printf 'X' >> "$TMP/badsrc/cyberhunter-source.tar.gz"
                                 expect "a tampered source archive"               REFUSE "$TMP/badsrc"
    make_release "$TMP/notelf";  e=$(awk -v n="cyberhunter-agent-linux-$ARCH" '$2==n{print $1}' "$TMP/notelf/checksums.txt")
                                 printf 'not an elf at all' > "$TMP/notelf/cyberhunter-agent-linux-$ARCH"
                                 (cd "$TMP/notelf" && sha256sum cyberhunter-* | sed 's/ \*/  /' | LC_ALL=C sort -k2 > checksums.txt)
                                 [ -n "$e" ] && expect "a correctly summed agent that is not ELF" REFUSE "$TMP/notelf"
fi

echo "── 3. setup.sh installs a local release, SHA-256 mandatory ──"
if grep -qF 'GITHUB_REPO' "$SETUP" || grep -cF 'dp_fetch' "$SETUP" >/dev/null; then
    bad "setup.sh still carries GITHUB_REPO or dp_fetch"
else
    ok "setup.sh carries neither GITHUB_REPO nor dp_fetch"
fi
if grep -qF 'Open an issue' "$SETUP"; then
    bad "setup.sh still prints the 'Open an issue' line"
else
    ok "the 'Open an issue' line is gone"
fi
SFUNCS=$(awk '/^(check_release_dir|install_asset)\(\) \{/ {on=1} on {print} on && /^\}/ {on=0}' "$SETUP")
if ! printf '%s\n' "$SFUNCS" | grep -c '^check_release_dir() {' >/dev/null \
   || ! printf '%s\n' "$SFUNCS" | grep -c '^install_asset() {' >/dev/null; then
    bad "could not extract check_release_dir/install_asset from setup.sh"
else
    ok "check_release_dir and install_asset were extracted from setup.sh"
    printf '%s\n' "$SFUNCS" > "$TMP/sfuncs.sh"
    # run_setup <release dir> <asset> ; PASS or REFUSE
    run_setup() {
        if CYBERHUNTER_RELEASE_DIR="$1" bash -c '
            set -euo pipefail
            error() { echo "ERR: $1" >&2; }; plog() { :; }
            . "'"$TMP"'/sfuncs.sh"
            check_release_dir
            install_asset "$2" "'"$TMP"'/dest-bin"
        ' _ "$1" "$2" >"$TMP/out" 2>&1; then echo PASS; else echo REFUSE; fi
    }
    s_expect() { local got; got=$(run_setup "$3" "$4")
        if [ "$got" = "$2" ]; then ok "setup.sh: $1 -> $got"; else bad "setup.sh: $1 -> $got (expected $2): $(tail -1 "$TMP/out")"; fi; }
    s_expect "an intact release"            PASS   "$TMP/good"   "cyberhunter-agent-linux-$ARCH"
    if [ -f "$TMP/dest-bin" ] && cmp -s "$TMP/dest-bin" "$TMP/good/cyberhunter-agent-linux-$ARCH"; then
        ok "setup.sh: the verified file is what lands on the destination"
    else
        bad "setup.sh: the destination does not hold the verified file"
    fi
    rm -f "$TMP/dest-bin"
    s_expect "a tampered api binary"        REFUSE "$TMP/tamper" "cyberhunter-api-linux-$ARCH"
    s_expect "no entry for the cli"         REFUSE "$TMP/noentry" "cyberhunter-cli-linux-$ARCH"
    s_expect "no checksums.txt"             REFUSE "$TMP/nosums" "cyberhunter-agent-linux-$ARCH"
    s_expect "a CRLF manifest"              REFUSE "$TMP/crlf"   "cyberhunter-agent-linux-$ARCH"
    if CYBERHUNTER_RELEASE_DIR="" bash -c 'set -euo pipefail; error() { :; }; . "'"$TMP"'/sfuncs.sh"; check_release_dir' >/dev/null 2>&1; then
        bad "setup.sh: release mode without CYBERHUNTER_RELEASE_DIR is accepted"
    else
        ok "setup.sh: release mode without CYBERHUNTER_RELEASE_DIR is refused"
    fi
    if [ -e "$TMP/dest-bin" ]; then
        bad "setup.sh: a refused release still left a file on the destination"
    else
        ok "setup.sh: no refused release left a file on the destination"
    fi
fi
if has_code "$SETUP" -E 'install_asset "cyberhunter-(agent|api|cli|mcp)-linux-\$\{DL_ARCH\}"' \
   && has_code "$SETUP" -F 'install_asset "cyberhunter-frontend.tar.gz"'; then
    ok "setup.sh installs the release under the contract's asset names"
else
    bad "setup.sh does not install the cyberhunter-* assets"
fi

echo "── 4. install-agent.sh downloads from the panel, SHA-256 mandatory ──"
if has_code "$IAGENT" -F '/api/agent/release/current'; then
    ok "install-agent.sh fetches from the panel's /api/agent/release/current"
else
    bad "install-agent.sh does not fetch from the panel"
fi
if has_code "$IAGENT" -F 'curl -fsSL -H "Authorization: Bearer $TOKEN"'; then
    ok "the download authenticates with the server token"
else
    bad "the download is not authenticated with the server token"
fi
if grep -qF 'Could not download the agent from the panel. Check that updates are configured on the panel (Telemetry, Updates) and that the token is valid.' "$IAGENT"; then
    ok "the failure message is the contract's"
else
    bad "the failure message differs from the contract"
fi
if grep -qiE 'installing unverified|github\.com' "$IAGENT"; then
    bad "install-agent.sh still has an unverified path or a GitHub URL"
else
    ok "install-agent.sh has no unverified path and no GitHub URL"
fi
if has_code "$IAGENT" -F 'cyberhunter-agent-linux-${ARCH_LABEL}' && has_code "$IAGENT" -F 'sha256sum "$AGENT_TMP"'; then
    ok "install-agent.sh hashes the downloaded cyberhunter-agent binary"
else
    bad "install-agent.sh does not hash the downloaded binary"
fi

echo "── 4b. update.sh: source archive mandatory, archives listed before extraction ──"
# Fail closed (B-4): the archive this script runs from is checked every time,
# never only "when it is still there", and the tree is compared to it.
if has_code "$UPD" -F 'if [ -f "$RELEASE_DIR/cyberhunter-source.tar.gz" ]'; then
    bad "update.sh still checks cyberhunter-source.tar.gz only when it is present"
else
    ok "update.sh does not make the source archive optional"
fi
if printf '%s\n' "$VBLOCK" | grep -cF 'verify_release_file "cyberhunter-source.tar.gz"' >/dev/null \
   && printf '%s\n' "$VBLOCK" | grep -cF 'check_release_archive "$STAGE_DIR/source.tar.gz" "cyberhunter-source"' >/dev/null \
   && printf '%s\n' "$VBLOCK" | grep -cF '"$(tree_digest "$REPO_DIR")"' >/dev/null; then
    ok "update.sh verifies the source archive, lists it, and compares the tree it runs from"
else
    bad "update.sh does not verify, list and compare the source archive in its verify block"
fi
if printf '%s\n' "$VBLOCK" | grep -cF 'check_release_archive "$STAGE_DIR/dockpanel-frontend.tar.gz"' >/dev/null \
   && has_code "$UPD" -F 'tar xzf "$STAGE_DIR/dockpanel-frontend.tar.gz" -C "$FE_DIR" --no-same-owner --no-same-permissions'; then
    ok "the frontend archive is listed first and extracted without owners or archived modes"
else
    bad "the frontend archive is not listed first, or is extracted with its owners and modes"
fi

# The listing guard, EXECUTED on archives built here.
GUARD=$(code_lines "$UPD" | sed -n '/^    check_release_archive() {/,/^    }/p')
if [ -z "$GUARD" ]; then
    bad "update.sh has no check_release_archive function to exercise"
else
    G="$TMP/guard"; mkdir -p "$G/src/cyberhunter-source/scripts" "$G/src/other"
    printf '%s\n' "$GUARD" > "$G/guard.sh"
    echo x > "$G/src/cyberhunter-source/scripts/update.sh"
    echo y > "$G/src/other/a"
    tar -C "$G/src" -czf "$G/ok.tgz" cyberhunter-source
    tar -C "$G/src" -czf "$G/outside.tgz" cyberhunter-source other
    ln -s /etc/passwd "$G/src/cyberhunter-source/link"
    tar -C "$G/src" -czf "$G/symlink.tgz" cyberhunter-source
    rm -f "$G/src/cyberhunter-source/link"
    ln "$G/src/cyberhunter-source/scripts/update.sh" "$G/src/cyberhunter-source/hard"
    tar -C "$G/src" -czf "$G/hardlink.tgz" cyberhunter-source
    rm -f "$G/src/cyberhunter-source/hard"
    tar -czPf "$G/absolute.tgz" "$G/src/other/a" 2>/dev/null
    run_guard() { # run_guard <archive> [prefix] ; echoes PASS or REFUSE
        if bash -c "error() { :; }; . '$G/guard.sh'; check_release_archive '$1' '${2:-}'" >/dev/null 2>&1; then
            echo PASS
        else
            echo REFUSE
        fi
    }
    expect() { # expect <label> <PASS|REFUSE> <archive> [prefix]
        local got; got=$(run_guard "$3" "${4:-}")
        if [ "$got" = "$2" ]; then ok "$1 -> $got"; else bad "$1 -> got $got, expected $2"; fi
    }
    expect "a plain source archive is accepted" PASS "$G/ok.tgz" cyberhunter-source
    expect "a member outside cyberhunter-source/ is refused" REFUSE "$G/outside.tgz" cyberhunter-source
    expect "a symbolic link is refused" REFUSE "$G/symlink.tgz" cyberhunter-source
    expect "a hard link is refused" REFUSE "$G/hardlink.tgz" cyberhunter-source
    expect "an absolute path is refused" REFUSE "$G/absolute.tgz"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$G/dotdot.tgz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as t:
    i = tarfile.TarInfo("cyberhunter-source/../../evil")
    i.size = 1
    t.addfile(i, io.BytesIO(b"x"))
PY
        expect "a .. component is refused" REFUSE "$G/dotdot.tgz" cyberhunter-source
    else
        echo "  (python3 not installed - the .. case is skipped)"
    fi
fi

echo "── 5. syntax of every script work stream B touches ──"
B_SCRIPTS=(scripts/update.sh scripts/agent-self-update.sh scripts/release.sh scripts/install.sh
           scripts/install-agent.sh scripts/setup.sh scripts/deploy-demo.sh)
for f in scripts/release-build/*.sh; do [ -f "$f" ] && B_SCRIPTS+=("$f"); done
for f in "${B_SCRIPTS[@]}"; do
    if [ ! -f "$f" ]; then bad "$f is missing"; continue; fi
    if bash -n "$f" 2>"$TMP/bashn"; then ok "bash -n $f"; else bad "bash -n $f: $(head -1 "$TMP/bashn")"; fi
done
if command -v shellcheck >/dev/null 2>&1; then
    for f in "${B_SCRIPTS[@]}"; do
        [ -f "$f" ] || continue
        if shellcheck -S error -s bash "$f" >"$TMP/sc" 2>&1; then
            ok "shellcheck -S error $f"
        else
            bad "shellcheck -S error $f: $(grep -m1 'SC[0-9]' "$TMP/sc")"
        fi
    done
else
    echo "  (shellcheck not installed - skipped)"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
