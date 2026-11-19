#!/usr/bin/env bash
# Regression pins for D9: UFW listed in the install summary while inactive.
#
# Ubuntu 24.04 ships ufw installed but inactive. detect_firewall therefore
# answered "ufw", and the matching branch of install_recommended_services only
# logged "already installed" and reported the service as fine. Nothing enabled
# the firewall, so 8443 stayed open on every interface under a summary that said
# otherwise.
#
# These run the real functions out of setup.sh against stub ufw/sshd/ss binaries.
# No real firewall is touched.
#
#   run: bash tests/ufw-activation-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETUP="$REPO/scripts/setup.sh"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$3], got [$2])"; fi; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"

# ── Stubs ────────────────────────────────────────────────────────────────
cat > "$BIN/ufw" <<'EOF'
#!/bin/bash
echo "ufw $*" >> "$STUB_DIR/ufw.log"
case "$1" in
    status) echo "Status: $(cat "$STUB_DIR/ufw.state")"; exit 0 ;;
    show)   cat "$STUB_DIR/ufw.added" 2>/dev/null; exit 0 ;;
    allow)  [ "$2" = "${UFW_FAIL_ALLOW:-}" ] && exit 1; exit 0 ;;
    --force)
        [ "${UFW_FAIL_ENABLE:-0}" = "1" ] && exit 1
        [ "${UFW_ENABLE_NOOP:-0}" = "1" ] || echo active > "$STUB_DIR/ufw.state"
        exit 0 ;;
esac
exit 0
EOF
cat > "$BIN/sshd" <<'EOF'
#!/bin/bash
[ -n "${SSHD_PORTS:-}" ] || exit 255
for p in $SSHD_PORTS; do echo "port $p"; done
echo "permitrootlogin yes"
EOF
cat > "$BIN/ss" <<'EOF'
#!/bin/bash
case "$*" in
    *established*) [ -n "${SS_SESSION:-}" ] && echo "0 0 10.0.0.5:${SS_SESSION} 10.0.0.9:51000 users:((\"sshd-session\",pid=9,fd=4))" ;;
    *) [ -n "${SS_LISTEN:-}" ] && echo "LISTEN 0 128 0.0.0.0:${SS_LISTEN} 0.0.0.0:* users:((\"sshd\",pid=8,fd=3))" ;;
esac
exit 0
EOF
cat > "$BIN/systemctl" <<'EOF'
#!/bin/bash
[ -n "${SOCKET_LISTEN:-}" ] && echo "[::]:${SOCKET_LISTEN} (Stream)"
exit 0
EOF
chmod +x "$BIN"/*

# ── The code under test, lifted out of setup.sh ──────────────────────────
for fn in detect_ssh_ports configure_ufw; do
    sed -n "/^$fn() {/,/^}/p" "$SETUP" > "$TMP/$fn.sh"
    if [ -s "$TMP/$fn.sh" ]; then ok "setup.sh defines $fn"; else bad "setup.sh defines $fn"; fi
done

# One scenario in a clean subshell. Prints FW_STATE, then the reason.
scenario() {
    local name="$1"; shift
    local dir="$TMP/$name"; mkdir -p "$dir"
    echo "${START_STATE:-inactive}" > "$dir/ufw.state"
    : > "$dir/ufw.log"
    [ -n "${ADDED_RULES:-}" ] && printf '%s\n' "$ADDED_RULES" > "$dir/ufw.added"
    (
        export STUB_DIR="$dir" PATH="$BIN:$PATH"
        unset SSH_CONNECTION
        for kv in "$@"; do export "${kv?}"; done
        FW_MGR=ufw; FW_STATE=""; FW_NOTE=""; FW_MANUAL=""
        PANEL_PORT="${PANEL_PORT:-8443}"
        PANEL_ALREADY_INSTALLED="${PANEL_ALREADY_INSTALLED:-0}"
        log()  { :; }; warn() { :; }; info() { :; }
        svc_ok() { echo "$1" >> "$STUB_DIR/svc_ok"; }
        svc_fail() { echo "$1" >> "$STUB_DIR/svc_fail"; }
        fw_allow() { ufw allow "$1" > /dev/null 2>&1; }
        # shellcheck disable=SC1090
        . "$TMP/detect_ssh_ports.sh"; . "$TMP/configure_ufw.sh"
        configure_ufw
        echo "rc=$?" > "$STUB_DIR/result"
        echo "state=$FW_STATE" >> "$STUB_DIR/result"
        echo "note=$FW_NOTE" >> "$STUB_DIR/result"
        echo "manual=$FW_MANUAL" >> "$STUB_DIR/result"
    ) > /dev/null 2>&1
    DIR="$dir"
}
field()   { sed -n "s/^$1=//p" "$DIR/result" 2>/dev/null; }
called()  { if grep -qF -- "$1" "$DIR/ufw.log"; then echo yes; else echo no; fi; }
line_of() { grep -nF -- "$1" "$DIR/ufw.log" | head -1 | cut -d: -f1; }
before()  { local a b; a=$(line_of "$1"); b=$(line_of "$2"); if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then echo yes; else echo no; fi; }
svc_reported() { if [ -f "$DIR/svc_ok" ] && grep -qx UFW "$DIR/svc_ok"; then echo yes; else echo no; fi; }

echo "── a fresh install really turns UFW on ──"
scenario fresh SSHD_PORTS=22
check "the firewall ends up active"          "$(cat "$DIR/ufw.state")" "active"
check "the reported state is active"         "$(field state)" "active"
check "UFW is listed as a working service"   "$(svc_reported)" "yes"
check "the SSH port is allowed"              "$(called 'ufw allow 22/tcp')" "yes"
check "80 is allowed"                        "$(called 'ufw allow 80/tcp')" "yes"
check "443 is allowed"                       "$(called 'ufw allow 443/tcp')" "yes"
check "the panel port is allowed"            "$(called 'ufw allow 8443/tcp')" "yes"
check "SSH is allowed before anything else"  "$(sed -n 's/^ufw allow //p' "$DIR/ufw.log" | head -1)" "22/tcp"
check "SSH is allowed before enable"         "$(before 'ufw allow 22/tcp' 'ufw --force enable')" "yes"
check "the panel port is allowed before enable" "$(before 'ufw allow 8443/tcp' 'ufw --force enable')" "yes"
check "incoming defaults to deny"            "$(called 'ufw default deny incoming')" "yes"
check "ufw reset is never used"              "$(called 'ufw reset')" "no"

echo
echo "── the SSH port is the one really in use ──"
scenario custom SSHD_PORTS=2222
check "a custom sshd -T port is allowed"     "$(called 'ufw allow 2222/tcp')" "yes"
check "22 is not opened for nothing"         "$(called 'ufw allow 22/tcp')" "no"

scenario multi "SSHD_PORTS=22 2200"
check "every configured port is allowed (22)"   "$(called 'ufw allow 22/tcp')" "yes"
check "every configured port is allowed (2200)" "$(called 'ufw allow 2200/tcp')" "yes"

scenario session SSHD_PORTS=22 "SSH_CONNECTION=10.0.0.9 51000 10.0.0.5 4022"
check "the current session's port is allowed"  "$(called 'ufw allow 4022/tcp')" "yes"
check "and allowed before enable"              "$(before 'ufw allow 4022/tcp' 'ufw --force enable')" "yes"

scenario sudo_session SSHD_PORTS=22 SS_SESSION=4122
check "a session hidden by sudo is found via ss" "$(called 'ufw allow 4122/tcp')" "yes"

scenario no_T SS_LISTEN=2022
check "sshd -T failing falls back to the listener" "$(called 'ufw allow 2022/tcp')" "yes"
check "and the firewall still comes up"            "$(cat "$DIR/ufw.state")" "active"

scenario socket_activated SOCKET_LISTEN=2023
check "a socket-activated sshd is found"           "$(called 'ufw allow 2023/tcp')" "yes"

echo
echo "── when SSH cannot be proven safe, UFW stays off and the summary says so ──"
scenario unknown_ssh
check "no SSH port found: never enabled"     "$(called 'ufw --force enable')" "no"
check "the state is inactive"                "$(field state)" "inactive"
check "the install does not fail"            "$(field rc)" "0"
check "UFW is not reported as working"       "$(svc_reported)" "no"
if [ -n "$(field note)" ]; then ok "a reason is given"; else bad "a reason is given"; fi
if [ -n "$(field manual)" ]; then ok "the manual command is given"; else bad "the manual command is given"; fi

scenario ssh_allow_fails SSHD_PORTS=22 UFW_FAIL_ALLOW=22/tcp
check "SSH rule refused: never enabled"      "$(called 'ufw --force enable')" "no"
check "the state is inactive"                "$(field state)" "inactive"
check "the install does not fail"            "$(field rc)" "0"

scenario web_allow_fails SSHD_PORTS=22 UFW_FAIL_ALLOW=443/tcp
check "443 rule refused: never enabled"      "$(called 'ufw --force enable')" "no"
check "the state is inactive"                "$(field state)" "inactive"

scenario enable_fails SSHD_PORTS=22 UFW_FAIL_ENABLE=1
check "enable failing is reported inactive"  "$(field state)" "inactive"
check "the install does not fail"            "$(field rc)" "0"
check "UFW is not reported as working"       "$(svc_reported)" "no"

scenario enable_lies SSHD_PORTS=22 UFW_ENABLE_NOOP=1
check "enable exit 0 but still inactive is not believed" "$(field state)" "inactive"
check "UFW is not reported as working"       "$(svc_reported)" "no"

ADDED_RULES='ufw deny 22/tcp'
scenario operator_deny SSHD_PORTS=22
unset ADDED_RULES
check "an existing deny rule stops activation" "$(called 'ufw --force enable')" "no"
check "the state is inactive"                  "$(field state)" "inactive"

echo
echo "── a server that is already installed is left alone ──"
PANEL_ALREADY_INSTALLED=1
scenario rerun SSHD_PORTS=22
unset PANEL_ALREADY_INSTALLED
check "a re-run never enables UFW"           "$(called 'ufw --force enable')" "no"
check "a re-run adds no rule"                "$(called 'ufw allow')" "no"
check "a re-run changes no default"          "$(called 'ufw default')" "no"
check "the state is honest"                  "$(field state)" "inactive"
if [ -n "$(field manual)" ]; then ok "the administrator is told how"; else bad "the administrator is told how"; fi

echo
echo "── a firewall that is already active keeps its rules ──"
START_STATE=active
scenario already_active SSHD_PORTS=22
unset START_STATE
check "no second enable"                     "$(called 'ufw --force enable')" "no"
check "defaults are not rewritten"           "$(called 'ufw default')" "no"
check "the panel ports are still opened"     "$(called 'ufw allow 8443/tcp')" "yes"
check "the state is active"                  "$(field state)" "active"

echo
echo "── the installer wiring ──"
code() { grep -vE '^[[:space:]]*#' "$SETUP"; }
branch() { code | sed -n '/^install_recommended_services() {/,/^}/p' | sed -n "/^        $1)/,/^            ;;/p"; }
if branch ufw | grep 'configure_ufw' > /dev/null; then R=yes; else R=no; fi
check "the 'ufw already present' branch configures it" "$R" "yes"
if branch none | grep 'configure_ufw' > /dev/null; then R=yes; else R=no; fi
check "the 'ufw just installed' branch configures it" "$R" "yes"
if branch ufw | grep 'svc_ok "UFW"' > /dev/null; then R=yes; else R=no; fi
check "presence of the binary alone is no longer reported as success" "$R" "no"
if code | grep 'ufw allow 22/tcp' > /dev/null; then R=yes; else R=no; fi
check "no hardcoded SSH port remains" "$R" "no"
if code | sed -n '/^main() {/,/^}/p' | grep 'PANEL_ALREADY_INSTALLED=1' > /dev/null; then R=yes; else R=no; fi
check "main records an existing install" "$R" "yes"
A=$(code | sed -n '/^main() {/,/^}/p' | grep -n 'PANEL_ALREADY_INSTALLED=1' | head -1 | cut -d: -f1)
B=$(code | sed -n '/^main() {/,/^}/p' | grep -n '^    generate_secrets' | head -1 | cut -d: -f1)
if [ -n "$A" ] && [ -n "$B" ] && [ "$A" -lt "$B" ]; then R=yes; else R=no; fi
check "and does so before api.env can be written" "$R" "yes"
if code | sed -n '/^print_summary() {/,/^}/p' | grep 'FW_STATE' > /dev/null; then R=yes; else R=no; fi
check "the summary reports the verified firewall state" "$R" "yes"

echo
echo "══ $PASS passed, $FAIL failed ══"
[ "$FAIL" -eq 0 ]
