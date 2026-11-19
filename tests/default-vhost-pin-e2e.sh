#!/usr/bin/env bash
# Regression pins for D6: an unknown host name served by the first site.
#
# Nothing declared a default server, so nginx answered an unknown name (or a
# deleted site's name) with the first enabled vhost: its certificate on 443 and
# its content on both ports. The agent now keeps a catch-all per listen address
# (services/default_vhost.rs). What it renders is unit tested there; this file
# pins that the catch-all actually reaches every server and stays out of the way.
#
#   run: bash tests/default-vhost-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$REPO/panel/agent/src"
MOD="$AGENT/services/default_vhost.rs"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()  { if grep -qE -- "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }
code() { grep -vE '^[[:space:]]*(//|#)' "$1" 2>/dev/null; }

echo "── the agent owns the file ──"
if [ -f "$MOD" ]; then ok "services/default_vhost.rs exists"; else bad "services/default_vhost.rs exists"; fi
has "the module is declared" '^pub mod default_vhost;' "$AGENT/services/mod.rs"
has "it rejects the TLS handshake" 'ssl_reject_handshake on;' "$MOD"
has "it closes the connection" 'return 444;' "$MOD"
has "it keeps ACME challenges answerable" 'location \^~ /\.well-known/acme-challenge/' "$MOD"

echo
echo "── every path that changes the listen set reaches it ──"
if code "$AGENT/main.rs" | grep 'default_vhost::reconcile().await' > /dev/null; then
    ok "the agent reconciles at startup (new installs and updates)"
else
    bad "the agent reconciles at startup (new installs and updates)"
fi
if code "$AGENT/services/nginx.rs" | sed -n '/^pub async fn reload() -> Result<(), String> {/,/^}/p' | grep 'default_vhost::sync().await' > /dev/null; then
    ok "every site reload re-derives it (an IP added later is covered)"
else
    bad "every site reload re-derives it (an IP added later is covered)"
fi

SYNC=$(code "$MOD" | sed -n '/^pub async fn sync() -> bool {/,/^}/p')
if printf '%s\n' "$SYNC" | grep 'test_config()' > /dev/null; then ok "sync checks nginx -t after writing"; else bad "sync checks nginx -t after writing"; fi
if printf '%s\n' "$SYNC" | grep 'restore_or_remove' > /dev/null; then ok "sync restores the previous file on failure"; else bad "sync restores the previous file on failure"; fi
if printf '%s\n' "$SYNC" | grep -E '(^|[^_])reload\(' > /dev/null; then bad "sync never reloads by itself"; else ok "sync never reloads by itself"; fi

echo
echo "── setup.sh covers the listeners certbot adds after the agent started ──"
MAIN=$(code "$REPO/scripts/setup.sh" | sed -n '/^main() {/,/^}/p')
A=$(printf '%s\n' "$MAIN" | grep -n '^    provision_panel_ssl' | cut -d: -f1)
B=$(printf '%s\n' "$MAIN" | grep -n 'systemctl restart dockpanel-agent' | tail -1 | cut -d: -f1)
if [ -n "$A" ] && [ -n "$B" ] && [ "$A" -lt "$B" ]; then ok "the agent is restarted after the panel certificate"; else bad "the agent is restarted after the panel certificate"; fi

echo
echo "── update.sh reaches it through the agent restart ──"
UPD="$REPO/scripts/update.sh"
A=$(code "$UPD" | grep -n 'nginx -t failed after config migrations' | head -1 | cut -d: -f1)
B=$(code "$UPD" | grep -n '^systemctl start dockpanel-agent' | head -1 | cut -d: -f1)
if [ -n "$A" ] && [ -n "$B" ] && [ "$A" -lt "$B" ]; then ok "the agent starts after the nginx migrations"; else bad "the agent starts after the nginx migrations"; fi

echo
echo "── the catch-all is not mistaken for a site (RHEL keeps it in the sites dir) ──"
for f in routes/iac.rs services/diagnostics.rs services/security_scanner.rs; do
    has "$f skips it" 'DEFAULT_VHOST_FILE' "$AGENT/$f"
done

echo
echo "── uninstall takes it away ──"
has "uninstall.sh removes the file" 'rm -f /etc/nginx/conf\.d/dockpanel-default-vhost\.conf' "$REPO/scripts/uninstall.sh"

echo
echo "══ $PASS passed, $FAIL failed ══"
[ "$FAIL" -eq 0 ]
