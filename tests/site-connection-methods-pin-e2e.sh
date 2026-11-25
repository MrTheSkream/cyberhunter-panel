#!/usr/bin/env bash
# Regression pin for the site's "SFTP / FTP Access" card: it must list each
# connection method with the details the server really uses.
#
# The card used to print `<domain> / 22` for every site. On a production
# server the `sftp_sites` group was key-only (SSH password login disabled), so
# the password from "Reset Password" never worked on port 22. FTPS (vsftpd) on
# port 21, with mandatory explicit TLS and passive ports 12000-12100, was the
# method that did work with that password. Users tried "port 22 + explicit TLS"
# and failed. Invariants:
#
#   - no hardcoded `/ 22` and no hardcoded host/port pair in the card
#   - the SFTP facts come from the EFFECTIVE sshd config for the account
#     (`sshd -T -C user=...`), with a probe address that is not loopback, and
#     the username is validated before it goes into the `-C` spec (a comma
#     would add match criteria of its own)
#   - "unknown" stays unknown: a failed `sshd -T` or an agent without the route
#     gives `password_login: null`, never `true`
#   - FTPS is shown only when vsftpd is installed AND the account is on the
#     allow-list (/etc/dockpanel/ftp-users), with port, passive range and the
#     certificate hostname
#   - the endpoint is read-only and scoped like the site itself
#   - the card says the same username and password serve both methods
#
# Pure source analysis: no box, no network, no DB.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_SVC=panel/agent/src/services/connection_info.rs
AGENT_ROUTE=panel/agent/src/routes/sftp.rs
AGENT_MOD=panel/agent/src/services/mod.rs
BACKEND=panel/backend/src/routes/sites.rs
BACKEND_ROUTES=panel/backend/src/routes/mod.rs
FRONTEND=panel/frontend/src/pages/SiteDetail.tsx
COMPONENT=panel/frontend/src/components/SiteConnectionMethods.tsx

for f in "$AGENT_SVC" "$AGENT_ROUTE" "$AGENT_MOD" "$BACKEND" "$BACKEND_ROUTES" "$FRONTEND" "$COMPONENT"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

code() { sed 's://.*$::' "$1"; }
flat() { code "$1" | tr -d ' \t\n'; }

must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc - pattern not found (whitespace-insensitive): $needle" ;;
  esac
}
must_not_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) bad "$desc - forbidden pattern present: $needle" ;;
    *) ok "$desc" ;;
  esac
}

SVC_FLAT=$(flat "$AGENT_SVC")
ROUTE_FLAT=$(flat "$AGENT_ROUTE")
BACKEND_ROUTES_FLAT=$(flat "$BACKEND_ROUTES")
COMP_FLAT=$(flat "$COMPONENT")

echo "── A: the agent reads the effective sshd config for the account ──"
must_contain "$(flat "$AGENT_MOD")" 'pub mod connection_info;' "connection_info is a registered agent service"
must_contain "$SVC_FLAT" 'safe_command("sshd").args(["-T", "-C", &spec])' \
  "SFTP facts come from 'sshd -T -C <spec>' (effective config, Match blocks included)"
must_contain "$SVC_FLAT" 'sftp_accounts::is_valid_custom_username(username)' \
  "the username is validated before it is put into the -C connection spec"
must_contain "$SVC_FLAT" 'format!("user={username},host={PROBE_HOST},addr={PROBE_ADDR}")' \
  "the -C spec carries user, host and addr"
case "$SVC_FLAT" in
  *'PROBE_ADDR:&str="127.'*|*'PROBE_ADDR:&str="::1"'*) bad "the sshd probe address is loopback - a Match Address 127.0.0.1 block would skew the answer" ;;
  *'PROBE_ADDR:&str="'*) ok "the sshd probe address is not loopback" ;;
  *) bad "PROBE_ADDR not found in $AGENT_SVC" ;;
esac
must_contain "$SVC_FLAT" 'yes("passwordauthentication")' "passwordauthentication is read from sshd -T"
must_contain "$SVC_FLAT" '"authenticationmethods"' "AuthenticationMethods can still demand a key and is read"
must_contain "$SVC_FLAT" '"password_login": null,' "a failed sshd -T reports password_login: null (unknown), not true"

echo
echo "── B: FTPS facts come from vsftpd's own files ──"
must_contain "$SVC_FLAT" 'ftp::whitelist().iter().any(|u| u == username)' \
  "FTPS 'allowed' is the account's presence in the allow-list file"
must_contain "$SVC_FLAT" 'port("listen_port", ftp::CONTROL_PORT)' "the FTPS control port honours listen_port, 21 by default"
must_contain "$SVC_FLAT" 'port("pasv_min_port", ftp::PASV_MIN)' "the passive range is read from vsftpd.conf"
must_contain "$SVC_FLAT" 'ftp::conf_value(&conf, "rsa_cert_file")' "the certificate is the one vsftpd.conf actually points at"
must_contain "$SVC_FLAT" '"cert_hostname": cert_names.first()' "the certificate hostname is reported"

echo
echo "── C: the agent endpoint is read-only ──"
must_contain "$ROUTE_FLAT" '.route("/sftp/sites/{domain}/access-info", get(access_info))' \
  "agent route GET /sftp/sites/{domain}/access-info is registered"
for w in 'std::fs::write' 'usermod' 'systemctl' 'remove_file' 'set_permissions'; do
  must_not_contain "$SVC_FLAT" "$w" "connection_info.rs never calls $w"
done

echo
echo "── D: the backend endpoint is scoped like the site and claims nothing it does not know ──"
must_contain "$BACKEND_ROUTES_FLAT" '.route("/api/sites/{id}/access-info", get(sites::sftp_access_info))' \
  "backend route GET /api/sites/{id}/access-info is registered"
HANDLER=$(awk '/^pub async fn sftp_access_info\(/{f=1} f{print} f&&/^}/{exit}' "$BACKEND" | sed 's://.*$::' | tr -d ' \t\n')
if [ -z "$HANDLER" ]; then
  bad "could not extract sftp_access_info from sites.rs"
else
  ok "sftp_access_info handler extracted"
  must_contain "$HANDLER" 'SITE_FOR_CALLER_ALL' "the handler loads the site with the caller's own visibility"
  must_contain "$HANDLER" 'sftp_account_name(&site)' "the account name is the one the backend uses everywhere"
  must_contain "$HANDLER" 'urlencoding::encode(&username)' "the username is URL-encoded into the agent query"
  must_contain "$HANDLER" 'AgentError::Status(404,_))=>Ok(Json(access_info_unknown(&username)))' \
    "an agent without the route answers 'unknown', not an error and not a guess"
  must_not_contain "$HANDLER" 'UPDATEsites' "the handler writes nothing"
fi
UNKNOWN=$(awk '/fn access_info_unknown\(/{f=1} f{print} f&&/^}/{exit}' "$BACKEND" | tr -d ' \t\n')
must_contain "$UNKNOWN" '"password_login":null' "the old-agent answer has password_login: null"

echo
echo "── E: the card lists each method with real details ──"
SFTP_CARD=$(awk '/\{\/\* SFTP Access \*\/\}/{f=1} f{print} f&&/\{\/\* WAF \(ModSecurity\) \*\/\}/{exit}' "$FRONTEND")
if [ -z "$SFTP_CARD" ]; then
  bad "could not extract the SFTP Access card from SiteDetail.tsx - markers moved or were renamed"
else
  ok "SFTP Access card block extracted"
fi
CARD_FLAT=$(printf '%s' "$SFTP_CARD" | tr -d ' \t\n')
must_not_contain "$CARD_FLAT" '{site.domain} / 22' "the card no longer hardcodes '<domain> / 22'"
must_not_contain "$CARD_FLAT" 'Host / Port' "the card no longer has a single 'Host / Port' field"
must_not_contain "$CARD_FLAT" 'window.location.hostname' "the card does not guess the FTP host from the browser URL"
must_contain "$CARD_FLAT" '<SiteConnectionMethods' "the card renders the connection methods component"
must_contain "$CARD_FLAT" 'siteAccess.refresh();' "the FTP toggle re-reads the access facts"
must_contain "$(flat "$FRONTEND")" 'useSiteAccessInfo(id, site?.status === "active" && site?.sftp_enabled === true)' \
  "the access facts are fetched for every role that sees an SFTP-enabled site (not admin-only)"
must_contain "$COMP_FLAT" '`/sites/${siteId}/access-info`' "the component reads the backend endpoint"
must_contain "$COMP_FLAT" 'const showFtps = ftps?.installed === true && ftps.allowed === true;' \
  "FTPS is shown only when vsftpd is installed and the account is on the allow-list"
must_contain "$COMP_FLAT" 'FTP with explicit TLS (FTPS)' "FTPS protocol is named"
must_contain "$COMP_FLAT" 'Passive ports' "the passive port range is shown"
must_contain "$COMP_FLAT" '{certHost ?? "unknown"}' "the certificate hostname is shown"
must_contain "$COMP_FLAT" 'FileZilla asks you to trust it' "a certificate for another name is explained"
must_contain "$COMP_FLAT" 'SFTP (SSH)' "SFTP protocol is named"
must_contain "$COMP_FLAT" 'if (passwordLogin === false) return "No - key only";' "a key-only server says 'key only'"
must_contain "$COMP_FLAT" 'return "Unknown";' "an unknown policy is shown as unknown"
must_not_contain "$COMP_FLAT" 'password_login ?? true' "unknown is never defaulted to 'password works'"
must_contain "$COMP_FLAT" 'The same username and password (from Reset Password) are used for every connection method below.' \
  "the card states one username and password for both methods"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
