#!/usr/bin/env bash
# Regression pins for s270 - the webmail and the spam filter nobody had driven.
#
# s268 drove Postfix/Dovecot/OpenDKIM on the RHEL family and stopped there.
# Driving the remaining two on a Rocky 9.8 box found that neither worked, and
# that the oldest un-root-caused defect on the books was a delivery problem
# rather than the bug everyone had been hunting.
#
#   W1  rspamd is NOT in EPEL. On a stock Rocky 9 with epel AND crb enabled,
#       `dnf install rspamd` answers "Unable to find a match: rspamd", so the
#       panel's Spam Filter button could never work on any RHEL box. Upstream
#       publishes an rpm repo; it must be added on the RPM family ONLY, because
#       Debian and Ubuntu package rspamd themselves and that path already works
#       (#95c - the fix for one family is the defect on the other).
#
#   W2  Even once installed, Postfix never consulted it - on EVERY family.
#       `rspamd_install` wired the milter by replacing the literal
#       `smtpd_milters = unix:opendkim/...`, which s268 stopped writing when it
#       moved OpenDKIM's milter to a loopback port. str::replace with an absent
#       needle returns the string unchanged, so main.cf was rewritten
#       byte-identical and the handler reported success. #96e, one ship later.
#
#   W3  s262's webmail fix reached NO existing box. The /webmail/ nginx
#       fragment is written only on the Install click, and update.sh carried a
#       hand-copied mirror frozen at the v2.10.1 shape - without the header
#       re-declaration - whose "heal" therefore WROTE the shape that makes
#       Roundcube render an empty inbox, and whose guard skipped every box that
#       already had sub_filter. Repaired by derivation: one generator in the
#       agent, reconciled at startup, and the shell mirror deleted.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Strip comments and the test module, so a pin can never be satisfied (or
# tripped) by prose describing the very thing it forbids.
code()  { sed '/#\[cfg(test)\]/q' "$1" | grep -vE '^[[:space:]]*(///|//!|//|\*|/\*)'; }
has()   { [ -n "$(code "$1" | grep -F -- "$2")" ]; }
hasre() { [ -n "$(code "$1" | grep -E -- "$2")" ]; }

# The same idea for shell: strip full-line `#` comments. Without this, the
# comment that explains WHY the mirror was deleted trips the pin forbidding
# the mirror - a pin matching prose about the thing it forbids, which is how
# this suite first went red against correct code.
shcode() { grep -vE '^[[:space:]]*#' "$1"; }

MAIL=panel/agent/src/routes/mail.rs
PKG=panel/agent/src/services/pkg.rs
MAIN=panel/agent/src/main.rs
UPDATE=scripts/update.sh

for f in "$MAIL" "$PKG" "$MAIN" "$UPDATE"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo "── 1. W2: the Rspamd milter is DERIVED, never matched as a literal ──"

# The heart of it. Any literal opendkim endpoint inside the rspamd wiring means
# the edit can be orphaned again by a change to OPENDKIM_MILTER.
if hasre "$MAIL" 'replace\(\s*$|\.replace\("smtpd_milters'; then
  bad "rspamd_install still string-replaces a literal smtpd_milters value - the s268→s270 defect"
else
  ok "no literal smtpd_milters replace remains"
fi

if has "$MAIL" "add_milter(&main_cf, RSPAMD_MILTER)"; then
  ok "rspamd_install derives the edit via add_milter"
else
  bad "rspamd_install no longer calls add_milter - how is the milter wired?"
fi

# A guard so the pins above cannot go vacuous if the function is renamed away.
if hasre "$MAIL" 'fn add_milter\('; then
  ok "add_milter exists"
else
  bad "add_milter is gone - the two pins above are now vacuous"
fi

# Anchored on the declaration's colon: a bare substring match stays satisfied
# by `const RSPAMD_MILTER_X`, which the negative sweep caught.
if hasre "$MAIL" 'const RSPAMD_MILTER:'; then
  ok "RSPAMD_MILTER is a named constant beside OPENDKIM_MILTER"
else
  bad "RSPAMD_MILTER constant missing - the endpoint is a magic string again"
fi

# The silent no-op is the actual defect: writing a file back unchanged and
# reporting success. Absent keys must reach the caller as an error.
if hasre "$MAIL" 'None => return Err'; then
  ok "a missing milter list is an error, not a silent no-op write"
else
  bad "add_milter returning None no longer fails the request - the silent path is back"
fi

if hasre "$MAIL" 'smtpd_milters = \{OPENDKIM_MILTER\}'; then
  ok "main.cf's milter lines are written from the OPENDKIM_MILTER constant"
else
  bad "the postfix template no longer interpolates OPENDKIM_MILTER"
fi

echo "── 2. W1: the Rspamd repo is added on the RPM family ONLY ──"

if has "$PKG" "Repo::Rspamd"; then
  ok "pkg.rs knows Repo::Rspamd"
else
  bad "Repo::Rspamd is gone - rspamd cannot be installed on RHEL"
fi

if has "$PKG" "rspamd.com/rpm-stable/centos-"; then
  ok "the upstream rpm repo is the one wired"
else
  bad "the rspamd repo URL changed or vanished"
fi

# The family gate is the #95c protection: Debian must not be routed through
# add_repo at all, or a probe failure there breaks the family that works.
if has "$MAIL" "PkgMgr::Rpm"; then
  ok "the repo add is gated on the RPM family explicitly"
else
  bad "the RPM-family gate is gone - a probe failure could add a repo on Debian"
fi

if hasre "$PKG" 'Repo::Rspamd => &\["/etc/yum.repos.d/rspamd.repo"\]'; then
  ok "remove_repo can clean up the rspamd repo (a half-added repo breaks every later transaction)"
else
  bad "Repo::Rspamd has no remove_repo path"
fi

echo "── 3. W3: ONE generator for the /webmail/ fragment, and it heals ──"

if hasre "$MAIL" 'fn webmail_nginx_block\('; then
  ok "webmail_nginx_block is the single source of the fragment"
else
  bad "webmail_nginx_block is gone - the pins below are vacuous"
fi

# The F8 invariant itself: without the re-declared header set the location
# inherits frame-ancestors 'none' and the inbox renders empty.
if has "$MAIL" "frame-ancestors 'self'"; then
  ok "the fragment re-declares framing as same-origin"
else
  bad "webmail inherits frame-ancestors 'none' - the inbox renders empty"
fi

if has "$MAIL" 'add_header X-Frame-Options \"SAMEORIGIN\"'; then
  ok "the fragment re-declares X-Frame-Options"
else
  bad "X-Frame-Options DENY is inherited again - the content frame is refused"
fi

if hasre "$MAIL" 'pub async fn heal_webmail_nginx\('; then
  ok "heal_webmail_nginx exists"
else
  bad "no heal function - a fix to the fragment reaches no existing install"
fi

if has "$MAIL" "heal_webmail_nginx" && has "$MAIN" "heal_webmail_nginx"; then
  ok "the heal runs at agent startup, so an upgrade is enough"
else
  bad "heal_webmail_nginx is never called from main.rs - it can never run"
fi

# Healing must never CREATE the fragment for someone who has no webmail.
if hasre "$MAIL" 'if !Path::new\(WEBMAIL_NGINX_CONF\)\.exists\(\)'; then
  ok "the heal is a no-op when webmail was never installed"
else
  bad "the heal no longer checks the fragment exists - it may install a proxy to nothing"
fi

echo "── 4. W3: the shell mirror is GONE, not merely updated ──"

# The mirror is the drift source. Correcting it would only reset the clock;
# deleting it is what closes the class (#96e - derivation, not correction).
if shcode "$UPDATE" | grep -cE '^[[:space:]]*location /webmail/' >/dev/null; then
  bad "update.sh spells out the /webmail/ fragment again - a second copy that will rot"
else
  ok "update.sh contains no copy of the fragment"
fi

if shcode "$UPDATE" | grep -cE 'sub_filter|proxy_redirect / /webmail/' >/dev/null; then
  bad "update.sh still carries fragment internals - the mirror is back"
else
  ok "update.sh carries no fragment internals"
fi

echo "── 5. W4: Roundcube dials the PANEL host, never the selected domain ──"
#
# W4  The mail page sent `{ domain: selectedDomain?.domain || "localhost" }`
#     and the agent wrote it verbatim into ROUNDCUBEMAIL_DEFAULT_HOST /
#     SMTP_SERVER. That apex has no certificate on the box (Postfix/Dovecot
#     present the panel's by default and mail.<d> ones by SNI only), so
#     Roundcube's peer verification failed every login: "Could not connect to
#     ssl://<apex>:993". `localhost` is the container itself. Webmail is
#     server-wide; its host is the panel's, gated on the panel certificate.

MAILPAGE=panel/frontend/src/pages/Mail.tsx
[ -f "$MAILPAGE" ] || { echo "missing source file: $MAILPAGE"; exit 1; }

if hasre "$MAIL" 'ROUNDCUBEMAIL_DEFAULT_HOST=ssl://\{mail_host\}' && hasre "$MAIL" 'ROUNDCUBEMAIL_SMTP_SERVER=tls://\{mail_host\}'; then
  ok "IMAP and SMTP hosts are both the resolved mail_host"
else
  bad "ROUNDCUBEMAIL_DEFAULT_HOST / SMTP_SERVER no longer use the resolved mail_host"
fi

if hasre "$MAIL" 'ssl://\{domain\}|tls://\{domain\}'; then
  bad "a Roundcube host is built from a client-sent domain again - the apex has no mail certificate"
else
  ok "no Roundcube host is built from {domain}"
fi

# One docker run, shared by install and heal: two copies drift (W3's lesson).
n_dh=$(code "$MAIL" | grep -cF 'ROUNDCUBEMAIL_DEFAULT_HOST=ssl://')
if [ "$n_dh" -eq 1 ]; then
  ok "ROUNDCUBEMAIL_DEFAULT_HOST is spelled exactly once (deploy_roundcube)"
else
  bad "ROUNDCUBEMAIL_DEFAULT_HOST spelled $n_dh times - the install and the heal can drift"
fi

if hasre "$MAIL" 'fn webmail_mail_host\(' && has "$MAIL" 'panel_tls_paths().is_some()'; then
  ok "the host is the panel's, gated on its certificate actually existing"
else
  bad "webmail_mail_host is gone or no longer checks panel_tls_paths - a server_name alone proves no certificate"
fi

if has "$MAIL" 'Webmail needs the panel served on a hostname' && hasre "$MAIL" 'let Some\(mail_host\) = resolve_webmail_mail_host\(\) else'; then
  ok "no verifiable host refuses the install instead of deploying a webmail nobody can log in to"
else
  bad "the install no longer refuses when there is no verifiable host"
fi

if hasre "$MAIL" 'pub async fn heal_webmail_host\(' && has "$MAIN" "heal_webmail_host"; then
  ok "existing installs are healed onto the panel host at agent startup"
else
  bad "heal_webmail_host is gone or never called from main.rs - the fix reaches no existing install"
fi

# A recreate without the db bind mount erases identities and contacts.
if has "$MAIL" 'm == ROUNDCUBE_DB_MOUNT' && has "$MAIL" 'WebmailHostHeal::FlagOnly =>'; then
  ok "the heal recreates only a container whose database is bind-mounted, flags otherwise"
else
  bad "the heal no longer checks the database bind mount before docker rm"
fi

if has "$MAIL" '"mail_host_ok": mail_host_ok'; then
  ok "status reports whether Roundcube dials the expected host"
else
  bad "webmail status no longer reports mail_host_ok"
fi

if hasre "$MAILPAGE" 'selectedDomain\?\.domain \|\| "localhost"|webmail/install", \{ domain'; then
  bad "Mail.tsx sends the selected domain to the webmail install again"
else
  ok "Mail.tsx sends no domain to the webmail install"
fi

if has "$MAILPAGE" 'webmail.mail_host_ok === false'; then
  ok "the webmail card flags a wrong host and offers a reinstall"
else
  bad "the webmail card no longer shows a wrong IMAP/SMTP host"
fi

echo
printf 'webmail/spam pins:\033[0;32m%d passed\033[0m, ' "$PASS"
if [ "$FAIL" -gt 0 ]; then
  printf '\033[0;31m%d failed\033[0m\n' "$FAIL"
  exit 1
fi
printf '0 failed\n'
exit 0
