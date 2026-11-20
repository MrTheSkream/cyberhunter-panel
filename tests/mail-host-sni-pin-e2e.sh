#!/usr/bin/env bash
# mail-host-sni-pin-e2e.sh - conception/14 (certificats mail.<d> par SNI, port 465)
#
# Pins the seams of the per-domain mail host certificate:
#
#   a. the agent declares POST /mail/tls/issue and POST /mail/hestia/import-host-cert;
#   b. master.cf gains a `submissions` (465) block, implicit TLS and SASL-only;
#   c. the active-entry test on master.cf is EXACT: a bare
#      starts_with("submission") also matches `submissions`, so a box with 465
#      would never get 587 back (or the reverse);
#   d. Postfix presents the certificates through tls_server_sni_maps, built with
#      `postmap -F` (the .db embeds the files, so every renewal re-runs it);
#   e. Dovecot gets a `local_name` block per host;
#   f. files live under /etc/dockpanel/mail-tls/, never /etc/dockpanel/ssl/
#      (that tree is keyed by site name, listed and deleted by the SSL routes);
#   g. a migration adds host_cert_status with a CHECK on its vocabulary;
#   h. the auto-healer calls auto_renew_mail_host_certs;
#   i. the Hestia import INSTALLS the archive's certificate and runs no ACME;
#   j. provision_mail_host_cert (apex) takes issuance_lock;
#   k. the mail page calls host-cert/retry, with the D11 labels.
#
# Pure source analysis: no box, no network, no build.
#
# Every arm reads STRIPPED source (full-line comments out, and every file cut
# at its `#[cfg(test)]` module), so neither prose nor a test fixture can
# satisfy a pin that is about shipped code.
#
# NO PIPES INTO `grep -q` - under `set -o pipefail` grep -q closes the pipe on
# its first match and the arm goes red on correct code.
#
#   run: bash tests/mail-host-sni-pin-e2e.sh

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 - missing: $3" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1 - present but must not be: $3" ;; *) ok "$1" ;; esac; }

PY=$(command -v python3 || command -v python || true)
[ -n "$PY" ] || { echo "python3 is required"; exit 2; }
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8

AGENT_SRC=panel/agent/src
HEALER=panel/backend/src/services/auto_healer.rs
IMPORT=panel/backend/src/services/import_mail.rs
BACKEND_SRC=panel/backend/src
MIGS=panel/backend/migrations
FRONT_SRC=panel/frontend/src
MAILPAGE=panel/frontend/src/pages/Mail.tsx

for f in "$AGENT_SRC" "$HEALER" "$IMPORT" "$BACKEND_SRC" "$MIGS" "$MAILPAGE"; do
  [ -e "$f" ] || bad "MISSING SUBJECT: $f"
done

# Comments out, CODE INTACT; the test module cut off. Line comments first,
# then block comments, so a `/*` inside a line comment cannot swallow the file.
code() {
  perl -0777 -pe '
    s{^#\[cfg\(test\)\].*\z}{}ms;
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{^\s*--.*$}{}gm;
  ' "$1"
}
# Every .rs under a tree, stripped and concatenated: the agent side may land in
# routes/mail.rs or in a new module, and the pin must not care which.
tree_rs() {
  local f out=""
  while IFS= read -r f; do out+="$(code "$f")"$'\n'; done < <(find "$1" -name '*.rs' -type f | sort)
  printf '%s' "$out"
}
flat() { printf '%s' "$1" | tr -d ' \n\\'; }

AG=$(tree_rs "$AGENT_SRC")
BE=$(tree_rs "$BACKEND_SRC")
HL=$(code "$HEALER" 2>/dev/null || true)
IM=$(code "$IMPORT" 2>/dev/null || true)
FE=$(code "$MAILPAGE" 2>/dev/null || true)
[ -n "$AG" ] || bad "agent sources stripped to nothing"
[ -n "$HL" ] || bad "auto_healer.rs stripped to nothing"
[ -n "$IM" ] || bad "import_mail.rs stripped to nothing"
[ -n "$FE" ] || bad "Mail.tsx stripped to nothing"

# Python helper: reads the subject on stdin, exits 0 when the check holds.
pycheck() { "$PY" -c "$1" "${@:2}"; }

echo "── a. agent routes ──"
has "a1 agent declares /mail/tls/issue" "$AG" '"/mail/tls/issue"'
has "a2 agent declares /mail/hestia/import-host-cert" "$AG" '"/mail/hestia/import-host-cert"'

echo "── b. master.cf submissions (465) block ──"
# Some occurrence of `submissions` followed by `inet` must carry, within the
# same block, implicit TLS and SASL-only recipients.
if printf '%s' "$AG" | pycheck '
import re, sys
s = sys.stdin.read()
# The block is rendered from a service-name parameter (`submissions`, or `465`
# when /etc/services lacks the name), so accept `{service} inet` too, provided
# the source picks `submissions` / `465` for it.
if not re.search(r"\"submissions\"\s*\}?\s*else\s*\{\s*\"465\"", s) and not re.search(r"submissions\s+inet", s):
    sys.exit(1)
for m in re.finditer(r"(?:submissions|\{service\})\s+inet", s):
    w = s[m.start():m.start() + 1500]
    # The next master.cf entry ends the block, whether the source breaks the
    # line for real or with an escaped \n inside a Rust literal.
    nxt = re.search(r"(?:\n|\\n)\s*(submission|smtp|pickup|cleanup)\s+inet", w[20:])
    if nxt: w = w[:20 + nxt.start()]
    if "smtpd_tls_wrappermode=yes" in w and "permit_sasl_authenticated,reject" in w:
        sys.exit(0)
sys.exit(1)'; then
  ok "b1 a submissions inet block sets smtpd_tls_wrappermode=yes and permit_sasl_authenticated,reject"
else
  bad "b1 no submissions inet block with smtpd_tls_wrappermode=yes + permit_sasl_authenticated,reject"
fi

echo "── c. exact detection of submission vs submissions ──"
hasnt "c1 no bare starts_with(\"submission\") on master.cf lines" "$(flat "$AG")" 'starts_with("submission")'

echo "── d. Postfix SNI ──"
has "d1 agent writes tls_server_sni_maps" "$AG" 'tls_server_sni_maps'
if printf '%s' "$AG" | pycheck '
import re, sys
s = sys.stdin.read()
ok = "postmap -F" in s or re.search(r"\"postmap\".{0,300}?\"-F\"", s, re.S)
sys.exit(0 if ok else 1)'; then
  ok "d2 the SNI table is built with postmap -F"
else
  bad "d2 postmap -F missing (the .db must embed the files)"
fi

echo "── e. Dovecot SNI ──"
# `local_name` alone also matches `is_valid_local_name` (local_db.rs): the pin
# wants the Dovecot block, `local_name <host> {` followed by an ssl_cert.
if printf '%s' "$AG" | pycheck '
import re, sys
s = sys.stdin.read()
for m in re.finditer(r"(?<![A-Za-z0-9_])local_name\s+\S+\s*\{", s):
    if "ssl_cert" in s[m.end():m.end() + 600]:
        sys.exit(0)
sys.exit(1)'; then
  ok "e1 agent writes a Dovecot local_name <host> { ssl_cert ... } block"
else
  bad "e1 no Dovecot local_name <host> { ssl_cert ... } block in the agent"
fi

echo "── f. storage under /etc/dockpanel/mail-tls/ ──"
has "f1 files live under /etc/dockpanel/mail-tls/" "$AG" '/etc/dockpanel/mail-tls'
hasnt "f2 no mail host certificate under /etc/dockpanel/ssl/mail.*" "$AG" '/etc/dockpanel/ssl/mail.'
if printf '%s' "$AG" | pycheck '
import re, sys
s = sys.stdin.read()
# A literal naming the per-site tree next to the SNI table or the mail-tls
# vocabulary would mean the two stores are mixed.
for lit in re.findall(r"\"(?:[^\"\\]|\\.)*\"", s):
    if "/etc/dockpanel/ssl" in lit and ("tls_server_sni" in lit or "local_name" in lit or "mail-tls" in lit):
        sys.exit(1)
sys.exit(0)'; then
  ok "f3 no SNI literal points into /etc/dockpanel/ssl"
else
  bad "f3 a SNI literal points into /etc/dockpanel/ssl"
fi

echo "── g. migration ──"
MIGFILE=$(grep -l 'host_cert_status' "$MIGS"/*.sql 2>/dev/null | head -1 || true)
if [ -z "$MIGFILE" ]; then
  bad "g1 no migration adds host_cert_status"
else
  ok "g1 migration found: $MIGFILE"
  MG=$(flat "$(code "$MIGFILE")")
  has "g2 host_cert_status is NOT NULL DEFAULT 'none'" "$MG" "host_cert_statusTEXTNOTNULLDEFAULT'none'"
  has "g3 a CHECK guards the vocabulary" "$MG" 'CHECK'
  for v in none pending_dns active imported failed; do
    has "g4 the CHECK vocabulary names '$v'" "$MG" "'$v'"
  done
  for c in host_cert_expiry host_cert_checked_at host_cert_error; do
    has "g5 migration adds $c" "$MG" "$c"
  done
fi
# sqlx keys migrations by their numeric prefix: two files sharing one make the
# API refuse to start (VersionMismatch), measured in the VM recette.
DUPV=$(ls panel/backend/migrations/*.sql | sed -E 's#.*/([0-9]+)_.*#\1#' | sort | uniq -d | tr '\n' ' ')
if [ -z "$DUPV" ]; then ok "g6 every migration version is unique"; else bad "g6 duplicate migration version(s): $DUPV"; fi

echo "── h. auto-healer ──"
if printf '%s' "$HL" | pycheck '
import re, sys
s = sys.stdin.read()
calls = [m for m in re.finditer(r"auto_renew_mail_host_certs\s*\(", s)
         if not re.search(r"fn\s+$", s[max(0, m.start() - 8):m.start()])]
sys.exit(0 if calls else 1)'; then
  ok "h1 auto_healer.rs calls auto_renew_mail_host_certs"
else
  bad "h1 auto_renew_mail_host_certs is not called from auto_healer.rs"
fi

echo "── i. Hestia import installs, never issues ──"
has "i1 import_mail.rs calls /mail/hestia/import-host-cert" "$IM" '"/mail/hestia/import-host-cert"'
hasnt "i2 import_mail.rs never calls /mail/tls/issue (no ACME at import)" "$IM" '/mail/tls/issue'
hasnt "i3 import_mail.rs never calls /ssl/provision (no ACME at import)" "$IM" '/ssl/provision'

echo "── j. issuance_lock on the apex certificate ──"
PMHC=$(printf '%s' "$BE" | pycheck '
import re, sys
s = sys.stdin.read()
m = re.search(r"^(?:pub(?:\(crate\))?\s+)?async\s+fn\s+provision_mail_host_cert\s*\(", s, re.M)
if not m: sys.exit(1)
rest = s[m.end():]
n = re.search(r"^(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s|^impl\s|^#\[", rest, re.M)
print(rest[:n.start()] if n else rest)' || true)
if [ -z "$PMHC" ]; then
  bad "j1 provision_mail_host_cert not found in the backend"
else
  ok "j1 provision_mail_host_cert found ($(wc -l <<< "$PMHC") lines)"
  has "j2 provision_mail_host_cert takes issuance_lock" "$PMHC" 'issuance_lock'
fi

echo "── k. frontend ──"
has "k1 the mail page calls host-cert/retry" "$FE" '/host-cert/retry'
has "k2 the domain type carries host_cert_status" "$FE" 'host_cert_status?: HostCertStatus'
has "k3 …host_cert_expiry" "$FE" 'host_cert_expiry?: string | null'
has "k4 …host_cert_error" "$FE" 'host_cert_error?: string | null'
has "k5 label: Active until <date>" "$FE" '`Active until ${date}`'
has "k6 label: Imported, until <date>" "$FE" '`Imported, until ${date}`'
has "k7 label: Waiting for DNS" "$FE" '"Waiting for DNS"'
has "k8 tooltip: mail.<d> does not point to this server yet" "$FE" '`${host} does not point to this server yet`'
has "k9 label: Failed: <message>" "$FE" '`Failed: ${'
has "k10 label: No certificate" "$FE" '"No certificate"'
has "k11 the Retry now button exists" "$FE" 'Retry now'
has "k12 Retry now hides on a certificate with more than 30 days left" "$FE" 'left <= 30'
BADGE=$(printf '%s' "$FE" | pycheck '
import sys
s = sys.stdin.read()
a = s.find("function HostCertBadge")
print(s[a:a + 3000] if a >= 0 else "")' || true)
if [ -n "$BADGE" ]; then
  hasnt "k13 no em dash in the mail.<d> badge" "$BADGE" '—'
else
  bad "k13 HostCertBadge not found"
fi

echo
printf 'PASS %d  FAIL %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
