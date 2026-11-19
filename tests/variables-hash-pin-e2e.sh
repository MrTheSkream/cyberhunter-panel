#!/usr/bin/env bash
# Regression pins for the variables_hash failure seen on rc.4 (Ubuntu 24.04,
# nginx 1.24): creating the proxied site casinosbelges.apps.bastiencordier.pro
# answered 400 with "could not build variables_hash, you should increase
# variables_hash_bucket_size: 64".
#
# The per-site Permissions-Policy variable copied the domain into its name, and
# a name past ~46 characters no longer fits a 64-byte bucket. The agent now
# names it ch_sec_pp_ + 16 hex characters of the domain's sha256 (unit tested in
# services/vhost_extras.rs). A vhost written before keeps the old name until it
# is rebuilt, so setup.sh and update.sh also raise the two sizes in conf.d, each
# one only when no other file sets it: a duplicate directive fails nginx -t.
#
# These run the real function out of setup.sh against a stub nginx that dumps
# and validates a throwaway conf.d. No real nginx is touched.
#
#   run: bash tests/variables-hash-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETUP="$REPO/scripts/setup.sh"
UPDATE="$REPO/scripts/update.sh"
UNINSTALL="$REPO/scripts/uninstall.sh"
AGENT="$REPO/panel/agent/src"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$3], got [$2])"; fi; }
has()  { if grep -qE -- "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }
code() { grep -vE '^[[:space:]]*(//|#)' "$1" 2>/dev/null; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"

# ── Stub nginx ───────────────────────────────────────────────────────────
# -T and -t read $STUB_DIR/nginx.conf then every conf.d/*.conf, the way the
# distro nginx.conf includes them. Either fails on a directive declared twice,
# like the real one. BROKEN=1 fails both for an unrelated reason;
# REJECT_OURS=1 fails them while the panel's file is present.
cat > "$BIN/nginx" <<'EOF'
#!/bin/bash
files=("$STUB_DIR/nginx.conf")
for f in "$STUB_DIR"/conf.d/*.conf; do [ -f "$f" ] && files+=("$f"); done
if [ "${BROKEN:-0}" = "1" ]; then
    echo 'nginx: [emerg] unknown directive "bogus" in /etc/nginx/nginx.conf:3' >&2; exit 1
fi
if [ "${REJECT_OURS:-0}" = "1" ] && [ -f "$STUB_DIR/conf.d/dockpanel-variables-hash.conf" ]; then
    echo 'nginx: [emerg] "variables_hash_max_size" directive invalid value' >&2; exit 1
fi
for d in variables_hash_bucket_size variables_hash_max_size; do
    n=$(sed 's/#.*//' "${files[@]}" | grep -cE "(^|[[:space:];{])$d[[:space:]]")
    if [ "$n" -gt 1 ]; then
        echo "nginx: [emerg] \"$d\" directive is duplicate" >&2; exit 1
    fi
done
if [ "$1" = "-T" ]; then
    for f in "${files[@]}"; do echo "# configuration file $f:"; cat "$f"; echo; done
fi
echo "nginx: configuration file test is successful" >&2
exit 0
EOF
chmod +x "$BIN/nginx"

# ── The code under test, lifted out of setup.sh ──────────────────────────
sed -n '/^ensure_nginx_variables_hash() {/,/^}/p' "$SETUP" > "$TMP/fn.sh"
if [ -s "$TMP/fn.sh" ]; then ok "setup.sh defines ensure_nginx_variables_hash"; else bad "setup.sh defines ensure_nginx_variables_hash"; fi
sed -n '/^ensure_nginx_variables_hash() {/,/^}/p' "$UPDATE" > "$TMP/fn-update.sh"
if [ -s "$TMP/fn-update.sh" ] && cmp -s "$TMP/fn.sh" "$TMP/fn-update.sh"; then
    ok "update.sh carries the very same function"
else
    bad "update.sh carries the very same function"
fi

# One scenario in a fresh conf.d, under update.sh's `set -euo pipefail`.
# Args: name, then files to pre-create as "name=content". Env passes through.
# Prints: rc, NGINX_VARHASH_CHANGED, the panel file (or ABSENT), the messages.
scenario() {
    local name="$1"; shift
    local dir="$TMP/$name"; mkdir -p "$dir/conf.d"
    printf 'http {\n    include %s/conf.d/*.conf;\n}\n' "$dir" > "$dir/nginx.conf"
    for kv in "$@"; do printf '%s\n' "${kv#*=}" > "$dir/conf.d/${kv%%=*}"; done
    (
        set -euo pipefail
        export STUB_DIR="$dir" PATH="$BIN:$PATH"
        log()  { echo "LOG $1"; }
        warn() { echo "WARN $1"; }
        # shellcheck disable=SC1090
        . "$TMP/fn.sh"
        ensure_nginx_variables_hash "$dir/conf.d" > "$dir/out" 2>&1
        echo "rc=$? changed=$NGINX_VARHASH_CHANGED" > "$dir/res"
    ) || echo "rc=aborted changed=?" > "$dir/res"
    DIR="$dir"
}
ours() { if [ -f "$DIR/conf.d/dockpanel-variables-hash.conf" ]; then grep -v '^#' "$DIR/conf.d/dockpanel-variables-hash.conf" | tr '\n' ' '; else echo ABSENT; fi; }
res()  { cat "$DIR/res"; }
said() { if grep -qE -- "$1" "$DIR/out"; then echo yes; else echo no; fi; }

echo "── nothing set anywhere: both sizes are written ──"
scenario fresh
check "it returns 0 and asks for a reload" "$(res)" "rc=0 changed=1"
check "the file holds both directives" "$(ours)" "variables_hash_bucket_size 128; variables_hash_max_size 2048; "
check "nginx -t passes afterwards" "$(STUB_DIR=$DIR "$BIN/nginx" -t 2>/dev/null && echo pass)" "pass"

echo
echo "── a second run changes nothing ──"
(
    set -euo pipefail
    export STUB_DIR="$DIR" PATH="$BIN:$PATH"
    log() { :; }; warn() { :; }
    . "$TMP/fn.sh"
    ensure_nginx_variables_hash "$DIR/conf.d"
    echo "rc=$? changed=$NGINX_VARHASH_CHANGED" > "$DIR/res"
)
check "no reload is asked" "$(res)" "rc=0 changed=0"
check "the file is unchanged" "$(ours)" "variables_hash_bucket_size 128; variables_hash_max_size 2048; "

echo
echo "── the operator's own 11-variables-hash.conf is respected ──"
scenario manual "11-variables-hash.conf=variables_hash_bucket_size 128;
variables_hash_max_size 2048;"
check "nothing is written" "$(ours)" "ABSENT"
check "it returns 0 without a reload" "$(res)" "rc=0 changed=0"
check "it says the sizes are set elsewhere" "$(said 'set elsewhere')" "yes"
check "nginx -t still passes (no duplicate)" "$(STUB_DIR=$DIR "$BIN/nginx" -t 2>/dev/null && echo pass)" "pass"

echo
echo "── each directive is decided on its own ──"
scenario only-bucket "11-variables-hash.conf=variables_hash_bucket_size 256;"
check "only the missing max_size is written" "$(ours)" "variables_hash_max_size 2048; "
check "nginx -t passes" "$(STUB_DIR=$DIR "$BIN/nginx" -t 2>/dev/null && echo pass)" "pass"
scenario only-max "11-variables-hash.conf=http_extra { variables_hash_max_size 4096; }"
check "only the missing bucket_size is written (directive after a brace counts)" "$(ours)" "variables_hash_bucket_size 128; "

echo
echo "── a commented directive does not count ──"
scenario commented "11-variables-hash.conf=# variables_hash_bucket_size 256;
#variables_hash_max_size 4096;"
check "both sizes are written" "$(ours)" "variables_hash_bucket_size 128; variables_hash_max_size 2048; "

echo
echo "── the operator adds a file after ours: ours steps aside ──"
scenario later "dockpanel-variables-hash.conf=variables_hash_bucket_size 128;
variables_hash_max_size 2048;" "11-variables-hash.conf=variables_hash_bucket_size 128;
variables_hash_max_size 2048;"
check "ours is removed" "$(ours)" "ABSENT"
check "a reload is asked" "$(res)" "rc=0 changed=1"
check "nginx -t passes again" "$(STUB_DIR=$DIR "$BIN/nginx" -t 2>/dev/null && echo pass)" "pass"

echo
echo "── nginx -t rejects the file: it is removed, the install goes on ──"
REJECT_OURS=1 scenario rejected
check "the file is gone" "$(ours)" "ABSENT"
check "it still returns 0" "$(res)" "rc=0 changed=0"
check "a clear message names the rejection" "$(said '^WARN nginx variables hash: nginx -t rejected')" "yes"

echo
echo "── a valid file is restored when its rewrite is rejected ──"
scenario restore "dockpanel-variables-hash.conf=variables_hash_bucket_size 128;"
# The run above rewrote it to both sizes. Put back a valid one-size file, then
# have nginx -t reject any new content.
printf 'variables_hash_bucket_size 128;\n' > "$DIR/conf.d/dockpanel-variables-hash.conf"
(
    set -euo pipefail
    export STUB_DIR="$DIR" PATH="$BIN:$PATH"
    log() { echo "LOG $1"; }; warn() { echo "WARN $1"; }
    . "$TMP/fn.sh"
    nginx() { if [ "$1" = "-t" ]; then echo "nginx: [emerg] rejected" >&2; return 1; fi; command nginx "$@"; }
    ensure_nginx_variables_hash "$DIR/conf.d" > "$DIR/out" 2>&1
    echo "rc=$? changed=$NGINX_VARHASH_CHANGED" > "$DIR/res"
) || echo "rc=aborted changed=?" > "$DIR/res"
check "the previous file is back" "$(ours)" "variables_hash_bucket_size 128; "
check "it returns 0" "$(res)" "rc=0 changed=0"
check "it says so" "$(said 'previous one restored')" "yes"
check "no .old file is left behind" "$(ls "$DIR/conf.d" | grep -c '\.old$')" "0"

echo
echo "── a configuration already broken elsewhere is left alone ──"
BROKEN=1 scenario broken
check "nothing is written" "$(ours)" "ABSENT"
check "it returns 0" "$(res)" "rc=0 changed=0"
check "it says the sizes were not checked" "$(said 'sizes not checked')" "yes"

echo
echo "── the scripts actually wire it up ──"
A=$(grep -n '^    set +e$' "$SETUP" | tail -1 | cut -d: -f1)
B=$(grep -n '^    ensure_nginx_variables_hash$' "$SETUP" | cut -d: -f1)
C=$(grep -n '^    configure_nginx$' "$SETUP" | cut -d: -f1)
if [ -n "$A" ] && [ -n "$B" ] && [ -n "$C" ] && [ "$A" -lt "$B" ] && [ "$B" -lt "$C" ]; then
    ok "setup.sh calls it under set +e, before configure_nginx's final nginx -t"
else
    bad "setup.sh calls it under set +e, before configure_nginx's final nginx -t"
fi
A=$(code "$UPDATE" | grep -n '^ensure_nginx_variables_hash$' | cut -d: -f1)
B=$(code "$UPDATE" | grep -n 'NGINX_NEEDS_RELOAD" = "1" ] || \[ "\$NGINX_NEEDS_RESTART' | head -1 | cut -d: -f1)
if [ -n "$A" ] && [ -n "$B" ] && [ "$A" -lt "$B" ]; then ok "update.sh calls it before its nginx reload"; else bad "update.sh calls it before its nginx reload"; fi
has "update.sh reloads nginx when the file changed" 'if \[ "\$NGINX_VARHASH_CHANGED" = "1" \]; then' "$UPDATE"
check "the function never swallows a failure with || true" "$(grep -c '|| true' "$TMP/fn.sh")" "0"
has "uninstall.sh takes the file away" 'VARHASH_CONF=/etc/nginx/conf\.d/dockpanel-variables-hash\.conf' "$UNINSTALL"
has "uninstall.sh keeps it when nginx -t still needs it" 'Kept \$VARHASH_CONF' "$UNINSTALL"

echo
echo "── the agent side ──"
VX="$AGENT/services/vhost_extras.rs"
has "the scripts and the agent share the file name" 'VARIABLES_HASH_FILE: &str = "dockpanel-variables-hash\.conf"' "$VX"
check "permissions_variable no longer copies the domain" "$(code "$VX" | grep -c "domain.replace(\['.', '-'\]")" "0"
has "permissions_variable hashes the domain" 'sha2::Sha256::digest\(domain\.as_bytes\(\)\)' "$VX"
for f in routes/iac.rs services/diagnostics.rs services/security_scanner.rs; do
    has "$f does not take the file for a site" 'VARIABLES_HASH_FILE' "$AGENT/$f"
done

echo
echo "══ $PASS passed, $FAIL failed ══"
[ "$FAIL" -eq 0 ]
