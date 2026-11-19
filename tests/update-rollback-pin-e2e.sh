#!/usr/bin/env bash
#
# CyberHunter - Panel - pins for the two update-subsystem defects closed at s282.
#
# 1. RESTORE (s231): a failure in a post-commit stage must not restart the
#    still-installed NEWER dockpanel-api on top of a database that has just been
#    reverted. It used to: `database-verify` and `record-rollback` both run after
#    the restore transaction commits and before the binaries are swapped back, so
#    a `fail` in either tripped the exit trap, the trap restarted the api
#    unconditionally, and that api migrated the reverted database forward again -
#    quietly undoing the rollback it was reporting as FAILED.
#
# 2. UPDATE (F1): `update.sh` re-execs itself into a transient unit with
#    `exec systemd-run` and no `--wait`, so the child the orchestrator waits on
#    exits 0 within milliseconds while the real update runs for minutes. Nothing
#    may promote that zero into "the update worked", and a run that fails before
#    the api is stopped has to leave a verdict behind, because no restart will
#    ever come to carry one.
#
# Part 1 DRIVES restore-snapshot.sh end to end against a scratch tree with
# stubbed systemctl/docker/curl - the guard decides whether to leave a panel
# down, and a guard that has never been executed is a comment. Part 2 is source
# analysis over CODE ONLY: it strips comments from both subjects and reads the
# Rust one as production code, because a claim about behaviour that a paragraph
# of prose can satisfy is not a claim (s338). Its own arms are mutation-tested
# on every run - commented out for the positive ones, and the real defect
# planted for each negative one, which is the direction that fails quietly.
# Neither part needs a box, a network or a build.
#
# Usage:   bash tests/update-rollback-pin-e2e.sh
#          KEEP=1 bash tests/update-rollback-pin-e2e.sh   # keep the scratch tree
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Overridable so the suite can be re-run against an older tree to prove it
# actually asserts something. A green run is indistinguishable from a suite that
# checks nothing; the evidence is the failure count against the code the fix
# replaced (lesson #109c).
RESTORE_SH="${RESTORE_SH:-$REPO_ROOT/scripts/restore-snapshot.sh}"
UPDATE_SH="${UPDATE_SH:-$REPO_ROOT/scripts/update.sh}"
ORCHESTRATOR="${ORCHESTRATOR:-$REPO_ROOT/panel/backend/src/services/panel_update.rs}"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
chk() { if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

contains()     { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
assert_has()   { if contains "$2" "$3"; then ok "$1"; else bad "$1 - expected to find: $2"; fi; }
assert_lacks() { if contains "$2" "$3"; then bad "$1 - must NOT contain: $2"; else ok "$1"; fi; }

# ── the comment strippers, ABOVE every arm that needs them (s337) ────────────
#
# A check placed below the thing it must run before inherits that position as a
# defect even when the check itself is perfect - the s336 lesson, and the reason
# these functions sit here rather than next to the source arms in Part 2.
#
# The comment marker is chosen by EXTENSION, never guessed. Getting it wrong is
# not symmetric: over-stripping turns a positive arm loudly red, but turns a
# NEGATIVE arm (match ⇒ bad) silently green, which is the direction that ships.
comment_marker_for() {
  case "$1" in
    *.rs|*.mjs|*.js|*.ts|*.tsx)                echo '//' ;;
    *.json)                                    echo ''   ;;  # JSON has no comments
    *)                                         echo '#'  ;;  # .sh, .service, .gitignore, .toml
  esac
}

# BLANK the comment, do not delete it. An ordering arm below compares line
# numbers obtained from this stream against each other; a stripper that removes
# lines renumbers the file and would silently change what that arm measures.
code_lines() {
  local f="$1" m
  m=$(comment_marker_for "$f")
  if [ -z "$m" ]; then cat "$f"; return; fi
  if [ "$m" = '//' ]; then
    # A block comment is recognised ONLY where one is actually written: opening
    # at the start of a line and closing at the end of one. s294: a `/*` inside a
    # string literal (a Dockerfile's `COPY … /app/target/release/*`) opened a
    # comment that swallowed 485 lines of git_build.rs, and every ABSENCE arm
    # over it passed on code the stripper had merely removed.
    #
    # A trailing `//` is stripped, but only when the text before it has BALANCED
    # double quotes - otherwise `let u = "https://host"` would lose its tail.
    # Backslash escapes are skipped so `\"` does not flip the parity.
    awk '
      /^[[:space:]]*\/\*/ &&  /\*\/[[:space:]]*$/ { print ""; next }
      /^[[:space:]]*\/\*/                         { inblk = 1; print ""; next }
      inblk { if ($0 ~ /\*\/[[:space:]]*$/) inblk = 0; print ""; next }
      /^[[:space:]]*\/\//                         { print ""; next }
      {
        line = $0; out = line; n = length(line); q = 0; i = 1
        while (i <= n) {
          c = substr(line, i, 1)
          if (c == "\\") { i += 2; continue }
          if (c == "\"") { q = 1 - q; i++; continue }
          if (q == 0 && c == "/" && substr(line, i + 1, 1) == "/") { out = substr(line, 1, i - 1); break }
          i++
        }
        print out
      }
    ' "$f"
  else
    # Shell keeps to FULL-LINE comments only, and the asymmetry with `//` above is
    # deliberate. A trailing `#` cannot be stripped safely here: `${VAR#prefix}`,
    # `$#`, a colour literal and `sed 's/#//'` are all ordinary code. The
    # convention in this tree is that explanation goes on its own line, and §2c
    # asserts the stripper leaves a `#` inside a string alone.
    awk '/^[[:space:]]*#/ { print ""; next } { print }' "$f"
  fi
}

# Counted, never `grep -q`, and the reason is a trap this suite walked straight
# into twice. Under `set -o pipefail`, `code_lines f | grep -q PATTERN` reports
# FAILURE on a successful match: grep -q exits at the first hit, the producer
# upstream dies of SIGPIPE (141), and pipefail takes the pipeline's status from
# it. The effect is silent and selective - a file whose match is near the top gets
# dropped while one whose match is near the bottom survives, because the producer
# had already finished. `grep -c` consumes all of its input, so there is no early
# exit and no signal. (s336 #365 is the same operator lying in the other
# direction: a failed PRODUCER read as a clean no-match.)
code_count() { local f="$1"; shift; code_lines "$f" | grep -c "$@" 2>/dev/null || true; }
has_code()   { local f="$1"; shift; [ "$(code_count "$f" "$@")" -gt 0 ]; }

# True file line numbers, because code_lines blanks rather than deletes.
code_lineno() { local f="$1"; shift; code_lines "$f" | grep -n "$@" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# ── one addition to the set, for a second kind of blindness ──────────────────
# The orchestrator's unit-test module quotes, in its own assertions, the very
# filename the arms below look for. An arm that reads the whole file is
# therefore satisfied BY THE TESTS even when the production constant has been
# retargeted at something else entirely - measured against this suite at s338,
# with nothing commented out at all. So the Rust subject is read as production
# code: comments stripped as above, then everything from the test attribute to
# EOF blanked. Height is preserved here too, for the same reason.
prod_lines() {
  code_lines "$1" | awk '
    /^[[:space:]]*#\[cfg\(test\)\]/ { intest = 1 }
    intest                          { print ""; next }
                                    { print }'
}
prod_count() { local f="$1"; shift; prod_lines "$f" | grep -c "$@" 2>/dev/null || true; }
has_prod()   { local f="$1"; shift; [ "$(prod_count "$f" "$@")" -gt 0 ]; }

# The source arms in Part 2 are written through these four, so that no arm can
# quietly go back to reading raw text: the file is named, never `cat`ed.
pin_code()    { local l="$1" f="$2"; shift 2
                if has_code "$f" "$@"; then ok "$l"; else bad "$l - expected to find in CODE: $*"; fi; }
pin_no_code() { local l="$1" f="$2"; shift 2
                if has_code "$f" "$@"; then bad "$l - must NOT appear in CODE: $*"; else ok "$l"; fi; }
pin_prod()    { local l="$1" f="$2"; shift 2
                if has_prod "$f" "$@"; then ok "$l"; else bad "$l - expected to find in PRODUCTION code: $*"; fi; }
pin_no_prod() { local l="$1" f="$2"; shift 2
                if has_prod "$f" "$@"; then bad "$l - must NOT appear in PRODUCTION code: $*"; else ok "$l"; fi; }

SCRATCH="$(mktemp -d /tmp/dp-rollback-pin.XXXXXX)"
cleanup() { [ -n "${KEEP:-}" ] || rm -rf "$SCRATCH"; }
trap cleanup EXIT

# ── Stub environment ─────────────────────────────────────────────────────────
# systemctl records what it was asked to do - that log IS the assertion for
# "was the api restarted". docker fakes postgres. curl fakes /api/health.
STUBS="$SCRATCH/stubs"
mkdir -p "$STUBS"

# Three knobs, each for one scenario: nginx running or not, its reload failing,
# and the agent refusing to start (from the exit trap). Everything else succeeds.
cat > "$STUBS/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_ACTIONS"
case "$*" in
    "is-active --quiet nginx") exit "${STUB_NGINX_ACTIVE_RC:-0}" ;;
    "reload nginx")            exit "${STUB_NGINX_RELOAD_RC:-0}" ;;
    "start dockpanel-agent")   exit "${STUB_AGENT_START_RC:-0}" ;;
    "stop dockpanel-api")      exit "${STUB_API_STOP_RC:-0}" ;;
    "is-active --quiet dockpanel-api") exit "${STUB_API_ACTIVE_RC:-3}" ;;
esac
exit 0
EOF

# Always present, so a box that has a real nginx never has it tested by this
# suite, and a container without one still reaches the reload branch.
cat > "$STUBS/nginx" <<'EOF'
#!/usr/bin/env bash
echo "nginx $*" >> "$STUB_ACTIONS"
if [ "${STUB_NGINX_T_RC:-0}" != "0" ]; then
    echo 'nginx: [emerg] cannot load certificate "/etc/dockpanel/ssl/example.test/fullchain.pem"' >&2
    echo 'nginx: configuration file /etc/nginx/nginx.conf test failed' >&2
    exit "$STUB_NGINX_T_RC"
fi
echo 'nginx: configuration file /etc/nginx/nginx.conf test is successful' >&2
exit 0
EOF

cat > "$STUBS/systemd-cat" <<'EOF'
#!/usr/bin/env bash
cat > /dev/null
EOF

cat > "$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
echo '{"status":"ok"}'
exit 0
EOF

# The docker stub only has to answer the four things the restore asks postgres.
# Each scenario steers it with STUB_* variables.
cat > "$STUBS/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$STUB_ACTIONS"
args="$*"
case "$args" in
    *pg_isready*)
        exit 0 ;;
    *pg_dump*)
        # The pre-rollback capture.
        echo "-- pre-rollback dump"
        exit 0 ;;
    *"INSERT INTO panel_snapshots"*)
        exit "${STUB_RECORD_RC:-0}" ;;
    *"INSERT INTO activity_logs"*)
        exit "${STUB_JOURNAL_RC:-0}" ;;
    *"information_schema.tables"*)
        echo "${STUB_VERIFY_COUNT:-3}"
        exit "${STUB_VERIFY_RC:-0}" ;;
    *psql*)
        # The restore itself: consume the stream it is fed.
        cat > /dev/null
        exit "${STUB_PSQL_RC:-0}" ;;
esac
exit 0
EOF

chmod +x "$STUBS"/*

# ── Build a snapshot tarball ─────────────────────────────────────────────────
# `with_api=no` produces the snapshot-carries-no-api case, which reaches the
# hazard window on the SUCCESS path with nothing having failed at all.
make_snapshot() {
    local dir="$1" with_api="${2:-yes}"
    rm -rf "$dir"; mkdir -p "$dir/src/binaries" "$dir/src/db" "$dir/src/etc"

    printf 'OLD-API\n'   > "$dir/src/binaries/dockpanel-api"
    printf 'OLD-AGENT\n' > "$dir/src/binaries/dockpanel-agent"
    printf 'OLD-CLI\n'   > "$dir/src/binaries/dockpanel"
    [ "$with_api" = "yes" ] || rm -f "$dir/src/binaries/dockpanel-api"
    # Older snapshots carry neither of these (SNAP_LEGACY).
    if [ -z "${SNAP_LEGACY:-}" ]; then
        printf 'OLD-MCP\n' > "$dir/src/binaries/dockpanel-mcp"
        mkdir -p "$dir/src/frontend/dist"
        printf 'OLD-UI\n' > "$dir/src/frontend/dist/index.html"
    fi
    printf 'OLD-ENV\n' > "$dir/src/etc/api.env"
    # The update source as it was when the snapshot was taken (S7).
    if [ -n "${SNAP_UPDATE_SOURCE:-}" ]; then
        printf 'OLD-TOKEN\n' > "$dir/src/etc/update-token"
        printf 'OLD-TOKEN\n' > "$dir/src/etc/.update-token.tmp-1"
        printf 'UPDATE_REPO=old/repo\n' > "$dir/src/etc/update.conf"
    fi

    {
        echo "CREATE TABLE a (id int);"
        echo "CREATE TABLE b (id int);"
        echo "CREATE TABLE c (id int);"
        echo "-- PostgreSQL database dump complete"
    } > "$dir/src/db/dump.sql"
    gzip -c "$dir/src/db/dump.sql" > "$dir/src/db/dump.sql.gz"
    rm -f "$dir/src/db/dump.sql"

    cat > "$dir/src/metadata.json" <<'JSON'
{"from_version":"2.47.3","trigger":"pre-update:2.48.0","created_at":"2026-07-28T10:00:00Z"}
JSON

    tar -C "$dir/src" -czf "$dir/snap.tar.gz" .
}

# Run the restore against a throwaway tree.
#
# Sets the globals RC / RES_JSON / ACTIONS / BIN_DIR_OUT rather than echoing the
# exit code: `run_restore …` runs the function in a SUBSHELL, so every
# variable it set vanished and each caller read an unbound one. Assigning
# globals directly is the whole reason this is not a command substitution.
run_restore() {
    local name="$1"; shift
    local with_api="${1:-yes}"; shift || true

    local base="$SCRATCH/$name"
    make_snapshot "$base" "$with_api"
    mkdir -p "$base/state" "$base/bin" "$base/etc"

    # What is installed right now: the NEWER build the operator is rolling away
    # from. If it is still here at the end, the rollback did not happen.
    printf 'NEW-API\n'   > "$base/bin/dockpanel-api"
    printf 'NEW-AGENT\n' > "$base/bin/dockpanel-agent"
    printf 'NEW-CLI\n'   > "$base/bin/dockpanel"
    printf 'NEW-MCP\n'   > "$base/bin/dockpanel-mcp"
    mkdir -p "$base/frontend/dist"
    printf 'NEW-UI\n'    > "$base/frontend/dist/index.html"
    printf 'stale\n'     > "$base/frontend/dist/only-in-new.js"
    # The update source as configured right now (S7): update.conf unless
    # NO_CUR_CONF is set, the token only when CUR_TOKEN is set - unset models
    # "the admin cleared it".
    if [ -n "${SNAP_UPDATE_SOURCE:-}" ]; then
        if [ -z "${NO_CUR_CONF:-}" ]; then
            printf 'UPDATE_REPO=new/repo\n' > "$base/etc/update.conf"
            chmod 0600 "$base/etc/update.conf"
        fi
        if [ -n "${CUR_TOKEN:-}" ]; then
            printf '%s\n' "$CUR_TOKEN" > "$base/etc/update-token"
            chmod 0600 "$base/etc/update-token"
        fi
    fi
    printf 'NEW-ENV\n'   > "$base/etc/api.env"

    ACTIONS="$base/actions.log"; : > "$ACTIONS"
    RES_JSON="$base/state/last-restore.json"
    BIN_DIR_OUT="$base/bin"

    local sha; sha="$(sha256sum "$base/snap.tar.gz" | awk '{print $1}')"

    # `env`, not a bare assignment prefix. The shell decides which words are
    # assignments SYNTACTICALLY, before expansion - so a `"$@"` that expands to
    # `STUB_RECORD_RC=1` is not an assignment, it becomes the COMMAND NAME, and
    # every scenario that passed an override silently ran nothing and exited 127.
    # `env` takes its VAR=VALUE arguments after expansion, which is the point.
    env PATH="$STUBS:$PATH" \
        STUB_ACTIONS="$ACTIONS" \
        DOCKPANEL_RESTORE_DETACHED=1 \
        DOCKPANEL_SNAPSHOT_ID="0000-$name" \
        DOCKPANEL_SNAPSHOT_TARBALL="$base/snap.tar.gz" \
        DOCKPANEL_SNAPSHOT_SHA256="$sha" \
        DOCKPANEL_STATE_DIR="$base/state" \
        DOCKPANEL_BIN_DIR="${BIN_DIR_OVERRIDE:-$base/bin}" \
        DOCKPANEL_ETC_DIR="$base/etc" \
        DOCKPANEL_FRONTEND_DIR="$base/frontend" \
        DOCKPANEL_HEALTH_URL="http://127.0.0.1:1/api/health" \
        "$@" \
        bash "$RESTORE_SH" > "$base/out.log" 2>&1
    RC=$?
}

echo
echo "══ Part 1 · the restore, driven end to end ══════════════════════════════"
echo
echo "S1 · a clean restore still restores, and still brings the panel back"
run_restore happy yes
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
J="$(cat "$RES_JSON" 2>/dev/null)"; A="$(cat "$ACTIONS" 2>/dev/null)"
assert_has "verdict is ok=true"                  '"ok":true'              "$J"
assert_has "stage is complete"                   '"stage":"complete"'     "$J"
assert_has "dockpanel-api was started"           'systemctl start dockpanel-api' "$A"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-api")" = "OLD-API" ] && echo 0 || echo 1)" \
    "the api binary was actually reverted to the snapshot's"
NGINX_T_AT="$(grep -n -m1 -x 'nginx -t' "$ACTIONS" | cut -d: -f1)"
RELOAD_AT="$(grep -n -m1 -x 'systemctl reload nginx' "$ACTIONS" | cut -d: -f1)"
chk "$([ -n "$NGINX_T_AT" ] && [ -n "$RELOAD_AT" ] && [ "$RELOAD_AT" -gt "$NGINX_T_AT" ] && echo 0 || echo 1)" \
    "nginx is reloaded after the restore, and only after nginx -t"

echo
echo "S1b · the MCP binary and the frontend go back with the rest"
run_restore full_set yes
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-mcp")" = "OLD-MCP" ] && echo 0 || echo 1)" \
    "dockpanel-mcp was reverted to the snapshot's"
chk "$([ "$(cat "$SCRATCH/full_set/frontend/dist/index.html")" = "OLD-UI" ] && echo 0 || echo 1)" \
    "the frontend was reverted to the snapshot's"
chk "$([ ! -e "$SCRATCH/full_set/frontend/dist/only-in-new.js" ] && echo 0 || echo 1)" \
    "a file only the newer frontend had is gone from the served directory"
assert_has "a running MCP service is restarted" 'systemctl try-restart dockpanel-mcp' "$(cat "$ACTIONS")"

SNAP_LEGACY=1 run_restore legacy_set yes
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a snapshot without them still restores"
assert_has "and its verdict is ok=true" '"ok":true' "$(cat "$RES_JSON")"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-mcp")" = "NEW-MCP" ] && echo 0 || echo 1)" \
    "the installed dockpanel-mcp is left alone when the snapshot has none"
chk "$([ "$(cat "$SCRATCH/legacy_set/frontend/dist/index.html")" = "NEW-UI" ] && echo 0 || echo 1)" \
    "the installed frontend is left alone when the snapshot has none"

echo
echo "S2 · the bookkeeping INSERT fails - the box must still end CONSISTENT"
run_restore record_fails yes STUB_RECORD_RC=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0 - the restore itself succeeded"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has "verdict is ok=false - there is something to read"  '"ok":false'      "$J"
assert_has "the detail names the bookkeeping failure"   'could not be recorded'  "$J"
assert_has "dockpanel-api WAS started (binaries match the database)" \
           'systemctl start dockpanel-api' "$A"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-api")" = "OLD-API" ] && echo 0 || echo 1)" \
    "the rollback completed rather than aborting mid-way"

echo
echo "S3 · the post-restore table count comes back short, and unreadable"
run_restore verify_short yes STUB_VERIFY_COUNT=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has "verdict is ok=false"                        '"ok":false'             "$J"
assert_has "the detail names the shortfall"             'expected >= 3'          "$J"
assert_has "dockpanel-api WAS started"     'systemctl start dockpanel-api'       "$A"

run_restore verify_junk yes STUB_VERIFY_COUNT=notanumber
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a NON-NUMERIC count does not abort the script either"
J="$(cat "$RES_JSON")"
assert_has "the unreadable count is reported, not raised" 'could not read a table count' "$J"

# Under pipefail a failing `docker exec` makes the count's assignment fail, and a
# bare failing assignment is an errexit abort - inside the post-commit window.
run_restore verify_docker_down yes STUB_VERIFY_RC=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a count query that FAILS does not abort the script either"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has "the failed count is reported, not raised" 'could not read a table count' "$J"
assert_has "and dockpanel-api WAS started"           'systemctl start dockpanel-api' "$A"

echo
echo "S4 · THE HAZARD · database reverted, api binary NOT - panel stays down"
run_restore no_api_in_snapshot no
chk "$([ "$RC" = "1" ] && echo 0 || echo 1)" "exits non-zero - this one needs an operator"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has "verdict is ok=false"                         '"ok":false'            "$J"
assert_has "the detail says the panel was left down ON PURPOSE" 'LEFT STOPPED'   "$J"
assert_has "the detail points at the pre-rollback dump"  'pre-rollback'          "$J"
assert_lacks "dockpanel-api was NOT started"   'systemctl start dockpanel-api'   "$A"
assert_has "the agent WAS started - the box stays reachable" \
           'systemctl start dockpanel-agent' "$A"

echo
echo "S5 · THE HAZARD · a hard failure in the binaries stage, same answer"
# The binary swap is made to fail AFTER the database has committed, so the script
# dies inside the window with nothing wrong with the database at all. This is the
# s231 shape exactly: the old exit trap restarted the api from here.
#
# The failure is injected by pointing BIN_DIR at a directory that does not exist,
# NOT by removing write permission - this suite runs as root on a box where the
# panel is installed, and root ignores the permission bits, so a chmod-based
# injection quietly produces a HAPPY PATH and the scenario asserts nothing.
BIN_DIR_OVERRIDE="$SCRATCH/binaries_fail/nonexistent-bin-dir" \
    run_restore binaries_fail yes
unset BIN_DIR_OVERRIDE
J="$(cat "$RES_JSON" 2>/dev/null)"; A="$(cat "$ACTIONS")"
chk "$([ "$RC" != "0" ] && echo 0 || echo 1)" "exits non-zero"
assert_has  "the binary swap is what failed"  'could not stage'                  "$J"
assert_has  "the detail says the panel was left down ON PURPOSE" 'LEFT STOPPED'  "$J"
assert_lacks "dockpanel-api was NOT started"  'systemctl start dockpanel-api'    "$A"

echo
echo "S6 · a failure BEFORE the commit must still bring the panel back"
# The guard has to be conditional. If it refused unconditionally it would turn
# every harmless early failure into a dark box - the s228 shape it must not
# reintroduce.
run_restore psql_fails yes STUB_PSQL_RC=3
chk "$([ "$RC" != "0" ] && echo 0 || echo 1)" "exits non-zero"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has  "the detail says nothing changed"   'nothing changed'                "$J"
assert_has  "dockpanel-api WAS restarted - nothing was lost, so nothing is held" \
            'systemctl start dockpanel-api' "$A"
assert_lacks "and it is NOT reported as left down" 'LEFT STOPPED'                "$J"
assert_lacks "and no rollback is journaled: the database never moved" \
            'INSERT INTO activity_logs' "$A"

# An api that will not stop must not have its database dropped under it. A stop
# that errors on a unit that is NOT running is only noted.
run_restore api_wont_stop yes STUB_API_STOP_RC=1 STUB_API_ACTIVE_RC=0
chk "$([ "$RC" != "0" ] && echo 0 || echo 1)" "an api that is still running after stop: exits non-zero"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has   "the detail says so, and that nothing changed" 'could not stop dockpanel-api - nothing changed' "$J"
assert_lacks "the database was never touched"     '--single-transaction'          "$A"
assert_has   "and the trap starts the api again"  'systemctl start dockpanel-api' "$A"
run_restore api_stop_errs_but_down yes STUB_API_STOP_RC=5 STUB_API_ACTIVE_RC=3
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a stop error on a unit that is not running: the restore goes on"
assert_has   "and its verdict is ok=true" '"ok":true' "$(cat "$RES_JSON")"

# The same early failure, with the agent refusing to come back from the trap:
# the api must still be tried, and the verdict must say what is still down.
run_restore trap_agent_fails yes STUB_PSQL_RC=3 STUB_AGENT_START_RC=1
chk "$([ "$RC" != "0" ] && echo 0 || echo 1)" "exits non-zero"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has  "dockpanel-api is still started after the agent fails" \
            'systemctl start dockpanel-api' "$A"
assert_has  "the verdict keeps the original failure"   'nothing changed'           "$J"
assert_has  "and says the agent is still down"         'dockpanel-agent could not be restarted' "$J"

echo
echo "S6b · a manual rollback is journaled as itself, after the database is back"
# The database restore erases every earlier entry, so only a row written after
# the commit can survive it, and only this script is still running by then: the
# api that boots next is the SNAPSHOT's binary, which may predate this code.
run_restore journal yes \
    DOCKPANEL_ROLLBACK_OPERATOR="o'brien@example.test" \
    DOCKPANEL_ROLLBACK_FROM_VERSION=2.48.0
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has  "the verdict stays ok=true"          '"ok":true'                     "$J"
assert_has  "it has an action of its own"        "'update.manual_rollback'"      "$A"
assert_has  "it names the snapshot"              '"snapshot_id":"0000-journal"'  "$A"
assert_has  "it names the version left"          '"from_version":"2.48.0"'       "$A"
assert_has  "it names the version restored"      '"to_version":"2.47.3"'         "$A"
assert_has  "it names the operator, SQL-quoted"  "o''brien@example.test"         "$A"
assert_has  "it says the rollback completed"     '"outcome":"completed"'         "$A"
assert_lacks "it does not borrow the update's motive" 'post-deploy health checks' "$A"
RESTORE_AT="$(grep -n -m1 -- '--single-transaction' "$ACTIONS" | cut -d: -f1)"
JOURNAL_AT="$(grep -n -m1 'INSERT INTO activity_logs' "$ACTIONS" | cut -d: -f1)"
chk "$([ -n "$RESTORE_AT" ] && [ -n "$JOURNAL_AT" ] && [ "$JOURNAL_AT" -gt "$RESTORE_AT" ] && echo 0 || echo 1)" \
    "the entry is written AFTER the database restore"
assert_has  "the snapshot row is closed, so the next boot does not report an update rollback" \
            "'2.47.3', '2.47.3'" "$A"

run_restore journal_anon yes
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has  "an unknown operator is said to be unknown" '"operator":"unknown"'   "$A"
assert_has  "and an unknown version too"                '"from_version":"unknown"' "$A"

echo
echo "S6c · a journal that cannot be written is reported, and undoes nothing"
run_restore journal_fails yes STUB_JOURNAL_RC=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0: the box is restored"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has  "the verdict is ok=false"            '"ok":false'                    "$J"
assert_has  "the detail names the journal"       'journal'                       "$J"
assert_has  "dockpanel-api WAS started"          'systemctl start dockpanel-api' "$A"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-api")" = "OLD-API" ] && echo 0 || echo 1)" \
    "the binaries are still the snapshot's"

echo
echo "S6d · a rollback that fails after the commit is journaled as failed"
BIN_DIR_OVERRIDE="$SCRATCH/journal_partial/nonexistent-bin-dir" \
    run_restore journal_partial yes DOCKPANEL_ROLLBACK_FROM_VERSION=2.48.0
chk "$([ "$RC" != "0" ] && echo 0 || echo 1)" "exits non-zero"
A="$(cat "$ACTIONS")"
assert_has  "the entry exists"                   "'update.manual_rollback'"      "$A"
assert_has  "and it does not claim success"      '"outcome":"failed at stage binaries"' "$A"

echo
echo "S7 · a restore leaves the CURRENT update source alone (token + update.conf)"
# The admin cleared a leaked token, then restored a snapshot taken while it was
# set: the token must stay gone. And a token set now must not be rewound.
SNAP_UPDATE_SOURCE=yes run_restore token_cleared yes
E="$SCRATCH/token_cleared/etc"
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
chk "$([ "$(cat "$E/api.env")" = "OLD-ENV" ] && echo 0 || echo 1)" \
    "the rest of /etc/dockpanel IS still restored"
chk "$([ ! -e "$E/update-token" ] && [ ! -L "$E/update-token" ] && echo 0 || echo 1)" \
    "a cleared token is NOT resurrected by the restore"
chk "$([ ! -e "$E/.update-token.tmp-1" ] && echo 0 || echo 1)" \
    "nor a leftover temporary copy of it"
chk "$([ "$(cat "$E/update.conf")" = "UPDATE_REPO=new/repo" ] && echo 0 || echo 1)" \
    "update.conf keeps its current content"
chk "$([ "$(stat -c %a "$E/update.conf")" = "600" ] && echo 0 || echo 1)" \
    "update.conf keeps mode 0600"

SNAP_UPDATE_SOURCE=yes NO_CUR_CONF=1 run_restore source_absent yes
E="$SCRATCH/source_absent/etc"
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
chk "$([ ! -e "$E/update.conf" ] && [ ! -e "$E/update-token" ] && echo 0 || echo 1)" \
    "no update source now - still none after the restore"

SNAP_UPDATE_SOURCE=yes CUR_TOKEN=NEW-TOKEN run_restore token_current yes
E="$SCRATCH/token_current/etc"
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "exits 0"
chk "$([ "$(cat "$E/update-token")" = "NEW-TOKEN" ] && echo 0 || echo 1)" \
    "a token set now keeps its current bytes"
chk "$([ "$(stat -c %a "$E/update-token")" = "600" ] && echo 0 || echo 1)" \
    "and its mode 0600"
chk "$([ "$(cat "$E/update.conf")" = "UPDATE_REPO=new/repo" ] && echo 0 || echo 1)" \
    "update.conf keeps its current content"

echo
echo "S8 · nginx picks up the restored certificates, and a bad config is not loaded"
# /etc/dockpanel/ssl holds the site certificates, so nginx is reloaded once it is
# back - after `nginx -t`, and never as a `fail`: by then the binaries and /etc
# are the snapshot's, and aborting could only strand the box.
run_restore nginx_t_fails yes STUB_NGINX_T_RC=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a failing nginx -t still exits 0: the box is restored"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has   "the verdict is ok=false"                 '"ok":false'                 "$J"
assert_has   "the stage named is nginx"                '"stage":"nginx"'            "$J"
assert_has   "the detail says nginx -t failed"         'nginx -t failed'            "$J"
assert_has   "and carries nginx's own reason"          'cannot load certificate'    "$J"
assert_has   "nginx -t was run"                        'nginx -t'                   "$A"
assert_lacks "nginx was NOT reloaded on a bad config"  'systemctl reload nginx'     "$A"
assert_has   "dockpanel-api WAS started"               'systemctl start dockpanel-api' "$A"
chk "$([ "$(cat "$BIN_DIR_OUT/dockpanel-api")" = "OLD-API" ] && echo 0 || echo 1)" \
    "the rollback completed"

run_restore nginx_reload_fails yes STUB_NGINX_RELOAD_RC=1
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "a failing reload still exits 0"
J="$(cat "$RES_JSON")"
assert_has   "the verdict is ok=false"                 '"ok":false'                 "$J"
assert_has   "the detail names the reload"             'systemctl reload nginx failed' "$J"

run_restore nginx_inactive yes STUB_NGINX_ACTIVE_RC=3
chk "$([ "$RC" = "0" ] && echo 0 || echo 1)" "no running nginx: exits 0"
J="$(cat "$RES_JSON")"; A="$(cat "$ACTIONS")"
assert_has   "and the verdict stays ok=true"           '"ok":true'                  "$J"
assert_lacks "nginx -t is not run"                     'nginx -t'                   "$A"
assert_lacks "nginx is not reloaded"                   'systemctl reload nginx'     "$A"
assert_has   "the skip is logged"                      'nginx is not installed or not running' \
             "$(cat "$SCRATCH/nginx_inactive/out.log")"

echo
echo "══ Part 2 · the update path, by source ══════════════════════════════════"
echo
# Every behavioural arm below reads CODE. This part used to `cat` both files and
# grep the text, which let a line of DOCUMENTATION satisfy a claim about
# behaviour - measured against this suite at s338: five separate mutations that
# disabled the update path outright left all six arms green, because the
# disabling edits' own comments still spelled the strings the arms looked for,
# and in one case a pre-existing paragraph did it with nothing planted at all.
#
# Each pattern is held in a variable so the mutation section (§2d) can re-use the
# arm's EXACT text. A mutation test that re-types the pattern proves the copy.
# Bracket classes rather than backslash escapes throughout: the same strings are
# handed to both grep -E and awk, and awk eats backslashes in a -v assignment.
#
# None of these patterns spells a name declared in the subjects. They match the
# SHAPE of the declaration and lift the identifier out of the source when one is
# needed, so that this file can never become the thing that satisfies a pin.
PAT_VERDICT_PATH='^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*="[^"]*last-panel-update[.]json"'
PAT_EXIT_TRAP='^[[:space:]]*trap[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+EXIT'
PAT_DETACHED='^[[:space:]]*exec[[:space:]]+systemd-run'
PAT_RESULT_CONST='^[[:space:]]*(pub[[:space:]]+)?(const|static)[[:space:]]+[A-Z][A-Z0-9_]*[^=]*=[[:space:]]*"[^"]*last-panel-update[.]json"'
PAT_RESULT_READ='read_to_string[(][A-Z][A-Z0-9_]*[)]'
PAT_PROMOTED='verdict[[:space:]]*=[[:space:]]*Some[(][(][[:space:]]*true'
PAT_VERDICT_DECL='^[[:space:]]*let[[:space:]]+mut[[:space:]]+[a-z_]+[[:space:]]*=[[:space:]]*None;'

O="$(cat "$ORCHESTRATOR")"   # raw, and used by exactly one arm - see §2b

echo "§2a · update.sh, read as code"
# The assignment has to be an assignment: the filename must sit inside the
# QUOTED VALUE of a statement that starts the line. The census retargeted this
# variable at /dev/null and left the old path in a trailing comment on the same
# line; the arm passed, because a substring search cannot tell a value from an
# apology.
pin_code "update.sh writes a verdict file"  "$UPDATE_SH" -E "$PAT_VERDICT_PATH"
pin_code "it writes one on every exit path" "$UPDATE_SH" -E "$PAT_EXIT_TRAP"

# The trap is only worth anything if the handler it names already exists when
# the trap is registered. Both line numbers come from the stripped stream, which
# BLANKS rather than deletes - the numbers are the file's real ones. The handler
# name is lifted out of the source rather than written here.
HANDLER="$(code_lines "$UPDATE_SH" | grep -oE "$PAT_EXIT_TRAP" | awk 'NR==1{print $2}')"
TRAP_LN="$(code_lineno "$UPDATE_SH" -E "$PAT_EXIT_TRAP")"
DEF_LN=""
[ -n "$HANDLER" ] && DEF_LN="$(code_lineno "$UPDATE_SH" -E "^[[:space:]]*${HANDLER}[(][)]")"
if [ -n "$HANDLER" ] && [ -n "$TRAP_LN" ] && [ -n "$DEF_LN" ] && [ "$DEF_LN" -lt "$TRAP_LN" ]; then
    ok "the trap names a handler that is already defined above it"
else
    bad "the trap names a handler that is already defined above it - handler='${HANDLER:-none}' defined=${DEF_LN:-none} trapped=${TRAP_LN:-none}"
fi

# The whole point: systemd-run's exit status describes the handoff, never the
# work. The agent side learned this at s232 (lesson #49); the local path is the
# sibling call site that never got it.
#
# The GATE reads code too, and that is not a detail. It used to read raw text, so
# when the census BLANKED the entire re-exec block - no comment planted anywhere
# - a paragraph further down still mentioned the invocation, the gate held, and
# both arms below printed green over a subject that no longer existed. An
# absence is only meaningful while the thing it is an absence FROM is present.
if has_code "$UPDATE_SH" -E "$PAT_DETACHED"; then
    pin_no_code "update.sh does not --wait on its own detached unit" "$UPDATE_SH" -F -e '--wait'
    # --pipe implies --wait AND wires the unit's stdout to the caller, so when
    # the api is stopped the updater's next write takes SIGPIPE mid-swap.
    pin_no_code "update.sh does not use --pipe either"               "$UPDATE_SH" -F -e '--pipe'
else
    bad "update.sh no longer re-execs into a transient unit"
fi

echo
echo "§2b · the orchestrator, read as production code"
# Read as PRODUCTION code: the file's own test module spells this filename twice
# in its assertions, and those two lines alone kept this arm green while the
# constant pointed somewhere else entirely.
pin_prod "the orchestrator reads that file" "$ORCHESTRATOR" -E "$PAT_RESULT_CONST"

# A constant that nothing reads is a comment with a type. The name is taken from
# whatever the declaration above actually declares, so the arm cannot drift from
# the constant it is about.
const_use_count() {
    local f="$1" name
    name="$(prod_lines "$f" | grep -E "$PAT_RESULT_CONST" \
            | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?(const|static)[[:space:]]+([A-Z][A-Z0-9_]*).*/\3/' \
            | awk 'NR==1{print}')"
    if [ -z "$name" ]; then echo 0; return; fi
    prod_count "$f" -F -e "$name"
}
if [ "$(const_use_count "$ORCHESTRATOR")" -ge 2 ]; then
    ok "the path constant is read, not merely declared"
else
    bad "the path constant is read, not merely declared - it appears on fewer than two production lines"
fi

# THE behavioural claim, and it is a NEGATIVE one: nothing may write a success
# verdict from the handoff. The census proved the point by promoting a zero exit
# straight into a recorded success and dead-coding the watch loop; the arm that
# used to carry this label was satisfied by a paragraph of prose two dozen lines
# above the code, so it never moved. §2e plants that exact defect and requires
# this pattern to fire on it.
pin_no_prod "the orchestrator says a zero exit is a handoff, not a success" \
            "$ORCHESTRATOR" -E "$PAT_PROMOTED"

# DELIBERATELY RAW, and the only arm here that is. Its subject IS the prose: the
# explanation of why a zero exit proves nothing has to stay beside the code that
# depends on it, and stripping comments for this one would be the defect rather
# than the fix. It makes no claim about behaviour - the arm above does that.
assert_has "the reason a zero exit proves nothing is still written down beside it" \
           'never "the work succeeded"' "$O"

echo
echo "§2c · the stripper itself, over and under"
# The strippers are now load-bearing for eight arms, so they get their own
# subjects. Over-stripping is the quiet failure on the negative arms above:
# every `--wait` in update.sh lives in a comment, so a stripper that ate one
# character too many would leave those two arms green forever.
PROBES="$SCRATCH/probes"; mkdir -p "$PROBES"
cat > "$PROBES/probe.sh" <<'PROBE'
#!/usr/bin/env bash
# this whole line is explanation and must be blanked
tag="colour #ffcc00"
suffix="${tag#colour }"
argc=$#
PROBE
cat > "$PROBES/probe.rs" <<'PROBE'
// this whole line is explanation and must be blanked
/* and so is this one,
   which runs on */
let endpoint = "https://example.invalid/api";
let kept = 1; // this tail is explanation and must be blanked
PROBE

if [ "$(code_lines "$PROBES/probe.sh" | wc -l)" = "$(wc -l < "$PROBES/probe.sh")" ] \
   && [ "$(code_count "$PROBES/probe.sh" -F -e 'must be blanked')" = "0" ]; then
    ok "shell: a whole-line comment is blanked, and the file keeps its height"
else
    bad "shell: a whole-line comment is blanked, and the file keeps its height"
fi
if [ "$(code_count "$PROBES/probe.sh" -F -e '#ffcc00')" = "1" ] \
   && [ "$(code_count "$PROBES/probe.sh" -F -e '${tag#colour }')" = "1" ] \
   && [ "$(code_count "$PROBES/probe.sh" -F -e 'argc=$#')" = "1" ]; then
    ok "shell: a # inside a string, a parameter expansion and \$# all survive"
else
    bad "shell: a # inside a string, a parameter expansion and \$# all survive"
fi
if [ "$(code_lines "$PROBES/probe.rs" | wc -l)" = "$(wc -l < "$PROBES/probe.rs")" ] \
   && [ "$(code_count "$PROBES/probe.rs" -F -e 'must be blanked')" = "0" ] \
   && [ "$(code_count "$PROBES/probe.rs" -F -e 'which runs on')" = "0" ]; then
    ok "rust: line comments, a block comment and a trailing tail are all blanked"
else
    bad "rust: line comments, a block comment and a trailing tail are all blanked"
fi
if [ "$(code_count "$PROBES/probe.rs" -F -e 'https://example.invalid/api')" = "1" ] \
   && [ "$(code_count "$PROBES/probe.rs" -F -e 'let kept = 1;')" = "1" ]; then
    ok "rust: a // inside a string literal is code, and the line before a tail survives"
else
    bad "rust: a // inside a string literal is code, and the line before a tail survives"
fi
if [ "$(comment_marker_for x.rs)" = '//' ] && [ "$(comment_marker_for x.sh)" = '#' ] \
   && [ -z "$(comment_marker_for x.json)" ]; then
    ok "the marker comes from the extension, so a copy must keep the subject's"
else
    bad "the marker comes from the extension, so a copy must keep the subject's"
fi

echo
echo "§2d · every pinned pattern, commented out on a copy"
# An arm that has never been made to fail is a decoration. Each pattern above is
# commented out in a COPY of its subject and its own predicate is run again: it
# has to come back blind. The copy KEEPS THE SUBJECT'S EXTENSION, because the
# stripper picks its language from the filename - a copy called `mutated` is read
# as shell whatever it holds, and a Rust subject would keep every `//` line.
MUTANTS="$SCRATCH/mutants"; mkdir -p "$MUTANTS"

mutate_out() {   # subject, ERE, tag  →  path of a copy with matching lines commented
    local src="$1" pat="$2" tag="$3" marker out
    out="$MUTANTS/$tag-$(basename "$src")"
    marker="$(comment_marker_for "$src")"; [ -n "$marker" ] || marker='#'
    awk -v pat="$pat" -v m="$marker" '$0 ~ pat { print m " " $0; next } { print }' "$src" > "$out"
    printf '%s\n' "$out"
}

# Did the plant LAND? Same height, and every changed line is the original with a
# marker in front of it - nothing added, nothing deleted, nothing else touched.
# A mutation arm that goes green over a plant which never landed is the blinded
# arm all over again, one level up.
plant_landed() {   # marker, subject, mutant  →  lines commented, or -1
    awk -v m="$1" '
        NR == FNR { a[FNR] = $0; n = FNR; next }
        { if (FNR > n) { broke = 1 }
          else if ($0 != a[FNR]) { if ($0 == m " " a[FNR]) c++; else broke = 1 } }
        END { if (FNR != n || broke) print -1; else print c + 0 }' "$2" "$3"
}

mutation_blinds() {   # label, subject, ERE, tag, predicate
    local label="$1" src="$2" pat="$3" tag="$4" pred="$5" mut marker n
    mut="$(mutate_out "$src" "$pat" "$tag")"
    marker="$(comment_marker_for "$src")"; [ -n "$marker" ] || marker='#'
    n="$(plant_landed "$marker" "$src" "$mut")"
    if [ "${n:--1}" -lt 1 ]; then
        bad "$label - the mutation never landed (changed=$n), so a green arm proves nothing"
    elif "$pred" "$mut" -E "$pat"; then
        bad "$label - the arm still finds it with the line commented out"
    else
        ok "$label"
    fi
}

mutation_blinds "commenting out the verdict-path assignment blinds its arm" \
                "$UPDATE_SH" "$PAT_VERDICT_PATH" vpath has_code
mutation_blinds "commenting out the exit trap blinds its arm" \
                "$UPDATE_SH" "$PAT_EXIT_TRAP" trap has_code
mutation_blinds "commenting out the detached re-exec trips the gate" \
                "$UPDATE_SH" "$PAT_DETACHED" detach has_code
mutation_blinds "commenting out the path constant blinds its arm" \
                "$ORCHESTRATOR" "$PAT_RESULT_CONST" pconst has_prod

MUT_READ="$(mutate_out "$ORCHESTRATOR" "$PAT_RESULT_READ" pread)"
MUT_READ_N="$(plant_landed '//' "$ORCHESTRATOR" "$MUT_READ")"
if [ "${MUT_READ_N:--1}" -lt 1 ]; then
    bad "commenting out the read of the path constant blinds the read-count arm - the mutation never landed (changed=$MUT_READ_N)"
elif [ "$(const_use_count "$MUT_READ")" -ge 2 ]; then
    bad "commenting out the read of the path constant blinds the read-count arm - the count did not move"
else
    ok "commenting out the read of the path constant blinds the read-count arm"
fi

echo
echo "§2e · the negative arms, with the real defect planted"
# Stripping makes a check see LESS. On a POSITIVE arm that is loud - over-strip
# and it goes red at HEAD, in front of whoever ran it. On a NEGATIVE arm, where
# a match means BROKEN, it is silent: the arm goes green over exactly the code it
# exists to forbid, and nothing anywhere says so. So each negative arm gets the
# real defect written into a copy and has to FIRE on it.
plant_line_after() {   # subject, anchor ERE, defect line, tag  →  copy path
    local src="$1" anchor="$2" line="$3" tag="$4" out
    out="$MUTANTS/$tag-$(basename "$src")"
    # The defect text travels in the ENVIRONMENT, not in a -v assignment: awk
    # interprets escape sequences in -v, and the flag being planted here is a
    # shell continuation, so its trailing backslash was silently eaten and the
    # plant landed as a different line than the one this arm then looked for.
    # The landing check caught it - which is the entire reason it is here.
    DEFECT_LINE="$line" awk -v a="$anchor" '
        BEGIN { l = ENVIRON["DEFECT_LINE"] }
        { print }
        !done && $0 ~ a { print l; done = 1 }' "$src" > "$out"
    printf '%s\n' "$out"
}
landed_insert() {   # subject, copy, defect line
    [ "$(wc -l < "$2")" -eq "$(( $(wc -l < "$1") + 1 ))" ] \
      && [ "$(grep -cxF "$3" "$1")" -eq 0 ] \
      && [ "$(grep -cxF "$3" "$2")" -eq 1 ]
}

WAIT_DEFECT='            --wait \'
CTL="$(plant_line_after "$UPDATE_SH" "$PAT_DETACHED" "$WAIT_DEFECT" ctlwait)"
if landed_insert "$UPDATE_SH" "$CTL" "$WAIT_DEFECT" && has_code "$CTL" -F -e '--wait'; then
    ok "planting --wait into the detached unit makes that arm fire"
else
    bad "planting --wait into the detached unit makes that arm fire - it did NOT, the arm is blind"
fi

PIPE_DEFECT='            --pipe \'
CTL="$(plant_line_after "$UPDATE_SH" "$PAT_DETACHED" "$PIPE_DEFECT" ctlpipe)"
if landed_insert "$UPDATE_SH" "$CTL" "$PIPE_DEFECT" && has_code "$CTL" -F -e '--pipe'; then
    ok "planting --pipe into the detached unit makes that arm fire"
else
    bad "planting --pipe into the detached unit makes that arm fire - it did NOT, the arm is blind"
fi

# The census's own inversion, minus the branch surgery: a success verdict
# recorded from the handoff itself, written one line under the declaration it
# overwrites so it is in scope and unconditional.
PROMOTE_DEFECT='        verdict = Some((true, String::from("complete"), String::new()));'
CTL="$(plant_line_after "$ORCHESTRATOR" "$PAT_VERDICT_DECL" "$PROMOTE_DEFECT" ctlpromote)"
if landed_insert "$ORCHESTRATOR" "$CTL" "$PROMOTE_DEFECT" && has_prod "$CTL" -E "$PAT_PROMOTED"; then
    ok "planting a recorded success at the handoff makes that arm fire"
else
    bad "planting a recorded success at the handoff makes that arm fire - it did NOT, the arm is blind"
fi

echo
echo "§2f · restore-snapshot.sh silences nothing, and tests nginx before reloading it"
# RAW for the plain form, on purpose: the file is not allowed to spell it even in
# prose, so a grep that finds it anywhere is a finding. The disguised forms are
# read as code, since an explanation may have to name them.
PAT_SILENCED_RAW='[|][|][[:space:]]*true'
PAT_SILENCED_CODE='[|][|][[:space:]]*(:|echo|true)([[:space:]]|;|[)]|$)|;[[:space:]]*true([[:space:]]|;|$)'
silenced_count() {   # file  →  raw hits + code hits
    local raw code
    raw="$(grep -cE "$PAT_SILENCED_RAW" "$1")"
    code="$(code_count "$1" -E "$PAT_SILENCED_CODE")"
    echo $(( ${raw:-0} + ${code:-0} ))
}
if [ "$(silenced_count "$RESTORE_SH")" = "0" ]; then
    ok "restore-snapshot.sh has no silenced command (|| true, || :, || echo, ; true)"
else
    bad "restore-snapshot.sh silences a command: $(grep -nE "$PAT_SILENCED_RAW" "$RESTORE_SH" | head -3 | tr '\n' ' ')$(code_lines "$RESTORE_SH" | grep -nE "$PAT_SILENCED_CODE" | head -3 | tr '\n' ' ')"
fi

# nginx -t must come before the reload, both after /etc is restored, and the
# stage between them must report rather than raise.
nginx_order_ok() {   # file  →  0 when the order holds and the stage never fails
    local f="$1" etc_ln t_ln rl_ln ng_ln st_ln
    etc_ln="$(code_lineno "$f" -F -e 'stage="etc"')"
    ng_ln="$(code_lineno "$f" -F -e 'stage="nginx"')"
    st_ln="$(code_lineno "$f" -F -e 'stage="start-services"')"
    t_ln="$(code_lineno "$f" -F -e 'nginx -t')"
    rl_ln="$(code_lineno "$f" -F -e 'systemctl reload nginx')"
    [ -n "$etc_ln" ] && [ -n "$ng_ln" ] && [ -n "$st_ln" ] && [ -n "$t_ln" ] && [ -n "$rl_ln" ] || return 1
    [ "$etc_ln" -lt "$ng_ln" ] && [ "$ng_ln" -lt "$t_ln" ] && [ "$t_ln" -lt "$rl_ln" ] && [ "$rl_ln" -lt "$st_ln" ] || return 1
    # The stage itself: at least one degrade, no fail.
    code_lines "$f" | sed -n "${ng_ln},${st_ln}p" > "$MUTANTS/nginx-stage.txt"
    [ "$(grep -cF -e 'degrade "' "$MUTANTS/nginx-stage.txt")" -gt 0 ] || return 1
    [ "$(grep -cF -e 'fail "' "$MUTANTS/nginx-stage.txt")" -eq 0 ]
}
if nginx_order_ok "$RESTORE_SH"; then
    ok "nginx -t precedes the reload, after /etc, in a stage that degrades and never fails"
else
    bad "nginx -t precedes the reload, after /etc, in a stage that degrades and never fails"
fi

# And both arms fire on the defect they forbid.
SILENCE_DEFECT='chmod 0700 "$STATE_DIR" 2>/dev/null || true'
CTL="$(plant_line_after "$RESTORE_SH" '^mkdir -p "[$]STATE_DIR"' "$SILENCE_DEFECT" silence)"
if landed_insert "$RESTORE_SH" "$CTL" "$SILENCE_DEFECT" && [ "$(silenced_count "$CTL")" -gt 0 ]; then
    ok "planting a silenced chmod makes the no-silencing arm fire"
else
    bad "planting a silenced chmod makes the no-silencing arm fire - it did NOT, the arm is blind"
fi
DISGUISE_DEFECT='    SIZE_BYTES="$(stat -c%s "$TARBALL" 2>/dev/null || echo 0)"'
CTL="$(plant_line_after "$RESTORE_SH" '^mkdir -p "[$]STATE_DIR"' "$DISGUISE_DEFECT" disguise)"
if landed_insert "$RESTORE_SH" "$CTL" "$DISGUISE_DEFECT" && [ "$(silenced_count "$CTL")" -gt 0 ]; then
    ok "planting a disguised '|| echo 0' fallback makes it fire too"
else
    bad "planting a disguised '|| echo 0' fallback makes it fire too - it did NOT, the arm is blind"
fi
RELOAD_DEFECT='systemctl reload nginx'
CTL="$(plant_line_after "$RESTORE_SH" '^stage="nginx"' "$RELOAD_DEFECT" reloadfirst)"
if landed_insert "$RESTORE_SH" "$CTL" "$RELOAD_DEFECT" && ! nginx_order_ok "$CTL"; then
    ok "planting a reload before nginx -t makes the ordering arm fire"
else
    bad "planting a reload before nginx -t makes the ordering arm fire - it did NOT, the arm is blind"
fi
FAIL_DEFECT='fail "nginx -t failed"'
CTL="$(plant_line_after "$RESTORE_SH" '^stage="nginx"' "$FAIL_DEFECT" nginxfail)"
if landed_insert "$RESTORE_SH" "$CTL" "$FAIL_DEFECT" && ! nginx_order_ok "$CTL"; then
    ok "planting a fail in the nginx stage makes that arm fire"
else
    bad "planting a fail in the nginx stage makes that arm fire - it did NOT, the arm is blind"
fi

echo
echo "─────────────────────────────────────────────────────────────────────────"
printf 'passed %d · failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
