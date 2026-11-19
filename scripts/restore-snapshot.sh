#!/usr/bin/env bash
#
# CyberHunter - Panel - restore a panel snapshot (binaries + frontend + /etc/dockpanel + database).
#
# This script is the ONLY thing that mutates state during a rollback. It is
# compiled into dockpanel-api (`include_str!`) and written to
# /var/lib/dockpanel/restore-snapshot.sh at rollback time, so it cannot drift
# from the binary that invokes it and does not depend on /opt/dockpanel being
# present (see lesson #35/#38 - a repo-side config that no installer deploys is
# dev fiction; embedding it removes the deployment step entirely).
#
# WHY A SEPARATE, DETACHED PROCESS (the whole point):
#   The restore used to run INLINE inside the dockpanel-api HTTP handler. A
#   restore takes longer than the panel's own 300s request timeout
#   (TimeoutLayer, backend main.rs; nginx proxy_read_timeout 300s) - measured at
#   394.9s on a lab box. At 300s axum dropped the request future, which broke the
#   `gunzip | docker exec ... psql` pipe; psql then read a clean EOF and EXITED 0,
#   so the code recorded a SUCCESSFUL restore while the database had been left
#   with 1 of 92 tables. Every pre-update snapshot the panel ever took was
#   unrestorable, and the failure was indistinguishable from success.
#
#   So: PID1 owns this process (systemd-run --collect, per lesson #47 - a
#   transient *service*, never a session-owned scope, which would die with the
#   caller), it outlives the api it stops, and the database stage is atomic and
#   status-checked (lesson #45).
#
# WHAT A ROLLBACK DOES AND DOES NOT DO (verified on a lab box, not assumed):
#   It restores what the snapshot CONTAINS - the binaries, the frontend,
#   /etc/dockpanel and the database. The database is a true point-in-time revert: the `public`
#   schema is dropped and rebuilt from the dump inside one transaction, so an
#   object created after the snapshot does NOT survive.
#
#   That is a deliberate change from v2.11.5/v2.11.6, where the restore applied
#   only the dump's own DROP statements and therefore MERGED the snapshot into
#   whatever was there. Post-snapshot tables outlived the rollback while
#   _sqlx_migrations was rewound, and a later forward update then re-ran a
#   migration whose objects already existed: the api panicked at startup and
#   crash-looped into a permanent 502. Reproduced end to end before this was
#   changed. The data those extra tables held is not silently discarded - the
#   pre-rollback dump written below captures the full pre-restore database.
#
#   Nothing outside the snapshot is touched at all: /etc/nginx, /etc/letsencrypt,
#   /var/www, docker volumes and site data are NOT rewound. A rollback is "put the
#   panel back", not "put the machine back". The one thing it does ask of nginx
#   is a reload, once /etc/dockpanel is back: the site certificates live there,
#   and nginx keeps serving the ones it loaded until it reloads. `nginx -t` runs
#   first; a configuration that fails it is reported (ok=false) and NOT loaded.
#
# Env (all set by the caller):
#   DOCKPANEL_SNAPSHOT_ID        uuid of the snapshot row
#   DOCKPANEL_SNAPSHOT_TARBALL   absolute path to the .tar.gz
#   DOCKPANEL_SNAPSHOT_SHA256    expected sha256 of that tarball
# Optional overrides: DOCKPANEL_PG_CONTAINER / _PG_USER / _PG_DB
# Optional provenance, for the activity log entry of this rollback:
#   DOCKPANEL_ROLLBACK_OPERATOR      who asked for it
#   DOCKPANEL_ROLLBACK_FROM_VERSION  the version running when they did
# Optional mode:
#   DOCKPANEL_RESTORE_MODE           `rollback` (default) or `dr`
#
# MODE dr: the restore of an off-site disaster recovery archive, usually on a
# freshly installed machine (`dockpanel-api dr restore`, or "Restore from remote
# snapshot" in the panel). The archive carries the database dump, the PowerDNS
# dump when there is one and /etc/dockpanel, but NO binaries and NO frontend:
#   - it is refused BEFORE any service is stopped when the installed version or
#     the machine architecture differs from the archive's metadata, or when the
#     archive is not a `kind=dr` one;
#   - the binaries and the frontend are left as installed (same version, checked);
#   - /etc/dockpanel is restored as it is in the archive EXCEPT the DATABASE_URL
#     line of api.env, which is kept from this machine (its PostgreSQL was created
#     with its own password); merged through a 0600 temporary file, never shown;
#   - agent.token is made to agree with AGENT_TOKEN of the restored api.env, and
#     a lone half of the agent TLS pair is not restored over this machine's pair;
#   - db/pdns.sql.gz, when present, is restored into the PowerDNS database;
#   - the restored database is not a local snapshot, so no panel_snapshots row
#     is recorded, and the decrypted tarball (it holds api.env) is deleted on
#     every exit path;
#   - /var/lib/dockpanel/vhost-rebuild.pending is written: at its next start the
#     api rebuilds every local site's vhost from the database and reports in
#     vhost-rebuild.json.
#   The api is considered to match the restored database only once
#   /etc/dockpanel is back (same binaries, but JWT_SECRET is in api.env): until
#   then the same guard as a rollback keeps dockpanel-api stopped.
#
# Result is always written to /var/lib/dockpanel/last-restore.json.
#
# READING THE VERDICT (the exit status alone is not enough):
#   exit 0, ok=true            restored, everything verified.
#   exit 0, ok=false           restored, but a post-commit check or the
#                              bookkeeping did not pass. The box is consistent
#                              and running; "detail" says what to look at.
#   non-zero, before the DB    nothing changed and nothing was lost.
#     commit
#   non-zero, after it         the database is back on the snapshot but the
#                              binaries are not. dockpanel-api is left STOPPED
#                              on purpose (see rollback_would_be_undone below)
#                              and the box needs an operator.
#
# So a non-zero exit does NOT universally mean "nothing lost" - that was true
# only while every failure path preceded the database stage, and it stopped
# being true once this script started refusing to restart a mismatched panel.

set -euo pipefail

SNAP_ID="${DOCKPANEL_SNAPSHOT_ID:?DOCKPANEL_SNAPSHOT_ID is required}"
TARBALL="${DOCKPANEL_SNAPSHOT_TARBALL:?DOCKPANEL_SNAPSHOT_TARBALL is required}"
EXPECT_SHA="${DOCKPANEL_SNAPSHOT_SHA256:?DOCKPANEL_SNAPSHOT_SHA256 is required}"
PG_CONTAINER="${DOCKPANEL_PG_CONTAINER:-dockpanel-postgres}"
# Deliberately mirrors the pg_dump invocation that CREATED the snapshot
# (panel_snapshot.rs build_snapshot_inner) - restore must be symmetric with dump.
PG_USER="${DOCKPANEL_PG_USER:-dockpanel}"
PG_DB="${DOCKPANEL_PG_DB:-dockpanel}"
ROLLBACK_OPERATOR="${DOCKPANEL_ROLLBACK_OPERATOR:-}"
ROLLBACK_FROM="${DOCKPANEL_ROLLBACK_FROM_VERSION:-}"
RESTORE_MODE="${DOCKPANEL_RESTORE_MODE:-rollback}"
# Set by the dr preflight: the version this machine runs (it matched the archive).
INSTALLED_VERSION=""

# Locations. Overridable ONLY so this script can be driven end to end by
# tests/update-rollback-pin-e2e.sh against a scratch tree: the guard below
# decides whether to leave a panel down, and a guard that has never been
# executed is a comment. The defaults are the real paths and the api sets none
# of these, so nothing in the product changes. `:-` (not `-`) so an empty value
# falls back rather than resolving to "".
STATE_DIR="${DOCKPANEL_STATE_DIR:-/var/lib/dockpanel}"
BIN_DIR="${DOCKPANEL_BIN_DIR:-/usr/local/bin}"
ETC_DIR="${DOCKPANEL_ETC_DIR:-/etc/dockpanel}"
FRONTEND_DIR="${DOCKPANEL_FRONTEND_DIR:-/opt/dockpanel/frontend}"
HEALTH_URL="${DOCKPANEL_HEALTH_URL:-http://127.0.0.1:3080/api/health}"
RESULT="$STATE_DIR/last-restore.json"
WORK="$STATE_DIR/restore-$SNAP_ID"
LOG_TAG=dockpanel-restore
# dockpanel-api FIRST, deliberately. It is the only one of these that runs
# migrations against the database, so the window in which the database has been
# reverted while a NEWER api is still installed is exactly the span between the
# database commit and this binary being replaced. Restoring it first makes that
# window as short as the script can make it.
BINS=(dockpanel-api dockpanel-agent dockpanel dockpanel-mcp)

# Always returns 0: it is called from `degrade` and from the exit trap, where a
# failing logger must never change what the restore does next. A journal that
# refuses the line is said so on stderr (the unit's own journal stream) instead
# of being swallowed. Writes to stdout, so never call it inside `$(...)`
# without redirecting it.
log() {
    echo "[restore] $*"
    if command -v systemd-cat >/dev/null 2>&1; then
        if ! echo "[restore] $*" | systemd-cat -t "$LOG_TAG"; then
            echo "[restore] systemd-cat refused the line above" >&2
        fi
    fi
}

mkdir -p "$STATE_DIR"
# Defence in depth only: the work directory is created 0700 and the verdict and
# pre-rollback dump are each restricted on their own, so a state directory whose
# mode cannot be tightened is reported, not fatal.
if ! chmod 0700 "$STATE_DIR"; then
    log "could not set mode 0700 on $STATE_DIR - the files in it are still restricted one by one"
fi

stage="init"
finished=0
services_stopped=0
# Set the instant the restore transaction commits: from here on the database is
# the SNAPSHOT's, and any api older or newer than it is a mismatch.
db_committed=0
# Set when /usr/local/bin/dockpanel-api has actually been replaced from the
# snapshot, which is what makes the running code agree with that database again.
api_reverted=0
# Non-fatal problems, collected rather than raised - see `degrade`.
degraded=""
degraded_stage=""
# Where the pre-restore database was captured; the way back from a rollback.
PRE_DUMP=""
# The version the snapshot puts back, read from its metadata once extracted.
M_FROM="unknown"
# Set once this rollback has its entry in the activity log.
journaled=0
# The last verdict written, raw, so the exit trap can append to it.
result_stage=""
result_detail=""

# JSON-escape a string for the single "detail" field (quotes, backslashes,
# control chars). Kept to one line so the result file stays trivially parseable.
json_escape() {
    printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

# Quote a string for a single-quoted SQL literal.
sqlq() { printf "%s" "$1" | sed "s/'/''/g"; }

# The activity log entry of this rollback.
#
# Written HERE, by the restore, because nothing else can: the database restore
# erases every entry made before it, and the api that boots afterwards is the
# snapshot's own binary, which may predate this code. Base columns only, since
# the schema is now the snapshot's. `user_id` stays NULL: the operator's account
# may not exist in the restored database, and the email names them either way.
#
# Returns non-zero when the entry could not be written; the caller decides what
# that means, because no failure here may abort a restore that has committed.
journal_manual_rollback() {
    local outcome="$1"
    local from="${ROLLBACK_FROM:-unknown}" who="${ROLLBACK_OPERATOR:-unknown}"
    local action="update.manual_rollback" target_type="panel_update"
    local reason="manual rollback to snapshot $SNAP_ID, from version $from to version $M_FROM, requested by $who"
    if [ "$RESTORE_MODE" = "dr" ]; then
        action="dr.restore"
        target_type="dr"
        reason="disaster recovery restore of off-site snapshot $SNAP_ID (version $M_FROM) onto this machine, requested by $who"
    fi
    local details
    details="$(printf '{"snapshot_id":"%s","from_version":"%s","to_version":"%s","operator":"%s","outcome":"%s","reason":"%s"}' \
        "$(json_escape "$SNAP_ID")" "$(json_escape "$from")" "$(json_escape "$M_FROM")" \
        "$(json_escape "$who")" "$(json_escape "$outcome")" "$(json_escape "$reason")")"
    journaled=1
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAq -v ON_ERROR_STOP=1 -c \
"INSERT INTO activity_logs (user_email, action, target_type, target_name, details)
 VALUES ('$(sqlq "${ROLLBACK_OPERATOR:-system}")', '$action', '$target_type', '$(sqlq "$SNAP_ID")', '$(sqlq "$details")')" \
        </dev/null >/dev/null 2>&1
}

write_result() {
    local ok="$1" st="$2" detail="$3"
    local tmp="$RESULT.tmp"
    result_stage="$st"
    result_detail="$detail"
    printf '{"snapshot_id":"%s","mode":"%s","ok":%s,"stage":"%s","detail":"%s","finished_at":"%s"}\n' \
        "$SNAP_ID" "$(json_escape "$RESTORE_MODE")" "$ok" "$st" "$(json_escape "$detail")" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp"
    # The verdict holds no secret, and this runs from the exit trap too, where
    # aborting would lose the verdict itself: reported, never fatal.
    if ! chmod 0600 "$tmp"; then
        log "could not set mode 0600 on $tmp"
    fi
    mv "$tmp" "$RESULT"
}

fail() {
    local detail="$1"
    log "FAILED at stage '$stage': $detail"
    write_result false "$stage" "$detail$(hazard_note)"
    finished=1
    exit 1
}

# A problem that is real but that aborting cannot fix.
#
# Everything after the database commit is in this class. The transaction has
# already applied, so there is nothing left to protect by stopping - and there
# IS something left to lose, because stopping here strands the box between two
# versions (see `rollback_would_be_undone`). So these are recorded, reported in
# the result file, and the restore carries on to make the box consistent.
degrade() {
    log "DEGRADED at stage '$stage': $1"
    [ -n "$degraded_stage" ] || degraded_stage="$stage"
    degraded="${degraded:+$degraded; }$1"
}

# The window this whole guard exists for: the database has been put back to the
# snapshot, but the api binary has not, so the api sitting in /usr/local/bin is
# still the NEWER one.
#
# Starting it here would not be a recovery, it would be the rollback being
# silently undone: sqlx runs the newer migrations against the just-restored
# database, and the operator ends up on the schema they explicitly rolled away
# from while this file reports the restore as FAILED. A panel that is down is
# recoverable and obvious; a database migrated forward behind a failed-rollback
# verdict is neither.
rollback_would_be_undone() {
    [ "$db_committed" = "1" ] && [ "$api_reverted" != "1" ]
}

# Appended to whatever verdict gets written while that window is open, so the
# operator reading last-restore.json is told the panel is down on purpose and
# where the way back is. Recovery, once the version mismatch is understood:
#     gunzip -c /var/lib/dockpanel/pre-rollback-<id>.sql.gz > /tmp/recover.sql
#     docker exec -i dockpanel-postgres psql -U dockpanel -d dockpanel \
#         -v ON_ERROR_STOP=1 < /tmp/recover.sql
#     systemctl start dockpanel-api
hazard_note() {
    if rollback_would_be_undone && [ "$RESTORE_MODE" = "dr" ]; then
        printf '%s' " - dockpanel-api was deliberately LEFT STOPPED: the database is back on the off-site snapshot but $ETC_DIR is not, and the installed api would start on this machine's JWT_SECRET over it (every stored credential unreadable). The pre-restore database is at ${PRE_DUMP:-$STATE_DIR/pre-rollback-$SNAP_ID.sql.gz}."
    elif rollback_would_be_undone; then
        printf '%s' " - dockpanel-api was deliberately LEFT STOPPED: the database is back on the snapshot but the binaries are not, and starting the installed api would migrate it forward and undo this rollback. The pre-rollback database is at ${PRE_DUMP:-$STATE_DIR/pre-rollback-$SNAP_ID.sql.gz}."
    fi
}

# Safety net (mirrors scripts/update.sh): if we die anywhere between stopping and
# starting the services, bring them back rather than leaving the box dark - the
# s228 BUG I failure shape (a test box sat down for 47 minutes).
#
# With ONE exception, which is the s231 defect: "bring the services back" was
# unconditional, so a failure in any stage between the database commit and the
# binary swap restarted the newer api on top of the reverted database. The box
# ended up migrated forward from a rollback that had just reported failure.
on_exit() {
    local code=$?
    # What the trap itself could not do, appended to the verdict. Every command
    # in here sits in a condition: errexit is live in a trap, and one bare
    # failure would skip the restarts below and the verdict with them.
    local trap_note=""
    # A rollback that stops after the commit has still replaced the database, and
    # with it the journal: the failure gets its entry here. The success path
    # writes its own, while it can still report a failure to do so.
    if [ "$db_committed" = "1" ] && [ "$journaled" != "1" ]; then
        if ! journal_manual_rollback "failed at stage $stage"; then
            log "the rollback could not be recorded in the activity log"
        fi
    fi
    if [ "$services_stopped" = "1" ]; then
        if rollback_would_be_undone; then
            log "NOT starting dockpanel-api: the database was restored but the binaries were not"
            log "starting it would migrate the reverted database forward and undo this rollback"
            log "the pre-rollback database is at ${PRE_DUMP:-$STATE_DIR/pre-rollback-$SNAP_ID.sql.gz}"
            if ! systemctl start dockpanel-agent; then
                log "dockpanel-agent could not be restarted from the exit trap"
                trap_note="$trap_note dockpanel-agent could not be restarted and must be started by hand."
            fi
        else
            log "restarting services from exit trap"
            if ! systemctl start dockpanel-agent; then
                log "dockpanel-agent could not be restarted from the exit trap"
                trap_note="$trap_note dockpanel-agent could not be restarted and must be started by hand."
            fi
            # Attempted even when the agent did not come back: the api is what
            # the operator reaches the box through.
            if ! systemctl start dockpanel-api; then
                log "dockpanel-api could not be restarted from the exit trap"
                trap_note="$trap_note dockpanel-api could not be restarted and must be started by hand."
            fi
        fi
    fi
    # The work directory holds a decompressed copy of the database dump, so a
    # leftover is worth an operator's attention.
    if ! rm -rf "$WORK"; then
        log "could not remove $WORK (it holds a copy of the database dump): remove it by hand"
        trap_note="$trap_note $WORK could not be removed and holds a copy of the database dump."
    fi
    # The decrypted off-site archive holds api.env and the database: it never
    # outlives the restore, whatever the outcome. It can be fetched again.
    if [ "$RESTORE_MODE" = "dr" ] && [ -e "$TARBALL" ]; then
        if ! rm -f "$TARBALL"; then
            log "could not remove the decrypted archive $TARBALL: remove it by hand"
            trap_note="$trap_note the decrypted archive $TARBALL could not be removed and holds secrets."
        fi
    fi
    if [ "$finished" != "1" ]; then
        write_result false "$stage" "aborted at stage '$stage' with exit code $code$(hazard_note)${trap_note:+ -$trap_note}"
    elif [ -n "$trap_note" ]; then
        # A verdict is already on disk (fail, or the success path): keep its
        # stage and words, and say what the trap could not do on top of it.
        write_result false "$result_stage" "$result_detail -$trap_note"
    fi
}
trap on_exit EXIT INT TERM

# Belt-and-braces: if invoked by hand from inside the panel's own cgroup, escape
# it first. The normal path already arrives here under systemd-run.
if [ -z "${DOCKPANEL_RESTORE_DETACHED:-}" ] && command -v systemd-run >/dev/null 2>&1; then
    if grep -qE 'dockpanel-(api|agent)\.service' /proc/self/cgroup 2>/dev/null; then
        log "re-executing outside the panel's service cgroup"
        trap - EXIT INT TERM
        exec systemd-run --quiet --collect \
            --unit="dockpanel-snapshot-restore-$SNAP_ID" \
            --setenv=DOCKPANEL_RESTORE_DETACHED=1 \
            --setenv=DOCKPANEL_SNAPSHOT_ID="$SNAP_ID" \
            --setenv=DOCKPANEL_SNAPSHOT_TARBALL="$TARBALL" \
            --setenv=DOCKPANEL_SNAPSHOT_SHA256="$EXPECT_SHA" \
            --setenv=DOCKPANEL_PG_CONTAINER="$PG_CONTAINER" \
            --setenv=DOCKPANEL_PG_USER="$PG_USER" \
            --setenv=DOCKPANEL_PG_DB="$PG_DB" \
            --setenv=DOCKPANEL_STATE_DIR="$STATE_DIR" \
            --setenv=DOCKPANEL_BIN_DIR="$BIN_DIR" \
            --setenv=DOCKPANEL_ETC_DIR="$ETC_DIR" \
            --setenv=DOCKPANEL_HEALTH_URL="$HEALTH_URL" \
            --setenv=DOCKPANEL_ROLLBACK_OPERATOR="$ROLLBACK_OPERATOR" \
            --setenv=DOCKPANEL_ROLLBACK_FROM_VERSION="$ROLLBACK_FROM" \
            --setenv=DOCKPANEL_RESTORE_MODE="$RESTORE_MODE" \
            bash "$0"
    fi
fi

write_result false "started" "restore in progress"
log "restoring snapshot $SNAP_ID from $TARBALL (mode $RESTORE_MODE)"
case "$RESTORE_MODE" in
    rollback|dr) ;;
    *) fail "unknown DOCKPANEL_RESTORE_MODE '$RESTORE_MODE' (expected rollback or dr) - nothing changed" ;;
esac

# ── 1. Verify the tarball ────────────────────────────────────────────────────
stage="verify-tarball"
[ -f "$TARBALL" ] || fail "tarball not found at $TARBALL"
ACTUAL_SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$EXPECT_SHA" ] || fail "sha256 mismatch: expected $EXPECT_SHA, got $ACTUAL_SHA"
log "sha256 verified"

# ── 2. Extract ───────────────────────────────────────────────────────────────
stage="extract"
rm -rf "$WORK"
mkdir -p "$WORK"
chmod 0700 "$WORK"
# The update source (update.conf + the token file) is NOT part of the panel's
# point-in-time state: a restore must leave whatever is configured right now
# untouched. Otherwise an admin who cleared a leaked token sees it come back
# with any older snapshot. Excluded at extraction, so the snapshot's copy of the
# token (and any leftover temporary file of it) is never written to disk here,
# and step 7 has nothing of the update source to copy over $ETC_DIR.
tar -C "$WORK" -xzf "$TARBALL" \
    --exclude='etc/update-token' \
    --exclude='etc/.update-token.tmp-*' \
    --exclude='etc/update.conf' \
    --exclude='etc/.update.conf.tmp-*' \
    || fail "tar extraction failed"
# Belt and braces against an entry tar's patterns did not match (any file type,
# symlinks included: rm -rf removes the link, never its target).
rm -rf "$WORK/etc/update-token" "$WORK/etc/update.conf" \
    "$WORK"/etc/.update-token.tmp-* "$WORK"/etc/.update.conf.tmp-* \
    || fail "could not drop the update source from the extracted snapshot"

DUMP_GZ="$WORK/db/dump.sql.gz"
DUMP_SQL="$WORK/db/dump.sql"

# Read before anything is destroyed: every path from the commit on names this
# version in the journal.
#
# Called inside `$(...)` both before and after the commit, so it never fails and
# never pipes: an unreadable field comes back empty and the caller's default
# applies. Its own log line goes to stderr, out of the captured value.
meta_field() {
    local out
    [ -f "$WORK/metadata.json" ] || return 0
    if ! out="$(sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$WORK/metadata.json")"; then
        log "could not read '$1' from the snapshot metadata" >&2
        return 0
    fi
    printf '%s\n' "${out%%$'\n'*}"
}
M_FROM="$(meta_field from_version)"; [ -n "$M_FROM" ] || M_FROM="unknown"

# ── 3. Prove the dump is complete BEFORE destroying anything ─────────────────
# Decompressing to a file first also removes the pipe that made truncation
# invisible: psql is fed from a regular file, so a broken producer cannot present
# a short read as a clean end-of-input.
stage="verify-dump"
if [ -f "$DUMP_GZ" ]; then
    gunzip -c "$DUMP_GZ" > "$DUMP_SQL" || fail "gunzip of the database dump failed"
    # The window is deliberately wider than the marker's current position. pg_dump
    # writes the marker near the end but not necessarily last: PostgreSQL's
    # August-2025 minors added a trailing `\unrestrict` line, which on the lab put
    # the marker at line 6243 of 6247 - inside a 5-line window by exactly zero
    # lines to spare. One more trailer from any future pg_dump and this check
    # would reject EVERY snapshot as truncated, breaking rollback completely.
    # It stays a tail window rather than a whole-file grep on purpose: this panel
    # stores operator-authored text, so the marker string can legitimately appear
    # inside the data and a whole-file grep could not tell that from a real end.
    if ! tail -20 "$DUMP_SQL" | grep -c 'PostgreSQL database dump complete' >/dev/null; then
        fail "database dump is truncated (completion marker absent) - refusing to apply it"
    fi
    # awk rather than `grep -c`: grep exits 1 on a count of zero, so its status
    # cannot tell "no table" from "could not read the dump". awk exits non-zero
    # only on a real read error, which is fatal here - nothing is touched yet.
    EXPECT_TABLES="$(awk '/^CREATE TABLE/ { n++ } END { print n + 0 }' "$DUMP_SQL")" \
        || fail "could not count the tables in the database dump - nothing changed"
    log "dump verified complete: $EXPECT_TABLES CREATE TABLE statements"
else
    EXPECT_TABLES=0
    log "snapshot contains no database dump - skipping the database stage"
fi

# ── 3b. Off-site archive: refuse what cannot work BEFORE stopping anything ───
# Everything in this block either proves the archive fits this machine or
# prepares the extracted copy; nothing here touches the running panel, so each
# refusal leaves the box exactly as it was.
PDNS_DB=""
PDNS_SQL="$WORK/db/pdns.sql"
if [ "$RESTORE_MODE" = "dr" ]; then
    stage="dr-preflight"
    M_KIND="$(meta_field kind)"
    [ "$M_KIND" = "dr" ] \
        || fail "this is not an off-site disaster recovery archive (kind '${M_KIND:-none}') - nothing changed"
    [ -f "$DUMP_GZ" ] || fail "the off-site archive carries no database dump - nothing changed"
    [ -f "$WORK/etc/api.env" ] || fail "the off-site archive carries no api.env - nothing changed"

    # Same version: the archive has no binaries, so the installed ones must be
    # the ones its database belongs to.
    if ! INSTALLED_VERSION="$("$BIN_DIR/dockpanel-api" --version 2>/dev/null </dev/null)"; then
        fail "could not read the version of $BIN_DIR/dockpanel-api - nothing changed"
    fi
    INSTALLED_VERSION="${INSTALLED_VERSION##* }"
    if [ -z "$INSTALLED_VERSION" ] || [ "$INSTALLED_VERSION" != "$M_FROM" ]; then
        fail "version mismatch: the archive was taken by version $M_FROM and this machine runs ${INSTALLED_VERSION:-an unknown version}. Install version $M_FROM first (DOCKPANEL_VERSION=v$M_FROM bash install.sh) - nothing changed"
    fi
    M_ARCH="$(meta_field arch)"
    HOST_ARCH="$(uname -m)"
    if [ -z "$M_ARCH" ] || [ "$M_ARCH" != "$HOST_ARCH" ]; then
        fail "architecture mismatch: the archive was taken on ${M_ARCH:-an unknown architecture} and this machine is $HOST_ARCH - nothing changed"
    fi
    log "off-site archive matches this machine: version $INSTALLED_VERSION, architecture $HOST_ARCH"

    # api.env: everything from the archive (JWT_SECRET, SECRETS_ENCRYPTION_KEY,
    # AGENT_TOKEN...) except DATABASE_URL, which must stay this machine's own:
    # its PostgreSQL was created with its own password. Merged into the extracted
    # copy, so $ETC_DIR never holds the archive's URL even for a moment. The line
    # is never printed: awk writes it straight into a 0600 file.
    [ -f "$ETC_DIR/api.env" ] || fail "$ETC_DIR/api.env does not exist on this machine - nothing changed"
    CUR_URLS="$(awk '/^DATABASE_URL=/ { n++ } END { print n + 0 }' "$ETC_DIR/api.env")" \
        || fail "could not read $ETC_DIR/api.env - nothing changed"
    [ "$CUR_URLS" = "1" ] \
        || fail "$ETC_DIR/api.env must hold exactly one DATABASE_URL line (found $CUR_URLS) - nothing changed"
    ENV_MERGED="$WORK/etc/.api.env.merge"
    if ! ( umask 077; awk '
            FNR == NR { if (!got && $0 ~ /^DATABASE_URL=/) { keep = $0; got = 1 } next }
            /^DATABASE_URL=/ { if (!done) { print keep; done = 1 } next }
            { print }
            END { if (!done) print keep }
        ' "$ETC_DIR/api.env" "$WORK/etc/api.env" > "$ENV_MERGED" ); then
        fail "could not merge DATABASE_URL into the restored api.env - nothing changed"
    fi
    chmod 0600 "$ENV_MERGED" || fail "could not restrict the merged api.env to 0600 - nothing changed"
    if ! cmp -s <(grep '^DATABASE_URL=' "$ETC_DIR/api.env") <(grep '^DATABASE_URL=' "$ENV_MERGED"); then
        fail "the merged api.env does not carry this machine's DATABASE_URL - nothing changed"
    fi
    mv "$ENV_MERGED" "$WORK/etc/api.env" || fail "could not place the merged api.env - nothing changed"
    log "api.env prepared: the archive's settings with this machine's DATABASE_URL"

    # agent.token must be the AGENT_TOKEN the restored api.env hands the api, or
    # the api cannot talk to its own agent. Never printed.
    ARCHIVE_TOKEN="$(awk '/^AGENT_TOKEN=/ { sub(/^AGENT_TOKEN=/, ""); print; exit }' "$WORK/etc/api.env")" \
        || fail "could not read AGENT_TOKEN from the restored api.env - nothing changed"
    if [ -n "$ARCHIVE_TOKEN" ]; then
        CUR_ARCHIVE_TOKEN=""
        if [ -f "$WORK/etc/agent.token" ]; then
            CUR_ARCHIVE_TOKEN="$(tr -d '[:space:]' < "$WORK/etc/agent.token")" \
                || fail "could not read the archive's agent.token - nothing changed"
        fi
        if [ "$CUR_ARCHIVE_TOKEN" != "$ARCHIVE_TOKEN" ]; then
            if ! ( umask 077; printf '%s\n' "$ARCHIVE_TOKEN" > "$WORK/etc/.agent.token.merge" ); then
                fail "could not write agent.token - nothing changed"
            fi
            mv "$WORK/etc/.agent.token.merge" "$WORK/etc/agent.token" \
                || fail "could not place agent.token - nothing changed"
            log "agent.token aligned with AGENT_TOKEN of the restored api.env"
        fi
    else
        log "the restored api.env has no AGENT_TOKEN line: agent.token is restored as it is"
    fi
    ARCHIVE_TOKEN=""
    CUR_ARCHIVE_TOKEN=""

    # The agent TLS pair goes back whole or not at all: half of it over this
    # machine's pair would leave a certificate without its key.
    if [ -f "$WORK/etc/ssl/agent.crt" ] && [ ! -f "$WORK/etc/ssl/agent.key" ]; then
        rm -f "$WORK/etc/ssl/agent.crt" || fail "could not drop the lone agent.crt - nothing changed"
        log "the archive has agent.crt without agent.key: this machine's agent TLS pair is kept"
    elif [ -f "$WORK/etc/ssl/agent.key" ] && [ ! -f "$WORK/etc/ssl/agent.crt" ]; then
        rm -f "$WORK/etc/ssl/agent.key" || fail "could not drop the lone agent.key - nothing changed"
        log "the archive has agent.key without agent.crt: this machine's agent TLS pair is kept"
    fi

    # PowerDNS zones (gpgsql): proven complete now, applied after the panel's
    # database.
    if [ -f "$WORK/db/pdns.sql.gz" ]; then
        PDNS_DB="$(meta_field pdns_database)"
        case "$PDNS_DB" in
            ''|*[!A-Za-z0-9_]*) fail "the archive has a PowerDNS dump but no valid pdns_database name - nothing changed" ;;
        esac
        gunzip -c "$WORK/db/pdns.sql.gz" > "$PDNS_SQL" || fail "gunzip of the PowerDNS dump failed - nothing changed"
        if ! tail -20 "$PDNS_SQL" | grep -c 'PostgreSQL database dump complete' >/dev/null; then
            fail "the PowerDNS dump is truncated (completion marker absent) - nothing changed"
        fi
        log "PowerDNS dump verified complete (database $PDNS_DB)"
    fi
fi

# ── 4. Stop services ─────────────────────────────────────────────────────────
# Everything below runs with nothing executing from /usr/local/bin, which is what
# makes the binary swap safe (lesson #48: you cannot write over a running
# executable; rename works, but not running at all is better still).
stage="stop-services"
log "stopping dockpanel-api and dockpanel-agent"
services_stopped=1
# What matters is that the unit is not RUNNING: an api still up while the schema
# is dropped would write into a database being replaced, and its binary is about
# to be swapped. So a stop that errors is only fatal if the unit is still
# active. Before the commit, so `fail` is safe: the trap brings both back.
stop_service() {
    local unit="$1"
    if systemctl stop "$unit"; then
        return 0
    fi
    if systemctl is-active --quiet "$unit"; then
        fail "could not stop $unit - nothing changed"
    fi
    log "systemctl stop $unit reported an error, but $unit is not running - continuing"
}
stop_service dockpanel-api
stop_service dockpanel-agent

# ── 5. Database (the destructive stage; atomic) ──────────────────────────────
# ON_ERROR_STOP=1 + --single-transaction is the difference between a restore that
# can destroy the database while reporting success and one that either fully
# applies or changes nothing. Verified both ways on a lab box against a
# deliberately truncated stream: without the flags psql exited 0 having left 1 of
# 92 tables; with them it exited 3 and all 92 survived.
stage="database"
if [ -f "$DUMP_SQL" ]; then
    docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 \
        || fail "postgres container '$PG_CONTAINER' is not accepting connections"

    # Undo for the undo. The transaction below makes a FAILED restore harmless,
    # but a SUCCESSFUL one is still a destructive act the operator may regret -
    # so capture where they were first. pipefail because the exit status of
    # `pg_dump | gzip` is gzip's, and gzip exits 0 on a truncated stream.
    stage="pre-rollback-dump"
    PRE_DUMP="$STATE_DIR/pre-rollback-$SNAP_ID.sql.gz"
    # umask 077 so the dump is never readable by anyone else, not even for the
    # moment before the chmod below.
    if bash -c "set -o pipefail; umask 077; docker exec '$PG_CONTAINER' pg_dump -U '$PG_USER' --clean --if-exists '$PG_DB' | gzip > '$PRE_DUMP'"; then
        # The whole database is in this file. A leftover from an earlier run of
        # the same snapshot keeps its old mode through the redirection, so the
        # mode is still set explicitly, and a dump that cannot be restricted
        # stops the restore: nothing has changed yet.
        chmod 0600 "$PRE_DUMP" \
            || fail "could not restrict $PRE_DUMP to mode 0600 - refusing to proceed, nothing changed"
        log "pre-rollback state saved to $PRE_DUMP"
        # These are now the only way back from a rollback, so they are worth
        # keeping - but nothing else in the product ever deletes them (the
        # retention sweep walks panel_snapshots rows and tarballs, not this
        # directory), and one is written on every rollback. Keep the newest few.
        # A failed prune must never fail a restore, so it is reported, not fatal.
        ls -1t "$STATE_DIR"/pre-rollback-*.sql.gz 2>/dev/null | tail -n +4 | while read -r old; do
            rm -f "$old" || log "could not prune stale pre-rollback dump $old"
        done
    else
        fail "could not capture the pre-rollback database state - refusing to proceed"
    fi

    stage="database"
    log "restoring database (atomic, $EXPECT_TABLES tables expected)"
    # The schema is torn down first, in the SAME transaction as the dump.
    #
    # `pg_dump --clean` only emits DROP statements for objects the dump itself
    # contains, so before this, anything created AFTER the snapshot outlived a
    # restore of it. That left a database that matched neither version: the newer
    # version's tables were still present while `_sqlx_migrations` had been
    # rewound to the older state, so a later forward update re-ran a migration
    # whose objects already existed. MEASURED on a lab box: the api panicked at
    # startup with `relation "..." already exists`, exited 101, and crash-looped
    # under Restart=always until it hit StartLimitBurst - a permanent 502 from a
    # rollback that had reported success. Dropping the schema makes a restore an
    # actual point-in-time revert instead of a merge.
    #
    # Owner and ACL are restored explicitly because the dump carries neither: a
    # bare CREATE SCHEMA would hand `public` to the restoring role and drop
    # PUBLIC's USAGE grant, silently changing the database's permissions on every
    # rollback. Verified to reproduce the original owner and ACL exactly.
    #
    # This is still all-or-nothing. The DROP is inside psql's --single-transaction,
    # so a dump that fails to apply rolls the teardown back with it and the
    # database is left exactly as it was. The pre-rollback dump taken above is the
    # second line of defence.
    # Assembled into a REGULAR FILE and fed to psql by redirection - never piped.
    # A pipe would put a live producer back in front of psql, which is the whole
    # defect this file exists to prevent: if the producer dies mid-stream psql
    # sees a clean EOF, and --single-transaction then COMMITS a dropped schema
    # plus half a dump. `set +e` below suppresses errexit but NOT pipefail, so the
    # status would also be the producer's rather than psql's, and the "nothing
    # changed" message below would be printed over a destroyed database. Same
    # reason the dump itself is decompressed to a file at the verify-dump stage.
    PREAMBLE_SQL="$WORK/db/preamble.sql"
    APPLY_SQL="$WORK/db/apply.sql"
    printf '%s\n' \
        'DROP SCHEMA IF EXISTS public CASCADE;' \
        'CREATE SCHEMA public;' \
        'ALTER SCHEMA public OWNER TO pg_database_owner;' \
        'GRANT USAGE ON SCHEMA public TO PUBLIC;' \
        > "$PREAMBLE_SQL" || fail "could not stage the schema teardown - nothing changed"
    cat "$PREAMBLE_SQL" "$DUMP_SQL" > "$APPLY_SQL" \
        || fail "could not assemble the restore stream - nothing changed"
    # Byte-exact, so a short write is caught before anything is destroyed rather
    # than presented to psql as a complete input.
    A_SZ="$(stat -c%s "$APPLY_SQL")"; P_SZ="$(stat -c%s "$PREAMBLE_SQL")"; D_SZ="$(stat -c%s "$DUMP_SQL")"
    if [ "$A_SZ" != "$(( P_SZ + D_SZ ))" ]; then
        fail "assembled restore stream is short ($A_SZ vs $(( P_SZ + D_SZ )) bytes) - nothing changed"
    fi
    set +e
    docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" \
        -X -q -v ON_ERROR_STOP=1 --single-transaction \
        < "$APPLY_SQL" > "$WORK/psql.out" 2> "$WORK/psql.err"
    DB_RC=$?
    set -e
    if [ "$DB_RC" != "0" ]; then
        # The transaction rolled back: the database is exactly as it was, and
        # no binary or config has been touched yet. Nothing is lost.
        fail "database restore failed (psql exit $DB_RC), transaction rolled back, nothing changed: $(tail -3 "$WORK/psql.err" | tr '\n' ' ')"
    fi
    # The point of no return. Everything from here to the binary swap is the
    # window `rollback_would_be_undone` describes.
    db_committed=1

    # "psql exited 0" is not the success condition - the schema is (lesson #45).
    #
    # Deliberately still a floor, even though the teardown now makes a surplus
    # structurally impossible: an equality would trip on a table the dump creates
    # outside `public`, or on any counting mismatch between the grep and the
    # catalogue query.
    #
    # It REPORTS rather than aborts, which is the s231 fix. The transaction has
    # already committed, so there is no longer anything to protect by stopping -
    # aborting here used to trip the exit trap, restart the still-installed NEWER
    # api against the just-reverted database, and let it migrate the database
    # forward again, quietly undoing the rollback it was reporting as failed.
    # Carrying on puts the matching binaries back and leaves the box consistent;
    # the operator learns about the shortfall from the result file instead of
    # from a box that silently re-applied the update they rolled away from.
    #
    # A non-numeric answer is treated the same way, and on purpose: the usual
    # reason this query returns junk is that docker or postgres is unreachable
    # for a moment, and `[ x -lt y ]` on junk is itself an errexit abort - inside
    # exactly the window that must not abort.
    #
    # The query sits in a condition for the same reason: under pipefail a failing
    # `docker exec` makes the assignment itself fail, and a bare failing
    # assignment is an errexit abort. An unanswered query lands in the empty case.
    stage="database-verify"
    if ! GOT_TABLES="$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAq \
        -c "select count(*) from information_schema.tables where table_schema='public' and table_type='BASE TABLE'" | tr -d ' \r')"; then
        GOT_TABLES=""
    fi
    case "$GOT_TABLES" in
        ''|*[!0-9]*)
            degrade "post-restore schema check could not read a table count (got '${GOT_TABLES:-none}')" ;;
        *)
            if [ "$GOT_TABLES" -lt "$EXPECT_TABLES" ]; then
                degrade "post-restore schema check failed: expected >= $EXPECT_TABLES tables, found $GOT_TABLES"
            else
                log "database restored and verified: $GOT_TABLES tables"
            fi ;;
    esac

    # Put the snapshot we just restored FROM back into the restored database,
    # and mark it used.
    #
    # Two things conspire here. A snapshot's dump is taken BEFORE its own row is
    # inserted, so the dump does not contain that row - restoring therefore
    # DELETES the very snapshot the operator restored from, leaving its tarball
    # on disk with nothing listing it. And a stamp written before the restore is
    # overwritten by the restore itself. Both were observed on a lab box
    # (rolled_back_at came back empty and the row was gone). So the row is
    # re-established here, from the tarball we can see and the metadata inside
    # it, and marked as rolled back.
    #
    # A pre-update row is also closed here, on the version it was taken from. Left
    # open, the next boot takes it for an update that has just failed and journals
    # `update.rolled_back` with the motive of the last update, which is how a
    # manual rollback came to be logged as "passed the post-deploy health checks".
    # Closing it here is what also reaches an older api booted from the snapshot.
    # Manual snapshots never carry a `to_version`.
    stage="record-rollback"
    M_TRIG="$(meta_field trigger)";      [ -n "$M_TRIG" ] || M_TRIG="manual"
    case "$M_TRIG" in
        pre-update:*) TO_SQL="'$(sqlq "$M_FROM")'" ;;
        *)            TO_SQL="NULL" ;;
    esac
    M_CREATED="$(meta_field created_at)"
    M_OPER="$(meta_field operator)"
    # Inside the post-commit window: an unreadable size is reported and recorded
    # as 0, never raised.
    if ! SIZE_BYTES="$(stat -c%s "$TARBALL")"; then
        SIZE_BYTES=0
        degrade "the snapshot size could not be read, so it is recorded as 0 bytes"
    fi
    if [ -n "$M_OPER" ]; then OPER_SQL="'$(sqlq "$M_OPER")'"; else OPER_SQL="NULL"; fi
    if [ -n "$M_CREATED" ]; then CREATED_SQL="'$(sqlq "$M_CREATED")'"; else CREATED_SQL="NOW()"; fi

    # Bookkeeping, and bookkeeping only - so it reports rather than aborts, for
    # the same reason as the check above. This INSERT is the likeliest thing in
    # the whole post-commit window to fail on a real box: it runs against the
    # schema the snapshot restored, so rolling back far enough that
    # `panel_snapshots` had a different shape is enough to break it. Losing the
    # row costs a listing entry and a `rolled_back_at` stamp; aborting used to
    # cost the rollback itself.
    #
    # An off-site archive is not a local snapshot: its decrypted tarball is
    # deleted when this script exits, so a row would list a file that is gone.
    if [ "$RESTORE_MODE" = "dr" ]; then
        log "off-site restore: no local snapshot row is recorded (the decrypted archive is removed at the end)"
    elif docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAq -v ON_ERROR_STOP=1 -c \
"INSERT INTO panel_snapshots (id, file_path, from_version, to_version, trigger, operator, size_bytes, sha256, created_at, rolled_back_at)
 VALUES ('$SNAP_ID', '$(sqlq "$TARBALL")', '$(sqlq "$M_FROM")', $TO_SQL, '$(sqlq "$M_TRIG")', $OPER_SQL, $SIZE_BYTES, '$(sqlq "$EXPECT_SHA")', $CREATED_SQL, NOW())
 ON CONFLICT (id) DO UPDATE SET rolled_back_at = NOW(), to_version = COALESCE(panel_snapshots.to_version, EXCLUDED.to_version)" >/dev/null 2>&1; then
        log "recorded rollback against snapshot $SNAP_ID"
    else
        degrade "restore applied but the rollback could not be recorded in panel_snapshots (the snapshot will not be listed as rolled back)"
    fi

    # The PowerDNS zones of an off-site archive (proven complete before the
    # services stopped). After the panel's database has committed, so a problem
    # here is reported and the restore carries on: the zones can be restored
    # again from the DNS backups, the panel cannot be half put back.
    #
    # Atomic on its own: the file opens a transaction and only its last line
    # commits it, and ON_ERROR_STOP ends psql at the first error, so an error or
    # a short file rolls everything back. Fed from a regular file, never piped.
    stage="pdns"
    if [ -n "$PDNS_DB" ] && [ -f "$PDNS_SQL" ]; then
        if ! PDNS_EXISTS="$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAq \
            -c "SELECT 1 FROM pg_database WHERE datname = '$(sqlq "$PDNS_DB")'" </dev/null | tr -d ' \r')"; then
            PDNS_EXISTS=""
        fi
        if [ "$PDNS_EXISTS" != "1" ]; then
            degrade "the PowerDNS database '$PDNS_DB' does not exist on this machine, so the DNS zones were not restored: set up PowerDNS with gpgsql, then restore the zones from a DNS backup"
        else
            PDNS_APPLY="$WORK/db/pdns-apply.sql"
            if { printf '%s\n' 'BEGIN;' 'DROP SCHEMA IF EXISTS public CASCADE;' 'CREATE SCHEMA public;' \
                    'ALTER SCHEMA public OWNER TO pg_database_owner;' 'GRANT USAGE ON SCHEMA public TO PUBLIC;' \
                    && cat "$PDNS_SQL" && printf '%s\n' 'COMMIT;'; } > "$PDNS_APPLY"; then
                set +e
                docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PDNS_DB" -X -q -v ON_ERROR_STOP=1 \
                    < "$PDNS_APPLY" > "$WORK/pdns.out" 2> "$WORK/pdns.err"
                PDNS_RC=$?
                set -e
                if [ "$PDNS_RC" = "0" ]; then
                    log "PowerDNS database $PDNS_DB restored"
                else
                    degrade "the PowerDNS database $PDNS_DB could not be restored (psql exit $PDNS_RC, rolled back, the zones are as before): $(tail -3 "$WORK/pdns.err" | tr '\n' ' ')"
                fi
            else
                degrade "the PowerDNS restore stream could not be assembled, so the DNS zones were not restored"
            fi
        fi
    fi
fi

# ── 6. Binaries ──────────────────────────────────────────────────────────────
# Services are stopped, so a plain mv is safe and atomic. Each binary keeps a
# .prerestore copy. No failure is silenced anywhere in this file: a restore that
# cannot restore must say so (lesson #48).
stage="binaries"
# An off-site archive carries none: the installed ones were checked to be the
# archive's version before anything stopped.
if [ "$RESTORE_MODE" = "dr" ]; then
    BINS=()
    log "off-site restore: the installed binaries (version $INSTALLED_VERSION) are kept"
fi
for bin in "${BINS[@]}"; do
    src="$WORK/binaries/$bin"
    dst="$BIN_DIR/$bin"
    if [ ! -f "$src" ]; then
        log "snapshot has no $bin - leaving the installed one in place"
        continue
    fi
    if [ -f "$dst" ]; then
        cp -a "$dst" "$dst.prerestore" || fail "could not back up $dst"
    fi
    install -m 0755 "$src" "$dst.restoring" || fail "could not stage $bin"
    mv "$dst.restoring" "$dst" || fail "could not move $bin into place"
    # The moment the mismatch is over: the code that will run against the
    # restored database is now the code that database belongs to.
    #
    # An `if`, not `[ ... ] && api_reverted=1`. Under `set -e` that AND-list
    # returns non-zero for every binary that is not the api, and a bare failing
    # list is an errexit abort - it would have killed the restore on the first
    # loop iteration, inside the very window this flag exists to protect.
    if [ "$bin" = "dockpanel-api" ]; then
        api_reverted=1
    fi
    log "restored $dst"
done

# ── 6b. Frontend ─────────────────────────────────────────────────────────────
# Prepared beside the live directory, then swapped by rename. Not fatal: the api
# and the database already agree, and stopping here would strand the box. A
# snapshot taken before the frontend was archived simply has none to restore.
stage="frontend"
if [ "$RESTORE_MODE" = "dr" ]; then
    log "off-site restore: the installed frontend is kept"
elif [ -f "$WORK/frontend/dist/index.html" ]; then
    if rm -rf "$FRONTEND_DIR/dist.restoring" "$FRONTEND_DIR/dist.prerestore" \
        && mkdir -p "$FRONTEND_DIR" \
        && cp -a "$WORK/frontend/dist" "$FRONTEND_DIR/dist.restoring"; then
        had_frontend=0
        if [ -d "$FRONTEND_DIR/dist" ]; then
            had_frontend=1
        fi
        if [ "$had_frontend" = "1" ] && ! mv "$FRONTEND_DIR/dist" "$FRONTEND_DIR/dist.prerestore"; then
            degrade "the frontend could not be restored: the installed one is still served"
        elif mv "$FRONTEND_DIR/dist.restoring" "$FRONTEND_DIR/dist"; then
            log "restored $FRONTEND_DIR/dist"
        else
            if [ "$had_frontend" = "1" ] && ! mv "$FRONTEND_DIR/dist.prerestore" "$FRONTEND_DIR/dist"; then
                degrade "the frontend could not be put back: the previous one is in $FRONTEND_DIR/dist.prerestore"
            else
                degrade "the frontend could not be restored: the installed one is still served"
            fi
        fi
    else
        degrade "the frontend could not be staged: the installed one is still served"
    fi
else
    log "snapshot has no frontend - leaving the installed one in place"
fi

# ── 7. /etc/dockpanel ────────────────────────────────────────────────────────
# Treated as fatal, not best-effort: api.env carries JWT_SECRET and the database
# password, so a half-applied /etc against a fully-restored database is a broken
# panel, not a warning.
#
# The safety copy is required, not best-effort: it is the only way back to the
# api.env this overwrites, and the likeliest reason it cannot be made (a full
# disk) would also break the copy below halfway. Failing here is the existing
# answer for this stage: the api binary is already the snapshot's, so the trap
# restarts the panel on the config it has now. A box with no config directory
# yet has nothing to keep.
stage="etc"
etc_restored=0
if [ -d "$WORK/etc" ]; then
    ETC_SAFETY="$ETC_DIR.prerestore.$SNAP_ID"
    if [ -d "$ETC_DIR" ]; then
        # A leftover from an earlier restore of the same snapshot would make
        # `cp -a` nest the new copy inside it, and the token removal below would
        # then miss the nested token.
        rm -rf "$ETC_SAFETY" || fail "could not clear the stale safety copy $ETC_SAFETY - $ETC_DIR left untouched"
        cp -a "$ETC_DIR" "$ETC_SAFETY" || fail "could not make the safety copy $ETC_SAFETY - $ETC_DIR left untouched"
        # The restore never touches the update token, so the safety copy needs
        # none: a token cleared later must not survive in it.
        if ! rm -rf "$ETC_SAFETY/update-token" "$ETC_SAFETY"/.update-token.tmp-*; then
            degrade "the update token could not be removed from the safety copy $ETC_SAFETY: delete it by hand"
        fi
    else
        log "$ETC_DIR does not exist yet - no safety copy to make"
    fi
    cp -a "$WORK/etc/." "$ETC_DIR/" || fail "restoring $ETC_DIR failed"
    etc_restored=1
    log "restored $ETC_DIR"
    if [ "$RESTORE_MODE" = "dr" ]; then
        # Same binaries (checked before the stop), and now the api.env the
        # restored database was written with: the api agrees with it again.
        api_reverted=1
        # The vhosts are not in the archive: the api rebuilds every local site's
        # from the restored database at its next start, and reports. An older
        # report is removed so nobody reads it as this restore's.
        if ! rm -f "$STATE_DIR/vhost-rebuild.json"; then
            degrade "the previous vhost rebuild report could not be removed"
        fi
        if printf '%s\n' "$SNAP_ID" > "$STATE_DIR/vhost-rebuild.pending"; then
            log "vhost rebuild requested for the next api start"
        else
            degrade "the vhost rebuild marker could not be written: rebuild the sites by saving each one, or create $STATE_DIR/vhost-rebuild.pending and restart dockpanel-api"
        fi
    fi
fi

# ── 7b. nginx ────────────────────────────────────────────────────────────────
# /etc/dockpanel/ssl holds the certificates the site vhosts point at, and the
# ACME account, so the stage above may just have swapped the files nginx serves.
# nginx keeps the old ones in memory until it reloads, and a reload with a
# broken configuration is refused anyway - so the configuration is tested first
# and only a configuration that passes is loaded.
#
# Everything here is after the point of no return (the binaries and /etc are
# already the snapshot's), so nothing in this stage may `fail`: a problem is a
# `degrade`, which tells the operator while the box stays consistent. A box
# without nginx, or with nginx stopped, has nothing to reload.
stage="nginx"
if [ "$etc_restored" != "1" ]; then
    log "the snapshot restored no $ETC_DIR - nginx left alone"
elif ! systemctl is-active --quiet nginx; then
    log "nginx is not installed or not running - no reload needed"
elif ! command -v nginx >/dev/null 2>&1; then
    degrade "nginx is running but its binary is not on PATH, so its configuration could not be tested and it was not reloaded"
elif ! nginx_test_out="$(nginx -t 2>&1)"; then
    # The output names the file and line at fault; it holds no secret.
    degrade "nginx -t failed after the restore, so nginx was NOT reloaded and still serves its previous certificates: $(printf '%s\n' "$nginx_test_out" | tail -3 | tr '\n' ' ')"
elif ! systemctl reload nginx; then
    degrade "nginx -t passed but systemctl reload nginx failed: nginx still serves its previous certificates"
else
    log "nginx configuration tested and nginx reloaded"
fi

# ── 8. Start + prove it came back ────────────────────────────────────────────
stage="start-services"
# Nothing this script restores is a unit file, so a failed daemon-reload changes
# nothing the start below depends on - but it does mean systemd is unwell, which
# the operator should hear about.
if ! systemctl daemon-reload; then
    degrade "systemctl daemon-reload failed after the restore"
fi
systemctl start dockpanel-agent || fail "dockpanel-agent failed to start after restore"
sleep 1

# The same guard as the exit trap, on the SUCCESS path - because this window can
# be reached without anything having failed at all. If the snapshot carried no
# dockpanel-api binary, the loop above skipped it with a note and fell through to
# here with the database reverted and the newer api still installed: starting it
# would migrate the database forward as the last act of a restore reporting
# success. Refusing is the same answer as in the trap, for the same reason.
if rollback_would_be_undone; then
    services_stopped=0
    if [ "$RESTORE_MODE" = "dr" ]; then
        degrade "the off-site archive restored the database but not $ETC_DIR, so the installed api.env does not match it; dockpanel-api has been left stopped"
    else
        degrade "the snapshot contains no dockpanel-api binary, so the database was reverted while the installed api was not; dockpanel-api has been left stopped"
    fi
    log "NOT starting dockpanel-api: $degraded"
    write_result false "$stage" "$degraded$(hazard_note)"
    finished=1
    exit 1
fi

systemctl start dockpanel-api || fail "dockpanel-api failed to start after restore"
services_stopped=0

# Opt-in service: restarted only if it was running, so it runs the restored binary.
if ! systemctl try-restart dockpanel-mcp 2>/dev/null; then
    degrade "dockpanel-mcp could not be restarted on the restored binary"
fi

stage="health"
HEALTH=""
for _ in $(seq 1 30); do
    # An `if`, not a silenced command: a per-attempt failure is expected while
    # the panel boots, but it must not be spelled the same way as a swallowed
    # error.
    if HEALTH="$(curl -fsS -m 3 "$HEALTH_URL" 2>/dev/null)"; then
        [ -n "$HEALTH" ] && break
    fi
    sleep 2
done
[ -n "$HEALTH" ] || fail "panel did not answer /api/health within 60s after restore"

stage="journal"
if [ -n "$degraded" ]; then
    journal_outcome="completed with warnings: $degraded"
else
    journal_outcome="completed"
fi
if ! journal_manual_rollback "$journal_outcome"; then
    degrade "the rollback could not be recorded in the activity log (journal entry missing)"
fi

# A degraded restore still RESTORED - the binaries, /etc and the database are all
# back on the snapshot and the panel answered. What did not pass is a check or
# the bookkeeping, so the verdict is ok=false (there is something to read) with
# exit 0 (there is nothing to recover). Collapsing the two into "failed" would
# put a working box behind the same words as a box that needs an operator, which
# is the distinction the whole result file exists to make.
if [ -n "$degraded" ]; then
    log "restore complete WITH WARNINGS: $degraded"
    write_result false "$degraded_stage" "restored snapshot $SNAP_ID, but: $degraded - the panel is running and consistent; health: $HEALTH"
else
    log "restore complete: $HEALTH"
    write_result true "complete" "restored snapshot $SNAP_ID; health: $HEALTH"
fi
finished=1
exit 0
