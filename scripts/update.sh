#!/usr/bin/env bash
#
# CyberHunter - Panel Updater
# Rebuilds (source mode) or installs (release mode) binaries + frontend,
# restarts services. Preserves database, secrets, and configuration.
#
# Usage: BUILD_FROM_SOURCE=1 bash scripts/update.sh   # compile the tree this script sits in
#
# Release mode (INSTALL_FROM_RELEASE=1) is started by the panel (Telemetry,
# Updates), never by hand. This script downloads nothing: the panel binary has
# already fetched the release, checked the minisign signature of checksums.txt
# and the SHA-256 of every file, and placed it in a root-only directory passed
# as CYBERHUNTER_RELEASE_DIR. The script runs from <release>/cyberhunter-source
# /scripts/, so the units, nginx templates and install-agent.sh it deploys come
# from that verified release, and it re-checks the SHA-256 of every file it
# installs against $CYBERHUNTER_RELEASE_DIR/checksums.txt before touching the box.
#
set -euo pipefail

# ── Escape the caller's service cgroup ────────────────────────────────────
# When the panel triggers an update it spawns this script from inside
# dockpanel-api.service. That unit is KillMode=control-group (the systemd
# default), so the `systemctl stop dockpanel-agent dockpanel-api` further down
# SIGTERMs every process in the cgroup - including this script, one line before
# it swaps the binaries. The box is then left with both services stopped and the
# old binaries still in place. Setting a POSIX process group (which the
# orchestrator does) does not help: systemd kills by cgroup, not process group.
#
# Re-exec into a transient scope so we live outside the unit being stopped.
# Harmless for the normal SSH invocation - that cgroup never matches.
# Must be a transient *service* (PID1-owned), not `--scope`: a scope is created
# in the caller's context, so it lands in the invoking session's user-0.slice and
# dies with it ("Removed slice user-0.slice" - observed killing an update
# mid-swap). A transient service is owned by PID1 and outlives both the unit
# being stopped and any session.
if [ -z "${DOCKPANEL_UPDATE_DETACHED:-}" ] && command -v systemd-run >/dev/null 2>&1; then
    if grep -qE 'dockpanel-(api|agent)\.service' /proc/self/cgroup 2>/dev/null; then
        echo "[+] Re-executing outside the panel's service cgroup..."
        exec systemd-run --quiet --collect \
            --unit="dockpanel-self-update-$$" \
            --setenv=DOCKPANEL_UPDATE_DETACHED=1 \
            --setenv=INSTALL_FROM_RELEASE="${INSTALL_FROM_RELEASE:-}" \
            --setenv=DOCKPANEL_VERSION="${DOCKPANEL_VERSION:-}" \
            --setenv=CYBERHUNTER_RELEASE_DIR="${CYBERHUNTER_RELEASE_DIR:-}" \
            bash "$0" "$@"
    fi
fi

# ── The verdict file ──────────────────────────────────────────────────────
# Why this exists (F1, s231→s282): the panel orchestrator spawns this script and
# waits on the child. But the block above `exec systemd-run`s without `--wait`,
# and systemd-run returns 0 the instant PID1 ACCEPTS the job - measured at ~29ms
# against a real update that runs ~54s. So the orchestrator's child exits 0
# almost immediately, its stdout pipe hits EOF one line in, and the exit status
# it observes belongs to systemd-run rather than to the update.
#
# For a SUCCESSFUL update that does not matter much: this script stops
# dockpanel-api, the orchestrator dies with it, and the next boot works out what
# happened. The case that was broken is a failure BEFORE the services are
# stopped - a bad download, a missing file, a failed database backup. The api is
# never stopped, so no restart ever comes to carry a verdict; the orchestrator
# saw exit 0 and finalises nothing; and the operator watches an in-flight update
# frozen on "Re-executing outside the panel's service cgroup…" until the
# 15-minute window lapses, with the real error only in the transient unit's
# journal.
#
# The fix is the one the agent side already uses (`last-agent-update.json`) and
# the restore already uses (`last-restore.json`): write the outcome to a file
# that outlives the process. `--pipe` is NOT the alternative - it implies
# `--wait` and wires the unit's stdout to a caller that is about to be killed, so
# the updater would take SIGPIPE on its next log line, mid binary swap.
DOCKPANEL_STATE_DIR="${DOCKPANEL_STATE_DIR:-/var/lib/dockpanel}"
_dockpanel_result="$DOCKPANEL_STATE_DIR/last-panel-update.json"
_dockpanel_stage="preflight"
_dockpanel_finished=0

_dockpanel_json_escape() {
    printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

_dockpanel_write_result() {
    local ok="$1" stage="$2" detail="$3"
    mkdir -p "$DOCKPANEL_STATE_DIR" 2>/dev/null || return 0
    local tmp="$_dockpanel_result.tmp"
    printf '{"target_version":"%s","ok":%s,"stage":"%s","detail":"%s","finished_at":"%s"}\n' \
        "$(_dockpanel_json_escape "${DOCKPANEL_VERSION:-}")" "$ok" "$stage" \
        "$(_dockpanel_json_escape "$detail")" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp" 2>/dev/null || return 0
    chmod 0600 "$tmp" 2>/dev/null || true
    mv "$tmp" "$_dockpanel_result" 2>/dev/null || true
}

# Safety net: if we get killed or fail after the services are stopped but before
# they are started again, bring them back rather than leaving the box dark.
_dockpanel_services_stopped=0
_dockpanel_on_exit() {
    local code=$?
    if [ "$_dockpanel_services_stopped" = "1" ]; then
        systemctl start dockpanel-agent dockpanel-api 2>/dev/null || true
    fi
    # The verified copies staged for a release install (root-only, in /tmp).
    if [ -n "${STAGE_DIR:-}" ] && [ -d "${STAGE_DIR:-}" ]; then
        rm -rf "$STAGE_DIR" 2>/dev/null || true
    fi
    # Every exit path leaves a verdict, including the ones nobody wrote by hand:
    # a `set -e` abort, a SIGTERM, a failed curl. Without this the only paths
    # that reported anything were the ones that happened to be instrumented.
    if [ "$_dockpanel_finished" != "1" ]; then
        _dockpanel_write_result false "$_dockpanel_stage" \
            "update aborted at stage '$_dockpanel_stage' with exit code $code"
    fi
}
trap _dockpanel_on_exit EXIT INT TERM

# ── Colors ────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[x]${NC} $1" >&2; }

# No download helper here any more (10, mises a jour): this script never
# fetches anything. In release mode every file comes from the directory the
# panel prepared and verified; in source mode it compiles the tree it sits in.

# ── Checks ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SRC="$REPO_DIR/panel/agent"
API_SRC="$REPO_DIR/panel/backend"
CLI_SRC="$REPO_DIR/panel/cli"
MCP_SRC="$REPO_DIR/panel/mcp"

# Directories the agent unit declares in ReadWritePaths, with any `-` prefix
# stripped. Derived from the unit that is about to be deployed (or, on a layout
# with no repo tree, the one already installed) so this can never fall behind it.
# Prints nothing if no unit is readable; callers must tolerate an empty result.
agent_rwp_dirs() {
    local unit="$AGENT_SRC/dockpanel-agent.service"
    [ -f "$unit" ] || unit="/etc/systemd/system/dockpanel-agent.service"
    [ -f "$unit" ] || return 0
    sed -n 's/^ReadWritePaths=//p' "$unit" | tr ' ' '\n' | sed 's/^-//' | grep '^/' || true
}
FRONTEND_DIR="$REPO_DIR/panel/frontend"
AGENT_BIN="/usr/local/bin/dockpanel-agent"
API_BIN="/usr/local/bin/dockpanel-api"
CLI_BIN="/usr/local/bin/dockpanel"
MCP_BIN="/usr/local/bin/dockpanel-mcp"
INSTALL_FROM_RELEASE="${INSTALL_FROM_RELEASE:-0}"

# ── Mode detection ────────────────────────────────────────────────────────
# Without a source tree or without cargo, this box can only be updated from a
# release - and a release update is started from the panel, which prepares and
# verifies the release first. The auto-detect is kept so that a bare
# `bash update.sh` on such a box stops with the message below instead of
# trying to compile nothing.
if [ "$INSTALL_FROM_RELEASE" != "1" ] && [ ! -d "$AGENT_SRC/src" ]; then
    log "No source found - this box can only be updated from a release"
    INSTALL_FROM_RELEASE=1
fi

# Production VPS installs typically don't have cargo on PATH (and usually
# don't have enough RAM to compile rustc's dep tree - proc-macro2 OOMs at
# ~1-2 GB).
if [ "$INSTALL_FROM_RELEASE" != "1" ] \
   && ! command -v cargo > /dev/null 2>&1 \
   && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    log "Rust toolchain not found - this box can only be updated from a release"
    log "(set BUILD_FROM_SOURCE=1 to force compile-from-source instead)"
    INSTALL_FROM_RELEASE=1
fi

# Explicit opt-in to keep compile-from-source behaviour even when cargo
# is on PATH (e.g. for developers iterating on a checkout).
if [ "${BUILD_FROM_SOURCE:-0}" = "1" ]; then
    INSTALL_FROM_RELEASE=0
fi

# ── Release mode: only from a release the panel has verified ──────────────
# There is no self-refresh and no repo sync any more. Both fetched code from a
# remote that, on servers installed before the fork, is the upstream project:
# a refreshed updater or a reset tree would have come from outside this
# project's signed releases. The trust chain is now: the panel binary verifies
# the minisign signature of checksums.txt (with its compiled-in key, and the
# trusted comment bound to the tag) and the SHA-256 of each file, then runs
# THIS script from inside that release. The script re-checks the SHA-256 of
# every file it installs below.
if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
    if [ -z "${CYBERHUNTER_RELEASE_DIR:-}" ]; then
        error "Release updates are started from the panel (Telemetry, Updates). To update by hand, build from source."
        exit 1
    fi
fi

# For source builds, verify source exists
if [ "$INSTALL_FROM_RELEASE" != "1" ] && [ ! -d "$AGENT_SRC/src" ]; then
    error "Cannot find agent source at $AGENT_SRC"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}CyberHunter - Panel Updater${NC}"
echo ""

# ── Release mode: re-check every file against checksums.txt ───────────────
# Before ANY change to the box (database dump included). Fail closed: a missing
# checksums.txt, a malformed one, a missing entry, a missing file or a hash
# mismatch aborts here, with nothing touched.
#
# Each file is COPIED to a root-only staging directory first and the COPY is
# hashed, so the bytes that are installed are the bytes that were checked (no
# window between the check and the use).
#
# The source tree this script runs from (<release>/cyberhunter-source) is
# checked too, fail closed: checksums.txt lists the archive, not its contents,
# so the archive is MANDATORY here (the panel keeps it in the release
# directory), its SHA-256 is checked, it is extracted to the staging directory
# and the tree this script runs from must be identical to it, file for file.
#
# Every archive is listed BEFORE it is extracted as root (check_release_archive):
# no absolute path, no `..`, nothing but regular files and directories. And it
# is extracted with --no-same-owner --no-same-permissions.
if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
    _dockpanel_stage="verify"
    case "$(uname -m)" in
        x86_64)         DL_ARCH="amd64" ;;
        aarch64|arm64)  DL_ARCH="arm64" ;;
        *) error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    RELEASE_TAG="${DOCKPANEL_VERSION:-}"
    case "$RELEASE_TAG" in
        [0-9]*) RELEASE_TAG="v$RELEASE_TAG" ;;
    esac
    RELEASE_DIR="$CYBERHUNTER_RELEASE_DIR"
    CHECKSUMS="$RELEASE_DIR/checksums.txt"
    if [ ! -f "$CHECKSUMS" ]; then
        error "No checksums.txt in $RELEASE_DIR - refusing to install unverified files"
        exit 1
    fi
    # The manifest format (one `<64 hex>  <name>` per line, LF only). A line
    # that does not match is a refusal, never a line to skip.
    if [ "$(tr -cd '\r' < "$CHECKSUMS" | wc -c)" -ne 0 ] \
       || grep -vcE '^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$' "$CHECKSUMS" >/dev/null; then
        error "checksums.txt in $RELEASE_DIR is malformed - refusing to install"
        exit 1
    fi
    STAGE_DIR="$(umask 077; mktemp -d /tmp/dockpanel-release-XXXXXX)"
    # verify_release_file <asset name> <staged copy>
    verify_release_file() {
        local asset="$1" dest="$2" expect actual
        expect=$(awk -v a="$asset" '$2 == a {print $1}' "$CHECKSUMS")
        if [ -z "$expect" ] || [ "$(printf '%s\n' "$expect" | wc -l)" -ne 1 ]; then
            error "checksums.txt for ${RELEASE_TAG:-this release} has no single entry for $asset - refusing to install"
            exit 1
        fi
        if [ ! -f "$RELEASE_DIR/$asset" ]; then
            error "$asset is missing from $RELEASE_DIR - refusing to install"
            exit 1
        fi
        cp "$RELEASE_DIR/$asset" "$dest"
        actual=$(sha256sum "$dest" | awk '{print $1}')
        if [ "$actual" != "$expect" ]; then
            error "sha256 mismatch for $asset: got $actual, expected $expect - refusing to install"
            exit 1
        fi
        log "Verified $asset (sha256)"
    }
    # check_release_archive <archive> [prefix]
    check_release_archive() {
        local archive="$1" prefix="${2:-}" name names verbose n_names n_types
        name=$(basename "$archive")
        if ! names=$(LC_ALL=C tar -tzf "$archive") || ! verbose=$(LC_ALL=C tar -tvzf "$archive"); then
            error "$name cannot be listed - refusing to install"
            exit 1
        fi
        n_names=$(printf '%s\n' "$names" | grep -c . || true)
        n_types=$(printf '%s\n' "$verbose" | grep -c . || true)
        if [ "$n_names" -eq 0 ] || [ "$n_names" -ne "$n_types" ]; then
            error "$name has an empty or ambiguous listing - refusing to install"
            exit 1
        fi
        if [ "$(printf '%s\n' "$names" | grep -cE '^/|(^|/)\.\.(/|$)' || true)" -ne 0 ]; then
            error "$name holds an absolute path or a .. component - refusing to install"
            exit 1
        fi
        if [ "$(printf '%s\n' "$verbose" | cut -c1 | grep -cv '^[-d]$' || true)" -ne 0 ]; then
            error "$name holds a link or a special file - refusing to install"
            exit 1
        fi
        if [ -n "$prefix" ] \
           && [ "$(printf '%s\n' "$names" | grep -cv "^${prefix}/" || true)" -ne 0 ]; then
            error "$name holds files outside ${prefix}/ - refusing to install"
            exit 1
        fi
    }
    # tree_digest <dir>: every path with its type, and the SHA-256 of every file.
    tree_digest() {
        (cd "$1" && LC_ALL=C find . -printf '%y %p\n' | LC_ALL=C sort \
            && LC_ALL=C find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)
    }
    verify_release_file "cyberhunter-agent-linux-${DL_ARCH}" "$STAGE_DIR/dockpanel-agent-new"
    verify_release_file "cyberhunter-api-linux-${DL_ARCH}"   "$STAGE_DIR/dockpanel-api-new"
    verify_release_file "cyberhunter-cli-linux-${DL_ARCH}"   "$STAGE_DIR/dockpanel-cli-new"
    verify_release_file "cyberhunter-mcp-linux-${DL_ARCH}"   "$STAGE_DIR/dockpanel-mcp-new"
    verify_release_file "cyberhunter-frontend.tar.gz"        "$STAGE_DIR/dockpanel-frontend.tar.gz"
    check_release_archive "$STAGE_DIR/dockpanel-frontend.tar.gz"
    # Mandatory, never "if it is still there": without it, nothing proves the
    # tree this script runs from is the one that was signed.
    verify_release_file "cyberhunter-source.tar.gz" "$STAGE_DIR/source.tar.gz"
    check_release_archive "$STAGE_DIR/source.tar.gz" "cyberhunter-source"
    mkdir "$STAGE_DIR/source-check"
    tar -xzf "$STAGE_DIR/source.tar.gz" -C "$STAGE_DIR/source-check" --no-same-owner --no-same-permissions
    if [ "$(tree_digest "$STAGE_DIR/source-check/cyberhunter-source")" != "$(tree_digest "$REPO_DIR")" ]; then
        error "The source tree in $REPO_DIR differs from the verified cyberhunter-source.tar.gz - refusing to install"
        exit 1
    fi
    rm -rf "$STAGE_DIR/source-check" "$STAGE_DIR/source.tar.gz"
    log "Verified the release source tree this updater runs from"
    for b in agent api cli mcp; do
        if [ "$(head -c 4 "$STAGE_DIR/dockpanel-${b}-new" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
            error "cyberhunter-${b}-linux-${DL_ARCH} is not an ELF executable - refusing to install"
            exit 1
        fi
        chmod 0755 "$STAGE_DIR/dockpanel-${b}-new"
    done
    log "Release ${RELEASE_TAG:-} verified from $RELEASE_DIR"
fi

# ── Backup database before upgrade ────────────────────────────────────────
_dockpanel_stage="db-backup"
BACKUP_DIR="/var/backups/dockpanel/db"
mkdir -p "$BACKUP_DIR"
# `>` creates 0666 & ~umask. This dump carries `servers.agent_token` in
# cleartext - the Bearer credential for every agent endpoint and the key the
# agent signs its own root-shell tickets with - so it is root-only. The two
# chmods repair a tree an older installer already left 0755/0644; the agent
# does the same at startup, but update.sh runs on panel boxes that may not
# restart the agent for hours.
#
# ⚠ The umask MUST stay inside the subshell. v2.88.0 set it bare at this line,
# which is top-level scope in a 1100-line script, so it governed every `mkdir`
# and `>` for the rest of the upgrade - including `mkdir -p "$FE_DIR"` below
# (nginx serves the SPA from there as www-data: 0700 makes every panel asset
# 403) and `/var/www/acme/.well-known/acme-challenge` (0700 breaks HTTP-01, so
# certificates stop renewing). Both are silent: `tar` restores its own archived
# modes, so the extracted tree looks right and only the parent is wrong.
# Scope it the way setup.sh already does at its three `$(umask 077; mktemp)`
# sites - the redirect is the only thing that needs it.
chmod 700 "$BACKUP_DIR" /var/backups/dockpanel 2>/dev/null || true
log "Backing up database..."
if ( umask 077; docker exec dockpanel-postgres pg_dump -U dockpanel dockpanel | gzip > "$BACKUP_DIR/pre-upgrade-$(date +%Y%m%d%H%M%S).sql.gz" ); then
    log "Database backup saved to $BACKUP_DIR/"
else
    error "Database backup failed, aborting upgrade"
    exit 1
fi

# ── Harden a legacy inline backup cron ────────────────────────────────────
# Installs predating v2.88.0 carry the daily dump as an INLINE crontab command
# whose bare `>` creates the file 0666 & ~umask - so the whole panel database,
# `servers.agent_token` in cleartext, lands 0644 on a box that also runs other
# people's PHP as www-data.
#
# v2.88.0 hardened the writer setup.sh EMITS, but nothing rewrote an existing
# install's crontab, and nothing could: setup.sh dedupes on the new script's
# path, which a legacy inline line never contains, so re-running setup leaves
# the old line in place and adds a SECOND daily dump. update.sh referenced
# crontab nowhere at all. The agent's startup sweep is what makes older dumps
# look correct - it repairs the tree once, at start, so the newest dump stays
# 0644 from 03:30 until the next agent restart.
#
# Prepending the umask is deliberately the whole fix: it needs no new file, it
# preserves whatever schedule the operator chose, and it is safe to run twice.
if crontab -l 2>/dev/null | grep -c 'pg_dump -U dockpanel.*/var/backups/dockpanel/db' >/dev/null \
   && ! crontab -l 2>/dev/null | grep 'pg_dump -U dockpanel' | grep -c 'umask 077' >/dev/null; then
    if crontab -l 2>/dev/null \
        | sed '\#/var/backups/dockpanel/db# s#docker exec dockpanel-postgres pg_dump#umask 077; docker exec dockpanel-postgres pg_dump#' \
        | crontab -; then
        log "Hardened legacy database-backup cron (umask 077)"
    else
        warn "Could not rewrite the legacy backup cron - dumps stay 0644 until it is fixed by hand"
    fi
fi

# ── Build or install binaries ─────────────────────────────────────────────
_dockpanel_stage="binaries"
if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
    # The binaries were verified and staged above; only the frontend is
    # unpacked here, from the verified staged copy.
    log "Installing frontend from the verified release..."
    FE_DIR="/opt/dockpanel/frontend"
    mkdir -p "$FE_DIR"
    # Modes through umask 022 whatever this process inherited: nginx serves
    # this tree as www-data.
    ( umask 022; tar xzf "$STAGE_DIR/dockpanel-frontend.tar.gz" -C "$FE_DIR" --no-same-owner --no-same-permissions )
    rm -f "$STAGE_DIR/dockpanel-frontend.tar.gz"
    log "Frontend updated"
else
    # Build from source
    # Detect Rust toolchain
    if command -v cargo &> /dev/null; then
        CARGO_CMD="cargo"
    elif [ -f "$HOME/.cargo/bin/cargo" ]; then
        CARGO_CMD="$HOME/.cargo/bin/cargo"
    else
        error "Rust toolchain not found, but BUILD_FROM_SOURCE=1 was requested."
        error "Without a toolchain, update this panel from its own interface (Telemetry, Updates)."
        error "If you really want to compile from source: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        error "(note: building from source needs ~4 GB RAM - most production VPSes won't have it)"
        exit 1
    fi

    log "Building agent..."
    (cd "$AGENT_SRC" && $CARGO_CMD build --release 2>&1 | tail -1)

    log "Building API..."
    (cd "$API_SRC" && $CARGO_CMD build --release 2>&1 | tail -1)

    log "Building CLI..."
    (cd "$CLI_SRC" && $CARGO_CMD build --release 2>&1 | tail -1)

    if [ -d "$MCP_SRC" ]; then
        log "Building MCP server..."
        (cd "$MCP_SRC" && $CARGO_CMD build --release 2>&1 | tail -1)
    fi

    if [ -d "$FRONTEND_DIR" ]; then
        log "Building frontend..."
        # `npm ci` installs EXACTLY the committed package-lock.json - the tree the
        # audit gates actually scanned. `npm install` re-resolves and can pull
        # versions no scanner here has ever seen, which silently un-ships a
        # dependency patch. Keep the fallback (a box whose lock has drifted should
        # still update) but never let it happen quietly, and never discard the
        # reason: sending both streams to /dev/null is how the RHEL agent install
        # failed for a year printing nothing at all.
        if ! (cd "$FRONTEND_DIR" && npm ci --silent); then
            warn "npm ci failed (reason above) - falling back to 'npm install'"
            warn "Dependencies will be RE-RESOLVED; the tree may differ from the audited lockfile"
            if ! (cd "$FRONTEND_DIR" && npm install --silent); then
                error "npm install also failed - the frontend build below will likely fail too"
            fi
        fi
        (cd "$FRONTEND_DIR" && npx vite build 2>&1 | tail -3)
        log "Frontend rebuilt"
    fi
fi

# ── Ensure required directories exist (may be new in this version) ────────
_dockpanel_stage="directories"
log "Ensuring required directories exist..."
mkdir -p /etc/dockpanel/ssl /var/run/dockpanel /var/backups/dockpanel
mkdir -p /var/www/acme/.well-known/acme-challenge
mkdir -p /var/lib/dockpanel/git
# Directories needed by agent ReadWritePaths (created only if missing), DERIVED
# FROM THE UNIT ABOUT TO BE DEPLOYED rather than hand-copied.
#
# systemd fails the namespace mount on a missing UNPREFIXED entry, so the agent
# would not start at all - loud. The dangerous half is the `-`-prefixed entries,
# which mean "bind IF IT EXISTS": when absent, systemd skips them silently, the
# unit starts and reports success, and every write beneath that path fails with
# `Read-only file system` until the next restart. The namespace is fixed at
# start, so creating the directory later does not rescue a running agent.
#
# This ran BEFORE the unit is refreshed and reloaded below, which is what makes
# the ordering work: the directories exist by the time the agent restarts.
#
# It used to be a literal list, hand-mirrored from setup.sh, and it drifted -
# /var/spool/cron reached the unit and setup.sh at s268 but never this loop, so
# an upgraded box with no cron spool got a silently unwritable one and the cron
# fix s268 shipped "so existing installs recover on upgrade" did not fully land
# on exactly those installs. Deriving the list closes the class, not the case.
for d in $(agent_rwp_dirs); do
    [ -d "$d" ] || mkdir -p "$d" 2>/dev/null || true
done
# Paths the agent reaches through an escape hatch, or that are not RWP entries.
for d in /run/opendkim /var/lib/nginx /var/cache/nginx/fastcgi; do
    [ -d "$d" ] || mkdir -p "$d" 2>/dev/null || true
done
echo "d /run/dockpanel 0755 root root -" > /etc/tmpfiles.d/dockpanel.conf 2>/dev/null || true

# v2.8.17: drop apt lock-wait config so agent's apt-get install/update/purge
# waits up to 5 min for the dpkg lock instead of failing immediately when
# unattended-upgrades is running in the background (common on fresh Debian).
# Idempotent - overwrites on every update.sh run, no apt operation needed.
if command -v apt-get &> /dev/null; then
    mkdir -p /etc/apt/apt.conf.d
    cat > /etc/apt/apt.conf.d/99-dockpanel-lock-wait.conf << 'APT_EOF'
DPkg::Lock::Timeout "300";
APT_EOF

    # v2.48.1: exclude the agent from needrestart's auto-restart list. A
    # panel-driven update runs apt from inside dockpanel-agent; because the
    # agent links libc, an ordinary libc6 upgrade made needrestart restart
    # dockpanel-agent.service mid-run and kill the process streaming the
    # update's own progress. apt itself survived (it runs in a systemd-run
    # transient scope), but the NDJSON stream died before its final
    # {"type":"done"} line, so the panel reported a clean 16-package upgrade
    # as "Update completed with errors" (measured on this box, s286).
    # Everything else still restarts - only the reporting channel is spared.
    if [ -d /etc/needrestart ]; then
        mkdir -p /etc/needrestart/conf.d
        # Subscript assignment ADDS to the hash the main needrestart.conf
        # already filled in; `$nrconf{override_rc} = {...}` would replace it
        # and drop the distro's own exclusions.
        cat > /etc/needrestart/conf.d/99-dockpanel.conf << 'NR_EOF'
# Managed by CyberHunter - Panel - do not edit; rewritten by setup.sh/update.sh.
$nrconf{override_rc}{qr(^dockpanel-agent)} = 0;
1;
NR_EOF
    fi

    # v2.8.19: pre-v2.8.19 cloudflared installs wrote a literal
    # `$(lsb_release -cs)` into /etc/apt/sources.list.d/cloudflared.list
    # (single-quoted bash didn't expand the substitution). Once landed, the
    # broken file made every subsequent `apt-get update` on the box fail -
    # blocking unrelated installs (Redis, WAF, …). Repair it here so
    # operators upgrading via update.sh get an unblocked apt without manual
    # intervention.
    if [ -f /etc/apt/sources.list.d/cloudflared.list ] && \
       grep -qF '$(lsb_release' /etc/apt/sources.list.d/cloudflared.list; then
        log "Removing broken cloudflared apt source (literal \$(lsb_release ...) - fixed in v2.8.19)"
        rm -f /etc/apt/sources.list.d/cloudflared.list
    fi
fi

# ── HestiaCP import (05): zstd + rsync, and no CGI module in Apache ──
# setup.sh installs zstd and rsync as base packages since the HestiaCP import:
# the agent reads .tar.zst blobs and places site files with rsync -a. Boxes
# installed before that get them here. Best-effort: a mirror that is down must
# not fail the update (the import then reports "install zstd" by name).
for bin in zstd rsync; do
    if ! command -v "$bin" &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$bin" > /dev/null 2>&1 \
                || warn "Could not install $bin - install it manually (apt-get install $bin)"
        elif command -v dnf &> /dev/null; then
            dnf install -y "$bin" > /dev/null 2>&1 \
                || warn "Could not install $bin - install it manually (dnf install $bin)"
        fi
    fi
done
# D9: ExecCGI is allowed in AllowOverride Options= (a client .htaccess with
# "Options -Indexes -ExecCGI" no longer answers 500); with mod_cgi/cgid off,
# "+ExecCGI" has no handler and executes nothing. Idempotent.
if command -v a2dismod &> /dev/null; then
    if [ -e /etc/apache2/mods-enabled/cgi.load ] || [ -e /etc/apache2/mods-enabled/cgid.load ]; then
        a2dismod -q -f cgi cgid > /dev/null 2>&1 || true
        systemctl reload apache2 > /dev/null 2>&1 || true
    fi
fi

# ── v2.38.0: heal RHEL-family installs the old installer left unreachable ──
# Every install on Rocky/Alma/CentOS/Fedora before v2.38.0 finished in one of
# two broken states, and an operator cannot click their way out of either
# because both make the panel unreachable - so the repair has to happen here.
#
#   1. setup.sh installed UFW next to the firewalld the distro was already
#      running, then opened 80/443 in UFW only. firewalld kept dropping them.
#   2. SELinux (Enforcing by default) blocks nginx from opening a socket to
#      the API, so every request answered 502 - even from the box itself. The
#      denial is dontaudit'ed, so nothing shows up in the journal or ausearch.
#
# Both repairs are idempotent and no-ops on Debian/Ubuntu.
if command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
    fw_changed=0
    for svc in http https; do
        if ! firewall-cmd --query-service="$svc" &> /dev/null; then
            firewall-cmd --permanent --add-service="$svc" &> /dev/null && fw_changed=1
        fi
    done
    if [ "$fw_changed" = "1" ]; then
        firewall-cmd --reload &> /dev/null || true
        log "firewalld: opened 80/443 (this box was serving behind a closed firewall)"
    fi
fi

if command -v getenforce &> /dev/null && [ "$(getenforce 2>/dev/null)" = "Enforcing" ] \
   && command -v getsebool &> /dev/null; then
    if getsebool httpd_can_network_connect 2>/dev/null | grep -c -- "--> off" >/dev/null; then
        if setsebool -P httpd_can_network_connect on 2>/dev/null; then
            log "SELinux: allowed nginx to reach the API (the panel was answering 502)"
        else
            warn "SELinux is Enforcing and httpd_can_network_connect is off - the panel will"
            warn "answer 502. Run: setsebool -P httpd_can_network_connect on"
        fi
    fi
fi

# ── Refresh systemd service files (may have changed between versions) ─────
_dockpanel_stage="systemd-units"
log "Updating systemd service files..."
# Agent unit - deploy from repo (single source of truth: panel/agent/dockpanel-agent.service)
# v2.8.13: existing installs upgrading from v2.8.12 or earlier get the strict sandbox here.
if [ -f "$AGENT_SRC/dockpanel-agent.service" ]; then
    cp "$AGENT_SRC/dockpanel-agent.service" /etc/systemd/system/dockpanel-agent.service
    chmod 644 /etc/systemd/system/dockpanel-agent.service
else
    warn "Agent unit source not found at $AGENT_SRC/dockpanel-agent.service - keeping existing on-disk unit (no repo tree on this layout)"
fi

# MCP server unit - deploy from repo (single source of truth:
# panel/mcp/dockpanel-mcp.service). Installed but never enabled/started here:
# see the matching comment in setup.sh's create_services(). An install that
# already has the service enabled (a manual opt-in) keeps running through the
# upgrade - this only refreshes the unit FILE, it never touches enablement.
if [ -f "$MCP_SRC/dockpanel-mcp.service" ]; then
    cp "$MCP_SRC/dockpanel-mcp.service" /etc/systemd/system/dockpanel-mcp.service
    chmod 644 /etc/systemd/system/dockpanel-mcp.service
fi

cat > /etc/systemd/system/dockpanel-api.service << 'EOF'
[Unit]
Description=CyberHunter - Panel API
After=network.target docker.service dockpanel-agent.service
Wants=dockpanel-agent.service
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/dockpanel-api
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=/etc/dockpanel/api.env
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectSystem=no
ReadWritePaths=/var/run/dockpanel /tmp
MemoryMax=1G
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# ── Update nginx frontend path if needed ──────────────────────────────────
if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
    FE_DIST="/opt/dockpanel/frontend/dist"
    for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
        if [ -f "$conf" ] && grep -q "panel/frontend/dist" "$conf" 2>/dev/null; then
            sed -i "s|/opt/dockpanel/panel/frontend/dist|${FE_DIST}|g" "$conf"
            log "Updated nginx frontend path in $conf"
            nginx -t > /dev/null 2>&1 && nginx -s reload > /dev/null 2>&1
        fi
    done
else
    # The build above lands in $REPO_DIR/panel/frontend/dist, but nginx's
    # `root` may point somewhere else entirely - every box that started life
    # via the standard curl|bash install.sh serves from
    # /opt/dockpanel/frontend/dist (the release-tarball layout, written by the
    # branch above), which this branch's own build output never touches. Left
    # alone, a source build logs "Frontend rebuilt" and changes nothing an
    # operator can see: the exact stale-panel-that-looks-healthy failure this
    # box's own nginx config already warns about (see the /assets/ location
    # comment in setup.sh's heredoc), reached through a second door - found by
    # actually loading the panel after a source-build upgrade, not by reading
    # the script. Detect the ACTUAL served root rather than assume one, and
    # sync the fresh build there; fall back to the build directory itself only
    # when no vhost exists yet to read (first-ever setup.sh run).
    BUILT_DIST="${REPO_DIR}/panel/frontend/dist"
    FE_DIST="$BUILT_DIST"
    for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
        if [ -f "$conf" ]; then
            SERVED_ROOT=$(grep -oP '^\s*root\s+\K[^;]+' "$conf" | head -1)
            if [ -n "$SERVED_ROOT" ] && [ "$SERVED_ROOT" != "$BUILT_DIST" ] && [ -d "$BUILT_DIST" ]; then
                mkdir -p "$SERVED_ROOT"
                rsync -a --delete "$BUILT_DIST/" "$SERVED_ROOT/" 2>/dev/null \
                    || cp -r "$BUILT_DIST/." "$SERVED_ROOT/"
                log "Synced built frontend to the served root ($SERVED_ROOT)"
                FE_DIST="$SERVED_ROOT"
            fi
            break
        fi
    done
fi

# ── Drop install-agent.sh into FE_ROOT (#56, v2.8.14) ─────────────────────
# Panel SPA-fallback nginx serves $uri before falling back to index.html.
# Without the script present in FE_ROOT, `curl {panel}/install-agent.sh | bash`
# returns the SPA HTML and fails with 'syntax error near unexpected token'.
if [ -f "${REPO_DIR}/scripts/install-agent.sh" ] && [ -d "$FE_DIST" ]; then
    cp "${REPO_DIR}/scripts/install-agent.sh" "$FE_DIST/install-agent.sh"
    chmod 644 "$FE_DIST/install-agent.sh"
    log "Refreshed install-agent.sh in $FE_DIST"
fi

# ── Migrate panel nginx config to bind IPv6 (fixes site-vhost dual-stack hijack) ──
_dockpanel_stage="nginx-migrations"
# v2.8.3: agent site templates declare `listen [::]:443 ssl;` (dual-stack), but
# pre-v2.8.3 setup.sh bound the panel to IPv4 only. The first SSL site to be
# provisioned then became the de-facto default for IPv6 traffic - WordPress
# would 301 panel-domain requests to its canonical home_url. Fix: ensure the
# panel vhost also has `listen [::]:80;` and `listen [::]:443 ssl;`. Plain
# (no `ipv6only=on`) so the panel listens dual-stack on the same socket as
# every site, and nginx routes by server_name across the shared listener.
# Strip any `ipv6only=on` certbot may have added on prior installs to keep
# the listener options consistent across vhosts (otherwise nginx errors with
# "duplicate listen options" when sites add their own [::]:443 ssl block).
NGINX_NEEDS_RELOAD=0
NGINX_NEEDS_RESTART=0
for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
    [ -f "$conf" ] || continue
    # certbot --nginx writes a WILDCARD `listen 443 ssl;`, while agent-generated
    # site vhosts bind `<ip>:443 ssl`. nginx treats those as different listen
    # sockets, the explicit-IP one wins every connection to that address, and the
    # panel's server_name is never consulted - so on a domain install the first
    # site to get a certificate silently takes over the panel's own hostname.
    # The IPv6 pairing step below cannot repair this shape: its rewrite needs a
    # colon before the port, so it slides straight past a wildcard `listen 443
    # ssl;`. (Its grep does fire - but on the [::]:443 line - which is why the
    # wildcard survived unnoticed.)
    if grep -qE '^[[:space:]]*listen 443 ssl;' "$conf"; then
        PANEL_BIND_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || true)
        if [ -n "$PANEL_BIND_IP" ]; then
            sed -i -E "s|^([[:space:]]*)listen 443 ssl;|\1listen ${PANEL_BIND_IP}:443 ssl;|" "$conf"
            log "Pinned panel :443 listen to ${PANEL_BIND_IP} in $conf (was wildcard; site vhosts could shadow the panel)"
            # A reload cannot move an already-bound 0.0.0.0:443 listener to a
            # specific address - nginx inherits the old socket and the rewrite
            # silently no-ops. This one needs a restart.
            NGINX_NEEDS_RESTART=1
        fi
    fi
    if ! grep -qE 'listen \[::\]:80' "$conf"; then
        sed -i -E '0,/^([[:space:]]*)listen ([^;]*):80;[[:space:]]*$/{s||\1listen \2:80;\n\1listen [::]:80;|}' "$conf"
        sed -i -E '0,/^([[:space:]]*)listen 80;[[:space:]]*$/{s||\1listen 80;\n\1listen [::]:80;|}' "$conf"
        log "Added IPv6 :80 listen to $conf"
        NGINX_NEEDS_RELOAD=1
    fi
    if grep -qE 'listen [^;]*:443 ssl' "$conf" && ! grep -qE 'listen \[::\]:443' "$conf"; then
        sed -i -E '0,/^([[:space:]]*)listen ([^;]*):443 ssl;[[:space:]]*$/{s||\1listen \2:443 ssl;\n\1listen [::]:443 ssl;|}' "$conf"
        log "Added IPv6 :443 ssl listen to $conf"
        NGINX_NEEDS_RELOAD=1
    fi
    # Strip `ipv6only=on` from panel listens if previously added - site vhosts
    # use plain `[::]:443 ssl;` and nginx rejects mixing the two on a shared socket.
    if grep -qE 'listen \[::\]:(80|443 ssl) ipv6only=on' "$conf"; then
        sed -i -E 's|^([[:space:]]*)listen \[::\]:80 ipv6only=on;|\1listen [::]:80;|' "$conf"
        sed -i -E 's|^([[:space:]]*)listen \[::\]:443 ssl ipv6only=on;|\1listen [::]:443 ssl;|' "$conf"
        log "Stripped ipv6only=on from $conf for shared-socket compatibility"
        NGINX_NEEDS_RELOAD=1
    fi
done
# Strip `ipv6only=on` from site vhosts left over from v2.8.3.
# v2.8.3 baked the option into agent templates AND added it via update.sh;
# v2.8.4 reverted the template but dropped this site-vhost cleanup. Result:
# v2.8.3-installed sites kept `[::]:443 ssl ipv6only=on` while the panel vhost
# (cleaned by the loop above) used plain `[::]:443 ssl` - nginx rejects the
# mix as "duplicate listen options" on the shared socket. Bringing them back
# in line restores reload-ability without touching site config in any other way.
if [ -d /etc/nginx/sites-enabled ]; then
    for site_conf in /etc/nginx/sites-enabled/*.conf; do
        [ -f "$site_conf" ] || continue
        case "$(basename "$site_conf")" in
            dockpanel-panel.conf) continue ;;
        esac
        if grep -qE 'listen \[::\]:(80|443 ssl) ipv6only=on' "$site_conf"; then
            sed -i -E 's|^([[:space:]]*)listen \[::\]:80 ipv6only=on;|\1listen [::]:80;|' "$site_conf"
            sed -i -E 's|^([[:space:]]*)listen \[::\]:443 ssl ipv6only=on;|\1listen [::]:443 ssl;|' "$site_conf"
            log "Stripped ipv6only=on from $site_conf for shared-socket compatibility"
            NGINX_NEEDS_RELOAD=1
        fi
    done
fi

# ── v2.68.1: retrofit the static branch's denies onto EXISTING site vhosts ───
# v2.68.0 fixed the TEMPLATE, and a template only reaches a site when something
# re-renders its vhost - a runtime switch, an SSL issuance, a settings change.
# Nothing re-renders on upgrade. So the site that most needs this fix, one already
# switched from php to static under v2.67.0, keeps serving wp-config.php, .env and
# .git/config as plain text after the operator has updated and been told it is
# fixed. Same shape as the v2.47.1 index.html migration below: a fix that reaches
# only new renders is a fix nobody in the field receives.
#
# Scoped by what the vhost IS, not by what we guess it was: a static vhost has the
# static branch's `index index.html index.htm;` and no fastcgi handler. A php vhost
# already carries these denies inside its preset branch and is skipped. Additive,
# idempotent (guarded on the deny already being present), and every edit is
# validated by `nginx -t` with a per-file rollback - a security retrofit must never
# be the thing that takes a customer's site down.
if [ -d /etc/nginx/sites-enabled ]; then
    for site_conf in /etc/nginx/sites-enabled/*.conf; do
        [ -f "$site_conf" ] || continue
        case "$(basename "$site_conf")" in
            dockpanel-panel.conf) continue ;;
        esac
        grep -q 'index index.html index.htm;' "$site_conf" || continue
        grep -q 'fastcgi_pass' "$site_conf" && continue
        grep -qF 'location ~ /\.(?!well-known)' "$site_conf" && continue

        cp -p "$site_conf" "$site_conf.pre-2680" 2>/dev/null || true
        if awk '
            { print }
            /^[[:space:]]*index index\.html index\.htm;[[:space:]]*$/ {
                print "";
                print "    # v2.68.1: a site switched from php to static keeps its application";
                print "    # source in the same docroot. Both denies exist in every php preset.";
                print "    location ~ /\\.(?!well-known) {";
                print "        deny all;";
                print "    }";
                print "";
                print "    location ~ \\.php$ {";
                print "        deny all;";
                print "    }";
            }
        ' "$site_conf.pre-2680" > "$site_conf.new" 2>/dev/null && [ -s "$site_conf.new" ]; then
            mv "$site_conf.new" "$site_conf"
            if nginx -t > /dev/null 2>&1; then
                rm -f "$site_conf.pre-2680"
                log "Retrofitted dotfile/.php denies onto static vhost $site_conf"
                NGINX_NEEDS_RELOAD=1
            else
                mv "$site_conf.pre-2680" "$site_conf"
                log "WARN: denies rejected by nginx -t for $site_conf - reverted, site untouched"
            fi
        else
            rm -f "$site_conf.new" "$site_conf.pre-2680"
            log "WARN: could not retrofit denies onto $site_conf - skipped"
        fi
    done
fi
# ── v2.8.22: ensure panel vhost includes dockpanel-panel.locations/*.conf ─
# Drop-in dir for path-mounted tool reverse-proxies. Webmail uses this in
# v2.8.22+ (writes webmail.conf on install, deletes on remove). Pre-v2.8.22
# panel vhosts lack the include directive - inject it just before the
# server-block closing brace via awk (sed nested-brace handling is fragile).
mkdir -p /etc/nginx/conf.d/dockpanel-panel.locations
for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
    [ -f "$conf" ] || continue
    if ! grep -q "dockpanel-panel.locations" "$conf"; then
        # Inject before the FIRST top-level `}` (the server block close).
        # Panel vhost has exactly one top-level `}`, so single-match is safe.
        if awk '
            /^}/ && !done {
                print "    # Drop-in location blocks for path-mounted tools (webmail, etc.)";
                print "    include /etc/nginx/conf.d/dockpanel-panel.locations/*.conf;";
                print "";
                done=1
            }
            { print }
        ' "$conf" > "$conf.new" && [ -s "$conf.new" ]; then
            mv "$conf.new" "$conf"
            log "Added dockpanel-panel.locations include to $conf"
            NGINX_NEEDS_RELOAD=1
        else
            rm -f "$conf.new"
            log "WARN: failed to inject panel-locations include into $conf - skipped"
        fi
    fi
done

# ── v2.47.1: give index.html a cache directive on EXISTING panel vhosts ───
# setup.sh started writing `location = /index.html { Cache-Control: no-cache }`
# in v2.47.1, but setup.sh only ever runs at INSTALL time and this script never
# re-runs it. Without a migration the fix therefore reaches new boxes only, and
# every panel already in the field keeps serving index.html with no cache
# directive at all: the browser falls back to HEURISTIC freshness - roughly a
# tenth of the file's age, so days on a panel that has been up a month - and in
# that window keeps naming the PREVIOUS hashed bundle, which is still on disk
# because the frontend untars OVER the directory rather than replacing it.
# Nothing 404s. The operator updates, is told it worked, and goes on running the
# old frontend against the new backend. That is s270's delivery class: a fix
# written into the install-time template only is a fix nobody who already
# installed will ever receive.
#
# The repeated add_headers are copied FROM THE VHOST BEING MIGRATED, not from
# this script. A location block's add_headers REPLACE the server block's set
# rather than merging with it, so the block has to re-state whatever that box
# already sends - otherwise this migration would strip the CSP off the one
# response that carries it, a worse bug than the one being fixed. Copying the
# box's own set (rather than today's) also keeps an old vhost from being
# silently given a different CSP on a single response. If no server-level
# add_header is found the migration is skipped rather than guessed at.
for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
    [ -f "$conf" ] || continue
    grep -q "location = /index.html" "$conf" && continue
    # Server-level headers are indented 4; location-level ones 8, so an exact
    # four-space prefix selects the parent set without matching nested blocks.
    if ! grep -qE '^    add_header ' "$conf"; then
        log "WARN: $conf has no server-level add_header - skipped index.html cache migration (injecting it would strip the security headers)"
        continue
    fi
    # Inject before the FIRST top-level `}`. The panel vhost has exactly one
    # (verified: one `server {` at column 0), the same assumption the
    # panel-locations migration above already relies on.
    if awk '
        /^    add_header / { hdr[++n] = $0 }
        /^}/ && !done {
            print "    # Without a cache directive the browser applies heuristic freshness and";
            print "    # serves a stale index.html, naming an older hashed bundle that is still";
            print "    # on disk - so an updated panel goes on running the previous frontend.";
            print "    # Every add_header here is a REPEAT: a location block replaces the";
            print "    # server block'"'"'s set rather than merging with it.";
            print "    location = /index.html {";
            print "        add_header Cache-Control \"no-cache\" always;";
            for (i = 1; i <= n; i++) { sub(/^    /, "        ", hdr[i]); print hdr[i] }
            print "    }";
            print "";
            done = 1
        }
        { print }
    ' "$conf" > "$conf.new" && [ -s "$conf.new" ] && grep -q "location = /index.html" "$conf.new"; then
        mv "$conf.new" "$conf"
        log "Added index.html cache directive to $conf"
        NGINX_NEEDS_RELOAD=1
    else
        rm -f "$conf.new"
        log "WARN: failed to inject index.html cache block into $conf - skipped"
    fi
done

# ── v2.47.2: repeat the security headers on /assets/ on EXISTING panel vhosts ──
# Same delivery class as the migration above, and this session's own lesson
# applied to this session's own change: setup.sh started repeating the server
# header set inside `location /assets/` in v2.47.2, and setup.sh runs only at
# install time. Without a migration, every panel already in the field goes on
# serving its JS and CSS bundles with NO X-Content-Type-Options - the one header
# that actually matters for a script response, missing from the only responses
# that are scripts - because a location block's add_headers REPLACE the server
# block's set rather than merging with it, and this block set only Cache-Control.
#
# It also emitted two Cache-Control lines saying different things (max-age from
# `expires 1y`, `public, immutable` from the add_header). One directive replaces
# both. Deliberately NOT `always` on it: an error response must not be cached,
# or a 404 during an update is remembered for a year.
#
# As above, the repeated headers are copied FROM THE VHOST BEING MIGRATED rather
# than written from this script, so an older install keeps its own policy instead
# of being silently handed today's on one class of response; and a vhost with no
# server-level add_header is skipped rather than guessed at.
#
# Two passes over the file (awk NR==FNR), unlike the single pass above: the
# server-level add_headers are written AFTER the /assets/ block, so they are not
# yet known at the point the block has to be rewritten.
for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
    [ -f "$conf" ] || continue
    grep -q "location /assets/" "$conf" || continue
    grep -q 'max-age=31536000, immutable' "$conf" && continue
    if ! grep -qE '^    add_header ' "$conf"; then
        log "WARN: $conf has no server-level add_header - skipped /assets/ header migration (rewriting it would strip the security headers)"
        continue
    fi
    if awk '
        NR == FNR { if (/^    add_header /) hdr[++n] = $0; next }
        /^    location \/assets\/ \{/ && !done {
            print "    # Hashed filenames, so a year is safe. ONE Cache-Control: the expires";
            print "    # directive emitted its own on top of the add_header and the two went out";
            print "    # as separate lines saying different things. Not \"always\" - an error";
            print "    # response must not be cached, or a 404 mid-update is kept for a year.";
            print "    # Every add_header below REPEATS this vhost'"'"'s own server-level set: a";
            print "    # location block replaces that set rather than merging with it, so without";
            print "    # them every script this panel serves goes out with no nosniff.";
            print "    location /assets/ {";
            print "        add_header Cache-Control \"public, max-age=31536000, immutable\";";
            for (i = 1; i <= n; i++) { h = hdr[i]; sub(/^    /, "        ", h); print h }
            print "    }";
            skip = 1; done = 1; next
        }
        skip && /^    \}/ { skip = 0; next }
        skip { next }
        { print }
    ' "$conf" "$conf" > "$conf.new" && [ -s "$conf.new" ] \
        && grep -q 'max-age=31536000, immutable' "$conf.new" \
        && ! awk '/^    location \/assets\/ \{/ {f=1} f {print} f && /^    \}/ {exit}' \
             "$conf.new" | grep -c 'expires ' >/dev/null; then
        mv "$conf.new" "$conf"
        log "Repeated the security headers on /assets/ in $conf"
        NGINX_NEEDS_RELOAD=1
    else
        rm -f "$conf.new"
        log "WARN: failed to rewrite the /assets/ block in $conf - skipped"
    fi
done

if [ "$NGINX_NEEDS_RELOAD" = "1" ] || [ "$NGINX_NEEDS_RESTART" = "1" ]; then
    if nginx -t > /dev/null 2>&1; then
        if [ "$NGINX_NEEDS_RESTART" = "1" ]; then
            systemctl restart nginx > /dev/null 2>&1 && log "Nginx restarted after panel :443 listen migration"
            # Verify the socket actually moved - the whole point of restarting.
            if command -v ss > /dev/null 2>&1 && [ -n "${PANEL_BIND_IP:-}" ] \
               && ! ss -ltn "( sport = :443 )" 2>/dev/null | grep -c "${PANEL_BIND_IP}:443" >/dev/null; then
                log "WARN: panel is still not listening on ${PANEL_BIND_IP}:443 - a site vhost may shadow it"
            fi
        else
            nginx -s reload > /dev/null 2>&1 && log "Nginx reloaded after config migrations"
        fi
    else
        log "WARN: nginx -t failed after config migrations; not reloading. Check sites-enabled/."
    fi
fi

# ── webmail nginx fragment: healed by the AGENT, not here ─────────
# This used to hold a hand-copied mirror of the fragment and rewrite it when
# `sub_filter` was missing. The mirror froze at the v2.10.1 shape and never
# learned the header set v2.36.0 added, so its "heal" produced a fragment whose
# inherited `frame-ancestors 'none'` makes Roundcube render an empty inbox -
# a repair that wrote the defect. The agent now owns the template outright
# (`routes::mail::{webmail_nginx_block, heal_webmail_nginx}`) and reconciles the
# file at startup, which this script triggers when it restarts the agent.
# Do not reintroduce a copy of the fragment here; one writer is the fix.

# Ensure BASE_URL is set in api.env for CORS.
# The test MUST stay anchored to the start of the line. An unanchored substring
# search also hits the DATABASE_URL= line that setup.sh writes first into every
# api.env (that key ends with the same eight characters), so before v2.31.2 this
# repair was skipped on every install that has ever existed. Require a real key
# with a non-empty value - setup.sh writes a bare, valueless key on domainless
# installs, and that counts as unset here.
if [ -f /etc/dockpanel/api.env ] && ! grep -qE '^BASE_URL=.+' /etc/dockpanel/api.env; then
    # Detect panel URL from nginx config
    PANEL_DOMAIN=""
    for conf in /etc/nginx/sites-enabled/dockpanel-panel.conf /etc/nginx/conf.d/dockpanel-panel.conf; do
        if [ -f "$conf" ]; then
            PANEL_DOMAIN=$(grep "server_name" "$conf" | head -1 | awk '{print $2}' | tr -d ';')
            break
        fi
    done
    if [ -n "$PANEL_DOMAIN" ] && [ "$PANEL_DOMAIN" != "_" ]; then
        if grep -qE '^BASE_URL=' /etc/dockpanel/api.env; then
            # A bare `BASE_URL=` is already there (domainless install later moved
            # onto a domain). Rewrite it in place - appending a second key would
            # leave two BASE_URL lines and make the effective value depend on
            # which one the env parser happens to keep.
            sed -i -E "s|^BASE_URL=.*|BASE_URL=https://${PANEL_DOMAIN}|" /etc/dockpanel/api.env
            log "Set empty BASE_URL to https://${PANEL_DOMAIN} in api.env"
        else
            echo "BASE_URL=https://${PANEL_DOMAIN}" >> /etc/dockpanel/api.env
            log "Added BASE_URL=https://${PANEL_DOMAIN} to api.env"
        fi
    fi
fi

# ── Deploy binaries ───────────────────────────────────────────────────────
_dockpanel_stage="deploy"
# Note: ~2-5s downtime during binary swap is expected for self-hosted deployments.
log "Backing up current binaries..."
cp "$AGENT_BIN" "${AGENT_BIN}.bak" 2>/dev/null || true
cp "$API_BIN" "${API_BIN}.bak" 2>/dev/null || true
cp "$CLI_BIN" "${CLI_BIN}.bak" 2>/dev/null || true
# dockpanel-mcp is a NEW binary as of this release - on every box upgrading
# for the first time since it shipped, $MCP_BIN does not exist yet, so there
# is nothing to back up and nothing to roll back TO. Recorded now so the
# rollback function below can tell "no backup because first install" apart
# from "no backup because something is actually wrong".
MCP_BIN_PRE_EXISTED=0
[ -f "$MCP_BIN" ] && MCP_BIN_PRE_EXISTED=1
cp "$MCP_BIN" "${MCP_BIN}.bak" 2>/dev/null || true

# dockpanel-mcp is opt-in (§ setup.sh/update.sh systemd-units comment) - most
# installs have it deployed but never enabled, so unlike agent/api it is only
# stopped/restarted here if an operator already turned it on. Captured BEFORE
# the stop below since `systemctl is-active` after stopping would always say no.
MCP_WAS_ACTIVE=0
systemctl is-active --quiet dockpanel-mcp 2>/dev/null && MCP_WAS_ACTIVE=1

log "Stopping services..."
_dockpanel_services_stopped=1
systemctl stop dockpanel-agent dockpanel-api 2>/dev/null || true
[ "$MCP_WAS_ACTIVE" = "1" ] && systemctl stop dockpanel-mcp 2>/dev/null || true

if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
    mv "$STAGE_DIR/dockpanel-agent-new" "$AGENT_BIN"
    mv "$STAGE_DIR/dockpanel-api-new" "$API_BIN"
    mv "$STAGE_DIR/dockpanel-cli-new" "$CLI_BIN"
    mv "$STAGE_DIR/dockpanel-mcp-new" "$MCP_BIN"
else
    cp "$AGENT_SRC/target/release/dockpanel-agent" "$AGENT_BIN"
    cp "$API_SRC/target/release/dockpanel-api" "$API_BIN"
    cp "$CLI_SRC/target/release/dockpanel" "$CLI_BIN"
    [ -f "$MCP_SRC/target/release/dockpanel-mcp" ] && cp "$MCP_SRC/target/release/dockpanel-mcp" "$MCP_BIN"
fi
chmod +x "$AGENT_BIN" "$API_BIN" "$CLI_BIN"
[ -f "$MCP_BIN" ] && chmod +x "$MCP_BIN"

# SELinux: restore the binaries' security context after the swap.
#
# A rename within one filesystem PRESERVES the source label, and the release
# path above moves these in from /tmp - so each binary arrives carrying
# `user_tmp_t` instead of `bin_t`, and on an Enforcing box systemd then refuses
# to execute it:
#
#     Failed at step EXEC spawning /usr/local/bin/dockpanel-agent: Permission denied
#     dockpanel-agent.service: Main process exited, code=exited, status=203/EXEC
#
# Measured on Rocky 9.8 at s266. The failure is silent in the worst way: the
# update reports success, and the service is dead until someone relabels it by
# hand. Note the `cp` branch does NOT have this problem - copying ONTO an
# existing file keeps the target's label - so this only ever bit the
# release-binary path, which is the one every real install uses.
#
# No-op on Debian/Ubuntu, where restorecon is usually absent.
if command -v restorecon > /dev/null 2>&1; then
    restorecon -F "$AGENT_BIN" "$API_BIN" "$CLI_BIN" "$MCP_BIN" 2>/dev/null || true
fi

log "Binaries updated (agent: $(du -h "$AGENT_BIN" | cut -f1), api: $(du -h "$API_BIN" | cut -f1), cli: $(du -h "$CLI_BIN" | cut -f1), mcp: $(du -h "$MCP_BIN" 2>/dev/null | cut -f1 || echo '?'))"

systemctl daemon-reload
systemctl start dockpanel-agent
sleep 1
systemctl start dockpanel-api
[ "$MCP_WAS_ACTIVE" = "1" ] && systemctl start dockpanel-mcp
_dockpanel_services_stopped=0
log "Services restarted"

# ── Health check with rollback ────────────────────────────────────────────
rollback() {
    error "Health check failed, rolling back..."

    # Restore with `mv`, not `cp`, and stop the services first.
    #
    # This path had never executed in production. `cp` writes into the existing
    # inode, so restoring over the RUNNING dockpanel-api/dockpanel-agent failed
    # ETXTBSY ("Text file busy") - and because each cp was suffixed
    # `2>/dev/null || true`, the failure was discarded and the script printed
    # "Rolled back to previous binaries" while the box kept running the binary
    # that had just failed its health check. Only the CLI (not running) was
    # actually restored, so the box then disagreed with itself:
    # `dockpanel --version` reported the old version while /api/health reported
    # the new one. rename(2) replaces the directory entry and is unaffected by a
    # busy inode - it is what the forward swap above already uses.
    _dockpanel_services_stopped=1
    systemctl stop dockpanel-agent dockpanel-api 2>/dev/null || true
    [ "$MCP_WAS_ACTIVE" = "1" ] && systemctl stop dockpanel-mcp 2>/dev/null || true

    local restore_failed=0
    local pair
    for pair in "$AGENT_BIN" "$API_BIN" "$CLI_BIN" "$MCP_BIN"; do
        if [ -f "${pair}.bak" ]; then
            if mv "${pair}.bak" "$pair"; then
                log "Restored $pair"
            else
                error "FAILED to restore $pair from ${pair}.bak"
                restore_failed=1
            fi
        elif [ "$pair" = "$MCP_BIN" ] && [ "$MCP_BIN_PRE_EXISTED" = "0" ]; then
            # Nothing to roll back to - this box never had dockpanel-mcp before
            # this update. Remove the newly-placed (unhealthy-update) binary
            # rather than leaving a stray one an un-rolled-back systemd unit
            # could later be pointed at.
            rm -f "$pair"
            log "No prior $pair to restore (first install of this binary) - removed"
        else
            error "No backup at ${pair}.bak - cannot restore $pair"
            restore_failed=1
        fi
    done

    # Tolerate a non-zero start here rather than letting `set -e` abort the
    # function before the diagnosis below is printed - the EXIT trap is a safety
    # net for the process dying, not a substitute for telling the operator what
    # happened.
    systemctl daemon-reload
    systemctl start dockpanel-agent || error "dockpanel-agent did not start after rollback"
    sleep 1
    systemctl start dockpanel-api || error "dockpanel-api did not start after rollback"
    if [ "$MCP_WAS_ACTIVE" = "1" ]; then
        systemctl start dockpanel-mcp || error "dockpanel-mcp did not start after rollback"
    fi
    _dockpanel_services_stopped=0

    if [ "$restore_failed" = "1" ]; then
        error "ROLLBACK INCOMPLETE - the panel may still be running the failed build."
        error "Inspect /usr/local/bin/dockpanel-{api,agent} and restore manually."
        _dockpanel_finished=1
        _dockpanel_write_result false "rollback" \
            "health check failed after the swap AND the rollback did not complete - the panel may still be running the failed build; inspect /usr/local/bin/dockpanel-{api,agent}"
        exit 1
    fi

    warn "Rolled back to previous binaries"
    # A completed rollback is a DIFFERENT outcome from a failed one, and the
    # orchestrator has to be able to tell them apart: this box is healthy and
    # running its previous version, which is not something that needs an
    # operator at 3am.
    _dockpanel_finished=1
    _dockpanel_write_result false "rollback" \
        "health check failed after the swap; rolled back to the previous binaries and the panel is running again"
    exit 1
}

log "Running post-deploy health check..."
sleep 20

# Basic health endpoint
if ! curl -sf --max-time 30 http://127.0.0.1:3080/api/health > /dev/null 2>&1; then
    rollback
fi
log "Health check: /api/health OK"

# Auth subsystem (setup-status is unauthenticated, tests DB connectivity).
# Note: this endpoint is GET-only - using POST returns 405 and triggered an
# unconditional rollback on every update before this fix.
if ! curl -sf --max-time 30 http://127.0.0.1:3080/api/auth/setup-status > /dev/null 2>&1; then
    rollback
fi
log "Health check: /api/auth/setup-status OK"

# Agent reachable (non-fatal - agent may start slower).
#
# Ask the AGENT, not the panel. `/api/system/info` is behind auth, and this
# check sent no token - so it returned 401, `curl -sf` treated that as failure,
# and every update on every install printed "Agent connectivity check failed"
# whether the agent was healthy or dead. A check that fails identically in both
# states carries no signal; it only taught operators to ignore the warning.
# The agent's own /health is explicitly exempt from auth
# (panel/agent/src/routes/mod.rs), which makes it the honest probe.
AGENT_SOCK=/run/dockpanel/agent.sock
[ -S "$AGENT_SOCK" ] || AGENT_SOCK=/var/run/dockpanel/agent.sock
if ! curl -sf --max-time 30 --unix-socket "$AGENT_SOCK" http://localhost/health > /dev/null 2>&1; then
    warn "Agent connectivity check failed (non-fatal, agent may still be starting)"
else
    log "Health check: agent /health OK"
fi

# CLI health check (non-fatal)
if ! dockpanel --version > /dev/null 2>&1; then
    warn "CLI health check failed (non-fatal)"
fi

log "Health checks passed"

# ── Release mode: refresh /opt/dockpanel/scripts from the verified release ──
# Only now, after the health checks: a release that rolled back must not leave
# its scripts behind for the next SSH session. These copies are for operators
# working over SSH (restore, uninstall, sync of site vhosts); the panel itself
# always runs update.sh from inside the release it has just verified.
if [ "$INSTALL_FROM_RELEASE" = "1" ] && [ -d "$REPO_DIR/scripts" ] \
   && [ "$REPO_DIR/scripts" != "/opt/dockpanel/scripts" ]; then
    _dockpanel_stage="scripts"
    mkdir -p /opt/dockpanel/scripts
    if cp -a "$REPO_DIR/scripts/." /opt/dockpanel/scripts/; then
        log "Refreshed /opt/dockpanel/scripts from the release"
    else
        warn "Could not refresh /opt/dockpanel/scripts - the update itself is complete"
    fi
fi

_dockpanel_stage="complete"
_dockpanel_finished=1
_dockpanel_write_result true "complete" \
    "updated to ${DOCKPANEL_VERSION:-latest} and passed the post-deploy health checks"

# Clean up backups
rm -f "${AGENT_BIN}.bak" "${API_BIN}.bak" "${CLI_BIN}.bak" "${MCP_BIN}.bak"

echo ""
echo -e "${GREEN}${BOLD}Update complete!${NC}"
echo ""
echo -e "  Agent: $(systemctl is-active dockpanel-agent)"
echo -e "  API:   $(systemctl is-active dockpanel-api)"
if systemctl list-unit-files dockpanel-mcp.service > /dev/null 2>&1; then
    echo -e "  MCP:   $(systemctl is-active dockpanel-mcp) $([ "$MCP_WAS_ACTIVE" = "0" ] && echo '(not enabled - see docs.dockpanel.dev)')"
fi
echo -e "  Version: $($CLI_BIN --version 2>/dev/null || echo 'unknown')"
echo ""
