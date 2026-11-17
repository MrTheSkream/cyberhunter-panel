#!/usr/bin/env bash
#
# CyberHunter - Panel Quick Installer
#
# Usage (release mode, the default: no git, no token):
#   curl -fsSLO https://github.com/MrTheSkream/cyberhunter-releases/releases/latest/download/install.sh
#   sudo bash install.sh
#   sudo DOCKPANEL_VERSION=v3.0.0-rc.5 bash install.sh     # a given release
#
#   releases/latest never points at a pre-release: while only vX.Y.Z-rc.N
#   releases exist, take install.sh from the tag itself:
#   curl -fsSLO https://github.com/MrTheSkream/cyberhunter-releases/releases/download/v3.0.0-rc.5/install.sh
#   sudo DOCKPANEL_VERSION=v3.0.0-rc.5 bash install.sh
#
# Modes:
#   Release (default):  download a published release from the public release
#                       repository, check the minisign signature of its
#                       checksums.txt against the key written in this file
#                       (trusted comment "cyberhunter-release <tag>"), check
#                       the SHA-256 of every file, then install it.
#   CYBERHUNTER_RELEASE_DIR=<dir>, without CYBERHUNTER_REPO_URL:
#                       the same checks and the same install, on a release
#                       downloaded by hand into <dir> (nothing is fetched). The
#                       tag is DOCKPANEL_VERSION, else the name of <dir>.
#   CYBERHUNTER_REPO_URL=<git clone URL>:
#                       clone that repository (git authentication is the
#                       operator's business) and build from source (Rust,
#                       ~3GB RAM). With CYBERHUNTER_RELEASE_DIR as well, the
#                       binaries come from that directory instead, checked by
#                       setup.sh against its checksums.txt.
#
# Environment:
#   DOCKPANEL_VERSION          release tag (vX.Y.Z or vX.Y.Z-rc.N). Release
#                              mode: default is the latest stable release; a
#                              pre-release is only installed when named here.
#                              Clone mode: the git ref (default main).
#   CYBERHUNTER_RELEASE_REPO   release repository (default
#                              MrTheSkream/cyberhunter-releases)
#   CYBERHUNTER_PUBKEY         override the signing public key written below
#                              (tests, or a fork with its own key). Leave it
#                              unset to use the key this file was released with.
#   CYBERHUNTER_RELEASE_BASE_URL
#                              where the release files are read from, instead of
#                              https://github.com/<repo>/releases/download/<tag>.
#                              https:// or file:// only. Used by
#                              tests/install-release-mode-pin.sh (file://); the
#                              signature and checksum checks are the same.
#
# Release mode needs minisign. It is installed with the package manager when
# missing; if that fails, the install stops. Verification is never skipped.
#
# The verified release is kept in /var/lib/dockpanel/releases/<tag>/ (the
# panel's verified-release cache), its source archive is unpacked into
# /opt/dockpanel (scripts/, panel/, LICENSE), then scripts/setup.sh runs with
# INSTALL_FROM_RELEASE=1. Once installed, the panel updates itself from
# Telemetry, Updates.
#
set -euo pipefail

# Written by scripts/release.sh into the copy attached to each release: the
# release signing public key (2nd line of the .pub). Empty in the repository:
# an unstamped copy refuses release mode.
CYBERHUNTER_STAMPED_PUBKEY=""

INSTALL_DIR="/opt/dockpanel"
RELEASES_ROOT="/var/lib/dockpanel/releases"
DEFAULT_RELEASE_REPO="MrTheSkream/cyberhunter-releases"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $*"; }
die() { echo -e "${RED}[x] $*${NC}" >&2; exit 1; }

echo ""
echo -e "${GREEN}${BOLD}CyberHunter - Panel Installer${NC}"
echo -e "  Free, self-hosted server management panel"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    die "Run as root - sudo bash install.sh"
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -y"
elif command -v dnf &> /dev/null; then
    PKG_INSTALL="dnf install -y"
    PKG_UPDATE="dnf check-update || true"
elif command -v yum &> /dev/null; then
    PKG_INSTALL="yum install -y"
    PKG_UPDATE="yum check-update || true"
else
    die "No supported package manager found (apt/dnf/yum)"
fi

PKG_UPDATED=0
# ensure_pkg <command> <package>: install <package> if <command> is missing.
ensure_pkg() {
    command -v "$1" &> /dev/null && return 0
    log "Installing $2..."
    if [ "$PKG_UPDATED" = "0" ]; then
        eval "$PKG_UPDATE" > /dev/null 2>&1 || true
        PKG_UPDATED=1
    fi
    $PKG_INSTALL "$2" > /dev/null 2>&1 || true
    command -v "$1" &> /dev/null
}

# ══════════════════════════════════════════════════════════════════════════
# Clone mode (CYBERHUNTER_REPO_URL): unchanged behaviour.
# ══════════════════════════════════════════════════════════════════════════
if [ -n "${CYBERHUNTER_REPO_URL:-}" ]; then
    VERSION="${DOCKPANEL_VERSION:-main}"
    REPO_URL="$CYBERHUNTER_REPO_URL"

    ensure_pkg git git || die "git could not be installed"

    # Clone or update repo
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating existing installation..."
        if ! (cd "$INSTALL_DIR" && git pull --ff-only); then
            die "Git update failed (local changes?). Run: cd $INSTALL_DIR && git stash && git pull"
        fi
    else
        log "Downloading CyberHunter - Panel..."
        rm -rf "$INSTALL_DIR"
        git clone --quiet --depth 1 -b "$VERSION" "$REPO_URL" "$INSTALL_DIR"
    fi

    # Pre-built binaries only from a release the operator downloaded by hand
    # (setup.sh verifies it); otherwise build the cloned tree.
    if [ -n "${CYBERHUNTER_RELEASE_DIR:-}" ] && [ "${BUILD_FROM_SOURCE:-0}" != "1" ]; then
        export INSTALL_FROM_RELEASE=1
        export CYBERHUNTER_RELEASE_DIR
    else
        export INSTALL_FROM_RELEASE=0
    fi

    log "Running setup..."
    exec bash "$INSTALL_DIR/scripts/setup.sh"
fi

# ══════════════════════════════════════════════════════════════════════════
# Release mode: a signed release, verified here before anything is installed.
# ══════════════════════════════════════════════════════════════════════════
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
STABLE_RE='^v[0-9]+\.[0-9]+\.[0-9]+$'
SUMS_LINE_RE='^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$'

# The signing key: the stamped one, unless CYBERHUNTER_PUBKEY overrides it.
PUBKEY="$CYBERHUNTER_STAMPED_PUBKEY"
if [ -n "${CYBERHUNTER_PUBKEY:-}" ]; then
    PUBKEY="$CYBERHUNTER_PUBKEY"
    echo "  Note: using the signing key from CYBERHUNTER_PUBKEY, not the one in this file."
fi
if [ -z "$PUBKEY" ]; then
    die "This install.sh has no release signing key (it is the unstamped copy from the
    source repository). Download install.sh from a release instead:
      https://github.com/${DEFAULT_RELEASE_REPO}/releases/latest/download/install.sh
    or set CYBERHUNTER_REPO_URL to build from source."
fi
if ! printf '%s' "$PUBKEY" | grep -Eqx 'RW[A-Za-z0-9+/]{54}'; then
    die "The release signing key is not a minisign public key (RW... , 56 characters)"
fi

RELEASE_REPO="${CYBERHUNTER_RELEASE_REPO:-$DEFAULT_RELEASE_REPO}"
if ! printf '%s' "$RELEASE_REPO" | grep -Eqx '[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'; then
    die "CYBERHUNTER_RELEASE_REPO must be <owner>/<name>, got '$RELEASE_REPO'"
fi

LOCAL_DIR="${CYBERHUNTER_RELEASE_DIR:-}"
if [ -n "$LOCAL_DIR" ]; then
    [ -d "$LOCAL_DIR" ] || die "CYBERHUNTER_RELEASE_DIR is not a directory: $LOCAL_DIR"
    LOCAL_DIR="$(cd "$LOCAL_DIR" && pwd)"
fi

ensure_pkg curl curl || die "curl could not be installed"
ensure_pkg sha256sum coreutils || die "sha256sum is missing (coreutils)"
ensure_pkg tar tar || die "tar could not be installed"

# fetch <url> <out> [max bytes]: download with retries (a connection dropped
# mid-transfer, curl exit 56, is not covered by --retry). https only, also
# after redirects; file:// only when the base URL itself is file://.
fetch() {
    local url="$1" out="$2" max="${3:-}" attempt=1 rc=0 proto="=https"
    case "$url" in file://*) proto="=file" ;; esac
    local extra=()
    [ -n "$max" ] && extra=(--max-filesize "$max")
    while [ "$attempt" -le 3 ]; do
        rc=0
        curl --proto "$proto" --proto-redir "=https" --retry 3 --retry-delay 2 \
             -fsSL "${extra[@]}" "$url" -o "$out" || rc=$?
        if [ "$rc" -eq 0 ]; then return 0; fi
        rm -f "$out"
        # 22: HTTP error (404...), 37: file not found. Retrying will not help.
        if [ "$rc" -eq 22 ] || [ "$rc" -eq 37 ]; then return "$rc"; fi
        echo "  fetch attempt ${attempt}/3 exited ${rc} - $url" >&2
        attempt=$((attempt + 1))
        if [ "$attempt" -le 3 ]; then sleep 3; fi
    done
    return "$rc"
}

# ── 1. Which release ──────────────────────────────────────────────────────
TAG="${DOCKPANEL_VERSION:-}"
case "$TAG" in [0-9]*) TAG="v$TAG" ;; esac
if [ -z "$TAG" ] && [ -n "$LOCAL_DIR" ]; then
    TAG="$(basename "$LOCAL_DIR")"
fi
if [ -z "$TAG" ]; then
    # The latest stable release, from the redirect of /releases/latest
    # (.../releases/tag/<tag>). GitHub never points it at a pre-release.
    LATEST_URL="https://github.com/${RELEASE_REPO}/releases/latest"
    EFFECTIVE="$(curl --proto '=https' --proto-redir '=https' -fsSL -o /dev/null \
        -w '%{url_effective}' "$LATEST_URL" 2>/dev/null)" \
        || die "Could not reach $LATEST_URL (no release published yet, or no network)"
    case "$EFFECTIVE" in
        "https://github.com/${RELEASE_REPO}/releases/tag/"*) TAG="${EFFECTIVE##*/}" ;;
        *) die "$LATEST_URL did not lead to a release (got '$EFFECTIVE'). Set DOCKPANEL_VERSION." ;;
    esac
    printf '%s\n' "$TAG" | grep -Eq "$STABLE_RE" \
        || die "The latest release tag '$TAG' is not a stable vX.Y.Z tag. Set DOCKPANEL_VERSION."
fi
printf '%s\n' "$TAG" | grep -Eq "$TAG_RE" \
    || die "Release tag '$TAG' is not vX.Y.Z or vX.Y.Z-rc.N"
TRUSTED="cyberhunter-release ${TAG}"

case "$(uname -m)" in
    x86_64)         ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
esac
ASSETS=(
    "cyberhunter-agent-linux-${ARCH}" "cyberhunter-api-linux-${ARCH}"
    "cyberhunter-cli-linux-${ARCH}"   "cyberhunter-mcp-linux-${ARCH}"
    cyberhunter-frontend.tar.gz       cyberhunter-source.tar.gz
)

if [ -n "$LOCAL_DIR" ]; then
    BASE_URL="file://${LOCAL_DIR}"
    log "Installing release $TAG from $LOCAL_DIR"
else
    BASE_URL="${CYBERHUNTER_RELEASE_BASE_URL:-https://github.com/${RELEASE_REPO}/releases/download/${TAG}}"
    case "$BASE_URL" in
        https://*|file:///*) ;;
        *) die "CYBERHUNTER_RELEASE_BASE_URL must start with https:// or file:///" ;;
    esac
    BASE_URL="${BASE_URL%/}"
    log "Installing release $TAG from $RELEASE_REPO"
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    die "$INSTALL_DIR is a git checkout (a source install). Update it with
    CYBERHUNTER_REPO_URL, or move it away to install release $TAG."
fi

# ── 2. minisign ───────────────────────────────────────────────────────────
if ! ensure_pkg minisign minisign; then
    die "minisign is required to verify the release signature and could not be installed
    with the package manager (it is not packaged on every distribution: Ubuntu
    22.04 does not have it). Install minisign 0.11 or later, then run this again.
    The signature is never skipped."
fi

# ── 3. Staging, then the signed manifest ─────────────────────────────────
mkdir -p "$RELEASES_ROOT"
chmod 0700 "$RELEASES_ROOT"
# A hidden name: the panel removes leftover hidden entries at start-up.
STAGE="$(umask 077; mktemp -d "$RELEASES_ROOT/.install-XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

fetch "$BASE_URL/checksums.txt.minisig" "$STAGE/checksums.txt.minisig" 4096 \
    || die "checksums.txt.minisig of $TAG could not be downloaded - refusing to install an unsigned release"
fetch "$BASE_URL/checksums.txt" "$STAGE/checksums.txt" 65536 \
    || die "checksums.txt of $TAG could not be downloaded"

# Pre-hashed signatures only ("ED"), as the panel requires.
SIG_ALG="$(sed -n '2p' "$STAGE/checksums.txt.minisig" | tr -d '\r\n' | base64 -d 2>/dev/null | head -c 2 || true)"
[ "$SIG_ALG" = "ED" ] || die "checksums.txt.minisig is not a pre-hashed minisign signature - refusing to install"

# -Q prints only the trusted comment, and only once both the signature and the
# trusted comment signature have verified with this key.
if ! COMMENT="$(minisign -Q -V -m "$STAGE/checksums.txt" -x "$STAGE/checksums.txt.minisig" -P "$PUBKEY" 2>"$STAGE/minisign.err")"; then
    sed 's/^/    /' "$STAGE/minisign.err" >&2
    die "The signature of checksums.txt does not verify with the release signing key - refusing to install"
fi
if [ "$COMMENT" != "$TRUSTED" ]; then
    die "The signature is for '$COMMENT', not '$TRUSTED' - refusing to install"
fi
log "Signature verified ($TRUSTED)"

# One `<64 hex>  <name>` per line, LF only, no duplicate: any other line is a
# refusal, never a line to skip.
SUMS="$STAGE/checksums.txt"
if [ "$(tr -cd '\r' < "$SUMS" | wc -c)" -ne 0 ] \
   || grep -vcE "$SUMS_LINE_RE" "$SUMS" >/dev/null \
   || [ "$(wc -l < "$SUMS")" -gt 32 ] \
   || [ -n "$(awk '{print $2}' "$SUMS" | sort | uniq -d)" ]; then
    die "checksums.txt of $TAG is malformed - refusing to install"
fi

# ── 4. Every file, against the signed manifest ───────────────────────────
for a in "${ASSETS[@]}"; do
    want="$(awk -v n="$a" '$2 == n {print $1}' "$SUMS")"
    [ -n "$want" ] || die "checksums.txt of $TAG has no entry for $a - refusing to install"
    fetch "$BASE_URL/$a" "$STAGE/$a.part" || die "$a is missing from release $TAG - refusing to install"
    got="$(sha256sum "$STAGE/$a.part" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
        die "sha256 mismatch for $a: got $got, expected $want - refusing to install"
    fi
    mv -f "$STAGE/$a.part" "$STAGE/$a"
    log "Verified $a (sha256)"
done

# check_archive <archive> [prefix]: list it before extracting it as root. No
# absolute path, no `..`, nothing but regular files and directories, and with a
# prefix, nothing outside it (same rules as scripts/update.sh and the panel).
check_archive() {
    local archive="$1" prefix="${2:-}" name names verbose n_names n_types
    name="$(basename "$archive")"
    names="$(LC_ALL=C tar -tzf "$archive")" && verbose="$(LC_ALL=C tar -tvzf "$archive")" \
        || die "$name cannot be listed - refusing to install"
    n_names="$(printf '%s\n' "$names" | grep -c . || true)"
    n_types="$(printf '%s\n' "$verbose" | grep -c . || true)"
    if [ "$n_names" -eq 0 ] || [ "$n_names" -ne "$n_types" ]; then
        die "$name has an empty or ambiguous listing - refusing to install"
    fi
    if [ "$(printf '%s\n' "$names" | grep -cE '^/|(^|/)\.\.(/|$)' || true)" -ne 0 ]; then
        die "$name holds an absolute path or a .. component - refusing to install"
    fi
    if [ "$(printf '%s\n' "$verbose" | cut -c1 | grep -cv '^[-d]$' || true)" -ne 0 ]; then
        die "$name holds a link or a special file - refusing to install"
    fi
    if [ -n "$prefix" ] && [ "$(printf '%s\n' "$names" | grep -cv "^${prefix}/" || true)" -ne 0 ]; then
        die "$name holds files outside ${prefix}/ - refusing to install"
    fi
}
check_archive "$STAGE/cyberhunter-frontend.tar.gz"
check_archive "$STAGE/cyberhunter-source.tar.gz" cyberhunter-source

# ── 5. The verified release in the cache, its source in /opt/dockpanel ───
mkdir "$STAGE/.extract"
tar -xzf "$STAGE/cyberhunter-source.tar.gz" -C "$STAGE/.extract" --no-same-owner --no-same-permissions
[ -f "$STAGE/.extract/cyberhunter-source/scripts/setup.sh" ] \
    || die "cyberhunter-source.tar.gz has no scripts/setup.sh - refusing to install"
mv "$STAGE/.extract/cyberhunter-source" "$STAGE/cyberhunter-source"
rmdir "$STAGE/.extract"
rm -f "$STAGE/minisign.err"

RELEASE_DIR="$RELEASES_ROOT/$TAG"
# Every file is in the staging directory now (a hand-downloaded release that
# already sat in the cache included): it replaces the cached copy whole.
rm -rf "$RELEASE_DIR"
mv "$STAGE" "$RELEASE_DIR"
trap - EXIT
chmod 0700 "$RELEASE_DIR"
SRC="$RELEASE_DIR/cyberhunter-source"

mkdir -p "$INSTALL_DIR"
for d in scripts panel; do
    rm -rf "$INSTALL_DIR/$d.new"
    cp -a "$SRC/$d" "$INSTALL_DIR/$d.new"
    rm -rf "${INSTALL_DIR:?}/${d:?}"
    mv "$INSTALL_DIR/$d.new" "$INSTALL_DIR/$d"
done
[ -f "$SRC/LICENSE" ] && cp "$SRC/LICENSE" "$INSTALL_DIR/LICENSE"
log "Source of $TAG unpacked into $INSTALL_DIR"

export INSTALL_FROM_RELEASE=1
export CYBERHUNTER_RELEASE_DIR="$RELEASE_DIR"
export DOCKPANEL_VERSION="$TAG"
log "Running setup..."
exec bash "$INSTALL_DIR/scripts/setup.sh"
