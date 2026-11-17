#!/usr/bin/env bash
# CyberHunter - Panel - build, sign and publish a release.
#
# Runs on the Windows release machine (Git Bash), with Docker, gh and
# minisign. Every compilation happens in a Linux container; nothing is built
# from the Windows working copy.
#
# Usage:
#   bash scripts/release.sh [--arm64] [--dry-run] [--notes-file <file>]
#
#   --arm64        also build the four aarch64 binaries
#   --dry-run      build, check and sign, then stop before tagging/publishing
#   --notes-file   release notes for `gh release create` (default: a one-liner)
#
# Environment:
#   CYBERHUNTER_MINISIGN_KEY   secret key  (default $HOME/.minisign/cyberhunter.key)
#   CYBERHUNTER_MINISIGN_PUB   public key  (default $HOME/.minisign/cyberhunter.pub)
#   CYBERHUNTER_RELEASE_REPO   GitHub repo (default MrTheSkream/cyberhunter-panel)
#   Test releases use the same variables pointed at a test key pair kept
#   outside the repository.
#
# What a release contains (and nothing else):
#   cyberhunter-agent-linux-amd64  cyberhunter-api-linux-amd64
#   cyberhunter-cli-linux-amd64    cyberhunter-mcp-linux-amd64
#   (with --arm64: the same four names ending in -linux-arm64)
#   cyberhunter-frontend.tar.gz    cyberhunter-source.tar.gz
#   checksums.txt                  checksums.txt.minisig
#
# checksums.txt is `sha256sum --text cyberhunter-* | LC_ALL=C sort -k2`, produced in
# a Linux container, LF only. It is signed byte for byte with the trusted
# comment "cyberhunter-release <tag>", which servers check against the tag
# they asked for.
#
# Internal entry point used by tests/release-format-pin.sh:
#   bash scripts/release.sh --checksums-only <dir>
# runs only the checksum step (step 5b) on <dir>, locally, and exits.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die()  { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }
step() { echo -e "${YELLOW}== $*${NC}"; }

# Image that compiles the release binaries (Ubuntu 22.04, glibc 2.35). The
# number is the org.cyberhunter.release-build label of
# scripts/release-build/Dockerfile.
BUILD_IMAGE_REPO="cyberhunter-release-build"
FRONTEND_IMAGE="node:22-bookworm"
MINISIGN_IMAGE="debian:bookworm-slim"
GLIBC_MAX="2.35"

# write_checksums <dir>: the one implementation of checksums.txt (contract
# 2.2). release.sh runs it on Linux coreutils in a container. `--text` is
# explicit because sha256sum defaults to binary mode (" *name") on MSYS, which
# the readers refuse; on Linux both modes hash the same bytes.
write_checksums() {
    local dir="$1"
    ( cd "$dir" && sha256sum --text cyberhunter-* | LC_ALL=C sort -k2 > checksums.txt )
}

if [ "${1:-}" = "--checksums-only" ]; then
    [ -n "${2:-}" ] && [ -d "$2" ] || die "usage: release.sh --checksums-only <dir>"
    write_checksums "$2"
    exit 0
fi

ARM64=0
DRY_RUN=0
NOTES_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --arm64) ARM64=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --notes-file) shift; NOTES_FILE="${1:-}"; [ -n "$NOTES_FILE" ] || die "--notes-file needs a file" ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (usage: release.sh [--arm64] [--dry-run] [--notes-file <file>])" ;;
    esac
    shift
done

MINISIGN_KEY="${CYBERHUNTER_MINISIGN_KEY:-$HOME/.minisign/cyberhunter.key}"
MINISIGN_PUB="${CYBERHUNTER_MINISIGN_PUB:-$HOME/.minisign/cyberhunter.pub}"
REPO="${CYBERHUNTER_RELEASE_REPO:-MrTheSkream/cyberhunter-panel}"

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Docker Desktop on Windows wants a Windows path for bind mounts; MSYS would
# otherwise rewrite /src-style container paths. Both are handled here.
export MSYS_NO_PATHCONV=1
host_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
IS_MSYS=0
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) IS_MSYS=1 ;; esac

for tool in git docker; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
if [ "$DRY_RUN" = "0" ]; then
    command -v gh >/dev/null 2>&1 || die "gh is required to publish (or use --dry-run)"
fi
[ -z "$NOTES_FILE" ] || [ -f "$NOTES_FILE" ] || die "notes file not found: $NOTES_FILE"
[ -f "$MINISIGN_KEY" ] || die "minisign secret key not found: $MINISIGN_KEY"
[ -f "$MINISIGN_PUB" ] || die "minisign public key not found: $MINISIGN_PUB"

# ── 1. Versions, tag, clean tree ─────────────────────────────────────────
step "1. Checking versions, tag and working tree"
cargo_version() { sed -n 's/^version *= *"\(.*\)"/\1/p' "$1" | head -1 | tr -d '\r'; }
VERSION="$(cargo_version panel/agent/Cargo.toml)"
V_BACKEND="$(cargo_version panel/backend/Cargo.toml)"
V_CLI="$(cargo_version panel/cli/Cargo.toml)"
V_MCP="$(cargo_version panel/mcp/Cargo.toml)"
V_FRONTEND="$(sed -n 's/^ *"version": *"\(.*\)".*/\1/p' panel/frontend/package.json | head -1 | tr -d '\r')"
if [ "$VERSION" != "$V_BACKEND" ] || [ "$VERSION" != "$V_CLI" ] || [ "$VERSION" != "$V_MCP" ] || [ "$VERSION" != "$V_FRONTEND" ]; then
    die "version mismatch: agent=$VERSION backend=$V_BACKEND cli=$V_CLI mcp=$V_MCP frontend=$V_FRONTEND"
fi
TAG="v${VERSION}"
echo "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' \
    || die "tag $TAG is not vX.Y.Z or vX.Y.Z-rc.N"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists locally. Bump the version first."
fi
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    die "tag $TAG already exists on origin. Bump the version first."
fi
if [ "$DRY_RUN" = "0" ] && gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    die "a release $TAG already exists on $REPO"
fi

DIRTY="$(git status --porcelain | grep -v ' panel/frontend/tsconfig.tsbuildinfo$' || true)"
[ -z "$DIRTY" ] || die "working tree is not clean:
$DIRTY"
COMMIT="$(git rev-parse HEAD)"
echo "  version $VERSION, tag $TAG, commit $COMMIT, repo $REPO"

# The public key line (2nd line of the .pub) is compiled into api and agent.
PUBKEY="$(sed -n '2p' "$MINISIGN_PUB" | tr -d '\r\n ')"
case "$PUBKEY" in
    RW*) ;;
    *) die "$MINISIGN_PUB does not look like a minisign public key (2nd line must start with RW)" ;;
esac
# Key ID as minisign prints it: bytes 2..9 of the decoded key, little-endian u64.
KEY_ID="$(printf '%s' "$PUBKEY" | base64 -d 2>/dev/null | od -An -tx1 -j2 -N8 \
    | tr -s ' \n' ' ' | awk '{ for (i = NF; i >= 1; i--) printf "%s", toupper($i) }')"
[ ${#KEY_ID} -eq 16 ] || die "could not read the key ID from $MINISIGN_PUB"
echo "  signing key ID $KEY_ID"

DIST="dist/release-${VERSION}"
rm -rf "$DIST"
mkdir -p "$DIST"
DIST_HOST="$(host_path "$ROOT/$DIST")"

# ── 2-3. Source archive and release binaries ─────────────────────────────
step "2-3. Compiling release binaries in the Ubuntu 22.04 image"
BUILD_LABEL="$(sed -n 's/^LABEL org\.cyberhunter\.release-build="\([0-9]*\)".*/\1/p' scripts/release-build/Dockerfile | tr -d '\r')"
[ -n "$BUILD_LABEL" ] || die "scripts/release-build/Dockerfile has no org.cyberhunter.release-build label"
BUILD_IMAGE="${BUILD_IMAGE_REPO}:${BUILD_LABEL}"
HAVE_LABEL="$(docker image inspect --format '{{ index .Config.Labels "org.cyberhunter.release-build" }}' "$BUILD_IMAGE" 2>/dev/null || true)"
if [ "$HAVE_LABEL" != "$BUILD_LABEL" ]; then
    echo "  building $BUILD_IMAGE"
    docker build -t "$BUILD_IMAGE" scripts/release-build
fi

BUILD_ARGS=(agent backend cli mcp)
[ "$ARM64" = "1" ] && BUILD_ARGS=(--arm64 "${BUILD_ARGS[@]}")
# The source is the committed tree, piped on stdin: no CRLF, no path rewriting.
git -c core.autocrlf=false archive --format=tar HEAD \
  | docker run --rm -i \
      -e CYBERHUNTER_UPDATE_PUBKEY="$PUBKEY" \
      -v cyberhunter-release-cargo:/usr/local/cargo/registry \
      -v "cyberhunter-release-target-${BUILD_LABEL}:/target" \
      -v "${DIST_HOST}:/out" \
      "$BUILD_IMAGE" build-in-container.sh "${BUILD_ARGS[@]}"

# ── 4. Frontend ──────────────────────────────────────────────────────────
step "4. Building the frontend in $FRONTEND_IMAGE"
# scripts/ rides along: the prebuild step stages scripts/install-agent.sh into
# the frontend dist, where the panel serves it.
git -c core.autocrlf=false archive --format=tar HEAD panel/frontend scripts \
  | docker run --rm -i -v "${DIST_HOST}:/out" "$FRONTEND_IMAGE" bash -c '
      set -euo pipefail
      mkdir -p /w && tar -C /w -xf -
      cd /w/panel/frontend
      npm ci --no-audit --no-fund
      npm run build
      tar -czf /out/cyberhunter-frontend.tar.gz dist/'

# ── 5. Source archive and checksums ──────────────────────────────────────
step "5. Assembling $DIST"
git -c core.autocrlf=false archive --format=tar.gz --prefix=cyberhunter-source/ HEAD -- scripts panel \
    > "$DIST/cyberhunter-source.tar.gz"

REQUIRED=(cyberhunter-agent-linux-amd64 cyberhunter-api-linux-amd64 cyberhunter-cli-linux-amd64
          cyberhunter-mcp-linux-amd64 cyberhunter-frontend.tar.gz cyberhunter-source.tar.gz)
if [ "$ARM64" = "1" ]; then
    REQUIRED+=(cyberhunter-agent-linux-arm64 cyberhunter-api-linux-arm64 cyberhunter-cli-linux-arm64
               cyberhunter-mcp-linux-arm64)
fi
for f in "${REQUIRED[@]}"; do
    [ -s "$DIST/$f" ] || die "missing release file $DIST/$f"
done
# Nothing else may be published.
for f in "$DIST"/*; do
    name="$(basename "$f")"
    printf '%s\n' "${REQUIRED[@]}" | grep -qx "$name" || die "unexpected file in $DIST: $name"
done

# 5b. checksums.txt, computed by Linux coreutils in a container, by the same
# write_checksums function the tests run (this script, fed on stdin).
tr -d '\r' < scripts/release.sh \
  | docker run --rm -i -v "${DIST_HOST}:/d" "$BUILD_IMAGE" bash -s -- --checksums-only /d
grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$' "$DIST/checksums.txt" \
    && die "checksums.txt does not have the expected format"
if grep -q $'\r' "$DIST/checksums.txt"; then die "checksums.txt contains CR"; fi
[ "$(wc -l < "$DIST/checksums.txt" | tr -d ' ')" = "${#REQUIRED[@]}" ] \
    || die "checksums.txt does not list exactly the ${#REQUIRED[@]} release files"

# ── 6. Checks ────────────────────────────────────────────────────────────
step "6. Checking glibc ceiling and the compiled key"
BINARIES=()
for f in "${REQUIRED[@]}"; do
    case "$f" in *-linux-amd64|*-linux-arm64) BINARIES+=("$f") ;; esac
done
GLIBC_SUMMARY=""
for b in "${BINARIES[@]}"; do
    line="$(docker run --rm -v "${DIST_HOST}:/d:ro" "$BUILD_IMAGE" check-glibc.sh "/d/$b" "$GLIBC_MAX")" \
        || die "$b fails the glibc check"
    echo "  $line"
    GLIBC_SUMMARY+="    $b: $(printf '%s' "$line" | sed -n 's/.* max \(GLIBC_[^ ]*\) .*/\1/p')"$'\n'
done
for b in "${BINARIES[@]}"; do
    case "$b" in
        cyberhunter-api-*|cyberhunter-agent-*)
            n="$(grep -c -a -F "$PUBKEY" "$DIST/$b" || true)"
            [ "${n:-0}" -ge 1 ] || die "$b does not contain the signing key (was CYBERHUNTER_UPDATE_PUBKEY passed?)"
            ;;
    esac
done

# ── 7. Signature ─────────────────────────────────────────────────────────
step "7. Signing checksums.txt (minisign will ask for the key passphrase)"
TRUSTED="cyberhunter-release ${TAG}"
if command -v minisign >/dev/null 2>&1; then
    # MSYS path conversion is off for docker, so a native Windows minisign
    # gets Windows paths explicitly.
    M_KEY="$(host_path "$MINISIGN_KEY")"; M_PUB="$(host_path "$MINISIGN_PUB")"
    M_SUMS="$(host_path "$ROOT/$DIST/checksums.txt")"; M_SIG="$(host_path "$ROOT/$DIST/checksums.txt.minisig")"
    minisign -S -s "$M_KEY" -m "$M_SUMS" -x "$M_SIG" -t "$TRUSTED"
    minisign -V -p "$M_PUB" -m "$M_SUMS" -x "$M_SIG"
else
    KEY_DIR_HOST="$(host_path "$(cd "$(dirname "$MINISIGN_KEY")" && pwd)")"
    PUB_DIR_HOST="$(host_path "$(cd "$(dirname "$MINISIGN_PUB")" && pwd)")"
    KEY_NAME="$(basename "$MINISIGN_KEY")"
    PUB_NAME="$(basename "$MINISIGN_PUB")"
    RUN=(docker run --rm -it -v "${DIST_HOST}:/d" -v "${KEY_DIR_HOST}:/k:ro" -v "${PUB_DIR_HOST}:/p:ro" "$MINISIGN_IMAGE")
    [ "$IS_MSYS" = "1" ] && command -v winpty >/dev/null 2>&1 && RUN=(winpty "${RUN[@]}")
    "${RUN[@]}" bash -c '
        set -euo pipefail
        apt-get update -qq >/dev/null && apt-get install -y -qq minisign >/dev/null
        minisign -S -s "/k/$1" -m /d/checksums.txt -x /d/checksums.txt.minisig -t "$2"
        minisign -V -p "/p/$3" -m /d/checksums.txt -x /d/checksums.txt.minisig' \
        _ "$KEY_NAME" "$TRUSTED" "$PUB_NAME"
fi
[ -s "$DIST/checksums.txt.minisig" ] || die "no signature was written"
grep -qxF "trusted comment: $TRUSTED" <(tr -d '\r' < "$DIST/checksums.txt.minisig") \
    || die "the signature does not carry the trusted comment '$TRUSTED'"
# Pre-hashed signatures only ("ED"). An old minisign writes legacy "Ed"
# signatures, which every server refuses: stop here rather than publish them.
SIG_ALG="$(sed -n '2p' "$DIST/checksums.txt.minisig" | tr -d '\r\n' | base64 -d 2>/dev/null | head -c 2 || true)"
[ "$SIG_ALG" = "ED" ] || die "signature algorithm is '$SIG_ALG', expected ED (pre-hashed); upgrade minisign"

# ── 8. Summary and confirmation ──────────────────────────────────────────
PRERELEASE=0
case "$TAG" in *-rc.*) PRERELEASE=1 ;; esac
echo ""
echo -e "${GREEN}Release $TAG ready in $DIST${NC}"
echo "  commit       $COMMIT"
echo "  repository   $REPO"
echo "  signing key  $KEY_ID"
echo "  pre-release  $([ "$PRERELEASE" = "1" ] && echo yes || echo no)"
echo "  highest glibc symbol version per binary (limit GLIBC_$GLIBC_MAX):"
printf '%s' "$GLIBC_SUMMARY"
echo "  files:"
ls -l "$DIST" | sed 's/^/    /'
echo ""

if [ "$DRY_RUN" = "1" ]; then
    echo "Dry run: nothing tagged, nothing published."
    exit 0
fi

read -r -p "Publish ${TAG}? [y/N] " answer
case "$answer" in
    y|Y) ;;
    *) echo "Not published."; exit 1 ;;
esac

# ── 9. Tag and publish ───────────────────────────────────────────────────
step "9. Tagging and publishing $TAG"
if [ -z "$NOTES_FILE" ]; then
    NOTES_FILE="$DIST.notes.md"
    printf 'CyberHunter %s\n' "$TAG" > "$NOTES_FILE"
fi
git tag -a "$TAG" -m "CyberHunter $TAG"
git push origin "$TAG"
PRE_FLAG=()
[ "$PRERELEASE" = "1" ] && PRE_FLAG=(--prerelease)
FILES=()
for f in "${REQUIRED[@]}" checksums.txt checksums.txt.minisig; do FILES+=("$DIST/$f"); done
gh release create "$TAG" --repo "$REPO" --verify-tag --title "CyberHunter $TAG" "${PRE_FLAG[@]}" \
    --notes-file "$NOTES_FILE" "${FILES[@]}"
echo -e "${GREEN}Published $TAG on $REPO${NC}"
