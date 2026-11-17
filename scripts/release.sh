#!/usr/bin/env bash
# CyberHunter - Panel - build and publish a release.
#
# Runs on the Windows release machine (Git Bash), with Docker and gh. Every
# compilation happens in a Linux container; nothing is built from the Windows
# working copy.
#
# Usage:
#   bash scripts/release.sh [--arm64] [--dry-run] [--notes-file <file>]
#
#   --arm64        also build the four aarch64 binaries
#   --dry-run      build and check, then stop before tagging/publishing
#                  (prints the repository it would publish to)
#   --notes-file   release notes for `gh release create` (default: a one-liner)
#
# Environment:
#   CYBERHUNTER_RELEASE_REPO   GitHub repo the release is published on
#                              (default MrTheSkream/cyberhunter-releases, the
#                              public release repository; the tag itself is
#                              still created and pushed in this private source
#                              repository, origin)
#
# What a release contains (and nothing else):
#   cyberhunter-agent-linux-amd64  cyberhunter-api-linux-amd64
#   cyberhunter-cli-linux-amd64    cyberhunter-mcp-linux-amd64
#   (with --arm64: the same four names ending in -linux-arm64)
#   cyberhunter-frontend.tar.gz    cyberhunter-source.tar.gz
#   install.sh                     checksums.txt
#
# cyberhunter-source.tar.gz is `git archive HEAD -- scripts panel LICENSE`
# (the AGPL source of the release). install.sh is the committed blob, as is.
# checksums.txt is `sha256sum --text cyberhunter-* install.sh | LC_ALL=C sort -k2`,
# produced in a Linux container, LF only, so install.sh is listed too.
#
# Releases are not signed (conception/12-depot-releases-public.md, D6). The
# checksums come from the same release as the files they cover: they catch a
# corrupted or truncated download, not a release replaced by someone who holds
# the GitHub account. The integrity of a release rests on the security of that
# account (2FA, keys, scoped tokens).
#
# Publishing (step 8): the tag is created and pushed here (origin, private),
# then the release is created on CYBERHUNTER_RELEASE_REPO with --target main:
# the tag does not exist there, GitHub creates it on that repository's main.
#
# Internal entry point used by tests/release-format-pin.sh and
# tests/install-release-mode-pin.sh:
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
GLIBC_MAX="2.35"

# write_checksums <dir>: the one implementation of checksums.txt (contract
# 2.2). release.sh runs it on Linux coreutils in a container. `--text` is
# explicit because sha256sum defaults to binary mode (" *name") on MSYS, which
# the readers refuse; on Linux both modes hash the same bytes.
write_checksums() {
    local dir="$1"
    ( cd "$dir" && files=(cyberhunter-*) && { [ ! -f install.sh ] || files+=(install.sh); } \
        && sha256sum --text "${files[@]}" | LC_ALL=C sort -k2 > checksums.txt )
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
        -h|--help) sed -n '2,48p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (usage: release.sh [--arm64] [--dry-run] [--notes-file <file>])" ;;
    esac
    shift
done

REPO="${CYBERHUNTER_RELEASE_REPO:-MrTheSkream/cyberhunter-releases}"

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Docker Desktop on Windows wants a Windows path for bind mounts; MSYS would
# otherwise rewrite /src-style container paths. Both are handled here.
export MSYS_NO_PATHCONV=1
host_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -wa "$1"; else printf '%s' "$1"; fi
}

for tool in git docker; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
if [ "$DRY_RUN" = "0" ]; then
    command -v gh >/dev/null 2>&1 || die "gh is required to publish (or use --dry-run)"
fi
[ -z "$NOTES_FILE" ] || [ -f "$NOTES_FILE" ] || die "notes file not found: $NOTES_FILE"

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
echo "$TAG" | grep -Ec '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' >/dev/null \
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
# --target main only creates the tag when it is not there: an existing tag on
# the release repository would be used as is, whatever commit it names.
if [ "$DRY_RUN" = "0" ] && gh api "repos/$REPO/git/ref/tags/$TAG" >/dev/null 2>&1; then
    die "tag $TAG already exists on $REPO"
fi
# ...and needs a main branch there (the README commit), checked before the tag
# is pushed to origin rather than after.
if [ "$DRY_RUN" = "0" ] && ! gh api "repos/$REPO/branches/main" >/dev/null 2>&1; then
    die "$REPO has no main branch (or is not reachable with gh): push its README first"
fi

DIRTY="$(git status --porcelain | grep -v ' panel/frontend/tsconfig.tsbuildinfo$' || true)"
[ -z "$DIRTY" ] || die "working tree is not clean:
$DIRTY"
COMMIT="$(git rev-parse HEAD)"
echo "  version $VERSION, tag $TAG, commit $COMMIT, repo $REPO"

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
git -c core.autocrlf=false archive --format=tar.gz --prefix=cyberhunter-source/ HEAD -- scripts panel LICENSE \
    > "$DIST/cyberhunter-source.tar.gz"
# install.sh from the committed blob (LF, whatever the Windows working copy
# holds), as is. It is listed in checksums.txt.
git -c core.autocrlf=false show HEAD:scripts/install.sh > "$DIST/install.sh"
[ "$(tr -cd '\r' < "$DIST/install.sh" | wc -c)" -eq 0 ] || die "install.sh contains CR"

REQUIRED=(cyberhunter-agent-linux-amd64 cyberhunter-api-linux-amd64 cyberhunter-cli-linux-amd64
          cyberhunter-mcp-linux-amd64 cyberhunter-frontend.tar.gz cyberhunter-source.tar.gz install.sh)
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
    printf '%s\n' "${REQUIRED[@]}" | grep -cx "$name" >/dev/null || die "unexpected file in $DIST: $name"
done

# 5b. checksums.txt, computed by Linux coreutils in a container, by the same
# write_checksums function the tests run (this script, fed on stdin).
tr -d '\r' < scripts/release.sh \
  | docker run --rm -i -v "${DIST_HOST}:/d" "$BUILD_IMAGE" bash -s -- --checksums-only /d
grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$' "$DIST/checksums.txt" \
    && die "checksums.txt does not have the expected format"
if [ "$(tr -cd '\r' < "$DIST/checksums.txt" | wc -c)" -ne 0 ]; then die "checksums.txt contains CR"; fi
[ "$(wc -l < "$DIST/checksums.txt" | tr -d ' ')" = "${#REQUIRED[@]}" ] \
    || die "checksums.txt does not list exactly the ${#REQUIRED[@]} release files"

# ── 6. Checks ────────────────────────────────────────────────────────────
step "6. Checking the glibc ceiling"
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

# ── 7. Summary and confirmation ──────────────────────────────────────────
PRERELEASE=0
case "$TAG" in *-rc.*) PRERELEASE=1 ;; esac
echo ""
echo -e "${GREEN}Release $TAG ready in $DIST${NC}"
echo "  commit       $COMMIT"
echo "  repository   $REPO"
echo "  pre-release  $([ "$PRERELEASE" = "1" ] && echo yes || echo no)"
echo "  highest glibc symbol version per binary (limit GLIBC_$GLIBC_MAX):"
printf '%s' "$GLIBC_SUMMARY"
echo "  files:"
ls -l "$DIST" | sed 's/^/    /'
echo ""

if [ "$DRY_RUN" = "1" ]; then
    echo "Dry run: nothing tagged, nothing published."
    echo "  would tag $TAG on origin and publish it on $REPO (release created with --target main)"
    exit 0
fi

read -r -p "Publish ${TAG}? [y/N] " answer
case "$answer" in
    y|Y) ;;
    *) echo "Not published."; exit 1 ;;
esac

# ── 8. Tag and publish ───────────────────────────────────────────────────
step "8. Tagging and publishing $TAG"
if [ -z "$NOTES_FILE" ]; then
    NOTES_FILE="$DIST.notes.md"
    printf 'CyberHunter %s\n' "$TAG" > "$NOTES_FILE"
fi
git tag -a "$TAG" -m "CyberHunter $TAG"
git push origin "$TAG"
PRE_FLAG=()
[ "$PRERELEASE" = "1" ] && PRE_FLAG=(--prerelease)
FILES=()
for f in "${REQUIRED[@]}" checksums.txt; do FILES+=("$DIST/$f"); done
gh release create "$TAG" --repo "$REPO" --target main --title "CyberHunter $TAG" "${PRE_FLAG[@]}" \
    --notes-file "$NOTES_FILE" "${FILES[@]}"
echo -e "${GREEN}Published $TAG on $REPO${NC}"
