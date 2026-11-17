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
#                  (prints the repository it would publish to)
#   --notes-file   release notes for `gh release create` (default: a one-liner)
#
# Environment:
#   CYBERHUNTER_MINISIGN_KEY   secret key  (default $HOME/.minisign/cyberhunter.key)
#   CYBERHUNTER_MINISIGN_PUB   public key  (default $HOME/.minisign/cyberhunter.pub)
#   CYBERHUNTER_RELEASE_REPO   GitHub repo the release is published on
#                              (default MrTheSkream/cyberhunter-releases, the
#                              public release repository; the tag itself is
#                              still created and pushed in this private source
#                              repository, origin)
#   CYBERHUNTER_SIGN_INLINE    set to 1 to run a native minisign inline under
#                              Git Bash too (see "Signing" below)
#   Test releases use the same variables pointed at a test key pair kept
#   outside the repository.
#
# Signing (step 7, also done by --dry-run):
#   Linux/macOS: minisign runs inline and asks for the key passphrase.
#   Git Bash with a native Windows minisign.exe: the console app does not get
#   the keyboard through mintty/bash, so the script prints the one-line
#   PowerShell command to run in another terminal, waits for Enter, then
#   verifies the signature. CYBERHUNTER_SIGN_INLINE=1 forces inline signing.
#   No minisign on PATH: it runs in a Debian container (winpty under MSYS).
#
# What a release contains (and nothing else):
#   cyberhunter-agent-linux-amd64  cyberhunter-api-linux-amd64
#   cyberhunter-cli-linux-amd64    cyberhunter-mcp-linux-amd64
#   (with --arm64: the same four names ending in -linux-arm64)
#   cyberhunter-frontend.tar.gz    cyberhunter-source.tar.gz
#   install.sh                     (with the signing public key stamped in)
#   checksums.txt                  checksums.txt.minisig
#
# cyberhunter-source.tar.gz is `git archive HEAD -- scripts panel LICENSE`
# (the AGPL source of the release). checksums.txt is
# `sha256sum --text cyberhunter-* install.sh | LC_ALL=C sort -k2`, produced in
# a Linux container, LF only, so install.sh is covered by the signature too.
# It is signed byte for byte with the trusted comment "cyberhunter-release
# <tag>", which servers and install.sh check against the tag they asked for.
#
# Publishing (step 9): the tag is created and pushed here (origin, private),
# then the release is created on CYBERHUNTER_RELEASE_REPO with --target main:
# the tag does not exist there, GitHub creates it on that repository's main.
#
# Internal entry points used by tests/release-format-pin.sh and
# tests/install-release-mode-pin.sh:
#   bash scripts/release.sh --checksums-only <dir>
# runs only the checksum step (step 5b) on <dir>, locally, and exits.
#   bash scripts/release.sh --stamp-install-only <install.sh> <pubkey> <out>
# runs only the install.sh stamping (step 5) and exits.
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
    ( cd "$dir" && files=(cyberhunter-*) && { [ ! -f install.sh ] || files+=(install.sh); } \
        && sha256sum --text "${files[@]}" | LC_ALL=C sort -k2 > checksums.txt )
}

# stamp_install <src> <pubkey> <out>: <src> (scripts/install.sh) with its one
# empty CYBERHUNTER_STAMPED_PUBKEY="" line set to <pubkey>. Refuses anything
# but exactly one placeholder line, a CR, or a key that is not RW + base64.
stamp_install() {
    local src="$1" key="$2" out="$3"
    printf '%s' "$key" | grep -Eqx 'RW[A-Za-z0-9+/]{54}' || die "not a minisign public key: $key"
    [ "$(grep -c '^CYBERHUNTER_STAMPED_PUBKEY=' "$src" || true)" = "1" ] \
        && [ "$(grep -cx 'CYBERHUNTER_STAMPED_PUBKEY=""' "$src" || true)" = "1" ] \
        || die "$src must hold exactly one CYBERHUNTER_STAMPED_PUBKEY=\"\" line"
    [ "$(tr -cd '\r' < "$src" | wc -c)" -eq 0 ] || die "$src contains CR"
    sed "s|^CYBERHUNTER_STAMPED_PUBKEY=\"\"\$|CYBERHUNTER_STAMPED_PUBKEY=\"$key\"|" "$src" > "$out"
    [ "$(grep -cx "CYBERHUNTER_STAMPED_PUBKEY=\"$key\"" "$out" || true)" = "1" ] \
        || die "install.sh was not stamped with the signing key"
    [ "$(wc -l < "$src")" = "$(wc -l < "$out")" ] || die "stamping changed the line count of install.sh"
    [ "$(tr -cd '\r' < "$out" | wc -c)" -eq 0 ] || die "the stamped install.sh contains CR"
}

# ps_quote <s>: <s> as a PowerShell single-quoted string ('' escapes ').
ps_quote() { local q="'"; printf "'%s'" "${1//$q/$q$q}"; }

# sign_native: step 7 with the minisign found on PATH. Reads M_KEY, M_PUB,
# M_SUMS, M_SIG (paths as minisign sees them), SIG_FILE (the same signature as
# this shell sees it), TRUSTED and IS_MSYS. Under Git Bash a native Windows
# minisign.exe cannot read the passphrase from the terminal (it sees an empty
# input and fails with "Wrong password"), so the signing command is handed to
# the user to run in PowerShell; CYBERHUNTER_SIGN_INLINE=1 overrides that.
# The verification always runs here.
sign_native() {
    if [ "$IS_MSYS" = "1" ] && [ "${CYBERHUNTER_SIGN_INLINE:-0}" != "1" ]; then
        echo "  Git Bash cannot pass the passphrase to the native minisign. In another"
        echo "  terminal (PowerShell), run this one line and type the passphrase there:"
        echo ""
        echo "    minisign -S -s $(ps_quote "$M_KEY") -m $(ps_quote "$M_SUMS") -x $(ps_quote "$M_SIG") -t $(ps_quote "$TRUSTED")"
        echo ""
        echo "  (CYBERHUNTER_SIGN_INLINE=1 runs minisign here instead, if this terminal works.)"
        local _answer
        while :; do
            read -r -p "Press Enter once checksums.txt.minisig is written... " _answer \
                || die "no input while waiting for the signature"
            [ -s "$SIG_FILE" ] && break
            echo "  $SIG_FILE is not there yet."
        done
    else
        minisign -S -s "$M_KEY" -m "$M_SUMS" -x "$M_SIG" -t "$TRUSTED"
    fi
    minisign -V -p "$M_PUB" -m "$M_SUMS" -x "$M_SIG"
}

if [ "${1:-}" = "--stamp-install-only" ]; then
    [ $# -eq 4 ] && [ -f "$2" ] || die "usage: release.sh --stamp-install-only <install.sh> <pubkey> <out>"
    stamp_install "$2" "$3" "$4"
    exit 0
fi
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
        -h|--help) sed -n '2,61p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (usage: release.sh [--arm64] [--dry-run] [--notes-file <file>])" ;;
    esac
    shift
done

MINISIGN_KEY="${CYBERHUNTER_MINISIGN_KEY:-$HOME/.minisign/cyberhunter.key}"
MINISIGN_PUB="${CYBERHUNTER_MINISIGN_PUB:-$HOME/.minisign/cyberhunter.pub}"
REPO="${CYBERHUNTER_RELEASE_REPO:-MrTheSkream/cyberhunter-releases}"

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Docker Desktop on Windows wants a Windows path for bind mounts; MSYS would
# otherwise rewrite /src-style container paths. Both are handled here.
export MSYS_NO_PATHCONV=1
host_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -wa "$1"; else printf '%s' "$1"; fi
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
git -c core.autocrlf=false archive --format=tar.gz --prefix=cyberhunter-source/ HEAD -- scripts panel LICENSE \
    > "$DIST/cyberhunter-source.tar.gz"
# install.sh from the committed blob (LF, whatever the Windows working copy
# holds), with the signing key stamped in. It is listed in checksums.txt.
git -c core.autocrlf=false show HEAD:scripts/install.sh > "$DIST.install.sh.src"
stamp_install "$DIST.install.sh.src" "$PUBKEY" "$DIST/install.sh"
rm -f "$DIST.install.sh.src"

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
SIG_FILE="$DIST/checksums.txt.minisig"
if command -v minisign >/dev/null 2>&1; then
    # MSYS path conversion is off for docker, so a native Windows minisign
    # gets Windows paths explicitly.
    M_KEY="$(host_path "$MINISIGN_KEY")"; M_PUB="$(host_path "$MINISIGN_PUB")"
    M_SUMS="$(host_path "$ROOT/$DIST/checksums.txt")"; M_SIG="$(host_path "$ROOT/$SIG_FILE")"
    sign_native
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
    echo "  would tag $TAG on origin and publish it on $REPO (release created with --target main)"
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
gh release create "$TAG" --repo "$REPO" --target main --title "CyberHunter $TAG" "${PRE_FLAG[@]}" \
    --notes-file "$NOTES_FILE" "${FILES[@]}"
echo -e "${GREEN}Published $TAG on $REPO${NC}"
