#!/usr/bin/env bash
# install.sh release mode (conception/12-depot-releases-public.md, D4 and D6),
# run for real, offline, on a fake release (releases are not signed, D6):
#
#   - a valid release is checked against its checksums.txt, cached in
#     /var/lib/dockpanel/releases/<tag>, unpacked into /opt/dockpanel and
#     handed to setup.sh (a stub that only records its environment) with
#     INSTALL_FROM_RELEASE=1; the committed install.sh is the shipped one, and
#     it needs no minisign and no key;
#   - refused, with setup.sh never reached and nothing left in the cache: a
#     missing checksums.txt, a bad sha256, a missing asset, a manifest without
#     the asset, a malformed manifest (bad line, CR, duplicate), an archive
#     escaping its prefix, a malformed tag, an implicit pre-release, a base
#     URL that is neither https nor file.
#
# Downloads go through CYBERHUNTER_RELEASE_BASE_URL=file://<dir> (the install.sh
# test hook); the "latest" lookup through a curl wrapper. No network.
#
# It writes /opt/dockpanel and /var/lib/dockpanel/releases, so it only runs as
# root in a throwaway container (or with CYBERHUNTER_TEST_ALLOW_SYSTEM=1).
# Needs curl, tar, coreutils. For example, from the repository root on an LF
# copy:
#   docker run --rm -v "$PWD:/src:ro" debian:bookworm bash -c \
#     'apt-get update -qq && apt-get install -y -qq curl >/dev/null \
#      && cp -r /src /tmp/w && bash /tmp/w/tests/install-release-mode-pin.sh'
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$ROOT/scripts/install.sh"
REL="$ROOT/scripts/release.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

if [ "$(id -u)" != "0" ]; then echo "must run as root (in a container)"; exit 2; fi
if [ ! -f /.dockerenv ] && [ "${CYBERHUNTER_TEST_ALLOW_SYSTEM:-0}" != "1" ]; then
    echo "refusing to run outside a container: it overwrites /opt/dockpanel"; exit 2
fi
for t in curl tar sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "$t is required"; exit 2; }
done
if [ -e /opt/dockpanel ] || [ -e /var/lib/dockpanel ]; then
    if [ "${CYBERHUNTER_TEST_ALLOW_SYSTEM:-0}" != "1" ] && [ ! -f /.dockerenv ]; then
        echo "/opt/dockpanel or /var/lib/dockpanel exists - refusing"; exit 2
    fi
fi

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
STUB_LOG=/tmp/install-stub.log
CACHE=/var/lib/dockpanel/releases

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported arch"; exit 2 ;;
esac

# ── fixtures ─────────────────────────────────────────────────────────────
# Releases are shipped with the committed install.sh, as is.
if grep -cE 'minisign|STAMPED_PUBKEY|CYBERHUNTER_PUBKEY|checksums\.txt\.minisig|cyberhunter-release ' "$INSTALL" >/dev/null; then
    bad "install.sh still names minisign, a signing key or a signature"
else
    ok "install.sh names no minisign, no signing key and no signature"
fi

# make_release <dir> <tag>: a complete fake release in <dir>, checksums by
# release.sh, no signature.
SRC_TREE="$T/srctree"
mkdir -p "$SRC_TREE/cyberhunter-source/scripts" "$SRC_TREE/cyberhunter-source/panel/agent"
cat > "$SRC_TREE/cyberhunter-source/scripts/setup.sh" <<STUB
#!/usr/bin/env bash
# setup.sh stub: records how it was called, installs nothing.
{
  echo "script=\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)/setup.sh"
  echo "INSTALL_FROM_RELEASE=\${INSTALL_FROM_RELEASE:-}"
  echo "CYBERHUNTER_RELEASE_DIR=\${CYBERHUNTER_RELEASE_DIR:-}"
  echo "DOCKPANEL_VERSION=\${DOCKPANEL_VERSION:-}"
} > $STUB_LOG
STUB
echo "unit" > "$SRC_TREE/cyberhunter-source/panel/agent/dockpanel-agent.service"
echo "AGPL" > "$SRC_TREE/cyberhunter-source/LICENSE"
make_release() {
    local d="$1" tag="$2" b
    rm -rf "$d"; mkdir -p "$d"
    for b in agent api cli mcp; do
        printf '\177ELFfake-%s-%s\n' "$b" "$tag" > "$d/cyberhunter-$b-linux-$ARCH"
    done
    mkdir -p "$T/fe/dist"; echo "<html>" > "$T/fe/dist/index.html"
    tar -C "$T/fe" -czf "$d/cyberhunter-frontend.tar.gz" dist
    tar -C "$SRC_TREE" -czf "$d/cyberhunter-source.tar.gz" cyberhunter-source
    cp "$INSTALL" "$d/install.sh"
    bash "$REL" --checksums-only "$d"
}

reset_box() { rm -rf /opt/dockpanel /var/lib/dockpanel "$STUB_LOG"; }

# run_install <script> [VAR=value...]: install.sh in a clean environment.
run_install() {
    local script="$1"; shift
    reset_box
    env -i PATH="${TEST_PATH:-$PATH}" HOME=/root "$@" bash "$script" > "$T/out" 2>&1
}

TAG="v9.9.9-rc.1"
R="$T/rel/$TAG"

# expect_refusal <label> <message> <script> [VAR=value...]
expect_refusal() {
    local label="$1" msg="$2"; shift 2
    run_install "$@"; local rc=$?
    local leftovers
    leftovers="$(ls -A "$CACHE" 2>/dev/null | tr '\n' ' ')"
    if [ "$rc" -ne 0 ] && [ ! -e "$STUB_LOG" ] && grep -qF -- "$msg" "$T/out" && [ -z "$leftovers" ]; then
        ok "$label: refused ('$msg')"
    else
        bad "$label: rc=$rc stub_ran=$([ -e "$STUB_LOG" ] && echo yes || echo no) cache='$leftovers'"
        sed 's/^/        /' "$T/out" | tail -6
    fi
}

echo "── 1. a valid release reaches setup.sh ──"
make_release "$R" "$TAG"
[ -e "$R/checksums.txt.minisig" ] && bad "the fake release has a signature file" || ok "the fake release has no checksums.txt.minisig"
# No minisign anywhere on PATH: a PATH of symlinks to the tools install.sh uses.
NOMS="$T/nominisign"; mkdir -p "$NOMS"
for t in bash sh env apt-get curl tar gzip sha256sum awk sed grep tr wc sort uniq cut cat ls mkdir mktemp \
         rm mv cp chmod rmdir basename dirname head tail uname stat sleep; do
    p="$(command -v "$t" 2>/dev/null)" && [ "${p#/}" != "$p" ] && ln -sf "$p" "$NOMS/$t"
done
TEST_PATH="$NOMS" run_install "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"; rc=$?
if [ "$rc" = "0" ] && [ -f "$STUB_LOG" ]; then
    ok "the committed install.sh installs a valid release, with no minisign on PATH"
    grep -qx "INSTALL_FROM_RELEASE=1" "$STUB_LOG" && ok "setup.sh gets INSTALL_FROM_RELEASE=1" || bad "INSTALL_FROM_RELEASE is not 1"
    grep -qx "CYBERHUNTER_RELEASE_DIR=$CACHE/$TAG" "$STUB_LOG" \
        && ok "setup.sh gets CYBERHUNTER_RELEASE_DIR=$CACHE/<tag> (basename = tag)" || bad "wrong CYBERHUNTER_RELEASE_DIR: $(cat "$STUB_LOG")"
    grep -qx "DOCKPANEL_VERSION=$TAG" "$STUB_LOG" && ok "setup.sh gets DOCKPANEL_VERSION=<tag>" || bad "wrong DOCKPANEL_VERSION"
    grep -qx "script=/opt/dockpanel/scripts/setup.sh" "$STUB_LOG" \
        && ok "the setup.sh that runs is the one from the verified source archive, in /opt/dockpanel" || bad "ran $(head -1 "$STUB_LOG")"
    [ -f /opt/dockpanel/panel/agent/dockpanel-agent.service ] && [ -f /opt/dockpanel/LICENSE ] \
        && ok "/opt/dockpanel holds panel/ and LICENSE from the archive" || bad "/opt/dockpanel is incomplete"
    missing=""
    for f in cyberhunter-agent-linux-$ARCH cyberhunter-api-linux-$ARCH cyberhunter-cli-linux-$ARCH \
             cyberhunter-mcp-linux-$ARCH cyberhunter-frontend.tar.gz cyberhunter-source.tar.gz \
             checksums.txt cyberhunter-source/scripts/setup.sh; do
        [ -f "$CACHE/$TAG/$f" ] || missing="$missing $f"
    done
    [ -z "$missing" ] && ok "the cache holds the verified files and the unpacked source" || bad "cache misses:$missing"
    if (cd "$CACHE/$TAG" && sha256sum -c --ignore-missing --quiet checksums.txt); then
        ok "the cached files match checksums.txt"
    else
        bad "the cached files do not match checksums.txt"
    fi
    [ "$(stat -c %a "$CACHE/$TAG")" = "700" ] && ok "the cache entry is 0700" || bad "cache entry mode $(stat -c %a "$CACHE/$TAG")"
    [ -z "$(ls -A "$CACHE" | grep '^\.')" ] && ok "no staging directory left behind" || bad "staging left: $(ls -A "$CACHE")"
    grep -q "Verified cyberhunter-source.tar.gz (sha256)" "$T/out" && ok "it says what it verified" || bad "no 'Verified ... (sha256)' line"
    grep -qi 'signature' "$T/out" && bad "the output still talks about a signature" || ok "the output claims no signature"
else
    bad "a valid release was refused (rc $rc)"; sed 's/^/        /' "$T/out" | tail -8
fi

run_install "$INSTALL" CYBERHUNTER_RELEASE_DIR="$R"; rc=$?
if [ "$rc" = "0" ] && grep -qx "CYBERHUNTER_RELEASE_DIR=$CACHE/$TAG" "$STUB_LOG" 2>/dev/null; then
    ok "CYBERHUNTER_RELEASE_DIR=<dir named after the tag>: same checks, installed from that directory"
else
    bad "the hand-downloaded release mode failed (rc $rc)"; tail -4 "$T/out"
fi

echo "── 2. refusals ──"
R2="$T/rel2/$TAG"
make_release "$R2" "$TAG"
rm -f "$R2/checksums.txt"
expect_refusal "missing checksums.txt" "checksums.txt of $TAG could not be downloaded" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
printf 'x' >> "$R2/cyberhunter-api-linux-$ARCH"
expect_refusal "bad sha256" "sha256 mismatch for cyberhunter-api-linux-$ARCH" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
rm -f "$R2/cyberhunter-frontend.tar.gz"
expect_refusal "missing asset" "cyberhunter-frontend.tar.gz is missing from release $TAG" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
grep -v "cyberhunter-mcp-linux-$ARCH" "$R2/checksums.txt" > "$T/s" && mv "$T/s" "$R2/checksums.txt"
expect_refusal "manifest without an asset" "has no entry for cyberhunter-mcp-linux-$ARCH" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
printf 'not a line\n' >> "$R2/checksums.txt"
expect_refusal "malformed manifest" "checksums.txt of $TAG is malformed" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
sed -i 's/$/\r/' "$R2/checksums.txt"
expect_refusal "manifest with CRLF" "checksums.txt of $TAG is malformed" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
head -1 "$R2/checksums.txt" >> "$R2/checksums.txt"
expect_refusal "manifest with a duplicate entry" "checksums.txt of $TAG is malformed" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
mkdir -p "$T/evil/other"; echo x > "$T/evil/other/f"
tar -C "$SRC_TREE" -cf "$T/evil.tar" cyberhunter-source && tar -C "$T/evil" -rf "$T/evil.tar" other && gzip -c "$T/evil.tar" > "$R2/cyberhunter-source.tar.gz"
bash "$REL" --checksums-only "$R2"
expect_refusal "source archive escaping cyberhunter-source/" "holds files outside cyberhunter-source/" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

expect_refusal "malformed tag" "is not vX.Y.Z or vX.Y.Z-rc.N" \
    "$INSTALL" DOCKPANEL_VERSION="v9.9" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
expect_refusal "tag with a path in it" "is not vX.Y.Z or vX.Y.Z-rc.N" \
    "$INSTALL" DOCKPANEL_VERSION="v9.9.9/../x" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
expect_refusal "base URL that is neither https nor file" "must start with https:// or file:///" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="http://example.invalid"

echo "── 3. latest release (curl wrapper, no network) ──"
FB="$T/fakebin"; mkdir -p "$FB"
REAL_CURL="$(command -v curl)"
cat > "$FB/curl" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
  if [ "\$a" = '%{url_effective}' ]; then printf '%s' "\$FAKE_LATEST"; exit 0; fi
done
exec "$REAL_CURL" "\$@"
EOF
chmod +x "$FB/curl"
GH="https://github.com/MrTheSkream/cyberhunter-releases/releases/tag"
RS="$T/rel/v9.9.9"
make_release "$RS" v9.9.9
TEST_PATH="$FB:$PATH" run_install "$INSTALL" FAKE_LATEST="$GH/v9.9.9" CYBERHUNTER_RELEASE_BASE_URL="file://$RS"; rc=$?
if [ "$rc" = "0" ] && grep -qx "DOCKPANEL_VERSION=v9.9.9" "$STUB_LOG" 2>/dev/null; then
    ok "no DOCKPANEL_VERSION: the latest stable tag is resolved and installed"
else
    bad "latest stable resolution failed (rc $rc)"; tail -4 "$T/out"
fi
TEST_PATH="$FB:$PATH" expect_refusal "latest pointing at a pre-release" "is not a stable vX.Y.Z tag" \
    "$INSTALL" FAKE_LATEST="$GH/$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
TEST_PATH="$FB:$PATH" expect_refusal "latest not leading to a release" "did not lead to a release" \
    "$INSTALL" FAKE_LATEST="https://github.com/MrTheSkream/cyberhunter-releases/releases" CYBERHUNTER_RELEASE_BASE_URL="file://$R"

echo "── 4. clone mode is still there ──"
if grep -q 'git clone --quiet --depth 1 -b "\$VERSION" "\$REPO_URL" "\$INSTALL_DIR"' "$INSTALL"; then
    ok "CYBERHUNTER_REPO_URL still clones the given ref"
else
    bad "clone mode is gone"
fi
if bash -n "$INSTALL"; then ok "bash -n install.sh"; else bad "bash -n install.sh"; fi

reset_box
echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
