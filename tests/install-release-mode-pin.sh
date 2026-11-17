#!/usr/bin/env bash
# install.sh release mode (conception/12-depot-releases-public.md, D4), run for
# real, offline, on a fake release signed with a throwaway minisign key:
#
#   - a valid release is verified, cached in /var/lib/dockpanel/releases/<tag>,
#     unpacked into /opt/dockpanel and handed to setup.sh (a stub that only
#     records its environment) with INSTALL_FROM_RELEASE=1;
#   - the copy stamped by `release.sh --stamp-install-only` carries the key, the
#     committed copy carries none and refuses release mode;
#   - refused, with setup.sh never reached and nothing left in the cache: a
#     missing signature, a signature by another key, a signature for another
#     tag, a tampered checksums.txt, a legacy signature, a bad sha256, a
#     missing asset, a manifest without the asset, an archive escaping its
#     prefix, a malformed tag, an implicit pre-release, a missing minisign.
#
# Downloads go through CYBERHUNTER_RELEASE_BASE_URL=file://<dir> (the install.sh
# test hook); the "latest" lookup through a curl wrapper. No network.
#
# It writes /opt/dockpanel and /var/lib/dockpanel/releases, and moves the
# minisign binary away for one case, so it only runs as root in a throwaway
# container (or with CYBERHUNTER_TEST_ALLOW_SYSTEM=1). Needs minisign, curl,
# tar, coreutils. For example, from the repository root on an LF copy:
#   docker run --rm -v "$PWD:/src:ro" debian:bookworm bash -c \
#     'apt-get update -qq && apt-get install -y -qq minisign curl >/dev/null \
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
for t in minisign curl tar sha256sum base64; do
    command -v "$t" >/dev/null 2>&1 || { echo "$t is required"; exit 2; }
done
if [ -e /opt/dockpanel ] || [ -e /var/lib/dockpanel ]; then
    if [ "${CYBERHUNTER_TEST_ALLOW_SYSTEM:-0}" != "1" ] && [ ! -f /.dockerenv ]; then
        echo "/opt/dockpanel or /var/lib/dockpanel exists - refusing"; exit 2
    fi
fi

T="$(mktemp -d)"
MINISIGN_BIN="$(command -v minisign)"
trap '[ -e "$MINISIGN_BIN.off" ] && mv "$MINISIGN_BIN.off" "$MINISIGN_BIN"; rm -rf "$T"' EXIT
STUB_LOG=/tmp/install-stub.log
CACHE=/var/lib/dockpanel/releases

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported arch"; exit 2 ;;
esac

# ── fixtures ─────────────────────────────────────────────────────────────
minisign -G -W -p "$T/k.pub" -s "$T/k.key" >/dev/null 2>&1 </dev/null || { echo "minisign -G failed"; exit 2; }
minisign -G -W -p "$T/k2.pub" -s "$T/k2.key" >/dev/null 2>&1 </dev/null || { echo "minisign -G failed"; exit 2; }
KEY="$(sed -n 2p "$T/k.pub")"
KEY2="$(sed -n 2p "$T/k2.pub")"

# The copy a release ships: the committed install.sh stamped with KEY.
STAMPED="$T/install-stamped.sh"
if bash "$REL" --stamp-install-only "$INSTALL" "$KEY" "$STAMPED" 2>"$T/stamp.err" \
   && [ "$(grep -cx "CYBERHUNTER_STAMPED_PUBKEY=\"$KEY\"" "$STAMPED")" = "1" ]; then
    ok "release.sh --stamp-install-only writes the key into install.sh"
else
    bad "stamping failed: $(cat "$T/stamp.err")"
fi
if [ "$(diff "$INSTALL" "$STAMPED" | grep -c '^[<>]')" = "2" ]; then
    ok "the stamped copy differs from the committed one by that line only"
else
    bad "the stamped copy differs by more than the key line"
fi
if grep -cx 'CYBERHUNTER_STAMPED_PUBKEY=""' "$INSTALL" >/dev/null; then
    ok "the committed install.sh carries the empty placeholder"
else
    bad "the committed install.sh has no empty CYBERHUNTER_STAMPED_PUBKEY=\"\" line"
fi
{ cat "$INSTALL"; echo 'CYBERHUNTER_STAMPED_PUBKEY=""'; } > "$T/two.sh"
if bash "$REL" --stamp-install-only "$T/two.sh" "$KEY" "$T/two.out" >/dev/null 2>&1; then
    bad "stamping accepted two placeholder lines"
else
    ok "stamping refuses two placeholder lines"
fi
sed 's/$/\r/' "$INSTALL" > "$T/crlf.sh"
if bash "$REL" --stamp-install-only "$T/crlf.sh" "$KEY" "$T/crlf.out" >/dev/null 2>&1; then
    bad "stamping accepted a CRLF install.sh"
else
    ok "stamping refuses a CRLF install.sh"
fi
if bash "$REL" --stamp-install-only "$INSTALL" "notakey" "$T/nk.out" >/dev/null 2>&1; then
    bad "stamping accepted a value that is not a minisign key"
else
    ok "stamping refuses a value that is not a minisign key"
fi

# make_release <dir> <tag> [trusted comment] [secret key]: a complete fake
# release in <dir>, checksums by release.sh, signed with the given key.
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
    local d="$1" tag="$2" tc="${3:-cyberhunter-release $2}" sk="${4:-$T/k.key}" b
    rm -rf "$d"; mkdir -p "$d"
    for b in agent api cli mcp; do
        printf '\177ELFfake-%s-%s\n' "$b" "$tag" > "$d/cyberhunter-$b-linux-$ARCH"
    done
    mkdir -p "$T/fe/dist"; echo "<html>" > "$T/fe/dist/index.html"
    tar -C "$T/fe" -czf "$d/cyberhunter-frontend.tar.gz" dist
    tar -C "$SRC_TREE" -czf "$d/cyberhunter-source.tar.gz" cyberhunter-source
    cp "$STAMPED" "$d/install.sh"
    bash "$REL" --checksums-only "$d"
    minisign -S -s "$sk" -m "$d/checksums.txt" -x "$d/checksums.txt.minisig" -t "$tc" >/dev/null 2>&1 </dev/null
}
resign() {  # resign <dir> <tag>
    rm -f "$1/checksums.txt.minisig"
    minisign -S -s "$T/k.key" -m "$1/checksums.txt" -x "$1/checksums.txt.minisig" -t "cyberhunter-release $2" >/dev/null 2>&1 </dev/null
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
run_install "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"; rc=$?
if [ "$rc" = "0" ] && [ -f "$STUB_LOG" ]; then
    ok "the stamped install.sh accepts a release signed with its key"
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
             checksums.txt checksums.txt.minisig cyberhunter-source/scripts/setup.sh; do
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
    grep -q "Signature verified (cyberhunter-release $TAG)" "$T/out" && ok "it says what it verified" || bad "no 'Signature verified' line"
else
    bad "a valid release was refused (rc $rc)"; sed 's/^/        /' "$T/out" | tail -8
fi

run_install "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R" CYBERHUNTER_PUBKEY="$KEY"; rc=$?
if [ "$rc" = "0" ] && [ -f "$STUB_LOG" ]; then
    ok "CYBERHUNTER_PUBKEY lets the unstamped copy verify with a given key"
else
    bad "CYBERHUNTER_PUBKEY override does not work (rc $rc)"; tail -4 "$T/out"
fi

run_install "$STAMPED" CYBERHUNTER_RELEASE_DIR="$R"; rc=$?
if [ "$rc" = "0" ] && grep -qx "CYBERHUNTER_RELEASE_DIR=$CACHE/$TAG" "$STUB_LOG" 2>/dev/null; then
    ok "CYBERHUNTER_RELEASE_DIR=<dir named after the tag>: same checks, installed from that directory"
else
    bad "the hand-downloaded release mode failed (rc $rc)"; tail -4 "$T/out"
fi

echo "── 2. refusals ──"
expect_refusal "unstamped install.sh" "has no release signing key" \
    "$INSTALL" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"

mv "$R/checksums.txt.minisig" "$T/sig.bak"
expect_refusal "missing signature" "refusing to install an unsigned release" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
mv "$T/sig.bak" "$R/checksums.txt.minisig"

expect_refusal "key override that is not the signer" "does not verify with the release signing key" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R" CYBERHUNTER_PUBKEY="$KEY2"

R2="$T/rel2/$TAG"
make_release "$R2" "$TAG" "cyberhunter-release $TAG" "$T/k2.key"
expect_refusal "signed by another key" "does not verify with the release signing key" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG" "cyberhunter-release v9.9.8"
expect_refusal "trusted comment for another tag" "The signature is for 'cyberhunter-release v9.9.8', not 'cyberhunter-release $TAG'" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG" "cyberhunter-release ${TAG} "
expect_refusal "trusted comment with a trailing space" "The signature is for" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
printf '%064d  cyberhunter-extra\n' 0 >> "$R2/checksums.txt"
expect_refusal "checksums.txt changed after signing" "does not verify with the release signing key" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
rm -f "$R2/checksums.txt.minisig"
if minisign -S -l -s "$T/k.key" -m "$R2/checksums.txt" -x "$R2/checksums.txt.minisig" -t "cyberhunter-release $TAG" >/dev/null 2>&1 </dev/null; then
    expect_refusal "legacy (not pre-hashed) signature" "not a pre-hashed minisign signature" \
        "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"
else
    echo "  (this minisign cannot write legacy signatures - case skipped)"
fi

make_release "$R2" "$TAG"
printf 'x' >> "$R2/cyberhunter-api-linux-$ARCH"
expect_refusal "bad sha256" "sha256 mismatch for cyberhunter-api-linux-$ARCH" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
rm -f "$R2/cyberhunter-frontend.tar.gz"
expect_refusal "missing asset" "cyberhunter-frontend.tar.gz is missing from release $TAG" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
grep -v "cyberhunter-mcp-linux-$ARCH" "$R2/checksums.txt" > "$T/s" && mv "$T/s" "$R2/checksums.txt"
resign "$R2" "$TAG"
expect_refusal "signed manifest without an asset" "has no entry for cyberhunter-mcp-linux-$ARCH" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
printf 'not a line\n' >> "$R2/checksums.txt"
resign "$R2" "$TAG"
expect_refusal "malformed signed manifest" "checksums.txt of $TAG is malformed" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

make_release "$R2" "$TAG"
mkdir -p "$T/evil/other"; echo x > "$T/evil/other/f"
tar -C "$SRC_TREE" -cf "$T/evil.tar" cyberhunter-source && tar -C "$T/evil" -rf "$T/evil.tar" other && gzip -c "$T/evil.tar" > "$R2/cyberhunter-source.tar.gz"
bash "$REL" --checksums-only "$R2"; resign "$R2" "$TAG"
expect_refusal "source archive escaping cyberhunter-source/" "holds files outside cyberhunter-source/" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R2"

expect_refusal "malformed tag" "is not vX.Y.Z or vX.Y.Z-rc.N" \
    "$STAMPED" DOCKPANEL_VERSION="v9.9" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
expect_refusal "tag with a path in it" "is not vX.Y.Z or vX.Y.Z-rc.N" \
    "$STAMPED" DOCKPANEL_VERSION="v9.9.9/../x" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
expect_refusal "base URL that is neither https nor file" "must start with https:// or file:///" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="http://example.invalid"

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
TEST_PATH="$FB:$PATH" run_install "$STAMPED" FAKE_LATEST="$GH/v9.9.9" CYBERHUNTER_RELEASE_BASE_URL="file://$RS"; rc=$?
if [ "$rc" = "0" ] && grep -qx "DOCKPANEL_VERSION=v9.9.9" "$STUB_LOG" 2>/dev/null; then
    ok "no DOCKPANEL_VERSION: the latest stable tag is resolved and installed"
else
    bad "latest stable resolution failed (rc $rc)"; tail -4 "$T/out"
fi
TEST_PATH="$FB:$PATH" expect_refusal "latest pointing at a pre-release" "is not a stable vX.Y.Z tag" \
    "$STAMPED" FAKE_LATEST="$GH/$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
TEST_PATH="$FB:$PATH" expect_refusal "latest not leading to a release" "did not lead to a release" \
    "$STAMPED" FAKE_LATEST="https://github.com/MrTheSkream/cyberhunter-releases/releases" CYBERHUNTER_RELEASE_BASE_URL="file://$R"

echo "── 4. no minisign, and none installable: stop ──"
mkdir -p "$T/noapt"
printf '#!/bin/sh\nexit 100\n' > "$T/noapt/apt-get"; chmod +x "$T/noapt/apt-get"
mv "$MINISIGN_BIN" "$MINISIGN_BIN.off"
TEST_PATH="$T/noapt:$PATH" expect_refusal "minisign missing" "minisign is required to verify the release signature" \
    "$STAMPED" DOCKPANEL_VERSION="$TAG" CYBERHUNTER_RELEASE_BASE_URL="file://$R"
mv "$MINISIGN_BIN.off" "$MINISIGN_BIN"

echo "── 5. clone mode is still there ──"
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
