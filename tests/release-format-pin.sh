#!/usr/bin/env bash
# Pins for the release format (conception/10-mises-a-jour-contrats.md, 2.1,
# 2.2, B-5, B-5bis):
#
#   - scripts/release.sh names exactly the release files servers ask for, signs
#     with the trusted comment that binds the signature to the tag, and builds
#     its archives with core.autocrlf=false;
#   - its checksum step, run for real on dummy files, produces the exact
#     checksums.txt format both readers (backend and agent) accept;
#   - the release build image starts from a digest-pinned ubuntu:22.04 and an
#     exact Rust toolchain, and release.sh never falls back to a newer-glibc
#     image;
#   - check-glibc.sh refuses a binary asking for GLIBC_2.36 or linking
#     libssl.so.3, and accepts GLIBC_2.34 (fake readelf output, no compiler).
#
# Static, needs only bash and coreutils. Run from anywhere:
#   bash tests/release-format-pin.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REL="$ROOT/scripts/release.sh"
DOCKERFILE="$ROOT/scripts/release-build/Dockerfile"
CHECK="$ROOT/scripts/release-build/check-glibc.sh"
BUILD="$ROOT/scripts/release-build/build-in-container.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

# Executable lines only (a pin satisfied by a comment is not a pin).
code_of() { tr -d '\r' < "$1" | grep -v '^[[:space:]]*#'; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "── 1. release.sh names exactly the release files ──"
REL_CODE="$(code_of "$REL")"
for name in cyberhunter-agent-linux-amd64 cyberhunter-api-linux-amd64 cyberhunter-cli-linux-amd64 \
            cyberhunter-mcp-linux-amd64 cyberhunter-agent-linux-arm64 cyberhunter-api-linux-arm64 \
            cyberhunter-cli-linux-arm64 cyberhunter-mcp-linux-arm64 cyberhunter-frontend.tar.gz \
            cyberhunter-source.tar.gz checksums.txt checksums.txt.minisig; do
    if printf '%s\n' "$REL_CODE" | grep -cF "$name" >/dev/null; then ok "names $name"; else bad "does not name $name"; fi
done
if printf '%s\n' "$REL_CODE" | grep -cE 'dockpanel-[a-z]+-linux-|SHA256SUMS|spdx' >/dev/null; then
    bad "still produces an old asset name (dockpanel-*-linux-*, SHA256SUMS or an SBOM)"
else
    ok "no old asset names, no SBOM"
fi

echo "── 2. signature, trusted comment, archives ──"
if printf '%s\n' "$REL_CODE" | grep -c 'TRUSTED="cyberhunter-release ${TAG}"' >/dev/null \
   && printf '%s\n' "$REL_CODE" | grep -c 'minisign -S .* -t "\$TRUSTED"' >/dev/null; then
    ok "signs with trusted comment 'cyberhunter-release <tag>'"
else
    bad "the signature is not made with the trusted comment cyberhunter-release <tag>"
fi
if printf '%s\n' "$REL_CODE" | grep -c 'minisign -V ' >/dev/null; then ok "verifies its own signature"; else bad "never runs minisign -V"; fi
if printf '%s\n' "$REL_CODE" | grep -c '\[ "\$SIG_ALG" = "ED" \]' >/dev/null; then
    ok "refuses a legacy (non pre-hashed) signature"
else
    bad "does not check that the signature is pre-hashed (ED)"
fi
if printf '%s\n' "$REL_CODE" | grep -c 'git -c core.autocrlf=false archive --format=tar.gz --prefix=cyberhunter-source/ HEAD -- scripts panel' >/dev/null; then
    ok "source archive is the contract's git archive command"
else
    bad "cyberhunter-source.tar.gz is not built with the contract's git archive command"
fi
N_ARCHIVE="$(printf '%s\n' "$REL_CODE" | grep -c 'git .*archive' || true)"
N_SAFE="$(printf '%s\n' "$REL_CODE" | grep -c 'git -c core.autocrlf=false archive' || true)"
if [ "$N_ARCHIVE" -ge 1 ] && [ "$N_ARCHIVE" = "$N_SAFE" ]; then
    ok "every git archive ($N_ARCHIVE) uses core.autocrlf=false"
else
    bad "$((N_ARCHIVE - N_SAFE)) git archive call(s) without core.autocrlf=false"
fi
if printf '%s\n' "$REL_CODE" | grep -c 'Publish ${TAG}? \[y/N\]' >/dev/null; then ok "asks 'Publish <tag>? [y/N]'"; else bad "no publish confirmation"; fi
DRY_AT="$(printf '%s\n' "$REL_CODE" | grep -n 'Dry run: nothing tagged' | head -1 | cut -d: -f1)"
TAG_AT="$(printf '%s\n' "$REL_CODE" | grep -n 'git tag -a ' | head -1 | cut -d: -f1)"
GH_AT="$(printf '%s\n' "$REL_CODE" | grep -n 'gh release create ' | head -1 | cut -d: -f1)"
if [ -n "$DRY_AT" ] && [ -n "$TAG_AT" ] && [ -n "$GH_AT" ] && [ "$DRY_AT" -lt "$TAG_AT" ] && [ "$TAG_AT" -lt "$GH_AT" ]; then
    ok "--dry-run stops before tagging, tag before gh release create"
else
    bad "--dry-run does not stop before tagging and publishing"
fi
if printf '%s\n' "$REL_CODE" | grep -c 'gh release create "\$TAG" --repo "\$REPO" --verify-tag' >/dev/null; then
    ok "gh release create uses --verify-tag"
else
    bad "gh release create without --verify-tag"
fi

echo "── 2b. signing step: Git Bash hands the command to PowerShell ──"
# sign_native and ps_quote are extracted from release.sh and run against a
# fake minisign that only logs its arguments.
SFUNCS="$(tr -d '\r' < "$REL" | awk '/^(ps_quote|sign_native)\(\) \{/ {on=1} on {print} on && /\}$/ && (/^\}/ || /^ps_quote/) {on=0}')"
if printf '%s\n' "$SFUNCS" | grep -c '^sign_native() {' >/dev/null \
   && printf '%s\n' "$SFUNCS" | grep -c '^ps_quote() {' >/dev/null; then
    ok "sign_native and ps_quote were extracted from release.sh"
    FB="$TMP/fakebin"; mkdir -p "$FB"
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "$FAKE_MS_LOG"\n' > "$FB/minisign"
    chmod +x "$FB/minisign"
    run_sign() {  # run_sign <IS_MSYS> <CYBERHUNTER_SIGN_INLINE>: output, log in $TMP/ms.log
        : > "$TMP/ms.log"; : > "$TMP/sig"; printf 'sig\n' > "$TMP/sig"
        printf '\n' | PATH="$FB:$PATH" FAKE_MS_LOG="$TMP/ms.log" CYBERHUNTER_SIGN_INLINE="$2" bash -c '
            set -euo pipefail
            die() { echo "ERROR: $*" >&2; exit 1; }
            eval "$1"
            IS_MSYS="$2"; TRUSTED="cyberhunter-release v9.9.9"; SIG_FILE="$3"
            M_KEY="C:\\Users\\O'"'"'Brien\\.minisign\\k.key"; M_PUB="C:\\k.pub"
            M_SUMS="F:\\r\\dist\\release-9.9.9\\checksums.txt"; M_SIG="F:\\r\\dist\\release-9.9.9\\checksums.txt.minisig"
            sign_native' _ "$SFUNCS" "$1" "$TMP/sig" 2>&1
    }
    out="$(run_sign 1 "")"; rc=$?
    want="minisign -S -s 'C:\\Users\\O''Brien\\.minisign\\k.key' -m 'F:\\r\\dist\\release-9.9.9\\checksums.txt' -x 'F:\\r\\dist\\release-9.9.9\\checksums.txt.minisig' -t 'cyberhunter-release v9.9.9'"
    if [ "$rc" = "0" ] && printf '%s\n' "$out" | grep -cF "    $want" >/dev/null; then
        ok "MSYS: prints the single-quoted PowerShell signing command"
    else
        bad "MSYS: the PowerShell signing command is missing or wrong (rc $rc): $out"
    fi
    if grep -q '^-S ' "$TMP/ms.log"; then bad "MSYS: minisign -S was still run inline"; else ok "MSYS: minisign -S is not run inline"; fi
    if grep -q '^-V -p C:\\k.pub ' "$TMP/ms.log"; then ok "MSYS: the signature is still verified (minisign -V)"; else bad "MSYS: no minisign -V after the handoff"; fi
    out="$(run_sign 1 1)"; rc=$?
    if [ "$rc" = "0" ] && grep -q '^-S -s ' "$TMP/ms.log" && ! printf '%s' "$out" | grep -q 'PowerShell'; then
        ok "MSYS + CYBERHUNTER_SIGN_INLINE=1: minisign -S runs inline"
    else
        bad "CYBERHUNTER_SIGN_INLINE=1 does not force inline signing (rc $rc)"
    fi
    out="$(run_sign 0 "")"; rc=$?
    if [ "$rc" = "0" ] && grep -q '^-S -s .* -t cyberhunter-release v9.9.9$' "$TMP/ms.log" && grep -q '^-V ' "$TMP/ms.log"; then
        ok "Linux/macOS: minisign -S then -V run inline"
    else
        bad "Linux/macOS: inline signing broken (rc $rc): $out"
    fi
else
    bad "could not extract sign_native/ps_quote from release.sh - section 2b is measuring nothing"
fi

echo "── 3. build image: ubuntu 22.04 by digest, exact toolchain ──"
RUST_BOOKWORM="rust:1-""bookworm"
if grep -qF "$RUST_BOOKWORM" "$REL"; then
    bad "release.sh cites $RUST_BOOKWORM (glibc 2.36) - release binaries must be built on 22.04"
else
    ok "release.sh does not cite $RUST_BOOKWORM"
fi
if code_of "$DOCKERFILE" | grep -cE '^FROM ubuntu:22\.04@sha256:[0-9a-f]{64}$' >/dev/null; then
    ok "Dockerfile starts FROM ubuntu:22.04@sha256:<digest>"
else
    bad "Dockerfile is not FROM ubuntu:22.04@sha256:<64 hex>"
fi
if [ "$(code_of "$DOCKERFILE" | grep -c '^FROM ')" = "1" ]; then ok "single FROM"; else bad "more than one FROM"; fi
if code_of "$DOCKERFILE" | grep -cE '^ARG RUST_TOOLCHAIN=[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null \
   && code_of "$DOCKERFILE" | grep -c -- '--default-toolchain "\${RUST_TOOLCHAIN}"' >/dev/null; then
    ok "toolchain pinned to an exact x.y.z"
else
    bad "the Rust toolchain is not pinned to an exact x.y.z"
fi
if code_of "$DOCKERFILE" | grep -cE '^LABEL org\.cyberhunter\.release-build="[0-9]+"$' >/dev/null; then
    ok "image carries a versioned org.cyberhunter.release-build label"
else
    bad "no org.cyberhunter.release-build label"
fi
for f in "$DOCKERFILE" "$CHECK" "$BUILD" "$REL"; do
    if grep -q $'\r' "$f"; then bad "$(basename "$f") has CRLF line endings"; else ok "$(basename "$f") is LF"; fi
done

echo "── 4. checksum step on dummy files ──"
D="$TMP/dist"
mkdir -p "$D"
for n in cyberhunter-mcp-linux-amd64 cyberhunter-agent-linux-amd64 cyberhunter-source.tar.gz \
         cyberhunter-api-linux-amd64 cyberhunter-frontend.tar.gz cyberhunter-cli-linux-amd64; do
    printf 'dummy %s\n' "$n" > "$D/$n"
done
if bash "$REL" --checksums-only "$D" && [ -f "$D/checksums.txt" ]; then
    ok "release.sh --checksums-only wrote checksums.txt"
    SUMS="$D/checksums.txt"
    if grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$' "$SUMS"; then
        bad "a line does not match ^[0-9a-f]{64}  name\$"
    else
        ok "every line is <64 lowercase hex><two spaces><name>"
    fi
    if grep -q $'\r' "$SUMS"; then bad "checksums.txt contains CR"; else ok "LF only"; fi
    if [ "$(head -c 3 "$SUMS" | od -An -tx1 | tr -d ' \n')" = "efbbbf" ]; then bad "UTF-8 BOM"; else ok "no BOM"; fi
    if [ "$(wc -l < "$SUMS" | tr -d ' ')" = "6" ]; then ok "one line per file (6)"; else bad "expected 6 lines"; fi
    if grep -q 'checksums.txt' "$SUMS"; then bad "lists itself"; else ok "does not list checksums.txt"; fi
    if awk '{print $2}' "$SUMS" | LC_ALL=C sort -c 2>/dev/null; then ok "sorted by name (C order)"; else bad "not sorted by name"; fi
    if [ "$(tail -c 1 "$SUMS" | od -An -tx1 | tr -d ' \n')" = "0a" ]; then ok "ends with LF"; else bad "no final LF"; fi
    want="$(cd "$D" && sha256sum cyberhunter-agent-linux-amd64 | awk '{print $1}')"
    if grep -qx "$want  cyberhunter-agent-linux-amd64" "$SUMS"; then ok "hash matches the file"; else bad "hash does not match"; fi
else
    bad "release.sh --checksums-only failed"
fi

echo "── 5. check-glibc.sh against fake readelf output ──"
FAKE="$TMP/fake-readelf"
cat > "$FAKE" <<'SH'
#!/usr/bin/env bash
# Fake readelf: prints canned output selected by FAKE_GLIBC and FAKE_NEEDED.
case "$1" in
  --version-info)
    cat <<EOF
Version symbols section '.gnu.version' contains 3 entries:
 Addr: 0x0000000000000000  Offset: 0x000400  Link: 5 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.2.5)   3 (${FAKE_GLIBC})

Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0x0000000000000000  Offset: 0x000500  Link: 6 (.dynstr)
  000000: Version: 1  File: libgcc_s.so.1  Cnt: 1
  0x0010:   Name: GCC_3.0  Flags: none  Version: 4
  0x0020: Version: 1  File: libc.so.6  Cnt: 2
  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 2
  0x0040:   Name: ${FAKE_GLIBC}  Flags: none  Version: 3
EOF
    ;;
  -d)
    cat <<EOF

Dynamic section at offset 0x1000 contains 3 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [${FAKE_NEEDED}]
EOF
    ;;
  *) exit 1 ;;
esac
SH
chmod +x "$FAKE"
ELF="$TMP/fake.elf"
printf '\177ELF\002\001\001\000fake' > "$ELF"

run_check() { FAKE_GLIBC="$1" FAKE_NEEDED="$2" READELF="$FAKE" bash "$CHECK" "$ELF" 2>&1; }

out="$(run_check GLIBC_2.34 libm.so.6)"; rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -c 'max GLIBC_2.34 (limit 2.35)' >/dev/null; then
    ok "accepts GLIBC_2.34 and reports it"
else
    bad "refused GLIBC_2.34 (rc $rc): $out"
fi
out="$(run_check GLIBC_2.35 libm.so.6)"; rc=$?
if [ "$rc" = "0" ]; then ok "accepts GLIBC_2.35 (the ceiling)"; else bad "refused GLIBC_2.35: $out"; fi
out="$(run_check GLIBC_2.36 libm.so.6)"; rc=$?
if [ "$rc" = "1" ] && printf '%s' "$out" | grep -cF "ERROR: $ELF requires GLIBC_2.36 (max 2.35)" >/dev/null; then
    ok "refuses GLIBC_2.36 with the contract message"
else
    bad "did not refuse GLIBC_2.36 correctly (rc $rc): $out"
fi
out="$(run_check GLIBC_2.4 libm.so.6)"; rc=$?
if [ "$rc" = "0" ]; then ok "compares numerically (2.4 < 2.35)"; else bad "2.4 judged newer than 2.35: $out"; fi
out="$(run_check GLIBC_PRIVATE libm.so.6)"; rc=$?
if [ "$rc" = "1" ]; then ok "refuses GLIBC_PRIVATE"; else bad "accepted GLIBC_PRIVATE"; fi
out="$(run_check GLIBC_2.34 libssl.so.3)"; rc=$?
if [ "$rc" = "1" ] && printf '%s' "$out" | grep -cF "ERROR: $ELF needs libssl.so.3" >/dev/null; then
    ok "refuses NEEDED libssl.so.3 with the contract message"
else
    bad "did not refuse libssl.so.3 correctly (rc $rc): $out"
fi
printf 'not an elf\n' > "$TMP/plain"
out="$(FAKE_GLIBC=GLIBC_2.34 FAKE_NEEDED=libm.so.6 READELF="$FAKE" bash "$CHECK" "$TMP/plain" 2>&1)"; rc=$?
if [ "$rc" = "1" ]; then ok "refuses a non-ELF file"; else bad "accepted a non-ELF file (rc $rc)"; fi
out="$(FAKE_GLIBC=GLIBC_2.34 FAKE_NEEDED=libm.so.6 READELF=/nonexistent/readelf bash "$CHECK" "$ELF" 2>&1)"; rc=$?
if [ "$rc" = "1" ]; then ok "a failing readelf is a refusal, not a pass"; else bad "a missing readelf passed (rc $rc)"; fi

echo "── 6. syntax ──"
for f in "$REL" "$CHECK" "$BUILD"; do
    if bash -n "$f"; then ok "bash -n $(basename "$f")"; else bad "bash -n $(basename "$f")"; fi
done
if command -v shellcheck >/dev/null 2>&1; then
    for f in "$REL" "$CHECK" "$BUILD"; do
        if shellcheck -S error "$f"; then ok "shellcheck $(basename "$f")"; else bad "shellcheck $(basename "$f")"; fi
    done
else
    echo "  (shellcheck not installed, skipped)"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
