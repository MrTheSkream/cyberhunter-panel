#!/usr/bin/env bash
# CyberHunter - Panel - compile release binaries INSIDE the release build image
# (scripts/release-build/Dockerfile, Ubuntu 22.04, glibc 2.35).
#
# Usage (from scripts/release.sh, source tree on stdin):
#   git -c core.autocrlf=false archive --format=tar HEAD | \
#     docker run --rm -i \
#       -e CYBERHUNTER_UPDATE_PUBKEY=<base64 key line> \
#       -v dp-cargo-registry:/usr/local/cargo/registry \
#       -v <target volume>:/target \
#       -v <output dir>:/out \
#       cyberhunter-release-build:<n> build-in-container.sh [--arm64] [crate...]
#
#   crate: agent backend cli mcp (default: all four). Each crate has its own
#   target directory under /target, so a persistent volume lets an interrupted
#   build resume where it stopped, one crate per run if need be.
#
# The source comes from `git archive` on stdin, never from a Windows bind
# mount: no CRLF conversion, no path conversion, exactly the committed tree.
#
# Writes /out/cyberhunter-<role>-linux-<arch> (role: agent api cli mcp) and
# runs check-glibc.sh on each; the first refusal stops the build.
set -euo pipefail

ARM64=0
CRATES=()
for a in "$@"; do
    case "$a" in
        --arm64) ARM64=1 ;;
        agent|backend|cli|mcp) CRATES+=("$a") ;;
        *) echo "build-in-container.sh: unknown argument '$a'" >&2; exit 2 ;;
    esac
done
[ ${#CRATES[@]} -eq 0 ] && CRATES=(agent backend cli mcp)

if [ -t 0 ]; then
    echo "build-in-container.sh: the source tree must be piped on stdin (git archive --format=tar)" >&2
    exit 2
fi

SRC=/build/src
rm -rf "$SRC"
mkdir -p "$SRC" /out
tar -C "$SRC" -xf -
[ -f "$SRC/panel/agent/Cargo.toml" ] || { echo "stdin did not contain the repository tree" >&2; exit 2; }

if [ -z "${CYBERHUNTER_UPDATE_PUBKEY:-}" ]; then
    echo "WARNING: CYBERHUNTER_UPDATE_PUBKEY is empty - these binaries will have updates disabled" >&2
fi

TARGETS=(x86_64-unknown-linux-gnu)
[ "$ARM64" = "1" ] && TARGETS+=(aarch64-unknown-linux-gnu)

rustc --version >&2

for crate in "${CRATES[@]}"; do
    case "$crate" in
        agent)   bin=dockpanel-agent; role=agent ;;
        backend) bin=dockpanel-api;   role=api ;;
        cli)     bin=dockpanel;       role=cli ;;
        mcp)     bin=dockpanel-mcp;   role=mcp ;;
    esac
    for triple in "${TARGETS[@]}"; do
        case "$triple" in
            x86_64-*)  arch=amd64 ;;
            aarch64-*) arch=arm64 ;;
        esac
        echo "=== release build: panel/$crate ($triple)" >&2
        export CARGO_TARGET_DIR="/target/$crate"
        (cd "$SRC/panel/$crate" && cargo build --release --locked --target "$triple")
        out="/out/cyberhunter-${role}-linux-${arch}"
        cp "$CARGO_TARGET_DIR/$triple/release/$bin" "$out"
        chmod 0755 "$out"
        check-glibc.sh "$out" 2.35
    done
done
echo "=== release build OK: ${CRATES[*]}" >&2
