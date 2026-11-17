#!/usr/bin/env bash
# CyberHunter - Panel - refuse a release binary that would not run on the
# oldest supported system (Ubuntu 22.04, glibc 2.35).
#
# Usage: check-glibc.sh <binary> [max=2.35]
#
# Meant to run INSIDE the release build image (binutils of Ubuntu 22.04), but
# usable on its own anywhere `readelf` exists.
#
#   - every GLIBC_2.N version the binary asks for (section .gnu.version_r, read
#     with `readelf --version-info --wide`) must be <= max, compared with
#     `sort -V`; GLIBC_PRIVATE is refused outright;
#   - every NEEDED entry (`readelf -d`) must be one of the base system
#     libraries listed in ALLOWED_NEEDED below;
#   - a file that is not ELF is refused.
#
# On success prints one line:
#   OK: <binary> max GLIBC_<v> (limit <max>)
# (`max GLIBC_none` for a binary that asks for no glibc version at all).
# scripts/release.sh reads that line for its summary.
#
# READELF may name another readelf (a cross binutils, or a fake one in tests).
set -euo pipefail

BIN="${1:-}"
MAX="${2:-2.35}"
READELF="${READELF:-readelf}"

ALLOWED_NEEDED="libc.so.6 libm.so.6 libgcc_s.so.1 libpthread.so.0 libdl.so.2 librt.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1"

if [ -z "$BIN" ]; then
    echo "usage: check-glibc.sh <binary> [max=2.35]" >&2
    exit 2
fi
if [ ! -f "$BIN" ]; then
    echo "ERROR: $BIN does not exist" >&2
    exit 1
fi
case "$MAX" in
    2.[0-9]|2.[0-9][0-9]) ;;
    *) echo "ERROR: max must look like 2.N, got '$MAX'" >&2; exit 2 ;;
esac

MAGIC="$(head -c 4 "$BIN" | od -An -tx1 | tr -d ' \n')"
if [ "$MAGIC" != "7f454c46" ]; then
    echo "ERROR: $BIN is not an ELF file" >&2
    exit 1
fi

# Capture readelf's output first and check ITS status on its own: a failed
# readelf at the head of a pipeline would otherwise look like "no versions
# required", which is the reassuring answer.
if ! VERSION_INFO="$("$READELF" --version-info --wide "$BIN" 2>&1)"; then
    echo "ERROR: readelf --version-info failed on $BIN" >&2
    exit 1
fi
if ! DYNAMIC="$("$READELF" -d "$BIN" 2>&1)"; then
    echo "ERROR: readelf -d failed on $BIN" >&2
    exit 1
fi

# Only the "Version needs" section: the .gnu.version section repeats the same
# names per symbol, and .gnu.version_d is what the binary DEFINES.
REQUIRED="$(printf '%s\n' "$VERSION_INFO" | awk '
    /^Version needs section/ { inside = 1; next }
    /^Version (symbols|definition) section/ { inside = 0 }
    inside && /Name: GLIBC_/ {
        for (i = 1; i <= NF; i++) if ($i == "Name:") print $(i + 1)
    }' | sort -u)"

if printf '%s\n' "$REQUIRED" | grep -qx 'GLIBC_PRIVATE'; then
    echo "ERROR: $BIN requires GLIBC_PRIVATE" >&2
    exit 1
fi

HIGHEST="$(printf '%s\n' "$REQUIRED" | sed -n 's/^GLIBC_\([0-9][0-9.]*\)$/\1/p' | sort -V | tail -n 1)"
if [ -n "$HIGHEST" ]; then
    TOP="$(printf '%s\n%s\n' "$MAX" "$HIGHEST" | sort -V | tail -n 1)"
    if [ "$TOP" != "$MAX" ]; then
        echo "ERROR: $BIN requires GLIBC_$HIGHEST (max $MAX)" >&2
        exit 1
    fi
fi

NEEDED="$(printf '%s\n' "$DYNAMIC" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p')"
for lib in $NEEDED; do
    case " $ALLOWED_NEEDED " in
        *" $lib "*) ;;
        *) echo "ERROR: $BIN needs $lib" >&2; exit 1 ;;
    esac
done

echo "OK: $BIN max GLIBC_${HIGHEST:-none} (limit $MAX)"
