#!/usr/bin/env bash
# Fetch and build a pinned static musl ET_EXEC BusyBox binary for Nilix (#66).
# BusyBox source and binaries live under target/conformance and are never committed.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")"
OUT_ROOT_ARG="${1:-$ROOT/target/conformance}"
mkdir -p "$OUT_ROOT_ARG"
OUT_ROOT="$(realpath "$OUT_ROOT_ARG")"
CONFIG_FRAG="$ROOT/scripts/conformance/busybox.config"
MAX_EXEC_BYTES="${BUSYBOX_MAX_EXEC_BYTES:-16777216}"

for tool in musl-gcc gcc make readelf stat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "BUSYBOX-BUILD ERROR: $tool not found in PATH" >&2
        exit 2
    fi
done

if [ ! -f "$CONFIG_FRAG" ]; then
    echo "BUSYBOX-BUILD ERROR: missing pinned config $CONFIG_FRAG" >&2
    exit 2
fi

SRC_DIR="$(bash "$ROOT/scripts/conformance/fetch.sh" busybox "$OUT_ROOT" | tail -n 1)"
BUILD_DIR="$OUT_ROOT/build/busybox"
BIN_OUT="$BUILD_DIR/busybox"
CONFIG_SHA="$(sha256sum "$CONFIG_FRAG" | awk '{print $1}')"
STAMP="$BUILD_DIR/.built-$CONFIG_SHA"

if [ -x "$BIN_OUT" ] && [ -f "$STAMP" ]; then
    echo "BUSYBOX-BUILD CACHED bin=$BIN_OUT size=$(stat -c '%s' "$BIN_OUT")"
    exit 0
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

make -C "$SRC_DIR" O="$BUILD_DIR" allnoconfig >/dev/null
# Strip comments/blank lines and apply pinned fragment deterministically.
while IFS= read -r line; do
    case "$line" in
        ""|\#*) continue ;;
    esac
    sym="${line%%=*}"
    # Remove any prior allnoconfig setting for this symbol before appending ours.
    sed -i "/^${sym}=/d; /^# ${sym} is not set\$/d" "$BUILD_DIR/.config"
    if [ "${line#*=}" = "n" ]; then
        printf '# %s is not set\n' "$sym" >> "$BUILD_DIR/.config"
    else
        printf '%s\n' "$line" >> "$BUILD_DIR/.config"
    fi
done < "$CONFIG_FRAG"

{ yes "" || true; } | make -C "$SRC_DIR" O="$BUILD_DIR" oldconfig >/dev/null
make -C "$SRC_DIR" O="$BUILD_DIR" -j"$(nproc)" \
    CC=musl-gcc \
    HOSTCC=gcc \
    EXTRA_CFLAGS="-fno-pie -Os" \
    EXTRA_LDFLAGS="-static -no-pie" >/dev/null

if ! readelf -h "$BIN_OUT" | grep -q 'Type:[[:space:]]*EXEC'; then
    echo "BUSYBOX-BUILD ERROR: $BIN_OUT is not ET_EXEC" >&2
    exit 1
fi

sz="$(stat -c '%s' "$BIN_OUT")"
if [ "$sz" -gt "$MAX_EXEC_BYTES" ]; then
    echo "BUSYBOX-BUILD ERROR: $BIN_OUT size $sz exceeds ceiling $MAX_EXEC_BYTES" >&2
    exit 1
fi

printf '%s\n' "$CONFIG_SHA" > "$STAMP"
echo "BUSYBOX-BUILD OK bin=$BIN_OUT size=$sz sha256=$(sha256sum "$BIN_OUT" | awk '{print $1}')"
