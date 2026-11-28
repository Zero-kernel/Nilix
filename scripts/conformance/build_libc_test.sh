#!/usr/bin/env bash
# Build static musl ET_EXEC binaries for musl libc-test (N2.2, #66).
# Only tests that build statically and fit within Nilix's exec size ceiling
# are staged into the output directory; skipped cases are recorded explicitly.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")"
OUT_ROOT="${1:-$ROOT/target/conformance}"
MAX_EXEC_BYTES="${CONFORMANCE_MAX_EXEC_BYTES:-262144}"

if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "CONFORMANCE-BUILD ERROR: musl-gcc not found in PATH" >&2
    exit 2
fi

SRC_DIR="$(bash "$ROOT/scripts/conformance/fetch.sh" libc-test "$OUT_ROOT" | tail -n 1)"
BUILD_DIR="$OUT_ROOT/build/libc-test"
BIN_DIR="$BUILD_DIR/bin"
OBJ_DIR="$BUILD_DIR/obj"
UNBUILDABLE="$BUILD_DIR/libc-test.unbuildable"
MANIFEST="$BUILD_DIR/manifest.txt"

rm -rf "$BUILD_DIR"
mkdir -p "$BIN_DIR" "$OBJ_DIR"

COMMON_CFLAGS=(
    -std=c99
    -D_POSIX_C_SOURCE=200809L
    -D_GNU_SOURCE
    -Os
    -fno-pie
    -fno-builtin
    -frounding-math
    -I"$SRC_DIR/src/common"
    -w
)

# 1. Build libtest.a from src/common helper sources (excluding runtest.c).
COMMON_OBJS=()
for cfile in "$SRC_DIR"/src/common/*.c; do
    base="$(basename "$cfile" .c)"
    if [ "$base" = "runtest" ]; then
        continue
    fi
    obj="$OBJ_DIR/common_${base}.o"
    musl-gcc "${COMMON_CFLAGS[@]}" -c -o "$obj" "$cfile"
    COMMON_OBJS+=("$obj")
done
LIBTEST="$BUILD_DIR/libtest.a"
ar rc "$LIBTEST" "${COMMON_OBJS[@]}"
ranlib "$LIBTEST"

: > "$UNBUILDABLE"
: > "$MANIFEST"

built_count=0
skipped_count=0

# Helper: build one test binary from a source path and group name.
build_one() {
    local group="$1"
    local cfile="$2"
    local base
    base="$(basename "$cfile" .c)"
    local name="${group}_${base}"

    # Skip shared-library / dlopen helper sources and dynamic-only tests.
    case "$base" in
        *-helper|*_dso|dlopen*|tls_align_dso*|tls_init_dso*|tls_get_new*|tls_local_exec*)
            printf '%s\tdynamic-only\n' "$name" >> "$UNBUILDABLE"
            skipped_count=$((skipped_count + 1))
            return 0
            ;;
    esac

    # Skip files with a custom .mk requiring extra .so / multi-object linking.
    local mkfile="${cfile%.c}.mk"
    if [ -f "$mkfile" ] && grep -qE '\.so|\.lo|LOBJS' "$mkfile"; then
        printf '%s\trequires-shared-lib\n' "$name" >> "$UNBUILDABLE"
        skipped_count=$((skipped_count + 1))
        return 0
    fi

    local out="$BIN_DIR/$name"
    local errlog="$OBJ_DIR/${name}.err"
    if ! musl-gcc "${COMMON_CFLAGS[@]}" -static -no-pie -s \
        -o "$out" "$cfile" "$LIBTEST" -lm -lpthread -lrt 2>"$errlog"; then
        local reason
        reason="$(head -n 1 "$errlog" | tr '\t\r\n' '   ')"
        printf '%s\tcompile-fail: %s\n' "$name" "$reason" >> "$UNBUILDABLE"
        rm -f "$out"
        skipped_count=$((skipped_count + 1))
        return 0
    fi

    # Verify ET_EXEC (Nilix does not support ET_DYN yet) and current exec size ceiling.
    if ! readelf -h "$out" | grep -q 'Type:[[:space:]]*EXEC'; then
        printf '%s\tnot-et-exec\n' "$name" >> "$UNBUILDABLE"
        rm -f "$out"
        skipped_count=$((skipped_count + 1))
        return 0
    fi

    local sz
    sz="$(stat -c '%s' "$out")"
    if [ "$sz" -gt "$MAX_EXEC_BYTES" ]; then
        printf '%s\texceeds-max-exec-bytes (%s > %s)\n' "$name" "$sz" "$MAX_EXEC_BYTES" >> "$UNBUILDABLE"
        rm -f "$out"
        skipped_count=$((skipped_count + 1))
        return 0
    fi

    printf 'libc-test %s /mnt/test/conformance/bin/%s\n' "$name" "$name" >> "$MANIFEST"
    built_count=$((built_count + 1))
}

for group in functional regression; do
    mapfile -t cfiles < <(printf '%s\n' "$SRC_DIR/src/$group"/*.c | LC_ALL=C sort)
    for cfile in "${cfiles[@]}"; do
        build_one "$group" "$cfile"
    done
done

LC_ALL=C sort -o "$MANIFEST" "$MANIFEST"
LC_ALL=C sort -o "$UNBUILDABLE" "$UNBUILDABLE"

echo "CONFORMANCE-BUILD suite=libc-test built=$built_count skipped=$skipped_count max_bytes=$MAX_EXEC_BYTES"
echo "  manifest=$MANIFEST"
echo "  unbuildable=$UNBUILDABLE"
