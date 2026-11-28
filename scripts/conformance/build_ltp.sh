#!/usr/bin/env bash
# Fetch and build static musl ET_EXEC LTP syscall tests for Nilix (N2.2, #66).
# Uses unmodified upstream LTP 20250130 sources verified by SHA-256 via fetch.sh.
# External sources and GPL binaries live under target/conformance and are never committed.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")"
OUT_ROOT_ARG="${1:-$ROOT/target/conformance}"
mkdir -p "$OUT_ROOT_ARG"
OUT_ROOT="$(realpath "$OUT_ROOT_ARG")"
MAX_EXEC_BYTES="${LTP_MAX_EXEC_BYTES:-16777216}"

for tool in musl-gcc make readelf strip stat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "CONFORMANCE-BUILD ERROR: $tool not found in PATH" >&2
        exit 2
    fi
done

SRC_DIR="$(bash "$ROOT/scripts/conformance/fetch.sh" ltp "$OUT_ROOT" | tail -n 1)"
BUILD_DIR="$OUT_ROOT/build/ltp"
BIN_DIR="$BUILD_DIR/bin"
UNBUILDABLE="$BUILD_DIR/ltp.unbuildable"
MANIFEST="$BUILD_DIR/manifest.txt"
UAPI_INC="$OUT_ROOT/uapi-inc"

# Expose ONLY Linux kernel UAPI headers (linux/, asm/, asm-generic/) to musl-gcc
# without leaking glibc user headers.
rm -rf "$UAPI_INC"
mkdir -p "$UAPI_INC"
for d in linux asm-generic; do
    if [ -d "/usr/include/$d" ]; then
        ln -s "/usr/include/$d" "$UAPI_INC/$d"
    fi
done
if [ -d /usr/include/x86_64-linux-gnu/asm ]; then
    ln -s /usr/include/x86_64-linux-gnu/asm "$UAPI_INC/asm"
elif [ -d /usr/include/asm ]; then
    ln -s /usr/include/asm "$UAPI_INC/asm"
fi

# Configure and build libltp.a once per fetched source tree.
LTP_STAMP="$SRC_DIR/.configured-musl"
if [ ! -f "$LTP_STAMP" ] || [ ! -f "$SRC_DIR/lib/libltp.a" ]; then
    (
        cd "$SRC_DIR"
        CC=musl-gcc \
        CFLAGS="-Os -fno-pie -w -idirafter $UAPI_INC" \
        LDFLAGS="-static -no-pie" \
        ./configure \
            --without-numa \
            --without-tirpc \
            --without-selinux \
            --without-keyutils \
            --without-libcap \
            --without-libacl \
            --without-libaio \
            --without-crypto >/dev/null
        make -C lib -j"$(nproc)" >/dev/null
    )
    date -u > "$LTP_STAMP"
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BIN_DIR"
: > "$UNBUILDABLE"
: > "$MANIFEST"

# Curated unmodified upstream LTP syscall test directories covering Nilix N2.0-N2.8
# (process/identity/job-control, signals, VFS/*at/links/mknod, MM, IPC/pipes,
# sockets/vectored-I/O, and system queries). All targets below use LTP's standalone
# old-API harness (no file-backed MAP_SHARED IPC prerequisite).
LTP_TARGETS=(
    "exit:exit01"
    "fchownat:fchownat01"
    "fchownat:fchownat02"
    "fcntl:fcntl01"
    "fdatasync:fdatasync01"
    "fdatasync:fdatasync02"
    "fstatat:fstatat01"
    "get_robust_list:get_robust_list01"
    "getresgid:getresgid01"
    "getresgid:getresgid02"
    "getresgid:getresgid03"
    "getresuid:getresuid01"
    "getresuid:getresuid02"
    "getresuid:getresuid03"
    "kill:kill02"
    "kill:kill08"
    "kill:kill09"
    "kill:kill12"
    "linkat:linkat01"
    "listen:listen01"
    "mkdirat:mkdirat01"
    "mknod:mknod03"
    "mknod:mknod04"
    "mknod:mknod05"
    "mknod:mknod06"
    "mknod:mknod07"
    "mknod:mknod08"
    "mknodat:mknodat01"
    "mknodat:mknodat02"
    "mmap:mmap001"
    "mprotect:mprotect01"
    "mprotect:mprotect02"
    "mprotect:mprotect03"
    "munmap:munmap01"
    "munmap:munmap02"
    "munmap:munmap03"
    "newuname:newuname01"
    "open:open12"
    "open:open13"
    "open:open14"
    "openat:openat03"
    "pause:pause02"
    "pause:pause03"
    "pipe:pipe04"
    "pipe:pipe05"
    "pipe:pipe09"
    "rename:rename14"
    "renameat:renameat01"
    "renameat2:renameat201"
    "rt_sigaction:rt_sigaction01"
    "rt_sigaction:rt_sigaction02"
    "rt_sigaction:rt_sigaction03"
    "rt_sigprocmask:rt_sigprocmask01"
    "rt_sigprocmask:rt_sigprocmask02"
    "sched_yield:sched_yield01"
    "send:send01"
    "sendto:sendto01"
    "sendmsg:sendmsg01"
    "set_robust_list:set_robust_list01"
    "setpgrp:setpgrp01"
    "setrlimit:setrlimit01"
    "setsid:setsid01"
    "sigaction:sigaction01"
    "sigaction:sigaction02"
    "sigaltstack:sigaltstack01"
    "sigprocmask:sigprocmask01"
    "string:string01"
    "symlink:symlink01"
    "symlink:symlink03"
    "symlinkat:symlinkat01"
    "sysconf:sysconf01"
    "sysinfo:sysinfo01"
    "sysinfo:sysinfo02"
    "writev:writev02"
    "writev:writev05"
    "writev:writev06"
)

built_count=0
skipped_count=0

# Build each unique syscall target individually to avoid failing on unrelated tests in a dir.
for spec in "${LTP_TARGETS[@]}"; do
    dir="${spec%%:*}"
    bin="${spec#*:}"
    tdir="$SRC_DIR/testcases/kernel/syscalls/$dir"
    if [ ! -d "$tdir" ]; then
        printf '%s\tmissing-dir\n' "$bin" >> "$UNBUILDABLE"
        skipped_count=$((skipped_count + 1))
        continue
    fi
    if ! make -C "$tdir" "$bin" >/dev/null 2>&1; then
        printf '%s\tcompile-fail\n' "$bin" >> "$UNBUILDABLE"
        skipped_count=$((skipped_count + 1))
        continue
    fi
    src_bin="$tdir/$bin"
    if [ ! -f "$src_bin" ]; then
        printf '%s\tmissing-binary\n' "$bin" >> "$UNBUILDABLE"
        skipped_count=$((skipped_count + 1))
        continue
    fi
    dst_bin="$BIN_DIR/$bin"
    cp "$src_bin" "$dst_bin"
    strip --strip-all "$dst_bin" 2>/dev/null || true
    if ! readelf -h "$dst_bin" | grep -q 'Type:[[:space:]]*EXEC'; then
        printf '%s\tnot-et-exec\n' "$bin" >> "$UNBUILDABLE"
        rm -f "$dst_bin"
        skipped_count=$((skipped_count + 1))
        continue
    fi
    sz="$(stat -c '%s' "$dst_bin")"
    if [ "$sz" -gt "$MAX_EXEC_BYTES" ]; then
        printf '%s\texceeds-max-exec-bytes (%s > %s)\n' "$bin" "$sz" "$MAX_EXEC_BYTES" >> "$UNBUILDABLE"
        rm -f "$dst_bin"
        skipped_count=$((skipped_count + 1))
        continue
    fi
    printf 'ltp %s /mnt/test/conformance/bin/%s\n' "$bin" "$bin" >> "$MANIFEST"
    built_count=$((built_count + 1))
done

LC_ALL=C sort -o "$MANIFEST" "$MANIFEST"
LC_ALL=C sort -o "$UNBUILDABLE" "$UNBUILDABLE"

echo "CONFORMANCE-BUILD suite=ltp built=$built_count skipped=$skipped_count max_bytes=$MAX_EXEC_BYTES"
echo "  manifest=$MANIFEST"
echo "  unbuildable=$UNBUILDABLE"
