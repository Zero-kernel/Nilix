#!/bin/bash
# Runtime suite gate. Exit 0=complete, 1=failed, 2=incomplete, 3=qualified.
# ZERO_OS_STRICT_TESTS=1 rejects warnings, deferrals and skips.
# KERNEL_TEST_DISK requires the production JBD2 write probe.
# KERNEL_TEST_KEEP_LOGS=1 retains serial, process diagnostics and JSON counts.
set -u

# Resolve the repo root from this script's own location so it runs from any
# working directory (CI, the remote build host, a fresh clone) without a `cd`.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"

QEMU=qemu-system-x86_64
# ESP defaults to <repo>/esp; a relative override is resolved against the repo root
# (so `bash scripts/boot_check.sh esp` works the same from anywhere), absolute kept.
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TO="${KERNEL_TEST_TIMEOUT:-45}"
if [[ ! "$TO" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ ]]; then
    echo "KERNEL-TEST BLOCKED: KERNEL_TEST_TIMEOUT must be an integer from 1 to 120"
    exit 2
fi
for tool in "$QEMU" timeout python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "KERNEL-TEST BLOCKED: $tool not found in PATH"
        exit 2
    fi
done

# OVMF firmware autodetect (mirrors the Makefile OVMF_PATH logic).
if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    echo "KERNEL-TEST FAIL: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "KERNEL-TEST FAIL: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

ser="$(mktemp)" || exit 2
intlog="$(mktemp)" || exit 2
qemuerr="$(mktemp)" || exit 2
timeoutlog="$(mktemp)" || exit 2
cleanup() {
    if [ "${KERNEL_TEST_KEEP_LOGS:-0}" = 1 ]; then
        echo "KERNEL-TEST ARTIFACTS: serial=$ser intlog=$intlog qemuerr=$qemuerr timeoutlog=$timeoutlog counts=$ser.counts.json gate_status=$ser.gate.status"
    else
        rm -rf -- "$ser.inputs"
        rm -f "$ser" "$intlog" "$qemuerr" "$timeoutlog" "$ser.counts.json" "$ser.gate.status"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

disk_args=()
if [[ -n "${KERNEL_TEST_DISK:-}" ]]; then
    logical_block_size="${KERNEL_TEST_BLOCK_SIZE:-512}"
    if [[ "$logical_block_size" != 512 && "$logical_block_size" != 4096 ]]; then
        echo "KERNEL-TEST BLOCKED: KERNEL_TEST_BLOCK_SIZE must be 512 or 4096"
        exit 2
    fi
    case "$KERNEL_TEST_DISK" in /*) ;; *) KERNEL_TEST_DISK="$ROOT/$KERNEL_TEST_DISK" ;; esac
    if [[ ! -f "$KERNEL_TEST_DISK" ]]; then
        echo "KERNEL-TEST BLOCKED: journaled test disk not found: $KERNEL_TEST_DISK"
        exit 2
    fi
    disk_args=(-drive "if=none,file=$KERNEL_TEST_DISK,format=raw,id=vdisk0,cache=writeback,discard=unmap"
               -device "virtio-blk-pci,drive=vdisk0,logical_block_size=$logical_block_size,physical_block_size=$logical_block_size")
fi

python3 "$ROOT/scripts/gate_inputs.py" prepare --source "$ESP" --output "$ser.inputs" \
    --firmware "$OVMF" --qemu "$(command -v "$QEMU")" || exit 2
"$QEMU" --version > "$ser.inputs/qemu.version" 2>&1 || exit 2

LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$TO" \
    bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:"$ser.inputs/esp",snapshot=on \
    "${disk_args[@]}" \
    -netdev user,id=net0,restrict=on,ipv6=off \
    -device virtio-net-pci,netdev=net0,romfile= \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"
qemu_status=$?

python3 "$ROOT/scripts/gate_log.py" --serial "$ser" --intlog "$intlog" \
    --qemu-stderr "$qemuerr" --timeout-stderr "$timeoutlog" --qemu-status "$qemu_status" --json-output "$ser.counts.json"
rc=$?
python3 "$ROOT/scripts/gate_inputs.py" verify --output "$ser.inputs" || rc=1
if [[ -n "${KERNEL_TEST_DISK:-}" ]] && ! grep -Fq 'R180-6 production JBD2 write path passed' "$ser"; then
    echo "KERNEL-TEST FAIL: missing production JBD2 write probe"
    rc=1
fi
if [[ -n "${KERNEL_TEST_DISK:-}" ]] && ! grep -Eq "^KSA-019-BLOCK PASS sector_bytes=$logical_block_size sector=[0-9]+ capacity_sectors=[0-9]+ restored=exact$" "$ser"; then
    echo "KERNEL-TEST FAIL: missing actual logical-sector round-trip/restoration evidence"
    rc=1
fi
if [ "$rc" -ne 0 ]; then
    echo "KERNEL-TEST NOT-PASSED: gate status=$rc (1=failure, 2=incomplete, 3=qualified)"
    echo "--- serial tail ---"
    tail -25 "$ser" 2>/dev/null | sed 's/^/    /'
    echo "--- timeout / QEMU stderr ---"
    tail -20 "$timeoutlog" "$qemuerr" 2>/dev/null | sed 's/^/    /'
fi

if [ "$rc" -eq 0 ]; then
    echo "KERNEL-TEST OK: runtime summary + PID 1 completion, no fatal markers or qualifications"
fi
printf '%s\n' "$rc" > "$ser.gate.status"
exit "$rc"
