#!/bin/bash
# Q35 positive gate: actual IOMMU activation plus complete, failure-free boot.
# Exit 0=strict pass, 1=failure, 2=incomplete/blocked, 3=qualified (not strict).
# IOMMU_Q35_TIMEOUT: 1..120 seconds (default 60).
# IOMMU_Q35_LOG_DIR: parent for unique retained evidence directories.
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
QEMU=qemu-system-x86_64
TO="${IOMMU_Q35_TIMEOUT:-60}"
if [[ ! "$TO" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ ]]; then
    echo "IOMMU-Q35-CHECK BLOCKED: IOMMU_Q35_TIMEOUT must be an integer from 1 to 120"
    exit 2
fi
for tool in "$QEMU" timeout python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "IOMMU-Q35-CHECK BLOCKED: $tool not found in PATH"
        exit 2
    fi
done

if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    echo "IOMMU-Q35-CHECK BLOCKED: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi
if [ ! -f "$ESP/kernel.elf" ]; then
    echo "IOMMU-Q35-CHECK BLOCKED: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

log_parent="${IOMMU_Q35_LOG_DIR:-${TMPDIR:-/tmp}}"
mkdir -p -- "$log_parent" || exit 2
log_parent="$(realpath "$log_parent")" || exit 2
log_dir="$(mktemp -d "$log_parent/iommu-q35.XXXXXX")" || exit 2
ser="$log_dir/serial.log"
intlog="$log_dir/interrupts.log"
qemuerr="$log_dir/qemu.stderr"
timeoutlog="$log_dir/timeout.stderr"
printf 'IOMMU-Q35-CHECK ARTIFACTS: %s\n' "$log_dir"
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

python3 "$ROOT/scripts/gate_inputs.py" prepare --source "$ESP" --output "$ser.inputs" \
    --firmware "$OVMF" --qemu "$(command -v "$QEMU")" || exit 2
"$QEMU" --version > "$ser.inputs/qemu.version" 2>&1 || exit 2

LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$TO" \
    bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
    -machine q35 \
    -device intel-iommu,intremap=on \
    -drive format=raw,file=fat:"$ser.inputs/esp",snapshot=on \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"
qemu_status=$?
printf '%s\n' "$qemu_status" >"$log_dir/qemu.status" || exit 2

python3 "$ROOT/scripts/gate_log.py" --serial "$ser" --intlog "$intlog" \
    --qemu-stderr "$qemuerr" --timeout-stderr "$timeoutlog" --qemu-status "$qemu_status" --json-output "$ser.counts.json" \
    --require-iommu >"$log_dir/gate.result"
rc=$?
python3 "$ROOT/scripts/gate_inputs.py" verify --output "$ser.inputs" || rc=1
printf '%s\n' "$rc" >"$log_dir/gate.status" || exit 2
cat "$log_dir/gate.result"
echo "=== IOMMU / DMAR lines ==="
grep -anE 'IOMMU|DMAR|DMA isolation|7\.53|InvalidDmar|InvalidStructure|unit' "$ser" | head -20 || true
if [ "$rc" -eq 0 ]; then
    echo "IOMMU-Q35-CHECK OK: IOMMU active/enabled, strict runtime summary and boot completion"
else
    echo "IOMMU-Q35-CHECK NOT-PASSED: gate status=$rc (1=failure, 2=incomplete, 3=qualified)"
    echo "=== last 30 serial lines ==="
    tail -30 "$ser" 2>/dev/null
    echo "=== timeout / QEMU stderr ==="
    tail -20 "$timeoutlog" "$qemuerr" 2>/dev/null
fi
exit "$rc"
