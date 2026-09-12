#!/bin/bash
# ============================================================================
# Zero-OS CI boot-health gate
# ============================================================================
# Sibling of `make test` / scripts/kernel_test.sh (runtime suite gate) and
# musl_check.sh. This script's exit code reflects real boot health — it boots
# the kernel under QEMU and asserts that:
#
#   1. one complete runtime summary reports failed=0, followed by PID 1 exit 0,
#   2. no fatal serial/interrupt evidence appears in the full observation window,
#   3. QEMU satisfies the bounded timeout termination contract, and
#   4. warnings/deferred/skipped evidence cannot satisfy strict pass (exit 3).
#
# Process lesson from D1: boot health MUST be read from the serial log and the
# QEMU `-d int` log as well as process termination, never exit status alone.
#
# Usage:   bash scripts/boot_check.sh [esp_dir]
# Env:     OVMF_PATH (default /usr/share/qemu/OVMF.fd)
#          BOOT_CHECK_TIMEOUT seconds (default 60, range 1..120)
#          BOOT_CHECK_KEEP_LOGS=1 retains all evidence files
# ============================================================================
set -u

# Resolve the repo root from this script's own location so it runs from any
# working directory (CI, the remote build host, a fresh clone) without a `cd`.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"

QEMU=qemu-system-x86_64
# ESP defaults to <repo>/esp; a relative override is resolved against the repo root
# (so `bash scripts/boot_check.sh esp` works the same from anywhere), absolute kept.
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TO="${BOOT_CHECK_TIMEOUT:-60}"
if [[ ! "$TO" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ ]]; then
    echo "BOOT-CHECK BLOCKED: BOOT_CHECK_TIMEOUT must be an integer from 1 to 120"
    exit 2
fi
for tool in "$QEMU" timeout python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "BOOT-CHECK BLOCKED: $tool not found in PATH"
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
    echo "BOOT-CHECK FAIL: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "BOOT-CHECK FAIL: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

ser="$(mktemp)" || exit 2
intlog="$(mktemp)" || exit 2
qemuerr="$(mktemp)" || exit 2
timeoutlog="$(mktemp)" || exit 2
cleanup() {
    if [ "${BOOT_CHECK_KEEP_LOGS:-0}" = 1 ]; then
        echo "BOOT-CHECK ARTIFACTS: serial=$ser intlog=$intlog qemuerr=$qemuerr timeoutlog=$timeoutlog counts=$ser.counts.json gate_status=$ser.gate.status"
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

# -d int,cpu_reset perturbs only host-side timing, not the guest binary/layout,
# and at boot almost no interrupts fire before [3/7], so it does not mask the
# layout-driven D1 fault while still capturing its #PF signature.
python3 "$ROOT/scripts/gate_inputs.py" prepare --source "$ESP" --output "$ser.inputs" \
    --firmware "$OVMF" --qemu "$(command -v "$QEMU")" || exit 2
"$QEMU" --version > "$ser.inputs/qemu.version" 2>&1 || exit 2

LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$TO" \
    bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:"$ser.inputs/esp",snapshot=on \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"
qemu_status=$?

python3 "$ROOT/scripts/gate_log.py" --serial "$ser" --intlog "$intlog" \
    --qemu-stderr "$qemuerr" --timeout-stderr "$timeoutlog" --qemu-status "$qemu_status" --json-output "$ser.counts.json"
rc=$?
python3 "$ROOT/scripts/gate_inputs.py" verify --output "$ser.inputs" || rc=1
if [ "$rc" -ne 0 ]; then
    echo "BOOT-CHECK NOT-PASSED: gate status=$rc (1=failure, 2=incomplete, 3=qualified)"
    echo "--- serial tail ---"
    tail -25 "$ser" 2>/dev/null | sed 's/^/    /'
    echo "--- timeout / QEMU stderr ---"
    tail -20 "$timeoutlog" "$qemuerr" 2>/dev/null | sed 's/^/    /'
fi

if [ "$rc" -eq 0 ]; then
    echo "BOOT-CHECK OK: runtime summary + PID 1 completion, no fatal markers or qualifications"
fi
printf '%s\n' "$rc" > "$ser.gate.status"
exit "$rc"
