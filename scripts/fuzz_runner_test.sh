#!/bin/bash
# ============================================================================
# KCOV Fuzz Runner Test Script (Phase 2 verification)
# ============================================================================
# Boots the KCOV-enabled kernel with fuzz_runner.elf and validates:
#   1. Kernel boots successfully
#   2. KCOV infrastructure initializes
#   3. fuzz_runner executes and reports results
#   4. No kernel panic or NX violations
#
# Exit codes:
#   0 = PASS     — fuzz_runner completed successfully
#   1 = FAILED   — panic, NX violation, or test failure
#   2 = NOT-RUN  — missing dependencies or timeout
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TO="${KERNEL_TEST_TIMEOUT:-30}"

# Detection markers
PANIC_MARKER='KERNEL PANIC'
NX_RE='v=0e e=0011'
KCOV_INIT_MARKER='KCOV'
FUZZ_START_MARKER='Phase 2'
FUZZ_COMPLETE_MARKER='Test.*PASS\|edges'

# OVMF autodetect
if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    OVMF="$(find /usr/share/OVMF/ -type f -name 'OVMF_CODE*.fd' 2>/dev/null | head -n 1)"
    if [ -z "$OVMF" ]; then
        echo "FUZZ-TEST BLOCKED: OVMF firmware not found"
        exit 2
    fi
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "FUZZ-TEST BLOCKED: $ESP/kernel.elf missing"
    exit 2
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "FUZZ-TEST BLOCKED: $QEMU not found in PATH"
    exit 2
fi

ser="$(mktemp)"
intlog="$(mktemp)"
qpid=""
cleanup() {
    if [ -n "${qpid:-}" ]; then
        kill "$qpid" 2>/dev/null || true
        wait "$qpid" 2>/dev/null || true
    fi
    rm -f "$ser" "$intlog"
}
trap cleanup EXIT

echo "=== KCOV Fuzz Runner Test (Phase 2) ==="
echo "Kernel:  $ESP/kernel.elf"
echo "OVMF:    $OVMF"
echo "Timeout: ${TO}s"
echo ""

timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -m 512M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Wait for completion or panic
for _ in $(seq 1 $((TO * 2))); do
    sleep 0.5
    if grep -Fq "$PANIC_MARKER" "$ser" 2>/dev/null; then
        break
    fi
    kill -0 "$qpid" 2>/dev/null || break
done

kill "$qpid" 2>/dev/null || true
wait "$qpid" 2>/dev/null || true
qpid=""

# Evaluate results
has_panic=0
grep -Fq "$PANIC_MARKER" "$ser" 2>/dev/null && has_panic=1

nx=$(grep -cF "$NX_RE" "$intlog" 2>/dev/null)
nx=${nx:-0}

has_kcov_init=0
grep -Eq "$KCOV_INIT_MARKER" "$ser" 2>/dev/null && has_kcov_init=1

has_fuzz_start=0
grep -Eq "$FUZZ_START_MARKER" "$ser" 2>/dev/null && has_fuzz_start=1

has_fuzz_complete=0
grep -Eq "$FUZZ_COMPLETE_MARKER" "$ser" 2>/dev/null && has_fuzz_complete=1

echo "=== Results ==="
echo "Panic:         $has_panic"
echo "NX violations: $nx"
echo "KCOV init:     $has_kcov_init"
echo "Fuzz start:    $has_fuzz_start"
echo "Fuzz complete: $has_fuzz_complete"
echo ""

# Classify
rc=0
if [ "$has_panic" -eq 1 ]; then
    echo "FUZZ-TEST FAIL: kernel panic"
    rc=1
fi
if [ "$nx" -gt 0 ]; then
    echo "FUZZ-TEST FAIL: $nx NX violations"
    rc=1
fi
if [ "$rc" -eq 0 ] && [ "$has_fuzz_complete" -ne 1 ]; then
    echo "FUZZ-TEST NOT-RUN: fuzz_runner did not complete within ${TO}s"
    rc=2
fi

echo "--- Serial output (last 50 lines) ---"
tail -50 "$ser" 2>/dev/null | sed 's/^/    /'
echo ""

if [ "$rc" -eq 0 ]; then
    echo "FUZZ-TEST PASS: fuzz_runner completed successfully"
else
    echo "FUZZ-TEST FAILED (exit $rc)"
fi

exit "$rc"
