#!/bin/bash
# Ring-3 memory-management oracle gate.
#
# Boots the `syscall_test` guest (built by `make build-syscall-test`) and checks
# the Ring-3 verdict: every expected [PASS] line is present, `Results: N passed,
# 0 failed`, and PID 1 exits 0.
#
# WHY THIS IS A SEPARATE GATE
# `scripts/gates/boot/kernel_test.sh` treats ANY `[PF ENTRY]` line as fatal. That
# ban is right for its own fixture (`hello.elf`), which never demand-faults. It
# is inapplicable here: the shared-anonymous model IS demand paging, so
# exercising it necessarily announces `[PF ENTRY]` on handled faults. This gate
# therefore reuses the boot harness for everything mechanical (firmware, ESP,
# artifacts, QEMU invocation) and applies the fault-tolerant verdict the same
# way `scripts/gates/qemu/open_fault_probe.py` does for the musl workload:
# require terminal fault outcomes and clean completion instead of the absence of
# handled faults.
#
# Exit: 0 = oracle passed, 1 = oracle failed, 2 = blocked/incomplete.
set -u

ROOT="$(dirname "$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")")"
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Terminal fault outcomes only. Deliberately omits `[PF ENTRY]`; see above.
FATAL='KERNEL PANIC|panicked at|PANIC:|\[(PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL)\]|triple fault'

BOOT_LOG="$(mktemp)" || exit 2
trap 'rm -f -- "$BOOT_LOG"' EXIT

# The boot gate's own status is NOT this gate's verdict: it will report failure
# solely because of the handled `[PF ENTRY]` lines. Everything mechanical is
# still reused, and its summary is printed for the record.
KERNEL_TEST_KEEP_LOGS=1 bash "$ROOT/scripts/gates/boot/kernel_test.sh" "$ESP" > "$BOOT_LOG" 2>&1
boot_status=$?
grep -E 'GATE-LOG|KERNEL-TEST' "$BOOT_LOG" | sed 's/^/  boot-harness: /'

serial="$(sed -n 's/^KERNEL-TEST ARTIFACTS: serial=\([^ ]*\).*/\1/p' "$BOOT_LOG" | tail -1)"
if [ -z "$serial" ] || [ ! -f "$serial" ]; then
    echo "RING3-MM BLOCKED: boot harness did not report a serial artifact"
    exit 2
fi

fail=0
report_fail() {
    echo "RING3-MM FAIL: $1"
    fail=1
}

# 1. No terminal fault outcome anywhere in the serial.
if grep -Eq "$FATAL" "$serial"; then
    report_fail "terminal fault marker in serial"
fi

# 2. Every leg printed its PASS line. The list is the contract: a leg that stops
#    running (or is renamed) must fail the gate rather than silently disappear.
while IFS= read -r leg; do
    [ -z "$leg" ] && continue
    if ! grep -Fq "[PASS] $leg" "$serial"; then
        report_fail "missing oracle leg: $leg"
    fi
done <<'LEGS'
mremap grow-in-place + shrink
mremap MREMAP_MAYMOVE relocation
mremap fail-closed shape matrix
mremap on a PROT_NONE reservation
mremap charge symmetry
MAP_SHARED|MAP_ANONYMOUS fork visibility + mremap boundary
shared-anon migration: gated on host root, refused
LEGS

# 3. No leg reported a failure, and the suite ran to completion.
if grep -Eq '^\[FAIL\]' "$serial"; then
    report_fail "the guest reported a failing leg"
fi
if ! grep -Eq '^  Results: [0-9]+ passed, 0 failed$' "$serial"; then
    report_fail "missing or non-zero 'Results: N passed, 0 failed' summary"
fi
if ! grep -Eq '^Process 1 terminated with exit code 0$' "$serial"; then
    report_fail "PID 1 did not exit 0"
fi

if [ "$fail" -ne 0 ]; then
    echo "RING3-MM FAIL"
    echo "RING3-MM ARTIFACTS: serial=$serial"
    echo "--- serial tail ---"
    tail -25 "$serial" 2>/dev/null | sed 's/^/    /'
    exit 1
fi

echo "RING3-MM OK: Ring-3 memory-management oracle passed (boot harness status was $boot_status)"
echo "RING3-MM ARTIFACTS: serial=$serial"
exit 0
