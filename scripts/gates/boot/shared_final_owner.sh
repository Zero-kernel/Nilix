#!/bin/bash
# Focused PR86-1 gate. Uses the same markers as the full ring3-mm oracle.
# Build with NILIX_ST_K2_FINAL_OWNER_FOCUSED=1; negative control additionally
# sets NILIX_ST_K2_FINAL_OWNER_NEGATIVE=1 and must fail this unchanged gate.
set -u
ROOT="$(dirname "$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]}")")")")")"
ESP="${1:-$ROOT/esp}"
BOOT_LOG="$(mktemp)" || exit 2
trap 'rm -f -- "$BOOT_LOG"' EXIT
# Always collect at completion: the Extended lane exports window mode for its
# stability gates, but this focused release-window probe must not idle to the
# deadline after it has already reached its verdict.
KERNEL_TEST_COMPLETION_PROFILE=ring3 KERNEL_TEST_KEEP_LOGS=1 QEMU_GATE_MODE=completion \
    bash "$ROOT/scripts/gates/boot/kernel_test.sh" "$ESP" > "$BOOT_LOG" 2>&1
boot_status=$?
grep -E 'GATE-LOG|KERNEL-TEST' "$BOOT_LOG"
ser="$(sed -n 's/^KERNEL-TEST ARTIFACTS: serial=\([^ ]*\).*/\1/p' "$BOOT_LOG" | tail -1)"
if [ -z "$ser" ] || [ ! -f "$ser" ]; then
    echo 'FINAL-OWNER BLOCKED: missing serial artifact'
    exit 2
fi
source "$ROOT/scripts/ci/qemu_run.sh"
timeoutlog="$(sed -n 's/.* timeoutlog=\([^ ]*\).*/\1/p' "$BOOT_LOG" | tail -1)"
qemu_status="$(cat "$ser.qemu.status" 2>/dev/null || echo 125)"
fail=0
# This focused guest has no deliberate fatal faults. Preserve all underlying
# input-integrity, runtime and terminal-fault checks. Status 3 retains the
# runtime suite's explicitly reported qualifications; it is not a strict pass.
if [ "$boot_status" -ne 0 ] && [ "$boot_status" -ne 3 ]; then
    fail=1
fi
verify_gate_termination || fail=1
python3 "$ROOT/scripts/gates/boot/shared_final_owner_oracle.py" "$ser" \
    --cpus "${KERNEL_TEST_CPUS:-1}" --iterations "${NILIX_ST_K2_FINAL_OWNER_ITERS:-200}" || fail=1
if grep -Eq 'KERNEL PANIC|panicked at|PANIC:|\[(PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL|FAIL)\]|triple fault' "$ser" \
    || ! grep -Fxq '  Results: 1 passed, 0 failed' "$ser" \
    || ! grep -Fxq 'Process 1 terminated with exit code 0' "$ser"; then
    fail=1
fi
if [ "$fail" -ne 0 ]; then
    echo 'FINAL-OWNER FAIL: focused guest did not satisfy release/accounting oracle'
    exit 1
fi
echo 'FINAL-OWNER PASS: focused guest release/accounting oracle'
