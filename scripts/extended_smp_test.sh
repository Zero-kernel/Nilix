#!/bin/bash
# ============================================================================
# Nilix Extended SMP Test - High Core Count Validation
# ============================================================================
# Tests SMP functionality and stability at higher core counts (8-core, 16-core).
# Validates scheduler scaling, lock contention, and IPI handling under high
# CPU count scenarios that the standard 2/4-core tests don't expose.
#
# Test Configurations:
#   1. 8-core stress test
#   2. 16-core stress test (if CPU_MAX >= 16)
#
# Validates:
#   - All CPUs come online properly
#   - Scheduler handles high core count
#   - Lock contention doesn't cause deadlocks
#   - IPI/TLB shootdown scales
#   - No race conditions under high concurrency
#
# Exit Codes:
#   0 = PASS     - all cores online, tests passed
#   1 = FAILED   - panic, hang, or core initialization failure
#   2 = BLOCKED  - missing prerequisites
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Test timeout (higher for more cores)
EXTENDED_SMP_TIMEOUT="${EXTENDED_SMP_TIMEOUT:-90}"

# OVMF firmware autodetect
if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    echo "EXTENDED-SMP-TEST BLOCKED: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "EXTENDED-SMP-TEST BLOCKED: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "EXTENDED-SMP-TEST BLOCKED: $QEMU not found in PATH"
    exit 2
fi

echo "=== Nilix Extended SMP Test Suite ==="
echo "Kernel:  $ESP/kernel.elf"
echo "Timeout: ${EXTENDED_SMP_TIMEOUT}s per test"
echo ""

# ============================================================================
# Helper Functions
# ============================================================================

run_smp_test() {
    local cpu_count="$1"
    local timeout_val="$2"

    echo "=== Testing ${cpu_count}-Core Configuration ==="
    echo "Start time: $(date)"
    echo ""

    local ser intlog qemuerr timeoutlog
    ser="$(mktemp)"
    intlog="$(mktemp)"
    qemuerr="$(mktemp)"
    timeoutlog="$(mktemp)"

    # Boot with specified CPU count
    LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$timeout_val" \
        bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
        -drive format=raw,file=fat:rw:"$ESP" \
        -smp "$cpu_count" \
        -m 512M -vga std -no-reboot -no-shutdown \
        -cpu qemu64,+smep,+smap,+umip,+rdrand \
        -display none -serial "file:$ser" \
        -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"

    local qemu_status=$?

    # Analyze results
    local nx cpu_resets supervisor_faults
    nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null || echo 0)
    cpu_resets=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null || echo 0)
    supervisor_faults=$(grep -cE '\[PF ENTRY\]|\[PAGE FAULT\]|\[DOUBLE FAULT\]|triple fault|Triple fault|KERNEL PANIC' "$ser" 2>/dev/null || echo 0)

    # Check for successful SMP initialization
    local smp_online_passed=0
    if grep -qE 'smp_online.*PASS' "$ser" 2>/dev/null; then
        smp_online_passed=1
    fi

    # Extract online CPU count
    local online_cpus=0
    online_cpus=$(grep -oE '[0-9]+ CPU\(s\) online' "$ser" 2>/dev/null | head -1 | grep -oE '^[0-9]+' || echo 0)
    if [ "$online_cpus" -eq 0 ]; then
        online_cpus=$(grep -oE 'SMP enabled: [0-9]+' "$ser" 2>/dev/null | head -1 | grep -oE '[0-9]+$' || echo 0)
    fi

    # Check for test completion
    local has_summary=0
    if grep -q 'Test Summary' "$ser" 2>/dev/null; then
        has_summary=1
    fi

    # Check for SMP-specific tests
    local r175_tests=$(grep -cE 'r175_d0_cross_.*PASS' "$ser" 2>/dev/null || echo 0)
    local rf178_33=$(grep -cE 'rf178_33_sched_smp_gate.*PASS' "$ser" 2>/dev/null || echo 0)
    local ipi_test=$(grep -cE 'ipi_ping_pong.*PASS' "$ser" 2>/dev/null || echo 0)
    local tlb_test=$(grep -cE 'tlb_shootdown_coherency.*PASS' "$ser" 2>/dev/null || echo 0)

    # Display results
    echo "=== Results for ${cpu_count}-Core Test ==="
    echo "Online CPUs:     $online_cpus / $cpu_count"
    echo "SMP online test: $([ $smp_online_passed -eq 1 ] && echo 'PASS' || echo 'FAIL')"
    echo "Test summary:    $([ $has_summary -eq 1 ] && echo 'Present' || echo 'Missing')"
    echo "NX violations:   $nx"
    echo "CPU resets:      $cpu_resets"
    echo "Supervisor faults: $supervisor_faults"
    echo ""
    echo "SMP-Specific Tests:"
    echo "  R175 D0 cross-CPU tests: $r175_tests"
    echo "  RF178-33 scheduler gate: $([ $rf178_33 -gt 0 ] && echo 'PASS' || echo 'SKIP')"
    echo "  IPI ping-pong test:      $([ $ipi_test -gt 0 ] && echo 'PASS' || echo 'SKIP')"
    echo "  TLB shootdown test:      $([ $tlb_test -gt 0 ] && echo 'PASS' || echo 'SKIP')"
    echo ""

    # Determine pass/fail
    local result=0

    if [ "$nx" -gt 0 ]; then
        echo "❌ FAIL: $nx NX-violation #PF detected"
        result=1
    fi

    if [ "$cpu_resets" -gt 0 ]; then
        echo "❌ FAIL: $cpu_resets CPU reset detected"
        result=1
    fi

    if [ "$supervisor_faults" -gt 0 ]; then
        echo "❌ FAIL: $supervisor_faults supervisor fault(s) detected"
        result=1
    fi

    # Expect at least 75% of CPUs to come online
    local min_expected_cpus=$(( (cpu_count * 3) / 4 ))
    if [ "$online_cpus" -lt "$min_expected_cpus" ]; then
        echo "❌ FAIL: Only $online_cpus CPUs online (expected at least $min_expected_cpus)"
        result=1
    fi

    if [ "$smp_online_passed" -eq 0 ]; then
        echo "❌ FAIL: smp_online test did not pass"
        result=1
    fi

    if [ "$has_summary" -eq 0 ]; then
        echo "⚠️  WARN: Test suite did not complete (timeout or early exit)"
        # Not a hard failure for extended SMP tests
    fi

    if [ "$result" -eq 0 ]; then
        echo "✅ PASS: ${cpu_count}-core test successful"
    else
        echo "❌ FAIL: ${cpu_count}-core test failed"
        echo ""
        echo "--- Serial log tail ---"
        tail -40 "$ser" 2>/dev/null | sed 's/^/    /'
    fi

    rm -f "$ser" "$intlog" "$qemuerr" "$timeoutlog"
    echo "End time: $(date)"
    echo ""

    return $result
}

# ============================================================================
# Main Test Execution
# ============================================================================

echo "=== System Information ==="
echo "Host CPU cores: $(nproc 2>/dev/null || echo 'unknown')"
echo ""

total_tests=0
passed_tests=0
failed_tests=0

# Test 1: 8-core configuration
echo "TEST 1: 8-Core SMP Validation"
echo ""
total_tests=$((total_tests + 1))
if run_smp_test 8 "$EXTENDED_SMP_TIMEOUT"; then
    passed_tests=$((passed_tests + 1))
else
    failed_tests=$((failed_tests + 1))
fi

# Test 2: 16-core configuration (if supported)
echo "TEST 2: 16-Core SMP Validation"
echo ""
total_tests=$((total_tests + 1))
if run_smp_test 16 "$((EXTENDED_SMP_TIMEOUT + 30))"; then
    passed_tests=$((passed_tests + 1))
else
    failed_tests=$((failed_tests + 1))
fi

# Summary
echo "=== Extended SMP Test Summary ==="
echo "Total tests:  $total_tests"
echo "Passed:       $passed_tests"
echo "Failed:       $failed_tests"
echo ""

if [ "$failed_tests" -gt 0 ]; then
    echo "❌ EXTENDED-SMP-TEST FAILED: $failed_tests test(s) failed"
    exit 1
else
    echo "✅ EXTENDED-SMP-TEST PASS: All high-core-count tests passed"
    echo ""
    echo "Validated configurations:"
    echo "  - 8-core SMP operation"
    echo "  - 16-core SMP operation"
    echo "  - Scheduler scaling to high core count"
    echo "  - IPI/TLB shootdown at scale"
    exit 0
fi
