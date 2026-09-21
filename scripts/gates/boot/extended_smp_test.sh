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
#   0 = PASS     - all cores online, strict runtime completion, tests passed
#   1 = FAILED   - panic, hang, or core initialization failure
#   2 = BLOCKED  - missing prerequisites
#   3 = QUALIFIED - warnings, deferred or skipped tests remain (not strict pass)
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Test timeout (higher for more cores)
EXTENDED_SMP_TIMEOUT="${EXTENDED_SMP_TIMEOUT:-900}"
if [[ ! "$EXTENDED_SMP_TIMEOUT" =~ ^([1-9]|[1-9][0-9]|[1-8][0-9][0-9]|900)$ ]]; then
    echo "EXTENDED-SMP-TEST BLOCKED: EXTENDED_SMP_TIMEOUT must be an integer from 1 to 900"
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "EXTENDED-SMP-TEST BLOCKED: python3 is required for gate-log validation"
    exit 2
fi

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
    python3 "$ROOT/scripts/ci/gate_inputs.py" prepare --source "$ESP" --output "$ser.inputs" \
        --firmware "$OVMF" --qemu "$(command -v "$QEMU")" || return 2
    "$QEMU" --version > "$ser.inputs/qemu.version" 2>&1 || return 2

    LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$timeout_val" \
        bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
        -drive format=raw,file=fat:"$ser.inputs/esp",snapshot=on \
        -smp "$cpu_count" \
        -m 512M -vga std -no-reboot -no-shutdown \
        -cpu qemu64,+smep,+smap,+umip,+rdrand \
        -display none -serial "file:$ser" \
        -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"

    local qemu_status=$?

    # Analyze results
    local nx cpu_resets supervisor_faults
    nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null)
    nx=${nx:-0}
    cpu_resets=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null)
    cpu_resets=${cpu_resets:-0}
    supervisor_faults=$(grep -cE '\[PF ENTRY\]|\[PAGE FAULT\]|\[DOUBLE FAULT\]|triple fault|Triple fault|KERNEL PANIC' "$ser" 2>/dev/null)
    supervisor_faults=${supervisor_faults:-0}

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
    local r175_tests rf178_33 ipi_test tlb_test
    r175_tests=$(grep -cE 'r175_d0_cross_.*PASS' "$ser" 2>/dev/null)
    r175_tests=${r175_tests:-0}
    rf178_33=$(grep -cE 'rf178_33_sched_smp_gate.*PASS' "$ser" 2>/dev/null)
    rf178_33=${rf178_33:-0}
    ipi_test=$(grep -cE 'ipi_ping_pong.*PASS' "$ser" 2>/dev/null)
    ipi_test=${ipi_test:-0}
    tlb_test=$(grep -cE 'tlb_shootdown_coherency.*PASS' "$ser" 2>/dev/null)
    tlb_test=${tlb_test:-0}

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
    python3 "$ROOT/scripts/ci/gate_log.py" --serial "$ser" --intlog "$intlog" \
        --qemu-stderr "$qemuerr" --timeout-stderr "$timeoutlog" --qemu-status "$qemu_status" --json-output "$ser.counts.json"
    local result=$?
    python3 "$ROOT/scripts/ci/gate_inputs.py" verify --output "$ser.inputs" || result=1

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
        echo "INCOMPLETE: Test suite did not complete (timeout or early exit)"
        if [ "$result" -eq 0 ] || [ "$result" -eq 3 ]; then
            result=2
        fi
    fi

    if [ "$online_cpus" -lt "$cpu_count" ] || [ "$r175_tests" -lt 3 ] || \
        [ "$rf178_33" -eq 0 ] || [ "$ipi_test" -eq 0 ] || [ "$tlb_test" -eq 0 ]; then
        echo "QUALIFIED: requested topology or SMP-specific checks were not fully exercised"
        if [ "$result" -eq 0 ]; then
            result=3
        fi
    fi

    if [ "$result" -eq 0 ]; then
        echo "✅ PASS: ${cpu_count}-core test successful"
    elif [ "$result" -eq 3 ]; then
        echo "QUALIFIED: ${cpu_count}-core test is not a strict pass"
    else
        echo "❌ FAIL: ${cpu_count}-core test failed"
        echo ""
        echo "--- Serial log tail ---"
        tail -40 "$ser" 2>/dev/null | sed 's/^/    /'
    fi

    printf '%s\n' "$result" > "$ser.gate.status"
    if [ "${EXTENDED_SMP_KEEP_LOGS:-0}" = 1 ]; then
        echo "EXTENDED-SMP ARTIFACTS: serial=$ser intlog=$intlog qemuerr=$qemuerr timeoutlog=$timeoutlog counts=$ser.counts.json gate_status=$ser.gate.status"
    else
        rm -rf -- "$ser.inputs"
        rm -f "$ser" "$intlog" "$qemuerr" "$timeoutlog" "$ser.counts.json" "$ser.gate.status"
    fi
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
incomplete_tests=0
qualified_tests=0
suite_status=0

record_result() {
    local result="$1"
    case "$result" in
        0) passed_tests=$((passed_tests + 1)) ;;
        3)
            qualified_tests=$((qualified_tests + 1))
            if [ "$suite_status" -eq 0 ]; then suite_status=3; fi
            ;;
        2)
            incomplete_tests=$((incomplete_tests + 1))
            if [ "$suite_status" -ne 1 ]; then suite_status=2; fi
            ;;
        *) failed_tests=$((failed_tests + 1)); suite_status=1 ;;
    esac
}

# Test 1: 8-core configuration
echo "TEST 1: 8-Core SMP Validation"
echo ""
total_tests=$((total_tests + 1))
run_smp_test 8 "$EXTENDED_SMP_TIMEOUT"
record_result "$?"

# Test 2: 16-core configuration (if supported)
echo "TEST 2: 16-Core SMP Validation"
echo ""
total_tests=$((total_tests + 1))
run_smp_test 16 "$EXTENDED_SMP_TIMEOUT"
record_result "$?"

# Summary
echo "=== Extended SMP Test Summary ==="
echo "Total tests:  $total_tests"
echo "Passed:       $passed_tests"
echo "Failed:       $failed_tests"
echo "Incomplete:   $incomplete_tests"
echo "Qualified:    $qualified_tests (not strict passes)"
echo ""

if [ "$suite_status" -ne 0 ]; then
    echo "EXTENDED-SMP-TEST NOT-PASSED: failed=$failed_tests incomplete=$incomplete_tests qualified=$qualified_tests"
    exit "$suite_status"
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
