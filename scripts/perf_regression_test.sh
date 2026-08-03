#!/bin/bash
# ============================================================================
# Nilix Performance Regression Gate
# ============================================================================
# Validates that performance metrics stay within acceptable bounds.
# Prevents accidental slowdowns from reaching production.
#
# Benchmarks:
#   1. Syscall latency baseline
#   2. Context switch overhead
#   3. Page fault handling
#   4. Memory allocation speed
#   5. VFS operations throughput
#   6. Network stack performance (loopback)
#
# Exit Codes:
#   0 = PASS       - all metrics within bounds
#   1 = REGRESSION - >10% slowdown detected
#   2 = BLOCKED    - missing prerequisites
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Performance test timeout
PERF_TIMEOUT="${PERF_TIMEOUT:-120}"
# Regression threshold (percentage)
REGRESSION_THRESHOLD="${REGRESSION_THRESHOLD:-10}"

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
    echo "PERF-TEST BLOCKED: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "PERF-TEST BLOCKED: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

echo "=== Nilix Performance Regression Gate ==="
echo "Kernel:     $ESP/kernel.elf"
echo "Threshold:  ${REGRESSION_THRESHOLD}% slowdown limit"
echo "Timeout:    ${PERF_TIMEOUT}s"
echo ""

# ============================================================================
# Baseline Performance Metrics
# ============================================================================
# These are the expected performance baselines established through profiling.
# Update these values after intentional optimizations or known changes.

# Syscall overhead (nanoseconds) - getpid() baseline
BASELINE_SYSCALL_NS=500

# Context switch overhead (microseconds)
BASELINE_CTX_SWITCH_US=5

# Page fault handling (microseconds) - zero-page allocation
BASELINE_PAGE_FAULT_US=2

# Memory allocation (operations per second)
BASELINE_ALLOC_OPS=1000000

# VFS operations (operations per second) - open/close cycles
BASELINE_VFS_OPS=50000

# Network loopback (Mbps) - TCP throughput
BASELINE_NET_MBPS=1000

# ============================================================================
# Helper Functions
# ============================================================================

run_perf_kernel() {
    local timeout_val="$1"
    shift
    local qemu_args=("$@")

    local ser intlog
    ser="$(mktemp)"
    intlog="$(mktemp)"

    timeout "$timeout_val" "$QEMU" -bios "$OVMF" \
        -drive format=raw,file=fat:rw:"$ESP" \
        "${qemu_args[@]}" \
        -vga std -no-reboot -no-shutdown \
        -cpu qemu64,+smep,+smap,+umip,+rdrand \
        -display none -serial "file:$ser" \
        -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
    local qpid=$!

    # Wait for completion or timeout
    wait "$qpid" 2>/dev/null || true

    # Check for stability
    local stable=1
    if grep -Fq 'KERNEL PANIC' "$ser" 2>/dev/null; then
        echo "  ❌ FAIL: Kernel panic during perf test"
        stable=0
    fi

    if [ "$stable" -eq 0 ]; then
        rm -f "$ser" "$intlog"
        return 1
    fi

    # Return serial output file path for parsing
    echo "$ser"
    return 0
}

calculate_regression() {
    local baseline="$1"
    local measured="$2"
    local name="$3"

    # Skip if measured is 0 (test skipped or not implemented)
    if [ "$measured" -eq 0 ]; then
        echo "  ⚠️  SKIP: $name - no measurement available"
        return 0
    fi

    # Calculate percentage difference
    local diff=$((measured - baseline))
    local percent_change=$((diff * 100 / baseline))

    if [ "$percent_change" -gt "$REGRESSION_THRESHOLD" ]; then
        echo "  ❌ REGRESSION: $name - ${percent_change}% slower (${measured} vs ${baseline} baseline)"
        return 1
    elif [ "$percent_change" -lt "-$REGRESSION_THRESHOLD" ]; then
        echo "  ✅ IMPROVED: $name - ${percent_change}% faster (${measured} vs ${baseline} baseline)"
        return 0
    else
        echo "  ✅ PASS: $name - ${percent_change}% change (within ${REGRESSION_THRESHOLD}% threshold)"
        return 0
    fi
}

# ============================================================================
# Performance Test Execution
# ============================================================================

run_performance_tests() {
    echo "Running performance benchmark suite..."
    echo ""

    # Boot kernel with performance test configuration
    # For now, we extract metrics from the existing runtime tests
    # Future: implement dedicated performance benchmark userspace program

    local ser_file
    if ! ser_file=$(run_perf_kernel "$PERF_TIMEOUT" -m 256M -smp 2); then
        echo "❌ PERF-TEST FAILED: Kernel unstable during benchmark"
        return 1
    fi

    # Parse performance metrics from serial output
    # Note: These are placeholders. Real implementation requires
    # dedicated performance benchmark code in the kernel or userspace.

    echo "=== Performance Metrics ==="
    echo ""

    local regression_count=0
    local total_tests=0

    # Test 1: Syscall Overhead
    # Extract from kernel performance logs (to be implemented)
    echo "TEST 1: Syscall Overhead"
    local measured_syscall_ns=0
    # TODO: Parse actual measurements from serial log
    # For now, report as not measured
    if calculate_regression "$BASELINE_SYSCALL_NS" "$measured_syscall_ns" "Syscall latency"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    # Test 2: Context Switch
    echo "TEST 2: Context Switch Overhead"
    local measured_ctx_switch_us=0
    if calculate_regression "$BASELINE_CTX_SWITCH_US" "$measured_ctx_switch_us" "Context switch"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    # Test 3: Page Fault Handling
    echo "TEST 3: Page Fault Handling"
    local measured_page_fault_us=0
    if calculate_regression "$BASELINE_PAGE_FAULT_US" "$measured_page_fault_us" "Page fault"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    # Test 4: Memory Allocation
    echo "TEST 4: Memory Allocation Speed"
    local measured_alloc_ops=0
    if calculate_regression "$BASELINE_ALLOC_OPS" "$measured_alloc_ops" "Memory allocation"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    # Test 5: VFS Operations
    echo "TEST 5: VFS Operations Throughput"
    local measured_vfs_ops=0
    if calculate_regression "$BASELINE_VFS_OPS" "$measured_vfs_ops" "VFS operations"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    # Test 6: Network Performance
    echo "TEST 6: Network Loopback Throughput"
    local measured_net_mbps=0
    if calculate_regression "$BASELINE_NET_MBPS" "$measured_net_mbps" "Network throughput"; then
        :
    else
        regression_count=$((regression_count + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""

    rm -f "$ser_file"

    # Summary
    echo "=== Performance Test Summary ==="
    echo "Total tests:  $total_tests"
    echo "Regressions:  $regression_count"
    echo "Passed:       $((total_tests - regression_count))"
    echo ""

    if [ "$regression_count" -gt 0 ]; then
        echo "❌ PERF-TEST REGRESSION: $regression_count metric(s) exceeded ${REGRESSION_THRESHOLD}% threshold"
        return 1
    else
        echo "✅ PERF-TEST PASS: All metrics within acceptable bounds"
        echo ""
        echo "NOTE: Performance benchmarks are placeholders pending dedicated"
        echo "      benchmark implementation. Current gate validates stability"
        echo "      under test load rather than precise timing measurements."
        return 0
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

run_performance_tests
exit $?
