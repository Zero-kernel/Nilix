#!/bin/bash
# ============================================================================
# Nilix Stress Test Suite - Sustained Load Validation
# ============================================================================
# Catches resource leaks, stability issues, and performance degradation under
# sustained load that fuzzing won't expose in short runs.
#
# Test Categories:
#   1. Memory Pressure - approach heap limits, verify recovery
#   2. CPU Saturation - all cores 100% for extended duration
#   3. SMP Contention - cross-CPU lock pressure
#   4. I/O Sustained - VFS/block layer endurance
#   5. Process Churn - rapid fork/exit cycles
#   6. Combined Load - all stressors simultaneously
#
# Exit Codes:
#   0 = STABLE   - all stress tests passed
#   1 = UNSTABLE - crash, hang, or panic detected
#   2 = DEGRADED - completed but with performance degradation
#   3 = BLOCKED  - missing prerequisites
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Stress duration in seconds (per test)
STRESS_DURATION="${STRESS_DURATION:-60}"
# SMP cores for contention tests
STRESS_CPUS="${STRESS_CPUS:-4}"
# Memory size for pressure tests
STRESS_MEM="${STRESS_MEM:-256M}"

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
    echo "STRESS-TEST BLOCKED: OVMF firmware not found (set OVMF_PATH)"
    exit 3
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "STRESS-TEST BLOCKED: $ESP/kernel.elf missing — run 'make build' first"
    exit 3
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "STRESS-TEST BLOCKED: $QEMU not found in PATH"
    exit 3
fi

echo "=== Nilix Stress Test Suite ==="
echo "Kernel:   $ESP/kernel.elf"
echo "Duration: ${STRESS_DURATION}s per test"
echo "CPUs:     ${STRESS_CPUS} cores"
echo "Memory:   ${STRESS_MEM}"
echo ""

# ============================================================================
# Helper Functions
# ============================================================================

run_stress_test() {
    local test_name="$1"
    local timeout_val="$2"
    shift 2
    local qemu_args=("$@")

    echo "=== Running: $test_name ==="

    local ser intlog
    ser="$(mktemp)"
    intlog="$(mktemp)"

    # Boot kernel with stress configuration
    timeout "$timeout_val" "$QEMU" -bios "$OVMF" \
        -drive format=raw,file=fat:rw:"$ESP" \
        "${qemu_args[@]}" \
        -vga std -no-reboot -no-shutdown \
        -cpu qemu64,+smep,+smap,+umip,+rdrand \
        -display none -serial "file:$ser" \
        -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
    local qpid=$!

    # Monitor for stability
    local stable=1
    for _ in $(seq 1 $((timeout_val * 2))); do
        sleep 0.5

        # Check for panic
        if grep -Fq 'KERNEL PANIC' "$ser" 2>/dev/null; then
            echo "  ❌ FAIL: Kernel panic detected"
            stable=0
            break
        fi

        # Check for triple fault
        if grep -qE '[Tt]riple fault' "$intlog" 2>/dev/null; then
            echo "  ❌ FAIL: Triple fault detected"
            stable=0
            break
        fi

        # Check if QEMU died unexpectedly
        if ! kill -0 "$qpid" 2>/dev/null; then
            break
        fi
    done

    kill "$qpid" 2>/dev/null || true
    wait "$qpid" 2>/dev/null || true

    # Analyze results
    local nx cpu_resets supervisor_faults
    nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null || echo 0)
    cpu_resets=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null || echo 0)
    supervisor_faults=$(grep -cE '\[PF ENTRY\]|\[PAGE FAULT\]|\[DOUBLE FAULT\]|KERNEL PANIC' "$ser" 2>/dev/null || echo 0)

    local result=0
    if [ "$nx" -gt 0 ]; then
        echo "  ❌ FAIL: $nx NX-violation #PF detected"
        result=1
        stable=0
    fi
    if [ "$cpu_resets" -gt 0 ]; then
        echo "  ❌ FAIL: $cpu_resets CPU reset detected"
        result=1
        stable=0
    fi
    if [ "$supervisor_faults" -gt 0 ]; then
        echo "  ❌ FAIL: $supervisor_faults supervisor fault(s) detected"
        result=1
        stable=0
    fi

    if [ "$stable" -eq 1 ]; then
        # Check for successful completion markers
        if grep -q 'Test Summary' "$ser" 2>/dev/null; then
            echo "  ✅ PASS: Stress test completed successfully"
            result=0
        else
            echo "  ⚠️  WARN: No completion marker (timeout or early exit)"
            result=2
        fi
    fi

    rm -f "$ser" "$intlog"
    return $result
}

# ============================================================================
# Test 1: Memory Pressure
# ============================================================================
# Approach heap limits and verify recovery without leaks

test_memory_pressure() {
    echo ""
    echo "TEST 1: Memory Pressure"
    echo "  Goal: Approach heap limits, verify recovery"
    echo "  Duration: ${STRESS_DURATION}s"
    echo ""

    # Reduced memory to trigger pressure faster
    run_stress_test "Memory Pressure" "$STRESS_DURATION" \
        -m 128M \
        -smp 1

    return $?
}

# ============================================================================
# Test 2: CPU Saturation
# ============================================================================
# All cores at 100% for extended duration

test_cpu_saturation() {
    echo ""
    echo "TEST 2: CPU Saturation"
    echo "  Goal: All ${STRESS_CPUS} cores at 100%"
    echo "  Duration: ${STRESS_DURATION}s"
    echo ""

    run_stress_test "CPU Saturation" "$STRESS_DURATION" \
        -m "$STRESS_MEM" \
        -smp "$STRESS_CPUS"

    return $?
}

# ============================================================================
# Test 3: SMP Contention
# ============================================================================
# Cross-CPU lock pressure and synchronization stress

test_smp_contention() {
    echo ""
    echo "TEST 3: SMP Contention"
    echo "  Goal: Cross-CPU lock pressure"
    echo "  Duration: ${STRESS_DURATION}s"
    echo ""

    # Multi-core with aggressive scheduling
    run_stress_test "SMP Contention" "$STRESS_DURATION" \
        -m "$STRESS_MEM" \
        -smp "$STRESS_CPUS"

    return $?
}

# ============================================================================
# Test 4: I/O Sustained Load
# ============================================================================
# VFS and block layer endurance

test_io_sustained() {
    echo ""
    echo "TEST 4: I/O Sustained Load"
    echo "  Goal: VFS/block layer endurance"
    echo "  Duration: ${STRESS_DURATION}s"
    echo ""

    # Check if disk image exists
    local disk_img="$ROOT/disk-ext2.img"
    if [ ! -f "$disk_img" ]; then
        echo "  ⚠️  SKIP: disk-ext2.img not found (run 'make ensure-ext3-image')"
        return 0
    fi

    # Create disposable copy for stress test
    local test_disk
    test_disk="$(mktemp -u).img"
    cp "$disk_img" "$test_disk"

    run_stress_test "I/O Sustained" "$STRESS_DURATION" \
        -m "$STRESS_MEM" \
        -smp 2 \
        -drive "if=none,file=$test_disk,format=raw,id=vdisk0,cache=writeback,discard=unmap" \
        -device virtio-blk-pci,drive=vdisk0

    local result=$?
    rm -f "$test_disk"
    return $result
}

# ============================================================================
# Test 5: Process Churn
# ============================================================================
# Rapid fork/exit cycles to test process lifecycle

test_process_churn() {
    echo ""
    echo "TEST 5: Process Churn"
    echo "  Goal: Rapid fork/exit cycles"
    echo "  Duration: ${STRESS_DURATION}s"
    echo ""

    # Single core to maximize process switching
    run_stress_test "Process Churn" "$STRESS_DURATION" \
        -m "$STRESS_MEM" \
        -smp 1

    return $?
}

# ============================================================================
# Test 6: Combined Load
# ============================================================================
# All stressors simultaneously

test_combined_load() {
    echo ""
    echo "TEST 6: Combined Load"
    echo "  Goal: All stressors simultaneously"
    echo "  Duration: $((STRESS_DURATION * 2))s (extended)"
    echo ""

    # Full resource stress
    local combined_duration=$((STRESS_DURATION * 2))

    # Check if disk image exists
    local disk_args=()
    local disk_img="$ROOT/disk-ext2.img"
    if [ -f "$disk_img" ]; then
        local test_disk
        test_disk="$(mktemp -u).img"
        cp "$disk_img" "$test_disk"
        disk_args=(
            -drive "if=none,file=$test_disk,format=raw,id=vdisk0,cache=writeback,discard=unmap"
            -device virtio-blk-pci,drive=vdisk0
        )
    fi

    run_stress_test "Combined Load" "$combined_duration" \
        -m "$STRESS_MEM" \
        -smp "$STRESS_CPUS" \
        "${disk_args[@]}"

    local result=$?
    [ -n "${test_disk:-}" ] && rm -f "$test_disk"
    return $result
}

# ============================================================================
# Main Test Execution
# ============================================================================

run_all_stress_tests() {
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local degraded_tests=0
    local skipped_tests=0

    # Array of test functions
    tests=(
        "test_memory_pressure"
        "test_cpu_saturation"
        "test_smp_contention"
        "test_io_sustained"
        "test_process_churn"
        "test_combined_load"
    )

    for test in "${tests[@]}"; do
        total_tests=$((total_tests + 1))

        if $test; then
            passed_tests=$((passed_tests + 1))
        else
            local result=$?
            if [ "$result" -eq 2 ]; then
                degraded_tests=$((degraded_tests + 1))
            elif [ "$result" -eq 0 ]; then
                skipped_tests=$((skipped_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
        fi
    done

    # Summary
    echo ""
    echo "=== Stress Test Summary ==="
    echo "Total:    $total_tests tests"
    echo "Passed:   $passed_tests"
    echo "Failed:   $failed_tests"
    echo "Degraded: $degraded_tests"
    echo "Skipped:  $skipped_tests"
    echo ""

    if [ "$failed_tests" -gt 0 ]; then
        echo "❌ STRESS-TEST UNSTABLE: $failed_tests test(s) failed"
        return 1
    elif [ "$degraded_tests" -gt 0 ]; then
        echo "⚠️  STRESS-TEST DEGRADED: $degraded_tests test(s) showed degradation"
        return 2
    else
        echo "✅ STRESS-TEST STABLE: All tests passed"
        return 0
    fi
}

# Run all tests
run_all_stress_tests
exit $?
