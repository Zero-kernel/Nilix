#!/bin/bash
# ============================================================================
# Zero-OS 2-Core SMP Test - R175 D0 Fix Validation
# ============================================================================
# Boots the kernel with 2 CPUs and validates R175 D0 fixes activate properly.
#
# P0-B VT-1: silent skip is a defect. This harness FAILS (not warns) when:
#   - smp_online does not PASS
#   - fewer than 3 r175_d0_cross_* tests PASS
#   - fewer than 2 CPUs are reported online
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TO=30
MIN_CPUS=2
MIN_R175=3

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
    echo "SMP-TEST FAIL: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "SMP-TEST FAIL: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

ser="$(mktemp)"
intlog="$(mktemp)"
trap 'rm -f "$ser" "$intlog"' EXIT

echo "=== Running 2-Core SMP Test ==="
echo "Kernel: $ESP/kernel.elf"
echo "Timeout: ${TO}s"
echo ""

# Boot with 2 CPUs (SMP enabled)
timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -smp 2 \
    -m 512M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Wait for boot completion
reached=0
for _ in $(seq 1 $((TO * 2))); do
    sleep 0.5
    if grep -qE 'Process 1 exited|Test Summary' "$ser" 2>/dev/null; then
        reached=1
        break
    fi
    kill -0 "$qpid" 2>/dev/null || break
done
kill "$qpid" 2>/dev/null
wait "$qpid" 2>/dev/null

# Extract test results
nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null)
nx=${nx:-0}
cpu_reset=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null)
cpu_reset=${cpu_reset:-0}

# Check SMP online + R175 D0-CROSS suite (not the broader r175_* stress set)
# P1-B / RF178-33: also require the dedicated scheduler SMP gate PASS.
smp_online=$(grep -cE 'smp_online.*PASS' "$ser" 2>/dev/null)
smp_online=${smp_online:-0}
r175_tests=$(grep -cE 'r175_d0_cross_.*PASS' "$ser" 2>/dev/null)
r175_tests=${r175_tests:-0}
rf178_33=$(grep -cE 'rf178_33_sched_smp_gate.*PASS' "$ser" 2>/dev/null)
rf178_33=${rf178_33:-0}

# Prefer explicit topology markers; fall back to smp_online PASS alone.
online_cpus=$(grep -oE '[0-9]+ CPU\(s\) online' "$ser" 2>/dev/null | head -1 | grep -oE '^[0-9]+' || true)
if [ -z "${online_cpus:-}" ]; then
    online_cpus=$(grep -oE 'SMP enabled: [0-9]+' "$ser" 2>/dev/null | head -1 | grep -oE '[0-9]+$' || true)
fi
online_cpus=${online_cpus:-0}

# Extract test summary
echo "=== Test Results ==="
grep -E 'CPUs online|smp_online|SMP enabled|Spectre mitigation floor' "$ser" 2>/dev/null | head -10
echo ""
grep -E 'r175_d0_cross' "$ser" 2>/dev/null
echo ""
grep 'Test Summary' "$ser" 2>/dev/null
echo ""
echo "Parsed: online_cpus=${online_cpus} smp_online_PASS=${smp_online} r175_d0_cross_PASS=${r175_tests} rf178_33_PASS=${rf178_33}"
echo ""

rc=0
if [ "$nx" -gt 0 ]; then
    echo "❌ FAIL: $nx NX-violation #PF detected"
    rc=1
fi
if [ "$cpu_reset" -gt 0 ]; then
    echo "❌ FAIL: $cpu_reset CPU reset detected"
    rc=1
fi
if [ "$reached" -ne 1 ]; then
    echo "❌ FAIL: kernel did not complete boot within ${TO}s"
    echo "--- serial tail ---"
    tail -30 "$ser" 2>/dev/null | sed 's/^/    /'
    rc=1
fi

# P0-B VT-1: hard requirements for test-smp truth (no silent skip)
if [ "$online_cpus" -lt "$MIN_CPUS" ]; then
    echo "❌ FAIL: only ${online_cpus} CPU(s) online (need ≥${MIN_CPUS})"
    rc=1
fi
if [ "$smp_online" -eq 0 ]; then
    echo "❌ FAIL: smp_online did not PASS (need multi-CPU topology)"
    rc=1
fi
if [ "$r175_tests" -lt "$MIN_R175" ]; then
    echo "❌ FAIL: only ${r175_tests}/${MIN_R175} r175_d0_cross_* tests PASSED"
    rc=1
fi
# P1-B / RF178-33: dedicated scheduler SMP gate must PASS on real multi-CPU
if [ "$rf178_33" -eq 0 ]; then
    echo "❌ FAIL: rf178_33_sched_smp_gate did not PASS"
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo ""
    echo "✅ SMP-TEST OK: ≥${MIN_CPUS} CPUs online, R175 D0-CROSS suite active"
    echo "✅ All ${MIN_R175} R175 D0 fix validation tests PASSED on 2-core SMP"
    echo "✅ RF178-33 scheduler SMP gate PASSED"
fi

exit "$rc"
