#!/bin/bash
# ============================================================================
# Zero-OS 4-Core SMP Stress Test
# ============================================================================
# P0-B VT-1: silent skip is a defect. This harness FAILS when:
#   - smp_online does not PASS
#   - fewer than 3 r175_d0_cross_* tests PASS
#   - fewer than 4 CPUs are reported online
# ============================================================================
set -u

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU=qemu-system-x86_64
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TO=30
MIN_CPUS=4
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

echo "=== Running 4-Core SMP Stress Test ==="
echo "Kernel: $ESP/kernel.elf"
echo "Configuration: 4 CPUs, 512MB RAM"
echo "Timeout: ${TO}s"
echo ""

# Boot with 4 CPUs
timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -smp 4 \
    -m 512M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Wait for boot
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

# Extract results
nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null)
nx=${nx:-0}
cpu_reset=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null)
cpu_reset=${cpu_reset:-0}

smp_online=$(grep -cE 'smp_online.*PASS' "$ser" 2>/dev/null)
smp_online=${smp_online:-0}
r175_tests=$(grep -cE 'r175_d0_cross_.*PASS' "$ser" 2>/dev/null)
r175_tests=${r175_tests:-0}

online_cpus=$(grep -oE '[0-9]+ CPU\(s\) online' "$ser" 2>/dev/null | head -1 | grep -oE '^[0-9]+' || true)
if [ -z "${online_cpus:-}" ]; then
    online_cpus=$(grep -oE 'SMP enabled: [0-9]+' "$ser" 2>/dev/null | head -1 | grep -oE '[0-9]+$' || true)
fi
online_cpus=${online_cpus:-0}

echo "=== Test Results ==="
echo "CPUs Online (parsed): ${online_cpus}"
echo ""
grep -E 'smp_online|SMP enabled|Spectre mitigation floor' "$ser" 2>/dev/null | head -10
echo ""
grep -E 'r175_d0_cross' "$ser" 2>/dev/null
echo ""
grep 'Test Summary' "$ser" 2>/dev/null
echo ""
echo "Parsed: online_cpus=${online_cpus} smp_online_PASS=${smp_online} r175_d0_cross_PASS=${r175_tests}"
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

# P0-B VT-1: hard requirements for 4-core truth
if [ "$online_cpus" -lt "$MIN_CPUS" ]; then
    echo "❌ FAIL: only ${online_cpus} CPU(s) online (need ≥${MIN_CPUS})"
    rc=1
fi
if [ "$smp_online" -eq 0 ]; then
    echo "❌ FAIL: smp_online did not PASS"
    rc=1
fi
if [ "$r175_tests" -lt "$MIN_R175" ]; then
    echo "❌ FAIL: only ${r175_tests}/${MIN_R175} r175_d0_cross_* tests PASSED"
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo ""
    echo "✅ 4-CORE SMP-TEST OK: ${MIN_CPUS} CPUs online, R175 D0-CROSS suite active"
    echo "✅ All ${MIN_R175} R175 D0 fix validation tests PASSED on 4-core SMP"
fi

exit "$rc"
