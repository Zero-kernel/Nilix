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
# RF180-52 FIX: match the two-core gate's bounded R180 boot window while
# retaining the stricter four-CPU topology checks below.
TO="${SMP_4CORE_TEST_TIMEOUT:-60}"
if [[ ! "$TO" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ ]]; then
    echo "SMP-TEST FAIL: SMP_4CORE_TEST_TIMEOUT must be an integer from 1 to 120"
    exit 2
fi
MIN_CPUS=4
MIN_R175=3
EXPECTED_READY_SUMMARY='[SMP] process-deferred gate complete: 3/3 APs acknowledged'

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
qemuerr="$(mktemp)"
timeoutlog="$(mktemp)"
keep_logs="${SMP_4CORE_TEST_KEEP_LOGS:-0}"
ordered_completion_seen() {
    awk -v summary="$EXPECTED_READY_SUMMARY" '
        $0 == summary { gate = 1; next }
        gate && $0 == "Process 1 exited with code 0" { complete = 1; exit }
        END { exit(complete ? 0 : 1) }
    ' "$ser"
}
cleanup() {
    if [ "$keep_logs" = 1 ]; then
        echo "SMP-4CORE-TEST ARTIFACTS: serial=$ser intlog=$intlog qemuerr=$qemuerr timeoutlog=$timeoutlog"
    else
        rm -f "$ser" "$intlog" "$qemuerr" "$timeoutlog"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

echo "=== Running 4-Core SMP Stress Test ==="
echo "Kernel: $ESP/kernel.elf"
echo "Configuration: 4 CPUs, 512MB RAM"
echo "Timeout: ${TO}s"
echo ""

# RF180-57 FIX: GNU timeout owns, terminates, and reaps QEMU synchronously.
# Waiting for the full bounded window preserves late-fault coverage without
# duplicating a numeric-PID process supervisor in this test harness.
LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$TO" \
    bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -smp 4 \
    -m 512M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>"$timeoutlog"
qemu_status=$?
timeout_events=$(grep -acF 'timeout: sending signal TERM to command' "$timeoutlog" 2>/dev/null)
timeout_events=${timeout_events:-0}
kill_events=$(grep -acF 'timeout: sending signal KILL to command' "$timeoutlog" 2>/dev/null)
kill_events=${kill_events:-0}

# RF180-54: require the later runtime marker plus the exact BSP-owned summary;
# `Test Summary` alone is too early and previously let a late AP #PF pass.
reached=0
if ordered_completion_seen; then
    reached=1
fi
unexpected_exit=0
if [ "$qemu_status" -ne 124 ] || [ "$timeout_events" -ne 1 ] || [ "$kill_events" -ne 0 ]; then
    unexpected_exit=1
fi

# Extract results
nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null)
nx=${nx:-0}
cpu_reset=$(grep -c 'cpu_reset' "$intlog" 2>/dev/null)
cpu_reset=${cpu_reset:-0}
supervisor_faults=$(grep -cE '\[PF ENTRY\]|\[PAGE FAULT\]|\[DOUBLE FAULT\]|triple fault|Triple fault|KERNEL PANIC' "$ser" 2>/dev/null)
supervisor_faults=${supervisor_faults:-0}
ready_summary=$(grep -xcF "$EXPECTED_READY_SUMMARY" "$ser" 2>/dev/null)
ready_summary=${ready_summary:-0}
pid1_exits=$(grep -xcF 'Process 1 exited with code 0' "$ser" 2>/dev/null)
pid1_exits=${pid1_exits:-0}
# RF180-56 FIX: include fatal exceptions raised in the fixed low-memory AP
# trampoline (0x8000-0x8fff) before control reaches high-half Rust code. The
# CPL0/kernel-CS restriction continues to exclude unrelated UEFI exceptions.
fatal_exceptions=$(grep -acE '^[[:space:]]*[0-9]+: v=(06|08|0d|0e) .*cpl=0 IP=0008:(ffffffff[[:xdigit:]]{8}|0000000000008[[:xdigit:]]{3})|[Tt]riple fault' "$intlog" 2>/dev/null)
fatal_exceptions=${fatal_exceptions:-0}

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
echo "Parsed: online_cpus=${online_cpus} deferred_summary=${ready_summary}/1 pid1_exit=${pid1_exits}/1 qemu_exceptions=${fatal_exceptions} smp_online_PASS=${smp_online} r175_d0_cross_PASS=${r175_tests}"
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
if [ "$supervisor_faults" -gt 0 ]; then
    echo "FAIL: $supervisor_faults supervisor fault marker(s) detected"
    rc=1
fi
if [ "$fatal_exceptions" -gt 0 ]; then
    echo "FAIL: $fatal_exceptions fatal CPU exception(s) detected in QEMU interrupt log"
    rc=1
fi
if [ "$unexpected_exit" -ne 0 ]; then
    echo "FAIL: QEMU timeout contract failed (status=${qemu_status}, TERM=${timeout_events}/1, KILL=${kill_events}/0)"
    echo "--- timeout stderr ---"
    tail -20 "$timeoutlog" 2>/dev/null | sed 's/^/    /'
    echo "--- QEMU stderr ---"
    tail -20 "$qemuerr" 2>/dev/null | sed 's/^/    /'
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
if [ "$ready_summary" -ne 1 ]; then
    echo "FAIL: expected exactly one BSP deferred-gate summary: $EXPECTED_READY_SUMMARY"
    rc=1
fi
if [ "$pid1_exits" -ne 1 ]; then
    echo "FAIL: expected exactly one post-gate 'Process 1 exited with code 0' marker"
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
