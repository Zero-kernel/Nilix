#!/bin/bash
# ============================================================================
# Zero-OS kernel runtime suite gate  (P1-C VT-2 / Gate #4 — make test truth)
# ============================================================================
# Unlike the historical `make test` one-liner (`timeout 10 qemu ... || true`),
# which ALWAYS exited 0 even on boot hangs / panics / suite failures, this
# script's exit code reflects REAL runtime-suite health.
#
# It boots the default `make build` ESP under QEMU and asserts ALL of:
#
#   1. the kernel emits a parseable Test Summary line
#        `=== Test Summary: N passed, M deferred (...), K failed ===`
#      (KEEP IN SYNC with kernel/src/runtime_tests.rs).
#   2. K (failed) == 0.
#   3. NO `KERNEL PANIC` on serial.
#   4. NO NX-violation instruction-fetch #PF (`v=0e e=0011` in the QEMU
#      `-d int` log — D1-BOOT-NX-KASLR-LAYOUT signature).
#
# Deferred/warning counts are informational only — they do NOT fail the gate
# (the suite intentionally carries placeholders awaiting syscall infrastructure).
#
# Exit polarity (RV-8 / Gate #4):
#   0 = PASS     — summary present, failed==0, no panic, no NX
#   1 = FAILED   — suite executed with defect (failed>0) OR panic OR NX
#   2 = NOT-RUN / BLOCKED — missing OVMF/kernel.elf/qemu OR no summary
#                           within the budget without definitive FAIL evidence
#
# Process lesson (D1 + musl_check): health is read from serial + intlog, NEVER
# from the QEMU exit code (`-no-reboot -no-shutdown` makes timeout the normal
# end of a healthy run).
#
# Usage:   bash scripts/kernel_test.sh [esp_dir]
# Env:     OVMF_PATH (autodetect fallback if unset)
#          KERNEL_TEST_TIMEOUT seconds (default 45)
#          KERNEL_TEST_DISK optional Ext3/JBD2 image; when set, the mounted
#          production-journal probe marker becomes a mandatory gate condition
# ============================================================================
set -u

# Resolve the repo root from this script's own location so it runs from any
# working directory (CI, the remote build host, a fresh clone) without a `cd`.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"

QEMU=qemu-system-x86_64
# ESP defaults to <repo>/esp; a relative override is resolved against the repo root
# (so `bash scripts/kernel_test.sh esp` works the same from anywhere), absolute kept.
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Default 45s: remote calibration shows the full runtime suite + Ring-3 exit
# lands under ~35s; 45s leaves CI/load margin without making NOT-RUN ambiguous
# forever. Override with KERNEL_TEST_TIMEOUT for slow hosts.
TO="${KERNEL_TEST_TIMEOUT:-45}"

# KEEP IN SYNC with kernel/src/runtime_tests.rs summary emitter.
# Strict form matches the current klog line exactly; loose form tolerates minor
# deferred-clause wording drift while still requiring three integer fields.
SUMMARY_RE_STRICT='=== Test Summary: ([0-9]+) passed, ([0-9]+) deferred \(awaiting syscall infrastructure\), ([0-9]+) failed ==='
SUMMARY_RE_LOOSE='Test Summary: ([0-9]+) passed, ([0-9]+) deferred[^,]*, ([0-9]+) failed'
PANIC_MARKER='KERNEL PANIC'
# Exact D1 NX signature (musl_check form). Bare `e=0011` is weaker and can
# false-match unrelated exceptions.
NX_RE='v=0e e=0011'
CPU_RESET_RE='cpu[_ ]reset|CPU Reset'
SUITE_START_MARKER='=== Runtime Functional Tests ==='
JOURNAL_PROBE_MARKER='R180-6 production JBD2 write path passed'

# OVMF firmware autodetect (prefers explicit OVMF_PATH, else mirrors the
# Makefile OVMF_PATH search order including the OVMF_CODE*.fd fallback).
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
        echo "KERNEL-TEST BLOCKED: OVMF firmware not found (set OVMF_PATH)"
        exit 2
    fi
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "KERNEL-TEST BLOCKED: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "KERNEL-TEST BLOCKED: $QEMU not found in PATH"
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

echo "=== Kernel Runtime Suite Gate (P1-C VT-2) ==="
echo "Kernel:  $ESP/kernel.elf"
echo "OVMF:    $OVMF"
echo "Timeout: ${TO}s"
echo ""

disk_args=()
journal_probe_required=0
if [[ -n "${KERNEL_TEST_DISK:-}" ]]; then
    case "$KERNEL_TEST_DISK" in /*) ;; *) KERNEL_TEST_DISK="$ROOT/$KERNEL_TEST_DISK" ;; esac
    if [[ ! -f "$KERNEL_TEST_DISK" ]]; then
        echo "KERNEL-TEST BLOCKED: journaled test disk not found: $KERNEL_TEST_DISK"
        exit 2
    fi
    journal_probe_required=1
    disk_args=(
        -drive "if=none,file=$KERNEL_TEST_DISK,format=raw,id=vdisk0,cache=writeback,discard=unmap"
        -device virtio-blk-pci,drive=vdisk0
    )
    echo "Disk:     $KERNEL_TEST_DISK (Ext3/JBD2 gate)"
fi

# Same proven health surface as boot_check / musl_check:
# -display none + serial-to-file (never trust -nographic stdio alone)
# -d int,cpu_reset for the NX signature without changing guest layout
# single-core (SMP is test-smp's job)
# D1-ISO: user-mode virtio-net (same device the run* targets attach, romfile=
# suppresses the PXE option ROM) so the net_ns_tx_isolation runtime test can
# exercise its driver-reach legs — without it eth0 never registers and the
# TX device-ownership gate is only Warning-covered. restrict=on isolates the
# guest from ALL external networking (slirp accepts + drops egress, so virtio
# descriptor completion still works); ipv6=off silences unsolicited RA noise.
timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    "${disk_args[@]}" \
    -netdev user,id=net0,restrict=on,ipv6=off \
    -device virtio-net-pci,netdev=net0,romfile= \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Full-window observation (musl_check lesson): do NOT kill at first summary.
# A panic during post-suite teardown can land AFTER the summary line; early-stop
# would open a false-pass window. Break early ONLY on panic (terminal) or if
# QEMU dies; otherwise let timeout end the guest and re-grep the FINAL logs.
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

# --- Evaluate FINAL logs only (do not trust poll flags alone) ---
has_panic=0
grep -Fq "$PANIC_MARKER" "$ser" 2>/dev/null && has_panic=1

nx=$(grep -cF "$NX_RE" "$intlog" 2>/dev/null)
nx=${nx:-0}
resets=$(grep -ciE "$CPU_RESET_RE" "$intlog" 2>/dev/null)
resets=${resets:-0}

has_suite_start=0
grep -Fq "$SUITE_START_MARKER" "$ser" 2>/dev/null && has_suite_start=1

journal_probe_passed=0
grep -Fq "$JOURNAL_PROBE_MARKER" "$ser" 2>/dev/null && journal_probe_passed=1

# Prefer the LAST matching summary line if multiple appear.
summary_line=""
if summary_line=$(grep -E "$SUMMARY_RE_STRICT" "$ser" 2>/dev/null | tail -n 1); then
    :
elif summary_line=$(grep -E "$SUMMARY_RE_LOOSE" "$ser" 2>/dev/null | tail -n 1); then
    :
else
    summary_line=""
fi

passed=""
deferred=""
failed=""
has_summary=0
if [ -n "$summary_line" ]; then
    # Extract the three integers in order of appearance.
    # shellcheck disable=SC2001
    nums=$(echo "$summary_line" | sed -E 's/.*Test Summary: ([0-9]+) passed, ([0-9]+) deferred[^,]*, ([0-9]+) failed.*/\1 \2 \3/')
    # Validate parse produced exactly three integers.
    if echo "$nums" | grep -qE '^[0-9]+ [0-9]+ [0-9]+$'; then
        # shellcheck disable=SC2086
        set -- $nums
        passed=$1
        deferred=$2
        failed=$3
        has_summary=1
    else
        summary_line=""
        has_summary=0
    fi
fi

echo "=== Parsed Results ==="
if [ "$has_summary" -eq 1 ]; then
    echo "Summary: passed=${passed} deferred=${deferred} failed=${failed}"
    echo "  line: $summary_line"
else
    echo "Summary: MISSING (no parseable Test Summary within ${TO}s)"
fi
echo "Panic:   $has_panic"
echo "NX #PF:  $nx (signature '$NX_RE')"
echo "Suite:   start_marker=${has_suite_start}"
if [ "$journal_probe_required" -eq 1 ]; then
    echo "Ext3:    journal_probe=${journal_probe_passed}"
fi
if [ "$resets" -gt 0 ]; then
    echo "INFO:    intlog contains $resets cpu_reset marker(s) (not hard-gated)"
fi
echo ""

# --- Classify (RV-8): definitive FAIL first, then NOT-RUN, else PASS ---
rc=0
class="PASS"

if [ "$has_panic" -eq 1 ]; then
    echo "KERNEL-TEST FAIL: kernel panic observed on serial"
    rc=1
    class="FAILED"
fi
if [ "$nx" -gt 0 ]; then
    echo "KERNEL-TEST FAIL: $nx NX-violation #PF (D1 signature '$NX_RE')"
    grep -m1 -F "$NX_RE" "$intlog" 2>/dev/null | sed 's/^/    /'
    rc=1
    class="FAILED"
fi
if [ "$has_summary" -eq 1 ] && [ "$failed" -gt 0 ]; then
    echo "KERNEL-TEST FAIL: runtime suite reported ${failed} failed test(s)"
    rc=1
    class="FAILED"
fi
if [ "$journal_probe_required" -eq 1 ] \
    && [ "$has_summary" -eq 1 ] \
    && [ "$journal_probe_passed" -ne 1 ]; then
    echo "KERNEL-TEST FAIL: attached Ext3 image did not complete the production JBD2 write probe"
    rc=1
    class="FAILED"
fi

# Incomplete only if no definitive FAIL evidence yet.
if [ "$rc" -eq 0 ] && [ "$has_summary" -ne 1 ]; then
    echo "KERNEL-TEST NOT-RUN: no parseable Test Summary within ${TO}s"
    if [ "$has_suite_start" -eq 1 ]; then
        echo "    => suite started but did not finish scoring (budget / hang mid-suite)"
    else
        echo "    => no suite-start marker either (firmware stall, wrong image, or pre-suite hang)"
    fi
    rc=2
    class="NOT-RUN"
fi

if [ "$rc" -ne 0 ]; then
    echo "--- serial tail ---"
    tail -40 "$ser" 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "KERNEL-TEST ${class} (exit ${rc})"
else
    echo "KERNEL-TEST OK: Test Summary present, failed=0, 0 panic, 0 NX (passed=${passed}, deferred=${deferred})"
fi

exit "$rc"
