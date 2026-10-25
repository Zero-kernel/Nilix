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
# is inapplicable here: legs end tasks with deliberate faults (the stack guard
# page leg's SIGSEGV), and the kernel traces every such unresolved fault with
# `[PF ENTRY]` (a debug kernel traces handled demand faults too). This gate
# therefore reuses the boot harness for everything mechanical (firmware, ESP,
# artifacts, QEMU invocation) and applies the fault-tolerant verdict the same
# way `scripts/gates/qemu/open_fault_probe.py` does for the musl workload:
# require terminal fault outcomes and clean completion instead of the absence of
# handled faults.
#
# Exit: 0 = oracle passed, 1 = failed, 2 = blocked, 3 = qualified (migration skipped).
set -u

ROOT="$(dirname "$(dirname "$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")")")"
ESP="${1:-$ROOT/esp}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

# Terminal fault outcomes only. Deliberately omits `[PF ENTRY]`; see above.
FATAL='KERNEL PANIC|panicked at|PANIC:|\[(PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL)\]|triple fault'

BOOT_LOG="$(mktemp)" || exit 2
trap 'rm -f -- "$BOOT_LOG"' EXIT

# The boot gate's own status is NOT this gate's verdict: it will report failure
# solely because of those `[PF ENTRY]` lines. Everything mechanical is
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
R192 identity map: user address spaces carry none; the low 4 GiB faults, maps and grows like free memory; user buffers still copy
mremap grow-in-place + shrink
mremap MREMAP_MAYMOVE relocation
mremap fail-closed shape matrix
mremap on a PROT_NONE reservation
mremap charge symmetry
MAP_SHARED|MAP_ANONYMOUS fork visibility + mremap boundary
shared-anon cross-page usercopy first touch
shared-anon PTE-only preflight accepts lazy buffer
lazy shared buffers pass the getrandom, pipe2, fstat, rt_sigprocmask and futex preflights; read-only, PROT_NONE and unmapped buffers stay EFAULT
the syscall preflight maps frames a fork child filled and keeps the words in front of the buffers
shared-anon adjacent private PT lifetime
waitid argument contract, WNOWAIT survival, EFAULT-before-reap, P_ALL
root-init adopts an orphaned grandchild and can reap it
selective wait reaps only its target across sibling and nested zombies
fork refused by pids.max leaves no child, task charge or reapable zombie
user stack guard page faults while the lazy region above it grows
CLONE_CHILD_CLEARTID clears a .bss tid word at exit
tkill and tgkill reach exactly the named task
a spinner killed at a timer interrupt is reaped while another spinner runs
thread groups share identity and files, exit as one and are reaped once
a group whose leader exited is reported when its last thread exits beside a spinner
exec from a thread group ends the other members: from the leader, and from a non-leader while the leader waits, spins or sleeps
a thread group shares its children: any thread waits for them and a dying thread hands them on
procfs lists group leaders and /proc/<pid>/task members with Tgid and Threads
futex requeue moves a sleeping sibling and bitset ops keep the Linux contract
futex WAKE_OP, requeue, partial bitsets and CLONE_VM keys match Linux
futex PI: user-space CAS fast path, kernel take-over and EDEADLK/EPERM/ESRCH contracts
futex PI: UNLOCK_PI hands the lock to the oldest waiter as tid|FUTEX_WAITERS; TRYLOCK_PI is EAGAIN while it is held
futex PI: a dead robust owner leaves OWNER_DIED and its waiter inherits the lock
futex PI: CMP_REQUEUE_PI wakes one waiter as owner and requeues one that is later handed the lock
futex PI: LOCK_PI and UNLOCK_PI update a copy-on-write word after a fork
futex PI: a handler signal does not end LOCK_PI, which returns 0 owning the lock
futex PI: a dead non-robust owner hands the lock to its waiter with OWNER_DIED
futex PI: a word naming a task of another address space is EPERM for LOCK_PI and CMP_REQUEUE_PI; a CLONE_VM owner still attaches
/proc/schedstat reports per-CPU switches and migrations and the RCU backlog
LSM denial and missing-subject arms fail closed at exec, kill, get_robust_list, mmap, mprotect and fstat
mmap: an unusable hint is placed elsewhere, MAP_FIXED_NOREPLACE maps exactly or refuses without replacing, MAP_FIXED stays rejected
R192-RES-2: 64 MiB brk, mmap, mprotect and mremap populate in bounded holds; an injected failure rolls back to the baseline charge
mremap relocation keeps the moved frames: relocated data survives a 32 MiB allocation
KPTI: ring 3 uses mappings in fresh 512 GiB slots made by mmap, mprotect and a shared first touch; the kernel and a fork child see them
LEGS

# 3. No leg reported a failure, and the suite ran to completion.
if grep -Eq '^\[FAIL\]' "$serial"; then
    report_fail "the guest reported a failing leg"
fi
# LEAD-KPTI-PML4-1: the mirror resyncs a KPTI user root that diverged from its
# kernel root and says so; on a correct kernel that never happens (a ring-3
# fault that built tables in the user root only would show up here).
if grep -q 'KPTI user root .* diverged' "$serial"; then
    report_fail "a KPTI user root diverged from its kernel root"
fi
if ! grep -Eq '^  Results: [0-9]+ passed, 0 failed$' "$serial"; then
    report_fail "missing or non-zero 'Results: N passed, 0 failed' summary"
fi
if ! grep -Eq '^Process 1 terminated with exit code 0$' "$serial"; then
    report_fail "PID 1 did not exit 0"
fi

# 4. ST-K2-P2a: the syscall preflight resolves a lazy shared buffer. Exactly
# one PASS (getrandom returned the full page) and no leftover SKIP from the
# pre-repair probe, so a duplicated or reverted probe cannot go unnoticed.
preflight_skip=$(grep -cF '[SKIP] shared-anon PTE-only preflight' "$serial" || true)
preflight_pass=$(grep -cF '[PASS] shared-anon PTE-only preflight accepts lazy buffer' "$serial" || true)
if [ "$preflight_pass" -ne 1 ] || [ "$preflight_skip" -ne 0 ]; then
    report_fail "expected exactly one lazy-buffer preflight PASS and no SKIP, saw pass=$preflight_pass skip=$preflight_skip"
fi

# 5. Force exactly one shared Busy return from a guarded usercopy fault. This
# proves the saved-IF=0 retry path ran; it does not claim remote CPU contention.
forced_busy=$(grep -cF 'ST-K2-FORCED-BUSY-USERCOPY-IF0' "$serial" || true)
if [ "$forced_busy" -ne 1 ]; then
    report_fail "expected exactly one forced Busy/saved-IF=0 usercopy oracle marker, saw $forced_busy"
fi
if [ "$(grep -cFx 'ST-K2-LAST-REGION-RELEASE PASS: refs=0 frames=1 charge=0' "$serial" || true)" -ne 1 ]; then
    report_fail "missing or duplicate exact last-region-release oracle"
fi

# 6. R192-RES-2: every eager population site ran in page-table holds of at most
# 64 pages (each 64 MiB population reports its largest hold), the boot-armed
# injected failure rolled back with no surviving table, the retry that stages
# no spare tables took them through the starvation path, and no population
# leaked a data frame. Markers are matched
# unanchored: guest output can share their line.
for site in brk mmap mprotect mremap; do
    if ! grep -Eq "R192-RES-2 populate site=$site pages=[0-9]+ holds=[0-9]+ max_pages_per_hold=64 result=ok " "$serial"; then
        report_fail "missing R192-RES-2 bounded-population marker for $site"
    fi
done
injected=$(grep -cE 'R192-RES-2 populate site=mmap pages=16387 holds=[0-9]+ max_pages_per_hold=64 result=enomem pruned=[0-9]+ survivors=0([^0-9]|$)' "$serial" || true)
if [ "$injected" -ne 1 ]; then
    report_fail "expected exactly one injected population rollback with survivors=0, saw $injected"
fi
starved=$(grep -cE 'R192-RES-2 populate site=mmap pages=16387 holds=[0-9]+ max_pages_per_hold=64 result=ok pruned=0 survivors=0 leaked=0 starved=[1-9][0-9]*([^0-9]|$)' "$serial" || true)
if [ "$starved" -ne 1 ]; then
    report_fail "expected exactly one population through the starvation path, saw $starved"
fi
largest=$(grep -oE 'R192-RES-2 populate .*max_pages_per_hold=[0-9]+' "$serial" | sed 's/.*max_pages_per_hold=//' | sort -n | tail -1)
if [ -n "$largest" ] && [ "$largest" -gt 64 ]; then
    report_fail "a population hold touched $largest pages (bound 64)"
fi
# Every data frame a population allocated is mapped on success and freed after
# a rollback: no marker may report a leaked frame (or lack the count).
markers=$(grep -cE 'R192-RES-2 populate ' "$serial" || true)
clean=$(grep -cE 'R192-RES-2 populate .* leaked=0([^0-9]|$)' "$serial" || true)
if [ "$markers" -ne "$clean" ]; then
    report_fail "population markers with a leaked data frame or no leak count: $((markers - clean)) of $markers"
fi

if [ "$fail" -ne 0 ]; then
    echo "RING3-MM FAIL"
    echo "RING3-MM ARTIFACTS: serial=$serial"
    echo "--- serial tail ---"
    tail -25 "$serial" 2>/dev/null | sed 's/^/    /'
    exit 1
fi

if grep -Fq '[SKIP] shared-anon migration: requires host-root fixture' "$serial"; then
    echo "RING3-MM QUALIFIED: executed memory legs passed; cgroup migration not executed"
    echo "RING3-MM ARTIFACTS: serial=$serial"
    exit 3
fi
if ! grep -Fq '[PASS] shared-anon cgroup ownership across migration' "$serial"; then
    echo "RING3-MM BLOCKED: missing migration verdict"
    exit 2
fi
echo "RING3-MM OK: Ring-3 memory-management oracle passed (boot harness status was $boot_status)"
echo "RING3-MM ARTIFACTS: serial=$serial"
exit 0
