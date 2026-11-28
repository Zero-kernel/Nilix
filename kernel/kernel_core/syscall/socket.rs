//! Syscall family module: `net` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// Socket Wait Hooks Implementation (scheduler integration for net crate)
// ============================================================================

// D1-RES R2: SocketWaiters is now a fixed `.bss` slot array (below) — no BTreeMap.

/// D1-RES R2: the SocketWaiters registry is a FIXED, preallocated flat array of
/// `WAITER_REGISTRY_MAX_ENTRIES` slots living in `.bss` (inside the static
/// `SOCKET_WAITERS`), so it consumes ZERO heap and performs ZERO allocation under
/// the SOCKET_WAITERS spinlock — eliminating BOTH the unledgered-heap residual and
/// the alloc-under-spinlock hard-rule tension that the prior
/// `BTreeMap<_, VecDeque<_>>` carried (it allocated a node + deque per new waiter
/// under the lock, and an OOM there hit the alloc-error path on a recoverable
/// path). All operations are linear scans over the fixed slot array (<= 96 entries
/// → trivial, bounded cost); FIFO wake order is preserved via a per-slot sequence.
pub(super) const SOCKET_WAITER_SLOTS: usize = WAITER_REGISTRY_MAX_ENTRIES;

/// One fixed slot in the flat SocketWaiters registry. `Copy` so the whole array is
/// a const-initializable `.bss` value with no heap backing.
#[derive(Clone, Copy)]
pub(super) struct SocketWaiterSlot {
    pub(super) occupied: bool,
    pub(super) queue_addr: usize,
    pub(super) pid: ProcessId,
    pub(super) generation: u64,
    pub(super) deadline: Option<u64>,
    /// Monotonic insertion order, for FIFO wake within a queue.
    pub(super) seq: u64,
}

impl SocketWaiterSlot {
    const EMPTY: SocketWaiterSlot = SocketWaiterSlot {
        occupied: false,
        queue_addr: 0,
        pid: 0,
        generation: 0,
        deadline: None,
        seq: 0,
    };
}

/// Per-queue waiter tracking for socket blocking operations (flat `.bss` registry).
///
/// Uses the WaitQueue address as the queue identifier. Waiters on the same queue
/// are woken in FIFO order (lowest `seq` first). D1-RES R2: a fixed slot array — no
/// heap, no allocation under the lock; `add_or_refresh_waiter` returns `false` when
/// every slot is occupied (the sole registration site maps that to a spurious
/// `Woken`, a safe bounded degradation, never a lost wakeup).
pub(super) struct SocketWaiters {
    pub(super) slots: [SocketWaiterSlot; SOCKET_WAITER_SLOTS],
    /// Monotonic generation counter, advanced on each `wait()` registration.
    /// All access is under the `SOCKET_WAITERS` lock, so a plain counter suffices.
    pub(super) next_generation: u64,
    /// Monotonic insertion sequence, for FIFO wake ordering within a queue.
    pub(super) next_seq: u64,
}

impl SocketWaiters {
    pub(super) const fn new() -> Self {
        SocketWaiters {
            slots: [SocketWaiterSlot::EMPTY; SOCKET_WAITER_SLOTS],
            next_generation: 1,
            next_seq: 1,
        }
    }

    /// R165-9 FIX: Allocate a fresh, unique generation for a `wait()` call.
    pub(super) fn alloc_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        generation
    }

    /// Add the current process to a wait queue, or refresh its generation and
    /// deadline if it is already queued.
    ///
    /// R165-9 FIX: on a duplicate (spurious re-entry of `wait()` for the same PID)
    /// we REFRESH the existing slot's generation/deadline (keeping its FIFO seq), so
    /// a subsequent timeout is attributed to the current wait and a legitimate
    /// timeout is never dropped (mirrors sync.rs R165-4).
    ///
    /// D1-RES R2: returns `false` when every slot is occupied — a fixed-array
    /// refusal with NO allocation. The sole registration site maps `false` to a
    /// spurious `Woken` (after yielding) BEFORE any Blocked publish (a safe bounded
    /// degradation, never a lost wakeup).
    pub(super) fn add_or_refresh_waiter(
        &mut self,
        queue_addr: usize,
        pid: ProcessId,
        generation: u64,
        deadline: Option<u64>,
    ) -> bool {
        // REFRESH arm: an existing (queue,pid) slot keeps its FIFO seq; only gen +
        // deadline are updated. Never consumes a new slot.
        for slot in self.slots.iter_mut() {
            if slot.occupied && slot.queue_addr == queue_addr && slot.pid == pid {
                slot.generation = generation;
                slot.deadline = deadline;
                return true;
            }
        }
        // NEW-entry arm: claim the first free slot. If none, the registry is full
        // (bounded by SOCKET_WAITER_SLOTS) → refuse WITHOUT allocating anything.
        let seq = self.next_seq;
        for slot in self.slots.iter_mut() {
            if !slot.occupied {
                *slot = SocketWaiterSlot {
                    occupied: true,
                    queue_addr,
                    pid,
                    generation,
                    deadline,
                    seq,
                };
                self.next_seq = self.next_seq.wrapping_add(1);
                return true;
            }
        }
        false
    }

    /// D1-RES R2: total occupied slots. Trivial fixed-array scan; no heap, no
    /// shadow counter that could desync.
    pub(super) fn total_entries(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied).count()
    }

    /// Remove a specific process from a queue (on wakeup or timeout).
    ///
    /// R165-9 FIX: when `expected` is `Some(gen)`, only the slot whose generation
    /// matches is cleared — a newer wait by the same PID is left intact. Returns
    /// true iff a slot was cleared.
    pub(super) fn remove_waiter(
        &mut self,
        queue_addr: usize,
        pid: ProcessId,
        expected: Option<u64>,
    ) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.occupied
                && slot.queue_addr == queue_addr
                && slot.pid == pid
                && expected.map_or(true, |e| slot.generation == e)
            {
                slot.occupied = false;
                return true;
            }
        }
        false
    }

    // M4-1b: `mark_timed_out` / `consume_timeout` (which mutated the deleted
    // `timed_out` BTreeMap) are removed. The timeout marker now lives per-PCB in
    // `Process.socket_timeout_marker`: SET inline (under the proc lock, gated on a
    // successful exact-(pid,gen) `remove_waiter`) or from the timer IRQ in
    // `check_timeouts`, and CONSUMED by the wait epilogue via
    // `process::consume_socket_timeout` (exact-generation, swap-to-clear).

    /// Wake one waiter from a queue (FIFO order — lowest insertion seq first).
    pub(super) fn wake_one(&mut self, queue_addr: usize) -> Option<ProcessId> {
        loop {
            // Find the lowest-seq occupied slot for this queue (FIFO front).
            let mut best: Option<usize> = None;
            let mut best_seq = u64::MAX;
            for (i, slot) in self.slots.iter().enumerate() {
                if slot.occupied && slot.queue_addr == queue_addr && slot.seq < best_seq {
                    best_seq = slot.seq;
                    best = Some(i);
                }
            }
            let i = best?;
            let pid = self.slots[i].pid;
            // Consume this slot regardless (matches the old pop_front: a woken OR an
            // invalid front entry is removed) — then try to ready the process.
            self.slots[i].occupied = false;
            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.enter_ready_at(crate::get_ticks());
                    return Some(pid);
                }
            }
            // Process gone or not blocked — discard and try the next-oldest.
        }
    }

    /// Wake all waiters from a queue.
    pub(super) fn wake_all(&mut self, queue_addr: usize) -> usize {
        let mut woken = 0;
        for slot in self.slots.iter_mut() {
            if slot.occupied && slot.queue_addr == queue_addr {
                let pid = slot.pid;
                slot.occupied = false;
                if let Some(proc_arc) = get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.enter_ready_at(crate::get_ticks());
                        woken += 1;
                    }
                }
            }
        }
        woken
    }

    /// Check and wake timed-out waiters. Called from the timer interrupt.
    ///
    /// Also cleans up waiters for processes that have exited. D1-RES R2: with the
    /// flat `.bss` slot array, clearing a slot is an in-place write — there is no
    /// BTreeMap node to free, so the former M4-1c deferred-reap machinery is gone.
    /// Index iteration lets us act (clear) in place during the single scan.
    pub(super) fn check_timeouts(&mut self, current_ticks: u64) {
        // Cap the wakes per tick to bound time spent in the IRQ.
        const MAX_TIMEOUTS_PER_TICK: usize = 16;
        let mut count = 0;

        for i in 0..self.slots.len() {
            if count >= MAX_TIMEOUTS_PER_TICK {
                break; // remaining caught on the next tick
            }
            if !self.slots[i].occupied {
                continue;
            }
            let pid = self.slots[i].pid;
            let generation = self.slots[i].generation;
            let deadline = self.slots[i].deadline;
            let is_timeout = deadline.map(|dl| current_ticks >= dl).unwrap_or(false);
            // R171-G5-1: tri-state try_get_process — NEVER block PROCESS_TABLE in IRQ.
            // A contended table (None) is NOT "exited": leave the slot, retry next tick.
            let tri = try_get_process(pid);
            let is_exited = matches!(tri, Some(None));
            if !(is_timeout || is_exited) {
                continue;
            }
            match tri {
                None => continue, // contended table — defer this slot
                // Process gone — clear membership; set NO marker (R155-12).
                Some(None) => {
                    self.slots[i].occupied = false;
                    count += 1;
                }
                Some(Some(proc_arc)) => {
                    // R155-2: try_lock BEFORE clearing. Contended → leave the slot.
                    if let Some(mut proc) = proc_arc.try_lock() {
                        if proc.state == ProcessState::Blocked {
                            // M4-1b: SET the per-PCB timeout marker (Release) STRICTLY
                            // BEFORE state=Ready, both inside THIS held proc-lock
                            // critical section — the proc-lock release/acquire hand-off
                            // (NOT the atomic's Release) is the marker-before-wake edge
                            // every `state` reader honors. Only on a real timeout that
                            // THIS call transitions to Ready (R165-9); a dead/contended/
                            // already-woken task leaves no stale marker.
                            if is_timeout {
                                proc.socket_timeout_marker.store(
                                    crate::process::pack_timeout_marker(generation),
                                    core::sync::atomic::Ordering::Release,
                                );
                            }
                            proc.enter_ready_at(crate::get_ticks());
                        }
                        // Lock succeeded — clear our exact slot (woken or already-ready).
                        self.slots[i].occupied = false;
                        count += 1;
                    } else {
                        continue; // contended proc lock: retry next tick
                    }
                }
            }
        }
        // D1-RES R2: no deferred node free — a cleared slot is reclaimed in place.
    }

    /// D1-RES R2: with the flat `.bss` slot array there are no BTreeMap nodes to
    /// free, so the former M4-1c deferred reap is a no-op. Retained (returning 0)
    /// only so external callers compile.
    pub(super) fn reap_empty_queues(&mut self) -> usize {
        0
    }

    /// D1-RES R2: no-op (see `reap_empty_queues`). `check_timeouts` no longer sets
    /// SOCKET_WAITER_CLEANUP_PENDING, so `drain_socket_waiter_cleanup`'s fast-path
    /// `load` always short-circuits; the swap here is kept for source compatibility.
    pub(super) fn drain_empty_queues(&mut self) {
        let _ = SOCKET_WAITER_CLEANUP_PENDING.swap(false, AtomicOrdering::AcqRel);
    }
}

/// Global socket waiter tracking.
pub(super) static SOCKET_WAITERS: spin::Mutex<SocketWaiters> =
    spin::Mutex::new(SocketWaiters::new());

/// M4-1c: lock-free hint that `check_timeouts` (timer IRQ) emptied at least one wait
/// queue, so `SocketWaiters.waiters` has empty BTreeMap nodes to reap in process
/// context. Set under the SOCKET_WAITERS lock (the IRQ holds it via try_lock); the
/// authoritative clear is the `swap(false)` under the same lock in
/// `drain_empty_queues`. The lock-free `load` in `drain_socket_waiter_cleanup` is
/// only a fast-path hint to avoid touching the hot SOCKET_WAITERS lock on every
/// reschedule when there is nothing to reap.
pub(super) static SOCKET_WAITER_CLEANUP_PENDING: AtomicBool = AtomicBool::new(false);

/// Kernel implementation of SocketWaitHooks trait.
///
/// Provides true blocking waits with scheduler integration and timeout support.
pub struct KernelSocketWaitHooks;

impl net::SocketWaitHooks for KernelSocketWaitHooks {
    fn wait(&self, queue: &net::WaitQueue, timeout_ns: Option<u64>) -> net::WaitOutcome {
        // Get current process
        let pid = match current_pid() {
            Some(p) => p,
            None => return net::WaitOutcome::NoProcess,
        };

        // Calculate deadline in ticks (if timeout specified)
        // Timer tick is 1ms (time::on_timer_tick increments every millisecond)
        // R154-10 FIX: Use checked_add to prevent overflow when user supplies
        // huge timeout values (e.g. u64::MAX). The previous (ns + NS_PER_TICK - 1)
        // expression wraps around for ns > u64::MAX - NS_PER_TICK + 1.
        const NS_PER_TICK: u64 = 1_000_000;
        let deadline = timeout_ns.map(|ns| {
            let current = crate::get_ticks();
            let ticks = ns.checked_add(NS_PER_TICK - 1).unwrap_or(u64::MAX) / NS_PER_TICK; // Round up (overflow-safe)
            current.saturating_add(ticks)
        });

        // Queue address as unique identifier
        let queue_addr = queue as *const _ as usize;

        // Phase 1: Add to wait queue and mark blocked (with interrupts disabled)
        // R152-2 FIX: Consume wake token *after* registering the waiter,
        // while interrupts are disabled and SOCKET_WAITERS is locked.
        // This closes the missed-wakeup race where wake_one() can run between
        // a pre-check and waiter registration.
        let (my_gen, immediate, registry_full) =
            x86_64::instructions::interrupts::without_interrupts(|| {
                let mut waiters = SOCKET_WAITERS.lock();

                // R165-9 FIX: allocate this wait's unique generation under the lock,
                // then register (or, on spurious re-entry for the same PID, refresh
                // the existing entry's generation + deadline to this wait's values).
                let my_gen = waiters.alloc_generation();
                // D1-RES R2: gate NEW registrations at the fixed slot count. On refusal
                // (all slots occupied), signal `registry_full` so the caller YIELDS the
                // CPU before returning a spurious Woken — a non-yielding retry could burn
                // a core on SMP or starve the very tasks that would free a slot. The
                // spurious Woken is safe (every wait() caller re-checks its data and
                // retries on Woken, exactly as wake_all produces; no Blocked was
                // published). Unreachable while resident tasks <= SOCKET_WAITER_SLOTS.
                if !waiters.add_or_refresh_waiter(queue_addr, pid, my_gen, deadline) {
                    return (my_gen, None, true);
                }

                // R152-2 FIX: Check for pending wake AFTER registration.
                // If a wake arrived before we registered, consume the token and
                // remove ourselves — no need to block.
                if queue.try_consume_wakeup() {
                    waiters.remove_waiter(queue_addr, pid, Some(my_gen));
                    return (my_gen, Some(net::WaitOutcome::Woken), false);
                }

                // Mark process as blocked
                if let Some(proc_arc) = get_process(pid) {
                    let mut proc = proc_arc.lock();
                    // M4-1b: entry-clear (born-clean). The prior wait's epilogue swap
                    // should already have zeroed this; the debug_assert is the tripwire
                    // for that invariant and the store is the belt so a future exit path
                    // that forgets to consume can never leak a stale incomparable
                    // generation into THIS wait. Must precede Blocked (the IRQ/inline
                    // timeout-set only fires on a Blocked, still-queued entry); the whole
                    // enqueue+block runs under SOCKET_WAITERS + IRQs-off, so no marker can
                    // be set between enqueue above and this clear.
                    debug_assert!(
                        proc.socket_timeout_marker
                            .load(core::sync::atomic::Ordering::Relaxed)
                            == 0,
                        "M4-1b: socket_timeout_marker not born-clean at wait entry"
                    );
                    proc.socket_timeout_marker
                        .store(0, core::sync::atomic::Ordering::Relaxed);
                    // R172-12 FIX: recheck kill/signal UNDER the proc lock before publishing
                    // Blocked (the data double-check at :928 ran, but not a kill/signal recheck).
                    // On a raced-in kill/handler-signal the bare state-flip wake would be lost; an
                    // UNTIMED socket recv/accept then has no backstop -> permanent strand. Bail
                    // with Interrupted (mapped to EINTR at the recv/accept callers); remove our
                    // waiter (exact gen) below, after dropping the proc lock (waiters is the outer
                    // lock). Born-clean marker means no socket_timeout_marker cleanup is owed.
                    if crate::signal::should_abort_pending_block(&proc) {
                        drop(proc);
                        waiters.remove_waiter(queue_addr, pid, Some(my_gen));
                        return (my_gen, Some(net::WaitOutcome::Interrupted), false);
                    }
                    proc.enter_blocked_at(crate::get_ticks());
                }
                (my_gen, None, false)
            });

        // D1-RES R2: registry full — YIELD the CPU (release SOCKET_WAITERS first,
        // which happened when the closure returned) so the tasks that would free a
        // slot can run, THEN return the spurious Woken. Matches the stdin RegistryFull
        // path; prevents a non-yielding busy-retry on a full registry.
        if registry_full {
            crate::force_reschedule();
            return net::WaitOutcome::Woken;
        }

        if let Some(outcome) = immediate {
            return outcome;
        }

        // Phase 2: Yield CPU and wait for wakeup
        crate::force_reschedule();

        // Phase 3: HLT loop waiting for interrupt (if no other process to run)
        // R171-F3: track whether a pending kill (not a normal wake/timeout/close)
        // ended the wait, so we can report Interrupted (EINTR) below.
        let mut aborted = false;
        loop {
            let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
                // R171-F3 FIX: a pending kill must interrupt the blocking
                // accept/recv FIRST. A kill flips Blocked->Ready, so the
                // `state != Blocked` check below would otherwise return a spurious
                // "Woken" and the caller (sys_accept / recv) would re-park forever.
                // Dequeue our exact (pid, generation), mark Ready, flag aborted.
                if wait_should_abort(pid) {
                    SOCKET_WAITERS
                        .lock()
                        .remove_waiter(queue_addr, pid, Some(my_gen));
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().enter_ready_at(crate::get_ticks());
                    }
                    aborted = true;
                    return false;
                }
                // M0-5 sub-slice 1b: same EINTR cleanup for a deliverable handler signal,
                // evaluated BEFORE the `state != Blocked` check below so the recv/accept
                // caller does not re-park with its exact (pid, gen) waiter dequeued.
                if crate::signal::has_deliverable_signal(pid) {
                    SOCKET_WAITERS
                        .lock()
                        .remove_waiter(queue_addr, pid, Some(my_gen));
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().enter_ready_at(crate::get_ticks());
                    }
                    aborted = true;
                    return false;
                }
                if let Some(proc_arc) = get_process(pid) {
                    let proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        return false; // Woken up
                    }
                } else {
                    return false; // Process gone
                }

                // Check if closed
                if queue.is_closed() {
                    // Remove from wait queue (R165-9: our exact generation)
                    SOCKET_WAITERS
                        .lock()
                        .remove_waiter(queue_addr, pid, Some(my_gen));
                    // Mark ready so we can return
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().enter_ready_at(crate::get_ticks());
                    }
                    return false;
                }

                // Check timeout
                if let Some(dl) = deadline {
                    if crate::get_ticks() >= dl {
                        // Timeout expired - mark and remove.
                        // R165-9 FIX: only record the timeout if we actually
                        // removed OUR (pid, generation) entry, so we never stamp a
                        // timeout over a concurrent wake/refresh of a newer wait.
                        // M4-1b: set the per-PCB marker IFF WE removed our exact
                        // (pid, my_gen) membership — preserves the R165-9 gate (never
                        // stamp a timeout over a concurrent wake/refresh of a newer
                        // wait). Drop SOCKET_WAITERS before taking the proc lock
                        // (strictly fewer locks than the old held-across form).
                        let we_timed_out = {
                            let mut waiters = SOCKET_WAITERS.lock();
                            waiters.remove_waiter(queue_addr, pid, Some(my_gen))
                        };
                        if let Some(proc_arc) = get_process(pid) {
                            let mut proc = proc_arc.lock();
                            // Store the marker (Release) STRICTLY BEFORE state=Ready,
                            // both under the proc lock — same marker-before-wake edge
                            // as the IRQ path (replaces SocketWaiters::mark_timed_out).
                            if we_timed_out {
                                proc.socket_timeout_marker.store(
                                    crate::process::pack_timeout_marker(my_gen),
                                    core::sync::atomic::Ordering::Release,
                                );
                            }
                            proc.enter_ready_at(crate::get_ticks());
                        }
                        return false;
                    }
                }

                true // Continue waiting
            });

            if !should_continue {
                break;
            }

            // Wait for interrupt (timer or network)
            x86_64::instructions::interrupts::enable_and_hlt();
        }

        // R171-F3 FIX: a pending-kill abort takes precedence over a coincident
        // close/timeout/wake — consume any stale timeout marker for THIS wait and
        // report Interrupted so the caller returns EINTR instead of re-parking.
        if aborted {
            crate::process::consume_socket_timeout(pid, my_gen);
            return net::WaitOutcome::Interrupted;
        }

        // Determine outcome using timeout marker (fixes race between timer and wake)
        if queue.is_closed() {
            // Consume any stale timeout marker for THIS wait (R165-9: exact gen)
            crate::process::consume_socket_timeout(pid, my_gen);
            return net::WaitOutcome::Closed;
        }

        // Check if we were marked as timed out (by timer callback or inline check)
        if crate::process::consume_socket_timeout(pid, my_gen) {
            return net::WaitOutcome::TimedOut;
        }

        net::WaitOutcome::Woken
    }

    fn wake_one(&self, queue: &net::WaitQueue) {
        let queue_addr = queue as *const _ as usize;
        x86_64::instructions::interrupts::without_interrupts(|| {
            SOCKET_WAITERS.lock().wake_one(queue_addr);
        });
    }

    fn wake_all(&self, queue: &net::WaitQueue) {
        let queue_addr = queue as *const _ as usize;
        x86_64::instructions::interrupts::without_interrupts(|| {
            SOCKET_WAITERS.lock().wake_all(queue_addr);
        });
    }

    fn get_ticks(&self) -> u64 {
        crate::get_ticks()
    }
}

/// Static instance of KernelSocketWaitHooks for registration.
pub(super) static KERNEL_SOCKET_WAIT_HOOKS: KernelSocketWaitHooks = KernelSocketWaitHooks;

/// Register socket wait hooks with the net crate.
///
/// Called during kernel initialization after process module is ready.
pub fn register_socket_hooks() {
    net::register_socket_wait_hooks(&KERNEL_SOCKET_WAIT_HOOKS);
}

/// J2-8: Kernel implementation of the per-cgroup ephemeral-port budget hooks.
///
/// Bridges the `net` crate (which cannot depend on `kernel_core::cgroup` — that
/// would be a dependency cycle) to `process::current_cgroup_id` +
/// `cgroup::try_charge_ports` / `cgroup::uncharge_ports`.
pub(super) struct KernelCgroupPortHooks;

impl net::CgroupPortHooks for KernelCgroupPortHooks {
    fn current_cgroup_id(&self) -> Option<u64> {
        // Returns None for non-process (kernel-thread / RX) callers; the net
        // side then treats the charge as cgid 0 (root / exempt).
        crate::process::current_cgroup_id()
    }

    fn try_charge_ports(&self, cgid: u64, n: u64) -> Result<(), ()> {
        crate::cgroup::try_charge_ports(cgid, n).map_err(|_| ())
    }

    fn uncharge_ports(&self, cgid: u64, n: u64) {
        crate::cgroup::uncharge_ports(cgid, n);
    }
}

/// Static instance of KernelCgroupPortHooks for registration.
pub(super) static KERNEL_CGROUP_PORT_HOOKS: KernelCgroupPortHooks = KernelCgroupPortHooks;

/// J2-8: Register the per-cgroup ephemeral-port budget hooks with the net crate.
///
/// Called during kernel initialization alongside `register_socket_hooks`, after
/// the process module and cgroup registry are ready.
pub fn register_cgroup_port_hooks() {
    net::register_cgroup_port_hooks(&KERNEL_CGROUP_PORT_HOOKS);
}

/// D1-ISO-NETNS-DATAPLANE: Kernel implementation of the TX device-ownership
/// verification hook.
///
/// Bridges the net crate's namespace-gated TX device resolver (which cannot
/// depend on kernel_core — dependency cycle) to the NetNamespace device
/// registry: root (ns 0) owns all registered devices by default; a child
/// namespace owns exactly the devices added via `add_device` / `move_device`
/// (CAP_NET_ADMIN-gated). Unknown / destroyed namespace ids own nothing.
pub(super) struct KernelNetNsDeviceHooks;

impl net::NetNsDeviceHooks for KernelNetNsDeviceHooks {
    fn ns_owns_device(&self, ns_id: u64, device_index: u32) -> bool {
        crate::net_namespace::net_ns_owns_device(ns_id, device_index)
    }

    /// D3-NETNS-DATAPLANE: hand the net crate namespace `ns_id`'s ARP cache.
    ///
    /// Unknown/destroyed namespace => `None` (fail-closed at the net-side
    /// callers: RX ARP drops, TX resolves to gateway only).
    ///
    /// Lock safety: `lookup_net_ns` releases the NET_NS_BY_ID read guard
    /// before returning, and the upgraded namespace Arc is dropped HERE,
    /// inside the closure — before this method returns. If that drop is the
    /// last reference, `NetNamespace::Drop` (NET_NS_BY_ID.write + net-crate
    /// leaf-lock drains) runs with no registry guard held; net-side callers
    /// invoke this hook before taking any ARP-cache lock, and TX send paths
    /// hold per-socket locks only while a live sending process pins the
    /// namespace (never the last reference) — the same envelope as
    /// `net_ns_owns_device` above.
    fn ns_arp_cache(
        &self,
        ns_id: u64,
    ) -> Option<alloc::sync::Arc<spin::Mutex<net::arp::ArpCache>>> {
        crate::net_namespace::lookup_net_ns(ns_id).map(|ns| ns.arp_cache())
    }

    /// D3 NETNS-CONFIG: hand the net crate namespace `ns_id`'s addressing.
    ///
    /// Root DELEGATES to `net::network_config()` — the global config IS the
    /// root namespace's addressing authority (no stored root copy exists,
    /// so root and the pre-registration fallback cannot drift; the existing
    /// root-only lazy eth0 MAC fill is reused unchanged). Children return
    /// their stored per-ns config; unknown / destroyed / unconfigured
    /// namespaces => `None` (fail-closed LinkDown at the TX acquisition).
    ///
    /// Lock safety: the net -> hook -> `net::network_config()` reentry
    /// takes only the NET_STATE config mutex (plus the device-registry read
    /// inside the lazy MAC fill) — leaf locks the TX path does not hold at
    /// config acquisition (the snapshot is acquired before any firewall /
    /// conntrack / ARP lock). The child arm copies a `Copy` snapshot under
    /// the namespace's own config mutex, and the upgraded namespace Arc
    /// drops before this method returns — the same teardown-safety envelope
    /// as `ns_arp_cache` above.
    fn ns_net_config(&self, ns_id: u64) -> Option<net::NetConfigSnapshot> {
        if ns_id == 0 {
            return Some(net::network_config());
        }
        crate::net_namespace::lookup_net_ns(ns_id).and_then(|ns| ns.net_config())
    }
}

/// Static instance of KernelNetNsDeviceHooks for registration.
pub(super) static KERNEL_NETNS_DEVICE_HOOKS: KernelNetNsDeviceHooks = KernelNetNsDeviceHooks;

/// D1-ISO-NETNS-DATAPLANE: Register the TX device-ownership hooks with the net
/// crate. Called during kernel initialization (before userspace), so no child
/// netns can transmit before the ownership gate is live; pre-registration the
/// net-side gate admits only the root namespace (fail-closed).
pub fn register_netns_device_hooks() {
    net::register_netns_device_hooks(&KERNEL_NETNS_DEVICE_HOOKS);
}

/// Timer callback to check socket wait timeouts.
///
/// Called from scheduler tick to wake processes whose timeouts have expired.
pub fn check_socket_timeouts() {
    let current_ticks = crate::get_ticks();
    // Use try_lock to avoid blocking in IRQ context
    if let Some(mut waiters) = SOCKET_WAITERS.try_lock() {
        waiters.check_timeouts(current_ticks);
    }
}

/// M4-1c: process-context drain of deferred empty wait-queue nodes (the BTreeMap
/// node free moved off the timer IRQ — R151-5 dealloc class).
///
/// Called from the UNCONDITIONAL `scheduler_hook::reschedule_if_needed` deferred-work
/// drain (IRQs ENABLED, runs on every syscall return + nanosleep + BSP/AP idle), so a
/// quiet system — or a socket dropped without `close()` (SocketState::drop does NOT
/// `wake_all`, so it never triggers the process-context `wake_all`/`remove_waiter`
/// node free) — still reclaims the nodes with bounded latency, not only on a future
/// blocking `wait()`.
///
/// The fast path is a lock-free `load`, so the hot SOCKET_WAITERS lock is untouched
/// when nothing emptied. Uses `try_lock` (NEVER a blocking lock from this hot drain):
/// a contended tick simply defers to the next reschedule — the pending flag stays set
/// (we only `swap(false)` it once we actually hold the lock, inside
/// `drain_empty_queues`), so the reap is never lost. `without_interrupts` so a
/// same-CPU timer IRQ cannot fire mid-reap (it would `try_lock`-fail and skip a
/// timeout tick).
pub fn drain_socket_waiter_cleanup() {
    if !SOCKET_WAITER_CLEANUP_PENDING.load(AtomicOrdering::Acquire) {
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(mut waiters) = SOCKET_WAITERS.try_lock() {
            waiters.drain_empty_queues();
        }
    });
}

/// D1-RES R2 self-test: the flat `.bss` SocketWaiters registry. Drives a LOCAL
/// `SocketWaiters` (same module) — no global, no PROCESS_TABLE. Pins add / refresh
/// (no new slot) / generation-matched remove / unconditional remove / capacity
/// refusal WITHOUT allocation — the properties a green build/boot cannot catch.
pub fn run_socket_waiter_deferred_free_self_test() {
    let q1: usize = 0xFFFF_FFFF_8000_1000;
    let q2: usize = 0xFFFF_FFFF_8000_2000;

    let mut sw = SocketWaiters::new();

    // (1) ADD + occupancy count.
    assert!(sw.add_or_refresh_waiter(q1, 7, 1, None));
    assert!(sw.add_or_refresh_waiter(q1, 8, 1, None));
    assert!(sw.add_or_refresh_waiter(q2, 9, 1, None));
    assert!(
        sw.total_entries() == 3,
        "flat registry must hold 3 occupied slots"
    );

    // (2) REFRESH: an existing (queue,pid) updates gen/deadline WITHOUT a new slot.
    assert!(sw.add_or_refresh_waiter(q1, 7, 5, Some(42)));
    assert!(
        sw.total_entries() == 3,
        "refresh of an existing waiter must not consume a slot"
    );

    // (3) GENERATION-MATCHED remove: wrong gen is a no-op; exact gen clears the slot.
    assert!(
        !sw.remove_waiter(q1, 7, Some(999)),
        "wrong-generation remove must be a no-op (R165-9)"
    );
    assert!(
        sw.remove_waiter(q1, 7, Some(5)),
        "exact-generation remove must succeed"
    );
    assert!(sw.total_entries() == 2, "one slot cleared");

    // (4) UNCONDITIONAL remove (expected == None).
    assert!(sw.remove_waiter(q2, 9, None));
    assert!(sw.total_entries() == 1);
    // removing a gone entry is a no-op.
    assert!(!sw.remove_waiter(q2, 9, None));

    // (5) CAPACITY REFUSAL without allocation: fill every slot, then a NEW waiter
    // must be refused (false) while a REFRESH of an existing one still succeeds.
    let mut full = SocketWaiters::new();
    for i in 0..SOCKET_WAITER_SLOTS {
        assert!(
            full.add_or_refresh_waiter(0xDEAD_0000 + i, 1000 + i, 1, None),
            "slot {i} must be accepted below capacity"
        );
    }
    assert!(full.total_entries() == SOCKET_WAITER_SLOTS);
    assert!(
        !full.add_or_refresh_waiter(0xBEEF_0000, 9999, 1, None),
        "a NEW waiter past capacity must be refused (no allocation)"
    );
    assert!(
        full.add_or_refresh_waiter(0xDEAD_0000, 1000, 2, Some(7)),
        "a REFRESH of an existing waiter must still succeed at capacity"
    );
}

/// U.S3-B: structural self-test for the generic `FileOps::cap_id()` accessor.
///
/// The fd→cap lifecycle (dup increment, close/exec/exit decrement) dispatches
/// through this trait method instead of per-type downcasts. A cap-BEARING
/// implementor that forgets the override silently falls back to the `None`
/// default — every decrement for its fds becomes a no-op and the cap leaks to
/// TableFull (the dev-v35 missing-override class). A green boot cannot catch
/// that, so each bearing type is pinned here. PURE: the fabricated socket_id
/// resolves to nothing in socket_table(), so clone/Drop side effects are
// ============================================================================
// Socket 系统调用 (Linux x86_64 ABI: 41/49/44/45)
// ============================================================================

/// Helper: Read sockaddr_in from user space with length validation.
pub(super) fn read_sockaddr_in(
    user: *const SockAddrIn,
    len: u32,
) -> Result<SockAddrIn, SyscallError> {
    if user.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let need = core::mem::size_of::<SockAddrIn>() as u32;
    if len < need {
        return Err(SyscallError::EINVAL);
    }

    validate_user_ptr(user as *const u8, need as usize)?;

    let mut addr = SockAddrIn::default();
    // lint-repr-c-copy: allow (no-padding: SockAddrIn {u16,u16,[u8;4],[u8;8]} = 16 bytes; user→kernel)
    let addr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut addr as *mut SockAddrIn as *mut u8,
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    copy_from_user(addr_bytes, user as *const u8)?;
    Ok(addr)
}

/// Helper: Write sockaddr_in to user space with length tracking.
pub(super) fn write_sockaddr_in(
    addr: &SockAddrIn,
    user_addr: *mut SockAddrIn,
    user_len: *mut u32,
) -> Result<(), SyscallError> {
    if user_addr.is_null() {
        return Ok(()); // Nothing to write
    }
    if user_len.is_null() {
        // Linux requires a socklen_t pointer whenever the address output
        // pointer is non-null. Silently assuming 16 bytes would discard the
        // caller's object-boundary contract.
        return Err(SyscallError::EFAULT);
    }

    // Get user-provided buffer length
    validate_user_ptr_mut(user_len as *mut u8, core::mem::size_of::<u32>())?;
    let mut len_bytes = [0u8; 4];
    copy_from_user(&mut len_bytes, user_len as *const u8)?;
    let provided_len = u32::from_ne_bytes(len_bytes);
    if (provided_len as i32) < 0 {
        return Err(SyscallError::EINVAL);
    }

    // lint-repr-c-copy: allow (no-padding: SockAddrIn {u16,u16,[u8;4],[u8;8]} = 16 bytes)
    let addr_bytes = unsafe {
        core::slice::from_raw_parts(
            addr as *const SockAddrIn as *const u8,
            core::mem::size_of::<SockAddrIn>(),
        )
    };

    let write_len = core::cmp::min(provided_len as usize, addr_bytes.len());
    if write_len > 0 {
        validate_user_ptr_mut(user_addr as *mut u8, write_len)?;
        copy_to_user(user_addr as *mut u8, &addr_bytes[..write_len])?;
    }

    // Write actual length back
    if !user_len.is_null() {
        let actual = (core::mem::size_of::<SockAddrIn>() as u32).to_ne_bytes();
        copy_to_user(user_len as *mut u8, &actual)?;
    }

    Ok(())
}

/// Helper: Get socket handle from fd_table.
pub(super) fn socket_handle_from_fd(fd: i32) -> Result<(cap::CapId, u64, bool), SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();
    let fd_obj = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
    let socket = fd_obj
        .as_any()
        .downcast_ref::<SocketFile>()
        .ok_or(SyscallError::ENOTSOCK)?;
    let state = net::socket_table()
        .get(socket.socket_id)
        .ok_or(SyscallError::EBADF)?;
    Ok((
        socket.cap_id,
        socket.socket_id,
        state.file_status_flags() & crate::process::FILE_STATUS_NONBLOCK != 0,
    ))
}

/// Helper: Resolve socket state from handle.
///
/// # Security (R76-1 FIX)
/// Enforces network namespace isolation: a process can only access sockets
/// that belong to its current network namespace. This prevents a process
/// from using sockets inherited from a parent namespace after calling
/// clone(CLONE_NEWNET) or setns().
pub(super) fn resolve_socket(
    cap_id: cap::CapId,
    socket_id: u64,
) -> Result<(cap::CapEntry, net::SocketArc), SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R132-1 FIX: Extract capability entry and net namespace ID under the process lock,
    // then drop the lock before any external lookups. Previously, current_net_ns_id()
    // was called while holding process.lock(), which re-acquired the same non-reentrant
    // Process mutex via PROCESS_TABLE → slot.lock() → deterministic self-deadlock on
    // every socket operation (bind, listen, accept, connect, sendto, recvfrom, shutdown).
    let (entry, caller_ns_id) = {
        let proc = process.lock();

        // Lookup capability entry
        let entry = proc
            .capability_lookup(cap_id)
            .map_err(cap_error_to_syscall)?;

        // Verify it's a socket with matching ID
        match &entry.object {
            cap::CapObject::Socket(ref h) if h.socket_id == socket_id => {}
            _ => return Err(SyscallError::ENOTSOCK),
        }

        // Read net_ns ID directly from the locked Process struct instead of calling
        // current_net_ns_id() which would re-enter PROCESS_TABLE and deadlock.
        let ns_id = proc.net_ns.id();

        (entry, ns_id)
    };
    // Process lock released — safe for external lookups

    // Get socket state from socket_table
    let sock = net::socket_table()
        .get(socket_id)
        .ok_or(SyscallError::EBADF)?;

    // R76-1 FIX: Enforce network namespace isolation.
    // A process that has entered a different network namespace (via clone/setns)
    // must not be able to use sockets from its previous namespace.
    // This prevents container escape via inherited socket capabilities.
    if sock.net_ns_id != caller_ns_id {
        // Socket belongs to a different namespace - deny access
        return Err(SyscallError::EACCES);
    }

    Ok((entry, sock))
}

/// RF180-37: all fallible per-process resources required to publish one
/// socket-backed descriptor. None of these fields exposes a capability, fd, or
/// SocketFile until `commit`; dropping the bundle is an exact rollback.
pub(super) struct PreparedSocketPublication<'a> {
    pub(super) descriptor: crate::process::PreparedFileDescriptor<SocketFile>,
    pub(super) fd_reservation: FdPublicationReservation,
    pub(super) capability: AuthorizedCapReservation<'a>,
    pub(super) net_ns_id: cap::NamespaceId,
}

impl PreparedSocketPublication<'_> {
    #[inline]
    pub(super) fn process_context(&self) -> &lsm::ProcessCtx {
        self.capability.process_context()
    }

    #[inline]
    pub(super) fn net_ns_id(&self) -> cap::NamespaceId {
        self.net_ns_id
    }

    /// Publish the capability and descriptor through resources that were fully
    /// reserved before any socket-table creation or accept-queue dequeue.
    pub(super) fn commit(
        self,
        cap_entry: cap::CapEntry,
        socket: &net::SocketArc,
        nonblocking: bool,
    ) -> (i32, cap::CapId) {
        let Self {
            descriptor,
            fd_reservation,
            capability,
            net_ns_id: _,
        } = self;
        socket.set_file_status_flags(if nonblocking {
            crate::process::FILE_STATUS_NONBLOCK
        } else {
            0
        });
        let cap_id = capability.cap_id();
        let grant = capability.install(cap_entry);
        let desc = descriptor.finalize(SocketFile::new(cap_id, socket.id));
        let fd = match fd_reservation.install(desc) {
            Ok(fd) => fd,
            Err(_desc) => {
                panic!("RF180-37: prepared socket FD publication invariant failed")
            }
        };
        let audited_cap_id = grant.audit();
        debug_assert_eq!(cap_id, audited_cap_id);
        (fd, cap_id)
    }
}

/// RF180-37: structural ordering primitive for socket(). A failed preflight
/// cannot invoke `publish`; a publication failure drops the unpublished
/// resource bundle through ordinary RAII.
pub(super) fn socket_publish_after_preflight<P, S, E>(
    preflight: impl FnOnce() -> Result<P, E>,
    publish: impl FnOnce(&P) -> Result<S, E>,
) -> Result<(P, S), E> {
    let prepared = preflight()?;
    let published = publish(&prepared)?;
    Ok((prepared, published))
}

pub(super) enum AcceptPublicationAttempt<P, C> {
    NotReady,
    LostRace,
    Ready { prepared: P, child: C },
}

/// RF180-37: non-consuming readiness -> full publication preflight -> atomic
/// recheck/pop. A resource failure returns before `pop`; a competing acceptor
/// that wins after the readiness snapshot yields `LostRace` and drops every
/// reservation before the caller retries.
pub(super) fn accept_after_preflight<P, C, E>(
    ready: bool,
    preflight: impl FnOnce() -> Result<P, E>,
    pop: impl FnOnce() -> Result<Option<C>, E>,
) -> Result<AcceptPublicationAttempt<P, C>, E> {
    if !ready {
        return Ok(AcceptPublicationAttempt::NotReady);
    }
    let prepared = preflight()?;
    match pop()? {
        Some(child) => Ok(AcceptPublicationAttempt::Ready { prepared, child }),
        None => Ok(AcceptPublicationAttempt::LostRace),
    }
}

pub(super) fn emit_cap_allocate_audit(proc_ctx: &lsm::ProcessCtx, cap_id: cap::CapId) {
    let subject = audit::AuditSubject::new(
        proc_ctx.pid as u32,
        proc_ctx.uid,
        proc_ctx.gid,
        proc_ctx.cap.map(|c| c.raw()),
    );
    let timestamp = crate::time::get_ticks();
    let _ = audit::emit_capability_event(
        audit::AuditOutcome::Success,
        subject,
        cap_id.raw(),
        audit::AuditCapOperation::Allocate,
        None,
        0,
        timestamp,
    );
}

/// sys_socket - Create a UDP socket (syscall 41).
///
/// # Arguments
/// * `domain` - Address family (AF_INET = 2)
/// * `type_` - Socket type (SOCK_DGRAM = 2, may have SOCK_CLOEXEC/SOCK_NONBLOCK)
/// * `protocol` - Protocol (IPPROTO_UDP = 17, or 0 for default)
///
/// # Returns
/// File descriptor on success, negative errno on failure.
///
/// # Security
/// - Invokes LSM hook_net_socket for policy check
/// - Creates CapEntry with READ|WRITE|BIND rights (TCP also gets CONNECT|LISTEN|ACCEPT)
/// - Stores CapId in fd_table via SocketFile wrapper
pub(super) fn sys_socket(domain: i32, type_: i32, protocol: i32) -> SyscallResult {
    // Parse domain
    let domain_val =
        net::SocketDomain::from_raw(domain as u32).ok_or(SyscallError::EAFNOSUPPORT)?;

    // Parse type (handle SOCK_CLOEXEC/SOCK_NONBLOCK flags)
    let raw_ty = type_ as u32;
    let cloexec = raw_ty & SOCK_CLOEXEC != 0;
    let nonblock = raw_ty & SOCK_NONBLOCK != 0;
    let clean_ty = raw_ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let ty = net::SocketType::from_raw(clean_ty).ok_or(SyscallError::EPROTOTYPE)?;

    // Parse protocol (infers default from socket type)
    let proto =
        net::SocketProtocol::from_raw(protocol as u32, ty).ok_or(SyscallError::EPROTONOSUPPORT)?;

    // Currently only support AF_INET
    if domain_val != net::SocketDomain::Inet4 {
        return Err(SyscallError::EAFNOSUPPORT);
    }

    // Validate socket type and protocol combinations
    match (ty, proto) {
        (net::SocketType::Dgram, net::SocketProtocol::Udp) => {}
        (net::SocketType::Stream, net::SocketProtocol::Tcp) => {}
        _ => return Err(SyscallError::EPROTONOSUPPORT),
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // RF180-37 FIX: prepare the exact SocketFile allocation, numeric fd,
    // files.max charge, CLOEXEC slot, capability backing, and capability LSM
    // permission before create_* publishes a socket in the global table.
    let (cap_authority, credentials) = {
        let proc = process.lock();
        (proc.capability_table_authority(), proc.shared_credentials())
    };
    let credential_authorization = credentials.begin_authorization();
    let ((prepared, socket), rights) = {
        let mut rights = cap::CapRights::READ | cap::CapRights::WRITE | cap::CapRights::BIND;
        if ty == net::SocketType::Stream && proto == net::SocketProtocol::Tcp {
            rights |= cap::CapRights::CONNECT | cap::CapRights::LISTEN | cap::CapRights::ACCEPT;
        }

        let pair = socket_publish_after_preflight(
            || {
                let descriptor =
                    crate::process::FileDescriptor::try_prepare(mm::HeapClass::SocketObject)
                        .map_err(|_| SyscallError::ENOMEM)?;
                let fd_reservation = FdPublicationReservation::try_new(process.clone(), cloexec)?;
                let (capability, net_ns_id) = {
                    let proc = process.lock();
                    let net_ns_id = proc.net_ns.id();
                    let capability = prepare_cap_allocation_authorized(
                        &proc,
                        &cap_authority,
                        credential_authorization,
                    )?;
                    (capability, net_ns_id)
                };
                Ok(PreparedSocketPublication {
                    descriptor,
                    fd_reservation,
                    capability,
                    net_ns_id,
                })
            },
            |prepared| {
                // RF186-7: derive the socket's persistent MAC subject from the
                // same owned credential authorization that mediated and reserved
                // its capability. The authorization remains live through socket,
                // capability, FD and audit publication, so a sibling credential
                // writer cannot splice two identities into one operation.
                let label = net::SocketLabel {
                    creator: *prepared.process_context(),
                    secmark: 0,
                };
                match (ty, proto) {
                    (net::SocketType::Dgram, net::SocketProtocol::Udp) => net::socket_table()
                        .create_udp_socket(label, prepared.net_ns_id())
                        .map_err(socket_error_to_syscall),
                    (net::SocketType::Stream, net::SocketProtocol::Tcp) => net::socket_table()
                        .create_tcp_socket(label, prepared.net_ns_id())
                        .map_err(socket_error_to_syscall),
                    _ => Err(SyscallError::EPROTONOSUPPORT),
                }
            },
        )?;
        (pair, rights)
    };

    // U.S3-B: SOCK_CLOEXEC remains exclusively fd-side. The capability install
    // and reserved-fd commit below are both allocation-free and cannot return a
    // recoverable error after socket publication.
    let cap_entry = cap::CapEntry::with_flags(
        cap::CapObject::Socket(cap::Socket::new(socket.id, socket.net_ns_id.raw())),
        rights,
        cap::CapFlags::empty(),
    );
    let (fd, _cap_id) = prepared.commit(cap_entry, &socket, nonblock);

    Ok(fd as usize)
}

/// Prepare a socket-backed descriptor publication for accept/accept4 while no
/// accept-queue state is owned. All recoverable errors therefore leave the
/// pending child available to another or later accept attempt.
pub(super) fn prepare_accept_publication<'a>(
    process: crate::process::ProcessArc,
    cap_authority: &'a crate::process::CapabilityTableAuthority,
    cloexec: bool,
) -> Result<PreparedSocketPublication<'a>, SyscallError> {
    let descriptor = crate::process::FileDescriptor::try_prepare(mm::HeapClass::SocketObject)
        .map_err(|_| SyscallError::ENOMEM)?;
    let fd_reservation = FdPublicationReservation::try_new(process.clone(), cloexec)?;
    let (credentials, net_ns_id) = {
        let proc = process.lock();
        (proc.shared_credentials(), proc.net_ns.id())
    };
    let authorization = credentials.begin_authorization();
    let capability = {
        let proc = process.lock();
        prepare_cap_allocation_authorized(&proc, cap_authority, authorization)?
    };
    Ok(PreparedSocketPublication {
        descriptor,
        fd_reservation,
        capability,
        net_ns_id,
    })
}

/// sys_bind - Bind socket to local address (syscall 49).
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `addr` - Pointer to sockaddr_in
/// * `addrlen` - Length of address structure
///
/// # Security
/// - Verifies CapRights::BIND
/// - Invokes LSM hook_net_bind for policy check
/// - Ports < 1024 require euid == 0 or NET_BIND_SERVICE capability
pub(super) fn sys_bind(fd: i32, addr: *const SockAddrIn, addrlen: u32) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check BIND right
    if !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    // Read address from user space
    let user_addr = read_sockaddr_in(addr, addrlen)?;
    if user_addr.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }

    let port = user_addr.port();
    let ip = net::Ipv4Addr(user_addr.ip_bytes());

    // Get current process context for LSM check
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // R49-3 FIX: Compute privileged port binding permission
    // R134-3 FIX: Use host-mapped root check instead of namespace euid==0.
    // Namespace root must NOT be able to bind privileged ports on the host network.
    let has_net_bind_cap = current_has_cap_rights(cap::CapRights::NET_BIND_SERVICE);
    let can_bind_privileged = crate::current_is_host_root() || has_net_bind_cap;

    // Early check for privileged port access
    const PRIVILEGED_PORT_LIMIT: u16 = 1024;
    if port != 0 && port < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
        return Err(SyscallError::EACCES);
    }

    // Bind via socket_table (includes LSM hook_net_bind check)
    // R51-1: Support both UDP and TCP binding
    // R169-6 FIX (D2-J2-PORT-COVERAGE): EVERY bind now charges the per-cgroup
    // `ports.max` budget (root cgroup id 0 exempt at the charge layer).
    // - `bind(0)` charges a kernel-chosen port as BindCharge::Ephemeral
    //   (ghost-bind teardown; POSIX-deviation note: its port does NOT persist
    //   across a failed connect — unchanged shipped semantics; the
    //   bind(0)+connect self-replace undercount stays closed on the connect
    //   side via the reuse-live-binding gate).
    // - R169-6 slice 2: an explicit NON-zero bind charges as
    //   BindCharge::Explicit with HOLD-UNTIL-CLOSE teardown (the while-alive
    //   teardown arms pure-skip it, so the port + charge persist until
    //   close()/exit) — closing the last ports.max bypass: `socket();
    //   bind(fd,p); ...` repeated no longer consumes uncharged ports.
    // A tenant at ports.max gets QuotaExceeded -> EAGAIN (definitively EAGAIN
    // via socket_error_to_syscall — NOT EADDRINUSE, so a quota failure is
    // never confused with a real port collision; note quota is checked before
    // the in-use probe, so a busy-port bind at the cap also reports EAGAIN).
    let (port_opt, policy) = if port == 0 {
        (None, net::BindCharge::Ephemeral)
    } else {
        (Some(port), net::BindCharge::Explicit)
    };
    if socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp {
        net::socket_table()
            .bind_udp(
                &socket,
                &ctx,
                cap_id,
                ip,
                port_opt,
                can_bind_privileged,
                policy,
            )
            .map_err(socket_error_to_syscall)?;
    } else if socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp {
        net::socket_table()
            .bind_tcp(
                &socket,
                &ctx,
                cap_id,
                ip,
                port_opt,
                can_bind_privileged,
                policy,
            )
            .map_err(socket_error_to_syscall)?;
    } else {
        return Err(SyscallError::EOPNOTSUPP);
    }

    Ok(0)
}

/// sys_listen - Mark a TCP socket as listening (syscall 50, R51-1).
///
/// Transitions a bound TCP socket to LISTEN state, enabling it to accept
/// incoming connections.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `backlog` - Maximum pending connections (clamped to system limits)
///
/// # Security
/// - Verifies CapRights::LISTEN (required for listen)
/// - Verifies CapRights::BIND if auto-bind is needed
/// - Invokes LSM hook_net_listen for policy check
/// - Auto-binds to ephemeral port if not already bound
pub(super) fn sys_listen(fd: i32, backlog: i32) -> SyscallResult {
    if backlog < 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets can listen
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R152-1 FIX: LISTEN right required for listen()
    if !entry.rights.allows(cap::CapRights::LISTEN) {
        return Err(SyscallError::EACCES);
    }

    // R152-1 FIX: BIND right required only if listen() must auto-bind
    if socket.local_port().is_none() && !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Compute privileged-port permission for auto-bind
    // R134-3 FIX: Use host-mapped root check instead of namespace euid==0.
    let has_net_bind_cap = current_has_cap_rights(cap::CapRights::NET_BIND_SERVICE);
    let can_bind_privileged = crate::current_is_host_root() || has_net_bind_cap;

    net::socket_table()
        .listen(&socket, &ctx, cap_id, backlog as u32, can_bind_privileged)
        .map_err(socket_error_to_syscall)?;

    Ok(0)
}

/// sys_accept - Accept a pending TCP connection (syscall 43, R51-1).
///
/// Extracts the first connection from the listen queue, creates a new
/// socket for it, and returns its file descriptor.
///
/// # Arguments
/// * `fd` - Listening socket file descriptor
/// * `addr` - Optional pointer to receive peer address
/// * `addrlen` - Optional pointer to address length
///
/// # Security
/// - Verifies CapRights::ACCEPT (required for accept)
/// - Invokes LSM hook_net_accept for policy check
/// - Returns EAGAIN for non-blocking if no connections pending
pub(super) fn sys_accept(fd: i32, addr: *mut SockAddrIn, addrlen: *mut u32) -> SyscallResult {
    sys_accept_common(fd, addr, addrlen, 0)
}

/// Linux accept4(2) (syscall 288): accept with atomic descriptor flags.
pub(super) fn sys_accept4(
    fd: i32,
    addr: *mut SockAddrIn,
    addrlen: *mut u32,
    flags: i32,
) -> SyscallResult {
    let flags = flags as u32;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(SyscallError::EINVAL);
    }
    sys_accept_common(fd, addr, addrlen, flags)
}

pub(super) fn sys_accept_common(
    fd: i32,
    addr: *mut SockAddrIn,
    addrlen: *mut u32,
    accept_flags: u32,
) -> SyscallResult {
    let (cap_id, socket_id, listener_nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets can accept
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R152-1 FIX: ACCEPT right required for accept()
    if !entry.rights.allows(cap::CapRights::ACCEPT) {
        return Err(SyscallError::EACCES);
    }

    // Must be in LISTEN state
    if !socket.is_listening() {
        return Err(SyscallError::EINVAL);
    }
    if !addr.is_null() && addrlen.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let cap_authority = { process.lock().capability_table_authority() };
    let cloexec = accept_flags & SOCK_CLOEXEC != 0;
    // Linux accept() does not inherit O_NONBLOCK from the listener; only
    // accept4(SOCK_NONBLOCK) marks the returned descriptor non-blocking.
    let child_nonblock = accept_flags & SOCK_NONBLOCK != 0;

    // RF180-37 FIX: readiness is observed without consuming the child. Only
    // after every descriptor/capability resource is prepared do we atomically
    // recheck and pop. ENOMEM/EMFILE/LSM rejection therefore leaves the child
    // queued and retryable; a competing acceptor yields LostRace and retries.
    //
    // R181-4 FIX: LostRace retries are bounded. Under sustained contention
    // (many threads accepting on one listener) an unbounded immediate-retry
    // loop monopolizes the CPU. After ACCEPT_LOST_RACE_YIELD_THRESHOLD
    // consecutive losses a non-blocking caller returns EAGAIN (a lost race
    // IS "no connection available for this caller" — POSIX-correct), and a
    // blocking caller yields the CPU before retrying, so competing acceptors
    // and the rest of the system always make progress.
    const ACCEPT_LOST_RACE_YIELD_THRESHOLD: u32 = 16;
    let mut lost_races: u32 = 0;
    let (prepared, child) = loop {
        let attempt = accept_after_preflight(
            socket.poll_readiness().readable,
            || prepare_accept_publication(process.clone(), &cap_authority, cloexec),
            || {
                net::socket_table()
                    .poll_accept_ready(&socket)
                    .map_err(socket_error_to_syscall)
            },
        )?;
        match attempt {
            AcceptPublicationAttempt::Ready { prepared, child } => break (prepared, child),
            AcceptPublicationAttempt::LostRace => {
                lost_races += 1;
                if lost_races >= ACCEPT_LOST_RACE_YIELD_THRESHOLD {
                    if listener_nonblock {
                        return Err(SyscallError::EAGAIN);
                    }
                    lost_races = 0;
                    if let Some(proc) = current_pid().and_then(get_process) {
                        proc.lock().enter_ready_at(crate::get_ticks());
                    }
                    yield_with_deferred_work();
                }
                continue;
            }
            AcceptPublicationAttempt::NotReady => {
                if listener_nonblock {
                    return Err(SyscallError::EAGAIN);
                }
                // Block on accept wait queue
                if let Some(waiters) = socket.listen_waiters() {
                    match waiters.wait_with_timeout(None) {
                        net::WaitOutcome::Woken => continue,
                        net::WaitOutcome::Closed => return Err(SyscallError::ECONNABORTED),
                        net::WaitOutcome::NoProcess => return Err(SyscallError::ESRCH),
                        net::WaitOutcome::TimedOut => continue,
                        // R171-F3: pending kill — interrupt the blocking accept.
                        net::WaitOutcome::Interrupted => return Err(SyscallError::EINTR),
                    }
                } else {
                    return Err(SyscallError::EINVAL);
                }
            }
        }
    };

    // Helper to clean up a child only for a post-dequeue policy rejection. All
    // resource failures happened before the dequeue and require no rollback.
    let cleanup_child = |c: &net::SocketArc| {
        c.mark_closed();
        net::socket_table().close(c.id);
    };

    // LSM accept hook (using child's context for peer info)
    let mut ctx = net::socket_table().ctx_from_socket(&child);
    ctx.cap = Some(cap_id);
    // RF180-37: use the Process-lock snapshot taken immediately before the
    // atomic pop, not a context captured before an arbitrarily long wait.
    if let Err(e) = lsm::hook_net_accept(prepared.process_context(), &ctx) {
        cleanup_child(&child);
        return Err(lsm_error_to_syscall(e));
    }

    // R75-1 FIX: Pass network namespace ID to Socket capability (inherited from listener)
    // R152-1 FIX: Child socket rights are limited to (READ|WRITE) & listener_rights.
    // This enforces capability monotonicity: a restricted listener cannot mint
    // broader child capabilities via accept().
    let child_rights = (cap::CapRights::READ | cap::CapRights::WRITE) & entry.rights;
    let cap_entry = cap::CapEntry::with_flags(
        cap::CapObject::Socket(cap::Socket::new(child.id, child.net_ns_id.raw())),
        child_rights,
        cap::CapFlags::empty(),
    );
    let (new_fd, _new_cap) = prepared.commit(cap_entry, &child, child_nonblock);

    // R162-11/R180-24: peer-address copy failure is non-fatal after the child
    // descriptor is valid. Copy at most the caller-provided length and report
    // the actual sockaddr size; an invalid destination cannot kill the child.
    if !addr.is_null() {
        if let (Some(rip), Some(rport)) = (child.remote_ip(), child.remote_port()) {
            let out = SockAddrIn::from_addr(rip, rport);
            let _ = write_sockaddr_in(&out, addr, addrlen);
        }
    }

    Ok(new_fd as usize)
}

#[cfg(test)]
mod fd_open_transaction_tests {
    use super::*;
    use crate::process::{ConsoleFile, FileOps, Process};
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct OpenProbe {
        length: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        deny: bool,
    }

    impl FileOps for OpenProbe {
        fn clone_box(&self) -> Result<FileDescriptor, ()> {
            Err(())
        }
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
        fn type_name(&self) -> &'static str {
            "OpenProbe"
        }
    }

    fn finish_probe(descriptor: &dyn FileOps) -> Result<(), SyscallError> {
        let probe = descriptor.as_any().downcast_ref::<OpenProbe>().unwrap();
        probe
            .calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .expect("bounded finalization probe counter");
        if probe.deny {
            return Err(SyscallError::EACCES);
        }
        probe.length.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn prepare_probe(deny: bool) -> (PreparedVfsOpen, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        mm::publish_heap_budgets();
        let length = Arc::new(AtomicUsize::new(17));
        let calls = Arc::new(AtomicUsize::new(0));
        let descriptor = FileDescriptor::try_new(
            OpenProbe {
                length: length.clone(),
                calls: calls.clone(),
                deny,
            },
            mm::HeapClass::CoreProcess,
        )
        .unwrap();
        (
            PreparedVfsOpen::new(descriptor, finish_probe),
            length,
            calls,
        )
    }

    #[test]
    fn ksa013_nofile_rejection_precedes_truncate_finalization() {
        let (prepared, length, calls) = prepare_probe(false);
        let mut process = Process::new(0x004013, 1, String::from("nofile-open-test"), 120);
        process.rlimits[crate::process::RLIMIT_NOFILE].rlim_cur = 0;
        let result = prepared.finish_after(|_| process.reserve_fd().ok_or(SyscallError::EMFILE));
        assert!(matches!(result, Err(SyscallError::EMFILE)));
        assert_eq!(length.load(Ordering::SeqCst), 17);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(process.total_fd_charge_count(), 0);
    }

    #[test]
    fn ksa004_publication_preflight_errors_never_truncate() {
        for error in [
            SyscallError::ENOMEM,
            SyscallError::EMFILE,
            SyscallError::EPERM,
            SyscallError::EAGAIN,
            SyscallError::EIO,
        ] {
            let (prepared, length, calls) = prepare_probe(false);
            assert!(
                matches!(prepared.finish_after(|_| Err::<(), _>(error)), Err(observed) if observed == error)
            );
            assert_eq!(length.load(Ordering::SeqCst), 17);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(Arc::strong_count(&length), 1);
        }
    }

    #[test]
    fn ksa004_finalization_failure_returns_preflight_ownership() {
        let (prepared, length, calls) = prepare_probe(true);
        let resource = Arc::new(());
        let result = prepared.finish_after(|_| Ok(resource.clone()));
        assert!(matches!(result, Err(SyscallError::EACCES)));
        assert_eq!(Arc::strong_count(&resource), 1);
        assert_eq!(length.load(Ordering::SeqCst), 17);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ksa004_success_truncates_once_after_preflight() {
        let (prepared, length, calls) = prepare_probe(false);
        let (descriptor, publication) = prepared
            .finish_after(|_| {
                assert_eq!(length.load(Ordering::SeqCst), 17);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                Ok(42)
            })
            .unwrap();
        assert_eq!(publication, 42);
        assert_eq!(length.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(descriptor);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ksa005_poll_follows_objects_not_standard_fd_numbers() {
        mm::publish_heap_budgets();
        let mut process = Process::new(0x004006, 1, String::from("poll-fd-test"), 120);
        for fd in 0..3 {
            assert!(matches!(poll_classify(&process, fd), FdKind::Nval));
        }
        let console =
            FileDescriptor::try_new(ConsoleFile { readable: true }, mm::HeapClass::CoreProcess)
                .unwrap();
        assert!(process.replace_fd_charged(9, console).unwrap().is_none());
        assert!(matches!(poll_classify(&process, 9), FdKind::Stdin));
        let output =
            FileDescriptor::try_new(ConsoleFile { readable: false }, mm::HeapClass::CoreProcess)
                .unwrap();
        assert!(process.replace_fd_charged(0, output).unwrap().is_none());
        assert!(matches!(poll_classify(&process, 0), FdKind::ConsoleOut));
        let (ordinary, _, _) = prepare_probe(false);
        drop(process.replace_fd_charged(0, ordinary.descriptor).unwrap());
        assert!(matches!(poll_classify(&process, 0), FdKind::AlwaysReady));
        drop(process.remove_fd(0).unwrap());
        drop(process.remove_fd(9).unwrap());
        assert!(matches!(poll_classify(&process, 0), FdKind::Nval));
        assert_eq!(process.total_fd_charge_count(), 0);
    }
}

#[cfg(test)]
mod rf180_37_socket_publication_tests {
    use super::*;
    use alloc::collections::VecDeque;
    use core::cell::Cell;

    struct DropMarker<'a>(&'a Cell<usize>);

    impl Drop for DropMarker<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn rf180_37_socket_resource_failure_precedes_all_publication() {
        // RF180-37 FIX: deterministic ENOMEM/EMFILE injection at the exact
        // preflight boundary. The socket-publication closure is a tripwire;
        // capability publication is independently covered by cap's prepared-
        // allocation visibility/rollback tests.
        for error in [SyscallError::ENOMEM, SyscallError::EMFILE] {
            let socket_publications = Cell::new(0usize);
            let result = socket_publish_after_preflight(
                || Err::<(), _>(error),
                |_| {
                    socket_publications.set(socket_publications.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(result, Err(error));
            assert_eq!(
                socket_publications.get(),
                0,
                "resource rejection must precede socket-table publication"
            );
        }
    }

    #[test]
    fn rf180_37_socket_publish_failure_drops_every_prepared_resource() {
        let drops = Cell::new(0usize);
        let result = socket_publish_after_preflight(
            || Ok::<_, SyscallError>(DropMarker(&drops)),
            |_| Err::<(), _>(SyscallError::ENOMEM),
        );
        assert!(matches!(result, Err(SyscallError::ENOMEM)));
        assert_eq!(drops.get(), 1, "failed create must roll preflight back");
    }

    #[test]
    fn rf180_37_accept_failure_keeps_child_queued_and_retryable() {
        for error in [SyscallError::ENOMEM, SyscallError::EMFILE] {
            let child = 0x1803_7000_u64;
            let mut queue = VecDeque::from([child]);
            let pop_calls = Cell::new(0usize);
            let ready = !queue.is_empty();
            let failed = accept_after_preflight(
                ready,
                || Err::<(), _>(error),
                || {
                    pop_calls.set(pop_calls.get() + 1);
                    Ok(queue.pop_front())
                },
            );
            assert!(matches!(failed, Err(e) if e == error));
            assert_eq!(pop_calls.get(), 0, "failed preflight must not dequeue");
            assert_eq!(queue.front(), Some(&child));

            let retry = accept_after_preflight(
                !queue.is_empty(),
                || Ok::<_, SyscallError>(()),
                || Ok(queue.pop_front()),
            )
            .expect("retry preflight");
            match retry {
                AcceptPublicationAttempt::Ready {
                    prepared: (),
                    child: accepted,
                } => assert_eq!(accepted, child),
                _ => panic!("queued child was not retryable after resource failure"),
            }
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn rf180_37_accept_lost_race_releases_preflight_before_retry() {
        let drops = Cell::new(0usize);
        let attempt = accept_after_preflight(
            true,
            || Ok::<_, SyscallError>(DropMarker(&drops)),
            || Ok::<Option<u64>, _>(None),
        )
        .expect("lost-race attempt");
        assert!(matches!(attempt, AcceptPublicationAttempt::LostRace));
        assert_eq!(drops.get(), 1);
    }
}

/// sys_connect - Connect a TCP socket (syscall 42).
///
/// Initiates a TCP three-way handshake for stream sockets.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `addr` - Pointer to sockaddr_in with destination address
/// * `addrlen` - Length of address structure
///
/// # Security
/// - Verifies CapRights::CONNECT for initiating connect()
/// - Verifies CapRights::WRITE for sending SYN
/// - Verifies CapRights::BIND if socket not yet bound (auto-bind)
/// - Invokes LSM hook_net_send for policy check
///
/// # Returns
/// - 0 on success (connection established or in progress)
/// - EINPROGRESS for non-blocking sockets when handshake is in progress
/// - EISCONN if already connected
pub(super) fn sys_connect(fd: i32, addr: *const SockAddrIn, addrlen: u32) -> SyscallResult {
    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only stream sockets are supported for connect()
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R152-1 FIX: CONNECT right required for connect()
    if !entry.rights.allows(cap::CapRights::CONNECT) {
        return Err(SyscallError::EACCES);
    }

    // WRITE right required to transmit SYN
    if !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // BIND right required if auto-bind is needed
    if socket.local_port().is_none() && !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    // Read destination address
    let dest = read_sockaddr_in(addr, addrlen)?;
    if dest.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }
    let dst_port = dest.port();
    if dst_port == 0 {
        return Err(SyscallError::EINVAL);
    }
    let dst_ip = net::Ipv4Addr(dest.ip_bytes());

    // Current process context for LSM
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Source IP: resolve consistently with the IPv4 TX path (loopback -> 127.0.0.1,
    // external -> namespace our_ip) when unbound or bound to INADDR_ANY.
    let src_ip = net::select_source_ip(socket.local_ip(), dst_ip, socket.net_ns_id.0);

    // Non-blocking connect uses zero timeout to get EINPROGRESS
    // Blocking connect uses a reasonable timeout to avoid indefinite blocks
    const TCP_CONNECT_TIMEOUT_NS: u64 = 5_000_000_000; // 5 seconds (for testing)

    // Phase 1: Build SYN segment and install TCB (always non-blocking first)
    // We use timeout=Some(0) to just build the segment without waiting
    let syn_result = net::socket_table()
        .connect(&socket, &ctx, cap_id, src_ip, dst_ip, dst_port, Some(0))
        .map_err(socket_error_to_syscall)?;

    // RF180-41 REVIEW FIX: the generic transmit path reserves and publishes
    // conntrack together with device queue acceptance. Pre-seeding here would
    // leave a ghost SYN on QueueFull and double-account successful sends.

    // Phase 2: Transmit the SYN segment via network device (or loopback `lo`)
    // R51-5 FIX: Abort connection if TX fails to prevent TCB/binding leak
    if let Err(e) = net::transmit_tcp_connect_opts(syn_result, socket.net_ns_id.0, socket.ip_ttl())
    {
        net::socket_table().abort_tcp_connect(&socket);
        return Err(tx_error_to_syscall(e));
    }

    // Non-blocking connect: if loopback already completed the 3-way handshake
    // synchronously, POSIX permits returning 0 immediately; otherwise return
    // EINPROGRESS (with any synchronous loopback RST recorded in SO_ERROR).
    if nonblock {
        if matches!(socket.tcp_state(), Some(net::TcpState::Established)) {
            return Ok(0);
        }
        return Err(SyscallError::EINPROGRESS);
    }

    // Phase 3: Blocking connect - wait for connection to complete
    // Poll the TCP state with the specified timeout
    let start_ticks = crate::time::get_ticks();
    let timeout_ticks = TCP_CONNECT_TIMEOUT_NS / 1_000_000; // Convert ns to ms (1 tick = ~1ms)

    loop {
        // Check if connection established or failed
        match socket.tcp_state() {
            Some(net::TcpState::Established) => return Ok(0),
            Some(net::TcpState::Closed) => {
                // R50-3 FIX: Clean up resources on connection refused
                net::socket_table().abort_tcp_connect(&socket);
                return Err(SyscallError::ECONNREFUSED);
            }
            None => {
                // R50-3 FIX (codex review): TCB was cleaned up by RST or error
                // Return connection refused since the connection attempt failed
                return Err(SyscallError::ECONNREFUSED);
            }
            _ => {} // Still connecting (SYN_SENT)
        }

        // Check timeout
        let elapsed = crate::time::get_ticks() - start_ticks;
        if elapsed > timeout_ticks {
            // R50-3 FIX: Clean up TCB, port binding, and 4-tuple on timeout
            // This prevents resource exhaustion from abandoned connection attempts
            net::socket_table().abort_tcp_connect(&socket);
            return Err(SyscallError::ETIMEDOUT);
        }

        // R172-09 FIX: honor a pending kill + deliverable handler signal EACH iteration. This
        // is a Running-state spin (never Blocked), so the deferred-kill model — which only
        // acts at the RPL==3 safe point — could not reach the task for up to
        // TCP_CONNECT_TIMEOUT (5s): SIGKILL/EINTR were delayed the whole window. Abort the
        // connect attempt and return EINTR so the task unwinds to its safe point.
        if let Some(pid) = current_pid() {
            if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
                net::socket_table().abort_tcp_connect(&socket);
                return Err(SyscallError::EINTR);
            }
        }

        // R177-L1 FIX: Yield CPU and halt until next timer tick to prevent tight-spin CPU livelock.
        // The old pause+force_reschedule busy-waited if SYN-ACK was lost and never retransmitted
        // (no RTO timer when SYN sent but TCB destroyed by spurious RST / net device error), spinning
        // at 100% CPU for up to TCP_CONNECT_TIMEOUT. Match the proven poll/nanosleep pattern:
        // reschedule_if_needed (drains deferred work + switches if NEED_RESCHED set by tick) + hlt
        // (yields CPU until next IRQ, typically the 1kHz timer). Defense-in-depth against lost-SYN
        // scenarios not yet covered by TCP RTO logic.
        crate::reschedule_if_needed();
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// sys_sendto - Send UDP datagram (syscall 44).
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `buf` - Data buffer
/// * `len` - Data length
/// * `flags` - Send flags (MSG_DONTWAIT supported)
/// * `dest_addr` - Destination address
/// * `addrlen` - Length of destination address
///
/// # Security
/// - Verifies CapRights::WRITE
/// - Invokes LSM hook_net_send for policy check
/// - Auto-binds to ephemeral port if not bound
pub(super) fn sys_sendto(
    fd: i32,
    buf: *const u8,
    len: usize,
    flags: i32,
    dest_addr: *const SockAddrIn,
    addrlen: u32,
) -> SyscallResult {
    // Check flags
    let flag_bits = flags as u32;
    if flag_bits & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check WRITE right
    if !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // Determine socket type
    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;
    if !is_tcp && !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // Get current process context early
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // TCP: send() semantics when dest_addr is NULL (connected socket)
    if dest_addr.is_null() {
        if !is_tcp {
            return Err(SyscallError::EDESTADDRREQ);
        }

        // R51-2 FIX: Cap TCP send size pre-copy to avoid large allocations.
        // tcp_send() also enforces this limit as the canonical check point.
        if len > net::tcp::TCP_MAX_SEND_SIZE {
            return Err(SyscallError::EMSGSIZE);
        }

        // RF180-27 REVIEW FIX: zero-length TCP send is successful only after
        // flags, fd kind, capability generation, namespace, rights, socket
        // type, connection state, and LSM validation. The net-layer connected
        // fast path remains allocation-free and does not mutate TCP state.
        if len == 0 {
            let (bytes_sent, segments) = net::socket_table()
                .tcp_send(&socket, &ctx, cap_id, &[])
                .map_err(socket_error_to_syscall)?;
            debug_assert_eq!(bytes_sent, 0);
            debug_assert!(segments.is_empty());
            return Ok(0);
        }

        // Copy payload from user space
        validate_user_ptr(buf, len)?;
        // R180-11: syscall copy staging competes with retained socket payloads
        // in the same aggregate class. Its owner releases only after the net
        // send path returns and the Vec backing has been deallocated.
        let mut data = try_admitted_zeroed_buffer(mm::HeapClass::SocketPayload, len)?;
        copy_from_user(&mut data, buf)?;

        return send_tcp_payload(&socket, &ctx, cap_id, &data);
    }

    // Non-TCP with dest_addr: must be UDP
    if !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // UDP size check
    if len > UDP_MAX_PAYLOAD {
        return Err(SyscallError::EMSGSIZE);
    }

    // R48-REVIEW FIX: Check BIND right if socket is not already bound.
    // Auto-bind in sendto requires BIND capability to prevent capability bypass.
    let is_bound = socket.local_port().is_some();
    if !is_bound && !entry.rights.allows(cap::CapRights::BIND) {
        // Socket not bound and no BIND right - cannot auto-bind
        return Err(SyscallError::EACCES);
    }

    // Read destination address
    let dest = read_sockaddr_in(dest_addr, addrlen)?;
    if dest.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }
    let dst_port = dest.port();
    if dst_port == 0 {
        return Err(SyscallError::EINVAL);
    }
    let dst_ip = net::Ipv4Addr(dest.ip_bytes());

    if len == 0 {
        return send_udp_payload(&socket, &ctx, cap_id, dst_ip, dst_port, &[]);
    }

    validate_user_ptr(buf, len)?;
    // R180-11: include the user-copy staging buffer in the socket-payload
    // ledger; PendingDatagram takes its own retained charge on publication.
    let mut data = try_admitted_zeroed_buffer(mm::HeapClass::SocketPayload, len)?;
    copy_from_user(&mut data, buf)?;
    send_udp_payload(&socket, &ctx, cap_id, dst_ip, dst_port, &data)
}

/// Shared TCP payload transmit core for `sys_sendto` and `sys_sendmsg`.
pub(super) fn send_tcp_payload(
    socket: &net::SocketArc,
    ctx: &lsm::ProcessCtx,
    cap_id: cap::CapId,
    data: &[u8],
) -> SyscallResult {
    let remote_ip = socket
        .remote_ip()
        .map(net::Ipv4Addr)
        .ok_or(SyscallError::ENOTCONN)?;
    let local_ip = socket
        .local_ip()
        .map(net::Ipv4Addr)
        .filter(|ip| !ip.is_unspecified());
    let ttl = socket.ip_ttl();

    let (bytes_sent, segments) = net::socket_table()
        .tcp_send(socket, ctx, cap_id, data)
        .map_err(socket_error_to_syscall)?;

    // R162-10 FIX: Ignore transmit failures — data is already committed
    // to the TCP send buffer with snd_nxt advanced. The retransmission
    // timer will re-send on failure.
    for segment in segments {
        let _ =
            net::transmit_tcp_segment_opts(local_ip, remote_ip, &segment, socket.net_ns_id.0, ttl);
    }

    Ok(bytes_sent)
}

/// Shared UDP payload transmit core for `sys_sendto` and `sys_sendmsg`.
pub(super) fn send_udp_payload(
    socket: &net::SocketArc,
    ctx: &lsm::ProcessCtx,
    cap_id: cap::CapId,
    dst_ip: net::Ipv4Addr,
    dst_port: u16,
    data: &[u8],
) -> SyscallResult {
    let src_ip = net::select_source_ip(socket.local_ip(), dst_ip, socket.net_ns_id.0);
    let datagram = net::socket_table()
        .send_to_udp(socket, ctx, cap_id, src_ip, dst_ip, dst_port, data)
        .map_err(socket_error_to_syscall)?;

    net::transmit_udp_datagram_opts(
        (!src_ip.is_unspecified()).then_some(src_ip),
        dst_ip,
        &datagram,
        socket.net_ns_id.0,
        socket.ip_ttl(),
    )
    .map_err(tx_error_to_syscall)?;
    net::socket_table().commit_udp_send(socket, data.len());

    Ok(data.len())
}

/// Resolve the receive timeout from nonblock/MSG_DONTWAIT and `SO_RCVTIMEO`.
#[inline]
pub(super) fn resolve_recv_timeout(
    socket: &net::SocketState,
    nonblock: bool,
    flags: u32,
) -> (Option<u64>, bool) {
    if nonblock || (flags & MSG_DONTWAIT != 0) {
        return (Some(0), false);
    }
    let us = socket.rcvtimeo_us();
    if us > 0 {
        (Some(us.saturating_mul(1000)), true)
    } else {
        (None, false)
    }
}

/// sys_recvfrom - Receive data from socket (syscall 45).
///
/// Supports both UDP (connectionless) and TCP (connection-oriented) sockets.
/// For TCP: use with NULL src_addr for recv() semantics.
/// For UDP: use with non-NULL src_addr to get sender info.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `buf` - Buffer for received data
/// * `len` - Buffer length
/// * `flags` - Receive flags (MSG_DONTWAIT supported)
/// * `src_addr` - Buffer for source address (optional, NULL for TCP recv)
/// * `addrlen` - Pointer to address length (in/out)
///
/// # Security
/// - Verifies CapRights::READ
/// - Invokes LSM hook_net_recv for policy check
pub(super) fn sys_recvfrom(
    fd: i32,
    buf: *mut u8,
    len: usize,
    flags: i32,
    src_addr: *mut SockAddrIn,
    addrlen: *mut u32,
) -> SyscallResult {
    // Check flags
    let flag_bits = flags as u32;
    if flag_bits & !MSG_DONTWAIT != 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check READ right
    if !entry.rights.allows(cap::CapRights::READ) {
        return Err(SyscallError::EACCES);
    }

    // Determine socket type
    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;
    if !is_tcp && !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R159-12 FIX: Clamp to MAX_RW_SIZE, matching sys_read/sys_write. Keep
    // this after fd/capability/namespace/rights/type validation so a zero-size
    // request cannot turn an invalid handle into a false success.
    if len > MAX_RW_SIZE {
        return Err(SyscallError::EINVAL);
    }

    // TCP recv() semantics require a NULL source-address pointer. Validate the
    // operation shape before touching any user range or receive queue.
    if is_tcp && !src_addr.is_null() {
        return Err(SyscallError::EOPNOTSUPP);
    }
    if is_udp && !src_addr.is_null() && addrlen.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R160-1/RF180-27: validate a non-empty destination before a transactional
    // receive can expose data. A zero-length buffer may be NULL and performs no
    // payload copy, but UDP still consumes one whole datagram after optional
    // source-address copyout succeeds.
    if len != 0 {
        validate_user_ptr_mut(buf, len)?;
    }

    // Get current process context
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Determine timeout (0 for non-blocking, SO_RCVTIMEO if set, else blocking)
    let (timeout, has_rcvtimeo) = resolve_recv_timeout(&socket, nonblock, flag_bits);
    let map_recv_err = |error: net::RecvTransactionError<SyscallError>| match error {
        net::RecvTransactionError::Socket(net::SocketError::Timeout) if has_rcvtimeo => {
            SyscallError::EAGAIN
        }
        net::RecvTransactionError::Socket(error) => socket_error_to_syscall(error),
        net::RecvTransactionError::Commit(error) => error,
    };

    // TCP: recv() semantics when src_addr is NULL (connected socket)
    if is_tcp {
        let copied = net::socket_table()
            .tcp_recv_with_commit(&socket, &ctx, cap_id, len, timeout, |data| {
                if !data.is_empty() {
                    copy_to_user(buf, data)?;
                }
                Ok(())
            })
            .map_err(map_recv_err)?;
        return Ok(copied);
    }

    // Keep the exact datagram queued until payload and optional source address
    // have both copied successfully. A fault may leave partial destination
    // bytes, but retry observes the same source packet instead of data loss.
    net::socket_table()
        .recv_from_udp_with_commit(&socket, &ctx, cap_id, timeout, |pkt| {
            if !src_addr.is_null() {
                let sockaddr = SockAddrIn::from_addr(pkt.src_ip.0, pkt.src_port);
                write_sockaddr_in(&sockaddr, src_addr, addrlen)?;
            }
            let payload = pkt.payload();
            let copied = core::cmp::min(len, payload.len());
            if copied != 0 {
                let copy = payload.get(..copied).ok_or(SyscallError::EIO)?;
                copy_to_user(buf, copy)?;
            }
            Ok(copied)
        })
        .map_err(map_recv_err)
}

/// Shared vectored socket receive core for `sys_readv` and `sys_recvmsg`.
///
/// Returns `(bytes_copied, msg_flags)` where `msg_flags` sets `MSG_TRUNC` when
/// a UDP datagram was larger than the total iovec capacity.
pub(super) fn recv_socket_into_iovecs(
    fd: i32,
    iovs: &[Iovec],
    total_cap: usize,
    flag_bits: u32,
    msg_name_out: Option<(*mut u8, u32)>,
    msg_hdr_user: Option<*mut MsgHdr>,
) -> SyscallResult {
    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    if !entry.rights.allows(cap::CapRights::READ) {
        return Err(SyscallError::EACCES);
    }

    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;
    if !is_tcp && !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    if total_cap > MAX_RW_SIZE {
        return Err(SyscallError::EINVAL);
    }

    if total_cap != 0 {
        validate_iovecs_writable(iovs, total_cap)?;
    }

    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;
    let (timeout, has_rcvtimeo) = resolve_recv_timeout(&socket, nonblock, flag_bits);
    let map_recv_err = |error: net::RecvTransactionError<SyscallError>| match error {
        net::RecvTransactionError::Socket(net::SocketError::Timeout) if has_rcvtimeo => {
            SyscallError::EAGAIN
        }
        net::RecvTransactionError::Socket(error) => socket_error_to_syscall(error),
        net::RecvTransactionError::Commit(error) => error,
    };

    if is_tcp {
        let copied = net::socket_table()
            .tcp_recv_with_commit(&socket, &ctx, cap_id, total_cap, timeout, |data| {
                if !data.is_empty() {
                    copy_slice_to_iovecs(iovs, data)?;
                }
                if let Some(user_msg) = msg_hdr_user {
                    write_msghdr_out_fields(user_msg, None, 0)?;
                }
                Ok(())
            })
            .map_err(map_recv_err)?;
        return Ok(copied);
    }

    net::socket_table()
        .recv_from_udp_with_commit(&socket, &ctx, cap_id, timeout, |pkt| {
            let mut out_namelen: Option<u32> = None;
            if let Some((name_ptr, name_cap)) = msg_name_out {
                if !name_ptr.is_null() {
                    let sockaddr = SockAddrIn::from_addr(pkt.src_ip.0, pkt.src_port);
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes[0..2].copy_from_slice(&sockaddr.sin_family.to_ne_bytes());
                    addr_bytes[2..4].copy_from_slice(&sockaddr.sin_port.to_ne_bytes());
                    addr_bytes[4..8].copy_from_slice(&sockaddr.sin_addr);
                    let write_len = core::cmp::min(name_cap as usize, addr_bytes.len());
                    if write_len > 0 {
                        validate_user_ptr_mut(name_ptr, write_len)?;
                        copy_to_user(name_ptr, &addr_bytes[..write_len])?;
                    }
                    out_namelen = Some(addr_bytes.len() as u32);
                }
            }
            let payload = pkt.payload();
            let copied = core::cmp::min(total_cap, payload.len());
            if copied != 0 {
                let copy = payload.get(..copied).ok_or(SyscallError::EIO)?;
                copy_slice_to_iovecs(iovs, copy)?;
            }
            let out_flags = if payload.len() > total_cap {
                MSG_TRUNC as i32
            } else {
                0
            };
            if let Some(user_msg) = msg_hdr_user {
                write_msghdr_out_fields(user_msg, out_namelen, out_flags)?;
            }
            Ok(copied)
        })
        .map_err(map_recv_err)
}

/// Fault-tolerant decode of Linux x86_64 `struct msghdr` (56 bytes) from user space.
pub(super) fn read_msghdr_from_user(user_msg: *const MsgHdr) -> Result<MsgHdr, SyscallError> {
    if user_msg.is_null() {
        return Err(SyscallError::EFAULT);
    }
    validate_user_ptr(user_msg as *const u8, core::mem::size_of::<MsgHdr>())?;
    let mut raw = [0u8; 56];
    copy_from_user(&mut raw, user_msg as *const u8)?;
    Ok(MsgHdr {
        msg_name: usize::from_ne_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]) as *mut u8,
        msg_namelen: u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]),
        _pad0: u32::from_ne_bytes([raw[12], raw[13], raw[14], raw[15]]),
        msg_iov: usize::from_ne_bytes([
            raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
        ]) as *const Iovec,
        msg_iovlen: usize::from_ne_bytes([
            raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
        ]),
        msg_control: usize::from_ne_bytes([
            raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39],
        ]) as *mut u8,
        msg_controllen: usize::from_ne_bytes([
            raw[40], raw[41], raw[42], raw[43], raw[44], raw[45], raw[46], raw[47],
        ]),
        msg_flags: i32::from_ne_bytes([raw[48], raw[49], raw[50], raw[51]]),
        _pad1: u32::from_ne_bytes([raw[52], raw[53], raw[54], raw[55]]),
    })
}

/// Write `msg_namelen` (when updated), `msg_controllen = 0`, and `msg_flags` back to user `msghdr`.
pub(super) fn write_msghdr_out_fields(
    user_msg: *mut MsgHdr,
    out_namelen: Option<u32>,
    out_flags: i32,
) -> Result<(), SyscallError> {
    let base = user_msg as usize;
    if let Some(namelen) = out_namelen {
        let ptr = base
            .checked_add(core::mem::offset_of!(MsgHdr, msg_namelen))
            .ok_or(SyscallError::EFAULT)? as *mut u8;
        validate_user_ptr_mut(ptr, 4)?;
        copy_to_user(ptr, &namelen.to_ne_bytes())?;
    }
    let ctrl_ptr = base
        .checked_add(core::mem::offset_of!(MsgHdr, msg_controllen))
        .ok_or(SyscallError::EFAULT)? as *mut u8;
    validate_user_ptr_mut(ctrl_ptr, 8)?;
    copy_to_user(ctrl_ptr, &0usize.to_ne_bytes())?;

    let flags_ptr = base
        .checked_add(core::mem::offset_of!(MsgHdr, msg_flags))
        .ok_or(SyscallError::EFAULT)? as *mut u8;
    validate_user_ptr_mut(flags_ptr, 4)?;
    copy_to_user(flags_ptr, &out_flags.to_ne_bytes())?;
    Ok(())
}

/// sys_sendmsg - Send message on a socket using scatter-gather `msghdr` (syscall 46).
///
/// Supports `msg_iov` gather for both TCP and UDP. Returns `EOPNOTSUPP` when
/// `msg_controllen != 0` (ancillary control messages / SCM_RIGHTS deferred to N4).
pub(super) fn sys_sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> SyscallResult {
    let flag_bits = flags as u32;
    if flag_bits & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    if !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;
    if !is_tcp && !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    let hdr = read_msghdr_from_user(msg)?;

    // N2.8: ancillary/control messages are not supported yet.
    if hdr.msg_controllen != 0 {
        return Err(SyscallError::EOPNOTSUPP);
    }

    let iov_array = copy_iovec_array_from_user(hdr.msg_iov, hdr.msg_iovlen)?;
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    let has_name = !hdr.msg_name.is_null() && hdr.msg_namelen != 0;
    if !has_name {
        if !is_tcp {
            return Err(SyscallError::EDESTADDRREQ);
        }
        let data = gather_iovecs_from_user(
            &iov_array,
            mm::HeapClass::SocketPayload,
            net::tcp::TCP_MAX_SEND_SIZE,
            SyscallError::EMSGSIZE,
        )?;
        if data.is_empty() {
            let (bytes_sent, segments) = net::socket_table()
                .tcp_send(&socket, &ctx, cap_id, &[])
                .map_err(socket_error_to_syscall)?;
            debug_assert_eq!(bytes_sent, 0);
            debug_assert!(segments.is_empty());
            return Ok(0);
        }
        return send_tcp_payload(&socket, &ctx, cap_id, &data);
    }

    if !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    if socket.local_port().is_none() && !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    let dest = read_sockaddr_in(hdr.msg_name as *const SockAddrIn, hdr.msg_namelen)?;
    if dest.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }
    let dst_port = dest.port();
    if dst_port == 0 {
        return Err(SyscallError::EINVAL);
    }
    let dst_ip = net::Ipv4Addr(dest.ip_bytes());

    let data = gather_iovecs_from_user(
        &iov_array,
        mm::HeapClass::SocketPayload,
        UDP_MAX_PAYLOAD,
        SyscallError::EMSGSIZE,
    )?;
    send_udp_payload(&socket, &ctx, cap_id, dst_ip, dst_port, &data)
}

/// sys_recvmsg - Receive message from a socket into scatter-gather `msghdr` (syscall 47).
///
/// Supports `msg_iov` scatter for both TCP and UDP (sharing iovec helpers with
/// `sys_readv`). Returns `EOPNOTSUPP` when `msg_controllen != 0`.
pub(super) fn sys_recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> SyscallResult {
    let flag_bits = flags as u32;
    if flag_bits & !MSG_DONTWAIT != 0 {
        return Err(SyscallError::EINVAL);
    }

    // Validate fd first so bad fds report EBADF/ENOTSOCK before msghdr checks.
    let (_cap_id, _socket_id, _nonblock) = socket_handle_from_fd(fd)?;

    let hdr = read_msghdr_from_user(msg as *const MsgHdr)?;

    // N2.8: ancillary/control messages are not supported yet.
    if hdr.msg_controllen != 0 {
        return Err(SyscallError::EOPNOTSUPP);
    }
    if (hdr.msg_namelen as i32) < 0 {
        return Err(SyscallError::EINVAL);
    }

    let iov_array = copy_iovec_array_from_user(hdr.msg_iov, hdr.msg_iovlen)?;
    let total_cap = iovec_total_len(&iov_array)?;
    if total_cap > MAX_RW_SIZE {
        return Err(SyscallError::EINVAL);
    }

    let name_out = if hdr.msg_name.is_null() {
        None
    } else {
        Some((hdr.msg_name, hdr.msg_namelen))
    };

    recv_socket_into_iovecs(fd, &iov_array, total_cap, flag_bits, name_out, Some(msg))
}

/// sys_getsockname - Get local address bound to a socket (syscall 51).
pub(super) fn sys_getsockname(fd: i32, addr: *mut SockAddrIn, addrlen: *mut u32) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (_entry, socket) = resolve_socket(cap_id, socket_id)?;

    if addr.is_null() || addrlen.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let ip = socket.local_ip().unwrap_or([0, 0, 0, 0]);
    let port = socket.local_port().unwrap_or(0);
    let out = SockAddrIn::from_addr(ip, port);
    write_sockaddr_in(&out, addr, addrlen)?;
    Ok(0)
}

/// sys_getpeername - Get remote peer address of a connected socket (syscall 52).
pub(super) fn sys_getpeername(fd: i32, addr: *mut SockAddrIn, addrlen: *mut u32) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (_entry, socket) = resolve_socket(cap_id, socket_id)?;

    if addr.is_null() || addrlen.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // For TCP sockets, peername is only available once the connection is established
    // (or in a post-establishment closing state).
    if socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp {
        match socket.tcp_state() {
            Some(
                net::TcpState::Established
                | net::TcpState::CloseWait
                | net::TcpState::FinWait1
                | net::TcpState::FinWait2
                | net::TcpState::Closing
                | net::TcpState::LastAck
                | net::TcpState::TimeWait,
            ) => {}
            _ => return Err(SyscallError::ENOTCONN),
        }
    }

    let (rip, rport) = match (socket.remote_ip(), socket.remote_port()) {
        (Some(ip), Some(port)) if port != 0 => (ip, port),
        _ => return Err(SyscallError::ENOTCONN),
    };
    let out = SockAddrIn::from_addr(rip, rport);
    write_sockaddr_in(&out, addr, addrlen)?;
    Ok(0)
}

/// sys_setsockopt - Set options on a socket (syscall 54).
///
/// Mediated by `lsm::hook_net_setsockopt` (N2.8). Supports:
/// - `SOL_SOCKET`: `SO_REUSEADDR`, `SO_KEEPALIVE`, `SO_RCVBUF`, `SO_SNDBUF`,
///   `SO_RCVTIMEO`, `SO_SNDTIMEO`
/// - `IPPROTO_TCP`: `TCP_NODELAY` (TCP sockets only)
/// - `IPPROTO_IP`: `IP_TTL` (1..=255, or -1 to reset to default 64)
/// Returns `ENOPROTOOPT` for unsupported or read-only (`SO_TYPE`/`SO_ERROR`) options.
pub(super) fn sys_setsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *const u8,
    optlen: u32,
) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (_entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Mandatory LSM mediation for every setsockopt call.
    let proc_ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;
    let mut net_ctx = net::socket_table().ctx_from_socket(&socket);
    net_ctx.cap = Some(cap_id);
    lsm::hook_net_setsockopt(&proc_ctx, &net_ctx, level, optname).map_err(lsm_error_to_syscall)?;

    if (optlen as i32) < 0 {
        return Err(SyscallError::EINVAL);
    }

    let read_i32_opt = || -> Result<i32, SyscallError> {
        if optval.is_null() {
            return Err(SyscallError::EFAULT);
        }
        if optlen < 4 {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr(optval, 4)?;
        let mut bytes = [0u8; 4];
        copy_from_user(&mut bytes, optval)?;
        Ok(i32::from_ne_bytes(bytes))
    };

    let read_timeval_us = || -> Result<u64, SyscallError> {
        if optval.is_null() {
            return Err(SyscallError::EFAULT);
        }
        if optlen < 16 {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr(optval, 16)?;
        let mut bytes = [0u8; 16];
        copy_from_user(&mut bytes, optval)?;
        let tv_sec = i64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let tv_usec = i64::from_ne_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        if tv_sec < 0 || !(0..1_000_000).contains(&tv_usec) {
            return Err(SyscallError::EINVAL);
        }
        Ok((tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(tv_usec as u64))
    };

    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            let val = read_i32_opt()?;
            socket.set_reuseaddr(val != 0);
            Ok(0)
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {
            let val = read_i32_opt()?;
            socket.set_keepalive(val != 0);
            Ok(0)
        }
        (SOL_SOCKET, SO_RCVBUF) => {
            let val = read_i32_opt()?;
            let size = if val < 0 { 0u32 } else { val as u32 };
            socket.set_rcvbuf(size);
            Ok(0)
        }
        (SOL_SOCKET, SO_SNDBUF) => {
            let val = read_i32_opt()?;
            let size = if val < 0 { 0u32 } else { val as u32 };
            socket.set_sndbuf(size);
            Ok(0)
        }
        (SOL_SOCKET, SO_RCVTIMEO) => {
            let us = read_timeval_us()?;
            socket.set_rcvtimeo_us(us);
            Ok(0)
        }
        (SOL_SOCKET, SO_SNDTIMEO) => {
            let us = read_timeval_us()?;
            socket.set_sndtimeo_us(us);
            Ok(0)
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
                return Err(SyscallError::ENOPROTOOPT);
            }
            let val = read_i32_opt()?;
            socket.set_nodelay(val != 0);
            Ok(0)
        }
        (IPPROTO_IP, IP_TTL) => {
            let val = read_i32_opt()?;
            if val == -1 {
                socket.set_ip_ttl(net::DEFAULT_IP_TTL);
            } else if (1..=255).contains(&val) {
                socket.set_ip_ttl(val as u8);
            } else {
                return Err(SyscallError::EINVAL);
            }
            Ok(0)
        }
        _ => Err(SyscallError::ENOPROTOOPT),
    }
}

/// sys_getsockopt - Get options on a socket (syscall 55).
pub(super) fn sys_getsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *mut u8,
    optlen: *mut u32,
) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (_entry, socket) = resolve_socket(cap_id, socket_id)?;

    if optval.is_null() || optlen.is_null() {
        return Err(SyscallError::EFAULT);
    }

    validate_user_ptr_mut(optlen as *mut u8, 4)?;
    let mut len_bytes = [0u8; 4];
    copy_from_user(&mut len_bytes, optlen as *const u8)?;
    let provided_len = u32::from_ne_bytes(len_bytes);
    if (provided_len as i32) < 0 {
        return Err(SyscallError::EINVAL);
    }

    let write_bytes = |data: &[u8]| -> SyscallResult {
        let write_len = core::cmp::min(provided_len as usize, data.len());
        if write_len > 0 {
            validate_user_ptr_mut(optval, write_len)?;
            copy_to_user(optval, &data[..write_len])?;
        }
        let out_len = (write_len as u32).to_ne_bytes();
        copy_to_user(optlen as *mut u8, &out_len)?;
        Ok(0)
    };

    let write_i32 = |v: i32| -> SyscallResult { write_bytes(&v.to_ne_bytes()) };

    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => write_i32(i32::from(socket.reuseaddr())),
        (SOL_SOCKET, SO_KEEPALIVE) => write_i32(i32::from(socket.keepalive())),
        (SOL_SOCKET, SO_RCVBUF) => write_i32(socket.rcvbuf() as i32),
        (SOL_SOCKET, SO_SNDBUF) => write_i32(socket.sndbuf() as i32),
        (SOL_SOCKET, SO_TYPE) => {
            let raw_ty = match socket.ty {
                net::SocketType::Stream => 1,
                net::SocketType::Dgram => 2,
            };
            write_i32(raw_ty)
        }
        (SOL_SOCKET, SO_ERROR) => write_i32(socket.take_pending_error()),
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => {
            let us = if optname == SO_RCVTIMEO {
                socket.rcvtimeo_us()
            } else {
                socket.sndtimeo_us()
            };
            let tv_sec = (us / 1_000_000) as i64;
            let tv_usec = (us % 1_000_000) as i64;
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
            buf[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
            write_bytes(&buf)
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
                return Err(SyscallError::ENOPROTOOPT);
            }
            write_i32(i32::from(socket.nodelay()))
        }
        (IPPROTO_IP, IP_TTL) => write_i32(socket.ip_ttl() as i32),
        _ => Err(SyscallError::ENOPROTOOPT),
    }
}

/// sys_shutdown - Shutdown TCP connection (syscall 48).
///
/// Implements graceful connection shutdown per RFC 793.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `how` - Shutdown mode: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
///
/// # State Transitions
/// - ESTABLISHED + SHUT_WR → FIN_WAIT_1 (sends FIN)
/// - CLOSE_WAIT + SHUT_WR → LAST_ACK (sends FIN)
///
/// # Security
/// - Verifies CapRights::WRITE for SHUT_WR/SHUT_RDWR
/// - Invokes LSM hook_net_shutdown for policy check
pub(super) fn sys_shutdown(fd: i32, how: i32) -> SyscallResult {
    // Validate how parameter
    const SHUT_RD: i32 = 0;
    const SHUT_WR: i32 = 1;
    const SHUT_RDWR: i32 = 2;

    if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets support shutdown
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // WRITE right required for SHUT_WR or SHUT_RDWR
    if how != SHUT_RD && !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // Get current process context
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Call tcp_shutdown
    match net::socket_table().tcp_shutdown(&socket, &ctx, cap_id, how) {
        Ok(Some(fin_segment)) => {
            // Transmit the FIN segment
            if let Some(dst_ip) = socket.remote_ip() {
                let src_ip = socket
                    .local_ip()
                    .map(net::Ipv4Addr)
                    .filter(|ip| !ip.is_unspecified());
                let _ = net::transmit_tcp_segment_opts(
                    src_ip,
                    net::Ipv4Addr(dst_ip),
                    &fin_segment,
                    socket.net_ns_id.0,
                    socket.ip_ttl(),
                );
            }
            Ok(0)
        }
        Ok(None) => Ok(0), // SHUT_RD or FIN already sent
        Err(e) => Err(socket_error_to_syscall(e)),
    }
}
