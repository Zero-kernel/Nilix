//! Socket capability layer for Zero-OS (Phase D.2)
//!
//! This module provides a capability-based socket API with security-first design:
//!
//! - **Capability-Based Access**: Sockets are accessed via CapId handles
//! - **LSM Integration**: All operations pass through security hooks
//! - **Rate Limiting**: Per-socket and global limits prevent DoS
//! - **Security Labels**: Sockets carry creator context for MAC enforcement
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |  User Syscall    | --> |  SocketTable     | --> |  SocketState     |
//! |  (via CapId)     |     |  (global lookup) |     |  (per-socket)    |
//! +------------------+     +------------------+     +------------------+
//!                                  |                        |
//!                                  v                        v
//!                          +------------------+     +------------------+
//!                          |  Port Bindings   |     |  RX Queue        |
//!                          |  (UDP port map)  |     |  (datagrams)     |
//!                          +------------------+     +------------------+
//! ```
//!
//! # Security Features
//!
//! 1. **Capability Checks**: Each syscall validates CapId and rights
//! 2. **LSM Hooks**: create/bind/send/recv pass through hook_net_*
//! 3. **Socket Labels**: Creator credentials captured for MAC decisions
//! 4. **Queue Limits**: MAX_RX_QUEUE prevents memory exhaustion
//! 5. **Port Validation**: Privileged ports require root or capability
//!
//! # Example Flow
//!
//! ```text
//! 1. sys_socket() -> LSM hook_net_socket -> create SocketState -> CapId
//! 2. sys_bind()   -> LSM hook_net_bind   -> allocate port
//! 3. sys_sendto() -> LSM hook_net_send   -> build UDP datagram
//! 4. sys_recvfrom() -> wait on RX queue  -> LSM hook_net_recv -> return data
//! ```
//!
//! # References
//!
//! - POSIX.1-2017 Socket Interface
//! - RFC 768: UDP Protocol

use alloc::alloc::Global;
use alloc::sync::{Arc, Weak};
use core::alloc::{AllocError, Allocator, Layout};
use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use cap::{CapId, NamespaceId};
use lsm::{
    hook_net_bind, hook_net_connect, hook_net_listen, hook_net_recv, hook_net_send,
    hook_net_shutdown, hook_net_socket, LsmError, NetCtx, ProcessCtx,
};

use crate::admitted::{AdmittedMap, AdmittedVec, WirePacket};
use crate::ipv4::Ipv4Addr;
use crate::stack::transmit_tcp_segment;
use crate::tcp::{
    build_tcp_segment, build_tcp_segment_with_options, calc_wscale, decode_window, encode_window,
    generate_isn, generate_syn_cookie_isn, handle_ack, handle_retransmission_timeout, initial_cwnd,
    seq_ge, seq_gt, seq_in_window, syn_cookie_select_mss, try_build_tcp_segment_admitted,
    try_build_tcp_segment_with_options, update_congestion_control, validate_syn_cookie,
    CongestionAction, PendingHandshakeCommit, SackBlock, TcpConnKey, TcpControlBlock, TcpHeader,
    TcpOptionKind, TcpOptions, TcpSegment, TcpState, TCP_DEFAULT_WINDOW, TCP_ETHERNET_MSS,
    TCP_FIN_TIMEOUT_MS, TCP_FIN_WAIT_2_TIMEOUT_MS, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH,
    TCP_FLAG_RST, TCP_FLAG_SYN, TCP_MAX_ACCEPT_BACKLOG, TCP_MAX_ACTIVE_CONNECTIONS,
    TCP_MAX_FIN_RETRIES, TCP_MAX_RETRIES, TCP_MAX_RTO_MS, TCP_MAX_SEND_BUFFER_BYTES,
    TCP_MAX_SEND_SIZE, TCP_MAX_SYN_BACKLOG, TCP_MAX_WINDOW_SCALE, TCP_PROTO, TCP_SYN_TIMEOUT_MS,
    TCP_TIME_WAIT_MS,
};
use crate::udp::{
    build_udp_datagram, UdpError, EPHEMERAL_PORT_END, EPHEMERAL_PORT_START, UDP_PROTO,
};
use mm::{arc_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};

// ============================================================================
// Charged Arc Allocator (RF180-25)
// ============================================================================

/// Maximum number of simultaneously live socket-owned Arc allocations.
///
/// The SocketObject class is capped at 256 KiB. Even a zero-sized Arc payload
/// is charged at least 32 bytes (two Arc counters plus allocator-link slack),
/// so the byte admission gate can never authorize more than 8192 live Arc
/// allocations. The slots live in static storage and therefore do not consume
/// or recursively depend on the heap they account.
const SOCKET_ARC_CHARGE_SLOTS: usize = 8192;

struct SocketArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static SOCKET_ARC_CHARGES: Mutex<[Option<SocketArcChargeSlot>; SOCKET_ARC_CHARGE_SLOTS]> =
    Mutex::new([const { None }; SOCKET_ARC_CHARGE_SLOTS]);
static NEXT_SOCKET_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_SOCKET_OWNER_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_TCP_EGRESS_TOKEN: AtomicU64 = AtomicU64::new(1);

fn next_nonzero_generation(counter: &AtomicU64) -> Result<u64, SocketError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .ok()
        .filter(|generation| *generation != 0)
        .ok_or(SocketError::IdExhausted)
}

/// Allocator carried by every socket-owned Arc/Weak handle.
///
/// RF180-25 FIX: the charge is stored in a fixed static slot rather than in
/// `T`. `Arc` invokes `deallocate` only when the final strong *and* weak owner
/// are gone; this allocator frees the Arc control block first and releases the
/// slot's `HeapCharge` second. Cloning the allocator copies only a
/// `(slot, generation)` capability; slot-locked single-use state prevents a
/// copied capability from allocating any additional uncharged backing.
#[derive(Clone, Copy, Debug)]
pub struct SocketArcAllocator {
    slot: u16,
    generation: u64,
}

impl SocketArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_SOCKET_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = SOCKET_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(SocketArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge.take().expect("socket Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("socket Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = SOCKET_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-25 socket Arc allocator slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-25 stale socket Arc allocator generation"),
            None => panic!("RF180-25 socket Arc charge released twice"),
        }
        slot.take()
            .expect("validated socket Arc charge disappeared")
            .charge
    }

    /// Cancel a prepared allocator after `Arc::try_new_in` reports allocation
    /// failure. No allocation exists in this path, so releasing the reservation
    /// is correct and cannot race a future deallocation callback.
    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }

    #[cfg(test)]
    fn charge_is_live_for_test(self) -> bool {
        SOCKET_ARC_CHARGES
            .lock()
            .get(self.slot as usize)
            .and_then(Option::as_ref)
            .is_some_and(|entry| entry.generation == self.generation)
    }
}

unsafe impl Allocator for SocketArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = SOCKET_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        match Global.allocate(layout) {
            Ok(allocation) => Ok(allocation),
            Err(error) => {
                // Arc::try_new_in may retry only after a failed allocation. Roll
                // the single-use bit back while retaining the charge slot.
                let mut slots = SOCKET_ARC_CHARGES.lock();
                if let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) {
                    if entry.generation == self.generation {
                        entry.allocated = false;
                    }
                }
                Err(error)
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // RF180-25 FIX: allocator memory first, admission second. A new socket
        // allocation cannot consume these bytes while the old Arc control block
        // is still physically live.
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_charge());
    }
}

pub type SocketArc = Arc<SocketState, SocketArcAllocator>;
type SocketWeak = Weak<SocketState, SocketArcAllocator>;
pub type WaitQueueArc = Arc<WaitQueue, SocketArcAllocator>;

fn try_new_socket_arc<T>(value: T) -> Result<Arc<T, SocketArcAllocator>, SocketError> {
    let bytes = arc_charge_bytes::<T>().map_err(|_| SocketError::NoMemory)?;
    let reservation =
        try_reserve_heap(HeapClass::SocketObject, bytes).map_err(|_| SocketError::NoMemory)?;
    let charge = reservation.commit().map_err(|_| SocketError::NoMemory)?;
    let allocator = SocketArcAllocator::try_install(charge).map_err(|charge| {
        drop(charge);
        SocketError::NoMemory
    })?;
    match Arc::try_new_in(value, allocator) {
        Ok(value) => Ok(value),
        Err(_) => {
            allocator.cancel_failed_allocation();
            Err(SocketError::NoMemory)
        }
    }
}

// ============================================================================
// Simple Wait Primitives (local to net crate to avoid ipc dependency)
// ============================================================================

/// Wait operation outcome.
///
/// Represents the result of a blocking wait operation.
/// Used by both socket waits and futex operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Resource became available (waiter was explicitly woken)
    Woken,
    /// Operation timed out
    TimedOut,
    /// Resource closed (socket/queue closed while waiting)
    Closed,
    /// No process context available (called from kernel context)
    NoProcess,
    /// R171 (F3): the waiting task has a pending kill — abort the blocking
    /// syscall with EINTR instead of re-parking (the unkillable-blocked class).
    Interrupted,
}

// ============================================================================
// Socket Wait Hooks (Scheduler Integration)
// ============================================================================

/// Scheduler integration hooks for socket blocking waits.
///
/// This trait allows the net crate to perform true blocking waits without
/// depending on kernel_core's process/scheduler implementation directly.
/// kernel_core registers an implementation at initialization time.
///
/// # Design
///
/// The trait design follows the same pattern as stdin blocking in syscall.rs:
/// 1. Mark process as Blocked
/// 2. Add to waiter queue
/// 3. Call force_reschedule to yield CPU
/// 4. On wakeup, check condition and return outcome
///
/// # Safety
///
/// Implementations must:
/// - Properly handle interrupt disabling during state transitions
/// - Not hold locks across reschedule calls to avoid deadlock
/// - Clean up waiter entries on timeout or close
pub trait SocketWaitHooks: Send + Sync {
    /// Block the current task until woken, timed out, or the queue is closed.
    ///
    /// # Arguments
    /// * `queue` - The wait queue to block on
    /// * `timeout_ns` - Optional timeout in nanoseconds:
    ///   - `None`: Block indefinitely
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///
    /// # Returns
    /// * `Woken` - Explicitly woken by wake_one/wake_all
    /// * `TimedOut` - Timeout expired before wakeup
    /// * `Closed` - Queue was closed while waiting
    /// * `NoProcess` - No current process context (kernel thread)
    fn wait(&self, queue: &WaitQueue, timeout_ns: Option<u64>) -> WaitOutcome;

    /// Wake one waiter blocked on this queue.
    ///
    /// If multiple waiters are blocked, wakes the one that blocked first (FIFO).
    fn wake_one(&self, queue: &WaitQueue);

    /// Wake all waiters blocked on this queue.
    fn wake_all(&self, queue: &WaitQueue);

    /// Get the current kernel tick count (monotonic milliseconds since boot).
    ///
    /// Used for TIME_WAIT timer initialization when the periodic sweep hasn't
    /// yet primed the cached clock. This provides accurate timing instead of
    /// relying on TSC assumptions.
    ///
    /// # R51-6 Enhancement
    ///
    /// Replaces the RDTSC-based fallback which assumed a 2GHz TSC frequency.
    /// The kernel tick counter is calibrated and reliable.
    fn get_ticks(&self) -> u64;
}

/// Static storage for the registered wait hooks.
///
/// Uses spin::Once to ensure thread-safe one-time initialization.
/// After initialization, the reference is valid for the lifetime of the kernel.
static SOCKET_WAIT_HOOKS: spin::Once<&'static dyn SocketWaitHooks> = spin::Once::new();

/// Register kernel scheduler hooks for socket waits.
///
/// This should be called once during kernel initialization from kernel_core::init().
/// Multiple calls are safe - only the first registration takes effect.
///
/// # Arguments
/// * `hooks` - Static reference to a SocketWaitHooks implementation
pub fn register_socket_wait_hooks(hooks: &'static dyn SocketWaitHooks) {
    SOCKET_WAIT_HOOKS.call_once(|| hooks);
}

/// Read CPU timestamp counter for low-quality entropy fallback.
///
/// Used when CSPRNG is unavailable to provide unpredictable port selection.
/// Not cryptographically secure but better than a monotonic counter.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn rdtsc() -> u64 {
    // Fallback for non-x86_64: use a constant that will be mixed with counter
    0xa5a5_5a5a_d3e4_c7d2_u64
}

/// Get the registered wait hooks, if any.
#[inline]
fn socket_wait_hooks() -> Option<&'static dyn SocketWaitHooks> {
    SOCKET_WAIT_HOOKS.get().copied()
}

/// R162-20 FIX: Public helper for stack.rs to get kernel ticks via hooks.
pub fn socket_wait_hooks_get_ticks() -> Option<u64> {
    socket_wait_hooks().map(|h| h.get_ticks())
}

// ============================================================================
// J2-8: Per-cgroup ephemeral-port budget upcall (CgroupPortHooks)
// ============================================================================
//
// The `net` crate cannot depend on `kernel_core::cgroup` (kernel_core depends on
// net -> a direct call would be a dependency cycle). So per-cgroup port charging
// is injected via a trait object registered by kernel_core at boot, exactly like
// `SocketWaitHooks`. kernel_core's impl forwards to `cgroup::try_charge_ports` /
// `cgroup::uncharge_ports` and `process::current_cgroup_id`.

/// Hooks for charging a per-cgroup ephemeral-port budget (J.2 item 8).
///
/// All three methods run in the contexts the lock-ordering invariant allows:
/// `current_cgroup_id` and `try_charge_ports` only from process (syscall)
/// context BEFORE any net-binding lock is taken; `uncharge_ports` only from the
/// process-context deferred-uncharge drain or the direct teardown sites AFTER
/// every binding lock is dropped (never under an L8 binding lock, never in IRQ).
pub trait CgroupPortHooks: Send + Sync {
    /// Current task's cgroup id, or `None` for non-process (kernel-thread / RX)
    /// callers. `None` and root both resolve to 0 (exempt) at the call site.
    fn current_cgroup_id(&self) -> Option<u64>;
    /// Hierarchically charge one ephemeral port against `cgid` and its NET
    /// ancestors. `Err(())` on `ports.max` exceeded (mapped to EAGAIN by net).
    fn try_charge_ports(&self, cgid: u64, n: u64) -> Result<(), ()>;
    /// Hierarchically uncharge `n` ephemeral ports from `cgid` (saturating).
    fn uncharge_ports(&self, cgid: u64, n: u64);
}

static CGROUP_PORT_HOOKS: spin::Once<&'static dyn CgroupPortHooks> = spin::Once::new();

/// Register the per-cgroup port-budget hooks (called once from kernel_core init).
pub fn register_cgroup_port_hooks(hooks: &'static dyn CgroupPortHooks) {
    CGROUP_PORT_HOOKS.call_once(|| hooks);
}

#[inline]
fn cgroup_port_hooks() -> Option<&'static dyn CgroupPortHooks> {
    CGROUP_PORT_HOOKS.get().copied()
}

// ============================================================================
// D1-ISO-NETNS-DATAPLANE: Device ownership verification hook
// ============================================================================
//
// The TX path (build_frame_and_transmit, transmit_prepared_reply, etc.) resolves
// the eth0 device globally. A socket in a child netns (created via CLONE_NEWNET,
// no devices in the namespace) can currently transmit out the root ns's eth0/IP/MAC.
// This hook gates TX on device ownership: the socket's netns must own the target device.

/// Verify whether a network namespace owns a device.
///
/// # Design
/// Net crate cannot depend on kernel_core (dependency cycle). Ownership queries
/// are injected via a trait object, following the SocketWaitHooks + CgroupPortHooks pattern.
///
/// # Semantics
/// - Root namespace (ns_id == 0) owns all registered devices by default.
/// - Child namespaces own only devices explicitly added via NetNamespace::add_device/move_device.
/// - Early boot (hook not yet registered): default to allowing ns_id == 0 only.
pub trait NetNsDeviceHooks: Send + Sync {
    /// Check if namespace ns_id owns device_index.
    /// Returns true iff the device was added to the namespace via add_device or move_device.
    fn ns_owns_device(&self, ns_id: u64, device_index: u32) -> bool;

    /// D3-NETNS-DATAPLANE: Return namespace `ns_id`'s ARP cache, or `None`
    /// if the namespace is unknown or already destroyed (fail-closed).
    ///
    /// Returns the cache Arc (not the namespace) so callers hold no
    /// namespace reference while processing ARP: dropping the returned Arc
    /// can never run `NetNamespace::Drop` teardown. The implementation must
    /// drop any namespace handle it upgrades BEFORE returning, outside any
    /// registry guard (see kernel_core's `lookup_net_ns` lock contract).
    ///
    /// LIVENESS CONTRACT (Codex round-2): `Some` proves the namespace was
    /// alive AT LOOKUP only. The namespace may be destroyed while the caller
    /// still holds the cache Arc; the orphaned cache stays memory-safe and
    /// private (never another namespace's), and in-flight ARP work merely
    /// completes against it. A future production RX loop that must not emit
    /// replies for dead namespaces has to pin liveness for the frame's whole
    /// lifetime or revalidate before emission — that is the Phase I.3
    /// revocation leg (ownership generation / token pinning), NOT this hook.
    fn ns_arp_cache(&self, ns_id: u64) -> Option<Arc<Mutex<crate::arp::ArpCache>>>;

    /// D3 NETNS-CONFIG: Return namespace `ns_id`'s network configuration
    /// (addresses, gateway, subnet prefix), or `None` if the namespace is
    /// unknown, destroyed, or has no configuration yet — three states the
    /// dataplane deliberately treats identically (fail-closed: no usable
    /// network identity, Codex round-9 Q2).
    ///
    /// Root (ns 0) must resolve to the net crate's global config — the
    /// implementation DELEGATES rather than storing a root copy, so root
    /// addressing has a single authority that cannot drift from the
    /// pre-registration fallback.
    ///
    /// Same liveness + lock contract as [`Self::ns_arp_cache`]: the value
    /// is a `Copy` snapshot taken under the namespace's own config lock and
    /// returned with no lock held across the return; `Some` proves the
    /// namespace was alive AT LOOKUP only. A send racing namespace death
    /// merely completes with the snapshot it acquired — the TX ownership
    /// gate downstream still denies egress for a namespace that owns no
    /// device.
    fn ns_net_config(&self, ns_id: u64) -> Option<crate::stack::NetConfigSnapshot>;
}

static NETNS_DEVICE_HOOKS: spin::Once<&'static dyn NetNsDeviceHooks> = spin::Once::new();

/// Register namespace device ownership hooks (called from kernel_core::init).
pub fn register_netns_device_hooks(hooks: &'static dyn NetNsDeviceHooks) {
    NETNS_DEVICE_HOOKS.call_once(|| hooks);
}

#[inline]
fn netns_device_hooks() -> Option<&'static dyn NetNsDeviceHooks> {
    NETNS_DEVICE_HOOKS.get().copied()
}

/// Single owner predicate for TX device-ownership decisions (used by stack.rs).
///
/// Fail-closed contract:
/// - Hook registered   => exactly the hook's answer (kernel_core registry truth).
/// - Hook unregistered => only the root namespace (ns 0) may use any device.
///   Registration precedes userspace (kernel_core::init), so no child netns can
///   exist while unregistered; this arm only covers early boot / host tests.
#[inline]
pub fn netns_owns_device(ns_id: u64, device_index: u32) -> bool {
    match netns_device_hooks() {
        Some(hooks) => hooks.ns_owns_device(ns_id, device_index),
        None => ns_id == 0,
    }
}

/// D3-NETNS-DATAPLANE: Resolve namespace `ns_id`'s ARP cache through the
/// registered hook (used by stack.rs for RX ARP processing and TX MAC
/// resolution).
///
/// Fail-closed contract:
/// - Hook registered + live namespace => that namespace's cache.
/// - Hook registered + unknown/destroyed namespace => `None`.
/// - Hook unregistered (early boot / host tests) => `None`; callers decide
///   their own pre-registration fallback via
///   [`netns_device_hooks_registered`] (the TX path falls back to the global
///   root cache; the RX ARP path drops the frame).
#[inline]
pub fn netns_arp_cache(ns_id: u64) -> Option<Arc<Mutex<crate::arp::ArpCache>>> {
    netns_device_hooks().and_then(|hooks| hooks.ns_arp_cache(ns_id))
}

/// D3 NETNS-CONFIG: Resolve namespace `ns_id`'s network configuration
/// through the registered hook (used by the TX path's `tx_net_config`).
///
/// Fail-closed contract:
/// - Hook registered => the hook's answer (`None` for unknown / destroyed /
///   unconfigured namespaces — deliberately collapsed).
/// - Hook unregistered (early boot / host tests) => `None`; callers decide
///   their own pre-registration fallback via
///   [`netns_device_hooks_registered`] (the TX path admits root only, from
///   the global config).
#[inline]
pub fn netns_net_config(ns_id: u64) -> Option<crate::stack::NetConfigSnapshot> {
    netns_device_hooks().and_then(|hooks| hooks.ns_net_config(ns_id))
}

/// D3-NETNS-DATAPLANE: Whether the kernel_core namespace hooks are live.
///
/// Lets callers distinguish "namespace lookup failed" (fail-closed) from
/// "pre-registration window" (early boot / host tests, root-only traffic).
#[inline]
pub fn netns_device_hooks_registered() -> bool {
    NETNS_DEVICE_HOOKS.get().is_some()
}

/// Resolve the current task's cgroup id for a port charge, or 0 (root / exempt)
/// when there is no process context or no hook is registered yet.
///
/// Fail-open is SAFE here: a non-zero cgid is only ever produced by a real
/// userspace process attached to a non-root cgroup, which cannot exist before
/// the hook is registered at boot (the registration precedes userspace), so the
/// charge/uncharge helpers below are never reached with `cgid != 0` while
/// unregistered. This mirrors how the other controllers short-circuit cgid 0.
#[inline]
fn resolve_port_cgroup() -> u64 {
    cgroup_port_hooks()
        .and_then(|h| h.current_cgroup_id())
        .unwrap_or(0)
}

/// Charge one ephemeral port against `cgid` (process context, before any binding
/// lock). Returns `QuotaExceeded` (-> EAGAIN) when `ports.max` is hit. A 0 cgid
/// (root / no process / pre-registration) is a no-op success.
#[inline]
fn try_charge_port_cgroup(cgid: u64) -> Result<(), SocketError> {
    if cgid == 0 {
        return Ok(());
    }
    match cgroup_port_hooks() {
        Some(h) => h
            .try_charge_ports(cgid, 1)
            .map_err(|_| SocketError::QuotaExceeded),
        None => Ok(()), // unreachable with cgid != 0 (see resolve_port_cgroup)
    }
}

/// Uncharge `n` ephemeral ports from `cgid`. Process context only (drain / direct
/// teardown after all binding locks are dropped). A 0 cgid is a no-op.
#[inline]
fn uncharge_port_cgroup(cgid: u64, n: u64) {
    if cgid == 0 || n == 0 {
        return;
    }
    if let Some(h) = cgroup_port_hooks() {
        h.uncharge_ports(cgid, n);
    }
}

/// Simple wait queue with optional scheduler integration.
///
/// When SocketWaitHooks are registered, this queue supports true blocking
/// with timeout. Without hooks, only non-blocking polling is supported.
///
/// # Architecture
///
/// The queue maintains:
/// - A closed flag to signal permanent closure
/// - A wakeup counter for detecting spurious wakeups
///
/// Actual waiter tracking is delegated to the SocketWaitHooks implementation
/// in kernel_core, which has access to the process table and scheduler.
pub struct WaitQueue {
    /// Flag indicating if the queue is closed
    closed: AtomicBool,
    /// Wakeup counter (incremented on wake, read on wait to detect wakeup).
    ///
    /// R153-I3 NOTE: Under sustained traffic, wake_one()/wake_all() accumulate
    /// tokens faster than waiters consume them. This is benign — the 2^64
    /// wraparound is non-exploitable, and try_consume_wakeup() returns early
    /// `Woken` (not a spin loop). If this becomes a performance concern under
    /// heavy load, consider a generation counter or 0/1 pending-wake flag.
    wakeup_count: AtomicU64,
}

impl WaitQueue {
    /// Create a new wait queue.
    pub fn new(_class: HeapClass) -> Self {
        WaitQueue {
            closed: AtomicBool::new(false),
            wakeup_count: AtomicU64::new(0),
        }
    }

    /// Allocate a standalone wait queue under the global socket-object gate.
    fn try_new_arc() -> Result<WaitQueueArc, SocketError> {
        try_new_socket_arc(Self::new(HeapClass::SocketObject))
    }

    /// Try to consume one pending wake token.
    ///
    /// Returns `true` if a token was consumed.
    ///
    /// R152-2 FIX: SocketWaitHooks implementations must consume wake tokens
    /// *after* waiter registration to avoid missed-wakeup races.
    pub fn try_consume_wakeup(&self) -> bool {
        self.wakeup_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current > 0).then(|| current - 1)
            })
            .is_ok()
    }

    /// Wait with optional timeout.
    ///
    /// # Arguments
    /// * `timeout_ns` - Timeout in nanoseconds.
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///   - `None`: Block indefinitely
    ///
    /// # Returns
    /// - `WaitOutcome::Woken` if wakeup was signaled
    /// - `WaitOutcome::TimedOut` if timeout expired or non-blocking poll
    /// - `WaitOutcome::Closed` if the queue is closed
    /// - `WaitOutcome::NoProcess` if no process context (kernel thread)
    pub fn wait_with_timeout(&self, timeout_ns: Option<u64>) -> WaitOutcome {
        // Check if closed
        if self.closed.load(Ordering::Acquire) {
            return WaitOutcome::Closed;
        }

        // Non-blocking poll returns immediately
        if timeout_ns == Some(0) {
            return WaitOutcome::TimedOut;
        }

        // R152-2 FIX: Delegate to scheduler hooks for true blocking.
        // Wake token consumption must happen *after* waiter registration inside
        // the hooks implementation, otherwise a wake that arrives between the
        // pre-check and registration is missed.
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wait(self, timeout_ns)
        } else if self.try_consume_wakeup() {
            WaitOutcome::Woken
        } else {
            // No scheduler hooks registered - fall back to non-blocking.
            // This happens early in boot or in kernel threads.
            WaitOutcome::TimedOut
        }
    }

    /// Signal one waiter.
    ///
    /// Wakes the first blocked waiter (FIFO order). If no waiters are blocked,
    /// increments the wakeup counter so the next wait() sees it.
    pub fn wake_one(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_one(self);
        }
    }

    /// Signal all waiters.
    ///
    /// Wakes all blocked waiters. If no waiters are blocked, increments the
    /// wakeup counter.
    pub fn wake_all(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_all(self);
        }
    }

    /// Close the queue and prevent further waits.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new(HeapClass::SocketObject)
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum queued datagrams per socket.
///
/// This limit prevents memory exhaustion attacks. When the queue is full,
/// new datagrams are dropped (not an error - normal network behavior).
const MAX_RX_QUEUE: usize = 64;

/// R132-4 FIX: Maximum aggregate UDP payload bytes queued across all sockets.
///
/// Prevents memory exhaustion when many UDP sockets each buffer large datagrams.
/// 16 MiB is a conservative cap: enough for normal traffic (~250 full-size
/// datagrams) but prevents unbounded kernel heap growth from UDP flooding.
const MAX_GLOBAL_UDP_QUEUED_BYTES: usize = 16 * 1024 * 1024;

/// R132-4 FIX: Global accounting of UDP payload bytes currently queued.
///
/// Incremented atomically in `enqueue_rx()`, decremented in `pop_rx()` and
/// `SocketState::drop()` (for unread datagrams still queued at socket close).
static GLOBAL_UDP_QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Privileged port boundary (ports below this require special permissions).
const PRIVILEGED_PORT_LIMIT: u16 = 1024;

/// RF178-30 / R180-L2 FIX: Accept a segment when either its first or last
/// sequence-space position is inside the receive window.  FIN contributes one
/// position even when every payload byte is duplicate.
#[inline]
fn segment_in_recv_window(
    seq: u32,
    payload_len: usize,
    has_fin: bool,
    rcv_nxt: u32,
    rcv_wnd: u32,
) -> bool {
    let wnd = rcv_wnd.max(1);
    let payload_len = match u32::try_from(payload_len) {
        Ok(len) => len,
        Err(_) => return false,
    };
    // R180-L2 FIX: SEG.LEN includes FIN's sequence-space byte.  A retransmission
    // may have no new payload bytes while its FIN is exactly RCV.NXT; treating
    // only payload bytes as the segment range rejects that new FIN before the
    // overlap path can consume it.  Compute the last sequence-space position
    // with wrapping arithmetic, as required by RFC 793 serial-number semantics.
    let sequence_len = match payload_len.checked_add(u32::from(has_fin)) {
        Some(len) => len,
        None => return false,
    };
    seq_in_window(seq, rcv_nxt, wnd)
        || (sequence_len != 0
            && seq_in_window(seq.wrapping_add(sequence_len).wrapping_sub(1), rcv_nxt, wnd))
}

/// True when every payload byte is left of RCV.NXT but the segment's FIN is
/// the next unconsumed sequence-space byte.
#[inline]
fn duplicate_payload_has_new_fin(
    seq: u32,
    payload_len: usize,
    has_fin: bool,
    rcv_nxt: u32,
) -> bool {
    has_fin
        && u32::try_from(payload_len)
            .ok()
            .map_or(false, |len| seq.wrapping_add(len) == rcv_nxt)
}

// ============================================================================
// Challenge ACK Rate Limiting (R54-2 FIX)
// ============================================================================

/// Maximum challenge ACKs per window period (RFC 5961 rate limiting).
///
/// R54-2 FIX: Prevents amplification attacks via spoofed RST packets.
/// Linux default: 100/sec (tcp_challenge_ack_limit sysctl).
const CHALLENGE_ACK_LIMIT: u32 = 100;

/// Challenge ACK rate limiting window in milliseconds.
const CHALLENGE_ACK_WINDOW_MS: u64 = 1000;

/// Token bucket for challenge ACK rate limiting.
static CHALLENGE_ACK_TOKENS: AtomicU32 = AtomicU32::new(CHALLENGE_ACK_LIMIT);

/// Window start time for challenge ACK rate limiter.
static CHALLENGE_ACK_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if a challenge ACK can be sent (rate limiter).
///
/// R54-2 FIX: Implements token bucket rate limiting for challenge ACKs
/// to prevent amplification attacks via spoofed RST packets.
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
///
/// # Returns
///
/// `true` if a challenge ACK can be sent, `false` if rate limit exceeded.
///
/// # Security
///
/// Without this check, an attacker could send high-rate spoofed RST packets
/// with invalid sequence numbers, causing the victim to generate unlimited
/// challenge ACKs. This consumes CPU and bandwidth, and can be used as a
/// reflection/amplification attack vector.
fn allow_challenge_ack(now_ms: u64) -> bool {
    // R121-6 FIX: Use compare_exchange on window start so only one CPU
    // wins the reset race. Without CAS, multiple CPUs can simultaneously
    // observe the window as expired and all refill tokens to the full limit.
    //
    // R155-13 FIX: Refill tokens only on CAS success to prevent a losing CPU
    // from overwriting tokens the winner already spent.
    // Release on CAS pairs with Acquire on window_start load to ensure
    // the token store is visible to any CPU that sees the new window.
    let window_start = CHALLENGE_ACK_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= CHALLENGE_ACK_WINDOW_MS {
        if CHALLENGE_ACK_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            CHALLENGE_ACK_TOKENS.store(CHALLENGE_ACK_LIMIT, Ordering::Release);
        }
    }

    // Try to consume a token using CAS loop
    let mut tokens = CHALLENGE_ACK_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match CHALLENGE_ACK_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }

    // Rate limit exceeded - drop the challenge ACK
    false
}

// ============================================================================
// RST Rate Limiting (R63-4 FIX)
// ============================================================================

/// Maximum RST packets per window period.
///
/// R63-4 FIX: Prevents amplification attacks via spoofed packets that trigger
/// RST responses. Without this limit, attackers can send invalid packets to
/// cause unlimited RST generation, consuming CPU and bandwidth.
const RST_RATE_LIMIT: u32 = 100;

/// RST rate limiting window in milliseconds.
const RST_RATE_WINDOW_MS: u64 = 1000;

/// Token bucket for RST rate limiting.
static RST_TOKENS: AtomicU32 = AtomicU32::new(RST_RATE_LIMIT);

/// Window start time for RST rate limiter.
static RST_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if an RST can be sent (rate limiter).
///
/// R63-4 FIX: Implements token bucket rate limiting for RST packets
/// to prevent amplification attacks.
fn allow_rst(now_ms: u64) -> bool {
    // R121-6 FIX: Use compare_exchange on window start so only one CPU
    // wins the reset race, preventing concurrent token refill on SMP.
    // R154-15 FIX: Use AcqRel/Release ordering (same rationale as
    // allow_challenge_ack) to prevent a second CPU from seeing the new
    // window but stale zero tokens.
    let window_start = RST_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= RST_RATE_WINDOW_MS {
        if RST_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            RST_TOKENS.store(RST_RATE_LIMIT, Ordering::Release);
        }
    }

    let mut tokens = RST_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match RST_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }
    false
}

// ============================================================================
// SYN Cookie SYN-ACK Rate Limiting (R137-2 FIX)
// ============================================================================

/// Maximum SYN-cookie SYN-ACK packets per window period.
///
/// R137-2 FIX: SYN cookies generate stateless SYN-ACK responses. Without a
/// global rate limit, spoofed SYN floods cause the server to reflect SYN-ACKs
/// to victims (low amplification ~1.2x but still undesirable). 200/sec is
/// generous enough for legitimate handshakes under load while capping
/// reflection bandwidth.
const SYNACK_COOKIE_RATE_LIMIT: u32 = 200;

/// SYN-cookie SYN-ACK rate limiting window in milliseconds.
const SYNACK_COOKIE_RATE_WINDOW_MS: u64 = 1000;

/// Token bucket for SYN-cookie SYN-ACK rate limiting.
static SYNACK_COOKIE_TOKENS: AtomicU32 = AtomicU32::new(SYNACK_COOKIE_RATE_LIMIT);

/// Window start time for SYN-cookie SYN-ACK rate limiter.
static SYNACK_COOKIE_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if a SYN-cookie SYN-ACK can be sent (rate limiter).
///
/// R137-2 FIX: Token bucket rate limiting for stateless SYN-cookie SYN-ACK
/// responses to reduce spoofed-source reflection amplification.
fn allow_syn_cookie_ack(now_ms: u64) -> bool {
    // Use compare_exchange on window start so only one CPU wins the reset
    // race, preventing concurrent token refill on SMP (same as allow_rst).
    // R154-15 FIX: Use AcqRel/Release ordering (same rationale as
    // allow_challenge_ack) to prevent a second CPU from seeing the new
    // window but stale zero tokens.
    let window_start = SYNACK_COOKIE_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= SYNACK_COOKIE_RATE_WINDOW_MS {
        if SYNACK_COOKIE_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            SYNACK_COOKIE_TOKENS.store(SYNACK_COOKIE_RATE_LIMIT, Ordering::Release);
        }
    }

    let mut tokens = SYNACK_COOKIE_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match SYNACK_COOKIE_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }
    false
}

// ============================================================================
// R74-5 FIX: Global TCP Connection Counters
// ============================================================================

/// Global counter for half-open (SYN_RECEIVED) TCP connections.
///
/// R74-5 FIX: Tracks connections in the SYN queue across all listeners to enforce
/// a global limit. Without this, an attacker could open unlimited half-open
/// connections across many listening sockets, exhausting kernel memory.
///
/// Incremented when a SYN is queued, decremented when:
/// - Connection completes handshake (moves to ESTABLISHED)
/// - SYN times out and is removed from queue
/// - Connection is rejected/dropped
static GLOBAL_HALF_OPEN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Global counter for active (ESTABLISHED, CLOSE_WAIT, etc.) TCP connections.
///
/// R74-5 FIX: Tracks all active connections to prevent resource exhaustion.
/// This is already partially enforced via tcp_conns.len() checks, but we
/// add this counter for O(1) limit checking without holding the lock.
///
/// R154-I6 FIX: Scope clarification -- this counter tracks passive-open (accepted)
/// connections only. Client-initiated (active-open / connect()) sockets are NOT
/// counted here. The counter is incremented in `queue_accept()` and decremented
/// on connection teardown. For observability, note that the public accessor
/// returns the passive-open count, not total TCP connections.
static GLOBAL_ACTIVE_CONN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Global maximum for half-open connections (SYN flood protection).
///
/// When this limit is reached, new SYNs should use SYN cookies instead of
/// queueing state. This provides stateless protection against SYN floods.
const GLOBAL_MAX_HALF_OPEN: u32 = 1024;

/// Atomically try to increment half-open counter if below limit.
///
/// # R74-5 Enhancement: TOCTOU Fix
///
/// The original implementation had a race condition:
/// ```ignore
/// if !can_queue_half_open() { return false; }  // Check
/// // RACE: Other thread can increment here
/// inc_half_open();  // Increment
/// ```
///
/// This atomic version uses `fetch_update` to check and increment in one
/// operation, preventing bursts from exceeding the limit.
///
/// # Returns
/// - `true`: Counter incremented, caller can queue the SYN
/// - `false`: Limit reached, caller should use SYN cookie fallback
#[inline]
fn try_inc_half_open() -> bool {
    GLOBAL_HALF_OPEN_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current < GLOBAL_MAX_HALF_OPEN {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

/// Decrement half-open connection count.
///
/// R74-5 FIX: Called when a half-open connection is removed (timeout, handshake, reject).
#[inline]
fn dec_half_open() {
    // Use saturating_sub to avoid underflow in case of accounting bugs
    let _ = GLOBAL_HALF_OPEN_COUNT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

/// Atomically try to increment active connection counter if below limit.
///
/// # R74-5 Enhancement: Active Connection Limit Enforcement
///
/// The original implementation incremented without checking the limit.
/// This atomic version enforces `TCP_MAX_ACTIVE_CONNECTIONS` to prevent
/// connection flood DoS attacks.
///
/// # Returns
/// - `true`: Counter incremented, connection can be established
/// - `false`: Limit reached, connection should be rejected (send RST)
#[inline]
fn try_inc_active_conn() -> bool {
    GLOBAL_ACTIVE_CONN_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if (current as usize) < TCP_MAX_ACTIVE_CONNECTIONS {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

/// Decrement active connection count.
///
/// R74-5 FIX: Called when a connection is closed/removed from tcp_conns.
#[inline]
fn dec_active_conn() {
    let _ = GLOBAL_ACTIVE_CONN_COUNT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

// ============================================================================
// R132-5 FIX: SYN Cookie Observability Counters
// ============================================================================

/// Total SYN cookies generated (SYN-ACKs sent with stateless cookie ISN).
static SYN_COOKIES_GENERATED: AtomicU64 = AtomicU64::new(0);

/// Total SYN cookies validated successfully (completed handshakes).
static SYN_COOKIES_VALIDATED: AtomicU64 = AtomicU64::new(0);

/// Total SYN cookies rejected (invalid MAC, expired, or malformed).
static SYN_COOKIES_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of SYN cookie observability counters.
#[derive(Debug, Clone, Copy)]
pub struct SynCookieCounters {
    pub generated: u64,
    pub validated: u64,
    pub rejected: u64,
}

/// Get current SYN cookie observability counters (for procfs/stats export).
pub fn syn_cookie_counters() -> SynCookieCounters {
    SynCookieCounters {
        generated: SYN_COOKIES_GENERATED.load(Ordering::Relaxed),
        validated: SYN_COOKIES_VALIDATED.load(Ordering::Relaxed),
        rejected: SYN_COOKIES_REJECTED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Socket Types
// ============================================================================

/// Socket address domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDomain {
    /// IPv4 Internet domain (AF_INET)
    Inet4,
}

impl SocketDomain {
    /// Linux AF_INET value
    pub const AF_INET: u32 = 2;

    /// Parse from Linux domain constant
    pub fn from_raw(domain: u32) -> Option<Self> {
        match domain {
            Self::AF_INET => Some(SocketDomain::Inet4),
            _ => None,
        }
    }
}

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Stream socket (SOCK_STREAM) - TCP
    Stream,
    /// Datagram socket (SOCK_DGRAM) - UDP
    Dgram,
}

impl SocketType {
    /// Linux SOCK_STREAM value
    pub const SOCK_STREAM: u32 = 1;
    /// Linux SOCK_DGRAM value
    pub const SOCK_DGRAM: u32 = 2;

    /// Parse from Linux type constant
    pub fn from_raw(ty: u32) -> Option<Self> {
        match ty {
            Self::SOCK_STREAM => Some(SocketType::Stream),
            Self::SOCK_DGRAM => Some(SocketType::Dgram),
            _ => None,
        }
    }
}

/// Socket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    /// TCP protocol (IPPROTO_TCP = 6)
    Tcp,
    /// UDP protocol (IPPROTO_UDP = 17)
    Udp,
}

impl SocketProtocol {
    /// Linux IPPROTO_TCP value
    pub const IPPROTO_TCP: u32 = 6;
    /// Linux IPPROTO_UDP value
    pub const IPPROTO_UDP: u32 = 17;

    /// Parse from Linux protocol constant with socket type inference
    pub fn from_raw(proto: u32, sock_type: SocketType) -> Option<Self> {
        match proto {
            0 => {
                // Default protocol based on socket type
                match sock_type {
                    SocketType::Stream => Some(SocketProtocol::Tcp),
                    SocketType::Dgram => Some(SocketProtocol::Udp),
                }
            }
            Self::IPPROTO_TCP => Some(SocketProtocol::Tcp),
            Self::IPPROTO_UDP => Some(SocketProtocol::Udp),
            _ => None,
        }
    }
}

// ============================================================================
// Security Label
// ============================================================================

/// Security label captured at socket creation.
///
/// This label is stored with the socket and used for:
/// 1. LSM hook invocations (passing original creator context)
/// 2. MAC policy decisions (e.g., SELinux domain transitions)
/// 3. Audit logging (who created this socket)
#[derive(Debug, Clone, Copy)]
pub struct SocketLabel {
    /// Process context at creation time
    pub creator: ProcessCtx,
    /// Optional security marking (SELinux/SMACK/AppArmor)
    /// Value 0 means no marking set
    pub secmark: u64,
}

impl SocketLabel {
    /// Create a label from the current process context.
    ///
    /// Returns `None` if there is no current process (kernel context).
    pub fn from_current(secmark: u64) -> Option<Self> {
        ProcessCtx::from_current().map(|creator| SocketLabel { creator, secmark })
    }
}

// ============================================================================
// Pending Datagram
// ============================================================================

/// A received UDP datagram queued for userspace delivery.
#[derive(Debug)]
pub struct PendingDatagram {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Source port
    pub src_port: u16,
    /// Datagram payload (UDP data only, no headers)
    data: AdmittedVec<u8>,
    /// Receive timestamp (ticks)
    pub received_at: u64,
}

impl PendingDatagram {
    /// Read-only userspace-copy view. Retained capacity and its lifetime charge
    /// remain encapsulated in the datagram until dequeue/teardown completes.
    pub fn payload(&self) -> &[u8] {
        self.data.as_slice()
    }
}

// ============================================================================
// TCP Socket State
// ============================================================================

/// TCP socket-specific state for stream sockets.
///
/// This structure holds the TCP control block and dedicated wait queues for
/// TCP state transitions (connect completion, close) and data availability.
struct TcpSocketState {
    /// TCP control block for this stream socket
    control: TcpControlBlock,
    /// Waiters interested in TCP state transitions (connect/close)
    state_waiters: WaitQueueArc,
    /// Waiters for data availability (recv)
    data_waiters: WaitQueueArc,
}

struct PreparedTcpWaiters {
    state_waiters: WaitQueueArc,
    data_waiters: WaitQueueArc,
}

impl PreparedTcpWaiters {
    fn try_new() -> Result<Self, SocketError> {
        Ok(Self {
            state_waiters: WaitQueue::try_new_arc()?,
            data_waiters: WaitQueue::try_new_arc()?,
        })
    }
}

impl TcpSocketState {
    fn try_new(control: TcpControlBlock) -> Result<Self, SocketError> {
        // R180-11 FIX: prepare both independently-owned waiter Arcs before
        // publishing the TCP state into its socket.
        Ok(Self::from_prepared(control, PreparedTcpWaiters::try_new()?))
    }

    fn from_prepared(control: TcpControlBlock, waiters: PreparedTcpWaiters) -> Self {
        TcpSocketState {
            control,
            state_waiters: waiters.state_waiters,
            data_waiters: waiters.data_waiters,
        }
    }
}

// ============================================================================
// TCP Listen State (R51-1: Passive Open)
// ============================================================================

/// R106-10 FIX: TCP connection lookup key type (net_ns_id, local_ip, local_port, remote_ip, remote_port)
///
/// Used for both active and passive TCP connection tracking.
/// The namespace ID ensures that connections in different network namespaces
/// cannot collide on the same 4-tuple.
type TcpLookupKey = (NamespaceId, u32, u16, u32, u16);

/// Half-open connection (SYN received, SYN-ACK sent, awaiting final ACK).
struct PendingSyn {
    /// Connection lookup key (4-tuple)
    key: TcpLookupKey,
    /// Child socket in SynReceived state
    sock: SocketArc,
    /// Cached SYN-ACK segment for retransmission
    syn_ack: WirePacket,
    /// Timestamp when SYN-ACK was sent (for SYN timeout)
    syn_sent_at: u64,
}

/// Passive-open bookkeeping for a listening TCP socket.
///
/// A listening socket maintains two bounded queues:
/// - SYN queue: Half-open connections (SYN received, SYN-ACK sent)
/// - Accept queue: Fully established connections ready for accept()
///
/// Both queues are bounded to prevent resource exhaustion from SYN floods.
struct TcpListenState {
    /// Maximum half-open connections (SYN queue size)
    syn_backlog: usize,
    /// Maximum pending accept connections (accept queue size)
    accept_backlog: usize,
    /// Half-open connections indexed by 4-tuple
    syn_queue: AdmittedMap<TcpLookupKey, PendingSyn>,
    /// Fully established connections awaiting accept()
    accept_queue: AdmittedVec<SocketArc>,
    /// Wait queue for blocking accept()
    accept_waiters: WaitQueueArc,
}

impl TcpListenState {
    /// Create new listen state with bounded backlogs.
    fn try_new(backlog: usize) -> Result<Self, SocketError> {
        // Clamp backlog to valid range
        let effective = backlog.clamp(1, TCP_MAX_ACCEPT_BACKLOG);
        Ok(TcpListenState {
            syn_backlog: TCP_MAX_SYN_BACKLOG.min(effective),
            accept_backlog: effective,
            syn_queue: AdmittedMap::new(HeapClass::SocketObject),
            accept_queue: AdmittedVec::new(HeapClass::SocketObject),
            accept_waiters: WaitQueue::try_new_arc()?,
        })
    }

    /// Enqueue a half-open connection.
    ///
    /// Returns false if SYN queue is full (silent drop for SYN flood mitigation).
    ///
    /// J2-2: `table` is threaded in so the per-namespace half-open budget can be
    /// charged in the same funnel as the global reservation (lock order
    /// `listen.lock` > `per_ns_syn_counts`; the caller holds `listen.lock`).
    fn try_reserve_syn_slot(&mut self, key: &TcpLookupKey, table: &SocketTable) -> bool {
        // Check local queue limit first (fast path)
        if self.syn_queue.len() >= self.syn_backlog || self.syn_queue.contains_key(key) {
            return false;
        }

        // R180-11 FIX: backing allocation is prepared before global/per-ns
        // counters change, so publication failure needs no allocation rollback.
        if self.syn_queue.ensure_capacity_for(1).is_err() {
            return false;
        }

        // R74-5 Enhancement: Atomically reserve global half-open slot.
        // This prevents the TOCTOU race where multiple threads could all pass
        // a non-atomic check before any increment, exceeding the global limit.
        //
        // If this returns false, caller falls back to SYN cookies for
        // stateless flood protection (R106-2 FIX: implemented in SYN handler).
        if !try_inc_half_open() {
            return false;
        }

        // J2-2: per-namespace half-open budget (a subset of the global limit). On
        // over-quota, roll back the global reservation we just took and signal the
        // caller to fall back to stateless SYN cookies (same as the global path).
        if !table.try_inc_ns_syn(key.0) {
            dec_half_open();
            return false;
        }

        true
    }

    /// Cancel a prepared-but-unpublished SYN slot.
    ///
    /// This is allocation-free and may be used after any later passive-open
    /// preparation failure, including socket-ID exhaustion.
    fn cancel_syn_slot(&mut self, ns_id: NamespaceId, table: &SocketTable) {
        table.dec_ns_syn(ns_id);
        dec_half_open();
    }

    /// Publish a half-open child after `try_reserve_syn_slot` succeeded.
    fn publish_syn_reserved(&mut self, entry: PendingSyn, table: &SocketTable) -> bool {
        let entry_ns = entry.key.0;
        if self
            .syn_queue
            .insert_unique_reserved(entry.key, entry)
            .is_err()
        {
            self.cancel_syn_slot(entry_ns, table);
            return false;
        }
        true
    }

    #[cfg(test)]
    fn queue_syn(&mut self, entry: PendingSyn, table: &SocketTable) -> bool {
        if !self.try_reserve_syn_slot(&entry.key, table) {
            return false;
        }

        self.publish_syn_reserved(entry, table)
    }

    /// Remove and return a half-open connection by key.
    ///
    /// J2-2: `table` is threaded in so the per-namespace half-open uncharge stays
    /// in the same single funnel as the global decrement.
    fn take_syn(&mut self, key: &TcpLookupKey, table: &SocketTable) -> Option<PendingSyn> {
        let result = self.syn_queue.remove(key);

        // R74-5 FIX: Decrement global half-open counter when removing
        if result.is_some() {
            dec_half_open();
            // J2-2: uncharge the per-namespace half-open slot in the same funnel.
            table.dec_ns_syn(key.0);
        }

        result
    }

    /// Get a reference to a half-open connection.
    fn get_syn(&self, key: &TcpLookupKey) -> Option<&PendingSyn> {
        self.syn_queue.get(key)
    }

    /// Enqueue a fully established connection for accept().
    ///
    /// Returns false if accept queue is full.
    fn try_reserve_accept_slot(&mut self) -> bool {
        if self.accept_queue.len() >= self.accept_backlog {
            return false;
        }

        // R180-11 FIX: no allocator call is permitted after the active-conn
        // side effect. Prepare the retained Arc slot first.
        if self.accept_queue.ensure_capacity_for(1).is_err() {
            return false;
        }

        // R74-5 Enhancement: Atomically reserve global active connection slot.
        // This enforces TCP_MAX_ACTIVE_CONNECTIONS to prevent connection floods.
        if !try_inc_active_conn() {
            return false;
        }

        true
    }

    fn cancel_accept_slot(&mut self) {
        dec_active_conn();
    }

    fn publish_accept_reserved(&mut self, sock: SocketArc) -> bool {
        // R121-3 FIX: Mark this socket as counted so cleanup_tcp_connection()
        // only decrements for sockets that actually incremented the counter.
        sock.counted_in_active.store(true, Ordering::Release);

        if let Err(sock) = self.accept_queue.push_reserved(sock) {
            sock.counted_in_active.store(false, Ordering::Release);
            dec_active_conn();
            return false;
        }
        true
    }

    fn queue_accept(&mut self, sock: SocketArc) -> bool {
        if !self.try_reserve_accept_slot() {
            return false;
        }
        self.publish_accept_reserved(sock)
    }

    /// Dequeue an established connection for accept().
    fn pop_accept(&mut self) -> Option<SocketArc> {
        self.accept_queue.pop_front()
    }

    /// Check if accept queue has pending connections.
    fn has_pending(&self) -> bool {
        !self.accept_queue.is_empty()
    }

    /// Get the accept wait queue for blocking.
    fn waiters(&self) -> WaitQueueArc {
        self.accept_waiters.clone()
    }
}

/// Result of initiating a TCP connect (SYN sent).
#[derive(Debug)]
pub struct TcpConnectResult {
    /// Serialized TCP segment (header + payload) ready for IPv4 encapsulation.
    pub segment: WirePacket,
    /// Local port used for the connection.
    pub local_port: u16,
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dst_ip: Ipv4Addr,
    /// Destination port.
    pub dst_port: u16,
    /// Exact socket operation that may publish SYN-SENT after device
    /// acceptance. This token is intentionally private to the network stack.
    pub(crate) egress_binding: TcpReplyBinding,
}

/// Exact socket identity and single pending egress operation bound to one
/// generated TCP control packet. Retaining the `SocketArc` prevents allocator
/// generation reuse while the packet is awaiting policy/device acceptance.
pub(crate) struct TcpReplyBinding {
    sock: SocketArc,
    socket_id: u64,
    socket_generation: u64,
    operation_token: u64,
}

impl core::fmt::Debug for TcpReplyBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpReplyBinding")
            .field("socket_id", &self.socket_id)
            .field("socket_generation", &self.socket_generation)
            .field("operation_token", &self.operation_token)
            .finish()
    }
}

/// A serialized TCP control packet whose heap admission remains owned until
/// the caller finishes transmission and drops the packet.
pub struct SerializedTcpPacket {
    bytes: WirePacket,
}

impl core::ops::Deref for SerializedTcpPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

/// One admitted timer packet plus the socket identity whose metadata may be
/// committed after the queue result.
struct DataRetransmitWork {
    sock: SocketArc,
    dst_ip: Ipv4Addr,
    packet: WirePacket,
    net_ns_id: u64,
    seq: u32,
    ack_generation: u64,
}

struct FinRetransmitWork {
    sock: SocketArc,
    dst_ip: Ipv4Addr,
    packet: WirePacket,
    net_ns_id: u64,
}

struct KeepaliveWork {
    sock: SocketArc,
    dst_ip: Ipv4Addr,
    packet: WirePacket,
    net_ns_id: u64,
    ack_generation: u64,
}

// ============================================================================
// Socket Metadata
// ============================================================================

/// Socket binding and connection state.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
struct SocketMeta {
    /// Local IP address (if bound)
    local_ip: Option<[u8; 4]>,
    /// Local port (if bound)
    local_port: Option<u16>,
    /// Remote IP address (if connected)
    remote_ip: Option<[u8; 4]>,
    /// Remote port (if connected)
    remote_port: Option<u16>,
}

impl SocketMeta {
    fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Socket State
// ============================================================================

/// M0-6 poll/select: non-consuming readiness snapshot of a socket, produced by
/// `SocketState::poll_readiness`. Booleans (not raw POLL* bits) so the poll layer
/// owns the bit mapping + masking.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SockPollReadiness {
    pub readable: bool,
    pub writable: bool,
    pub hup: bool,
    pub err: bool,
    pub rdhup: bool,
}

/// Per-socket state backing a capability handle.
///
/// This structure is wrapped in `Arc` and stored in the capability table.
/// Multiple CapId entries can reference the same socket (via dup()).
pub struct SocketState {
    /// Unique socket identifier (monotonically increasing)
    pub id: u64,
    /// Non-reusable lifetime generation bound to prepared network operations.
    owner_generation: u64,
    /// Socket domain
    pub domain: SocketDomain,
    /// Socket type
    pub ty: SocketType,
    /// Socket protocol
    pub proto: SocketProtocol,
    /// Security label from creation
    pub label: SocketLabel,
    /// R75-1 FIX: Network namespace identifier (for CLONE_NEWNET isolation)
    ///
    /// Sockets are isolated by network namespace. Port bindings and lookups
    /// are partitioned by this ID, ensuring that different namespaces can
    /// bind to the same port independently.
    pub net_ns_id: NamespaceId,
    /// Reference count for file descriptors referencing this socket.
    ///
    /// Initialized to 1 at creation. Incremented on dup()/fork(), decremented
    /// on close(). Socket is only fully closed when refcount reaches 0.
    refcount: AtomicU64,
    /// R180-21 FIX: Serializes state-changing userspace operations on a shared
    /// socket handle.  This is the outermost socket-operation lock: bind,
    /// connect, listen auto-bind, UDP send auto-bind, and connect abort hold it
    /// across validation, quota charge, registry publication, metadata/TCB
    /// commit, and synchronous rollback.  It is never held across a scheduler
    /// wait; connect drops it before blocking and reacquires it for rollback.
    ///
    /// Close never blocks on this lock: it publishes `close_pending`, marks the
    /// socket closed, and uses `try_lock`. If an operation owns the lock, its
    /// `SocketOperationGuard` performs the exactly-once final teardown after
    /// unlocking. This preserves the established operation-outermost order
    /// without creating Process-lock -> operation -> cgroup-lock inversion.
    operation: Mutex<()>,
    /// RF180-26 FIX: a close request has linearized and no later userspace
    /// state operation may publish a live socket state.
    close_pending: AtomicBool,
    /// Exactly-once ownership of the deferred close finalizer.
    close_finalizer_claimed: AtomicBool,
    /// Binding/connection metadata
    meta: Mutex<SocketMeta>,
    /// Received datagram queue
    rx_queue: Mutex<AdmittedVec<PendingDatagram>>,
    /// Wait queue for blocking recv
    waiters: WaitQueue,
    /// Socket closed flag
    closed: AtomicBool,
    /// R121-3 FIX: Whether this socket was counted in GLOBAL_ACTIVE_CONN_COUNT.
    ///
    /// Set to `true` when `try_inc_active_conn()` succeeds in `queue_accept()`.
    /// Checked in `cleanup_tcp_connection()` to avoid decrementing the counter
    /// for client-initiated connections that were never counted.
    counted_in_active: AtomicBool,
    /// Bytes received counter
    rx_bytes: AtomicU64,
    /// Bytes sent counter
    tx_bytes: AtomicU64,
    /// Datagrams received counter
    rx_datagrams: AtomicU64,
    /// Datagrams sent counter
    tx_datagrams: AtomicU64,
    /// Datagrams dropped due to queue full
    rx_dropped: AtomicU64,
    /// TCP state (only populated for stream sockets)
    tcp: Mutex<Option<TcpSocketState>>,
    /// Listen state (only for listening TCP sockets)
    listen: Mutex<Option<TcpListenState>>,
}

impl core::fmt::Debug for SocketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketState")
            .field("id", &self.id)
            .field("domain", &self.domain)
            .field("ty", &self.ty)
            .field("proto", &self.proto)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SocketState {
    /// Prepare and allocate the sole supported socket representation.
    fn try_new_arc(
        id: u64,
        domain: SocketDomain,
        ty: SocketType,
        proto: SocketProtocol,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Result<SocketArc, SocketError> {
        let owner_generation = next_nonzero_generation(&NEXT_SOCKET_OWNER_GENERATION)?;
        try_new_socket_arc(SocketState {
            id,
            owner_generation,
            domain,
            ty,
            proto,
            label,
            net_ns_id,
            refcount: AtomicU64::new(1),
            operation: Mutex::new(()),
            close_pending: AtomicBool::new(false),
            close_finalizer_claimed: AtomicBool::new(false),
            meta: Mutex::new(SocketMeta::new()),
            rx_queue: Mutex::new(AdmittedVec::new(HeapClass::SocketPayload)),
            waiters: WaitQueue::new(HeapClass::SocketObject),
            closed: AtomicBool::new(false),
            counted_in_active: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_datagrams: AtomicU64::new(0),
            tx_datagrams: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            tcp: Mutex::new(None),
            listen: Mutex::new(None),
        })
    }

    /// Check if the socket is closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Increment the socket reference count.
    ///
    /// Called when a file descriptor is duplicated (dup/dup2/dup3) or when
    /// forking a process that has socket file descriptors.
    ///
    /// Uses AcqRel ordering for symmetry with decrement_refcount() and to
    /// ensure visibility of all modifications before the increment.
    #[inline]
    pub fn increment_refcount(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrement the socket reference count and return the new count.
    ///
    /// Called when a file descriptor is closed. The socket should only be
    /// fully closed (port released, waiters woken) when this returns 0.
    ///
    /// Uses `fetch_update` to prevent underflow: if the refcount is already 0
    /// (which indicates a double-drop bug), we return 0 without modifying the
    /// counter, avoiding wrap to `u64::MAX` which would leak the socket.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if called with refcount == 0 (double-drop).
    #[inline]
    pub fn decrement_refcount(&self) -> u64 {
        match self
            .refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    // Debug: catch double-drop bugs early
                    debug_assert!(false, "socket refcount underflow: double-drop detected");
                    None // Don't modify - already at 0
                } else {
                    Some(current - 1)
                }
            }) {
            Ok(old) => old - 1, // Return new value (old - 1)
            Err(_) => 0,        // Was already 0, return 0
        }
    }

    /// Mark the socket as closed and wake all waiters.
    pub fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return; // Already closed
        }
        // Wake UDP/datagram waiters
        self.waiters.wake_all();
        // Wake TCP state waiters
        if let Some(waiters) = self.tcp_waiters() {
            waiters.close();
            waiters.wake_all();
        }
        // Wake TCP data waiters
        if let Some(waiters) = self.tcp_data_waiters() {
            waiters.close();
            waiters.wake_all();
        }
        // Wake accept waiters (for listening sockets)
        if let Some(waiters) = self.listen_waiters() {
            waiters.close();
            waiters.wake_all();
        }
    }

    /// Bind the socket to a local address.
    fn bind_local(&self, ip: Ipv4Addr, port: u16) {
        let mut meta = self.meta.lock();
        meta.local_ip = Some(ip.0);
        meta.local_port = Some(port);
    }

    /// Get the local port if bound.
    pub fn local_port(&self) -> Option<u16> {
        self.meta.lock().local_port
    }

    /// Get the local IP address if bound.
    ///
    /// R48-REVIEW FIX: Expose bound local IP for correct source address in sendto.
    pub fn local_ip(&self) -> Option<[u8; 4]> {
        self.meta.lock().local_ip
    }

    /// Set the remote endpoint (for connect).
    fn set_remote(&self, ip: Ipv4Addr, port: u16) {
        let mut meta = self.meta.lock();
        meta.remote_ip = Some(ip.0);
        meta.remote_port = Some(port);
    }

    /// Get the remote port if connected.
    pub fn remote_port(&self) -> Option<u16> {
        self.meta.lock().remote_port
    }

    /// Get the remote IP address if connected.
    pub fn remote_ip(&self) -> Option<[u8; 4]> {
        self.meta.lock().remote_ip
    }

    /// Install a TCP control block for this socket.
    fn attach_tcp(&self, control: TcpControlBlock) -> Result<(), SocketError> {
        let state = TcpSocketState::try_new(control)?;
        *self.tcp.lock() = Some(state);
        Ok(())
    }

    /// Get the current TCP state (if any).
    pub fn tcp_state(&self) -> Option<TcpState> {
        self.tcp.lock().as_ref().map(|tcp| tcp.control.state)
    }

    /// M0-6 poll/select: non-consuming readiness snapshot for this socket.
    ///
    /// # Lock discipline (NORMATIVE — do not violate)
    /// At most ONE `SocketState` sub-lock (`listen`, `tcp`, or `rx_queue`) is held
    /// at any instant: the listener arm takes+drops `listen` BEFORE the connection
    /// arm touches `tcp` (never nest them — `push_accept_ready` wakes under `listen`
    /// into Process-reaching hooks, so a `tcp`→`listen` nesting here would form a
    /// cross-lock cycle with the accept path). Callable from process context with
    /// IRQs enabled ONLY while no socket sub-lock is ever acquired in IRQ context
    /// (today NIC RX is not IRQ-driven and TCP timers are flag-deferred); an
    /// IRQ-context RX pump must first convert these to irqsave/try_lock discipline.
    ///
    /// Readiness is a "won't block" predicate: an unconnected / reset / closed
    /// stream reports ready so the follow-up op fails FAST (ENOTCONN/EOF) instead of
    /// hanging — never a false "would block". The send-window POLLOUT rule ignores
    /// the per-namespace J2-6 budget (over-reporting POLLOUT is safe: the level-
    /// triggered poll re-checks each tick and the real `tcp_send` enforces the cap).
    pub fn poll_readiness(&self) -> SockPollReadiness {
        // (1) Fully-closed socket: readable (EOF), writable (op fails fast), hup.
        if self.is_closed() {
            return SockPollReadiness {
                readable: true,
                writable: true,
                hup: true,
                err: false,
                rdhup: false,
            };
        }

        match self.ty {
            SocketType::Stream => {
                // (2) Listener: readable iff the accept queue has a pending conn.
                // Take + DROP the `listen` lock before touching `tcp`.
                {
                    let lg = self.listen.lock();
                    if let Some(l) = lg.as_ref() {
                        return SockPollReadiness {
                            readable: l.has_pending(),
                            writable: false,
                            hup: false,
                            err: false,
                            rdhup: false,
                        };
                    }
                }

                // (3) Connection TCB (single `tcp` lock).
                let tg = self.tcp.lock();
                match tg.as_ref() {
                    // Not-yet-connected or post-RST stream: report all-ready so a
                    // read/write/recv/send fails fast (never blocks). Documented
                    // approximation of Linux tcp_poll on TCP_CLOSE.
                    None => SockPollReadiness {
                        readable: true,
                        writable: true,
                        hup: true,
                        err: true,
                        rdhup: false,
                    },
                    Some(tcp) => {
                        let state = tcp.control.state;
                        // Handshake in progress: neither readable nor writable yet.
                        if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
                            return SockPollReadiness::default();
                        }
                        let cb = &tcp.control;
                        let readable = !cb.recv_buffer.is_empty()
                            || cb.fin_received
                            || state.is_closed()
                            || !state.can_receive();
                        let writable = if !state.can_send() {
                            true
                        } else {
                            cb.send_window_available() > 0
                                && cb.send_buffer_bytes < TCP_MAX_SEND_BUFFER_BYTES
                        };
                        SockPollReadiness {
                            readable,
                            writable,
                            hup: false,
                            err: false,
                            rdhup: cb.fin_received,
                        }
                    }
                }
            }
            // (5) Datagram / raw: readable iff a datagram is queued; always writable.
            _ => SockPollReadiness {
                readable: !self.rx_queue.lock().is_empty(),
                writable: true,
                hup: false,
                err: false,
                rdhup: false,
            },
        }
    }

    /// Get a clone of the TCP state waiters (for blocking connect/wakeups).
    fn tcp_waiters(&self) -> Option<WaitQueueArc> {
        self.tcp
            .lock()
            .as_ref()
            .map(|tcp| tcp.state_waiters.clone())
    }

    /// Wake TCP state waiters (called when state transitions occur).
    pub fn wake_tcp_waiters(&self) {
        if let Some(waiters) = self.tcp_waiters() {
            waiters.wake_all();
        }
    }

    /// Get a clone of the TCP data waiters (for blocking recv).
    fn tcp_data_waiters(&self) -> Option<WaitQueueArc> {
        self.tcp.lock().as_ref().map(|tcp| tcp.data_waiters.clone())
    }

    /// Wake TCP data waiters (called when data arrives).
    pub fn wake_tcp_data_waiters(&self) {
        if let Some(waiters) = self.tcp_data_waiters() {
            waiters.wake_all();
        }
    }

    // -----------------------------------------------------------------------
    // Listen State Helpers (R51-1)
    // -----------------------------------------------------------------------

    /// Install listen state for a listening socket.
    fn install_listen_state(&self, state: TcpListenState) {
        *self.listen.lock() = Some(state);
    }

    /// Clear listen state when socket is closed.
    fn clear_listen_state(&self) {
        self.listen.lock().take();
    }

    /// Get the accept wait queue for blocking accept().
    pub fn listen_waiters(&self) -> Option<WaitQueueArc> {
        self.listen.lock().as_ref().map(|l| l.waiters())
    }

    /// Pop the next established connection from the accept queue.
    pub fn pop_accept_ready(&self) -> Option<SocketArc> {
        self.listen.lock().as_mut().and_then(|l| l.pop_accept())
    }

    /// Push an established connection to the accept queue.
    ///
    /// Returns false if the accept queue is full.
    fn push_accept_ready(&self, child: SocketArc) -> bool {
        let mut guard = self.listen.lock();
        if let Some(state) = guard.as_mut() {
            let queued = state.queue_accept(child);
            if queued {
                state.waiters().wake_one();
            }
            queued
        } else {
            false
        }
    }

    /// Check if this socket is in Listen state.
    pub fn is_listening(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpState::Listen))
    }

    /// Get a snapshot of socket metadata.
    fn meta_snapshot(&self) -> SocketMeta {
        *self.meta.lock()
    }

    /// Enqueue a received datagram.
    ///
    /// Returns `true` if the datagram was queued, `false` if dropped
    /// (queue full, global byte cap exceeded, or socket closed).
    ///
    /// R133-2 FIX: Accept raw parameters instead of pre-allocated PendingDatagram.
    /// The payload is only copied (to_vec) after per-socket queue depth and
    /// global byte cap checks pass, preventing allocation/copy churn DoS under
    /// UDP flood conditions when the cap is saturated.
    fn enqueue_rx(&self, src_ip: Ipv4Addr, src_port: u16, data: &[u8], received_at: u64) -> bool {
        if self.is_closed() {
            return false;
        }

        let pkt_len = data.len();

        let mut queue = self.rx_queue.lock();
        if queue.len() >= MAX_RX_QUEUE {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // R180-11 FIX: reserve queue backing before payload allocation or
        // logical publication. The retained capacity remains globally charged
        // and reusable if this datagram is rejected later.
        if queue.ensure_capacity_for(1).is_err() {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // R132-4 FIX: Enforce global UDP queued bytes cap via atomic CAS loop.
        // Prevents aggregate memory exhaustion across all UDP sockets.
        if GLOBAL_UDP_QUEUED_BYTES
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let new_total = current.saturating_add(pkt_len);
                if new_total <= MAX_GLOBAL_UDP_QUEUED_BYTES {
                    Some(new_total)
                } else {
                    None
                }
            })
            .is_err()
        {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // R133-2 FIX: Only allocate/copy the payload after all cap checks pass.
        // R164-6 FIX: Fallible copy of UDP payload. On OOM, roll back the
        // global byte counter and reject the datagram.
        let data_copy = match AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, data) {
            Ok(copy) => copy,
            Err(_) => {
                GLOBAL_UDP_QUEUED_BYTES.fetch_sub(pkt_len, Ordering::Relaxed);
                return false;
            }
        };
        let pkt = PendingDatagram {
            src_ip,
            src_port,
            data: data_copy,
            received_at,
        };

        if queue.push_reserved(pkt).is_err() {
            GLOBAL_UDP_QUEUED_BYTES.fetch_sub(pkt_len, Ordering::Relaxed);
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.rx_bytes.fetch_add(pkt_len as u64, Ordering::Relaxed);
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        drop(queue);

        self.waiters.wake_one();
        true
    }

    /// Pop the next received datagram from the queue.
    ///
    /// R132-4 FIX: Decrements GLOBAL_UDP_QUEUED_BYTES on dequeue.
    fn pop_rx(&self) -> Option<PendingDatagram> {
        let pkt = self.rx_queue.lock().pop_front();
        if let Some(ref pkt) = pkt {
            // R146-NET-4 FIX: Saturating decrement prevents underflow wrap
            // in case of hypothetical double-dequeue, which would permanently
            // block all UDP receive queueing.
            let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(pkt.data.len())),
            );
        }
        pkt
    }

    /// Get socket statistics.
    pub fn stats(&self) -> SocketStats {
        SocketStats {
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            rx_queue_len: self.rx_queue.lock().len(),
        }
    }
}

/// R132-4 FIX: Release global UDP queued byte accounting when a socket is
/// dropped with unread datagrams still in its rx_queue.
impl Drop for SocketState {
    fn drop(&mut self) {
        let queued_bytes: usize = self
            .rx_queue
            .get_mut()
            .iter()
            .map(|pkt| pkt.data.len())
            .sum();
        if queued_bytes > 0 {
            // R146-NET-4 FIX: Saturating decrement prevents underflow wrap.
            let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(queued_bytes)),
            );
        }

        // J2-6: uncharge any residual per-namespace TCP send bytes for a connection
        // whose TCB rode this Arc to its grave WITHOUT being nulled — the
        // close-non-keep path (close() removes the socket from `sockets` without
        // nulling the TCB). The strong Arc<SocketState> owners are `sockets` AND a
        // listener's `accept_queue` (udp/tcp_bindings/tcp_conns hold only Weak);
        // accept-queue children carry NO charged send bytes (not yet accept()ed, so
        // never tcp_send'd: ns_charged_send_bytes == 0) and are uncharged via
        // cleanup_tcp_connection at listener teardown — so for every charge-bearing
        // socket `sockets` is the last strong ref and this Drop is the catch-all.
        // get_mut() is exclusive purely from `&mut self` in drop (independent of
        // strong_count). Paths that null the TCB first (detach_tcp_uncharged /
        // cleanup_tcp_connection) zero the mirror, so Drop then reads None and
        // uncharges 0 — each residual is uncharged EXACTLY once.
        if self.net_ns_id != NamespaceId(0) {
            if let Some(ts) = self.tcp.get_mut().as_mut() {
                let charged = ts.control.ns_charged_send_bytes;
                if charged > 0 {
                    socket_table().uncharge_ns_send_residual(self.net_ns_id, charged);
                    ts.control.ns_charged_send_bytes = 0;
                }
                // J2-4: symmetric recv-byte residual uncharge. NOTE (unlike send,
                // where accept-queue children carry ns_charged_send_bytes == 0 since
                // never tcp_send'd): an accept-queue child CAN carry
                // ns_charged_recv_bytes > 0 from piggybacked SynReceived data — those
                // children are torn down via cleanup_tcp_connection (which nulls the
                // TCB first), so this Drop catch-all covers the normal-accept()
                // ->sockets-owned path.
                let rcharged = ts.control.ns_charged_recv_bytes;
                if rcharged > 0 {
                    socket_table().uncharge_ns_recv_residual(self.net_ns_id, rcharged);
                    ts.control.ns_charged_recv_bytes = 0;
                }
            }
        }
    }
}

/// Socket statistics.
#[derive(Debug, Clone, Copy)]
pub struct SocketStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    pub rx_dropped: u64,
    pub rx_queue_len: usize,
}

// ============================================================================
// Socket Errors
// ============================================================================

/// Socket operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// Invalid socket domain
    InvalidDomain,
    /// Invalid socket type
    InvalidType,
    /// Invalid protocol
    InvalidProtocol,
    /// Permission denied (LSM or DAC)
    PermissionDenied,
    /// Port already in use
    PortInUse,
    /// No ephemeral ports available
    NoPorts,
    /// R107-5: Socket ID space exhausted (u64 counter wrapped around)
    IdExhausted,
    /// Socket not bound (sendto without prior bind)
    NotBound,
    /// Socket is closed
    Closed,
    /// Operation timed out
    Timeout,
    /// Payload exceeds TCP/UDP size limits (R51-2)
    MessageTooLarge,
    /// No current process context
    NoProcess,
    /// Socket not found
    NotFound,
    /// Privileged port requires root
    PrivilegedPort,
    /// Connection already established or in progress
    AlreadyConnected,
    /// Operation would block while connect is in progress (non-blocking)
    InProgress,
    /// Operation would block on non-blocking socket (R51-1)
    WouldBlock,
    /// Invalid socket state for the requested operation
    InvalidState,
    /// R76-3 FIX: Per-namespace socket quota exceeded
    QuotaExceeded,
    /// UDP layer error
    Udp(UdpError),
    /// LSM policy denial
    Lsm(LsmError),
    /// R162-9 FIX: Allocation failed
    NoMemory,
    /// R171 (F3): a blocking socket operation was interrupted by a pending kill
    /// (maps to EINTR).
    Interrupted,
}

/// R180-L1: receive failure split between socket/source handling and the
/// caller-supplied copyout transaction. A Commit error guarantees the UDP/TCP
/// source queue was not advanced.
#[derive(Debug)]
pub enum RecvTransactionError<E> {
    Socket(SocketError),
    Commit(E),
}

impl From<UdpError> for SocketError {
    fn from(e: UdpError) -> Self {
        SocketError::Udp(e)
    }
}

impl From<LsmError> for SocketError {
    fn from(e: LsmError) -> Self {
        SocketError::Lsm(e)
    }
}

// ============================================================================
// Socket Table
// ============================================================================

// TcpLookupKey is defined earlier in this file, near TcpListenState.

/// R169-6 slice 2: lifetime contract of a port binding (see `PortBinding.kind`).
/// `Explicit` = user-requested specific port via `bind(non-zero)`; a CHARGED
/// entry of this kind is HOLD-UNTIL-CLOSE. `Ephemeral` = kernel-chosen
/// (connect auto-alloc, send_to_udp/listener auto-bind, and `bind(0)` — which
/// keeps its already-shipped charged-Ephemeral ghost-bind teardown this slice)
/// plus every uncharged/repair insert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BindKind {
    Ephemeral,
    Explicit,
}

/// J2-8: Value stored in `udp_bindings` / `tcp_bindings`.
///
/// The map is keyed by `(NamespaceId, port)` — the cgroup that allocated an
/// ephemeral port is NOT derivable from the key (many cgroups per netns) and is
/// NOT recoverable from a dead `Weak`. So the charged cgroup travels INSIDE the
/// map value: this is the single source of truth for the per-cgroup port budget
/// (`ports_current(g)` == count of live entries with `charged_cgroup == g`, by
/// construction). `charged_cgroup == 0` means "not charged" (passive-open
/// child, root cgroup, or pre-hook-registration) — a no-op at uncharge.
/// R169-6 slice 1: the listener auto-bind is CHARGED (kernel-chosen ephemeral
/// port). R169-6 slice 2: an explicit `bind(non-zero)` is now ALSO charged,
/// stamped `BindKind::Explicit`.
///
/// `kind` records the bind's LIFETIME contract, not how the port number was
/// chosen. It is load-bearing ONLY for CHARGED entries: a charged `Explicit`
/// binding is HOLD-UNTIL-CLOSE — the five while-alive teardown arms PURE-SKIP
/// it via `resolve_while_alive_teardown` (POSIX: an explicitly bound socket
/// keeps its port across failed connects until close), while a charged
/// `Ephemeral` binding gets the ghost-bind teardown (remove + refund + clear
/// `local_*` so a retry re-allocates and re-charges). An UNcharged entry's
/// kind is never CONSULTED (the `cgid != 0` qualifier in
/// `resolve_while_alive_teardown` is load-bearing): a root/pre-hook explicit
/// bind stamps `Explicit` with cgid 0 and keeps today's remove-while-alive +
/// connect-repair semantics. For UDP the kind is INERT — UDP has no
/// while-alive teardown arm (see the UDP-EXPLICIT INVARIANT in `bind_udp`).
///
/// Changing the value type from a bare `Weak<SocketState>` is deliberate: it is
/// the single source of truth, evicted atomically with the entry by
/// `BTreeMap::remove`/`insert`. Every mutation MUST go through
/// `insert_binding_charged` / `remove_binding_charged` /
/// `resolve_while_alive_teardown`; every read projects `.sock`.
struct PortBinding {
    sock: SocketWeak,
    charged_cgroup: u64,
    kind: BindKind,
}

impl PortBinding {
    #[inline]
    fn sock_ptr(&self) -> *const SocketState {
        self.sock.as_ptr()
    }
}

/// J2-8: Outcome of `insert_binding_charged`. The new entry always carries the
/// new charge; the caller's only obligation is to REFUND any displaced non-zero
/// charge. This single rule is correct for every case — fresh insert, replacing
/// a dead stale-Weak (reclaim its leaked charge), or re-registering the same
/// socket (the old charge is refunded and the new one takes its place, so the
/// owning cgroup's count is net-unchanged and exactly one charge sits in the
/// map for that port).
enum InsertOutcome {
    /// No prior entry (or the prior entry carried no charge): nothing to refund.
    FreshGrowth,
    /// The replaced entry carried this non-zero charge — refund it (enqueue,
    /// since the caller holds the binding lock). The new charge is kept.
    DisplacedCharge(u64),
}

/// R169-6 slice 2: charge policy a caller passes to `bind_udp` / `bind_tcp`
/// (replaces the old `charge_ephemeral: bool`). `Ephemeral` REQUIRES
/// `port == None` (kernel-chosen; charged, ghost-bind teardown); `Explicit`
/// REQUIRES `port == Some(p)` (user-chosen; charged, hold-until-close); `None`
/// is the kept-total no-charge arm (no live caller today — every current bind
/// path charges; root resolves to cgid 0 and is exempted at the charge layer
/// instead).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindCharge {
    None,
    Ephemeral,
    Explicit,
}

impl BindCharge {
    #[inline]
    fn should_charge(self) -> bool {
        !matches!(self, BindCharge::None)
    }
    #[inline]
    fn kind(self) -> BindKind {
        match self {
            BindCharge::Explicit => BindKind::Explicit,
            _ => BindKind::Ephemeral,
        }
    }
}

/// R169-6 slice 2: outcome of `resolve_while_alive_teardown` — the single
/// choke-point decision for the five while-alive teardown arms.
/// `SkipExplicit` = the entry is this socket's own CHARGED `Explicit` binding:
/// HOLD-UNTIL-CLOSE — the caller must do NOTHING (no remove, no refund, no
/// `local_*` clear). `Removed(Some(cgid))` = an own CHARGED `Ephemeral`
/// binding was removed — the caller refunds it (direct in process ctx /
/// enqueue under L8) AND clears `local_ip`/`local_port` (the ghost-bind fix;
/// lexically unreachable for a charged Explicit entry by the match in
/// `resolve_while_alive_teardown`). `Removed(None)` = uncharged own entry
/// removed, foreign ptr-miss (entry restored), or absent — nothing to refund,
/// nothing to clear.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TeardownAction {
    SkipExplicit,
    Removed(Option<u64>),
}

/// The kernel-wide cgroup registry admits at most 4096 simultaneously pinned
/// cgroups. A charged port pins its cgroup until this deferred uncharge runs,
/// so 4096 fixed slots are sufficient for every distinct pending producer,
/// including churned/deleted-but-still-pinned nodes. This makes IRQ/timer
/// cleanup allocation-free without reducing any socket or cgroup limit.
const DEFERRED_PORT_UNCHARGE_SLOTS: usize = 4096;

#[derive(Clone, Copy)]
struct DeferredPortUnchargeSlot {
    cgid: u64,
    count: u64,
}

impl DeferredPortUnchargeSlot {
    /// RF180-33 FIX: the zero cgroup id is an internal empty-slot sentinel,
    /// never a queryable queue key. Keep both fields in one representation
    /// state so a partially cleared or zero-count occupied slot cannot be
    /// mistaken for valid accounting state.
    #[inline]
    fn assert_valid(&self) {
        assert_eq!(
            self.cgid == 0,
            self.count == 0,
            "RF180-33 deferred port-uncharge slot representation corrupted"
        );
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.assert_valid();
        self.cgid == 0
    }
}

const EMPTY_DEFERRED_PORT_UNCHARGE: DeferredPortUnchargeSlot =
    DeferredPortUnchargeSlot { cgid: 0, count: 0 };

struct DeferredPortUncharges {
    slots: [DeferredPortUnchargeSlot; DEFERRED_PORT_UNCHARGE_SLOTS],
}

impl DeferredPortUncharges {
    const fn new() -> Self {
        Self {
            slots: [EMPTY_DEFERRED_PORT_UNCHARGE; DEFERRED_PORT_UNCHARGE_SLOTS],
        }
    }

    fn enqueue(&mut self, cgid: u64, count: u64) {
        if cgid == 0 || count == 0 {
            return;
        }
        let mut empty = None;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            slot.assert_valid();
            if slot.cgid == cgid {
                slot.count = slot
                    .count
                    .checked_add(count)
                    .expect("RF180-33 deferred port-uncharge count overflow");
                return;
            }
            if slot.cgid == 0 && empty.is_none() {
                empty = Some(index);
            }
        }
        let index = empty.expect("R180-11 deferred cgroup uncharge slots exhausted");
        self.slots[index] = DeferredPortUnchargeSlot { cgid, count };
    }

    fn take_one(&mut self) -> Option<(u64, u64)> {
        for slot in &mut self.slots {
            if !slot.is_empty() {
                let out = (slot.cgid, slot.count);
                *slot = EMPTY_DEFERRED_PORT_UNCHARGE;
                return Some(out);
            }
        }
        None
    }

    fn get(&self, cgid: &u64) -> Option<&u64> {
        if *cgid == 0 {
            return None;
        }
        self.slots.iter().find_map(|slot| {
            slot.assert_valid();
            (slot.cgid == *cgid).then_some(&slot.count)
        })
    }

    fn clear(&mut self) {
        self.slots.fill(EMPTY_DEFERRED_PORT_UNCHARGE);
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(DeferredPortUnchargeSlot::is_empty)
    }
}

/// Per-socket operation ownership with deferred-close handoff.
///
/// RF180-26 FIX: close-on-fd-drop may run while the Process table is locked, so
/// it must never block on `SocketState::operation`. Every state-changing socket
/// operation uses this guard. The guard releases the operation mutex first,
/// then claims and runs any pending close finalizer; consequently teardown may
/// take binding/cgroup locks without inserting the operation lock into their
/// existing order.
struct SocketOperationGuard<'a> {
    table: &'a SocketTable,
    sock: &'a SocketArc,
    lock: Option<spin::MutexGuard<'a, ()>>,
}

pub(crate) struct TcpReplyOperation<'a> {
    guard: SocketOperationGuard<'a>,
    token: u64,
}

impl TcpReplyOperation<'_> {
    fn exact_registry_owner(&self) -> bool {
        let sock = self.guard.sock;
        let meta = sock.meta_snapshot();
        let (Some(local_ip), Some(local_port), Some(remote_ip), Some(remote_port)) = (
            meta.local_ip.map(Ipv4Addr),
            meta.local_port,
            meta.remote_ip.map(Ipv4Addr),
            meta.remote_port,
        ) else {
            return false;
        };
        let key =
            tcp_map_key_from_parts(sock.net_ns_id, local_ip, local_port, remote_ip, remote_port);
        self.guard
            .table
            .tcp_conns
            .lock()
            .get(&key)
            .and_then(|owner| owner.upgrade())
            .is_some_and(|owner| Arc::ptr_eq(&owner, sock))
    }

    pub(crate) fn commit(&mut self, response: &TcpHeader, queued_at_ms: u64) -> bool {
        let sock = self.guard.sock;
        if sock.close_pending.load(Ordering::Acquire)
            || sock.is_closed()
            || !self.exact_registry_owner()
        {
            return false;
        }

        let mut tcp_guard = sock.tcp.lock();
        let Some(tcp_state) = tcp_guard.as_mut() else {
            return false;
        };
        if tcp_state.control.pending_reply_token != Some(self.token) {
            return false;
        }

        if tcp_state.control.active_open_pending {
            if response.flags != TCP_FLAG_SYN
                || response.seq_num != tcp_state.control.iss
                || response.ack_num != 0
                || tcp_state.control.state != TcpState::Closed
            {
                return false;
            }
            tcp_state.control.active_open_pending = false;
            tcp_state.control.pending_reply_token = None;
            tcp_state.control.state = TcpState::SynSent;
            tcp_state.control.last_activity = queued_at_ms;
            return true;
        }

        if let Some(pending) = tcp_state.control.pending_handshake {
            if tcp_state.control.state != TcpState::SynSent
                || response.flags != pending.response_flags
                || response.seq_num != pending.response_seq
                || response.ack_num != pending.response_ack
            {
                return false;
            }

            if let Some((ack_num, observed_at_ms)) = pending.ack_to_apply {
                self.guard.table.handle_ack_reconciled(
                    sock,
                    &mut tcp_state.control,
                    ack_num,
                    observed_at_ms,
                );
            }
            let control = &mut tcp_state.control;
            control.irs = pending.irs;
            control.rcv_nxt = pending.rcv_nxt;
            control.snd_wscale = pending.snd_wscale;
            control.wscale_received = pending.wscale_received;
            control.sack_received = pending.sack_received;
            control.snd_mss = pending.snd_mss;
            control.cwnd = pending.cwnd;
            control.snd_wnd = pending.snd_wnd;
            control.snd_wl1 = pending.snd_wl1;
            if let Some(snd_wl2) = pending.snd_wl2 {
                control.snd_wl2 = snd_wl2;
            }
            control.rcv_wnd = pending.rcv_wnd;
            control.passive_egress_confirmed = true;
            control.state = pending.target_state;
            control.pending_handshake = None;
            control.pending_reply_token = None;
            let wake_connect = pending.wake_connect;
            drop(tcp_guard);
            if wake_connect {
                sock.wake_tcp_waiters();
            }
            return true;
        }

        if tcp_state.control.state == TcpState::SynReceived
            && response.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
            && response.seq_num == tcp_state.control.iss
            && response.ack_num == tcp_state.control.rcv_nxt
        {
            tcp_state.control.passive_egress_confirmed = true;
            tcp_state.control.pending_reply_token = None;
            return true;
        }

        false
    }
}

impl Drop for SocketOperationGuard<'_> {
    fn drop(&mut self) {
        drop(self.lock.take());
        self.table.maybe_finalize_deferred_close(self.sock);
    }
}

/// RF180-52: release aggregate-admission backing retained only by a completed
/// boot self-test. Never disturb a map with live production entries; the high
/// test IDs have already been removed before this helper is called.
fn release_empty_boot_test_backing<K: Ord, V>(map: &Mutex<AdmittedMap<K, V>>) {
    let retired = {
        let mut guard = map.lock();
        if !guard.is_empty() {
            return;
        }
        core::mem::replace(&mut *guard, AdmittedMap::new(HeapClass::SocketObject))
    };
    drop(retired);
}

/// Global socket table: tracks all sockets and port bindings.
///
/// Thread-safe via RwLock (read-heavy) and Mutex (write operations).
///
/// # R75-1 FIX: Network Namespace Isolation
///
/// Port bindings (udp_bindings, tcp_bindings) are partitioned by NamespaceId.
/// Different network namespaces can bind to the same port independently,
/// providing true CLONE_NEWNET isolation.
///
/// # R76-3 FIX: Per-Namespace Socket Quota
///
/// Each namespace is limited to MAX_SOCKETS_PER_NS sockets to prevent DoS
/// attacks where a container exhausts global socket resources.
pub struct SocketTable {
    /// Next socket ID (monotonically increasing)
    next_socket_id: AtomicU64,
    /// Next ephemeral port seed
    next_ephemeral: AtomicU16,
    /// All active sockets (socket_id -> SocketState)
    sockets: RwLock<AdmittedMap<u64, SocketArc>>,
    /// R75-1 FIX: UDP port bindings partitioned by network namespace.
    /// J2-8: value carries the charged cgroup (see `PortBinding`).
    udp_bindings: Mutex<AdmittedMap<(NamespaceId, u16), PortBinding>>,
    /// R75-1 FIX: TCP local port bindings partitioned by network namespace.
    /// J2-8: value carries the charged cgroup (see `PortBinding`).
    tcp_bindings: Mutex<AdmittedMap<(NamespaceId, u16), PortBinding>>,
    /// Active TCP connections keyed by 4-tuple
    tcp_conns: Mutex<AdmittedMap<TcpLookupKey, SocketWeak>>,
    /// R76-3 FIX: Per-namespace socket count for quota enforcement
    per_ns_counts: Mutex<AdmittedMap<NamespaceId, u64>>,
    /// J2-1 FIX (Phase J.2 per-tenant quotas): Per-namespace live TCP connection
    /// count. Bound to `tcp_conns` 4-tuple MEMBERSHIP (key.0 == net_ns_id), NOT a
    /// per-socket flag, so the six stale-Weak reapers cannot leak it. A strict
    /// subset of the global `TCP_MAX_ACTIVE_CONNECTIONS` cap; root (ns 0) is exempt.
    /// Lock order: `tcp_conns` > `per_ns_conn_counts` (pure leaf, takes no further lock).
    per_ns_conn_counts: Mutex<AdmittedMap<NamespaceId, u32>>,
    /// J2-2 FIX (Phase J.2 per-tenant quotas): Per-namespace half-open (SYN-queue)
    /// count, summed across all listeners in the namespace. A strict subset of the
    /// global half-open cap; root (ns 0) is exempt. Charged/uncharged through
    /// `queue_syn`/`take_syn`. Lock order: `listen.lock` > `per_ns_syn_counts`.
    per_ns_syn_counts: Mutex<AdmittedMap<NamespaceId, u64>>,
    /// J2-6 FIX (Phase J.2 per-tenant quotas): Per-namespace aggregate TCP send
    /// buffer bytes, summed across all live connections in the namespace. A strict
    /// additional layer over the per-connection `TCP_MAX_SEND_BUFFER_BYTES` (4 MiB)
    /// cap; root (ns 0) is exempt. Charged at `tcp_send`, uncharged via the
    /// `handle_ack` reconcile and at teardown (the per-TCB `ns_charged_send_bytes`
    /// mirror records each connection's contribution). Lock order:
    /// `sock.tcp` > `per_ns_send_bytes` (pure leaf, takes no further lock).
    per_ns_send_bytes: Mutex<AdmittedMap<NamespaceId, usize>>,
    /// J2-4 FIX (Phase J.2 per-tenant quotas): Per-namespace aggregate TCP RECV
    /// footprint F = recv_buffer.len() + ooo_bytes, summed across all live
    /// connections in the namespace. A strict additional layer over the per-conn
    /// `TCP_MAX_RECV_BUFFER_BYTES` cap; root (ns 0) is exempt. Charged via a
    /// decision/counter-slot preflight + reconciled to live F under `sock.tcp`
    /// (`try_charge_ns_recv_gate` / `reconcile_ns_recv`). SOFT cap (bounded,
    /// self-correcting overshoot — never under-counts, no isolation bypass). Lock
    /// order: `sock.tcp` > `per_ns_recv_bytes` (pure leaf, takes no further lock).
    per_ns_recv_bytes: Mutex<AdmittedMap<NamespaceId, usize>>,
    /// J2-8 FIX (Phase J.2 per-tenant quotas): Deferred per-cgroup port-uncharge
    /// queue, folded by cgroup id (so its size is bounded by the number of
    /// distinct charged cgroups, never by event count). The cgroup uncharge
    /// primitive takes CGROUP_REGISTRY (Level 5) and so MUST NOT run under a
    /// net-binding lock (Level 8) or in IRQ; teardown sites that remove a binding
    /// in those contexts (cleanup_tcp_connection, deliver_udp/lookup stale prune,
    /// stale-replace, the new bindings reaper, netns Drop) ENQUEUE here instead.
    /// `drain_deferred_port_uncharges` flushes it in process context (the
    /// scheduler reschedule hook). Pure Level-8 leaf: only appended while a
    /// binding lock is already held, or alone during the process-ctx drain.
    port_uncharge_pending: Mutex<DeferredPortUncharges>,
    /// Last observed timestamp (ms) used for TIME_WAIT bookkeeping.
    /// Updated by sweep_time_wait() and used by RX path when transitioning to TIME_WAIT.
    time_wait_clock: AtomicU64,
    /// R63-5 FIX: Timer sweeps skipped due to lock contention
    timer_sweeps_skipped: AtomicU64,
    /// Statistics
    created: AtomicU64,
    closed_count: AtomicU64,
    bind_count: AtomicU64,
    /// P0-2 FIX: Forced TIME_WAIT evictions to admit SYN cookie completions
    forced_tw_evictions: AtomicU64,
    /// Deterministic cleanup-worklist OOM injection for RF180-7 tests.
    #[cfg(test)]
    fail_next_timer_cleanup_reserve: AtomicBool,
    /// Deterministic passive SYN-ACK construction failure injection.
    #[cfg(test)]
    fail_next_passive_syn_ack_build: AtomicBool,
    /// Deterministic simultaneous-open SYN-ACK construction failure injection.
    #[cfg(test)]
    fail_next_simultaneous_syn_ack_build: AtomicBool,
    /// Deterministic close-vs-operation commit-window pause.
    #[cfg(test)]
    test_operation_pause_kind: core::sync::atomic::AtomicU8,
    #[cfg(test)]
    test_operation_paused: AtomicBool,
    #[cfg(test)]
    test_operation_resume: AtomicBool,
}

#[cfg(test)]
const TEST_PAUSE_BIND_COMMIT: u8 = 1;
#[cfg(test)]
const TEST_PAUSE_CONNECT_COMMIT: u8 = 2;
#[cfg(test)]
const TEST_PAUSE_LISTEN_COMMIT: u8 = 3;
#[cfg(test)]
const TEST_PAUSE_SHUTDOWN_COMMIT: u8 = 4;

impl SocketTable {
    fn lock_socket_operation<'a>(&'a self, sock: &'a SocketArc) -> SocketOperationGuard<'a> {
        SocketOperationGuard {
            table: self,
            sock,
            lock: Some(sock.operation.lock()),
        }
    }

    fn maybe_finalize_deferred_close(&self, sock: &SocketArc) {
        if !sock.close_pending.load(Ordering::Acquire) {
            return;
        }
        if sock
            .close_finalizer_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.finish_close(sock);
        }
    }

    #[cfg(test)]
    fn pause_operation_commit_for_test(&self, kind: u8) {
        if self
            .test_operation_pause_kind
            .compare_exchange(kind, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.test_operation_paused.store(true, Ordering::Release);
        while !self.test_operation_resume.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        self.test_operation_resume.store(false, Ordering::Release);
        self.test_operation_paused.store(false, Ordering::Release);
    }

    /// Encode advertised receive window for TCP header using window scaling.
    ///
    /// RFC 7323: If window scaling is enabled, the advertised window in the
    /// TCP header is the actual available window divided by 2^scale.
    /// Uses `avoid_zero=true` to prevent advertising zero window when space exists.
    #[inline]
    fn encode_adv_window(tcb: &TcpControlBlock, available: u32) -> u16 {
        encode_window(available, tcb.effective_rcv_wscale(), true)
    }

    /// Compute current advertised receive window (scaled if negotiated).
    ///
    /// Accounts for both in-order receive buffer and out-of-order queue bytes
    /// to accurately reflect available space.
    #[inline]
    fn current_adv_window(tcb: &TcpControlBlock) -> u16 {
        let consumed = (tcb.recv_buffer.len() as u32).saturating_add(tcb.ooo_bytes);
        let available = tcb.rcv_wnd.saturating_sub(consumed);
        Self::encode_adv_window(tcb, available)
    }

    /// Build an ACK segment carrying SACK blocks (RFC 2018).
    ///
    /// If SACK is negotiated and the OOO queue is non-empty, SACK blocks are
    /// serialized into TCP options. Otherwise a plain ACK is emitted.
    ///
    /// The most recently received OOO range is placed first in the SACK block
    /// list per RFC 2018 Section 3 recommendation.
    fn build_sack_ack(
        tcb: &TcpControlBlock,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        window: u16,
    ) -> WirePacket {
        let sack_blocks = if tcb.sack_enabled() {
            tcb.generate_sack_blocks()
        } else {
            Default::default()
        };

        if sack_blocks.is_empty() {
            // Plain ACK — no SACK blocks to report
            return build_tcp_segment(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                TCP_FLAG_ACK,
                window,
                &[],
            );
        }

        // Build ACK with SACK option (kind=5).
        // NOP padding before SACK aligns to 32-bit boundary:
        //   NOP, NOP, SACK(blocks...)
        // R163-10 FIX: There are always exactly 3 options (NOP, NOP, SACK).
        // Use a stack array to eliminate the heap allocation for the opts Vec,
        // making ACK generation OOM-free for the options list itself.
        let opts = [
            TcpOptionKind::Nop,
            TcpOptionKind::Nop,
            TcpOptionKind::Sack(sack_blocks),
        ];

        build_tcp_segment_with_options(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            TCP_FLAG_ACK,
            window,
            &opts[..],
            &[],
        )
    }

    /// Create a new socket table.
    pub const fn new() -> Self {
        SocketTable {
            next_socket_id: AtomicU64::new(1),
            next_ephemeral: AtomicU16::new(EPHEMERAL_PORT_START),
            sockets: RwLock::new(AdmittedMap::new(HeapClass::SocketObject)),
            udp_bindings: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            tcp_bindings: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            tcp_conns: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            per_ns_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)), // R76-3 FIX
            per_ns_conn_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)), // J2-1 FIX
            per_ns_syn_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)), // J2-2 FIX
            per_ns_send_bytes: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)), // J2-6 FIX
            per_ns_recv_bytes: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)), // J2-4 FIX
            port_uncharge_pending: Mutex::new(DeferredPortUncharges::new()),      // J2-8/R180-11
            time_wait_clock: AtomicU64::new(0),
            timer_sweeps_skipped: AtomicU64::new(0),
            created: AtomicU64::new(0),
            closed_count: AtomicU64::new(0),
            bind_count: AtomicU64::new(0),
            forced_tw_evictions: AtomicU64::new(0),
            #[cfg(test)]
            fail_next_timer_cleanup_reserve: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_passive_syn_ack_build: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_simultaneous_syn_ack_build: AtomicBool::new(false),
            #[cfg(test)]
            test_operation_pause_kind: core::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            test_operation_paused: AtomicBool::new(false),
            #[cfg(test)]
            test_operation_resume: AtomicBool::new(false),
        }
    }

    /// R76-3 FIX: Maximum sockets allowed per network namespace.
    /// Prevents DoS via socket exhaustion within a single namespace.
    ///
    /// R180-11 FIX: this compatibility/isolation ceiling remains 8192, but is
    /// no longer the heap-safety authority. Every namespace, including root,
    /// competes under the global `SocketObject` byte admission class, which
    /// charges the real Arc and registry backing before publication.
    pub const MAX_SOCKETS_PER_NS: u64 = 8192;

    /// R76-3 FIX: Try to increment namespace socket count, failing if quota exceeded.
    fn try_inc_ns_count(&self, ns_id: NamespaceId) -> Result<(), SocketError> {
        let mut counts = self.per_ns_counts.lock();
        if let Some(count) = counts.get_mut(&ns_id) {
            if *count >= Self::MAX_SOCKETS_PER_NS {
                return Err(SocketError::QuotaExceeded);
            }
            *count += 1;
            return Ok(());
        }
        counts
            .ensure_capacity_for(1)
            .map_err(|_| SocketError::NoMemory)?;
        counts
            .insert_unique_reserved(ns_id, 1)
            .map_err(|_| SocketError::NoMemory)?;
        Ok(())
    }

    /// R76-3 FIX: Decrement namespace socket count.
    ///
    /// R170-7 FIX: remove the row at zero (mirrors the other four per-ns
    /// counter maps' prune-at-zero discipline). Without this, EVERY namespace
    /// that ever created a socket left a permanent `(ns_id, 0)` row behind —
    /// `NamespaceId`s are monotonic and never reused, so the map grew
    /// unboundedly across short-lived namespaces even when fully drained.
    fn dec_ns_count(&self, ns_id: NamespaceId) {
        let mut counts = self.per_ns_counts.lock();
        if let Some(count) = counts.get_mut(&ns_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ns_id);
            }
        }
    }

    // ========================================================================
    // Phase J.2: Per-Tenant (Per-Network-Namespace) TCP Resource Budgets
    // ========================================================================
    //
    // J2-1 (connection budget) and J2-2 (SYN-backlog budget) bound, per network
    // namespace, the two count-class TCP resources that a single tenant could
    // otherwise use to monopolize the GLOBAL pools (`TCP_MAX_ACTIVE_CONNECTIONS`
    // and the global half-open limit). Both per-ns caps are strict SUBSETS of the
    // corresponding global caps, so both gates must pass (fail-closed) — the
    // per-ns budget never weakens the existing global protection, only refines it.
    //
    // The ROOT namespace (`NamespaceId(0)`, the host) is EXEMPT: it is bounded
    // only by the global caps. This is deliberate — quotas isolate untrusted
    // tenants (CLONE_NEWNET, ns >= 1) without regressing host connection capacity
    // (a per-ns cap below the global 4096 would otherwise cap a host-only system).
    // R180-11's `SocketObject`/`SocketPayload` byte gates are separate global
    // safety limits and include root; this exemption applies only to tenant
    // fairness policy, never to retained heap admission.
    //
    // `NamespaceId` is monotonic and never reused (net_namespace.rs: NEXT_NET_NS_ID
    // is allocated via `fetch_update` + `checked_add`; Drop does not recycle), so a
    // dead namespace's stale TCP state cannot bleed accounting into a new tenant.

    /// J2-1: maximum live TCP connections per NON-root namespace (subset of the
    /// global `TCP_MAX_ACTIVE_CONNECTIONS`).
    pub const MAX_CONNS_PER_NS: u32 = 1024;
    /// J2-2: maximum half-open (SYN-queue) entries per NON-root namespace, summed
    /// across all listeners (subset of the global half-open limit).
    pub const MAX_HALF_OPEN_PER_NS: u64 = 256;
    /// J2-6: maximum aggregate buffered TCP send bytes per NON-root namespace,
    /// summed across all live connections. A strict ADDITIONAL layer on top of the
    /// per-connection `TCP_MAX_SEND_BUFFER_BYTES` (4 MiB) cap — and necessarily
    /// `>=` it so a single connection can still fill its own send buffer. 64 MiB
    /// caps a tenant at ~16 fully-buffered connections' worth of TX backlog,
    /// bounding the aggregate kernel-heap DoS a single CLONE_NEWNET tenant can
    /// inflict while leaving generous headroom for real multi-connection workloads.
    pub const MAX_SEND_BYTES_PER_NS: usize = 64 * 1024 * 1024;
    /// J2-4: maximum aggregate TCP recv footprint (recv_buffer.len() + ooo_bytes)
    /// per NON-root namespace, summed across all live connections. 64x the per-conn
    /// `TCP_MAX_RECV_BUFFER_BYTES` (256 KiB) = 16 MiB — and necessarily `>=` it so a
    /// single connection can still fill its own recv buffer. 1/4 of the 64 MiB send
    /// cap, matching the 4:1 per-conn send:recv buffer ratio. SOFT cap: the
    /// preflight-only `try_charge_ns_recv_gate` releases its leaf before the buffer
    /// mutation + `reconcile_ns_recv`, so concurrent same-ns siblings may transiently
    /// overshoot by at most (concurrent admissions) x one segment payload
    /// (<= num_cpus x snd_mss), bounded overall by MAX_CONNS_PER_NS x
    /// TCP_MAX_RECV_BUFFER_BYTES; it self-corrects on the next gate and NEVER
    /// under-counts (no isolation bypass). A hard reserve-at-gate is deliberately
    /// avoided — it would reintroduce the OOO pre-charge-refund leak class.
    pub const MAX_RECV_BYTES_PER_NS: usize = 16 * 1024 * 1024;

    /// J2-1: charge one per-namespace TCP connection. Fails closed
    /// (`QuotaExceeded` -> EAGAIN) when the tenant is at its cap. Root (ns 0) is
    /// never charged. The count is bound to `tcp_conns` MEMBERSHIP — every charge
    /// here is matched by an uncharge at the corresponding `tcp_conns` removal
    /// (`dec_ns_conn`) or stale-Weak prune (`conns_retain_accounted`), so it is
    /// exactly the live key count per namespace by construction (no flag to leak).
    /// Caller holds the `tcp_conns` guard; this nests `per_ns_conn_counts` under it.
    fn try_inc_ns_conn(&self, ns_id: NamespaceId) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) {
            return Ok(());
        }
        let mut counts = self.per_ns_conn_counts.lock();
        if let Some(count) = counts.get_mut(&ns_id) {
            if *count >= Self::MAX_CONNS_PER_NS {
                return Err(SocketError::QuotaExceeded);
            }
            *count += 1;
            return Ok(());
        }
        counts
            .ensure_capacity_for(1)
            .map_err(|_| SocketError::NoMemory)?;
        counts
            .insert_unique_reserved(ns_id, 1)
            .map_err(|_| SocketError::NoMemory)?;
        Ok(())
    }

    /// J2-1: uncharge one per-namespace TCP connection. `saturating_sub` +
    /// remove-at-0 keeps the map bounded (mirrors conntrack `dec_ns_entry_count`).
    /// No-op for root and for any namespace without a live charge.
    fn dec_ns_conn(&self, ns_id: NamespaceId) {
        if ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_conn_counts.lock();
        let now_zero = match counts.get_mut(&ns_id) {
            Some(c) => {
                *c = c.saturating_sub(1);
                *c == 0
            }
            None => false,
        };
        if now_zero {
            counts.remove(&ns_id);
        }
    }

    /// J2-1: prune dead-Weak `tcp_conns` entries AND uncharge their per-namespace
    /// connection count in a single pass, under the caller's held `tcp_conns`
    /// guard. This is the load-bearing leak fix: the dominant `tcp_conns` teardown
    /// is the six stale-Weak reapers (a freed `Arc` can never run
    /// `cleanup_tcp_connection`), so binding the count to map membership HERE is
    /// the only way to keep it leak-free. Replaces the bare
    /// `conns.retain(|_, w| w.strong_count() > 0)`.
    fn conns_retain_accounted(&self, conns: &mut AdmittedMap<TcpLookupKey, SocketWeak>) {
        let mut counts = self.per_ns_conn_counts.lock();
        conns.retain(|key, weak| {
            let keep = weak.strong_count() > 0;
            if !keep && key.0 != NamespaceId(0) {
                if let Some(c) = counts.get_mut(&key.0) {
                    *c = c.saturating_sub(1);
                }
            }
            keep
        });
        // Drop any namespace entries that reached zero (keep the map bounded).
        counts.retain(|_, v| *v != 0);
    }

    /// Remove a live TCP registration only while `sock` is still its exact owner.
    ///
    /// RF180-36 FIX: a tuple can be removed and reused between an earlier metadata
    /// snapshot and close/rollback cleanup. A key-only removal in that stale
    /// cleanup would delete the replacement socket and uncharge its namespace.
    /// Upgrade and compare the stored owner while holding `tcp_conns`; only the
    /// exact owner may remove the entry and release its accounting. The nested
    /// quota update preserves the established `tcp_conns` >
    /// `per_ns_conn_counts` lock order. Dead Weak entries deliberately remain for
    /// the existing accounted stale-Weak pruning paths.
    fn remove_tcp_conn_exact_owner(&self, key: TcpLookupKey, sock: &SocketArc) -> bool {
        let mut conns = self.tcp_conns.lock();
        let owns_entry = conns
            .get(&key)
            .and_then(|weak| weak.upgrade())
            .map_or(false, |owner| Arc::ptr_eq(&owner, sock));
        if !owns_entry || conns.remove(&key).is_none() {
            return false;
        }

        self.dec_ns_conn(key.0);
        // RF180-36 FIX: transfer the passive-open count exactly once with the
        // registration ownership. Repeated close/cleanup attempts and stale
        // tuple owners cannot decrement the replacement's global admission.
        if sock.counted_in_active.swap(false, Ordering::AcqRel) {
            dec_active_conn();
        }
        true
    }

    // ========================================================================
    // J2-8: per-cgroup ephemeral-port budget — binding choke-points, deferred
    // uncharge queue, reapers, and the netns teardown backstop.
    // ========================================================================

    /// J2-8: fold one deferred port-uncharge (`cgid` += `n`) into the pending
    /// queue. Pure Level-8 leaf — safe to call while a binding lock is held
    /// (lock order: binding-lock > `port_uncharge_pending`). The actual Level-5
    /// cgroup uncharge happens later in `drain_deferred_port_uncharges`.
    fn enqueue_port_uncharge(&self, cgid: u64, n: u64) {
        if cgid == 0 || n == 0 {
            return;
        }
        // R180-11 FIX: fixed slots make timer/RX cleanup allocation-free.
        self.port_uncharge_pending.lock().enqueue(cgid, n);
    }

    /// J2-8: flush the deferred port-uncharge queue in PROCESS context. Snapshot
    /// then clear under the leaf lock, DROP that guard, then perform the Level-5
    /// cgroup uncharges (never under a binding lock, never in IRQ). Idempotent:
    /// a second drain finds the queue empty. Called from the scheduler reschedule
    /// hook after the deferred TCP-timer drain (a producer in the same pass).
    pub fn drain_deferred_port_uncharges(&self) {
        // Take one fixed slot at a time and drop the leaf lock before entering
        // cgroup Level 5. No snapshot allocation and no lock-order regression.
        loop {
            let next = { self.port_uncharge_pending.lock().take_one() };
            match next {
                Some((cgid, n)) => uncharge_port_cgroup(cgid, n),
                None => break,
            }
        }
    }

    /// J2-8: single choke-point for REMOVING a binding entry. Returns the charged
    /// cgroup id to uncharge (non-zero only), or `None`. `expect_ptr` (`Some`)
    /// gates the removal on the entry pointing at THAT socket: a foreign entry —
    /// a recycled `(ns,port)` now owned by another socket, or a passive-open
    /// child carrying the listener's port — is restored untouched and `None`
    /// returned, so a stale-meta teardown can never uncharge/unbind someone
    /// else's binding. Operates on the caller's held guard; the caller chooses
    /// direct uncharge (process ctx, after dropping the guard) vs `enqueue`.
    fn remove_binding_charged(
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: Option<*const SocketState>,
    ) -> Option<u64> {
        match bindings.remove(&key) {
            Some(pb) => {
                if let Some(p) = expect_ptr {
                    if pb.sock_ptr() != p {
                        if bindings.insert_unique_reserved(key, pb).is_err() {
                            panic!("R180-11 removed binding lost reserved capacity");
                        }
                        return None;
                    }
                }
                if pb.charged_cgroup != 0 {
                    Some(pb.charged_cgroup)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// R169-6 slice 2: pure ptr-eq-gated read of an entry's (kind, charge).
    /// Operates on the caller's already-held guard and takes NO lock internally
    /// (the RX-context cleanup arm would self-deadlock otherwise — doc-pinned).
    /// Compares `Weak::as_ptr` WITHOUT upgrading: every caller passes the ptr
    /// of an `Arc` it itself holds, so a ptr match is live by construction; a
    /// foreign / passive-child / recycled-key entry returns `None`. (The
    /// connect registration gate deliberately does NOT use this — it must
    /// distinguish a live foreign owner from a dead stale entry, which needs
    /// `upgrade()`.)
    fn peek_binding_kind(
        bindings: &AdmittedMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: *const SocketState,
    ) -> Option<(BindKind, u64)> {
        bindings.get(&key).and_then(|pb| {
            if pb.sock_ptr() == expect_ptr {
                Some((pb.kind, pb.charged_cgroup))
            } else {
                None
            }
        })
    }

    /// R169-6 slice 2: the while-alive teardown decision for the five
    /// remove-first arms (the four connect cleanup arms + the
    /// `cleanup_tcp_connection` survivor branch). The connect registration
    /// ROLLBACK is deliberately NOT one of them — it is gated by its local
    /// `binding_registered` flag and must never adopt this helper (see the
    /// comment there). Fuses the kind peek and the ptr-eq remove under the
    /// caller's SINGLE guard hold (no TOCTOU). The `cgid != 0` qualifier is
    /// load-bearing: an uncharged (root / pre-hook) Explicit entry keeps
    /// today's remove-while-alive + connect-repair semantics.
    fn resolve_while_alive_teardown(
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: *const SocketState,
    ) -> TeardownAction {
        match Self::peek_binding_kind(bindings, key, expect_ptr) {
            Some((BindKind::Explicit, cgid)) if cgid != 0 => TeardownAction::SkipExplicit,
            _ => TeardownAction::Removed(Self::remove_binding_charged(
                bindings,
                key,
                Some(expect_ptr),
            )),
        }
    }

    /// J2-8: single choke-point for INSERTING/replacing a binding entry carrying
    /// `new_cgid`. The exhaustive `InsertOutcome` tells the caller whether the
    /// new charge is genuine growth (keep), a self-replace (undo the speculative
    /// charge), or evicted a stale charged entry (enqueue the old charge). Any
    /// displaced UNcharged entry is a plain `FreshGrowth` (nothing to uncharge).
    fn try_insert_binding_charged(
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        sock: &SocketArc,
        new_cgid: u64,
        kind: BindKind,
    ) -> Result<InsertOutcome, SocketError> {
        let prev = bindings
            .try_insert(
                key,
                PortBinding {
                    sock: Arc::downgrade(sock),
                    charged_cgroup: new_cgid,
                    kind,
                },
            )
            .map_err(|_| SocketError::NoMemory)?;
        // Always refund the displaced charge; ptr identity is irrelevant.
        match prev {
            Some(old) if old.charged_cgroup != 0 => {
                Ok(InsertOutcome::DisplacedCharge(old.charged_cgroup))
            }
            _ => Ok(InsertOutcome::FreshGrowth),
        }
    }

    /// Boot/self-test compatibility wrapper. Runtime publication paths use the
    /// fallible variant above and roll back quota state; a self-test OOM is an
    /// invariant/test-environment failure and must be visible.
    fn insert_binding_charged(
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        sock: &SocketArc,
        new_cgid: u64,
        kind: BindKind,
    ) -> InsertOutcome {
        Self::try_insert_binding_charged(bindings, key, sock, new_cgid, kind)
            .expect("R180-11 binding self-test admission")
    }

    /// J2-8: prune dead-`Weak` entries for namespace `ns` from a binding map,
    /// ENQUEUEing each charged cgroup for deferred uncharge (cgroup uncharge is
    /// not a pure leaf, so — unlike J2-1's inline `conns_retain_accounted` — it
    /// cannot run under this binding lock). Also prunes UNcharged dead Weaks so a
    /// stale entry never makes a port look in-use to the ephemeral allocator
    /// (the pre-existing `contains_key`-counts-dead-Weak port-availability bug).
    /// Runs under the caller's held binding guard.
    fn reap_dead_bindings(
        &self,
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        ns: NamespaceId,
    ) {
        self.collect_dead_binding_charges(bindings, Some(ns));
    }

    /// R169-L9/L10/L11: the shared dead-`Weak` collector behind both the
    /// alloc-time namespace-local reaper (`reap_dead_bindings`) and the global
    /// stranded-charge sweep (`sweep_stranded_port_charges`). Drops EVERY dead
    /// entry (so a stale `Weak` never makes a port look in-use to the ephemeral
    /// allocator — the pre-existing port-availability fix) and pushes the
    /// `charged_cgroup` of each dead CHARGED entry onto `to_enqueue`. When `ns`
    /// is `Some`, only that namespace is scanned (leaving others untouched);
    /// `None` scans all namespaces. Runs under the caller's held binding guard;
    /// it never charges/uncharges (the L5 cgroup uncharge is deferred to the
    /// process-context drain), so it is a pure Level-8-leaf operation.
    /// R169-6 slice 2: dead-Weak reclaim is KIND-AGNOSTIC — it reads
    /// `charged_cgroup`, never `kind` (a held Explicit charge is reclaimed
    /// identically once its socket is gone).
    fn collect_dead_binding_charges(
        &self,
        bindings: &mut AdmittedMap<(NamespaceId, u16), PortBinding>,
        ns: Option<NamespaceId>,
    ) {
        bindings.retain(|key, pb| {
            if let Some(target_ns) = ns {
                if key.0 != target_ns {
                    return true; // leave other namespaces untouched
                }
            }
            let alive = pb.sock.strong_count() > 0;
            if !alive && pb.charged_cgroup != 0 {
                self.enqueue_port_uncharge(pb.charged_cgroup, 1);
            }
            alive
        });
    }

    /// R169-L9/L10/L11: ns-AGNOSTIC sweep of stranded per-cgroup port charges.
    ///
    /// `reap_dead_bindings` only runs for the namespace of an *active* ephemeral
    /// allocation, so a socket dropped without `close()` (L9), a charge stranded
    /// in a quiescent sibling namespace (L10), or a binding whose owning netns is
    /// pinned alive by a zombie process (L11) would never be revisited and its
    /// charge would leak toward `ports.max` indefinitely. This sweep generalizes
    /// the proven dead-`Weak` reap across BOTH binding maps and ALL namespaces:
    /// the binding maps are the single source of truth, and a dead `Weak` is
    /// sufficient proof that the stored charge is reclaimable — no per-socket
    /// mirror (and therefore no ABA-prone side state) is required.
    ///
    /// Enqueue-only: each reclaimed charge is folded into the deferred
    /// port-uncharge queue (pure Level-8 leaf push under the binding lock); the
    /// Level-5 cgroup uncharge runs later in `drain_deferred_port_uncharges`
    /// (process context, IRQs enabled, no binding lock held). Locks the two maps
    /// one at a time and never crosses L8 -> L5 under a lock. Driven rate-gated
    /// from the reschedule deferred-work drain and synchronously before the
    /// `delete_cgroup` emptiness gate.
    pub fn sweep_stranded_port_charges(&self) {
        {
            let mut bindings = self.udp_bindings.lock();
            self.collect_dead_binding_charges(&mut bindings, None);
        }
        {
            let mut bindings = self.tcp_bindings.lock();
            self.collect_dead_binding_charges(&mut bindings, None);
        }
    }

    /// J2-8: remove ALL bindings (alive or dead) for namespace `ns`, enqueuing
    /// each charged cgroup. The netns-teardown backstop: once a netns is
    /// destroyed nothing ever allocates an ephemeral port in it again, so the
    /// alloc-time reaper would never run and a still-charged binding would leak
    /// forever. Wired from `NetNamespace::Drop`. Enqueue-only (Drop runs in
    /// arbitrary context; the Level-5 uncharge is deferred to the drain).
    pub fn drain_ns_port_bindings(&self, ns: NamespaceId) {
        {
            let mut bindings = self.udp_bindings.lock();
            bindings.retain(|key, pb| {
                if key.0 != ns {
                    return true;
                }
                if pb.charged_cgroup != 0 {
                    self.enqueue_port_uncharge(pb.charged_cgroup, 1);
                }
                false
            });
        }
        {
            let mut bindings = self.tcp_bindings.lock();
            bindings.retain(|key, pb| {
                if key.0 != ns {
                    return true;
                }
                if pb.charged_cgroup != 0 {
                    self.enqueue_port_uncharge(pb.charged_cgroup, 1);
                }
                false
            });
        }
    }

    /// R170-7 FIX: netns-death backstop for the FIVE per-ns COUNTER maps
    /// (`per_ns_counts` / `per_ns_conn_counts` / `per_ns_syn_counts` /
    /// `per_ns_send_bytes` / `per_ns_recv_bytes`). Every decrement path
    /// self-prunes its row at zero, but a namespace destroyed while a counter
    /// is still non-zero (draining TCB, half-open SYN, residual buffered
    /// bytes) would leak that row forever — `NamespaceId`s are monotonic and
    /// never reused, so nothing would ever decrement it again (unbounded
    /// zombie-row growth across short-lived namespaces). Wired from
    /// `NetNamespace::Drop` next to `drain_ns_port_bindings`.
    ///
    /// # Lock context (proof pinned HERE, not inherited from the Drop comment)
    ///
    /// Each of the five maps is a documented pure-leaf `Mutex` (lock_ordering
    /// J2 table: takes no further lock while held), locked ONE AT A TIME in
    /// its own statement scope. `drain_ns_port_bindings`'s "Drop runs in
    /// arbitrary context" note is about the LEVEL-5 cgroup uncharge (which
    /// must be enqueue-only) — NOT about leaf locks. The last
    /// `Arc<NetNamespace>` drop is process-context today (a PCB's namespace
    /// ref drops at reap / syscall return; `NetNamespaceFd` drops at fd
    /// close; no IRQ path holds an owning Arc), so these leaf-mutex
    /// acquisitions cannot self-deadlock against an IRQ holder. If a future
    /// change introduces an IRQ-context owning-Arc drop, this drain (and the
    /// binding-lock acquisition in `drain_ns_port_bindings`) must be
    /// re-audited.
    ///
    /// # Residual (documented, accepted)
    ///
    /// A socket mid-teardown on another CPU can hold a transient strong
    /// `Arc<SocketState>` and reconcile AFTER this drain, re-`or_insert`ing a
    /// row — but every straggler pairs its charge with an uncharge and all
    /// five decrement paths now remove-at-zero, so a re-inserted row
    /// self-heals. This drain is the backstop for rows non-zero AT namespace
    /// death, not a hard "no row after Drop" invariant (that would need
    /// ns-liveness gating of every `or_insert` — deferred; CLONE_NEWNET is
    /// implemented so namespaces ARE created/destroyed today, but sockets
    /// carry only `net_ns_id` by value and the residual self-heals via the
    /// remove-at-zero decrement paths).
    pub fn drain_ns_counters(&self, ns: NamespaceId) {
        {
            self.per_ns_counts.lock().remove(&ns);
        }
        {
            self.per_ns_conn_counts.lock().remove(&ns);
        }
        {
            self.per_ns_syn_counts.lock().remove(&ns);
        }
        {
            self.per_ns_send_bytes.lock().remove(&ns);
        }
        {
            self.per_ns_recv_bytes.lock().remove(&ns);
        }
    }

    /// J2-2: charge one per-namespace half-open (SYN-queue) slot. Returns false
    /// (caller falls back to stateless SYN cookies) when the tenant is at its cap.
    /// Root (ns 0) is exempt only from this tenant-fairness counter. Every
    /// half-open child's object, queue backing, and cached packet remains under
    /// the global SocketObject/SocketPayload admission gates. Charged in the
    /// SYN publication transaction and uncharged in `take_syn` / listener close.
    fn try_inc_ns_syn(&self, ns_id: NamespaceId) -> bool {
        if ns_id == NamespaceId(0) {
            return true;
        }
        let mut counts = self.per_ns_syn_counts.lock();
        if let Some(count) = counts.get_mut(&ns_id) {
            if *count >= Self::MAX_HALF_OPEN_PER_NS {
                return false;
            }
            *count += 1;
            return true;
        }
        if counts.ensure_capacity_for(1).is_err() {
            return false;
        }
        counts.insert_unique_reserved(ns_id, 1).is_ok()
    }

    /// J2-2: uncharge one per-namespace half-open slot.
    fn dec_ns_syn(&self, ns_id: NamespaceId) {
        self.dec_ns_syn_by(ns_id, 1);
    }

    /// J2-2: uncharge `n` per-namespace half-open slots at once. Used by the
    /// listener-close drain, which removes the whole SYN queue under `listen.lock`
    /// and defers the per-ns decrement to the proven `dec_ns_count` safe context.
    fn dec_ns_syn_by(&self, ns_id: NamespaceId, n: u64) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_syn_counts.lock();
        let now_zero = match counts.get_mut(&ns_id) {
            Some(c) => {
                *c = c.saturating_sub(n);
                *c == 0
            }
            None => false,
        };
        if now_zero {
            counts.remove(&ns_id);
        }
    }

    /// J2-6: charge `additional` aggregate send bytes to the namespace's TX-memory
    /// budget, RESERVING headroom atomically under the leaf lock so the cap is HARD
    /// even across sibling sockets in the same namespace (no read-then-commit
    /// TOCTOU). On success the per-TCB mirror is advanced by the SAME amount so the
    /// invariant `per_ns_send_bytes[ns] == Σ live tcb.ns_charged_send_bytes` holds.
    /// Fails closed (`WouldBlock` -> caller retries after ACKs drain) at the cap;
    /// the reservation is all-or-nothing (never partially applied on failure).
    /// Root (ns 0) / zero are no-ops. Caller holds `sock.tcp.lock()`; nests
    /// `per_ns_send_bytes` as a pure leaf.
    fn try_charge_ns_send(
        &self,
        ns_id: NamespaceId,
        tcb: &mut TcpControlBlock,
        additional: usize,
    ) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) || additional == 0 {
            return Ok(());
        }
        let mut counts = self.per_ns_send_bytes.lock();
        let current = counts.get(&ns_id).copied().unwrap_or(0);
        let projected = match current.checked_add(additional) {
            Some(p) if p <= Self::MAX_SEND_BYTES_PER_NS => p,
            _ => return Err(SocketError::WouldBlock),
        };
        if let Some(e) = counts.get_mut(&ns_id) {
            *e = projected;
        } else {
            counts
                .ensure_capacity_for(1)
                .map_err(|_| SocketError::NoMemory)?;
            counts
                .insert_unique_reserved(ns_id, projected)
                .map_err(|_| SocketError::NoMemory)?;
        }
        tcb.ns_charged_send_bytes = tcb.ns_charged_send_bytes.saturating_add(additional);
        Ok(())
    }

    /// J2-6: reconcile the namespace TX-memory counter toward this TCB's LIVE
    /// `send_buffer_bytes`, applying the signed delta vs the per-TCB mirror
    /// (`ns_charged_send_bytes`). REFUNDS an over-reservation after partial
    /// buffering and UNCHARGES bytes freed by `handle_ack`. Never enforces the cap
    /// (the charge path already did) — it only trues the counter toward the real
    /// footprint, so it can never reject. Saturating + remove-at-0. Root (ns 0):
    /// just keep the mirror in lockstep. Caller holds `sock.tcp.lock()`; pure leaf.
    fn reconcile_ns_send(&self, ns_id: NamespaceId, tcb: &mut TcpControlBlock) {
        if ns_id == NamespaceId(0) {
            tcb.ns_charged_send_bytes = tcb.send_buffer_bytes;
            return;
        }
        let live = tcb.send_buffer_bytes;
        let charged = tcb.ns_charged_send_bytes;
        if live == charged {
            return;
        }
        let mut counts = self.per_ns_send_bytes.lock();
        if live > charged {
            let e = counts
                .get_mut(&ns_id)
                .expect("R180-11 send counter slot was not prepared before payload growth");
            *e = e.saturating_add(live - charged);
        } else if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(charged - live);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
        tcb.ns_charged_send_bytes = live;
    }

    /// J2-6: uncharge `n` residual send bytes at connection teardown (the caller
    /// reads the per-TCB mirror and zeroes it). Saturating + remove-at-0; mirrors
    /// `dec_ns_conn`. Root (ns 0) / zero are no-ops.
    fn uncharge_ns_send_residual(&self, ns_id: NamespaceId, n: usize) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_send_bytes.lock();
        if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(n);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
    }

    /// J2-6: run `handle_ack` then reconcile the per-namespace send-byte counter
    /// down by the bytes the ACK freed from `send_buffer`. The thin wrapper exists
    /// because `handle_ack` (tcp.rs) has no `net_ns_id` in scope; the socket-layer
    /// caller holds `sock` and the `sock.tcp` guard. Applied at the 7
    /// ESTABLISHED/FIN-state ACK sites; the SYN-cookie path (detached TCB,
    /// `send_buffer_bytes == 0`) and the `apply_ack_and_cc` hot path reconcile
    /// separately. `handle_ack`'s `AckUpdate` is discarded at these sites, as
    /// before.
    fn handle_ack_reconciled(
        &self,
        sock: &SocketArc,
        tcb: &mut TcpControlBlock,
        ack_num: u32,
        now_ms: u64,
    ) {
        handle_ack(tcb, ack_num, now_ms);
        self.reconcile_ns_send(sock.net_ns_id, tcb);
    }

    /// J2-6: the SOLE helper allowed to null a connection's TCB (`*sock.tcp = None`)
    /// from a context that does not already hold the guard. It first uncharges the
    /// residual per-namespace send bytes and zeroes the mirror, closing the leak
    /// class (a TCB dropped with bytes still charged) STRUCTURALLY. Used at the
    /// SYN-SENT connect-timeout site; `cleanup_tcp_connection` inlines the same
    /// sequence under its already-held guard. The last-ref `impl Drop for
    /// SocketState` is the catch-all for the close-non-keep path that nulls nothing.
    fn detach_tcp_uncharged(&self, sock: &SocketArc) {
        let mut g = sock.tcp.lock();
        if let Some(ts) = g.as_mut() {
            let charged = ts.control.ns_charged_send_bytes;
            if charged > 0 {
                self.uncharge_ns_send_residual(sock.net_ns_id, charged);
                ts.control.ns_charged_send_bytes = 0;
            }
            // J2-4: symmetric recv-byte residual uncharge.
            let rcharged = ts.control.ns_charged_recv_bytes;
            if rcharged > 0 {
                self.uncharge_ns_recv_residual(sock.net_ns_id, rcharged);
                ts.control.ns_charged_recv_bytes = 0;
            }
        }
        *g = None;
    }

    /// J2-4: per-namespace RECV-memory budget PRE-GATE. It takes no byte charge
    /// and does not move the TCB mirror; it decides whether `grow_by` would push
    /// the namespace aggregate past the cap and prepares a zero-valued counter
    /// slot so post-allocation reconciliation is allocation-free. Root (ns 0) /
    /// zero are admitted. The actual counter move happens later in
    /// `reconcile_ns_recv` AFTER the buffer mutation,
    /// because recv's true F-delta is unknown pre-mutation (ooo_insert returns a
    /// merge-adjusted delta; ooo_drain is net-neutral-except-FIN-clear). `grow_by`
    /// is the UPPER bound on F-growth (payload.len()/useful.len()), so the gate is
    /// conservative-strict and never under-counts. SOFT cap — see MAX_RECV_BYTES_PER_NS.
    /// Caller holds `sock.tcp.lock()`; nests `per_ns_recv_bytes` as a pure leaf.
    fn try_charge_ns_recv_gate(
        &self,
        ns_id: NamespaceId,
        tcb: &TcpControlBlock,
        grow_by: usize,
    ) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) || grow_by == 0 {
            return Ok(());
        }
        let mut counts = self.per_ns_recv_bytes.lock();
        let live = counts.get(&ns_id).copied().unwrap_or(0);
        let charged = tcb.ns_charged_recv_bytes;
        // The namespace footprint EXCLUDING this connection's current contribution,
        // plus this connection's projected footprint after the growth.
        let other_conns = live.saturating_sub(charged);
        let conn_after = charged.saturating_add(grow_by);
        match other_conns.checked_add(conn_after) {
            Some(projected) if projected <= Self::MAX_RECV_BYTES_PER_NS => {
                if !counts.contains_key(&ns_id) {
                    counts
                        .ensure_capacity_for(1)
                        .map_err(|_| SocketError::NoMemory)?;
                    counts
                        .insert_unique_reserved(ns_id, 0)
                        .map_err(|_| SocketError::NoMemory)?;
                }
                Ok(())
            }
            _ => Err(SocketError::WouldBlock),
        }
    }

    /// J2-4: reconcile the namespace RECV counter toward this TCB's LIVE footprint
    /// F = recv_buffer.len() + ooo_bytes, applying the signed delta vs the per-TCB
    /// mirror (`ns_charged_recv_bytes`). This single primitive absorbs ooo_drain
    /// neutrality, ooo_insert merge-absorption, and FIN-clear shrink. Saturating +
    /// remove-at-0. NEVER rejects (the gate already enforced). Idempotent — a second
    /// call with unchanged F is a no-op (safe to over-place). Root (ns 0): just keep
    /// the mirror in lockstep. Caller holds `sock.tcp.lock()`; pure leaf.
    fn reconcile_ns_recv(&self, ns_id: NamespaceId, tcb: &mut TcpControlBlock) {
        let live = tcb.recv_buffer.len().saturating_add(tcb.ooo_bytes as usize);
        if ns_id == NamespaceId(0) {
            tcb.ns_charged_recv_bytes = live;
            return;
        }
        let charged = tcb.ns_charged_recv_bytes;
        if live == charged {
            if live == 0 {
                self.per_ns_recv_bytes.lock().remove(&ns_id);
            }
            return;
        }
        let mut counts = self.per_ns_recv_bytes.lock();
        if live > charged {
            let e = counts
                .get_mut(&ns_id)
                .expect("R180-11 recv counter slot was not prepared before payload growth");
            *e = e.saturating_add(live - charged);
        } else if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(charged - live);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
        tcb.ns_charged_recv_bytes = live;
    }

    /// J2-4: uncharge `n` residual recv bytes at connection teardown (the caller
    /// reads the per-TCB mirror and zeroes it). Saturating + remove-at-0; mirrors
    /// `uncharge_ns_send_residual`. Root (ns 0) / zero are no-ops.
    fn uncharge_ns_recv_residual(&self, ns_id: NamespaceId, n: usize) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_recv_bytes.lock();
        if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(n);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
    }

    /// Remove a socket from the `sockets` map, returning the owned Arc with the
    /// write guard ALREADY dropped (the guard is a temporary confined to this fn).
    /// Callers can then run teardown — e.g. cleanup_tcp_connection(), which
    /// re-acquires `sockets.write()` (R129-2) — WITHOUT self-deadlocking. In
    /// edition 2021 a temporary in an `if let` scrutinee lives to the END of the
    /// block, so `if let Some(s) = self.sockets.write().remove(..) { .. }` would
    /// hold the write lock across the body; routing the removal through this helper
    /// confines the guard to the call.
    fn remove_socket(&self, socket_id: u64) -> Option<SocketArc> {
        self.sockets.write().remove(&socket_id)
    }

    /// J2-1/J2-2 self-test (Phase J.2 per-tenant TCP budgets). Exercises the
    /// per-namespace connection + half-open counters directly on the
    /// boot-quiescent global `SocketTable`, using reserved high namespace IDs:
    /// cap enforcement (fail-closed), namespace isolation, root exemption,
    /// remove-at-0 bookkeeping, and — critically — that the stale-Weak
    /// reaper (`conns_retain_accounted`) UNCHARGES pruned entries (the leak fix a
    /// per-socket flag could not provide). Any failure panics; `make boot-check`
    /// surfaces it via the serial log. Wired into the boot integration suite.
    pub fn run_per_ns_budget_self_test() {
        // RF180-52: never instantiate SocketTable on a kernel stack; its fixed
        // deferred-uncharge array alone exceeds the AP stack. Deferred process
        // work remains gated until boot self-tests finish, so isolated high IDs
        // make the production singleton a safe, allocation-neutral fixture.
        let table = socket_table();
        let ns_a = NamespaceId(0x7100_0001);
        let ns_b = NamespaceId(0x7100_0002);
        let root = NamespaceId(0);

        // --- J2-1 connection budget: cap (fail-closed), isolation, root exemption ---
        for _ in 0..SocketTable::MAX_CONNS_PER_NS {
            table
                .try_inc_ns_conn(ns_a)
                .expect("J2-1: ns_a under cap should succeed");
        }
        assert!(
            table.try_inc_ns_conn(ns_a).is_err(),
            "J2-1: ns_a connection budget must fail closed at the cap"
        );
        table
            .try_inc_ns_conn(ns_b)
            .expect("J2-1: ns_b must be independent of ns_a");
        table.dec_ns_conn(ns_b);
        for _ in 0..(SocketTable::MAX_CONNS_PER_NS + 16) {
            table
                .try_inc_ns_conn(root)
                .expect("J2-1: root namespace must be exempt");
        }
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&root),
            "J2-1: root must never be tracked in per_ns_conn_counts"
        );
        for _ in 0..SocketTable::MAX_CONNS_PER_NS {
            table.dec_ns_conn(ns_a);
        }
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&ns_a),
            "J2-1: per_ns_conn_counts key must be removed at zero"
        );
        table.dec_ns_conn(ns_a); // saturating underflow guard (no panic, no underflow)

        // --- J2-1 leak-via-retain regression (the load-bearing fix) ---
        // A dead-Weak prune MUST uncharge the per-namespace count, else a tenant
        // wedges at its cap forever (self-DoS). Build a tcp_conns map of dead Weaks
        // and confirm conns_retain_accounted prunes AND uncharges exactly them,
        // leaving an unrelated namespace's count untouched.
        let ns_dead = NamespaceId(0x7100_0003);
        let ns_other = NamespaceId(0x7100_0004);
        const N_DEAD: u32 = 5;
        for _ in 0..N_DEAD {
            table.try_inc_ns_conn(ns_dead).unwrap();
        }
        table.try_inc_ns_conn(ns_other).unwrap(); // unrelated tenant, no map entry
        let mut conns: AdmittedMap<TcpLookupKey, SocketWeak> =
            AdmittedMap::new(HeapClass::SocketObject);
        let dead_owner = SocketState::try_new_arc(
            0,
            SocketDomain::Inet4,
            SocketType::Stream,
            SocketProtocol::Tcp,
            SocketLabel {
                creator: ProcessCtx::new(0, 0, 0, 0, 0, 0),
                secmark: 0,
            },
            ns_dead,
        )
        .expect("J2 self-test dead-Weak owner admission");
        let dead = Arc::downgrade(&dead_owner);
        drop(dead_owner);
        for i in 0..N_DEAD {
            // The sole strong owner is gone, while cloned weak handles keep the
            // charged Arc control block valid until the reaper destroys them.
            conns
                .try_insert((ns_dead, i, 0u16, 0u32, 0u16), dead.clone())
                .expect("J2 self-test admitted conn map insert");
        }
        drop(dead);
        table.conns_retain_accounted(&mut conns);
        assert!(
            conns.is_empty(),
            "J2-1: all dead-Weak entries must be pruned"
        );
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&ns_dead),
            "J2-1 LEAK REGRESSION: pruned dead-Weak entries must uncharge to zero"
        );
        assert_eq!(
            table.per_ns_conn_counts.lock().get(&ns_other).copied(),
            Some(1u32),
            "J2-1: an unrelated namespace must be untouched by the reaper"
        );
        table.dec_ns_conn(ns_other);

        // --- J2-2 half-open (SYN) budget: cap, isolation, root exemption, batch drain ---
        for _ in 0..SocketTable::MAX_HALF_OPEN_PER_NS {
            assert!(
                table.try_inc_ns_syn(ns_a),
                "J2-2: ns_a under cap should succeed"
            );
        }
        assert!(
            !table.try_inc_ns_syn(ns_a),
            "J2-2: ns_a half-open budget must fail closed at the cap"
        );
        assert!(
            table.try_inc_ns_syn(ns_b),
            "J2-2: ns_b must be independent of ns_a"
        );
        table.dec_ns_syn(ns_b);
        for _ in 0..(SocketTable::MAX_HALF_OPEN_PER_NS + 8) {
            assert!(
                table.try_inc_ns_syn(root),
                "J2-2: root namespace must be exempt"
            );
        }
        assert!(
            !table.per_ns_syn_counts.lock().contains_key(&root),
            "J2-2: root must never be tracked in per_ns_syn_counts"
        );
        // Batch drain mirrors the listener-close path; key removed at zero.
        table.dec_ns_syn_by(ns_a, SocketTable::MAX_HALF_OPEN_PER_NS);
        assert!(
            !table.per_ns_syn_counts.lock().contains_key(&ns_a),
            "J2-2: per_ns_syn_counts key must be removed at zero after batch drain"
        );
        table.dec_ns_syn_by(ns_a, 100); // saturating underflow guard

        // --- J2-6 send-byte budget: hard cap, isolation, root exemption,
        //     reserve->refund reconcile, remove-at-0, and the load-bearing
        //     Drop/detach residual regressions ---
        let ns_s = NamespaceId(0x7100_0010);
        let ns_t = NamespaceId(0x7100_0011);
        let ns_u = NamespaceId(0x7100_0012);

        // (1) HARD cap, fail-closed, atomic reservation (no partial-apply on reject).
        let mut tcb_a =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 1]), 1, Ipv4Addr([10, 0, 0, 2]), 2, 0);
        assert!(
            table
                .try_charge_ns_send(ns_s, &mut tcb_a, SocketTable::MAX_SEND_BYTES_PER_NS)
                .is_ok(),
            "J2-6: charge up to the cap must succeed"
        );
        assert_eq!(
            tcb_a.ns_charged_send_bytes,
            SocketTable::MAX_SEND_BYTES_PER_NS,
            "J2-6: the per-TCB mirror must track the charged amount"
        );
        let mut tcb_b =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 3]), 3, Ipv4Addr([10, 0, 0, 4]), 4, 0);
        assert!(
            table.try_charge_ns_send(ns_s, &mut tcb_b, 1).is_err(),
            "J2-6: one byte over the cap must fail closed"
        );
        assert_eq!(
            tcb_b.ns_charged_send_bytes, 0,
            "J2-6: a rejected reservation must not advance the mirror"
        );
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_s).copied(),
            Some(SocketTable::MAX_SEND_BYTES_PER_NS),
            "J2-6: a rejected reservation must not partially apply to the counter"
        );

        // (2) Namespace isolation: ns_t independent of ns_s.
        let mut tcb_c =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 5]), 5, Ipv4Addr([10, 0, 0, 6]), 6, 0);
        assert!(
            table.try_charge_ns_send(ns_t, &mut tcb_c, 4096).is_ok(),
            "J2-6: ns_t must be independent of ns_s"
        );

        // (3) Root exemption: never charged, never tracked.
        let mut tcb_root =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 7]), 7, Ipv4Addr([10, 0, 0, 8]), 8, 0);
        assert!(
            table
                .try_charge_ns_send(root, &mut tcb_root, SocketTable::MAX_SEND_BYTES_PER_NS * 4)
                .is_ok(),
            "J2-6: root is exempt from the send-byte cap"
        );
        assert_eq!(
            tcb_root.ns_charged_send_bytes, 0,
            "J2-6: a root charge must not advance the mirror"
        );
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&root),
            "J2-6: root must never be tracked in per_ns_send_bytes"
        );

        // (4) Reserve->refund reconcile (the double-count fix): reserve a payload,
        //     buffer fewer bytes (OOM truncation), reconcile -> counter trues DOWN.
        let mut tcb_r = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 9]),
            9,
            Ipv4Addr([10, 0, 0, 10]),
            10,
            0,
        );
        assert!(table.try_charge_ns_send(ns_u, &mut tcb_r, 8192).is_ok());
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_u).copied(),
            Some(8192)
        );
        tcb_r.send_buffer_bytes = 5000; // only 5000 of the 8192 reserved were buffered
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert_eq!(
            tcb_r.ns_charged_send_bytes, 5000,
            "J2-6: reconcile must true the mirror to the live send_buffer_bytes"
        );
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_u).copied(),
            Some(5000),
            "J2-6: reconcile must refund the (reserved - buffered) shortfall (no double-count)"
        );
        tcb_r.send_buffer_bytes = 1000; // ACK drains 5000 -> 1000
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_u).copied(),
            Some(1000)
        );
        tcb_r.send_buffer_bytes = 0; // fully drained -> remove-at-0
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&ns_u),
            "J2-6: per_ns_send_bytes key must be removed at zero"
        );
        assert_eq!(tcb_r.ns_charged_send_bytes, 0);

        // (5) Saturating-underflow guard on residual uncharge (absent key).
        table.uncharge_ns_send_residual(ns_u, 999);
        assert!(!table.per_ns_send_bytes.lock().contains_key(&ns_u));

        // (6) DROP-RESIDUAL regression — the load-bearing Channel-A anchor. Build a
        //     real Arc<SocketState> with an attached TCB, charge the GLOBAL table
        //     (impl Drop uncharges via socket_table()), then drop the Arc and assert
        //     the residual is gone. Unique high namespace ids avoid colliding with
        //     any live boot socket.
        let gtable = socket_table();
        let drop_ns = NamespaceId(0x7000_0001);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = SocketState::try_new_arc(
                u64::MAX,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                drop_ns,
            )
            .expect("J2 self-test socket admission");
            let tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 0, 0, 11]),
                11,
                Ipv4Addr([10, 0, 0, 12]),
                12,
                0,
            );
            sock.attach_tcp(tcb).expect("J2 self-test TCP waiters");
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable
                    .try_charge_ns_send(drop_ns, &mut ts.control, 256 * 1024)
                    .expect("charge under cap");
            }
            assert_eq!(
                gtable.per_ns_send_bytes.lock().get(&drop_ns).copied(),
                Some(256 * 1024),
                "J2-6: global per-ns send bytes charged before drop"
            );
            // `sock` dropped here -> impl Drop uncharges the residual via the mirror.
        }
        assert!(
            !gtable.per_ns_send_bytes.lock().contains_key(&drop_ns),
            "J2-6: Drop must uncharge the residual per-ns send bytes (leak-class regression)"
        );

        // (7) detach_tcp_uncharged regression: nulling the TCB uncharges + zeroes the
        //     mirror, and a subsequent Drop is a 0 no-op (no double-subtract).
        let detach_ns = NamespaceId(0x7000_0002);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = SocketState::try_new_arc(
                u64::MAX - 1,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                detach_ns,
            )
            .expect("J2 self-test socket admission");
            let tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 0, 0, 13]),
                13,
                Ipv4Addr([10, 0, 0, 14]),
                14,
                0,
            );
            sock.attach_tcp(tcb).expect("J2 self-test TCP waiters");
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable
                    .try_charge_ns_send(detach_ns, &mut ts.control, 128 * 1024)
                    .expect("charge under cap");
            }
            gtable.detach_tcp_uncharged(&sock);
            assert!(
                !gtable.per_ns_send_bytes.lock().contains_key(&detach_ns),
                "J2-6: detach_tcp_uncharged must uncharge the residual"
            );
            // `sock` dropped here -> Drop finds the TCB nulled -> uncharges 0.
        }
        assert!(
            !gtable.per_ns_send_bytes.lock().contains_key(&detach_ns),
            "J2-6: a post-detach Drop must not double-subtract"
        );

        // (8) AGGREGATION invariant: per_ns_send_bytes[ns] == sum over MULTIPLE live
        //     conns in the SAME ns. Charge TWO TCBs into one namespace, assert the
        //     sum, tear ONE down, assert the counter drops to exactly the other's
        //     mirror (not 0, not the sum). This is the only test that proves the
        //     cross-sibling accumulation the whole budget exists to enforce.
        let ns_agg = NamespaceId(0x7100_0013);
        let mut tcb_x = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 15]),
            15,
            Ipv4Addr([10, 0, 0, 16]),
            16,
            0,
        );
        let mut tcb_y = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 17]),
            17,
            Ipv4Addr([10, 0, 0, 18]),
            18,
            0,
        );
        assert!(table.try_charge_ns_send(ns_agg, &mut tcb_x, 3000).is_ok());
        assert!(table.try_charge_ns_send(ns_agg, &mut tcb_y, 5000).is_ok());
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_agg).copied(),
            Some(8000),
            "J2-6: the per-ns counter must be the SUM of sibling conns' charges"
        );
        // Tear down conn x (simulate its full drain): the counter must drop to
        // exactly y's mirror, proving per-conn attribution within the sum.
        tcb_x.send_buffer_bytes = 0;
        table.reconcile_ns_send(ns_agg, &mut tcb_x);
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_agg).copied(),
            Some(5000),
            "J2-6: tearing down one sibling must leave exactly the other's charge"
        );
        assert_eq!(tcb_y.ns_charged_send_bytes, 5000);
        tcb_y.send_buffer_bytes = 0;
        table.reconcile_ns_send(ns_agg, &mut tcb_y);
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&ns_agg),
            "J2-6: counter removed at zero after all siblings drain"
        );

        // ================= J2-4 recv-byte budget (10 cases) =================
        // Drive the counter via a TCB's ooo_bytes (a plain field — no multi-MiB
        // allocation) + reconcile_ns_recv; the gate is decide-only so it is tested
        // separately. recv_buffer is exercised directly only in the FIN-clear case.
        let ns_rs = NamespaceId(0x7100_0020);
        let ns_rt = NamespaceId(0x7100_0021);
        let ns_ru = NamespaceId(0x7100_0022);
        let ns_ragg = NamespaceId(0x7100_0023);
        let ns_rx = NamespaceId(0x7100_0024);

        // (1) Aggregate cap (decide-only gate): drive ns_rs to the cap, assert a
        //     sibling (charged==0) is rejected — proving it is an aggregate, not
        //     per-conn, cap.
        let mut rtcb_a =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 1]), 1, Ipv4Addr([10, 1, 0, 2]), 2, 0);
        table
            .try_charge_ns_recv_gate(ns_rs, &rtcb_a, SocketTable::MAX_RECV_BYTES_PER_NS)
            .expect("J2 recv test gate");
        rtcb_a.ooo_bytes = SocketTable::MAX_RECV_BYTES_PER_NS as u32;
        table.reconcile_ns_recv(ns_rs, &mut rtcb_a);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_rs).copied(),
            Some(SocketTable::MAX_RECV_BYTES_PER_NS),
            "J2-recv: reconcile must charge the full footprint"
        );
        let rtcb_b =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 3]), 3, Ipv4Addr([10, 1, 0, 4]), 4, 0);
        assert!(
            table.try_charge_ns_recv_gate(ns_rs, &rtcb_b, 1).is_err(),
            "J2-recv: one byte over the aggregate cap must be rejected (sibling)"
        );

        // (2) Namespace isolation.
        let rtcb_c =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 5]), 5, Ipv4Addr([10, 1, 0, 6]), 6, 0);
        assert!(
            table.try_charge_ns_recv_gate(ns_rt, &rtcb_c, 4096).is_ok(),
            "J2-recv: ns_rt must be independent of ns_rs"
        );

        // (3) Root exemption: gate always Ok; reconcile sets the mirror but no key.
        let mut rtcb_root =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 7]), 7, Ipv4Addr([10, 1, 0, 8]), 8, 0);
        assert!(
            table
                .try_charge_ns_recv_gate(root, &rtcb_root, SocketTable::MAX_RECV_BYTES_PER_NS * 4)
                .is_ok(),
            "J2-recv: root is exempt from the recv cap"
        );
        rtcb_root.ooo_bytes = 9999;
        table.reconcile_ns_recv(root, &mut rtcb_root);
        assert!(
            !table.per_ns_recv_bytes.lock().contains_key(&root),
            "J2-recv: root must never be tracked in per_ns_recv_bytes"
        );

        // (4) Reconcile down-true + remove-at-0.
        let mut rtcb_u = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 9]),
            9,
            Ipv4Addr([10, 1, 0, 10]),
            10,
            0,
        );
        table
            .try_charge_ns_recv_gate(ns_ru, &rtcb_u, 8192)
            .expect("J2 recv test gate");
        rtcb_u.ooo_bytes = 8192;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ru).copied(),
            Some(8192)
        );
        rtcb_u.ooo_bytes = 5000;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ru).copied(),
            Some(5000)
        );
        rtcb_u.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert!(
            !table.per_ns_recv_bytes.lock().contains_key(&ns_ru),
            "J2-recv: counter removed at zero"
        );

        // (5) Saturating-underflow guard on residual uncharge (absent key).
        table.uncharge_ns_recv_residual(ns_ru, 999);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ru));

        // (9) FIN-CLEAR-NO-OVERCOUNT (headline recv hazard): F = recv_buffer.len() +
        //     ooo_bytes; clearing OOO must drop the counter to recv_buffer.len() only.
        let mut rtcb_fin = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 11]),
            11,
            Ipv4Addr([10, 1, 0, 12]),
            12,
            0,
        );
        for _ in 0..1000 {
            rtcb_fin
                .recv_buffer
                .try_push(0u8)
                .map_err(|_| ())
                .expect("J2 recv self-test admitted byte");
        }
        table
            .try_charge_ns_recv_gate(ns_ru, &rtcb_fin, 5000)
            .expect("J2 recv FIN test gate");
        rtcb_fin.ooo_bytes = 4000;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ru).copied(),
            Some(5000)
        );
        rtcb_fin.ooo_bytes = 0; // simulate the FIN-clear OOO purge
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ru).copied(),
            Some(1000),
            "J2-recv: FIN-clear must drop the counter to recv_buffer.len() (no over-count)"
        );
        rtcb_fin.recv_buffer.clear();
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ru));

        // (8) AGGREGATION across two live siblings in one namespace.
        let mut rtcb_x = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 13]),
            13,
            Ipv4Addr([10, 1, 0, 14]),
            14,
            0,
        );
        let mut rtcb_y = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 15]),
            15,
            Ipv4Addr([10, 1, 0, 16]),
            16,
            0,
        );
        table
            .try_charge_ns_recv_gate(ns_ragg, &rtcb_x, 3000)
            .expect("J2 recv aggregate x gate");
        rtcb_x.ooo_bytes = 3000;
        table
            .try_charge_ns_recv_gate(ns_ragg, &rtcb_y, 5000)
            .expect("J2 recv aggregate y gate");
        rtcb_y.ooo_bytes = 5000;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_x);
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_y);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ragg).copied(),
            Some(8000),
            "J2-recv: per-ns counter must be the SUM of sibling footprints"
        );
        rtcb_x.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_x);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ragg).copied(),
            Some(5000),
            "J2-recv: tearing down one sibling leaves exactly the other's footprint"
        );
        rtcb_y.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_y);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ragg));

        // (10) GATE-REARM + OOO-non-bypass: the post-mutation reconcile (not the
        //      gate) is what re-arms enforcement; the gate is grow_by-agnostic, so an
        //      OOO grow_by is admitted/rejected identically to an in-order one.
        let mut rtcb_near = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 17]),
            17,
            Ipv4Addr([10, 1, 0, 18]),
            18,
            0,
        );
        table
            .try_charge_ns_recv_gate(ns_rx, &rtcb_near, SocketTable::MAX_RECV_BYTES_PER_NS - 1000)
            .expect("J2 recv near-cap gate");
        rtcb_near.ooo_bytes = (SocketTable::MAX_RECV_BYTES_PER_NS - 1000) as u32;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_near);
        let rtcb_probe = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 19]),
            19,
            Ipv4Addr([10, 1, 0, 20]),
            20,
            0,
        );
        assert!(
            table
                .try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 500)
                .is_ok(),
            "J2-recv: gate admits below the cap"
        );
        assert!(
            table
                .try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 2000)
                .is_err(),
            "J2-recv: gate rejects above the cap (same logic for OOO and in-order)"
        );
        let mut rtcb_push = TcpControlBlock::new_client(
            Ipv4Addr([10, 1, 0, 21]),
            21,
            Ipv4Addr([10, 1, 0, 22]),
            22,
            0,
        );
        rtcb_push.ooo_bytes = 1500;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_push);
        assert!(
            table
                .try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 1)
                .is_err(),
            "J2-recv: a reconcile that pushes the ns past the cap re-arms the gate"
        );
        rtcb_near.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_near);
        rtcb_push.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_push);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_rx));

        // (6) DROP-RESIDUAL + (7) detach regressions on a real Arc<SocketState>,
        //     charging the GLOBAL socket_table() (impl Drop / detach uncharge it).
        let rdrop_ns = NamespaceId(0x7000_0011);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = SocketState::try_new_arc(
                u64::MAX - 2,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                rdrop_ns,
            )
            .expect("J2 recv self-test socket admission");
            let mut tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 1, 0, 23]),
                23,
                Ipv4Addr([10, 1, 0, 24]),
                24,
                0,
            );
            gtable
                .try_charge_ns_recv_gate(rdrop_ns, &tcb, 256 * 1024)
                .expect("J2 recv drop gate");
            tcb.ooo_bytes = 256 * 1024;
            sock.attach_tcp(tcb).expect("J2 recv self-test TCP waiters");
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable.reconcile_ns_recv(rdrop_ns, &mut ts.control);
            }
            assert_eq!(
                gtable.per_ns_recv_bytes.lock().get(&rdrop_ns).copied(),
                Some(256 * 1024),
                "J2-recv: global per-ns recv bytes charged before drop"
            );
        }
        assert!(
            !gtable.per_ns_recv_bytes.lock().contains_key(&rdrop_ns),
            "J2-recv: Drop must uncharge the residual recv bytes (leak-class regression)"
        );

        let rdetach_ns = NamespaceId(0x7000_0012);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = SocketState::try_new_arc(
                u64::MAX - 3,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                rdetach_ns,
            )
            .expect("J2 recv self-test socket admission");
            let mut tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 1, 0, 25]),
                25,
                Ipv4Addr([10, 1, 0, 26]),
                26,
                0,
            );
            gtable
                .try_charge_ns_recv_gate(rdetach_ns, &tcb, 128 * 1024)
                .expect("J2 recv detach gate");
            tcb.ooo_bytes = 128 * 1024;
            sock.attach_tcp(tcb).expect("J2 recv self-test TCP waiters");
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable.reconcile_ns_recv(rdetach_ns, &mut ts.control);
            }
            gtable.detach_tcp_uncharged(&sock);
            assert!(
                !gtable.per_ns_recv_bytes.lock().contains_key(&rdetach_ns),
                "J2-recv: detach_tcp_uncharged must uncharge the residual recv bytes"
            );
        }
        assert!(
            !gtable.per_ns_recv_bytes.lock().contains_key(&rdetach_ns),
            "J2-recv: a post-detach Drop must not double-subtract"
        );

        // RF180-52: the old stack-local table discarded these deliberate
        // over-cap fixtures on return. The global fixture must release the two
        // retained send counters and the retained recv-cap counter explicitly.
        table.uncharge_ns_send_residual(ns_s, tcb_a.ns_charged_send_bytes);
        table.uncharge_ns_send_residual(ns_t, tcb_c.ns_charged_send_bytes);
        table.uncharge_ns_recv_residual(ns_rs, rtcb_a.ns_charged_recv_bytes);
        for test_ns in [ns_s, ns_t] {
            assert!(!table.per_ns_send_bytes.lock().contains_key(&test_ns));
        }
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_rs));
        release_empty_boot_test_backing(&table.per_ns_conn_counts);
        release_empty_boot_test_backing(&table.per_ns_syn_counts);
        release_empty_boot_test_backing(&table.per_ns_send_bytes);
        release_empty_boot_test_backing(&table.per_ns_recv_bytes);
    }

    /// J2-8: in-kernel self-test for the per-cgroup ephemeral-port budget
    /// MECHANISM — the membership/leak-class logic the budget's correctness rests
    /// on (the cgroup arithmetic itself is tested in `cgroup::run_ports_budget_self_test`).
    ///
    /// Runs against the boot-quiescent global `SocketTable`, manipulating
    /// isolated high-ID `PortBinding` values directly and asserting the
    /// `port_uncharge_pending` bookkeeping. The boot
    /// process is in the root cgroup (id 0, exempt) so a behavioural charge would
    /// be a no-op; instead this proves the dangerous classes — uncharge-once via
    /// the ptr-eq remove choke-point, refund-the-displaced-charge, dead-Weak
    /// reaping (incl. the port-availability prune), the netns-teardown backstop,
    /// and fold-by-cgid drain idempotency.
    pub fn run_per_cgroup_port_budget_self_test() {
        let mk = |id: u64, ns: NamespaceId| -> SocketArc {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            SocketState::try_new_arc(
                id,
                SocketDomain::Inet4,
                SocketType::Dgram,
                SocketProtocol::Udp,
                label,
                ns,
            )
            .expect("J2 port self-test socket admission")
        };
        // RF180-52: avoid a >64 KiB SocketTable temporary on the BSP stack.
        let table = socket_table();
        let ns = NamespaceId(0x7200_0001);

        // (1) Fresh insert is FreshGrowth (nothing displaced to refund).
        let s1 = mk(101, ns);
        {
            let mut b = table.udp_bindings.lock();
            match SocketTable::insert_binding_charged(
                &mut b,
                (ns, 5000),
                &s1,
                42,
                BindKind::Ephemeral,
            ) {
                InsertOutcome::FreshGrowth => {}
                InsertOutcome::DisplacedCharge(_) => {
                    panic!("J2-8: fresh insert must be FreshGrowth")
                }
            }
            assert_eq!(b.get(&(ns, 5000)).map(|pb| pb.charged_cgroup), Some(42));
        }

        // (2) Ptr-eq guard: a FOREIGN socket cannot remove/uncharge this binding,
        //     and the entry is restored untouched (recycled-key / passive-child
        //     cross-cgroup-clobber protection). The OWNING socket gets the charge.
        let s_other = mk(102, ns);
        {
            let mut b = table.udp_bindings.lock();
            assert!(
                SocketTable::remove_binding_charged(
                    &mut b,
                    (ns, 5000),
                    Some(Arc::as_ptr(&s_other))
                )
                .is_none(),
                "J2-8: a foreign ptr must NOT remove/uncharge the binding"
            );
            assert!(
                b.contains_key(&(ns, 5000)),
                "J2-8: foreign-rejected entry restored"
            );
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5000), Some(Arc::as_ptr(&s1))),
                Some(42),
                "J2-8: the owning socket's remove returns its stored charge exactly once"
            );
            assert!(b.contains_key(&(ns, 5000)) == false);
        }

        // (3) Removing an UNcharged (cgid 0) entry yields no uncharge.
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5001), &s1, 0, BindKind::Ephemeral);
            assert!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5001), None).is_none(),
                "J2-8: an uncharged binding must not produce an uncharge"
            );
        }

        // (4) Replacing a charged entry reports DisplacedCharge(old) and keeps the
        //     new charge — the single rule that keeps one-port==one-charge across
        //     stale-Weak overwrite and same-socket re-registration.
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5002), &s1, 7, BindKind::Ephemeral);
            match SocketTable::insert_binding_charged(
                &mut b,
                (ns, 5002),
                &s1,
                8,
                BindKind::Ephemeral,
            ) {
                InsertOutcome::DisplacedCharge(old) => {
                    assert_eq!(old, 7, "J2-8: must report the displaced charge for refund")
                }
                InsertOutcome::FreshGrowth => {
                    panic!("J2-8: replacing a charged entry must displace")
                }
            }
            assert_eq!(
                b.get(&(ns, 5002)).map(|pb| pb.charged_cgroup),
                Some(8),
                "J2-8: the new charge is what remains in the map"
            );
            b.clear();
        }

        // (5) Deferred-uncharge queue: fold-by-cgid + drain clears + idempotent.
        table.enqueue_port_uncharge(3, 1);
        table.enqueue_port_uncharge(3, 2); // folds 3 -> 3
        table.enqueue_port_uncharge(4, 1);
        table.enqueue_port_uncharge(0, 5); // cgid 0 is a no-op
        assert_eq!(
            table.port_uncharge_pending.lock().get(&3).copied(),
            Some(3),
            "J2-8: fold-by-cgid"
        );
        assert_eq!(table.port_uncharge_pending.lock().get(&4).copied(), Some(1));
        assert!(
            table.port_uncharge_pending.lock().get(&0).is_none(),
            "J2-8: cgid 0 never enqueued"
        );
        table.drain_deferred_port_uncharges();
        assert!(
            table.port_uncharge_pending.lock().is_empty(),
            "J2-8: drain must clear the pending queue"
        );
        table.drain_deferred_port_uncharges(); // idempotent: no panic/underflow

        // (6) Dead-Weak reaper: a dead charged binding is pruned AND its charge
        //     enqueued; a dead UNcharged binding is pruned (port-availability fix)
        //     with NO enqueue; a live binding is kept.
        let live = mk(200, ns);
        {
            let dead1 = mk(201, ns);
            let dead2 = mk(202, ns);
            {
                let mut b = table.udp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 6000),
                    &live,
                    0,
                    BindKind::Ephemeral,
                );
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 6001),
                    &dead1,
                    55,
                    BindKind::Ephemeral,
                );
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 6002),
                    &dead2,
                    0,
                    BindKind::Ephemeral,
                );
            }
            // dead1 / dead2 dropped here -> their Weaks become un-upgradeable.
        }
        {
            let mut b = table.udp_bindings.lock();
            table.reap_dead_bindings(&mut b, ns);
            assert!(b.contains_key(&(ns, 6000)), "J2-8: live binding kept");
            assert!(
                !b.contains_key(&(ns, 6001)),
                "J2-8: dead charged binding reaped"
            );
            assert!(
                !b.contains_key(&(ns, 6002)),
                "J2-8: dead UNcharged binding reaped too (port-availability fix)"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&55).copied(),
            Some(1),
            "J2-8: the reaper enqueued exactly the dead binding's charge"
        );
        table.drain_deferred_port_uncharges();

        // (7) Netns-teardown backstop: remove ALL (ns,*) bindings (alive or dead),
        //     enqueue the charged ones, and leave other namespaces untouched.
        let other_ns = NamespaceId(0x7200_0002);
        let s_a = mk(300, ns);
        let s_b = mk(301, ns);
        let s_c = mk(302, other_ns);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 7000), &s_a, 71, BindKind::Ephemeral);
            SocketTable::insert_binding_charged(&mut b, (ns, 7001), &s_b, 0, BindKind::Ephemeral);
            SocketTable::insert_binding_charged(
                &mut b,
                (other_ns, 7000),
                &s_c,
                99,
                BindKind::Ephemeral,
            );
        }
        table.drain_ns_port_bindings(ns);
        {
            let b = table.tcp_bindings.lock();
            assert!(
                !b.contains_key(&(ns, 7000)),
                "J2-8: backstop removed the ns binding"
            );
            assert!(!b.contains_key(&(ns, 7001)));
            assert!(
                b.contains_key(&(other_ns, 7000)),
                "J2-8: backstop must leave OTHER namespaces untouched"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&71).copied(),
            Some(1),
            "J2-8: backstop enqueued the charged ns binding"
        );
        assert!(
            table.port_uncharge_pending.lock().get(&99).is_none(),
            "J2-8: backstop must not enqueue another namespace's charge"
        );
        table.drain_deferred_port_uncharges();

        // (8) R169-L9/L10/L11 global sweep: reaps dead charged bindings across
        //     ALL namespaces and BOTH maps, even when no allocator ever revisits
        //     that namespace — the idle/cross-netns/zombie-pinned reclamation
        //     class. A live binding in any ns is left intact.
        let live_keep = mk(402, other_ns);
        {
            let dead_udp = mk(400, ns);
            let dead_tcp = mk(401, other_ns);
            {
                let mut b = table.udp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 7100),
                    &dead_udp,
                    81,
                    BindKind::Ephemeral,
                );
            }
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (other_ns, 7101),
                    &dead_tcp,
                    91,
                    BindKind::Ephemeral,
                );
                SocketTable::insert_binding_charged(
                    &mut b,
                    (other_ns, 7102),
                    &live_keep,
                    17,
                    BindKind::Ephemeral,
                );
            }
            // dead_udp / dead_tcp dropped here -> their Weaks become dead.
        }
        table.sweep_stranded_port_charges();
        {
            let bu = table.udp_bindings.lock();
            assert!(
                !bu.contains_key(&(ns, 7100)),
                "R169-L10: global sweep reaps a dead UDP binding with no ns-local allocator"
            );
        }
        {
            let bt = table.tcp_bindings.lock();
            assert!(
                !bt.contains_key(&(other_ns, 7101)),
                "R169-L10: global sweep reaps a dead TCP binding in another namespace"
            );
            assert!(
                bt.contains_key(&(other_ns, 7102)),
                "R169-L10: global sweep must keep a LIVE binding"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&81).copied(),
            Some(1),
            "R169-L10: sweep enqueued the dead UDP binding charge"
        );
        assert_eq!(
            table.port_uncharge_pending.lock().get(&91).copied(),
            Some(1),
            "R169-L10: sweep enqueued the dead TCP binding charge"
        );
        assert!(
            table.port_uncharge_pending.lock().get(&17).is_none(),
            "R169-L10: sweep must NOT enqueue a live binding's charge"
        );
        table.drain_deferred_port_uncharges();

        // (9) R169-6 slice-1 (listener charging) invariant. A listener now carries
        //     a real charge in its single (ns,port) PortBinding. Assert the two
        //     properties that make charging it through the existing Ephemeral path
        //     safe: (a) a passive-open CHILD (a distinct Arc sharing the listener's
        //     (ns,port)) can NEVER uncharge the listener — ptr-eq miss — and the
        //     listener's charge survives intact; (b) the listener's OWN close
        //     refunds the stored charge exactly once; (c) a no-close listener drop
        //     is reclaimed by the global sweep. This regression-guards the widening
        //     of charged bindings to listeners.
        let listener = mk(500, ns);
        let child = mk(501, ns); // passive-open child: distinct Arc, same (ns,port)
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(
                &mut b,
                (ns, 7200),
                &listener,
                123,
                BindKind::Ephemeral,
            );
            // (a) child cannot uncharge the listener (ptr-eq miss); entry restored.
            assert!(
                SocketTable::remove_binding_charged(&mut b, (ns, 7200), Some(Arc::as_ptr(&child)))
                    .is_none(),
                "R169-6: a passive-open child must NOT uncharge the listener's port"
            );
            assert_eq!(
                b.get(&(ns, 7200)).map(|pb| pb.charged_cgroup),
                Some(123),
                "R169-6: the listener's charge survives a child's removal attempt"
            );
            // (b) the listener's own close refunds exactly once.
            assert_eq!(
                SocketTable::remove_binding_charged(
                    &mut b,
                    (ns, 7200),
                    Some(Arc::as_ptr(&listener))
                ),
                Some(123),
                "R169-6: the listener's own close refunds its stored charge once"
            );
        }
        // (c) a no-close listener drop is reclaimed by the global sweep.
        {
            let dropped_listener = mk(502, ns);
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 7201),
                    &dropped_listener,
                    124,
                    BindKind::Ephemeral,
                );
            }
            // dropped_listener dropped here -> its Weak is dead.
        }
        table.sweep_stranded_port_charges();
        assert!(
            !table.tcp_bindings.lock().contains_key(&(ns, 7201)),
            "R169-6: a no-close listener drop is reaped by the global sweep"
        );
        assert_eq!(
            table.port_uncharge_pending.lock().get(&124).copied(),
            Some(1),
            "R169-6: the dropped listener's charge is reclaimed exactly once"
        );
        table.drain_deferred_port_uncharges();

        // ---- R169-6 slice 2: BindKind / hold-until-close mechanism ----

        // (10) REGRESSION TRIPWIRE for the slice-2 kill class: an own CHARGED
        //      Explicit binding is PURE-SKIPPED by the while-alive choke-point
        //      (NOT removed, NOT refunded). Reverting any arm to an
        //      unconditional remove flips this to Removed(Some) and fails boot.
        let s_x = mk(600, ns);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5100), &s_x, 222, BindKind::Explicit);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&s_x)),
                TeardownAction::SkipExplicit,
                "R169-6 s2: own charged Explicit must be PURE-SKIPPED while alive"
            );
            assert_eq!(
                b.get(&(ns, 5100)).map(|pb| pb.charged_cgroup),
                Some(222),
                "R169-6 s2: the skipped Explicit binding keeps its charge"
            );

            // (11) own CHARGED Ephemeral -> Removed(Some): the ghost-bind arm.
            SocketTable::insert_binding_charged(&mut b, (ns, 5101), &s_x, 223, BindKind::Ephemeral);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5101), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(Some(223)),
                "R169-6 s2: own charged Ephemeral is removed + refunded while alive"
            );
            assert!(!b.contains_key(&(ns, 5101)));

            // (12) own UNcharged Ephemeral -> Removed(None): removed, no refund.
            SocketTable::insert_binding_charged(&mut b, (ns, 5102), &s_x, 0, BindKind::Ephemeral);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5102), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(None)
            );
            assert!(!b.contains_key(&(ns, 5102)));

            // (12b) own UNcharged EXPLICIT (root / pre-hook) -> Removed(None):
            //      the `cgid != 0` qualifier is load-bearing — an uncharged
            //      Explicit keeps today's remove-while-alive + connect-repair
            //      semantics (no hold, no refund, no clear).
            SocketTable::insert_binding_charged(&mut b, (ns, 5105), &s_x, 0, BindKind::Explicit);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5105), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(None),
                "R169-6 s2: an UNcharged Explicit (cgid 0) is NOT held"
            );
            assert!(!b.contains_key(&(ns, 5105)));

            // (13) FOREIGN ptr-miss: a passive-open child can neither hold-skip
            //      nor remove the owner's Explicit binding; entry restored.
            let child2 = mk(601, ns);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&child2)),
                TeardownAction::Removed(None),
                "R169-6 s2: foreign ptr-miss must not skip-hold or uncharge"
            );
            assert_eq!(
                b.get(&(ns, 5100)).map(|pb| pb.charged_cgroup),
                Some(222),
                "R169-6 s2: entry restored untouched after a foreign attempt"
            );
            assert!(
                SocketTable::peek_binding_kind(&b, (ns, 5100), Arc::as_ptr(&child2)).is_none(),
                "R169-6 s2: peek is ptr-eq gated (the discriminant that replaces a liveness bool)"
            );

            // (14) explicit-bind-then-listen single charge: the held Explicit
            //      binding survives arbitrary while-alive attempts, then the
            //      OWNER's kind-agnostic terminal remove refunds exactly once.
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&s_x)),
                TeardownAction::SkipExplicit
            );
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5100), Some(Arc::as_ptr(&s_x))),
                Some(222),
                "R169-6 s2: terminal close refunds the held Explicit exactly once"
            );
            assert!(!b.contains_key(&(ns, 5100)));

            // (15) PRIVILEGED (port < 1024) Explicit: identical accounting —
            //      no port-magnitude branch exists in teardown (hoarding closed).
            let priv_sock = mk(602, ns);
            SocketTable::insert_binding_charged(
                &mut b,
                (ns, 80),
                &priv_sock,
                224,
                BindKind::Explicit,
            );
            assert_eq!(
                SocketTable::peek_binding_kind(&b, (ns, 80), Arc::as_ptr(&priv_sock)),
                Some((BindKind::Explicit, 224))
            );
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(
                    &mut b,
                    (ns, 80),
                    Arc::as_ptr(&priv_sock)
                ),
                TeardownAction::SkipExplicit,
                "R169-6 s2: privileged Explicit is held identically"
            );
            assert_eq!(
                SocketTable::remove_binding_charged(
                    &mut b,
                    (ns, 80),
                    Some(Arc::as_ptr(&priv_sock))
                ),
                Some(224)
            );

            // (16) TERMINAL teardown (the cleanup is_closed()==true branch and
            //      close()) removes a held Explicit KIND-AGNOSTICALLY —
            //      hold-until-close is NOT hold-forever.
            SocketTable::insert_binding_charged(&mut b, (ns, 5106), &s_x, 225, BindKind::Explicit);
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5106), Some(Arc::as_ptr(&s_x))),
                Some(225),
                "R169-6 s2: terminal (is_closed) teardown removes a held Explicit"
            );
            b.clear();
        }

        // (19) dead-Explicit displaced by a live Explicit bind on the SAME
        //      port: the kind-agnostic displacement refund reclaims the dead
        //      socket's stranded charge exactly once while the new charge is
        //      stamped (reachable now that explicit binds are charged).
        {
            let dead_explicit = mk(603, ns);
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 5107),
                    &dead_explicit,
                    226,
                    BindKind::Explicit,
                );
            }
            // dead_explicit drops here -> its Weak is dead, charge stranded.
        }
        {
            let mut b = table.tcp_bindings.lock();
            let s_y = mk(604, ns);
            match SocketTable::insert_binding_charged(
                &mut b,
                (ns, 5107),
                &s_y,
                227,
                BindKind::Explicit,
            ) {
                InsertOutcome::DisplacedCharge(old) => assert_eq!(
                    old, 226,
                    "R169-6 s2: dead Explicit displaced by a live Explicit refunds once"
                ),
                InsertOutcome::FreshGrowth => {
                    panic!("R169-6 s2: displacing a dead charged Explicit must refund")
                }
            }
            assert_eq!(b.get(&(ns, 5107)).map(|pb| pb.charged_cgroup), Some(227));
            let _ = &s_y; // alive through the assertions above
            b.clear();
        }

        // (17) UDP Explicit inert hold-until-close: no UDP while-alive arm
        //      exists; the only remover (the close-equivalent kind-agnostic
        //      remove) refunds exactly once.
        let s_udp = mk(605, ns);
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(
                &mut b,
                (ns, 5108),
                &s_udp,
                228,
                BindKind::Explicit,
            );
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5108), Some(Arc::as_ptr(&s_udp))),
                Some(228),
                "R169-6 s2: UDP explicit bind+close refunds exactly once"
            );
        }

        // (18) netns-drain-then-repair accounting: the drain enqueues the held
        //      Explicit charge (netns finality removes live bindings, non-ptr-
        //      gated); a subsequent connect-style repair stamps charge-0
        //      Ephemeral — net effect exactly one uncharge, no double-refund,
        //      no new undercount.
        let drain_ns2 = NamespaceId(0x7200_0003);
        let s_drain = mk(606, drain_ns2);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(
                &mut b,
                (drain_ns2, 5109),
                &s_drain,
                229,
                BindKind::Explicit,
            );
        }
        table.drain_ns_port_bindings(drain_ns2);
        assert_eq!(
            table.port_uncharge_pending.lock().get(&229).copied(),
            Some(1),
            "R169-6 s2: netns drain enqueues the held Explicit charge once"
        );
        {
            let mut b = table.tcp_bindings.lock();
            // The connect-repair stamps speculative 0 / Ephemeral (see connect()).
            match SocketTable::insert_binding_charged(
                &mut b,
                (drain_ns2, 5109),
                &s_drain,
                0,
                BindKind::Ephemeral,
            ) {
                InsertOutcome::FreshGrowth => {}
                InsertOutcome::DisplacedCharge(_) => {
                    panic!("R169-6 s2: a post-drain repair must not displace a charge")
                }
            }
            b.clear();
        }
        table.drain_deferred_port_uncharges();

        // The old stack-local fixture discarded surviving live bindings on
        // return. Remove the exact high-ID test namespaces before process
        // deferred work is published so the production singleton starts clean.
        for test_ns in [ns, other_ns, drain_ns2] {
            table.drain_ns_port_bindings(test_ns);
        }
        table.drain_deferred_port_uncharges();
        {
            let udp = table.udp_bindings.lock();
            let tcp = table.tcp_bindings.lock();
            for test_ns in [ns, other_ns, drain_ns2] {
                assert!(!udp.keys().any(|(entry_ns, _)| *entry_ns == test_ns));
                assert!(!tcp.keys().any(|(entry_ns, _)| *entry_ns == test_ns));
            }
        }
        release_empty_boot_test_backing(&table.udp_bindings);
        release_empty_boot_test_backing(&table.tcp_bindings);

        // Keep every live socket alive through all assertions above.
        let _ = (
            &s1, &s_other, &live, &s_a, &s_b, &s_c, &live_keep, &listener, &child, &s_x, &s_udp,
            &s_drain,
        );
    }

    /// Create a UDP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// The socket is bound to the caller's network namespace via `net_ns_id`.
    /// Port bindings will be isolated within this namespace.
    ///
    /// # R76-3 FIX: Per-Namespace Socket Quota
    ///
    /// Enforces MAX_SOCKETS_PER_NS limit to prevent namespace DoS.
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_udp_socket(
        &self,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Result<SocketArc, SocketError> {
        self.create_socket_prepared(
            label,
            net_ns_id,
            SocketType::Dgram,
            SocketProtocol::Udp,
            UDP_PROTO as u16,
        )
    }

    /// Create a TCP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// The socket is bound to the caller's network namespace via `net_ns_id`.
    /// Port bindings will be isolated within this namespace.
    ///
    /// # R76-3 FIX: Per-Namespace Socket Quota
    ///
    /// Enforces MAX_SOCKETS_PER_NS limit to prevent namespace DoS.
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_tcp_socket(
        &self,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Result<SocketArc, SocketError> {
        self.create_socket_prepared(
            label,
            net_ns_id,
            SocketType::Stream,
            SocketProtocol::Tcp,
            TCP_PROTO as u16,
        )
    }

    /// Fallibly duplicate a transient wire segment. Cached SYN-ACK storage is
    /// aggregate-admitted separately; response copies never use infallible
    /// `Vec::clone` under RX pressure.
    fn try_clone_wire_segment(bytes: &[u8]) -> Option<WirePacket> {
        WirePacket::try_copy_from_slice(bytes).ok()
    }

    #[inline]
    fn passive_syn_ack_build_faulted(&self) -> bool {
        #[cfg(test)]
        {
            return self
                .fail_next_passive_syn_ack_build
                .swap(false, Ordering::AcqRel);
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    #[inline]
    fn simultaneous_syn_ack_build_faulted(&self) -> bool {
        #[cfg(test)]
        {
            return self
                .fail_next_simultaneous_syn_ack_build
                .swap(false, Ordering::AcqRel);
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Restore an ID consumed by a passive-open transaction that never became
    /// visible. Every production ID allocator holds `sockets.write()`, so the
    /// compare-exchange is exact while the caller retains that guard. The CAS is
    /// still used as defense in depth against future allocators that fail to
    /// preserve the serialization contract.
    fn rollback_unpublished_socket_id(&self, id: u64) {
        let Some(next) = id.checked_add(1) else {
            return;
        };
        let restored =
            self.next_socket_id
                .compare_exchange(next, id, Ordering::Relaxed, Ordering::Relaxed);
        debug_assert!(
            restored.is_ok(),
            "R180-11 unpublished socket ID was not the allocation frontier"
        );
    }

    /// Atomically publish a fully prepared stateful passive-open child.
    ///
    /// The caller holds `listener.listen`. This routine then takes the registry
    /// locks in the established order `listen > sockets > tcp_conns` and keeps
    /// all three through publication. Thus no lookup can observe a child until
    /// its TCB, cached SYN-ACK, SYN membership, namespace accounting, socket ID,
    /// socket-table entry, and 4-tuple entry are all committed. Every allocation
    /// and every reversible quota reservation precedes ID consumption.
    fn try_publish_pending_syn_child(
        &self,
        listen_state: &mut TcpListenState,
        key: TcpLookupKey,
        mut child: SocketArc,
        syn_ack: WirePacket,
        syn_sent_at: u64,
    ) -> bool {
        if listen_state.syn_queue.len() >= listen_state.syn_backlog
            || listen_state.syn_queue.contains_key(&key)
            || listen_state.syn_queue.ensure_capacity_for(1).is_err()
        {
            return false;
        }

        let mut sockets = self.sockets.write();
        if sockets.ensure_capacity_for(1).is_err() {
            return false;
        }

        let mut conns = self.tcp_conns.lock();
        self.conns_retain_accounted(&mut conns);
        if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS
            || conns.get(&key).and_then(|weak| weak.upgrade()).is_some()
            || conns.ensure_capacity_for(1).is_err()
        {
            return false;
        }

        if self.try_inc_ns_count(key.0).is_err() {
            return false;
        }
        if self.try_inc_ns_conn(key.0).is_err() {
            self.dec_ns_count(key.0);
            return false;
        }
        if !listen_state.try_reserve_syn_slot(&key, self) {
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }

        let id = match self.next_socket_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => {
                listen_state.cancel_syn_slot(key.0, self);
                self.dec_ns_conn(key.0);
                self.dec_ns_count(key.0);
                return false;
            }
        };
        let Some(unique_child) = Arc::get_mut(&mut child) else {
            self.rollback_unpublished_socket_id(id);
            listen_state.cancel_syn_slot(key.0, self);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        };
        unique_child.id = id;

        let pending = PendingSyn {
            key,
            sock: child.clone(),
            syn_ack,
            syn_sent_at,
        };
        if !listen_state.publish_syn_reserved(pending, self) {
            self.rollback_unpublished_socket_id(id);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }
        if sockets.insert_unique_reserved(id, child.clone()).is_err() {
            listen_state.take_syn(&key, self);
            self.rollback_unpublished_socket_id(id);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }
        if conns
            .insert_unique_reserved(key, Arc::downgrade(&child))
            .is_err()
        {
            sockets.remove(&id);
            listen_state.take_syn(&key, self);
            self.rollback_unpublished_socket_id(id);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }

        true
    }

    /// Atomically publish a fully prepared SYN-cookie child into the socket,
    /// connection, and accept registries. The listener guard prevents accept()
    /// from observing the child until every other registry has committed; the
    /// socket and connection guards provide the same guarantee to ID/4-tuple
    /// lookups.
    fn try_publish_cookie_child(
        &self,
        listener: &SocketArc,
        key: TcpLookupKey,
        mut child: SocketArc,
    ) -> bool {
        let mut listen_guard = listener.listen.lock();
        let Some(listen_state) = listen_guard.as_mut() else {
            return false;
        };
        if listen_state.accept_queue.len() >= listen_state.accept_backlog
            || listen_state.accept_queue.ensure_capacity_for(1).is_err()
        {
            return false;
        }

        let mut sockets = self.sockets.write();
        if sockets.ensure_capacity_for(1).is_err() {
            return false;
        }

        let mut conns = self.tcp_conns.lock();
        self.conns_retain_accounted(&mut conns);
        if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS
            || conns.get(&key).and_then(|weak| weak.upgrade()).is_some()
            || conns.ensure_capacity_for(1).is_err()
        {
            return false;
        }

        if self.try_inc_ns_count(key.0).is_err() {
            return false;
        }
        if self.try_inc_ns_conn(key.0).is_err() {
            self.dec_ns_count(key.0);
            return false;
        }
        if !listen_state.try_reserve_accept_slot() {
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }

        let id = match self.next_socket_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => {
                listen_state.cancel_accept_slot();
                self.dec_ns_conn(key.0);
                self.dec_ns_count(key.0);
                return false;
            }
        };
        let Some(unique_child) = Arc::get_mut(&mut child) else {
            self.rollback_unpublished_socket_id(id);
            listen_state.cancel_accept_slot();
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        };
        unique_child.id = id;

        if sockets.insert_unique_reserved(id, child.clone()).is_err() {
            self.rollback_unpublished_socket_id(id);
            listen_state.cancel_accept_slot();
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }
        if !listen_state.publish_accept_reserved(child.clone()) {
            sockets.remove(&id);
            self.rollback_unpublished_socket_id(id);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }
        if conns
            .insert_unique_reserved(key, Arc::downgrade(&child))
            .is_err()
        {
            let queued = listen_state.accept_queue.pop();
            if !queued
                .as_ref()
                .map_or(false, |queued| Arc::ptr_eq(queued, &child))
            {
                if let Some(queued) = queued {
                    let _ = listen_state.accept_queue.push_reserved(queued);
                }
                panic!("R180-11 cookie child was not the accept-queue tail");
            }
            child.counted_in_active.store(false, Ordering::Release);
            dec_active_conn();
            sockets.remove(&id);
            self.rollback_unpublished_socket_id(id);
            self.dec_ns_conn(key.0);
            self.dec_ns_count(key.0);
            return false;
        }

        listen_state.accept_waiters.wake_one();
        true
    }

    /// R180-11 FIX: one transactional funnel for every active socket birth.
    /// Registry backing, namespace policy, Arc bytes, and the ID are prepared
    /// in that order; the ID is consumed only after every fallible allocation
    /// succeeds, and publication itself is allocation-free.
    fn create_socket_prepared(
        &self,
        label: SocketLabel,
        net_ns_id: NamespaceId,
        ty: SocketType,
        proto: SocketProtocol,
        protocol_number: u16,
    ) -> Result<SocketArc, SocketError> {
        let mut ctx = NetCtx::new(0, protocol_number);
        ctx.cap = Some(CapId::INVALID);
        hook_net_socket(&label.creator, &ctx).map_err(|_| SocketError::PermissionDenied)?;

        let mut sockets = self.sockets.write();
        sockets
            .ensure_capacity_for(1)
            .map_err(|_| SocketError::NoMemory)?;
        self.try_inc_ns_count(net_ns_id)?;

        let mut sock =
            match SocketState::try_new_arc(0, SocketDomain::Inet4, ty, proto, label, net_ns_id) {
                Ok(sock) => sock,
                Err(error) => {
                    drop(sockets);
                    self.dec_ns_count(net_ns_id);
                    return Err(error);
                }
            };

        let id = match self.next_socket_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => {
                drop(sockets);
                self.dec_ns_count(net_ns_id);
                return Err(SocketError::IdExhausted);
            }
        };
        Arc::get_mut(&mut sock)
            .expect("new socket Arc unexpectedly aliased before publication")
            .id = id;
        if sockets.insert_unique_reserved(id, sock.clone()).is_err() {
            self.rollback_unpublished_socket_id(id);
            drop(sockets);
            self.dec_ns_count(net_ns_id);
            return Err(SocketError::IdExhausted);
        }
        drop(sockets);
        self.created.fetch_add(1, Ordering::Relaxed);
        Ok(sock)
    }

    /// Bind a UDP socket to an address and port.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to bind
    /// * `current` - Current process context (for privilege check)
    /// * `cap_id` - Capability used for this operation
    /// * `ip` - Local IP address
    /// * `port` - Port number (None for ephemeral)
    /// * `can_bind_privileged` - Whether caller can bind to privileged ports
    ///                           (euid == 0 or NET_BIND_SERVICE capability)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_bind` for LSM policy check
    /// - Ports < 1024 require can_bind_privileged == true
    /// - R47-1 FIX: Uses current creds, not creation creds
    /// - R49-3 FIX: Respects NET_BIND_SERVICE capability via flag
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port bindings are partitioned by the socket's network namespace.
    /// Different namespaces can bind to the same port independently.
    ///
    /// # Returns
    ///
    /// The bound port number on success.
    ///
    /// # J2-8 / R169-6: Per-cgroup port budget
    ///
    /// `policy` selects the charge + teardown contract (replaces the old
    /// `charge_ephemeral: bool`): `BindCharge::Ephemeral` for a kernel-chosen
    /// port (`port == None` — send_to_udp auto-bind, explicit `bind(0)`),
    /// `BindCharge::Explicit` for a user-chosen port (`port == Some(p)` —
    /// sys_bind non-zero; charged AND hold-until-close, R169-6 slice 2). One
    /// port is charged to the current cgroup's NET `ports.max` after LSM
    /// admits and before the binding lock; the charge is rolled back if the
    /// port turns out to be in use.
    ///
    /// NOTE (errno precedence, accepted): a tenant at ports.max binding a BUSY
    /// port gets EAGAIN (quota, checked first) rather than EADDRINUSE —
    /// reordering would add an extra L8 probe before the charge.
    /// NOTE (capability persistence): a privileged explicit bind that passed
    /// NET_BIND_SERVICE keeps its port + charge after a later capability drop
    /// (POSIX: bind permission is checked at bind time) — do not "fix" this by
    /// refunding on cap-drop.
    pub fn bind_udp(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // R180-21 FIX: one shared socket handle admits one bind/connect state
        // transaction at a time.  The private helper prevents listen/send
        // auto-bind from recursively acquiring this non-reentrant lock.
        let _operation = self.lock_socket_operation(sock);
        self.bind_udp_locked(sock, current, cap_id, ip, port, can_bind_privileged, policy)
    }

    /// Bind implementation for callers already holding `sock.operation`.
    fn bind_udp_locked(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // R169-6 slice 2: the charge policy must match the port-argument shape.
        debug_assert!(
            matches!(policy, BindCharge::None)
                || (matches!(policy, BindCharge::Explicit) == port.is_some()),
            "BindCharge::Explicit <=> explicit port; Ephemeral <=> port == None"
        );

        // Determine port
        // R75-1 FIX: Pass namespace ID for ephemeral port allocation
        let chosen_port = if let Some(p) = port {
            // R49-3 FIX: Privileged port check uses flag from syscall layer
            // This ensures NET_BIND_SERVICE capability is properly honored
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_port(sock.net_ns_id)?
        };

        // Build LSM context with actual CapId and current context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_bind(current, &ctx)?;

        // R180-11 FIX: pre-grow retained registry backing before the cgroup
        // charge. A later race is still handled fallibly with full rollback.
        {
            let mut bindings = self.udp_bindings.lock();
            if !bindings.contains_key(&(sock.net_ns_id, chosen_port)) {
                bindings
                    .ensure_capacity_for(1)
                    .map_err(|_| SocketError::NoMemory)?;
            }
        }

        // J2-8 / R169-6 slice 2: resolve + charge the per-cgroup port budget
        // AFTER LSM admits and BEFORE taking the binding lock (lock-ordering:
        // cgroup L5 must precede the L8 binding lock). Soft pre-insert charge —
        // rolled back below if the port races to PortInUse. cgid 0 (root / no
        // proc) is a no-op. Charging is kind-blind; the stamped kind only
        // selects the TEARDOWN contract.
        //
        // UDP-EXPLICIT INVARIANT: a charged Explicit UDP binding is
        // hold-until-close BY CONSTRUCTION — UDP has NO while-alive teardown
        // arm (connect() is TCP-gated; send_to_udp auto-binds only when
        // unbound; every UDP remover — close(), deliver_udp dead-Weak cleanup,
        // reap/sweep, drain_ns — is kind-agnostic and fires only at
        // close()/dead-Weak/netns-finality). The BindKind::Explicit stamp is
        // INERT for UDP. A FUTURE UDP connect()/rebind that removes a LIVE
        // binding MUST add the same peek_binding_kind PURE-SKIP guard or it
        // reintroduces the TCP undercount class.
        let charged_cgroup = if policy.should_charge() {
            if matches!(policy, BindCharge::Explicit) {
                // Self-heal for the explicit path: the ephemeral allocator
                // reaps this namespace's dead bindings before its availability
                // scan, but an explicit Some(p) bind never runs the allocator —
                // reap here so a tenant wedged at ports.max by dead bindings is
                // unwedged before the gate. Own block: the L8 guard MUST drop
                // before the drain/charge below (L5 under L8 is forbidden).
                let mut bindings = self.udp_bindings.lock();
                self.reap_dead_bindings(&mut bindings, sock.net_ns_id);
            }
            // Drain reclaimed charges (incl. the reap's, and the allocator's
            // for the port==None path) so the gate reads a healed
            // ports_current.
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // R75-1 FIX: Use (namespace, port) key for binding
        let binding_key = (sock.net_ns_id, chosen_port);

        // Register port binding. Compute the outcome WITHOUT returning from inside
        // the L8 critical section, so the speculative charge can be rolled back
        // after the guard drops (cgroup uncharge under the binding lock is
        // forbidden by the lock-ordering invariant).
        let mut port_in_use = false;
        let mut evicted: Option<u64> = None;
        let mut publication_error = None;
        {
            let mut bindings = self.udp_bindings.lock();
            if bindings
                .get(&binding_key)
                .map_or(false, |pb| pb.sock.upgrade().is_some())
            {
                port_in_use = true;
            } else {
                match Self::try_insert_binding_charged(
                    &mut bindings,
                    binding_key,
                    sock,
                    charged_cgroup,
                    policy.kind(),
                ) {
                    Ok(InsertOutcome::DisplacedCharge(old)) => evicted = Some(old),
                    Ok(InsertOutcome::FreshGrowth) => {}
                    Err(error) => publication_error = Some(error),
                }
            }
        }
        // J2-8: enqueue any evicted stale charge (deferred; drained in process
        // ctx). Done after dropping the guard.
        if let Some(old) = evicted {
            self.enqueue_port_uncharge(old, 1);
        }
        if port_in_use {
            // Roll back the speculative charge (guard dropped above) —
            // kind-agnostic: a failed explicit bind costs zero.
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(SocketError::PortInUse);
        }
        if let Some(error) = publication_error {
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(error);
        }

        #[cfg(test)]
        self.pause_operation_commit_for_test(TEST_PAUSE_BIND_COMMIT);

        // Update socket state
        sock.bind_local(ip, chosen_port);
        self.bind_count.fetch_add(1, Ordering::Relaxed);

        Ok(chosen_port)
    }

    // NOTE: alloc_ephemeral_tcp_port is defined later in this impl block.

    /// Bind a TCP socket (stream) to a local address/port (R51-1).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to bind
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `ip` - Local IP address to bind to
    /// * `port` - Port to bind (None for ephemeral)
    /// * `can_bind_privileged` - Whether privileged ports are allowed
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_bind` for LSM policy check
    /// - Privileged ports require root or NET_BIND_SERVICE
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port bindings are partitioned by the socket's network namespace.
    ///
    /// # J2-8 / R169-6
    ///
    /// `policy` mirrors `bind_udp` (see there, incl. the errno-precedence and
    /// capability-persistence notes): `BindCharge::Ephemeral` for `bind(0)` /
    /// `listen()` auto-bind (kernel-chosen, charged, ghost-bind teardown),
    /// `BindCharge::Explicit` for sys_bind non-zero (charged AND
    /// hold-until-close — the five while-alive teardown arms PURE-SKIP it,
    /// R169-6 slice 2). The active-open TCP path (`connect`) allocates inline
    /// and charges at its own site rather than through `bind_tcp`; its
    /// `did_alloc==false` reconnect over an own charged `bind(0)`/explicit
    /// binding preserves that charge (reuse-live-binding) rather than
    /// displacing it.
    pub fn bind_tcp(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // R180-21 FIX: serialize the full bind transaction, including quota
        // charge, binding-map publication, metadata commit, and every rollback.
        let _operation = self.lock_socket_operation(sock);
        self.bind_tcp_locked(sock, current, cap_id, ip, port, can_bind_privileged, policy)
    }

    /// Bind implementation for callers already holding `sock.operation`.
    fn bind_tcp_locked(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // R169-6 slice 2: the charge policy must match the port-argument shape.
        debug_assert!(
            matches!(policy, BindCharge::None)
                || (matches!(policy, BindCharge::Explicit) == port.is_some()),
            "BindCharge::Explicit <=> explicit port; Ephemeral <=> port == None"
        );

        // Determine port
        // R75-1 FIX: Pass namespace ID for ephemeral port allocation
        let chosen_port = if let Some(p) = port {
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_tcp_port(sock.net_ns_id)?
        };

        // Build LSM context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id);

        // Check LSM policy
        hook_net_bind(current, &ctx)?;

        // R180-11 FIX: prepare map capacity before the reversible quota charge.
        {
            let mut bindings = self.tcp_bindings.lock();
            if !bindings.contains_key(&(sock.net_ns_id, chosen_port)) {
                bindings
                    .ensure_capacity_for(1)
                    .map_err(|_| SocketError::NoMemory)?;
            }
        }

        // J2-8 / R169-6 slice 2: charge AFTER LSM, BEFORE the binding lock
        // (see bind_udp for the full ordering + UDP-EXPLICIT INVARIANT notes;
        // here the TCP while-alive arms enforce hold-until-close via
        // resolve_while_alive_teardown).
        let charged_cgroup = if policy.should_charge() {
            if matches!(policy, BindCharge::Explicit) {
                // Self-heal for the explicit path (see bind_udp): reap this
                // namespace's dead bindings — the explicit Some(p) bind never
                // runs the allocator's reaper. Own block: the L8 guard MUST
                // drop before the drain/charge below.
                let mut bindings = self.tcp_bindings.lock();
                self.reap_dead_bindings(&mut bindings, sock.net_ns_id);
            }
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // R75-1 FIX: Use (namespace, port) key for binding
        let binding_key = (sock.net_ns_id, chosen_port);

        // Register port binding (never return from inside the L8 section).
        let mut port_in_use = false;
        let mut evicted: Option<u64> = None;
        let mut publication_error = None;
        {
            let mut bindings = self.tcp_bindings.lock();
            if bindings
                .get(&binding_key)
                .map_or(false, |pb| pb.sock.upgrade().is_some())
            {
                port_in_use = true;
            } else {
                match Self::try_insert_binding_charged(
                    &mut bindings,
                    binding_key,
                    sock,
                    charged_cgroup,
                    policy.kind(),
                ) {
                    Ok(InsertOutcome::DisplacedCharge(old)) => evicted = Some(old),
                    Ok(InsertOutcome::FreshGrowth) => {}
                    Err(error) => publication_error = Some(error),
                }
            }
        }
        if let Some(old) = evicted {
            self.enqueue_port_uncharge(old, 1);
        }
        if port_in_use {
            // Kind-agnostic rollback — a failed explicit bind costs zero.
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(SocketError::PortInUse);
        }
        if let Some(error) = publication_error {
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(error);
        }

        #[cfg(test)]
        self.pause_operation_commit_for_test(TEST_PAUSE_BIND_COMMIT);

        // Update socket state
        sock.bind_local(ip, chosen_port);
        self.bind_count.fetch_add(1, Ordering::Relaxed);

        Ok(chosen_port)
    }

    /// Roll back the ephemeral binding created by this `listen()` attempt.
    ///
    /// The caller holds `sock.operation`, so no sibling bind/connect/listen can
    /// replace the socket's metadata while this runs. The binding lock still
    /// performs a pointer-identity check as defense in depth: a recycled or
    /// foreign `(namespace, port)` owner is never removed or uncharged.
    fn rollback_listen_auto_bind_locked(&self, sock: &SocketArc, port: u16) {
        let key = (sock.net_ns_id, port);
        let sock_ptr = Arc::as_ptr(sock);
        let (owned, charged_cgroup) = {
            let mut bindings = self.tcp_bindings.lock();
            let owned = Self::peek_binding_kind(&bindings, key, sock_ptr).is_some();
            let charged_cgroup = if owned {
                Self::remove_binding_charged(&mut bindings, key, Some(sock_ptr))
            } else {
                None
            };
            (owned, charged_cgroup)
        };
        if let Some(cgid) = charged_cgroup {
            uncharge_port_cgroup(cgid, 1);
        }
        if owned {
            let mut meta = sock.meta.lock();
            if meta.local_port == Some(port) {
                meta.local_ip = None;
                meta.local_port = None;
            }
        }
    }

    /// Transition a TCP socket into LISTEN state (R51-1).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to put into listen mode
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `backlog` - Maximum pending connections (clamped to limits)
    /// * `can_bind_privileged` - Whether privileged ports are allowed (for auto-bind)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_listen` for LSM policy check
    /// - Auto-binds to ephemeral port if not already bound
    pub fn listen(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        backlog: u32,
        can_bind_privileged: bool,
    ) -> Result<(), SocketError> {
        // R180-21 FIX: listen's implicit bind and listen-state publication are
        // one socket operation.  Use the locked bind helper to avoid recursive
        // acquisition while keeping bind-vs-connect/listen atomic.
        let _operation = self.lock_socket_operation(sock);

        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Cannot listen on connected socket
        if sock.remote_port().is_some() {
            return Err(SocketError::AlreadyConnected);
        }

        // Already listening?
        if sock.is_listening() {
            return Ok(());
        }

        let backlog = backlog.max(1) as usize;

        // R180-11 FIX: prepare every standalone waiter Arc before auto-bind or
        // any other externally visible listen side effect.
        let tcp_waiters = PreparedTcpWaiters::try_new()?;
        let listen_state = TcpListenState::try_new(backlog)?;

        // Auto-bind if not bound. `auto_bound_port` is a transaction-local
        // ownership proof used only to undo this attempt if a later listen
        // policy/precondition check fails.
        let auto_bound_port = if sock.local_port().is_none() {
            let local_ip = sock
                .local_ip()
                .map(Ipv4Addr)
                .unwrap_or(Ipv4Addr([0, 0, 0, 0]));
            // R169-6 FIX (slice 1): the listener auto-bind IS charged to the
            // current cgroup's `ports.max`. The port is KERNEL-CHOSEN (port==None
            // → BindCharge::Ephemeral, charged by bind_tcp exactly like an
            // active-open auto-bind),
            // it stamps `charged_cgroup` into the single (ns,port) PortBinding, and
            // it tears down through the EXISTING class-agnostic sites with Ephemeral
            // semantics: close() (5121) reads the STORED cgid and uncharges (ptr-eq
            // gated, so a passive-open child sharing this (ns,port) can never
            // uncharge it), and the dead-Weak triad (lookup cleanup / reap /
            // sweep / netns-Drop backstop) reclaims a no-close drop. A listener is
            // charged exactly ONCE: passive-open children share this entry and
            // never re-insert. Closes the listener-port exhaustion bypass where a
            // server forking thousands of listeners escaped ports.max entirely.
            // (R169-6 slice 2 LANDED: explicit bind(non-zero) is now charged as
            // BindCharge::Explicit with hold-until-close teardown; a listener on
            // an EXPLICITLY-bound socket skips this auto-bind entirely — its
            // binding was already charged once at sys_bind.)
            let port = self.bind_tcp_locked(
                sock,
                current,
                cap_id,
                local_ip,
                None,
                can_bind_privileged,
                BindCharge::Ephemeral,
            )?;
            Some(port)
        } else {
            None
        };

        // LSM listen hook
        let mut ctx = self.ctx_from_socket(sock);
        ctx.cap = Some(cap_id);
        if let Err(error) = hook_net_listen(current, &ctx, backlog as u32) {
            if let Some(port) = auto_bound_port {
                self.rollback_listen_auto_bind_locked(sock, port);
            }
            return Err(error.into());
        }

        // Install listen TCB + queues
        let meta = sock.meta_snapshot();
        let lip = meta
            .local_ip
            .map(Ipv4Addr)
            .unwrap_or(Ipv4Addr([0, 0, 0, 0]));
        let lport = match meta.local_port {
            Some(port) => port,
            None => {
                if let Some(port) = auto_bound_port {
                    self.rollback_listen_auto_bind_locked(sock, port);
                }
                return Err(SocketError::InvalidState);
            }
        };

        #[cfg(test)]
        self.pause_operation_commit_for_test(TEST_PAUSE_LISTEN_COMMIT);

        *sock.tcp.lock() = Some(TcpSocketState::from_prepared(
            TcpControlBlock::new_listen(lip, lport),
            tcp_waiters,
        ));
        sock.install_listen_state(listen_state);

        Ok(())
    }

    /// Lookup a listening socket by local port (R51-1).
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Listener lookup is scoped to the specified network namespace.
    fn lookup_tcp_listener(&self, net_ns_id: NamespaceId, local_port: u16) -> Option<SocketArc> {
        // R75-1 FIX: Use namespace-scoped binding key
        let binding_key = (net_ns_id, local_port);
        let mut bindings = self.tcp_bindings.lock();
        match bindings.get(&binding_key).and_then(|pb| pb.sock.upgrade()) {
            Some(sock) if sock.is_listening() => Some(sock),
            Some(_) => None, // Bound but not listening
            None => {
                // J2-8: clean up the stale Weak AND enqueue its charge (this runs
                // in RX/lookup context under the binding lock — DEFERRED uncharge).
                // R169-6: listener entries are now CHARGED (Ephemeral semantics), so
                // reading the STORED cgid here correctly reclaims a dead listener's
                // port charge. No expect_ptr: the entry is already known dead.
                if let Some(cgid) = Self::remove_binding_charged(&mut bindings, binding_key, None) {
                    self.enqueue_port_uncharge(cgid, 1);
                }
                None
            }
        }
    }

    /// Poll the accept queue of a listening socket (non-blocking) (R51-1).
    pub fn poll_accept_ready(
        &self,
        listener: &SocketArc,
    ) -> Result<Option<SocketArc>, SocketError> {
        if !listener.is_listening() {
            return Err(SocketError::InvalidState);
        }
        Ok(listener.pop_accept_ready())
    }

    /// Build a UDP datagram for transmission.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to send from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `src_ip` - Source IP address (our IP)
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `payload` - Data to send
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_send` for LSM policy check
    /// - Automatically binds to ephemeral port if not bound
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Complete UDP datagram ready for IPv4 encapsulation.
    pub fn send_to_udp(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<WirePacket, SocketError> {
        // R180-21 FIX: serialize the check-or-auto-bind portion.  A second
        // sender that observed `None` before another core committed the bind
        // now waits and then reuses the committed port instead of spuriously
        // failing with PortInUse or publishing a second binding.
        let operation = self.lock_socket_operation(sock);

        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if closed
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Get or allocate local port
        let local_port = match sock.local_port() {
            Some(p) => p,
            None => {
                // Auto-bind to ephemeral port - no privilege needed for ephemeral ports
                // (ephemeral range is 49152-65535, well above privileged port limit)
                // J2-8: ACTIVE-OPEN ephemeral auto-bind -> charge the per-cgroup
                // ports.max budget (BindCharge::Ephemeral).
                self.bind_udp_locked(
                    sock,
                    current,
                    cap_id,
                    src_ip,
                    None,
                    false,
                    BindCharge::Ephemeral,
                )?
            }
        };
        drop(operation);
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Build LSM context with actual CapId
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(src_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(dst_ip.0);
        ctx.remote_port = dst_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_send(current, &ctx, payload.len())?;

        // Build UDP datagram
        let datagram = build_udp_datagram(src_ip, dst_ip, local_port, dst_port, payload)?;

        // RF180-41 REVIEW FIX: conntrack is owned by the generic egress
        // transaction. Seeding here would publish an unqueued datagram and
        // double-account the successful path.

        Ok(datagram)
    }

    /// Commit UDP transmit statistics only after the device accepted the exact
    /// datagram. Construction, firewall rejection, and QueueFull leave counters
    /// unchanged.
    pub fn commit_udp_send(&self, sock: &SocketArc, payload_len: usize) {
        sock.tx_bytes
            .fetch_add(payload_len as u64, Ordering::Relaxed);
        sock.tx_datagrams.fetch_add(1, Ordering::Relaxed);
    }

    /// Initiate a TCP connect (client-side SYN).
    ///
    /// Builds and returns the SYN segment and records the TCB.
    /// The handshake completes asynchronously via the RX path (Phase 2).
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket to connect
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `src_ip` - Source IP address (0.0.0.0 for auto-select)
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `timeout_ns` - Timeout for blocking connect (None = blocking indefinitely)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_connect` for LSM policy check on active open
    /// - Auto-binds to ephemeral port if not already bound
    ///
    /// # Returns
    ///
    /// - `Ok(TcpConnectResult)` with SYN segment on successful initiation
    /// - `Err(InProgress)` for non-blocking connect (timeout_ns == Some(0))
    /// - `Err(Timeout)` if blocking connect times out before ESTABLISHED
    ///
    /// # Note
    ///
    /// Phase 1 implementation only initiates the handshake (SYN). Full 3-way
    /// handshake completion (SYN-ACK handling, ACK transmission) requires the
    /// RX path integration in Phase 2.
    pub fn connect(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        timeout_ns: Option<u64>,
    ) -> Result<TcpConnectResult, SocketError> {
        // R180-21 FIX: the active-open transaction is serialized per socket
        // from validation through quota charge, both registry publications,
        // metadata/TCB commit, and segment construction.  This prevents two
        // shared-handle connect callers from publishing different 4-tuples and
        // then overwriting one another's metadata/TCB.
        let operation = self.lock_socket_operation(sock);

        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }
        if dst_port == 0 {
            return Err(SocketError::InvalidProtocol);
        }

        // Check if already connected or connecting
        if sock.remote_port().is_some() {
            return Err(SocketError::AlreadyConnected);
        }
        if let Some(state) = sock.tcp_state() {
            if state != TcpState::Closed {
                return Err(SocketError::AlreadyConnected);
            }
        }

        // Determine local endpoint (bind if needed)
        // R75-1 FIX: Allocate port within socket's network namespace
        // J2-8: `did_alloc` marks an ACTIVE-OPEN ephemeral allocation — the only
        // per-cgroup port-budget charge candidate (an already-bound socket
        // re-uses its port and is not charged here).
        let (local_port, did_alloc) = match sock.local_port() {
            Some(p) => (p, false),
            None => (self.alloc_ephemeral_tcp_port(sock.net_ns_id)?, true),
        };
        let local_ip = sock.local_ip().map(Ipv4Addr).unwrap_or(src_ip);

        // Build the connection key for uniqueness check
        let conn_key =
            tcp_map_key_from_parts(sock.net_ns_id, local_ip, local_port, dst_ip, dst_port);

        // Check for duplicate connection (but don't register yet - defer until after LSM)
        {
            let conns = self.tcp_conns.lock();
            if conns.get(&conn_key).and_then(|w| w.upgrade()).is_some() {
                return Err(SocketError::PortInUse);
            }
        }

        // LSM policy check BEFORE registering connection
        // Use hook_net_connect for active open (per LSM API)
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(dst_ip.0);
        ctx.remote_port = dst_port;
        ctx.cap = Some(cap_id);
        hook_net_connect(current, &ctx)?;

        // R180-11 FIX: prepare all active-open allocations before quota or map
        // publication: waiter Arcs, SYN bytes, and registry backing.
        let prepared_waiters = PreparedTcpWaiters::try_new()?;
        let iss = generate_isn(local_ip, local_port, dst_ip, dst_port);
        let mut prepared_tcb =
            TcpControlBlock::new_client(local_ip, local_port, dst_ip, dst_port, iss);
        let egress_token = next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN)?;
        prepared_tcb.state = TcpState::Closed;
        prepared_tcb.active_open_pending = true;
        prepared_tcb.pending_reply_token = Some(egress_token);
        prepared_tcb.snd_una = iss;
        prepared_tcb.snd_nxt = iss.wrapping_add(1);
        prepared_tcb.snd_wnd = TCP_DEFAULT_WINDOW as u32;
        prepared_tcb.rcv_wscale = calc_wscale(prepared_tcb.rcv_wnd);
        prepared_tcb.wscale_requested = true;
        prepared_tcb.sack_requested = true;
        let syn_wnd = Self::encode_adv_window(&prepared_tcb, prepared_tcb.rcv_wnd);
        let syn_options = [
            TcpOptionKind::WindowScale(prepared_tcb.rcv_wscale),
            TcpOptionKind::SackPermitted,
        ];
        let segment = try_build_tcp_segment_with_options(
            local_ip,
            dst_ip,
            local_port,
            dst_port,
            iss,
            0,
            TCP_FLAG_SYN,
            syn_wnd,
            &syn_options,
            &[],
        )
        .map_err(|_| SocketError::NoMemory)?;
        {
            let mut bindings = self.tcp_bindings.lock();
            if !bindings.contains_key(&(sock.net_ns_id, local_port)) {
                bindings
                    .ensure_capacity_for(1)
                    .map_err(|_| SocketError::NoMemory)?;
            }
        }
        {
            let mut conns = self.tcp_conns.lock();
            if !conns.contains_key(&conn_key) {
                conns
                    .ensure_capacity_for(1)
                    .map_err(|_| SocketError::NoMemory)?;
            }
        }

        // J2-8: charge the per-cgroup ephemeral-port budget for an ACTIVE-OPEN
        // allocation, AFTER LSM admits and BEFORE any binding lock (lock-ordering
        // forbids the L5 cgroup charge under the L8 binding lock). Soft pre-charge
        // — refunded by the rollback below if registration fails. cgid 0 (root /
        // no process ctx) is a no-op.
        let charged_cgroup = if did_alloc {
            // Drain reclaimed charges first (the allocator just reaped this ns's
            // dead bindings) so a wedged tenant is unwedged before the gate.
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // Track what we've registered for cleanup on failure
        let mut binding_registered = false;
        let mut conn_registered = false;

        // Register local port binding and connection 4-tuple
        // This is done AFTER LSM check to prevent resource leaks on denial
        // R75-1 FIX: Use namespace-scoped port binding keys
        let binding_key = (sock.net_ns_id, local_port);
        let registration_result: Result<(), SocketError> = (|| {
            // Register local port in tcp_bindings
            {
                let mut bindings = self.tcp_bindings.lock();
                // R169-6: skip the re-insert ONLY when a LIVE binding for this
                // (ns,port) owned by THIS socket already exists. That entry
                // already carries the correct stored charge AND kind (bind(0)
                // Ephemeral, explicit bind Explicit), so overwriting it with
                // the `did_alloc == false` speculative charge (0) would
                // displace + refund the live charge while the port stays held —
                // the R169-6 self-replace undercount. It is NOT safe to gate
                // purely on `did_alloc`: an UNcharged teardown can remove the
                // entry while leaving `local_port` set.
                //
                // REPAIR PROOF (R169-6 slice 2): a CHARGED Ephemeral
                // while-alive removal clears `local_port` (ghost-bind fix, so
                // the retry takes `did_alloc == true`); a CHARGED Explicit
                // binding is NEVER removed by a while-alive arm
                // (hold-until-close — removed only by close()/terminal
                // cleanup/dead-Weak reap/netns drain). So an own binding ABSENT
                // here with `local_port == Some` is always UNcharged (an
                // uncharged-teardown survivor, or post-netns-drain where the
                // drain already enqueued any charge) — repairing it with the
                // speculative 0 / BindKind::Ephemeral never undercounts.
                //
                // This gate deliberately uses get()+upgrade()+ptr_eq, NOT
                // peek_binding_kind: it must distinguish a live FOREIGN owner
                // (PortInUse) from a dead stale entry (repairable), which
                // requires upgrade().
                let mut reuse_live_binding = false;
                // Reject only a LIVE binding owned by a DIFFERENT socket (a live
                // binding owned by THIS socket — re-connect — proceeds).
                if let Some(existing) = bindings.get(&binding_key) {
                    if let Some(existing_sock) = existing.sock.upgrade() {
                        if !Arc::ptr_eq(&existing_sock, sock) {
                            return Err(SocketError::PortInUse);
                        }
                        reuse_live_binding = !did_alloc;
                    }
                }
                if !reuse_live_binding {
                    // J2-8: stamp the (possibly 0) charge into a newly-created or
                    // repaired binding value, and refund any displaced stale charge
                    // (enqueue — we hold the L8 binding lock). From here the BINDING
                    // owns `charged_cgroup`; the failure rollback below removes it
                    // (returning the charge to uncharge), so `binding_registered`
                    // gates direct-vs-via-binding refund of the speculative charge.
                    // R169-6 slice 2: a connect-created/repaired binding is always
                    // BindKind::Ephemeral (fresh auto-alloc, or an uncharged repair
                    // — see the REPAIR PROOF above; a non-zero charge here implies
                    // did_alloc).
                    debug_assert!(
                        charged_cgroup == 0 || did_alloc,
                        "connect: non-zero speculative charge implies did_alloc"
                    );
                    if let InsertOutcome::DisplacedCharge(old) = Self::try_insert_binding_charged(
                        &mut bindings,
                        binding_key,
                        sock,
                        charged_cgroup,
                        BindKind::Ephemeral,
                    )? {
                        self.enqueue_port_uncharge(old, 1);
                    }
                    binding_registered = true;
                }
            }

            // Register connection 4-tuple
            {
                let mut conns = self.tcp_conns.lock();

                // R50-5 IMPROVEMENT: Prune stale Weak entries before counting
                // This prevents false exhaustion when connections have been dropped
                // but their Weak references haven't been cleaned up yet
                self.conns_retain_accounted(&mut conns);

                // R50-5 FIX: Enforce global TCP connection limit to prevent resource exhaustion
                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                    return Err(SocketError::NoPorts);
                }
                // Re-check after lock acquisition (race-safe)
                if conns.get(&conn_key).and_then(|w| w.upgrade()).is_some() {
                    return Err(SocketError::PortInUse);
                }
                conns
                    .ensure_capacity_for(1)
                    .map_err(|_| SocketError::NoMemory)?;
                // J2-1: per-namespace connection budget (composes with the global
                // cap checked above; both must pass). On over-quota this `?` exits
                // the registration closure with QuotaExceeded -> EAGAIN, dropping
                // the `conns` guard before the binding rollback below.
                self.try_inc_ns_conn(conn_key.0)?;
                if conns
                    .insert_unique_reserved(conn_key, Arc::downgrade(sock))
                    .is_err()
                {
                    self.dec_ns_conn(conn_key.0);
                    return Err(SocketError::PortInUse);
                }
                conn_registered = true;
            }

            Ok(())
        })();

        // On registration failure, clean up any partial registrations
        if let Err(e) = registration_result {
            if conn_registered {
                // RF180-36 FIX: rollback may run after tuple reuse; release only
                // the registration still owned by this connect transaction.
                self.remove_tcp_conn_exact_owner(conn_key, sock);
            }
            if binding_registered {
                // R75-1 FIX: Remove using namespace-scoped key.
                // J2-8: removing the binding returns its STORED charge to
                // uncharge (process ctx — block-scoped so the L8 guard drops
                // before the L5 uncharge, avoiding the Rust-2021 temporary trap).
                // R169-6 slice 2 (ARM-1): deliberately NOT routed through
                // resolve_while_alive_teardown — this rollback is gated by the
                // LOCAL `binding_registered` flag, so it can only ever remove
                // the own EPHEMERAL binding THIS connect just inserted. A
                // pre-existing own Explicit/bind(0) binding took the
                // reuse_live_binding path (binding_registered == false) and is
                // structurally unreachable here; converting this arm to
                // peek-then-remove would remove a binding this call never
                // inserted -> spurious uncharge -> undercount.
                let cgid = {
                    let mut bindings = self.tcp_bindings.lock();
                    Self::remove_binding_charged(
                        &mut bindings,
                        binding_key,
                        Some(Arc::as_ptr(sock)),
                    )
                };
                if let Some(c) = cgid {
                    uncharge_port_cgroup(c, 1);
                }
            } else {
                // J2-8: the binding was never inserted (e.g. PortInUse on a live
                // foreign binding) — refund the orphaned speculative charge.
                uncharge_port_cgroup(charged_cgroup, 1);
            }
            return Err(e);
        }

        #[cfg(test)]
        self.pause_operation_commit_for_test(TEST_PAUSE_CONNECT_COMMIT);

        // Update socket metadata (connection is now registered)
        sock.bind_local(local_ip, local_port);
        sock.set_remote(dst_ip, dst_port);

        *sock.tcp.lock() = Some(TcpSocketState::from_prepared(
            prepared_tcb,
            prepared_waiters,
        ));

        let result = TcpConnectResult {
            segment,
            local_port,
            src_ip: local_ip,
            dst_ip,
            dst_port,
            egress_binding: self.bind_tcp_reply(sock, egress_token),
        };

        // Non-blocking connect: return result immediately with InProgress
        // The caller should transmit the SYN and poll for state transition
        if timeout_ns == Some(0) {
            // For non-blocking, we still return the result so the SYN can be transmitted
            // The socket is in SYN_SENT state; completion happens via RX path
            drop(operation);
            if sock.is_closed() {
                return Err(SocketError::Closed);
            }
            return Ok(result);
        }

        // A spin mutex must never be held across a scheduler wait.  Socket
        // metadata and the SYN-SENT TCB are already committed, so concurrent
        // bind/connect callers will fail validation while we sleep.  Terminal
        // rollback paths reacquire this same lock before tearing the attempt down.
        drop(operation);
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Blocking connect: wait for state transition signaled via TCP waiters
        // Note: Full handshake completion requires RX path integration (Phase 2)
        // For now, we wait but the RX path to process SYN-ACK is not yet implemented
        if let Some(waiters) = sock.tcp_waiters() {
            match waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => {
                    if matches!(sock.tcp_state(), Some(TcpState::Established)) {
                        return Ok(result);
                    }
                    if !matches!(sock.tcp_state(), Some(TcpState::Closed) | None) {
                        // A wake may be unrelated/spurious. Preserve the live
                        // attempt and report that it remains in progress.
                        return Err(SocketError::InProgress);
                    }

                    // Reacquire the operation lock for terminal rollback. A
                    // SYN-ACK that committed while we waited wins this re-check.
                    let _operation = self.lock_socket_operation(sock);
                    if matches!(sock.tcp_state(), Some(TcpState::Established)) {
                        return Ok(result);
                    }
                    self.abort_tcp_connect_locked(sock);
                    return Err(SocketError::Closed);
                }
                WaitOutcome::TimedOut => {
                    let _operation = self.lock_socket_operation(sock);
                    // Establishment racing the deadline wins once committed.
                    if matches!(sock.tcp_state(), Some(TcpState::Established)) {
                        return Ok(result);
                    }
                    self.abort_tcp_connect_locked(sock);
                    return Err(SocketError::Timeout);
                }
                WaitOutcome::Closed => {
                    let _operation = self.lock_socket_operation(sock);
                    self.abort_tcp_connect_locked(sock);
                    return Err(SocketError::Closed);
                }
                WaitOutcome::Interrupted => {
                    // R171-F3 FIX: a pending kill interrupted the blocking connect.
                    // Unified rollback releases binding/quota/TCB state before EINTR.
                    let _operation = self.lock_socket_operation(sock);
                    self.abort_tcp_connect_locked(sock);
                    return Err(SocketError::Interrupted);
                }
                WaitOutcome::NoProcess => {
                    // An error return must not retain a published SYN-SENT ghost.
                    let _operation = self.lock_socket_operation(sock);
                    self.abort_tcp_connect_locked(sock);
                    return Err(SocketError::NoProcess);
                }
            }
        }

        // No waiters registered (early boot) - return result for async processing
        // The SYN segment is ready to be transmitted by the caller
        Ok(result)
    }

    /// Receive a UDP datagram (blocking with optional timeout).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to receive from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `timeout_ns` - Timeout in nanoseconds (None for blocking)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_recv` for LSM policy check
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Received datagram on success.
    /// Transactional UDP receive: LSM-check and expose the exact front packet
    /// to `commit` while holding `rx_queue`; dequeue/account only after the
    /// caller confirms all user copyouts succeeded.
    pub fn recv_from_udp_with_commit<E, F>(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        timeout_ns: Option<u64>,
        mut commit: F,
    ) -> Result<usize, RecvTransactionError<E>>
    where
        F: FnMut(&PendingDatagram) -> Result<usize, E>,
    {
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(RecvTransactionError::Socket(SocketError::InvalidType));
        }

        loop {
            if sock.is_closed() {
                return Err(RecvTransactionError::Socket(SocketError::Closed));
            }

            let mut queue = sock.rx_queue.lock();
            if let Some(pkt) = queue.front() {
                let mut ctx = self.ctx_from_socket(sock);
                ctx.remote = ipv4_to_u64(pkt.src_ip.0);
                ctx.remote_port = pkt.src_port;
                ctx.cap = Some(cap_id);
                hook_net_recv(current, &ctx, pkt.data.len())
                    .map_err(|error| RecvTransactionError::Socket(error.into()))?;

                let copied = commit(pkt).map_err(RecvTransactionError::Commit)?;
                if copied > pkt.data.len() {
                    return Err(RecvTransactionError::Socket(SocketError::InvalidState));
                }
                let packet_len = pkt.data.len();
                let removed = queue.pop_front();
                if removed.is_none() {
                    return Err(RecvTransactionError::Socket(SocketError::InvalidState));
                }
                let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| Some(current.saturating_sub(packet_len)),
                );
                return Ok(copied);
            }

            drop(queue);
            match sock.waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => continue,
                WaitOutcome::TimedOut => {
                    return Err(RecvTransactionError::Socket(SocketError::Timeout))
                }
                WaitOutcome::Closed => {
                    return Err(RecvTransactionError::Socket(SocketError::Closed))
                }
                WaitOutcome::NoProcess => {
                    return Err(RecvTransactionError::Socket(SocketError::NoProcess))
                }
                WaitOutcome::Interrupted => {
                    return Err(RecvTransactionError::Socket(SocketError::Interrupted))
                }
            }
        }
    }

    // ========================================================================
    // TCP Data Transfer (Phase 3)
    // ========================================================================

    /// Send TCP data (PSH+ACK segment).
    ///
    /// Builds MSS-sized TCP segments for transmission.
    /// Large payloads are split into multiple segments to fit within MTU.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket (must be in ESTABLISHED state)
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `payload` - Data to send
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_send` for LSM policy check
    /// - Validates socket is in ESTABLISHED state
    /// - Enforces TCP_MAX_SEND_SIZE limit
    ///
    /// # Returns
    ///
    /// Tuple of (bytes_queued, segments) on success.
    /// Caller is responsible for transmitting each segment.
    pub fn tcp_send(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        payload: &[u8],
    ) -> Result<(usize, mm::AdmittedVec<WirePacket>), SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // R51-2 FIX: Enforce send size limit to prevent OOM DoS
        // This is the canonical enforcement point for all TCP send paths.
        if payload.len() > TCP_MAX_SEND_SIZE {
            return Err(SocketError::MessageTooLarge);
        }

        // Get connection endpoints from metadata
        let meta = sock.meta_snapshot();
        let (local_ip, local_port, remote_ip, remote_port) = match (
            meta.local_ip.map(Ipv4Addr),
            meta.local_port,
            meta.remote_ip.map(Ipv4Addr),
            meta.remote_port,
        ) {
            (Some(li), Some(lp), Some(ri), Some(rp)) => (li, lp, ri, rp),
            _ => return Err(SocketError::InvalidState),
        };

        // LSM policy check
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(remote_ip.0);
        ctx.remote_port = remote_port;
        ctx.cap = Some(cap_id);
        hook_net_send(current, &ctx, payload.len())?;

        // Build segment under TCP lock
        let mut guard = sock.tcp.lock();
        let tcp_state = guard.as_mut().ok_or(SocketError::InvalidState)?;

        // Must be in a send-capable state (ESTABLISHED or CLOSE_WAIT)
        if !tcp_state.control.state.can_send() {
            return Err(SocketError::InvalidState);
        }

        // RF180-27 REVIEW FIX: a zero-length stream send performs no payload
        // copy or sequence mutation, but it does not bypass connection-state
        // validation. Linux may report EPIPE instead of ENOTCONN; this kernel's
        // established InvalidState mapping is ENOTCONN. Once the connected TCB
        // and LSM policy are validated, return allocation-free without touching
        // congestion, idle, retransmission, or accounting state.
        if payload.is_empty() {
            return Ok((0, mm::AdmittedVec::new(HeapClass::SocketObject)));
        }

        // Get current timestamp for idle validation and retransmission tracking
        let now_ms = self.time_wait_now();

        // R57-1: RFC 2861 idle cwnd validation - reduce cwnd if connection was idle
        // This prevents bursting with a stale (potentially large) cwnd after idle periods
        crate::tcp::validate_cwnd_after_idle(&mut tcp_state.control, now_ms);

        // Respect the peer-advertised send window; refuse to emit data that would overflow it
        let window_avail = tcp_state.control.send_window_available() as usize;
        if !payload.is_empty() && payload.len() > window_avail {
            // Window too small - caller should retry later
            return Err(SocketError::Timeout);
        }

        // R115-3 FIX: Bound total buffered TX bytes per connection to prevent OOM.
        // The send_buffer_bytes counter tracks cumulative data in the send_buffer.
        // If adding this payload would exceed the per-socket cap, reject with
        // WouldBlock so the caller retries after ACKs drain the buffer.
        let new_total = tcp_state
            .control
            .send_buffer_bytes
            .checked_add(payload.len())
            .ok_or(SocketError::WouldBlock)?;
        if new_total > TCP_MAX_SEND_BUFFER_BYTES {
            return Err(SocketError::WouldBlock);
        }

        // RF184-3 FIX: J2-6 per-namespace TX-memory budget — reserve the requested
        // payload.len() before segmentation while TCP lock is held. The reservation
        // will be reconciled to the actual buffered amount after segmentation,
        // eliminating the post-buffer fallible charge that caused accounting desync.
        // Original R184-3 claimed a TOCTOU race between charge and reconcile, but
        // the TCP lock serializes send and ACK paths — no race exists. However,
        // charging AFTER buffering with ? operator (R184-3 line 6871) created a
        // real bug: charge failure left segments in send_buffer without incrementing
        // send_buffer_bytes, causing permanent desync.
        self.try_charge_ns_send(sock.net_ns_id, &mut tcp_state.control, payload.len())?;

        // Get current sequence numbers
        let base_seq = tcp_state.control.snd_nxt;
        let ack = tcp_state.control.rcv_nxt;

        // R58: Advertise our scaled receive window
        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

        // TCP segmentation: split payload into MSS-sized chunks
        let mss = TCP_ETHERNET_MSS as usize;
        // R163-10 FIX: Start with Vec::new() instead of Vec::with_capacity so
        // the segments list itself has no infallible reservation. Each slot is
        // reserved fallibly inside the loop via try_reserve(1) before push.
        // RF180-41 FIX: both each serialized packet and the owner-list backing
        // participate in aggregate admission for their complete lifetimes.
        let mut segments: mm::AdmittedVec<WirePacket> =
            mm::AdmittedVec::new(HeapClass::SocketObject);
        let mut offset = 0usize;

        while offset < payload.len() {
            let end = core::cmp::min(offset + mss, payload.len());
            let seg_payload = &payload[offset..end];
            let seq = base_seq.wrapping_add(offset as u32);

            // PSH flag on non-empty data (typically set on last segment)
            let is_last = end == payload.len();
            let flags = TCP_FLAG_ACK
                | if !seg_payload.is_empty() && is_last {
                    TCP_FLAG_PSH
                } else {
                    0
                };

            // R163-10 FIX: Reserve space in the output segments Vec before
            // building the segment. If we cannot even reserve the slot, break
            // now — no data was buffered for retransmission for this chunk.
            if segments.try_reserve(1).is_err() {
                break;
            }

            let segment = match crate::tcp::try_build_tcp_segment(
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                seq,
                ack,
                flags,
                advertised_wnd,
                seg_payload,
            ) {
                Ok(segment) => segment,
                Err(_) => break,
            };

            // Buffer segment for potential retransmission
            // This enables reliable delivery: segments are kept until ACKed
            // R162-9 FIX: Fallible allocation for retransmission buffer copy.
            // R180-11 FIX: both queue backing and owned retransmit payload are
            // globally admitted before publication.
            if tcp_state
                .control
                .send_buffer
                .ensure_capacity_for(1)
                .is_err()
            {
                break;
            }
            let retrans_data =
                match AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, seg_payload) {
                    Ok(data) => data,
                    Err(_) => break,
                };
            if tcp_state
                .control
                .send_buffer
                .push_reserved(TcpSegment {
                    seq,
                    data: retrans_data,
                    sent_at: now_ms,
                    retrans_count: 0,
                    sacked: false,
                    lost: false,
                    retransmit_pending: false,
                    retransmit_in_flight: false,
                    retransmit_requires_rto: false,
                    tx_reject_count: 0,
                    retry_not_before_ms: 0,
                })
                .is_err()
            {
                break;
            }

            if segments.try_push(segment).is_err() {
                // Capacity was just prepared; treat invariant failure as OOM
                // and leave sequence/accounting at the last committed chunk.
                break;
            }
            offset = end;
        }

        // R163-1 FIX: Use `offset` (actual bytes buffered) not `payload.len()`.
        // When try_reserve_exact fails mid-loop, only `offset` bytes have
        // retransmission buffers. Advancing snd_nxt past unbuffered data
        // causes irrecoverable sequence number corruption on packet loss.
        if offset == 0 {
            // RF184-3 FIX: nothing was buffered — refund the full speculative
            // reservation before exit. reconcile_ns_send trues the per-ns counter
            // to match send_buffer_bytes (still zero), releasing the reservation.
            self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);
            drop(guard);
            return Err(SocketError::NoMemory);
        }

        tcp_state.control.send_buffer_bytes =
            tcp_state.control.send_buffer_bytes.saturating_add(offset);

        // RF184-3 FIX: reconcile the speculative reservation to the actual buffered
        // amount. send_buffer_bytes now reflects `offset` bytes; reconcile_ns_send
        // refunds (payload.len() - offset) by trueing the per-ns counter to match
        // the updated send_buffer_bytes. This eliminates the post-buffer fallible
        // charge that caused accounting desync when charge failed after buffering.
        self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);

        tcp_state.control.snd_nxt = base_seq.wrapping_add(offset as u32);

        // R57-1: Record activity timestamp for idle detection (RFC 2861)
        tcp_state.control.last_activity = now_ms;

        drop(guard);

        // Update statistics
        sock.tx_bytes.fetch_add(offset as u64, Ordering::Relaxed);

        Ok((offset, segments))
    }

    /// Shutdown TCP connection (half-close).
    ///
    /// Implements graceful shutdown per RFC 793. SHUT_RD is a no-op (we continue
    /// receiving data until FIN). SHUT_WR sends FIN and transitions state.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `how` - Shutdown mode: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
    ///
    /// # State Transitions
    ///
    /// - ESTABLISHED + SHUT_WR → FIN_WAIT_1 (send FIN)
    /// - CLOSE_WAIT + SHUT_WR → LAST_ACK (send FIN)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_shutdown` for LSM policy check
    ///
    /// # Returns
    ///
    /// Serialized FIN segment for transmission (if needed), or None.
    pub fn tcp_shutdown(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        how: i32,
    ) -> Result<Option<SerializedTcpPacket>, SocketError> {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;

        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Validate how parameter
        if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
            return Err(SocketError::InvalidState);
        }

        // SHUT_RD is a no-op for TCP (we continue receiving until FIN)
        if how == SHUT_RD {
            return Ok(None);
        }

        // Get connection endpoints from metadata
        let meta = sock.meta_snapshot();
        let (local_ip, local_port, remote_ip, remote_port) = match (
            meta.local_ip.map(Ipv4Addr),
            meta.local_port,
            meta.remote_ip.map(Ipv4Addr),
            meta.remote_port,
        ) {
            (Some(li), Some(lp), Some(ri), Some(rp)) => (li, lp, ri, rp),
            _ => return Err(SocketError::InvalidState),
        };

        // LSM policy check
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(remote_ip.0);
        ctx.remote_port = remote_port;
        ctx.cap = Some(cap_id);
        hook_net_shutdown(current, &ctx, how).map_err(|_| SocketError::PermissionDenied)?;

        let operation = self.lock_socket_operation(sock);
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }
        let mut guard = sock.tcp.lock();
        let tcp_state = guard.as_mut().ok_or(SocketError::InvalidState)?;

        // Check if FIN already sent
        if tcp_state.control.fin_sent {
            return Ok(None);
        }

        // Can only send FIN from states that allow sending
        if !tcp_state.control.state.can_send() {
            return Err(SocketError::InvalidState);
        }

        // Build FIN segment
        let seq = tcp_state.control.snd_nxt;
        let ack = tcp_state.control.rcv_nxt;
        // R58: Use scaled window advertisement
        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

        // RF180-25 FIX: allocation/admission and complete serialization precede
        // every sequence/state mutation. ENOMEM leaves shutdown retryable.
        let fin_segment = try_build_tcp_segment_admitted(
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            seq,
            ack,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            advertised_wnd,
            &[],
        )
        .map_err(|_| SocketError::NoMemory)?;

        let next_state = match tcp_state.control.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            other => other, // Should not happen due to can_send() check
        };
        tcp_state.control.snd_nxt = tcp_state.control.snd_nxt.wrapping_add(1);
        tcp_state.control.fin_sent = true;
        tcp_state.control.fin_sent_time = self.time_wait_now();
        tcp_state.control.fin_retries = 0;
        tcp_state.control.state = next_state;

        drop(guard);

        #[cfg(test)]
        self.pause_operation_commit_for_test(TEST_PAUSE_SHUTDOWN_COMMIT);

        drop(operation);

        // RF180-26 REVIEW FIX: the FIN and its sequence/state transition were
        // committed while this operation owned the serialization lock.  A
        // racing close may publish `closed` and run its deferred finalizer when
        // the guard is released, but it observes FinWait1/LastAck and preserves
        // that same graceful-close transaction.  Rejecting here discarded the
        // sole prepared FIN after consuming sequence space, leaving recovery to
        // a later retransmission timer.  The operation linearized first, so its
        // prepared packet must be returned to the caller exactly once.
        sock.wake_tcp_waiters();

        Ok(Some(SerializedTcpPacket { bytes: fin_segment }))
    }

    /// Receive TCP data (blocking with optional timeout).
    ///
    /// Returns data from the receive buffer, blocking if empty.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket (must be in ESTABLISHED state)
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `max_len` - Maximum bytes to return
    /// * `timeout_ns` - Timeout in nanoseconds (None for blocking indefinitely)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_recv` for LSM policy check
    ///
    /// # Returns
    ///
    /// Vector of received bytes (may be less than max_len).
    /// Transactional TCP receive. The shared receive operation is serialized;
    /// bytes are staged without draining, copied out under the TCP lock, and
    /// removed/accounted only after the caller reports copyout success.
    pub fn tcp_recv_with_commit<E, F>(
        &self,
        sock: &SocketArc,
        current: &ProcessCtx,
        cap_id: CapId,
        max_len: usize,
        timeout_ns: Option<u64>,
        mut commit: F,
    ) -> Result<usize, RecvTransactionError<E>>
    where
        F: FnMut(&[u8]) -> Result<(), E>,
    {
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(RecvTransactionError::Socket(SocketError::InvalidType));
        }
        if sock.is_closed() {
            return Err(RecvTransactionError::Socket(SocketError::Closed));
        }
        // RF180-27 FIX: a zero-length receive is an immediate successful
        // no-op after type/closed/LSM validation. Without this gate, a
        // non-empty receive buffer produced `actual == 0` forever and spun
        // while retaining the operation lock.  Do not require a TCB or touch
        // receive state: Linux also permits recv(..., 0) on an unconnected
        // stream socket.
        if max_len == 0 {
            let mut ctx = self.ctx_from_socket(sock);
            ctx.cap = Some(cap_id);
            hook_net_recv(current, &ctx, 0)
                .map_err(|error| RecvTransactionError::Socket(error.into()))?;
            return Ok(0);
        }

        loop {
            let waiters = sock
                .tcp_data_waiters()
                .ok_or(RecvTransactionError::Socket(SocketError::Closed))?;

            {
                // Serialize syscall consumers across the LSM gap. RX/ACK paths
                // do not take this process-context lock and remain interrupt-safe.
                let _operation = self.lock_socket_operation(sock);
                if sock.is_closed() {
                    return Err(RecvTransactionError::Socket(SocketError::Closed));
                }
                let mut guard = sock.tcp.lock();
                let tcp_state = guard
                    .as_mut()
                    .ok_or(RecvTransactionError::Socket(SocketError::Closed))?;
                if tcp_state.control.state.is_closed() {
                    return Err(RecvTransactionError::Socket(SocketError::Closed));
                }
                if !tcp_state.control.state.can_receive() {
                    return Err(RecvTransactionError::Socket(SocketError::InvalidState));
                }

                if !tcp_state.control.recv_buffer.is_empty() {
                    let requested = core::cmp::min(max_len, tcp_state.control.recv_buffer.len());
                    drop(guard);

                    let mut ctx = self.ctx_from_socket(sock);
                    ctx.cap = Some(cap_id);
                    hook_net_recv(current, &ctx, requested)
                        .map_err(|error| RecvTransactionError::Socket(error.into()))?;

                    let mut guard = sock.tcp.lock();
                    let tcp_state = guard
                        .as_mut()
                        .ok_or(RecvTransactionError::Socket(SocketError::Closed))?;
                    let actual = core::cmp::min(requested, tcp_state.control.recv_buffer.len());
                    if actual == 0 {
                        continue;
                    }

                    // R180-11 FIX: the transactional read snapshot is admitted
                    // for its complete allocator capacity and remains charged
                    // across user copyout/commit.
                    let data = AdmittedVec::try_copy_from_slice(
                        HeapClass::SocketPayload,
                        &tcp_state.control.recv_buffer.as_slice()[..actual],
                    )
                    .map_err(|_| RecvTransactionError::Socket(SocketError::NoMemory))?;

                    commit(data.as_slice()).map_err(RecvTransactionError::Commit)?;

                    // Lock-held length preflight above makes this commit
                    // allocation-free and infallible.
                    for _ in 0..actual {
                        let removed = tcp_state.control.recv_buffer.pop_front();
                        debug_assert!(removed.is_some());
                    }
                    tcp_state.control.ooo_drain_contiguous();
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                    if tcp_state.control.state == TcpState::TimeWait
                        && tcp_state.control.time_wait_start == 0
                    {
                        tcp_state.control.time_wait_start = self.time_wait_now();
                    }
                    drop(guard);
                    sock.rx_bytes.fetch_add(actual as u64, Ordering::Relaxed);
                    return Ok(actual);
                }

                if tcp_state.control.fin_received {
                    return Ok(0);
                }
            }

            match waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => continue,
                WaitOutcome::TimedOut => {
                    return Err(RecvTransactionError::Socket(SocketError::Timeout))
                }
                WaitOutcome::Closed => {
                    return Err(RecvTransactionError::Socket(SocketError::Closed))
                }
                WaitOutcome::NoProcess => {
                    return Err(RecvTransactionError::Socket(SocketError::NoProcess))
                }
                WaitOutcome::Interrupted => {
                    return Err(RecvTransactionError::Socket(SocketError::Interrupted))
                }
            }
        }
    }

    /// Deliver an inbound UDP datagram to a bound socket.
    ///
    /// Called from the network stack's packet processing path.
    ///
    /// # Arguments
    ///
    /// * `dst_port` - Destination port
    /// * `src_ip` - Source IP address
    /// * `src_port` - Source port
    /// * `data` - Datagram payload
    /// * `now_ticks` - Current time in ticks
    ///
    /// # Security
    ///
    /// - R47-3 FIX: Cleans up stale port bindings
    /// - R47-4 FIX: Checks queue capacity before copying to prevent DoS
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Packet delivery is scoped to the caller's network namespace.
    /// Only sockets bound to the same namespace can receive the packet.
    ///
    /// # Returns
    ///
    /// `true` if delivered to a socket, `false` if no listener.
    pub fn deliver_udp(
        &self,
        net_ns_id: NamespaceId,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        data: &[u8],
        now_ticks: u64,
    ) -> bool {
        // R75-1 FIX: Look up bound socket within the specified namespace
        let binding_key = (net_ns_id, dst_port);
        let target = {
            let mut bindings = self.udp_bindings.lock();
            match bindings.get(&binding_key).and_then(|pb| pb.sock.upgrade()) {
                Some(sock) => Some(sock),
                None => {
                    // R47-3 FIX: Clean up stale binding if upgrade failed.
                    // J2-8: this is the UDP RX path (IRQ/softirq-reachable by
                    // contract) and removes under the binding lock — so the
                    // stored charge is ENQUEUED for deferred uncharge, never
                    // uncharged inline (L5 under L8 / in IRQ is forbidden). No
                    // expect_ptr: the entry is already known dead.
                    if let Some(cgid) =
                        Self::remove_binding_charged(&mut bindings, binding_key, None)
                    {
                        self.enqueue_port_uncharge(cgid, 1);
                    }
                    None
                }
            }
        };

        let Some(sock) = target else {
            return false;
        };

        // R48-3 FIX: Invoke LSM policy check BEFORE allocating/copying
        // attacker-controlled payload. This prevents unauthorized peers from
        // filling MAX_RX_QUEUE of MAC-protected sockets, causing legitimate
        // traffic to be dropped despite policy denial at recv_from_udp time.
        //
        // We use the socket creator's context for the policy decision, since
        // this is packet delivery (not a specific syscall caller context).
        {
            let mut ctx = self.ctx_from_socket(&sock);
            ctx.remote = ipv4_to_u64(src_ip.0);
            ctx.remote_port = src_port;
            // Note: No CapId available in delivery path (not a syscall)

            if hook_net_recv(&sock.label.creator, &ctx, data.len()).is_err() {
                // LSM policy denied - drop packet without consuming queue space
                sock.rx_dropped.fetch_add(1, Ordering::Relaxed);
                return true; // Socket exists but policy denied
            }
        }

        // R133-2 FIX: Removed pre-allocation of data.to_vec() before cap checks.
        // enqueue_rx now performs queue depth and global byte cap checks BEFORE
        // allocating/copying the attacker-controlled payload.
        // Regardless of the enqueue outcome, a bound socket exists so report
        // "listener found".
        let _ = sock.enqueue_rx(src_ip, src_port, data, now_ticks);
        true
    }

    /// Close a socket, initiating TCP graceful shutdown if needed.
    ///
    /// Called when the capability is revoked or file descriptor is closed.
    ///
    /// # TCP Graceful Shutdown
    ///
    /// For TCP sockets in ESTABLISHED or CLOSE_WAIT state, this function:
    /// 1. Sends a FIN segment to initiate graceful shutdown
    /// 2. Transitions state to FIN_WAIT_1 or LAST_ACK
    /// 3. Keeps the socket registered for FIN retransmission and TIME_WAIT handling
    ///
    /// The sweep_time_wait function will clean up the socket after:
    /// - TIME_WAIT expires (120 seconds per RFC 793)
    /// - FIN retransmission limit exceeded (peer unresponsive)
    ///
    /// For UDP sockets or TCP sockets already closing, immediate cleanup occurs.
    pub fn close(&self, socket_id: u64) {
        // RF180-26 FIX: close-on-drop can run under the Process table lock. Do
        // not block on the socket-operation mutex: publish the close first, then
        // try to claim the idle lock. If an operation is active, its guard runs
        // the exact same finalizer after unlocking. The closed publication makes
        // every later operation fail validation while the in-flight operation is
        // ordered before this close and fully cleaned by the finalizer.
        let sock = {
            let sockets = self.sockets.read();
            sockets.get(&socket_id).cloned()
        };

        let Some(sock) = sock else {
            return;
        };
        if sock.close_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        sock.mark_closed();

        let idle_lock = sock.operation.try_lock();
        if let Some(lock) = idle_lock {
            drop(SocketOperationGuard {
                table: self,
                sock: &sock,
                lock: Some(lock),
            });
        }
    }

    /// Complete a close after no pre-close userspace operation owns the socket
    /// operation lock. Called exactly once by `maybe_finalize_deferred_close`.
    fn finish_close(&self, sock: &SocketArc) {
        let socket_id = sock.id;

        let mut keep_registered = false;
        let mut fin_to_send: Option<(Ipv4Addr, WirePacket, u64)> = None;

        // TCP sockets may need to send FIN and stay registered for TIME_WAIT/ACK handling.
        if sock.proto == SocketProtocol::Tcp {
            let meta = sock.meta_snapshot();
            if let (Some(local_ip), Some(local_port), Some(remote_ip), Some(remote_port)) = (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    match tcp_state.control.state {
                        TcpState::Established => {
                            keep_registered = true;

                            if !tcp_state.control.fin_sent {
                                let seq = tcp_state.control.snd_nxt;
                                let ack = tcp_state.control.rcv_nxt;
                                // R58: Use scaled window
                                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                                // RF180-25 FIX: admit and fully serialize FIN
                                // work before consuming sequence space or
                                // publishing the closing state. On pressure we
                                // fall back to immediate terminal cleanup.
                                let fin_segment = try_build_tcp_segment_admitted(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    advertised_wnd,
                                    &[],
                                );
                                if let Ok(fin_segment) = fin_segment {
                                    tcp_state.control.snd_nxt =
                                        tcp_state.control.snd_nxt.wrapping_add(1);
                                    tcp_state.control.fin_sent = true;
                                    tcp_state.control.fin_sent_time = self.time_wait_now();
                                    tcp_state.control.fin_retries = 0;
                                    tcp_state.control.state = TcpState::FinWait1;
                                    fin_to_send = Some((remote_ip, fin_segment, sock.net_ns_id.0));
                                } else {
                                    keep_registered = false;
                                }
                            }
                        }
                        TcpState::CloseWait => {
                            keep_registered = true;

                            if !tcp_state.control.fin_sent {
                                let seq = tcp_state.control.snd_nxt;
                                let ack = tcp_state.control.rcv_nxt;
                                // R58: Use scaled window
                                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                                let fin_segment = try_build_tcp_segment_admitted(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    advertised_wnd,
                                    &[],
                                );
                                if let Ok(fin_segment) = fin_segment {
                                    tcp_state.control.snd_nxt =
                                        tcp_state.control.snd_nxt.wrapping_add(1);
                                    tcp_state.control.fin_sent = true;
                                    tcp_state.control.fin_sent_time = self.time_wait_now();
                                    tcp_state.control.fin_retries = 0;
                                    tcp_state.control.state = TcpState::LastAck;
                                    fin_to_send = Some((remote_ip, fin_segment, sock.net_ns_id.0));
                                } else {
                                    keep_registered = false;
                                }
                            }
                        }
                        TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::Closing
                        | TcpState::LastAck
                        | TcpState::TimeWait => {
                            // Already in closing states; leave registered for sweep_time_wait.
                            keep_registered = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        if keep_registered {
            // Mark closed but leave in the tables so FIN/ACK/TIME_WAIT can complete.
            // The sweep_time_wait timer will clean up after TIME_WAIT expires or
            // FIN retransmission gives up.
            sock.mark_closed();
            sock.wake_tcp_waiters();
            self.closed_count.fetch_add(1, Ordering::Relaxed);

            // R169-6 slice 2 BACKSTOP (Codex convergence round-1 UNSAFE fix):
            // an RX-side cleanup_tcp_connection can race this close() — it read
            // is_closed()==false (so it PURE-SKIPPED a charged Explicit binding)
            // and its FINAL is_closed() gate also missed our mark_closed().
            // Without this backstop the socket would linger in `sockets`
            // forever: its TCB is already None so sweep_time_wait never
            // revisits it, and the map's strong Arc keeps the binding's Weak
            // alive, so the dead-Weak triad never reclaims the held charge
            // (pre-existing socket/ns-count linger, now also a permanent
            // ports.max strand for a charged Explicit bind).
            //
            // ORDERING PROOF that exactly one side always finishes the
            // teardown: we mark_closed() (A1) THEN re-check the TCB (A2);
            // cleanup nulls the TCB (B1) THEN reads is_closed() (B2).
            // - B1 < A2: we observe TCB == None here and run the terminal
            //   teardown below.
            // - A2 < B1: then A1 < A2 < B1 < B2, so B2 observes mark_closed and
            //   cleanup removes the socket itself (its now-dead Weak is swept).
            // Overlap may fire BOTH; every step below is exactly-once gated
            // (sockets-map remove is_some / BTreeMap single arbiter / ptr-eq).
            let tcb_gone = sock.tcp.lock().is_none();
            if tcb_gone {
                if self.sockets.write().remove(&socket_id).is_some() {
                    self.dec_ns_count(sock.net_ns_id);
                }
                let meta = sock.meta_snapshot();
                if let Some(port) = meta.local_port {
                    let binding_key = (sock.net_ns_id, port);
                    // Terminal teardown: KIND-AGNOSTIC ptr-eq-gated remove
                    // (hold-until-close ends at close). Block-scoped so the L8
                    // guard drops before the L5 uncharge; STORED cgid only —
                    // close() may run under the Process lock (exec/cloexec).
                    let port_cgid = {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::remove_binding_charged(
                            &mut bindings,
                            binding_key,
                            Some(Arc::as_ptr(&sock)),
                        )
                    };
                    if let Some(c) = port_cgid {
                        uncharge_port_cgroup(c, 1);
                    }
                }
            }
        } else if let Some(sock) = self.remove_socket(socket_id) {
            // DEADLOCK FIX (found in J2-6 convergence audit, PE-06): the removal now
            // goes through remove_socket() so the `sockets` write guard is dropped
            // BEFORE this body. In edition 2021 a temporary in an `if let` scrutinee
            // lives to the end of the block, so the prior inline
            // `self.sockets.write().remove(..)` held the write lock across the child
            // cleanup loop below — and cleanup_tcp_connection() re-acquires
            // `sockets.write()` (R129-2), self-deadlocking on listener close with
            // queued children. This makes the R52-2 "cleanup after releasing locks"
            // intent actually hold.
            // R52-2 FIX: Clean up pending SYN/accept queues for listening sockets
            //
            // When a listening socket is closed, we must tear down all pending
            // connections to prevent resource leaks. This includes:
            // - Half-open connections in the SYN queue (awaiting final ACK)
            // - Fully established connections in the accept queue (awaiting accept())
            //
            // DEADLOCK FIX (Codex review): Collect children first while holding
            // listen lock, then release it before calling cleanup_tcp_connection,
            // which may acquire sockets.write() lock internally.
            // J2-2: count the half-open SYNs drained below; the per-namespace
            // half-open uncharge is deferred to the proven dec_ns_count safe
            // context (all drained SYNs share this listener's namespace).
            let mut drained_syn_count: u64 = 0;
            let mut detached_listen = if sock.is_listening() {
                sock.listen.lock().take()
            } else {
                None
            };
            if let Some(listen_state) = detached_listen.as_ref() {
                listen_state.accept_waiters.close();
                listen_state.accept_waiters.wake_all();
            }

            let meta = sock.meta_snapshot();

            // R75-1 FIX: Remove port bindings using namespace-scoped keys.
            // J2-8: route through remove_binding_charged — ptr-eq gated, so a
            // child socket carrying the listener's port (passive open) can NEVER
            // unbind/uncharge the listener's binding — and refund the STORED port
            // charge. Block-scoped so the L8 binding guard drops BEFORE the L5
            // uncharge (Rust-2021 temporary-lifetime trap). Read the STORED cgid,
            // never current_cgroup_id(): close() also runs UNDER the Process lock
            // on exec/cloexec teardown, where re-locking PROCESS_TABLE would
            // self-deadlock. DOMINANT teardown for UDP + non-ESTABLISHED TCP.
            if let Some(port) = meta.local_port {
                let binding_key = (sock.net_ns_id, port);
                let sock_ptr = Some(Arc::as_ptr(&sock));
                let port_cgid = match sock.proto {
                    SocketProtocol::Udp => {
                        let mut bindings = self.udp_bindings.lock();
                        Self::remove_binding_charged(&mut bindings, binding_key, sock_ptr)
                    }
                    SocketProtocol::Tcp => {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::remove_binding_charged(&mut bindings, binding_key, sock_ptr)
                    }
                };
                if let Some(c) = port_cgid {
                    uncharge_port_cgroup(c, 1);
                }
            }

            // Remove TCP connection from 4-tuple map
            if sock.proto == SocketProtocol::Tcp {
                if let (Some(lip), Some(lport), Some(rip), Some(rport)) = (
                    meta.local_ip,
                    meta.local_port,
                    meta.remote_ip,
                    meta.remote_port,
                ) {
                    let key = tcp_map_key_from_parts(
                        sock.net_ns_id,
                        Ipv4Addr(lip),
                        lport,
                        Ipv4Addr(rip),
                        rport,
                    );
                    // RF180-36 FIX: a delayed close must not remove or uncharge a
                    // same-tuple replacement published after this socket detached.
                    self.remove_tcp_conn_exact_owner(key, &sock);
                }
            }

            // Mark closed and wake waiters
            sock.mark_closed();
            self.closed_count.fetch_add(1, Ordering::Relaxed);

            // R180-11 FIX: detached listen state permits allocation-free,
            // one-at-a-time child teardown with no listen lock held.
            if let Some(mut listen_state) = detached_listen.take() {
                loop {
                    let key = listen_state.syn_queue.keys().next().copied();
                    let Some(key) = key else { break };
                    if let Some(pending) = listen_state.syn_queue.remove(&key) {
                        pending.sock.mark_closed();
                        dec_half_open();
                        drained_syn_count = drained_syn_count.saturating_add(1);
                        self.cleanup_tcp_connection(&pending.sock);
                    }
                }
                while let Some(child) = listen_state.accept_queue.pop_front() {
                    child.mark_closed();
                    self.cleanup_tcp_connection(&child);
                }
            }

            // RF180-26 FIX: a close racing the last commit of bind/connect/
            // listen must not leave metadata or a TCB reachable through an Arc
            // retained by the losing syscall thread. Registry removals above are
            // pointer-gated; this final object-local scrub is allocation-free.
            if sock.proto == SocketProtocol::Tcp {
                self.cleanup_tcp_connection(&sock);
            }
            *sock.meta.lock() = SocketMeta::new();
            sock.clear_listen_state();

            // R76-3 FIX: Decrement per-namespace socket count AFTER releasing sockets lock
            // to avoid deadlock (Codex review fix: lock ordering with per_ns_counts)
            self.dec_ns_count(sock.net_ns_id);
            // J2-2: uncharge the per-namespace half-open SYNs drained above, in the
            // SAME safe context as dec_ns_count (mirrors that proven lock ordering).
            self.dec_ns_syn_by(sock.net_ns_id, drained_syn_count);
        }

        // Transmit FIN after releasing locks to avoid blocking critical sections.
        if let Some((dst_ip, segment, ns_id)) = fin_to_send {
            let _ = transmit_tcp_segment(dst_ip, &segment, ns_id);
        }
    }

    /// Get a socket by ID.
    pub fn get(&self, socket_id: u64) -> Option<SocketArc> {
        self.sockets.read().get(&socket_id).cloned()
    }

    /// Get table statistics.
    pub fn stats(&self) -> TableStats {
        TableStats {
            created: self.created.load(Ordering::Relaxed),
            closed: self.closed_count.load(Ordering::Relaxed),
            active: self.sockets.read().len(),
            bound_ports: self.udp_bindings.lock().len(),
            timer_sweeps_skipped: self.timer_sweeps_skipped.load(Ordering::Relaxed),
            forced_tw_evictions: self.forced_tw_evictions.load(Ordering::Relaxed),
        }
    }

    /// R59-2 FIX: Fallback seed when CSPRNG is unavailable.
    ///
    /// Uses RDTSC mixed with monotonic counter via multiply-rotate-xor.
    /// Not cryptographically secure but unpredictable enough to prevent
    /// trivial port guessing when hardware RNG is unavailable.
    #[inline]
    fn fallback_port_seed(&self) -> u16 {
        let tsc = rdtsc();
        let counter = self.next_ephemeral.fetch_add(1, Ordering::Relaxed) as u64;

        // SipHash-like mixing for unpredictable output
        let mut v0 = tsc.wrapping_add(counter);
        let mut v1 = (tsc ^ counter).rotate_left(17);

        v0 = v0.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        v1 ^= v0.rotate_left(23);
        v1 = v1.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        v0 ^= v1.rotate_left(41);

        let mixed = v0 ^ v1;
        (mixed ^ (mixed >> 32)) as u16
    }

    /// Allocate an ephemeral port.
    ///
    /// R59-1 FIX: Use CSPRNG for port randomization to prevent off-path attacks.
    /// Attackers who can predict ephemeral ports can more easily hijack connections.
    ///
    /// Algorithm:
    /// 1. Try random ports from CSPRNG (2x range attempts for good coverage)
    /// 2. Fall back to deterministic sweep if CSPRNG fails or all random ports taken
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port availability is checked within the given namespace. Different namespaces
    /// can independently use the same ephemeral port without conflict.
    fn alloc_ephemeral_port(&self, net_ns_id: NamespaceId) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let mut bindings = self.udp_bindings.lock();
        // J2-8: prune this namespace's dead-Weak bindings (enqueuing their charges)
        // so a stale entry never makes a port look in-use below, and the leaked
        // charge is reclaimed.
        self.reap_dead_bindings(&mut bindings, net_ns_id);

        // Phase 1: Random selection using CSPRNG (preferred)
        // Try 2x range to give good coverage while limiting iterations
        for _ in 0..(range.saturating_mul(2)) {
            // Try CSPRNG first, fall back to RDTSC-based hash if RNG unavailable
            // R149-5 FIX: Use fill_random (FIPS boundary pub API).
            let seed = {
                let mut buf = [0u8; 4];
                if security::fill_random(&mut buf).is_ok() {
                    u32::from_le_bytes(buf) as u16
                } else {
                    self.fallback_port_seed()
                }
            };
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            // R75-1 FIX: Check namespace-scoped port binding
            if !bindings.contains_key(&(net_ns_id, candidate)) {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback (guarantees finding free port if one exists)
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            // R75-1 FIX: Check namespace-scoped port binding
            if !bindings.contains_key(&(net_ns_id, candidate)) {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Allocate an ephemeral port for TCP (ensures no existing TCP socket uses it).
    ///
    /// R59-1 FIX: Use CSPRNG for port randomization to prevent off-path attacks.
    /// Predictable ephemeral ports enable connection hijacking and blind injection.
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port availability is checked within the given namespace. Different namespaces
    /// can independently use the same ephemeral port without conflict.
    fn alloc_ephemeral_tcp_port(&self, net_ns_id: NamespaceId) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let mut tcp_bindings = self.tcp_bindings.lock();
        // J2-8: prune dead-Weak bindings (enqueue their charges) so a stale entry
        // is not counted as in-use. Done while only tcp_bindings is held, so the
        // pending leaf is never taken under tcp_conns.
        self.reap_dead_bindings(&mut tcp_bindings, net_ns_id);
        let mut tcp_conns = self.tcp_conns.lock();
        // J2-8 (Codex review): a stale `tcp_conns` Weak ALSO makes a port look
        // in-use via the `keys().any(...)` scan below, so prune those too —
        // completing the dead-Weak port-availability fix for TCP (J2-1's
        // per-namespace conn count is uncharged here as a side effect).
        self.conns_retain_accounted(&mut tcp_conns);

        // Phase 1: Random selection using CSPRNG (preferred)
        for _ in 0..(range.saturating_mul(2)) {
            // R59-2 FIX: Use RDTSC-based fallback instead of predictable counter
            // R149-5 FIX: Use fill_random (FIPS boundary pub API).
            let seed = {
                let mut buf = [0u8; 4];
                if security::fill_random(&mut buf).is_ok() {
                    u32::from_le_bytes(buf) as u16
                } else {
                    self.fallback_port_seed()
                }
            };
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            // R75-1 FIX: Check namespace-scoped TCP port binding
            if tcp_bindings.contains_key(&(net_ns_id, candidate)) {
                continue;
            }
            // R106-10 FIX: Check if any connection uses this port within this namespace
            let in_use = tcp_conns
                .keys()
                .any(|(ns_id, _, port, _, _)| *ns_id == net_ns_id && *port == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            // R75-1 FIX: Check namespace-scoped TCP port binding
            if tcp_bindings.contains_key(&(net_ns_id, candidate)) {
                continue;
            }
            let in_use = tcp_conns
                .keys()
                .any(|(ns_id, _, port, _, _)| *ns_id == net_ns_id && *port == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Build LSM NetCtx from socket state.
    ///
    /// # R51-1: Made public for sys_accept to build context for LSM hook.
    pub fn ctx_from_socket(&self, sock: &SocketState) -> NetCtx {
        let meta = sock.meta_snapshot();
        // Use correct protocol based on socket type
        let proto = match sock.proto {
            SocketProtocol::Udp => UDP_PROTO as u16,
            SocketProtocol::Tcp => TCP_PROTO as u16,
        };
        let mut ctx = NetCtx::new(sock.id, proto);

        if let Some(ip) = meta.local_ip {
            ctx.local = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.local_port {
            ctx.local_port = port;
        }
        if let Some(ip) = meta.remote_ip {
            ctx.remote = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.remote_port {
            ctx.remote_port = port;
        }
        ctx.cap = Some(CapId::INVALID);

        ctx
    }

    // ========================================================================
    // TCP RX Path (Phase 2)
    // ========================================================================

    /// R106-10 FIX: Look up a TCP connection by namespace + 4-tuple, removing stale entries.
    ///
    /// # Arguments
    /// * `net_ns_id` - Network namespace for scoped lookup
    /// * `local_ip` - Our IP (destination in incoming packet)
    /// * `local_port` - Our port (destination port in incoming packet)
    /// * `remote_ip` - Peer IP (source in incoming packet)
    /// * `remote_port` - Peer port (source port in incoming packet)
    pub fn lookup_tcp_conn(
        &self,
        net_ns_id: NamespaceId,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<SocketArc> {
        let key = tcp_map_key_from_parts(net_ns_id, local_ip, local_port, remote_ip, remote_port);
        let mut conns = self.tcp_conns.lock();
        match conns.get(&key).and_then(|w| w.upgrade()) {
            Some(sock) => Some(sock),
            None => {
                // Clean up stale weak reference.
                // J2-1: uncharge the per-namespace connection on lazy stale-Weak removal.
                if conns.remove(&key).is_some() {
                    self.dec_ns_conn(key.0);
                }
                None
            }
        }
    }

    fn bind_tcp_reply(&self, sock: &SocketArc, operation_token: u64) -> TcpReplyBinding {
        TcpReplyBinding {
            sock: sock.clone(),
            socket_id: sock.id,
            socket_generation: sock.owner_generation,
            operation_token,
        }
    }

    pub(crate) fn lock_tcp_reply_operation<'a>(
        &'a self,
        binding: &'a TcpReplyBinding,
        response: &TcpHeader,
    ) -> Option<TcpReplyOperation<'a>> {
        let guard = self.lock_socket_operation(&binding.sock);
        let operation = TcpReplyOperation {
            guard,
            token: binding.operation_token,
        };
        let sock = operation.guard.sock;
        if sock.id != binding.socket_id
            || sock.owner_generation != binding.socket_generation
            || sock.close_pending.load(Ordering::Acquire)
            || sock.is_closed()
            || !operation.exact_registry_owner()
        {
            return None;
        }

        let tcp_guard = sock.tcp.lock();
        let tcp_state = tcp_guard.as_ref()?;
        if tcp_state.control.pending_reply_token != Some(binding.operation_token) {
            return None;
        }
        let exact_packet = if tcp_state.control.active_open_pending {
            tcp_state.control.state == TcpState::Closed
                && response.flags == TCP_FLAG_SYN
                && response.seq_num == tcp_state.control.iss
                && response.ack_num == 0
        } else if let Some(pending) = tcp_state.control.pending_handshake {
            tcp_state.control.state == TcpState::SynSent
                && response.flags == pending.response_flags
                && response.seq_num == pending.response_seq
                && response.ack_num == pending.response_ack
        } else {
            tcp_state.control.state == TcpState::SynReceived
                && response.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
                && response.seq_num == tcp_state.control.iss
                && response.ack_num == tcp_state.control.rcv_nxt
        };
        drop(tcp_guard);
        exact_packet.then_some(operation)
    }

    /// P0-2 FIX: Attempt to reclaim one TCP connection slot by evicting the
    /// oldest TIME_WAIT entry from `tcp_conns`.
    ///
    /// Called exclusively from the SYN cookie ACK validation path when the
    /// global connection limit is reached.  Under sustained overload the
    /// normal periodic `sweep_time_wait` may not have run yet, so we do a
    /// targeted eviction of the single oldest TIME_WAIT socket.
    ///
    /// # Lock ordering
    ///
    /// `tcp_conns` is locked briefly to collect candidate sockets, then
    /// released before calling `cleanup_tcp_connection` (which re-locks
    /// `tcp_conns` internally).  `sock.tcp` is acquired via `try_lock()` to
    /// avoid deadlock if another core is already processing that socket.
    ///
    /// # Returns
    ///
    /// `true` if `tcp_conns.len()` is below `TCP_MAX_ACTIVE_CONNECTIONS`
    /// after cleanup/eviction (i.e. the caller may proceed to create a
    /// connection).
    fn try_evict_time_wait_for_cookie(&self, now_ms: u64) -> bool {
        // R180-11 FIX: scan under the registry leaf with try-lock-only TCB
        // probes and retain just one Arc. This avoids a cleanup-time Vec
        // allocation without introducing a blocking conns -> tcp edge.
        let victim: Option<SocketArc> = {
            let mut conns = self.tcp_conns.lock();
            self.conns_retain_accounted(&mut conns);
            if conns.len() < TCP_MAX_ACTIVE_CONNECTIONS {
                return true; // stale-Weak pruning alone freed capacity
            }
            let mut oldest_start = u64::MAX;
            let mut victim = None;
            for weak in conns.values() {
                let Some(sock) = weak.upgrade() else { continue };
                if !sock.is_closed() {
                    continue;
                }
                let Some(guard) = sock.tcp.try_lock() else {
                    continue;
                };
                let Some(tcp_state) = guard.as_ref() else {
                    continue;
                };
                if tcp_state.control.state != TcpState::TimeWait {
                    continue;
                }
                let start = if tcp_state.control.time_wait_start == 0 {
                    now_ms
                } else {
                    tcp_state.control.time_wait_start
                };
                if start < oldest_start {
                    oldest_start = start;
                    victim = Some(sock.clone());
                }
            }
            victim
        };

        let victim = match victim {
            Some(v) => v,
            None => return false, // no eligible TIME_WAIT entries to evict
        };
        if let Some(mut guard) = victim.tcp.try_lock() {
            if let Some(tcp_state) = guard.as_mut() {
                if tcp_state.control.state == TcpState::TimeWait {
                    tcp_state.control.state = TcpState::Closed;
                }
            }
        }
        // cleanup_tcp_connection: removes from tcp_conns + dec_active_conn.
        // R129-2: If the victim was mark_closed(), cleanup_tcp_connection now also
        // removes from sockets map and calls dec_ns_count. The is_some() guard below
        // ensures we only decrement if cleanup_tcp_connection didn't already do it.
        self.cleanup_tcp_connection(&victim);
        // Remove from sockets map + decrement namespace quota (fallback for
        // victims not yet mark_closed when cleanup_tcp_connection ran).
        if self.sockets.write().remove(&victim.id).is_some() {
            self.dec_ns_count(victim.net_ns_id);
        }
        self.forced_tw_evictions.fetch_add(1, Ordering::Relaxed);

        // Phase 4: re-check capacity.
        let mut conns = self.tcp_conns.lock();
        self.conns_retain_accounted(&mut conns);
        conns.len() < TCP_MAX_ACTIVE_CONNECTIONS
    }

    /// Process an inbound TCP segment for handshake completion.
    ///
    /// This implements Phase 2 of the TCP state machine:
    /// - SYN_SENT + SYN-ACK → ESTABLISHED (send ACK)
    /// - Unknown connection → RST
    ///
    /// # Arguments
    /// * `src_ip` - Source IP (remote peer)
    /// * `dst_ip` - Destination IP (our IP)
    /// * `header` - Parsed TCP header
    /// * `payload` - TCP payload (after header)
    /// * `options` - Parsed TCP options (for window scaling, etc.)
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// TCP segment processing is scoped to the specified network namespace.
    /// Listener lookup and connection matching respect namespace boundaries.
    ///
    /// # Returns
    /// TCP segment to transmit (ACK or RST) if a response is required.
    pub(crate) fn process_tcp_segment(
        &self,
        net_ns_id: NamespaceId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
        options: &TcpOptions,
        reply_binding: &mut Option<TcpReplyBinding>,
        ingress_handshake_committed: &mut bool,
    ) -> Option<WirePacket> {
        *reply_binding = None;
        *ingress_handshake_committed = false;
        // R160-9 FIX: Reject invalid TCP flag combinations per RFC 793 §3.4.
        // SYN+RST is always invalid (connection-setup contradicts abort).
        // SYN+FIN is suspicious and rejected by modern stacks. These malformed
        // segments are typically from port scanners or exploit attempts.
        let flags = header.flags;
        if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_RST != 0 {
            return None;
        }
        if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_FIN != 0 {
            return None;
        }

        // RFC 793/5961: Handle RST segments with sequence validation
        if header.flags & TCP_FLAG_RST != 0 {
            // If we have a connection, validate RST before accepting
            if let Some(sock) =
                self.lookup_tcp_conn(net_ns_id, dst_ip, header.dst_port, src_ip, header.src_port)
            {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    let old_state = tcp_state.control.state;

                    // R151-7 FIX: Validate RST per RFC 5961 Section 3.2.
                    // In synchronized states, accept RST ONLY if SEG.SEQ == RCV.NXT (exact match).
                    // In-window but non-exact RSTs trigger a rate-limited challenge ACK.
                    // Out-of-window RSTs are silently dropped.
                    let (accept_rst, send_challenge) = match old_state {
                        TcpState::SynSent => {
                            // R152-6 FIX: In SYN_SENT, require ACK flag on RST per RFC 793 §3.4.
                            // Never send challenge ACK — RFC 5961 challenge ACKs are for
                            // synchronized states only. Bare RST (no ACK) is silently dropped.
                            let has_ack = header.flags & TCP_FLAG_ACK != 0;
                            (
                                has_ack && header.ack_num == tcp_state.control.snd_nxt,
                                false,
                            )
                        }
                        // R146-NET-3 FIX: Accept RST in SynReceived so
                        // half-open connections can be aborted and SYN queue
                        // slots freed. Per RFC 793 Section 3.4, a valid RST
                        // in SYN_RECEIVED returns the connection to CLOSED.
                        TcpState::SynReceived
                        | TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::CloseWait
                        | TcpState::Closing
                        | TcpState::LastAck => {
                            // R151-7 FIX: RFC 5961 strict RST validation.
                            // Only exact seq match accepts RST; in-window triggers challenge ACK.
                            let wnd = tcp_state.control.rcv_wnd.max(1);
                            if header.seq_num == tcp_state.control.rcv_nxt {
                                (true, false)
                            } else if seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, wnd)
                            {
                                (false, true)
                            } else {
                                (false, false)
                            }
                        }
                        _ => (false, false), // Silently drop RST in other states
                    };

                    if !accept_rst {
                        // R151-7 FIX: Out-of-window RSTs are silently dropped (no challenge ACK).
                        if !send_challenge {
                            drop(guard);
                            return None;
                        }
                        // R54-2 FIX: Rate limit challenge ACKs to prevent amplification attacks
                        // An attacker could send spoofed RST packets at high rate to exhaust
                        // CPU and bandwidth via unlimited challenge ACK responses.
                        if !allow_challenge_ack(self.time_wait_now()) {
                            drop(guard);
                            return None;
                        }

                        // R50-4 IMPROVEMENT: Send challenge ACK per RFC 5961 Section 3.2
                        // This allows legitimate endpoints to prove their connection state
                        // while preventing blind RST injection attacks
                        // R58: Use scaled window advertisement
                        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                        let challenge_ack = build_tcp_segment(
                            dst_ip,                    // Our IP
                            src_ip,                    // Peer IP
                            header.dst_port,           // Our port
                            header.src_port,           // Peer port
                            tcp_state.control.snd_nxt, // Our next seq
                            tcp_state.control.rcv_nxt, // Expected peer seq
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        drop(guard);
                        return Some(challenge_ack);
                    }

                    // R130-4 FIX: Extend RST cleanup to all synchronized states.
                    // RFC 793 §3.4 requires a valid RST in any synchronized state
                    // to immediately close the connection. Previously only SynSent
                    // and Established triggered cleanup; closing-state RSTs were
                    // silently ignored, leaving sockets until timer sweep.
                    if matches!(
                        old_state,
                        TcpState::SynSent
                            | TcpState::SynReceived
                            | TcpState::Established
                            | TcpState::FinWait1
                            | TcpState::FinWait2
                            | TcpState::CloseWait
                            | TcpState::Closing
                            | TcpState::LastAck
                    ) {
                        tcp_state.control.state = TcpState::Closed;
                        drop(guard);

                        // R164-5 FIX: When RST aborts a SynReceived connection,
                        // remove the PendingSyn entry from the listener's SYN
                        // queue and decrement GLOBAL_HALF_OPEN_COUNT. Without
                        // this, the slot leaks until SYN timeout (30s), allowing
                        // an attacker to exhaust the half-open limit.
                        if old_state == TcpState::SynReceived {
                            if let Some(listener) =
                                self.lookup_tcp_listener(net_ns_id, header.dst_port)
                            {
                                let mut listen_guard = listener.listen.lock();
                                if let Some(listen_state) = listen_guard.as_mut() {
                                    let syn_key = tcp_map_key_from_parts(
                                        net_ns_id,
                                        dst_ip,
                                        header.dst_port,
                                        src_ip,
                                        header.src_port,
                                    );
                                    listen_state.take_syn(&syn_key, self);
                                }
                            }
                        }

                        self.cleanup_tcp_connection(&sock);
                        sock.wake_tcp_waiters();
                    }
                }
            }
            return None;
        }

        // Look up existing connection by namespace + 4-tuple
        let sock =
            match self.lookup_tcp_conn(net_ns_id, dst_ip, header.dst_port, src_ip, header.src_port)
            {
                Some(s) => s,
                None => {
                    // R51-1: Passive open handling for inbound SYN
                    let is_syn = header.flags & TCP_FLAG_SYN != 0;
                    let is_ack = header.flags & TCP_FLAG_ACK != 0;

                    // Pure SYN (without ACK) indicates new connection request
                    if is_syn && !is_ack {
                        // R75-1 FIX: Look up listener within the specified namespace
                        if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port)
                        {
                            let mut listen_guard = listener.listen.lock();
                            if let Some(listen_state) = listen_guard.as_mut() {
                                let syn_key = tcp_map_key_from_parts(
                                    listener.net_ns_id,
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                );

                                // Handle retransmitted SYN: resend cached SYN-ACK
                                if let Some(existing) = listen_state.get_syn(&syn_key) {
                                    let retry =
                                        Self::try_clone_wire_segment(existing.syn_ack.as_slice())?;
                                    let token =
                                        next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN).ok()?;
                                    {
                                        let mut child_tcp = existing.sock.tcp.lock();
                                        let child_state = child_tcp.as_mut()?;
                                        if child_state.control.state != TcpState::SynReceived
                                            || child_state.control.passive_egress_confirmed
                                        {
                                            return None;
                                        }
                                        child_state.control.pending_reply_token = Some(token);
                                    }
                                    *reply_binding =
                                        Some(self.bind_tcp_reply(&existing.sock, token));
                                    return Some(retry);
                                }

                                // Get current timestamp for SYN cookie timing
                                let now_ms = self.time_wait_now();

                                // Select MSS for SYN cookie (used in both paths)
                                let (mss_index, cookie_mss) = syn_cookie_select_mss(options.mss);

                                // R106-2 FIX: Determine if we should fall back to SYN cookies.
                                // When the global connection limit is reached, use stateless
                                // SYN-ACK instead of silently dropping.  This ensures legitimate
                                // clients can still complete handshakes once connection slots
                                // free up, while attackers gain no DoS advantage.
                                let mut force_syn_cookie = false;
                                {
                                    let mut conns = self.tcp_conns.lock();
                                    self.conns_retain_accounted(&mut conns);
                                    if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                        // R106-2 FIX: Global active connection limit reached —
                                        // fall back to SYN cookies instead of dropping the SYN.
                                        force_syn_cookie = true;
                                    }
                                    // Check if 4-tuple already exists (race condition guard)
                                    if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                        return None;
                                    }
                                }

                                // R106-2 FIX: SYN Cookie Path — use stateless SYN-ACK when:
                                // 1. Per-listener SYN backlog is full (original condition), OR
                                // 2. Global active connection limit is reached (new condition)
                                // SYN cookies require zero per-connection state, providing
                                // graceful degradation instead of silent SYN drops.
                                if force_syn_cookie
                                    || listen_state.syn_queue.len() >= listen_state.syn_backlog
                                {
                                    // R137-2 FIX: Rate limit stateless SYN-cookie SYN-ACK
                                    // generation to reduce spoofed-source reflection.
                                    if !allow_syn_cookie_ack(now_ms) {
                                        return None;
                                    }

                                    // Generate SYN cookie ISN (encodes 4-tuple, time, MSS)
                                    let cookie_iss = generate_syn_cookie_isn(
                                        now_ms,
                                        dst_ip,
                                        header.dst_port,
                                        src_ip,
                                        header.src_port,
                                        mss_index,
                                    );

                                    // Build SYN-ACK with cookie ISN and MSS option
                                    // Note: Window scaling is NOT preserved in SYN cookies
                                    let syn_ack_options = [TcpOptionKind::Mss(cookie_mss)];
                                    if self.passive_syn_ack_build_faulted() {
                                        return None;
                                    }
                                    let syn_ack = match try_build_tcp_segment_with_options(
                                        dst_ip,
                                        src_ip,
                                        header.dst_port,
                                        header.src_port,
                                        cookie_iss,
                                        header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                                        TCP_DEFAULT_WINDOW, // Unscaled window
                                        &syn_ack_options,
                                        &[],
                                    ) {
                                        Ok(segment) => segment,
                                        Err(_) => return None,
                                    };
                                    // RF180-7 FIX: count only a cookie whose complete
                                    // option-bearing SYN-ACK was actually prepared.
                                    SYN_COOKIES_GENERATED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX

                                    // RF180-41 REVIEW FIX: ingress already created
                                    // the SYN flow. The returned SYN-ACK advances it
                                    // only in transmit_prepared_reply after queueing.
                                    return Some(syn_ack);
                                }

                                // R180-11 FIX: build the complete child privately with ID 0.
                                // The real ID and every registry/counter publication are committed
                                // together below, after all fallible Arc/TCB/cache allocations.
                                let child = match SocketState::try_new_arc(
                                    0,
                                    listener.domain,
                                    listener.ty,
                                    listener.proto,
                                    listener.label,
                                    listener.net_ns_id,
                                ) {
                                    Ok(child) => child,
                                    Err(_) => return None,
                                };

                                // Set local and remote addresses
                                child.bind_local(dst_ip, header.dst_port);
                                child.set_remote(src_ip, header.src_port);

                                // Generate server ISN using the secure ISN generator
                                let iss =
                                    generate_isn(dst_ip, header.dst_port, src_ip, header.src_port);

                                // Create server-side TCB in SynReceived state
                                let mut tcb = TcpControlBlock::new_server(
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                    iss,
                                    header.seq_num,
                                );

                                // Set MSS from negotiated value
                                tcb.snd_mss = cookie_mss;
                                tcb.rcv_mss = cookie_mss;
                                tcb.cwnd = initial_cwnd(cookie_mss);

                                // R58: RFC 7323 Window Scaling - process WSopt from incoming SYN
                                // If client sent WSopt, we should respond with our own WSopt
                                if let Some(peer_scale) = options.window_scale {
                                    tcb.snd_wscale = peer_scale.min(TCP_MAX_WINDOW_SCALE);
                                    tcb.wscale_received = true;
                                    // Calculate our scale factor for outgoing window advertisements
                                    tcb.rcv_wscale = calc_wscale(tcb.rcv_wnd);
                                    tcb.wscale_requested = true;
                                }

                                // RFC 2018: SACK negotiation — record peer's SACK-Permitted
                                // and advertise our own capability in the SYN-ACK.
                                if options.sack_permitted {
                                    tcb.sack_received = true;
                                }
                                tcb.sack_requested = true;

                                if child.attach_tcp(tcb).is_err() {
                                    return None;
                                }

                                // R58: Calculate window for SYN-ACK (unscaled per RFC 7323)
                                // RFC 7323 Section 2.2: The window field in SYN and SYN-ACK
                                // segments is never scaled; scaling takes effect only after
                                // the SYN exchange is complete.
                                let syn_ack_wnd = {
                                    let guard = child.tcp.lock();
                                    if let Some(ts) = guard.as_ref() {
                                        encode_window(ts.control.rcv_wnd, 0, true)
                                    } else {
                                        TCP_DEFAULT_WINDOW
                                    }
                                };

                                // Build SYN-ACK segment with MSS, SACK-Permitted, and optional WSopt
                                // RFC 793: SYN consumes 1 sequence number
                                if self.passive_syn_ack_build_faulted() {
                                    return None;
                                }
                                let syn_ack = if options.window_scale.is_some() {
                                    // Include MSS, WSopt, and SACK-Permitted in response
                                    let our_scale = {
                                        let guard = child.tcp.lock();
                                        guard.as_ref().map(|ts| ts.control.rcv_wscale).unwrap_or(0)
                                    };
                                    let syn_ack_options = [
                                        TcpOptionKind::Mss(cookie_mss),
                                        TcpOptionKind::WindowScale(our_scale),
                                        TcpOptionKind::SackPermitted,
                                    ];
                                    try_build_tcp_segment_with_options(
                                        dst_ip,
                                        src_ip,
                                        header.dst_port,
                                        header.src_port,
                                        iss,
                                        header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                                        syn_ack_wnd,
                                        &syn_ack_options,
                                        &[],
                                    )
                                } else {
                                    // Include MSS and SACK-Permitted
                                    let syn_ack_options = [
                                        TcpOptionKind::Mss(cookie_mss),
                                        TcpOptionKind::SackPermitted,
                                    ];
                                    try_build_tcp_segment_with_options(
                                        dst_ip,
                                        src_ip,
                                        header.dst_port,
                                        header.src_port,
                                        iss,
                                        header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                                        syn_ack_wnd,
                                        &syn_ack_options,
                                        &[],
                                    )
                                };
                                // RF180-7 FIX: a passive child must not become
                                // observable unless its initial and cached SYN-ACK
                                // are both complete. In particular, option
                                // serialization OOM cannot publish a TCB that claims
                                // window-scale/SACK state absent from the wire.
                                let syn_ack = match syn_ack {
                                    Ok(segment) => segment,
                                    Err(_) => return None,
                                };

                                // Register connection for demux.
                                // J2-1: charge the per-namespace connection budget bound
                                // to this tcp_conns insertion. If the tenant is already at
                                // its connection cap, skip the insert + SYN queue and fall
                                // back to stateless SYN cookies (handled below), exactly
                                // like the global half-open / queue_syn failure path.
                                let cached_syn_ack = match WirePacket::try_copy_from_slice(&syn_ack)
                                {
                                    Ok(cached) => cached,
                                    Err(_) => return None,
                                };

                                let token = match next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN) {
                                    Ok(token) => token,
                                    Err(_) => return None,
                                };
                                {
                                    let mut child_tcp = child.tcp.lock();
                                    let Some(child_state) = child_tcp.as_mut() else {
                                        return None;
                                    };
                                    child_state.control.pending_reply_token = Some(token);
                                }
                                let binding_owner = child.clone();
                                let published = self.try_publish_pending_syn_child(
                                    listen_state,
                                    syn_key,
                                    child,
                                    cached_syn_ack,
                                    now_ms,
                                );

                                if published {
                                    self.created.fetch_add(1, Ordering::Relaxed);
                                    // RF180-41 REVIEW FIX: child publication records
                                    // the accepted ingress SYN, not an unsent SYN-ACK.
                                    // Conntrack transition is deferred to device queue.
                                    *reply_binding =
                                        Some(self.bind_tcp_reply(&binding_owner, token));
                                    return Some(syn_ack);
                                }

                                // Publication/admission failed without leaving a live ID,
                                // counter, or registry entry. Fall back statelessly.

                                // Fall back to stateless SYN cookie SYN-ACK
                                // R137-2 FIX: Rate limit fallback SYN-cookie path as well.
                                if !allow_syn_cookie_ack(now_ms) {
                                    return None;
                                }
                                let cookie_iss = generate_syn_cookie_isn(
                                    now_ms,
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                    mss_index,
                                );
                                let syn_ack_options = [TcpOptionKind::Mss(cookie_mss)];
                                if self.passive_syn_ack_build_faulted() {
                                    return None;
                                }
                                let cookie_syn_ack = match try_build_tcp_segment_with_options(
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    cookie_iss,
                                    header.seq_num.wrapping_add(1),
                                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                                    TCP_DEFAULT_WINDOW,
                                    &syn_ack_options,
                                    &[],
                                ) {
                                    Ok(segment) => segment,
                                    Err(_) => return None,
                                };
                                // R132-5 FIX: count only successfully built cookie replies.
                                SYN_COOKIES_GENERATED.fetch_add(1, Ordering::Relaxed);
                                // RF180-41 REVIEW FIX: the fallback cookie remains
                                // stateless until its admitted reply is queued.
                                return Some(cookie_syn_ack);
                            }
                        }
                    }

                    // SYN Cookie Validation Path: If this is an ACK with no half-open
                    // connection, it might be completing a SYN cookie handshake
                    let is_ack = header.flags & TCP_FLAG_ACK != 0;
                    let is_syn = header.flags & TCP_FLAG_SYN != 0;

                    if is_ack && !is_syn {
                        // R75-1 FIX: Look up listener within the specified namespace
                        if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port)
                        {
                            let now_ms = self.time_wait_now();

                            // The cookie ISN is (ACK number - 1) since we sent SYN-ACK with ISN,
                            // and client ACK should acknowledge ISN+1
                            let cookie_isn = header.ack_num.wrapping_sub(1);

                            if let Some(cookie_data) = validate_syn_cookie(
                                now_ms,
                                cookie_isn,
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                            ) {
                                SYN_COOKIES_VALIDATED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX
                                                                                       // Security: Final ACK must exactly acknowledge our SYN (ISS + 1)
                                                                                       // This prevents attacks with forged ACK numbers that could
                                                                                       // corrupt send-window accounting
                                if header.ack_num != cookie_data.iss.wrapping_add(1) {
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                }

                                // Security: SYN-cookie completion must be a pure ACK (no data)
                                // Accepting data here would silently drop or misorder it
                                // and increase attack surface for injection attacks
                                if !payload.is_empty() {
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                }

                                // Valid SYN cookie - create connection
                                let syn_key = tcp_map_key_from_parts(
                                    listener.net_ns_id,
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                );

                                // P0-2 FIX: Check limits before creating connection.
                                // When at capacity, attempt TIME_WAIT eviction so that
                                // validated SYN cookie completions are not silently
                                // dropped under sustained load.
                                {
                                    let mut conns = self.tcp_conns.lock();
                                    self.conns_retain_accounted(&mut conns);
                                    // Check for duplicate first (race condition guard)
                                    if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                        return None;
                                    }
                                    if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                        // Release lock — try_evict needs it internally.
                                        drop(conns);
                                        if !self.try_evict_time_wait_for_cookie(now_ms) {
                                            // Genuinely no capacity even after eviction.
                                            return None;
                                        }
                                        // Re-check under fresh lock: another core may have
                                        // consumed the freed slot or inserted a duplicate.
                                        let mut conns = self.tcp_conns.lock();
                                        self.conns_retain_accounted(&mut conns);
                                        if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                            return None;
                                        }
                                        if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                            return None;
                                        }
                                    }
                                }

                                // Check accept queue capacity
                                {
                                    let mut listen_guard = listener.listen.lock();
                                    if let Some(listen_state) = listen_guard.as_mut() {
                                        if listen_state.accept_queue.len()
                                            >= listen_state.accept_backlog
                                        {
                                            // Accept queue full - send RST
                                            return self
                                                .build_tcp_rst(dst_ip, src_ip, header, payload);
                                        }
                                        if listen_state.accept_queue.ensure_capacity_for(1).is_err()
                                        {
                                            return self
                                                .build_tcp_rst(dst_ip, src_ip, header, payload);
                                        }
                                    }
                                }

                                // R180-11 FIX: as in the stateful SYN path, construct a
                                // private ID-0 child. The transaction helper assigns the real
                                // ID only after all TCB/waiter/map backing is prepared.
                                let child = match SocketState::try_new_arc(
                                    0,
                                    listener.domain,
                                    listener.ty,
                                    listener.proto,
                                    listener.label,
                                    listener.net_ns_id,
                                ) {
                                    Ok(child) => child,
                                    Err(_) => {
                                        return self.build_tcp_rst(dst_ip, src_ip, header, payload)
                                    }
                                };

                                child.bind_local(dst_ip, header.dst_port);
                                child.set_remote(src_ip, header.src_port);

                                // Create TCB in Established state (handshake completed via cookie)
                                // The IRS (Initial Receive Sequence) was header.seq_num in the original SYN
                                // which is now header.seq_num - 1 (they sent +1 in their ACK)
                                let irs = header.seq_num.wrapping_sub(1);
                                let mut tcb = TcpControlBlock::new_server(
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                    cookie_data.iss,
                                    irs,
                                );

                                // R151-8 FIX: SYN cookie connections do not negotiate window
                                // scaling. Cap rcv_wnd to what can be advertised in the 16-bit
                                // TCP window field without WSopt. Without this cap, the stack
                                // accepts up to 256 KiB per connection while only advertising
                                // 64 KiB, enabling 4x memory amplification under SYN flood.
                                if !tcb.wscale_enabled() {
                                    tcb.rcv_wnd = tcb.rcv_wnd.min(u16::MAX as u32);
                                }

                                // Set MSS from cookie
                                tcb.snd_mss = cookie_data.mss;
                                tcb.rcv_mss = cookie_data.mss;
                                tcb.cwnd = initial_cwnd(cookie_data.mss);

                                // Update sequence numbers: our SYN consumed 1 byte
                                tcb.snd_nxt = cookie_data.iss.wrapping_add(1);
                                tcb.snd_una = cookie_data.iss;

                                // Initialize send window from their ACK
                                // Note: No window scaling for SYN cookie connections
                                tcb.snd_wnd = decode_window(header.window, 0);
                                tcb.snd_wl1 = header.seq_num;
                                tcb.snd_wl2 = header.ack_num;

                                // Transition directly to Established (cookie validated)
                                tcb.state = TcpState::Established;
                                tcb.established_at = now_ms;
                                tcb.last_activity = now_ms;

                                // Process the ACK to update snd_una
                                handle_ack(&mut tcb, header.ack_num, now_ms);

                                if child.attach_tcp(tcb).is_err() {
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                }

                                if !self.try_publish_cookie_child(&listener, syn_key, child) {
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                }
                                self.created.fetch_add(1, Ordering::Relaxed);
                                return None;
                            } else {
                                SYN_COOKIES_REJECTED.fetch_add(1, Ordering::Relaxed);
                                // R132-5 FIX
                            }
                        }
                    }

                    // No connection found - send RST per RFC 793
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }
            };

        // Process based on current TCP state
        let mut guard = sock.tcp.lock();
        let tcp_state = match guard.as_mut() {
            Some(s) => s,
            None => {
                // Socket has no TCP state (shouldn't happen for TCP sockets)
                drop(guard);
                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
            }
        };

        match tcp_state.control.state {
            TcpState::SynSent => {
                // Expecting SYN-ACK to complete active open
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                // RFC 793: In SYN-SENT, must receive SYN+ACK (normal 3-way handshake)
                // or SYN without ACK (simultaneous open).
                if !is_ack {
                    if is_syn {
                        // R148-I2 FIX: RFC 793 simultaneous open.
                        // Both endpoints independently sent SYN to each other.
                        // Accept the remote's SYN, transition to SYN-RECEIVED,
                        // and respond with SYN+ACK (our original ISS + ACK their SYN).
                        // RF180-7 FIX: stage every peer-derived TCB field privately.
                        // The option-bearing SYN-ACK allocation is still fallible;
                        // no handshake state may become durable until that packet is
                        // complete, otherwise a later normal SYN-ACK can inherit stale
                        // SACK/window-scale/MSS negotiation from a reply never sent.
                        let peer_irs = header.seq_num;
                        let peer_rcv_nxt = header.seq_num.wrapping_add(1);
                        let peer_snd_wscale = tcp_state
                            .control
                            .wscale_requested
                            .then(|| {
                                options
                                    .window_scale
                                    .map(|scale| scale.min(TCP_MAX_WINDOW_SCALE))
                            })
                            .flatten();
                        let peer_sack_received =
                            tcp_state.control.sack_requested && options.sack_permitted;
                        // R150-2 FIX: Process peer MSS from bare SYN (simultaneous open).
                        // Without this, snd_mss stays at TCP_DEFAULT_MSS (536) →
                        // initial_cwnd = 536 × 10 = 5360 instead of 1460 × 10 = 14600.
                        let (peer_snd_mss, peer_cwnd) = match options.mss {
                            Some(mss) => {
                                let clamped = mss.max(64).min(TCP_ETHERNET_MSS);
                                (clamped, initial_cwnd(clamped))
                            }
                            None => (tcp_state.control.snd_mss, tcp_state.control.cwnd),
                        };
                        // SYN/SYN-ACK windows are unscaled per RFC 7323 §2.2.
                        let peer_snd_wnd = decode_window(header.window, 0);

                        // Build SYN+ACK: retransmit our SYN (snd_una = ISS) + ACK their SYN
                        // R163-10 FIX: Replace infallible alloc::vec![...] + push() opts
                        // construction with a bounded stack array. There are at most 3
                        // options (MSS, WindowScale, SackPermitted); we populate a
                        // fixed-size array and slice it to the actual count used.
                        let wscale_opt = tcp_state
                            .control
                            .wscale_requested
                            .then(|| TcpOptionKind::WindowScale(tcp_state.control.rcv_wscale));
                        let sack_opt = tcp_state
                            .control
                            .sack_requested
                            .then(|| TcpOptionKind::SackPermitted);
                        if self.simultaneous_syn_ack_build_faulted() {
                            return None;
                        }
                        let syn_ack = match (wscale_opt, sack_opt) {
                            (Some(ws), Some(_sack)) => try_build_tcp_segment_with_options(
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                tcp_state.control.snd_una,
                                peer_rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK,
                                TCP_DEFAULT_WINDOW,
                                &[
                                    TcpOptionKind::Mss(TCP_ETHERNET_MSS),
                                    ws,
                                    TcpOptionKind::SackPermitted,
                                ],
                                &[],
                            ),
                            (Some(ws), None) => try_build_tcp_segment_with_options(
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                tcp_state.control.snd_una,
                                peer_rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK,
                                TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS), ws],
                                &[],
                            ),
                            (None, Some(_sack)) => try_build_tcp_segment_with_options(
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                tcp_state.control.snd_una,
                                peer_rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK,
                                TCP_DEFAULT_WINDOW,
                                &[
                                    TcpOptionKind::Mss(TCP_ETHERNET_MSS),
                                    TcpOptionKind::SackPermitted,
                                ],
                                &[],
                            ),
                            (None, None) => try_build_tcp_segment_with_options(
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                tcp_state.control.snd_una,
                                peer_rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK,
                                TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS)],
                                &[],
                            ),
                        };
                        // RF180-7 FIX: keep the complete active-open TCB unchanged
                        // if the simultaneous-open SYN-ACK cannot be prepared.
                        let syn_ack = match syn_ack {
                            Ok(segment) => segment,
                            Err(_) => return None,
                        };
                        let token = match next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN) {
                            Ok(token) => token,
                            Err(_) => return None,
                        };
                        // RF180-41 REVIEW FIX: keep SYN-SENT externally visible
                        // until this exact SYN-ACK reaches the device queue. A
                        // policy/QueueFull failure leaves the peer's retransmitted
                        // SYN able to replace this provisional snapshot.
                        let control = &mut tcp_state.control;
                        control.pending_reply_token = Some(token);
                        control.pending_handshake = Some(PendingHandshakeCommit {
                            response_flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                            response_seq: control.snd_una,
                            response_ack: peer_rcv_nxt,
                            target_state: TcpState::SynReceived,
                            irs: peer_irs,
                            rcv_nxt: peer_rcv_nxt,
                            ack_to_apply: None,
                            snd_wscale: peer_snd_wscale.unwrap_or(0),
                            wscale_received: peer_snd_wscale.is_some(),
                            sack_received: peer_sack_received,
                            snd_mss: peer_snd_mss,
                            cwnd: peer_cwnd,
                            snd_wnd: peer_snd_wnd,
                            snd_wl1: peer_irs,
                            snd_wl2: None,
                            rcv_wnd: control.rcv_wnd,
                            wake_connect: false,
                        });

                        *reply_binding = Some(self.bind_tcp_reply(&sock, token));
                        drop(guard);
                        return Some(syn_ack);
                    }
                    // Non-SYN without ACK in SYN-SENT — ignore
                    return None;
                }

                if !is_syn {
                    // ACK without SYN in SYN-SENT is invalid per RFC 793
                    // Send RST and abort connection
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    sock.wake_tcp_waiters();
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Validate ACK number: must acknowledge our SYN (ISS + 1)
                let expected_ack = tcp_state.control.snd_nxt;
                if header.ack_num != expected_ack {
                    // Invalid ACK - send RST and abort connection
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    sock.wake_tcp_waiters();
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // RF180-41 REVIEW FIX: prepare the mandatory third-handshake ACK
                // before mutating negotiation, ACK, or connection state. If
                // aggregate admission is exhausted, leave the complete SYN-SENT
                // transaction retryable for the peer's retransmitted SYN-ACK.
                let peer_rcv_nxt = header.seq_num.wrapping_add(1);
                let wscale_will_be_enabled =
                    tcp_state.control.wscale_requested && options.window_scale.is_some();
                let prospective_rcv_wnd = if wscale_will_be_enabled {
                    tcp_state.control.rcv_wnd
                } else {
                    tcp_state.control.rcv_wnd.min(u16::MAX as u32)
                };
                let consumed = (tcp_state.control.recv_buffer.len() as u32)
                    .saturating_add(tcp_state.control.ooo_bytes);
                let available = prospective_rcv_wnd.saturating_sub(consumed);
                let rcv_scale = if wscale_will_be_enabled {
                    tcp_state.control.rcv_wscale
                } else {
                    0
                };
                let handshake_adv_wnd = encode_window(available, rcv_scale, true);
                let ack_segment = match try_build_tcp_segment_admitted(
                    dst_ip,
                    src_ip,
                    header.dst_port,
                    header.src_port,
                    tcp_state.control.snd_nxt,
                    peer_rcv_nxt,
                    TCP_FLAG_ACK,
                    handshake_adv_wnd,
                    &[],
                ) {
                    Ok(segment) => segment,
                    Err(_) => return None,
                };

                let peer_snd_wscale = if tcp_state.control.wscale_requested {
                    options
                        .window_scale
                        .map(|scale| scale.min(TCP_MAX_WINDOW_SCALE))
                } else {
                    None
                };
                let peer_sack_received = tcp_state.control.sack_requested && options.sack_permitted;
                let (peer_snd_mss, peer_cwnd) = match options.mss {
                    Some(mss) => {
                        let clamped = mss.max(64).min(TCP_ETHERNET_MSS);
                        (clamped, initial_cwnd(clamped))
                    }
                    None => (tcp_state.control.snd_mss, tcp_state.control.cwnd),
                };

                // Accept the remote's ISN and transition to ESTABLISHED
                // R51-3 FIX: Ignore SYN-ACK payload (not buffered, breaks integrity)
                // RFC 793: SYN consumes 1 sequence number only.
                // TCP Fast Open (RFC 7413) would require explicit negotiation and
                // buffering of early data before ACKing, which we don't support.
                let ack_observed_at = self.time_wait_now();

                // R58: RFC 7323 Window Scaling - process WSopt from SYN-ACK
                // Window scaling is ONLY negotiated if we sent WSopt in our SYN
                // AND the peer includes WSopt in their SYN-ACK.
                // Negotiation is staged below and becomes visible at queue commit.

                // RFC 2018: SACK negotiation — record peer's SACK capability.
                // SACK is active only when both sides exchanged SACK-Permitted
                // during the SYN/SYN-ACK handshake.
                // SACK negotiation is likewise provisional until queue commit.
                // R150-2 FIX: Process peer MSS from SYN-ACK. Without this,
                // snd_mss stays at TCP_DEFAULT_MSS (536) for ALL connect()-initiated
                // connections → initial_cwnd = 536 × 10 = 5360 bytes instead of
                // 1460 × 10 = 14600 bytes, throttling throughput ~60% in slow-start.
                // MSS/cwnd negotiation is staged in the pending snapshot.

                // Initialize send window from SYN-ACK (window field is never scaled on SYNs)
                // RFC 7323 Section 2.2: Scaling takes effect only after SYN exchange completes
                let peer_snd_wnd = decode_window(
                    header.window,
                    0, // RFC 7323: SYN/SYN-ACK window is unscaled
                );

                let token = match next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN) {
                    Ok(token) => token,
                    Err(_) => return None,
                };

                // R58 FIX: RFC 793 semantics - if window scaling was not negotiated,
                // cap receive window to 16 bits to avoid accepting more data than
                // we can advertise without scaling. This ensures sequence/window
                // checks remain consistent with advertised window.
                tcp_state.control.pending_reply_token = Some(token);
                tcp_state.control.pending_handshake = Some(PendingHandshakeCommit {
                    response_flags: TCP_FLAG_ACK,
                    response_seq: tcp_state.control.snd_nxt,
                    response_ack: peer_rcv_nxt,
                    target_state: TcpState::Established,
                    irs: header.seq_num,
                    rcv_nxt: peer_rcv_nxt,
                    ack_to_apply: Some((header.ack_num, ack_observed_at)),
                    snd_wscale: peer_snd_wscale.unwrap_or(0),
                    wscale_received: peer_snd_wscale.is_some(),
                    sack_received: peer_sack_received,
                    snd_mss: peer_snd_mss,
                    cwnd: peer_cwnd,
                    snd_wnd: peer_snd_wnd,
                    snd_wl1: header.seq_num,
                    snd_wl2: Some(header.ack_num),
                    rcv_wnd: prospective_rcv_wnd,
                    wake_connect: true,
                });

                // Wake is deferred until transmit_prepared_reply commits.
                *reply_binding = Some(self.bind_tcp_reply(&sock, token));
                drop(guard);

                Some(ack_segment)
            }

            TcpState::Established => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                // RFC 793: in synchronized states, segments must carry ACK
                if !is_ack {
                    return None;
                }

                // R58: Calculate scaled advertised receive window
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                // R50-2 FIX: Validate ACK with wraparound-safe sequence comparisons
                // ACK must be: snd_una <= ack_num <= snd_nxt
                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                // R50-2 FIX: Validate segment sequence number is within receive window
                // This prevents blind data injection attacks
                //
                // R178-L6 / RF178-30 FIX: Partial-left-overlap data must reach
                // the trimming logic below.
                let seq_in_recv_window = segment_in_recv_window(
                    header.seq_num,
                    payload.len(),
                    is_fin,
                    tcp_state.control.rcv_nxt,
                    tcp_state.control.rcv_wnd,
                );

                // If sequence is completely outside receive window, send challenge ACK
                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                if ack_in_range {
                    // RFC 2018 / RFC 6675: Extract SACK blocks from incoming segment
                    // for sender scoreboard processing and loss-based retransmission.
                    let sack_blocks = if tcp_state.control.sack_enabled() {
                        options.sack_blocks.as_slice()
                    } else {
                        &[]
                    };

                    // Combined ACK processing + SACK scoreboard + congestion control.
                    // TCB -> conntrack -> device is the one-way egress lock
                    // order. Keeping this TCB guard across the bounded queue
                    // call makes retransmission metadata publication atomic.
                    let (_retransmit_queued, limited_transmit) = self.apply_ack_and_cc(
                        &mut tcp_state.control,
                        header.ack_num,
                        advertised_wnd,
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        self.time_wait_now(),
                        sack_blocks,
                        !payload.is_empty(),
                        header.window,
                        |segment| transmit_tcp_segment(src_ip, segment, sock.net_ns_id.0).is_ok(),
                    );

                    // J2-6: apply_ack_and_cc ran handle_ack internally (freeing acked
                    // send bytes); reconcile the per-namespace send counter here at
                    // the caller, which holds `sock` — keeping apply_ack_and_cc's
                    // signature free of net_ns_id (no change to the hot CC path).
                    self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);

                    // R56-1: RFC 3042 Limited Transmit — wake sender to push new data
                    if limited_transmit {
                        sock.wake_tcp_waiters();
                    }

                    // R58: Decode peer's advertised window and update send window
                    let peer_adv_wnd =
                        decode_window(header.window, tcp_state.control.effective_snd_wscale());

                    // R50-2 FIX: Use seq_gt/seq_ge for wraparound-safe window update (RFC 793)
                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        tcp_state.control.snd_wnd = peer_adv_wnd;
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    // Unacceptable ACK: send duplicate ACK without aborting (RFC 793)
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                let mut data_received = false;
                // R155-15 FIX: Track whether OOO drain delivered a buffered FIN,
                // so that state waiters are also woken (not just data waiters).
                let mut ooo_fin_delivered = false;
                let mut response: Option<WirePacket> = None;
                // R144-1 FIX: Save rcv_nxt AFTER in-order data but BEFORE OOO drain.
                //
                // When a segment carries both data and FIN, rcv_nxt advances by
                // payload.len() for the data, then ooo_drain_contiguous() may
                // advance it further for contiguous OOO segments.  The FIN check
                // below compares header.seq_num + payload.len() against rcv_nxt,
                // which must reflect the position immediately after the in-order
                // data (the FIN position) -- not the post-drain position.
                // Without this fix, the FIN is silently lost and the connection
                // stays in Established state indefinitely (TCB leak).
                let mut fin_expected_seq: Option<u32> = None;

                // Process incoming data if present
                if !payload.is_empty() {
                    // Recalculate window after ACK processing (includes OOO bytes)
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    // LSM check before buffering data
                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        // LSM denied - silently drop
                        return None;
                    }

                    // Check if segment is in-order (seq == rcv_nxt)
                    if header.seq_num == tcp_state.control.rcv_nxt {
                        // In-order: buffer directly into receive buffer
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            // Would overrun advertised window — send ACK with current window
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R180-11 FIX: admitted detached growth, then
                        // allocation-free publication into the live TCB.
                        if tcp_state
                            .control
                            .recv_buffer
                            .try_extend_from_slice(payload)
                            .is_err()
                        {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            return None;
                        }
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);

                        // R144-1 FIX: Snapshot rcv_nxt before OOO drain so the FIN
                        // check uses the correct expected sequence.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);

                        // R144-1 FIX: Skip OOO drain when the current segment carries
                        // FIN.  The FIN handler below will clear the OOO queue (no data
                        // is valid after FIN).  If we drained here, OOO data starting at
                        // the FIN position would be appended to recv_buffer before FIN
                        // acceptance, enabling post-FIN data injection.
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();

                            // R155-15 FIX: OOO drain may deliver a buffered FIN,
                            // triggering state transitions inside tcp.rs (e.g.
                            // Established→CloseWait) without socket-layer side
                            // effects.  If fin_received became true, ensure recv
                            // waiters are woken for EOF delivery.
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                            }
                        }

                        // Build ACK (plain — no SACK blocks needed for in-order data
                        // with empty OOO queue; includes SACK if OOO queue is non-empty)
                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // Out-of-order: buffer in OOO queue and send SACK-bearing ACK
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state
                            .control
                            .ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Per RFC 793, accept in-window portion of partial
                        // retransmission overlaps (seq < rcv_nxt, seq+len > rcv_nxt).
                        // R162-6-1/6-2 FIX: Pass FIN flag when FIN position is at seg_end,
                        // and handle OOO-drain state transitions (wake waiters, set timers).
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip =
                                tcp_state.control.rcv_nxt.wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(
                                    sock.net_ns_id,
                                    &tcp_state.control,
                                    useful.len(),
                                )
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt,
                                useful,
                                pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        // R180-L2 FIX: payload ending exactly at RCV.NXT is fully
                        // duplicate, but a FIN at that position is new sequence
                        // space.  Fall through to the state-specific FIN handler;
                        // every other fully-duplicate segment remains a dup-ACK.
                        if !duplicate_payload_has_new_fin(
                            header.seq_num,
                            payload.len(),
                            is_fin,
                            tcp_state.control.rcv_nxt,
                        ) {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let dup_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(dup_ack);
                        }
                    }
                }

                // RFC 793: Handle FIN flag - peer wants to close
                if is_fin {
                    // R144-1 FIX: Use the pre-OOO-drain rcv_nxt (if available) so that
                    // contiguous OOO segments drained after the in-order data do not
                    // push rcv_nxt past the FIN position, silently losing FIN.
                    let expected_fin_pos = fin_expected_seq.unwrap_or(tcp_state.control.rcv_nxt);
                    // FIN must be in-order (seq_num + payload_len == expected position)
                    if header.seq_num.wrapping_add(payload.len() as u32) != expected_fin_pos {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: FIN consumes 1 sequence number.
                    // Set rcv_nxt to expected_fin_pos + 1, since the OOO drain may
                    // have already advanced rcv_nxt past the FIN position.  Data
                    // delivered by OOO drain that was beyond the FIN is invalid
                    // (no legitimate data can follow FIN in the same direction);
                    // clearing the OOO queue below prevents further delivery.
                    tcp_state.control.rcv_nxt = expected_fin_pos.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: No data is valid after FIN.  Drop any buffered
                    // OOO segments to prevent delivering data past FIN and to free
                    // memory sooner.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    // Transition to CLOSE_WAIT (passive close)
                    tcp_state.control.state = TcpState::CloseWait;

                    drop(guard);
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(data_ack) = response {
                    drop(guard);

                    if data_received {
                        // Wake any threads blocked in tcp_recv()
                        sock.wake_tcp_data_waiters();
                    }

                    // R155-15 FIX: OOO drain delivered a buffered FIN, which
                    // transitioned the state (e.g. Established→CloseWait)
                    // inside tcp.rs.  Wake state waiters so close/shutdown
                    // paths see the transition, and ensure data waiters are
                    // woken for EOF even if data_received was not set.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }

                    return Some(data_ack);
                }

                // Pure ACK with no data - nothing more to do
                None
            }

            // ================================================================
            // FIN-WAIT-1: We sent FIN, waiting for ACK and/or peer's FIN
            // ================================================================
            TcpState::FinWait1 => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let seq_in_recv_window = segment_in_recv_window(
                    header.seq_num,
                    payload.len(),
                    is_fin,
                    tcp_state.control.rcv_nxt,
                    tcp_state.control.rcv_wnd,
                );

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(
                        &sock,
                        &mut tcp_state.control,
                        header.ack_num,
                        self.time_wait_now(),
                    );

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in closing states,
                // so retransmit timer selects the right segment if data remains.
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                // Check if our FIN was ACKed
                let acked_fin = seq_ge(header.ack_num, tcp_state.control.snd_nxt);
                if acked_fin {
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::FinWait2;
                    // R65-5 FIX: Start FIN_WAIT_2 idle timeout timer
                    tcp_state.control.fin_wait2_start = self.time_wait_now();
                }

                let mut data_received = false;
                // R155-15 FIX: Track OOO-drain-delivered FIN for wake side effects.
                let mut ooo_fin_delivered = false;
                let mut response: Option<WirePacket> = None;
                // R144-1 FIX: See Established-state comment for rationale.
                let mut fin_expected_seq: Option<u32> = None;

                // Process incoming data (we can still receive in FIN_WAIT_1)
                if !payload.is_empty() {
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    if header.seq_num == tcp_state.control.rcv_nxt {
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R180-11 FIX: reserve allocator capacity before retain.
                        if tcp_state
                            .control
                            .recv_buffer
                            .try_extend_from_slice(payload)
                            .is_err()
                        {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            return None;
                        }
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);
                        // R144-1 FIX: Snapshot before OOO drain; skip drain if FIN.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();
                            // R155-15 FIX: OOO drain may deliver buffered FIN.
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                                // R161-11 FIX: OOO drain may transition FinWait2→TimeWait
                                // (when FIN ACK above moved us to FinWait2 first).
                                // Set time_wait_start immediately.
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                            }
                        }

                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state
                            .control
                            .ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Accept in-window portion of partial overlap.
                        // R162-6-1/6-2 FIX: Pass FIN and handle OOO-drain transitions.
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip =
                                tcp_state.control.rcv_nxt.wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(
                                    sock.net_ns_id,
                                    &tcp_state.control,
                                    useful.len(),
                                )
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt,
                                useful,
                                pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        // R180-L2 FIX: consume an in-order FIN independently of
                        // whether any retransmitted payload byte was new.
                        if !duplicate_payload_has_new_fin(
                            header.seq_num,
                            payload.len(),
                            is_fin,
                            tcp_state.control.rcv_nxt,
                        ) {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let dup_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(dup_ack);
                        }
                    }
                }

                // Handle peer's FIN
                if is_fin {
                    // R144-1 FIX: Use pre-OOO-drain rcv_nxt.
                    let expected_fin_seq = fin_expected_seq.unwrap_or(tcp_state.control.rcv_nxt);
                    if header.seq_num.wrapping_add(payload.len() as u32) != expected_fin_seq {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: Set rcv_nxt to the FIN position + 1.
                    tcp_state.control.rcv_nxt = expected_fin_seq.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: Clear OOO queue — no data valid past FIN.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // If our FIN was ACKed: FIN_WAIT_1 + FIN → TIME_WAIT
                    // If not ACKed: FIN_WAIT_1 + FIN → CLOSING (simultaneous close)
                    if acked_fin {
                        // Record TIME_WAIT start for 2MSL timer
                        tcp_state.control.time_wait_start = self.time_wait_now();
                        // FIN ACKed - clear retransmission timer
                        tcp_state.control.fin_sent_time = 0;
                        tcp_state.control.fin_retries = 0;
                    }
                    tcp_state.control.state = if acked_fin {
                        TcpState::TimeWait
                    } else {
                        TcpState::Closing
                    };

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);

                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(resp) = response {
                    drop(guard);
                    if data_received {
                        sock.wake_tcp_data_waiters();
                    }
                    // R155-15 FIX: OOO drain delivered buffered FIN — wake
                    // both data and state waiters for EOF and state transition.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }
                    if acked_fin {
                        sock.wake_tcp_waiters();
                    }
                    return Some(resp);
                }

                if acked_fin {
                    drop(guard);
                    sock.wake_tcp_waiters();
                }

                None
            }

            // ================================================================
            // FIN-WAIT-2: Our FIN was ACKed, waiting for peer's FIN
            // ================================================================
            TcpState::FinWait2 => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let seq_in_recv_window = segment_in_recv_window(
                    header.seq_num,
                    payload.len(),
                    is_fin,
                    tcp_state.control.rcv_nxt,
                    tcp_state.control.rcv_wnd,
                );

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(
                        &sock,
                        &mut tcp_state.control,
                        header.ack_num,
                        self.time_wait_now(),
                    );

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in FIN_WAIT_2.
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                let mut data_received = false;
                // R155-15 FIX: Track OOO-drain-delivered FIN for wake side effects.
                let mut ooo_fin_delivered = false;
                let mut response: Option<WirePacket> = None;
                // R144-1 FIX: See Established-state comment for rationale.
                let mut fin_expected_seq: Option<u32> = None;

                // We can still receive data in FIN_WAIT_2
                if !payload.is_empty() {
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    if header.seq_num == tcp_state.control.rcv_nxt {
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R180-11 FIX: reserve allocator capacity before retain.
                        if tcp_state
                            .control
                            .recv_buffer
                            .try_extend_from_slice(payload)
                            .is_err()
                        {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            return None;
                        }
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);
                        // R144-1 FIX: Snapshot before OOO drain; skip drain if FIN.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();
                            // R155-15 FIX: OOO drain may deliver buffered FIN
                            // (FinWait2→TimeWait transition inside tcp.rs).
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                                // R161-11 FIX: Set time_wait_start immediately on
                                // OOO-drain-triggered FinWait2→TimeWait transition.
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                            }
                        }

                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state
                            .control
                            .ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Accept in-window portion of partial overlap.
                        // R162-6-1/6-2 FIX: Pass FIN and handle OOO-drain transitions.
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip =
                                tcp_state.control.rcv_nxt.wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(
                                    sock.net_ns_id,
                                    &tcp_state.control,
                                    useful.len(),
                                )
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt,
                                useful,
                                pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        // R180-L2 FIX: consume an in-order FIN independently of
                        // whether any retransmitted payload byte was new.
                        if !duplicate_payload_has_new_fin(
                            header.seq_num,
                            payload.len(),
                            is_fin,
                            tcp_state.control.rcv_nxt,
                        ) {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let dup_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            );
                            return Some(dup_ack);
                        }
                    }
                }

                // Handle peer's FIN
                if is_fin {
                    // R144-1 FIX: Use pre-OOO-drain rcv_nxt.
                    let expected_fin_seq = fin_expected_seq.unwrap_or(tcp_state.control.rcv_nxt);
                    if header.seq_num.wrapping_add(payload.len() as u32) != expected_fin_seq {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: Set rcv_nxt to FIN position + 1.
                    tcp_state.control.rcv_nxt = expected_fin_seq.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: Clear OOO queue — no data valid past FIN.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    // FIN_WAIT_2 + FIN → TIME_WAIT
                    tcp_state.control.time_wait_start = self.time_wait_now();
                    tcp_state.control.state = TcpState::TimeWait;

                    drop(guard);
                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(resp) = response {
                    drop(guard);
                    if data_received {
                        sock.wake_tcp_data_waiters();
                    }
                    // R155-15 FIX: OOO drain delivered buffered FIN
                    // (FinWait2→TimeWait) — wake both waiters for EOF
                    // and state-transition side effects.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }
                    return Some(resp);
                }

                None
            }

            // ================================================================
            // CLOSE-WAIT: Peer sent FIN, waiting for local close
            // ================================================================
            TcpState::CloseWait => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(
                        &sock,
                        &mut tcp_state.control,
                        header.ack_num,
                        self.time_wait_now(),
                    );

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in CLOSE_WAIT.
                // Data may still be sent in this state (application has not closed yet).
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                // In CLOSE_WAIT, we don't expect more data but still ACK segments
                if !payload.is_empty() || (header.flags & TCP_FLAG_FIN != 0) {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let ack_seg = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);
                    return Some(ack_seg);
                }

                None
            }

            // ================================================================
            // CLOSING: Simultaneous close, waiting for ACK of our FIN
            // ================================================================
            TcpState::Closing => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(
                        &sock,
                        &mut tcp_state.control,
                        header.ack_num,
                        self.time_wait_now(),
                    );

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // Handle retransmitted FIN from peer
                let mut fin_ack = None;
                if header.flags & TCP_FLAG_FIN != 0 {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Re-ACK the FIN
                    fin_ack = Some(build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    ));
                }

                // Check if our FIN was ACKed
                if seq_ge(header.ack_num, tcp_state.control.snd_nxt) {
                    // CLOSING + ACK of FIN → TIME_WAIT
                    tcp_state.control.time_wait_start = self.time_wait_now();
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::TimeWait;
                    drop(guard);
                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();
                    return fin_ack;
                }

                if let Some(seg) = fin_ack {
                    drop(guard);
                    return Some(seg);
                }

                None
            }

            // ================================================================
            // LAST-ACK: Waiting for ACK of our FIN (passive close)
            // ================================================================
            TcpState::LastAck => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(
                        &sock,
                        &mut tcp_state.control,
                        header.ack_num,
                        self.time_wait_now(),
                    );

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // Check if our FIN was ACKed
                if seq_ge(header.ack_num, tcp_state.control.snd_nxt) {
                    // LAST_ACK + ACK of FIN → CLOSED
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    return None;
                }

                // Handle retransmitted FIN from peer
                if header.flags & TCP_FLAG_FIN != 0 {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let ack_seg = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);
                    return Some(ack_seg);
                }

                None
            }

            // ================================================================
            // TIME-WAIT: Wait for 2MSL before final cleanup
            // ================================================================
            TcpState::TimeWait => {
                // R58: Use scaled window advertisement
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);

                // R164-4 FIX: Check for retransmitted FIN BEFORE the window check.
                // A retransmitted FIN has seq == rcv_nxt - 1 (FIN consumed one
                // sequence number). This falls outside [rcv_nxt, rcv_nxt + wnd),
                // so the old window check silently dropped it. Per RFC 793, the
                // TIME_WAIT state must re-ACK retransmitted FINs and restart 2MSL.
                let is_retransmitted_fin = header.flags & TCP_FLAG_FIN != 0
                    && header.seq_num == tcp_state.control.rcv_nxt.wrapping_sub(1);

                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window && !is_retransmitted_fin {
                    drop(guard);
                    return None;
                }

                // Handle retransmitted FIN from peer
                // R159-9 FIX: Only accept FIN at the exact expected sequence position.
                let mut fin_ack = None;
                if is_retransmitted_fin {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Re-ACK the FIN and restart 2MSL timer
                    fin_ack = Some(build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    ));

                    // Restart 2MSL timer on retransmitted FIN
                    tcp_state.control.time_wait_start = self.time_wait_now();
                }

                drop(guard);

                // No immediate cleanup - sweep_time_wait() will handle it after 2MSL
                if fin_ack.is_some() {
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();
                }

                fin_ack
            }

            TcpState::SynReceived => {
                // R51-1: Handle final ACK to complete passive open handshake
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let syn_key = tcp_map_key_from_parts(
                    net_ns_id,
                    dst_ip,
                    header.dst_port,
                    src_ip,
                    header.src_port,
                );

                if tcp_state.control.passive_open {
                    drop(guard);
                    return self.process_passive_final_ack(
                        &sock,
                        net_ns_id,
                        src_ip,
                        dst_ip,
                        header,
                        payload,
                        syn_key,
                        reply_binding,
                        ingress_handshake_committed,
                    );
                }

                // Handle retransmitted SYN: resend cached SYN-ACK
                if is_syn && !is_ack {
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_ref() {
                            if let Some(pending) = listen_state.get_syn(&syn_key) {
                                drop(guard);
                                return Self::try_clone_wire_segment(pending.syn_ack.as_slice());
                            }
                        }
                    }
                    return None;
                }

                // RF180-41 REVIEW FIX: the child registries retain the staged
                // half-open object so a retransmitted SYN can reuse its cached
                // response, but no ACK/data may complete or use that child until
                // the SYN-ACK's device-queue transaction confirms egress.
                if !tcp_state.control.passive_egress_confirmed {
                    return None;
                }

                // Must have ACK to complete handshake
                if !is_ack {
                    return None;
                }

                // Validate ACK acknowledges our SYN (ISS + 1)
                let ack_valid = header.ack_num == tcp_state.control.snd_nxt;
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                // R148-I2 FIX: During RFC 793 simultaneous open, the peer's SYN+ACK
                // carries seq = their ISS (already received, below rcv_nxt). The SYN
                // portion is a known retransmission — relax seq_in_window only for the
                // exact expected simultaneous-open pattern: SYN+ACK with seq == rcv_nxt-1
                // (the retransmitted SYN) and no payload.
                let simultaneous_open_synack = is_syn
                    && is_ack
                    && header.seq_num == tcp_state.control.rcv_nxt.wrapping_sub(1)
                    && payload.is_empty();
                let seq_ok = simultaneous_open_synack
                    || seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !ack_valid || !seq_ok {
                    // Invalid ACK - abort handshake, send RST
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);

                    // R51-1 FIX: Remove stale PendingSyn from listener's SYN queue
                    // before cleanup to prevent cached SYN-ACK responses to dead socket
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let mut listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_mut() {
                            listen_state.take_syn(&syn_key, self);
                        }
                    }

                    // R51-1 FIX (Codex): Mark socket closed before cleanup to ensure
                    // it's removed from sockets map (cleanup checks is_closed())
                    sock.mark_closed();
                    self.cleanup_tcp_connection(&sock);
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Handshake complete - transition to Established
                self.handle_ack_reconciled(
                    &sock,
                    &mut tcp_state.control,
                    header.ack_num,
                    self.time_wait_now(),
                );
                // R58: Apply window scaling when updating send window
                tcp_state.control.snd_wnd =
                    decode_window(header.window, tcp_state.control.effective_snd_wscale());
                tcp_state.control.snd_wl1 = header.seq_num;
                tcp_state.control.snd_wl2 = header.ack_num;
                tcp_state.control.state = TcpState::Established;
                *ingress_handshake_committed = true;

                // R58 FIX: RFC 793 semantics - if window scaling was not negotiated,
                // cap receive window to 16 bits to avoid accepting more data than
                // we can advertise without scaling. This ensures sequence/window
                // checks remain consistent with advertised window.
                if !tcp_state.control.wscale_enabled()
                    && tcp_state.control.rcv_wnd > u16::MAX as u32
                {
                    tcp_state.control.rcv_wnd = u16::MAX as u32;
                }

                // R152-4 FIX: Process any payload piggybacked on the completing ACK.
                // RFC 793 §3.4 permits data on the third handshake segment.
                // Without this, the payload is silently discarded and the peer
                // must retransmit, adding an unnecessary RTT of latency.
                let mut ack_response: Option<WirePacket> = None;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                // R154-7 FIX: Apply LSM recv hook BEFORE buffering piggybacked data.
                // Established/FinWait1/FinWait2 all call hook_net_recv; SynReceived
                // was missing this check, allowing one segment of unauthorized data.
                let payload_allowed = if !payload.is_empty() {
                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_ok()
                } else {
                    true
                };

                if payload_allowed
                    && !payload.is_empty()
                    && header.seq_num == tcp_state.control.rcv_nxt
                {
                    // R154-I2 FIX: Window calculation uses recv_buffer.len() without ooo_bytes.
                    // Invariant: SynReceived state cannot have out-of-order data because OOO
                    // buffering only occurs in Established/FinWait1/FinWait2 paths. This is
                    // the first data segment accepted after handshake completion, so ooo_bytes
                    // is guaranteed to be zero here.
                    debug_assert_eq!(
                        tcp_state.control.ooo_bytes, 0,
                        "R154-I2: OOO bytes non-zero in SynReceived→Established transition"
                    );
                    let consumed = tcp_state.control.recv_buffer.len() as u32;
                    let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);
                    if (payload.len() as u32) <= available {
                        // J2-4: per-namespace recv gate. On reject send a window ACK and
                        // do NOT extend / advance rcv_nxt (fail-closed; peer retransmits).
                        // rcv_nxt is advanced ONLY in the else-branch extend, so a
                        // data+FIN segment whose data is budget-rejected also fails the
                        // FIN check at the piggyback block below -> no half-accept.
                        if self
                            .try_charge_ns_recv_gate(
                                sock.net_ns_id,
                                &tcp_state.control,
                                payload.len(),
                            )
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            ack_response = Some(Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            ));
                        } else {
                            // R180-11 FIX: reserve allocator capacity before retain.
                            if tcp_state
                                .control
                                .recv_buffer
                                .try_extend_from_slice(payload)
                                .is_err()
                            {
                                self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                                return None;
                            }
                            tcp_state.control.rcv_nxt =
                                tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);
                            // J2-4: reconcile to true F (== recv_buffer.len(); ooo_bytes==0
                            // here per the debug_assert above). Runs before drop(guard).
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            ack_response = Some(Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                ack_wnd,
                            ));
                        }
                    }
                }

                // Handle FIN piggybacked on completing ACK (passive close)
                if is_fin
                    && header.seq_num.wrapping_add(payload.len() as u32)
                        == tcp_state.control.rcv_nxt
                {
                    tcp_state.control.rcv_nxt = tcp_state.control.rcv_nxt.wrapping_add(1);
                    tcp_state.control.fin_received = true;
                    tcp_state.control.state = TcpState::CloseWait;
                    let window = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                    ack_response = Some(build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window),
                        &[],
                    ));
                }

                // Codex review: only wake data waiters if we actually buffered something
                let has_data = ack_response.is_some();

                drop(guard);

                // Remove from SYN queue and add to accept queue
                // R75-1 FIX: Look up listener within the specified namespace
                if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                    let mut listen_guard = listener.listen.lock();
                    if let Some(listen_state) = listen_guard.as_mut() {
                        // Remove from SYN queue
                        listen_state.take_syn(&syn_key, self);
                    }
                    drop(listen_guard);

                    // Push to accept queue and wake accept() waiters
                    // R154-9 FIX: Defense-in-depth note — completed child sockets are
                    // pushed here without a per-socket LSM accept check. Currently
                    // sys_accept() performs hook_net_accept() before returning the fd
                    // to userspace, so security is maintained. If a future code path
                    // hands out accepted sockets without going through sys_accept(),
                    // an LSM gate should be added here as well.
                    if !listener.push_accept_ready(sock.clone()) {
                        // Accept queue full - abort connection
                        // R51-1 FIX (Codex): Mark socket closed before cleanup
                        sock.mark_closed();
                        self.cleanup_tcp_connection(&sock);
                        return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                    }
                }

                // Wake any waiters (accept queue changed)
                // R152-4 FIX: Also wake data waiters if payload was buffered
                if has_data {
                    sock.wake_tcp_data_waiters();
                }
                sock.wake_tcp_waiters();
                ack_response
            }

            TcpState::Listen => {
                // Listen state should not receive segments here - handled above
                // This is an internal error / unexpected state
                None
            }

            _ => {
                // Other states not yet implemented
                None
            }
        }
    }

    /// Complete a listener-owned third handshake segment as one transaction.
    /// Lock order is listener -> child TCB -> namespace recv leaf. Every
    /// fallible accept/payload/reply preparation happens before Established is
    /// published, and the exact SYN entry is moved to the reserved accept slot
    /// under the same listener guard.
    #[allow(clippy::too_many_arguments)]
    fn process_passive_final_ack(
        &self,
        sock: &SocketArc,
        net_ns_id: NamespaceId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
        syn_key: TcpLookupKey,
        reply_binding: &mut Option<TcpReplyBinding>,
        ingress_handshake_committed: &mut bool,
    ) -> Option<WirePacket> {
        let is_syn = header.flags & TCP_FLAG_SYN != 0;
        let is_ack = header.flags & TCP_FLAG_ACK != 0;

        if !payload.is_empty() {
            let mut ctx = self.ctx_from_socket(sock);
            ctx.remote = ipv4_to_u64(src_ip.0);
            ctx.remote_port = header.src_port;
            if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                return None;
            }
        }

        let listener = self.lookup_tcp_listener(net_ns_id, header.dst_port)?;
        let mut listen_guard = listener.listen.lock();
        let listen_state = listen_guard.as_mut()?;
        if !listen_state
            .get_syn(&syn_key)
            .is_some_and(|pending| Arc::ptr_eq(&pending.sock, sock))
        {
            return None;
        }

        if is_syn && !is_ack {
            let retry = {
                let pending = listen_state.get_syn(&syn_key)?;
                Self::try_clone_wire_segment(pending.syn_ack.as_slice())?
            };
            let token = next_nonzero_generation(&NEXT_TCP_EGRESS_TOKEN).ok()?;
            let mut child_guard = sock.tcp.lock();
            let child = child_guard.as_mut()?;
            if child.control.state != TcpState::SynReceived || !child.control.passive_open {
                return None;
            }
            child.control.pending_reply_token = Some(token);
            drop(child_guard);
            *reply_binding = Some(self.bind_tcp_reply(sock, token));
            return Some(retry);
        }

        if !is_ack {
            return None;
        }

        let mut child_guard = sock.tcp.lock();
        let child = child_guard.as_mut()?;
        if child.control.state != TcpState::SynReceived
            || !child.control.passive_open
            || !child.control.passive_egress_confirmed
        {
            return None;
        }

        let ack_valid = header.ack_num == child.control.snd_nxt;
        let recv_wnd = child.control.rcv_wnd.max(1);
        let sequence_valid = if payload.is_empty() && header.flags & TCP_FLAG_FIN == 0 {
            seq_in_window(header.seq_num, child.control.rcv_nxt, recv_wnd)
        } else {
            header.seq_num == child.control.rcv_nxt
        };
        if !ack_valid || !sequence_valid {
            child.control.state = TcpState::Closed;
            child.control.pending_reply_token = None;
            let retired = listen_state.take_syn(&syn_key, self);
            drop(child_guard);
            drop(listen_guard);
            drop(retired);
            sock.mark_closed();
            self.cleanup_tcp_connection(sock);
            return self.build_tcp_rst(dst_ip, src_ip, header, payload);
        }

        if !listen_state.try_reserve_accept_slot() {
            return None;
        }

        if self
            .try_charge_ns_recv_gate(sock.net_ns_id, &child.control, payload.len())
            .is_err()
        {
            listen_state.cancel_accept_slot();
            return None;
        }
        if child
            .control
            .recv_buffer
            .ensure_capacity_for(payload.len())
            .is_err()
        {
            self.reconcile_ns_recv(sock.net_ns_id, &mut child.control);
            listen_state.cancel_accept_slot();
            return None;
        }

        let fin = header.flags & TCP_FLAG_FIN != 0;
        let prospective_rcv_nxt = child
            .control
            .rcv_nxt
            .wrapping_add(payload.len() as u32)
            .wrapping_add(u32::from(fin));
        let committed_rcv_wnd = if child.control.wscale_enabled() {
            child.control.rcv_wnd
        } else {
            child.control.rcv_wnd.min(u16::MAX as u32)
        };
        let prospective_used = child
            .control
            .recv_buffer
            .len()
            .saturating_add(payload.len());
        let prospective_window = committed_rcv_wnd.saturating_sub(prospective_used as u32);
        let response = if payload.is_empty() && !fin {
            None
        } else {
            match try_build_tcp_segment_admitted(
                dst_ip,
                src_ip,
                header.dst_port,
                header.src_port,
                child.control.snd_nxt,
                prospective_rcv_nxt,
                TCP_FLAG_ACK,
                Self::encode_adv_window(&child.control, prospective_window),
                &[],
            ) {
                Ok(packet) => Some(packet),
                Err(_) => {
                    self.reconcile_ns_recv(sock.net_ns_id, &mut child.control);
                    listen_state.cancel_accept_slot();
                    return None;
                }
            }
        };

        if !payload.is_empty() {
            child
                .control
                .recv_buffer
                .try_extend_from_slice(payload)
                .expect("RF180-41 passive payload lost pre-reserved capacity");
            self.reconcile_ns_recv(sock.net_ns_id, &mut child.control);
        }
        self.handle_ack_reconciled(
            sock,
            &mut child.control,
            header.ack_num,
            self.time_wait_now(),
        );
        child.control.snd_wnd = decode_window(header.window, child.control.effective_snd_wscale());
        child.control.snd_wl1 = header.seq_num;
        child.control.snd_wl2 = header.ack_num;
        child.control.rcv_wnd = committed_rcv_wnd;
        child.control.rcv_nxt = prospective_rcv_nxt;
        child.control.established_at = self.time_wait_now();
        child.control.last_activity = child.control.established_at;
        child.control.state = if fin {
            child.control.fin_received = true;
            TcpState::CloseWait
        } else {
            TcpState::Established
        };

        let pending = listen_state
            .take_syn(&syn_key, self)
            .expect("RF180-41 exact passive SYN entry vanished under listener guard");
        assert!(
            Arc::ptr_eq(&pending.sock, sock),
            "RF180-41 passive SYN identity changed under listener guard"
        );
        let PendingSyn {
            sock: accept_sock,
            syn_ack: retired_syn_ack,
            ..
        } = pending;
        assert!(
            listen_state.publish_accept_reserved(accept_sock),
            "RF180-41 reserved passive accept publication failed"
        );
        listen_state.waiters().wake_one();

        let wake_data = !payload.is_empty() || fin;
        drop(child_guard);
        drop(listen_guard);
        drop(retired_syn_ack);
        *ingress_handshake_committed = true;
        if wake_data {
            sock.wake_tcp_data_waiters();
        }
        sock.wake_tcp_waiters();
        response
    }

    /// Get the current timestamp for TCP timing operations.
    ///
    /// # R53-2 FIX (Timestamp Precision)
    ///
    /// This function now ALWAYS fetches the real-time kernel tick counter
    /// instead of using the cached sweep timestamp. This is critical for:
    ///
    /// 1. **RTT Sampling**: Accurate RTT measurements require precise
    ///    timestamps when segments are sent and when ACKs arrive. Using a
    ///    5-second cached timestamp would produce RTT samples of either 0
    ///    (if both occur in same sweep period) or ~5s (if they span periods),
    ///    completely corrupting SRTT/RTTVAR/RTO calculations.
    ///
    /// 2. **Retransmission Timing**: Segments sent just after a sweep would
    ///    have `sent_at` equal to the sweep time, making them appear older
    ///    than they are and triggering immediate spurious retransmissions.
    ///
    /// The cached `time_wait_clock` is still used as a fallback only when:
    /// - SocketWaitHooks are not yet registered (very early boot)
    /// - As a fallback for TIME_WAIT timer initialization
    ///
    /// Performance: get_ticks() is a simple atomic load from kernel_core's
    /// TICKS counter, not an expensive RDTSC or syscall.
    #[inline]
    fn time_wait_now(&self) -> u64 {
        // Always prefer real-time ticks for accurate RTT/retransmission timing
        if let Some(hooks) = socket_wait_hooks() {
            return hooks.get_ticks().max(1);
        }
        // Fallback to cached time or minimal non-zero value during early boot
        let cached = self.time_wait_clock.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        1 // Minimal non-zero value before any time source is available
    }

    /// Apply ACK processing with RFC 5681 congestion control and RFC 6675 SACK recovery.
    ///
    /// Combines `handle_ack()`, SACK scoreboard updates, and `update_congestion_control()`.
    ///
    /// # Arguments
    ///
    /// * `tcb` - TCP control block to update
    /// * `ack_num` - ACK number from incoming segment
    /// * `advertised_wnd` - Our current scaled advertised window for response segments
    /// * `local_ip`, `remote_ip` - IP addresses for segment construction
    /// * `local_port`, `remote_port` - Ports for segment construction
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `sack_blocks` - SACK blocks from incoming segment (empty if SACK disabled)
    /// * `has_payload` - True if the incoming segment carries data (not a pure ACK)
    /// * `peer_raw_window` - Raw window field from incoming TCP header (pre-decode)
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `bool`: retransmission was accepted by the egress queue
    /// - `bool`: True if RFC 3042 Limited Transmit was signaled (caller should wake sender)
    fn apply_ack_and_cc<F>(
        &self,
        tcb: &mut TcpControlBlock,
        ack_num: u32,
        advertised_wnd: u16,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        now_ms: u64,
        sack_blocks: &[SackBlock],
        has_payload: bool,
        peer_raw_window: u16,
        queue: F,
    ) -> (bool, bool)
    where
        F: FnOnce(&WirePacket) -> bool,
    {
        // Process ACK and get update info
        let ack_update = handle_ack(tcb, ack_num, now_ms);

        // RFC 2018 / RFC 6675: Process incoming SACK blocks on the sender scoreboard.
        // Mark segments as SACKed, update highest_sacked, then detect lost segments.
        if tcb.sack_enabled() && !sack_blocks.is_empty() {
            tcb.process_sack_blocks(sack_blocks);
            tcb.sack_mark_lost();
        }

        // RFC 5681 §3.2: Duplicate ACK definition — a pure duplicate ACK must:
        // 1. Have the same acknowledgment number as a previous ACK (ack_update.duplicate)
        // 2. Carry no data (payload empty)
        // 3. NOT be a pure window update (window must match current snd_wnd)
        // Segments with data or window changes are NOT duplicate ACKs.
        let peer_adv_wnd = decode_window(peer_raw_window, tcb.effective_snd_wscale());
        let is_window_update = peer_adv_wnd != tcb.snd_wnd;
        let has_eligible_segment = tcb
            .send_buffer
            .iter()
            .any(|segment| !segment.retransmit_in_flight && segment.retry_due(now_ms));
        if ack_update.duplicate && !has_eligible_segment {
            // A duplicate ACK cannot signal loss when no data is outstanding.
            // Clear stale evidence so later data cannot inherit a poisoned count.
            tcb.dup_ack_count = 0;
        }
        let is_pure_dup_ack =
            ack_update.duplicate && !has_payload && !is_window_update && has_eligible_segment;

        // Update congestion control and check for fast retransmit
        // R55-1: Pass ack_num for NewReno partial ACK detection
        let congestion_before = (
            tcb.cwnd,
            tcb.ssthresh,
            tcb.dup_ack_count,
            tcb.congestion_state,
            tcb.recover,
        );
        let action =
            update_congestion_control(tcb, ack_update.newly_acked, is_pure_dup_ack, ack_num);

        if action == CongestionAction::LimitedTransmit {
            return (false, true);
        }

        // FastRetransmit/RetransmitNext select new work. A previously failed
        // NewReno retransmission remains an explicit per-segment task and is
        // retried on the next ACK even when this ACK has no new CC action.
        let action_idx = if matches!(
            action,
            CongestionAction::FastRetransmit | CongestionAction::RetransmitNext
        ) {
            let first_eligible = tcb
                .send_buffer
                .iter()
                .position(|segment| !segment.retransmit_in_flight && segment.retry_due(now_ms));
            if tcb.sack_enabled() {
                tcb.sack_find_lost_segment()
                    .filter(|idx| {
                        tcb.send_buffer
                            .get(*idx)
                            .map(|segment| {
                                !segment.retransmit_in_flight && segment.retry_due(now_ms)
                            })
                            .unwrap_or(false)
                    })
                    .or(first_eligible)
            } else {
                first_eligible
            }
        } else {
            None
        };
        let retransmit_idx = action_idx.or_else(|| {
            tcb.send_buffer.iter().position(|seg| {
                seg.retransmit_pending && !seg.retransmit_in_flight && seg.retry_due(now_ms)
            })
        });

        if let Some(idx) = retransmit_idx {
            if let Some(seg) = tcb.send_buffer.get_mut(idx) {
                let flags = TCP_FLAG_ACK
                    | if !seg.data.is_empty() {
                        TCP_FLAG_PSH
                    } else {
                        0
                    };
                // RF180-41 REVIEW FIX: prepare the exact wire owner first. A
                // NewReno partial ACK keeps its valid ACK progress but records
                // an explicit retry task if allocation fails; triple-duplicate
                // CC state is restored so another duplicate ACK retriggers it.
                let packet = match try_build_tcp_segment_admitted(
                    local_ip,
                    remote_ip,
                    local_port,
                    remote_port,
                    seg.seq,
                    tcb.rcv_nxt,
                    flags,
                    advertised_wnd,
                    &seg.data,
                ) {
                    Ok(packet) => packet,
                    Err(_) => {
                        if action == CongestionAction::FastRetransmit {
                            (
                                tcb.cwnd,
                                tcb.ssthresh,
                                tcb.dup_ack_count,
                                tcb.congestion_state,
                                tcb.recover,
                            ) = congestion_before;
                        } else if action == CongestionAction::RetransmitNext {
                            seg.retransmit_pending = true;
                        }
                        return (false, false);
                    }
                };
                if !queue(&packet) {
                    // Policy/device rejection is not a transmission. Keep the
                    // admitted retry explicit and leave sent_at/retrans_count
                    // unchanged. A triple-duplicate transition is also rolled
                    // back: Fast Recovery must not become externally visible
                    // until its retransmission is accepted by egress.
                    seg.retransmit_pending = true;
                    seg.record_tx_rejection(now_ms);
                    if action == CongestionAction::FastRetransmit {
                        (
                            tcb.cwnd,
                            tcb.ssthresh,
                            tcb.dup_ack_count,
                            tcb.congestion_state,
                            tcb.recover,
                        ) = congestion_before;
                    }
                    return (false, false);
                }
                seg.retransmit_pending = false;
                seg.retransmit_requires_rto = false;
                seg.clear_tx_rejection();
                seg.retrans_count = seg.retrans_count.saturating_add(1);
                seg.sent_at = now_ms;
                // `handle_ack` already records the inbound ACK as activity. This
                // assignment additionally timestamps the admitted outbound work.
                tcb.last_activity = now_ms;

                return (true, false);
            }
        }

        if action == CongestionAction::FastRetransmit {
            (
                tcb.cwnd,
                tcb.ssthresh,
                tcb.dup_ack_count,
                tcb.congestion_state,
                tcb.recover,
            ) = congestion_before;
        } else if action == CongestionAction::RetransmitNext && tcb.send_buffer.is_empty() {
            // A partial-ACK action without remaining retransmittable data is an
            // inconsistent recovery point, not permission to stay stuck in FR.
            tcb.cwnd = tcb.ssthresh.max(tcb.snd_mss as u32);
            tcb.dup_ack_count = 0;
            tcb.congestion_state = crate::tcp::TcpCongestionState::CongestionAvoidance;
        }

        (false, false)
    }

    /// Sweep TIME_WAIT connections and clean up those that exceeded 2MSL.
    ///
    /// This is a backward-compatible wrapper for `run_tcp_timers` that always
    /// performs TIME_WAIT cleanup. Use `run_tcp_timers` directly when you need
    /// to control whether TIME_WAIT cleanup runs.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Monotonic timestamp in milliseconds
    pub fn sweep_time_wait(&self, current_time_ms: u64) {
        self.run_tcp_timers(current_time_ms, true);
    }

    #[inline]
    fn prepare_timer_cleanup_slot<T>(&self, worklist: &mut AdmittedVec<T>) -> bool {
        #[cfg(test)]
        if self
            .fail_next_timer_cleanup_reserve
            .swap(false, Ordering::AcqRel)
        {
            return false;
        }
        worklist.ensure_capacity_for(1).is_ok()
    }

    #[inline]
    fn publish_timer_work<T>(worklist: &mut AdmittedVec<T>, work: T) {
        if worklist.push_reserved(work).is_err() {
            panic!("RF180-25 admitted timer worklist capacity invariant violated");
        }
    }

    /// Queue one data retransmission, then publish its retry/RTO metadata under
    /// the TCB lock. Queue rejection clears only the in-flight reservation; the
    /// pending work and original timestamps remain retryable.
    fn finish_data_retransmit(&self, work: DataRetransmitWork, now_ms: u64) -> bool {
        self.finish_data_retransmit_with_queue(work, now_ms, |dst_ip, packet, net_ns_id| {
            transmit_tcp_segment(dst_ip, packet, net_ns_id).is_ok()
        })
    }

    fn finish_data_retransmit_with_queue<F>(
        &self,
        work: DataRetransmitWork,
        now_ms: u64,
        queue: F,
    ) -> bool
    where
        F: FnOnce(Ipv4Addr, &WirePacket, u64) -> bool,
    {
        let queued = queue(work.dst_ip, &work.packet, work.net_ns_id);
        let mut guard = work.sock.tcp.lock();
        let Some(tcp_state) = guard.as_mut() else {
            return queued;
        };
        let Some(idx) = tcp_state
            .control
            .send_buffer
            .iter()
            .position(|segment| segment.seq == work.seq && segment.retransmit_in_flight)
        else {
            // A concurrent ACK legitimately retired the original segment.
            return queued;
        };

        let ack_generation_unchanged = tcp_state.control.peer_ack_generation == work.ack_generation;
        let requires_rto = {
            let segment = tcp_state
                .control
                .send_buffer
                .get_mut(idx)
                .expect("RF180-41 retransmit completion index vanished");
            segment.retransmit_in_flight = false;
            if !queued {
                segment.retransmit_pending = true;
                segment.record_tx_rejection(now_ms);
                return false;
            }
            let requires_rto = segment.retransmit_requires_rto && ack_generation_unchanged;
            segment.retransmit_pending = false;
            segment.retransmit_requires_rto = false;
            segment.clear_tx_rejection();
            segment.retrans_count = segment.retrans_count.saturating_add(1);
            segment.sent_at = now_ms;
            requires_rto
        };

        if requires_rto {
            handle_retransmission_timeout(&mut tcp_state.control);
            tcp_state.control.sack_clear_scoreboard();
            tcp_state.control.retries = tcp_state.control.retries.saturating_add(1);
            tcp_state.control.rto_ms = tcp_state
                .control
                .rto_ms
                .saturating_mul(2)
                .min(TCP_MAX_RTO_MS);
        }
        tcp_state.control.last_activity = now_ms;
        true
    }

    fn finish_fin_retransmit(&self, work: FinRetransmitWork, now_ms: u64) -> bool {
        self.finish_fin_retransmit_with_queue(work, now_ms, |dst_ip, packet, net_ns_id| {
            transmit_tcp_segment(dst_ip, packet, net_ns_id).is_ok()
        })
    }

    fn finish_fin_retransmit_with_queue<F>(
        &self,
        work: FinRetransmitWork,
        now_ms: u64,
        queue: F,
    ) -> bool
    where
        F: FnOnce(Ipv4Addr, &WirePacket, u64) -> bool,
    {
        let queued = queue(work.dst_ip, &work.packet, work.net_ns_id);
        let mut guard = work.sock.tcp.lock();
        let Some(tcp_state) = guard.as_mut() else {
            return queued;
        };
        tcp_state.control.fin_retransmit_in_flight = false;
        if queued
            && tcp_state.control.fin_sent
            && matches!(
                tcp_state.control.state,
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            )
        {
            tcp_state.control.fin_retries = tcp_state.control.fin_retries.saturating_add(1);
            tcp_state.control.fin_sent_time = now_ms;
        }
        queued
    }

    fn finish_keepalive(&self, work: KeepaliveWork) -> bool {
        self.finish_keepalive_with_queue(work, |dst_ip, packet, net_ns_id| {
            transmit_tcp_segment(dst_ip, packet, net_ns_id).is_ok()
        })
    }

    fn finish_keepalive_with_queue<F>(&self, work: KeepaliveWork, queue: F) -> bool
    where
        F: FnOnce(Ipv4Addr, &WirePacket, u64) -> bool,
    {
        let queued = queue(work.dst_ip, &work.packet, work.net_ns_id);
        let mut guard = work.sock.tcp.lock();
        let Some(tcp_state) = guard.as_mut() else {
            return queued;
        };
        tcp_state.control.keepalive_probe_in_flight = false;
        if queued
            && tcp_state.control.keepalive_enabled
            && tcp_state.control.peer_ack_generation == work.ack_generation
            && matches!(
                tcp_state.control.state,
                TcpState::Established | TcpState::CloseWait
            )
        {
            tcp_state.control.keepalive_probes_sent =
                tcp_state.control.keepalive_probes_sent.saturating_add(1);
        }
        queued
    }

    /// Run TCP timers for retransmission and optional TIME_WAIT cleanup.
    ///
    /// R53-3 FIX: Split TCP timer processing into two frequencies:
    /// - Fast timer (every 200ms): Data/FIN retransmission checks
    /// - Slow timer (every 1s): TIME_WAIT and SYN queue cleanup
    ///
    /// This enables responsive retransmission (within 200ms of RTO expiry)
    /// while avoiding excessive TIME_WAIT iteration overhead.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Monotonic timestamp in milliseconds
    /// * `sweep_time_wait` - If true, also check TIME_WAIT expiry and SYN queue timeouts
    ///
    /// # Design
    ///
    /// The function performs:
    /// 1. Updates the cached time_wait_clock for new TIME_WAIT transitions
    /// 2. Data segment retransmission (always, for responsive RTO)
    /// 3. FIN retransmission (always, needed for graceful close)
    /// 4. TIME_WAIT expiry cleanup (only when sweep_time_wait=true)
    /// 5. SYN queue timeout cleanup (only when sweep_time_wait=true)
    ///
    /// The two-phase approach (collect then cleanup) avoids holding locks
    /// across cleanup operations which may wake blocked processes.
    ///
    /// # Safety
    ///
    /// R150-1 FIX: This function must NOT be called from hard IRQ context.
    /// It allocates admitted worklists and wire packets and may transmit packets
    /// (transmit_tcp_segment → device spinlock + DMA allocation).
    ///
    /// Uses try_lock on the sockets lock to avoid blocking. If the lock is
    /// held, the sweep is skipped and returns `false`.
    /// R65-6 FIX: Returns `true` if timer sweep completed successfully, `false` if
    /// skipped due to lock contention (caller should defer work to safe context).
    pub fn run_tcp_timers(&self, current_time_ms: u64, sweep_time_wait: bool) -> bool {
        // Update cached time so RX path can stamp new TIME_WAIT transitions
        self.time_wait_clock
            .store(current_time_ms, Ordering::Relaxed);

        // Retransmission worklists are transient, but every growth remains
        // fallible. Cleanup is detection-only in this non-blocking pass: no
        // state is irreversibly closed until the blocking pass owns the work.
        let mut needs_cleanup = false;
        let mut collection_complete = true;
        let mut fin_retransmit: AdmittedVec<FinRetransmitWork> =
            AdmittedVec::new(HeapClass::SocketObject);
        // Data segment retransmissions (TCP retransmission RFC 6298)
        let mut data_retransmit: AdmittedVec<DataRetransmitWork> =
            AdmittedVec::new(HeapClass::SocketObject);
        // R149-2 FIX: Track whether any expired SYN entries were detected
        // (non-destructive; actual removal deferred to blocking path).
        let mut has_expired_syn = false;

        // R62-4 FIX: Avoid timer starvation under lock contention.
        // Previously, try_read failure would skip the entire sweep, allowing
        // TIME_WAIT and SYN queue entries to accumulate indefinitely under flood.
        // Now we retry with spin hints to increase chance of success.
        // Note: We avoid blocking read since this may be called from timer context.
        // If still contended after retries, we skip but increment a counter for monitoring.
        let sockets_guard = {
            let mut guard_opt = None;
            // Try non-blocking read up to 5 times with spin hint
            for _ in 0..5 {
                if let Some(g) = self.sockets.try_read() {
                    guard_opt = Some(g);
                    break;
                }
                // Yield to allow writer to complete
                core::hint::spin_loop();
            }
            match guard_opt {
                Some(g) => g,
                None => {
                    // Still contended - skip this sweep but don't starve indefinitely
                    // The next timer tick will retry. Under sustained flood, some sweeps
                    // will succeed between write bursts.
                    // R63-5 FIX: Track skipped sweeps for monitoring/alerting
                    self.timer_sweeps_skipped.fetch_add(1, Ordering::Relaxed);
                    // R65-6 FIX: Return false to signal incomplete - caller should defer
                    return false;
                }
            }
        };

        for sock in sockets_guard.values() {
            // Get socket metadata for FIN retransmission
            let meta = sock.meta_snapshot();
            let key_parts = match (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                (Some(li), Some(lp), Some(ri), Some(rp)) => Some((li, lp, ri, rp)),
                _ => None,
            };

            // Use try_lock to avoid blocking on per-socket lock
            let mut tcp_guard = match sock.tcp.try_lock() {
                Some(guard) => guard,
                None => continue, // Skip this socket, try next
            };

            let mut should_cleanup = false;
            let mut need_init_timestamp = false;
            let mut need_init_fin_time = false;
            let mut need_fin_retransmit = false;

            if let Some(tcp_state) = tcp_guard.as_mut() {
                // TIME_WAIT handling
                // R53-3: TIME_WAIT expiry check only runs on slow timer (1s cadence)
                // to reduce iteration overhead. Timestamp init always runs.
                if tcp_state.control.state == TcpState::TimeWait {
                    let start = tcp_state.control.time_wait_start;
                    if start == 0 {
                        need_init_timestamp = true;
                    } else if sweep_time_wait
                        && current_time_ms.saturating_sub(start) >= TCP_TIME_WAIT_MS
                    {
                        should_cleanup = true;
                    }
                }

                // R186-5/RF186-3: active-open deadline — see the identical arm in
                // `run_tcp_timers_blocking` for the full rationale. Both sweeps must
                // carry it: whichever one runs must be able to reap an active open
                // whose SYN was parked-and-dropped, simply lost, or moved into
                // SYN-RECEIVED by a bare simultaneous-open SYN. Passive listener
                // children are owned exclusively by the listener SYN-queue timer.
                if tcp_state.control.active_open_needs_timeout() {
                    let started = tcp_state.control.last_activity;
                    if started == 0 {
                        tcp_state.control.last_activity = current_time_ms;
                    } else if current_time_ms.saturating_sub(started) >= TCP_SYN_TIMEOUT_MS {
                        should_cleanup = true;
                    }
                }

                // R65-5 FIX: FIN_WAIT_2 idle timeout handling
                //
                // Without this timeout, connections can remain in FIN_WAIT_2 indefinitely
                // if the peer never sends their FIN. This creates a resource exhaustion
                // vulnerability: an attacker can establish many connections, send FIN,
                // and never complete the close sequence.
                //
                // Linux uses tcp_fin_timeout sysctl (default 60 seconds). We implement
                // the same approach: if no FIN is received within the timeout, clean up
                // the connection to reclaim resources.
                if tcp_state.control.state == TcpState::FinWait2 && sweep_time_wait {
                    let start = tcp_state.control.fin_wait2_start;
                    if start != 0
                        && current_time_ms.saturating_sub(start) >= TCP_FIN_WAIT_2_TIMEOUT_MS
                    {
                        // Timeout expired - peer never sent FIN, cleanup connection
                        should_cleanup = true;
                    }
                }

                // FIN retransmission handling for FIN_WAIT_1 / CLOSING / LAST_ACK
                if matches!(
                    tcp_state.control.state,
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                ) && tcp_state.control.fin_sent
                    && !tcp_state.control.fin_retransmit_in_flight
                {
                    let fin_start = tcp_state.control.fin_sent_time;
                    if fin_start == 0 {
                        need_init_fin_time = true;
                    } else {
                        let fin_timeout =
                            core::cmp::max(tcp_state.control.rto_ms, TCP_FIN_TIMEOUT_MS);
                        if current_time_ms.saturating_sub(fin_start) >= fin_timeout {
                            if tcp_state.control.fin_retries >= TCP_MAX_FIN_RETRIES {
                                // Max retries exceeded - cleanup connection
                                should_cleanup = true;
                            } else {
                                // Need to retransmit FIN
                                need_fin_retransmit = true;
                            }
                        }
                    }
                }

                // Data retransmission: check send_buffer for segments past RTO
                // This handles reliable delivery for established connections
                if tcp_state.control.retries >= TCP_MAX_RETRIES {
                    should_cleanup = true;
                }
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if !should_cleanup
                        && !tcp_state.control.send_buffer.is_empty()
                        && matches!(
                            tcp_state.control.state,
                            TcpState::Established
                                | TcpState::CloseWait
                                | TcpState::FinWait1
                                | TcpState::FinWait2
                                | TcpState::Closing
                                | TcpState::LastAck
                        )
                    {
                        let rto = tcp_state.control.rto_ms;
                        let ack = tcp_state.control.rcv_nxt;
                        // R58: Use scaled window advertisement
                        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                        // RFC 5681 §3.1: On RTO, check if FIRST unacked segment has timed out
                        // If so, enter loss recovery FIRST (cwnd = 1*SMSS), then retransmit
                        // only the first segment. Do NOT retransmit entire send buffer.
                        //
                        // Use two-phase approach to avoid borrow conflict:
                        // 1. Check timeout with immutable borrow
                        // 2. Enter loss recovery
                        // 3. Build retransmit segment with mutable borrow
                        let pending_idx = tcp_state.control.send_buffer.iter().position(|seg| {
                            seg.retransmit_pending
                                && !seg.retransmit_in_flight
                                && seg.retry_due(current_time_ms)
                        });
                        let rto_idx = tcp_state
                            .control
                            .send_buffer
                            .front()
                            .filter(|seg| {
                                !seg.retransmit_in_flight
                                    && seg.retry_due(current_time_ms)
                                    && current_time_ms.saturating_sub(seg.sent_at) >= rto
                            })
                            .map(|_| 0);
                        let retransmit_idx = pending_idx.or(rto_idx);

                        if let Some(retransmit_idx) = retransmit_idx {
                            let is_pending = pending_idx == Some(retransmit_idx);
                            // Reserve the deferred-work slot and build the packet before
                            // advancing RTO/retry state. OOM leaves the segment eligible
                            // for the blocking retry instead of recording a send that
                            // never occurred.
                            let prepared = if data_retransmit.ensure_capacity_for(1).is_err() {
                                None
                            } else {
                                tcp_state
                                    .control
                                    .send_buffer
                                    .get_mut(retransmit_idx)
                                    .and_then(|segment| {
                                        let flags = TCP_FLAG_ACK
                                            | if !segment.data.is_empty() {
                                                TCP_FLAG_PSH
                                            } else {
                                                0
                                            };
                                        try_build_tcp_segment_admitted(
                                            local_ip,
                                            remote_ip,
                                            local_port,
                                            remote_port,
                                            segment.seq,
                                            ack,
                                            flags,
                                            advertised_wnd,
                                            &segment.data,
                                        )
                                        .ok()
                                    })
                            };

                            if let Some(seg_bytes) = prepared {
                                let segment_seq = tcp_state
                                    .control
                                    .send_buffer
                                    .get(retransmit_idx)
                                    .expect("RF180-41 prepared timer segment vanished")
                                    .seq;
                                Self::publish_timer_work(
                                    &mut data_retransmit,
                                    DataRetransmitWork {
                                        sock: sock.clone(),
                                        dst_ip: remote_ip,
                                        packet: seg_bytes,
                                        net_ns_id: sock.net_ns_id.0,
                                        seq: segment_seq,
                                        ack_generation: tcp_state.control.peer_ack_generation,
                                    },
                                );
                                if let Some(segment) =
                                    tcp_state.control.send_buffer.get_mut(retransmit_idx)
                                {
                                    segment.retransmit_pending = true;
                                    segment.retransmit_requires_rto |= !is_pending;
                                    segment.retransmit_in_flight = true;
                                }
                            } else {
                                collection_complete = false;
                            }
                        }
                    }
                }
            }
            drop(tcp_guard);

            // Initialize TIME_WAIT timestamp if needed
            if need_init_timestamp {
                if let Some(mut guard) = sock.tcp.try_lock() {
                    if let Some(tcp_state) = guard.as_mut() {
                        if tcp_state.control.state == TcpState::TimeWait
                            && tcp_state.control.time_wait_start == 0
                        {
                            tcp_state.control.time_wait_start = current_time_ms;
                        }
                    }
                }
            }

            // Initialize FIN timestamp if needed
            if need_init_fin_time {
                if let Some(mut guard) = sock.tcp.try_lock() {
                    if let Some(tcp_state) = guard.as_mut() {
                        if matches!(
                            tcp_state.control.state,
                            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                        ) && tcp_state.control.fin_sent
                            && tcp_state.control.fin_sent_time == 0
                        {
                            tcp_state.control.fin_sent_time = current_time_ms;
                        }
                    }
                }
            }

            // Build FIN retransmission segment
            if need_fin_retransmit {
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if let Some(mut guard) = sock.tcp.try_lock() {
                        if let Some(tcp_state) = guard.as_mut() {
                            if matches!(
                                tcp_state.control.state,
                                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                            ) && tcp_state.control.fin_sent
                                && !tcp_state.control.fin_retransmit_in_flight
                                && tcp_state.control.fin_retries < TCP_MAX_FIN_RETRIES
                            {
                                let window_after = tcp_state
                                    .control
                                    .rcv_wnd
                                    .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                                // FIN sequence is snd_nxt - 1 (since FIN consumed one seq number)
                                let seq = tcp_state.control.snd_nxt.wrapping_sub(1);
                                let ack = tcp_state.control.rcv_nxt;

                                if fin_retransmit.ensure_capacity_for(1).is_ok() {
                                    let seg = try_build_tcp_segment_admitted(
                                        local_ip,
                                        remote_ip,
                                        local_port,
                                        remote_port,
                                        seq,
                                        ack,
                                        TCP_FLAG_FIN | TCP_FLAG_ACK,
                                        Self::encode_adv_window(&tcp_state.control, window_after),
                                        &[],
                                    );
                                    if let Ok(seg) = seg {
                                        Self::publish_timer_work(
                                            &mut fin_retransmit,
                                            FinRetransmitWork {
                                                sock: sock.clone(),
                                                dst_ip: remote_ip,
                                                packet: seg,
                                                net_ns_id: sock.net_ns_id.0,
                                            },
                                        );
                                        tcp_state.control.fin_retransmit_in_flight = true;
                                    } else {
                                        collection_complete = false;
                                    }
                                } else {
                                    collection_complete = false;
                                }
                            }
                        }
                    }
                }
            }

            // Handle cleanup
            //
            // R53-1 FIX: Cleanup must handle both graceful shutdown states
            // (TimeWait, FinWait1, Closing, LastAck) AND connections closed
            // due to retransmission timeout (already in Closed state with
            // mark_timeout_close flag set).
            if should_cleanup {
                // Detection only. The blocking pass revalidates the live state,
                // reserves cleanup storage, then performs the terminal transition.
                needs_cleanup = true;
            }

            // R52-1 FIX: Sweep half-open SYN queue for listening sockets
            //
            // Half-open connections (SYN received, SYN-ACK sent) that exceed
            // TCP_SYN_TIMEOUT_MS are cleaned up to prevent SYN flood resource
            // exhaustion. This ensures listeners can accept new connections
            // even under attack.
            //
            // R53-3: SYN queue cleanup only runs on slow timer (1s cadence)
            // to reduce iteration overhead for listening sockets.
            //
            // R149-2 FIX: In IRQ context, do NOT call take_syn() or perform
            // any destructive SYN queue operations. Only detect whether any
            // expired entries exist. All removal + cleanup is deferred to
            // run_tcp_timers_blocking() in process context. Without this,
            // take_syn() removes entries that are then dropped on the floor
            // when we return false, leaking half-open counter slots.
            if sweep_time_wait {
                if let Some(listen_guard) = sock.listen.try_lock() {
                    if let Some(listen_state) = listen_guard.as_ref() {
                        for (_key, pending) in listen_state.syn_queue.iter() {
                            if current_time_ms.saturating_sub(pending.syn_sent_at)
                                >= TCP_SYN_TIMEOUT_MS
                            {
                                // At least one expired SYN entry exists —
                                // mark for deferred blocking cleanup.
                                has_expired_syn = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        drop(sockets_guard);

        // R149-2 FIX: In IRQ context, NEVER perform blocking cleanup that
        // requires `sockets.write()`, `sock.tcp.lock()`, or `cleanup_tcp_connection()`.
        // If the timer IRQ interrupted a code path holding `sockets.read()`,
        // blocking `sockets.write()` would spin forever (reader can never release).
        //
        // All blocking cleanup is deferred to `run_tcp_timers_blocking()` in
        // process context (called from `drain_deferred_tcp_timers()`).
        // Queue completion briefly re-locks only the owning TCB after the
        // device operation; this function runs in deferred process context.
        let mut needs_blocking_cleanup = needs_cleanup || has_expired_syn || !collection_complete;

        // Transmit any pending FIN retransmissions (best-effort, no locks needed)
        while let Some(work) = fin_retransmit.pop() {
            if !self.finish_fin_retransmit(work, current_time_ms) {
                collection_complete = false;
            }
        }

        // Transmit data segment retransmissions (RFC 6298, no locks needed)
        while let Some(work) = data_retransmit.pop() {
            if !self.finish_data_retransmit(work, current_time_ms) {
                collection_complete = false;
            }
        }
        needs_blocking_cleanup |= !collection_complete;

        // If any sockets need blocking cleanup, signal incomplete to caller
        // so work is deferred to safe (non-IRQ) context.
        if needs_blocking_cleanup {
            return false;
        }

        // R65-6 FIX: Signal successful completion to caller
        true
    }

    /// R65-6 FIX: Blocking variant of run_tcp_timers for safe (non-IRQ) context.
    ///
    /// Called from syscall return path to drain deferred timer work when IRQ-time
    /// processing was incomplete due to lock contention.
    ///
    /// Unlike run_tcp_timers(), this function uses blocking locks. Transient
    /// worklist/packet allocation is still fallible; on pressure it leaves the
    /// affected socket state retryable and returns `false`, preserving the
    /// deferred flag for the next process-context opportunity.
    ///
    /// # Returns
    ///
    /// `true` only when every detected item was collected and processed.
    pub fn run_tcp_timers_blocking(&self, current_time_ms: u64, sweep_time_wait: bool) -> bool {
        // Update cached time so RX path can stamp new TIME_WAIT transitions
        self.time_wait_clock
            .store(current_time_ms, Ordering::Relaxed);

        // RF180-25 FIX: every deferred owner and serialized packet is admitted
        // before publication. Worklist backing uses SocketObject; wire bytes use
        // SocketPayload and retain that charge through transmit/drop.
        let mut to_cleanup: AdmittedVec<SocketArc> = AdmittedVec::new(HeapClass::SocketObject);
        let mut fin_retransmit: AdmittedVec<FinRetransmitWork> =
            AdmittedVec::new(HeapClass::SocketObject);
        let mut data_retransmit: AdmittedVec<DataRetransmitWork> =
            AdmittedVec::new(HeapClass::SocketObject);
        let mut syn_timeouts: AdmittedVec<(SocketArc, Ipv4Addr, Option<WirePacket>)> =
            AdmittedVec::new(HeapClass::SocketObject);
        // R148-I3 FIX: Collect keepalive probes to send after releasing locks.
        // R160-8 FIX: Extended tuple includes conntrack seeding metadata.
        let mut keepalive_probes: AdmittedVec<KeepaliveWork> =
            AdmittedVec::new(HeapClass::SocketObject);
        // R148-3 FIX: Collect listeners for deferred SYN queue sweep outside
        // sockets lock. Sweeping under sockets.read() creates AB-BA deadlock
        // with the SYN handler path: sockets.read()->listen.lock() vs
        // listen.lock()->sockets.write().
        let mut listeners_to_sweep: AdmittedVec<SocketArc> =
            AdmittedVec::new(HeapClass::SocketObject);
        let mut collection_complete = true;

        // R65-6 FIX: Use blocking read lock - safe in non-IRQ context
        let sockets_guard = self.sockets.read();

        for sock in sockets_guard.values() {
            let meta = sock.meta_snapshot();
            let key_parts = match (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                (Some(li), Some(lp), Some(ri), Some(rp)) => Some((li, lp, ri, rp)),
                _ => None,
            };

            // RF180-7 FIX: prepare the irreversible cleanup handoff before
            // taking the TCB lock. If this socket proves due below, validation,
            // the terminal state transition, and worklist publication all occur
            // under that single lock. A failed preflight therefore leaves every
            // timer state retryable without a stale detection/relock window.
            let cleanup_slot_ready = self.prepare_timer_cleanup_slot(&mut to_cleanup);

            // R65-6 FIX: Use blocking lock for per-socket state
            let mut tcp_guard = sock.tcp.lock();

            let mut should_cleanup = false;
            let mut need_fin_retransmit = false;
            let mut mark_timeout_close = false;
            let mut queued_timeout_close = false;

            if let Some(tcp_state) = tcp_guard.as_mut() {
                // TIME_WAIT handling
                if tcp_state.control.state == TcpState::TimeWait {
                    let start = tcp_state.control.time_wait_start;
                    if start == 0 {
                        tcp_state.control.time_wait_start = current_time_ms;
                    } else if sweep_time_wait
                        && current_time_ms.saturating_sub(start) >= TCP_TIME_WAIT_MS
                    {
                        should_cleanup = true;
                    }
                }

                // R186-5/RF186-3: give every active handshake a durable timeout owner.
                //
                // `SYN_SENT` was the one active state with NO timer at all. The
                // initial SYN is never placed in `send_buffer`, so the data
                // retransmission arm below (which requires a non-empty send buffer)
                // never selects it, `control.retries` is never advanced for it, and
                // the `retries >= TCP_MAX_RETRIES` cleanup can therefore never fire.
                // `TCP_SYN_TIMEOUT_MS` was consulted only against a LISTENER's
                // syn_queue — never against a connecting socket.
                //
                // Consequences, both reachable by an unprivileged process:
                //   - A nonblocking `connect()` to an unresolved on-link address
                //     returns EINPROGRESS after the frame is merely PARKED on the
                //     ARP queue. Every terminal outcome for a parked frame
                //     (eviction, TTL expiry, flush on reconfiguration, transmit
                //     failure) silently drops it, leaving the tuple, the ephemeral
                //     port, the TCB and the connection credit charged until an
                //     explicit close that may never come.
                //   - Even a SYN that reaches the wire and is simply lost leaves the
                //     same residue.
                // Flooding either case exhausts the 1024-per-netns / 4096 global
                // connection caps.
                //
                // A timeout here is the durable owner the state machine requires,
                // and it closes both paths with one mechanism rather than patching
                // each parked-frame terminal. RF186-3 extends the same ownership
                // through simultaneous-open SYN-RECEIVED when `passive_open` is
                // false; listener children remain under the SYN queue's timer.
                // `last_activity` is stamped when SYN_SENT is published and is
                // preserved across the simultaneous-open transition. Reaching the
                // deadline tears the connection down and marks it
                // timed-out, which releases every charge and makes the failure
                // observable to poll/select instead of hanging silently.
                if tcp_state.control.active_open_needs_timeout() {
                    let started = tcp_state.control.last_activity;
                    if started == 0 {
                        tcp_state.control.last_activity = current_time_ms;
                    } else if current_time_ms.saturating_sub(started) >= TCP_SYN_TIMEOUT_MS {
                        should_cleanup = true;
                        mark_timeout_close = true;
                    }
                }

                // R65-5 FIX: FIN_WAIT_2 idle timeout handling
                if tcp_state.control.state == TcpState::FinWait2 && sweep_time_wait {
                    let start = tcp_state.control.fin_wait2_start;
                    if start != 0
                        && current_time_ms.saturating_sub(start) >= TCP_FIN_WAIT_2_TIMEOUT_MS
                    {
                        should_cleanup = true;
                        mark_timeout_close = true;
                    }
                }

                // FIN retransmission handling
                if matches!(
                    tcp_state.control.state,
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                ) && tcp_state.control.fin_sent
                    && !tcp_state.control.fin_retransmit_in_flight
                {
                    let fin_start = tcp_state.control.fin_sent_time;
                    if fin_start == 0 {
                        tcp_state.control.fin_sent_time = current_time_ms;
                    } else {
                        let fin_timeout =
                            core::cmp::max(tcp_state.control.rto_ms, TCP_FIN_TIMEOUT_MS);
                        if current_time_ms.saturating_sub(fin_start) >= fin_timeout {
                            if tcp_state.control.fin_retries >= TCP_MAX_FIN_RETRIES {
                                should_cleanup = true;
                            } else {
                                need_fin_retransmit = true;
                            }
                        }
                    }
                }

                if tcp_state.control.retries >= TCP_MAX_RETRIES {
                    should_cleanup = true;
                    mark_timeout_close = true;
                }

                // Data retransmission
                if !mark_timeout_close {
                    if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                        if !tcp_state.control.send_buffer.is_empty()
                            && matches!(
                                tcp_state.control.state,
                                TcpState::Established
                                    | TcpState::CloseWait
                                    | TcpState::FinWait1
                                    | TcpState::FinWait2
                                    | TcpState::Closing
                                    | TcpState::LastAck
                            )
                        {
                            let rto = tcp_state.control.rto_ms;
                            let ack = tcp_state.control.rcv_nxt;
                            let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                            let pending_idx =
                                tcp_state.control.send_buffer.iter().position(|seg| {
                                    seg.retransmit_pending
                                        && !seg.retransmit_in_flight
                                        && seg.retry_due(current_time_ms)
                                });
                            let rto_idx = tcp_state
                                .control
                                .send_buffer
                                .front()
                                .filter(|seg| {
                                    !seg.retransmit_in_flight
                                        && seg.retry_due(current_time_ms)
                                        && current_time_ms.saturating_sub(seg.sent_at) >= rto
                                })
                                .map(|_| 0);
                            let retransmit_idx = pending_idx.or(rto_idx);

                            if let Some(retransmit_idx) = retransmit_idx {
                                let is_pending = pending_idx == Some(retransmit_idx);
                                let prepared = if data_retransmit.ensure_capacity_for(1).is_err() {
                                    None
                                } else {
                                    tcp_state
                                        .control
                                        .send_buffer
                                        .get_mut(retransmit_idx)
                                        .and_then(|segment| {
                                            let flags = TCP_FLAG_ACK
                                                | if !segment.data.is_empty() {
                                                    TCP_FLAG_PSH
                                                } else {
                                                    0
                                                };
                                            try_build_tcp_segment_admitted(
                                                local_ip,
                                                remote_ip,
                                                local_port,
                                                remote_port,
                                                segment.seq,
                                                ack,
                                                flags,
                                                advertised_wnd,
                                                &segment.data,
                                            )
                                            .ok()
                                        })
                                };

                                if let Some(seg_bytes) = prepared {
                                    let segment_seq = tcp_state
                                        .control
                                        .send_buffer
                                        .get(retransmit_idx)
                                        .expect("RF180-41 prepared blocking segment vanished")
                                        .seq;
                                    Self::publish_timer_work(
                                        &mut data_retransmit,
                                        DataRetransmitWork {
                                            sock: sock.clone(),
                                            dst_ip: remote_ip,
                                            packet: seg_bytes,
                                            net_ns_id: sock.net_ns_id.0,
                                            seq: segment_seq,
                                            ack_generation: tcp_state.control.peer_ack_generation,
                                        },
                                    );
                                    if let Some(segment) =
                                        tcp_state.control.send_buffer.get_mut(retransmit_idx)
                                    {
                                        segment.retransmit_pending = true;
                                        segment.retransmit_requires_rto |= !is_pending;
                                        segment.retransmit_in_flight = true;
                                    }
                                } else {
                                    collection_complete = false;
                                }
                            }
                        }
                    }
                }

                // R148-I3 FIX: TCP keepalive probes per RFC 1122 §4.2.3.6.
                // Send probes only when idle (no outstanding data) in a state
                // where the connection should remain alive.
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if !mark_timeout_close
                        && tcp_state.control.keepalive_enabled
                        && !tcp_state.control.keepalive_probe_in_flight
                        && tcp_state.control.send_buffer.is_empty()
                        && matches!(
                            tcp_state.control.state,
                            TcpState::Established | TcpState::CloseWait
                        )
                        && tcp_state.control.last_activity != 0
                    {
                        let idle_ms =
                            current_time_ms.saturating_sub(tcp_state.control.last_activity);
                        let probes_sent = tcp_state.control.keepalive_probes_sent as u64;
                        let threshold = tcp_state.control.keepalive_idle_ms.saturating_add(
                            probes_sent.saturating_mul(tcp_state.control.keepalive_interval_ms),
                        );

                        if idle_ms >= threshold {
                            if tcp_state.control.keepalive_probes_sent
                                >= tcp_state.control.keepalive_probes_max
                            {
                                // Connection dead — terminal transition is deferred
                                // until a cleanup worklist slot is guaranteed.
                                should_cleanup = true;
                                mark_timeout_close = true;
                            } else {
                                // Send keepalive probe: seq = snd_una - 1 to elicit ACK
                                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                                if keepalive_probes.ensure_capacity_for(1).is_ok() {
                                    let probe = try_build_tcp_segment_admitted(
                                        local_ip,
                                        remote_ip,
                                        local_port,
                                        remote_port,
                                        tcp_state.control.snd_una.wrapping_sub(1),
                                        tcp_state.control.rcv_nxt,
                                        TCP_FLAG_ACK,
                                        advertised_wnd,
                                        &[],
                                    );
                                    if let Ok(probe) = probe {
                                        Self::publish_timer_work(
                                            &mut keepalive_probes,
                                            KeepaliveWork {
                                                sock: sock.clone(),
                                                dst_ip: remote_ip,
                                                packet: probe,
                                                net_ns_id: sock.net_ns_id.0,
                                                ack_generation: tcp_state
                                                    .control
                                                    .peer_ack_generation,
                                            },
                                        );
                                        tcp_state.control.keepalive_probe_in_flight = true;
                                    } else {
                                        collection_complete = false;
                                    }
                                } else {
                                    collection_complete = false;
                                }
                            }
                        }
                    }
                }

                // Build and publish FIN retransmission work while the same TCB
                // identity/state lock used for detection is still held. Packet
                // and worklist allocation complete before retry counters move.
                if need_fin_retransmit && !should_cleanup {
                    if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                        if matches!(
                            tcp_state.control.state,
                            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                        ) && tcp_state.control.fin_sent
                            && !tcp_state.control.fin_retransmit_in_flight
                            && tcp_state.control.fin_retries < TCP_MAX_FIN_RETRIES
                        {
                            let window_after = tcp_state
                                .control
                                .rcv_wnd
                                .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                            let seq = tcp_state.control.snd_nxt.wrapping_sub(1);
                            let ack = tcp_state.control.rcv_nxt;

                            let prepared = if fin_retransmit.ensure_capacity_for(1).is_err() {
                                None
                            } else {
                                try_build_tcp_segment_admitted(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    Self::encode_adv_window(&tcp_state.control, window_after),
                                    &[],
                                )
                                .ok()
                            };
                            if let Some(segment) = prepared {
                                Self::publish_timer_work(
                                    &mut fin_retransmit,
                                    FinRetransmitWork {
                                        sock: sock.clone(),
                                        dst_ip: remote_ip,
                                        packet: segment,
                                        net_ns_id: sock.net_ns_id.0,
                                    },
                                );
                                tcp_state.control.fin_retransmit_in_flight = true;
                            } else {
                                collection_complete = false;
                            }
                        }
                    }
                }

                // RF180-7 FIX: this is the cleanup commit point for every
                // blocking timer kind (TIME_WAIT, FIN_WAIT_2, FIN retry, data
                // retry, and keepalive). No observer can make ACK/FIN progress
                // between the due-state proof and the Closed publication.
                if should_cleanup {
                    if cleanup_slot_ready {
                        tcp_state.control.state = TcpState::Closed;
                        Self::publish_timer_work(&mut to_cleanup, sock.clone());
                        queued_timeout_close = mark_timeout_close;
                    } else {
                        collection_complete = false;
                    }
                }
            }
            drop(tcp_guard);

            // mark_closed() re-enters the TCB to wake waiters, so call it only
            // after the transaction lock is released. The Closed transition and
            // cleanup Arc are already durably committed at this point.
            if queued_timeout_close {
                sock.mark_closed();
            }

            // R148-3 FIX: Defer SYN queue sweep outside sockets lock to avoid
            // AB-BA deadlock with the RX SYN handler path.
            if sweep_time_wait && sock.is_listening() {
                if listeners_to_sweep.ensure_capacity_for(1).is_ok() {
                    Self::publish_timer_work(&mut listeners_to_sweep, sock.clone());
                } else {
                    collection_complete = false;
                }
            }
        }

        drop(sockets_guard);

        // R148-3 FIX: Sweep SYN queues after releasing sockets lock. The RX
        // SYN handler acquires listen.lock() then sockets.write(); sweeping
        // under sockets.read() then listen.lock() would create AB-BA deadlock.
        if sweep_time_wait {
            for listener in &listeners_to_sweep {
                let mut listen_guard = listener.listen.lock();
                if let Some(listen_state) = listen_guard.as_mut() {
                    loop {
                        let expired_key = listen_state
                            .syn_queue
                            .iter()
                            .find(|(_, pending)| {
                                current_time_ms.saturating_sub(pending.syn_sent_at)
                                    >= TCP_SYN_TIMEOUT_MS
                            })
                            .map(|(key, _)| *key);
                        let Some(key) = expired_key else {
                            break;
                        };
                        // Reserve the irreversible cleanup handoff before removing
                        // the SYN entry/counters. On OOM leave it queued for retry.
                        if syn_timeouts.ensure_capacity_for(1).is_err() {
                            collection_complete = false;
                            break;
                        }
                        if let Some(pending) = listen_state.take_syn(&key, self) {
                            let rst_seg = {
                                let mut tcb_guard = pending.sock.tcp.lock();
                                if let Some(tcb) = tcb_guard.as_mut() {
                                    // R106-10 FIX: key.0 is now NamespaceId; IPs/ports shifted by 1
                                    let local_ip = Ipv4Addr(key.1.to_be_bytes());
                                    let remote_ip = Ipv4Addr(key.3.to_be_bytes());
                                    let seq = tcb.control.snd_nxt;
                                    let ack = tcb.control.rcv_nxt;

                                    try_build_tcp_segment_admitted(
                                        local_ip,
                                        remote_ip,
                                        key.2,
                                        key.4,
                                        seq,
                                        ack,
                                        TCP_FLAG_RST | TCP_FLAG_ACK,
                                        0,
                                        &[],
                                    )
                                    .ok()
                                } else {
                                    None
                                }
                            };

                            Self::publish_timer_work(
                                &mut syn_timeouts,
                                (pending.sock, Ipv4Addr(key.3.to_be_bytes()), rst_seg),
                            );
                        }
                    }
                }
            }
        }

        // Cleanup phase (outside sockets lock). Pop work directly; no secondary
        // ID/namespace vectors are needed, so cleanup remains allocation-free.
        while let Some(sock) = to_cleanup.pop() {
            self.cleanup_tcp_connection(&sock);
            if sock.is_closed() {
                if self.sockets.write().remove(&sock.id).is_some() {
                    self.dec_ns_count(sock.net_ns_id);
                }
            }
        }

        while let Some((child, dst_ip, rst_seg)) = syn_timeouts.pop() {
            let child_ns = child.net_ns_id.0;
            child.mark_closed();
            self.cleanup_tcp_connection(&child);
            if let Some(seg) = rst_seg {
                let _ = transmit_tcp_segment(dst_ip, &seg, child_ns);
            }
            if self.sockets.write().remove(&child.id).is_some() {
                self.dec_ns_count(child.net_ns_id);
            }
        }

        while let Some(work) = fin_retransmit.pop() {
            if !self.finish_fin_retransmit(work, current_time_ms) {
                collection_complete = false;
            }
        }

        while let Some(work) = data_retransmit.pop() {
            if !self.finish_data_retransmit(work, current_time_ms) {
                collection_complete = false;
            }
        }

        // Generic egress refreshes conntrack transactionally; no pre-seed is
        // allowed before the queue operation.
        while let Some(work) = keepalive_probes.pop() {
            if !self.finish_keepalive(work) {
                collection_complete = false;
            }
        }

        collection_complete
    }

    /// Clean up TCP connection resources (bindings and 4-tuple registration).
    ///
    /// Called when a connection is aborted (RST received, timeout, error) or
    /// when graceful shutdown completes (LAST_ACK→CLOSED, TIME_WAIT expiry).
    ///
    /// If the socket was marked closed by close() (indicating graceful shutdown
    /// initiated by the local side), this function also removes the socket from
    /// the sockets map to prevent memory leaks.
    fn cleanup_tcp_connection(&self, sock: &SocketArc) {
        let meta = sock.meta_snapshot();

        // R51-1 FIX: Only remove local port binding if this socket owns it.
        // Child sockets from passive open share the listener's port binding,
        // so we must not unbind the port when cleaning up a child socket.
        // R75-1 FIX: Use namespace-scoped binding key.
        if let Some(port) = meta.local_port {
            let binding_key = (sock.net_ns_id, port);
            // J2-8 / R169-6 slice 2: ptr-eq-gated, KIND-GATED teardown (the
            // R51-1 ownership check is folded into the expect_ptr — a
            // passive-open child sharing the listener's port leaves the
            // listener binding intact). This is the funnel for RX-RST / sweep /
            // abort / TIME_WAIT-evict and runs under the L8 binding lock in
            // RX-reachable context, so a reclaimed charge is ENQUEUED for
            // deferred uncharge — never uncharged inline.
            //
            // is_closed() gate (load-bearing): is_closed() is set ONLY by
            // close()/mark_closed — the TCB-Closed transitions (abort_tcp_connect,
            // forced TIME_WAIT evict) do NOT set it.
            // - is_closed() == true: TERMINAL teardown (the graceful-close
            //   funnel — the socket is removed from `sockets` below). Remove
            //   the binding KIND-AGNOSTICALLY: hold-until-close ends HERE for
            //   an Explicit binding; deferring to the dead-Weak sweep would
            //   only add reclaim latency.
            // - is_closed() == false: the socket SURVIVES (RST-on-Established,
            //   abort-for-retry, forced TIME_WAIT eviction of a never-closed
            //   socket). Kind-gated: an own charged Explicit binding is
            //   PURE-SKIPPED (POSIX hold-until-close — the still-open FD owns
            //   the port; a retry connect() reuses it with the charge intact;
            //   if the owner is later dropped without close(), the
            //   kind-agnostic dead-Weak triad reclaims the charge exactly
            //   once); an own charged Ephemeral is removed + enqueued +
            //   local-cleared (ghost-bind fix below).
            let action = {
                let mut bindings = self.tcp_bindings.lock();
                if sock.is_closed() {
                    TeardownAction::Removed(Self::remove_binding_charged(
                        &mut bindings,
                        binding_key,
                        Some(Arc::as_ptr(sock)),
                    ))
                } else {
                    Self::resolve_while_alive_teardown(
                        &mut bindings,
                        binding_key,
                        Arc::as_ptr(sock),
                    )
                }
            };
            if let TeardownAction::Removed(Some(cgid)) = action {
                self.enqueue_port_uncharge(cgid, 1);
                // Ghost-bind clear: without this, local_port survives as a
                // charge-less "ghost bind" — the retry sees local_port == Some
                // -> did_alloc == false -> re-inserts the binding UNCHARGED,
                // undercounting live ports and bypassing ports.max. Reachable
                // for a charged-EPHEMERAL removal and for the TERMINAL
                // (is_closed) removal only (a surviving charged Explicit took
                // SkipExplicit; uncharged/foreign yield Removed(None)), so a
                // live user's explicit bind is never silently cleared. (For a
                // fully-closed socket the clear is a harmless no-op — it is
                // removed from `sockets` below anyway.)
                let mut m = sock.meta.lock();
                m.local_ip = None;
                m.local_port = None;
            }
        }

        // Remove namespace + 4-tuple from connection map
        if let (Some(lip), Some(lport), Some(rip), Some(rport)) = (
            meta.local_ip,
            meta.local_port,
            meta.remote_ip,
            meta.remote_port,
        ) {
            let key =
                tcp_map_key_from_parts(sock.net_ns_id, Ipv4Addr(lip), lport, Ipv4Addr(rip), rport);
            // RF180-36 FIX: metadata is a snapshot, so ownership must be checked
            // against the live Weak before removing a potentially reused tuple.
            self.remove_tcp_conn_exact_owner(key, sock);
        }

        // Clear remote metadata to allow retry
        {
            let mut meta = sock.meta.lock();
            meta.remote_ip = None;
            meta.remote_port = None;
        }

        // Close and wake TCP waiters before dropping the TCB
        let mut tcp_guard = sock.tcp.lock();
        if let Some(tcp_state) = tcp_guard.as_mut() {
            tcp_state.state_waiters.close();
            tcp_state.state_waiters.wake_all();
            tcp_state.data_waiters.close();
            tcp_state.data_waiters.wake_all();
            // J2-6: uncharge the residual per-namespace send bytes before the TCB is
            // dropped. LOAD-BEARING for the path where is_closed() is false below
            // (the Arc lives on with the TCB nulled, so impl Drop would find None
            // and uncharge 0 — this is then the only uncharge that runs). Mirrors
            // detach_tcp_uncharged under the already-held guard (no re-lock). Only
            // sock.tcp is held here (tcp_bindings/tcp_conns released above), so
            // per_ns_send_bytes stays a pure leaf.
            let charged = tcp_state.control.ns_charged_send_bytes;
            if charged > 0 {
                self.uncharge_ns_send_residual(sock.net_ns_id, charged);
                tcp_state.control.ns_charged_send_bytes = 0;
            }
            // J2-4: symmetric recv-byte residual uncharge (LOAD-BEARING on the
            // is_closed()==false path: the Arc lives on with the TCB nulled, so Drop
            // later finds None and this is the only recv uncharge that runs).
            let rcharged = tcp_state.control.ns_charged_recv_bytes;
            if rcharged > 0 {
                self.uncharge_ns_recv_residual(sock.net_ns_id, rcharged);
                tcp_state.control.ns_charged_recv_bytes = 0;
            }
        }
        *tcp_guard = None;
        drop(tcp_guard);

        // If socket was marked closed by close() (graceful shutdown path),
        // remove it from the sockets map to complete cleanup and prevent leak.
        // This handles the case where close() kept the socket registered for
        // FIN/ACK handling and the TCP state machine has now completed.
        // R129-2 FIX: When removing from sockets map, also decrement per-namespace
        // socket count. This fixes a leak where SynReceived sockets aborted via
        // invalid ACK or accept-queue-full had try_inc_ns_count() called at
        // creation but dec_ns_count() was never called on abort. The is_some()
        // guard prevents double-decrement when close_socket() or sweep_time_wait
        // already removed the socket from the map.
        if sock.is_closed() {
            if self.sockets.write().remove(&sock.id).is_some() {
                self.dec_ns_count(sock.net_ns_id);
            }
        }
    }

    /// R50-3 FIX: Abort an in-flight outbound TCP connection (timeout/reset path).
    ///
    /// Called from sys_connect when a blocking connect times out to ensure
    /// TCB and port bindings are properly released.
    ///
    /// # Arguments
    ///
    /// * `sock` - The socket with a connection attempt to abort
    pub fn abort_tcp_connect(&self, sock: &SocketArc) {
        // R180-21 FIX: TX-failure rollback participates in the same per-socket
        // transaction protocol as bind/connect initiation.
        let _operation = self.lock_socket_operation(sock);
        self.abort_tcp_connect_locked(sock);
    }

    /// Abort helper for callers already holding `sock.operation`.
    fn abort_tcp_connect_locked(&self, sock: &SocketArc) {
        // Transition TCB to Closed state
        {
            let mut guard = sock.tcp.lock();
            if let Some(tcp_state) = guard.as_mut() {
                tcp_state.control.state = TcpState::Closed;
                tcp_state.control.active_open_pending = false;
                tcp_state.control.pending_handshake = None;
                tcp_state.control.pending_reply_token = None;
            }
        }
        // Clean up all connection resources
        self.cleanup_tcp_connection(sock);
    }

    /// Build a TCP RST segment for invalid/unknown connections.
    ///
    /// R63-4 FIX: Returns `None` if RST rate limit is exceeded.
    ///
    /// Per RFC 793:
    /// - If ACK was set: RST seq = incoming ACK number, no ACK flag
    /// - If ACK was not set: RST seq = 0, ACK = incoming SEQ + segment length
    fn build_tcp_rst(
        &self,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
    ) -> Option<WirePacket> {
        // R63-4 FIX: Rate limit RST responses to prevent amplification attacks
        if !allow_rst(self.time_wait_now()) {
            return None;
        }

        let is_ack = header.flags & TCP_FLAG_ACK != 0;
        let is_syn = header.flags & TCP_FLAG_SYN != 0;
        let is_fin = header.flags & 0x01 != 0; // FIN flag

        if is_ack {
            // RFC 793: <SEQ=SEG.ACK><CTL=RST>
            crate::tcp::try_build_tcp_segment(
                local_ip,
                remote_ip,
                header.dst_port,
                header.src_port,
                header.ack_num,
                0,
                TCP_FLAG_RST,
                0,
                &[],
            )
            .ok()
        } else {
            // RFC 793: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            let mut seg_len = payload.len() as u32;
            if is_syn {
                seg_len = seg_len.wrapping_add(1);
            }
            if is_fin {
                seg_len = seg_len.wrapping_add(1);
            }
            let ack_num = header.seq_num.wrapping_add(seg_len);

            crate::tcp::try_build_tcp_segment(
                local_ip,
                remote_ip,
                header.dst_port,
                header.src_port,
                0,
                ack_num,
                TCP_FLAG_RST | TCP_FLAG_ACK,
                0,
                &[],
            )
            .ok()
        }
    }
}

/// Socket table statistics.
#[derive(Debug, Clone, Copy)]
pub struct TableStats {
    pub created: u64,
    pub closed: u64,
    pub active: usize,
    pub bound_ports: usize,
    /// R63-5 FIX: Timer sweeps skipped due to lock contention
    pub timer_sweeps_skipped: u64,
    /// P0-2 FIX: Forced TIME_WAIT evictions to admit SYN cookie completions
    pub forced_tw_evictions: u64,
}

// ============================================================================
// Global Singleton
// ============================================================================

// RF180-52 FIX: construct the large global table directly in static storage.
// `SocketTable` contains the 4096-slot deferred-uncharge array, so routing its
// const constructor through `Once::call_once` materialized a value larger than
// an AP's 16 KiB kernel stack before moving it into the singleton. Static const
// initialization removes that transient stack object entirely.
static SOCKET_TABLE: SocketTable = SocketTable::new();

/// Get the global socket table.
pub fn socket_table() -> &'static SocketTable {
    &SOCKET_TABLE
}

// ============================================================================
// Helpers
// ============================================================================

/// Convert IPv4 bytes to u64 for LSM context.
#[inline]
fn ipv4_to_u64(bytes: [u8; 4]) -> u64 {
    u32::from_be_bytes(bytes) as u64
}

/// R106-10 FIX: Build TCP lookup key from namespace + connection parts.
#[inline]
fn tcp_map_key_from_parts(
    net_ns_id: NamespaceId,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> TcpLookupKey {
    (
        net_ns_id,
        u32::from_be_bytes(local_ip.0),
        local_port,
        u32::from_be_bytes(remote_ip.0),
        remote_port,
    )
}

/// R106-10 FIX: Build TCP lookup key from namespace + TcpConnKey.
#[inline]
#[allow(dead_code)]
fn tcp_map_key_from_conn_key(net_ns_id: NamespaceId, key: &TcpConnKey) -> TcpLookupKey {
    (
        net_ns_id,
        u32::from_be_bytes(key.local_ip.0),
        key.local_port,
        u32::from_be_bytes(key.remote_ip.0),
        key.remote_port,
    )
}

// ============================================================================
// R74-5 Test Helpers: Expose counter state for runtime testing
// ============================================================================

/// Get current half-open connection count for testing.
///
/// R74-5 Enhancement: Used by runtime tests to verify atomic counter behavior.
pub fn test_get_half_open_count() -> u32 {
    GLOBAL_HALF_OPEN_COUNT.load(Ordering::Relaxed)
}

/// Get current active connection count for testing.
///
/// R74-5 Enhancement: Used by runtime tests to verify atomic counter behavior.
pub fn test_get_active_conn_count() -> u32 {
    GLOBAL_ACTIVE_CONN_COUNT.load(Ordering::Relaxed)
}

/// Get the maximum half-open connection limit for testing.
pub fn test_get_max_half_open() -> u32 {
    GLOBAL_MAX_HALF_OPEN
}

/// Test atomic increment of half-open counter (public wrapper for testing).
///
/// R74-5 Enhancement: Verifies atomic `fetch_update` behavior.
/// Returns true if increment succeeded (under limit), false if at limit.
pub fn test_try_inc_half_open() -> bool {
    try_inc_half_open()
}

/// Test decrement of half-open counter (public wrapper for testing).
pub fn test_dec_half_open() {
    dec_half_open()
}

/// Test atomic increment of active connection counter (public wrapper for testing).
///
/// R74-5 Enhancement: Verifies atomic `fetch_update` behavior.
/// Returns true if increment succeeded (under limit), false if at limit.
pub fn test_try_inc_active_conn() -> bool {
    try_inc_active_conn()
}

/// Test decrement of active connection counter (public wrapper for testing).
pub fn test_dec_active_conn() {
    dec_active_conn()
}

/// Reset counters to zero for test isolation.
///
/// # Safety
/// Only call from test code when no real network activity is happening.
pub fn test_reset_counters() {
    GLOBAL_HALF_OPEN_COUNT.store(0, Ordering::Relaxed);
    GLOBAL_ACTIVE_CONN_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Barrier;
    use std::thread;
    use std::vec::Vec;

    // Tests below reset process-global TCP counters. Serialize every reset-based
    // probe so the hosted runner's parallel scheduling cannot manufacture
    // cross-test counter drift or hide an exactly-once cleanup regression.
    static TEST_TCP_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_test_tcp_counters() -> std::sync::MutexGuard<'static, ()> {
        TEST_TCP_COUNTER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // D1-ISO-NETNS-DATAPLANE: with no NetNsDeviceHooks registered (host tests
    // never register one), the TX ownership predicate must admit ONLY the root
    // namespace — the fail-closed early-boot contract.
    #[test]
    fn d1_iso_unregistered_device_gate_admits_only_root_ns() {
        assert!(
            netns_owns_device(0, 0),
            "unregistered gate must admit the root namespace"
        );
        assert!(
            !netns_owns_device(1, 0),
            "unregistered gate must deny child namespace 1"
        );
        assert!(
            !netns_owns_device(u64::MAX, 7),
            "unregistered gate must deny arbitrary namespace ids"
        );
    }

    // Host socket tests link the production `security` dependency without the
    // kernel linker script.  Supply inert section-boundary symbols so the test
    // binary can link; none of the socket tests execute the hardening routines
    // that interpret these addresses.
    #[unsafe(no_mangle)]
    static kernel_start: u8 = 0;
    #[unsafe(no_mangle)]
    static text_start: u8 = 0;
    #[unsafe(no_mangle)]
    static text_end: u8 = 0;
    #[unsafe(no_mangle)]
    static rodata_start: u8 = 0;
    #[unsafe(no_mangle)]
    static rodata_end: u8 = 0;
    #[unsafe(no_mangle)]
    static data_start: u8 = 0;
    #[unsafe(no_mangle)]
    static data_end: u8 = 0;
    #[unsafe(no_mangle)]
    static bss_start: u8 = 0;
    #[unsafe(no_mangle)]
    static bss_end: u8 = 0;
    #[unsafe(no_mangle)]
    static kernel_end: u8 = 0;

    fn test_socket(id: u64, ty: SocketType, proto: SocketProtocol) -> SocketArc {
        test_socket_in_ns(id, ty, proto, NamespaceId(0))
    }

    fn test_socket_in_ns(
        id: u64,
        ty: SocketType,
        proto: SocketProtocol,
        namespace: NamespaceId,
    ) -> SocketArc {
        mm::publish_heap_budgets();
        SocketState::try_new_arc(
            id,
            SocketDomain::Inet4,
            ty,
            proto,
            SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            },
            namespace,
        )
        .expect("hosted socket admission")
    }

    #[test]
    fn deferred_port_uncharges_do_not_alias_empty_sentinel() {
        let mut pending = DeferredPortUncharges::new();

        assert!(pending.get(&0).is_none());
        pending.enqueue(0, 7);
        pending.enqueue(7, 0);
        assert!(pending.is_empty());

        pending.enqueue(7, 2);
        pending.enqueue(7, 3);
        assert_eq!(pending.get(&7).copied(), Some(5));
        assert_eq!(pending.take_one(), Some((7, 5)));
        assert!(pending.is_empty());
        assert_eq!(pending.take_one(), None);
    }

    #[test]
    fn rf180_25_socket_arc_charge_outlives_payload_until_control_block_free() {
        let sock = test_socket(0x1800, SocketType::Dgram, SocketProtocol::Udp);
        let allocator = *Arc::allocator(&sock);
        assert!(allocator.charge_is_live_for_test());
        assert_eq!(sock.net_ns_id, NamespaceId(0));
        let weak = Arc::downgrade(&sock);
        drop(sock);
        assert!(
            allocator.charge_is_live_for_test(),
            "payload drop must not release the Arc control-block charge"
        );
        drop(weak);
        assert!(
            !allocator.charge_is_live_for_test(),
            "final Weak drop must deallocate then release the charge"
        );
    }

    #[test]
    fn rf180_25_socket_arc_allocator_capability_is_single_use() {
        let sock = test_socket(0x1801, SocketType::Dgram, SocketProtocol::Udp);
        let allocator = *Arc::allocator(&sock);
        let layout = Layout::from_size_align(64, 8).expect("valid test layout");

        assert!(
            Allocator::allocate(&allocator, layout).is_err(),
            "a copied Arc allocator capability must not allocate uncharged backing"
        );
        assert!(allocator.charge_is_live_for_test());
        assert_eq!(sock.net_ns_id, NamespaceId(0));

        let weak = Arc::downgrade(&sock);
        drop(sock);
        assert!(allocator.charge_is_live_for_test());
        drop(weak);
        assert!(!allocator.charge_is_live_for_test());
    }

    #[test]
    fn rf180_25_standalone_wait_queue_uses_control_block_lifetime_charge() {
        mm::publish_heap_budgets();
        let queue = WaitQueue::try_new_arc().expect("standalone wait-queue admission");
        let allocator = *Arc::allocator(&queue);
        let weak = Arc::downgrade(&queue);
        drop(queue);
        assert!(allocator.charge_is_live_for_test());
        drop(weak);
        assert!(!allocator.charge_is_live_for_test());
    }

    #[test]
    fn r180_registry_fault_rolls_back_quota_id_and_publication() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        table.sockets.write().fail_next_growth_for_test();
        let label = SocketLabel {
            creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
            secmark: 0,
        };
        assert!(matches!(
            table.create_udp_socket(label, NamespaceId(41)),
            Err(SocketError::NoMemory)
        ));
        assert!(table.sockets.read().is_empty());
        assert!(table.per_ns_counts.lock().is_empty());
        assert_eq!(table.next_socket_id.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rf180_36_stale_tcp_owner_cannot_remove_same_tuple_replacement() {
        let _counter_guard = lock_test_tcp_counters();
        test_reset_counters();
        let table = SocketTable::new();
        let namespace = NamespaceId(0x1836);
        let local_ip = Ipv4Addr([10, 36, 0, 1]);
        let remote_ip = Ipv4Addr([10, 36, 0, 2]);
        let key = tcp_map_key_from_parts(namespace, local_ip, 31_836, remote_ip, 41_836);
        let stale = test_socket_in_ns(
            0x1836_01,
            SocketType::Stream,
            SocketProtocol::Tcp,
            namespace,
        );
        let replacement = test_socket_in_ns(
            0x1836_02,
            SocketType::Stream,
            SocketProtocol::Tcp,
            namespace,
        );

        let publish_owner = |owner: &SocketArc| {
            let mut conns = table.tcp_conns.lock();
            conns
                .ensure_capacity_for(1)
                .expect("TCP registry admission");
            table
                .try_inc_ns_conn(namespace)
                .expect("namespace connection admission");
            conns
                .insert_unique_reserved(key, Arc::downgrade(owner))
                .expect("exact TCP owner publication");
            assert!(try_inc_active_conn(), "global active admission");
            owner.counted_in_active.store(true, Ordering::Release);
        };

        // First teardown releases the old owner and clears its exactly-once bit.
        publish_owner(&stale);
        assert!(table.remove_tcp_conn_exact_owner(key, &stale));
        assert!(!stale.counted_in_active.load(Ordering::Acquire));
        assert!(table.tcp_conns.lock().is_empty());
        assert!(!table.per_ns_conn_counts.lock().contains_key(&namespace));
        assert_eq!(test_get_active_conn_count(), 0);

        // Reuse the tuple, then replay stale cleanup from the old socket. The
        // replacement and both of its accounting dimensions must survive.
        publish_owner(&replacement);
        assert!(!table.remove_tcp_conn_exact_owner(key, &stale));
        assert!(
            table
                .tcp_conns
                .lock()
                .get(&key)
                .and_then(|weak| weak.upgrade())
                .map_or(false, |owner| Arc::ptr_eq(&owner, &replacement)),
            "stale cleanup removed the replacement owner"
        );
        assert_eq!(
            table.per_ns_conn_counts.lock().get(&namespace).copied(),
            Some(1)
        );
        assert!(replacement.counted_in_active.load(Ordering::Acquire));
        assert_eq!(test_get_active_conn_count(), 1);

        // The exact replacement owner releases the same counters once; a
        // duplicate cleanup is inert.
        assert!(table.remove_tcp_conn_exact_owner(key, &replacement));
        assert!(!table.remove_tcp_conn_exact_owner(key, &replacement));
        assert!(!replacement.counted_in_active.load(Ordering::Acquire));
        assert!(table.tcp_conns.lock().is_empty());
        assert!(!table.per_ns_conn_counts.lock().contains_key(&namespace));
        assert_eq!(test_get_active_conn_count(), 0);

        // A dead Weak is not a live owner and remains the responsibility of the
        // accounted stale-entry reaper; the exact-owner funnel must not consume
        // it or bypass the reaper's namespace uncharge.
        let dead = test_socket_in_ns(
            0x1836_03,
            SocketType::Stream,
            SocketProtocol::Tcp,
            namespace,
        );
        let dead_weak = Arc::downgrade(&dead);
        drop(dead);
        {
            let mut conns = table.tcp_conns.lock();
            table
                .try_inc_ns_conn(namespace)
                .expect("dead-Weak namespace admission");
            conns
                .insert_unique_reserved(key, dead_weak)
                .expect("dead-Weak registry publication");
        }
        assert!(!table.remove_tcp_conn_exact_owner(key, &stale));
        assert!(table.tcp_conns.lock().contains_key(&key));
        assert_eq!(
            table.per_ns_conn_counts.lock().get(&namespace).copied(),
            Some(1)
        );
        {
            let mut conns = table.tcp_conns.lock();
            table.conns_retain_accounted(&mut conns);
        }
        assert!(table.tcp_conns.lock().is_empty());
        assert!(!table.per_ns_conn_counts.lock().contains_key(&namespace));
    }

    #[test]
    fn r180_passive_syn_oom_has_no_counter_or_publication_drift() {
        let _counter_guard = lock_test_tcp_counters();
        test_reset_counters();
        let table = SocketTable::new();
        let namespace = NamespaceId(42);
        let child = test_socket_in_ns(0x1801, SocketType::Stream, SocketProtocol::Tcp, namespace);
        child
            .attach_tcp(TcpControlBlock::new_server(
                Ipv4Addr([10, 0, 0, 1]),
                8080,
                Ipv4Addr([10, 0, 0, 2]),
                40000,
                1,
                2,
            ))
            .expect("passive child waiter admission");
        let mut listen = TcpListenState::try_new(8).expect("listen waiter admission");
        listen.syn_queue.fail_next_growth_for_test();
        let key = (namespace, 0x0a00_0001, 8080, 0x0a00_0002, 40000);
        let pending = PendingSyn {
            key,
            sock: child,
            syn_ack: WirePacket::try_copy_from_slice(&[1, 2, 3, 4])
                .expect("cached SYN-ACK admission"),
            syn_sent_at: 0,
        };
        assert!(!listen.queue_syn(pending, &table));
        assert!(listen.syn_queue.is_empty());
        assert_eq!(test_get_half_open_count(), 0);
        assert!(!table.per_ns_syn_counts.lock().contains_key(&namespace));
    }

    #[test]
    fn rf180_7_passive_syn_ack_build_failure_precedes_all_publication() {
        let _counter_guard = lock_test_tcp_counters();
        test_reset_counters();
        let table = SocketTable::new();
        let namespace = NamespaceId(0x1807);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let local_port = 8080;
        let remote_port = 40_000;
        let listener = test_socket_in_ns(99, SocketType::Stream, SocketProtocol::Tcp, namespace);
        listener.bind_local(local_ip, local_port);
        listener
            .attach_tcp(TcpControlBlock::new_listen(local_ip, local_port))
            .expect("listener waiter admission");
        listener.install_listen_state(TcpListenState::try_new(8).expect("listen admission"));
        {
            let mut bindings = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(
                &mut bindings,
                (namespace, local_port),
                &listener,
                0,
                BindKind::Explicit,
            );
        }

        table
            .fail_next_passive_syn_ack_build
            .store(true, Ordering::Release);
        let header = TcpHeader::new(
            remote_port,
            local_port,
            100,
            0,
            TCP_FLAG_SYN,
            TCP_DEFAULT_WINDOW,
        );
        let options = TcpOptions {
            mss: Some(TCP_ETHERNET_MSS),
            window_scale: Some(2),
            sack_permitted: true,
            ..TcpOptions::default()
        };
        assert!(table
            .process_tcp_segment(
                namespace,
                remote_ip,
                local_ip,
                &header,
                &[],
                &options,
                &mut None,
                &mut false,
            )
            .is_none());

        assert_eq!(table.next_socket_id.load(Ordering::Relaxed), 1);
        assert!(table.sockets.read().is_empty());
        assert!(table.tcp_conns.lock().is_empty());
        assert!(table.per_ns_counts.lock().is_empty());
        assert!(table.per_ns_conn_counts.lock().is_empty());
        assert!(table.per_ns_syn_counts.lock().is_empty());
        assert_eq!(test_get_half_open_count(), 0);
        assert_eq!(test_get_active_conn_count(), 0);
        let listen = listener.listen.lock();
        assert!(listen.as_ref().unwrap().syn_queue.is_empty());
        assert!(listen.as_ref().unwrap().accept_queue.is_empty());
    }

    #[test]
    fn rf180_7_simultaneous_open_build_failure_preserves_complete_tcb() {
        let table = SocketTable::new();
        let namespace = NamespaceId(0x1808);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let local_port = 30_000;
        let remote_port = 40_000;
        let sock = test_socket_in_ns(0x1808, SocketType::Stream, SocketProtocol::Tcp, namespace);
        sock.bind_local(local_ip, local_port);
        sock.set_remote(remote_ip, remote_port);

        let mut tcb = TcpControlBlock::new_client(local_ip, local_port, remote_ip, remote_port, 77);
        tcb.state = TcpState::SynSent;
        tcb.snd_nxt = tcb.iss.wrapping_add(1);
        tcb.irs = 7;
        tcb.rcv_nxt = 8;
        tcb.snd_wscale = 0;
        tcb.rcv_wscale = 3;
        tcb.wscale_requested = true;
        tcb.wscale_received = false;
        tcb.sack_requested = true;
        tcb.sack_received = false;
        tcb.snd_wnd = 9;
        tcb.snd_wl1 = 10;
        let before = (
            tcb.state,
            tcb.irs,
            tcb.rcv_nxt,
            tcb.snd_wscale,
            tcb.wscale_received,
            tcb.sack_received,
            tcb.snd_mss,
            tcb.cwnd,
            tcb.snd_wnd,
            tcb.snd_wl1,
        );
        sock.attach_tcp(tcb)
            .expect("simultaneous-open waiter admission");

        let key = tcp_map_key_from_parts(namespace, local_ip, local_port, remote_ip, remote_port);
        {
            let mut conns = table.tcp_conns.lock();
            conns
                .ensure_capacity_for(1)
                .expect("connection-map admission");
            conns
                .insert_unique_reserved(key, Arc::downgrade(&sock))
                .expect("simultaneous-open publication");
        }

        let header = TcpHeader::new(
            remote_port,
            local_port,
            0x1234_5678,
            0,
            TCP_FLAG_SYN,
            32_000,
        );
        let options = TcpOptions {
            mss: Some(TCP_ETHERNET_MSS),
            window_scale: Some(9),
            sack_permitted: true,
            ..TcpOptions::default()
        };

        table
            .fail_next_simultaneous_syn_ack_build
            .store(true, Ordering::Release);
        assert!(table
            .process_tcp_segment(
                namespace,
                remote_ip,
                local_ip,
                &header,
                &[],
                &options,
                &mut None,
                &mut false,
            )
            .is_none());
        {
            let guard = sock.tcp.lock();
            let control = &guard
                .as_ref()
                .expect("TCB retained after build failure")
                .control;
            assert_eq!(
                (
                    control.state,
                    control.irs,
                    control.rcv_nxt,
                    control.snd_wscale,
                    control.wscale_received,
                    control.sack_received,
                    control.snd_mss,
                    control.cwnd,
                    control.snd_wnd,
                    control.snd_wl1,
                ),
                before,
                "failed SYN-ACK preparation must not leave stale negotiation state"
            );
        }

        let mut reply_binding = None;
        let syn_ack = table
            .process_tcp_segment(
                namespace,
                remote_ip,
                local_ip,
                &header,
                &[],
                &options,
                &mut reply_binding,
                &mut false,
            )
            .expect("retransmitted peer SYN must retry SYN-ACK preparation");
        assert!(!syn_ack.is_empty());
        let syn_ack_header =
            crate::tcp::parse_tcp_header(&syn_ack).expect("prepared simultaneous SYN-ACK parses");
        {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().expect("TCB retained before commit").control;
            assert_eq!(control.state, TcpState::SynSent);
            assert!(control.pending_handshake.is_some());
        }
        let mut operation = table
            .lock_tcp_reply_operation(
                reply_binding
                    .as_ref()
                    .expect("simultaneous SYN-ACK has an identity binding"),
                &syn_ack_header,
            )
            .expect("simultaneous SYN-ACK binding remains current");
        assert!(operation.commit(&syn_ack_header, 0));
        drop(operation);
        let guard = sock.tcp.lock();
        let control = &guard.as_ref().expect("TCB retained after retry").control;
        assert_eq!(control.state, TcpState::SynReceived);
        assert_eq!(control.irs, header.seq_num);
        assert_eq!(control.rcv_nxt, header.seq_num.wrapping_add(1));
        assert_eq!(control.snd_wscale, 9);
        assert!(control.wscale_received);
        assert!(control.sack_received);
        assert_eq!(control.snd_mss, TCP_ETHERNET_MSS);
        assert_eq!(control.snd_wnd, decode_window(header.window, 0));
        assert_eq!(control.snd_wl1, header.seq_num);
    }

    #[test]
    fn rf180_41_active_syn_ack_admission_failure_preserves_syn_sent_transaction() {
        let table = SocketTable::new();
        let namespace = NamespaceId(0x1841);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let local_port = 30_041;
        let remote_port = 40_041;
        let sock = test_socket_in_ns(0x1841, SocketType::Stream, SocketProtocol::Tcp, namespace);
        sock.bind_local(local_ip, local_port);
        sock.set_remote(remote_ip, remote_port);

        let mut tcb = TcpControlBlock::new_client(local_ip, local_port, remote_ip, remote_port, 77);
        tcb.state = TcpState::SynSent;
        tcb.snd_nxt = tcb.iss.wrapping_add(1);
        tcb.rcv_wscale = 3;
        tcb.wscale_requested = true;
        tcb.sack_requested = true;
        let before_handshake = (
            tcb.state,
            tcb.irs,
            tcb.rcv_nxt,
            tcb.snd_una,
            tcb.snd_wscale,
            tcb.wscale_received,
            tcb.sack_received,
            tcb.snd_mss,
            tcb.cwnd,
        );
        let before_windows = (tcb.snd_wnd, tcb.snd_wl1, tcb.snd_wl2, tcb.rcv_wnd);
        let expected_ack = tcb.snd_nxt;
        sock.attach_tcp(tcb)
            .expect("active-handshake waiter admission");

        let key = tcp_map_key_from_parts(namespace, local_ip, local_port, remote_ip, remote_port);
        {
            let mut conns = table.tcp_conns.lock();
            conns
                .ensure_capacity_for(1)
                .expect("connection-map admission");
            conns
                .insert_unique_reserved(key, Arc::downgrade(&sock))
                .expect("active-handshake publication");
        }

        let header = TcpHeader::new(
            remote_port,
            local_port,
            0x1234_5678,
            expected_ack,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            32_000,
        );
        let options = TcpOptions {
            mss: Some(TCP_ETHERNET_MSS),
            window_scale: Some(9),
            sack_permitted: true,
            ..TcpOptions::default()
        };

        WirePacket::fail_next_admission_for_test();
        assert!(table
            .process_tcp_segment(
                namespace,
                remote_ip,
                local_ip,
                &header,
                &[],
                &options,
                &mut None,
                &mut false,
            )
            .is_none());
        {
            let guard = sock.tcp.lock();
            let control = &guard
                .as_ref()
                .expect("TCB retained after final-ACK allocation failure")
                .control;
            assert_eq!(
                (
                    control.state,
                    control.irs,
                    control.rcv_nxt,
                    control.snd_una,
                    control.snd_wscale,
                    control.wscale_received,
                    control.sack_received,
                    control.snd_mss,
                    control.cwnd,
                ),
                before_handshake,
                "failed final-ACK preparation must leave SYN-SENT retryable"
            );
            assert_eq!(
                (
                    control.snd_wnd,
                    control.snd_wl1,
                    control.snd_wl2,
                    control.rcv_wnd,
                ),
                before_windows,
                "failed final-ACK preparation must preserve window state"
            );
        }

        let mut reply_binding = None;
        let ack = table
            .process_tcp_segment(
                namespace,
                remote_ip,
                local_ip,
                &header,
                &[],
                &options,
                &mut reply_binding,
                &mut false,
            )
            .expect("retransmitted SYN-ACK must retry final-ACK preparation");
        let ack_header = crate::tcp::parse_tcp_header(&ack).expect("prepared final ACK parses");
        assert_eq!(ack_header.flags, TCP_FLAG_ACK);
        assert_eq!(ack_header.ack_num, header.seq_num.wrapping_add(1));
        {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().expect("TCB retained before commit").control;
            assert_eq!(control.state, TcpState::SynSent);
            assert!(control.pending_handshake.is_some());
        }
        let mut operation = table
            .lock_tcp_reply_operation(
                reply_binding
                    .as_ref()
                    .expect("final ACK has an identity binding"),
                &ack_header,
            )
            .expect("final ACK binding remains current");
        assert!(operation.commit(&ack_header, 0));
        drop(operation);
        let guard = sock.tcp.lock();
        let control = &guard
            .as_ref()
            .expect("TCB retained after handshake")
            .control;
        assert_eq!(control.state, TcpState::Established);
        assert_eq!(control.rcv_nxt, header.seq_num.wrapping_add(1));
        assert_eq!(control.snd_wscale, 9);
        assert!(control.wscale_received);
        assert!(control.sack_received);
    }

    #[test]
    fn rf180_41_fast_retransmit_admission_failure_preserves_retry_state() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 30_042, remote_ip, 40_042, 77);
        tcb.state = TcpState::Established;
        tcb.snd_una = 100;
        tcb.snd_nxt = 104;
        tcb.snd_wnd = 4096;
        tcb.dup_ack_count = 2;
        tcb.last_activity = 7;
        tcb.keepalive_probes_sent = 3;
        tcb.send_buffer
            .try_push(TcpSegment {
                seq: 100,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[1, 2, 3, 4])
                    .expect("fast-retransmit payload admission"),
                sent_at: 10,
                retrans_count: 0,
                sacked: false,
                lost: false,
                retransmit_pending: false,
                retransmit_in_flight: false,
                retransmit_requires_rto: false,
                tx_reject_count: 0,
                retry_not_before_ms: 0,
            })
            .map_err(|_| ())
            .expect("fast-retransmit queue admission");
        tcb.send_buffer_bytes = 4;
        let congestion_before = (
            tcb.cwnd,
            tcb.ssthresh,
            tcb.dup_ack_count,
            tcb.congestion_state,
            tcb.recover,
        );

        WirePacket::fail_next_admission_for_test();
        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            100,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_042,
            40_042,
            20,
            &[],
            false,
            4096,
            |_| panic!("allocation failure must not reach the queue closure"),
        );
        assert!(!queued);
        assert!(!limited);
        assert_eq!(
            (
                tcb.cwnd,
                tcb.ssthresh,
                tcb.dup_ack_count,
                tcb.congestion_state,
                tcb.recover,
            ),
            congestion_before,
            "failed fast-retransmit preparation must remain retriggerable"
        );
        let segment = tcb
            .send_buffer
            .front()
            .expect("retransmit segment retained");
        assert_eq!(segment.retrans_count, 0);
        assert_eq!(segment.sent_at, 10);
        assert!(!segment.retransmit_pending);
        assert_eq!(
            tcb.last_activity, 20,
            "the received ACK remains valid inbound activity"
        );
        assert_eq!(
            tcb.keepalive_probes_sent, 0,
            "a peer ACK must still clear keepalive probes"
        );

        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            100,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_042,
            40_042,
            21,
            &[],
            false,
            4096,
            |_| true,
        );
        assert!(queued, "next duplicate ACK must retry retransmit");
        assert!(!limited);
        let segment = tcb
            .send_buffer
            .front()
            .expect("retransmit segment retained");
        assert_eq!(segment.retrans_count, 1);
        assert_eq!(segment.sent_at, 21);
        assert!(!segment.retransmit_pending);
    }

    #[test]
    fn rf180_41_empty_send_buffer_duplicate_acks_cannot_poison_recovery() {
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 30_044, remote_ip, 40_044, 78);
        tcb.state = TcpState::Established;
        tcb.snd_una = 100;
        tcb.snd_nxt = 104;
        tcb.snd_wnd = 4096;
        tcb.dup_ack_count = 2;
        let congestion_before = (tcb.cwnd, tcb.ssthresh, tcb.congestion_state, tcb.recover);
        let queue_called = core::cell::Cell::new(false);

        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            100,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_044,
            40_044,
            20,
            &[],
            false,
            4096,
            |_| {
                queue_called.set(true);
                true
            },
        );

        assert!(!queued);
        assert!(!limited);
        assert!(!queue_called.get());
        assert_eq!(tcb.dup_ack_count, 0, "stale duplicate evidence is cleared");
        assert_eq!(
            (tcb.cwnd, tcb.ssthresh, tcb.congestion_state, tcb.recover,),
            congestion_before
        );
    }

    #[test]
    fn rf180_41_fast_retransmit_queue_rejection_preserves_metadata() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 30_045, remote_ip, 40_045, 79);
        tcb.state = TcpState::Established;
        tcb.snd_una = 100;
        tcb.snd_nxt = 104;
        tcb.snd_wnd = 4096;
        tcb.dup_ack_count = 2;
        tcb.send_buffer
            .try_push(TcpSegment {
                seq: 100,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[1, 2, 3, 4])
                    .expect("fast-retransmit payload admission"),
                sent_at: 10,
                retrans_count: 0,
                sacked: false,
                lost: false,
                retransmit_pending: false,
                retransmit_in_flight: false,
                retransmit_requires_rto: true,
                tx_reject_count: 0,
                retry_not_before_ms: 0,
            })
            .map_err(|_| ())
            .expect("fast-retransmit queue admission");
        tcb.send_buffer_bytes = 4;
        let congestion_before = (
            tcb.cwnd,
            tcb.ssthresh,
            tcb.dup_ack_count,
            tcb.congestion_state,
            tcb.recover,
        );
        let queue_called = core::cell::Cell::new(false);

        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            100,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_045,
            40_045,
            20,
            &[],
            false,
            4096,
            |_| {
                queue_called.set(true);
                false
            },
        );

        assert!(!queued);
        assert!(!limited);
        assert!(queue_called.get());
        assert_eq!(
            (
                tcb.cwnd,
                tcb.ssthresh,
                tcb.dup_ack_count,
                tcb.congestion_state,
                tcb.recover,
            ),
            congestion_before,
            "QueueFull cannot publish Fast Recovery"
        );
        let segment = tcb.send_buffer.front().expect("segment retained");
        assert!(segment.retransmit_pending);
        assert!(segment.retransmit_requires_rto);
        assert!(!segment.retransmit_in_flight);
        assert_eq!(segment.retrans_count, 0);
        assert_eq!(segment.sent_at, 10);
    }

    #[test]
    fn rf180_41_newreno_partial_ack_allocation_failure_retries_pending_segment() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 30_043, remote_ip, 40_043, 77);
        tcb.state = TcpState::Established;
        tcb.congestion_state = crate::tcp::TcpCongestionState::FastRecovery;
        tcb.snd_una = 100;
        tcb.snd_nxt = 108;
        tcb.recover = 108;
        tcb.snd_wnd = 4096;

        for (seq, bytes) in [(100, &[1u8, 2, 3, 4][..]), (104, &[5u8, 6, 7, 8][..])] {
            tcb.send_buffer
                .try_push(TcpSegment {
                    seq,
                    data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, bytes)
                        .expect("NewReno payload admission"),
                    sent_at: 10,
                    retrans_count: 0,
                    sacked: false,
                    lost: false,
                    retransmit_pending: false,
                    retransmit_in_flight: false,
                    retransmit_requires_rto: false,
                    tx_reject_count: 0,
                    retry_not_before_ms: 0,
                })
                .map_err(|_| ())
                .expect("NewReno queue admission");
        }
        tcb.send_buffer_bytes = 8;

        WirePacket::fail_next_admission_for_test();
        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            104,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_043,
            40_043,
            20,
            &[],
            false,
            4096,
            |_| panic!("allocation failure must not reach the queue closure"),
        );
        assert!(!queued);
        assert!(!limited);
        assert_eq!(tcb.snd_una, 104, "valid partial-ACK progress is retained");
        assert_eq!(tcb.send_buffer.len(), 1);
        let pending = tcb.send_buffer.front().expect("remaining NewReno segment");
        assert_eq!(pending.seq, 104);
        assert!(pending.retransmit_pending);
        assert_eq!(pending.retrans_count, 0);
        assert_eq!(pending.sent_at, 10);

        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            104,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_043,
            40_043,
            21,
            &[],
            false,
            4096,
            |_| true,
        );
        assert!(queued, "the next ACK must retry pending NewReno work");
        assert!(!limited);
        let retried = tcb.send_buffer.front().expect("retried NewReno segment");
        assert!(!retried.retransmit_pending);
        assert_eq!(retried.retrans_count, 1);
        assert_eq!(retried.sent_at, 21);
    }

    #[test]
    fn rf180_41_newreno_queue_rejection_preserves_retransmit_metadata() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 30_046, remote_ip, 40_046, 80);
        tcb.state = TcpState::Established;
        tcb.congestion_state = crate::tcp::TcpCongestionState::FastRecovery;
        tcb.snd_una = 100;
        tcb.snd_nxt = 108;
        tcb.recover = 108;
        tcb.snd_wnd = 4096;
        for (seq, bytes) in [(100, &[1u8, 2, 3, 4][..]), (104, &[5u8, 6, 7, 8][..])] {
            tcb.send_buffer
                .try_push(TcpSegment {
                    seq,
                    data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, bytes)
                        .expect("NewReno payload admission"),
                    sent_at: 10,
                    retrans_count: 0,
                    sacked: false,
                    lost: false,
                    retransmit_pending: false,
                    retransmit_in_flight: false,
                    retransmit_requires_rto: false,
                    tx_reject_count: 0,
                    retry_not_before_ms: 0,
                })
                .map_err(|_| ())
                .expect("NewReno queue admission");
        }
        tcb.send_buffer_bytes = 8;

        let (queued, limited) = table.apply_ack_and_cc(
            &mut tcb,
            104,
            TCP_DEFAULT_WINDOW,
            local_ip,
            remote_ip,
            30_046,
            40_046,
            20,
            &[],
            false,
            4096,
            |_| false,
        );

        assert!(!queued);
        assert!(!limited);
        assert_eq!(tcb.snd_una, 104, "the peer's valid ACK remains committed");
        assert_eq!(tcb.send_buffer.len(), 1);
        let segment = tcb.send_buffer.front().expect("remaining segment retained");
        assert_eq!(segment.seq, 104);
        assert!(segment.retransmit_pending);
        assert!(!segment.retransmit_in_flight);
        assert_eq!(segment.retrans_count, 0);
        assert_eq!(segment.sent_at, 10);
    }

    #[test]
    fn rf180_41_timer_queue_rejection_preserves_data_fin_and_keepalive_metadata() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);

        let data_sock = test_socket(0x1804_4101, SocketType::Stream, SocketProtocol::Tcp);
        let mut data_tcb = TcpControlBlock::new_client(local_ip, 31_001, remote_ip, 41_001, 81);
        data_tcb.state = TcpState::Established;
        data_tcb.peer_ack_generation = 7;
        data_tcb.retries = 2;
        data_tcb.rto_ms = 500;
        data_tcb.last_activity = 9;
        data_tcb
            .send_buffer
            .try_push(TcpSegment {
                seq: 100,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[1, 2, 3, 4])
                    .expect("timer payload admission"),
                sent_at: 10,
                retrans_count: 0,
                sacked: false,
                lost: false,
                retransmit_pending: true,
                retransmit_in_flight: true,
                retransmit_requires_rto: true,
                tx_reject_count: 0,
                retry_not_before_ms: 0,
            })
            .map_err(|_| ())
            .expect("timer segment admission");
        data_tcb.send_buffer_bytes = 4;
        let data_cwnd = data_tcb.cwnd;
        data_sock.attach_tcp(data_tcb).expect("attach data TCB");
        assert!(!table.finish_data_retransmit_with_queue(
            DataRetransmitWork {
                sock: data_sock.clone(),
                dst_ip: remote_ip,
                packet: WirePacket::try_copy_from_slice(&[0xaa; 20])
                    .expect("data work packet admission"),
                net_ns_id: 0,
                seq: 100,
                ack_generation: 7,
            },
            20,
            |_, _, _| false,
        ));
        {
            let guard = data_sock.tcp.lock();
            let control = &guard.as_ref().expect("data TCB retained").control;
            let segment = control.send_buffer.front().expect("data segment retained");
            assert!(segment.retransmit_pending);
            assert!(!segment.retransmit_in_flight);
            assert!(segment.retransmit_requires_rto);
            assert_eq!(segment.sent_at, 10);
            assert_eq!(segment.retrans_count, 0);
            assert_eq!(control.retries, 2);
            assert_eq!(control.rto_ms, 500);
            assert_eq!(control.cwnd, data_cwnd);
            assert_eq!(control.last_activity, 9);
        }

        let fin_sock = test_socket(0x1804_4102, SocketType::Stream, SocketProtocol::Tcp);
        let mut fin_tcb = TcpControlBlock::new_client(local_ip, 31_002, remote_ip, 41_002, 82);
        fin_tcb.state = TcpState::FinWait1;
        fin_tcb.fin_sent = true;
        fin_tcb.fin_retransmit_in_flight = true;
        fin_tcb.fin_retries = 3;
        fin_tcb.fin_sent_time = 11;
        fin_sock.attach_tcp(fin_tcb).expect("attach FIN TCB");
        assert!(!table.finish_fin_retransmit_with_queue(
            FinRetransmitWork {
                sock: fin_sock.clone(),
                dst_ip: remote_ip,
                packet: WirePacket::try_copy_from_slice(&[0xbb; 20])
                    .expect("FIN work packet admission"),
                net_ns_id: 0,
            },
            21,
            |_, _, _| false,
        ));
        {
            let guard = fin_sock.tcp.lock();
            let control = &guard.as_ref().expect("FIN TCB retained").control;
            assert!(!control.fin_retransmit_in_flight);
            assert_eq!(control.fin_retries, 3);
            assert_eq!(control.fin_sent_time, 11);
        }

        let keepalive_sock = test_socket(0x1804_4103, SocketType::Stream, SocketProtocol::Tcp);
        let mut keepalive_tcb =
            TcpControlBlock::new_client(local_ip, 31_003, remote_ip, 41_003, 83);
        keepalive_tcb.state = TcpState::Established;
        keepalive_tcb.keepalive_enabled = true;
        keepalive_tcb.keepalive_probe_in_flight = true;
        keepalive_tcb.keepalive_probes_sent = 2;
        keepalive_tcb.peer_ack_generation = 9;
        keepalive_sock
            .attach_tcp(keepalive_tcb)
            .expect("attach keepalive TCB");
        assert!(!table.finish_keepalive_with_queue(
            KeepaliveWork {
                sock: keepalive_sock.clone(),
                dst_ip: remote_ip,
                packet: WirePacket::try_copy_from_slice(&[0xcc; 20])
                    .expect("keepalive work packet admission"),
                net_ns_id: 0,
                ack_generation: 9,
            },
            |_, _, _| false,
        ));
        let guard = keepalive_sock.tcp.lock();
        let control = &guard.as_ref().expect("keepalive TCB retained").control;
        assert!(!control.keepalive_probe_in_flight);
        assert_eq!(control.keepalive_probes_sent, 2);
    }

    #[test]
    fn rf180_41_peer_ack_generation_suppresses_false_rto_and_keepalive_publication() {
        mm::publish_heap_budgets();
        let table = SocketTable::new();
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);

        let data_sock = test_socket(0x1804_4111, SocketType::Stream, SocketProtocol::Tcp);
        let mut data_tcb = TcpControlBlock::new_client(local_ip, 31_011, remote_ip, 41_011, 84);
        data_tcb.state = TcpState::Established;
        data_tcb.peer_ack_generation = 2;
        data_tcb.retries = 4;
        data_tcb.rto_ms = 600;
        data_tcb
            .send_buffer
            .try_push(TcpSegment {
                seq: 200,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[5, 6, 7, 8])
                    .expect("ACK-race payload admission"),
                sent_at: 12,
                retrans_count: 0,
                sacked: false,
                lost: false,
                retransmit_pending: true,
                retransmit_in_flight: true,
                retransmit_requires_rto: true,
                tx_reject_count: 0,
                retry_not_before_ms: 0,
            })
            .map_err(|_| ())
            .expect("ACK-race segment admission");
        data_tcb.send_buffer_bytes = 4;
        let data_cwnd = data_tcb.cwnd;
        data_sock.attach_tcp(data_tcb).expect("attach ACK-race TCB");
        assert!(table.finish_data_retransmit_with_queue(
            DataRetransmitWork {
                sock: data_sock.clone(),
                dst_ip: remote_ip,
                packet: WirePacket::try_copy_from_slice(&[0xdd; 20])
                    .expect("ACK-race work packet admission"),
                net_ns_id: 0,
                seq: 200,
                ack_generation: 1,
            },
            30,
            |_, _, _| true,
        ));
        {
            let guard = data_sock.tcp.lock();
            let control = &guard.as_ref().expect("ACK-race TCB retained").control;
            let segment = control
                .send_buffer
                .front()
                .expect("ACK-race segment retained");
            assert_eq!(segment.retrans_count, 1);
            assert_eq!(segment.sent_at, 30);
            assert!(!segment.retransmit_pending);
            assert!(!segment.retransmit_requires_rto);
            assert_eq!(control.retries, 4, "peer ACK suppresses false RTO retry");
            assert_eq!(control.rto_ms, 600, "peer ACK suppresses false backoff");
            assert_eq!(
                control.cwnd, data_cwnd,
                "peer ACK suppresses false loss recovery"
            );
        }

        let keepalive_sock = test_socket(0x1804_4112, SocketType::Stream, SocketProtocol::Tcp);
        let mut keepalive_tcb =
            TcpControlBlock::new_client(local_ip, 31_012, remote_ip, 41_012, 85);
        keepalive_tcb.state = TcpState::Established;
        keepalive_tcb.keepalive_enabled = true;
        keepalive_tcb.keepalive_probe_in_flight = true;
        keepalive_tcb.keepalive_probes_sent = 0;
        keepalive_tcb.peer_ack_generation = 2;
        keepalive_sock
            .attach_tcp(keepalive_tcb)
            .expect("attach keepalive ACK-race TCB");
        assert!(table.finish_keepalive_with_queue(
            KeepaliveWork {
                sock: keepalive_sock.clone(),
                dst_ip: remote_ip,
                packet: WirePacket::try_copy_from_slice(&[0xee; 20])
                    .expect("keepalive ACK-race work packet admission"),
                net_ns_id: 0,
                ack_generation: 1,
            },
            |_, _, _| true,
        ));
        let guard = keepalive_sock.tcp.lock();
        let control = &guard
            .as_ref()
            .expect("keepalive ACK-race TCB retained")
            .control;
        assert!(!control.keepalive_probe_in_flight);
        assert_eq!(control.keepalive_probes_sent, 0);
    }

    fn assert_timer_cleanup_reserve_failure_is_retryable<F>(
        state: TcpState,
        sweep_time_wait: bool,
        configure: F,
    ) where
        F: FnOnce(&mut TcpControlBlock),
    {
        let table = SocketTable::new();
        let sock = test_socket(0x1807, SocketType::Stream, SocketProtocol::Tcp);
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 1]),
            30_000,
            Ipv4Addr([10, 0, 0, 2]),
            40_000,
            1,
        );
        tcb.state = state;
        configure(&mut tcb);
        // RF180-25 FIX: timer eligibility depends on the socket metadata
        // 4-tuple, not merely the TCB key. The old keepalive case omitted this
        // publication and therefore never reached the fifth cleanup kind.
        sock.bind_local(tcb.key.local_ip, tcb.key.local_port);
        sock.set_remote(tcb.key.remote_ip, tcb.key.remote_port);
        sock.attach_tcp(tcb).expect("timer test waiter admission");
        {
            let mut sockets = table.sockets.write();
            sockets
                .ensure_capacity_for(1)
                .expect("timer registry admission");
            sockets
                .insert_unique_reserved(sock.id, sock.clone())
                .expect("timer socket publication");
        }

        table
            .fail_next_timer_cleanup_reserve
            .store(true, Ordering::Release);
        assert!(
            !table.run_tcp_timers_blocking(1_000_000, sweep_time_wait),
            "cleanup handoff OOM must preserve deferred retry"
        );
        assert_eq!(
            sock.tcp_state(),
            Some(state),
            "cleanup handoff OOM must not publish Closed"
        );
        assert!(table.sockets.read().contains_key(&sock.id));

        assert!(table.run_tcp_timers_blocking(1_000_000, sweep_time_wait));
        assert!(
            sock.tcp.lock().is_none(),
            "retry with a prepared handoff must complete cleanup"
        );
    }

    #[test]
    fn rf186_3_all_timer_cleanup_kinds_roll_back_on_worklist_oom() {
        let mut completed_cases = 0usize;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::TimeWait, true, |tcb| {
            tcb.time_wait_start = 1;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::FinWait2, true, |tcb| {
            tcb.fin_wait2_start = 1;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::FinWait1, false, |tcb| {
            tcb.fin_sent = true;
            tcb.fin_sent_time = 1;
            tcb.fin_retries = TCP_MAX_FIN_RETRIES;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::Established, false, |tcb| {
            tcb.retries = TCP_MAX_RETRIES;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::Established, false, |tcb| {
            tcb.keepalive_enabled = true;
            tcb.keepalive_idle_ms = 1;
            tcb.keepalive_interval_ms = 1;
            tcb.keepalive_probes_sent = tcb.keepalive_probes_max;
            tcb.last_activity = 1;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::SynSent, false, |tcb| {
            tcb.last_activity = 1;
            tcb.passive_open = false;
        });
        completed_cases += 1;
        assert_timer_cleanup_reserve_failure_is_retryable(TcpState::SynReceived, false, |tcb| {
            tcb.last_activity = 1;
            tcb.passive_open = false;
        });
        completed_cases += 1;
        assert_eq!(completed_cases, 7, "all timer cleanup classes must execute");
    }

    #[test]
    fn rf180_7_ack_and_fin_progress_win_before_timer_transaction() {
        let table = SocketTable::new();
        let sock = test_socket(0x1808, SocketType::Stream, SocketProtocol::Tcp);
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 1]),
            30_001,
            Ipv4Addr([10, 0, 0, 2]),
            40_001,
            1,
        );
        // Model an expired FIN_WAIT_2 observation followed by peer FIN progress
        // before the timer obtains the TCB transaction lock.
        tcb.state = TcpState::TimeWait;
        tcb.fin_wait2_start = 1;
        tcb.time_wait_start = 999_999;
        // Model a previously exhausted data timer whose ACK progress reset the
        // retry state before this transaction begins.
        tcb.retries = 0;
        tcb.last_activity = 999_999;
        sock.attach_tcp(tcb)
            .expect("timer progress waiter admission");
        {
            let mut sockets = table.sockets.write();
            sockets
                .ensure_capacity_for(1)
                .expect("timer registry admission");
            sockets
                .insert_unique_reserved(sock.id, sock.clone())
                .expect("timer socket publication");
        }

        assert!(table.run_tcp_timers_blocking(1_000_000, true));
        let guard = sock.tcp.lock();
        let live = &guard.as_ref().expect("progressed TCB must survive").control;
        assert_eq!(live.state, TcpState::TimeWait);
        assert_eq!(live.time_wait_start, 999_999);
        assert_eq!(live.retries, 0);
    }

    #[test]
    fn r180_stateful_passive_publication_rolls_back_id_and_all_accounting() {
        let _counter_guard = lock_test_tcp_counters();
        test_reset_counters();
        let table = SocketTable::new();
        let namespace = NamespaceId(43);

        // Occupy ID 1 without advancing the allocator. This injects the only
        // post-ID failure that the reserved publication path can encounter and
        // proves the rollback is exact while `sockets.write()` serializes IDs.
        let blocker = test_socket(1, SocketType::Dgram, SocketProtocol::Udp);
        {
            let mut sockets = table.sockets.write();
            sockets.ensure_capacity_for(1).expect("registry admission");
            sockets
                .insert_unique_reserved(1, blocker)
                .expect("ID blocker publication");
        }

        let child = test_socket_in_ns(0, SocketType::Stream, SocketProtocol::Tcp, namespace);
        child
            .attach_tcp(TcpControlBlock::new_server(
                Ipv4Addr([10, 0, 0, 1]),
                8080,
                Ipv4Addr([10, 0, 0, 2]),
                40000,
                1,
                2,
            ))
            .expect("passive child waiter admission");
        let mut listen = TcpListenState::try_new(8).expect("listen waiter admission");
        let key = (namespace, 0x0a00_0001, 8080, 0x0a00_0002, 40000);
        let cached =
            WirePacket::try_copy_from_slice(&[1, 2, 3, 4]).expect("cached SYN-ACK admission");

        assert!(!table.try_publish_pending_syn_child(&mut listen, key, child, cached, 0));
        assert_eq!(table.next_socket_id.load(Ordering::Relaxed), 1);
        assert_eq!(table.sockets.read().len(), 1);
        assert!(table.tcp_conns.lock().is_empty());
        assert!(listen.syn_queue.is_empty());
        assert!(table.per_ns_counts.lock().is_empty());
        assert!(table.per_ns_conn_counts.lock().is_empty());
        assert!(table.per_ns_syn_counts.lock().is_empty());
        assert_eq!(test_get_half_open_count(), 0);
    }

    #[test]
    fn r180_cookie_passive_publication_rolls_back_id_accept_and_active_count() {
        let _counter_guard = lock_test_tcp_counters();
        test_reset_counters();
        let table = SocketTable::new();
        let namespace = NamespaceId(44);
        let blocker = test_socket(1, SocketType::Dgram, SocketProtocol::Udp);
        {
            let mut sockets = table.sockets.write();
            sockets.ensure_capacity_for(1).expect("registry admission");
            sockets
                .insert_unique_reserved(1, blocker)
                .expect("ID blocker publication");
        }

        let listener = test_socket_in_ns(99, SocketType::Stream, SocketProtocol::Tcp, namespace);
        listener.install_listen_state(TcpListenState::try_new(8).expect("listen admission"));
        let child = test_socket_in_ns(0, SocketType::Stream, SocketProtocol::Tcp, namespace);
        let mut tcb = TcpControlBlock::new_server(
            Ipv4Addr([10, 0, 0, 1]),
            8080,
            Ipv4Addr([10, 0, 0, 2]),
            40000,
            1,
            2,
        );
        tcb.state = TcpState::Established;
        child
            .attach_tcp(tcb)
            .expect("cookie child waiter admission");
        let key = (namespace, 0x0a00_0001, 8080, 0x0a00_0002, 40000);

        assert!(!table.try_publish_cookie_child(&listener, key, child));
        assert_eq!(table.next_socket_id.load(Ordering::Relaxed), 1);
        assert_eq!(table.sockets.read().len(), 1);
        assert!(table.tcp_conns.lock().is_empty());
        let listen = listener.listen.lock();
        assert!(listen.as_ref().unwrap().accept_queue.is_empty());
        drop(listen);
        assert!(table.per_ns_counts.lock().is_empty());
        assert!(table.per_ns_conn_counts.lock().is_empty());
        assert_eq!(test_get_active_conn_count(), 0);
    }

    #[test]
    fn r180_listen_auto_bind_rollback_is_owner_checked_and_clears_metadata() {
        let table = SocketTable::new();
        let namespace = NamespaceId(45);
        let sock = test_socket_in_ns(77, SocketType::Stream, SocketProtocol::Tcp, namespace);
        let port = 49_152;
        sock.bind_local(Ipv4Addr([0, 0, 0, 0]), port);
        {
            let mut bindings = table.tcp_bindings.lock();
            bindings.ensure_capacity_for(1).expect("binding admission");
            assert!(bindings
                .insert_unique_reserved(
                    (namespace, port),
                    PortBinding {
                        sock: Arc::downgrade(&sock),
                        charged_cgroup: 0,
                        kind: BindKind::Ephemeral,
                    },
                )
                .is_ok());
        }

        table.rollback_listen_auto_bind_locked(&sock, port);
        assert!(!table.tcp_bindings.lock().contains_key(&(namespace, port)));
        assert_eq!(sock.local_port(), None);
        assert_eq!(sock.local_ip(), None);
    }

    #[test]
    fn r180_udp_queue_growth_dequeue_and_teardown_are_symmetric() {
        let table = SocketTable::new();
        let sock = test_socket(0x1802, SocketType::Dgram, SocketProtocol::Udp);
        assert!(sock.enqueue_rx(Ipv4Addr([10, 0, 0, 2]), 40000, &[0x5a; 128], 1,));
        let (queue_charge, payload_charge) = {
            let queue = sock.rx_queue.lock();
            (
                queue.charged_bytes_for_test(),
                queue.front().unwrap().data.charged_bytes_for_test(),
            )
        };
        assert!(queue_charge > 0 && payload_charge > 0);
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);
        let copied = table
            .recv_from_udp_with_commit(&sock, &current, CapId::INVALID, Some(0), |packet| {
                Ok::<usize, ()>(packet.data.len())
            })
            .expect("UDP dequeue commit");
        assert_eq!(copied, 128);
        let queue = sock.rx_queue.lock();
        assert!(queue.is_empty());
        assert_eq!(queue.charged_bytes_for_test(), queue_charge);
        drop(queue);
        drop(sock); // queue backing charge and socket charge release by RAII
    }

    #[test]
    fn r180_tcp_all_retained_queue_states_drop_cleanly() {
        let sock = test_socket(0x1803, SocketType::Stream, SocketProtocol::Tcp);
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 1]),
            1000,
            Ipv4Addr([10, 0, 0, 2]),
            2000,
            1,
        );
        tcb.send_buffer
            .try_push(TcpSegment {
                seq: 1,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[1, 2, 3])
                    .expect("send payload admission"),
                sent_at: 0,
                retrans_count: 0,
                sacked: false,
                lost: false,
                retransmit_pending: false,
                retransmit_in_flight: false,
                retransmit_requires_rto: false,
                tx_reject_count: 0,
                retry_not_before_ms: 0,
            })
            .map_err(|_| ())
            .expect("send queue admission");
        tcb.send_buffer_bytes = 3;
        tcb.recv_buffer
            .try_extend_from_slice(&[4, 5, 6])
            .expect("recv queue admission");
        tcb.ooo_queue
            .try_push(crate::tcp::OooSegment {
                seq: 10,
                data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, &[7, 8, 9])
                    .expect("OOO payload admission"),
                fin: false,
            })
            .map_err(|_| ())
            .expect("OOO queue admission");
        sock.attach_tcp(tcb).expect("TCP waiter admission");
        drop(sock);
    }

    #[test]
    fn r180_recv_gate_placeholder_is_removed_after_payload_growth_failure() {
        let table = SocketTable::new();
        let namespace = NamespaceId(46);
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr([10, 0, 0, 1]),
            1000,
            Ipv4Addr([10, 0, 0, 2]),
            2000,
            1,
        );

        tcb.recv_buffer.fail_next_growth_for_test();
        table
            .try_charge_ns_recv_gate(namespace, &tcb, 4)
            .expect("recv counter-slot admission");
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&namespace).copied(),
            Some(0)
        );
        assert!(tcb
            .recv_buffer
            .try_extend_from_slice(&[1, 2, 3, 4])
            .is_err());
        table.reconcile_ns_recv(namespace, &mut tcb);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&namespace));

        tcb.ooo_queue.fail_next_growth_for_test();
        table
            .try_charge_ns_recv_gate(namespace, &tcb, 4)
            .expect("OOO counter-slot admission");
        assert_eq!(tcb.ooo_insert(100, &[5, 6, 7, 8], false), 0);
        table.reconcile_ns_recv(namespace, &mut tcb);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&namespace));
    }

    fn assert_concurrent_bind_is_single_commit(ty: SocketType, proto: SocketProtocol) {
        const WORKERS: usize = 8;
        let table = Arc::new(SocketTable::new());
        let sock = test_socket(1, ty, proto);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();

        for worker in 0..WORKERS {
            let table = table.clone();
            let sock = sock.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                let port = 20_000 + worker as u16;
                barrier.wait();
                let current = ProcessCtx::new(worker + 1, worker + 1, 0, 0, 0, 0);
                let result = match proto {
                    SocketProtocol::Udp => table.bind_udp(
                        &sock,
                        &current,
                        CapId::INVALID,
                        Ipv4Addr([127, 0, 0, 1]),
                        Some(port),
                        true,
                        BindCharge::None,
                    ),
                    SocketProtocol::Tcp => table.bind_tcp(
                        &sock,
                        &current,
                        CapId::INVALID,
                        Ipv4Addr([127, 0, 0, 1]),
                        Some(port),
                        true,
                        BindCharge::None,
                    ),
                };
                (port, result)
            }));
        }

        let mut winner = None;
        for handle in handles {
            let (candidate, result) = handle.join().expect("bind worker panicked");
            match result {
                Ok(port) => {
                    assert_eq!(port, candidate);
                    assert!(
                        winner.replace(port).is_none(),
                        "more than one bind committed"
                    );
                }
                Err(SocketError::PortInUse) => {}
                Err(other) => panic!("unexpected bind result: {other:?}"),
            }
        }

        let winner = winner.expect("one bind must commit");
        let meta = sock.meta_snapshot();
        assert_eq!(meta.local_port, Some(winner));
        assert_eq!(meta.local_ip, Some([127, 0, 0, 1]));

        let owner_is_socket = match proto {
            SocketProtocol::Udp => {
                let bindings = table.udp_bindings.lock();
                assert_eq!(bindings.len(), 1, "losing UDP binds left ghost entries");
                bindings
                    .get(&(NamespaceId(0), winner))
                    .and_then(|binding| binding.sock.upgrade())
                    .map_or(false, |owner| Arc::ptr_eq(&owner, &sock))
            }
            SocketProtocol::Tcp => {
                let bindings = table.tcp_bindings.lock();
                assert_eq!(bindings.len(), 1, "losing TCP binds left ghost entries");
                bindings
                    .get(&(NamespaceId(0), winner))
                    .and_then(|binding| binding.sock.upgrade())
                    .map_or(false, |owner| Arc::ptr_eq(&owner, &sock))
            }
        };
        assert!(
            owner_is_socket,
            "committed binding does not match socket metadata"
        );
    }

    fn test_label() -> SocketLabel {
        SocketLabel {
            creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
            secmark: 0,
        }
    }

    fn arm_operation_commit_pause(table: &SocketTable, kind: u8) {
        table.test_operation_resume.store(false, Ordering::Release);
        table.test_operation_paused.store(false, Ordering::Release);
        table
            .test_operation_pause_kind
            .store(kind, Ordering::Release);
    }

    fn wait_for_operation_commit_pause(table: &SocketTable) {
        for _ in 0..1_000_000 {
            if table.test_operation_paused.load(Ordering::Acquire) {
                return;
            }
            thread::yield_now();
        }
        panic!("state operation did not reach deterministic commit pause");
    }

    fn resume_operation_commit(table: &SocketTable) {
        table.test_operation_resume.store(true, Ordering::Release);
    }

    fn assert_close_left_no_publication(
        table: &SocketTable,
        sock: &SocketArc,
        namespace: NamespaceId,
    ) {
        assert!(!table.sockets.read().contains_key(&sock.id));
        assert!(table.udp_bindings.lock().is_empty());
        assert!(table.tcp_bindings.lock().is_empty());
        assert!(table.tcp_conns.lock().is_empty());
        assert!(!table.per_ns_counts.lock().contains_key(&namespace));
        assert!(!table.per_ns_conn_counts.lock().contains_key(&namespace));
        assert!(!table.per_ns_syn_counts.lock().contains_key(&namespace));
        assert!(!table.per_ns_send_bytes.lock().contains_key(&namespace));
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&namespace));
        assert!(table.port_uncharge_pending.lock().is_empty());
        assert_eq!(sock.meta_snapshot(), SocketMeta::new());
        assert!(sock.tcp.lock().is_none());
        assert!(sock.listen.lock().is_none());
        assert!(sock.is_closed());
    }

    #[test]
    fn rf180_26_close_vs_bind_leaves_no_registry_metadata_or_quota_ghost() {
        mm::publish_heap_budgets();
        let table = Arc::new(SocketTable::new());
        let namespace = NamespaceId(0x1826_01);
        let sock = table
            .create_udp_socket(test_label(), namespace)
            .expect("close-vs-bind socket admission");
        arm_operation_commit_pause(&table, TEST_PAUSE_BIND_COMMIT);

        let worker_table = table.clone();
        let worker_sock = sock.clone();
        let worker = thread::spawn(move || {
            worker_table.bind_udp(
                &worker_sock,
                &ProcessCtx::new(2, 2, 0, 0, 0, 0),
                CapId::INVALID,
                Ipv4Addr([127, 0, 0, 1]),
                Some(31_026),
                true,
                BindCharge::None,
            )
        });

        wait_for_operation_commit_pause(&table);
        table.close(sock.id);
        resume_operation_commit(&table);
        let _ = worker.join().expect("close-vs-bind worker panicked");
        assert_close_left_no_publication(&table, &sock, namespace);
    }

    #[test]
    fn rf180_26_close_vs_connect_leaves_no_tuple_tcb_or_quota_ghost() {
        mm::publish_heap_budgets();
        let table = Arc::new(SocketTable::new());
        let namespace = NamespaceId(0x1826_02);
        let sock = table
            .create_tcp_socket(test_label(), namespace)
            .expect("close-vs-connect socket admission");
        arm_operation_commit_pause(&table, TEST_PAUSE_CONNECT_COMMIT);

        let worker_table = table.clone();
        let worker_sock = sock.clone();
        let worker = thread::spawn(move || {
            worker_table.connect(
                &worker_sock,
                &ProcessCtx::new(3, 3, 0, 0, 0, 0),
                CapId::INVALID,
                Ipv4Addr([10, 26, 0, 1]),
                Ipv4Addr([10, 26, 0, 2]),
                41_026,
                Some(0),
            )
        });

        wait_for_operation_commit_pause(&table);
        table.close(sock.id);
        resume_operation_commit(&table);
        assert!(matches!(
            worker.join().expect("close-vs-connect worker panicked"),
            Err(SocketError::Closed)
        ));
        assert_close_left_no_publication(&table, &sock, namespace);
    }

    #[test]
    fn rf180_26_close_vs_listen_leaves_no_binding_tcb_or_backlog_ghost() {
        mm::publish_heap_budgets();
        let table = Arc::new(SocketTable::new());
        let namespace = NamespaceId(0x1826_03);
        let sock = table
            .create_tcp_socket(test_label(), namespace)
            .expect("close-vs-listen socket admission");
        arm_operation_commit_pause(&table, TEST_PAUSE_LISTEN_COMMIT);

        let worker_table = table.clone();
        let worker_sock = sock.clone();
        let worker = thread::spawn(move || {
            worker_table.listen(
                &worker_sock,
                &ProcessCtx::new(4, 4, 0, 0, 0, 0),
                CapId::INVALID,
                16,
                true,
            )
        });

        wait_for_operation_commit_pause(&table);
        table.close(sock.id);
        resume_operation_commit(&table);
        let _ = worker.join().expect("close-vs-listen worker panicked");
        assert_close_left_no_publication(&table, &sock, namespace);
    }

    fn assert_shutdown_close_race_returns_committed_fin(
        initial_state: TcpState,
        expected_state: TcpState,
        namespace: NamespaceId,
    ) {
        mm::publish_heap_budgets();
        let table = Arc::new(SocketTable::new());
        let sock = table
            .create_tcp_socket(test_label(), namespace)
            .expect("shutdown-vs-close socket admission");
        let local_ip = Ipv4Addr([10, 27, 0, 1]);
        let remote_ip = Ipv4Addr([10, 27, 0, 2]);
        let local_port = 31_027;
        let remote_port = 41_027;
        sock.bind_local(local_ip, local_port);
        sock.set_remote(remote_ip, remote_port);

        let mut tcb =
            TcpControlBlock::new_client(local_ip, local_port, remote_ip, remote_port, 0x1800);
        tcb.state = initial_state;
        tcb.snd_nxt = 0x1801;
        tcb.rcv_nxt = 0x2801;
        sock.attach_tcp(tcb).expect("hosted TCP waiter admission");
        arm_operation_commit_pause(&table, TEST_PAUSE_SHUTDOWN_COMMIT);

        let worker_table = table.clone();
        let worker_sock = sock.clone();
        let worker = thread::spawn(move || {
            let packet = worker_table
                .tcp_shutdown(
                    &worker_sock,
                    &ProcessCtx::new(5, 5, 0, 0, 0, 0),
                    CapId::INVALID,
                    1,
                )
                .expect("shutdown that committed FIN must succeed")
                .expect("shutdown that committed FIN must return its packet");
            assert!(packet.len() >= 20);
            (packet[13], packet.len())
        });

        wait_for_operation_commit_pause(&table);
        {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().expect("committed TCB").control;
            assert_eq!(control.state, expected_state);
            assert!(control.fin_sent);
            assert_eq!(control.snd_nxt, 0x1802);
        }

        // close() publishes closed while shutdown still owns the operation
        // lock. Releasing the deterministic pause transfers finalization to
        // the shutdown guard's Drop implementation.
        table.close(sock.id);
        assert!(sock.is_closed());
        resume_operation_commit(&table);

        let (flags, packet_len) = worker.join().expect("shutdown worker panicked");
        assert_ne!(flags & TCP_FLAG_FIN, 0, "prepared packet lost its FIN flag");
        assert_ne!(flags & TCP_FLAG_ACK, 0, "prepared packet lost its ACK flag");
        assert!(packet_len >= 20, "FIN packet is shorter than a TCP header");

        {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().expect("graceful close retains TCB").control;
            assert_eq!(control.state, expected_state);
            assert!(control.fin_sent);
            assert_eq!(control.snd_nxt, 0x1802);
        }
        assert!(
            table.sockets.read().contains_key(&sock.id),
            "graceful close must retain the socket for FIN ACK/retry processing"
        );
    }

    #[test]
    fn rf180_26_shutdown_established_close_race_returns_prepared_fin() {
        assert_shutdown_close_race_returns_committed_fin(
            TcpState::Established,
            TcpState::FinWait1,
            NamespaceId(0x1826_04),
        );
    }

    #[test]
    fn rf180_26_shutdown_close_wait_close_race_returns_prepared_fin() {
        assert_shutdown_close_race_returns_committed_fin(
            TcpState::CloseWait,
            TcpState::LastAck,
            NamespaceId(0x1826_05),
        );
    }

    fn assert_duplicate_payload_fin_transition(
        initial_state: TcpState,
        expected_state: TcpState,
        rcv_nxt: u32,
    ) {
        let table = SocketTable::new();
        let sock = test_socket(2, SocketType::Stream, SocketProtocol::Tcp);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let local_port = 30_000;
        let remote_port = 40_000;
        sock.bind_local(local_ip, local_port);
        sock.set_remote(remote_ip, remote_port);

        let mut tcb =
            TcpControlBlock::new_client(local_ip, local_port, remote_ip, remote_port, 100);
        tcb.state = initial_state;
        tcb.snd_una = 100;
        tcb.snd_nxt = 100;
        tcb.snd_wnd = TCP_DEFAULT_WINDOW as u32;
        tcb.rcv_nxt = rcv_nxt;
        tcb.rcv_wnd = 128;
        sock.attach_tcp(tcb).expect("hosted TCP waiter admission");

        let key =
            tcp_map_key_from_parts(NamespaceId(0), local_ip, local_port, remote_ip, remote_port);
        table
            .tcp_conns
            .lock()
            .try_insert(key, Arc::downgrade(&sock))
            .expect("hosted conn registry admission");

        let payload = [0x5a; 4];
        let header = TcpHeader::new(
            remote_port,
            local_port,
            rcv_nxt.wrapping_sub(payload.len() as u32),
            100,
            TCP_FLAG_ACK | TCP_FLAG_FIN,
            TCP_DEFAULT_WINDOW,
        );
        let response = table.process_tcp_segment(
            NamespaceId(0),
            remote_ip,
            local_ip,
            &header,
            &payload,
            &TcpOptions::default(),
            &mut None,
            &mut false,
        );
        assert!(response.is_some(), "an in-order FIN must be acknowledged");

        let guard = sock.tcp.lock();
        let tcb = &guard.as_ref().expect("TCB must remain present").control;
        assert_eq!(tcb.state, expected_state);
        assert!(tcb.fin_received);
        assert_eq!(tcb.rcv_nxt, rcv_nxt.wrapping_add(1));
        assert!(
            tcb.recv_buffer.is_empty(),
            "fully duplicate payload must not be delivered twice"
        );
    }

    #[test]
    fn test_socket_domain_from_raw() {
        assert_eq!(SocketDomain::from_raw(2), Some(SocketDomain::Inet4));
        assert_eq!(SocketDomain::from_raw(0), None);
        assert_eq!(SocketDomain::from_raw(10), None); // AF_INET6
    }

    #[test]
    fn test_socket_type_from_raw() {
        assert_eq!(SocketType::from_raw(2), Some(SocketType::Dgram));
        assert_eq!(SocketType::from_raw(1), Some(SocketType::Stream)); // SOCK_STREAM
    }

    #[test]
    fn test_socket_protocol_from_raw() {
        // UDP tests
        assert_eq!(
            SocketProtocol::from_raw(17, SocketType::Dgram),
            Some(SocketProtocol::Udp)
        );
        assert_eq!(
            SocketProtocol::from_raw(0, SocketType::Dgram),
            Some(SocketProtocol::Udp)
        );
        // TCP tests
        assert_eq!(
            SocketProtocol::from_raw(6, SocketType::Stream),
            Some(SocketProtocol::Tcp)
        );
        assert_eq!(
            SocketProtocol::from_raw(0, SocketType::Stream),
            Some(SocketProtocol::Tcp)
        );
        // Invalid
        assert_eq!(SocketProtocol::from_raw(99, SocketType::Dgram), None);
    }

    #[test]
    fn test_ipv4_to_u64() {
        assert_eq!(ipv4_to_u64([192, 168, 1, 1]), 0xC0A80101);
        assert_eq!(ipv4_to_u64([0, 0, 0, 0]), 0);
        assert_eq!(ipv4_to_u64([255, 255, 255, 255]), 0xFFFFFFFF);
    }

    #[test]
    fn test_udp_copyout_failure_preserves_front_datagram() {
        let table = SocketTable::new();
        let sock = test_socket(90, SocketType::Dgram, SocketProtocol::Udp);
        assert!(sock.enqueue_rx(Ipv4Addr([10, 1, 2, 3]), 1234, b"payload", 1));
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);

        let failed =
            table.recv_from_udp_with_commit(&sock, &current, CapId::INVALID, Some(0), |_packet| {
                Err::<usize, _>(())
            });
        assert!(matches!(failed, Err(RecvTransactionError::Commit(()))));
        assert_eq!(sock.rx_queue.lock().len(), 1);

        let copied = table
            .recv_from_udp_with_commit(&sock, &current, CapId::INVALID, Some(0), |packet| {
                assert_eq!(packet.data.as_slice(), b"payload");
                Ok::<usize, ()>(packet.data.len())
            })
            .expect("retry must receive the same datagram");
        assert_eq!(copied, 7);
        assert!(sock.rx_queue.lock().is_empty());
    }

    #[test]
    fn test_tcp_copyout_failure_preserves_stream_prefix() {
        let table = SocketTable::new();
        let sock = test_socket(91, SocketType::Stream, SocketProtocol::Tcp);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 1000, remote_ip, 2000, 1);
        tcb.state = TcpState::Established;
        tcb.recv_buffer
            .try_extend_from_slice(b"stream")
            .expect("hosted recv buffer admission");
        sock.attach_tcp(tcb).expect("hosted TCP waiter admission");
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);

        let failed =
            table.tcp_recv_with_commit(&sock, &current, CapId::INVALID, 6, Some(0), |_bytes| {
                Err::<(), _>(())
            });
        assert!(matches!(failed, Err(RecvTransactionError::Commit(()))));
        assert_eq!(
            sock.tcp.lock().as_ref().unwrap().control.recv_buffer.len(),
            6
        );

        let copied = table
            .tcp_recv_with_commit(&sock, &current, CapId::INVALID, 6, Some(0), |bytes| {
                assert_eq!(bytes, b"stream");
                Ok::<(), ()>(())
            })
            .expect("retry must receive the same stream prefix");
        assert_eq!(copied, 6);
        assert!(sock
            .tcp
            .lock()
            .as_ref()
            .unwrap()
            .control
            .recv_buffer
            .is_empty());
    }

    #[test]
    fn rf180_27_zero_length_tcp_send_is_allocation_free_and_non_mutating() {
        let table = SocketTable::new();
        let sock = test_socket(0x1827_01, SocketType::Stream, SocketProtocol::Tcp);
        let local_ip = Ipv4Addr([10, 27, 1, 1]);
        let remote_ip = Ipv4Addr([10, 27, 1, 2]);
        let local_port = 31_127;
        let remote_port = 41_127;
        sock.bind_local(local_ip, local_port);
        sock.set_remote(remote_ip, remote_port);

        let mut tcb =
            TcpControlBlock::new_client(local_ip, local_port, remote_ip, remote_port, 0x2710);
        tcb.state = TcpState::Established;
        tcb.snd_nxt = 0x2711;
        tcb.snd_una = 0x2710;
        tcb.last_activity = 7;
        sock.attach_tcp(tcb).expect("hosted TCP waiter admission");
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);

        sock.tcp
            .lock()
            .as_mut()
            .unwrap()
            .control
            .send_buffer
            .fail_next_growth_for_test();
        let before_tx = sock.tx_bytes.load(Ordering::Relaxed);
        let before = {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().unwrap().control;
            (
                control.state,
                control.snd_una,
                control.snd_nxt,
                control.cwnd,
                control.last_activity,
                control.send_buffer.len(),
                control.send_buffer_bytes,
                control.ns_charged_send_bytes,
            )
        };

        let (sent, segments) = table
            .tcp_send(&sock, &current, CapId::INVALID, &[])
            .expect("validated zero-length TCP send");
        assert_eq!(sent, 0);
        assert!(segments.is_empty());
        assert_eq!(sock.tx_bytes.load(Ordering::Relaxed), before_tx);

        let after = {
            let guard = sock.tcp.lock();
            let control = &guard.as_ref().unwrap().control;
            (
                control.state,
                control.snd_una,
                control.snd_nxt,
                control.cwnd,
                control.last_activity,
                control.send_buffer.len(),
                control.send_buffer_bytes,
                control.ns_charged_send_bytes,
            )
        };
        assert_eq!(after, before, "zero TCP send mutated transport state");
        assert!(
            sock.tcp
                .lock()
                .as_mut()
                .unwrap()
                .control
                .send_buffer
                .ensure_capacity_for(1)
                .is_err(),
            "zero TCP send must not touch retransmission queue allocation"
        );

        let unconnected = test_socket(0x1827_02, SocketType::Stream, SocketProtocol::Tcp);
        assert!(matches!(
            table.tcp_send(&unconnected, &current, CapId::INVALID, &[]),
            Err(SocketError::InvalidState)
        ));
        assert!(unconnected.tcp.lock().is_none());
    }

    #[test]
    fn rf180_27_zero_length_udp_send_emits_header_only_datagram() {
        let table = SocketTable::new();
        let sock = test_socket(0x1827_03, SocketType::Dgram, SocketProtocol::Udp);
        let src_ip = Ipv4Addr([10, 27, 2, 1]);
        let dst_ip = Ipv4Addr([10, 27, 2, 2]);
        let src_port = 31_227;
        let dst_port = 41_227;
        sock.bind_local(src_ip, src_port);
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);
        let before_datagrams = sock.tx_datagrams.load(Ordering::Relaxed);
        let before_bytes = sock.tx_bytes.load(Ordering::Relaxed);

        let datagram = table
            .send_to_udp(
                &sock,
                &current,
                CapId::INVALID,
                src_ip,
                dst_ip,
                dst_port,
                &[],
            )
            .expect("zero-length UDP send must serialize a datagram");

        assert_eq!(datagram.len(), 8, "UDP header has a fixed eight-byte size");
        assert_eq!(u16::from_be_bytes([datagram[0], datagram[1]]), src_port);
        assert_eq!(u16::from_be_bytes([datagram[2], datagram[3]]), dst_port);
        assert_eq!(u16::from_be_bytes([datagram[4], datagram[5]]), 8);
        assert_eq!(
            sock.tx_datagrams.load(Ordering::Relaxed),
            before_datagrams,
            "packet construction must not account an unqueued datagram"
        );
        table.commit_udp_send(&sock, 0);
        assert_eq!(
            sock.tx_datagrams.load(Ordering::Relaxed),
            before_datagrams + 1
        );
        assert_eq!(sock.tx_bytes.load(Ordering::Relaxed), before_bytes);
    }

    #[test]
    fn rf180_27_zero_length_tcp_recv_is_immediate_and_non_consuming() {
        let table = SocketTable::new();
        let sock = test_socket(92, SocketType::Stream, SocketProtocol::Tcp);
        let local_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);
        let mut tcb = TcpControlBlock::new_client(local_ip, 1000, remote_ip, 2000, 1);
        tcb.state = TcpState::Established;
        tcb.recv_buffer
            .try_extend_from_slice(b"retained")
            .expect("hosted recv buffer admission");
        sock.attach_tcp(tcb).expect("hosted TCP waiter admission");
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);
        let mut commit_called = false;

        let copied = table
            .tcp_recv_with_commit(&sock, &current, CapId::INVALID, 0, None, |_bytes| {
                commit_called = true;
                Ok::<(), ()>(())
            })
            .expect("zero-length receive must not block");

        assert_eq!(copied, 0);
        assert!(!commit_called);
        assert_eq!(
            sock.tcp.lock().as_ref().unwrap().control.recv_buffer.len(),
            b"retained".len()
        );

        let unconnected = test_socket(0x1827_04, SocketType::Stream, SocketProtocol::Tcp);
        let copied = table
            .tcp_recv_with_commit(
                &unconnected,
                &current,
                CapId::INVALID,
                0,
                Some(0),
                |_bytes| Err::<(), _>("zero receive invoked commit"),
            )
            .expect("Linux-compatible zero recv does not require a connection");
        assert_eq!(copied, 0);
        assert!(unconnected.tcp.lock().is_none());
    }

    #[test]
    fn rf180_27_zero_length_udp_recv_consumes_one_and_reports_source() {
        let table = SocketTable::new();
        let sock = test_socket(0x1827_05, SocketType::Dgram, SocketProtocol::Udp);
        assert!(sock.enqueue_rx(Ipv4Addr([10, 27, 3, 1]), 31_327, b"first", 1));
        assert!(sock.enqueue_rx(Ipv4Addr([10, 27, 3, 2]), 31_328, b"second", 2));
        let current = ProcessCtx::new(1, 1, 0, 0, 0, 0);
        let mut observed = None;

        let copied = table
            .recv_from_udp_with_commit(&sock, &current, CapId::INVALID, Some(0), |packet| {
                observed = Some((packet.src_ip, packet.src_port, packet.payload().to_vec()));
                Ok::<usize, ()>(0)
            })
            .expect("zero-length UDP receive must consume one datagram");

        assert_eq!(copied, 0);
        assert_eq!(
            observed,
            Some((Ipv4Addr([10, 27, 3, 1]), 31_327, b"first".to_vec()))
        );
        let queue = sock.rx_queue.lock();
        assert_eq!(queue.len(), 1, "zero recv must consume exactly one packet");
        let next = queue.front().expect("second datagram remains queued");
        assert_eq!(next.src_ip, Ipv4Addr([10, 27, 3, 2]));
        assert_eq!(next.src_port, 31_328);
        assert_eq!(next.payload(), b"second");
    }

    #[test]
    fn test_segment_partial_left_overlap_window() {
        assert!(segment_in_recv_window(990, 11, false, 1000, 128));
        assert!(!segment_in_recv_window(990, 10, false, 1000, 128));
        assert!(segment_in_recv_window(990, 10, true, 1000, 128));
        assert!(segment_in_recv_window(1127, 1, false, 1000, 128));
        assert!(!segment_in_recv_window(1128, 1, false, 1000, 128));
        assert!(segment_in_recv_window(u32::MAX, 4, false, 2, 128));
    }

    #[test]
    fn test_concurrent_udp_binds_commit_once() {
        assert_concurrent_bind_is_single_commit(SocketType::Dgram, SocketProtocol::Udp);
    }

    #[test]
    fn test_concurrent_tcp_binds_commit_once() {
        assert_concurrent_bind_is_single_commit(SocketType::Stream, SocketProtocol::Tcp);
    }

    #[test]
    fn test_concurrent_tcp_connects_publish_one_tuple() {
        const WORKERS: usize = 8;
        let table = Arc::new(SocketTable::new());
        let sock = test_socket(3, SocketType::Stream, SocketProtocol::Tcp);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();

        for worker in 0..WORKERS {
            let table = table.clone();
            let sock = sock.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                let dst_ip = Ipv4Addr([10, 1, 0, worker as u8 + 1]);
                let dst_port = 41_000 + worker as u16;
                barrier.wait();
                let current = ProcessCtx::new(worker + 1, worker + 1, 0, 0, 0, 0);
                let result = table.connect(
                    &sock,
                    &current,
                    CapId::INVALID,
                    Ipv4Addr([10, 1, 1, 1]),
                    dst_ip,
                    dst_port,
                    Some(0),
                );
                (dst_ip, dst_port, result)
            }));
        }

        let mut winner = None;
        for handle in handles {
            let (dst_ip, dst_port, result) = handle.join().expect("connect worker panicked");
            match result {
                Ok(_) => assert!(
                    winner.replace((dst_ip, dst_port)).is_none(),
                    "more than one connect transaction committed"
                ),
                Err(SocketError::AlreadyConnected) => {}
                Err(other) => panic!("unexpected connect result: {other:?}"),
            }
        }

        let (remote_ip, remote_port) = winner.expect("one connect must commit");
        let meta = sock.meta_snapshot();
        let local_ip = Ipv4Addr(meta.local_ip.expect("connected socket has local IP"));
        let local_port = meta.local_port.expect("connected socket has local port");
        assert_eq!(meta.remote_ip, Some(remote_ip.0));
        assert_eq!(meta.remote_port, Some(remote_port));
        assert_eq!(
            sock.tcp_state(),
            Some(TcpState::Closed),
            "connect preparation must not expose SYN-SENT before device acceptance"
        );
        assert!(
            sock.tcp
                .lock()
                .as_ref()
                .is_some_and(|state| state.control.active_open_pending),
            "the winning connect retains an identity-bound provisional SYN"
        );

        let key =
            tcp_map_key_from_parts(NamespaceId(0), local_ip, local_port, remote_ip, remote_port);
        let conns = table.tcp_conns.lock();
        assert_eq!(conns.len(), 1, "losing connects left ghost 4-tuples");
        assert!(
            conns
                .get(&key)
                .and_then(|entry| entry.upgrade())
                .map_or(false, |owner| Arc::ptr_eq(&owner, &sock)),
            "published 4-tuple does not match committed socket metadata"
        );
        drop(conns);

        let bindings = table.tcp_bindings.lock();
        assert_eq!(bindings.len(), 1, "connect race left ghost local bindings");
        assert!(bindings.contains_key(&(NamespaceId(0), local_port)));
    }

    #[test]
    fn test_concurrent_listen_auto_bind_is_reentrant_safe() {
        const WORKERS: usize = 4;
        let table = Arc::new(SocketTable::new());
        let sock = test_socket(4, SocketType::Stream, SocketProtocol::Tcp);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let table = table.clone();
            let sock = sock.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                table.listen(
                    &sock,
                    &ProcessCtx::new(worker + 1, worker + 1, 0, 0, 0, 0),
                    CapId::INVALID,
                    16,
                    true,
                )
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().expect("listen worker panicked"), Ok(()));
        }
        assert!(sock.is_listening());
        let local_port = sock.local_port().expect("listener must be bound");
        let bindings = table.tcp_bindings.lock();
        assert_eq!(bindings.len(), 1);
        assert!(bindings.contains_key(&(NamespaceId(0), local_port)));
    }

    #[test]
    fn test_concurrent_udp_send_auto_bind_commits_once() {
        const WORKERS: usize = 4;
        let table = Arc::new(SocketTable::new());
        let sock = test_socket(5, SocketType::Dgram, SocketProtocol::Udp);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let table = table.clone();
            let sock = sock.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                table.send_to_udp(
                    &sock,
                    &ProcessCtx::new(worker + 1, worker + 1, 0, 0, 0, 0),
                    CapId::INVALID,
                    Ipv4Addr([10, 2, 0, 1]),
                    Ipv4Addr([10, 2, 0, worker as u8 + 2]),
                    42_000 + worker as u16,
                    &[worker as u8],
                )
            }));
        }
        for handle in handles {
            assert!(
                handle.join().expect("UDP send worker panicked").is_ok(),
                "a racing sender must reuse the committed auto-bind"
            );
        }
        let local_port = sock.local_port().expect("UDP sender must be auto-bound");
        let bindings = table.udp_bindings.lock();
        assert_eq!(bindings.len(), 1, "UDP auto-bind race left ghost ports");
        assert!(bindings.contains_key(&(NamespaceId(0), local_port)));
    }

    #[test]
    fn test_duplicate_payload_new_fin_transitions_all_receive_states() {
        assert_duplicate_payload_fin_transition(TcpState::Established, TcpState::CloseWait, 5_000);
        assert_duplicate_payload_fin_transition(TcpState::FinWait1, TcpState::TimeWait, 6_000);
        assert_duplicate_payload_fin_transition(TcpState::FinWait2, TcpState::TimeWait, 7_000);
        // Wraparound tripwire: duplicate data crosses 2^32 and FIN is RCV.NXT.
        assert_duplicate_payload_fin_transition(TcpState::Established, TcpState::CloseWait, 2);
    }
}
