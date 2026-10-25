//! Connection Tracking (Conntrack) for Zero-OS
//!
//! This module provides stateful connection tracking for the network stack,
//! independent of the socket layer. It tracks TCP, UDP, and ICMP flows for:
//!
//! - Stateful firewall decisions
//! - NAT support (future)
//! - Connection statistics
//!
//! # Design
//!
//! - Independent from socket.rs TCP state machine
//! - Tracks packet-level state transitions
//! - Per-protocol timeout management
//! - Memory-bounded with LRU eviction
//!
//! # Security
//!
//! - Validates state transitions to detect invalid packets
//! - Rate limits new connection creation
//! - Bounded memory usage with configurable limits

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use mm::HeapClass;
use spin::{Mutex, Once, RwLock};

use crate::admitted::{
    AdmittedAllocError, AdmittedMap, AdmittedVec, CapacityPlan, PreparedAdmittedMapCapacity,
    RetiredAdmittedMapCapacity,
};
use crate::ipv4::Ipv4Addr;

static NEXT_EGRESS_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpLocalHandshake {
    None,
    SynQueued,
    SynAckQueued,
    Complete,
}

#[derive(Debug, Clone, Copy)]
struct PendingEgress {
    token: u64,
    new_state: CtProtoState,
    decision: CtDecision,
    state_dir: ConntrackDir,
    payload_len: usize,
    now_ms: u64,
    tcp_handshake: TcpLocalHandshake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressVictimKind {
    Expired,
    Evicted,
}

struct DetachedEgressVictim {
    key: FlowKey,
    entry: Mutex<ConntrackEntry>,
    kind: EgressVictimKind,
}

struct EgressReservation {
    key: FlowKey,
    dir: ConntrackDir,
    token: u64,
    created_entry: bool,
    victim: Option<DetachedEgressVictim>,
}

/// Serializes conntrack creation through publication and egress settlement.
/// The owner performs heap preparation and queue callbacks without metadata
/// locks; ordinary lookup/update, removal, and existing-flow egress never wait
/// on this flag. Competing creators fail closed instead of waiting.
struct ConntrackCapacityPermit<'a> {
    flag: &'a AtomicBool,
}

impl Drop for ConntrackCapacityPermit<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

const CT_CAPACITY_PREPARE_RETRIES: usize = 16;

// ============================================================================
// Constants
// ============================================================================

/// RF178-7 + P2-A: conntrack hard floor is the arbiter slot
/// [`mm::HeapBudgetId::Conntrack`] (HEAP/4 = 256 KiB), not an independent
/// HEAP/2 fraction. Charge covers flow + namespace metadata + map slack.
const CT_FLOW_CHARGE_BYTES: usize = 1024;
const CT_HEAP_BUDGET_BYTES: usize = mm::hard_floor_bytes(mm::HeapBudgetId::Conntrack);

/// Maximum entries in the conntrack table, derived from the heap-budget arbiter.
pub const CT_MAX_ENTRIES: usize = CT_HEAP_BUDGET_BYTES / CT_FLOW_CHARGE_BYTES;

/// R140-9 FIX: Maximum entries per network namespace.
/// Prevents a single namespace from monopolizing the global conntrack table.
/// Set to 1/4 of global limit as a fair-share heuristic.
const CT_MAX_ENTRIES_PER_NS: usize = CT_MAX_ENTRIES / 4;
/// R192-RES-4: the root (host) namespace.
const CT_ROOT_NS: u64 = 0;
/// R192-RES-4: slots tenants together must leave to the root namespace. Root is
/// not held to the per-namespace share (only the global cap), tenants are, and
/// together they may hold at most `CT_MAX_ENTRIES - CT_ROOT_RESERVE` flows.
const CT_ROOT_RESERVE: usize = CT_MAX_ENTRIES_PER_NS;
const _: () = assert!(CT_ROOT_RESERVE < CT_MAX_ENTRIES);

// P2-A: 256 KiB / 1024 B = 256 entries (was 512 under the old HEAP/2 claim).
const _: () = assert!(CT_MAX_ENTRIES == 256);
const _: () = assert!(CT_HEAP_BUDGET_BYTES == mm::CONNTRACK_HARD_BYTES);

/// TCP timeout values (milliseconds)
pub const CT_TCP_TIMEOUT_SYN_SENT_MS: u64 = 60_000;
pub const CT_TCP_TIMEOUT_SYN_RECV_MS: u64 = 60_000;
// R147-4 FIX: Increased from 300_000 (5 min) to 7_200_000 (2 hours).
// 5 minutes silently dropped SSH, DB, and long-poll connections.
// 2 hours balances memory usage against real-world idle connection lifetimes.
pub const CT_TCP_TIMEOUT_ESTABLISHED_MS: u64 = 7_200_000; // 2 hours
                                                          // R155-10 FIX: Aligned with socket-layer FIN_WAIT_2 timeout (60s).
                                                          // Previously 120s, causing conntrack to persist 60s after socket layer
                                                          // killed the connection, classifying stale packets as Established.
pub const CT_TCP_TIMEOUT_FIN_WAIT_MS: u64 = 60_000; // 1 minute
pub const CT_TCP_TIMEOUT_CLOSE_WAIT_MS: u64 = 60_000;
pub const CT_TCP_TIMEOUT_LAST_ACK_MS: u64 = 30_000;
pub const CT_TCP_TIMEOUT_TIME_WAIT_MS: u64 = 120_000; // 2*MSL
pub const CT_TCP_TIMEOUT_CLOSE_MS: u64 = 10_000;

/// UDP timeout values (milliseconds)
pub const CT_UDP_TIMEOUT_UNREPLIED_MS: u64 = 30_000;
pub const CT_UDP_TIMEOUT_REPLIED_MS: u64 = 180_000; // 3 minutes
/// R192-4: a replied UDP flow is a stream (protected from replacement) once it
/// has carried traffic for this long, as Linux marks UDP assured.
const CT_UDP_STREAM_MS: u64 = 2_000;

/// ICMP timeout values (milliseconds)
pub const CT_ICMP_TIMEOUT_MS: u64 = 30_000;

/// Sweep budget per timer tick
pub const CT_SWEEP_BUDGET: usize = 256;

// ============================================================================
// Protocol Numbers
// ============================================================================

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// ============================================================================
// Flow Key
// ============================================================================

/// Normalized flow key for bidirectional matching.
///
/// The key is normalized so that (A->B) and (B->A) map to the same entry.
/// Direction is tracked separately in the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// R107-2 FIX: Network namespace ID for cross-namespace isolation.
    /// Uses raw u64 to avoid cap crate dependency in the conntrack module.
    pub net_ns_id: u64,
    /// Protocol number (TCP=6, UDP=17, ICMP=1)
    pub proto: u8,
    /// Lower IP address (for normalization)
    pub ip_lo: [u8; 4],
    /// Higher IP address (for normalization)
    pub ip_hi: [u8; 4],
    /// Lower port (for normalization)
    pub port_lo: u16,
    /// Higher port (for normalization)
    pub port_hi: u16,
}

impl FlowKey {
    /// Create a normalized flow key from packet fields.
    ///
    /// Returns the key and the direction (Original if src < dst, Reply otherwise).
    /// R107-2 FIX: Includes network namespace ID for cross-namespace isolation.
    pub fn from_packet(
        net_ns_id: u64,
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> (Self, ConntrackDir) {
        let src_tuple = (src_ip.0, src_port);
        let dst_tuple = (dst_ip.0, dst_port);

        if src_tuple <= dst_tuple {
            (
                Self {
                    net_ns_id,
                    proto,
                    ip_lo: src_ip.0,
                    ip_hi: dst_ip.0,
                    port_lo: src_port,
                    port_hi: dst_port,
                },
                ConntrackDir::Original,
            )
        } else {
            (
                Self {
                    net_ns_id,
                    proto,
                    ip_lo: dst_ip.0,
                    ip_hi: src_ip.0,
                    port_lo: dst_port,
                    port_hi: src_port,
                },
                ConntrackDir::Reply,
            )
        }
    }

    /// Create a flow key for ICMP (using type/code/id as port fields).
    /// R107-2 FIX: Includes network namespace ID for cross-namespace isolation.
    pub fn from_icmp(
        net_ns_id: u64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        icmp_type: u8,
        icmp_code: u8,
        icmp_id: u16,
    ) -> (Self, ConntrackDir) {
        // Pack type/code into port_lo, id into port_hi
        let pseudo_port = ((icmp_type as u16) << 8) | (icmp_code as u16);
        Self::from_packet(
            net_ns_id,
            IPPROTO_ICMP,
            src_ip,
            dst_ip,
            pseudo_port,
            icmp_id,
        )
    }
}

// ============================================================================
// Direction
// ============================================================================

/// Direction of a packet relative to the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackDir {
    /// Original direction (initiator -> responder)
    Original,
    /// Reply direction (responder -> initiator)
    Reply,
}

// ============================================================================
// Protocol States
// ============================================================================

/// TCP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpCtState {
    /// No connection
    None,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN-ACK received, waiting for ACK
    SynRecv,
    /// Connection established
    Established,
    /// FIN sent, waiting for ACK
    FinWait,
    /// R146-NET-2 FIX: FIN acknowledged, waiting for peer FIN (half-close).
    /// RFC 793 FIN_WAIT_2 — peer may still send data before closing.
    FinWait2,
    /// FIN received, waiting for close
    CloseWait,
    /// Final ACK sent
    LastAck,
    /// Waiting for 2*MSL timeout
    TimeWait,
    /// Connection closed
    Close,
}

impl TcpCtState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            TcpCtState::None => CT_TCP_TIMEOUT_CLOSE_MS,
            TcpCtState::SynSent => CT_TCP_TIMEOUT_SYN_SENT_MS,
            TcpCtState::SynRecv => CT_TCP_TIMEOUT_SYN_RECV_MS,
            TcpCtState::Established => CT_TCP_TIMEOUT_ESTABLISHED_MS,
            TcpCtState::FinWait => CT_TCP_TIMEOUT_FIN_WAIT_MS,
            TcpCtState::FinWait2 => CT_TCP_TIMEOUT_FIN_WAIT_MS,
            TcpCtState::CloseWait => CT_TCP_TIMEOUT_CLOSE_WAIT_MS,
            TcpCtState::LastAck => CT_TCP_TIMEOUT_LAST_ACK_MS,
            TcpCtState::TimeWait => CT_TCP_TIMEOUT_TIME_WAIT_MS,
            TcpCtState::Close => CT_TCP_TIMEOUT_CLOSE_MS,
        }
    }
}

/// UDP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCtState {
    /// Single packet seen (unreplied)
    Unreplied,
    /// Bidirectional traffic seen
    Replied,
}

impl UdpCtState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            UdpCtState::Unreplied => CT_UDP_TIMEOUT_UNREPLIED_MS,
            UdpCtState::Replied => CT_UDP_TIMEOUT_REPLIED_MS,
        }
    }
}

/// ICMP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpCtState {
    /// Echo request sent
    EchoRequest,
    /// Echo reply received
    EchoReply,
}

/// Protocol-specific state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtProtoState {
    Tcp(TcpCtState),
    Udp(UdpCtState),
    Icmp(IcmpCtState),
    Other,
}

impl CtProtoState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            CtProtoState::Tcp(s) => s.timeout_ms(),
            CtProtoState::Udp(s) => s.timeout_ms(),
            CtProtoState::Icmp(_) => CT_ICMP_TIMEOUT_MS,
            CtProtoState::Other => CT_UDP_TIMEOUT_UNREPLIED_MS,
        }
    }
}

// ============================================================================
// Conntrack Entry
// ============================================================================

/// A connection tracking entry.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// Normalized flow key
    pub key: FlowKey,
    /// Protocol-specific state
    pub state: CtProtoState,
    /// Last packet timestamp (ms)
    pub last_seen_ms: u64,
    /// Bytes transferred (original direction)
    pub bytes_orig: u64,
    /// Bytes transferred (reply direction)
    pub bytes_reply: u64,
    /// Packets transferred (original direction)
    pub packets_orig: u64,
    /// Packets transferred (reply direction)
    pub packets_reply: u64,
    /// Creation timestamp (ms)
    pub created_ms: u64,
    /// Whether reply has been seen
    pub seen_reply: bool,
    /// R63-1 FIX: True initiator direction for this flow.
    ///
    /// FlowKey normalization uses lexicographic ordering which may not match
    /// the actual connection initiator. This field records the direction of
    /// the first packet (the true initiator) so the state machine can correctly
    /// distinguish Original (initiator→responder) from Reply (responder→initiator).
    pub initiator_dir: ConntrackDir,
    /// Locally queued handshake evidence. Ingress alone cannot manufacture an
    /// Established flow; the required SYN/SYN-ACK/final-ACK must have crossed
    /// the device acceptance boundary.
    tcp_local_handshake: TcpLocalHandshake,
    /// Provisional egress transition. Ingress encountering this token fails
    /// closed until the lock-free device callback resolves it.
    pending_egress: Option<PendingEgress>,
    /// R192-RES-4: created by this host's egress (an outbound SYN, a DNS
    /// query), not by a remote peer. Victim selection takes these last.
    local_origin: bool,
}

impl ConntrackEntry {
    /// Create a new entry.
    ///
    /// # Arguments
    ///
    /// * `key` - Normalized flow key
    /// * `state` - Initial protocol state
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `initiator_dir` - Direction of the first packet (true initiator)
    pub fn new(
        key: FlowKey,
        state: CtProtoState,
        now_ms: u64,
        initiator_dir: ConntrackDir,
    ) -> Self {
        Self {
            key,
            state,
            last_seen_ms: now_ms,
            bytes_orig: 0,
            bytes_reply: 0,
            packets_orig: 0,
            packets_reply: 0,
            created_ms: now_ms,
            seen_reply: false,
            initiator_dir,
            tcp_local_handshake: TcpLocalHandshake::None,
            pending_egress: None,
            local_origin: false,
        }
    }

    /// Check if the entry has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let timeout = self.state.timeout_ms();
        now_ms.saturating_sub(self.last_seen_ms) > timeout
    }

    /// R192-4 FIX (D2-RES-1): may a new flow replace this one when the table
    /// or its namespace is full? Only a flow that is not an established
    /// session, like Linux's `early_drop` of a non-assured flow: TCP before
    /// Established or after it closed, UDP that is unreplied or replied within
    /// `CT_UDP_STREAM_MS` of its first packet (a single request and answer),
    /// ICMP and other protocols. A TCP connection from Established until it
    /// closes and a UDP stream are never replaced, so a burst of new tuples
    /// cannot tear down live sessions. (SYN-ACK alone does not protect a flow,
    /// so a SYN flood to a listening port creates only replaceable flows.)
    fn replaceable(&self) -> bool {
        match self.state {
            CtProtoState::Tcp(state) => !matches!(
                state,
                TcpCtState::Established
                    | TcpCtState::FinWait
                    | TcpCtState::FinWait2
                    | TcpCtState::CloseWait
                    | TcpCtState::LastAck
            ),
            CtProtoState::Udp(UdpCtState::Unreplied) => true,
            CtProtoState::Udp(UdpCtState::Replied) => {
                self.last_seen_ms.saturating_sub(self.created_ms) < CT_UDP_STREAM_MS
            }
            CtProtoState::Icmp(_) | CtProtoState::Other => true,
        }
    }

    /// Update statistics for a packet.
    pub fn update_stats(&mut self, dir: ConntrackDir, bytes: usize, now_ms: u64) {
        self.last_seen_ms = now_ms;
        match dir {
            ConntrackDir::Original => {
                self.bytes_orig = self.bytes_orig.saturating_add(bytes as u64);
                self.packets_orig = self.packets_orig.saturating_add(1);
            }
            ConntrackDir::Reply => {
                self.bytes_reply = self.bytes_reply.saturating_add(bytes as u64);
                self.packets_reply = self.packets_reply.saturating_add(1);
                self.seen_reply = true;
            }
        }
    }
}

// ============================================================================
// Decision
// ============================================================================

/// Decision from conntrack processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtDecision {
    /// Packet matches existing tracked connection
    Established,
    /// New connection created
    New,
    /// Related to existing connection (e.g., ICMP error)
    Related,
    /// Invalid state transition - should be dropped
    Invalid,
}

/// R192-RES-4: where a new flow takes its slot from (`admission_locked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Below every limit: a new slot.
    Free,
    /// Replace this replaceable flow.
    Replace(FlowKey),
    /// No replaceable flow in scope: reject.
    Full,
}

/// Result of conntrack update.
#[derive(Debug, Clone, Copy)]
pub struct CtUpdateResult {
    /// Decision for this packet
    pub decision: CtDecision,
    /// Current protocol state
    pub state: CtProtoState,
    /// Packet direction
    pub dir: ConntrackDir,
    /// RF178-7 FIX: Metadata admission failed and ingress must hard-drop.
    pub resource_exhausted: bool,
}

/// Result of an egress transaction whose device-queue operation is serialized
/// with conntrack publication.
///
/// RF180-41 REVIEW FIX: an outbound packet must be neither visible to
/// conntrack before the device accepts it nor irreversibly queued before a
/// potentially-fallible conntrack insertion. `Rejected` means conntrack
/// preflight failed and the queue closure was not invoked. `QueueFailed` means
/// all metadata admission succeeded, but the device rejected the packet and no
/// logical conntrack state changed.
#[derive(Debug)]
pub enum CtEgressResult<E> {
    Committed(CtUpdateResult),
    Rejected(CtUpdateResult),
    QueueFailed(E),
    /// The device accepted the packet and conntrack committed the exact wire
    /// transition, but the identity-bound socket operation could no longer be
    /// published (for example, close linearized during the device callback).
    /// The packet owner is consumed and must never be returned as retryable.
    QueuedOwnerStale(CtUpdateResult),
    /// A provisional token disappeared or changed despite removal/eviction
    /// exclusion. `queued` distinguishes a pre-device rollback failure from an
    /// already-emitted packet; either case is an internal fail-closed fault.
    StateLost {
        queued: bool,
    },
}

// ============================================================================
// L4 Metadata
// ============================================================================

/// Layer 4 metadata for state machine transitions.
#[derive(Debug, Clone, Copy)]
pub struct L4Meta {
    /// TCP flags (SYN, ACK, FIN, RST)
    pub tcp_flags: u8,
    /// Packet payload length
    pub payload_len: usize,
}

impl L4Meta {
    pub fn new(tcp_flags: u8, payload_len: usize) -> Self {
        Self {
            tcp_flags,
            payload_len,
        }
    }

    /// Check if SYN flag is set.
    pub fn is_syn(&self) -> bool {
        self.tcp_flags & 0x02 != 0
    }

    /// Check if ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.tcp_flags & 0x10 != 0
    }

    /// Check if FIN flag is set.
    pub fn is_fin(&self) -> bool {
        self.tcp_flags & 0x01 != 0
    }

    /// Check if RST flag is set.
    pub fn is_rst(&self) -> bool {
        self.tcp_flags & 0x04 != 0
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Conntrack statistics.
#[derive(Debug, Default)]
pub struct ConntrackStats {
    /// Total entries created
    pub entries_created: AtomicU64,
    /// Total entries deleted
    pub entries_deleted: AtomicU64,
    /// Entries deleted due to timeout
    pub timeout_deletes: AtomicU64,
    /// New connections rejected (table full)
    pub insert_failed: AtomicU64,
    /// Invalid state transitions
    pub invalid_transitions: AtomicU64,
    /// R63-3 FIX: Entries evicted via LRU when table is full
    pub evictions: AtomicU64,
    /// Current entry count
    pub current_entries: AtomicU32,
}

impl ConntrackStats {
    pub const fn new() -> Self {
        Self {
            entries_created: AtomicU64::new(0),
            entries_deleted: AtomicU64::new(0),
            timeout_deletes: AtomicU64::new(0),
            insert_failed: AtomicU64::new(0),
            invalid_transitions: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            current_entries: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// Conntrack Table
// ============================================================================

/// The connection tracking table.
pub struct ConntrackTable {
    /// RF178-7 FIX: Fallible, bounded entry storage with stable ordered iteration.
    entries: RwLock<AdmittedMap<FlowKey, Mutex<ConntrackEntry>>>,
    /// R140-9 FIX: Per-namespace entry counts for fair quota enforcement.
    ns_entry_counts: Mutex<AdmittedMap<u64, usize>>,
    /// At most one absent/expired-flow creator snapshots and prepares detached
    /// entry/count backing at a time. This is an atomic ownership token, not a
    /// spin lock held across allocation.
    capacity_preparing: AtomicBool,
    /// Deterministic hosted-test fault injection for the second half of an
    /// egress replacement transaction. It fires only at namespace-row
    /// publication, after the new flow has been inserted and a victim may
    /// already be detached, so rollback tests exercise the real atomicity
    /// boundary rather than an earlier capacity preflight.
    #[cfg(test)]
    fail_next_ns_publication: AtomicBool,
    /// Statistics
    stats: ConntrackStats,
}

impl ConntrackTable {
    /// Create a new conntrack table.
    pub fn new() -> Self {
        #[cfg(test)]
        mm::publish_heap_budgets();
        Self {
            entries: RwLock::new(AdmittedMap::new(HeapClass::SocketObject)),
            ns_entry_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            capacity_preparing: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_ns_publication: AtomicBool::new(false),
            stats: ConntrackStats::new(),
        }
    }

    #[cfg(test)]
    fn fail_next_ns_publication_for_test(&self) {
        self.fail_next_ns_publication.store(true, Ordering::Release);
    }

    fn insert_ns_count_reserved(
        &self,
        counts: &mut AdmittedMap<u64, usize>,
        ns_id: u64,
        count: usize,
    ) -> bool {
        #[cfg(test)]
        if self
            .fail_next_ns_publication
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return false;
        }
        counts.insert_unique_reserved(ns_id, count).is_ok()
    }

    fn try_capacity_permit(&self) -> Option<ConntrackCapacityPermit<'_>> {
        self.capacity_preparing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ConntrackCapacityPermit {
                flag: &self.capacity_preparing,
            })
    }

    fn resource_rejection(dir: ConntrackDir) -> CtUpdateResult {
        CtUpdateResult {
            decision: CtDecision::Invalid,
            state: CtProtoState::Other,
            dir,
            resource_exhausted: true,
        }
    }

    /// Look up an entry by flow key.
    pub fn lookup(&self, key: &FlowKey) -> Option<ConntrackEntry> {
        let entries = self.entries.read();
        entries.get(key).and_then(|entry_lock| {
            let entry = entry_lock.lock();
            entry.pending_egress.is_none().then(|| entry.clone())
        })
    }

    /// Whether a flow is tracked, including an unresolved egress transaction.
    /// Unlike `lookup`, this does not expose or require committed state.
    pub fn contains_flow(&self, key: &FlowKey) -> bool {
        self.entries.read().contains_key(key)
    }

    /// Update conntrack state on packet arrival.
    ///
    /// This is the main entry point for packet processing.
    /// R107-2 FIX: Namespace-isolated conntrack lookup and creation.
    pub fn update_on_packet(
        &self,
        net_ns_id: u64,
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        l4: &L4Meta,
        now_ms: u64,
    ) -> CtUpdateResult {
        let (key, dir) = FlowKey::from_packet(net_ns_id, proto, src_ip, dst_ip, src_port, dst_port);

        // Fast path: check existing entry with read lock
        {
            let entries = self.entries.read();
            if let Some(entry_lock) = entries.get(&key) {
                let mut entry = entry_lock.lock();

                if entry.pending_egress.is_some() {
                    return CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: entry.state,
                        dir,
                        resource_exhausted: false,
                    };
                }

                // R151-10 FIX: Treat expired entries as absent so late packets
                // don't revive stale flows. Fall through to create_entry() which
                // will remove the expired entry under write lock and create fresh state.
                if entry.is_expired(now_ms) {
                    drop(entry);
                    drop(entries);
                    return self.create_entry(key, dir, proto, l4, now_ms);
                }
                // R63-1 FIX: Compute state machine direction based on true initiator.
                // FlowKey normalization uses lexicographic ordering, but the state machine
                // needs to know if this packet is from the initiator (Original) or responder (Reply).
                let state_dir = if dir == entry.initiator_dir {
                    ConntrackDir::Original
                } else {
                    ConntrackDir::Reply
                };

                let (new_state, decision) = self.transition_state(&entry, state_dir, proto, l4);

                if decision == CtDecision::Invalid {
                    self.stats
                        .invalid_transitions
                        .fetch_add(1, Ordering::Relaxed);
                    return CtUpdateResult {
                        decision,
                        state: entry.state,
                        dir,
                        resource_exhausted: false,
                    };
                }

                entry.state = new_state;
                entry.update_stats(state_dir, l4.payload_len, now_ms);

                // R95-2 FIX: Propagate actual decision from state machine
                // instead of hardcoded Established. This prevents firewall
                // bypass via SYN retransmission seeding a conntrack entry.
                return CtUpdateResult {
                    decision,
                    state: new_state,
                    dir,
                    resource_exhausted: false,
                };
            }
        }

        // Slow path: create new entry with write lock
        self.create_entry(key, dir, proto, l4, now_ms)
    }

    /// Queue an outbound packet and publish its conntrack transition as one
    /// externally atomic transaction.
    ///
    /// This compatibility entry point has no socket-side commit. Stateful TCP
    /// reply paths use [`Self::update_on_egress_transaction_with_commit`].
    pub fn update_on_egress_transaction<E, F>(
        &self,
        net_ns_id: u64,
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        l4: &L4Meta,
        now_ms: u64,
        queue: F,
    ) -> CtEgressResult<E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        self.update_on_egress_transaction_with_commit(
            net_ns_id,
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            l4,
            now_ms,
            queue,
            || true,
        )
    }

    /// RF180-41 REVIEW FIX: reserve a token under conntrack locks, release all
    /// locks before the device callback, then commit the identity-bound socket
    /// operation while the token remains provisional and finally publish the
    /// conntrack transition. Ingress, sweep, drain, and eviction all fail closed
    /// around a live token. No device or socket callback executes under a
    /// conntrack spin lock.
    pub(crate) fn update_on_egress_transaction_with_commit<E, F, C>(
        &self,
        net_ns_id: u64,
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        l4: &L4Meta,
        now_ms: u64,
        queue: F,
        commit_owner: C,
    ) -> CtEgressResult<E>
    where
        F: FnOnce() -> Result<(), E>,
        C: FnOnce() -> bool,
    {
        let token =
            match NEXT_EGRESS_TOKEN.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            }) {
                Ok(token) if token != 0 => token,
                _ => {
                    return CtEgressResult::Rejected(CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: CtProtoState::Other,
                        dir: ConntrackDir::Original,
                        resource_exhausted: true,
                    });
                }
            };

        let (key, dir) = FlowKey::from_packet(net_ns_id, proto, src_ip, dst_ip, src_port, dst_port);

        // Existing flows need no collection growth and stay fully concurrent.
        // An absent/expired flow, however, owns the preparation token from its
        // first capacity snapshot through queue settlement so neither detached
        // backing nor a rollback victim can be claimed by another creator.
        let needs_capacity_transaction = {
            let entries = self.entries.read();
            entries
                .get(&key)
                .map(|entry_lock| entry_lock.lock().is_expired(now_ms))
                .unwrap_or(true)
        };
        let capacity_permit = if needs_capacity_transaction {
            match self.try_capacity_permit() {
                Some(permit) => Some(permit),
                None => {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return CtEgressResult::Rejected(Self::resource_rejection(dir));
                }
            }
        } else {
            None
        };

        let mut prepared_entries: Option<
            PreparedAdmittedMapCapacity<FlowKey, Mutex<ConntrackEntry>>,
        > = None;
        let mut prepared_ns: Option<PreparedAdmittedMapCapacity<u64, usize>> = None;

        if capacity_permit.is_some() {
            let mut prepared = false;
            for _ in 0..CT_CAPACITY_PREPARE_RETRIES {
                let plans: Result<
                    (Option<CapacityPlan>, Option<CapacityPlan>),
                    AdmittedAllocError,
                > = (|| {
                    let mut entries = self.entries.write();
                    let replacing_expired = entries
                        .get(&key)
                        .map(|entry_lock| {
                            let entry = entry_lock.lock();
                            entry.pending_egress.is_none() && entry.is_expired(now_ms)
                        })
                        .unwrap_or(false);
                    let existing_live = entries
                        .get(&key)
                        .map(|entry_lock| {
                            let entry = entry_lock.lock();
                            entry.pending_egress.is_some() || !entry.is_expired(now_ms)
                        })
                        .unwrap_or(false);
                    if existing_live {
                        Ok((None, None))
                    } else {
                        let mut ns_counts = self.ns_entry_counts.lock();
                        let ns_count = ns_counts.get(&key.net_ns_id).copied().unwrap_or(0);
                        // R192-4 FIX (D2-RES-1, R192-RES-4): see `admission_locked`.
                        let admission = if replacing_expired {
                            Admission::Replace(key)
                        } else {
                            Self::admission_locked(&entries, &ns_counts, key.net_ns_id)
                        };
                        let victim_plan = match admission {
                            Admission::Replace(victim) => Some(victim),
                            Admission::Free | Admission::Full => None,
                        };
                        if admission == Admission::Full {
                            Ok((None, None))
                        } else {
                            let victim_in_requester_ns =
                                victim_plan.is_some_and(|victim| victim.net_ns_id == key.net_ns_id);
                            if key.net_ns_id != CT_ROOT_NS
                                && ns_count.saturating_sub(usize::from(victim_in_requester_ns))
                                    >= CT_MAX_ENTRIES_PER_NS
                            {
                                Ok((None, None))
                            } else {
                                let victim_frees_ns_row = victim_plan
                                    .and_then(|victim| {
                                        ns_counts.get(&victim.net_ns_id).map(|count| *count == 1)
                                    })
                                    .unwrap_or(false);
                                let entry_plan = if victim_plan.is_none() {
                                    entries.capacity_plan_for(1)?
                                } else {
                                    None
                                };
                                let ns_plan = if !ns_counts.contains_key(&key.net_ns_id)
                                    && !victim_frees_ns_row
                                {
                                    ns_counts.capacity_plan_for(1)?
                                } else {
                                    None
                                };
                                Ok((entry_plan, ns_plan))
                            }
                        }
                    }
                })();

                let (entry_plan, ns_plan) = match plans {
                    Ok(plans) => plans,
                    Err(_) => {
                        self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                        return CtEgressResult::Rejected(Self::resource_rejection(dir));
                    }
                };
                let need_entries = entry_plan.filter(|plan| {
                    prepared_entries
                        .as_ref()
                        .map(|candidate| candidate.capacity() < plan.required())
                        .unwrap_or(true)
                });
                let need_ns = ns_plan.filter(|plan| {
                    prepared_ns
                        .as_ref()
                        .map(|candidate| candidate.capacity() < plan.required())
                        .unwrap_or(true)
                });
                if need_entries.is_none() && need_ns.is_none() {
                    prepared = true;
                    break;
                }
                if let Some(plan) = need_entries {
                    drop(prepared_entries.take());
                    prepared_entries = match PreparedAdmittedMapCapacity::try_from_plan(plan) {
                        Ok(candidate) => Some(candidate),
                        Err(_) => {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                    };
                }
                if let Some(plan) = need_ns {
                    drop(prepared_ns.take());
                    prepared_ns = match PreparedAdmittedMapCapacity::try_from_plan(plan) {
                        Ok(candidate) => Some(candidate),
                        Err(_) => {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                    };
                }
            }
            if !prepared {
                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                return CtEgressResult::Rejected(Self::resource_rejection(dir));
            }
        }

        let mut retired_entries: Option<
            RetiredAdmittedMapCapacity<FlowKey, Mutex<ConntrackEntry>>,
        > = None;
        let mut retired_ns: Option<RetiredAdmittedMapCapacity<u64, usize>> = None;
        let mut reservation = {
            let mut entries = self.entries.write();

            let mut existing_reservation = None;
            let replacing_expired = if let Some(entry_lock) = entries.get(&key) {
                let mut entry = entry_lock.lock();
                if entry.pending_egress.is_some() {
                    return CtEgressResult::Rejected(CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: entry.state,
                        dir,
                        resource_exhausted: false,
                    });
                }
                if !entry.is_expired(now_ms) {
                    let state_dir = if dir == entry.initiator_dir {
                        ConntrackDir::Original
                    } else {
                        ConntrackDir::Reply
                    };
                    let tcp_handshake = self.egress_tcp_handshake(&entry, state_dir, proto, l4);
                    let (mut new_state, decision) = self.transition_state_with_handshake(
                        &entry,
                        state_dir,
                        proto,
                        l4,
                        tcp_handshake,
                    );
                    // R192 FIX (R192-RES-4): an RST this host sends ends the
                    // connection. R145-4 ignores RST because ingress cannot
                    // validate it; our own is authoritative. Close makes the
                    // flow replaceable and short-lived instead of pinning a
                    // slot for the established timeout.
                    if proto == IPPROTO_TCP && l4.is_rst() {
                        new_state = CtProtoState::Tcp(TcpCtState::Close);
                    }
                    if decision == CtDecision::Invalid {
                        self.stats
                            .invalid_transitions
                            .fetch_add(1, Ordering::Relaxed);
                        return CtEgressResult::Rejected(CtUpdateResult {
                            decision,
                            state: entry.state,
                            dir,
                            resource_exhausted: false,
                        });
                    }
                    entry.pending_egress = Some(PendingEgress {
                        token,
                        new_state,
                        decision,
                        state_dir,
                        payload_len: l4.payload_len,
                        now_ms,
                        tcp_handshake,
                    });
                    drop(entry);
                    existing_reservation = Some(EgressReservation {
                        key,
                        dir,
                        token,
                        created_entry: false,
                        victim: None,
                    });
                    false
                } else {
                    true
                }
            } else {
                false
            };

            if let Some(existing_reservation) = existing_reservation {
                drop(entries);
                existing_reservation
            } else {
                let initial_state = match proto {
                    IPPROTO_TCP if l4.is_syn() && !l4.is_ack() => {
                        CtProtoState::Tcp(TcpCtState::SynSent)
                    }
                    IPPROTO_TCP => {
                        self.stats
                            .invalid_transitions
                            .fetch_add(1, Ordering::Relaxed);
                        return CtEgressResult::Rejected(CtUpdateResult {
                            decision: CtDecision::Invalid,
                            state: CtProtoState::Tcp(TcpCtState::None),
                            dir,
                            resource_exhausted: false,
                        });
                    }
                    IPPROTO_UDP => CtProtoState::Udp(UdpCtState::Unreplied),
                    IPPROTO_ICMP => CtProtoState::Icmp(IcmpCtState::EchoRequest),
                    _ => CtProtoState::Other,
                };
                let tcp_handshake = if proto == IPPROTO_TCP {
                    TcpLocalHandshake::SynQueued
                } else {
                    TcpLocalHandshake::None
                };

                let mut ns_counts = self.ns_entry_counts.lock();
                let ns_count = ns_counts.get(&key.net_ns_id).copied().unwrap_or(0);
                // R192-4 FIX (D2-RES-1, R192-RES-4): see `admission_locked`;
                // with no replaceable flow in its scope the flow is rejected
                // before the device queue.
                let admission = if replacing_expired {
                    Admission::Free
                } else {
                    Self::admission_locked(&entries, &ns_counts, key.net_ns_id)
                };
                let victim_plan = match admission {
                    Admission::Free if replacing_expired => Some((key, EgressVictimKind::Expired)),
                    Admission::Free => None,
                    Admission::Replace(victim_key) => Some((victim_key, EgressVictimKind::Evicted)),
                    Admission::Full => {
                        self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                        return CtEgressResult::Rejected(CtUpdateResult {
                            decision: CtDecision::Invalid,
                            state: CtProtoState::Other,
                            dir,
                            resource_exhausted: true,
                        });
                    }
                };

                let victim_in_requester_ns = victim_plan
                    .map(|(victim_key, _)| victim_key.net_ns_id == key.net_ns_id)
                    .unwrap_or(false);
                let effective_ns_count =
                    ns_count.saturating_sub(usize::from(victim_in_requester_ns));
                if key.net_ns_id != CT_ROOT_NS && effective_ns_count >= CT_MAX_ENTRIES_PER_NS {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return CtEgressResult::Rejected(CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: CtProtoState::Other,
                        dir,
                        resource_exhausted: true,
                    });
                }

                if capacity_permit.is_none() {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return CtEgressResult::Rejected(Self::resource_rejection(dir));
                }

                if victim_plan.is_none() {
                    let plan = match entries.capacity_plan_for(1) {
                        Ok(plan) => plan,
                        Err(_) => {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                    };
                    if let Some(plan) = plan {
                        let Some(candidate) = prepared_entries.take() else {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        };
                        if candidate.capacity() < plan.required() {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                        retired_entries =
                            Some(match entries.install_prepared_deferred(candidate) {
                                Ok(retired) => retired,
                                Err(_) => {
                                    // Prepared capacity is an optimization, not a
                                    // correctness assertion.  A stale/rejected
                                    // candidate must become a normal resource
                                    // rejection instead of halting the kernel.
                                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                                    return CtEgressResult::Rejected(Self::resource_rejection(dir));
                                }
                            });
                    }
                }

                let victim_frees_ns_row = victim_plan
                    .and_then(|(victim_key, _)| {
                        ns_counts
                            .get(&victim_key.net_ns_id)
                            .map(|count| *count == 1)
                    })
                    .unwrap_or(false);
                if !ns_counts.contains_key(&key.net_ns_id) && !victim_frees_ns_row {
                    let plan = match ns_counts.capacity_plan_for(1) {
                        Ok(plan) => plan,
                        Err(_) => {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                    };
                    if let Some(plan) = plan {
                        let Some(candidate) = prepared_ns.take() else {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        };
                        if candidate.capacity() < plan.required() {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        }
                        retired_ns = Some(match ns_counts.install_prepared_deferred(candidate) {
                            Ok(retired) => retired,
                            Err(_) => {
                                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                                return CtEgressResult::Rejected(Self::resource_rejection(dir));
                            }
                        });
                    }
                }

                let victim = match victim_plan {
                    Some((victim_key, kind)) => {
                        let Some(entry) = entries.remove(&victim_key) else {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::Rejected(Self::resource_rejection(dir));
                        };
                        Some(DetachedEgressVictim {
                            key: victim_key,
                            entry,
                            kind,
                        })
                    }
                    None => None,
                };

                let mut entry = ConntrackEntry::new(key, initial_state, now_ms, dir);
                entry.local_origin = true;
                entry.pending_egress = Some(PendingEgress {
                    token,
                    new_state: initial_state,
                    decision: CtDecision::New,
                    state_dir: ConntrackDir::Original,
                    payload_len: l4.payload_len,
                    now_ms,
                    tcp_handshake,
                });
                if entries
                    .insert_unique_reserved(key, Mutex::new(entry))
                    .is_err()
                {
                    // The victim's namespace charge has deliberately not been
                    // changed yet.  Restore the detached entry and leave both
                    // ledgers byte-for-byte as they were before this
                    // replacement attempt.
                    if let Some(victim) = victim {
                        if entries
                            .insert_unique_reserved(victim.key, victim.entry)
                            .is_err()
                        {
                            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                            return CtEgressResult::StateLost { queued: false };
                        }
                    }
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return CtEgressResult::Rejected(Self::resource_rejection(dir));
                }

                // Publish namespace accounting as the second half of the
                // replacement transaction.  The old implementation detached
                // the victim and decremented its row first; if the new row
                // publication then failed, removing the new entry leaked the
                // victim and/or its charge.  Keep the victim charge intact
                // until the new entry is present, and only use operations that
                // have an explicit inverse on failure.
                let requester_ns = key.net_ns_id;
                let victim_ns = victim.as_ref().map(|item| item.key.net_ns_id);
                let requester_before = ns_counts.get(&requester_ns).copied();
                let victim_before = victim_ns.and_then(|ns| ns_counts.get(&ns).copied());
                let same_namespace = victim_ns == Some(requester_ns);

                let publication_ok = if same_namespace {
                    // A same-namespace replacement preserves the count.  A
                    // missing/zero row is an accounting corruption, not a
                    // reason to publish an uncharged flow.
                    requester_before.is_some_and(|count| count > 0)
                } else if let Some(victim_ns) = victim_ns {
                    if let Some(victim_count) = victim_before.filter(|count| *count > 0) {
                        if requester_before.is_none() && victim_count == 1 {
                            // The preflight intentionally skipped an allocation
                            // because removing the victim row frees the map slot.
                            ns_counts.remove(&victim_ns);
                            if self.insert_ns_count_reserved(&mut ns_counts, requester_ns, 1) {
                                true
                            } else {
                                false
                            }
                        } else {
                            let requester_ok = if let Some(count) = ns_counts.get_mut(&requester_ns)
                            {
                                count.checked_add(1).map(|next| *count = next).is_some()
                            } else if self.insert_ns_count_reserved(&mut ns_counts, requester_ns, 1)
                            {
                                true
                            } else {
                                false
                            };
                            if !requester_ok {
                                false
                            } else if victim_count == 1 {
                                ns_counts.remove(&victim_ns);
                                true
                            } else if let Some(count) = ns_counts.get_mut(&victim_ns) {
                                *count -= 1;
                                true
                            } else {
                                false
                            }
                        }
                    } else {
                        false
                    }
                } else if let Some(count) = ns_counts.get_mut(&requester_ns) {
                    count.checked_add(1).map(|next| *count = next).is_some()
                } else if self.insert_ns_count_reserved(&mut ns_counts, requester_ns, 1) {
                    true
                } else {
                    false
                };

                if !publication_ok {
                    // Undo any namespace mutations first.  Every restoration
                    // is checked; losing either row is an internal state-loss
                    // event and must never be reported as a normal rejection.
                    let requester_restore_ok = match requester_before {
                        Some(before) => {
                            if let Some(current) = ns_counts.get_mut(&requester_ns) {
                                *current = before;
                                true
                            } else {
                                ns_counts
                                    .insert_unique_reserved(requester_ns, before)
                                    .is_ok()
                            }
                        }
                        None => {
                            ns_counts.remove(&requester_ns);
                            true
                        }
                    };
                    let victim_restore_ok = if let Some(victim_ns) = victim_ns {
                        match victim_before {
                            Some(before) => {
                                if let Some(current) = ns_counts.get_mut(&victim_ns) {
                                    *current = before;
                                    true
                                } else {
                                    ns_counts.insert_unique_reserved(victim_ns, before).is_ok()
                                }
                            }
                            None => {
                                ns_counts.remove(&victim_ns);
                                true
                            }
                        }
                    } else {
                        true
                    };
                    let entry_restore_ok = entries.remove(&key).is_some();
                    let victim_entry_restore_ok = if let Some(victim) = victim {
                        entries
                            .insert_unique_reserved(victim.key, victim.entry)
                            .is_ok()
                    } else {
                        true
                    };
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    if requester_restore_ok
                        && victim_restore_ok
                        && entry_restore_ok
                        && victim_entry_restore_ok
                    {
                        return CtEgressResult::Rejected(Self::resource_rejection(dir));
                    }
                    return CtEgressResult::StateLost { queued: false };
                }
                drop(ns_counts);
                drop(entries);
                EgressReservation {
                    key,
                    dir,
                    token,
                    created_entry: true,
                    victim,
                }
            }
        };

        // Physical frees are after both conntrack locks leave publication.
        // RF192-1 FIX: retain the creation permit through queue settlement.
        // Otherwise another creator can reuse the detached victim's key (or
        // namespace-row slot), making a failed send's rollback lose its owner.
        // The permit never holds a metadata lock or waits for another creator;
        // RAII releases it on every failure return below.
        drop(retired_ns.take());
        drop(retired_entries.take());
        drop(prepared_ns.take());
        drop(prepared_entries.take());

        if let Err(error) = queue() {
            if !self.rollback_egress_reservation(&mut reservation) {
                return CtEgressResult::StateLost { queued: false };
            }
            return CtEgressResult::QueueFailed(error);
        }

        let owner_committed = commit_owner();
        let Some(result) = self.finalize_egress_reservation(&mut reservation) else {
            return CtEgressResult::StateLost { queued: true };
        };
        drop(capacity_permit);
        if owner_committed {
            CtEgressResult::Committed(result)
        } else {
            CtEgressResult::QueuedOwnerStale(result)
        }
    }

    fn rollback_egress_reservation(&self, reservation: &mut EgressReservation) -> bool {
        let mut entries = self.entries.write();
        if !reservation.created_entry {
            let Some(entry_lock) = entries.get(&reservation.key) else {
                return false;
            };
            let mut entry = entry_lock.lock();
            if entry.pending_egress.map(|pending| pending.token) != Some(reservation.token) {
                return false;
            }
            entry.pending_egress = None;
            return true;
        }

        let mut ns_counts = self.ns_entry_counts.lock();
        let token_matches = entries
            .get(&reservation.key)
            .map(|entry_lock| {
                entry_lock
                    .lock()
                    .pending_egress
                    .map(|pending| pending.token)
                    == Some(reservation.token)
            })
            .unwrap_or(false);
        if !token_matches {
            return false;
        }
        let removed = entries.remove(&reservation.key);
        if removed.is_none() {
            return false;
        }
        Self::dec_ns_entry_count_locked(&mut ns_counts, reservation.key.net_ns_id);

        if let Some(victim) = reservation.victim.take() {
            let victim_ns = victim.key.net_ns_id;
            let (victim_key, victim_entry) = (victim.key, victim.entry);
            if let Err((_key, entry)) = entries.insert_unique_reserved(victim_key, victim_entry) {
                // Keep the detached owner attached to the reservation so a
                // caller can retry cleanup; never panic while unwinding a
                // user-triggered queue failure.
                reservation.victim = Some(DetachedEgressVictim {
                    key: victim_key,
                    entry,
                    kind: victim.kind,
                });
                return false;
            }
            if let Some(count) = ns_counts.get_mut(&victim_ns) {
                let Some(next) = count.checked_add(1) else {
                    return false;
                };
                *count = next;
            } else if ns_counts.insert_unique_reserved(victim_ns, 1).is_err() {
                return false;
            }
        }
        true
    }

    fn finalize_egress_reservation(
        &self,
        reservation: &mut EgressReservation,
    ) -> Option<CtUpdateResult> {
        let entries = self.entries.write();
        let entry_lock = entries.get(&reservation.key)?;
        let mut entry = entry_lock.lock();
        let pending = entry.pending_egress?;
        if pending.token != reservation.token {
            return None;
        }
        entry.state = pending.new_state;
        entry.tcp_local_handshake = pending.tcp_handshake;
        entry.update_stats(pending.state_dir, pending.payload_len, pending.now_ms);
        entry.pending_egress = None;
        let result = CtUpdateResult {
            decision: pending.decision,
            state: pending.new_state,
            dir: reservation.dir,
            resource_exhausted: false,
        };
        drop(entry);
        drop(entries);

        if reservation.created_entry {
            self.stats.entries_created.fetch_add(1, Ordering::Relaxed);
            match reservation.victim.as_ref().map(|victim| victim.kind) {
                Some(EgressVictimKind::Expired) => {
                    self.stats.timeout_deletes.fetch_add(1, Ordering::Relaxed);
                    self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
                }
                Some(EgressVictimKind::Evicted) => {
                    self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    self.stats.current_entries.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // The detached victim may own nested heap allocations. Retire it only
        // after every conntrack/count lock has been released.
        drop(reservation.victim.take());
        Some(result)
    }

    /// Create a new conntrack entry.
    fn create_entry(
        &self,
        key: FlowKey,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
        now_ms: u64,
    ) -> CtUpdateResult {
        // Determine initial state first (before acquiring lock)
        let initial_state = match proto {
            IPPROTO_TCP => {
                if l4.is_syn() && !l4.is_ack() {
                    CtProtoState::Tcp(TcpCtState::SynSent)
                } else {
                    // Non-SYN packet without existing entry - invalid
                    self.stats
                        .invalid_transitions
                        .fetch_add(1, Ordering::Relaxed);
                    return CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: CtProtoState::Tcp(TcpCtState::None),
                        dir,
                        resource_exhausted: false,
                    };
                }
            }
            IPPROTO_UDP => CtProtoState::Udp(UdpCtState::Unreplied),
            IPPROTO_ICMP => CtProtoState::Icmp(IcmpCtState::EchoRequest),
            _ => CtProtoState::Other,
        };

        let capacity_permit = match self.try_capacity_permit() {
            Some(permit) => permit,
            None => {
                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                return Self::resource_rejection(dir);
            }
        };

        // Detached prepare: snapshot only fixed metadata under the locks, then
        // allocate and reserve with no conntrack lock held. Every new-flow
        // publication owns `capacity_permit`, so no competitor can invalidate
        // the required length between this snapshot and the write recheck.
        let plans: Result<(Option<CapacityPlan>, Option<CapacityPlan>), AdmittedAllocError> =
            (|| {
                let mut entries = self.entries.write();
                let existing_live = entries
                    .get(&key)
                    .map(|entry_lock| {
                        let entry = entry_lock.lock();
                        entry.pending_egress.is_some() || !entry.is_expired(now_ms)
                    })
                    .unwrap_or(false);
                if existing_live {
                    return Ok((None, None));
                }
                let replacing_expired = entries.get(&key).is_some();
                let table_full = entries.len() >= CT_MAX_ENTRIES;
                let entry_plan = if replacing_expired || table_full {
                    None
                } else {
                    entries.capacity_plan_for(1)?
                };
                let mut ns_counts = self.ns_entry_counts.lock();
                // Preparing a missing row even when an eviction might free one is
                // conservative and closes the victim-changing-to-pending race.
                let ns_plan = if ns_counts.contains_key(&key.net_ns_id) {
                    None
                } else {
                    ns_counts.capacity_plan_for(1)?
                };
                Ok((entry_plan, ns_plan))
            })();
        let (entry_plan, ns_plan) = match plans {
            Ok(plans) => plans,
            Err(_) => {
                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                return Self::resource_rejection(dir);
            }
        };
        let mut prepared_entries: Option<
            PreparedAdmittedMapCapacity<FlowKey, Mutex<ConntrackEntry>>,
        > = match entry_plan {
            Some(plan) => match PreparedAdmittedMapCapacity::try_from_plan(plan) {
                Ok(candidate) => Some(candidate),
                Err(_) => {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
            },
            None => None,
        };
        let mut prepared_ns: Option<PreparedAdmittedMapCapacity<u64, usize>> = match ns_plan {
            Some(plan) => match PreparedAdmittedMapCapacity::try_from_plan(plan) {
                Ok(candidate) => Some(candidate),
                Err(_) => {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
            },
            None => None,
        };
        let mut retired_entries: Option<
            RetiredAdmittedMapCapacity<FlowKey, Mutex<ConntrackEntry>>,
        > = None;
        let mut retired_ns: Option<RetiredAdmittedMapCapacity<u64, usize>> = None;

        // Insert entry
        let mut entries = self.entries.write();

        // Double-check after acquiring write lock
        // R65-2 FIX: Entry was inserted concurrently. Reuse the packet's real
        // direction (`dir`) instead of calling update_on_packet with normalized
        // (ip_lo, ip_hi) which would re-normalize and lose direction information.
        if let Some(entry_lock) = entries.get(&key) {
            let mut entry = entry_lock.lock();

            if entry.pending_egress.is_some() {
                return CtUpdateResult {
                    decision: CtDecision::Invalid,
                    state: entry.state,
                    dir,
                    resource_exhausted: false,
                };
            }

            // R151-10 FIX: If the existing entry is expired, remove it and fall
            // through to create a fresh entry below.
            if entry.is_expired(now_ms) {
                drop(entry);
                if entries.remove(&key).is_some() {
                    self.dec_ns_entry_count(key.net_ns_id);
                    self.stats.timeout_deletes.fetch_add(1, Ordering::Relaxed);
                    self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
                }
                // Fall through to create new entry below
            } else {
                // Calculate state direction relative to initiator
                let state_dir = if dir == entry.initiator_dir {
                    ConntrackDir::Original
                } else {
                    ConntrackDir::Reply
                };

                let (new_state, decision) = self.transition_state(&entry, state_dir, proto, l4);

                if decision == CtDecision::Invalid {
                    self.stats
                        .invalid_transitions
                        .fetch_add(1, Ordering::Relaxed);
                    return CtUpdateResult {
                        decision,
                        state: entry.state,
                        dir,
                        resource_exhausted: false,
                    };
                }

                entry.state = new_state;
                entry.update_stats(state_dir, l4.payload_len, now_ms);

                // R95-2 FIX: Propagate actual decision from state machine
                // (double-check path after write-lock acquisition).
                return CtUpdateResult {
                    decision,
                    state: new_state,
                    dir,
                    resource_exhausted: false,
                };
            } // else (non-expired)
        }

        // RF178-7 / R178-18 FIX: Reserve every potentially-growing metadata
        // store before eviction or publication. Requester quota is deliberately
        // checked first so a saturated namespace cannot evict another tenant.
        let mut ns_counts = self.ns_entry_counts.lock();
        // R192-4 FIX (D2-RES-1, R192-RES-4): see `admission_locked`. The victim
        // is removed only after the namespace row is in place, so a metadata
        // failure rejects the new flow without having evicted one.
        let victim = match Self::admission_locked(&entries, &ns_counts, key.net_ns_id) {
            Admission::Free => None,
            Admission::Replace(victim) => Some(victim),
            Admission::Full => {
                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                return CtUpdateResult {
                    decision: CtDecision::Invalid,
                    state: CtProtoState::Other,
                    dir,
                    resource_exhausted: true,
                };
            }
        };
        let ns_row_exists = ns_counts.get(&key.net_ns_id).is_some();

        if !ns_row_exists {
            let plan = match ns_counts.capacity_plan_for(1) {
                Ok(plan) => plan,
                Err(_) => {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
            };
            if let Some(plan) = plan {
                let Some(candidate) = prepared_ns.take() else {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                };
                if candidate.capacity() < plan.required() {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
                retired_ns = Some(match ns_counts.install_prepared_deferred(candidate) {
                    Ok(retired) => retired,
                    Err(_) => {
                        self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                        return Self::resource_rejection(dir);
                    }
                });
            }
        }

        if victim.is_some() && !self.evict_victim_locked(&mut entries, &mut ns_counts, victim) {
            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
            return Self::resource_rejection(dir);
        }

        let table_full = entries.len() >= CT_MAX_ENTRIES;
        if !table_full {
            let plan = match entries.capacity_plan_for(1) {
                Ok(plan) => plan,
                Err(_) => {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
            };
            if let Some(plan) = plan {
                let Some(candidate) = prepared_entries.take() else {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                };
                if candidate.capacity() < plan.required() {
                    self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                    return Self::resource_rejection(dir);
                }
                retired_entries = Some(match entries.install_prepared_deferred(candidate) {
                    Ok(retired) => retired,
                    Err(_) => {
                        self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                        return Self::resource_rejection(dir);
                    }
                });
            }
        }

        // At the hard cap admission has already replaced a flow (removal
        // retains the ordered map's backing capacity, so the insert is
        // allocation-free) or rejected; a full table here would be a ledger
        // inconsistency, so fail closed.
        if table_full {
            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
            return CtUpdateResult {
                decision: CtDecision::Invalid,
                state: CtProtoState::Other,
                dir,
                resource_exhausted: true,
            };
        }

        // R63-1 FIX: Pass initiator_dir to track the true connection initiator.
        // The first packet's direction (dir) is the initiator direction.
        let mut entry = ConntrackEntry::new(key, initial_state, now_ms, dir);
        // Use Original for stats since this is the first packet from initiator
        entry.update_stats(ConntrackDir::Original, l4.payload_len, now_ms);

        // Both backing stores have capacity now. Keep defensive error handling
        // so a future map implementation change cannot make admission fail open.
        if entries
            .insert_unique_reserved(key, Mutex::new(entry))
            .is_err()
        {
            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
            return Self::resource_rejection(dir);
        }

        if let Some(count) = ns_counts.get_mut(&key.net_ns_id) {
            *count += 1;
        } else if ns_counts.insert_unique_reserved(key.net_ns_id, 1).is_err() {
            // Transactional rollback: no flow may remain published without its
            // namespace charge.
            entries.remove(&key);
            self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
            return CtUpdateResult {
                decision: CtDecision::Invalid,
                state: CtProtoState::Other,
                dir,
                resource_exhausted: true,
            };
        }

        self.stats.entries_created.fetch_add(1, Ordering::Relaxed);
        self.stats.current_entries.fetch_add(1, Ordering::Relaxed);

        drop(ns_counts);
        drop(entries);
        drop(retired_ns.take());
        drop(retired_entries.take());
        drop(prepared_ns.take());
        drop(prepared_entries.take());
        drop(capacity_permit);

        CtUpdateResult {
            decision: CtDecision::New,
            state: initial_state,
            dir,
            resource_exhausted: false,
        }
    }

    /// Compute state transition for a packet.
    fn transition_state(
        &self,
        entry: &ConntrackEntry,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
    ) -> (CtProtoState, CtDecision) {
        self.transition_state_with_handshake(entry, dir, proto, l4, entry.tcp_local_handshake)
    }

    fn transition_state_with_handshake(
        &self,
        entry: &ConntrackEntry,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
        tcp_handshake: TcpLocalHandshake,
    ) -> (CtProtoState, CtDecision) {
        match (proto, &entry.state) {
            (IPPROTO_TCP, CtProtoState::Tcp(tcp_state)) => {
                self.tcp_transition(*tcp_state, tcp_handshake, dir, l4)
            }
            (IPPROTO_UDP, CtProtoState::Udp(udp_state)) => self.udp_transition(*udp_state, dir),
            (IPPROTO_ICMP, CtProtoState::Icmp(icmp_state)) => {
                self.icmp_transition(*icmp_state, dir)
            }
            // R95-2 FIX: Fail-closed instead of fail-open. Protocol/state mismatch
            // (e.g., TCP proto with UDP state) indicates internal corruption or bug.
            // Return Invalid to prevent accidental firewall bypass.
            _ => (entry.state, CtDecision::Invalid),
        }
    }

    fn egress_tcp_handshake(
        &self,
        entry: &ConntrackEntry,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
    ) -> TcpLocalHandshake {
        if proto != IPPROTO_TCP {
            return entry.tcp_local_handshake;
        }
        if l4.is_syn() && !l4.is_ack() {
            return match entry.tcp_local_handshake {
                TcpLocalHandshake::None => TcpLocalHandshake::SynQueued,
                committed => committed,
            };
        }
        if l4.is_syn() && l4.is_ack() {
            return TcpLocalHandshake::SynAckQueued;
        }
        if l4.is_ack()
            && !l4.is_syn()
            && matches!(entry.state, CtProtoState::Tcp(TcpCtState::SynRecv))
            && dir == ConntrackDir::Original
            && entry.tcp_local_handshake == TcpLocalHandshake::SynQueued
        {
            return TcpLocalHandshake::Complete;
        }
        entry.tcp_local_handshake
    }

    /// TCP state machine transition.
    fn tcp_transition(
        &self,
        state: TcpCtState,
        local_handshake: TcpLocalHandshake,
        dir: ConntrackDir,
        l4: &L4Meta,
    ) -> (CtProtoState, CtDecision) {
        // R145-4 FIX: Do NOT transition conntrack state on RST.  The
        // conntrack layer lacks sequence numbers to validate RST legitimacy.
        // Preserve the current state and let the socket layer (RFC 5961)
        // perform proper RST validation.  The conntrack entry expires
        // naturally via its idle timeout.
        // R156-7 FIX: Return Related instead of Established for RST.
        // Established lets spoofed RSTs pass the default firewall ACCEPT
        // rule, amplifying CPU load via socket-layer lock contention.
        // Related allows the firewall to distinguish RST from normal data.
        if l4.is_rst() {
            return (CtProtoState::Tcp(state), CtDecision::Related);
        }

        let new_state = match (state, dir) {
            // SYN sent, waiting for SYN-ACK (normal 3-way handshake)
            (TcpCtState::SynSent, ConntrackDir::Reply)
                if matches!(
                    local_handshake,
                    TcpLocalHandshake::SynQueued | TcpLocalHandshake::SynAckQueued
                ) && l4.is_syn()
                    && l4.is_ack() =>
            {
                TcpCtState::SynRecv
            }
            // R150-I1 FIX: SYN sent, peer also sent bare SYN (simultaneous open).
            // Both endpoints independently initiated; transition to SynRecv so the
            // completing ACK (from either direction) moves to Established.
            (TcpCtState::SynSent, ConntrackDir::Reply)
                if local_handshake == TcpLocalHandshake::SynQueued
                    && l4.is_syn()
                    && !l4.is_ack() =>
            {
                TcpCtState::SynRecv
            }
            // SYN-ACK received, waiting for ACK (normal handshake completion)
            (TcpCtState::SynRecv, ConntrackDir::Original)
                if local_handshake == TcpLocalHandshake::Complete
                    && l4.is_ack()
                    && !l4.is_syn() =>
            {
                TcpCtState::Established
            }
            // Established - handle FIN
            (TcpCtState::Established, _) if l4.is_fin() => match dir {
                ConntrackDir::Original => TcpCtState::FinWait,
                ConntrackDir::Reply => TcpCtState::CloseWait,
            },
            // FIN wait - handle reply FIN or ACK
            // R146-NET-2 FIX: FinWait→FinWait2 on ACK (half-close; peer may
            // still send data), FinWait→LastAck on simultaneous FIN.
            // R156-8 FIX: FIN+ACK (common piggybacked close) skips directly
            // to TimeWait. Without this, the LastAck 30s timeout expires
            // prematurely vs TimeWait 120s if the initiator's ACK is lost.
            (TcpCtState::FinWait, ConntrackDir::Reply) if l4.is_fin() && l4.is_ack() => {
                TcpCtState::TimeWait
            }
            (TcpCtState::FinWait, ConntrackDir::Reply) if l4.is_fin() => TcpCtState::LastAck,
            (TcpCtState::FinWait, ConntrackDir::Reply) if l4.is_ack() => TcpCtState::FinWait2,
            // FinWait2 → TimeWait when peer sends FIN (normal half-close close)
            (TcpCtState::FinWait2, ConntrackDir::Reply) if l4.is_fin() => TcpCtState::TimeWait,
            // Close wait - handle FIN
            (TcpCtState::CloseWait, ConntrackDir::Original) if l4.is_fin() => TcpCtState::LastAck,
            // Last ACK - handle final ACK
            (TcpCtState::LastAck, _) if l4.is_ack() => TcpCtState::TimeWait,
            // Stay in current state for other packets
            _ => state,
        };

        // R95-2 FIX: Compute decision based on post-transition state.
        // - SynSent means the connection has not been acknowledged by the peer,
        //   so the packet is still "New" (firewall should evaluate it against
        //   NEW rules, not pass it as ESTABLISHED).
        // - Close/TimeWait and other teardown states are where the connection
        //   is ending. A SYN during these states indicates tuple reuse, but
        //   we must NOT classify it as Established or attackers can bypass the
        //   firewall via RST→Close→SYN. Treat such packets as Invalid.
        // - None is explicitly invalid.
        // - All other valid states indicate an active tracked connection.
        let is_pure_syn = l4.is_syn() && !l4.is_ack();
        let decision = match (new_state, state) {
            (TcpCtState::SynSent | TcpCtState::SynRecv, _) => CtDecision::New,
            (TcpCtState::None, _) => CtDecision::Invalid,
            // R95-2 HARDENING: If we stayed in ANY teardown state and a pure SYN
            // arrived, reject it. This prevents:
            // - RST→Close→SYN bypass
            // - TimeWait tuple reuse bypass
            // - FinWait/CloseWait/LastAck tuple reuse bypass
            // A legitimate client should wait for the entry to expire or use
            // a different ephemeral port.
            (TcpCtState::Close, TcpCtState::Close)
            | (TcpCtState::TimeWait, TcpCtState::TimeWait)
            | (TcpCtState::FinWait, TcpCtState::FinWait)
            | (TcpCtState::FinWait2, TcpCtState::FinWait2)
            | (TcpCtState::CloseWait, TcpCtState::CloseWait)
            | (TcpCtState::LastAck, TcpCtState::LastAck)
                if is_pure_syn =>
            {
                CtDecision::Invalid
            }
            // R140-2 FIX: Non-SYN packets (ACK, data) remaining in Close/TimeWait
            // are also invalid.  The R95-2 fix blocked SYN tuple reuse but non-SYN
            // packets in teardown states still fell through to Established, allowing
            // post-RST traffic to bypass firewall DROP rules via the ESTABLISHED
            // accept rule.
            (TcpCtState::Close, TcpCtState::Close)
            | (TcpCtState::TimeWait, TcpCtState::TimeWait) => CtDecision::Invalid,
            _ => CtDecision::Established,
        };
        (CtProtoState::Tcp(new_state), decision)
    }

    /// UDP state machine transition.
    fn udp_transition(&self, state: UdpCtState, dir: ConntrackDir) -> (CtProtoState, CtDecision) {
        let new_state = match (state, dir) {
            (UdpCtState::Unreplied, ConntrackDir::Reply) => UdpCtState::Replied,
            _ => state,
        };
        // R95-2 FIX: Unreplied UDP flows are still New (one-way traffic only).
        let decision = match new_state {
            UdpCtState::Unreplied => CtDecision::New,
            UdpCtState::Replied => CtDecision::Established,
        };
        (CtProtoState::Udp(new_state), decision)
    }

    /// ICMP state machine transition.
    fn icmp_transition(&self, state: IcmpCtState, dir: ConntrackDir) -> (CtProtoState, CtDecision) {
        let new_state = match (state, dir) {
            (IcmpCtState::EchoRequest, ConntrackDir::Reply) => IcmpCtState::EchoReply,
            _ => state,
        };
        // R95-2 FIX: Unreplied ICMP echo is still New.
        let decision = match new_state {
            IcmpCtState::EchoRequest => CtDecision::New,
            IcmpCtState::EchoReply => CtDecision::Established,
        };
        (CtProtoState::Icmp(new_state), decision)
    }

    /// Publish a peer final-ACK transition only after the exact socket child
    /// has completed its accept/payload transaction. `update_on_packet` already
    /// accounted the packet while leaving SYN-RECV classified as NEW.
    pub fn commit_tcp_ingress_handshake(
        &self,
        net_ns_id: u64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        let (key, _) =
            FlowKey::from_packet(net_ns_id, IPPROTO_TCP, src_ip, dst_ip, src_port, dst_port);
        let entries = self.entries.read();
        let Some(entry_lock) = entries.get(&key) else {
            return false;
        };
        let mut entry = entry_lock.lock();
        if entry.pending_egress.is_some()
            || entry.state != CtProtoState::Tcp(TcpCtState::SynRecv)
            || entry.tcp_local_handshake != TcpLocalHandshake::SynAckQueued
        {
            return false;
        }
        entry.state = CtProtoState::Tcp(TcpCtState::Established);
        entry.tcp_local_handshake = TcpLocalHandshake::Complete;
        true
    }

    /// R192 FIX (R192-RES-4): the socket layer accepted an RST for this
    /// connection (RFC 5961: exact sequence match), so the flow is over. Mark
    /// it Close: short-lived and replaceable. Conntrack itself still ignores
    /// RST (R145-4), since it cannot validate the sequence number.
    pub fn commit_tcp_ingress_reset(
        &self,
        net_ns_id: u64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        let (key, _) =
            FlowKey::from_packet(net_ns_id, IPPROTO_TCP, src_ip, dst_ip, src_port, dst_port);
        let entries = self.entries.read();
        let Some(entry_lock) = entries.get(&key) else {
            return false;
        };
        let mut entry = entry_lock.lock();
        if !matches!(entry.state, CtProtoState::Tcp(_)) {
            return false;
        }
        let close = CtProtoState::Tcp(TcpCtState::Close);
        // A segment of ours may be queued (`pending_egress`): its commit must
        // not bring the connection back; a rollback leaves `state` as set here.
        if let Some(pending) = entry.pending_egress.as_mut() {
            pending.new_state = close;
        }
        entry.state = close;
        true
    }

    /// Remove an entry by key.
    pub fn remove(&self, key: &FlowKey) -> bool {
        let mut entries = self.entries.write();
        if entries
            .get(key)
            .is_some_and(|entry_lock| entry_lock.lock().pending_egress.is_some())
        {
            return false;
        }
        if entries.remove(key).is_some() {
            self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
            self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
            // R140-9 FIX: Decrement per-namespace entry count.
            self.dec_ns_entry_count(key.net_ns_id);
            true
        } else {
            false
        }
    }

    /// R63-3 FIX: Evict the least-recently-seen entry (LRU) while holding the write lock.
    ///
    /// This prevents table exhaustion attacks where an attacker fills the table
    /// with long-lived UDP or half-open TCP connections to block legitimate traffic.
    ///
    /// # Returns
    ///
    /// R140-9 FIX: Decrement the per-namespace entry count for a removed entry.
    fn dec_ns_entry_count(&self, ns_id: u64) {
        let mut counts = self.ns_entry_counts.lock();
        Self::dec_ns_entry_count_locked(&mut counts, ns_id);
    }

    /// Decrement a namespace charge when the caller already holds the count lock.
    fn dec_ns_entry_count_locked(counts: &mut AdmittedMap<u64, usize>, ns_id: u64) {
        if let Some(c) = counts.get_mut(&ns_id) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&ns_id);
            }
        }
    }

    fn evict_victim_locked(
        &self,
        entries: &mut AdmittedMap<FlowKey, Mutex<ConntrackEntry>>,
        counts: &mut AdmittedMap<u64, usize>,
        victim: Option<FlowKey>,
    ) -> bool {
        let Some(victim_key) = victim else {
            return false;
        };
        if entries.remove(&victim_key).is_none() {
            return false;
        }

        Self::dec_ns_entry_count_locked(counts, victim_key.net_ns_id);
        self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
        self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// R192-4 FIX (D2-RES-1, R192-RES-4): where a new flow of namespace `ns`
    /// takes its slot from. RF178-7/R63-3: the scans are allocation-free and
    /// bounded by the heap-derived `CT_MAX_ENTRIES` cap.
    ///
    /// The per-namespace share was checked before an eviction that ran only at
    /// the global cap, so a namespace at its share (64 flows a peer keeps
    /// refreshed) rejected every new flow while the table had room, and the
    /// root namespace's ingress hard-dropped. Now:
    /// - a tenant at its share, or with the tenants together at
    ///   `CT_MAX_ENTRIES - CT_ROOT_RESERVE`, replaces its own oldest
    ///   replaceable flow, so it can neither evict another namespace nor take
    ///   root's reserve;
    /// - root has no share of its own, only the global cap;
    /// - at the global cap, root replaces its own oldest replaceable flow, and
    ///   a tenant below its limits takes root's oldest replaceable flow (root
    ///   then holds more than its reserve), never another tenant's.
    ///
    /// Only replaceable flows are victims, so an established session is never
    /// evicted to admit a flow; with none in scope the flow is rejected.
    fn admission_locked(
        entries: &AdmittedMap<FlowKey, Mutex<ConntrackEntry>>,
        ns_counts: &AdmittedMap<u64, usize>,
        ns: u64,
    ) -> Admission {
        let table_len = entries.len();
        let ns_count = ns_counts.get(&ns).copied().unwrap_or(0);
        let root_count = ns_counts.get(&CT_ROOT_NS).copied().unwrap_or(0);
        let tenant_total = table_len.saturating_sub(root_count);
        let scope = if ns != CT_ROOT_NS
            && (ns_count >= CT_MAX_ENTRIES_PER_NS
                || tenant_total >= CT_MAX_ENTRIES - CT_ROOT_RESERVE)
        {
            ns
        } else if table_len >= CT_MAX_ENTRIES {
            CT_ROOT_NS
        } else {
            return Admission::Free;
        };
        match Self::lru_victim_in_ns_locked(entries, scope) {
            Some(victim) => Admission::Replace(victim),
            None => Admission::Full,
        }
    }

    /// The least-recently-seen replaceable flow of namespace `ns`
    /// (`ConntrackEntry::replaceable`), preferring a flow a remote peer created
    /// over one this host initiated, so a flood of new tuples replaces its own
    /// flows before an outbound handshake or query waiting for its reply.
    /// Deterministic; a flow with pending egress is never a victim.
    fn lru_victim_in_ns_locked(
        entries: &AdmittedMap<FlowKey, Mutex<ConntrackEntry>>,
        ns: u64,
    ) -> Option<FlowKey> {
        let mut remote: Option<(FlowKey, u64)> = None;
        let mut local: Option<(FlowKey, u64)> = None;
        for (flow_key, entry_lock) in entries.iter() {
            if flow_key.net_ns_id != ns {
                continue;
            }
            let entry = entry_lock.lock();
            if entry.pending_egress.is_some() || !entry.replaceable() {
                continue;
            }
            let best = if entry.local_origin {
                &mut local
            } else {
                &mut remote
            };
            let last_seen_ms = entry.last_seen_ms;
            let replace = match *best {
                None => true,
                Some((victim_key, victim_last_seen)) => {
                    last_seen_ms < victim_last_seen
                        || (last_seen_ms == victim_last_seen && *flow_key < victim_key)
                }
            };
            if replace {
                *best = Some((*flow_key, last_seen_ms));
            }
        }
        remote.or(local).map(|(key, _)| key)
    }

    /// Sweep expired entries.
    ///
    /// Should be called periodically from timer context.
    /// Returns the number of entries removed.
    pub fn sweep(&self, now_ms: u64, budget: usize) -> usize {
        // R163-24 FIX: Fallible allocation for timer-context sweep.
        let mut to_remove = AdmittedVec::new(HeapClass::SocketObject);
        if to_remove
            .ensure_capacity_for(budget.min(CT_SWEEP_BUDGET))
            .is_err()
        {
            return 0;
        }

        // Collect expired keys with read lock
        {
            let entries = self.entries.read();
            for (key, entry_lock) in entries.iter() {
                if to_remove.len() >= budget {
                    break;
                }
                let entry = entry_lock.lock();
                if entry.pending_egress.is_none() && entry.is_expired(now_ms) {
                    if to_remove.push_reserved(*key).is_err() {
                        break;
                    }
                }
            }
        }

        // Remove with write lock
        // R65-4 FIX: Only decrement current_entries for entries actually removed.
        // The previous code unconditionally decremented by to_remove.len(), but
        // concurrent operations might have already removed some entries.
        // Now we check remove() return value and only count successful removals.
        if !to_remove.is_empty() {
            let mut entries = self.entries.write();
            let mut actually_removed: u64 = 0;
            for key in &to_remove {
                // R65-4 FIX: Check if entry actually existed before counting
                let removable = entries
                    .get(key)
                    .is_some_and(|entry_lock| entry_lock.lock().pending_egress.is_none());
                if removable && entries.remove(key).is_some() {
                    actually_removed += 1;
                    // R140-9 FIX: Decrement per-namespace entry count.
                    self.dec_ns_entry_count(key.net_ns_id);
                }
            }
            if actually_removed > 0 {
                self.stats
                    .timeout_deletes
                    .fetch_add(actually_removed, Ordering::Relaxed);
                self.stats
                    .entries_deleted
                    .fetch_add(actually_removed, Ordering::Relaxed);
                // R65-4 FIX: Only subtract actually removed count to prevent underflow
                self.stats
                    .current_entries
                    .fetch_sub(actually_removed as u32, Ordering::Relaxed);
            }
            actually_removed as usize
        } else {
            0
        }
    }

    /// R171-G4-2 FIX: remove ALL conntrack flows belonging to a destroyed network
    /// namespace and drop its per-ns counter row. Namespace teardown must reclaim
    /// the ns's `CT_MAX_ENTRIES_PER_NS` budget + the global table slots immediately
    /// (ns ids are never reused) rather than waiting for each flow to time out via
    /// the periodic `sweep`. This is the conntrack analogue of the socket-table
    /// `drain_ns_counters` teardown backstop (R170-7) — the 6th per-ns map that
    /// backstop missed. Returns the number of flows removed.
    pub fn drain_ns(&self, ns_id: u64) -> usize {
        // Repeated ordered-map removal deletes EVERY flow for this namespace
        // without intermediate allocation or a read-then-write snapshot window.
        // The O(table^2) shifts are bounded by CT_MAX_ENTRIES and namespace
        // teardown is rare. (NOTE: a packet on
        // a socket that outlives the namespace and still carries this raw ns id
        // could re-create a flow AFTER this drain; that straggler is bounded and
        // reclaimed by the now-wired periodic `ct_sweep`, matching the accepted
        // self-healing residual of the socket-table teardown backstop, R170-7.)
        let mut removed: u64 = 0;
        let mut entries = self.entries.write();
        // Keep the namespace-count ledger under the same entries -> counts
        // lock order used by every other removal path.  Updating it in the
        // removal loop is essential: deleting the row only after the loop
        // loses the distinction between live and provisional entries and
        // strands one charge per removed flow.
        let mut ns_counts = self.ns_entry_counts.lock();
        loop {
            let victim = entries
                .iter()
                .find(|(key, entry_lock)| {
                    key.net_ns_id == ns_id && entry_lock.lock().pending_egress.is_none()
                })
                .map(|(key, _)| *key);
            let Some(key) = victim else {
                break;
            };
            if entries.remove(&key).is_some() {
                removed += 1;
                Self::dec_ns_entry_count_locked(&mut ns_counts, key.net_ns_id);
            }
        }

        // Preserve the row while an unresolved provisional transaction still
        // owns a flow. Its finalizer/rollback will settle the exact charge; a
        // later teardown drain removes the row once no protected entry remains.
        let provisional_remains = entries.keys().any(|key| key.net_ns_id == ns_id);
        if !provisional_remains {
            ns_counts.remove(&ns_id);
        }
        drop(ns_counts);
        drop(entries);

        if removed > 0 {
            self.stats
                .entries_deleted
                .fetch_add(removed, Ordering::Relaxed);
            self.stats
                .current_entries
                .fetch_sub(removed as u32, Ordering::Relaxed);
        }
        removed as usize
    }

    /// Get current statistics.
    pub fn stats(&self) -> &ConntrackStats {
        &self.stats
    }

    /// Get current entry count.
    pub fn len(&self) -> usize {
        self.stats.current_entries.load(Ordering::Relaxed) as usize
    }

    /// Check if table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static CONNTRACK_TABLE: Once<ConntrackTable> = Once::new();

// RF186-22 FIX: only hosted tests that mutate the global singleton take this
// guard. The singleton's production concurrency remains fully exercised and
// production code must never acquire a test-serialization lock.
#[cfg(all(test, feature = "conntrack"))]
pub(crate) static GLOBAL_CONNTRACK_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Get the global conntrack table.
pub fn conntrack_table() -> &'static ConntrackTable {
    CONNTRACK_TABLE.call_once(ConntrackTable::new)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Process a TCP packet through conntrack.
/// R107-2 FIX: Namespace-isolated conntrack processing.
pub fn ct_process_tcp(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    let l4 = L4Meta::new(tcp_flags, payload_len);
    conntrack_table().update_on_packet(
        net_ns_id,
        IPPROTO_TCP,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &l4,
        now_ms,
    )
}

/// Transactional outbound TCP conntrack update paired with the final device
/// queue operation. See [`ConntrackTable::update_on_egress_transaction`].
pub fn ct_egress_tcp<E, F>(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
    now_ms: u64,
    queue: F,
) -> CtEgressResult<E>
where
    F: FnOnce() -> Result<(), E>,
{
    let l4 = L4Meta::new(tcp_flags, payload_len);
    conntrack_table().update_on_egress_transaction(
        net_ns_id,
        IPPROTO_TCP,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &l4,
        now_ms,
        queue,
    )
}

/// Stateful TCP egress transaction with an identity-bound socket commit that
/// runs only after device acceptance and before conntrack finalization.
pub(crate) fn ct_egress_tcp_with_commit<E, F, C>(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
    now_ms: u64,
    queue: F,
    commit_owner: C,
) -> CtEgressResult<E>
where
    F: FnOnce() -> Result<(), E>,
    C: FnOnce() -> bool,
{
    let l4 = L4Meta::new(tcp_flags, payload_len);
    conntrack_table().update_on_egress_transaction_with_commit(
        net_ns_id,
        IPPROTO_TCP,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &l4,
        now_ms,
        queue,
        commit_owner,
    )
}

/// Complete a socket-accepted peer final ACK without re-accounting the packet.
pub fn ct_commit_tcp_ingress_handshake(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> bool {
    conntrack_table().commit_tcp_ingress_handshake(net_ns_id, src_ip, dst_ip, src_port, dst_port)
}

/// R192 FIX (R192-RES-4): report an RST the socket layer accepted (RFC 5961).
pub fn ct_commit_tcp_ingress_reset(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> bool {
    conntrack_table().commit_tcp_ingress_reset(net_ns_id, src_ip, dst_ip, src_port, dst_port)
}

/// Process a UDP packet through conntrack.
/// R107-2 FIX: Namespace-isolated conntrack processing.
pub fn ct_process_udp(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    let l4 = L4Meta::new(0, payload_len);
    conntrack_table().update_on_packet(
        net_ns_id,
        IPPROTO_UDP,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &l4,
        now_ms,
    )
}

/// Transactional outbound UDP conntrack update paired with the final device
/// queue operation. See [`ConntrackTable::update_on_egress_transaction`].
pub fn ct_egress_udp<E, F>(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    now_ms: u64,
    queue: F,
) -> CtEgressResult<E>
where
    F: FnOnce() -> Result<(), E>,
{
    let l4 = L4Meta::new(0, payload_len);
    conntrack_table().update_on_egress_transaction(
        net_ns_id,
        IPPROTO_UDP,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &l4,
        now_ms,
        queue,
    )
}

/// Process an ICMP packet through connection tracking.
///
/// ICMP tracking is simpler than TCP/UDP:
/// - Echo request/reply pairs can be tracked
/// - ICMP error messages (Type 3, 11, etc.) are RELATED to existing connections
/// - Other ICMP messages are treated as NEW
///
/// R107-2 FIX: Namespace-isolated conntrack processing.
///
/// # Arguments
/// * `net_ns_id` - Network namespace ID
/// * `src_ip` - Source IP address
/// * `dst_ip` - Destination IP address
/// * `icmp_type` - ICMP message type
/// * `icmp_code` - ICMP message code
/// * `icmp_id` - Echo identifier (zero for non-echo messages)
/// * `payload_len` - Length of payload
/// * `now_ms` - Current time in milliseconds
pub fn ct_process_icmp(
    net_ns_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    icmp_id: u16,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    // ICMP error messages (Destination Unreachable, Time Exceeded, etc.)
    // are RELATED to existing connections
    let is_error_type = icmp_type == 3 || icmp_type == 11 || icmp_type == 12;

    // Use type/code as pseudo-ports for flow tracking
    // This allows tracking echo request/reply pairs
    // Include the echo identifier in the flow key.  Type/code alone aliases
    // every ping stream in a namespace and makes unrelated request/reply
    // pairs collide under concurrent traffic.
    let pseudo_src_port = icmp_id;
    let pseudo_dst_port = ((icmp_type as u16) << 8) | (icmp_code as u16);

    let l4 = L4Meta::new(0, payload_len);

    // R159-I2 FIX: ICMP error packets (Dest Unreachable, Time Exceeded,
    // Parameter Problem) are classified as RELATED. Without parsing the
    // embedded IP header we cannot verify the original flow, but returning
    // Related is correct per RFC and allows firewall rules matching
    // ESTABLISHED/RELATED to pass legitimate ICMP error feedback
    // (e.g., path MTU discovery, traceroute TTL exceeded).
    if is_error_type {
        return CtUpdateResult {
            decision: CtDecision::Related,
            state: CtProtoState::Icmp(IcmpCtState::EchoRequest),
            dir: ConntrackDir::Original,
            resource_exhausted: false,
        };
    }

    conntrack_table().update_on_packet(
        net_ns_id,
        IPPROTO_ICMP,
        src_ip,
        dst_ip,
        pseudo_src_port,
        pseudo_dst_port,
        &l4,
        now_ms,
    )
}

/// Run conntrack sweep (call from timer).
pub fn ct_sweep(now_ms: u64) -> usize {
    conntrack_table().sweep(now_ms, CT_SWEEP_BUDGET)
}

/// R171-G4-2 FIX: drain all conntrack flows for a destroyed network namespace.
/// Called from `NetNamespace::Drop` so a torn-down namespace reclaims its
/// conntrack budget + global table slots immediately. Returns flows removed.
pub fn ct_drain_ns(ns_id: u64) -> usize {
    conntrack_table().drain_ns(ns_id)
}

/// R171-G4-1/G4-2 in-kernel self-test (boot suite). Verifies (1) the periodic
/// timer sweep reclaims an expired flow (`ct_sweep`, now wired into
/// `net::handle_timer_tick`), and (2) namespace-teardown drain (`ct_drain_ns`)
/// removes ALL of a namespace's flows and drops its per-ns counter row, and (3)
/// a namespace at its share replaces its own oldest flow (R192-4). Panics on failure
/// → caught by `make test`. Uses high, otherwise-unused test namespace ids so it
/// never perturbs real traffic.
pub fn run_conntrack_reclaim_self_test() {
    let table = conntrack_table();
    let ns_sweep: u64 = 0x7E57_0001;
    let ns_drain: u64 = 0x7E57_0002;
    let ip_a = Ipv4Addr::new(10, 0, 0, 1);
    let ip_b = Ipv4Addr::new(10, 0, 0, 2);
    let t0: u64 = 1_000;
    const SYN: u8 = 0x02;

    // (1) the periodic sweep reclaims an expired flow.
    let before = table.len();
    let _ = ct_process_tcp(ns_sweep, ip_a, ip_b, 12345, 80, SYN, 0, t0);
    assert!(
        table.len() > before,
        "conntrack: tracking a flow must grow the table"
    );
    let far_future = t0 + 24 * 3600 * 1000; // +24h: past any conntrack timeout
    let swept = ct_sweep(far_future);
    assert!(
        swept >= 1,
        "conntrack: ct_sweep must reclaim the expired flow"
    );

    // (2) namespace-teardown drain removes all of a ns's flows + drops its row.
    for p in 0..4u16 {
        let _ = ct_process_tcp(ns_drain, ip_a, ip_b, 20000 + p, 80, SYN, 0, far_future);
    }
    let drained = ct_drain_ns(ns_drain);
    assert!(
        drained >= 1,
        "conntrack: ct_drain_ns must remove the ns's flows"
    );
    // Idempotent: nothing left, the counter row is already gone.
    assert_eq!(
        ct_drain_ns(ns_drain),
        0,
        "conntrack: ns drain must be idempotent"
    );

    // (3) R192-4: a namespace at its share replaces its own least-recently-seen
    // replaceable flow (here SYN-only TCP) instead of hard-dropping every new
    // one while the table has room.
    let ns_quota: u64 = 0x7E57_0003;
    for p in 0..CT_MAX_ENTRIES_PER_NS as u16 {
        // The first flow is the oldest, so it is the deterministic victim.
        let seen = if p == 0 { far_future - 1 } else { far_future };
        let result = ct_process_tcp(ns_quota, ip_a, ip_b, 30000 + p, 443, SYN, 0, seen);
        assert!(
            !result.resource_exhausted,
            "conntrack: entries within the namespace quota must be admitted"
        );
    }
    let before_replace = table.len();
    let replaced = ct_process_tcp(
        ns_quota,
        ip_a,
        ip_b,
        30000 + CT_MAX_ENTRIES_PER_NS as u16,
        443,
        SYN,
        0,
        far_future,
    );
    assert!(
        !replaced.resource_exhausted,
        "conntrack: a namespace at its share must replace its own LRU flow"
    );
    assert_eq!(
        table.len(),
        before_replace,
        "conntrack: a same-namespace replacement keeps the table size"
    );
    let oldest = FlowKey::from_packet(ns_quota, IPPROTO_TCP, ip_a, ip_b, 30000, 443).0;
    assert!(
        table.lookup(&oldest).is_none(),
        "conntrack: the namespace's oldest flow is the one replaced"
    );
    assert_eq!(
        ct_drain_ns(ns_quota),
        CT_MAX_ENTRIES_PER_NS,
        "conntrack: quota self-test cleanup must reclaim every flow"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum QueueFault {
        Full,
    }

    fn endpoints() -> (Ipv4Addr, Ipv4Addr) {
        (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2))
    }

    #[test]
    fn rf180_41_new_flow_queue_failure_publishes_no_conntrack_state() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let queued = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            41,
            IPPROTO_TCP,
            local,
            remote,
            40_001,
            443,
            &L4Meta::new(0x02, 0),
            1_000,
            || {
                queued.set(true);
                Err(QueueFault::Full)
            },
        );

        assert!(matches!(
            outcome,
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));
        assert!(queued.get(), "queue runs only after admission preflight");
        assert_eq!(table.len(), 0);
        assert_eq!(table.stats.current_entries.load(Ordering::Relaxed), 0);
        assert_eq!(table.stats.entries_created.load(Ordering::Relaxed), 0);
        assert!(table.ns_entry_counts.lock().is_empty());
    }

    #[test]
    fn rf180_41_existing_reply_queue_failure_preserves_transition_and_counters() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        assert!(matches!(
            table.update_on_egress_transaction(
                42,
                IPPROTO_TCP,
                local,
                remote,
                40_002,
                443,
                &L4Meta::new(0x02, 0),
                2_000,
                || Ok::<(), QueueFault>(()),
            ),
            CtEgressResult::Committed(_)
        ));
        let (key, _) = FlowKey::from_packet(42, IPPROTO_TCP, local, remote, 40_002, 443);
        let before = table.lookup(&key).expect("seed transaction committed");

        assert!(matches!(
            table.update_on_egress_transaction(
                42,
                IPPROTO_TCP,
                remote,
                local,
                443,
                40_002,
                &L4Meta::new(0x12, 0),
                2_001,
                || Err(QueueFault::Full),
            ),
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));

        let after = table.lookup(&key).expect("entry retained after QueueFull");
        assert_eq!(after.state, before.state);
        assert_eq!(after.last_seen_ms, before.last_seen_ms);
        assert_eq!(after.packets_orig, before.packets_orig);
        assert_eq!(after.packets_reply, before.packets_reply);
        assert_eq!(after.bytes_orig, before.bytes_orig);
        assert_eq!(after.bytes_reply, before.bytes_reply);
        assert_eq!(after.seen_reply, before.seen_reply);
        assert_eq!(table.stats.entries_created.load(Ordering::Relaxed), 1);
        assert_eq!(table.stats.current_entries.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rf180_41_admission_rejection_never_invokes_device_queue() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            let result = table.update_on_packet(
                43,
                IPPROTO_TCP,
                local,
                remote,
                20_000 + index as u16,
                443,
                &L4Meta::new(0x02, 0),
                3_000,
            );
            assert!(!result.resource_exhausted);
        }

        // R192-4: a namespace at its share now replaces its own LRU flow, so
        // the admission rejection under test is a busy capacity permit (another
        // publication is preparing); it must still precede the device queue.
        let _permit = table.try_capacity_permit().expect("idle table");
        let queued = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            43,
            IPPROTO_TCP,
            local,
            remote,
            30_000,
            443,
            &L4Meta::new(0x02, 0),
            3_001,
            || {
                queued.set(true);
                Ok::<(), QueueFault>(())
            },
        );
        assert!(matches!(
            outcome,
            CtEgressResult::Rejected(CtUpdateResult {
                resource_exhausted: true,
                ..
            })
        ));
        assert!(!queued.get());
        assert_eq!(table.len(), CT_MAX_ENTRIES_PER_NS);
    }

    #[test]
    fn r192_4_namespace_at_its_share_replaces_its_own_lru_flow() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        // Tenant 5 fills its share; its first flow is its oldest.
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            let seen = if index == 0 { 2 } else { 3 };
            let port = 10_000 + index as u16;
            let result =
                table.update_on_packet(5, IPPROTO_UDP, local, remote, port, 53, &udp, seen);
            assert!(!result.resource_exhausted);
        }
        // Another tenant's flows are older still: a global LRU would pick them.
        for port in 20_000..20_008u16 {
            let result = table.update_on_packet(7, IPPROTO_UDP, local, remote, port, 53, &udp, 1);
            assert!(!result.resource_exhausted);
        }
        let total = table.len();
        assert!(total < CT_MAX_ENTRIES, "the global table still has room");
        let own_flow = |port| FlowKey::from_packet(5, IPPROTO_UDP, local, remote, port, 53).0;
        let other_untouched = || {
            (20_000..20_008u16).all(|port| {
                let key = FlowKey::from_packet(7, IPPROTO_UDP, local, remote, port, 53).0;
                table.lookup(&key).is_some()
            })
        };

        // Ingress: the new flow replaces the tenant's own oldest flow.
        let ingress = table.update_on_packet(5, IPPROTO_UDP, local, remote, 11_000, 53, &udp, 4);
        assert!(
            !ingress.resource_exhausted,
            "a namespace at its share was hard-dropped"
        );
        assert_eq!(table.len(), total);
        assert!(table.lookup(&own_flow(11_000)).is_some());
        assert!(table.lookup(&own_flow(10_000)).is_none());
        assert!(other_untouched());
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert_eq!(table.ns_entry_counts.lock().get(&7).copied(), Some(8));

        // Egress: the transactional path replaces an own flow the same way.
        let queued = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_UDP,
            local,
            remote,
            12_000,
            53,
            &udp,
            5,
            || {
                queued.set(true);
                Ok::<(), QueueFault>(())
            },
        );
        assert!(matches!(outcome, CtEgressResult::Committed(_)));
        assert!(queued.get());
        assert_eq!(table.len(), total);
        assert!(table.lookup(&own_flow(12_000)).is_some());
        assert!(other_untouched());
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert_eq!(table.drain_ns(5), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.drain_ns(7), 8);
    }

    /// Drive one UDP flow of `ns` (local `port` to remote port 53): its first
    /// packet at `t`, and with `stream` a reply at `t + 500` and one more packet
    /// at `t + CT_UDP_STREAM_MS`, which makes it a stream.
    fn udp_flow(table: &ConntrackTable, ns: u64, port: u16, t: u64, stream: bool) {
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        let first = table.update_on_packet(ns, IPPROTO_UDP, local, remote, port, 53, &udp, t);
        assert!(!first.resource_exhausted);
        if stream {
            let reply =
                table.update_on_packet(ns, IPPROTO_UDP, remote, local, 53, port, &udp, t + 500);
            assert_eq!(reply.decision, CtDecision::Established);
            let next = t + CT_UDP_STREAM_MS;
            table.update_on_packet(ns, IPPROTO_UDP, local, remote, port, 53, &udp, next);
        }
    }

    #[test]
    fn r192_4_established_sessions_are_never_replaced_at_the_share() {
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        let own_flow = |port| FlowKey::from_packet(5, IPPROTO_UDP, local, remote, port, 53).0;
        let entry = |state| ConntrackEntry::new(own_flow(1), state, 0, ConntrackDir::Original);
        for state in [
            TcpCtState::Established,
            TcpCtState::FinWait,
            TcpCtState::FinWait2,
            TcpCtState::CloseWait,
            TcpCtState::LastAck,
        ] {
            assert!(!entry(CtProtoState::Tcp(state)).replaceable());
        }
        for state in [
            TcpCtState::None,
            TcpCtState::SynSent,
            TcpCtState::SynRecv,
            TcpCtState::TimeWait,
            TcpCtState::Close,
        ] {
            assert!(entry(CtProtoState::Tcp(state)).replaceable());
        }
        assert!(entry(CtProtoState::Udp(UdpCtState::Unreplied)).replaceable());
        // A single request and answer stays replaceable; a stream does not.
        let mut answered = entry(CtProtoState::Udp(UdpCtState::Replied));
        answered.last_seen_ms = CT_UDP_STREAM_MS - 1;
        assert!(answered.replaceable());
        answered.last_seen_ms = CT_UDP_STREAM_MS;
        assert!(!answered.replaceable());
        assert!(entry(CtProtoState::Icmp(IcmpCtState::EchoReply)).replaceable());
        assert!(entry(CtProtoState::Other).replaceable());

        let table = ConntrackTable::new();
        let last = CT_MAX_ENTRIES_PER_NS - 1;
        // Tenant 5 fills its share with streams, then one answered request.
        for index in 0..last {
            udp_flow(&table, 5, 10_000 + index as u16, 1_000, true);
        }
        let answered = 10_000 + last as u16;
        udp_flow(&table, 5, answered, 3_100, false);
        let reply =
            table.update_on_packet(5, IPPROTO_UDP, remote, local, 53, answered, &udp, 3_200);
        assert_eq!(reply.decision, CtDecision::Established);
        let streams_untouched =
            || (0..last).all(|index| table.lookup(&own_flow(10_000 + index as u16)).is_some());

        // The answered request is replaced, although it is the newest flow.
        let ingress =
            table.update_on_packet(5, IPPROTO_UDP, local, remote, 11_000, 53, &udp, 3_300);
        assert!(!ingress.resource_exhausted);
        assert!(table.lookup(&own_flow(answered)).is_none());
        assert!(table.lookup(&own_flow(11_000)).is_some());
        assert!(streams_untouched());
        let reply = table.update_on_packet(5, IPPROTO_UDP, remote, local, 53, 11_000, &udp, 3_400);
        assert_eq!(reply.decision, CtDecision::Established);
        table.update_on_packet(5, IPPROTO_UDP, local, remote, 11_000, 53, &udp, 5_300);

        // Every flow is a stream now: a new flow is rejected, none is evicted,
        // and the egress rejection precedes the device queue.
        let ingress =
            table.update_on_packet(5, IPPROTO_UDP, local, remote, 11_001, 53, &udp, 5_400);
        assert!(ingress.resource_exhausted);
        assert!(table.lookup(&own_flow(11_001)).is_none());
        let queued = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_UDP,
            local,
            remote,
            12_000,
            53,
            &udp,
            5_500,
            || {
                queued.set(true);
                Ok::<(), QueueFault>(())
            },
        );
        assert!(matches!(
            outcome,
            CtEgressResult::Rejected(CtUpdateResult {
                resource_exhausted: true,
                ..
            })
        ));
        assert!(!queued.get());
        assert!(streams_untouched());
        assert!(table.lookup(&own_flow(11_000)).is_some());
        assert_eq!(table.len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert_eq!(table.drain_ns(5), CT_MAX_ENTRIES_PER_NS);
    }

    #[test]
    fn r192_res_4_root_keeps_its_reserve_and_tenants_borrow_only_its_surplus() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        let flow = |ns, port| FlowKey::from_packet(ns, IPPROTO_UDP, local, remote, port, 53).0;
        let count = |ns| table.ns_entry_counts.lock().get(&ns).copied().unwrap_or(0);
        let tenant_room = CT_MAX_ENTRIES - CT_ROOT_RESERVE;
        // Tenants fill their combined limit with replaceable (unreplied) flows.
        let tenants = [61u64, 62, 63];
        assert_eq!(tenants.len() * CT_MAX_ENTRIES_PER_NS, tenant_room);
        let mut port = 20_000u16;
        for &ns in &tenants {
            for _ in 0..CT_MAX_ENTRIES_PER_NS {
                udp_flow(&table, ns, port, 1, false);
                port += 1;
            }
        }
        assert_eq!(table.len(), tenant_room);

        // A new tenant gets no slot from the tenants or from root's reserve.
        let refused = table.update_on_packet(70, IPPROTO_UDP, local, remote, 30_000, 53, &udp, 10);
        assert!(refused.resource_exhausted);
        assert_eq!(table.len(), tenant_room);
        assert_eq!(count(70), 0);
        // A tenant at its share still replaces its own oldest flow.
        let own = table.update_on_packet(61, IPPROTO_UDP, local, remote, 30_001, 53, &udp, 10);
        assert!(!own.resource_exhausted);
        assert!(table.lookup(&flow(61, 20_000)).is_none());
        assert_eq!(table.len(), tenant_room);

        // Root is not held to a per-namespace share: it fills the reserve.
        for index in 0..CT_ROOT_RESERVE {
            udp_flow(&table, CT_ROOT_NS, 40_000 + index as u16, 20, false);
        }
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        assert_eq!(count(CT_ROOT_NS), CT_ROOT_RESERVE);
        // At the full table root replaces its own oldest flow, never a tenant's.
        let root =
            table.update_on_packet(CT_ROOT_NS, IPPROTO_UDP, local, remote, 41_000, 53, &udp, 30);
        assert!(!root.resource_exhausted);
        assert!(table.lookup(&flow(CT_ROOT_NS, 40_000)).is_none());
        assert_eq!(count(CT_ROOT_NS), CT_ROOT_RESERVE);
        for &ns in &tenants {
            assert_eq!(count(ns), CT_MAX_ENTRIES_PER_NS);
        }

        // With one tenant gone root grows past its reserve; that surplus is
        // what a tenant below its limits may borrow at the full table.
        let gone = tenants[tenants.len() - 1];
        assert_eq!(table.drain_ns(gone), CT_MAX_ENTRIES_PER_NS);
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            udp_flow(&table, CT_ROOT_NS, 42_000 + index as u16, 40, false);
        }
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        let root_before = count(CT_ROOT_NS);
        assert_eq!(root_before, CT_ROOT_RESERVE + CT_MAX_ENTRIES_PER_NS);
        let borrowed = table.update_on_packet(70, IPPROTO_UDP, local, remote, 30_002, 53, &udp, 50);
        assert!(!borrowed.resource_exhausted);
        assert_eq!(count(70), 1);
        assert_eq!(count(CT_ROOT_NS), root_before - 1);
        assert!(
            table.lookup(&flow(CT_ROOT_NS, 40_001)).is_none(),
            "root's oldest flow"
        );
        for &ns in &tenants[..tenants.len() - 1] {
            assert_eq!(count(ns), CT_MAX_ENTRIES_PER_NS);
        }

        for ns in tenants.into_iter().chain([70, CT_ROOT_NS]) {
            table.drain_ns(ns);
        }
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn r192_4_global_eviction_spares_established_sessions() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        let flow = |ns, port| FlowKey::from_packet(ns, IPPROTO_UDP, local, remote, port, 53).0;
        // Two tenants fill their shares with streams; root fills the rest with
        // streams, except one unreplied flow, which is the newest in the table.
        let mut port = 20_000u16;
        for ns in [61u64, 62] {
            for _ in 0..CT_MAX_ENTRIES_PER_NS {
                udp_flow(&table, ns, port, 1_000, true);
                port += 1;
            }
        }
        let root_flows = CT_MAX_ENTRIES - 2 * CT_MAX_ENTRIES_PER_NS;
        let unreplied = port + 7;
        for _ in 0..root_flows {
            let stream = port != unreplied;
            udp_flow(
                &table,
                CT_ROOT_NS,
                port,
                if stream { 1_000 } else { 3_050 },
                stream,
            );
            port += 1;
        }
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        let streams_untouched = || {
            (20_000..port).filter(|&p| p != unreplied).all(|p| {
                let ns = match (p - 20_000) / CT_MAX_ENTRIES_PER_NS as u16 {
                    0 => 61,
                    1 => 62,
                    _ => CT_ROOT_NS,
                };
                table.lookup(&flow(ns, p)).is_some()
            })
        };

        // A new tenant below its limits replaces the only replaceable flow of
        // root's surplus, not the older streams.
        let first = table.update_on_packet(70, IPPROTO_UDP, local, remote, 30_000, 53, &udp, 3_100);
        assert!(!first.resource_exhausted);
        assert!(table.lookup(&flow(CT_ROOT_NS, unreplied)).is_none());
        assert!(streams_untouched());
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        assert_eq!(
            table.ns_entry_counts.lock().get(&CT_ROOT_NS).copied(),
            Some(root_flows - 1)
        );

        // Once that flow is a stream too, nothing is replaceable: rejected,
        // for a tenant and for root alike.
        let reply = table.update_on_packet(70, IPPROTO_UDP, remote, local, 53, 30_000, &udp, 3_200);
        assert_eq!(reply.decision, CtDecision::Established);
        table.update_on_packet(70, IPPROTO_UDP, local, remote, 30_000, 53, &udp, 5_100);
        let second =
            table.update_on_packet(71, IPPROTO_UDP, local, remote, 30_001, 53, &udp, 5_200);
        assert!(second.resource_exhausted);
        let root = table.update_on_packet(
            CT_ROOT_NS,
            IPPROTO_UDP,
            local,
            remote,
            30_002,
            53,
            &udp,
            5_200,
        );
        assert!(root.resource_exhausted);
        assert!(table.lookup(&flow(70, 30_000)).is_some());
        assert!(streams_untouched());
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        for ns in [61u64, 62, 70, CT_ROOT_NS] {
            table.drain_ns(ns);
        }
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn r192_res_4_victims_prefer_flows_a_remote_peer_created() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        let flow = |ns, port| FlowKey::from_packet(ns, IPPROTO_UDP, local, remote, port, 53).0;
        let egress = |ns, port, t| {
            table.update_on_egress_transaction(
                ns,
                IPPROTO_UDP,
                local,
                remote,
                port,
                53,
                &udp,
                t,
                || Ok::<(), QueueFault>(()),
            )
        };
        // Tenant 5: two outbound queries (the oldest flows), then flows a
        // remote peer opened, up to the share.
        assert!(matches!(egress(5, 10_000, 1), CtEgressResult::Committed(_)));
        assert!(matches!(egress(5, 10_001, 1), CtEgressResult::Committed(_)));
        for index in 2..CT_MAX_ENTRIES_PER_NS {
            udp_flow(&table, 5, 10_000 + index as u16, 5, false);
        }
        assert!(table
            .lookup(&flow(5, 10_000))
            .is_some_and(|entry| entry.local_origin));
        assert!(table
            .lookup(&flow(5, 10_002))
            .is_some_and(|entry| !entry.local_origin));

        // A new remote flow replaces the oldest remote-created flow, although
        // the outbound queries are older.
        let first = table.update_on_packet(5, IPPROTO_UDP, local, remote, 11_000, 53, &udp, 6);
        assert!(!first.resource_exhausted);
        assert!(table.lookup(&flow(5, 10_002)).is_none());
        assert!(table.lookup(&flow(5, 10_000)).is_some());
        assert!(table.lookup(&flow(5, 10_001)).is_some());

        // Tenant 6 holds only its own outbound flows: they are replaced, oldest
        // first, rather than the namespace refusing every new flow.
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            let t = if index == 0 { 1 } else { 2 };
            assert!(matches!(
                egress(6, 12_000 + index as u16, t),
                CtEgressResult::Committed(_)
            ));
        }
        let second = table.update_on_packet(6, IPPROTO_UDP, local, remote, 13_000, 53, &udp, 3);
        assert!(!second.resource_exhausted);
        assert!(table.lookup(&flow(6, 12_000)).is_none());
        assert_eq!(table.drain_ns(5), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.drain_ns(6), CT_MAX_ENTRIES_PER_NS);
    }

    #[test]
    fn r192_res_4_a_validated_or_local_reset_retires_an_established_flow() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let syn = L4Meta::new(0x02, 0);
        let tcp_flow = |port| FlowKey::from_packet(5, IPPROTO_TCP, local, remote, port, 443).0;
        let establish = |port| {
            let result = table.update_on_packet(5, IPPROTO_TCP, local, remote, port, 443, &syn, 1);
            assert!(!result.resource_exhausted);
            let entries = table.entries.read();
            entries.get(&tcp_flow(port)).expect("flow").lock().state =
                CtProtoState::Tcp(TcpCtState::Established);
        };
        let state = |port| table.lookup(&tcp_flow(port)).map(|entry| entry.state);
        let established = Some(CtProtoState::Tcp(TcpCtState::Established));
        let closed = Some(CtProtoState::Tcp(TcpCtState::Close));

        // An RST conntrack sees on ingress is not validated: ignored (R145-4).
        establish(40_000);
        let rst = L4Meta::new(0x04, 0);
        table.update_on_packet(5, IPPROTO_TCP, remote, local, 443, 40_000, &rst, 2);
        assert_eq!(state(40_000), established);
        // The socket layer accepted it (RFC 5961): the flow closes.
        assert!(table.commit_tcp_ingress_reset(5, remote, local, 443, 40_000));
        assert_eq!(state(40_000), closed);
        assert!(table
            .lookup(&tcp_flow(40_000))
            .is_some_and(|entry| entry.replaceable()));
        // Unknown flows and other namespaces are untouched.
        assert!(!table.commit_tcp_ingress_reset(5, remote, local, 443, 40_009));
        establish(40_001);
        assert!(!table.commit_tcp_ingress_reset(6, remote, local, 443, 40_001));
        assert_eq!(state(40_001), established);

        // An RST this host sends closes the flow when it is queued.
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_TCP,
            local,
            remote,
            40_001,
            443,
            &rst,
            3,
            || Ok::<(), QueueFault>(()),
        );
        assert!(matches!(outcome, CtEgressResult::Committed(_)));
        assert_eq!(state(40_001), closed);
        // A failed queue leaves the established state in place.
        establish(40_002);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_TCP,
            local,
            remote,
            40_002,
            443,
            &rst,
            4,
            || Err(QueueFault::Full),
        );
        assert!(matches!(
            outcome,
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));
        assert_eq!(state(40_002), established);
        // A validated RST that lands while our own segment is queued wins over
        // that segment's commit.
        let ack = L4Meta::new(0x10, 0);
        let reset_in_flight = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_TCP,
            local,
            remote,
            40_002,
            443,
            &ack,
            5,
            || {
                reset_in_flight.set(table.commit_tcp_ingress_reset(5, remote, local, 443, 40_002));
                Ok::<(), QueueFault>(())
            },
        );
        assert!(matches!(outcome, CtEgressResult::Committed(_)));
        assert!(reset_in_flight.get());
        assert_eq!(state(40_002), closed);
        // When the queued segment then fails, its rollback keeps the reset.
        establish(40_003);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_TCP,
            local,
            remote,
            40_003,
            443,
            &ack,
            6,
            || {
                assert!(table.commit_tcp_ingress_reset(5, remote, local, 443, 40_003));
                Err(QueueFault::Full)
            },
        );
        assert!(matches!(
            outcome,
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));
        assert_eq!(state(40_003), closed);
        assert_eq!(table.drain_ns(5), 4);
    }

    #[test]
    fn r192_4_same_namespace_replacement_queue_failure_restores_the_victim() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            let seen = if index == 0 { 2 } else { 3 };
            let port = 10_000 + index as u16;
            let result =
                table.update_on_packet(5, IPPROTO_UDP, local, remote, port, 53, &udp, seen);
            assert!(!result.resource_exhausted);
        }
        let victim = FlowKey::from_packet(5, IPPROTO_UDP, local, remote, 10_000, 53).0;
        let requested = FlowKey::from_packet(5, IPPROTO_UDP, local, remote, 12_000, 53).0;
        let before = table.lookup(&victim).expect("victim present");

        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_UDP,
            local,
            remote,
            12_000,
            53,
            &udp,
            4,
            || Err(QueueFault::Full),
        );
        assert!(matches!(
            outcome,
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));
        let after = table
            .lookup(&victim)
            .expect("victim restored after QueueFull");
        assert_eq!(after.state, before.state);
        assert_eq!(after.last_seen_ms, before.last_seen_ms);
        assert_eq!(after.packets_orig, before.packets_orig);
        assert!(table.lookup(&requested).is_none());
        assert_eq!(table.len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert_eq!(table.drain_ns(5), CT_MAX_ENTRIES_PER_NS);
    }

    #[test]
    fn rf192_1_replacement_keeps_rollback_ownership_during_queue() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();
        let udp = L4Meta::new(0, 0);
        for index in 0..CT_MAX_ENTRIES_PER_NS {
            let seen = if index == 0 { 2 } else { 3 };
            assert!(
                !table
                    .update_on_packet(
                        5,
                        IPPROTO_UDP,
                        local,
                        remote,
                        10_000 + index as u16,
                        53,
                        &udp,
                        seen
                    )
                    .resource_exhausted
            );
        }
        let victim = FlowKey::from_packet(5, IPPROTO_UDP, local, remote, 10_000, 53).0;
        let requested = FlowKey::from_packet(5, IPPROTO_UDP, local, remote, 12_000, 53).0;
        let before = table.lookup(&victim).expect("victim present");
        let competing_creation_rejected = Cell::new(false);
        let outcome = table.update_on_egress_transaction(
            5,
            IPPROTO_UDP,
            local,
            remote,
            12_000,
            53,
            &udp,
            4,
            || {
                // Model a packet on another CPU recreating the detached victim
                // while the new entry's send has not yet committed.
                competing_creation_rejected.set(
                    table
                        .update_on_packet(5, IPPROTO_UDP, local, remote, 10_000, 53, &udp, 5)
                        .resource_exhausted,
                );
                Err(QueueFault::Full)
            },
        );
        assert!(
            matches!(outcome, CtEgressResult::QueueFailed(QueueFault::Full)),
            "{outcome:?}"
        );
        assert!(competing_creation_rejected.get());
        let after = table.lookup(&victim).expect("original victim restored");
        assert_eq!(after.last_seen_ms, before.last_seen_ms);
        assert_eq!(after.packets_orig, before.packets_orig);
        assert!(table.lookup(&requested).is_none());
        assert_eq!(table.entries.read().len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert!(!table.capacity_preparing.load(Ordering::Acquire));
        // The permit is released after settlement, so the next creator can
        // replace an entry normally instead of permanently losing admission.
        assert!(
            !table
                .update_on_packet(5, IPPROTO_UDP, local, remote, 13_000, 53, &udp, 6)
                .resource_exhausted
        );
        let committed = table.update_on_egress_transaction(
            5,
            IPPROTO_UDP,
            local,
            remote,
            14_000,
            53,
            &udp,
            7,
            || {
                // Keeping the creation permit must not serialize an existing
                // flow's independent egress, even when it re-enters this table.
                assert!(matches!(
                    table.update_on_egress_transaction(
                        5,
                        IPPROTO_UDP,
                        local,
                        remote,
                        13_000,
                        53,
                        &udp,
                        8,
                        || Ok::<(), QueueFault>(()),
                    ),
                    CtEgressResult::Committed(_)
                ));
                assert!(
                    table
                        .update_on_packet(5, IPPROTO_UDP, local, remote, 15_000, 53, &udp, 8,)
                        .resource_exhausted
                );
                Ok::<(), QueueFault>(())
            },
        );
        assert!(matches!(committed, CtEgressResult::Committed(_)));
        assert_eq!(table.entries.read().len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.len(), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(
            table.ns_entry_counts.lock().get(&5).copied(),
            Some(CT_MAX_ENTRIES_PER_NS)
        );
        assert!(!table.capacity_preparing.load(Ordering::Acquire));
        assert_eq!(table.drain_ns(5), CT_MAX_ENTRIES_PER_NS);
    }

    #[test]
    fn r188_replacement_publication_failure_restores_victim_and_namespace_charge() {
        let table = ConntrackTable::new();
        let (local, remote) = endpoints();

        // Fill the bounded global table: two tenants at their shares and root
        // with the rest, keeping root's first entry old enough to be the
        // deterministic victim (R192-RES-4: a tenant below its limits borrows
        // root's surplus).  The requester namespace is intentionally absent,
        // so publication needs both a victim replacement and a new
        // namespace-count row.
        let namespaces = [51u64, 52, CT_ROOT_NS];
        let root_flows = CT_MAX_ENTRIES - 2 * CT_MAX_ENTRIES_PER_NS;
        let mut port = 30_000u16;
        for ns_id in namespaces {
            let flows = if ns_id == CT_ROOT_NS {
                root_flows
            } else {
                CT_MAX_ENTRIES_PER_NS
            };
            for entry_index in 0..flows {
                let timestamp = if ns_id == CT_ROOT_NS && entry_index == 0 {
                    1
                } else {
                    2
                };
                let result = table.update_on_packet(
                    ns_id,
                    IPPROTO_UDP,
                    local,
                    remote,
                    port,
                    53,
                    &L4Meta::new(0, 0),
                    timestamp,
                );
                assert!(!result.resource_exhausted);
                port = port.wrapping_add(1);
            }
        }
        assert_eq!(table.len(), CT_MAX_ENTRIES);

        let victim_port = 30_000 + 2 * CT_MAX_ENTRIES_PER_NS as u16;
        let victim_key =
            FlowKey::from_packet(CT_ROOT_NS, IPPROTO_UDP, local, remote, victim_port, 53).0;
        assert!(table.lookup(&victim_key).is_some());
        table.fail_next_ns_publication_for_test();

        let outcome = table.update_on_egress_transaction(
            99,
            IPPROTO_UDP,
            local,
            remote,
            40_000,
            53,
            &L4Meta::new(0, 0),
            3,
            || Ok::<(), QueueFault>(()),
        );
        assert!(matches!(
            outcome,
            CtEgressResult::Rejected(CtUpdateResult {
                resource_exhausted: true,
                ..
            })
        ));

        let requester_key = FlowKey::from_packet(99, IPPROTO_UDP, local, remote, 40_000, 53).0;
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        assert!(table.lookup(&requester_key).is_none());
        assert!(
            table.lookup(&victim_key).is_some(),
            "failed namespace publication must restore the detached LRU victim"
        );
        assert_eq!(
            table.ns_entry_counts.lock().get(&CT_ROOT_NS).copied(),
            Some(root_flows),
            "victim namespace charge must be restored exactly"
        );
        assert!(
            table.ns_entry_counts.lock().get(&99).is_none(),
            "requester namespace row must not survive a failed publication"
        );

        // The same replacement failing at the device queue restores the victim
        // and both namespace rows as well.
        let outcome = table.update_on_egress_transaction(
            99,
            IPPROTO_UDP,
            local,
            remote,
            40_000,
            53,
            &L4Meta::new(0, 0),
            4,
            || Err(QueueFault::Full),
        );
        assert!(matches!(
            outcome,
            CtEgressResult::QueueFailed(QueueFault::Full)
        ));
        assert_eq!(table.len(), CT_MAX_ENTRIES);
        assert!(table.lookup(&requester_key).is_none());
        assert!(table.lookup(&victim_key).is_some());
        assert_eq!(
            table.ns_entry_counts.lock().get(&CT_ROOT_NS).copied(),
            Some(root_flows)
        );
        assert!(table.ns_entry_counts.lock().get(&99).is_none());

        assert_eq!(table.drain_ns(51), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.drain_ns(52), CT_MAX_ENTRIES_PER_NS);
        assert_eq!(table.drain_ns(CT_ROOT_NS), root_flows);
    }
}
