//! ARP (Address Resolution Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 826 compliant ARP implementation with security-first design.
//!
//! # Packet Format (RFC 826)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Hardware Type         |         Protocol Type         |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |  HLen |  PLen |            Operation (1=Req, 2=Reply)         |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Sender Hardware Address (6 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Sender Protocol Address (4 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Target Hardware Address (6 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Target Protocol Address (4 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - Rate limiting for both RX processing and TX replies (anti-flooding)
//! - Cache conflict detection (anti-poisoning)
//! - Static entry protection (never overwritten by dynamic)
//! - Source validation (reject broadcast/multicast/zero MACs)
//! - Reflection attack prevention
//! - Bounded cache with LRU eviction
//!
//! # References
//!
//! - RFC 826: Ethernet Address Resolution Protocol
//! - RFC 5227: IPv4 Address Conflict Detection

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;

use crate::admitted::{AdmittedVec, WirePacket};
use crate::ethernet::{build_ethernet_frame, EthAddr, ETHERTYPE_ARP};
use crate::icmp::TokenBucket;
use crate::ipv4::Ipv4Addr;
use crate::stack::PreparedReply;
use mm::{HeapClass, NsByteBudget};

// ============================================================================
// ARP Constants (RFC 826)
// ============================================================================

/// Hardware type: Ethernet
pub const HTYPE_ETHERNET: u16 = 1;

/// Protocol type: IPv4
pub const PTYPE_IPV4: u16 = 0x0800;

/// Hardware address length: Ethernet MAC (6 bytes)
pub const HLEN_ETHERNET: u8 = 6;

/// Protocol address length: IPv4 (4 bytes)
pub const PLEN_IPV4: u8 = 4;

/// ARP operation: Request
pub const OPCODE_REQUEST: u16 = 1;

/// ARP operation: Reply
pub const OPCODE_REPLY: u16 = 2;

/// ARP packet size for Ethernet/IPv4
pub const ARP_PACKET_LEN: usize = 28;

/// Default ARP cache TTL (5 minutes)
pub const DEFAULT_CACHE_TTL_MS: u64 = 5 * 60 * 1000;

/// Default maximum ARP cache entries
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 256;

/// Default ARP RX rate limit (packets per second)
pub const DEFAULT_RX_RATE_PPS: u64 = 50;

/// Default ARP RX burst capacity
pub const DEFAULT_RX_BURST: u64 = 100;

/// Default ARP TX rate limit (packets per second)
pub const DEFAULT_TX_RATE_PPS: u64 = 20;

/// Default ARP TX burst capacity
pub const DEFAULT_TX_BURST: u64 = 40;

/// D3 ARP-PROBE: probe-throttle ring size — how many distinct unresolved
/// on-link IPs one cache tracks for per-IP probe suppression. Heap-free by
/// design (inline array); working sets beyond this let a hot IP re-claim
/// early through oldest-replacement, and the probe token buckets remain the
/// hard bound.
pub const ARP_PROBE_RING_SIZE: usize = 8;

/// D3 ARP-PROBE: minimum spacing between admitted probes for the SAME IP
/// (per cache). RFC 1122 §2.3.2.1-flavored 1 s retransmission spacing.
pub const ARP_PROBE_INTERVAL_MS: u64 = 1_000;

/// D3 ARP-PROBE: per-cache probe admission rate (packets per second).
/// Deliberately BELOW the reply TX rate — probes are speculative traffic.
pub const DEFAULT_PROBE_RATE_PPS: u64 = 8;

/// D3 ARP-PROBE: per-cache probe admission burst capacity.
pub const DEFAULT_PROBE_BURST: u64 = 8;

/// D3 PENDING-FRAME v2: bounded per-cache queue of data frames PARKED on an
/// on-link ARP miss — gateway-fallback DELIVERY is retired; the frame waits
/// for the neighbor to be learned. Global-per-cache bound: one unresolved
/// neighbor may occupy every slot (deliberate — the queue serves ONE
/// namespace, and eviction keeps the newest application intent).
pub const PENDING_FRAME_SLOTS: usize = 8;

/// D3 PENDING-FRAME v2: parked-frame lifetime — three probe intervals, so a
/// frame outlives ~3 admitted probes for its target before dropping on
/// expiry. Probe-bucket denial does NOT extend the TTL: congestion must
/// never retain frames indefinitely. Expiry is evaluated BEFORE readiness
/// (`now_ms >= expires_at` wins over a learn landing at the same instant).
pub const PENDING_FRAME_TTL_MS: u64 = 3 * ARP_PROBE_INTERVAL_MS;

// ============================================================================
// ARP Operation Code
// ============================================================================

/// ARP operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    /// ARP Request (who-has)
    Request,
    /// ARP Reply (is-at)
    Reply,
}

impl ArpOp {
    /// Convert from raw opcode
    pub fn from_raw(op: u16) -> Option<Self> {
        match op {
            OPCODE_REQUEST => Some(ArpOp::Request),
            OPCODE_REPLY => Some(ArpOp::Reply),
            _ => None,
        }
    }

    /// Convert to raw opcode
    pub fn to_raw(self) -> u16 {
        match self {
            ArpOp::Request => OPCODE_REQUEST,
            ArpOp::Reply => OPCODE_REPLY,
        }
    }
}

// ============================================================================
// ARP Packet
// ============================================================================

/// Parsed ARP packet for Ethernet/IPv4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    /// Sender hardware (MAC) address
    pub sender_hw: EthAddr,
    /// Sender protocol (IP) address
    pub sender_ip: Ipv4Addr,
    /// Target hardware (MAC) address
    pub target_hw: EthAddr,
    /// Target protocol (IP) address
    pub target_ip: Ipv4Addr,
    /// ARP operation
    pub op: ArpOp,
}

// ============================================================================
// ARP Errors
// ============================================================================

/// Errors that can occur during ARP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpError {
    /// Packet is too short
    Truncated,
    /// Invalid hardware type (not Ethernet)
    InvalidHardwareType,
    /// Invalid protocol type (not IPv4)
    InvalidProtocolType,
    /// Invalid address lengths
    InvalidAddressLength,
    /// Invalid operation code
    InvalidOpcode,
    /// Invalid sender address (broadcast/multicast/zero MAC)
    InvalidSender,
    /// Rate limited (flood protection)
    RateLimited,
    /// Conflicting cache entry (anti-spoofing)
    CacheConflict,
    /// Aggregate heap admission failed before cache publication.
    NoMemory,
}

// ============================================================================
// ARP Cache Entry
// ============================================================================

/// Type of ARP cache entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryKind {
    /// Statically configured (never expires, never overwritten)
    Static,
    /// Dynamically learned from network
    Dynamic,
}

/// An entry in the ARP cache
#[derive(Debug, Clone, Copy)]
pub struct ArpEntry {
    /// IP address
    pub ip: Ipv4Addr,
    /// MAC address
    pub mac: EthAddr,
    /// Entry type
    pub kind: ArpEntryKind,
    /// Last update timestamp (milliseconds)
    pub updated_at: u64,
}

// ============================================================================
// ARP Cache
// ============================================================================

/// D3 ARP-PROBE: one probe-throttle ring slot — the last time this cache
/// ADMITTED a probe claim for `ip`. Claims are retained even when a token
/// bucket later denies or the motivating data TX fails: conservative
/// fail-closed throttling (Codex round-26 Q1 — the ring meters admission
/// attempts, never confirmed transmissions).
#[derive(Debug, Clone, Copy)]
struct ProbeSlot {
    ip: Ipv4Addr,
    last_probe_ms: u64,
}

/// D3 ARP-PROBE: outcome of [`ArpCache::admit_probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAdmission {
    /// Ring claim and per-cache probe bucket both passed — the caller may
    /// emit ONE probe intent for this IP.
    Admitted,
    /// A claim for this IP is younger than [`ARP_PROBE_INTERVAL_MS`], or
    /// the clock regressed below the recorded claim (conservative
    /// suppress — a rewound clock must throttle harder, never spam).
    DuplicateSuppressed,
    /// The ring claim succeeded but the per-cache probe bucket denied. The
    /// claim is RETAINED — this IP re-attempts only after the interval.
    RateLimited,
}

// ============================================================================
// D3 PENDING-FRAME v2: park-on-miss queue
// ============================================================================

/// D3 PENDING-FRAME v2: cumulative lifecycle counters for one cache's
/// pending-frame queue. Saturating; every successfully parked frame reaches
/// EXACTLY ONE terminal counter, so in quiescence:
///
/// `parked_total == occupancy + retransmitted + expired + evicted + flushed
///  + retx_failures`
///
/// (`retransmitted` means the device queue ACCEPTED the popped frame, never
/// mere extraction; frames in flight between pop and queue-accept make the
/// identity transiently under-count — quiescent-only invariant.)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingFrameCounters {
    /// Frames accepted into the queue (cumulative).
    pub parked_total: u64,
    /// Popped frames the device queue accepted after a learn.
    pub retransmitted: u64,
    /// Frames dropped at TTL expiry (no learn arrived in time).
    pub expired: u64,
    /// Frames displaced by a newer park on a full queue (oldest-first).
    pub evicted: u64,
    /// Frames discarded by a reconfiguration flush ([`ArpCache::clear_all`]).
    pub flushed: u64,
    /// Popped frames whose retransmission failed (policy/ownership/queue) —
    /// never re-parked, dropped fail-closed.
    pub retx_failures: u64,
}

/// D3 PENDING-FRAME v2: one parked data frame — a fully built, policy-passed
/// wire frame whose destination MAC is the ZERO placeholder until the
/// neighbor is learned ([`PreparedReply::patch_dst_mac`] runs under the cache
/// lock at pop; no unpatched frame can leave the queue toward a device).
/// Identity fields (`our_mac`/`our_ip`) are COPIES from the ORIGINAL config
/// snapshot for interval re-probes; `park_seq` (per-cache monotonic) is the
/// FIFO release and eviction key — timestamps alone cannot order same-ms
/// parks and regress with the clock.
pub(crate) struct ParkedFrame {
    pub(crate) reply: PreparedReply,
    pub(crate) target_ip: Ipv4Addr,
    pub(crate) our_mac: EthAddr,
    pub(crate) our_ip: Ipv4Addr,
    pub(crate) expires_at: u64,
    pub(crate) park_seq: u64,
}

/// D3 PENDING-FRAME v2: bounded move-out batch. Destruction discipline: the
/// cache mutex is a leaf lock and frame drops release heap admissions — every
/// batch MUST be dropped (or consumed) strictly AFTER the cache guard.
/// (`pub` because `clear_all` is a cross-crate seam; the contents remain
/// crate-private — external callers can only bind and drop the batch.)
#[must_use = "drop or transmit the batch only after releasing the ARP-cache mutex"]
pub struct PendingFrameBatch {
    frames: [Option<ParkedFrame>; PENDING_FRAME_SLOTS],
    len: usize,
}

impl PendingFrameBatch {
    fn new() -> Self {
        Self {
            frames: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    fn push(&mut self, frame: ParkedFrame) {
        debug_assert!(self.len < PENDING_FRAME_SLOTS);
        if self.len < PENDING_FRAME_SLOTS {
            self.frames[self.len] = Some(frame);
            self.len += 1;
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn into_frames(self) -> impl Iterator<Item = ParkedFrame> {
        self.frames.into_iter().flatten()
    }
}

/// D3 PENDING-FRAME v2: one interval-admitted re-probe intent popped by the
/// sweep — identity from the parked frame's ORIGINAL snapshot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingProbe {
    pub(crate) target_ip: Ipv4Addr,
    pub(crate) our_mac: EthAddr,
    pub(crate) our_ip: Ipv4Addr,
}

/// D3 PENDING-FRAME v2: bounded batch of admitted re-probe intents.
pub(crate) struct PendingProbeBatch {
    probes: [Option<PendingProbe>; PENDING_FRAME_SLOTS],
    len: usize,
}

impl PendingProbeBatch {
    fn new() -> Self {
        Self {
            probes: [None; PENDING_FRAME_SLOTS],
            len: 0,
        }
    }

    fn push(&mut self, probe: PendingProbe) {
        debug_assert!(self.len < PENDING_FRAME_SLOTS);
        if self.len < PENDING_FRAME_SLOTS {
            self.probes[self.len] = Some(probe);
            self.len += 1;
        }
    }

    pub(crate) fn into_probes(self) -> impl Iterator<Item = PendingProbe> {
        self.probes.into_iter().flatten()
    }
}

/// D3 PENDING-FRAME v2: the pending keys observed under ONE cache-lock hold,
/// taken BEFORE the sweep's ownership check (which must run without the cache
/// lock). The drain re-probes only keys in this snapshot: a frame parked
/// between the two lock holds ran its OWN post-gate initial admission and
/// needs no sweep probe yet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingKeySnapshot {
    keys: [Option<Ipv4Addr>; PENDING_FRAME_SLOTS],
    len: usize,
    occupied: bool,
}

impl PendingKeySnapshot {
    /// Any frame present (live or expired) — the sweep must run.
    pub(crate) fn occupied(&self) -> bool {
        self.occupied
    }

    /// At least one UNEXPIRED key — worth an ownership check for re-probes.
    pub(crate) fn has_live_keys(&self) -> bool {
        self.len != 0
    }

    fn contains(&self, target_ip: Ipv4Addr) -> bool {
        self.keys[..self.len].iter().any(|k| *k == Some(target_ip))
    }
}

/// D3 PENDING-FRAME v2: everything one sweep moved out of the queue. All
/// three batches leave the cache lock with the caller; `ready` frames are
/// already dst-MAC-patched and transmit through the ownership-gated prepared
/// path, `retired` frames (expired) just drop, `probes` emit afresh.
pub(crate) struct PendingDrain {
    pub(crate) ready: PendingFrameBatch,
    pub(crate) retired: PendingFrameBatch,
    pub(crate) probes: PendingProbeBatch,
}

/// ARP cache with anti-spoofing protection
///
/// # Security Features
///
/// - Bounded size with LRU eviction
/// - TTL-based expiration for dynamic entries
/// - Conflict detection (rejects updates that change existing MAC)
/// - Static entry protection (never overwritten)
pub struct ArpCache {
    /// Cache entries (LRU order: oldest first)
    entries: AdmittedVec<ArpEntry>,
    /// TTL for dynamic entries in milliseconds
    ttl_ms: u64,
    /// Maximum number of entries
    max_entries: usize,
    /// R102-12 FIX: Per-interface RX rate limiter.
    /// Prevents a single malicious host on one interface from exhausting the
    /// global token bucket and starving ARP processing on all other interfaces.
    pub rx_rate_limiter: TokenBucket,
    /// R102-12 FIX: Per-interface TX rate limiter.
    pub tx_rate_limiter: TokenBucket,
    /// D3 PENDING-FRAME v2: data frames parked on an on-link miss, awaiting
    /// the neighbor learn (retired the metered gateway-fallback delivery).
    /// Guarded by this cache's own mutex like every other field; frames are
    /// MOVED OUT under the lock and dropped/transmitted strictly after it.
    parked: [Option<ParkedFrame>; PENDING_FRAME_SLOTS],
    /// D3 PENDING-FRAME v2: monotonic park sequence — FIFO release/eviction
    /// key (same-ms parks and clock regressions cannot reorder it).
    next_park_seq: u64,
    /// D3 PENDING-FRAME v2: lifecycle counters (see [`PendingFrameCounters`]).
    pending_counters: PendingFrameCounters,
    /// D3 ARP-PROBE: per-IP probe suppression ring (heap-free, inline).
    /// Claimed under this cache's own mutex by the TX resolver's on-link
    /// miss arm — see [`Self::admit_probe`].
    probe_ring: [Option<ProbeSlot>; ARP_PROBE_RING_SIZE],
    /// D3 ARP-PROBE: per-cache probe rate limiter — per-namespace isolation
    /// (Codex round-26 D3: a global-only bucket would let one namespace's
    /// unresolved fan-out starve every other namespace's probes). The
    /// global [`ARP_PROBE_RATE_LIMITER`] backstops the AGGREGATE behind it,
    /// mirroring the established RX/TX dual-limiter pattern.
    probe_rate_limiter: TokenBucket,
}

impl ArpCache {
    /// Create a new ARP cache with specified TTL and capacity.
    ///
    /// Entries are heap-admitted to `HeapClass::SocketObject` (the global
    /// cache's class). Per-namespace caches use [`Self::new_in_class`] with
    /// `HeapClass::NetnsConfig` so per-ns dataplane state is accounted
    /// against the per-ns config ceiling, not the socket budget.
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self::new_in_class(ttl_ms, max_entries, HeapClass::SocketObject)
    }

    /// D3-NETNS-DATAPLANE: Create a new ARP cache whose entry storage is
    /// heap-admitted to `class`.
    pub fn new_in_class(ttl_ms: u64, max_entries: usize, class: HeapClass) -> Self {
        ArpCache {
            // RF180-41 REVIEW FIX: the declared maximum is the truthful
            // logical limit. Backing grows only through fallible aggregate
            // admission; there is no hidden 64-entry infallible prefix.
            entries: AdmittedVec::new(class),
            ttl_ms,
            max_entries,
            // R102-12 FIX: Per-interface rate limiters with same defaults as global.
            rx_rate_limiter: TokenBucket::new(DEFAULT_RX_RATE_PPS, DEFAULT_RX_BURST),
            tx_rate_limiter: TokenBucket::new(DEFAULT_TX_RATE_PPS, DEFAULT_TX_BURST),
            parked: core::array::from_fn(|_| None),
            next_park_seq: 0,
            pending_counters: PendingFrameCounters::default(),
            probe_ring: [None; ARP_PROBE_RING_SIZE],
            probe_rate_limiter: TokenBucket::new(DEFAULT_PROBE_RATE_PPS, DEFAULT_PROBE_BURST),
        }
    }

    /// Create a cache with default settings (5 min TTL, 256 entries).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CACHE_TTL_MS, DEFAULT_CACHE_MAX_ENTRIES)
    }

    /// D3-NETNS-DATAPLANE: Default-sized cache heap-admitted to `class`
    /// (per-namespace caches charge `HeapClass::NetnsConfig`).
    pub fn with_defaults_in_class(class: HeapClass) -> Self {
        Self::new_in_class(DEFAULT_CACHE_TTL_MS, DEFAULT_CACHE_MAX_ENTRIES, class)
    }

    /// D3 NETNS-SUBBUDGET-1: Default-sized cache whose entry storage takes
    /// a dual lease on every growth — the shared `class` ceiling AND the
    /// owning namespace's byte budget. Either rejection surfaces to callers
    /// as `ArpError::NoMemory`; the budget limit is a ceiling, not an
    /// entitlement (class exhaustion can reject below the owner's limit).
    ///
    /// CALLER CONTRACT: `budget` MUST be the config budget of the namespace
    /// that OWNS this cache. A foreign budget keeps both ledgers internally
    /// balanced but attributes consumption to the wrong namespace
    /// (accounting confusion / cross-ns DoS).
    pub fn with_defaults_budgeted(class: HeapClass, budget: Arc<NsByteBudget>) -> Self {
        ArpCache {
            entries: AdmittedVec::with_ns_budget(class, budget),
            ttl_ms: DEFAULT_CACHE_TTL_MS,
            max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            rx_rate_limiter: TokenBucket::new(DEFAULT_RX_RATE_PPS, DEFAULT_RX_BURST),
            tx_rate_limiter: TokenBucket::new(DEFAULT_TX_RATE_PPS, DEFAULT_TX_BURST),
            parked: core::array::from_fn(|_| None),
            next_park_seq: 0,
            pending_counters: PendingFrameCounters::default(),
            probe_ring: [None; ARP_PROBE_RING_SIZE],
            probe_rate_limiter: TokenBucket::new(DEFAULT_PROBE_RATE_PPS, DEFAULT_PROBE_BURST),
        }
    }

    /// Look up a MAC address for the given IP.
    ///
    /// Returns `None` if not found or expired.
    pub fn lookup(&self, ip: Ipv4Addr, now_ms: u64) -> Option<EthAddr> {
        self.entries
            .iter()
            .find(|e| e.ip == ip && !self.is_expired(e, now_ms))
            .map(|e| e.mac)
    }

    /// Insert or update an entry in the cache.
    ///
    /// # Security: Anti-Spoofing
    ///
    /// - Never overwrites static entries
    /// - Rejects dynamic updates that change an existing MAC (conflict)
    /// - Purges expired entries before checking conflicts (R45 FIX)
    /// - This prevents ARP cache poisoning attacks
    ///
    /// # Returns
    ///
    /// `Ok(())` if inserted/updated, `Err(ArpError::CacheConflict)` if rejected.
    pub fn insert(
        &mut self,
        ip: Ipv4Addr,
        mac: EthAddr,
        kind: ArpEntryKind,
        now_ms: u64,
    ) -> Result<(), ArpError> {
        // R45 FIX: Purge expired entries first so they cannot block fresh mappings
        self.purge_expired(now_ms);

        // Check for existing entry
        if let Some(pos) = self.entries.iter().position(|e| e.ip == ip) {
            let existing = &self.entries[pos];

            // Never overwrite static entries
            if existing.kind == ArpEntryKind::Static {
                if kind == ArpEntryKind::Static && existing.mac == mac {
                    // Same static entry, just update timestamp
                    let entry = &mut self.entries[pos];
                    entry.updated_at = now_ms;
                    return Ok(());
                }
                return Err(ArpError::CacheConflict);
            }

            // For dynamic entries, reject if MAC changes (anti-poisoning)
            // Only allow refresh with same MAC
            if existing.mac != mac {
                return Err(ArpError::CacheConflict);
            }

            // Remove and re-add at end (update LRU position). Existing backing
            // already has the required slot, so publication cannot allocate.
            let refreshed = self
                .entries
                .remove(pos)
                .expect("RF180-41 ARP refresh position vanished");
            debug_assert_eq!(refreshed.ip, ip);
            return self
                .entries
                .push_reserved(ArpEntry {
                    ip,
                    mac,
                    kind,
                    updated_at: now_ms,
                })
                .map_err(|_| ArpError::NoMemory);
        }

        // R62-5 FIX: Evict oldest *dynamic* entry if at capacity; never evict static.
        // Static entries represent trusted bindings (e.g., gateway) and must be protected
        // from cache-filling attacks that could enable ARP poisoning.
        if self.entries.len() >= self.max_entries {
            // Find first dynamic entry to evict (oldest dynamic)
            if let Some(pos) = self
                .entries
                .iter()
                .position(|e| e.kind == ArpEntryKind::Dynamic)
            {
                self.entries.remove(pos);
            } else {
                // Cache is full of static entries; refuse new insertion
                // This prevents attackers from forcing eviction of static entries
                return Err(ArpError::CacheConflict);
            }
        }

        if self.entries.len() < self.max_entries {
            self.entries
                .ensure_capacity_for(1)
                .map_err(|_| ArpError::NoMemory)?;
        }

        // Add new entry at end (most recently used)
        self.entries
            .push_reserved(ArpEntry {
                ip,
                mac,
                kind,
                updated_at: now_ms,
            })
            .map_err(|_| ArpError::NoMemory)?;

        Ok(())
    }

    /// Add a static entry that never expires and cannot be overwritten.
    pub fn add_static(&mut self, ip: Ipv4Addr, mac: EthAddr, now_ms: u64) -> Result<(), ArpError> {
        self.insert(ip, mac, ArpEntryKind::Static, now_ms)
    }

    /// Remove expired dynamic entries.
    pub fn purge_expired(&mut self, now_ms: u64) {
        let ttl_ms = self.ttl_ms;
        self.entries.retain(|e| {
            // Static entries never expire
            if e.kind == ArpEntryKind::Static {
                return true;
            }
            // Dynamic entries expire after ttl_ms
            now_ms.saturating_sub(e.updated_at) <= ttl_ms
        });
    }

    /// D3-NETNS-DATAPLANE RX-COMPLETION test seam: remove ONE dynamic entry
    /// by IP. Static entries (the authoritative gateway seeds) are refused —
    /// this cannot be used to displace a config-derived mapping. Returns
    /// whether an entry was removed. Capacity charge is unaffected (this
    /// cache charges capacity, not membership). Production motivation: the
    /// SLIRP round-trip boot test must un-learn its probe target so a suite
    /// re-run in the same boot sees a virgin cache.
    pub fn remove_dynamic(&mut self, ip: Ipv4Addr) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.ip == ip && e.kind == ArpEntryKind::Dynamic));
        self.entries.len() != before
    }

    /// Check if an entry is expired.
    fn is_expired(&self, entry: &ArpEntry, now_ms: u64) -> bool {
        // Static entries never expire
        if entry.kind == ArpEntryKind::Static {
            return false;
        }
        now_ms.saturating_sub(entry.updated_at) > self.ttl_ms
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the maximum number of entries allowed in the cache.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// D3 PENDING-FRAME v2: snapshot of this cache's pending-frame lifecycle
    /// counters (conservation identity documented on
    /// [`PendingFrameCounters`]).
    pub fn pending_frame_counters(&self) -> PendingFrameCounters {
        self.pending_counters
    }

    /// D3 PENDING-FRAME v2: current pending-queue occupancy.
    pub fn pending_frame_count(&self) -> usize {
        self.parked.iter().filter(|slot| slot.is_some()).count()
    }

    /// D3 PENDING-FRAME v2: park one policy-passed data frame awaiting the
    /// neighbor learn for `target_ip`.
    ///
    /// CALLER CONTRACT (post-gate discipline, v1 round-27 F3 direction):
    /// the TX ownership gate for this namespace ALREADY passed — an
    /// ownership-denied send must never occupy queue slots or, downstream,
    /// draw probe claims. The frame's destination MAC is the ZERO
    /// placeholder; the ONLY exits from the queue are the dst-patched ready
    /// pop, expiry, eviction, and the reconfiguration flush — no unpatched
    /// frame can reach a device.
    ///
    /// A full queue displaces the OLDEST frame (minimum `park_seq` — the
    /// drop-head unresolved-neighbor discipline, keeping the newest
    /// application intent). The displaced frame is RETURNED: its drop
    /// releases heap admissions, so the caller drops it strictly AFTER this
    /// cache's mutex.
    pub(crate) fn park_pending(
        &mut self,
        reply: PreparedReply,
        target_ip: Ipv4Addr,
        our_mac: EthAddr,
        our_ip: Ipv4Addr,
        now_ms: u64,
    ) -> Option<ParkedFrame> {
        let slot = match self.parked.iter().position(Option::is_none) {
            Some(vacant) => vacant,
            None => {
                // Full: first minimum park_seq = the oldest park. The
                // sequence (not the timestamp) orders same-ms parks and is
                // immune to clock regression.
                let mut oldest = 0;
                let mut oldest_seq = u64::MAX;
                for (index, frame) in self.parked.iter().enumerate() {
                    if let Some(frame) = frame {
                        if frame.park_seq < oldest_seq {
                            oldest_seq = frame.park_seq;
                            oldest = index;
                        }
                    }
                }
                oldest
            }
        };
        let evicted = self.parked[slot].take();
        if evicted.is_some() {
            self.pending_counters.evicted = self.pending_counters.evicted.saturating_add(1);
        }
        let park_seq = self.next_park_seq;
        // Wrap is unreachable (2^64 parks); wrapping keeps release ordering
        // deterministic rather than sticking every later park at one seq.
        self.next_park_seq = self.next_park_seq.wrapping_add(1);
        self.pending_counters.parked_total = self.pending_counters.parked_total.saturating_add(1);
        self.parked[slot] = Some(ParkedFrame {
            reply,
            target_ip,
            our_mac,
            our_ip,
            expires_at: now_ms.saturating_add(PENDING_FRAME_TTL_MS),
            park_seq,
        });
        evicted
    }

    /// D3 PENDING-FRAME v2: the pending keys visible NOW — taken under one
    /// cache-lock hold BEFORE the sweep's ownership check (which must run
    /// with no cache lock held). See [`PendingKeySnapshot`].
    pub(crate) fn pending_key_snapshot(&self, now_ms: u64) -> PendingKeySnapshot {
        let mut snapshot = PendingKeySnapshot {
            keys: [None; PENDING_FRAME_SLOTS],
            len: 0,
            occupied: false,
        };
        for frame in self.parked.iter().flatten() {
            snapshot.occupied = true;
            if now_ms >= frame.expires_at || snapshot.contains(frame.target_ip) {
                continue;
            }
            if snapshot.len < PENDING_FRAME_SLOTS {
                snapshot.keys[snapshot.len] = Some(frame.target_ip);
                snapshot.len += 1;
            }
        }
        snapshot
    }

    /// D3 PENDING-FRAME v2: one sweep over the pending queue, under this
    /// cache's mutex. In order:
    ///
    /// 1. EXPIRY (always, even ownership-denied — reclamation must not
    ///    depend on authorization): `now_ms >= expires_at` frames move to
    ///    `retired`. Expiry deliberately precedes readiness — a learn
    ///    landing at the deadline instant loses ("drop on expiry" is the
    ///    hard boundary).
    /// 2. READY POP (authorized only), FIFO by `park_seq`: targets with a
    ///    live cache entry patch their dst MAC here under the lock and move
    ///    to `ready` for the ownership-gated prepared-reply path.
    /// 3. RE-PROBES (authorized only): for STILL-parked keys in `snapshot`,
    ///    one [`Self::admit_probe`] per distinct key — the ring interval
    ///    throttles to ~1/s per IP regardless of sweep cadence. Sweep
    ///    denials tick NO stats counters: `probe_duplicate_suppressed` /
    ///    `probe_rate_limited` meter TX-path admission attempts, and a
    ///    ~10 ms sweep would flood them with interval suppressions.
    ///
    /// An `ownership_authorized == false` sweep leaves live frames parked
    /// (they expire on the TTL; no revocation path exists today — see the
    /// production sweep site) and admits no probes — a denied namespace
    /// must not draw ring claims or bucket tokens.
    ///
    /// Every returned batch MUST outlive this cache's guard and be
    /// consumed/dropped after it (frame drops release heap admissions).
    pub(crate) fn drain_pending(
        &mut self,
        now_ms: u64,
        ownership_authorized: bool,
        snapshot: &PendingKeySnapshot,
    ) -> PendingDrain {
        let mut ready = PendingFrameBatch::new();
        let mut retired = PendingFrameBatch::new();
        let mut probes = PendingProbeBatch::new();

        for slot in 0..PENDING_FRAME_SLOTS {
            let expired = self.parked[slot]
                .as_ref()
                .is_some_and(|frame| now_ms >= frame.expires_at);
            if expired {
                if let Some(frame) = self.parked[slot].take() {
                    self.pending_counters.expired = self.pending_counters.expired.saturating_add(1);
                    retired.push(frame);
                }
            }
        }

        if !ownership_authorized {
            return PendingDrain {
                ready,
                retired,
                probes,
            };
        }

        let (order, len) = self.ordered_pending_indices();
        for slot in order[..len].iter().copied() {
            let Some(target_ip) = self.parked[slot].as_ref().map(|frame| frame.target_ip) else {
                continue;
            };
            let Some(mac) = self.lookup(target_ip, now_ms) else {
                continue;
            };
            let Some(mut frame) = self.parked[slot].take() else {
                continue;
            };
            if frame.reply.patch_dst_mac(mac) {
                ready.push(frame);
            } else {
                // Structurally unreachable (parked frames carry a full
                // Ethernet header); fail-closed — never emit unpatched.
                self.pending_counters.retx_failures =
                    self.pending_counters.retx_failures.saturating_add(1);
                retired.push(frame);
            }
        }

        let mut seen: [Option<Ipv4Addr>; PENDING_FRAME_SLOTS] = [None; PENDING_FRAME_SLOTS];
        let mut seen_len = 0usize;
        for slot in 0..PENDING_FRAME_SLOTS {
            let Some((target_ip, our_mac, our_ip)) = self.parked[slot]
                .as_ref()
                .map(|frame| (frame.target_ip, frame.our_mac, frame.our_ip))
            else {
                continue;
            };
            if !snapshot.contains(target_ip)
                || seen[..seen_len].iter().any(|key| *key == Some(target_ip))
            {
                continue;
            }
            seen[seen_len] = Some(target_ip);
            seen_len += 1;
            if self.admit_probe(target_ip, now_ms) == ProbeAdmission::Admitted {
                probes.push(PendingProbe {
                    target_ip,
                    our_mac,
                    our_ip,
                });
            }
        }

        PendingDrain {
            ready,
            retired,
            probes,
        }
    }

    /// D3 PENDING-FRAME v2: fold one drain's post-lock transmission results
    /// back into the lifecycle counters (one re-lock per sweep, not per
    /// frame). `accepted` = device queue accepted; `failed` = dropped
    /// fail-closed (policy/ownership/queue) — popped frames are NEVER
    /// re-parked.
    pub(crate) fn record_pending_tx_outcomes(&mut self, accepted: u64, failed: u64) {
        self.pending_counters.retransmitted =
            self.pending_counters.retransmitted.saturating_add(accepted);
        self.pending_counters.retx_failures =
            self.pending_counters.retx_failures.saturating_add(failed);
    }

    /// D3 PENDING-FRAME v2: occupied slot indices in ascending `park_seq`
    /// order (insertion sort over ≤ [`PENDING_FRAME_SLOTS`] entries — FIFO
    /// release, deterministic under same-ms parks).
    fn ordered_pending_indices(&self) -> ([usize; PENDING_FRAME_SLOTS], usize) {
        let mut indices = [0usize; PENDING_FRAME_SLOTS];
        let mut len = 0;
        for (slot, frame) in self.parked.iter().enumerate() {
            if frame.is_some() {
                indices[len] = slot;
                len += 1;
            }
        }
        let seq_of = |slot: usize| -> u64 {
            self.parked[slot]
                .as_ref()
                .map(|frame| frame.park_seq)
                .unwrap_or(u64::MAX)
        };
        for i in 1..len {
            let candidate = indices[i];
            let candidate_seq = seq_of(candidate);
            let mut j = i;
            while j > 0 && seq_of(indices[j - 1]) > candidate_seq {
                indices[j] = indices[j - 1];
                j -= 1;
            }
            indices[j] = candidate;
        }
        (indices, len)
    }

    /// D3 ARP-PROBE: claim a probe slot for `ip` and admit the claim
    /// against the per-cache probe bucket. Called by the TX resolver under
    /// this cache's own mutex, on the on-link-miss fallback arm only (a
    /// cache HIT never probes; off-link destinations resolve through the
    /// gateway and are never probed).
    ///
    /// Ring semantics (heap-free, deterministic):
    /// - An existing claim for `ip` suppresses re-claims until
    ///   [`ARP_PROBE_INTERVAL_MS`] has elapsed; a REGRESSED clock
    ///   (`now_ms < last_probe_ms`) also suppresses — fail-closed, the
    ///   same direction as [`TokenBucket`]'s monotonic guard.
    /// - A new IP takes the first vacant slot, else REPLACES the slot with
    ///   the minimum `last_probe_ms` (FIRST minimum on ties —
    ///   deterministic, Codex round-26 D2). Working sets larger than the
    ///   ring degrade per-IP spacing through eviction; the token buckets
    ///   stay the hard bound.
    /// - Claims are retained on bucket denial AND when the motivating data
    ///   TX later fails: the bucket meters admitted intents, not confirmed
    ///   transmissions (Codex round-26 Q1).
    ///
    /// # Clock domain
    ///
    /// On SHARED caches (per-namespace or the pre-registration global)
    /// this must only ever be fed the real kernel clock: the bucket is
    /// monotonic fail-closed, so one fake-clock call would deny every
    /// later real-clock admission. Fixed-clock tests use standalone
    /// instances.
    pub fn admit_probe(&mut self, ip: Ipv4Addr, now_ms: u64) -> ProbeAdmission {
        if let Some(slot) = self
            .probe_ring
            .iter_mut()
            .flatten()
            .find(|slot| slot.ip == ip)
        {
            if now_ms < slot.last_probe_ms || now_ms - slot.last_probe_ms < ARP_PROBE_INTERVAL_MS {
                return ProbeAdmission::DuplicateSuppressed;
            }
            slot.last_probe_ms = now_ms;
        } else {
            let target = match self.probe_ring.iter().position(Option::is_none) {
                Some(vacant) => vacant,
                None => {
                    // Full ring: replace the oldest claim (first minimum).
                    let mut oldest = 0;
                    let mut oldest_ms = u64::MAX;
                    for (index, slot) in self.probe_ring.iter().enumerate() {
                        if let Some(slot) = slot {
                            if slot.last_probe_ms < oldest_ms {
                                oldest_ms = slot.last_probe_ms;
                                oldest = index;
                            }
                        }
                    }
                    oldest
                }
            };
            self.probe_ring[target] = Some(ProbeSlot {
                ip,
                last_probe_ms: now_ms,
            });
        }
        if !self.probe_rate_limiter.allow(now_ms) {
            return ProbeAdmission::RateLimited;
        }
        ProbeAdmission::Admitted
    }

    /// Clear all dynamic entries.
    pub fn clear_dynamic(&mut self) {
        self.entries.retain(|e| e.kind == ArpEntryKind::Static);
    }

    /// D3 NETNS-CONFIG: Drop every entry — static AND dynamic.
    ///
    /// Reconfiguration flush: when a namespace's addressing changes, ALL
    /// prior neighbor state is suspect — dynamic entries were learned on
    /// the old subnet, and the static gateway seed maps the OLD gateway
    /// (Codex round-9: stale ARP state must not survive reconfiguration).
    /// The backing capacity (and its heap-class / ns-budget charge) is
    /// retained; only the logical contents are discarded.
    ///
    /// D3 PENDING-FRAME v2: parked frames embed the PRE-reconfiguration
    /// identity (source MAC/IP baked into their bytes) — they flush with
    /// the entries and are RETURNED so the caller drops them strictly
    /// after this cache's mutex (frame drops release heap admissions).
    /// The probe ring and buckets are REAL-clock throttle state and
    /// deliberately survive: reconfiguration must not grant a rate reset.
    pub fn clear_all(&mut self) -> PendingFrameBatch {
        self.entries.retain(|_| false);
        let mut flushed = PendingFrameBatch::new();
        for slot in &mut self.parked {
            if let Some(frame) = slot.take() {
                flushed.push(frame);
            }
        }
        self.pending_counters.flushed = self
            .pending_counters
            .flushed
            .saturating_add(flushed.len() as u64);
        flushed
    }

    /// D3 NETNS-CONFIG: authoritatively (re)seed the static gateway mapping
    /// from the sending namespace's OWN configuration snapshot.
    ///
    /// Unlike `insert`, an existing entry for `ip` — static OR dynamic, any
    /// MAC — is REPLACED. This does not weaken the anti-poisoning contracts
    /// (R65-7 / R101-11 / insert's static protection): those defend the
    /// cache against WIRE-derived updates (learned replies, gratuitous
    /// ARP); this seed's values come from the kernel's own namespace
    /// configuration, which outranks whatever the cache holds. Without
    /// replacement, a bounded in-flight send from the PREVIOUS
    /// configuration generation can re-seed the OLD gateway MAC after the
    /// reconfiguration flush, and the stale static entry then survives
    /// forever — statics never expire, never evict, and plain `insert`
    /// refuses to overwrite them (Codex round-10 finding). With
    /// replacement, every send re-asserts its snapshot's values, so
    /// pollution is bounded by the in-flight send itself — the documented
    /// non-quiescence envelope of `set_net_config`.
    pub fn seed_static_gateway(
        &mut self,
        ip: Ipv4Addr,
        mac: EthAddr,
        now_ms: u64,
    ) -> Result<(), ArpError> {
        if let Some(pos) = self.entries.iter().position(|e| e.ip == ip) {
            let existing = &self.entries[pos];
            if existing.kind == ArpEntryKind::Static && existing.mac == mac {
                // Already correct — refresh the timestamp only.
                self.entries[pos].updated_at = now_ms;
                return Ok(());
            }
            let _ = self.entries.remove(pos);
        }
        self.insert(ip, mac, ArpEntryKind::Static, now_ms)
    }

    /// R101-11 FIX: Check if a static entry exists for the given IP.
    ///
    /// Used by gratuitous ARP processing to protect static entries (e.g., gateway)
    /// from being updated via gratuitous ARP packets, even with matching MACs.
    pub fn has_static_entry(&self, ip: Ipv4Addr) -> bool {
        self.entries
            .iter()
            .any(|e| e.ip == ip && e.kind == ArpEntryKind::Static)
    }
}

// ============================================================================
// ARP Statistics
// ============================================================================

/// ARP protocol statistics
#[derive(Debug, Default)]
pub struct ArpStats {
    /// ARP packets received
    pub rx_packets: AtomicU64,
    /// ARP requests received
    pub rx_requests: AtomicU64,
    /// ARP replies received
    pub rx_replies: AtomicU64,
    /// ARP replies sent
    pub tx_replies: AtomicU64,
    /// Packets dropped due to parse errors
    pub rx_errors: AtomicU64,
    /// Packets dropped due to rate limiting
    pub rx_rate_limited: AtomicU64,
    /// Packets dropped due to cache conflicts
    pub cache_conflicts: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// D3 ARP-PROBE: probe requests actually accepted by the TX queue.
    pub probes_sent: AtomicU64,
    /// D3 ARP-PROBE: admitted probe intents that failed to build or
    /// enqueue (best-effort v1 drops them — no pending queue).
    pub probe_tx_failures: AtomicU64,
    /// D3 ARP-PROBE: probe claims denied by a probe token bucket
    /// (per-cache or the global aggregate backstop).
    pub probe_rate_limited: AtomicU64,
    /// D3 ARP-PROBE: probe claims suppressed by the per-IP interval ring.
    pub probe_duplicate_suppressed: AtomicU64,
}

impl ArpStats {
    pub const fn new() -> Self {
        ArpStats {
            rx_packets: AtomicU64::new(0),
            rx_requests: AtomicU64::new(0),
            rx_replies: AtomicU64::new(0),
            tx_replies: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            rx_rate_limited: AtomicU64::new(0),
            cache_conflicts: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            probes_sent: AtomicU64::new(0),
            probe_tx_failures: AtomicU64::new(0),
            probe_rate_limited: AtomicU64::new(0),
            probe_duplicate_suppressed: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_requests(&self) {
        self.rx_requests.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_replies(&self) {
        self.rx_replies.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_tx_replies(&self) {
        self.tx_replies.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_rate_limited(&self) {
        self.rx_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_conflicts(&self) {
        self.cache_conflicts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_probes_sent(&self) {
        self.probes_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_probe_tx_failures(&self) {
        self.probe_tx_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_probe_rate_limited(&self) {
        self.probe_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_probe_duplicate_suppressed(&self) {
        self.probe_duplicate_suppressed
            .fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// ARP Parsing
// ============================================================================

/// Parse an ARP packet from raw bytes.
///
/// # Security
///
/// - Validates hardware type (Ethernet), protocol type (IPv4)
/// - Validates address lengths
/// - Validates operation code
/// - Rejects packets with broadcast/multicast/zero sender MAC
///
/// # Arguments
///
/// * `buf` - Raw ARP packet bytes (Ethernet payload)
///
/// # Returns
///
/// Parsed `ArpPacket` or error describing the validation failure.
pub fn parse_arp(buf: &[u8]) -> Result<ArpPacket, ArpError> {
    // Minimum length check
    if buf.len() < ARP_PACKET_LEN {
        return Err(ArpError::Truncated);
    }

    // Parse and validate fixed fields
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    if htype != HTYPE_ETHERNET {
        return Err(ArpError::InvalidHardwareType);
    }

    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    if ptype != PTYPE_IPV4 {
        return Err(ArpError::InvalidProtocolType);
    }

    let hlen = buf[4];
    let plen = buf[5];
    if hlen != HLEN_ETHERNET || plen != PLEN_IPV4 {
        return Err(ArpError::InvalidAddressLength);
    }

    let opcode = u16::from_be_bytes([buf[6], buf[7]]);
    let op = ArpOp::from_raw(opcode).ok_or(ArpError::InvalidOpcode)?;

    // Parse addresses
    let mut sender_hw_bytes = [0u8; 6];
    sender_hw_bytes.copy_from_slice(&buf[8..14]);
    let sender_hw = EthAddr(sender_hw_bytes);

    let sender_ip = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);

    let mut target_hw_bytes = [0u8; 6];
    target_hw_bytes.copy_from_slice(&buf[18..24]);
    let target_hw = EthAddr(target_hw_bytes);

    let target_ip = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);

    // Security: Validate sender address
    // Reject broadcast/multicast source MACs (potential spoofing)
    if sender_hw.is_broadcast() || sender_hw.is_multicast() {
        return Err(ArpError::InvalidSender);
    }

    // Reject zero MAC (invalid sender)
    if sender_hw == EthAddr::ZERO {
        return Err(ArpError::InvalidSender);
    }

    // R159-15 FIX: Reject invalid sender IPs using comprehensive validation.
    // Previously only checked is_unspecified(); now rejects loopback, multicast,
    // broadcast, 0/8 reserved, and .255 directed broadcasts — matching the
    // is_valid_source() validation used for IP packets.
    if !sender_ip.is_valid_source() {
        return Err(ArpError::InvalidSender);
    }

    Ok(ArpPacket {
        sender_hw,
        sender_ip,
        target_hw,
        target_ip,
        op,
    })
}

// ============================================================================
// ARP Serialization
// ============================================================================

/// Serialize an ARP packet to bytes.
///
/// # Arguments
///
/// * `pkt` - ARP packet to serialize
///
/// # Returns
///
/// 28-byte ARP packet suitable for Ethernet payload.
fn serialize_arp_bytes(pkt: &ArpPacket) -> [u8; ARP_PACKET_LEN] {
    let mut bytes = [0u8; ARP_PACKET_LEN];
    bytes[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    bytes[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
    bytes[4] = HLEN_ETHERNET;
    bytes[5] = PLEN_IPV4;
    bytes[6..8].copy_from_slice(&pkt.op.to_raw().to_be_bytes());
    bytes[8..14].copy_from_slice(&pkt.sender_hw.0);
    bytes[14..18].copy_from_slice(&pkt.sender_ip.octets());
    bytes[18..24].copy_from_slice(&pkt.target_hw.0);
    bytes[24..28].copy_from_slice(&pkt.target_ip.octets());
    bytes
}

// RF180-41 FIX: serialization is aggregate-admitted and owns that charge for
// the exact lifetime of its backing allocation.
pub fn serialize_arp(pkt: &ArpPacket) -> WirePacket {
    WirePacket::try_copy_from_slice(&serialize_arp_bytes(pkt)).unwrap_or_default()
}

/// Build an ARP reply packet.
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `target_mac` - Target MAC address (original sender)
/// * `target_ip` - Target IP address (original sender)
///
/// # Returns
///
/// Complete Ethernet frame containing ARP reply.
pub fn build_arp_reply(
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    target_mac: EthAddr,
    target_ip: Ipv4Addr,
) -> WirePacket {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: target_mac,
        target_ip: target_ip,
        op: ArpOp::Reply,
    };

    let arp_payload = serialize_arp_bytes(&arp_pkt);
    build_ethernet_frame(target_mac, our_mac, ETHERTYPE_ARP, &arp_payload)
}

/// Build an ARP request packet.
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `target_ip` - IP address we're looking for
///
/// # Returns
///
/// Complete Ethernet frame containing ARP request (broadcast).
pub fn build_arp_request(our_mac: EthAddr, our_ip: Ipv4Addr, target_ip: Ipv4Addr) -> WirePacket {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: EthAddr::ZERO, // Unknown, set to zero for request
        target_ip: target_ip,
        op: ArpOp::Request,
    };

    let arp_payload = serialize_arp_bytes(&arp_pkt);
    // Broadcast the request
    build_ethernet_frame(EthAddr::BROADCAST, our_mac, ETHERTYPE_ARP, &arp_payload)
}

/// Build a gratuitous ARP packet (announce our presence).
///
/// Gratuitous ARP has sender IP == target IP, used for:
/// - Announcing presence on network
/// - Updating stale ARP caches
/// - Detecting IP conflicts
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
///
/// # Returns
///
/// Complete Ethernet frame containing gratuitous ARP (broadcast).
pub fn build_gratuitous_arp(our_mac: EthAddr, our_ip: Ipv4Addr) -> WirePacket {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: EthAddr::ZERO,
        target_ip: our_ip, // Same as sender IP for gratuitous ARP
        op: ArpOp::Request,
    };

    let arp_payload = serialize_arp_bytes(&arp_pkt);
    build_ethernet_frame(EthAddr::BROADCAST, our_mac, ETHERTYPE_ARP, &arp_payload)
}

// ============================================================================
// ARP Rate Limiter
// ============================================================================

/// Global ARP rate limiter for RX processing.
pub static ARP_RX_RATE_LIMITER: TokenBucket =
    TokenBucket::new(DEFAULT_RX_RATE_PPS, DEFAULT_RX_BURST);

/// Global ARP rate limiter for TX replies.
pub static ARP_TX_RATE_LIMITER: TokenBucket =
    TokenBucket::new(DEFAULT_TX_RATE_PPS, DEFAULT_TX_BURST);

/// D3 ARP-PROBE: global AGGREGATE probe backstop across every cache —
/// bounds total ARP-request wire load as namespace counts grow (round-20:
/// the separate probe bucket is the aggregate hard bound). Sits BEHIND
/// each cache's own `probe_rate_limiter` and is drawn ONLY at EMISSION,
/// after the motivating data frame passed the ownership-gated TX queue
/// (Codex round-27 F3: an admission-time draw would let one gated-out
/// namespace pin the shared bucket at empty — per-cache rate equals the
/// global refill rate). Real-clock only — see `ArpCache::admit_probe`
/// clock-domain note.
pub static ARP_PROBE_RATE_LIMITER: TokenBucket =
    TokenBucket::new(DEFAULT_PROBE_RATE_PPS, DEFAULT_PROBE_BURST);

// ============================================================================
// ARP Processing Result
// ============================================================================

/// Result of processing an ARP packet
#[derive(Debug)]
pub enum ArpResult {
    /// ARP was handled, no response needed
    Handled,
    /// ARP requires a reply to be sent
    Reply(WirePacket),
    /// ARP was dropped with reason
    Dropped(ArpError),
}

// ============================================================================
// ARP Packet Handler
// ============================================================================

/// Process an incoming ARP packet.
///
/// This function handles:
/// 1. Rate limiting (flood protection)
/// 2. Packet parsing and validation
/// 3. Cache update (with anti-spoofing)
/// 4. ARP reply generation for requests targeting our IP
///
/// # Security
///
/// - Rate limits both RX processing and TX replies
/// - Validates sender addresses (rejects broadcast/multicast/zero)
/// - Detects cache conflicts (anti-poisoning)
/// - Prevents reflection attacks (won't reply to conflicting sender)
///
/// # Arguments
///
/// * `payload` - ARP packet bytes (Ethernet payload)
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `cache` - ARP cache for address resolution
/// * `stats` - Statistics counters
/// * `now_ms` - Current time in milliseconds
///
/// # Returns
///
/// `ArpResult` indicating what action to take.
pub fn process_arp(
    payload: &[u8],
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    cache: &mut ArpCache,
    stats: &ArpStats,
    now_ms: u64,
) -> ArpResult {
    stats.inc_rx_packets();

    // R102-12 FIX: Check per-interface rate limiter first, then global as backstop.
    // This prevents a single malicious host on one interface from starving all others.
    if !cache.rx_rate_limiter.allow(now_ms) || !ARP_RX_RATE_LIMITER.allow(now_ms) {
        stats.inc_rx_rate_limited();
        return ArpResult::Dropped(ArpError::RateLimited);
    }

    // Parse ARP packet
    let pkt = match parse_arp(payload) {
        Ok(p) => p,
        Err(e) => {
            stats.inc_rx_errors();
            return ArpResult::Dropped(e);
        }
    };

    // Track request/reply stats
    match pkt.op {
        ArpOp::Request => stats.inc_rx_requests(),
        ArpOp::Reply => stats.inc_rx_replies(),
    }

    // R45 FIX: Determine if packet involves us or is gratuitous
    let is_gratuitous = pkt.sender_ip == pkt.target_ip;
    let for_us = pkt.target_ip == our_ip;

    // R101-11 FIX: Strengthened gratuitous ARP anti-spoofing.
    //
    // R48-2 restricted gratuitous ARP to same-MAC refreshes. R101-11 adds an
    // additional check: if a static entry exists for the sender IP, gratuitous
    // ARP is NEVER used to update the cache (static entries are authoritative).
    // This protects critical entries like the default gateway from gratuitous ARP
    // cache poisoning attacks even if the attacker can spoof the legitimate MAC.
    //
    // Acceptance rules for gratuitous ARP:
    // 1. It's for our own IP (legitimate self-announcement), OR
    // 2. It's a same-MAC refresh of an existing DYNAMIC cache entry
    //    (static entries are never updated via gratuitous ARP)
    let existing_mac = cache.lookup(pkt.sender_ip, now_ms);

    // Check if a static entry exists for this IP
    let has_static_entry = cache.has_static_entry(pkt.sender_ip);

    let allow_gratuitous = is_gratuitous
        && !has_static_entry  // R101-11: Never allow gratuitous ARP to affect static entries
        && (
            pkt.sender_ip == our_ip ||                        // Our own announcement
        existing_mac == Some(pkt.sender_hw)
            // Same-MAC refresh only (dynamic entries)
        );

    // Security: Detect reflection attack attempt
    // If sender claims our IP but has different MAC, ignore completely
    if pkt.sender_ip == our_ip && pkt.sender_hw != our_mac {
        stats.inc_cache_conflicts();
        return ArpResult::Dropped(ArpError::CacheConflict);
    }

    // R45 FIX: Drop ARP replies not directed at us to reduce poisoning surface
    // Only accept replies that are:
    // 1. Targeted at our IP and MAC, or
    // 2. Gratuitous announcements that pass the R48-2 check
    if pkt.op == ArpOp::Reply {
        // Reject replies with invalid target MAC (broadcast/multicast/zero)
        if pkt.target_hw.is_broadcast()
            || pkt.target_hw.is_multicast()
            || pkt.target_hw == EthAddr::ZERO
        {
            stats.inc_rx_errors();
            return ArpResult::Dropped(ArpError::InvalidSender);
        }
        // Drop replies not for us (check allow_gratuitous instead of is_gratuitous)
        if !allow_gratuitous && (!for_us || pkt.target_hw != our_mac) {
            return ArpResult::Handled;
        }
    }

    // R65-7 FIX: Only learn from ARP replies (or allowed gratuitous/self-refresh requests).
    // This blocks attackers from poisoning the cache via forged ARP requests targeted at us.
    // Previously, any packet with target_ip == our_ip would learn the sender's mapping,
    // allowing an attacker to send a request claiming sender_ip = gateway_ip to hijack traffic.
    match pkt.op {
        ArpOp::Reply => {
            // Learn from replies addressed to us or allowed gratuitous
            if for_us || allow_gratuitous {
                if let Err(e) =
                    cache.insert(pkt.sender_ip, pkt.sender_hw, ArpEntryKind::Dynamic, now_ms)
                {
                    stats.inc_cache_conflicts();
                    return ArpResult::Dropped(e);
                }
            }
        }
        ArpOp::Request => {
            // Only allow gratuitous/self-refresh to update cache; ignore other requests.
            // Normal requests should only trigger a reply, not learn the sender's mapping.
            if allow_gratuitous {
                if let Err(e) =
                    cache.insert(pkt.sender_ip, pkt.sender_hw, ArpEntryKind::Dynamic, now_ms)
                {
                    stats.inc_cache_conflicts();
                    return ArpResult::Dropped(e);
                }
            }
        }
    }

    // Handle based on operation type
    match pkt.op {
        ArpOp::Request => {
            // Only respond if the request is for our IP
            if !for_us {
                return ArpResult::Handled;
            }

            // Ignore gratuitous ARP (target IP == sender IP, request for self)
            if is_gratuitous {
                return ArpResult::Handled;
            }

            // R102-12 FIX: Per-interface TX rate limiter + global backstop.
            if !cache.tx_rate_limiter.allow(now_ms) || !ARP_TX_RATE_LIMITER.allow(now_ms) {
                stats.inc_rx_rate_limited();
                return ArpResult::Dropped(ArpError::RateLimited);
            }

            // Build and return reply
            let reply = build_arp_reply(our_mac, our_ip, pkt.sender_hw, pkt.sender_ip);
            // R165-19 FIX: build_arp_reply returns an empty admitted packet when
            // allocation/admission fails. Drop rather than emit a runt frame;
            // the peer will retry.
            if reply.is_empty() {
                return ArpResult::Handled;
            }
            ArpResult::Reply(reply)
        }
        ArpOp::Reply => {
            // Reply processing: mapping was already learned above (if applicable)
            ArpResult::Handled
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_arp_request() -> WirePacket {
        let pkt = ArpPacket {
            sender_hw: EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Request,
        };
        serialize_arp(&pkt)
    }

    #[test]
    fn test_parse_valid_arp() {
        let data = make_test_arp_request();
        let pkt = parse_arp(&data).expect("should parse");
        assert_eq!(pkt.op, ArpOp::Request);
        assert_eq!(pkt.sender_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(pkt.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0u8; 10];
        assert_eq!(parse_arp(&data), Err(ArpError::Truncated));
    }

    #[test]
    fn test_parse_invalid_htype() {
        let mut data = make_test_arp_request();
        data[0] = 0x00; // Invalid hardware type
        data[1] = 0x02;
        assert_eq!(parse_arp(&data), Err(ArpError::InvalidHardwareType));
    }

    #[test]
    fn test_parse_broadcast_sender() {
        let pkt = ArpPacket {
            sender_hw: EthAddr::BROADCAST,
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Request,
        };
        let data = serialize_arp(&pkt);
        assert_eq!(parse_arp(&data), Err(ArpError::InvalidSender));
    }

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        cache.insert(ip, mac, ArpEntryKind::Dynamic, 1000).unwrap();
        assert_eq!(cache.lookup(ip, 1000), Some(mac));
    }

    #[test]
    fn test_cache_conflict_rejection() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac1 = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac2 = EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        cache.insert(ip, mac1, ArpEntryKind::Dynamic, 1000).unwrap();
        // Attempt to update with different MAC should be rejected (anti-poisoning)
        assert_eq!(
            cache.insert(ip, mac2, ArpEntryKind::Dynamic, 2000),
            Err(ArpError::CacheConflict)
        );
        // Original mapping should still be there
        assert_eq!(cache.lookup(ip, 2000), Some(mac1));
    }

    #[test]
    fn test_cache_static_protection() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let static_mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let spoofed_mac = EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        cache.add_static(ip, static_mac, 1000).unwrap();
        // Attempt to overwrite static with dynamic should be rejected
        assert_eq!(
            cache.insert(ip, spoofed_mac, ArpEntryKind::Dynamic, 2000),
            Err(ArpError::CacheConflict)
        );
        assert_eq!(cache.lookup(ip, 2000), Some(static_mac));
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = ArpCache::new(1000, 10); // 1 second TTL
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        cache.insert(ip, mac, ArpEntryKind::Dynamic, 0).unwrap();
        assert_eq!(cache.lookup(ip, 500), Some(mac)); // Not expired
        assert_eq!(cache.lookup(ip, 1500), None); // Expired
    }

    #[test]
    fn test_serialize_roundtrip() {
        let pkt = ArpPacket {
            sender_hw: EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Reply,
        };
        let data = serialize_arp(&pkt);
        let parsed = parse_arp(&data).expect("should parse");
        assert_eq!(parsed.sender_hw, pkt.sender_hw);
        assert_eq!(parsed.sender_ip, pkt.sender_ip);
        assert_eq!(parsed.target_hw, pkt.target_hw);
        assert_eq!(parsed.target_ip, pkt.target_ip);
        assert_eq!(parsed.op, pkt.op);
    }
}
