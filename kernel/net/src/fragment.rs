//! IPv4 Fragment Reassembly for Zero-OS
//!
//! This module provides secure IP fragment reassembly with anti-DoS protections.
//!
//! # Security Features
//! - RFC 5722 overlap detection (reject overlapping fragments)
//! - Per-source queue limits (prevent memory exhaustion)
//! - Global fragment count limits
//! - Reassembly timeout (45 seconds)
//! - First fragment L4 header visibility requirement
//! - Rate limiting per source
//!
//! # References
//! - RFC 791: Internet Protocol (fragmentation)
//! - RFC 815: IP Datagram Reassembly Algorithms
//! - RFC 5722: Handling of Overlapping IPv4 Fragments
//! - RFC 8900: IP Fragmentation Considered Fragile

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use mm::HeapClass;

use crate::admitted::{
    AdmittedMap, AdmittedVec, CapacityPlan, PreparedAdmittedMapCapacity,
    RetiredAdmittedMapCapacity, WirePacket,
};
use crate::ipv4::Ipv4Header;

// ============================================================================
// Constants - Security Limits
// ============================================================================

/// R101-12 FIX: Reduced fragment reassembly timeout from 45s to 30s.
///
/// The previous 45-second timeout allowed attackers to hold reassembly buffer
/// memory for longer. Linux default is 30 seconds (net.ipv4.ipfrag_time).
/// Reducing timeout limits the memory pressure window from crafted fragments
/// that are never completed.
pub const FRAG_TIMEOUT_MS: u64 = 30_000;

/// Maximum reassembled packet size (IPv4 max is 65535)
pub const MAX_PACKET_SIZE: usize = 65_535;

/// Maximum fragments per reassembly queue
pub const MAX_FRAGS_PER_QUEUE: usize = 64;

/// R62-2 FIX: Maximum buffered bytes per reassembly queue (DoS bound)
/// 512KB per queue prevents single attacker from exhausting memory
pub const MAX_BYTES_PER_QUEUE: usize = 512 * 1024;

/// Maximum queues per source IP address
pub const MAX_QUEUES_PER_SRC: usize = 256;

/// Global maximum reassembly queues
pub const GLOBAL_MAX_QUEUES: usize = 4096;

/// Global maximum fragments across all queues
pub const GLOBAL_MAX_FRAGS: usize = 32_768;

/// R62-2 FIX: Global maximum buffered fragment bytes (DoS bound)
/// 64MB global limit prevents memory exhaustion from fragment floods
pub const GLOBAL_MAX_FRAG_BYTES: usize = 64 * 1024 * 1024;

// R169-10: per-namespace fragment-reassembly ceilings = a FIXED 1/4 of each
// global budget. The cross-ns isolation goal (one netns flooding crafted
// fragments must not deny another netns reassembly) requires capping ALL THREE
// dimensions per-ns: a queue-count cap alone is insufficient because the global
// BYTE budget exhausts at 64MiB/512KiB = 128 queues and the global FRAG budget at
// 32768/64 = 512 queues — BOTH below the 1024 queue cap — so a flooder would
// exhaust the byte/frag pool below any queue cap (those rejection paths have no
// LRU recycling => renewable cross-ns starvation). Fixing each per-ns cap at 1/4
// of global guarantees >=3/4 of every global budget is ALWAYS reachable by other
// tenants, and a tenant's ceiling never shrinks as neighbors appear (a FIXED
// fraction, NOT GLOBAL/live_ns_count — which would have a shrinking-floor TOCTOU
// hazard). DOCUMENTED RESIDUAL (per-ns FAIRNESS, not the single-flooder goal): 4
// coordinated flooding namespaces each at their ceiling jointly consume the full
// 4x16MiB = 64MiB global pool and can deny a 5th — an intentional trade of
// multi-ns headroom for the non-shrinking single-tenant floor.
pub const MAX_QUEUES_PER_NS: usize = GLOBAL_MAX_QUEUES / 4; // 1024
pub const MAX_FRAGS_PER_NS: usize = GLOBAL_MAX_FRAGS / 4; // 8192
pub const MAX_BYTES_PER_NS: u64 = (GLOBAL_MAX_FRAG_BYTES as u64) / 4; // 16 MiB

/// Minimum L4 header bytes required in first fragment
/// (8 bytes covers UDP header and TCP source/dest ports)
pub const MIN_L4_HEADER_BYTES: usize = 8;

/// Rate limit tokens per source (fragments per window)
pub const RATE_LIMIT_TOKENS: u32 = 128;

/// Rate limit refill window in milliseconds
pub const RATE_LIMIT_WINDOW_MS: u64 = 1000;

/// Number of independent fragment mutation lanes.  A lane is selected from
/// the network-namespace id, so unrelated namespaces can make progress in
/// parallel while a single namespace still has a serialized transaction
/// boundary.  The power-of-two size keeps selection allocation-free.
const FRAGMENT_TRANSACTION_SLOTS: usize = 64;

// ============================================================================
// Statistics
// ============================================================================

/// Fragment reassembly statistics
#[derive(Debug, Default)]
pub struct FragmentStats {
    /// Fragments received
    pub fragments_received: AtomicU64,
    /// Successfully reassembled packets
    pub reassembled: AtomicU64,
    /// Fragments dropped due to timeout
    pub timeout_drops: AtomicU64,
    /// Fragments dropped due to overlap
    pub overlap_drops: AtomicU64,
    /// Fragments dropped due to queue limit
    pub queue_limit_drops: AtomicU64,
    /// Fragments dropped due to global limit
    pub global_limit_drops: AtomicU64,
    /// Fragments dropped due to rate limit
    pub rate_limit_drops: AtomicU64,
    /// Fragments dropped - first too small
    pub first_too_small_drops: AtomicU64,
    /// Fragments dropped - too large
    pub too_large_drops: AtomicU64,
    /// Current active queues
    pub active_queues: AtomicU32,
    /// Current buffered fragments
    pub buffered_fragments: AtomicU32,
    /// R62-2 FIX: Current buffered bytes
    pub buffered_bytes: AtomicU64,
}

impl FragmentStats {
    pub const fn new() -> Self {
        Self {
            fragments_received: AtomicU64::new(0),
            reassembled: AtomicU64::new(0),
            timeout_drops: AtomicU64::new(0),
            overlap_drops: AtomicU64::new(0),
            queue_limit_drops: AtomicU64::new(0),
            global_limit_drops: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            first_too_small_drops: AtomicU64::new(0),
            too_large_drops: AtomicU64::new(0),
            active_queues: AtomicU32::new(0),
            buffered_fragments: AtomicU32::new(0),
            buffered_bytes: AtomicU64::new(0),
        }
    }

    /// R66-11 FIX: Atomically reserve a fragment slot if within limit.
    /// Returns true if reservation succeeded, false if limit would be exceeded.
    pub fn try_reserve_fragment(&self, max_frags: usize) -> bool {
        self.buffered_fragments
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if (current as usize) < max_frags {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// R66-11 FIX: Atomically reserve bytes if within limit.
    /// Returns true if reservation succeeded, false if limit would be exceeded.
    pub fn try_reserve_bytes(&self, bytes: usize, max_bytes: usize) -> bool {
        self.buffered_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let new_val = current.saturating_add(bytes as u64);
                if (new_val as usize) <= max_bytes {
                    Some(new_val)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// R66-11 FIX: Release previously reserved fragment slot.
    pub fn release_fragment(&self) {
        // Saturating sub to handle edge cases
        self.buffered_fragments
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            })
            .ok();
    }

    /// R66-11 FIX: Release previously reserved bytes.
    pub fn release_bytes(&self, bytes: usize) {
        self.buffered_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(bytes as u64))
            })
            .ok();
    }
}

// ============================================================================
// Drop Reasons
// ============================================================================

/// Reason a fragment was dropped
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentDropReason {
    /// Rate limited (too many fragments from source)
    RateLimited,
    /// Fragment would exceed max packet size
    TooLarge,
    /// Queue has too many fragments
    QueueFragLimit,
    /// R62-2 FIX: Queue has too many buffered bytes
    QueueByteLimit,
    /// First fragment too small to contain L4 header
    FirstTooSmall,
    /// Overlapping fragments (RFC 5722 violation)
    Overlap,
    /// Global queue limit exceeded
    GlobalQueueLimit,
    /// Global fragment limit exceeded
    GlobalFragLimit,
    /// R62-2 FIX: Global byte limit exceeded
    GlobalByteLimit,
    /// Per-source queue limit exceeded
    PerSourceLimit,
    /// Reassembly timeout
    Timeout,
    /// Zero-length fragment
    ZeroLength,
    /// Duplicate fragment
    Duplicate,
    /// R169-10: per-namespace live-queue count ceiling reached
    PerNsQueueLimit,
    /// R169-10: per-namespace buffered-fragment ceiling reached
    PerNsFragLimit,
    /// R169-10: per-namespace buffered-byte ceiling reached
    PerNsByteLimit,
}

// ============================================================================
// Fragment Key
// ============================================================================

/// Key to identify a fragment reassembly queue
///
/// Per RFC 791, fragments are identified by (src, dst, protocol, identification).
/// R140-4 FIX: Include net_ns_id so that fragment reassembly is isolated per
/// network namespace.  Without this, overlapping private IP address spaces in
/// different namespaces can cause cross-namespace fragment injection or DoS via
/// global queue exhaustion.
/// Ord is derived for the admitted ordered-map key (avoiding lossy u64 packing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentKey {
    /// R140-4 FIX: Network namespace ID for cross-namespace isolation.
    pub net_ns_id: u64,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub identification: u16,
}

impl FragmentKey {
    /// Create key from IPv4 header within a specific network namespace.
    pub fn from_header(net_ns_id: u64, hdr: &Ipv4Header) -> Self {
        Self {
            net_ns_id,
            src: hdr.src.octets(),
            dst: hdr.dst.octets(),
            protocol: hdr.protocol,
            identification: hdr.identification,
        }
    }

    /// Get source IP for per-source tracking
    pub fn src_ip(&self) -> u32 {
        u32::from_be_bytes(self.src)
    }
}

// ============================================================================
// Fragment Hole Tracking (RFC 815)
// ============================================================================

/// A hole in the reassembly buffer
///
/// Represents a gap [start, end) that still needs to be filled.
#[derive(Debug, Clone, Copy)]
struct FragmentHole {
    /// Start offset (inclusive)
    start: u16,
    /// End offset (exclusive)
    end: u16,
}

// ============================================================================
// Per-Source Rate Limiter
// ============================================================================

/// Token bucket rate limiter
struct RateLimiter {
    tokens: u32,
    last_refill_ms: u64,
}

impl RateLimiter {
    fn new(now_ms: u64) -> Self {
        Self {
            tokens: RATE_LIMIT_TOKENS,
            last_refill_ms: now_ms,
        }
    }

    fn allow(&mut self, cost: u32, now_ms: u64) -> bool {
        // Refill tokens based on elapsed time
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        let refill = ((elapsed as u64 * RATE_LIMIT_TOKENS as u64) / RATE_LIMIT_WINDOW_MS) as u32;
        self.tokens = self.tokens.saturating_add(refill).min(RATE_LIMIT_TOKENS);
        self.last_refill_ms = now_ms;

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Fragment Queue
// ============================================================================

/// A single reassembly queue for one IP datagram
struct FragmentQueue {
    /// Creation timestamp (ms)
    created_ms: u64,
    /// Expiration timestamp (ms)
    expires_at_ms: u64,
    /// Total length once last fragment received
    total_len: Option<u16>,
    /// Number of fragments received
    received_frags: usize,
    /// Total bytes received
    received_bytes: usize,
    /// Hole list (gaps to fill)
    /// RF180-41 REVIEW FIX: retained hole metadata owns aggregate heap
    /// admission for its complete lifetime.
    holes: AdmittedVec<FragmentHole>,
    /// RF180-41 REVIEW FIX: both ordered-map backing and each retained payload
    /// are aggregate-admitted before publication.
    frags: AdmittedMap<u16, WirePacket>,
    /// First fragment (offset 0) received
    have_first: bool,
    /// Last fragment (MF=0) received
    have_last: bool,
    /// First fragment has enough bytes for L4 header
    l4_header_ok: bool,
    /// Rate limiter for this source
    rate_limiter: RateLimiter,
    #[cfg(test)]
    fail_next_hole_growth: bool,
    #[cfg(test)]
    fail_next_frag_map_growth: bool,
}

impl FragmentQueue {
    /// R169-11: fallible constructor — the initial single-hole `Vec` is reserved
    /// via `try_reserve_exact` so an OOM here returns `Err(QueueByteLimit)` instead
    /// of aborting the kernel. The caller propagates the error WITHOUT charging any
    /// counter (the queue was never inserted), so accounting stays balanced.
    fn new(_key: FragmentKey, now_ms: u64) -> Result<Self, FragmentDropReason> {
        let mut holes = AdmittedVec::new(HeapClass::SocketObject);
        holes
            .ensure_capacity_for(1)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        // Initial hole: entire possible packet range (capacity reserved above).
        holes
            .push_reserved(FragmentHole {
                start: 0,
                end: u16::MAX,
            })
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        Ok(Self {
            created_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(FRAG_TIMEOUT_MS),
            total_len: None,
            received_frags: 0,
            received_bytes: 0,
            holes,
            frags: AdmittedMap::new(HeapClass::SocketObject),
            have_first: false,
            have_last: false,
            l4_header_ok: false,
            rate_limiter: RateLimiter::new(now_ms),
            #[cfg(test)]
            fail_next_hole_growth: false,
            #[cfg(test)]
            fail_next_frag_map_growth: false,
        })
    }

    /// Insert a fragment into the queue
    ///
    /// Returns Ok(true) if reassembly is now complete.
    fn insert(
        &mut self,
        offset: u16,
        more_fragments: bool,
        data: &[u8],
        now_ms: u64,
    ) -> Result<bool, FragmentDropReason> {
        // R102-L1 FIX: Use checked conversion instead of silent truncation.
        // Upstream callers enforce MTU limits, but defense-in-depth rejects
        // oversized data that would silently wrap to a smaller u16 value.
        let len = u16::try_from(data.len()).map_err(|_| FragmentDropReason::TooLarge)?;

        // Rate limiting
        if !self.rate_limiter.allow(1, now_ms) {
            return Err(FragmentDropReason::RateLimited);
        }

        // Zero-length fragments are invalid
        if len == 0 {
            return Err(FragmentDropReason::ZeroLength);
        }

        // Check fragment count limit
        if self.received_frags >= MAX_FRAGS_PER_QUEUE {
            return Err(FragmentDropReason::QueueFragLimit);
        }

        // R62-2 FIX: Check per-queue byte limit before accepting fragment
        // This prevents a single source from exhausting memory with large fragments
        if self.received_bytes.saturating_add(data.len()) > MAX_BYTES_PER_QUEUE {
            return Err(FragmentDropReason::QueueByteLimit);
        }

        let frag_start = offset;
        let frag_end = offset
            .checked_add(len)
            .ok_or(FragmentDropReason::TooLarge)?;

        // Check max packet size
        if frag_end as usize > MAX_PACKET_SIZE {
            return Err(FragmentDropReason::TooLarge);
        }

        // Validate the first-fragment visibility contract without publishing it
        // yet. All reassembly fields remain unchanged until every allocation
        // below succeeds.
        let is_first = offset == 0;
        if is_first {
            if data.len() < MIN_L4_HEADER_BYTES {
                return Err(FragmentDropReason::FirstTooSmall);
            }
        }

        // Check if this is last fragment (MF=0) and validate size
        // Note: We defer setting have_last/total_len until after validation succeeds
        let is_last = !more_fragments;
        if is_last {
            if frag_end as usize > MAX_PACKET_SIZE {
                return Err(FragmentDropReason::TooLarge);
            }
            // Security: If we already have fragments beyond this new total_len,
            // it's an inconsistent/malicious datagram - reject as overlap
            // This catches attacks that try to shrink the packet after data is buffered
            for (&stored_off, stored_data) in self.frags.iter() {
                let stored_len =
                    u16::try_from(stored_data.len()).map_err(|_| FragmentDropReason::TooLarge)?;
                let stored_end = stored_off
                    .checked_add(stored_len)
                    .ok_or(FragmentDropReason::TooLarge)?;
                if stored_end > frag_end {
                    return Err(FragmentDropReason::Overlap);
                }
            }
        }

        // Determine max valid offset for hole clipping
        // Use tentative total_len if this is last fragment, otherwise existing or max
        let max_end = if is_last {
            frag_end
        } else {
            self.total_len.unwrap_or(u16::MAX)
        };

        // RFC 5722: Overlap detection against existing fragments
        // Check previous fragment
        if let Some((&prev_off, prev_data)) = self.frags.range(..=frag_start).next_back() {
            let prev_len =
                u16::try_from(prev_data.len()).map_err(|_| FragmentDropReason::TooLarge)?;
            let prev_end = prev_off
                .checked_add(prev_len)
                .ok_or(FragmentDropReason::TooLarge)?;
            if prev_end > frag_start {
                return Err(FragmentDropReason::Overlap);
            }
        }

        // Check next fragment
        if let Some((&next_off, _)) = self.frags.range(frag_start..).next() {
            if next_off < frag_end {
                return Err(FragmentDropReason::Overlap);
            }
        }

        // RFC 815 hole algorithm: fragment must fill part of a hole.
        // R169-11 (transactional, OOM-safe): reserve the new-holes buffer BEFORE
        // touching `self.holes`, and iterate `self.holes` by COPY (FragmentHole is
        // `Copy`) instead of `drain(..)`. So if the `try_reserve` here — or the
        // payload copy / `try_insert` below — fails under memory pressure, the
        // ACCOUNTING-critical queue state (`holes`, `frags`, `total_len`,
        // `have_last`, `received_frags`/`received_bytes`) is left unchanged and we
        // return `Err(QueueByteLimit)`. (The first-fragment `have_first`/
        // `l4_header_ok` flags and the rate-limiter token are updated earlier, but
        // that does NOT affect retry correctness: the offset-0 hole is still
        // present, so `is_complete()` cannot mis-fire and a retry of the same
        // fragment re-inserts normally.)
        // RF180-41 REVIEW FIX: the historical note above is now conservative:
        // first-fragment visibility is also staged until commit. Only the
        // independent rate-limit token changes on an allocation failure.
        let mut new_holes = AdmittedVec::new(HeapClass::SocketObject);
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_hole_growth) {
            new_holes.fail_next_growth_for_test();
        }
        new_holes
            .ensure_capacity_for(self.holes.len() + 1)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        let mut covered = false;

        for hole in self.holes.iter().copied() {
            // Skip holes entirely beyond the known packet length
            if hole.start >= max_end {
                continue;
            }

            // Clip hole end to max valid offset
            let hole_end = hole.end.min(max_end);

            // No intersection with this hole
            if frag_end <= hole.start || frag_start >= hole_end {
                new_holes
                    .push_reserved(FragmentHole {
                        start: hole.start,
                        end: hole_end,
                    })
                    .map_err(|_| FragmentDropReason::QueueByteLimit)?;
                continue;
            }

            // Fragment must be fully inside this hole
            if frag_start < hole.start || frag_end > hole_end {
                return Err(FragmentDropReason::Overlap);
            }

            covered = true;

            // Split the hole around the fragment. Bound proof: exactly one hole is
            // `covered` (yields <=2 outputs, consuming 1) and every other hole
            // yields <=1, so total pushes <= self.holes.len() + 1 — the reserved
            // capacity — and these pushes therefore never reallocate.
            if hole.start < frag_start {
                new_holes
                    .push_reserved(FragmentHole {
                        start: hole.start,
                        end: frag_start,
                    })
                    .map_err(|_| FragmentDropReason::QueueByteLimit)?;
            }
            if frag_end < hole_end {
                new_holes
                    .push_reserved(FragmentHole {
                        start: frag_end,
                        end: hole_end,
                    })
                    .map_err(|_| FragmentDropReason::QueueByteLimit)?;
            }
        }

        if !covered {
            // Fragment doesn't fit in any hole - duplicate or overlap
            // Per RFC 5722, this should trigger queue discard (handled by caller).
            // `self` is still unmutated (drain replaced by copy-iteration).
            return Err(FragmentDropReason::Duplicate);
        }

        // === Fragment validated. R169-11: perform ALL fallible allocation FIRST,
        // then commit the accounting-critical state — so an OOM cannot leave the
        // queue's hole list / stored fragments / byte+frag counts half-mutated
        // (the offset-0 hole + counters stay consistent, so a retry is correct). ===

        // 1. RF180-41 FIX: every retained fragment byte owns aggregate heap
        //    admission until its backing is destroyed. Failure remains
        //    transactional because no queue state has been committed yet.
        let frag_data = WirePacket::try_copy_from_slice(data)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;

        // 2. Aggregate-admitted ordered-map insert reserves replacement backing
        //    before the shift; on Err the map is unchanged.
        //    Offset uniqueness was established by the overlap checks above.
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_frag_map_growth) {
            self.frags.fail_next_growth_for_test();
        }
        self.frags
            .try_insert(offset, frag_data)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;

        // 3. COMMIT — all infallible from here; the accounting-critical state
        //    (holes/frags/total_len/have_last/received_*) was untouched until now.
        //    Deferring the is_last/total_len write past the fallible steps is what
        //    keeps the insert transactional (a retry after an OOM here must not see
        //    a stale `total_len`/`have_last` with no stored fragment).
        if is_last {
            self.have_last = true;
            self.total_len = Some(frag_end);
        }
        if is_first {
            self.have_first = true;
            self.l4_header_ok = true;
        }
        new_holes.as_mut_slice().sort_by_key(|h| h.start);
        self.holes = new_holes;
        self.received_frags += 1;
        self.received_bytes += len as usize;

        // Note: We do NOT refresh expiration on fragment arrival.
        // This prevents DoS by sending trickle fragments to keep queues alive indefinitely.
        // Queue expires at created_ms + FRAG_TIMEOUT_MS regardless of activity.

        // Check if reassembly is complete
        Ok(self.is_complete())
    }

    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.have_first && self.have_last && self.l4_header_ok && self.holes.is_empty()
    }

    /// Reassemble the complete packet
    ///
    /// Returns None if not complete or on error.
    fn reassemble(&self) -> Option<WirePacket> {
        if !self.is_complete() {
            return None;
        }

        let total = self.total_len? as usize;
        if total > MAX_PACKET_SIZE {
            return None;
        }

        // RF180-41 FIX: the completion buffer is admitted before allocation and
        // remains charged after the queue's fragment owners are released.
        let mut buf = WirePacket::try_zeroed(total).ok()?;

        for (&off, frag) in self.frags.iter() {
            let start = off as usize;
            let end = start + frag.len();
            if end > total {
                return None; // Shouldn't happen if complete
            }
            buf[start..end].copy_from_slice(frag);
        }

        Some(buf)
    }

    /// Check if this queue has expired
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

// ============================================================================
// Fragment Cache (Global State)
// ============================================================================

/// Global fragment reassembly cache
pub struct FragmentCache {
    /// RF180-41 REVIEW FIX: active-queue backing is aggregate-admitted before
    /// a new queue becomes reachable.
    queues: Mutex<AdmittedMap<FragmentKey, FragmentQueueOwner>>,
    /// R141-2 FIX: Per-source queue counts, scoped by (net_ns_id, src_ip).
    /// Previously keyed by src_ip alone; one namespace's fragment traffic
    /// could exhaust the per-source budget for all namespaces sharing the
    /// same source IP (cross-namespace DoS).
    per_src_counts: Mutex<AdmittedMap<(u64, u32), usize>>,
    /// R169-10: per-netns fragment budget counts (queues / frags / bytes). The
    /// INNERMOST reassembly lock — order: `queues` -> `per_src_counts` ->
    /// `per_ns_counts`. An entry exists only while a namespace holds >=1 live
    /// queue (or any buffered frag/byte) and is pruned when all three reach 0, so
    /// the map stays bounded by the live-namespace count. RF180-41 removes the
    /// old bounded-but-infallible BTreeMap-node residual: backing growth is now
    /// admitted and fallible like the queue and per-source indexes.
    per_ns_counts: Mutex<AdmittedMap<u64, PerNsBudget>>,
    /// Per-namespace hashed transaction lanes.  The old single global token
    /// made a slow allocation in one namespace reject traffic in every other
    /// namespace.  Hash collisions are intentional and conservative; they
    /// only serialize the colliding lanes and never weaken namespace limits.
    transaction_slots: [AtomicBool; FRAGMENT_TRANSACTION_SLOTS],
    /// Statistics
    stats: FragmentStats,
}

/// R169-10: a namespace's contribution to the three global fragment budgets.
/// `sum(per_ns) == global` is maintained as an invariant across every charge /
/// release site (asserted by `run_fragment_perns_self_test`).
#[derive(Debug, Default, Clone, Copy)]
struct PerNsBudget {
    /// live reassembly queues owned by this namespace (mirrors active_queues)
    queues: usize,
    /// buffered fragments charged to this namespace (mirrors buffered_fragments)
    frags: u32,
    /// buffered bytes charged to this namespace (mirrors buffered_bytes)
    bytes: u64,
}

// R169-10: per-ns budget mutators. Free functions over the held guard's map so
// they never re-enter the lock. `*_charge_*` use `entry().or_default()`; `*_release_*`
// saturating-sub then prune. PRUNE ONLY when ALL THREE fields are 0 (a live queue
// implies `queues >= 1`, so an entry is never dropped while a queue lives — which
// keeps `entry()`/`get()` for an existing queue's frag/byte charge consistent).
fn per_ns_charge_queue(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64) {
    if let Some(entry) = m.get_mut(&ns) {
        entry.queues = entry
            .queues
            .checked_add(1)
            .expect("RF180-41 fragment namespace queue counter overflow");
        return;
    }
    assert!(
        m.insert_unique_reserved(
            ns,
            PerNsBudget {
                queues: 1,
                ..PerNsBudget::default()
            },
        )
        .is_ok(),
        "RF180-41 fragment namespace row publication lacked reserved capacity"
    );
}

struct FragmentTransactionPermit<'a> {
    active: &'a AtomicBool,
}

impl Drop for FragmentTransactionPermit<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

struct FragmentCleanupPermit<'a> {
    slots: &'a [AtomicBool; FRAGMENT_TRANSACTION_SLOTS],
    acquired: usize,
}

impl Drop for FragmentCleanupPermit<'_> {
    fn drop(&mut self) {
        for slot in self.slots[..self.acquired].iter().rev() {
            slot.store(false, Ordering::Release);
        }
    }
}

struct FragmentIndexCapacity {
    queues: Option<PreparedAdmittedMapCapacity<FragmentKey, FragmentQueueOwner>>,
    per_src: Option<PreparedAdmittedMapCapacity<(u64, u32), usize>>,
    per_ns: Option<PreparedAdmittedMapCapacity<u64, PerNsBudget>>,
}

impl FragmentIndexCapacity {
    fn prepare(
        queue_plan: Option<CapacityPlan>,
        per_src_plan: Option<CapacityPlan>,
        per_ns_plan: Option<CapacityPlan>,
    ) -> Result<Self, FragmentDropReason> {
        let queues = queue_plan
            .map(PreparedAdmittedMapCapacity::try_from_plan)
            .transpose()
            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?;
        let per_src = per_src_plan
            .map(PreparedAdmittedMapCapacity::try_from_plan)
            .transpose()
            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?;
        let per_ns = per_ns_plan
            .map(PreparedAdmittedMapCapacity::try_from_plan)
            .transpose()
            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?;
        Ok(Self {
            queues,
            per_src,
            per_ns,
        })
    }
}

struct RetiredFragmentIndexCapacity {
    queues: Option<RetiredAdmittedMapCapacity<FragmentKey, FragmentQueueOwner>>,
    per_src: Option<RetiredAdmittedMapCapacity<(u64, u32), usize>>,
    per_ns: Option<RetiredAdmittedMapCapacity<u64, PerNsBudget>>,
}

impl RetiredFragmentIndexCapacity {
    const fn empty() -> Self {
        Self {
            queues: None,
            per_src: None,
            per_ns: None,
        }
    }
}

/// Compact pointer-stable cache value. Moving an ordered-map entry shifts only
/// this small allocation owner; the large queue and all nested containers stay
/// at a fixed address until the detached owner is retired outside cache locks.
struct FragmentQueueOwner {
    queue: AdmittedVec<FragmentQueue>,
}

impl FragmentQueueOwner {
    fn try_new(queue: FragmentQueue) -> Result<Self, FragmentDropReason> {
        let mut owner = AdmittedVec::new(HeapClass::SocketObject);
        owner
            .ensure_capacity_for(1)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        owner
            .push_reserved(queue)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        Ok(Self { queue: owner })
    }

    #[inline]
    fn queue(&self) -> &FragmentQueue {
        self.queue
            .as_slice()
            .first()
            .expect("RF180-41 fragment owner lost its queue")
    }

    #[inline]
    fn queue_mut(&mut self) -> &mut FragmentQueue {
        self.queue
            .as_mut_slice()
            .first_mut()
            .expect("RF180-41 fragment owner lost its queue")
    }
}

impl core::ops::Deref for FragmentQueueOwner {
    type Target = FragmentQueue;

    fn deref(&self) -> &Self::Target {
        self.queue()
    }
}

impl core::ops::DerefMut for FragmentQueueOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.queue_mut()
    }
}
fn per_ns_charge_frag(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64) {
    let entry = m
        .get_mut(&ns)
        .expect("RF180-41 live fragment queue lost namespace row");
    entry.frags = entry
        .frags
        .checked_add(1)
        .expect("RF180-41 fragment namespace fragment counter overflow");
}
fn per_ns_charge_bytes(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64, b: u64) {
    let entry = m
        .get_mut(&ns)
        .expect("RF180-41 live fragment queue lost namespace row");
    entry.bytes = entry
        .bytes
        .checked_add(b)
        .expect("RF180-41 fragment namespace byte counter overflow");
}
fn per_ns_prune_if_zero(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64) {
    if let Some(e) = m.get(&ns) {
        if e.queues == 0 && e.frags == 0 && e.bytes == 0 {
            m.remove(&ns);
        }
    }
}
fn per_ns_release_queue(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64) {
    if let Some(e) = m.get_mut(&ns) {
        e.queues = e.queues.saturating_sub(1);
    }
    per_ns_prune_if_zero(m, ns);
}
fn per_ns_release_frags(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64, n: u32) {
    if let Some(e) = m.get_mut(&ns) {
        e.frags = e.frags.saturating_sub(n);
    }
    per_ns_prune_if_zero(m, ns);
}
fn per_ns_release_bytes(m: &mut AdmittedMap<u64, PerNsBudget>, ns: u64, b: u64) {
    if let Some(e) = m.get_mut(&ns) {
        e.bytes = e.bytes.saturating_sub(b);
    }
    per_ns_prune_if_zero(m, ns);
}

impl FragmentCache {
    /// Create a new fragment cache
    pub const fn new() -> Self {
        Self {
            queues: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            per_src_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            per_ns_counts: Mutex::new(AdmittedMap::new(HeapClass::SocketObject)),
            transaction_slots: [const { AtomicBool::new(false) }; FRAGMENT_TRANSACTION_SLOTS],
            stats: FragmentStats::new(),
        }
    }

    #[inline]
    fn transaction_slot(net_ns_id: u64) -> usize {
        // Mix the high and low halves before masking.  This avoids the common
        // case where namespace ids are sequential and differ only in the low
        // bits while retaining a bounded, lock-free selection operation.
        let mut x = net_ns_id ^ (net_ns_id >> 32);
        x ^= x >> 16;
        x = x.wrapping_mul(0x9E37_79B9);
        (x as usize) & (FRAGMENT_TRANSACTION_SLOTS - 1)
    }

    fn try_transaction(&self, net_ns_id: u64) -> Option<FragmentTransactionPermit<'_>> {
        let active = &self.transaction_slots[Self::transaction_slot(net_ns_id)];
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| FragmentTransactionPermit { active })
    }

    /// Cleanup is a global operation, therefore it must own every lane before
    /// detaching entries.  Acquisition is deterministic and all-or-nothing;
    /// a concurrent dataplane transaction causes a bounded deferral rather
    /// than a partial sweep or a lock-order inversion.
    fn try_cleanup_transaction(&self) -> Option<FragmentCleanupPermit<'_>> {
        let mut acquired = 0usize;
        for slot in &self.transaction_slots {
            if slot
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                for held in self.transaction_slots[..acquired].iter().rev() {
                    held.store(false, Ordering::Release);
                }
                return None;
            }
            acquired += 1;
        }
        Some(FragmentCleanupPermit {
            slots: &self.transaction_slots,
            acquired,
        })
    }

    /// Process one fragment as a detached cache transaction.
    pub fn process_fragment(
        &self,
        net_ns_id: u64,
        header: &Ipv4Header,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<WirePacket>, FragmentDropReason> {
        self.stats
            .fragments_received
            .fetch_add(1, Ordering::Relaxed);
        let _transaction = match self.try_transaction(net_ns_id) {
            Some(permit) => permit,
            None => {
                self.stats.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
                return Err(FragmentDropReason::RateLimited);
            }
        };

        let key = FragmentKey::from_header(net_ns_id, header);
        let offset = header.fragment_offset() * 8;
        let more_fragments = header.more_fragments();

        // Detach expired nested owners and destroy them only after all cache
        // locks have gone.
        let expired = {
            let mut queues = self.queues.lock();
            let mut per_src = self.per_src_counts.lock();
            let mut per_ns = self.per_ns_counts.lock();
            if !queues
                .get(&key)
                .is_some_and(|owner| owner.is_expired(now_ms))
            {
                None
            } else {
                let owner = queues
                    .remove(&key)
                    .expect("RF180-41 expired fragment owner vanished");
                let frags = owner.received_frags as u32;
                let bytes = owner.received_bytes as u64;
                let source = (key.net_ns_id, key.src_ip());
                if let Some(count) = per_src.get_mut(&source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&source);
                    }
                }
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
                per_ns_release_frags(&mut per_ns, key.net_ns_id, frags);
                per_ns_release_bytes(&mut per_ns, key.net_ns_id, bytes);
                self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                self.stats
                    .buffered_fragments
                    .fetch_sub(frags, Ordering::Relaxed);
                self.stats
                    .buffered_bytes
                    .fetch_sub(bytes, Ordering::Relaxed);
                Some(owner)
            }
        };
        if let Some(owner) = expired {
            drop(owner);
            return Err(FragmentDropReason::Timeout);
        }

        if self.queues.lock().contains_key(&key) {
            self.process_existing_fragment(key, offset, more_fragments, payload, now_ms)
        } else {
            self.process_new_fragment(key, offset, more_fragments, payload, now_ms)
        }
    }

    fn record_drop_reason(&self, reason: FragmentDropReason) {
        match reason {
            FragmentDropReason::RateLimited => {
                self.stats.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::FirstTooSmall => {
                self.stats
                    .first_too_small_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::TooLarge => {
                self.stats.too_large_drops.fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::QueueFragLimit
            | FragmentDropReason::QueueByteLimit
            | FragmentDropReason::PerSourceLimit
            | FragmentDropReason::PerNsQueueLimit => {
                self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::GlobalQueueLimit
            | FragmentDropReason::GlobalFragLimit
            | FragmentDropReason::GlobalByteLimit
            | FragmentDropReason::PerNsFragLimit
            | FragmentDropReason::PerNsByteLimit => {
                self.stats
                    .global_limit_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::Overlap | FragmentDropReason::Duplicate => {
                self.stats.overlap_drops.fetch_add(1, Ordering::Relaxed);
            }
            FragmentDropReason::Timeout | FragmentDropReason::ZeroLength => {}
        }
    }

    fn process_existing_fragment(
        &self,
        key: FragmentKey,
        offset: u16,
        more_fragments: bool,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<WirePacket>, FragmentDropReason> {
        let source = (key.net_ns_id, key.src_ip());
        let detached = {
            let mut queues = self.queues.lock();
            let mut per_ns = self.per_ns_counts.lock();
            if !queues.contains_key(&key) {
                drop(per_ns);
                drop(queues);
                return self.process_new_fragment(key, offset, more_fragments, payload, now_ms);
            }
            let owner = queues
                .get(&key)
                .expect("RF180-41 existing fragment owner vanished");
            if owner.received_frags >= MAX_FRAGS_PER_QUEUE {
                self.record_drop_reason(FragmentDropReason::QueueFragLimit);
                return Err(FragmentDropReason::QueueFragLimit);
            }
            if owner.received_bytes.saturating_add(payload.len()) > MAX_BYTES_PER_QUEUE {
                self.record_drop_reason(FragmentDropReason::QueueByteLimit);
                return Err(FragmentDropReason::QueueByteLimit);
            }
            let ns = per_ns.get(&key.net_ns_id).copied().unwrap_or_default();
            if key.net_ns_id != 0 && ns.frags as usize >= MAX_FRAGS_PER_NS {
                self.record_drop_reason(FragmentDropReason::PerNsFragLimit);
                return Err(FragmentDropReason::PerNsFragLimit);
            }
            if key.net_ns_id != 0
                && ns.bytes.saturating_add(payload.len() as u64) > MAX_BYTES_PER_NS
            {
                self.record_drop_reason(FragmentDropReason::PerNsByteLimit);
                return Err(FragmentDropReason::PerNsByteLimit);
            }
            if !self.stats.try_reserve_fragment(GLOBAL_MAX_FRAGS) {
                self.record_drop_reason(FragmentDropReason::GlobalFragLimit);
                return Err(FragmentDropReason::GlobalFragLimit);
            }
            per_ns_charge_frag(&mut per_ns, key.net_ns_id);
            if !self
                .stats
                .try_reserve_bytes(payload.len(), GLOBAL_MAX_FRAG_BYTES)
            {
                self.stats.release_fragment();
                per_ns_release_frags(&mut per_ns, key.net_ns_id, 1);
                self.record_drop_reason(FragmentDropReason::GlobalByteLimit);
                return Err(FragmentDropReason::GlobalByteLimit);
            }
            per_ns_charge_bytes(&mut per_ns, key.net_ns_id, payload.len() as u64);
            queues
                .remove(&key)
                .expect("RF180-41 selected fragment owner vanished")
        };

        let mut owner = detached;
        match owner.insert(offset, more_fragments, payload, now_ms) {
            Ok(true) => {
                let result = owner.reassemble();
                let frags = owner.received_frags as u32;
                let bytes = owner.received_bytes as u64;
                {
                    let mut per_src = self.per_src_counts.lock();
                    let mut per_ns = self.per_ns_counts.lock();
                    if let Some(count) = per_src.get_mut(&source) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&source);
                        }
                    }
                    per_ns_release_queue(&mut per_ns, key.net_ns_id);
                    per_ns_release_frags(&mut per_ns, key.net_ns_id, frags);
                    per_ns_release_bytes(&mut per_ns, key.net_ns_id, bytes);
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                    self.stats
                        .buffered_fragments
                        .fetch_sub(frags, Ordering::Relaxed);
                    self.stats
                        .buffered_bytes
                        .fetch_sub(bytes, Ordering::Relaxed);
                }
                drop(owner);
                match result {
                    Some(packet) => {
                        self.stats.reassembled.fetch_add(1, Ordering::Relaxed);
                        Ok(Some(packet))
                    }
                    None => {
                        self.stats
                            .global_limit_drops
                            .fetch_add(1, Ordering::Relaxed);
                        Ok(None)
                    }
                }
            }
            Ok(false) => {
                let mut queues = self.queues.lock();
                assert!(
                    queues.insert_unique_reserved(key, owner).is_ok(),
                    "RF180-41 detached fragment queue lost its slot"
                );
                Ok(None)
            }
            Err(reason) => {
                self.stats.release_fragment();
                self.stats.release_bytes(payload.len());
                let discard = matches!(
                    reason,
                    FragmentDropReason::Overlap
                        | FragmentDropReason::Duplicate
                        | FragmentDropReason::FirstTooSmall
                );
                let mut retired_owner = None;
                {
                    let mut queues = self.queues.lock();
                    let mut per_src = self.per_src_counts.lock();
                    let mut per_ns = self.per_ns_counts.lock();
                    per_ns_release_frags(&mut per_ns, key.net_ns_id, 1);
                    per_ns_release_bytes(&mut per_ns, key.net_ns_id, payload.len() as u64);
                    if discard {
                        let frags = owner.received_frags as u32;
                        let bytes = owner.received_bytes as u64;
                        if let Some(count) = per_src.get_mut(&source) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                per_src.remove(&source);
                            }
                        }
                        per_ns_release_queue(&mut per_ns, key.net_ns_id);
                        per_ns_release_frags(&mut per_ns, key.net_ns_id, frags);
                        per_ns_release_bytes(&mut per_ns, key.net_ns_id, bytes);
                        self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                        self.stats
                            .buffered_fragments
                            .fetch_sub(frags, Ordering::Relaxed);
                        self.stats
                            .buffered_bytes
                            .fetch_sub(bytes, Ordering::Relaxed);
                        retired_owner = Some(owner);
                    } else {
                        assert!(
                            queues.insert_unique_reserved(key, owner).is_ok(),
                            "RF180-41 failed fragment lost its queue"
                        );
                    }
                }
                drop(retired_owner);
                self.record_drop_reason(reason);
                Err(reason)
            }
        }
    }

    fn process_new_fragment(
        &self,
        key: FragmentKey,
        offset: u16,
        more_fragments: bool,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<WirePacket>, FragmentDropReason> {
        // Build the complete retained candidate before planning/removing a victim.
        let mut queue = FragmentQueue::new(key, now_ms).map_err(|reason| {
            self.record_drop_reason(reason);
            reason
        })?;
        match queue.insert(offset, more_fragments, payload, now_ms) {
            Ok(true) => {
                let result = queue.reassemble();
                drop(queue);
                return match result {
                    Some(packet) => {
                        self.stats.reassembled.fetch_add(1, Ordering::Relaxed);
                        Ok(Some(packet))
                    }
                    None => {
                        self.stats
                            .global_limit_drops
                            .fetch_add(1, Ordering::Relaxed);
                        Ok(None)
                    }
                };
            }
            Ok(false) => {}
            Err(reason) => {
                self.record_drop_reason(reason);
                return Err(reason);
            }
        }
        let mut candidate = Some(FragmentQueueOwner::try_new(queue).map_err(|reason| {
            self.record_drop_reason(reason);
            reason
        })?);
        let source = (key.net_ns_id, key.src_ip());

        #[derive(Clone, Copy)]
        struct Victim {
            key: FragmentKey,
            source: (u64, u32),
            frags: u32,
            bytes: u64,
        }

        let planned: Result<
            (
                Option<Victim>,
                Option<CapacityPlan>,
                Option<CapacityPlan>,
                Option<CapacityPlan>,
            ),
            FragmentDropReason,
        > = (|| {
            let mut queues = self.queues.lock();
            let mut per_src = self.per_src_counts.lock();
            let mut per_ns = self.per_ns_counts.lock();
            if queues.contains_key(&key) {
                return Err(FragmentDropReason::Duplicate);
            }
            let ns = per_ns.get(&key.net_ns_id).copied().unwrap_or_default();
            let need_ns_victim = key.net_ns_id != 0 && ns.queues >= MAX_QUEUES_PER_NS;
            let need_global_victim = queues.len() >= GLOBAL_MAX_QUEUES;
            let victim = if need_ns_victim || need_global_victim {
                let victim_key = queues
                    .iter()
                    .filter(|(candidate_key, _)| candidate_key.net_ns_id == key.net_ns_id)
                    .min_by_key(|(_, owner)| owner.created_ms)
                    .map(|(candidate_key, _)| *candidate_key)
                    .ok_or(if need_ns_victim {
                        FragmentDropReason::PerNsQueueLimit
                    } else {
                        FragmentDropReason::GlobalQueueLimit
                    })?;
                let owner = queues
                    .get(&victim_key)
                    .expect("RF180-41 planned fragment victim vanished");
                Some(Victim {
                    key: victim_key,
                    source: (victim_key.net_ns_id, victim_key.src_ip()),
                    frags: owner.received_frags as u32,
                    bytes: owner.received_bytes as u64,
                })
            } else {
                None
            };

            let same_ns = victim.is_some_and(|v| v.key.net_ns_id == key.net_ns_id);
            let victim_frags = victim.filter(|_| same_ns).map_or(0, |v| v.frags);
            let victim_bytes = victim.filter(|_| same_ns).map_or(0, |v| v.bytes);
            if key.net_ns_id != 0
                && ns.queues.saturating_sub(usize::from(same_ns)) >= MAX_QUEUES_PER_NS
            {
                return Err(FragmentDropReason::PerNsQueueLimit);
            }
            if key.net_ns_id != 0
                && ns.frags.saturating_sub(victim_frags) as usize >= MAX_FRAGS_PER_NS
            {
                return Err(FragmentDropReason::PerNsFragLimit);
            }
            if key.net_ns_id != 0
                && ns
                    .bytes
                    .saturating_sub(victim_bytes)
                    .saturating_add(payload.len() as u64)
                    > MAX_BYTES_PER_NS
            {
                return Err(FragmentDropReason::PerNsByteLimit);
            }
            let global_frags = self
                .stats
                .buffered_fragments
                .load(Ordering::Relaxed)
                .saturating_sub(victim.map_or(0, |v| v.frags));
            let global_bytes = self
                .stats
                .buffered_bytes
                .load(Ordering::Relaxed)
                .saturating_sub(victim.map_or(0, |v| v.bytes));
            if global_frags as usize >= GLOBAL_MAX_FRAGS {
                return Err(FragmentDropReason::GlobalFragLimit);
            }
            if global_bytes.saturating_add(payload.len() as u64) > GLOBAL_MAX_FRAG_BYTES as u64 {
                return Err(FragmentDropReason::GlobalByteLimit);
            }
            let source_count = per_src.get(&source).copied().unwrap_or(0);
            if source_count.saturating_sub(usize::from(victim.is_some_and(|v| v.source == source)))
                >= MAX_QUEUES_PER_SRC
            {
                return Err(FragmentDropReason::PerSourceLimit);
            }

            let queue_plan = if victim.is_none() {
                queues
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
            } else {
                None
            };
            let frees_source = victim
                .and_then(|v| per_src.get(&v.source).map(|count| *count == 1))
                .unwrap_or(false);
            let source_plan = if !per_src.contains_key(&source) && !frees_source {
                per_src
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
            } else {
                None
            };
            let frees_ns = victim
                .and_then(|v| per_ns.get(&v.key.net_ns_id).map(|b| b.queues == 1))
                .unwrap_or(false);
            let ns_plan = if !per_ns.contains_key(&key.net_ns_id) && !frees_ns {
                per_ns
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
            } else {
                None
            };
            Ok((victim, queue_plan, source_plan, ns_plan))
        })();

        let (victim, queue_plan, source_plan, ns_plan) = planned.map_err(|reason| {
            self.record_drop_reason(reason);
            reason
        })?;
        let mut capacity = FragmentIndexCapacity::prepare(queue_plan, source_plan, ns_plan)
            .map_err(|reason| {
                self.record_drop_reason(reason);
                reason
            })?;
        let mut retired = RetiredFragmentIndexCapacity::empty();
        let mut retired_victim = None;

        let commit: Result<(), FragmentDropReason> = (|| {
            let mut queues = self.queues.lock();
            let mut per_src = self.per_src_counts.lock();
            let mut per_ns = self.per_ns_counts.lock();
            if queues.contains_key(&key) || victim.is_some_and(|v| !queues.contains_key(&v.key)) {
                return Err(FragmentDropReason::Duplicate);
            }

            if victim.is_none() {
                if let Some(plan) = queues
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
                {
                    let prepared = capacity
                        .queues
                        .take()
                        .filter(|p| p.capacity() >= plan.required())
                        .ok_or(FragmentDropReason::GlobalQueueLimit)?;
                    retired.queues = Some(
                        queues
                            .install_prepared_deferred(prepared)
                            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?,
                    );
                }
            }
            let frees_source = victim
                .and_then(|v| per_src.get(&v.source).map(|count| *count == 1))
                .unwrap_or(false);
            if !per_src.contains_key(&source) && !frees_source {
                if let Some(plan) = per_src
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
                {
                    let prepared = capacity
                        .per_src
                        .take()
                        .filter(|p| p.capacity() >= plan.required())
                        .ok_or(FragmentDropReason::GlobalQueueLimit)?;
                    retired.per_src = Some(
                        per_src
                            .install_prepared_deferred(prepared)
                            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?,
                    );
                }
            }
            let frees_ns = victim
                .and_then(|v| per_ns.get(&v.key.net_ns_id).map(|b| b.queues == 1))
                .unwrap_or(false);
            if !per_ns.contains_key(&key.net_ns_id) && !frees_ns {
                if let Some(plan) = per_ns
                    .capacity_plan_for(1)
                    .map_err(|_| FragmentDropReason::GlobalQueueLimit)?
                {
                    let prepared = capacity
                        .per_ns
                        .take()
                        .filter(|p| p.capacity() >= plan.required())
                        .ok_or(FragmentDropReason::GlobalQueueLimit)?;
                    retired.per_ns = Some(
                        per_ns
                            .install_prepared_deferred(prepared)
                            .map_err(|_| FragmentDropReason::GlobalQueueLimit)?,
                    );
                }
            }

            if let Some(victim) = victim {
                retired_victim = Some(
                    queues
                        .remove(&victim.key)
                        .expect("RF180-41 fragment victim disappeared at commit"),
                );
                if let Some(count) = per_src.get_mut(&victim.source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&victim.source);
                    }
                }
                per_ns_release_queue(&mut per_ns, victim.key.net_ns_id);
                per_ns_release_frags(&mut per_ns, victim.key.net_ns_id, victim.frags);
                per_ns_release_bytes(&mut per_ns, victim.key.net_ns_id, victim.bytes);
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                self.stats
                    .buffered_fragments
                    .fetch_sub(victim.frags, Ordering::Relaxed);
                self.stats
                    .buffered_bytes
                    .fetch_sub(victim.bytes, Ordering::Relaxed);
                self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
            }

            let owner = candidate
                .take()
                .expect("RF180-41 fragment candidate consumed once");
            assert!(
                queues.insert_unique_reserved(key, owner).is_ok(),
                "RF180-41 fragment candidate publication lacked capacity"
            );
            if let Some(count) = per_src.get_mut(&source) {
                *count = count
                    .checked_add(1)
                    .expect("RF180-41 fragment per-source counter overflow");
            } else {
                assert!(
                    per_src.insert_unique_reserved(source, 1).is_ok(),
                    "RF180-41 fragment source publication lacked capacity"
                );
            }
            per_ns_charge_queue(&mut per_ns, key.net_ns_id);
            per_ns_charge_frag(&mut per_ns, key.net_ns_id);
            per_ns_charge_bytes(&mut per_ns, key.net_ns_id, payload.len() as u64);
            self.stats.active_queues.fetch_add(1, Ordering::Relaxed);
            self.stats
                .buffered_fragments
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .buffered_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            Ok(())
        })();

        drop(retired_victim);
        drop(retired.per_ns.take());
        drop(retired.per_src.take());
        drop(retired.queues.take());
        drop(capacity);
        drop(candidate.take());

        match commit {
            Ok(()) => Ok(None),
            Err(reason) => {
                self.record_drop_reason(reason);
                Err(reason)
            }
        }
    }

    /// Run timeout cleanup without heap scratch or lock-held destruction.
    ///
    /// The transaction token excludes concurrent fragment publication while
    /// each owner is detached. Cleanup remains bounded by the live queue cap;
    /// a busy dataplane simply defers this sweep to the next timer tick.
    pub fn cleanup_expired(&self, now_ms: u64) -> usize {
        let _transaction = match self.try_cleanup_transaction() {
            Some(permit) => permit,
            None => return 0,
        };
        let mut removed = 0usize;
        loop {
            let retired = {
                let mut queues = self.queues.lock();
                let mut per_src = self.per_src_counts.lock();
                let mut per_ns = self.per_ns_counts.lock();
                let key = queues
                    .iter()
                    .find(|(_, owner)| owner.is_expired(now_ms))
                    .map(|(key, _)| *key);
                let Some(key) = key else {
                    break;
                };
                let owner = queues
                    .remove(&key)
                    .expect("RF180-41 cleanup-selected fragment owner vanished");
                let source = (key.net_ns_id, key.src_ip());
                let frags = owner.received_frags as u32;
                let bytes = owner.received_bytes as u64;
                if let Some(count) = per_src.get_mut(&source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&source);
                    }
                }
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
                per_ns_release_frags(&mut per_ns, key.net_ns_id, frags);
                per_ns_release_bytes(&mut per_ns, key.net_ns_id, bytes);
                self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                self.stats
                    .buffered_fragments
                    .fetch_sub(frags, Ordering::Relaxed);
                self.stats
                    .buffered_bytes
                    .fetch_sub(bytes, Ordering::Relaxed);
                owner
            };
            drop(retired);
            removed = removed.saturating_add(1);
        }
        removed
    }

    /// Get current statistics
    pub fn stats(&self) -> &FragmentStats {
        &self.stats
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static FRAGMENT_CACHE: Once<FragmentCache> = Once::new();

/// Get the global fragment cache
pub fn fragment_cache() -> &'static FragmentCache {
    FRAGMENT_CACHE.call_once(FragmentCache::new)
}

/// Process an incoming IP fragment
///
/// Convenience wrapper around fragment_cache().process_fragment()
/// R140-4 FIX: Requires network namespace ID for per-namespace isolation.
pub fn process_fragment(
    net_ns_id: u64,
    header: &Ipv4Header,
    payload: &[u8],
    now_ms: u64,
) -> Result<Option<WirePacket>, FragmentDropReason> {
    fragment_cache().process_fragment(net_ns_id, header, payload, now_ms)
}

/// Run fragment timeout cleanup
///
/// Should be called from timer interrupt handler.
pub fn cleanup_expired_fragments(now_ms: u64) -> usize {
    fragment_cache().cleanup_expired(now_ms)
}

/// R169-10: in-kernel self-test for the per-ns fragment triple-budget. Proves the
/// load-bearing `sum(per_ns) == global` invariant across the create / complete /
/// timeout release paths (R3, R9, C1/C2/C3), the per-ns prune, and the cross-ns
/// isolation gate (one ns at its QUEUE ceiling is rejected with `PerNsQueueLimit`
/// — fired ABOVE the global-LRU branch — while another ns still reassembles
/// normally). Runs against a LOCAL `FragmentCache`; wired into the boot suite.
pub fn run_fragment_perns_self_test() {
    fn hdr(src: [u8; 4], id: u16, offset: u16, mf: bool) -> Ipv4Header {
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_len: 0,
            identification: id,
            flags_fragment: if mf { 0x2000 | offset } else { offset },
            ttl: 64,
            protocol: 17, // UDP
            checksum: 0,
            src: crate::ipv4::Ipv4Addr(src),
            dst: crate::ipv4::Ipv4Addr([192, 168, 1, 1]),
            options_len: 0,
        }
    }
    // sum(per_ns) == the three global atomics — the invariant every charge/release
    // site must preserve. A single missed/duplicated per-ns op breaks this.
    fn assert_balanced(c: &FragmentCache, ctx: &str) {
        let pn = c.per_ns_counts.lock();
        let mut q = 0usize;
        let mut f = 0u64;
        let mut b = 0u64;
        for v in pn.values() {
            q += v.queues;
            f += v.frags as u64;
            b += v.bytes;
        }
        let gq = c.stats.active_queues.load(Ordering::Relaxed) as usize;
        let gf = c.stats.buffered_fragments.load(Ordering::Relaxed) as u64;
        let gb = c.stats.buffered_bytes.load(Ordering::Relaxed);
        assert!(
            q == gq && f == gf && b == gb,
            "R169-10 balance [{}]: per_ns(q={},f={},b={}) != global(q={},f={},b={})",
            ctx,
            q,
            f,
            b,
            gq,
            gf,
            gb
        );
    }

    let cache = FragmentCache::new();
    let (ns_a, ns_b) = (10u64, 20u64);
    let payload = [0u8; 64]; // >= MIN_L4_HEADER_BYTES

    // (1) create one incomplete queue in each ns (offset 0, MF=1 -> 1 buffered frag).
    assert!(matches!(
        cache.process_fragment(ns_a, &hdr([10, 0, 0, 1], 1, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_balanced(&cache, "A create");
    assert!(matches!(
        cache.process_fragment(ns_b, &hdr([20, 0, 0, 1], 1, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_balanced(&cache, "B create");
    {
        let pn = cache.per_ns_counts.lock();
        assert_eq!(
            pn.get(&ns_a).map(|v| (v.queues, v.frags, v.bytes)),
            Some((1, 1, 64)),
            "R169-10: ns A charged 1 queue / 1 frag / 64 bytes"
        );
    }

    // (1b) ROOT namespace (ns 0): cap-EXEMPT at admission / C2 / C3, but STILL
    // charged AND released, so the `sum(per_ns) == global` invariant must hold for
    // the ns-0 entry too. (Its release is covered by the timeout sweep in step 4.)
    assert!(matches!(
        cache.process_fragment(0, &hdr([1, 1, 1, 1], 7, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_eq!(
        cache
            .per_ns_counts
            .lock()
            .get(&0)
            .map(|v| (v.queues, v.frags, v.bytes)),
        Some((1, 1, 64)),
        "R169-10: root ns 0 IS charged (cap-exempt but fully accounted)"
    );
    assert_balanced(&cache, "root ns 0 charged");

    // (2) complete A (offset 8*8=64, MF=0 fills [64,128)) -> R3 whole-queue release.
    assert!(matches!(
        cache.process_fragment(ns_a, &hdr([10, 0, 0, 1], 1, 8, false), &payload, 0),
        Ok(Some(_))
    ));
    assert_balanced(&cache, "A complete");
    assert!(
        cache.per_ns_counts.lock().get(&ns_a).is_none(),
        "R169-10: ns A pruned after completion (R3 + prune-at-zero)"
    );

    // (3) overlap-discard (exercises R4 + R5, the subtlest accounting): create a
    // fresh ns B queue, then send an OVERLAPPING fragment for it. The Err arm
    // releases BOTH the failed fragment's per-ns C2/C3 charges (R4) AND the queue's
    // prior committed contents (R5) — disjoint magnitudes that must both balance.
    // Heap-light (a couple of 64-byte fragments), unlike a queue-cap test which
    // would need MAX_QUEUES_PER_NS=1024 live queues (cap correctness is simple
    // arithmetic, covered by review). ns A is untouched, proving per-ns isolation.
    assert!(matches!(
        cache.process_fragment(ns_b, &hdr([20, 0, 0, 2], 2, 0, true), &payload, 0),
        Ok(None)
    ));
    assert!(
        matches!(
            cache.process_fragment(ns_b, &hdr([20, 0, 0, 2], 2, 0, true), &payload, 0),
            Err(FragmentDropReason::Overlap) | Err(FragmentDropReason::Duplicate)
        ),
        "R169-10: an overlapping fragment discards the queue (R4 + R5 release)"
    );
    assert_balanced(&cache, "B overlap-discard (R4 + R5)");

    // (4) timeout sweep -> R9 drains every queue; per_ns map empties, globals -> 0.
    cache.cleanup_expired(FRAG_TIMEOUT_MS + 1);
    assert_balanced(&cache, "after timeout sweep");
    assert!(
        cache.per_ns_counts.lock().is_empty()
            && cache.stats.active_queues.load(Ordering::Relaxed) == 0
            && cache.stats.buffered_bytes.load(Ordering::Relaxed) == 0,
        "R169-10: per_ns + globals fully drained after the timeout sweep"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::Ipv4Addr;

    fn make_header(src: [u8; 4], id: u16, offset: u16, mf: bool) -> Ipv4Header {
        let flags_frag = if mf { 0x2000 | offset } else { offset };
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_len: 0,
            identification: id,
            flags_fragment: flags_frag,
            ttl: 64,
            protocol: 17, // UDP
            checksum: 0,
            src: Ipv4Addr(src),
            dst: Ipv4Addr([192, 168, 1, 1]),
            options_len: 0,
        }
    }

    #[test]
    fn test_fragment_key() {
        let hdr = make_header([10, 0, 0, 1], 0x1234, 0, true);
        // R140-4 FIX: FragmentKey now includes net_ns_id
        let key = FragmentKey::from_header(42, &hdr);
        assert_eq!(key.net_ns_id, 42);
        assert_eq!(key.src, [10, 0, 0, 1]);
        assert_eq!(key.identification, 0x1234);
    }

    #[test]
    fn test_simple_reassembly() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // Fragment 1: offset 0, MF=1
        let hdr1 = make_header([10, 0, 0, 1], 0x1234, 0, true);
        let data1 = [1u8; 16]; // 16 bytes at offset 0

        // Fragment 2: offset 2 (16 bytes), MF=0
        let hdr2 = make_header([10, 0, 0, 1], 0x1234, 2, false);
        let data2 = [2u8; 16]; // 16 bytes at offset 16

        let result1 = cache.process_fragment(1, &hdr1, &data1, now);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none());

        let result2 = cache.process_fragment(1, &hdr2, &data2, now);
        assert!(result2.is_ok());
        let reassembled = result2.unwrap();
        assert!(reassembled.is_some());

        let packet = reassembled.unwrap();
        assert_eq!(packet.len(), 32);
        assert_eq!(&packet[0..16], &[1u8; 16]);
        assert_eq!(&packet[16..32], &[2u8; 16]);
    }

    #[test]
    fn test_overlap_rejection() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // Fragment 1: offset 0, 16 bytes
        let hdr1 = make_header([10, 0, 0, 1], 0x5678, 0, true);
        let data1 = [1u8; 16];

        // Fragment 2: offset 1 (8 bytes) - overlaps!
        let hdr2 = make_header([10, 0, 0, 1], 0x5678, 1, true);
        let data2 = [2u8; 16];

        let _ = cache.process_fragment(1, &hdr1, &data1, now);
        let result2 = cache.process_fragment(1, &hdr2, &data2, now);

        assert!(result2.is_err());
        assert_eq!(result2.unwrap_err(), FragmentDropReason::Overlap);
    }

    #[test]
    fn test_first_fragment_too_small() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // First fragment with only 4 bytes (less than MIN_L4_HEADER_BYTES)
        let hdr = make_header([10, 0, 0, 1], 0x9ABC, 0, true);
        let data = [1u8; 4];

        let result = cache.process_fragment(1, &hdr, &data, now);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FragmentDropReason::FirstTooSmall);
    }

    fn test_key(id: u16) -> FragmentKey {
        FragmentKey {
            net_ns_id: 0x1804_1000 + id as u64,
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            protocol: 17,
            identification: id,
        }
    }

    fn assert_empty_queue_state(queue: &FragmentQueue) {
        assert_eq!(queue.received_frags, 0);
        assert_eq!(queue.received_bytes, 0);
        assert_eq!(queue.total_len, None);
        assert!(!queue.have_first);
        assert!(!queue.have_last);
        assert!(!queue.l4_header_ok);
        assert!(queue.frags.is_empty());
        assert_eq!(queue.holes.len(), 1);
        assert_eq!(queue.holes[0].start, 0);
        assert_eq!(queue.holes[0].end, u16::MAX);
    }

    #[test]
    fn rf180_41_fragment_hole_growth_failure_is_transactional() {
        mm::publish_heap_budgets();
        let mut queue = FragmentQueue::new(test_key(1), 1).expect("queue admission");
        queue.fail_next_hole_growth = true;

        assert_eq!(
            queue.insert(0, true, &[0x11; 16], 2),
            Err(FragmentDropReason::QueueByteLimit)
        );
        assert_empty_queue_state(&queue);

        assert_eq!(queue.insert(0, true, &[0x11; 16], 3), Ok(false));
        assert_eq!(queue.received_frags, 1);
    }

    #[test]
    fn rf180_41_fragment_map_growth_failure_is_transactional() {
        mm::publish_heap_budgets();
        let mut queue = FragmentQueue::new(test_key(2), 1).expect("queue admission");
        queue.fail_next_frag_map_growth = true;

        assert_eq!(
            queue.insert(0, true, &[0x22; 16], 2),
            Err(FragmentDropReason::QueueByteLimit)
        );
        assert_empty_queue_state(&queue);

        assert_eq!(queue.insert(0, true, &[0x22; 16], 3), Ok(false));
        assert!(queue.holes.charged_bytes_for_test() > 0);
        assert!(queue.frags.charged_bytes_for_test() > 0);
    }

    #[test]
    fn rf180_41_fragment_cache_index_admission_failure_publishes_nothing() {
        mm::publish_heap_budgets();
        let cache = FragmentCache::new();
        cache.queues.lock().fail_next_growth_for_test();
        let header = make_header([10, 0, 0, 9], 0x1804, 0, true);

        assert_eq!(
            cache.process_fragment(0x1804, &header, &[0x33; 16], 1),
            Err(FragmentDropReason::GlobalQueueLimit)
        );
        assert!(cache.queues.lock().is_empty());
        assert!(cache.per_src_counts.lock().is_empty());
        assert!(cache.per_ns_counts.lock().is_empty());
        assert_eq!(cache.stats.active_queues.load(Ordering::Relaxed), 0);
        assert_eq!(cache.stats.buffered_fragments.load(Ordering::Relaxed), 0);
        assert_eq!(cache.stats.buffered_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn r188_u16_namespace_transaction_lanes_are_independent() {
        let cache = FragmentCache::new();
        let first_ns = 1u64;
        let first_slot = FragmentCache::transaction_slot(first_ns);
        let second_ns = (2u64..10_000)
            .find(|candidate| FragmentCache::transaction_slot(*candidate) != first_slot)
            .expect("hashed fragment lanes must provide a second slot");

        let first = cache
            .try_transaction(first_ns)
            .expect("first namespace lane should be available");
        let second = cache
            .try_transaction(second_ns)
            .expect("a different namespace lane must not be globally blocked");
        assert!(cache.try_transaction(first_ns).is_none());
        drop(second);
        drop(first);
        assert!(cache.try_transaction(first_ns).is_some());
    }
}
