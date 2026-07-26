//! Network protocol stack for Zero-OS (Phase D.2)
//!
//! This module provides the main packet processing loop that integrates
//! all protocol layers (Ethernet, IPv4, ICMP).
//!
//! # Architecture
//!
//! ```text
//!                     +------------------+
//!                     |   NetDevice      |
//!                     | (virtio-net)     |
//!                     +--------+---------+
//!                              |
//!                     +--------v---------+
//!                     |   Ethernet       |
//!                     |   (parse/build)  |
//!                     +--------+---------+
//!                              |
//!              +---------------+---------------+
//!              |                               |
//!     +--------v---------+           +---------v--------+
//!     |     IPv4         |           |      ARP         |
//!     | (validate/route) |           |  (cache/reply)   |
//!     +--------+---------+           +------------------+
//!              |
//!     +--------v---------+
//!     |     ICMP         |
//!     |  (echo reply)    |
//!     +------------------+
//! ```
//!
//! # Security
//!
//! - All packet parsing uses strict validation
//! - ICMP responses are rate-limited
//! - Source routing is rejected
//! - Broadcast/multicast sources are rejected

use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::arp::{process_arp, ArpCache, ArpEntryKind, ArpError, ArpResult, ArpStats};
use crate::buffer::NetBuf;
use crate::device::TxError;
use crate::ethernet::{
    build_ethernet_frame_from_parts, parse_ethernet, try_build_ethernet_frame_from_parts, EthAddr,
    EthHeader, ETHERTYPE_ARP, ETHERTYPE_IPV4,
};
use crate::firewall::{firewall_table_for_ns, FirewallAction, FirewallPacket, FirewallVerdict};
use crate::fragment::{
    cleanup_expired_fragments, process_fragment as reassemble_fragment, FragmentDropReason,
};
use crate::icmp::{
    build_dest_unreachable, build_echo_reply, parse_icmp, IcmpError, ICMP_RATE_LIMITER,
    ICMP_TYPE_ECHO_REQUEST,
};
use crate::ipv4::{
    build_ipv4_header, compute_checksum, parse_ipv4, Ipv4Addr, Ipv4Error, Ipv4Header, Ipv4Proto,
    IPV4_HEADER_MIN_LEN,
};
use crate::socket::{socket_table, TcpConnectResult, TcpReplyBinding};
use crate::tcp::{
    build_tcp_segment, parse_tcp_header, parse_tcp_options, verify_tcp_checksum, TcpError,
    TcpHeader, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_HEADER_MIN_LEN,
};
use crate::udp::{parse_udp, parse_udp_header, UdpError, UdpHeader, UdpStats, UDP_HEADER_LEN};
use crate::WirePacket;
use crate::DEFAULT_MTU;
use cap::NamespaceId;
use mm::dma::{alloc_dma_buffer, DMA_PAGE_SIZE};

// ============================================================================
// Statistics
// ============================================================================

/// Network stack statistics
#[derive(Debug, Default)]
pub struct NetStats {
    /// Total packets received
    pub rx_packets: AtomicU64,
    /// Packets dropped due to parsing errors
    pub rx_errors: AtomicU64,
    /// IPv4 packets received
    pub ipv4_rx: AtomicU64,
    /// ICMP packets received
    pub icmp_rx: AtomicU64,
    /// ICMP echo requests received
    pub icmp_echo_rx: AtomicU64,
    /// ICMP echo replies sent
    pub icmp_echo_tx: AtomicU64,
    /// Packets dropped by rate limiter
    pub rate_limited: AtomicU64,
    /// Packets dropped due to unsupported protocol
    pub unsupported_proto: AtomicU64,
    /// IP fragments received
    pub fragments_rx: AtomicU64,
    /// Successfully reassembled datagrams
    pub fragments_reassembled: AtomicU64,
    /// Fragments dropped (security limits, overlap, etc.)
    pub fragments_dropped: AtomicU64,
    /// ARP statistics
    pub arp_stats: ArpStats,
    /// UDP statistics
    pub udp_stats: UdpStats,
}

impl NetStats {
    /// Create new stats counter
    pub const fn new() -> Self {
        NetStats {
            rx_packets: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            ipv4_rx: AtomicU64::new(0),
            icmp_rx: AtomicU64::new(0),
            icmp_echo_rx: AtomicU64::new(0),
            icmp_echo_tx: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            unsupported_proto: AtomicU64::new(0),
            fragments_rx: AtomicU64::new(0),
            fragments_reassembled: AtomicU64::new(0),
            fragments_dropped: AtomicU64::new(0),
            arp_stats: ArpStats::new(),
            udp_stats: UdpStats::new(),
        }
    }

    #[inline]
    fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_ipv4_rx(&self) {
        self.ipv4_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_rx(&self) {
        self.icmp_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_rx(&self) {
        self.icmp_echo_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_tx(&self) {
        self.icmp_echo_tx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_unsupported_proto(&self) {
        self.unsupported_proto.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_rx(&self) {
        self.fragments_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_reassembled(&self) {
        self.fragments_reassembled.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_dropped(&self) {
        self.fragments_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Packet Processing Result
// ============================================================================

/// A complete ingress-generated frame whose policy decision and conntrack
/// publication remain bound to the eventual device-queue operation.
///
/// The type is intentionally non-cloneable and does not expose its owned
/// `WirePacket`. Callers may inspect the bytes, but must consume the owner with
/// [`transmit_prepared_reply`] to obtain the queue/conntrack transaction.
pub struct PreparedReply {
    frame: WirePacket,
    tx_context: Option<u64>,
    tcp_binding: Option<TcpReplyBinding>,
    stat: PreparedReplyStat,
    reject_count: u8,
    retry_not_before_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedReplyStat {
    None,
    ArpReply,
    IcmpEcho,
}

impl PreparedReply {
    fn new(frame: WirePacket) -> Self {
        Self {
            frame,
            tx_context: None,
            tcp_binding: None,
            stat: PreparedReplyStat::None,
            reject_count: 0,
            retry_not_before_ms: 0,
        }
    }

    fn bind_tcp(&mut self, binding: Option<TcpReplyBinding>) {
        self.tcp_binding = binding;
    }

    fn with_stat(mut self, stat: PreparedReplyStat) -> Self {
        self.stat = stat;
        self
    }

    fn commit_stat(&self, stats: &NetStats) {
        match self.stat {
            PreparedReplyStat::None => {}
            PreparedReplyStat::ArpReply => stats.arp_stats.inc_tx_replies(),
            PreparedReplyStat::IcmpEcho => stats.inc_icmp_echo_tx(),
        }
    }

    fn note_queue_rejection(&mut self, now_ms: u64) {
        const BASE_MS: u64 = 10;
        const MAX_MS: u64 = 1_000;
        self.reject_count = self.reject_count.saturating_add(1);
        let shift = self.reject_count.saturating_sub(1).min(7) as u32;
        let delay = BASE_MS.checked_shl(shift).unwrap_or(MAX_MS).min(MAX_MS);
        self.retry_not_before_ms = now_ms.saturating_add(delay);
    }

    fn authorize(&mut self, net_ns_id: u64, _now_ms: u64) {
        self.tx_context = Some(net_ns_id);
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.frame.as_slice()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.frame.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.frame.is_empty()
    }
}

impl core::ops::Deref for PreparedReply {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for PreparedReply {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::fmt::Debug for PreparedReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedReply")
            .field("frame", &self.frame)
            .field("authorized", &self.tx_context.is_some())
            .field("tcp_binding", &self.tcp_binding)
            .field("stat", &self.stat)
            .field("reject_count", &self.reject_count)
            .field("retry_not_before_ms", &self.retry_not_before_ms)
            .finish()
    }
}

#[derive(Debug)]
pub enum PreparedReplyTxError {
    /// Nothing reached the device; the exact admitted owner remains retryable.
    Retryable(TxError, PreparedReply),
    /// The device accepted the packet (or the transaction invariant was lost),
    /// so returning the owner would permit an unsafe duplicate transmission.
    Consumed(TxError),
}

/// Result of processing an incoming packet
#[derive(Debug)]
pub enum ProcessResult {
    /// Packet was handled, no response needed
    Handled,
    /// Packet requires a response to be sent
    Reply(PreparedReply),
    /// Packet was dropped with reason
    Dropped(DropReason),
}

/// Reason for dropping a packet
#[derive(Debug, Clone, Copy)]
pub enum DropReason {
    /// Ethernet frame parsing failed
    EthParseError,
    /// IPv4 parsing/validation failed
    Ipv4Error(Ipv4Error),
    /// ICMP parsing failed
    IcmpError(IcmpError),
    /// ARP processing error
    ArpError(ArpError),
    /// UDP processing error
    UdpError(UdpError),
    /// TCP processing error
    TcpError(TcpError),
    /// Fragment reassembly error
    FragmentError(FragmentDropReason),
    /// Unsupported EtherType
    UnsupportedEtherType,
    /// Unsupported IP protocol
    UnsupportedProtocol,
    /// Rate limited
    RateLimited,
    /// RF178-7 FIX: Conntrack metadata admission failed.
    ConntrackExhausted,
    /// A socket-accepted handshake could not finalize its exact conntrack flow.
    ConntrackInvalid,
    /// D3-NETNS-DATAPLANE: RX namespace is unknown/destroyed (or the kernel
    /// namespace hooks are not registered yet), so no per-namespace ARP cache
    /// exists to process the frame against. Fail-closed drop.
    NetNsUnavailable,
    /// Dropped by firewall
    Firewall {
        rule_id: Option<u32>,
        rejected: bool,
    },
}

// ============================================================================
// Packet Handler
// ============================================================================

/// Process an incoming Ethernet frame.
///
/// This is the main entry point for packet processing. It:
/// 1. Parses the Ethernet header
/// 2. Validates the frame is addressed to us (unicast or broadcast)
/// 3. Routes to the appropriate protocol handler (IPv4, ARP, etc.)
/// 4. Returns any response packet that should be sent
///
/// # Security
///
/// - Only processes frames addressed to our MAC or broadcast
/// - Silently drops frames to other destinations (no error logged)
/// - R90-2 FIX: Network namespace ID is threaded from the receiving device
///   to socket delivery, ensuring namespace isolation for ingress traffic.
///
/// # Arguments
/// * `frame` - Raw Ethernet frame bytes
/// * `our_mac` - Our MAC address (for filtering and responses)
/// * `our_ip` - Our IP address (for filtering and responses)
/// * `stats` - Statistics counters
/// * `net_ns_id` - Network namespace of the receiving device
/// * `now_ms` - Current time in milliseconds (for rate limiting)
///
/// # Returns
/// `ProcessResult` indicating what action to take
///
/// # D3 NETNS-DATAPLANE-CONFIG: Per-namespace ARP cache
/// Looks up the namespace's ARP cache using `net_ns_id` instead of accepting
/// it as a parameter. This implements per-namespace dataplane state.
pub fn process_frame(
    frame: &[u8],
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    net_ns_id: NamespaceId,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_rx_packets();

    // Parse Ethernet header
    let (eth_hdr, eth_payload) = match parse_ethernet(frame) {
        Ok(result) => result,
        Err(_) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::EthParseError);
        }
    };

    // MAC filtering: only accept frames addressed to us or broadcast
    // This prevents processing stray traffic and reflection attacks
    if eth_hdr.dst != our_mac && !eth_hdr.dst.is_broadcast() {
        // Not for us - silently drop without incrementing error counter
        return ProcessResult::Handled;
    }

    // Route to protocol handler
    let mut result = match eth_hdr.ethertype {
        ETHERTYPE_IPV4 => {
            // R90-2 FIX: Pass network namespace to IPv4 handler
            process_ipv4(
                eth_payload,
                &eth_hdr,
                our_mac,
                our_ip,
                stats,
                net_ns_id,
                now_ms,
            )
        }
        ETHERTYPE_ARP => {
            // D3-NETNS-DATAPLANE: resolve the RECEIVING namespace's ARP cache
            // through the kernel_core hook. Fail-closed: an ARP frame may only
            // be learned into (and answered from) the cache of a LIVE, resolved
            // namespace — an unknown/destroyed ns, or a pre-registration RX
            // (no hook yet), drops the frame rather than touching any shared
            // cache. The hook returns the cache Arc, never a namespace handle,
            // so no namespace reference is held across ARP processing.
            //
            // RX-WIRING CONTRACT (Codex round-2): pre-registration this drops
            // root-ns ARP too. There is no production RX caller today; the
            // future ingress loop MUST start only after kernel_core registers
            // the hooks (assert at wiring time), and must decide its own
            // policy for a namespace dying mid-frame (the `Some` below proves
            // liveness at lookup only — see `NetNsDeviceHooks::ns_arp_cache`).
            let arp_cache = match crate::socket::netns_arp_cache(net_ns_id.0) {
                Some(cache) => cache,
                None => {
                    stats.inc_rx_errors();
                    return ProcessResult::Dropped(DropReason::NetNsUnavailable);
                }
            };
            let mut arp_cache_guard = arp_cache.lock();

            // Process ARP packet
            match process_arp(
                eth_payload,
                our_mac,
                our_ip,
                &mut arp_cache_guard,
                &stats.arp_stats,
                now_ms,
            ) {
                ArpResult::Handled => ProcessResult::Handled,
                ArpResult::Reply(frame) => ProcessResult::Reply(
                    PreparedReply::new(frame).with_stat(PreparedReplyStat::ArpReply),
                ),
                ArpResult::Dropped(e) => ProcessResult::Dropped(DropReason::ArpError(e)),
            }
        }
        _ => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedEtherType)
        }
    };

    // R163-7 FIX: All ingress reply frames (ICMP echo replies, TCP RSTs, firewall REJECT
    // responses, ARP replies) were previously returned directly to the caller, bypassing the
    // egress firewall added in R161-7. Intercept every Reply here and apply the egress
    // firewall before allowing the frame to leave. Frames that fail the egress check are
    // silently dropped so the caller sees Dropped(Firewall) instead of Reply.
    if let ProcessResult::Reply(ref mut reply_frame) = result {
        if !matches!(
            egress_firewall_allows_reply(reply_frame, net_ns_id.0, now_ms),
            EgressFirewallDecision::Allow
        ) {
            return ProcessResult::Dropped(DropReason::Firewall {
                rule_id: None,
                rejected: false,
            });
        }
        // RF180-41 REVIEW FIX: policy acceptance authorizes preparation only.
        // Conntrack and socket-visible completion remain deferred until the
        // caller successfully queues this non-cloneable reply owner.
        reply_frame.authorize(net_ns_id.0, now_ms);
    }
    result
}

/// Structurally validated transport metadata used by both direct egress and
/// prepared-reply policy evaluation.
///
/// RF180-51 FIX: firewall classification must never run on raw port bytes from
/// a malformed TCP/UDP packet. Keeping the parsed header here also prevents the
/// transmit path from validating one representation and committing another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatedTransport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Other,
}

impl ValidatedTransport {
    #[inline]
    fn ports(self) -> (Option<u16>, Option<u16>) {
        match self {
            Self::Tcp(header) => (Some(header.src_port), Some(header.dst_port)),
            Self::Udp(header) => (Some(header.src_port), Some(header.dst_port)),
            Self::Other => (None, None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportValidationError {
    Tcp(TcpError),
    Udp(UdpError),
}

fn validate_transport_payload(
    proto: Ipv4Proto,
    payload: &[u8],
) -> Result<ValidatedTransport, TransportValidationError> {
    match proto {
        Ipv4Proto::Tcp => parse_tcp_header(payload)
            .map(ValidatedTransport::Tcp)
            .map_err(TransportValidationError::Tcp),
        Ipv4Proto::Udp => {
            let header = parse_udp_header(payload).map_err(TransportValidationError::Udp)?;
            if header.length as usize != payload.len() {
                return Err(TransportValidationError::Udp(UdpError::LengthMismatch));
            }
            Ok(ValidatedTransport::Udp(header))
        }
        _ => Ok(ValidatedTransport::Other),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressFirewallDecision {
    Allow,
    Deny,
    Malformed,
}

/// R163-7 FIX: Evaluate an outbound reply frame against the egress firewall.
///
/// Parses the complete Ethernet+IPv4 frame, extracts protocol/port information,
/// and evaluates the egress firewall rules for the given namespace. Returns
/// Returns a typed decision so prepared-reply callers can distinguish a
/// malformed generated frame from a valid frame denied by policy.
///
/// ARP frames (non-IPv4) are always allowed because ARP has no IP-level firewall
/// semantics. Malformed kernel-generated frames fail closed.
#[cfg(feature = "conntrack")]
fn egress_firewall_allows_reply(
    frame: &[u8],
    net_ns_id: u64,
    now_ms: u64,
) -> EgressFirewallDecision {
    use crate::conntrack::{conntrack_table, FlowKey};

    // Parse Ethernet header; non-IPv4 frames (ARP, etc.) are passed through.
    let (eth_hdr, ip_payload) = match parse_ethernet(frame) {
        Ok(r) => r,
        Err(_) => return EgressFirewallDecision::Malformed,
    };
    if eth_hdr.ethertype != ETHERTYPE_IPV4 {
        return EgressFirewallDecision::Allow;
    }

    // Parse IPv4 header.
    let (ip_hdr, _opts, l4_bytes) = match parse_ipv4(ip_payload) {
        Ok(r) => r,
        Err(_) => return EgressFirewallDecision::Malformed,
    };

    let proto = match ip_hdr.proto() {
        Some(p) => p,
        None => return EgressFirewallDecision::Malformed,
    };

    let transport = match validate_transport_payload(proto, l4_bytes) {
        Ok(transport) => transport,
        Err(_) => return EgressFirewallDecision::Malformed,
    };
    let (src_port, dst_port) = transport.ports();

    // R165-7 FIX: This hook only evaluates kernel-generated reply frames
    // (ProcessResult::Reply — ICMP echo replies, TCP RSTs, REJECT responses),
    // i.e. responses to a just-received ingress packet. Such a frame must never
    // be classified `New`. In particular an ICMP echo reply cannot share a
    // FlowKey with its request (the type/code pseudo-ports differ: request 0x800
    // vs reply 0x000) and this lookup does not reconstruct ICMP pseudo-ports, so
    // the naive lookup returns `New` and the default ruleset silently drops the
    // host's own ping reply. Treat any found flow as Established, and floor an
    // unmatched reply to Related, so the default accept-ESTABLISHED/RELATED rule
    // permits legitimate replies. Operators can still drop these with an explicit
    // higher-priority egress rule (evaluated before the default accept rule).
    let ct_decision = {
        let sp = src_port.unwrap_or(0);
        let dp = dst_port.unwrap_or(0);
        let proto_u8 = match proto {
            Ipv4Proto::Tcp => 6u8,
            Ipv4Proto::Udp => 17u8,
            Ipv4Proto::Icmp => 1u8,
            _ => 0u8,
        };
        let (key, _) = FlowKey::from_packet(net_ns_id, proto_u8, ip_hdr.src, ip_hdr.dst, sp, dp);
        Some(match conntrack_table().lookup(&key) {
            Some(_) => crate::conntrack::CtDecision::Established,
            None => crate::conntrack::CtDecision::Related,
        })
    };

    let fw_pkt = FirewallPacket {
        net_ns_id,
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto,
        src_port,
        dst_port,
        ct_state: ct_decision,
    };

    let fw_verdict = firewall_table_for_ns(net_ns_id).evaluate(&fw_pkt);
    crate::firewall::log_match(&fw_verdict, &fw_pkt, now_ms);

    if matches!(fw_verdict.action, FirewallAction::Accept) {
        EgressFirewallDecision::Allow
    } else {
        EgressFirewallDecision::Deny
    }
}

/// R165-6 FIX: Evaluate STATELESS egress rules on reply frames in non-conntrack
/// builds instead of bypassing the firewall entirely.
///
/// The previous non-conntrack variant returned `true` unconditionally, so a
/// stateless egress DROP/REJECT rule (src/dst IP, port, proto — all evaluable
/// without conntrack since `CtStateMask::matches(None)` is true for ANY-masked
/// rules) was enforced on the TX path (R164-7) but silently bypassed for every
/// locally-generated reply frame (ICMP echo replies, TCP RSTs, REJECT responses).
/// This mirrors the conntrack variant's parse+evaluate path with `ct_state: None`,
/// closing the asymmetric-enforcement gap.
///
/// Non-IPv4 (ARP, etc.) passes through; malformed generated frames fail closed, matching
/// the conntrack variant's behavior for kernel-generated replies.
#[cfg(not(feature = "conntrack"))]
fn egress_firewall_allows_reply(
    frame: &[u8],
    net_ns_id: u64,
    now_ms: u64,
) -> EgressFirewallDecision {
    let (eth_hdr, ip_payload) = match parse_ethernet(frame) {
        Ok(r) => r,
        Err(_) => return EgressFirewallDecision::Malformed,
    };
    if eth_hdr.ethertype != ETHERTYPE_IPV4 {
        return EgressFirewallDecision::Allow;
    }

    let (ip_hdr, _opts, l4_bytes) = match parse_ipv4(ip_payload) {
        Ok(r) => r,
        Err(_) => return EgressFirewallDecision::Malformed,
    };

    let proto = match ip_hdr.proto() {
        Some(p) => p,
        None => return EgressFirewallDecision::Malformed,
    };

    let transport = match validate_transport_payload(proto, l4_bytes) {
        Ok(transport) => transport,
        Err(_) => return EgressFirewallDecision::Malformed,
    };
    let (src_port, dst_port) = transport.ports();

    // No conntrack: only stateless rules can match (ct_state = None).
    let fw_pkt = FirewallPacket {
        net_ns_id,
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto,
        src_port,
        dst_port,
        ct_state: None,
    };

    let fw_verdict = firewall_table_for_ns(net_ns_id).evaluate(&fw_pkt);
    crate::firewall::log_match(&fw_verdict, &fw_pkt, now_ms);

    if matches!(fw_verdict.action, FirewallAction::Accept) {
        EgressFirewallDecision::Allow
    } else {
        EgressFirewallDecision::Deny
    }
}

/// Process an IPv4 packet.
///
/// # R90-2 FIX
///
/// Network namespace ID is threaded to UDP/TCP handlers for proper socket delivery.
fn process_ipv4(
    packet: &[u8],
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    net_ns_id: NamespaceId,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_ipv4_rx();

    // Parse and validate IPv4 header first
    let (ip_hdr, _options, payload) = match parse_ipv4(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::Ipv4Error(e));
        }
    };

    // Check if packet is destined for us (unicast only for responses)
    // Security: We accept broadcast for informational purposes but will NOT
    // generate responses to broadcast destinations (Smurf attack prevention)
    let is_broadcast_dst = ip_hdr.dst.is_broadcast();
    if ip_hdr.dst != our_ip && !is_broadcast_dst {
        // Not for us, silently drop (no error)
        return ProcessResult::Handled;
    }

    // Fragment handling with secure reassembly
    // R48-6 + R60: Process fragments through reassembly cache with anti-DoS limits
    let final_payload = if ip_hdr.is_fragment() {
        stats.inc_fragments_rx();
        // R140-4 FIX: Pass net_ns_id to isolate fragment reassembly per namespace.
        match reassemble_fragment(net_ns_id.raw(), &ip_hdr, payload, now_ms) {
            Ok(Some(reassembled)) => {
                // Reassembly complete - use the reassembled payload
                stats.inc_fragments_reassembled();
                reassembled
            }
            Ok(None) => {
                // More fragments needed - handled, no response
                return ProcessResult::Handled;
            }
            Err(reason) => {
                // Fragment dropped due to security limit or error
                stats.inc_fragments_dropped();
                return ProcessResult::Dropped(DropReason::FragmentError(reason));
            }
        }
    } else {
        // RF180-41 FIX: any owned RX payload participates in the aggregate
        // socket-payload ledger for its complete lifetime.
        match WirePacket::try_copy_from_slice(payload) {
            Ok(packet) => packet,
            Err(_) => {
                stats.inc_rx_errors();
                return ProcessResult::Dropped(DropReason::EthParseError);
            }
        }
    };

    // Route to protocol handler
    match ip_hdr.proto() {
        Some(Ipv4Proto::Icmp) => {
            // Pass broadcast flag to ICMP handler for response suppression
            process_icmp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                our_mac,
                our_ip,
                stats,
                net_ns_id,
                now_ms,
                is_broadcast_dst,
            )
        }
        Some(Ipv4Proto::Udp) => {
            // Process UDP packet
            process_udp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                stats,
                is_broadcast_dst,
                net_ns_id,
                now_ms,
            )
        }
        Some(Ipv4Proto::Tcp) => {
            // Process TCP packet
            process_tcp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                stats,
                is_broadcast_dst,
                net_ns_id,
                now_ms,
            )
        }
        None => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedProtocol)
        }
    }
}

/// Process a UDP datagram.
///
/// # Security
///
/// - Does NOT process datagrams sent to broadcast/multicast addresses
///   (prevents amplification attacks)
/// - Validates checksum strictly (zero checksums rejected)
/// - Validates length fields
/// - Delivers to bound sockets via socket_table()
///
/// # R90-2 FIX
///
/// Uses the provided network namespace ID from the receiving device
/// instead of hardcoded ROOT_NET_NS_ID, ensuring proper namespace isolation.
fn process_udp(
    payload: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    stats: &NetStats,
    is_broadcast_dst: bool,
    net_ns_id: NamespaceId,
    now_ms: u64,
) -> ProcessResult {
    stats.udp_stats.inc_rx_packets();

    // Security: Reject UDP to broadcast/multicast destinations
    // This prevents amplification attacks
    if is_broadcast_dst || ip_hdr.dst.is_multicast() {
        stats.udp_stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::UdpError(UdpError::BroadcastDest));
    }

    // Parse and validate UDP datagram
    let (header, data) = match parse_udp(payload, ip_hdr.src, ip_hdr.dst) {
        Ok(result) => result,
        Err(e) => {
            match e {
                UdpError::ChecksumInvalid | UdpError::ZeroChecksum => {
                    stats.udp_stats.inc_checksum_errors();
                }
                _ => {
                    stats.udp_stats.inc_rx_errors();
                }
            }
            return ProcessResult::Dropped(DropReason::UdpError(e));
        }
    };

    // Record bytes received
    stats.udp_stats.add_rx_bytes(data.len() as u64);

    // Conntrack: Update connection tracking state (used by firewall)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_udp;
        Some(ct_process_udp(
            // R107-2 FIX: Include network namespace in conntrack key.
            net_ns_id.0,
            ip_hdr.src,
            ip_hdr.dst,
            header.src_port,
            header.dst_port,
            payload.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // RF178-7 FIX: Resource failure is an ingress hard drop, not merely an
    // INVALID state that a broader firewall ACCEPT rule could override.
    if ct_result
        .as_ref()
        .map(|result| result.resource_exhausted)
        .unwrap_or(false)
    {
        return ProcessResult::Dropped(DropReason::ConntrackExhausted);
    }

    // R121-1 FIX: Evaluate packet against per-namespace firewall rule table.
    let fw_packet = FirewallPacket {
        net_ns_id: net_ns_id.0,
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Udp,
        src_port: Some(header.src_port),
        dst_port: Some(header.dst_port),
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_table = firewall_table_for_ns(net_ns_id.0);
    let fw_verdict = fw_table.evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, payload, now_ms)
    {
        return result;
    }

    // Deliver to socket layer
    // R90-2 FIX: Use namespace ID from receiving device instead of hardcoded root
    if socket_table().deliver_udp(
        net_ns_id,
        header.dst_port,
        ip_hdr.src,
        header.src_port,
        data,
        now_ms,
    ) {
        return ProcessResult::Handled;
    }

    // No listener - silently drop to avoid port scanning feedback
    // Note: We could send ICMP Port Unreachable, but that requires:
    // 1. Rate limiting (to prevent reflection attacks)
    // 2. Building the ICMP response
    // For now, silent drop is the safer default
    stats.udp_stats.inc_no_listener();
    ProcessResult::Handled
}

/// Process an ICMP packet.
///
/// # Security
///
/// - Does NOT respond to echo requests sent to broadcast/multicast IP addresses
///   (Smurf attack prevention per RFC 1122 section 3.2.2.6)
/// - Rate limits all ICMP responses
fn process_icmp(
    packet: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    // R107-2 FIX: ICMP conntrack must be namespace-isolated.
    net_ns_id: NamespaceId,
    now_ms: u64,
    is_broadcast_dst: bool,
) -> ProcessResult {
    stats.inc_icmp_rx();

    // Parse ICMP header
    let (icmp_hdr, _payload) = match parse_icmp(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::IcmpError(e));
        }
    };

    // R64-2 FIX: Add firewall evaluation for ICMP traffic
    // ICMP uses conntrack for RELATED state (e.g., ICMP errors for tracked connections)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_icmp;
        Some(ct_process_icmp(
            // R107-2 FIX: Include network namespace in conntrack key.
            net_ns_id.0,
            ip_hdr.src,
            ip_hdr.dst,
            icmp_hdr.icmp_type,
            icmp_hdr.code,
            packet.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // RF178-7 FIX: Conntrack admission failure is fail-closed before firewall.
    if ct_result
        .as_ref()
        .map(|result| result.resource_exhausted)
        .unwrap_or(false)
    {
        return ProcessResult::Dropped(DropReason::ConntrackExhausted);
    }

    // R121-1 FIX: Evaluate ICMP packet against per-namespace firewall rule table.
    let fw_packet = FirewallPacket {
        net_ns_id: net_ns_id.0,
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Icmp,
        src_port: None, // ICMP has no ports
        dst_port: None,
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_table = firewall_table_for_ns(net_ns_id.0);
    let fw_verdict = fw_table.evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, packet, now_ms)
    {
        return result;
    }

    // Handle echo request (ping)
    if icmp_hdr.icmp_type == ICMP_TYPE_ECHO_REQUEST {
        stats.inc_icmp_echo_rx();

        // SECURITY: Never respond to echo requests sent to broadcast/multicast
        // This prevents Smurf attacks (RFC 1122 section 3.2.2.6)
        if is_broadcast_dst {
            return ProcessResult::Handled;
        }

        // Also check if destination MAC was broadcast (belt and suspenders)
        if eth_hdr.dst.is_broadcast() || eth_hdr.dst.is_multicast() {
            return ProcessResult::Handled;
        }

        // Rate limit ICMP responses
        if !ICMP_RATE_LIMITER.allow(now_ms) {
            stats.inc_rate_limited();
            return ProcessResult::Dropped(DropReason::RateLimited);
        }

        // Build ICMP echo reply
        let icmp_reply = match build_echo_reply(packet) {
            Ok(reply) => reply,
            Err(e) => {
                stats.inc_rx_errors();
                return ProcessResult::Dropped(DropReason::IcmpError(e));
            }
        };

        // Build IPv4 header (swap src/dst)
        let ip_reply = build_ipv4_header(
            our_ip,     // Our IP as source
            ip_hdr.src, // Original source as destination
            Ipv4Proto::Icmp,
            icmp_reply.len() as u16,
            64, // Default TTL
        );

        // RF180-41 FIX: construct the final frame in one admitted allocation;
        // do not retain a second heap-backed IPv4 concatenation concurrently.
        let frame = build_ethernet_frame_from_parts(
            eth_hdr.src,
            our_mac,
            ETHERTYPE_IPV4,
            &[&ip_reply, &icmp_reply],
        );
        if frame.is_empty() {
            return ProcessResult::Dropped(DropReason::EthParseError);
        }

        // R165-7 FIX: Removed the R159-14 outbound echo-reply conntrack seeding.
        // It created a SEPARATE flow (echo-reply pseudo-port 0x000) that never
        // matched the request flow (0x800) and always carried seen_reply=false,
        // so the egress reply firewall still saw it as `New`. The reply path now
        // floors kernel-generated replies to Related/Established in
        // egress_firewall_allows_reply, which is what actually lets the default
        // ESTABLISHED/RELATED accept rule pass legitimate ping replies. Seeding a
        // bogus half-open flow served no purpose and only polluted the table.

        return ProcessResult::Reply(
            PreparedReply::new(frame).with_stat(PreparedReplyStat::IcmpEcho),
        );
    }

    // Other ICMP types are just handled (logged but no response)
    ProcessResult::Handled
}

/// Construct the complete TCP reply owner without another allocator request.
///
/// RF180-41 REVIEW FIX: every non-empty `WirePacket` carries admitted L2/L3
/// headroom. Stateful TCP code therefore allocates the segment and its final
/// encapsulation backing before committing handshake/retransmission state;
/// this helper only fills that already-owned prefix.
fn try_prepare_tcp_reply_frame(
    peer_mac: EthAddr,
    local_mac: EthAddr,
    peer_ip: Ipv4Addr,
    local_ip: Ipv4Addr,
    mut resp_seg: WirePacket,
) -> Option<WirePacket> {
    let ip_reply = build_ipv4_header(local_ip, peer_ip, Ipv4Proto::Tcp, resp_seg.len() as u16, 64);
    let eth_reply = EthHeader {
        dst: peer_mac,
        src: local_mac,
        ethertype: ETHERTYPE_IPV4,
    }
    .to_bytes();
    resp_seg
        .try_prepend_from_slices(&[&eth_reply, &ip_reply])
        .ok()?;
    Some(resp_seg)
}

/// Process a TCP segment.
///
/// # Security
///
/// - Does NOT process segments sent to broadcast/multicast addresses
///   (prevents amplification attacks)
/// - Validates checksum before processing
/// - Sends RST for unknown connections
///
/// # R90-2 FIX
///
/// Uses the provided network namespace ID from the receiving device
/// instead of hardcoded ROOT_NET_NS_ID, ensuring proper namespace isolation.
fn process_tcp(
    payload: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    stats: &NetStats,
    is_broadcast_dst: bool,
    net_ns_id: NamespaceId,
    now_ms: u64,
) -> ProcessResult {
    // Security: ignore TCP to broadcast/multicast destinations
    if is_broadcast_dst || ip_hdr.dst.is_multicast() {
        stats.inc_unsupported_proto();
        return ProcessResult::Handled;
    }

    // Parse TCP header
    let tcp_hdr = match parse_tcp_header(payload) {
        Ok(h) => h,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::TcpError(e));
        }
    };

    // Validate header length
    let hdr_len = tcp_hdr.header_len();
    if payload.len() < hdr_len || hdr_len < TCP_HEADER_MIN_LEN {
        stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::TcpError(TcpError::Truncated));
    }

    // Verify checksum
    if !verify_tcp_checksum(ip_hdr.src, ip_hdr.dst, payload) {
        stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::TcpError(TcpError::BadChecksum));
    }

    // Extract payload (data after TCP header)
    let tcp_payload = &payload[hdr_len..];

    // Conntrack: Update connection tracking state (used by firewall)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_tcp;
        Some(ct_process_tcp(
            // R107-2 FIX: Include network namespace in conntrack key.
            net_ns_id.0,
            ip_hdr.src,
            ip_hdr.dst,
            tcp_hdr.src_port,
            tcp_hdr.dst_port,
            tcp_hdr.flags,
            tcp_payload.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // RF178-7 FIX: Conntrack admission failure is fail-closed before firewall.
    if ct_result
        .as_ref()
        .map(|result| result.resource_exhausted)
        .unwrap_or(false)
    {
        return ProcessResult::Dropped(DropReason::ConntrackExhausted);
    }

    // R121-1 FIX: Evaluate TCP packet against per-namespace firewall rule table.
    let fw_packet = FirewallPacket {
        net_ns_id: net_ns_id.0,
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Tcp,
        src_port: Some(tcp_hdr.src_port),
        dst_port: Some(tcp_hdr.dst_port),
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_table = firewall_table_for_ns(net_ns_id.0);
    let fw_verdict = fw_table.evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, payload, now_ms)
    {
        return result;
    }

    // R58: Parse TCP options for window scaling support
    // Use the full segment so parse_tcp_options can validate header_len
    let tcp_options = parse_tcp_options(payload, &tcp_hdr);

    // Delegate to socket layer for stateful TCP processing
    // R90-2 FIX: Use namespace ID from receiving device instead of hardcoded root
    let mut reply_binding = None;
    let mut ingress_handshake_committed = false;
    let response = socket_table().process_tcp_segment(
        net_ns_id,
        ip_hdr.src,
        ip_hdr.dst,
        &tcp_hdr,
        tcp_payload,
        &tcp_options,
        &mut reply_binding,
        &mut ingress_handshake_committed,
    );

    #[cfg(feature = "conntrack")]
    if ingress_handshake_committed {
        if !crate::conntrack::ct_commit_tcp_ingress_handshake(
            net_ns_id.0,
            ip_hdr.src,
            ip_hdr.dst,
            tcp_hdr.src_port,
            tcp_hdr.dst_port,
        ) {
            return ProcessResult::Dropped(DropReason::ConntrackInvalid);
        }
    }

    if let Some(resp_seg) = response {
        // RF180-41 FIX: compatibility TCP builders use an empty packet as the
        // admission-failure sentinel. Never encapsulate that sentinel as a
        // header-only malformed TCP response.
        if resp_seg.is_empty() {
            return ProcessResult::Handled;
        }
        // R157-10 FIX: the completing ACK advances SynRecv→Established.
        // R158-11 FIX: use parse_tcp_header instead of a fragile byte offset.
        let frame = match try_prepare_tcp_reply_frame(
            eth_hdr.src,
            eth_hdr.dst,
            ip_hdr.src,
            ip_hdr.dst,
            resp_seg,
        ) {
            Some(frame) => frame,
            None => return ProcessResult::Handled,
        };

        let mut reply = PreparedReply::new(frame);
        reply.bind_tcp(reply_binding);
        return ProcessResult::Reply(reply);
    }

    ProcessResult::Handled
}

// ============================================================================
// Outbound Transmission (TX path)
// ============================================================================

/// Default IP address for Zero-OS in QEMU user-mode networking.
const DEFAULT_OUR_IP: Ipv4Addr = Ipv4Addr([10, 0, 2, 15]);

/// Default gateway IP in QEMU user-mode networking.
const DEFAULT_GATEWAY_IP: Ipv4Addr = Ipv4Addr([10, 0, 2, 2]);

/// Default gateway MAC (QEMU's virtual router).
/// This is the standard MAC QEMU assigns to its SLIRP gateway.
const DEFAULT_GATEWAY_MAC: EthAddr = EthAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// Network configuration for TX path.
#[derive(Clone, Copy)]
struct NetConfig {
    our_ip: Ipv4Addr,
    our_mac: EthAddr,
    gateway_ip: Ipv4Addr,
    gateway_mac: EthAddr,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            our_ip: DEFAULT_OUR_IP,
            our_mac: EthAddr::ZERO,
            gateway_ip: DEFAULT_GATEWAY_IP,
            gateway_mac: DEFAULT_GATEWAY_MAC,
        }
    }
}

/// Public snapshot of network configuration.
#[derive(Clone, Copy)]
pub struct NetConfigSnapshot {
    pub our_ip: Ipv4Addr,
    pub our_mac: EthAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: EthAddr,
}

/// Global network state for TX path.
struct NetState {
    config: Mutex<NetConfig>,
    arp: Mutex<ArpCache>,
}

static NET_STATE: Once<NetState> = Once::new();

#[inline]
fn net_state() -> &'static NetState {
    NET_STATE.call_once(|| NetState {
        config: Mutex::new(NetConfig::default()),
        arp: Mutex::new(ArpCache::with_defaults()),
    })
}

/// Resolve MAC address from network device if not yet set.
fn resolve_mac_from_device(cfg: &mut NetConfig) {
    if cfg.our_mac != EthAddr::ZERO {
        return;
    }
    // D1-ISO: metadata-only read — no transmit-capable handle egresses the registry.
    if let Some(mac) = crate::device_mac("eth0") {
        cfg.our_mac = EthAddr(mac);
    }
}

/// Get a snapshot of the current network configuration.
///
/// Lazily initializes our MAC address from the network device.
pub fn network_config() -> NetConfigSnapshot {
    let state = net_state();
    let mut cfg = state.config.lock();
    resolve_mac_from_device(&mut cfg);
    NetConfigSnapshot {
        our_ip: cfg.our_ip,
        our_mac: cfg.our_mac,
        gateway_ip: cfg.gateway_ip,
        gateway_mac: cfg.gateway_mac,
    }
}

/// Resolve destination MAC address.
///
/// For now, we use the gateway MAC for all destinations.
/// A proper implementation would check if dst_ip is on the local subnet
/// and use ARP for local destinations.
fn resolve_dst_mac(dst_ip: Ipv4Addr, cfg: &NetConfigSnapshot) -> EthAddr {
    let state = net_state();
    let mut cache = state.arp.lock();
/// holds no lock across its return (see `NetNsDeviceHooks::ns_arp_cache`),
/// and send paths hold their per-socket locks only while the sending
/// process pins the namespace, so the hook's internal namespace-handle drop
/// never runs teardown here.
///
/// # Visibility
///
/// `pub` as the runtime tests' real-seam observable (Codex round-13: the
/// routing proof must exercise the ACTUAL resolution path, and frame bytes
/// stay unobservable until TX-loopback). Capability-safe: this resolves
/// addressing only — no transmit authority egresses (that is
/// `tx_auth::AuthorizedTxDevice`). Side effects: seeds the namespace's

    // R162-20 FIX: Use actual kernel time for ARP cache TTL checks.
    // Previously hardcoded to 0, causing dynamic entries to never expire.
    let now_ms = crate::socket::socket_wait_hooks_get_ticks().unwrap_or(0);

    // Ensure gateway is always in cache
    let _ = cache.insert(
        cfg.gateway_ip,
        cfg.gateway_mac,
        ArpEntryKind::Static,
        now_ms,
    );
    match crate::socket::netns_arp_cache(net_ns_id) {
        Some(cache) => {
            let mut cache = cache.lock();

    // Try direct lookup first
    if let Some(mac) = cache.lookup(dst_ip, now_ms) {
        return mac;
    }

    // Fall back to gateway MAC for off-link destinations
    cfg.gateway_mac
}

/// D1-ISO-NETNS-DATAPLANE: `tx_auth` owns the ONLY path to the driver `transmit`.
/// A transmit-capable `NetDeviceHandle` no longer egresses the `net` registry
/// (its accessor is `pub(crate)` + sole-caller-pinned); the sole way to reach
/// `NetDevice::transmit` is `AuthorizedTxDevice`, minted only by the namespace-
/// gated resolver below. This turns the TX device-ownership gate from convention
/// (a resolver a new call site could forget) into a type-enforced capability:
/// adding a new physical-TX site is impossible without obtaining a token, and a
/// token is impossible to obtain without the ownership check.
///
/// Fail-closed contract (Safety > Efficiency > Speed):
/// - the handle + its stable registry index come from ONE registry critical
///   section, so ownership binds to the SAME device object the token transmits on;
/// - a namespace that does not own the device gets `TxError::FirewallDenied`
///   (EPERM) — a CLONE_NEWNET child starts with NO devices;
/// - an unregistered hook (early boot / host tests) admits only the root ns.
///
/// Scope of the type barrier: OUT-OF-CRATE bypass is impossible by construction
/// (no transmit-capable handle egresses the `net` crate). In-crate, the raw
/// registry lookup (`get_device_with_index`) is a one-caller audited TCB
/// (contract pinned in lib.rs), not a type barrier.
mod tx_auth {
    use super::TxError;
    use crate::{NetBuf, NetDeviceHandle};

    /// A single-use capability authorizing exactly one driver enqueue on the device
    /// whose ownership `resolve_authorized_tx_device` verified. Deliberately NOT
    /// Clone/Copy/Default and exposes no accessor returning the raw handle — so a
    /// transmit-capable handle can be neither forged nor duplicated, and every
    /// physical-TX site must route through this type.
    pub(super) struct AuthorizedTxDevice {
        dev: NetDeviceHandle,
    }

    impl AuthorizedTxDevice {
        /// Consume the token and enqueue `buf` on the authorized device — the SOLE
        /// `NetDevice::transmit` call in the tree. Takes ONLY the per-device spin
        /// Mutex (no registry/namespace lock), so it is safe inside conntrack egress
        /// closures (RF180-41 context: no conntrack lock is held across the device
        /// callback) and adds no allocation. Dropping an UNCONSUMED token is safe
        /// (authorized-but-unsent); the registry keeps a strong ref to every
        /// registered device for the kernel's lifetime (no unregister API), so
        /// dropping the token's Arc clone never runs a device destructor — re-audit
        /// destructor timing if hot-unregister is ever added.
        ///
        /// D1-ISO revocation contract (safe-scope): authority is granted at MINT
        /// time; a later `remove_device`/`move_device` is NOT synchronous with an
        /// already-minted token (in-flight window = this one enqueue). No concurrent
        /// production mutator exists today: `move_device` is CAP-gated and unwired
        /// to any syscall, and the only runtime add/remove_device callers are the
        /// single-threaded boot-time runtime tests. A sink re-check here (to honor
        /// in-kernel reassignment landing after mint) is deferred to Phase I.3
        /// (NETNS-DATAPLANE-CONFIG) and requires an ownership-generation / token-
        /// pinning design: a naive re-check would upgrade a `NET_NS_BY_ID` Weak
        /// whose last-ref drop could run `NetNamespace::Drop` teardown under the
        /// per-socket `operation` spinlock the TCP reply sinks hold — so the safe
        /// closure is: check at mint, carry the verified handle, no namespace lock
        /// at the sink.
        pub(super) fn transmit(self, buf: NetBuf) -> Result<(), (TxError, NetBuf)> {
            let mut device = self.dev.lock();
            device.transmit(buf)
        }
    }

    /// Resolve the egress device for `net_ns_id`, fail-closed, minting a token only
    /// when the namespace owns the device.
    pub(super) fn resolve_authorized_tx_device(
        net_ns_id: u64,
    ) -> Result<AuthorizedTxDevice, TxError> {
        let (dev, index) = match crate::get_device_with_index("eth0") {
            Some(pair) => pair,
            None => return Err(TxError::LinkDown),
        };
        // Checked narrowing: a theoretical > u32::MAX index must deny, never alias
        // another device's index (fail-closed).
        let index = match u32::try_from(index) {
            Ok(index) => index,
            Err(_) => return Err(TxError::FirewallDenied),
        };
        if !crate::socket::netns_owns_device(net_ns_id, index) {
            return Err(TxError::FirewallDenied);
        }
        Ok(AuthorizedTxDevice { dev })
    }
}
use tx_auth::resolve_authorized_tx_device;

/// Build complete Ethernet frame and transmit via network device.
/// R162-7-2 FIX: Added net_ns_id for per-namespace egress firewall evaluation.
fn build_frame_and_transmit(
    proto: Ipv4Proto,
    dst_ip: Ipv4Addr,
    payload: &[u8],
    net_ns_id: u64,
    tcp_binding: Option<TcpReplyBinding>,
) -> Result<(), TxError> {
    if payload.is_empty() || payload.len() > DEFAULT_MTU {
        return Err(TxError::InvalidBuffer);
    }

    // RF180-51 FIX: validate the complete transport header before consulting
    // policy. Otherwise a malformed non-empty packet can be misclassified as a
    // firewall denial, hiding InvalidBuffer behind EPERM and polluting policy
    // statistics with input that never formed a valid packet.
    let transport =
        validate_transport_payload(proto, payload).map_err(|_| TxError::InvalidBuffer)?;

    // R164-7 FIX: Evaluate egress firewall for ALL builds, not only conntrack.
    // The stateless firewall (src/dst IP, ports, protocol) is evaluated
    // unconditionally. Conntrack-aware ct_state is only available when the
    // conntrack feature is enabled; without it, ct_state is None and
    // stateful rules won't match, but stateless DROP/REJECT rules still fire.
    let (src_port, dst_port) = transport.ports();
    let cfg_pre = network_config();

    // Conntrack-aware ct_state lookup (only with conntrack feature).
    #[cfg(feature = "conntrack")]
    let ct_decision = {
        let sp = src_port.unwrap_or(0);
        let dp = dst_port.unwrap_or(0);
        let proto_u8 = match proto {
            Ipv4Proto::Tcp => 6u8,
            Ipv4Proto::Udp => 17u8,
            Ipv4Proto::Icmp => 1u8,
            _ => 0u8,
        };
        let (key, _) = crate::conntrack::FlowKey::from_packet(
            net_ns_id,
            proto_u8,
            cfg_pre.our_ip,
            dst_ip,
            sp,
            dp,
        );
        crate::conntrack::conntrack_table().lookup(&key).map(|e| {
            if e.seen_reply {
                crate::conntrack::CtDecision::Established
            } else {
                crate::conntrack::CtDecision::New
            }
        })
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_decision: Option<crate::conntrack::CtDecision> = None;

    let fw_pkt = FirewallPacket {
        net_ns_id,
        src_ip: cfg_pre.our_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        ct_state: ct_decision,
    };
    let fw_table = firewall_table_for_ns(net_ns_id);
    let fw_verdict = fw_table.evaluate(&fw_pkt);
    if matches!(
        fw_verdict.action,
        FirewallAction::Drop | FirewallAction::Reject { .. }
    ) {
        // RF180-51 FIX: policy denial is not malformed packet data. Preserve
        // default-deny while giving syscall callers a distinct fail-closed
        // result after their L4 header has parsed successfully.
        return Err(TxError::FirewallDenied);
    }

    // RF180-41 REVIEW FIX: one immutable snapshot binds firewall metadata,
    // conntrack metadata, source addressing, and L2 encapsulation. A second
    // snapshot here could otherwise queue a frame for a different local IP/MAC
    // than the tuple whose policy and conntrack transition were authorized.
    let cfg = cfg_pre;
    if cfg.our_mac == EthAddr::ZERO {
        // No network device available
        return Err(TxError::LinkDown);
    }

    // D3-NETNS-DATAPLANE: Pass net_ns_id to use per-namespace ARP cache.

    // Build IPv4 header
    let ip_hdr = build_ipv4_header(cfg.our_ip, dst_ip, proto, payload.len() as u16, 64);

    // RF180-41 FIX: build the complete wire frame with one admitted allocation.
    let frame = try_build_ethernet_frame_from_parts(
        dst_mac,
        cfg.our_mac,
        ETHERTYPE_IPV4,
        &[&ip_hdr, payload],
    )
    .map_err(|_| TxError::NoMemory)?;

    // R98-2 FIX: Allocate NetBuf via DMA buffer (IOMMU-mapped)
    let dma = alloc_dma_buffer(DMA_PAGE_SIZE).map_err(|_| TxError::NoBuffers)?;
    let mut buf = NetBuf::with_defaults(dma).ok_or(TxError::NoBuffers)?;

    let data = match buf.push_tail(frame.len()) {
        Some(d) => d,
        None => {
            return Err(TxError::InvalidBuffer);
        }
    };
    data.copy_from_slice(&frame);

    // Transmit via network device.
    // D1-ISO-NETNS-DATAPLANE FIX: resolution goes through the single
    // namespace-gated resolver — a netns that does not own the device cannot
    // egress on it (fail-closed EPERM), closing the policy-only TX isolation
    // hole where a CLONE_NEWNET child transmitted with the root ns's IP/MAC.
    let dev = resolve_authorized_tx_device(net_ns_id)?;

    #[cfg(feature = "conntrack")]
    {
        use crate::conntrack::{
            ct_egress_tcp, ct_egress_tcp_with_commit, ct_egress_udp, CtEgressResult,
        };

        let ct_now_ms = crate::socket::socket_wait_hooks_get_ticks().unwrap_or(0);
        let outcome = match proto {
            Ipv4Proto::Tcp => {
                let ValidatedTransport::Tcp(tcp) = transport else {
                    return Err(TxError::InvalidBuffer);
                };
                let header_len = tcp.header_len();
                if header_len < TCP_HEADER_MIN_LEN || header_len > payload.len() {
                    return Err(TxError::InvalidBuffer);
                }
                if let Some(binding) = tcp_binding.as_ref() {
                    let mut operation = socket_table()
                        .lock_tcp_reply_operation(binding, &tcp)
                        .ok_or(TxError::InvalidBuffer)?;
                    let outcome = ct_egress_tcp_with_commit(
                        net_ns_id,
                        cfg_pre.our_ip,
                        dst_ip,
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.flags,
                        payload.len() - header_len,
                        ct_now_ms,
                        move || dev.transmit(buf).map_err(|(error, _returned)| error),
                        || operation.commit(&tcp, ct_now_ms),
                    );
                    drop(operation);
                    outcome
                } else {
                    ct_egress_tcp(
                        net_ns_id,
                        cfg_pre.our_ip,
                        dst_ip,
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.flags,
                        payload.len() - header_len,
                        ct_now_ms,
                        move || dev.transmit(buf).map_err(|(error, _returned)| error),
                    )
                }
            }
            Ipv4Proto::Udp => {
                let ValidatedTransport::Udp(udp) = transport else {
                    return Err(TxError::InvalidBuffer);
                };
                if udp.length as usize != payload.len() || payload.len() < UDP_HEADER_LEN {
                    return Err(TxError::InvalidBuffer);
                }
                ct_egress_udp(
                    net_ns_id,
                    cfg_pre.our_ip,
                    dst_ip,
                    udp.src_port,
                    udp.dst_port,
                    payload.len() - UDP_HEADER_LEN,
                    ct_now_ms,
                    move || dev.transmit(buf).map_err(|(error, _returned)| error),
                )
            }
            _ => {
                return dev.transmit(buf).map_err(|(error, _returned)| error);
            }
        };

        return match outcome {
            CtEgressResult::Committed(_) => Ok(()),
            CtEgressResult::Rejected(_) => Err(TxError::InvalidBuffer),
            CtEgressResult::QueueFailed(error) => Err(error),
            CtEgressResult::QueuedOwnerStale(_) => Err(TxError::InvalidBuffer),
            CtEgressResult::StateLost { .. } => Err(TxError::IoError),
        };
    }

    #[cfg(not(feature = "conntrack"))]
    {
        if let Some(binding) = tcp_binding.as_ref() {
            if proto != Ipv4Proto::Tcp {
                return Err(TxError::InvalidBuffer);
            }
            let ValidatedTransport::Tcp(tcp) = transport else {
                return Err(TxError::InvalidBuffer);
            };
            let mut operation = socket_table()
                .lock_tcp_reply_operation(binding, &tcp)
                .ok_or(TxError::InvalidBuffer)?;
            let result = dev.transmit(buf);
            return match result {
                Ok(()) if operation.commit(&tcp, 0) => Ok(()),
                Ok(()) => Err(TxError::InvalidBuffer),
                Err((error, _returned)) => Err(error),
            };
        }
        dev.transmit(buf).map_err(|(error, _returned)| error)
    }
}

/// Queue an ingress-generated reply and commit all state that depends on that
/// queue acceptance.
///
/// RF180-41 REVIEW FIX: `process_frame` performs an initial egress-policy check
/// but does not claim that the returned frame was sent. This consuming API
/// rechecks policy to close caller-delay TOCTOU, prepares DMA, and couples the
/// final device operation to allocation-free conntrack publication. On error it
/// returns the original admitted owner for retry and commits no socket state.
fn preflight_prepared_reply(reply: &PreparedReply, now_ms: u64) -> Result<u64, TxError> {
    let Some(net_ns_id) = reply.tx_context else {
        return Err(TxError::InvalidBuffer);
    };
    if now_ms < reply.retry_not_before_ms {
        return Err(TxError::QueueFull);
    }
    if reply.is_empty() || reply.len() > DMA_PAGE_SIZE {
        return Err(TxError::InvalidBuffer);
    }
    match egress_firewall_allows_reply(reply, net_ns_id, now_ms) {
        EgressFirewallDecision::Allow => {}
        EgressFirewallDecision::Deny => return Err(TxError::FirewallDenied),
        EgressFirewallDecision::Malformed => return Err(TxError::InvalidBuffer),
    }
    Ok(net_ns_id)
}

/// Queue an ingress-generated reply and commit conntrack/socket state only
/// after the device accepts that exact admitted owner.
///
/// On any policy, preparation, or queue error, returns the original owner so
/// the caller may retry without reconstructing or duplicating the frame.
pub fn transmit_prepared_reply(
    reply: PreparedReply,
    now_ms: u64,
    stats: &NetStats,
) -> Result<(), PreparedReplyTxError> {
    let net_ns_id = match preflight_prepared_reply(&reply, now_ms) {
        Ok(net_ns_id) => net_ns_id,
        Err(error) => return Err(PreparedReplyTxError::Retryable(error, reply)),
    };
    // D1-ISO-NETNS-DATAPLANE FIX: prepared replies egress through the same
    // namespace-gated resolver as direct TX. `Retryable` here follows the
    // existing preflight convention (egress-firewall Deny is also returned as
    // Retryable(FirewallDenied, reply)): it hands the admitted owner back so
    // the caller decides to drop; callers must treat FirewallDenied as a
    // terminal policy verdict, not a transient queue state.
    let dev = match resolve_authorized_tx_device(net_ns_id) {
        Ok(dev) => dev,
        Err(error) => {
            return Err(PreparedReplyTxError::Retryable(error, reply));
        }
    };
    transmit_prepared_reply_with_queue(reply, now_ms, net_ns_id, stats, move |buf| {
        dev.transmit(buf)
    })
}

fn transmit_prepared_reply_with_queue<F>(
    reply: PreparedReply,
    now_ms: u64,
    net_ns_id: u64,
    stats: &NetStats,
    queue: F,
) -> Result<(), PreparedReplyTxError>
where
    F: FnOnce(NetBuf) -> Result<(), (TxError, NetBuf)>,
{
    let dma = match alloc_dma_buffer(DMA_PAGE_SIZE) {
        Ok(dma) => dma,
        Err(_) => {
            return Err(PreparedReplyTxError::Retryable(TxError::NoBuffers, reply));
        }
    };
    let mut buf = match NetBuf::with_defaults(dma) {
        Some(buf) => buf,
        None => {
            return Err(PreparedReplyTxError::Retryable(TxError::NoBuffers, reply));
        }
    };
    let Some(data) = buf.push_tail(reply.len()) else {
        return Err(PreparedReplyTxError::Retryable(
            TxError::InvalidBuffer,
            reply,
        ));
    };
    data.copy_from_slice(&reply);

    complete_prepared_reply_transaction(reply, now_ms, net_ns_id, stats, move || {
        queue(buf).map_err(|(error, _returned)| error)
    })
}

fn complete_prepared_reply_transaction<F>(
    reply: PreparedReply,
    now_ms: u64,
    net_ns_id: u64,
    stats: &NetStats,
    queue: F,
) -> Result<(), PreparedReplyTxError>
where
    F: FnOnce() -> Result<(), TxError>,
{
    let (eth, ip_bytes) = match parse_ethernet(&reply) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Err(PreparedReplyTxError::Retryable(
                TxError::InvalidBuffer,
                reply,
            ));
        }
    };

    #[cfg(feature = "conntrack")]
    if eth.ethertype == ETHERTYPE_IPV4 {
        use crate::conntrack::{
            conntrack_table, ct_egress_tcp_with_commit, CtEgressResult, FlowKey, IPPROTO_TCP,
        };

        let (ip, _options, l4_bytes) = match parse_ipv4(ip_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }
        };
        if ip.proto() == Some(Ipv4Proto::Tcp) {
            let tcp = match parse_tcp_header(l4_bytes) {
                Ok(tcp) => tcp,
                Err(_) => {
                    return Err(PreparedReplyTxError::Retryable(
                        TxError::InvalidBuffer,
                        reply,
                    ));
                }
            };
            let header_len = tcp.header_len();
            if header_len < TCP_HEADER_MIN_LEN || header_len > l4_bytes.len() {
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }

            let (key, _) = FlowKey::from_packet(
                net_ns_id,
                IPPROTO_TCP,
                ip.src,
                ip.dst,
                tcp.src_port,
                tcp.dst_port,
            );
            // An explicit firewall RST for an untracked packet is intentionally
            // stateless. Every state-advancing TCP reply has an ingress-created
            // flow and must use the transaction below.
            if conntrack_table().lookup(&key).is_none() && tcp.flags & TCP_FLAG_RST != 0 {
                let queued = queue();
                return match queued {
                    Ok(()) => {
                        reply.commit_stat(stats);
                        Ok(())
                    }
                    Err(error) => {
                        let mut reply = reply;
                        if error == TxError::QueueFull {
                            reply.note_queue_rejection(now_ms);
                        }
                        Err(PreparedReplyTxError::Retryable(error, reply))
                    }
                };
            }

            let operation_result = reply
                .tcp_binding
                .as_ref()
                .map(|binding| socket_table().lock_tcp_reply_operation(binding, &tcp));
            if matches!(operation_result, Some(None)) {
                // End the binding borrow before returning the retry owner.
                drop(operation_result);
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }
            let mut operation = operation_result.flatten();

            let outcome = ct_egress_tcp_with_commit(
                net_ns_id,
                ip.src,
                ip.dst,
                tcp.src_port,
                tcp.dst_port,
                tcp.flags,
                l4_bytes.len() - header_len,
                now_ms,
                queue,
                || {
                    operation
                        .as_mut()
                        .map(|operation| operation.commit(&tcp, now_ms))
                        .unwrap_or(true)
                },
            );
            drop(operation);
            return match outcome {
                CtEgressResult::Committed(_) => {
                    reply.commit_stat(stats);
                    Ok(())
                }
                CtEgressResult::Rejected(_) => Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                )),
                CtEgressResult::QueueFailed(error) => {
                    let mut reply = reply;
                    if error == TxError::QueueFull {
                        reply.note_queue_rejection(now_ms);
                    }
                    Err(PreparedReplyTxError::Retryable(error, reply))
                }
                CtEgressResult::QueuedOwnerStale(_) => {
                    reply.commit_stat(stats);
                    Err(PreparedReplyTxError::Consumed(TxError::InvalidBuffer))
                }
                CtEgressResult::StateLost { queued } => {
                    if queued {
                        reply.commit_stat(stats);
                    }
                    Err(PreparedReplyTxError::Consumed(TxError::IoError))
                }
            };
        }
    }

    #[cfg(not(feature = "conntrack"))]
    if eth.ethertype == ETHERTYPE_IPV4 {
        let (ip, _options, l4_bytes) = match parse_ipv4(ip_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }
        };
        if ip.proto() == Some(Ipv4Proto::Tcp) {
            let tcp = match parse_tcp_header(l4_bytes) {
                Ok(tcp) => tcp,
                Err(_) => {
                    return Err(PreparedReplyTxError::Retryable(
                        TxError::InvalidBuffer,
                        reply,
                    ));
                }
            };
            if tcp.header_len() < TCP_HEADER_MIN_LEN || tcp.header_len() > l4_bytes.len() {
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }
            let operation_result = reply
                .tcp_binding
                .as_ref()
                .map(|binding| socket_table().lock_tcp_reply_operation(binding, &tcp));
            if matches!(operation_result, Some(None)) {
                drop(operation_result);
                return Err(PreparedReplyTxError::Retryable(
                    TxError::InvalidBuffer,
                    reply,
                ));
            }
            let mut operation = operation_result.flatten();
            let queued = queue();
            return match queued {
                Ok(()) => {
                    reply.commit_stat(stats);
                    let committed = operation
                        .as_mut()
                        .map(|operation| operation.commit(&tcp, now_ms))
                        .unwrap_or(true);
                    drop(operation);
                    if committed {
                        Ok(())
                    } else {
                        Err(PreparedReplyTxError::Consumed(TxError::InvalidBuffer))
                    }
                }
                Err(error) => {
                    drop(operation);
                    let mut reply = reply;
                    if error == TxError::QueueFull {
                        reply.note_queue_rejection(now_ms);
                    }
                    Err(PreparedReplyTxError::Retryable(error, reply))
                }
            };
        }
    }

    let queued = queue();
    match queued {
        Ok(()) => {
            reply.commit_stat(stats);
            Ok(())
        }
        Err(error) => {
            let mut reply = reply;
            if error == TxError::QueueFull {
                reply.note_queue_rejection(now_ms);
            }
            Err(PreparedReplyTxError::Retryable(error, reply))
        }
    }
}

/// Transmit a serialized TCP segment (without IP/Ethernet headers).
///
/// The segment should be a complete TCP header + payload as built by
/// the socket layer's tcp_send() or connect().
///
/// # Arguments
/// * `dst_ip` - Destination IP address
/// * `segment` - Complete TCP segment (header + payload)
///
/// # Returns
/// * `Ok(())` on successful transmission
/// * `Err(TxError)` on failure
pub fn transmit_tcp_segment(
    dst_ip: Ipv4Addr,
    segment: &[u8],
    net_ns_id: u64,
) -> Result<(), TxError> {
    build_frame_and_transmit(Ipv4Proto::Tcp, dst_ip, segment, net_ns_id, None)
}

/// Transmit the exact initial active-open SYN and publish SYN-SENT only after
/// the device accepts it. The private binding keeps a close/stale socket from
/// queueing a control packet whose TCB can no longer commit.
pub fn transmit_tcp_connect(result: TcpConnectResult, net_ns_id: u64) -> Result<(), TxError> {
    let dst_ip = result.dst_ip;
    let segment = result.segment;
    let binding = result.egress_binding;
    build_frame_and_transmit(Ipv4Proto::Tcp, dst_ip, &segment, net_ns_id, Some(binding))
}

/// Transmit a serialized UDP datagram (without IP/Ethernet headers).
///
/// The datagram should be a complete UDP header + payload as built by
/// the socket layer's send_to_udp().
///
/// # Arguments
/// * `dst_ip` - Destination IP address
/// * `datagram` - Complete UDP datagram (header + payload)
///
/// # Returns
/// * `Ok(())` on successful transmission
/// * `Err(TxError)` on failure
pub fn transmit_udp_datagram(
    dst_ip: Ipv4Addr,
    datagram: &[u8],
    net_ns_id: u64,
) -> Result<(), TxError> {
    build_frame_and_transmit(Ipv4Proto::Udp, dst_ip, datagram, net_ns_id, None)
}

// ============================================================================
// Firewall Helpers
// ============================================================================

/// Build original IP header snapshot for ICMP reject response.
///
/// Per RFC 792, ICMP error messages include the original IP header + first 8 bytes
/// of the original payload (L4 header).
///
/// # R64-3 NOTE: Current implementation reconstructs the IP header from parsed fields
/// rather than copying the original bytes. This means:
/// - IP options are not included (assumes IHL=5)
/// - Checksum is recalculated
///
/// A more RFC-compliant implementation would pass through the original packet slice.
/// This is acceptable for most cases but may cause issues with packets containing
/// IP options. Future improvement: pass original IP header bytes through the call chain.
fn build_original_ip_for_reject(ip_hdr: &Ipv4Header, l4_bytes: &[u8]) -> WirePacket {
    let quoted_len = cmp::min(l4_bytes.len(), 8);
    let mut hdr = [0u8; IPV4_HEADER_MIN_LEN];

    // Build minimal header snapshot from the parsed fields
    hdr[0] = 0x45; // Version + IHL (no options)
    hdr[1] = ip_hdr.dscp_ecn;
    let total_len = (IPV4_HEADER_MIN_LEN + quoted_len) as u16;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&ip_hdr.identification.to_be_bytes());
    hdr[6..8].copy_from_slice(&ip_hdr.flags_fragment.to_be_bytes());
    hdr[8] = ip_hdr.ttl;
    hdr[9] = ip_hdr.protocol;
    hdr[12..16].copy_from_slice(&ip_hdr.src.0);
    hdr[16..20].copy_from_slice(&ip_hdr.dst.0);
    let checksum = compute_checksum(&hdr, IPV4_HEADER_MIN_LEN);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    // RF180-41 FIX: the firewall quote is an admitted wire owner and cannot
    // escape the global heap proof while a reject is being assembled.
    WirePacket::try_from_slices(&[&hdr, &l4_bytes[..quoted_len]]).unwrap_or_default()
}

/// Apply firewall verdict, generating response if needed.
///
/// Returns `Some(ProcessResult)` if the packet should be dropped/rejected,
/// or `None` if the packet should be accepted and processing should continue.
fn apply_firewall_verdict(
    verdict: &FirewallVerdict,
    packet: &FirewallPacket,
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    l4_bytes: &[u8],
    now_ms: u64,
) -> Option<ProcessResult> {
    crate::firewall::log_match(verdict, packet, now_ms);

    match verdict.action {
        FirewallAction::Accept => None,
        FirewallAction::Drop => Some(ProcessResult::Dropped(DropReason::Firewall {
            rule_id: verdict.rule_id,
            rejected: false,
        })),
        FirewallAction::Reject { icmp_code } => {
            // Don't send ICMP errors to broadcast/multicast
            if ip_hdr.dst.is_broadcast() || ip_hdr.dst.is_multicast() {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }

            // R64-1 FIX: Rate limit firewall REJECT ICMP responses
            // Prevents reflection/amplification attacks
            if !ICMP_RATE_LIMITER.allow(now_ms) {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }

            // R64-5 FIX: For TCP rejections, send a TCP RST per RFC 793 instead of ICMP
            // This is more appropriate for TCP as RST immediately terminates the connection
            // and is the standard response for rejected TCP traffic.
            if packet.proto == Ipv4Proto::Tcp {
                if let Ok(tcp_hdr) = parse_tcp_header(l4_bytes) {
                    let hdr_len = tcp_hdr.header_len();
                    if l4_bytes.len() >= hdr_len && hdr_len >= TCP_HEADER_MIN_LEN {
                        let tcp_payload = &l4_bytes[hdr_len..];

                        let is_ack = tcp_hdr.flags & TCP_FLAG_ACK != 0;
                        let is_syn = tcp_hdr.flags & TCP_FLAG_SYN != 0;
                        let is_fin = tcp_hdr.flags & TCP_FLAG_FIN != 0;

                        // RFC 793: If ACK was set, RST seq = incoming ACK number, no ACK flag
                        // If ACK was not set, RST seq = 0, ACK = incoming SEQ + segment length
                        let (seq_num, ack_num, flags) = if is_ack {
                            (tcp_hdr.ack_num, 0, TCP_FLAG_RST)
                        } else {
                            let mut seg_len = tcp_payload.len() as u32;
                            if is_syn {
                                seg_len = seg_len.wrapping_add(1);
                            }
                            if is_fin {
                                seg_len = seg_len.wrapping_add(1);
                            }
                            let computed_ack = tcp_hdr.seq_num.wrapping_add(seg_len);
                            (0, computed_ack, TCP_FLAG_RST | TCP_FLAG_ACK)
                        };

                        let rst_segment = build_tcp_segment(
                            ip_hdr.dst, // Our IP as source
                            ip_hdr.src, // Original source as destination
                            tcp_hdr.dst_port,
                            tcp_hdr.src_port,
                            seq_num,
                            ack_num,
                            flags,
                            0,   // Window size
                            &[], // No payload
                        );
                        if rst_segment.is_empty() {
                            return Some(ProcessResult::Dropped(DropReason::Firewall {
                                rule_id: verdict.rule_id,
                                rejected: true,
                            }));
                        }

                        let ip_reply = build_ipv4_header(
                            ip_hdr.dst,
                            ip_hdr.src,
                            Ipv4Proto::Tcp,
                            rst_segment.len() as u16,
                            64,
                        );

                        let frame = build_ethernet_frame_from_parts(
                            eth_hdr.src,
                            eth_hdr.dst,
                            ETHERTYPE_IPV4,
                            &[&ip_reply, &rst_segment],
                        );
                        // R165-18 / R178-L1 FIX: drop on empty-OOM frame instead of emitting
                        // a runt RST frame or accepting.
                        if frame.is_empty() {
                            return Some(ProcessResult::Dropped(DropReason::Firewall {
                                rule_id: verdict.rule_id,
                                rejected: true,
                            }));
                        }

                        return Some(ProcessResult::Reply(PreparedReply::new(frame)));
                    }
                }
                // If TCP header parsing fails, fall through to ICMP response
            }

            // Build ICMP destination unreachable for non-TCP protocols
            let quoted = build_original_ip_for_reject(ip_hdr, l4_bytes);
            if quoted.is_empty() {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }
            let icmp = build_dest_unreachable(icmp_code, &quoted);
            if icmp.is_empty() {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }
            let ip_reply = build_ipv4_header(
                ip_hdr.dst,
                ip_hdr.src,
                Ipv4Proto::Icmp,
                icmp.len() as u16,
                64,
            );

            let frame = build_ethernet_frame_from_parts(
                eth_hdr.src,
                eth_hdr.dst,
                ETHERTYPE_IPV4,
                &[&ip_reply, &icmp],
            );
            // R165-18 / R178-L1 FIX: drop on empty-OOM frame instead of emitting a runt
            // ICMP-reject frame or accepting.
            if frame.is_empty() {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }

            Some(ProcessResult::Reply(PreparedReply::new(frame)))
        }
    }
}

/// fail-closed `NetNsUnavailable`). Re-resolving the registry per frame would
/// buy no isolation and add lock churn (Efficiency).
///
/// v1 ATTRIBUTION CONTRACT: every registered device is attributed to the ROOT
/// namespace (ns 0). No inverse device→owner mapping exists in the tree —
/// `net_ns_owns_device(0, _)` admits root for every device and
/// `sys_move_net_device` is hard-gated ENOSYS — so root is the only owner any
/// device can have today. ARMING `move_device` MUST introduce an inverse
/// ownership lookup (+ generation, so a mid-poll move cannot attribute a frame
// ============================================================================
// Timer Maintenance
// ============================================================================

/// Handle periodic timer tick for network stack maintenance.
///
/// Invoked from the PROCESS-CONTEXT deferred timer drain (kernel_core
/// `drain_deferred_tcp_timers`, on syscall-return / reschedule), NOT the hard-IRQ
/// timer handler — so it may take the conntrack/fragment locks. Performs cleanup
/// of expired fragment reassembly queues and (R171-G4-1) the conntrack expiry sweep.
///
/// # Arguments
/// * `now_ms` - Current time in milliseconds
///
/// # Returns
/// Number of expired fragment queues + conntrack flows reclaimed
pub fn handle_timer_tick(now_ms: u64) -> usize {
    // R171-G4-1 FIX: run the conntrack expiry sweep here too. `handle_timer_tick`
    // is the already-rate-driven per-tick netns garbage-reclaim entry; previously
    // `conntrack::ct_sweep` had ZERO callers, so expired conntrack flows + dead-ns
    // rows were never proactively reclaimed and per-ns conntrack budgets could
    // self-wedge as the global table filled. Process-context (timer bottom-half),
    // so the conntrack locks are safe here — same context the fragment cleanup
    // already runs in.
    let fragments = cleanup_expired_fragments(now_ms);
    let flows = crate::conntrack::ct_sweep(now_ms);
    fragments + flows
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_atomic() {
        let stats = NetStats::new();
        stats.inc_rx_packets();
        stats.inc_rx_packets();
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn rf180_51_malformed_transport_never_collapses_into_firewall_denial() {
        use crate::firewall::{firewall_remove_ns, FirewallRule};

        const DIRECT_NS: u64 = 0x7e57_1805_1001;
        const REPLY_NS: u64 = 0x7e57_1805_1002;
        let local_ip = Ipv4Addr::new(192, 0, 2, 51);
        let peer_ip = Ipv4Addr::new(192, 0, 2, 52);

        let valid_zero_udp = [
            0xc0, 0x01, // source port 49153
            0x00, 0x09, // destination port 9
            0x00, 0x08, // header-only UDP length
            0x00, 0x00, // IPv4 permits a zero UDP checksum
        ];
        let mut malformed_udp = valid_zero_udp;
        malformed_udp[5] = 0x09; // claims one byte beyond the immutable payload

        firewall_remove_ns(DIRECT_NS);
        assert_eq!(
            build_frame_and_transmit(Ipv4Proto::Udp, peer_ip, &malformed_udp, DIRECT_NS, None,),
            Err(TxError::InvalidBuffer),
            "malformed UDP must fail before default-deny policy evaluation"
        );
        assert_eq!(
            build_frame_and_transmit(Ipv4Proto::Udp, peer_ip, &valid_zero_udp, DIRECT_NS, None,),
            Err(TxError::FirewallDenied),
            "a structurally valid header-only datagram must reach default-deny"
        );
        firewall_remove_ns(DIRECT_NS);

        firewall_remove_ns(REPLY_NS);
        firewall_table_for_ns(REPLY_NS).replace_rules(alloc::vec![FirewallRule::builder(51)
            .priority(i32::MAX)
            .proto(Ipv4Proto::Udp)
            .action(FirewallAction::Drop)
            .build(),]);

        let make_reply = |udp: &[u8]| {
            let ip = build_ipv4_header(local_ip, peer_ip, Ipv4Proto::Udp, udp.len() as u16, 64);
            let frame = try_build_ethernet_frame_from_parts(
                EthAddr::new(0x02, 0, 0, 0, 0, 52),
                EthAddr::new(0x02, 0, 0, 0, 0, 51),
                ETHERTYPE_IPV4,
                &[&ip, udp],
            )
            .expect("RF180-51 reply fixture admission");
            let mut reply = PreparedReply::new(frame);
            reply.authorize(REPLY_NS, 0);
            reply
        };

        assert_eq!(
            preflight_prepared_reply(&make_reply(&malformed_udp), 0),
            Err(TxError::InvalidBuffer),
            "prepared-reply parsing failure must not be reported as policy denial"
        );
        assert_eq!(
            preflight_prepared_reply(&make_reply(&valid_zero_udp), 0),
            Err(TxError::FirewallDenied),
            "valid prepared reply must retain the explicit firewall verdict"
        );
        firewall_remove_ns(REPLY_NS);
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn rf180_41_reply_encapsulation_is_allocation_free_and_conntrack_is_deferred() {
        use crate::conntrack::{
            conntrack_table, ct_drain_ns, ct_process_tcp, CtProtoState, FlowKey, TcpCtState,
            IPPROTO_TCP,
        };

        const NS: u64 = 0x7e57_1804_1001;
        let peer_ip = Ipv4Addr::new(192, 0, 2, 10);
        let local_ip = Ipv4Addr::new(192, 0, 2, 20);
        let peer_port = 40_001;
        let local_port = 8080;
        let now_ms = 41_000;

        ct_drain_ns(NS);
        let seeded = ct_process_tcp(
            NS,
            peer_ip,
            local_ip,
            peer_port,
            local_port,
            TCP_FLAG_SYN,
            0,
            now_ms,
        );
        assert_eq!(seeded.state, CtProtoState::Tcp(TcpCtState::SynSent));

        let syn_ack = build_tcp_segment(
            local_ip,
            peer_ip,
            local_port,
            peer_port,
            1,
            2,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            4096,
            &[],
        );
        assert!(!syn_ack.is_empty(), "test SYN-ACK allocation must succeed");

        WirePacket::fail_next_admission_for_test();
        let frame = try_prepare_tcp_reply_frame(
            EthAddr::new(0x02, 0, 0, 0, 0, 1),
            EthAddr::new(0x02, 0, 0, 0, 0, 2),
            peer_ip,
            local_ip,
            syn_ack,
        )
        .expect("encapsulation must consume reserved headroom without allocation");
        assert_eq!(
            parse_ethernet(&frame)
                .expect("encapsulated Ethernet frame parses")
                .0
                .ethertype,
            ETHERTYPE_IPV4
        );

        // The injected failure remains pending, proving encapsulation did not
        // issue a second allocator/admission request.
        assert!(WirePacket::try_copy_from_slice(&[0xaa]).is_err());

        let (key, _) =
            FlowKey::from_packet(NS, IPPROTO_TCP, peer_ip, local_ip, peer_port, local_port);
        let before_commit = conntrack_table()
            .lookup(&key)
            .expect("seeded conntrack entry must remain present");
        assert_eq!(
            before_commit.state,
            CtProtoState::Tcp(TcpCtState::SynSent),
            "frame preparation alone must not publish outbound conntrack"
        );
        assert_eq!(
            before_commit.packets_reply, 0,
            "reply accounting is deferred until policy acceptance"
        );

        let mut reply = PreparedReply::new(frame);
        reply.authorize(NS, now_ms);
        let stats = NetStats::new();
        let reply = match complete_prepared_reply_transaction(reply, now_ms + 1, NS, &stats, || {
            Err(TxError::QueueFull)
        }) {
            Err(PreparedReplyTxError::Retryable(TxError::QueueFull, reply)) => reply,
            _ => panic!("QueueFull must return the original prepared owner"),
        };
        let after_reject = conntrack_table()
            .lookup(&key)
            .expect("QueueFull retains the ingress-created flow");
        assert_eq!(after_reject.state, before_commit.state);
        assert_eq!(after_reject.packets_reply, before_commit.packets_reply);

        assert!(
            complete_prepared_reply_transaction(reply, now_ms + 2, NS, &stats, || Ok(())).is_ok()
        );
        let committed = conntrack_table()
            .lookup(&key)
            .expect("committed conntrack entry remains present");
        assert_eq!(committed.state, CtProtoState::Tcp(TcpCtState::SynRecv));
        assert_eq!(committed.packets_reply, 1);

        assert_eq!(ct_drain_ns(NS), 1);
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn rf180_41_egress_firewall_drop_does_not_commit_reply_conntrack() {
        use crate::conntrack::{
            conntrack_table, ct_drain_ns, CtProtoState, FlowKey, TcpCtState, IPPROTO_TCP,
        };
        use crate::firewall::{firewall_remove_ns, FirewallRule, IpCidrMatch};

        const NS: u64 = 0x7e57_1804_1002;
        let peer_ip = Ipv4Addr::new(192, 0, 2, 30);
        let local_ip = Ipv4Addr::new(192, 0, 2, 40);
        let peer_mac = EthAddr::new(0x02, 0, 0, 0, 0, 3);
        let local_mac = EthAddr::new(0x02, 0, 0, 0, 0, 4);
        let peer_port = 40_002;
        let local_port = 8081;

        ct_drain_ns(NS);
        firewall_remove_ns(NS);
        let firewall = firewall_table_for_ns(NS);
        firewall.replace_rules(alloc::vec![
            FirewallRule::builder(41)
                .priority(200)
                .src_ip(IpCidrMatch::host(local_ip))
                .dst_ip(IpCidrMatch::host(peer_ip))
                .proto(Ipv4Proto::Tcp)
                .action(FirewallAction::Drop)
                .build(),
            FirewallRule::builder(42)
                .priority(100)
                .src_ip(IpCidrMatch::host(peer_ip))
                .dst_ip(IpCidrMatch::host(local_ip))
                .proto(Ipv4Proto::Tcp)
                .action(FirewallAction::Accept)
                .build(),
        ]);

        let syn = build_tcp_segment(
            peer_ip,
            local_ip,
            peer_port,
            local_port,
            1,
            0,
            TCP_FLAG_SYN,
            4096,
            &[],
        );
        let ip = build_ipv4_header(peer_ip, local_ip, Ipv4Proto::Tcp, syn.len() as u16, 64);
        let frame =
            try_build_ethernet_frame_from_parts(local_mac, peer_mac, ETHERTYPE_IPV4, &[&ip, &syn])
                .expect("test ingress frame admission");
        let stats = NetStats::new();
        assert!(matches!(
            process_frame(&frame, local_mac, local_ip, &stats, NamespaceId(NS), 42_000,),
            ProcessResult::Dropped(DropReason::Firewall { .. })
        ));

        let (key, _) =
            FlowKey::from_packet(NS, IPPROTO_TCP, peer_ip, local_ip, peer_port, local_port);
        let entry = conntrack_table()
            .lookup(&key)
            .expect("accepted ingress SYN must remain tracked");
        assert_eq!(entry.state, CtProtoState::Tcp(TcpCtState::SynSent));
        assert_eq!(entry.packets_reply, 0);

        assert_eq!(ct_drain_ns(NS), 1);
        firewall_remove_ns(NS);
    }

    /// D1-ISO-NETNS-DATAPLANE (T1 support): minimal mock so the namespace-gated
    /// resolver can find an "eth0" on the host. The full sink path is
    /// host-infeasible (`alloc_dma_buffer` fails before any driver is reached),
    /// so driver-reach is proven by the `net_ns_tx_isolation` boot test instead.
    struct MockEthDevice;

    impl crate::NetDevice for MockEthDevice {
        fn name(&self) -> &str {
            "eth0"
        }
        fn mac_address(&self) -> crate::MacAddress {
            [0x02, 0xd1, 0x15, 0x00, 0x00, 0x01]
        }
        fn set_mac_address(&mut self, _mac: crate::MacAddress) -> Result<(), crate::NetError> {
            Err(crate::NetError::NotSupported)
        }
        fn capabilities(&self) -> crate::DeviceCaps {
            crate::DeviceCaps::default()
        }
        fn link_status(&self) -> crate::LinkStatus {
            crate::LinkStatus::UP_UNKNOWN
        }
        fn operating_mode(&self) -> crate::OperatingMode {
            crate::OperatingMode::Polling
        }
        fn set_operating_mode(
            &mut self,
            _mode: crate::OperatingMode,
        ) -> Result<(), crate::NetError> {
            Ok(())
        }
        fn enable_interrupts(&mut self) -> Result<(), crate::NetError> {
            Ok(())
        }
        fn disable_interrupts(&mut self) -> Result<(), crate::NetError> {
            Ok(())
        }
        fn transmit(&mut self, _buf: NetBuf) -> Result<(), (TxError, NetBuf)> {
            Ok(())
        }
        fn reclaim_tx(&mut self) -> usize {
            0
        }
        fn tx_queue_space(&self) -> usize {
            64
        }
        fn receive(&mut self) -> Result<Option<NetBuf>, crate::RxError> {
            Ok(None)
        }
        fn replenish_rx(&mut self, _pool: &crate::BufPool, _count: usize) -> usize {
            0
        }
        fn rx_queue_depth(&self) -> usize {
            0
        }
        fn poll(&mut self) -> bool {
            false
        }
        fn handle_interrupt(&mut self) {}
    }

    /// D1-ISO-NETNS-DATAPLANE (T1, resolver-level): the resolver is the sole
    /// token mint and is fail-closed on namespace ownership. On the host no
    /// `NetNsDeviceHooks` is ever registered (registration happens only in
    /// kernel_core::init on the boot path), so the unregistered arm must admit
    /// ONLY ns 0.
    ///
    /// T2 from the original design (a sink recheck-method test) is deliberately
    /// ABSENT: under the mint-time safe-scope there is no runtime re-check to
    /// test, and the single-use / non-Clone properties are compile-time enforced.
    #[test]
    fn d1iso_resolver_gates_tx_by_namespace_ownership() {
        // Make "eth0" resolvable. The registry rejects duplicate names, so if a
        // parallel test already registered one this is a no-op — every assert
        // below is invariant to WHICH eth0 instance is registered.
        let _ = crate::register_device(MockEthDevice);

        // Non-root namespace owning no devices: fail-closed EPERM mapping.
        const CHILD_NS: u64 = 0x7e57_d150_0001;
        assert!(
            matches!(
                resolve_authorized_tx_device(CHILD_NS),
                Err(TxError::FirewallDenied)
            ),
            "unowned non-root ns must be denied at the resolver"
        );

        // Root namespace: admitted by the unregistered-hook arm; a token mints.
        let token = resolve_authorized_tx_device(0)
            .expect("root ns must be admitted by the unregistered-hook arm");
        // Dropping an unconsumed token is safe (authorized-but-unsent).
        drop(token);
    }
}
