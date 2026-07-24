//! TCP (Transmission Control Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 793 compliant TCP implementation with security-first design.
//!
//! # TCP Header Format (RFC 793)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Source Port           |       Destination Port        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                        Sequence Number                        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                     Acknowledgment Number                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Data  |       |U|A|P|R|S|F|                                   |
//! | Offs  | Resv  |R|C|S|S|Y|I|            Window                 |
//! |       |       |G|K|H|T|N|N|                                   |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |           Checksum            |         Urgent Pointer        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Options (if data offset > 5)               |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                             Data                              |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - ISN randomization per RFC 6528 (keyed hash over 4-tuple + time)
//! - Strict sequence number validation (prevents off-path attacks)
//! - SYN flood protection with backlog limits (SYN cookies placeholder)
//! - Connection resource limits
//! - Checksum verification with IPv4 pseudo-header
//! - RST rate limiting
//! - Invalid flag combination rejection
//!
//! # State Machine
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   \
//!                              +---------+            CLOSE    |    \
//!                              |  LISTEN |          ---------- |     |
//!                              +---------+          delete TCB |     |
//!                   rcv SYN      |     |     SEND              |     |
//!                  -----------   |     |    -------            |     V
//! +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//! |         |<-----------------           ------------------>|         |
//! |   SYN   |                    rcv SYN                     |   SYN   |
//! |   RCVD  |<-----------------------------------------------|   SENT  |
//! |         |                    snd ACK                     |         |
//! |         |------------------           -------------------|         |
//! +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//!   |           --------------   |     |   -----------
//!   |                  x         |     |     snd ACK
//!   |                            V     V
//!   |  CLOSE                   +---------+
//!   | -------                  |  ESTAB  |
//!   | snd FIN                  +---------+
//!   |                   ...continued states...
//! ```
//!
//! # References
//!
//! - RFC 793: Transmission Control Protocol
//! - RFC 1122: Requirements for Internet Hosts
//! - RFC 6528: Defending Against Sequence Number Attacks
//! - RFC 5961: Improving TCP's Robustness to Blind In-Window Attacks

#[cfg(test)]
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::admitted::{AdmittedVec, WirePacket};
use crate::ipv4::{calculate_checksum_with_pseudo, Ipv4Addr};
use mm::HeapClass;

// ============================================================================
// TCP Constants
// ============================================================================

/// TCP header minimum length in bytes (without options)
pub const TCP_HEADER_MIN_LEN: usize = 20;

/// TCP header maximum length in bytes (with max options)
pub const TCP_HEADER_MAX_LEN: usize = 60;

/// TCP protocol number (for IPv4)
pub const TCP_PROTO: u8 = 6;

/// Maximum Segment Size default (RFC 879)
pub const TCP_DEFAULT_MSS: u16 = 536;

/// Maximum Segment Size for Ethernet (1500 - 20 IP - 20 TCP)
pub const TCP_ETHERNET_MSS: u16 = 1460;

/// Default receive window size (unscaled, for compatibility)
pub const TCP_DEFAULT_WINDOW: u16 = 65535;

// ============================================================================
// SYN Cookie Constants (RFC 4987)
// ============================================================================

/// Supported MSS values encoded in SYN cookies (3 bits => 8 slots).
///
/// These are sorted in ascending order. When generating a cookie, we select
/// the largest value that doesn't exceed the peer's offered MSS.
///
/// # Security Consideration
///
/// SYN cookies lose MSS precision (only 8 values supported). The table covers
/// common network paths from small MTU links to Ethernet. Window scaling
/// information is not preserved in cookies (limitation of the protocol).
pub const TCP_SYN_COOKIE_MSS_TABLE: [u16; 8] = [
    256,              // Minimum practical MSS
    TCP_DEFAULT_MSS,  // 536 - RFC 879 default
    576,              // Common older networks
    1024,             // Intermediate networks
    1200,             // Conservative Ethernet estimate
    1360,             // PPPoE/VPN overhead adjustment
    1400,             // Common datacenter setting
    TCP_ETHERNET_MSS, // 1460 - Full Ethernet
];

/// Time granularity for SYN cookie timestamps (milliseconds).
///
/// Coarser granularity (4 seconds) allows more time slots in fewer bits
/// while still providing reasonable protection against replay attacks.
pub const TCP_SYN_COOKIE_TIME_GRANULARITY_MS: u64 = 4_000;

/// Maximum age for a valid SYN cookie (milliseconds).
///
/// Cookies older than this are rejected to prevent replay attacks.
/// 120 seconds allows for slow networks with high packet loss while
/// limiting the attack window.
pub const TCP_SYN_COOKIE_MAX_AGE_MS: u64 = 120_000;

/// Secret rotation period for SYN cookie MAC (milliseconds).
///
/// The secret is rotated every 5 minutes. During rotation, both the
/// current and previous secrets are accepted to handle in-flight packets.
const TCP_SYN_COOKIE_SECRET_ROTATE_MS: u64 = 300_000;

/// Bit width for time slot in SYN cookie (6 bits = 64 slots × 4 sec = 256 sec range).
const TCP_SYN_COOKIE_TIME_BITS: u32 = 6;

/// Bit width for MSS index in SYN cookie (3 bits = 8 MSS options).
const TCP_SYN_COOKIE_MSS_BITS: u32 = 3;

/// Bit width for MAC in SYN cookie (remaining 23 bits).
const TCP_SYN_COOKIE_MAC_BITS: u32 = 32 - TCP_SYN_COOKIE_TIME_BITS - TCP_SYN_COOKIE_MSS_BITS;

/// Bitmask for time slot extraction.
const TCP_SYN_COOKIE_TIME_MASK: u32 = (1 << TCP_SYN_COOKIE_TIME_BITS) - 1;

/// Bitmask for MSS index extraction.
const TCP_SYN_COOKIE_MSS_MASK: u32 = (1 << TCP_SYN_COOKIE_MSS_BITS) - 1;

/// Bitmask for MAC extraction.
const TCP_SYN_COOKIE_MAC_MASK: u32 = (1 << TCP_SYN_COOKIE_MAC_BITS) - 1;

/// Maximum valid age in time slots for SYN cookie validation.
const TCP_SYN_COOKIE_MAX_AGE_SLOTS: u32 =
    (TCP_SYN_COOKIE_MAX_AGE_MS / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32;

// ============================================================================
// Window Scaling Constants (RFC 7323)
// ============================================================================

/// Maximum window scale shift factor per RFC 7323.
/// Scale factor of 14 allows windows up to 1GB (65535 << 14).
pub const TCP_MAX_WINDOW_SCALE: u8 = 14;

/// Maximum scaled window size in bytes.
/// This is the largest receive window we can advertise (65535 << 14).
pub const TCP_MAX_SCALED_WINDOW: u32 = (u16::MAX as u32) << TCP_MAX_WINDOW_SCALE;

/// Default receive buffer size in bytes (256 KB).
/// This is larger than 64KB to make window scaling worthwhile.
/// Provides good throughput on typical networks.
pub const TCP_DEFAULT_RCV_WINDOW_BYTES: u32 = 256 * 1024;

/// Maximum retransmission attempts before giving up
pub const TCP_MAX_RETRIES: u8 = 15;

/// Initial retransmission timeout in milliseconds
pub const TCP_INITIAL_RTO_MS: u64 = 1000;

/// Minimum retransmission timeout in milliseconds
///
/// RFC 6298 Section 2.4 recommends a minimum RTO of 1 second to avoid
/// spurious retransmissions due to delayed ACKs. While some implementations
/// use lower values (Linux uses 200ms with tcp_rto_min), we follow the RFC
/// for correctness and to account for our coarser timer granularity.
pub const TCP_MIN_RTO_MS: u64 = 1000;

/// Maximum retransmission timeout in milliseconds
pub const TCP_MAX_RTO_MS: u64 = 120_000;

/// TIME-WAIT duration (2*MSL = 2*60 seconds per RFC 793)
pub const TCP_TIME_WAIT_MS: u64 = 120_000;

/// R65-5 FIX: FIN_WAIT_2 idle timeout (60 seconds).
///
/// RFC 793 does not specify a timeout for FIN_WAIT_2, but without one, connections
/// can remain in this state indefinitely if the peer never sends FIN. This creates
/// a resource exhaustion vulnerability where an attacker can:
/// 1. Establish many connections
/// 2. Send FIN and receive our FIN-ACK (we move to FIN_WAIT_2)
/// 3. Never send their FIN, leaking our TCB resources forever
///
/// Linux uses tcp_fin_timeout sysctl (default 60 seconds) to bound this state.
/// We follow the same approach for consistency and security.
pub const TCP_FIN_WAIT_2_TIMEOUT_MS: u64 = 60_000;

/// R52-1 FIX: SYN timeout for half-open connections in SYN queue.
///
/// Half-open connections (SYN received, SYN-ACK sent, awaiting final ACK) are
/// evicted from the SYN queue after this timeout to prevent SYN flood attacks
/// from exhausting listener resources.
///
/// 30 seconds is a reasonable balance:
/// - Long enough for legitimate slow connections (high-latency, packet loss)
/// - Short enough to recover from SYN flood attacks within minutes
///
/// Reference: Linux uses tcp_synack_retries (default 5) * exponential backoff,
/// resulting in ~63 seconds total. We use a simpler fixed timeout.
pub const TCP_SYN_TIMEOUT_MS: u64 = 30_000;

/// FIN retransmission timeout floor (RFC 6298 style, reuse RTO baseline)
pub const TCP_FIN_TIMEOUT_MS: u64 = TCP_INITIAL_RTO_MS;

/// Maximum FIN retransmission attempts before giving up
pub const TCP_MAX_FIN_RETRIES: u8 = 5;

/// Maximum SYN backlog per listening socket
pub const TCP_MAX_SYN_BACKLOG: usize = 128;

/// Maximum pending connections per listening socket
pub const TCP_MAX_ACCEPT_BACKLOG: usize = 128;

/// R50-5 FIX: Maximum active TCP connections (all states) to prevent resource exhaustion
pub const TCP_MAX_ACTIVE_CONNECTIONS: usize = 4096;

/// R51-2 FIX: Maximum TCP send size (bounds kernel allocations).
/// Limits per-send payload to 64KB to align with default receive window.
/// Enforced in tcp_send() to protect all send paths from OOM DoS.
pub const TCP_MAX_SEND_SIZE: usize = 64 * 1024;

/// R115-3 FIX: Maximum per-connection buffered TX bytes (4 MB).
///
/// Bounds total memory usage of `send_buffer` per TCP socket. Prevents a sustained
/// sender (especially with peer-controlled large window or delayed ACKs) from growing
/// the buffer without bound. Also bounds worst-case CPU cost of ACK/SACK processing
/// since those iterate the buffer.
pub const TCP_MAX_SEND_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// R158-10 FIX: Explicit per-connection receive buffer cap (256 KB).
///
/// Matches TCP_DEFAULT_RCV_WINDOW_BYTES. The receive window already prevents
/// remote peers from sending more than rcv_wnd bytes, but this constant
/// provides defense-in-depth against OOO drain extending the buffer beyond
/// the advertised window (e.g. after window shrink).
pub const TCP_MAX_RECV_BUFFER_BYTES: usize = 256 * 1024;

// ============================================================================
// Congestion Control Constants (RFC 5681)
// ============================================================================

/// Initial slow-start threshold.
///
/// Set to a large value initially; will be reduced on congestion events.
/// 64KB aligns with the default receive window.
pub const TCP_INITIAL_SSTHRESH: u32 = 64 * 1024;

/// Compute the initial congestion window per RFC 5681 Section 3.1.
///
/// IW = min(4*SMSS, max(2*SMSS, 4380 bytes))
///
/// This formula allows:
/// - At least 2 segments for small MSS
/// - Up to 4 segments for larger MSS
/// - Maximum of ~3 full-size Ethernet segments
#[inline]
pub fn initial_cwnd(smss: u16) -> u32 {
    let smss = smss as u32;
    let four_smss = smss.saturating_mul(4);
    let two_smss = smss.saturating_mul(2);
    core::cmp::min(four_smss, core::cmp::max(two_smss, 4380))
}

// ============================================================================
// TCP Flags
// ============================================================================

/// FIN flag - sender has finished sending
pub const TCP_FLAG_FIN: u8 = 0x01;
/// SYN flag - synchronize sequence numbers
pub const TCP_FLAG_SYN: u8 = 0x02;
/// RST flag - reset the connection
pub const TCP_FLAG_RST: u8 = 0x04;
/// PSH flag - push function
pub const TCP_FLAG_PSH: u8 = 0x08;
/// ACK flag - acknowledgment field is significant
pub const TCP_FLAG_ACK: u8 = 0x10;
/// URG flag - urgent pointer field is significant
pub const TCP_FLAG_URG: u8 = 0x20;
/// ECE flag - ECN-Echo (RFC 3168)
pub const TCP_FLAG_ECE: u8 = 0x40;
/// CWR flag - Congestion Window Reduced (RFC 3168)
pub const TCP_FLAG_CWR: u8 = 0x80;

// ============================================================================
// TCP State Machine
// ============================================================================

/// TCP connection state per RFC 793
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection state at all
    Closed,
    /// Waiting for a connection request from any remote TCP
    Listen,
    /// Waiting for a matching connection request after having sent one
    SynSent,
    /// Waiting for confirming connection request acknowledgment
    SynReceived,
    /// Open connection, data can be exchanged
    Established,
    /// Waiting for a connection termination request from remote TCP
    /// (after local close)
    FinWait1,
    /// Waiting for a connection termination request from remote TCP
    FinWait2,
    /// Waiting for a connection termination request from local user
    CloseWait,
    /// Waiting for connection termination request acknowledgment from remote TCP
    Closing,
    /// Waiting for acknowledgment of connection termination request
    LastAck,
    /// Waiting for enough time to pass to be sure remote TCP received
    /// acknowledgment of its connection termination request
    TimeWait,
}

impl TcpState {
    /// Check if the connection is in an established or semi-established state
    pub fn can_send(&self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }

    /// Check if the connection can receive data
    ///
    /// R145-3 FIX: Include CloseWait — the receive buffer may still contain
    /// data buffered before the peer's FIN.  POSIX requires recv() to drain
    /// the buffer and then return 0 (EOF) in CLOSE_WAIT.
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait
        )
    }

    /// Check if the connection is closed or closing
    pub fn is_closed(&self) -> bool {
        matches!(self, TcpState::Closed | TcpState::TimeWait)
    }

    /// Check if the connection is synchronized (after handshake)
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
        )
    }
}

// ============================================================================
// Congestion Control State Machine (RFC 5681)
// ============================================================================

/// Congestion control state per RFC 5681.
///
/// TCP congestion control operates in one of three phases:
/// - Slow Start: Exponential growth of cwnd until ssthresh is reached
/// - Congestion Avoidance: Linear growth after ssthresh
/// - Fast Recovery: Entered after triple duplicate ACK
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpCongestionState {
    /// Exponential cwnd growth (cwnd < ssthresh).
    ///
    /// On each ACK: cwnd += min(N, SMSS) where N is newly acked bytes.
    SlowStart,

    /// Linear cwnd growth (cwnd >= ssthresh).
    ///
    /// On each ACK: cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT).
    CongestionAvoidance,

    /// Fast recovery after triple duplicate ACK (RFC 5681 Section 3.2).
    ///
    /// ssthresh = max(FlightSize/2, 2*SMSS)
    /// cwnd = ssthresh + 3*SMSS (inflate for segments in flight)
    /// Retransmit the first unacked segment.
    FastRecovery,
}

impl Default for TcpCongestionState {
    fn default() -> Self {
        Self::SlowStart
    }
}

/// Result of ACK processing for congestion control decisions.
#[derive(Debug, Default, Clone, Copy)]
pub struct AckUpdate {
    /// Number of newly acknowledged bytes (0 for duplicate ACK).
    pub newly_acked: u32,
    /// True if this ACK did not advance snd_una (duplicate ACK).
    pub duplicate: bool,
}

/// Actions that congestion control may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAction {
    /// No immediate transmission change needed.
    None,
    /// Trigger fast retransmit of the first unacknowledged segment.
    FastRetransmit,
    /// R56-1: RFC 3042 Limited Transmit - request sending new data on early dup ACKs.
    ///
    /// On the first or second duplicate ACK (before fast retransmit threshold),
    /// if FlightSize + SMSS <= cwnd + 2*SMSS, send one new segment to help
    /// drive fast retransmit on small-window connections.
    LimitedTransmit,
    /// Retransmit next unacknowledged segment after partial ACK (NewReno).
    ///
    /// R55-1: NewReno partial ACK handling - stay in fast recovery and
    /// retransmit the next unacked segment instead of exiting FR.
    RetransmitNext,
}

// ============================================================================
// TCP Header
// ============================================================================

/// Parsed TCP header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number (valid if ACK flag set)
    pub ack_num: u32,
    /// Data offset in 32-bit words (5-15)
    pub data_offset: u8,
    /// Reserved bits (must be zero)
    pub reserved: u8,
    /// Control flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
    pub flags: u8,
    /// Receive window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer (valid if URG flag set)
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Create a new TCP header with the given parameters
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        window: u16,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset: 5, // No options, 20 bytes
            reserved: 0,
            flags,
            window,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Get the header length in bytes
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_FLAG_SYN != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & TCP_FLAG_ACK != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FLAG_FIN != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & TCP_FLAG_RST != 0
    }

    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        self.flags & TCP_FLAG_PSH != 0
    }

    /// Serialize header to bytes (without checksum)
    pub fn to_bytes(&self) -> [u8; TCP_HEADER_MIN_LEN] {
        let mut bytes = [0u8; TCP_HEADER_MIN_LEN];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        // Data offset (4 bits) + reserved (4 bits)
        bytes[12] = (self.data_offset << 4) | (self.reserved & 0x0F);
        bytes[13] = self.flags;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes
    }
}

// ============================================================================
// TCP Options
// ============================================================================

/// Maximum number of SACK blocks in a single TCP option (RFC 2018).
///
/// Each block is 8 bytes (left_edge + right_edge). With 40 bytes of option
/// space and kind(1) + length(1) overhead, at most 4 blocks fit without
/// other variable-length options. We cap at 4 to avoid heap allocation
/// in the RX hot path.
pub const TCP_SACK_MAX_BLOCKS: usize = 4;

/// A single SACK block representing a contiguous range of received bytes.
///
/// Per RFC 2018, each block describes bytes `[left_edge, right_edge)` that
/// have been received out of order. `left_edge` is the first sequence number
/// of the block; `right_edge` is the sequence number immediately following
/// the last byte in the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    /// First sequence number of the contiguous block
    pub left_edge: u32,
    /// Sequence number immediately past the last byte in the block
    pub right_edge: u32,
}

/// Allocation-free bounded SACK block collection.
///
/// RF180-41 REVIEW FIX: wire-controlled SACK parsing and scoreboard scratch
/// never need heap storage: the TCP option space can encode at most four
/// blocks. Keeping the exact protocol maximum inline eliminates both retained
/// and transient attacker-driven allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlocks {
    blocks: [SackBlock; TCP_SACK_MAX_BLOCKS],
    len: u8,
}

impl SackBlocks {
    /// Create an empty bounded collection.
    pub const fn new() -> Self {
        Self {
            blocks: [SackBlock {
                left_edge: 0,
                right_edge: 0,
            }; TCP_SACK_MAX_BLOCKS],
            len: 0,
        }
    }

    /// Number of present blocks.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether no blocks are present.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow the initialized prefix.
    pub fn as_slice(&self) -> &[SackBlock] {
        &self.blocks[..self.len()]
    }

    /// Append one block if protocol capacity remains.
    pub fn push(&mut self, block: SackBlock) -> bool {
        let index = self.len();
        if index >= TCP_SACK_MAX_BLOCKS {
            return false;
        }
        self.blocks[index] = block;
        self.len += 1;
        true
    }

    /// Iterate initialized blocks.
    pub fn iter(&self) -> core::slice::Iter<'_, SackBlock> {
        self.as_slice().iter()
    }
}

impl Default for SackBlocks {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for SackBlocks {
    type Target = [SackBlock];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// TCP option kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOptionKind {
    /// End of option list
    EndOfList,
    /// No-operation (padding)
    Nop,
    /// Maximum Segment Size
    Mss(u16),
    /// Window Scale (RFC 7323)
    WindowScale(u8),
    /// Selective Acknowledgment Permitted (RFC 2018)
    SackPermitted,
    /// Selective Acknowledgment blocks (RFC 2018, kind=5)
    Sack(SackBlocks),
    /// Timestamps (RFC 7323)
    Timestamps { ts_val: u32, ts_ecr: u32 },
    /// Unknown option
    Unknown { kind: u8, len: u8 },
}

/// Parsed TCP options
#[derive(Debug, Clone, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size
    pub mss: Option<u16>,
    /// Window Scale factor
    pub window_scale: Option<u8>,
    /// SACK permitted (kind=4, SYN/SYN-ACK only)
    pub sack_permitted: bool,
    /// SACK blocks (kind=5, data segments and ACKs)
    pub sack_blocks: SackBlocks,
    /// Timestamps
    pub timestamps: Option<(u32, u32)>,
}

// ============================================================================
// TCP Option Serialization
// ============================================================================

/// Serialize a single TCP option to bytes.
///
/// Returns the raw bytes for the option, including kind and length fields
/// where applicable. Single-byte options (End, NOP) return just the kind byte.
///
#[inline]
fn tcp_option_wire_len(option: &TcpOptionKind) -> usize {
    match option {
        TcpOptionKind::EndOfList | TcpOptionKind::Nop => 1,
        TcpOptionKind::Mss(_) => 4,
        TcpOptionKind::WindowScale(_) => 3,
        TcpOptionKind::SackPermitted => 2,
        TcpOptionKind::Sack(blocks) => 2 + 8 * blocks.len().min(TCP_SACK_MAX_BLOCKS),
        TcpOptionKind::Timestamps { .. } => 10,
        TcpOptionKind::Unknown { len, .. } => usize::from((*len).max(2)),
    }
}

fn write_tcp_option(option: &TcpOptionKind, output: &mut [u8]) -> usize {
    let len = tcp_option_wire_len(option);
    debug_assert!(output.len() >= len);
    match option {
        TcpOptionKind::EndOfList => output[0] = 0,
        TcpOptionKind::Nop => output[0] = 1,
        TcpOptionKind::Mss(mss) => {
            output[0..2].copy_from_slice(&[2, 4]);
            output[2..4].copy_from_slice(&mss.to_be_bytes());
        }
        TcpOptionKind::WindowScale(scale) => output[0..3].copy_from_slice(&[3, 3, *scale]),
        TcpOptionKind::SackPermitted => output[0..2].copy_from_slice(&[4, 2]),
        TcpOptionKind::Sack(blocks) => {
            output[0] = 5;
            output[1] = len as u8;
            let mut offset = 2;
            for block in blocks.iter().take(TCP_SACK_MAX_BLOCKS) {
                output[offset..offset + 4].copy_from_slice(&block.left_edge.to_be_bytes());
                output[offset + 4..offset + 8].copy_from_slice(&block.right_edge.to_be_bytes());
                offset += 8;
            }
        }
        TcpOptionKind::Timestamps { ts_val, ts_ecr } => {
            output[0..2].copy_from_slice(&[8, 10]);
            output[2..6].copy_from_slice(&ts_val.to_be_bytes());
            output[6..10].copy_from_slice(&ts_ecr.to_be_bytes());
        }
        TcpOptionKind::Unknown { kind, .. } => {
            output[..len].fill(0);
            output[0] = *kind;
            output[1] = len as u8;
        }
    }
    len
}

/// RF180-41 FIX: one option serialization owns an admitted wire allocation for
/// its complete lifetime. No intermediate uncharged `Vec` is constructed.
pub fn serialize_tcp_option(option: &TcpOptionKind) -> WirePacket {
    let len = tcp_option_wire_len(option);
    let mut bytes = match WirePacket::try_zeroed(len) {
        Ok(bytes) => bytes,
        Err(_) => return WirePacket::new(),
    };
    write_tcp_option(option, bytes.as_mut_slice());
    bytes
}

/// Serialize a slice of TCP options with padding to 32-bit boundary.
///
/// This function:
/// 1. Serializes each option in order
/// 2. Appends End-of-List marker if not already present
/// 3. Pads with NOP (0x00) bytes to ensure 32-bit alignment
///
/// Returns an empty packet if no options are provided (no padding needed for
/// the minimal header), or if aggregate admission rejects the allocation.
///
/// R163-10 FIX: TCP options are bounded by TCP_HEADER_MAX_LEN (60) minus the
/// minimum header (20), leaving at most 40 bytes of option space.
///
/// Safety guarantees:
/// - The complete bounded option block is serialized into a 40-byte stack
///   scratch buffer, so serialization performs no heap growth.
/// - Every option is length-checked against the remaining option space before
///   it is written; EOL and alignment padding remain within the same bound.
/// - The public serializer performs one admitted final allocation and returns
///   an empty packet if aggregate admission or allocation fails.
fn serialize_tcp_options_into(options: &[TcpOptionKind], output: &mut [u8; 40]) -> usize {
    if options.is_empty() {
        return 0;
    }

    let max_opts = TCP_HEADER_MAX_LEN - TCP_HEADER_MIN_LEN;
    let mut used = 0usize;
    let mut has_end = false;

    for opt in options {
        let option_len = tcp_option_wire_len(opt);
        let Some(end) = used.checked_add(option_len) else {
            break;
        };
        if end > max_opts {
            break;
        }
        write_tcp_option(opt, &mut output[used..end]);
        used = end;

        if matches!(opt, TcpOptionKind::EndOfList) {
            has_end = true;
            break;
        }
    }

    // Append End-of-List if not present and space permits.
    if !has_end && used < max_opts {
        output[used] = 0;
        used += 1;
    }

    let padded = (used + 3) & !3;
    output[used..padded].fill(0);
    padded
}

pub fn serialize_tcp_options(options: &[TcpOptionKind]) -> WirePacket {
    let mut scratch = [0u8; TCP_HEADER_MAX_LEN - TCP_HEADER_MIN_LEN];
    let len = serialize_tcp_options_into(options, &mut scratch);
    if len == 0 {
        return WirePacket::new();
    }
    WirePacket::try_copy_from_slice(&scratch[..len]).unwrap_or_default()
}

// ============================================================================
// TCP Control Block (TCB)
// ============================================================================

/// 4-tuple connection key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnKey {
    /// Local IP address
    pub local_ip: Ipv4Addr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_ip: Ipv4Addr,
    /// Remote port
    pub remote_port: u16,
}

impl TcpConnKey {
    /// Create a new connection key
    pub fn new(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }

    /// Create the reverse key (for matching incoming packets)
    pub fn reverse(&self) -> Self {
        Self {
            local_ip: self.remote_ip,
            local_port: self.remote_port,
            remote_ip: self.local_ip,
            remote_port: self.local_port,
        }
    }
}

/// Provisional SYN-SENT transition committed only after the generated TCP
/// response has passed egress policy and entered the device queue.
///
/// RF180-41 REVIEW FIX: the receive path may prepare the final ACK or a
/// simultaneous-open SYN-ACK, but it must not report `Established`/`SynReceived`
/// to socket observers while that response can still be dropped. Retransmitted
/// peer handshakes may safely replace this plain, allocation-free snapshot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingHandshakeCommit {
    pub response_flags: u8,
    pub response_seq: u32,
    pub response_ack: u32,
    pub target_state: TcpState,
    pub irs: u32,
    pub rcv_nxt: u32,
    pub ack_to_apply: Option<(u32, u64)>,
    pub snd_wscale: u8,
    pub wscale_received: bool,
    pub sack_received: bool,
    pub snd_mss: u16,
    pub cwnd: u32,
    pub snd_wnd: u32,
    pub snd_wl1: u32,
    pub snd_wl2: Option<u32>,
    pub rcv_wnd: u32,
    pub wake_connect: bool,
}

/// TCP Control Block - per-connection state
pub struct TcpControlBlock {
    /// Connection state
    pub state: TcpState,

    /// Connection key (4-tuple)
    pub key: TcpConnKey,

    // === Send Sequence Space (RFC 793 Section 3.2) ===
    /// Initial Send Sequence Number
    pub iss: u32,
    /// Send Unacknowledged - oldest unacknowledged sequence number
    pub snd_una: u32,
    /// Send Next - next sequence number to send
    pub snd_nxt: u32,
    /// Send Window - send window size
    pub snd_wnd: u32,
    /// Segment sequence number used for last window update
    pub snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    pub snd_wl2: u32,

    // === Congestion Control (RFC 5681) ===
    /// Congestion window in bytes.
    ///
    /// Limits the amount of data that can be in flight (unacknowledged).
    /// Initialized to IW = min(4*MSS, max(2*MSS, 4380)).
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    ///
    /// When cwnd < ssthresh: slow start (exponential growth).
    /// When cwnd >= ssthresh: congestion avoidance (linear growth).
    pub ssthresh: u32,
    /// Duplicate ACK counter for fast retransmit detection.
    ///
    /// Incremented on each duplicate ACK; reset on new data ACK.
    /// Fast retransmit triggered when dup_ack_count reaches 3.
    pub dup_ack_count: u8,
    /// Current congestion control state.
    pub congestion_state: TcpCongestionState,
    /// R55-1: Recovery point for NewReno partial ACK handling.
    ///
    /// Set to snd_nxt when entering fast recovery. A full ACK (ack >= recover)
    /// exits fast recovery; a partial ACK (ack < recover) triggers retransmit
    /// of the next unacked segment while staying in fast recovery.
    pub recover: u32,

    // === Receive Sequence Space ===
    /// Initial Receive Sequence Number
    pub irs: u32,
    /// Receive Next - next sequence number expected
    pub rcv_nxt: u32,
    /// Receive Window - receive window size
    pub rcv_wnd: u32,

    // === Segment Size ===
    /// Maximum Segment Size for sending
    pub snd_mss: u16,
    /// Maximum Segment Size for receiving
    pub rcv_mss: u16,

    // === Window Scaling (RFC 7323) ===
    /// Send window scale factor (shift count for peer's advertised window).
    /// Applied when decoding peer's window advertisements.
    pub snd_wscale: u8,
    /// Receive window scale factor (shift count for our advertised window).
    /// Applied when encoding our window advertisements.
    pub rcv_wscale: u8,
    /// True if we sent Window Scale option in our SYN/SYN-ACK.
    pub wscale_requested: bool,
    /// True if peer sent Window Scale option in their SYN/SYN-ACK.
    pub wscale_received: bool,

    // === SACK (RFC 2018 / RFC 6675) ===
    /// True if we sent SACK-Permitted in our SYN/SYN-ACK.
    pub sack_requested: bool,
    /// True if peer sent SACK-Permitted in their SYN/SYN-ACK.
    pub sack_received: bool,
    /// Highest SACKed sequence number seen from peer (for RFC 6675 loss detection).
    pub highest_sacked: u32,
    /// Number of bytes currently buffered in the OOO queue (for window accounting).
    pub ooo_bytes: u32,

    // === Retransmission State ===
    /// Current retransmission timeout in milliseconds
    pub rto_ms: u64,
    /// Smoothed Round-Trip Time (SRTT) in microseconds
    pub srtt_us: u64,
    /// RTT variance (RTTVAR) in microseconds
    pub rttvar_us: u64,
    /// Number of consecutive retransmissions
    pub retries: u8,
    /// Prepared active/simultaneous handshake state awaiting actual egress.
    pub(crate) pending_handshake: Option<PendingHandshakeCommit>,
    /// Single packet/socket operation token that owns the pending handshake
    /// publication. A retransmitted peer handshake replaces this token and
    /// makes every older prepared packet stale before it can reach the device.
    pub(crate) pending_reply_token: Option<u64>,
    /// Initial active SYN has been prepared and registered but has not yet
    /// crossed the device acceptance boundary. The externally visible TCP
    /// state remains Closed until the exact token commits.
    pub(crate) active_open_pending: bool,
    /// Distinguishes listener-owned children from simultaneous-open clients in
    /// SYN-RECEIVED so only passive children move through the accept queues.
    pub(crate) passive_open: bool,
    /// A passive-open child is staged but cannot accept the third ACK until its
    /// SYN-ACK has actually entered the egress queue.
    pub(crate) passive_egress_confirmed: bool,

    // === Buffers ===
    /// Send buffer (unacknowledged segments)
    pub(crate) send_buffer: AdmittedVec<TcpSegment>,
    /// R115-3 FIX: Total bytes currently buffered in `send_buffer`.
    /// Maintained by tcp_send() (increment) and handle_ack() (decrement).
    /// Bounded by `TCP_MAX_SEND_BUFFER_BYTES` to prevent OOM.
    pub send_buffer_bytes: usize,
    /// J2-6 (Phase J.2 per-tenant quotas): per-TCB mirror of how many send bytes
    /// THIS connection currently has charged to its namespace's aggregate
    /// `per_ns_send_bytes` budget. Kept equal to `send_buffer_bytes` by the
    /// socket layer's reconcile (charge at tcp_send, uncharge via handle_ack). The
    /// teardown path uncharges exactly this amount, so an abruptly-freed TCB
    /// cannot leak per-namespace TX accounting. Init 0; never mutated by tcp.rs.
    pub ns_charged_send_bytes: usize,
    /// J2-4 (Phase J.2 per-tenant quotas): per-TCB mirror of how many recv bytes
    /// THIS connection currently has charged to its namespace's aggregate
    /// `per_ns_recv_bytes` budget. The recv footprint is F = recv_buffer.len() +
    /// ooo_bytes; this mirror is kept equal to F by the socket layer's
    /// reconcile_ns_recv after every F-mutation, so teardown uncharges exactly this
    /// amount. Init 0; never mutated by tcp.rs (only the socket layer).
    pub ns_charged_recv_bytes: usize,
    /// Receive buffer (in-order data)
    pub(crate) recv_buffer: AdmittedVec<u8>,
    /// Out-of-order receive queue (sorted by sequence number)
    pub(crate) ooo_queue: AdmittedVec<OooSegment>,

    // === Flags ===
    /// FIN has been sent
    pub fin_sent: bool,
    /// Timestamp when FIN was last sent (for retransmission timer)
    pub fin_sent_time: u64,
    /// FIN retransmission counter
    pub fin_retries: u8,
    /// A prepared FIN retry currently has sole ownership of the egress attempt.
    pub(crate) fin_retransmit_in_flight: bool,
    /// FIN has been received
    pub fin_received: bool,
    /// ACK is pending (delayed ACK)
    pub ack_pending: bool,

    // === Timestamps ===
    /// Connection established timestamp (for TIME-WAIT)
    pub established_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// TIME_WAIT start timestamp (for 2MSL timer)
    pub time_wait_start: u64,
    /// R65-5 FIX: FIN_WAIT_2 start timestamp (for idle timeout)
    pub fin_wait2_start: u64,

    // === R148-I3 FIX: TCP Keepalive ===
    /// Whether keepalive probes are enabled for this connection.
    pub keepalive_enabled: bool,
    /// Idle time before first keepalive probe (default: 7200s = 2 hours, per RFC 1122).
    pub keepalive_idle_ms: u64,
    /// Interval between successive keepalive probes (default: 75s).
    pub keepalive_interval_ms: u64,
    /// Maximum number of unacknowledged probes before declaring connection dead (default: 9).
    pub keepalive_probes_max: u8,
    /// Number of keepalive probes sent without receiving a response.
    pub keepalive_probes_sent: u8,
    /// Monotonic (wrapping) generation advanced for every accepted peer ACK.
    /// Timer completion uses it to avoid counting a probe whose ACK raced the
    /// post-device metadata commit.
    pub(crate) peer_ack_generation: u64,
    /// A keepalive probe is prepared and awaiting its queue result.
    pub(crate) keepalive_probe_in_flight: bool,
}

/// A TCP segment for buffering
#[derive(Debug)]
pub struct TcpSegment {
    /// Sequence number of first byte
    pub seq: u32,
    /// Segment data
    pub(crate) data: AdmittedVec<u8>,
    /// Timestamp when segment was sent (for RTT)
    pub sent_at: u64,
    /// Number of times retransmitted
    pub retrans_count: u8,
    /// SACK scoreboard: this segment has been selectively acknowledged by the peer
    pub sacked: bool,
    /// SACK scoreboard: this segment has been marked as lost (RFC 6675)
    pub lost: bool,
    /// RF180-41 REVIEW FIX: a NewReno/SACK retransmission whose wire-owner
    /// preparation failed remains explicitly scheduled. Timer/ACK paths retry
    /// it without pretending a transmission occurred or waiting for its RTO.
    pub retransmit_pending: bool,
    /// Exactly one prepared egress attempt owns this segment's retry commit.
    pub retransmit_in_flight: bool,
    /// The pending attempt originated at RTO and must apply loss recovery only
    /// after a successful device queue operation.
    pub retransmit_requires_rto: bool,
    /// Consecutive device/policy rejections for this segment's retransmission.
    pub(crate) tx_reject_count: u8,
    /// Monotonic time before which ACK/timer recovery must not select it.
    pub(crate) retry_not_before_ms: u64,
}

impl TcpSegment {
    #[inline]
    pub(crate) fn retry_due(&self, now_ms: u64) -> bool {
        now_ms >= self.retry_not_before_ms
    }

    pub(crate) fn record_tx_rejection(&mut self, now_ms: u64) {
        const BASE_MS: u64 = 10;
        const MAX_MS: u64 = 1_000;
        self.tx_reject_count = self.tx_reject_count.saturating_add(1);
        let shift = self.tx_reject_count.saturating_sub(1).min(7) as u32;
        let delay = BASE_MS.checked_shl(shift).unwrap_or(MAX_MS).min(MAX_MS);
        self.retry_not_before_ms = now_ms.saturating_add(delay);
    }

    pub(crate) fn clear_tx_rejection(&mut self) {
        self.tx_reject_count = 0;
        self.retry_not_before_ms = 0;
    }
}

/// Maximum number of out-of-order segments buffered per connection.
///
/// Bounds CPU cost of OOO insertion/merge and prevents memory exhaustion
/// from adversarial tiny-segment floods. 64 segments × ~1460 bytes ≈ 93 KB
/// which is within the default receive window.
pub const TCP_OOO_MAX_SEGMENTS: usize = 64;

/// A contiguous range of out-of-order received data.
///
/// Unlike `TcpSegment` (TX-oriented), this is RX-only and carries no
/// retransmission metadata.
#[derive(Debug)]
pub struct OooSegment {
    /// First sequence number of this contiguous range
    pub seq: u32,
    /// Contiguous received data
    pub(crate) data: AdmittedVec<u8>,
    /// R133-3 FIX: True if this segment carries a FIN at the end of the data.
    /// FIN occupies one sequence number after the data payload.
    pub fin: bool,
}

impl TcpControlBlock {
    /// Create a new TCB for an outgoing connection (client)
    pub fn new_client(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
    ) -> Self {
        Self {
            state: TcpState::Closed,
            key: TcpConnKey::new(local_ip, local_port, remote_ip, remote_port),
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            cwnd: initial_cwnd(TCP_DEFAULT_MSS),
            ssthresh: TCP_INITIAL_SSTHRESH,
            dup_ack_count: 0,
            congestion_state: TcpCongestionState::SlowStart,
            recover: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: TCP_DEFAULT_RCV_WINDOW_BYTES,
            snd_mss: TCP_DEFAULT_MSS,
            rcv_mss: TCP_ETHERNET_MSS,
            snd_wscale: 0,
            rcv_wscale: 0,
            wscale_requested: false,
            wscale_received: false,
            sack_requested: false,
            sack_received: false,
            highest_sacked: iss,
            ooo_bytes: 0,
            rto_ms: TCP_INITIAL_RTO_MS,
            srtt_us: 0,
            rttvar_us: 0,
            retries: 0,
            pending_handshake: None,
            pending_reply_token: None,
            active_open_pending: false,
            passive_open: false,
            passive_egress_confirmed: true,
            send_buffer: AdmittedVec::new(HeapClass::SocketPayload),
            send_buffer_bytes: 0,
            ns_charged_send_bytes: 0,
            ns_charged_recv_bytes: 0,
            recv_buffer: AdmittedVec::new(HeapClass::SocketPayload),
            ooo_queue: AdmittedVec::new(HeapClass::SocketPayload),
            fin_sent: false,
            fin_sent_time: 0,
            fin_retries: 0,
            fin_retransmit_in_flight: false,
            fin_received: false,
            ack_pending: false,
            established_at: 0,
            last_activity: 0,
            time_wait_start: 0,
            fin_wait2_start: 0,
            // R148-I3 FIX: TCP keepalive defaults per RFC 1122 §4.2.3.6.
            // Disabled by default; applications opt in via socket option.
            keepalive_enabled: false,
            keepalive_idle_ms: 7_200_000,  // 2 hours
            keepalive_interval_ms: 75_000, // 75 seconds
            keepalive_probes_max: 9,
            keepalive_probes_sent: 0,
            peer_ack_generation: 0,
            keepalive_probe_in_flight: false,
        }
    }

    /// Create a new TCB for an incoming connection (server)
    pub fn new_server(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
        irs: u32,
    ) -> Self {
        let mut tcb = Self::new_client(local_ip, local_port, remote_ip, remote_port, iss);
        tcb.irs = irs;
        tcb.rcv_nxt = irs.wrapping_add(1);
        // R146-NET-1 FIX: Advance snd_nxt past the SYN-ACK sequence number.
        // Per RFC 793, sending SYN-ACK consumes one sequence number, so
        // snd_nxt must be ISS+1. Without this, the SynReceived handler's
        // `ack_num == snd_nxt` check rejects compliant clients that send
        // ack_num = ISS+1, breaking all stateful TCP passive opens.
        tcb.snd_nxt = iss.wrapping_add(1);
        tcb.state = TcpState::SynReceived;
        tcb.passive_open = true;
        tcb.passive_egress_confirmed = false;
        tcb
    }

    /// Create a TCB for a listening socket without a peer.
    ///
    /// R51-1: Used for TCP passive open (listen/accept).
    pub fn new_listen(local_ip: Ipv4Addr, local_port: u16) -> Self {
        let mut tcb = Self::new_client(local_ip, local_port, Ipv4Addr([0, 0, 0, 0]), 0, 0);
        tcb.state = TcpState::Listen;
        tcb
    }

    /// Check if there is unsent or unacknowledged data
    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty() || self.snd_una != self.snd_nxt
    }

    /// Bytes currently in flight (unacknowledged data).
    ///
    /// FlightSize = snd_nxt - snd_una
    #[inline]
    pub fn bytes_in_flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// Get the amount of data available to read
    pub fn available_data(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Calculate available send window respecting both peer window and cwnd.
    ///
    /// The effective send window is min(snd_wnd, cwnd) - bytes_in_flight.
    /// This ensures congestion control limits sending even when the peer
    /// advertises a large window.
    pub fn send_window_available(&self) -> u32 {
        let bytes_in_flight = self.bytes_in_flight();
        // Effective window is minimum of peer's advertised window and cwnd
        // Ensure cwnd is at least 1 MSS to allow progress
        let effective_wnd = core::cmp::min(self.snd_wnd, self.cwnd.max(self.snd_mss as u32));
        effective_wnd.saturating_sub(bytes_in_flight)
    }

    /// Check if window scaling is enabled for this connection.
    ///
    /// Window scaling is only active if both sides exchanged WSopt during handshake.
    #[inline]
    pub fn wscale_enabled(&self) -> bool {
        self.wscale_requested && self.wscale_received
    }

    /// Get effective send window scale (0 if scaling not enabled).
    #[inline]
    pub fn effective_snd_wscale(&self) -> u8 {
        if self.wscale_enabled() {
            self.snd_wscale
        } else {
            0
        }
    }

    /// Get effective receive window scale (0 if scaling not enabled).
    #[inline]
    pub fn effective_rcv_wscale(&self) -> u8 {
        if self.wscale_enabled() {
            self.rcv_wscale
        } else {
            0
        }
    }

    /// Check if SACK is enabled for this connection (RFC 2018).
    ///
    /// SACK is active only if both sides exchanged SACK-Permitted during the
    /// SYN/SYN-ACK handshake.
    #[inline]
    pub fn sack_enabled(&self) -> bool {
        self.sack_requested && self.sack_received
    }

    /// Insert an out-of-order segment into the OOO queue.
    ///
    /// Maintains the queue sorted by sequence number. Overlapping and adjacent
    /// segments are merged to keep the queue compact. Enforces a hard cap on
    /// the number of entries (`TCP_OOO_MAX_SEGMENTS`) to bound CPU/memory cost.
    ///
    /// Returns the byte length of the final merged segment that was inserted.
    /// This may exceed the input `data.len()` if existing segments were merged.
    pub fn ooo_insert(&mut self, seq: u32, data: &[u8], fin: bool) -> u32 {
        if data.is_empty() && !fin {
            return 0;
        }

        // R113-2 FIX: Enforce advertised receive window for OOO buffering.
        // Without this check, an attacker can send OOO segments that exceed the
        // advertised window, inflating per-connection memory unboundedly.
        let consumed = (self.recv_buffer.len() as u32).saturating_add(self.ooo_bytes);
        let available = self.rcv_wnd.saturating_sub(consumed);
        if available == 0 {
            return 0;
        }

        // Trim payload to the remaining window budget so a single large
        // OOO segment cannot overshoot the advertised receive window.
        // R133-3 FIX: If we trim, drop FIN because it is beyond the retained bytes.
        let (data, fin) = if (data.len() as u32) > available {
            (&data[..available as usize], false)
        } else {
            (data, fin)
        };

        // R180-11 FIX: copy the incoming payload privately first. Queue growth
        // is prepared only after we know whether existing entries will be
        // removed by the merge (a full queue can still absorb an overlap).
        let seg_data = match AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, data) {
            Ok(data) => data,
            Err(_) => return 0,
        };

        // Compute the complete transitive merge span without mutating the live
        // queue. Repeated scans are intentional: an overlap discovered to the
        // left can make an earlier, previously skipped range newly adjacent.
        // TCP_OOO_MAX_SEGMENTS bounds this O(n²) preflight.
        let mut merged_start = seq;
        let mut merged_data_end = seq.wrapping_add(seg_data.len() as u32);
        let mut merged_fin_pos = fin.then_some(merged_data_end);
        loop {
            let mut changed = false;
            for existing in &self.ooo_queue {
                let ex_data_end = existing.seq.wrapping_add(existing.data.len() as u32);
                let ex_seq_end = ex_data_end.wrapping_add(if existing.fin { 1 } else { 0 });
                let merged_seq_end =
                    merged_data_end.wrapping_add(if merged_fin_pos.is_some() { 1 } else { 0 });
                if !seq_le(merged_start, ex_seq_end) || !seq_le(existing.seq, merged_seq_end) {
                    continue;
                }

                let old_start = merged_start;
                let old_end = merged_data_end;
                let old_fin = merged_fin_pos;
                if seq_le(existing.seq, merged_start) {
                    merged_start = existing.seq;
                }
                if seq_ge(ex_data_end, merged_data_end) {
                    merged_data_end = ex_data_end;
                }
                if existing.fin {
                    merged_fin_pos = match merged_fin_pos {
                        Some(current) if seq_le(current, ex_data_end) => Some(current),
                        _ => Some(ex_data_end),
                    };
                }
                if let Some(fin_pos) = merged_fin_pos {
                    if seq_lt(fin_pos, merged_data_end) {
                        merged_data_end = fin_pos;
                    }
                }
                changed |= old_start != merged_start
                    || old_end != merged_data_end
                    || old_fin != merged_fin_pos;
            }
            if !changed {
                break;
            }
        }

        let merged_seq_end =
            merged_data_end.wrapping_add(if merged_fin_pos.is_some() { 1 } else { 0 });
        let overlaps = self
            .ooo_queue
            .iter()
            .filter(|existing| {
                let ex_data_end = existing.seq.wrapping_add(existing.data.len() as u32);
                let ex_seq_end = ex_data_end.wrapping_add(if existing.fin { 1 } else { 0 });
                seq_le(merged_start, ex_seq_end) && seq_le(existing.seq, merged_seq_end)
            })
            .count();

        let final_entries = self
            .ooo_queue
            .len()
            .saturating_sub(overlaps)
            .saturating_add(1);
        if final_entries > TCP_OOO_MAX_SEGMENTS {
            return 0;
        }
        if final_entries > self.ooo_queue.len() && self.ooo_queue.ensure_capacity_for(1).is_err() {
            return 0;
        }

        // Allocate and populate the complete replacement payload before the
        // first removal. Existing bytes are copied first and the newly received
        // bytes overwrite overlaps, preserving the prior merge semantics.
        let new_seg = if overlaps == 0 {
            OooSegment {
                seq,
                data: seg_data,
                fin,
            }
        } else {
            let merged_len = merged_data_end.wrapping_sub(merged_start) as usize;
            let mut merged_data =
                match AdmittedVec::try_zeroed(HeapClass::SocketPayload, merged_len) {
                    Ok(data) => data,
                    Err(_) => return 0,
                };
            for existing in &self.ooo_queue {
                let ex_data_end = existing.seq.wrapping_add(existing.data.len() as u32);
                let ex_seq_end = ex_data_end.wrapping_add(if existing.fin { 1 } else { 0 });
                if !seq_le(merged_start, ex_seq_end) || !seq_le(existing.seq, merged_seq_end) {
                    continue;
                }
                let offset = existing.seq.wrapping_sub(merged_start) as usize;
                if offset < merged_len {
                    let len = existing.data.len().min(merged_len.saturating_sub(offset));
                    merged_data.as_mut_slice()[offset..offset + len]
                        .copy_from_slice(&existing.data.as_slice()[..len]);
                }
            }
            let new_offset = seq.wrapping_sub(merged_start) as usize;
            if new_offset < merged_len {
                let len = seg_data.len().min(merged_len.saturating_sub(new_offset));
                merged_data.as_mut_slice()[new_offset..new_offset + len]
                    .copy_from_slice(&seg_data.as_slice()[..len]);
            }
            // The complete replacement now owns the incoming bytes. Release
            // the private preflight copy before live entries are removed so
            // peak SocketPayload admission is bounded to the true transaction.
            drop(seg_data);
            OooSegment {
                seq: merged_start,
                data: merged_data,
                fin: merged_fin_pos.is_some(),
            }
        };

        // All fallible work is complete. Remove every member of the final merge
        // set, then publish the single replacement allocation-free.
        let mut removed_bytes = 0u32;
        let mut i = 0;
        while i < self.ooo_queue.len() {
            let existing = &self.ooo_queue[i];
            let ex_data_end = existing.seq.wrapping_add(existing.data.len() as u32);
            let ex_seq_end = ex_data_end.wrapping_add(if existing.fin { 1 } else { 0 });
            if seq_le(merged_start, ex_seq_end) && seq_le(existing.seq, merged_seq_end) {
                let removed = self.ooo_queue.remove(i).unwrap();
                removed_bytes = removed_bytes.saturating_add(removed.data.len() as u32);
            } else {
                i += 1;
            }
        }

        // Find insertion position (sorted by sequence number)
        let pos = self
            .ooo_queue
            .iter()
            .position(|s| seq_gt(s.seq, new_seg.seq))
            .unwrap_or(self.ooo_queue.len());

        let new_bytes = new_seg.data.len() as u32;

        self.ooo_queue
            .insert_reserved(pos, new_seg)
            .expect("R180-11 OOO merge lost reserved queue capacity");

        // Correct ooo_bytes: subtract all removed segments, add the final merged one.
        // This prevents ooo_bytes from drifting upward on successive overlapping inserts,
        // which would shrink the advertised receive window to zero (DoS vector).
        self.ooo_bytes = self
            .ooo_bytes
            .saturating_sub(removed_bytes)
            .saturating_add(new_bytes);
        new_bytes
    }

    /// Drain contiguous data from the front of the OOO queue into the receive
    /// buffer, advancing `rcv_nxt`.
    ///
    /// Returns the total number of bytes delivered to the receive buffer.
    pub fn ooo_drain_contiguous(&mut self) -> u32 {
        let mut delivered = 0u32;

        while let Some(front) = self.ooo_queue.front() {
            let front_end = front.seq.wrapping_add(front.data.len() as u32);

            if seq_le(front.seq, self.rcv_nxt) {
                // This segment starts at or before rcv_nxt
                if seq_gt(front_end, self.rcv_nxt) {
                    // Some new data past rcv_nxt
                    let skip = self.rcv_nxt.wrapping_sub(front.seq) as usize;
                    let useful = &self.ooo_queue.front().unwrap().data.as_slice()[skip..];
                    // R158-10 FIX: Cap recv_buffer to prevent unbounded growth.
                    let room = TCP_MAX_RECV_BUFFER_BYTES.saturating_sub(self.recv_buffer.len());
                    if useful.len() > room {
                        break;
                    }
                    // R180-11 FIX: detached admitted growth means the in-order
                    // buffer cannot allocate during publication.
                    if self.recv_buffer.try_extend_from_slice(useful).is_err() {
                        break;
                    }
                    let useful_len = useful.len() as u32;
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(useful_len);
                    delivered = delivered.saturating_add(useful_len);
                }
                // Remove the segment (fully consumed or redundant)
                let removed = self.ooo_queue.pop_front().unwrap();
                self.ooo_bytes = self.ooo_bytes.saturating_sub(removed.data.len() as u32);

                // R133-3 FIX: Process FIN received in OOO segment.
                // FIN occupies one sequence number after the data payload.
                let removed_end = removed.seq.wrapping_add(removed.data.len() as u32);
                if removed.fin && removed_end == self.rcv_nxt {
                    self.fin_received = true;
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);

                    // Trigger state transition for passive close.
                    self.state = match self.state {
                        TcpState::Established => TcpState::CloseWait,
                        TcpState::FinWait1 => TcpState::Closing,
                        TcpState::FinWait2 => TcpState::TimeWait,
                        other => other,
                    };

                    // No data is valid after FIN. Clear remaining OOO segments
                    // to prevent attacker-injected data beyond FIN from being
                    // delivered after the connection is logically closed.
                    while let Some(stale) = self.ooo_queue.pop_front() {
                        self.ooo_bytes = self.ooo_bytes.saturating_sub(stale.data.len() as u32);
                    }
                    break;
                }
            } else {
                // Gap — stop draining
                break;
            }
        }

        delivered
    }

    /// Generate SACK blocks from the current OOO queue.
    ///
    /// Returns up to `TCP_SACK_MAX_BLOCKS` blocks describing the contiguous
    /// ranges in the OOO queue. The most recently inserted range is placed
    /// first (RFC 2018 Section 3 recommendation), followed by earlier ranges.
    ///
    /// R163-10 FIX: Reserve SACK block storage fallibly before the loop so
    /// the OOO receive path returns an empty block list instead of panicking
    /// on OOM. TCP_SACK_MAX_BLOCKS is always 4, so this is a bounded heap
    /// reservation. Callers already handle the empty-blocks case as a plain
    /// ACK, making silent degradation correct protocol behaviour.
    pub fn generate_sack_blocks(&self) -> SackBlocks {
        let mut blocks = SackBlocks::new();
        for seg in self.ooo_queue.iter().rev().take(TCP_SACK_MAX_BLOCKS) {
            // R145-5 FIX: FIN occupies one sequence number after the data
            // payload.  Include it in right_edge so the peer doesn't
            // unnecessarily retransmit the FIN position.
            let fin_len: u32 = if seg.fin { 1 } else { 0 };
            let inserted = blocks.push(SackBlock {
                left_edge: seg.seq,
                right_edge: seg
                    .seq
                    .wrapping_add(seg.data.len() as u32)
                    .wrapping_add(fin_len),
            });
            debug_assert!(
                inserted,
                "bounded SACK generation exceeded protocol maximum"
            );
        }
        blocks
    }

    /// Process incoming SACK blocks from the peer and update the sender-side
    /// scoreboard.
    ///
    /// R115-3 FIX: Rewrote from O(n*m) nested iteration to O(n + m log m)
    /// single-pass algorithm. SACK blocks are clamped to `[snd_una, snd_nxt)`,
    /// normalized to relative offsets, sorted, and merged (eliminating overlaps).
    /// Then a single sweep of `send_buffer` marks covered segments as SACKed.
    ///
    /// This prevents CPU amplification where an attacker crafts ACKs with varied
    /// SACK ranges to trigger O(buffer_len * sack_blocks) processing per packet.
    pub fn process_sack_blocks(&mut self, blocks: &[SackBlock]) {
        if blocks.is_empty() {
            return;
        }

        // Phase 1: Clamp blocks to [snd_una, snd_nxt) and normalize to offsets
        // from snd_una so we can sort/merge safely even when sequence numbers wrap.
        let mut rel_blocks = [(0u32, 0u32); TCP_SACK_MAX_BLOCKS];
        let mut rel_len = 0usize;

        for block in blocks.iter().take(TCP_SACK_MAX_BLOCKS) {
            let left = if seq_lt(block.left_edge, self.snd_una) {
                self.snd_una
            } else {
                block.left_edge
            };
            let right = if seq_gt(block.right_edge, self.snd_nxt) {
                self.snd_nxt
            } else {
                block.right_edge
            };

            // Reject degenerate or empty blocks after clamping
            if !seq_gt(right, left) {
                continue;
            }

            rel_blocks[rel_len] = (
                left.wrapping_sub(self.snd_una),
                right.wrapping_sub(self.snd_una),
            );
            rel_len += 1;
        }

        if rel_len == 0 {
            return;
        }

        // Phase 2: Sort by left edge, then merge overlapping/adjacent blocks.
        rel_blocks[..rel_len].sort_by_key(|(l, _)| *l);

        let mut merged = [(0u32, 0u32); TCP_SACK_MAX_BLOCKS];
        let mut merged_len = 0usize;
        for &(l, r) in &rel_blocks[..rel_len] {
            if merged_len != 0 {
                let last = &mut merged[merged_len - 1];
                if l <= last.1 {
                    // Overlapping or adjacent — extend the previous block
                    if r > last.1 {
                        last.1 = r;
                    }
                    continue;
                }
            }
            merged[merged_len] = (l, r);
            merged_len += 1;
        }

        // Phase 3: Update highest_sacked (guaranteed <= snd_nxt after clamping).
        for &(_, r_rel) in &merged[..merged_len] {
            let right = self.snd_una.wrapping_add(r_rel);
            if seq_gt(right, self.highest_sacked) {
                self.highest_sacked = right;
            }
        }

        // Phase 4: Single-pass mark of fully-covered TX segments.
        // Both send_buffer (sorted by seq) and merged blocks (sorted by left)
        // are traversed left-to-right, yielding O(n + m) after the sort.
        let mut bi = 0usize;
        for seg in self.send_buffer.iter_mut() {
            let seg_left_rel = seg.seq.wrapping_sub(self.snd_una);
            let seg_end = seg.seq.wrapping_add(seg.data.len() as u32);
            let seg_right_rel = seg_end.wrapping_sub(self.snd_una);

            // Advance past merged blocks that end before this segment starts
            while bi < merged_len && merged[bi].1 <= seg_left_rel {
                bi += 1;
            }

            if bi < merged_len {
                let (bl, br) = merged[bi];
                if bl <= seg_left_rel && seg_right_rel <= br {
                    seg.sacked = true;
                    seg.lost = false; // SACKed implies not lost
                }
            }
        }
    }

    /// RFC 6675 loss detection: mark unsacked segments as `lost` if
    /// `DupThresh` (3) SACKed segments exist above them.
    ///
    /// Walk from highest-sequence backward. Once we've seen 3 SACKed segments
    /// above an unsacked one, that segment is considered lost.
    pub fn sack_mark_lost(&mut self) {
        const DUP_THRESH: usize = 3;
        let mut sacked_above = 0usize;

        // Walk from tail (highest seq) toward head (lowest seq)
        for i in (0..self.send_buffer.len()).rev() {
            let seg = &self.send_buffer[i];
            let seg_end = seg.seq.wrapping_add(seg.data.len() as u32);

            if seg.sacked {
                sacked_above += 1;
            } else if seq_le(seg_end, self.highest_sacked) && sacked_above >= DUP_THRESH {
                // This segment has 3+ SACKed segments above it → mark lost
                self.send_buffer[i].lost = true;
            }
        }
    }

    /// Compute the RFC 6675 `pipe` estimate: bytes considered still in the network.
    ///
    /// `pipe = bytes_in_flight - sacked_bytes - lost_not_retransmitted_bytes`
    /// This approximation counts segments that are outstanding (not SACKed, not
    /// marked Lost) plus segments that were marked Lost and already retransmitted.
    pub fn sack_pipe(&self) -> u32 {
        let mut pipe = 0u32;
        for seg in &self.send_buffer {
            let seg_len = seg.data.len() as u32;
            if seg.sacked {
                // SACKed: not in the network
                continue;
            }
            if seg.lost {
                // Lost and retransmitted: counts toward pipe
                if seg.retrans_count > 0 {
                    pipe = pipe.saturating_add(seg_len);
                }
                // Lost but not yet retransmitted: does NOT count
            } else {
                // Outstanding (not SACKed, not Lost): in the network
                pipe = pipe.saturating_add(seg_len);
            }
        }
        pipe
    }

    /// Clear SACK scoreboard state (called on RTO or recovery exit).
    pub fn sack_clear_scoreboard(&mut self) {
        self.highest_sacked = self.snd_una;
        for seg in self.send_buffer.iter_mut() {
            seg.sacked = false;
            seg.lost = false;
        }
    }

    /// Find the earliest segment marked as `lost` that has not been retransmitted,
    /// returning its index in the send buffer (if any).
    pub fn sack_find_lost_segment(&self) -> Option<usize> {
        self.send_buffer
            .iter()
            .position(|seg| seg.lost && seg.retrans_count == 0)
    }
}

// ============================================================================
// Window Scaling Functions (RFC 7323)
// ============================================================================

/// Calculate the window scale factor needed for a desired window size.
///
/// Returns the minimum shift count (0-14) that allows advertising the desired
/// window within the 16-bit window field.
///
/// # Arguments
///
/// * `desired_wnd` - Desired receive window size in bytes
///
/// # Returns
///
/// Window scale shift count (0-14)
pub fn calc_wscale(desired_wnd: u32) -> u8 {
    if desired_wnd <= u16::MAX as u32 {
        return 0;
    }
    // Find minimum shift to fit desired_wnd in 16 bits
    // desired_wnd >> shift <= 65535
    for shift in 1..=TCP_MAX_WINDOW_SCALE {
        if desired_wnd >> shift <= u16::MAX as u32 {
            return shift;
        }
    }
    TCP_MAX_WINDOW_SCALE
}

/// Decode a received window value using the peer's window scale.
///
/// Applies the scale factor and caps at TCP_MAX_SCALED_WINDOW to prevent
/// overflow and unreasonable window sizes.
///
/// # Arguments
///
/// * `raw` - Raw window value from TCP header (16-bit)
/// * `scale` - Window scale shift count (0-14)
///
/// # Returns
///
/// Scaled window size in bytes
#[inline]
pub fn decode_window(raw: u16, scale: u8) -> u32 {
    let shift = scale.min(TCP_MAX_WINDOW_SCALE);
    // Shift is clamped to 14, raw is 16-bit, so max result is 65535 << 14 = ~1GB
    // which fits in u32 without overflow
    let scaled = (raw as u32) << shift;
    scaled.min(TCP_MAX_SCALED_WINDOW)
}

/// Encode a window value for transmission using our window scale.
///
/// Divides the available window by the scale factor for transmission in
/// the 16-bit window field. If avoid_zero is true and the result would be
/// zero but we have some window available, returns 1 to avoid advertising
/// a zero window incorrectly.
///
/// # Arguments
///
/// * `avail` - Available receive window in bytes
/// * `scale` - Window scale shift count (0-14)
/// * `avoid_zero` - If true, return at least 1 when avail > 0
///
/// # Returns
///
/// Encoded window value for TCP header (16-bit)
#[inline]
pub fn encode_window(avail: u32, scale: u8, avoid_zero: bool) -> u16 {
    let shift = scale.min(TCP_MAX_WINDOW_SCALE);
    let mut w = avail >> shift;
    // Avoid advertising zero window when we have some space
    if avoid_zero && w == 0 && avail > 0 {
        w = 1;
    }
    w.min(u16::MAX as u32) as u16
}

// ============================================================================
// RTT Estimation and Retransmission (RFC 6298)
// ============================================================================

/// Clock granularity (G) in microseconds for RTO calculation.
/// RFC 6298 recommends 100ms or finer; we use 100ms.
const RTO_CLOCK_GRANULARITY_US: u64 = 100_000;

/// Smoothing factor alpha = 1/8 for SRTT calculation.
const RTT_ALPHA_NUM: u64 = 1;
const RTT_ALPHA_DEN: u64 = 8;

/// Variance factor beta = 1/4 for RTTVAR calculation.
const RTT_BETA_NUM: u64 = 1;
const RTT_BETA_DEN: u64 = 4;

/// Multiplier K = 4 for RTO variance term.
const RTT_K: u64 = 4;

/// Update RTT estimates and compute RTO per RFC 6298.
///
/// This function implements the standard TCP RTT estimation algorithm:
/// - First sample: SRTT = R, RTTVAR = R/2
/// - Subsequent:   RTTVAR = (1-β)×RTTVAR + β×|SRTT - R|
///                 SRTT = (1-α)×SRTT + α×R
/// - RTO = SRTT + max(G, K×RTTVAR)
///
/// Where α = 1/8, β = 1/4, K = 4, G = 100ms
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `sample_us` - RTT sample in microseconds
///
/// # Security
///
/// - RTO is clamped to [TCP_MIN_RTO_MS, TCP_MAX_RTO_MS] to prevent
///   both too-aggressive retransmission and unbounded delays.
pub fn update_rtt(tcb: &mut TcpControlBlock, sample_us: u64) {
    // Reject zero or unreasonably large samples (> 10 minutes)
    if sample_us == 0 || sample_us > 600_000_000 {
        return;
    }

    if tcb.srtt_us == 0 {
        // First RTT measurement (RFC 6298 Section 2.2)
        tcb.srtt_us = sample_us;
        tcb.rttvar_us = sample_us / 2;
    } else {
        // Subsequent measurements (RFC 6298 Section 2.3)
        let srtt = tcb.srtt_us;
        let rttvar = tcb.rttvar_us;

        // Compute absolute RTT error: |SRTT - R|
        let rtt_err = if srtt > sample_us {
            srtt - sample_us
        } else {
            sample_us - srtt
        };

        // RTTVAR = (1 - β)×RTTVAR + β×|SRTT - R|
        // Using integer arithmetic: (3×RTTVAR + error) / 4
        tcb.rttvar_us =
            ((RTT_BETA_DEN - RTT_BETA_NUM) * rttvar + RTT_BETA_NUM * rtt_err) / RTT_BETA_DEN;

        // SRTT = (1 - α)×SRTT + α×R
        // Using integer arithmetic: (7×SRTT + sample) / 8
        tcb.srtt_us =
            ((RTT_ALPHA_DEN - RTT_ALPHA_NUM) * srtt + RTT_ALPHA_NUM * sample_us) / RTT_ALPHA_DEN;
    }

    // RTO = SRTT + max(G, K×RTTVAR)
    let variance_term = RTT_K.saturating_mul(tcb.rttvar_us);
    let rto_us = tcb
        .srtt_us
        .saturating_add(core::cmp::max(RTO_CLOCK_GRANULARITY_US, variance_term));

    // Convert to milliseconds and clamp to valid range
    let rto_ms = (rto_us / 1000).clamp(TCP_MIN_RTO_MS, TCP_MAX_RTO_MS);
    tcb.rto_ms = rto_ms;
}

/// Process incoming ACK: advance snd_una, clean send buffer, sample RTT.
///
/// This function implements ACK processing per RFC 793 with RFC 6298
/// RTT sampling (Karn's algorithm - don't sample retransmitted segments).
///
/// Returns `AckUpdate` for congestion control decisions.
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `ack_num` - ACK number from incoming segment
/// * `now_ms` - Current monotonic time in milliseconds
///
/// # Effects
///
/// - Removes fully acknowledged segments from send_buffer
/// - Samples RTT from first non-retransmitted acknowledged segment
/// - Updates snd_una to new acknowledgment point
/// - Resets retries counter on progress (new ACK)
///
/// # Security
///
/// - Uses seq_gt() for wraparound-safe sequence comparison
/// - Karn's algorithm prevents RTT corruption from retransmissions
///
/// # Precondition (caller-enforced; R184-7)
///
/// This function assumes `snd_una < ack_num <= snd_nxt` — i.e. the ACK
/// acknowledges data actually sent. It does NOT itself reject a fabricated
/// future ACK (`ack_num > snd_nxt`); the RFC 793 §3.9 acceptability test that
/// bounds `ack_num <= snd_nxt` (inclusive) is enforced by EVERY caller before
/// this runs — the socket-layer per-state ACK guards
/// (`socket.rs` established/FIN_WAIT/CLOSING/etc.: `seq_ge(snd_nxt, ack_num)`)
/// and the exact `ack_num == snd_nxt` handshake/SYN-cookie gates. A future
/// caller that invokes `handle_ack` WITHOUT that guard would let a crafted ACK
/// clear the send buffer and advance `snd_una` past `snd_nxt` (data loss). R184-7
/// was audited as a HIGH on this function in isolation and verified a FALSE
/// POSITIVE precisely because all 10 production callers guard it; this note
/// pins the contract so the guard is not dropped by a future caller.
pub fn handle_ack(tcb: &mut TcpControlBlock, ack_num: u32, now_ms: u64) -> AckUpdate {
    let mut update = AckUpdate::default();

    // R148-I3 FIX: Any ACK from the peer (including duplicate ACKs from keepalive
    // responses) proves the connection is alive — reset the keepalive probe count
    // and update last_activity so the idle timer restarts.
    tcb.keepalive_probes_sent = 0;
    tcb.last_activity = now_ms;

    if seq_gt(ack_num, tcb.snd_una) {
        // New ACK - advances the acknowledgment point
        // RF180-41 REVIEW FIX: RTO completion suppression requires proof of
        // forward progress. Duplicate ACKs still prove liveness for keepalive,
        // but cannot cancel loss recovery for the unchanged oldest target.
        tcb.peer_ack_generation = tcb.peer_ack_generation.wrapping_add(1);
        update.newly_acked = ack_num.wrapping_sub(tcb.snd_una);

        let mut rtt_sampled = false;

        // Remove fully acknowledged segments from send buffer
        while let Some(seg) = tcb.send_buffer.front() {
            // Segment end sequence = seq + data.len()
            let end_seq = seg.seq.wrapping_add(seg.data.len() as u32);

            // Check if entire segment is acknowledged (ack_num >= end_seq)
            if !seq_ge(ack_num, end_seq) {
                // This segment is not fully acknowledged yet
                break;
            }

            // Pop the acknowledged segment
            let seg = tcb.send_buffer.pop_front().unwrap();
            // R115-3 FIX: Decrement byte counter to track cumulative buffer size.
            tcb.send_buffer_bytes = tcb.send_buffer_bytes.saturating_sub(seg.data.len());

            // Karn's algorithm: only sample RTT from non-retransmitted segments
            // This prevents RTT estimate corruption from ambiguous RTT samples
            if !rtt_sampled && seg.retrans_count == 0 {
                let rtt_ms = now_ms.saturating_sub(seg.sent_at);
                // Convert to microseconds (cap to prevent overflow)
                let rtt_us = rtt_ms.saturating_mul(1000);
                update_rtt(tcb, rtt_us);
                rtt_sampled = true;
            }
        }

        // Update send unacknowledged pointer
        tcb.snd_una = ack_num;

        // Reset consecutive retransmission counter on progress
        tcb.retries = 0;
    } else if ack_num == tcb.snd_una {
        // Duplicate ACK - same ACK number as before
        update.duplicate = true;
    }

    update
}

// ============================================================================
// Congestion Control (RFC 5681)
// ============================================================================

/// Update congestion control state per RFC 5681.
///
/// Called after ACK processing to adjust cwnd and detect fast retransmit.
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `acked_bytes` - Number of newly acknowledged bytes (0 for duplicate ACK)
/// * `duplicate_ack` - True if this was a duplicate ACK
///
/// # Returns
///
/// `CongestionAction::FastRetransmit` if 3 duplicate ACKs detected,
/// otherwise `CongestionAction::None`.
///
/// # Algorithm
///
/// **Slow Start** (cwnd < ssthresh):
/// - cwnd += min(N, SMSS) where N is newly acked bytes
///
/// **Congestion Avoidance** (cwnd >= ssthresh):
/// - cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT)
///
/// **Fast Recovery** (RFC 5681 Section 3.2 + NewReno):
/// - On 3rd duplicate ACK: ssthresh = max(FlightSize/2, 2*SMSS)
/// - cwnd = ssthresh + 3*SMSS, trigger fast retransmit
/// - On each additional duplicate ACK: cwnd += SMSS
/// - R55-1: On partial ACK (ack < recover): stay in FR, retransmit next
/// - On full ACK (ack >= recover): exit fast recovery, cwnd = ssthresh
pub fn update_congestion_control(
    tcb: &mut TcpControlBlock,
    acked_bytes: u32,
    duplicate_ack: bool,
    ack_num: u32,
) -> CongestionAction {
    if acked_bytes > 0 {
        // New data acknowledged - reset duplicate ACK counter
        tcb.dup_ack_count = 0;

        let mss = tcb.snd_mss as u32;

        match tcb.congestion_state {
            TcpCongestionState::SlowStart => {
                // Slow start: exponential growth
                // cwnd += min(N, SMSS) for each ACK
                let growth = core::cmp::min(acked_bytes, mss).max(1);
                tcb.cwnd = tcb.cwnd.saturating_add(growth);

                // Transition to congestion avoidance when cwnd >= ssthresh
                if tcb.cwnd >= tcb.ssthresh {
                    tcb.congestion_state = TcpCongestionState::CongestionAvoidance;
                }
            }
            TcpCongestionState::CongestionAvoidance => {
                // RFC 5681: Congestion avoidance - linear growth
                // cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT)
                let increment = mss.saturating_mul(mss).saturating_div(tcb.cwnd.max(1));
                tcb.cwnd = tcb.cwnd.saturating_add(increment.max(1));
            }
            TcpCongestionState::FastRecovery => {
                // R55-1: NewReno partial ACK handling
                if seq_ge(ack_num, tcb.recover) {
                    // Full ACK: all data sent before entering FR is acknowledged
                    // Exit fast recovery and deflate cwnd
                    tcb.cwnd = tcb.ssthresh.max(mss);
                    tcb.congestion_state = TcpCongestionState::CongestionAvoidance;
                    return CongestionAction::None;
                } else {
                    // Partial ACK: some but not all FR data acknowledged
                    // Stay in fast recovery, deflate cwnd, retransmit next
                    // cwnd = ssthresh + 3*MSS - acked_bytes (deflate for acked data)
                    tcb.cwnd = tcb
                        .ssthresh
                        .saturating_add(3 * mss)
                        .saturating_sub(acked_bytes)
                        .max(mss);
                    return CongestionAction::RetransmitNext;
                }
            }
        }

        return CongestionAction::None;
    }

    // Handle duplicate ACKs
    if duplicate_ack {
        tcb.dup_ack_count = tcb.dup_ack_count.saturating_add(1);
        let mss = tcb.snd_mss as u32;

        // R55-2 FIX: Only enter fast recovery if not already in it (RFC 6582).
        // After a partial ACK, dup_ack_count resets to 0, so subsequent dup ACKs
        // would hit this branch again. The state check prevents re-cutting ssthresh.
        if tcb.congestion_state != TcpCongestionState::FastRecovery {
            // R56-1: RFC 3042 Limited Transmit on first/second duplicate ACK.
            //
            // For small-window connections that may never accumulate 3 dup ACKs,
            // send new data on the first two dup ACKs if:
            //   FlightSize + SMSS <= cwnd + 2*SMSS
            //
            // This helps generate additional ACKs to reach the fast retransmit
            // threshold without waiting for RTO.
            if tcb.dup_ack_count <= 2 {
                let flight = tcb.bytes_in_flight();
                // Check: can we send one more MSS under RFC 3042 allowance?
                if flight.saturating_add(mss) <= tcb.cwnd.saturating_add(2 * mss) {
                    return CongestionAction::LimitedTransmit;
                }
            }

            if tcb.dup_ack_count == 3 {
                // Triple duplicate ACK - enter fast retransmit/recovery
                // RFC 5681 Section 3.2: ssthresh = max(FlightSize/2, 2*SMSS)
                let flight = tcb.bytes_in_flight().max(mss);
                tcb.ssthresh = core::cmp::max(flight / 2, 2 * mss);

                // cwnd = ssthresh + 3*SMSS (account for segments that triggered dup ACKs)
                tcb.cwnd = tcb.ssthresh.saturating_add(3 * mss);
                tcb.congestion_state = TcpCongestionState::FastRecovery;

                // R55-1: Set recovery point for NewReno partial ACK detection
                tcb.recover = tcb.snd_nxt;

                return CongestionAction::FastRetransmit;
            }
        }

        // R55-3 FIX: Window inflation on any dup ACK during fast recovery (RFC 6582).
        // Changed from dup_ack_count > 3 to > 0 so dup ACKs after partial ACK
        // (when dup_ack_count restarts from 0) still inflate cwnd to keep pipe full.
        if tcb.congestion_state == TcpCongestionState::FastRecovery && tcb.dup_ack_count > 0 {
            tcb.cwnd = tcb.cwnd.saturating_add(mss);
        }
    }

    CongestionAction::None
}

/// Handle retransmission timeout - enter loss recovery (RFC 5681 Section 3.1).
///
/// Called when RTO expires and a segment is retransmitted.
///
/// # Effects
///
/// - ssthresh = max(FlightSize/2, 2*SMSS)
/// - cwnd = 1*SMSS (back to slow start)
/// - congestion_state = SlowStart
/// - dup_ack_count = 0
/// - recover = snd_nxt (R55-1: reset recovery point)
pub fn handle_retransmission_timeout(tcb: &mut TcpControlBlock) {
    let flight = tcb.bytes_in_flight().max(tcb.snd_mss as u32);
    tcb.ssthresh = core::cmp::max(flight / 2, 2 * tcb.snd_mss as u32);
    tcb.cwnd = tcb.snd_mss as u32; // Back to 1 SMSS
    tcb.congestion_state = TcpCongestionState::SlowStart;
    tcb.recover = tcb.snd_nxt; // R55-1: Reset recovery point
    tcb.dup_ack_count = 0;
}

/// R57-1: RFC 2861 idle cwnd validation to prevent stale bursts.
///
/// A TCP connection is considered "idle" when no data is in flight and no
/// data has been sent for at least one RTO period. After idle periods, cwnd
/// may no longer reflect current network conditions, so we reduce it to avoid
/// congestion bursts.
///
/// # Algorithm
///
/// - After first idle RTO: cap cwnd at initial window (IW)
/// - For each additional idle RTO: halve cwnd until ssthresh floor
/// - If cwnd falls to or below ssthresh, re-enter slow start
///
/// # Arguments
///
/// * `tcb` - TCP control block to validate
/// * `now_ms` - Current monotonic time in milliseconds
///
/// # Security
///
/// Prevents connections from bursting with a stale (potentially large) cwnd
/// after being idle, which could cause network congestion or self-induced
/// packet loss.
#[inline]
pub fn validate_cwnd_after_idle(tcb: &mut TcpControlBlock, now_ms: u64) {
    // Skip if no activity recorded yet or invalid RTO
    if tcb.last_activity == 0 || tcb.rto_ms == 0 {
        return;
    }

    // RFC 2861: Not idle if there is still outstanding data in flight
    if tcb.bytes_in_flight() > 0 {
        return;
    }

    let idle_ms = now_ms.saturating_sub(tcb.last_activity);
    if idle_ms < tcb.rto_ms {
        // Not idle yet - no adjustment needed
        return;
    }

    let iw = initial_cwnd(tcb.snd_mss);
    let idle_rtos = idle_ms / tcb.rto_ms;

    // First idle RTO: collapse inflated cwnd to initial window
    let mut new_cwnd = core::cmp::min(tcb.cwnd, iw);

    // Additional RTOs: exponential decay toward ssthresh floor
    if idle_rtos > 1 && new_cwnd > tcb.ssthresh {
        let floor = core::cmp::max(tcb.ssthresh, tcb.snd_mss as u32).max(1);
        for _ in 1..idle_rtos {
            if new_cwnd <= floor {
                break;
            }
            new_cwnd = new_cwnd.saturating_div(2).max(floor);
        }
    }

    // Apply reduction if cwnd decreased
    if new_cwnd < tcb.cwnd {
        tcb.cwnd = new_cwnd;
        // Re-enter slow start if cwnd fell to or below ssthresh
        if tcb.cwnd <= tcb.ssthresh {
            tcb.congestion_state = TcpCongestionState::SlowStart;
        }
    }
}

// ============================================================================
// TCP Errors
// ============================================================================

/// Errors that can occur during TCP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// Packet is too short
    Truncated,
    /// Invalid header length (data offset)
    InvalidHeaderLen,
    /// Invalid flags combination
    InvalidFlags,
    /// Checksum verification failed
    BadChecksum,
    /// Connection refused (RST received)
    ConnectionRefused,
    /// Connection reset by peer
    ConnectionReset,
    /// Connection timed out
    Timeout,
    /// Invalid state for operation
    InvalidState,
    /// No route to host
    NoRoute,
    /// Address already in use
    AddressInUse,
    /// Connection already exists
    ConnectionExists,
    /// Not connected
    NotConnected,
    /// Resource temporarily unavailable
    WouldBlock,
    /// Invalid sequence number
    InvalidSeq,
    /// TCP header plus payload exceeds the IPv4 pseudo-header u16 length.
    SegmentTooLong,
    /// TCP option serialization exceeded the 60-byte header limit.
    OptionsTooLong,
    /// Fallible segment storage reservation failed.
    AllocationFailed,
}

/// Result type for TCP operations
pub type TcpResult<T> = Result<T, TcpError>;

// ============================================================================
// TCP Statistics
// ============================================================================

/// TCP stack statistics
#[derive(Debug, Default)]
pub struct TcpStats {
    /// Total segments received
    pub rx_segments: AtomicU64,
    /// Total segments sent
    pub tx_segments: AtomicU64,
    /// Segments dropped (invalid)
    pub rx_dropped: AtomicU64,
    /// Checksum errors
    pub checksum_errors: AtomicU64,
    /// Connections established
    pub connections_established: AtomicU64,
    /// Connections reset
    pub connections_reset: AtomicU64,
    /// Retransmissions
    pub retransmissions: AtomicU64,
    /// Segments received out of order
    pub out_of_order: AtomicU64,
}

impl TcpStats {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            rx_segments: AtomicU64::new(0),
            tx_segments: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            checksum_errors: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_reset: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            out_of_order: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// TCP Parsing Functions
// ============================================================================

/// Parse TCP header from raw bytes
///
/// # Security
///
/// - Validates minimum header length
/// - Validates data offset field
/// - Does NOT verify checksum (caller must do this)
///
/// # Arguments
///
/// * `data` - Raw TCP segment bytes
///
/// # Returns
///
/// Parsed header on success
pub fn parse_tcp_header(data: &[u8]) -> TcpResult<TcpHeader> {
    // Check minimum length
    if data.len() < TCP_HEADER_MIN_LEN {
        return Err(TcpError::Truncated);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) & 0x0F;
    let reserved = data[12] & 0x0F;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    // Validate data offset (must be at least 5 = 20 bytes)
    if data_offset < 5 {
        return Err(TcpError::InvalidHeaderLen);
    }

    // Validate data offset doesn't exceed packet
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return Err(TcpError::Truncated);
    }

    // Validate reserved bits are zero (RFC 793)
    // Note: Modern TCP uses some reserved bits for ECN, so we're lenient here
    if reserved & 0x0E != 0 {
        // Only check bits 1-3, bit 0 is NS flag
        // For strict compliance, could reject here
    }

    Ok(TcpHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_ptr,
    })
}

/// Parse TCP options from header
///
/// # Arguments
///
/// * `data` - TCP segment bytes (starting from byte 0)
/// * `header` - Parsed TCP header
///
/// # Returns
///
/// Parsed options
pub fn parse_tcp_options(data: &[u8], header: &TcpHeader) -> TcpOptions {
    let mut options = TcpOptions::default();
    let header_len = header.header_len();

    if header_len <= TCP_HEADER_MIN_LEN || data.len() < header_len {
        return options;
    }

    let opts_data = &data[TCP_HEADER_MIN_LEN..header_len];
    let mut i = 0;

    while i < opts_data.len() {
        match opts_data[i] {
            0 => break,  // End of Option List
            1 => i += 1, // NOP
            2 => {
                // MSS
                if i + 4 <= opts_data.len() && opts_data[i + 1] == 4 {
                    let raw_mss = u16::from_be_bytes([opts_data[i + 2], opts_data[i + 3]]);
                    // R66-1 FIX: Clamp to RFC 879 minimum of 536 bytes to prevent
                    // tiny-MSS DoS attacks (CPU/memory amplification via micro-segments)
                    options.mss = Some(raw_mss.max(TCP_DEFAULT_MSS));
                    i += 4;
                } else {
                    break;
                }
            }
            3 => {
                // Window Scale
                if i + 3 <= opts_data.len() && opts_data[i + 1] == 3 {
                    // R66-2 FIX: RFC 7323 mandates maximum shift count of 14.
                    // Values > 14 are treated as 14 to prevent overflow in window calculations.
                    options.window_scale = Some(opts_data[i + 2].min(TCP_MAX_WINDOW_SCALE));
                    i += 3;
                } else {
                    break;
                }
            }
            4 => {
                // SACK Permitted
                if i + 2 <= opts_data.len() && opts_data[i + 1] == 2 {
                    options.sack_permitted = true;
                    i += 2;
                } else {
                    break;
                }
            }
            5 => {
                // SACK Blocks (RFC 2018, kind=5)
                // Format: kind(1) + length(1) + N * (left_edge(4) + right_edge(4))
                // Minimum length is 10 (1 block), (length - 2) must be divisible by 8.
                if i + 2 > opts_data.len() {
                    break;
                }
                let opt_len = opts_data[i + 1] as usize;
                if opt_len < 10 || (opt_len - 2) % 8 != 0 {
                    // Malformed SACK option — skip it safely
                    if let Some(next) = i.checked_add(opt_len.max(2)) {
                        if next <= opts_data.len() {
                            i = next;
                            continue;
                        }
                    }
                    break;
                }
                if i + opt_len > opts_data.len() {
                    break;
                }
                let block_count = (opt_len - 2) / 8;
                let remaining = TCP_SACK_MAX_BLOCKS.saturating_sub(options.sack_blocks.len());
                let count = block_count.min(remaining);
                let mut j = i + 2;
                for _ in 0..count {
                    if j + 8 > opts_data.len() {
                        break;
                    }
                    let left = u32::from_be_bytes([
                        opts_data[j],
                        opts_data[j + 1],
                        opts_data[j + 2],
                        opts_data[j + 3],
                    ]);
                    let right = u32::from_be_bytes([
                        opts_data[j + 4],
                        opts_data[j + 5],
                        opts_data[j + 6],
                        opts_data[j + 7],
                    ]);
                    // Discard invalid blocks where left >= right (wrap-safe)
                    if seq_lt(left, right) {
                        let inserted = options.sack_blocks.push(SackBlock {
                            left_edge: left,
                            right_edge: right,
                        });
                        debug_assert!(inserted, "bounded SACK parser exceeded protocol maximum");
                    }
                    j += 8;
                }
                i += opt_len;
            }
            8 => {
                // Timestamps
                if i + 10 <= opts_data.len() && opts_data[i + 1] == 10 {
                    let ts_val = u32::from_be_bytes([
                        opts_data[i + 2],
                        opts_data[i + 3],
                        opts_data[i + 4],
                        opts_data[i + 5],
                    ]);
                    let ts_ecr = u32::from_be_bytes([
                        opts_data[i + 6],
                        opts_data[i + 7],
                        opts_data[i + 8],
                        opts_data[i + 9],
                    ]);
                    options.timestamps = Some((ts_val, ts_ecr));
                    i += 10;
                } else {
                    break;
                }
            }
            _ => {
                // R50-6 FIX: Unknown option - skip based on length field with overflow-safe math
                if i + 1 < opts_data.len() {
                    let len = opts_data[i + 1] as usize;
                    // Minimum option length is 2 (kind + length bytes)
                    if len < 2 {
                        break;
                    }
                    // Use checked_add to prevent integer overflow attacks
                    if let Some(next) = i.checked_add(len) {
                        if next <= opts_data.len() {
                            i = next;
                            continue;
                        }
                    }
                    // Overflow or out-of-bounds - stop parsing
                    break;
                } else {
                    break;
                }
            }
        }
    }

    options
}

/// Compute TCP checksum using IPv4 pseudo-header
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// TCP checksum value
pub fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    try_compute_tcp_checksum(src_ip, dst_ip, tcp_data).unwrap_or(0)
}

/// Checked TCP checksum API. Unlike the compatibility wrapper above, an
/// oversized segment cannot be confused with the valid checksum value zero.
pub fn try_compute_tcp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_data: &[u8],
) -> TcpResult<u16> {
    // Build pseudo-header
    // R157-9 FIX: Checked conversion — reject oversized segments instead of
    // silent truncation (IPv4 prevents >65535 in practice, defense-in-depth).
    let tcp_len = u16::try_from(tcp_data.len()).map_err(|_| TcpError::SegmentTooLong)?;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.0);
    pseudo[4..8].copy_from_slice(&dst_ip.0);
    pseudo[8] = 0; // Zero
    pseudo[9] = TCP_PROTO;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    // R180-20 FIX: accumulate the pseudo-header and complete TCP segment as
    // raw one's-complement words, then complement exactly once.  The previous
    // implementation added two already-complemented partial checksums and
    // complemented that result again, producing the complement of the wire
    // checksum while its matching verifier repeated the same mistake.
    Ok(calculate_checksum_with_pseudo(&pseudo, tcp_data))
}

/// Verify TCP checksum
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// true if checksum is valid
pub fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> bool {
    matches!(try_compute_tcp_checksum(src_ip, dst_ip, tcp_data), Ok(0))
}

/// R180-20 byte-level checksum oracle used by the kernel integration suite.
///
/// The expected values were generated from the RFC 1071 raw word sum outside
/// this crate. Keeping them in non-test code makes the boot suite exercise the
/// actual no_std path even when unrelated host-unit tests fail to compile.
pub fn run_tcp_checksum_self_test() {
    let src = Ipv4Addr::new(192, 0, 2, 1);
    let dst = Ipv4Addr::new(198, 51, 100, 2);
    let mut syn = [
        0x30, 0x39, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa,
        0xf0, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(compute_tcp_checksum(src, dst, &syn), 0x53cb);
    syn[16..18].copy_from_slice(&0x53cbu16.to_be_bytes());
    assert!(verify_tcp_checksum(src, dst, &syn));
    syn[4] ^= 0x01;
    assert!(!verify_tcp_checksum(src, dst, &syn));

    let mut odd = [
        0x30, 0x39, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa,
        0xf0, 0x00, 0x00, 0x00, 0x00, b'a', b'b', b'c',
    ];
    assert_eq!(compute_tcp_checksum(src, dst, &odd), 0x8f65);
    odd[16..18].copy_from_slice(&0x8f65u16.to_be_bytes());
    assert!(verify_tcp_checksum(src, dst, &odd));
}

/// Build a TCP segment with the given parameters
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq_num` - Sequence number
/// * `ack_num` - Acknowledgment number
/// * `flags` - TCP flags
/// * `window` - Window size
/// * `payload` - Segment payload
///
/// # Returns
///
/// Complete TCP segment with checksum
pub fn build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> WirePacket {
    try_build_tcp_segment(
        src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, window, payload,
    )
    .unwrap_or_default()
}

/// Checked segment builder. The compatibility wrapper returns an empty packet
/// on error, while this API preserves the precise rejection reason.
pub fn try_build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> TcpResult<WirePacket> {
    let header = TcpHeader::new(src_port, dst_port, seq_num, ack_num, flags, window);
    // R163-10 FIX: Use checked_add to guard against theoretical usize overflow
    // (e.g. payload near usize::MAX). The checked API preserves allocation and
    // admission failures; the compatibility wrapper converts them into the
    // empty-packet sentinel that downstream transmit paths drop fail-closed.
    let segment_len = TCP_HEADER_MIN_LEN
        .checked_add(payload.len())
        .ok_or(TcpError::SegmentTooLong)?;
    if segment_len > u16::MAX as usize {
        return Err(TcpError::SegmentTooLong);
    }
    // RF180-41 FIX: the complete SYN/data/control segment is admitted before
    // its allocator request and keeps the charge through transmit/drop.
    let mut segment =
        WirePacket::try_zeroed(segment_len).map_err(|_| TcpError::AllocationFailed)?;
    segment[..TCP_HEADER_MIN_LEN].copy_from_slice(&header.to_bytes());
    segment[TCP_HEADER_MIN_LEN..].copy_from_slice(payload);

    // Compute and set checksum
    let checksum = try_compute_tcp_checksum(src_ip, dst_ip, &segment)?;
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(segment)
}

/// Build a serialized segment whose backing allocation remains charged until
/// the caller has transmitted and destroyed it.
///
/// RF180-25 FIX: timer and close work cannot use a merely fallible `Vec`:
/// allocation must also participate in the whole-kernel socket-payload ledger.
/// The complete admitted packet is constructed before callers advance TCP
/// sequence, retry, or state fields.
pub(crate) fn try_build_tcp_segment_admitted(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> TcpResult<WirePacket> {
    try_build_tcp_segment(
        src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, window, payload,
    )
}

/// Build a TCP segment with options and correct data offset.
///
/// This function serializes TCP options, pads them to 32-bit boundary,
/// and includes them in the header. The data_offset field is set correctly
/// to reflect the actual header length (base header + options).
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq_num` - Sequence number
/// * `ack_num` - Acknowledgment number
/// * `flags` - TCP flags
/// * `window` - Window size (already scaled by caller if applicable)
/// * `options` - TCP options to include (e.g., MSS, Window Scale)
/// * `payload` - Segment payload
///
/// # Returns
///
/// Complete TCP segment with options and checksum
///
/// # Panics
///
/// Debug-asserts if options exceed maximum header length (40 bytes of options).
pub fn build_tcp_segment_with_options(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[TcpOptionKind],
    payload: &[u8],
) -> WirePacket {
    try_build_tcp_segment_with_options(
        src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, window, options, payload,
    )
    .unwrap_or_default()
}

/// Checked option-bearing segment builder.
pub fn try_build_tcp_segment_with_options(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[TcpOptionKind],
    payload: &[u8],
) -> TcpResult<WirePacket> {
    // Serialize bounded options into stack storage so final-packet admission
    // does not temporarily coexist with a second heap-backed wire buffer.
    let mut option_scratch = [0u8; TCP_HEADER_MAX_LEN - TCP_HEADER_MIN_LEN];
    let options_len = serialize_tcp_options_into(options, &mut option_scratch);
    let header_len = TCP_HEADER_MIN_LEN + options_len;

    // Validate header length doesn't exceed maximum (60 bytes = 15 * 4)
    debug_assert!(
        header_len <= TCP_HEADER_MAX_LEN,
        "TCP options exceed maximum header length: {} > {}",
        header_len,
        TCP_HEADER_MAX_LEN
    );
    if header_len > TCP_HEADER_MAX_LEN {
        return Err(TcpError::OptionsTooLong);
    }

    // Create header with correct data offset
    let mut header = TcpHeader::new(src_port, dst_port, seq_num, ack_num, flags, window);
    header.data_offset = (header_len / 4) as u8;

    // Build segment: header + options + payload
    // R163-10 FIX: Compute and validate the complete option-bearing segment
    // length before its single admitted allocation. The checked API preserves
    // allocation errors; its compatibility wrapper returns an empty packet.
    let segment_len = header_len
        .checked_add(payload.len())
        .ok_or(TcpError::SegmentTooLong)?;
    if segment_len > u16::MAX as usize {
        return Err(TcpError::SegmentTooLong);
    }
    let mut segment =
        WirePacket::try_zeroed(segment_len).map_err(|_| TcpError::AllocationFailed)?;
    segment[..TCP_HEADER_MIN_LEN].copy_from_slice(&header.to_bytes());
    segment[TCP_HEADER_MIN_LEN..header_len].copy_from_slice(&option_scratch[..options_len]);
    segment[header_len..].copy_from_slice(payload);

    // Compute and set checksum
    let checksum = try_compute_tcp_checksum(src_ip, dst_ip, &segment)?;
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(segment)
}

// ============================================================================
// ISN Generation (RFC 6528)
// ============================================================================

/// Global ISN generator state
static ISN_COUNTER: AtomicU32 = AtomicU32::new(0);

/// R54-1 FIX: ISN secret key with auto-upgrade capability.
///
/// Initially may use a weak RDTSC-based fallback during early boot before
/// CSPRNG is seeded. Once CSPRNG is ready, the secret is transparently
/// upgraded to strong entropy on next use.
///
/// Uses AtomicU64 instead of Once<u64> to enable runtime upgrade.
static ISN_SECRET: AtomicU64 = AtomicU64::new(0);

/// R54-1 FIX: Tracks whether current ISN_SECRET is from weak entropy source.
///
/// When true, subsequent calls to isn_secret() will attempt to upgrade
/// to strong entropy from CSPRNG.
static ISN_SECRET_WEAK: AtomicBool = AtomicBool::new(true);

/// R62-3 FIX: Counter for connections established with weak ISN entropy.
/// Used for monitoring/auditing purposes.
static ISN_WEAK_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

/// Get or initialize the ISN secret key from CSPRNG.
///
/// R54-1 IMPROVEMENT: Auto-upgrades weak secret to strong once CSPRNG is ready.
///
/// # Security Design
///
/// 1. **Fast path**: If strong secret is already installed, return immediately
/// 2. **Upgrade path**: If CSPRNG is now available and current secret is weak,
///    atomically upgrade to strong entropy
/// 3. **Fallback path**: For early boot, use RDTSC-based weak secret that
///    will be upgraded later
///
/// The upgrade is transparent to callers and maintains ISN monotonicity
/// (the counter is never reset, only the secret key changes).
#[inline]
fn isn_secret() -> u64 {
    // Fast path: strong secret already installed
    let current = ISN_SECRET.load(Ordering::Acquire);
    if current != 0 && !ISN_SECRET_WEAK.load(Ordering::Relaxed) {
        return current;
    }

    // Try to install or upgrade to strong entropy from CSPRNG
    // R149-5 FIX: Use fill_random (FIPS boundary pub API).
    let strong_result = {
        let mut buf = [0u8; 8];
        security::fill_random(&mut buf)
            .ok()
            .map(|()| u64::from_le_bytes(buf))
    };
    if let Some(strong) = strong_result {
        let prev = ISN_SECRET.load(Ordering::Acquire);
        let is_weak = ISN_SECRET_WEAK.load(Ordering::Relaxed);

        // Upgrade if: no secret yet OR current secret is weak
        if prev == 0 || is_weak {
            if ISN_SECRET
                .compare_exchange(prev, strong, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Successfully installed strong secret
                ISN_SECRET_WEAK.store(false, Ordering::Release);
                return strong;
            }
        }

        // Another thread may have upgraded - check if strong now
        let upgraded = ISN_SECRET.load(Ordering::Acquire);
        if upgraded != 0 && !ISN_SECRET_WEAK.load(Ordering::Relaxed) {
            return upgraded;
        }
    }

    // Fallback: weak secret for early boot (will be upgraded later)
    #[cfg(target_arch = "x86_64")]
    let weak = {
        let lo: u64;
        let hi: u64;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        }
        // Mix with prime constant for better distribution of weak entropy
        let tsc = (hi << 32) | lo;
        tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let weak = 0xa5a5_5a5a_d3e4_c7d2_u64;

    // Install weak secret only if none exists; keep marked as upgradeable
    if ISN_SECRET
        .compare_exchange(0, weak, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        ISN_SECRET_WEAK.store(true, Ordering::Release);
        return weak;
    }

    // Another thread installed something - use that
    ISN_SECRET.load(Ordering::Acquire)
}

/// Generate an Initial Sequence Number (ISN) per RFC 6528
///
/// R50-1 FIX: Uses keyed hash over 4-tuple + counter for security.
/// The secret key is initialized at boot from CSPRNG entropy.
///
/// # Security
///
/// - Secret key prevents off-path ISN prediction
/// - Counter prevents ISN reuse within connection lifetime
/// - Multiple mixing rounds provide diffusion
///
/// # Arguments
///
/// * `local_ip` - Local IP address
/// * `local_port` - Local port
/// * `remote_ip` - Remote IP address
/// * `remote_port` - Remote port
///
/// # Returns
///
/// Cryptographically unpredictable ISN for the connection
pub fn generate_isn(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> u32 {
    // RFC 6528-style keyed ISN generation: ISN = F(secret, 4-tuple, counter)
    // Increment counter by 1 (not 64000) since mixing provides enough diffusion
    let counter = ISN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let secret = isn_secret();

    // R62-3 FIX: Track connections established with weak entropy for auditing
    // This allows monitoring of security posture during early boot
    if ISN_SECRET_WEAK.load(Ordering::Relaxed) {
        ISN_WEAK_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    }

    // Pack 4-tuple into 64-bit values for mixing
    let tuple_ip = u64::from_be_bytes([
        local_ip.0[0],
        local_ip.0[1],
        local_ip.0[2],
        local_ip.0[3],
        remote_ip.0[0],
        remote_ip.0[1],
        remote_ip.0[2],
        remote_ip.0[3],
    ]);
    let tuple_port = ((local_port as u64) << 48) | ((remote_port as u64) << 32) | (counter as u64);

    // SipHash-like mixing for unpredictable output
    // Multiple rounds of multiply-rotate-xor for avalanche effect
    let mut v0 = secret;
    let mut v1 = tuple_ip;

    // Round 1: Mix secret with IP tuple
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);

    // Round 2: Mix with port tuple
    v0 = v0.wrapping_add(tuple_port);
    v1 = v1.rotate_left(17);
    v0 ^= v1;
    v1 = v1.rotate_left(21);

    // Round 3: Final diffusion with golden ratio prime
    let mixed = v0.wrapping_add(v1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let final_mix = mixed.rotate_left(23);

    // Fold 64-bit result to 32-bit
    (final_mix >> 32) as u32 ^ final_mix as u32
}

// ============================================================================
// SYN Cookies (RFC 4987)
// ============================================================================
//
// SYN cookies provide SYN flood protection without allocating per-connection
// state for half-open connections. When the SYN backlog is full, we encode
// connection parameters into the ISN of the SYN-ACK:
//
// ISN Format (32 bits):
// +------------------------+-----------+------------+
// |     MAC (23 bits)      | Time (6b) | MSS (3b)   |
// +------------------------+-----------+------------+
//
// On receiving the final ACK, we validate the cookie by recomputing the MAC
// and checking the time slot hasn't expired.
//
// Limitations:
// - Window scaling information is lost (reverts to no scaling)
// - Only 8 MSS values supported (reduced precision)
// - SACK/Timestamps cannot be negotiated
//
// Security Properties:
// - CSPRNG-seeded secret rotated every 5 minutes
// - 23-bit MAC provides ~8 million possible values (brute force resistant)
// - 2-minute validity window limits replay attacks
// - Dual-secret system handles rotation gracefully

/// Decoded data from a validated SYN cookie.
///
/// Contains the recovered connection parameters for establishing the TCB.
#[derive(Debug, Clone, Copy)]
pub struct SynCookieData {
    /// Initial Sequence Number (the cookie value)
    pub iss: u32,
    /// MSS table index (0-7)
    pub mss_index: u8,
    /// Recovered MSS value from table
    pub mss: u16,
}

/// SYN cookie secret state with rotation support.
///
/// Maintains current and previous secrets for graceful rotation.
/// In-flight SYN-ACKs using the previous secret remain valid during
/// the transition period.
struct SynCookieSecrets {
    /// Current active secret for new cookies
    current: u64,
    /// Previous secret accepted during rotation grace period
    previous: u64,
    /// Timestamp of last rotation (milliseconds)
    last_rotated_ms: u64,
}

impl SynCookieSecrets {
    /// Create new secrets initialized from CSPRNG or fallback.
    fn new(now_ms: u64) -> Self {
        let key = syn_cookie_get_key();
        Self {
            current: key,
            // Initialize previous as derived from current (different value)
            previous: key.rotate_left(17) ^ 0xA5A5_A5A5_A5A5_A5A5,
            last_rotated_ms: now_ms,
        }
    }

    /// Get current and previous secrets, rotating if necessary.
    ///
    /// Rotation occurs when the secret age exceeds TCP_SYN_COOKIE_SECRET_ROTATE_MS.
    /// Both secrets are returned to allow validation of cookies generated with
    /// either the current or previous secret.
    fn get_secrets(&mut self, now_ms: u64) -> (u64, u64) {
        let elapsed = now_ms.saturating_sub(self.last_rotated_ms);
        if elapsed > TCP_SYN_COOKIE_SECRET_ROTATE_MS {
            // Rotate: current becomes previous, generate new current
            self.previous = self.current;
            self.current = syn_cookie_get_key();
            self.last_rotated_ms = now_ms;
        }
        (self.current, self.previous)
    }
}

/// Global SYN cookie secrets storage.
static SYN_COOKIE_SECRETS: Once<Mutex<SynCookieSecrets>> = Once::new();

/// Get the SYN cookie secrets state, initializing if necessary.
#[inline]
fn syn_cookie_state(now_ms: u64) -> &'static Mutex<SynCookieSecrets> {
    SYN_COOKIE_SECRETS.call_once(|| Mutex::new(SynCookieSecrets::new(now_ms)));
    SYN_COOKIE_SECRETS
        .get()
        .expect("SYN cookie secrets must be initialized")
}

/// Get a random key for SYN cookie generation.
///
/// Attempts to use CSPRNG; falls back to ISN secret if unavailable.
#[inline]
fn syn_cookie_get_key() -> u64 {
    // R149-5 FIX: Use fill_random (FIPS boundary pub API).
    let mut buf = [0u8; 8];
    if security::fill_random(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        isn_secret()
    }
}

/// Parameters for SYN cookie MAC computation.
///
/// Packs the 4-tuple and encoded values for hashing.
#[derive(Clone, Copy)]
struct SynCookieMacParams {
    /// Packed local and remote IP addresses
    tuple_ip: u64,
    /// Packed local and remote ports
    tuple_ports: u64,
    /// Time slot (6 bits)
    time_slot: u8,
    /// MSS table index (3 bits)
    mss_index: u8,
}

impl SynCookieMacParams {
    /// Create MAC parameters from connection 4-tuple and encoded values.
    fn new(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        time_slot: u8,
        mss_index: u8,
    ) -> Self {
        let tuple_ip = u64::from_be_bytes([
            local_ip.0[0],
            local_ip.0[1],
            local_ip.0[2],
            local_ip.0[3],
            remote_ip.0[0],
            remote_ip.0[1],
            remote_ip.0[2],
            remote_ip.0[3],
        ]);
        let tuple_ports = ((local_port as u64) << 48) | ((remote_port as u64) << 32);
        Self {
            tuple_ip,
            tuple_ports,
            time_slot,
            mss_index,
        }
    }
}

/// Compute SYN cookie MAC using SipHash-like mixing.
///
/// Returns a 23-bit MAC value for cookie verification.
///
/// # Security
///
/// Uses multiple rounds of multiply-rotate-xor mixing for avalanche effect.
/// The secret provides keying; the parameters provide domain separation.
#[inline]
fn syn_cookie_compute_mac(secret: u64, params: &SynCookieMacParams) -> u32 {
    // Mix secret with parameters using SipHash-like rounds
    let mut v0 = secret.rotate_left(7) ^ params.tuple_ip ^ ((params.time_slot as u64) << 24);
    let mut v1 = secret.rotate_right(11) ^ params.tuple_ports ^ ((params.mss_index as u64) << 8);

    // Round 1
    v0 = v0.wrapping_add(v1 ^ 0x9E37_79B9_7F4A_7C15).rotate_left(17);
    v1 ^= v0.rotate_right(19);

    // Round 2
    let mix = v0.wrapping_add(v1).rotate_left(23) ^ v1;

    // Fold to 23 bits
    ((mix as u32) ^ ((mix >> 32) as u32)) & TCP_SYN_COOKIE_MAC_MASK
}

/// Select the best MSS index for SYN cookie encoding.
///
/// Given a peer's offered MSS (or None for default), returns the index into
/// TCP_SYN_COOKIE_MSS_TABLE and the corresponding MSS value to advertise.
///
/// # Algorithm
///
/// Selects the largest table entry that doesn't exceed the offered MSS.
/// This ensures we don't send segments larger than the peer can handle.
///
/// # Arguments
///
/// * `offered` - The MSS value from the peer's SYN, or None if not specified
///
/// # Returns
///
/// A tuple of (table_index, mss_value) where table_index can be encoded
/// in 3 bits and mss_value is the actual MSS to use.
pub fn syn_cookie_select_mss(offered: Option<u16>) -> (u8, u16) {
    let target = offered.unwrap_or(TCP_ETHERNET_MSS);
    let mut best_index = 0usize;

    // Find the largest MSS that doesn't exceed the offered value
    for (i, &candidate) in TCP_SYN_COOKIE_MSS_TABLE.iter().enumerate() {
        if candidate <= target {
            best_index = i;
        } else {
            // Table is sorted, no need to check further
            break;
        }
    }

    (best_index as u8, TCP_SYN_COOKIE_MSS_TABLE[best_index])
}

/// Generate a SYN cookie ISN for stateless SYN-ACK.
///
/// When the SYN backlog is full, this function generates an ISN that encodes:
/// - 23 bits: MAC over (4-tuple, time_slot, mss_index, secret)
/// - 6 bits: Current time slot (4-second granularity)
/// - 3 bits: MSS index into TCP_SYN_COOKIE_MSS_TABLE
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
/// * `local_ip` - Local (server) IP address
/// * `local_port` - Local (server) port
/// * `remote_ip` - Remote (client) IP address
/// * `remote_port` - Remote (client) port
/// * `mss_index` - Index into MSS table (from syn_cookie_select_mss)
///
/// # Returns
///
/// The 32-bit ISN to use in the SYN-ACK segment.
///
/// # Security
///
/// The MAC provides authentication - only the server with the secret can
/// generate valid cookies. The time slot prevents replay attacks beyond
/// the validity window.
pub fn generate_syn_cookie_isn(
    now_ms: u64,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    mss_index: u8,
) -> u32 {
    // Compute current time slot (wrapping within 6-bit range)
    let time_slot =
        ((now_ms / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32) & TCP_SYN_COOKIE_TIME_MASK;

    // Build MAC parameters
    let params = SynCookieMacParams::new(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        time_slot as u8,
        mss_index,
    );

    // Get current secret (with rotation check)
    let (current_secret, _) = {
        let mut guard = syn_cookie_state(now_ms).lock();
        guard.get_secrets(now_ms)
    };

    // Compute MAC
    let mac = syn_cookie_compute_mac(current_secret, &params);

    // Pack into ISN: [MAC (23 bits)][Time (6 bits)][MSS (3 bits)]
    let data_bits = ((time_slot & TCP_SYN_COOKIE_TIME_MASK) << TCP_SYN_COOKIE_MSS_BITS)
        | (mss_index as u32 & TCP_SYN_COOKIE_MSS_MASK);
    (mac << (TCP_SYN_COOKIE_TIME_BITS + TCP_SYN_COOKIE_MSS_BITS)) | data_bits
}

/// Validate a SYN cookie from an incoming ACK and recover connection parameters.
///
/// When we receive an ACK completing the handshake but have no half-open
/// connection state, we attempt to validate it as a SYN cookie response.
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
/// * `cookie_isn` - The ISN we sent in the SYN-ACK (ACK number - 1)
/// * `local_ip` - Local (server) IP address
/// * `local_port` - Local (server) port
/// * `remote_ip` - Remote (client) IP address
/// * `remote_port` - Remote (client) port
///
/// # Returns
///
/// * `Some(SynCookieData)` if the cookie is valid and not expired
/// * `None` if the cookie is invalid, expired, or malformed
///
/// # Security
///
/// Validates the cookie against both current and previous secrets to handle
/// rotation gracefully. The time slot is checked against the maximum age
/// to prevent replay attacks. The MSS index is bounds-checked.
pub fn validate_syn_cookie(
    now_ms: u64,
    cookie_isn: u32,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Option<SynCookieData> {
    // Extract encoded fields from cookie
    let mss_index = (cookie_isn & TCP_SYN_COOKIE_MSS_MASK) as usize;
    if mss_index >= TCP_SYN_COOKIE_MSS_TABLE.len() {
        return None;
    }

    let time_slot = (cookie_isn >> TCP_SYN_COOKIE_MSS_BITS) & TCP_SYN_COOKIE_TIME_MASK;
    let received_mac = cookie_isn >> (TCP_SYN_COOKIE_TIME_BITS + TCP_SYN_COOKIE_MSS_BITS);

    // R62-1 FIX: Check age with wraparound protection.
    // The 6-bit time field wraps after 64 slots (256 seconds). Without this fix,
    // a cookie from slot 63 validated at slot 1 would compute age_slots = 2 after
    // masking, incorrectly passing the age check despite being ~252 seconds old.
    // We reject any age >= half the range (32 slots = 128s) to detect wrap-around.
    let now_slot =
        ((now_ms / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32) & TCP_SYN_COOKIE_TIME_MASK;
    let age_slots = now_slot.wrapping_sub(time_slot) & TCP_SYN_COOKIE_TIME_MASK;
    let half_range = 1u32 << (TCP_SYN_COOKIE_TIME_BITS - 1); // 32 slots = 128 seconds
    if age_slots > TCP_SYN_COOKIE_MAX_AGE_SLOTS || age_slots >= half_range {
        return None;
    }

    // Build MAC parameters
    let params = SynCookieMacParams::new(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        time_slot as u8,
        mss_index as u8,
    );

    // Get both secrets for rotation grace period
    let (current_secret, previous_secret) = {
        let mut guard = syn_cookie_state(now_ms).lock();
        guard.get_secrets(now_ms)
    };

    // R160-10 FIX: Constant-time MAC comparison (XOR-accumulate pattern).
    // While the 23-bit MAC makes timing attacks impractical over a network,
    // constant-time comparison is defense-in-depth best practice.
    let expected_mac = syn_cookie_compute_mac(current_secret, &params);
    if (received_mac ^ expected_mac) == 0 {
        return Some(SynCookieData {
            iss: cookie_isn,
            mss_index: mss_index as u8,
            mss: TCP_SYN_COOKIE_MSS_TABLE[mss_index],
        });
    }

    // Try previous secret (for rotation grace period)
    let expected_mac_prev = syn_cookie_compute_mac(previous_secret, &params);
    if (received_mac ^ expected_mac_prev) == 0 {
        return Some(SynCookieData {
            iss: cookie_isn,
            mss_index: mss_index as u8,
            mss: TCP_SYN_COOKIE_MSS_TABLE[mss_index],
        });
    }

    // Invalid cookie
    None
}

// ============================================================================
// Sequence Number Arithmetic (RFC 793 Section 3.3)
// ============================================================================

/// Check if sequence number a is less than b (with wraparound)
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Check if sequence number a is less than or equal to b (with wraparound)
#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// Check if sequence number a is greater than b (with wraparound)
#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Check if sequence number a is greater than or equal to b (with wraparound)
#[inline]
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Check if sequence number seq is within window [left, left+size)
#[inline]
pub fn seq_in_window(seq: u32, left: u32, size: u32) -> bool {
    let right = left.wrapping_add(size);
    if size == 0 {
        false
    } else if seq_le(left, right) {
        // No wraparound
        seq_ge(seq, left) && seq_lt(seq, right)
    } else {
        // Window wraps around
        seq_ge(seq, left) || seq_lt(seq, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_header_parsing() {
        // SYN packet
        let syn = [
            0x00, 0x50, // src port 80
            0x1F, 0x90, // dst port 8080
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, // data offset 5 (20 bytes)
            0x02, // SYN flag
            0xFF, 0xFF, // window 65535
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent ptr
        ];

        let header = parse_tcp_header(&syn).unwrap();
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 8080);
        assert_eq!(header.seq_num, 1);
        assert_eq!(header.ack_num, 0);
        assert!(header.is_syn());
        assert!(!header.is_ack());
    }

    #[test]
    fn test_tcp_checksum_known_syn_wire_vector() {
        // Independently generated Internet-checksum vector for:
        // 192.0.2.1:12345 -> 198.51.100.2:80, seq=0x11223344,
        // SYN, window=64240, no options/payload.  The expected checksum is a
        // fixed wire oracle, not derived by another helper in this crate.
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let mut syn = [
            0x30, 0x39, // source port 12345
            0x00, 0x50, // destination port 80
            0x11, 0x22, 0x33, 0x44, // sequence
            0x00, 0x00, 0x00, 0x00, // acknowledgment
            0x50, 0x02, // data offset 5, SYN
            0xfa, 0xf0, // window 64240
            0x00, 0x00, // checksum placeholder
            0x00, 0x00, // urgent pointer
        ];

        assert_eq!(compute_tcp_checksum(src, dst, &syn), 0x53cb);
        syn[16..18].copy_from_slice(&0x53cbu16.to_be_bytes());
        assert!(verify_tcp_checksum(src, dst, &syn));

        // A bit flip must not validate against the known checksum.
        syn[4] ^= 0x01;
        assert!(!verify_tcp_checksum(src, dst, &syn));
    }

    #[test]
    fn test_tcp_checksum_odd_payload_wire_vector() {
        // Same header as the SYN oracle with an odd-length "abc" payload.
        // The independent expected checksum pins high-byte padding of the
        // final odd octet (RFC 1071) as well as pseudo-header composition.
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let mut segment = [
            0x30, 0x39, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, b'a', b'b', b'c',
        ];

        assert_eq!(compute_tcp_checksum(src, dst, &segment), 0x8f65);
        segment[16..18].copy_from_slice(&0x8f65u16.to_be_bytes());
        assert!(verify_tcp_checksum(src, dst, &segment));
    }

    #[test]
    fn test_oversized_checksum_and_builders_fail_closed() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let oversized_payload = vec![0u8; u16::MAX as usize - TCP_HEADER_MIN_LEN + 1];
        let oversized_segment = vec![0u8; u16::MAX as usize + 1];

        assert_eq!(
            try_compute_tcp_checksum(src, dst, &oversized_segment),
            Err(TcpError::SegmentTooLong)
        );
        assert!(!verify_tcp_checksum(src, dst, &oversized_segment));
        assert_eq!(
            try_build_tcp_segment(
                src,
                dst,
                12345,
                80,
                1,
                0,
                TCP_FLAG_SYN,
                TCP_DEFAULT_WINDOW,
                &oversized_payload,
            ),
            Err(TcpError::SegmentTooLong)
        );
        assert!(build_tcp_segment(
            src,
            dst,
            12345,
            80,
            1,
            0,
            TCP_FLAG_SYN,
            TCP_DEFAULT_WINDOW,
            &oversized_payload,
        )
        .is_empty());

        assert_eq!(
            try_build_tcp_segment_with_options(
                src,
                dst,
                12345,
                80,
                1,
                0,
                TCP_FLAG_SYN,
                TCP_DEFAULT_WINDOW,
                &[TcpOptionKind::Mss(1460)],
                &oversized_payload,
            ),
            Err(TcpError::SegmentTooLong)
        );
    }

    #[test]
    fn rf180_41_tcp_wire_admission_failure_is_fail_closed() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);

        WirePacket::fail_next_admission_for_test();
        assert_eq!(
            try_build_tcp_segment(
                src,
                dst,
                12345,
                80,
                1,
                0,
                TCP_FLAG_SYN,
                TCP_DEFAULT_WINDOW,
                &[],
            ),
            Err(TcpError::AllocationFailed)
        );

        WirePacket::fail_next_admission_for_test();
        assert!(build_tcp_segment(
            src,
            dst,
            12345,
            80,
            1,
            0,
            TCP_FLAG_SYN,
            TCP_DEFAULT_WINDOW,
            &[],
        )
        .is_empty());
    }

    #[test]
    fn rf180_41_tcp_option_wire_bytes_remain_exact() {
        assert_eq!(
            serialize_tcp_option(&TcpOptionKind::Mss(1460)).as_slice(),
            &[2, 4, 0x05, 0xb4]
        );
        assert_eq!(
            serialize_tcp_option(&TcpOptionKind::Unknown { kind: 30, len: 1 }).as_slice(),
            &[30, 2]
        );

        let serialized = serialize_tcp_options(&[
            TcpOptionKind::Mss(1460),
            TcpOptionKind::WindowScale(7),
            TcpOptionKind::SackPermitted,
        ]);
        assert_eq!(
            serialized.as_slice(),
            &[2, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 0, 0, 0]
        );
    }

    #[test]
    fn test_seq_arithmetic() {
        // Normal case
        assert!(seq_lt(100, 200));
        assert!(seq_le(100, 100));
        assert!(seq_gt(200, 100));

        // Wraparound case
        assert!(seq_lt(0xFFFFFFFF, 0));
        assert!(seq_gt(0, 0xFFFFFFFF));
    }

    #[test]
    fn test_tcp_state() {
        assert!(!TcpState::Closed.can_send());
        assert!(TcpState::Established.can_send());
        assert!(TcpState::Established.can_receive());
        assert!(!TcpState::TimeWait.can_receive());
    }

    #[test]
    fn r180_ooo_merge_preflights_complete_transitive_span() {
        mm::publish_heap_budgets();
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr::new(10, 0, 0, 1),
            1000,
            Ipv4Addr::new(10, 0, 0, 2),
            2000,
            1,
        );

        // Seed two adjacent legacy ranges directly. A one-pass scan starting
        // from the new range at 108 would skip [100,104), merge [104,108), and
        // need a second pass to discover the newly adjacent earlier range.
        for (seq, bytes) in [(100, &[1u8; 4][..]), (104, &[2u8; 4][..])] {
            tcb.ooo_queue
                .try_push(OooSegment {
                    seq,
                    data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, bytes)
                        .expect("OOO test payload admission"),
                    fin: false,
                })
                .map_err(|_| ())
                .expect("OOO test queue admission");
        }
        tcb.ooo_bytes = 8;

        assert_eq!(tcb.ooo_insert(108, &[3u8; 4], false), 12);
        assert_eq!(tcb.ooo_queue.len(), 1);
        let merged = tcb.ooo_queue.front().expect("merged OOO range");
        assert_eq!(merged.seq, 100);
        assert_eq!(
            merged.data.as_slice(),
            &[1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]
        );
        assert_eq!(tcb.ooo_bytes, 12);
    }

    #[test]
    fn r180_ooo_queue_growth_failure_is_non_mutating() {
        mm::publish_heap_budgets();
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr::new(10, 0, 0, 1),
            1000,
            Ipv4Addr::new(10, 0, 0, 2),
            2000,
            1,
        );
        tcb.ooo_queue.fail_next_growth_for_test();

        assert_eq!(tcb.ooo_insert(100, &[9u8; 4], false), 0);
        assert!(tcb.ooo_queue.is_empty());
        assert_eq!(tcb.ooo_bytes, 0);
    }

    #[test]
    fn rf180_7_ooo_merge_preserves_earliest_fin_across_wrap() {
        mm::publish_heap_budgets();
        let mut tcb = TcpControlBlock::new_client(
            Ipv4Addr::new(10, 0, 0, 1),
            1000,
            Ipv4Addr::new(10, 0, 0, 2),
            2000,
            1,
        );

        // [MAX-3, 0) carries FIN at sequence 0. The second range begins at 1,
        // immediately after that FIN. An injected byte at the FIN position must
        // merge transitively, preserve the earliest FIN, and discard all data
        // beyond it even though the sequence interval wraps through zero.
        for (seq, bytes, fin) in [
            (u32::MAX - 3, &[1u8; 4][..], true),
            (1, &[2u8; 3][..], false),
        ] {
            tcb.ooo_queue
                .try_push(OooSegment {
                    seq,
                    data: AdmittedVec::try_copy_from_slice(HeapClass::SocketPayload, bytes)
                        .expect("OOO wrap payload admission"),
                    fin,
                })
                .map_err(|_| ())
                .expect("OOO wrap queue admission");
        }
        tcb.ooo_bytes = 7;

        assert_eq!(tcb.ooo_insert(0, &[9], false), 4);
        assert_eq!(tcb.ooo_queue.len(), 1);
        let merged = tcb.ooo_queue.front().expect("wrapped merged range");
        assert_eq!(merged.seq, u32::MAX - 3);
        assert_eq!(merged.data.as_slice(), &[1, 1, 1, 1]);
        assert!(merged.fin);
        assert_eq!(tcb.ooo_bytes, 4);
    }
}
