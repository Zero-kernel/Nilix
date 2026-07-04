//! poll(7) / select(23) / pselect6(270) / ppoll(271) — pure ABI + readiness core.
//!
//! M0-6 Post-M0 (Priority 1: event infrastructure). This module holds ONLY the
//! pure, lock-free, allocation-free pieces of the poll/select family: the POLL*
//! constants, the `PollFd` wire struct, the `fd_set` bitmap codec, the
//! timeout-conversion math, and the revents masking / select-bit mapping. The
//! stateful machinery (fd classification, readiness probes, the wait loop, the
//! four syscall handlers) lives in `kernel_core::syscall` where it can hold the
//! Process lock and reach the per-kind probes.
//!
//! # Design invariants (see docs/next-phase-plan.md M0-6 poll/select section)
//! - **I7 pointer-free:** this module NEVER touches a raw user pointer. It
//!   operates on owned values, `&[u64]`, and `&mut [u64]` only. Every raw
//!   user-memory copy / `read_unaligned` site lives in `syscall.rs`, which IS in
//!   the `lint-repr-c-copy` FILES scan (this file is not). Keeping the codec here
//!   value-only is what makes that lint hole harmless.
//! - The functions here are the single normative source for the revents truth
//!   table's *masking* and the timeout math; the per-kind readiness *values* are
//!   produced by the probes in `syscall.rs` and fed through `mask_revents`.

use alloc::sync::Arc;

// ────────────────────────────────────────────────────────────────────────────
// POLL* event bits (Linux x86-64 asm-generic values).
// ────────────────────────────────────────────────────────────────────────────
pub const POLLIN: i16 = 0x001;
pub const POLLPRI: i16 = 0x002;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;
pub const POLLRDNORM: i16 = 0x040;
pub const POLLWRNORM: i16 = 0x100;
pub const POLLRDHUP: i16 = 0x2000;

/// Bits that are ALWAYS reported in `revents` regardless of the requested
/// `events` mask (POSIX: POLLERR/POLLHUP/POLLNVAL are output-only and can never
/// be suppressed by the caller's interest set).
pub const POLL_ALWAYS: i16 = POLLERR | POLLHUP | POLLNVAL;

/// Upper bound on `nfds` for poll/ppoll and on the effective fd range for
/// select/pselect6. select is additionally clamped to `MAX_FD` (256) in the
/// handler; this constant bounds the poll array + the fd_set logical width so a
/// crafted `nfds` cannot drive an unbounded allocation.
pub const POLL_MAX_NFDS: usize = 1024;
/// select(2) fd_set logical width. Mirrors Linux FD_SETSIZE; the actual scanned
/// range is `min(nfds, MAX_FD)` because this kernel's fd_table caps at MAX_FD.
pub const FD_SETSIZE: usize = 1024;

// ────────────────────────────────────────────────────────────────────────────
// pollfd wire struct (Linux ABI: { i32 fd; i16 events; i16 revents } = 8 bytes,
// no padding, every byte pattern valid → safe to build from raw user bytes in
// syscall.rs via the TimeSpec-style annotated copy).
// ────────────────────────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// Non-consuming readiness snapshot produced by a per-kind probe. Booleans, not
/// raw POLL* bits, so a probe cannot accidentally emit a requested-only bit; the
/// caller maps this to bits via `status_to_bits` then masks with `mask_revents`.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PollStatus {
    pub readable: bool,
    pub writable: bool,
    pub hup: bool,
    pub err: bool,
    pub rdhup: bool,
}

/// Non-consuming readiness probe for an fd kind that lives in another crate
/// (pipe today; the trait is defined here in kernel_core so ipc/vfs can
/// implement it without a dependency cycle — the same pattern as `FileOps`).
///
/// An implementor MUST NOT block, allocate, mutate observable state, or fire any
/// wakeups, and MUST hold at most one leaf lock for the duration of the call.
pub trait PollProbeOps: Send + Sync {
    /// Readiness of the READ end (POLLIN / POLLHUP relevant).
    fn poll_status_read(&self) -> PollStatus;
    /// Readiness of the WRITE end (POLLOUT / POLLERR relevant).
    fn poll_status_write(&self) -> PollStatus;
}

/// Classification of an fd for polling, produced under the Process lock and
/// consumed by the lock-free probe pass. The socket arm carries ONLY Copy ids
/// (never an `Arc<SocketState>`): a Drop-bearing socket handle parked here would
/// let `SocketState::drop` run its per-namespace uncharge under the Process lock
/// and would defeat the re-resolution-per-tick lifetime rule (see the
/// TEARDOWN/LIFETIME lens + lock_ordering.rs strong-owner enumeration).
pub enum PollArm {
    /// Always ready per Linux DEFAULT_POLLMASK (regular files, ns fds, unknown).
    AlwaysReady,
    /// A cross-crate probe (pipe). `write_end` selects which end's status to read.
    Dyn {
        probe: Arc<dyn PollProbeOps>,
        write_end: bool,
    },
    /// A socket fd; resolved to `Arc<SocketState>` fresh in the probe pass.
    Socket { cap_id: cap::CapId, socket_id: u64 },
}

// ────────────────────────────────────────────────────────────────────────────
// fd_set bitmap codec (select). fd_set is an array of 64-bit words, LSB-first:
// fd N lives in word N/64, bit N%64.
// ────────────────────────────────────────────────────────────────────────────

/// Number of u64 words needed to hold `nfds` bits.
#[inline]
pub fn fd_set_words(nfds: usize) -> usize {
    nfds.div_ceil(64)
}

/// Test bit `fd` in a copied fd_set. Returns false if `fd` is outside `bits`.
#[inline]
pub fn fd_set_test(bits: &[u64], fd: usize) -> bool {
    let w = fd / 64;
    w < bits.len() && (bits[w] & (1u64 << (fd % 64))) != 0
}

/// Set bit `fd` in an output fd_set. No-op if `fd` is outside `bits`.
#[inline]
pub fn fd_set_mark(bits: &mut [u64], fd: usize) {
    let w = fd / 64;
    if w < bits.len() {
        bits[w] |= 1u64 << (fd % 64);
    }
}

/// Zero every bit `>= nfds` in the copied words (Linux do_select stops the
/// per-word scan at `nfds`). A userspace fd_set can carry stale bits beyond the
/// requested `nfds`; without trimming, those would be treated as selected and
/// produce spurious EBADF / spurious readiness. MUST be applied after every set
/// copy-in, before building entries.
pub fn fd_set_trim(bits: &mut [u64], nfds: usize) {
    for (w, word) in bits.iter_mut().enumerate() {
        let base = w * 64;
        if base >= nfds {
            *word = 0;
        } else if base + 64 > nfds {
            // Partial word straddling the nfds boundary: keep bits [0, nfds-base).
            let keep = nfds - base;
            *word &= (1u64 << keep) - 1;
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Timeout conversion. This kernel's tick is milliseconds, so poll timeouts are
// converted to a whole-ms bound (ceil, min 1 for any nonzero request — the
// R172-20 nanosleep rounding rule: never under-sleep a sub-ms request into a
// busy no-op). Returns Ok(None) for "infinite", Ok(Some(ms)) for a bound.
// ────────────────────────────────────────────────────────────────────────────

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;
const US_PER_SEC: i64 = 1_000_000;

#[inline]
fn ns_to_ms_ceil(total_ns: u64) -> u64 {
    if total_ns == 0 {
        0
    } else {
        (total_ns / NS_PER_MS)
            .saturating_add(if total_ns % NS_PER_MS != 0 { 1 } else { 0 })
            .max(1)
    }
}

/// Convert a `struct timespec` to a millisecond bound. STRICT (ppoll/pselect6
/// semantics): `tv_nsec` must be in `[0, 1e9)` and `tv_sec >= 0`, else EINVAL
/// (returned as `Err(())`). `{0,0}` → `Some(0)` (poll returns immediately).
pub fn timespec_to_ms(tv_sec: i64, tv_nsec: i64) -> Result<Option<u64>, ()> {
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= NS_PER_SEC as i64 {
        return Err(());
    }
    let total_ns = (tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(tv_nsec as u64);
    Ok(Some(ns_to_ms_ceil(total_ns)))
}

/// Convert a `struct timeval` to a millisecond bound. LENIENT (select
/// semantics): Linux `kern_select` NORMALIZES an unnormalized timeval
/// (`tv_usec >= 1e6` folds into `tv_sec`) and only rejects negatives. Real
/// programs pass computed values like `{0, 2_500_000}`.
pub fn timeval_to_ms(tv_sec: i64, tv_usec: i64) -> Result<Option<u64>, ()> {
    if tv_sec < 0 || tv_usec < 0 {
        return Err(());
    }
    // Normalize (saturating): fold whole seconds out of usec.
    let sec = (tv_sec as u64).saturating_add((tv_usec / US_PER_SEC) as u64);
    let usec = (tv_usec % US_PER_SEC) as u64;
    let total_ns = sec
        .saturating_mul(NS_PER_SEC)
        .saturating_add(usec.saturating_mul(1_000));
    Ok(Some(ns_to_ms_ceil(total_ns)))
}

/// Split a millisecond count into `(tv_sec, tv_nsec)` for remaining-time
/// write-back (ppoll/pselect6).
#[inline]
pub fn ms_to_timespec(ms: u64) -> (i64, i64) {
    (
        (ms / 1000) as i64,
        ((ms % 1000).saturating_mul(NS_PER_MS)) as i64,
    )
}

/// Split a millisecond count into `(tv_sec, tv_usec)` for remaining-time
/// write-back (select).
#[inline]
pub fn ms_to_timeval(ms: u64) -> (i64, i64) {
    (
        (ms / 1000) as i64,
        ((ms % 1000).saturating_mul(1_000)) as i64,
    )
}

// ────────────────────────────────────────────────────────────────────────────
// revents masking + select-bit mapping.
// ────────────────────────────────────────────────────────────────────────────

/// Map a probe's `PollStatus` to the pre-mask computed revents bits.
#[inline]
pub fn status_to_bits(st: &PollStatus) -> i16 {
    let mut r = 0i16;
    if st.readable {
        r |= POLLIN | POLLRDNORM;
    }
    if st.writable {
        r |= POLLOUT | POLLWRNORM;
    }
    if st.hup {
        r |= POLLHUP;
    }
    if st.err {
        r |= POLLERR;
    }
    if st.rdhup {
        r |= POLLRDHUP;
    }
    r
}

/// Mask computed revents against the caller's requested `events`. POLLERR /
/// POLLHUP / POLLNVAL always pass (output-only); every other bit (incl.
/// POLLRDHUP) is reported only if the caller requested it.
#[inline]
pub fn mask_revents(events: i16, computed: i16) -> i16 {
    computed & (events | POLL_ALWAYS)
}

/// Map a poll `revents` value to `(readable, writable, except)` for select's
/// three fd_sets. readfds ← IN|HUP|ERR|RDNORM; writefds ← OUT|ERR|WRNORM;
/// exceptfds ← PRI (never fires here — no out-of-band data support).
#[inline]
pub fn select_bits(revents: i16) -> (bool, bool, bool) {
    let rd = revents & (POLLIN | POLLHUP | POLLERR | POLLRDNORM) != 0;
    let wr = revents & (POLLOUT | POLLERR | POLLWRNORM) != 0;
    let ex = revents & POLLPRI != 0;
    (rd, wr, ex)
}

// ────────────────────────────────────────────────────────────────────────────
// Pure self-test (registered from kernel/src/integration_test.rs). Covers the
// codec / trim / timeout math / masking — the parity a green boot cannot catch.
// ────────────────────────────────────────────────────────────────────────────

/// Pure poll-core self-test. Panics on failure (caught by the boot test harness).
pub fn run_poll_pure_self_test() {
    // PollFd wire layout is load-bearing (raw user copy in syscall.rs).
    assert_eq!(core::mem::size_of::<PollFd>(), 8, "pollfd must be 8 bytes");
    assert_eq!(core::mem::align_of::<PollFd>(), 4, "pollfd align 4");

    // fd_set words / test / mark across word boundaries.
    assert_eq!(fd_set_words(0), 0);
    assert_eq!(fd_set_words(1), 1);
    assert_eq!(fd_set_words(64), 1);
    assert_eq!(fd_set_words(65), 2);
    let mut bits = [0u64; 4];
    fd_set_mark(&mut bits, 0);
    fd_set_mark(&mut bits, 63);
    fd_set_mark(&mut bits, 64);
    fd_set_mark(&mut bits, 255);
    assert!(fd_set_test(&bits, 0) && fd_set_test(&bits, 63));
    assert!(fd_set_test(&bits, 64) && fd_set_test(&bits, 255));
    assert!(!fd_set_test(&bits, 1) && !fd_set_test(&bits, 62));
    assert!(!fd_set_test(&bits, 256), "out-of-range fd must read false");

    // fd_set_trim clears bits >= nfds, preserves bits below.
    let mut t = [u64::MAX; 2];
    fd_set_trim(&mut t, 5);
    assert_eq!(t[0], (1u64 << 5) - 1, "trim@5 keeps bits 0..5");
    assert_eq!(t[1], 0, "trim@5 clears the high word");
    let mut t = [u64::MAX; 2];
    fd_set_trim(&mut t, 64);
    assert_eq!(t[0], u64::MAX, "trim@64 keeps the whole low word");
    assert_eq!(t[1], 0);
    let mut t = [u64::MAX; 2];
    fd_set_trim(&mut t, 65);
    assert_eq!(t[1], 1, "trim@65 keeps exactly bit 64");

    // timespec_to_ms: strict edges.
    assert_eq!(timespec_to_ms(0, 0), Ok(Some(0)));
    assert_eq!(timespec_to_ms(0, 1), Ok(Some(1)), "sub-ms rounds up to 1");
    assert_eq!(timespec_to_ms(0, NS_PER_MS as i64), Ok(Some(1)));
    assert_eq!(timespec_to_ms(1, 500_000_000), Ok(Some(1500)));
    assert_eq!(
        timespec_to_ms(0, NS_PER_SEC as i64),
        Err(()),
        "nsec==1e9 EINVAL"
    );
    assert_eq!(timespec_to_ms(-1, 0), Err(()));
    assert_eq!(timespec_to_ms(0, -1), Err(()));

    // timeval_to_ms: lenient normalization + negative rejection.
    assert_eq!(timeval_to_ms(0, 0), Ok(Some(0)));
    assert_eq!(
        timeval_to_ms(0, 2_500_000),
        Ok(Some(2500)),
        "unnormalized ok"
    );
    assert_eq!(timeval_to_ms(0, 1), Ok(Some(1)), "1us rounds to 1ms");
    assert_eq!(timeval_to_ms(-1, 0), Err(()));
    assert_eq!(timeval_to_ms(0, -1), Err(()));

    // ms→timespec / ms→timeval round components.
    assert_eq!(ms_to_timespec(1500), (1, 500_000_000));
    assert_eq!(ms_to_timeval(1500), (1, 500_000));

    // mask_revents: ERR/HUP/NVAL always pass; IN only if requested; RDHUP requested.
    assert_eq!(mask_revents(0, POLLERR), POLLERR, "ERR passes unrequested");
    assert_eq!(mask_revents(0, POLLHUP), POLLHUP, "HUP passes unrequested");
    assert_eq!(
        mask_revents(0, POLLNVAL),
        POLLNVAL,
        "NVAL passes unrequested"
    );
    assert_eq!(mask_revents(0, POLLIN), 0, "IN suppressed when unrequested");
    // Requesting only POLLIN strips the co-emitted POLLRDNORM (Linux masks
    // revents by events|ERR|HUP|NVAL; RDNORM is a distinct bit that must be
    // requested to be reported).
    assert_eq!(
        mask_revents(POLLIN, POLLIN | POLLRDNORM),
        POLLIN,
        "RDNORM stripped when only IN requested"
    );
    assert_eq!(
        mask_revents(POLLIN | POLLRDNORM, POLLIN | POLLRDNORM),
        POLLIN | POLLRDNORM,
        "RDNORM reported when requested"
    );
    assert_eq!(mask_revents(0, POLLRDHUP), 0, "RDHUP needs request");
    assert_eq!(mask_revents(POLLRDHUP, POLLRDHUP), POLLRDHUP);

    // status_to_bits + select_bits mapping.
    let st = PollStatus {
        readable: true,
        writable: false,
        hup: true,
        err: false,
        rdhup: true,
    };
    let bits = status_to_bits(&st);
    assert!(bits & POLLIN != 0 && bits & POLLHUP != 0 && bits & POLLRDHUP != 0);
    assert!(bits & POLLOUT == 0);
    assert_eq!(select_bits(POLLHUP), (true, false, false), "HUP→read-ready");
    assert_eq!(select_bits(POLLERR), (true, true, false), "ERR→read+write");
    assert_eq!(select_bits(POLLPRI), (false, false, true), "PRI→except");
    assert_eq!(select_bits(POLLOUT | POLLWRNORM), (false, true, false));
}
