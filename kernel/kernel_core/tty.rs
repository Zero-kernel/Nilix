//! Minimal Console TTY Line Discipline & Termios State (N2.5 / BusyBox Gate)
//!
//! Provides POSIX-compatible `struct termios` storage (60-byte x86_64 Linux ABI),
//! lock-free IRQ-safe control-character signal latching (`^C` -> `SIGINT`,
//! `^\` -> `SIGQUIT`, `^Z` -> `SIGTSTP`), `ICRNL` carriage-return translation,
//! and allocation-free canonical line editing (`ICANON`, `VERASE`, `VKILL`,
//! `VEOF`, `ECHO`) over the serial/keyboard console.
//!
//! # Lock & IRQ Safety
//! - `on_rx_byte_irq()` is called directly from `serial_interrupt_handler`
//!   (IRQ context) and touches ONLY lock-free atomics (`RX_CONFIG` and
//!   `PENDING_TTY_SIGNALS`). It never acquires `PROCESS_TABLE`, PCB locks,
//!   or heap allocations.
//! - `drain_pending_tty_signals()` runs in deferred soft-progress context
//!   (and at console read entry), scans `PROCESS_TABLE` into a fixed stack
//!   array (`[ProcessId; 64]`, zero heap allocations), and delivers latched
//!   signals to the controlling terminal's foreground process group.

use crate::process::{ProcessId, ProcessState, PROCESS_TABLE};
use crate::signal::Signal;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

/// Linux x86_64 `struct termios` wire size in bytes (`NCCS = 32`).
pub const TERMIOS_SIZE: usize = 60;
const NCCS: usize = 32;

// Input flags (`c_iflag`)
pub const ICRNL: u32 = 0x0100;

// Output flags (`c_oflag`)
pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;

// Control flags (`c_cflag`)
pub const CS8: u32 = 0x0030;
pub const CREAD: u32 = 0x0080;
pub const HUPCL: u32 = 0x0400;
pub const B38400: u32 = 0x000F;

// Local flags (`c_lflag`)
pub const ISIG: u32 = 0x0001;
pub const ICANON: u32 = 0x0002;
pub const ECHO: u32 = 0x0008;
pub const ECHOE: u32 = 0x0010;
pub const ECHOK: u32 = 0x0020;
pub const IEXTEN: u32 = 0x8000;

// Control character indices (`c_cc`)
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSUSP: usize = 10;

// Pending signal latch bits in `PENDING_TTY_SIGNALS`.
const LATCH_SIGINT: u64 = 1 << 0;
const LATCH_SIGQUIT: u64 = 1 << 1;
const LATCH_SIGTSTP: u64 = 1 << 2;

// Bit packing inside `RX_CONFIG`:
//   bits  0..7:  vintr
//   bits  8..15: vquit
//   bits 16..23: vsusp
//   bit  24:     ISIG enabled
//   bit  25:     ICRNL enabled
const RX_FLAG_ISIG: u64 = 1 << 24;
const RX_FLAG_ICRNL: u64 = 1 << 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl ConsoleTermios {
    pub const fn posix_default() -> Self {
        let mut cc = [0u8; NCCS];
        cc[VINTR] = 0x03; // ^C
        cc[VQUIT] = 0x1C; // ^\
        cc[VERASE] = 0x7F; // DEL
        cc[VKILL] = 0x15; // ^U
        cc[VEOF] = 0x04; // ^D
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[VSUSP] = 0x1A; // ^Z
        Self {
            c_iflag: ICRNL,
            c_oflag: OPOST | ONLCR,
            c_cflag: B38400 | CS8 | CREAD | HUPCL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            c_line: 0,
            c_cc: cc,
            c_ispeed: B38400,
            c_ospeed: B38400,
        }
    }

    pub fn to_bytes(&self) -> [u8; TERMIOS_SIZE] {
        let mut out = [0u8; TERMIOS_SIZE];
        out[0..4].copy_from_slice(&self.c_iflag.to_ne_bytes());
        out[4..8].copy_from_slice(&self.c_oflag.to_ne_bytes());
        out[8..12].copy_from_slice(&self.c_cflag.to_ne_bytes());
        out[12..16].copy_from_slice(&self.c_lflag.to_ne_bytes());
        out[16] = self.c_line;
        out[17..49].copy_from_slice(&self.c_cc);
        // bytes 49..52 are struct padding (stay zero)
        out[52..56].copy_from_slice(&self.c_ispeed.to_ne_bytes());
        out[56..60].copy_from_slice(&self.c_ospeed.to_ne_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8; TERMIOS_SIZE]) -> Self {
        let c_iflag = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let c_oflag = u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let c_cflag = u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let c_lflag = u32::from_ne_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let c_line = raw[16];
        let mut c_cc = [0u8; NCCS];
        c_cc.copy_from_slice(&raw[17..49]);
        let c_ispeed = u32::from_ne_bytes([raw[52], raw[53], raw[54], raw[55]]);
        let c_ospeed = u32::from_ne_bytes([raw[56], raw[57], raw[58], raw[59]]);
        Self {
            c_iflag,
            c_oflag,
            c_cflag,
            c_lflag,
            c_line,
            c_cc,
            c_ispeed,
            c_ospeed,
        }
    }

    const fn pack_rx_config(&self) -> u64 {
        let mut v = (self.c_cc[VINTR] as u64)
            | ((self.c_cc[VQUIT] as u64) << 8)
            | ((self.c_cc[VSUSP] as u64) << 16);
        if self.c_lflag & ISIG != 0 {
            v |= RX_FLAG_ISIG;
        }
        if self.c_iflag & ICRNL != 0 {
            v |= RX_FLAG_ICRNL;
        }
        v
    }
}

const DEFAULT_TERMIOS: ConsoleTermios = ConsoleTermios::posix_default();

static CONSOLE_TERMIOS: Mutex<ConsoleTermios> = Mutex::new(DEFAULT_TERMIOS);
static RX_CONFIG: AtomicU64 = AtomicU64::new(DEFAULT_TERMIOS.pack_rx_config());
static PENDING_TTY_SIGNALS: AtomicU64 = AtomicU64::new(0);
static CONSOLE_FG_PGID: AtomicUsize = AtomicUsize::new(1);

/// Result of classifying one incoming serial/keyboard byte in IRQ context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxAction {
    /// Deliver this byte to the input buffer (possibly CR->NL translated).
    Data(u8),
    /// Byte matched `VINTR`/`VQUIT`/`VSUSP` under `ISIG` and latched a signal;
    /// caller must schedule soft-progress drain and wake stdin waiters.
    Signal,
}

/// Update the cached foreground process group ID of the console TTY.
#[inline]
pub fn set_fg_pgid(pgid: ProcessId) {
    CONSOLE_FG_PGID.store(pgid, Ordering::Release);
}

/// Read the cached foreground process group ID of the console TTY.
#[inline]
pub fn fg_pgid() -> ProcessId {
    CONSOLE_FG_PGID.load(Ordering::Acquire)
}

/// Serialize the current console `struct termios` for `TCGETS`.
pub fn get_termios_bytes() -> [u8; TERMIOS_SIZE] {
    CONSOLE_TERMIOS.lock().to_bytes()
}

/// Update the console `struct termios` for `TCSETS`/`TCSETSW`/`TCSETSF`.
pub fn set_termios_bytes(raw: &[u8; TERMIOS_SIZE], flush_input: bool) {
    let parsed = ConsoleTermios::from_bytes(raw);
    {
        let mut guard = CONSOLE_TERMIOS.lock();
        *guard = parsed;
    }
    RX_CONFIG.store(parsed.pack_rx_config(), Ordering::Release);
    if flush_input {
        flush_console_input();
    }
}

/// Lock-free IRQ-safe classifier for incoming serial console bytes.
#[inline]
pub fn on_rx_byte_irq(byte: u8) -> RxAction {
    let cfg = RX_CONFIG.load(Ordering::Acquire);
    if cfg & RX_FLAG_ISIG != 0 && byte != 0 {
        let vintr = (cfg & 0xFF) as u8;
        let vquit = ((cfg >> 8) & 0xFF) as u8;
        let vsusp = ((cfg >> 16) & 0xFF) as u8;
        if byte == vintr {
            PENDING_TTY_SIGNALS.fetch_or(LATCH_SIGINT, Ordering::AcqRel);
            return RxAction::Signal;
        }
        if byte == vquit {
            PENDING_TTY_SIGNALS.fetch_or(LATCH_SIGQUIT, Ordering::AcqRel);
            return RxAction::Signal;
        }
        if byte == vsusp {
            PENDING_TTY_SIGNALS.fetch_or(LATCH_SIGTSTP, Ordering::AcqRel);
            return RxAction::Signal;
        }
    }
    let out = if cfg & RX_FLAG_ICRNL != 0 && byte == b'\r' {
        b'\n'
    } else {
        byte
    };
    RxAction::Data(out)
}

/// Allocation-free delivery of a TTY job-control signal to all live thread
/// groups in `pgid`. Safe to invoke from soft-progress context.
fn deliver_signal_to_pgid_noalloc(pgid: ProcessId, signal: Signal) {
    if pgid == 0 {
        return;
    }
    let mut targets = [0usize; 64];
    let mut count = 0usize;
    {
        let table = PROCESS_TABLE.lock();
        for (slot_pid, slot) in table.iter().enumerate() {
            let Some(arc) = slot else { continue };
            let p = arc.lock();
            if p.tgid == slot_pid
                && !matches!(p.state, ProcessState::Zombie | ProcessState::Terminated)
                && p.thread_group.pgid() == pgid
            {
                if count < targets.len() {
                    targets[count] = slot_pid;
                    count += 1;
                }
            }
        }
    }
    for &tgid in &targets[..count] {
        let _ = crate::signal::send_signal_kernel(tgid, signal);
    }
}

/// Deferred soft-progress drain for TTY signals latched by `on_rx_byte_irq()`.
pub fn drain_pending_tty_signals() {
    let bits = PENDING_TTY_SIGNALS.swap(0, Ordering::AcqRel);
    if bits == 0 {
        return;
    }
    let fg = CONSOLE_FG_PGID.load(Ordering::Acquire);
    if bits & LATCH_SIGINT != 0 {
        deliver_signal_to_pgid_noalloc(fg, Signal::SIGINT);
    }
    if bits & LATCH_SIGQUIT != 0 {
        deliver_signal_to_pgid_noalloc(fg, Signal::SIGQUIT);
    }
    if bits & LATCH_SIGTSTP != 0 {
        deliver_signal_to_pgid_noalloc(fg, Signal::SIGTSTP);
    }
}

// ============================================================================
// Allocation-Free Canonical Line Discipline Buffer
// ============================================================================

const CANON_BUF_CAP: usize = 512;

struct CanonState {
    /// In-progress editing line (not yet committed by `\n` or `^D`).
    edit: [u8; CANON_BUF_CAP],
    edit_len: usize,
    /// Completed line bytes ready for `read(2)` consumers.
    ready: [u8; CANON_BUF_CAP],
    ready_head: usize,
    ready_len: usize,
    /// Pending zero-byte EOF marker from `VEOF` (`^D`) on an empty line.
    pending_eof: bool,
}

impl CanonState {
    const fn new() -> Self {
        Self {
            edit: [0u8; CANON_BUF_CAP],
            edit_len: 0,
            ready: [0u8; CANON_BUF_CAP],
            ready_head: 0,
            ready_len: 0,
            pending_eof: false,
        }
    }

    fn clear(&mut self) {
        self.edit_len = 0;
        self.ready_head = 0;
        self.ready_len = 0;
        self.pending_eof = false;
    }

    fn push_ready_byte(&mut self, b: u8) {
        if self.ready_len >= CANON_BUF_CAP {
            return;
        }
        let idx = (self.ready_head + self.ready_len) % CANON_BUF_CAP;
        self.ready[idx] = b;
        self.ready_len += 1;
    }

    fn flush_edit_to_ready(&mut self) {
        for i in 0..self.edit_len {
            let b = self.edit[i];
            self.push_ready_byte(b);
        }
        self.edit_len = 0;
    }

    fn feed_byte(&mut self, b: u8, verase: u8, vkill: u8, veof: u8) {
        if (verase != 0 && b == verase) || b == 0x08 {
            if self.edit_len > 0 {
                self.edit_len -= 1;
            }
            return;
        }
        if vkill != 0 && b == vkill {
            self.edit_len = 0;
            return;
        }
        if veof != 0 && b == veof {
            if self.edit_len > 0 {
                self.flush_edit_to_ready();
            } else {
                self.pending_eof = true;
            }
            return;
        }
        if self.edit_len < CANON_BUF_CAP {
            self.edit[self.edit_len] = b;
            self.edit_len += 1;
        }
        if b == b'\n' || self.edit_len >= CANON_BUF_CAP {
            self.flush_edit_to_ready();
        }
    }

    fn peek_ready(&self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.ready_len);
        for (i, slot) in dst.iter_mut().take(n).enumerate() {
            *slot = self.ready[(self.ready_head + i) % CANON_BUF_CAP];
        }
        n
    }

    fn consume_ready(&mut self, n: usize) {
        let take = core::cmp::min(n, self.ready_len);
        self.ready_head = (self.ready_head + take) % CANON_BUF_CAP;
        self.ready_len -= take;
        if self.ready_len == 0 {
            self.ready_head = 0;
        }
    }
}

static CANON_STATE: Mutex<CanonState> = Mutex::new(CanonState::new());

/// Clear both the raw keyboard buffer and any in-progress canonical line.
pub fn flush_console_input() {
    drivers::keyboard::clear();
    CANON_STATE.lock().clear();
}

/// Outcome of a non-blocking console read attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleReadOutcome {
    /// Successfully copied `n` bytes (where `n == 0` signals `VEOF` / EOF).
    Ready(usize),
    /// No complete line (or raw byte) is available yet; caller should block.
    WouldBlock,
}

/// Read available console input according to current `ICANON` / `ECHO` flags.
///
/// Copies bytes into user memory via `commit` BEFORE consuming them from the
/// ready queue so an `EFAULT` loses zero input.
pub fn console_read_with_commit<E, F>(
    scratch: &mut [u8],
    commit: F,
) -> Result<ConsoleReadOutcome, E>
where
    F: FnOnce(&[u8]) -> Result<(), E>,
{
    drain_pending_tty_signals();

    let (icanon, echo, verase, vkill, veof) = {
        let t = CONSOLE_TERMIOS.lock();
        (
            t.c_lflag & ICANON != 0,
            t.c_lflag & ECHO != 0,
            t.c_cc[VERASE],
            t.c_cc[VKILL],
            t.c_cc[VEOF],
        )
    };

    if !icanon {
        // Non-canonical mode: preserve direct raw keyboard reads.
        let n = drivers::keyboard_read_with_commit(scratch, commit)?;
        return if n > 0 {
            Ok(ConsoleReadOutcome::Ready(n))
        } else {
            Ok(ConsoleReadOutcome::WouldBlock)
        };
    }

    // Drain any newly arrived raw bytes into the canonical line buffer.
    let mut echo_buf = [0u8; 64];
    let mut echo_len = 0usize;
    let (ready_n, is_eof) = {
        let mut canon = CANON_STATE.lock();
        while canon.ready_len < CANON_BUF_CAP && !canon.pending_eof {
            let Some(ch) = drivers::keyboard_read_char() else {
                break;
            };
            if echo && echo_len < echo_buf.len() {
                if ch == b'\n' || (0x20..0x7f).contains(&ch) {
                    echo_buf[echo_len] = ch;
                    echo_len += 1;
                }
            }
            canon.feed_byte(ch, verase, vkill, veof);
            if canon.ready_len > 0 || canon.pending_eof {
                break;
            }
        }
        let n = canon.peek_ready(scratch);
        if n > 0 {
            (n, false)
        } else if canon.pending_eof {
            canon.pending_eof = false;
            (0, true)
        } else {
            (0, false)
        }
    };

    if echo && echo_len > 0 {
        if let Ok(text) = core::str::from_utf8(&echo_buf[..echo_len]) {
            let mut session = drivers::vga_buffer::ConsoleWrite::begin(
                crate::process::current_pid().unwrap_or(0),
            );
            session.write_str(text);
        }
    }

    if is_eof {
        return Ok(ConsoleReadOutcome::Ready(0));
    }
    if ready_n == 0 {
        return Ok(ConsoleReadOutcome::WouldBlock);
    }

    commit(&scratch[..ready_n])?;
    CANON_STATE.lock().consume_ready(ready_n);
    Ok(ConsoleReadOutcome::Ready(ready_n))
}

/// Check whether canonical/raw console input has readable data right now
/// (used by `FIONREAD` and `poll(POLLIN)`).
pub fn console_bytes_readable() -> usize {
    let icanon = CONSOLE_TERMIOS.lock().c_lflag & ICANON != 0;
    if !icanon {
        return drivers::keyboard_available();
    }
    let canon = CANON_STATE.lock();
    if canon.ready_len > 0 || canon.pending_eof {
        canon.ready_len.max(1)
    } else {
        drivers::keyboard_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termios_wire_layout_and_defaults_roundtrip() {
        let def = ConsoleTermios::posix_default();
        let bytes = def.to_bytes();
        assert_eq!(bytes.len(), TERMIOS_SIZE);
        let parsed = ConsoleTermios::from_bytes(&bytes);
        assert_eq!(parsed, def);
        assert_ne!(parsed.c_iflag & ICRNL, 0);
        assert_ne!(parsed.c_lflag & ISIG, 0);
        assert_ne!(parsed.c_lflag & ICANON, 0);
        assert_eq!(parsed.c_cc[VINTR], 0x03);
        assert_eq!(parsed.c_cc[VQUIT], 0x1C);
        assert_eq!(parsed.c_cc[VSUSP], 0x1A);
    }

    #[test]
    fn rx_irq_classifier_latches_job_control_signals_and_translates_cr() {
        let _guard = crate::HOSTED_CPU_CONTEXT_TEST_LOCK.lock();
        let saved = get_termios_bytes();
        let def = ConsoleTermios::posix_default().to_bytes();
        set_termios_bytes(&def, false);
        PENDING_TTY_SIGNALS.store(0, Ordering::SeqCst);

        assert_eq!(on_rx_byte_irq(b'\r'), RxAction::Data(b'\n'));
        assert_eq!(on_rx_byte_irq(b'a'), RxAction::Data(b'a'));
        assert_eq!(on_rx_byte_irq(0x03), RxAction::Signal);
        assert_eq!(on_rx_byte_irq(0x1A), RxAction::Signal);
        assert_eq!(on_rx_byte_irq(0x1C), RxAction::Signal);
        let latched = PENDING_TTY_SIGNALS.swap(0, Ordering::SeqCst);
        assert_eq!(latched, LATCH_SIGINT | LATCH_SIGTSTP | LATCH_SIGQUIT);

        // Disabling ISIG and ICRNL passes control bytes and CR through verbatim.
        let mut raw = ConsoleTermios::posix_default();
        raw.c_lflag &= !ISIG;
        raw.c_iflag &= !ICRNL;
        set_termios_bytes(&raw.to_bytes(), false);
        assert_eq!(on_rx_byte_irq(0x03), RxAction::Data(0x03));
        assert_eq!(on_rx_byte_irq(0x1A), RxAction::Data(0x1A));
        assert_eq!(on_rx_byte_irq(b'\r'), RxAction::Data(b'\r'));
        assert_eq!(PENDING_TTY_SIGNALS.load(Ordering::SeqCst), 0);

        set_termios_bytes(&saved, false);
    }

    #[test]
    fn canonical_line_discipline_handles_erase_kill_nl_and_eof() {
        let mut canon = CanonState::new();
        for &b in b"abx" {
            canon.feed_byte(b, 0x7f, 0x15, 0x04);
        }
        canon.feed_byte(0x7f, 0x7f, 0x15, 0x04); // erase 'x'
        canon.feed_byte(b'c', 0x7f, 0x15, 0x04);
        let mut out = [0u8; 16];
        assert_eq!(canon.peek_ready(&mut out), 0); // not yet newline-terminated
        canon.feed_byte(b'\n', 0x7f, 0x15, 0x04);
        assert_eq!(canon.peek_ready(&mut out), 4);
        assert_eq!(&out[..4], b"abc\n");
        canon.consume_ready(4);
        assert_eq!(canon.peek_ready(&mut out), 0);

        // VKILL discards partial line; VEOF on empty line sets pending_eof.
        canon.feed_byte(b'z', 0x7f, 0x15, 0x04);
        canon.feed_byte(0x15, 0x7f, 0x15, 0x04);
        canon.feed_byte(0x04, 0x7f, 0x15, 0x04);
        assert!(canon.pending_eof);
    }
}
