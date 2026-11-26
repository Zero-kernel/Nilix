// VGA文本模式缓冲区实现
// Uses volatile writes to ensure MMIO operations reach the VGA hardware
use core::cell::UnsafeCell;
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    buffer: &'static mut Buffer,
}

impl Writer {
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;

                let color_code = self.color_code;
                // Use volatile write to ensure MMIO reaches VGA hardware
                unsafe {
                    ptr::write_volatile(
                        &mut self.buffer.chars[row][col],
                        ScreenChar {
                            ascii_character: byte,
                            color_code,
                        },
                    );
                }
                self.column_position += 1;
            }
        }
    }

    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                // 可打印的ASCII字节，或换行符
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                // 非可打印的ASCII字节
                _ => self.write_byte(0xfe),
            }
        }
    }

    fn new_line(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                // Use volatile read/write for MMIO safety
                let character = unsafe { ptr::read_volatile(&self.buffer.chars[row][col]) };
                unsafe { ptr::write_volatile(&mut self.buffer.chars[row - 1][col], character) };
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
        self.column_position = 0;
    }

    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            // Use volatile write for MMIO safety
            unsafe { ptr::write_volatile(&mut self.buffer.chars[row][col], blank) };
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer {
        column_position: 0,
        color_code: ColorCode::new(Color::Yellow, Color::Black),
        // VGA缓冲区虚拟地址 (物理0xb8000映射到虚拟0xffffffff800b8000)
        buffer: unsafe { &mut *(0xffffffff800b8000 as *mut Buffer) },
    });
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::vga_buffer::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

// 串口端口地址 (COM1 16550A)
const SERIAL_PORT: u16 = 0x3F8;
#[cfg(not(test))]
const SERIAL_IER_PORT: u16 = SERIAL_PORT + 1;
#[cfg(not(test))]
const SERIAL_LSR_PORT: u16 = SERIAL_PORT + 5;
#[cfg(not(test))]
const SERIAL_IER_OFF: u8 = 0x00;
#[cfg(not(test))]
const SERIAL_IER_RX: u8 = 0x01;
#[cfg(not(test))]
const SERIAL_IER_RX_TX: u8 = 0x03;
#[cfg(not(test))]
const SERIAL_LSR_THRE: u8 = 0x20;
#[cfg(not(test))]
const SERIAL_LSR_TEMT: u8 = 0x40;

/// 16550A hardware TX FIFO depth (enabled via FCR = 0xC7).
const SERIAL_TX_FIFO_DEPTH: usize = 16;

/// Max bytes drained per IRQ4 invocation (4 × 16-byte FIFO fills, checking
/// `LSR_THRE` before each fill). On real 16550A hardware `THRE` clears after
/// one 16-byte fill; under QEMU this keeps each IRQ-masked hold tiny (~200 µs).
const SERIAL_TX_IRQ_MAX_BURST: usize = 64;

/// Maximum consecutive full IRQ4 bursts (8 × 64 = 512 bytes) before deferring
/// PIC ExtINT to grant LAPIC vectors a quiet service window.
const SERIAL_TX_MAX_CONSECUTIVE_BURSTS: u8 = 8;

/// Bounded wait retries for UART readiness (`LSR_THRE` / `LSR_TEMT`) so dead
/// or absent UART hardware never livelocks backpressure, panic, or shutdown.
#[cfg(not(test))]
const BACKPRESSURE_TX_READY_SPINS: usize = 100_000;
#[cfg(test)]
const BACKPRESSURE_TX_READY_SPINS: usize = 16;

#[cfg(not(test))]
const PANIC_TX_READY_SPINS: usize = 100_000;
#[cfg(test)]
const PANIC_TX_READY_SPINS: usize = 16;

#[cfg(not(test))]
const TERMINAL_TEMT_SPINS: usize = 200_000;
#[cfg(test)]
const TERMINAL_TEMT_SPINS: usize = 16;

/// Asynchronous TX ring buffer capacity (power of two). Holds 16 KiB (~65
/// stress rounds) before falling back to FIFO-ready synchronous backpressure.
const SERIAL_TX_BUF_CAP: usize = 16 * 1024;
const SERIAL_TX_BUF_MASK: usize = SERIAL_TX_BUF_CAP - 1;

/// 向串口写入一个字节
///
/// No `nomem`: the port write must stay between the serial lock's acquire and
/// release (TD-SERIAL-1).
#[cfg(not(test))]
unsafe fn serial_outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
    );
}

// Hosted tests cannot execute `out`; they record the bytes instead.
#[cfg(test)]
unsafe fn serial_outb(_port: u16, val: u8) {
    tests::PORT_LOG.lock().unwrap().push(val);
}

/// Enable or disable COM1 TX-empty interrupts (`IER` bit 1, keeping RX bit 0).
///
/// No `nomem`: must stay ordered with ring buffer updates under `SERIAL_OWNER_CPU`.
#[cfg(not(test))]
unsafe fn serial_set_tx_irq(enable: bool) {
    let ier = if enable {
        SERIAL_IER_RX_TX
    } else {
        SERIAL_IER_RX
    };
    core::arch::asm!(
        "out dx, al",
        in("dx") SERIAL_IER_PORT,
        in("al") ier,
    );
}

#[cfg(test)]
unsafe fn serial_set_tx_irq(enable: bool) {
    tests::TX_IRQ_ENABLED.store(enable, Ordering::SeqCst);
}

/// Force all enabled COM1 interrupt sources off (`IER = 0x00`) and then restore
/// `IER = ERBFI | ETBEI` (`0x03`).
///
/// On a PC16550D wired to an edge-triggered 8259 PIC, pending RX data keeps the
/// shared INTR line high across `IER = 0x03 -> 0x01 -> 0x03`. Clearing `IER` to
/// `0x00` drives INTR strictly low without touching the RX FIFO, so restoring
/// `0x03` guarantees a clean rising edge for both RX and TX.
#[cfg(not(test))]
unsafe fn serial_pulse_all_irqs_for_tx() {
    core::arch::asm!(
        "out dx, al",
        in("dx") SERIAL_IER_PORT,
        in("al") SERIAL_IER_OFF,
    );
    core::arch::asm!(
        "out dx, al",
        in("dx") SERIAL_IER_PORT,
        in("al") SERIAL_IER_RX_TX,
    );
}

#[cfg(test)]
unsafe fn serial_pulse_all_irqs_for_tx() {
    tests::IER_FULL_PULSES.fetch_add(1, Ordering::SeqCst);
    tests::TX_IRQ_ENABLED.store(true, Ordering::SeqCst);
}

/// Returns `true` if COM1's Transmitter Holding Register / TX FIFO is empty (`LSR_THRE`).
#[cfg(not(test))]
unsafe fn serial_tx_ready() -> bool {
    let lsr: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") lsr,
        in("dx") SERIAL_LSR_PORT,
    );
    (lsr & SERIAL_LSR_THRE) != 0
}

#[cfg(test)]
unsafe fn serial_tx_ready() -> bool {
    let ready = tests::TX_READY_MOCK.load(Ordering::SeqCst);
    if !ready {
        let inject = tests::TX_READY_INJECT_OPEN_LINE.swap(NO_OPEN_LINE, Ordering::SeqCst);
        if inject != NO_OPEN_LINE {
            // Simulate another stream writing an unfinished line after this
            // caller unlocks on THRE=0 and before its next retry.
            tests::PORT_LOG
                .lock()
                .unwrap()
                .extend_from_slice(b"prompt> ");
            SERIAL_OPEN_LINE.store(inject, Ordering::SeqCst);
            tests::TX_READY_MOCK.store(true, Ordering::SeqCst);
        }
    }
    ready
}

/// Returns `true` if both COM1's TX FIFO and shift register are empty (`LSR_TEMT`).
#[cfg(not(test))]
unsafe fn serial_tx_empty() -> bool {
    let lsr: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") lsr,
        in("dx") SERIAL_LSR_PORT,
    );
    (lsr & SERIAL_LSR_TEMT) != 0
}

#[cfg(test)]
unsafe fn serial_tx_empty() -> bool {
    tests::TX_EMPTY_MOCK.load(Ordering::SeqCst)
}

const NO_DISPLAY_OWNER: usize = usize::MAX;

/// Owner token used before the BSP is registered in `cpu_local` (single-CPU
/// early boot, or an AP printing before its own registration).
const UNREGISTERED_DISPLAY_OWNER: usize = usize::MAX - 1;

/// R190-7 FIX: the display lock *and* its owner in one word.
///
/// Holds the logical CPU that owns the display backends (VGA text and
/// framebuffer), or `NO_DISPLAY_OWNER`. Taking ownership and naming the owner
/// are one `compare_exchange`, and releasing is one store, so there is no
/// window in which the lock is held without a recorded owner.
static DISPLAY_OWNER_CPU: AtomicUsize = AtomicUsize::new(NO_DISPLAY_OWNER);

/// R190-7 FIX: run `f` with exclusive use of the display, or skip it.
///
/// The display writers used to take a plain spin lock with IRQs enabled. A
/// print from an IRQ handler, exception or NMI on a CPU already inside
/// `_print` therefore spun on its own lock forever. A re-entry on the owning
/// CPU now sees its own id, skips the display and returns `None`. Serial
/// output is written by the caller either way. Other CPUs spin until the
/// owner finishes a bounded render. No IRQ masking is needed: rendering keeps
/// the caller's IRQ state (a full-screen framebuffer scroll is too long to run
/// with ticks masked), and waiting CPUs still service IPIs. Unregistered
/// contexts share one owner token, so overlapping prints between them skip
/// the display instead of risking a self-deadlock. The framebuffer/VGA
/// `WRITER` mutexes are only taken inside `f`, so they are always uncontended.
pub(crate) fn with_display<R>(f: impl FnOnce() -> R) -> Option<R> {
    let owner = console_owner_token();
    loop {
        match DISPLAY_OWNER_CPU.compare_exchange_weak(
            NO_DISPLAY_OWNER,
            owner,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(current) if current == owner => return None,
            Err(_) => core::hint::spin_loop(),
        }
    }
    let result = f();
    DISPLAY_OWNER_CPU.store(NO_DISPLAY_OWNER, Ordering::Release);
    Some(result)
}

/// The calling context's owner token for the display and serial locks: its
/// registered logical CPU, or the shared token before registration.
#[inline]
fn console_owner_token() -> usize {
    cpu_local::try_current_registered_cpu_id().unwrap_or(UNREGISTERED_DISPLAY_OWNER)
}

/// Whether the legacy VGA text buffer is this boot's display.
///
/// It is, unless the firmware handed over a graphics framebuffer. A firmware
/// that does has left the adapter in a graphics mode, where the text buffer
/// at `0xB8000` is not scanned out. Console output written there shows
/// nothing, and one scrolled line costs 3920 single-cell accesses, each an
/// emulated device access under an emulator (C3, #90).
static TEXT_DISPLAY: AtomicBool = AtomicBool::new(true);

/// C3 (#90): the firmware handed over a graphics framebuffer, so the text
/// buffer is not the display for the rest of this boot, whether or not the
/// kernel accepts that framebuffer. Call before the first console output.
pub fn disable_text_display() {
    TEXT_DISPLAY.store(false, Ordering::Release);
}

/// Where console output is rendered besides the serial port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayBackend {
    /// The firmware's framebuffer, accepted by the kernel.
    Framebuffer,
    /// The legacy text buffer: no framebuffer was handed over.
    VgaText,
    /// A framebuffer was handed over and is not in use, refused at boot or
    /// turned off later: serial port only.
    Absent,
}

fn display_backend(framebuffer_ready: bool, text_display: bool) -> DisplayBackend {
    if framebuffer_ready {
        DisplayBackend::Framebuffer
    } else if text_display {
        DisplayBackend::VgaText
    } else {
        DisplayBackend::Absent
    }
}

fn active_display() -> DisplayBackend {
    display_backend(
        crate::framebuffer::is_initialized(),
        TEXT_DISPLAY.load(Ordering::Acquire),
    )
}

/// Whether console output is rendered anywhere besides the serial port. The
/// kernel reports a boot that has no display from this, whichever check
/// refused the framebuffer.
pub fn has_display() -> bool {
    active_display() != DisplayBackend::Absent
}

/// Render to the active display backend.
fn write_display(args: fmt::Arguments) {
    use core::fmt::Write;
    // Without a display there is nothing to render, and no reason to queue
    // every CPU's console output on the display lock.
    if active_display() == DisplayBackend::Absent {
        return;
    }
    let _ = with_display(|| match active_display() {
        // 优先输出到 framebuffer（现代 GOP 方式）
        DisplayBackend::Framebuffer => crate::framebuffer::write_args(args),
        // 后备：输出到 VGA 文本缓冲区（旧式 BIOS）
        DisplayBackend::VgaText => {
            let _ = WRITER.lock().write_fmt(args);
        }
        DisplayBackend::Absent => {}
    });
}

/// R190-13 FIX: the character a kernel message may put on the serial console.
///
/// Kernel diagnostics can embed user-controlled text (paths, argv, names).
/// Raw C0/C1 control characters, ESC included, would let that text drive the
/// operator's terminal emulator. Every Unicode control character except
/// newline and tab becomes `?`. Other characters, including non-ASCII text,
/// pass unchanged. The VGA path already substitutes non-printables.
#[inline]
fn serial_safe_char(ch: char) -> char {
    if ch == '\n' || ch == '\t' || !ch.is_control() {
        ch
    } else {
        '?'
    }
}

// ============================================================================
// TD-SERIAL-1: serial console lock
// ============================================================================

/// TD-SERIAL-1: the most bytes one serial-lock hold writes, and so the longest
/// run that reaches the UART with no other output inside it. The longest
/// console line in the R192 gate logs is 242 bytes. A hold masks IRQs, so this
/// also bounds the masked time (reported at PID 1's exit, see
/// [`serial_hold_stats`]). Polling the THRE inside a hold would break that
/// bound.
const SERIAL_CHUNK: usize = 256;

const NO_SERIAL_OWNER: usize = usize::MAX;

/// TD-SERIAL-1 FIX: the serial lock and its owner in one word (the R190-7
/// shape): `NO_SERIAL_OWNER`, or the owner token of the writing context.
static SERIAL_OWNER_CPU: AtomicUsize = AtomicUsize::new(NO_SERIAL_OWNER);

/// Line state on the UART: the stream whose last chunk did not end with a
/// newline, or `NO_OPEN_LINE`. Read and written only under the lock.
static SERIAL_OPEN_LINE: AtomicUsize = AtomicUsize::new(NO_OPEN_LINE);
const NO_OPEN_LINE: usize = usize::MAX;

/// Stream id of the kernel shell's raw echo and prompt.
const SHELL_STREAM: usize = usize::MAX - 2;
/// Stream ids of user TTY data are `USER_STREAM | task id`; kernel output
/// uses the writing CPU's owner token, which is below this.
const USER_STREAM: usize = 1 << 48;

/// Longest hold so far, in TSC cycles.
static SERIAL_MAX_HOLD_TSC: AtomicU64 = AtomicU64::new(0);

/// Bytes written by the longest hold.
static SERIAL_MAX_HOLD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Locked holds, the bytes they wrote and their total TSC cycles.
static SERIAL_HOLDS: AtomicU64 = AtomicU64::new(0);
static SERIAL_HOLD_BYTES: AtomicU64 = AtomicU64::new(0);
static SERIAL_HOLD_TSC: AtomicU64 = AtomicU64::new(0);

/// Holds of at least 2^18, 2^20, 2^22 and 2^24 TSC cycles.
const SERIAL_HOLD_BUCKET_SHIFTS: [u32; 4] = [18, 20, 22, 24];
static SERIAL_HOLDS_OVER: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Set once IDT, PIC, and COM1 FIFO/RX interrupts are armed (right before `sti`).
/// Cleared permanently on panic or terminal shutdown/reboot.
static SERIAL_TX_IRQ_READY: AtomicBool = AtomicBool::new(false);

/// Lock-free mirror of queued bytes in `SERIAL_TX_RING` for fast idle checks.
static SERIAL_TX_PENDING: AtomicUsize = AtomicUsize::new(0);

/// Lock-free mirror of `ring.tx_irq_armed`.
static SERIAL_TX_IRQ_ARMED: AtomicBool = AtomicBool::new(false);

/// Lock-free mirror of `ring.tx_irq_deferred`: `true` while IRQ4 intentionally
/// yielded PIC ExtINT to give LAPIC vectors a guaranteed quiet service window.
static SERIAL_TX_IRQ_DEFERRED: AtomicBool = AtomicBool::new(false);

/// Set when non-blocking IRQ4 failed to acquire `SERIAL_OWNER_CPU`, prompting
/// the next BSP timer tick to immediately pulse `IER` for recovery.
static SERIAL_TX_MISSED_LOCK: AtomicBool = AtomicBool::new(false);

/// Monotonic drain progress counter updated under `SERIAL_OWNER_CPU` whenever
/// bytes leave `SERIAL_TX_RING` to the UART (used by the BSP timer backstop).
static SERIAL_TX_DRAIN_SEQ: AtomicU64 = AtomicU64::new(0);

/// BSP timer-tick backstop state (accessed only on CPU 0 in timer IRQ).
static SERIAL_TX_LAST_TICK_PENDING: AtomicBool = AtomicBool::new(false);
static SERIAL_TX_LAST_TICK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Fixed-size FIFO ring buffer for IRQ4-driven COM1 transmission.
///
/// Accessed exclusively while holding `SERIAL_OWNER_CPU` (with IRQs masked)
/// or after `claim_serial_for_panic` acquires `SERIAL_OWNER_CPU`.
struct SerialTxRing {
    buf: [u8; SERIAL_TX_BUF_CAP],
    head: usize,
    tail: usize,
    len: usize,
    /// Monotonic total bytes pushed into the ring (watermark for bounded flush).
    enqueued_total: u64,
    /// Monotonic total bytes popped out of the ring to the UART.
    drained_total: u64,
    tx_irq_armed: bool,
    /// Deliberate LAPIC yield deferral; producers must not re-enable THRI while set.
    tx_irq_deferred: bool,
    /// Remaining BSP ticks before clearing `tx_irq_deferred` (ensures at least
    /// one quiet interval after a PIT IRQ0 returns before re-asserting IRQ4).
    defer_quiet_ticks: u8,
    consecutive_bursts: u8,
}

impl SerialTxRing {
    const fn new() -> Self {
        Self {
            buf: [0; SERIAL_TX_BUF_CAP],
            head: 0,
            tail: 0,
            len: 0,
            enqueued_total: 0,
            drained_total: 0,
            tx_irq_armed: false,
            tx_irq_deferred: false,
            defer_quiet_ticks: 0,
            consecutive_bursts: 0,
        }
    }

    #[inline]
    fn free_space(&self) -> usize {
        SERIAL_TX_BUF_CAP - self.len
    }

    #[inline]
    fn push_byte(&mut self, byte: u8) {
        debug_assert!(self.len < SERIAL_TX_BUF_CAP);
        self.buf[self.tail] = byte;
        self.tail = (self.tail + 1) & SERIAL_TX_BUF_MASK;
        self.len += 1;
        self.enqueued_total = self.enqueued_total.wrapping_add(1);
    }

    fn push_slice(&mut self, src: &[u8]) {
        debug_assert!(src.len() <= self.free_space());
        if src.is_empty() {
            return;
        }
        let first = src.len().min(SERIAL_TX_BUF_CAP - self.tail);
        self.buf[self.tail..self.tail + first].copy_from_slice(&src[..first]);
        let rem = src.len() - first;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&src[first..]);
        }
        self.tail = (self.tail + src.len()) & SERIAL_TX_BUF_MASK;
        self.len += src.len();
        self.enqueued_total = self.enqueued_total.wrapping_add(src.len() as u64);
    }

    #[inline]
    fn pop_byte(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let byte = self.buf[self.head];
        self.head = (self.head + 1) & SERIAL_TX_BUF_MASK;
        self.len -= 1;
        self.drained_total = self.drained_total.wrapping_add(1);
        Some(byte)
    }

    #[inline]
    fn sync_pending_and_seq(&self, drained: usize) {
        SERIAL_TX_PENDING.store(self.len, Ordering::Release);
        if drained > 0 {
            let seq = SERIAL_TX_DRAIN_SEQ.load(Ordering::Relaxed).wrapping_add(1);
            SERIAL_TX_DRAIN_SEQ.store(seq, Ordering::Relaxed);
        }
    }

    /// Disarm THRI while preserving any active LAPIC yield deferral cooldown
    /// (used by non-terminal drains such as RX-triggered IRQ4 or `flush_serial_sync`).
    #[inline]
    fn disarm_tx_irq_keep_deferral(&mut self) {
        self.tx_irq_armed = false;
        self.consecutive_bursts = 0;
        SERIAL_TX_IRQ_ARMED.store(false, Ordering::Release);
        unsafe { serial_set_tx_irq(false) };
    }

    /// Disarm THRI and clear LAPIC deferral (used only on cooldown expiry,
    /// terminal shutdown/reboot, or panic).
    #[inline]
    fn disarm_tx_irq_clear_deferral(&mut self) {
        self.tx_irq_armed = false;
        self.tx_irq_deferred = false;
        self.defer_quiet_ticks = 0;
        self.consecutive_bursts = 0;
        SERIAL_TX_IRQ_ARMED.store(false, Ordering::Release);
        SERIAL_TX_IRQ_DEFERRED.store(false, Ordering::Release);
        unsafe { serial_set_tx_irq(false) };
    }

    /// Drain up to `limit` oldest bytes in 16-byte FIFO batches, checking
    /// `LSR_THRE` before each batch and dequeuing only bytes actually accepted.
    fn drain_ready_up_to(&mut self, limit: usize) -> usize {
        let mut drained = 0usize;
        while drained < limit && self.len > 0 {
            if !unsafe { serial_tx_ready() } {
                break;
            }
            let batch = self.len.min(SERIAL_TX_FIFO_DEPTH).min(limit - drained);
            for _ in 0..batch {
                if let Some(byte) = self.pop_byte() {
                    unsafe { serial_outb(SERIAL_PORT, byte) };
                    drained += 1;
                }
            }
        }
        self.sync_pending_and_seq(drained);
        drained
    }

    /// Bounded timeout fallback for broken/absent UART hardware when `THRE`
    /// never asserts: force-submit up to `limit` bytes so callers retain
    /// forward progress.
    fn drain_unconditional_up_to(&mut self, limit: usize) -> usize {
        let count = self.len.min(limit);
        for _ in 0..count {
            if let Some(byte) = self.pop_byte() {
                unsafe { serial_outb(SERIAL_PORT, byte) };
            }
        }
        self.sync_pending_and_seq(count);
        count
    }

    /// Drain all queued bytes for panic (IF already masked permanently),
    /// pacing each 16-byte FIFO fill on `LSR_THRE` with a bounded spin timeout.
    fn drain_all_panic_bounded(&mut self) -> usize {
        let mut total = 0usize;
        while self.len > 0 {
            for _ in 0..PANIC_TX_READY_SPINS {
                if unsafe { serial_tx_ready() } {
                    break;
                }
                core::hint::spin_loop();
            }
            let batch = self.len.min(SERIAL_TX_FIFO_DEPTH);
            for _ in 0..batch {
                if let Some(byte) = self.pop_byte() {
                    unsafe { serial_outb(SERIAL_PORT, byte) };
                    total += 1;
                }
            }
        }
        self.sync_pending_and_seq(total);
        self.disarm_tx_irq_clear_deferral();
        total
    }
}

struct SerialTxRingCell(UnsafeCell<SerialTxRing>);

// SAFETY: `SerialTxRingCell` is only dereferenced while holding
// `SERIAL_OWNER_CPU` with IRQs masked (exclusive access across all CPUs).
unsafe impl Sync for SerialTxRingCell {}

static SERIAL_TX_RING: SerialTxRingCell = SerialTxRingCell(UnsafeCell::new(SerialTxRing::new()));

/// Wrap-safe remaining distance from `drained` to `target`.
/// Returns `0` once `drained` has reached or passed `target` (e.g. when a
/// concurrent IRQ4 drain overtakes a flush caller's captured watermark).
#[inline]
fn watermark_remaining(target: u64, drained: u64) -> usize {
    let diff = target.wrapping_sub(drained) as i64;
    if diff <= 0 {
        0
    } else {
        (diff as u64).min(usize::MAX as u64) as usize
    }
}

/// Record one IRQ-masked serial hold into `TD-SERIAL-1` statistics.
/// Caller must hold `SERIAL_OWNER_CPU`.
#[inline]
fn record_serial_hold(held: u64, sample_bytes: usize, count_output_bytes: bool) {
    if held > SERIAL_MAX_HOLD_TSC.load(Ordering::Relaxed) {
        SERIAL_MAX_HOLD_TSC.store(held, Ordering::Relaxed);
        SERIAL_MAX_HOLD_BYTES.store(sample_bytes as u64, Ordering::Relaxed);
    }
    SERIAL_HOLDS.fetch_add(1, Ordering::Relaxed);
    if count_output_bytes {
        SERIAL_HOLD_BYTES.fetch_add(sample_bytes as u64, Ordering::Relaxed);
    }
    SERIAL_HOLD_TSC.fetch_add(held, Ordering::Relaxed);
    for (shift, count) in SERIAL_HOLD_BUCKET_SHIFTS.iter().zip(&SERIAL_HOLDS_OVER) {
        if held >> shift != 0 {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Enable IRQ4-driven asynchronous serial transmission.
///
/// Called by `arch::interrupts::enable_serial_interrupts()` right before `sti`,
/// once the IDT, 8259 PIC IRQ4 route, and 16550A FIFO are initialized.
pub fn enable_serial_tx_irq() {
    SERIAL_TX_IRQ_READY.store(true, Ordering::Release);
}

/// Drain up to `SERIAL_TX_IRQ_MAX_BURST` bytes from the TX ring in IRQ4 context.
///
/// Called by `serial_interrupt_handler` (BSP, IRQs already masked by the
/// interrupt gate). Uses a non-blocking lock acquisition so IRQ4 never spins
/// with IF=0 under AP contention; if contended, flags `SERIAL_TX_MISSED_LOCK`
/// for immediate timer-tick recovery. When `yield_to_lapic` is set or
/// `SERIAL_TX_MAX_CONSECUTIVE_BURSTS` consecutive full bursts have run while
/// bytes remain queued, enters deliberate deferral (`tx_irq_deferred = true`)
/// and disarms `THRI` so AP producers cannot defeat the LAPIC service window.
pub fn serial_tx_irq_drain(yield_to_lapic: bool) {
    if PANIC_CLAIM_STARTED.load(Ordering::Acquire) {
        unsafe { serial_set_tx_irq(false) };
        return;
    }

    let owner = console_owner_token();
    if SERIAL_OWNER_CPU
        .compare_exchange(NO_SERIAL_OWNER, owner, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // Another CPU holds `SERIAL_OWNER_CPU` (or same-CPU panic claim): do
        // not spin with IF=0. Flag the BSP timer tick to re-pulse IER cleanly.
        if SERIAL_TX_PENDING.load(Ordering::Acquire) > 0
            && !PANIC_CLAIM_STARTED.load(Ordering::Acquire)
        {
            SERIAL_TX_MISSED_LOCK.store(true, Ordering::Release);
        }
        return;
    }
    SERIAL_TX_MISSED_LOCK.store(false, Ordering::Relaxed);

    let start = read_tsc();
    let drained = {
        // SAFETY: `SERIAL_OWNER_CPU` is exclusively held with IRQs masked.
        let ring = unsafe { &mut *SERIAL_TX_RING.0.get() };
        let drained = ring.drain_ready_up_to(SERIAL_TX_IRQ_MAX_BURST);
        if ring.len == 0 {
            if yield_to_lapic {
                // Honor an explicit LAPIC yield even when the ring just emptied
                // so an AP producer cannot immediately re-arm PIC ExtINT before
                // the BSP returns from IRQ4 and services LAPIC vectors.
                ring.tx_irq_armed = false;
                ring.tx_irq_deferred = true;
                ring.defer_quiet_ticks = 1;
                ring.consecutive_bursts = 0;
                SERIAL_TX_IRQ_ARMED.store(false, Ordering::Release);
                SERIAL_TX_IRQ_DEFERRED.store(true, Ordering::Release);
                unsafe { serial_set_tx_irq(false) };
            } else if ring.tx_irq_armed {
                ring.disarm_tx_irq_keep_deferral();
            } else {
                ring.consecutive_bursts = 0;
            }
        } else {
            if drained >= SERIAL_TX_IRQ_MAX_BURST {
                ring.consecutive_bursts = ring.consecutive_bursts.saturating_add(1);
            } else {
                ring.consecutive_bursts = 0;
            }
            // Honor explicit LAPIC yield regardless of burst size, or enforce
            // deferral after `SERIAL_TX_MAX_CONSECUTIVE_BURSTS` full bursts.
            let must_defer =
                yield_to_lapic || ring.consecutive_bursts >= SERIAL_TX_MAX_CONSECUTIVE_BURSTS;
            if must_defer {
                ring.tx_irq_armed = false;
                ring.tx_irq_deferred = true;
                ring.defer_quiet_ticks = 1;
                ring.consecutive_bursts = 0;
                SERIAL_TX_IRQ_ARMED.store(false, Ordering::Release);
                SERIAL_TX_IRQ_DEFERRED.store(true, Ordering::Release);
                unsafe { serial_set_tx_irq(false) };
            }
        }
        drained
    };
    let held = read_tsc().wrapping_sub(start);
    if drained > 0 {
        // Bytes were already counted in `SERIAL_HOLD_BYTES` when enqueued;
        // still account for this IRQ-masked hold in max/total/bucket stats.
        record_serial_hold(held, drained, false);
    }

    SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::Release);
}

/// BSP timer-tick deferral release & edge-triggered PIC IRQ4 recovery backstop.
///
/// In steady state (idle or actively draining), executes only Relaxed atomic
/// loads. Handles three cases non-blockingly:
/// 1. Deliberate LAPIC yield deferral (`SERIAL_TX_IRQ_DEFERRED`): enforces one
///    quiet tick interval (allowing LAPIC vectors to run with PIC IRQ4=0 after
///    PIT EOI) before re-arming `THRI` on the subsequent tick.
/// 2. Non-blocking IRQ4 lock contention (`SERIAL_TX_MISSED_LOCK`): immediately
///    pulses `IER = 0x00 -> 0x03` to produce a guaranteed rising edge even if
///    RX data holds the shared UART INTR line high.
/// 3. Lost-edge backstop: if bytes remain queued across two consecutive ticks
///    with zero drain progress, pulses `IER = 0x00 -> 0x03`.
pub fn serial_tx_kick_if_pending() {
    let deferred = SERIAL_TX_IRQ_DEFERRED.load(Ordering::Acquire);
    let pending = SERIAL_TX_PENDING.load(Ordering::Relaxed);
    if !SERIAL_TX_IRQ_READY.load(Ordering::Relaxed)
        || PANIC_CLAIM_STARTED.load(Ordering::Relaxed)
        || (pending == 0 && !deferred)
    {
        SERIAL_TX_LAST_TICK_PENDING.store(false, Ordering::Relaxed);
        SERIAL_TX_MISSED_LOCK.store(false, Ordering::Relaxed);
        return;
    }

    let seq = SERIAL_TX_DRAIN_SEQ.load(Ordering::Relaxed);
    let missed_lock = SERIAL_TX_MISSED_LOCK.load(Ordering::Acquire);
    let unarmed = !SERIAL_TX_IRQ_ARMED.load(Ordering::Acquire);

    if !deferred
        && !missed_lock
        && !unarmed
        && (!SERIAL_TX_LAST_TICK_PENDING.load(Ordering::Relaxed)
            || SERIAL_TX_LAST_TICK_SEQ.load(Ordering::Relaxed) != seq)
    {
        SERIAL_TX_LAST_TICK_PENDING.store(true, Ordering::Relaxed);
        SERIAL_TX_LAST_TICK_SEQ.store(seq, Ordering::Relaxed);
        return;
    }

    let owner = console_owner_token();
    if SERIAL_OWNER_CPU
        .compare_exchange(NO_SERIAL_OWNER, owner, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        // SAFETY: `SERIAL_OWNER_CPU` is exclusively held with IRQs masked.
        let ring = unsafe { &mut *SERIAL_TX_RING.0.get() };
        SERIAL_TX_MISSED_LOCK.store(false, Ordering::Relaxed);
        if ring.tx_irq_deferred && ring.defer_quiet_ticks > 0 {
            // Preserve the quiet tick interval even when `ring.len == 0` so an
            // AP write right after an empty-ring yield cannot defeat cooldown.
            ring.defer_quiet_ticks -= 1;
        } else if ring.len == 0 {
            if ring.tx_irq_armed || ring.tx_irq_deferred {
                ring.disarm_tx_irq_clear_deferral();
            }
        } else {
            ring.tx_irq_deferred = false;
            ring.defer_quiet_ticks = 0;
            ring.tx_irq_armed = true;
            SERIAL_TX_IRQ_DEFERRED.store(false, Ordering::Release);
            SERIAL_TX_IRQ_ARMED.store(true, Ordering::Release);
            // Pulse IER 0x00 -> 0x03 so pending RX data cannot mask the rising
            // edge on the edge-triggered 8259 PIC (RX FIFO data is preserved).
            unsafe { serial_pulse_all_irqs_for_tx() };
            SERIAL_TX_LAST_TICK_PENDING.store(true, Ordering::Relaxed);
            SERIAL_TX_LAST_TICK_SEQ.store(seq, Ordering::Relaxed);
        }
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::Release);
    }
}

/// Drain `SERIAL_TX_RING` synchronously up to a captured enqueue watermark.
///
/// If `stop_async` is `true` (terminal shutdown/reboot), atomically disables
/// asynchronous admission under `SERIAL_OWNER_CPU` before capturing the
/// watermark, and afterward waits (boundedly) for `LSR_TEMT` so both the UART
/// TX FIFO and shift register have finished transmitting.
fn flush_serial_impl(stop_async: bool) {
    let mut target_watermark: Option<u64> = None;
    let mut ready_wait_spins = 0usize;

    loop {
        let mut done = false;
        let mut made_progress = false;
        let hold = with_serial(|_, locked| {
            if !locked {
                done = true;
                return;
            }
            let start = read_tsc();
            // SAFETY: `SERIAL_OWNER_CPU` is exclusively held with IRQs masked.
            let ring = unsafe { &mut *SERIAL_TX_RING.0.get() };
            if stop_async && SERIAL_TX_IRQ_READY.swap(false, Ordering::AcqRel) {
                ring.disarm_tx_irq_clear_deferral();
            }
            let target = *target_watermark.get_or_insert(ring.enqueued_total);
            let remaining_to_target = watermark_remaining(target, ring.drained_total);
            if remaining_to_target == 0 || ring.len == 0 {
                if ring.len == 0 {
                    if stop_async {
                        if ring.tx_irq_armed || ring.tx_irq_deferred {
                            ring.disarm_tx_irq_clear_deferral();
                        }
                    } else if ring.tx_irq_armed {
                        ring.disarm_tx_irq_keep_deferral();
                    }
                }
                done = true;
                return;
            }
            let chunk_limit = remaining_to_target.min(SERIAL_CHUNK);
            let mut drained = ring.drain_ready_up_to(chunk_limit);
            if drained == 0 && ready_wait_spins >= BACKPRESSURE_TX_READY_SPINS {
                drained = ring.drain_unconditional_up_to(chunk_limit);
            }
            if drained > 0 {
                made_progress = true;
                let held = read_tsc().wrapping_sub(start);
                record_serial_hold(held, drained, false);
            }
            if watermark_remaining(target, ring.drained_total) == 0 || ring.len == 0 {
                if ring.len == 0 {
                    if stop_async {
                        if ring.tx_irq_armed || ring.tx_irq_deferred {
                            ring.disarm_tx_irq_clear_deferral();
                        }
                    } else if ring.tx_irq_armed {
                        ring.disarm_tx_irq_keep_deferral();
                    }
                }
                done = true;
            }
        });
        if hold == SerialHold::Reentered || done {
            break;
        }
        if made_progress {
            ready_wait_spins = 0;
        } else {
            ready_wait_spins += 1;
            core::hint::spin_loop();
        }
    }

    if stop_async {
        // Wait (with IRQs restored) for both the 16550A TX FIFO and shift
        // register to empty (`LSR_TEMT`), bounded against failed hardware.
        for _ in 0..TERMINAL_TEMT_SPINS {
            if unsafe { serial_tx_empty() } {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Synchronously flush all bytes queued prior to this call in bounded
/// `SERIAL_CHUNK` holds (each accounted in `TD-SERIAL-1`). Capturing an
/// enqueue watermark ensures concurrent writers on other CPUs cannot prevent
/// PID 1 retirement from completing.
pub fn flush_serial_sync() {
    flush_serial_impl(false);
}

/// Terminal synchronous flush for system shutdown and reboot.
///
/// Atomically stops asynchronous TX admission, drains every already-queued byte
/// through its watermark without overrunning the UART FIFO, and waits boundedly
/// for `LSR_TEMT` so the final byte leaves the shift register before power-off
/// or reset.
pub fn flush_serial_for_shutdown() {
    flush_serial_impl(true);
}

/// TD-SERIAL-1: what the serial holds cost so far, for the gates' report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialHoldStats {
    /// Longest hold, in TSC cycles, and the bytes it wrote.
    pub max_tsc: u64,
    pub max_bytes: u64,
    /// Locked holds, their bytes and their total TSC cycles.
    pub holds: u64,
    pub bytes: u64,
    pub tsc: u64,
    /// Holds of at least 2^18, 2^20, 2^22 and 2^24 TSC cycles.
    pub over: [u64; 4],
}

/// Who writes a chunk, for the line state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialStream {
    /// Kernel diagnostics, one stream per CPU.
    Kernel,
    /// The kernel shell (`arch::serial_write_*`).
    Shell,
    /// One user task's TTY data.
    User(usize),
}

impl SerialStream {
    fn id(self, owner: usize) -> usize {
        match self {
            SerialStream::Kernel => owner,
            SerialStream::Shell => SHELL_STREAM,
            SerialStream::User(task) => USER_STREAM | (task & (USER_STREAM - 1)),
        }
    }
}

/// How [`with_serial`] ran its writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialHold {
    /// Under the lock, with IRQs masked.
    Locked,
    /// Without the lock: the holder is an interrupted context with this token.
    Reentered,
}

/// TD-SERIAL-1 FIX: run `write(owner, locked)` as one serial-console hold.
///
/// Unlocked byte writes from several CPUs used to interleave on the UART and
/// break the gates' serial markers (musl-check at 8 CPUs). The holder masks
/// IRQs, and `write` only copies at most `SERIAL_CHUNK` buffered bytes to the
/// port: no lock, allocation, fault or wait, so every hold ends and the lock
/// is a terminal leaf. A caller holding a lock also used by a local IRQ must
/// already have masked IRQs: waiters restore the caller's IRQ state, so taking
/// such a lock with IRQs enabled is not made safe by this console lock.
/// Masking is what makes
/// that true: an IRQ handler on the holder's CPU spinning on an IRQ-safe lock
/// whose owner waits here would otherwise keep the hold open forever. Only an
/// NMI or exception can still interrupt a holder; a print from it sees its own
/// token and writes without the lock (inside the interrupted chunk) instead of
/// deadlocking. Waiters spin with the caller's IRQ state, so they keep taking
/// IPIs. Unregistered contexts share one token, as in R190-7, so overlapping
/// prints among them write without the lock. The fatal exception diagnostics
/// and kdump write the UART directly; the panic handler first claims the lock
/// for good ([`claim_serial_for_panic`]).
fn with_serial(write: impl FnOnce(usize, bool)) -> SerialHold {
    let mut irqs_enabled = irq_save_disable();
    // Once per call: a kernel thread does not migrate inside a print (kernel
    // mode is not preemptible), and the lookup is an LAPIC MMIO read that the
    // waiters below must not repeat while a holder needs the port.
    let owner = console_owner_token();
    loop {
        let current = SERIAL_OWNER_CPU.load(Ordering::Relaxed);
        if current == owner {
            write(owner, false);
            irq_restore(irqs_enabled);
            return SerialHold::Reentered;
        }
        if current == NO_SERIAL_OWNER
            && SERIAL_OWNER_CPU
                .compare_exchange_weak(NO_SERIAL_OWNER, owner, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            write(owner, true);
            SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::Release);
            irq_restore(irqs_enabled);
            return SerialHold::Locked;
        }
        // Wait with the caller's IRQ state, then mask again before retrying.
        irq_restore(irqs_enabled);
        core::hint::spin_loop();
        irqs_enabled = irq_save_disable();
    }
}

/// Write one chunk under the serial lock. A different stream's open line is
/// ended first, so every stream's lines start at column 0 (the shell prompt
/// has no newline, and gates match whole lines).
///
/// Once IRQ4 TX is enabled (`SERIAL_TX_IRQ_READY`), chunks are copied into the
/// 16 KiB TX ring buffer under `SERIAL_OWNER_CPU` and drained asynchronously
/// by `serial_interrupt_handler`, keeping both `cli` hold time and caller
/// blocking latency near zero. If the ring fills, the oldest queued bytes are
/// drained synchronously in FIFO order (never dropped). Before IRQ4 is armed
/// or during panic, bytes go directly to `SERIAL_PORT` synchronously.
fn serial_emit(stream: SerialStream, chunk: &[u8]) {
    let mut ready_wait_spins = 0usize;
    let mut sync_sent = 0usize;
    loop {
        let mut retry_after_unlock = false;
        let mut made_progress = false;
        let _ = with_serial(|owner, locked| {
            if !locked {
                for &byte in &chunk[sync_sent..] {
                    unsafe { serial_outb(SERIAL_PORT, byte) };
                }
                return;
            }
            let start = read_tsc();
            let id = stream.id(owner);
            let open = SERIAL_OPEN_LINE.load(Ordering::Relaxed);
            // SAFETY: `SERIAL_OWNER_CPU` is exclusively held with IRQs masked.
            let ring = unsafe { &mut *SERIAL_TX_RING.0.get() };

            if SERIAL_TX_IRQ_READY.load(Ordering::Acquire)
                && !PANIC_CLAIM_STARTED.load(Ordering::Acquire)
                && sync_sent == 0
            {
                let need_newline = open != NO_OPEN_LINE && open != id;
                let needed = chunk.len() + usize::from(need_newline);
                if ring.free_space() < needed {
                    let overflow = needed - ring.free_space();
                    let limit = overflow.min(SERIAL_CHUNK);
                    let mut drained = ring.drain_ready_up_to(limit);
                    if drained == 0 && ready_wait_spins >= BACKPRESSURE_TX_READY_SPINS {
                        drained = ring.drain_unconditional_up_to(limit);
                    }
                    if drained > 0 {
                        made_progress = true;
                    }
                    if ring.free_space() < needed {
                        // Release `SERIAL_OWNER_CPU` and restore caller IRQs
                        // before retrying so we never spin on THRE under `cli`
                        // and never overrun a busy 16-byte UART FIFO.
                        if drained > 0 {
                            let held = read_tsc().wrapping_sub(start);
                            record_serial_hold(held, drained, false);
                        }
                        retry_after_unlock = true;
                        return;
                    }
                }
                if need_newline {
                    ring.push_byte(b'\n');
                }
                ring.push_slice(chunk);
                SERIAL_TX_PENDING.store(ring.len, Ordering::Release);
                if !ring.tx_irq_armed && !ring.tx_irq_deferred && ring.len > 0 {
                    ring.tx_irq_armed = true;
                    SERIAL_TX_IRQ_ARMED.store(true, Ordering::Release);
                    unsafe { serial_set_tx_irq(true) };
                }
                let next_open = match chunk.last() {
                    Some(b'\n') => NO_OPEN_LINE,
                    Some(_) => id,
                    None => open,
                };
                SERIAL_OPEN_LINE.store(next_open, Ordering::Relaxed);
                let held = read_tsc().wrapping_sub(start);
                record_serial_hold(held, chunk.len(), true);
                return;
            }

            // Synchronous mode (early boot, post-shutdown, or panic fallback):
            // preserve strict FIFO ordering by draining any queued ring bytes
            // first, then pace both the separator (recomputed under every lock
            // acquisition so an intervening stream's open line is always
            // separated) and `chunk` in 16-byte FIFO batches checked against
            // `LSR_THRE`.
            if ring.len > 0 {
                let mut drained = ring.drain_ready_up_to(SERIAL_CHUNK);
                if drained == 0 && ready_wait_spins >= BACKPRESSURE_TX_READY_SPINS {
                    drained = ring.drain_unconditional_up_to(SERIAL_CHUNK);
                }
                if drained > 0 {
                    made_progress = true;
                }
                if ring.len > 0 {
                    if drained > 0 {
                        let held = read_tsc().wrapping_sub(start);
                        record_serial_hold(held, drained, false);
                    }
                    retry_after_unlock = true;
                    return;
                }
                if ring.tx_irq_armed || ring.tx_irq_deferred {
                    ring.disarm_tx_irq_clear_deferral();
                }
            }

            let need_nl = open != NO_OPEN_LINE && open != id;
            let mut newline_left = need_nl;
            let mut payload_written = 0usize;
            let mut total_written = 0usize;

            while newline_left || sync_sent < chunk.len() {
                let ready = unsafe { serial_tx_ready() };
                if !ready && (total_written > 0 || ready_wait_spins < BACKPRESSURE_TX_READY_SPINS) {
                    break;
                }
                let mut budget = SERIAL_TX_FIFO_DEPTH;
                if newline_left && budget > 0 {
                    unsafe { serial_outb(SERIAL_PORT, b'\n') };
                    newline_left = false;
                    budget -= 1;
                    total_written += 1;
                }
                let take = (chunk.len() - sync_sent).min(budget);
                for &byte in &chunk[sync_sent..sync_sent + take] {
                    unsafe { serial_outb(SERIAL_PORT, byte) };
                }
                sync_sent += take;
                payload_written += take;
                total_written += take;
                if !ready {
                    // Bounded timeout fallback submits at most one FIFO batch per hold.
                    break;
                }
            }

            if total_written > 0 {
                made_progress = true;
            }
            if newline_left || sync_sent < chunk.len() {
                if payload_written > 0 {
                    let next_open = match chunk[..sync_sent].last() {
                        Some(b'\n') => NO_OPEN_LINE,
                        Some(_) => id,
                        None => NO_OPEN_LINE,
                    };
                    SERIAL_OPEN_LINE.store(next_open, Ordering::Relaxed);
                } else if need_nl && !newline_left {
                    SERIAL_OPEN_LINE.store(NO_OPEN_LINE, Ordering::Relaxed);
                }
                if total_written > 0 {
                    let held = read_tsc().wrapping_sub(start);
                    record_serial_hold(held, payload_written, payload_written > 0);
                }
                retry_after_unlock = true;
                return;
            }

            let next_open = match chunk.last() {
                Some(b'\n') => NO_OPEN_LINE,
                Some(_) => id,
                None => open,
            };
            SERIAL_OPEN_LINE.store(next_open, Ordering::Relaxed);
            let held = read_tsc().wrapping_sub(start);
            record_serial_hold(held, payload_written, true);
        });
        if !retry_after_unlock {
            break;
        }
        if made_progress {
            ready_wait_spins = 0;
        } else {
            ready_wait_spins += 1;
            core::hint::spin_loop();
        }
    }
}

/// A consistent snapshot, under the same lock as the writers. Reentry from
/// an exception/NMI cannot wait for the interrupted writer; omit that sample.
/// Taking a snapshot does not itself count as a serial write/hold.
pub fn serial_hold_stats() -> Option<SerialHoldStats> {
    let mut stats = None;
    with_serial(|_, locked| {
        if locked {
            stats = Some(SerialHoldStats {
                max_tsc: SERIAL_MAX_HOLD_TSC.load(Ordering::Relaxed),
                max_bytes: SERIAL_MAX_HOLD_BYTES.load(Ordering::Relaxed),
                holds: SERIAL_HOLDS.load(Ordering::Relaxed),
                bytes: SERIAL_HOLD_BYTES.load(Ordering::Relaxed),
                tsc: SERIAL_HOLD_TSC.load(Ordering::Relaxed),
                over: core::array::from_fn(|i| SERIAL_HOLDS_OVER[i].load(Ordering::Relaxed)),
            });
        }
    });
    stats
}

/// Exchange attempts before a panic writes without the serial lock.
const PANIC_CLAIM_SPINS: usize = 1 << 22;

/// Set by the first claim attempt, so a fault inside the claim (its owner
/// lookup reads the LAPIC) cannot recurse through the panic handler.
static PANIC_CLAIM_STARTED: AtomicBool = AtomicBool::new(false);

/// TD-SERIAL-1: claim the serial lock for this CPU for good, before the panic
/// handler's raw writes.
///
/// No path stops the other CPUs on a panic, so their later chunks could land
/// inside the panic text or the kdump. After the claim they stall at their
/// next serial print, while this CPU's own prints see its token and pass. The
/// claim waits only a bounded number of attempts (another CPU may hold it
/// for good, e.g. a concurrent panic) and then leaves the raw writes unlocked.
/// An open line of another stream is ended first.
pub fn claim_serial_for_panic() {
    if PANIC_CLAIM_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    SERIAL_TX_IRQ_READY.store(false, Ordering::Release);
    let owner = console_owner_token();
    for _ in 0..PANIC_CLAIM_SPINS {
        match SERIAL_OWNER_CPU.compare_exchange_weak(
            NO_SERIAL_OWNER,
            owner,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                // Flush any queued async bytes with FIFO pacing and disarm THRI
                // before the panic separator and raw panic/kdump writes.
                // SAFETY: `SERIAL_OWNER_CPU` is exclusively owned by this CPU.
                let ring = unsafe { &mut *SERIAL_TX_RING.0.get() };
                ring.drain_all_panic_bounded();
                if SERIAL_OPEN_LINE.swap(NO_OPEN_LINE, Ordering::Relaxed) != NO_OPEN_LINE {
                    for _ in 0..PANIC_TX_READY_SPINS {
                        if unsafe { serial_tx_ready() } {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    unsafe { serial_outb(SERIAL_PORT, b'\n') };
                }
                return;
            }
            Err(current) if current == owner => return,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

#[inline]
fn read_tsc() -> u64 {
    // SAFETY: RDTSC has no memory or privilege effect in kernel or user mode.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Mask IRQs, returning whether they were enabled. Not `nomem`: the lock
/// operations must not move across it.
#[cfg(not(test))]
#[inline]
fn irq_save_disable() -> bool {
    let rflags: u64;
    unsafe {
        core::arch::asm!("pushfq", "pop {}", "cli", out(reg) rflags);
    }
    rflags & (1 << 9) != 0
}

#[cfg(not(test))]
#[inline]
fn irq_restore(enabled: bool) {
    if enabled {
        unsafe { core::arch::asm!("sti") };
    }
}

// Hosted tests run in user mode, where `cli`/`sti` fault.
#[cfg(test)]
fn irq_save_disable() -> bool {
    false
}

#[cfg(test)]
fn irq_restore(_enabled: bool) {}

/// Where a [`SerialChunker`] sends each chunk.
trait ChunkSink {
    fn emit(&mut self, chunk: &[u8]);
}

/// Serial port only.
struct SerialSink(SerialStream);

impl ChunkSink for SerialSink {
    fn emit(&mut self, chunk: &[u8]) {
        serial_emit(self.0, chunk);
    }
}

/// User TTY data: the display copy and the serial copy, chunk by chunk, so
/// neither lock is held for a whole (up to 1 MiB) write.
struct ConsoleSink(SerialStream);

impl ChunkSink for ConsoleSink {
    fn emit(&mut self, chunk: &[u8]) {
        // Chunks hold whole characters of `&str` input, so this always holds.
        if let Ok(text) = core::str::from_utf8(chunk) {
            write_display(format_args!("{}", text));
        }
        serial_emit(self.0, chunk);
    }
}

/// TD-SERIAL-1: buffers console output in one stack chunk and hands each full
/// chunk to its sink, so neither formatting nor a long write runs under the
/// serial lock. On overflow it emits through the last newline in the chunk
/// (the whole chunk if it has none), so a line of up to `SERIAL_CHUNK` bytes is
/// never split; `&str` input is appended a whole character at a time, so a
/// UTF-8 sequence never is. `sanitize` applies the R190-13 filter (kernel
/// diagnostics); user TTY data and the shell pass through. The rest is
/// emitted when the chunker is dropped.
struct SerialChunker<S: ChunkSink> {
    buf: [u8; SERIAL_CHUNK],
    len: usize,
    sanitize: bool,
    sink: S,
}

impl<S: ChunkSink> SerialChunker<S> {
    fn new(sanitize: bool, sink: S) -> Self {
        Self {
            buf: [0; SERIAL_CHUNK],
            len: 0,
            sanitize,
            sink,
        }
    }

    fn push_str(&mut self, s: &str) {
        let mut utf8 = [0u8; 4];
        for ch in s.chars() {
            let ch = if self.sanitize {
                serial_safe_char(ch)
            } else {
                ch
            };
            self.push_encoded(ch.encode_utf8(&mut utf8).as_bytes());
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.push_encoded(core::slice::from_ref(byte));
        }
    }

    /// Append one character's encoding (1 to 4 bytes).
    fn push_encoded(&mut self, encoded: &[u8]) {
        // Each pass emits at least one byte: the chunk is nearly full here.
        while self.len + encoded.len() > SERIAL_CHUNK {
            let end = match self.buf[..self.len].iter().rposition(|&b| b == b'\n') {
                Some(newline) => newline + 1,
                None => self.len,
            };
            self.sink.emit(&self.buf[..end]);
            self.buf.copy_within(end..self.len, 0);
            self.len -= end;
        }
        self.buf[self.len..self.len + encoded.len()].copy_from_slice(encoded);
        self.len += encoded.len();
    }
}

impl<S: ChunkSink> fmt::Write for SerialChunker<S> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl<S: ChunkSink> Drop for SerialChunker<S> {
    fn drop(&mut self) {
        if self.len != 0 {
            self.sink.emit(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

/// Kernel console output (`print!`/`println!`/klog). The serial copy is
/// sanitized (R190-13).
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    write_display(args);
    // 始终同时发送到串口，便于在 -nographic 模式下查看
    let _ = SerialChunker::new(true, SerialSink(SerialStream::Kernel)).write_fmt(args);
}

/// TD-SERIAL-1: kernel diagnostics for the serial console only (the
/// non-fatal `[PF ENTRY]` traces), sanitized and locked like `_print`.
pub fn serial_print(args: fmt::Arguments) {
    use core::fmt::Write;
    let _ = SerialChunker::new(true, SerialSink(SerialStream::Kernel)).write_fmt(args);
}

/// TD-SERIAL-1: the kernel shell's raw serial output (prompt, echo).
pub fn shell_serial_write(bytes: &[u8]) {
    SerialChunker::new(false, SerialSink(SerialStream::Shell)).push_bytes(bytes);
}

/// TD-SERIAL-1: one user console write (`write`, a whole `writev`, or a
/// `/dev/console` write).
///
/// R190-13: a user program owns its terminal stream (ANSI colors, `\r`,
/// backspace line editing), so the serial copy is byte-exact, as on a Linux
/// TTY. Only the kernel's own diagnostics go through the sanitizing `_print`.
/// The data reaches the display and the serial port in chunks of up to
/// `SERIAL_CHUNK` bytes, each under one hold; one session keeps musl's
/// `writev({line}, {"\n"})` together. Whatever is buffered is written when the
/// session is dropped.
pub struct ConsoleWrite(SerialChunker<ConsoleSink>);

impl ConsoleWrite {
    /// Start a write by task `task` (its lines are kept apart from other
    /// writers' lines on the UART).
    pub fn begin(task: usize) -> Self {
        Self(SerialChunker::new(
            false,
            ConsoleSink(SerialStream::User(task)),
        ))
    }

    pub fn write_str(&mut self, s: &str) {
        self.0.push_str(s);
    }
}

pub fn init() {
    clear_screen();
}

pub fn clear_screen() {
    // The text buffer is touched only while it is the display.
    if active_display() != DisplayBackend::VgaText {
        return;
    }
    let _ = with_display(|| {
        let mut writer = WRITER.lock();
        for row in 0..BUFFER_HEIGHT {
            writer.clear_row(row);
        }
    });
}

pub fn write_str(s: &str) {
    use core::fmt::Write;
    if active_display() != DisplayBackend::VgaText {
        return;
    }
    let _ = with_display(|| {
        let _ = WRITER.lock().write_str(s);
    });
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// Bytes the hosted `serial_outb` "wrote".
    pub(super) static PORT_LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    /// Mock COM1 `IER` bit 1 (`THRI`) state for async TX tests.
    pub(super) static TX_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
    /// Count of full `IER = 0x00 -> 0x03` pulses issued by the timer backstop.
    pub(super) static IER_FULL_PULSES: AtomicUsize = AtomicUsize::new(0);
    /// Mock COM1 `LSR` bit 5 (`THRE`) state for async TX tests.
    pub(super) static TX_READY_MOCK: AtomicBool = AtomicBool::new(true);
    /// Optional one-shot stream id injected on a `THRE=0` poll to deterministically
    /// simulate an intervening open line between unlocked synchronous retries.
    pub(super) static TX_READY_INJECT_OPEN_LINE: AtomicUsize = AtomicUsize::new(NO_OPEN_LINE);
    /// Mock COM1 `LSR` bit 6 (`TEMT`) state for terminal flush tests.
    pub(super) static TX_EMPTY_MOCK: AtomicBool = AtomicBool::new(true);
    /// Serializes the tests that use the global lock word and port log.
    static SERIAL_TESTS: Mutex<()> = Mutex::new(());

    impl ChunkSink for Vec<Vec<u8>> {
        fn emit(&mut self, chunk: &[u8]) {
            self.push(chunk.to_vec());
        }
    }

    fn chunks(sanitize: bool, input: &str) -> Vec<Vec<u8>> {
        let mut chunker = SerialChunker::new(sanitize, Vec::new());
        chunker.push_str(input);
        let mut emitted = core::mem::take(&mut chunker.sink);
        let rest = chunker.buf[..chunker.len].to_vec();
        chunker.len = 0;
        if !rest.is_empty() {
            emitted.push(rest);
        }
        emitted
    }

    fn assert_chunks_rejoin(input: &str, emitted: &[Vec<u8>]) {
        assert_eq!(emitted.concat(), input.as_bytes());
        for chunk in emitted {
            assert!(chunk.len() <= SERIAL_CHUNK);
            assert!(core::str::from_utf8(chunk).is_ok(), "split a character");
        }
    }

    #[test]
    fn td_serial_1_short_output_is_one_chunk() {
        let input = "hello\nworld\n";
        assert_eq!(chunks(false, input), [input.as_bytes().to_vec()]);
    }

    #[test]
    fn td_serial_1_overflow_splits_after_the_last_newline() {
        let first = std::format!("{}\n", "a".repeat(199));
        let second = std::format!("{}\n", "b".repeat(99));
        let input = std::format!("{}{}", first, second);
        let emitted = chunks(false, &input);
        assert_eq!(emitted, [first.into_bytes(), second.into_bytes()]);
    }

    #[test]
    fn td_serial_1_long_line_splits_between_characters() {
        let input = "\u{4e2d}".repeat(200);
        let emitted = chunks(false, &input);
        assert!(emitted.len() >= 3);
        assert_chunks_rejoin(&input, &emitted);
    }

    #[test]
    fn td_serial_1_newline_at_the_start_still_terminates() {
        let input = std::format!("\n{}", "\u{4e2d}".repeat(100));
        let emitted = chunks(false, &input);
        assert_eq!(emitted[0], b"\n");
        assert_chunks_rejoin(&input, &emitted);
    }

    #[test]
    fn td_serial_1_only_kernel_output_is_sanitized() {
        let input = "a\u{1b}[31mb\r\n";
        assert_eq!(chunks(false, input).concat(), input.as_bytes());
        assert_eq!(chunks(true, input).concat(), b"a?[31mb?\n");
    }

    /// Reset the lock word, line state, async ring, and port log; return the
    /// guard that keeps the other lock tests out.
    fn serial_test_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERIAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
        SERIAL_OPEN_LINE.store(NO_OPEN_LINE, Ordering::SeqCst);
        PANIC_CLAIM_STARTED.store(false, Ordering::SeqCst);
        SERIAL_TX_IRQ_READY.store(false, Ordering::SeqCst);
        SERIAL_TX_PENDING.store(0, Ordering::SeqCst);
        SERIAL_TX_IRQ_ARMED.store(false, Ordering::SeqCst);
        SERIAL_TX_IRQ_DEFERRED.store(false, Ordering::SeqCst);
        SERIAL_TX_MISSED_LOCK.store(false, Ordering::SeqCst);
        SERIAL_TX_DRAIN_SEQ.store(0, Ordering::SeqCst);
        SERIAL_TX_LAST_TICK_PENDING.store(false, Ordering::SeqCst);
        SERIAL_TX_LAST_TICK_SEQ.store(0, Ordering::SeqCst);
        TX_IRQ_ENABLED.store(false, Ordering::SeqCst);
        IER_FULL_PULSES.store(0, Ordering::SeqCst);
        TX_READY_MOCK.store(true, Ordering::SeqCst);
        TX_READY_INJECT_OPEN_LINE.store(NO_OPEN_LINE, Ordering::SeqCst);
        TX_EMPTY_MOCK.store(true, Ordering::SeqCst);
        unsafe {
            let ring = &mut *SERIAL_TX_RING.0.get();
            ring.head = 0;
            ring.tail = 0;
            ring.len = 0;
            ring.enqueued_total = 0;
            ring.drained_total = 0;
            ring.tx_irq_armed = false;
            ring.tx_irq_deferred = false;
            ring.defer_quiet_ticks = 0;
            ring.consecutive_bursts = 0;
        }
        PORT_LOG.lock().unwrap().clear();
        guard
    }

    fn port_log() -> Vec<u8> {
        PORT_LOG.lock().unwrap().clone()
    }

    #[test]
    fn c3_display_backend_is_the_framebuffer_then_the_text_buffer_then_absent() {
        assert_eq!(display_backend(true, true), DisplayBackend::Framebuffer);
        assert_eq!(display_backend(true, false), DisplayBackend::Framebuffer);
        assert_eq!(display_backend(false, true), DisplayBackend::VgaText);
        assert_eq!(display_backend(false, false), DisplayBackend::Absent);
    }

    /// The hosted process has nothing mapped at the text buffer's address,
    /// so a single access to it would end this test with a fault.
    #[test]
    fn c3_console_output_reaches_only_the_serial_port_without_a_display() {
        let _guard = serial_test_state();
        disable_text_display();
        assert_eq!(active_display(), DisplayBackend::Absent);
        _print(format_args!("Process {} exited with code {}\n", 7, 0));
        ConsoleWrite::begin(7).write_str("user line\n");
        clear_screen();
        write_str("not rendered\n");
        assert_eq!(port_log(), b"Process 7 exited with code 0\nuser line\n");
    }

    /// The memory-map check does not look at the geometry. The framebuffer
    /// driver does, and refuses one that does not fit its region. That boot
    /// has no display either, and `has_display` is what the kernel reports
    /// it from.
    #[test]
    fn c3_a_framebuffer_refused_for_its_geometry_leaves_no_display() {
        let _guard = serial_test_state();
        disable_text_display();
        // 1024 x 768 at four bytes a pixel does not fit in one page.
        crate::framebuffer::init(&crate::framebuffer::FramebufferInfo {
            base: 0x8000_0000,
            size: 0x1000,
            width: 1024,
            height: 768,
            stride: 1024,
            pixel_format: crate::framebuffer::PixelFormat::Bgr,
        });
        assert!(!crate::framebuffer::is_initialized());
        assert!(!has_display());
        _print(format_args!("serial only\n"));
        assert_eq!(port_log(), b"serial only\n");
    }

    #[test]
    fn td_serial_1_hold_releases_and_tracks_the_open_line() {
        let _guard = serial_test_state();
        serial_emit(SerialStream::User(5), b"prompt> ");
        assert_eq!(SERIAL_OWNER_CPU.load(Ordering::SeqCst), NO_SERIAL_OWNER);
        serial_emit(SerialStream::User(5), b"same line\n");
        serial_emit(SerialStream::Shell, b"/ nilix# ");
        serial_emit(SerialStream::User(5), b"42 * 2 = 84\n");
        serial_emit(SerialStream::Kernel, b"done\n");
        assert_eq!(
            port_log(),
            b"prompt> same line\n/ nilix# \n42 * 2 = 84\ndone\n"
        );
        assert_eq!(SERIAL_OPEN_LINE.load(Ordering::SeqCst), NO_OPEN_LINE);
    }

    #[test]
    fn td_serial_1_same_token_reentry_writes_without_the_lock() {
        let _guard = serial_test_state();
        let me = console_owner_token();
        SERIAL_OWNER_CPU.store(me, Ordering::SeqCst);
        SERIAL_OPEN_LINE.store(SHELL_STREAM, Ordering::SeqCst);
        let hold = with_serial(|_, locked| {
            assert!(!locked);
            unsafe { serial_outb(SERIAL_PORT, b'x') };
        });
        assert_eq!(hold, SerialHold::Reentered);
        serial_emit(SerialStream::Kernel, b"nmi\n");
        assert_eq!(port_log(), b"xnmi\n", "no line handling without the lock");
        assert_eq!(SERIAL_OWNER_CPU.load(Ordering::SeqCst), me);
        assert_eq!(SERIAL_OPEN_LINE.load(Ordering::SeqCst), SHELL_STREAM);
        assert_eq!(
            serial_hold_stats(),
            None,
            "reentry cannot sample a half-written record"
        );
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
    }

    #[test]
    fn td_serial_1_stats_wait_for_a_complete_record() {
        let _guard = serial_test_state();
        SERIAL_OWNER_CPU.store(console_owner_token() + 1, Ordering::SeqCst);
        SERIAL_MAX_HOLD_TSC.store(123456, Ordering::Relaxed);
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || tx.send(serial_hold_stats()).unwrap());
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        SERIAL_MAX_HOLD_BYTES.store(42, Ordering::Relaxed);
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::Release);
        let sample = rx.recv().unwrap().unwrap();
        reader.join().unwrap();
        assert_eq!((sample.max_tsc, sample.max_bytes), (123456, 42));
        assert_eq!(
            serial_hold_stats(),
            Some(sample),
            "sampling does not change statistics"
        );
    }

    #[test]
    fn td_serial_1_waiter_writes_after_the_other_cpu_releases() {
        let _guard = serial_test_state();
        let other = console_owner_token() + 1;
        SERIAL_OWNER_CPU.store(other, Ordering::SeqCst);
        let waiter = std::thread::spawn(|| serial_emit(SerialStream::Kernel, b"late\n"));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let early = port_log();
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
        waiter.join().unwrap();
        assert!(early.is_empty(), "wrote while another CPU held the lock");
        assert_eq!(port_log(), b"late\n");
        assert_eq!(SERIAL_OWNER_CPU.load(Ordering::SeqCst), NO_SERIAL_OWNER);
    }

    #[test]
    fn td_serial_1_panic_claim_keeps_the_lock_for_this_cpu() {
        let _guard = serial_test_state();
        serial_emit(SerialStream::Shell, b"/ nilix# ");
        PANIC_CLAIM_STARTED.store(false, Ordering::SeqCst);
        claim_serial_for_panic();
        claim_serial_for_panic();
        let me = console_owner_token();
        assert_eq!(SERIAL_OWNER_CPU.load(Ordering::SeqCst), me);
        assert_eq!(
            with_serial(|_, _| {}),
            SerialHold::Reentered,
            "the panicking CPU's own prints still pass"
        );
        assert_eq!(port_log(), b"/ nilix# \n");
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
    }

    #[test]
    fn r190_13_serial_sanitizer_neutralizes_terminal_controls() {
        for ch in [
            '\u{1b}', '\r', '\u{7}', '\u{8}', '\u{0}', '\u{7f}', '\u{9b}',
        ] {
            assert_eq!(serial_safe_char(ch), '?', "{:?} must be neutralized", ch);
        }
        for ch in ['\n', '\t', ' ', 'a', '~', '\u{e9}', '\u{4e2d}'] {
            assert_eq!(serial_safe_char(ch), ch, "{:?} must pass", ch);
        }
    }

    #[test]
    fn async_tx_ring_enqueues_arms_irq_and_drains_in_fifo_order() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        serial_emit(SerialStream::User(5), b"prompt> ");
        assert!(
            port_log().is_empty(),
            "bytes stay buffered until IRQ4 drain"
        );
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        serial_emit(SerialStream::Shell, b"cmd\n");
        serial_emit(SerialStream::Kernel, b"ok\n");
        assert!(port_log().is_empty());

        serial_tx_irq_drain(false);
        assert_eq!(port_log(), b"prompt> \ncmd\nok\n");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert_eq!(SERIAL_TX_PENDING.load(Ordering::SeqCst), 0);
        assert_eq!(SERIAL_OPEN_LINE.load(Ordering::SeqCst), NO_OPEN_LINE);
    }

    #[test]
    fn async_tx_ring_respects_burst_cap_and_thre_not_ready() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        let total = SERIAL_TX_IRQ_MAX_BURST * 2 + 25;
        let payload: Vec<u8> = (0..total).map(|i| b'a' + (i % 26) as u8).collect();
        serial_emit(SerialStream::Kernel, &payload);
        assert!(port_log().is_empty());
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        // Without LAPIC pressure, first burst keeps THRI armed for fast drain.
        serial_tx_irq_drain(false);
        assert_eq!(port_log(), &payload[..SERIAL_TX_IRQ_MAX_BURST]);
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        // When hardware reports THRE=0, drain writes nothing and keeps THRI armed.
        TX_READY_MOCK.store(false, Ordering::SeqCst);
        serial_tx_irq_drain(false);
        assert_eq!(port_log().len(), SERIAL_TX_IRQ_MAX_BURST);
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        // When LAPIC work is pending (`yield_to_lapic=true`), IRQ4 defers THRI
        // so PIC ExtINT yields to LAPIC IPIs.
        TX_READY_MOCK.store(true, Ordering::SeqCst);
        serial_tx_irq_drain(true);
        assert_eq!(port_log(), &payload[..SERIAL_TX_IRQ_MAX_BURST * 2]);
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // First BSP tick preserves a quiet interval (THRI stays disarmed);
        // second BSP tick clears deferral and pulses IER to re-arm.
        serial_tx_kick_if_pending();
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending();
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(!SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        serial_tx_irq_drain(false);
        assert_eq!(port_log(), payload);
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
    }

    #[test]
    fn async_tx_ring_backpressure_drains_oldest_without_dropping() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        let mut expected = Vec::new();
        // Advance head/tail first so wrap-around is exercised across the boundary.
        let warmup = [b'W'; 100];
        serial_emit(SerialStream::Kernel, &warmup);
        expected.extend_from_slice(&warmup);
        serial_tx_irq_drain(false);

        // Emit more than SERIAL_TX_BUF_CAP without further IRQ drains to force
        // synchronous FIFO backpressure.
        for chunk_idx in 0..(SERIAL_TX_BUF_CAP / 128 + 10) {
            let mut chunk = [0u8; 128];
            for (i, slot) in chunk.iter_mut().enumerate() {
                *slot = b'A' + ((chunk_idx + i) % 26) as u8;
            }
            serial_emit(SerialStream::Kernel, &chunk);
            expected.extend_from_slice(&chunk);
        }
        assert!(
            port_log().len() > SERIAL_TX_IRQ_MAX_BURST,
            "overflow must synchronously drain oldest bytes"
        );

        flush_serial_sync();
        assert_eq!(port_log(), expected);
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert_eq!(SERIAL_TX_PENDING.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn async_tx_ring_panic_claim_flushes_queued_bytes_before_separator() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        serial_emit(SerialStream::User(1), b"unfinished line");
        assert!(port_log().is_empty());
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        claim_serial_for_panic();
        assert_eq!(port_log(), b"unfinished line\n");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(!SERIAL_TX_IRQ_READY.load(Ordering::SeqCst));
        assert_eq!(SERIAL_TX_PENDING.load(Ordering::SeqCst), 0);
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
    }

    #[test]
    fn async_tx_ring_stalled_timer_kick_rearms_tx_irq() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        serial_emit(SerialStream::Kernel, b"pending\n");
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        // Simulate a lost edge where THRI was cleared externally.
        TX_IRQ_ENABLED.store(false, Ordering::SeqCst);
        // First tick records pending state; second tick with no drain progress re-arms.
        serial_tx_kick_if_pending();
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending();
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));

        flush_serial_sync();
        assert_eq!(port_log(), b"pending\n");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
    }

    #[test]
    fn async_tx_ring_deferral_blocks_producer_rearm_and_honors_short_yield() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        // Enqueue 40 bytes (< 64) with THRE=0 so 0 bytes drain, then request an
        // explicit LAPIC yield: deferral must engage even when <64 bytes drained.
        serial_emit(SerialStream::Kernel, &[b'x'; 40]);
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        TX_READY_MOCK.store(false, Ordering::SeqCst);
        serial_tx_irq_drain(true);
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // A producer writing while deferred must NOT re-enable THRI.
        serial_emit(SerialStream::Kernel, b"more\n");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // Quiet tick 1 keeps THRI off; tick 2 releases deferral and pulses IER.
        serial_tx_kick_if_pending();
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending();
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(IER_FULL_PULSES.load(Ordering::SeqCst) >= 1);

        TX_READY_MOCK.store(true, Ordering::SeqCst);
        flush_serial_sync();
        assert_eq!(port_log().len(), 45);
    }

    #[test]
    fn async_tx_ring_irq_nonblocking_and_rx_safe_ier_pulse() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        serial_emit(SerialStream::Kernel, b"queued\n");
        // Simulate another CPU holding `SERIAL_OWNER_CPU`: IRQ4 must return
        // immediately without spinning and record `SERIAL_TX_MISSED_LOCK`.
        let other = console_owner_token() + 1;
        SERIAL_OWNER_CPU.store(other, Ordering::SeqCst);
        TX_IRQ_ENABLED.store(false, Ordering::SeqCst);
        serial_tx_irq_drain(false);
        assert!(port_log().is_empty());
        assert!(SERIAL_TX_MISSED_LOCK.load(Ordering::SeqCst));

        // Once the other CPU releases, the very next BSP tick pulses IER 0->3.
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
        serial_tx_kick_if_pending();
        assert!(!SERIAL_TX_MISSED_LOCK.load(Ordering::SeqCst));
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert_eq!(IER_FULL_PULSES.load(Ordering::SeqCst), 1);

        flush_serial_sync();
        assert_eq!(port_log(), b"queued\n");
    }

    #[test]
    fn async_tx_ring_watermark_flush_shutdown_temt_and_stats_accounting() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        // Queue > 1 chunk so flush runs across multiple bounded holds and
        // verify TD-SERIAL-1 records flush holds without double-counting bytes.
        let payload = [b'Z'; SERIAL_CHUNK + 32];
        serial_emit(SerialStream::Kernel, &payload);
        let before = serial_hold_stats().unwrap();
        flush_serial_sync();
        let after = serial_hold_stats().unwrap();
        assert_eq!(port_log(), payload);
        assert!(
            after.holds >= before.holds + 2,
            "chunked flush must record each IRQ-masked hold"
        );
        assert_eq!(
            after.bytes, before.bytes,
            "flush must not double-count already-enqueued bytes"
        );

        // Terminal shutdown flush disables async mode, drains remaining bytes,
        // and polls TEMT boundedly (terminating even if TEMT stays false).
        PORT_LOG.lock().unwrap().clear();
        serial_emit(SerialStream::Kernel, b"bye\n");
        TX_EMPTY_MOCK.store(false, Ordering::SeqCst);
        flush_serial_for_shutdown();
        assert_eq!(port_log(), b"bye\n");
        assert!(!SERIAL_TX_IRQ_READY.load(Ordering::SeqCst));
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        // Post-shutdown writes bypass the async ring synchronously.
        serial_emit(SerialStream::Kernel, b"halt\n");
        assert_eq!(port_log(), b"bye\nhalt\n");
    }

    #[test]
    fn async_tx_ring_watermark_handles_concurrent_overtake_and_wrap() {
        let _guard = serial_test_state();
        assert_eq!(watermark_remaining(300, 320), 0);
        assert_eq!(watermark_remaining(300, 300), 0);
        assert_eq!(watermark_remaining(300, 256), 44);
        assert_eq!(watermark_remaining(10, u64::MAX - 5), 16);
        assert_eq!(watermark_remaining(u64::MAX - 5, 10), 0);

        enable_serial_tx_irq();
        // Enqueue 300 bytes, capture target, let IRQ4 drain past target while
        // newer bytes remain queued, and verify watermark_remaining is 0.
        serial_emit(SerialStream::Kernel, &[b'a'; 200]);
        serial_emit(SerialStream::Kernel, &[b'b'; 100]);
        let target = unsafe { (*SERIAL_TX_RING.0.get()).enqueued_total };
        assert_eq!(target, 300);

        // Drain 256 bytes, enqueue 200 newer bytes, then let IRQ4 drain 64 more
        // (reaching drained_total = 320 > target = 300 with 180 bytes still pending).
        unsafe {
            let ring = &mut *SERIAL_TX_RING.0.get();
            assert_eq!(ring.drain_ready_up_to(256), 256);
        }
        serial_emit(SerialStream::Kernel, &[b'c'; 200]);
        serial_tx_irq_drain(false);
        let (drained_total, pending) = unsafe {
            let ring = &*SERIAL_TX_RING.0.get();
            (ring.drained_total, ring.len)
        };
        assert_eq!(drained_total, 320);
        assert_eq!(pending, 180);
        assert_eq!(watermark_remaining(target, drained_total), 0);

        flush_serial_sync();
        assert_eq!(port_log().len(), 500);
    }

    #[test]
    fn async_tx_ring_empty_ring_yield_enforces_cooldown_against_immediate_enqueue() {
        let _guard = serial_test_state();
        enable_serial_tx_irq();

        // Drain 32 bytes to empty with yield_to_lapic=true: cooldown must engage.
        serial_emit(SerialStream::Kernel, &[b'y'; 32]);
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        serial_tx_irq_drain(true);
        assert_eq!(port_log().len(), 32);
        assert_eq!(SERIAL_TX_PENDING.load(Ordering::SeqCst), 0);
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // Immediate AP enqueue must NOT re-arm THRI while cooldown is active.
        serial_emit(SerialStream::Kernel, b"next\n");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // Tick 1 preserves quiet window; Tick 2 clears deferral and pulses IER.
        serial_tx_kick_if_pending();
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending();
        assert!(TX_IRQ_ENABLED.load(Ordering::SeqCst));
        assert!(!SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));

        // Non-terminal drains (flush_serial_sync and RX-triggered empty IRQ4)
        // must preserve active cooldown until BSP timer ticks expire it.
        serial_emit(SerialStream::Kernel, b"z");
        serial_tx_irq_drain(true);
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
        flush_serial_sync();
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
        serial_tx_irq_drain(false);
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
        // Even after those non-terminal drains, an enqueue cannot re-arm THRI yet.
        serial_emit(SerialStream::Kernel, b"w");
        assert!(!TX_IRQ_ENABLED.load(Ordering::SeqCst));
        flush_serial_sync();
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending(); // consumes quiet tick while pending == 0
        assert!(SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
        serial_tx_kick_if_pending(); // clears deferral cleanly while pending == 0
        assert!(!SERIAL_TX_IRQ_DEFERRED.load(Ordering::SeqCst));
    }

    #[test]
    fn sync_serial_emit_paces_fifo_batches_on_thre_timeout_and_preserves_order() {
        let _guard = serial_test_state();
        // Sync mode (async TX disabled, e.g. post-shutdown).
        serial_emit(SerialStream::Shell, b"open");
        PORT_LOG.lock().unwrap().clear();

        // With THRE=0 throughout, bounded timeout pacing must submit the
        // separator + 28-byte diagnostic across multiple 16-byte FIFO holds
        // without losing any byte or hanging.
        TX_READY_MOCK.store(false, Ordering::SeqCst);
        let before = serial_hold_stats().unwrap();
        serial_emit(SerialStream::Kernel, b"Shutdown failed, halting...\n");
        let after = serial_hold_stats().unwrap();
        assert_eq!(port_log(), b"\nShutdown failed, halting...\n");
        assert!(
            after.holds >= before.holds + 2,
            "29 bytes must span at least two 16-byte FIFO batches when THRE=0"
        );
        assert_eq!(SERIAL_OPEN_LINE.load(Ordering::SeqCst), NO_OPEN_LINE);

        // Deterministic interleaving regression: writer initially sees
        // NO_OPEN_LINE, hits THRE=0, unlocks, and an intervening stream leaves
        // an open prompt (`SHELL_STREAM`). On retry, `serial_emit` must recheck
        // `SERIAL_OPEN_LINE` and emit `\n` before its diagnostic.
        PORT_LOG.lock().unwrap().clear();
        SERIAL_OPEN_LINE.store(NO_OPEN_LINE, Ordering::SeqCst);
        TX_READY_MOCK.store(false, Ordering::SeqCst);
        TX_READY_INJECT_OPEN_LINE.store(SHELL_STREAM, Ordering::SeqCst);
        serial_emit(SerialStream::Kernel, b"diag\n");
        assert_eq!(
            port_log(),
            b"prompt> \ndiag\n",
            "interleaved sync retry must recheck SERIAL_OPEN_LINE and separate diag from prompt"
        );
        assert_eq!(SERIAL_OPEN_LINE.load(Ordering::SeqCst), NO_OPEN_LINE);
    }
}

// 简单的测试函数
pub fn print_something() {
    println!("Kernel started!");
    println!("VGA buffer initialized");
}
