// VGA文本模式缓冲区实现
// Uses volatile writes to ensure MMIO operations reach the VGA hardware
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

// 串口端口地址
const SERIAL_PORT: u16 = 0x3F8;

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

/// Render to the active display backend.
fn write_display(args: fmt::Arguments) {
    use core::fmt::Write;
    let _ = with_display(|| {
        // 优先输出到 framebuffer（现代 GOP 方式）
        if crate::framebuffer::is_initialized() {
            crate::framebuffer::write_args(args);
        } else {
            // 后备：输出到 VGA 文本缓冲区（旧式 BIOS）
            let _ = WRITER.lock().write_fmt(args);
        }
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
/// [`serial_max_hold_tsc`]). Polling the THRE inside a hold would break that
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
/// is a leaf that may be taken under any other lock. Masking is what makes
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
                .compare_exchange_weak(
                    NO_SERIAL_OWNER,
                    owner,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
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
fn serial_emit(stream: SerialStream, chunk: &[u8]) {
    let _ = with_serial(|owner, locked| {
        if !locked {
            for &byte in chunk {
                unsafe { serial_outb(SERIAL_PORT, byte) };
            }
            return;
        }
        let start = read_tsc();
        let id = stream.id(owner);
        let open = SERIAL_OPEN_LINE.load(Ordering::Relaxed);
        if open != NO_OPEN_LINE && open != id {
            unsafe { serial_outb(SERIAL_PORT, b'\n') };
        }
        for &byte in chunk {
            unsafe { serial_outb(SERIAL_PORT, byte) };
        }
        let open = match chunk.last() {
            Some(b'\n') => NO_OPEN_LINE,
            Some(_) => id,
            None => open,
        };
        SERIAL_OPEN_LINE.store(open, Ordering::Relaxed);
        SERIAL_MAX_HOLD_TSC.fetch_max(read_tsc().wrapping_sub(start), Ordering::Relaxed);
    });
}

/// TD-SERIAL-1: longest IRQ-masked serial hold so far, in TSC cycles.
pub fn serial_max_hold_tsc() -> u64 {
    SERIAL_MAX_HOLD_TSC.load(Ordering::Relaxed)
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
    let owner = console_owner_token();
    for _ in 0..PANIC_CLAIM_SPINS {
        match SERIAL_OWNER_CPU.compare_exchange_weak(
            NO_SERIAL_OWNER,
            owner,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                if SERIAL_OPEN_LINE.swap(NO_OPEN_LINE, Ordering::Relaxed) != NO_OPEN_LINE {
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
    let _ = with_display(|| {
        let mut writer = WRITER.lock();
        for row in 0..BUFFER_HEIGHT {
            writer.clear_row(row);
        }
    });
}

pub fn write_str(s: &str) {
    use core::fmt::Write;
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

    /// Reset the lock word, line state and port log; return the guard that
    /// keeps the other lock tests out.
    fn serial_test_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERIAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
        SERIAL_OPEN_LINE.store(NO_OPEN_LINE, Ordering::SeqCst);
        PORT_LOG.lock().unwrap().clear();
        guard
    }

    fn port_log() -> Vec<u8> {
        PORT_LOG.lock().unwrap().clone()
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
        SERIAL_OWNER_CPU.store(NO_SERIAL_OWNER, Ordering::SeqCst);
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
}

// 简单的测试函数
pub fn print_something() {
    println!("Kernel started!");
    println!("VGA buffer initialized");
}
