// VGA文本模式缓冲区实现
// Uses volatile writes to ensure MMIO operations reach the VGA hardware
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
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
unsafe fn serial_outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
    );
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
    let owner = cpu_local::try_current_registered_cpu_id().unwrap_or(UNREGISTERED_DISPLAY_OWNER);
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

/// Serial console writer; `raw` passes user TTY data through untouched.
struct SerialWriter {
    raw: bool,
}

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.raw {
            for byte in s.bytes() {
                unsafe { serial_outb(SERIAL_PORT, byte) };
            }
            return Ok(());
        }
        let mut utf8 = [0u8; 4];
        for ch in s.chars() {
            for &byte in serial_safe_char(ch).encode_utf8(&mut utf8).as_bytes() {
                unsafe { serial_outb(SERIAL_PORT, byte) };
            }
        }
        Ok(())
    }
}

/// Kernel console output (`print!`/`println!`/klog). The serial copy is
/// sanitized (R190-13).
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    write_display(args);
    // 始终同时发送到串口，便于在 -nographic 模式下查看
    let _ = SerialWriter { raw: false }.write_fmt(args);
}

/// User console data written through stdout/stderr or `/dev/console`.
///
/// R190-13: a user program owns its terminal stream (ANSI colors, `\r`,
/// backspace line editing), so the serial copy is byte-exact, as on a Linux
/// TTY. Only the kernel's own diagnostics go through the sanitizing `_print`.
pub fn console_write_str(s: &str) {
    use core::fmt::Write;
    write_display(format_args!("{}", s));
    let _ = SerialWriter { raw: true }.write_str(s);
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
    use super::serial_safe_char;

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
