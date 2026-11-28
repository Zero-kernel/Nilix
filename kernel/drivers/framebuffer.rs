//! Framebuffer Console Driver
//!
//! Provides pixel-based text rendering using GOP framebuffer.
//! This is the modern approach (like Linux fbcon) instead of legacy VGA text mode.

use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// Physical memory offset for high-half mapping
const PHYS_OFFSET: u64 = 0xffff_ffff_8000_0000;

/// Default console colors (ARGB format)
const FG_COLOR: u32 = 0x00AAAAAA; // Light gray foreground
const BG_COLOR: u32 = 0x00000000; // Black background

/// Character cell dimensions (8x16 font)
const CHAR_WIDTH: usize = 8;
const CHAR_HEIGHT: usize = 16;

/// Bounded shadow text-cell grid covering up to 2048x2048 pixels (256x128 chars),
/// including 800x600, 1024x768, 1280x800, 1600x1200, and 1920x1080 GOP modes.
/// Eliminates MMIO VRAM readback during scrolling (`ptr::copy` on uncacheable
/// VRAM) while remaining completely static (zero heap allocation).
const MAX_CELL_ROWS: usize = 128;
const MAX_CELL_COLS: usize = 256;

/// Minimum TSC interval between full-screen scroll flushes (~16 ms / 60 Hz at
/// 2.4 GHz). Rapid scrolling coalesces in the RAM cell ring buffer instead of
/// copying megabytes of MMIO VRAM on every newline; `flush_if_due()` and
/// `flush_now()` ensure the final visible frame is always presented promptly.
const SCROLL_FLUSH_MIN_TSC: u64 = 40_000_000;

#[inline]
fn encode_pixel(color: u32, format: PixelFormat) -> u32 {
    match format {
        PixelFormat::Rgb => {
            let r = (color >> 16) & 0xFF;
            let g = (color >> 8) & 0xFF;
            let b = color & 0xFF;
            (r << 16) | (g << 8) | b
        }
        PixelFormat::Bgr => {
            let r = (color >> 16) & 0xFF;
            let g = (color >> 8) & 0xFF;
            let b = color & 0xFF;
            (b << 16) | (g << 8) | r
        }
        PixelFormat::Unknown => color,
    }
}

#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_os = "none")]
    {
        // SAFETY: RDTSC has no memory or privilege effect in Ring 0.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Pixel format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum PixelFormat {
    Rgb = 0,
    Bgr = 1,
    Unknown = 2,
}

/// Framebuffer information passed from bootloader
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    pub base: u64,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
}

/// Framebuffer console writer
pub struct FramebufferWriter {
    /// Framebuffer base virtual address
    fb_base: u64,
    /// Width in pixels
    width: u32,
    /// Height in pixels
    height: u32,
    /// Bytes per scanline
    stride: u32,
    /// Pixel format
    pixel_format: PixelFormat,
    /// Current cursor column (in characters)
    col: usize,
    /// Current cursor row (in characters)
    row: usize,
    /// Maximum columns
    max_col: usize,
    /// Maximum rows
    max_row: usize,
    /// Foreground color (ARGB)
    fg_color: u32,
    /// Background color (ARGB)
    bg_color: u32,
    /// Pre-encoded foreground pixel value for `pixel_format`
    fg_pixel: u32,
    /// Pre-encoded background pixel value for `pixel_format`
    bg_pixel: u32,
    /// Whether framebuffer is initialized
    initialized: bool,
    /// R24-8 fix: Validated framebuffer size in bytes
    /// All pixel writes must stay within this bound
    fb_size: usize,
    /// Logical text-cell ring buffer (O(1) scroll without MMIO VRAM reads)
    cells: [[u8; MAX_CELL_COLS]; MAX_CELL_ROWS],
    /// Cells currently presented in VRAM (used to diff on coalesced scroll flush)
    presented: [[u8; MAX_CELL_COLS]; MAX_CELL_ROWS],
    /// Ring-buffer index corresponding to logical screen row 0
    top_row: usize,
    /// True when one or more scrolls have occurred since the last VRAM sync
    scroll_pending: bool,
    /// TSC timestamp of the last full VRAM sync
    last_flush_tsc: u64,
}

impl Default for FramebufferWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FramebufferWriter {
    /// Create an uninitialized writer
    pub const fn new() -> Self {
        Self {
            fb_base: 0,
            width: 0,
            height: 0,
            stride: 0,
            pixel_format: PixelFormat::Bgr,
            col: 0,
            row: 0,
            max_col: 0,
            max_row: 0,
            fg_color: FG_COLOR,
            bg_color: BG_COLOR,
            fg_pixel: FG_COLOR,
            bg_pixel: BG_COLOR,
            initialized: false,
            fb_size: 0,
            cells: [[b' '; MAX_CELL_COLS]; MAX_CELL_ROWS],
            presented: [[b' '; MAX_CELL_COLS]; MAX_CELL_ROWS],
            top_row: 0,
            scroll_pending: false,
            last_flush_tsc: 0,
        }
    }

    /// Initialize with framebuffer info
    pub fn init(&mut self, info: &FramebufferInfo) {
        // R24-8 fix: Validate framebuffer dimensions before using
        // Check that stride * height (in bytes) doesn't exceed provided size
        // stride is in pixels, so multiply by 4 for bytes
        let stride_bytes = (info.stride as usize).saturating_mul(4);
        let required_size = stride_bytes.saturating_mul(info.height as usize);

        if info.size == 0 || required_size > info.size {
            // Invalid framebuffer info - dimensions exceed buffer size
            // Refuse to initialize to prevent out-of-bounds writes
            return;
        }

        // Also validate that width fits within stride
        if info.width > info.stride {
            return;
        }

        // Calculate virtual address for framebuffer
        //
        // The bootloader sets up identity mapping for 0-4GB, so we can access
        // the framebuffer at its physical address directly.
        //
        // However, identity mapping will be hardened (made read-only) during
        // security initialization. To avoid this, we use the high-half direct
        // mapping if the address is within range, otherwise we need to create
        // a dedicated mapping.
        //
        // Bootloader maps physical 0-1GB to virtual 0xffffffff80000000-...
        // For framebuffer addresses beyond 1GB (common for GOP), we need
        // to use identity mapping and mark it as MMIO-exempt during hardening.
        //
        // Note: Framebuffer physical address is typically:
        // - 0x80000000 (2GB) for QEMU/OVMF
        // - Could be higher on real hardware
        self.fb_base = if info.base.saturating_add(required_size as u64) <= 0x4000_0000 {
            // Within first 1GB - can use high-half mapping
            info.base + PHYS_OFFSET
        } else {
            // Beyond high-half mapping - use identity mapping
            // The security module should preserve this as writable MMIO
            info.base
        };

        self.width = info.width;
        self.height = info.height;
        // IMPORTANT: UEFI GOP stride is in PIXELS, convert to BYTES (4 bytes per pixel)
        self.stride = info.stride * 4;
        self.pixel_format = info.pixel_format;
        self.fg_pixel = encode_pixel(self.fg_color, self.pixel_format);
        self.bg_pixel = encode_pixel(self.bg_color, self.pixel_format);
        self.max_col = ((info.width as usize) / CHAR_WIDTH).min(MAX_CELL_COLS);
        self.max_row = ((info.height as usize) / CHAR_HEIGHT).min(MAX_CELL_ROWS);
        self.col = 0;
        self.row = 0;
        self.top_row = 0;
        self.scroll_pending = false;
        self.last_flush_tsc = read_tsc();
        self.initialized = true;
        // R24-8 fix: Store validated framebuffer size for bounds checking
        self.fb_size = info.size;

        // Store framebuffer info for security module to access
        unsafe {
            FRAMEBUFFER_PHYS_BASE = info.base;
            FRAMEBUFFER_SIZE = info.size;
            FRAMEBUFFER_DRAWN_SIZE = required_size;
        }

        // Clear screen with background color
        self.clear_screen();
    }

    /// Check if writer is initialized
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    #[inline]
    fn logical_to_ring_row(&self, logical_row: usize) -> usize {
        if self.max_row == 0 {
            0
        } else {
            (self.top_row + logical_row) % self.max_row
        }
    }

    /// Draw a single character directly to VRAM using write-only 32-bit stores
    /// (zero MMIO reads, single up-front bounds check per glyph).
    fn draw_char(&self, c: char, char_col: usize, char_row: usize) {
        if !self.initialized || char_col >= self.max_col || char_row >= self.max_row {
            return;
        }
        let stride = self.stride as usize;
        let base_offset = (char_row * CHAR_HEIGHT)
            .saturating_mul(stride)
            .saturating_add(char_col * CHAR_WIDTH * 4);
        let last_row_end = base_offset
            .saturating_add((CHAR_HEIGHT - 1).saturating_mul(stride))
            .saturating_add(CHAR_WIDTH * 4);
        // R24-8 fix: verify entire 8x16 glyph stays within validated framebuffer bounds.
        if last_row_end > self.fb_size {
            return;
        }

        let fg = self.fg_pixel;
        let bg = self.bg_pixel;
        let mut row_addr = self.fb_base + base_offset as u64;
        let aligned_u64 = (row_addr & 7) == 0 && (stride & 7) == 0;

        if c == ' ' {
            if aligned_u64 {
                let bg2 = ((bg as u64) << 32) | (bg as u64);
                for _ in 0..CHAR_HEIGHT {
                    let row_ptr = row_addr as *mut u64;
                    unsafe {
                        ptr::write_volatile(row_ptr, bg2);
                        ptr::write_volatile(row_ptr.add(1), bg2);
                        ptr::write_volatile(row_ptr.add(2), bg2);
                        ptr::write_volatile(row_ptr.add(3), bg2);
                    }
                    row_addr += stride as u64;
                }
            } else {
                for _ in 0..CHAR_HEIGHT {
                    let row_ptr = row_addr as *mut u32;
                    unsafe {
                        for col in 0..CHAR_WIDTH {
                            ptr::write_volatile(row_ptr.add(col), bg);
                        }
                    }
                    row_addr += stride as u64;
                }
            }
            return;
        }

        let bitmap = get_font_bitmap(c);
        if aligned_u64 {
            let fg64 = fg as u64;
            let bg64 = bg as u64;
            for &bits in bitmap.iter() {
                let row_ptr = row_addr as *mut u64;
                let p0 = if (bits & 0x80) != 0 { fg64 } else { bg64 };
                let p1 = if (bits & 0x40) != 0 { fg64 } else { bg64 };
                let p2 = if (bits & 0x20) != 0 { fg64 } else { bg64 };
                let p3 = if (bits & 0x10) != 0 { fg64 } else { bg64 };
                let p4 = if (bits & 0x08) != 0 { fg64 } else { bg64 };
                let p5 = if (bits & 0x04) != 0 { fg64 } else { bg64 };
                let p6 = if (bits & 0x02) != 0 { fg64 } else { bg64 };
                let p7 = if (bits & 0x01) != 0 { fg64 } else { bg64 };
                unsafe {
                    ptr::write_volatile(row_ptr, p0 | (p1 << 32));
                    ptr::write_volatile(row_ptr.add(1), p2 | (p3 << 32));
                    ptr::write_volatile(row_ptr.add(2), p4 | (p5 << 32));
                    ptr::write_volatile(row_ptr.add(3), p6 | (p7 << 32));
                }
                row_addr += stride as u64;
            }
        } else {
            for &bits in bitmap.iter() {
                let row_ptr = row_addr as *mut u32;
                unsafe {
                    for col in 0..CHAR_WIDTH {
                        let pixel = if (bits >> (7 - col)) & 1 != 0 { fg } else { bg };
                        ptr::write_volatile(row_ptr.add(col), pixel);
                    }
                }
                row_addr += stride as u64;
            }
        }
    }

    /// Clear entire screen
    pub fn clear_screen(&mut self) {
        if !self.initialized {
            return;
        }

        // Fast fill: write entire framebuffer
        let total_bytes = self.height as usize * self.stride as usize;

        // R24-8 fix: Clamp to validated framebuffer size
        let safe_bytes = total_bytes.min(self.fb_size);
        let pixel_value = self.bg_pixel;

        // Fill 4 bytes at a time
        let ptr = self.fb_base as *mut u32;
        let count = safe_bytes / 4;
        for i in 0..count {
            unsafe {
                ptr::write_volatile(ptr.add(i), pixel_value);
            }
        }

        for r in 0..self.max_row {
            self.cells[r][..self.max_col].fill(b' ');
            self.presented[r][..self.max_col].fill(b' ');
        }
        self.col = 0;
        self.row = 0;
        self.top_row = 0;
        self.scroll_pending = false;
        let now = read_tsc();
        self.last_flush_tsc = now;
        LAST_FLUSH_TSC.store(now, Ordering::Relaxed);
        FB_DIRTY.store(false, Ordering::Release);
    }

    /// Scroll screen up by one line in O(max_col) RAM without any MMIO VRAM reads.
    /// The actual VRAM redraw is coalesced via `flush_dirty_vram()`.
    fn scroll_up(&mut self) {
        if !self.initialized || self.max_row == 0 || self.max_col == 0 {
            return;
        }
        if self.max_row > 1 {
            self.top_row = (self.top_row + 1) % self.max_row;
        }
        let bottom_ring_row = self.logical_to_ring_row(self.max_row - 1);
        self.cells[bottom_ring_row][..self.max_col].fill(b' ');
        self.scroll_pending = true;
        FB_DIRTY.store(true, Ordering::Release);
    }

    /// Synchronize any pending scrolled shadow cells to VRAM using diffed
    /// write-only glyph blits (zero MMIO reads, skipping unchanged cells).
    fn flush_dirty_vram(&mut self, now_tsc: u64) {
        if !self.initialized || !self.scroll_pending {
            return;
        }
        for logical_row in 0..self.max_row {
            let ring_row = self.logical_to_ring_row(logical_row);
            for col in 0..self.max_col {
                let ch = self.cells[ring_row][col];
                if self.presented[logical_row][col] != ch {
                    self.draw_char(ch as char, col, logical_row);
                    self.presented[logical_row][col] = ch;
                }
            }
        }
        self.scroll_pending = false;
        self.last_flush_tsc = now_tsc;
        LAST_FLUSH_TSC.store(now_tsc, Ordering::Relaxed);
        FB_DIRTY.store(false, Ordering::Release);
    }

    #[inline]
    fn write_cell(&mut self, ch: u8, col: usize, row: usize) {
        if col >= self.max_col || row >= self.max_row {
            return;
        }
        let ring_row = self.logical_to_ring_row(row);
        self.cells[ring_row][col] = ch;
        if !self.scroll_pending {
            if self.presented[row][col] != ch {
                self.draw_char(ch as char, col, row);
                self.presented[row][col] = ch;
            }
        }
    }

    #[inline]
    fn scroll_flush_due(&self, now_tsc: u64) -> bool {
        #[cfg(target_os = "none")]
        {
            now_tsc.wrapping_sub(self.last_flush_tsc) >= SCROLL_FLUSH_MIN_TSC
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = now_tsc;
            true
        }
    }

    /// Write a single byte
    pub fn write_byte(&mut self, byte: u8) {
        if !self.initialized || self.max_row == 0 || self.max_col == 0 {
            return;
        }

        match byte {
            b'\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.max_row {
                    self.scroll_up();
                    self.row = self.max_row - 1;
                }
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                // Tab: advance to next 8-character boundary
                let next = (self.col + 8) & !7;
                for _ in self.col..next.min(self.max_col) {
                    self.write_cell(b' ', self.col, self.row);
                    self.col += 1;
                }
                if self.col >= self.max_col {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.max_row {
                        self.scroll_up();
                        self.row = self.max_row - 1;
                    }
                }
            }
            0x08 => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                    self.write_cell(b' ', self.col, self.row);
                }
            }
            byte => {
                // Printable character
                if self.col >= self.max_col {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.max_row {
                        self.scroll_up();
                        self.row = self.max_row - 1;
                    }
                }
                let c = if (0x20..0x7f).contains(&byte) {
                    byte
                } else {
                    b'?' // Replace unprintable with '?'
                };
                self.write_cell(c, self.col, self.row);
                self.col += 1;
            }
        }
    }

    /// Write a string
    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for FramebufferWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

/// Global framebuffer writer.
///
/// R190-7: lock it only inside `vga_buffer::with_display`, which detects
/// same-CPU re-entry (it keeps the caller's IRQ state).
pub static WRITER: Mutex<FramebufferWriter> = Mutex::new(FramebufferWriter::new());

/// R190-7 FIX: lock-free mirror of `WRITER.initialized`, so every print no
/// longer takes the writer lock just to choose a backend.
static FB_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Lock-free mirror of `WRITER.scroll_pending` for cheap 60 Hz tail flushes.
static FB_DIRTY: AtomicBool = AtomicBool::new(false);
/// Lock-free mirror of `WRITER.last_flush_tsc`.
static LAST_FLUSH_TSC: AtomicU64 = AtomicU64::new(0);

/// Framebuffer physical base address (for security module to query)
static mut FRAMEBUFFER_PHYS_BASE: u64 = 0;
/// Framebuffer size in bytes
static mut FRAMEBUFFER_SIZE: usize = 0;
/// Bytes the console draws (stride x height), at most `FRAMEBUFFER_SIZE`.
static mut FRAMEBUFFER_DRAWN_SIZE: usize = 0;

/// Get the framebuffer physical memory region
///
/// Returns (base_phys_addr, size) if framebuffer is initialized, None otherwise.
/// Used by security module to preserve this region as writable during identity
/// map hardening.
pub fn get_framebuffer_region() -> Option<(u64, usize)> {
    unsafe {
        if FRAMEBUFFER_PHYS_BASE != 0 && FRAMEBUFFER_SIZE != 0 {
            Some((FRAMEBUFFER_PHYS_BASE, FRAMEBUFFER_SIZE))
        } else {
            None
        }
    }
}

/// D0-ISO-1 Approach A (R192-RES-1): draw through `virt`, a high-half mapping
/// of the first `mapped_len` bytes of the framebuffer (at least the drawn
/// region). Its identity address exists only in the boot page table; user
/// address spaces carry no identity map.
pub fn relocate(virt: u64, mapped_len: usize) {
    crate::vga_buffer::with_display(|| {
        let mut writer = WRITER.lock();
        if writer.initialized {
            writer.fb_base = virt;
            writer.fb_size = writer.fb_size.min(mapped_len);
        }
    });
}

/// The drawn part of the framebuffer, `(physical base, stride x height bytes)`:
/// what a relocated console must map. `None` without a framebuffer console.
pub fn get_drawn_region() -> Option<(u64, usize)> {
    unsafe {
        if FRAMEBUFFER_PHYS_BASE != 0 && FRAMEBUFFER_DRAWN_SIZE != 0 {
            Some((FRAMEBUFFER_PHYS_BASE, FRAMEBUFFER_DRAWN_SIZE))
        } else {
            None
        }
    }
}

/// Turn the framebuffer console off: no high-half mapping of it could be
/// made. Output stays on the serial port only, because the text buffer is not
/// the display of a boot whose firmware handed over a framebuffer.
pub fn disable() {
    crate::vga_buffer::with_display(|| {
        let mut writer = WRITER.lock();
        writer.initialized = false;
        writer.scroll_pending = false;
        FB_INITIALIZED.store(false, Ordering::Release);
        FB_DIRTY.store(false, Ordering::Release);
    });
}

/// Initialize framebuffer console with info from bootloader
pub fn init(info: &FramebufferInfo) {
    let initialized = crate::vga_buffer::with_display(|| {
        let mut writer = WRITER.lock();
        writer.init(info);
        writer.is_initialized()
    });
    FB_INITIALIZED.store(initialized == Some(true), Ordering::Release);
}

/// Check if framebuffer is initialized
pub fn is_initialized() -> bool {
    FB_INITIALIZED.load(Ordering::Acquire)
}

/// Render formatted text. The caller holds the display (`with_display`).
pub(crate) fn write_args(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut writer = WRITER.lock();
    // A formatting error must not panic while the display is held.
    let _ = writer.write_fmt(args);
    if writer.scroll_pending {
        let now = read_tsc();
        if writer.scroll_flush_due(now) {
            writer.flush_dirty_vram(now);
        }
    }
}

/// Non-blocking 60 Hz flush of any coalesced scroll updates (safe for process-
/// context tail hooks: one Relaxed load when clean, never spins on contention).
#[inline]
pub fn flush_if_due() {
    if !FB_DIRTY.load(Ordering::Relaxed) || !FB_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let now = read_tsc();
    if now.wrapping_sub(LAST_FLUSH_TSC.load(Ordering::Relaxed)) < SCROLL_FLUSH_MIN_TSC {
        return;
    }
    let _ = crate::vga_buffer::try_with_display(|| {
        if let Some(mut writer) = WRITER.try_lock() {
            if writer.scroll_pending && writer.scroll_flush_due(now) {
                writer.flush_dirty_vram(now);
            }
        }
    });
}

/// Synchronously flush any pending framebuffer scroll updates (used on clean
/// shutdown / PID 1 exit).
pub fn flush_now() {
    if !FB_DIRTY.load(Ordering::Acquire) || !FB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let _ = crate::vga_buffer::with_display(|| {
        let mut writer = WRITER.lock();
        writer.flush_dirty_vram(read_tsc());
    });
}

/// Best-effort non-blocking framebuffer flush for panic paths (never spins if
/// another CPU or interrupted context holds the display lock).
pub(crate) fn flush_for_panic() {
    if !FB_DIRTY.load(Ordering::Acquire) || !FB_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let _ = crate::vga_buffer::try_with_display(|| {
        if let Some(mut writer) = WRITER.try_lock() {
            writer.flush_dirty_vram(read_tsc());
        }
    });
}

// ============================================================================
// 8x16 Bitmap Font
// ============================================================================

/// Get font bitmap for a character (8x16 pixels)
fn get_font_bitmap(c: char) -> [u8; CHAR_HEIGHT] {
    let idx = c as usize;
    if (0x20..0x7f).contains(&idx) {
        FONT_8X16[idx - 0x20]
    } else {
        FONT_8X16[0] // Space for unknown characters
    }
}

/// 8x16 bitmap font for ASCII characters 0x20-0x7E
/// Each character is 16 bytes, one byte per row (8 pixels)
static FONT_8X16: [[u8; 16]; 95] = [
    // 0x20 ' ' (space)
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x21 '!'
    [
        0x00, 0x00, 0x18, 0x3C, 0x3C, 0x3C, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x22 '"'
    [
        0x00, 0x66, 0x66, 0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x23 '#'
    [
        0x00, 0x00, 0x00, 0x6C, 0x6C, 0xFE, 0x6C, 0x6C, 0x6C, 0xFE, 0x6C, 0x6C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x24 '$'
    [
        0x18, 0x18, 0x7C, 0xC6, 0xC2, 0xC0, 0x7C, 0x06, 0x06, 0x86, 0xC6, 0x7C, 0x18, 0x18, 0x00,
        0x00,
    ],
    // 0x25 '%'
    [
        0x00, 0x00, 0x00, 0x00, 0xC2, 0xC6, 0x0C, 0x18, 0x30, 0x60, 0xC6, 0x86, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x26 '&'
    [
        0x00, 0x00, 0x38, 0x6C, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x27 '''
    [
        0x00, 0x30, 0x30, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x28 '('
    [
        0x00, 0x00, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x29 ')'
    [
        0x00, 0x00, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x2A '*'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x2B '+'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x2C ','
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x30, 0x00, 0x00,
        0x00,
    ],
    // 0x2D '-'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x2E '.'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x2F '/'
    [
        0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x30 '0'
    [
        0x00, 0x00, 0x38, 0x6C, 0xC6, 0xC6, 0xD6, 0xD6, 0xC6, 0xC6, 0x6C, 0x38, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x31 '1'
    [
        0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x32 '2'
    [
        0x00, 0x00, 0x7C, 0xC6, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xC6, 0xFE, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x33 '3'
    [
        0x00, 0x00, 0x7C, 0xC6, 0x06, 0x06, 0x3C, 0x06, 0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x34 '4'
    [
        0x00, 0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x0C, 0x0C, 0x1E, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x35 '5'
    [
        0x00, 0x00, 0xFE, 0xC0, 0xC0, 0xC0, 0xFC, 0x06, 0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x36 '6'
    [
        0x00, 0x00, 0x38, 0x60, 0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x37 '7'
    [
        0x00, 0x00, 0xFE, 0xC6, 0x06, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x38 '8'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x39 '9'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x06, 0x06, 0x0C, 0x78, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3A ':'
    [
        0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3B ';'
    [
        0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3C '<'
    [
        0x00, 0x00, 0x00, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3D '='
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3E '>'
    [
        0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x3F '?'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x0C, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x40 '@'
    [
        0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xDE, 0xDE, 0xDE, 0xDC, 0xC0, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x41 'A'
    [
        0x00, 0x00, 0x10, 0x38, 0x6C, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x42 'B'
    [
        0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x66, 0x66, 0xFC, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x43 'C'
    [
        0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xC0, 0xC0, 0xC2, 0x66, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x44 'D'
    [
        0x00, 0x00, 0xF8, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x6C, 0xF8, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x45 'E'
    [
        0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68, 0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x46 'F'
    [
        0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x47 'G'
    [
        0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xDE, 0xC6, 0xC6, 0x66, 0x3A, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x48 'H'
    [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x49 'I'
    [
        0x00, 0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4A 'J'
    [
        0x00, 0x00, 0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0xCC, 0xCC, 0xCC, 0x78, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4B 'K'
    [
        0x00, 0x00, 0xE6, 0x66, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4C 'L'
    [
        0x00, 0x00, 0xF0, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4D 'M'
    [
        0x00, 0x00, 0xC6, 0xEE, 0xFE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4E 'N'
    [
        0x00, 0x00, 0xC6, 0xE6, 0xF6, 0xFE, 0xDE, 0xCE, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x4F 'O'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x50 'P'
    [
        0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x51 'Q'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6, 0xDE, 0x7C, 0x0C, 0x0E, 0x00,
        0x00,
    ],
    // 0x52 'R'
    [
        0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x53 'S'
    [
        0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x60, 0x38, 0x0C, 0x06, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x54 'T'
    [
        0x00, 0x00, 0x7E, 0x7E, 0x5A, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x55 'U'
    [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x56 'V'
    [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x57 'W'
    [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6, 0xD6, 0xD6, 0xFE, 0xEE, 0x6C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x58 'X'
    [
        0x00, 0x00, 0xC6, 0xC6, 0x6C, 0x7C, 0x38, 0x38, 0x7C, 0x6C, 0xC6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x59 'Y'
    [
        0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5A 'Z'
    [
        0x00, 0x00, 0xFE, 0xC6, 0x86, 0x0C, 0x18, 0x30, 0x60, 0xC2, 0xC6, 0xFE, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5B '['
    [
        0x00, 0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5C '\'
    [
        0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0x70, 0x38, 0x1C, 0x0E, 0x06, 0x02, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5D ']'
    [
        0x00, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5E '^'
    [
        0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x5F '_'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00,
        0x00,
    ],
    // 0x60 '`'
    [
        0x30, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x61 'a'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x0C, 0x7C, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x62 'b'
    [
        0x00, 0x00, 0xE0, 0x60, 0x60, 0x78, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x63 'c'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x64 'd'
    [
        0x00, 0x00, 0x1C, 0x0C, 0x0C, 0x3C, 0x6C, 0xCC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x65 'e'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x66 'f'
    [
        0x00, 0x00, 0x38, 0x6C, 0x64, 0x60, 0xF0, 0x60, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x67 'g'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x7C, 0x0C, 0xCC, 0x78,
        0x00,
    ],
    // 0x68 'h'
    [
        0x00, 0x00, 0xE0, 0x60, 0x60, 0x6C, 0x76, 0x66, 0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x69 'i'
    [
        0x00, 0x00, 0x18, 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x6A 'j'
    [
        0x00, 0x00, 0x06, 0x06, 0x00, 0x0E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x66, 0x66, 0x3C,
        0x00,
    ],
    // 0x6B 'k'
    [
        0x00, 0x00, 0xE0, 0x60, 0x60, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0xE6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x6C 'l'
    [
        0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x6D 'm'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xD6, 0xD6, 0xD6, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x6E 'n'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x6F 'o'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x70 'p'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0xF0,
        0x00,
    ],
    // 0x71 'q'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x7C, 0x0C, 0x0C, 0x1E,
        0x00,
    ],
    // 0x72 'r'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x76, 0x66, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x73 's'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0x60, 0x38, 0x0C, 0xC6, 0x7C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x74 't'
    [
        0x00, 0x00, 0x10, 0x30, 0x30, 0xFC, 0x30, 0x30, 0x30, 0x30, 0x36, 0x1C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x75 'u'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x76 'v'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x77 'w'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xD6, 0xD6, 0xFE, 0x6C, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x78 'x'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x6C, 0x38, 0x38, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x79 'y'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0xF8,
        0x00,
    ],
    // 0x7A 'z'
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xCC, 0x18, 0x30, 0x60, 0xC6, 0xFE, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x7B '{'
    [
        0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x18, 0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x7C '|'
    [
        0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x7D '}'
    [
        0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00,
        0x00,
    ],
    // 0x7E '~'
    [
        0x00, 0x00, 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::boxed::Box;
    use std::vec;

    #[test]
    fn shadow_ring_scroll_and_diff_flush_renders_exact_pixels() {
        // 4 columns x 3 rows => 32 x 48 pixels (RGB).
        let width = 32u32;
        let height = 48u32;
        let stride = width;
        let mut vram = vec![0u32; (stride * height) as usize];

        let mut writer = Box::new(FramebufferWriter::new());
        writer.fb_base = vram.as_mut_ptr() as u64;
        writer.width = width;
        writer.height = height;
        writer.stride = stride * 4;
        writer.pixel_format = PixelFormat::Rgb;
        writer.fg_pixel = encode_pixel(FG_COLOR, PixelFormat::Rgb);
        writer.bg_pixel = encode_pixel(BG_COLOR, PixelFormat::Rgb);
        writer.max_col = (width as usize) / CHAR_WIDTH;
        writer.max_row = (height as usize) / CHAR_HEIGHT;
        writer.fb_size = vram.len() * 4;
        writer.initialized = true;
        writer.clear_screen();

        // Write 4 lines into a 3-row viewport: triggers 2 coalesced scrolls
        // without touching VRAM until flush_dirty_vram().
        writer.write_string("AA\nBB\nCC\nDD");
        assert!(
            writer.scroll_pending,
            "scrolling must defer VRAM redraw into the shadow cell ring"
        );
        // Logical visible rows after scrolling twice: row 0 = "CC", row 1 = "DD", row 2 = "  ".
        // Wait: "AA\n" -> row 1; "BB\n" -> row 2; "CC\n" -> scrolls once (row 0="BB", row 1="CC", row 2="");
        // then "DD" lands on row 2 => visible rows are ["BB  ", "CC  ", "DD  "].
        let r0 = writer.logical_to_ring_row(0);
        let r1 = writer.logical_to_ring_row(1);
        let r2 = writer.logical_to_ring_row(2);
        assert_eq!(&writer.cells[r0][..4], b"BB  ");
        assert_eq!(&writer.cells[r1][..4], b"CC  ");
        assert_eq!(&writer.cells[r2][..4], b"DD  ");

        // Flush diff into mock VRAM and verify exact glyph pixels for row 0 ('B')
        // and row 2 ('D'), and clean blank pixels for col 2..4.
        writer.flush_dirty_vram(SCROLL_FLUSH_MIN_TSC);
        assert!(!writer.scroll_pending);
        assert_eq!(&writer.presented[0][..4], b"BB  ");
        assert_eq!(&writer.presented[1][..4], b"CC  ");
        assert_eq!(&writer.presented[2][..4], b"DD  ");

        let check_glyph = |ch: char, char_col: usize, char_row: usize| {
            let bitmap = get_font_bitmap(ch);
            for (gy, &bits) in bitmap.iter().enumerate() {
                for gx in 0..CHAR_WIDTH {
                    let px = char_col * CHAR_WIDTH + gx;
                    let py = char_row * CHAR_HEIGHT + gy;
                    let expected = if (bits >> (7 - gx)) & 1 != 0 {
                        writer.fg_pixel
                    } else {
                        writer.bg_pixel
                    };
                    assert_eq!(
                        vram[py * (stride as usize) + px],
                        expected,
                        "pixel mismatch for '{}' at cell ({},{}) offset ({},{})",
                        ch,
                        char_col,
                        char_row,
                        gx,
                        gy
                    );
                }
            }
        };
        check_glyph('B', 0, 0);
        check_glyph('B', 1, 0);
        check_glyph(' ', 2, 0);
        check_glyph('C', 0, 1);
        check_glyph('D', 0, 2);
        check_glyph('D', 1, 2);
        check_glyph(' ', 2, 2);
    }
}
