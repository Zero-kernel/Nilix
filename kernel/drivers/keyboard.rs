//! Keyboard Input Driver for Zero-OS
//!
//! This module provides:
//! - PS/2 Set 1 scancode to ASCII translation
//! - Ring buffer for keyboard input
//! - Thread-safe access from interrupt handler and syscall context
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +----------------+     +-------------+
//! | Keyboard IRQ (33) | --> | push_scancode  | --> | Ring Buffer |
//! +-------------------+     +----------------+     +-------------+
//!                                                        |
//!                                                        v
//!                           +----------------+     +-------------+
//!                           | sys_read(fd=0) | <-- | read_buf    |
//!                           +----------------+     +-------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // In keyboard interrupt handler:
//! keyboard::push_scancode(scancode);
//!
//! // In sys_read for stdin:
//! let bytes_read = keyboard::read_buf(&mut buffer);
//! ```

use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

/// Ring buffer capacity (increased to handle burst input)
const BUFFER_SIZE: usize = 1024;

/// Keyboard input ring buffer
///
/// A simple circular buffer optimized for single-producer (IRQ) and
/// single-consumer (syscall) access patterns.
pub struct KeyboardBuffer {
    /// Character buffer
    buffer: [u8; BUFFER_SIZE],
    /// Read position (consumer index)
    read_pos: usize,
    /// Write position (producer index)
    write_pos: usize,
    /// Number of characters in buffer
    count: usize,
    /// Characters rejected because the bounded input ring was full.
    dropped: u64,
    /// R190-3 FIX: consumer generation, advanced by every operation that
    /// removes bytes. Producers only append and never move `read_pos`, so an
    /// unchanged generation proves a previously peeked prefix is still the
    /// front of the ring.
    consumed: u64,
    /// Shift key state (true if pressed)
    shift_pressed: bool,
    /// Ctrl key state (true if pressed)
    ctrl_pressed: bool,
    /// Caps Lock state (true if active)
    caps_lock: bool,
}

impl KeyboardBuffer {
    /// Create a new empty keyboard buffer
    const fn new() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            dropped: 0,
            consumed: 0,
            shift_pressed: false,
            ctrl_pressed: false,
            caps_lock: false,
        }
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer is full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= BUFFER_SIZE
    }

    /// Get number of available characters
    #[inline]
    pub fn available(&self) -> usize {
        self.count
    }

    /// Number of input characters dropped due to a full ring.
    #[inline]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Push a character into the buffer
    ///
    /// Returns true if character was added, false if buffer is full.
    fn push(&mut self, ch: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.buffer[self.write_pos] = ch;
        self.write_pos = (self.write_pos + 1) % BUFFER_SIZE;
        self.count += 1;
        true
    }

    /// Pop a character from the buffer
    ///
    /// Returns None if buffer is empty.
    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let ch = self.buffer[self.read_pos];
        self.read_pos = (self.read_pos + 1) % BUFFER_SIZE;
        self.count -= 1;
        self.consumed = self.consumed.wrapping_add(1);
        Some(ch)
    }

    /// Read multiple characters into a buffer
    ///
    /// Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for byte in buf.iter_mut() {
            match self.pop() {
                Some(ch) => {
                    *byte = ch;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Copy buffered bytes without advancing the consumer cursor.
    fn peek(&self, buf: &mut [u8]) -> usize {
        let to_read = core::cmp::min(buf.len(), self.count);
        let mut pos = self.read_pos;
        for byte in buf.iter_mut().take(to_read) {
            *byte = self.buffer[pos];
            pos = (pos + 1) % BUFFER_SIZE;
        }
        to_read
    }

    /// Commit a previously peeked prefix while the buffer lock is held.
    fn consume(&mut self, count: usize) {
        debug_assert!(count <= self.count);
        let count = count.min(self.count);
        self.read_pos = (self.read_pos + count) % BUFFER_SIZE;
        self.count -= count;
        self.consumed = self.consumed.wrapping_add(1);
    }

    /// R190-3 FIX: peek like [`Self::peek`] and return the consumer generation
    /// that [`Self::consume_if_generation`] later validates.
    fn peek_with_generation(&self, buf: &mut [u8]) -> (usize, u64) {
        (self.peek(buf), self.consumed)
    }

    /// R190-3 FIX: consume a prefix peeked at `generation` only if no other
    /// reader removed bytes in between. Returns whether the prefix was taken.
    fn consume_if_generation(&mut self, count: usize, generation: u64) -> bool {
        if self.consumed != generation {
            return false;
        }
        self.consume(count);
        true
    }

    /// Drop all buffered input.
    fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
        self.consumed = self.consumed.wrapping_add(1);
    }

    /// Process a PS/2 Set 1 scancode
    ///
    /// Handles key press/release, modifier state, and character conversion.
    fn process_scancode(&mut self, scancode: u8) {
        // Check for key release (bit 7 set)
        let released = scancode & 0x80 != 0;
        let scancode = scancode & 0x7F; // Clear release bit

        // Handle modifier keys
        match scancode {
            // Left/Right Shift
            0x2A | 0x36 => {
                self.shift_pressed = !released;
                return;
            }
            // Left/Right Ctrl
            0x1D => {
                self.ctrl_pressed = !released;
                return;
            }
            // Caps Lock (toggle on press only)
            0x3A => {
                if !released {
                    self.caps_lock = !self.caps_lock;
                }
                return;
            }
            _ => {}
        }

        // Only process key presses, not releases
        if released {
            return;
        }

        // Convert scancode to ASCII
        if let Some(ch) = self.scancode_to_ascii(scancode) {
            // Handle Ctrl+C (SIGINT placeholder - push ETX)
            if self.ctrl_pressed && (ch == b'c' || ch == b'C') {
                if !self.push(0x03) {
                    self.dropped = self.dropped.saturating_add(1);
                }
                return;
            }

            // Handle Ctrl+D (EOF placeholder - push EOT)
            if self.ctrl_pressed && (ch == b'd' || ch == b'D') {
                if !self.push(0x04) {
                    self.dropped = self.dropped.saturating_add(1);
                }
                return;
            }

            if !self.push(ch) {
                // U51-3 FIX: retain explicit loss telemetry for every input
                // path, including control characters, instead of silently
                // discarding a keystroke when the bounded ring is full.
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }

    /// Convert PS/2 Set 1 scancode to ASCII character
    ///
    /// Returns None for non-printable keys (function keys, arrows, etc.)
    fn scancode_to_ascii(&self, scancode: u8) -> Option<u8> {
        // PS/2 Set 1 scancode to ASCII mapping
        // Layout: US QWERTY
        static SCANCODE_ASCII: [u8; 128] = [
            0, 0x1B, // 0x00: None, 0x01: Escape
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
            b'0', // 0x02-0x0B: Number row
            b'-', b'=', 0x08,  // 0x0C: -, 0x0D: =, 0x0E: Backspace
            b'\t', // 0x0F: Tab
            b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o',
            b'p', // 0x10-0x19: QWERTY row
            b'[', b']', b'\n', // 0x1A: [, 0x1B: ], 0x1C: Enter
            0,     // 0x1D: Left Ctrl (modifier)
            b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E-0x26: ASDF row
            b';', b'\'', b'`', // 0x27: ;, 0x28: ', 0x29: `
            0,    // 0x2A: Left Shift (modifier)
            b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2B-0x32: ZXCV row
            b',', b'.', b'/', // 0x33: ,, 0x34: ., 0x35: /
            0,    // 0x36: Right Shift (modifier)
            b'*', // 0x37: Keypad *
            0,    // 0x38: Left Alt
            b' ', // 0x39: Space
            0,    // 0x3A: Caps Lock (modifier)
            // 0x3B-0x44: F1-F10 (non-printable)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x45-0x46: Num Lock, Scroll Lock
            0, 0, // 0x47-0x53: Keypad and arrows (non-printable in this simple impl)
            0, 0, 0, b'-', 0, 0, 0, b'+', 0, 0, 0, 0, 0, // Rest: not mapped
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Shifted characters mapping
        static SCANCODE_ASCII_SHIFT: [u8; 128] = [
            0, 0x1B, // 0x00: None, 0x01: Escape
            b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', // Shifted numbers
            b'_', b'+', 0x08,  // 0x0C: _, 0x0D: +, 0x0E: Backspace
            b'\t', // 0x0F: Tab
            b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', // Shifted QWERTY
            b'{', b'}', b'\n', // 0x1A: {, 0x1B: }, 0x1C: Enter
            0,     // 0x1D: Left Ctrl
            b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', // Shifted ASDF
            b':', b'"', b'~', // 0x27: :, 0x28: ", 0x29: ~
            0,    // 0x2A: Left Shift
            b'|', b'Z', b'X', b'C', b'V', b'B', b'N', b'M', // Shifted ZXCV
            b'<', b'>', b'?', // 0x33: <, 0x34: >, 0x35: ?
            0,    // 0x36: Right Shift
            b'*', // 0x37: Keypad *
            0,    // 0x38: Left Alt
            b' ', // 0x39: Space
            0,    // 0x3A: Caps Lock
            // 0x3B-0x44: F1-F10 (non-printable)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x45-0x46: Num Lock, Scroll Lock
            0, 0, // 0x47-0x53: Keypad and arrows
            0, 0, 0, b'-', 0, 0, 0, b'+', 0, 0, 0, 0, 0,
            // 0x54-0x7F: Rest not mapped (44 elements)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        if scancode as usize >= SCANCODE_ASCII.len() {
            return None;
        }

        // Determine effective shift state (XOR with Caps Lock for letters)
        let use_shift = if self.is_letter_scancode(scancode) {
            self.shift_pressed ^ self.caps_lock
        } else {
            self.shift_pressed
        };

        let ch = if use_shift {
            SCANCODE_ASCII_SHIFT[scancode as usize]
        } else {
            SCANCODE_ASCII[scancode as usize]
        };

        if ch == 0 {
            None
        } else {
            Some(ch)
        }
    }

    /// Check if scancode corresponds to a letter key (affected by Caps Lock)
    fn is_letter_scancode(&self, scancode: u8) -> bool {
        matches!(
            scancode,
            0x10..=0x19 | // Q-P
            0x1E..=0x26 | // A-L
            0x2C..=0x32   // Z-M
        )
    }
}

lazy_static! {
    /// Global keyboard input buffer
    ///
    /// Protected by a spin lock for IRQ-safe access. Access it only through
    /// [`with_buffer`].
    static ref KEYBOARD_BUFFER: Mutex<KeyboardBuffer> = Mutex::new(KeyboardBuffer::new());
}

/// R190-3 FIX: the only way to touch `KEYBOARD_BUFFER`.
///
/// The keyboard and serial IRQ handlers spin on this lock. That is sound on SMP
/// only if every holder runs with IRQs masked on its own CPU and does bounded,
/// non-faulting work. The closure receives only the ring (copying at most
/// `BUFFER_SIZE` kernel bytes). User copyout always runs after the guard is
/// dropped and IRQs are restored (see [`read_buf_with_commit`]). Before this,
/// `read_buf_with_commit` ran `copy_to_user` under the lock, so an IRQ handler
/// on another CPU could spin for as long as a user page fault took.
#[inline]
fn with_buffer<R>(f: impl FnOnce(&mut KeyboardBuffer) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut KEYBOARD_BUFFER.lock()))
}

/// R190-3 FIX: serializes keyboard consumers. IRQ producers never take it.
///
/// Every operation that removes bytes holds this lock outside `with_buffer`
/// (lock order: `KEYBOARD_CONSUMER` before `KEYBOARD_BUFFER`). In
/// [`read_buf_with_commit`] it spans peek, user copyout and consume, so the
/// commit runs exactly once (the VFS read transaction rejects a second
/// commit) and no other reader can take the peeked prefix. Holding a spin lock
/// across a faultable copyout is bounded: every consumer runs in process
/// context, the kernel does not preempt kernel-mode code, and page-fault
/// resolution never sleeps (it retries or fixes up). IRQs stay enabled while
/// the lock is held, and producers never contend for it.
static KEYBOARD_CONSUMER: Mutex<()> = Mutex::new(());

/// Counter for dropped bytes due to buffer full or lock contention
static DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Process a keyboard scancode from the interrupt handler
///
/// This function is called from the keyboard IRQ handler (IRQ 1).
/// It decodes the PS/2 Set 1 scancode and pushes any resulting
/// character into the keyboard buffer.
///
/// Uses a blocking lock, which is safe because every holder goes through
/// [`with_buffer`]: IRQs are masked on the holder's CPU and the critical section
/// is a bounded ring operation with no user copyout (R190-3).
///
/// # Arguments
///
/// * `scancode` - Raw PS/2 Set 1 scancode from port 0x60
#[inline]
pub fn push_scancode(scancode: u8) {
    // U51-4 FIX: IRQ exclusion stays explicit at the API boundary (in
    // `with_buffer`). Hardware enters with IF=0, but callers/tests may invoke
    // this helper from a soft-interrupt path where that is not guaranteed.
    with_buffer(|buffer| buffer.process_scancode(scancode));
}

/// Push a raw ASCII character directly into the keyboard buffer
///
/// This function is called from the serial IRQ handler (IRQ 4)
/// for `-nographic` mode input. The character is already ASCII,
/// no scancode conversion is needed.
///
/// Uses a blocking lock; see [`push_scancode`] for why that is bounded.
///
/// # Arguments
///
/// * `ch` - ASCII character to push
///
/// # Returns
///
/// `true` if character was pushed, `false` if buffer full
#[inline]
pub fn push_char(ch: u8) -> bool {
    let pushed = with_buffer(|buffer| buffer.push(ch));
    if !pushed {
        DROPPED_BYTES.fetch_add(1, Ordering::Relaxed);
    }
    pushed
}

/// Read characters from the keyboard buffer
///
/// Non-blocking: returns immediately with 0 if no input available.
///
/// # Arguments
///
/// * `buf` - Destination buffer for keyboard input
///
/// # Returns
///
/// Number of bytes read (0 if buffer empty)
///
/// # Note
///
/// Interrupts are disabled while holding the buffer lock to prevent
/// deadlock with the keyboard/serial interrupt handlers.
pub fn read_buf(buf: &mut [u8]) -> usize {
    let _consumer = KEYBOARD_CONSUMER.lock();
    with_buffer(|buffer| buffer.read(buf))
}

/// R180-L1: perform copyout before consuming keyboard bytes, so a failed
/// copyout loses nothing.
///
/// R190-3 FIX: the copyout no longer runs under the IRQ-shared buffer lock.
/// The prefix is peeked into the caller's kernel staging buffer, that lock is
/// dropped and IRQs are restored, `commit` copies to user memory (and may
/// fault), and the prefix is then consumed. `KEYBOARD_CONSUMER` is held
/// throughout, so `commit` runs exactly once and the prefix cannot change.
/// The consumer generation re-checks that invariant.
pub fn read_buf_with_commit<E, F>(buf: &mut [u8], commit: F) -> Result<usize, E>
where
    F: FnOnce(&[u8]) -> Result<(), E>,
{
    let _consumer = KEYBOARD_CONSUMER.lock();
    let (count, generation) = with_buffer(|buffer| buffer.peek_with_generation(buf));
    if count == 0 {
        return Ok(0);
    }
    commit(&buf[..count])?;
    let consumed = with_buffer(|buffer| buffer.consume_if_generation(count, generation));
    // Unreachable unless a consumer bypasses KEYBOARD_CONSUMER. Leaving the
    // bytes queued is the non-destructive outcome.
    debug_assert!(consumed, "keyboard consumer bypassed KEYBOARD_CONSUMER");
    Ok(count)
}

/// Read a single character from the keyboard buffer
///
/// Non-blocking: returns None if no input available.
///
/// # Returns
///
/// The next character, or None if buffer empty
pub fn read_char() -> Option<u8> {
    let _consumer = KEYBOARD_CONSUMER.lock();
    with_buffer(|buffer| buffer.pop())
}

/// Check if keyboard input is available
///
/// # Returns
///
/// true if there is at least one character in the buffer
pub fn has_input() -> bool {
    with_buffer(|buffer| !buffer.is_empty())
}

/// Get number of characters available in the buffer
pub fn available() -> usize {
    with_buffer(|buffer| buffer.available())
}

/// Clear all buffered keyboard input
///
/// Useful for flushing stale input after mode switches.
pub fn clear() {
    let _consumer = KEYBOARD_CONSUMER.lock();
    with_buffer(|buffer| buffer.clear())
}

/// Get number of characters dropped due to buffer full or lock contention
///
/// Useful for debugging input issues.
pub fn dropped_count() -> u64 {
    DROPPED_BYTES.load(Ordering::Relaxed)
}

/// Try to pop a character from the buffer (non-blocking).
/// Returns `None` if no character is available.
pub fn try_pop_char() -> Option<u8> {
    read_char()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_is_zero_mutation_until_consume() {
        let mut buffer = KeyboardBuffer::new();
        assert!(buffer.push(b'a'));
        assert!(buffer.push(b'b'));
        assert!(buffer.push(b'c'));

        let initial_pos = buffer.read_pos;
        let initial_count = buffer.count;
        let mut first = [0u8; 2];
        assert_eq!(buffer.peek(&mut first), 2);
        assert_eq!(&first, b"ab");
        assert_eq!(buffer.read_pos, initial_pos);
        assert_eq!(buffer.count, initial_count);

        let mut retry = [0u8; 2];
        assert_eq!(buffer.peek(&mut retry), 2);
        assert_eq!(retry, first);
        buffer.consume(2);
        assert_eq!(buffer.count, 1);
        assert_eq!(buffer.pop(), Some(b'c'));
    }

    #[test]
    fn failed_copyout_preserves_keyboard_prefix() {
        let mut buffer = KeyboardBuffer::new();
        assert!(buffer.push(b'x'));
        assert!(buffer.push(b'y'));
        let mut staging = [0u8; 2];

        // A failed copyout never reaches the consume step.
        let (count, generation) = buffer.peek_with_generation(&mut staging);
        assert_eq!(count, 2);
        assert_eq!(buffer.available(), 2);

        let (retry, retry_generation) = buffer.peek_with_generation(&mut staging);
        assert_eq!((retry, retry_generation), (count, generation));
        assert_eq!(&staging, b"xy");
        assert!(buffer.consume_if_generation(retry, retry_generation));
        assert!(buffer.is_empty());
    }

    #[test]
    fn r190_3_concurrent_consumer_invalidates_peeked_prefix() {
        let mut buffer = KeyboardBuffer::new();
        for &ch in b"abc" {
            assert!(buffer.push(ch));
        }
        let mut first = [0u8; 2];
        let (count, generation) = buffer.peek_with_generation(&mut first);
        assert_eq!(&first, b"ab");

        // A producer append keeps the peeked prefix valid.
        assert!(buffer.push(b'd'));
        // Another reader takes 'a' before the first reader commits.
        assert_eq!(buffer.pop(), Some(b'a'));
        assert!(
            !buffer.consume_if_generation(count, generation),
            "stale prefix must not be consumed"
        );
        assert_eq!(buffer.available(), 3);

        let mut retry = [0u8; 2];
        let (count, generation) = buffer.peek_with_generation(&mut retry);
        assert_eq!(&retry, b"bc");
        assert!(buffer.consume_if_generation(count, generation));
        assert_eq!(buffer.pop(), Some(b'd'));

        let generation = buffer.peek_with_generation(&mut retry).1;
        buffer.clear();
        assert!(!buffer.consume_if_generation(0, generation));
    }
}
