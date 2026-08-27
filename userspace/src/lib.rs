//! Zero-OS User-Space Library
//!
//! Provides system call wrappers and runtime support for user-space programs.
//!
//! ## Modules
//!
//! - `syscall`: Raw system call wrappers
//! - `libc`: Minimal C library functions (string, memory, I/O)
//!
//! ## Usage
//!
//! ```rust
//! #![no_std]
//! #![no_main]
//!
//! use userspace::syscall::{sys_write, sys_exit};
//! use userspace::libc::{puts, gets_s};
//!
//! #[no_mangle]
//! pub extern "C" fn _start() -> ! {
//!     unsafe {
//!         let mut buf = [0u8; 64];
//!         puts(b"Enter your name:\0".as_ptr());
//!         gets_s(buf.as_mut_ptr(), buf.len());
//!         sys_exit(0);
//!     }
//! }
//! ```

#![no_std]

#[cfg(test)]
extern crate std;

pub mod libc;
pub mod shell_parse;
pub mod syscall;

/// Panic handler for user-space programs.
///
/// Attempts to print an error message and exits with code 1.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Try to print panic message to stderr
    unsafe {
        let msg = b"PANIC in user program\n";
        let _ = syscall::sys_write(2, msg.as_ptr(), msg.len() as u64);
        syscall::sys_exit(1);
    }
}
