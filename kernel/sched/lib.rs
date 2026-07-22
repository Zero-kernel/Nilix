#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::double_must_use)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::new_without_default)]
#![allow(clippy::wrong_self_convention)]
#![allow(private_interfaces)]
#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

extern crate kernel_core;
extern crate lazy_static;
extern crate spin;

pub use kernel_core::process;

pub mod cpuset;
pub mod enhanced_scheduler;
pub mod lock_ordering;

// Re-export Scheduler for runtime tests
pub use enhanced_scheduler::Scheduler;

// Re-export lockdep types for use by other modules
pub use lock_ordering::{LockClassKey, LockLevel, LockdepMutex};

// Re-export cpuset types
pub use cpuset::{CpusetError, CpusetId, CpusetNode};

pub fn init() {
    klog_always!("Scheduler module initialized");
    enhanced_scheduler::init();
    // Note: cpuset::init() should be called after CPU enumeration in main.rs
}
