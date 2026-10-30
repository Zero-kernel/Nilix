//! Host-UID admission shared by every thread group of the same principal.
//!
//! Slot identities are pinned by HeapOwner, including owners retained by live
//! allocations after exit. Counters and registry storage are static: neither
//! admission nor reclaim needs to allocate, and PID/user-namespace churn cannot
//! create a fresh budget. A slot is reusable only after its last owner dies.
//!
//! # Policy
//!
//! Admission requires BOTH a thread-group budget and this UID aggregate, then
//! the existing class/global ledgers. Local limits preserve progress between
//! groups; the aggregate prevents fork from multiplying the available pool.
//!
//! | Ceiling | Thread group | Host UID |
//! | --- | ---: | ---: |
//! | All classes, including exec | 1152 KiB | 1280 KiB |
//! | Non-exec | 512 KiB | 768 KiB |
//! | Blocking I/O | 128 KiB | 256 KiB |
//! | Each ordinary class | 3/4 of class | 7/8 of class |
//!
//! Exec retains its 1 MiB class transaction ceiling. UID ceilings are not
//! entitlements: another UID can still compete for the global pool. The normal
//! arena guarantees at least 128 KiB of aggregate headroom outside any one UID.
//!
//! Process construction selects host UID 0 for kernel-created root tasks and
//! otherwise inherits the calling task's stable host principal (65534 for
//! taskless construction). Fork gets a fresh LOCAL owner in that same domain;
//! CLONE_THREAD shares its owner, and exec retains it. Namespace mapping and
//! cgroup migration never mint a new host-UID budget. The current credential API
//! does not implement runtime real-UID changes; any future such transition must
//! explicitly define its resource-principal policy before publishing credentials.
//!
//! Each successful reservation is released from exactly the domains it charged.
//! All rejection paths undo earlier counters. Slot acquisition/reclaim uses a
//! short IRQ-excluded registry lock; reservation/release only use atomic counters.
//! Sixty-four simultaneously pinned UIDs are supported; a new UID fails closed
//! when full, while existing UIDs may still acquire owners. No ancestor-owner
//! chain, heap registry, weak tombstone, or allocation on admission is needed.

use super::{HeapAdmissionError, HeapClass, NsBudgetSnapshot, NsByteBudget, HEAP_CLASS_COUNT};
use core::sync::atomic::AtomicU64;

pub const UID_NON_EXEC_BYTES: usize = 768 * 1024;
pub const UID_HEAP_BYTES: usize = super::OWNER_HEAP_BYTES + 128 * 1024;
pub const UID_BLOCKING_IO_BYTES: usize = 256 * 1024;
const _: () = assert!(UID_HEAP_BYTES + 128 * 1024 <= super::ADMITTED_HEAP_BYTES);
pub(super) const MAX_UID_DOMAINS: usize = 64;

struct Budget {
    total: NsByteBudget,
    non_exec: NsByteBudget,
    blocking_io: NsByteBudget,
    classes: [AtomicU64; HEAP_CLASS_COUNT],
}

impl Budget {
    const fn new() -> Self {
        Self {
            total: NsByteBudget::new(UID_HEAP_BYTES),
            non_exec: NsByteBudget::new(UID_NON_EXEC_BYTES),
            blocking_io: NsByteBudget::new(UID_BLOCKING_IO_BYTES),
            classes: [const { AtomicU64::new(0) }; HEAP_CLASS_COUNT],
        }
    }

    fn release_total(&self, class: HeapClass, bytes: usize) {
        if class != HeapClass::Exec {
            self.non_exec.release(bytes);
        }
        self.total.release(bytes);
    }
}

static BUDGETS: [Budget; MAX_UID_DOMAINS] = [const { Budget::new() }; MAX_UID_DOMAINS];
// (host real UID, live HeapOwner count). No Weak tombstones or heap registry.
static IDENTITIES: spin::Mutex<[Option<(u32, usize)>; MAX_UID_DOMAINS]> =
    spin::Mutex::new([None; MAX_UID_DOMAINS]);

fn with_identities<R>(f: impl FnOnce(&mut [Option<(u32, usize)>; MAX_UID_DOMAINS]) -> R) -> R {
    let access = || f(&mut IDENTITIES.lock());
    #[cfg(feature = "host_harness")]
    {
        access()
    }
    #[cfg(not(feature = "host_harness"))]
    {
        x86_64::instructions::interrupts::without_interrupts(access)
    }
}

pub(super) struct UidLease {
    slot: usize,
    uid: u32,
}

impl UidLease {
    pub fn acquire(uid: u32) -> Result<Self, HeapAdmissionError> {
        with_identities(|ids| {
            let slot = ids
                .iter()
                .position(|id| id.is_some_and(|(key, _)| key == uid))
                .or_else(|| ids.iter().position(Option::is_none))
                .ok_or(HeapAdmissionError::UidDomainLimit)?;
            let count = ids[slot]
                .map_or(0, |(_, count)| count)
                .checked_add(1)
                .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
            ids[slot] = Some((uid, count));
            Ok(Self { slot, uid })
        })
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn snapshot(&self) -> NsBudgetSnapshot {
        BUDGETS[self.slot].total.snapshot()
    }

    pub fn reserve(&self, class: HeapClass, bytes: usize) -> Result<(), HeapAdmissionError> {
        let budget = &BUDGETS[self.slot];
        budget
            .total
            .try_charge(bytes)
            .map_err(|_| HeapAdmissionError::UidLimit)?;
        if class != HeapClass::Exec && budget.non_exec.try_charge(bytes).is_err() {
            budget.total.release(bytes);
            return Err(HeapAdmissionError::UidLimit);
        }
        let limit = if class == HeapClass::Exec {
            class.limit_bytes()
        } else {
            class.limit_bytes() / 8 * 7
        };
        if super::add_reserved(&budget.classes[class.index()], bytes, limit).is_err() {
            budget.release_total(class, bytes);
            return Err(HeapAdmissionError::UidClassLimit);
        }
        if class == HeapClass::BlockingIo && budget.blocking_io.try_charge(bytes).is_err() {
            super::subtract_reserved(&budget.classes[class.index()], bytes)
                .expect("UID class rollback");
            budget.release_total(class, bytes);
            return Err(HeapAdmissionError::BlockingIoUidLimit);
        }
        Ok(())
    }

    pub fn release(&self, class: HeapClass, bytes: usize) {
        let budget = &BUDGETS[self.slot];
        if class == HeapClass::BlockingIo {
            budget.blocking_io.release(bytes);
        }
        super::subtract_reserved(&budget.classes[class.index()], bytes).expect("UID class release");
        budget.release_total(class, bytes);
    }
}

impl Drop for UidLease {
    fn drop(&mut self) {
        with_identities(|ids| {
            let (uid, count) = ids[self.slot].expect("live UID slot");
            assert_eq!(uid, self.uid);
            assert!(count > 0);
            ids[self.slot] = if count == 1 {
                assert_eq!(
                    self.snapshot().used_bytes,
                    0,
                    "UID released with live charges"
                );
                None
            } else {
                Some((uid, count - 1))
            };
        });
    }
}
