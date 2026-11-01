//! Futex (Fast Userspace Mutex) 实现
//!
//! 提供用户空间快速互斥锁的内核支持，包括：
//! - FUTEX_WAIT / FUTEX_WAIT_BITSET: 如果 *uaddr == val，阻塞当前进程（可选超时、
//!   位掩码）；否则返回 EAGAIN
//! - FUTEX_WAKE / FUTEX_WAKE_BITSET: 唤醒最多 n 个位掩码相交的等待者
//! - FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: 唤醒一部分等待者，把其余的移到另一个地址
//! - FUTEX_WAKE_OP: 原子修改第二个字并按条件唤醒两个地址上的等待者
//! - FUTEX_LOCK_PI / FUTEX_LOCK_PI2 / FUTEX_TRYLOCK_PI / FUTEX_UNLOCK_PI: PI
//!   互斥锁（带优先级继承），遵循 Linux 用户字协议（见下）
//! - FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI: 条件变量把等待者重排到 PI 互斥锁
//!
//! 使用全局 FutexTable，以 (address space, vaddr) 为键索引等待桶（GAP-5 futex
//! parity: the key space is the task's `MmState`, see [`FutexSpace`]).
//! 进程退出时自动清理其所有 futex 等待队列。
//!
//! # PI futexes (GAP-5 PI parity)
//!
//! The PI mutex lives in the user word, as on Linux: the owner's TID (the
//! value its `gettid` returns) in bits 0-29, [`FUTEX_OWNER_DIED`] and
//! [`FUTEX_WAITERS`]. User space takes a free lock with a CAS `0 -> tid` and
//! releases it with `tid -> 0`; it enters the kernel only on contention
//! (WAITERS set). The kernel keeps a *PI state* in the bucket ([`PiOwner`] and
//! the PI waiters) only while tasks wait: Linux's `pi_state`. Every kernel
//! update of the word is a fault-safe CAS made under the bucket lock, which
//! serializes it with the other kernel updates of that word. Under a futex
//! lock a word access never resolves a page fault ([`LockedWord`]): the
//! operation drops its locks, faults the word in and retries (review D2-1).
//! A PI state's owner is a user task of the futex's address space; a word
//! naming any other live task is refused with EPERM (R191-1,
//! [`pi_owner_in_space`]).
//!
//! # Plain waiters (GAP-5 futex parity)
//!
//! A FUTEX_WAIT task is attached to two places:
//! - **Physically** to the wait queue of the bucket it called FUTEX_WAIT on (its
//!   *origin*). It sleeps there for the whole wait, and that bucket's
//!   `waiter_count` counts it until its own epilogue. This never changes.
//! - **Logically** through a [`FutexWaiterRecord`] in the `waiters` list of its
//!   *home* bucket, which wakers scan (FIFO, bitset-filtered). A requeue moves
//!   the record to another bucket of the same space; the task stays asleep.
//!
//! A waker removes a record under the home bucket's lock, sets the task's wake
//! mark (one bit per PID, [`set_wake_mark`]) and then readies the task on the
//! origin's queue. The task's arm step reads the mark under that same queue's
//! lock, so a wake that lands before the task is asleep is never lost. Lock
//! order: `FUTEX_TABLE` -> bucket (two buckets: ascending key) -> `WaitQueue`
//! -> `PROCESS_TABLE` -> PCB. Record moves happen with `FUTEX_TABLE` held, so a
//! task that must find its moved record scans its space under that lock.

use alloc::sync::Weak;
use alloc::{
    alloc::{AllocError, Allocator, Global},
    sync::Arc,
};
use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ops::Bound;
use core::ptr::NonNull;
#[cfg(test)]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::process::{self, FutexKey, MmState, Priority, ProcessId};
use kernel_core::request_resched_from_irq;
use kernel_core::syscall::FutexWakeOp;
use mm::{
    arc_charge_bytes, try_reserve_heap, AdmittedDeque, AdmittedMap, HeapCharge, HeapClass,
    PreparedAdmittedDequeCapacity, PreparedAdmittedMapCapacity, RetiredAdmittedDequeCapacity,
    RetiredAdmittedMapCapacity,
};
use spin::Mutex;

use crate::sync::{PrepareWait, WaitOutcome, WaitQueue};

/// FUTEX_WAIT/FUTEX_WAKE match every bit of a bitset waiter.
pub const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;

// Linux robust-futex ABI bits.  The low 30 bits carry the owner TID; bit 30
// is FUTEX_OWNER_DIED and bit 31 is FUTEX_WAITERS.  Keep these constants local
// to the futex implementation so user-provided list data can never be treated
// as a kernel pointer or a wider owner identity.
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// The PI word has (or had) kernel waiters: its owner must unlock through
/// FUTEX_UNLOCK_PI, which hands the lock over.
const FUTEX_WAITERS: u32 = 0x8000_0000;

// A hostile task may publish a cyclic or arbitrarily long robust list.  The
// fixed walk bound is additionally clamped to the per-space futex bucket
// budget below, so exit work cannot exceed the metadata budget already
// admitted for that address space.  CAS retries are bounded independently to prevent a
// racing userspace writer from turning teardown into an unbounded loop.
const MAX_ROBUST_LIST_ENTRIES: usize = 256;
const MAX_ROBUST_CAS_RETRIES: usize = 4;
const ROBUST_LIST_HEAD_SIZE: usize = 24;
const _: () = assert!(MAX_ROBUST_LIST_ENTRIES > 0);
const _: () = assert!(MAX_ROBUST_CAS_RETRIES > 0);

/// Futex 错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexError {
    /// 值不匹配（FUTEX_WAIT 时 *uaddr != val）
    WouldBlock,
    /// 无效的操作码
    InvalidOperation,
    /// 内存访问错误
    Fault,
    /// 无当前进程
    NoProcess,
    /// R39-6 FIX: 等待超时
    TimedOut,
    /// E.4 PI: Robust futex - 锁持有者已退出 (EOWNERDEAD). GAP-5 PI parity:
    /// FUTEX_LOCK_PI no longer returns it; as on Linux the kernel keeps
    /// FUTEX_OWNER_DIED in the word and user space reports EOWNERDEAD.
    OwnerDied,
    /// R171 (F3): 等待期间检测到挂起的 kill —— 以 EINTR 中断 futex 等待。
    Interrupted,
    /// Futex metadata admission/allocation failed -> ENOMEM. This includes the
    /// heap-derived global/per-space bucket budget and fallible queue/PI metadata growth.
    TooManyBuckets,
    /// GAP-5 PI parity: FUTEX_UNLOCK_PI by a task the word does not name -> EPERM.
    /// R191-1: also a PI word naming a task that cannot own the PI state (a
    /// kernel task, or a task of another address space) -> EPERM.
    NotOwner,
    /// GAP-5 PI parity: the PI word already names the locking task (or, for
    /// FUTEX_CMP_REQUEUE_PI, the waiter it acts for) -> EDEADLK.
    Deadlock,
    /// GAP-5 PI review D2-1, internal: a futex-word access made under a futex
    /// lock faulted ([`LockedWord`] never resolves a fault). The operation
    /// drops its locks, faults the word in ([`fault_in_word`]) and starts
    /// over, so this does not reach user space; lib.rs maps it to EFAULT.
    WordFault,
}

/// RF178-8 + P2-A: the table-residency cap is derived from the futex hard-floor
/// slot. RF180-47 additionally charges every physical Arc and map backing through
/// the runtime ledger, so stale owners that outlive table unlink cannot escape
/// aggregate admission merely because `FUTEX_TABLE.len()` decreased.
const FUTEX_HEAP_BUDGET_BYTES: usize = mm::hard_floor_bytes(mm::HeapBudgetId::Futex);
const ARC_HEADER_BYTES: usize = 2 * size_of::<usize>();
type FutexQueueRef = Arc<WaitQueue, FutexArcAllocator>;
type FutexBucketRef = Arc<Mutex<FutexBucket>, FutexArcAllocator>;
#[cfg(test)]
type FutexWeak<T> = Weak<T, FutexArcAllocator>;
const FUTEX_TABLE_SLOT_BYTES: usize = size_of::<(FutexKey, FutexBucketRef)>();
/// A PI waiter occupies one per-bucket wait-deque entry and one PI-map entry;
/// a plain waiter occupies one wait-deque entry, one two-word
/// `FutexWaiterRecord` and possibly one global timeout-registry entry. Eight
/// words cover either set before the whole bucket estimate is doubled for
/// backing growth, alignment, and allocator metadata. A bucket holds at most
/// this many physically attached waiters (`waiter_count`), at most this many
/// PI waiters, and records under [`MAX_FUTEX_RECORDS_PER_BUCKET`].
const MAX_FUTEX_WAITERS_PER_BUCKET: usize = 16;
/// GAP-5 futex parity: a requeue moves records (never the sleeping task) and
/// moves one into a bucket only while that bucket holds fewer than
/// [`MAX_FUTEX_WAITERS_PER_BUCKET`] records, so at most that many are foreign;
/// a waiter attached here adds at most one more, and a direct FUTEX_WAIT is
/// admitted below twice the bound. A requeue-to-mutex broadcast therefore never
/// shuts out the threads that then contend on the mutex with FUTEX_WAIT
/// (Linux has no such bound at all). The extra record headroom is charged to
/// every bucket below.
const MAX_FUTEX_RECORDS_PER_BUCKET: usize = 2 * MAX_FUTEX_WAITERS_PER_BUCKET;
const FUTEX_PER_WAITER_RAW_BYTES: usize = 8 * size_of::<usize>();
const FUTEX_BUCKET_RAW_BYTES: usize = size_of::<Mutex<FutexBucket>>()
    + ARC_HEADER_BYTES
    + size_of::<WaitQueue>()
    + ARC_HEADER_BYTES
    + 2 * FUTEX_TABLE_SLOT_BYTES
    + MAX_FUTEX_WAITERS_PER_BUCKET * FUTEX_PER_WAITER_RAW_BYTES
    + (MAX_FUTEX_RECORDS_PER_BUCKET - MAX_FUTEX_WAITERS_PER_BUCKET)
        * size_of::<FutexWaiterRecord>();
const FUTEX_BUCKET_CHARGE_BYTES: usize = 2 * FUTEX_BUCKET_RAW_BYTES;
const MAX_FUTEX_BUCKETS_GLOBAL: usize = FUTEX_HEAP_BUDGET_BYTES / FUTEX_BUCKET_CHARGE_BYTES;
/// A single key space (address space, see [`FutexSpace`]) receives at most
/// one quarter of the global futex budget. Before GAP-5 futex parity the key
/// space was the TGID; every thread group lives in one address space, so a
/// group's budget did not shrink.
const MAX_FUTEX_BUCKETS_PER_SPACE: usize = MAX_FUTEX_BUCKETS_GLOBAL / 4;

const _: () = assert!(FUTEX_HEAP_BUDGET_BYTES < mm::memory::HEAP_SIZE_BYTES);
const _: () = assert!(FUTEX_BUCKET_CHARGE_BYTES >= FUTEX_BUCKET_RAW_BYTES);
const _: () = assert!(MAX_FUTEX_BUCKETS_PER_SPACE > 0);
const _: () =
    assert!(MAX_FUTEX_BUCKETS_GLOBAL * FUTEX_BUCKET_CHARGE_BYTES <= FUTEX_HEAP_BUDGET_BYTES);

// ============================================================================
// RF180-47 exact-lifetime futex Arc allocator
// ============================================================================

const FUTEX_QUEUE_ARC_MIN_CHARGE: usize = size_of::<WaitQueue>() + 4 * size_of::<usize>();
const FUTEX_BUCKET_ARC_MIN_CHARGE: usize = size_of::<Mutex<FutexBucket>>() + 4 * size_of::<usize>();
const FUTEX_ARC_MIN_CHARGE: usize = if FUTEX_QUEUE_ARC_MIN_CHARGE < FUTEX_BUCKET_ARC_MIN_CHARGE {
    FUTEX_QUEUE_ARC_MIN_CHARGE
} else {
    FUTEX_BUCKET_ARC_MIN_CHARGE
};
const FUTEX_ARC_CHARGE_SLOTS: usize = HeapClass::Futex.limit_bytes() / FUTEX_ARC_MIN_CHARGE + 1;
const _: () = assert!(FUTEX_ARC_CHARGE_SLOTS <= u16::MAX as usize);

struct FutexArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static FUTEX_ARC_CHARGES: Mutex<[Option<FutexArcChargeSlot>; FUTEX_ARC_CHARGE_SLOTS]> =
    Mutex::new([const { None }; FUTEX_ARC_CHARGE_SLOTS]);
static NEXT_FUTEX_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
static FAIL_NEXT_FUTEX_ARC_ALLOCATION: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FAIL_NEXT_FUTEX_GLOBAL_ALLOCATION: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
struct FutexArcAllocator {
    slot: u16,
    generation: u64,
}

impl FutexArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_FUTEX_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = FUTEX_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FutexArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge.take().expect("futex Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("futex Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = FUTEX_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-47 futex Arc allocator slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-47 stale futex Arc allocator generation"),
            None => panic!("RF180-47 futex Arc charge released twice"),
        }
        slot.take()
            .expect("validated futex Arc charge disappeared")
            .charge
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }

    #[cfg(test)]
    fn charge_is_live_for_test(self) -> bool {
        FUTEX_ARC_CHARGES
            .lock()
            .get(self.slot as usize)
            .and_then(Option::as_ref)
            .is_some_and(|entry| entry.generation == self.generation)
    }
}

unsafe impl Allocator for FutexArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        #[cfg(test)]
        if FAIL_NEXT_FUTEX_ARC_ALLOCATION.swap(false, Ordering::AcqRel) {
            return Err(AllocError);
        }

        {
            let mut slots = FUTEX_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        #[cfg(test)]
        let allocation = if FAIL_NEXT_FUTEX_GLOBAL_ALLOCATION.swap(false, Ordering::AcqRel) {
            Err(AllocError)
        } else {
            Global.allocate(layout)
        };
        #[cfg(not(test))]
        let allocation = Global.allocate(layout);

        match allocation {
            Ok(allocation) => Ok(allocation),
            Err(error) => {
                let mut slots = FUTEX_ARC_CHARGES.lock();
                if let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) {
                    if entry.generation == self.generation {
                        entry.allocated = false;
                    }
                }
                Err(error)
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_charge());
    }
}

fn try_new_futex_arc<T>(value: T) -> Result<Arc<T, FutexArcAllocator>, FutexError> {
    let bytes = arc_charge_bytes::<T>().map_err(|_| FutexError::TooManyBuckets)?;
    let reservation =
        try_reserve_heap(HeapClass::Futex, bytes).map_err(|_| FutexError::TooManyBuckets)?;
    let charge = reservation
        .commit()
        .map_err(|_| FutexError::TooManyBuckets)?;
    let allocator = FutexArcAllocator::try_install(charge).map_err(|charge| {
        drop(charge);
        FutexError::TooManyBuckets
    })?;
    match Arc::try_new_in(value, allocator) {
        Ok(owner) => Ok(owner),
        Err(_) => {
            allocator.cancel_failed_allocation();
            Err(FutexError::TooManyBuckets)
        }
    }
}

/// 单个 futex 地址的等待状态
struct FutexBucket {
    /// 等待队列（Arc 包装，避免持有桶锁时阻塞导致死锁）。PI waiters and the plain
    /// waiters that called FUTEX_WAIT on this address sleep here.
    queue: FutexQueueRef,
    /// Tasks physically attached to `queue` (PI waiters and plain waiters whose
    /// origin is this bucket) until their own epilogue; pins the bucket
    /// table-resident. 活跃等待者计数（用于判断是否可以清理）
    waiter_count: usize,
    /// GAP-5 futex parity: plain waiters homed here, FIFO. Wakers take from
    /// this list; a requeue moves entries between lists of one space.
    waiters: AdmittedDeque<FutexWaiterRecord>,
    /// GAP-5 futex parity: keeps the key space's `MmState` allocation (not the
    /// address space itself) alive while this bucket exists, so the space id
    /// in the key cannot be reused by a new address space. `None` only for
    /// test buckets.
    space_pin: Option<Weak<Mutex<MmState>>>,
    /// GAP-5 PI parity: the owner of the PI state (Linux `pi_state->owner`).
    /// Present only while the PI futex at this address has kernel waiters, or
    /// while a waiter the kernel handed the lock to after its owner died has
    /// yet to store its TID in the word ([`PiOwner::fixup`]). The user word,
    /// not this field, says who owns an uncontended PI mutex.
    pi_owner: Option<PiOwner>,
    /// E.4 PI: PI 等待者列表 (pid -> [`PiWaiter`])。The top waiter is the
    /// highest priority (lowest value), oldest first among equals. Holds the
    /// FUTEX_LOCK_PI waiters sleeping on this bucket's queue and the
    /// FUTEX_WAIT_REQUEUE_PI waiters that FUTEX_CMP_REQUEUE_PI moved here
    /// (they keep sleeping on their source bucket's queue).
    pi_waiters: AdmittedMap<ProcessId, PiWaiter>,
    /// Arrival counter for `PiWaiter::seq`.
    pi_seq: u64,
    /// R172-07/08 FIX: tombstone published UNDER the bucket lock atomically with the
    /// bucket's removal from FUTEX_TABLE (see `cleanup_empty_bucket`). `get_or_create_bucket`
    /// drops FUTEX_TABLE before the caller publishes its first state under the bucket lock;
    /// in that gap the reaper (or a thread-group-exit drain) can remove the bucket from the
    /// table while a concurrent thread still holds a stale `Arc` to it. Without the tombstone
    /// that stale `Arc` could be revived (a second LOCK_PI mints a fresh bucket for the same
    /// key -> TWO owners of one PI mutex; or a waiter enqueues on an orphan that no waker can
    /// find). Set-once, never cleared (a tombstoned `Arc` is discarded). A first-publish site
    /// that observes `unlinked` retries `get_or_create_bucket` to obtain the live entry.
    unlinked: bool,
}

impl FutexBucket {
    fn new(queue: FutexQueueRef, space_pin: Option<Weak<Mutex<MmState>>>) -> Self {
        FutexBucket {
            queue,
            waiter_count: 0,
            waiters: AdmittedDeque::new(HeapClass::Futex),
            space_pin,
            pi_owner: None,
            pi_waiters: AdmittedMap::new(HeapClass::Futex),
            pi_seq: 0,
            unlinked: false,
        }
    }

    /// GAP-5 PI parity: whether a plain-waiter record belongs to a
    /// FUTEX_WAIT_REQUEUE_PI waiter. Plain wakes and requeues refuse such a
    /// word (EINVAL), as Linux does.
    fn has_requeue_pi_waiters(&self) -> bool {
        self.waiters.iter().any(FutexWaiterRecord::is_requeue_pi)
    }

    /// The next PI arrival number (FIFO among equal priorities).
    fn next_pi_seq(&mut self) -> u64 {
        let seq = self.pi_seq;
        self.pi_seq = self.pi_seq.wrapping_add(1);
        seq
    }

    /// Drop the PI state once nothing needs it: no PI waiter is left and no
    /// fixup is pending (invariant I-PI1, re-established before every PI
    /// bucket-lock release). Returns the owner it dropped.
    fn settle_pi_state(&mut self) -> Option<ProcessId> {
        match self.pi_owner {
            Some(owner) if self.pi_waiters.is_empty() && !owner.fixup => {
                self.pi_owner = None;
                Some(owner.pid)
            }
            _ => None,
        }
    }

    /// Whether every task of this bucket's address space is gone. Test
    /// buckets (no pin) never are.
    fn space_is_dead(&self) -> bool {
        self.space_pin
            .as_ref()
            .is_some_and(|pin| pin.strong_count() == 0)
    }

    fn record_position(&self, pid: u32) -> Option<usize> {
        self.waiters.iter().position(|record| record.pid == pid)
    }
}

// ============================================================================
// GAP-5 futex parity: key spaces, waiter records and wake marks
// ============================================================================

/// The key space of private futexes: the task's address space.
///
/// `id` is the address of the shared `MmState` allocation. Every task that
/// shares an address space (CLONE_VM, thread or not) holds the same `Arc`;
/// fork and the initial process allocate a new one; exec keeps it (exec runs
/// only when the caller is the space's sole user). Linux keys private futexes
/// by `mm` for the same reason: a CLONE_VM child that is not a thread can wake
/// its parent.
///
/// An address alone could be reused by a later address space. `pin` is a
/// `Weak` reference: bucket creation stores it, which keeps the allocation
/// (not the `MmState` value, and without touching `Arc::strong_count`, which
/// the address-space sharing checks read) from being freed while any bucket
/// of the space exists. A live space's id therefore never equals the id of a
/// bucket left over from a dead one.
#[derive(Clone)]
pub struct FutexSpace {
    id: usize,
    pin: Option<Weak<Mutex<MmState>>>,
}

impl FutexSpace {
    /// The key space of an address space. The caller holds a strong
    /// reference, so the pin taken here is never the allocation's last.
    pub fn of_mm(mm: &Arc<Mutex<MmState>>) -> Self {
        Self {
            id: Self::id_of_mm(mm),
            pin: Some(Arc::downgrade(mm)),
        }
    }

    /// The key space of a task; read it under the task's PCB lock.
    pub fn of_process(proc: &process::Process) -> Self {
        Self::of_mm(&proc.mm)
    }

    /// The space id alone, for lookups that never create a bucket.
    pub fn id_of_mm(mm: &Arc<Mutex<MmState>>) -> usize {
        Arc::as_ptr(mm) as usize
    }

    pub fn id(&self) -> usize {
        self.id
    }

    #[cfg(test)]
    fn unpinned(id: usize) -> Self {
        Self { id, pin: None }
    }
}

/// One plain (non-PI) waiter, queued in its home bucket's `waiters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FutexWaiterRecord {
    /// The address the task called FUTEX_WAIT on. The task sleeps on that
    /// bucket's queue for the whole wait; a requeue moves this record but not
    /// the task, so a waker readies the task through this address.
    origin: usize,
    /// The waiter's PID (at most `PID_MAX`). A task has at most one futex
    /// wait in flight, and a PID is not recycled before
    /// `cleanup_process_futexes` has removed its records (RF180-3), so the
    /// PID identifies the record within its space.
    pid: u32,
    /// The wait's bitset; never 0 for a plain waiter (FUTEX_WAIT_BITSET
    /// refuses an empty mask). [`REQUEUE_PI_RECORD`] marks a
    /// FUTEX_WAIT_REQUEUE_PI waiter instead.
    bitset: u32,
}

/// GAP-5 PI parity: the `bitset` of a FUTEX_WAIT_REQUEUE_PI waiter's record.
/// Such a record never moves between plain buckets (plain requeues refuse
/// it), so the task sleeps on the bucket that holds the record, and `origin`
/// is free to carry the PI futex the waiter expects to be requeued to. An
/// empty mask intersects no wake mask, so bitset wakes skip it by
/// construction; the plain wake and requeue paths refuse the word first.
const REQUEUE_PI_RECORD: u32 = 0;

impl FutexWaiterRecord {
    /// A FUTEX_WAIT_REQUEUE_PI waiter that expects to be requeued to `target`.
    fn requeue_pi(target: usize, pid: u32) -> Self {
        Self {
            origin: target,
            pid,
            bitset: REQUEUE_PI_RECORD,
        }
    }

    fn is_requeue_pi(&self) -> bool {
        self.bitset == REQUEUE_PI_RECORD
    }

    /// The PI futex a FUTEX_WAIT_REQUEUE_PI waiter named as `uaddr2`.
    fn requeue_pi_target(&self) -> Option<usize> {
        self.is_requeue_pi().then_some(self.origin)
    }

    /// The address of the bucket whose queue the task sleeps on, given the
    /// address of the bucket that holds the record.
    fn sleep_origin(&self, home: usize) -> usize {
        if self.is_requeue_pi() {
            home
        } else {
            self.origin
        }
    }
}

// Two words: see FUTEX_PER_WAITER_RAW_BYTES.
const _: () = assert!(size_of::<FutexWaiterRecord>() <= 2 * size_of::<usize>());
const _: () = assert!(process::PID_MAX <= u32::MAX as usize);
const _: () = assert!(process::PID_MAX <= FUTEX_TID_MASK as usize);

/// GAP-5 PI parity: one PI waiter, in `FutexBucket::pi_waiters` (keyed by PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PiWaiter {
    /// The address of the bucket whose queue the task sleeps on: the PI
    /// futex itself for FUTEX_LOCK_PI, the source futex for a
    /// FUTEX_WAIT_REQUEUE_PI waiter that FUTEX_CMP_REQUEUE_PI moved here.
    origin: usize,
    /// Arrival order, for FIFO among equal priorities.
    seq: u64,
    /// The waiter's TID as user space sees it: what a hand-off stores in the
    /// word.
    tid: u32,
    priority: Priority,
}

// A PI waiter is one queue entry (two words) plus one PI-map entry; together
// they fit FUTEX_PER_WAITER_RAW_BYTES.
const _: () = assert!(
    size_of::<(ProcessId, PiWaiter)>() + 2 * size_of::<usize>() <= FUTEX_PER_WAITER_RAW_BYTES
);

/// GAP-5 PI parity: the owner of a bucket's PI state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PiOwner {
    pid: ProcessId,
    /// The owner's TID as the word names it.
    tid: u32,
    /// Set when the kernel handed the lock to `pid` because the previous
    /// owner died (Linux `exit_pi_state_list` + `fixup_pi_state_owner`): the
    /// word still names the dead owner (or carries TID 0 after the robust
    /// walk), and `pid` stores its own TID from its own context when it wakes.
    fixup: bool,
}

/// What the kernel's PI state looks like to a word check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PiStateView {
    owner_tid: u32,
    fixup: bool,
}

impl From<PiOwner> for PiStateView {
    fn from(owner: PiOwner) -> Self {
        Self {
            owner_tid: owner.tid,
            fixup: owner.fixup,
        }
    }
}

type PreparedWaiterList = PreparedAdmittedDequeCapacity<FutexWaiterRecord>;
type RetiredWaiterList = RetiredAdmittedDequeCapacity<FutexWaiterRecord>;

/// One bit per PID: "a waker removed this task's record". A waker sets it
/// under the record's home bucket lock, before it readies the task; the task
/// clears it before publishing a record, reads it under its origin queue's
/// lock when it arms (a wake that came first means: do not sleep), and reads
/// it in its epilogue (a set mark means the wait reports a wake, whatever
/// else ended the sleep, because the waker counted it). A task has at most
/// one futex wait in flight, so one bit per PID is exact.
const FUTEX_WAKE_MARK_WORDS: usize = process::PID_MAX / 64 + 1;
static FUTEX_WAKE_MARKS: [AtomicU64; FUTEX_WAKE_MARK_WORDS] =
    [const { AtomicU64::new(0) }; FUTEX_WAKE_MARK_WORDS];

fn wake_mark(pid: ProcessId) -> Option<(&'static AtomicU64, u64)> {
    FUTEX_WAKE_MARKS
        .get(pid / 64)
        .map(|word| (word, 1u64 << (pid % 64)))
}

fn clear_wake_mark(pid: ProcessId) {
    if let Some((word, bit)) = wake_mark(pid) {
        word.fetch_and(!bit, Ordering::SeqCst);
    }
}

fn set_wake_mark(pid: ProcessId) {
    if let Some((word, bit)) = wake_mark(pid) {
        word.fetch_or(bit, Ordering::SeqCst);
    }
}

fn wake_mark_is_set(pid: ProcessId) -> bool {
    wake_mark(pid).is_some_and(|(word, bit)| word.load(Ordering::SeqCst) & bit != 0)
}

/// GAP-5 PI parity: one more bit per PID, for the outcome of a PI wait. A
/// waker sets the outcome mark before the wake mark, under the lock of the
/// bucket that held the waiter, so a task that sees its wake mark also sees
/// the outcome. The task clears every mark before it publishes itself.
struct PidMarkSet([AtomicU64; FUTEX_WAKE_MARK_WORDS]);

impl PidMarkSet {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; FUTEX_WAKE_MARK_WORDS])
    }

    fn slot(&self, pid: ProcessId) -> Option<(&AtomicU64, u64)> {
        self.0.get(pid / 64).map(|word| (word, 1u64 << (pid % 64)))
    }

    fn set(&self, pid: ProcessId) {
        if let Some((word, bit)) = self.slot(pid) {
            word.fetch_or(bit, Ordering::SeqCst);
        }
    }

    fn clear(&self, pid: ProcessId) {
        if let Some((word, bit)) = self.slot(pid) {
            word.fetch_and(!bit, Ordering::SeqCst);
        }
    }

    fn is_set(&self, pid: ProcessId) -> bool {
        self.slot(pid)
            .is_some_and(|(word, bit)| word.load(Ordering::SeqCst) & bit != 0)
    }
}

/// "The kernel made this task the owner of the PI futex it waited for."
static PI_GRANT_MARKS: PidMarkSet = PidMarkSet::new();
/// "FUTEX_CMP_REQUEUE_PI refused to requeue this task: it owns the PI
/// futex" (Linux wakes it with EDEADLK).
static PI_DEADLOCK_MARKS: PidMarkSet = PidMarkSet::new();

/// Clear every wait-outcome mark of `pid` before it publishes a new wait.
fn clear_wait_marks(pid: ProcessId) {
    clear_wake_mark(pid);
    PI_GRANT_MARKS.clear(pid);
    PI_DEADLOCK_MARKS.clear(pid);
}

/// Wakes of records whose task sleeps on another bucket's queue (it was
/// requeued to the bucket being woken). They run after the home bucket lock
/// is released, because finding the origin bucket takes `FUTEX_TABLE`. One
/// lock hold removes at most one bucket's records, so the batch never fills.
/// GAP-5 PI parity: PI grants and requeue-PI wakes are always deferred, so
/// the caller can give a new owner its donation before it runs. Every wake
/// of one pass (a wake, a requeue with its fallback wakes, a requeue-PI pass
/// with its new owner) takes a record of one source bucket, or is a single
/// grant, so the record bound covers a batch.
const FUTEX_DEFERRED_WAKES: usize = MAX_FUTEX_RECORDS_PER_BUCKET;

struct FutexDeferredWakes {
    entries: [(usize, u32); FUTEX_DEFERRED_WAKES],
    len: usize,
}

impl FutexDeferredWakes {
    const fn new() -> Self {
        Self {
            entries: [(0, 0); FUTEX_DEFERRED_WAKES],
            len: 0,
        }
    }

    fn push(&mut self, origin: usize, pid: u32) {
        // A full batch would mean a bucket held more records than its bound,
        // and dropping the wake would strand a task whose record is gone.
        assert!(
            self.len < self.entries.len(),
            "GAP-5 futex: more deferred wakes than one bucket's record bound"
        );
        self.entries[self.len] = (origin, pid);
        self.len += 1;
    }

    /// Ready each task on its origin bucket's queue. Call with no lock held.
    ///
    /// The origin bucket is table-resident while the task is still asleep
    /// there (its `waiter_count` attachment lasts until the task's own
    /// epilogue). If the lookup finds no bucket, the task has already left.
    /// Every entry's waker set the task's wake mark first, and a wait clears
    /// its mark before it publishes itself and arms; the mark is checked
    /// under the queue lock the arm takes, so a wake that runs after the
    /// task left this wait and started another (on the same word or a newer
    /// bucket for it) does not end the new one.
    fn run(&self, space: usize) {
        for &(origin, pid) in &self.entries[..self.len] {
            let bucket = lookup_bucket((space, origin));
            if let Some(bucket) = bucket {
                let queue = bucket.lock().queue.clone();
                let pid = pid as ProcessId;
                let _ = queue.wake_specific_if(pid, || wake_mark_is_set(pid));
            }
        }
    }
}

fn lookup_bucket(key: FutexKey) -> Option<FutexBucketRef> {
    let table = FUTEX_TABLE.lock();
    table.get(&key).cloned()
}

/// Complete a waker's removal of `record` from `bucket` (whose address is
/// `home`): publish the wake mark, then ready the task on its origin queue,
/// now if that is this bucket's queue, else after the lock is dropped.
fn dequeue_record_locked(
    bucket: &FutexBucket,
    home: usize,
    record: FutexWaiterRecord,
    deferred: &mut FutexDeferredWakes,
) {
    set_wake_mark(record.pid as ProcessId);
    let origin = record.sleep_origin(home);
    if origin == home {
        let _ = bucket.queue.wake_specific(record.pid as ProcessId);
    } else {
        deferred.push(origin, record.pid);
    }
}

/// Under the bucket lock: take up to `max` records, oldest first, whose
/// bitset intersects `mask`, and wake their tasks. Returns how many.
fn take_waiters_locked(
    bucket: &mut FutexBucket,
    home: usize,
    max: usize,
    mask: u32,
    deferred: &mut FutexDeferredWakes,
) -> usize {
    let mut taken = 0;
    let mut index = 0;
    while taken < max {
        let Some(record) = bucket.waiters.get(index).copied() else {
            break;
        };
        if record.bitset & mask == 0 {
            index += 1;
            continue;
        }
        bucket.waiters.remove_retaining_capacity(index);
        dequeue_record_locked(bucket, home, record, deferred);
        taken += 1;
    }
    taken
}

/// Under the source (and target) bucket locks: wake up to `nr_wake` of the
/// source's waiters, oldest first, then move up to `nr_requeue` more to the
/// target, where they keep sleeping and keep their bitsets. A waiter that
/// cannot be moved (no target, a target holding [`MAX_FUTEX_WAITERS_PER_BUCKET`]
/// records, which keeps the rest of [`MAX_FUTEX_RECORDS_PER_BUCKET`] for its
/// direct waiters, or target backing that a racing growth used up) is woken
/// instead: an early return
/// from FUTEX_WAIT is always allowed, a waiter left behind on the source
/// would miss the wake its waker will send to the target. Returns (woken,
/// requeued); fallback wakes count as requeued, as Linux counts every waiter
/// it handled beyond `nr_wake`.
fn requeue_locked(
    source: &mut FutexBucket,
    source_addr: usize,
    mut target: Option<&mut FutexBucket>,
    nr_wake: usize,
    nr_requeue: usize,
    deferred: &mut FutexDeferredWakes,
) -> (usize, usize) {
    let woken = take_waiters_locked(
        source,
        source_addr,
        nr_wake,
        FUTEX_BITSET_MATCH_ANY,
        deferred,
    );
    let mut requeued = 0;
    while requeued < nr_requeue {
        let Some(record) = source.waiters.pop_front_retaining_capacity() else {
            break;
        };
        let moved = match target.as_deref_mut() {
            Some(target) if target.waiters.len() < MAX_FUTEX_WAITERS_PER_BUCKET => {
                target.waiters.push_back_reserved(record).is_ok()
            }
            _ => false,
        };
        if !moved {
            dequeue_record_locked(source, source_addr, record, deferred);
        }
        requeued += 1;
    }
    (woken, requeued)
}

/// Prepare waiter-list backing for `additional` more records outside every
/// lock (RF180-42 pattern); `None` when the current backing suffices.
fn prepare_waiter_list_growth(
    len: usize,
    capacity: usize,
    additional: usize,
) -> Result<Option<PreparedWaiterList>, FutexError> {
    let required = len
        .checked_add(additional)
        .ok_or(FutexError::TooManyBuckets)?;
    if required <= capacity {
        return Ok(None);
    }
    let preferred = capacity
        .max(2)
        .checked_mul(2)
        .ok_or(FutexError::TooManyBuckets)?
        .min(MAX_FUTEX_RECORDS_PER_BUCKET)
        .max(required);
    match PreparedWaiterList::try_new(HeapClass::Futex, preferred) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) if preferred != required => PreparedWaiterList::try_new(HeapClass::Futex, required)
            .map(Some)
            .map_err(|_| FutexError::TooManyBuckets),
        Err(_) => Err(FutexError::TooManyBuckets),
    }
}

/// Under the bucket lock: make room for `additional` records without
/// allocating. The replaced backing is handed back through `retired` and
/// must be dropped after the lock. False: the snapshot raced, prepare again.
fn ensure_waiter_list_capacity(
    list: &mut AdmittedDeque<FutexWaiterRecord>,
    additional: usize,
    prepared: &mut Option<PreparedWaiterList>,
    retired: &mut Option<RetiredWaiterList>,
) -> bool {
    let Some(required) = list.len().checked_add(additional) else {
        return false;
    };
    if required <= list.capacity() {
        return true;
    }
    install_waiter_list_backing(list, prepared, retired);
    required <= list.capacity()
}

/// Under the bucket lock: install `prepared` if it is larger than the
/// current backing. Never allocates or frees.
fn install_waiter_list_backing(
    list: &mut AdmittedDeque<FutexWaiterRecord>,
    prepared: &mut Option<PreparedWaiterList>,
    retired: &mut Option<RetiredWaiterList>,
) {
    let Some(backing) = prepared.take() else {
        return;
    };
    if retired.is_some()
        || backing.class() != list.class()
        || backing.capacity() <= list.capacity()
        || backing.capacity() < list.len()
    {
        *prepared = Some(backing);
        return;
    }
    *retired = Some(
        list.install_prepared_deferred(backing)
            .expect("GAP-5 futex waiter-list prepared-capacity invariant"),
    );
}

/// R172-07/08: bounded retry count for obtaining a live (non-tombstoned) bucket. A
/// pathological reaper could repeatedly unlink between create and lock; the bound makes the
/// loop terminate (the per-site `unlinked` guard is the authoritative correctness check).
const FUTEX_REVALIDATE_RETRIES: usize = 16;

/// RF180-47: serialize detached futex preparation per key space (the address
/// space since GAP-5 futex parity; the TGID before) from the first
/// resident-cap check through publication. The fixed registry is large enough
/// for every space that can own a live bucket; unlike a hashed lock, unrelated
/// spaces never alias. Its mutex protects only slot claim/release and is never
/// held across allocation or a futex/table/queue lock.
const FUTEX_PREPARE_GATE_COUNT: usize = MAX_FUTEX_BUCKETS_GLOBAL;

#[derive(Clone, Copy)]
struct FutexPrepareGateSlot {
    space: usize,
    busy: bool,
}

const EMPTY_FUTEX_PREPARE_GATE: FutexPrepareGateSlot = FutexPrepareGateSlot {
    space: 0,
    busy: false,
};

static FUTEX_PREPARE_GATES: Mutex<[FutexPrepareGateSlot; FUTEX_PREPARE_GATE_COUNT]> =
    Mutex::new([EMPTY_FUTEX_PREPARE_GATE; FUTEX_PREPARE_GATE_COUNT]);

struct FutexPreparePermit {
    gate: usize,
    space: usize,
}

/// One attempt to claim a preparation gate.
enum FutexGateClaim {
    Claimed(FutexPreparePermit),
    /// Another task of the same space is inside its prepare/publish window.
    SameTgidBusy,
    /// Every gate is held by some space.
    RegistryFull,
}

/// GAP-5 slice 4 G4: how long a task yields to a same-TGID sibling that holds
/// the preparation gate before failing with a resource error (timer ticks,
/// about 100 ms at the 1 kHz tick). The holder keeps the gate only across
/// bucket admission and publication, never across the sleep. A deadline rather
/// than a retry count: on an otherwise idle CPU each yield returns at once.
const FUTEX_PREPARE_SIBLING_WAIT_TICKS: u64 = 100;
/// Backstop on yields for contexts whose tick does not advance (the host
/// harness has no timer).
const FUTEX_PREPARE_SIBLING_MAX_YIELDS: usize = 1 << 16;

impl FutexPreparePermit {
    fn try_claim(space: usize) -> FutexGateClaim {
        let mut gates = FUTEX_PREPARE_GATES.lock();
        if gates.iter().any(|slot| slot.busy && slot.space == space) {
            return FutexGateClaim::SameTgidBusy;
        }
        let Some((gate, slot)) = gates.iter_mut().enumerate().find(|(_, slot)| !slot.busy) else {
            return FutexGateClaim::RegistryFull;
        };
        *slot = FutexPrepareGateSlot { space, busy: true };
        FutexGateClaim::Claimed(Self { gate, space })
    }

    fn try_acquire(space: usize) -> Result<Self, FutexError> {
        match Self::try_claim(space) {
            FutexGateClaim::Claimed(permit) => Ok(permit),
            FutexGateClaim::SameTgidBusy | FutexGateClaim::RegistryFull => {
                Err(FutexError::TooManyBuckets)
            }
        }
    }

    /// GAP-5 slice 4 G4: claim the gate from a syscall entry. Without this,
    /// two threads of one group entering FUTEX_WAIT or FUTEX_LOCK_PI together
    /// failed the second with ENOMEM. A busy sibling is waited out by yielding
    /// (bounded); a full registry is still an immediate resource failure.
    /// Callers hold no lock and run in process context with IRQs enabled.
    fn acquire(space: usize) -> Result<Self, FutexError> {
        let deadline = kernel_core::get_ticks().saturating_add(FUTEX_PREPARE_SIBLING_WAIT_TICKS);
        for _ in 0..FUTEX_PREPARE_SIBLING_MAX_YIELDS {
            match Self::try_claim(space) {
                FutexGateClaim::Claimed(permit) => return Ok(permit),
                FutexGateClaim::RegistryFull => return Err(FutexError::TooManyBuckets),
                FutexGateClaim::SameTgidBusy if kernel_core::get_ticks() >= deadline => break,
                FutexGateClaim::SameTgidBusy => kernel_core::force_reschedule(),
            }
        }
        Err(FutexError::TooManyBuckets)
    }

    /// GAP-5 PI review D2-2: [`Self::acquire`] for FUTEX_LOCK_PI, which must
    /// not fail with ENOMEM because siblings keep the gate busy. The gate is
    /// held only across bucket admission, so it is waited for without a
    /// bound, until a kill (EINTR) or `deadline` (ETIMEDOUT). A full
    /// registry is still a resource failure.
    fn acquire_killable(
        space: usize,
        pid: ProcessId,
        deadline: Option<u64>,
    ) -> Result<Self, FutexError> {
        let mut round = 0usize;
        loop {
            match Self::try_claim(space) {
                FutexGateClaim::Claimed(permit) => return Ok(permit),
                FutexGateClaim::RegistryFull => return Err(FutexError::TooManyBuckets),
                FutexGateClaim::SameTgidBusy => pi_pause(pid, deadline, &mut round, false)?,
            }
        }
    }
}

impl Drop for FutexPreparePermit {
    fn drop(&mut self) {
        let mut gates = FUTEX_PREPARE_GATES.lock();
        let slot = gates
            .get_mut(self.gate)
            .expect("RF180-47 futex preparation gate index out of range");
        assert!(
            slot.busy && slot.space == self.space,
            "RF180-47 futex preparation permit identity mismatch"
        );
        *slot = EMPTY_FUTEX_PREPARE_GATE;
    }
}

/// R172-07/08: get-or-create a bucket and ensure the returned `Arc` is not already
/// tombstoned. The per-first-publish-site `unlinked` re-check under the bucket lock is the
/// authoritative guard; this just avoids handing out an obviously-dead `Arc`.
fn get_live_bucket_with(
    mut acquire: impl FnMut() -> Result<FutexBucketRef, FutexError>,
) -> Result<FutexBucketRef, FutexError> {
    for _ in 0..FUTEX_REVALIDATE_RETRIES {
        let bucket = acquire()?;
        if !bucket.lock().unlinked {
            return Ok(bucket);
        }
    }
    Err(FutexError::TooManyBuckets)
}

fn get_or_create_live_bucket(
    key: FutexKey,
    permit: &FutexPreparePermit,
    space_pin: Option<&Weak<Mutex<MmState>>>,
) -> Result<FutexBucketRef, FutexError> {
    get_live_bucket_with(|| get_or_create_bucket_with_permit(key, permit, space_pin))
}

lazy_static::lazy_static! {
    /// 全局 Futex 表
    ///
    /// 以 (key space, vaddr) 为键（key space 是地址空间，见 [`FutexSpace`]），
    /// 管理该地址上的等待队列。
    /// 空队列会在唤醒后被清理，避免内存泄漏。
    static ref FUTEX_TABLE: Mutex<AdmittedMap<FutexKey, FutexBucketRef>> =
        Mutex::new(AdmittedMap::new(HeapClass::Futex));
}

fn prepare_futex_map_growth<K: Ord, V>(
    len: usize,
    capacity: usize,
) -> Result<Option<PreparedAdmittedMapCapacity<K, V>>, FutexError> {
    let required = len.checked_add(1).ok_or(FutexError::TooManyBuckets)?;
    if required <= capacity {
        return Ok(None);
    }
    let preferred = capacity
        .max(4)
        .checked_mul(2)
        .map(|doubled| doubled.max(required))
        .ok_or(FutexError::TooManyBuckets)?;
    match PreparedAdmittedMapCapacity::try_new(HeapClass::Futex, preferred) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) if preferred != required => {
            PreparedAdmittedMapCapacity::try_new(HeapClass::Futex, required)
                .map(Some)
                .map_err(|_| FutexError::TooManyBuckets)
        }
        Err(_) => Err(FutexError::TooManyBuckets),
    }
}

fn reserve_bucket_waiter(bucket: &mut FutexBucket) -> Result<(), FutexError> {
    if bucket.waiter_count >= MAX_FUTEX_WAITERS_PER_BUCKET {
        return Err(FutexError::TooManyBuckets);
    }
    bucket.waiter_count = bucket
        .waiter_count
        .checked_add(1)
        .ok_or(FutexError::TooManyBuckets)?;
    Ok(())
}

type PreparedPiWaiterCapacity = PreparedAdmittedMapCapacity<ProcessId, PiWaiter>;
type RetiredPiWaiterCapacity = RetiredAdmittedMapCapacity<ProcessId, PiWaiter>;

fn remove_pi_waiter_locked(
    bucket: &mut FutexBucket,
    pid: ProcessId,
) -> (Option<PiWaiter>, Option<RetiredPiWaiterCapacity>) {
    let removed = bucket.pi_waiters.remove_retaining_capacity(&pid);
    let retired = bucket.pi_waiters.take_empty_capacity();
    (removed, retired)
}

/// Prepare PI-waiter map backing for `additional` more entries outside every
/// lock (RF180-42 pattern); `None` when the current backing suffices.
fn prepare_pi_waiter_growth(
    len: usize,
    capacity: usize,
    additional: usize,
) -> Result<Option<PreparedPiWaiterCapacity>, FutexError> {
    let required = len
        .checked_add(additional)
        .ok_or(FutexError::TooManyBuckets)?;
    if required <= capacity {
        return Ok(None);
    }
    let preferred = capacity
        .max(2)
        .checked_mul(2)
        .ok_or(FutexError::TooManyBuckets)?
        .min(MAX_FUTEX_WAITERS_PER_BUCKET)
        .max(required);
    match PreparedPiWaiterCapacity::try_new(HeapClass::Futex, preferred) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) if preferred != required => {
            PreparedPiWaiterCapacity::try_new(HeapClass::Futex, required)
                .map(Some)
                .map_err(|_| FutexError::TooManyBuckets)
        }
        Err(_) => Err(FutexError::TooManyBuckets),
    }
}

/// Under the bucket lock: make room for `additional` PI waiters without
/// allocating, installing `prepared` when it is larger than the current
/// backing. The replaced backing goes to `retired`, to be dropped after the
/// lock. False: the snapshot raced, prepare again.
fn ensure_pi_waiter_capacity(
    map: &mut AdmittedMap<ProcessId, PiWaiter>,
    additional: usize,
    prepared: &mut Option<PreparedPiWaiterCapacity>,
    retired: &mut Option<RetiredPiWaiterCapacity>,
) -> bool {
    let Some(required) = map.len().checked_add(additional) else {
        return false;
    };
    if required <= map.capacity() {
        return true;
    }
    let Some(backing) = prepared.take() else {
        return false;
    };
    if retired.is_some()
        || backing.class() != map.class()
        || backing.capacity() <= map.capacity()
        || backing.capacity() < map.len()
    {
        *prepared = Some(backing);
        return false;
    }
    *retired = Some(
        map.install_prepared_deferred(backing)
            .expect("GAP-5 PI waiter prepared-capacity invariant"),
    );
    required <= map.capacity()
}

/// Under the bucket lock: add or refresh `pid` in the PI waiter map. The
/// caller made room with [`ensure_pi_waiter_capacity`].
fn insert_pi_waiter_locked(
    map: &mut AdmittedMap<ProcessId, PiWaiter>,
    pid: ProcessId,
    waiter: PiWaiter,
) -> bool {
    if let Some(existing) = map.get_mut(&pid) {
        *existing = waiter;
        return true;
    }
    map.insert_unique_reserved(pid, waiter).is_ok()
}

/// 从用户空间读取 u32 值
///
/// R24-5 fix: 验证跨页、使用 SMAP 保护和容错 usercopy. GAP-5 PI review D2-1:
/// this access resolves a fault (it may run the copy-on-write or demand-fault
/// paths), so it is made only with no futex lock held; under a futex lock use
/// [`LockedUserWord`].
fn read_user_u32(uaddr: usize) -> Result<u32, FutexError> {
    use kernel_core::usercopy::{read_user_u32_atomic, UserAddr};
    read_user_u32_atomic(UserAddr::new(uaddr)).map_err(|_| FutexError::Fault)
}

/// GAP-5 PI review D2-1: a futex word as a step made under a futex lock
/// (bucket, `FUTEX_TABLE` or wait queue) reads and CASes it. The kernel's
/// [`LockedUserWord`] never resolves a fault, as Linux disables page faults
/// around `get_futex_value_locked` and `cmpxchg_futex_value_locked`: a
/// copy-on-write or not-present word reports [`FutexError::WordFault`]
/// instead of running PT_LOCK, frame allocation and TLB-shootdown waits under
/// the lock. Hosted tests substitute an in-memory word.
trait LockedWord {
    fn read(&self) -> Result<u32, FutexError>;
    /// Ok(true) when the word held `expected` and now holds `new`.
    fn cas(&self, expected: u32, new: u32) -> Result<bool, FutexError>;
}

/// The user word at this address, accessed without resolving faults.
struct LockedUserWord(usize);

impl LockedWord for LockedUserWord {
    fn read(&self) -> Result<u32, FutexError> {
        use kernel_core::usercopy::{read_user_u32_atomic_nofault, UserAddr};
        read_user_u32_atomic_nofault(UserAddr::new(self.0)).map_err(|()| FutexError::WordFault)
    }

    fn cas(&self, expected: u32, new: u32) -> Result<bool, FutexError> {
        use kernel_core::usercopy::{compare_exchange_user_u32_nofault, UserAddr};
        compare_exchange_user_u32_nofault(UserAddr::new(self.0), expected, new)
            .map_err(|()| FutexError::WordFault)
    }
}

/// GAP-5 PI review D2-1 (Linux `fault_in_user_writeable`): with no futex lock
/// held, make the word at `uaddr` present and, for `write`, writable, so the
/// caller's locked step can be retried. The write is a `lock cmpxchg`, which
/// always performs a write cycle: one that does not match (or stores the
/// value it found) breaks copy-on-write without changing the word. A word
/// that still faults is not mapped (EFAULT). A racing fork can make the page
/// copy-on-write again; the caller then faults it in again.
fn fault_in_word(uaddr: usize, write: bool) -> Result<(), FutexError> {
    use kernel_core::usercopy::{compare_exchange_user_u32, read_user_u32_atomic, UserAddr};
    let addr = UserAddr::new(uaddr);
    let faulted_in = if write {
        compare_exchange_user_u32(addr, 0, 0).map(|_| ())
    } else {
        read_user_u32_atomic(addr).map(|_| ())
    };
    faulted_in.map_err(|()| FutexError::Fault)
}

/// Return whether an address/range satisfies the architectural user-space
/// contract used by robust-list accesses.  The no-fault usercopy helpers perform
/// the final page-table access; this predicate rejects null/near-null,
/// non-canonical, overflowing, and misaligned ranges before reaching assembly.
#[inline]
fn robust_user_range(addr: usize, len: usize, alignment: usize) -> bool {
    alignment != 0
        && addr & (alignment - 1) == 0
        && addr >= kernel_core::usercopy::MMAP_MIN_ADDR
        && addr
            .checked_add(len)
            .is_some_and(|end| end < kernel_core::usercopy::USER_SPACE_TOP)
}

/// Compute the futex word for one robust-list node using the Linux ABI's signed
/// `futex_offset`: `futex = entry + futex_offset`.  (glibc normally publishes a
/// negative offset because the lock word precedes the embedded list node.)  All
/// arithmetic is checked; malformed offsets fail closed instead of wrapping
/// into kernel/low memory.
#[inline]
fn robust_futex_address(entry: usize, futex_offset: i64) -> Option<usize> {
    if futex_offset >= 0 {
        entry.checked_add(futex_offset as usize)
    } else {
        let magnitude = futex_offset.checked_neg()? as usize;
        entry.checked_sub(magnitude)
    }
}

/// Pure robust-futex word transition.  A transition is produced only when the
/// low 30 bits identify the exiting thread; all non-owner bits (including the
/// FUTEX_WAITERS bit) are preserved, the owner TID is cleared, and
/// FUTEX_OWNER_DIED is set according to the Linux ABI.
#[inline]
fn robust_owner_transition(word: u32, owner_tids: [u32; 2]) -> Option<u32> {
    let tid = word & FUTEX_TID_MASK;
    // An already-dead word has been published by an earlier exit.  Do not
    // rewrite or wake it again: a recycled TID must never make a stale
    // OWNER_DIED word look like ownership by the new task.
    if tid == 0 || (tid != owner_tids[0] && tid != owner_tids[1]) || (word & FUTEX_OWNER_DIED) != 0
    {
        return None;
    }
    Some((word & !FUTEX_TID_MASK) | FUTEX_OWNER_DIED)
}

/// Atomically mark one robust futex as owner-dead.  A concurrent userspace
/// owner update is retried a small, fixed number of times; a user-memory fault
/// is returned to the caller so the complete robust walk can stop fail-closed.
fn mark_robust_futex(uaddr: usize, owner_tids: [u32; 2]) -> Result<bool, ()> {
    use kernel_core::usercopy::{compare_exchange_user_u32, read_user_u32_atomic, UserAddr};

    if !robust_user_range(uaddr, size_of::<u32>(), align_of::<u32>()) {
        return Err(());
    }

    for _ in 0..MAX_ROBUST_CAS_RETRIES {
        let current = read_user_u32_atomic(UserAddr::new(uaddr))?;
        let Some(updated) = robust_owner_transition(current, owner_tids) else {
            return Ok(false);
        };
        match compare_exchange_user_u32(UserAddr::new(uaddr), current, updated)? {
            true => return Ok(true),
            false => continue,
        }
    }

    // A continuously racing word is not a fault and must not make teardown
    // spin forever.  The owner can only be released if one bounded CAS wins.
    Ok(false)
}

/// Wake one waiter of a robust futex whose word the walk just marked
/// OWNER_DIED, as Linux's `handle_futex_death` does for a non-PI futex.
///
/// GAP-5 PI parity: the walk never queues a PI futex (the list entry's low
/// bit) here, and a word with a kernel PI state is left alone too: the PI
/// exit pass that follows the walk ([`release_pi_states_of`]) hands such a
/// lock to its top waiter, and Linux's `futex_wake` refuses a PI word
/// (EINVAL). Requeue-PI records have an empty bitset, so the wake below
/// skips them. Runs after the walk, with the caller's address space restored
/// and interrupts enabled (see [`exit_robust_futexes_with_tid`]); it reads
/// no user memory.
fn release_robust_futex(space: usize, uaddr: usize) {
    let key = (space, uaddr);
    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    };
    let Some(bucket) = bucket else {
        // It is valid for a robust mutex to have no kernel bucket until a
        // waiter executes FUTEX_WAIT.  The OWNER_DIED bit in user memory is the
        // durable state for that case.
        return;
    };

    let mut deferred = FutexDeferredWakes::new();
    let retired = {
        let mut b = bucket.lock();
        if b.pi_owner.is_some() {
            return;
        }
        // A non-PI robust mutex: wake its oldest FUTEX_WAIT waiter.
        take_waiters_locked(&mut b, uaddr, 1, FUTEX_BITSET_MATCH_ANY, &mut deferred);
        b.waiters.take_empty_capacity()
    };
    drop(retired);
    deferred.run(space);
    cleanup_empty_bucket(key, &bucket);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RobustWalkOutcome {
    Complete,
    Limit,
    Fault,
}

/// The non-PI robust futexes whose OWNER_DIED transition a walk published.
/// Their waiters are woken after the walk ([`release_robust_futex`]), so the
/// walk itself, which runs with interrupts disabled and possibly under the
/// dying task's page tables, takes no futex table or bucket lock. Bounded by
/// the walk budget; never allocates.
struct RobustReleases {
    addrs: [usize; MAX_ROBUST_LIST_ENTRIES],
    len: usize,
}

impl RobustReleases {
    const fn new() -> Self {
        Self {
            addrs: [0; MAX_ROBUST_LIST_ENTRIES],
            len: 0,
        }
    }

    /// Record `uaddr` unless it is a PI futex. The walk visits at most
    /// `MAX_ROBUST_LIST_ENTRIES` nodes in all, so a slot is always free.
    fn push(&mut self, uaddr: usize, pi: bool) {
        if pi {
            return;
        }
        if let Some(slot) = self.addrs.get_mut(self.len) {
            *slot = uaddr;
            self.len += 1;
        }
    }

    fn as_slice(&self) -> &[usize] {
        &self.addrs[..self.len]
    }
}

/// Split a robust-list pointer into the node address and its PI flag. As on
/// Linux (`fetch_robust_entry`), bit 0 of every list pointer (the head's
/// `list`, each node's `next` and `list_op_pending`) marks a PI futex; glibc
/// sets it for PTHREAD_PRIO_INHERIT robust mutexes.
#[inline]
fn robust_entry(raw: usize) -> (usize, bool) {
    (raw & !1, raw & 1 != 0)
}

/// Walk one registered robust-list head.  This function performs no allocation:
/// the visited-node array is fixed at the same bound as the work budget.  A
/// malformed pointer, usercopy fault, or arithmetic overflow aborts the walk;
/// entries already transitioned remain safely marked OWNER_DIED, matching
/// Linux's fail-closed stop-on-fault behavior.
fn walk_robust_list(
    head_addr: usize,
    owner_tids: [u32; 2],
    releases: &mut RobustReleases,
) -> (RobustWalkOutcome, usize) {
    use kernel_core::usercopy::{read_user_u64_atomic, UserAddr};

    if !robust_user_range(head_addr, ROBUST_LIST_HEAD_SIZE, align_of::<usize>()) {
        return (RobustWalkOutcome::Fault, 0);
    }

    let Some(offset_addr) = head_addr.checked_add(size_of::<usize>()) else {
        return (RobustWalkOutcome::Fault, 0);
    };
    let Some(pending_addr) = offset_addr.checked_add(size_of::<usize>()) else {
        return (RobustWalkOutcome::Fault, 0);
    };

    let (list, list_pi) = match read_user_u64_atomic(UserAddr::new(head_addr)) {
        Ok(value) => robust_entry(value as usize),
        Err(_) => return (RobustWalkOutcome::Fault, 0),
    };
    let futex_offset = match read_user_u64_atomic(UserAddr::new(offset_addr)) {
        Ok(value) => value as i64,
        Err(_) => return (RobustWalkOutcome::Fault, 0),
    };
    let (list_op_pending, pending_pi) = match read_user_u64_atomic(UserAddr::new(pending_addr)) {
        Ok(value) => robust_entry(value as usize),
        Err(_) => return (RobustWalkOutcome::Fault, 0),
    };

    // The per-space metadata budget is a hard upper bound even if the global
    // robust-list cap is raised later.  MAX_FUTEX_BUCKETS_PER_SPACE is asserted
    // non-zero at compile time above, so this bound always permits at least one
    // well-formed node on a normally configured kernel.
    let budget = MAX_ROBUST_LIST_ENTRIES.min(MAX_FUTEX_BUCKETS_PER_SPACE);
    // Reserve one bounded work slot for `list_op_pending`.  Otherwise a
    // malicious list containing exactly `budget` linked entries could consume
    // the entire quota and silently skip the in-flight acquisition node that
    // Linux requires us to process separately.
    let pending_slot = if list_op_pending != 0 { 1 } else { 0 };
    let limit = budget.saturating_sub(pending_slot);
    let mut visited = [0usize; MAX_ROBUST_LIST_ENTRIES];
    let mut visited_len = 0usize;
    let mut processed = 0usize;
    let mut entry = list;
    let mut entry_pi = list_pi;
    let mut hit_limit = false;

    while entry != 0 && entry != head_addr {
        // This walk runs with IF=0. A sibling may hold PT_LOCK while waiting
        // for this CPU's ACK; keep shootdowns progressing between nodes.
        mm::tlb_shootdown::handle_shootdown_ipi();
        if visited_len >= limit {
            hit_limit = true;
            break;
        }
        if !robust_user_range(entry, size_of::<usize>(), align_of::<usize>()) {
            return (RobustWalkOutcome::Fault, processed);
        }
        if visited[..visited_len].contains(&entry) {
            // A cyclic list is bounded and already fully visited up to the
            // cycle; stop without repeatedly waking the same futex.
            break;
        }
        visited[visited_len] = entry;
        visited_len += 1;

        let Some(futex_addr) = robust_futex_address(entry, futex_offset) else {
            return (RobustWalkOutcome::Fault, processed);
        };
        if !robust_user_range(futex_addr, size_of::<u32>(), align_of::<u32>()) {
            return (RobustWalkOutcome::Fault, processed);
        }
        match mark_robust_futex(futex_addr, owner_tids) {
            Ok(true) => {
                releases.push(futex_addr, entry_pi);
                processed += 1;
            }
            Ok(false) => {}
            Err(_) => return (RobustWalkOutcome::Fault, processed),
        }

        // Read the link only after processing this node.  A fault here stops
        // the entire walk, but does not undo already-published OWNER_DIED bits.
        (entry, entry_pi) = match read_user_u64_atomic(UserAddr::new(entry)) {
            Ok(next) => robust_entry(next as usize),
            Err(_) => return (RobustWalkOutcome::Fault, processed),
        };
    }

    // Linux separately handles the node involved in an in-flight lock acquire.
    // It may not be linked yet, so process it after the normal list while
    // retaining the same global bound and duplicate suppression.
    let pending_needs_visit = list_op_pending != 0
        && list_op_pending != head_addr
        && !visited[..visited_len].contains(&list_op_pending);
    if pending_needs_visit && visited_len >= budget {
        hit_limit = true;
    } else if pending_needs_visit {
        if !robust_user_range(list_op_pending, size_of::<usize>(), align_of::<usize>()) {
            return (RobustWalkOutcome::Fault, processed);
        }
        let Some(futex_addr) = robust_futex_address(list_op_pending, futex_offset) else {
            return (RobustWalkOutcome::Fault, processed);
        };
        if !robust_user_range(futex_addr, size_of::<u32>(), align_of::<u32>()) {
            return (RobustWalkOutcome::Fault, processed);
        }
        match mark_robust_futex(futex_addr, owner_tids) {
            Ok(true) => {
                releases.push(futex_addr, pending_pi);
                processed += 1;
            }
            Ok(false) => {}
            Err(_) => return (RobustWalkOutcome::Fault, processed),
        }
    }

    let outcome = if hit_limit {
        RobustWalkOutcome::Limit
    } else {
        RobustWalkOutcome::Complete
    };
    (outcome, processed)
}

/// Exit-time robust-futex cleanup entry point with an explicit owner TID.  The
/// process subsystem captures the namespace-local TID before it detaches the
/// PCB's PID-namespace chain, then invokes this callback immediately after
/// publishing `Zombie` while the address space is still retained.
///
/// GAP-5 PI parity: after the robust walk (which publishes OWNER_DIED in the
/// words of the robust mutexes the task held), every PI futex the dying task
/// owns in the kernel's view is handed to its top waiter, as Linux's
/// `futex_cleanup` runs `exit_robust_list` and then `exit_pi_state_list`.
/// This runs whether or not the task registered a robust list, and before
/// `teardown_done`, which a FUTEX_LOCK_PI caller waits for when the word
/// names an exiting owner.
///
/// GAP-5 PI review D2-1: the release passes spin on `FUTEX_TABLE`, bucket,
/// wait-queue and PCB locks. They run with interrupts enabled on every exit
/// path: `terminate_self_and_halt` enables them before the teardown (an
/// exception exit arrives with IF=0) and the deferred-kill drain runs in
/// process context. With IF=0 this CPU could not acknowledge a TLB shootdown
/// that the holder of one of those locks, directly or through another lock,
/// waits for. No futex lock is held across a resolving page fault.
pub(crate) fn exit_robust_futexes_with_tid(
    pid: ProcessId,
    tgid: ProcessId,
    generation: u64,
    owner_tid: ProcessId,
) {
    let process = match process::get_process(pid) {
        Some(process) => process,
        None => return,
    };
    let (memory_space, space, head_addr, head_len) = {
        let proc = process.lock();
        if proc.generation != generation
            || proc.tgid != tgid
            || proc.state != process::ProcessState::Zombie
        {
            return;
        }
        (
            proc.memory_space,
            // GAP-5 futex parity: the futex key space of the dying task.
            FutexSpace::id_of_mm(&proc.mm),
            proc.robust_list_head as usize,
            proc.robust_list_len,
        )
    };
    drop(process);

    // A CR3 root must be page aligned.  Reject malformed PCB state rather
    // than rounding it into a potentially unrelated address space.
    let walkable = memory_space != 0
        && memory_space & 0xfff == 0
        && head_addr != 0
        && head_len == ROBUST_LIST_HEAD_SIZE;
    if walkable {
        walk_dying_robust_list(pid, memory_space, space, head_addr, owner_tid);
    }

    release_pi_states_of(pid);
}

/// Walk the dying task's robust list in its own address space.
fn walk_dying_robust_list(
    pid: ProcessId,
    memory_space: usize,
    space: usize,
    head_addr: usize,
    owner_tid: ProcessId,
) {
    // Robust futex words contain the TID as returned by `gettid()` in the
    // owning PID namespace (`task_pid_vnr()` in Linux), not the kernel's
    // global PID.  Matching the global PID as a second candidate would be
    // unsafe in nested PID namespaces: it can collide with a different live
    // thread's namespace-local TID and spuriously mark that mutex dead.
    let owner_tids = [(owner_tid as u64 & FUTEX_TID_MASK as u64) as u32, 0];
    let mut releases = RobustReleases::new();
    let (outcome, processed) = unsafe {
        use x86_64::structures::paging::PhysFrame;
        use x86_64::PhysAddr;

        let Some(target_phys) = PhysAddr::try_new(memory_space as u64).ok() else {
            return;
        };
        let target_frame = PhysFrame::containing_address(target_phys);
        mm::tlb_shootdown::with_temporary_address_space(target_frame, || {
            walk_robust_list(head_addr, owner_tids, &mut releases)
        })
    };

    // Wake the marked non-PI futexes' waiters now that interrupts are on and
    // the caller's address space is back (no futex lock was taken inside).
    for &uaddr in releases.as_slice() {
        release_robust_futex(space, uaddr);
    }

    #[cfg(debug_assertions)]
    match outcome {
        RobustWalkOutcome::Complete => {}
        RobustWalkOutcome::Limit => kprintln!(
            "[FUTEX] robust-list walk capped for pid {} (processed {})",
            pid,
            processed
        ),
        RobustWalkOutcome::Fault => kprintln!(
            "[FUTEX] robust-list walk stopped on user fault for pid {} (processed {})",
            pid,
            processed
        ),
    }
    #[cfg(not(debug_assertions))]
    let _ = (pid, outcome, processed);
}

/// Public compatibility wrapper for callers that still provide only the
/// generation-bound PID/TGID identity.  Normal exit uses the explicit-TID
/// callback above; this wrapper falls back to the global PID when the namespace
/// chain is unavailable (for example, a diagnostic invocation).
pub fn exit_robust_futexes(pid: ProcessId, tgid: ProcessId, generation: u64) {
    let owner_tid = process::get_process(pid)
        .and_then(|proc| {
            let proc = proc.lock();
            kernel_core::pid_in_owning_namespace(&proc.pid_ns_chain)
        })
        .unwrap_or(pid);
    exit_robust_futexes_with_tid(pid, tgid, generation, owner_tid);
}

/// FUTEX_WAIT / FUTEX_WAIT_BITSET 操作
///
/// 如果 *uaddr == expected，则阻塞当前进程；否则返回 WouldBlock。
///
/// # Arguments
///
/// * `space` - futex key space（调用者的地址空间，见 [`FutexSpace`]）
/// * `uaddr` - 用户空间 futex 地址（已验证）
/// * `expected` - 期望的值
/// * `current_value` - 当前从用户空间读取的值（调用者负责验证和读取）
/// * `timeout_ns` - R39-6 FIX: 可选超时时间（纳秒），None 表示无限等待
/// * `bitset` - 等待者的位掩码（FUTEX_WAIT 为 MATCH_ANY），不能为 0
///
/// # Returns
///
/// 被唤醒后返回 Ok(0)，值不匹配返回 WouldBlock，超时返回 TimedOut。A waiter
/// whose record a waker took reports the wake even when a timeout or signal
/// also ended its sleep, because the waker counted it (Linux does the same).
pub fn futex_wait(
    space: &FutexSpace,
    uaddr: usize,
    expected: u32,
    current_value: u32,
    timeout_ns: Option<u64>,
    bitset: u32,
) -> Result<usize, FutexError> {
    if bitset == 0 {
        return Err(FutexError::InvalidOperation);
    }
    // 值不匹配，立即返回
    if current_value != expected {
        return Err(FutexError::WouldBlock);
    }
    let pid = process::current_pid().ok_or(FutexError::NoProcess)?;
    if pid > process::PID_MAX {
        return Err(FutexError::NoProcess);
    }
    let record = FutexWaiterRecord {
        origin: uaddr,
        pid: pid as u32,
        bitset,
    };

    // R37-2 / GAP-5 futex parity: the key is scoped by the address space, so
    // every task sharing it (CLONE_THREAD siblings and CLONE_VM children)
    // can wake each other.
    let key = (space.id, uaddr);
    let prepare_permit = FutexPreparePermit::acquire(space.id)?;

    // A mark left by an earlier wait of this task must not end this one. It
    // is cleared before any waker can see the record published below.
    clear_wake_mark(pid);
    let (bucket, queue) = publish_plain_waiter(key, space, record, expected, &prepare_permit)?;

    // Sleep on the origin queue unless a waker has already taken the record.
    // The mark is read under the queue's `waiters` lock, which a waker's
    // `wake_specific` takes after setting it: either this check sees the
    // mark, or the waker finds the task queued.
    let prepared = queue.try_prepare_with_timeout_after(timeout_ns, || {
        if wake_mark_is_set(pid) {
            Err(())
        } else {
            Ok(())
        }
    });
    drop(prepare_permit);
    let outcome = match prepared {
        Ok(Ok(PrepareWait::Armed(ticket))) => queue.finish_prepared(ticket),
        Ok(Ok(PrepareWait::Immediate(outcome))) => outcome,
        Ok(Err(())) => WaitOutcome::Woken,
        Err(_) => WaitOutcome::ResourceExhausted,
    };

    if finish_plain_wait(key, &bucket, &queue, pid) {
        return Ok(0);
    }

    // R39-6 FIX: 根据等待结果返回. A sleep that ended without a waker (a
    // spurious return) reports 0, which FUTEX_WAIT allows.
    match outcome {
        WaitOutcome::Woken => Ok(0),
        WaitOutcome::TimedOut => Err(FutexError::TimedOut),
        WaitOutcome::Closed | WaitOutcome::NoProcess => Err(FutexError::NoProcess),
        // R171-F3: a pending kill interrupted the futex wait (-> EINTR).
        WaitOutcome::Interrupted => Err(FutexError::Interrupted),
        WaitOutcome::ResourceExhausted => Err(FutexError::TooManyBuckets),
    }
}

enum PlainPublish {
    Published(FutexQueueRef),
    Retry,
    /// GAP-5 PI review D2-1: the word faulted under the bucket lock.
    FaultIn,
    Failed(FutexError),
}

/// Attach the caller to the bucket of `key` and queue its record. The futex
/// word is read again under the bucket lock: every waker and requeue holds
/// that lock while it scans the records, so a waker either finds the record
/// or stored its new value before this read (P2-B / RF178-8 lost-wake rule,
/// the Linux hash-bucket rule). That read does not resolve a fault (review
/// D2-1): the word is faulted in with the lock dropped and the step retried.
fn publish_plain_waiter(
    key: FutexKey,
    space: &FutexSpace,
    record: FutexWaiterRecord,
    expected: u32,
    permit: &FutexPreparePermit,
) -> Result<(FutexBucketRef, FutexQueueRef), FutexError> {
    let mut last = None;
    let mut faults = 0usize;
    let mut retries = 0usize;
    while retries < FUTEX_REVALIDATE_RETRIES {
        let bucket = get_or_create_live_bucket(key, permit, space.pin.as_ref())?;
        let (len, capacity) = {
            let b = bucket.lock();
            (b.waiters.len(), b.waiters.capacity())
        };
        let mut prepared = match prepare_waiter_list_growth(len, capacity, 1) {
            Ok(prepared) => prepared,
            Err(error) => {
                cleanup_empty_bucket(key, &bucket);
                return Err(error);
            }
        };
        let mut retired = None;
        let outcome = {
            let mut b = bucket.lock();
            if b.unlinked {
                // R172-07/08: a reaper unlinked it after the lookup.
                PlainPublish::Retry
            } else if !direct_waiter_fits(&b) {
                PlainPublish::Failed(FutexError::TooManyBuckets)
            } else if !ensure_waiter_list_capacity(&mut b.waiters, 1, &mut prepared, &mut retired) {
                PlainPublish::Retry
            } else {
                match LockedUserWord(key.1).read() {
                    Ok(value) if value == expected => match reserve_bucket_waiter(&mut b) {
                        // R172-07/08: waiter_count >= 1 now pins the bucket
                        // table-resident until this task's epilogue.
                        Ok(()) => {
                            b.waiters
                                .push_back_reserved(record)
                                .expect("GAP-5 futex waiter-list capacity vanished under lock");
                            PlainPublish::Published(b.queue.clone())
                        }
                        Err(error) => PlainPublish::Failed(error),
                    },
                    Ok(_) => PlainPublish::Failed(FutexError::WouldBlock),
                    Err(FutexError::WordFault) => PlainPublish::FaultIn,
                    Err(error) => PlainPublish::Failed(error),
                }
            }
        };
        // Neither unused nor replaced backing is freed under the bucket lock.
        drop(retired);
        drop(prepared);
        match outcome {
            PlainPublish::Published(queue) => return Ok((bucket, queue)),
            PlainPublish::Retry => {
                retries += 1;
                last = Some(bucket);
            }
            // A word that faults again after each fault-in is being unmapped
            // and remapped under the caller: give up with EFAULT eventually.
            PlainPublish::FaultIn if faults < FUTEX_REVALIDATE_RETRIES => {
                faults += 1;
                cleanup_empty_bucket(key, &bucket);
                fault_in_word(key.1, false)?;
            }
            PlainPublish::FaultIn => {
                cleanup_empty_bucket(key, &bucket);
                return Err(FutexError::Fault);
            }
            PlainPublish::Failed(error) => {
                cleanup_empty_bucket(key, &bucket);
                return Err(error);
            }
        }
    }
    if let Some(bucket) = last {
        cleanup_empty_bucket(key, &bucket);
    }
    // R181-1: retry exhaustion is a resource failure (ENOMEM), not EAGAIN.
    Err(FutexError::TooManyBuckets)
}

/// Whether a task may attach to `bucket` and queue its own record there
/// (FUTEX_WAIT, FUTEX_WAIT_REQUEUE_PI). Records requeued from other words fill
/// at most [`MAX_FUTEX_WAITERS_PER_BUCKET`] slots and the attached tasks' own
/// records fewer than that, so this fails only at the attachment bound.
fn direct_waiter_fits(bucket: &FutexBucket) -> bool {
    bucket.waiter_count < MAX_FUTEX_WAITERS_PER_BUCKET
        && bucket.waiters.len() < MAX_FUTEX_RECORDS_PER_BUCKET
}

/// Epilogue of a plain wait: leave the origin queue and the origin bucket,
/// then remove the record from whichever bucket holds it now, unless a waker
/// already took it. Returns true when a waker took it.
fn finish_plain_wait(
    key: FutexKey,
    bucket: &FutexBucketRef,
    queue: &FutexQueueRef,
    pid: ProcessId,
) -> bool {
    enum Record {
        TakenByWaker,
        RemovedHere,
        Elsewhere,
    }

    // A sleep that a timeout, a signal or nothing at all ended can leave this
    // task's entry on the origin queue; it must not absorb a later wake.
    let _ = queue.cancel_wait();

    let record_pid = pid as u32;
    let record = {
        let mut b = bucket.lock();
        b.waiter_count = b.waiter_count.saturating_sub(1);
        if wake_mark_is_set(pid) {
            Record::TakenByWaker
        } else if let Some(index) = b.record_position(record_pid) {
            b.waiters.remove_retaining_capacity(index);
            Record::RemovedHere
        } else {
            Record::Elsewhere
        }
    };
    let mut moved_to = None;
    let taken_by_waker = match record {
        Record::TakenByWaker => true,
        Record::RemovedHere => false,
        // A requeue moved the record, and a waker may have taken it there.
        Record::Elsewhere if wake_mark_is_set(pid) => true,
        Record::Elsewhere => {
            moved_to = take_moved_record(key.0, record_pid);
            // Not in any bucket of the space: a waker removed it before the
            // scan locked its bucket, and set the mark under that lock.
            debug_assert!(moved_to.is_some() || wake_mark_is_set(pid));
            moved_to.is_none()
        }
    };
    cleanup_empty_bucket(key, bucket);
    if let Some((home_key, home)) = moved_to {
        cleanup_empty_bucket(home_key, &home);
    }
    taken_by_waker
}

/// Find and remove `pid`'s record in any bucket of `space`. A requeue moves
/// records only while it holds `FUTEX_TABLE`, so this scan, under the same
/// lock, cannot miss a record that is being moved.
fn take_moved_record(space: usize, pid: u32) -> Option<(FutexKey, FutexBucketRef)> {
    let table = FUTEX_TABLE.lock();
    for (key, bucket) in table.range((space, 0)..=(space, usize::MAX)) {
        let mut b = bucket.lock();
        if let Some(index) = b.record_position(pid) {
            b.waiters.remove_retaining_capacity(index);
            drop(b);
            return Some((*key, bucket.clone()));
        }
    }
    None
}

/// FUTEX_WAKE 操作
///
/// 唤醒最多 n 个在 uaddr 上等待的进程（任意位掩码）。
///
/// # Arguments
///
/// * `space` - futex key-space id（见 [`FutexSpace`]）
/// * `uaddr` - 用户空间 futex 地址
/// * `n` - 最多唤醒的进程数量
///
/// # Returns
///
/// 实际唤醒的进程数量 (0 when the word is a PI futex or has requeue-PI
/// waiters, which a plain wake refuses).
pub fn futex_wake(space: usize, uaddr: usize, n: usize) -> usize {
    wake_key((space, uaddr), n, FUTEX_BITSET_MATCH_ANY).unwrap_or(0)
}

/// FUTEX_WAKE_BITSET: wake up to `n` waiters of `uaddr` whose bitset
/// intersects `mask`, oldest first.
pub fn futex_wake_bitset(
    space: usize,
    uaddr: usize,
    n: usize,
    mask: u32,
) -> Result<usize, FutexError> {
    if mask == 0 {
        return Err(FutexError::InvalidOperation);
    }
    wake_key((space, uaddr), n, mask)
}

/// GAP-5 PI parity: a plain wake or requeue refuses (EINVAL) a word with PI
/// waiters or FUTEX_WAIT_REQUEUE_PI waiters, as Linux's `futex_wake` and
/// `futex_requeue` do when they meet such a waiter. Unlike Linux, the
/// refusal comes before any waiter of the word is woken or moved.
fn plain_op_refused(bucket: &FutexBucket) -> bool {
    !bucket.pi_waiters.is_empty() || bucket.has_requeue_pi_waiters()
}

fn wake_key(key: FutexKey, n: usize, mask: u32) -> Result<usize, FutexError> {
    if n == 0 {
        return Ok(0);
    }
    let Some(bucket) = lookup_bucket(key) else {
        return Ok(0);
    };
    let mut deferred = FutexDeferredWakes::new();
    let (woken, retired) = {
        let mut b = bucket.lock();
        let woken = if plain_op_refused(&b) {
            Err(FutexError::InvalidOperation)
        } else {
            Ok(take_waiters_locked(&mut b, key.1, n, mask, &mut deferred))
        };
        (woken, b.waiters.take_empty_capacity())
    };
    drop(retired);
    deferred.run(key.0);
    cleanup_empty_bucket(key, &bucket);
    woken
}

/// FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake up to `nr_wake` waiters of
/// `uaddr1`, then move up to `nr_requeue` more onto `uaddr2`, where they keep
/// sleeping until a wake of `uaddr2`, a timeout or a signal. With `compare`,
/// `*uaddr1` must still equal it when checked under the bucket lock that
/// waiters queue under (else WouldBlock, EAGAIN). Returns woken plus moved.
pub fn futex_requeue(
    space: &FutexSpace,
    uaddr1: usize,
    uaddr2: usize,
    nr_wake: usize,
    nr_requeue: usize,
    compare: Option<u32>,
) -> Result<usize, FutexError> {
    enum Step {
        Done(Result<usize, FutexError>),
        NoSource,
        Retry,
    }

    let key1: FutexKey = (space.id, uaddr1);
    let key2: FutexKey = (space.id, uaddr2);
    if key1 == key2 {
        return requeue_same_key(key1, nr_wake, nr_requeue, compare);
    }

    let mut attempt = 0;
    let mut faults = 0;
    loop {
        // Phase 1, no lock held across allocation: when the snapshot says
        // waiters will move, make sure the target bucket and room for them
        // exist. Failure is not an error: unmoved waiters are woken instead.
        let queued = lookup_bucket(key1).map_or(0, |bucket| bucket.lock().waiters.len());
        let wanted = nr_requeue
            .min(queued.saturating_sub(nr_wake))
            .min(MAX_FUTEX_WAITERS_PER_BUCKET);
        let (created, mut prepared) = if wanted > 0 {
            prepare_requeue_target(space, key2, wanted)
        } else {
            (None, None)
        };

        // Phase 2: FUTEX_TABLE is held across the move so a waiter looking
        // for its moved record (take_moved_record) never misses it.
        let mut retired = None;
        let mut deferred = FutexDeferredWakes::new();
        let source: Option<FutexBucketRef>;
        let target: Option<FutexBucketRef>;
        let step = {
            let table = FUTEX_TABLE.lock();
            source = table.get(&key1).cloned();
            target = table.get(&key2).cloned();
            match source.as_ref() {
                None => Step::NoSource,
                // The target created above was reaped before the table lock
                // was taken: create it again instead of waking the waiters.
                Some(_) if created.is_some() && target.is_none() => Step::Retry,
                Some(source) => match requeue_pass(
                    key1,
                    key2,
                    source,
                    target.as_ref(),
                    nr_wake,
                    nr_requeue,
                    wanted,
                    compare,
                    &mut prepared,
                    &mut retired,
                    &mut deferred,
                ) {
                    Ok(None) => Step::Retry,
                    Ok(Some(count)) => Step::Done(Ok(count)),
                    Err(error) => Step::Done(Err(error)),
                },
            }
        };
        drop(retired);
        drop(prepared);
        drop(created);
        let result = match step {
            Step::Retry if attempt < FUTEX_REVALIDATE_RETRIES => {
                attempt += 1;
                continue;
            }
            Step::Retry => Err(FutexError::TooManyBuckets),
            Step::NoSource => check_requeue_compare_unlocked(uaddr1, compare).map(|()| 0),
            // GAP-5 PI review D2-1: the compare faulted under the locks
            // (nothing moved). Fault the word in and start over.
            Step::Done(Err(FutexError::WordFault)) if faults < FUTEX_REVALIDATE_RETRIES => {
                faults += 1;
                if let Some(source) = source.as_ref() {
                    cleanup_empty_bucket(key1, source);
                }
                if let Some(target) = target.as_ref() {
                    cleanup_empty_bucket(key2, target);
                }
                fault_in_word(uaddr1, false)?;
                continue;
            }
            Step::Done(Err(FutexError::WordFault)) => Err(FutexError::Fault),
            Step::Done(result) => result,
        };
        deferred.run(space.id);
        if let Some(source) = source.as_ref() {
            cleanup_empty_bucket(key1, source);
        }
        if let Some(target) = target.as_ref() {
            cleanup_empty_bucket(key2, target);
        }
        return result;
    }
}

/// Get (or create) the requeue target and backing for `wanted` more records,
/// as many as a requeue may move there (below [`MAX_FUTEX_WAITERS_PER_BUCKET`]
/// records; the rest are woken).
fn prepare_requeue_target(
    space: &FutexSpace,
    key: FutexKey,
    wanted: usize,
) -> (Option<FutexBucketRef>, Option<PreparedWaiterList>) {
    let Ok(permit) = FutexPreparePermit::acquire(space.id) else {
        return (None, None);
    };
    let Ok(target) = get_or_create_live_bucket(key, &permit, space.pin.as_ref()) else {
        return (None, None);
    };
    drop(permit);
    let (len, capacity) = {
        let b = target.lock();
        (b.waiters.len(), b.waiters.capacity())
    };
    let movable = wanted.min(MAX_FUTEX_WAITERS_PER_BUCKET.saturating_sub(len));
    let prepared = if movable == 0 {
        None
    } else {
        prepare_waiter_list_growth(len, capacity, movable)
            .ok()
            .flatten()
    };
    (Some(target), prepared)
}

/// The locked part of a requeue between two distinct keys. The caller holds
/// `FUTEX_TABLE`; the two bucket locks are taken in ascending key order.
/// `Ok(None)` requests fresh preparation without changing any waiter.
#[allow(clippy::too_many_arguments)]
fn requeue_pass(
    key1: FutexKey,
    key2: FutexKey,
    source: &FutexBucketRef,
    target: Option<&FutexBucketRef>,
    nr_wake: usize,
    nr_requeue: usize,
    prepared_movers: usize,
    compare: Option<u32>,
    prepared: &mut Option<PreparedWaiterList>,
    retired: &mut Option<RetiredWaiterList>,
    deferred: &mut FutexDeferredWakes,
) -> Result<Option<usize>, FutexError> {
    let (mut src, mut tgt) = match target {
        Some(target) if key2 < key1 => {
            let tgt = target.lock();
            (source.lock(), Some(tgt))
        }
        Some(target) => {
            let src = source.lock();
            (src, Some(target.lock()))
        }
        None => (source.lock(), None),
    };
    check_requeue_compare(key1.1, compare)?;
    if plain_op_refused(&src) {
        return Err(FutexError::InvalidOperation);
    }
    // A waiter may publish after phase 1 observed an empty/short source.
    // Retry before waking or moving anyone: lack of preparation for these
    // new arrivals is not allocation pressure and must not spuriously wake
    // a waiter that the caller asked to move to the target.
    let movers = nr_requeue.min(src.waiters.len().saturating_sub(nr_wake));
    if movers > prepared_movers {
        return Ok(None);
    }
    if let Some(tgt) = tgt.as_mut() {
        install_waiter_list_backing(&mut tgt.waiters, prepared, retired);
    }
    let (woken, requeued) = requeue_locked(
        &mut src,
        key1.1,
        tgt.as_deref_mut(),
        nr_wake,
        nr_requeue,
        deferred,
    );
    Ok(Some(woken + requeued))
}

/// Requeue onto the same futex: Linux counts the waiters it would move, and
/// they stay queued where they are.
fn requeue_same_key(
    key: FutexKey,
    nr_wake: usize,
    nr_requeue: usize,
    compare: Option<u32>,
) -> Result<usize, FutexError> {
    for _ in 0..FUTEX_REVALIDATE_RETRIES {
        let Some(bucket) = lookup_bucket(key) else {
            return check_requeue_compare_unlocked(key.1, compare).map(|()| 0);
        };
        let mut deferred = FutexDeferredWakes::new();
        let result = {
            let mut b = bucket.lock();
            check_requeue_compare(key.1, compare).and_then(|()| {
                if plain_op_refused(&b) {
                    return Err(FutexError::InvalidOperation);
                }
                let woken = take_waiters_locked(
                    &mut b,
                    key.1,
                    nr_wake,
                    FUTEX_BITSET_MATCH_ANY,
                    &mut deferred,
                );
                Ok(woken + nr_requeue.min(b.waiters.len()))
            })
        };
        deferred.run(key.0);
        cleanup_empty_bucket(key, &bucket);
        if result != Err(FutexError::WordFault) {
            return result;
        }
        // GAP-5 PI review D2-1: fault the word in with the lock dropped.
        fault_in_word(key.1, false)?;
    }
    Err(FutexError::Fault)
}

/// CMP_REQUEUE: `*uaddr` must still equal the expected value. The caller
/// holds a futex lock: the source bucket lock when there is one, which
/// serializes this read with the value check of a queueing waiter, else
/// `FUTEX_TABLE`. The read therefore does not resolve a fault
/// ([`FutexError::WordFault`], review D2-1).
fn check_requeue_compare(uaddr: usize, compare: Option<u32>) -> Result<(), FutexError> {
    let Some(expected) = compare else {
        return Ok(());
    };
    if LockedUserWord(uaddr).read()? == expected {
        Ok(())
    } else {
        Err(FutexError::WouldBlock)
    }
}

/// [`check_requeue_compare`] with no futex lock held: the read may fault the
/// word in.
fn check_requeue_compare_unlocked(uaddr: usize, compare: Option<u32>) -> Result<(), FutexError> {
    match compare {
        Some(expected) if read_user_u32(uaddr)? != expected => Err(FutexError::WouldBlock),
        _ => Ok(()),
    }
}

/// FUTEX_WAKE_OP: atomically replace `*uaddr2` with `op.apply(old)`, wake up
/// to `nr_wake` waiters of `uaddr1`, and, when `op.compare(old)` holds, up to
/// `nr_wake2` waiters of `uaddr2`. Returns the total woken.
///
/// The update is a compare-and-swap loop on the user word through the
/// fault-safe accessors (a fault is EFAULT and leaves the word unchanged),
/// done before either wake and without a bucket lock. A waiter queues only
/// after reading the word under its bucket lock, which the later wake takes,
/// so it either saw the new value or is found by the wake. Linux holds both
/// bucket locks across the update for the same effect.
pub fn futex_wake_op(
    space: usize,
    uaddr1: usize,
    uaddr2: usize,
    nr_wake: usize,
    nr_wake2: usize,
    op: FutexWakeOp,
) -> Result<usize, FutexError> {
    let old = atomic_op_user_u32(uaddr2, op)?;
    let mut woken = wake_key((space, uaddr1), nr_wake, FUTEX_BITSET_MATCH_ANY)?;
    if op.compare(old) {
        woken += wake_key((space, uaddr2), nr_wake2, FUTEX_BITSET_MATCH_ANY)?;
    }
    Ok(woken)
}

/// Compare-and-swap attempts per round, and rounds (a yield between rounds),
/// before FUTEX_WAKE_OP gives up on a word that other threads keep changing.
/// Linux retries without bound; the bound keeps a hostile writer from pinning
/// the kernel. Giving up leaves the word unchanged and reports EAGAIN.
const WAKE_OP_CAS_ATTEMPTS: usize = 64;
const WAKE_OP_CAS_ROUNDS: usize = 64;

fn atomic_op_user_u32(uaddr: usize, op: FutexWakeOp) -> Result<u32, FutexError> {
    use kernel_core::usercopy::{compare_exchange_user_u32, read_user_u32_atomic, UserAddr};

    for round in 0..WAKE_OP_CAS_ROUNDS {
        if round != 0 {
            kernel_core::force_reschedule();
        }
        for _ in 0..WAKE_OP_CAS_ATTEMPTS {
            let old = read_user_u32_atomic(UserAddr::new(uaddr)).map_err(|_| FutexError::Fault)?;
            match compare_exchange_user_u32(UserAddr::new(uaddr), old, op.apply(old)) {
                Ok(true) => return Ok(old),
                Ok(false) => continue,
                Err(()) => return Err(FutexError::Fault),
            }
        }
    }
    Err(FutexError::WouldBlock)
}

// ============================================================================
// GAP-5 PI parity: the Linux PI user-word protocol and requeue-PI
// ============================================================================

/// Bound on the retries of the PI operations that may give up: the
/// requeue-PI calls (FUTEX_WAIT_REQUEUE_PI's spurious wakes, FUTEX_CMP_
/// REQUEUE_PI's changed or faulting words), for which Linux documents EAGAIN.
/// FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_TRYLOCK_PI and FUTEX_UNLOCK_PI retry
/// without a bound (review D2-2, see [`pi_pause`]).
const FUTEX_PI_ATTEMPTS: usize = 1024;
/// CAS attempts per bucket-lock hold on a PI word that user space keeps
/// changing; a pause, with the lock dropped, separates rounds.
const FUTEX_PI_CAS_ATTEMPTS: usize = 64;
/// GAP-5 PI review D2-2: an unbounded PI retry loop yields between rounds
/// and sleeps about one timer tick every this many rounds, so it does not
/// keep a CPU from the task it waits for.
const FUTEX_PI_YIELDS_PER_SLEEP: usize = 16;
/// One tick of the 1 kHz timer: the sleep of a PI retry round.
const FUTEX_PI_PAUSE_NS: u64 = 1_000_000;

/// GAP-5 PI review D2-2: where a PI retry round sleeps. Nobody wakes it: only
/// the timeout or a kill ends such a sleep (a handler signal ends it early).
static PI_PAUSE_QUEUE: WaitQueue = WaitQueue::new(HeapClass::Futex);

/// GAP-5 PI review D2-2: pause between two rounds of an unbounded PI retry
/// loop: an exiting owner, a word user space keeps changing, a word to fault
/// in, an owner-death fixup, a full waiter set. Linux loops in these cases
/// too (`wait_for_owner_exiting`, `cond_resched`, `fault_in_user_writeable`).
/// FUTEX_LOCK_PI must not give up with EAGAIN or EINTR: glibc takes either
/// for "acquired". Only a kill or an exec handoff ends the loop (EINTR, which
/// never reaches user space: the task exits, or the exec's result replaces it)
/// and so does `deadline` (ETIMEDOUT). A handler
/// signal does not: it is delivered when the call returns. `sleep` asks for
/// a tick's sleep instead of a yield.
fn pi_pause(
    pid: ProcessId,
    deadline: Option<u64>,
    round: &mut usize,
    sleep: bool,
) -> Result<(), FutexError> {
    if process::wait_should_abort(pid) {
        return Err(FutexError::Interrupted);
    }
    if deadline.is_some_and(|deadline| futex_now_ns() >= deadline) {
        return Err(FutexError::TimedOut);
    }
    *round = round.wrapping_add(1);
    if sleep || *round % FUTEX_PI_YIELDS_PER_SLEEP == 0 {
        pi_sleep_tick(deadline);
    } else {
        kernel_core::force_reschedule();
    }
    Ok(())
}

/// Sleep about one tick (less when `deadline` is nearer), killably. A sleep
/// that cannot be armed (waiter metadata exhausted) becomes a yield.
fn pi_sleep_tick(deadline: Option<u64>) {
    let timeout =
        remaining_timeout(deadline).map_or(FUTEX_PI_PAUSE_NS, |left| left.min(FUTEX_PI_PAUSE_NS));
    let prepared = PI_PAUSE_QUEUE.try_prepare_killable_with_timeout_after(Some(timeout), || {
        Ok::<(), core::convert::Infallible>(())
    });
    match prepared {
        Ok(Ok(PrepareWait::Armed(ticket))) => {
            let _ = PI_PAUSE_QUEUE.finish_prepared(ticket);
            // A handler signal ends the sleep with the entry still queued.
            let _ = PI_PAUSE_QUEUE.cancel_wait();
        }
        Ok(Ok(PrepareWait::Immediate(_))) | Err(_) => kernel_core::force_reschedule(),
        Ok(Err(never)) => match never {},
    }
}

/// The task making a PI request.
pub struct PiCaller {
    /// Global PID.
    pub pid: ProcessId,
    /// The TID user space sees (`gettid` in the caller's PID namespace),
    /// which it stores in the word when it takes the lock.
    pub tid: u32,
    /// The caller's PID namespace: a TID read from a word is resolved there,
    /// as Linux's `find_get_task_by_vpid` does.
    pub ns: Option<kernel_core::PidNamespaceArc>,
}

impl PiCaller {
    /// The task a word's TID names, with its PCB generation. Called with no
    /// lock held: the namespace lookup takes locks of its own.
    fn resolve(&self, tid: u32) -> Option<(ProcessId, u64)> {
        let ns = self.ns.as_ref()?;
        let pid = kernel_core::resolve_pid_in_namespace(ns, tid as ProcessId)?;
        let proc = process::get_process(pid)?;
        let generation = proc.lock().generation;
        Some((pid, generation))
    }

    fn is_valid(&self) -> bool {
        self.pid != 0 && self.pid <= process::PID_MAX && self.tid != 0 && self.tid <= FUTEX_TID_MASK
    }
}

/// One step of a PI lock attempt on the word read under the PI bucket's
/// lock (Linux `futex_lock_pi_atomic` and `attach_to_pi_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiLockStep {
    /// The word names the taker already: EDEADLK.
    Deadlock,
    /// The word contradicts the kernel's PI state: EINVAL.
    Invalid,
    /// Wait behind the existing PI state.
    Join,
    /// Nobody owns the lock: store `new` (CAS from the word read) and own it.
    Acquire { new: u32 },
    /// Set FUTEX_WAITERS (CAS to `new`), so the owner's unlock enters the
    /// kernel, before looking the owner up.
    SetWaiters { new: u32 },
    /// The word, WAITERS set, names owner `tid`: attach a PI state to it.
    Attach { tid: u32 },
}

fn pi_lock_step(
    word: u32,
    taker_tid: u32,
    state: Option<PiStateView>,
    set_waiters: bool,
) -> PiLockStep {
    let tid = word & FUTEX_TID_MASK;
    if tid == taker_tid {
        return PiLockStep::Deadlock;
    }
    if let Some(state) = state {
        // The word must agree with the PI state. While a hand-off after the
        // owner's death awaits its fixup, the word still names the dead
        // owner, or carries TID 0 with OWNER_DIED after the robust walk.
        let owner_died_in_transit = word & FUTEX_OWNER_DIED != 0 && tid == 0;
        return if state.fixup || owner_died_in_transit || tid == state.owner_tid {
            PiLockStep::Join
        } else {
            PiLockStep::Invalid
        };
    }
    if tid == 0 {
        // Free (a stale WAITERS bit, or OWNER_DIED from the robust walk):
        // take it over. OWNER_DIED stays, so user space sees EOWNERDEAD.
        let waiters = if set_waiters { FUTEX_WAITERS } else { 0 };
        return PiLockStep::Acquire {
            new: (word & FUTEX_OWNER_DIED) | taker_tid | waiters,
        };
    }
    if word & FUTEX_WAITERS == 0 {
        return PiLockStep::SetWaiters {
            new: word | FUTEX_WAITERS,
        };
    }
    PiLockStep::Attach { tid }
}

/// What FUTEX_UNLOCK_PI does with the word read under the bucket lock
/// (Linux `futex_unlock_pi` and `wake_futex_pi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiUnlockStep {
    /// The word does not name the caller: EPERM.
    NotOwner,
    /// The kernel PI state belongs to another task (user space rewrote the
    /// word), or awaits an owner-death fixup: EINVAL.
    Invalid,
    /// No kernel waiter: store 0 (WAITERS and OWNER_DIED go, as on Linux).
    Release,
    /// Store `new` for the top waiter and wake it as the owner. WAITERS
    /// stays set while a PI state could exist, as on Linux, so the new
    /// owner's unlock enters the kernel.
    HandOff { new: u32 },
}

fn pi_unlock_step(
    word: u32,
    caller_pid: ProcessId,
    caller_tid: u32,
    state: Option<PiOwner>,
    top_tid: Option<u32>,
) -> PiUnlockStep {
    if word & FUTEX_TID_MASK != caller_tid {
        return PiUnlockStep::NotOwner;
    }
    if state.is_some_and(|owner| owner.pid != caller_pid || owner.fixup) {
        return PiUnlockStep::Invalid;
    }
    match top_tid {
        Some(tid) => PiUnlockStep::HandOff {
            new: tid | FUTEX_WAITERS,
        },
        None => PiUnlockStep::Release,
    }
}

/// The word a task handed the lock after its owner died stores (Linux
/// `__fixup_pi_state_owner`): its TID and WAITERS, and OWNER_DIED. GAP-5 PI
/// review D5: Linux sets OWNER_DIED whenever `exit_pi_state_list` cleared the
/// owner (`if (!pi_state->owner) newtid |= FUTEX_OWNER_DIED`), so the heir of
/// a non-robust owner sees it too; a fixup is pending only after such a
/// death ([`pi_owner_died_locked`]).
fn pi_fixup_word(tid: u32) -> u32 {
    FUTEX_OWNER_DIED | tid | FUTEX_WAITERS
}

/// The top PI waiter: highest priority (lowest value), oldest first.
fn select_top_pi_waiter(
    waiters: &AdmittedMap<ProcessId, PiWaiter>,
) -> Option<(ProcessId, PiWaiter)> {
    waiters
        .iter()
        .min_by_key(|(_, waiter)| (waiter.priority, waiter.seq))
        .map(|(pid, waiter)| (*pid, *waiter))
}

/// Under the PI bucket lock: make `pid` (no longer in `pi_waiters`) the
/// owner, publish its grant and wake marks, and queue its wake. The wake
/// runs after the caller has dropped the lock and given the new owner its
/// donation, so the owner runs boosted.
fn grant_pi_waiter_locked(
    bucket: &mut FutexBucket,
    pid: ProcessId,
    waiter: PiWaiter,
    fixup: bool,
    deferred: &mut FutexDeferredWakes,
) {
    bucket.pi_owner = Some(PiOwner {
        pid,
        tid: waiter.tid,
        fixup,
    });
    PI_GRANT_MARKS.set(pid);
    set_wake_mark(pid);
    deferred.push(waiter.origin, pid as u32);
}

/// Under the PI bucket lock (Linux `exit_pi_state_list`): if `dead` owns
/// this PI state, hand the lock to the top waiter, which stores its own TID
/// in the word when it runs ([`PiOwner::fixup`]), or drop the state when
/// nobody waits. Returns None when `dead` is not the owner, else the new
/// owner, if any.
fn pi_owner_died_locked(
    bucket: &mut FutexBucket,
    dead: ProcessId,
    deferred: &mut FutexDeferredWakes,
) -> Option<Option<ProcessId>> {
    if !bucket.pi_owner.is_some_and(|owner| owner.pid == dead) {
        return None;
    }
    let Some((pid, waiter)) = select_top_pi_waiter(&bucket.pi_waiters) else {
        bucket.pi_owner = None;
        return Some(None);
    };
    bucket.pi_waiters.remove_retaining_capacity(&pid);
    grant_pi_waiter_locked(bucket, pid, waiter, true, deferred);
    Some(Some(pid))
}

/// Hand every PI futex whose kernel PI state `dead` owns to its top waiter.
/// Called from the exit callback right after the robust walk, and again,
/// normally finding nothing, from the reap-time cleanup.
fn release_pi_states_of(dead: ProcessId) {
    let mut after = None;
    while let Some((key, bucket)) = next_bucket(after) {
        after = Some(key);
        let mut deferred = FutexDeferredWakes::new();
        let (handled, retired) = {
            let mut b = bucket.lock();
            let handled = if b.pi_owner.is_some_and(|owner| owner.pid == dead) {
                // U34-2: never hand the lock to a task that is already dead.
                prune_dead_pi_waiters_locked(&mut b);
                pi_owner_died_locked(&mut b, dead, &mut deferred)
            } else {
                None
            };
            (handled, b.pi_waiters.take_empty_capacity())
        };
        drop(retired);
        if handled.is_some() {
            // The dead owner's own boosts go with its PCB.
            refresh_pi_boosts(key, &bucket, None);
            deferred.run(key.0);
            cleanup_empty_bucket(key, &bucket);
        }
    }
}

/// A CAS on the PI word made with no futex lock held: it may fault the word
/// in.
fn cas_user_u32(uaddr: usize, expected: u32, new: u32) -> Result<bool, FutexError> {
    use kernel_core::usercopy::{compare_exchange_user_u32, UserAddr};
    compare_exchange_user_u32(UserAddr::new(uaddr), expected, new).map_err(|()| FutexError::Fault)
}

/// The kernel's view of the task a PI word names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiOwnerLiveness {
    Live,
    /// R191-1: alive, but it cannot own a PI state of the futex's key space
    /// ([`pi_owner_in_space`]).
    Foreign,
    /// Zombie, futex exit work (robust walk and PI hand-off) not yet done.
    Exiting,
    /// Gone, recycled, or its exit work is done.
    Dead,
}

/// R191-1 FIX (D3-ARC-1, INV-SEC-04): whether a live task whose page-table
/// root is `memory_space` and whose key space is `owner_space` may own a PI
/// state of key space `space`. Every futex key is private to one address
/// space ([`FutexSpace`]), so the owner must be a user task (a kernel task
/// has no page table of its own) of the caller's address space: a CLONE_VM
/// task shares it, thread or not. Linux rejects only kernel threads
/// (`attach_to_pi_owner`, `PF_KTHREAD`) and has no address-space check; its
/// shared futexes let tasks of several address spaces use one PI word. Here
/// every key is private, so a task of another address space reaches the word
/// through another key and could never unlock through this state; attaching
/// to it would only boost an unrelated task.
fn pi_owner_in_space(memory_space: usize, owner_space: usize, space: usize) -> bool {
    memory_space != 0 && owner_space == space
}

/// Called under a bucket lock (bucket -> PROCESS_TABLE -> PCB), for a PI
/// state of key space `space`. A task's exit callback (robust walk, then
/// [`release_pi_states_of`]) runs after it publishes `Zombie` and before it
/// publishes `teardown_done`, so a task seen alive here has not run its PI
/// hand-off yet, and the hand-off takes this bucket's lock after the caller
/// releases it. The identity of an exiting task is not checked: it is only
/// waited for, and its exit work then hands off or drops every PI state it
/// owns. (Its `memory_space` is cleared only after it leaves the table, or,
/// for a clone aborted before it ran, while it is `Terminated`.)
fn pi_owner_liveness(pid: ProcessId, generation: u64, space: usize) -> PiOwnerLiveness {
    let Some(proc_arc) = process::get_process(pid) else {
        return PiOwnerLiveness::Dead;
    };
    let proc = proc_arc.lock();
    if proc.generation != generation {
        return PiOwnerLiveness::Dead;
    }
    match proc.state {
        process::ProcessState::Zombie | process::ProcessState::Terminated => {
            if proc.teardown_done.load(Ordering::Acquire) {
                PiOwnerLiveness::Dead
            } else {
                PiOwnerLiveness::Exiting
            }
        }
        _ if !pi_owner_in_space(proc.memory_space, FutexSpace::id_of_mm(&proc.mm), space) => {
            PiOwnerLiveness::Foreign
        }
        _ => PiOwnerLiveness::Live,
    }
}

/// Linux `wait_for_owner_exiting`: let an exiting owner finish its futex
/// exit work, then retry. GAP-5 PI review D2-2: no bound and no EAGAIN (the
/// exit work always completes); only a kill or an exec handoff (EINTR) or
/// `deadline` (ETIMEDOUT) ends the wait.
fn wait_for_pi_owner_exit(
    owner: ProcessId,
    generation: u64,
    space: usize,
    waiter: ProcessId,
    deadline: Option<u64>,
) -> Result<(), FutexError> {
    let mut round = 0usize;
    while pi_owner_liveness(owner, generation, space) == PiOwnerLiveness::Exiting {
        pi_pause(waiter, deadline, &mut round, false)?;
    }
    Ok(())
}

/// Result of [`pi_take_or_attach_locked`].
enum PiTake {
    /// The word now names the taker.
    Taken,
    /// A PI state with a live owner exists; the taker may wait on it.
    Attached,
    /// The word changed: start over.
    Retry,
    /// The owner is exiting: wait for its exit work, then start over.
    OwnerExiting(ProcessId, u64),
}

/// Under the PI bucket lock of a futex of key space `space`: Linux
/// `futex_lock_pi_atomic` for the task `taker_pid`/`taker_tid`. `named` is
/// the owner TID the word held before the lock was taken and `resolved` the
/// task it named then. A word access that faults returns
/// [`FutexError::WordFault`] (review D2-1).
#[allow(clippy::too_many_arguments)]
fn pi_take_or_attach_locked(
    bucket: &mut FutexBucket,
    word: &dyn LockedWord,
    space: usize,
    taker_pid: ProcessId,
    taker_tid: u32,
    set_waiters: bool,
    named: u32,
    resolved: Option<(ProcessId, u64)>,
) -> Result<PiTake, FutexError> {
    let mut current = word.read()?;
    // At most two rounds: SetWaiters, then Attach.
    for _ in 0..2 {
        let state = bucket.pi_owner.map(PiStateView::from);
        match pi_lock_step(current, taker_tid, state, set_waiters) {
            PiLockStep::Deadlock => return Err(FutexError::Deadlock),
            PiLockStep::Invalid => return Err(FutexError::InvalidOperation),
            PiLockStep::Join => return Ok(PiTake::Attached),
            PiLockStep::Acquire { new } => {
                return Ok(if word.cas(current, new)? {
                    PiTake::Taken
                } else {
                    PiTake::Retry
                });
            }
            PiLockStep::SetWaiters { new } => {
                if !word.cas(current, new)? {
                    return Ok(PiTake::Retry);
                }
                current = new;
            }
            PiLockStep::Attach { tid } => {
                if tid != named {
                    return Ok(PiTake::Retry);
                }
                let Some((owner, generation)) = resolved else {
                    return pi_owner_gone(word, current);
                };
                if owner == taker_pid {
                    // The word names the taker under another namespace's TID.
                    return Err(FutexError::Deadlock);
                }
                // R191-1 FIX: the owner's identity is checked with its
                // liveness, under this bucket's lock and the owner's PCB lock,
                // before any PI state or boost names it.
                return match pi_owner_liveness(owner, generation, space) {
                    PiOwnerLiveness::Live => {
                        bucket.pi_owner = Some(PiOwner {
                            pid: owner,
                            tid,
                            fixup: false,
                        });
                        Ok(PiTake::Attached)
                    }
                    PiOwnerLiveness::Foreign => Err(FutexError::NotOwner),
                    PiOwnerLiveness::Exiting => Ok(PiTake::OwnerExiting(owner, generation)),
                    PiOwnerLiveness::Dead => pi_owner_gone(word, current),
                };
            }
        }
    }
    Ok(PiTake::Retry)
}

/// Linux `handle_exit_race`: the owner the word names is gone. Its robust
/// walk may have changed the word meanwhile (retry); otherwise the word names
/// nobody (ESRCH).
fn pi_owner_gone(word: &dyn LockedWord, observed: u32) -> Result<PiTake, FutexError> {
    if word.read()? != observed {
        Ok(PiTake::Retry)
    } else {
        Err(FutexError::NoProcess)
    }
}

/// An absolute deadline, in nanoseconds of the clock `clock_gettime` reads,
/// for a relative timeout.
fn futex_deadline(timeout_ns: Option<u64>) -> Option<u64> {
    timeout_ns.map(|ns| futex_now_ns().saturating_add(ns))
}

fn futex_now_ns() -> u64 {
    kernel_core::current_timestamp_ms().saturating_mul(1_000_000)
}

/// Time left until `deadline`; 0 (an immediate timeout) once it passed.
fn remaining_timeout(deadline: Option<u64>) -> Option<u64> {
    deadline.map(|deadline| deadline.saturating_sub(futex_now_ns()))
}

/// FUTEX_LOCK_PI / FUTEX_LOCK_PI2 (`trylock` false) and FUTEX_TRYLOCK_PI
/// (`trylock` true): take the PI mutex at `uaddr` under the Linux user-word
/// protocol.
///
/// - The word is 0 (or TID 0 with OWNER_DIED, and no kernel waiter): store
///   the caller's TID, keeping OWNER_DIED, and return 0. User space reads
///   OWNER_DIED to report EOWNERDEAD; the kernel returns 0, as Linux does.
/// - The word names the caller: EDEADLK.
/// - Otherwise set FUTEX_WAITERS, find the owner by the TID in the word (in
///   the caller's PID namespace; none: ESRCH), and wait with priority
///   inheritance until the lock is handed over (return 0) or the deadline
///   passes (ETIMEDOUT). FUTEX_TRYLOCK_PI returns EAGAIN instead of waiting.
///
/// GAP-5 PI review D2-2: glibc takes EINTR and EAGAIN from FUTEX_LOCK_PI for
/// "acquired" and aborts on ENOMEM; musl sleeps forever on EAGAIN or ENOMEM.
/// So the wait is killable, not interruptible: a handler signal ends the
/// sleep like a spurious wake and the call goes on (Linux restarts it with
/// ERESTARTNOINTR; here the handler runs when the call returns), and a
/// changed word, an exiting owner, a word to fault in, a busy preparation
/// gate and a full waiter set are retried without a bound. Only a kill or an
/// exec handoff ends the call early (EINTR, never seen by user space). ENOMEM is left for
/// memory and futex-metadata exhaustion, as Linux's pi_state allocation can
/// fail with it.
///
/// `timeout_ns` is the time left until the caller's absolute deadline.
pub fn futex_lock_pi(
    space: &FutexSpace,
    uaddr: usize,
    caller: &PiCaller,
    timeout_ns: Option<u64>,
    trylock: bool,
) -> Result<usize, FutexError> {
    if !caller.is_valid() {
        return Err(FutexError::NoProcess);
    }
    let key: FutexKey = (space.id, uaddr);
    let deadline = futex_deadline(timeout_ns);
    let proc_arc = process::get_process(caller.pid).ok_or(FutexError::NoProcess)?;
    // RF178-8: reserve the boost slot this task needs if it later owns the
    // lock with waiters behind it, so a hand-off never allocates. The wait
    // edge feeds chained PI propagation.
    let priority = {
        let mut proc = proc_arc.lock();
        if !trylock {
            proc.try_reserve_pi_boost(key)
                .map_err(|()| FutexError::TooManyBuckets)?;
            proc.set_waiting_on_futex(Some(key));
        }
        proc.dynamic_priority
    };
    let result = lock_pi_attempts(space, key, caller, priority, deadline, trylock);
    if !trylock {
        let mut proc = proc_arc.lock();
        proc.set_waiting_on_futex(None);
        proc.cancel_pi_boost_reservation(&key);
    }
    result
}

fn lock_pi_attempts(
    space: &FutexSpace,
    key: FutexKey,
    caller: &PiCaller,
    priority: Priority,
    deadline: Option<u64>,
    trylock: bool,
) -> Result<usize, FutexError> {
    let mut round = 0usize;
    loop {
        let sleep = match pi_lock_attempt(space, key, caller, priority, deadline, trylock)? {
            PiLockAttempt::Acquired => return Ok(0),
            PiLockAttempt::Queued(bucket, queue) => {
                if pi_block(key, &bucket, &queue, caller, deadline)? {
                    return Ok(0);
                }
                // The sleep ended without a hand-off, timeout or kill (a
                // handler signal or a spurious wake). Linux never returns
                // from LOCK_PI then: try again.
                false
            }
            PiLockAttempt::Retry => false,
            PiLockAttempt::FaultIn => {
                fault_in_word(key.1, true)?;
                false
            }
            PiLockAttempt::OwnerExiting(owner, generation) => {
                wait_for_pi_owner_exit(owner, generation, key.0, caller.pid, deadline)?;
                false
            }
            // Past the per-futex waiter bound: poll for a slot once a tick.
            PiLockAttempt::Full => true,
        };
        pi_pause(caller.pid, deadline, &mut round, sleep)?;
    }
}

enum PiLockAttempt {
    Acquired,
    /// The caller is a published PI waiter of the bucket.
    Queued(FutexBucketRef, FutexQueueRef),
    Retry,
    /// GAP-5 PI review D2-1: the word faulted under the bucket lock.
    FaultIn,
    OwnerExiting(ProcessId, u64),
    /// GAP-5 PI review D2-2: the futex has its maximum of waiters.
    Full,
}

enum PiLocked {
    Acquired,
    Queued,
    Retry,
    OwnerExiting(ProcessId, u64),
    Full,
}

fn pi_lock_attempt(
    space: &FutexSpace,
    key: FutexKey,
    caller: &PiCaller,
    priority: Priority,
    deadline: Option<u64>,
    trylock: bool,
) -> Result<PiLockAttempt, FutexError> {
    // Resolve the owner the word names before taking any lock. The locked
    // step re-reads the word and retries if it changed. This read, made
    // with no lock held, also faults the word in.
    let named = read_user_u32(key.1)? & FUTEX_TID_MASK;
    let resolved = if named != 0 && named != caller.tid {
        caller.resolve(named)
    } else {
        None
    };

    let permit = FutexPreparePermit::acquire_killable(space.id, caller.pid, deadline)?;
    let bucket = get_or_create_live_bucket(key, &permit, space.pin.as_ref())?;
    let prepared = if trylock {
        Ok(None)
    } else {
        let (len, capacity) = {
            let b = bucket.lock();
            (b.pi_waiters.len(), b.pi_waiters.capacity())
        };
        prepare_pi_waiter_growth(len, capacity, 1)
    };
    let mut prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            cleanup_empty_bucket(key, &bucket);
            return Err(error);
        }
    };
    // A mark left by an earlier wait must not end this one; cleared before
    // any granter can see the waiter published below.
    clear_wait_marks(caller.pid);
    let mut retired = None;
    let (outcome, retired_empty) = {
        let mut b = bucket.lock();
        let outcome = pi_lock_locked(
            &mut b,
            key,
            &LockedUserWord(key.1),
            caller,
            priority,
            (named, resolved),
            trylock,
            &mut prepared,
            &mut retired,
        );
        (outcome, b.pi_waiters.take_empty_capacity())
    };
    // No backing is freed under the bucket lock.
    drop(retired_empty);
    drop(retired);
    drop(prepared);
    // Published (or not): the bucket is pinned by waiter_count if needed.
    drop(permit);
    let attempt = match outcome {
        Ok(PiLocked::Queued) => {
            let queue = bucket.lock().queue.clone();
            return Ok(PiLockAttempt::Queued(bucket, queue));
        }
        Ok(PiLocked::Acquired) => Ok(PiLockAttempt::Acquired),
        Ok(PiLocked::Retry) => Ok(PiLockAttempt::Retry),
        Ok(PiLocked::Full) => Ok(PiLockAttempt::Full),
        Ok(PiLocked::OwnerExiting(owner, generation)) => {
            Ok(PiLockAttempt::OwnerExiting(owner, generation))
        }
        Err(FutexError::WordFault) => Ok(PiLockAttempt::FaultIn),
        Err(error) => Err(error),
    };
    cleanup_empty_bucket(key, &bucket);
    attempt
}

/// The locked part of a PI lock attempt: take the lock, or attach to the
/// owner and publish the caller as a PI waiter.
#[allow(clippy::too_many_arguments)]
fn pi_lock_locked(
    b: &mut FutexBucket,
    key: FutexKey,
    word: &dyn LockedWord,
    caller: &PiCaller,
    priority: Priority,
    (named, resolved): (u32, Option<(ProcessId, u64)>),
    trylock: bool,
    prepared: &mut Option<PreparedPiWaiterCapacity>,
    retired: &mut Option<RetiredPiWaiterCapacity>,
) -> Result<PiLocked, FutexError> {
    if b.unlinked {
        // R172-07/08: a reaper unlinked it after the lookup.
        return Ok(PiLocked::Retry);
    }
    // GAP-5 PI review D4: the caller already holds this lock, handed over
    // after its owner died, but the call that was handed it could not store
    // its TID (the word was not mapped then). Finish that fixup and report
    // the lock taken (0); before, the caller queued behind itself.
    if b.pi_owner
        .is_some_and(|owner| owner.pid == caller.pid && owner.fixup)
    {
        return Ok(if pi_fixup_locked(b, word, caller)? {
            PiLocked::Acquired
        } else {
            PiLocked::Retry
        });
    }
    match pi_take_or_attach_locked(
        b, word, key.0, caller.pid, caller.tid, false, named, resolved,
    )? {
        PiTake::Taken => return Ok(PiLocked::Acquired),
        PiTake::Retry => return Ok(PiLocked::Retry),
        PiTake::OwnerExiting(owner, generation) => {
            return Ok(PiLocked::OwnerExiting(owner, generation))
        }
        PiTake::Attached => {}
    }
    // A PI state exists now; queue behind it (I-PI1 is re-established on
    // every exit below).
    if trylock {
        b.settle_pi_state();
        return Err(FutexError::WouldBlock);
    }
    if b.waiter_count >= MAX_FUTEX_WAITERS_PER_BUCKET
        || b.pi_waiters.len() >= MAX_FUTEX_WAITERS_PER_BUCKET
    {
        // GAP-5 PI review D2-2: not ENOMEM; the caller waits for a slot.
        b.settle_pi_state();
        return Ok(PiLocked::Full);
    }
    if !ensure_pi_waiter_capacity(&mut b.pi_waiters, 1, prepared, retired) {
        b.settle_pi_state();
        return Ok(PiLocked::Retry);
    }
    // R172-07/08: waiter_count >= 1 pins the bucket table-resident until
    // this task's epilogue (checked above, so this cannot fail).
    if let Err(error) = reserve_bucket_waiter(b) {
        b.settle_pi_state();
        return Err(error);
    }
    // GAP-5 PI review (third pass) F1: publish the caller's live priority,
    // read under this bucket's lock (bucket -> PROCESS_TABLE -> PCB). The
    // value read at the call's entry lost a boost the caller gained while it
    // waited (a retry re-inserts it) or kept one it lost since, and a chain hop
    // that reached this bucket before the entry existed updated nothing. The
    // entry value stands in only when no PCB is found (hosted tests).
    let priority = process::get_process(caller.pid)
        .map_or(priority, |proc_arc| proc_arc.lock().dynamic_priority);
    let waiter = PiWaiter {
        origin: key.1,
        seq: b.next_pi_seq(),
        tid: caller.tid,
        priority,
    };
    if !insert_pi_waiter_locked(&mut b.pi_waiters, caller.pid, waiter) {
        b.waiter_count = b.waiter_count.saturating_sub(1);
        b.settle_pi_state();
        return Ok(PiLocked::Retry);
    }
    Ok(PiLocked::Queued)
}

/// Sleep as a published PI waiter. Ok(true): the caller owns the lock;
/// Ok(false): the sleep ended with no hand-off, timeout or kill (retry).
fn pi_block(
    key: FutexKey,
    bucket: &FutexBucketRef,
    queue: &FutexQueueRef,
    caller: &PiCaller,
    deadline: Option<u64>,
) -> Result<bool, FutexError> {
    let pid = caller.pid;
    // Donate to the owner and its chain. GAP-5 PI review D4: a donation that
    // finds no memory is skipped (the owner runs unboosted); it never fails
    // the waiter.
    refresh_pi_boosts(key, bucket, None);
    // Sleep on the bucket's queue unless a granter has already set the
    // mark: it reads the mark under the queue lock that the granter's wake
    // takes after setting it, so a hand-off is never lost. GAP-5 PI review
    // D2-2: killable, so a handler signal neither aborts the arm nor ends the
    // sleep as an interruption.
    let prepared =
        queue.try_prepare_killable_with_timeout_after(remaining_timeout(deadline), || {
            if wake_mark_is_set(pid) {
                Err(())
            } else {
                Ok(())
            }
        });
    let outcome = match prepared {
        Ok(Ok(PrepareWait::Armed(ticket))) => queue.finish_prepared(ticket),
        Ok(Ok(PrepareWait::Immediate(outcome))) => outcome,
        Ok(Err(())) => WaitOutcome::Woken,
        Err(_) => WaitOutcome::ResourceExhausted,
    };
    // A hand-off wins over a timeout or kill that also ended the sleep: the
    // lock is the caller's (Linux returns 0 then too).
    if leave_pi_wait(key, bucket, queue, caller)? {
        return Ok(true);
    }
    match outcome {
        WaitOutcome::Woken => Ok(false),
        WaitOutcome::TimedOut => Err(FutexError::TimedOut),
        // A kill (the task is exiting) or an exec handoff (the exec's result
        // replaces this one).
        WaitOutcome::Interrupted => Err(FutexError::Interrupted),
        WaitOutcome::Closed | WaitOutcome::NoProcess => Err(FutexError::NoProcess),
        WaitOutcome::ResourceExhausted => Err(FutexError::TooManyBuckets),
    }
}

/// End a FUTEX_LOCK_PI wait: leave the queue and the bucket. True when the
/// caller was made the owner; it then stores its TID in the word if the
/// lock came from an owner's death.
fn leave_pi_wait(
    key: FutexKey,
    bucket: &FutexBucketRef,
    queue: &FutexQueueRef,
    caller: &PiCaller,
) -> Result<bool, FutexError> {
    let pid = caller.pid;
    // A sleep a timeout, a signal or nothing at all ended can leave this
    // task's entry on the queue; it must not absorb a later wake.
    let _ = queue.cancel_wait();
    let (granted, previous, retired) = {
        let mut b = bucket.lock();
        b.waiter_count = b.waiter_count.saturating_sub(1);
        if PI_GRANT_MARKS.is_set(pid) {
            // The granter removed the PI entry when it set the mark.
            (true, None, None)
        } else {
            let previous = b.pi_owner.map(|owner| owner.pid);
            b.pi_waiters.remove_retaining_capacity(&pid);
            b.settle_pi_state();
            (false, previous, b.pi_waiters.take_empty_capacity())
        }
    };
    drop(retired);
    let fixed = if granted {
        pi_fixup_owner(key, bucket, caller)
    } else {
        Ok(())
    };
    refresh_pi_boosts(key, bucket, previous);
    cleanup_empty_bucket(key, bucket);
    fixed.map(|()| granted)
}

/// The caller was handed the lock after the previous owner died: store its
/// TID in the word (Linux `fixup_pi_state_owner`). No-op when no fixup is
/// pending. GAP-5 PI review D2-2 / D4: retried until it succeeds (a word
/// user space keeps changing, a word to fault in). Only a kill (whose exit
/// hands the lock on), an exec handoff or an unmapped word (EFAULT) leaves it
/// pending; the
/// caller's next FUTEX_LOCK_PI or FUTEX_UNLOCK_PI on the word finishes it.
fn pi_fixup_owner(
    key: FutexKey,
    bucket: &FutexBucketRef,
    caller: &PiCaller,
) -> Result<(), FutexError> {
    let word = LockedUserWord(key.1);
    let mut round = 0usize;
    loop {
        let fixed = {
            let mut b = bucket.lock();
            pi_fixup_locked(&mut b, &word, caller)
        };
        match fixed {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(FutexError::WordFault) => fault_in_word(key.1, true)?,
            Err(error) => return Err(error),
        }
        pi_pause(caller.pid, None, &mut round, false)?;
    }
}

/// Under the PI bucket lock: if the caller holds the lock by an owner-death
/// hand-off whose fixup is pending, store [`pi_fixup_word`] with a CAS and
/// clear the fixup. Ok(true) once nothing is pending; Ok(false) when user
/// space kept changing the word.
fn pi_fixup_locked(
    b: &mut FutexBucket,
    word: &dyn LockedWord,
    caller: &PiCaller,
) -> Result<bool, FutexError> {
    if !b
        .pi_owner
        .is_some_and(|owner| owner.pid == caller.pid && owner.fixup)
    {
        return Ok(true);
    }
    let new = pi_fixup_word(caller.tid);
    for _ in 0..FUTEX_PI_CAS_ATTEMPTS {
        let current = word.read()?;
        if word.cas(current, new)? {
            b.pi_owner = Some(PiOwner {
                pid: caller.pid,
                tid: caller.tid,
                fixup: false,
            });
            b.settle_pi_state();
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `pid` holds the PI state of `bucket` with its owner-death fixup
/// still pending (review D4).
fn pi_fixup_pending(bucket: &FutexBucketRef, pid: ProcessId) -> bool {
    bucket
        .lock()
        .pi_owner
        .is_some_and(|owner| owner.pid == pid && owner.fixup)
}

/// FUTEX_UNLOCK_PI: release the PI mutex at `uaddr`, which the word must
/// name as the caller's (else EPERM). With kernel waiters, the top one
/// (highest priority, then oldest) gets `its TID | FUTEX_WAITERS` in the
/// word and is woken as the owner; without, the word becomes 0.
///
/// GAP-5 PI review D2-2: glibc ignores the result of FUTEX_UNLOCK_PI, so a
/// call that gave up would leave the lock held for good. A word user space
/// keeps changing and a word to fault in are retried without a bound, as on
/// Linux; only a kill or an exec handoff ends the call early.
pub fn futex_unlock_pi(space: usize, uaddr: usize, caller: &PiCaller) -> Result<usize, FutexError> {
    if !caller.is_valid() {
        return Err(FutexError::NoProcess);
    }
    let key: FutexKey = (space, uaddr);
    let mut round = 0usize;
    loop {
        // No lock held: this read faults the word in.
        let current = read_user_u32(uaddr)?;
        let bucket = lookup_bucket(key);
        if current & FUTEX_TID_MASK != caller.tid {
            // GAP-5 PI review D4: a lock handed to the caller after its owner
            // died, whose fixup an earlier call could not finish, is the
            // caller's: finish the fixup, then unlock it.
            match bucket {
                Some(bucket) if pi_fixup_pending(&bucket, caller.pid) => {
                    let fixed = pi_fixup_owner(key, &bucket, caller);
                    cleanup_empty_bucket(key, &bucket);
                    fixed?;
                    continue;
                }
                _ => return Err(FutexError::NotOwner),
            }
        }
        let Some(bucket) = bucket else {
            // No kernel state. A waiter sets WAITERS only under a bucket it
            // created first, so if one raced in, this CAS fails and the next
            // round finds its bucket.
            if cas_user_u32(uaddr, current, 0)? {
                // GAP-5 PI review D3: a donation for this key that a refresh
                // left behind goes with the lock.
                drop_pi_boost(caller.pid, key);
                return Ok(0);
            }
            pi_pause(caller.pid, None, &mut round, false)?;
            continue;
        };
        let mut deferred = FutexDeferredWakes::new();
        let (step, retired) = {
            let mut b = bucket.lock();
            // U34-2 / R162-8-2: never hand the lock to a dead waiter. Removal
            // retains backing and never allocates.
            prune_dead_pi_waiters_locked(&mut b);
            let step = unlock_pi_locked(&mut b, &LockedUserWord(uaddr), caller, &mut deferred);
            (step, b.pi_waiters.take_empty_capacity())
        };
        drop(retired);
        match step {
            Ok(PiUnlocked::Done) => {
                // The caller's donation goes; the new owner, if any, gets
                // the remaining waiters' before it is woken.
                refresh_pi_boosts(key, &bucket, Some(caller.pid));
                deferred.run(space);
                cleanup_empty_bucket(key, &bucket);
                return Ok(0);
            }
            Ok(PiUnlocked::Retry) => cleanup_empty_bucket(key, &bucket),
            // D2-1: nothing changed under the lock; fault the word in.
            Err(FutexError::WordFault) => {
                cleanup_empty_bucket(key, &bucket);
                fault_in_word(uaddr, true)?;
            }
            Err(error) => {
                cleanup_empty_bucket(key, &bucket);
                return Err(error);
            }
        }
        pi_pause(caller.pid, None, &mut round, false)?;
    }
}

enum PiUnlocked {
    Done,
    Retry,
}

/// The locked part of FUTEX_UNLOCK_PI (Linux `wake_futex_pi`). The caller
/// has pruned dead waiters. Nothing changes before a CAS succeeds, so a
/// [`FutexError::WordFault`] leaves the state as it was.
fn unlock_pi_locked(
    b: &mut FutexBucket,
    word: &dyn LockedWord,
    caller: &PiCaller,
    deferred: &mut FutexDeferredWakes,
) -> Result<PiUnlocked, FutexError> {
    if b.unlinked {
        return Ok(PiUnlocked::Retry);
    }
    b.settle_pi_state();
    let top = select_top_pi_waiter(&b.pi_waiters);
    for _ in 0..FUTEX_PI_CAS_ATTEMPTS {
        let current = word.read()?;
        let step = pi_unlock_step(
            current,
            caller.pid,
            caller.tid,
            b.pi_owner,
            top.map(|(_, waiter)| waiter.tid),
        );
        match step {
            PiUnlockStep::NotOwner => return Err(FutexError::NotOwner),
            PiUnlockStep::Invalid => return Err(FutexError::InvalidOperation),
            PiUnlockStep::Release => {
                if word.cas(current, 0)? {
                    return Ok(PiUnlocked::Done);
                }
            }
            PiUnlockStep::HandOff { new } => {
                let Some((pid, waiter)) = top else {
                    return Ok(PiUnlocked::Retry);
                };
                if word.cas(current, new)? {
                    // Past the word update the hand-off cannot fail.
                    b.pi_waiters.remove_retaining_capacity(&pid);
                    grant_pi_waiter_locked(b, pid, waiter, false, deferred);
                    b.settle_pi_state();
                    return Ok(PiUnlocked::Done);
                }
            }
        }
    }
    Ok(PiUnlocked::Retry)
}

/// FUTEX_WAIT_REQUEUE_PI: wait on the non-PI futex `uaddr` while it holds
/// `expected` (else EAGAIN), for FUTEX_CMP_REQUEUE_PI to make the caller the
/// owner of the PI futex `uaddr2` or to requeue it onto that futex's PI
/// waiters. Returns 0 only once the caller owns `uaddr2`.
///
/// Before a requeue: a timeout is ETIMEDOUT and a sleep that ended for no
/// reason EAGAIN (Linux EWOULDBLOCK). Plain wakes and requeues refuse a word
/// with such a waiter (EINVAL), as on Linux. After a requeue the caller waits
/// for the PI lock: a timeout is ETIMEDOUT and a handler signal EAGAIN (Linux
/// converts that EINTR to EWOULDBLOCK), unless the lock was handed over
/// meanwhile. A requeue that refuses the caller because it owns `uaddr2`
/// wakes it with EDEADLK; one that finds no room on `uaddr2` wakes it with
/// EAGAIN.
///
/// GAP-5 PI review D2-2: the sleep is killable. A handler signal before the
/// requeue keeps the caller waiting on `uaddr` (Linux restarts the call with
/// ERESTARTNOINTR, which waits again; here the handler runs when the call
/// returns). A kill ends the wait (EINTR, never seen by user space).
#[allow(clippy::too_many_arguments)]
pub fn futex_wait_requeue_pi(
    space: &FutexSpace,
    uaddr: usize,
    expected: u32,
    current_value: u32,
    timeout_ns: Option<u64>,
    uaddr2: usize,
    caller: &PiCaller,
) -> Result<usize, FutexError> {
    if uaddr == uaddr2 {
        return Err(FutexError::InvalidOperation);
    }
    if current_value != expected {
        return Err(FutexError::WouldBlock);
    }
    if !caller.is_valid() {
        return Err(FutexError::NoProcess);
    }
    let key: FutexKey = (space.id, uaddr);
    let key2: FutexKey = (space.id, uaddr2);
    let deadline = futex_deadline(timeout_ns);
    let proc_arc = process::get_process(caller.pid).ok_or(FutexError::NoProcess)?;
    // RF178-8: the boost slot needed if this task later owns `uaddr2` with
    // waiters behind it. The requeue sets the wait edge.
    proc_arc
        .lock()
        .try_reserve_pi_boost(key2)
        .map_err(|()| FutexError::TooManyBuckets)?;
    let result = wait_requeue_pi_published(space, key, key2, expected, deadline, caller);
    let mut proc = proc_arc.lock();
    proc.set_waiting_on_futex(None);
    proc.cancel_pi_boost_reservation(&key2);
    result
}

fn wait_requeue_pi_published(
    space: &FutexSpace,
    key: FutexKey,
    key2: FutexKey,
    expected: u32,
    deadline: Option<u64>,
    caller: &PiCaller,
) -> Result<usize, FutexError> {
    let pid = caller.pid;
    let record = FutexWaiterRecord::requeue_pi(key2.1, pid as u32);
    let permit = FutexPreparePermit::acquire(space.id)?;
    clear_wait_marks(pid);
    let (bucket, queue) = publish_plain_waiter(key, space, record, expected, &permit)?;
    drop(permit);

    let mut result = Err(FutexError::WouldBlock);
    for attempt in 0..FUTEX_PI_ATTEMPTS {
        let prepared =
            queue.try_prepare_killable_with_timeout_after(remaining_timeout(deadline), || {
                if wake_mark_is_set(pid) {
                    Err(())
                } else {
                    Ok(())
                }
            });
        let outcome = match prepared {
            Ok(Ok(PrepareWait::Armed(ticket))) => queue.finish_prepared(ticket),
            Ok(Ok(PrepareWait::Immediate(outcome))) => outcome,
            Ok(Err(())) => WaitOutcome::Woken,
            Err(_) => WaitOutcome::ResourceExhausted,
        };
        // D2-2: a handler signal ends a killable sleep like a wake (its
        // sender readies the task); tell the two apart, with no lock held.
        let signal =
            outcome == WaitOutcome::Woken && kernel_core::signal::has_deliverable_signal(pid);
        let give_up = attempt + 1 == FUTEX_PI_ATTEMPTS;
        if let Some(done) = requeue_pi_wait_state(&bucket, key2, caller, outcome, signal, give_up) {
            result = done;
            break;
        }
    }

    // The task slept on the source queue throughout; leave it now.
    let _ = queue.cancel_wait();
    {
        let mut b = bucket.lock();
        b.waiter_count = b.waiter_count.saturating_sub(1);
    }
    cleanup_empty_bucket(key, &bucket);
    result
}

/// Linux `handle_early_requeue_pi_wakeup`: the result of a requeue-PI wait
/// that ended before any requeue.
fn early_requeue_pi_error(outcome: WaitOutcome) -> FutexError {
    match outcome {
        WaitOutcome::TimedOut => FutexError::TimedOut,
        WaitOutcome::Interrupted => FutexError::Interrupted,
        WaitOutcome::Woken => FutexError::WouldBlock,
        WaitOutcome::Closed | WaitOutcome::NoProcess => FutexError::NoProcess,
        WaitOutcome::ResourceExhausted => FutexError::TooManyBuckets,
    }
}

/// After a FUTEX_WAIT_REQUEUE_PI sleep on the source bucket: the result if
/// the wait is over, or None to sleep again: requeued, and the sleep ended
/// for no reason, or (review D2-2) not requeued yet, and a handler `signal`
/// ended it. `give_up` turns that None into EAGAIN.
fn requeue_pi_wait_state(
    source: &FutexBucketRef,
    key2: FutexKey,
    caller: &PiCaller,
    outcome: WaitOutcome,
    signal: bool,
    give_up: bool,
) -> Option<Result<usize, FutexError>> {
    enum Source {
        Left,
        StillWaiting,
        Moved,
    }

    let pid = caller.pid;
    // Still waiting on the source? A requeue moves the record only under
    // this lock, and a waker sets the mark under it.
    let (source_state, retired) = {
        let mut b = source.lock();
        let state = if wake_mark_is_set(pid) {
            Source::Moved
        } else {
            match b.record_position(pid as u32) {
                // Linux restarts the call (ERESTARTNOINTR) and waits again.
                Some(_) if signal && !give_up => Source::StillWaiting,
                Some(index) => {
                    b.waiters.remove_retaining_capacity(index);
                    Source::Left
                }
                None => Source::Moved,
            }
        };
        (state, b.waiters.take_empty_capacity())
    };
    drop(retired);
    match source_state {
        Source::StillWaiting => return None,
        Source::Left => return Some(Err(early_requeue_pi_error(outcome))),
        Source::Moved => {}
    }

    if !wake_mark_is_set(pid) {
        // Requeued onto the PI futex: a PI waiter there until a hand-off.
        if let Some(target) = lookup_bucket(key2) {
            let mut left = None;
            let (previous, retired) = {
                let mut b = target.lock();
                if !wake_mark_is_set(pid) && b.pi_waiters.contains_key(&pid) {
                    let error = match outcome {
                        WaitOutcome::Woken if !signal && !give_up => return None,
                        WaitOutcome::TimedOut => FutexError::TimedOut,
                        // A kill (the task is exiting) or an exec handoff.
                        WaitOutcome::Interrupted => FutexError::Interrupted,
                        // Linux: a signal after the requeue cannot restart
                        // the call (the source word changed); EWOULDBLOCK.
                        WaitOutcome::Woken => FutexError::WouldBlock,
                        WaitOutcome::Closed | WaitOutcome::NoProcess => FutexError::NoProcess,
                        WaitOutcome::ResourceExhausted => FutexError::TooManyBuckets,
                    };
                    left = Some(error);
                    let previous = b.pi_owner.map(|owner| owner.pid);
                    b.pi_waiters.remove_retaining_capacity(&pid);
                    b.settle_pi_state();
                    (previous, b.pi_waiters.take_empty_capacity())
                } else {
                    (None, None)
                }
            };
            drop(retired);
            if let Some(error) = left {
                refresh_pi_boosts(key2, &target, previous);
                cleanup_empty_bucket(key2, &target);
                return Some(Err(error));
            }
        }
    }

    // A waker resolved the wait (its marks were set under the lock of the
    // bucket that held the waiter, before it dropped it).
    Some(requeue_pi_resolved(key2, caller))
}

fn requeue_pi_resolved(key2: FutexKey, caller: &PiCaller) -> Result<usize, FutexError> {
    let pid = caller.pid;
    if PI_DEADLOCK_MARKS.is_set(pid) {
        return Err(FutexError::Deadlock);
    }
    if !PI_GRANT_MARKS.is_set(pid) {
        // Woken without the lock: user space takes the mutex itself.
        return Err(FutexError::WouldBlock);
    }
    // The caller owns `uaddr2`: store its TID if the lock came from an
    // owner's death, and take the remaining waiters' donation.
    let Some(target) = lookup_bucket(key2) else {
        return Ok(0);
    };
    let fixed = pi_fixup_owner(key2, &target, caller);
    refresh_pi_boosts(key2, &target, None);
    cleanup_empty_bucket(key2, &target);
    fixed.map(|()| 0)
}

/// FUTEX_CMP_REQUEUE_PI (`nr_wake` is 1, checked at decode): with `*uaddr1
/// == expected` (else EAGAIN), try to take the PI futex `uaddr2` for the
/// oldest waiter of `uaddr1` (Linux `futex_proxy_trylock_atomic`; it then
/// wakes as the owner), then move up to `nr_requeue` more waiters (one more
/// when the lock was not taken) onto `uaddr2`'s PI waiters, where they wait
/// for the lock. Every waiter must have called FUTEX_WAIT_REQUEUE_PI with
/// this `uaddr2` (else EINVAL). Returns the woken owner plus the requeued.
pub fn futex_cmp_requeue_pi(
    space: &FutexSpace,
    uaddr1: usize,
    uaddr2: usize,
    nr_requeue: usize,
    expected: u32,
    caller: &PiCaller,
) -> Result<usize, FutexError> {
    let key1: FutexKey = (space.id, uaddr1);
    let key2: FutexKey = (space.id, uaddr2);
    if key1 == key2 {
        return Err(FutexError::InvalidOperation);
    }
    for _ in 0..FUTEX_PI_ATTEMPTS {
        // Phase 1, no lock held: the target bucket and PI-waiter room for
        // the waiters that may move, and the owner the target word names.
        let queued = lookup_bucket(key1).map_or(0, |bucket| bucket.lock().waiters.len());
        let wanted = queued
            .min(nr_requeue.saturating_add(1))
            .min(MAX_FUTEX_WAITERS_PER_BUCKET);
        let named = read_user_u32(uaddr2)? & FUTEX_TID_MASK;
        let resolved = if named != 0 {
            caller.resolve(named)
        } else {
            None
        };
        let (created, mut prepared) = if wanted > 0 {
            prepare_requeue_pi_target(space, key2, wanted)?
        } else {
            (None, None)
        };

        // Phase 2: FUTEX_TABLE is held across the move, so a waiter that
        // looks for itself on the target never misses an entry in flight.
        let mut retired = None;
        let mut deferred = FutexDeferredWakes::new();
        let source: Option<FutexBucketRef>;
        let target: Option<FutexBucketRef>;
        let step = {
            let table = FUTEX_TABLE.lock();
            source = table.get(&key1).cloned();
            target = table.get(&key2).cloned();
            match source.as_ref() {
                None => {
                    RequeuePiStep::Done(check_requeue_compare(uaddr1, Some(expected)).map(|()| 0))
                }
                Some(source) => cmp_requeue_pi_pass(
                    (key1, source),
                    (key2, target.as_ref()),
                    nr_requeue,
                    expected,
                    (named, resolved),
                    &mut prepared,
                    &mut retired,
                    &mut deferred,
                ),
            }
        };
        drop(retired);
        drop(prepared);
        drop(created);
        let result = match step {
            // GAP-5 PI review D2-1: a word faulted under the locks before
            // anything moved. Fault both in with no lock held and retry.
            RequeuePiStep::Done(Err(FutexError::WordFault)) => fault_in_word(uaddr1, false)
                .and_then(|()| fault_in_word(uaddr2, true))
                .err()
                .map(Err),
            RequeuePiStep::Done(result) => Some(result),
            RequeuePiStep::Retry => None,
            RequeuePiStep::OwnerExiting(owner, generation) => {
                wait_for_pi_owner_exit(owner, generation, space.id, caller.pid, None)
                    .err()
                    .map(Err)
            }
        };
        if let Some(target) = target.as_ref() {
            // The new owner (or the existing one) gets the requeued
            // waiters' donation before a granted waiter is woken.
            refresh_pi_boosts(key2, target, None);
        }
        deferred.run(space.id);
        if let Some(source) = source.as_ref() {
            cleanup_empty_bucket(key1, source);
        }
        if let Some(target) = target.as_ref() {
            cleanup_empty_bucket(key2, target);
        }
        if let Some(result) = result {
            return result;
        }
    }
    Err(FutexError::WouldBlock)
}

enum RequeuePiStep {
    Done(Result<usize, FutexError>),
    Retry,
    OwnerExiting(ProcessId, u64),
}

/// Get (or create) the requeue-PI target and PI-waiter backing for `wanted`
/// more waiters.
fn prepare_requeue_pi_target(
    space: &FutexSpace,
    key: FutexKey,
    wanted: usize,
) -> Result<(Option<FutexBucketRef>, Option<PreparedPiWaiterCapacity>), FutexError> {
    let permit = FutexPreparePermit::acquire(space.id)?;
    let target = get_or_create_live_bucket(key, &permit, space.pin.as_ref())?;
    drop(permit);
    let (len, capacity) = {
        let b = target.lock();
        (b.pi_waiters.len(), b.pi_waiters.capacity())
    };
    match prepare_pi_waiter_growth(len, capacity, wanted) {
        Ok(prepared) => Ok((Some(target), prepared)),
        Err(error) => {
            cleanup_empty_bucket(key, &target);
            Err(error)
        }
    }
}

/// A requeue-PI waiter's TID and priority, read under its PCB lock, which
/// also points its PI wait edge at `key2` when `requeued` (bucket ->
/// PROCESS_TABLE -> PCB). None: the task is gone or exiting.
fn requeue_pi_waiter_info(
    pid: ProcessId,
    key2: FutexKey,
    requeued: bool,
) -> Option<(u32, Priority)> {
    let proc_arc = process::get_process(pid)?;
    let mut proc = proc_arc.lock();
    if matches!(
        proc.state,
        process::ProcessState::Zombie | process::ProcessState::Terminated
    ) {
        return None;
    }
    let tid = kernel_core::pid_in_owning_namespace(&proc.pid_ns_chain)?;
    if requeued {
        proc.set_waiting_on_futex(Some(key2));
    }
    Some((tid as u32 & FUTEX_TID_MASK, proc.dynamic_priority))
}

/// The locked part of FUTEX_CMP_REQUEUE_PI. The caller holds `FUTEX_TABLE`;
/// the two bucket locks are taken in ascending key order.
#[allow(clippy::too_many_arguments)]
fn cmp_requeue_pi_pass(
    (key1, source): (FutexKey, &FutexBucketRef),
    (key2, target): (FutexKey, Option<&FutexBucketRef>),
    nr_requeue: usize,
    expected: u32,
    (named, resolved): (u32, Option<(ProcessId, u64)>),
    prepared: &mut Option<PreparedPiWaiterCapacity>,
    retired: &mut Option<RetiredPiWaiterCapacity>,
    deferred: &mut FutexDeferredWakes,
) -> RequeuePiStep {
    let Some(target) = target else {
        // No target: fine only if there is nobody to requeue.
        let src = source.lock();
        return match check_requeue_compare(key1.1, Some(expected)) {
            Err(error) => RequeuePiStep::Done(Err(error)),
            Ok(()) if src.waiters.is_empty() => RequeuePiStep::Done(Ok(0)),
            Ok(()) => RequeuePiStep::Retry,
        };
    };
    let (mut src, mut tgt) = if key2 < key1 {
        let tgt = target.lock();
        (source.lock(), tgt)
    } else {
        let src = source.lock();
        (src, target.lock())
    };
    if let Err(error) = check_requeue_compare(key1.1, Some(expected)) {
        return RequeuePiStep::Done(Err(error));
    }
    if tgt.unlinked {
        return RequeuePiStep::Retry;
    }
    // Room for every waiter this pass can move, installed from the backing
    // prepared in phase 1; a snapshot that raced a growth prepares again.
    let movable = src
        .waiters
        .len()
        .min(nr_requeue.saturating_add(1))
        .min(MAX_FUTEX_WAITERS_PER_BUCKET.saturating_sub(tgt.pi_waiters.len()));
    if !ensure_pi_waiter_capacity(&mut tgt.pi_waiters, movable, prepared, retired) {
        return RequeuePiStep::Retry;
    }
    let mut lookup = |pid: ProcessId, requeued: bool| requeue_pi_waiter_info(pid, key2, requeued);
    let result = requeue_pi_locked(
        &mut src,
        key1.1,
        &mut tgt,
        (key2, &LockedUserWord(key2.1)),
        nr_requeue,
        (named, resolved),
        &mut lookup,
        deferred,
    );
    tgt.settle_pi_state();
    result
}

/// Under both bucket locks: the proxy lock for the top waiter of `src`,
/// then the requeue loop (Linux `futex_requeue` with `requeue_pi`). `info`
/// returns a waiter's TID and priority (None: it is gone) and, when asked,
/// points its wait edge at the target.
#[allow(clippy::too_many_arguments)]
fn requeue_pi_locked(
    src: &mut FutexBucket,
    uaddr1: usize,
    tgt: &mut FutexBucket,
    (key2, word2): (FutexKey, &dyn LockedWord),
    nr_requeue: usize,
    (named, resolved): (u32, Option<(ProcessId, u64)>),
    info: &mut dyn FnMut(ProcessId, bool) -> Option<(u32, Priority)>,
    deferred: &mut FutexDeferredWakes,
) -> RequeuePiStep {
    let uaddr2 = key2.1;
    let (top_pid, top_tid, top_priority) = match requeue_pi_top_locked(src, uaddr2, info) {
        Ok(Some(top)) => top,
        Ok(None) => return RequeuePiStep::Done(Ok(0)),
        Err(error) => return RequeuePiStep::Done(Err(error)),
    };

    // Linux futex_proxy_trylock_atomic: take `uaddr2` for the top waiter,
    // setting WAITERS when more waiters may follow it. R191-1: the proxy
    // attach checks the owner's identity like FUTEX_LOCK_PI.
    let take = pi_take_or_attach_locked(
        tgt,
        word2,
        key2.0,
        top_pid,
        top_tid,
        nr_requeue > 0,
        named,
        resolved,
    );
    let acquired = match take {
        Ok(PiTake::Taken) => {
            src.waiters.pop_front_retaining_capacity();
            let waiter = PiWaiter {
                origin: uaddr1,
                seq: tgt.next_pi_seq(),
                tid: top_tid,
                priority: top_priority,
            };
            // The PI state the requeued waiters attach to belongs to the new
            // owner; with none to follow it is dropped again afterwards.
            grant_pi_waiter_locked(tgt, top_pid, waiter, false, deferred);
            true
        }
        Ok(PiTake::Attached) => false,
        Ok(PiTake::Retry) => return RequeuePiStep::Retry,
        Ok(PiTake::OwnerExiting(owner, generation)) => {
            return RequeuePiStep::OwnerExiting(owner, generation)
        }
        // EDEADLK (the word names the top waiter), EINVAL, ESRCH, and a
        // word fault (retried by the caller): the top waiter is left
        // waiting; the error is the requeuer's.
        Err(error) => return RequeuePiStep::Done(Err(error)),
    };

    // Linux requeues up to nr_requeue waiters, one more when the top waiter
    // did not get the lock (it is requeued too).
    let limit = if acquired {
        nr_requeue
    } else {
        nr_requeue.saturating_add(1)
    };
    let moved = requeue_pi_move_locked(src, uaddr1, tgt, uaddr2, limit, info, deferred);
    RequeuePiStep::Done(moved.map(|requeued| usize::from(acquired) + requeued))
}

/// The top waiter of a requeue-PI source: its oldest record, which must be
/// a FUTEX_WAIT_REQUEUE_PI waiter for `uaddr2` (else EINVAL). Records of
/// tasks that died inside the wait are dropped (reap-time cleanup would drop
/// them too). Returns its PID, TID and priority.
fn requeue_pi_top_locked(
    src: &mut FutexBucket,
    uaddr2: usize,
    info: &mut dyn FnMut(ProcessId, bool) -> Option<(u32, Priority)>,
) -> Result<Option<(ProcessId, u32, Priority)>, FutexError> {
    loop {
        let Some(record) = src.waiters.front().copied() else {
            return Ok(None);
        };
        if record.requeue_pi_target() != Some(uaddr2) {
            return Err(FutexError::InvalidOperation);
        }
        let pid = record.pid as ProcessId;
        match info(pid, false) {
            Some((tid, priority)) => return Ok(Some((pid, tid, priority))),
            None => {
                src.waiters.pop_front_retaining_capacity();
            }
        }
    }
}

/// Wake a requeue-PI waiter whose record was taken off `src` (at `uaddr1`,
/// where it sleeps) without making it the owner. The wake runs after every
/// lock is dropped, like a grant's.
fn defer_requeue_pi_wake(pid: ProcessId, uaddr1: usize, deferred: &mut FutexDeferredWakes) {
    set_wake_mark(pid);
    deferred.push(uaddr1, pid as u32);
}

/// The requeue loop: move up to `limit` FUTEX_WAIT_REQUEUE_PI waiters of
/// `src`, oldest first, onto `tgt`'s PI waiters (they keep sleeping on
/// `src`'s queue). Stops with EINVAL at a waiter that is not one for
/// `uaddr2`, and with EDEADLK at a waiter that owns the PI state (woken with
/// EDEADLK). A waiter that finds `tgt` at its PI-waiter bound (or without
/// backing) is woken without the lock (EAGAIN) and still counted, as Linux
/// counts every waiter it handled. Returns how many it handled.
fn requeue_pi_move_locked(
    src: &mut FutexBucket,
    uaddr1: usize,
    tgt: &mut FutexBucket,
    uaddr2: usize,
    limit: usize,
    info: &mut dyn FnMut(ProcessId, bool) -> Option<(u32, Priority)>,
    deferred: &mut FutexDeferredWakes,
) -> Result<usize, FutexError> {
    let mut requeued = 0usize;
    while requeued < limit {
        let Some(record) = src.waiters.front().copied() else {
            break;
        };
        if record.requeue_pi_target() != Some(uaddr2) {
            return Err(FutexError::InvalidOperation);
        }
        src.waiters.pop_front_retaining_capacity();
        let pid = record.pid as ProcessId;
        if tgt.pi_owner.is_some_and(|owner| owner.pid == pid) {
            // It owns the PI futex: Linux wakes it with EDEADLK and stops.
            PI_DEADLOCK_MARKS.set(pid);
            defer_requeue_pi_wake(pid, uaddr1, deferred);
            return Err(FutexError::Deadlock);
        }
        let fits = tgt.pi_owner.is_some()
            && tgt.pi_waiters.len() < MAX_FUTEX_WAITERS_PER_BUCKET
            && tgt.pi_waiters.len() < tgt.pi_waiters.capacity();
        let Some((tid, priority)) = info(pid, fits) else {
            // Died inside the wait: drop the stale record.
            continue;
        };
        let waiter = PiWaiter {
            origin: uaddr1,
            seq: tgt.next_pi_seq(),
            tid,
            priority,
        };
        if !(fits && insert_pi_waiter_locked(&mut tgt.pi_waiters, pid, waiter)) {
            // No room on the PI futex: woken without the lock (EAGAIN).
            defer_requeue_pi_wake(pid, uaddr1, deferred);
        }
        requeued += 1;
    }
    Ok(requeued)
}

/// 清理进程的所有 futex 等待队列
///
/// 进程/线程退出时调用，唤醒所有等待者并移除该进程的所有 futex 条目。
///
/// GAP-5 futex parity: buckets are keyed by address space, which the reaped
/// task can share with tasks of other thread groups (CLONE_VM), so the
/// per-task passes walk every bucket (the table holds at most
/// MAX_FUTEX_BUCKETS_GLOBAL) and a space's buckets are unlinked only once no
/// task uses that address space (this replaces the R37-2/R178-19 rule that
/// kept a TGID's buckets while a CLONE_THREAD sibling lived).
///
/// E.4 PI / GAP-5 PI parity: 如果退出的线程仍持有内核 PI 状态，把锁交给最高
/// 优先级（同优先级先到先得）的等待者，由它在自己的上下文里把 TID 写进用户字
/// （[`release_pi_states_of`]；通常退出回调已经做过）。只唤醒继任者以保持互斥。
///
/// R37-2 FIX (Codex review): Accept TGID directly from caller to avoid deadlock.
/// The caller (free_process_resources) already holds the process lock, so we must
/// not try to lock the process again.
///
/// # R72-1 FIX: Waiter Cleanup
///
/// Previously, this function only handled the exiting thread when it was the futex
/// owner. If the thread was a waiter (in pi_waiters and/or WaitQueue), its entry
/// was left behind. This is dangerous because:
///
/// 1. The PID may be reused by a new process
/// 2. When the owner unlocks, `select_top_pi_waiter()` may return the stale PID
/// 3. `wake_specific()` would try to wake the new (unrelated) process
/// 4. The real waiters would never be woken, causing deadlock
///
/// Now we clean up waiter entries first, before handling owner cleanup.
fn next_bucket(after: Option<FutexKey>) -> Option<(FutexKey, FutexBucketRef)> {
    let table = FUTEX_TABLE.lock();
    let lower = match after {
        Some(key) => Bound::Excluded(key),
        None => Bound::Unbounded,
    };
    let next = table
        .range((lower, Bound::Unbounded))
        .next()
        .map(|(key, bucket)| (*key, bucket.clone()));
    next
}

/// RF178-8: unlink one bucket whose address space is gone, without a key
/// snapshot Vec. The tombstone and removal remain atomic under the
/// established table->bucket lock order. Its records belong to tasks that no
/// longer exist and go with it.
fn unlink_first_dead_space_bucket() -> Option<FutexQueueRef> {
    let (queue, removed, retired, retired_records) = {
        let mut table = FUTEX_TABLE.lock();
        let key = table
            .iter()
            .find(|(_, bucket)| bucket.lock().space_is_dead())
            .map(|(key, _)| *key)?;
        let (queue, retired_records) = {
            let bucket = table
                .get(&key)
                .expect("RF180-47 selected futex bucket disappeared under table lock");
            let mut bucket = bucket.lock();
            bucket.unlinked = true;
            bucket.waiters.clear_retaining_capacity();
            (bucket.queue.clone(), bucket.waiters.take_empty_capacity())
        };
        let removed = table.remove_retaining_capacity(&key);
        let retired = table.take_empty_capacity();
        (queue, removed, retired, retired_records)
    };
    drop(retired_records);
    drop(retired);
    drop(removed);
    Some(queue)
}

/// R180-5 FIX: generation-bound process futex cleanup.
///
/// `generation` is the reaped PCB generation captured before the table slot was
/// cleared. If a live PCB at `pid` has a different generation, skip all
/// PID-keyed waiter/owner mutations for that pid (successor already owns it).
/// The dead-address-space sweep still runs: it depends on no PID.
pub fn cleanup_process_futexes(pid: ProcessId, tgid: ProcessId, generation: u64) {
    // GAP-5 futex parity: the key space is the address space, not the TGID;
    // the TGID is no longer needed here.
    let _ = tgid;

    // R180-5: if a successor already occupies this PID, do not strip its
    // waiters / PI / ownership. Still drain process-gen-stamped WaitQueue
    // entries for the reaped identity via queue.cleanup_for_identity below.
    let successor_live = process::get_process(pid)
        .map(|p| p.lock().generation != generation)
        .unwrap_or(false);

    // R72-1 FIX: Clean up this PID from ALL waiter lists (even if not owner).
    // This prevents stale PID references from poisoning futex state after PID reuse.
    {
        let mut after = None;
        while let Some((key, bucket)) = next_bucket(after) {
            after = Some(key);
            if successor_live {
                // Only generation-bound WaitQueue drain — no pi_waiters / owner
                // mutation against a live successor.
                let queue = {
                    let b = bucket.lock();
                    b.queue.clone()
                };
                queue.cleanup_for_identity(pid, generation);
                continue;
            }

            // GAP-5 futex parity: a plain-wait record of this task, and its
            // PI-waiter entry. A task removes its own (or a waker or granter
            // does) before its wait ends, so only a task that died inside a
            // wait could leave one. Its waiter_count attachment belongs to
            // the bucket it slept on: settled with the queue entry below, or
            // here for a PI entry whose task slept on this bucket.
            let (queue, previous_owner, attached_pi, retired_records, retired_pi) = {
                let mut b = bucket.lock();
                b.waiters
                    .retain_capacity(|record| record.pid as ProcessId != pid);
                let retired_records = b.waiters.take_empty_capacity();
                let previous_owner = b.pi_owner.map(|owner| owner.pid);
                let (removed, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
                b.settle_pi_state();
                let attached_pi = removed.is_some_and(|waiter| waiter.origin == key.1);
                (
                    b.queue.clone(),
                    removed.is_some().then_some(previous_owner).flatten(),
                    attached_pi,
                    retired_records,
                    retired_pi,
                )
            };
            drop(retired_records);
            drop(retired_pi);

            // Remove from WaitQueue (this handles non-PI waiters too)
            // wake_specific returns true if the PID was found and removed
            let was_in_queue = queue.wake_specific(pid);
            // Also drain process-generation-stamped entries for this identity.
            queue.cleanup_for_identity(pid, generation);

            // R72-1 FIX (Codex review): Only decrement waiter_count once.
            // A process waiting on a PI futex is counted once in waiter_count,
            // even though it appears in both pi_waiters and WaitQueue.
            if attached_pi || was_in_queue {
                let mut b = bucket.lock();
                if b.waiter_count > 0 {
                    b.waiter_count -= 1;
                }
            }

            // A removed PI waiter no longer donates to the owner.
            if previous_owner.is_some() {
                refresh_pi_boosts(key, &bucket, previous_owner);
            }

            // Try to clean up empty bucket
            cleanup_empty_bucket(key, &bucket);
        }
    }

    // E.4 PI / GAP-5 PI parity: a PI state this task still owns is handed to
    // its top waiter. The exit callback normally did this already, right
    // after the robust walk; this pass finds a state it could not see.
    // R180-5: never transfer PI ownership when a successor already owns the PID.
    if !successor_live {
        release_pi_states_of(pid);
    }

    // GAP-5 futex parity (replaces the R178-19 last-thread-of-TGID unlink):
    // unlink the buckets of every address space no task uses any more. The
    // reaped task's PCB still holds its address space during this callback,
    // so its own space's leftovers go on a later pass; the bucket's pin keeps
    // that space id from being reused meanwhile. Live spaces are untouched,
    // so this pass needs no PID identity (and runs under R180-5 too).
    // RF178-8: stream removals; exit never allocates a key/bucket snapshot.
    while let Some(queue) = unlink_first_dead_space_bucket() {
        queue.wake_all();
    }
}

/// 获取或创建指定键的等待桶
type PreparedFutexTableCapacity = PreparedAdmittedMapCapacity<FutexKey, FutexBucketRef>;
type RetiredFutexTableCapacity = RetiredAdmittedMapCapacity<FutexKey, FutexBucketRef>;

enum FutexBucketPublish {
    Ready(FutexBucketRef),
    RetryCapacity,
    Limit,
}

fn publish_futex_bucket_candidate(
    table: &Mutex<AdmittedMap<FutexKey, FutexBucketRef>>,
    key: FutexKey,
    candidate: &mut Option<FutexBucketRef>,
    prepared: &mut Option<PreparedFutexTableCapacity>,
    retired: &mut Option<RetiredFutexTableCapacity>,
) -> FutexBucketPublish {
    let mut table = table.lock();
    if let Some(existing) = table.get(&key) {
        return FutexBucketPublish::Ready(existing.clone());
    }

    let space = key.0;
    let space_live = table.range((space, 0)..=(space, usize::MAX)).count();
    if table.len() >= MAX_FUTEX_BUCKETS_GLOBAL || space_live >= MAX_FUTEX_BUCKETS_PER_SPACE {
        return FutexBucketPublish::Limit;
    }

    if table.len() == table.capacity() {
        let Some(backing) = prepared.take() else {
            return FutexBucketPublish::RetryCapacity;
        };
        if backing.class() != table.class() || backing.capacity() <= table.len() {
            *prepared = Some(backing);
            return FutexBucketPublish::RetryCapacity;
        }
        debug_assert!(retired.is_none());
        *retired = Some(
            table
                .install_prepared_deferred(backing)
                .expect("RF180-47 futex table prepared-capacity invariant"),
        );
    }

    let owner = candidate
        .take()
        .expect("futex bucket candidate consumed once");
    match table.insert_unique_reserved(key, owner) {
        Ok(()) => FutexBucketPublish::Ready(
            table
                .get(&key)
                .expect("RF180-47 published futex bucket missing")
                .clone(),
        ),
        Err((_key, owner)) => {
            *candidate = Some(owner);
            FutexBucketPublish::RetryCapacity
        }
    }
}

fn get_or_create_bucket_with_permit(
    key: FutexKey,
    _permit: &FutexPreparePermit,
    space_pin: Option<&Weak<Mutex<MmState>>>,
) -> Result<FutexBucketRef, FutexError> {
    {
        let table = FUTEX_TABLE.lock();
        if let Some(bucket) = table.get(&key) {
            return Ok(bucket.clone());
        }
        let space_live = table.range((key.0, 0)..=(key.0, usize::MAX)).count();
        if table.len() >= MAX_FUTEX_BUCKETS_GLOBAL || space_live >= MAX_FUTEX_BUCKETS_PER_SPACE {
            return Err(FutexError::TooManyBuckets);
        }
    }

    let queue = try_new_futex_arc(WaitQueue::new(HeapClass::Futex))?;
    let mut candidate = Some(try_new_futex_arc(Mutex::new(FutexBucket::new(
        queue,
        space_pin.cloned(),
    )))?);

    for _ in 0..FUTEX_REVALIDATE_RETRIES {
        let (len, capacity) = {
            let table = FUTEX_TABLE.lock();
            (table.len(), table.capacity())
        };
        let mut prepared = prepare_futex_map_growth::<FutexKey, FutexBucketRef>(len, capacity)?;
        let mut retired = None;
        let outcome = publish_futex_bucket_candidate(
            &FUTEX_TABLE,
            key,
            &mut candidate,
            &mut prepared,
            &mut retired,
        );
        drop(retired);
        drop(prepared);
        match outcome {
            FutexBucketPublish::Ready(bucket) => return Ok(bucket),
            FutexBucketPublish::RetryCapacity => continue,
            FutexBucketPublish::Limit => return Err(FutexError::TooManyBuckets),
        }
    }
    Err(FutexError::TooManyBuckets)
}

/// Hosted tests only: a bucket without a space pin, which a live kernel must
/// never create (its space id could be reused by a new address space).
#[cfg(test)]
fn get_or_create_bucket(key: FutexKey) -> Result<FutexBucketRef, FutexError> {
    let permit = FutexPreparePermit::try_acquire(key.0)?;
    get_or_create_bucket_with_permit(key, &permit, None)
}

/// 清理空的等待桶（无等待者时移除）
///
/// E.4 PI: 额外检查 owner 和 pi_waiters 是否为空
fn cleanup_empty_bucket(key: FutexKey, bucket: &FutexBucketRef) {
    // R172-07/08 FIX: TABLE-first then bucket (the established table->bucket lock order, e.g.
    // take_moved_record / futex_drop_space), so publishing the `unlinked`
    // tombstone and removing the table entry are ATOMIC w.r.t. any bucket-lock holder. This
    // closes the get_or_create_bucket(drop table) -> claim-under-bucket-lock window: a
    // first-publish site holding a stale Arc either observes unlinked==false on a still-
    // resident bucket (and its waiter_count++/owner-set then makes the bucket non-empty, so
    // this emptiness gate fails and it is never reaped out from under it), or observes
    // unlinked==true and retries get_or_create_bucket for the live entry. (Previously this
    // took bucket-then-table with the table re-checked separately, leaving the stale-Arc
    // revival gap the audit found.)
    let mut removed = None;
    let mut retired = None;
    {
        let mut table = FUTEX_TABLE.lock();
        if let Some(existing) = table.get(&key) {
            // 确保是同一个桶（防止竞态条件下移除新创建的桶）
            if Arc::ptr_eq(existing, bucket) {
                let mut b = bucket.lock();
                // E.4 PI: 只有当 owner、等待者、队列都为空时才清理. GAP-5 futex
                // parity: also no plain-waiter record; a requeued waiter keeps
                // its origin bucket through the queue entry and waiter_count.
                if b.waiter_count == 0
                    && b.waiters.is_empty()
                    && b.queue.is_empty()
                    && b.pi_owner.is_none()
                    && b.pi_waiters.is_empty()
                {
                    b.unlinked = true; // tombstone published atomically with the removal below
                    drop(b);
                    removed = table.remove_retaining_capacity(&key);
                    retired = table.take_empty_capacity();
                }
            }
        }
    }
    drop(retired);
    drop(removed);
}

/// GAP-5 futex parity (exec): unlink every bucket of key space `space` (a
/// [`FutexSpace`] id, `FutexSpace::id_of_mm(&proc.mm)`) that no task waits
/// on, together with any kernel PI state it still holds. Exec keeps the
/// task's `MmState`, so without this a futex word of the new image at an old
/// address would meet the old image's state. The caller runs after exec has
/// ended every other task of the space, so normally every bucket goes; a
/// bucket that a task is still attached to, or that holds a record or a PI
/// waiter, is left in place. Returns how many were left (0 expected).
///
/// Lock order FUTEX_TABLE -> bucket, one bucket per table-lock hold; the
/// unlinked buckets and table backing are freed with no lock held, and no
/// allocation is made. Call from process context with no futex lock held.
pub fn futex_drop_space(space: usize) -> usize {
    let mut left = 0usize;
    let mut after: Option<FutexKey> = None;
    loop {
        let lower = match after {
            Some(key) => Bound::Excluded(key),
            None => Bound::Included((space, 0)),
        };
        let (removed, retired, retired_records, retired_pi) = {
            let mut table = FUTEX_TABLE.lock();
            let Some((key, bucket)) = table
                .range((lower, Bound::Included((space, usize::MAX))))
                .next()
                .map(|(key, bucket)| (*key, bucket.clone()))
            else {
                break;
            };
            after = Some(key);
            let unlinked = {
                let mut b = bucket.lock();
                let idle = b.waiter_count == 0
                    && b.waiters.is_empty()
                    && b.queue.is_empty()
                    && b.pi_waiters.is_empty();
                if idle {
                    // The tombstone is published with the removal below, as
                    // in cleanup_empty_bucket; a pending fixup or an owner
                    // with no waiter left goes with the bucket.
                    b.unlinked = true;
                    b.pi_owner = None;
                    Some((
                        b.waiters.take_empty_capacity(),
                        b.pi_waiters.take_empty_capacity(),
                    ))
                } else {
                    None
                }
            };
            match unlinked {
                Some((retired_records, retired_pi)) => (
                    table.remove_retaining_capacity(&key),
                    table.take_empty_capacity(),
                    retired_records,
                    retired_pi,
                ),
                None => {
                    left += 1;
                    (None, None, None, None)
                }
            }
        };
        drop(retired_records);
        drop(retired_pi);
        drop(retired);
        drop(removed);
    }
    left
}

/// 获取活跃的 futex 地址数量（调试用）
pub fn active_futex_count() -> usize {
    FUTEX_TABLE.lock().len()
}

/// FutexTable 类型别名（向后兼容）
pub type FutexTable = ();

// ============================================================================
// E.4 PI: 内部辅助函数（优先级继承支持）
// ============================================================================

/// Remove PI waiters whose PCB has already reached a terminal state before a
/// successor is selected.  A task can become `Zombie` between the normal
/// per-PID cleanup pass and the owner's handoff; leaving that entry in
/// `pi_waiters` lets `select_top_pi_waiter` grant the mutex to a dead task and
/// can strand every live waiter behind it.  The scan/removal is entirely
/// allocation-free because the admitted map retains its backing capacity.
fn prune_dead_pi_waiters_locked(bucket: &mut FutexBucket) {
    loop {
        let dead = bucket.pi_waiters.iter().find_map(|(waiter, _)| {
            let is_dead = match process::get_process(*waiter) {
                None => true,
                Some(proc_arc) => matches!(
                    proc_arc.lock().state,
                    process::ProcessState::Zombie | process::ProcessState::Terminated
                ),
            };
            is_dead.then_some(*waiter)
        });
        match dead {
            Some(waiter) => {
                bucket.pi_waiters.remove_retaining_capacity(&waiter);
            }
            None => break,
        }
    }
}

/// E.4 PI: 获取当前最高优先级等待者的优先级（仅优先级值）
fn highest_waiter_priority(bucket: &FutexBucket) -> Option<Priority> {
    bucket
        .pi_waiters
        .values()
        .map(|waiter| waiter.priority)
        .min()
}

/// E.4 PI: Maximum number of distinct owners that can occur in a live chain.
///
/// A live owner PID is admitted in the bounded process table, so using the
/// table's PID ceiling as the walk bound covers every valid acyclic chain. The
/// previous depth-64 cutoff could stop before reaching the CPU holder and leave
/// it unboosted (U34-3). Cycle detection below keeps malformed cyclic graphs
/// bounded without allocating a heap set.
const MAX_PI_CHAIN_DEPTH: usize = process::PID_MAX;
const PI_VISITED_WORDS: usize = (MAX_PI_CHAIN_DEPTH + 1).div_ceil(64);
const _: () = assert!(PI_VISITED_WORDS * 64 > process::PID_MAX);

/// What one PI-boost step did under its bucket lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiHop {
    /// Nothing more to do: no owner, the owner is gone, or it waits on no
    /// other PI futex.
    Done,
    /// The owner has no room for a new boost entry: reserve it with no
    /// futex lock held, then redo the step.
    NeedsRoom(ProcessId),
    /// The owner `waiter` waits on the PI futex `key`: carry its priority
    /// there (read live under that bucket's lock, review D3-B).
    Next { waiter: ProcessId, key: FutexKey },
}

/// Give the PI owner of `key` the best remaining donation, take the
/// donation back from `previous` if that task no longer owns the PI state,
/// and carry the owner's new priority along its own wait edge (chained PI).
///
/// GAP-5 PI review D3: each step updates the owner's entry under the lock
/// of the bucket whose waiters it reflects (bucket -> PROCESS_TABLE -> PCB),
/// so refreshes of one bucket apply in the order of the states they read,
/// and the last one matches the final state. Before, a refresh applied its
/// snapshot after the lock, and an older snapshot could land last and leave
/// a stale boost. A chain step also records the waiter's new priority in
/// its `PiWaiter` entry, so a later refresh of that bucket keeps it.
///
/// D4: a removal or a replacement never allocates; an owner that took the
/// lock in user space may have no room for a new entry. Room is then
/// reserved under its PCB lock with no futex lock held and the step redone;
/// without memory the owner runs without the donation (logged), which never
/// fails the waiter.
///
/// RF178-8: the chain has out-degree one (`waiting_on_futex`); a fixed owner
/// bitmap bounds it and stops at a cycle. Nothing is allocated here except
/// that boost room.
fn refresh_pi_boosts(key: FutexKey, bucket: &FutexBucketRef, previous: Option<ProcessId>) {
    let mut resched = false;
    let mut previous_hop = PiHop::Done;
    let owner_hop = pi_boost_step(
        key,
        Some(bucket),
        None,
        previous,
        &mut previous_hop,
        &mut resched,
    );
    // GAP-5 PI review D3-B: a task that lost its donation here may itself
    // wait on another PI futex (a waiter that timed out, or one requeued);
    // its lower priority is carried along its own wait edge too.
    walk_pi_chain(owner_hop, &mut resched);
    walk_pi_chain(previous_hop, &mut resched);
    if resched {
        request_resched_from_irq();
    }
}

/// Follow one wait edge of [`refresh_pi_boosts`] owner by owner. Not inlined:
/// each call holds a PID bitmap, and `refresh_pi_boosts` makes two.
#[inline(never)]
fn walk_pi_chain(mut next: PiHop, resched: &mut bool) {
    let mut visited_owners = [0u64; PI_VISITED_WORDS];
    let mut steps = 0usize;
    while let PiHop::Next {
        waiter,
        key: next_key,
    } = next
    {
        if waiter == 0 || waiter > process::PID_MAX || steps == MAX_PI_CHAIN_DEPTH {
            break;
        }
        let (word, bit) = (waiter / 64, 1u64 << (waiter % 64));
        if visited_owners[word] & bit != 0 {
            // A cyclic wait-for graph (an ABBA deadlock, which Linux refuses
            // with EDEADLK): every owner on it has had the donation.
            break;
        }
        visited_owners[word] |= bit;
        steps += 1;
        let mut unused = PiHop::Done;
        next = pi_boost_step(next_key, None, Some(waiter), None, &mut unused, resched);
    }
}

/// One step of [`refresh_pi_boosts`] on `key` (its bucket, if the caller
/// has it), redone once after reserving room for the owner's entry.
fn pi_boost_step(
    key: FutexKey,
    bucket: Option<&FutexBucketRef>,
    from: Option<ProcessId>,
    previous: Option<ProcessId>,
    previous_hop: &mut PiHop,
    resched: &mut bool,
) -> PiHop {
    let bucket = match bucket {
        Some(bucket) => bucket.clone(),
        None => match lookup_bucket(key) {
            Some(bucket) => bucket,
            None => return PiHop::Done,
        },
    };
    for attempt in 0..2 {
        let hop = {
            let mut b = bucket.lock();
            pi_boost_step_locked(&mut b, key, from, previous, previous_hop, resched)
        };
        match hop {
            PiHop::NeedsRoom(owner) if attempt == 0 && reserve_pi_boost_room(owner, key) => {}
            PiHop::NeedsRoom(_) => break,
            hop => return hop,
        }
    }
    kprintln!(
        "[FUTEX] GAP-5 PI: no memory for the donation to the owner of {:?}",
        key
    );
    PiHop::Done
}

/// Under the bucket lock of `key`: record the chain waiter's priority
/// (`from`), take `previous`'s donation back (its own wait edge goes to
/// `previous_hop`), and give the owner the best waiter's priority.
fn pi_boost_step_locked(
    b: &mut FutexBucket,
    key: FutexKey,
    from: Option<ProcessId>,
    previous: Option<ProcessId>,
    previous_hop: &mut PiHop,
    resched: &mut bool,
) -> PiHop {
    if let Some(waiter) = from {
        let Some(entry) = b.pi_waiters.get_mut(&waiter) else {
            // It left (or owns the lock) meanwhile; whatever changed the
            // bucket refreshes it.
            return PiHop::Done;
        };
        // GAP-5 PI review D3-B: the waiter's live priority, read under this
        // bucket's lock (bucket -> PROCESS_TABLE -> PCB), not a snapshot
        // taken upstream: whichever of several refreshes lands here last
        // records the current value.
        match process::get_process(waiter) {
            Some(proc_arc) => entry.priority = proc_arc.lock().dynamic_priority,
            None => return PiHop::Done,
        }
    }
    let owner = b.pi_owner.map(|owner| owner.pid);
    if let Some(previous) = previous.filter(|previous| owner != Some(*previous)) {
        // A removal never needs room.
        *previous_hop = set_pi_boost_locked(previous, key, None, resched);
    }
    match owner {
        Some(owner) => set_pi_boost_locked(owner, key, highest_waiter_priority(b), resched),
        None => PiHop::Done,
    }
}

/// Under a bucket lock (bucket -> PROCESS_TABLE -> PCB): set `pid`'s boost
/// for `key` without allocating, and report its wait edge.
fn set_pi_boost_locked(
    pid: ProcessId,
    key: FutexKey,
    donation: Option<Priority>,
    resched: &mut bool,
) -> PiHop {
    let Some(proc_arc) = process::get_process(pid) else {
        return PiHop::Done;
    };
    let mut proc = proc_arc.lock();
    if donation.is_some() && pi_boost_room_needed(&proc, key) > 0 {
        return PiHop::NeedsRoom(pid);
    }
    // Room was checked above, so this cannot fail or allocate.
    if proc.try_update_pi_boost(key, donation).unwrap_or(false) {
        *resched = true;
    }
    match proc.get_waiting_on_futex() {
        Some(next) if next != key => PiHop::Next {
            waiter: pid,
            key: next,
        },
        _ => PiHop::Done,
    }
}

/// Entries `try_update_pi_boost(key, Some(_))` would have to add room for:
/// none for a replacement or for the insertion that consumes `key`'s
/// reservation, else one plus the slot it keeps for another key's
/// reservation (its `try_reserve`), minus the room already there.
fn pi_boost_room_needed(proc: &process::Process, key: FutexKey) -> usize {
    if proc.pi_boosts.contains_key(&key) {
        return 0;
    }
    let wanted = if proc.pi_boost_reservation == Some(key) {
        1
    } else {
        1 + usize::from(proc.pi_boost_reservation.is_some())
    };
    let spare = proc
        .pi_boosts
        .capacity()
        .saturating_sub(proc.pi_boosts.len());
    wanted.saturating_sub(spare)
}

/// D4: reserve the boost room `pid` lacks for `key`, under its PCB lock and
/// no futex lock. False when memory is short or the task is gone.
fn reserve_pi_boost_room(pid: ProcessId, key: FutexKey) -> bool {
    let Some(proc_arc) = process::get_process(pid) else {
        return false;
    };
    let mut proc = proc_arc.lock();
    let wanted = if proc.pi_boosts.contains_key(&key) {
        0
    } else if proc.pi_boost_reservation == Some(key) {
        1
    } else {
        1 + usize::from(proc.pi_boost_reservation.is_some())
    };
    proc.pi_boosts.try_reserve(wanted).is_ok()
}

/// D3: drop `pid`'s donation for `key` once it released that PI futex with
/// no kernel state left. A removal never allocates.
fn drop_pi_boost(pid: ProcessId, key: FutexKey) {
    let changed = process::get_process(pid).is_some_and(|proc_arc| {
        proc_arc
            .lock()
            .try_update_pi_boost(key, None)
            .unwrap_or(false)
    });
    if changed {
        request_resched_from_irq();
    }
}

/// R188-U34 executable probe for the robust-futex exit contract.  The probe is
/// deliberately pure and allocation-free so it can run during the hosted and
/// boot integration suites without manufacturing a live user address space.
/// Hardware-backed fault recovery is exercised by the exception-table helpers;
/// these assertions pin the ABI transition, checked offset arithmetic, bounds,
/// namespace-local TID choice, and the full-PID PI cycle budget.
pub fn run_robust_futex_self_test() {
    const WAITERS: u32 = 0x8000_0000;
    let old = 7u32 | WAITERS;
    let updated = robust_owner_transition(old, [7, 0])
        .expect("R188-U34: matching namespace-local owner must transition");
    assert_eq!(updated & FUTEX_TID_MASK, 0);
    assert_eq!(updated & FUTEX_OWNER_DIED, FUTEX_OWNER_DIED);
    assert_eq!(updated & WAITERS, WAITERS);
    assert!(
        robust_owner_transition(100, [7, 0]).is_none(),
        "R188-U34: a foreign namespace-local TID must not be marked dead"
    );
    assert!(
        robust_owner_transition(7 | FUTEX_OWNER_DIED, [7, 0]).is_none(),
        "R188-U34: an already-dead word must not be woken twice"
    );

    assert_eq!(robust_futex_address(0x2000, -0x20), Some(0x1fe0));
    assert_eq!(robust_futex_address(0x2000, 0x20), Some(0x2020));
    assert!(robust_futex_address(0x10, i64::MIN).is_none());
    assert!(robust_futex_address(usize::MAX, 1).is_none());

    assert!(robust_user_range(
        kernel_core::usercopy::MMAP_MIN_ADDR,
        size_of::<u32>(),
        align_of::<u32>()
    ));
    assert!(!robust_user_range(
        kernel_core::usercopy::MMAP_MIN_ADDR + 1,
        size_of::<u32>(),
        align_of::<u32>()
    ));
    assert!(!robust_user_range(
        kernel_core::usercopy::USER_SPACE_TOP - 2,
        size_of::<u32>(),
        align_of::<u32>()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn new_test_bucket() -> FutexBucketRef {
        let queue =
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)).expect("RF180-47 test queue");
        try_new_futex_arc(Mutex::new(FutexBucket::new(queue, None))).expect("RF180-47 test bucket")
    }

    fn cleanup_global_test_bucket(key: FutexKey) {
        let bucket = {
            let table = FUTEX_TABLE.lock();
            table.get(&key).cloned()
        };
        if let Some(bucket) = bucket {
            cleanup_empty_bucket(key, &bucket);
        }
    }

    #[test]
    fn robust_owner_transition_preserves_waiters_and_sets_owner_died() {
        let owner = 0x1234u32;
        // Only bits 30/31 are outside the owner-TID field.  Bit 29 is part
        // of the low-30-bit TID and would (correctly) make this a foreign
        // owner rather than an auxiliary flag.
        let old = owner | 0x8000_0000;
        let updated = robust_owner_transition(old, [owner, 0]).expect("owner must match");

        assert_eq!(updated & FUTEX_TID_MASK, 0, "owner TID is cleared");
        assert_ne!(updated & FUTEX_OWNER_DIED, 0, "OWNER_DIED is set");
        assert_eq!(
            updated & !(FUTEX_TID_MASK | FUTEX_OWNER_DIED),
            old & !(FUTEX_TID_MASK | FUTEX_OWNER_DIED),
            "non-owner bits other than OWNER_DIED, including FUTEX_WAITERS, are preserved"
        );
    }

    #[test]
    fn robust_owner_transition_rejects_foreign_or_empty_owner() {
        assert!(robust_owner_transition(0, [7, 0]).is_none());
        assert!(robust_owner_transition(8, [7, 0]).is_none());
        assert!(robust_owner_transition(FUTEX_OWNER_DIED, [7, 0]).is_none());
        assert!(robust_owner_transition(7 | FUTEX_OWNER_DIED, [7, 0]).is_none());
    }

    #[test]
    fn robust_futex_address_uses_checked_signed_offset() {
        assert_eq!(robust_futex_address(0x2000, 0x20), Some(0x2020));
        assert_eq!(robust_futex_address(0x2000, -0x20), Some(0x1fe0));
        assert_eq!(robust_futex_address(usize::MAX, 1), None);
        assert_eq!(robust_futex_address(0x10, -0x20), None);
        assert_eq!(robust_futex_address(0x2000, i64::MIN), None);
    }

    #[test]
    fn robust_walk_limit_is_bounded_by_metadata_budget() {
        let expected = MAX_ROBUST_LIST_ENTRIES.min(MAX_FUTEX_BUCKETS_PER_SPACE);
        assert!(expected > 0);
        assert!(expected <= MAX_ROBUST_LIST_ENTRIES);
        assert!(expected <= MAX_FUTEX_BUCKETS_PER_SPACE);
        assert!(expected.saturating_sub(1) < expected);
    }

    #[test]
    fn pi_owner_cycle_bitmap_covers_every_admitted_pid() {
        assert!(PI_VISITED_WORDS * 64 > process::PID_MAX);
        let last = process::PID_MAX;
        assert_eq!(last / 64, PI_VISITED_WORDS - 1);
        assert!(last % 64 < 64);
    }

    #[test]
    fn futex_live_bucket_retry_exhaustion_fails_closed() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let bucket = new_test_bucket();
        bucket.lock().unlinked = true;
        let calls = Cell::new(0usize);

        assert!(matches!(
            get_live_bucket_with(|| {
                calls.set(calls.get() + 1);
                Ok(Arc::clone(&bucket))
            }),
            Err(FutexError::TooManyBuckets)
        ));
        assert_eq!(calls.get(), FUTEX_REVALIDATE_RETRIES);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_bucket_waiter_limit_is_fail_closed() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let bucket = new_test_bucket();
        {
            let mut bucket = bucket.lock();
            bucket.waiter_count = MAX_FUTEX_WAITERS_PER_BUCKET - 1;
            assert!(reserve_bucket_waiter(&mut bucket).is_ok());
            assert_eq!(bucket.waiter_count, MAX_FUTEX_WAITERS_PER_BUCKET);
            assert!(matches!(
                reserve_bucket_waiter(&mut bucket),
                Err(FutexError::TooManyBuckets)
            ));
            assert_eq!(bucket.waiter_count, MAX_FUTEX_WAITERS_PER_BUCKET);
        }
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_same_tgid_prepublication_is_serialized_and_retryable() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let tgid = 0x1804_7047;
        let permit = FutexPreparePermit::try_acquire(tgid)
            .expect("RF180-47 first same-TGID preparation permit");
        let unrelated = FutexPreparePermit::try_acquire(tgid + 1)
            .expect("RF180-47 unrelated TGIDs must not alias preparation gates");
        assert!(matches!(
            FutexPreparePermit::try_acquire(tgid),
            Err(FutexError::TooManyBuckets)
        ));
        drop(unrelated);
        drop(permit);
        drop(
            FutexPreparePermit::try_acquire(tgid)
                .expect("RF180-47 released preparation permit must be reusable"),
        );
    }

    #[test]
    fn gap5_futex_sibling_gate_wait_is_bounded_and_full_registry_fails_fast() {
        use alloc::vec::Vec;

        let _serial = crate::HEAP_TEST_LOCK.lock();
        let tgid = 0x0005_4004;

        // Free gate: claimed on the first attempt.
        drop(FutexPreparePermit::acquire(tgid).expect("G4 free gate"));

        // A sibling that never releases (no scheduler in the host harness)
        // must end in a bounded resource error, not a hang.
        let sibling = FutexPreparePermit::try_acquire(tgid).expect("G4 sibling permit");
        assert!(matches!(
            FutexPreparePermit::acquire(tgid),
            Err(FutexError::TooManyBuckets)
        ));
        drop(sibling);
        drop(FutexPreparePermit::acquire(tgid).expect("G4 gate after sibling release"));

        // Every gate held by other TGIDs: no point waiting.
        let mut held = Vec::new();
        held.try_reserve_exact(FUTEX_PREPARE_GATE_COUNT)
            .expect("G4 permit ledger");
        for index in 0..FUTEX_PREPARE_GATE_COUNT {
            held.push(
                FutexPreparePermit::try_acquire(0x0006_0000 + index as ProcessId)
                    .expect("G4 fill gate registry"),
            );
        }
        assert!(matches!(
            FutexPreparePermit::try_claim(tgid),
            FutexGateClaim::RegistryFull
        ));
        assert!(matches!(
            FutexPreparePermit::acquire(tgid),
            Err(FutexError::TooManyBuckets)
        ));
        drop(held);
        drop(FutexPreparePermit::acquire(tgid).expect("G4 gate after registry drains"));
    }

    #[test]
    fn futex_arc_charges_release_only_after_final_weak() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);

        let queue =
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)).expect("RF180-47 charged queue");
        let queue_allocator = *Arc::allocator(&queue);
        let queue_weak: FutexWeak<WaitQueue> = Arc::downgrade(&queue);
        let bucket = try_new_futex_arc(Mutex::new(FutexBucket::new(queue, None)))
            .expect("RF180-47 charged bucket");
        let bucket_allocator = *Arc::allocator(&bucket);
        let bucket_weak: FutexWeak<Mutex<FutexBucket>> = Arc::downgrade(&bucket);

        drop(bucket);
        assert!(bucket_allocator.charge_is_live_for_test());
        assert!(queue_allocator.charge_is_live_for_test());

        drop(bucket_weak);
        assert!(!bucket_allocator.charge_is_live_for_test());
        assert!(queue_allocator.charge_is_live_for_test());

        drop(queue_weak);
        assert!(!queue_allocator.charge_is_live_for_test());
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_arc_allocation_failure_rolls_back_charge_and_slot() {
        struct ResetFault;
        impl Drop for ResetFault {
            fn drop(&mut self) {
                FAIL_NEXT_FUTEX_ARC_ALLOCATION.store(false, Ordering::Release);
                FAIL_NEXT_FUTEX_GLOBAL_ALLOCATION.store(false, Ordering::Release);
            }
        }

        let _serial = crate::HEAP_TEST_LOCK.lock();
        let _reset = ResetFault;
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);

        FAIL_NEXT_FUTEX_ARC_ALLOCATION.store(true, Ordering::Release);
        assert!(matches!(
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)),
            Err(FutexError::TooManyBuckets)
        ));
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);

        FAIL_NEXT_FUTEX_GLOBAL_ALLOCATION.store(true, Ordering::Release);
        assert!(matches!(
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)),
            Err(FutexError::TooManyBuckets)
        ));
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);

        let queue = try_new_futex_arc(WaitQueue::new(HeapClass::Futex))
            .expect("RF180-47 bucket-failure queue");
        FAIL_NEXT_FUTEX_ARC_ALLOCATION.store(true, Ordering::Release);
        assert!(matches!(
            try_new_futex_arc(Mutex::new(FutexBucket::new(queue, None))),
            Err(FutexError::TooManyBuckets)
        ));
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_named_class_exhaustion_rejects_all_physical_owners() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        assert_eq!(
            crate::sync::timed_waiter_heap_class_for_test(),
            HeapClass::Futex
        );
        let remaining = before
            .capacity_bytes
            .checked_sub(before.committed_bytes + before.reserved_bytes)
            .expect("RF180-47 futex class snapshot overflow");
        let reservation = try_reserve_heap(HeapClass::Futex, remaining)
            .expect("RF180-47 fill exact remaining futex class capacity");
        assert!(matches!(
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)),
            Err(FutexError::TooManyBuckets)
        ));
        assert!(
            PreparedAdmittedMapCapacity::<FutexKey, FutexBucketRef>::try_new(HeapClass::Futex, 1)
                .is_err()
        );
        drop(reservation);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_per_tgid_bucket_cap_is_enforced() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let tgid = 0x1804_7000;

        for index in 0..MAX_FUTEX_BUCKETS_PER_SPACE {
            let key = (tgid, 0x1000 + index);
            drop(get_or_create_bucket(key).expect("RF180-47 admitted TGID bucket"));
        }

        let rejected_key = (tgid, 0x2000 + MAX_FUTEX_BUCKETS_PER_SPACE);
        assert!(matches!(
            get_or_create_bucket(rejected_key),
            Err(FutexError::TooManyBuckets)
        ));
        for index in 0..MAX_FUTEX_BUCKETS_PER_SPACE {
            cleanup_global_test_bucket((tgid, 0x1000 + index));
        }
        assert_eq!(active_futex_count(), 0);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_global_bucket_cap_is_enforced_and_reclaimed() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let base_tgid = 0x1804_8000;

        for index in 0..MAX_FUTEX_BUCKETS_GLOBAL {
            let group = index / MAX_FUTEX_BUCKETS_PER_SPACE;
            let slot = index % MAX_FUTEX_BUCKETS_PER_SPACE;
            let key = (base_tgid + group, 0x1000 + slot);
            drop(get_or_create_bucket(key).expect("RF180-47 admitted global bucket"));
        }

        let rejected_group = MAX_FUTEX_BUCKETS_GLOBAL / MAX_FUTEX_BUCKETS_PER_SPACE + 1;
        assert!(matches!(
            get_or_create_bucket((base_tgid + rejected_group, 0x4000)),
            Err(FutexError::TooManyBuckets)
        ));
        for index in 0..MAX_FUTEX_BUCKETS_GLOBAL {
            let group = index / MAX_FUTEX_BUCKETS_PER_SPACE;
            let slot = index % MAX_FUTEX_BUCKETS_PER_SPACE;
            cleanup_global_test_bucket((base_tgid + group, 0x1000 + slot));
        }
        assert_eq!(active_futex_count(), 0);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_waiter_backing_retires_after_bucket_unlock() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let bucket = new_test_bucket();

        // Publication installs backing prepared outside the lock.
        let mut prepared = prepare_pi_waiter_growth(0, 0, 1).expect("RF180-47 PI waiter backing");
        let mut installed = None;
        let waiter = pi_waiter(0x4000, 0, 7);
        {
            let mut bucket = bucket.lock();
            assert!(ensure_pi_waiter_capacity(
                &mut bucket.pi_waiters,
                1,
                &mut prepared,
                &mut installed
            ));
            assert!(insert_pi_waiter_locked(
                &mut bucket.pi_waiters,
                0x47,
                waiter
            ));
        }
        drop(installed);
        drop(prepared);
        let with_backing = mm::heap_class_snapshot(HeapClass::Futex);
        let retired = {
            let mut bucket = bucket.lock();
            let (removed, retired) = remove_pi_waiter_locked(&mut bucket, 0x47);
            assert_eq!(removed, Some(waiter));
            retired.expect("RF180-47 empty PI backing retirement")
        };
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::Futex),
            with_backing,
            "retired backing must remain charged until its out-of-lock drop"
        );
        drop(retired);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_table_publish_race_retires_loser_outside_lock() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let table = Mutex::new(AdmittedMap::new(HeapClass::Futex));
        let key: FutexKey = (0x1804, 0x0047);

        let mut winner = Some(new_test_bucket());
        let mut winner_backing = prepare_futex_map_growth::<FutexKey, FutexBucketRef>(0, 0)
            .expect("RF180-47 winner table backing");
        let mut winner_retired = None;
        let published = match publish_futex_bucket_candidate(
            &table,
            key,
            &mut winner,
            &mut winner_backing,
            &mut winner_retired,
        ) {
            FutexBucketPublish::Ready(bucket) => bucket,
            FutexBucketPublish::RetryCapacity | FutexBucketPublish::Limit => {
                panic!("RF180-47 winner publish failed")
            }
        };
        drop(winner_retired);
        drop(winner_backing);
        let published_allocator = *Arc::allocator(&published);
        let winner_only = mm::heap_class_snapshot(HeapClass::Futex);

        let mut loser = Some(new_test_bucket());
        let replacement_target = table
            .lock()
            .capacity()
            .checked_add(8)
            .expect("RF180-47 test table target");
        let mut loser_backing = Some(
            PreparedAdmittedMapCapacity::try_new(HeapClass::Futex, replacement_target)
                .expect("RF180-47 loser table backing"),
        );
        let mut loser_retired = None;
        let observed = match publish_futex_bucket_candidate(
            &table,
            key,
            &mut loser,
            &mut loser_backing,
            &mut loser_retired,
        ) {
            FutexBucketPublish::Ready(bucket) => bucket,
            FutexBucketPublish::RetryCapacity | FutexBucketPublish::Limit => {
                panic!("RF180-47 existing winner was not observed")
            }
        };
        assert!(loser.is_some());
        assert!(loser_backing.is_some());
        assert!(loser_retired.is_none());
        drop(observed);
        drop(loser);
        drop(loser_backing);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), winner_only);

        let (removed, retired) = {
            let mut table = table.lock();
            let removed = table.remove_retaining_capacity(&key);
            let retired = table.take_empty_capacity();
            (removed, retired)
        };
        drop(retired);
        drop(removed);
        assert!(
            published_allocator.charge_is_live_for_test(),
            "table unlink must not release a stale strong owner's Arc charge"
        );
        drop(published);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    // ------------------------------------------------------------------
    // GAP-5 futex parity. Each test uses its own PID range: the wake marks
    // are global and the hosted harness runs tests in parallel.
    // ------------------------------------------------------------------

    fn record(origin: usize, pid: u32, bitset: u32) -> FutexWaiterRecord {
        FutexWaiterRecord {
            origin,
            pid,
            bitset,
        }
    }

    /// Queue `records` on a bucket the way publication does, with fresh
    /// marks and one physical attachment each.
    fn queue_records(bucket: &mut FutexBucket, records: &[FutexWaiterRecord]) {
        bucket
            .waiters
            .try_reserve_exact(records.len())
            .expect("GAP-5 futex test record backing");
        for &entry in records {
            clear_wake_mark(entry.pid as ProcessId);
            bucket
                .waiters
                .push_back_reserved(entry)
                .expect("GAP-5 futex test record capacity");
        }
    }

    /// Empty a test bucket so its drop releases every charge.
    fn drain_test_bucket(bucket: &FutexBucketRef) {
        let retired = {
            let mut bucket = bucket.lock();
            bucket.waiter_count = 0;
            bucket.waiters.clear_retaining_capacity();
            bucket.waiters.take_empty_capacity()
        };
        drop(retired);
    }

    #[test]
    fn futex_parity_bitset_wake_takes_only_intersecting_waiters() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const HOME: usize = 0x5000;
        // The sleepers were requeued here from ORIGIN, so every wake is
        // deferred: a hosted test cannot run the in-place wake, whose
        // `WaitQueue::wake_specific` disables interrupts.
        const ORIGIN: usize = 0x4000;
        let pids = [0x7101u32, 0x7102, 0x7103, 0x7104];
        let bucket = new_test_bucket();
        {
            let mut b = bucket.lock();
            queue_records(
                &mut b,
                &[
                    record(ORIGIN, pids[0], 0x1),
                    record(ORIGIN, pids[1], 0x2),
                    record(ORIGIN, pids[2], 0x6),
                    record(ORIGIN, pids[3], 0x8),
                ],
            );
            let mut deferred = FutexDeferredWakes::new();

            // FUTEX_WAKE_BITSET 0x2 wakes the second and third waiters only.
            assert_eq!(
                take_waiters_locked(&mut b, HOME, usize::MAX, 0x2, &mut deferred),
                2
            );
            assert_eq!(b.waiters.len(), 2);
            assert_eq!(b.waiters[0], record(ORIGIN, pids[0], 0x1));
            assert_eq!(b.waiters[1], record(ORIGIN, pids[3], 0x8));
            assert!(!wake_mark_is_set(pids[0] as ProcessId));
            assert!(wake_mark_is_set(pids[1] as ProcessId));
            assert!(wake_mark_is_set(pids[2] as ProcessId));
            assert!(!wake_mark_is_set(pids[3] as ProcessId));
            // Both are readied on their origin queue, in FIFO order.
            assert_eq!(deferred.len, 2);
            assert_eq!(deferred.entries[0], (ORIGIN, pids[1]));
            assert_eq!(deferred.entries[1], (ORIGIN, pids[2]));

            // A mask that intersects nobody wakes nobody.
            assert_eq!(
                take_waiters_locked(&mut b, HOME, usize::MAX, 0x10, &mut deferred),
                0
            );
            // MATCH_ANY (plain FUTEX_WAKE) takes the oldest first, up to n.
            assert_eq!(
                take_waiters_locked(&mut b, HOME, 1, FUTEX_BITSET_MATCH_ANY, &mut deferred),
                1
            );
            assert!(wake_mark_is_set(pids[0] as ProcessId));
            assert_eq!(deferred.len, 3);
            assert_eq!(b.waiters.len(), 1);
            assert_eq!(b.waiters[0].pid, pids[3]);
            // n == 0 takes nothing.
            assert_eq!(
                take_waiters_locked(&mut b, HOME, 0, FUTEX_BITSET_MATCH_ANY, &mut deferred),
                0
            );
            assert_eq!(b.waiters.len(), 1);
        }
        drain_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_requeue_moves_records_and_keeps_attachments() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0x6000;
        const TARGET: usize = 0x7000;
        // Sleepers on ORIGIN, requeued to SOURCE earlier: every wake below is
        // deferred (see futex_parity_bitset_wake_takes_only_intersecting_waiters).
        const ORIGIN: usize = 0x5800;
        let pids = [0x7201u32, 0x7202, 0x7203, 0x7204, 0x7205];
        let bitsets = [0x1u32, 0x2, 0x4, 0x8, 0x10];
        let source = new_test_bucket();
        let target = new_test_bucket();
        {
            let mut s = source.lock();
            let mut t = target.lock();
            let mut queued = [record(0, 0, 0); 5];
            for (index, slot) in queued.iter_mut().enumerate() {
                *slot = record(ORIGIN, pids[index], bitsets[index]);
            }
            queue_records(&mut s, &queued);
            s.waiter_count = queued.len();
            t.waiters
                .try_reserve_exact(3)
                .expect("GAP-5 futex test target backing");
            let mut deferred = FutexDeferredWakes::new();

            // CMP_REQUEUE(nr_wake = 1, nr_requeue = 3): the oldest is woken,
            // the next three move in FIFO order, the last one stays.
            assert_eq!(
                requeue_locked(&mut s, SOURCE, Some(&mut *t), 1, 3, &mut deferred),
                (1, 3)
            );
            assert!(wake_mark_is_set(pids[0] as ProcessId));
            for pid in &pids[1..] {
                assert!(
                    !wake_mark_is_set(*pid as ProcessId),
                    "a moved waiter keeps sleeping"
                );
            }
            assert_eq!(s.waiters.len(), 1);
            assert_eq!(s.waiters[0], queued[4]);
            assert_eq!(t.waiters.len(), 3);
            for index in 0..3 {
                // Moved records keep their bitset and their origin queue.
                assert_eq!(t.waiters[index], queued[index + 1]);
            }
            // Physical attachments never move: the source still pins all
            // five sleepers' queue, the target none.
            assert_eq!(s.waiter_count, 5);
            assert_eq!(t.waiter_count, 0);
            assert_eq!(deferred.len, 1);
            assert_eq!(deferred.entries[0], (ORIGIN, pids[0]));

            // A wake of the target readies a moved waiter on its origin
            // queue, after the target lock is released.
            assert_eq!(
                take_waiters_locked(&mut t, TARGET, 1, FUTEX_BITSET_MATCH_ANY, &mut deferred),
                1
            );
            assert!(wake_mark_is_set(pids[1] as ProcessId));
            assert_eq!(deferred.len, 2);
            assert_eq!(deferred.entries[1], (ORIGIN, pids[1]));
            // Bitsets still select among moved waiters.
            assert_eq!(
                take_waiters_locked(&mut t, TARGET, usize::MAX, 0x8, &mut deferred),
                1
            );
            assert!(wake_mark_is_set(pids[3] as ProcessId));
            assert!(!wake_mark_is_set(pids[2] as ProcessId));
            assert_eq!(t.waiters.len(), 1);
            assert_eq!(t.waiters[0], queued[2]);
        }
        drain_test_bucket(&source);
        drain_test_bucket(&target);
        drop(source);
        drop(target);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_requeue_revalidates_arrivals_after_preparation() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: FutexKey = (0x7249, 0x6000);
        const TARGET: FutexKey = (0x7249, 0x7000);
        const PID: u32 = 0x7249;
        let source = new_test_bucket();
        let target = new_test_bucket();
        let mut deferred = FutexDeferredWakes::new();
        let mut retired = None;
        let mut prepared = None;
        // Phase 1 saw no waiters. One arrives before the table/bucket locks
        // for phase 2. There is consequently no prepared target yet.
        queue_records(
            &mut source.lock(),
            &[record(0x5800, PID, FUTEX_BITSET_MATCH_ANY)],
        );
        assert_eq!(
            requeue_pass(
                SOURCE,
                TARGET,
                &source,
                None,
                0,
                1,
                0,
                None,
                &mut prepared,
                &mut retired,
                &mut deferred
            ),
            Ok(None)
        );
        assert_eq!(source.lock().waiters.len(), 1);
        assert_eq!(deferred.len, 0);
        assert!(!wake_mark_is_set(PID as ProcessId));

        // A second preparation sees the waiter and the next locked pass
        // moves it, leaving it asleep and discoverable on the target.
        prepared = prepare_waiter_list_growth(0, 0, 1).expect("target backing");
        assert_eq!(
            requeue_pass(
                SOURCE,
                TARGET,
                &source,
                Some(&target),
                0,
                1,
                1,
                None,
                &mut prepared,
                &mut retired,
                &mut deferred
            ),
            Ok(Some(1))
        );
        assert!(source.lock().waiters.is_empty());
        assert_eq!(target.lock().waiters.len(), 1);
        assert_eq!(target.lock().waiters[0].pid, PID);
        assert_eq!(deferred.len, 0);
        assert!(!wake_mark_is_set(PID as ProcessId));
        drop(retired);
        drop(prepared);
        drain_test_bucket(&source);
        drain_test_bucket(&target);
        drop(source);
        drop(target);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_requeue_wakes_waiters_it_cannot_move() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0x8000;
        const TARGET: usize = 0x9000;
        // Fallback wakes are deferred because the sleepers' origin is not
        // SOURCE (see futex_parity_bitset_wake_takes_only_intersecting_waiters).
        const ORIGIN: usize = 0x7800;
        let movers = [0x7301u32, 0x7302, 0x7303];
        let source = new_test_bucket();
        let target = new_test_bucket();
        {
            let mut s = source.lock();
            let mut t = target.lock();
            queue_records(
                &mut s,
                &[
                    record(ORIGIN, movers[0], FUTEX_BITSET_MATCH_ANY),
                    record(ORIGIN, movers[1], FUTEX_BITSET_MATCH_ANY),
                    record(ORIGIN, movers[2], FUTEX_BITSET_MATCH_ANY),
                ],
            );
            // A target already at its record bound.
            let mut full = [record(0, 0, 0); MAX_FUTEX_WAITERS_PER_BUCKET];
            for (index, slot) in full.iter_mut().enumerate() {
                *slot = record(TARGET, 0x7400 + index as u32, FUTEX_BITSET_MATCH_ANY);
            }
            queue_records(&mut t, &full);
            let mut deferred = FutexDeferredWakes::new();

            // Nothing fits: both waiters to requeue are woken instead and
            // still count as requeued; the third is left alone.
            assert_eq!(
                requeue_locked(&mut s, SOURCE, Some(&mut *t), 0, 2, &mut deferred),
                (0, 2)
            );
            assert!(wake_mark_is_set(movers[0] as ProcessId));
            assert!(wake_mark_is_set(movers[1] as ProcessId));
            assert!(!wake_mark_is_set(movers[2] as ProcessId));
            assert_eq!(t.waiters.len(), MAX_FUTEX_WAITERS_PER_BUCKET);
            assert_eq!(s.waiters.len(), 1);

            // No target bucket at all: the same fallback; the count stops at
            // the waiters that exist.
            assert_eq!(
                requeue_locked(&mut s, SOURCE, None, 0, 5, &mut deferred),
                (0, 1)
            );
            assert!(wake_mark_is_set(movers[2] as ProcessId));
            assert!(s.waiters.is_empty());
            assert_eq!(deferred.len, 3);
            assert_eq!(deferred.entries[2], (ORIGIN, movers[2]));
        }
        // A target whose backing is full (below the record bound) also falls
        // back instead of allocating under the lock.
        let small = new_test_bucket();
        {
            let mut s = source.lock();
            let mut t = small.lock();
            let spare = 0x7350u32;
            queue_records(&mut s, &[record(ORIGIN, spare, 0x1)]);
            queue_records(&mut t, &[record(TARGET, 0x7351, 0x1)]);
            while t.waiters.len() < t.waiters.capacity() {
                t.waiters
                    .push_back_reserved(record(TARGET, 0x7352, 0x1))
                    .expect("GAP-5 futex test filler");
            }
            let mut deferred = FutexDeferredWakes::new();
            if t.waiters.len() < MAX_FUTEX_WAITERS_PER_BUCKET {
                assert_eq!(
                    requeue_locked(&mut s, SOURCE, Some(&mut *t), 0, 1, &mut deferred),
                    (0, 1)
                );
                assert!(wake_mark_is_set(spare as ProcessId));
                assert!(s.waiters.is_empty());
            }
        }
        drain_test_bucket(&source);
        drain_test_bucket(&target);
        drain_test_bucket(&small);
        drop(source);
        drop(target);
        drop(small);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_waiter_list_growth_installs_without_allocating_under_lock() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        let bucket = new_test_bucket();

        // An empty list needs backing for its first record.
        let mut prepared = prepare_waiter_list_growth(0, 0, 1).expect("first backing");
        assert!(prepared
            .as_ref()
            .is_some_and(|backing| backing.capacity() >= 1));
        let mut retired = None;
        {
            let mut b = bucket.lock();
            assert!(ensure_waiter_list_capacity(
                &mut b.waiters,
                1,
                &mut prepared,
                &mut retired
            ));
            assert!(b.waiters.capacity() >= 1);
            // Without prepared backing, a full list reports a retry.
            while b.waiters.len() < b.waiters.capacity() {
                b.waiters
                    .push_back_reserved(record(0xa000, 0x7601, 1))
                    .expect("GAP-5 futex test filler");
            }
            let mut none = None;
            assert!(!ensure_waiter_list_capacity(
                &mut b.waiters,
                1,
                &mut none,
                &mut retired
            ));
        }
        drop(retired);
        drop(prepared);
        // Growth never asks for more than the record bound unless required.
        let grown = prepare_waiter_list_growth(4, 4, 1)
            .expect("grown backing")
            .expect("growth needed");
        assert!(grown.capacity() >= 5);
        drop(grown);
        assert!(prepare_waiter_list_growth(2, 8, 3)
            .expect("no growth")
            .is_none());

        drain_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_key_space_follows_the_address_space() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let mm = Arc::new(Mutex::new(MmState::new(0)));
        // A CLONE_VM sharer (thread or not) holds the same Arc.
        let sharer = Arc::clone(&mm);
        // fork gives the child a new MmState.
        let forked = Arc::new(Mutex::new(MmState::new(0)));

        let space = FutexSpace::of_mm(&mm);
        assert_eq!(space.id(), FutexSpace::of_mm(&sharer).id());
        assert_eq!(space.id(), FutexSpace::id_of_mm(&mm));
        assert_ne!(space.id(), FutexSpace::of_mm(&forked).id());
        // Keys of one address in two spaces never collide.
        assert_ne!(
            (space.id(), 0x1000usize),
            (FutexSpace::id_of_mm(&forked), 0x1000usize)
        );
        // The pin holds the allocation, not the address space: the sharing
        // checks that read the strong count are unaffected.
        assert_eq!(Arc::strong_count(&mm), 2);

        let queue = try_new_futex_arc(WaitQueue::new(HeapClass::Futex)).expect("test queue");
        let bucket = FutexBucket::new(queue, space.pin.clone());
        drop(space);
        assert!(!bucket.space_is_dead());
        drop(mm);
        assert!(
            !bucket.space_is_dead(),
            "a remaining sharer keeps the space alive"
        );
        drop(sharer);
        assert!(bucket.space_is_dead());
        // The pinned allocation outlives the address space, so its address
        // (the space id) cannot be handed to a new MmState while the bucket
        // exists.
        assert!(bucket
            .space_pin
            .as_ref()
            .is_some_and(|pin| pin.strong_count() == 0 && pin.upgrade().is_none()));
        drop(bucket);

        // Test buckets carry no pin and are never swept as dead.
        let unpinned = new_test_bucket();
        assert!(!unpinned.lock().space_is_dead());
        drop(unpinned);
        drop(forked);
        assert_eq!(FutexSpace::unpinned(0x42).id(), 0x42);
    }

    #[test]
    fn futex_parity_wake_marks_are_per_pid_and_bounded() {
        let pid = 0x7701;
        clear_wake_mark(pid);
        assert!(!wake_mark_is_set(pid));
        set_wake_mark(pid);
        assert!(wake_mark_is_set(pid));
        assert!(!wake_mark_is_set(pid + 1));
        clear_wake_mark(pid);
        assert!(!wake_mark_is_set(pid));
        // Every admitted PID has a mark; anything beyond is ignored.
        assert!(wake_mark(process::PID_MAX).is_some());
        assert!(wake_mark(process::PID_MAX + 64).is_none());
        set_wake_mark(process::PID_MAX + 64);
        assert!(!wake_mark_is_set(process::PID_MAX + 64));
    }

    #[test]
    fn futex_parity_requeued_records_leave_room_for_direct_waiters() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0xa000;
        const TARGET: usize = 0xb000;
        // The sleepers' origin is neither word, so every wake is deferred.
        const ORIGIN: usize = 0xa800;
        const MOVERS: usize = MAX_FUTEX_WAITERS_PER_BUCKET + 4;
        let source = new_test_bucket();
        let target = new_test_bucket();
        {
            let mut s = source.lock();
            let mut t = target.lock();
            let mut movers = [record(0, 0, 0); MOVERS];
            for (index, slot) in movers.iter_mut().enumerate() {
                *slot = record(ORIGIN, 0x6d00 + index as u32, FUTEX_BITSET_MATCH_ANY);
            }
            queue_records(&mut s, &movers);
            t.waiters
                .try_reserve_exact(MAX_FUTEX_RECORDS_PER_BUCKET)
                .expect("GAP-5 futex test record backing");

            // A broadcast requeue (a condition variable onto its mutex) fills
            // the target up to the attachment bound and wakes the rest; every
            // waiter it handled counts.
            let mut deferred = FutexDeferredWakes::new();
            assert_eq!(
                requeue_locked(&mut s, SOURCE, Some(&mut *t), 0, MOVERS, &mut deferred),
                (0, MOVERS)
            );
            assert_eq!(t.waiters.len(), MAX_FUTEX_WAITERS_PER_BUCKET);
            assert_eq!(deferred.len, MOVERS - MAX_FUTEX_WAITERS_PER_BUCKET);
            assert!(s.waiters.is_empty());

            // Tasks that then contend with FUTEX_WAIT on the target word are
            // admitted up to the attachment bound, whatever was requeued.
            for index in 0..MAX_FUTEX_WAITERS_PER_BUCKET {
                assert!(direct_waiter_fits(&t), "direct waiter {index} refused");
                t.waiter_count += 1;
                t.waiters
                    .push_back_reserved(record(
                        TARGET,
                        0x6e00 + index as u32,
                        FUTEX_BITSET_MATCH_ANY,
                    ))
                    .expect("GAP-5 futex test record capacity");
            }
            assert!(!direct_waiter_fits(&t));
            assert_eq!(t.waiters.len(), MAX_FUTEX_RECORDS_PER_BUCKET);

            // A requeue onto the full target moves nothing and wakes instead.
            queue_records(&mut s, &[record(ORIGIN, 0x6d40, FUTEX_BITSET_MATCH_ANY)]);
            let mut deferred = FutexDeferredWakes::new();
            assert_eq!(
                requeue_locked(&mut s, SOURCE, Some(&mut *t), 0, 1, &mut deferred),
                (0, 1)
            );
            assert_eq!(t.waiters.len(), MAX_FUTEX_RECORDS_PER_BUCKET);
            assert_eq!(deferred.entries[..deferred.len], [(ORIGIN, 0x6d40)]);
        }
        drain_test_bucket(&source);
        drain_test_bucket(&target);
        drop(source);
        drop(target);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_parity_drop_space_unlinks_the_idle_buckets_of_one_space() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SPACE: usize = 0x1804_9000;
        const OTHER: usize = SPACE + 1;
        let idle = get_or_create_bucket((SPACE, 0x1000)).expect("GAP-5 exec test bucket");
        let stale_pi = get_or_create_bucket((SPACE, 0x2000)).expect("GAP-5 exec test bucket");
        let busy = get_or_create_bucket((SPACE, 0x3000)).expect("GAP-5 exec test bucket");
        let other = get_or_create_bucket((OTHER, 0x1000)).expect("GAP-5 exec test bucket");
        // An owner-death hand-off whose grantee never stored its TID.
        stale_pi.lock().pi_owner = Some(PiOwner {
            pid: 0x6f01,
            tid: 0x6f01,
            fixup: true,
        });
        // A task still attached: kept (exec's drain leaves none).
        busy.lock().waiter_count = 1;

        assert_eq!(futex_drop_space(SPACE), 1);
        assert!(idle.lock().unlinked);
        assert!(stale_pi.lock().unlinked && stale_pi.lock().pi_owner.is_none());
        assert!(!busy.lock().unlinked);
        assert!(!other.lock().unlinked);
        assert!(lookup_bucket((SPACE, 0x1000)).is_none());
        assert!(lookup_bucket((SPACE, 0x2000)).is_none());
        assert!(lookup_bucket((SPACE, 0x3000)).is_some());
        assert!(lookup_bucket((OTHER, 0x1000)).is_some());

        busy.lock().waiter_count = 0;
        assert_eq!(futex_drop_space(SPACE), 0);
        assert!(busy.lock().unlinked);
        assert!(lookup_bucket((SPACE, 0x3000)).is_none());
        drop(idle);
        drop(stale_pi);
        drop(busy);
        cleanup_global_test_bucket((OTHER, 0x1000));
        drop(other);
        assert_eq!(active_futex_count(), 0);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    // ------------------------------------------------------------------
    // GAP-5 PI parity. Pure decision logic and locked bookkeeping only: a
    // hosted test cannot touch user memory or run a WaitQueue wake (both
    // use ring-0 instructions), so the locked steps run on an in-memory word
    // ([`TestWord`]), the user-word CASes themselves are exercised by the
    // ring-3 legs, and every wake here is a deferred one. Each test uses its
    // own PID range: the marks are global and tests run in parallel.
    // ------------------------------------------------------------------

    /// An in-memory PI word for the locked steps. While `fault` is set every
    /// access fails as a copy-on-write or not-present word does under a
    /// futex lock (review D2-1).
    struct TestWord {
        value: Cell<u32>,
        fault: Cell<bool>,
    }

    impl TestWord {
        fn new(value: u32) -> Self {
            Self {
                value: Cell::new(value),
                fault: Cell::new(false),
            }
        }
    }

    impl LockedWord for TestWord {
        fn read(&self) -> Result<u32, FutexError> {
            if self.fault.get() {
                return Err(FutexError::WordFault);
            }
            Ok(self.value.get())
        }

        fn cas(&self, expected: u32, new: u32) -> Result<bool, FutexError> {
            if self.fault.get() {
                return Err(FutexError::WordFault);
            }
            if self.value.get() != expected {
                return Ok(false);
            }
            self.value.set(new);
            Ok(true)
        }
    }

    fn pi_caller(pid: ProcessId, tid: u32) -> PiCaller {
        PiCaller { pid, tid, ns: None }
    }

    fn pi_waiter(origin: usize, seq: u64, priority: Priority) -> PiWaiter {
        PiWaiter {
            origin,
            seq,
            tid: 0x100 + seq as u32,
            priority,
        }
    }

    /// Publish PI waiters on a test bucket, with fresh marks.
    fn queue_pi_waiters(bucket: &mut FutexBucket, waiters: &[(ProcessId, PiWaiter)]) {
        bucket
            .pi_waiters
            .try_reserve(waiters.len())
            .expect("GAP-5 PI test backing");
        for &(pid, waiter) in waiters {
            clear_wait_marks(pid);
            assert!(insert_pi_waiter_locked(&mut bucket.pi_waiters, pid, waiter));
        }
    }

    /// Empty a test bucket's PI state so its drop releases every charge.
    fn drain_pi_test_bucket(bucket: &FutexBucketRef) {
        let retired = {
            let mut b = bucket.lock();
            b.pi_owner = None;
            while let Some((pid, _)) = select_top_pi_waiter(&b.pi_waiters) {
                b.pi_waiters.remove_retaining_capacity(&pid);
            }
            b.pi_waiters.take_empty_capacity()
        };
        drop(retired);
        drain_test_bucket(bucket);
    }

    #[test]
    fn futex_pi_lock_step_follows_the_linux_word_protocol() {
        const ME: u32 = 0x55;
        const OWNER: u32 = 0x77;
        let step = pi_lock_step;

        // Free: take it. OWNER_DIED stays (user space reports EOWNERDEAD);
        // a stale WAITERS bit goes unless a requeue asks for it.
        assert_eq!(step(0, ME, None, false), PiLockStep::Acquire { new: ME });
        assert_eq!(
            step(0, ME, None, true),
            PiLockStep::Acquire {
                new: ME | FUTEX_WAITERS
            }
        );
        assert_eq!(
            step(FUTEX_WAITERS, ME, None, false),
            PiLockStep::Acquire { new: ME }
        );
        assert_eq!(
            step(FUTEX_OWNER_DIED | FUTEX_WAITERS, ME, None, false),
            PiLockStep::Acquire {
                new: FUTEX_OWNER_DIED | ME
            }
        );
        // The caller's own lock: EDEADLK, whatever the flag bits.
        assert_eq!(step(ME, ME, None, false), PiLockStep::Deadlock);
        assert_eq!(
            step(ME | FUTEX_WAITERS | FUTEX_OWNER_DIED, ME, None, false),
            PiLockStep::Deadlock
        );
        // Contended: set WAITERS first, then attach to the named owner.
        assert_eq!(
            step(OWNER, ME, None, false),
            PiLockStep::SetWaiters {
                new: OWNER | FUTEX_WAITERS
            }
        );
        assert_eq!(
            step(OWNER | FUTEX_OWNER_DIED, ME, None, false),
            PiLockStep::SetWaiters {
                new: OWNER | FUTEX_OWNER_DIED | FUTEX_WAITERS
            }
        );
        assert_eq!(
            step(OWNER | FUTEX_WAITERS, ME, None, false),
            PiLockStep::Attach { tid: OWNER }
        );

        // With a PI state the word must agree with it (attach_to_pi_state).
        let state = Some(PiStateView {
            owner_tid: OWNER,
            fixup: false,
        });
        assert_eq!(
            step(OWNER | FUTEX_WAITERS, ME, state, false),
            PiLockStep::Join
        );
        assert_eq!(
            step(FUTEX_OWNER_DIED | FUTEX_WAITERS, ME, state, false),
            PiLockStep::Join
        );
        assert_eq!(
            step(0x99 | FUTEX_WAITERS, ME, state, false),
            PiLockStep::Invalid
        );
        assert_eq!(step(FUTEX_WAITERS, ME, state, false), PiLockStep::Invalid);
        assert_eq!(
            step(ME | FUTEX_WAITERS, ME, state, false),
            PiLockStep::Deadlock
        );
        // While a hand-off after an owner's death awaits its fixup, the word
        // still names the dead owner: lockers queue behind it.
        let fixup = Some(PiStateView {
            owner_tid: OWNER,
            fixup: true,
        });
        assert_eq!(
            step(0x99 | FUTEX_WAITERS, ME, fixup, false),
            PiLockStep::Join
        );
        assert_eq!(step(0, ME, fixup, false), PiLockStep::Join);
    }

    #[test]
    fn futex_pi_owner_must_be_a_user_task_of_the_futex_address_space() {
        // R191-1 (INV-SEC-04): the task a PI word names may own the PI
        // state only if it shares the futex's key space (a CLONE_VM task
        // does, thread or not) and has a page table of its own. A task of
        // another address space and a kernel task are refused (EPERM); the
        // guest PI owner-identity leg covers the locked attach paths.
        const SPACE: usize = 0x7a00_0000;
        const OTHER: usize = 0x7b00_0000;
        const ROOT: usize = 0x0010_0000;
        assert!(pi_owner_in_space(ROOT, SPACE, SPACE));
        assert!(!pi_owner_in_space(ROOT, OTHER, SPACE));
        assert!(!pi_owner_in_space(0, SPACE, SPACE));
        assert!(!pi_owner_in_space(0, OTHER, SPACE));
    }

    #[test]
    fn futex_pi_unlock_step_checks_the_word_then_the_state() {
        const PID: ProcessId = 0x7810;
        const TID: u32 = 0x31;
        let owner = |pid, fixup| {
            Some(PiOwner {
                pid,
                tid: TID,
                fixup,
            })
        };

        // Only the task the word names may unlock (EPERM).
        assert_eq!(
            pi_unlock_step(0x32 | FUTEX_WAITERS, PID, TID, None, None),
            PiUnlockStep::NotOwner
        );
        assert_eq!(
            pi_unlock_step(0, PID, TID, None, None),
            PiUnlockStep::NotOwner
        );
        // No kernel waiter: the word becomes 0, flags and all.
        assert_eq!(
            pi_unlock_step(TID, PID, TID, None, None),
            PiUnlockStep::Release
        );
        assert_eq!(
            pi_unlock_step(TID | FUTEX_WAITERS | FUTEX_OWNER_DIED, PID, TID, None, None),
            PiUnlockStep::Release
        );
        // A waiter gets its TID with WAITERS; OWNER_DIED goes, the unlocker
        // having owned a consistent lock (Linux wake_futex_pi).
        assert_eq!(
            pi_unlock_step(
                TID | FUTEX_WAITERS | FUTEX_OWNER_DIED,
                PID,
                TID,
                owner(PID, false),
                Some(0x40)
            ),
            PiUnlockStep::HandOff {
                new: 0x40 | FUTEX_WAITERS
            }
        );
        // The PI state of another task, or one awaiting a fixup: EINVAL.
        assert_eq!(
            pi_unlock_step(
                TID | FUTEX_WAITERS,
                PID,
                TID,
                owner(PID + 1, false),
                Some(0x40)
            ),
            PiUnlockStep::Invalid
        );
        assert_eq!(
            pi_unlock_step(TID | FUTEX_WAITERS, PID, TID, owner(PID, true), None),
            PiUnlockStep::Invalid
        );

        // The owner-death fixup stores the heir's TID with WAITERS and
        // OWNER_DIED, whether or not the dead owner was robust (review D5,
        // Linux __fixup_pi_state_owner).
        assert_eq!(pi_fixup_word(0x40), FUTEX_OWNER_DIED | FUTEX_WAITERS | 0x40);

        // A PI caller needs a PID and a TID that fit the word.
        let valid = |pid, tid| PiCaller { pid, tid, ns: None }.is_valid();
        assert!(valid(PID, TID));
        assert!(!valid(0, TID));
        assert!(!valid(process::PID_MAX + 1, TID));
        assert!(!valid(PID, 0));
        assert!(!valid(PID, FUTEX_TID_MASK + 1));
    }

    #[test]
    fn futex_pi_unlock_hands_off_to_the_top_waiter_and_defers_its_wake() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const HOME: usize = 0xb000;
        // A requeued waiter sleeps on its source futex's queue.
        const ORIGIN: usize = 0xa000;
        let owner: ProcessId = 0x7820;
        let (low, high_old, high_new) = (0x7821, 0x7822, 0x7823);
        let bucket = new_test_bucket();
        {
            let mut b = bucket.lock();
            b.pi_owner = Some(PiOwner {
                pid: owner,
                tid: 0x20,
                fixup: false,
            });
            let w_low = pi_waiter(HOME, b.next_pi_seq(), 20);
            let w_old = pi_waiter(ORIGIN, b.next_pi_seq(), 5);
            let w_new = pi_waiter(HOME, b.next_pi_seq(), 5);
            queue_pi_waiters(
                &mut b,
                &[(high_new, w_new), (low, w_low), (high_old, w_old)],
            );

            // Highest priority (lowest value) first, the oldest among equals.
            assert_eq!(select_top_pi_waiter(&b.pi_waiters), Some((high_old, w_old)));
            assert_eq!(highest_waiter_priority(&b), Some(5));
            let mut deferred = FutexDeferredWakes::new();
            let mut unlocker = pi_caller(owner, 0x20);

            // Only the task the word names may unlock.
            let word = TestWord::new(0x21 | FUTEX_WAITERS);
            assert!(matches!(
                unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                Err(FutexError::NotOwner)
            ));

            // Review D2-1: a word that faults under the lock (copy-on-write
            // after a fork) is reported, not resolved, and nothing changes:
            // the caller faults it in with the lock dropped and retries.
            word.value.set(0x20 | FUTEX_WAITERS);
            word.fault.set(true);
            assert!(matches!(
                unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                Err(FutexError::WordFault)
            ));
            assert_eq!(b.pi_waiters.len(), 3);
            assert_eq!(b.pi_owner.map(|o| o.pid), Some(owner));
            assert!(!PI_GRANT_MARKS.is_set(high_old) && !wake_mark_is_set(high_old));
            assert_eq!(deferred.len, 0);

            // Faulted in: the top waiter gets its TID with WAITERS, the
            // grant and wake marks, and the PI state.
            word.fault.set(false);
            assert!(matches!(
                unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                Ok(PiUnlocked::Done)
            ));
            assert_eq!(word.value.get(), w_old.tid | FUTEX_WAITERS);
            assert_eq!(
                b.pi_owner,
                Some(PiOwner {
                    pid: high_old,
                    tid: w_old.tid,
                    fixup: false
                })
            );
            assert!(PI_GRANT_MARKS.is_set(high_old) && wake_mark_is_set(high_old));
            assert!(!PI_GRANT_MARKS.is_set(high_new) && !wake_mark_is_set(high_new));
            // The wake waits until the new owner has its donation, and goes
            // to the queue the waiter sleeps on.
            assert_eq!(deferred.len, 1);
            assert_eq!(deferred.entries[0], (ORIGIN, high_old as u32));
            // The old owner no longer owns it.
            assert!(matches!(
                unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                Err(FutexError::NotOwner)
            ));

            // Each owner unlocks in turn: the other priority-5 waiter, then
            // the low one. Once nobody waits, the PI state goes.
            unlocker = pi_caller(high_old, w_old.tid);
            for (next, next_tid, state_stays) in
                [(high_new, w_new.tid, true), (low, w_low.tid, false)]
            {
                assert!(matches!(
                    unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                    Ok(PiUnlocked::Done)
                ));
                assert_eq!(word.value.get(), next_tid | FUTEX_WAITERS);
                assert!(PI_GRANT_MARKS.is_set(next));
                assert_eq!(b.pi_owner.is_some(), state_stays);
                unlocker = pi_caller(next, next_tid);
            }
            assert_eq!(deferred.len, 3);
            assert_eq!(deferred.entries[2], (HOME, low as u32));
            // The last owner's unlock with no kernel waiter stores 0.
            assert!(matches!(
                unlock_pi_locked(&mut b, &word, &unlocker, &mut deferred),
                Ok(PiUnlocked::Done)
            ));
            assert_eq!(word.value.get(), 0);
            assert_eq!(deferred.len, 3);
        }
        drain_pi_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_locked_steps_fault_in_and_wait_for_a_slot() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const WORD_KEY: FutexKey = (0x7870_0000, 0xb200);
        const OWNER_TID: u32 = 0x77;
        let other_owner: ProcessId = 0x7871;
        let caller = pi_caller(0x7870, 0x70);
        let bucket = new_test_bucket();
        {
            let mut b = bucket.lock();
            let (mut prepared, mut retired) = (None, None);

            // Review D2-1: a free word on a copy-on-write page. The take
            // reports the fault instead of resolving it under the lock, and
            // takes nothing; once faulted in, it takes the lock.
            let word = TestWord::new(0);
            word.fault.set(true);
            assert!(matches!(
                pi_take_or_attach_locked(
                    &mut b, &word, WORD_KEY.0, caller.pid, caller.tid, false, 0, None,
                ),
                Err(FutexError::WordFault)
            ));
            assert_eq!(word.value.get(), 0);
            assert!(b.pi_owner.is_none());
            word.fault.set(false);
            assert!(matches!(
                pi_take_or_attach_locked(
                    &mut b, &word, WORD_KEY.0, caller.pid, caller.tid, false, 0, None,
                ),
                Ok(PiTake::Taken)
            ));
            assert_eq!(word.value.get(), caller.tid);

            // Review D2-2: at the per-futex waiter bound a locker waits for a
            // slot (Full) instead of failing with ENOMEM, and is not queued.
            b.pi_owner = Some(PiOwner {
                pid: other_owner,
                tid: OWNER_TID,
                fixup: false,
            });
            b.waiter_count = MAX_FUTEX_WAITERS_PER_BUCKET;
            word.value.set(OWNER_TID | FUTEX_WAITERS);
            let full = pi_lock_locked(
                &mut b,
                WORD_KEY,
                &word,
                &caller,
                9,
                (OWNER_TID, None),
                false,
                &mut prepared,
                &mut retired,
            );
            assert!(matches!(full, Ok(PiLocked::Full)));
            assert!(b.pi_waiters.is_empty());
            assert_eq!(b.waiter_count, MAX_FUTEX_WAITERS_PER_BUCKET);
            assert_eq!(word.value.get(), OWNER_TID | FUTEX_WAITERS);
            b.waiter_count = 0;

            // Review D4: the caller holds the lock by an owner-death hand-off
            // whose fixup an earlier call could not finish; the word still
            // names the dead owner. LOCK_PI finishes the fixup and reports
            // the lock taken instead of queueing behind itself; a fault is
            // retried like any other.
            b.pi_owner = Some(PiOwner {
                pid: caller.pid,
                tid: caller.tid,
                fixup: true,
            });
            word.value.set(OWNER_TID | FUTEX_WAITERS);
            word.fault.set(true);
            let faulted = pi_lock_locked(
                &mut b,
                WORD_KEY,
                &word,
                &caller,
                9,
                (OWNER_TID, None),
                false,
                &mut prepared,
                &mut retired,
            );
            assert!(matches!(faulted, Err(FutexError::WordFault)));
            assert_eq!(b.pi_owner.map(|o| o.fixup), Some(true));
            word.fault.set(false);
            let fixed = pi_lock_locked(
                &mut b,
                WORD_KEY,
                &word,
                &caller,
                9,
                (OWNER_TID, None),
                false,
                &mut prepared,
                &mut retired,
            );
            assert!(matches!(fixed, Ok(PiLocked::Acquired)));
            assert_eq!(
                word.value.get(),
                FUTEX_OWNER_DIED | caller.tid | FUTEX_WAITERS
            );
            // Nobody waits: the word alone names the owner now.
            assert!(b.pi_owner.is_none() && b.pi_waiters.is_empty());
            assert_eq!(b.waiter_count, 0);
            assert!(prepared.is_none() && retired.is_none());
        }
        drain_pi_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_owner_death_hands_the_lock_over_with_a_pending_fixup() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const HOME: usize = 0xb100;
        const ORIGIN: usize = 0xa100;
        let owner: ProcessId = 0x7830;
        let (pa, pb) = (0x7831, 0x7832);
        let bucket = new_test_bucket();
        {
            let mut b = bucket.lock();
            b.pi_owner = Some(PiOwner {
                pid: owner,
                tid: 0x30,
                fixup: false,
            });
            let wa = pi_waiter(HOME, b.next_pi_seq(), 10);
            let wb = pi_waiter(ORIGIN, b.next_pi_seq(), 3);
            queue_pi_waiters(&mut b, &[(pa, wa), (pb, wb)]);
            let mut deferred = FutexDeferredWakes::new();

            // Another task's death changes nothing.
            assert_eq!(pi_owner_died_locked(&mut b, 0x7839, &mut deferred), None);
            assert_eq!(deferred.len, 0);

            // The owner died: the top waiter owns the lock and stores its
            // own TID in the word when it runs (exit_pi_state_list + fixup).
            assert_eq!(
                pi_owner_died_locked(&mut b, owner, &mut deferred),
                Some(Some(pb))
            );
            assert_eq!(
                b.pi_owner,
                Some(PiOwner {
                    pid: pb,
                    tid: wb.tid,
                    fixup: true
                })
            );
            assert!(PI_GRANT_MARKS.is_set(pb) && wake_mark_is_set(pb));
            assert_eq!(deferred.entries[0], (ORIGIN, pb as u32));
            // Lockers queue behind the pending hand-off whatever the word,
            // still naming the dead owner, says.
            assert_eq!(
                pi_lock_step(
                    0x30 | FUTEX_WAITERS,
                    0x99,
                    b.pi_owner.map(PiStateView::from),
                    false
                ),
                PiLockStep::Join
            );

            // The new owner died before its fixup: the next waiter gets it.
            assert_eq!(
                pi_owner_died_locked(&mut b, pb, &mut deferred),
                Some(Some(pa))
            );
            assert_eq!(b.pi_owner.map(|o| (o.pid, o.fixup)), Some((pa, true)));
            // A pending fixup keeps the state with nobody waiting ...
            assert!(b.pi_waiters.is_empty());
            assert_eq!(b.settle_pi_state(), None);
            assert!(b.pi_owner.is_some());
            // ... until the heir stores its TID. The word still names the
            // first (non-robust) owner; the heir sees OWNER_DIED all the same
            // (review D5). Another task's fixup step changes nothing.
            let word = TestWord::new(0x30 | FUTEX_WAITERS);
            assert!(matches!(
                pi_fixup_locked(&mut b, &word, &pi_caller(pb, wb.tid)),
                Ok(true)
            ));
            assert_eq!(b.pi_owner.map(|o| (o.pid, o.fixup)), Some((pa, true)));
            assert_eq!(word.value.get(), 0x30 | FUTEX_WAITERS);
            assert!(matches!(
                pi_fixup_locked(&mut b, &word, &pi_caller(pa, wa.tid)),
                Ok(true)
            ));
            assert_eq!(word.value.get(), FUTEX_OWNER_DIED | FUTEX_WAITERS | wa.tid);
            assert_eq!(b.pi_owner, None);

            // An owner death with nobody waiting drops the state; the word
            // keeps what the robust walk wrote.
            b.pi_owner = Some(PiOwner {
                pid: pa,
                tid: wa.tid,
                fixup: false,
            });
            assert_eq!(pi_owner_died_locked(&mut b, pa, &mut deferred), Some(None));
            assert_eq!(b.pi_owner, None);
            assert_eq!(deferred.len, 2);
        }
        drain_pi_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_requeue_pi_records_are_refused_by_plain_wakes_and_requeues() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0xc000;
        const PI_WORD: usize = 0xd000;
        const ELSEWHERE: usize = 0xe000;
        let (rq_pid, plain_pid, pi_pid) = (0x7841u32, 0x7842u32, 0x7843);

        // A requeue-PI record names the PI futex and sleeps where it is.
        let rq = FutexWaiterRecord::requeue_pi(PI_WORD, rq_pid);
        assert!(rq.is_requeue_pi());
        assert_eq!(rq.requeue_pi_target(), Some(PI_WORD));
        assert_eq!(rq.sleep_origin(SOURCE), SOURCE);
        // A plain record that a requeue moved here sleeps on its origin.
        let plain = record(ELSEWHERE, plain_pid, FUTEX_BITSET_MATCH_ANY);
        assert!(!plain.is_requeue_pi());
        assert_eq!(plain.requeue_pi_target(), None);
        assert_eq!(plain.sleep_origin(SOURCE), ELSEWHERE);

        let bucket = new_test_bucket();
        {
            let mut b = bucket.lock();
            assert!(!plain_op_refused(&b));
            queue_records(&mut b, &[plain, rq]);
            // FUTEX_WAKE, WAKE_OP and the plain requeues refuse the word
            // (Linux: EINVAL on a waiter with an rt_waiter).
            assert!(b.has_requeue_pi_waiters());
            assert!(plain_op_refused(&b));
            // Even a direct bitset scan cannot select it: its mask is empty.
            let mut deferred = FutexDeferredWakes::new();
            assert_eq!(
                take_waiters_locked(
                    &mut b,
                    SOURCE,
                    usize::MAX,
                    FUTEX_BITSET_MATCH_ANY,
                    &mut deferred
                ),
                1
            );
            assert!(wake_mark_is_set(plain_pid as ProcessId));
            assert!(!wake_mark_is_set(rq_pid as ProcessId));
            assert_eq!(b.waiters.len(), 1);
            assert_eq!(deferred.entries[0], (ELSEWHERE, plain_pid));

            // PI waiters on the word refuse plain wakes as well.
            b.waiters.clear_retaining_capacity();
            assert!(!plain_op_refused(&b));
            queue_pi_waiters(&mut b, &[(pi_pid, pi_waiter(SOURCE, 0, 9))]);
            b.pi_owner = Some(PiOwner {
                pid: 0x7844,
                tid: 0x44,
                fixup: false,
            });
            assert!(plain_op_refused(&b));
        }
        drain_pi_test_bucket(&bucket);
        drop(bucket);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_cmp_requeue_pi_moves_only_waiters_for_its_pi_futex() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0xc100;
        const PI_WORD: usize = 0xd100;
        const OTHER_PI: usize = 0xd200;
        let (top, second, third, other, gone, owner_waiter, crowded) =
            (0x7851, 0x7852, 0x7853, 0x7854, 0x7855, 0x7856, 0x7857);
        let src = new_test_bucket();
        let tgt = new_test_bucket();
        {
            let mut s = src.lock();
            let mut t = tgt.lock();
            queue_records(
                &mut s,
                &[
                    FutexWaiterRecord::requeue_pi(PI_WORD, top as u32),
                    FutexWaiterRecord::requeue_pi(PI_WORD, second as u32),
                    FutexWaiterRecord::requeue_pi(PI_WORD, gone as u32),
                    FutexWaiterRecord::requeue_pi(PI_WORD, third as u32),
                    FutexWaiterRecord::requeue_pi(OTHER_PI, other as u32),
                ],
            );
            s.waiter_count = 5;
            t.pi_waiters
                .try_reserve(MAX_FUTEX_WAITERS_PER_BUCKET)
                .expect("GAP-5 PI test target backing");
            // TID = low byte of the PID, priority = its low nibble; `gone`
            // died inside its wait.
            let mut info = |pid: ProcessId, _requeued: bool| {
                (pid != gone).then_some((pid as u32 & 0xff, (pid & 0xf) as Priority))
            };
            let mut deferred = FutexDeferredWakes::new();

            // The top waiter must have named this PI futex (else EINVAL).
            assert_eq!(
                requeue_pi_top_locked(&mut s, OTHER_PI, &mut info),
                Err(FutexError::InvalidOperation)
            );
            assert_eq!(
                requeue_pi_top_locked(&mut s, PI_WORD, &mut info),
                Ok(Some((top, 0x51, 1)))
            );

            // The proxy lock took the PI futex for it: it wakes as the owner
            // and the requeued waiters attach to its PI state.
            s.waiters.pop_front_retaining_capacity();
            let granted = PiWaiter {
                origin: SOURCE,
                seq: t.next_pi_seq(),
                tid: 0x51,
                priority: 1,
            };
            grant_pi_waiter_locked(&mut t, top, granted, false, &mut deferred);
            assert!(PI_GRANT_MARKS.is_set(top));
            assert_eq!(deferred.entries[0], (SOURCE, top as u32));

            // nr_requeue 2: `second` moves, the dead `gone` is dropped
            // uncounted, `third` moves. They keep sleeping on the source.
            assert_eq!(
                requeue_pi_move_locked(
                    &mut s,
                    SOURCE,
                    &mut t,
                    PI_WORD,
                    2,
                    &mut info,
                    &mut deferred
                ),
                Ok(2)
            );
            for (pid, seq) in [(second, 1), (third, 2)] {
                let waiter = t.pi_waiters.get(&pid).copied().expect("requeued waiter");
                assert_eq!((waiter.origin, waiter.seq), (SOURCE, seq));
                assert!(!wake_mark_is_set(pid));
            }
            assert!(!t.pi_waiters.contains_key(&gone));
            assert_eq!(s.waiter_count, 5, "physical attachments stay on the source");
            assert_eq!(deferred.len, 1);

            // A waiter for another PI futex stops the requeue with EINVAL
            // and stays where it is.
            assert_eq!(
                requeue_pi_move_locked(
                    &mut s,
                    SOURCE,
                    &mut t,
                    PI_WORD,
                    5,
                    &mut info,
                    &mut deferred
                ),
                Err(FutexError::InvalidOperation)
            );
            assert_eq!(s.waiters.len(), 1);
            s.waiters.clear_retaining_capacity();

            // A waiter that owns the PI futex is woken with EDEADLK.
            queue_records(
                &mut s,
                &[FutexWaiterRecord::requeue_pi(PI_WORD, owner_waiter as u32)],
            );
            clear_wait_marks(owner_waiter);
            let saved_owner = t.pi_owner;
            t.pi_owner = Some(PiOwner {
                pid: owner_waiter,
                tid: 0x56,
                fixup: false,
            });
            assert_eq!(
                requeue_pi_move_locked(
                    &mut s,
                    SOURCE,
                    &mut t,
                    PI_WORD,
                    1,
                    &mut info,
                    &mut deferred
                ),
                Err(FutexError::Deadlock)
            );
            assert!(PI_DEADLOCK_MARKS.is_set(owner_waiter) && wake_mark_is_set(owner_waiter));
            assert!(!PI_GRANT_MARKS.is_set(owner_waiter));
            assert_eq!(deferred.entries[1], (SOURCE, owner_waiter as u32));
            t.pi_owner = saved_owner;

            // A PI futex at its waiter bound: woken without the lock (EAGAIN
            // in the waiter) and still counted.
            let mut filler = 0x7a00;
            while t.pi_waiters.len() < MAX_FUTEX_WAITERS_PER_BUCKET {
                let seq = t.next_pi_seq();
                assert!(insert_pi_waiter_locked(
                    &mut t.pi_waiters,
                    filler,
                    pi_waiter(SOURCE, seq, 30)
                ));
                filler += 1;
            }
            queue_records(
                &mut s,
                &[FutexWaiterRecord::requeue_pi(PI_WORD, crowded as u32)],
            );
            assert_eq!(
                requeue_pi_move_locked(
                    &mut s,
                    SOURCE,
                    &mut t,
                    PI_WORD,
                    1,
                    &mut info,
                    &mut deferred
                ),
                Ok(1)
            );
            assert!(wake_mark_is_set(crowded));
            assert!(!PI_GRANT_MARKS.is_set(crowded) && !PI_DEADLOCK_MARKS.is_set(crowded));
            assert!(!t.pi_waiters.contains_key(&crowded));
            assert_eq!(deferred.entries[2], (SOURCE, crowded as u32));
            assert!(s.waiters.is_empty());
        }
        drain_pi_test_bucket(&src);
        drain_pi_test_bucket(&tgt);
        drop(src);
        drop(tgt);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_requeue_pi_wait_results_follow_linux() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        // Ended before any requeue (handle_early_requeue_pi_wakeup).
        assert_eq!(
            early_requeue_pi_error(WaitOutcome::TimedOut),
            FutexError::TimedOut
        );
        assert_eq!(
            early_requeue_pi_error(WaitOutcome::Woken),
            FutexError::WouldBlock
        );
        assert_eq!(
            early_requeue_pi_error(WaitOutcome::Interrupted),
            FutexError::Interrupted
        );
        // Resolved by a requeuer or a hand-off: owner, EDEADLK, or woken
        // without the lock. (No bucket exists for this key, so a grant needs
        // no fixup.)
        let caller = PiCaller {
            pid: 0x7861,
            tid: 0x61,
            ns: None,
        };
        let key2: FutexKey = (0x7860_0000, 0xd300);
        clear_wait_marks(caller.pid);
        assert_eq!(
            requeue_pi_resolved(key2, &caller),
            Err(FutexError::WouldBlock)
        );
        PI_DEADLOCK_MARKS.set(caller.pid);
        assert_eq!(
            requeue_pi_resolved(key2, &caller),
            Err(FutexError::Deadlock)
        );
        clear_wait_marks(caller.pid);
        PI_GRANT_MARKS.set(caller.pid);
        assert_eq!(requeue_pi_resolved(key2, &caller), Ok(0));
        // A new wait starts with every outcome mark clear.
        clear_wait_marks(caller.pid);
        assert!(!PI_GRANT_MARKS.is_set(caller.pid));
        assert!(!PI_DEADLOCK_MARKS.is_set(caller.pid));
        assert!(!wake_mark_is_set(caller.pid));
    }

    #[test]
    fn futex_pi_requeue_pi_signals_restart_before_the_requeue_and_end_it_after() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);
        const SOURCE: usize = 0xc300;
        const PI_WORD: usize = 0xd400;
        let key2: FutexKey = (0x7880_0000, PI_WORD);
        let caller = pi_caller(0x7881, 0x81);
        let pid = caller.pid;
        let source = new_test_bucket();
        let on_source = || source.lock().record_position(pid as u32).is_some();
        let wait_state = |outcome, signal, give_up| {
            requeue_pi_wait_state(&source, key2, &caller, outcome, signal, give_up)
        };
        clear_wait_marks(pid);
        let record = FutexWaiterRecord::requeue_pi(PI_WORD, pid as u32);
        queue_records(&mut source.lock(), &[record]);

        // Review D2-2, before the requeue: a handler signal keeps the waiter
        // waiting on the source (Linux restarts the call and waits again),
        // up to the give-up bound; a wake for no reason is EAGAIN and a
        // timeout ETIMEDOUT, and either takes the record off.
        assert_eq!(wait_state(WaitOutcome::Woken, true, false), None);
        assert!(on_source());
        assert_eq!(
            wait_state(WaitOutcome::Woken, true, true),
            Some(Err(FutexError::WouldBlock))
        );
        assert!(!on_source());
        queue_records(&mut source.lock(), &[record]);
        assert_eq!(
            wait_state(WaitOutcome::Woken, false, false),
            Some(Err(FutexError::WouldBlock))
        );
        assert!(!on_source());
        queue_records(&mut source.lock(), &[record]);
        assert_eq!(
            wait_state(WaitOutcome::TimedOut, false, false),
            Some(Err(FutexError::TimedOut))
        );
        assert!(!on_source());

        // After the requeue the waiter is a PI waiter of the target. A wake
        // for no reason keeps it waiting for the lock; a handler signal is
        // EAGAIN (Linux EWOULDBLOCK) and it leaves the PI futex, whose state
        // goes with its last waiter.
        let target = get_or_create_bucket(key2).expect("GAP-5 PI test target");
        {
            let mut t = target.lock();
            t.pi_owner = Some(PiOwner {
                pid: 0x7882,
                tid: 0x82,
                fixup: false,
            });
            queue_pi_waiters(&mut t, &[(pid, pi_waiter(SOURCE, 0, 9))]);
        }
        assert_eq!(wait_state(WaitOutcome::Woken, false, false), None);
        assert!(target.lock().pi_waiters.contains_key(&pid));
        assert_eq!(
            wait_state(WaitOutcome::Woken, true, false),
            Some(Err(FutexError::WouldBlock))
        );
        {
            let t = target.lock();
            assert!(t.pi_waiters.is_empty() && t.pi_owner.is_none());
        }
        assert!(lookup_bucket(key2).is_none());

        drop(target);
        cleanup_global_test_bucket(key2);
        drain_test_bucket(&source);
        drop(source);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Futex), before);
    }

    #[test]
    fn futex_pi_list_pointers_carry_the_pi_bit() {
        // Linux fetch_robust_entry: bit 0 of a list pointer marks a PI
        // futex; the node itself is the pointer without it.
        assert_eq!(robust_entry(0x7000_1000), (0x7000_1000, false));
        assert_eq!(robust_entry(0x7000_1001), (0x7000_1000, true));
        let (node, pi) = robust_entry(0x7000_1001);
        assert!(pi && robust_user_range(node, size_of::<usize>(), align_of::<usize>()));
        assert!(!robust_user_range(
            0x7000_1001,
            size_of::<usize>(),
            align_of::<usize>()
        ));
    }
}
