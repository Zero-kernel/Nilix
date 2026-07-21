//! Futex (Fast Userspace Mutex) 实现
//!
//! 提供用户空间快速互斥锁的内核支持，包括：
//! - FUTEX_WAIT: 如果 *uaddr == val，阻塞当前进程；否则返回 EAGAIN
//! - FUTEX_WAIT_TIMEOUT: 同上，但支持超时（R39-6 FIX）
//! - FUTEX_WAKE: 唤醒最多 n 个在 uaddr 上等待的进程
//! - FUTEX_LOCK_PI: 互斥锁加锁（带优先级继承）- E.4 PI
//! - FUTEX_UNLOCK_PI: 互斥锁解锁（带优先级继承）- E.4 PI
//!
//! 使用全局 FutexTable，以 (pid, vaddr) 为键索引等待队列。
//! 进程退出时自动清理其所有 futex 等待队列。

#[cfg(test)]
use alloc::sync::Weak;
use alloc::{
    alloc::{AllocError, Allocator, Global},
    sync::Arc,
};
use core::alloc::Layout;
use core::mem::size_of;
use core::ops::Bound;
use core::ptr::NonNull;
#[cfg(test)]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::process::{self, FutexKey, Priority, ProcessId};
use kernel_core::request_resched_from_irq;
use mm::{
    arc_charge_bytes, try_reserve_heap, AdmittedMap, HeapCharge, HeapClass,
    PreparedAdmittedMapCapacity, RetiredAdmittedMapCapacity,
};
use spin::Mutex;

use crate::sync::{PrepareWait, WaitOutcome, WaitQueue};

/// Futex 操作码
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
/// R39-6 FIX: 带超时的等待
pub const FUTEX_WAIT_TIMEOUT: i32 = 2;
/// E.4 PI: 互斥锁加锁（带优先级继承）
pub const FUTEX_LOCK_PI: i32 = 3;
/// E.4 PI: 互斥锁解锁（带优先级继承）
pub const FUTEX_UNLOCK_PI: i32 = 4;

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
    /// E.4 PI: Robust futex - 锁持有者已退出
    OwnerDied,
    /// R171 (F3): 等待期间检测到挂起的 kill —— 以 EINTR 中断 futex 等待。
    Interrupted,
    /// Futex metadata admission/allocation failed -> ENOMEM. This includes the
    /// heap-derived global/per-TGID bucket budget and fallible queue/PI metadata growth.
    TooManyBuckets,
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
/// A waiter can simultaneously occupy the per-bucket wait deque, the PI map,
/// and the global timeout registry.  Eight words conservatively cover those
/// three entries before the whole bucket estimate is doubled for backing
/// growth, alignment, and allocator metadata.
const MAX_FUTEX_WAITERS_PER_BUCKET: usize = 16;
const FUTEX_PER_WAITER_RAW_BYTES: usize = 8 * size_of::<usize>();
const FUTEX_BUCKET_RAW_BYTES: usize = size_of::<Mutex<FutexBucket>>()
    + ARC_HEADER_BYTES
    + size_of::<WaitQueue>()
    + ARC_HEADER_BYTES
    + 2 * FUTEX_TABLE_SLOT_BYTES
    + MAX_FUTEX_WAITERS_PER_BUCKET * FUTEX_PER_WAITER_RAW_BYTES;
const FUTEX_BUCKET_CHARGE_BYTES: usize = 2 * FUTEX_BUCKET_RAW_BYTES;
const MAX_FUTEX_BUCKETS_GLOBAL: usize = FUTEX_HEAP_BUDGET_BYTES / FUTEX_BUCKET_CHARGE_BYTES;
/// A single TGID receives at most one quarter of the global futex budget.
const MAX_FUTEX_BUCKETS_PER_TGID: usize = MAX_FUTEX_BUCKETS_GLOBAL / 4;

const _: () = assert!(FUTEX_HEAP_BUDGET_BYTES < mm::memory::HEAP_SIZE_BYTES);
const _: () = assert!(FUTEX_BUCKET_CHARGE_BYTES >= FUTEX_BUCKET_RAW_BYTES);
const _: () = assert!(MAX_FUTEX_BUCKETS_PER_TGID > 0);
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
    /// 等待队列（Arc 包装，避免持有桶锁时阻塞导致死锁）
    queue: FutexQueueRef,
    /// 活跃等待者计数（用于判断是否可以清理）
    waiter_count: usize,
    /// E.4 PI: 当前持有者（线程ID），FUTEX_LOCK_PI 使用
    owner: Option<ProcessId>,
    /// E.4 PI: 持有者已经死亡（robust futex 语义）
    owner_dead: bool,
    /// E.4 PI: PI 等待者列表 (pid -> priority)，用于找出最高优先级的等待者
    pi_waiters: AdmittedMap<ProcessId, Priority>,
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
    fn new(queue: FutexQueueRef) -> Self {
        FutexBucket {
            queue,
            waiter_count: 0,
            owner: None,
            owner_dead: false,
            pi_waiters: AdmittedMap::new(HeapClass::Futex),
            unlinked: false,
        }
    }
}

/// R172-07/08: bounded retry count for obtaining a live (non-tombstoned) bucket. A
/// pathological reaper could repeatedly unlink between create and lock; the bound makes the
/// loop terminate (the per-site `unlinked` guard is the authoritative correctness check).
const FUTEX_REVALIDATE_RETRIES: usize = 16;

/// RF180-47: serialize detached futex preparation per TGID from the first
/// resident-cap check through publication. The fixed registry is large enough
/// for every TGID that can own a live bucket; unlike a hashed lock, unrelated
/// TGIDs never alias. Its mutex protects only slot claim/release and is never
/// held across allocation or a futex/table/queue lock.
const FUTEX_PREPARE_GATE_COUNT: usize = MAX_FUTEX_BUCKETS_GLOBAL;

#[derive(Clone, Copy)]
struct FutexPrepareGateSlot {
    tgid: ProcessId,
    busy: bool,
}

const EMPTY_FUTEX_PREPARE_GATE: FutexPrepareGateSlot = FutexPrepareGateSlot {
    tgid: 0,
    busy: false,
};

static FUTEX_PREPARE_GATES: Mutex<[FutexPrepareGateSlot; FUTEX_PREPARE_GATE_COUNT]> =
    Mutex::new([EMPTY_FUTEX_PREPARE_GATE; FUTEX_PREPARE_GATE_COUNT]);

struct FutexPreparePermit {
    gate: usize,
    tgid: ProcessId,
}

impl FutexPreparePermit {
    fn try_acquire(tgid: ProcessId) -> Result<Self, FutexError> {
        let mut gates = FUTEX_PREPARE_GATES.lock();
        if gates.iter().any(|slot| slot.busy && slot.tgid == tgid) {
            return Err(FutexError::TooManyBuckets);
        }
        let (gate, slot) = gates
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.busy)
            .ok_or(FutexError::TooManyBuckets)?;
        *slot = FutexPrepareGateSlot { tgid, busy: true };
        Ok(Self { gate, tgid })
    }
}

impl Drop for FutexPreparePermit {
    fn drop(&mut self) {
        let mut gates = FUTEX_PREPARE_GATES.lock();
        let slot = gates
            .get_mut(self.gate)
            .expect("RF180-47 futex preparation gate index out of range");
        assert!(
            slot.busy && slot.tgid == self.tgid,
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
) -> Result<FutexBucketRef, FutexError> {
    get_live_bucket_with(|| get_or_create_bucket_with_permit(key, permit))
}

lazy_static::lazy_static! {
    /// 全局 Futex 表
    ///
    /// 以 (pid, vaddr) 为键，管理该地址上的等待队列。
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

type RetiredPiWaiterCapacity = RetiredAdmittedMapCapacity<ProcessId, Priority>;

fn remove_pi_waiter_locked(
    bucket: &mut FutexBucket,
    pid: ProcessId,
) -> (Option<Priority>, Option<RetiredPiWaiterCapacity>) {
    let removed = bucket.pi_waiters.remove_retaining_capacity(&pid);
    let retired = bucket.pi_waiters.take_empty_capacity();
    (removed, retired)
}

enum PiWaiterPublish {
    Published,
    RetryCapacity,
}

fn publish_pi_waiter(
    bucket: &FutexBucketRef,
    pid: ProcessId,
    priority: Priority,
    prepared: &mut Option<PreparedAdmittedMapCapacity<ProcessId, Priority>>,
    retired: &mut Option<RetiredPiWaiterCapacity>,
) -> PiWaiterPublish {
    let mut bucket = bucket.lock();
    if let Some(existing) = bucket.pi_waiters.get_mut(&pid) {
        *existing = priority;
        return PiWaiterPublish::Published;
    }

    if bucket.pi_waiters.len() == bucket.pi_waiters.capacity() {
        let Some(backing) = prepared.take() else {
            return PiWaiterPublish::RetryCapacity;
        };
        if backing.class() != bucket.pi_waiters.class()
            || backing.capacity() <= bucket.pi_waiters.len()
        {
            *prepared = Some(backing);
            return PiWaiterPublish::RetryCapacity;
        }
        debug_assert!(retired.is_none());
        *retired = Some(
            bucket
                .pi_waiters
                .install_prepared_deferred(backing)
                .expect("RF180-47 PI waiter prepared-capacity invariant"),
        );
    }

    match bucket.pi_waiters.insert_unique_reserved(pid, priority) {
        Ok(()) => PiWaiterPublish::Published,
        Err(_) => PiWaiterPublish::RetryCapacity,
    }
}

fn insert_pi_waiter(
    bucket: &FutexBucketRef,
    pid: ProcessId,
    priority: Priority,
    _permit: &FutexPreparePermit,
) -> Result<(), FutexError> {
    for _ in 0..FUTEX_REVALIDATE_RETRIES {
        let (len, capacity) = {
            let bucket = bucket.lock();
            (bucket.pi_waiters.len(), bucket.pi_waiters.capacity())
        };
        let mut prepared = prepare_futex_map_growth::<ProcessId, Priority>(len, capacity)?;
        let mut retired = None;
        let outcome = publish_pi_waiter(bucket, pid, priority, &mut prepared, &mut retired);
        // Neither an unused candidate nor obsolete installed backing is freed
        // while the FutexBucket lock is live.
        drop(retired);
        drop(prepared);
        match outcome {
            PiWaiterPublish::Published => return Ok(()),
            PiWaiterPublish::RetryCapacity => continue,
        }
    }
    Err(FutexError::TooManyBuckets)
}

/// 从用户空间读取 u32 值
///
/// 用于 futex_wait 在入队前二次检查值，防止 lost-wake 竞态
/// R24-5 fix: 验证跨页、使用 SMAP 保护和容错 usercopy
fn read_user_u32(uaddr: usize) -> Result<u32, FutexError> {
    use kernel_core::usercopy::{read_user_u32_atomic, UserAddr};

    // RF178-8: the syscall already validated the aligned u32 range. This
    // second, exception-table-backed copy is deliberately PT_LOCK-free because
    // the caller serializes FUTEX_WAKE with the wait-queue lock. A concurrent
    // unmap is reported as EFAULT by the nofault helper.
    read_user_u32_atomic(UserAddr::new(uaddr)).map_err(|_| FutexError::Fault)
}

/// FUTEX_WAIT / FUTEX_WAIT_TIMEOUT 操作
///
/// 如果 *uaddr == expected，则阻塞当前进程；否则返回 WouldBlock。
///
/// # Arguments
///
/// * `tgid` - 线程组 ID (R37-2 FIX: 使用 TGID 而非 PID)
/// * `uaddr` - 用户空间 futex 地址（已验证）
/// * `expected` - 期望的值
/// * `current_value` - 当前从用户空间读取的值（调用者负责验证和读取）
/// * `timeout_ns` - R39-6 FIX: 可选超时时间（纳秒），None 表示无限等待
///
/// # Returns
///
/// 成功阻塞并被唤醒后返回 Ok(0)，值不匹配返回 WouldBlock，超时返回 TimedOut
pub fn futex_wait(
    tgid: ProcessId,
    uaddr: usize,
    expected: u32,
    current_value: u32,
    timeout_ns: Option<u64>,
) -> Result<usize, FutexError> {
    // 值不匹配，立即返回
    if current_value != expected {
        return Err(FutexError::WouldBlock);
    }

    // R37-2 FIX: Futex key is scoped by TGID so CLONE_THREAD siblings can wake each other
    let key = (tgid, uaddr);
    let prepare_permit = FutexPreparePermit::try_acquire(tgid)?;

    // 获取或创建此地址的等待桶
    // R172-07/08 FIX: obtain a LIVE bucket and bump waiter_count under the bucket lock with a
    // re-check of `unlinked` — the first-publish guard. waiter_count>=1 then pins the bucket
    // table-resident (cleanup_empty_bucket's emptiness gate fails), so all later re-locks of
    // `bucket` operate on the live table entry. If a reaper unlinked it in the get->lock gap
    // we retry; on exhaustion fail closed rather than enqueue on an orphan no waker can find.
    // R181-1 FIX: exhaustion returns TooManyBuckets (-> ENOMEM), NOT WouldBlock (-> EAGAIN).
    // EAGAIN means "futex word mismatched, retry immediately" — under sustained reaper
    // thrashing that spins userspace in a livelock. Retry exhaustion is a transient resource
    // failure, so it must surface as one.
    let (bucket, queue) = {
        let mut attempt = 0;
        loop {
            let bucket = get_or_create_live_bucket(key, &prepare_permit)?;
            let mut b = bucket.lock();
            if b.unlinked {
                drop(b);
                attempt += 1;
                if attempt >= FUTEX_REVALIDATE_RETRIES {
                    return Err(FutexError::TooManyBuckets);
                }
                continue;
            }
            if reserve_bucket_waiter(&mut b).is_err() {
                drop(b);
                cleanup_empty_bucket(key, &bucket);
                return Err(FutexError::TooManyBuckets);
            }
            let queue = b.queue.clone();
            drop(b);
            break (bucket, queue);
        }
    };

    // P2-B / RF178-8: under-lock recheck-before-publish. `try_prepare_with_timeout_after`
    // holds the WaitQueue `waiters` lock across (1) this futex-word re-read and
    // (2) enqueue+Blocked. All FUTEX_WAKE paths take the same lock first, so a
    // concurrent wake either observes this waiter or its store is visible to the
    // re-read — the R172 compare/enqueue lost-wake class is closed by construction.
    let prepared =
        match queue.try_prepare_with_timeout_after(timeout_ns, || match read_user_u32(uaddr) {
            Ok(cur) if cur == expected => Ok(()),
            Ok(_) => Err(FutexError::WouldBlock),
            Err(error) => Err(error),
        }) {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                let mut b = bucket.lock();
                b.waiter_count = b.waiter_count.saturating_sub(1);
                drop(b);
                cleanup_empty_bucket(key, &bucket);
                return Err(error);
            }
            Err(_) => {
                let mut b = bucket.lock();
                b.waiter_count = b.waiter_count.saturating_sub(1);
                drop(b);
                cleanup_empty_bucket(key, &bucket);
                return Err(FutexError::TooManyBuckets);
            }
        };
    drop(prepare_permit);
    let outcome = match prepared {
        PrepareWait::Armed(ticket) => queue.finish_prepared(ticket),
        PrepareWait::Immediate(outcome) => outcome,
    };

    // 被唤醒后减少等待者计数
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
    }

    // 尝试清理空桶
    cleanup_empty_bucket(key, &bucket);

    // R39-6 FIX: 根据等待结果返回
    match outcome {
        WaitOutcome::Woken => Ok(0),
        WaitOutcome::TimedOut => Err(FutexError::TimedOut),
        WaitOutcome::Closed | WaitOutcome::NoProcess => Err(FutexError::NoProcess),
        // R171-F3: a pending kill interrupted the futex wait (-> EINTR).
        WaitOutcome::Interrupted => Err(FutexError::Interrupted),
        WaitOutcome::ResourceExhausted => Err(FutexError::TooManyBuckets),
    }
}

/// FUTEX_WAKE 操作
///
/// 唤醒最多 n 个在 uaddr 上等待的进程。
///
/// # Arguments
///
/// * `tgid` - 线程组 ID (R37-2 FIX: 使用 TGID 而非 PID)
/// * `uaddr` - 用户空间 futex 地址
/// * `n` - 最多唤醒的进程数量
///
/// # Returns
///
/// 实际唤醒的进程数量
pub fn futex_wake(tgid: ProcessId, uaddr: usize, n: usize) -> usize {
    // R37-2 FIX: Futex key is scoped by TGID
    let key = (tgid, uaddr);

    // 查找此地址的等待桶
    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    };

    let woken = if let Some(ref bucket) = bucket {
        // 获取队列 Arc 后释放桶锁，避免在唤醒时持有锁
        let queue = {
            let b = bucket.lock();
            b.queue.clone()
        };
        queue.wake_n(n)
    } else {
        0
    };

    // 尝试清理空桶
    if let Some(ref bucket) = bucket {
        cleanup_empty_bucket(key, bucket);
    }

    woken
}

/// E.4 PI: FUTEX_LOCK_PI 操作（带优先级继承的互斥锁加锁）
///
/// # 语义
///
/// - 如果未被持有，当前线程成为 owner，返回 Ok(0)
/// - 如果被其他线程持有，当前线程加入等待队列，并将自身优先级捐赠给 owner（链式传播）
/// - 如果 owner 已经死亡（robust futex），新的持有者获得锁并返回 OwnerDied
/// - 如果自己已经持有该锁，返回 InvalidOperation（防止死锁）
///
/// # Arguments
///
/// * `tgid` - 线程组 ID
/// * `uaddr` - 用户空间 futex 地址
/// * `_current_value` - 当前从用户空间读取的值（用于验证）
///
/// # Returns
///
/// 成功获取锁返回 Ok(0)，锁持有者死亡返回 Err(OwnerDied)
pub fn futex_lock_pi(
    tgid: ProcessId,
    uaddr: usize,
    _current_value: u32,
) -> Result<usize, FutexError> {
    let pid = process::current_pid().ok_or(FutexError::NoProcess)?;
    let key: FutexKey = (tgid, uaddr);
    let prepare_permit = FutexPreparePermit::try_acquire(tgid)?;

    // 获取当前等待者的优先级
    let waiter_priority = {
        let proc_arc = process::get_process(pid).ok_or(FutexError::NoProcess)?;
        let proc = proc_arc.lock();
        proc.dynamic_priority
    };

    // R172-07/08 FIX: acquire a LIVE bucket and run the claim/wait fast-path under the bucket
    // lock with an `unlinked` first-publish guard (retry on the rare get->lock reap race,
    // bounded). The owner-claim / waiter_count++ below makes the bucket non-empty, pinning it
    // table-resident so cleanup_empty_bucket cannot orphan it — which previously let a stale
    // Arc be claimed while a second LOCK_PI minted a fresh bucket for the same key, giving
    // TWO simultaneous owners of one PI mutex (the R172-08 double-owner bug).
    let bucket = {
        let mut attempt = 0;
        loop {
            let bucket = get_or_create_live_bucket(key, &prepare_permit)?;
            let mut b = bucket.lock();
            if b.unlinked {
                drop(b);
                attempt += 1;
                if attempt >= FUTEX_REVALIDATE_RETRIES {
                    // R181-1 FIX: same class as futex_wait — retry exhaustion on
                    // tombstoned buckets is a resource failure (ENOMEM), not a
                    // futex-word race (EAGAIN would livelock the LOCK_PI caller).
                    return Err(FutexError::TooManyBuckets);
                }
                continue;
            }

            // 清理已死亡的 owner（robust futex）
            // R161-13 FIX: Also detect zombie/terminated owners, not just reaped ones.
            if let Some(owner) = b.owner {
                let owner_dead = match process::get_process(owner) {
                    None => true,
                    Some(proc_arc) => {
                        let state = proc_arc.lock().state;
                        matches!(
                            state,
                            process::ProcessState::Zombie | process::ProcessState::Terminated
                        )
                    }
                };
                if owner_dead {
                    b.owner = None;
                    b.owner_dead = true;
                }
            }

            if b.owner.is_none() {
                // 锁空闲，直接获取
                let owner_died = b.owner_dead;
                b.owner = Some(pid);
                b.owner_dead = false;
                let (_, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
                drop(b);
                drop(retired_pi);
                return if owner_died {
                    Err(FutexError::OwnerDied)
                } else {
                    Ok(0)
                };
            }

            if b.owner == Some(pid) {
                // 自己已经持有，防止死锁
                return Err(FutexError::InvalidOperation);
            }

            // 需要等待：增加计数但暂不记录 pi_waiters（避免 race）
            reserve_bucket_waiter(&mut b)?;
            drop(b);
            break bucket;
        }
    };

    // RF178-8: reserve the future owner's keyed boost slot under the target
    // PCB lock before publishing either waiting_on_futex or PI queue state.
    // A robust-exit/unlock handoff can therefore propagate without allocation.
    let proc_arc = match process::get_process(pid) {
        Some(proc) => proc,
        None => {
            let mut b = bucket.lock();
            b.waiter_count = b.waiter_count.saturating_sub(1);
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::NoProcess);
        }
    };
    {
        let mut proc = proc_arc.lock();
        if proc.try_reserve_pi_boost(key).is_err() {
            drop(proc);
            let mut b = bucket.lock();
            b.waiter_count = b.waiter_count.saturating_sub(1);
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::TooManyBuckets);
        }
        proc.set_waiting_on_futex(Some(key));
    }

    // CRITICAL FIX: 先加入 WaitQueue，再记录 pi_waiters
    // 这避免了 unlock_pi 在 waiter 入队前就尝试 wake_specific 的 race
    let queue = { bucket.lock().queue.clone() };
    let prepared = match queue.try_prepare_to_wait() {
        Ok(prepared) => prepared,
        Err(_) => {
            let mut b = bucket.lock();
            b.waiter_count = b.waiter_count.saturating_sub(1);
            drop(b);
            let mut proc = proc_arc.lock();
            proc.set_waiting_on_futex(None);
            proc.cancel_pi_boost_reservation(&key);
            drop(proc);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::TooManyBuckets);
        }
    };
    if !prepared {
        // 入队失败（队列已关闭或无当前进程），回滚
        let mut b = bucket.lock();
        b.waiter_count = b.waiter_count.saturating_sub(1);
        drop(b);
        let mut proc = proc_arc.lock();
        proc.set_waiting_on_futex(None);
        proc.cancel_pi_boost_reservation(&key);
        drop(proc);
        cleanup_empty_bucket(key, &bucket);
        // M0-5 1b-1b: prepare_to_wait ALSO bails (returns false) when a pending kill or a
        // deliverable HANDLER signal raced in before the task published Blocked (the M0-5
        // 1b should_abort_pending_block re-check). Distinguish that from a genuine
        // closed-queue / no-current-process failure and return a PRECISE EINTR. kill-first.
        if process::wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
            return Err(FutexError::Interrupted);
        }
        return Err(FutexError::NoProcess);
    }

    // 现在 waiter 已在队列中，安全地记录 pi_waiters
    if insert_pi_waiter(&bucket, pid, waiter_priority, &prepare_permit).is_err() {
        let mut b = bucket.lock();
        b.waiter_count = b.waiter_count.saturating_sub(1);
        let (_, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
        drop(b);
        drop(retired_pi);
        queue.cancel_wait();
        let mut proc = proc_arc.lock();
        proc.set_waiting_on_futex(None);
        proc.cancel_pi_boost_reservation(&key);
        drop(proc);
        cleanup_empty_bucket(key, &bucket);
        return Err(FutexError::TooManyBuckets);
    }
    drop(prepare_permit);

    // R73-1 FIX: 窗口修复——在 pi_waiters.insert 后再次检查 owner 状态
    // 如果在 prepare_to_wait() 和 pi_waiters.insert() 之间 owner 已经 unlock,
    // 此时 owner 会是 None，我们需要直接获取锁而不是阻塞
    {
        let mut b = bucket.lock();
        if b.owner.is_none() {
            let owner_died = b.owner_dead;
            b.owner = Some(pid);
            b.owner_dead = false;
            let (_, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            drop(retired_pi);
            // 取消排队的等待，防止永久阻塞
            queue.cancel_wait();
            proc_arc.lock().set_waiting_on_futex(None);
            recompute_pi_state_noalloc(key, &bucket);
            proc_arc.lock().cancel_pi_boost_reservation(&key);
            cleanup_empty_bucket(key, &bucket);
            return if owner_died {
                Err(FutexError::OwnerDied)
            } else {
                Ok(0)
            };
        }
    }

    // 触发 PI 传播到当前 owner
    if recompute_pi_state(key, &bucket).is_err() {
        // The only expected allocation in propagation is the current owner's
        // first keyed boost. Roll back every published waiter facet before
        // returning ENOMEM, then restore the owner's remaining donation.
        let mut b = bucket.lock();
        let (_, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
        b.waiter_count = b.waiter_count.saturating_sub(1);
        drop(b);
        drop(retired_pi);
        queue.cancel_wait();
        let mut proc = proc_arc.lock();
        proc.set_waiting_on_futex(None);
        proc.cancel_pi_boost_reservation(&key);
        drop(proc);
        recompute_pi_state_noalloc(key, &bucket);
        cleanup_empty_bucket(key, &bucket);
        return Err(FutexError::TooManyBuckets);
    }

    // 完成等待（实际阻塞）
    queue.finish_wait();

    // 检查是否因超时或关闭被唤醒（此处没有超时，所以只处理正常唤醒和关闭）
    // Note: finish_wait 不返回 outcome，需要通过其他方式判断
    // 我们使用 Woken 作为默认，因为 PI futex 不支持超时（目前）

    // 出队并更新 PI 状态
    let mut owner_died = false;
    // R169-8 FIX: track whether the caller actually became the PI-mutex owner.
    let mut acquired = false;
    let retired_pi;
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
        (_, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
        owner_died = b.owner_dead;

        // CRITICAL FIX: 检查是否已被 unlock_pi 设置为 owner
        // 如果已经是 owner，就不需要再竞争
        if b.owner == Some(pid) {
            // 已经被 unlock_pi 转移了所有权
            drop(b);
            drop(retired_pi);
            // R170-4 FIX (R169-8 asymmetry): a NON-dequeuing wake (signal/kill
            // wake, timeout) can leave our WaitQueue entry behind even though
            // unlock_pi transferred ownership to us — the stale entry would
            // make the next prepare_to_wait() on this queue skip the Blocked
            // transition (busy-spin) and could consume a wake_one meant for a
            // real waiter. Clear it BEFORE the PI recompute / bucket-emptiness
            // check (mirrors the tail exits below). Idempotent: a genuine
            // wake_specific already dequeued us → no-op. The Ready re-stamp
            // hazard on a Running task is closed by cancel_wait's new
            // Blocked-only state guard (sync.rs, R170-4).
            queue.cancel_wait();
            let mut proc = proc_arc.lock();
            proc.set_waiting_on_futex(None);
            proc.cancel_pi_boost_reservation(&key);
            drop(proc);
            recompute_pi_state_noalloc(key, &bucket);
            cleanup_empty_bucket(key, &bucket);
            return if owner_died {
                Err(FutexError::OwnerDied)
            } else {
                Ok(0)
            };
        }

        // 如果 owner 已经被清空（owner 死亡且未被 unlock_pi 处理），尝试接管锁
        if b.owner.is_none() {
            b.owner = Some(pid);
            b.owner_dead = false;
            acquired = true; // R169-8: took over the lock from a cleared owner
        }
        // else: b.owner == Some(other_pid) — the PI mutex is STILL held by
        // another task and we were woken WITHOUT acquiring it (a signal/kill/
        // spurious wake, NOT a grant). `acquired` stays false → fail CLOSED at
        // the tail rather than falsely reporting Ok(0).
    }
    drop(retired_pi);

    // 清除等待标记
    {
        let mut proc = proc_arc.lock();
        proc.set_waiting_on_futex(None);
        if !acquired {
            proc.cancel_pi_boost_reservation(&key);
        }
    }

    // R170-4 FIX (R169-8 asymmetry): clear any stale WaitQueue entry on EVERY
    // exit — takeover success AND EAGAIN — not just the retry path. After a
    // non-dequeuing wake (signal/kill wake, timeout) the entry lingers; on the
    // SUCCESS exit it is a phantom that (a) makes the next prepare_to_wait()
    // skip the Blocked transition (busy-spin on a later wait) and (b) can
    // consume a wake_one meant for a real waiter. Runs BEFORE the PI
    // recompute / bucket-emptiness check so cleanup_empty_bucket never
    // observes a phantom entry. Idempotent on the normal grant path (the
    // waker already dequeued us); the Ready re-stamp on a Running task is
    // closed by cancel_wait's Blocked-only guard (sync.rs, R170-4).
    queue.cancel_wait();

    // 等待者离开后重新计算 PI
    recompute_pi_state_noalloc(key, &bucket);
    if acquired {
        proc_arc.lock().cancel_pi_boost_reservation(&key);
    }
    cleanup_empty_bucket(key, &bucket);

    // R169-8 FIX (fail-closed-on-non-grant, INV-FUTEX-PI): report success ONLY
    // when the caller actually OWNS the PI mutex. `acquired` is the takeover case
    // (b.owner was None and we claimed it under the bucket lock above); the
    // case-A transfer (b.owner == Some(pid)) already returned early. `owner_died`
    // is meaningful ONLY when we hold the lock: a robust-owner handoff sets
    // `owner_dead = true` WITH `owner = Some(successor)`, so surfacing OwnerDied
    // for a NON-owner wake would falsely tell the caller it owns an inconsistent
    // mutex — the SAME fail-open class as the original Ok(0) fallthrough. Hence
    // `owner_died` is conditioned on `acquired`. Any other wake (b.owner ==
    // Some(other): signal/kill/spurious, NOT a grant) failed to acquire → return
    // EAGAIN (WouldBlock) so the caller retries the LOCK_PI loop. The stale
    // WaitQueue entry was already cleared for BOTH exits by the R170-4
    // queue.cancel_wait() above (before the PI recompute), so the retry
    // re-enqueues cleanly and the success exit leaves no phantom entry.
    if acquired {
        if owner_died {
            Err(FutexError::OwnerDied)
        } else {
            Ok(0)
        }
    } else {
        // M0-5 1b-1b: a NON-grant wake that is a pending kill OR a deliverable HANDLER
        // signal returns a PRECISE EINTR (Interrupted) instead of the imprecise EAGAIN
        // (WouldBlock). kill-FIRST (wait_should_abort short-circuits before the signal
        // check); the signal branch never consumes pending_kill. Mirrors the already-
        // converged sync.rs wait epilogue (R171-F3 kill gate + M0-5 1b
        // has_deliverable_signal). A non-kill, non-signal spurious wake still returns
        // WouldBlock so the caller retries the LOCK_PI loop (no control-flow change).
        if process::wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
            Err(FutexError::Interrupted)
        } else {
            Err(FutexError::WouldBlock)
        }
    }
}

/// E.4 PI: FUTEX_UNLOCK_PI 操作（带优先级继承的互斥锁解锁）
///
/// # 语义
///
/// - 仅持有者可以解锁
/// - 将锁直接转移给最高优先级的等待者
/// - 根据剩余等待者更新 PI 状态
///
/// # Arguments
///
/// * `tgid` - 线程组 ID
/// * `uaddr` - 用户空间 futex 地址
///
/// # Returns
///
/// 成功解锁返回 Ok(0)，不是持有者返回 Err(InvalidOperation)
pub fn futex_unlock_pi(tgid: ProcessId, uaddr: usize) -> Result<usize, FutexError> {
    let pid = process::current_pid().ok_or(FutexError::NoProcess)?;
    let key: FutexKey = (tgid, uaddr);

    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    }
    .ok_or(FutexError::InvalidOperation)?;

    let (queue, next_owner, remaining_boost, retired_pi) = {
        let mut b = bucket.lock();
        if b.owner != Some(pid) {
            return Err(FutexError::InvalidOperation);
        }

        // R162-8-2 / RF178-8: prune in place without BTreeMap::retain or a
        // scratch collection. AdmittedMap removal retains backing and never allocates.
        loop {
            let dead = b.pi_waiters.iter().find_map(|(waiter, _)| {
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
                    b.pi_waiters.remove_retaining_capacity(&waiter);
                }
                None => break,
            }
        }

        let queue = b.queue.clone();
        let next = select_highest_waiter(&b.pi_waiters);

        if let Some((next_pid, _prio)) = next {
            // 直接移除并转移所有权
            b.pi_waiters.remove_retaining_capacity(&next_pid);
            b.owner = Some(next_pid);
            b.owner_dead = false;
        } else {
            b.owner = None;
            b.owner_dead = false;
        }

        let donation = highest_waiter_priority(&b);
        let retired_pi = b.pi_waiters.take_empty_capacity();
        (queue, next.map(|(p, _)| p), donation, retired_pi)
    };
    drop(retired_pi);

    // 当前持有者清除自己的 PI 提升
    if let Some(proc) = process::get_process(pid) {
        let changed = proc.lock().try_update_pi_boost(key, None).unwrap_or(false);
        if changed {
            request_resched_from_irq();
        }
    }

    if let Some(new_owner) = next_owner {
        // 传递剩余等待者的捐赠到新的 owner，并链式传播
        if apply_pi_and_propagate(key, new_owner, remaining_boost).is_err() {
            kprintln!(
                "[FUTEX] RF178-8: successor {} lacked reserved PI slot for {:?}",
                new_owner,
                key
            );
        }

        // 清理等待标记并唤醒新的 owner
        if let Some(proc) = process::get_process(new_owner) {
            let mut proc = proc.lock();
            proc.set_waiting_on_futex(None);
            proc.cancel_pi_boost_reservation(&key);
        }
        queue.wake_specific(new_owner);
    } else {
        // 无等待者，尝试清理桶
        cleanup_empty_bucket(key, &bucket);
    }

    Ok(0)
}

/// 清理进程的所有 futex 等待队列
///
/// 进程/线程退出时调用，唤醒所有等待者并移除该进程的所有 futex 条目。
///
/// R37-2 FIX: 如果退出的线程还有 CLONE_THREAD 兄弟线程存活，则保留 TGID 的
/// futex 桶，避免清除正在使用的 futex。这保持了 pthread 语义。
///
/// E.4 PI: 如果退出的线程持有 PI futex，标记为 owner_dead 并选择
/// 最高优先级等待者作为继任者（robust futex 语义）。只唤醒继任者以保持互斥。
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
/// 2. When the owner unlocks, `select_highest_waiter()` may return the stale PID
/// 3. `wake_specific()` would try to wake the new (unrelated) process
/// 4. The real waiters would never be woken, causing deadlock
///
/// Now we clean up waiter entries first, before handling owner cleanup.
fn next_tgid_bucket(
    tgid: ProcessId,
    after: Option<FutexKey>,
) -> Option<(FutexKey, FutexBucketRef)> {
    let table = FUTEX_TABLE.lock();
    let lower = match after {
        Some(key) => Bound::Excluded(key),
        None => Bound::Included((tgid, 0)),
    };
    let next = table
        .range((lower, Bound::Included((tgid, usize::MAX))))
        .next()
        .map(|(key, bucket)| (*key, bucket.clone()));
    next
}

/// RF178-8: unlink one TGID bucket without a key snapshot Vec. The tombstone
/// and removal remain atomic under the established table->bucket lock order.
fn unlink_first_tgid_bucket(tgid: ProcessId) -> Option<FutexQueueRef> {
    let (queue, removed, retired) = {
        let mut table = FUTEX_TABLE.lock();
        let key = table
            .range((tgid, 0)..=(tgid, usize::MAX))
            .next()
            .map(|(key, _)| *key)?;
        let queue = {
            let bucket = table
                .get(&key)
                .expect("RF180-47 selected futex bucket disappeared under table lock");
            let mut bucket = bucket.lock();
            bucket.unlinked = true;
            bucket.queue.clone()
        };
        let removed = table.remove_retaining_capacity(&key);
        let retired = table.take_empty_capacity();
        (queue, removed, retired)
    };
    drop(retired);
    drop(removed);
    Some(queue)
}

/// R180-5 FIX: generation-bound process futex cleanup.
///
/// `generation` is the reaped PCB generation captured before the table slot was
/// cleared. If a live PCB at `pid` has a different generation, skip all
/// PID-keyed waiter/owner mutations for that pid (successor already owns it).
/// TGID-scoped bucket walks still run for the reaped identity's group.
pub fn cleanup_process_futexes(pid: ProcessId, tgid: ProcessId, generation: u64) {
    // R37-2 FIX (Codex review): Use TGID provided by caller, not from process lock.
    // Check thread group size without locking the current process.
    let group_size = process::thread_group_size(tgid);

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
        while let Some((key, bucket)) = next_tgid_bucket(tgid, after) {
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
            let mut needs_pi_recompute = false;
            let (queue, removed_from_pi, retired_pi) = {
                let mut b = bucket.lock();

                // Skip if this PID is the owner (handled in next phase)
                if b.owner == Some(pid) {
                    continue;
                }

                // Remove from pi_waiters if present
                let (removed_from_pi, retired_pi) = remove_pi_waiter_locked(&mut b, pid);
                let removed_from_pi = removed_from_pi.is_some();

                if removed_from_pi {
                    needs_pi_recompute = true;
                }

                (b.queue.clone(), removed_from_pi, retired_pi)
            };
            drop(retired_pi);

            // Remove from WaitQueue (this handles non-PI waiters too)
            // wake_specific returns true if the PID was found and removed
            let was_in_queue = queue.wake_specific(pid);
            // Also drain process-generation-stamped entries for this identity.
            queue.cleanup_for_identity(pid, generation);

            // R72-1 FIX (Codex review): Only decrement waiter_count once.
            // A process waiting on a PI futex is counted once in waiter_count,
            // even though it appears in both pi_waiters and WaitQueue.
            // Decrement only if we found it in either location.
            if removed_from_pi || was_in_queue {
                let mut b = bucket.lock();
                if b.waiter_count > 0 {
                    b.waiter_count -= 1;
                }
            }

            // Recompute PI state if we removed a PI waiter
            // This ensures the owner's priority boost is correctly updated
            if needs_pi_recompute {
                recompute_pi_state_noalloc(key, &bucket);
            }

            // Try to clean up empty bucket
            cleanup_empty_bucket(key, &bucket);
        }
    }

    // E.4 PI: 先标记由退出线程持有的 futex（robust 语义）
    // R180-5: never transfer PI ownership when a successor already owns the PID.
    if !successor_live {
        let mut after = None;
        while let Some((key, bucket)) = next_tgid_bucket(tgid, after) {
            after = Some(key);
            let (queue, next_owner, retired_pi) = {
                let mut b = bucket.lock();
                if b.owner != Some(pid) {
                    continue;
                }

                // 标记 owner 死亡
                b.owner_dead = true;

                // CRITICAL FIX: 选择最高优先级等待者作为继任者，而非唤醒全部
                // 这保持了互斥语义
                let queue = b.queue.clone();
                let next = select_highest_waiter(&b.pi_waiters);

                if let Some((next_pid, _prio)) = next {
                    // 转移所有权给继任者
                    b.pi_waiters.remove_retaining_capacity(&next_pid);
                    b.owner = Some(next_pid);
                    // 保持 owner_dead = true 以便继任者知道前任已死亡
                } else {
                    // 无等待者，清除所有权
                    b.owner = None;
                }

                let retired_pi = b.pi_waiters.take_empty_capacity();
                (queue, next.map(|(p, _)| p), retired_pi)
            };
            drop(retired_pi);

            if let Some(new_owner) = next_owner {
                // 清除继任者的等待标记并唤醒
                if let Some(proc) = process::get_process(new_owner) {
                    proc.lock().set_waiting_on_futex(None);
                }
                queue.wake_specific(new_owner);
            }

            // 重新计算 PI（owner 已变更）
            recompute_pi_state_noalloc(key, &bucket);
            if let Some(new_owner) = next_owner {
                if let Some(proc) = process::get_process(new_owner) {
                    proc.lock().cancel_pi_boost_reservation(&key);
                }
            }
        }
    }

    // R178-19 FIX: Preserve buckets when group_size > 0 (not > 1).
    // group_size is the count EXCLUDING the exiting thread (process::thread_group_size
    // already decremented by terminate_process). So group_size == 1 means exactly one
    // OTHER thread remains alive; group_size == 0 means this is the LAST thread.
    // Only remove buckets when group_size == 0 (last thread exiting).
    // R180-5: also skip TGID unlink when a successor recycled the PID — the
    // successor may share the TGID and still need the buckets.
    if group_size > 0 || successor_live {
        return;
    }

    // RF178-8: stream removals; exit never allocates a key/bucket snapshot.
    while let Some(queue) = unlink_first_tgid_bucket(tgid) {
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

    let tgid = key.0;
    let tgid_live = table.range((tgid, 0)..=(tgid, usize::MAX)).count();
    if table.len() >= MAX_FUTEX_BUCKETS_GLOBAL || tgid_live >= MAX_FUTEX_BUCKETS_PER_TGID {
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
) -> Result<FutexBucketRef, FutexError> {
    {
        let table = FUTEX_TABLE.lock();
        if let Some(bucket) = table.get(&key) {
            return Ok(bucket.clone());
        }
        let tgid_live = table.range((key.0, 0)..=(key.0, usize::MAX)).count();
        if table.len() >= MAX_FUTEX_BUCKETS_GLOBAL || tgid_live >= MAX_FUTEX_BUCKETS_PER_TGID {
            return Err(FutexError::TooManyBuckets);
        }
    }

    let queue = try_new_futex_arc(WaitQueue::new(HeapClass::Futex))?;
    let mut candidate = Some(try_new_futex_arc(Mutex::new(FutexBucket::new(queue)))?);

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

fn get_or_create_bucket(key: FutexKey) -> Result<FutexBucketRef, FutexError> {
    let permit = FutexPreparePermit::try_acquire(key.0)?;
    get_or_create_bucket_with_permit(key, &permit)
}

/// 清理空的等待桶（无等待者时移除）
///
/// E.4 PI: 额外检查 owner 和 pi_waiters 是否为空
fn cleanup_empty_bucket(key: FutexKey, bucket: &FutexBucketRef) {
    // R172-07/08 FIX: TABLE-first then bucket (the established table->bucket lock order, e.g.
    // apply_pi_and_propagate / cleanup_process_futexes), so publishing the `unlinked`
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
                // E.4 PI: 只有当 owner、等待者、队列都为空时才清理
                if b.waiter_count == 0
                    && b.queue.is_empty()
                    && b.owner.is_none()
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

/// 获取活跃的 futex 地址数量（调试用）
pub fn active_futex_count() -> usize {
    FUTEX_TABLE.lock().len()
}

/// FutexTable 类型别名（向后兼容）
pub type FutexTable = ();

// ============================================================================
// E.4 PI: 内部辅助函数（优先级继承支持）
// ============================================================================

/// E.4 PI: 选择最高优先级（数值最小）的等待者
fn select_highest_waiter(
    waiters: &AdmittedMap<ProcessId, Priority>,
) -> Option<(ProcessId, Priority)> {
    waiters
        .iter()
        .min_by_key(|(_, prio)| *prio)
        .map(|(pid, prio)| (*pid, *prio))
}

/// E.4 PI: 获取当前最高优先级等待者的优先级（仅优先级值）
fn highest_waiter_priority(bucket: &FutexBucket) -> Option<Priority> {
    bucket.pi_waiters.values().min().copied()
}

/// E.4 PI: Maximum PI chain propagation depth
///
/// Limits the depth of PI chain traversal to prevent stack overflow from
/// maliciously constructed long wait chains. 64 is a reasonable limit -
/// real-world systems rarely have chains deeper than 5-10 levels.
const MAX_PI_CHAIN_DEPTH: usize = 64;

/// E.4 PI: 将优先级捐赠应用于 owner 并沿等待链路传播（A -> B -> C）
///
/// 支持链式优先级继承：如果 owner 也在等待其他 futex，则继续向上传播
///
/// RF178-8: the PI graph has out-degree at most one (`waiting_on_futex`), so a
/// cursor plus a fixed visited array is sufficient. This path is used during
/// process exit; it must not allocate a Vec/BTreeSet or grow a boost map.
fn apply_pi_and_propagate(
    key: FutexKey,
    owner: ProcessId,
    donated: Option<Priority>,
) -> Result<(), FutexError> {
    let mut visited = [(0, 0); MAX_PI_CHAIN_DEPTH];
    let mut visited_len = 0usize;
    let mut current = Some((key, owner, donated));

    while let Some((cur_key, cur_owner, donation)) = current.take() {
        if visited[..visited_len].contains(&cur_key) {
            break;
        }
        if visited_len == MAX_PI_CHAIN_DEPTH {
            kprintln!(
                "[FUTEX] PI chain depth exceeded {} at key {:?}, truncating",
                MAX_PI_CHAIN_DEPTH,
                cur_key
            );
            break;
        }
        visited[visited_len] = cur_key;
        visited_len += 1;

        let proc = match process::get_process(cur_owner) {
            Some(proc) => proc,
            None => break,
        };
        let (changed, next_wait, effective_prio) = {
            let mut p = proc.lock();
            let changed = p
                .try_update_pi_boost(cur_key, donation)
                .map_err(|_| FutexError::TooManyBuckets)?;
            let next = p.get_waiting_on_futex();
            let eff = p.dynamic_priority;
            (changed, next, eff)
        };

        if changed {
            request_resched_from_irq();
        }

        current = next_wait.and_then(|next_key| {
            let table = FUTEX_TABLE.lock();
            table
                .get(&next_key)
                .and_then(|bucket| bucket.lock().owner)
                .map(|next_owner| (next_key, next_owner, Some(effective_prio)))
        });
    }

    Ok(())
}

/// E.4 PI: 根据当前等待者重新计算 owner 的 PI，并处理链式传播/清除
fn recompute_pi_state(key: FutexKey, bucket: &FutexBucketRef) -> Result<(), FutexError> {
    let (owner, donation) = {
        let mut b = bucket.lock();
        // R162-8-1 FIX: Detect zombie/terminated owners (same pattern as R161-13).
        if let Some(owner_pid) = b.owner {
            let owner_dead = match process::get_process(owner_pid) {
                None => true,
                Some(proc_arc) => {
                    let state = proc_arc.lock().state;
                    matches!(
                        state,
                        process::ProcessState::Zombie | process::ProcessState::Terminated
                    )
                }
            };
            if owner_dead {
                b.owner = None;
                b.owner_dead = true;
            }
        }
        (b.owner, highest_waiter_priority(&b))
    };

    if let Some(owner_pid) = owner {
        apply_pi_and_propagate(key, owner_pid, donation)?;
    }
    Ok(())
}

/// Propagation sites after waiter admission are allocation-free by invariant:
/// an existing owner already has the keyed boost entry, while a successor owns
/// a PCB reservation made before it entered the PI queue. Never convert an
/// invariant violation into a false lock failure after ownership moved.
fn recompute_pi_state_noalloc(key: FutexKey, bucket: &FutexBucketRef) {
    if recompute_pi_state(key, bucket).is_err() {
        kprintln!(
            "[FUTEX] RF178-8: missing reserved PI boost slot for key {:?}",
            key
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn new_test_bucket() -> FutexBucketRef {
        let queue =
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)).expect("RF180-47 test queue");
        try_new_futex_arc(Mutex::new(FutexBucket::new(queue))).expect("RF180-47 test bucket")
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
    fn futex_arc_charges_release_only_after_final_weak() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Futex);

        let queue =
            try_new_futex_arc(WaitQueue::new(HeapClass::Futex)).expect("RF180-47 charged queue");
        let queue_allocator = *Arc::allocator(&queue);
        let queue_weak: FutexWeak<WaitQueue> = Arc::downgrade(&queue);
        let bucket = try_new_futex_arc(Mutex::new(FutexBucket::new(queue)))
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
            try_new_futex_arc(Mutex::new(FutexBucket::new(queue))),
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

        for index in 0..MAX_FUTEX_BUCKETS_PER_TGID {
            let key = (tgid, 0x1000 + index);
            drop(get_or_create_bucket(key).expect("RF180-47 admitted TGID bucket"));
        }

        let rejected_key = (tgid, 0x2000 + MAX_FUTEX_BUCKETS_PER_TGID);
        assert!(matches!(
            get_or_create_bucket(rejected_key),
            Err(FutexError::TooManyBuckets)
        ));
        for index in 0..MAX_FUTEX_BUCKETS_PER_TGID {
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
            let group = index / MAX_FUTEX_BUCKETS_PER_TGID;
            let slot = index % MAX_FUTEX_BUCKETS_PER_TGID;
            let key = (base_tgid + group, 0x1000 + slot);
            drop(get_or_create_bucket(key).expect("RF180-47 admitted global bucket"));
        }

        let rejected_group = MAX_FUTEX_BUCKETS_GLOBAL / MAX_FUTEX_BUCKETS_PER_TGID + 1;
        assert!(matches!(
            get_or_create_bucket((base_tgid + rejected_group, 0x4000)),
            Err(FutexError::TooManyBuckets)
        ));
        for index in 0..MAX_FUTEX_BUCKETS_GLOBAL {
            let group = index / MAX_FUTEX_BUCKETS_PER_TGID;
            let slot = index % MAX_FUTEX_BUCKETS_PER_TGID;
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

        let permit =
            FutexPreparePermit::try_acquire(0x47).expect("RF180-47 PI waiter preparation permit");
        insert_pi_waiter(&bucket, 0x47, 7, &permit).expect("RF180-47 PI waiter publish");
        drop(permit);
        let with_backing = mm::heap_class_snapshot(HeapClass::Futex);
        let retired = {
            let mut bucket = bucket.lock();
            let (removed, retired) = remove_pi_waiter_locked(&mut bucket, 0x47);
            assert_eq!(removed, Some(7));
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
}
