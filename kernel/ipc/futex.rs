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

use alloc::sync::Arc;
use core::mem::size_of;
use core::ops::Bound;
use kernel_core::process::{self, FutexKey, Priority, ProcessId};
use kernel_core::request_resched_from_irq;
use mm::fallible_map::FallibleOrderedMap;
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

/// RF178-8: futex metadata may retain at most one quarter of the actual 1 MiB
/// kernel heap. The charge covers both Arc allocations plus worst-case 2x Vec
/// backing slack for the global FallibleOrderedMap, then doubles the whole raw
/// layout for allocator alignment/fragmentation headroom. Birth is independently
/// fallible, so fragmentation rejects admission rather than aborting the kernel.
const FUTEX_HEAP_BUDGET_BYTES: usize = mm::memory::HEAP_SIZE_BYTES / 4;
const ARC_HEADER_BYTES: usize = 2 * size_of::<usize>();
type FutexBucketRef = Arc<Mutex<FutexBucket>>;
const FUTEX_TABLE_SLOT_BYTES: usize = size_of::<(FutexKey, FutexBucketRef)>();
const FUTEX_BUCKET_RAW_BYTES: usize = size_of::<Mutex<FutexBucket>>()
    + ARC_HEADER_BYTES
    + size_of::<WaitQueue>()
    + ARC_HEADER_BYTES
    + 2 * FUTEX_TABLE_SLOT_BYTES;
const FUTEX_BUCKET_CHARGE_BYTES: usize = 2 * FUTEX_BUCKET_RAW_BYTES;
const MAX_FUTEX_BUCKETS_GLOBAL: usize = FUTEX_HEAP_BUDGET_BYTES / FUTEX_BUCKET_CHARGE_BYTES;
/// A single TGID receives at most one quarter of the global futex budget.
const MAX_FUTEX_BUCKETS_PER_TGID: usize = MAX_FUTEX_BUCKETS_GLOBAL / 4;

const _: () = assert!(FUTEX_HEAP_BUDGET_BYTES < mm::memory::HEAP_SIZE_BYTES);
const _: () = assert!(FUTEX_BUCKET_CHARGE_BYTES >= FUTEX_BUCKET_RAW_BYTES);
const _: () = assert!(MAX_FUTEX_BUCKETS_PER_TGID > 0);
const _: () =
    assert!(MAX_FUTEX_BUCKETS_GLOBAL * FUTEX_BUCKET_CHARGE_BYTES <= FUTEX_HEAP_BUDGET_BYTES);

/// 单个 futex 地址的等待状态
struct FutexBucket {
    /// 等待队列（Arc 包装，避免持有桶锁时阻塞导致死锁）
    queue: Arc<WaitQueue>,
    /// 活跃等待者计数（用于判断是否可以清理）
    waiter_count: usize,
    /// E.4 PI: 当前持有者（线程ID），FUTEX_LOCK_PI 使用
    owner: Option<ProcessId>,
    /// E.4 PI: 持有者已经死亡（robust futex 语义）
    owner_dead: bool,
    /// E.4 PI: PI 等待者列表 (pid -> priority)，用于找出最高优先级的等待者
    pi_waiters: FallibleOrderedMap<ProcessId, Priority>,
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
    fn new(queue: Arc<WaitQueue>) -> Self {
        FutexBucket {
            queue,
            waiter_count: 0,
            owner: None,
            owner_dead: false,
            pi_waiters: FallibleOrderedMap::new(),
            unlinked: false,
        }
    }
}

/// R172-07/08: bounded retry count for obtaining a live (non-tombstoned) bucket. A
/// pathological reaper could repeatedly unlink between create and lock; the bound makes the
/// loop terminate (the per-site `unlinked` guard is the authoritative correctness check).
const FUTEX_REVALIDATE_RETRIES: usize = 16;

/// R172-07/08: get-or-create a bucket and ensure the returned `Arc` is not already
/// tombstoned. The per-first-publish-site `unlinked` re-check under the bucket lock is the
/// authoritative guard; this just avoids handing out an obviously-dead `Arc`.
fn get_or_create_live_bucket(key: FutexKey) -> Result<Arc<Mutex<FutexBucket>>, FutexError> {
    let mut last = get_or_create_bucket(key)?;
    for _ in 0..FUTEX_REVALIDATE_RETRIES {
        if !last.lock().unlinked {
            return Ok(last);
        }
        last = get_or_create_bucket(key)?;
    }
    Ok(last)
}

lazy_static::lazy_static! {
    /// 全局 Futex 表
    ///
    /// 以 (pid, vaddr) 为键，管理该地址上的等待队列。
    /// 空队列会在唤醒后被清理，避免内存泄漏。
    static ref FUTEX_TABLE: Mutex<FallibleOrderedMap<FutexKey, FutexBucketRef>> =
        Mutex::new(FallibleOrderedMap::new());
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

    // 获取或创建此地址的等待桶
    // R172-07/08 FIX: obtain a LIVE bucket and bump waiter_count under the bucket lock with a
    // re-check of `unlinked` — the first-publish guard. waiter_count>=1 then pins the bucket
    // table-resident (cleanup_empty_bucket's emptiness gate fails), so all later re-locks of
    // `bucket` operate on the live table entry. If a reaper unlinked it in the get->lock gap
    // we retry; on exhaustion fail closed (WouldBlock -> userspace retries) rather than
    // enqueue on an orphan no waker can find.
    let (bucket, queue) = {
        let mut attempt = 0;
        loop {
            let bucket = get_or_create_live_bucket(key)?;
            let mut b = bucket.lock();
            if b.unlinked {
                drop(b);
                attempt += 1;
                if attempt >= FUTEX_REVALIDATE_RETRIES {
                    return Err(FutexError::WouldBlock);
                }
                continue;
            }
            b.waiter_count += 1;
            let queue = b.queue.clone();
            drop(b);
            break (bucket, queue);
        }
    };

    // 【关键修复】在入队前二次读取 futex 值，防止 lost-wake 竞态
    // 如果值已变化，说明唤醒者已经完成操作，我们不应该阻塞
    // RF178-8 FIX: publish the complete fallible queue/timer transaction before
    // the second futex-word read. A concurrent wake now either observes this
    // waiter, or its preceding store is observed by the re-read below.
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
            let bucket = get_or_create_live_bucket(key)?;
            let mut b = bucket.lock();
            if b.unlinked {
                drop(b);
                attempt += 1;
                if attempt >= FUTEX_REVALIDATE_RETRIES {
                    return Err(FutexError::WouldBlock);
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
                b.pi_waiters.remove(&pid);
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
            b.waiter_count += 1;
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
    {
        let mut b = bucket.lock();
        if b.pi_waiters.try_insert(pid, waiter_priority).is_err() {
            b.waiter_count = b.waiter_count.saturating_sub(1);
            drop(b);
            queue.cancel_wait();
            let mut proc = proc_arc.lock();
            proc.set_waiting_on_futex(None);
            proc.cancel_pi_boost_reservation(&key);
            drop(proc);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::TooManyBuckets);
        }
    }

    // R73-1 FIX: 窗口修复——在 pi_waiters.insert 后再次检查 owner 状态
    // 如果在 prepare_to_wait() 和 pi_waiters.insert() 之间 owner 已经 unlock,
    // 此时 owner 会是 None，我们需要直接获取锁而不是阻塞
    {
        let mut b = bucket.lock();
        if b.owner.is_none() {
            let owner_died = b.owner_dead;
            b.owner = Some(pid);
            b.owner_dead = false;
            b.pi_waiters.remove(&pid);
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
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
        b.pi_waiters.remove(&pid);
        b.waiter_count = b.waiter_count.saturating_sub(1);
        drop(b);
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
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
        b.pi_waiters.remove(&pid);
        owner_died = b.owner_dead;

        // CRITICAL FIX: 检查是否已被 unlock_pi 设置为 owner
        // 如果已经是 owner，就不需要再竞争
        if b.owner == Some(pid) {
            // 已经被 unlock_pi 转移了所有权
            drop(b);
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

    let (queue, next_owner, remaining_boost) = {
        let mut b = bucket.lock();
        if b.owner != Some(pid) {
            return Err(FutexError::InvalidOperation);
        }

        // R162-8-2 / RF178-8: prune in place without BTreeMap::retain or a
        // scratch collection. Removal from FallibleOrderedMap never allocates.
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
                    b.pi_waiters.remove(&waiter);
                }
                None => break,
            }
        }

        let queue = b.queue.clone();
        let next = select_highest_waiter(&b.pi_waiters);

        if let Some((next_pid, _prio)) = next {
            // 直接移除并转移所有权
            b.pi_waiters.remove(&next_pid);
            b.owner = Some(next_pid);
            b.owner_dead = false;
        } else {
            b.owner = None;
            b.owner_dead = false;
        }

        let donation = highest_waiter_priority(&b);
        (queue, next.map(|(p, _)| p), donation)
    };

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
fn unlink_first_tgid_bucket(tgid: ProcessId) -> Option<Arc<WaitQueue>> {
    let mut table = FUTEX_TABLE.lock();
    let (key, bucket) = table
        .range((tgid, 0)..=(tgid, usize::MAX))
        .next()
        .map(|(key, bucket)| (*key, bucket.clone()))?;
    let queue = {
        let mut b = bucket.lock();
        b.unlinked = true;
        b.queue.clone()
    };
    table.remove(&key);
    Some(queue)
}

pub fn cleanup_process_futexes(pid: ProcessId, tgid: ProcessId) {
    // R37-2 FIX (Codex review): Use TGID provided by caller, not from process lock.
    // Check thread group size without locking the current process.
    let group_size = process::thread_group_size(tgid);

    // R72-1 FIX: Clean up this PID from ALL waiter lists (even if not owner).
    // This prevents stale PID references from poisoning futex state after PID reuse.
    {
        let mut after = None;
        while let Some((key, bucket)) = next_tgid_bucket(tgid, after) {
            after = Some(key);
            let mut needs_pi_recompute = false;
            let (queue, removed_from_pi) = {
                let mut b = bucket.lock();

                // Skip if this PID is the owner (handled in next phase)
                if b.owner == Some(pid) {
                    continue;
                }

                // Remove from pi_waiters if present
                let removed_from_pi = b.pi_waiters.remove(&pid).is_some();

                if removed_from_pi {
                    needs_pi_recompute = true;
                }

                (b.queue.clone(), removed_from_pi)
            };

            // Remove from WaitQueue (this handles non-PI waiters too)
            // wake_specific returns true if the PID was found and removed
            let was_in_queue = queue.wake_specific(pid);

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
    {
        let mut after = None;
        while let Some((key, bucket)) = next_tgid_bucket(tgid, after) {
            after = Some(key);
            let (queue, next_owner) = {
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
                    b.pi_waiters.remove(&next_pid);
                    b.owner = Some(next_pid);
                    // 保持 owner_dead = true 以便继任者知道前任已死亡
                } else {
                    // 无等待者，清除所有权
                    b.owner = None;
                }

                (queue, next.map(|(p, _)| p))
            };

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
    if group_size > 0 {
        return;
    }

    // RF178-8: stream removals; exit never allocates a key/bucket snapshot.
    while let Some(queue) = unlink_first_tgid_bucket(tgid) {
        queue.wake_all();
    }
}

/// 获取或创建指定键的等待桶
fn get_or_create_bucket(key: FutexKey) -> Result<Arc<Mutex<FutexBucket>>, FutexError> {
    let mut table = FUTEX_TABLE.lock();
    // Fast path: an existing bucket never counts against the cap (no growth).
    if let Some(b) = table.get(&key) {
        return Ok(b.clone());
    }
    // RF178-8: derive both counts from the authoritative table while holding its
    // lock, so admission and publication are atomic and no counter can desync.
    // The global cap is the heap-derived byte budget; the per-TGID cap prevents
    // one group from monopolizing it.
    let tgid = key.0;
    let live = table.range((tgid, 0)..=(tgid, usize::MAX)).count();
    if table.len() >= MAX_FUTEX_BUCKETS_GLOBAL || live >= MAX_FUTEX_BUCKETS_PER_TGID {
        return Err(FutexError::TooManyBuckets);
    }

    // Every nested birth is truly fallible. Unlike the rejected scratch probe,
    // these are the allocations that become the live objects. The table insert
    // uses its own fallible Vec reservation while this lock prevents any peer
    // from consuming the capacity between reserve and publication.
    let queue = Arc::try_new(WaitQueue::new()).map_err(|_| FutexError::TooManyBuckets)?;
    let bucket = Arc::try_new(Mutex::new(FutexBucket::new(queue)))
        .map_err(|_| FutexError::TooManyBuckets)?;
    table
        .try_insert(key, bucket.clone())
        .map_err(|_| FutexError::TooManyBuckets)?;
    Ok(bucket)
}

/// 清理空的等待桶（无等待者时移除）
///
/// E.4 PI: 额外检查 owner 和 pi_waiters 是否为空
fn cleanup_empty_bucket(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) {
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
                table.remove(&key);
            }
        }
    }
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
    waiters: &FallibleOrderedMap<ProcessId, Priority>,
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
fn recompute_pi_state(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) -> Result<(), FutexError> {
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
fn recompute_pi_state_noalloc(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) {
    if recompute_pi_state(key, bucket).is_err() {
        kprintln!(
            "[FUTEX] RF178-8: missing reserved PI boost slot for key {:?}",
            key
        );
    }
}
