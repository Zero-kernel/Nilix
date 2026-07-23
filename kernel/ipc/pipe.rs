//! 匿名管道实现
//!
//! 提供进程间单向数据通道：
//! - pipe() 创建管道，返回读端和写端
//! - 环形缓冲区存储数据
//! - 阻塞/非阻塞模式支持
//! - 正确的关闭语义（EOF/EPIPE）

use alloc::alloc::{AllocError, Allocator, Global};
use alloc::sync::Arc;
#[cfg(test)]
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::any::Any;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use mm::{arc_charge_bytes, try_reserve_heap, vec_charge_bytes, HeapCharge, HeapClass};
use spin::Mutex;

use crate::sync::{PrepareToWaitCapacityOutcome, WaitQueue};
use kernel_core::process::{current_pid, wait_should_abort};
use kernel_core::{FileDescriptor, FileOps, PreparedFileDescriptor, SyscallError, VfsStat};

/// 默认管道缓冲区大小（4KB）
pub const DEFAULT_PIPE_CAPACITY: usize = 4096;

/// 最大管道缓冲区大小（1MB），防止无界内核内存分配
pub const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

/// R178-22 FIX: POSIX PIPE_BUF atomicity threshold
///
/// POSIX requires writes ≤PIPE_BUF to be atomic across concurrent writers.
/// This must not exceed the minimum guaranteed pipe capacity.
pub const PIPE_BUF: usize = 4096;

// ============================================================================
// Exact-lifetime charged Pipe Arc allocator (RF180-42 convergence)
// ============================================================================

/// Every live pipe consumes at least one `PIPE_BUF` backing allocation, so the
/// Pipe class byte gate can never authorize more live Pipe Arc allocations than
/// this fixed slot count. Static slots avoid recursively allocating metadata for
/// the allocation being accounted.
const PIPE_ARC_CHARGE_SLOTS: usize = HeapClass::Pipe.limit_bytes() / PIPE_BUF + 1;
const _: () = assert!(PIPE_ARC_CHARGE_SLOTS <= u16::MAX as usize);

struct PipeArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static PIPE_ARC_CHARGES: Mutex<[Option<PipeArcChargeSlot>; PIPE_ARC_CHARGE_SLOTS]> =
    Mutex::new([const { None }; PIPE_ARC_CHARGE_SLOTS]);
static NEXT_PIPE_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Allocator token carried by every Pipe Arc/Weak owner. The committed Arc
/// charge lives in a fixed slot until `Arc` invokes `deallocate` after the final
/// strong and weak reference has disappeared.
#[derive(Clone, Copy, Debug)]
struct PipeArcAllocator {
    slot: u16,
    generation: u64,
}

impl PipeArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_PIPE_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = PIPE_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PipeArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge.take().expect("pipe Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("pipe Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = PIPE_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-42 pipe Arc allocator slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-42 stale pipe Arc allocator generation"),
            None => panic!("RF180-42 pipe Arc charge released twice"),
        }
        slot.take()
            .expect("validated pipe Arc charge disappeared")
            .charge
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }

    #[cfg(test)]
    fn charge_is_live_for_test(self) -> bool {
        PIPE_ARC_CHARGES
            .lock()
            .get(self.slot as usize)
            .and_then(Option::as_ref)
            .is_some_and(|entry| entry.generation == self.generation)
    }
}

unsafe impl Allocator for PipeArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = PIPE_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        match Global.allocate(layout) {
            Ok(allocation) => Ok(allocation),
            Err(error) => {
                let mut slots = PIPE_ARC_CHARGES.lock();
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
        // Physical control-block memory first, admission second.
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_charge());
    }
}

type PipeArc = Arc<Pipe, PipeArcAllocator>;
#[cfg(test)]
type PipeWeak = Weak<Pipe, PipeArcAllocator>;

/// 管道错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// 没有当前进程上下文
    NoCurrentProcess,
    /// 读端已关闭，写入会产生EPIPE
    BrokenPipe,
    /// 非阻塞模式下操作会阻塞
    WouldBlock,
    /// 管道已关闭
    Closed,
    /// 无效的管道ID
    InvalidPipe,
    /// 权限错误（尝试在错误的端读/写）
    InvalidOperation,
    /// 管道 ID 分配耗尽
    PipeIdExhausted,
    /// 管道容量为零或超过允许的最大值
    InvalidCapacity,
    /// 无法为管道缓冲区分配内存
    NoMemory,
    /// R171 (F2): 阻塞读/写期间检测到挂起的 kill —— 以 EINTR 中断（写已写出则返回短计数）。
    Interrupted,
}

/// Failure of a transactional pipe read. Source errors preserve the existing
/// pipe errno mapping; commit errors come from the caller's copyout operation.
pub enum PipeReadTransactionError<E> {
    Pipe(PipeError),
    Commit(E),
}

/// 管道标志
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeFlags {
    /// 非阻塞模式
    pub nonblock: bool,
    /// exec时关闭
    pub cloexec: bool,
}

/// 管道ID类型
pub type PipeId = u64;

/// 管道端类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEndType {
    /// 读端
    Read,
    /// 写端
    Write,
}

/// 共享管道内部状态
struct PipeInner {
    /// 环形缓冲区
    buffer: Vec<u8>,
    /// 缓冲区容量
    capacity: usize,
    /// 读位置（head）
    read_pos: usize,
    /// 当前数据长度
    len: usize,
    /// 读端引用计数
    readers: usize,
    /// 写端引用计数
    writers: usize,
}

impl PipeInner {
    fn new(capacity: usize) -> Result<Self, PipeError> {
        // MEDIUM-6 FIX: Reserve fallibly before resizing so allocation failure is
        // returned to the caller instead of triggering an OOM panic.
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| PipeError::NoMemory)?;
        buffer.resize(capacity, 0);

        Ok(PipeInner {
            buffer,
            capacity,
            read_pos: 0,
            len: 0,
            readers: 1,
            writers: 1,
        })
    }

    /// 检查缓冲区是否为空
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 检查缓冲区是否已满
    fn is_full(&self) -> bool {
        self.len >= self.capacity
    }

    /// 可读取的字节数
    fn available(&self) -> usize {
        self.len
    }

    /// 可写入的字节数
    fn space(&self) -> usize {
        self.capacity - self.len
    }

    /// 从缓冲区读取数据
    fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = core::cmp::min(dst.len(), self.len);
        if to_read == 0 {
            return 0;
        }

        let mut read = 0;
        while read < to_read {
            let chunk_size = core::cmp::min(to_read - read, self.capacity - self.read_pos);
            dst[read..read + chunk_size]
                .copy_from_slice(&self.buffer[self.read_pos..self.read_pos + chunk_size]);
            self.read_pos = (self.read_pos + chunk_size) % self.capacity;
            read += chunk_size;
        }

        self.len -= to_read;
        to_read
    }

    /// Copy the readable prefix without consuming it.
    fn peek(&self, dst: &mut [u8]) -> usize {
        let to_read = core::cmp::min(dst.len(), self.len);
        let mut copied = 0usize;
        let mut pos = self.read_pos;
        while copied < to_read {
            let chunk = core::cmp::min(to_read - copied, self.capacity - pos);
            dst[copied..copied + chunk].copy_from_slice(&self.buffer[pos..pos + chunk]);
            pos = (pos + chunk) % self.capacity;
            copied += chunk;
        }
        to_read
    }

    /// Consume an already-peeked prefix. The PipeInner lock spans both phases.
    fn consume(&mut self, count: usize) {
        debug_assert!(count <= self.len);
        let count = count.min(self.len);
        self.read_pos = (self.read_pos + count) % self.capacity;
        self.len -= count;
    }

    /// 向缓冲区写入数据
    fn write(&mut self, src: &[u8]) -> usize {
        let to_write = core::cmp::min(src.len(), self.space());
        if to_write == 0 {
            return 0;
        }

        let write_pos = (self.read_pos + self.len) % self.capacity;
        let mut written = 0;
        let mut pos = write_pos;

        while written < to_write {
            let chunk_size = core::cmp::min(to_write - written, self.capacity - pos);
            self.buffer[pos..pos + chunk_size].copy_from_slice(&src[written..written + chunk_size]);
            pos = (pos + chunk_size) % self.capacity;
            written += chunk_size;
        }

        self.len += to_write;
        to_write
    }
}

/// 管道对象
pub struct Pipe {
    /// 管道ID
    id: PipeId,
    /// 内部状态（受锁保护）
    inner: Mutex<PipeInner>,
    /// 等待读取的进程队列
    read_wait: WaitQueue,
    /// 等待写入的进程队列
    write_wait: WaitQueue,
    /// R180-13/RF180-42: exact lifetime charge for the allocator's actual pipe
    /// buffer capacity. The separate Arc charge lives in `PipeArcAllocator`
    /// until the final Weak deallocates the control block.
    _buffer_charge: HeapCharge,
    /// Allocator token used to reconstruct a raw poll strong owner without
    /// erasing the Arc allocator.
    arc_allocator: PipeArcAllocator,
}

/// Private buffer + charge owner used across the remaining fallible Arc setup.
/// Field order guarantees the buffer is freed before its charge is released on
/// every rollback path.
struct PreparedPipeStorage {
    inner: PipeInner,
    buffer_charge: HeapCharge,
}

impl Pipe {
    /// 创建新管道
    fn new(id: PipeId, storage: PreparedPipeStorage, arc_allocator: PipeArcAllocator) -> Self {
        Pipe {
            id,
            inner: Mutex::new(storage.inner),
            read_wait: WaitQueue::new(HeapClass::Pipe),
            write_wait: WaitQueue::new(HeapClass::Pipe),
            _buffer_charge: storage.buffer_charge,
            arc_allocator,
        }
    }

    /// 获取管道ID
    pub fn id(&self) -> PipeId {
        self.id
    }

    /// 从管道读取数据
    ///
    /// # Arguments
    /// * `dst` - 目标缓冲区
    /// * `flags` - 管道标志
    ///
    /// # Returns
    /// * `Ok(n)` - 成功读取n字节（0表示EOF）
    /// * `Err(WouldBlock)` - 非阻塞模式下缓冲区为空
    /// * `Err(Closed)` - 管道已关闭
    ///
    /// # Z-11 fix: Lost-wakeup race condition
    ///
    /// 使用 prepare_to_wait/finish_wait 模式防止丢失唤醒：
    /// 1. 在持有锁时调用 prepare_to_wait 加入等待队列
    /// 2. 释放锁
    /// 3. 调用 finish_wait 实际阻塞
    ///
    /// 这样即使写者在释放锁后立即唤醒，由于读者已在队列中，
    /// 唤醒信号不会丢失。
    pub fn read(&self, dst: &mut [u8], flags: PipeFlags) -> Result<usize, PipeError> {
        loop {
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
                    return Err(PipeError::Interrupted);
                }
            }

            // First condition pass: do not spend heap admission on a wait that
            // can complete immediately.
            {
                let mut inner = self.inner.lock();
                if inner.len > 0 {
                    let count = inner.read(dst);
                    drop(inner);
                    self.write_wait.wake_one();
                    return Ok(count);
                }
                if inner.writers == 0 {
                    return Ok(0);
                }
                if flags.nonblock {
                    return Err(PipeError::WouldBlock);
                }
            }

            // RF180-42 FIX: allocate possible WaitQueue growth only after
            // proving the operation would block, and before re-taking Pipe.inner.
            // R181-5 DISPOSITION (accept-as-is): if data races in between the
            // first pass and this reservation, the under-lock re-check below
            // returns the data and `capacity` is dropped — the reservation is
            // transient, bounded by the waiter count, and reclaimed immediately;
            // reserving-then-rechecking is the correct order (the inverse —
            // arming the wait before reserving — reintroduces the RF180-42
            // alloc-under-lock hazard this pattern exists to prevent).
            let mut capacity = self
                .read_wait
                .prepare_current_wait_capacity()
                .map_err(|_| PipeError::NoMemory)?;
            let arm = {
                let mut inner = self.inner.lock();
                if inner.len > 0 {
                    let count = inner.read(dst);
                    drop(inner);
                    self.write_wait.wake_one();
                    return Ok(count);
                }
                if inner.writers == 0 {
                    return Ok(0);
                }
                if flags.nonblock {
                    return Err(PipeError::WouldBlock);
                }
                self.read_wait
                    .try_prepare_to_wait_with_capacity(&mut capacity)
            };
            drop(capacity);

            match arm {
                PrepareToWaitCapacityOutcome::Prepared(true) => self.read_wait.finish_wait(),
                PrepareToWaitCapacityOutcome::RetryCapacity => continue,
                PrepareToWaitCapacityOutcome::Prepared(false) => {
                    if current_pid().is_none() {
                        return Err(PipeError::NoCurrentProcess);
                    }
                    if self.read_wait.is_closed() {
                        return Err(PipeError::Closed);
                    }
                    if let Some(pid) = current_pid() {
                        if wait_should_abort(pid)
                            || kernel_core::signal::has_deliverable_signal(pid)
                        {
                            return Err(PipeError::Interrupted);
                        }
                    }
                }
            }
        }
    }

    /// R180-L1: copy a pipe prefix to the caller's destination before advancing
    /// the ring cursor. `inner` stays locked across peek/copyout/consume, giving
    /// one atomic source transaction even with competing readers and writers.
    pub fn read_with_commit<E, F>(
        &self,
        dst: &mut [u8],
        flags: PipeFlags,
        mut commit: F,
    ) -> Result<usize, PipeReadTransactionError<E>>
    where
        F: FnMut(&[u8]) -> Result<(), E>,
    {
        loop {
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
                    return Err(PipeReadTransactionError::Pipe(PipeError::Interrupted));
                }
            }

            {
                let mut inner = self.inner.lock();
                if inner.len > 0 {
                    let count = inner.peek(dst);
                    commit(&dst[..count]).map_err(PipeReadTransactionError::Commit)?;
                    inner.consume(count);
                    drop(inner);
                    self.write_wait.wake_one();
                    return Ok(count);
                }
                if inner.writers == 0 {
                    return Ok(0);
                }
                if flags.nonblock {
                    return Err(PipeReadTransactionError::Pipe(PipeError::WouldBlock));
                }
            }

            let mut capacity = self
                .read_wait
                .prepare_current_wait_capacity()
                .map_err(|_| PipeReadTransactionError::Pipe(PipeError::NoMemory))?;
            let arm = {
                let mut inner = self.inner.lock();
                if inner.len > 0 {
                    let count = inner.peek(dst);
                    commit(&dst[..count]).map_err(PipeReadTransactionError::Commit)?;
                    inner.consume(count);
                    drop(inner);
                    self.write_wait.wake_one();
                    return Ok(count);
                }
                if inner.writers == 0 {
                    return Ok(0);
                }
                if flags.nonblock {
                    return Err(PipeReadTransactionError::Pipe(PipeError::WouldBlock));
                }
                self.read_wait
                    .try_prepare_to_wait_with_capacity(&mut capacity)
            };
            drop(capacity);

            match arm {
                PrepareToWaitCapacityOutcome::Prepared(true) => self.read_wait.finish_wait(),
                PrepareToWaitCapacityOutcome::RetryCapacity => continue,
                PrepareToWaitCapacityOutcome::Prepared(false) => {
                    if current_pid().is_none() {
                        return Err(PipeReadTransactionError::Pipe(PipeError::NoCurrentProcess));
                    }
                    if self.read_wait.is_closed() {
                        return Err(PipeReadTransactionError::Pipe(PipeError::Closed));
                    }
                    if let Some(pid) = current_pid() {
                        if wait_should_abort(pid)
                            || kernel_core::signal::has_deliverable_signal(pid)
                        {
                            return Err(PipeReadTransactionError::Pipe(PipeError::Interrupted));
                        }
                    }
                }
            }
        }
    }

    /// 向管道写入数据
    ///
    /// # Arguments
    /// * `src` - 源数据
    /// * `flags` - 管道标志
    ///
    /// # Returns
    /// * `Ok(n)` - 成功写入n字节
    /// * `Err(BrokenPipe)` - 读端已关闭
    /// * `Err(WouldBlock)` - 非阻塞模式下缓冲区已满
    ///
    /// # Z-11 fix: Lost-wakeup race condition
    ///
    /// 使用 prepare_to_wait/finish_wait 模式防止丢失唤醒。
    pub fn write(&self, src: &[u8], flags: PipeFlags) -> Result<usize, PipeError> {
        if src.is_empty() {
            return Ok(0);
        }
        if src.len() <= PIPE_BUF {
            return self.write_atomic(src, flags);
        }

        let mut total_written = 0usize;
        while total_written < src.len() {
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
                    return if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(PipeError::Interrupted)
                    };
                }
            }

            {
                let mut inner = self.inner.lock();
                if inner.readers == 0 {
                    return if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(PipeError::BrokenPipe)
                    };
                }
                if inner.space() > 0 {
                    total_written += inner.write(&src[total_written..]);
                    drop(inner);
                    self.read_wait.wake_one();
                    if total_written == src.len() {
                        return Ok(total_written);
                    }
                } else {
                    drop(inner);
                }
                if flags.nonblock {
                    return if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(PipeError::WouldBlock)
                    };
                }
            }

            let mut capacity = match self.write_wait.prepare_current_wait_capacity() {
                Ok(capacity) => capacity,
                Err(_) if total_written > 0 => return Ok(total_written),
                Err(_) => return Err(PipeError::NoMemory),
            };
            let arm = {
                let mut inner = self.inner.lock();
                if inner.readers == 0 {
                    return if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(PipeError::BrokenPipe)
                    };
                }
                if inner.space() > 0 {
                    total_written += inner.write(&src[total_written..]);
                    self.read_wait.wake_one();
                    if total_written == src.len() {
                        return Ok(total_written);
                    }
                    debug_assert_eq!(inner.space(), 0);
                }
                if flags.nonblock {
                    return if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(PipeError::WouldBlock)
                    };
                }
                self.write_wait
                    .try_prepare_to_wait_with_capacity(&mut capacity)
            };
            drop(capacity);

            match arm {
                PrepareToWaitCapacityOutcome::Prepared(true) => self.write_wait.finish_wait(),
                PrepareToWaitCapacityOutcome::RetryCapacity => continue,
                PrepareToWaitCapacityOutcome::Prepared(false) => {
                    if total_written > 0 {
                        return Ok(total_written);
                    }
                    if current_pid().is_none() {
                        return Err(PipeError::NoCurrentProcess);
                    }
                    if self.write_wait.is_closed() {
                        return Err(PipeError::Closed);
                    }
                    if let Some(pid) = current_pid() {
                        if wait_should_abort(pid)
                            || kernel_core::signal::has_deliverable_signal(pid)
                        {
                            return Err(PipeError::Interrupted);
                        }
                    }
                }
            }
        }
        Ok(total_written)
    }

    /// R178-22 FIX: Atomic write for buffers ≤PIPE_BUF
    ///
    /// POSIX atomicity: either the entire write succeeds, or none of it does.
    /// Blocks until sufficient space is available (blocking mode) or returns
    /// EAGAIN immediately (nonblock mode).
    fn write_atomic(&self, src: &[u8], flags: PipeFlags) -> Result<usize, PipeError> {
        debug_assert!(src.len() <= PIPE_BUF);

        loop {
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) || kernel_core::signal::has_deliverable_signal(pid) {
                    return Err(PipeError::Interrupted);
                }
            }

            {
                let mut inner = self.inner.lock();
                if inner.readers == 0 {
                    return Err(PipeError::BrokenPipe);
                }
                if inner.space() >= src.len() {
                    let count = inner.write(src);
                    debug_assert_eq!(count, src.len());
                    drop(inner);
                    self.read_wait.wake_one();
                    return Ok(count);
                }
                if flags.nonblock {
                    return Err(PipeError::WouldBlock);
                }
            }

            let mut capacity = self
                .write_wait
                .prepare_current_wait_capacity()
                .map_err(|_| PipeError::NoMemory)?;
            let arm = {
                let mut inner = self.inner.lock();
                if inner.readers == 0 {
                    return Err(PipeError::BrokenPipe);
                }
                if inner.space() >= src.len() {
                    let count = inner.write(src);
                    debug_assert_eq!(count, src.len());
                    drop(inner);
                    self.read_wait.wake_one();
                    return Ok(count);
                }
                if flags.nonblock {
                    return Err(PipeError::WouldBlock);
                }
                self.write_wait
                    .try_prepare_to_wait_with_capacity(&mut capacity)
            };
            drop(capacity);

            match arm {
                PrepareToWaitCapacityOutcome::Prepared(true) => self.write_wait.finish_wait(),
                PrepareToWaitCapacityOutcome::RetryCapacity => continue,
                PrepareToWaitCapacityOutcome::Prepared(false) => {
                    if current_pid().is_none() {
                        return Err(PipeError::NoCurrentProcess);
                    }
                    if self.write_wait.is_closed() {
                        return Err(PipeError::Closed);
                    }
                    if let Some(pid) = current_pid() {
                        if wait_should_abort(pid)
                            || kernel_core::signal::has_deliverable_signal(pid)
                        {
                            return Err(PipeError::Interrupted);
                        }
                    }
                }
            }
        }
    }

    /// 关闭读端
    fn close_read(&self) {
        let mut inner = self.inner.lock();
        inner.readers = inner.readers.saturating_sub(1);
        // 唤醒所有写者，让它们检测到EPIPE
        self.write_wait.wake_all();
    }

    /// 关闭写端
    fn close_write(&self) {
        let mut inner = self.inner.lock();
        inner.writers = inner.writers.saturating_sub(1);
        // 唤醒所有读者，让它们检测到EOF
        self.read_wait.wake_all();
    }

    /// 增加读端引用
    fn add_reader(&self) {
        let mut inner = self.inner.lock();
        // R161-14 FIX: Use saturating_add for consistency with saturating_sub on decrement.
        inner.readers = inner.readers.saturating_add(1);
    }

    /// 增加写端引用
    fn add_writer(&self) {
        let mut inner = self.inner.lock();
        // R161-14 FIX: Use saturating_add for consistency with saturating_sub on decrement.
        inner.writers = inner.writers.saturating_add(1);
    }

    /// 获取管道状态
    pub fn status(&self) -> PipeStatus {
        let inner = self.inner.lock();
        PipeStatus {
            available: inner.available(),
            space: inner.space(),
            readers: inner.readers,
            writers: inner.writers,
        }
    }
}

/// M0-6 poll/select: non-consuming readiness probe for a pipe.
///
/// Takes exactly ONE `inner` lock via `status()`; mutates nothing and fires no
/// wakeups (unlike `read`/`write`/`close_*`). Read-end readiness: POLLIN when
/// data is buffered, POLLHUP when all write ends are gone (a read then returns
/// EOF). Write-end readiness: POLLOUT when buffer space exists, POLLERR when all
/// read ends are gone (a write then returns EPIPE).
impl kernel_core::poll::PollProbeOps for Pipe {
    fn poll_status_read(&self) -> kernel_core::poll::PollStatus {
        let st = self.status();
        kernel_core::poll::PollStatus {
            readable: st.available > 0,
            hup: st.writers == 0,
            writable: false,
            err: false,
            rdhup: false,
        }
    }

    fn poll_status_write(&self) -> kernel_core::poll::PollStatus {
        let st = self.status();
        kernel_core::poll::PollStatus {
            writable: st.space > 0,
            err: st.readers == 0,
            readable: false,
            hup: false,
            rdhup: false,
        }
    }
}

unsafe fn pipe_poll_status_read(raw: *const ()) -> kernel_core::poll::PollStatus {
    let pipe = unsafe { &*raw.cast::<Pipe>() };
    <Pipe as kernel_core::poll::PollProbeOps>::poll_status_read(pipe)
}

unsafe fn pipe_poll_status_write(raw: *const ()) -> kernel_core::poll::PollStatus {
    let pipe = unsafe { &*raw.cast::<Pipe>() };
    <Pipe as kernel_core::poll::PollProbeOps>::poll_status_write(pipe)
}

unsafe fn drop_pipe_poll_owner(raw: *const ()) {
    let pipe = unsafe { &*raw.cast::<Pipe>() };
    let allocator = pipe.arc_allocator;
    drop(unsafe { Arc::from_raw_in(raw.cast::<Pipe>(), allocator) });
}

/// 管道状态信息
#[derive(Debug, Clone, Copy)]
pub struct PipeStatus {
    /// 可读字节数
    pub available: usize,
    /// 可写字节数
    pub space: usize,
    /// 读端数量
    pub readers: usize,
    /// 写端数量
    pub writers: usize,
}

/// 管道端句柄
pub struct PipeHandle {
    /// 底层管道
    pipe: PipeArc,
    /// 端类型（读/写）
    end_type: PipeEndType,
    /// 标志
    flags: PipeFlags,
    /// U.S2-SLICE-3: the CapId allocated for this pipe end at the sys_pipe
    /// install site (`pipe_create_callback`), or `None` for a handle that was
    /// never fd-installed (unit-test pipes, pre-install rollback handles).
    ///
    /// Lifecycle: set ONCE under the owning Process lock (between cap
    /// allocation and fd install), then carried VERBATIM by every
    /// `duplicate()`/`clone_box()` copy — dup/fork/CLONE_THREAD copies share
    /// the SAME CapId, and the per-fd refcount bump happens at each INSTALL
    /// site (U.S3-A3), never inside the clone itself (U.S3-A2 purity).
    ///
    /// U.S2 SLICE-3B: Interior mutability via spin::once::Once to match FileOps
    /// trait contract (&self for set_cap_id).
    cap_id: spin::once::Once<cap::CapId>,
}

impl PipeHandle {
    /// 创建读端句柄
    fn new_read(pipe: PipeArc, flags: PipeFlags) -> Self {
        PipeHandle {
            pipe,
            end_type: PipeEndType::Read,
            flags,
            cap_id: spin::once::Once::new(),
        }
    }

    /// 创建写端句柄
    fn new_write(pipe: PipeArc, flags: PipeFlags) -> Self {
        PipeHandle {
            pipe,
            end_type: PipeEndType::Write,
            flags,
            cap_id: spin::once::Once::new(),
        }
    }

    /// U.S2-SLICE-3: attach the CapId allocated for this pipe end.
    ///
    /// Called by `pipe_create_callback` under the owning Process lock, AFTER
    /// both pipe caps were allocated and BEFORE either fd is installed
    /// (CRITICAL-6 ordering). Idempotence is not needed — each handle is set
    /// exactly once on the create path; test fixtures may also set it to pin
    /// the accessor contract.
    ///
    /// U.S2 SLICE-3B: Uses spin::once::Once for interior mutability to match
    /// FileOps trait contract (&self). Panics on duplicate calls (Once guard).
    pub(crate) fn set_cap_id(&self, cap_id: cap::CapId) {
        self.cap_id.call_once(|| cap_id);
    }

    /// 获取端类型
    pub fn end_type(&self) -> PipeEndType {
        self.end_type
    }

    /// 获取管道ID
    pub fn pipe_id(&self) -> PipeId {
        self.pipe.id()
    }

    /// 读取数据（仅读端有效）
    pub fn read(&self, dst: &mut [u8]) -> Result<usize, PipeError> {
        if self.end_type != PipeEndType::Read {
            return Err(PipeError::InvalidOperation);
        }
        self.pipe.read(dst, self.flags)
    }

    pub fn read_with_commit<E, F>(
        &self,
        dst: &mut [u8],
        commit: F,
    ) -> Result<usize, PipeReadTransactionError<E>>
    where
        F: FnMut(&[u8]) -> Result<(), E>,
    {
        if self.end_type != PipeEndType::Read {
            return Err(PipeReadTransactionError::Pipe(PipeError::InvalidOperation));
        }
        self.pipe.read_with_commit(dst, self.flags, commit)
    }

    /// 写入数据（仅写端有效）
    pub fn write(&self, src: &[u8]) -> Result<usize, PipeError> {
        if self.end_type != PipeEndType::Write {
            return Err(PipeError::InvalidOperation);
        }
        self.pipe.write(src, self.flags)
    }

    /// 设置非阻塞模式
    pub fn set_nonblock(&mut self, nonblock: bool) {
        self.flags.nonblock = nonblock;
    }

    /// 检查是否为非阻塞模式
    pub fn is_nonblock(&self) -> bool {
        self.flags.nonblock
    }

    /// 获取管道状态
    pub fn status(&self) -> PipeStatus {
        self.pipe.status()
    }

    /// 复制句柄（用于fork）
    ///
    /// U.S2-SLICE-3: the copy carries the SAME `cap_id` (shared CapEntry, not
    /// a fresh allocation). Pipe-internal `readers`/`writers` counts and the
    /// cap refcount are DECOUPLED lifecycles: duplicate() bumps the pipe end
    /// count here (transient I/O clones included), while the cap refcount is
    /// bumped only at fd INSTALL sites (dup/F_DUPFD/CLONE_THREAD — U.S3-A3)
    /// and never inside the clone itself (U.S3-A2 purity).
    ///
    /// U.S2 SLICE-3B: Once::poll() + call_once to copy the cap_id if set.
    pub fn duplicate(&self) -> Self {
        // 增加相应端的引用计数
        match self.end_type {
            PipeEndType::Read => self.pipe.add_reader(),
            PipeEndType::Write => self.pipe.add_writer(),
        }

        let new_cap_id = spin::once::Once::new();
        if let Some(id) = self.cap_id.poll().copied() {
            new_cap_id.call_once(|| id);
        }

        PipeHandle {
            pipe: self.pipe.clone(),
            end_type: self.end_type,
            flags: self.flags,
            cap_id: new_cap_id,
        }
    }

    /// Prepare exact-lifetime outer descriptor storage before cap/fd side
    /// effects. Finalization is allocation-free.
    pub fn try_prepare_descriptor() -> Result<PreparedFileDescriptor<Self>, ()> {
        FileDescriptor::try_prepare(HeapClass::Pipe)
    }

    fn try_duplicate_descriptor(&self) -> Result<FileDescriptor, ()> {
        let prepared = Self::try_prepare_descriptor()?;
        Ok(prepared.finalize(self.duplicate()))
    }
}

impl Clone for PipeHandle {
    fn clone(&self) -> Self {
        self.duplicate()
    }
}

impl core::fmt::Debug for PipeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeHandle")
            .field("pipe_id", &self.pipe_id())
            .field("end_type", &self.end_type)
            .field("nonblock", &self.flags.nonblock)
            .field("cloexec", &self.flags.cloexec)
            .finish()
    }
}

/// U.S2-SLICE-3 Drop / refcount contract (CRITICAL-7 fix, design-v3 Fix 4):
///
/// Drop closes the underlying RESOURCE (pipe end count → EOF/EPIPE wakeups)
/// and MUST NOT touch any cap_table. Cap refcount decrement is the exclusive
/// responsibility of the fd REMOVAL PATH (`remove_fd` → `decrement_fd_cap`
/// funnel); a Drop-side decrement would double-decrement every removed fd
/// (funnel once, Drop again → underflow/premature revoke). This is also what
/// makes transient I/O clones (fd_read/write_callback) and pre-install
/// rollback handles safe to drop: they leave the pipe end count balanced and
/// leave cap accounting alone. Drop MUST run OUTSIDE the Process lock
/// (R155-3/R170-6 discipline at every call site) because `close_*` re-locks
/// the pipe and fires wakeups.
impl Drop for PipeHandle {
    fn drop(&mut self) {
        match self.end_type {
            PipeEndType::Read => self.pipe.close_read(),
            PipeEndType::Write => self.pipe.close_write(),
        }
    }
}

/// 实现 FileOps trait，支持在进程 fd_table 中存储
impl FileOps for PipeHandle {
    fn clone_box(&self) -> FileDescriptor {
        self.try_duplicate_descriptor()
            .expect("PipeHandle clone allocation/admission failed")
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_duplicate_descriptor()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        match self.end_type {
            PipeEndType::Read => "PipeRead",
            PipeEndType::Write => "PipeWrite",
        }
    }

    /// U.S2-SLICE-3: pipe fds are cap-BEARING — expose the CapId allocated at
    /// the sys_pipe install site so the generic fd→cap lifecycle (dup bump,
    /// close/exec/exit decrement via `decrement_fd_cap`) covers pipes without
    /// downcasting. `None` for never-installed handles (test pipes). A revoked
    /// cap (CLONE_THREAD sibling raced last-close) makes the decrement a
    /// documented no-op — see `decrement_fd_cap`.
    ///
    /// U.S2 SLICE-3B: Uses spin::once::Once::poll() to read the cap_id.
    fn cap_id(&self) -> Option<cap::CapId> {
        self.cap_id.poll().copied()
    }

    /// U.S2-SLICE-3B: set the CapId allocated at the sys_pipe install site.
    ///
    /// Called by sys_pipe after allocating both pipe end caps under Process lock,
    /// BEFORE fd installation. This override is required by the FileOps contract
    /// so the generic fd→cap lifecycle (dup bump, close decrement) covers pipes
    /// without downcasting.
    fn set_cap_id(&self, cap_id: cap::CapId) {
        self.set_cap_id(cap_id);
    }

    /// M0-6 poll/select: hand the poll layer a probe over the shared Pipe Arc.
    ///
    /// `self.pipe.clone()` is an `Arc` refcount bump only — it does NOT touch
    /// `PipeInner.readers`/`writers` (that is `duplicate()`/`clone_box`, which also
    /// fire close-time wakes on drop). The raw owned probe keeps the original
    /// charged allocator token and reconstructs that exact Arc on drop; no
    /// allocation or allocator erasure occurs. `write_end` selects the end.
    fn poll_arm(&self) -> kernel_core::poll::PollArm {
        let (raw, _) = Arc::into_raw_with_allocator(self.pipe.clone());
        let raw = raw.cast::<()>();
        kernel_core::poll::PollArm::Dyn {
            probe: unsafe {
                kernel_core::poll::OwnedPollProbe::from_raw_owned(
                    raw,
                    pipe_poll_status_read,
                    pipe_poll_status_write,
                    drop_pipe_poll_owner,
                )
            },
            write_end: self.end_type == PipeEndType::Write,
        }
    }

    /// R41-1 FIX: Return S_IFIFO mode for pipe fstat.
    ///
    /// Returns pipe metadata with FIFO type (S_IFIFO = 0o010000) and rw-rw-rw- permissions.
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
            dev: 0,
            ino: self.pipe_id() as u64,
            mode: 0o010000 | 0o666, // S_IFIFO | rw-rw-rw-
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        })
    }
}

/// 下一个管道ID
static NEXT_PIPE_ID: AtomicUsize = AtomicUsize::new(1);

/// 创建管道
///
/// 返回 (读端句柄, 写端句柄)
pub fn create_pipe(flags: PipeFlags) -> Result<(PipeHandle, PipeHandle), PipeError> {
    create_pipe_with_capacity(DEFAULT_PIPE_CAPACITY, flags)
}

/// 创建指定容量的管道
pub fn create_pipe_with_capacity(
    capacity: usize,
    flags: PipeFlags,
) -> Result<(PipeHandle, PipeHandle), PipeError> {
    // RF178-18 FIX: A pipe smaller than PIPE_BUF can never satisfy the promised
    // all-or-nothing short-write contract and would block forever.
    if capacity < PIPE_BUF || capacity > MAX_PIPE_CAPACITY {
        return Err(PipeError::InvalidCapacity);
    }

    // R180-13 FIX: reserve the complete retained allocation set before either
    // the buffer or Arc is allocated. The reservation participates in the
    // whole-kernel ledger, so many individually valid pipes cannot jointly
    // exhaust the normal heap.
    let arc_bytes = arc_charge_bytes::<Pipe>().map_err(|_| PipeError::NoMemory)?;
    let estimated_buffer = vec_charge_bytes::<u8>(capacity).map_err(|_| PipeError::NoMemory)?;
    let arc_reservation =
        try_reserve_heap(HeapClass::Pipe, arc_bytes).map_err(|_| PipeError::NoMemory)?;
    let mut buffer_reservation =
        try_reserve_heap(HeapClass::Pipe, estimated_buffer).map_err(|_| PipeError::NoMemory)?;

    // Allocation is fallible and remains private. Reconcile the allocator's
    // actual capacity before the object can become reachable.
    let inner = PipeInner::new(capacity)?;
    let actual_buffer =
        vec_charge_bytes::<u8>(inner.buffer.capacity()).map_err(|_| PipeError::NoMemory)?;
    buffer_reservation
        .resize(actual_buffer)
        .map_err(|_| PipeError::NoMemory)?;

    // R111-3 FIX: Use fetch_update + checked_add to prevent wrapping to 0
    // on usize overflow.  Follows the R105-5 pattern established for IPC
    // endpoint IDs and socket IDs.
    let id = NEXT_PIPE_ID
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
        .map_err(|_| PipeError::PipeIdExhausted)? as PipeId;
    // Split the buffer and control-block lifetimes. The private storage owner
    // keeps rollback drop order exact; the Arc allocator retains its independent
    // charge until the final Weak actually frees the control block.
    let storage = PreparedPipeStorage {
        inner,
        buffer_charge: buffer_reservation
            .commit()
            .map_err(|_| PipeError::NoMemory)?,
    };
    let arc_charge = arc_reservation.commit().map_err(|_| PipeError::NoMemory)?;
    let allocator = PipeArcAllocator::try_install(arc_charge).map_err(|charge| {
        drop(charge);
        PipeError::NoMemory
    })?;
    let pipe = match Arc::try_new_in(Pipe::new(id, storage, allocator), allocator) {
        Ok(pipe) => pipe,
        Err(_) => {
            allocator.cancel_failed_allocation();
            return Err(PipeError::NoMemory);
        }
    };

    let read_handle = PipeHandle::new_read(pipe.clone(), flags);
    let write_handle = PipeHandle::new_write(pipe, flags);

    Ok((read_handle, write_handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish_heap_admission() {
        mm::publish_heap_budgets();
    }

    #[test]
    fn transactional_peek_does_not_consume_before_commit() {
        let mut inner = PipeInner::new(8).expect("pipe buffer");
        assert_eq!(inner.write(b"abcdef"), 6);

        let initial_pos = inner.read_pos;
        let initial_len = inner.len;
        let mut first = [0u8; 4];
        assert_eq!(inner.peek(&mut first), 4);
        assert_eq!(&first, b"abcd");

        // Model a copyout fault: no consume call is made.
        assert_eq!(inner.read_pos, initial_pos);
        assert_eq!(inner.len, initial_len);
        let mut retry = [0u8; 4];
        assert_eq!(inner.peek(&mut retry), 4);
        assert_eq!(retry, first);

        inner.consume(4);
        assert_eq!(inner.len, 2);
        let mut tail = [0u8; 2];
        assert_eq!(inner.peek(&mut tail), 2);
        assert_eq!(&tail, b"ef");
    }

    #[test]
    fn pipe_arc_charge_survives_poll_owner_until_final_weak() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let before = mm::heap_class_snapshot(HeapClass::Pipe);
        let arc_bytes = arc_charge_bytes::<Pipe>().expect("pipe Arc charge");

        let (read_end, write_end) = create_pipe(PipeFlags::default()).expect("pipe fixture");
        let allocator = *Arc::allocator(&read_end.pipe);
        let weak: PipeWeak = Arc::downgrade(&read_end.pipe);
        let arm = <PipeHandle as FileOps>::poll_arm(&read_end);

        drop(read_end);
        drop(write_end);
        assert!(
            allocator.charge_is_live_for_test(),
            "poll's raw strong owner must retain the charged Pipe Arc"
        );

        drop(arm);
        assert!(
            allocator.charge_is_live_for_test(),
            "payload drop must not release the live Arc control-block charge"
        );
        let weak_only = mm::heap_class_snapshot(HeapClass::Pipe);
        assert_eq!(
            weak_only.committed_bytes - before.committed_bytes,
            arc_bytes,
            "after payload destruction only the Pipe Arc control block remains"
        );

        drop(weak);
        assert!(!allocator.charge_is_live_for_test());
        assert_eq!(mm::heap_class_snapshot(HeapClass::Pipe), before);
    }

    #[test]
    fn pipe_admission_exhaustion_and_rollback_are_exact() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let before = mm::heap_class_snapshot(HeapClass::Pipe);

        // The fairness ceiling must not narrow the public 1 MiB capacity.
        // Concurrent live allocations are bounded by the authoritative global
        // ledger below, not by making one otherwise-valid pipe impossible.
        let max_pipe_charge = arc_charge_bytes::<Pipe>()
            .and_then(|arc| {
                vec_charge_bytes::<u8>(MAX_PIPE_CAPACITY).and_then(|buffer| {
                    arc.checked_add(buffer)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .expect("maximum pipe charge must be representable");
        assert!(
            max_pipe_charge <= HeapClass::Pipe.limit_bytes(),
            "Pipe class must preserve the allocator-inclusive 1 MiB contract"
        );
        assert_eq!(mm::heap_class_snapshot(HeapClass::Pipe), before);

        let mut live = Vec::new();
        loop {
            match create_pipe(PipeFlags::default()) {
                Ok(pair) => live.push(pair),
                Err(PipeError::NoMemory) => break,
                Err(error) => panic!("unexpected pipe creation error: {:?}", error),
            }
        }
        let exhausted = mm::heap_class_snapshot(HeapClass::Pipe);
        assert!(exhausted.committed_bytes > before.committed_bytes);
        assert_eq!(exhausted.reserved_bytes, before.reserved_bytes);
        assert!(exhausted.committed_bytes + exhausted.reserved_bytes <= exhausted.capacity_bytes);

        drop(live);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Pipe), before);
    }

    #[test]
    fn mixed_pipe_ramfs_consumers_share_the_global_gate() {
        use vfs::{FileMode, FileSystem, FileType, RamFs};

        let _serial = crate::HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let global_before = mm::heap_admission_snapshot();
        let pipe_before = mm::heap_class_snapshot(HeapClass::Pipe);
        let ramfs_before = mm::heap_class_snapshot(HeapClass::RamFs);

        let fs = RamFs::try_new().expect("ramfs fixture admission");
        let root = fs.root_inode();
        let file = fs
            .create(
                &root,
                "mixed-admission",
                FileMode::new(FileType::Regular, 0o600),
            )
            .expect("ramfs fixture file");

        // Retain enough RAMFS payload that the shared global gate, rather than
        // the independent Pipe class ceiling, becomes the limiting resource.
        let target = global_before
            .capacity_bytes
            .saturating_sub(pipe_before.capacity_bytes)
            .saturating_add(32 * 1024)
            .min(ramfs_before.capacity_bytes.saturating_sub(32 * 1024));
        let payload = alloc::vec![0x5au8; target];
        file.write_at(0, &payload).expect("ramfs payload admission");

        let mut live = Vec::new();
        let first = create_pipe(PipeFlags::default()).expect("first mixed pipe");
        live.push(first);
        let one_pipe = mm::heap_class_snapshot(HeapClass::Pipe)
            .committed_bytes
            .checked_sub(pipe_before.committed_bytes)
            .expect("pipe charge delta");
        loop {
            match create_pipe(PipeFlags::default()) {
                Ok(pair) => live.push(pair),
                Err(PipeError::NoMemory) => break,
                Err(error) => panic!("unexpected mixed pipe error: {:?}", error),
            }
        }

        let global_exhausted = mm::heap_admission_snapshot();
        let pipe_at_failure = mm::heap_class_snapshot(HeapClass::Pipe);
        assert!(
            global_exhausted.capacity_bytes
                - global_exhausted.committed_bytes
                - global_exhausted.reserved_bytes
                < one_pipe,
            "failure must be explained by the shared aggregate gate"
        );
        assert!(
            pipe_at_failure.capacity_bytes
                - pipe_at_failure.committed_bytes
                - pipe_at_failure.reserved_bytes
                >= one_pipe,
            "Pipe class must still have room when the global gate refuses"
        );

        drop(live);
        drop(file);
        drop(root);
        drop(fs);
        drop(payload);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Pipe), pipe_before);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), ramfs_before);
        assert_eq!(mm::heap_admission_snapshot(), global_before);
    }

    // 基本管道测试（在内核环境中运行）
    fn test_pipe_basic() {
        let flags = PipeFlags::default();
        let (read_end, write_end) = create_pipe(flags).unwrap();

        // 写入数据
        let data = b"Hello, Pipe!";
        let written = write_end.write(data).unwrap();
        assert_eq!(written, data.len());

        // 读取数据
        let mut buf = [0u8; 32];
        let read = read_end.read(&mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }
}
