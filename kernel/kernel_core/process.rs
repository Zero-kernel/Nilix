use crate::fork::PAGE_REF_COUNT;
use crate::signal::PendingSignals;
use crate::signal::{SigAction, NSIG};
use crate::syscall::{SyscallError, VfsStat};
use crate::time;
use alloc::alloc::{AllocError, Allocator, Global, Layout};
use alloc::{
    boxed::Box,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use cap::CapTable;
use core::any::Any;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use lsm::ProcessCtx as LsmProcessCtx; // R25-7 FIX: Import LSM for task_exit hook
use mm::memory::FrameAllocator;
use mm::page_table;
use mm::{
    allocation_charge_bytes, arc_charge_bytes, try_reserve_heap, vec_charge_bytes, AdmittedMap,
    AdmittedSet, AdmittedVec, HeapCharge, HeapClass, HeapReservation, PreparedAdmittedVecCapacity,
    RetiredAdmittedVecCapacity,
};
use seccomp::{PledgeState, SeccompState};
use spin::{Mutex, Once, RwLock};
// D2-ARC: fixed held-pid registry for the alloc-free process-registry transaction.
use core::cell::Cell;
// G.1 Observability: Watchdog integration for hung-task detection
use trace::watchdog::{register_watchdog, unregister_watchdog, WatchdogConfig, WatchdogHandle};
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{
        FrameAllocator as X64FrameAllocator, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

/// 进程ID类型
pub type ProcessId = usize;

/// R65-19 / M4-1: starvation threshold — a Ready task that waits this many timer ticks
/// without running earns one dynamic-priority boost level. Lifted to a `pub` module const
/// (was function-local in `check_and_boost_starved`) so the timer tick can gate on it
/// without calling the now-deferred boost method in IRQ (M4-1 latch-on-tick).
pub const STARVATION_THRESHOLD: u64 = 100;

/// 进程优先级（0-139，数值越小优先级越高）
pub type Priority = u8;

/// E.4 Priority Inheritance: Futex 键 (tgid, uaddr)
///
/// Used for tracking which futex a task is waiting on (for transitive PI)
/// and as keys in the PI boost map.
pub type FutexKey = (ProcessId, usize);

// ============================================================================
// Exact-lifetime process Arc admission (RF180-40)
// ============================================================================

/// Maximum number of simultaneously live process Arc control blocks.
///
/// `HeapClass::CoreProcess` is capped at 512 KiB, and the compile-time assertion
/// below proves every `Mutex<Process>` payload consumes at least 512 bytes. The
/// byte ledger therefore rejects a 1025th process Arc before this fixed, heap-
/// independent registry can be exhausted.
const PROCESS_ARC_CHARGE_SLOTS: usize = 1024;

struct ProcessArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static PROCESS_ARC_CHARGES: Mutex<[Option<ProcessArcChargeSlot>; PROCESS_ARC_CHARGE_SLOTS]> =
    Mutex::new([const { None }; PROCESS_ARC_CHARGE_SLOTS]);
static NEXT_PROCESS_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Allocator carried by every process `Arc` and `Weak` handle.
///
/// RF180-40 FIX: storing the outer-Arc charge inside `Process` released it when
/// the last strong owner destroyed the payload, even though procfs can retain a
/// `Weak` and keep the control block allocated indefinitely. The allocator owns
/// the charge in static, generation-tagged storage instead. `Arc` calls
/// `deallocate` only after the final strong and weak reference disappears; this
/// implementation deallocates the control block first and releases admission
/// second. A copied allocator is a single-use capability and cannot allocate a
/// second uncharged block.
#[derive(Clone, Copy, Debug)]
pub struct ProcessArcAllocator {
    slot: u16,
    generation: u64,
}

impl ProcessArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_PROCESS_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = PROCESS_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(ProcessArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge.take().expect("process Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("process Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = PROCESS_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-40 process Arc allocator slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-40 stale process Arc allocator generation"),
            None => panic!("RF180-40 process Arc charge released twice"),
        }
        slot.take()
            .expect("validated process Arc charge disappeared")
            .charge
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }
}

unsafe impl Allocator for ProcessArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = PROCESS_ARC_CHARGES.lock();
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
                let mut slots = PROCESS_ARC_CHARGES.lock();
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
        // Memory first, admission second: a concurrent creator cannot consume
        // these bytes while the old control block is still physically live.
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_charge());
    }
}

pub type ProcessArc = Arc<Mutex<Process>, ProcessArcAllocator>;
pub type ProcessWeak = Weak<Mutex<Process>, ProcessArcAllocator>;

/// mmap 默认起始地址
const DEFAULT_MMAP_BASE: usize = 0x4000_0000;

/// 页大小
const PAGE_SIZE: u64 = 0x1000;

/// 每进程内核栈基址（PML4[511]/PDPT[508]，在共享内核空间内）
pub const KSTACK_BASE: u64 = 0xFFFF_FFFF_0000_0000;

/// 每进程内核栈步长（16KB 栈 + 4KB 守护页 = 20KB）
pub const KSTACK_STRIDE: u64 = 0x5000;

/// 内核栈页数（16KB = 4 页）
const KSTACK_PAGES: usize = 4;

/// 守护页数
const KSTACK_GUARD_PAGES: usize = 1;

/// `map_to` can request at most three intermediate frames per 4 KiB leaf.
/// The deliberately conservative per-stack ledger remains tiny and makes all
/// post-admission mapping/rollback bookkeeping allocation-free.
const KSTACK_PT_LEDGER_CAPACITY: usize = KSTACK_PAGES * 3;

struct KernelStackPtRecorder<'a> {
    inner: &'a mut FrameAllocator,
    frames: [Option<PhysFrame<Size4KiB>>; KSTACK_PT_LEDGER_CAPACITY],
    len: usize,
}

impl<'a> KernelStackPtRecorder<'a> {
    fn new(inner: &'a mut FrameAllocator) -> Self {
        Self {
            inner,
            frames: [None; KSTACK_PT_LEDGER_CAPACITY],
            len: 0,
        }
    }

    fn into_record(
        self,
    ) -> (
        [Option<PhysFrame<Size4KiB>>; KSTACK_PT_LEDGER_CAPACITY],
        usize,
    ) {
        (self.frames, self.len)
    }
}

unsafe impl X64FrameAllocator<Size4KiB> for KernelStackPtRecorder<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // Refuse before allocation if the fixed provenance ledger is full.
        // A live but unrecorded table frame would make failure rollback unable
        // to prove ownership.
        if self.len == KSTACK_PT_LEDGER_CAPACITY {
            return None;
        }
        let frame = self.inner.allocate_frame()?;
        self.frames[self.len] = Some(frame);
        self.len += 1;
        Some(frame)
    }
}

/// G.1: Default watchdog timeout for hung-task detection (10 seconds).
///
/// If a task hasn't been scheduled (heartbeat) for this duration, it will
/// trigger the hung_task tracepoint. 10s is a reasonable default that catches
/// true hangs while allowing normal blocking operations.
const WATCHDOG_TIMEOUT_MS: u64 = 10_000;

/// 调度器清理回调类型
///
/// RF178-33 / P1-B: identity is `(pid, generation)`, not PID alone.
/// `cleanup_zombie` detaches the table slot before this fires; a recycled PID
/// may already own a live PCB under the same numeric id. The callback must
/// only purge queue membership for the reaped generation (see
/// `Scheduler::remove_process`).
type SchedulerCleanupCallback = fn(ProcessId, u64);

/// IPC清理回调类型
/// R37-2 FIX (Codex review): Pass both PID and TGID to avoid deadlock.
/// R114-1 FIX: The callback is invoked by `cleanup_zombie()` AFTER detaching the PCB from
/// `PROCESS_TABLE` and releasing the table lock. This avoids deadlocks from IPC/futex cleanup
/// paths that call `thread_group_size()` or `get_process()` (both re-lock `PROCESS_TABLE`).
/// R75-2 FIX: Also pass IPC namespace ID for per-namespace endpoint cleanup.
/// R180-5 FIX: Also pass the reaped process **generation**. The PID slot may already
/// be reused by a successor before Phase 2 runs; callbacks must key identity by
/// `(pid, generation)` (mirrors RF178-33 / P1-B scheduler cleanup).
type IpcCleanupCallback = fn(ProcessId, ProcessId, cap::NamespaceId, u64); // (pid, tgid, ipc_ns_id, generation)

/// R180-19: identity-bound token for a pre-staged scheduler admission.
///
/// The scheduler inserts the child into a fallible ready-queue slot while the
/// child is still `Provisioning`.  Fork/clone then complete every remaining
/// fallible operation and consume the token to publish `Ready` without any heap
/// growth.  `(pid, generation)` prevents cancellation or commit from touching a
/// recycled PID, while `cpu_id + priority` identify the exact reserved bucket.
/// The pinned Arc lets COMMIT publish the exact PCB without rediscovering it
/// under a ready-queue lock after the transaction's point of no return.
pub struct SchedulerAddToken {
    pub cpu_id: usize,
    pub priority: Priority,
    pub pid: ProcessId,
    pub generation: u64,
    pub process: ProcessArc,
}

/// Recoverable scheduler-admission failures.  They are deliberately coarse:
/// callers fail the process-creation transaction before publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerAddError {
    Unavailable,
    NoMemory,
    NoEligibleCpu,
    InvalidState,
}

pub type SchedulerReserveCallback = fn(ProcessArc) -> Result<SchedulerAddToken, SchedulerAddError>;
pub type SchedulerCommitCallback = fn(SchedulerAddToken);
pub type SchedulerCancelCallback = fn(SchedulerAddToken);

#[derive(Clone, Copy)]
struct SchedulerAdmissionCallbacks {
    reserve: SchedulerReserveCallback,
    commit: SchedulerCommitCallback,
    cancel: SchedulerCancelCallback,
}

/// RAII ownership of one exact scheduler queue slot.
///
/// Dropping an uncommitted permit removes the non-runnable placeholder without
/// allocation.  `commit` is intentionally infallible: the queue entry and all
/// of its backing capacity already exist.
pub struct SchedulerAddPermit {
    token: Option<SchedulerAddToken>,
    commit: SchedulerCommitCallback,
    cancel: SchedulerCancelCallback,
    armed: bool,
}

impl SchedulerAddPermit {
    #[inline]
    pub fn commit(mut self) {
        let token = self
            .token
            .take()
            .expect("scheduler admission permit consumed twice");
        (self.commit)(token);
        self.armed = false;
    }
}

impl Drop for SchedulerAddPermit {
    fn drop(&mut self) {
        if self.armed {
            let token = self
                .token
                .take()
                .expect("armed scheduler admission permit lost its token");
            (self.cancel)(token);
        }
    }
}

/// Futex 唤醒回调类型
///
/// 线程退出时调用，唤醒等待在 clear_child_tid 地址上的进程
/// 参数: (tgid, uaddr, max_wake_count) -> 实际唤醒数量
pub type FutexWakeCallback = fn(ProcessId, usize, usize) -> usize;

/// E.5 Cpuset: Callback for task joining a cpuset
///
/// Called when a new process is created (fork/clone) to update cpuset task count.
/// Parameter: cpuset_id (u32)
pub type CpusetTaskJoinedCallback = fn(u32);

/// E.5 Cpuset: Callback for task leaving a cpuset
///
/// Called when a process exits to update cpuset task count.
/// Parameter: cpuset_id (u32)
pub type CpusetTaskLeftCallback = fn(u32);

/// H.3 KPTI: Callback to update per-CPU GS-addressable CR3 pair
///
/// Called during context switch to keep the syscall entry/exit assembly's
/// GS-relative CR3 values in sync with the loaded address space.
/// Parameters: (user_cr3, kernel_cr3) — physical addresses.
///
/// When KPTI is disabled, both values are the same (causing the cmp/je
/// skip pattern in syscall_entry_stub to bypass the CR3 switch entirely).
pub type KptiCr3UpdateCallback = fn(u64, u64);

/// 最大文件描述符数量（每进程）
pub const MAX_FD: i32 = 256;
const FD_RESERVATION_WORDS: usize = (MAX_FD as usize + 63) / 64;

/// 文件操作 trait
///
/// 定义文件描述符必须实现的操作，支持：
/// - 克隆（用于 fork）
/// - 向下转型（用于类型特定操作）
/// - 调试输出
///
/// 由于循环依赖限制，kernel_core 定义此 trait，具体类型（如 PipeHandle）
/// 在各自的 crate（如 ipc）中实现。
pub trait FileOps: Send + Sync {
    /// 克隆此文件描述符（用于 fork）
    fn clone_box(&self) -> FileDescriptor;

    /// Fallibly clone this file description for fork/dup transactions.
    ///
    /// Persistent publication paths must use this method: `clone_box` is kept
    /// only for legacy non-transactional callers while they are migrated.  An
    /// implementation must prepare a [`FileDescriptor`] allocation before any
    /// manual resource-refcount increment, then finalize it without allocation.
    fn try_clone_box(&self) -> Result<FileDescriptor, ()>;

    /// 获取 Any 引用用于向下转型
    fn as_any(&self) -> &dyn Any;

    /// 获取 Any 可变引用用于向下转型（U.S2 SLICE-3B: set_cap_id after VFS returns）
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// 获取类型名称（用于调试）
    fn type_name(&self) -> &'static str;

    /// U.S3-B: report the CapId this fd carries, if any, so the generic fd
    /// lifecycle paths (`remove_fd`, dup increment, exec-cloexec drain, process
    /// exit) can decrement its refcount and revoke-at-0 WITHOUT downcasting to
    /// each concrete type.
    ///
    /// Default `None` = this fd kind carries no capability (namespace fds:
    /// mount/ipc/net/user — they refcount the namespace object itself, not a
    /// CapEntry). A cap-BEARING implementor (`SocketFile`, `PipeHandle` since
    /// U.S2 SLICE-3; file fds in SLICE-3B) MUST override this AND have a
    /// structural self-test asserting the override — a new default-bearing
    /// trait method silently makes the specialized path dead for any
    /// implementor that forgot to override it (the dev-v35 missing-override
    /// class; see `run_fileops_cap_id_self_test` +
    /// `run_pipe_cap_id_self_test`).
    ///
    /// # Drop / refcount contract (U.S2-SLICE-3, CRITICAL-7)
    ///
    /// A cap-bearing implementor's `Drop` MUST NOT touch any cap_table: cap
    /// refcount decrement is the exclusive responsibility of the fd REMOVAL
    /// path (`remove_fd` → `decrement_fd_cap` funnel and its exec/exit
    /// siblings). Drop MAY close the underlying resource (pipe end, socket).
    /// A Drop-side decrement would double-decrement every removed fd (funnel
    /// once, Drop again → underflow/premature revoke of a still-referenced
    /// cap). The R155-3/R170-6 drop-outside-lock discipline additionally keeps
    /// those resource-close side effects (wake_all) off the Process lock.
    ///
    /// # Transient clones and cap lifetime (U.S2-SLICE-3, CRITICAL-10)
    ///
    /// `clone_box()` copies are refcount-PURE (U.S3-A2) and carry the SAME
    /// CapId. The I/O paths (fd_read/fd_write callbacks) clone the handle and
    /// drop the Process lock before blocking I/O (R41-3); such transient
    /// clones do NOT extend cap lifetime. If another task drives the cap's
    /// refcount to 0 mid-I/O (last close → revoke), the in-flight clone's
    /// cap_id points to a REVOKED CapId. That is benign today (I/O paths do
    /// not consult cap rights); any future rights-checking I/O path must
    /// tolerate `InvalidCapId` (generation mismatch) and map it to EBADF
    /// ("fd closed during I/O"), never panic.
    fn cap_id(&self) -> Option<cap::CapId> {
        None
    }

    /// U.S2 SLICE-3B: Set the CapId for this file descriptor.
    ///
    /// Called by syscall layer after allocating a capability but before installing
    /// the fd. Only implemented by cap-bearing types (FileHandle for regular files,
    /// PipeHandle for pipes, SocketFile for sockets). The default no-op is for
    /// non-cap-bearing types (namespace fds, special files).
    ///
    /// # Contract
    ///
    /// - Must be called exactly once per fd, immediately after cap allocation
    /// - Must store the cap_id so that subsequent cap_id() calls return Some(id)
    /// - Must use interior mutability (OnceCell or similar) since this is &self
    /// - Must panic if called twice (OnceCell::set returns Err on second call)
    ///
    /// The default no-op silently ignores the cap_id, which is correct for types
    /// that don't carry capabilities (they never call this method).
    fn set_cap_id(&self, _id: cap::CapId) {
        // Default: no-op for non-cap-bearing types
    }

    /// R41-1 FIX: 获取文件状态信息（用于 fstat）
    ///
    /// 默认返回 EBADF，子类型应覆盖此方法返回正确的元数据。
    /// FileHandle、Ext2File 应返回 inode 元数据，
    /// PipeHandle 应返回 S_IFIFO 模式。
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Err(SyscallError::EBADF)
    }

    /// M0-6 poll/select: classify this fd for a non-consuming readiness probe.
    ///
    /// Called under the Process lock by the poll/select classify pass; the returned
    /// `PollArm` is then probed OUTSIDE the lock. Because `kernel_core` cannot
    /// downcast the concrete types living in the `ipc`/`vfs` crates (they depend on
    /// `kernel_core`, not the reverse), each implementor overrides this instead of a
    /// central downcast — the same cycle-avoiding pattern as `FD_READ_CALLBACK`.
    ///
    /// The default is `AlwaysReady` (Linux DEFAULT_POLLMASK: a fd kind with no
    /// blocking read/write always reports readable+writable). Regular files
    /// (`FileHandle`/`Ext2File`) and namespace fds keep the default. NOTE: a
    /// `/dev/console` `FileHandle` is a KNOWN-WRONG case under this default (its
    /// `read_at` is a non-blocking `keyboard_read` that returns 0 when empty, so
    /// poll would spuriously report POLLIN) — no in-tree consumer opens it today;
    /// a char-device override rides this same mechanism as a tracked residual.
    fn poll_arm(&self) -> crate::poll::PollArm {
        crate::poll::PollArm::AlwaysReady
    }
}

impl core::fmt::Debug for dyn FileOps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileOps({})", self.type_name())
    }
}

/// 文件描述符类型
/// Detached, admitted backing for one concrete file-operations value.
///
/// RF180-37: the allocation and its lifetime charge are acquired before the
/// caller performs externally visible work. Finalization only initializes the
/// already-allocated slot and unsizes its Box; it cannot allocate or fail.
#[must_use = "dropping a prepared descriptor releases its private allocation and admission"]
pub struct PreparedFileDescriptor<T: FileOps + 'static> {
    storage: Box<core::mem::MaybeUninit<T>>,
    charge: Option<HeapCharge>,
}

impl<T: FileOps + 'static> PreparedFileDescriptor<T> {
    pub fn try_new(class: HeapClass) -> Result<Self, ()> {
        let bytes = allocation_charge_bytes(core::mem::size_of::<T>(), core::mem::align_of::<T>())
            .map_err(|_| ())?;
        let reservation = try_reserve_heap(class, bytes).map_err(|_| ())?;
        let storage = Box::<T>::try_new_uninit().map_err(|_| ())?;
        let charge = reservation.commit().map_err(|_| ())?;
        Ok(Self {
            storage,
            charge: Some(charge),
        })
    }

    /// Initialize and publish the already-admitted descriptor allocation.
    ///
    /// This function is intentionally infallible. `storage` is declared before
    /// `charge` both here and in [`FileDescriptor`], so every rollback and live
    /// drop destroys/deallocates the concrete value before releasing admission.
    pub fn finalize(mut self, value: T) -> FileDescriptor {
        unsafe {
            self.storage.as_mut_ptr().write(value);
        }
        let storage = self.storage;
        let concrete = unsafe { storage.assume_init() };
        let ops: Box<dyn FileOps> = concrete;
        let charge = self
            .charge
            .take()
            .expect("prepared file descriptor lost its heap charge");
        FileDescriptor {
            ops,
            _charge: charge,
        }
    }
}

/// Exact-lifetime owner for a heap-allocated file-operations value.
///
/// RF180-37: this replaces the raw `Box<dyn FileOps>` alias. The trait object is
/// the first field, so its concrete value is dropped and its Box is deallocated
/// before the second field releases the whole-heap charge. Embedding the charge
/// inside the concrete FileOps value is not exact: that field is destroyed while
/// the outer Box allocation is still live.
pub struct FileDescriptor {
    ops: Box<dyn FileOps>,
    _charge: HeapCharge,
}

impl FileDescriptor {
    /// Admit and allocate a descriptor before constructing/publishing it.
    #[inline]
    pub fn try_prepare<T: FileOps + 'static>(
        class: HeapClass,
    ) -> Result<PreparedFileDescriptor<T>, ()> {
        PreparedFileDescriptor::try_new(class)
    }

    /// Convenience for side-effect-free values. Transactions with external
    /// ownership changes should call `try_prepare` first and `finalize` last.
    #[inline]
    pub fn try_new<T: FileOps + 'static>(value: T, class: HeapClass) -> Result<Self, ()> {
        Self::try_prepare(class).map(|prepared| prepared.finalize(value))
    }

    #[inline]
    pub fn try_clone(&self) -> Result<Self, ()> {
        self.ops.try_clone_box()
    }
}

impl core::ops::Deref for FileDescriptor {
    type Target = dyn FileOps;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ops.as_ref()
    }
}

impl core::ops::DerefMut for FileDescriptor {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ops.as_mut()
    }
}

impl AsRef<dyn FileOps> for FileDescriptor {
    #[inline]
    fn as_ref(&self) -> &(dyn FileOps + 'static) {
        self.ops.as_ref()
    }
}

impl core::fmt::Debug for FileDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.ops.fmt(f)
    }
}

/// 内核栈分配错误
#[derive(Debug, Clone, Copy)]
pub enum KernelStackError {
    /// 栈地址已被映射（PID 复用时可能发生）
    AlreadyMapped,
    /// 物理内存分配失败
    AllocationFailed,
    /// 页表映射失败
    MapFailed,
    /// R103-I2 FIX: 地址计算溢出（PID 超出内核栈地址空间范围）
    AddressOverflow,
    /// R180-12: fixed RCU callback pool is full. No stack was allocated.
    CallbackPoolExhausted,
    /// The recycled PID's previous stack is still awaiting RCU reclamation.
    ReclaimPending,
}

/// 进程创建错误
///
/// SECURITY FIX Z-7: 进程创建失败时必须正确报告错误，而非静默回退
#[derive(Debug, Clone, Copy)]
pub enum ProcessCreateError {
    /// 内核栈分配失败
    KernelStackAllocFailed(KernelStackError),
    /// R29-5 FIX: PID 空间耗尽（内核栈地址空间溢出）
    PidExhausted,
    /// Whole-heap admission or a fallible PCB allocation failed.
    OutOfMemory,
    /// F.1: PID namespace chain assignment failed
    NamespaceError,
}

/// R29-5 FIX: Maximum PID before kernel stack address overflow
///
/// Each process gets a kernel stack at KSTACK_BASE + pid * KSTACK_STRIDE.
/// After this many PIDs, new stacks would overflow into other kernel memory.
/// Calculation: (u64::MAX - KSTACK_BASE) / KSTACK_STRIDE ≈ 209,715
pub const MAX_PID: ProcessId = ((u64::MAX - KSTACK_BASE) / KSTACK_STRIDE) as ProcessId;

/// R106-11 (P0-4): User-visible PID upper bound (Linux default: 32768).
///
/// Bounded separately from `MAX_PID` (kernel stack address space limit) so PID
/// recycling keeps the process table bounded and prevents PID exhaustion under
/// fork/exit churn. Valid PIDs are in [1, PID_MAX].
pub const PID_MAX: ProcessId = 32_768;

/// R180-12: every valid PID has one dedicated RCU stack-lifecycle slot.
/// This is an admission invariant, not a reduction of the PID/task capability.
pub const KERNEL_STACK_ADMISSION_LIMIT: usize = crate::rcu::RCU_STACK_CALLBACK_CAPACITY;
const _: () = assert!(KERNEL_STACK_ADMISSION_LIMIT == PID_MAX);

/// RF180-3 FIX: PIDs detached for Phase-2 reap cleanup remain unavailable
/// until every raw-PID subsystem callback has completed.  A thread-group ID
/// remains pinned as well until every member has left `PROCESS_TABLE` and all
/// concurrent Phase-2 cleanups for that group have finished.
///
/// The table slot must be removed before callbacks because they re-enter
/// PROCESS_TABLE, but making the numeric PID immediately reusable lets futex
/// owner/waiter metadata either mutate a successor or survive into it.  This
/// fixed bitmap is allocation-free and is consulted by the PID allocator.
const REAPING_PID_WORDS: usize = (PID_MAX + 64) / 64;

struct ReapingPidState {
    bits: [u64; REAPING_PID_WORDS],
    /// Number of detached members whose Phase-2 cleanup still references this
    /// raw TGID.  `u16` covers the complete bounded PID space.
    tgid_inflight: [u16; PID_MAX + 1],
}

static REAPING_PID_STATE: Mutex<ReapingPidState> = Mutex::new(ReapingPidState {
    bits: [0; REAPING_PID_WORDS],
    tgid_inflight: [0; PID_MAX + 1],
});

#[inline]
fn reaping_pid_is_set(state: &ReapingPidState, pid: ProcessId) -> bool {
    let word = pid / 64;
    let bit = pid % 64;
    state
        .bits
        .get(word)
        .map(|value| (*value & (1u64 << bit)) != 0)
        .unwrap_or(true)
}

#[inline]
fn set_reaping_bit(state: &mut ReapingPidState, pid: ProcessId) {
    if let Some(value) = state.bits.get_mut(pid / 64) {
        *value |= 1u64 << (pid % 64);
    }
}

#[inline]
fn clear_reaping_bit(state: &mut ReapingPidState, pid: ProcessId) {
    if let Some(value) = state.bits.get_mut(pid / 64) {
        *value &= !(1u64 << (pid % 64));
    }
}

/// Begin one detached task's raw-PID/TGID cleanup transaction.
///
/// Caller holds `PROCESS_TABLE`, so allocator observation is atomic with the
/// slot detach.  Pinning `tgid` prevents a new process from becoming a leader
/// with the same numeric TGID while surviving old-group members still own
/// futex buckets keyed by `(tgid, uaddr)`.
fn begin_reaping_identity(pid: ProcessId, tgid: ProcessId) {
    let mut state = REAPING_PID_STATE.lock();
    set_reaping_bit(&mut state, pid);
    set_reaping_bit(&mut state, tgid);
    if let Some(inflight) = state.tgid_inflight.get_mut(tgid) {
        *inflight = inflight
            .checked_add(1)
            .expect("reaping TGID inflight count exceeds PID_MAX");
    }
}

/// Complete one detached task's cleanup and release recyclable identities only
/// after the old thread group has no table members and no other Phase-2 reaper.
fn finish_reaping_identity(pid: ProcessId, tgid: ProcessId) {
    // Lock order matches the allocator and all table scanners:
    // PROCESS_TABLE -> PCB -> REAPING_PID_STATE.
    let table = PROCESS_TABLE.lock();
    let group_has_table_member = table.iter().any(|slot| {
        slot.as_ref()
            .map(|process| process.lock().tgid == tgid)
            .unwrap_or(false)
    });

    let mut state = REAPING_PID_STATE.lock();
    let remaining = match state.tgid_inflight.get_mut(tgid) {
        Some(inflight) if *inflight > 0 => {
            *inflight -= 1;
            *inflight
        }
        _ => {
            // Bookkeeping corruption must fail closed: retain both bits.
            klog!(
                Error,
                "RF180-3: missing reaping TGID reference for pid={} tgid={}",
                pid,
                tgid
            );
            return;
        }
    };

    // A non-leader PID is no longer present in any raw-PID callback after this
    // point.  The group leader/TGID has the stronger group-wide lifetime below.
    if pid != tgid {
        clear_reaping_bit(&mut state, pid);
    }
    if !group_has_table_member && remaining == 0 {
        clear_reaping_bit(&mut state, tgid);
    }
}

/// 计算指定 PID 的内核栈虚拟地址范围
///
/// 返回 Ok((栈底, 栈顶))，栈向下生长，栈顶用于 TSS.rsp0
///
/// # R103-I2 FIX
///
/// Returns `Err(KernelStackError::AddressOverflow)` instead of panicking
/// when the PID causes address arithmetic to overflow.  Although current
/// callers validate `pid <= MAX_PID`, this function is `pub` and future
/// call sites might not enforce the bound.  Returning `Result` makes the
/// contract explicit and prevents kernel panics from propagating.
#[inline]
pub fn kernel_stack_slot(pid: ProcessId) -> Result<(VirtAddr, VirtAddr), KernelStackError> {
    // R102-8 FIX: Use checked arithmetic to prevent silent wrapping on invalid PID.
    // R103-I2 FIX: Propagate overflow as error instead of panicking.
    //
    // H.2 Partial KASLR: Apply boot-time random slide to the kernel stack region
    // base. This prevents attackers from predicting per-process kernel stack addresses
    // even when the kernel text is at a fixed address.
    let kstack_base = KSTACK_BASE
        .checked_add(security::kernel_stack_slide())
        .ok_or(KernelStackError::AddressOverflow)?;
    let slot_offset = (pid as u64)
        .checked_mul(KSTACK_STRIDE)
        .ok_or(KernelStackError::AddressOverflow)?;
    let guard_base_addr = kstack_base
        .checked_add(slot_offset)
        .ok_or(KernelStackError::AddressOverflow)?;

    let guard_bytes = KSTACK_GUARD_PAGES as u64 * PAGE_SIZE; // compile-time constant, safe
    let stack_base_addr = guard_base_addr
        .checked_add(guard_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;

    let stack_bytes = KSTACK_PAGES as u64 * PAGE_SIZE; // compile-time constant, safe
    let stack_top_addr = stack_base_addr
        .checked_add(stack_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;

    Ok((
        VirtAddr::new(stack_base_addr),
        VirtAddr::new(stack_top_addr),
    ))
}

/// 为指定 PID 分配并映射带守护页的内核栈
///
/// 在共享的内核页表上映射，所有进程地址空间均可见。
/// 守护页不映射物理帧，访问时会触发页错误。
///
/// # Returns
///
/// 成功返回 (栈底, 栈顶)，失败返回错误
pub fn allocate_kernel_stack(
    pid: ProcessId,
) -> Result<
    (
        VirtAddr,
        VirtAddr,
        PhysFrame<Size4KiB>,
        crate::rcu::RcuCallbackPermit,
    ),
    KernelStackError,
> {
    let (stack_base, stack_top) = kernel_stack_slot(pid)?;
    // R180-12: reserve deferred-reclamation capacity before allocating frames
    // or publishing mappings. Pool exhaustion is ordinary creation backpressure.
    let reclaim_permit =
        crate::rcu::try_reserve_stack_callback(pid).map_err(|error| match error {
            crate::rcu::RcuBackpressure::StackCallbackLimit => KernelStackError::ReclaimPending,
            crate::rcu::RcuBackpressure::CallbackPoolExhausted => {
                KernelStackError::CallbackPoolExhausted
            }
        })?;
    // R103-I2 FIX: Derive guard_base from stack_base using checked arithmetic
    // instead of the previous unchecked `KSTACK_BASE + pid as u64 * KSTACK_STRIDE`.
    let guard_bytes = KSTACK_GUARD_PAGES as u64 * PAGE_SIZE;
    let guard_base_addr = stack_base
        .as_u64()
        .checked_sub(guard_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;
    let guard_base = VirtAddr::new(guard_base_addr);

    let mut frame_alloc = FrameAllocator::new();
    let mut rollback_data_frame: Option<PhysFrame<Size4KiB>> = None;
    let mut rollback_table_frames: [Option<PhysFrame<Size4KiB>>; KSTACK_PT_LEDGER_CAPACITY] =
        [None; KSTACK_PT_LEDGER_CAPACITY];
    let mut rollback_table_count = 0usize;
    let mut rollback_quarantine = false;

    let mapped_result = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            // 检查整个 slot（守护页 + 栈页）是否已被映射
            let total_pages = KSTACK_PAGES + KSTACK_GUARD_PAGES;
            for i in 0..total_pages {
                let addr = guard_base + (i as u64 * PAGE_SIZE);
                if !mgr.page_slot_is_unused(Page::containing_address(addr)) {
                    return Err(KernelStackError::AlreadyMapped);
                }
            }

            // 分配连续物理帧
            let phys_start_frame = frame_alloc
                .allocate_contiguous_frames(KSTACK_PAGES)
                .ok_or(KernelStackError::AllocationFailed)?;
            let phys_start = phys_start_frame.start_address();

            // R128-1 FIX: 内核栈页标志：可写、不可执行。
            // 不使用 GLOBAL 标志：per-process 内核栈在 PID 回收时会被解映射并重新分配。
            // GLOBAL TLB 条目跨 CR3 切换持久化，且现有 TLB shootdown 路径
            // (invpcid_all_nonglobal / flush_all_local) 不刷新 GLOBAL 条目。
            // 移除 GLOBAL 可确保 CR3 切换自动清除 stale 条目，
            // 消除 PID 回收后 stale GLOBAL TLB 导致的内核栈 UAF 风险。
            let flags =
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

            // 映射栈页（守护页不映射，自动触发页错误）
            let stack_size = (KSTACK_PAGES as u64 * PAGE_SIZE) as usize;
            // Map with a fixed rollback ledger. `map_range()` uses a heap Vec
            // after physical allocation; a kernel stack has exactly four pages,
            // so keep this post-admission path allocation-free.
            let mut mapped_pages = 0usize;
            let mut pt_recorder = KernelStackPtRecorder::new(&mut frame_alloc);
            for index in 0..KSTACK_PAGES {
                let page = Page::containing_address(stack_base + (index as u64 * PAGE_SIZE));
                let frame = PhysFrame::containing_address(phys_start + (index as u64 * PAGE_SIZE));
                if mgr.map_page(page, frame, flags, &mut pt_recorder).is_err() {
                    // Freeze the table-frame provenance record before any
                    // rollback mutation. No allocation occurs below this point.
                    let (tracked_tables, tracked_len) = pt_recorder.into_record();

                    // First prove every installed leaf still maps the exact
                    // order-2 block allocated by this transaction. If proof
                    // fails, mutate nothing and quarantine both the mapping and
                    // PID-indexed RCU permit.
                    let mut leaves_valid = true;
                    for rollback in 0..mapped_pages {
                        let rollback_page =
                            Page::containing_address(stack_base + (rollback as u64 * PAGE_SIZE));
                        let expected = PhysFrame::containing_address(
                            phys_start + (rollback as u64 * PAGE_SIZE),
                        );
                        if mgr.translate_page_4k(rollback_page) != Some(expected) {
                            leaves_valid = false;
                            break;
                        }
                    }

                    let mut cleared = 0usize;
                    let mut matched = 0usize;
                    if leaves_valid {
                        for rollback in (0..mapped_pages).rev() {
                            let rollback_page = Page::containing_address(
                                stack_base + (rollback as u64 * PAGE_SIZE),
                            );
                            let expected = PhysFrame::containing_address(
                                phys_start + (rollback as u64 * PAGE_SIZE),
                            );
                            match mgr.unmap_page(rollback_page) {
                                Ok(actual) => {
                                    cleared += 1;
                                    if actual == expected {
                                        matched += 1;
                                    } else {
                                        leaves_valid = false;
                                        break;
                                    }
                                }
                                Err(_) => {
                                    leaves_valid = false;
                                    break;
                                }
                            }
                        }
                    }

                    // These high-half tables are shared by many distinct CR3
                    // roots. A current-CR3 range shootdown is insufficient.
                    if cleared != 0 {
                        mm::flush_all_address_spaces();
                    }

                    if leaves_valid && matched == mapped_pages {
                        let report = mgr.rollback_tracked_leaf_tables(
                            stack_base,
                            stack_size,
                            &tracked_tables,
                            tracked_len,
                            &mut rollback_table_frames,
                            false,
                        );
                        if report.all_accounted {
                            rollback_table_count = report.reclaimed_count;
                            rollback_data_frame = Some(phys_start_frame);
                        } else {
                            // R180-12 FIX: an incomplete hierarchy report can
                            // mean that a recorder-owned table still contains an
                            // unexpected leaf.  Even though the requested stack
                            // leaves were removed, that leaf may alias the same
                            // buddy block.  Quarantine the detached table frames
                            // and data block together; freeing either would turn
                            // an accounting anomaly into mapped-frame reuse.
                            rollback_table_count = 0;
                            rollback_quarantine = true;
                        }
                    } else {
                        rollback_quarantine = true;
                    }
                    return Err(KernelStackError::MapFailed);
                }
                mapped_pages += 1;
            }

            // 清零栈区域
            core::ptr::write_bytes(stack_base.as_mut_ptr::<u8>(), 0, stack_size);

            Ok((stack_base, stack_top, phys_start_frame))
        })
    };

    match mapped_result {
        Ok(mapped) => Ok((mapped.0, mapped.1, mapped.2, reclaim_permit)),
        Err(error) => {
            let mut release_failed = false;
            for frame in rollback_table_frames
                .iter()
                .take(rollback_table_count)
                .flatten()
                .copied()
            {
                if frame_alloc.try_deallocate_frame(frame).is_err() {
                    release_failed = true;
                }
            }
            if let Some(frame) = rollback_data_frame {
                if frame_alloc
                    .try_deallocate_contiguous_frames(frame, KSTACK_PAGES)
                    .is_err()
                {
                    release_failed = true;
                }
            }

            if rollback_quarantine || release_failed {
                // Dropping the permit would make the PID/VA slot reusable after
                // a rollback whose physical/table ownership was not completely
                // proven. Permanently pin it fail-closed.
                core::mem::forget(reclaim_permit);
            }
            Err(error)
        }
    }
}

/// 进程状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// R180-19: fully constructed enough to own a reserved scheduler slot, but
    /// not yet committed/runnable.  Wake paths do not treat this as Blocked,
    /// and scheduler selection admits only `Ready`, so no signal can publish a
    /// pre-COW child early.
    Provisioning,
    /// 就绪状态，等待被调度
    Ready,
    /// 运行状态
    Running,
    /// 阻塞状态（等待I/O或其他事件）
    Blocked,
    /// 暂停状态（如 SIGSTOP）
    Stopped,
    /// 睡眠状态
    Sleeping,
    /// 僵尸状态（已终止但未被父进程回收）
    Zombie,
    /// 已终止
    Terminated,
}

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// 512 字节的 FXSAVE/FXRSTOR 区域
/// 按 64 字节对齐以兼容 XSAVE 路径
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub data: [u8; FXSAVE_SIZE],
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxSaveArea").finish_non_exhaustive()
    }
}

impl Default for FxSaveArea {
    fn default() -> Self {
        let mut area = FxSaveArea {
            data: [0; FXSAVE_SIZE],
        };
        // 设置默认的 FCW（FPU Control Word）：双精度、所有异常屏蔽
        area.data[0] = 0x7F;
        area.data[1] = 0x03;
        // 设置默认的 MXCSR（SSE Control/Status）：所有异常屏蔽
        area.data[24] = 0x80;
        area.data[25] = 0x1F;
        area
    }
}

/// CPU上下文（用于进程切换）
///
/// 包含通用寄存器和 FPU/SIMD 状态，与 arch::Context 布局一致
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct Context {
    // 通用寄存器 (偏移 0x00 - 0x7F)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // 指令指针和标志 (偏移 0x80 - 0x8F)
    pub rip: u64,
    pub rflags: u64,

    // 段寄存器 (偏移 0x90 - 0x9F)
    pub cs: u64,
    pub ss: u64,

    // 填充以对齐 FxSaveArea 到 64 字节边界 (偏移 0xA0 - 0xBF)
    _padding: [u64; 4],

    /// FPU/SIMD 保存区 (偏移 0xC0)
    pub fx: FxSaveArea,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202, // IF (中断使能) 位设置
            cs: 0x08,      // 内核代码段
            ss: 0x10,      // 内核数据段
            _padding: [0; 4],
            fx: FxSaveArea::default(),
        }
    }
}

/// D3-ARC-MM-SHARED: Shared virtual memory metadata for an address space.
///
/// Under CLONE_VM (threads), all tasks sharing a physical address space (CR3)
/// also share a single `MmState` via `Arc<Mutex<MmState>>`. This eliminates
/// the prior per-task `mmap_regions`/`brk` snapshot model that required 7+
/// sync_vm_siblings_* functions and caused systemic cgroup accounting bugs
/// (D2-RES-CGROUP-CLONE: R123-R127, R139-R142, R146-R147, R161).
///
/// For non-CLONE_VM processes (regular fork), each child gets an independent
/// `MmState` built field-by-field in `fork_inner`, with `mmap_regions` cloned
/// fallibly via `FallibleOrderedMap::from_sorted_vec` (no infallible deep copy).
///
/// Lock ordering: Process → MmState (never reverse).
///
/// `MmState` deliberately does NOT derive `Clone`: `mmap_regions` is a
/// `FallibleOrderedMap` (next-phase #11 / R165-14) whose only growth path is the
/// allocation-fallible `try_clone`, so an infallible `derive(Clone)` would
/// reintroduce the OOM-abort class. Use `try_*` paths instead.
#[derive(Debug)]
pub struct MmState {
    /// D2-MMAP-LIFECYCLE: mmap region tracking (base_addr -> length_with_flags).
    ///
    /// ## Encoding Contract
    ///
    /// Each value packs a page-aligned length in bits [63:12] with flags in bits [11:0]:
    ///
    /// | Bits | Name | Lifecycle | Description |
    /// |------|------|-----------|-------------|
    /// | 0 | PENDING_MAP | Transient | Phase 1 reservation; cleared on Phase 3 commit or rollback |
    /// | 1 | PENDING_UNMAP | Transient | Region marked for removal; cleared after unmap+dealloc |
    /// | 2 | PROT_NONE | Persistent | Pure address reservation, no physical frames allocated |
    /// | 3 | PROT_READ | Persistent | POSIX PROT_READ permission |
    /// | 4 | PROT_WRITE | Persistent | POSIX PROT_WRITE permission |
    /// | 5 | PROT_EXEC | Persistent | POSIX PROT_EXEC permission |
    /// | 6 | PENDING_MPROTECT | Transient | mprotect Path A in progress; cleared on commit/rollback |
    ///
    /// ## Invariants
    ///
    /// 1. Length is always a multiple of PAGE_SIZE (4096)
    /// 2. At most ONE transient flag (PENDING_MAP | PENDING_UNMAP | PENDING_MPROTECT) per entry
    /// 3. Consumers MUST use `mmap_region_len()` to extract length, never raw value
    /// 4. Fork MUST strip transient flags via `& !MMAP_REGION_FLAG_TRANSIENT_MASK`
    /// 5. `compute_cgroup_charged_bytes()` MUST skip PROT_NONE entries
    /// 6. Concurrent mprotect MUST check PENDING_MPROTECT before setting (R164-2)
    ///
    /// D2-MMAP-LIFECYCLE Phase 2: values are the typed `MmapEntry` newtype
    /// (a `#[repr(transparent)]` wrapper over the same packed word) so the magic
    /// bit-arithmetic above is accessed through named, contract-enforcing methods.
    pub mmap_regions: crate::fallible_map::FallibleOrderedMap<usize, crate::syscall::MmapEntry>,

    /// Heap start address (page-aligned end of ELF BSS)
    pub brk_start: usize,

    /// Current program break
    pub brk: usize,

    /// Next auto-allocated mmap start address
    pub next_mmap_addr: usize,

    /// Cgroup memory bytes charged via sys_mmap / sys_brk.
    /// Under shared MmState, this is per-address-space (not per-task).
    /// Non-last CLONE_VM exit must NOT uncharge; last exit uncharges all.
    pub vm_charged_bytes: u64,

    /// Cgroup memory bytes charged by the ELF loader for PT_LOAD segments
    /// and the initial user stack. Uncharged on last-exit or subsequent exec.
    pub elf_charged_bytes: u64,

    /// J2-9 FIX: Cgroup MEMORY-controller bytes charged for the INTERMEDIATE
    /// page-table frames (PT/PD/PDPT) that `map_to` allocated to back this
    /// address space's anonymous `mmap()` mappings. Page-table memory is kernel
    /// memory (kmem) and rides `memory.max` (cgroup-v2 folds kmem into
    /// `memory.current`); without this term a tenant bypasses `memory.max` by
    /// forcing unbounded page-table growth. R171-CG1x0 FIX (M2-1 SLICE-0): this is
    /// NO LONGER monotonic — `sys_munmap` now reclaims the intermediate PT/PD frames
    /// it empties and uncharges this field per-frame via the `pt_charged_frames`
    /// ledger (frame identity, see below). Only the non-ledgered remainder
    /// (`pt_inherited_bytes`: fork-inherited + any Phase-3 OOM-fallback frames) is
    /// released wholesale at last exit (`free_process_resources`) and at exec image
    /// replacement (`sys_exec`, which frees the old AS synchronously). Follows the elf
    /// LIFECYCLE (copy-on-fork, parent charged at fork, child last-exit cancels)
    /// — NOT elf's value (the ELF loader charges ZERO page-table frames today).
    /// SCOPE: mmap + mprotect Path-A (PROT_NONE -> real materialization, M2-1
    /// SLICE-4a). brk-grow / COW-fault / ELF-image page-table frames are NOT yet
    /// counted (bounded, teardown-reclaimed, tracked deferred residual: SLICE-4b/4d).
    ///
    /// R171-CG1x0 FIX (M2-1 SLICE-0): scoped INVARIANT I' now governs this field:
    ///   `pt_charged_bytes == pt_inherited_bytes + pt_charged_frames.len() * 0x1000`
    /// The frame-identity ledger (`pt_charged_frames`) makes `sys_munmap` uncharge
    /// a reclaimed page-table frame IFF this AS charged it (on mmap or mprotect
    /// Path-A) — defeating the cross-origin `memory.max` bypass (a naive
    /// `min(0x1000, pt_charged_bytes)` decrement would debit a real charge for an
    /// UNCHARGED brk/ELF frame reclaimed by `prune_empty_tables_in_range`).
    pub pt_charged_bytes: u64,

    /// R171-CG1x0 FIX (M2-1 SLICE-0): per-address-space frame-identity provenance
    /// ledger for the page-table frames charged on `sys_mmap`, keyed by physical
    /// frame address (`frame.start_address().as_u64()`). `sys_munmap` reclaims a
    /// pruned PT/PD frame and uncharges `memory_current`/`pt_charged_bytes` for it
    /// IFF the frame is present here — provenance-correct, never a guessed
    /// constant. Populated under the Process+MmState hold at mmap Phase 3 (frames
    /// recorded by `RecordingFrameAllocator`), drained per-frame under the folded
    /// munmap Phase 3, and `clear()`ed wholesale at last-exit teardown and exec
    /// image replacement. `FallibleOrderedMap` ⇒ every insert is fallible
    /// (`try_reserve`); on OOM the frames fall back to `pt_inherited_bytes`
    /// (over-count-safe — they reclaim at teardown, never a bypass).
    pub pt_charged_frames: crate::fallible_map::FallibleOrderedMap<u64, ()>,

    /// R171-CG1x0 FIX (M2-1 SLICE-0): the portion of `pt_charged_bytes` that is
    /// NOT individually tracked in `pt_charged_frames` and therefore reclaims only
    /// at last-exit teardown / exec replacement, never per-munmap. Two sources:
    /// (1) fork inheritance — a child is born with `pt_inherited_bytes ==
    /// parent.pt_charged_bytes` and an EMPTY ledger (the child builds its own
    /// frames with different physical addresses, so parent frame keys are
    /// meaningless); (2) a Phase-3 ledger `try_reserve` OOM fallback. Keeping these
    /// in a separate basis preserves INVARIANT I' exactly across the fork seam (the
    /// naive single-field form would falsely fire I' the instant a forked child's
    /// first own mmap lands).
    pub pt_inherited_bytes: u64,

    /// R171-CG1x0 FIX (M2-1 SLICE-0): gates whether `sys_munmap` consults the
    /// `pt_charged_frames` ledger for THIS address space. `true` once the AS may hold
    /// its own ledgered mmap PT charges — it is a SKIP-the-known-empty-ledger gate,
    /// NOT a proof that every own PT charge is ledgered: a Phase-3 `try_reserve` OOM
    /// keeps the AS authoritative while parking those bytes in `pt_inherited_bytes`
    /// (safe — munmap simply won't find them in the ledger and they reclaim at
    /// teardown). A fresh AS is authoritative (empty ledger == no own charges). A
    /// forked child starts NON-authoritative (its whole `pt_charged_bytes` basis
    /// lives in `pt_inherited_bytes`, untracked by frame), flipping to authoritative
    /// on its first own `sys_mmap`. While non-authoritative the munmap PT leg skips
    /// the (empty) ledger scan; the inherited basis rides to teardown
    /// (over-count-safe). Reset to true at teardown / exec replacement.
    pub pt_ledger_authoritative: bool,

    /// Transient: bytes charged to cgroup via sys_brk growth not yet
    /// reflected in `brk`. Non-zero only while MmState lock is dropped
    /// for PT operations. Included by `compute_cgroup_charged_bytes()`.
    pub brk_pending_growth: u64,

    /// Transient: bytes charged by mprotect(PROT_NONE → real) not yet
    /// reflected in `mmap_regions`. Non-zero during PT operations.
    pub mprotect_pending_bytes: u64,

    /// Transient: bytes charged by sys_exec (ELF loader) not yet reflected
    /// in `elf_charged_bytes`. Non-zero between load_elf() and exec commit.
    pub exec_pending_bytes: u64,

    /// R165-1/R165-2 FIX (D2-MM-BRK-RESV): Single-owner reservation that
    /// serializes concurrent `brk()` operations on a shared MmState
    /// (CLONE_VM / CLONE_THREAD siblings). `sys_brk` drops the MmState lock
    /// across irreversible page-table work; without a reservation a sibling
    /// `brk()` could move `mm.brk` in that window, leaving the just-freed
    /// shrink range as an unmapped hole inside the grown heap (self-SIGSEGV)
    /// or the just-mapped grow range leaked above the logical heap (cgroup
    /// under-count). While `true`, any other `brk()` returns the current break
    /// unchanged, so the lock-dropped PT work stays consistent with the commit.
    /// `fork()` is rejected while this is set (mirrors the mmap transient-state
    /// guard) so a child cannot inherit a half-applied heap.
    pub brk_in_progress: bool,

    /// R172-16: the in-flight `sys_brk` heap-grow VA range `[lo, hi)` (`old_top`,
    /// `new_top`), armed atomically with the mmap-overlap check while the grow drops the
    /// MmState lock for page-table work. `sys_mmap` rejects any placement intersecting it,
    /// so a CLONE_VM / CLONE_THREAD sibling mmap cannot land inside the grow window and be
    /// silently adopted into the heap (double VMA ownership + double cgroup uncharge).
    /// Inactive ⇔ `lo == hi` (both `0`). Carries NO charge — a pure VA placement-exclusion.
    pub brk_grow_resv_lo: usize,
    pub brk_grow_resv_hi: usize,

    /// M0-7 item7 SLICE 4 (user-stack demand-grow PRIMITIVE): the in-flight DATA
    /// charge for an in-progress `try_grow_user_stack`, the stack-lane twin of
    /// `brk_pending_growth`. The grow HARD-charges the DATA bytes to its snapshot
    /// cgroup, records them HERE, drops the Process lock for the irreversible
    /// page-table work, then on the migration-atomic commit MOVES them into
    /// `elf_charged_bytes`. `compute_cgroup_charged_bytes` sums this lane so a
    /// cgroup migration racing the lock-dropped window cannot under-transfer the
    /// in-flight charge (the R144-1 `brk_pending_growth` protection, on the stack
    /// lane). Reset to 0 on fork (child) and exec (clean slate); only ever nonzero
    /// between arming and the matching commit/rollback of a single grow.
    pub stack_grow_pending_bytes: u64,

    /// M0-7 item7 SLICE 4: the lowest COMMITTED (mapped) user main-stack VA — the
    /// demand-grow watermark. `0` = sentinel (no user image yet, e.g. `MmState::new`
    /// before exec); set to `elf_loader::user_stack_mapped_floor()` at the exec
    /// image-install commit and COPIED on fork (the grown region is COW-inherited,
    /// so the child shares the floor). `try_grow_user_stack` lowers it under the
    /// migration-atomic commit; SLICE 5 will drive it from the `#PF` arm. The DATA
    /// for `[new_floor, stack_floor_committed)` is charged to `elf_charged_bytes`
    /// (FA-04: the bucket teardown + compute + fork read; `vm_charged_bytes` is read
    /// by NEITHER teardown NOR compute → would strand `mem_pinned>0` at exit →
    /// `delete_cgroup` fail-closed forever).
    pub stack_floor_committed: usize,

    /// M0-7 item7 SLICE 4: reservation serializing a `try_grow_user_stack` against
    /// siblings, fork, and cgroup migration (the stack-lane twin of
    /// `brk_in_progress`). While set: a sibling grow on the shared `MmState`
    /// early-returns `EAGAIN`; `fork` `EAGAIN`s (no half-applied grow inherited);
    /// `sys_cgroup_attach` `EAGAIN`s (the grow HARD-charges with the Process lock
    /// dropped — migrating mid-grow would snapshot `compute_cgroup_charged_bytes`
    /// and strand the in-flight lane). Cleared on EVERY commit / rollback / abort
    /// path (RAII `StackGrowReservation`) and reset on exec.
    pub stack_grow_in_progress: bool,

    /// R180-19 FIX: address-space fork transaction reservation.
    ///
    /// Set under the shared `MmState` lock only after proving that mmap,
    /// munmap, mprotect, brk, and stack growth have no in-flight transient.
    /// Every PT+metadata mutator checks this flag before arming its own
    /// transient reservation.  Fork may then snapshot `MmState`, drop the lock,
    /// and COW-clone under PT_LOCK without a CLONE_VM sibling changing PTEs or
    /// metadata between those two steps.  Cleared by an RAII guard on every
    /// fork exit.
    pub fork_in_progress: bool,
}

impl MmState {
    pub fn new(next_mmap_addr: usize) -> Self {
        Self {
            mmap_regions: crate::fallible_map::FallibleOrderedMap::new(),
            brk_start: 0,
            brk: 0,
            next_mmap_addr,
            vm_charged_bytes: 0,
            elf_charged_bytes: 0,
            pt_charged_bytes: 0,
            // R171-CG1x0 FIX (M2-1 SLICE-0): fresh AS — empty ledger, no inherited
            // basis, authoritative (INVARIANT I' holds: 0 == 0 + 0).
            pt_charged_frames: crate::fallible_map::FallibleOrderedMap::new(),
            pt_inherited_bytes: 0,
            pt_ledger_authoritative: true,
            brk_pending_growth: 0,
            mprotect_pending_bytes: 0,
            exec_pending_bytes: 0,
            brk_in_progress: false,
            brk_grow_resv_lo: 0,
            brk_grow_resv_hi: 0,
            // M0-7 item7 SLICE 4: no in-flight stack grow, sentinel floor (set at
            // exec image-install commit / copied on fork), no grow reservation.
            stack_grow_pending_bytes: 0,
            stack_floor_committed: 0,
            stack_grow_in_progress: false,
            fork_in_progress: false,
        }
    }

    /// M2-1 SLICE-4a: record `pt_frames` (the intermediate PT/PD frames a
    /// `map_to` / `map_page` call just built for an EAGER mapping) into this
    /// address space's frame-identity ledger and bump `pt_charged_bytes`,
    /// preserving INVARIANT I'
    /// (`pt_charged_bytes == pt_inherited_bytes + pt_charged_frames.len() * 0x1000`).
    ///
    /// The caller pairs this with `cgroup::charge_memory_forced(cgroup_id,
    /// pt_frames.len() * 0x1000)` under the SAME `Process -> MmState` lock hold
    /// (the cgroup side-effect stays at the call site, so this method is pure over
    /// `self` and unit-testable). This is the extracted, unit-tested form of the
    /// inline `sys_mmap` Phase-3 fold (kernel/kernel_core/syscall.rs ~7525); the
    /// mmap site KEEPS that fold inline and the two MUST stay in sync (a future
    /// slice may switch mmap to this method once brk/exec also adopt it).
    ///
    /// On ledger-reserve OOM (or the never-firing aliasing safety net) the frames
    /// fall back to the untracked `pt_inherited_bytes` basis: they then reclaim
    /// only at teardown (over-count-safe — restricts the tenant further, never a
    /// `memory.max` bypass), and INVARIANT I' is preserved on EVERY branch.
    pub(crate) fn record_pt_charge(&mut self, pt_frames: &[PhysFrame<Size4KiB>]) {
        let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);
        if pt_bytes == 0 {
            return;
        }
        let ledgered = if self.pt_charged_frames.try_reserve(pt_frames.len()).is_ok() {
            let mut all_fresh = true;
            for f in pt_frames {
                match self
                    .pt_charged_frames
                    .try_insert(f.start_address().as_u64(), ())
                {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        // A frame the allocator just handed out as is_unused() CANNOT
                        // already be ledgered unless free-after-remove were violated —
                        // a never-firing safety net, NEVER a silent in-place replace.
                        debug_assert!(
                            false,
                            "pt ledger frame aliased — free-after-remove invariant violated"
                        );
                        all_fresh = false;
                    }
                    // Unreachable after a successful try_reserve(len); defensive.
                    Err(_) => {
                        all_fresh = false;
                        break;
                    }
                }
            }
            all_fresh
        } else {
            false
        };
        self.pt_charged_bytes = self.pt_charged_bytes.saturating_add(pt_bytes);
        if ledgered {
            // This AS now authoritatively tracks its own PT charges by frame.
            if !self.pt_ledger_authoritative {
                self.pt_ledger_authoritative = true;
            }
        } else {
            // OOM / aliasing fallback: drop any partial inserts and carry the bytes
            // in the untracked basis so the ledger stays consistent with I' (these
            // frames reclaim wholesale at teardown).
            for f in pt_frames {
                self.pt_charged_frames.remove(&f.start_address().as_u64());
            }
            self.pt_inherited_bytes = self.pt_inherited_bytes.saturating_add(pt_bytes);
        }
    }

    /// M0-7 item7 SLICE 4: the PURE migration-atomic accounting commit for a
    /// successfully-mapped user-stack grow of `grow_size` DATA bytes that lowered
    /// the committed floor to `new_floor`. Called by `try_grow_user_stack` under
    /// the canonical `Process -> MmState` hold (so it lands atomically w.r.t. a
    /// cgroup migration, which snapshots `compute_cgroup_charged_bytes` under the
    /// Process lock — R155-5), and unit-tested directly by the SLICE-4 accounting
    /// self-test.
    ///
    /// FA-04 FIX: the DATA moves from the transient `stack_grow_pending_bytes` lane
    /// into the PERSISTENT `elf_charged_bytes` bucket — the one bucket that
    /// `free_process_resources` (process.rs:4992) AND `compute_cgroup_charged_bytes`
    /// (process.rs:5433) BOTH read, and that the fork child literal inherits
    /// (fork.rs:545). `vm_charged_bytes` (the demand-grow design's original home) is
    /// read by NEITHER, so a grow charged there would strand `mem_pinned>0` at every
    /// stack-growing exit → `delete_cgroup` fail-closed forever. The PT-frame kmem
    /// charge (`charge_memory_forced` + `record_pt_charge`) stays at the call site
    /// (a cgroup side-effect), keeping this method pure over `self`.
    ///
    /// `saturating_sub` on the pending lane is defensive: under the
    /// `stack_grow_in_progress` reservation exactly `grow_size` is in flight, so the
    /// subtract is exact; saturation only ever floors at 0 (never negative).
    pub(crate) fn commit_stack_grow(&mut self, grow_size: u64, new_floor: usize) {
        self.elf_charged_bytes = self.elf_charged_bytes.saturating_add(grow_size);
        self.stack_grow_pending_bytes = self.stack_grow_pending_bytes.saturating_sub(grow_size);
        self.stack_floor_committed = new_floor;
        self.stack_grow_in_progress = false;
    }

    /// RF178-12 FIX: allocation-free commit for a synchronous stack #PF.
    ///
    /// The fault keeps `Process -> MmState` locked from cgroup selection through
    /// PTE publication, so no transient pending lane or deferred identity lookup
    /// is needed. Fault-built page-table frames are intentionally inherited-basis
    /// bytes: the main stack has no munmap lifecycle, so they reclaim wholesale
    /// with the address space. The frame ledger and its capacity stay untouched,
    /// preserving invariant I'.
    pub(crate) fn commit_fault_stack_grow(
        &mut self,
        data_bytes: u64,
        pt_bytes: u64,
        new_floor: usize,
    ) {
        debug_assert_eq!(
            self.stack_grow_pending_bytes, 0,
            "synchronous #PF must not use the migration pending lane"
        );
        self.elf_charged_bytes = self.elf_charged_bytes.saturating_add(data_bytes);
        self.pt_charged_bytes = self.pt_charged_bytes.saturating_add(pt_bytes);
        self.pt_inherited_bytes = self.pt_inherited_bytes.saturating_add(pt_bytes);
        self.stack_floor_committed = new_floor;
        self.stack_grow_in_progress = false;
    }

    // NOTE: the former `clone_for_fork()` helper was removed (next-phase #11).
    // It was dead (zero callers — `fork_inner` builds the child `MmState` by an
    // explicit field-by-field struct literal) and relied on `MmState: Clone`,
    // which no longer exists now that `mmap_regions` is a `FallibleOrderedMap`.
    // The child's regions are cloned fallibly via `FallibleOrderedMap::
    // from_sorted_vec` over a try_reserve'd snapshot, eliminating the OOM-abort.
}

/// 进程控制块（PCB）
///
/// 注意：Process 不实现 Clone，因为 fd_table 包含需可失败复制的 FileDescriptor。
/// 进程复制（fork）通过手动字段复制和 clone_box() 实现。
///
/// # 线程模型
///
/// 在 CLONE_THREAD 模式下，多个 Process 结构体共享同一个 tgid（线程组ID）。
/// - pid: 唯一标识符（Linux 中称为 task）
/// - tid: 等于 pid（Linux 语义）
/// - tgid: 线程组ID（主线程的 pid，所有线程共享）
/// - is_thread: true 表示由 CLONE_THREAD 创建
// ============================================================================
// M0-6: POSIX resource limits (rlimit)
// ============================================================================

/// A single resource limit (soft `rlim_cur` <= hard `rlim_max`).
/// ABI: matches Linux `struct rlimit64` (two u64, no padding).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}
const _: () = assert!(core::mem::size_of::<RLimit>() == 16);

/// "No limit" sentinel (RLIM64_INFINITY).
pub const RLIM_INFINITY: u64 = u64::MAX;
/// Number of resource-limit slots (Linux RLIMIT_NLIMITS = 16).
pub const RLIMIT_NLIMITS: usize = 16;

// Linux x86-64 resource indices (the ones referenced by name; the array spans 0..16).
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_NOFILE: usize = 7;

/// Default resource limits for a freshly-created process.
///
/// NOFILE/STACK track the kernel's ACTUAL caps so the reported soft limit does
/// not lie (NOFILE soft==hard==MAX_FD; STACK soft == the loader's ACTUAL writable
/// stack = `USER_STACK_SIZE - USER_STACK_GUARD_SIZE`, i.e. the reserved window minus
/// the M0-7 permanently-unmapped low guard page). All other limits are RLIM_INFINITY.
/// **ALL limits are ADVISORY**: stored + reported faithfully but NOT enforced —
/// `allocate_fd` uses the compile-time `MAX_FD` cap and the loader maps a fixed
/// writable stack regardless of these values (M0 scope; enforcement is future work).
pub fn default_rlimits() -> [RLimit; RLIMIT_NLIMITS] {
    let inf = RLimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };
    let mut r = [inf; RLIMIT_NLIMITS];
    r[RLIMIT_NOFILE] = RLimit {
        rlim_cur: MAX_FD as u64,
        rlim_max: MAX_FD as u64,
    };
    // M0-7: report the ACTUAL writable stack (reserved window minus the unmapped low
    // guard page), so getrlimit/prlimit64 do not overstate the mapped extent by a page.
    // R172-X-F2: derived from the single-sourced mapped floor (TOP - mapped_floor ==
    // SIZE - GUARD, byte-identical) so the limit tracks any future guard-size change.
    r[RLIMIT_STACK] = RLimit {
        rlim_cur: crate::elf_loader::USER_STACK_TOP - crate::elf_loader::user_stack_usable_floor(),
        rlim_max: RLIM_INFINITY,
    };
    r
}

#[derive(Debug)]
pub struct Process {
    /// 进程ID（唯一标识，也是 Linux 语义中的 tid）
    pub pid: ProcessId,

    /// R106-1 FIX: 进程代际（monotonic generation counter）。
    ///
    /// 每个进程实例获得一个全局唯一、单调递增的 generation 值。
    /// 当 PID 被回收并分配给新进程时，新进程的 generation 不同于旧进程，
    /// 从而防止 IPC allowed_senders 等基于 PID 的授权被新进程继承。
    pub generation: u64,

    /// 线程ID（等于 pid，保持 Linux 兼容性）
    pub tid: ProcessId,

    /// 线程组ID（主线程时等于 pid，子线程时等于主线程的 pid）
    pub tgid: ProcessId,

    /// 父进程ID
    pub ppid: ProcessId,

    /// 是否为线程（由 CLONE_THREAD 创建）
    pub is_thread: bool,

    /// 进程名称
    pub name: String,

    /// 进程状态
    pub state: ProcessState,

    /// R98-1 FIX: 作业控制停止标志（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）。
    ///
    /// 与 `state` 正交：进程可以同时处于 Blocked/Sleeping 且被 job-control 停止。
    /// 当 `stopped == true` 时，调度器不会选择该进程运行，但其等待队列位置不变，
    /// 避免 SIGSTOP 覆盖 Blocked 状态导致丢失唤醒（H-34）。
    pub stopped: bool,

    /// 挂起的信号位图（1-64）
    pub pending_signals: PendingSignals,

    // ──────────────────────────────────────────────────────────────────────
    // M0 item 5 (sub-slice 1a): user signal-handler delivery state.
    //
    // PER-TASK storage (a documented M0 DIVERGENCE from Linux, which shares the
    // disposition table across a CLONE_SIGHAND thread group — same accepted
    // pattern as the M0-6 per-task `rlimits`). A future CLONE_SIGHAND slice must
    // NOT silently swap in a shared `Arc<Mutex<..>>` without a Process→table
    // lock-ordering review.
    // ──────────────────────────────────────────────────────────────────────
    /// Per-task blocked-signal mask (signal `n` → bit `1<<(n-1)`). SIGKILL/SIGSTOP
    /// are structurally never set (`apply_sigprocmask` force-clears them).
    pub blocked: u64,
    /// Per-signal disposition table (index = signum-1). Born-clean = all SIG_DFL;
    /// reset to SIG_DFL for caught signals on exec (SIG_IGN preserved).
    pub sigactions: [SigAction; NSIG],
    /// The blocked mask saved when a handler frame is built; restored by
    /// `rt_sigreturn` from THIS field (never from the user-controlled `uc_sigmask`,
    /// closing a mask-widening SROP). Cleared on exec.
    pub saved_blocked: u64,
    /// M0 #5 (sub-slice 1b-2): SAME-return handler delivery for a syscall that
    /// BLOCKED and resumed. The per-CPU `frame_ptr` (the live kernel-stack
    /// `SyscallFrame`) is ZEROED by `switch_context` on switch-out
    /// (arch/context_switch.rs), so when a blocked syscall resumes, its return-tail
    /// mutable-frame accessor fails-closed and delivery would defer to the NEXT
    /// syscall (the 1b-1 gap → a syscall-free post-EINTR compute-spinner never runs
    /// its handler). These capture the live `(frame_ptr, owner_pid)` binding at THIS
    /// syscall's entry (gated by the any-handler hint) so `maybe_deliver_signal` can
    /// REPUBLISH the per-CPU binding and deliver at the SAME return as the EINTR
    /// wake. The frame VA is per-task-invariant (kernel_stack_top − frame − fpu) and
    /// the kernel stack persists across a block, so a binding captured at this (or a
    /// prior) entry still points at the live frame. Handler SCRATCH: born-clean, NOT
    /// inherited on fork / CLONE_VM, cleared on exec (exactly like `saved_blocked` /
    /// `in_signal_handler`).
    pub saved_frame_ptr: u64,
    /// Owner PID of `saved_frame_ptr` (always this task). Re-validated against
    /// `current_pid()` by the owner-checked mutable accessor after republish, so a
    /// stale/corrupt binding can never redirect another task's frame.
    pub saved_frame_owner: u64,
    /// Nesting guard: true while a handler frame is live (between delivery and
    /// `rt_sigreturn`). Caps slice-1a nested delivery at one (a second deliverable
    /// signal stays pending until `rt_sigreturn` clears this). Cleared on exec.
    /// (The lock-free "any handler installed" fast-path hint is a MONOTONIC GLOBAL,
    /// `signal::any_handler_installed()`, not a per-task field — an AtomicBool inside
    /// this Mutex-guarded struct could not be read lock-free anyway.)
    pub in_signal_handler: bool,

    /// M0-6 poll/select (ppoll/pselect6 TIF_RESTORE_SIGMASK analog): when a
    /// ppoll/pselect6 with a temporary signal mask is interrupted by a signal that
    /// is deliverable ONLY under the caller's ORIGINAL mask, the temporary mask is
    /// LEFT installed (so the just-woken signal is delivered under it at the
    /// dispatcher tail) and the original mask is stashed here. It is restored to
    /// `blocked` either by `maybe_deliver_signal` (as the `saved_blocked` source, so
    /// `rt_sigreturn` lands on the original mask) OR by the dispatcher-tail
    /// `poll_restore_sigmask_tail` on every no-delivery path. `None` = no pending
    /// restore (the common case). Handler-scratch class: born-clean, NOT inherited on
    /// fork/CLONE_VM (stays `None` via `Process::new`), cleared on exec — exactly like
    /// `saved_blocked`.
    pub poll_restore_blocked: Option<u64>,

    /// 进程优先级（静态优先级）
    pub priority: Priority,

    /// 动态优先级（用于调度）
    pub dynamic_priority: Priority,

    /// E.4 Priority Inheritance: 未应用 PI 的动态优先级基线
    ///
    /// When priority inheritance is active, `dynamic_priority` becomes the effective
    /// priority (min of base and all PI boosts). This field stores the original
    /// priority before any PI modifications were applied.
    pub base_dynamic_priority: Priority,

    /// E.4 Priority Inheritance: 当前的 futex PI 捐赠 (key -> 最高等待者优先级)
    ///
    /// When this task holds a futex and high-priority waiters are blocked on it,
    /// those waiters' priorities are recorded here. The effective priority is
    /// computed as min(base_dynamic_priority, min(all pi_boosts values)).
    pub pi_boosts: crate::fallible_map::FallibleOrderedMap<FutexKey, Priority>,

    /// RF178-8: one capacity slot reserved for the PI futex this task is
    /// currently waiting to inherit. A task can wait on at most one futex, so a
    /// single keyed reservation is sufficient. Other boost insertions preserve
    /// this spare slot, making robust-owner handoff/exit propagation allocation-free.
    pub pi_boost_reservation: Option<FutexKey>,

    /// E.4 Priority Inheritance: 如果阻塞在 futex 上，记录等待的 futex key
    ///
    /// Used for transitive priority inheritance: if A waits on B, and B waits on C,
    /// then A's priority should propagate through to C.
    pub waiting_on_futex: Option<FutexKey>,

    /// 时间片（剩余时间片，单位：毫秒）
    pub time_slice: u32,

    /// CPU上下文
    pub context: Context,

    /// Has this process ever used FPU/SIMD (lazy FPU tracking).
    ///
    /// When false, the FPU state in `context.fx` is default-initialized and
    /// has never been saved from hardware. When true, the state was saved by
    /// the #NM handler and should be restored on next FPU use.
    /// This enables lazy FPU save/restore to skip processes that never use FPU.
    pub fpu_used: bool,

    /// 内核栈指针（栈底）
    pub kernel_stack: VirtAddr,

    /// 内核栈顶（用于 TSS.rsp0）
    pub kernel_stack_top: VirtAddr,

    /// Original buddy block identity for the four-page kernel stack. Deferred
    /// reclaim validates every leaf against this exact base before returning
    /// the order-2 block; deriving identity from mutable PTEs at teardown would
    /// let corruption substitute an unrelated allocation.
    pub(crate) kernel_stack_phys: Option<PhysFrame<Size4KiB>>,

    /// R180-12: callback capacity reserved before this stack was allocated.
    /// Teardown consumes it to enqueue allocation-free deferred reclamation.
    pub(crate) kernel_stack_rcu: Option<crate::rcu::RcuCallbackPermit>,

    /// 用户栈指针（如果是用户进程）
    pub user_stack: Option<VirtAddr>,

    /// 内存空间（页表基址）
    pub memory_space: usize,

    /// H.3 KPTI: 用户页表根（user CR3 / 用户 PML4 物理地址）
    ///
    /// When KPTI dual page tables are active:
    /// - `memory_space` serves as the **kernel CR3** (full kernel + user mappings)
    /// - `user_memory_space` serves as the **user CR3** (user mappings + entry trampoline only)
    ///
    /// When KPTI is disabled (the default), this field is 0 and `memory_space` is
    /// used for both kernel and user modes (identical CR3, zero-overhead skip in
    /// the syscall assembly's `cmp/je` pattern).
    ///
    /// The user PML4 shares user-half page table sub-trees (PML4[0..255]) with the
    /// kernel PML4 — entries point to the same PDPT/PD/PT frames. Only the PML4
    /// root frame itself is privately owned. When freeing, only the root frame is
    /// deallocated (no recursion into shared sub-tables).
    pub user_memory_space: usize,

    /// D3-ARC-MM-SHARED: Shared virtual memory metadata.
    /// Under CLONE_VM, siblings share the same Arc. Under fork, each gets a clone.
    /// Lock ordering: Process → MmState (never reverse).
    pub mm: Arc<Mutex<MmState>>,

    /// 文件描述符表（fd -> 描述符）
    ///
    /// fd 0/1/2 分别保留给 stdin/stdout/stderr，新分配从 3 开始
    pub fd_table: AdmittedMap<i32, FileDescriptor>,

    /// R39-4 FIX: 带 FD_CLOEXEC 标记的文件描述符集合
    ///
    /// exec 时会关闭这些 fd，防止敏感句柄泄漏到新程序
    pub cloexec_fds: AdmittedSet<i32>,

    /// R180-23: FD numbers admitted for an in-progress open transaction but not
    /// yet published in `fd_table`. Fixed bitmap: reservation cannot allocate,
    /// competing allocators skip the slot, and guessed use still observes EBADF.
    fd_reservations: [u64; FD_RESERVATION_WORDS],

    /// Subset of `fd_reservations` whose eventual publication must atomically
    /// install FD_CLOEXEC. Keeping this in fixed storage lets reservation also
    /// pre-grow the admitted set before a mutating VFS operation begins.
    fd_cloexec_reservations: [u64; FD_RESERVATION_WORDS],

    /// `files.max` charges currently held by `fd_reservations`. Kept separate
    /// from the installed-FD count so both invariants remain auditable at exit.
    fd_reservations_charged_count: u64,

    /// M0-6: POSIX resource limits (getrlimit/setrlimit/prlimit64).
    ///
    /// PER-TASK storage (a documented M0 DIVERGENCE from Linux, which shares one
    /// rlimit set per thread group). Inherited by COPY on both fork and clone.
    /// Mostly ADVISORY (see `default_rlimits`). A future thread-group-sharing
    /// slice must NOT silently swap in a mutable Arc without a Process→MmState
    /// lock-ordering review.
    pub rlimits: [RLimit; RLIMIT_NLIMITS],

    /// J2-7: Running count of open file descriptors this process has charged to
    /// its cgroup's `files.max` budget. Maintained in LOCKSTEP with every
    /// fd_table mutation (allocate_fd +1, remove_fd −1, apply_fd_cloexec −N,
    /// fork/clone batch = N, dup2/dup3 net delta) so it is the AUTHORITATIVE
    /// amount to uncharge at exit — independent of `fd_table.len()`, which can
    /// diverge on a clone-error child that copied fds but failed before the
    /// batch charge. INV-CG-FD: `fds_charged_count == fds this process holds
    /// charged to `cgroup_id``; fd_table is per-process (deep-copied, never
    /// Arc-shared even under CLONE_FILES) so exit-uncharge is unconditional.
    pub fds_charged_count: u64,

    /// 能力表（Capability Table，管理进程持有的能力）
    ///
    /// 每个进程拥有独立的能力表。能力表中的条目（CapEntry）包含：
    /// - 对内核对象（文件、端点、Socket 等）的引用
    /// - 权限掩码（只读、读写、执行等）
    /// - 标志（CLOEXEC、CLOFORK 等）
    ///
    /// 使用 Arc 包装以支持 fork 时的高效克隆。
    cap_table: Arc<CapTable>,

    /// 退出码
    pub exit_code: Option<i32>,

    /// R153-3 FIX: Thread-group exiting flag (shared among CLONE_THREAD siblings).
    ///
    /// Set by exit_group() before sibling marking begins. sys_clone(CLONE_THREAD)
    /// checks this flag to prevent new threads from being created during
    /// exit_group(), closing the TOCTOU window where per-thread pending_kill
    /// has not yet been set.
    pub thread_group_exiting: Arc<AtomicBool>,

    /// R115-1 FIX: Cross-CPU exit request flag.
    ///
    /// `exit_group()` terminates sibling threads that may be running on other CPUs.
    /// Directly calling `terminate_process()` cross-CPU is unsafe (UAF on kernel
    /// stack/FPU state). Instead, the requesting CPU sets this flag, and the target
    /// consumes it at a safe point (syscall return) to self-terminate.
    pub pending_kill: AtomicBool,

    /// R115-1 FIX: Exit code to use when `pending_kill` is consumed.
    pub pending_exit_code: AtomicI32,

    /// 等待的子进程（Some(0) 表示等待任意子进程，Some(pid) 表示等待特定子进程）
    pub waiting_child: Option<ProcessId>,

    /// 子进程列表
    pub children: AdmittedVec<ProcessId>,

    /// R158-4 FIX: Reserved child slots not yet committed (prevents concurrent capacity theft).
    pub children_reserved: usize,

    /// R158-4 FIX: Set when reparent_orphans cannot push a child into this process's
    /// children list. Signals sys_wait to perform a PROCESS_TABLE fallback scan.
    pub children_incomplete: bool,

    /// CPU时间统计（毫秒）
    pub cpu_time: u64,

    /// R65-19 FIX: 等待时间计数器（调度器tick数）
    ///
    /// 跟踪进程在就绪队列中等待的时间。当等待时间超过阈值时，
    /// 调度器会提升进程的动态优先级，防止低优先级进程饥饿。
    /// 每次进程被调度运行时重置为0。
    pub wait_ticks: u64,

    /// RF178-3 FIX: Timer epoch already folded into `wait_ticks`. Selection can
    /// scan a queue multiple times per tick; this prevents scan count from
    /// masquerading as elapsed wait time.
    pub wait_age_tick: u64,

    /// CPU亲和性位掩码（bit N = 允许在CPU N上运行）
    ///
    /// 用于SMP调度，限制进程可以运行的CPU集合。
    /// 默认值：0xFFFFFFFFFFFFFFFF（允许在所有CPU上运行）
    /// 位0对应CPU 0，位1对应CPU 1，以此类推。
    pub allowed_cpus: u64,

    /// Cpuset ID for CPU isolation.
    ///
    /// Tasks are restricted to CPUs in their cpuset's mask.
    /// Effective affinity = online_mask ∩ cpuset_mask ∩ allowed_cpus.
    /// Default: CpusetId(0) = root cpuset (all CPUs).
    pub cpuset_id: u32,

    /// 创建时间戳
    pub created_at: u64,

    // ========== 进程凭证 (DAC支持) ==========
    /// R39-3 FIX: 共享凭证结构
    ///
    /// 使用 Arc<SharedCredentials> 实现线程间共享凭证和代际。
    /// CLONE_THREAD 创建的线程共享同一个 Arc，因此 setuid/setgid
    /// 等操作会影响所有同进程的线程（符合 POSIX 语义）。
    /// 普通 fork 会 clone 凭证到新的 Arc。
    credentials: Arc<SharedCredentials>,

    /// 文件创建掩码 (umask)
    /// 新建文件的权限 = mode & !umask
    pub umask: u16,

    // ========== OOM Killer 支持 ==========
    /// Nice 值 (-20 到 19)
    /// 负值表示更高优先级，正值表示更低优先级
    /// 对于 OOM killer：nice 值越高越容易被杀
    pub nice: i32,

    /// OOM 分数调整值 (-1000 到 1000)
    /// -1000 表示完全免疫 OOM killer
    /// 正值增加被杀概率，负值降低被杀概率
    pub oom_score_adj: i32,

    // ========== 堆管理 (brk) — moved to MmState ==========

    // ========== TLS 支持 ==========
    /// FS segment base (用于 TLS)
    pub fs_base: u64,

    /// GS segment base (保留)
    pub gs_base: u64,

    // ========== 线程支持 (musl 初始化需要) ==========
    /// clear_child_tid 指针 (set_tid_address / CLONE_CHILD_CLEARTID)
    /// 进程退出时内核会将此地址处的值设为 0 并执行 futex_wake
    pub clear_child_tid: u64,

    /// set_child_tid 指针 (CLONE_CHILD_SETTID)
    /// clone 时内核会将子线程 tid 写入此地址
    pub set_child_tid: u64,

    /// robust_list 头指针 (set_robust_list)
    /// 用于 robust futex 机制，进程退出时内核会清理持有的 robust mutex
    pub robust_list_head: u64,

    /// robust_list 长度
    pub robust_list_len: usize,

    // ========== F.1: PID Namespace Support ==========
    /// PID namespace membership chain (root -> owning namespace)
    ///
    /// Each entry contains the namespace and the PID as seen from that namespace.
    /// The last entry is the owning (leaf) namespace where the process was created.
    /// Root namespace (level 0) uses global PID directly.
    pub pid_ns_chain: AdmittedVec<crate::pid_namespace::PidNamespaceMembership>,

    /// PID namespace for children
    ///
    /// When CLONE_NEWPID is used, children are created in a new child namespace.
    /// Otherwise, children inherit this namespace (same as parent's owning namespace).
    pub pid_ns_for_children: crate::pid_namespace::PidNamespaceArc,

    // ========== F.1: Mount Namespace Support ==========
    /// Mount namespace of this process
    ///
    /// All path resolution and mount operations are confined to this namespace.
    /// CLONE_THREAD keeps the same mount namespace; CLONE_NEWNS creates a copy.
    pub mount_ns: Arc<crate::mount_namespace::MountNamespace>,

    /// Mount namespace for children (set by CLONE_NEWNS)
    ///
    /// Children inherit this namespace unless CLONE_NEWNS is requested,
    /// in which case a new namespace copy is created for them.
    pub mount_ns_for_children: Arc<crate::mount_namespace::MountNamespace>,

    // ========== F.1: IPC Namespace Support ==========
    /// IPC namespace of this process
    ///
    /// All IPC resources (message queues, semaphores, shared memory) are
    /// confined to this namespace. CLONE_NEWIPC creates an isolated namespace.
    pub ipc_ns: Arc<crate::ipc_namespace::IpcNamespace>,

    /// IPC namespace for children (set by CLONE_NEWIPC)
    pub ipc_ns_for_children: Arc<crate::ipc_namespace::IpcNamespace>,

    // ========== F.1: Network Namespace Support ==========
    /// Network namespace of this process
    ///
    /// All network operations (sockets, interfaces, routing) are confined
    /// to this namespace. CLONE_NEWNET creates an isolated namespace.
    pub net_ns: Arc<crate::net_namespace::NetNamespace>,

    /// Network namespace for children (set by CLONE_NEWNET)
    pub net_ns_for_children: Arc<crate::net_namespace::NetNamespace>,

    // ========== F.1: User Namespace Support ==========
    /// User namespace of this process
    ///
    /// Provides UID/GID virtualization. Inside a user namespace, a process
    /// can appear as root (uid=0) while being unprivileged on the host.
    /// CLONE_NEWUSER creates an isolated namespace with its own UID/GID mappings.
    pub user_ns: Arc<crate::user_namespace::UserNamespace>,

    /// User namespace for children (set by CLONE_NEWUSER)
    pub user_ns_for_children: Arc<crate::user_namespace::UserNamespace>,

    // ========== F.2: Cgroup v2 Support ==========
    /// Cgroup ID this process belongs to.
    ///
    /// Every process is attached to exactly one cgroup. The root cgroup (id=0)
    /// is the default. Cgroup controllers (CPU/Memory/PIDs) enforce resource
    /// limits based on this membership.
    pub cgroup_id: crate::cgroup::CgroupId,

    /// R171 M2-1 SLICE-1 FIX: true while this task is inside `sys_exec` between the
    /// cgroup snapshot (`exec_cgroup_id` captured under the Process lock) and the
    /// commit/rollback. `sys_exec` HARD-charges the new image's memory to that
    /// snapshot cgroup inside `load_elf` with the Process lock DROPPED (lock-ordering
    /// forbids holding it across the PT work); arming `exec_pending_bytes` only
    /// afterward leaves a window where a concurrent cgroup migration would snapshot
    /// `compute_cgroup_charged_bytes` WITHOUT the in-flight charge and strand it on
    /// the snapshot cgroup (the 4 mem-leg exec KILLs). Both migration front doors
    /// (`sys_cgroup_attach`, cgroupfs `cgroup.procs`) refuse to re-home a task whose
    /// `exec_in_progress` is set (EAGAIN/EBUSY retry, checked under the Process lock
    /// BEFORE `migrate_task`), making the exec charge migration-atomic by mutual
    /// exclusion — no held-Arc, no compute change, no FA-04. Set/cleared ONLY under
    /// the Process lock; a RAII guard clears it on every `sys_exec` exit.
    pub exec_in_progress: bool,

    /// R170-3 FIX: contention-deferred CPU-quota debt (ns) not yet landed on
    /// `cpu_quota_debt_cgid`'s quota windows. `on_clock_tick` folds TICK_NS in
    /// here when `charge_cpu_quota` returns `ContentionDeferred` (which
    /// guarantees NOTHING was accumulated) and passes `TICK_NS + debt` on the
    /// next tick — so induced registry/limits contention DEFERS quota
    /// accounting by a tick instead of silently DROPPING it (the R170-3
    /// cpu.max evasion). Read/written only under the PCB lock. Taken
    /// (read + zero, same critical section) and flushed via
    /// `cgroup::flush_cpu_quota_debt` at every `cgroup_id` re-point
    /// (`sys_cgroup_attach`, cgroupfs `cgroup.procs`) and at
    /// `terminate_process`, so the tag below can never go stale.
    pub cpu_quota_debt_ns: u64,
    /// R170-3 FIX: the cgroup id the deferred debt was accrued against (the
    /// tag). On a tag/cgroup_id mismatch the tick handler drops the debt
    /// defensively rather than mis-charge — unreachable while the three
    /// flush sites above hold.
    pub cpu_quota_debt_cgid: crate::cgroup::CgroupId,

    // ========== Seccomp/Pledge 沙箱 ==========
    /// Seccomp 过滤器状态
    /// 包含 BPF 过滤器栈和 no_new_privs 标志
    pub seccomp_state: SeccompState,

    /// Pledge 状态（可选）
    /// 如果设置，表示进程使用 OpenBSD 风格的 pledge 沙箱
    pub pledge_state: Option<PledgeState>,

    /// R26-3: 标记当前是否正在安装 seccomp 过滤器
    /// 在安装期间拒绝创建新线程，防止 TSYNC 竞态绕过
    pub seccomp_installing: bool,

    /// RF180-1 FIX: monotonic revision of the committed seccomp filter stack.
    ///
    /// Clone snapshots this value with the filter state, then re-validates it
    /// while holding the parent lock through child policy publication.  A
    /// boolean `seccomp_installing` sample cannot detect an installation that
    /// both starts and completes between two clone snapshots; the revision can.
    pub seccomp_generation: u64,

    // ========== G.1: Observability ==========
    /// Watchdog handle for hung-task detection.
    ///
    /// If set, the scheduler sends heartbeats during context switches.
    /// Unregistered on process termination.
    pub watchdog_handle: Option<WatchdogHandle>,

    /// R169-9 FIX: exactly-once heavy-teardown CLAIM. The IRQ-deferred kill path
    /// may pre-set `state = Zombie` (to mark the halted task non-runnable) BEFORE
    /// the deferred `terminate_process` runs, so `state` can no longer be the
    /// teardown-skip arbiter (doing so skipped teardown entirely — the R169-9
    /// leak). This atomic is: the first `terminate_process` to win
    /// `compare_exchange(false -> true)` runs the heavy teardown; all others
    /// early-return. Strictly stronger than the old `Zombie|Terminated` state
    /// guard for exactly-once, while a pre-set Zombie no longer suppresses it.
    pub teardown_claimed: core::sync::atomic::AtomicBool,

    /// R169-9 FIX: published (Release) when heavy teardown has COMPLETED. A
    /// Zombie is reapable ONLY when this is set — this blocks the reaper
    /// (`wait_process`/`cleanup_zombie`/`sys_wait4`) from freeing the PCB before
    /// the deferred `terminate_process` has actually torn it down (cgroup / pid-ns
    /// / futex / FPU-owner / watchdog), which would strand those charges (BREAK #1).
    pub teardown_done: core::sync::atomic::AtomicBool,

    /// M4-1b: per-PCB socket-wait timeout marker (replaces the global heap
    /// `SocketWaiters.timed_out: BTreeMap` whose `insert` allocated a node in
    /// TIMER-IRQ context — the R151-5 deadlock class). Packed encoding:
    /// `0` == no marker; otherwise `(generation << 1) | 1` (low tag bit makes 0
    /// an unambiguous sentinel). SET (`store(packed, Release)`) strictly BEFORE
    /// `state = Ready`, both inside the SAME held proc-lock critical section, by
    /// the timer-IRQ / inline path that itself performs the Blocked->Ready wake.
    /// CONSUMED by the waiter's own epilogue via `swap(0, AcqRel)` under the proc
    /// lock. The proc-lock release/acquire hand-off — NOT the atomic ordering — is
    /// the marker-before-wake synchronizing edge (every `state` reader holds the
    /// proc lock). Re-zeroed at every wait ENTRY (born-clean), so a marker for one
    /// wait can never surface in the next wait of the same PCB. RESIDUAL: the
    /// `(gen<<1)|1` pack aliases generations differing by exactly 2^63 (top bit
    /// shifted out) — unreachable within a sub-tick consume window.
    pub socket_timeout_marker: AtomicU64,

    /// M4-1b: per-PCB WaitQueue timeout marker — twin of `socket_timeout_marker`
    /// for the `ipc::sync::WaitQueue` path (replaces the per-queue heap
    /// `WaitQueue.timed_out: Mutex<BTreeMap>` whose IRQ `insert` allocated). A
    /// SEPARATE field because the two subsystems own INDEPENDENT, non-comparable
    /// generation counters (socket `next_generation` starts at 1; per-queue
    /// `wait_generation` starts at 0); a task blocks on exactly one primitive so
    /// the two fields are never both live. Same encoding / ordering / entry-clear
    /// contract as `socket_timeout_marker`.
    pub wq_timeout_marker: AtomicU64,

    /// M1-02: the globally-unique sequence (`alloc_wait_seq`) of the timed
    /// `ipc::sync::WaitQueue` wait this PCB is currently blocked in; `0` = none.
    /// STAMPED under the proc lock in the SAME critical section as the
    /// `wq_timeout_marker` entry-clear and `state = Blocked` (so the proc-lock
    /// RELEASE is the publishing edge), and MATCHED by the timer-tick IRQ under the
    /// proc lock (`wq_timeout_wake_by_seq`) to wake EXACTLY this wait WITHOUT
    /// dereferencing the `WaitQueue` — the structural fix for the M1-02 timer-IRQ
    /// use-after-free. Born-clean; cleared to 0 on EVERY wait-exit path. Only ever
    /// read/written under the proc lock, so `Relaxed` access is sufficient (the lock
    /// is the synchronizing edge).
    pub active_wait_seq: AtomicU64,

    /// R172-03 FIX (CONTEXT-SAVE-COMPLETE): a lock-free "this task's `context` is not
    /// yet durable / its kernel stack may still be aliased by an in-flight switch"
    /// gate, composed AND with `state == Ready` by EVERY scheduler claimant
    /// (`select_next_locked` / `steal_one` / `select_next_process` / `pop_ready_process`).
    /// SET (`store(true, Release)`) under the proc lock at every Running->Ready flip of
    /// the running task (`schedule()`, the `on_clock_tick` deferred-preempt flips, and
    /// `sys_yield`), and at the cross-CPU claim itself; CLEARED (`store(false, Release)`)
    /// ONLY after the outgoing register+FPU save has fully completed — deferred to the
    /// NEXT `reschedule_now` entry on the switching CPU (the Linux `finish_task_switch`
    /// model) so the clear can never race the still-in-progress save or alias the old
    /// kernel stack. Accessed lock-free via the PCB's stable address (same discipline as
    /// the timeout markers above), so concurrent readers never need the proc lock.
    pub on_cpu: AtomicBool,
    /// RF178-33: finish-task-switch is clearing `on_cpu` and completing the
    /// corresponding parent wake. Reapers must wait until this handoff clears.
    pub switch_reap_pending: AtomicBool,

    // ========== KCOV (Kernel Code Coverage) ==========
    /// Coverage buffer for fuzzing infrastructure
    ///
    /// When initialized via sys_kcov_init, tracks which code edges were hit
    /// during task execution. Used for coverage-guided fuzzing.
    /// None = coverage not initialized for this task.
    #[cfg(feature = "kcov")]
    pub coverage_buffer: Option<alloc::sync::Arc<spin::Mutex<coverage::CoverageBuffer>>>,

    /// Aggregate lifetime charge for construction-time shared control blocks
    /// and the retained process-name buffer. The outer PCB Arc has an
    /// independent allocator-owned charge that survives the last strong owner
    /// until the final `ProcessWeak` deallocates the control block (RF180-40).
    /// Declared last so all payload-owned allocations are destroyed before this
    /// payload charge is released.
    _heap_charge: Option<HeapCharge>,
}

// The fixed charge registry must never be the limiting resource. At this
// conservative lower bound, the CoreProcess byte gate permits at most 1024
// simultaneously live process Arc allocations.
const _: () = assert!(
    core::mem::size_of::<Mutex<Process>>()
        >= HeapClass::CoreProcess.limit_bytes() / PROCESS_ARC_CHARGE_SLOTS
);

impl Process {
    /// 创建新进程
    ///
    /// 默认以root权限运行（uid=0, gid=0），umask为标准0o022
    pub fn new(pid: ProcessId, ppid: ProcessId, name: String, priority: Priority) -> Self {
        let mm = Arc::new(Mutex::new(MmState::new(security::randomized_mmap_base(
            DEFAULT_MMAP_BASE,
        ))));
        let cap_table = Arc::new(CapTable::new());
        let thread_group_exiting = Arc::new(AtomicBool::new(false));
        let credentials = Arc::new(SharedCredentials::new(Credentials {
            uid: 65534,
            gid: 65534,
            euid: 65534,
            egid: 65534,
            supplementary_groups: AdmittedVec::new(HeapClass::CoreProcess),
        }));
        Self::new_with_allocations(
            pid,
            ppid,
            name,
            priority,
            mm,
            cap_table,
            thread_group_exiting,
            credentials,
            None,
        )
    }

    /// R180-7: construct a production PCB as one fallible admission
    /// transaction. Every allocator request is preceded by a conservative byte
    /// reservation; failure drops all private allocations and rolls the ledger
    /// back before the PCB can enter `PROCESS_TABLE`.
    pub fn try_new_pcb(
        pid: ProcessId,
        ppid: ProcessId,
        name: ProcessNameSnapshot,
        priority: Priority,
    ) -> Result<ProcessArc, ProcessCreateError> {
        let process_arc_bytes =
            arc_charge_bytes::<Mutex<Process>>().map_err(|_| ProcessCreateError::OutOfMemory)?;
        let mut fixed_total = 0usize;
        for bytes in [
            arc_charge_bytes::<Mutex<MmState>>(),
            arc_charge_bytes::<AtomicBool>(),
            arc_charge_bytes::<SharedCredentials>(),
        ] {
            let bytes = bytes.map_err(|_| ProcessCreateError::OutOfMemory)?;
            fixed_total = fixed_total
                .checked_add(bytes)
                .ok_or(ProcessCreateError::OutOfMemory)?;
        }
        let estimated_name = vec_charge_bytes::<u8>(name.as_str().len())
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let estimated_total = fixed_total
            .checked_add(estimated_name)
            .ok_or(ProcessCreateError::OutOfMemory)?;
        let mut reservation = try_reserve_heap(HeapClass::CoreProcess, estimated_total)
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        // Reserve the outer Arc independently before any allocation. Its charge
        // is transferred to ProcessArcAllocator and therefore follows the
        // control block through the final Weak drop instead of the PCB payload.
        let process_arc_reservation = try_reserve_heap(HeapClass::CoreProcess, process_arc_bytes)
            .map_err(|_| ProcessCreateError::OutOfMemory)?;

        // RF180-17 FIX: no process-name allocation precedes admission.
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.as_str().len())
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let actual_total = fixed_total
            .checked_add(
                vec_charge_bytes::<u8>(owned_name.capacity())
                    .map_err(|_| ProcessCreateError::OutOfMemory)?,
            )
            .ok_or(ProcessCreateError::OutOfMemory)?;
        reservation
            .resize(actual_total)
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        owned_name.push_str(name.as_str());

        let mm = Arc::try_new(Mutex::new(MmState::new(security::randomized_mmap_base(
            DEFAULT_MMAP_BASE,
        ))))
        .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let cap_table = CapTable::try_new_arc().map_err(|_| ProcessCreateError::OutOfMemory)?;
        let thread_group_exiting =
            Arc::try_new(AtomicBool::new(false)).map_err(|_| ProcessCreateError::OutOfMemory)?;
        let credentials = Arc::try_new(SharedCredentials::new(Credentials {
            uid: 65534,
            gid: 65534,
            euid: 65534,
            egid: 65534,
            supplementary_groups: AdmittedVec::new(HeapClass::CoreProcess),
        }))
        .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let payload_charge = reservation
            .commit()
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let process = Self::new_with_allocations(
            pid,
            ppid,
            owned_name,
            priority,
            mm,
            cap_table,
            thread_group_exiting,
            credentials,
            Some(payload_charge),
        );
        let process_arc_charge = process_arc_reservation
            .commit()
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let allocator = ProcessArcAllocator::try_install(process_arc_charge).map_err(|charge| {
            drop(charge);
            ProcessCreateError::OutOfMemory
        })?;
        match Arc::try_new_in(Mutex::new(process), allocator) {
            Ok(process) => Ok(process),
            Err(_) => {
                allocator.cancel_failed_allocation();
                Err(ProcessCreateError::OutOfMemory)
            }
        }
    }

    /// RF180-40 executable proof for the outer process Arc's exact accounting
    /// lifetime. The PCB payload and every payload-owned allocation disappear
    /// with the last strong reference, but a procfs-style Weak must keep the Arc
    /// control block and its independent charge live until that Weak is dropped.
    pub fn run_arc_lifetime_self_test() {
        let before = mm::heap_class_snapshot(HeapClass::CoreProcess);
        let outer_bytes = arc_charge_bytes::<Mutex<Process>>()
            .expect("RF180-40 process Arc charge must be representable");
        let process = Self::try_new_pcb(
            0x180_4001,
            1,
            ProcessNameSnapshot::from_parts("rf180-40-process-arc", ""),
            120,
        )
        .expect("RF180-40 process Arc fixture");
        let weak: ProcessWeak = Arc::downgrade(&process);

        drop(process);
        let after_strong = mm::heap_class_snapshot(HeapClass::CoreProcess);
        assert_eq!(after_strong.reserved_bytes, before.reserved_bytes);
        assert_eq!(
            after_strong.committed_bytes,
            before
                .committed_bytes
                .checked_add(outer_bytes)
                .expect("RF180-40 snapshot arithmetic"),
            "RF180-40 final Weak must retain exactly the outer Arc charge"
        );
        assert!(weak.upgrade().is_none());

        drop(weak);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::CoreProcess),
            before,
            "RF180-40 final Weak drop must deallocate then release admission"
        );
    }

    /// RF180-17 FIX: publish an already-admitted name with no allocation or
    /// recoverable failure in exec's post-PONR commit window.
    pub fn commit_prepared_name(&mut self, prepared: PreparedProcessName) {
        let old_bytes = vec_charge_bytes::<u8>(self.name.capacity())
            .expect("live process-name capacity charge must be representable");
        let PreparedProcessName { name, reservation } = prepared;
        let charge = self
            ._heap_charge
            .as_mut()
            .expect("production process must own aggregate heap charge");
        charge
            .absorb(reservation)
            .expect("prepared process-name charge must match PCB class");
        let old = core::mem::replace(&mut self.name, name);
        drop(old);
        charge
            .release_after_deallocation(old_bytes)
            .expect("process-name charge release must match old allocation");
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_allocations(
        pid: ProcessId,
        ppid: ProcessId,
        name: String,
        priority: Priority,
        mm: Arc<Mutex<MmState>>,
        cap_table: Arc<CapTable>,
        thread_group_exiting: Arc<AtomicBool>,
        credentials: Arc<SharedCredentials>,
        heap_charge: Option<HeapCharge>,
    ) -> Self {
        Process {
            pid,
            generation: NEXT_GENERATION.fetch_add(1, Ordering::SeqCst), // lint-fetch-add: allow (generation counter)
            tid: pid,                                                   // tid == pid (Linux 语义)
            tgid: pid,                                                  // 主线程时 tgid == pid
            ppid,
            is_thread: false,
            name,
            state: ProcessState::Ready,
            stopped: false, // R98-1 FIX: Job-control stop flag starts cleared
            pending_signals: PendingSignals::new(),
            // M0 item 5: signal-handler state born clean (no handlers, empty mask,
            // no live handler frame).
            blocked: 0,
            sigactions: crate::signal::default_sigactions(),
            saved_blocked: 0,
            // M0 #5 (1b-2): no live syscall-frame binding at birth.
            saved_frame_ptr: 0,
            saved_frame_owner: 0,
            in_signal_handler: false,
            // M0-6 poll/select: no pending ppoll/pselect6 sigmask restore at birth.
            poll_restore_blocked: None,
            priority,
            dynamic_priority: priority,
            base_dynamic_priority: priority, // E.4 PI: starts same as dynamic_priority
            socket_timeout_marker: AtomicU64::new(0), // M4-1b: born-clean, no timeout pending
            wq_timeout_marker: AtomicU64::new(0), // M4-1b: born-clean, no timeout pending
            active_wait_seq: AtomicU64::new(0), // M1-02: born-clean, no active timed wait
            on_cpu: AtomicBool::new(false),  // R172-03: born off-CPU (context durable)
            switch_reap_pending: AtomicBool::new(false),
            pi_boosts: crate::fallible_map::FallibleOrderedMap::new(),
            pi_boost_reservation: None,
            waiting_on_futex: None, // E.4 PI: not waiting on any futex
            time_slice: calculate_time_slice(priority),
            context: Context::default(),
            fpu_used: false, // Lazy FPU: process hasn't used FPU yet
            kernel_stack: VirtAddr::new(0),
            kernel_stack_top: VirtAddr::new(0),
            kernel_stack_phys: None,
            kernel_stack_rcu: None,
            user_stack: None,
            memory_space: 0,
            user_memory_space: 0,
            mm,
            fd_table: AdmittedMap::new(HeapClass::CoreProcess),
            cloexec_fds: AdmittedSet::new(HeapClass::CoreProcess),
            fd_reservations: [0; FD_RESERVATION_WORDS],
            fd_cloexec_reservations: [0; FD_RESERVATION_WORDS],
            fd_reservations_charged_count: 0,
            rlimits: default_rlimits(), // M0-6: POSIX resource limits
            fds_charged_count: 0,       // J2-7: no fds charged at construction

            cap_table,
            exit_code: None,
            thread_group_exiting,
            pending_kill: AtomicBool::new(false),
            pending_exit_code: AtomicI32::new(0),
            waiting_child: None,
            children: AdmittedVec::new(HeapClass::CoreProcess),
            children_reserved: 0,
            children_incomplete: false,
            cpu_time: 0,
            // R170-3: no deferred quota debt at birth. `Process::new` is the
            // sole full constructor (fork builds children through it), so a
            // child can never inherit its parent's debt.
            cpu_quota_debt_ns: 0,
            cpu_quota_debt_cgid: 0,
            wait_ticks: 0, // R65-19 FIX: Initialize starvation counter
            wait_age_tick: crate::get_ticks(),
            allowed_cpus: 0xFFFFFFFFFFFFFFFF, // SMP: Allow on all CPUs by default
            cpuset_id: 0,                     // Root cpuset (all CPUs)
            created_at: time::current_timestamp_ms(),
            // R101-1 FIX: Default to unprivileged nobody (uid=65534) credentials.
            //
            // Previously all processes started with uid=0 (root), creating a flat
            // privilege model with no defense-in-depth. Now Process::new() uses
            // restricted defaults. Kernel-internal processes (ppid=0) are promoted
            // to root explicitly by create_process(), and fork()/clone() inherit
            // credentials from the parent process via independent clone.
            credentials,
            umask: 0o022,
            // OOM killer 支持 - 默认中立设置
            nice: 0,
            oom_score_adj: 0,
            // 堆管理 — moved to MmState (brk_start/brk initialized to 0 there)
            // TLS 支持
            fs_base: 0,
            gs_base: 0,
            // 线程支持 (musl 初始化)
            clear_child_tid: 0,
            set_child_tid: 0,
            robust_list_head: 0,
            robust_list_len: 0,
            // F.1: PID namespace - default to root namespace
            // The actual chain will be assigned by create_process after PID allocation
            pid_ns_chain: AdmittedVec::new(HeapClass::CoreProcess),
            pid_ns_for_children: crate::pid_namespace::ROOT_PID_NAMESPACE.clone(),
            // F.1: Mount namespace - default to root mount namespace
            // The actual namespace will be assigned by create_process from parent
            mount_ns: crate::mount_namespace::ROOT_MNT_NAMESPACE.clone(),
            mount_ns_for_children: crate::mount_namespace::ROOT_MNT_NAMESPACE.clone(),
            // F.1: IPC namespace - default to root IPC namespace
            ipc_ns: crate::ipc_namespace::ROOT_IPC_NAMESPACE.clone(),
            ipc_ns_for_children: crate::ipc_namespace::ROOT_IPC_NAMESPACE.clone(),
            // F.1: Network namespace - default to root network namespace
            net_ns: crate::net_namespace::ROOT_NET_NAMESPACE.clone(),
            net_ns_for_children: crate::net_namespace::ROOT_NET_NAMESPACE.clone(),
            // F.1: User namespace - default to root user namespace
            // Unlike other namespaces, CLONE_NEWUSER does not require root/CAP_SYS_ADMIN
            user_ns: crate::user_namespace::ROOT_USER_NAMESPACE.clone(),
            user_ns_for_children: crate::user_namespace::ROOT_USER_NAMESPACE.clone(),
            // F.2: Cgroup v2 - default to root cgroup
            cgroup_id: 0,
            // R171 M2-1 SLICE-1: not mid-exec at construction.
            exec_in_progress: false,
            // Seccomp/Pledge 沙箱 (默认无限制)
            seccomp_state: SeccompState::new(),
            pledge_state: None,
            // R26-3: seccomp 安装状态标志
            seccomp_installing: false,
            // RF180-1: no committed filter installations at process birth.
            seccomp_generation: 0,
            // G.1: Watchdog not registered until process starts running
            watchdog_handle: None,
            // R169-9: teardown bookkeeping starts unclaimed / not-done.
            teardown_claimed: core::sync::atomic::AtomicBool::new(false),
            teardown_done: core::sync::atomic::AtomicBool::new(false),
            // KCOV: coverage not initialized at birth
            #[cfg(feature = "kcov")]
            coverage_buffer: None,
            _heap_charge: heap_charge,
        }
    }

    /// 分配新的文件描述符
    ///
    /// fd 0/1/2 保留给标准输入/输出/错误，新分配从 3 开始
    ///
    /// # Returns
    ///
    /// 成功返回分配的 fd；失败（fd 上限 / `files.max` 拒绝）返回 `Err(desc)`。
    ///
    /// # R170-6 FIX (D2-FD-DROP-UNDER-LOCK)
    ///
    /// On failure the un-installed object is handed BACK to the caller instead
    /// of being dropped inside this `&mut self` (Process-lock-held) scope —
    /// a `FileOps` Drop can re-enter wake paths / foreign Process locks / the
    /// L5 cgroup registry (the R154-3/R155-3 inversion family). The caller
    /// owns the object again and SHOULD let it drop only after releasing the
    /// Process lock (`sys_pipe` does); callers that deliberately keep today's
    /// inline-drop timing are tagged `D2-FD-DROP-UNDER-LOCK` at the call site.
    /// Both failure arms are charge-neutral: the no-slot arm never charged,
    /// and the charge arm's `try_charge_fds` already failed.
    #[inline]
    fn fd_is_reserved(&self, fd: i32) -> bool {
        if !(0..MAX_FD).contains(&fd) {
            return false;
        }
        let fd = fd as usize;
        self.fd_reservations
            .get(fd / 64)
            .is_some_and(|word| word & (1u64 << (fd % 64)) != 0)
    }

    #[inline]
    fn set_fd_reserved(&mut self, fd: i32, reserved: bool) -> bool {
        if !(0..MAX_FD).contains(&fd) {
            return false;
        }
        let fd = fd as usize;
        let Some(word) = self.fd_reservations.get_mut(fd / 64) else {
            return false;
        };
        let mask = 1u64 << (fd % 64);
        let was_reserved = *word & mask != 0;
        if reserved {
            *word |= mask;
        } else {
            *word &= !mask;
        }
        was_reserved
    }

    #[inline]
    fn fd_cloexec_is_reserved(&self, fd: i32) -> bool {
        if !(0..MAX_FD).contains(&fd) {
            return false;
        }
        let fd = fd as usize;
        self.fd_cloexec_reservations
            .get(fd / 64)
            .is_some_and(|word| word & (1u64 << (fd % 64)) != 0)
    }

    #[inline]
    fn set_fd_cloexec_reserved(&mut self, fd: i32, reserved: bool) -> bool {
        if !(0..MAX_FD).contains(&fd) {
            return false;
        }
        let fd = fd as usize;
        let Some(word) = self.fd_cloexec_reservations.get_mut(fd / 64) else {
            return false;
        };
        let mask = 1u64 << (fd % 64);
        let was_reserved = *word & mask != 0;
        if reserved {
            *word |= mask;
        } else {
            *word &= !mask;
        }
        was_reserved
    }

    #[inline]
    fn pending_fd_reservations(&self) -> Option<usize> {
        usize::try_from(self.fd_reservations_charged_count).ok()
    }

    #[inline]
    fn pending_cloexec_reservations(&self) -> usize {
        self.fd_cloexec_reservations
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Ensure live admitted backing has room for all existing reservations and
    /// one additional publication. No externally visible state is changed.
    fn prepare_fd_reservation_storage(&mut self, cloexec: bool) -> Result<(), ()> {
        let fd_additional = self
            .pending_fd_reservations()
            .ok_or(())?
            .checked_add(1)
            .ok_or(())?;
        self.fd_table
            .ensure_capacity_for(fd_additional)
            .map_err(|_| ())?;

        if cloexec {
            let cloexec_additional = self
                .pending_cloexec_reservations()
                .checked_add(1)
                .ok_or(())?;
            self.cloexec_fds
                .ensure_capacity_for(cloexec_additional)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    #[inline]
    fn remove_fd_entry_preserving_reservations(&mut self, fd: i32) -> Option<FileDescriptor> {
        if self.fd_reservations_charged_count == 0 {
            self.fd_table.remove(&fd)
        } else {
            self.fd_table.remove_retaining_capacity(&fd)
        }
    }

    #[inline]
    fn remove_cloexec_preserving_reservations(&mut self, fd: i32) -> bool {
        if self.pending_cloexec_reservations() == 0 {
            self.cloexec_fds.remove(&fd)
        } else {
            self.cloexec_fds.remove_retaining_capacity(&fd)
        }
    }

    /// R180-23: reserve an FD number and its hierarchical `files.max` charge
    /// before a VFS call is allowed to create or truncate anything. The fixed
    /// bitmap mutation is allocation-free and competing FD operations skip the
    /// number until commit or cancellation.
    pub fn reserve_fd(&mut self) -> Option<i32> {
        self.reserve_fd_with_cloexec(false)
    }

    /// Reserve an FD and, when requested, an admitted CLOEXEC publication slot
    /// before any VFS/socket/pipe side effect. Both insertions are allocation-
    /// free at commit, and cancellation releases the files.max credit exactly.
    pub fn reserve_fd_with_cloexec(&mut self, cloexec: bool) -> Option<i32> {
        self.reserve_fd_from_with_cloexec(3, cloexec)
    }

    /// F_DUPFD/F_DUPFD_CLOEXEC reservation: choose the lowest free descriptor
    /// at or above `min_fd`, including 0..2 when explicitly requested, while
    /// skipping every in-flight reservation bit.
    pub fn reserve_fd_from_with_cloexec(&mut self, min_fd: i32, cloexec: bool) -> Option<i32> {
        let fd = self.next_available_fd_from(min_fd)?;
        self.prepare_fd_reservation_storage(cloexec).ok()?;
        crate::cgroup::try_charge_fds(self.cgroup_id, 1).ok()?;
        let Some(next_reserved_count) = self.fd_reservations_charged_count.checked_add(1) else {
            crate::cgroup::uncharge_fds(self.cgroup_id, 1);
            return None;
        };
        if self.set_fd_reserved(fd, true) {
            panic!("R180-23: free-FD scan selected an already reserved slot");
        }
        if cloexec && self.set_fd_cloexec_reserved(fd, true) {
            panic!("R180-23: CLOEXEC reservation bit duplicated");
        }
        self.fd_reservations_charged_count = next_reserved_count;
        Some(fd)
    }

    /// Publish a descriptor into a previously reserved slot. This consumes the
    /// existing cgroup charge; no second files.max admission occurs.
    pub fn install_reserved_fd(
        &mut self,
        fd: i32,
        desc: FileDescriptor,
    ) -> Result<(), FileDescriptor> {
        assert!(
            self.fd_is_reserved(fd) && !self.fd_table.contains_key(&fd),
            "R180-23: invalid or occupied FD reservation at commit"
        );
        let next_reserved_count = self
            .fd_reservations_charged_count
            .checked_sub(1)
            .expect("R180-23: reservation charge underflow at commit");
        let next_installed_count = self
            .fds_charged_count
            .checked_add(1)
            .expect("R180-23: installed FD charge overflow at commit");

        let cloexec = self.fd_cloexec_is_reserved(fd);
        if let Err((_fd, _desc)) = self.fd_table.insert_unique_reserved(fd, desc) {
            // The reservation owns an exact map slot. A failure here is ledger
            // or local-state corruption after an irreversible VFS operation;
            // returning an ordinary error would violate R180-23 atomicity.
            panic!("R180-23: reserved FD backing/identity invariant failed at commit");
        }
        if cloexec {
            match self.cloexec_fds.insert_reserved(fd) {
                Ok(true) => {}
                Ok(false) => panic!("R180-23: stale CLOEXEC marker preceded FD publication"),
                Err(_) => panic!("R180-23: reserved CLOEXEC backing invariant failed at commit"),
            }
        }

        let was_reserved = self.set_fd_reserved(fd, false);
        assert!(
            was_reserved,
            "R180-23: committed FD lost its reservation bit"
        );
        let was_cloexec_reserved = self.set_fd_cloexec_reserved(fd, false);
        assert_eq!(was_cloexec_reserved, cloexec);
        self.fd_reservations_charged_count = next_reserved_count;
        self.fds_charged_count = next_installed_count;
        Ok(())
    }

    /// Cancel one reservation and return its files.max credit. Idempotent false
    /// on stale/mismatched tokens so a double-cancel cannot undercharge.
    pub fn cancel_fd_reservation(&mut self, fd: i32) -> bool {
        if !self.fd_is_reserved(fd) || self.fd_reservations_charged_count == 0 {
            return false;
        }
        if !self.set_fd_reserved(fd, false) {
            return false;
        }
        let _ = self.set_fd_cloexec_reserved(fd, false);
        self.fd_reservations_charged_count -= 1;
        crate::cgroup::uncharge_fds(self.cgroup_id, 1);
        if self.fd_reservations_charged_count == 0 {
            self.fd_table.reclaim_empty_capacity();
        }
        if self.pending_cloexec_reservations() == 0 {
            self.cloexec_fds.reclaim_empty_capacity();
        }
        true
    }

    /// Installed plus in-flight open charges. Cgroup migration must move both
    /// before changing `cgroup_id`, otherwise reservation Drop would uncharge a
    /// different hierarchy from the one originally charged.
    pub fn total_fd_charge_count(&self) -> u64 {
        self.fds_charged_count
            .checked_add(self.fd_reservations_charged_count)
            .expect("FD charge accounting overflow")
    }

    pub fn allocate_fd(&mut self, desc: FileDescriptor) -> Result<i32, FileDescriptor> {
        self.allocate_fd_with_cloexec(desc, false)
    }

    /// Allocate and atomically publish an FD plus its optional CLOEXEC marker.
    pub fn allocate_fd_with_cloexec(
        &mut self,
        desc: FileDescriptor,
        cloexec: bool,
    ) -> Result<i32, FileDescriptor> {
        self.allocate_fd_from_with_cloexec(desc, 3, cloexec)
    }

    /// Allocate from a Linux F_DUPFD lower bound with the same admitted table,
    /// files.max, rollback, and optional CLOEXEC transaction as ordinary open.
    pub fn allocate_fd_from_with_cloexec(
        &mut self,
        desc: FileDescriptor,
        min_fd: i32,
        cloexec: bool,
    ) -> Result<i32, FileDescriptor> {
        let Some(fd) = self.reserve_fd_from_with_cloexec(min_fd, cloexec) else {
            return Err(desc);
        };
        match self.install_reserved_fd(fd, desc) {
            Ok(()) => Ok(fd),
            Err(desc) => {
                let _ = self.cancel_fd_reservation(fd);
                Err(desc)
            }
        }
    }

    /// 获取指定 fd 对应的描述符引用
    pub fn get_fd(&self, fd: i32) -> Option<&FileDescriptor> {
        if fd < 0 || self.fd_is_reserved(fd) {
            return None;
        }
        self.fd_table.get(&fd)
    }

    /// 移除并返回指定 fd 的描述符
    ///
    /// 关闭文件描述符时使用，描述符的 Drop 会自动处理资源清理
    /// R39-4 FIX: 同时清除 CLOEXEC 标记
    pub fn remove_fd(&mut self, fd: i32) -> Option<FileDescriptor> {
        if fd < 0 || self.fd_is_reserved(fd) {
            return None;
        }
        self.remove_cloexec_preserving_reservations(fd);
        let removed = self.remove_fd_entry_preserving_reservations(fd);
        if removed.is_some() {
            // J2-7: every fd_table entry corresponds to exactly one charge (fds
            // 0/1/2 are virtual — allocate_fd starts at 3), so uncharge exactly 1.
            crate::cgroup::uncharge_fds(self.cgroup_id, 1);
            self.fds_charged_count = self.fds_charged_count.saturating_sub(1);
        }

        // U.S2-α FIX: Revoke CapId on close (refcounted; revoke only at 0).
        // U.S3-B FIX: use the generic `FileOps::cap_id()` accessor instead of a
        // `SocketFile` downcast, so EVERY cap-bearing fd kind (pipes/files in
        // U.S2 SLICE-3+) rides this same last-close revocation without touching
        // this function again. Non-bearing kinds return None (no-op).
        if let Some(ref desc) = removed {
            self.decrement_fd_cap(desc.as_ref());
        }

        removed
    }

    /// U.S3-B: decrement the CapEntry refcount carried by `desc` (if any) and
    /// revoke the capability at refcount→0 (last fd reference gone).
    ///
    /// This is THE single fd→cap teardown edge; every path that removes an fd
    /// from `fd_table` funnels here (`remove_fd`, `replace_fd_charged`
    /// displacement, `take_cloexec_fds_into` exec drain, and process-exit
    /// extraction in `free_process_resources`). Pairs with the explicit
    /// per-fd increments at the dup/F_DUPFD/CLONE_THREAD-install sites
    /// (U.S3-A3) and the allocate()-time refcount=1 (sys_socket/sys_accept).
    ///
    /// A failed decrement (InvalidCapId) is a NO-OP by design: a CLONE_THREAD
    /// sibling sharing this cap_table may have already driven the refcount to
    /// 0 and revoked (its last-close raced ours), or the cap was CLOFORK/
    /// CLOEXEC-revoked table-side while the fd lingered. The fd is then a
    /// documented dead-handle (ops fail EBADF-class) — never a double-revoke,
    /// because generation counters make revoke idempotent-safe.
    ///
    /// Lock context: called under the owning Process lock. CapTable's inner
    /// spinlock is a LEAF (without_interrupts + no callbacks), and revoke()
    /// only drops plain-data cap objects today (cap::Socket = ids;
    /// cap::Pipe/RegularFile = ids since U.S2-SLICE-3 — enforced by the
    /// CRITICAL-5 plain-data rule). CAUTION: if CapObject ever carries a Drop
    /// that re-locks (FileOps-like), the revoke must move outside the Process
    /// lock (R154-3/R169-4 class).
    pub(crate) fn decrement_fd_cap(&self, desc: &dyn FileOps) {
        if let Some(cap_id) = desc.cap_id() {
            let should_revoke = self.cap_table.decrement_refcount(cap_id).unwrap_or(false);
            if should_revoke {
                let _ = self.cap_table.revoke(cap_id);
            }
        }
    }

    /// R39-4 FIX: 设置或清除指定 fd 的 FD_CLOEXEC 标记
    ///
    /// # Arguments
    /// * `fd` - 文件描述符
    /// * `cloexec` - true 设置 CLOEXEC，false 清除
    pub fn set_fd_cloexec(&mut self, fd: i32, cloexec: bool) -> Result<(), ()> {
        if self.fd_is_reserved(fd) || !self.fd_table.contains_key(&fd) {
            return Err(());
        }
        if cloexec {
            if self.cloexec_fds.contains(&fd) {
                return Ok(());
            }
            // Do not consume capacity promised to an in-flight O_CLOEXEC open.
            let additional = self
                .pending_cloexec_reservations()
                .checked_add(1)
                .ok_or(())?;
            self.cloexec_fds
                .ensure_capacity_for(additional)
                .map_err(|_| ())?;
            match self.cloexec_fds.insert_reserved(fd) {
                Ok(true) => {}
                Ok(false) => panic!("CLOEXEC marker appeared during locked publication"),
                Err(_) => panic!("prepared CLOEXEC capacity disappeared during publication"),
            }
        } else {
            self.remove_cloexec_preserving_reservations(fd);
        }
        Ok(())
    }

    /// R39-4 FIX: 在 exec 期间关闭所有带 FD_CLOEXEC 的文件描述符
    ///
    /// SECURITY: 防止敏感句柄（如设备、管道）泄漏到 exec 后的新程序。
    /// 这是 POSIX close-on-exec 语义的实现。
    ///
    /// # R169-4 FIX (HIGH, lock inversion): drop CLOEXEC FDs OUTSIDE the lock
    ///
    /// This runs with the Process lock held. The previous version dropped each
    /// removed `FileDescriptor` INLINE (`fd_table.remove(&fd).is_some()`), so a
    /// `SocketFile`'s `Drop` ran under the Process lock → socket `close` →
    /// `wake_all` (re-locks PROCESS_TABLE + a foreign `Process::inner`) and
    /// `uncharge_port_cgroup` (L5 `CGROUP_REGISTRY`). That is exactly the
    /// Process→foreign-PCB lock inversion (R154-3/R155-3) that
    /// `replace_fd_charged` was written to avoid, plus an L5-under-Process-lock
    /// acquire (D1-CGROUP-IRQ-L5). Two concurrent execs each closing a socket
    /// that wakes the other could ABBA-deadlock.
    ///
    /// Drains the close-on-exec descriptors into the caller-provided `removed`
    /// buffer and returns the closed count. The CALLER MUST have pre-reserved
    /// `removed` to at least the current `cloexec_fds.len()` (the exec caller
    /// snapshots that count under this same lock hold, before any irreversible
    /// exec mutation, and fails with ENOMEM if the reservation fails). Because
    /// capacity is guaranteed and FD state is per-process (never Arc-shared,
    /// even under `CLONE_FILES`) so nothing adds cloexec marks in between, every
    /// `push` here is infallible and **no `FileDescriptor` is ever dropped
    /// inline under the Process lock** — fully eliminating the lock-inversion
    /// class for the cloexec-on-exec path, with no fatal-OOM residual.
    ///
    /// The `fds_charged_count` decrement is a Process-local field and stays
    /// under the lock; the caller performs the L5 `uncharge_fds` and the actual
    /// descriptor drops AFTER releasing the Process lock. The `cloexec_fds` set
    /// is taken out with `mem::take` (which clears it and lets us iterate it
    /// while mutating `fd_table`), replacing the prior infallible `.collect()`.
    #[must_use = "the returned closed count must be uncharged from the per-cgroup \
                  FD budget (L5) OUTSIDE the Process lock (R169-4)"]
    pub fn take_cloexec_fds_into(&mut self, removed: &mut Vec<FileDescriptor>) -> u64 {
        let cloexec = core::mem::replace(
            &mut self.cloexec_fds,
            AdmittedSet::new(HeapClass::CoreProcess),
        );
        debug_assert!(
            removed.capacity().saturating_sub(removed.len()) >= cloexec.len(),
            "take_cloexec_fds_into: caller under-reserved the cloexec drop buffer"
        );
        let mut closed: u64 = 0;
        for fd in cloexec.iter().copied() {
            if let Some(desc) = self.remove_fd_entry_preserving_reservations(fd) {
                // Stale cloexec entries for already-closed fds contribute 0
                // (remove() == None), so the uncharge count stays exact.
                closed += 1;
                // U.S3-B FIX: decrement the removed fd's cap (revoke at 0).
                // Without this, an fd marked close-on-exec via F_SETFD *after*
                // creation (so its CapEntry never carried CapFlags::CLOEXEC)
                // leaked its refcount at exec — the cap outlived every fd and
                // the slot was permanently lost (TableFull DoS class, since the
                // cap_table SURVIVES exec). Safe under the Process lock: leaf
                // spinlock, plain-data drop (see decrement_fd_cap).
                self.decrement_fd_cap(desc.as_ref());
                // Infallible: the caller pre-reserved enough capacity, so this
                // never reallocates and never drops `desc` inline under the lock.
                removed.push(desc);
            }
        }
        if closed > 0 {
            self.fds_charged_count = self.fds_charged_count.saturating_sub(closed);
        }
        if self.fd_reservations_charged_count == 0 {
            self.fd_table.reclaim_empty_capacity();
        }
        closed
    }

    /// J2-7: Install `desc` at a caller-chosen `fd` (dup2/dup3 semantics),
    /// replacing any existing entry, with NET-AWARE, FAIL-CLOSED per-cgroup FD
    /// accounting:
    /// - Empty slot → net +1: charge the budget BEFORE mutating; on over-budget
    ///   return `Err(())` (caller surfaces EMFILE) leaving the table UNCHANGED.
    /// - Occupied slot → net 0: the replaced entry's existing charge is reused,
    ///   so no charge/uncharge occurs and the operation can never fail on budget.
    ///
    /// Returns the displaced `FileDescriptor` (if any) so the caller can drop it
    /// OUTSIDE the Process lock (R155-3: socket destructors re-lock other PCBs).
    /// CLOEXEC on the target fd is cleared (the dup copy is not close-on-exec
    /// unless dup3's O_CLOEXEC sets it afterwards).
    pub fn replace_fd_charged(
        &mut self,
        fd: i32,
        desc: FileDescriptor,
    ) -> Result<Option<FileDescriptor>, FileDescriptor> {
        self.replace_fd_charged_with_cloexec(fd, desc, false)
    }

    /// Net-aware dup2/dup3 publication with optional atomic CLOEXEC marking.
    /// Every allocation is prepared before the old descriptor is displaced.
    pub fn replace_fd_charged_with_cloexec(
        &mut self,
        fd: i32,
        desc: FileDescriptor,
        cloexec: bool,
    ) -> Result<Option<FileDescriptor>, FileDescriptor> {
        if !(0..MAX_FD).contains(&fd) || self.fd_is_reserved(fd) {
            return Err(desc);
        }
        let occupied = self.fd_table.contains_key(&fd);
        let had_cloexec = self.cloexec_fds.contains(&fd);
        if !occupied {
            // Net +1 — charge fail-closed BEFORE any mutation.
            let Some(additional) = self
                .pending_fd_reservations()
                .and_then(|pending| pending.checked_add(1))
            else {
                return Err(desc);
            };
            if self.fd_table.ensure_capacity_for(additional).is_err() {
                return Err(desc);
            }
            if crate::cgroup::try_charge_fds(self.cgroup_id, 1).is_err() {
                return Err(desc);
            }
        }
        if cloexec && !had_cloexec {
            let Some(additional) = self.pending_cloexec_reservations().checked_add(1) else {
                if !occupied {
                    crate::cgroup::uncharge_fds(self.cgroup_id, 1);
                }
                return Err(desc);
            };
            if self.cloexec_fds.ensure_capacity_for(additional).is_err() {
                if !occupied {
                    crate::cgroup::uncharge_fds(self.cgroup_id, 1);
                }
                return Err(desc);
            }
        }
        // Occupied → insert returns the old entry (its charge is reused, count
        // unchanged); empty → returns None.
        let displaced = if occupied {
            self.fd_table
                .try_insert(fd, desc)
                .unwrap_or_else(|_| panic!("occupied FD replacement attempted allocation"))
        } else {
            match self.fd_table.insert_unique_reserved(fd, desc) {
                Ok(()) => {
                    self.fds_charged_count = self
                        .fds_charged_count
                        .checked_add(1)
                        .expect("installed FD charge count overflow");
                    None
                }
                Err((_fd, desc)) => {
                    crate::cgroup::uncharge_fds(self.cgroup_id, 1);
                    return Err(desc);
                }
            }
        };
        if cloexec {
            if !had_cloexec {
                match self.cloexec_fds.insert_reserved(fd) {
                    Ok(true) => {}
                    Ok(false) => panic!("dup CLOEXEC marker appeared without publication"),
                    Err(_) => panic!("prepared dup CLOEXEC slot disappeared during publication"),
                }
            }
        } else {
            self.remove_cloexec_preserving_reservations(fd);
        }
        // U.S3-B FIX: the DISPLACED entry leaves fd_table here without passing
        // through remove_fd, so its cap refcount must be decremented (revoke at
        // 0) or every dup2/dup3 onto an occupied cap-bearing fd leaks a slot
        // (TableFull DoS class). The displaced Box itself is still returned to
        // the caller to DROP outside the Process lock (R155-3) — only the leaf
        // cap accounting happens here.
        if let Some(ref old) = displaced {
            self.decrement_fd_cap(old.as_ref());
        }
        Ok(displaced)
    }

    /// 查找下一个可用的 fd（从 3 开始）
    fn next_available_fd_from(&self, min_fd: i32) -> Option<i32> {
        // 从 3 开始，因为 0/1/2 保留给标准流
        if !(0..MAX_FD).contains(&min_fd) {
            return None;
        }
        let mut fd = min_fd;
        while fd < MAX_FD {
            if !self.fd_table.contains_key(&fd) && !self.fd_is_reserved(fd) {
                return Some(fd);
            }
            fd = fd.checked_add(1)?;
        }
        None // 已达到 fd 上限
    }

    /// 重置时间片
    ///
    /// F.2: Now factors in cgroup cpu_weight for resource governance.
    pub fn reset_time_slice(&mut self) {
        self.time_slice = calculate_time_slice_with_cgroup(self.dynamic_priority, self.cgroup_id);
    }

    // ========================================================================
    // E.4 Priority Inheritance (PI) Methods
    // ========================================================================

    /// E.4 PI: 重新计算包含 PI 的有效优先级
    ///
    /// `dynamic_priority` = min(base_dynamic_priority, min(all pi_boosts))
    /// Returns true if the effective priority changed.
    ///
    /// F.2: Now factors in cgroup cpu_weight when recalculating time slice.
    pub fn recompute_effective_priority(&mut self) -> bool {
        let inherited = self.pi_boosts.values().min().copied();
        let base = self.base_dynamic_priority;
        let effective = inherited.map_or(base, |p| core::cmp::min(p, base));
        if effective != self.dynamic_priority {
            self.dynamic_priority = effective;
            self.time_slice =
                calculate_time_slice_with_cgroup(self.dynamic_priority, self.cgroup_id);
            true
        } else {
            false
        }
    }

    /// E.4 PI: Get the current effective priority (read-only accessor).
    ///
    /// Returns the current `dynamic_priority`, which is the effective priority
    /// after considering both base priority and any active PI boosts.
    /// This is the priority used by the scheduler for task selection.
    pub fn effective_priority(&self) -> Priority {
        self.dynamic_priority
    }

    /// RF178-8: reserve the allocation needed if this waiter later inherits
    /// `key` during robust-owner exit or normal PI unlock.
    ///
    /// The caller holds this PCB lock across the reservation publication. Every
    /// unrelated boost insertion preserves one additional spare while this key
    /// is reserved, so the capacity cannot be stolen before handoff.
    pub fn try_reserve_pi_boost(&mut self, key: FutexKey) -> Result<(), ()> {
        match self.pi_boost_reservation {
            Some(existing) if existing == key => return Ok(()),
            Some(_) => return Err(()),
            None => {}
        }
        if self.pi_boosts.contains_key(&key) {
            return Ok(());
        }
        self.pi_boosts.try_reserve(1).map_err(|_| ())?;
        self.pi_boost_reservation = Some(key);
        Ok(())
    }

    /// RF178-8: release an unused handoff reservation. Capacity is retained;
    /// this operation never allocates or deallocates.
    pub fn cancel_pi_boost_reservation(&mut self, key: &FutexKey) {
        if self.pi_boost_reservation.as_ref() == Some(key) {
            self.pi_boost_reservation = None;
        }
    }

    /// RF178-8: set or clear one keyed PI donation with fallible growth.
    ///
    /// Replacements/removals are allocation-free. A new key either consumes
    /// its pre-reserved handoff slot or reserves enough room for the insertion
    /// *and* any other outstanding handoff reservation before mutation.
    pub fn try_update_pi_boost(
        &mut self,
        key: FutexKey,
        donated: Option<Priority>,
    ) -> Result<bool, ()> {
        match donated {
            Some(priority) => {
                if let Some(existing) = self.pi_boosts.get_mut(&key) {
                    if *existing == priority {
                        return Ok(false);
                    }
                    *existing = priority;
                    return Ok(self.recompute_effective_priority());
                }

                let consumes_reservation = self.pi_boost_reservation == Some(key);
                if !consumes_reservation {
                    // Preserve a different waiter's reserved slot. All boost
                    // insertions pass through this method, so it cannot be stolen.
                    let additional = 1 + usize::from(self.pi_boost_reservation.is_some());
                    self.pi_boosts.try_reserve(additional).map_err(|_| ())?;
                }
                self.pi_boosts.try_insert(key, priority).map_err(|_| ())?;
                if consumes_reservation {
                    self.pi_boost_reservation = None;
                }
                Ok(self.recompute_effective_priority())
            }
            None => {
                self.cancel_pi_boost_reservation(&key);
                if self.pi_boosts.remove(&key).is_some() {
                    Ok(self.recompute_effective_priority())
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// E.4 PI: 记录 / 清除当前等待的 futex（用于链式 PI）
    pub fn set_waiting_on_futex(&mut self, key: Option<FutexKey>) {
        self.waiting_on_futex = key;
    }

    /// E.4 PI: 获取当前等待的 futex key（用于链式 PI）
    pub fn get_waiting_on_futex(&self) -> Option<FutexKey> {
        self.waiting_on_futex
    }

    // ========================================================================
    // Standard Priority Methods (updated for PI awareness)
    // ========================================================================

    /// 更新动态优先级（用于公平调度）
    ///
    /// E.4 PI: Now operates on base_dynamic_priority and recomputes effective.
    pub fn update_dynamic_priority(&mut self) {
        // 简单的优先级提升策略
        if self.base_dynamic_priority > 0 {
            self.base_dynamic_priority -= 1;
            self.recompute_effective_priority();
        }
    }

    /// 降低动态优先级（惩罚CPU密集型进程）
    ///
    /// E.4 PI: Now operates on base_dynamic_priority and recomputes effective.
    pub fn decrease_dynamic_priority(&mut self) {
        if self.base_dynamic_priority < 139 {
            self.base_dynamic_priority += 1;
            self.recompute_effective_priority();
        }
    }

    /// R65-19 FIX: 饥饿防止 - 提升长时间等待进程的优先级
    ///
    /// 每次调度器tick时，对所有就绪但未运行的进程增加wait_ticks。
    /// 当wait_ticks超过阈值(STARVATION_THRESHOLD)时，提升动态优先级。
    ///
    /// # 算法
    ///
    /// - 每STARVATION_THRESHOLD个tick提升1级优先级
    /// - 最多提升到静态优先级（不会超过原始优先级）
    /// - 提升后重置wait_ticks，开始新的等待周期
    ///
    /// # 防饥饿保证
    ///
    /// 即使低优先级进程被高优先级进程持续抢占，经过足够长的等待时间后，
    /// 其优先级会被逐渐提升直到获得运行机会。
    ///
    /// # R66-4 FIX: Priority Boost Cap
    ///
    /// Previously, dynamic_priority could be boosted below static priority,
    /// allowing low-priority processes to gain higher priority than intended.
    /// Now capped at static priority to prevent priority inversion abuse.
    ///
    /// # E.4 PI: Updated for priority inheritance
    ///
    /// Now operates on base_dynamic_priority and recomputes effective priority.
    pub fn check_and_boost_starved(&mut self) {
        // RF178-33 FIX: A sparse bounded scheduler scan can observe several
        // starvation periods at once. Fold the quotient into every available
        // boost and retain the exact sub-threshold remainder. Complete periods
        // are consumed even at the static-priority floor, matching the original
        // one-period reset policy without scan-frequency dependence.
        let periods = self.wait_ticks / STARVATION_THRESHOLD;
        if periods == 0 {
            return;
        }
        let available = self.base_dynamic_priority.saturating_sub(self.priority) as u64;
        let boosts = periods.min(available);
        if boosts != 0 {
            self.base_dynamic_priority = self
                .base_dynamic_priority
                .saturating_sub(boosts.min(u8::MAX as u64) as u8);
            self.recompute_effective_priority();
        }
        self.wait_ticks %= STARVATION_THRESHOLD;
    }

    /// RF178-33 FIX: Start a fresh Ready residence epoch.
    ///
    /// A Ready-to-Ready queue move preserves credit. `stopped` and `on_cpu`
    /// are part of runnable readiness, so resuming a Ready-but-stopped task or
    /// preempting a Ready-marked on-CPU task starts a new epoch as well.
    #[inline]
    pub fn enter_ready_at(&mut self, now_tick: u64) {
        let starts_new_epoch = self.state != ProcessState::Ready
            || self.stopped
            || self.on_cpu.load(Ordering::Acquire);
        self.state = ProcessState::Ready;
        if starts_new_epoch {
            self.wait_ticks = 0;
            self.wait_age_tick = now_tick;
        }
    }

    /// RF178-33 FIX: Publish newly-created or explicitly re-enqueued work.
    /// Constructor/fork preparation time is not scheduler queue residence.
    #[inline]
    pub fn publish_ready_at(&mut self, now_tick: u64) {
        self.state = ProcessState::Ready;
        self.wait_ticks = 0;
        self.wait_age_tick = now_tick;
    }

    /// RF178-33 FIX: Mark a task Running and stop Ready-wait accounting.
    #[inline]
    pub fn enter_running_at(&mut self, now_tick: u64) {
        self.state = ProcessState::Running;
        self.wait_ticks = 0;
        self.wait_age_tick = now_tick;
    }

    /// RF178-33 FIX: Mark a task blocked and exclude the blocked interval.
    #[inline]
    pub fn enter_blocked_at(&mut self, now_tick: u64) {
        self.state = ProcessState::Blocked;
        self.wait_ticks = 0;
        self.wait_age_tick = now_tick;
    }

    /// RF178-33 FIX: Mark a task stopped and exclude the stopped interval.
    #[inline]
    pub fn enter_stopped_at(&mut self, now_tick: u64) {
        self.state = ProcessState::Stopped;
        self.stopped = true;
        self.wait_ticks = 0;
        self.wait_age_tick = now_tick;
    }

    /// R65-19 FIX: 重置等待时间（进程被调度运行时调用）
    #[inline]
    pub fn reset_wait_ticks(&mut self) {
        self.wait_ticks = 0;
        self.wait_age_tick = crate::get_ticks();
    }

    /// R65-19 FIX: 增加等待时间（调度器tick时调用）
    #[inline]
    pub fn age_wait_ticks_to(&mut self, now_tick: u64) {
        // RF178-33 FIX: Only genuine off-CPU Ready residence earns aging
        // credit. Lifecycle edges re-anchor wait_age_tick, so returning here
        // cannot cause Running, Blocked, or Stopped time to be folded later.
        if self.state != ProcessState::Ready || self.stopped || self.on_cpu.load(Ordering::Acquire)
        {
            return;
        }
        let elapsed = now_tick.saturating_sub(self.wait_age_tick);
        self.wait_ticks = self.wait_ticks.saturating_add(elapsed);
        self.wait_age_tick = now_tick;
    }

    /// 恢复静态优先级
    ///
    /// E.4 PI: Now resets base_dynamic_priority and recomputes effective priority.
    pub fn restore_static_priority(&mut self) {
        self.base_dynamic_priority = self.priority;
        self.recompute_effective_priority();
    }

    /// U.S2-3B FIX: Read current credential generation counter for LSM TOCTOU
    /// defense. Incremented on every credential mutation (setuid/setgid/setgroups).
    #[inline]
    pub fn cred_generation(&self) -> u64 {
        self.credentials.generation()
    }

    /// Try to read credentials without exposing a writable credential lock to
    /// callers or yielding while the caller holds this PCB lock.
    ///
    /// R186 review-fix: mutation is intentionally confined to this module's
    /// generation-publishing transaction, so no caller can change credentials
    /// while bypassing the shared generation counter.
    #[inline]
    pub fn try_credentials_read(&self) -> Option<CredentialReadGuard<'_>> {
        self.credentials.try_read()
    }

    /// Clone the shared credential identity for a transaction that must keep a
    /// read guard alive independently of a mutable `Process` borrow.
    #[inline]
    pub fn shared_credentials(&self) -> Arc<SharedCredentials> {
        Arc::clone(&self.credentials)
    }

    /// Bind an owned authorization token to this exact PCB credential identity.
    #[inline]
    pub fn credentials_match_authorization(&self, authorization: &CredentialAuthorization) -> bool {
        authorization.matches(&self.credentials)
    }

    /// Install the exact credential identity selected by clone/fork preparation
    /// before the child is schedulable.
    #[inline]
    pub(crate) fn install_shared_credentials_for_clone(
        &mut self,
        credentials: Arc<SharedCredentials>,
    ) {
        assert_eq!(
            self.state,
            ProcessState::Provisioning,
            "credential identity may only be installed on a provisioning child"
        );
        assert_eq!(
            self.credentials.generation(),
            0,
            "provisioning child credential identity was already mutated"
        );
        self.credentials = credentials;
    }

    /// Read-only capability-table observability for boot diagnostics.
    #[inline]
    pub fn capability_count(&self) -> usize {
        self.cap_table.len()
    }

    /// Opaque cloneable authority for this exact capability table. Cross-crate
    /// brokers may carry it, but cannot dereference it or invoke raw mint APIs.
    pub fn capability_table_authority(&self) -> CapabilityTableAuthority {
        CapabilityTableAuthority {
            table: Arc::clone(&self.cap_table),
        }
    }

    /// Identity-bound, LSM-mediated two-phase mint broker. Raw production-table
    /// access never leaves this module; callers receive only an opaque prepared
    /// grant whose authorization token remains live through publication/audit.
    pub fn prepare_capability_allocation_authorized<'a>(
        &self,
        authority: &'a CapabilityTableAuthority,
        authorization: CredentialAuthorization,
    ) -> Result<crate::syscall::AuthorizedCapReservation<'a>, SyscallError> {
        if !self.credentials_match_authorization(&authorization)
            || !Arc::ptr_eq(&self.cap_table, &authority.table)
        {
            return Err(SyscallError::EPERM);
        }
        let credentials = authorization.read();
        let proc_ctx = LsmProcessCtx::new(
            self.pid,
            self.tgid,
            credentials.uid,
            credentials.gid,
            credentials.euid,
            credentials.egid,
        );
        lsm::hook_task_cap_modify(&proc_ctx, cap::CapId::INVALID, lsm::cap_op::ALLOCATE)
            .map_err(|_| SyscallError::EPERM)?;
        let capability = authority
            .table
            .prepare_allocation()
            .map_err(crate::syscall::cap_error_to_syscall)?;
        drop(credentials);
        Ok(crate::syscall::AuthorizedCapReservation::new(
            capability,
            proc_ctx,
            authorization,
        ))
    }

    #[inline]
    pub(crate) fn capability_table_is_shared(&self) -> bool {
        Arc::strong_count(&self.cap_table) > 1
    }

    pub(crate) fn try_clone_capability_table_for_fork(
        &self,
        reconciled_refcounts: Option<&[(cap::CapId, usize)]>,
    ) -> Result<CapabilityTableInheritance, ()> {
        let mut table = self.cap_table.try_clone_for_fork()?;
        if let Some(refcounts) = reconciled_refcounts {
            table.reconcile_refcounts_after_fork(refcounts);
        }
        let table = Arc::try_new(table).map_err(|_| ())?;
        Ok(CapabilityTableInheritance { table })
    }

    #[inline]
    pub(crate) fn share_capability_table(&self) -> CapabilityTableInheritance {
        CapabilityTableInheritance {
            table: Arc::clone(&self.cap_table),
        }
    }

    #[inline]
    pub(crate) fn install_capability_table(&mut self, inheritance: CapabilityTableInheritance) {
        self.cap_table = inheritance.table;
    }

    #[inline]
    pub(crate) fn capability_increment_refcount(&self, cap_id: cap::CapId) {
        let _ = self.cap_table.increment_refcount(cap_id);
    }

    #[inline]
    pub(crate) fn capability_lookup(
        &self,
        cap_id: cap::CapId,
    ) -> Result<cap::CapEntry, cap::CapError> {
        self.cap_table.lookup(cap_id)
    }

    #[inline]
    pub(crate) fn apply_capability_cloexec(&mut self) {
        self.cap_table.apply_cloexec();
    }

    /// Adopt accounting for a freshly loaded boot image into an unscheduled PCB.
    ///
    /// `load_elf` has already hard-charged the image data to this process's
    /// cgroup (the boot caller passes cgroup 0). Intermediate page-table frames
    /// are knowable only after mapping, so they receive the same forced kmem
    /// charge and provenance fold used by the normal exec success transaction.
    ///
    /// # Contract
    ///
    /// The process must be unscheduled, own a fresh nonzero address space, and
    /// have no prior image accounting. No fallible operation may follow this
    /// commit before the setup receipt is disarmed; its rollback path routes
    /// through `free_process_resources`, which releases both accounting lanes.
    pub fn commit_boot_loaded_image_accounting(
        &mut self,
        load_result: &crate::elf_loader::ElfLoadResult,
    ) {
        assert_ne!(
            self.memory_space, 0,
            "boot image requires an owned address space"
        );
        let mut mm = self.mm.lock();
        assert_eq!(
            mm.elf_charged_bytes, 0,
            "boot image accounting committed twice"
        );
        assert_eq!(mm.pt_charged_bytes, 0, "boot PT accounting committed twice");

        let pt_bytes = (load_result.pt_frames.len() as u64).saturating_mul(0x1000);
        if pt_bytes > 0 {
            crate::cgroup::charge_memory_forced(self.cgroup_id, pt_bytes);
            mm.record_pt_charge(&load_result.pt_frames);
        }
        mm.elf_charged_bytes = load_result.charged_bytes;
        mm.stack_floor_committed = crate::elf_loader::user_stack_mapped_floor() as usize;
        mm.brk_start = load_result.brk_start;
        mm.brk = load_result.brk_start;
    }

    /// Check a VFS authorization snapshot. Operation-spanning callers already
    /// own a `CredentialAuthorization`, so reopening reader admission here can
    /// deadlock behind a queued writer and is unnecessary.
    #[inline]
    pub fn cred_generation_is_current(&self, expected: u64) -> bool {
        self.credentials.generation() == expected
    }
}

/// RF178-33 executable probe for scheduler wait-lifecycle accounting.
///
/// Uses injected ticks so a green boot cannot hide epoch drift behind timing.
pub fn run_ready_aging_self_test() {
    let mut proc = Process::new(0x17_833, 1, String::from("rf178-33-aging"), 100);

    proc.enter_running_at(10);
    proc.wait_ticks = 77;
    proc.wait_age_tick = 10;
    proc.enter_ready_at(100);
    assert_eq!(proc.state, ProcessState::Ready);
    assert_eq!((proc.wait_ticks, proc.wait_age_tick), (0, 100));

    proc.age_wait_ticks_to(150);
    assert_eq!(proc.wait_ticks, 50);
    proc.age_wait_ticks_to(150);
    assert_eq!(proc.wait_ticks, 50, "same-tick aging must be idempotent");

    // A Ready-to-Ready move is migration/rebucketing, not a new wait epoch.
    proc.enter_ready_at(175);
    assert_eq!((proc.wait_ticks, proc.wait_age_tick), (50, 150));

    proc.enter_running_at(200);
    proc.age_wait_ticks_to(250);
    assert_eq!((proc.wait_ticks, proc.wait_age_tick), (0, 200));

    proc.enter_blocked_at(300);
    proc.age_wait_ticks_to(450);
    assert_eq!((proc.wait_ticks, proc.wait_age_tick), (0, 300));
    proc.enter_ready_at(450);
    proc.age_wait_ticks_to(475);
    assert_eq!(
        proc.wait_ticks, 25,
        "blocked time must not become Ready wait"
    );

    proc.enter_ready_at(500);
    proc.stopped = true;
    proc.wait_ticks = 19;
    proc.wait_age_tick = 500;
    proc.age_wait_ticks_to(600);
    assert_eq!(
        proc.wait_ticks, 19,
        "stopped time must not earn aging credit"
    );
    proc.enter_ready_at(600);
    proc.stopped = false;
    proc.age_wait_ticks_to(625);
    assert_eq!(proc.wait_ticks, 25);

    proc.enter_ready_at(700);
    proc.wait_ticks = 11;
    proc.wait_age_tick = 700;
    proc.on_cpu.store(true, Ordering::Release);
    proc.age_wait_ticks_to(800);
    assert_eq!(
        proc.wait_ticks, 11,
        "Ready+on_cpu must not earn wait credit"
    );
    proc.enter_ready_at(800);
    proc.on_cpu.store(false, Ordering::Release);
    proc.age_wait_ticks_to(825);
    assert_eq!(proc.wait_ticks, 25);

    // Sparse scans fold every complete period and keep the exact remainder.
    proc.priority = 100;
    proc.base_dynamic_priority = 110;
    proc.dynamic_priority = 110;
    proc.wait_ticks = 250;
    proc.check_and_boost_starved();
    assert_eq!(proc.base_dynamic_priority, 108);
    assert_eq!(proc.dynamic_priority, 108);
    assert_eq!(proc.wait_ticks, 50);

    // Complete periods are consumed at the policy floor; only the remainder
    // survives, exactly as repeated one-period checks would produce.
    proc.base_dynamic_priority = proc.priority;
    proc.dynamic_priority = proc.priority;
    proc.wait_ticks = 250;
    proc.check_and_boost_starved();
    assert_eq!(proc.wait_ticks, 50);

    // Limited headroom still consumes the full quotient, not merely the one
    // period that could alter priority.
    proc.base_dynamic_priority = proc.priority + 1;
    proc.dynamic_priority = proc.priority + 1;
    proc.wait_ticks = 250;
    proc.check_and_boost_starved();
    assert_eq!(proc.base_dynamic_priority, proc.priority);
    assert_eq!(proc.wait_ticks, 50);
}

/// R180-23 executable probe: a migration snapshot must include FD charges
/// owned by in-flight open reservations as well as installed descriptors.
pub fn run_fd_charge_migration_self_test() {
    let mut proc = Process::new(0x180_2301, 1, String::from("r180-23-fd-migration"), 120);
    proc.fds_charged_count = 3;
    proc.fd_reservations_charged_count = 2;
    assert_eq!(
        proc.total_fd_charge_count(),
        5,
        "migration must transfer installed and reserved FD charges"
    );
    proc.fd_reservations_charged_count = 0;
    assert_eq!(proc.total_fd_charge_count(), 3);

    // F_DUPFD lower-bound scans include 0..2 when explicitly requested and
    // never collide with an in-flight open reservation.
    assert_eq!(proc.next_available_fd_from(0), Some(0));
    assert!(!proc.set_fd_reserved(4, true));
    assert_eq!(proc.next_available_fd_from(4), Some(5));
    assert!(proc.set_fd_reserved(4, false));
    assert_eq!(proc.next_available_fd_from(4), Some(4));
    assert_eq!(proc.next_available_fd_from(MAX_FD), None);
}

/// Public task-name bound used by fork/clone snapshots.
pub const PROCESS_NAME_MAX: usize = 256;

/// Heap-free name snapshot. User-triggered fork/clone builds this while the
/// parent PCB is locked, then the PCB constructor admits and allocates String
/// storage after all process-creation reservations are in place.
#[derive(Clone, Copy)]
pub struct ProcessNameSnapshot {
    bytes: [u8; PROCESS_NAME_MAX],
    len: usize,
}

impl ProcessNameSnapshot {
    pub fn from_parts(base: &str, suffix: &str) -> Self {
        let mut bytes = [0u8; PROCESS_NAME_MAX];
        let mut suffix_len = suffix.len().min(PROCESS_NAME_MAX);
        while !suffix.is_char_boundary(suffix_len) {
            suffix_len -= 1;
        }
        let mut base_len = base.len().min(PROCESS_NAME_MAX - suffix_len);
        while !base.is_char_boundary(base_len) {
            base_len -= 1;
        }
        bytes[..base_len].copy_from_slice(&base.as_bytes()[..base_len]);
        bytes[base_len..base_len + suffix_len].copy_from_slice(&suffix.as_bytes()[..suffix_len]);
        Self {
            bytes,
            len: base_len + suffix_len,
        }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len])
            .expect("ProcessNameSnapshot is copied only at UTF-8 boundaries")
    }

    pub fn from_sanitized_ascii(bytes: &[u8]) -> Self {
        let mut snapshot = Self {
            bytes: [0u8; PROCESS_NAME_MAX],
            len: bytes.len().min(PROCESS_NAME_MAX),
        };
        for (dst, &src) in snapshot.bytes[..snapshot.len].iter_mut().zip(bytes.iter()) {
            *dst = if (0x20..0x7f).contains(&src) {
                src
            } else {
                b'?'
            };
        }
        snapshot
    }
}

pub struct PreparedProcessName {
    name: String,
    reservation: HeapReservation,
}

impl PreparedProcessName {
    pub fn try_new(snapshot: ProcessNameSnapshot) -> Result<Self, ProcessCreateError> {
        let estimated = vec_charge_bytes::<u8>(snapshot.as_str().len())
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let mut reservation = try_reserve_heap(HeapClass::CoreProcess, estimated)
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        let mut name = String::new();
        name.try_reserve_exact(snapshot.as_str().len())
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        reservation
            .resize(
                vec_charge_bytes::<u8>(name.capacity())
                    .map_err(|_| ProcessCreateError::OutOfMemory)?,
            )
            .map_err(|_| ProcessCreateError::OutOfMemory)?;
        name.push_str(snapshot.as_str());
        Ok(Self { name, reservation })
    }
}

pub trait IntoProcessNameSnapshot {
    fn into_process_name_snapshot(self) -> ProcessNameSnapshot;
}

impl IntoProcessNameSnapshot for ProcessNameSnapshot {
    fn into_process_name_snapshot(self) -> ProcessNameSnapshot {
        self
    }
}

impl IntoProcessNameSnapshot for String {
    fn into_process_name_snapshot(self) -> ProcessNameSnapshot {
        ProcessNameSnapshot::from_parts(&self, "")
    }
}

impl IntoProcessNameSnapshot for &str {
    fn into_process_name_snapshot(self) -> ProcessNameSnapshot {
        ProcessNameSnapshot::from_parts(self, "")
    }
}

/// 根据优先级计算时间片（毫秒）
fn calculate_time_slice(priority: Priority) -> u32 {
    // 优先级越高，时间片越长
    // 优先级0-99: 100-200ms
    // 优先级100-139: 10-100ms
    if priority < 100 {
        200 - priority as u32
    } else {
        140 - priority as u32
    }
}

/// F.2: 根据优先级和 cgroup cpu_weight 计算时间片
///
/// Scales base time slice by cgroup weight:
/// - weight=100 (default): no change
/// - weight=200: 2x time slice (more CPU time)
/// - weight=50: 0.5x time slice (less CPU time)
///
/// Clamps result to [1, 300]ms.
fn calculate_time_slice_with_cgroup(priority: Priority, cgroup_id: crate::cgroup::CgroupId) -> u32 {
    let base = calculate_time_slice(priority);
    let weight = crate::cgroup::get_effective_cpu_weight(cgroup_id);

    // Scale: new_slice = base * weight / 100
    // Use u64 to avoid overflow during multiplication
    let scaled = (base as u64 * weight as u64) / 100;

    // RF178-33: keep the final, weight-scaled slice above the IRQ-scan cadence floor.
    // Upper bound reduced from 1000ms to 300ms to prevent excessive starvation
    // of peer cgroups when high weights (e.g., 10000) are configured.
    scaled.clamp(1, 300) as u32
}

/// 全局进程表
///
/// 使用 Option<Arc<Mutex<Process>>> 以支持 PID 作为直接索引。
/// 索引 0 保留为空（PID 从 1 开始），实际进程存储在其 PID 对应的索引位置。
lazy_static::lazy_static! {
pub static ref PROCESS_TABLE: Mutex<AdmittedVec<Option<ProcessArc>>> =
        Mutex::new(AdmittedVec::new(HeapClass::CoreProcess));
    static ref SCHEDULER_CLEANUP: Mutex<Option<SchedulerCleanupCallback>> = Mutex::new(None);
    static ref IPC_CLEANUP: Mutex<Option<IpcCleanupCallback>> = Mutex::new(None);
    /// R180-19: scheduler admission is registered as one atomic callback set so
    /// a permit can never be born without matching commit/cancel operations.
    static ref SCHEDULER_ADMISSION: Mutex<Option<SchedulerAdmissionCallbacks>> = Mutex::new(None);
    /// Futex 唤醒回调（用于 clear_child_tid）
    static ref FUTEX_WAKE: Mutex<Option<FutexWakeCallback>> = Mutex::new(None);
    /// E.5 Cpuset: Task joined callback (for fork/clone)
    static ref CPUSET_TASK_JOINED: Mutex<Option<CpusetTaskJoinedCallback>> = Mutex::new(None);
    /// E.5 Cpuset: Task left callback (for process exit)
    static ref CPUSET_TASK_LEFT: Mutex<Option<CpusetTaskLeftCallback>> = Mutex::new(None);
    /// H.3 KPTI: Per-CPU CR3 update callback (bridges kernel_core → arch)
    /// 缓存引导时的 CR3 值，用于内核进程或 memory_space == 0 的情况
    static ref BOOT_CR3: (PhysFrame<Size4KiB>, Cr3Flags) = Cr3::read();
}

/// Detach the process-table backing when no published PCB remains.
///
/// RF180-44: this function runs while `PROCESS_TABLE` is held, so it may only
/// mutate and detach storage. The returned owner must be dropped after the
/// caller releases the table lock; its destructor physically deallocates the
/// backing before releasing the corresponding whole-heap charge.
#[must_use = "retired process-table backing must be dropped after PROCESS_TABLE unlock"]
pub(crate) fn reclaim_empty_process_table(
    table: &mut AdmittedVec<Option<ProcessArc>>,
) -> Option<RetiredAdmittedVecCapacity<Option<ProcessArc>>> {
    if table.iter().all(Option::is_none) {
        // Every element is `None`, so clearing cannot run an Arc destructor.
        table.clear_retaining_capacity();
        table.take_empty_capacity()
    } else {
        None
    }
}

/// RF180-44 executable proof that process-table backing retirement is split
/// into an allocation-free locked phase and an out-of-lock destruction phase.
pub fn run_process_table_retirement_self_test() {
    let before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    let table = Mutex::new(AdmittedVec::<Option<ProcessArc>>::new(
        HeapClass::CoreProcess,
    ));

    let retired = {
        let mut table = table.lock();
        table
            .try_reserve_exact(4)
            .expect("RF180-44 process-table fixture backing");
        table
            .push_reserved(None)
            .unwrap_or_else(|_| panic!("RF180-44 process-table fixture capacity vanished"));
        let live = mm::heap_class_snapshot(HeapClass::CoreProcess);
        assert!(live.committed_bytes > before.committed_bytes);

        let retired = reclaim_empty_process_table(&mut table)
            .expect("RF180-44 empty process table must detach its backing");
        assert!(table.is_empty());
        assert_eq!(table.capacity(), 0);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::CoreProcess),
            live,
            "RF180-44 locked detach must not deallocate or uncharge"
        );
        retired
    };

    let detached = mm::heap_class_snapshot(HeapClass::CoreProcess);
    assert!(detached.committed_bytes > before.committed_bytes);
    drop(retired);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::CoreProcess),
        before,
        "RF180-44 retired backing must deallocate before returning admission"
    );
}

/// D2-ARC: self-test for the ProcessRegistryTransaction API. Every enforcement leg
/// runs against a PRIVATE table fixture (never the global PROCESS_TABLE), then one
/// read-only graceful-skip probe of the live table. RF180-40/44 discipline: the
/// CoreProcess heap-class charge is asserted to restore EXACTLY after the fixture
/// drops. All visit closures are alloc-free; no klog occurs while any lock is held.
pub fn run_process_registry_txn_self_test() {
    const SENTINEL: usize = 0xD2A2_C000;
    const OTHER_SPACE: usize = 0x0E11_5000;
    let before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    {
        let table = Mutex::new(AdmittedVec::<Option<ProcessArc>>::new(
            HeapClass::CoreProcess,
        ));
        {
            let mut t = table.lock();
            t.try_reserve_exact(6).expect("D2-ARC fixture backing");
            t.push_reserved(None)
                .unwrap_or_else(|_| panic!("D2-ARC fixture slot 0"));
            for pid in 1..=5usize {
                let arc = Process::try_new_pcb(
                    pid,
                    1,
                    ProcessNameSnapshot::from_parts("d2arc-txn-fixture", ""),
                    120,
                )
                .expect("D2-ARC fixture pcb");
                t.push_reserved(Some(arc))
                    .unwrap_or_else(|_| panic!("D2-ARC fixture slot"));
            }
            // Stage tgid/space/state:
            //   pid 1,2: tgid 1, SENTINEL, live   (thread group)
            //   pid 3:   tgid 1, SENTINEL, Zombie (share-count includes; recount excludes)
            //   pid 4:   tgid 4, SENTINEL, live   (pure CLONE_VM sibling)
            //   pid 5:   tgid 5, OTHER,    live   (neither)
            for pid in 1..=5usize {
                if let Some(Some(arc)) = t.get(pid) {
                    let mut g = arc.lock();
                    match pid {
                        1 | 2 => {
                            g.tgid = 1;
                            g.memory_space = SENTINEL;
                            g.state = ProcessState::Ready;
                        }
                        3 => {
                            g.tgid = 1;
                            g.memory_space = SENTINEL;
                            g.state = ProcessState::Zombie;
                        }
                        4 => {
                            g.tgid = 4;
                            g.memory_space = SENTINEL;
                            g.state = ProcessState::Ready;
                        }
                        _ => {
                            g.tgid = 5;
                            g.memory_space = OTHER_SPACE;
                            g.state = ProcessState::Ready;
                        }
                    }
                }
            }
        }

        // Leg 1: happy-path scan visits exactly the 5 live slots.
        let n = with_registry_txn_on(&table, |txn| {
            let mut n = 0usize;
            txn.try_visit_all_except(None, |_p, _| n += 1)?;
            Ok(n)
        })
        .expect("D2-ARC leg1");
        assert_eq!(n, 5, "D2-ARC leg1: happy scan visits all live slots");

        // Leg 2: guard + scan composition (held pid skipped, contains() true).
        with_registry_txn_on(&table, |txn| {
            let _g1 = txn.try_lock_process(1)?;
            assert!(txn.contains(1), "D2-ARC leg2: contains(held) true");
            let mut n = 0usize;
            txn.try_visit_all_except(None, |_p, _| n += 1)?;
            assert_eq!(n, 4, "D2-ARC leg2: scan skips the txn-held pid");
            Ok(())
        })
        .expect("D2-ARC leg2");

        // Leg 3: same-pid re-lock → OrderViolation.
        with_registry_txn_on(&table, |txn| {
            let _g2 = txn.try_lock_process(2)?;
            assert_eq!(
                txn.try_lock_process(2).err(),
                Some(RegistryTxnError::OrderViolation),
                "D2-ARC leg3: same-pid re-lock rejected"
            );
            Ok(())
        })
        .expect("D2-ARC leg3");

        // Leg 4: descending-order → OrderViolation; legal re-lock after drop.
        with_registry_txn_on(&table, |txn| {
            {
                let _g3 = txn.try_lock_process(3)?;
                assert_eq!(
                    txn.try_lock_process(1).err(),
                    Some(RegistryTxnError::OrderViolation),
                    "D2-ARC leg4: descending-order rejected"
                );
            }
            // g3 dropped → pid 3 re-lockable.
            let _g3b = txn.try_lock_process(3)?;
            Ok(())
        })
        .expect("D2-ARC leg4");

        // Leg 5: guard cap → TooManyGuards on the 5th simultaneous guard.
        with_registry_txn_on(&table, |txn| {
            let _a = txn.try_lock_process(1)?;
            let _b = txn.try_lock_process(2)?;
            let _c = txn.try_lock_process(3)?;
            let _d = txn.try_lock_process(4)?;
            assert_eq!(
                txn.try_lock_process(5).err(),
                Some(RegistryTxnError::TooManyGuards),
                "D2-ARC leg5: guard cap enforced"
            );
            Ok(())
        })
        .expect("D2-ARC leg5");

        // Leg 6: sibling contention → clean abort, no leaked locks.
        {
            let external = {
                let t = table.lock();
                t.get(4).and_then(|s| s.clone()).expect("D2-ARC pid4 arc")
            };
            let held = external.lock(); // hold pid 4's inner externally
            let r = with_registry_txn_on(&table, |txn| {
                let mut n = 0usize;
                txn.try_visit_all_except(None, |_p, _| n += 1)?;
                Ok(n)
            });
            assert_eq!(
                r.err(),
                Some(RegistryTxnError::Contention),
                "D2-ARC leg6: scan aborts on contention"
            );
            drop(held);
            assert!(
                table.try_lock().is_some(),
                "D2-ARC leg6: table free after abort"
            );
            let t = table.lock();
            for pid in 1..=5usize {
                if let Some(Some(arc)) = t.get(pid) {
                    assert!(
                        arc.try_lock().is_some(),
                        "D2-ARC leg6: no leaked PCB lock after abort"
                    );
                }
            }
        }

        // Leg 7: guard release on early Err return from the closure.
        let r: Result<(), RegistryTxnError> = with_registry_txn_on(&table, |txn| {
            let _g = txn.try_lock_process(2)?;
            Err(RegistryTxnError::NotFound)
        });
        assert_eq!(
            r.err(),
            Some(RegistryTxnError::NotFound),
            "D2-ARC leg7: early Err propagates"
        );
        {
            let t = table.lock();
            if let Some(Some(arc)) = t.get(2) {
                assert!(
                    arc.try_lock().is_some(),
                    "D2-ARC leg7: guard released on early return"
                );
            }
        }

        // Leg 8: table contention → Contention without deadlock.
        {
            let held = table.lock();
            let r = with_registry_txn_on(&table, |txn| txn.try_visit_all_except(None, |_p, _| {}));
            assert_eq!(
                r.err(),
                Some(RegistryTxnError::Contention),
                "D2-ARC leg8: table contention aborts"
            );
            drop(held);
        }

        // Leg 9a: share-count shape (mirrors try_address_space_share_count_holding —
        // includes Zombie, excludes Terminated). skip pid 1; SENTINEL live-or-zombie:
        // pids 2,3(Zombie),4 = 3; + contains(1) = 4.
        let share = with_registry_txn_on(&table, |txn| {
            let mut c = 0usize;
            txn.try_visit_all_except(Some(1), |_p, p| {
                if p.memory_space == SENTINEL && p.state != ProcessState::Terminated {
                    c += 1;
                }
            })?;
            if txn.contains(1) {
                c += 1;
            }
            // NotFound on the empty slot 0.
            assert_eq!(
                txn.try_lock_process(0).err(),
                Some(RegistryTxnError::NotFound),
                "D2-ARC leg9: NotFound on empty slot"
            );
            Ok(c)
        })
        .expect("D2-ARC leg9a");
        assert_eq!(
            share, 4,
            "D2-ARC leg9a: share-count shape (Zombie included)"
        );

        // Leg 9b: seccomp-recount shape (mirrors try_seccomp_isolation_recount_holding
        // — excludes Zombie+Terminated; threads = same tgid, vm = diff tgid same space).
        // held_tgid=1, skip pid 1: threads = pid 2 (+contains(1)) = 2; vm = pid 4 = 1.
        let (threads, vm) = with_registry_txn_on(&table, |txn| {
            let mut threads = 0usize;
            let mut vm = 0usize;
            txn.try_visit_all_except(Some(1), |_p, p| {
                if matches!(p.state, ProcessState::Zombie | ProcessState::Terminated) {
                    return;
                }
                if p.tgid == 1 {
                    threads += 1;
                } else if p.memory_space == SENTINEL {
                    vm += 1;
                }
            })?;
            if txn.contains(1) {
                threads += 1;
            }
            Ok((threads, vm))
        })
        .expect("D2-ARC leg9b");
        assert_eq!(
            (threads, vm),
            (2, 1),
            "D2-ARC leg9b: recount shape (threads/vm split, Zombie excluded)"
        );
    }

    // Leg 10: exact CoreProcess charge restoration after the fixture drops.
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::CoreProcess),
        before,
        "D2-ARC leg10: fixture must restore CoreProcess charge exactly"
    );

    // Read-only probe of the LIVE global table — graceful-skip on contention, never
    // fails boot. klog only AFTER the txn returns (never under a held lock).
    match with_process_registry_txn(|txn| {
        let mut n = 0usize;
        txn.try_visit_all_except(None, |_p, _| n += 1)?;
        Ok(n)
    }) {
        Ok(n) => klog!(Info, "[D2-ARC] live-table txn probe ok ({} live PCBs)", n),
        Err(_) => klog!(Warn, "[D2-ARC] live-table txn probe skipped (contention)"),
    }
}

/// RF178-33: installed once during boot, then read lock-free from the
/// timer-return context-switch path.
static KPTI_CR3_UPDATE: Once<KptiCr3UpdateCallback> = Once::new();

/// R67-4 FIX: Per-CPU storage for current process ID.
///
/// Each CPU tracks its own currently running process. This prevents race
/// conditions where multiple CPUs could interfere with each other's
/// current process state.
///
/// R91-1 FIX: Uses AtomicUsize instead of Mutex<Option<ProcessId>> to eliminate
/// IRQ deadlock. Timer ISR calls current_pid() from interrupt context while
/// syscall path enables interrupts (sti) before dispatcher. If timer fires
/// while syscall code holds the per-CPU Mutex, the ISR would deadlock trying
/// to acquire the same non-reentrant spinlock on the same CPU.
///
/// Encoding: 0 = no current process, N > 0 = ProcessId N.
/// PID 0 is never assigned, so 0 is a safe sentinel.
static CURRENT_PID: cpu_local::CpuLocal<AtomicUsize> =
    cpu_local::CpuLocal::new(|| AtomicUsize::new(0));

/// M4-1 (force-init): pre-allocate the `CURRENT_PID` per-CPU slab in process context
/// before IRQs are enabled. `current_pid()` is called from the raw timer ISR
/// (arch/interrupts.rs) BEFORE `on_scheduler_tick`; without this the first AP timer IRQ
/// would lazily `Box::new_uninit_slice` the CpuLocal slab while the heap lock may be
/// held, deadlocking in IRQ (the R151-5 class). Call on the BSP before `start_aps()`;
/// the single global `Once` covers every CPU.
pub fn force_init_current_pid() {
    CURRENT_PID.force_init();
}

/// R106-11 (P0-4): Next PID allocation hint for circular scan.
///
/// PID 0 is never allocated; valid PIDs are in [1, PID_MAX].
/// On each allocation, the scan starts from this hint and wraps around.
static NEXT_PID_HINT: Mutex<ProcessId> = Mutex::new(1);

/// R106-1 FIX: 下一个可用的进程 generation（单调递增，永不复用）。
///
/// 每个新进程实例（包括 PID 复用场景）获得唯一的 generation 值，
/// 用于 IPC 授权等需要区分进程身份的场景。u64 空间在实际中不可耗尽。
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// M1-02: global, monotonic per-WAIT sequence allocator for the queue-free
/// `ipc::sync::WaitQueue` timeout path. Unlike the per-queue `wait_generation`
/// (which restarts at 0 for every `WaitQueue` and is therefore NOT unique across
/// queues), this counter is unique across ALL queues and ALL PIDs, so the timer
/// IRQ can identify THE exact pending timed wait by `(pid, seq)` WITHOUT ever
/// dereferencing a `WaitQueue`. That deref of a pointer smuggled through the timer
/// table was a real SMP use-after-free (M1-02): a concurrent `FUTEX_WAKE` +
/// `cleanup_empty_bucket` could free the heap `Arc<WaitQueue>` between the drain's
/// lock-dropped Phase-1 copy and the Phase-2 deref. `0` is the reserved "no active
/// timed wait" sentinel for `Process.active_wait_seq`.
static NEXT_WAIT_SEQ: AtomicU64 = AtomicU64::new(1);

/// M1-02: allocate the next globally-unique wait sequence. Skips the reserved `0`
/// sentinel on the (practically unreachable) u64 wraparound, so an allocated seq
/// can never collide with the born-clean `active_wait_seq` value.
#[inline]
pub fn alloc_wait_seq() -> u64 {
    loop {
        let seq = NEXT_WAIT_SEQ.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (wait sequence counter)
        if seq != 0 {
            return seq;
        }
    }
}

/// 初始化进程子系统
///
/// 必须在任何进程创建或调度之前调用，以确保 BOOT_CR3 捕获正确的引导页表值。
pub fn init() {
    // 强制 BOOT_CR3 lazy_static 初始化，确保捕获当前（引导）CR3
    let _ = *BOOT_CR3;
    klog_always!("  Process subsystem initialized (boot CR3 cached)");
}

/// R106-11 (P0-4): Allocate a free global PID with recycling.
///
/// Uses a circular scan starting from `hint`. On wrap-around, scans from PID 1
/// up to the previous hint. PID 0 is never allocated.
///
/// # Lock ordering
///
/// The caller must hold `NEXT_PID_HINT` and pass the already-locked
/// `PROCESS_TABLE` to avoid double-locking.
fn allocate_global_pid(
    hint: &mut ProcessId,
    table: &[Option<ProcessArc>],
) -> Result<ProcessId, ProcessCreateError> {
    let pid_max = PID_MAX.min(MAX_PID);
    // Lock order: NEXT_PID_HINT -> PROCESS_TABLE -> REAPING_PID_BITS.
    // cleanup_zombie marks under PROCESS_TABLE before releasing the empty slot,
    // so the allocator can never observe a reusable gap between those states.
    let reaping = REAPING_PID_STATE.lock();

    let start = match *hint {
        0 => 1,
        n if n > pid_max => 1,
        n => n,
    };

    // Forward scan: [start, pid_max]
    for pid in start..=pid_max {
        let is_free = table.get(pid).map(|slot| slot.is_none()).unwrap_or(true)
            && !reaping_pid_is_set(&reaping, pid);
        if is_free {
            *hint = if pid == pid_max { 1 } else { pid + 1 };
            return Ok(pid);
        }
    }

    // Wrap-around scan: [1, start)
    for pid in 1..start {
        let is_free = table.get(pid).map(|slot| slot.is_none()).unwrap_or(true)
            && !reaping_pid_is_set(&reaping, pid);
        if is_free {
            *hint = if pid == pid_max { 1 } else { pid + 1 };
            return Ok(pid);
        }
    }

    Err(ProcessCreateError::PidExhausted)
}

/// R158-4 FIX: Reserve a child slot in the parent's children Vec BEFORE allocating
/// any resources. Uses a reservation counter to prevent concurrent capacity theft.
/// Returns Ok(()) on success or if ppid == 0 (kernel threads have no parent).
pub fn reserve_child_slot(ppid: ProcessId) -> Result<(), ProcessCreateError> {
    if ppid == 0 {
        return Ok(());
    }
    let table = PROCESS_TABLE.lock();
    if let Some(Some(parent_arc)) = table.get(ppid) {
        let mut parent = parent_arc.lock();
        let needed_capacity = parent.children.len() + parent.children_reserved + 1;
        let current_capacity = parent.children.capacity();
        if current_capacity < needed_capacity {
            let additional = needed_capacity - current_capacity;
            parent
                .children
                .try_reserve(additional)
                .map_err(|_| ProcessCreateError::OutOfMemory)?;
        }
        parent.children_reserved += 1;
        Ok(())
    } else {
        Ok(())
    }
}

/// R158-4 FIX: Commit a previously reserved child slot — push is infallible
/// because capacity was pre-reserved.
pub fn commit_child_slot(ppid: ProcessId, child_pid: ProcessId) {
    if ppid == 0 {
        return;
    }
    let table = PROCESS_TABLE.lock();
    if let Some(Some(parent_arc)) = table.get(ppid) {
        let mut parent = parent_arc.lock();
        if parent.children_reserved > 0 {
            parent.children_reserved -= 1;
        }
        parent
            .children
            .push_reserved(child_pid)
            .expect("reserved parent child slot disappeared");
    }
}

/// R158-4 FIX: Cancel a child-slot reservation on any error path before commit.
pub fn cancel_child_slot(ppid: ProcessId) {
    if ppid == 0 {
        return;
    }
    let table = PROCESS_TABLE.lock();
    if let Some(Some(parent_arc)) = table.get(ppid) {
        let mut parent = parent_arc.lock();
        if parent.children_reserved > 0 {
            parent.children_reserved -= 1;
        }
    }
}

/// RAII guard that cancels a child-slot reservation on Drop unless committed.
struct ChildSlotGuard {
    ppid: ProcessId,
    committed: bool,
}

impl ChildSlotGuard {
    fn new(ppid: ProcessId) -> Self {
        Self {
            ppid,
            committed: false,
        }
    }
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ChildSlotGuard {
    fn drop(&mut self) {
        if !self.committed {
            cancel_child_slot(self.ppid);
        }
    }
}

enum ProcessTablePublicationAttempt {
    NeedCapacity,
    Complete(Result<(), ProcessCreateError>),
}

/// RF180-43: publish a fully prepared PCB while every source PID namespace is
/// live without allocating or deallocating under namespace/PROCESS_TABLE locks.
/// A capacity miss exits the lifecycle lock set, prepares detached admitted
/// backing, and retries; shutdown is revalidated on every commit attempt.
fn publish_process_with_pid_sources(
    sources: &crate::pid_namespace::PidPublicationSources,
    process: &ProcessArc,
    pid: ProcessId,
    ppid: ProcessId,
    slot_guard: &mut ChildSlotGuard,
) -> Result<(), ProcessCreateError> {
    let target_capacity = pid.checked_add(1).ok_or(ProcessCreateError::PidExhausted)?;
    let mut prepared: Option<PreparedAdmittedVecCapacity<Option<ProcessArc>>> = None;

    loop {
        let mut retired: Option<RetiredAdmittedVecCapacity<Option<ProcessArc>>> = None;
        let attempt = sources
            .with_live_publication(|| {
                let mut table = PROCESS_TABLE.lock();
                if table.len() <= pid && table.capacity() < target_capacity {
                    let Some(candidate) = prepared.take() else {
                        return ProcessTablePublicationAttempt::NeedCapacity;
                    };
                    assert!(candidate.capacity() >= target_capacity);
                    retired = Some(
                        table
                            .install_prepared_deferred(candidate)
                            .expect("validated process-table backing rejected"),
                    );
                }

                while table.len() <= pid {
                    if table.push_reserved(None).is_err() {
                        return ProcessTablePublicationAttempt::Complete(Err(
                            ProcessCreateError::OutOfMemory,
                        ));
                    }
                }
                if table[pid].is_some() {
                    return ProcessTablePublicationAttempt::Complete(Err(
                        ProcessCreateError::PidExhausted,
                    ));
                }

                table[pid] = Some(process.clone());
                if ppid > 0 {
                    if let Some(Some(parent_arc)) = table.get(ppid) {
                        let mut parent = parent_arc.lock();
                        if parent.children_reserved > 0 {
                            parent.children_reserved -= 1;
                        }
                        parent
                            .children
                            .push_reserved(pid)
                            .expect("reserved parent child slot disappeared");
                    }
                }
                slot_guard.commit();
                ProcessTablePublicationAttempt::Complete(Ok(()))
            })
            .map_err(|_| ProcessCreateError::NamespaceError)?;

        drop(retired);
        match attempt {
            ProcessTablePublicationAttempt::Complete(result) => {
                drop(prepared);
                return result;
            }
            ProcessTablePublicationAttempt::NeedCapacity => {
                drop(prepared.take());
                prepared = Some(
                    PreparedAdmittedVecCapacity::try_new(HeapClass::CoreProcess, target_capacity)
                        .map_err(|_| ProcessCreateError::OutOfMemory)?,
                );
            }
        }
    }
}

/// RF180-16: allocation-free rollback for a process whose namespace mappings
/// exist but whose PCB was never published in PROCESS_TABLE. The PID chain is
/// moved out so OOM/shutdown rejection cannot recurse into allocation while
/// returning namespace slots and the kernel stack.
fn cleanup_unpublished_process_resources(
    process: &ProcessArc,
    pid: ProcessId,
    stack_base: VirtAddr,
    stack_phys: PhysFrame<Size4KiB>,
) {
    let (chain, permit) = {
        let mut proc = process.lock();
        (
            core::mem::replace(
                &mut proc.pid_ns_chain,
                AdmittedVec::new(HeapClass::CoreProcess),
            ),
            proc.kernel_stack_rcu
                .take()
                .expect("kernel stack missing RCU reclaim permit"),
        )
    };
    if !chain.is_empty() {
        crate::pid_namespace::detach_pid_chain(&chain, pid);
    }
    free_kernel_stack(pid, stack_base, stack_phys, permit);
}

/// 创建新进程
///
/// # Arguments
/// * `name` - 进程名称
/// * `ppid` - 父进程 ID（0 表示无父进程）
/// * `priority` - 进程优先级
///
/// # Returns
/// 成功返回新创建进程的 PID，失败返回错误
///
/// # Security Fix Z-7
/// 内核栈分配失败时必须返回错误终止进程创建，绝不能共享内核栈
pub fn create_process<N: IntoProcessNameSnapshot>(
    name: N,
    ppid: ProcessId,
    priority: Priority,
) -> Result<ProcessId, ProcessCreateError> {
    let name = name.into_process_name_snapshot();
    // R158-4 FIX: Reserve parent child slot BEFORE allocating any resources.
    // If reservation fails, return ENOMEM with no cleanup needed.
    reserve_child_slot(ppid)?;
    let mut slot_guard = ChildSlotGuard::new(ppid);

    // R106-11 (P0-4): Allocate PID via recycling scan.
    // Lock ordering: NEXT_PID_HINT → PROCESS_TABLE (consistent with all paths).
    //
    // Kernel stack deallocation is deferred via call_rcu(), so a recycled PID's
    // stack slot may still be mapped. If allocate_kernel_stack returns AlreadyMapped,
    // advance the hint past that PID and retry with the next candidate.
    let mut hint_guard = NEXT_PID_HINT.lock();

    // A PID may be free in PROCESS_TABLE while its old stack callback is still
    // queued. Scan the complete bounded PID space so one busy recycled PID (or
    // even a large teardown wave) never becomes a false global admission failure.
    const MAX_STACK_RETRIES: usize = PID_MAX;
    let mut stack_retries = 0;
    let (pid, stack_base, stack_top, stack_phys, stack_rcu) = loop {
        let pid = {
            let table = PROCESS_TABLE.lock();
            allocate_global_pid(&mut hint_guard, &table)?
        };

        match allocate_kernel_stack(pid) {
            Ok((base, top, phys, permit)) => break (pid, base, top, phys, permit),
            Err(KernelStackError::AlreadyMapped | KernelStackError::ReclaimPending) => {
                // Stack slot still mapped from RCU-deferred free; skip this PID.
                stack_retries += 1;
                if stack_retries >= MAX_STACK_RETRIES {
                    kprintln!(
                        "Error: all {} PID stack slots are still mapped or reclaim-pending",
                        stack_retries
                    );
                    return Err(ProcessCreateError::KernelStackAllocFailed(
                        KernelStackError::AlreadyMapped,
                    ));
                }
                // Advance hint past the stale PID so the next scan starts beyond it.
                // The slot is None in PROCESS_TABLE, so the allocator will normally
                // return it again on wrap-around. However, with forward-scanning and
                // a large PID space (32768), the RCU grace period will almost certainly
                // complete before the allocator wraps back to this PID.
                let pid_max = PID_MAX.min(MAX_PID);
                *hint_guard = if pid >= pid_max { 1 } else { pid + 1 };
                continue;
            }
            Err(e) => {
                kprintln!(
                    "Error: Failed to allocate kernel stack for PID {}: {:?}",
                    pid,
                    e
                );
                return Err(ProcessCreateError::KernelStackAllocFailed(e));
            }
        }
    };

    let process = match Process::try_new_pcb(pid, ppid, name, priority) {
        Ok(process) => process,
        Err(error) => {
            free_kernel_stack(pid, stack_base, stack_phys, stack_rcu);
            return Err(error);
        }
    };

    // 设置已分配的内核栈
    {
        let mut proc = process.lock();
        proc.kernel_stack = stack_base;
        proc.kernel_stack_top = stack_top;
        proc.kernel_stack_phys = Some(stack_phys);
        proc.kernel_stack_rcu = Some(stack_rcu);
    }

    // R101-1 FIX: Kernel-internal processes (ppid == 0) need explicit root credentials.
    //
    // Process::new() now defaults to nobody (uid=65534). Kernel threads and init
    // processes must be explicitly promoted to root. User-spawned processes will
    // inherit credentials from the parent via fork()/clone().
    if ppid == 0 {
        let mut proc = process.lock();
        proc.credentials.replace_unpublished(Credentials {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            supplementary_groups: AdmittedVec::new(HeapClass::CoreProcess),
        });
    }

    // F.1 PID Namespace: Assign namespace chain for the new process
    //
    // For kernel-created processes (ppid == 0), use root namespace.
    // For forked/cloned processes, the caller (fork.rs/sys_clone) will handle
    // namespace inheritance from the parent.
    let pid_publication_sources = {
        let target_ns = if ppid == 0 {
            // Kernel thread: use root namespace
            crate::pid_namespace::ROOT_PID_NAMESPACE.clone()
        } else {
            // Child process: inherit from parent's pid_ns_for_children
            // Note: For now, default to root. Fork/clone will override this.
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().pid_ns_for_children.clone()
            } else {
                crate::pid_namespace::ROOT_PID_NAMESPACE.clone()
            }
        };

        // Assign PID chain from root namespace down to target
        match crate::pid_namespace::assign_pid_chain(target_ns.clone(), pid) {
            Ok(chain) => {
                let Some(publication_sources) =
                    crate::pid_namespace::PidPublicationSources::from_chain(&chain)
                else {
                    let mut proc = process.lock();
                    proc.pid_ns_chain = chain;
                    drop(proc);
                    cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
                    return Err(ProcessCreateError::NamespaceError);
                };
                let mut proc = process.lock();
                proc.pid_ns_chain = chain;
                proc.pid_ns_for_children = target_ns;
                publication_sources
            }
            Err(e) => {
                // Namespace chain assignment failed, clean up
                // R104-2 FIX: Gate diagnostic println behind debug_assertions.
                kprintln!("Error: Failed to assign PID namespace chain: {:?}", e);
                let _ = e; // suppress unused warning in release
                cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
                // R106-11: PID reclaim is automatic — the slot is still None,
                // so the next allocate_global_pid() scan will find it.
                return Err(ProcessCreateError::NamespaceError);
            }
        }
    };

    // Mount namespace: inherit from parent's mount_ns_for_children (or root for kernel threads)
    {
        let target_mnt_ns = if ppid == 0 {
            crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
        } else {
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().mount_ns_for_children.clone()
            } else {
                crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
            }
        };

        let mut proc = process.lock();
        proc.mount_ns = target_mnt_ns.clone();
        proc.mount_ns_for_children = target_mnt_ns;
    }

    // RF180-16: namespace mapping and PCB publication are one lifecycle
    // transaction. Lock order is namespace sources (root->leaf) ->
    // PROCESS_TABLE -> parent PCB. Init teardown takes only one source lock,
    // releases it before PROCESS_TABLE lookup, and therefore cannot deadlock:
    // publication-first is enumerated; shutdown-first rejects publication.
    if let Err(error) = publish_process_with_pid_sources(
        &pid_publication_sources,
        &process,
        pid,
        ppid,
        &mut slot_guard,
    ) {
        cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
        return Err(error);
    }

    // Safe to release now — the PID slot is occupied in PROCESS_TABLE
    drop(hint_guard);

    // E.5 Cpuset: count kernel-created tasks (ppid == 0) so root cpuset reflects live tasks.
    // Fork path handles task counting separately via fork.rs which also copies cpuset_id.
    if ppid == 0 {
        let cpuset_id = process.lock().cpuset_id;
        notify_cpuset_task_joined(cpuset_id);
    }

    // G.1 Observability: Register watchdog for hung-task detection.
    // Best-effort registration - failure is logged but doesn't fail process creation.
    // The 10-second timeout catches true hangs while allowing normal blocking operations.
    let now_ms = time::current_timestamp_ms();
    let cfg = WatchdogConfig {
        task_id: pid as u64,
        timeout_ms: WATCHDOG_TIMEOUT_MS,
    };
    match register_watchdog(cfg, now_ms) {
        Ok(handle) => {
            process.lock().watchdog_handle = Some(handle);
        }
        Err(_) => {
            // Watchdog slots full - system under heavy load but not fatal
            // R104-2 FIX: Gate diagnostic println behind debug_assertions.
            kprintln!(
                "  Warning: Failed to register watchdog for PID {} (slots full)",
                pid
            );
        }
    }

    // R104-2 FIX: Gate diagnostic println behind debug_assertions.
    {
        let proc = process.lock();
        klog!(
            Info,
            "Created process: PID={}, Name={}, Priority={}",
            pid,
            proc.name,
            priority
        );
    }

    Ok(pid)
}

/// F.1 PID Namespace: Create a process in a specific namespace.
///
/// This is used by sys_clone with CLONE_NEWPID to create processes
/// in a new namespace instead of inheriting from parent.
///
/// # Arguments
///
/// * `name` - Process name
/// * `ppid` - Parent process ID
/// * `priority` - Process priority
/// * `target_ns` - The PID namespace to create the process in
///
/// # Returns
///
/// The new process's global PID on success
pub fn create_process_in_namespace<N: IntoProcessNameSnapshot>(
    name: N,
    ppid: ProcessId,
    priority: Priority,
    target_ns: crate::pid_namespace::PidNamespaceArc,
) -> Result<ProcessId, ProcessCreateError> {
    let name = name.into_process_name_snapshot();
    // R158-4 FIX: Reserve parent child slot BEFORE allocating any resources.
    reserve_child_slot(ppid)?;
    let mut slot_guard = ChildSlotGuard::new(ppid);

    // Allocate PID and kernel stack (same as create_process)
    // R106-11 (P0-4): Allocate PID via recycling scan with AlreadyMapped retry.
    let mut hint_guard = NEXT_PID_HINT.lock();

    const MAX_STACK_RETRIES: usize = PID_MAX;
    let mut stack_retries = 0;
    let (pid, stack_base, stack_top, stack_phys, stack_rcu) = loop {
        let pid = {
            let table = PROCESS_TABLE.lock();
            allocate_global_pid(&mut hint_guard, &table)?
        };

        match allocate_kernel_stack(pid) {
            Ok((base, top, phys, permit)) => break (pid, base, top, phys, permit),
            Err(KernelStackError::AlreadyMapped | KernelStackError::ReclaimPending) => {
                stack_retries += 1;
                if stack_retries >= MAX_STACK_RETRIES {
                    kprintln!(
                        "Error: all {} PID stack slots are still mapped or reclaim-pending",
                        stack_retries
                    );
                    return Err(ProcessCreateError::KernelStackAllocFailed(
                        KernelStackError::AlreadyMapped,
                    ));
                }
                let pid_max = PID_MAX.min(MAX_PID);
                *hint_guard = if pid >= pid_max { 1 } else { pid + 1 };
                continue;
            }
            Err(e) => {
                kprintln!(
                    "Error: Failed to allocate kernel stack for PID {}: {:?}",
                    pid,
                    e
                );
                return Err(ProcessCreateError::KernelStackAllocFailed(e));
            }
        }
    };

    let process = match Process::try_new_pcb(pid, ppid, name, priority) {
        Ok(process) => process,
        Err(error) => {
            free_kernel_stack(pid, stack_base, stack_phys, stack_rcu);
            return Err(error);
        }
    };

    // Set up kernel stack
    {
        let mut proc = process.lock();
        proc.kernel_stack = stack_base;
        proc.kernel_stack_top = stack_top;
        proc.kernel_stack_phys = Some(stack_phys);
        proc.kernel_stack_rcu = Some(stack_rcu);
    }

    // R101-1 FIX: Kernel-internal processes (ppid == 0) need explicit root credentials.
    if ppid == 0 {
        let mut proc = process.lock();
        proc.credentials.replace_unpublished(Credentials {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            supplementary_groups: AdmittedVec::new(HeapClass::CoreProcess),
        });
    }

    // Assign PID namespace chain using the specified target namespace.
    let pid_publication_sources =
        match crate::pid_namespace::assign_pid_chain(target_ns.clone(), pid) {
            Ok(chain) => {
                let Some(publication_sources) =
                    crate::pid_namespace::PidPublicationSources::from_chain(&chain)
                else {
                    let mut proc = process.lock();
                    proc.pid_ns_chain = chain;
                    drop(proc);
                    cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
                    return Err(ProcessCreateError::NamespaceError);
                };
                let mut proc = process.lock();
                proc.pid_ns_chain = chain;
                proc.pid_ns_for_children = target_ns;
                publication_sources
            }
            Err(e) => {
                // R104-2 FIX: Gate diagnostic println behind debug_assertions.
                kprintln!("Error: Failed to assign PID namespace chain: {:?}", e);
                let _ = e; // suppress unused warning in release
                cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
                // R106-11: PID reclaim is automatic — the slot is still None,
                // so the next allocate_global_pid() scan will find it.
                return Err(ProcessCreateError::NamespaceError);
            }
        };

    // Mount namespace: inherit from parent's mount_ns_for_children (or root for kernel threads)
    {
        let target_mnt_ns = if ppid == 0 {
            crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
        } else {
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().mount_ns_for_children.clone()
            } else {
                crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
            }
        };

        let mut proc = process.lock();
        proc.mount_ns = target_mnt_ns.clone();
        proc.mount_ns_for_children = target_mnt_ns;
    }

    // RF180-16: hold the exact root-to-leaf namespace lifecycle sources across
    // PROCESS_TABLE publication. See create_process() for the lock-order proof.
    if let Err(error) = publish_process_with_pid_sources(
        &pid_publication_sources,
        &process,
        pid,
        ppid,
        &mut slot_guard,
    ) {
        cleanup_unpublished_process_resources(&process, pid, stack_base, stack_phys);
        return Err(error);
    }

    // Safe to release now — the PID slot is occupied in PROCESS_TABLE
    drop(hint_guard);

    if ppid == 0 {
        let cpuset_id = process.lock().cpuset_id;
        notify_cpuset_task_joined(cpuset_id);
    }

    // G.1 Observability: Register watchdog for hung-task detection.
    // Best-effort registration - failure is logged but doesn't fail process creation.
    let now_ms = time::current_timestamp_ms();
    let cfg = WatchdogConfig {
        task_id: pid as u64,
        timeout_ms: WATCHDOG_TIMEOUT_MS,
    };
    match register_watchdog(cfg, now_ms) {
        Ok(handle) => {
            process.lock().watchdog_handle = Some(handle);
        }
        Err(_) => {
            // R104-2 FIX: Gate diagnostic println behind debug_assertions.
            kprintln!(
                "  Warning: Failed to register watchdog for PID {} (slots full)",
                pid
            );
        }
    }

    // R104-2 FIX: Gate diagnostic println behind debug_assertions.
    {
        let proc = process.lock();
        klog!(
            Info,
            "Created process in namespace: PID={}, Name={}, Priority={}, NS={}",
            pid,
            proc.name,
            priority,
            proc.pid_ns_for_children.id().raw()
        );
    }

    Ok(pid)
}

/// 获取当前进程ID
///
/// R67-4 FIX: Reads from per-CPU storage to avoid cross-CPU races.
///
/// R91-1 FIX: Lock-free atomic load. Safe to call from any context including
/// IRQ handlers (timer ISR profiler sampling) without deadlock risk.
pub fn current_pid() -> Option<ProcessId> {
    let raw = CURRENT_PID.with(|pid| pid.load(Ordering::Relaxed));
    if raw == 0 {
        None
    } else {
        Some(raw)
    }
}

/// R106-1 FIX: 获取当前进程的 generation 值。
///
/// 与 `current_pid()` 配合使用，提供 (pid, generation) 二元组
/// 作为不可伪造的进程身份标识，防止 PID 复用后的授权继承。
pub fn current_generation() -> Option<u64> {
    let pid = current_pid()?;
    let process = get_process(pid)?;
    let proc = process.lock();
    Some(proc.generation)
}

/// R25-6 FIX: Get the size of a thread group (number of tasks sharing the same tgid).
///
/// Returns the count of active threads in the thread group identified by tgid.
/// Used to detect multi-threaded processes for seccomp TSYNC enforcement.
pub fn thread_group_size(tgid: ProcessId) -> usize {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.tgid == tgid
                    && p.state != ProcessState::Zombie
                    && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

/// R37-1 FIX: Count tasks sharing the same address space (CLONE_VM siblings).
///
/// Returns 0 if no valid memory_space is set.
///
/// R136-1 FIX: Counts all non-Terminated tasks, **including Zombie**.
/// This kernel defers page-table teardown to `cleanup_zombie()`, so a Zombie
/// process retains its `memory_space` reference until reaped. Excluding zombies
/// allowed `sys_exec()` to see `share_count == 1` and free the old CR3 while an
/// unreaped CLONE_VM zombie still held a reference — causing a double-free when
/// `cleanup_zombie()` later freed the same address space.
///
/// Note: `non_thread_group_vm_share_count()` (used for seccomp TSYNC) still
/// excludes zombies because TSYNC only cares about live tasks that can execute
/// seccomp filters.
pub fn address_space_share_count(memory_space: usize) -> usize {
    if memory_space == 0 {
        return 0;
    }
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.memory_space == memory_space && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

/// R181-3 FIX: lock-order-safe CLONE_VM share re-count for callers that HOLD a
/// Process::inner lock (the cgroupfs/attach migration window). The blocking
/// `address_space_share_count` takes PROCESS_TABLE then locks every
/// Process::inner — calling it while holding one Process::inner inverts the
/// Level-5 order (ABBA). This variant fails CLOSED instead of blocking:
///
/// - `PROCESS_TABLE` is acquired via `try_lock`; contention aborts the count.
/// - The slot whose lock the CALLER already holds (`held_pid`) is counted
///   WITHOUT locking (the caller holds it; its membership cannot change).
/// - Every other slot uses `try_lock`; ANY contended sibling aborts the count
///   (a skipped sibling could be the CLONE_VM partner we exist to detect —
///   skipping would silently under-count, re-opening the bypass).
///
/// Returns `Some(count)` on a complete observation, `None` on any contention.
/// Callers treat `None` as EBUSY (transient; userspace retries).
pub fn try_address_space_share_count_holding(
    memory_space: usize,
    held_pid: ProcessId,
) -> Option<usize> {
    if memory_space == 0 {
        return Some(0);
    }
    // D2-ARC: reimplemented on the ProcessRegistryTxn combinator with provably
    // identical observable semantics to the original hand-rolled scan:
    //   - same table try_lock (contention → None via `.ok()`),
    //   - same ascending per-slot try_lock-check-drop with abort-on-ANY-contention
    //     (the `?` inside the visit propagates Contention exactly like the old `?`),
    //   - `held_pid` counted +1 IFF its slot is occupied (`contains` replicates the
    //     old `let Some(p) = slot else { continue }` guard before the held_pid arm;
    //     the caller-held-lock membership argument is unchanged — the caller holds
    //     this PCB's Process::inner and has already verified its memory_space),
    //   - same predicate, same alloc-free property, same lock hold windows.
    // OrderViolation/TooManyGuards are unreachable here (no TxnProcessGuards taken),
    // so `.ok()` maps exactly the original None-on-contention surface. Both
    // production callers (sys_cgroup_attach R181-3 arm; cgroupfs cgroup.procs arm)
    // remain byte-for-byte untouched — the narrowest honest adoption.
    with_process_registry_txn(|txn| {
        let mut count = 0usize;
        txn.try_visit_all_except(Some(held_pid), |_pid, p| {
            if p.memory_space == memory_space && p.state != ProcessState::Terminated {
                count += 1;
            }
        })?;
        if txn.contains(held_pid) {
            count += 1;
        }
        Ok(count)
    })
    .ok()
}

/// D2-ARC second consumer: fail-closed under-held-`Process::inner` recount of the
/// seccomp isolation predicates. Returns `Some((thread_group_count,
/// pure_vm_sibling_count))` on a complete observation, `None` on any contention.
///
/// Mirrors `thread_group_size` (self-inclusive; excludes Zombie+Terminated) and
/// `non_thread_group_vm_share_count` (excludes same-tgid tasks + Zombie+Terminated;
/// 0 for `memory_space == 0`) EXACTLY, but never blocks — the blocking scans would
/// ABBA-invert Level-5 `PROCESS_TABLE → Process::inner` when called under a held
/// `Process::inner` (the R181-3 rationale). The caller must hold `held_pid`'s
/// `Process::inner` and pass `held_tgid`/`held_memory_space` read UNDER that lock;
/// the held task is live by contract (executing a syscall), so the `contains` leg
/// counts it into `threads` unconditionally.
///
/// SEVERITY NOTE (see the seccomp call sites): this recount NARROWS the stale-
/// preflight window but does NOT close the R37-1 TSYNC TOCTOU — it is
/// defense-in-depth, not a race fix. A residual recount→commit window remains (the
/// caller's held lock never blocks a sibling's clone; the clone gate checks only
/// the cloning task's own `seccomp_installing`), and post-install an unfiltered
/// TSYNC-admitted sibling can still clone a pure-VM task (TSYNC does not fan the
/// filter out). The R37-1 TSYNC residual stays OPEN (clone-side space-member gate).
pub fn try_seccomp_isolation_recount_holding(
    held_pid: ProcessId,
    held_tgid: ProcessId,
    held_memory_space: usize,
) -> Option<(usize, usize)> {
    with_process_registry_txn(|txn| {
        let mut threads = 0usize;
        let mut vm_siblings = 0usize;
        txn.try_visit_all_except(Some(held_pid), |_pid, p| {
            if matches!(p.state, ProcessState::Zombie | ProcessState::Terminated) {
                return;
            }
            if p.tgid == held_tgid {
                threads += 1;
            } else if held_memory_space != 0 && p.memory_space == held_memory_space {
                vm_siblings += 1;
            }
        })?;
        if txn.contains(held_pid) {
            threads += 1;
        }
        Ok((threads, vm_siblings))
    })
    .ok()
}

// D3-ARC-MM-SHARED: The following sync_vm_siblings_* functions have been deleted.
// With shared MmState (Arc<Mutex<MmState>>), CLONE_VM siblings share a single
// MmState instance. Mutations are automatically visible to all siblings through
// the shared Arc, eliminating the need for cross-task propagation:
//   - atomic_remove_mmap_region()
//   - atomic_mprotect_prot_none_transition() / atomic_mprotect_to_prot_none()
//   - sync_vm_siblings_remove_mmap()
//   - sync_vm_siblings_split_region()
//   - sync_vm_siblings_brk()
//   - sync_vm_siblings_add_mmap()
//   - sync_vm_siblings_mprotect_flags()
//   - reconcile_clone_vm_mmap_regions()

/// R37-1 FIX (Codex review): Count CLONE_VM siblings that are NOT in the same thread group.
///
/// CLONE_THREAD siblings share memory_space AND have the same tgid - these can be TSYNC'd.
/// Pure CLONE_VM siblings share memory_space but have DIFFERENT tgid - these cannot be TSYNC'd.
///
/// This function returns the count of processes that share the same memory_space but have
/// a different tgid than the caller. If count > 0, TSYNC must be rejected.
pub fn non_thread_group_vm_share_count(memory_space: usize, caller_tgid: ProcessId) -> usize {
    if memory_space == 0 {
        return 0;
    }
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.memory_space == memory_space
                    && p.tgid != caller_tgid // Different thread group = pure CLONE_VM sibling
                    && p.state != ProcessState::Zombie
                    && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

// ============================================================================
// D2-ARC-CLONE-LOCK: ProcessRegistryTransaction — fail-closed cross-registry
// try-lock API (Level-5 PROCESS_TABLE + Process::inner).
//
// This is the SANCTIONED way to observe PROCESS_TABLE (Level 5) while a
// Process::inner (Level 5) is already held. ALL acquisition inside it is
// try-only and fail-closed (Contention aborts; callers surface EAGAIN/EBUSY), so
// no blocking cycle can ever form — deadlock-freedom derives SOLELY from try-only
// acquisition. It generalizes the R181-3 primitive's already-proven
// try-lock-under-held-Process::inner profile (the documented Level-5 exception).
//
// This is NOT transactional memory: there is no mutation journal and no rollback.
// Consumers MUST validate-everything-then-mutate — all fallible observation under
// the txn, any mutation only AFTER the txn returns Ok — so an Err return leaves
// state untouched by construction.
//
// FORBIDDEN inside the closure (same-CPU silent infinite spin that lockdep CANNOT
// catch — PROCESS_TABLE / Process::inner are plain spin::Mutex, not LockdepMutex):
//   - anything that (re)acquires PROCESS_TABLE or blocking-locks a Process::inner:
//     get_process / try_get_process / current_generation / thread_group_size /
//     address_space_share_count / non_thread_group_vm_share_count /
//     process_table_snapshot;
//   - any allocation (RF180-44): no Vec / format! / klog! while the table is held;
//   - no sleep, no user copy, no driver IO, no blocking lock.
// Not for IRQ context (IRQ table readers use the try_get_process tri-state,
// R171-G5-1). Nested with_process_registry_txn fails closed as Contention
// (spin try_lock on the self-held table returns None).
//
// Guard-ordering rule: multiple caller-held TxnProcessGuards must be acquired in
// strictly-ascending pid order (runtime-enforced by register(), max 4). This is a
// determinism/hygiene contract only — it is NOT what makes the API safe.
// try_visit_all_except's TRANSIENT per-slot guards are EXEMPT from this rule (they
// may try-lock pids below a held guard) and are safe SOLELY because acquisition is
// try-only with the guard dropped before the next slot. No blocking variant of the
// scan may EVER be added on the strength of the ordering discipline.
// ============================================================================

/// Error from a process-registry transaction. Every variant means "observation
/// incomplete, nothing mutated" — callers map it to EAGAIN/EBUSY (transient).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryTxnError {
    /// A try-lock (table or a PCB) was contended — abort, nothing acquired.
    Contention,
    /// The requested pid has no live table slot.
    NotFound,
    /// Same-pid re-lock, or out-of-ascending-order acquisition of a held guard.
    OrderViolation,
    /// More than MAX_TXN_GUARDS simultaneous caller-held guards requested.
    TooManyGuards,
}

/// Max simultaneously caller-held `TxnProcessGuard`s. No production site holds >1
/// published PCB guard; 4 is headroom. The fixed array keeps the txn alloc-free.
pub const MAX_TXN_GUARDS: usize = 4;

/// A process-registry transaction. Holds ONLY a reborrow of the entry-frame-owned
/// `PROCESS_TABLE` guard (never process guards → non-self-referential) plus a fixed
/// held-pid registry. `Cell` makes it `!Sync`, which is correct: single-thread
/// closure scope.
pub struct ProcessRegistryTxn<'t> {
    table: &'t AdmittedVec<Option<ProcessArc>>,
    held: Cell<[Option<ProcessId>; MAX_TXN_GUARDS]>,
}

/// A locked PCB handed to the caller by `try_lock_process`. Its lifetime is bound
/// to `&'a self` (the txn), so it cannot escape the closure. `Drop` unregisters the
/// pid from the held registry BEFORE the inner guard releases the lock — the only
/// inconsistency window is held-but-unregistered, which fails CLOSED.
pub struct TxnProcessGuard<'a, 't> {
    txn: &'a ProcessRegistryTxn<'t>,
    pid: ProcessId,
    guard: spin::MutexGuard<'a, Process>,
}

impl core::ops::Deref for TxnProcessGuard<'_, '_> {
    type Target = Process;
    fn deref(&self) -> &Process {
        &self.guard
    }
}

impl core::ops::DerefMut for TxnProcessGuard<'_, '_> {
    fn deref_mut(&mut self) -> &mut Process {
        &mut self.guard
    }
}

impl Drop for TxnProcessGuard<'_, '_> {
    fn drop(&mut self) {
        self.txn.unregister(self.pid);
    }
}

impl<'t> ProcessRegistryTxn<'t> {
    /// Register a caller-held pid: reject same-pid re-lock and descending order
    /// (both → OrderViolation), else claim the first free slot (else TooManyGuards).
    fn register(&self, pid: ProcessId) -> Result<(), RegistryTxnError> {
        let mut slots = self.held.get();
        for s in slots.iter() {
            if let Some(h) = s {
                if *h == pid || pid < *h {
                    return Err(RegistryTxnError::OrderViolation);
                }
            }
        }
        for s in slots.iter_mut() {
            if s.is_none() {
                *s = Some(pid);
                self.held.set(slots);
                return Ok(());
            }
        }
        Err(RegistryTxnError::TooManyGuards)
    }

    fn unregister(&self, pid: ProcessId) {
        let mut slots = self.held.get();
        for s in slots.iter_mut() {
            if *s == Some(pid) {
                *s = None;
                break;
            }
        }
        self.held.set(slots);
    }

    /// Try-lock a PCB by pid, returning a guard the caller holds in a local.
    /// NEVER txn-lock a pid whose `Process::inner` you already hold OUTSIDE the txn
    /// (pass it as `skip_pid` to scans instead) — spin try_lock would see it as
    /// contention and abort cleanly, but it is a contract violation.
    pub fn try_lock_process<'a>(
        &'a self,
        pid: ProcessId,
    ) -> Result<TxnProcessGuard<'a, 't>, RegistryTxnError> {
        let arc = self
            .table
            .get(pid)
            .and_then(|slot| slot.as_ref())
            .ok_or(RegistryTxnError::NotFound)?;
        self.register(pid)?;
        match arc.try_lock() {
            Some(guard) => Ok(TxnProcessGuard {
                txn: self,
                pid,
                guard,
            }),
            None => {
                self.unregister(pid);
                Err(RegistryTxnError::Contention)
            }
        }
    }

    /// Lockless check: does `pid` currently occupy a live table slot? Used to count
    /// a caller-held pid (whose `Process::inner` the caller already holds) without
    /// re-locking it — the R181-3 held-leg argument.
    pub fn contains(&self, pid: ProcessId) -> bool {
        self.table
            .get(pid)
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Visit every live PCB except `skip_pid` and any caller-held txn pids (the
    /// holder observes those via its own guards). Per-slot try-lock-check-drop with
    /// abort-on-ANY-contention — identical hold-window profile to the R181-3 scan.
    pub fn try_visit_all_except(
        &self,
        skip_pid: Option<ProcessId>,
        mut visit: impl FnMut(ProcessId, &Process),
    ) -> Result<(), RegistryTxnError> {
        let held = self.held.get();
        for (pid, slot) in self.table.iter().enumerate() {
            let Some(arc) = slot.as_ref() else { continue };
            if Some(pid) == skip_pid {
                continue;
            }
            if held.iter().any(|h| *h == Some(pid)) {
                continue;
            }
            let guard = arc.try_lock().ok_or(RegistryTxnError::Contention)?;
            visit(pid, &guard);
            // guard drops here, before the next slot — never 2 transient held.
        }
        Ok(())
    }
}

/// Fixture-injectable core of the transaction (RF180-44 retirement-test precedent):
/// acquires the table guard in THIS frame (drops strictly after every process guard
/// — borrow-checker enforced), builds the txn over a reborrow, runs `f`.
fn with_registry_txn_on<T>(
    table: &Mutex<AdmittedVec<Option<ProcessArc>>>,
    f: impl FnOnce(&ProcessRegistryTxn<'_>) -> Result<T, RegistryTxnError>,
) -> Result<T, RegistryTxnError> {
    let guard = table.try_lock().ok_or(RegistryTxnError::Contention)?;
    let txn = ProcessRegistryTxn {
        table: &guard,
        held: Cell::new([None; MAX_TXN_GUARDS]),
    };
    f(&txn)
}

/// Run a fail-closed transaction against the global `PROCESS_TABLE`. See the module
/// contract above: NOT transactional memory (validate-everything-then-mutate), no
/// allocation / klog / blocking lock inside the closure, not for IRQ context.
pub fn with_process_registry_txn<T>(
    f: impl FnOnce(&ProcessRegistryTxn<'_>) -> Result<T, RegistryTxnError>,
) -> Result<T, RegistryTxnError> {
    with_registry_txn_on(&PROCESS_TABLE, f)
}

///
/// Returns a Vec of all PIDs that have live process entries.
///
/// R165-15 FIX: Build the snapshot with a fallible allocation (`try_reserve_exact`)
/// instead of an infallible `.collect()`, which would abort the kernel on OOM.
/// Returns `None` when the snapshot allocation fails so callers can degrade
/// gracefully rather than panic. The reservation is exact (sized to the live
/// slot count) and bounded by the process table length (≤ MAX_PID slots).
pub fn process_table_snapshot() -> Option<alloc::vec::Vec<ProcessId>> {
    let table = PROCESS_TABLE.lock();
    let live = table.iter().filter(|slot| slot.is_some()).count();
    let mut pids: alloc::vec::Vec<ProcessId> = alloc::vec::Vec::new();
    pids.try_reserve_exact(live).ok()?;
    for (i, slot) in table.iter().enumerate() {
        if slot.is_some() {
            pids.push(i);
        }
    }
    Some(pids)
}

/// R152-10 FIX: Atomically mark all threads in a thread group for exit.
///
/// Holds PROCESS_TABLE lock while iterating and marking, preventing a concurrent
/// sys_clone(CLONE_THREAD) from creating a new thread that escapes the exit_group.
/// Returns the number of siblings marked for exit.
/// RF178-35: group membership is authorized by the shared exit-token identity,
/// not a reusable numeric TGID. The table lock still closes clone insertion.
pub fn request_exit_group_atomic(
    caller_pid: ProcessId,
    group_exit_token: &Arc<AtomicBool>,
    exit_code: i32,
) -> usize {
    let table = PROCESS_TABLE.lock();
    let mut marked = 0usize;
    let mut post = FatalExitPost::None;
    let now_tick = crate::get_ticks();
    for (i, slot) in table.iter().enumerate() {
        let pid = i;
        if pid == caller_pid {
            continue; // Skip caller — it will self-terminate
        }
        if let Some(proc_arc) = slot {
            let mut proc = proc_arc.lock();
            if Arc::ptr_eq(&proc.thread_group_exiting, group_exit_token)
                && !matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated)
            {
                let request = request_process_exit_locked(&mut proc, exit_code, now_tick);
                if request != FatalExitPost::None {
                    marked += 1;
                    if request == FatalExitPost::Kick {
                        post = FatalExitPost::Kick;
                    } else if post == FatalExitPost::None {
                        post = FatalExitPost::Posted;
                    }
                }
            }
        }
    }
    // RF178-35: never send an IPI while PROCESS_TABLE or a sibling PCB is held.
    drop(table);
    let _ = finish_process_exit_request(post);
    marked
}

/// R115-1 FIX: Request that a remote process terminates itself at a safe point.
///
/// Used by `exit_group()` to avoid cross-CPU UAF: sibling threads may be running
/// on other CPUs, so we cannot directly call `terminate_process()`. Instead, we
/// set a pending-kill flag that the target consumes on its next syscall return.
///
/// Returns `true` if the request was posted, `false` if the process does not
/// exist or is already zombie/terminated.
pub fn request_process_exit(pid: ProcessId, exit_code: i32) -> bool {
    let proc_arc = match get_process(pid) {
        Some(p) => p,
        None => return false,
    };

    request_process_exit_arc(&proc_arc, exit_code)
}

/// RF178-14 FIX: Post a fatal-exit request against an already-authorized
/// process identity. Holding the Arc binds the request to that generation and
/// prevents a PID-reuse relookup from killing an unrelated process.
pub fn request_process_exit_arc(proc_arc: &ProcessArc, exit_code: i32) -> bool {
    let post = {
        let mut proc = proc_arc.lock();
        request_process_exit_locked(&mut proc, exit_code, crate::get_ticks())
    };
    finish_process_exit_request(post)
}

/// RF178-35 post-lock action token. First publication or runnable-state repair
/// requests one broadcast; an already-runnable repost is recorded without IPI
/// amplification. Callers finish the token only after dropping all guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum FatalExitPost {
    None,
    Posted,
    Kick,
}

/// Atomically publish a fatal exit and make every non-running live task
/// selectable. The caller must hold this exact PCB's guard.
pub(crate) fn request_process_exit_locked(
    proc: &mut Process,
    exit_code: i32,
    now_tick: u64,
) -> FatalExitPost {
    if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
        return FatalExitPost::None;
    }

    let was_pending = proc.pending_kill.load(Ordering::Acquire);
    let was_stopped = proc.stopped;

    // Running and the Ready+on_cpu switch transient already own a CPU. Every
    // other *published* live state must become Ready in place; scheduler queues
    // retain blocked/sleeping/stopped PCBs, so no queue move is required.
    //
    // R180-19 review-fix: Provisioning is the scheduler-admission transaction's
    // unpublished state. A remote SIGKILL/OOM/namespace-cascade request may post
    // `pending_kill`, but it must not turn that reserved child Ready before fork
    // or clone commits the rest of its PCB/MM state. The eventual admission
    // commit publishes Ready and the already-posted fatal request is then
    // consumed at the ordinary safe point.
    let actively_running = proc.on_cpu.load(Ordering::Acquire)
        && matches!(proc.state, ProcessState::Running | ProcessState::Ready);
    let needs_ready = proc.state != ProcessState::Provisioning
        && !actively_running
        && proc.state != ProcessState::Ready;

    // RF178-35 FIX: publish the fatal request before making a parked task
    // selectable. Every consumer that can act on the request takes this PCB
    // guard, so it cannot observe the post-publication normalization half-done.
    proc.pending_exit_code.store(exit_code, Ordering::Relaxed);
    proc.pending_kill.store(true, Ordering::Release);

    if needs_ready || (proc.state == ProcessState::Ready && was_stopped) {
        // Keep `stopped` set through this call so a newly runnable residence
        // begins a fresh starvation-aging epoch.
        proc.enter_ready_at(now_tick);
    }
    proc.stopped = false;

    if !was_pending || needs_ready || was_stopped {
        FatalExitPost::Kick
    } else {
        FatalExitPost::Posted
    }
}

/// Apply a job-control stop while preserving fatal-exit precedence.
/// The caller must hold this exact PCB's guard.
pub(crate) fn try_mark_job_control_stopped_locked(proc: &mut Process) -> bool {
    if proc.pending_kill.load(Ordering::Acquire) {
        return false;
    }
    proc.stopped = true;
    true
}

/// Complete a fatal request after all locks have been released.
pub(crate) fn finish_process_exit_request(post: FatalExitPost) -> bool {
    match post {
        FatalExitPost::None => false,
        FatalExitPost::Posted => true,
        FatalExitPost::Kick => {
            let _ = crate::signal::kernel_kick_reschedule();
            true
        }
    }
}

/// RF178-35 executable state-matrix probe for fatal publication.
pub fn run_fatal_exit_publication_self_test() {
    let mut proc = Process::new(0x178_3501, 1, String::from("rf178-35-fatal"), 120);
    let group_token = Arc::clone(&proc.thread_group_exiting);
    let unrelated_group_token = Arc::new(AtomicBool::new(false));
    assert!(Arc::ptr_eq(&proc.thread_group_exiting, &group_token));
    assert!(!Arc::ptr_eq(
        &proc.thread_group_exiting,
        &unrelated_group_token,
    ));
    let live_states = [
        (ProcessState::Provisioning, false),
        (ProcessState::Provisioning, true),
        (ProcessState::Ready, false),
        (ProcessState::Ready, true),
        (ProcessState::Running, false),
        (ProcessState::Running, true),
        (ProcessState::Blocked, false),
        (ProcessState::Blocked, true),
        (ProcessState::Sleeping, false),
        (ProcessState::Sleeping, true),
        (ProcessState::Stopped, false),
        (ProcessState::Stopped, true),
    ];

    let mut case = 0usize;
    for (state, on_cpu) in live_states.iter().copied() {
        for stopped in [false, true] {
            proc.state = state;
            proc.stopped = stopped;
            proc.on_cpu.store(on_cpu, Ordering::Release);
            proc.pending_kill.store(false, Ordering::Release);
            proc.socket_timeout_marker.store(0x3501, Ordering::Release);
            proc.wq_timeout_marker.store(0x3503, Ordering::Release);
            let code = 0x3500 + case as i32;
            assert_eq!(
                request_process_exit_locked(&mut proc, code, case as u64),
                FatalExitPost::Kick,
            );
            let actively_running =
                on_cpu && matches!(state, ProcessState::Running | ProcessState::Ready);
            let expected = if state == ProcessState::Provisioning {
                ProcessState::Provisioning
            } else if !actively_running && state != ProcessState::Ready
                || (state == ProcessState::Ready && stopped)
            {
                ProcessState::Ready
            } else {
                state
            };
            assert_eq!(proc.state, expected);
            assert!(!proc.stopped);
            assert_eq!(proc.on_cpu.load(Ordering::Acquire), on_cpu);
            assert_eq!(proc.socket_timeout_marker.load(Ordering::Acquire), 0x3501);
            assert_eq!(proc.wq_timeout_marker.load(Ordering::Acquire), 0x3503);
            assert!(proc.pending_kill.load(Ordering::Acquire));
            assert_eq!(proc.pending_exit_code.load(Ordering::Acquire), code);
            case += 1;
        }
    }

    // A first publication kicks; a redundant, already-runnable repost only
    // updates the code and cannot amplify cross-CPU IPIs.
    proc.state = ProcessState::Ready;
    proc.stopped = false;
    proc.on_cpu.store(false, Ordering::Release);
    proc.pending_kill.store(false, Ordering::Release);
    assert_eq!(
        request_process_exit_locked(&mut proc, 0x35ff, 100),
        FatalExitPost::Kick,
    );
    assert_eq!(
        request_process_exit_locked(&mut proc, 0x35fe, 101),
        FatalExitPost::Posted,
    );
    assert_eq!(proc.pending_exit_code.load(Ordering::Acquire), 0x35fe);

    // A repost repairs a task that was re-parked by stale state and must kick.
    proc.state = ProcessState::Blocked;
    assert_eq!(
        request_process_exit_locked(&mut proc, 0x35fd, 102),
        FatalExitPost::Kick,
    );
    assert_eq!(proc.state, ProcessState::Ready);

    // Both lock-serialized race orders give fatal exit precedence over stop.
    proc.state = ProcessState::Blocked;
    proc.stopped = false;
    proc.pending_kill.store(false, Ordering::Release);
    assert!(try_mark_job_control_stopped_locked(&mut proc));
    assert_eq!(
        request_process_exit_locked(&mut proc, 0x35fc, 103),
        FatalExitPost::Kick,
    );
    assert!(!proc.stopped);
    assert!(!try_mark_job_control_stopped_locked(&mut proc));
    assert!(!proc.stopped);
    assert_eq!(proc.pending_exit_code.load(Ordering::Acquire), 0x35fc);

    for terminal in [ProcessState::Zombie, ProcessState::Terminated] {
        proc.state = terminal;
        proc.stopped = true;
        proc.pending_kill.store(false, Ordering::Release);
        proc.pending_exit_code.store(7, Ordering::Release);
        assert_eq!(
            request_process_exit_locked(&mut proc, 99, 200),
            FatalExitPost::None,
        );
        assert_eq!(proc.state, terminal);
        assert!(proc.stopped);
        assert!(!proc.pending_kill.load(Ordering::Acquire));
        assert_eq!(proc.pending_exit_code.load(Ordering::Acquire), 7);
    }
}

/// R115-1 FIX: Consume a pending cross-CPU exit request for the given PID.
///
/// Returns `Some(exit_code)` if an exit was requested, otherwise `None`.
/// Called from the syscall return path on the CPU that is actually running
/// the target thread, ensuring termination happens locally (no cross-CPU UAF).
pub fn take_pending_process_exit(pid: ProcessId) -> Option<i32> {
    let proc_arc = get_process(pid)?;
    let proc = proc_arc.lock();

    if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
        // Clear stale flag so it doesn't linger in diagnostics.
        proc.pending_kill.store(false, Ordering::Relaxed);
        return None;
    }

    // Swap the flag atomically; Acquire pairs with the Release store in
    // request_process_exit() to ensure we see the correct exit_code.
    if !proc.pending_kill.swap(false, Ordering::AcqRel) {
        return None;
    }

    Some(proc.pending_exit_code.load(Ordering::Acquire))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqExitDefer {
    NoRequest,
    Retry,
    Queued,
}

/// RF178-35: transactionally move a pending fatal request into the fixed IRQ
/// termination queue. Contention or a full queue returns `Retry` without
/// consuming `pending_kill`; only `Queued` provisionally marks the PCB Zombie.
pub fn try_defer_pending_process_exit(pid: ProcessId) -> IrqExitDefer {
    let proc_arc = match try_get_process(pid) {
        None => return IrqExitDefer::Retry,
        Some(None) => return IrqExitDefer::NoRequest,
        Some(Some(proc_arc)) => proc_arc,
    };
    let mut proc = match proc_arc.try_lock() {
        Some(proc) => proc,
        None => return IrqExitDefer::Retry,
    };

    if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
        proc.pending_kill.store(false, Ordering::Relaxed);
        return IrqExitDefer::NoRequest;
    }
    if !proc.pending_kill.load(Ordering::Acquire) {
        return IrqExitDefer::NoRequest;
    }
    let exit_code = proc.pending_exit_code.load(Ordering::Acquire);
    if !defer_irq_terminate(pid, exit_code) {
        return IrqExitDefer::Retry;
    }

    // The queue's NONRUNNABLE claim already excludes scheduler admission.
    // Only after that claim succeeds may the IRQ path consume the request and
    // publish the provisional lifecycle state used by deferred teardown.
    proc.state = ProcessState::Zombie;
    proc.exit_code = Some(exit_code);
    proc.pending_kill.store(false, Ordering::Release);
    IrqExitDefer::Queued
}

/// 设置当前进程ID
///
/// R67-4 FIX: Writes to per-CPU storage to avoid cross-CPU races.
///
/// R91-1 FIX: Lock-free atomic store. Uses Relaxed ordering because this is
/// per-CPU data only written by the owning CPU's scheduler and read by the
/// same CPU's IRQ handler. No cross-CPU visibility is needed.
pub fn set_current_pid(pid: Option<ProcessId>) {
    let raw = pid.unwrap_or(0);
    CURRENT_PID.with(|current| current.store(raw, Ordering::Relaxed));
}

// ========== 进程凭证访问 (DAC支持) ==========

/// 进程凭证结构
#[derive(Debug)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub supplementary_groups: AdmittedVec<u32>,
}

/// R186-18: credentials and their mutation generation share one Arc identity.
///
/// `CLONE_THREAD` siblings already share the credential lock; keeping the
/// generation in the same object ensures a mutation by any sibling invalidates
/// every opener's snapshot. Writers publish the generation after a successful
/// mutation while still holding the write lock. Final authorization snapshots
/// take the read lock before checking the generation, so they cannot observe new
/// credentials paired with the old generation.
#[derive(Debug)]
pub struct SharedCredentials {
    /// Serializes credential-changing transactions against both ordinary
    /// credential readers and authorization spans that include side effects
    /// outside the credential lock (for example VFS create/truncate).
    authorization_state: AtomicUsize,
    credentials: RwLock<Credentials>,
    generation: AtomicU64,
}

enum CredentialMutation<T> {
    Changed(T),
    Unchanged(T),
}

impl SharedCredentials {
    const AUTH_READER: usize = 2;
    const AUTH_WRITER: usize = 1;
    const AUTH_SPIN_BUDGET: u32 = 64;

    #[inline]
    fn wait_for_authorization_turn(spins: &mut u32) {
        if *spins < Self::AUTH_SPIN_BUDGET {
            *spins += 1;
            core::hint::spin_loop();
        } else {
            *spins = 0;
            crate::scheduler_hook::force_reschedule();
        }
    }

    pub fn new(credentials: Credentials) -> Self {
        Self {
            authorization_state: AtomicUsize::new(0),
            credentials: RwLock::new(credentials),
            generation: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[inline]
    fn publish_mutation(&self) {
        // lint-fetch-add: allow - generation counter, wrapping is safe
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn try_acquire_read_admission(&self) -> Option<CredentialReadAdmission<'_>> {
        let state = self.authorization_state.load(Ordering::Acquire);
        if state & Self::AUTH_WRITER != 0 {
            return None;
        }
        let next = state
            .checked_add(Self::AUTH_READER)
            .expect("credential reader count overflow");
        self.authorization_state
            .compare_exchange(state, next, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| CredentialReadAdmission { identity: self })
    }

    /// Nonblocking read-only access for lock-held and recovery paths. Ordinary
    /// readers participate in the same writer-fair admission gate as long-lived
    /// authorization tokens; once a writer claims admission, callers fail
    /// closed and may retry without yielding under an outer PCB/VFS lock.
    #[inline]
    pub fn try_read(&self) -> Option<CredentialReadGuard<'_>> {
        let admission = self.try_acquire_read_admission()?;
        let credentials = self.credentials.try_read()?;
        Some(CredentialReadGuard {
            credentials,
            _admission: admission,
        })
    }

    /// Begin an owned authorization span. Runtime credential writers cannot
    /// enter until every returned token is dropped.
    pub fn begin_authorization(self: &Arc<Self>) -> CredentialAuthorization {
        let mut spins = 0;
        loop {
            let state = self.authorization_state.load(Ordering::Acquire);
            if state & Self::AUTH_WRITER != 0 {
                Self::wait_for_authorization_turn(&mut spins);
                continue;
            }
            let next = state
                .checked_add(Self::AUTH_READER)
                .expect("credential authorization reader count overflow");
            if self
                .authorization_state
                .compare_exchange_weak(state, next, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return CredentialAuthorization {
                    identity: Arc::clone(self),
                };
            }
        }
    }

    /// Single-attempt admission for callers that cannot yield because they
    /// already hold an outer transaction lock. A queued writer wins; callers
    /// fail closed and may retry the syscall.
    pub fn try_begin_authorization(self: &Arc<Self>) -> Option<CredentialAuthorization> {
        let state = self.authorization_state.load(Ordering::Acquire);
        if state & Self::AUTH_WRITER != 0 {
            return None;
        }
        let next = state
            .checked_add(Self::AUTH_READER)
            .expect("credential authorization reader count overflow");
        self.authorization_state
            .compare_exchange(state, next, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| CredentialAuthorization {
                identity: Arc::clone(self),
            })
    }

    fn mutate<T>(
        &self,
        mutation: impl FnOnce(&mut Credentials) -> Result<CredentialMutation<T>, CredentialsError>,
    ) -> Result<T, CredentialsError> {
        let _operation = CredentialMutationGuard::acquire(self);
        let mut credentials = self.credentials.write();
        match mutation(&mut credentials)? {
            CredentialMutation::Changed(value) => {
                self.publish_mutation();
                Ok(value)
            }
            CredentialMutation::Unchanged(value) => Ok(value),
        }
    }

    /// Replace credentials before the PCB is published. This is construction,
    /// not a runtime authorization transition, so the initial generation stays
    /// at zero. The assertion prevents accidental use on a live identity.
    fn replace_unpublished(&self, credentials: Credentials) {
        let _operation = CredentialMutationGuard::acquire(self);
        assert_eq!(
            self.generation(),
            0,
            "credential identity replacement attempted after runtime mutation"
        );
        *self.credentials.write() = credentials;
    }
}

/// Owned proof that one exact credential identity cannot mutate for the
/// lifetime of an authorization/publication transaction.
pub struct CredentialAuthorization {
    identity: Arc<SharedCredentials>,
}

struct CredentialReadAdmission<'a> {
    identity: &'a SharedCredentials,
}

impl Drop for CredentialReadAdmission<'_> {
    fn drop(&mut self) {
        let previous = self
            .identity
            .authorization_state
            .fetch_sub(SharedCredentials::AUTH_READER, Ordering::Release);
        assert!(previous >= SharedCredentials::AUTH_READER);
    }
}

/// Composite ordinary credential reader. Field order is intentional: Rust
/// drops the RwLock guard before the admission unit, so a queued writer can
/// never enter the underlying write lock while this read guard remains live.
pub struct CredentialReadGuard<'a> {
    credentials: spin::RwLockReadGuard<'a, Credentials>,
    _admission: CredentialReadAdmission<'a>,
}

impl core::ops::Deref for CredentialReadGuard<'_> {
    type Target = Credentials;

    fn deref(&self) -> &Self::Target {
        &self.credentials
    }
}

pub struct CapabilityTableAuthority {
    table: Arc<CapTable>,
}

pub(crate) struct CapabilityTableInheritance {
    table: Arc<CapTable>,
}

impl CredentialAuthorization {
    #[inline]
    pub fn read(&self) -> spin::RwLockReadGuard<'_, Credentials> {
        // This token already owns one reader unit. Reopening admission here
        // could deadlock behind a queued writer that is waiting for this exact
        // authorization span to complete.
        self.identity.credentials.read()
    }

    #[inline]
    fn matches(&self, identity: &Arc<SharedCredentials>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }

    /// Derive a nested token without reopening reader admission. A queued
    /// writer may already own the odd pending bit, but the existing token proves
    /// mutation cannot start until both reader units are released.
    pub fn derive(&self) -> Self {
        let mut state = self.identity.authorization_state.load(Ordering::Acquire);
        loop {
            assert!(state >= SharedCredentials::AUTH_READER);
            let next = state
                .checked_add(SharedCredentials::AUTH_READER)
                .expect("credential authorization reader count overflow");
            match self.identity.authorization_state.compare_exchange_weak(
                state,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        Self {
            identity: Arc::clone(&self.identity),
        }
    }
}

impl Drop for CredentialAuthorization {
    fn drop(&mut self) {
        let previous = self
            .identity
            .authorization_state
            .fetch_sub(SharedCredentials::AUTH_READER, Ordering::Release);
        assert!(previous >= SharedCredentials::AUTH_READER);
    }
}

struct CredentialMutationGuard<'a> {
    identity: &'a SharedCredentials,
}

impl<'a> CredentialMutationGuard<'a> {
    fn try_claim(identity: &'a SharedCredentials) -> bool {
        let state = identity.authorization_state.load(Ordering::Acquire);
        state & SharedCredentials::AUTH_WRITER == 0
            && identity
                .authorization_state
                .compare_exchange(
                    state,
                    state | SharedCredentials::AUTH_WRITER,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    fn acquire(identity: &'a SharedCredentials) -> Self {
        let mut spins = 0;
        loop {
            if Self::try_claim(identity) {
                break;
            }
            SharedCredentials::wait_for_authorization_turn(&mut spins);
        }

        // Owning the odd bit closes reader admission. Drain readers that
        // linearized before the writer claim; no later reader can barge.
        while identity.authorization_state.load(Ordering::Acquire) != SharedCredentials::AUTH_WRITER
        {
            SharedCredentials::wait_for_authorization_turn(&mut spins);
        }
        Self { identity }
    }
}

impl Drop for CredentialMutationGuard<'_> {
    fn drop(&mut self) {
        let previous = self.identity.authorization_state.swap(0, Ordering::Release);
        assert_eq!(previous, SharedCredentials::AUTH_WRITER);
    }
}

#[cfg(test)]
mod credential_gate_tests {
    use super::*;

    fn test_identity() -> SharedCredentials {
        SharedCredentials::new(Credentials {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            supplementary_groups: AdmittedVec::new(HeapClass::CoreProcess),
        })
    }

    #[test]
    fn rf186_credential_writer_claim_blocks_ordinary_reader_barging() {
        let identity = test_identity();
        let reader = identity.try_read().expect("initial ordinary reader");
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_READER
        );

        assert!(CredentialMutationGuard::try_claim(&identity));
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_READER | SharedCredentials::AUTH_WRITER
        );
        assert!(identity.try_read().is_none());

        drop(reader);
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_WRITER
        );
        drop(CredentialMutationGuard {
            identity: &identity,
        });
        assert_eq!(identity.authorization_state.load(Ordering::Acquire), 0);
    }

    #[test]
    fn rf186_derived_authorization_accounts_behind_pending_writer() {
        let identity = Arc::new(test_identity());
        let authorization = identity.begin_authorization();
        let derived = authorization.derive();
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_READER * 2
        );

        assert!(CredentialMutationGuard::try_claim(&identity));
        assert!(identity.try_begin_authorization().is_none());
        drop(derived);
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_READER | SharedCredentials::AUTH_WRITER
        );
        drop(authorization);
        assert_eq!(
            identity.authorization_state.load(Ordering::Acquire),
            SharedCredentials::AUTH_WRITER
        );
        drop(CredentialMutationGuard {
            identity: identity.as_ref(),
        });
    }
}

/// Allocation-free scalar credential snapshot used by authorization callers.
#[derive(Debug, Clone, Copy)]
pub struct CredentialIds {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsError {
    NoCurrentProcess,
    PermissionDenied,
    TooManyGroups,
    OutOfMemory,
}

/// 获取当前进程的凭证
///
/// R39-3 FIX: 从共享凭证结构读取，线程间共享
/// 返回 None 如果没有当前进程
pub fn current_credentials() -> Option<CredentialIds> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    let creds = proc.credentials.try_read()?;
    Some(CredentialIds {
        uid: creds.uid,
        gid: creds.gid,
        euid: creds.euid,
        egid: creds.egid,
    })
}

/// 获取当前进程的有效用户ID
pub fn current_euid() -> Option<u32> {
    current_credentials().map(|c| c.euid)
}

/// R133-1 FIX: 获取当前进程的 host 级有效用户ID（映射后的 euid）。
///
/// User namespace 内的 euid 是命名空间相对的。该函数将当前进程的
/// namespace euid 通过 UserNamespace::map_uid_from_ns() 转换为 host UID。
/// 对于 root namespace 进程，map_uid_from_ns 返回 identity（input == output）。
///
/// 如果 UID 未映射，返回 OVERFLOW_UID (65534) 以确保 fail-closed。
pub fn current_host_euid() -> Option<u32> {
    const OVERFLOW_UID: u32 = 65534;

    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();

    let ns_euid = proc.credentials.try_read()?.euid;
    let user_ns = proc.user_ns.clone();
    // Drop locks before calling into user_ns to avoid holding PROCESS_TABLE
    // across the uid_map read lock.
    drop(proc);
    drop(table);

    Some(user_ns.map_uid_from_ns(ns_euid).unwrap_or(OVERFLOW_UID))
}

/// R133-1 FIX: 判断当前进程是否为 host root（host-mapped euid == 0）。
///
/// Host-global privilege gates (audit, FIPS, trace, cgroup governance,
/// network device moves) MUST use this function instead of checking
/// `euid == 0`, which only proves namespace-level root.
#[inline]
pub fn current_is_host_root() -> bool {
    current_host_euid() == Some(0)
}

/// 获取当前进程的有效组ID
pub fn current_egid() -> Option<u32> {
    current_credentials().map(|c| c.egid)
}

/// R135-1 FIX: 获取当前进程的 host 级有效组ID（映射后的 egid）。
///
/// User namespace 内的 egid 是命名空间相对的。该函数将当前进程的
/// namespace egid 通过 UserNamespace::map_gid_from_ns() 转换为 host GID。
/// 对于 root namespace 进程，map_gid_from_ns 返回 identity（input == output）。
///
/// 如果 GID 未映射，返回 OVERFLOW_GID (65534) 以确保 fail-closed。
pub fn current_host_egid() -> Option<u32> {
    const OVERFLOW_GID: u32 = 65534;

    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();

    let ns_egid = proc.credentials.try_read()?.egid;
    let user_ns = proc.user_ns.clone();
    // Drop locks before calling into user_ns to avoid holding PROCESS_TABLE
    // across the gid_map read lock.
    drop(proc);
    drop(table);

    Some(user_ns.map_gid_from_ns(ns_egid).unwrap_or(OVERFLOW_GID))
}

/// F.1: 获取当前进程的挂载命名空间
///
/// Returns the current process's mount namespace, used by VFS for
/// namespace-aware path resolution.
pub fn current_mount_ns() -> Option<Arc<crate::mount_namespace::MountNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.mount_ns.clone())
}

/// F.1: 获取当前进程的IPC命名空间
///
/// Returns the current process's IPC namespace, used for isolating
/// System V IPC resources (message queues, semaphores, shared memory).
pub fn current_ipc_ns() -> Option<Arc<crate::ipc_namespace::IpcNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.ipc_ns.clone())
}

/// F.1: 获取当前进程的网络命名空间
///
/// Returns the current process's network namespace, used for isolating
/// network devices, sockets, and routing tables.
pub fn current_net_ns() -> Option<Arc<crate::net_namespace::NetNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.net_ns.clone())
}

/// R75-2 FIX: 获取当前进程的 IPC 命名空间 ID
///
/// Returns the current process's IPC namespace identifier, used for
/// partitioning IPC endpoint tables by namespace.
#[inline]
pub fn current_ipc_ns_id() -> Option<cap::NamespaceId> {
    current_ipc_ns().map(|ns| ns.id())
}

/// R75-1 FIX: 获取当前进程的网络命名空间 ID
///
/// Returns the current process's network namespace identifier, used for
/// partitioning socket tables and port bindings by namespace.
#[inline]
pub fn current_net_ns_id() -> Option<cap::NamespaceId> {
    current_net_ns().map(|ns| ns.id())
}

/// F.2: 获取当前进程的 Cgroup ID
///
/// Returns the current process's cgroup identifier, used for resource
/// accounting and limit enforcement by cgroup controllers.
#[inline]
pub fn current_cgroup_id() -> Option<crate::cgroup::CgroupId> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.cgroup_id)
}

/// 获取当前进程的附属组列表
///
/// R39-3 FIX: 从共享凭证结构读取
/// 返回附属组ID的克隆列表，如果没有当前进程则返回 None
pub fn current_supplementary_groups() -> Result<Option<AdmittedVec<u32>>, CredentialsError> {
    let Some(pid) = current_pid() else {
        return Ok(None);
    };
    let Some(proc) = get_process(pid) else {
        return Ok(None);
    };
    let credentials = Arc::clone(&proc.lock().credentials);
    let creds = credentials
        .try_read()
        .ok_or(CredentialsError::PermissionDenied)?;
    AdmittedVec::try_copy_from_slice(HeapClass::CoreProcess, &creds.supplementary_groups)
        .map(Some)
        .map_err(|_| CredentialsError::OutOfMemory)
}

/// R135-1 FIX: 获取当前进程的 host 级附属组列表（映射后的 supplementary groups）。
///
/// 将当前进程的 namespace supplementary groups 通过
/// UserNamespace::map_gid_from_ns() 转换为 host GID 列表。
/// 对于 root namespace 进程，该映射为 identity（input == output）。
///
/// 未映射的 GID 将被替换为 OVERFLOW_GID (65534) 以确保 fail-closed。
pub fn current_host_supplementary_groups() -> Result<Option<AdmittedVec<u32>>, CredentialsError> {
    const OVERFLOW_GID: u32 = 65534;

    let Some((ns_groups, len, user_ns)) = snapshot_current_groups() else {
        return Ok(None);
    };
    let mut host_groups = AdmittedVec::new(HeapClass::CoreProcess);
    host_groups
        .try_reserve_exact(len)
        .map_err(|_| CredentialsError::OutOfMemory)?;
    for &group in &ns_groups[..len] {
        host_groups
            .push_reserved(user_ns.map_gid_from_ns(group).unwrap_or(OVERFLOW_GID))
            .map_err(|_| CredentialsError::OutOfMemory)?;
    }
    normalize_groups(&mut host_groups);
    Ok(Some(host_groups))
}

/// RF180-17/RF180-19: allocation-free host-group authorization predicate.
pub fn current_in_host_supplementary_group(host_gid: u32) -> Option<bool> {
    const OVERFLOW_GID: u32 = 65534;
    let (groups, len, user_ns) = snapshot_current_groups()?;
    Some(
        groups[..len]
            .iter()
            .any(|&group| user_ns.map_gid_from_ns(group).unwrap_or(OVERFLOW_GID) == host_gid),
    )
}

fn snapshot_current_groups() -> Option<(
    [u32; NGROUPS_MAX],
    usize,
    Arc<crate::user_namespace::UserNamespace>,
)> {
    let pid = current_pid()?;
    let process = get_process(pid)?;
    let proc = process.lock();
    let credentials = proc.credentials.try_read()?;
    let len = credentials.supplementary_groups.len().min(NGROUPS_MAX);
    let mut groups = [0u32; NGROUPS_MAX];
    groups[..len].copy_from_slice(&credentials.supplementary_groups[..len]);
    Some((groups, len, Arc::clone(&proc.user_ns)))
}

fn normalize_groups(groups: &mut AdmittedVec<u32>) {
    groups.sort_unstable();
    let mut previous = None;
    groups.retain(|group| {
        if previous == Some(*group) {
            false
        } else {
            previous = Some(*group);
            true
        }
    });
}

/// Maximum number of supplementary groups per process
///
/// This limit prevents memory exhaustion and keeps permission check performance reasonable.
/// Linux uses NGROUPS_MAX (typically 65536), but we use a smaller value for kernel simplicity.
pub const NGROUPS_MAX: usize = 256;

/// 设置当前进程的附属组列表
///
/// 会自动去重并排序，方便后续查找。
/// 最多保留 NGROUPS_MAX 个组以防止资源耗尽。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以修改附属组列表。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `groups` - 新的附属组列表
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn set_current_supplementary_groups(groups: &[u32]) -> Result<(), CredentialsError> {
    if groups.len() > NGROUPS_MAX {
        return Err(CredentialsError::TooManyGroups);
    }
    let pid = current_pid().ok_or(CredentialsError::NoCurrentProcess)?;
    let process = get_process(pid).ok_or(CredentialsError::NoCurrentProcess)?;
    let credentials = {
        let proc = process.lock();
        Arc::clone(&proc.credentials)
    };
    let old = credentials.mutate(|creds| {
        if creds.euid != 0 {
            return Err(CredentialsError::PermissionDenied);
        }

        // RF180-17 FIX: complete the admitted replacement before publication.
        let mut replacement = AdmittedVec::try_copy_from_slice(HeapClass::CoreProcess, groups)
            .map_err(|_| CredentialsError::OutOfMemory)?;
        normalize_groups(&mut replacement);
        if creds.supplementary_groups.as_slice() == replacement.as_slice() {
            return Ok(CredentialMutation::Unchanged(None));
        }
        Ok(CredentialMutation::Changed(Some(core::mem::replace(
            &mut creds.supplementary_groups,
            replacement,
        ))))
    })?;
    drop(old);
    Ok(())
}

/// 向当前进程添加一个附属组
///
/// 如果该组已存在则不会重复添加。
/// 如果已达到 NGROUPS_MAX 上限，添加操作被忽略。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以添加附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要添加的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn add_supplementary_group(gid: u32) -> Result<(), CredentialsError> {
    let pid = current_pid().ok_or(CredentialsError::NoCurrentProcess)?;
    let process = get_process(pid).ok_or(CredentialsError::NoCurrentProcess)?;
    let credentials = {
        let proc = process.lock();
        Arc::clone(&proc.credentials)
    };
    credentials.mutate(|creds| {
        if creds.euid != 0 {
            return Err(CredentialsError::PermissionDenied);
        }

        if creds.supplementary_groups.contains(&gid) {
            return Ok(CredentialMutation::Unchanged(()));
        }
        if creds.supplementary_groups.len() >= NGROUPS_MAX {
            return Err(CredentialsError::TooManyGroups);
        }
        creds
            .supplementary_groups
            .try_reserve(1)
            .map_err(|_| CredentialsError::OutOfMemory)?;
        creds
            .supplementary_groups
            .push_reserved(gid)
            .map_err(|_| CredentialsError::OutOfMemory)?;
        normalize_groups(&mut creds.supplementary_groups);
        Ok(CredentialMutation::Changed(()))
    })
}

/// 从当前进程移除一个附属组
///
/// 如果该组不存在则无操作
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以移除附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要移除的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn remove_supplementary_group(gid: u32) -> Result<(), CredentialsError> {
    let pid = current_pid().ok_or(CredentialsError::NoCurrentProcess)?;
    let process = get_process(pid).ok_or(CredentialsError::NoCurrentProcess)?;
    let credentials = {
        let proc = process.lock();
        Arc::clone(&proc.credentials)
    };
    credentials.mutate(|creds| {
        if creds.euid != 0 {
            return Err(CredentialsError::PermissionDenied);
        }

        let old_len = creds.supplementary_groups.len();
        creds.supplementary_groups.retain(|&g| g != gid);
        if creds.supplementary_groups.len() != old_len {
            Ok(CredentialMutation::Changed(()))
        } else {
            Ok(CredentialMutation::Unchanged(()))
        }
    })
}

/// 获取当前进程的umask
pub fn current_umask() -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.umask)
}

/// 设置当前进程的umask，返回旧的umask
pub fn set_current_umask(new_mask: u16) -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();
    let old = proc.umask;
    proc.umask = new_mask & 0o777; // 只保留权限位
    Some(old)
}

// ========== 能力表访问 ==========

/// Test the current process's aggregate capability rights without exposing its
/// mutable capability table to callers.
///
/// RF186-12: raw `CapTable` access made unmediated mint/revoke APIs reachable
/// outside kernel-core. Keep production tables private and export only the
/// narrow authorization query required by policy gates. Missing current-process
/// state fails closed.
pub fn current_has_cap_rights(rights: cap::CapRights) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    let table = PROCESS_TABLE.lock();
    let Some(Some(process)) = table.get(pid) else {
        return false;
    };
    let authorized = process.lock().cap_table.has_rights(rights);
    authorized
}

// ========== Seccomp/Pledge 沙箱访问 ==========

use seccomp::SeccompVerdict;

/// 评估当前进程的 seccomp 过滤器
///
/// 在系统调用分发前调用此函数检查 seccomp 过滤器和 pledge 限制。
///
/// # Arguments
/// * `syscall_nr` - 系统调用号
/// * `args` - 系统调用参数数组 (6 个参数)
///
/// # Returns
/// 返回 seccomp 评估结果:
/// - `SeccompAction::Allow` - 允许执行
/// - `SeccompAction::Kill` - 终止进程
/// - `SeccompAction::Errno(e)` - 返回错误码
/// - `SeccompAction::Trap` - 触发 SIGSYS
/// - `SeccompAction::Log` - 记录日志但允许执行
pub fn evaluate_seccomp(syscall_nr: u64, args: &[u64; 6]) -> SeccompVerdict {
    let pid = match current_pid() {
        Some(p) => p,
        None => return SeccompVerdict::allow(),
    };

    // R148-I1 FIX: Use get_process() instead of holding PROCESS_TABLE lock
    // for the entire seccomp evaluation.  get_process() briefly locks the
    // table to clone the Arc, then releases.  Only the per-process Mutex is
    // held during the O(n) filter evaluation, removing PROCESS_TABLE as a
    // global contention point on every syscall.
    let proc_arc = match get_process(pid) {
        Some(p) => p,
        None => return SeccompVerdict::allow(),
    };
    let proc = proc_arc.lock();

    // First check pledge if set
    if let Some(ref pledge) = proc.pledge_state {
        if !pledge.allows(syscall_nr, args) {
            return SeccompVerdict::kill(0);
        }
    }

    // Then evaluate seccomp filters
    if proc.seccomp_state.has_filters() {
        let mut verdict = proc.seccomp_state.evaluate(syscall_nr, args);

        // R25-5 FIX: Honor log_violations flag
        // When log_violations is set, convert Allow to Log for auditing
        if proc.seccomp_state.log_violations {
            if matches!(verdict.action, seccomp::SeccompAction::Allow) {
                verdict.action = seccomp::SeccompAction::Log;
            }
        }

        verdict
    } else {
        SeccompVerdict::allow()
    }
}

/// 检查当前进程是否启用了 seccomp
pub fn has_seccomp_enabled() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    let table = PROCESS_TABLE.lock();
    let slot = match table.get(pid) {
        Some(s) => s,
        None => return false,
    };
    let proc = match slot.as_ref() {
        Some(p) => p.lock(),
        None => return false,
    };

    proc.seccomp_state.has_filters() || proc.pledge_state.is_some()
}

/// 检查当前进程是否设置了 no_new_privs
pub fn has_no_new_privs() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    let table = PROCESS_TABLE.lock();
    let slot = match table.get(pid) {
        Some(s) => s,
        None => return false,
    };
    let proc = match slot.as_ref() {
        Some(p) => p.lock(),
        None => return false,
    };

    proc.seccomp_state.no_new_privs
}

/// H.3 KPTI: Look up the user PML4 physical address for a given kernel memory_space.
///
/// Scans the process table for a process whose `memory_space` matches the given
/// kernel CR3, returning its `user_memory_space` (0 if KPTI is not active for that
/// process, or if no match is found).
///
/// R118-6 FIX: This function is now only used by `sync_kpti_cr3()` as a recovery
/// path when the caller updates `user_memory_space` in the PCB without changing CR3.
/// The scheduler hot path passes `user_memory_space` directly to
/// `activate_memory_space()`, avoiding the O(n) scan + Mutex acquisition.
///
/// # Performance
///
/// Linear scan of MAX_PID slots — intentionally kept out of the scheduler hot path.
fn lookup_user_memory_space(kernel_memory_space: usize) -> usize {
    let table = PROCESS_TABLE.lock();
    for slot in table.iter() {
        if let Some(arc) = slot {
            let proc = arc.lock();
            if proc.memory_space == kernel_memory_space {
                return proc.user_memory_space;
            }
        }
    }
    0
}

/// 激活指定的地址空间
///
/// 切换到进程的页表。memory_space 为 0 时使用引导时的页表（内核共享页表）。
/// 调用 Cr3::write 会刷新 TLB，确保新地址空间立即生效。
///
/// # R118-6 FIX: Direct user_memory_space parameter
///
/// The optional `user_memory_space` parameter eliminates the need for
/// `lookup_user_memory_space()` in the scheduler hot path.  Callers that know
/// the user PML4 (context switch, sys_exec) pass it directly; callers that
/// don't care (boot CR3, test code) pass `None`.
///
/// # Arguments
/// * `memory_space` - 进程的 PML4 物理地址，0 表示使用引导页表
/// * `user_memory_space` - H.3 KPTI user PML4 physical address.
///   `Some(phys)` installs a dual KPTI context; `None` skips KPTI update
///   unless CR3 actually changes (in which case single-root is installed).
///
/// # Safety
/// 这个函数会修改 CR3 寄存器，调用者必须确保：
/// - memory_space 指向有效的 PML4 页表
/// - 内核代码和数据在新旧页表中都有正确映射
pub fn activate_memory_space(memory_space: usize, user_memory_space: Option<usize>) {
    let (boot_frame, boot_flags) = *BOOT_CR3;
    let (current_frame, _) = Cr3::read();

    let (target_frame, target_flags) = if memory_space == 0 {
        // 使用引导页表（内核进程或尚未分配独立页表的进程）
        (boot_frame, boot_flags)
    } else {
        // 使用进程的独立页表
        (
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64)),
            boot_flags, // 使用相同的 CR3 标志
        )
    };

    let target_cr3_phys = target_frame.start_address().as_u64();
    let need_cr3_switch = target_frame != current_frame;
    // Update KPTI state when: (a) CR3 is changing, or (b) caller explicitly
    // provides a user_memory_space (e.g., sys_exec re-sync after Phase 4).
    let should_update_kpti = need_cr3_switch || user_memory_space.is_some();

    // R118-6 safety net: When KPTI is globally enabled, context-switching to a
    // user address space (memory_space != 0) without an explicit user_memory_space
    // is likely a caller bug. Debug-assert to catch missed call sites early.
    #[cfg(debug_assertions)]
    if memory_space != 0 && user_memory_space.is_none() && security::is_kpti_enabled() {
        klog!(Warn,
            "activate_memory_space: KPTI enabled but user_memory_space=None for cr3=0x{:x} — KPTI will be single-root for this switch",
            memory_space
        );
    }

    // 只有当目标页表与当前不同时才切换（避免不必要的 TLB 刷新）
    if need_cr3_switch {
        unsafe { Cr3::write(target_frame, target_flags) };
    }

    // H.3 KPTI: Keep per-CPU KPTI context in sync with the active address space.
    //
    // R118-6 FIX: Callers now pass user_memory_space directly, eliminating
    // the O(n) PROCESS_TABLE scan under Mutex inside without_interrupts.
    // This removes the NMI deadlock risk and improves context switch latency.
    if should_update_kpti {
        let user_cr3 = user_memory_space.unwrap_or(0);

        x86_64::instructions::interrupts::without_interrupts(|| {
            let kpti_ctx = if user_cr3 != 0 {
                security::KptiContext::dual(user_cr3 as u64, target_cr3_phys, 0)
            } else {
                security::KptiContext::single(target_cr3_phys)
            };

            security::install_kpti_context(kpti_ctx);

            // H.3 KPTI: Also update the per-CPU GS-addressable CR3 pair used
            // by the syscall entry/exit assembly trampoline.
            let user_cr3_val = if user_cr3 != 0 {
                user_cr3 as u64
            } else {
                target_cr3_phys
            };
            notify_kpti_cr3_update(user_cr3_val, target_cr3_phys);
        });
    }

    if need_cr3_switch {
        // R68 Architecture Improvement: Update per-address-space TLB tracking.
        //
        // This allows TLB shootdown to target only CPUs that might have TLB entries
        // for the affected address space, rather than broadcasting to all CPUs.
        // The tracking is used by collect_target_cpus() in tlb_shootdown.rs.
        //
        // # Race Condition Safety
        //
        // There's a window between the CR3 write and map update where another CPU's
        // shootdown for this CR3 could miss us. This is SAFE because:
        // - Writing CR3 flushes all non-global TLB entries on this CPU
        // - We have no stale entries to flush since our TLB is fresh
        // - Any subsequent TLB entries will be populated after the shootdown
        mm::tlb_shootdown::track_cr3_switch(target_cr3_phys);
    }
}

/// H.3 KPTI: Re-synchronize per-CPU KPTI CR3 pair for the currently loaded address space.
///
/// This must be called after `user_memory_space` is updated in the PCB but CR3 has
/// not changed (e.g., after `sys_execve` commits the new user PML4 into the PCB —
/// `activate_memory_space` already ran before the user PML4 existed, so the per-CPU
/// state was installed as "single" context).
///
/// The function re-reads the current CR3, looks up the corresponding `user_memory_space`,
/// and pushes the (user_cr3, kernel_cr3) pair to the per-CPU GS-addressable fields
/// used by the syscall assembly trampoline.
pub fn sync_kpti_cr3() {
    // R118-7 FIX: CR3 read moved inside without_interrupts to prevent TOCTOU.
    //
    // Previously, Cr3::read() was outside the interrupt-disabled section.
    // A timer IRQ between the read and the lookup could trigger a context switch,
    // changing CR3 to a different process's page table. The lookup would then
    // find the wrong (or no) user_memory_space, installing a stale KPTI context.
    x86_64::instructions::interrupts::without_interrupts(|| {
        let (current_frame, _) = Cr3::read();
        let current_cr3_phys = current_frame.start_address().as_u64();
        let memory_space = current_cr3_phys as usize;
        let user_cr3 = if memory_space != 0 {
            lookup_user_memory_space(memory_space)
        } else {
            0
        };

        let kpti_ctx = if user_cr3 != 0 {
            security::KptiContext::dual(user_cr3 as u64, current_cr3_phys, 0)
        } else {
            security::KptiContext::single(current_cr3_phys)
        };

        security::install_kpti_context(kpti_ctx);

        let user_cr3_val = if user_cr3 != 0 {
            user_cr3 as u64
        } else {
            current_cr3_phys
        };
        notify_kpti_cr3_update(user_cr3_val, current_cr3_phys);
    });
}

/// 获取进程
///
/// # Arguments
/// * `pid` - 进程 ID
///
/// # Returns
/// 如果进程存在，返回进程的 Arc 引用；否则返回 None
pub fn get_process(pid: ProcessId) -> Option<ProcessArc> {
    let table = PROCESS_TABLE.lock();
    table.get(pid).and_then(|slot| slot.clone())
}

/// R171-G5-1 FIX: non-blocking `PROCESS_TABLE` lookup for IRQ / timer-tick context.
///
/// Mirrors [`get_process`] but acquires `PROCESS_TABLE` with `try_lock`, so a
/// caller running in IRQ context (the socket-timeout tick scan in
/// `SocketWaiters::check_timeouts`, the timed-wait timer scan in
/// `wq_timeout_wake_by_seq`) never blocks on the table lock — closing the same
/// self-deadlock class as R169-2 / R170-1 (a writer holding `PROCESS_TABLE`
/// while the timer IRQ fires on the same CPU and re-enters the table).
///
/// Tri-state result (the contended case is DISTINCT from "process gone"):
/// - `None`            — the table was contended; the caller MUST defer (retry on
///                       a later tick) and MUST NOT treat this as "process gone".
/// - `Some(None)`      — the lock was taken and there is no live PCB for `pid`.
/// - `Some(Some(arc))` — the lock was taken and the live PCB was cloned out.
///
/// Only clones an `Arc` under the (briefly held) lock — no allocation — so it is
/// safe on the IRQ tick path.
pub fn try_get_process(pid: ProcessId) -> Option<Option<ProcessArc>> {
    let table = PROCESS_TABLE.try_lock()?;
    Some(table.get(pid).and_then(|slot| slot.clone()))
}

/// 注册调度器的清理回调，用于在 PCB 删除时同步调度器状态
pub fn register_cleanup_notifier(callback: SchedulerCleanupCallback) {
    *SCHEDULER_CLEANUP.lock() = Some(callback);
}

/// 注册IPC清理回调，用于在进程退出时清理其端点
pub fn register_ipc_cleanup(callback: IpcCleanupCallback) {
    *IPC_CLEANUP.lock() = Some(callback);
}

/// Register the scheduler's prepare/commit/cancel admission transaction.
pub fn register_scheduler_admission(
    reserve: SchedulerReserveCallback,
    commit: SchedulerCommitCallback,
    cancel: SchedulerCancelCallback,
) {
    *SCHEDULER_ADMISSION.lock() = Some(SchedulerAdmissionCallbacks {
        reserve,
        commit,
        cancel,
    });
}

/// 注册 futex 唤醒回调，用于线程退出时唤醒等待者
pub fn register_futex_wake(callback: FutexWakeCallback) {
    *FUTEX_WAKE.lock() = Some(callback);
}

/// 通知调度器进程已被移除
///
/// RF178-33 / P1-B: generation is load-bearing. Call only with the reaped
/// task's identity captured under the PCB lock before the slot was cleared.
fn notify_scheduler_process_removed(pid: ProcessId, generation: u64) {
    let callback = *SCHEDULER_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid, generation);
    }
}

/// 通知IPC子系统清理进程端点
/// R37-2 FIX (Codex review): Pass TGID to avoid re-locking the process in callback.
/// R75-2 FIX: Pass IPC namespace ID for per-namespace endpoint cleanup.
/// R180-5 FIX: Pass reaped generation so delayed cleanup cannot target a recycled PID.
fn notify_ipc_process_cleanup(
    pid: ProcessId,
    tgid: ProcessId,
    ipc_ns_id: cap::NamespaceId,
    generation: u64,
) {
    let callback = *IPC_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid, tgid, ipc_ns_id, generation);
    }
}

/// Fallibly reserve an exact scheduler queue entry before a process-creation
/// transaction reaches an irreversible commit point.
pub fn prepare_scheduler_add_process(
    process: ProcessArc,
) -> Result<SchedulerAddPermit, SchedulerAddError> {
    let callbacks = (*SCHEDULER_ADMISSION.lock()).ok_or(SchedulerAddError::Unavailable)?;
    let token = (callbacks.reserve)(process)?;
    Ok(SchedulerAddPermit {
        token: Some(token),
        commit: callbacks.commit,
        cancel: callbacks.cancel,
        armed: true,
    })
}

/// 通知 futex 唤醒等待者
///
/// 由线程退出时调用，用于 clear_child_tid 机制
fn notify_futex_wake(tgid: ProcessId, uaddr: usize, max_wake: usize) -> usize {
    let callback = *FUTEX_WAKE.lock();
    if let Some(cb) = callback {
        cb(tgid, uaddr, max_wake)
    } else {
        0
    }
}

/// E.5 Cpuset: Register callback for task joining a cpuset
///
/// Called by sched::cpuset during initialization to register its task_joined function.
pub fn register_cpuset_task_joined(callback: CpusetTaskJoinedCallback) {
    *CPUSET_TASK_JOINED.lock() = Some(callback);
}

/// E.5 Cpuset: Register callback for task leaving a cpuset
///
/// Called by sched::cpuset during initialization to register its task_left function.
pub fn register_cpuset_task_left(callback: CpusetTaskLeftCallback) {
    *CPUSET_TASK_LEFT.lock() = Some(callback);
}

/// E.5 Cpuset: Notify that a task joined a cpuset
///
/// Called when a new process is created via fork/clone.
pub fn notify_cpuset_task_joined(cpuset_id: u32) {
    let callback = *CPUSET_TASK_JOINED.lock();
    if let Some(cb) = callback {
        cb(cpuset_id);
    }
}

/// E.5 Cpuset: Notify that a task left a cpuset
///
/// Called when a process exits.
pub fn notify_cpuset_task_left(cpuset_id: u32) {
    let callback = *CPUSET_TASK_LEFT.lock();
    if let Some(cb) = callback {
        cb(cpuset_id);
    }
}

/// H.3 KPTI: Register callback to update per-CPU GS-addressable CR3 pair.
///
/// Called by main kernel during initialization to bridge kernel_core → arch.
/// The callback is `arch::arch_set_kpti_cr3s`.
pub fn register_kpti_cr3_callback(callback: KptiCr3UpdateCallback) {
    KPTI_CR3_UPDATE.call_once(|| callback);
}

/// H.3 KPTI: Update per-CPU GS-addressable CR3 pair via registered callback.
///
/// No-op if the callback has not been registered (early boot or KPTI disabled).
fn notify_kpti_cr3_update(user_cr3: u64, kernel_cr3: u64) {
    if let Some(cb) = KPTI_CR3_UPDATE.get().copied() {
        cb(user_cr3, kernel_cr3);
    }
}

// R155-6 FIX: Deferred IRQ termination queue.
// Timer IRQ handlers cannot safely run terminate_process() (blocking locks,
// heap allocation, deep call stack) on the interrupt stack. Instead, they
// enqueue the (pid, exit_code) here. The caller provisionally marks the exact
// PCB Zombie only after the slot claim succeeds; the next process-context
// drain_deferred_irq_terminates() call performs the full cleanup.
const MAX_DEFERRED_IRQ_KILLS: usize = 8;
static DEFERRED_IRQ_KILL_PIDS: [AtomicU64; MAX_DEFERRED_IRQ_KILLS] =
    [const { AtomicU64::new(0) }; MAX_DEFERRED_IRQ_KILLS];
static DEFERRED_IRQ_KILL_CODES: [AtomicI32; MAX_DEFERRED_IRQ_KILLS] =
    [const { AtomicI32::new(0) }; MAX_DEFERRED_IRQ_KILLS];
static DEFERRED_IRQ_KILL_PENDING: AtomicBool = AtomicBool::new(false);

// R170-5 FIX: scheduler-visibility companion set for IRQ-deferred kills,
// index-paired with DEFERRED_IRQ_KILL_PIDS. The R169-9 skip-predicate used to
// scan DEFERRED_IRQ_KILL_PIDS directly, but the drain's exactly-once `swap(0)`
// claim cleared that membership BEFORE `terminate_process` published `Zombie`
// — re-opening a [swap → Zombie] window on SMP where another CPU's scheduler
// saw `state == Ready && !is_pending_irq_kill` and re-selected the halting
// victim into its IRQs-off no-return halt loop (R170-5).
//
// Lifecycle: `defer_irq_terminate` CAS-claims NONRUNNABLE[i] FIRST (this is
// the slot-ownership claim; DEFERRED[i] then gets a plain store — invariant:
// DEFERRED[i] != 0 ⟹ NONRUNNABLE[i] == the same pid, established before the
// kill is drain-visible, so there is no publication gap and no rollback
// path). `is_pending_irq_kill` scans THIS set, whose membership spans
// [defer → Zombie-publish]. The entry is cleared by `terminate_process`
// ITSELF (value-keyed CAS, `clear_irq_kill_nonrunnable`) immediately after
// the Zombie store — strictly BEFORE `teardown_done` is published and before
// any internal `force_reschedule`, so a reaped-and-recycled pid can NEVER
// inherit a stale membership (recycling requires reap, which requires
// `Zombie && teardown_done`, which the clear precedes on the terminating
// thread). That kills the unbounded recycled-pid scheduler-skip the
// clear-after-terminate variant suffered from.
static IRQ_KILL_NONRUNNABLE_PIDS: [AtomicU64; MAX_DEFERRED_IRQ_KILLS] =
    [const { AtomicU64::new(0) }; MAX_DEFERRED_IRQ_KILLS];

fn defer_irq_terminate(pid: ProcessId, exit_code: i32) -> bool {
    for i in 0..MAX_DEFERRED_IRQ_KILLS {
        // R170-5 FIX: the NONRUNNABLE entry IS the slot claim (CAS) and is
        // published BEFORE the drain-visible DEFERRED store, so the scheduler
        // skip-predicate covers the kill from the instant it can be drained.
        if IRQ_KILL_NONRUNNABLE_PIDS[i].load(Ordering::Relaxed) == 0
            && IRQ_KILL_NONRUNNABLE_PIDS[i]
                .compare_exchange(0, pid as u64, Ordering::Release, Ordering::Relaxed)
                .is_ok()
        {
            // Store exit code BEFORE publishing the PID to the drain so a
            // concurrent swap can never read a stale code. The slot is OURS
            // (NONRUNNABLE claim), so plain stores suffice here.
            DEFERRED_IRQ_KILL_CODES[i].store(exit_code, Ordering::Relaxed);
            DEFERRED_IRQ_KILL_PIDS[i].store(pid as u64, Ordering::Release);
            DEFERRED_IRQ_KILL_PENDING.store(true, Ordering::Release);
            return true;
        }
    }
    false
}

/// R170-5 FIX: drop `pid` from the IRQ-kill non-runnable set. Called by
/// `terminate_process` (the teardown-claim WINNER) immediately after the
/// `Zombie` publish and strictly before `teardown_done` — see the set's doc.
/// Value-keyed CAS so a slot already re-claimed for a DIFFERENT pid is never
/// erased; iterates all slots so a hypothetical double-defer of one pid
/// cannot strand a duplicate entry. Lock-free; takes no locks.
fn clear_irq_kill_nonrunnable(pid: ProcessId) {
    let pid_raw = pid as u64;
    for i in 0..MAX_DEFERRED_IRQ_KILLS {
        let _ = IRQ_KILL_NONRUNNABLE_PIDS[i].compare_exchange(
            pid_raw,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}

/// R169-9 FIX: lock-free membership test for the IRQ-deferred-kill set.
///
/// A task killed from IRQ context (`defer_irq_terminate`) is queued for teardown
/// but may not yet be `Zombie` — if the IRQ path's `try_lock` to set `Zombie`
/// failed, the scheduler would otherwise re-select the still-`Ready` task and
/// resume it into its no-return `loop { hlt() }` (IRQs disabled), wedging the CPU
/// on UP before the deferred drain runs. The scheduler consults this predicate so
/// such a task is never selected; it idles via the scheduler (IRQs enabled) until
/// `drain_deferred_irq_terminates` → `terminate_process` marks it `Zombie` and the
/// reaper frees it.
///
/// R170-5 FIX: scans `IRQ_KILL_NONRUNNABLE_PIDS` (not the drain-claim set), so
/// membership now spans [defer → `Zombie`-publish] instead of [defer →
/// drain-`swap(0)`] — closing the SMP window where the drain's claim cleared
/// the predicate BEFORE `terminate_process` published `Zombie` and another
/// CPU could select/steal the still-`Ready` victim. Every scheduler admission
/// point checks this together with `state == Ready` under the held PCB lock,
/// so post-clear observers see `Zombie` (the clear is program-ordered after
/// the Zombie store's lock release on the terminating thread).
///
/// Lock-free (8 `Acquire` loads, no locks / no allocation), so it is safe to call
/// while holding the ready-queue and PCB locks.
pub fn is_pending_irq_kill(pid: ProcessId) -> bool {
    // 0 is the empty-slot marker (and a reserved pid), never a schedulable task.
    if pid == 0 {
        return false;
    }
    let pid_raw = pid as u64;
    for i in 0..MAX_DEFERRED_IRQ_KILLS {
        if IRQ_KILL_NONRUNNABLE_PIDS[i].load(Ordering::Acquire) == pid_raw {
            return true;
        }
    }
    false
}

/// R171 FIX (F2/F3): process-context kill predicate for INTERRUPTIBLE blocking
/// syscalls (accept/recv/pipe/stdin/wait/futex). True iff `pid` has a pending
/// kill that a blocking wait must observe and abort on (return EINTR /
/// self-terminate) instead of re-parking forever (the "unkillable blocked task"
/// class).
///
/// Predicate = `pending_kill` ONLY. `pending_kill` is set by
/// `request_process_exit` / `exit_group` (request_exit_group_atomic) BEFORE the
/// target is unblocked, so a woken blocked task observes it; the syscall
/// epilogue's `take_pending_process_exit` then turns it into REAL termination.
/// This is the ONLY kill path that reaches a task BLOCKED in a syscall.
///
/// We deliberately DO NOT consult `is_pending_irq_kill` (the IRQ-deferred path):
/// its tasks are reaped by `drain_deferred_irq_terminates` (terminate_process)
/// and skipped by the scheduler — NOT by the syscall epilogue. Returning EINTR
/// for such a task would unwind to an epilogue that does NOT terminate it
/// (`take_pending_process_exit` consumes only `pending_kill`), letting it resume
/// briefly in userspace before the drain reaps it (Codex R171 slice-2 finding).
/// A blocked-in-syscall task is never the target of `defer_irq_terminate` anyway
/// (that fires from IRQ context against a RUNNING task), so this is also a
/// no-op-removal in practice. `thread_group_exiting` is excluded for the same
/// epilogue-mismatch reason (it would yield a spurious EINTR that never
/// terminates — a livelock).
///
/// Process-context ONLY: it takes PROCESS_TABLE via `get_process`. NEVER call it
/// from IRQ / timer-tick context (use `try_get_process` there instead).
pub fn wait_should_abort(pid: ProcessId) -> bool {
    match get_process(pid) {
        Some(arc) => arc.lock().pending_kill.load(Ordering::Acquire),
        None => false,
    }
}

/// M4-1b: pack a wait generation into a per-PCB timeout marker.
///
/// `0` is the "no marker" sentinel; a live marker is `(generation << 1) | 1`.
/// The low tag bit makes `0` unambiguous even when the generation itself is 0
/// (the `ipc::sync::WaitQueue` `wait_generation` counter starts at 0). The top
/// bit is shifted out, so two generations differing by exactly 2^63 alias —
/// unreachable within the sub-tick window a marker lives.
#[inline]
pub fn pack_timeout_marker(generation: u64) -> u64 {
    (generation << 1) | 1
}

/// M4-1b: atomically read-and-clear a per-PCB timeout marker, applying the exact
/// generation semantics of the retired `consume_timeout` / `consume_timeout_flag`
/// BTreeMap helpers.
///
/// `swap(0, AcqRel)` is a single op (no load-then-store TOCTOU): it ALWAYS clears
/// any residue — reproducing the old `stored <= expected => remove` stale-drop —
/// and reports a timeout ONLY on an exact `(packed >> 1) == expected` match
/// (a stored generation `> expected` is impossible: one in-flight wait per PCB).
/// The caller MUST hold the proc lock across this swap (it is the synchronizing
/// edge that pairs with the IRQ-side store-under-proc-lock); any future lock-free
/// reader of the field must add its own Acquire.
#[inline]
fn consume_timeout_marker(field: &AtomicU64, expected: u64) -> bool {
    let raw = field.swap(0, Ordering::AcqRel);
    if raw & 1 == 0 {
        return false; // no marker
    }
    (raw >> 1) == expected
}

/// M4-1b: consume the per-PCB SOCKET-wait timeout marker for `pid`.
///
/// Process-context ONLY: it takes PROCESS_TABLE via `get_process` and then the
/// proc lock. NEVER call from IRQ / timer-tick context — a blocking PROCESS_TABLE
/// acquire in IRQ is the very R151-5 deadlock class this item is reducing. All
/// callers are socket-wait epilogues (process context). Returns true iff a
/// timeout for exactly this `(pid, expected)` wait was pending; clears the marker
/// either way.
pub fn consume_socket_timeout(pid: ProcessId, expected: u64) -> bool {
    match get_process(pid) {
        Some(arc) => consume_timeout_marker(&arc.lock().socket_timeout_marker, expected),
        None => false,
    }
}

/// M4-1b: consume the per-PCB WaitQueue timeout marker for `pid` (twin of
/// `consume_socket_timeout`). Process-context ONLY — same PROCESS_TABLE-in-IRQ
/// prohibition. All callers are `WaitQueue::wait_with_timeout` epilogues.
pub fn consume_wq_timeout(pid: ProcessId, expected: u64) -> bool {
    match get_process(pid) {
        Some(arc) => consume_timeout_marker(&arc.lock().wq_timeout_marker, expected),
        None => false,
    }
}

/// M1-02: pure decision core for the queue-free timer-IRQ wake — SHARED by
/// `wq_timeout_wake_by_seq` (production) and `run_timeout_marker_self_test` so the
/// IRQ wake predicate is unit-testable without an SMP timer race. A timer fires a
/// wake IFF its `seq` still matches the PCB's currently-blocked timed wait
/// (`active_wait_seq`) AND the task is still `Blocked` (a normal wake or kill that
/// already flipped it `Ready` must not be re-timed-out).
#[inline]
pub fn decide_wq_timeout(active_seq: u64, timer_seq: u64, blocked: bool) -> bool {
    active_seq == timer_seq && blocked
}

/// M1-02: queue-free `ipc::sync::WaitQueue` timeout wake, invoked from the
/// timer-tick IRQ drain.
///
/// REPLACES the deleted `WaitQueue::timeout_wake`, which dereferenced a `WaitQueue`
/// pointer smuggled through the timer table — a real SMP use-after-free (a
/// concurrent `FUTEX_WAKE` + `cleanup_empty_bucket` could free the heap
/// `Arc<WaitQueue>` between the drain's lock-dropped Phase-1 copy and the Phase-2
/// deref). Here the IRQ touches ONLY per-PCB state (no `WaitQueue`, no
/// `self.waiters`), so the dangling-pointer class is structurally impossible.
///
/// IRQ-safe: `try_get_process` + `try_lock` only — it NEVER blocks PROCESS_TABLE or
/// the proc lock in IRQ context. The waiter is removed from its `WaitQueue.waiters`
/// by its OWN epilogue (the wakee self-dequeues on the timeout path), not here.
///
/// The marker store-Release precedes `state = Ready`, both inside ONE held proc-lock
/// critical section: the proc-lock release/acquire hand-off (NOT the atomic) is the
/// marker-before-wake edge the epilogue honors (the M4-1b lesson). `active_wait_seq`
/// is only ever accessed under the proc lock, so `Relaxed` is sufficient.
///
/// Returns `true` when the timer entry is DONE (woke the exact wait, OR it is stale
/// / the PCB is gone / already woken) so the drain removes it; returns `false` ONLY
/// on genuine contention (PROCESS_TABLE or the proc lock held elsewhere) so the
/// drain defers it to the next tick (deadline still expired). The lock-acquired
/// seq-mismatch path returning `true` is what makes a duplicate cross-CPU Phase-1
/// copy idempotent: the first copy clears `active_wait_seq`, the second sees the
/// mismatch and drops as a no-op.
pub fn wq_timeout_wake_by_seq(pid: ProcessId, seq: u64, marker_gen: u64) -> bool {
    match try_get_process(pid) {
        // PROCESS_TABLE contended — defer, do NOT drop the timer.
        None => false,
        // PCB gone (killed / reaped) — drop the stale timer.
        Some(None) => true,
        Some(Some(proc_arc)) => {
            if let Some(mut proc) = proc_arc.try_lock() {
                if decide_wq_timeout(
                    proc.active_wait_seq.load(Ordering::Relaxed),
                    seq,
                    proc.state == ProcessState::Blocked,
                ) {
                    proc.wq_timeout_marker
                        .store(pack_timeout_marker(marker_gen), Ordering::Release);
                    proc.enter_ready_at(crate::get_ticks());
                    proc.active_wait_seq.store(0, Ordering::Relaxed);
                }
                // Lock acquired: an exact hit woke the wait; a mismatch means the
                // timer is stale / already-woken (a duplicate cross-CPU copy, or a
                // normal wake beat us). Either way the entry is complete — drop it.
                true
            } else {
                // Proc lock held (e.g. a concurrent wake) — defer to the next tick.
                false
            }
        }
    }
}

/// M4-1b: in-kernel self-test for the per-PCB timeout-marker mechanism. The
/// marker logic is invisible to a green build/boot (no boot test drives a real
/// timeout-vs-wake cross-field race), so this is the tripwire for the high-value
/// mis-wires: a bare-generation encoding that aliases wq-gen-0 with "no marker",
/// a missing `swap` on some exit path (a leak across waits), a wrong-field read,
/// or a broken exact-generation compare. Panics on failure; surfaced by
/// `make test` / `make boot-check` via the serial log.
pub fn run_timeout_marker_self_test() {
    // (1) ENCODING / SENTINEL: pack(0) must NOT be 0 (else wq generation 0 would
    // be indistinguishable from "no marker"); the tag bit must round-trip.
    assert_eq!(
        pack_timeout_marker(0),
        1,
        "pack(0) must set the tag bit, != 0"
    );
    assert_eq!(pack_timeout_marker(5), 11, "pack(5) == (5<<1)|1");
    assert_eq!(pack_timeout_marker(0) >> 1, 0, "decode(pack(0)) == 0");
    assert_eq!(pack_timeout_marker(5) >> 1, 5, "decode(pack(5)) == 5");

    let field = AtomicU64::new(0);

    // (2) EXACT-GEN + TOTAL STALE-DROP (reproduces old `<=`-clears + `==`-reports):
    field.store(pack_timeout_marker(5), Ordering::Relaxed);
    assert!(
        !consume_timeout_marker(&field, 7),
        "stored 5, expect 7 => not timed out"
    );
    assert_eq!(
        field.load(Ordering::Relaxed),
        0,
        "stale-low residue is cleared by swap"
    );
    field.store(pack_timeout_marker(5), Ordering::Relaxed);
    assert!(
        consume_timeout_marker(&field, 5),
        "stored 5, expect 5 => timed out"
    );
    assert_eq!(
        field.load(Ordering::Relaxed),
        0,
        "exact match clears the marker"
    );
    field.store(pack_timeout_marker(5), Ordering::Relaxed);
    assert!(
        !consume_timeout_marker(&field, 3),
        "stored 5, expect 3 => not timed out (no panic)"
    );
    assert_eq!(
        field.load(Ordering::Relaxed),
        0,
        "stale-high-than-expected residue cleared"
    );

    // (3) NO MARKER: a never-set field consumes to false without underflow.
    assert!(
        !consume_timeout_marker(&field, 0),
        "absent marker => false (gen 0)"
    );
    assert!(
        !consume_timeout_marker(&field, 42),
        "absent marker => false"
    );

    // (4) NO-LEAK ACROSS SEQUENTIAL WAITS: wait A times out and is consumed;
    // wait B never times out and MUST observe a clean field (Woken, not a stale
    // TimedOut from A).
    field.store(pack_timeout_marker(100), Ordering::Relaxed); // wait A's timer fires
    assert!(
        consume_timeout_marker(&field, 100),
        "wait A reports TimedOut"
    );
    assert!(
        !consume_timeout_marker(&field, 101),
        "wait B (no timer) reports Woken, no leak"
    );

    // (5) ENTRY-CLEAR neutralizes any residue (the born-clean belt).
    field.store(pack_timeout_marker(7), Ordering::Relaxed);
    field.store(0, Ordering::Relaxed); // entry-clear
    assert_eq!(
        field.load(Ordering::Relaxed),
        0,
        "entry-clear zeroes the field"
    );
    assert!(
        !consume_timeout_marker(&field, 7),
        "post entry-clear: no timeout"
    );

    // (6) TWO-FIELD ISOLATION: consuming the socket field must NOT disturb the wq
    // field — catches a copy-paste wrong-field read between the two markers.
    let socket_field = AtomicU64::new(pack_timeout_marker(9));
    let wq_field = AtomicU64::new(pack_timeout_marker(9));
    assert!(
        consume_timeout_marker(&socket_field, 9),
        "socket field consumes"
    );
    assert_eq!(
        socket_field.load(Ordering::Relaxed),
        0,
        "socket field cleared"
    );
    assert_eq!(
        wq_field.load(Ordering::Relaxed),
        pack_timeout_marker(9),
        "wq field UNTOUCHED by socket consume (two independent fields)"
    );
    assert!(
        consume_timeout_marker(&wq_field, 9),
        "wq field still consumable"
    );

    // (7) FORK CLEANLINESS: a freshly constructed PCB is born-clean on both fields
    // (defends the fork.rs explicit-zero + Process::new default).
    let child = Process::new(424242, 1, String::from("m4_1b_selftest"), 10);
    assert_eq!(
        child.socket_timeout_marker.load(Ordering::Relaxed),
        0,
        "child socket marker born-clean"
    );
    assert_eq!(
        child.wq_timeout_marker.load(Ordering::Relaxed),
        0,
        "child wq marker born-clean"
    );
    // M0 #5 (1b-2): a fresh PCB carries NO inherited syscall-frame binding — a stale
    // parent frame_ptr republished into a child would redirect the wrong kernel stack.
    assert_eq!(child.saved_frame_ptr, 0, "child saved_frame_ptr born-clean");
    assert_eq!(
        child.saved_frame_owner, 0,
        "child saved_frame_owner born-clean"
    );

    // (8) M1-02: queue-free IRQ-wake DECISION CORE. `decide_wq_timeout` is the exact
    // predicate `wq_timeout_wake_by_seq` uses under the proc lock; table-test it so a
    // future edit that breaks the seq/Blocked gate (waking the wrong wait, or a stale
    // timer flipping a non-blocked task Ready) fails HERE, not in an SMP timer-vs-wake
    // race a green boot never exercises.
    assert!(decide_wq_timeout(7, 7, true), "match seq + Blocked => fire");
    assert!(
        !decide_wq_timeout(7, 8, true),
        "seq mismatch (stale / other-queue wait) => no fire"
    );
    assert!(
        !decide_wq_timeout(7, 7, false),
        "already-Ready (normal-woken / killed) => no fire"
    );
    assert!(
        !decide_wq_timeout(0, 5, true),
        "a no-active-wait PCB (active_seq=0 sentinel) is never matched by an allocated timer (seq>=1)"
    );

    // (9) M1-02: the global wait-seq allocator is monotonic, distinct per call, and
    // never returns the reserved 0 sentinel (so an allocated seq can never alias the
    // born-clean active_wait_seq value).
    let s1 = alloc_wait_seq();
    let s2 = alloc_wait_seq();
    assert!(
        s1 != 0 && s2 != 0,
        "alloc_wait_seq never returns the 0 sentinel"
    );
    assert!(s2 != s1, "alloc_wait_seq is distinct per call");

    // (10) M1-02: a fresh PCB is born-clean on active_wait_seq (no inherited timed-wait
    // token); pairs with the fork.rs explicit-zero tripwire and Process::new default.
    assert_eq!(
        child.active_wait_seq.load(Ordering::Relaxed),
        0,
        "child active_wait_seq born-clean"
    );

    kprintln!("[selftest] run_timeout_marker_self_test: OK (M4-1b + M1-02)");
}

pub fn drain_deferred_irq_terminates() {
    if !DEFERRED_IRQ_KILL_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut still_running = false;
    for i in 0..MAX_DEFERRED_IRQ_KILLS {
        // Inspect before the exactly-once CAS claim so an active handoff can
        // remain queued without transiently losing scheduler visibility.
        // scheduler-visibility membership — that lives in
        // IRQ_KILL_NONRUNNABLE_PIDS and is cleared by terminate_process itself
        // right after the Zombie publish, so the [swap → Zombie] window is no
        // longer scheduler-visible. This drain does NOT touch NONRUNNABLE.
        let pid_raw = DEFERRED_IRQ_KILL_PIDS[i].load(Ordering::Acquire);
        if pid_raw == 0 {
            continue;
        }

        // A timer-kill handoff may still be executing on this task's kernel
        // stack. Leave both queue and NONRUNNABLE membership intact until the
        // scheduler publishes on_cpu=false after saving its context.
        let on_cpu = get_process(pid_raw as ProcessId)
            .map(|proc| proc.lock().on_cpu.load(Ordering::Acquire))
            .unwrap_or(false);
        if on_cpu {
            still_running = true;
            continue;
        }

        if DEFERRED_IRQ_KILL_PIDS[i]
            .compare_exchange(pid_raw, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let code = DEFERRED_IRQ_KILL_CODES[i].load(Ordering::Relaxed);
            terminate_process(pid_raw as ProcessId, code);
        }
    }
    if still_running {
        DEFERRED_IRQ_KILL_PENDING.store(true, Ordering::Release);
    }
}

/// R117-1 FIX: Centralized self-termination primitive.
///
/// Terminates the current process and enters a safe no-return halt loop.
/// This function guarantees that after self-termination:
///   1. Interrupts are disabled (no timer IRQ frames on zombie's stack)
///   2. CR3 is switched to boot page tables (freed user page tables not in TLB)
///   3. The scheduler is given a chance to pick another task
///   4. If no task is available, the CPU halts with IF=0 on safe CR3
///
/// **DESIGN GOAL (H.0.9 addendum):** No exit path may ever run with IRQs
/// enabled while still on the exiting task's CR3 or kernel stack.
///
/// # Panics
///
/// This function never returns (`-> !`).
pub fn terminate_self_and_halt(pid: ProcessId, exit_code: i32) -> ! {
    terminate_process(pid, exit_code);

    // R117-1 FIX: Disable interrupts immediately after marking Zombie.
    // Without this, timer IRQs push frames onto the zombie's kernel stack,
    // and RCU grace periods can complete (quiescent state on timer IRQ),
    // allowing a concurrent reaper to free the stack via cleanup_zombie().
    x86_64::instructions::interrupts::disable();

    // R117-1 FIX: Switch to boot CR3 (kernel-global page table cached at init).
    // The zombie's user page tables may be freed by a concurrent reaper on
    // another CPU. Switching to BOOT_CR3 ensures no stale TLB entries reference
    // freed page table frames.
    activate_memory_space(0, Some(0));
    // Bounded selection can legitimately miss a later queue window or a
    // contended PCB. Retry from boot CR3 after every interrupt wake. Reaping
    // is gated by on_cpu below, so this stack remains live until the scheduler
    // has durably saved it and finish-task-switch clears the publication.
    loop {
        crate::force_reschedule_from_irq();
        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    }
}

/// Terminate a process and transition it to Zombie state.
///
/// # Process Lifecycle Contract (H.0.7 + H.0.9)
///
/// **SAFETY:** This function may ONLY be called when the target process is:
///   1. The currently-executing process on this CPU (`current_pid() == Some(pid)`), OR
///   2. A process that has never been scheduled (pre-scheduler child during clone error cleanup).
///
/// **NO-RETURN RULE (H.0.9):** When terminating self (case 1), the caller MUST
/// enter a no-return halt loop after this call (`force_reschedule()` + `loop { hlt() }`).
/// Returning to the caller (especially via IRET in exception handlers) allows the zombie
/// to continue executing on freed page tables — use-after-free.
///
/// Calling `terminate_process()` on a process that may be running on another CPU
/// causes use-after-free: FPU state, cgroup accounting, kernel stack, and other
/// resources are freed while the remote CPU may still be using them.
///
/// For remote termination, use `request_process_exit()` which sets a pending-kill
/// flag that the target consumes at its next syscall return or timer IRQ safe point.
///
/// # Callers (audited H.0.9):
/// - `sys_exit()` — self + halt loop
/// - `sys_exit_group()` — self + halt loop (siblings use `request_process_exit`)
/// - `send_signal_inner()` fatal path — self + halt loop (remote uses `request_process_exit`)
/// - Interrupt/exception handlers — self + halt loop (`handle_user_exception`, page_fault, usercopy)
/// - Timer IRQ pending_kill check — self + halt loop
/// - Seccomp Kill/Trap — self + halt loop
/// - `syscall_bad_return()` — self + halt loop (fn -> !)
/// - Syscall return pending_kill check — self + halt loop
/// - `sys_fork()`/`sys_clone()` LSM denial on fork-based child — remote, never-scheduled
///   (safe: no CPU has ever run this process; followed immediately by `cleanup_zombie()`)
/// - `sys_clone()` no-CLONE_VM PID translation failure — remote, never-scheduled
///   (safe: same reasoning; followed immediately by `cleanup_zombie()`)
/// - `drain_deferred_irq_terminates()` — remote, `current_pid() != pid` (the
///   draining CPU's current task is NOT the dying pid). R171-S-R170-5-01: because of
///   this caller class the namespace init-death cascade MUST be deferred-only
///   (`request_process_exit` / `force_remote_kill`, NEVER `send_signal_inner`'s
///   no-return self branch) so a cascade victim that happens to be the draining
///   CPU's current task cannot abandon this teardown before `teardown_done`.
///
/// Pre-scheduler children created via `create_process()` (sys_clone CLONE_VM error paths,
/// main-path LSM rollback) use `cleanup_unscheduled_process()` instead, which avoids
/// cross-subsystem detach on never-joined cgroup/cpuset/IPC subsystems.
pub fn terminate_process(pid: ProcessId, exit_code: i32) {
    if let Some(process) = get_process(pid) {
        let children_to_reparent: AdmittedVec<ProcessId>;
        let parent_pid: ProcessId;
        let clear_child_tid: u64;
        let tgid: ProcessId;
        let memory_space: usize;
        // R25-7 FIX: Save credentials for LSM exit hook
        let lsm_uid: u32;
        let lsm_gid: u32;
        let lsm_euid: u32;
        let lsm_egid: u32;
        // F.1: Save namespace info for cleanup
        let pid_ns_chain: AdmittedVec<crate::pid_namespace::PidNamespaceMembership>;
        // F.2: Save cgroup_id for task detachment
        let cgroup_id: crate::cgroup::CgroupId;
        // R170-3: (tag, ns) of any contention-deferred CPU-quota debt, taken
        // (read + zero) under the PCB lock below and flushed after it drops.
        let quota_debt: (crate::cgroup::CgroupId, u64);
        // G.1: Save watchdog handle for unregistration
        let watchdog_handle: Option<WatchdogHandle>;
        // RF184-1: Removed mmap_snapshot (allocation-free validation)

        {
            let mut proc = process.lock();
            // R169-9 FIX (supersedes the R159-5 state guard): `state` is no longer
            // the exactly-once teardown arbiter — the IRQ-deferred kill path may
            // pre-set `Zombie` before the FIRST real teardown runs, and treating
            // that pre-set Zombie as "already torn down" skipped teardown entirely
            // (the R169-9 cgroup/ns/fd charge leak). Two guards now:
            //  (1) `Terminated` stays a HARD fast-return: the unscheduled-child
            //      error paths (`cleanup_unscheduled_process`) mark a PCB
            //      `Terminated` while it is briefly still in the table; a stray
            //      terminate here must NOT re-run teardown.
            //  (2) the exactly-once teardown CLAIM (`teardown_claimed`) is the sole
            //      teardown-skip arbiter — the first caller to win runs the heavy
            //      teardown; concurrent drain + signal delivery on the same pid
            //      serialize on it (stronger than the old guard: a pre-set Zombie
            //      no longer suppresses the first teardown, double-teardown is
            //      still blocked, so cgroup fetch_sub underflow / double
            //      detach_pid_chain cannot occur).
            if proc.state == ProcessState::Terminated {
                return;
            }
            if proc
                .teardown_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
            proc.state = ProcessState::Zombie;
            proc.exit_code = Some(exit_code);
            parent_pid = proc.ppid;
            // R158-10 FIX: take() instead of clone()+clear() — avoids infallible alloc on exit.
            children_to_reparent =
                core::mem::replace(&mut proc.children, AdmittedVec::new(HeapClass::CoreProcess));
            // 获取 clear_child_tid 信息用于线程退出通知
            clear_child_tid = proc.clear_child_tid;
            tgid = proc.tgid;
            memory_space = proc.memory_space;
            // 清除 clear_child_tid 避免重复处理
            proc.clear_child_tid = 0;
            // R25-7 + R39-3 FIX: Capture credentials from shared structure
            {
                if let Some(creds) = proc.credentials.try_read() {
                    lsm_uid = creds.uid;
                    lsm_gid = creds.gid;
                    lsm_euid = creds.euid;
                    lsm_egid = creds.egid;
                } else {
                    // Teardown cannot wait while holding the PCB. An in-flight
                    // credential writer makes the subject unavailable, so use
                    // the unprivileged overflow identity for fail-closed exit
                    // mediation rather than bypassing writer admission.
                    lsm_uid = 65534;
                    lsm_gid = 65534;
                    lsm_euid = 65534;
                    lsm_egid = 65534;
                }
            } // Drop creds read guard before mutable access below
              // RF180-16: transfer the admitted chain; a dying task no longer
              // needs namespace visibility and teardown must not allocate.
            pid_ns_chain = core::mem::replace(
                &mut proc.pid_ns_chain,
                AdmittedVec::new(HeapClass::CoreProcess),
            );
            // F.2: Copy cgroup_id for detachment
            cgroup_id = proc.cgroup_id;
            // R170-3 FIX: take (read + zero) the deferred quota debt in this
            // SAME critical section — a concurrent on_clock_tick on another
            // CPU serializes on this PCB lock, so it can never re-fold the ns
            // taken here (any ticks it folds AFTER this point are dropped:
            // bounded by the [take → deschedule] window of a dying task).
            quota_debt = (proc.cpu_quota_debt_cgid, proc.cpu_quota_debt_ns);
            proc.cpu_quota_debt_ns = 0;
            // G.1: Take watchdog handle (process no longer needs it)
            watchdog_handle = proc.watchdog_handle.take();

            // RF184-1 FIX: Removed mmap_snapshot to eliminate infallible allocation on exit.
            // Instead, validate clear_child_tid directly under mm lock at write time (below).
            // This is allocation-free and preserves TOCTOU protection.
        }

        // R170-5 FIX: drop the pid from the IRQ-kill non-runnable set NOW —
        // immediately after the Zombie publish (the scheduler skip is taken
        // over by `state == Zombie`, checked under the same PCB lock) and
        // strictly BEFORE `teardown_done` is published or any internal
        // `force_reschedule` runs. Pid recycling requires reap, which requires
        // `Zombie && teardown_done`; the clear precedes `teardown_done` on
        // this thread, so a recycled pid can never inherit a stale membership
        // (the unbounded recycled-pid scheduler-skip the clear-after-
        // terminate variant suffered from). Only the teardown-claim WINNER
        // reaches this point — the early returns above leave the membership
        // for the winner to clear. Invariant carried (pre-existing,
        // Codex-verified): a deferred pid reaches terminate_process
        // exclusively via the drain (remote kills route through
        // pending_kill → defer; the direct terminate callers are
        // never-scheduled-child cleanups that are never deferred).
        clear_irq_kill_nonrunnable(pid);

        // R170-3 FIX: land the taken contention-deferred quota debt on its
        // origin cgroup (process context — the blocking walk is legal here).
        crate::cgroup::flush_cpu_quota_debt(
            quota_debt.0,
            quota_debt.1,
            time::current_timestamp_ms().saturating_mul(1_000_000),
        );

        // G.1 Observability: Unregister watchdog before any other cleanup.
        // This must happen early to prevent false hung-task alerts during teardown.
        if let Some(handle) = watchdog_handle {
            if unregister_watchdog(&handle).is_err() {
                debug_assert!(false, "live process carried a stale watchdog handle");
            }
        }

        // R25-7 FIX: Call LSM task_exit hook for forced terminations (kill/seccomp paths)
        // This ensures policy can track ALL process exits, not just normal sys_exit
        let lsm_ctx = LsmProcessCtx::new(pid, tgid, lsm_uid, lsm_gid, lsm_euid, lsm_egid);
        let _ = lsm::hook_task_exit(&lsm_ctx, exit_code);

        // F.2: Detach from cgroup (decrement task count)
        // This must happen before other cleanup to maintain correct stats
        if let Some(cgroup) = crate::cgroup::lookup_cgroup(cgroup_id) {
            let _ = cgroup.detach_task(pid as u64);
        }

        // R69-2 FIX: Clear FPU ownership on all CPUs to prevent use-after-free.
        // If this process was the FPU owner on any CPU, its FPU state would be saved
        // to the PCB which is about to be deallocated. Clear ownership now.
        cpu_local::clear_fpu_owner_all_cpus(pid);

        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        klog_always!("Process {} terminated with exit code {}", pid, exit_code);

        // F.1 PID Namespace: Handle init death cascade
        //
        // If this process is the init (PID 1) of any namespace, all other processes
        // in that namespace must be killed (SIGKILL). This is Linux semantics.
        handle_namespace_init_death(pid, &pid_ns_chain);

        // F.1: Detach from all namespaces
        crate::pid_namespace::detach_pid_chain(&pid_ns_chain, pid);

        // 处理 clear_child_tid (CLONE_CHILD_CLEARTID)
        // 线程退出时将 clear_child_tid 地址处的值设为 0 并唤醒 futex
        if clear_child_tid != 0 && memory_space != 0 {
            // RF184-1 FIX: Validate clear_child_tid is still mapped before write, checking
            // directly under mm lock to avoid infallible allocation on exit (R158-10 principle).
            //
            // SAFETY PROOF: Without this check, a concurrent munmap (under CLONE_VM) or exec
            // could unmap the region before the write below. Writing to unmapped memory would:
            // 1. Page-fault in kernel context (undefined behavior)
            // 2. Potentially corrupt unrelated memory if remapped to something else
            // 3. Leak the 0-write to a different process's mapping (privilege violation)
            //
            // We acquire the mm lock HERE (not earlier) to validate the address is within
            // ANY mapped region. The lock is held briefly (O(log n) or O(n) scan), then
            // released before the CR3 switch and write. A concurrent munmap after validation
            // but before write is acceptable: worst case is writing 0 to a page about to be
            // unmapped (still our address space, no cross-process corruption).
            let addr_is_mapped = {
                // Acquire Process lock then mm lock to safely read mmap_regions
                let proc_guard = process.lock();
                let mm_guard = proc_guard.mm.lock();
                let addr = clear_child_tid as usize;
                let result = mm_guard.mmap_regions.iter().any(|(base, entry)| {
                    let len = crate::syscall::mmap_region_len(*entry);
                    addr >= *base && addr < base.saturating_add(len)
                });
                // Explicitly drop locks before CR3 switch
                drop(mm_guard);
                drop(proc_guard);
                result
            };

            if addr_is_mapped {
                // R24-3 fix: 写入 0 到 clear_child_tid 地址（SMAP + fault-tolerant）
                // 注意：需要在正确的地址空间中执行
                unsafe {
                    use crate::usercopy::copy_to_user_safe;
                    use x86_64::registers::control::Cr3;
                    use x86_64::structures::paging::PhysFrame;
                    use x86_64::PhysAddr;

                    // R102-4 FIX: Disable interrupts around CR3 switch to prevent:
                    // 1. Interrupt handlers running with the wrong page tables
                    // 2. Timer interrupts triggering rescheduling in foreign address space
                    // 3. KPTI context mismatch if interrupts load incorrect CR3
                    x86_64::instructions::interrupts::without_interrupts(|| {
                        // 切换到目标进程的地址空间
                        let current_cr3 = Cr3::read();
                        let target_frame =
                            PhysFrame::containing_address(PhysAddr::new(memory_space as u64));
                        Cr3::write(target_frame, current_cr3.1);

                        // 将 0 写入 clear_child_tid 地址（带 SMAP 保护和容错处理）
                        // P1-6 FIX: Removed redundant outer UserAccessGuard —
                        // copy_to_user_safe creates its own guard internally.
                        let tid_ptr = clear_child_tid as *mut u8;
                        if (tid_ptr as usize) >= 0x1000 && (tid_ptr as usize) < 0x8000_0000_0000 {
                            let zero = 0i32.to_ne_bytes();
                            // 忽略写入错误（用户可能已 unmap 该地址）
                            let _ = copy_to_user_safe(tid_ptr, &zero);
                        }

                        // 恢复原来的地址空间
                        Cr3::write(current_cr3.0, current_cr3.1);
                    });
                }

                // 唤醒等待在 clear_child_tid 地址上的 futex
                let woken = notify_futex_wake(tgid, clear_child_tid as usize, 1);
                if woken > 0 {
                    // R102-L6 FIX: Gate address-revealing log behind debug_assertions
                    kprintln!(
                        "  Woke {} waiters on clear_child_tid=0x{:x}",
                        woken,
                        clear_child_tid
                    );
                    let _ = woken; // suppress unused warning in release
                }
            } else {
                // R184-1 FIX: Address is no longer mapped — skip the write and futex wake.
                // This is the correct behavior: if the region was unmapped, any futex
                // waiters on that address are already invalid (futex keys are tied to
                // the mapping), so there's nothing to wake.
                #[cfg(debug_assertions)]
                kprintln!(
                    "[terminate_process] Skipping clear_child_tid write to unmapped 0x{:x}",
                    clear_child_tid
                );
            }
        }

        // 将孤儿进程重新分配给 init 进程 (PID 1)
        // R171-S-R170-5-01 FIX (SLICE 3): pass `pid` (the dying process) so
        // reparent_orphans excludes it as a reaper candidate (it has already
        // drained its own children list above).
        if !children_to_reparent.is_empty() {
            reparent_orphans(&children_to_reparent, pid);
        }

        // R169-9 FIX: heavy teardown (cgroup detach / pid-ns detach / clear_child_tid
        // futex / FPU-owner clear / watchdog / reparent) is now COMPLETE. Publish
        // teardown completion (Release) BEFORE waking/notifying the parent, so the
        // woken waiter (and any concurrent reaper) observes `teardown_done == true`
        // together with the already-set `Zombie` state and may now reap. Until this
        // store, every reaper gate (wait_process / cleanup_zombie / sys_wait4) sees
        // `teardown_done == false` and refuses to free the PCB — closing the
        // IRQ-deferred early-reap / teardown-bypass leak (R169-9 BREAK #1).
        process.lock().teardown_done.store(true, Ordering::Release);

        // R160-16 FIX: Deliver SIGCHLD to parent per POSIX. Previously only
        // the waitpid wakeup path was used. SIGCHLD enables async notification
        // for parents using signal handlers instead of blocking waitpid.
        if parent_pid > 0 {
            let _ = crate::signal::send_signal_kernel(parent_pid, crate::signal::Signal::SIGCHLD);
        }

        // 唤醒等待此进程的父进程
        let mut wake_parent = false;

        if parent_pid > 0 {
            if let Some(parent) = get_process(parent_pid) {
                let mut parent_proc = parent.lock();
                let waiting = parent_proc.waiting_child;
                // 父进程正在等待，且等待的是任意子进程(0)或此特定子进程
                if parent_proc.state == ProcessState::Blocked
                    && (waiting == Some(0) || waiting == Some(pid))
                {
                    parent_proc.enter_ready_at(crate::get_ticks());
                    parent_proc.waiting_child = None;
                    wake_parent = true;
                }
            }
        }

        // 在释放锁后触发调度，让被唤醒的父进程有机会运行
        if wake_parent {
            crate::force_reschedule();
        }
    }
}

/// F.1 PID Namespace: 将孤儿进程重新分配给正确的 init 进程
///
/// Orphans are reparented to the init process of their owning PID namespace,
/// not necessarily global PID 1. This ensures getppid() returns a valid PID
/// that is visible within the process's namespace.
fn reparent_orphans(orphans: &[ProcessId], dying_pid: ProcessId) {
    const ROOT_INIT_PID: ProcessId = 1;
    // Bound on namespace nesting (root + MAX_PID_NS_LEVEL levels) ⇒ heap-free
    // candidate buffer, so this teardown-path function never allocates.
    const MAX_REAPER_CANDS: usize = crate::pid_namespace::MAX_PID_NS_LEVEL as usize + 1;

    // R160-4 FIX: Single PROCESS_TABLE lock acquisition for the entire
    // reparenting batch. The previous 3-lock-per-orphan pattern had a race:
    // between updating child.ppid and pushing to adopter.children, the adopter
    // could terminate on another CPU → child stuck with ppid pointing to a dead
    // process and never added to any children list → permanent zombie leak.
    //
    // R171-S-R170-5-01 FIX (SLICE 3): rewritten to resolve a LIVE reaper.
    // INVARIANTS (lock discipline — the residual-KILL fix):
    //   * NEVER hold the child PCB lock and an adopter PCB lock simultaneously.
    //     Holding both self-deadlocks deterministically when the orphan IS global
    //     pid 1 (`table.get(1)` returns the same `Arc<Mutex<Process>>` as the
    //     child), wedging PROCESS_TABLE for every CPU.
    //   * Skip any adopter candidate equal to the orphan itself (no self-parent)
    //     or to `dying_pid` (it has already drained its own children list).
    //   * Adopter liveness is "present AND not Zombie/Terminated", checked under
    //     the adopter lock in `try_commit_reaper`.
    // Candidates are the orphan's per-namespace inits, nearest first (leaf → root),
    // snapshotted under the child lock which is then DROPPED before any adopter is
    // touched; namespaces that are shutting down are skipped.
    let table = PROCESS_TABLE.lock();

    for &child_pid in orphans {
        let child_arc = match table.get(child_pid).and_then(|s| s.clone()) {
            Some(arc) => arc,
            None => continue,
        };

        // STEP 1: heap-free candidate snapshot (leaf → root); child lock dropped
        // before any adopter is resolved.
        let mut cands: [Option<ProcessId>; MAX_REAPER_CANDS] = [None; MAX_REAPER_CANDS];
        let mut n = 0usize;
        {
            let child = child_arc.lock();
            for m in child.pid_ns_chain.iter().rev() {
                if n >= cands.len() {
                    break;
                }
                if m.ns.is_shutting_down() {
                    continue; // never adopt onto a namespace that is tearing down
                }
                if let Some(c) = m.ns.init_global_pid() {
                    cands[n] = Some(c);
                    n += 1;
                }
            }
        } // child PCB lock dropped here

        // STEP 2: commit to the first LIVE candidate that is neither the orphan
        // itself nor the dying parent.
        let mut committed = false;
        for slot in cands.iter().take(n) {
            let cand = match *slot {
                Some(c) => c,
                None => continue,
            };
            if cand == child_pid || cand == dying_pid {
                continue;
            }
            if try_commit_reaper(&table, &child_arc, child_pid, cand) {
                committed = true;
                break;
            }
        }

        // STEP 3: ROOT_INIT_PID fallback — SAME one-lock-at-a-time protocol.
        if !committed {
            if child_pid == ROOT_INIT_PID {
                // pid 1 can never be its own reaper.
                reparent_logged_leak(&child_arc, child_pid, ROOT_INIT_PID);
            } else if !try_commit_reaper(&table, &child_arc, child_pid, ROOT_INIT_PID) {
                // ROOT_INIT_PID absent / Zombie / Terminated: fail SAFE (deterministic
                // ppid, no dead-slot push) rather than panic — a panic on the teardown
                // path would re-open the abandonment class this slice closes. A
                // guaranteed-live global init is tracked as boot-hardening future work.
                reparent_logged_leak(&child_arc, child_pid, ROOT_INIT_PID);
                debug_assert!(
                    false,
                    "ROOT_INIT_PID must be a live reaper (boot-hardening pending)"
                );
            }
        }
    }

    drop(table);

    if !orphans.is_empty() {
        klog!(Info, "Reparented {} orphan process(es)", orphans.len());
    }
}

/// R171-S-R170-5-01 FIX (SLICE 3): link `child_pid` under live reaper `cand`, then
/// set the child's ppid — each under its OWN PCB lock, NEVER both held at once (the
/// residual-KILL fix). Returns false (⇒ advance the candidate cursor) if `cand` is
/// absent from the table or is not a live reaper (Zombie/Terminated).
///
/// The liveness check and the children push are one adopter-lock hold, atomic
/// against the adopter's own teardown (which sets Zombie and drains its children
/// list under the same PCB lock): we either push before it drains (our child rides
/// along and is re-reparented by the adopter) or observe Zombie and skip.
fn try_commit_reaper(
    table: &[Option<ProcessArc>],
    child_arc: &ProcessArc,
    child_pid: ProcessId,
    cand: ProcessId,
) -> bool {
    let adopter = match table.get(cand) {
        Some(Some(a)) => a.clone(),
        _ => return false,
    };
    {
        let mut adopter_proc = adopter.lock();
        if matches!(
            adopter_proc.state,
            ProcessState::Zombie | ProcessState::Terminated
        ) {
            return false; // dead/Zombie adopter ⇒ advance the cursor
        }
        if !adopter_proc.children.contains(&child_pid) {
            if adopter_proc.children.try_reserve(1).is_ok() {
                adopter_proc
                    .children
                    .push_reserved(child_pid)
                    .expect("reparent child reservation disappeared");
            } else {
                adopter_proc.children_incomplete = true;
            }
        }
    } // adopter PCB lock dropped BEFORE the child lock — never both at once
    {
        let mut child = child_arc.lock();
        child.ppid = cand;
    }
    true
}

/// R171-S-R170-5-01 FIX (SLICE 3): no live reaper exists. Set a deterministic ppid
/// (so getppid is well-defined) WITHOUT pushing into any dead/absent adopter's
/// children list, and log the orphan as leaked. Child PCB lock alone.
fn reparent_logged_leak(child_arc: &ProcessArc, child_pid: ProcessId, fallback_pid: ProcessId) {
    {
        let mut child = child_arc.lock();
        child.ppid = fallback_pid;
    }
    klog_force!(
        "R171-S: orphan {} has no live reaper; ppid set to {} (logged leak)",
        child_pid,
        fallback_pid
    );
}

/// F.1 PID Namespace: Handle cascade killing when a namespace init dies
///
/// When the init process (PID 1) of a namespace exits, all other processes
/// in that namespace receive SIGKILL. This is Linux semantics to ensure
/// proper namespace teardown.
///
/// # Arguments
///
/// * `dying_pid` - The global PID of the exiting process
/// * `pid_ns_chain` - The namespace membership chain of the exiting process
fn handle_namespace_init_death(
    dying_pid: ProcessId,
    pid_ns_chain: &[crate::pid_namespace::PidNamespaceMembership],
) {
    // R115-2 FIX: Namespace teardown MUST unconditionally kill all members
    // regardless of credentials (the dying init may lack CAP_KILL / matching UIDs).
    //
    // R171-S-R170-5-01 FIX (SLICE 3): This cascade runs mid-teardown of `dying_pid`,
    // BEFORE `teardown_done` is published. It MUST take NO no-return path. The old
    // `send_signal_kernel(victim, SIGKILL)` routes a fatal signal through
    // `send_signal_inner`, whose `current_pid() == victim` arm calls the
    // never-returning `terminate_self_and_halt`. If a cascade victim is ever the
    // currently-running task — reachable whenever `terminate_process` is driven for
    // a NON-current pid (the never-scheduled-child cleanup and, notably, the
    // `drain_deferred_irq_terminates` path) — that arm abandons this in-flight
    // teardown: `teardown_done` is never published and the parent is never woken,
    // leaving a permanently unreapable Zombie + leaked address space/PCB. We
    // therefore route EVERY victim through the deferred, no-return-free
    // `force_remote_kill` (built on `request_process_exit`), which merely defers the
    // current task instead of self-halting it.

    // SIGKILL's exit code, identical to send_signal_kernel(SIGKILL).
    let sigkill_code = crate::signal::signal_exit_code(crate::signal::Signal::SIGKILL);

    // Check each namespace in the chain (root has no cascade).
    for membership in pid_ns_chain.iter() {
        if membership.ns.is_root() {
            continue;
        }

        if membership.ns.is_init(dying_pid) {
            // mark_shutting_down latches once: only the first init-death cascades.
            if membership.ns.mark_shutting_down() {
                // R171-S FIX: mark the whole descendant subtree shutting-down up
                // front so a member joining a nested namespace mid-cascade is never
                // adopted as a reaper by reparent_orphans (which skips is_shutting_down
                // namespaces).
                membership.ns.mark_descendants_shutting_down();

                // R104-2 FIX: Gate to prevent leaking namespace IDs + PIDs.
                kprintln!(
                    "[PID NS] Init death cascade: namespace {} is shutting down (init pid={})",
                    membership.ns.id().raw(),
                    dying_pid
                );

                // R171-S FIX: fallible enumeration — an OOM here must not panic and
                // abandon teardown; log and skip the cascade (logged leak) instead.
                let victims = match crate::pid_namespace::get_cascade_kill_pids_fallible(
                    &membership.ns,
                ) {
                    Ok(v) => v,
                    Err(_) => {
                        klog_force!(
                            "R171-S: cascade enumeration OOM for ns {} (init {}); members left un-cascaded (logged leak)",
                            membership.ns.id().raw(),
                            dying_pid
                        );
                        break;
                    }
                };

                if !victims.is_empty() {
                    // R104-2 FIX: Gate namespace cascade logging.
                    kprintln!(
                        "[PID NS] Sending SIGKILL to {} processes in namespace {}",
                        victims.len(),
                        membership.ns.id().raw()
                    );

                    for victim_pid in victims {
                        if victim_pid == dying_pid {
                            continue;
                        }
                        // R171-S FIX: deferred, no-return-free kill for EVERY victim
                        // (including the current task, which is merely deferred — never
                        // self-halted from inside this teardown).
                        force_remote_kill(victim_pid, sigkill_code, &membership.ns);
                    }
                }
            }
            // Only one namespace can have this process as init
            // (processes are init only in their owning namespace)
            break;
        }
    }
}

/// R171-S-R170-5-01 FIX (SLICE 3): Deferred, no-return-free remote kill used by the
/// namespace init-death cascade. Posts a pending exit (consumed at the victim's next
/// syscall/IRQ safe point) and applies SIGKILL un-stop semantics so a job-control-
/// stopped victim is made runnable and actually reaches that safe point — otherwise a
/// `Stopped` member of a shutting-down namespace would survive the cascade (a live
/// leak). NEVER calls the no-return self-termination path, so it cannot abandon the
/// caller's in-flight teardown even if `victim_pid` is the currently-running task.
fn force_remote_kill(
    victim_pid: ProcessId,
    exit_code: i32,
    shutting_namespace: &crate::pid_namespace::PidNamespaceArc,
) {
    // RF178-36 FIX: resolve exactly once. A namespace victim may be reaped and
    // its PID reused after this lock is released, so every later action carries
    // this Arc plus its generation instead of looking the raw PID up again.
    let Some(arc) = get_process(victim_pid) else {
        return;
    };
    let post = {
        let mut proc = arc.lock();
        // The namespace member list contains reusable numeric PIDs. Revalidate
        // membership against the resolved PCB under the same guard that posts
        // the fatal request, so PID recycling cannot kill an unrelated task.
        if !crate::pid_namespace::is_visible_in_namespace(shutting_namespace, &proc.pid_ns_chain) {
            return;
        }
        request_process_exit_locked(&mut proc, exit_code, crate::get_ticks())
    };
    let _ = finish_process_exit_request(post);
}

/// 等待子进程
pub fn wait_process(pid: ProcessId) -> Option<i32> {
    if let Some(process) = get_process(pid) {
        let proc = process.lock();
        // R169-9: a Zombie is reapable/observable as exited ONLY after teardown
        // has been published — never report exit before teardown ran.
        if proc.state == ProcessState::Zombie
            && proc.teardown_done.load(Ordering::Acquire)
            && !proc.on_cpu.load(Ordering::Acquire)
            && !proc.switch_reap_pending.load(Ordering::Acquire)
        {
            return proc.exit_code;
        }
    }
    None
}

/// 清理僵尸进程
///
/// # Reaper Contract (H.0.9)
///
/// **SAFETY:** This function MUST ONLY be called by a **reaper** — the parent process
/// via `waitpid()`, the init reaper, or a never-scheduled child rollback path.
/// NEVER call on the currently-executing process (`current_pid() == Some(pid)`).
///
/// Self-reaping frees the active CR3 page tables and kernel stack while the calling
/// code is still executing — immediate use-after-free. A `debug_assert!` guards this
/// invariant; violations are caught in debug builds.
///
/// # Callers (audited H.0.9):
/// - `sys_wait4()` — parent reaps child (waitpid semantics)
/// - `sys_fork()`/`sys_clone()` LSM denial on fork-based child — immediately after
///   `terminate_process()`, never-scheduled (remote-only invariant holds)
/// - `sys_clone()` no-CLONE_VM PID translation failure — same as above
///
/// Pre-scheduler children created via `create_process()` (sys_clone CLONE_VM error paths,
/// main-path LSM rollback) use `cleanup_unscheduled_process()` instead.
///
/// R114-1 FIX: Two-phase reap to prevent deadlock.
///
/// Previously, `free_process_resources()` (and its IPC/futex cleanup callbacks) was called
/// while holding `PROCESS_TABLE`, causing a deterministic deadlock:
///   `PROCESS_TABLE.lock()` → `free_process_resources()` → `notify_ipc_process_cleanup()`
///   → `cleanup_process_futexes()` → `thread_group_size(tgid)` → `PROCESS_TABLE.lock()` [DEADLOCK]
///
/// The fix splits reaping into two phases:
/// - **Phase 1 (under `PROCESS_TABLE` lock):** Verify zombie state, check shared address space,
///   detach the `Arc<Mutex<Process>>` from the table via `slot.take()`, mark Terminated, and
///   capture IDs needed for cross-subsystem cleanup.
/// - **Phase 2 (without `PROCESS_TABLE` lock):** Free kernel resources, run IPC/futex/cpuset
///   cleanup callbacks, and notify the scheduler. These callbacks may safely re-lock
///   `PROCESS_TABLE` since we no longer hold it.
pub fn cleanup_zombie(pid: ProcessId) {
    // R116-3 FIX: cleanup_zombie() is designed to be called by a reaper (parent
    // via waitpid), NOT by the zombie itself. Self-reaping frees the active CR3
    // page tables and kernel stack while the calling code is still executing.
    // R117-3 FIX: Runtime guard for release builds. debug_assert! is stripped in
    // release; this `if` check prevents silent UAF if a regression reintroduces
    // self-reaping. Cost: single AtomicU32 load (current_pid()).
    if current_pid() == Some(pid) {
        klog!(
            Error,
            "SECURITY: cleanup_zombie called on self (pid={}) — refusing to prevent UAF",
            pid
        );
        return;
    }
    debug_assert!(
        current_pid() != Some(pid),
        "cleanup_zombie called on self (pid={}) — self-reaping causes UAF",
        pid
    );
    // Phase 1: Detach process from PROCESS_TABLE under lock.
    // After `slot.take()`, no other code path can look up this PID in the table,
    // so the extracted Arc is the sole remaining reference to the PCB.
    let (reap_info, retired_process_table) = {
        let mut table = PROCESS_TABLE.lock();

        // Phase 1a: Check process state
        let (memory_space, is_zombie) = {
            if let Some(slot) = table.get(pid) {
                if let Some(process) = slot {
                    let proc = process.lock();
                    // R169-9: only a torn-down Zombie (teardown_done published) is
                    // reapable — block the IRQ-deferred early-reap before teardown.
                    if proc.state == ProcessState::Zombie
                        && proc.teardown_done.load(Ordering::Acquire)
                        && !proc.on_cpu.load(Ordering::Acquire)
                        && !proc.switch_reap_pending.load(Ordering::Acquire)
                    {
                        (proc.memory_space, true)
                    } else {
                        (0, false)
                    }
                } else {
                    (0, false)
                }
            } else {
                (0, false)
            }
        };

        let result = if !is_zombie {
            None
        } else {
            // Phase 1b: Check if other processes still reference this address space.
            //
            // R136-1 FIX: Zombies are intentionally INCLUDED here (only Terminated
            // excluded). A Zombie retains `memory_space` until reaped, so we must
            // keep the address space alive if any other Zombie (or live process)
            // still references it. This is consistent with the updated
            // `address_space_share_count()` which also counts zombies.
            // (Must be done under PROCESS_TABLE lock since we iterate the table.)
            let keep_address_space = if memory_space == 0 {
                false
            } else {
                table.iter().enumerate().any(|(idx, other_slot)| {
                    if idx == pid {
                        return false;
                    }
                    if let Some(other_proc_arc) = other_slot {
                        let other = other_proc_arc.lock();
                        other.memory_space == memory_space
                            && other.state != ProcessState::Terminated
                    } else {
                        false
                    }
                })
            };

            // Phase 1c: Detach the Arc<Mutex<Process>> from the table and mark Terminated.
            // `slot.take()` atomically removes the process from the table, ensuring
            // no concurrent code path can find it by PID while we clean up.
            if let Some(slot) = table.get_mut(pid) {
                if let Some(process) = slot.take() {
                    let mut proc = process.lock();
                    // Re-validate state + teardown completion (defensive against
                    // concurrent modification). R169-9: a Zombie whose teardown has
                    // not been published is NOT reapable — restore the slot below.
                    if proc.state == ProcessState::Zombie
                        && proc.teardown_done.load(Ordering::Acquire)
                    {
                        proc.state = ProcessState::Terminated;
                        // Capture IDs needed for Phase 2 callbacks before dropping the lock.
                        // RF178-33 / P1-B: generation must ride with the reaped PID so the
                        // scheduler cleanup callback cannot purge a recycled-PID successor.
                        let reaped_pid = proc.pid;
                        let reaped_generation = proc.generation;
                        let tgid = proc.tgid;
                        let ipc_ns_id = proc.ipc_ns.id();
                        let cpuset_id = proc.cpuset_id;
                        // RF180-3: reserve the numeric PID before PROCESS_TABLE
                        // becomes observable as empty.  Phase 2 clears it only
                        // after all raw-PID cleanup and scheduler removal finish.
                        begin_reaping_identity(reaped_pid, tgid);
                        drop(proc);
                        Some((
                            process,
                            keep_address_space,
                            reaped_pid,
                            reaped_generation,
                            tgid,
                            ipc_ns_id,
                            cpuset_id,
                        ))
                    } else {
                        // Not a zombie anymore (concurrent state change); restore the slot
                        drop(proc);
                        *slot = Some(process);
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        let retired = result
            .as_ref()
            .and_then(|_| reclaim_empty_process_table(&mut table));
        (result, retired)
    };
    // PROCESS_TABLE lock is released here.
    drop(retired_process_table);

    // Phase 2: Free resources and run cross-subsystem cleanup WITHOUT holding PROCESS_TABLE.
    if let Some((
        process,
        keep_address_space,
        reaped_pid,
        reaped_generation,
        tgid,
        ipc_ns_id,
        cpuset_id,
    )) = reap_info
    {
        // Free kernel-internal resources (stack, mmap, fd_table, address space).
        // This is safe because the Arc we hold is the only remaining reference —
        // the table slot was cleared in Phase 1c.
        // R154-3 FIX: Extract fd_table under lock, drop destructors outside to
        // prevent lock inversion (socket close → wake_all → other Process lock).
        let fds_to_drop = {
            let mut proc = process.lock();
            free_process_resources(&mut proc, keep_address_space)
        };
        // Process lock is released; run FileOps destructors while the PID/TGID
        // pins are still held because they can wake PID-keyed waiters.
        drop(fds_to_drop);

        // Cross-subsystem cleanup: IPC endpoint teardown + futex waiter cleanup.
        // These callbacks may re-lock PROCESS_TABLE (e.g., thread_group_size(),
        // get_process()) which is safe now since we no longer hold it.
        // R180-5: generation rides with the reaped PID (same identity contract as
        // RF178-33 scheduler cleanup) so a recycled successor is never targeted.
        notify_ipc_process_cleanup(reaped_pid, tgid, ipc_ns_id, reaped_generation);

        // E.5 Cpuset: decrement task count when process exits
        notify_cpuset_task_left(cpuset_id);

        // RF178-33 / P1-B: pass generation so a recycled PID's live queue entry
        // is never removed by the reaper of the previous occupant.
        notify_scheduler_process_removed(reaped_pid, reaped_generation);
        // RF180-3: all PID-only subsystem state for this task has been drained.
        // Release the PID, and release the TGID only after no old-group table
        // member or concurrent Phase-2 reaper remains. Kernel-stack RCU lag is
        // independently guarded by create_process's AlreadyMapped retry path.
        finish_reaping_identity(reaped_pid, tgid);
        klog!(Info, "Cleaned up zombie process {}", reaped_pid);
    }
}

/// Clean up a process that was created by `create_process()` but never scheduled.
///
/// # Pre-scheduler Child Contract (H.0.9)
///
/// This function is for **error-path cleanup only** — when `sys_clone()` or
/// `enforce_lsm_task_fork()` creates a child via `create_process()` but encounters
/// an error before its reserved scheduler admission is committed.
///
/// Unlike the `terminate_process()` + `cleanup_zombie()` pair, this function
/// performs **only kernel-internal resource teardown** and PID namespace detachment.
/// It deliberately skips cross-subsystem callbacks that assume full initialization:
///
/// - **No cgroup detach** — `create_process()` does not call `cgroup.attach_task()`
///   for ppid != 0; that is done later in `fork_inner()`. Detaching an unattached
///   task causes `fetch_sub` underflow on cgroup task counters.
///
/// - **Conditional cpuset task_left** — `create_process()` joins kernel-created
///   tasks (`ppid == 0`) immediately, while ordinary children are joined later by
///   `fork_inner()`. Rollback records that distinction under the PCB lock and only
///   decrements the cpuset counter for the former.
///
/// - **No IPC cleanup** — the child never registered IPC endpoints.
///
/// - **No scheduler removal** — the child was never added to any run queue.
///
/// # Arguments
///
/// * `pid` - The PID of the pre-scheduler child to clean up
///
/// # Panics (debug)
///
/// Panics if called on the currently-executing process (self-cleanup is UAF).
///
/// # Callers (audited H.0.9)
///
/// - `enforce_lsm_task_fork()` — LSM hook denied the fork
/// - `sys_clone()` error paths (7 sites) — seccomp installing, frame unavailable,
///   invalid TLS, copy_to_user failure
pub fn cleanup_unscheduled_process(pid: ProcessId) {
    debug_assert!(
        current_pid() != Some(pid),
        "cleanup_unscheduled_process called on self (pid={}) — self-cleanup causes UAF",
        pid
    );

    // Phase 1: Detach from PROCESS_TABLE under lock, capturing info for Phase 2.
    let (cleanup_info, retired_process_table) = {
        let mut table = PROCESS_TABLE.lock();

        let result = if let Some(slot) = table.get_mut(pid) {
            if let Some(process) = slot.take() {
                let mut proc = process.lock();
                proc.state = ProcessState::Terminated;

                let memory_space = proc.memory_space;
                // RF180-19 defense-in-depth: this is an error/OOM rollback path.
                // The detached, never-scheduled PCB will never need namespace
                // visibility again, so transfer its already-owned chain instead
                // of allocating a clone while the system may be out of memory.
                let pid_ns_chain = core::mem::replace(
                    &mut proc.pid_ns_chain,
                    AdmittedVec::new(HeapClass::CoreProcess),
                );
                let watchdog_handle = proc.watchdog_handle.take();
                let joined_cpuset = proc.ppid == 0;
                let cpuset_id = proc.cpuset_id;

                // Determine whether another live process shares this address space.
                // If memory_space was already zeroed by the caller (to prevent
                // freeing a shared CLONE_VM address space), keep_address_space is
                // irrelevant since free_process_resources won't touch it.
                let keep_address_space = if memory_space == 0 {
                    false
                } else {
                    table.iter().enumerate().any(|(idx, other_slot)| {
                        if idx == pid {
                            return false;
                        }
                        if let Some(other_arc) = other_slot {
                            let other = other_arc.lock();
                            other.memory_space == memory_space
                                && other.state != ProcessState::Terminated
                        } else {
                            false
                        }
                    })
                };

                drop(proc);
                Some((
                    process,
                    keep_address_space,
                    pid_ns_chain,
                    watchdog_handle,
                    joined_cpuset,
                    cpuset_id,
                ))
            } else {
                None
            }
        } else {
            None
        };
        let retired = result
            .as_ref()
            .and_then(|_| reclaim_empty_process_table(&mut table));
        (result, retired)
    };
    // PROCESS_TABLE lock released here.
    drop(retired_process_table);

    // Phase 2: Free resources without cross-subsystem callbacks.
    if let Some((
        process,
        keep_address_space,
        pid_ns_chain,
        watchdog_handle,
        joined_cpuset,
        cpuset_id,
    )) = cleanup_info
    {
        // G.1 Observability: Unregister watchdog before releasing other resources.
        if let Some(handle) = watchdog_handle {
            if unregister_watchdog(&handle).is_err() {
                debug_assert!(false, "reaped process carried a stale watchdog handle");
            }
        }

        // Free kernel-internal resources (stack, mmap, fd_table, address space).
        // R154-3 FIX: Extract fd_table under lock, drop destructors outside.
        let _fds_to_drop = {
            let mut proc = process.lock();
            free_process_resources(&mut proc, keep_address_space)
        };
        // _fds_to_drop dropped here — safe for socket destructors outside lock.

        // F.1 PID Namespace: Detach from all namespaces.
        crate::pid_namespace::detach_pid_chain(&pid_ns_chain, pid);

        if joined_cpuset {
            notify_cpuset_task_left(cpuset_id);
        }

        // NOTE: No IPC cleanup, cgroup detach, or scheduler removal — none of
        // those subsystems were joined. Cpuset rollback is conditional above.

        klog!(Info, "Cleaned up unscheduled process {}", pid);
    }
}

/// 释放进程持有的内核资源
///
/// - 释放 per-process 内核栈（取消映射并归还物理帧）
/// - 清理 mmap 区域跟踪信息
/// - 如果进程拥有独立页表（memory_space != 0），直接遍历该页表：
///   * 仅处理用户空间 PML4 条目 0-255
///   * 对叶子页减少 COW 引用计数并在归零时释放物理帧
///   * 递归释放中间页表帧，最后释放 PML4 帧本身
///
/// 恒等映射 0-4GB 允许将物理地址当作虚拟地址解引用。
///
/// # 当前限制
///
/// - **HUGE_PAGE**: 用户空间应仅使用 4KB 页面。若存在 2MB/1GB 大页映射，
///   当前实现会跳过以避免 buddy allocator 损坏。
///
/// # Arguments
///
/// * `proc` - 进程引用
/// * `keep_address_space` - R24-1 fix: 如果为 true，不释放地址空间（其他线程仍在使用）
fn free_process_resources(
    proc: &mut Process,
    keep_address_space: bool,
) -> AdmittedMap<i32, FileDescriptor> {
    // D3-ARC-MM-SHARED: Lock the shared MmState to access mmap/brk metadata.
    // For shared MmState (CLONE_VM), Arc::strong_count > 1 means other tasks
    // still reference this mm — non-last exit must NOT uncharge cgroup memory.
    let mm_shared = Arc::strong_count(&proc.mm) > 1;
    let mut mm = proc.mm.lock();

    let region_count = mm.mmap_regions.len();
    // R123-5 FIX: Mask low-bit flags (PENDING/PROT_NONE) before summing,
    // so diagnostic logs reflect actual region lengths, not inflated values.
    let total_size: usize = mm
        .mmap_regions
        .values()
        .map(|&v| crate::syscall::mmap_region_len(v))
        .sum();

    // 释放 per-process 内核栈
    if proc.kernel_stack.as_u64() != 0 {
        let permit = proc
            .kernel_stack_rcu
            .take()
            .expect("live kernel stack missing RCU reclaim permit");
        let phys = proc
            .kernel_stack_phys
            .take()
            .expect("live kernel stack missing physical block identity");
        free_kernel_stack(proc.pid, proc.kernel_stack, phys, permit);
        proc.kernel_stack = VirtAddr::new(0);
        proc.kernel_stack_top = VirtAddr::new(0);
    }

    // R124-1 FIX: Uncharge cgroup memory for all charged mmap regions BEFORE
    // clearing the bookkeeping. Without this, process exit permanently leaks
    // cgroup memory_current, eventually blocking all allocations in the cgroup
    // (user-triggerable container DoS).
    //
    // D3-ARC-MM-SHARED: Under shared MmState, only the last task holding the
    // Arc performs uncharge (mm_shared == false). Non-last exits skip uncharge
    // to prevent double-uncharge / memory.max bypass.
    //
    // Guard conditions:
    //   - !keep_address_space: When the address space is shared by threads
    //     (CLONE_VM), only the last thread to exit (keep_address_space=false)
    //     performs uncharge. This prevents double-uncharge of inherited entries.
    //   - !mm_shared: Only the last MmState holder uncharges.
    //   - proc.memory_space != 0: Clone error paths zero memory_space before
    //     calling cleanup_unscheduled_process(). Those children inherited a
    //     snapshot of the parent's mmap_regions but never owned the charges;
    //     uncharging here would corrupt the parent's cgroup accounting.
    //
    // Skip PROT_NONE reservations: they never allocated physical frames or
    // charged cgroup memory (R123-1 invariant INV-MM-PROT-NONE).
    if !keep_address_space && !mm_shared && proc.memory_space != 0 {
        let cgroup_id = proc.cgroup_id;
        for (_base, len_with_flags) in mm.mmap_regions.iter() {
            // R172-22: annotate value type (opaque iter() + Borrow-generic map).
            let len_with_flags: &crate::syscall::MmapEntry = len_with_flags;
            if len_with_flags.is_prot_none() {
                continue;
            }
            let len = crate::syscall::mmap_region_len(*len_with_flags) as u64;
            if len > 0 {
                crate::cgroup::uncharge_memory(cgroup_id, len);
            }
        }

        // R127-3 FIX: Uncharge brk heap allocations from cgroup as well.
        let heap_bytes = {
            const PAGE_SIZE: usize = 0x1000;
            let brk_aligned = (mm.brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let brk_start_aligned = (mm.brk_start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            brk_aligned.saturating_sub(brk_start_aligned) as u64
        };
        if heap_bytes > 0 {
            crate::cgroup::uncharge_memory(cgroup_id, heap_bytes);
        }

        // R137-1 FIX: Uncharge ELF loader allocations (PT_LOAD segments + user stack).
        let elf_bytes = mm.elf_charged_bytes;
        if elf_bytes > 0 {
            crate::cgroup::uncharge_memory(cgroup_id, elf_bytes);
            mm.elf_charged_bytes = 0;
        }

        // J2-9 FIX: Uncharge the page-table-frame kmem (PT/PD/PDPT frames charged
        // by sys_mmap). The intermediate tables are freed below by
        // free_page_table_level at last-AS teardown, so the charge is released
        // here under the SAME gate as the mmap/heap/elf uncharge: only the last
        // task holding this MmState (!keep_address_space && !mm_shared) uncharges,
        // exactly once. The non-last CLONE_VM exit (the else-if below) is a pt
        // no-op — surviving siblings still own the shared page-table frames.
        //
        // R171-CG1x0 FIX (M2-1 SLICE-0): by INVARIANT I' this single wholesale
        // uncharge of `pt_charged_bytes` (== pt_inherited_bytes + |ledger|*0x1000)
        // drains BOTH lanes at once — the per-frame munmap path only ever touched
        // the ledger lane (and already decremented pt_charged_bytes for it), so this
        // neither double-uncharges nor strands. The never-ledgered ELF/brk/KPTI
        // frames that free_page_table_level reclaims are correctly NOT uncharged
        // (they were never charged). Reset all three fields so a reused physical
        // frame in the next process can never collide with a stale ledger entry.
        let pt_bytes = mm.pt_charged_bytes;
        if pt_bytes > 0 {
            crate::cgroup::uncharge_memory(cgroup_id, pt_bytes);
            mm.pt_charged_bytes = 0;
        }
        mm.pt_charged_frames.clear();
        mm.pt_inherited_bytes = 0;
        mm.pt_ledger_authoritative = true;
    } else if (keep_address_space || mm_shared) && proc.memory_space != 0 {
        // Non-last CLONE_VM exit keeps the shared address space and MmState.
        // Do NOT uncharge — pages remain mapped in the shared page tables.
        // R162-16 FIX: Do NOT zero vm_charged_bytes on shared MmState —
        // surviving siblings still own those charges. The field is a running
        // counter used by compute_cgroup_charged_bytes() for diagnostics.
    }

    // 清理 mmap 区域跟踪 (only clear if we are the last holder)
    if !mm_shared {
        mm.mmap_regions.clear();
    }
    drop(mm);

    // R154-3 FIX: Extract fd_table entries WITHOUT dropping them here.
    // Socket destructors (close → wake_all) can lock other Process PCBs,
    // causing lock inversion if we drop while holding the caller's Process lock.
    // The extracted fds are returned; the caller drops them AFTER releasing the lock.
    let fd_count = proc.fd_table.len();
    let extracted_fds =
        core::mem::replace(&mut proc.fd_table, AdmittedMap::new(HeapClass::CoreProcess));
    proc.cloexec_fds.clear();

    // U.S3-B FIX: decrement each extracted fd's cap (revoke at 0) BEFORE the
    // PCB is torn down. Load-bearing for CLONE_THREAD: the cap_table Arc is
    // SHARED with surviving siblings, so a thread that exits without paying
    // back its per-fd refcounts (bumped at the CLONE_FILES install, U.S3-A3)
    // would strand every shared cap above 0 forever — the siblings' last
    // close could then never revoke (permanent slot leak → TableFull DoS).
    // For a non-shared table this is a harmless pre-drop of entries the table
    // teardown would free anyway. Leaf-safe under the Process lock; the
    // descriptor Boxes themselves still drop OUTSIDE the lock (R154-3).
    for desc in extracted_fds.values() {
        proc.decrement_fd_cap(desc.as_ref());
    }

    // J2-7: uncharge the per-cgroup FD budget. fd_table is PER-PROCESS (deep-
    // copied, never Arc-shared even under CLONE_FILES), so this is UNGATED by
    // keep_address_space/mm_shared (unlike the memory uncharge above). Uncharge
    // exactly the running charged count — authoritative, and may differ from
    // fd_count for a clone-error child that copied fds but failed before the
    // batch charge (fds_charged_count == 0 there → uncharge nothing). Idempotent:
    // zero after, so a second teardown call uncharges nothing.
    let total_fd_charges = proc
        .fds_charged_count
        .checked_add(proc.fd_reservations_charged_count)
        .expect("FD charge accounting overflow");
    if total_fd_charges > 0 {
        crate::cgroup::uncharge_fds(proc.cgroup_id, total_fd_charges);
    }
    proc.fds_charged_count = 0;
    proc.fd_reservations_charged_count = 0;
    proc.fd_reservations.fill(0);
    proc.fd_cloexec_reservations.fill(0);
    // R104-2 FIX: Gate all resource-cleanup diagnostics behind debug_assertions
    // to prevent leaking fd count, page table root addresses, and PID in release.
    if fd_count > 0 {
        kprintln!(
            "  Closed {} file descriptors for process {}",
            fd_count,
            proc.pid
        );
    }

    // 如果进程拥有独立的页表（memory_space != 0），释放页表及其管理的物理帧
    // R24-1 fix: 检查是否有其他线程共享地址空间，只有在无共享引用时才释放
    // 如果该线程是最后持有者（keep_address_space 为 false），也要释放地址空间避免泄漏
    if proc.memory_space != 0 {
        if keep_address_space {
            // 线程或被共享的地址空间不释放，只清零引用
            if !proc.is_thread {
                kprintln!(
                    "  Deferred address space release for process {} (shared by other threads)",
                    proc.pid
                );
            }
            proc.memory_space = 0;
            proc.user_memory_space = 0;
        } else {
            // H.3 KPTI: Free user PML4 root BEFORE freeing the kernel PML4.
            // The user PML4 shares user-half sub-table pointers with the kernel PML4,
            // so only the root frame is freed (no recursion into shared sub-tables).
            if proc.user_memory_space != 0 {
                crate::fork::free_kpti_user_pml4(proc.user_memory_space);
                proc.user_memory_space = 0;
            }

            // R104-2 FIX: Capture root before free for debug print, but gate the
            // print behind debug_assertions to avoid leaking PT root addresses.
            #[cfg(debug_assertions)]
            let _saved_root = proc.memory_space;
            free_address_space(proc.memory_space);
            kprintln!(
                "  Released page table hierarchy for process {} (root=0x{:x})",
                proc.pid,
                _saved_root
            );
            proc.memory_space = 0;
        }
    }

    // R114-1 FIX: IPC endpoint cleanup and cpuset task accounting are now performed
    // by `cleanup_zombie()` AFTER releasing PROCESS_TABLE, to avoid deadlocks from
    // callbacks that re-lock PROCESS_TABLE (e.g., futex cleanup → thread_group_size()).

    if region_count > 0 {
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
            "  Cleared {} mmap regions ({} KB) for process {}",
            region_count,
            total_size / 1024,
            proc.pid
        );
    }

    // R154-3 FIX: Return extracted fd_table so caller drops destructors
    // OUTSIDE the Process lock, preventing socket close lock inversion.
    extracted_fds
}

/// 释放指定进程的内核栈
///
/// 取消内核栈页面的映射并归还物理帧。守护页从未映射故无需处理。
///
/// # Arguments
///
/// * `pid` - 进程 ID（用于日志）
/// * `stack_base` - 内核栈底地址
///
/// # Safety Notes
///
/// SMP 下可能存在其他 CPU 仍在引用该栈（例如其正在进行上下文切换）。
/// 因此，实际的取消映射与物理帧归还通过 `call_rcu()` 延迟到 RCU grace period
/// 之后执行，以确保所有 CPU 都已进入过 quiescent state。
///
/// 如果当前 CPU 正在使用该栈，则仍跳过释放以避免自踩栈导致崩溃。
fn reclaim_kernel_stack(args: [usize; 2]) {
    let pid = args[0];
    let expected_phys = PhysFrame::from_start_address(PhysAddr::new(args[1] as u64))
        .unwrap_or_else(|_| panic!("RCU: unaligned kernel-stack physical identity"));
    let (stack_base, _) = kernel_stack_slot(pid)
        .unwrap_or_else(|_| panic!("RCU: invalid PID in kernel-stack callback"));

    // Prevalidate every leaf against the immutable original buddy-block
    // identity before mutating any PTE. A mismatch is quarantined in place.
    let reclaim_ready = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            for index in 0..KSTACK_PAGES {
                let page = Page::containing_address(stack_base + (index as u64 * PAGE_SIZE));
                let expected = PhysFrame::containing_address(
                    expected_phys.start_address() + (index as u64 * PAGE_SIZE),
                );
                if mgr.translate_page_4k(page) != Some(expected) {
                    return false;
                }
            }

            let mut cleared = 0usize;
            let mut matched = 0usize;
            let mut exact = true;
            for index in (0..KSTACK_PAGES).rev() {
                let page = Page::containing_address(stack_base + (index as u64 * PAGE_SIZE));
                let expected = PhysFrame::containing_address(
                    expected_phys.start_address() + (index as u64 * PAGE_SIZE),
                );
                match mgr.unmap_page(page) {
                    Ok(actual) => {
                        // `unmap_page` has already cleared the PTE on every Ok,
                        // even if the returned physical identity is wrong.  TLB
                        // invalidation therefore follows mutation accounting,
                        // while physical reuse additionally requires identity.
                        cleared += 1;
                        if actual == expected {
                            matched += 1;
                        } else {
                            exact = false;
                            break;
                        }
                    }
                    Err(_) => {
                        exact = false;
                        break;
                    }
                }
            }

            // Kernel-stack mappings are shared through many distinct CR3 roots.
            // Broadcast before any physical reuse, even on a partial failure.
            if cleared != 0 {
                mm::flush_all_address_spaces();
            }
            exact && matched == KSTACK_PAGES
        })
    };

    if !reclaim_ready {
        kprintln!(
            "  CRITICAL: quarantining unverifiable kernel-stack reclaim for PID {}",
            pid
        );
        crate::rcu::quarantine_running_stack_callback(pid);
        return;
    }

    let mut frame_alloc = FrameAllocator::new();
    if frame_alloc
        .try_deallocate_contiguous_frames(expected_phys, KSTACK_PAGES)
        .is_err()
    {
        kprintln!(
            "  CRITICAL: buddy rejected kernel-stack block for PID {}; quarantining slot",
            pid
        );
        crate::rcu::quarantine_running_stack_callback(pid);
        return;
    }

    kprintln!("  Released kernel stack for PID {}", pid);
}

pub fn free_kernel_stack(
    pid: ProcessId,
    stack_base: VirtAddr,
    stack_phys: PhysFrame<Size4KiB>,
    reclaim_permit: crate::rcu::RcuCallbackPermit,
) {
    use core::arch::asm;

    let stack_base_u64 = stack_base.as_u64();
    if kernel_stack_slot(pid)
        .map(|(expected, _)| expected != stack_base)
        .unwrap_or(true)
    {
        kprintln!(
            "  CRITICAL: quarantining invalid kernel-stack teardown identity for PID {}",
            pid
        );
        core::mem::forget(reclaim_permit);
        return;
    }

    // 【关键修复】检查当前 CPU 是否正在使用该栈
    let current_rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags));
    }

    let stack_bottom = stack_base_u64;
    let stack_top = stack_bottom + (KSTACK_PAGES as u64 * PAGE_SIZE);

    if current_rsp >= stack_bottom && current_rsp < stack_top {
        // 当前 CPU 正在使用此栈，不能释放（会导致自踩栈崩溃）
        // 这种情况不应该发生（进程应在不同栈上清理自己的栈），但防御性编程
        // R104-2 FIX: Gate to prevent leaking kernel RSP in release builds.
        kprintln!(
            "  CRITICAL: quarantining kernel stack for PID {} (in use by current CPU, RSP=0x{:x})",
            pid,
            current_rsp
        );
        // Releasing this dedicated permit would allow PID reuse while its old
        // stack remains mapped. Keep both resources quarantined fail-closed.
        core::mem::forget(reclaim_permit);
        return;
    }

    // R180-12: permit consumption makes enqueue infallible after teardown's
    // point of no return. Function pointer + two words fit in the static slot.
    crate::rcu::call_rcu_stack(
        reclaim_permit,
        pid,
        reclaim_kernel_stack,
        [pid, stack_phys.start_address().as_u64() as usize],
    );
}

/// 释放独立用户地址空间（PML4 物理地址）
///
/// - 仅遍历用户空间映射 (PML4[0..255])
/// - 使用 COW 引用计数安全地释放叶子页
/// - 最后释放 PML4 帧本身
///
/// 调用者必须确保该地址空间不再被任何 CPU 使用。
pub fn free_address_space(memory_space: usize) {
    if memory_space == 0 {
        return;
    }

    unsafe {
        let mut frame_alloc = FrameAllocator::new();
        let root_frame: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64));
        let root_table = phys_to_virt_table(root_frame.start_address());

        // 只遍历用户空间映射 (PML4 index 0-255)，内核高半区 (256-511) 共享无需处理
        free_page_table_level(root_table, 4, &mut frame_alloc);

        // 释放 PML4 帧本身
        frame_alloc.deallocate_frame(root_frame);
    }
}

/// 递归释放页表层级
///
/// level: 4=PML4, 3=PDPT, 2=PD, 1=PT
///
/// 直接使用 memory_space 的物理地址，通过恒等映射访问页表，避免依赖当前 CR3。
///
/// # Safety
///
/// 调用者必须确保 `table` 指向有效的页表，且页表不再被任何进程使用。
unsafe fn free_page_table_level(
    table: &mut PageTable,
    level: u8,
    frame_alloc: &mut FrameAllocator,
) {
    // PML4 只处理用户空间条目 (0-255)，其他层级处理全部 512 条目
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut table[idx];
        if entry.is_unused() {
            continue;
        }

        let flags = entry.flags();
        let entry_phys = entry.addr();

        // RF178-31: the low identity map is supervisor-only and shared. COW
        // clones copy those leaves but never own their physical frames; only
        // the private intermediate page-table frames are reclaimed below.
        let is_leaf = level == 1 || flags.contains(PageTableFlags::HUGE_PAGE);
        if is_leaf && !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            entry.set_unused();
            continue;
        }

        // R123-1 defense-in-depth: Reclaim leaf frames referenced by non-present
        // PTEs. A buggy PROT_NONE mmap path could install non-present leaf entries
        // that still encode a physical frame address. Older code skipped all
        // non-PRESENT entries, leaking those frames permanently. At level 1 (PT),
        // if the PTE is non-present but encodes a non-zero physical address, free
        // the frame. At higher levels, skip non-present entries (intermediate page
        // table structures are always present when valid).
        if level == 1 && !flags.contains(PageTableFlags::PRESENT) {
            if entry_phys.as_u64() != 0 {
                free_leaf_frame(entry_phys, frame_alloc);
                entry.set_unused();
            }
            continue;
        }

        if !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        // 检查是否是大页 (2MB 或 1GB)
        //
        // R49-2 FIX: Previously this code skipped huge pages entirely, causing
        // memory leaks if user-space ever used huge pages. While user-space
        // typically doesn't use huge pages currently, we should:
        // 1. Clear the page table entry (defense-in-depth)
        // 2. Attempt to free the physical memory
        //
        // Note: Buddy allocator only tracks 4KB frames. For huge pages, we
        // release the base frame which may not fully reclaim the memory.
        // Future improvement: Extend buddy allocator for multi-page frees.
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            // Release the huge page physical memory to prevent leak
            let huge_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(entry_phys);
            frame_alloc.deallocate_frame(huge_frame);

            // Clear the page table entry for defense-in-depth
            entry.set_unused();
            continue;
        }

        if level == 1 {
            // PT 层级的叶子节点：释放 4KB 物理帧
            free_leaf_frame(entry_phys, frame_alloc);
        } else {
            // 中间节点：递归处理子页表
            let next_table = phys_to_virt_table(entry_phys);
            free_page_table_level(next_table, level - 1, frame_alloc);

            // 释放子页表帧本身
            let next_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(entry_phys);
            frame_alloc.deallocate_frame(next_frame);
        }
    }
}

/// 释放叶子页物理帧
///
/// 使用 COW 引用计数管理：减少引用计数，当计数归零时释放物理帧。
/// 对于未被 COW 跟踪的页面（refcount=0），直接释放。
fn free_leaf_frame(phys: PhysAddr, frame_alloc: &mut FrameAllocator) {
    let phys_usize = phys.as_u64() as usize;

    // RF178-31: one atomic operation decides ownership. An invalid physical
    // address is retained leak-safe instead of being returned to the buddy.
    if PAGE_REF_COUNT.release(phys_usize).should_free_unmapped() {
        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(phys);
        frame_alloc.deallocate_frame(frame);
    }
}

/// 将物理地址转换为页表引用（使用高半区直映）
///
/// # Safety
///
/// 调用者必须确保：
/// - 物理地址指向有效的页表
/// - 物理地址在 0-1GB 范围内（高半区直映覆盖的范围）
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 获取进程统计信息
pub fn get_process_stats() -> ProcessStats {
    let table = PROCESS_TABLE.lock();
    let mut stats = ProcessStats::default();

    // 遍历进程表，跳过 None 值
    for slot in table.iter() {
        if let Some(process) = slot {
            stats.total += 1;
            let proc = process.lock();
            // R98-1 FIX: Check orthogonal stopped flag before state.
            // Zombie/Terminated take priority, then stopped flag, then scheduler state.
            match proc.state {
                ProcessState::Zombie => stats.zombie += 1,
                ProcessState::Terminated => stats.terminated += 1,
                ProcessState::Stopped => stats.stopped += 1,
                _ if proc.stopped => stats.stopped += 1,
                ProcessState::Provisioning => stats.blocked += 1,
                ProcessState::Ready => stats.ready += 1,
                ProcessState::Running => stats.running += 1,
                ProcessState::Blocked => stats.blocked += 1,
                ProcessState::Sleeping => stats.sleeping += 1,
            }
        }
    }

    stats
}

/// Computes the total cgroup-charged memory bytes for a process.
///
/// R143-1 FIX: Used by cgroup migration to transfer memory charges from
/// source to destination cgroup. Sums:
/// 1. mmap_regions (excluding PROT_NONE reservations which never charged)
/// 2. brk heap (page-aligned brk - brk_start)
/// 3. elf_charged_bytes (PT_LOAD segments + user stack from ELF loader)
/// 4. mprotect_pending_bytes (R147-1 FIX: in-flight PROT_NONE→real charges)
///
/// This mirrors the uncharge logic in `free_process_resources()`.
pub fn compute_cgroup_charged_bytes(proc: &Process) -> u64 {
    // D3-ARC-MM-SHARED: Lock the shared MmState to read mmap/brk metadata.
    let mm = proc.mm.lock();

    // Sum mmap region charges, skipping PROT_NONE reservations (never charged).
    let mmap_bytes: u64 = mm
        .mmap_regions
        .iter()
        .filter_map(
            |(_base, len_with_flags): (&usize, &crate::syscall::MmapEntry)| {
                if len_with_flags.is_prot_none() {
                    return None;
                }
                let len = crate::syscall::mmap_region_len(*len_with_flags) as u64;
                if len > 0 {
                    Some(len)
                } else {
                    None
                }
            },
        )
        .sum();

    // Compute brk heap charge (page-aligned).
    const PAGE_SIZE: usize = 0x1000;
    let brk_aligned = (mm.brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let brk_start_aligned = (mm.brk_start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let heap_bytes = brk_aligned.saturating_sub(brk_start_aligned) as u64;

    // R144-1 FIX: Include pending brk growth that has been charged to the
    // cgroup but not yet reflected in mm.brk (lock dropped for PT ops).
    let pending_brk = mm.brk_pending_growth;

    // R147-1 FIX: Include pending mprotect PROT_NONE->real charges.
    let pending_mprotect = mm.mprotect_pending_bytes;

    // R149-3 FIX: Include pending exec (load_elf) charges.
    let pending_exec = mm.exec_pending_bytes;

    // M0-7 item7 SLICE 4: include an in-flight user-stack grow's DATA charge that
    // has been HARD-charged to the cgroup but not yet folded into elf_charged_bytes
    // (the Process lock is dropped for the grow's page-table work). Mirrors the
    // R144-1 brk_pending_growth term so a cgroup migration racing the lock-dropped
    // window transfers the in-flight stack charge instead of stranding it.
    let pending_stack = mm.stack_grow_pending_bytes;

    // ELF loader charges (PT_LOAD segments + user stack).
    let elf_bytes = mm.elf_charged_bytes;

    // J2-9 FIX: Include the page-table-frame kmem charge. MANDATORY for cgroup
    // migration correctness: cgroup migration transfers exactly
    // compute_cgroup_charged_bytes() from source to destination. If the pt term
    // were omitted, migration would under-transfer the pt bytes — the source
    // would later double-uncharge them (memory_current underflow → memory.max
    // bypass) and the destination would under-count. pt_charged_bytes is the
    // sole pt term (charged under the Process lock at sys_mmap Phase 3, so no
    // lock-dropped in-flight window exists that would need a transient mirror —
    // migration is Process-lock-atomic, see sys_cgroup_attach R155-5).
    let pt_bytes = mm.pt_charged_bytes;

    mmap_bytes
        .saturating_add(heap_bytes)
        .saturating_add(pending_brk)
        .saturating_add(pending_mprotect)
        .saturating_add(pending_exec)
        .saturating_add(pending_stack)
        .saturating_add(elf_bytes)
        .saturating_add(pt_bytes)
}

/// R171-CG1x0 FIX (M2-1 SLICE-0): reconcile the per-AS page-table provenance ledger
/// against the frames a `sys_munmap` prune reclaimed. Returns the bytes to uncharge
/// = `0x1000 * |reclaimed ∩ ledger|` and REMOVES the matched frames from the ledger.
///
/// This is the load-bearing anti-bypass primitive: a reclaimed table frame is debited
/// IFF this address space charged it (frame identity — on `sys_mmap` or mprotect
/// Path-A), so a frame that `prune_empty_tables_in_range` happened to reclaim but was
/// built UNCHARGED by brk/ELF (absent from the ledger) is correctly NOT debited — closing
/// the cross-origin `memory.max` under-count. Pure and side-effect-scoped to `ledger`
/// so the property is unit-testable without a live process context.
pub fn pt_ledger_reconcile<I: Iterator<Item = u64>>(
    ledger: &mut crate::fallible_map::FallibleOrderedMap<u64, ()>,
    reclaimed_phys: I,
) -> u64 {
    let mut pt_freed: u64 = 0;
    for fa in reclaimed_phys {
        if ledger.remove(&fa).is_some() {
            pt_freed = pt_freed.saturating_add(0x1000);
        }
    }
    pt_freed
}

/// In-kernel self-test for the R171-CG1x0 frame-identity PT ledger reconcile (the
/// anti-bypass core of M2-1 SLICE-0). Panics on failure; detected by `make test` /
/// `make boot-check` via the serial log. The full mmap/munmap integration (Phase-3
/// fold + free-after-remove ordering) is exercised by reaching userspace under
/// `boot-check`; this asserts the provenance arithmetic the syscall path relies on.
pub fn run_pt_ledger_self_test() {
    use crate::fallible_map::FallibleOrderedMap;
    const PT: u64 = 0x1000;

    // Ledger holds three CHARGED mmap PT frames (A, B, C by physical address).
    let (a, b, c) = (0x10_0000u64, 0x20_0000u64, 0x30_0000u64);
    // Two UNCHARGED frames (built by brk/ELF — mprotect Path-A is charged as of
    // SLICE-4a): X, Y — never ledgered.
    let (x, y) = (0x40_0000u64, 0x50_0000u64);

    let mut ledger: FallibleOrderedMap<u64, ()> = FallibleOrderedMap::new();
    ledger.try_reserve(3).expect("reserve pt ledger");
    assert!(ledger.try_insert(a, ()).expect("ins a").is_none());
    assert!(ledger.try_insert(b, ()).expect("ins b").is_none());
    assert!(ledger.try_insert(c, ()).expect("ins c").is_none());
    assert_eq!(ledger.len(), 3, "ledger holds three charged frames");

    // A munmap reclaims {A, X, Y}: only A is in the ledger ⇒ debit exactly 0x1000.
    // X and Y are UNCHARGED — debiting them would be the cross-origin memory.max
    // bypass. This is the property's whole point.
    let freed = pt_ledger_reconcile(&mut ledger, [a, x, y].into_iter());
    assert_eq!(
        freed, PT,
        "reclaim {{A,X,Y}} debits ONLY the charged frame A"
    );
    assert_eq!(ledger.len(), 2, "A removed; B,C remain");
    assert!(ledger.get(&a).is_none(), "A gone from ledger");

    // Re-reclaiming A (e.g. a buggy double-free) debits nothing (already removed) —
    // saturating / idempotent in the safe direction.
    let again = pt_ledger_reconcile(&mut ledger, core::iter::once(a));
    assert_eq!(
        again, 0,
        "double-reclaim of A debits nothing (no under-count)"
    );

    // Reclaiming the rest {B, C} drains the ledger exactly: 2 * 0x1000.
    let rest = pt_ledger_reconcile(&mut ledger, [b, c].into_iter());
    assert_eq!(
        rest,
        2 * PT,
        "reclaim {{B,C}} debits both remaining charged frames"
    );
    assert_eq!(
        ledger.len(),
        0,
        "ledger empty after all charged frames reclaimed"
    );

    // A reclaim against an empty/non-authoritative ledger (e.g. a forked child's
    // inherited region) debits nothing — the basis rides to teardown (over-count-safe).
    let none = pt_ledger_reconcile(&mut ledger, [x, y, a, b].into_iter());
    assert_eq!(none, 0, "empty ledger debits nothing");
}

/// M2-1 SLICE-4a: in-kernel self-test for `MmState::record_pt_charge` — the
/// extracted, unit-tested PT-charge fold that `sys_mprotect` Path-A now uses to
/// charge the page-table frames a `PROT_NONE -> real` materialization builds
/// (mirror of the inline `sys_mmap` Phase-3 fold). Validates INVARIANT I' on the
/// ledgered-success branch, the data/PT split guard (charge == frame count, NOT
/// region bytes), and the telescoping round-trip through the REAL
/// `pt_ledger_reconcile` (the munmap reclaim path). Panics on failure; detected
/// by `make test` / `make boot-check` via the serial log. (The OOM-fallback
/// branch — `pt_inherited_bytes` — is not unit-forced here, same as the mmap
/// fold; it is over-count-safe by construction and exercised only under heap
/// exhaustion.)
pub fn run_record_pt_charge_self_test() {
    use x86_64::structures::paging::PhysFrame;
    const PT: u64 = 0x1000;

    let frame = |pa: u64| -> PhysFrame<Size4KiB> {
        PhysFrame::containing_address(x86_64::PhysAddr::new(pa))
    };
    // INVARIANT I': pt_charged_bytes == pt_inherited_bytes + |ledger| * 0x1000.
    let inv = |mm: &MmState| -> bool {
        mm.pt_charged_bytes == mm.pt_inherited_bytes + (mm.pt_charged_frames.len() as u64) * PT
    };

    // Fresh AS: authoritative, all zero (I' holds: 0 == 0 + 0).
    let mut mm = MmState::new(0);
    assert!(inv(&mm), "fresh AS satisfies I'");
    assert_eq!(mm.pt_charged_bytes, 0);
    assert!(mm.pt_ledger_authoritative);

    // RF178-12: synchronous #PF commits are allocation-free and put PT bytes in
    // the wholesale-teardown basis. Neither the ledger length nor its retained
    // capacity may change on the full-DATA or PT-only partial-publication path.
    let mut fault_mm = MmState::new(0);
    fault_mm.elf_charged_bytes = 9 * PT;
    fault_mm.stack_floor_committed = 0x7000_0000;
    fault_mm.stack_grow_in_progress = true;
    let ledger_len = fault_mm.pt_charged_frames.len();
    let ledger_capacity = fault_mm.pt_charged_frames.capacity();
    fault_mm.commit_fault_stack_grow(3 * PT, 2 * PT, 0x6fff_d000);
    assert_eq!(fault_mm.elf_charged_bytes, 12 * PT);
    assert_eq!(fault_mm.pt_charged_bytes, 2 * PT);
    assert_eq!(fault_mm.pt_inherited_bytes, 2 * PT);
    assert_eq!(fault_mm.stack_floor_committed, 0x6fff_d000);
    assert!(!fault_mm.stack_grow_in_progress);
    assert_eq!(fault_mm.pt_charged_frames.len(), ledger_len);
    assert_eq!(fault_mm.pt_charged_frames.capacity(), ledger_capacity);
    assert!(inv(&fault_mm), "synchronous full commit preserves I'");

    // A mapper can publish an intermediate PT and then fail before its first
    // leaf. Account the PT, keep the DATA floor unchanged, and clear the grow
    // reservation before the architectural caller terminates the task.
    fault_mm.stack_grow_in_progress = true;
    let unchanged_floor = fault_mm.stack_floor_committed;
    fault_mm.commit_fault_stack_grow(0, PT, unchanged_floor);
    assert_eq!(fault_mm.elf_charged_bytes, 12 * PT);
    assert_eq!(fault_mm.pt_charged_bytes, 3 * PT);
    assert_eq!(fault_mm.pt_inherited_bytes, 3 * PT);
    assert_eq!(fault_mm.stack_floor_committed, unchanged_floor);
    assert!(!fault_mm.stack_grow_in_progress);
    assert_eq!(fault_mm.pt_charged_frames.len(), ledger_len);
    assert_eq!(fault_mm.pt_charged_frames.capacity(), ledger_capacity);
    assert!(inv(&fault_mm), "PT-only fatal partial commit preserves I'");

    // 1) LEDGERED-SUCCESS branch: record 3 distinct PT frames (as mprotect Path-A
    //    does for a freshly-materialized region). pt_charged_bytes rises by
    //    EXACTLY 3 * PT — NOT the region's DATA bytes: this is the guard against
    //    the allocate_data_frame mis-wire that would route DATA pages through the
    //    recording trait and over-charge ~100%. The ledger grows by 3 (frame
    //    identity), the inherited basis is untouched, authoritative stays true.
    let (a, b, c) = (0x10_0000u64, 0x20_0000u64, 0x30_0000u64);
    mm.record_pt_charge(&[frame(a), frame(b), frame(c)]);
    assert_eq!(
        mm.pt_charged_bytes,
        3 * PT,
        "charged the PT-frame COUNT, not data bytes"
    );
    assert_eq!(
        mm.pt_charged_frames.len(),
        3,
        "three frames ledgered by identity"
    );
    assert_eq!(
        mm.pt_inherited_bytes, 0,
        "ledgered branch leaves the inherited basis at 0"
    );
    assert!(mm.pt_ledger_authoritative, "AS stays authoritative");
    assert!(inv(&mm), "I' holds after the ledgered charge");

    // 2) Empty record is a no-op (the pt_bytes == 0 fast path).
    mm.record_pt_charge(&[]);
    assert_eq!(mm.pt_charged_bytes, 3 * PT, "empty record is a no-op");
    assert!(inv(&mm));

    // 3) TELESCOPING round-trip: reclaim the exact frames via the REAL
    //    pt_ledger_reconcile (the munmap reclaim path mprotect Path-A regions ride).
    //    Each charged frame debits exactly PT; draining pt_charged_bytes leaves I'
    //    holding at 0 == 0 + 0 — charge == reclaim, the whole point of SLICE-4a.
    let freed = pt_ledger_reconcile(&mut mm.pt_charged_frames, [a, b, c].into_iter());
    assert_eq!(
        freed,
        3 * PT,
        "reconcile debits exactly the three charged frames"
    );
    mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(freed);
    assert_eq!(
        mm.pt_charged_bytes, 0,
        "pt_charged_bytes telescopes to 0 on matched reclaim"
    );
    assert_eq!(mm.pt_charged_frames.len(), 0, "ledger empty after reclaim");
    assert!(inv(&mm), "I' holds after the matched reclaim");

    // 4) Cross-origin guard: reclaiming frames NOT in the ledger debits 0 — an
    //    uncharged brk/ELF frame is never debited (the anti-bypass property the
    //    frame-identity ledger exists for, here for the mprotect lane).
    let (x, y) = (0x40_0000u64, 0x50_0000u64);
    let none = pt_ledger_reconcile(&mut mm.pt_charged_frames, [x, y].into_iter());
    assert_eq!(
        none, 0,
        "reclaim of unledgered frames debits nothing (no bypass)"
    );

    // 5) INHERITED-basis coexistence: an AS born with a fork-inherited basis that
    //    then records its OWN mprotect-materialized frames keeps I' across BOTH
    //    lanes (inherited wholesale + own frame-identity).
    let mut child = MmState::new(0);
    child.pt_inherited_bytes = 5 * PT; // simulate fork inheritance basis
    child.pt_charged_bytes = 5 * PT; // I' holds: 5PT == 5PT + 0
    child.pt_ledger_authoritative = false;
    assert!(inv(&child), "inherited-only child satisfies I'");
    child.record_pt_charge(&[frame(a), frame(b)]);
    assert_eq!(child.pt_charged_bytes, 7 * PT, "inherited 5PT + own 2PT");
    assert_eq!(
        child.pt_charged_frames.len(),
        2,
        "own frames ledgered by identity"
    );
    assert_eq!(
        child.pt_inherited_bytes,
        5 * PT,
        "inherited basis untouched by ledgered charge"
    );
    assert!(
        child.pt_ledger_authoritative,
        "child flips authoritative once it tracks own frames"
    );
    assert!(inv(&child), "I' holds across inherited + ledgered lanes");
}

/// M0-7 item7 SLICE 4: pure unit test for the stack-grow accounting STATE MACHINE —
/// the `stack_grow_floor` RLIMIT clamp and the FA-04 `commit_stack_grow` move. No
/// Process / page-table / cgroup context is needed (the cgroup-charge telescoping is
/// proven separately by `cgroup::run_stack_grow_cgroup_self_test`). Panics on failure;
/// detected by `make test` / `make boot-check` via the serial log.
pub fn run_stack_grow_accounting_self_test() {
    use crate::elf_loader::{
        stack_grow_floor, user_stack_mapped_floor, user_stack_usable_floor, USER_STACK_TOP,
    };
    const PAGE: usize = 0x1000;

    // ── grow_floor clamp (the RLIMIT_STACK → lowest growable VA mapping) ──
    let mapped_floor = user_stack_mapped_floor() as usize;
    let usable_floor = user_stack_usable_floor() as usize;
    let writable_extent = USER_STACK_TOP as usize - usable_floor; // == SIZE - GUARD

    // Default rlim_cur (== the writable extent) ⇒ floor == the architectural mapped floor:
    // on a default process the whole window-minus-guard is already eager-mapped, so there
    // is NO lazy region to grow into (a real grow would be ENOMEM — SLICE 5 splits this).
    assert_eq!(
        stack_grow_floor(writable_extent as u64),
        usable_floor,
        "default RLIMIT_STACK => grow_floor == architectural usable floor"
    );
    // An INFINITE rlim_cur clamps to the SAME floor — the load-bearing min(): a raised
    // soft limit can never push the growable region below the architectural window.
    assert_eq!(
        stack_grow_floor(u64::MAX),
        usable_floor,
        "infinite RLIMIT_STACK clamps to the usable floor (window bound)"
    );
    // A SMALLER limit (1 page) ⇒ a HIGHER floor (one page growable below TOP).
    assert_eq!(
        stack_grow_floor(PAGE as u64),
        USER_STACK_TOP as usize - PAGE,
        "1-page RLIMIT_STACK ⇒ floor one page below TOP"
    );
    // A partial-page limit rounds the extent DOWN (a SMALLER region, the conservative
    // direction) so the floor stays page-aligned.
    assert_eq!(
        stack_grow_floor((PAGE + 1) as u64),
        USER_STACK_TOP as usize - PAGE,
        "partial-page RLIMIT_STACK rounds the extent down (page-aligned floor)"
    );
    // Whatever the limit, the floor is page-aligned and within [usable_floor, TOP].
    for &r in &[
        0u64,
        1,
        PAGE as u64,
        writable_extent as u64,
        writable_extent as u64 + PAGE as u64,
        u64::MAX,
    ] {
        let f = stack_grow_floor(r);
        assert_eq!(f & (PAGE - 1), 0, "grow_floor must be page-aligned");
        assert!(
            f >= usable_floor && f <= USER_STACK_TOP as usize,
            "grow_floor within [usable_floor, TOP]"
        );
    }

    // ── commit_stack_grow: the FA-04 move (pending lane → elf_charged_bytes) ──
    let mut mm = MmState::new(0);
    let old_floor = mapped_floor;
    let new_floor = old_floor - 4 * PAGE;
    let grow = (4 * PAGE) as u64;
    // Simulate Phase-0/1 arming: reservation set, the grow DATA in the pending lane, and a
    // prior elf charge present (the initial eager stack already lives in elf_charged_bytes).
    mm.elf_charged_bytes = (9 * PAGE) as u64;
    mm.stack_floor_committed = old_floor;
    mm.stack_grow_in_progress = true;
    mm.stack_grow_pending_bytes = grow;
    let elf_before = mm.elf_charged_bytes;
    mm.commit_stack_grow(grow, new_floor);
    // FA-04: the grow DATA lands in elf_charged_bytes — the ONE bucket that
    // free_process_resources (process.rs:4992) AND compute_cgroup_charged_bytes
    // (process.rs:5433) BOTH read, and fork inherits — so a stack-growing exit cannot
    // strand a charge (the vm_charged_bytes home would have, → delete_cgroup DoS).
    assert_eq!(
        mm.elf_charged_bytes,
        elf_before + grow,
        "grow DATA folded into elf_charged_bytes (FA-04 home)"
    );
    assert_eq!(
        mm.stack_grow_pending_bytes, 0,
        "pending lane drained by the commit"
    );
    assert_eq!(
        mm.stack_floor_committed, new_floor,
        "watermark advanced to new_floor"
    );
    assert!(
        !mm.stack_grow_in_progress,
        "reservation cleared by the commit"
    );

    // compute_cgroup_charged_bytes summand wiring: an in-flight pending lane is counted
    // (so a cgroup migration racing the lock-dropped window transfers it). Re-arm and
    // assert the field is the one summed — proven at the FIELD level here; the live
    // compute() sum over a real Process is exercised by the cgroup migration self-test.
    mm.stack_grow_pending_bytes = grow;
    assert_eq!(
        mm.stack_grow_pending_bytes, grow,
        "pending lane holds the in-flight grow DATA between arm and commit"
    );
}

/// 进程统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessStats {
    pub total: usize,
    pub ready: usize,
    pub running: usize,
    pub stopped: usize,
    pub blocked: usize,
    pub sleeping: usize,
    pub zombie: usize,
    pub terminated: usize,
}

impl ProcessStats {
    pub fn print(&self) {
        klog!(Info, "=== Process Statistics ===");
        klog!(Info, "Total:      {}", self.total);
        klog!(Info, "Ready:      {}", self.ready);
        klog!(Info, "Running:    {}", self.running);
        klog!(Info, "Stopped:    {}", self.stopped);
        klog!(Info, "Blocked:    {}", self.blocked);
        klog!(Info, "Sleeping:   {}", self.sleeping);
        klog!(Info, "Zombie:     {}", self.zombie);
        klog!(Info, "Terminated: {}", self.terminated);
    }
}

// ========== OOM Killer 回调实现 ==========

/// Return the highest-scoring currently observable OOM victim without allocating.
/// Every lock in this recovery scan is nonblocking: a contended table, PCB, mm,
/// or credential object is deferred to a later allocator-failure poll.
pub fn oom_snapshot() -> Option<mm::OomProcessInfo> {
    let table = PROCESS_TABLE.try_lock()?;
    let mut best = None;
    let mut best_score = i64::MIN;

    for process in table.iter().flatten() {
        let proc = match process.try_lock() {
            Some(proc) => proc,
            None => continue,
        };
        if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
            continue;
        }

        let rss_pages = {
            let mm_state = match proc.mm.try_lock() {
                Some(mm_state) => mm_state,
                None => continue,
            };
            let rss_bytes = mm_state
                .mmap_regions
                .values()
                .fold(0usize, |total, &entry| {
                    total.saturating_add(crate::syscall::mmap_region_len(entry))
                });
            (rss_bytes / 4096) as u64
        };

        let (uid, gid) = {
            let creds = match proc.credentials.try_read() {
                Some(creds) => creds,
                None => continue,
            };
            (creds.uid, creds.gid)
        };

        let candidate = mm::OomProcessInfo {
            pid: proc.pid,
            generation: proc.generation,
            tgid: proc.tgid,
            uid,
            gid,
            rss_pages,
            nice: proc.nice,
            oom_score_adj: proc.oom_score_adj,
            has_mm: proc.memory_space != 0,
            is_kernel_thread: proc.memory_space == 0,
        };
        let score = mm::score_oom_process(&candidate);
        if score > best_score {
            best_score = score;
            best = Some(candidate);
        }
    }

    best
}

/// Post a generation-bound deferred exit request for the selected OOM victim.
/// Validation and publication share one PCB try-lock, so PID reuse cannot redirect
/// the kill and contention cannot deadlock an allocation recovery path.
pub fn oom_kill(pid: ProcessId, generation: u64, exit_code: i32) -> bool {
    let proc_arc = match try_get_process(pid) {
        Some(Some(proc_arc)) => proc_arc,
        Some(None) | None => return false,
    };
    let mut proc = match proc_arc.try_lock() {
        Some(proc) => proc,
        None => return false,
    };
    if proc.pid != pid || proc.generation != generation {
        return false;
    }

    let post = request_process_exit_locked(&mut proc, exit_code, crate::get_ticks());
    drop(proc);
    finish_process_exit_request(post)
}

/// OOM killer 调用的时间戳函数
///
/// 返回当前时间戳（毫秒）
pub fn oom_timestamp() -> u64 {
    time::current_timestamp_ms()
}

/// 注册 OOM killer 回调
///
/// 在内核初始化时调用，将进程管理函数注册到 OOM killer
pub fn register_oom_callbacks() {
    mm::register_oom_callbacks(oom_snapshot, oom_kill, oom_timestamp);
    klog!(Info, "  OOM killer callbacks registered");
}
