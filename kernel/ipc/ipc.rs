//! 进程间通信 (IPC) 系统
//!
//! 实现基于能力的端点通信，提供：
//! - 每进程端点命名空间隔离
//! - 基于能力的访问控制（allowed_senders）
//! - 不可伪造的发送者身份（自动从current_pid获取）
//! - 有界消息队列（防止OOM）
//! - 背压机制（队列满时返回错误）
//! - R75-2 FIX: 按 IPC 命名空间分区端点表

use alloc::{
    alloc::{AllocError, Allocator, Global},
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::{
    alloc::Layout,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use mm::{
    arc_charge_bytes, try_reserve_heap, AdmittedAllocError, AdmittedDeque, HeapCharge, HeapClass,
    PreparedAdmittedDequeCapacity, RetiredAdmittedDequeCapacity,
};
use spin::Mutex;

use crate::process::{self, ProcessId};
use kernel_core::{current_ipc_ns_id, NamespaceId};
// G.1 Observability: Per-CPU counter integration for IPC message tracking
use trace::counters::{increment_counter, TraceCounter};

/// 端点标识符类型
pub type EndpointId = u64;

/// 每个端点的最大消息数量（背压阈值）
const MAX_MESSAGES_PER_ENDPOINT: usize = 64;

/// 每个进程可注册的最大端点数
const MAX_ENDPOINTS_PER_PROCESS: usize = 32;

/// 每个端点可显式授权的最大发送者数量（所有者自动包含）
const MAX_ALLOWED_SENDERS: usize = 32;

/// 单条消息最大数据长度（字节）
const MAX_MESSAGE_SIZE: usize = 4096;

/// IPC消息
#[derive(Debug, Clone)]
pub struct Message {
    /// 发送者进程ID（由系统自动填充，不可伪造）
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// 接收到的消息
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// 发送者进程ID
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// IPC错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// 没有当前进程上下文
    NoCurrentProcess,
    /// R106-1 FIX: 目标进程不存在（无法查询 generation）
    ProcessNotFound,
    /// 端点不存在
    EndpointNotFound,
    /// 访问被拒绝（无发送权限或非端点所有者）
    AccessDenied,
    /// 消息队列已满（背压）
    QueueFull,
    /// 消息过大
    MessageTooLarge,
    /// 端点数量超限
    TooManyEndpoints,
    /// 端点发送者白名单数量超限
    TooManySenders,
    /// IPC 操作所需内存分配失败
    NoMemory,
    /// R105-5 FIX: 全局端点 ID 空间耗尽
    EndpointIdExhausted,
    /// M0-5 1b-1b: a pending kill or a deliverable HANDLER signal interrupted a blocking
    /// `receive_message_blocking` (the M0-5 1b wake) → maps to EINTR, replacing the
    /// imprecise `NoCurrentProcess`/ESRCH. See `ipc_error_to_syscall`.
    Interrupted,
}

/// IPC端点
///
/// 每个端点属于一个进程（owner），只有owner可以接收消息。
/// 发送权限通过allowed_senders白名单控制。
///
/// R106-1 FIX: 授权现在使用 (ProcessId, generation) 二元组而非裸 PID，
/// 防止 PID 复用后新进程继承旧进程的 IPC 发送权限。
#[derive(Debug)]
struct Endpoint {
    /// 端点所有者进程ID
    owner: ProcessId,
    /// R106-1 FIX: 端点所有者的 generation
    owner_generation: u64,
    /// R106-1 FIX: 允许发送消息的进程 (pid -> generation)
    allowed_senders: BTreeMap<ProcessId, u64>,
    /// 消息队列
    queue: VecDeque<Message>,
}

impl Endpoint {
    /// 创建新端点
    ///
    /// R106-1 FIX: 接受预解析的 (pid, generation) 对，避免在持有 ENDPOINTS 锁时
    /// 访问 PROCESS_TABLE（防止锁序反转死锁）。
    fn new(owner: ProcessId, owner_generation: u64, resolved_senders: &[(ProcessId, u64)]) -> Self {
        let mut allowed = BTreeMap::new();
        // 所有者总是可以发送（给自己）
        allowed.insert(owner, owner_generation);
        for &(pid, gen) in resolved_senders {
            if pid == owner {
                continue; // 已添加
            }
            allowed.insert(pid, gen);
        }

        Endpoint {
            owner,
            owner_generation,
            allowed_senders: allowed,
            queue: VecDeque::new(),
        }
    }

    /// 检查进程是否有发送权限
    ///
    /// R106-1 FIX: 同时验证 PID 和 generation，防止 PID 复用后的越权发送。
    fn can_send(&self, sender: ProcessId, sender_generation: u64) -> bool {
        self.allowed_senders.get(&sender).copied() == Some(sender_generation)
    }

    /// 授权另一个进程发送
    ///
    /// R106-1 FIX: 接受预查询的 generation 值，避免在持有 ENDPOINTS 锁时
    /// 访问 PROCESS_TABLE（防止锁序反转死锁）。
    ///
    /// MEDIUM-5 FIX: 强制执行 MAX_ALLOWED_SENDERS 限制，防止授权后无界增长。
    /// 更新现有发送者的 generation 总是允许的（不增加计数）。
    /// 所有者自动包含，限制适用于显式授权的非所有者发送者。
    fn grant_access(&mut self, pid: ProcessId, generation: u64) -> Result<(), IpcError> {
        // 所有者总是允许（已在构造时添加），不计入显式授权配额
        if pid == self.owner {
            self.allowed_senders.insert(pid, generation);
            return Ok(());
        }

        // 如果是新增授权（而非更新现有），检查是否超过限制
        // allowed_senders.len() 包含所有者，所以上限是 MAX_ALLOWED_SENDERS + 1
        if !self.allowed_senders.contains_key(&pid)
            && self.allowed_senders.len() >= MAX_ALLOWED_SENDERS + 1
        {
            return Err(IpcError::TooManySenders);
        }
        self.allowed_senders.insert(pid, generation);
        Ok(())
    }

    /// 撤销另一个进程的发送权限
    fn revoke_access(&mut self, pid: ProcessId) {
        // 所有者权限不可撤销
        if pid != self.owner {
            self.allowed_senders.remove(&pid);
        }
    }

    /// 推送消息到队列
    fn push_message(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.queue.len() >= MAX_MESSAGES_PER_ENDPOINT {
            return Err(IpcError::QueueFull);
        }
        self.queue.push_back(msg);
        Ok(())
    }
}

/// 全局端点注册表
///
/// R75-2 FIX: 按 IPC 命名空间分区，提供真正的 IPC 隔离。
/// 不同命名空间的端点互不可见、互不可访问。
#[derive(Default)]
struct EndpointRegistry {
    /// 每命名空间、每进程端点表: NamespaceId -> ProcessId -> (EndpointId -> Endpoint)
    per_ns: BTreeMap<NamespaceId, BTreeMap<ProcessId, BTreeMap<EndpointId, Endpoint>>>,
    /// 端点到所有者的索引: EndpointId -> (NamespaceId, ProcessId)
    owner_index: BTreeMap<EndpointId, (NamespaceId, ProcessId)>,
}

impl EndpointRegistry {
    /// 注册新端点
    ///
    /// R75-2 FIX: 端点注册在调用者的 IPC 命名空间内
    ///
    /// R106-1 FIX: 接受预解析的 (pid, generation) 对，所有 PROCESS_TABLE 查询
    /// 必须在获取 ENDPOINTS 锁之前完成（防止锁序反转死锁）。
    fn register_endpoint(
        &mut self,
        ns_id: NamespaceId,
        owner: ProcessId,
        owner_generation: u64,
        resolved_senders: &[(ProcessId, u64)],
    ) -> Result<EndpointId, IpcError> {
        // 检查端点数量限制
        let process_endpoints = self
            .per_ns
            .entry(ns_id)
            .or_default()
            .entry(owner)
            .or_default();
        if process_endpoints.len() >= MAX_ENDPOINTS_PER_PROCESS {
            return Err(IpcError::TooManyEndpoints);
        }

        // R105-5 FIX: Use fetch_update with checked_add to prevent wrapping to 0
        // on u64 overflow.  In practice u64 exhaustion is unreachable, but
        // correctness should not depend on probabilistic arguments.
        let endpoint_id = NEXT_ENDPOINT_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| IpcError::EndpointIdExhausted)?;
        let endpoint = Endpoint::new(owner, owner_generation, resolved_senders);

        process_endpoints.insert(endpoint_id, endpoint);
        self.owner_index.insert(endpoint_id, (ns_id, owner));

        Ok(endpoint_id)
    }

    /// 获取端点的可变引用
    ///
    /// R75-2 FIX: 只返回同命名空间内的端点
    fn endpoint_mut(
        &mut self,
        ns_id: NamespaceId,
        endpoint_id: EndpointId,
    ) -> Option<&mut Endpoint> {
        let (stored_ns, owner) = *self.owner_index.get(&endpoint_id)?;
        if stored_ns != ns_id {
            // 命名空间不匹配 - 端点对调用者不可见
            return None;
        }
        self.per_ns
            .get_mut(&ns_id)
            .and_then(|by_pid| by_pid.get_mut(&owner))
            .and_then(|table| table.get_mut(&endpoint_id))
    }

    /// 获取端点的不可变引用
    ///
    /// R75-2 FIX: 只返回同命名空间内的端点
    fn endpoint(&self, ns_id: NamespaceId, endpoint_id: EndpointId) -> Option<&Endpoint> {
        let (stored_ns, owner) = *self.owner_index.get(&endpoint_id)?;
        if stored_ns != ns_id {
            // 命名空间不匹配 - 端点对调用者不可见
            return None;
        }
        self.per_ns
            .get(&ns_id)
            .and_then(|by_pid| by_pid.get(&owner))
            .and_then(|table| table.get(&endpoint_id))
    }

    /// 删除端点
    ///
    /// R75-2 FIX: 只能删除同命名空间内的端点
    fn remove_endpoint(&mut self, ns_id: NamespaceId, endpoint_id: EndpointId) -> bool {
        if let Some((stored_ns, owner)) = self.owner_index.get(&endpoint_id).copied() {
            if stored_ns != ns_id {
                // 命名空间不匹配 - 不允许跨命名空间删除
                return false;
            }
            self.owner_index.remove(&endpoint_id);
            if let Some(table) = self
                .per_ns
                .get_mut(&ns_id)
                .and_then(|ns| ns.get_mut(&owner))
            {
                table.remove(&endpoint_id);
                return true;
            }
        }
        false
    }

    /// 清理进程的所有端点（进程退出时调用）
    ///
    /// R75-2 FIX: 只清理指定命名空间内该进程的端点
    /// R180-5 FIX: only remove endpoints whose `owner_generation` matches the
    /// reaped identity. A successor may already own `(ns, pid)` after slot
    /// recycle; its endpoints carry a different generation and must survive.
    fn remove_one_process_endpoint(
        &mut self,
        ns_id: NamespaceId,
        pid: ProcessId,
        generation: u64,
    ) -> Option<EndpointId> {
        // RF180-3 FIX: stream one bounded endpoint removal at a time.  The
        // previous repair collected the same ID set twice with infallible Vec
        // allocation in exit cleanup, reopening teardown-OOM panic exposure.
        let endpoint_id = self
            .per_ns
            .get(&ns_id)
            .and_then(|by_pid| by_pid.get(&pid))
            .and_then(|table| {
                table
                    .iter()
                    .find(|(_, endpoint)| endpoint.owner_generation == generation)
                    .map(|(id, _)| *id)
            })?;

        let mut remove_pid_bucket = false;
        if let Some(by_pid) = self.per_ns.get_mut(&ns_id) {
            if let Some(table) = by_pid.get_mut(&pid) {
                table.remove(&endpoint_id);
                remove_pid_bucket = table.is_empty();
            }
            if remove_pid_bucket {
                by_pid.remove(&pid);
            }
        }
        self.owner_index.remove(&endpoint_id);
        Some(endpoint_id)
    }
}

/// 下一个可用的端点ID
static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(1);

lazy_static::lazy_static! {
    /// 全局端点注册表
    static ref ENDPOINTS: Mutex<EndpointRegistry> = Mutex::new(EndpointRegistry::default());
}

/// 初始化IPC系统
pub fn init() {
    klog_always!("IPC system initialized (capability-based endpoints)");
}

/// 注册新端点
///
/// 当前进程成为端点的所有者，只有所有者可以接收消息。
///
/// R75-2 FIX: 端点注册在调用者的 IPC 命名空间内
///
/// # Arguments
///
/// * `allowed_senders` - 允许发送消息的进程ID列表（所有者自动包含）
///
/// # Returns
///
/// 成功返回端点ID，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `ProcessNotFound` - 白名单中的进程不存在
/// * `TooManyEndpoints` - 端点数量超过限制
/// * `TooManySenders` - 发送者白名单数量超过限制
/// * `NoMemory` - 无法为发送者白名单分配内存
pub fn register_endpoint(allowed_senders: &[ProcessId]) -> Result<EndpointId, IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let owner_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    // MEDIUM-5 FIX: 限制发送者白名单大小，防止无界分配
    if allowed_senders.len() > MAX_ALLOWED_SENDERS {
        return Err(IpcError::TooManySenders);
    }

    // R106-1 FIX: 在获取 ENDPOINTS 锁之前解析所有 sender 的 generation，
    // 避免在持有 ENDPOINTS 锁时访问 PROCESS_TABLE（防止锁序反转死锁）。
    let mut resolved_senders = Vec::new();
    resolved_senders
        .try_reserve_exact(allowed_senders.len())
        .map_err(|_| IpcError::NoMemory)?;

    for &pid in allowed_senders {
        if pid == owner {
            continue; // 所有者已在 Endpoint::new() 中自动添加
        }

        // MAX_ALLOWED_SENDERS bounds this linear scan. Reusing resolved_senders
        // avoids a second allocation and deduplicates before generation lookup.
        if resolved_senders
            .iter()
            .any(|&(resolved_pid, _)| resolved_pid == pid)
        {
            continue;
        }

        let proc_arc = process::get_process(pid).ok_or(IpcError::ProcessNotFound)?;
        let gen = proc_arc.lock().generation;
        resolved_senders.push((pid, gen));
    }

    ENDPOINTS
        .lock()
        .register_endpoint(ns_id, owner, owner_generation, &resolved_senders)
}

/// 发送消息到端点
///
/// 发送者身份自动从当前进程获取，不可伪造。
///
/// R75-2 FIX: 只能发送到同一 IPC 命名空间内的端点
///
/// # Arguments
///
/// * `endpoint_id` - 目标端点ID
/// * `data` - 消息数据
///
/// # Returns
///
/// 成功返回`Ok(())`，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在或不在当前命名空间内
/// * `AccessDenied` - 当前进程无发送权限
/// * `QueueFull` - 端点消息队列已满
/// * `MessageTooLarge` - 消息数据超过大小限制
pub fn send_message(endpoint_id: EndpointId, data: Vec<u8>) -> Result<(), IpcError> {
    // 自动获取发送者身份（不可伪造）
    let sender = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let sender_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    // 检查消息大小
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 检查发送权限（PID + generation 双重验证）
    if !endpoint.can_send(sender, sender_generation) {
        return Err(IpcError::AccessDenied);
    }

    endpoint.push_message(Message { sender, data })?;
    // G.1: Track successful IPC message sends
    increment_counter(TraceCounter::IpcMessages, 1);
    Ok(())
}

/// 接收消息
///
/// 只有端点所有者可以接收消息。
///
/// R75-2 FIX: 只能从同一 IPC 命名空间内的端点接收
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
///
/// # Returns
///
/// * `Ok(Some(msg))` - 成功接收消息
/// * `Ok(None)` - 队列为空
/// * `Err(...)` - 发生错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在或不在当前命名空间内
/// * `AccessDenied` - 当前进程不是端点所有者
pub fn receive_message(endpoint_id: EndpointId) -> Result<Option<ReceivedMessage>, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let receiver_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 只有所有者可以接收（PID + generation 双重验证）
    if endpoint.owner != receiver || endpoint.owner_generation != receiver_generation {
        return Err(IpcError::AccessDenied);
    }

    let result = endpoint.queue.pop_front().map(|msg| ReceivedMessage {
        sender: msg.sender,
        data: msg.data,
    });
    // G.1: Track successful IPC message receives
    if result.is_some() {
        increment_counter(TraceCounter::IpcMessages, 1);
    }
    Ok(result)
}

/// 授权进程发送权限
///
/// 只有端点所有者可以授权。
///
/// R75-2 FIX: 只能授权同一 IPC 命名空间内的端点
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要授权的进程ID
///
/// # Errors
///
/// * `TooManySenders` - 端点授权列表已满（更新现有授权不受限制）
pub fn grant_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let owner_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    // R106-1 FIX: 在获取 ENDPOINTS 锁之前查询目标进程的 generation，
    // 避免锁序反转死锁（ENDPOINTS → PROCESS_TABLE vs PROCESS_TABLE → ENDPOINTS）。
    let target_proc = process::get_process(pid).ok_or(IpcError::ProcessNotFound)?;
    let target_generation = target_proc.lock().generation;
    drop(target_proc); // 显式释放，确保不跨 ENDPOINTS 锁持有

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 所有者验证包含 generation
    if endpoint.owner != owner || endpoint.owner_generation != owner_generation {
        return Err(IpcError::AccessDenied);
    }

    endpoint.grant_access(pid, target_generation)
}

/// 撤销进程发送权限
///
/// 只有端点所有者可以撤销。所有者自身的权限不可撤销。
///
/// R75-2 FIX: 只能撤销同一 IPC 命名空间内端点的权限
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要撤销权限的进程ID
pub fn revoke_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let owner_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 所有者验证包含 generation
    if endpoint.owner != owner || endpoint.owner_generation != owner_generation {
        return Err(IpcError::AccessDenied);
    }

    endpoint.revoke_access(pid);
    Ok(())
}

/// 删除端点
///
/// 只有端点所有者可以删除。
///
/// R75-2 FIX: 只能删除同一 IPC 命名空间内的端点
///
/// # X-6 安全修复
///
/// 销毁端点时必须清理关联的等待队列，唤醒所有阻塞等待的进程。
/// 否则这些进程会永久阻塞，造成资源泄漏和 DoS。
///
/// **重要**：必须先移除端点注册，再清理等待队列。这确保被唤醒的线程
/// 在下一次 receive_message 时立即看到 EndpointNotFound，避免重新创建
/// 新的等待队列导致再次阻塞。
pub fn destroy_endpoint(endpoint_id: EndpointId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let owner_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 所有者验证包含 generation
    if endpoint.owner != owner || endpoint.owner_generation != owner_generation {
        return Err(IpcError::AccessDenied);
    }

    drop(registry);

    // 先移除端点注册，确保被唤醒的等待者在下一次 receive 时立即得到 EndpointNotFound
    ENDPOINTS.lock().remove_endpoint(ns_id, endpoint_id);

    // X-6 修复：清理等待队列，唤醒所有阻塞的接收者
    // 被唤醒的进程会在下次 receive_message 时得到 EndpointNotFound 错误
    cleanup_wait_queue(endpoint_id);

    Ok(())
}

/// 清理进程的所有端点（进程退出时调用）
///
/// 此函数应在进程终止时由进程管理子系统调用。
///
/// R75-2 FIX: 接受 IPC 命名空间 ID 用于按命名空间清理端点
/// R180-5 FIX: `generation` filters which endpoints are reaped so a recycled
/// PID's successor cannot lose freshly-created endpoints.
///
/// # X-6 安全修复
///
/// 进程退出时必须清理其所有端点的等待队列，唤醒所有阻塞等待的进程。
/// 否则其他进程会永久阻塞在已销毁的端点上。
///
/// **重要**：必须先移除端点注册，再清理等待队列。这确保被唤醒的线程
/// 在下一次 receive_message 时立即看到 EndpointNotFound，避免重新创建
/// 新的等待队列导致再次阻塞。
pub fn cleanup_process_endpoints(ns_id: NamespaceId, pid: ProcessId, generation: u64) {
    // X-6 + R180-5 + RF180-3: remove registry state before each wake/close,
    // without any heap snapshot.  Successor-generation endpoints remain.
    loop {
        let endpoint_id = ENDPOINTS
            .lock()
            .remove_one_process_endpoint(ns_id, pid, generation);
        match endpoint_id {
            Some(id) => cleanup_wait_queue(id),
            None => break,
        }
    }
}

/// 获取端点队列中的消息数量
///
/// R75-2 FIX: 只能查询同一 IPC 命名空间内的端点
pub fn get_queue_length(endpoint_id: EndpointId) -> Result<usize, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let receiver_generation = process::current_generation().ok_or(IpcError::ProcessNotFound)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // R106-1 FIX: 只有所有者可以查看队列状态（PID + generation 双重验证）
    if endpoint.owner != receiver || endpoint.owner_generation != receiver_generation {
        return Err(IpcError::AccessDenied);
    }

    Ok(endpoint.queue.len())
}

// ============================================================================
// 阻塞IPC扩展
// ============================================================================

use crate::sync::WaitQueue;

const ENDPOINT_WAIT_QUEUE_ARC_MIN_CHARGE: usize =
    core::mem::size_of::<WaitQueue>() + 4 * core::mem::size_of::<usize>();
const ENDPOINT_WAIT_QUEUE_ARC_SLOTS: usize =
    HeapClass::BlockingIo.limit_bytes() / ENDPOINT_WAIT_QUEUE_ARC_MIN_CHARGE + 1;
const _: () = assert!(ENDPOINT_WAIT_QUEUE_ARC_SLOTS <= u16::MAX as usize);

struct EndpointWaitQueueArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static ENDPOINT_WAIT_QUEUE_ARC_CHARGES: Mutex<
    [Option<EndpointWaitQueueArcChargeSlot>; ENDPOINT_WAIT_QUEUE_ARC_SLOTS],
> = Mutex::new([const { None }; ENDPOINT_WAIT_QUEUE_ARC_SLOTS]);
static NEXT_ENDPOINT_WAIT_QUEUE_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
struct EndpointWaitQueueArcAllocator {
    slot: u16,
    generation: u64,
}

impl EndpointWaitQueueArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_ENDPOINT_WAIT_QUEUE_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = ENDPOINT_WAIT_QUEUE_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(EndpointWaitQueueArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge
                        .take()
                        .expect("endpoint wait-queue Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("endpoint wait-queue Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = ENDPOINT_WAIT_QUEUE_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-42 endpoint wait-queue Arc slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-42 stale endpoint wait-queue Arc generation"),
            None => panic!("RF180-42 endpoint wait-queue Arc charge released twice"),
        }
        slot.take()
            .expect("validated endpoint wait-queue Arc charge disappeared")
            .charge
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }

    #[cfg(test)]
    fn charge_is_live_for_test(self) -> bool {
        ENDPOINT_WAIT_QUEUE_ARC_CHARGES
            .lock()
            .get(self.slot as usize)
            .and_then(Option::as_ref)
            .is_some_and(|entry| entry.generation == self.generation)
    }
}

unsafe impl Allocator for EndpointWaitQueueArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = ENDPOINT_WAIT_QUEUE_ARC_CHARGES.lock();
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
                let mut slots = ENDPOINT_WAIT_QUEUE_ARC_CHARGES.lock();
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

type EndpointWaitQueueArc = Arc<WaitQueue, EndpointWaitQueueArcAllocator>;
type EndpointWaitQueueEntry = (EndpointId, EndpointWaitQueueArc);

struct EndpointWaitQueueRegistry {
    entries: AdmittedDeque<EndpointWaitQueueEntry>,
}

impl EndpointWaitQueueRegistry {
    const fn new() -> Self {
        Self {
            entries: AdmittedDeque::new(HeapClass::BlockingIo),
        }
    }

    fn get(&self, endpoint_id: EndpointId) -> Option<&EndpointWaitQueueArc> {
        self.entries
            .iter()
            .find(|(queued_id, _)| *queued_id == endpoint_id)
            .map(|(_, queue)| queue)
    }

    fn max_id(&self) -> Option<EndpointId> {
        self.entries.iter().map(|(id, _)| *id).max()
    }

    fn next_after(
        &self,
        after: Option<EndpointId>,
        upper: EndpointId,
    ) -> Option<(EndpointId, EndpointWaitQueueArc)> {
        self.entries
            .iter()
            .filter(|(id, _)| after.is_none_or(|cursor| *id > cursor) && *id <= upper)
            .min_by_key(|(id, _)| *id)
            .map(|(id, queue)| (*id, queue.clone()))
    }

    fn remove_retaining(&mut self, endpoint_id: EndpointId) -> Option<EndpointWaitQueueEntry> {
        let pos = self
            .entries
            .iter()
            .position(|(queued_id, _)| *queued_id == endpoint_id)?;
        self.entries.remove_retaining_capacity(pos)
    }
}

lazy_static::lazy_static! {
    /// 每端点等待队列：用于阻塞接收
    ///
    /// # X-6 安全增强
    ///
    /// 使用 Arc<WaitQueue> 引用计数，避免在锁外访问时发生 use-after-free。
    /// 当端点销毁时，通过 close() 关闭队列，唤醒所有等待者。
    static ref ENDPOINT_WAIT_QUEUES: spin::Mutex<EndpointWaitQueueRegistry> =
        spin::Mutex::new(EndpointWaitQueueRegistry::new());
}

fn prepare_endpoint_wait_queue_registry_growth(
    len: usize,
    capacity: usize,
) -> Result<Option<PreparedAdmittedDequeCapacity<EndpointWaitQueueEntry>>, AdmittedAllocError> {
    let required = len.checked_add(1).ok_or(AdmittedAllocError::Admission(
        mm::HeapAdmissionError::ArithmeticOverflow,
    ))?;
    if required <= capacity {
        return Ok(None);
    }
    let preferred = capacity
        .max(4)
        .checked_mul(2)
        .map(|doubled| doubled.max(required))
        .ok_or(AdmittedAllocError::Admission(
            mm::HeapAdmissionError::ArithmeticOverflow,
        ))?;
    match PreparedAdmittedDequeCapacity::try_new(HeapClass::BlockingIo, preferred) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) if preferred != required => {
            PreparedAdmittedDequeCapacity::try_new(HeapClass::BlockingIo, required).map(Some)
        }
        Err(error) => Err(error),
    }
}

fn try_new_endpoint_wait_queue_arc() -> Result<EndpointWaitQueueArc, IpcError> {
    let bytes = arc_charge_bytes::<WaitQueue>().map_err(|_| IpcError::NoMemory)?;
    let reservation =
        try_reserve_heap(HeapClass::BlockingIo, bytes).map_err(|_| IpcError::NoMemory)?;
    let charge = reservation.commit().map_err(|_| IpcError::NoMemory)?;
    let allocator = EndpointWaitQueueArcAllocator::try_install(charge).map_err(|charge| {
        drop(charge);
        IpcError::NoMemory
    })?;
    match Arc::try_new_in(WaitQueue::new(HeapClass::BlockingIo), allocator) {
        Ok(queue) => Ok(queue),
        Err(_) => {
            allocator.cancel_failed_allocation();
            Err(IpcError::NoMemory)
        }
    }
}

enum EndpointWaitQueuePublish {
    Ready(EndpointWaitQueueArc),
    RetryCapacity,
}

fn publish_endpoint_wait_queue_candidate(
    registry: &Mutex<EndpointWaitQueueRegistry>,
    endpoint_id: EndpointId,
    candidate: &mut Option<EndpointWaitQueueArc>,
    prepared: &mut Option<PreparedAdmittedDequeCapacity<EndpointWaitQueueEntry>>,
    retired: &mut Option<RetiredAdmittedDequeCapacity<EndpointWaitQueueEntry>>,
) -> EndpointWaitQueuePublish {
    let mut queues = registry.lock();
    if let Some(existing) = queues.get(endpoint_id) {
        return EndpointWaitQueuePublish::Ready(existing.clone());
    }

    if queues.entries.len() == queues.entries.capacity() {
        let Some(backing) = prepared.take() else {
            return EndpointWaitQueuePublish::RetryCapacity;
        };
        if backing.class() != queues.entries.class() || backing.capacity() <= queues.entries.len() {
            *prepared = Some(backing);
            return EndpointWaitQueuePublish::RetryCapacity;
        }
        debug_assert!(retired.is_none());
        *retired = Some(
            queues
                .entries
                .install_prepared_deferred(backing)
                .expect("RF180-42 endpoint registry prepared-capacity invariant"),
        );
    }

    let queue = candidate
        .take()
        .expect("endpoint wait-queue candidate consumed once");
    let result = queue.clone();
    queues
        .entries
        .push_back_reserved((endpoint_id, queue))
        .unwrap_or_else(|_| panic!("RF180-42 endpoint registry capacity vanished under lock"));
    EndpointWaitQueuePublish::Ready(result)
}

fn detach_endpoint_wait_queue_from(
    registry: &Mutex<EndpointWaitQueueRegistry>,
    endpoint_id: EndpointId,
) -> Option<EndpointWaitQueueArc> {
    let (removed, retired) = {
        let mut queues = registry.lock();
        let removed = queues.remove_retaining(endpoint_id);
        let retired = queues.entries.take_empty_capacity();
        (removed, retired)
    };
    // The obsolete registry backing and any removed Arc are destroyed only
    // after the registry lock is released.
    drop(retired);
    removed.map(|(_, queue)| queue)
}

/// 获取或创建端点的等待队列
///
/// # X-6 安全增强
///
/// 返回 Arc<WaitQueue> 而非裸指针，确保引用计数正确管理内存。
fn get_or_create_wait_queue(endpoint_id: EndpointId) -> Result<EndpointWaitQueueArc, IpcError> {
    if let Some(existing) = ENDPOINT_WAIT_QUEUES.lock().get(endpoint_id).cloned() {
        return Ok(existing);
    }

    let mut candidate = Some(try_new_endpoint_wait_queue_arc()?);
    loop {
        let (len, capacity) = {
            let queues = ENDPOINT_WAIT_QUEUES.lock();
            (queues.entries.len(), queues.entries.capacity())
        };
        let mut prepared = prepare_endpoint_wait_queue_registry_growth(len, capacity)
            .map_err(|_| IpcError::NoMemory)?;
        let mut retired = None;
        let outcome = publish_endpoint_wait_queue_candidate(
            &ENDPOINT_WAIT_QUEUES,
            endpoint_id,
            &mut candidate,
            &mut prepared,
            &mut retired,
        );
        drop(retired);
        drop(prepared);
        match outcome {
            EndpointWaitQueuePublish::Ready(queue) => return Ok(queue),
            EndpointWaitQueuePublish::RetryCapacity => continue,
        }
    }
}

/// 发送消息并唤醒等待的接收者
///
/// 与send_message相同，但会唤醒在此端点上阻塞等待的进程。
pub fn send_message_notify(endpoint_id: EndpointId, data: Vec<u8>) -> Result<(), IpcError> {
    // 发送消息
    send_message(endpoint_id, data)?;

    // X-6: 克隆 Arc 后再释放锁，避免在持有锁时调用 wake
    let wq = {
        let queues = ENDPOINT_WAIT_QUEUES.lock();
        queues.get(endpoint_id).cloned()
    };

    if let Some(wq) = wq {
        wq.wake_one();
    }

    Ok(())
}

/// 阻塞接收消息
///
/// 如果队列为空，当前进程会阻塞直到有消息到达。
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
///
/// # Returns
///
/// * `Ok(msg)` - 成功接收消息
/// * `Err(...)` - 发生错误
///
/// # X-6 安全增强
///
/// 使用 Arc<WaitQueue> 避免 use-after-free，检查 is_closed() 避免永久阻塞。
/// 如果端点在等待期间被销毁，返回 EndpointNotFound 错误。
pub fn receive_message_blocking(endpoint_id: EndpointId) -> Result<ReceivedMessage, IpcError> {
    loop {
        // R156-4 FIX: Use prepare_to_wait/cancel_wait/finish_wait to
        // close the lost-wakeup window. Previously, a sender could call
        // wake_one() between receive_message() returning None and the
        // internal prepare_to_wait inside wq.wait() — losing the signal.
        //
        // Now: register in WaitQueue FIRST, then check for messages.
        // If a message arrived between registration and check, cancel_wait.
        let wq = get_or_create_wait_queue(endpoint_id)?;

        if wq.is_closed() {
            return Err(IpcError::EndpointNotFound);
        }

        if let Err(prepare_failure) = wq.prepare_to_wait() {
            if wq.is_closed() {
                return Err(IpcError::EndpointNotFound);
            }
            // M0-5 1b-1b: prepare_to_wait ALSO bails when a pending kill or a deliverable
            // HANDLER signal raced in (the M0-5 1b should_abort_pending_block re-check).
            // BOTH the first-iteration entry AND a post-block re-loop (after finish_wait
            // returns from a signal-wake) funnel through here. Ordering (Codex impl-diff):
            //   1. kill-FIRST — a pending kill ABORTS the recv (the task is terminating);
            //      do NOT deliver a queued message to a dying task.
            //   2. message-first (POSIX) — for a non-kill wake (deliverable signal OR a
            //      spurious wake), deliver any QUEUED message rather than interrupting; a
            //      signal interrupts a blocking recv only if it would otherwise block.
            //      (The pre-1b-1b bail dropped such a message; this re-check closes that.)
            //   3. signal with no message => precise EINTR (replaces the imprecise ESRCH).
            //   4. otherwise the genuine no-current-process bail.
            let cur = process::current_pid();
            if let Some(pid) = cur {
                if process::wait_should_abort(pid) {
                    return Err(IpcError::Interrupted);
                }
            }
            match receive_message(endpoint_id) {
                Ok(Some(msg)) => return Ok(msg),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
            if let Some(pid) = cur {
                if kernel_core::signal::has_deliverable_signal(pid) {
                    return Err(IpcError::Interrupted);
                }
            }
            return Err(match prepare_failure {
                crate::sync::WaitOutcome::ResourceExhausted => IpcError::NoMemory,
                crate::sync::WaitOutcome::Closed => IpcError::EndpointNotFound,
                crate::sync::WaitOutcome::Interrupted => IpcError::Interrupted,
                crate::sync::WaitOutcome::NoProcess => IpcError::NoCurrentProcess,
                crate::sync::WaitOutcome::Woken | crate::sync::WaitOutcome::TimedOut => {
                    IpcError::NoCurrentProcess
                }
            });
        }

        // Re-check for messages AFTER registering in the WaitQueue.
        // If a sender enqueued + woke between our prepare_to_wait and
        // this check, we'll find the message and cancel_wait.
        match receive_message(endpoint_id) {
            Ok(Some(msg)) => {
                wq.cancel_wait();
                return Ok(msg);
            }
            Ok(None) => {
                wq.finish_wait();
            }
            Err(e) => {
                wq.cancel_wait();
                // R160-5 FIX: Remove stale WaitQueue entry when endpoint
                // doesn't exist. Without this, repeated blocking receives on
                // non-existent endpoints leak WaitQueue entries in the global
                // BTreeMap, causing unbounded memory growth.
                if matches!(e, IpcError::EndpointNotFound) {
                    drop(detach_endpoint_wait_queue_from(
                        &ENDPOINT_WAIT_QUEUES,
                        endpoint_id,
                    ));
                }
                return Err(e);
            }
        }
    }
}

/// 带超时的接收消息（简化版：仅支持重试次数）
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `max_retries` - 最大重试次数（每次重试会yield）
///
/// # Returns
///
/// * `Ok(Some(msg))` - 成功接收消息
/// * `Ok(None)` - 超时（达到最大重试次数）
/// * `Err(...)` - 发生错误
pub fn receive_message_with_retries(
    endpoint_id: EndpointId,
    max_retries: usize,
) -> Result<Option<ReceivedMessage>, IpcError> {
    for _ in 0..max_retries {
        match receive_message(endpoint_id)? {
            Some(msg) => return Ok(Some(msg)),
            None => {
                // 让出CPU
                kernel_core::force_reschedule();
            }
        }
    }
    Ok(None)
}

/// 清理端点的等待队列（端点销毁时调用）
///
/// # X-6 安全增强
///
/// 使用 close() 方法而非仅 wake_all()，确保：
/// 1. 设置 closed 标志，阻止新的等待者加入
/// 2. 唤醒所有现有等待者
/// 3. 等待者被唤醒后会检查 is_closed() 并返回错误
/// R156-6 + R180-5 FIX: Remove stale WaitQueue entries for a reaped identity.
///
/// `generation` is the reaped process's PCB generation captured under the PCB
/// lock before the table slot was cleared. Entries stamped with a process
/// generation (PROCESS_GEN_TAG) are removed only on exact match; untagged
/// entries for `pid` are removed only when no live successor owns the PID
/// (or the live PCB generation still matches).
pub fn cleanup_waitqueues_for_pid(pid: ProcessId, generation: u64) {
    // RF180-3 FIX: bound the allocation-free walk to queues that existed at
    // entry. Endpoint IDs are monotonic and never reused, so a cursor through
    // this upper bound cannot miss an old queue or loop on concurrent creation.
    let upper = {
        let wqs = ENDPOINT_WAIT_QUEUES.lock();
        wqs.max_id()
    };
    let Some(upper) = upper else {
        return;
    };

    let mut after = None;
    loop {
        let next = {
            let wqs = ENDPOINT_WAIT_QUEUES.lock();
            wqs.next_after(after, upper)
        };
        let Some((id, queue)) = next else {
            break;
        };
        queue.cleanup_for_identity(pid, generation);
        after = Some(id);
    }
}

fn cleanup_wait_queue(endpoint_id: EndpointId) {
    // X-6: 先取出 Arc，再释放锁后调用 close()
    // 这避免了在持有锁时调用可能导致调度的操作
    let wq = detach_endpoint_wait_queue_from(&ENDPOINT_WAIT_QUEUES, endpoint_id);

    if let Some(wq) = wq {
        // 关闭队列并唤醒所有等待者
        // 被唤醒的进程会检查 is_closed() 并返回 EndpointNotFound
        wq.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_wait_queue_arc_charge_releases_after_final_weak() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::BlockingIo);

        let queue = try_new_endpoint_wait_queue_arc().expect("endpoint wait-queue Arc");
        let allocator = *Arc::allocator(&queue);
        let weak = Arc::downgrade(&queue);
        drop(queue);
        assert!(
            allocator.charge_is_live_for_test(),
            "payload drop must retain the endpoint wait-queue Arc charge"
        );

        drop(weak);
        assert!(!allocator.charge_is_live_for_test());
        assert_eq!(mm::heap_class_snapshot(HeapClass::BlockingIo), before);
    }

    #[test]
    fn endpoint_wait_queue_publish_race_rolls_back_candidate_and_backing() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::BlockingIo);
        let registry = Mutex::new(EndpointWaitQueueRegistry::new());
        let endpoint_id = 0x1804_0042;

        let mut winner = Some(try_new_endpoint_wait_queue_arc().expect("winner Arc"));
        let mut winner_backing =
            prepare_endpoint_wait_queue_registry_growth(0, 0).expect("winner backing");
        let mut winner_retired = None;
        let published = match publish_endpoint_wait_queue_candidate(
            &registry,
            endpoint_id,
            &mut winner,
            &mut winner_backing,
            &mut winner_retired,
        ) {
            EndpointWaitQueuePublish::Ready(queue) => queue,
            EndpointWaitQueuePublish::RetryCapacity => {
                panic!("winner publish unexpectedly retried")
            }
        };
        drop(winner_retired);
        drop(winner_backing);
        drop(published);
        let winner_only = mm::heap_class_snapshot(HeapClass::BlockingIo);

        // Model a publisher that prepared from a stale full snapshot while the
        // winner raced in. Neither its Arc nor its detached oversized backing
        // may become reachable or remain charged after the locked recheck.
        let mut loser = Some(try_new_endpoint_wait_queue_arc().expect("loser Arc"));
        let replacement_target = registry
            .lock()
            .entries
            .capacity()
            .checked_add(8)
            .expect("test registry capacity");
        let mut loser_backing = Some(
            PreparedAdmittedDequeCapacity::try_new(HeapClass::BlockingIo, replacement_target)
                .expect("loser detached backing"),
        );
        let mut loser_retired = None;
        let observed = match publish_endpoint_wait_queue_candidate(
            &registry,
            endpoint_id,
            &mut loser,
            &mut loser_backing,
            &mut loser_retired,
        ) {
            EndpointWaitQueuePublish::Ready(queue) => queue,
            EndpointWaitQueuePublish::RetryCapacity => panic!("existing winner must not retry"),
        };
        assert!(
            loser.is_some(),
            "losing Arc candidate was incorrectly published"
        );
        assert!(
            loser_backing.is_some(),
            "losing detached backing was incorrectly installed"
        );
        assert!(loser_retired.is_none());
        drop(observed);
        drop(loser);
        drop(loser_backing);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::BlockingIo),
            winner_only,
            "losing publication leaked admission or registry state"
        );

        let removed =
            detach_endpoint_wait_queue_from(&registry, endpoint_id).expect("winner registry entry");
        assert_eq!(registry.lock().entries.capacity(), 0);
        drop(removed);
        assert_eq!(mm::heap_class_snapshot(HeapClass::BlockingIo), before);
    }
}
