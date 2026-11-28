//! Syscall family module: `futex` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// Futex 系统调用
// ============================================================================

/// GAP-5 futex parity: one decoded futex request, handed whole to the IPC
/// futex implementation through [`FutexCallback`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexRequest {
    /// FUTEX_WAIT / FUTEX_WAIT_BITSET: sleep while `*uaddr == expected`.
    /// `current` is the word read at syscall entry (the fast mismatch path);
    /// the IPC side reads it again under the bucket lock before queueing.
    /// `bitset` is FUTEX_BITSET_MATCH_ANY for plain FUTEX_WAIT, never 0.
    Wait {
        expected: u32,
        current: u32,
        timeout_ns: Option<u64>,
        bitset: u32,
    },
    /// FUTEX_WAKE / FUTEX_WAKE_BITSET: wake up to `count` waiters whose
    /// bitset intersects `bitset` (MATCH_ANY for plain FUTEX_WAKE).
    Wake { count: u32, bitset: u32 },
    /// FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake up to `nr_wake` waiters of
    /// `uaddr`, then move up to `nr_requeue` more onto `uaddr2`, where they
    /// keep sleeping. `compare` carries CMP_REQUEUE's `val3`.
    Requeue {
        nr_wake: u32,
        nr_requeue: u32,
        uaddr2: usize,
        compare: Option<u32>,
    },
    /// FUTEX_WAKE_OP: apply `op` atomically to `*uaddr2`, wake up to
    /// `nr_wake` waiters of `uaddr`, and, when the old value satisfies the
    /// comparison, up to `nr_wake2` waiters of `uaddr2`.
    WakeOp {
        nr_wake: u32,
        nr_wake2: u32,
        uaddr2: usize,
        op: FutexWakeOp,
    },
    /// FUTEX_LOCK_PI / FUTEX_LOCK_PI2 (`trylock` false) and
    /// FUTEX_TRYLOCK_PI (`trylock` true) under the Linux PI user-word
    /// protocol. `timeout_ns` is the time left until the caller's absolute
    /// deadline (FUTEX_TRYLOCK_PI has none).
    LockPi {
        timeout_ns: Option<u64>,
        trylock: bool,
    },
    /// FUTEX_UNLOCK_PI.
    UnlockPi,
    /// FUTEX_WAIT_REQUEUE_PI: wait on the non-PI `uaddr` while it holds
    /// `expected` until FUTEX_CMP_REQUEUE_PI hands over or requeues onto the
    /// PI futex `uaddr2`. `current` is the word read at syscall entry;
    /// `timeout_ns` is the time left until the absolute deadline.
    WaitRequeuePi {
        expected: u32,
        current: u32,
        timeout_ns: Option<u64>,
        uaddr2: usize,
    },
    /// FUTEX_CMP_REQUEUE_PI (one waiter woken as the owner at most): with
    /// `*uaddr == expected`, move up to `nr_requeue` FUTEX_WAIT_REQUEUE_PI
    /// waiters onto the PI futex `uaddr2`.
    CmpRequeuePi {
        nr_requeue: u32,
        uaddr2: usize,
        expected: u32,
    },
}

/// The arithmetic half of a FUTEX_WAKE_OP word: `*uaddr2 = old OP oparg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexWakeOpKind {
    Set,
    Add,
    Or,
    AndNot,
    Xor,
}

/// The comparison half of a FUTEX_WAKE_OP word: `old CMP cmparg`, signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexWakeOpCmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A decoded FUTEX_WAKE_OP operation word, Linux `FUTEX_OP(op, oparg, cmp,
/// cmparg)`: bits 28-30 select the operation, bit 31 is
/// FUTEX_OP_OPARG_SHIFT, bits 24-27 select the comparison, and bits 12-23
/// (`oparg`) and 0-11 (`cmparg`) are 12-bit two's-complement operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWakeOp {
    kind: FutexWakeOpKind,
    /// The operand after FUTEX_OP_OPARG_SHIFT has been applied.
    oparg: u32,
    cmp: FutexWakeOpCmp,
    cmparg: i32,
}

/// Sign-extend a 12-bit two's-complement field.
pub(super) const fn sign_extend_12(field: u32) -> i32 {
    ((field << 20) as i32) >> 20
}

impl FutexWakeOp {
    /// Decode an operation word. An unknown operation or comparison is
    /// `ENOSYS`, as on Linux; unlike Linux, an unknown comparison is refused
    /// before the word is modified (Linux applies the operation first). An
    /// out-of-range shift is masked to 0..=31, as Linux does.
    pub fn decode(encoded: u32) -> Result<Self, SyscallError> {
        const FUTEX_OP_OPARG_SHIFT: u32 = 8;
        let kind = match (encoded >> 28) & 0x7 {
            0 => FutexWakeOpKind::Set,
            1 => FutexWakeOpKind::Add,
            2 => FutexWakeOpKind::Or,
            3 => FutexWakeOpKind::AndNot,
            4 => FutexWakeOpKind::Xor,
            _ => return Err(SyscallError::ENOSYS),
        };
        let cmp = match (encoded >> 24) & 0xf {
            0 => FutexWakeOpCmp::Eq,
            1 => FutexWakeOpCmp::Ne,
            2 => FutexWakeOpCmp::Lt,
            3 => FutexWakeOpCmp::Le,
            4 => FutexWakeOpCmp::Gt,
            5 => FutexWakeOpCmp::Ge,
            _ => return Err(SyscallError::ENOSYS),
        };
        let oparg = sign_extend_12((encoded >> 12) & 0xfff);
        let cmparg = sign_extend_12(encoded & 0xfff);
        let oparg = if (encoded >> 28) & FUTEX_OP_OPARG_SHIFT != 0 {
            1u32 << ((oparg as u32) & 31)
        } else {
            oparg as u32
        };
        Ok(Self {
            kind,
            oparg,
            cmp,
            cmparg,
        })
    }

    /// The new value of the word given its old value (two's-complement
    /// wrapping, as the Linux `int` arithmetic on x86).
    pub fn apply(self, old: u32) -> u32 {
        match self.kind {
            FutexWakeOpKind::Set => self.oparg,
            FutexWakeOpKind::Add => old.wrapping_add(self.oparg),
            FutexWakeOpKind::Or => old | self.oparg,
            FutexWakeOpKind::AndNot => old & !self.oparg,
            FutexWakeOpKind::Xor => old ^ self.oparg,
        }
    }

    /// Whether the old value selects the second wake (signed comparison).
    pub fn compare(self, old: u32) -> bool {
        let old = old as i32;
        match self.cmp {
            FutexWakeOpCmp::Eq => old == self.cmparg,
            FutexWakeOpCmp::Ne => old != self.cmparg,
            FutexWakeOpCmp::Lt => old < self.cmparg,
            FutexWakeOpCmp::Le => old <= self.cmparg,
            FutexWakeOpCmp::Gt => old > self.cmparg,
            FutexWakeOpCmp::Ge => old >= self.cmparg,
        }
    }
}

/// GAP-5 slice 4: a decoded Linux futex request (op word level).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinuxFutexOp {
    /// FUTEX_WAIT (bitset MATCH_ANY) or FUTEX_WAIT_BITSET; `timeout` is
    /// `None` for a NULL timeout pointer.
    Wait {
        timeout: Option<FutexTimeoutKind>,
        bitset: u32,
    },
    /// FUTEX_WAKE (bitset MATCH_ANY) or FUTEX_WAKE_BITSET.
    Wake {
        bitset: u32,
    },
    /// FUTEX_REQUEUE, or FUTEX_CMP_REQUEUE when `compare` is set.
    Requeue {
        nr_requeue: u32,
        compare: bool,
    },
    /// FUTEX_WAKE_OP; the second wake count travels in the timeout slot.
    WakeOp {
        nr_wake2: u32,
        op: FutexWakeOp,
    },
    /// FUTEX_LOCK_PI / FUTEX_LOCK_PI2 (absolute timeout, `None` for NULL).
    LockPi {
        timeout: Option<FutexTimeoutKind>,
    },
    TryLockPi,
    UnlockPi,
    /// FUTEX_WAIT_REQUEUE_PI (absolute timeout, `None` for NULL).
    WaitRequeuePi {
        timeout: Option<FutexTimeoutKind>,
    },
    /// FUTEX_CMP_REQUEUE_PI; the requeue count travels in the timeout slot.
    CmpRequeuePi {
        nr_requeue: u32,
    },
}

/// FUTEX_WAIT takes a relative timeout; FUTEX_WAIT_BITSET, the PI locks and
/// FUTEX_WAIT_REQUEUE_PI an absolute one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FutexTimeoutKind {
    Relative,
    Absolute,
}

pub(super) const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;

/// Decode a Linux futex `op` word and its operation-specific arguments.
///
/// Futexes are private to the address space (the IPC side keys them by the
/// task's `MmState`), so FUTEX_PRIVATE_FLAG changes nothing. As on Linux,
/// FUTEX_CLOCK_REALTIME is accepted with FUTEX_WAIT_BITSET,
/// FUTEX_WAIT_REQUEUE_PI and FUTEX_LOCK_PI2 (`ENOSYS` otherwise, including
/// FUTEX_LOCK_PI, whose deadline is always CLOCK_REALTIME); both clocks read
/// the millisecond tick that `sys_clock_gettime` reports. Bitset operations
/// take any non-zero mask; an empty mask could never match and is `EINVAL`.
/// GAP-5 PI parity: the PI operations follow the Linux user-word protocol.
/// FUTEX_CMP_REQUEUE_PI requires `nr_wake == 1` and non-negative counts
/// (`EINVAL`). Only FUTEX_FD (2) and unknown commands are `ENOSYS`.
pub(super) fn decode_linux_futex_op(
    op: i32,
    val: u32,
    timeout_arg: usize,
    val3: u32,
) -> Result<LinuxFutexOp, SyscallError> {
    const LINUX_FUTEX_WAIT: i32 = 0;
    const LINUX_FUTEX_WAKE: i32 = 1;
    const LINUX_FUTEX_REQUEUE: i32 = 3;
    const LINUX_FUTEX_CMP_REQUEUE: i32 = 4;
    const LINUX_FUTEX_WAKE_OP: i32 = 5;
    const LINUX_FUTEX_LOCK_PI: i32 = 6;
    const LINUX_FUTEX_UNLOCK_PI: i32 = 7;
    const LINUX_FUTEX_TRYLOCK_PI: i32 = 8;
    const LINUX_FUTEX_WAIT_BITSET: i32 = 9;
    const LINUX_FUTEX_WAKE_BITSET: i32 = 10;
    const LINUX_FUTEX_WAIT_REQUEUE_PI: i32 = 11;
    const LINUX_FUTEX_CMP_REQUEUE_PI: i32 = 12;
    const LINUX_FUTEX_LOCK_PI2: i32 = 13;
    const FUTEX_PRIVATE_FLAG: i32 = 128;
    const FUTEX_CLOCK_REALTIME: i32 = 256;

    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if op & FUTEX_CLOCK_REALTIME != 0
        && !matches!(
            cmd,
            LINUX_FUTEX_WAIT_BITSET | LINUX_FUTEX_WAIT_REQUEUE_PI | LINUX_FUTEX_LOCK_PI2
        )
    {
        return Err(SyscallError::ENOSYS);
    }
    let timeout = |kind| (timeout_arg != 0).then_some(kind);
    let bitset = || match val3 {
        0 => Err(SyscallError::EINVAL),
        mask => Ok(mask),
    };
    match cmd {
        LINUX_FUTEX_WAIT => Ok(LinuxFutexOp::Wait {
            timeout: timeout(FutexTimeoutKind::Relative),
            bitset: FUTEX_BITSET_MATCH_ANY,
        }),
        LINUX_FUTEX_WAKE => Ok(LinuxFutexOp::Wake {
            bitset: FUTEX_BITSET_MATCH_ANY,
        }),
        LINUX_FUTEX_REQUEUE | LINUX_FUTEX_CMP_REQUEUE => {
            // Linux reads both counts as ints; the requeue count travels in
            // the low 32 bits of the timeout argument.
            let nr_requeue = timeout_arg as u32;
            if (val as i32) < 0 || (nr_requeue as i32) < 0 {
                return Err(SyscallError::EINVAL);
            }
            Ok(LinuxFutexOp::Requeue {
                nr_requeue,
                compare: cmd == LINUX_FUTEX_CMP_REQUEUE,
            })
        }
        // Linux validates neither wake count of FUTEX_WAKE_OP.
        LINUX_FUTEX_WAKE_OP => Ok(LinuxFutexOp::WakeOp {
            nr_wake2: timeout_arg as u32,
            op: FutexWakeOp::decode(val3)?,
        }),
        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_LOCK_PI2 => Ok(LinuxFutexOp::LockPi {
            timeout: timeout(FutexTimeoutKind::Absolute),
        }),
        LINUX_FUTEX_TRYLOCK_PI => Ok(LinuxFutexOp::TryLockPi),
        LINUX_FUTEX_UNLOCK_PI => Ok(LinuxFutexOp::UnlockPi),
        LINUX_FUTEX_WAIT_REQUEUE_PI => Ok(LinuxFutexOp::WaitRequeuePi {
            timeout: timeout(FutexTimeoutKind::Absolute),
        }),
        LINUX_FUTEX_CMP_REQUEUE_PI => {
            // As FUTEX_CMP_REQUEUE, and Linux wakes exactly one waiter here.
            let nr_requeue = timeout_arg as u32;
            if (val as i32) < 0 || (nr_requeue as i32) < 0 || val != 1 {
                return Err(SyscallError::EINVAL);
            }
            Ok(LinuxFutexOp::CmpRequeuePi { nr_requeue })
        }
        LINUX_FUTEX_WAIT_BITSET => Ok(LinuxFutexOp::Wait {
            timeout: timeout(FutexTimeoutKind::Absolute),
            bitset: bitset()?,
        }),
        LINUX_FUTEX_WAKE_BITSET => Ok(LinuxFutexOp::Wake { bitset: bitset()? }),
        _ => Err(SyscallError::ENOSYS),
    }
}

/// sys_futex - 快速用户空间互斥锁操作
///
/// 实现 Linux futex(2) 的一个子集，用于用户空间高效同步。
///
/// # Arguments
///
/// * `uaddr` - 用户空间 futex 地址（指向 u32）
/// * `op` - Linux 操作码：0=FUTEX_WAIT, 1=FUTEX_WAKE, 3=FUTEX_REQUEUE,
///   4=FUTEX_CMP_REQUEUE, 5=FUTEX_WAKE_OP, 6=FUTEX_LOCK_PI,
///   7=FUTEX_UNLOCK_PI, 8=FUTEX_TRYLOCK_PI, 9=FUTEX_WAIT_BITSET,
///   10=FUTEX_WAKE_BITSET, 11=FUTEX_WAIT_REQUEUE_PI, 12=FUTEX_CMP_REQUEUE_PI,
///   13=FUTEX_LOCK_PI2（见 `decode_linux_futex_op`）
/// * `val` - WAIT: 期望值；WAKE/REQUEUE/WAKE_OP: 最大唤醒数量
/// * `timeout_ptr` - FUTEX_WAIT: 相对超时 timespec；FUTEX_WAIT_BITSET、
///   LOCK_PI、LOCK_PI2、WAIT_REQUEUE_PI: 绝对超时 timespec（均可为 NULL）；
///   REQUEUE/CMP_REQUEUE_PI: 最大重排数量；WAKE_OP: 第二个唤醒数量
/// * `uaddr2` - REQUEUE 的目标地址；WAKE_OP 原子修改的字；requeue-PI 的 PI 字
/// * `val3` - CMP_REQUEUE(_PI): 期望值；BITSET 操作: 位掩码；WAKE_OP: 操作字
///
/// # Returns
///
/// * FUTEX_WAIT/FUTEX_WAIT_BITSET: 被唤醒返回 0，值不匹配返回 EAGAIN，超时返回 ETIMEDOUT
/// * FUTEX_WAKE/FUTEX_WAKE_BITSET: 返回实际唤醒的进程数量
/// * FUTEX_REQUEUE/FUTEX_CMP_REQUEUE(_PI): 返回唤醒数与重排数之和
/// * FUTEX_WAKE_OP: 返回两个地址上唤醒数之和
/// * PI 操作: 成功返回 0（GAP-5 PI parity: Linux 用户字协议）
pub(super) fn sys_futex(
    uaddr: usize,
    op: i32,
    val: u32,
    timeout_ptr: usize,
    uaddr2: usize,
    val3: u32,
) -> SyscallResult {
    let linux_op = op as u32;
    let request = decode_linux_futex_op(op, val, timeout_ptr, val3)?;

    // 验证用户指针
    if uaddr == 0 {
        return Err(SyscallError::EFAULT);
    }

    // 检查地址对齐（u32 需要 4 字节对齐）
    if uaddr % 4 != 0 {
        return Err(SyscallError::EINVAL);
    }

    // The second word must be a well-formed user futex address, as for a
    // Linux private futex. A requeue never touches it (the moved waiters are
    // woken from it later); FUTEX_WAKE_OP updates it, and so may
    // FUTEX_CMP_REQUEUE_PI (it takes the PI lock there for a waiter), so it
    // must also be writable (or copy-on-write, which the atomic update
    // breaks). FUTEX_WAIT_REQUEUE_PI only names it.
    let second_word_written = match request {
        LinuxFutexOp::Requeue { .. } | LinuxFutexOp::WaitRequeuePi { .. } => Some(false),
        LinuxFutexOp::WakeOp { .. } | LinuxFutexOp::CmpRequeuePi { .. } => Some(true),
        _ => None,
    };
    if let Some(written) = second_word_written {
        if uaddr2 == 0 {
            return Err(SyscallError::EFAULT);
        }
        if uaddr2 % 4 != 0 {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr(uaddr2 as *const u8, core::mem::size_of::<u32>())?;
        if written {
            verify_user_memory(uaddr2 as *const u8, core::mem::size_of::<u32>(), true)?;
        }
    }
    // Requeue-PI works on two distinct words (Linux: EINVAL).
    if matches!(
        request,
        LinuxFutexOp::WaitRequeuePi { .. } | LinuxFutexOp::CmpRequeuePi { .. }
    ) && uaddr == uaddr2
    {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存可访问
    // E.4 PI: only the PI operations write `uaddr` under the bucket lock;
    // WAIT/WAKE/REQUEUE/WAIT_REQUEUE_PI only read `uaddr` (or key on it), so
    // probing them with read intent avoids unnecessary RFO cache-line bouncing
    // and avoids breaking CoW on read-only futex waits.
    let writes_word = matches!(
        request,
        LinuxFutexOp::LockPi { .. } | LinuxFutexOp::TryLockPi | LinuxFutexOp::UnlockPi
    );
    let compares_word = matches!(
        request,
        LinuxFutexOp::Requeue { compare: true, .. } | LinuxFutexOp::CmpRequeuePi { .. }
    );
    let needs_entry_value = matches!(
        request,
        LinuxFutexOp::Wait { .. } | LinuxFutexOp::WaitRequeuePi { .. }
    );
    verify_user_memory(uaddr as *const u8, core::mem::size_of::<u32>(), writes_word)?;

    // R190-1 FIX: MAC-mediate the futex operation (raw Linux op word) after
    // argument validation and before any word read, wait or wake. Unreadable
    // credentials fail closed with EPERM, as at syscall entry.
    let lsm_ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
    lsm::hook_ipc_futex(&lsm_ctx, uaddr, linux_op).map_err(lsm_error_to_syscall)?;

    // 获取回调函数
    let futex_fn = {
        let callback = FUTEX_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 对于 WAIT/WAIT_BITSET/WAIT_REQUEUE_PI/CMP_REQUEUE(_PI)，需要先读取当前值。
    // The read also faults the word's page in; the IPC side re-reads it
    // without faulting while it holds the bucket lock.
    let current_value = if needs_entry_value || compares_word {
        // 读取 futex 字（安全：已验证用户内存）
        let mut value_bytes = [0u8; 4];
        copy_from_user(&mut value_bytes, uaddr as *const u8)?;
        u32::from_ne_bytes(value_bytes)
    } else {
        0 // WAKE/WAKE_OP/REQUEUE 不需要当前值；PI 锁在桶锁下读取
    };
    // CMP_REQUEUE's fast mismatch path; the IPC side repeats the comparison
    // under the bucket lock that serializes it with queueing waiters.
    if compares_word && current_value != val3 {
        return Err(SyscallError::EAGAIN);
    }

    // R39-6 FIX: 解析可选超时（纳秒）
    // `timeout` is set only for a non-NULL timeout pointer.
    let timeout_kind = match request {
        LinuxFutexOp::Wait { timeout, .. }
        | LinuxFutexOp::LockPi { timeout }
        | LinuxFutexOp::WaitRequeuePi { timeout } => timeout,
        _ => None,
    };
    let timeout_ns = if let Some(timeout_kind) = timeout_kind {
        // 验证 timespec 结构可读
        verify_user_memory(
            timeout_ptr as *const u8,
            core::mem::size_of::<TimeSpec>(),
            false,
        )?;

        // 读取 timespec
        let mut ts_bytes = [0u8; 16]; // sizeof(TimeSpec) = 16
        copy_from_user(&mut ts_bytes, timeout_ptr as *const u8)?;

        // 解析 timespec (tv_sec: i64, tv_nsec: i64)
        let mut tv_sec_bytes = [0u8; 8];
        let mut tv_nsec_bytes = [0u8; 8];
        tv_sec_bytes.copy_from_slice(&ts_bytes[0..8]);
        tv_nsec_bytes.copy_from_slice(&ts_bytes[8..16]);
        let tv_sec = i64::from_ne_bytes(tv_sec_bytes);
        let tv_nsec = i64::from_ne_bytes(tv_nsec_bytes);

        // 验证 timespec 有效性
        if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(SyscallError::EINVAL);
        }

        // 转换为纳秒
        let timeout_ns = (tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(tv_nsec as u64);
        Some(match timeout_kind {
            FutexTimeoutKind::Relative => timeout_ns,
            // A deadline already passed becomes 0, which times out at once
            // (after the value check, as on Linux). N2.6b: honor
            // FUTEX_CLOCK_REALTIME (and FUTEX_LOCK_PI which is always realtime)
            // against wall-clock `realtime_ns()`, and monotonic ops against
            // `monotonic_ns()`.
            FutexTimeoutKind::Absolute => {
                let use_realtime = (linux_op & 256) != 0 || (linux_op & !(128 | 256)) == 6;
                let now_ns = if use_realtime {
                    crate::time::realtime_ns()
                } else {
                    crate::time::monotonic_ns()
                };
                timeout_ns.saturating_sub(now_ns)
            }
        })
    } else {
        None
    };

    let call = match request {
        LinuxFutexOp::Wait { bitset, .. } => FutexRequest::Wait {
            expected: val,
            current: current_value,
            timeout_ns,
            bitset,
        },
        LinuxFutexOp::Wake { bitset } => FutexRequest::Wake { count: val, bitset },
        LinuxFutexOp::Requeue {
            nr_requeue,
            compare,
        } => FutexRequest::Requeue {
            nr_wake: val,
            nr_requeue,
            uaddr2,
            compare: compare.then_some(val3),
        },
        LinuxFutexOp::WakeOp { nr_wake2, op } => FutexRequest::WakeOp {
            nr_wake: val,
            nr_wake2,
            uaddr2,
            op,
        },
        LinuxFutexOp::LockPi { .. } => FutexRequest::LockPi {
            timeout_ns,
            trylock: false,
        },
        LinuxFutexOp::TryLockPi => FutexRequest::LockPi {
            timeout_ns: None,
            trylock: true,
        },
        LinuxFutexOp::UnlockPi => FutexRequest::UnlockPi,
        LinuxFutexOp::WaitRequeuePi { .. } => FutexRequest::WaitRequeuePi {
            expected: val,
            current: current_value,
            timeout_ns,
            uaddr2,
        },
        LinuxFutexOp::CmpRequeuePi { nr_requeue } => FutexRequest::CmpRequeuePi {
            nr_requeue,
            uaddr2,
            expected: val3,
        },
    };

    // 调用 IPC 模块的 futex 实现
    futex_fn(uaddr, call)
}

#[cfg(test)]
mod gap5_futex_abi_tests {
    use super::*;

    #[test]
    fn linux_futex_ops_decode_to_served_requests() {
        use FutexTimeoutKind::{Absolute, Relative};
        const PRIVATE: i32 = 128;
        const CLOCK_REALTIME: i32 = 256;
        let any = FUTEX_BITSET_MATCH_ANY;
        let decode = decode_linux_futex_op;
        let wait = |timeout, bitset| Ok(LinuxFutexOp::Wait { timeout, bitset });

        assert_eq!(decode(PRIVATE, 0, 0, 0), wait(None, any));
        assert_eq!(decode(0, 0, 0x1000, 0), wait(Some(Relative), any));
        assert_eq!(
            decode(1 | PRIVATE, 1, 0, 0),
            Ok(LinuxFutexOp::Wake { bitset: any })
        );
        assert_eq!(
            decode(3 | PRIVATE, 0, 1, 0),
            Ok(LinuxFutexOp::Requeue {
                nr_requeue: 1,
                compare: false
            })
        );
        // The requeue count is the low 32 bits of the timeout argument.
        assert_eq!(
            decode(4, 1, (1 << 32) | i32::MAX as usize, 7),
            Ok(LinuxFutexOp::Requeue {
                nr_requeue: i32::MAX as u32,
                compare: true
            })
        );
        assert_eq!(
            decode(6, 0, 0, 0),
            Ok(LinuxFutexOp::LockPi { timeout: None })
        );
        assert_eq!(decode(7 | PRIVATE, 0, 0, 0), Ok(LinuxFutexOp::UnlockPi));
        assert_eq!(
            decode(9 | PRIVATE | CLOCK_REALTIME, 0, 0x1000, any),
            wait(Some(Absolute), any)
        );
        assert_eq!(decode(9, 0, 0, any), wait(None, any));
        assert_eq!(
            decode(10 | PRIVATE, 1, 0, any),
            Ok(LinuxFutexOp::Wake { bitset: any })
        );

        // Negative counts, an empty bitset and a REALTIME relative wait are
        // invalid, as on Linux.
        assert_eq!(decode(3, u32::MAX, 1, 0), Err(SyscallError::EINVAL));
        assert_eq!(
            decode(4, 1, u32::MAX as usize, 0),
            Err(SyscallError::EINVAL)
        );
        assert_eq!(decode(9, 0, 0, 0), Err(SyscallError::EINVAL));
        assert_eq!(decode(10, 1, 0, 0), Err(SyscallError::EINVAL));
        assert_eq!(decode(CLOCK_REALTIME, 0, 0, 0), Err(SyscallError::ENOSYS));
        assert_eq!(
            decode(5 | CLOCK_REALTIME, 0, 0, 0),
            Err(SyscallError::ENOSYS)
        );
        // FUTEX_FD and unknown commands stay unserved.
        for unserved in [2, 14, 15] {
            assert_eq!(decode(unserved, 0, 0, any), Err(SyscallError::ENOSYS));
        }
    }

    #[test]
    fn futex_pi_ops_decode_with_linux_clock_and_count_rules() {
        use FutexTimeoutKind::Absolute;
        const PRIVATE: i32 = 128;
        const CLOCK_REALTIME: i32 = 256;
        let decode = decode_linux_futex_op;

        // LOCK_PI and LOCK_PI2 take an absolute deadline; TRYLOCK_PI none.
        assert_eq!(
            decode(6 | PRIVATE, 0, 0x1000, 0),
            Ok(LinuxFutexOp::LockPi {
                timeout: Some(Absolute)
            })
        );
        assert_eq!(
            decode(13, 0, 0x1000, 0),
            Ok(LinuxFutexOp::LockPi {
                timeout: Some(Absolute)
            })
        );
        assert_eq!(
            decode(13, 0, 0, 0),
            Ok(LinuxFutexOp::LockPi { timeout: None })
        );
        assert_eq!(
            decode(8 | PRIVATE, 0, 0x1000, 0),
            Ok(LinuxFutexOp::TryLockPi)
        );
        // FUTEX_CLOCK_REALTIME: LOCK_PI2 and WAIT_REQUEUE_PI yes, LOCK_PI
        // (always CLOCK_REALTIME), TRYLOCK_PI, UNLOCK_PI, CMP_REQUEUE_PI no.
        assert_eq!(
            decode(13 | CLOCK_REALTIME, 0, 0x1000, 0),
            Ok(LinuxFutexOp::LockPi {
                timeout: Some(Absolute)
            })
        );
        assert_eq!(
            decode(11 | PRIVATE | CLOCK_REALTIME, 0, 0x1000, 0),
            Ok(LinuxFutexOp::WaitRequeuePi {
                timeout: Some(Absolute)
            })
        );
        for refused in [6, 7, 8, 12] {
            assert_eq!(
                decode(refused | CLOCK_REALTIME, 1, 0, 0),
                Err(SyscallError::ENOSYS)
            );
        }
        assert_eq!(
            decode(11, 0, 0, 0),
            Ok(LinuxFutexOp::WaitRequeuePi { timeout: None })
        );
        // CMP_REQUEUE_PI: nr_wake must be 1, both counts non-negative; the
        // requeue count is the low 32 bits of the timeout slot.
        assert_eq!(
            decode(12 | PRIVATE, 1, (1 << 32) | 5, 0),
            Ok(LinuxFutexOp::CmpRequeuePi { nr_requeue: 5 })
        );
        assert_eq!(
            decode(12, 1, 0, 0),
            Ok(LinuxFutexOp::CmpRequeuePi { nr_requeue: 0 })
        );
        for nr_wake in [0, 2, u32::MAX] {
            assert_eq!(decode(12, nr_wake, 1, 0), Err(SyscallError::EINVAL));
        }
        assert_eq!(
            decode(12, 1, u32::MAX as usize, 0),
            Err(SyscallError::EINVAL)
        );
        // EDEADLK is the Linux errno value.
        assert_eq!(SyscallError::EDEADLK.as_i64(), -35);
    }

    #[test]
    fn futex_parity_partial_bitsets_decode_with_their_mask() {
        assert_eq!(
            decode_linux_futex_op(9 | 128, 0, 0, 0x5),
            Ok(LinuxFutexOp::Wait {
                timeout: None,
                bitset: 0x5
            })
        );
        assert_eq!(
            decode_linux_futex_op(10, 1, 0, 0x8000_0000),
            Ok(LinuxFutexOp::Wake {
                bitset: 0x8000_0000
            })
        );
        // Plain WAIT/WAKE ignore val3 and match every bit.
        assert_eq!(
            decode_linux_futex_op(0, 0, 0, 0x5),
            Ok(LinuxFutexOp::Wait {
                timeout: None,
                bitset: FUTEX_BITSET_MATCH_ANY
            })
        );
        assert_eq!(
            decode_linux_futex_op(1, 1, 0, 0),
            Ok(LinuxFutexOp::Wake {
                bitset: FUTEX_BITSET_MATCH_ANY
            })
        );
    }

    /// Linux `FUTEX_OP(op, oparg, cmp, cmparg)`.
    const fn futex_op(op: u32, oparg: u32, cmp: u32, cmparg: u32) -> u32 {
        ((op & 0xf) << 28) | ((cmp & 0xf) << 24) | ((oparg & 0xfff) << 12) | (cmparg & 0xfff)
    }

    #[test]
    fn futex_parity_wake_op_decode_validates_the_operation_word() {
        const OPARG_SHIFT: u32 = 8;
        // The second wake count is the low 32 bits of the timeout slot.
        let word = futex_op(1, 1, 0, 0);
        assert_eq!(
            decode_linux_futex_op(5 | 128, 1, (7 << 32) | 3, word),
            Ok(LinuxFutexOp::WakeOp {
                nr_wake2: 3,
                op: FutexWakeOp::decode(word).unwrap()
            })
        );
        // Operations 5..=7 and comparisons 6..=15 are ENOSYS.
        for op in 5..=7 {
            assert_eq!(
                FutexWakeOp::decode(futex_op(op, 0, 0, 0)),
                Err(SyscallError::ENOSYS)
            );
            assert_eq!(
                decode_linux_futex_op(5, 1, 1, futex_op(op, 0, 0, 0)),
                Err(SyscallError::ENOSYS)
            );
        }
        for cmp in 6..=15 {
            assert_eq!(
                FutexWakeOp::decode(futex_op(0, 0, cmp, 0)),
                Err(SyscallError::ENOSYS)
            );
        }
        // Every valid op/cmp pair decodes, with and without the shift flag.
        for op in 0..=4 {
            for cmp in 0..=5 {
                assert!(FutexWakeOp::decode(futex_op(op, 3, cmp, 1)).is_ok());
                assert!(FutexWakeOp::decode(futex_op(op | OPARG_SHIFT, 3, cmp, 1)).is_ok());
            }
        }
    }

    #[test]
    fn futex_parity_wake_op_applies_linux_arithmetic_and_signed_compare() {
        const OPARG_SHIFT: u32 = 8;
        let op =
            |op, oparg, cmp, cmparg| FutexWakeOp::decode(futex_op(op, oparg, cmp, cmparg)).unwrap();

        // SET, ADD, OR, ANDN, XOR.
        assert_eq!(op(0, 7, 0, 0).apply(100), 7);
        assert_eq!(op(1, 3, 0, 0).apply(5), 8);
        assert_eq!(op(1, 0xfff, 0, 0).apply(5), 4); // oparg -1
        assert_eq!(op(1, 1, 0, 0).apply(u32::MAX), 0); // wraps
        assert_eq!(op(2, 0x0f0, 0, 0).apply(0x00f), 0x0ff);
        assert_eq!(op(3, 0x0f0, 0, 0).apply(0x0ff), 0x00f);
        assert_eq!(op(4, 0x0ff, 0, 0).apply(0x0f0), 0x00f);
        // A negative SET operand stores its 32-bit sign extension.
        assert_eq!(op(0, 0x800, 0, 0).apply(0), (-2048i32) as u32);
        // FUTEX_OP_OPARG_SHIFT uses 1 << oparg; out-of-range shifts are
        // masked to 0..=31 as on Linux (-1 & 31 == 31).
        assert_eq!(op(OPARG_SHIFT, 4, 0, 0).apply(0), 1 << 4);
        assert_eq!(op(2 | OPARG_SHIFT, 31, 0, 0).apply(1), 0x8000_0001);
        assert_eq!(op(OPARG_SHIFT, 0xfff, 0, 0).apply(0), 1 << 31);
        assert_eq!(op(OPARG_SHIFT, 33, 0, 0).apply(0), 1 << 1);

        // EQ, NE, LT, LE, GT, GE on the old value, signed.
        assert!(op(0, 0, 0, 5).compare(5));
        assert!(!op(0, 0, 0, 5).compare(6));
        assert!(op(0, 0, 1, 5).compare(6));
        assert!(!op(0, 0, 1, 5).compare(5));
        assert!(op(0, 0, 2, 5).compare(4));
        assert!(!op(0, 0, 2, 5).compare(5));
        assert!(op(0, 0, 3, 5).compare(5));
        assert!(!op(0, 0, 3, 5).compare(6));
        assert!(op(0, 0, 4, 5).compare(6));
        assert!(!op(0, 0, 4, 5).compare(5));
        assert!(op(0, 0, 5, 5).compare(5));
        assert!(!op(0, 0, 5, 5).compare(4));
        // cmparg is a 12-bit signed field and the old value is an int: an
        // all-ones word is -1, which is below 0 and equal to cmparg 0xfff.
        assert!(op(0, 0, 2, 0).compare(u32::MAX));
        assert!(op(0, 0, 0, 0xfff).compare(u32::MAX));
        assert!(!op(0, 0, 4, 0).compare(0x8000_0000));
    }
}
