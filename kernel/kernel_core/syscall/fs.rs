//! Syscall family module: `fs` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// 文件I/O系统调用
// ============================================================================

/// sys_pipe - 创建匿名管道
///
/// 创建一个管道，返回两个文件描述符：
/// - fds[0]: 读端
/// - fds[1]: 写端
///
/// # Arguments
///
/// * `fds` - 指向用户空间的 i32[2] 数组，用于返回文件描述符
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
pub(super) fn sys_pipe(fds: *mut i32, entry_proc: Option<&ProcessArc>) -> SyscallResult {
    // 验证用户指针
    if fds.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R163-I1 FIX: Removed redundant validate_user_ptr — verify_user_memory
    // already calls validate_user_ptr internally as its first step.
    verify_user_memory(fds as *const u8, core::mem::size_of::<[i32; 2]>(), true)?;

    // 获取回调函数指针（无锁原子读取）
    let create_fn = get_pipe_create_callback().ok_or(SyscallError::ENOSYS)?;

    // 调用管道创建回调
    let (read_fd, write_fd) = create_fn(0, entry_proc)?;

    // 将文件描述符写回用户空间
    let fd_array = [read_fd, write_fd];
    // lint-repr-c-copy: allow (no-padding: [i32; 2] = 8 bytes, primitive array)
    let bytes = unsafe {
        core::slice::from_raw_parts(
            fd_array.as_ptr() as *const u8,
            core::mem::size_of::<[i32; 2]>(),
        )
    };

    // copy_to_user 失败时回滚：关闭已创建的文件描述符
    if let Err(e) = copy_to_user(fds as *mut u8, bytes) {
        if let Some(close) = get_fd_close_callback() {
            let _ = close(read_fd, entry_proc);
            let _ = close(write_fd, entry_proc);
        }
        return Err(e);
    }

    Ok(0)
}

/// sys_pipe2 - 创建管道，带标志位
///
/// M0-6 SLICE 4: Extends sys_pipe with O_CLOEXEC and O_NONBLOCK flags.
///
/// # Arguments
///
/// * `fds` - 用户空间指针，写入 [read_fd, write_fd]
/// * `flags` - O_CLOEXEC (0x80000) and/or O_NONBLOCK (0x800)
///
/// # Returns
///
/// 0 on success, errno on failure
pub(super) fn sys_pipe2(
    fds: *mut i32,
    flags: i32,
    entry_proc: Option<&ProcessArc>,
) -> SyscallResult {
    // Validate flags (only O_CLOEXEC and O_NONBLOCK are supported)
    const O_CLOEXEC: i32 = 0x80000;
    const O_NONBLOCK: i32 = 0x800;
    const VALID_FLAGS: i32 = O_CLOEXEC | O_NONBLOCK;

    if flags & !VALID_FLAGS != 0 {
        return Err(SyscallError::EINVAL);
    }

    // Validate user pointer
    if fds.is_null() {
        return Err(SyscallError::EFAULT);
    }
    verify_user_memory(fds as *const u8, core::mem::size_of::<[i32; 2]>(), true)?;

    // Get pipe creation callback (lock-free)
    let create_fn = get_pipe_create_callback().ok_or(SyscallError::ENOSYS)?;

    // KSA-013: prepare NONBLOCK and both CLOEXEC slots before publication.
    // The callback reserves both numeric descriptors within soft NOFILE and
    // rolls back both ends if any preflight resource cannot be acquired.
    let (read_fd, write_fd) = create_fn(flags as u32, entry_proc)?;

    // Write fds to user space
    let fd_array = [read_fd, write_fd];
    // lint-repr-c-copy: allow (no-padding: [i32; 2] = 8 bytes, primitive array)
    let bytes = unsafe {
        core::slice::from_raw_parts(
            fd_array.as_ptr() as *const u8,
            core::mem::size_of::<[i32; 2]>(),
        )
    };

    // copy_to_user failure → rollback: close allocated fds
    if let Err(e) = copy_to_user(fds as *mut u8, bytes) {
        if let Some(close) = get_fd_close_callback() {
            let _ = close(read_fd, entry_proc);
            let _ = close(write_fd, entry_proc);
        }
        return Err(e);
    }

    Ok(0)
}

/// sys_fcntl - 文件描述符控制操作
///
/// M0-6 SLICE 4: Minimal fcntl support for F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL.
///
/// # Arguments
///
/// * `fd` - 文件描述符
/// * `cmd` - 命令 (F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL)
/// * `arg` - 命令参数
///
/// # Returns
///
/// Command-dependent result or errno
pub(super) fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> SyscallResult {
    // fcntl command constants
    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_DUPFD_CLOEXEC: i32 = 1030;

    // FD_CLOEXEC flag
    const FD_CLOEXEC: i32 = 1;

    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            // Duplicate fd to lowest-numbered fd >= arg.
            // R173-06 PROPER FIX (supersedes the fail-closed EINVAL stopgap):
            // per-fd CLOEXEC tracking exists (Process::cloexec_fds, R39-4) —
            // F_DUPFD_CLOEXEC is F_DUPFD + set_fd_cloexec on the new fd,
            // mirroring sys_dup3's O_CLOEXEC handling.
            // Get current process
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = process_arc.lock();

            if arg >= proc.effective_fd_limit() as u64 {
                return Err(SyscallError::EINVAL);
            }
            let min_fd = arg as i32;

            // Get the source fd
            let cloned_desc = proc
                .get_fd(fd)
                .ok_or(SyscallError::EBADF)?
                .try_clone_box()
                .map_err(|_| SyscallError::ENOMEM)?;
            // One Process transaction chooses the lowest non-published and
            // non-reserved fd >= min_fd, admits both retained containers,
            // charges files.max, and publishes CLOEXEC atomically.
            let new_fd = match proc.allocate_fd_from_with_cloexec(
                cloned_desc,
                min_fd,
                cmd == F_DUPFD_CLOEXEC,
            ) {
                Ok(fd) => fd,
                Err(rejected) => {
                    drop(proc);
                    drop(rejected);
                    return Err(SyscallError::EMFILE);
                }
            };
            // U.S3-A3 FIX: bump the shared CapEntry refcount for the installed
            // copy only after publication succeeds.
            if let Some(cid) = proc.get_fd(new_fd).and_then(|d| d.cap_id()) {
                proc.capability_increment_refcount(cid);
            }

            Ok(new_fd as usize)
        }

        F_GETFD => {
            // Get file descriptor flags (only FD_CLOEXEC is defined).
            // R173-06 companion: report the REAL per-fd CLOEXEC state instead
            // of the old hardcoded 0 (which lied for fds marked via dup3/pipe2).
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = process_arc.lock();

            // Check if fd exists
            proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

            if proc.files.lock().cloexec_fds.contains(&fd) {
                Ok(FD_CLOEXEC as usize)
            } else {
                Ok(0)
            }
        }

        F_SETFD => {
            // Set file descriptor flags (only FD_CLOEXEC is defined).
            let flags = arg as i32;

            // Only FD_CLOEXEC is valid
            if flags & !FD_CLOEXEC != 0 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = process_arc.lock();

            // Check if fd exists (existence-gate BEFORE mutating the mark, so
            // cloexec_fds can never hold an entry for an absent fd —
            // INV: cloexec_fds ⊆ fd_table keys, relied on by exec's drain).
            proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

            proc.set_fd_cloexec(fd, flags & FD_CLOEXEC != 0)
                .map_err(|_| SyscallError::ENOMEM)?;

            Ok(0)
        }

        F_GETFL => {
            // Get file status flags
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = process_arc.lock();

            let descriptor = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
            descriptor.status_flags().map(|flags| flags as usize)
        }

        F_SETFL => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = process_arc.lock();

            let descriptor = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
            descriptor.set_status_flags(arg as u32)?;
            Ok(0)
        }

        _ => {
            // Unsupported fcntl command
            Err(SyscallError::EINVAL)
        }
    }
}

/// sys_pread64 - 从文件描述符在指定偏移量读取数据
///
/// M0-6 SLICE 4: Positioned read (does not change fd offset).
/// R173-07 proper fix (supersedes the ENOSYS stopgap): wire to VFS_PREAD_CALLBACK.
///
/// # Arguments
///
/// * `fd` - 文件描述符
/// * `buf` - 用户缓冲区
/// * `count` - 要读取的字节数
/// * `offset` - 文件偏移量
///
/// # Returns
///
/// Number of bytes read or errno
pub(super) fn sys_pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> SyscallResult {
    if lookup_console_file(fd)?.is_some() {
        return Err(SyscallError::ESPIPE);
    }

    // Validate offset (must be non-negative)
    if offset < 0 {
        return Err(SyscallError::EINVAL);
    }

    // Bound count (same MAX_RW_SIZE limit as sys_read)
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // Validate user buffer early
    validate_user_ptr_mut(buf, count)?;

    // Get the VFS pread callback
    let pread_fn = VFS_PREAD_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;

    // R180-10 FIX: admission lives through positioned I/O and copyout.
    let mut tmp = try_admitted_zeroed_io_buffer(count)?;

    // Call VFS positioned read (does not mutate fd offset)
    let bytes_read = pread_fn(fd, &mut tmp, offset as u64)?;
    // R188-U02-1 FIX: a filesystem callback is an internal trust boundary.
    // Clamp its reported count before slicing/copying so a buggy or malicious
    // implementation cannot turn a bounded read into an out-of-bounds panic.
    let bytes_read = bytes_read.min(tmp.len());

    // Copy result to user space
    if bytes_read > 0 {
        copy_to_user(buf, &tmp[..bytes_read])?;
    }

    Ok(bytes_read)
}

/// sys_pwrite64 - 向文件描述符在指定偏移量写入数据
///
/// M0-6 SLICE 4: Positioned write (does not change fd offset).
/// R173-07 proper fix (supersedes the ENOSYS stopgap): wire to VFS_PWRITE_CALLBACK.
///
/// # Arguments
///
/// * `fd` - 文件描述符
/// * `buf` - 用户缓冲区
/// * `count` - 要写入的字节数
/// * `offset` - 文件偏移量
///
/// # Returns
///
/// Number of bytes written or errno
pub(super) fn sys_pwrite64(fd: i32, buf: *const u8, count: usize, offset: i64) -> SyscallResult {
    if lookup_console_file(fd)?.is_some() {
        return Err(SyscallError::ESPIPE);
    }

    // Validate offset (must be non-negative)
    if offset < 0 {
        return Err(SyscallError::EINVAL);
    }

    // Bound count (same MAX_RW_SIZE limit as sys_write)
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // Validate user buffer early
    validate_user_ptr(buf, count)?;

    // Get the VFS pwrite callback
    let pwrite_fn = VFS_PWRITE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;

    // R180-10 FIX: admission lives through copyin and the positioned write.
    let mut tmp = try_admitted_zeroed_io_buffer(count)?;
    copy_from_user(&mut tmp, buf)?;

    // Call VFS positioned write (does not mutate fd offset)
    pwrite_fn(fd, &tmp, offset as u64)
}

/// sys_read - 从文件描述符读取数据
///
/// # Security (X-2 fix)
///
/// 限制单次读取大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_read 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值导致切片越界 panic。
/// Resolve `fd` and report whether it names the console.
///
/// R190-16: the result is a snapshot taken at syscall entry, the equivalent of
/// Linux `fdget()`. `ConsoleFile` is a stateless handle onto the one global
/// console, so finishing an in-flight read/write/ioctl on the console after
/// another thread `close`s or `dup2`s the descriptor is the same file-lifetime
/// behavior Linux gives a file reference taken at entry. Non-console
/// descriptors are re-resolved by the fd callbacks. `close(0/1/2)` has no
/// special case: `sys_close` removes the console entry like any other
/// descriptor (EBADF if absent), and later console I/O on that number fails
/// with EBADF.
pub(super) fn lookup_console_file(
    fd: i32,
) -> Result<Option<crate::process::ConsoleFile>, SyscallError> {
    lookup_console_file_with(fd, None)
}

pub(super) fn lookup_console_file_with(
    fd: i32,
    entry_proc: Option<&ProcessArc>,
) -> Result<Option<crate::process::ConsoleFile>, SyscallError> {
    let owned_process;
    let process = match entry_proc {
        Some(proc_arc) => proc_arc,
        None => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            owned_process = get_process(pid).ok_or(SyscallError::ESRCH)?;
            &owned_process
        }
    };
    let proc = process.lock();
    let descriptor = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
    Ok(descriptor
        .as_any()
        .downcast_ref::<crate::process::ConsoleFile>()
        .copied())
}

/// N2.7: Recognize both stdio `ConsoleFile` descriptors and VFS `/dev/console`
/// or `/dev/tty` handles for terminal `ioctl` handling. Returns `Some(readable)`.
fn lookup_tty_ioctl_target(fd: i32) -> Result<Option<bool>, SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();
    let descriptor = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
    if let Some(console) = descriptor
        .as_any()
        .downcast_ref::<crate::process::ConsoleFile>()
    {
        return Ok(Some(console.readable));
    }
    if let crate::poll::PollArm::Console { readable, .. } = descriptor.poll_arm() {
        return Ok(Some(readable));
    }
    Ok(None)
}

pub(super) fn sys_read(
    fd: i32,
    buf: *mut u8,
    count: usize,
    entry_proc: Option<&ProcessArc>,
) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1000); // sys_read entry
    }

    let console = lookup_console_file_with(fd, entry_proc)?;

    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr_mut(buf, count)?;

    // stdin (fd 0): 从键盘缓冲区读取字符
    // R23-5 fix: 阻塞模式 - 如果没有输入则等待
    // 使用 prepare-check-finish 模式避免丢失唤醒竞态
    if let Some(console) = console {
        if !console.readable {
            return Err(SyscallError::EBADF);
        }
        if !crate::process::console_input_allowed() {
            return Err(SyscallError::EPERM);
        }
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1001); // sys_read stdin path
        }
        // R158-I8 FIX: removed unconditional debug kprintln (log spam + info disclosure).

        // R180-10 FIX: the reservation remains live across the indefinite
        // keyboard wait and transactional copyout.
        let mut tmp = try_admitted_zeroed_io_buffer(count)?;
        loop {
            // 先尝试读取
            let bytes_read =
                drivers::keyboard_read_with_commit(&mut tmp, |bytes| copy_to_user(buf, bytes))?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }

            // 无数据：先入队再检查（避免丢失唤醒）
            match stdin_prepare_to_wait() {
                StdinWaitPrepare::Enqueued => {}
                StdinWaitPrepare::NoProcess => {
                    // 无当前进程，返回 0 (EOF)
                    return Ok(0);
                }
                StdinWaitPrepare::RegistryFull => {
                    // D1-RES R2: registry at capacity for a new pid — no Blocked
                    // publish, no lost wakeup. Bounded busy-retry (yield the CPU).
                    // Unreachable while resident tasks <= WAITER_REGISTRY_MAX_ENTRIES.
                    yield_with_deferred_work();
                    continue;
                }
            }

            // R180-L1: every exit from the post-enqueue second check must
            // dequeue and restore Blocked->Ready, including a copyout EFAULT.
            // The successful sleep/wake path is also safe: cancellation is
            // idempotent after the waker already popped this PID.
            struct StdinPreparedWaitGuard;
            impl Drop for StdinPreparedWaitGuard {
                fn drop(&mut self) {
                    stdin_cancel_wait();
                }
            }
            let _wait_guard = StdinPreparedWaitGuard;

            // 二次检查：入队后可能有新数据到达
            let bytes_read =
                drivers::keyboard_read_with_commit(&mut tmp, |bytes| copy_to_user(buf, bytes))?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }

            // 确实没有数据，完成等待（让出 CPU）
            // R171-F3: a pending kill interrupts the blocking stdin read (EINTR);
            // stdin_finish_wait() already dequeued us + restored Ready.
            if stdin_finish_wait() {
                return Err(SyscallError::EINTR);
            }
            // 被唤醒后继续循环尝试读取
        }
    }

    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1003); // sys_read fd callback path
    }

    // POSIX: read() on a socket fd is equivalent to recv(fd, buf, count, 0).
    if fd_is_socket(fd, entry_proc) {
        return sys_recvfrom(
            fd,
            buf,
            count,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }

    // 获取回调函数指针（无锁原子读取）
    let read_fn = get_fd_read_callback().ok_or(SyscallError::EBADF)?;

    // R180-10 FIX: ordinary files, pipes, and sockets retain this buffer across
    // their callback lifetime, which may block. Small transfers (<= 256 B) use
    // stack storage and consume zero heap bytes.
    let mut tmp = IoScratchBuffer::try_zeroed(count)?;
    let bytes_read = read_fn(
        fd,
        tmp.as_mut_slice(),
        &mut |bytes| copy_to_user(buf, bytes),
        entry_proc,
    )?;

    // Z-4 安全修复：将回调返回值 clamp 到请求的大小
    // 防止恶意/错误回调返回超大值导致切片越界 panic
    let bytes_read = bytes_read.min(count);

    // The callback copied out before committing its source transaction.
    Ok(bytes_read)
}

/// sys_write - 向文件描述符写入数据
///
/// # Security (X-2 fix)
///
/// 限制单次写入大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_written 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值。
pub(super) fn sys_write(
    fd: i32,
    buf: *const u8,
    count: usize,
    entry_proc: Option<&ProcessArc>,
) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1010); // sys_write entry
    }

    let console = lookup_console_file_with(fd, entry_proc)?;

    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr(buf, count)?;

    // R180-10 FIX: keep aggregate admission through copyin and any blocking
    // pipe/socket write callback. Small transfers (<= 256 B) use stack storage
    // and consume zero heap bytes.
    let mut tmp = IoScratchBuffer::try_zeroed(count)?;
    copy_from_user(tmp.as_mut_slice(), buf)?;

    // stdout(1)/stderr(2): 直接打印
    // R158-I9 FIX: Accept non-UTF-8 bytes (POSIX write(2) is byte-oriented).
    // Display valid UTF-8 as text; replace invalid sequences with U+FFFD.
    if let Some(console) = console {
        if console.readable {
            return Err(SyscallError::EBADF);
        }
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1011); // sys_write stdout/stderr path
        }
        // TD-SERIAL-1: one console write session for the whole call.
        let mut session = console_write_session();
        write_console_lossy(&mut session, tmp.as_slice());
        drop(session);
        // GAP-6 F11 diagnostic: console output is the stress runner's progress.
        #[cfg(feature = "stall_dump")]
        crate::process::LAST_CONSOLE_WRITE_TICK
            .store(crate::get_ticks(), core::sync::atomic::Ordering::Relaxed);
        Ok(tmp.len())
    } else {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1013); // sys_write fd callback path
        }
        // POSIX: write() on a socket fd is equivalent to send(fd, buf, count, 0).
        if fd_is_socket(fd, entry_proc) {
            drop(tmp);
            return sys_sendto(fd, buf, count, 0, core::ptr::null(), 0);
        }
        // 获取回调函数指针（无锁原子读取）
        let write_fn = get_fd_write_callback().ok_or(SyscallError::EBADF)?;

        // 在锁外执行写入
        let bytes_written = write_fn(fd, tmp.as_slice(), entry_proc)?;

        // Z-4 安全修复：将回调返回值 clamp 到请求的大小
        Ok(bytes_written.min(count))
    }
}

/// iovec 结构，用于 writev/readv 分散-聚集 I/O
#[repr(C)]
pub(super) struct Iovec {
    /// 缓冲区起始地址
    pub(super) iov_base: *const u8,
    /// 缓冲区长度
    pub(super) iov_len: usize,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<Iovec>()];

/// writev 最大 iovec 数量
pub(super) const IOV_MAX: usize = 1024;

/// Copy and validate a user-supplied `iovec[]` array into kernel memory.
///
/// Shared by `sys_writev` and `sys_readv` so the scatter/gather I/O ABI has a
/// SINGLE hardened validation path (a divergent copy in each would be a latent
/// audit gap). Returns an empty `Vec` for `iovcnt == 0`.
///
/// Preserves the writev security history:
/// - R97-1: `checked_mul`/`checked_add` guard the array-size and per-entry
///   offset arithmetic against integer overflow.
/// - R24-11 / P1-6: each entry is copied with the fault-tolerant
///   `copy_from_user_safe` (its own per-chunk SMAP window — NO outer
///   `UserAccessGuard`, which would widen the inter-chunk interrupt-restore
///   window). A concurrent user unmap degrades to `EFAULT`, never a kernel fault.
/// - R158-9: fallible `try_reserve_exact` (bounded by `IOV_MAX`, but policy
///   forbids the infallible `Vec` allocation).
pub(super) fn copy_iovec_array_from_user(
    iov: *const Iovec,
    iovcnt: usize,
) -> Result<AdmittedVec<Iovec>, SyscallError> {
    use crate::usercopy::copy_from_user_safe;

    if iovcnt == 0 {
        return try_admitted_vec(mm::HeapClass::BlockingIo, 0);
    }
    if iovcnt > IOV_MAX {
        return Err(SyscallError::EINVAL);
    }
    if iov.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let iov_size = iovcnt
        .checked_mul(mem::size_of::<Iovec>())
        .ok_or(SyscallError::EFAULT)?;
    validate_user_ptr(iov as *const u8, iov_size)?;

    // R180-10 FIX: readv/writev keep this descriptor array alive across the
    // underlying operation, which may block. Return its reservation with it.
    let mut iov_array = try_admitted_vec::<Iovec>(mm::HeapClass::BlockingIo, iovcnt)?;
    for i in 0..iovcnt {
        let entry_offset = i
            .checked_mul(mem::size_of::<Iovec>())
            .ok_or(SyscallError::EFAULT)?;
        let entry_ptr = (iov as usize)
            .checked_add(entry_offset)
            .ok_or(SyscallError::EFAULT)? as *const u8;

        // Fault-tolerant per-entry copy, then unaligned read (entry_bytes has
        // only 1-byte alignment).
        // SAFETY: Iovec is repr(C) and every byte pattern is a valid Iovec.
        let mut entry_bytes = [0u8; mem::size_of::<Iovec>()];
        if copy_from_user_safe(&mut entry_bytes, entry_ptr).is_err() {
            return Err(SyscallError::EFAULT);
        }
        let iov_entry: Iovec =
            unsafe { core::ptr::read_unaligned(entry_bytes.as_ptr() as *const Iovec) };
        iov_array.push(iov_entry);
    }

    Ok(iov_array)
}

/// sys_writev - 分散写入多个缓冲区
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `iov` - iovec 数组指针
/// * `iovcnt` - iovec 数组元素个数
///
/// # Returns
/// 成功返回写入的总字节数，失败返回错误码
pub(super) fn sys_writev(fd: i32, iov: *const Iovec, iovcnt: usize) -> SyscallResult {
    // Shared hardened validation/copy (R97-1 / R24-11 / P1-6 / R158-9).
    let iov_array = copy_iovec_array_from_user(iov, iovcnt)?;
    if iov_array.is_empty() {
        return Ok(0);
    }

    // TD-SERIAL-1: musl writes every stdio line as `writev({text}, {"\n"})`.
    // Through `sys_write` each iovec was its own console write, so another
    // writer's output could land between a line and its newline; a console
    // `writev` is one session instead.
    if iov_array.iter().any(|entry| entry.iov_len != 0) {
        if let Some(console) = lookup_console_file(fd)? {
            return sys_writev_console(console, &iov_array);
        }
    }

    // 逐个写入每个缓冲区
    let mut total_written: usize = 0;
    for entry in iov_array.iter() {
        if entry.iov_len == 0 {
            continue;
        }

        // 验证并写入单个缓冲区
        match sys_write(fd, entry.iov_base, entry.iov_len, None) {
            Ok(written) => {
                // R104-4 FIX: Use checked_add to prevent silent usize wrap-around
                // when a malicious/buggy iov list accumulates > usize::MAX bytes.
                total_written = total_written
                    .checked_add(written)
                    .ok_or(SyscallError::EOVERFLOW)?;

                // R177-2 FIX: Stop on short write (written < iov_len).
                // When sys_write accepts only part of a buffer (e.g., non-blocking socket/pipe
                // with limited send buffer space), continuing to the next iovec creates a data
                // gap. POSIX writev semantics: return partial count on short write, letting
                // the caller retry with adjusted iovecs. This is correct for regular files
                // (writes are always complete), and fixes the correctness edge for partial-
                // accepting fds.
                if written < entry.iov_len {
                    break;
                }
            }
            Err(e) => {
                // 如果已写入部分数据，返回已写入的字节数
                if total_written > 0 {
                    return Ok(total_written);
                }
                return Err(e);
            }
        }
    }

    Ok(total_written)
}

/// TD-SERIAL-1: a console write session for the calling task.
pub(super) fn console_write_session() -> drivers::vga_buffer::ConsoleWrite {
    drivers::vga_buffer::ConsoleWrite::begin(current_pid().unwrap_or(0))
}

/// Write user console bytes to `session`.
///
/// R158-I9 FIX: Accept non-UTF-8 bytes (POSIX write(2) is byte-oriented).
/// Display valid UTF-8 as text; replace invalid sequences with U+FFFD.
/// R162-17 FIX: Avoid infallible from_utf8_lossy which can allocate ~3x input
/// size on all-invalid bytes: write valid spans and one replacement character
/// per invalid sequence. R190-13: user stdout is TTY data, written byte-exact
/// to the serial console (kernel diagnostics use the sanitizing `print!`).
pub(super) fn write_console_lossy(session: &mut drivers::vga_buffer::ConsoleWrite, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(valid) => {
                session.write_str(valid);
                break;
            }
            Err(error) => {
                let (valid, invalid) = rest.split_at(error.valid_up_to());
                if let Ok(valid) = core::str::from_utf8(valid) {
                    session.write_str(valid);
                }
                session.write_str("\u{FFFD}");
                rest = &invalid[error.error_len().unwrap_or(1).min(invalid.len())..];
            }
        }
    }
}

/// TD-SERIAL-1: `writev` on a console descriptor, as one console write
/// session. Per iovec this keeps `sys_write`'s console contract (size cap,
/// pointer validation, admitted copy, then EBADF for a readable console); an
/// error after some bytes returns the count written so far.
pub(super) fn sys_writev_console(
    console: crate::process::ConsoleFile,
    iovs: &[Iovec],
) -> SyscallResult {
    let mut session = console_write_session();
    let mut total_written: usize = 0;
    for entry in iovs.iter().filter(|entry| entry.iov_len != 0) {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1010); // sys_write entry
        }
        let copied = (|| {
            if entry.iov_len > MAX_RW_SIZE {
                return Err(SyscallError::E2BIG);
            }
            validate_user_ptr(entry.iov_base, entry.iov_len)?;
            let mut tmp = IoScratchBuffer::try_zeroed(entry.iov_len)?;
            copy_from_user(tmp.as_mut_slice(), entry.iov_base)?;
            if console.readable {
                return Err(SyscallError::EBADF);
            }
            Ok(tmp)
        })();
        let tmp = match copied {
            Ok(tmp) => tmp,
            Err(_) if total_written > 0 => break,
            Err(error) => return Err(error),
        };
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1011); // sys_write stdout/stderr path
        }
        write_console_lossy(&mut session, tmp.as_slice());
        total_written = total_written
            .checked_add(tmp.len())
            .ok_or(SyscallError::EOVERFLOW)?;
    }
    drop(session);
    // GAP-6 F11 diagnostic: console output is the stress runner's progress.
    #[cfg(feature = "stall_dump")]
    crate::process::LAST_CONSOLE_WRITE_TICK
        .store(crate::get_ticks(), core::sync::atomic::Ordering::Relaxed);
    Ok(total_written)
}

/// Check whether `fd` currently refers to a `SocketFile`.
pub(super) fn fd_is_socket(fd: i32, entry_proc: Option<&ProcessArc>) -> bool {
    let process = match entry_proc {
        Some(proc_arc) => proc_arc.clone(),
        None => match current_pid().and_then(get_process) {
            Some(proc_arc) => proc_arc,
            None => return false,
        },
    };
    let proc = process.lock();
    proc.get_fd(fd)
        .and_then(|obj| obj.as_any().downcast_ref::<SocketFile>().map(|_| ()))
        .is_some()
}

/// Index of the first non-empty iovec — kept for M0 #2 self-test coverage.
pub(super) fn first_nonempty_iovec(iovs: &[Iovec]) -> Option<usize> {
    iovs.iter().position(|e| e.iov_len != 0)
}

/// Compute the total byte length of an `iovec` slice, rejecting `isize::MAX` overflow
/// per POSIX/Linux `readv`/`writev`/`sendmsg`/`recvmsg` rules.
pub(super) fn iovec_total_len(iovs: &[Iovec]) -> Result<usize, SyscallError> {
    let mut total: usize = 0;
    for entry in iovs {
        total = total
            .checked_add(entry.iov_len)
            .ok_or(SyscallError::EINVAL)?;
        if total > isize::MAX as usize {
            return Err(SyscallError::EINVAL);
        }
    }
    Ok(total)
}

/// Validate writable user pointers for all non-empty iovecs up to `max_bytes`.
pub(super) fn validate_iovecs_writable(
    iovs: &[Iovec],
    max_bytes: usize,
) -> Result<(), SyscallError> {
    let mut remaining = max_bytes;
    for entry in iovs {
        if remaining == 0 {
            break;
        }
        if entry.iov_len == 0 {
            continue;
        }
        let chunk = core::cmp::min(entry.iov_len, remaining);
        validate_user_ptr_mut(entry.iov_base as *mut u8, chunk)?;
        remaining -= chunk;
    }
    Ok(())
}

/// Scatter `data` sequentially across user `iovs` using fault-tolerant `copy_to_user`.
///
/// Shared by `sys_readv` and `sys_recvmsg`. Returns the exact number of bytes copied
/// (`min(data.len(), sum(iov_len))`). If any segment faults, returns `EFAULT` immediately
/// so transactional readers (pipes, VFS files, sockets) leave their source position
/// unchanged.
pub(super) fn copy_slice_to_iovecs(iovs: &[Iovec], data: &[u8]) -> Result<usize, SyscallError> {
    let mut offset = 0usize;
    for entry in iovs {
        if offset >= data.len() {
            break;
        }
        if entry.iov_len == 0 {
            continue;
        }
        let take = core::cmp::min(entry.iov_len, data.len() - offset);
        copy_to_user(entry.iov_base as *mut u8, &data[offset..offset + take])?;
        offset += take;
    }
    Ok(offset)
}

/// Gather all non-empty user `iovs` into a single admitted kernel buffer of class `class`,
/// enforcing `max_bytes` (returning `too_large_err` when exceeded).
///
/// Shared by `sys_sendmsg` (and available to other vectored writers).
pub(super) fn gather_iovecs_from_user(
    iovs: &[Iovec],
    class: mm::HeapClass,
    max_bytes: usize,
    too_large_err: SyscallError,
) -> Result<AdmittedVec<u8>, SyscallError> {
    let total = iovec_total_len(iovs)?;
    if total > max_bytes {
        return Err(too_large_err);
    }
    if total == 0 {
        return try_admitted_vec(class, 0);
    }
    for entry in iovs {
        if entry.iov_len != 0 {
            validate_user_ptr(entry.iov_base, entry.iov_len)?;
        }
    }
    let mut buf = try_admitted_zeroed_buffer(class, total)?;
    let mut offset = 0usize;
    for entry in iovs {
        if entry.iov_len == 0 {
            continue;
        }
        let end = offset + entry.iov_len;
        copy_from_user(&mut buf[offset..end], entry.iov_base)?;
        offset = end;
    }
    Ok(buf)
}

/// sys_readv - 分散读取到多个缓冲区 (Linux x86_64 syscall 19)
///
/// N2.8: True multi-iovec scatter read backed by a SINGLE transactional read
/// operation into a bounded staging buffer (`min(total_len, MAX_RW_SIZE)`), then
/// scattered across all iovecs via `copy_slice_to_iovecs`.
///
/// Because only ONE underlying read executes per `readv`, blocking sources (stdin,
/// pipes, sockets) never issue a second blocking read at a segment boundary, and
/// any usercopy fault on a later segment leaves the file offset / pipe queue /
/// socket queue untouched.
pub(super) fn sys_readv(fd: i32, iov: *const Iovec, iovcnt: usize) -> SyscallResult {
    // Shared hardened validation/copy (R97-1 / R24-11 / P1-6 / R158-9).
    let iov_array = copy_iovec_array_from_user(iov, iovcnt)?;
    let total_len = iovec_total_len(&iov_array)?;

    // Validate fd even when total_len == 0? Match existing sys_read/readv:
    // empty vector or all zero-length segments reads nothing and returns 0.
    if total_len == 0 {
        return Ok(0);
    }

    let read_cap = core::cmp::min(total_len, MAX_RW_SIZE);
    validate_iovecs_writable(&iov_array, read_cap)?;

    let console = lookup_console_file_with(fd, None)?;

    if let Some(console) = console {
        if !console.readable {
            return Err(SyscallError::EBADF);
        }
        if !crate::process::console_input_allowed() {
            return Err(SyscallError::EPERM);
        }
        let mut tmp = try_admitted_zeroed_io_buffer(read_cap)?;
        loop {
            let bytes_read = drivers::keyboard_read_with_commit(&mut tmp, |bytes| {
                copy_slice_to_iovecs(&iov_array, bytes).map(|_| ())
            })?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }
            match stdin_prepare_to_wait() {
                StdinWaitPrepare::Enqueued => {}
                StdinWaitPrepare::NoProcess => return Ok(0),
                StdinWaitPrepare::RegistryFull => {
                    yield_with_deferred_work();
                    continue;
                }
            }
            struct StdinPreparedWaitGuard;
            impl Drop for StdinPreparedWaitGuard {
                fn drop(&mut self) {
                    stdin_cancel_wait();
                }
            }
            let _wait_guard = StdinPreparedWaitGuard;

            let bytes_read = drivers::keyboard_read_with_commit(&mut tmp, |bytes| {
                copy_slice_to_iovecs(&iov_array, bytes).map(|_| ())
            })?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }
            if stdin_finish_wait() {
                return Err(SyscallError::EINTR);
            }
        }
    }

    // Socket descriptors scatter via the shared transactional socket recv path.
    if fd_is_socket(fd, None) {
        return recv_socket_into_iovecs(fd, &iov_array, read_cap, 0, None, None);
    }

    let read_fn = get_fd_read_callback().ok_or(SyscallError::EBADF)?;
    let mut tmp = IoScratchBuffer::try_zeroed(read_cap)?;
    let bytes_read = read_fn(
        fd,
        tmp.as_mut_slice(),
        &mut |bytes| copy_slice_to_iovecs(&iov_array, bytes).map(|_| ()),
        None,
    )?;

    Ok(bytes_read.min(read_cap))
}

/// sys_open - 打开文件
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `flags` - 打开标志 (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - 创建文件时的权限模式
///
/// # Returns
/// 成功返回文件描述符，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
pub(super) fn sys_open(path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1020); // sys_open entry
    }

    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?
    };

    // R96-5 FIX: Delegate to internal helper to avoid TOCTOU in openat
    sys_open_internal(&path_str, flags, mode)
}

/// R180-23/RF180-37: RAII ownership of one FD number plus its hierarchical
/// files.max charge while open/socket/accept performs work before publication.
/// Every failed preflight or side effect pays the reservation back exactly.
#[must_use = "dropping an uncommitted FD reservation cancels its files.max admission"]
pub(super) struct FdPublicationReservation {
    pub(super) process: crate::process::ProcessArc,
    pub(super) fd: i32,
    pub(super) active: bool,
}

impl FdPublicationReservation {
    pub(super) fn commit_with_guard(
        mut self,
        process: &mut crate::process::Process,
        descriptor: FileDescriptor,
    ) -> i32 {
        process.commit_reserved_fd(self.fd, descriptor);
        self.active = false;
        self.fd
    }

    pub(super) fn try_new(
        process: crate::process::ProcessArc,
        cloexec: bool,
    ) -> Result<Self, SyscallError> {
        let fd = process
            .lock()
            .reserve_fd_with_cloexec(cloexec)
            .ok_or(SyscallError::EMFILE)?;
        Ok(Self {
            process,
            fd,
            active: true,
        })
    }

    /// R186-1 FIX: publish through a Process guard the caller ALREADY holds.
    ///
    /// D2-ARC-FD-PUBLICATION: `install` below acquires `self.process` internally.
    /// A caller holding that same guard therefore spins forever on the
    /// non-reentrant mutex — the R186-1 CRITICAL, which every successful
    /// `open`/`openat` hit. This variant borrows the live guard so a second
    /// acquisition is impossible by construction.
    ///
    /// The error leg settles the reservation THROUGH THE CALLER'S GUARD and
    /// disarms `active`. That is load-bearing, not tidiness: allowing `Drop` to
    /// run here would re-enter `self.process.lock()` while the caller still owns
    /// it, reproducing the very deadlock this method exists to remove.
    ///
    /// The returned `FileDescriptor` must be dropped only after the caller
    /// releases the guard (R170-6: `FileHandle::drop` may re-enter the VFS).
    pub(super) fn install_with_guard(
        mut self,
        proc: &mut crate::process::Process,
        desc: crate::process::FileDescriptor,
    ) -> Result<i32, crate::process::FileDescriptor> {
        match proc.install_reserved_fd(self.fd, desc) {
            Ok(()) => {
                self.active = false;
                Ok(self.fd)
            }
            Err(desc) => {
                if !proc.cancel_fd_reservation(self.fd) {
                    klog!(
                        Error,
                        "R186-1: FD publication rollback rejected under caller guard"
                    );
                }
                self.active = false;
                Err(desc)
            }
        }
    }

    /// Publish for callers that hold NO Process guard. This is the only place a
    /// reservation may acquire the Process lock itself; anyone already holding it
    /// must use [`Self::install_with_guard`] (R186-1).
    pub(super) fn install(
        self,
        desc: crate::process::FileDescriptor,
    ) -> Result<i32, crate::process::FileDescriptor> {
        let process = self.process.clone();
        let mut guard = process.lock();
        self.install_with_guard(&mut guard, desc)
    }
}

impl Drop for FdPublicationReservation {
    fn drop(&mut self) {
        if self.active {
            let cancelled = self.process.lock().cancel_fd_reservation(self.fd);
            if !cancelled {
                klog!(
                    Error,
                    "R180-23/RF180-37: stale or corrupt FD publication reservation rollback"
                );
            }
        }
    }
}

/// R96-5 FIX: Internal helper for sys_open that works on already-copied path.
///
/// This eliminates TOCTOU window in sys_openat where the path could be modified
/// between checking the first byte and calling sys_open.
pub(super) fn sys_open_internal(path_str: &str, flags: i32, mode: u32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1021); // sys_open_internal entry
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R105-1 FIX: Removed duplicate LSM hook_file_create / hook_file_open from
    // the syscall layer.  The VFS layer (manager.rs open_file / create_file)
    // already invokes both hooks with the authoritative inode metadata.
    // Keeping the hooks here caused:
    //   1. Double hook invocation per open, with inconsistent object identity
    //      (path_hash here vs real inode in VFS).
    //   2. Risk of policy desync if one layer is bypassed.
    let open_flags = flags as u32;

    // RF186-7: keep one credential identity stable across the complete VFS
    // authorization and side-effect span. The separate operation gate allows
    // VFS/LSM callbacks to read current credentials without recursively taking
    // the credential RwLock, while credential writers cannot race create or
    // truncate and turn a later EAGAIN into a failure-after-side-effect.
    let credentials = process.lock().shared_credentials();
    let credential_authorization = credentials.begin_authorization();
    let cred_gen_before = credentials.generation();

    // 获取 VFS 回调
    let open_fn = {
        let callback = VFS_OPEN_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // Reserve both the numeric slot and files.max credit BEFORE VFS may create
    // or truncate an inode. The guard rolls back on every `?` below.
    let fd_reservation =
        FdPublicationReservation::try_new(process.clone(), open_flags & 0x80000 != 0)?;

    // 调用 VFS 打开文件 — VFS enforces LSM hooks with real inode context
    // RUNG 2: VFS failure auto-rollback via Drop (fd_reservation + PreparedFileHandle)
    let prepared = open_fn(path_str, open_flags, mode, &credential_authorization)?;
    publish_prepared_open(
        &process,
        open_flags,
        prepared,
        fd_reservation,
        credential_authorization,
        cred_gen_before,
    )
}

pub(super) fn publish_prepared_open(
    process: &crate::process::ProcessArc,
    open_flags: u32,
    prepared: PreparedVfsOpen,
    fd_reservation: FdPublicationReservation,
    authorization: crate::process::CredentialAuthorization,
    credential_generation: u64,
) -> SyscallResult {
    #[cfg(feature = "open_fault_probe")]
    let probe = prepared.probe;
    #[cfg(feature = "open_fault_probe")]
    let credential_generation = if probe == OpenFaultProbe::StaleCredentials {
        credential_generation.wrapping_add(1)
    } else {
        credential_generation
    };
    let cap_authority = process.lock().capability_table_authority();
    let (descriptor, prepared_cap) = prepared.finish_after(|descriptor| {
        let stat = descriptor.stat().map_err(|_| SyscallError::EIO)?;
        let proc = process.lock();
        if !proc.credentials_match_authorization(&authorization)
            || proc.cred_generation() != credential_generation
        {
            #[cfg(feature = "open_fault_probe")]
            if probe == OpenFaultProbe::StaleCredentials {
                assert!(proc.credentials_match_authorization(&authorization));
                klog::klog_always!("KSA-004-INJECT stage=credential errno=11");
            }
            return Err(SyscallError::EAGAIN);
        }
        if stat.mode & S_IFMT == 0o100000 {
            let mut rights = cap::CapRights::empty();
            let access_mode = open_flags & 0x3;
            if access_mode == 0 || access_mode == 2 {
                rights |= cap::CapRights::READ;
            }
            if access_mode == 1 || access_mode == 2 {
                rights |= cap::CapRights::WRITE;
            }
            let entry = cap::CapEntry::with_flags(
                cap::CapObject::RegularFile(cap::RegularFile {
                    inode_id: stat.ino,
                    fs_id: stat.dev,
                }),
                rights,
                cap::CapFlags::empty(),
            );
            #[cfg(feature = "open_fault_probe")]
            if probe == OpenFaultProbe::CapabilityAllocation {
                klog::klog_always!("KSA-004-INJECT stage=capability errno=12");
                return Err(SyscallError::ENOMEM);
            }
            let reservation =
                prepare_cap_allocation_authorized(&proc, &cap_authority, authorization.derive())?;
            descriptor.set_cap_id(reservation.cap_id());
            Ok(Some((reservation, entry)))
        } else {
            Ok(None)
        }
    })?;
    let (fd, grant) = {
        let mut proc = process.lock();
        let fd = fd_reservation.commit_with_guard(&mut proc, descriptor);
        let grant = prepared_cap.map(|(reservation, entry)| reservation.install(entry));
        (fd, grant)
    };
    if let Some(grant) = grant {
        grant.audit();
    }
    Ok(fd as usize)
}

/// sys_stat - 获取文件状态
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
pub(super) fn sys_stat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?
    };

    // R96-5 FIX: Delegate to internal helper to avoid TOCTOU in fstatat
    sys_stat_internal(&path_str, statbuf)
}

/// R113-1 FIX: Copy VfsStat to userspace via a zeroed byte buffer so that
/// every byte of the 144-byte Linux stat record is kernel-controlled.
/// D2-ABI-STAT-LAYOUT: the layout no longer has implicit padding (pad0 and
/// unused0..2 are explicit fields, serialized as 0 below); the zeroed staging
/// buffer is retained as defense-in-depth.
#[inline]
pub(super) fn copy_vfs_stat_to_user(
    user_dst: *mut VfsStat,
    stat: &VfsStat,
) -> Result<(), SyscallError> {
    let process =
        get_process(current_pid().ok_or(SyscallError::ESRCH)?).ok_or(SyscallError::ESRCH)?;
    let namespace = process.lock().user_ns.clone();
    let mut mapped = *stat;
    mapped.uid = namespace.map_uid_to_ns(stat.uid).unwrap_or(65534);
    mapped.gid = namespace.map_gid_to_ns(stat.gid).unwrap_or(65534);
    let stat = &mapped;
    let mut buf = [0u8; mem::size_of::<VfsStat>()];

    macro_rules! put {
        ($field:ident) => {
            let off = mem::offset_of!(VfsStat, $field);
            let bytes = stat.$field.to_ne_bytes();
            buf[off..off + bytes.len()].copy_from_slice(&bytes);
        };
    }

    put!(dev);
    put!(ino);
    put!(nlink);
    put!(mode);
    put!(uid);
    put!(gid);
    put!(pad0);
    put!(rdev);
    put!(size);
    put!(blksize);
    put!(blocks);
    put!(atime_sec);
    put!(atime_nsec);
    put!(mtime_sec);
    put!(mtime_nsec);
    put!(ctime_sec);
    put!(ctime_nsec);
    put!(unused0);
    put!(unused1);
    put!(unused2);

    copy_to_user(user_dst as *mut u8, &buf)
}

/// R96-5 FIX: Internal helper for sys_stat that works on already-copied path.
///
/// This eliminates TOCTOU window in sys_fstatat where the path could be modified
/// between checking the first byte and calling sys_stat.
pub(super) fn sys_stat_internal(path_str: &str, statbuf: *mut VfsStat) -> SyscallResult {
    // 获取 VFS stat 回调
    let stat_fn = {
        let callback = VFS_STAT_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS stat
    let stat = stat_fn(path_str)?;

    // R113-1 FIX: Copy via zeroed buffer to avoid padding info leak
    copy_vfs_stat_to_user(statbuf, &stat)?;

    Ok(0)
}

/// sys_fstat - 获取文件描述符状态
///
/// R41-1 FIX: 现在返回真实的 inode 元数据，而非虚假数据。
/// - 标准流 (0/1/2) 返回字符设备模式 (S_IFCHR | 0666)
/// - FileHandle: 查询底层 inode.stat() 获取真实元数据
/// - PipeHandle: 返回 S_IFIFO | 0666 模式
/// - 其他类型: 返回 EBADF
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
///
/// # Security
/// 此修复解决了 R41-1 安全漏洞：之前的实现返回虚假的 S_IFREG|0644
/// 给所有 fd>2，导致类型混淆和安全策略绕过。现在正确返回文件
/// 类型（普通文件、FIFO 等），使安全检查能够正确判断 fd 类型。
pub(super) fn sys_fstat(fd: i32, statbuf: *mut VfsStat) -> SyscallResult {
    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    validate_user_ptr(statbuf as *const u8, mem::size_of::<VfsStat>())?;
    verify_user_memory(statbuf as *const u8, mem::size_of::<VfsStat>(), true)?;

    // 负数 fd 无效
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }

    // 获取 stat 数据
    let stat = {
        // R41-1 FIX: 查询 fd 对象获取真实元数据
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
        // R131-4 FIX: Release process lock before calling VFS stat() callback.
        // Holding the process lock across inode.stat() creates a lock ordering
        // inversion risk: process lock → procfs → PROCESS_TABLE (reverse of
        // normal signal delivery path: PROCESS_TABLE → process lock).
        // Same clone_box() pattern as R130-2 sys_lseek fix.
        let fd_obj = {
            let proc = process.lock();
            let cloned = proc
                .get_fd(fd)
                .ok_or(SyscallError::EBADF)?
                .try_clone_box()
                .map_err(|_| SyscallError::ENOMEM)?;
            cloned
        };
        // Process lock released here — safe for VFS/procfs operations
        fd_obj.stat()?
    };

    // R113-1 FIX: Copy via zeroed buffer to avoid padding info leak
    copy_vfs_stat_to_user(statbuf, &stat)?;

    Ok(0)
}

/// sys_lseek - 移动文件读写偏移
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `offset` - 偏移量
/// * `whence` - 偏移起点：
///   - 0 (SEEK_SET): 从文件开头
///   - 1 (SEEK_CUR): 从当前位置
///   - 2 (SEEK_END): 从文件结尾
///
/// # Returns
/// 成功返回新的偏移位置，失败返回错误码
pub(super) fn sys_lseek(fd: i32, offset: i64, whence: i32) -> SyscallResult {
    // 标准流不支持 seek
    if lookup_console_file(fd)?.is_some() {
        return Err(SyscallError::ESPIPE);
    }

    // 验证 whence 参数
    if whence < 0 || whence > 2 {
        return Err(SyscallError::EINVAL);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R130-2 FIX: Extract file descriptor and release process lock before
    // calling VFS callback. Holding the process lock across the VFS callback
    // creates a lock ordering inversion risk (process lock -> procfs ->
    // PROCESS_TABLE vs. signal delivery PROCESS_TABLE -> process lock).
    // Follows the same pattern as vfs_readdir_callback and vfs_truncate_callback.
    let file_ops = {
        let proc = process.lock();
        let cloned = proc
            .get_fd(fd)
            .ok_or(SyscallError::EBADF)?
            .try_clone_box()
            .map_err(|_| SyscallError::ENOMEM)?;
        cloned
    };
    // Process lock released here — safe for VFS operations

    // 获取 lseek 回调函数
    let lseek_fn = {
        let callback = VFS_LSEEK_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EINVAL)?
    };

    // 通过回调执行 seek 操作
    // 回调函数会尝试将 file_ops 向下转型到 FileHandle 并执行 seek
    match lseek_fn(file_ops.as_any(), offset, whence) {
        Ok(new_offset) => Ok(new_offset as usize),
        Err(e) => Err(e),
    }
}

/// sys_close - 关闭文件描述符
pub(super) fn sys_close(fd: i32, entry_proc: Option<&ProcessArc>) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1030); // sys_close entry
    }

    // R190-16: standard streams are ordinary fd-table entries (ConsoleFile).
    // The close callback removes them like any other descriptor and returns
    // EBADF for an unused number; there is no console special case.
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1032); // sys_close callback path
    }

    // 获取回调函数指针（无锁原子读取）
    let close_fn = get_fd_close_callback().ok_or(SyscallError::EBADF)?;

    // 在锁外执行关闭
    close_fn(fd, entry_proc)?;
    Ok(0)
}

/// sys_ioctl - I/O 控制
///
/// 为 musl libc 提供最小化 stub 实现。
/// musl 会在终端检测时调用 TCGETS 等 ioctl，返回 ENOTTY 表明不是终端。
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `cmd` - ioctl 命令码
/// * `arg` - 命令参数
///
/// # Returns
/// 当前始终返回 ENOTTY（不是终端设备）
pub(super) fn sys_ioctl(fd: i32, cmd: u64, arg: u64) -> SyscallResult {
    let console = lookup_tty_ioctl_target(fd)?;

    // M0-6 SLICE 5+: Basic termios support for stdin/stdout/stderr
    // Common ioctl commands for terminal control
    const TCGETS: u64 = 0x5401; // Get terminal attributes
    const TCSETS: u64 = 0x5402; // Set terminal attributes
    const TCSETSW: u64 = 0x5403; // Set after drain
    const TCSETSF: u64 = 0x5404; // Set after flush
    const TIOCGWINSZ: u64 = 0x5413; // Get window size
    const TIOCSWINSZ: u64 = 0x5414; // Set window size
    const FIONREAD: u64 = 0x541B; // Bytes available to read
                                  // N2.5: Controlling terminal & foreground process group job control ioctls.
    const TIOCSCTTY: u64 = 0x540E; // Make controlling terminal
    const TIOCGPGRP: u64 = 0x540F; // Get foreground process group
    const TIOCSPGRP: u64 = 0x5410; // Set foreground process group
    const TIOCNOTTY: u64 = 0x5422; // Give up controlling terminal
    const TIOCGSID: u64 = 0x5429; // Get session ID of controlling terminal

    match cmd {
        TCGETS if console.is_some() => {
            // Return minimal termios structure for stdin/stdout/stderr
            // struct termios is 60 bytes on x86_64
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            // Zero out termios structure (canonical mode, no special flags)
            let zero_termios = [0u8; 60];
            crate::usercopy::copy_to_user_safe(arg as *mut u8, &zero_termios)
                .map_err(|_| SyscallError::EFAULT)?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF if console.is_some() => {
            // Accept termios settings but don't actually apply them
            // (no real terminal to configure)
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            // Just verify the buffer is readable
            let mut termios_buf = [0u8; 60];
            crate::usercopy::copy_from_user_safe(&mut termios_buf, arg as *const u8)
                .map_err(|_| SyscallError::EFAULT)?;
            Ok(0)
        }
        TIOCGWINSZ if console.is_some() => {
            // Return default window size (80x24)
            // struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel } = 8 bytes (4 u16s)
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let winsize: [u16; 4] = [24, 80, 0, 0]; // rows, cols, xpixel, ypixel
                                                    // lint-repr-c-copy: allow (winsize is [u16;4], no padding, deterministic layout)
            let winsize_bytes =
                unsafe { core::slice::from_raw_parts(winsize.as_ptr() as *const u8, 8) };
            crate::usercopy::copy_to_user_safe(arg as *mut u8, winsize_bytes)
                .map_err(|_| SyscallError::EFAULT)?;
            Ok(0)
        }
        TIOCSWINSZ if console.is_some() => {
            // Accept window size but don't store it
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let mut winsize_buf = [0u8; 8];
            crate::usercopy::copy_from_user_safe(&mut winsize_buf, arg as *const u8)
                .map_err(|_| SyscallError::EFAULT)?;
            Ok(0)
        }
        FIONREAD if console.is_some_and(|readable| readable) => {
            // M0-6 poll/select: report the real count of buffered stdin bytes
            // (non-consuming keyboard probe), consistent with poll(fd0, POLLIN).
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let bytes_available: i32 = drivers::keyboard_available() as i32;
            // lint-repr-c-copy: allow (i32 is a primitive, no padding)
            let bytes_slice = unsafe {
                core::slice::from_raw_parts(&bytes_available as *const i32 as *const u8, 4)
            };
            crate::usercopy::copy_to_user_safe(arg as *mut u8, bytes_slice)
                .map_err(|_| SyscallError::EFAULT)?;
            Ok(0)
        }
        TIOCSCTTY if console.is_some() => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (tgid, sid, pgid, has_ctty) = {
                let p = proc_arc.lock();
                (
                    p.tgid,
                    p.thread_group.sid(),
                    p.thread_group.pgid(),
                    p.thread_group.has_ctty(),
                )
            };
            // Must be a session leader.
            if tgid != sid {
                return Err(SyscallError::EPERM);
            }
            let steal = arg == 1;
            let privileged =
                current_has_cap_rights(cap::CapRights::ADMIN) || crate::current_is_host_root();
            if has_ctty && crate::process::console_tty_get_sid(sid, true).is_ok() {
                return Ok(0);
            }
            crate::process::console_tty_attach(sid, pgid, steal, privileged)?;
            proc_arc.lock().thread_group.set_has_ctty(true);
            Ok(0)
        }
        TIOCNOTTY if console.is_some() => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (tgid, sid, has_ctty) = {
                let p = proc_arc.lock();
                (p.tgid, p.thread_group.sid(), p.thread_group.has_ctty())
            };
            // Verify this console is indeed the caller's controlling terminal.
            let _ = crate::process::console_tty_get_sid(sid, has_ctty)?;
            proc_arc.lock().thread_group.set_has_ctty(false);
            if tgid == sid {
                if let Some(old_fg) = crate::process::console_tty_release_session(sid) {
                    // POSIX: notify former foreground process group with SIGHUP + SIGCONT.
                    let _ = send_signal_to_pgid_kernel(old_fg, crate::signal::Signal::SIGHUP);
                    let _ = send_signal_to_pgid_kernel(old_fg, crate::signal::Signal::SIGCONT);
                }
            }
            Ok(0)
        }
        TIOCGPGRP if console.is_some() => {
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (sid, has_ctty, owning_ns) = {
                let p = proc_arc.lock();
                (
                    p.thread_group.sid(),
                    p.thread_group.has_ctty(),
                    crate::pid_namespace::owning_namespace(&p.pid_ns_chain),
                )
            };
            let fg_global = crate::process::console_tty_get_fg_pgid(sid, has_ctty)?;
            let fg_view = match owning_ns {
                Some(ns) => ns.lookup_ns_pid(fg_global).unwrap_or(0) as i32,
                None => fg_global as i32,
            };
            copy_to_user(arg as *mut u8, &fg_view.to_ne_bytes())?;
            Ok(0)
        }
        TIOCSPGRP if console.is_some() => {
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let mut raw = [0u8; 4];
            copy_from_user(&mut raw, arg as *const u8)?;
            let req_pgid = i32::from_ne_bytes(raw);
            if req_pgid <= 0 {
                return Err(SyscallError::EINVAL);
            }
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (sid, has_ctty, owning_ns) = {
                let p = proc_arc.lock();
                (
                    p.thread_group.sid(),
                    p.thread_group.has_ctty(),
                    crate::pid_namespace::owning_namespace(&p.pid_ns_chain),
                )
            };
            // Verify caller has console ctty first.
            let _ = crate::process::console_tty_get_sid(sid, has_ctty)?;
            let target_global_pgid = match owning_ns {
                Some(ns) => {
                    crate::pid_namespace::resolve_pid_in_namespace(&ns, req_pgid as ProcessId)
                        .ok_or(SyscallError::EPERM)?
                }
                None => req_pgid as ProcessId,
            };
            if !crate::process::pgid_exists_in_session(target_global_pgid, sid) {
                return Err(SyscallError::EPERM);
            }
            crate::process::console_tty_set_fg_pgid(sid, has_ctty, target_global_pgid)?;
            Ok(0)
        }
        TIOCGSID if console.is_some() => {
            if arg == 0 {
                return Err(SyscallError::EFAULT);
            }
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (sid, has_ctty, owning_ns) = {
                let p = proc_arc.lock();
                (
                    p.thread_group.sid(),
                    p.thread_group.has_ctty(),
                    crate::pid_namespace::owning_namespace(&p.pid_ns_chain),
                )
            };
            let tty_sid = crate::process::console_tty_get_sid(sid, has_ctty)?;
            let view_sid = match owning_ns {
                Some(ns) => ns.lookup_ns_pid(tty_sid).unwrap_or(0) as i32,
                None => tty_sid as i32,
            };
            copy_to_user(arg as *mut u8, &view_sid.to_ne_bytes())?;
            Ok(0)
        }
        _ => {
            // For non-standard streams or unknown commands, return ENOTTY
            Err(SyscallError::ENOTTY)
        }
    }
}

// ============================================================================
// 文件系统附加系统调用
// ============================================================================

/// sys_getcwd - 获取当前工作目录
///
/// Walk the process's owned root/cwd bindings and copy the exact NUL-terminated path.
pub(super) fn sys_getcwd(buf: *mut u8, size: usize) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut cwd = (crate::fs_context::callbacks()?.getcwd)()?;
    let count = cwd.len().checked_add(1).ok_or(SyscallError::ERANGE)?;
    if size < count {
        return Err(SyscallError::ERANGE);
    }
    cwd.try_reserve_exact(1).map_err(|_| SyscallError::ENOMEM)?;
    cwd.push('\0');
    copy_to_user(buf, cwd.as_bytes())?;
    Ok(count)
}

pub(super) fn sys_chdir(path: *const u8) -> SyscallResult {
    sys_change_directory(path, false)
}

pub(super) fn sys_chroot(path: *const u8) -> SyscallResult {
    sys_change_directory(path, true)
}

pub(super) fn sys_pivot_root(new_root: *const u8, put_old: *const u8) -> SyscallResult {
    if new_root.is_null() || put_old.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let new_bytes =
        crate::usercopy::copy_user_cstring(new_root).map_err(|_| SyscallError::EFAULT)?;
    let old_bytes =
        crate::usercopy::copy_user_cstring(put_old).map_err(|_| SyscallError::EFAULT)?;
    let new_name = core::str::from_utf8(&new_bytes).map_err(|_| SyscallError::EINVAL)?;
    let old_name = core::str::from_utf8(&old_bytes).map_err(|_| SyscallError::EINVAL)?;
    (crate::fs_context::callbacks()?.pivot_root)(new_name, old_name)?;
    Ok(0)
}

pub(super) fn sys_change_directory(path: *const u8, root: bool) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path = core::str::from_utf8(&bytes).map_err(|_| SyscallError::EINVAL)?;
    (crate::fs_context::callbacks()?.change_directory)(path, root)?;
    Ok(0)
}

/// sys_mkdir - 创建目录
pub(super) fn sys_mkdir(path: *const u8, mode: u32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // R172-X-F4: the syscall-layer path-hash LSM prehook is REMOVED. VFS Manager::create
    // fires hook_file_mkdir ONCE with the REVALIDATED parent inode (manager.rs:1136, under
    // the create lock) — a coherent inode-keyed MAC object the syscall layer (no lookup /
    // lock / inode context) could only approximate with a path-hash, yielding an incoherent
    // double-keyed decision + a double audit-emit on denial. A denial now surfaces as the
    // VFS error (FsError::PermDenied -> EACCES), matching create/open post-R105-1.
    let create_fn = VFS_CREATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    create_fn(path_str, mode & 0o7777, true)?;
    Ok(0)
}

/// sys_rmdir - 删除空目录
pub(super) fn sys_rmdir(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // R172-X-F4-FOLLOWON: the POSIX dir-vs-file gate is NO LONGER a separate syscall-layer
    // stat(path) (which raced the actual removal — a file<->dir swap between the stat and the
    // unlink could make rmdir remove a file). It is folded into the VFS unlink contract via
    // `must_be_dir = Some(true)`, enforced against the FINAL revalidated inode ATOMICALLY with
    // the removal (manager.rs -> fs.unlink). ENOTDIR is preserved via FsError::NotDir. The MAC
    // gate (hook_file_rmdir) still fires ONCE in Manager::unlink with the revalidated parent
    // inode (R172-X-F4).
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str, Some(true))?;
    Ok(0)
}

/// sys_link - 创建硬链接
///
/// M0-6 SLICE 4: Hard link stub (not supported in current VFS).
///
/// # Arguments
///
/// * `oldpath` - 源文件路径
/// * `newpath` - 新链接路径
///
/// # Returns
///
/// EPERM (hard links not supported yet)
pub(super) fn sys_link(oldpath: *const u8, newpath: *const u8) -> SyscallResult {
    // R173-09 FIX: Return EPERM immediately after null check
    // Skip usercopy validation for unimplemented stub (low-priority efficiency fix)
    if oldpath.is_null() || newpath.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Hard links require:
    // 1. VFS inode link count tracking
    // 2. ramfs/ext2 support for multiple directory entries pointing to same inode
    // 3. Proper handling of link count in unlink/rmdir
    //
    // TODO: Implement when VFS gains hard link support
    Err(SyscallError::EPERM)
}

/// sys_symlink - create symbolic link
///
/// # M0-6 SLICE 3 - DEFERRED per plan
///
/// Blocked on:
/// 1. ramfs lacks Symlink NodeKind (only File/Directory)
/// 2. /proc/self is contradictory (is_dir()==true but file_type==Symlink)
/// 3. readlink resolver broken (lookup_path_with_flags(..,false) returns ELOOP for final symlink)
///
/// The readlink-resolver fix + ramfs Symlink node land together as one coherent change.
pub(super) fn sys_symlink(target: *const u8, linkpath: *const u8) -> SyscallResult {
    // M0-6 SLICE 3: Create symbolic link
    if target.is_null() || linkpath.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 1. Copy both paths from userspace (SMAP-safe)
    let target_bytes =
        crate::usercopy::copy_user_cstring(target).map_err(|_| SyscallError::EFAULT)?;
    let target_str = core::str::from_utf8(&target_bytes).map_err(|_| SyscallError::EINVAL)?;

    let linkpath_bytes =
        crate::usercopy::copy_user_cstring(linkpath).map_err(|_| SyscallError::EFAULT)?;
    let linkpath_str = core::str::from_utf8(&linkpath_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 2. Call VFS symlink callback
    let symlink_fn = VFS_SYMLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    symlink_fn(linkpath_str, target_str)?;

    Ok(0)
}

/// sys_readlink - read value of symbolic link
///
/// # M0-6 SLICE 3 - DEFERRED per plan
///
/// Blocked on same issues as sys_symlink (see above).
pub(super) fn sys_readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> SyscallResult {
    // M0-6 SLICE 3: Read symbolic link target
    if path.is_null() || buf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // SYM-READLINK-BUFSIZ-ZERO fix: Linux readlink(2) requires bufsiz > 0.
    // A zero-sized buffer is EINVAL, not a no-op that returns 0.
    if bufsiz == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 1. Copy path from userspace (SMAP-safe)
    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 2. Call VFS readlink callback to get target
    let readlink_fn = VFS_READLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let target = readlink_fn(path_str)?;

    // 3. Copy to userspace (truncate if needed, NO null terminator per POSIX)
    let copy_len = target.len().min(bufsiz);
    if copy_len > 0 {
        let target_bytes = target.as_bytes();
        crate::usercopy::copy_to_user_safe(buf, &target_bytes[..copy_len])
            .map_err(|_| SyscallError::EFAULT)?;
    }

    Ok(copy_len)
}

/// sys_unlink - 删除文件
pub(super) fn sys_unlink(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // R172-X-F4-FOLLOWON: the "不允许删除目录 (应使用rmdir)" gate is NO LONGER a separate
    // syscall-layer stat(path) (which raced the actual removal — a file<->dir swap between the
    // stat and the unlink could make unlink remove a directory). It is folded into the VFS
    // unlink contract via `must_be_dir = Some(false)`, enforced against the FINAL revalidated
    // inode ATOMICALLY with the removal. EISDIR is preserved via FsError::IsDir. The MAC gate
    // (hook_file_unlink) still fires ONCE in Manager::unlink (R172-X-F4).
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str, Some(false))?;
    Ok(0)
}

// ===== M0-6 slice 2: rename(82) / renameat(264) / renameat2(316) =====

/// renameat2 flags (Linux). Only RENAME_NOREPLACE is implemented this slice.
pub(super) const RENAME_NOREPLACE: u32 = 1;
pub(super) const RENAME_EXCHANGE: u32 = 2;
pub(super) const RENAME_WHITEOUT: u32 = 4;

/// Copy both rename pathnames from user space (EFAULT on null/bad ptr).
///
/// M0 path-length note: `copy_user_cstring` caps at `MAX_CSTRING_LEN` (4096) and returns a
/// generic Err for "no NUL within 4096 bytes", which is indistinguishable from a bad
/// pointer, so a whole-path that exceeds PATH_MAX surfaces here as EFAULT (not
/// ENAMETOOLONG) — a documented divergence shared by EVERY path syscall (open/stat/unlink/
/// …). A per-COMPONENT name > 255 bytes still surfaces as ENAMETOOLONG via the fs mapper.
pub(super) fn copy_rename_paths(
    oldp: *const u8,
    newp: *const u8,
) -> Result<(Vec<u8>, Vec<u8>), SyscallError> {
    if oldp.is_null() || newp.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let old_bytes = crate::usercopy::copy_user_cstring(oldp).map_err(|_| SyscallError::EFAULT)?;
    let new_bytes = crate::usercopy::copy_user_cstring(newp).map_err(|_| SyscallError::EFAULT)?;
    Ok((old_bytes, new_bytes))
}

/// Shared rename core: copy the pathnames then invoke the VFS rename callback. R172-X-F4:
/// the rename MAC decision lives ONLY at the VFS layer (Manager::rename, keyed on the
/// REVALIDATED parent inodes under RAMFS_RENAME_LOCK — the coherent inode-identity object,
/// consistent with the R172-15 bind). The former syscall-layer path-hash prehook
/// double-keyed the decision (incoherent vs the VFS ino key) and double-emitted the audit
/// record on denial; a denial now surfaces as the VFS error (EACCES).
pub(super) fn do_rename_str(old_str: &str, new_str: &str, noreplace: bool) -> SyscallResult {
    let rename_fn = VFS_RENAME_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    rename_fn(old_str, new_str, noreplace)?;
    Ok(0)
}

/// sys_rename(82): relative paths use the process's owned cwd.
pub(super) fn sys_rename(oldp: *const u8, newp: *const u8) -> SyscallResult {
    let (old_bytes, new_bytes) = copy_rename_paths(oldp, newp)?;
    let old_str = core::str::from_utf8(&old_bytes).map_err(|_| SyscallError::EINVAL)?;
    let new_str = core::str::from_utf8(&new_bytes).map_err(|_| SyscallError::EINVAL)?;
    do_rename_str(old_str, new_str, false)
}

/// Absolute paths ignore dirfd. Relative AT_FDCWD paths use the stored cwd;
/// other dirfd-relative combinations remain explicitly unsupported.
pub(super) fn rename_at_paths_supported(
    old_dirfd: i32,
    old_str: &str,
    new_dirfd: i32,
    new_str: &str,
) -> Result<(), SyscallError> {
    if (!old_str.starts_with('/') && old_dirfd != AT_FDCWD)
        || (!new_str.starts_with('/') && new_dirfd != AT_FDCWD)
    {
        return Err(SyscallError::EOPNOTSUPP);
    }
    Ok(())
}

/// sys_renameat(264).
pub(super) fn sys_renameat(
    _olddirfd: i32,
    oldp: *const u8,
    _newdirfd: i32,
    newp: *const u8,
) -> SyscallResult {
    let (old_bytes, new_bytes) = copy_rename_paths(oldp, newp)?;
    let old_str = core::str::from_utf8(&old_bytes).map_err(|_| SyscallError::EINVAL)?;
    let new_str = core::str::from_utf8(&new_bytes).map_err(|_| SyscallError::EINVAL)?;
    rename_at_paths_supported(_olddirfd, old_str, _newdirfd, new_str)?;
    do_rename_str(old_str, new_str, false)
}

/// sys_renameat2(316). RENAME_NOREPLACE implemented; EXCHANGE/WHITEOUT/unknown-bit => EINVAL.
pub(super) fn sys_renameat2(
    _olddirfd: i32,
    oldp: *const u8,
    _newdirfd: i32,
    newp: *const u8,
    flags: u32,
) -> SyscallResult {
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        return Err(SyscallError::EINVAL); // unknown flag bit
    }
    if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        return Err(SyscallError::EINVAL); // unimplemented (also rejects NOREPLACE|EXCHANGE)
    }
    let noreplace = flags & RENAME_NOREPLACE != 0;
    let (old_bytes, new_bytes) = copy_rename_paths(oldp, newp)?;
    let old_str = core::str::from_utf8(&old_bytes).map_err(|_| SyscallError::EINVAL)?;
    let new_str = core::str::from_utf8(&new_bytes).map_err(|_| SyscallError::EINVAL)?;
    rename_at_paths_supported(_olddirfd, old_str, _newdirfd, new_str)?;
    do_rename_str(old_str, new_str, noreplace)
}

/// sys_access - 检查文件访问权限
///
/// mode: R_OK(4) | W_OK(2) | X_OK(1) | F_OK(0)
pub(super) fn sys_access(path: *const u8, mode: i32) -> SyscallResult {
    if mode & !7 != 0 {
        return Err(SyscallError::EINVAL);
    }
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;
    (crate::fs_context::callbacks()?.access)(path_str, mode)?;
    Ok(0)
}

/// sys_lstat - 获取符号链接状态
///
/// M0-6 SLICE 3: lstat now stats the LINK itself (no-follow), not its target.
/// Falls back to sys_stat only if the no-follow callback is unregistered (e.g.
/// pre-VFS-init), preserving prior behavior.
pub(super) fn sys_lstat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    if path.is_null() || statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?
    };

    sys_lstat_internal(&path_str, statbuf)
}

/// Shared lstat core: no-follow stat with fall-back to follow-stat if the
/// no-follow callback is not registered.
pub(super) fn sys_lstat_internal(path_str: &str, statbuf: *mut VfsStat) -> SyscallResult {
    let nofollow = *VFS_STAT_NOFOLLOW_CALLBACK.lock();
    match nofollow {
        Some(cb) => {
            let stat = cb(path_str)?;
            // R113-1 padding-safe copy (same as sys_stat_internal).
            copy_vfs_stat_to_user(statbuf, &stat)?;
            Ok(0)
        }
        // No-follow unavailable (pre-init): fall back to follow-stat.
        None => sys_stat_internal(path_str, statbuf),
    }
}

/// sys_fstatat - 相对路径stat
///
/// 当前仅支持AT_FDCWD或绝对路径。
///
/// # R154-8 FIX: AT_SYMLINK_NOFOLLOW documentation
/// The `flags` parameter (including AT_SYMLINK_NOFOLLOW = 0x100) is currently
/// ignored because the VFS does not implement symbolic links. When symlink
/// support is added, this function must inspect `flags` and branch on
/// AT_SYMLINK_NOFOLLOW to lstat() the link itself rather than its target.
///
/// # R96-5 FIX: TOCTOU Protection
/// Copies the entire path once and uses the kernel copy for both the
/// check and the actual operation, eliminating the window where an
/// attacker could modify the path between check and use.
pub(super) fn sys_fstatat(
    dirfd: i32,
    path: *const u8,
    statbuf: *mut VfsStat,
    flags: i32,
) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // M0-6 SLICE 3: Validate flags (only AT_SYMLINK_NOFOLLOW is defined).
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(SyscallError::EINVAL);
    }

    // R96-5 FIX: Copy the entire path once to eliminate TOCTOU window.
    // Previously we copied only the first byte, then called sys_stat which
    // would copy the path again. An attacker could modify the path between
    // the two copies.
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?
    };

    // Check from kernel copy - no TOCTOU possible
    let first_byte = path_str.as_bytes().first().copied().unwrap_or(0);
    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        return Err(SyscallError::EOPNOTSUPP);
    }

    // M0-6 SLICE 3: Honor AT_SYMLINK_NOFOLLOW — route to lstat when set,
    // otherwise route to stat (follow symlinks).
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        sys_lstat_internal(&path_str, statbuf)
    } else {
        sys_stat_internal(&path_str, statbuf)
    }
}

/// sys_statx - extended file status (modern stat interface)
///
/// # M0-6 SLICE 5+ Implementation
/// Minimal stub returning ENOSYS. Full statx provides:
/// - Extended attributes (birth time, mount ID, inode flags)
/// - Fine-grained control over what's returned (mask parameter)
/// - Better timestamp precision (nanoseconds)
///
/// # Arguments
/// - `dirfd`: directory fd for relative paths (AT_FDCWD for current)
/// - `pathname`: path to stat
/// - `flags`: AT_* flags (AT_SYMLINK_NOFOLLOW, AT_STATX_SYNC_*, etc.)
/// - `mask`: STATX_* mask for what fields to return
/// - `statxbuf`: pointer to struct statx (256 bytes)
pub(super) fn sys_statx(
    _dirfd: i32,
    _pathname: *const u8,
    _flags: i32,
    _mask: u32,
    _statxbuf: *mut u8,
) -> SyscallResult {
    // M0-6: statx is the modern stat interface used by new code
    // For M0 compatibility, programs fall back to fstatat/stat
    // Full implementation would:
    // 1. Parse AT_* flags and STATX_* mask
    // 2. Lookup path (with/without symlink following per flags)
    // 3. Fill struct statx (256 bytes) with requested fields
    // 4. Include extended attributes (btime, mount_id, inode_flags)
    Err(SyscallError::ENOSYS)
}

/// sys_openat - 相对路径打开文件
///
/// 当前仅支持AT_FDCWD或绝对路径。
///
/// # R96-5 FIX: TOCTOU Protection
/// Copies the entire path once and uses the kernel copy for both the
/// check and the actual operation, eliminating the window where an
/// attacker could modify the path between check and use.
pub(super) fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R96-5 FIX: Copy the entire path once to eliminate TOCTOU window.
    // Previously we copied only the first byte, then called sys_open which
    // would copy the path again. An attacker could modify the path between
    // the two copies.
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?
    };

    // Check from kernel copy - no TOCTOU possible
    let first_byte = path_str.as_bytes().first().copied().unwrap_or(0);
    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        return Err(SyscallError::EOPNOTSUPP);
    }

    // Use internal helper with already-copied path
    sys_open_internal(&path_str, flags, mode)
}

/// sys_openat2 - open with extended flags and resolve options (Linux 5.6+)
///
/// # Arguments
/// * `dirfd` - Base directory fd (AT_FDCWD for current directory)
/// * `path` - File path (user space pointer)
/// * `how` - Pointer to struct open_how (flags, mode, resolve)
/// * `size` - Size of the open_how structure
///
/// # Returns
/// File descriptor on success, error code on failure
///
/// # Security
/// - RESOLVE_NO_SYMLINKS: Reject any symlink in path (ELOOP)
/// - RESOLVE_BENEATH: Reject paths escaping starting point (EXDEV)
/// - RESOLVE_NO_MAGICLINKS: Block /proc magic symlinks (ELOOP)
/// - RESOLVE_NO_XDEV: Don't cross mount boundaries (EXDEV)
pub(super) fn sys_openat2(
    dirfd: i32,
    path: *const u8,
    how: *const OpenHow,
    size: usize,
) -> SyscallResult {
    use crate::usercopy::{copy_from_user, copy_user_cstring, UserPtr};

    // Validate pointers
    if path.is_null() || how.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Validate size (must be at least as large as our struct)
    if size < core::mem::size_of::<OpenHow>() {
        return Err(SyscallError::EINVAL);
    }

    // Copy open_how from user space
    let mut how_local = OpenHow::default();
    let how_ptr = UserPtr::<OpenHow>::new(how as *mut OpenHow).map_err(|_| SyscallError::EFAULT)?;
    copy_from_user(&mut how_local, how_ptr).map_err(|_| SyscallError::EFAULT)?;

    // Copy path from user space
    let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    if path_bytes.is_empty() {
        return Err(SyscallError::EINVAL);
    }
    let path_str =
        try_str_to_string(core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?)?;

    // Get current process
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R65-22 FIX: Handle dirfd for relative paths
    // Resolve relative paths against the directory referenced by dirfd
    // R164-3 FIX: Use fallible allocation for resolved path construction.
    // R165-5 FIX: Move (not clone) path_str on the absolute-path arm. The prior
    // `path_str.clone()` was an infallible String allocation of up to
    // MAX_ARG_STRLEN+1 = 4097 user-controlled bytes — an OOM-time kernel panic.
    // path_str is not used after this if/else, so the move is sound.
    let resolved_path = if path_str.starts_with('/') || dirfd == AT_FDCWD {
        path_str
    } else {
        let fd = {
            let proc = process.lock();
            let cloned = proc
                .get_fd(dirfd)
                .ok_or(SyscallError::EBADF)?
                .try_clone_box()
                .map_err(|_| SyscallError::ENOMEM)?;
            cloned
        };
        if !is_directory_mode(fd.stat()?.mode) {
            return Err(SyscallError::ENOTDIR);
        }
        return Err(SyscallError::EOPNOTSUPP);
    };

    // R65-22 FIX: Validate RESOLVE_BENEATH/RESOLVE_IN_ROOT constraints
    // These flags should confine path resolution to the anchor directory.
    // Without proper dirfd tracking, we cannot fully enforce these flags for
    // non-AT_FDCWD dirfd, so we reject such combinations.
    //
    // R72-ENOSYS FIX: Return EINVAL instead of ENOSYS. The syscall exists but
    // this specific flag combination is invalid for our current implementation.
    let resolve = how_local.resolve;
    if dirfd != AT_FDCWD && (resolve & 0x08 != 0 || resolve & 0x10 != 0) {
        // RESOLVE_BENEATH (0x08) or RESOLVE_IN_ROOT (0x10) with non-AT_FDCWD dirfd
        // Cannot properly enforce without fd_path tracking
        return Err(SyscallError::EINVAL);
    }

    // Validate flags: reject unknown flags
    let known_flags: u64 = 0o17777777; // All valid O_* flags
    if how_local.flags & !known_flags != 0 {
        return Err(SyscallError::EINVAL);
    }

    // Validate resolve: reject unknown resolve flags
    let known_resolve: u64 = 0x3F; // RESOLVE_NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH | IN_ROOT | CACHED
    if how_local.resolve & !known_resolve != 0 {
        return Err(SyscallError::EINVAL);
    }

    let open_flags = how_local.flags as u32;
    let mode = how_local.mode as u32;
    // Note: `resolve` already defined above for R65-22 validation

    // R105-1 FIX: Removed duplicate LSM hooks — VFS layer enforces
    // hook_file_create and hook_file_open with real inode context.
    // See sys_open_internal R105-1 comment for rationale.

    // RF186-7: serialize credential mutation against the full resolve/open and
    // publication span, including create/truncate side effects.
    let credentials = process.lock().shared_credentials();
    let credential_authorization = credentials.begin_authorization();
    let cred_gen_before = credentials.generation();

    // Get VFS callback with resolve support
    let open_fn = {
        let callback = VFS_OPEN_WITH_RESOLVE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // R180-23: admit FD slot + files.max before resolve/open can create or
    // truncate. The reservation remains invisible to guessed FD lookups.
    let fd_reservation =
        FdPublicationReservation::try_new(process.clone(), open_flags & 0x80000 != 0)?;

    let prepared = open_fn(
        &resolved_path,
        open_flags,
        mode,
        resolve,
        &credential_authorization,
    )?;
    publish_prepared_open(
        &process,
        open_flags,
        prepared,
        fd_reservation,
        credential_authorization,
        cred_gen_before,
    )
}

// ============================================================================
// 文件描述符操作系统调用
// ============================================================================

/// sys_dup - 复制文件描述符
pub(super) fn sys_dup(oldfd: i32) -> SyscallResult {
    if oldfd < 0 {
        return Err(SyscallError::EBADF);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let cloned = proc
        .get_fd(oldfd)
        .ok_or(SyscallError::EBADF)?
        .try_clone_box()
        .map_err(|_| SyscallError::ENOMEM)?;
    let newfd = match proc.allocate_fd_with_cloexec(cloned, false) {
        Ok(fd) => fd,
        Err(rejected) => {
            // A descriptor destructor may acquire socket/waiter locks.
            drop(proc);
            drop(rejected);
            return Err(SyscallError::EMFILE);
        }
    };
    // U.S3-A3 FIX: the new fd shares oldfd's CapId, so bump the CapEntry
    // refcount HERE, under the already-held Process lock, AFTER the install
    // succeeded — never inside clone_box (U.S3-A2 self-deadlock). Failure
    // (InvalidCapId) means a CLONE_THREAD sibling sharing this cap_table
    // revoked the cap between clone and install; the dup then carries a
    // documented dead handle (ops fail, close is a no-op decrement) — same
    // accepted race class as clone_box's dead-socket note above.
    if let Some(cid) = proc.get_fd(newfd).and_then(|d| d.cap_id()) {
        proc.capability_increment_refcount(cid);
    }
    Ok(newfd as usize)
}

/// sys_dup2 - 复制文件描述符到指定位置
pub(super) fn sys_dup2(oldfd: i32, newfd: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    // R141-3 FIX: Reject newfd >= MAX_FD to prevent unbounded fd_table growth.
    // allocate_fd() enforces MAX_FD for sys_dup/sys_open, but dup2 accepts an
    // arbitrary newfd — without this gate a user can dup2(fd, 1_000_000) and
    // grow the per-process BTreeMap in kernel heap without limit (local OOM DoS).
    if newfd >= crate::process::MAX_FD {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        // 验证oldfd有效
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
        return Ok(newfd as usize);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R155-3 FIX: Extract old fd under lock, drop OUTSIDE to prevent
    // lock inversion (Process → SocketFile::drop → waiters → Process).
    let old_fd_entry = {
        let mut proc = proc_arc.lock();
        if newfd >= proc.effective_fd_limit() {
            return Err(SyscallError::EBADF);
        }
        let cloned = proc
            .get_fd(oldfd)
            .ok_or(SyscallError::EBADF)?
            .try_clone_box()
            .map_err(|_| SyscallError::ENOMEM)?;
        // J2-7: net-aware, fail-closed FD accounting (replaces remove_fd+insert):
        // empty newfd → charge +1 (EMFILE on over-budget, table untouched);
        // occupied newfd → net 0, reuses the replaced entry's charge.
        // (replace_fd_charged also pays back the DISPLACED entry's cap
        // refcount — U.S3-B.)
        let displaced = match proc.replace_fd_charged_with_cloexec(newfd, cloned, false) {
            Ok(displaced) => displaced,
            Err(rejected) => {
                drop(proc);
                drop(rejected);
                return Err(SyscallError::EMFILE);
            }
        };
        // U.S3-A3 FIX: bump the shared CapEntry refcount for the installed
        // copy, under the held Process lock (see sys_dup for the failure-race
        // note).
        if let Some(cid) = proc.get_fd(newfd).and_then(|d| d.cap_id()) {
            proc.capability_increment_refcount(cid);
        }
        displaced
    };
    drop(old_fd_entry);

    Ok(newfd as usize)
}

/// sys_dup3 - 复制文件描述符(带flags)
///
/// flags: O_CLOEXEC(0x80000)
pub(super) fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        return Err(SyscallError::EINVAL);
    }

    // R141-3 FIX: Reject newfd >= MAX_FD (same gate as sys_dup2 above).
    if newfd >= crate::process::MAX_FD {
        return Err(SyscallError::EBADF);
    }

    // 仅接受O_CLOEXEC标志
    const O_CLOEXEC: i32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        return Err(SyscallError::EINVAL);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R155-3 FIX: Extract old fd under lock, drop OUTSIDE to prevent
    // lock inversion (Process → SocketFile::drop → waiters → Process).
    let old_fd_entry = {
        let mut proc = proc_arc.lock();
        if newfd >= proc.effective_fd_limit() {
            return Err(SyscallError::EBADF);
        }
        let cloned = proc
            .get_fd(oldfd)
            .ok_or(SyscallError::EBADF)?
            .try_clone_box()
            .map_err(|_| SyscallError::ENOMEM)?;
        // J2-7: net-aware, fail-closed FD accounting (replaces remove_fd+insert).
        // replace_fd_charged clears CLOEXEC on newfd; re-set it below if requested.
        // (It also pays back the DISPLACED entry's cap refcount — U.S3-B.)
        let removed =
            match proc.replace_fd_charged_with_cloexec(newfd, cloned, flags & O_CLOEXEC != 0) {
                Ok(removed) => removed,
                Err(rejected) => {
                    drop(proc);
                    drop(rejected);
                    return Err(SyscallError::EMFILE);
                }
            };

        // U.S3-A3 FIX: bump the shared CapEntry refcount for the installed
        // copy, under the held Process lock (see sys_dup for the failure-race
        // note).
        if let Some(cid) = proc.get_fd(newfd).and_then(|d| d.cap_id()) {
            proc.capability_increment_refcount(cid);
        }

        removed
    };
    drop(old_fd_entry);

    Ok(newfd as usize)
}

/// sys_ftruncate - 截断文件
pub(super) fn sys_ftruncate(fd: i32, length: i64) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if length < 0 {
        return Err(SyscallError::EINVAL);
    }

    // 通过回调执行截断
    let truncate_fn = VFS_TRUNCATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    truncate_fn(fd, length as u64)?;
    Ok(0)
}

/// ST-K4: copy the callbacks out so no registry lock is held across device I/O.
pub(super) fn durability_callbacks() -> Result<VfsDurabilityCallbacks, SyscallError> {
    VFS_DURABILITY_CALLBACKS.lock().ok_or(SyscallError::ENOSYS)
}

/// fsync(2): returns 0 only after a device barrier the device can stand behind.
pub(super) fn sys_fsync(fd: i32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1303); // sys_fsync entry
    }
    (durability_callbacks()?.fsync)(fd)?;
    Ok(0)
}

/// fdatasync(2): identical to fsync under write-through, where metadata commits
/// before write() returns.
pub(super) fn sys_fdatasync(fd: i32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1304); // sys_fdatasync entry
    }
    (durability_callbacks()?.fsync)(fd)?;
    Ok(0)
}

/// sync(2) over the caller's mount namespace. Unlike Linux it reports failure;
/// libc's `sync()` returns void, so only raw callers can see the difference.
pub(super) fn sys_sync() -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1305); // sys_sync entry
    }
    (durability_callbacks()?.sync)()?;
    Ok(0)
}

/// sync_file_range(2). As on Linux this is not a durability barrier; under
/// write-through the range is already on the device.
pub(super) fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1306); // sys_sync_file_range entry
    }
    (durability_callbacks()?.sync_file_range)(fd, offset, nbytes, flags)?;
    Ok(0)
}

/// sys_chmod - 修改文件权限
///
/// 当前VFS不支持chmod操作。
///
/// # R72-ENOSYS FIX
/// Returns EOPNOTSUPP instead of ENOSYS since the syscall IS implemented,
/// but the operation is not supported by the current VFS backend.
pub(super) fn sys_chmod(_path: *const u8, _mode: u32) -> SyscallResult {
    // VFS trait未提供chmod方法
    Err(SyscallError::EOPNOTSUPP)
}

/// sys_fchmod - 修改文件权限(通过fd)
///
/// 当前VFS不支持chmod操作。
///
/// # R72-ENOSYS FIX
/// Returns EOPNOTSUPP instead of ENOSYS since the syscall IS implemented,
/// but the operation is not supported by the current VFS backend.
pub(super) fn sys_fchmod(_fd: i32, _mode: u32) -> SyscallResult {
    Err(SyscallError::EOPNOTSUPP)
}

/// sys_umask - 设置文件创建掩码
pub(super) fn sys_umask(mask: u32) -> SyscallResult {
    let old = crate::set_current_umask((mask & 0o777) as u16).ok_or(SyscallError::ESRCH)?;
    Ok(old as usize)
}

/// sys_getdents64 - 读取目录项
pub(super) fn linux_dirent64_record_len(entry: &DirEntry) -> Result<usize, SyscallError> {
    let reclen = LINUX_DIRENT64_NAME_OFFSET
        .checked_add(entry.name.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(7))
        .map(|value| value & !7)
        .ok_or(SyscallError::EINVAL)?;
    if reclen > u16::MAX as usize {
        return Err(SyscallError::EINVAL);
    }
    Ok(reclen)
}

pub(super) fn serialize_dirent_prefix(
    entries: &[DirEntry],
    wire: &mut [u8],
) -> Result<usize, SyscallError> {
    let mut written = 0usize;
    for entry in entries {
        let name = entry.name.as_bytes();
        let reclen = linux_dirent64_record_len(entry)?;
        let next = written.checked_add(reclen).ok_or(SyscallError::EINVAL)?;
        if next > wire.len() {
            break;
        }
        let d_type = match entry.file_type {
            FileType::Regular => 8,
            FileType::Directory => 4,
            FileType::CharDevice => 2,
            FileType::BlockDevice => 6,
            FileType::Symlink => 10,
            FileType::Fifo => 1,
            FileType::Socket => 12,
        };
        let record = &mut wire[written..next];
        record[0..8].copy_from_slice(&entry.ino.to_ne_bytes());
        // RF180-14 FIX: d_off is an opaque filesystem resume cookie.
        record[8..16].copy_from_slice(&entry.next_cookie.to_ne_bytes());
        record[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        record[18] = d_type;
        let name_start = LINUX_DIRENT64_NAME_OFFSET;
        record[name_start..name_start + name.len()].copy_from_slice(name);
        record[name_start + name.len()] = 0;
        written = next;
    }
    Ok(written)
}

pub(super) fn copy_dirents_to_user(
    dirp: *mut u8,
    count: usize,
    entries: &[DirEntry],
) -> Result<usize, SyscallError> {
    let mut total = 0usize;
    let mut included = 0usize;
    for entry in entries {
        let next = total
            .checked_add(linux_dirent64_record_len(entry)?)
            .ok_or(SyscallError::EINVAL)?;
        if next > count {
            break;
        }
        total = next;
        included += 1;
    }
    if total == 0 {
        return Ok(0);
    }

    // One zeroed wire buffer and one fault-tolerant copyout: directory offset
    // publication remains entirely after this operation in the VFS callback.
    let mut wire = try_admitted_zeroed_io_buffer(total)?;

    let written = serialize_dirent_prefix(&entries[..included], &mut wire)?;

    copy_to_user(dirp, &wire)?;
    Ok(written)
}

#[cfg(test)]
mod getdents_cookie_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rf180_14_serializes_non_unit_resume_cookies_across_calls() {
        let entries = [
            DirEntry {
                name: "first".into(),
                ino: 11,
                file_type: FileType::Regular,
                next_cookie: 0x1_0000,
            },
            DirEntry {
                name: "second".into(),
                ino: 12,
                file_type: FileType::Directory,
                next_cookie: 0x7fff_1234,
            },
        ];
        let first_len = linux_dirent64_record_len(&entries[0]).unwrap();
        let mut first_call = vec![0u8; first_len];
        assert_eq!(
            serialize_dirent_prefix(&entries, &mut first_call).unwrap(),
            first_len
        );
        assert_eq!(
            i64::from_ne_bytes(first_call[8..16].try_into().unwrap()),
            entries[0].next_cookie
        );

        let second_len = linux_dirent64_record_len(&entries[1]).unwrap();
        let mut second_call = vec![0u8; second_len];
        assert_eq!(
            serialize_dirent_prefix(&entries[1..], &mut second_call).unwrap(),
            second_len
        );
        assert_eq!(
            i64::from_ne_bytes(second_call[8..16].try_into().unwrap()),
            entries[1].next_cookie
        );
        assert!(i64::try_from(usize::MAX).is_err());
    }
}

pub(super) fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if dirp.is_null() || count == 0 {
        return Err(SyscallError::EINVAL);
    }

    // R114-2 FIX: Cap `count` to MAX_RW_SIZE to prevent extreme kernel allocations
    // even with large user buffers. Uses the residual-derived MAX_RW_SIZE (R180-10).
    let budget = count.min(MAX_RW_SIZE);

    // J2-10: per-cgroup VFS dir-enumeration budget (vfs_dir.max). Resolve the
    // cgroup id FIRST (current_cgroup_id releases the Process lock before we
    // charge — INV-2: cgroup charges never run under the Process lock). The RAII
    // guard charges at construction and uncharges on Ok and every early `?` Err
    // return through Drop, covering the lifetime of both the `entries` Vec and the
    // per-entry serialization buffers below. (The kernel is built panic=abort, so
    // Drop does not run on panic — but a panic halts the kernel, making the
    // transient charge moot.) When the
    // tenant's budget is tight it grants a SMALLER amount → a graceful getdents64
    // short read (the next call resumes from the advanced offset); it never fails
    // the syscall or returns a false EOD. Root id==0 is exempt (full budget).
    let vfs_cg = crate::process::current_cgroup_id().unwrap_or(0);
    let vfs_guard = crate::cgroup::VfsDirBudgetGuard::charge(vfs_cg, budget);
    let budget = vfs_guard.granted();

    // The VFS callback keeps the shared directory offset locked and uncommitted
    // until `copy_dirents_to_user` succeeds.
    let readdir_fn = VFS_READDIR_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    readdir_fn(fd, budget, dirp, copy_dirents_to_user)
}

/// chown(2) - change file ownership
///
/// # M0-6 Implementation Strategy
/// Dispatch-or-stub per plan. Stub for now as VFS lacks full ownership tracking.
pub(super) fn sys_chown(_path: *const u8, _uid: u32, _gid: u32) -> Result<usize, SyscallError> {
    // M0-6: chown requires VFS inode ownership + DAC checks
    // Current VFS has minimal ownership tracking
    Err(SyscallError::ENOSYS)
}

/// fchown(2) - change file ownership by fd
pub(super) fn sys_fchown(_fd: i32, _uid: u32, _gid: u32) -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

/// lchown(2) - change symlink ownership (don't follow link)
pub(super) fn sys_lchown(_path: *const u8, _uid: u32, _gid: u32) -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}
