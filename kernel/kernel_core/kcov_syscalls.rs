// Add after the existing KCOV syscalls section (around line 18750)

// ============================================================================
// KCOV (Kernel Code Coverage) Syscalls - Fuzzing Infrastructure
// ============================================================================

/// Initialize KCOV for current task
///
/// Allocates a coverage buffer and prepares the task for coverage collection.
/// Must be called before sys_kcov_enable.
///
/// # Arguments
/// - `buf_size`: Size of coverage buffer in bytes (must be <= 4096)
///
/// # Returns
/// - Success: 0
/// - Error: EINVAL (invalid size), ENOMEM (allocation failed), EEXIST (already initialized)
///
/// # Example
/// ```c
/// if (syscall(520, 4096) != 0) {
///     perror("kcov_init");
/// }
/// ```
fn sys_kcov_init(buf_size: usize) -> Result<usize, SyscallError> {
    use coverage;

    // Validate buffer size
    if buf_size == 0 || buf_size > coverage::KCOV_BUFFER_SIZE {
        return Err(SyscallError::InvalidArgument);
    }

    // Check if already initialized
    with_current_process(|proc| {
        if proc.coverage_buffer.is_some() {
            return Err(SyscallError::AlreadyExists);
        }
        Ok(())
    })??;

    // Enable coverage and store buffer in process
    let buf = coverage::enable_coverage().ok_or(SyscallError::OutOfMemory)?;

    with_current_process(|proc| {
        proc.coverage_buffer = Some(buf);
        Ok(())
    })??;

    Ok(0)
}

/// Enable coverage collection for current task
///
/// Must be called after sys_kcov_init. Coverage data will be collected
/// until sys_kcov_disable is called.
///
/// # Returns
/// - Success: 0
/// - Error: EINVAL (not initialized)
fn sys_kcov_enable() -> Result<usize, SyscallError> {
    with_current_process(|proc| {
        let buf = proc.coverage_buffer.as_ref().ok_or(SyscallError::InvalidArgument)?;
        buf.lock().enable();
        Ok(0)
    })?
}

/// Disable coverage collection for current task
///
/// Stops collecting coverage data but preserves existing data for later dump.
///
/// # Returns
/// - Success: 0
/// - Error: EINVAL (not initialized)
fn sys_kcov_disable() -> Result<usize, SyscallError> {
    with_current_process(|proc| {
        let buf = proc.coverage_buffer.as_ref().ok_or(SyscallError::InvalidArgument)?;
        buf.lock().disable();
        Ok(0)
    })?
}

/// Dump coverage data to userspace
///
/// Copies the coverage bitmap to user-provided buffer and returns the count
/// of unique edges hit.
///
/// # Arguments
/// - `user_buf`: Pointer to userspace buffer (must be at least 4096 bytes)
/// - `len`: Length of user buffer
///
/// # Returns
/// - Success: Number of unique edges hit (>= 0)
/// - Error: EINVAL (not initialized), EFAULT (invalid user pointer)
///
/// # Example
/// ```c
/// uint8_t coverage[4096];
/// long edges = syscall(523, coverage, sizeof(coverage));
/// if (edges < 0) {
///     perror("kcov_dump");
/// } else {
///     printf("Hit %ld unique edges\\n", edges);
/// }
/// ```
fn sys_kcov_dump(user_buf: usize, len: usize) -> Result<usize, SyscallError> {
    use usercopy;

    if user_buf == 0 {
        return Err(SyscallError::InvalidArgument);
    }

    if len > coverage::KCOV_BUFFER_SIZE {
        return Err(SyscallError::InvalidArgument);
    }

    with_current_process(|proc| {
        let buf = proc.coverage_buffer.as_ref().ok_or(SyscallError::InvalidArgument)?;
        let buf_lock = buf.lock();

        // Allocate temporary kernel buffer
        let mut kernel_buf = alloc::vec![0u8; len];
        let copied = buf_lock.copy_to_user(&mut kernel_buf);

        // Copy to userspace via SMAP-compliant path
        usercopy::copy_to_user(user_buf, kernel_buf.as_ptr() as usize, copied)?;

        Ok(buf_lock.edge_count())
    })?
}

/// Reset coverage data
///
/// Clears all collected coverage data. Coverage collection remains enabled/disabled
/// as before; only the recorded edges are cleared.
///
/// # Returns
/// - Success: 0
/// - Error: EINVAL (not initialized)
fn sys_kcov_reset() -> Result<usize, SyscallError> {
    with_current_process(|proc| {
        let buf = proc.coverage_buffer.as_ref().ok_or(SyscallError::InvalidArgument)?;
        buf.lock().reset();
        Ok(0)
    })?
}
