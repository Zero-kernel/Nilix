// kernel/kernel_core/syscall_macros.rs
//
// Fail-closed syscall stub generator
//
// Defense-in-Depth Layer 3: Consistent Stub Pattern
// Part of R173 defense strategy to prevent silent flag/parameter ignore

/// Generate a fail-closed syscall stub
///
/// # Purpose
///
/// Unimplemented syscalls should return explicit errors (EINVAL/ENOSYS/EPERM)
/// rather than silently ignoring parameters or returning success with non-POSIX
/// behavior. This macro enforces the fail-closed pattern.
///
/// # Pattern
///
/// R173-05/06/07/09 all involved syscalls silently ignoring user-provided
/// parameters. This macro prevents that class by:
/// 1. Validating NULL pointers (fail-fast on EFAULT)
/// 2. Returning error immediately (no usercopy waste)
/// 3. Logging reason for unimplemented status
///
/// # Example
///
/// ```rust
/// // Before (R173-09 pattern — validates unnecessarily)
/// fn sys_link(oldpath: *const u8, newpath: *const u8) -> SyscallResult {
///     if oldpath.is_null() || newpath.is_null() {
///         return Err(SyscallError::EFAULT);
///     }
///
///     // ❌ Validates and copies paths despite always returning EPERM
///     let _old = copy_user_cstring(oldpath)?;
///     let _new = copy_user_cstring(newpath)?;
///
///     Err(SyscallError::EPERM)
/// }
///
/// // After (fail-closed stub — immediate rejection)
/// syscall_stub!(sys_link, EPERM, "Hard links not implemented",
///     oldpath: *const u8,
///     newpath: *const u8
/// );
/// ```
///
/// # Arguments
///
/// * `$name` - Function name (e.g., sys_link)
/// * `$errno` - Error to return (EPERM, ENOSYS, EINVAL)
/// * `$reason` - Human-readable reason string
/// * `$($arg_name:ident : $arg_type:ty),*` - Function parameters
///
/// # Expansion
///
/// Generates a function that:
/// 1. Checks pointer arguments for NULL (EFAULT)
/// 2. Logs reason at WARN level (searchable for unimplemented syscalls)
/// 3. Returns specified error immediately (no work)
///
/// # Benefits
///
/// - Consistent pattern (all stubs follow same structure)
/// - No usercopy waste (R173-09 insight)
/// - Searchable (grep for "not implemented")
/// - Self-documenting (reason in code)
#[macro_export]
macro_rules! syscall_stub {
    // Variant 1: No arguments
    ($name:ident, $errno:ident, $reason:expr) => {
        fn $name() -> SyscallResult {
            klog::klog!(Warn,concat!(stringify!($name), ": ", $reason));
            Err(SyscallError::$errno)
        }
    };

    // Variant 2: With arguments
    ($name:ident, $errno:ident, $reason:expr, $($arg_name:ident : $arg_type:ty),+ $(,)?) => {
        fn $name($($arg_name: $arg_type),+) -> SyscallResult {
            // Validate pointer arguments (fail-fast on NULL)
            $(
                syscall_stub!(@check_ptr $arg_name, $arg_type);
            )+

            // Log reason for unimplemented status
            klog::klog!(Warn,concat!(stringify!($name), ": ", $reason));

            // Return error immediately (no further work)
            Err(SyscallError::$errno)
        }
    };

    // Helper: Check if argument is a pointer and validate it
    (@check_ptr $arg_name:ident, *const $t:ty) => {
        if $arg_name.is_null() {
            return Err(SyscallError::EFAULT);
        }
    };
    (@check_ptr $arg_name:ident, *mut $t:ty) => {
        if $arg_name.is_null() {
            return Err(SyscallError::EFAULT);
        }
    };
    (@check_ptr $arg_name:ident, $t:ty) => {
        // Non-pointer argument, no check needed
        let _ = $arg_name;  // Suppress unused warning
    };
}

/// Generate a stub for a syscall with flags parameter
///
/// Special case for syscalls that accept flags but only support a subset.
/// Explicitly rejects unsupported flags (fail-closed pattern).
///
/// # Example
///
/// ```rust
/// // Before (R173-05 pattern — silently ignores O_CLOEXEC)
/// fn sys_pipe2(fds: *mut [i32; 2], flags: i32) -> SyscallResult {
///     // ... create pipe ...
///     if flags & O_CLOEXEC != 0 {
///         // TODO: Implement CLOEXEC
///         // ❌ Silently ignores flag
///     }
///     Ok(0)
/// }
///
/// // After (fail-closed flags stub)
/// syscall_stub_with_flags!(
///     sys_pipe2,
///     SUPPORTED_FLAGS = O_NONBLOCK,
///     EINVAL,
///     "O_CLOEXEC not yet implemented",
///     fds: *mut [i32; 2],
///     flags: i32
/// );
/// ```
#[macro_export]
macro_rules! syscall_stub_with_flags {
    (
        $name:ident,
        SUPPORTED_FLAGS = $supported:expr,
        $errno:ident,
        $reason:expr,
        $($arg_name:ident : $arg_type:ty),+ $(,)?
    ) => {
        fn $name($($arg_name: $arg_type),+) -> SyscallResult {
            // Extract flags parameter (must be named 'flags')
            let unsupported = flags & !$supported;

            if unsupported != 0 {
                klog::klog!(Warn,
                    concat!(stringify!($name), ": ", $reason, " (flags={:#x})"),
                    unsupported
                );
                return Err(SyscallError::$errno);
            }

            // If we reach here, all flags are supported
            // ... actual implementation ...
            unimplemented!(concat!(stringify!($name), " base implementation"))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock types for testing
    type SyscallResult = Result<usize, SyscallError>;

    #[allow(clippy::upper_case_acronyms)]
    #[derive(Debug, PartialEq)]
    enum SyscallError {
        EFAULT,
        EPERM,
        ENOSYS,
        EINVAL,
    }

    #[test]
    fn test_syscall_stub_no_args() {
        syscall_stub!(sys_example_noargs, ENOSYS, "Not implemented");

        let result = sys_example_noargs();
        assert_eq!(result, Err(SyscallError::ENOSYS));
    }

    #[test]
    fn test_syscall_stub_with_args() {
        syscall_stub!(
            sys_example_with_args,
            EPERM,
            "Feature not implemented",
            fd: i32,
            buf: *const u8,
            len: usize
        );

        // Non-null pointer should still return EPERM
        let buf = &42u8 as *const u8;
        let result = sys_example_with_args(0, buf, 100);
        assert_eq!(result, Err(SyscallError::EPERM));
    }

    #[test]
    fn test_syscall_stub_null_pointer() {
        syscall_stub!(
            sys_example_null_check,
            EPERM,
            "Feature not implemented",
            path: *const u8
        );

        // NULL pointer should return EFAULT
        let result = sys_example_null_check(core::ptr::null());
        assert_eq!(result, Err(SyscallError::EFAULT));
    }
}
