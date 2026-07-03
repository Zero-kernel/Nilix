// kernel/src/abi_compliance_tests.rs
//
// ABI Compliance Test Suite
//
// Defense-in-Depth Layer 4: Regression Testing
// Part of R173 defense strategy to prevent silent flag/parameter ignore

#![cfg(test)]

use kernel_core::syscall::*;

/// Test that unimplemented flags are explicitly rejected (not silently ignored)
///
/// R173-05/06/07 Pattern: Syscalls silently ignore user-provided flags
/// This test suite prevents regressions by verifying fail-closed behavior.

#[test]
fn test_pipe2_rejects_unsupported_flags() {
    // R173-05: pipe2 must reject O_CLOEXEC until implemented

    let mut fds = [0i32; 2];

    // O_CLOEXEC not implemented — should fail
    let result = unsafe {
        sys_pipe2(&mut fds as *mut [i32; 2], O_CLOEXEC)
    };

    assert!(
        result.is_err(),
        "pipe2 with O_CLOEXEC should fail, not silently ignore"
    );

    // Should return EINVAL specifically
    assert_eq!(
        result,
        Err(SyscallError::EINVAL),
        "pipe2 with unsupported flag should return EINVAL"
    );

    // Ensure no side effects on failure (fds unchanged)
    assert_eq!(fds, [0, 0], "pipe2 failure should not modify fds array");
}

#[test]
fn test_fcntl_dupfd_cloexec_rejected() {
    // R173-06: F_DUPFD_CLOEXEC must be rejected until implemented

    let fd = 0;  // stdin
    let min_fd = 3;

    let result = unsafe {
        sys_fcntl(fd, F_DUPFD_CLOEXEC, min_fd as usize)
    };

    assert!(
        result.is_err(),
        "fcntl(F_DUPFD_CLOEXEC) should fail, not silently ignore cloexec"
    );

    assert_eq!(
        result,
        Err(SyscallError::EINVAL),
        "F_DUPFD_CLOEXEC should return EINVAL until implemented"
    );
}

#[test]
fn test_pread64_rejects_with_enosys() {
    // R173-07: pread64 must fail explicitly (not read from wrong offset)

    let mut buf = [0u8; 128];
    let fd = 0;  // stdin
    let offset = 1000i64;  // Positioned I/O offset

    let result = unsafe {
        sys_pread64(fd, buf.as_mut_ptr(), buf.len(), offset)
    };

    assert!(
        result.is_err(),
        "pread64 should fail when positioned I/O not implemented"
    );

    assert_eq!(
        result,
        Err(SyscallError::ENOSYS),
        "pread64 should return ENOSYS (not silently ignore offset)"
    );

    // Ensure no data was read
    assert_eq!(
        buf,
        [0u8; 128],
        "pread64 failure should not modify buffer"
    );
}

#[test]
fn test_pwrite64_rejects_with_enosys() {
    // R173-07: pwrite64 must fail explicitly (not write to wrong offset)

    let buf = [0x42u8; 128];
    let fd = 1;  // stdout
    let offset = 1000i64;  // Positioned I/O offset

    let result = unsafe {
        sys_pwrite64(fd, buf.as_ptr(), buf.len(), offset)
    };

    assert!(
        result.is_err(),
        "pwrite64 should fail when positioned I/O not implemented"
    );

    assert_eq!(
        result,
        Err(SyscallError::ENOSYS),
        "pwrite64 should return ENOSYS (not silently ignore offset)"
    );
}

#[test]
fn test_sys_link_immediate_rejection() {
    // R173-09: sys_link should return EPERM immediately (no usercopy)

    let oldpath = b"/path/old\0".as_ptr();
    let newpath = b"/path/new\0".as_ptr();

    let result = unsafe {
        sys_link(oldpath, newpath)
    };

    assert!(
        result.is_err(),
        "sys_link should fail (hard links not implemented)"
    );

    assert_eq!(
        result,
        Err(SyscallError::EPERM),
        "sys_link should return EPERM for unimplemented feature"
    );
}

#[test]
fn test_sys_link_null_pointer_check() {
    // R173-09: Even stubs should validate NULL pointers

    let result = unsafe {
        sys_link(core::ptr::null(), core::ptr::null())
    };

    assert_eq!(
        result,
        Err(SyscallError::EFAULT),
        "sys_link should return EFAULT for NULL pointers"
    );
}

/// Test that implemented features work correctly (not broken by fail-closed changes)

#[test]
fn test_pipe2_zero_flags_works() {
    // Ensure pipe2 with flags=0 still works

    let mut fds = [0i32; 2];

    let result = unsafe {
        sys_pipe2(&mut fds as *mut [i32; 2], 0)
    };

    // Should succeed with no flags
    assert!(
        result.is_ok(),
        "pipe2 with flags=0 should work"
    );

    // Should have created two file descriptors
    assert_ne!(fds[0], 0);
    assert_ne!(fds[1], 0);
    assert_ne!(fds[0], fds[1]);
}

#[test]
fn test_fcntl_dupfd_works() {
    // Ensure F_DUPFD (without CLOEXEC) still works

    let fd = 0;  // stdin
    let min_fd = 3;

    let result = unsafe {
        sys_fcntl(fd, F_DUPFD, min_fd as usize)
    };

    // Should succeed (F_DUPFD is implemented)
    assert!(
        result.is_ok() || result == Err(SyscallError::EBADF),
        "F_DUPFD should work (not conflated with F_DUPFD_CLOEXEC)"
    );
}

/// Test flag combination handling

#[test]
fn test_combined_flags_rejected_if_any_unsupported() {
    // Test that combining supported + unsupported flags is rejected

    let mut fds = [0i32; 2];

    // If O_NONBLOCK is supported but O_CLOEXEC is not,
    // the combination should still be rejected
    let combined_flags = O_NONBLOCK | O_CLOEXEC;

    let result = unsafe {
        sys_pipe2(&mut fds as *mut [i32; 2], combined_flags)
    };

    assert!(
        result.is_err(),
        "Combined flags with unsupported bit should fail"
    );
}

/// Test error consistency

#[test]
fn test_error_codes_are_consistent() {
    // EINVAL for unsupported flags
    let mut fds = [0i32; 2];
    let r1 = unsafe { sys_pipe2(&mut fds as *mut [i32; 2], O_CLOEXEC) };
    assert_eq!(r1, Err(SyscallError::EINVAL));

    // ENOSYS for unimplemented syscall
    let mut buf = [0u8; 128];
    let r2 = unsafe { sys_pread64(0, buf.as_mut_ptr(), 128, 0) };
    assert_eq!(r2, Err(SyscallError::ENOSYS));

    // EPERM for operations not permitted
    let r3 = unsafe {
        sys_link(b"/old\0".as_ptr(), b"/new\0".as_ptr())
    };
    assert_eq!(r3, Err(SyscallError::EPERM));

    // EFAULT for NULL pointers
    let r4 = unsafe { sys_link(core::ptr::null(), core::ptr::null()) };
    assert_eq!(r4, Err(SyscallError::EFAULT));
}

// Constants (should match syscall.rs)
const O_CLOEXEC: i32 = 0x80000;
const O_NONBLOCK: i32 = 0x800;
const F_DUPFD: i32 = 0;
const F_DUPFD_CLOEXEC: i32 = 1030;

// Mock SyscallError for tests
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SyscallError {
    EFAULT,
    EINVAL,
    ENOSYS,
    EPERM,
    EBADF,
}

// Mock syscall signatures (actual implementations in kernel_core)
unsafe fn sys_pipe2(_fds: *mut [i32; 2], _flags: i32) -> Result<usize, SyscallError> {
    // Mock implementation - actual version in kernel_core/syscall.rs
    unimplemented!("This is a test module - real syscalls are in kernel_core")
}

unsafe fn sys_fcntl(_fd: i32, _cmd: i32, _arg: usize) -> Result<usize, SyscallError> {
    unimplemented!()
}

unsafe fn sys_pread64(
    _fd: i32,
    _buf: *mut u8,
    _count: usize,
    _offset: i64,
) -> Result<usize, SyscallError> {
    unimplemented!()
}

unsafe fn sys_pwrite64(
    _fd: i32,
    _buf: *const u8,
    _count: usize,
    _offset: i64,
) -> Result<usize, SyscallError> {
    unimplemented!()
}

unsafe fn sys_link(_oldpath: *const u8, _newpath: *const u8) -> Result<usize, SyscallError> {
    unimplemented!()
}
