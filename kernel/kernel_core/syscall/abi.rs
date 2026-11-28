//! Syscall family module: `abi` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// Seccomp/Prctl Constants (Linux x86_64 ABI)
// ============================================================================

/// Seccomp operation modes
pub(super) const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub(super) const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// Seccomp mode return values for prctl(PR_GET_SECCOMP)
pub(super) const SECCOMP_MODE_DISABLED: usize = 0;
pub(super) const SECCOMP_MODE_STRICT: usize = 1;
pub(super) const SECCOMP_MODE_FILTER: usize = 2;

/// prctl option codes for seccomp operations
pub(super) const PR_GET_SECCOMP: i32 = 21;
pub(super) const PR_SET_SECCOMP: i32 = 22;
pub(super) const PR_SET_NO_NEW_PRIVS: i32 = 38;
pub(super) const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// User-space BPF instruction opcodes (simplified encoding)
/// These define the wire format for filters passed from userspace
pub(super) const SECCOMP_USER_OP_LD_NR: u8 = 0;
pub(super) const SECCOMP_USER_OP_LD_ARG: u8 = 1;
pub(super) const SECCOMP_USER_OP_LD_CONST: u8 = 2;
pub(super) const SECCOMP_USER_OP_AND: u8 = 3;
pub(super) const SECCOMP_USER_OP_OR: u8 = 4;
pub(super) const SECCOMP_USER_OP_SHR: u8 = 5;
pub(super) const SECCOMP_USER_OP_JMP_EQ: u8 = 6;
pub(super) const SECCOMP_USER_OP_JMP_NE: u8 = 7;
pub(super) const SECCOMP_USER_OP_JMP_LT: u8 = 8;
pub(super) const SECCOMP_USER_OP_JMP_LE: u8 = 9;
pub(super) const SECCOMP_USER_OP_JMP_GT: u8 = 10;
pub(super) const SECCOMP_USER_OP_JMP_GE: u8 = 11;
pub(super) const SECCOMP_USER_OP_JMP: u8 = 12;
pub(super) const SECCOMP_USER_OP_RET: u8 = 13;

/// Seccomp action codes for RET instruction
pub(super) const SECCOMP_USER_ACTION_ALLOW: u32 = 0;
pub(super) const SECCOMP_USER_ACTION_LOG: u32 = 1;
pub(super) const SECCOMP_USER_ACTION_ERRNO: u32 = 2;
pub(super) const SECCOMP_USER_ACTION_TRAP: u32 = 3;
pub(super) const SECCOMP_USER_ACTION_KILL: u32 = 4;

/// User-space seccomp instruction structure
/// Matches the format passed from userspace via sys_seccomp(FILTER)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UserSeccompInsn {
    /// Opcode (SECCOMP_USER_OP_*)
    pub(super) op: u8,
    pub(super) _padding: [u8; 7],
    /// First operand (varies by opcode)
    pub(super) arg0: u64,
    /// Second operand (jump targets for conditional jumps)
    pub(super) arg1: u64,
    /// Third operand (false branch offset for conditional jumps)
    pub(super) arg2: u64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 32] = [(); core::mem::size_of::<UserSeccompInsn>()];

/// User-space seccomp program header
/// Describes the filter to be installed
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UserSeccompProg {
    /// Number of instructions
    pub(super) len: u32,
    /// Default action (applied when no instruction returns)
    pub(super) default_action: u32,
    /// Pointer to instruction array
    pub(super) filter: u64, // Using u64 instead of *const for safe Copy
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<UserSeccompProg>()];

// ============================================================================
// Linux ABI struct definitions for new syscalls
// ============================================================================

/// AT_FDCWD sentinel for *at() syscalls (openat, fstatat, etc.)
pub(super) const AT_FDCWD: i32 = -100;

/// struct open_how (Linux openat2 ABI)
///
/// Used by the openat2(2) syscall to specify open flags, mode, and resolve flags.
/// Compatible with Linux 5.6+ ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct OpenHow {
    /// Open flags (O_RDONLY, O_WRONLY, O_CREAT, O_NOFOLLOW, etc.)
    pub(super) flags: u64,
    /// File creation mode (only used with O_CREAT)
    pub(super) mode: u64,
    /// Path resolution flags (RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH, etc.)
    pub(super) resolve: u64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 24] = [(); core::mem::size_of::<OpenHow>()];

/// struct timeval (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TimeVal {
    pub(super) tv_sec: i64,
    pub(super) tv_usec: i64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<TimeVal>()];

/// struct timespec (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TimeSpec {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: i64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<TimeSpec>()];

/// struct utsname (Linux ABI, fixed-size strings)
///
/// D2-ABI-STAT-LAYOUT (LOW leg): Linux `new_utsname` is 6 x [u8;65] = 390
/// bytes INCLUDING `domainname`. The former 5-field 325-byte layout left the
/// caller's last 65 bytes unwritten (musl/glibc buffers are 390B), i.e.
/// domainname read back as uninitialized user stack. Enforced by abi-check.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct UtsName {
    pub(super) sysname: [u8; 65],
    pub(super) nodename: [u8; 65],
    pub(super) release: [u8; 65],
    pub(super) version: [u8; 65],
    pub(super) machine: [u8; 65],
    pub(super) domainname: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

// H.0.1-3: Compile-time ABI size assertion (Linux new_utsname).
const _: [(); 390] = [(); core::mem::size_of::<UtsName>()];

/// Linux dirent64 layout for getdents64 syscall
#[repr(C)]
pub(super) struct LinuxDirent64 {
    pub(super) d_ino: u64,
    pub(super) d_off: i64,
    pub(super) d_reclen: u16,
    pub(super) d_type: u8,
    // followed by name bytes + '\0'
}

// The Rust object includes five bytes of tail padding, but Linux places the
// flexible `d_name[]` tail immediately after `d_type` at byte offset 19.
// R180-25: never use size_of::<LinuxDirent64>() as the wire tail offset.
const _: [(); 24] = [(); core::mem::size_of::<LinuxDirent64>()];
pub const LINUX_DIRENT64_NAME_OFFSET: usize = core::mem::offset_of!(LinuxDirent64, d_type) + 1;
const _: [(); 19] = [(); LINUX_DIRENT64_NAME_OFFSET];

// ============================================================================
// Socket ABI (Linux x86_64)
// ============================================================================

/// Socket type flags (Linux ABI)
pub(super) const SOCK_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
pub(super) const SOCK_CLOEXEC: u32 = 0o2000000; // O_CLOEXEC

/// sendto/recvfrom/sendmsg/recvmsg flags we support
pub(super) const MSG_TRUNC: u32 = 0x20;
pub(super) const MSG_DONTWAIT: u32 = 0x40;
pub(super) const MSG_NOSIGNAL: u32 = 0x4000;

/// Socket option levels (Linux x86_64 ABI)
pub(super) const IPPROTO_IP: i32 = 0;
pub(super) const SOL_SOCKET: i32 = 1;
pub(super) const IPPROTO_TCP: i32 = 6;

/// SOL_SOCKET option names (Linux x86_64 ABI)
pub(super) const SO_REUSEADDR: i32 = 2;
pub(super) const SO_TYPE: i32 = 3;
pub(super) const SO_ERROR: i32 = 4;
pub(super) const SO_SNDBUF: i32 = 7;
pub(super) const SO_RCVBUF: i32 = 8;
pub(super) const SO_KEEPALIVE: i32 = 9;
pub(super) const SO_RCVTIMEO: i32 = 20;
pub(super) const SO_SNDTIMEO: i32 = 21;

/// IPPROTO_TCP option names (Linux x86_64 ABI)
pub(super) const TCP_NODELAY: i32 = 1;

/// IPPROTO_IP option names (Linux x86_64 ABI)
pub(super) const IP_TTL: i32 = 2;

/// Maximum UDP payload size
pub(super) const UDP_MAX_PAYLOAD: usize = 65507;

/// struct msghdr (Linux x86_64 ABI compatible, 56 bytes, explicit padding)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct MsgHdr {
    pub(super) msg_name: *mut u8,
    pub(super) msg_namelen: u32,
    pub(super) _pad0: u32,
    pub(super) msg_iov: *const Iovec,
    pub(super) msg_iovlen: usize,
    pub(super) msg_control: *mut u8,
    pub(super) msg_controllen: usize,
    pub(super) msg_flags: i32,
    pub(super) _pad1: u32,
}

const _: [(); 56] = [(); core::mem::size_of::<MsgHdr>()];
const _: [(); 8] = [(); core::mem::align_of::<MsgHdr>()];
const _: [(); 0] = [(); core::mem::offset_of!(MsgHdr, msg_name)];
const _: [(); 8] = [(); core::mem::offset_of!(MsgHdr, msg_namelen)];
const _: [(); 16] = [(); core::mem::offset_of!(MsgHdr, msg_iov)];
const _: [(); 24] = [(); core::mem::offset_of!(MsgHdr, msg_iovlen)];
const _: [(); 32] = [(); core::mem::offset_of!(MsgHdr, msg_control)];
const _: [(); 40] = [(); core::mem::offset_of!(MsgHdr, msg_controllen)];
const _: [(); 48] = [(); core::mem::offset_of!(MsgHdr, msg_flags)];

/// struct sockaddr_in (Linux x86_64 ABI compatible)
///
/// Used by socket syscalls for IPv4 address specification.
/// All multi-byte fields are in network byte order.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SockAddrIn {
    /// Address family (AF_INET = 2)
    pub(super) sin_family: u16,
    /// Port number (network byte order)
    pub(super) sin_port: u16,
    /// IPv4 address as the exact four network-order bytes from `struct in_addr`.
    pub(super) sin_addr: [u8; 4],
    /// Padding to 16 bytes (Linux ABI)
    pub(super) sin_zero: [u8; 8],
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<SockAddrIn>()];
const _: [(); 4] = [(); core::mem::offset_of!(SockAddrIn, sin_addr)];
const _: [(); 4] = [(); core::mem::align_of::<SockAddrIn>()];

impl SockAddrIn {
    /// Create from Ipv4Addr and port (host byte order).
    pub(super) fn from_addr(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: ip,
            sin_zero: [0; 8],
        }
    }

    /// Extract IP address as [u8; 4] in network byte order.
    pub(super) fn ip_bytes(&self) -> [u8; 4] {
        self.sin_addr
    }

    /// Extract port in host byte order.
    pub(super) fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }
}

/// R180-24/R180-25 byte-level Linux ABI oracle.
///
/// This is intentionally independent of the bundled userspace wrappers. It
/// pins the native x86_64 `sa_family_t` bytes, network-order port/address bytes,
/// and the flexible-tail offset used by a host C `linux_dirent64` consumer.
pub fn run_linux_wire_abi_self_test() {
    let addr = SockAddrIn::from_addr([127, 0, 0, 1], 8080);
    let bytes = unsafe {
        // lint-repr-c-copy: allow (SockAddrIn is compile-time 16-byte, padding-free, and fully initialized)
        core::slice::from_raw_parts(
            &addr as *const SockAddrIn as *const u8,
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    assert_eq!(
        bytes,
        &[2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        "sockaddr_in wire bytes differ from Linux x86_64 ABI"
    );
    assert_eq!(addr.ip_bytes(), [127, 0, 0, 1]);
    assert_eq!(addr.port(), 8080);
    assert_eq!(core::mem::align_of::<SockAddrIn>(), 4);
    assert_eq!(LINUX_DIRENT64_NAME_OFFSET, 19);
}

/// AF_INET constant (IPv4)
pub(super) const AF_INET: u32 = 2;

/// Socket file descriptor wrapper for fd_table.
///
/// Stores the CapId and socket_id together for efficient lookup.
#[derive(Clone)]
pub(crate) struct SocketFile {
    /// Capability ID referencing this socket in cap_table
    pub(super) cap_id: cap::CapId,
    /// Socket ID in socket_table()
    pub(super) socket_id: u64,
}

impl SocketFile {
    pub(super) fn new(cap_id: cap::CapId, socket_id: u64) -> Self {
        Self { cap_id, socket_id }
    }
}

/// S_IFSOCK constant - socket file type marker
pub(super) const S_IFSOCK: u32 = 0o140000;

impl crate::process::FileOps for SocketFile {
    fn status_flags(&self) -> Result<u32, SyscallError> {
        let socket = net::socket_table()
            .get(self.socket_id)
            .ok_or(SyscallError::EBADF)?;
        Ok(2 | socket.file_status_flags()) // O_RDWR, shared across dup/fork
    }

    fn set_status_flags(&self, flags: u32) -> Result<(), SyscallError> {
        let flags = crate::process::mutable_file_status_bits(flags)?;
        let socket = net::socket_table()
            .get(self.socket_id)
            .ok_or(SyscallError::EBADF)?;
        socket.set_file_status_flags(flags);
        Ok(())
    }

    fn clone_box(&self) -> Result<crate::process::FileDescriptor, ()> {
        // Increment the SOCKET refcount on clone (for dup/fork POSIX semantics).
        //
        // NOTE: If the socket was already closed/removed from the table,
        // get() returns None and we create a SocketFile pointing to a dead
        // socket. This is acceptable because:
        // 1. Any operation on the dead socket will fail gracefully (EBADF)
        // 2. Drop will do nothing (get() returns None again)
        // 3. The FileOps trait doesn't allow returning errors from clone_box
        //
        // This edge case can occur if the socket is closed between dup/fork
        // initiation and completion - a valid race condition in concurrent
        // environments.
        // U.S3-A2 FIX (CRITICAL self-deadlock): clone_box is PURE with respect to
        // the cap_table — it does NOT take the Process lock or bump the CapEntry
        // refcount. The prior U.S2-SLICE-2 code did `try_get_process(pid).lock()`
        // + `cap_table.increment_refcount()` HERE, but EVERY clone_box caller
        // (sys_dup/dup2/dup3, fcntl F_DUPFD, fork.rs:443, the CLONE_FILES snapshot
        // at :3833) already holds THAT SAME Process spin::Mutex — a non-reentrant
        // lock — so any dup/fork of a socket fd was a same-CPU self-deadlock,
        // masked only because no boot/musl path dups a live socket. The cap
        // refcount is now bumped EXPLICITLY at each call site under the
        // already-held guard AFTER the fd install succeeds (U.S3-A3), and copied
        // verbatim (not incremented) into the fork child table (U.S3-A1
        // CapSlot::clone). See `remove_fd` (process.rs) for the matching decrement
        // via the generic `FileOps::cap_id()` accessor.
        self.try_clone_box()
    }

    fn try_clone_box(&self) -> Result<crate::process::FileDescriptor, ()> {
        // RF180-37: allocate/admit the exact-lifetime outer owner before
        // incrementing socket ownership. Finalization is infallible, so no
        // compensating refcount rollback is needed under Process.
        let prepared = crate::process::FileDescriptor::try_prepare(mm::HeapClass::SocketObject)?;
        let socket = net::socket_table().get(self.socket_id);
        if let Some(socket) = socket.as_ref() {
            socket.increment_refcount();
        }
        Ok(prepared.finalize(self.clone()))
    }

    /// U.S3-B FIX: expose this fd's CapId so the generic `remove_fd` /
    /// dup / exec-cloexec / exit paths can decrement its refcount without
    /// downcasting to the concrete `SocketFile` type. `Some` because a socket fd
    /// always carries a live cap allocated at `sys_socket` / `sys_accept`.
    fn cap_id(&self) -> Option<cap::CapId> {
        Some(self.cap_id)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "SocketFile"
    }

    // M0-6 poll/select: classify a socket fd for the readiness probe. Carries ONLY
    // the Copy ids (cap_id, socket_id) — NEVER an Arc<SocketState> — so the probe
    // pass re-resolves the socket fresh each tick under no lock and a Drop-bearing
    // TCB is never parked here. Without this override the fd would fall through to
    // the FileOps default (AlwaysReady) and report spurious POLLIN/POLLOUT every
    // tick, and SocketState::poll_readiness would be dead code.
    fn poll_arm(&self) -> crate::poll::PollArm {
        crate::poll::PollArm::Socket {
            cap_id: self.cap_id,
            socket_id: self.socket_id,
        }
    }

    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
            dev: 0,
            ino: self.socket_id,
            nlink: 1,
            mode: S_IFSOCK | 0o666, // Socket with rw-rw-rw- permissions
            uid: 0,
            gid: 0,
            pad0: 0,
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
            unused0: 0,
            unused1: 0,
            unused2: 0,
        })
    }
}

/// Socket cleanup on Drop with reference counting.
///
/// When a SocketFile is dropped (via sys_close or process exit), we decrement
/// the socket's reference count. Only when the refcount reaches 0 do we fully
/// close the socket, releasing the port binding and waking any waiters.
///
/// This preserves POSIX semantics for:
/// - dup()/dup2()/dup3(): Multiple FDs can share one socket
/// - fork(): Child inherits socket FDs with proper refcounting
///
/// The reference count is:
/// - Initialized to 1 at socket creation
/// - Incremented in clone_box() (called by dup/fork)
/// - Decremented here on drop
impl Drop for SocketFile {
    fn drop(&mut self) {
        // Decrement refcount; only close when reaching 0
        if let Some(sock) = net::socket_table().get(self.socket_id) {
            if sock.decrement_refcount() == 0 {
                net::socket_table().close(self.socket_id);
            }
        }
    }
}
