//! N2.0b: Single Authoritative Syscall Table.
//!
//! Every Linux x86_64 and Zero-OS native syscall known to the kernel is declared
//! **once** in this module. All four historical sources of drift are generated
//! directly from this single table:
//!
//! 1. **Kernel dispatch** (`DispatchedSyscall` enum + `from_nr()`): exhaustive
//!    `match` in `kernel_core::syscall::syscall_dispatcher` makes any table /
//!    dispatcher mismatch a compile error, and `drops_entry_proc()` drives
//!    cached `ProcessArc` release before fatal/non-unwinding handlers.
//! 2. **Seccomp strict filter** (`STRICT_ALLOWED` / `build_strict_program()`):
//!    compiled at `const` time from entries with `strict_allowed == true`.
//! 3. **Seccomp pledge BPF whitelist** (`seccomp::pledge_syscall_list()` and
//!    `pledge_to_filter()`): filtered directly from `SYSCALL_TABLE`.
//! 4. **Seccomp pledge semantic evaluator** (`promise_allows_syscall()`):
//!    looks up `SYSCALL_TABLE` via `lookup()` so BPF and semantic pledge gates
//!    are structurally identical on syscall membership.

use crate::types::PledgePromises;

/// How a syscall entry is wired in `kernel_core::syscall::syscall_dispatcher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchStatus {
    /// Functional dispatcher arm (not a fixed ENOSYS stub).
    Dispatched,
    /// Intentionally has no dispatcher arm (falls through to ENOSYS).
    /// Excluded from `DispatchedSyscall` so a stray arm cannot even compile.
    IntentionalNoArm,
    /// Intentionally wired to a fixed ENOSYS stub arm.
    IntentionalEnosysStub,
}

/// Seccomp/pledge filtering policy for a syscall in the single table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PledgePolicy {
    /// Always allowed under every pledge promise set (`exit`, `exit_group`).
    Always,
    /// Allowed unconditionally when ANY bit in the mask is held.
    Promises(PledgePromises),
    /// Allowed when ANY bit in the mask is held AND argument-sensitive semantic
    /// gating passes (`open`/`openat` flags, `mmap`/`mprotect` `PROT_EXEC`,
    /// `clone` flags).
    Guarded(PledgePromises),
    /// Default-denied for pledged processes (callable when unpledged).
    Unpledged,
    /// R172-P6-F3: Private/native/sibling arm explicitly fenced out of pledge.
    /// Structurally disjoint from every pledge-allow variant.
    PrivateNeverPledged,
}

impl PledgePolicy {
    /// True if this syscall can be granted by at least one pledge promise set.
    #[inline]
    pub const fn is_pledged(self) -> bool {
        matches!(self, Self::Always | Self::Promises(_) | Self::Guarded(_))
    }

    /// True if this syscall is permitted (at the syscall-number level) by `promises`.
    #[inline]
    pub const fn allows_nr(self, promises: PledgePromises) -> bool {
        match self {
            Self::Always => true,
            Self::Promises(bits) | Self::Guarded(bits) => promises.intersects(bits),
            Self::Unpledged | Self::PrivateNeverPledged => false,
        }
    }
}

/// Complete single-source metadata for one syscall.
#[derive(Debug, Clone, Copy)]
pub struct SyscallSpec {
    /// Linux x86_64 or Zero-OS native syscall number.
    pub nr: u64,
    /// Canonical lowercase syscall name.
    pub name: &'static str,
    /// Exact `DispatchedSyscall` variant name (empty for `IntentionalNoArm`).
    pub variant_name: &'static str,
    /// Allowed in `SECCOMP_MODE_STRICT`.
    pub strict_allowed: bool,
    /// Must drop cached `entry_proc` before calling handler (fatal/sigreturn/exec).
    pub drops_entry_proc: bool,
    /// Dispatch wiring status.
    pub dispatch: DispatchStatus,
    /// Seccomp/pledge membership policy.
    pub pledge: PledgePolicy,
    /// Rationale for `IntentionalNoArm` / `IntentionalEnosysStub` exemptions.
    pub exemption_reason: &'static str,
}

impl SyscallSpec {
    /// True if this entry is a pledge-promised syscall that is intentionally
    /// undispatched (either `NoArm` or `EnosysStub`).
    #[inline]
    pub const fn is_pledge_exemption(&self) -> bool {
        self.pledge.is_pledged() && !matches!(self.dispatch, DispatchStatus::Dispatched)
    }

    /// True if this entry is a pledge-promised syscall with a live functional arm.
    #[inline]
    pub const fn is_dispatched_promised(&self) -> bool {
        self.pledge.is_pledged() && matches!(self.dispatch, DispatchStatus::Dispatched)
    }

    /// True if this entry is fenced out of pledge by R172-P6-F3.
    #[inline]
    pub const fn is_private_never_pledged(&self) -> bool {
        matches!(self.pledge, PledgePolicy::PrivateNeverPledged)
    }
}

// Promise shorthand constants for readable single-table rows.
const P_STDIO: PledgePromises = PledgePromises::STDIO;
const P_RPATH: PledgePromises = PledgePromises::RPATH;
const P_WPATH: PledgePromises = PledgePromises::WPATH;
const P_CPATH: PledgePromises = PledgePromises::CPATH;
const P_TMPPATH: PledgePromises = PledgePromises::TMPPATH;
const P_PATH_ANY: PledgePromises = PledgePromises::from_bits_truncate(
    P_RPATH.bits() | P_WPATH.bits() | P_CPATH.bits() | P_TMPPATH.bits(),
);
const P_VM: PledgePromises = PledgePromises::VM;
const P_PROC: PledgePromises = PledgePromises::PROC;
const P_EXEC: PledgePromises = PledgePromises::EXEC;
const P_THREAD: PledgePromises = PledgePromises::THREAD;
const P_PROC_OR_THREAD: PledgePromises =
    PledgePromises::from_bits_truncate(P_PROC.bits() | P_THREAD.bits());
const P_TIME: PledgePromises = PledgePromises::TIME;
const P_SENDSIG: PledgePromises = PledgePromises::SENDSIG;
const P_PROC_OR_SENDSIG: PledgePromises =
    PledgePromises::from_bits_truncate(P_PROC.bits() | P_SENDSIG.bits());
const P_FATTR: PledgePromises = PledgePromises::FATTR;
const P_RLIMIT: PledgePromises = PledgePromises::RLIMIT;

macro_rules! define_syscall_table {
    (
        dispatched: [
            $(
                ($d_nr:literal, $d_const:ident, $d_variant:ident, $d_name:literal,
                 strict: $d_strict:expr, drop_proc: $d_drop:expr,
                 status: $d_status:ident, pledge: $d_pledge:expr, reason: $d_reason:literal),
            )*
        ],
        no_arm: [
            $(
                ($n_nr:literal, $n_const:ident, $n_name:literal,
                 pledge: $n_pledge:expr, reason: $n_reason:literal),
            )*
        ],
    ) => {
        // 1. Canonical syscall number constants (single source of truth).
        $( pub const $d_const: u64 = $d_nr; )*
        $( pub const $n_const: u64 = $n_nr; )*

        // 2. Exhaustive enum of all syscalls that have a dispatcher arm.
        //    `no_arm` entries (e.g. `vfork(58)`) are deliberately excluded so
        //    an accidental dispatcher arm fails to compile.
        #[repr(u64)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum DispatchedSyscall {
            $( $d_variant = $d_nr, )*
        }

        impl DispatchedSyscall {
            /// Map a raw syscall number to its dispatched variant, or `None` if
            /// undispatched (ENOSYS).
            #[inline]
            pub const fn from_nr(nr: u64) -> Option<Self> {
                match nr {
                    $( $d_nr => Some(Self::$d_variant), )*
                    _ => None,
                }
            }

            /// Return the raw Linux/Zero-OS syscall number.
            #[inline]
            pub const fn as_u64(self) -> u64 {
                self as u64
            }

            /// Look up the variant from its exact Rust identifier name (for
            /// hosted parity tests).
            pub fn from_variant_name(name: &str) -> Option<Self> {
                match name {
                    $( stringify!($d_variant) => Some(Self::$d_variant), )*
                    _ => None,
                }
            }
        }

        /// Unsorted raw entry list used to construct the sorted canonical table
        /// at compile time.
        const RAW_TABLE: &[SyscallSpec] = &[
            $(
                SyscallSpec {
                    nr: $d_nr,
                    name: $d_name,
                    variant_name: stringify!($d_variant),
                    strict_allowed: $d_strict,
                    drops_entry_proc: $d_drop,
                    dispatch: DispatchStatus::$d_status,
                    pledge: $d_pledge,
                    exemption_reason: $d_reason,
                },
            )*
            $(
                SyscallSpec {
                    nr: $n_nr,
                    name: $n_name,
                    variant_name: "",
                    strict_allowed: false,
                    drops_entry_proc: false,
                    dispatch: DispatchStatus::IntentionalNoArm,
                    pledge: $n_pledge,
                    exemption_reason: $n_reason,
                },
            )*
        ];

        /// Total number of syscalls declared in the single table.
        pub const SYSCALL_TABLE_LEN: usize = RAW_TABLE.len();

        const fn build_sorted_table() -> [SyscallSpec; SYSCALL_TABLE_LEN] {
            let mut arr = [RAW_TABLE[0]; SYSCALL_TABLE_LEN];
            let mut i = 0;
            while i < SYSCALL_TABLE_LEN {
                arr[i] = RAW_TABLE[i];
                i += 1;
            }
            // Insertion sort by `nr` at compile time (table is ~138 entries).
            let mut j = 1;
            while j < SYSCALL_TABLE_LEN {
                let key = arr[j];
                let mut k = j;
                while k > 0 && arr[k - 1].nr > key.nr {
                    arr[k] = arr[k - 1];
                    k -= 1;
                }
                arr[k] = key;
                j += 1;
            }
            arr
        }

        /// Canonical syscall table, strictly sorted by ascending syscall number.
        pub const SYSCALL_TABLE: &[SyscallSpec] = &build_sorted_table();
    };
}

define_syscall_table! {
    dispatched: [
        // File I/O & core POSIX
        (0,   SYS_READ,               Read,              "read",               strict: true,  drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (1,   SYS_WRITE,              Write,             "write",              strict: true,  drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (2,   SYS_OPEN,               Open,              "open",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Guarded(P_PATH_ANY),       reason: ""),
        (3,   SYS_CLOSE,              Close,             "close",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (4,   SYS_STAT,               Stat,              "stat",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RPATH),         reason: ""),
        (5,   SYS_FSTAT,              Fstat,             "fstat",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (6,   SYS_LSTAT,              Lstat,             "lstat",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RPATH),         reason: ""),
        (7,   SYS_POLL,               Poll,              "poll",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (8,   SYS_LSEEK,              Lseek,             "lseek",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        // Memory management
        (9,   SYS_MMAP,               Mmap,              "mmap",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Guarded(P_VM),             reason: ""),
        (10,  SYS_MPROTECT,           Mprotect,          "mprotect",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Guarded(P_VM),             reason: ""),
        (11,  SYS_MUNMAP,             Munmap,            "munmap",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_VM),            reason: ""),
        (12,  SYS_BRK,                Brk,               "brk",                strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_VM),            reason: ""),
        // Signals
        (13,  SYS_RT_SIGACTION,       RtSigaction,       "rt_sigaction",       strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (14,  SYS_RT_SIGPROCMASK,     RtSigprocmask,     "rt_sigprocmask",     strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (15,  SYS_RT_SIGRETURN,       RtSigreturn,       "rt_sigreturn",       strict: true,  drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        // Extended I/O & multiplexing
        (16,  SYS_IOCTL,              Ioctl,             "ioctl",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (17,  SYS_PREAD64,            Pread64,           "pread64",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (18,  SYS_PWRITE64,           Pwrite64,          "pwrite64",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (19,  SYS_READV,              Readv,             "readv",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (20,  SYS_WRITEV,             Writev,            "writev",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (21,  SYS_ACCESS,             Access,            "access",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (22,  SYS_PIPE,               Pipe,              "pipe",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (23,  SYS_SELECT,             Select,            "select",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (24,  SYS_SCHED_YIELD,        SchedYield,        "sched_yield",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (25,  SYS_MREMAP,             Mremap,            "mremap",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_VM),            reason: ""),
        (32,  SYS_DUP,                Dup,               "dup",                strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (33,  SYS_DUP2,               Dup2,              "dup2",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (35,  SYS_NANOSLEEP,          Nanosleep,         "nanosleep",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (39,  SYS_GETPID,             Getpid,            "getpid",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        // Sockets (Linux x86_64 ABI)
        (41,  SYS_SOCKET,             Socket,            "socket",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (42,  SYS_CONNECT,            Connect,           "connect",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (43,  SYS_ACCEPT,             Accept,            "accept",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (44,  SYS_SENDTO,             Sendto,            "sendto",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (45,  SYS_RECVFROM,           Recvfrom,          "recvfrom",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (46,  SYS_SENDMSG,            Sendmsg,           "sendmsg",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (47,  SYS_RECVMSG,            Recvmsg,           "recvmsg",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (48,  SYS_SHUTDOWN,           Shutdown,          "shutdown",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (49,  SYS_BIND,               Bind,              "bind",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (50,  SYS_LISTEN,             Listen,            "listen",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (51,  SYS_GETSOCKNAME,        Getsockname,       "getsockname",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (52,  SYS_GETPEERNAME,        Getpeername,       "getpeername",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (54,  SYS_SETSOCKOPT,         Setsockopt,        "setsockopt",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (55,  SYS_GETSOCKOPT,         Getsockopt,        "getsockopt",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        // Process lifecycle
        (56,  SYS_CLONE,              Clone,             "clone",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Guarded(P_PROC_OR_THREAD), reason: ""),
        (57,  SYS_FORK,               Fork,              "fork",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_PROC),          reason: ""),
        (59,  SYS_EXECVE,             Execve,            "execve",             strict: false, drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Promises(P_EXEC),          reason: ""),
        (60,  SYS_EXIT,               Exit,              "exit",               strict: true,  drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Always,                    reason: ""),
        (61,  SYS_WAIT4,              Wait4,             "wait4",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_PROC),          reason: ""),
        (62,  SYS_KILL,               Kill,              "kill",               strict: false, drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Promises(P_PROC_OR_SENDSIG), reason: ""),
        (63,  SYS_UNAME,              Uname,             "uname",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        // File descriptors, durability, filesystem operations
        (72,  SYS_FCNTL,              Fcntl,             "fcntl",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (74,  SYS_FSYNC,              Fsync,             "fsync",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (75,  SYS_FDATASYNC,          Fdatasync,         "fdatasync",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (77,  SYS_FTRUNCATE,          Ftruncate,         "ftruncate",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (79,  SYS_GETCWD,             Getcwd,            "getcwd",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (80,  SYS_CHDIR,              Chdir,             "chdir",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (82,  SYS_RENAME,             Rename,            "rename",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_WPATH),         reason: ""),
        (83,  SYS_MKDIR,              Mkdir,             "mkdir",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_CPATH),         reason: ""),
        (84,  SYS_RMDIR,              Rmdir,             "rmdir",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_CPATH),         reason: ""),
        (86,  SYS_LINK,               Link,              "link",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_CPATH),         reason: ""),
        (87,  SYS_UNLINK,             Unlink,            "unlink",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_WPATH),         reason: ""),
        (88,  SYS_SYMLINK,            Symlink,           "symlink",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_WPATH),         reason: ""),
        (89,  SYS_READLINK,           Readlink,          "readlink",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RPATH),         reason: ""),
        // File attributes (chmod/fchmod return EOPNOTSUPP; chown/fchown/lchown return ENOSYS)
        (90,  SYS_CHMOD,              Chmod,             "chmod",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_FATTR),         reason: ""),
        (91,  SYS_FCHMOD,             Fchmod,            "fchmod",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_FATTR),         reason: ""),
        (92,  SYS_CHOWN,              Chown,             "chown",              strict: false, drop_proc: false, status: IntentionalEnosysStub, pledge: PledgePolicy::Promises(P_FATTR),         reason: "chown: FATTR, ENOSYS stub arm (M0-6 later slice)"),
        (93,  SYS_FCHOWN,             Fchown,            "fchown",             strict: false, drop_proc: false, status: IntentionalEnosysStub, pledge: PledgePolicy::Promises(P_FATTR),         reason: "fchown: FATTR (post-const-fix), ENOSYS stub arm (M0-6 later slice)"),
        (94,  SYS_LCHOWN,             Lchown,            "lchown",             strict: false, drop_proc: false, status: IntentionalEnosysStub, pledge: PledgePolicy::Unpledged,                 reason: "lchown: ENOSYS stub arm (unpledged)"),
        (95,  SYS_UMASK,              Umask,             "umask",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (96,  SYS_GETTIMEOFDAY,       Gettimeofday,      "gettimeofday",       strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (97,  SYS_GETRLIMIT,          Getrlimit,         "getrlimit",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RLIMIT),        reason: ""),
        // Credentials
        (102, SYS_GETUID,             Getuid,            "getuid",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (104, SYS_GETGID,             Getgid,            "getgid",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (107, SYS_GETEUID,            Geteuid,           "geteuid",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (108, SYS_GETEGID,            Getegid,           "getegid",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (110, SYS_GETPPID,            Getppid,           "getppid",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        // Root/prctl/arch/rlimit/sync
        (155, SYS_PIVOT_ROOT,         PivotRoot,         "pivot_root",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (157, SYS_PRCTL,              Prctl,             "prctl",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (158, SYS_ARCH_PRCTL,         ArchPrctl,         "arch_prctl",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (160, SYS_SETRLIMIT,          Setrlimit,         "setrlimit",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RLIMIT),        reason: ""),
        (161, SYS_CHROOT,             Chroot,            "chroot",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (162, SYS_SYNC,               Sync,              "sync",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        // Threading, scheduling, directories, time
        (186, SYS_GETTID,             Gettid,            "gettid",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (200, SYS_TKILL,              Tkill,             "tkill",              strict: false, drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (202, SYS_FUTEX,              Futex,             "futex",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_THREAD),        reason: ""),
        (203, SYS_SCHED_SETAFFINITY,  SchedSetaffinity,  "sched_setaffinity",  strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (204, SYS_SCHED_GETAFFINITY,  SchedGetaffinity,  "sched_getaffinity",  strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (217, SYS_GETDENTS64,         Getdents64,        "getdents64",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RPATH),         reason: ""),
        (218, SYS_SET_TID_ADDRESS,    SetTidAddress,     "set_tid_address",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_THREAD),        reason: ""),
        (228, SYS_CLOCK_GETTIME,      ClockGettime,      "clock_gettime",      strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_TIME),          reason: ""),
        (231, SYS_EXIT_GROUP,         ExitGroup,         "exit_group",         strict: true,  drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Always,                    reason: ""),
        (234, SYS_TGKILL,             Tgkill,            "tgkill",             strict: false, drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (247, SYS_WAITID,             Waitid,            "waitid",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_PROC),          reason: ""),
        // *at(), namespaces, robust list, modern POSIX
        (257, SYS_OPENAT,             Openat,            "openat",             strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Guarded(P_PATH_ANY),       reason: ""),
        (262, SYS_FSTATAT,            Fstatat,           "newfstatat",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::PrivateNeverPledged,       reason: ""),
        (264, SYS_RENAMEAT,           Renameat,          "renameat",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::PrivateNeverPledged,       reason: ""),
        (270, SYS_PSELECT6,           Pselect6,          "pselect6",           strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (271, SYS_PPOLL,              Ppoll,             "ppoll",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (272, SYS_UNSHARE,            Unshare,           "unshare",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (273, SYS_SET_ROBUST_LIST,    SetRobustList,     "set_robust_list",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (274, SYS_GET_ROBUST_LIST,    GetRobustList,     "get_robust_list",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (277, SYS_SYNC_FILE_RANGE,    SyncFileRange,     "sync_file_range",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_STDIO),         reason: ""),
        (288, SYS_ACCEPT4,            Accept4,           "accept4",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (292, SYS_DUP3,               Dup3,              "dup3",               strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (293, SYS_PIPE2,              Pipe2,             "pipe2",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (302, SYS_PRLIMIT64,          Prlimit64,         "prlimit64",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_RLIMIT),        reason: ""),
        (308, SYS_SETNS,              Setns,             "setns",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (316, SYS_RENAMEAT2,          Renameat2,         "renameat2",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::PrivateNeverPledged,       reason: ""),
        (317, SYS_SECCOMP,            Seccomp,           "seccomp",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (318, SYS_GETRANDOM,          Getrandom,         "getrandom",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Promises(P_TIME),          reason: ""),
        (332, SYS_STATX,              Statx,             "statx",              strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (437, SYS_OPENAT2,            Openat2,           "openat2",            strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::PrivateNeverPledged,       reason: ""),
        // Zero-OS native syscalls (500-524)
        (500, SYS_CGROUP_CREATE,      CgroupCreate,      "cgroup_create",      strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (501, SYS_CGROUP_DESTROY,     CgroupDestroy,     "cgroup_destroy",     strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (502, SYS_CGROUP_ATTACH,      CgroupAttach,      "cgroup_attach",      strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (503, SYS_CGROUP_SET_LIMIT,   CgroupSetLimit,    "cgroup_set_limit",   strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (504, SYS_CGROUP_GET_STATS,   CgroupGetStats,    "cgroup_get_stats",   strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (505, SYS_COMPLIANCE_STATUS,  ComplianceStatus,  "compliance_status",  strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (506, SYS_FIPS_ENABLE,        FipsEnable,        "fips_enable",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (507, SYS_COMPLIANCE_QUERY,   ComplianceQuery,   "compliance_query",   strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (508, SYS_AUDIT_EXPORT,       AuditExport,       "audit_export",       strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (509, SYS_KPATCH_LOAD,        KpatchLoad,        "kpatch_load",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (510, SYS_KPATCH_ENABLE,      KpatchEnable,      "kpatch_enable",      strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (511, SYS_KPATCH_DISABLE,     KpatchDisable,     "kpatch_disable",     strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (512, SYS_KPATCH_UNLOAD,      KpatchUnload,      "kpatch_unload",      strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (513, SYS_CGROUP_DELEGATE,    CgroupDelegate,    "cgroup_delegate",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (514, SYS_KPATCH_ENABLE_ALL,  KpatchEnableAll,   "kpatch_enable_all",  strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (515, SYS_KPATCH_DISABLE_ALL, KpatchDisableAll,  "kpatch_disable_all", strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (516, SYS_CGROUP_GET_STATS2,  CgroupGetStats2,   "cgroup_get_stats2",  strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (517, SYS_SPAWN_IMAGE,        SpawnImage,        "spawn_image",        strict: false, drop_proc: true,  status: Dispatched,            pledge: PledgePolicy::PrivateNeverPledged,       reason: ""),
        (518, SYS_MOVE_NET_DEVICE,    MoveNetDevice,     "move_net_device",    strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (520, SYS_KCOV_INIT,          KcovInit,          "kcov_init",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (521, SYS_KCOV_ENABLE,        KcovEnable,        "kcov_enable",        strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (522, SYS_KCOV_DISABLE,       KcovDisable,       "kcov_disable",       strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (523, SYS_KCOV_DUMP,          KcovDump,          "kcov_dump",          strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
        (524, SYS_KCOV_RESET,         KcovReset,         "kcov_reset",         strict: false, drop_proc: false, status: Dispatched,            pledge: PledgePolicy::Unpledged,                 reason: ""),
    ],
    no_arm: [
        (58,  SYS_VFORK, "vfork", pledge: PledgePolicy::Promises(P_PROC), reason: "vfork: deliberate ENOSYS-by-invariant (sys_clone documents the fallback)"),
    ],
}

/// Binary-search `SYSCALL_TABLE` by syscall number (`const fn`, allocation-free).
#[inline]
pub const fn lookup(nr: u64) -> Option<&'static SyscallSpec> {
    let mut lo = 0usize;
    let mut hi = SYSCALL_TABLE.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mid_nr = SYSCALL_TABLE[mid].nr;
        if mid_nr == nr {
            return Some(&SYSCALL_TABLE[mid]);
        } else if mid_nr < nr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    None
}

/// True if `syscall_dispatcher` must release cached `entry_proc` before
/// invoking this syscall's handler (fatal / non-unwinding / sigreturn / exec).
#[inline]
pub const fn drops_entry_proc(nr: u64) -> bool {
    match lookup(nr) {
        Some(spec) => spec.drops_entry_proc,
        None => false,
    }
}

/// Count of syscalls marked `strict_allowed == true` in `SYSCALL_TABLE`.
pub const STRICT_ALLOWED_COUNT: usize = {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < SYSCALL_TABLE.len() {
        if SYSCALL_TABLE[i].strict_allowed {
            count += 1;
        }
        i += 1;
    }
    count
};

/// Sorted array of syscall numbers permitted in `SECCOMP_MODE_STRICT`,
/// derived at compile time from `SYSCALL_TABLE`.
pub const STRICT_ALLOWED: [u64; STRICT_ALLOWED_COUNT] = {
    let mut out = [0u64; STRICT_ALLOWED_COUNT];
    let mut i = 0usize;
    let mut w = 0usize;
    while i < SYSCALL_TABLE.len() {
        if SYSCALL_TABLE[i].strict_allowed {
            out[w] = SYSCALL_TABLE[i].nr;
            w += 1;
        }
        i += 1;
    }
    out
};

/// Total distinct syscalls grantable by `PledgePromises::all()`, derived from
/// `SYSCALL_TABLE` at compile time.
pub const PLEDGE_UNION_COUNT: usize = {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < SYSCALL_TABLE.len() {
        if SYSCALL_TABLE[i].pledge.is_pledged() {
            count += 1;
        }
        i += 1;
    }
    count
};

/// Total pledge-promised syscalls that are intentionally undispatched.
pub const PLEDGE_EXEMPTION_COUNT: usize = {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < SYSCALL_TABLE.len() {
        if SYSCALL_TABLE[i].is_pledge_exemption() {
            count += 1;
        }
        i += 1;
    }
    count
};

// ============================================================================
// Compile-time table invariants (zero-runtime-cost drift fences)
// ============================================================================

const _: () = {
    // 1. Strictly increasing syscall numbers (zero duplicates, valid binary search).
    let mut i = 1usize;
    while i < SYSCALL_TABLE.len() {
        assert!(SYSCALL_TABLE[i - 1].nr < SYSCALL_TABLE[i].nr);
        i += 1;
    }

    // 2. Every pledged syscall fits inside the 512-bit FastAllowSet boundary,
    //    and every Promises/Guarded entry specifies non-empty promise bits.
    let mut j = 0usize;
    while j < SYSCALL_TABLE.len() {
        let spec = SYSCALL_TABLE[j];
        if spec.pledge.is_pledged() {
            assert!(spec.nr < 512);
        }
        match spec.pledge {
            PledgePolicy::Promises(bits) | PledgePolicy::Guarded(bits) => {
                assert!(!bits.is_empty());
            }
            _ => {}
        }
        if spec.strict_allowed {
            assert!(matches!(spec.dispatch, DispatchStatus::Dispatched));
        }
        j += 1;
    }

    // 3. Exact strict-mode syscall count (read, write, rt_sigreturn, exit, exit_group).
    assert!(STRICT_ALLOWED_COUNT == 5);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pledge_syscall_list, strict_filter, types};

    #[test]
    fn table_lookup_matches_every_entry_and_dispatched_enum() {
        for spec in SYSCALL_TABLE {
            let found = lookup(spec.nr).expect("every table entry must resolve via lookup");
            assert_eq!(found.nr, spec.nr);
            assert_eq!(found.name, spec.name);

            let dispatched = DispatchedSyscall::from_nr(spec.nr);
            match spec.dispatch {
                DispatchStatus::IntentionalNoArm => {
                    assert!(
                        dispatched.is_none(),
                        "IntentionalNoArm {} ({}) must not be in DispatchedSyscall",
                        spec.nr,
                        spec.name
                    );
                }
                DispatchStatus::Dispatched | DispatchStatus::IntentionalEnosysStub => {
                    let variant =
                        dispatched.expect("dispatched entry must resolve in DispatchedSyscall");
                    assert_eq!(variant.as_u64(), spec.nr);
                    assert_eq!(
                        DispatchedSyscall::from_variant_name(spec.variant_name),
                        Some(variant)
                    );
                }
            }
        }
        assert!(DispatchedSyscall::from_nr(SYS_VFORK).is_none());
        assert!(DispatchedSyscall::from_nr(9999).is_none());
    }

    #[test]
    fn strict_filter_generated_from_table_matches_exact_set() {
        assert_eq!(
            STRICT_ALLOWED,
            [
                SYS_READ,
                SYS_WRITE,
                SYS_RT_SIGRETURN,
                SYS_EXIT,
                SYS_EXIT_GROUP
            ]
        );
        let filter = strict_filter();
        let args = [0u64; 6];
        for nr in 0..=600u64 {
            let expected = if STRICT_ALLOWED.contains(&nr) {
                types::SeccompAction::Allow
            } else {
                types::SeccompAction::Kill
            };
            assert_eq!(
                filter.evaluate(nr, &args),
                expected,
                "strict filter mismatch for syscall {nr}"
            );
        }
    }

    #[test]
    fn pledge_bpf_list_and_semantic_gate_are_bijective_for_all_promises() {
        let single_bits = [
            PledgePromises::STDIO,
            PledgePromises::RPATH,
            PledgePromises::WPATH,
            PledgePromises::CPATH,
            PledgePromises::TMPPATH,
            PledgePromises::VM,
            PledgePromises::PROC,
            PledgePromises::EXEC,
            PledgePromises::THREAD,
            PledgePromises::TIME,
            PledgePromises::SENDSIG,
            PledgePromises::FATTR,
            PledgePromises::RLIMIT,
            PledgePromises::all(),
        ];

        for promises in single_bits {
            let bpf_list = pledge_syscall_list(promises);
            for nr in 0..=600u64 {
                let in_bpf = bpf_list.contains(&nr);
                let spec = lookup(nr);
                let is_guarded = matches!(spec.map(|s| s.pledge), Some(PledgePolicy::Guarded(_)));
                if !is_guarded {
                    assert_eq!(
                        in_bpf,
                        types::promise_allows_syscall_probe(promises, nr),
                        "BPF/semantic mismatch for promises={promises:?} nr={nr}"
                    );
                } else if !in_bpf {
                    assert!(
                        !types::promise_allows_syscall_probe(promises, nr),
                        "semantic gate allowed guarded nr={nr} not in BPF list for {promises:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn guarded_syscalls_enforce_argument_semantics() {
        let mut guarded_nrs = alloc::vec::Vec::new();
        for spec in SYSCALL_TABLE {
            if matches!(spec.pledge, PledgePolicy::Guarded(_)) {
                guarded_nrs.push(spec.nr);
            }
        }
        assert_eq!(
            guarded_nrs,
            alloc::vec![SYS_OPEN, SYS_MMAP, SYS_MPROTECT, SYS_CLONE, SYS_OPENAT]
        );

        // open: O_RDONLY ok under RPATH, O_WRONLY denied under RPATH
        assert!(types::promise_allows_syscall_with_args(
            PledgePromises::RPATH,
            SYS_OPEN,
            &[0, 0, 0, 0, 0, 0]
        ));
        assert!(!types::promise_allows_syscall_with_args(
            PledgePromises::RPATH,
            SYS_OPEN,
            &[0, 1, 0, 0, 0, 0]
        ));

        // mmap/mprotect: PROT_EXEC denied under VM alone, allowed with VM|PROT_EXEC
        assert!(types::promise_allows_syscall_with_args(
            PledgePromises::VM,
            SYS_MMAP,
            &[0, 0, 3, 0, 0, 0]
        ));
        assert!(!types::promise_allows_syscall_with_args(
            PledgePromises::VM,
            SYS_MMAP,
            &[0, 0, 5, 0, 0, 0]
        ));
        assert!(types::promise_allows_syscall_with_args(
            PledgePromises::VM | PledgePromises::PROT_EXEC,
            SYS_MPROTECT,
            &[0, 0, 5, 0, 0, 0]
        ));

        // clone: THREAD alone rejects fork-like flags=0, accepts CLONE_VM|CLONE_SIGHAND|CLONE_THREAD
        assert!(!types::promise_allows_syscall_with_args(
            PledgePromises::THREAD,
            SYS_CLONE,
            &[0; 6]
        ));
        assert!(types::promise_allows_syscall_with_args(
            PledgePromises::THREAD,
            SYS_CLONE,
            &[0x0001_0900, 0, 0, 0, 0, 0]
        ));
        // clone: PROC rejects CLONE_NEWPID (0x2000_0000)
        assert!(!types::promise_allows_syscall_with_args(
            PledgePromises::PROC,
            SYS_CLONE,
            &[0x2000_0000, 0, 0, 0, 0, 0]
        ));
    }
}
