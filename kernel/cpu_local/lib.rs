//! Minimal per-CPU storage for SMP support
//!
//! Provides a bounded per-CPU storage abstraction indexed by logical CPU IDs.
//! Early bootstrap retains a narrow CPU-0 fallback, but normal SMP operation
//! resolves registered LAPIC identities and fails closed for unknown topology.
//! Topology-sensitive users should use the strict registered-and-online APIs.
//!
//! # Usage
//!
//! ```rust,ignore
//! use cpu_local::CpuLocal;
//! use core::sync::atomic::AtomicUsize;
//!
//! static MY_DATA: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));
//!
//! MY_DATA.with(|d| d.fetch_add(1, Ordering::SeqCst));
//! ```

#![no_std]

#[cfg(all(feature = "host_harness", target_os = "none"))]
compile_error!(
    "cpu_local/host_harness is test-only and must never be enabled for a bare-metal kernel build"
);

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use spin::{Mutex, Once};

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 64;

// The online-CPU topology is represented by one u64. Keep the capacity and
// its bitmap representation coupled at compile time so a future capacity bump
// cannot turn a shift below into undefined topology admission.
const _: () = assert!(MAX_CPUS <= u64::BITS as usize);

/// Invalid LAPIC ID marker
const INVALID_LAPIC_ID: u32 = u32::MAX;

/// Invalid CPU ID marker for reverse mapping
const INVALID_CPU_ID: usize = usize::MAX;

/// Size of LAPIC ID reverse mapping table (covers all 8-bit LAPIC IDs)
const LAPIC_ID_REVERSE_MAP_SIZE: usize = 256;

/// Architected xAPIC MMIO base address (Intel SDM reset default).
///
/// R169-L7 FIX: the single named source for the LAPIC MMIO base. The kernel runs
/// the local APIC in xAPIC mode at this base, and the identity-map hardening
/// carve-out preserves exactly this page, so `current_cpu_id()` and `arch::apic`
/// must agree on it. `arch::apic::LAPIC_DEFAULT_BASE` and `arch::ipi::LAPIC_BASE`
/// are derived from this constant rather than re-declaring the literal.
pub const LAPIC_MMIO_DEFAULT_BASE: u32 = 0xFEE0_0000;

/// R151-6 FIX: Flag set when SMP bring-up is complete.
///
/// After this point, `current_cpu_id()` must not silently fall back to CPU 0
/// because doing so aliases per-CPU slots and corrupts TLB shootdown mailboxes,
/// IRQ nesting counters, FPU save areas, and scheduler state.
static CPU_LOCAL_SMP_DONE: AtomicBool = AtomicBool::new(false);

/// Global NMI nesting depth used by no-allocation asynchronous-context gates.
///
/// This is intentionally global rather than CPU-local: an NMI can arrive
/// before the heap-backed `CpuLocal` storage is initialized, when consulting a
/// per-CPU slot would itself be unsafe. Best-effort facilities conservatively
/// drop work on every CPU while any NMI is active; that trades a negligible
/// sampling gap for an early-boot-safe, allocation-free fail-closed policy.
static NMI_CONTEXT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Mark SMP initialization complete for the cpu_local subsystem.
///
/// Called by arch SMP bring-up code once all CPU registrations are finished.
/// After this call, `current_cpu_id()` will panic instead of returning 0 for
/// unregistered LAPIC IDs.
#[inline]
pub fn set_smp_init_done() {
    CPU_LOCAL_SMP_DONE.store(true, Ordering::Release);
}

/// Enter an NMI context without consulting heap-backed CPU-local storage.
///
/// The architecture entry stub calls this before any work that may reach an
/// allocator, lock, or KCOV tracepoint. Nested NMIs are supported.
#[inline]
pub fn nmi_enter() {
    NMI_CONTEXT_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_add(1)
        })
        .expect("NMI nesting counter overflow");
}

/// Leave an NMI context entered through [`nmi_enter`].
#[inline]
pub fn nmi_exit() {
    let result = NMI_CONTEXT_COUNT.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
        count.checked_sub(1)
    });
    assert!(result.is_ok(), "nmi_exit called with count already 0");
}

/// Return whether any CPU is currently executing an NMI handler.
///
/// This global answer deliberately makes best-effort tracing conservative on
/// another CPU as well, which is necessary before per-CPU storage exists.
#[inline]
pub fn nmi_active() -> bool {
    NMI_CONTEXT_COUNT.load(Ordering::Acquire) > 0
}

/// Authoritative LAPIC MMIO base shared by `current_cpu_id()` and `arch::apic`.
///
/// R169-L7 FIX: single runtime source of truth for the LAPIC MMIO base. Both the
/// per-CPU-id lookup in `current_cpu_id()` and `arch::apic::{lapic_read,
/// lapic_write}` read this one atomic, replacing the three previously-duplicated
/// hard-coded `0xFEE0_0000` copies (the old `apic::LAPIC_BASE` static, the
/// `current_cpu_id()` literal, and the dead `ipi::LAPIC_BASE` const). `arch::apic`
/// validates the physical aperture against IA32_APIC_BASE, then publishes its
/// permanent high-half mapping after memory initialization. Before publication,
/// early boot alone uses the identity address.
static LAPIC_MMIO_BASE: AtomicU64 = AtomicU64::new(LAPIC_MMIO_DEFAULT_BASE as u64);

/// True once the platform is operating the local APIC in x2APIC mode.
///
/// R169-L7 FIX: in x2APIC mode the APIC ID is delivered via an MSR, can exceed
/// 8 bits (overflowing the 256-entry `LAPIC_ID_REVERSE_MAP`), and the xAPIC MMIO
/// ID register is invalid. `current_cpu_id()` fails closed when this is set rather
/// than read a bogus ID and alias another CPU's per-CPU slot. Published by
/// `arch::apic` at LAPIC init; the current kernel never enables x2APIC.
static X2APIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Read the authoritative LAPIC MMIO base (see [`LAPIC_MMIO_BASE`]).
#[inline]
pub fn lapic_mmio_base() -> u64 {
    LAPIC_MMIO_BASE.load(Ordering::Acquire)
}

/// Publish the LAPIC MMIO base. Called by `arch::apic` at LAPIC init.
///
/// # Panics
///
/// Panics if `base` is not 4 KiB aligned (a malformed APIC base would desync the
/// register reads from the page tables).
///
/// # Safety
///
/// The complete register page must be mapped as supervisor MMIO in every kernel
/// address space that can execute a consumer. Publish before starting other CPUs.
#[inline]
pub unsafe fn set_lapic_mmio_base(base: u64) {
    assert_eq!(
        base & 0xFFF,
        0,
        "LAPIC MMIO base {:#x} must be 4 KiB aligned",
        base
    );
    LAPIC_MMIO_BASE.store(base, Ordering::Release);
}

/// Report whether the local APIC is operating in x2APIC mode.
#[inline]
pub fn x2apic_active() -> bool {
    X2APIC_ACTIVE.load(Ordering::Acquire)
}

/// Publish the x2APIC-mode flag. Called by `arch::apic` at LAPIC init.
#[inline]
pub fn set_x2apic_active(active: bool) {
    X2APIC_ACTIVE.store(active, Ordering::Release);
}

/// Marker for "no FPU owner" in per-CPU lazy FPU tracking
pub const NO_FPU_OWNER: usize = usize::MAX;

/// LAPIC ID to CPU index mapping table.
///
/// Index = CPU logical index, Value = hardware LAPIC ID.
/// Used by `current_cpu_id()` to map LAPIC ID to CPU index.
#[allow(clippy::declare_interior_mutable_const)]
static LAPIC_ID_MAP: [AtomicU32; MAX_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
    [INIT; MAX_CPUS]
};

/// R67-8 FIX: Reverse mapping for O(1) LAPIC ID to CPU index lookup.
///
/// Index = hardware LAPIC ID (0..255), Value = CPU logical index.
/// This enables fast CPU ID lookup in syscall entry without linear search.
#[allow(clippy::declare_interior_mutable_const)]
static LAPIC_ID_REVERSE_MAP: [AtomicUsize; LAPIC_ID_REVERSE_MAP_SIZE] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; LAPIC_ID_REVERSE_MAP_SIZE]
};

/// Serializes LAPIC-ID registration so the forward and reverse maps remain a
/// bijection while AP topology is being admitted. Registration runs only
/// during BSP/AP bring-up, before ordinary interrupt traffic begins.
static CPU_ID_REGISTRATION_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// C3 repair 2 (#90): the current CPU's id from IA32_TSC_AUX
// ============================================================================
//
// Under TCG every MMIO read takes QEMU's global lock, and the LAPIC ID read
// was the kernel's most frequent one: every per-CPU access made it. Each CPU
// now writes its logical id plus one to IA32_TSC_AUX once (`publish_identity`),
// and once every online CPU has, the lookup executes RDPID or RDTSCP instead
// (`select_identity_method`). CPUID alone decides whether the MSR is touched:
// no probe may fault. The LAPIC stays the authority: each CPU checks its value
// against the LAPIC when it publishes and on every timer tick
// (`check_identity_tick`), and a value that names no registered CPU falls back
// to the LAPIC read.

/// IA32_TSC_AUX. RDTSCP returns it in ECX, RDPID in its operand.
#[cfg(not(feature = "host_harness"))]
const IA32_TSC_AUX: u32 = 0xC000_0103;

/// Issue #109 §2.1: Fixed byte offset inside the Ring-0 `IA32_GS_BASE` per-CPU
/// record (`arch::syscall::SyscallPerCpu`) where each CPU stores its encoded
/// logical CPU ID (`cpu_id + 1`, so `0` is always invalid/fail-closed).
pub const GS_CPU_ID_OFFSET: usize = 80;

/// Issue #109 §2.1: Fixed byte offset inside the Ring-0 `IA32_GS_BASE` per-CPU
/// record where each CPU stores a direct pointer to its `&'static PerCpuData`
/// slot (`PER_CPU_DATA[cpu_id]`), enabling single-instruction `current_cpu()`.
pub const GS_PER_CPU_DATA_PTR_OFFSET: usize = 88;

/// How [`current_cpu_id`] finds the current CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityMethod {
    /// Read the LAPIC ID register and map it. The only method until
    /// [`select_identity_method`], and the fallback of the other methods.
    Lapic = 0,
    /// RDTSCP, which also reads the time-stamp counter.
    Rdtscp = 1,
    /// RDPID.
    Rdpid = 2,
    /// Issue #109 §2.1: Ring-0 `IA32_GS_BASE` direct per-CPU read (`mov gs:[80]`).
    GsBase = 3,
}

impl IdentityMethod {
    /// The name the boot line and `/proc/schedstat` print.
    pub const fn name(self) -> &'static str {
        match self {
            IdentityMethod::Lapic => "lapic",
            IdentityMethod::Rdtscp => "rdtscp",
            IdentityMethod::Rdpid => "rdpid",
            IdentityMethod::GsBase => "gsbase",
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            1 => IdentityMethod::Rdtscp,
            2 => IdentityMethod::Rdpid,
            3 => IdentityMethod::GsBase,
            _ => IdentityMethod::Lapic,
        }
    }
}

/// CPUID reports RDTSCP (CPUID.80000001H:EDX[27]).
const REPORTS_RDTSCP: u8 = 1 << 0;
/// CPUID reports RDPID (CPUID.(EAX=7,ECX=0):ECX[22]).
const REPORTS_RDPID: u8 = 1 << 1;

/// The method in use. It changes at most once, from `Lapic`, in
/// [`select_identity_method`], after every online CPU published and verified
/// its id. There is no CPU hotplug and no resume path; a CPU that came online
/// after the selection would have to publish before its first lookup.
static IDENTITY_METHOD: AtomicU8 = AtomicU8::new(IdentityMethod::Lapic as u8);

/// What every CPU that has published so far reports. Each CPU clears the bits
/// it lacks.
static IDENTITY_COMMON: AtomicU8 = AtomicU8::new(REPORTS_RDTSCP | REPORTS_RDPID);

/// One bit per CPU that wrote and verified its IA32_TSC_AUX.
static IDENTITY_PUBLISHED: AtomicU64 = AtomicU64::new(0);

/// Issue #109 §2.1: One bit per CPU that populated and verified its Ring-0
/// `IA32_GS_BASE` per-CPU `encoded_cpu_id` (`gs:[80]`) and `per_cpu_data_ptr`
/// (`gs:[88]`) against hardware LAPIC identity.
static GS_IDENTITY_PUBLISHED: AtomicU64 = AtomicU64::new(0);

/// Tick cross-checks made by one CPU, on a cache line of its own.
#[repr(align(64))]
struct IdentityChecks(AtomicU64);

static IDENTITY_CHECKS: [IdentityChecks; MAX_CPUS] =
    [const { IdentityChecks(AtomicU64::new(0)) }; MAX_CPUS];

/// The logical CPU an IA32_TSC_AUX value names: the value minus one. Zero,
/// and a value past `MAX_CPUS`, name none.
#[cfg_attr(feature = "host_harness", allow(dead_code))]
const fn identity_value_cpu(value: u64) -> Option<usize> {
    if value == 0 || value > MAX_CPUS as u64 {
        None
    } else {
        Some(value as usize - 1)
    }
}

/// The CPU an IA32_TSC_AUX value names, if that CPU is registered: its two
/// LAPIC maps agree (R187-7).
#[cfg_attr(feature = "host_harness", allow(dead_code))]
fn identity_value_registered_cpu(value: u64) -> Option<usize> {
    let cpu_id = identity_value_cpu(value)?;
    lapic_id_for_cpu(cpu_id).map(|_| cpu_id)
}

/// The method the CPUs allow. RDPID if every CPU reported it, else RDTSCP if
/// every CPU reported that, else the LAPIC read; and the LAPIC read unless
/// every online CPU has published.
const fn identity_method_for(common: u8, published: u64, online: u64) -> IdentityMethod {
    if online == 0 || published & online != online {
        IdentityMethod::Lapic
    } else if common & REPORTS_RDPID != 0 {
        IdentityMethod::Rdpid
    } else if common & REPORTS_RDTSCP != 0 {
        IdentityMethod::Rdtscp
    } else {
        IdentityMethod::Lapic
    }
}

/// Issue #109 §2.1: Prefer Ring-0 `GsBase` once every online CPU has published
/// and LAPIC-verified its `gs:[GS_CPU_ID_OFFSET]` and `gs:[GS_PER_CPU_DATA_PTR_OFFSET]`;
/// otherwise fall back cleanly to `RDPID` -> `RDTSCP` -> `LAPIC`.
const fn identity_method_with_gs(
    gs_published: u64,
    common: u8,
    published: u64,
    online: u64,
) -> IdentityMethod {
    if online != 0 && gs_published & online == online {
        IdentityMethod::GsBase
    } else {
        identity_method_for(common, published, online)
    }
}

/// The method [`current_cpu_id`] uses now.
#[inline]
pub fn identity_method() -> IdentityMethod {
    IdentityMethod::from_u8(IDENTITY_METHOD.load(Ordering::Acquire))
}

/// The CPUs that published their active fast-path identity (bit N = CPU N).
#[inline]
pub fn identity_published_mask() -> u64 {
    match identity_method() {
        IdentityMethod::GsBase => GS_IDENTITY_PUBLISHED.load(Ordering::Acquire),
        _ => IDENTITY_PUBLISHED.load(Ordering::Acquire),
    }
}

/// Tick cross-checks made by `cpu_id`.
#[inline]
pub fn identity_checks(cpu_id: usize) -> u64 {
    IDENTITY_CHECKS
        .get(cpu_id)
        .map_or(0, |checks| checks.0.load(Ordering::Relaxed))
}

/// Tick cross-checks made by all CPUs.
pub fn identity_checks_total() -> u64 {
    IDENTITY_CHECKS.iter().fold(0u64, |sum, checks| {
        sum.wrapping_add(checks.0.load(Ordering::Relaxed))
    })
}

/// What CPUID on this CPU reports of RDTSCP and RDPID.
#[cfg(not(feature = "host_harness"))]
#[allow(unused_unsafe)]
fn cpuid_identity_reports() -> u8 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    let mut reports = 0;
    // SAFETY: CPUID exists on every x86-64 CPU; each leaf is read only after
    // its maximum-leaf check.
    unsafe {
        if __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ecx & (1 << 22) != 0 {
            reports |= REPORTS_RDPID;
        }
        if __cpuid(0x8000_0000).eax >= 0x8000_0001 && __cpuid(0x8000_0001).edx & (1 << 27) != 0 {
            reports |= REPORTS_RDTSCP;
        }
    }
    reports
}

/// IA32_TSC_AUX through RDTSCP. Not `pure`: every call reads hardware (I7).
#[cfg(not(feature = "host_harness"))]
#[inline(always)]
fn read_tsc_aux_rdtscp() -> u64 {
    let aux: u32;
    // SAFETY: executed only when CPUID reported RDTSCP on this CPU
    // (`publish_identity`) or on every CPU (`select_identity_method`). It
    // writes EAX, EDX and ECX and touches no memory.
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") _,
            out("edx") _,
            out("ecx") aux,
            options(nomem, nostack, preserves_flags)
        );
    }
    u64::from(aux)
}

/// IA32_TSC_AUX through RDPID. Not `pure`: every call reads hardware (I7).
#[cfg(not(feature = "host_harness"))]
#[inline(always)]
fn read_tsc_aux_rdpid() -> u64 {
    let value: u64;
    // SAFETY: executed only when CPUID reported RDPID on this CPU
    // (`publish_identity`) or on every CPU (`select_identity_method`). It
    // writes one register and touches no memory.
    unsafe {
        core::arch::asm!(
            "rdpid {}",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write IA32_TSC_AUX on this CPU.
///
/// # Safety
///
/// CPUID on this CPU must report RDTSCP or RDPID, so that the MSR exists.
#[cfg(not(feature = "host_harness"))]
unsafe fn write_tsc_aux(value: u64) {
    // SAFETY: the caller established that the MSR exists. WRMSR touches no
    // memory and leaves the flags alone.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_TSC_AUX,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Publish this CPU's id in IA32_TSC_AUX.
///
/// Runs on the CPU itself, after its `register_cpu_id` and with its IDT
/// loaded: on the BSP after `init_bsp`, on an AP before it reports READY.
/// A CPU whose CPUID reports neither RDTSCP nor RDPID executes no MSR
/// instruction and keeps every CPU on the LAPIC read.
///
/// # Panics
///
/// If the value does not read back through each instruction CPUID reports, or
/// if it names another CPU than this CPU's LAPIC does.
#[cfg(not(feature = "host_harness"))]
pub fn publish_identity(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    let reports = cpuid_identity_reports();
    IDENTITY_COMMON.fetch_and(reports, Ordering::AcqRel);
    if reports == 0 {
        return;
    }

    let value = cpu_id as u64 + 1;
    // SAFETY: CPUID on this CPU reports RDTSCP or RDPID.
    unsafe { write_tsc_aux(value) };
    if reports & REPORTS_RDTSCP != 0 {
        let read = read_tsc_aux_rdtscp();
        assert_eq!(
            read, value,
            "C3 CPU identity: RDTSCP on CPU {} read {:#x} after writing {:#x}",
            cpu_id, read, value
        );
    }
    if reports & REPORTS_RDPID != 0 {
        let read = read_tsc_aux_rdpid();
        assert_eq!(
            read, value,
            "C3 CPU identity: RDPID on CPU {} read {:#x} after writing {:#x}",
            cpu_id, read, value
        );
    }

    // The LAPIC stays the authority (I8): the value must name the CPU this
    // CPU's LAPIC names.
    let by_value = identity_value_registered_cpu(value);
    let by_lapic = match lapic_cpu_lookup() {
        CurrentCpuLookup::Registered(lapic_cpu) => Some(lapic_cpu),
        CurrentCpuLookup::X2ApicActive | CurrentCpuLookup::Unregistered(_) => None,
    };
    assert!(
        by_value.is_some() && by_value == by_lapic,
        "C3 CPU identity: CPU {} published {:#x}, which names CPU {:?}; its LAPIC names CPU {:?}",
        cpu_id,
        value,
        by_value,
        by_lapic
    );
    IDENTITY_PUBLISHED.fetch_or(1u64 << cpu_id, Ordering::AcqRel);
}

/// Issue #109 §2.1: Read this CPU's encoded logical ID (`cpu_id + 1`) directly
/// from Ring-0 `IA32_GS_BASE` (`gs:[GS_CPU_ID_OFFSET]`).
///
/// Not `pure`: the executing CPU can change if preemption occurs across calls.
#[cfg(not(feature = "host_harness"))]
#[inline(always)]
fn read_gs_encoded_cpu_id() -> u64 {
    let value: u64;
    // SAFETY: invoked only after `publish_gs_identity` verified this CPU's
    // `IA32_GS_BASE` points to `SYSCALL_PERCPU[cpu_id]` and every Ring-3->Ring-0
    // entry (SYSCALL, all normal IDT stubs, and all paranoid IST stubs) enforces
    // kernel `IA32_GS_BASE`.
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{off}]",
            out(reg) value,
            off = const GS_CPU_ID_OFFSET,
            options(nostack, readonly, preserves_flags)
        );
    }
    value
}

/// Issue #109 §2.1: Read this CPU's cached `&'static PerCpuData` pointer directly
/// from Ring-0 `IA32_GS_BASE` (`gs:[GS_PER_CPU_DATA_PTR_OFFSET]`).
#[cfg(not(feature = "host_harness"))]
#[inline(always)]
fn read_gs_per_cpu_data_ptr() -> *const PerCpuData {
    let ptr: u64;
    // SAFETY: same GS-base invariant as `read_gs_encoded_cpu_id`; pointer was
    // written from `PER_CPU_DATA.get_cpu(cpu_id)` (immortal heap slice) and
    // verified non-null during `publish_gs_identity`.
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{off}]",
            out(reg) ptr,
            off = const GS_PER_CPU_DATA_PTR_OFFSET,
            options(nostack, readonly, preserves_flags)
        );
    }
    ptr as *const PerCpuData
}

/// Issue #109 §2.1: Verify this CPU's Ring-0 GS-base per-CPU identity fields
/// (`gs:[GS_CPU_ID_OFFSET]` and `gs:[GS_PER_CPU_DATA_PTR_OFFSET]`) against the
/// authoritative LAPIC registration and publish this CPU as GS-ready.
///
/// Must be called on the target CPU after `register_cpu_id`, `PER_CPU_DATA`
/// initialization, and `arch::syscall::init_syscall_percpu(cpu_id)`.
#[cfg(not(feature = "host_harness"))]
pub fn publish_gs_identity(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    let expected_val = cpu_id as u64 + 1;
    let gs_val = read_gs_encoded_cpu_id();
    assert_eq!(
        gs_val, expected_val,
        "Issue #109 §2.1: CPU {} gs:[{}] read {:#x}, expected {:#x}",
        cpu_id, GS_CPU_ID_OFFSET, gs_val, expected_val
    );

    let expected_ptr = PER_CPU_DATA
        .get_cpu(cpu_id)
        .expect("PerCpuData slot missing during GS identity publish")
        as *const PerCpuData;
    let gs_ptr = read_gs_per_cpu_data_ptr();
    assert_eq!(
        gs_ptr, expected_ptr,
        "Issue #109 §2.1: CPU {} gs:[{}] ptr {:p} != PER_CPU_DATA[{cpu_id}] {:p}",
        cpu_id, GS_PER_CPU_DATA_PTR_OFFSET, gs_ptr, expected_ptr
    );

    let by_value = identity_value_registered_cpu(gs_val);
    let by_lapic = match lapic_cpu_lookup() {
        CurrentCpuLookup::Registered(lapic_cpu) => Some(lapic_cpu),
        CurrentCpuLookup::X2ApicActive | CurrentCpuLookup::Unregistered(_) => None,
    };
    assert!(
        by_value.is_some() && by_value == by_lapic,
        "Issue #109 §2.1: CPU {} GS identity names {:?}, LAPIC names {:?}",
        cpu_id,
        by_value,
        by_lapic
    );

    GS_IDENTITY_PUBLISHED.fetch_or(1u64 << cpu_id, Ordering::AcqRel);
}

#[cfg(feature = "host_harness")]
pub fn publish_gs_identity(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
}

/// Hosted tests have no IA32_TSC_AUX: nothing is published, so the method
/// stays `Lapic`.
#[cfg(feature = "host_harness")]
pub fn publish_identity(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
}

/// Choose how every CPU finds its id from now on, once, before SMP bring-up is
/// declared complete. Returns the method in use.
///
/// Only CPUs in the online mask count: a CPU that was rejected during
/// bring-up halts and never looks itself up. Hosted builds publish nothing,
/// so there it stays `Lapic`.
pub fn select_identity_method() -> IdentityMethod {
    let method = identity_method_with_gs(
        GS_IDENTITY_PUBLISHED.load(Ordering::Acquire),
        IDENTITY_COMMON.load(Ordering::Acquire),
        IDENTITY_PUBLISHED.load(Ordering::Acquire),
        online_cpu_mask(),
    );
    let _ = IDENTITY_METHOD.compare_exchange(
        IdentityMethod::Lapic as u8,
        method as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    identity_method()
}

/// The timer tick's cross-check: the id the lookup gives must be the CPU the
/// LAPIC names. Counts the check.
///
/// It runs first in the timer handler, before any per-CPU access, so a wrong
/// id is found within one tick. It is not part of the lookup itself, because
/// the panic handler looks the CPU up.
///
/// # Panics
///
/// On a mismatch.
#[cfg(not(feature = "host_harness"))]
pub fn check_identity_tick() {
    if identity_method() == IdentityMethod::Lapic {
        return;
    }
    let cpu_id = current_cpu_id();
    let lapic_id = read_lapic_id_register();
    let expected = lapic_id_for_cpu(cpu_id);
    assert!(
        expected == Some(lapic_id),
        "C3 CPU identity: the lookup names CPU {} (LAPIC ID {:?}), but this CPU's LAPIC ID is {}",
        cpu_id,
        expected,
        lapic_id
    );
    IDENTITY_CHECKS[cpu_id].0.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow
}

/// Hosted tests have no LAPIC and never leave the `Lapic` method.
#[cfg(feature = "host_harness")]
pub fn check_identity_tick() {}

/// The current CPU as the LAPIC read and the registration maps give it,
/// whatever the method. `None` when it is not registered.
#[cfg(not(feature = "host_harness"))]
pub fn lapic_registered_cpu_id() -> Option<usize> {
    match lapic_cpu_lookup() {
        CurrentCpuLookup::Registered(cpu_id) => Some(cpu_id),
        CurrentCpuLookup::X2ApicActive | CurrentCpuLookup::Unregistered(_) => None,
    }
}

/// Hosted tests have one deterministic logical CPU.
#[cfg(feature = "host_harness")]
pub fn lapic_registered_cpu_id() -> Option<usize> {
    Some(0)
}

// ============================================================================
// Per-CPU Data Structure for SMP Support (Phase E)
// ============================================================================

/// Raw task pointer used to avoid circular dependencies with the scheduler.
pub type RawTaskPtr = *mut ();

/// Depth of the per-CPU TLB shootdown queue.
///
/// This allows batching multiple TLB shootdown requests without
/// serializing on a single slot. A depth of 4 is sufficient for
/// most workloads while keeping memory overhead low.
pub const TLB_SHOOTDOWN_QUEUE_LEN: usize = 4;

/// A single TLB shootdown request stored in the per-CPU queue.
///
/// Each entry represents a pending TLB invalidation request that
/// the IPI handler will process in FIFO order.
#[repr(C)]
pub struct TlbShootdownEntry {
    /// Request generation (0 = empty/processed slot)
    pub generation: AtomicU64,
    /// Target CR3 (0 means flush regardless of CR3)
    pub cr3: AtomicU64,
    /// Page-aligned virtual start address (0 for full flush)
    pub start: AtomicU64,
    /// Length in bytes, page-aligned (0 for full flush)
    pub len: AtomicU64,
}

impl TlbShootdownEntry {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            start: AtomicU64::new(0),
            len: AtomicU64::new(0),
        }
    }
}

impl Default for TlbShootdownEntry {
    fn default() -> Self {
        Self::new()
    }
}

// Manual Clone impl since AtomicU64 doesn't implement Clone
impl Clone for TlbShootdownEntry {
    fn clone(&self) -> Self {
        Self {
            generation: AtomicU64::new(self.generation.load(Ordering::Relaxed)),
            cr3: AtomicU64::new(self.cr3.load(Ordering::Relaxed)),
            start: AtomicU64::new(self.start.load(Ordering::Relaxed)),
            len: AtomicU64::new(self.len.load(Ordering::Relaxed)),
        }
    }
}

/// Per-CPU mailbox for TLB shootdown IPIs (small FIFO queue).
///
/// # R72: Queue-Based Design
///
/// Instead of a single-slot mailbox that requires serialization before posting,
/// this uses a bounded ring buffer (depth 4) allowing multiple requests to be
/// queued. This reduces contention and IPI overhead for high-frequency shootdowns.
///
/// # Memory Ordering
///
/// - Requester: writes entry fields Relaxed, then publishes entry.generation with Release,
///   then updates request_gen with Release
/// - Handler: loads entry.generation with Acquire, reads fields Relaxed, acks via ack_gen Release,
///   then clears entry.generation with Release and advances head
/// - Waiter: loads ack_gen with Acquire to ensure flush completion is visible
/// Issue #109 §5: 64-byte aligned so cross-CPU TLB shootdown mailbox writes
/// (`request_gen`/`tail`/`entries`) never false-share a cache line with the
/// owning CPU's local `rcu_epoch` or `kpti_*` fields in `PerCpuData`.
#[repr(C, align(64))]
pub struct TlbShootdownMailbox {
    /// Monotonic generation number for the most recent request (for compat/fast path)
    pub request_gen: AtomicU64,
    /// Last generation this CPU has processed
    pub ack_gen: AtomicU64,
    /// Queue head (next entry to consume), wraps via modulo
    pub head: AtomicU64,
    /// Queue tail (next slot to publish), wraps via modulo
    pub tail: AtomicU64,
    /// Fixed-size ring buffer of pending shootdown requests
    pub entries: [TlbShootdownEntry; TLB_SHOOTDOWN_QUEUE_LEN],
}

impl TlbShootdownMailbox {
    pub const fn new() -> Self {
        Self {
            request_gen: AtomicU64::new(0),
            ack_gen: AtomicU64::new(0),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            entries: [
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
            ],
        }
    }
}

impl Default for TlbShootdownMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU data required for SMP operation.
///
/// This structure contains all per-CPU metadata needed by the scheduler,
/// interrupt handlers, and RCU subsystem. All fields use atomics for
/// safe access from interrupt handlers and cross-CPU visibility.
///
/// # Memory Layout
///
/// Fields are ordered to minimize padding and optimize cache line usage.
/// The structure is designed to fit within a single cache line (64 bytes)
/// for the core fields.
#[repr(C, align(64))]
pub struct PerCpuData {
    /// Logical CPU index in the OS scheduler (0-based)
    pub cpu_id: AtomicUsize,
    /// Local APIC ID read from hardware
    pub lapic_id: AtomicU32,
    /// Preemption disable nesting counter (non-zero = preemption disabled)
    pub preempt_count: AtomicU32,
    /// Interrupt disable nesting counter
    pub irq_count: AtomicU32,
    /// True while a bounded callback drain runs on the IRQ-return path.
    ///
    /// IRQ return temporarily enables IF after `irq_exit()` so deferred work
    /// can use its process-context locks.  It is still not an ordinary task
    /// execution point: KCOV must not attribute callback tracepoints to the
    /// interrupted task.  Keeping this bit in already-initialized per-CPU
    /// storage avoids a lazy allocation in the very path it protects.
    pub soft_progress_active: AtomicBool,
    /// Last task (PID) that owns the FPU on this CPU (NO_FPU_OWNER if none).
    ///
    /// Used for lazy FPU save/restore: when a #NM exception fires, we save
    /// the previous owner's state before restoring the new owner's state.
    pub fpu_owner: AtomicUsize,
    /// Set by scheduler/interrupts to trigger a reschedule
    pub need_resched: AtomicBool,
    /// Padding for alignment
    _pad: [u8; 3],
    /// Currently running task (raw pointer to avoid scheduler dependency)
    pub current_task: AtomicPtr<()>,
    /// Top of the privilege 0 kernel stack
    pub kernel_stack_top: AtomicUsize,
    /// Top of the interrupt stack (IST1)
    pub irq_stack_top: AtomicUsize,
    /// Top of the syscall entry stack
    pub syscall_stack_top: AtomicUsize,
    /// Epoch counter for RCU/quiescent state tracking
    pub rcu_epoch: AtomicU64,
    /// Per-CPU TLB shootdown mailbox for cross-CPU invalidation
    pub tlb_mailbox: TlbShootdownMailbox,
    // ---- KPTI per-CPU context (H.3) ----
    /// Seqlock sequence counter for KPTI context consistency.
    /// Even = no write in progress; odd = write in progress.
    pub kpti_seq: AtomicU64,
    /// KPTI user-mode CR3 value for this CPU's current process.
    pub kpti_user_cr3: AtomicU64,
    /// KPTI kernel-mode CR3 value for this CPU's current process.
    pub kpti_kernel_cr3: AtomicU64,
    /// KPTI PCID value for this CPU's current process.
    pub kpti_pcid: AtomicU64,
}

// Safety: PerCpuData uses only atomics, so it's Send+Sync
unsafe impl Send for PerCpuData {}
unsafe impl Sync for PerCpuData {}

impl Default for PerCpuData {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuData {
    /// Construct a zeroed per-CPU record.
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicUsize::new(0),
            lapic_id: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            irq_count: AtomicU32::new(0),
            soft_progress_active: AtomicBool::new(false),
            fpu_owner: AtomicUsize::new(NO_FPU_OWNER),
            need_resched: AtomicBool::new(false),
            _pad: [0; 3],
            current_task: AtomicPtr::new(null_mut()),
            kernel_stack_top: AtomicUsize::new(0),
            irq_stack_top: AtomicUsize::new(0),
            syscall_stack_top: AtomicUsize::new(0),
            rcu_epoch: AtomicU64::new(0),
            tlb_mailbox: TlbShootdownMailbox::new(),
            kpti_seq: AtomicU64::new(0),
            kpti_user_cr3: AtomicU64::new(0),
            kpti_kernel_cr3: AtomicU64::new(0),
            kpti_pcid: AtomicU64::new(0),
        }
    }

    /// Initialize this CPU slot with identity and stack metadata.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
    /// * `lapic_id` - Hardware Local APIC ID
    /// * `kernel_stack_top` - Top of kernel privilege stack
    /// * `irq_stack_top` - Top of interrupt stack (IST1)
    /// * `syscall_stack_top` - Top of syscall entry stack
    pub fn init(
        &self,
        cpu_id: usize,
        lapic_id: u32,
        kernel_stack_top: usize,
        irq_stack_top: usize,
        syscall_stack_top: usize,
    ) {
        self.cpu_id.store(cpu_id, Ordering::Relaxed);
        self.lapic_id.store(lapic_id, Ordering::Relaxed);
        self.current_task.store(null_mut(), Ordering::Relaxed);
        self.need_resched.store(false, Ordering::Relaxed);
        self.kernel_stack_top
            .store(kernel_stack_top, Ordering::Relaxed);
        self.irq_stack_top.store(irq_stack_top, Ordering::Relaxed);
        self.syscall_stack_top
            .store(syscall_stack_top, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        self.irq_count.store(0, Ordering::Relaxed);
        self.soft_progress_active.store(false, Ordering::Relaxed);
        self.fpu_owner.store(NO_FPU_OWNER, Ordering::Relaxed);
        self.rcu_epoch.store(0, Ordering::Relaxed);
    }

    /// Disable preemption on this CPU.
    ///
    /// Returns the new preemption count. Preemption is disabled when count > 0.
    #[inline]
    pub fn preempt_disable(&self) -> u32 {
        self.preempt_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Enable preemption on this CPU.
    ///
    /// Returns the new preemption count. Panics if count would go negative.
    #[inline]
    pub fn preempt_enable(&self) -> u32 {
        let old = self.preempt_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "preempt_enable called with count already 0");
        old - 1
    }

    /// Check if preemption is enabled on this CPU.
    #[inline]
    pub fn preemptible(&self) -> bool {
        self.preempt_count.load(Ordering::Relaxed) == 0
            && self.irq_count.load(Ordering::Relaxed) == 0
    }

    /// Enter an IRQ handler context.
    #[inline]
    pub fn irq_enter(&self) {
        self.irq_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Exit an IRQ handler context.
    #[inline]
    pub fn irq_exit(&self) {
        let old = self.irq_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "irq_exit called with count already 0");
    }

    /// Check if we're currently in an IRQ handler.
    #[inline]
    pub fn in_irq(&self) -> bool {
        self.irq_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether this CPU is executing the bounded IRQ-return soft drain.
    #[inline]
    pub fn in_soft_progress(&self) -> bool {
        self.soft_progress_active.load(Ordering::Acquire)
    }

    /// Enter the IRQ-return soft-progress context exactly once.
    ///
    /// The guard is non-blocking and allocation-free.  A nested attempt is
    /// rejected so a callback cannot recursively re-enter the drain while its
    /// caller's task attribution is still ambiguous.
    #[inline]
    pub fn try_enter_soft_progress(&'static self) -> Option<SoftProgressGuard> {
        self.soft_progress_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(SoftProgressGuard { per_cpu: self })
    }

    /// Mark that a reschedule is needed on this CPU.
    #[inline]
    pub fn set_need_resched(&self) {
        self.need_resched.store(true, Ordering::Release);
    }

    /// Clear and return the need_resched flag.
    #[inline]
    pub fn clear_need_resched(&self) -> bool {
        self.need_resched.swap(false, Ordering::AcqRel)
    }

    /// Get the current task pointer.
    #[inline]
    pub fn get_current_task(&self) -> RawTaskPtr {
        self.current_task.load(Ordering::Acquire)
    }

    /// Set the current task pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the task pointer is valid for the duration it's set.
    #[inline]
    pub unsafe fn set_current_task(&self, task: RawTaskPtr) {
        self.current_task.store(task, Ordering::Release);
    }

    /// Get the FPU owner (PID) on this CPU.
    ///
    /// Returns NO_FPU_OWNER if no process owns the FPU state on this CPU.
    #[inline]
    pub fn get_fpu_owner(&self) -> usize {
        self.fpu_owner.load(Ordering::Acquire)
    }

    /// Set the FPU owner on this CPU.
    ///
    /// Called by the #NM handler after restoring a process's FPU state.
    #[inline]
    pub fn set_fpu_owner(&self, pid: usize) {
        self.fpu_owner.store(pid, Ordering::Release);
    }

    /// Clear the FPU owner if it matches the given PID.
    ///
    /// Called when a process exits to prevent #NM from trying to save
    /// state to freed memory. Uses compare-exchange to handle races.
    ///
    /// # Returns
    ///
    /// `true` if the owner was cleared, `false` if it was already different.
    #[inline]
    pub fn clear_fpu_owner_if(&self, pid: usize) -> bool {
        self.fpu_owner
            .compare_exchange(pid, NO_FPU_OWNER, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Access this CPU's TLB shootdown mailbox.
    ///
    /// Used by both the requesting CPU (to set up shootdown request) and
    /// the IPI handler (to read request and write ACK).
    #[inline]
    pub fn tlb_mailbox(&self) -> &TlbShootdownMailbox {
        &self.tlb_mailbox
    }
}

/// Issue #109 §5: 64-byte cache-line wrapper for per-CPU slots.
///
/// Prevents adjacent CPUs' `CpuLocal<T>` elements (such as `CURRENT_PID`,
/// `SMAP_GUARD_DEPTH`, `IRQ_RESCHED_PENDING`, `USER_COPY_STATE`, and
/// `PER_CPU_DATA`) from sharing a cache line and causing MESI ping-pong.
#[repr(align(64))]
struct CacheAligned<T>(T);

/// Per-CPU storage wrapper
///
/// Stores one instance of T per CPU, lazily initialized on first access.
/// Interrupt users must force initialization before enabling interrupts and use
/// T's normal synchronization for shared mutable state.
///
/// Slots are initialized one at a time in a heap allocation to avoid
/// placing `[T; MAX_CPUS]` on the stack during `call_once`.
/// For large per-CPU types like `SampleRing` (~41KB), the previous stack-based
/// approach would allocate ~2.6MB on the stack (64 * 41KB), causing a
/// deterministic stack overflow on first access.
pub struct CpuLocal<T> {
    /// Initialization function for each CPU's slot
    init: fn() -> T,
    /// Per-CPU slots, cache-line isolated, heap-allocated and initialized lazily via Once
    slots: Once<Box<[CacheAligned<T>]>>,
}

impl<T> CpuLocal<T> {
    /// Create a new per-CPU storage with the given initializer
    ///
    /// The initializer is called once per CPU slot on first access.
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            init,
            slots: Once::new(),
        }
    }

    /// Get or initialize the slots array.
    ///
    /// R91-2 FIX: Allocates on the heap instead of the stack to prevent
    /// stack overflow for large per-CPU types (e.g., SampleRing ~41KB * 64 CPUs).
    fn get_slots(&self) -> &[CacheAligned<T>] {
        self.slots.call_once(|| {
            // KSA-017: Vec owns every initialized T, including during a panic.
            // Once publishes only the completed slice. Automatic Send/Sync bounds
            // and owner-scoped borrows enforce ordinary shared-reference rules.
            let mut slots = Vec::with_capacity(MAX_CPUS);
            for _ in 0..MAX_CPUS {
                slots.push(CacheAligned((self.init)()));
            }
            slots.into_boxed_slice()
        })
    }

    /// Force-initialize the backing heap allocation in non-IRQ context.
    ///
    /// R151-5 FIX: `CpuLocal` lazily heap-allocates via `Once::call_once()`.
    /// If the first access occurs in IRQ context while another code path holds
    /// the heap allocator lock, the IRQ handler deadlocks. Call this during
    /// BSP/AP init before enabling interrupts.
    #[inline]
    pub fn force_init(&self) {
        let _ = self.get_slots();
    }

    /// Access the current CPU's slot immutably
    ///
    /// This selects a slot, without pinning execution or granting exclusivity.
    /// Mutations through shared references use T's atomics or locks.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let id = current_cpu_id();
        // Hard bound check to prevent UB with non-zero-based APIC IDs
        assert!(
            id < MAX_CPUS,
            "CPU ID {} out of range (max {})",
            id,
            MAX_CPUS
        );
        let slot = self
            .get_cpu(id)
            .expect("CPU slot missing after bounds check");
        f(slot)
    }

    /// Access a specific CPU's slot immutably.
    ///
    /// Used for cross-CPU operations like TLB shootdown where we need to
    /// access another CPU's mailbox.
    ///
    /// Cross-thread access follows T's automatic Send/Sync requirements.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn with_cpu<R>(&self, cpu_id: usize, f: impl FnOnce(&T) -> R) -> Option<R> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        self.get_cpu(cpu_id).map(f)
    }

    /// Borrow a specific CPU's slot for no longer than this storage owner lives.
    /// Static owners naturally provide static borrows; local owners cannot escape.
    ///
    /// ```compile_fail
    /// use cpu_local::CpuLocal;
    /// let dangling = {
    ///     let local = CpuLocal::new(|| 42usize);
    ///     local.get_cpu(0).unwrap()
    /// };
    /// assert_eq!(*dangling, 42);
    /// ```
    ///
    /// Cross-thread access follows T's automatic Send/Sync requirements.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn get_cpu(&self, cpu_id: usize) -> Option<&T> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        self.get_slots().get(cpu_id).map(|slot| &slot.0)
    }
}

/// Get the current CPU ID
///
/// # R67-8 FIX: O(1) Lookup
///
/// Uses a reverse mapping table (LAPIC ID → CPU index) for constant-time lookup.
/// This is critical for syscall entry performance where the CPU ID must be
/// determined very early without a stack.
///
/// # Implementation
///
/// 1. After SMP bring-up, if every CPU published its id (C3 repair 2): read
///    IA32_TSC_AUX with RDPID or RDTSCP, and accept the CPU it names if that
///    CPU is registered. No MMIO.
/// 2. Otherwise read the LAPIC ID from hardware (0xFEE00020, bits 31:24)
/// 3. O(1) lookup in LAPIC_ID_REVERSE_MAP
/// 4. Fallback to CPU 0 only during early boot (before registration)
///
/// # Panics
///
/// Once SMP bring-up is complete, an unregistered CPU panics in every build:
/// falling back to CPU 0 would alias its per-CPU slots (R151-6).
#[inline]
pub fn current_cpu_id() -> usize {
    current_cpu_id_impl()
}

/// Resolve the current CPU only when its LAPIC ID has an explicit logical-CPU
/// registration.
///
/// Unlike [`current_cpu_id`], this never applies the early-boot CPU-0 fallback.
/// Best-effort facilities such as KCOV use it to fail closed rather than
/// attributing work from a not-yet-admitted AP to the BSP's per-CPU state.
#[inline]
pub fn try_current_registered_cpu_id() -> Option<usize> {
    #[cfg(feature = "host_harness")]
    {
        Some(0)
    }

    #[cfg(not(feature = "host_harness"))]
    {
        match current_cpu_lookup() {
            CurrentCpuLookup::Registered(cpu_id) => Some(cpu_id),
            CurrentCpuLookup::X2ApicActive | CurrentCpuLookup::Unregistered(_) => None,
        }
    }
}

/// Hosted tests have one deterministic logical CPU and no LAPIC MMIO mapping.
///
/// RF180 hosted-verification fix: keep hardware discovery entirely out of the
/// hosted execution path. This is feature-gated rather than target-gated so an
/// accidental non-kernel target never silently changes production semantics.
#[cfg(feature = "host_harness")]
#[inline]
fn current_cpu_id_impl() -> usize {
    0
}

/// Result of a hardware LAPIC-to-logical-CPU lookup.
#[cfg(not(feature = "host_harness"))]
enum CurrentCpuLookup {
    Registered(usize),
    X2ApicActive,
    Unregistered(u32),
}

/// Verify that a reverse-map candidate still agrees with the authoritative
/// logical-CPU-to-LAPIC map.
///
/// A reverse entry alone is not a registration proof: firmware or a buggy
/// re-registration could otherwise leave a stale entry that aliases KCOV (and
/// other per-CPU state) to an unrelated online CPU.
#[inline]
fn registered_cpu_mapping_matches(cpu_id: usize, lapic_id: u32) -> bool {
    cpu_id < MAX_CPUS && LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire) == lapic_id
}

/// Production CPU identification through the registered LAPIC-to-logical map.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn current_cpu_lookup() -> CurrentCpuLookup {
    // R169-L7 FIX: in x2APIC mode the APIC ID comes from an MSR, can exceed 8 bits
    // (overflowing the 256-entry reverse map), and the xAPIC MMIO ID register read
    // below is invalid. Reading it would alias another CPU's per-CPU slot, so fail
    // closed. `arch::apic` publishes this flag at LAPIC init (it is xAPIC-MMIO
    // only); the kernel never enables x2APIC, so on supported hardware this branch
    // is never taken.
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        return CurrentCpuLookup::X2ApicActive;
    }

    // Issue #109 §2.1: single-instruction Ring-0 GS-base fast path once every
    // online CPU has published and LAPIC-verified its GS per-CPU record.
    // Falls through to LAPIC on an invalid/zero encoding (fail-closed).
    match identity_method() {
        IdentityMethod::GsBase => {
            if let Some(cpu_id) = identity_value_cpu(read_gs_encoded_cpu_id()) {
                return CurrentCpuLookup::Registered(cpu_id);
            }
        }
        IdentityMethod::Rdpid => {
            if let Some(cpu_id) = identity_value_registered_cpu(read_tsc_aux_rdpid()) {
                return CurrentCpuLookup::Registered(cpu_id);
            }
        }
        IdentityMethod::Rdtscp => {
            if let Some(cpu_id) = identity_value_registered_cpu(read_tsc_aux_rdtscp()) {
                return CurrentCpuLookup::Registered(cpu_id);
            }
        }
        IdentityMethod::Lapic => {}
    }

    lapic_cpu_lookup()
}

/// The LAPIC ID register of this CPU.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn read_lapic_id_register() -> u32 {
    // R169-L7 FIX: read the LAPIC ID register (offset 0x20, bits 31:24) through the
    // single authoritative MMIO base shared with `arch::apic::lapic_read`, not a
    // hard-coded `0xFEE0_0020` literal. After memory initialization this is a
    // supervisor high-half alias inherited by every process's kernel CR3.
    unsafe {
        let id_reg = (lapic_mmio_base() as usize + 0x20) as *const u32;
        core::ptr::read_volatile(id_reg) >> 24
    }
}

/// CPU identification through the LAPIC ID register and the registered
/// LAPIC-to-logical map, whatever the identity method.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn lapic_cpu_lookup() -> CurrentCpuLookup {
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        return CurrentCpuLookup::X2ApicActive;
    }

    let apic_id = read_lapic_id_register();

    // R67-8 FIX: O(1) reverse lookup instead of linear search
    let cpu_idx = if (apic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE {
        LAPIC_ID_REVERSE_MAP[apic_id as usize].load(Ordering::Acquire)
    } else {
        INVALID_CPU_ID
    };

    // R187-7 FIX: a valid reverse entry must also agree with the forward map.
    // This rejects stale/reassigned LAPIC mappings instead of aliasing their
    // per-CPU KCOV state to a currently online logical slot.
    if registered_cpu_mapping_matches(cpu_idx, apic_id) {
        return CurrentCpuLookup::Registered(cpu_idx);
    }

    CurrentCpuLookup::Unregistered(apic_id)
}

/// Production CPU identification through the registered LAPIC-to-logical map.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn current_cpu_id_impl() -> usize {
    match current_cpu_lookup() {
        CurrentCpuLookup::Registered(cpu_id) => cpu_id,
        CurrentCpuLookup::X2ApicActive => {
            panic!("current_cpu_id: x2APIC mode is unsupported (would alias per-CPU data)");
        }
        CurrentCpuLookup::Unregistered(apic_id) => {
            // R151-6 FIX: After SMP init, an unregistered LAPIC ID is a critical bug
            // that would silently alias CPU 0's per-CPU data. Panic immediately.
            if CPU_LOCAL_SMP_DONE.load(Ordering::Acquire) {
                panic!(
                    "current_cpu_id: LAPIC ID {} not registered after SMP init complete",
                    apic_id
                );
            }

            // Fallback to CPU 0 - only safe during early boot before registration.
            0
        }
    }
}

/// Register the LAPIC ID to CPU index mapping.
///
/// This must be called for each CPU during bring-up to enable
/// proper `current_cpu_id()` operation.
///
/// # R67-8 FIX
///
/// Also populates the reverse mapping table for O(1) lookup in syscall entry.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
/// * `lapic_id` - Hardware LAPIC ID
///
/// # Panics
///
/// Panics if `cpu_id` is out of range.
pub fn register_cpu_id(cpu_id: usize, lapic_id: u32) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    assert!(
        (lapic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE,
        "LAPIC ID {} exceeds the xAPIC reverse-map capacity",
        lapic_id
    );

    let _registration = CPU_ID_REGISTRATION_LOCK.lock();
    let previous_lapic = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    assert!(
        previous_lapic == INVALID_LAPIC_ID || previous_lapic == lapic_id || !is_cpu_online(cpu_id),
        "CPU {} is online and cannot change LAPIC ID {} to {}",
        cpu_id,
        previous_lapic,
        lapic_id
    );
    let claimed_by = LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire);
    assert!(
        claimed_by == INVALID_CPU_ID || claimed_by == cpu_id,
        "LAPIC ID {} is already registered to CPU {}",
        lapic_id,
        claimed_by
    );
    assert!(
        claimed_by == INVALID_CPU_ID || previous_lapic == lapic_id,
        "LAPIC ID {} has a stale reverse mapping for CPU {}",
        lapic_id,
        cpu_id
    );

    if previous_lapic != INVALID_LAPIC_ID && previous_lapic != lapic_id {
        assert!(
            (previous_lapic as usize) < LAPIC_ID_REVERSE_MAP_SIZE,
            "CPU {} had an out-of-range prior LAPIC ID {}",
            cpu_id,
            previous_lapic
        );
        let old_owner = LAPIC_ID_REVERSE_MAP[previous_lapic as usize].load(Ordering::Acquire);
        assert_eq!(
            old_owner, cpu_id,
            "CPU {} had a non-bijective LAPIC mapping for ID {}",
            cpu_id, previous_lapic
        );
        LAPIC_ID_REVERSE_MAP[previous_lapic as usize].store(INVALID_CPU_ID, Ordering::Release);
    }

    // Publish forward first and reverse second. A concurrent reader can only
    // observe an incomplete mapping and fail closed because it validates both
    // directions in `registered_cpu_mapping_matches`.
    LAPIC_ID_MAP[cpu_id].store(lapic_id, Ordering::Release);
    LAPIC_ID_REVERSE_MAP[lapic_id as usize].store(cpu_id, Ordering::Release);
}

/// Get the maximum number of supported CPUs
pub const fn max_cpus() -> usize {
    MAX_CPUS
}

/// Get the LAPIC ID for a CPU index if it has been registered.
///
/// Returns None if:
/// - cpu_id is out of range (>= MAX_CPUS)
/// - cpu_id has not been registered yet (LAPIC ID is INVALID_LAPIC_ID)
///
/// # Usage
///
/// Used by IPI sending code to map logical CPU index to hardware LAPIC ID.
#[inline]
pub fn lapic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    let lapic_id = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    if lapic_id == INVALID_LAPIC_ID || (lapic_id as usize) >= LAPIC_ID_REVERSE_MAP_SIZE {
        None
    } else if LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire) == cpu_id {
        Some(lapic_id)
    } else {
        // Registration publishes a forward/reverse pair. Returning a forward
        // entry without its reciprocal reverse entry could target a stale or
        // reassigned LAPIC during AP topology changes, so fail closed.
        None
    }
}

// ============================================================================
// Global Per-CPU Data Access
// ============================================================================

/// Global per-CPU data block for scheduler and IRQ metadata.
///
/// This is the primary per-CPU data structure used by the kernel.
/// Access it via `current_cpu()` or `PER_CPU_DATA.with()`.
pub static PER_CPU_DATA: CpuLocal<PerCpuData> = CpuLocal::new(PerCpuData::new);

/// Access the current CPU's `PerCpuData`.
///
/// This is the primary way to access per-CPU state. The returned reference
/// remains valid for the static storage lifetime. A later CPU migration does
/// not change which CPU this reference identifies; CPU-local operations must pin.
///
/// # Example
///
/// ```rust,ignore
/// use cpu_local::current_cpu;
///
/// current_cpu().set_need_resched();
/// if current_cpu().preemptible() {
///     // Safe to reschedule
/// }
/// ```
#[inline]
pub fn current_cpu() -> &'static PerCpuData {
    #[cfg(not(feature = "host_harness"))]
    if identity_method() == IdentityMethod::GsBase {
        let ptr = read_gs_per_cpu_data_ptr();
        if !ptr.is_null() {
            // SAFETY: `publish_gs_identity` verified `gs:[GS_PER_CPU_DATA_PTR_OFFSET]`
            // equals `PER_CPU_DATA.get_cpu(cpu_id)` (immortal heap-allocated slot).
            return unsafe { &*ptr };
        }
    }
    PER_CPU_DATA
        .get_cpu(current_cpu_id())
        .expect("current CPU slot out of range")
}

/// Allocation-free guard for the IRQ-return deferred callback drain.
pub struct SoftProgressGuard {
    per_cpu: &'static PerCpuData,
}

impl Drop for SoftProgressGuard {
    #[inline]
    fn drop(&mut self) {
        let was_active = self
            .per_cpu
            .soft_progress_active
            .swap(false, Ordering::Release);
        assert!(was_active, "soft-progress guard was not active");
    }
}

/// Try to enter the current CPU's IRQ-return soft-progress context.
#[inline]
pub fn try_enter_soft_progress() -> Option<SoftProgressGuard> {
    current_cpu().try_enter_soft_progress()
}

/// Initialize the bootstrap processor's per-CPU slot.
///
/// Must be invoked during early boot before interrupts are enabled.
/// The BSP (CPU 0) is initialized with the provided stack addresses.
///
/// # Arguments
///
/// * `lapic_id` - Hardware Local APIC ID of the BSP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if called when not on CPU 0.
pub fn init_bsp(
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    // Register BSP's LAPIC ID mapping first
    register_cpu_id(0, lapic_id);

    current_cpu().init(
        0,
        lapic_id,
        kernel_stack_top,
        irq_stack_top,
        syscall_stack_top,
    );
}

/// Initialize an application processor's per-CPU slot.
///
/// Called by AP bootstrap code after the AP has started executing.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (1+ for APs)
/// * `lapic_id` - Hardware Local APIC ID of this AP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if cpu_id is 0 (BSP) or out of range.
pub fn init_ap(
    cpu_id: usize,
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    assert!(cpu_id > 0, "init_ap must not be called for BSP (CPU 0)");
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);

    // Register AP's LAPIC ID mapping
    register_cpu_id(cpu_id, lapic_id);

    // Initialize this CPU's PerCpuData
    // Note: We access via PER_CPU_DATA since current_cpu_id() now uses LAPIC map
    PER_CPU_DATA.with(|d| {
        d.init(
            cpu_id,
            lapic_id,
            kernel_stack_top,
            irq_stack_top,
            syscall_stack_top,
        );
    });
}

/// R178-28 FIX: Bitmap of online CPU IDs (bit N = CPU N is online).
///
/// Authoritative mask for scheduler affinity and cpuset validation. Only bits
/// corresponding to registered CPUs (via `register_cpu_id`) that have called
/// `mark_cpu_online` are set. BSP (CPU 0) is marked online at init.
static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(1); // Bit 0 set for BSP

/// Get the number of online CPUs.
///
/// # R69-1 FIX: Accurate Online CPU Count
///
/// Derives the count from the authoritative ID bitmap so count and mask cannot
/// diverge when logical IDs are sparse.
#[inline]
pub fn num_online_cpus() -> usize {
    ONLINE_CPU_MASK.load(Ordering::Acquire).count_ones() as usize
}

/// R178-28 FIX: Get the online CPU mask (bit N = CPU N is online).
///
/// Returns a bitmap of online CPU IDs. Used by scheduler affinity and cpuset
/// code to validate that requested CPUs are actually online. Only CPUs that
/// have both registered their LAPIC ID and completed AP initialization are set.
#[inline]
pub fn online_cpu_mask() -> u64 {
    ONLINE_CPU_MASK.load(Ordering::Acquire)
}

/// Test one logical CPU ID against the same authoritative bitmap.
#[inline]
pub fn is_cpu_online(cpu_id: usize) -> bool {
    cpu_id < MAX_CPUS && (online_cpu_mask() & (1u64 << cpu_id)) != 0
}

/// Compute the online mask after admitting one logical CPU.
///
/// The transition is intentionally idempotent: repeated lifecycle callbacks
/// cannot inflate a separate count because the count is always derived from
/// the resulting bitmap. Keeping this small transition pure also lets the host
/// topology harness exercise duplicate-publication behavior without mutating
/// the global boot topology.
#[inline]
fn online_mask_after_publish(current_mask: u64, cpu_id: usize) -> Option<u64> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    Some(current_mask | (1u64 << cpu_id))
}

/// Admit a logical CPU only when a prior LAPIC lookup produced a valid ID and
/// that ID is currently online.
///
/// Keeping the capacity check ahead of the shift makes this helper safe for
/// every caller, including best-effort KCOV paths that must fail closed rather
/// than turn an unknown topology result into a static-array index.
#[inline]
fn registered_online_cpu_id(registered_cpu_id: Option<usize>, online_mask: u64) -> Option<usize> {
    let cpu_id = registered_cpu_id?;
    if cpu_id >= MAX_CPUS || (online_mask & (1u64 << cpu_id)) == 0 {
        return None;
    }
    Some(cpu_id)
}

/// Resolve the current CPU only when it is both LAPIC-registered and online.
///
/// This is the strict admission boundary for fixed-capacity per-CPU state.
/// Unlike [`current_cpu_id`], it never applies the early-boot CPU-0 fallback.
#[inline]
pub fn try_current_registered_online_cpu_id() -> Option<usize> {
    registered_online_cpu_id(try_current_registered_cpu_id(), online_cpu_mask())
}

/// Read the architectural interrupt-enable flag without depending on the arch
/// crate (which itself depends on `cpu_local`).
///
/// KCOV treats every IF-masked context conservatively as non-task context. On
/// x86-64 this covers interrupt-gate entries and ordinary task critical
/// sections; NMI is additionally accounted explicitly because its entry does
/// not reliably clear IF. Other architectures currently retain the existing
/// IRQ/NMI accounting until they provide an equivalent flag reader.
#[inline]
fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let rflags: usize;
        // SAFETY: PUSHFQ/POP only read the current CPU's RFLAGS and restore the
        // stack pointer before returning. They do not alter interrupt state.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        }
        (rflags & (1 << 9)) != 0
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}

#[inline]
fn is_non_task_context(in_irq: bool, in_nmi: bool, interrupts_enabled: bool) -> bool {
    in_irq || in_nmi || !interrupts_enabled
}

/// Return whether the current, registered, online CPU is in non-task context.
///
/// `None` is deliberately fail-closed: callers must not attribute work to an
/// unregistered or offline CPU. This is a pre-admission filter only; a caller
/// that needs a stable CPU must re-check through [`CurrentCpuPin`] after pinning.
#[inline]
pub fn try_current_online_cpu_in_non_task_context() -> Option<bool> {
    // Check the allocation-free global NMI gate first. An NMI can arrive
    // before CPU-local storage and LAPIC registration are initialized, so no
    // CPU-local lookup is safe on that path.
    if nmi_active() {
        return Some(true);
    }

    let cpu_id = try_current_registered_online_cpu_id()?;
    // Hardware interrupt gates clear IF. Check it before consulting the
    // heap-backed per-CPU slab so the common asynchronous path cannot make
    // its first allocation while rejecting KCOV work.
    let interrupts_enabled = interrupts_enabled();
    if !interrupts_enabled {
        return Some(true);
    }
    let per_cpu = PER_CPU_DATA.get_cpu(cpu_id)?;
    Some(
        per_cpu.in_soft_progress()
            || is_non_task_context(per_cpu.in_irq(), nmi_active(), interrupts_enabled),
    )
}

/// Return whether the current, registered, online CPU is servicing an
/// accounted hard IRQ.
///
/// This deliberately does not inspect IF. Scheduler switch code publishes a
/// task token with IF masked, which is ordinary scheduler context rather than
/// an IRQ handler. Callers that must reject every asynchronous context should
/// use [`try_current_online_cpu_in_non_task_context`] instead.
#[inline]
pub fn try_current_online_cpu_in_irq_context() -> Option<bool> {
    let cpu_id = try_current_registered_online_cpu_id()?;
    Some(PER_CPU_DATA.get_cpu(cpu_id)?.in_irq())
}

/// A non-sendable preemption pin for a registered, online CPU.
///
/// The pin holds the validated per-CPU reference so dropping it never repeats
/// CPU lookup or indexes a caller-owned per-CPU array. KCOV uses this to keep
/// topology admission and preemption restoration fail-closed.
pub struct CurrentCpuPin {
    cpu_id: usize,
    per_cpu: &'static PerCpuData,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl CurrentCpuPin {
    /// Return the validated logical CPU ID associated with this pin.
    #[inline]
    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }

    /// Return whether this pinned CPU is in a non-task context.
    #[inline]
    pub fn in_non_task_context(&self) -> bool {
        self.per_cpu.in_soft_progress()
            || is_non_task_context(self.per_cpu.in_irq(), nmi_active(), interrupts_enabled())
    }

    /// Return whether the pinned CPU is servicing an accounted hard IRQ.
    ///
    /// Unlike [`Self::in_non_task_context`], this intentionally permits a
    /// scheduler critical section with IF masked.
    #[inline]
    pub fn in_irq(&self) -> bool {
        self.per_cpu.in_irq()
    }
}

impl Drop for CurrentCpuPin {
    #[inline]
    fn drop(&mut self) {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        self.per_cpu.preempt_enable();
    }
}

/// Try to pin the current CPU only after strict topology admission.
///
/// R187-7 FIX: KCOV must never use the legacy pre-SMP CPU-0 fallback for
/// per-CPU tracing state. The retry closes the sample-before-disable migration
/// window, while every unavailable/offline topology state drops the caller's
/// best-effort operation without indexing a static array.
#[inline]
pub fn try_pin_current_online_cpu() -> Option<CurrentCpuPin> {
    loop {
        let cpu_id = try_current_registered_online_cpu_id()?;

        let per_cpu = PER_CPU_DATA.get_cpu(cpu_id)?;
        per_cpu.preempt_disable();
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        if try_current_registered_online_cpu_id() == Some(cpu_id) {
            return Some(CurrentCpuPin {
                cpu_id,
                per_cpu,
                _not_send: core::marker::PhantomData,
            });
        }

        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        per_cpu.preempt_enable();
        core::hint::spin_loop();
    }
}

/// Mark a CPU as online (call this from AP initialization).
///
/// Sets the corresponding bit in the online mask. Should be called once per AP
/// after it has completed initialization.
///
/// # Safety
///
/// Should only be called once per CPU during SMP initialization.
///
/// # R178-28 FIX
///
/// Now also updates the authoritative online-CPU mask so affinity/cpuset
/// validation can distinguish registered-but-offline from truly online CPUs.
#[inline]
pub fn mark_cpu_online() {
    let cpu_id = try_current_registered_cpu_id()
        .expect("cannot publish online topology for an unregistered LAPIC identity");
    mark_cpu_online_with_id(cpu_id);
}

/// Publish a registered logical CPU as online.
///
/// Registration and online publication share `CPU_ID_REGISTRATION_LOCK`, so a
/// re-registration cannot pass an offline check while this bit is being set.
/// The reciprocal LAPIC map is validated again under the same lock, and the
/// bitmap transition is idempotent for duplicate callbacks.
#[inline]
pub fn mark_cpu_online_with_id(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    let _registration = CPU_ID_REGISTRATION_LOCK.lock();
    let lapic_id = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    assert!(
        lapic_id != INVALID_LAPIC_ID
            && (lapic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE
            && LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire) == cpu_id,
        "CPU {} cannot become online before reciprocal LAPIC registration",
        cpu_id
    );

    // The idempotent transition is serialized under the lifecycle lock.
    // Readers derive their count from this authoritative mask, so no second
    // counter can diverge.
    let current = ONLINE_CPU_MASK.load(Ordering::Relaxed);
    let next = online_mask_after_publish(current, cpu_id)
        .expect("validated CPU ID unexpectedly exceeded online-mask capacity");
    ONLINE_CPU_MASK.store(next, Ordering::Release);
}

/// Clear FPU ownership for a process across all CPUs.
///
/// Called when a process exits to ensure no CPU holds a stale FPU owner
/// reference that would cause #NM to save state to freed memory.
///
/// This function iterates all CPU slots and uses compare-exchange to
/// atomically clear any slot that matches the given PID.
pub fn clear_fpu_owner_all_cpus(pid: usize) {
    for cpu_id in 0..MAX_CPUS {
        if let Some(per_cpu) = PER_CPU_DATA.get_cpu(cpu_id) {
            per_cpu.clear_fpu_owner_if(pid);
        }
    }
}

#[cfg(all(test, feature = "host_harness"))]
mod host_harness_tests {
    extern crate std;
    use core::sync::atomic::Ordering;

    #[test]
    fn local_storage_drops_each_initialized_value() {
        static DROPPED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        struct Tracked;
        impl Drop for Tracked {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let local = super::CpuLocal::new(|| Tracked);
        assert!(local.get_cpu(super::MAX_CPUS).is_none());
        assert_eq!(DROPPED.load(Ordering::Relaxed), 0);
        local.force_init();
        assert!(local.get_cpu(0).is_some());
        drop(local);
        assert_eq!(DROPPED.load(Ordering::Relaxed), super::MAX_CPUS);
    }

    #[test]
    fn concurrent_access_initializes_once_and_shares_atomic_state() {
        use core::sync::atomic::AtomicUsize;
        static INITIALIZED: AtomicUsize = AtomicUsize::new(0);
        let local = super::CpuLocal::new(|| {
            INITIALIZED.fetch_add(1, Ordering::Relaxed);
            AtomicUsize::new(0)
        });
        let start = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let local = &local;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    for cpu in 0..super::MAX_CPUS {
                        local.get_cpu(cpu).unwrap().fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(INITIALIZED.load(Ordering::Relaxed), super::MAX_CPUS);
        for cpu in 0..super::MAX_CPUS {
            assert_eq!(
                local.with_cpu(cpu, |slot| slot.load(Ordering::Relaxed)),
                Some(4)
            );
        }
        assert!(local.with_cpu(usize::MAX, |_| ()).is_none());
    }

    #[test]
    fn panicking_initializer_drops_partial_slots_and_poison_prevents_access() {
        use core::sync::atomic::AtomicUsize;
        static CREATED: AtomicUsize = AtomicUsize::new(0);
        static DROPPED: AtomicUsize = AtomicUsize::new(0);
        struct Tracked;
        impl Drop for Tracked {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let local = super::CpuLocal::new(|| {
            if CREATED.fetch_add(1, Ordering::Relaxed) == 3 {
                panic!("initializer failure");
            }
            Tracked
        });
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.force_init())).is_err()
        );
        assert_eq!(DROPPED.load(Ordering::Relaxed), 3);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.get_cpu(0))).is_err()
        );
        drop(local);
        assert_eq!(DROPPED.load(Ordering::Relaxed), 3);
        assert_eq!(CREATED.load(Ordering::Relaxed), 4);
    }

    static TOPOLOGY_TEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

    #[test]
    fn current_cpu_id_is_deterministic_without_lapic_mmio() {
        assert_eq!(super::current_cpu_id(), 0);
    }

    #[test]
    fn strict_cpu_pin_is_registered_online_and_restores_preemption() {
        // Reads the shared host CPU's IRQ/NMI context and preempt count, which
        // the classifier tests change; serialize with them.
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        assert_eq!(super::try_current_registered_cpu_id(), Some(0));
        assert_eq!(super::try_current_registered_online_cpu_id(), Some(0));
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
        assert_eq!(super::try_current_online_cpu_in_irq_context(), Some(false));
        assert!(super::is_cpu_online(0));
        assert!(!super::is_cpu_online(super::MAX_CPUS));
        assert!(!super::is_cpu_online(usize::MAX));

        let before = super::current_cpu().preempt_count.load(Ordering::Relaxed);
        let pin = super::try_pin_current_online_cpu().expect("host CPU 0 is admitted");
        assert_eq!(pin.cpu_id(), 0);
        assert!(!pin.in_non_task_context());
        assert_eq!(
            super::current_cpu().preempt_count.load(Ordering::Relaxed),
            before + 1
        );
        drop(pin);
        assert_eq!(
            super::current_cpu().preempt_count.load(Ordering::Relaxed),
            before
        );
    }

    #[test]
    fn strict_topology_admission_rejects_unregistered_offline_and_out_of_range_ids() {
        let highest = super::MAX_CPUS - 1;
        let online = (1u64 << 0) | (1u64 << highest);

        assert_eq!(super::registered_online_cpu_id(None, online), None);
        assert_eq!(super::registered_online_cpu_id(Some(1), online), None);
        assert_eq!(
            super::registered_online_cpu_id(Some(super::MAX_CPUS), online),
            None
        );
        assert_eq!(
            super::registered_online_cpu_id(Some(usize::MAX), online),
            None
        );
        assert_eq!(super::registered_online_cpu_id(Some(0), online), Some(0));
        assert_eq!(
            super::registered_online_cpu_id(Some(highest), online),
            Some(highest)
        );
    }

    #[test]
    fn non_task_context_classifier_rejects_irq_and_interrupt_masking() {
        // The IRQ/NMI legs below change the shared host CPU's context state,
        // which the soft-progress test observes; serialize with it.
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        assert!(!super::is_non_task_context(false, false, true));
        assert!(super::is_non_task_context(true, false, true));
        assert!(super::is_non_task_context(false, true, true));
        assert!(super::is_non_task_context(false, false, false));
        assert!(super::is_non_task_context(true, true, false));

        super::current_cpu().irq_enter();
        assert_eq!(super::try_current_online_cpu_in_irq_context(), Some(true));
        super::current_cpu().irq_exit();
        super::nmi_enter();
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(true)
        );
        super::nmi_exit();
    }

    #[test]
    fn soft_progress_context_is_fail_closed_and_non_reentrant() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();

        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
        let guard = super::try_enter_soft_progress().expect("outer soft-progress entry");
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(true)
        );
        let pin = super::try_pin_current_online_cpu().expect("host CPU 0 is admitted");
        assert!(pin.in_non_task_context());
        assert!(super::try_enter_soft_progress().is_none());
        drop(pin);
        drop(guard);
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
    }

    #[test]
    fn registration_reassignment_clears_stale_reverse_entry() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        let cpu_id = super::MAX_CPUS - 2;
        let first_lapic = 250;
        let second_lapic = 251;

        super::register_cpu_id(cpu_id, first_lapic);
        assert!(super::registered_cpu_mapping_matches(cpu_id, first_lapic));
        super::register_cpu_id(cpu_id, second_lapic);

        assert_eq!(super::lapic_id_for_cpu(cpu_id), Some(second_lapic));
        assert!(!super::registered_cpu_mapping_matches(cpu_id, first_lapic));
        assert!(super::registered_cpu_mapping_matches(cpu_id, second_lapic));
        assert_eq!(
            super::LAPIC_ID_REVERSE_MAP[first_lapic as usize].load(Ordering::Acquire),
            super::INVALID_CPU_ID
        );
        assert_eq!(
            super::LAPIC_ID_REVERSE_MAP[second_lapic as usize].load(Ordering::Acquire),
            cpu_id
        );

        // A forward entry alone is never enough to target a LAPIC. This
        // models an interrupted/externally-corrupted registration and proves
        // forward-map consumers fail closed until reciprocity is restored.
        super::LAPIC_ID_REVERSE_MAP[second_lapic as usize]
            .store(super::INVALID_CPU_ID, Ordering::Release);
        assert_eq!(super::lapic_id_for_cpu(cpu_id), None);
        super::LAPIC_ID_REVERSE_MAP[second_lapic as usize].store(cpu_id, Ordering::Release);
        assert_eq!(super::lapic_id_for_cpu(cpu_id), Some(second_lapic));
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn registration_rejects_duplicate_lapic_identity() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        let lapic_id = 249;
        super::register_cpu_id(super::MAX_CPUS - 4, lapic_id);
        super::register_cpu_id(super::MAX_CPUS - 3, lapic_id);
    }

    #[test]
    fn identity_value_names_only_a_registered_cpu() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        let cpu_id = super::MAX_CPUS - 5;
        assert_eq!(super::identity_value_cpu(0), None);
        assert_eq!(super::identity_value_cpu(1), Some(0));
        assert_eq!(
            super::identity_value_cpu(super::MAX_CPUS as u64),
            Some(super::MAX_CPUS - 1)
        );
        assert_eq!(super::identity_value_cpu(super::MAX_CPUS as u64 + 1), None);
        assert_eq!(super::identity_value_cpu(u64::MAX), None);

        // A CPU that is not registered is not accepted, whatever the value.
        assert_eq!(super::lapic_id_for_cpu(cpu_id), None);
        assert_eq!(
            super::identity_value_registered_cpu(cpu_id as u64 + 1),
            None
        );
        super::register_cpu_id(cpu_id, 248);
        assert_eq!(
            super::identity_value_registered_cpu(cpu_id as u64 + 1),
            Some(cpu_id)
        );
        assert_eq!(super::identity_value_registered_cpu(0), None);
    }

    #[test]
    fn identity_method_is_what_every_cpu_reports() {
        use super::{identity_method_for, IdentityMethod, REPORTS_RDPID, REPORTS_RDTSCP};
        let both = REPORTS_RDPID | REPORTS_RDTSCP;
        let online = 0b1011;
        assert_eq!(
            identity_method_for(both, online, online),
            IdentityMethod::Rdpid
        );
        assert_eq!(
            identity_method_for(REPORTS_RDPID, online, online),
            IdentityMethod::Rdpid
        );
        // One CPU without RDPID: the CPUs share what all of them report.
        assert_eq!(
            identity_method_for(REPORTS_RDTSCP, online, online),
            IdentityMethod::Rdtscp
        );
        // One CPU with neither.
        assert_eq!(
            identity_method_for(0, online, online),
            IdentityMethod::Lapic
        );
        assert_eq!(
            IdentityMethod::from_u8(IdentityMethod::Rdpid as u8),
            IdentityMethod::Rdpid
        );
        assert_eq!(
            IdentityMethod::from_u8(IdentityMethod::Rdtscp as u8),
            IdentityMethod::Rdtscp
        );
        assert_eq!(IdentityMethod::from_u8(7), IdentityMethod::Lapic);
        assert_eq!(IdentityMethod::Rdtscp.name(), "rdtscp");
    }

    #[test]
    fn identity_method_needs_every_online_cpu_published() {
        use super::{identity_method_for, IdentityMethod, REPORTS_RDPID, REPORTS_RDTSCP};
        let both = REPORTS_RDPID | REPORTS_RDTSCP;
        let online = 0b1011;
        assert_eq!(
            identity_method_for(both, 0b0011, online),
            IdentityMethod::Lapic
        );
        assert_eq!(identity_method_for(both, 0, online), IdentityMethod::Lapic);
        assert_eq!(identity_method_for(both, 0, 0), IdentityMethod::Lapic);
        // A published CPU that is not online (rejected in bring-up) does not matter.
        assert_eq!(
            identity_method_for(both, 0b1111, online),
            IdentityMethod::Rdpid
        );
    }

    #[test]
    fn duplicate_online_publication_is_idempotent() {
        let mask = 1u64 | (1u64 << (super::MAX_CPUS - 1));
        assert_eq!(
            super::online_mask_after_publish(mask, super::MAX_CPUS - 1),
            Some(mask)
        );
        assert_eq!(
            super::online_mask_after_publish(mask, super::MAX_CPUS),
            None
        );
    }

    #[test]
    fn cpu_local_slots_are_cache_line_isolated() {
        let local = super::CpuLocal::new(|| core::sync::atomic::AtomicUsize::new(0));
        let p0 = local.get_cpu(0).unwrap() as *const _ as usize;
        let p1 = local.get_cpu(1).unwrap() as *const _ as usize;
        assert_eq!(p0 % 64, 0, "CPU 0 slot must be 64-byte aligned");
        assert_eq!(p1 % 64, 0, "CPU 1 slot must be 64-byte aligned");
        assert!(
            p1.abs_diff(p0) >= 64,
            "adjacent CPU slots must not share a 64-byte cache line (delta={})",
            p1.abs_diff(p0)
        );
    }

    #[test]
    fn per_cpu_data_and_tlb_mailbox_are_cache_line_isolated() {
        assert!(core::mem::align_of::<super::PerCpuData>() >= 64);
        assert!(core::mem::align_of::<super::TlbShootdownMailbox>() >= 64);
        let mailbox_off = core::mem::offset_of!(super::PerCpuData, tlb_mailbox);
        let kpti_off = core::mem::offset_of!(super::PerCpuData, kpti_seq);
        assert_eq!(
            mailbox_off % 64,
            0,
            "tlb_mailbox must start on a 64-byte boundary"
        );
        assert_eq!(
            kpti_off % 64,
            0,
            "kpti_seq must start on a fresh 64-byte cache line after tlb_mailbox"
        );
        assert!(
            kpti_off >= mailbox_off + core::mem::size_of::<super::TlbShootdownMailbox>(),
            "kpti_seq must not overlap tlb_mailbox"
        );
    }

    #[test]
    fn issue109_2_1_gs_base_identity_precedence_and_gate() {
        use super::{
            identity_method_with_gs, IdentityMethod, GS_CPU_ID_OFFSET, GS_PER_CPU_DATA_PTR_OFFSET,
            REPORTS_RDPID, REPORTS_RDTSCP,
        };
        let both = REPORTS_RDPID | REPORTS_RDTSCP;
        let online = 0b1011;
        // GS-base takes precedence over RDPID/RDTSCP/LAPIC once every online CPU published.
        assert_eq!(
            identity_method_with_gs(online, both, online, online),
            IdentityMethod::GsBase
        );
        assert_eq!(
            identity_method_with_gs(online, 0, 0, online),
            IdentityMethod::GsBase
        );
        // Extra published bit for a rejected offline CPU is harmless.
        assert_eq!(
            identity_method_with_gs(0b1111, both, online, online),
            IdentityMethod::GsBase
        );
        // Missing even one online CPU falls back to RDPID/RDTSCP/LAPIC.
        assert_eq!(
            identity_method_with_gs(0b0011, both, online, online),
            IdentityMethod::Rdpid
        );
        assert_eq!(
            identity_method_with_gs(0, REPORTS_RDTSCP, online, online),
            IdentityMethod::Rdtscp
        );
        assert_eq!(
            identity_method_with_gs(online, both, online, 0),
            IdentityMethod::Lapic
        );
        assert_eq!(
            IdentityMethod::from_u8(IdentityMethod::GsBase as u8),
            IdentityMethod::GsBase
        );
        assert_eq!(IdentityMethod::GsBase.name(), "gsbase");
        assert_eq!(GS_CPU_ID_OFFSET, 80);
        assert_eq!(GS_PER_CPU_DATA_PTR_OFFSET, 88);

        // Issue #109 §2.1: mirror the 4-state paranoid MSR bit-63 SWAPGS predicate
        // used by NMI / #DB / #MC / #DF stubs:
        //   (gs_base < 0)                          => kernel GS already active (no swap)
        //   (gs_base >= 0 && kernel_gs_base < 0)   => user GS / swapgs-window (must swap)
        //   (gs_base >= 0 && kernel_gs_base >= 0)  => early boot before init (no swap)
        let paranoid_needs_swap = |gs_base: u64, kernel_gs_base: u64| -> bool {
            (gs_base as i64) >= 0 && (kernel_gs_base as i64) < 0
        };
        let user_zero = 0u64;
        let user_nonzero = 0x0000_7fff_1234_5000u64;
        let kernel_slot = 0xffff_ffff_8012_3400u64;
        assert!(!paranoid_needs_swap(user_zero, user_zero)); // early boot
        assert!(!paranoid_needs_swap(kernel_slot, user_zero)); // normal Ring-0, user GS=0
        assert!(!paranoid_needs_swap(kernel_slot, user_nonzero)); // normal Ring-0, user GS!=0
        assert!(paranoid_needs_swap(user_zero, kernel_slot)); // Ring-3 / swapgs window, user GS=0
        assert!(paranoid_needs_swap(user_nonzero, kernel_slot)); // Ring-3 / swapgs window, user GS!=0
    }
}
