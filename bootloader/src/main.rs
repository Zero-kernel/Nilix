#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, BootServices, MemoryType};
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};
use uefi::CStr16;
use uefi::Identify;
use xmas_elf::program::Type;
use xmas_elf::sections::SectionData;
use xmas_elf::ElfFile;

// ============================================================================
// R39-7 FIX: KASLR Configuration
// ============================================================================

/// Kernel load base physical address (matches kernel/security/kaslr.rs)
const KERNEL_PHYS_BASE: u64 = 0x100000;
/// Kernel virtual base address matching the linker script.
/// Used to filter out non-kernel LOAD segments (e.g., `.rela.dyn` metadata at VA 0).
const KERNEL_VIRT_BASE: u64 = 0xffffffff80000000;

/// R167-C: BootInfo ABI version. MUST match `BOOT_INFO_VERSION` in
/// `kernel/mm/memory.rs`. Bump on any change to the `BootInfo` layout.
const BOOT_INFO_VERSION: u64 = 3;

/// N3.1a (#67): Dedicated high-half linear direct map (`PML4[273]`), decoupled
/// from the 1 GiB kernel image window at `PML4[511]/PDPT[510]`.
const DIRECT_MAP_PML4_INDEX: usize = 273;
const DIRECT_MAP_OFFSET: u64 = 0xffff_8880_0000_0000;
/// Maximum physical address mapped into `PML4[273]` (64 GiB; 1 PML4 + 1 PDPT + <=64 PDs).
const DIRECT_MAP_MAX_PHYS_CAP: u64 = 64 * 1024 * 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
const TWO_MIB: u64 = 2 * 1024 * 1024;

/// BootInfo `kaslr_flags`: the exact placement order was produced by a
/// complete, unbiased RDRAND-backed shuffle. A non-zero relocation slide
/// without this bit is availability relocation, not KASLR.
const BOOT_INFO_KASLR_RANDOMIZED: u64 = 1 << 0;

/// Maximum KASLR slide (512 MiB, within the 1GB high-half mapping)
const KASLR_MAX_SLIDE: u64 = 512 * 1024 * 1024;

/// KASLR slide granularity.  The initial page tables cover the whole 1 GiB
/// window, so placement does not need to be constrained to huge-page
/// boundaries.  A 64 KiB quantum provides materially more than the old
/// eight-bit placement entropy while keeping the bounded permutation small.
const KASLR_SLIDE_GRANULARITY: u64 = 64 * 1024;

/// Physical window covered by the initial high-half 1 GiB mapping.
const KERNEL_PHYS_WINDOW_END: u64 = 1024 * 1024 * 1024;

/// F9: highest address of a page the kernel reaches through its 1 GiB direct
/// map (page-table frames, BootInfo, the memory-map copy). UEFI allocates
/// top-down, so with 2 GiB of RAM or more an unbounded allocation landed above
/// the window and the kernel's first page-table walk faulted.
const DIRECT_MAP_MAX_ADDRESS: u64 = KERNEL_PHYS_WINDOW_END - 1;

/// Defensive upper bound for the kernel file read.  The UEFI file metadata is
/// untrusted input; refusing an absurd length keeps a corrupt directory entry
/// from turning the bootloader's initial allocation into an unbounded request.
const KERNEL_MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Maximum post-ExitBootServices memory-map snapshot.  The buffer is sized for
/// a deliberately generous descriptor budget (2 MiB) and is checked against
/// the firmware-reported byte count before copying; a corrupt/hostile map is
/// rejected without an out-of-bounds write.
const MEMORY_MAP_COPY_PAGES: usize = 512;

/// Number of bounded placement slots, including slide zero.
const KASLR_SLOT_COUNT: usize = (KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY + 1) as usize;

const _: () = assert!(KASLR_MAX_SLIDE.is_multiple_of(KASLR_SLIDE_GRANULARITY));
const _: () = assert!(KERNEL_PHYS_BASE + KASLR_MAX_SLIDE < KERNEL_PHYS_WINDOW_END);
const _: () = assert!(KASLR_SLOT_COUNT <= u16::MAX as usize + 1);

/// U55-6: Position-independent 64-bit CR3-switch-and-jump stub copied into a
/// dedicated 4 KiB `LOADER_CODE` page below `DIRECT_MAP_MAX_ADDRESS`.
///
/// Register contract on entry (interrupts disabled, EFER.NXE=1, CR0.WP=1):
/// - `rax`: new CR3 value (PML4 physical address | CR3 flags)
/// - `rdi`: `BootInfo` pointer (System V AMD64 arg 1 for kernel `_start`)
/// - `r8`:  high-half kernel entry virtual address
///
/// Instructions:
/// - `0f 22 d8`: `mov cr3, rax`  (switches to W^X-hardened PML4)
/// - `41 ff e0`: `jmp r8`        (transfers directly to high-half RX kernel `_start`)
/// - `0f 0b`:    `ud2`           (unreachable trap)
const CR3_TRANSITION_STUB: [u8; 8] = [0x0F, 0x22, 0xD8, 0x41, 0xFF, 0xE0, 0x0F, 0x0B];

/// U55-6 / N3.1a: Fail-closed verification of the boot page tables before `ExitBootServices`.
///
/// Proves that from the very first instruction after `mov cr3, rax`:
/// 1. Neither `PML4[0]` (identity map), `PML4[273]` (linear direct map), nor
///    `PML4[511]` (high-half kernel image window) contains any leaf that is
///    simultaneously writable and executable (W+X).
/// 2. In `PML4[0]`, the ONLY executable leaf is the single 4 KiB R-X CR3
///    transition stub page at `transition_stub_phys`.
/// 3. In `PML4[273]`, `NO_EXECUTE` is set at the PML4 entry and ZERO leaves are
///    executable.
/// 4. No physical frame mapped executable in `PML4[0]` or `PML4[511]` has a
///    live writable alias in any other root hierarchy.
/// 5. `PML4[510]` (recursive mapping) has `NO_EXECUTE` set.
unsafe fn verify_boot_page_tables(pml4_frame: u64, transition_stub_phys: u64) {
    use x86_64::structures::paging::{PageTable, PageTableFlags as Flags};

    let pml4 = &*(pml4_frame as *const PageTable);

    // 1. Recursive slot and linear direct map slot must remain non-executable.
    let rec = &pml4[510];
    if rec.is_unused() || !rec.flags().contains(Flags::NO_EXECUTE) {
        panic!("U55-6: PML4[510] recursive mapping missing or executable");
    }
    let dm = &pml4[DIRECT_MAP_PML4_INDEX];
    if dm.is_unused()
        || !dm.flags().contains(Flags::PRESENT)
        || !dm.flags().contains(Flags::NO_EXECUTE)
    {
        panic!("U55-6: PML4[273] linear direct map missing or executable");
    }

    let lookup_writable = |root_idx: usize, target_phys: u64| -> bool {
        let pml4e = &pml4[root_idx];
        if pml4e.is_unused() || !pml4e.flags().contains(Flags::PRESENT) {
            return false;
        }
        let mut eff_w = pml4e.flags().contains(Flags::WRITABLE);
        let pdpt = &*(pml4e.addr().as_u64() as *const PageTable);
        let pdpt_idx = if root_idx == 511 {
            if target_phys >= KERNEL_PHYS_WINDOW_END {
                return false;
            }
            510usize
        } else {
            let idx = (target_phys / 0x4000_0000) as usize;
            if idx >= 512 {
                return false;
            }
            idx
        };
        let pdpte = &pdpt[pdpt_idx];
        if pdpte.is_unused() || !pdpte.flags().contains(Flags::PRESENT) {
            return false;
        }
        eff_w &= pdpte.flags().contains(Flags::WRITABLE);
        if pdpte.flags().contains(Flags::HUGE_PAGE) {
            return eff_w;
        }
        let pd = &*(pdpte.addr().as_u64() as *const PageTable);
        let pd_idx = ((target_phys % 0x4000_0000) / 0x20_0000) as usize;
        let pde = &pd[pd_idx];
        if pde.is_unused() || !pde.flags().contains(Flags::PRESENT) {
            return false;
        }
        eff_w &= pde.flags().contains(Flags::WRITABLE);
        if pde.flags().contains(Flags::HUGE_PAGE) {
            return eff_w;
        }
        let pt = &*(pde.addr().as_u64() as *const PageTable);
        let pt_idx = ((target_phys % 0x20_0000) / KERNEL_PAGE_SIZE) as usize;
        let pte = &pt[pt_idx];
        if pte.is_unused() || !pte.flags().contains(Flags::PRESENT) {
            return false;
        }
        eff_w && pte.flags().contains(Flags::WRITABLE)
    };

    let mut low_exec_leaves = 0usize;
    let mut high_exec_leaves = 0usize;
    let roots = [0usize, DIRECT_MAP_PML4_INDEX, 511usize];

    for &root_idx in &roots {
        let pml4e = &pml4[root_idx];
        if pml4e.is_unused() || !pml4e.flags().contains(Flags::PRESENT) {
            panic!("U55-6: expected PML4[{}] to be present", root_idx);
        }
        let p4_w = pml4e.flags().contains(Flags::WRITABLE);
        let p4_x = !pml4e.flags().contains(Flags::NO_EXECUTE);
        let pdpt = &*(pml4e.addr().as_u64() as *const PageTable);
        for pdpte in pdpt.iter() {
            if pdpte.is_unused() || !pdpte.flags().contains(Flags::PRESENT) {
                continue;
            }
            let p3_w = p4_w && pdpte.flags().contains(Flags::WRITABLE);
            let p3_x = p4_x && !pdpte.flags().contains(Flags::NO_EXECUTE);
            if pdpte.flags().contains(Flags::HUGE_PAGE) {
                if p3_w && p3_x {
                    panic!("U55-6: 1 GiB RWX leaf in PML4[{}]", root_idx);
                }
                if p3_x {
                    panic!(
                        "U55-6: unexpected 1 GiB executable leaf in PML4[{}]",
                        root_idx
                    );
                }
                continue;
            }
            let pd = &*(pdpte.addr().as_u64() as *const PageTable);
            for pde in pd.iter() {
                if pde.is_unused() || !pde.flags().contains(Flags::PRESENT) {
                    continue;
                }
                let p2_w = p3_w && pde.flags().contains(Flags::WRITABLE);
                let p2_x = p3_x && !pde.flags().contains(Flags::NO_EXECUTE);
                if pde.flags().contains(Flags::HUGE_PAGE) {
                    if p2_w && p2_x {
                        panic!("U55-6: 2 MiB RWX leaf in PML4[{}]", root_idx);
                    }
                    if p2_x {
                        panic!(
                            "U55-6: unexpected 2 MiB executable leaf in PML4[{}]",
                            root_idx
                        );
                    }
                    continue;
                }
                let pt = &*(pde.addr().as_u64() as *const PageTable);
                for pte in pt.iter() {
                    if pte.is_unused() || !pte.flags().contains(Flags::PRESENT) {
                        continue;
                    }
                    let p1_w = p2_w && pte.flags().contains(Flags::WRITABLE);
                    let p1_x = p2_x && !pte.flags().contains(Flags::NO_EXECUTE);
                    if p1_w && p1_x {
                        panic!("U55-6: 4 KiB RWX leaf in PML4[{}]", root_idx);
                    }
                    if p1_x {
                        let phys = pte.addr().as_u64();
                        if root_idx == 0 {
                            if phys != transition_stub_phys {
                                panic!("U55-6: unexpected executable leaf in PML4[0]");
                            }
                            low_exec_leaves += 1;
                        } else if root_idx == 511 {
                            high_exec_leaves += 1;
                        } else {
                            panic!("U55-6: unexpected executable leaf in PML4[{}]", root_idx);
                        }
                        for &other_idx in &roots {
                            if other_idx != root_idx && lookup_writable(other_idx, phys) {
                                panic!(
                                    "U55-6: live writable alias in PML4[{}] for executable leaf in PML4[{}]",
                                    other_idx, root_idx
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    if low_exec_leaves != 1 {
        panic!(
            "U55-6: expected exactly 1 executable leaf in PML4[0] (transition stub), found {}",
            low_exec_leaves
        );
    }
    if high_exec_leaves == 0 {
        panic!("U55-6: expected at least 1 executable kernel leaf in PML4[511]");
    }
}

/// ELF relocation type: R_X86_64_RELATIVE (base + addend)
const R_X86_64_RELATIVE: u32 = 8;

/// Apply `.rela.dyn` relocations to the loaded kernel image.
///
/// A static-PIE kernel emits only `R_X86_64_RELATIVE` relocations (no GOT/PLT
/// symbol references). Each entry patches an absolute address in the loaded
/// image: `*site = addend + load_bias`.
///
/// # Arguments
///
/// * `elf` — Parsed ELF file (still refers to the original in-memory buffer)
/// * `kernel_min_vaddr` — Lowest virtual address among LOAD segments (link-time base)
/// * `kernel_phys_base` — Physical address where the kernel image is loaded
/// * `load_bias` — KASLR slide: the delta between the actual and linked load addresses
///
/// # Panics
///
/// Panics if:
/// - `load_bias != 0` but the kernel has no `.rela.dyn` section
/// - Any relocation type other than `R_X86_64_RELATIVE` is encountered
/// - A relocation targets a VA below `kernel_min_vaddr`
/// - A relocation target + 8 exceeds the kernel image bounds
fn apply_rela_dyn_relocations(
    elf: &ElfFile<'_>,
    kernel_min_vaddr: u64,
    kernel_size: u64,
    kernel_phys_base: u64,
    load_bias: u64,
) {
    let rela_dyn = match elf.find_section_by_name(".rela.dyn") {
        Some(section) => section,
        None => {
            if load_bias != 0 {
                // R120-4 FIX: Do not include the KASLR slide value in the panic
                // string — it would be captured by UEFI firmware logs, serial
                // console, or BMC/IPMI history, leaking the slide in release builds.
                panic!(
                    "KASLR slide is non-zero but kernel has no .rela.dyn section — \
                     kernel must be compiled as PIE (-C relocation-model=pie) \
                     and keep relocation sections in the linker script"
                );
            }
            // No relocations and no slide — nothing to do
            return;
        }
    };

    let relas = match rela_dyn
        .get_data(elf)
        .expect("Failed to parse .rela.dyn section data")
    {
        SectionData::Rela64(relas) => relas,
        _ => panic!("Unexpected .rela.dyn format (expected Rela64 for x86_64 kernel)"),
    };

    if relas.is_empty() {
        return;
    }

    // R119-1 FIX: Gate load_bias value behind debug_assertions to prevent KASLR
    // slide leak to serial console observers. The relocation count is safe to log.
    #[cfg(debug_assertions)]
    info!(
        "Applying {} .rela.dyn relocations (load_bias=0x{:x})",
        relas.len(),
        load_bias
    );
    #[cfg(not(debug_assertions))]
    info!("Applying {} .rela.dyn relocations", relas.len());

    let mut applied = 0u64;
    for rela in relas {
        let rtype = rela.get_type();
        if rtype != R_X86_64_RELATIVE {
            panic!(
                "Unsupported relocation type {} at offset 0x{:x} — \
                 static-PIE kernel should only emit R_X86_64_RELATIVE (type 8)",
                rtype,
                rela.get_offset()
            );
        }

        // R_X86_64_RELATIVE must have symbol index 0
        if rela.get_symbol_table_index() != 0 {
            panic!(
                "R_X86_64_RELATIVE at offset 0x{:x} has unexpected symbol index {} — \
                 expected 0 for base-relative relocations",
                rela.get_offset(),
                rela.get_symbol_table_index()
            );
        }

        let reloc_va = rela.get_offset();
        if reloc_va < kernel_min_vaddr {
            panic!(
                "Relocation target VA 0x{:x} is below kernel base VA 0x{:x}",
                reloc_va, kernel_min_vaddr
            );
        }
        let offset_in_image = reloc_va - kernel_min_vaddr;
        // Each relocation writes a u64 (8 bytes); ensure the write stays within
        // the allocated kernel image to prevent out-of-bounds memory corruption.
        if offset_in_image + 8 > kernel_size {
            panic!(
                "Relocation at VA 0x{:x} (offset 0x{:x}) + 8 exceeds kernel image size 0x{:x}",
                reloc_va, offset_in_image, kernel_size
            );
        }

        // Translate the virtual address to the physical address in the loaded image
        let site_phys = kernel_phys_base + offset_in_image;

        // R_X86_64_RELATIVE: *site = addend + load_bias
        // addend is the link-time absolute VA; adding load_bias shifts it to the slid VA
        let value = rela.get_addend().wrapping_add(load_bias);

        unsafe {
            core::ptr::write_unaligned(site_phys as *mut u64, value);
        }
        applied += 1;
    }

    info!("  {} relocations applied successfully", applied);
}

#[cfg(feature = "kaslr")]
#[derive(Clone, Copy)]
struct HardwareEntropyCapabilities {
    rdseed: bool,
    rdrand: bool,
}

/// Detect each hardware entropy instruction independently.
///
/// CPUID leaf 7 is queried only when the maximum basic leaf advertises it.
/// This distinction is load-bearing: RDRAND support does not imply RDSEED
/// support, and executing an unsupported instruction raises #UD in firmware.
#[cfg(feature = "kaslr")]
fn hardware_entropy_capabilities() -> HardwareEntropyCapabilities {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    let maximum_basic_leaf = unsafe { __cpuid(0) }.eax;
    let rdrand = if maximum_basic_leaf >= 1 {
        (unsafe { __cpuid(1) }.ecx & (1 << 30)) != 0
    } else {
        false
    };
    let rdseed = if maximum_basic_leaf >= 7 {
        (unsafe { __cpuid_count(7, 0) }.ebx & (1 << 18)) != 0
    } else {
        false
    };

    HardwareEntropyCapabilities { rdseed, rdrand }
}

/// Probe hardware entropy safely before the permutation consumes additional
/// samples. RDSEED is preferred when present; RDRAND is retained as a
/// fallback. The capability set is carried through the whole permutation so
/// no later sample can execute an instruction that CPUID did not authorize;
/// transient RDSEED backpressure can still fall through to supported RDRAND.
/// A successful sample is deliberately discarded; provenance is published
/// only after the complete unbiased shuffle succeeds.
#[cfg(feature = "kaslr")]
fn probe_entropy_sources() -> Option<HardwareEntropyCapabilities> {
    let capabilities = hardware_entropy_capabilities();

    let rdseed_ready = capabilities.rdseed && unsafe { next_rdseed_u64() }.is_some();
    let rdrand_ready = capabilities.rdrand && unsafe { next_rdrand_u64() }.is_some();
    if rdseed_ready || rdrand_ready {
        Some(capabilities)
    } else {
        None
    }
}

#[cfg(feature = "kaslr")]
/// Read one RDSEED sample with bounded retries.
///
/// # Safety
///
/// The caller must first verify CPUID.07H:EBX[18]. Executing RDSEED without
/// that capability raises #UD before the bootloader can install an exception
/// handler.
unsafe fn next_rdseed_u64() -> Option<u64> {
    for _ in 0..16 {
        let value: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdseed {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nostack, nomem),
            );
        }
        if success == 1 {
            return Some(value);
        }
    }
    None
}

#[cfg(feature = "kaslr")]
#[inline]
fn read_tsc_entropy() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, nomem, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(feature = "kaslr")]
/// Read one RDRAND sample with bounded retries.
///
/// # Safety
///
/// The caller must first verify CPUID.01H:ECX[30]. Executing RDRAND without
/// that capability raises #UD before the bootloader can install an exception
/// handler.
unsafe fn next_rdrand_u64() -> Option<u64> {
    for _ in 0..10 {
        let value: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nostack, nomem),
            );
        }
        if success == 1 {
            return Some(value);
        }
    }
    None
}

#[cfg(feature = "kaslr")]
fn next_entropy_u64(sources: HardwareEntropyCapabilities) -> Option<u64> {
    let tsc = read_tsc_entropy();
    if sources.rdseed {
        if let Some(seed) = unsafe { next_rdseed_u64() } {
            return Some(seed ^ tsc.rotate_left(17));
        }
    }
    if sources.rdrand {
        return unsafe { next_rdrand_u64() }.map(|random| random ^ tsc.rotate_left(29));
    }
    None
}

#[cfg(feature = "kaslr")]
fn uniform_entropy_below(upper: u64, sources: HardwareEntropyCapabilities) -> Option<u64> {
    assert!(upper > 0, "entropy bound must be non-zero");
    let threshold = upper.wrapping_neg() % upper;
    for _ in 0..32 {
        let value = next_entropy_u64(sources)?;
        if value >= threshold {
            return Some(value % upper);
        }
    }
    None
}

/// RF180-32 FIX: build a complete exact-address candidate order.
///
/// With healthy entropy this is an unbiased Fisher-Yates permutation, so the
/// first UEFI-allocatable member is uniform over the viable subset even when
/// much of the configured window is absent. If CPUID, RDRAND, or any shuffle
/// sample fails, discard the partial permutation and search every slot in a
/// deterministic order for availability without claiming KASLR.
fn kernel_placement_order() -> ([u16; KASLR_SLOT_COUNT], bool) {
    let mut deterministic = [0u16; KASLR_SLOT_COUNT];
    for (index, slot) in deterministic.iter_mut().enumerate() {
        *slot = u16::try_from(index).expect("KASLR slot index exceeds u16");
    }

    #[cfg(feature = "kaslr")]
    {
        let Some(sources) = probe_entropy_sources() else {
            return (deterministic, false);
        };
        let mut shuffled = deterministic;
        for upper in (2..=KASLR_SLOT_COUNT).rev() {
            let Some(other) = uniform_entropy_below(upper as u64, sources) else {
                return (deterministic, false);
            };
            shuffled.swap(upper - 1, other as usize);
        }
        (shuffled, true)
    }

    #[cfg(not(feature = "kaslr"))]
    {
        (deterministic, false)
    }
}

/// RF180-32 FIX: allocate the kernel at an exact, relocatable address inside
/// the initial high-half physical window.
///
/// UEFI `AllocateType::Address` is the allocation authority. A memory-map
/// snapshot would introduce a stale-snapshot TOCTOU, so this consumes the
/// complete candidate order above and lets exact allocation decide. The first
/// exact allocation wins; no failed candidate publishes state.
fn allocate_kernel_image_pages(
    boot_services: &BootServices,
    pages: usize,
    alloc_bytes: u64,
) -> (u64, u64, bool) {
    assert!(
        pages > 0,
        "ELF kernel allocation must contain at least one page"
    );
    assert!(alloc_bytes > 0, "ELF kernel allocation must contain bytes");

    let (order, randomized) = kernel_placement_order();

    for (attempt, slot) in order.into_iter().enumerate() {
        let slide = u64::from(slot)
            .checked_mul(KASLR_SLIDE_GRANULARITY)
            .expect("KASLR slot multiplication overflow");
        let candidate = KERNEL_PHYS_BASE
            .checked_add(slide)
            .expect("KASLR physical base overflow");
        let candidate_end = candidate
            .checked_add(alloc_bytes)
            .expect("KASLR physical extent overflow");
        if candidate_end > KERNEL_PHYS_WINDOW_END {
            continue;
        }

        match boot_services.allocate_pages(
            AllocateType::Address(candidate),
            MemoryType::LOADER_DATA,
            pages,
        ) {
            Ok(allocated) => {
                if allocated != candidate {
                    let freed = unsafe { boot_services.free_pages(allocated, pages) };
                    assert!(
                        freed.is_ok(),
                        "UEFI returned and retained an unexpected kernel allocation"
                    );
                    panic!("UEFI violated exact-address kernel allocation semantics");
                }
                #[cfg(debug_assertions)]
                if attempt != 0 {
                    info!(
                        "Kernel placement used bounded fallback attempt {} of {}",
                        attempt + 1,
                        KASLR_SLOT_COUNT
                    );
                }
                #[cfg(not(debug_assertions))]
                if attempt != 0 {
                    info!("Kernel placement used bounded exact-address fallback");
                }
                return (allocated, slide, randomized);
            }
            Err(error) => match error.status() {
                uefi::Status::NOT_FOUND | uefi::Status::OUT_OF_RESOURCES => continue,
                uefi::Status::INVALID_PARAMETER => {
                    panic!("UEFI rejected a validated kernel allocation request")
                }
                _ => panic!("UEFI returned an unexpected kernel allocation failure"),
            },
        }
    }

    panic!(
        "FATAL: no contiguous {}-page kernel range exists in the bounded {}-slot high-half window",
        pages, KASLR_SLOT_COUNT
    );
}

/// Locate the ACPI RSDP via the UEFI configuration table.
///
/// Prefers ACPI 2.0 GUID, falls back to ACPI 1.0 GUID if not available.
/// Returns 0 if RSDP cannot be found.
fn find_rsdp_address(system_table: &SystemTable<Boot>) -> u64 {
    // Try ACPI 2.0 first (preferred)
    for entry in system_table.config_table() {
        if entry.guid == ACPI2_GUID {
            let addr = entry.address as usize as u64;
            info!("ACPI 2.0 RSDP found at 0x{:x}", addr);
            return addr;
        }
    }

    // Fall back to ACPI 1.0
    for entry in system_table.config_table() {
        if entry.guid == ACPI_GUID {
            let addr = entry.address as usize as u64;
            info!("ACPI 1.0 RSDP found at 0x{:x}", addr);
            return addr;
        }
    }

    info!("ACPI RSDP not found in UEFI configuration table");
    0
}

/// P1-1: Read UEFI load options (boot command line) into a fixed-size ASCII buffer.
///
/// UEFI load options are UCS-2 (little-endian u16) encoded. This function
/// down-converts ASCII-range code points to single bytes (non-ASCII → `?`)
/// and rejects input over 256 bytes. Returns `(len, buffer)`.
///
/// Must be called **before** `exit_boot_services()` — the LoadedImage
/// protocol becomes inaccessible after that point.
fn read_uefi_cmdline(handle: Handle, system_table: &SystemTable<Boot>) -> (usize, [u8; 256]) {
    let mut cmdline = [0u8; 256];
    let mut cmdline_len = 0usize;

    let boot_services = system_table.boot_services();
    if let Ok(loaded_image) = boot_services.open_protocol_exclusive::<LoadedImage>(handle) {
        if let Some(bytes) = loaded_image.load_options_as_bytes() {
            // UCS-2 little-endian: each character is 2 bytes (lo, hi).
            let mut i = 0;
            while i + 1 < bytes.len() {
                let lo = bytes[i];
                let hi = bytes[i + 1];
                i += 2;
                // Stop at NUL terminator
                if lo == 0 && hi == 0 {
                    break;
                }
                assert!(
                    cmdline_len < cmdline.len(),
                    "boot command line exceeds 256 bytes"
                );
                // ASCII range: hi == 0 && lo <= 0x7F
                cmdline[cmdline_len] = if hi == 0 && lo <= 0x7F { lo } else { b'?' };
                cmdline_len += 1;
            }
        }
    }

    (cmdline_len, cmdline)
}

/// 内存映射信息，传递给内核
#[repr(C)]
pub struct MemoryMapInfo {
    pub buffer: u64,             // 内存映射缓冲区地址
    pub size: usize,             // 缓冲区大小
    pub descriptor_size: usize,  // 每个描述符的大小
    pub descriptor_version: u32, // 描述符版本
}

/// 像素格式
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum PixelFormat {
    /// RGB (8位红, 8位绿, 8位蓝, 8位保留)
    Rgb = 0,
    /// BGR (8位蓝, 8位绿, 8位红, 8位保留)
    Bgr = 1,
    /// 未知格式
    Unknown = 2,
}

/// 帧缓冲区信息 (GOP framebuffer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// 帧缓冲区物理地址
    pub base: u64,
    /// 帧缓冲区大小（字节）
    pub size: usize,
    /// 水平分辨率（像素）
    pub width: u32,
    /// 垂直分辨率（像素）
    pub height: u32,
    /// 每行的字节数（stride）
    pub stride: u32,
    /// 像素格式
    pub pixel_format: PixelFormat,
}

/// 引导信息结构，传递给内核
#[repr(C)]
pub struct BootInfo {
    pub memory_map: MemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    /// R39-7/RF180-32: relocation slide. Randomization is reported separately
    /// in `kaslr_flags`; zero is a valid randomly selected slot.
    pub kaslr_slide: u64,
    /// ACPI RSDP physical address (from UEFI configuration table)
    pub rsdp_address: u64,
    /// P1-1: UEFI boot command line length in bytes (ASCII, max 256).
    pub cmdline_len: usize,
    /// P1-1: UEFI boot command line buffer (ASCII, NUL-padded).
    pub cmdline: [u8; 256],
    /// R167-C: physical base where the kernel image was loaded
    /// (`KERNEL_PHYS_BASE + kaslr_slide`).
    pub kernel_phys_base: u64,
    /// R167-C: in-memory size of the kernel image in bytes.
    pub kernel_phys_size: u64,
    /// R167-C: BootInfo ABI version (see `BOOT_INFO_VERSION`).
    pub version: u64,
    /// RF180-32: placement provenance flags. `BOOT_INFO_KASLR_RANDOMIZED`
    /// means the complete candidate order was uniformly randomized; the slide
    /// alone never proves KASLR because deterministic relocation is permitted.
    pub kaslr_flags: u64,
    /// N3.1a (#67): virtual base of the linear physical direct map (`PML4[273]`).
    pub direct_map_base: u64,
    /// N3.1a (#67): exclusive upper physical bound covered by `PML4[273]`
    /// (1 GiB multiple, `>= 1 GiB`, `<= DIRECT_MAP_MAX_PHYS_CAP`).
    pub direct_map_limit: u64,
}

/// N3.1a (#67): inspect the UEFI memory map before page-table construction so
/// `PML4[273]` maps every write-back RAM and firmware range up to 64 GiB while
/// leaving pure PCI MMIO holes unmapped.
fn discover_direct_map_plan(boot_services: &BootServices) -> (u64, Vec<(u64, u64)>) {
    use uefi::table::boot::MemoryAttribute;

    let mmap = boot_services
        .memory_map(MemoryType::LOADER_DATA)
        .expect("N3.1a: failed to query UEFI memory map for direct-map sizing");

    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut max_end: u64 = ONE_GIB;

    for desc in mmap.entries() {
        if desc.page_count == 0 {
            continue;
        }
        let is_ram_or_fw = matches!(
            desc.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::LOADER_CODE
                | MemoryType::LOADER_DATA
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
                | MemoryType::RUNTIME_SERVICES_CODE
                | MemoryType::RUNTIME_SERVICES_DATA
                | MemoryType::ACPI_RECLAIM
                | MemoryType::ACPI_NON_VOLATILE
                | MemoryType::PERSISTENT_MEMORY
        ) || (desc.ty == MemoryType::RESERVED
            && desc.att.contains(MemoryAttribute::WRITE_BACK));
        if !is_ram_or_fw {
            continue;
        }
        let start = desc.phys_start;
        if start >= DIRECT_MAP_MAX_PHYS_CAP {
            continue;
        }
        let end = start
            .saturating_add(desc.page_count.saturating_mul(KERNEL_PAGE_SIZE))
            .min(DIRECT_MAP_MAX_PHYS_CAP);
        if end <= start {
            continue;
        }
        if end > max_end {
            max_end = end;
        }
        ranges.push((start, end));
    }

    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }

    let aligned_limit = ((max_end + ONE_GIB - 1) & !(ONE_GIB - 1))
        .max(ONE_GIB)
        .min(DIRECT_MAP_MAX_PHYS_CAP);
    (aligned_limit, merged)
}

#[inline]
fn range_overlaps_any(ranges: &[(u64, u64)], start: u64, end: u64) -> bool {
    ranges.iter().any(|&(lo, hi)| lo < end && start < hi)
}

const KERNEL_PAGE_SIZE: u64 = 4096;
const KERNEL_PAGE_EXECUTABLE: u8 = 1 << 0;
const KERNEL_PAGE_WRITABLE: u8 = 1 << 1;
const KERNEL_PAGE_CLAIMED: u8 = 1 << 2;

struct KernelPagePermissions {
    phys_base: u64,
    pages: Vec<u8>,
}

impl KernelPagePermissions {
    fn get(&self, phys_page: u64) -> Option<u8> {
        let offset = phys_page.checked_sub(self.phys_base)?;
        if !offset.is_multiple_of(KERNEL_PAGE_SIZE) {
            return None;
        }
        let index = usize::try_from(offset / KERNEL_PAGE_SIZE).ok()?;
        self.pages.get(index).copied()
    }
}

#[entry]
fn efi_main(handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();

    info!("Rust Microkernel Bootloader v0.1");
    info!("Initializing...");

    // R39-7/RF180-32: get entry, relocation slide, image size, and provenance.
    // Codex Review Fix: kernel_size needed for accurate page table setup
    let (
        entry_point,
        kaslr_slide,
        kernel_size,
        kaslr_randomized,
        actual_phys_base,
        kernel_permissions,
    ) = {
        let boot_services = system_table.boot_services();

        let fs_handle = boot_services
            .locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(
                &SimpleFileSystem::GUID,
            ))
            .expect("Failed to locate file system handles");

        let fs_handle = fs_handle[0];

        let mut fs = boot_services
            .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
            .expect("Failed to open file system protocol");

        let mut root_dir = fs.open_volume().expect("Failed to open root directory");

        info!("Loading kernel...");
        let kernel_path = CStr16::from_u16_with_nul(&[
            b'k' as u16,
            b'e' as u16,
            b'r' as u16,
            b'n' as u16,
            b'e' as u16,
            b'l' as u16,
            b'.' as u16,
            b'e' as u16,
            b'l' as u16,
            b'f' as u16,
            0,
        ])
        .unwrap();

        let mut kernel_file = root_dir
            .open(kernel_path, FileMode::Read, FileAttribute::empty())
            .expect("Failed to open kernel.elf")
            .into_regular_file()
            .expect("kernel.elf is not a regular file");

        let mut info_buffer = [0u8; 512];
        let info = kernel_file
            .get_info::<FileInfo>(&mut info_buffer)
            .expect("Failed to get file info");

        let file_size =
            usize::try_from(info.file_size()).expect("kernel file size does not fit in usize");
        if file_size == 0 || file_size > KERNEL_MAX_FILE_SIZE {
            panic!("kernel.elf size outside the supported bootloader bound");
        }

        let mut kernel_data = Vec::new();
        kernel_data
            .try_reserve_exact(file_size)
            .expect("kernel.elf allocation failed");
        kernel_data.resize(file_size, 0);

        // 循环读取直到完整读取整个文件
        let mut total_read = 0usize;
        while total_read < file_size {
            let read_size = kernel_file
                .read(&mut kernel_data[total_read..])
                .expect("Failed to read kernel file");

            if read_size == 0 {
                // 读取返回0但文件未读完，说明发生了截断
                panic!(
                    "Kernel file read truncated: expected {} bytes, got {} bytes",
                    file_size, total_read
                );
            }
            total_read += read_size;
        }

        info!("Kernel loaded: {} bytes", total_read);

        info!("Parsing ELF...");
        let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF file");

        let entry_point = elf.header.pt2.entry_point();
        info!("Entry point: 0x{:x}", entry_point);

        assert_eq!(
            elf.header.pt1.magic,
            [0x7f, 0x45, 0x4c, 0x46],
            "Invalid ELF magic"
        );

        // 首先，计算内核需要的总内存大小
        let mut min_addr = u64::MAX;
        let mut max_addr = 0u64;

        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }
            let virt_addr = program_header.virtual_addr();
            // Skip non-kernel LOAD segments (e.g., .rela.dyn metadata at VA 0
            // emitted by PIE linking). Only kernel segments reside in the
            // high-half virtual range.
            if virt_addr < KERNEL_VIRT_BASE {
                continue;
            }
            let mem_size = program_header.mem_size();

            if virt_addr < min_addr {
                min_addr = virt_addr;
            }
            // R120-1 FIX: Use checked arithmetic to detect crafted ELF
            // headers with wrapping virt_addr + mem_size values.
            let end_addr = virt_addr
                .checked_add(mem_size)
                .expect("ELF LOAD segment virt_addr + mem_size overflow");
            if end_addr > max_addr {
                max_addr = end_addr;
            }
        }

        // 分配一块连续的内存来容纳整个内核
        //
        // Text KASLR: The kernel is compiled as a static PIE with
        // `-C relocation-model=pie`. The bootloader:
        //   1. Builds an unbiased random permutation of every 2 MiB slot when
        //      RDRAND is healthy; otherwise uses a deterministic full search
        //   2. Lets exact UEFI allocation choose the first available slot
        //   3. Carries randomization provenance separately from relocation
        //   4. Loads LOAD segments into the allocated region
        //   5. Applies .rela.dyn R_X86_64_RELATIVE relocations with slide as load_bias
        //   6. Jumps to entry_point + slide
        // R120-1 FIX: Use checked subtraction to detect empty LOAD segment set
        // (where no valid high-half segments were found).
        let kernel_size = max_addr
            .checked_sub(min_addr)
            .expect("ELF LOAD: max_addr < min_addr (no valid kernel segments)")
            as usize;
        // R120-1 FIX: Use checked arithmetic for page computation to prevent
        // wrapping on crafted ELF headers with absurd segment sizes.
        let pages = kernel_size
            .checked_add(0xFFF)
            .expect("ELF kernel size + page alignment overflow")
            / 0x1000;
        let alloc_bytes = pages
            .checked_mul(0x1000)
            .expect("Kernel allocation pages * 0x1000 overflow");

        // R119-1 FIX: Gate physical addresses and KASLR slide behind debug_assertions
        #[cfg(debug_assertions)]
        info!(
            "Allocating {} pages ({} bytes) for kernel",
            pages, kernel_size
        );
        #[cfg(not(debug_assertions))]
        info!(
            "Allocating {} pages ({} bytes) for kernel",
            pages, kernel_size
        );

        let (actual_phys_base, kaslr_slide, kaslr_randomized) = allocate_kernel_image_pages(
            boot_services,
            pages,
            u64::try_from(alloc_bytes).expect("kernel allocation size exceeds u64"),
        );

        // R119-1 FIX: Gate allocated address and slide behind debug_assertions
        #[cfg(debug_assertions)]
        info!(
            "Kernel memory allocated at 0x{:x} (final slide=0x{:x}, randomized={})",
            actual_phys_base, kaslr_slide, kaslr_randomized
        );
        #[cfg(not(debug_assertions))]
        info!(
            "Kernel memory allocated ({})",
            if kaslr_randomized {
                "randomized placement"
            } else if kaslr_slide != 0 {
                "deterministic availability relocation"
            } else {
                "fixed placement"
            }
        );

        // R120-1 FIX: Zero the entire page-aligned allocation (alloc_bytes),
        // not just kernel_size. This ensures the tail bytes (up to 4095) in
        // the last page are zeroed, preventing stale UEFI memory from being
        // mapped into the kernel's high-half virtual address range.
        unsafe {
            core::ptr::write_bytes(actual_phys_base as *mut u8, 0, alloc_bytes);
        }

        if !actual_phys_base.is_multiple_of(KERNEL_PAGE_SIZE) {
            panic!("UEFI kernel allocation is not page aligned");
        }
        let mut page_permissions = Vec::new();
        page_permissions
            .try_reserve_exact(pages)
            .expect("kernel page-permission allocation failed");
        page_permissions.resize(pages, 0);
        let mut kernel_permissions = KernelPagePermissions {
            phys_base: actual_phys_base,
            pages: page_permissions,
        };

        // 加载所有程序段 to the exact UEFI-selected physical address.
        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }

            let virt_addr = program_header.virtual_addr();
            // Skip non-kernel LOAD segments (e.g., .rela.dyn metadata at VA 0)
            if virt_addr < KERNEL_VIRT_BASE {
                continue;
            }
            let mem_size = program_header.mem_size();
            let file_size = program_header.file_size();
            let file_offset = program_header.offset();

            // A zero-sized LOAD contributes no image bytes or permissions;
            // skip it before the inclusive page-range calculation so
            // `mem_size - 1` cannot accidentally classify the preceding page.
            if mem_size == 0 {
                continue;
            }

            // R188-U55-2 FIX: ELF metadata is attacker-controlled at the boot
            // boundary.  A LOAD segment may not copy more initialized bytes
            // than its destination reservation, and every arithmetic step must
            // remain inside the exact page-aligned image allocation.
            if file_size > mem_size {
                panic!("ELF LOAD file_size exceeds mem_size");
            }
            let mem_size_usize =
                usize::try_from(mem_size).expect("ELF LOAD mem_size does not fit in usize");
            let file_size_usize =
                usize::try_from(file_size).expect("ELF LOAD file_size does not fit in usize");

            // R24-10 fix: Validate that file_offset + file_size doesn't exceed kernel_data bounds
            // A malformed ELF could have segments pointing beyond the file, causing OOB read
            let file_end = file_offset
                .checked_add(file_size)
                .expect("ELF segment offset+size overflow");
            if file_end as usize > kernel_data.len() {
                panic!(
                    "ELF segment out of bounds: offset=0x{:x}, file_size=0x{:x}, file_len=0x{:x}",
                    file_offset,
                    file_size,
                    kernel_data.len()
                );
            }

            // 计算物理地址：虚拟地址 - 虚拟基址 + 物理基址
            // 虚拟基址是 min_addr (0xffffffff80000000)，物理基址是 actual_phys_base (0x100000)
            let segment_offset = virt_addr
                .checked_sub(min_addr)
                .expect("ELF LOAD virtual address below image base");
            let phys_addr = actual_phys_base
                .checked_add(segment_offset)
                .expect("ELF LOAD physical address overflow");
            let image_end = actual_phys_base
                .checked_add(u64::try_from(alloc_bytes).expect("allocation size overflow"))
                .expect("ELF image allocation end overflow");
            let segment_mem_end = phys_addr
                .checked_add(mem_size)
                .expect("ELF LOAD destination overflow");
            let segment_file_end = phys_addr
                .checked_add(file_size)
                .expect("ELF LOAD file destination overflow");
            if phys_addr < actual_phys_base
                || segment_mem_end > image_end
                || segment_file_end > image_end
            {
                panic!("ELF LOAD destination exceeds allocated image");
            }

            // Classify final permissions at the architectural 4 KiB page
            // granularity.  The kernel's legitimate text/data boundary can
            // share a 2 MiB bucket, especially with a 64 KiB KASLR slide; a
            // huge-page-only classifier would reject that image or force the
            // whole bucket W+X.  Mixed buckets are split into 4 KiB leaves
            // when the new page tables are built below.
            let first_page = usize::try_from(
                phys_addr
                    .checked_sub(actual_phys_base)
                    .expect("ELF LOAD starts below kernel allocation")
                    / KERNEL_PAGE_SIZE,
            )
            .expect("ELF LOAD first page index overflow");
            let last_page = usize::try_from(
                segment_mem_end
                    .saturating_sub(1)
                    .checked_sub(actual_phys_base)
                    .expect("ELF LOAD ends below kernel allocation")
                    / KERNEL_PAGE_SIZE,
            )
            .expect("ELF LOAD last page index overflow");
            if last_page >= kernel_permissions.pages.len() {
                panic!("ELF LOAD permission range exceeds allocated image");
            }
            let segment_executable = program_header.flags().is_execute();
            let segment_writable = program_header.flags().is_write();
            let segment_permissions = KERNEL_PAGE_CLAIMED
                | if segment_executable {
                    KERNEL_PAGE_EXECUTABLE
                } else {
                    0
                }
                | if segment_writable {
                    KERNEL_PAGE_WRITABLE
                } else {
                    0
                };
            for page_index in first_page..=last_page {
                let current = kernel_permissions.pages[page_index];
                if (segment_executable && current & KERNEL_PAGE_WRITABLE != 0)
                    || (segment_writable && current & KERNEL_PAGE_EXECUTABLE != 0)
                {
                    panic!("ELF LOAD segments require a writable/executable 4 KiB page");
                }
                kernel_permissions.pages[page_index] = current | segment_permissions;
            }

            // 清零整个段内存区域（包括.bss）
            unsafe {
                let dest = phys_addr as *mut u8;
                core::ptr::write_bytes(dest, 0, mem_size_usize);
            }

            // 复制段数据（file_size可能小于mem_size，剩余部分已清零）
            if file_size > 0 {
                unsafe {
                    let dest = phys_addr as *mut u8;
                    let src = kernel_data.as_ptr().add(file_offset as usize);
                    core::ptr::copy_nonoverlapping(src, dest, file_size_usize);
                }
            }

            // R119-1 FIX: Physical addresses reveal KASLR slide; gate behind debug_assertions.
            // Virtual addresses are link-time public and safe to log.
            #[cfg(debug_assertions)]
            info!(
                "Loaded segment: virt=0x{:x}, phys=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                virt_addr, phys_addr, file_size, mem_size
            );
            #[cfg(not(debug_assertions))]
            info!(
                "Loaded segment: virt=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                virt_addr, file_size, mem_size
            );
        }

        // R119-1 FIX: Verification dump reveals physical load address; gate behind
        // debug_assertions. In release, just do a volatile read to confirm accessibility.
        #[cfg(debug_assertions)]
        unsafe {
            let kernel_start = actual_phys_base as *const u8;
            let first_bytes = core::slice::from_raw_parts(kernel_start, 16);
            info!(
                "First 16 bytes at phys 0x{:x}: {:x?}",
                actual_phys_base, first_bytes
            );
        }
        #[cfg(not(debug_assertions))]
        {
            let kernel_start = actual_phys_base as *const u8;
            let _ = unsafe { core::ptr::read_volatile(kernel_start) };
            info!("Kernel image load verified");
        }

        for permissions in &kernel_permissions.pages {
            if permissions & KERNEL_PAGE_EXECUTABLE != 0 && permissions & KERNEL_PAGE_WRITABLE != 0
            {
                panic!("ELF LOAD segments require a writable/executable 4 KiB page");
            }
        }

        // Text KASLR: Apply PIE relocations so absolute addresses in the
        // kernel image point to the correct (slid) virtual addresses.
        // This is a no-op when kaslr_slide == 0 and no .rela.dyn section exists.
        apply_rela_dyn_relocations(
            &elf,
            min_addr,
            kernel_size as u64,
            actual_phys_base,
            kaslr_slide,
        );

        // R39-7 FIX: Apply KASLR slide to entry point
        let adjusted_entry = entry_point + kaslr_slide;
        // R119-1 FIX: Entry point and slide values reveal the kernel memory layout;
        // gate behind debug_assertions to match kernel-side redaction pattern.
        #[cfg(debug_assertions)]
        info!(
            "Using ELF entry point: 0x{:x} (slide applied: 0x{:x}, final: 0x{:x})",
            entry_point, kaslr_slide, adjusted_entry
        );
        #[cfg(not(debug_assertions))]
        info!(
            "ELF entry point resolved ({})",
            if kaslr_randomized {
                "randomized placement"
            } else if kaslr_slide != 0 {
                "deterministic availability relocation"
            } else {
                "fixed placement"
            }
        );
        (
            adjusted_entry,
            kaslr_slide,
            kernel_size,
            kaslr_randomized,
            actual_phys_base,
            kernel_permissions,
        )
    };

    // 测试 VGA 缓冲区是否可访问 - 在 info! 之前
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + i as isize * 2 + 1) = 0x0E;
        }
    }

    info!("Automatically jumping to kernel...");

    // Find ACPI RSDP before exiting boot services (EFI config table won't be accessible after)
    let rsdp_address = find_rsdp_address(&system_table);

    // P1-1: Read UEFI load options (boot command line) before exiting boot services.
    // The LoadedImage protocol is inaccessible after exit_boot_services().
    let (cmdline_len, cmdline) = read_uefi_cmdline(handle, &system_table);
    if cmdline_len > 0 {
        info!(
            "Boot cmdline ({} bytes): {:?}",
            cmdline_len,
            core::str::from_utf8(&cmdline[..cmdline_len]).unwrap_or("<invalid>")
        );
    }

    // 分配 BootInfo 结构的内存（在低于 4GiB 的位置，便于恒等映射访问）
    let boot_info_ptr = {
        let boot_services = system_table.boot_services();
        // F9: inside the kernel's 1 GiB direct map as well.
        let boot_info_page = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate boot info page");
        // R167-C: zero the page so every byte not explicitly written (struct tail,
        // any future appended field) is deterministic. This makes the kernel's
        // `BootInfo.version` guard meaningful — a kernel paired with an older
        // bootloader that never wrote `version` would read 0, not stale garbage.
        unsafe {
            core::ptr::write_bytes(boot_info_page as *mut u8, 0, 4096);
        }
        boot_info_page as *mut BootInfo
    };

    // N3.1a (#67): size the linear direct map (`PML4[273]`) from UEFI RAM/firmware descriptors.
    let (direct_map_limit, direct_map_ranges) =
        discover_direct_map_plan(system_table.boot_services());
    info!(
        "N3.1a: Linear direct map PML4[{}] covers 0..{} GiB ({} RAM/firmware spans)",
        DIRECT_MAP_PML4_INDEX,
        direct_map_limit / ONE_GIB,
        direct_map_ranges.len()
    );

    // 构建四级页表结构，将物理内核地址映射到高半区虚拟地址
    let (pml4_frame, entry_point_to_jump, transition_stub_phys) = unsafe {
        // 最早的 VGA 写入 - 在任何其他操作之前
        let vga = 0xb8000 as *mut u8;
        let msg = b"SETUP";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 22 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 22 * 2 + i as isize * 2 + 1) = 0x09;
        }
        use x86_64::{
            structures::paging::{PageTable, PageTableFlags as Flags},
            PhysAddr,
        };

        let boot_services = system_table.boot_services();

        // U55-6: Allocate a dedicated 4 KiB LOADER_CODE page for the CR3-switch
        // transition stub so PML4[0] never needs any RWX region or bootloader
        // .text execution after `mov cr3`.
        let transition_stub_phys = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_CODE,
                1,
            )
            .expect("Failed to allocate CR3 transition stub page");
        if !transition_stub_phys.is_multiple_of(KERNEL_PAGE_SIZE)
            || transition_stub_phys >= KERNEL_PHYS_WINDOW_END
        {
            panic!("U55-6: CR3 transition stub allocation is misaligned or outside direct map");
        }
        core::ptr::write_bytes(
            transition_stub_phys as *mut u8,
            0,
            KERNEL_PAGE_SIZE as usize,
        );
        core::ptr::copy_nonoverlapping(
            CR3_TRANSITION_STUB.as_ptr(),
            transition_stub_phys as *mut u8,
            CR3_TRANSITION_STUB.len(),
        );

        // 分配并清零 PML4
        let pml4_frame = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate PML4");
        let pml4_ptr = pml4_frame as *mut PageTable;
        core::ptr::write_bytes(pml4_ptr as *mut u8, 0, 4096);

        // 分配并清零 PDPT（高半区）
        let pdpt_high_frame = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate PDPT");
        let pdpt_high_ptr = pdpt_high_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_high_ptr as *mut u8, 0, 4096);

        // 分配并清零 PD
        let pd_frame = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate PD");
        let pd_ptr = pd_frame as *mut PageTable;
        core::ptr::write_bytes(pd_ptr as *mut u8, 0, 4096);

        // Map the high-half direct window with huge pages except for the small
        // set of 2 MiB buckets that overlap the kernel image, the first 2 MiB
        // (SMP trampoline / low MMIO), or the CR3 transition stub.  Those
        // buckets use 4 KiB leaves so text/rodata/data boundaries and live
        // aliases enforce exact W^X from the first instruction after CR3 load.
        // 虚拟地址 0xffffffff80000000 映射到物理地址 0
        // 由于使用2MB大页，必须从2MB边界开始，所以实际映射：
        // 虚拟 0xffffffff80000000 → 物理 0x0
        //
        // Text KASLR: With a PIE kernel, the physical load base is
        // KERNEL_PHYS_BASE + kaslr_slide. The 1 GiB high-half mapping
        // (virtual 0xffffffff80000000 → physical 0x0) covers the entire
        // first GB, so the slid kernel is still accessible. NX marking
        // tracks the actual kernel physical extent.
        //
        // The high-half mapping MUST remain at virtual→physical offset 0xffffffff80000000→0
        // because PHYSICAL_MEMORY_OFFSET is used throughout the kernel for phys_to_virt().
        //
        // W^X safety:
        // - LOAD permissions were classified per 4 KiB page before this
        //   transaction.
        // - Executable pages become RX, writable pages become RW+NX, and
        //   read-only/gap pages become R+NX.
        // - The CR3 transition stub's high-half alias is R+NX so it has zero
        //   writable alias while executing in PML4[0].
        // - No final high-half leaf is both writable and executable.
        // R188-U55-8 FIX: use the exact address returned by UEFI allocation,
        // not a recomputation from the requested base and slide.  The latter
        // can diverge on firmware that applies an address adjustment or on a
        // future allocator implementation with a different placement policy.
        let kernel_phys_start = actual_phys_base;
        let kernel_phys_end = kernel_phys_start
            .checked_add(
                u64::try_from(kernel_permissions.pages.len())
                    .expect("kernel page count exceeds u64")
                    .checked_mul(KERNEL_PAGE_SIZE)
                    .expect("kernel page extent overflow"),
            )
            .expect("kernel physical extent overflow");
        if transition_stub_phys >= kernel_phys_start && transition_stub_phys < kernel_phys_end {
            panic!("U55-6: CR3 transition stub overlaps loaded kernel image");
        }
        let start_pd_idx = (kernel_phys_start / 0x200000) as usize;
        // Last PD entry that actually contains kernel bytes (inclusive).
        // saturating_sub(1) handles the edge case where kernel_phys_end is
        // exactly on a 2 MiB boundary — without it the ceil formula would
        // mark one extra 2 MiB page as executable.
        let end_pd_idx = (kernel_phys_end.saturating_sub(1) / 0x200000) as usize;
        let stub_pd_idx = (transition_stub_phys / 0x200000) as usize;

        for i in 0..512usize {
            let bucket_start = (i as u64) * 0x200000;
            // Split PD[0] (0..2 MiB for 4 KiB SMP trampoline alias control),
            // all kernel image buckets, and the CR3 transition stub bucket.
            let split_bucket = i == 0 || (i >= start_pd_idx && i <= end_pd_idx) || i == stub_pd_idx;
            if split_bucket {
                let pt_frame = boot_services
                    .allocate_pages(
                        AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                        MemoryType::LOADER_DATA,
                        1,
                    )
                    .expect("Failed to allocate kernel permission PT");
                let pt_ptr = pt_frame as *mut PageTable;
                core::ptr::write_bytes(pt_ptr as *mut u8, 0, 4096);

                for page_index in 0..512usize {
                    let phys_page = bucket_start
                        .checked_add((page_index as u64) * KERNEL_PAGE_SIZE)
                        .expect("kernel PT physical address overflow");
                    let flags = if phys_page == transition_stub_phys {
                        // U55-6: High-half alias of the R-X CR3 transition stub
                        // must be non-writable and non-executable (R--).
                        Flags::PRESENT | Flags::NO_EXECUTE
                    } else {
                        match kernel_permissions.get(phys_page) {
                            Some(permissions) if permissions & KERNEL_PAGE_EXECUTABLE != 0 => {
                                Flags::PRESENT
                            }
                            Some(permissions) if permissions & KERNEL_PAGE_WRITABLE != 0 => {
                                Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE
                            }
                            Some(permissions) if permissions & KERNEL_PAGE_CLAIMED != 0 => {
                                Flags::PRESENT | Flags::NO_EXECUTE
                            }
                            Some(_) => Flags::PRESENT | Flags::NO_EXECUTE,
                            None => Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
                        }
                    };
                    (&mut *pt_ptr)[page_index].set_addr(PhysAddr::new(phys_page), flags);
                }

                (&mut *pd_ptr)[i]
                    .set_addr(PhysAddr::new(pt_frame), Flags::PRESENT | Flags::WRITABLE);
            } else {
                (&mut *pd_ptr)[i].set_addr(
                    PhysAddr::new(bucket_start),
                    Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE | Flags::NO_EXECUTE,
                );
            }
        }

        // PDPT的第510项指向PD（对应虚拟地址的第30-38位）
        // Maps virtual 0xffffffff80000000-0xffffffffbfffffff (1GB) to physical 0x0-0x3fffffff
        (&mut *pdpt_high_ptr)[510]
            .set_addr(PhysAddr::new(pd_frame), Flags::PRESENT | Flags::WRITABLE);

        // PML4的第511项指向高半区PDPT（内核镜像 + 0..1 GiB 引导别名）
        (&mut *pml4_ptr)[511].set_addr(
            PhysAddr::new(pdpt_high_frame),
            Flags::PRESENT | Flags::WRITABLE,
        );

        // N3.1a (#67): Build dedicated linear direct map at PML4[273]
        // (`0xffff_8880_0000_0000`), mapping 0..direct_map_limit with RW+NX 2 MiB
        // huge pages for RAM/firmware regions while splitting PD[0], kernel-image
        // buckets, and the CR3 transition stub to 4 KiB leaves (RO+NX on executable
        // frames) so U55-6 zero-cross-alias W^X holds across PML4[0], [273], [511].
        let pdpt_dm_frame = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate direct-map PDPT");
        let pdpt_dm_ptr = pdpt_dm_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_dm_ptr as *mut u8, 0, 4096);

        let num_gb = (direct_map_limit / ONE_GIB) as usize;
        for gb_idx in 0..num_gb {
            let gb_start = (gb_idx as u64) * ONE_GIB;
            let gb_end = gb_start + ONE_GIB;
            if gb_idx > 0 && !range_overlaps_any(&direct_map_ranges, gb_start, gb_end) {
                continue;
            }
            let pd_dm_frame = boot_services
                .allocate_pages(
                    AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                    MemoryType::LOADER_DATA,
                    1,
                )
                .expect("Failed to allocate direct-map PD");
            let pd_dm_ptr = pd_dm_frame as *mut PageTable;
            core::ptr::write_bytes(pd_dm_ptr as *mut u8, 0, 4096);

            for i in 0..512usize {
                let bucket_start = gb_start + (i as u64) * TWO_MIB;
                let bucket_end = bucket_start + TWO_MIB;
                if gb_idx > 0 && !range_overlaps_any(&direct_map_ranges, bucket_start, bucket_end) {
                    continue;
                }
                let split_bucket = gb_idx == 0
                    && (i == 0 || (i >= start_pd_idx && i <= end_pd_idx) || i == stub_pd_idx);
                if split_bucket {
                    let pt_dm_frame = boot_services
                        .allocate_pages(
                            AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                            MemoryType::LOADER_DATA,
                            1,
                        )
                        .expect("Failed to allocate direct-map W^X PT");
                    let pt_dm_ptr = pt_dm_frame as *mut PageTable;
                    core::ptr::write_bytes(pt_dm_ptr as *mut u8, 0, 4096);

                    for page_index in 0..512usize {
                        let phys_page = bucket_start + (page_index as u64) * KERNEL_PAGE_SIZE;
                        let flags = if phys_page == transition_stub_phys {
                            Flags::PRESENT | Flags::NO_EXECUTE
                        } else if let Some(permissions) = kernel_permissions.get(phys_page) {
                            if permissions & KERNEL_PAGE_WRITABLE != 0 {
                                Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE
                            } else {
                                // Kernel .text / .rodata / gaps: RO+NX (zero writable alias).
                                Flags::PRESENT | Flags::NO_EXECUTE
                            }
                        } else {
                            Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE
                        };
                        (&mut *pt_dm_ptr)[page_index].set_addr(PhysAddr::new(phys_page), flags);
                    }

                    (&mut *pd_dm_ptr)[i].set_addr(
                        PhysAddr::new(pt_dm_frame),
                        Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
                    );
                } else {
                    (&mut *pd_dm_ptr)[i].set_addr(
                        PhysAddr::new(bucket_start),
                        Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE | Flags::NO_EXECUTE,
                    );
                }
            }

            (&mut *pdpt_dm_ptr)[gb_idx].set_addr(
                PhysAddr::new(pd_dm_frame),
                Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
            );
        }

        (&mut *pml4_ptr)[DIRECT_MAP_PML4_INDEX].set_addr(
            PhysAddr::new(pdpt_dm_frame),
            Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
        );

        // 建立恒等映射以防止切换页表时崩溃
        let pdpt_low_frame = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate low PDPT");
        let pdpt_low_ptr = pdpt_low_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_low_ptr as *mut u8, 0, 4096);

        // U55-6: Hardened 0..4 GiB early-boot identity map with ZERO RWX leaves
        // and ZERO writable aliases of executable pages:
        // - Every 2 MiB huge page is mapped RW+NX (never executable).
        // - In PDPT[0] (0..1 GiB), PD[0], all kernel-image buckets, and the
        //   CR3 transition stub bucket are split into 4 KiB leaves:
        //   * `transition_stub_phys` is the ONLY executable page in PML4[0],
        //     mapped strictly R-X (and R-- in PML4[511]).
        //   * Kernel `.text`, `.rodata`, and gaps are mapped R-- (RO+NX) so
        //     kernel `.text` has ZERO writable aliases in PML4[0].
        //   * Kernel `.data`/`.bss` and non-kernel pages (bootloader stack,
        //     BootInfo, MMIO, RAM) are mapped RW+NX until kernel
        //     `cleanup_identity_map()` hardens PML4[0] to RO+NX.
        for pdpt_idx in 0..4usize {
            let pd_low_frame = boot_services
                .allocate_pages(
                    AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                    MemoryType::LOADER_DATA,
                    1,
                )
                .expect("Failed to allocate low PD");
            let pd_low_ptr = pd_low_frame as *mut PageTable;
            core::ptr::write_bytes(pd_low_ptr as *mut u8, 0, 4096);

            // 每个PD映射512个2MB页（1GB）
            for i in 0..512usize {
                let bucket_start = ((pdpt_idx * 512 + i) as u64) * 0x200000;
                let split_bucket = pdpt_idx == 0
                    && (i == 0 || (i >= start_pd_idx && i <= end_pd_idx) || i == stub_pd_idx);
                if split_bucket {
                    let pt_frame = boot_services
                        .allocate_pages(
                            AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                            MemoryType::LOADER_DATA,
                            1,
                        )
                        .expect("Failed to allocate low identity PT");
                    let pt_ptr = pt_frame as *mut PageTable;
                    core::ptr::write_bytes(pt_ptr as *mut u8, 0, 4096);

                    for page_index in 0..512usize {
                        let phys_page = bucket_start
                            .checked_add((page_index as u64) * KERNEL_PAGE_SIZE)
                            .expect("low identity PT physical address overflow");
                        let flags = if phys_page == transition_stub_phys {
                            // Strictly R-X for the 8-byte CR3 switch & jump stub.
                            Flags::PRESENT
                        } else if let Some(permissions) = kernel_permissions.get(phys_page) {
                            if permissions & KERNEL_PAGE_WRITABLE != 0 {
                                Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE
                            } else {
                                // Kernel .text / .rodata / gaps: RO+NX (no writable alias).
                                Flags::PRESENT | Flags::NO_EXECUTE
                            }
                        } else {
                            // Bootloader stack, BootInfo, MMIO, RAM: RW+NX.
                            Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE
                        };
                        (&mut *pt_ptr)[page_index].set_addr(PhysAddr::new(phys_page), flags);
                    }

                    (&mut *pd_low_ptr)[i]
                        .set_addr(PhysAddr::new(pt_frame), Flags::PRESENT | Flags::WRITABLE);
                } else {
                    (&mut *pd_low_ptr)[i].set_addr(
                        PhysAddr::new(bucket_start),
                        Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE | Flags::NO_EXECUTE,
                    );
                }
            }

            (&mut *pdpt_low_ptr)[pdpt_idx].set_addr(
                PhysAddr::new(pd_low_frame),
                Flags::PRESENT | Flags::WRITABLE,
            );
        }

        (&mut *pml4_ptr)[0].set_addr(
            PhysAddr::new(pdpt_low_frame),
            Flags::PRESENT | Flags::WRITABLE,
        );

        // 设置递归页表槽 (PML4[510] → PML4 自身)
        // 这允许通过特殊虚拟地址访问任何页表帧，无论其物理地址在哪里
        // 递归映射虚拟地址计算：
        //   PML4:  0xFFFFFF7FBFDFE000
        //   PDPT:  0xFFFFFF7FBFC00000 + pml4_idx * 0x1000
        //   PD:    0xFFFFFF7F80000000 + pml4_idx * 0x200000 + pdpt_idx * 0x1000
        //   PT:    0xFFFFFF0000000000 + pml4_idx * 0x40000000 + pdpt_idx * 0x200000 + pd_idx * 0x1000
        //
        // L-6 fix: Add NO_EXECUTE flag to prevent code execution from page table pages.
        // This is defense-in-depth: even if an attacker can write to page tables via
        // the recursive mapping, they cannot execute code from them.
        (&mut *pml4_ptr)[510].set_addr(
            PhysAddr::new(pml4_frame),
            Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
        );

        // U55-6: Verify W^X and zero cross-alias W+X before ExitBootServices.
        verify_boot_page_tables(pml4_frame, transition_stub_phys);
        info!("U55-6: Boot page tables verified (0 RWX leaves, 0 cross-alias W+X, 1 R-X handoff page)");

        // F9: the new tables are loaded only after ExitBootServices (below).
        // Boot services run on the active CR3, and OVMF's memory protection
        // edits it (it splits huge pages and allocates the new tables top-down,
        // above the kernel's 1 GiB direct map once the guest has 2 GiB).
        (pml4_frame, entry_point, transition_stub_phys)
    };

    // 获取 GOP 帧缓冲区信息（必须在 exit_boot_services 之前）
    let framebuffer_info = {
        let boot_services = system_table.boot_services();
        let gop_handle = boot_services
            .get_handle_for_protocol::<GraphicsOutput>()
            .expect("Failed to get GOP handle");
        let mut gop = boot_services
            .open_protocol_exclusive::<GraphicsOutput>(gop_handle)
            .expect("Failed to open GOP");

        let mode_info = gop.current_mode_info();
        let (width, height) = mode_info.resolution();
        let stride = mode_info.stride() as u32;

        let pixel_format = match mode_info.pixel_format() {
            GopPixelFormat::Rgb => PixelFormat::Rgb,
            GopPixelFormat::Bgr => PixelFormat::Bgr,
            _ => PixelFormat::Unknown,
        };

        let mut fb = gop.frame_buffer();
        let fb_base = fb.as_mut_ptr() as u64;
        let fb_size = fb.size();

        info!(
            "GOP framebuffer: {}x{}, stride={}, format={:?}",
            width, height, stride, pixel_format
        );
        info!("Framebuffer at 0x{:x}, size {} bytes", fb_base, fb_size);

        FramebufferInfo {
            base: fb_base,
            size: fb_size,
            width: width as u32,
            height: height as u32,
            stride,
            pixel_format,
        }
    };

    // 预先分配一块低地址缓冲区，用于在退出后保存内存映射副本，确保恒等映射可访问
    // Reserve a bounded, substantially larger map snapshot than the former
    // 64-page assumption.  The exact firmware-reported size is checked below.
    let (memory_map_copy_ptr, memory_map_copy_len) = {
        let pages = MEMORY_MAP_COPY_PAGES;
        // F9: the kernel reads this copy through its 1 GiB direct map.
        let addr = system_table
            .boot_services()
            .allocate_pages(
                AllocateType::MaxAddress(DIRECT_MAP_MAX_ADDRESS),
                MemoryType::LOADER_DATA,
                pages,
            )
            .expect("Failed to allocate low memory map copy buffer");
        (addr as *mut u8, pages * 0x1000)
    };

    // 退出 UEFI 引导服务，获取最终的内存映射
    // 这必须在页表设置之后、跳转之前完成
    let memory_map = unsafe {
        let (_runtime_system_table, memory_map) =
            system_table.exit_boot_services(MemoryType::LOADER_DATA);
        memory_map
    };

    // 将内存映射信息填充到 BootInfo 结构中
    // 需要将内存映射复制到低于4GiB的缓冲区，因为原始映射可能在高地址
    unsafe {
        let (memory_map_bytes, memory_map_meta) = memory_map.as_raw();

        // 确保预分配的缓冲区足够大
        if memory_map_meta.map_size > memory_map_copy_len {
            // R188-U55-7 FIX: fail closed before the copy rather than relying
            // on a brittle debug assertion.  Firmware that needs a larger map
            // must increase the explicit bounded budget above.
            panic!("UEFI memory map exceeds the bounded handoff buffer");
        }

        // 复制内存映射到低地址缓冲区
        core::ptr::copy_nonoverlapping(
            memory_map_bytes.as_ptr(),
            memory_map_copy_ptr,
            memory_map_meta.map_size,
        );

        *boot_info_ptr = BootInfo {
            memory_map: MemoryMapInfo {
                buffer: memory_map_copy_ptr as u64,
                size: memory_map_meta.map_size,
                descriptor_size: memory_map_meta.desc_size,
                descriptor_version: memory_map_meta.desc_version,
            },
            framebuffer: framebuffer_info,
            kaslr_slide,  // R39-7 FIX: Pass KASLR slide to kernel
            rsdp_address, // ACPI RSDP for SMP CPU enumeration
            cmdline_len,  // P1-1: Boot command line
            cmdline,
            // R167-C/RF180-32: exact kernel image range for reservation-aware
            // MM. The slide records relocation; flags record whether it was random.
            kernel_phys_base: actual_phys_base,
            kernel_phys_size: kernel_size as u64,
            version: BOOT_INFO_VERSION,
            kaslr_flags: if kaslr_randomized {
                BOOT_INFO_KASLR_RANDOMIZED
            } else {
                0
            },
            direct_map_base: DIRECT_MAP_OFFSET,
            direct_map_limit,
        };
        // 阻止 memory_map 被释放，因为内核需要访问它
        core::mem::forget(memory_map);
    }

    // U55-6: Switch to the W^X-hardened PML4 and jump directly into high-half
    // kernel `_start` via the single 4 KiB R-X transition stub page.
    // F9: only now, with boot services gone, so firmware never runs on or edits
    // the kernel's tables. Bootloader `.text` is NX under the new PML4, so
    // execution never continues in the bootloader image after `mov cr3, rax`.
    unsafe {
        use x86_64::registers::{
            control::{Cr0, Cr0Flags, Cr3},
            model_specific::{Efer, EferFlags},
        };

        // 在切换前写 VGA 测试
        let vga = 0xb8000 as *mut u8;
        let msg1 = b"B4CR3";
        for (i, &byte) in msg1.iter().enumerate() {
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + i as isize * 2), byte);
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + i as isize * 2 + 1), 0x0A);
        }

        // Disable interrupts and ensure both EFER.NXE and CR0.WP are enabled
        // BEFORE loading the W^X page tables so NX bits are honored (never
        // reserved-bit #PF) and Ring-0 writes honor read-only PTEs from
        // instruction 0 of the kernel.
        core::arch::asm!("cli", options(nomem, nostack));
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
        Cr0::update(|flags| flags.insert(Cr0Flags::WRITE_PROTECT));

        let (_, cr3_flags) = Cr3::read();
        let new_cr3 = (pml4_frame & 0x000F_FFFF_FFFF_F000) | (cr3_flags.bits() & 0x18);

        // Jump to the 8-byte stub (`mov cr3, rax; jmp r8; ud2`) at
        // `transition_stub_phys`, which is executable in both UEFI's CR3 and
        // our new PML4[0] (strictly R-X, with R-- in PML4[511]).
        core::arch::asm!(
            "jmp {stub}",
            stub = in(reg) transition_stub_phys,
            in("rax") new_cr3,
            in("rdi") boot_info_ptr as u64,
            in("r8") entry_point_to_jump,
            options(noreturn),
        );
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("BOOTLOADER PANIC: {}", info);

    // 在屏幕上显示 panic
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT PANIC!";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize * 2) = byte;
            *vga.offset(i as isize * 2 + 1) = 0x4F;
        }
    }

    loop {}
}
