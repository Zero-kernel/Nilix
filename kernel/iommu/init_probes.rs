//! Terminal, default-off Q35 probes. Each initialization case needs a fresh VM.

use super::*;
use x86_64::structures::paging::{Page, PageTableFlags};

static REJECTED_BASE: AtomicU64 = AtomicU64::new(0);
static REJECTIONS: AtomicU32 = AtomicU32::new(0);

fn scenario() -> &'static str {
    option_env!("ZERO_OS_IOMMU_PROBE").unwrap_or("constructor")
}

// Called only after the real GCMD write with cmd_lock held. Numeric observations
// only: no allocation and no lock acquisition. Match the requested transaction,
// not reconstructed persistent GCMD bits (TE commands can also carry IRE).
pub(super) fn reject_ack(base: u64, update: &GcmdUpdate, ack: &GcmdAck) -> bool {
    let requested = match scenario() {
        "sirtp" => Some((GCMD_SIRTP, GSTS_IRTPS)),
        "ir" => Some((GCMD_IRE, GSTS_IRES)),
        "te" => Some((GCMD_TE, GSTS_TES)),
        _ => None,
    };
    if let (Some((command, status)), GcmdUpdate::Set(bits), GcmdAck::Set(bit)) =
        (requested, update, ack)
    {
        if *bits == command && *bit == status {
            REJECTED_BASE.store(base, Ordering::Release);
            REJECTIONS.fetch_add(1, Ordering::AcqRel);
            return true;
        }
    }
    false
}

/// Exercise the actual register-window owner without reading scratch UC RAM.
///
/// # Safety
/// BSP only before KPTI/AP startup; MM is ready and no VT-d owner exists.
pub unsafe fn run_register_mapping_probes() {
    assert!(VTD_MMIO_SLOTS.lock().iter().all(Option::is_none));
    let mut allocator = mm::FrameAllocator::new();
    let scratch = allocator
        .allocate_contiguous_frames(2)
        .expect("VT-d owner scratch");
    let phys = scratch.start_address();
    // Establish the permanent driver reservation's reusable upper tables. They
    // remain part of the actual VT-d reservation, rather than a temporary root.
    drop(VtdRegisterMapping::new(phys.as_u64()).unwrap());
    let baseline = buddy_allocator::get_allocator_stats().unwrap().free_pages;
    let mut mapping = VtdRegisterMapping::new(phys.as_u64()).unwrap();
    let prefix = VirtAddr::new(mapping.virt_base);
    let suffix = prefix + 4096u64;
    mm::map_mmio(suffix, phys + 4096u64, 4096, &mut allocator).unwrap();
    assert!(matches!(
        mapping.extend(8192),
        Err(VtdError::RegisterMappingFailed)
    ));
    assert_eq!(mapping.mapped_bytes, 4096);
    drop(mapping);
    mm::with_current_manager(VirtAddr::new(0), |manager| {
        assert!(manager.translate_with_flags(prefix).is_none());
        assert_eq!(
            manager.translate_with_flags(suffix).unwrap().0,
            phys + 4096u64
        );
    });
    assert!(VTD_MMIO_SLOTS.lock().iter().all(Option::is_none));
    mm::unmap_mmio(suffix, 4096, &mut allocator).unwrap();
    assert_eq!(
        buddy_allocator::get_allocator_stats().unwrap().free_pages,
        baseline
    );
    allocator.deallocate_contiguous_frames(scratch, 2);
    klog::klog_always!("KSA-001-REGISTER-OWNER PASS prefix_removed=1 foreign_suffix_preserved=1 slots_restored=1 scratch_reclaimed=1");
}

fn assert_retained(unit: &VtdUnit, translation_case: bool) {
    assert_eq!(unit.reg_base, REJECTED_BASE.load(Ordering::Acquire));
    assert!(unit._register_mapping.mapped_bytes >= register_window::PAGE_BYTES);
    let qi_phys = unit
        .qi_queue
        .lock()
        .as_ref()
        .expect("QI owner lost after GCMD")
        .phys;
    let ir_phys = unit
        .ir_table
        .lock()
        .as_ref()
        .expect("IR owner lost after GCMD")
        .physical_address();
    let iqa = unsafe { VtdUnit::read_reg64(unit.reg_base, VTD_REG_IQA) };
    let irta = unsafe { VtdUnit::read_reg64(unit.reg_base, VTD_REG_IRTA) };
    let gsts = unsafe { VtdUnit::read_reg32(unit.reg_base, VTD_REG_GSTS) };
    assert_eq!(iqa & !0xfff, qi_phys);
    assert_eq!(irta & !0xfff, ir_phys);
    assert_ne!(gsts & GSTS_QIES, 0);
    assert_ne!(gsts & GSTS_IRTPS, 0, "Q35 must load IRTA before injection");
    if scenario() == "sirtp" {
        assert_eq!(
            gsts & GSTS_IRES,
            0,
            "IRE must not follow rejected SIRTP ack"
        );
    } else {
        assert_ne!(
            gsts & GSTS_IRES,
            0,
            "Q35 must actually enable IR before injection"
        );
    }
    let root = unit.root_table_phys.load(Ordering::Acquire);
    if translation_case {
        assert_ne!(root, 0);
        assert!(unit.root_pointer_loaded.load(Ordering::Acquire));
        assert_eq!(
            unsafe { VtdUnit::read_reg64(unit.reg_base, VTD_REG_RTADDR) } & !0xfff,
            root
        );
        assert_ne!(
            gsts & GSTS_TES,
            0,
            "Q35 must actually enable TE before injection"
        );
        assert!(!unit.translation_enabled.load(Ordering::Acquire));
        assert!(unit.cache_poisoned.load(Ordering::Acquire));
    } else {
        assert!(unit.ir_poisoned.load(Ordering::Acquire));
        assert_eq!(root, 0);
        assert_eq!(gsts & GSTS_TES, 0);
    }
}

/// Terminal guest driver at the normal IOMMU initialization site.
pub fn run_init_failure_probe(rsdp_phys: u64) -> ! {
    let scenario = scenario();
    assert!(matches!(scenario, "constructor" | "sirtp" | "ir" | "te"));
    assert!(!crate::init_done());
    assert!(!crate::IOMMU_INIT_FAILED.load(Ordering::Acquire));
    let dmar = crate::dmar::parse_dmar_table(rsdp_phys).expect("probe requires Q35 DMAR");
    assert_eq!(dmar.drhd_count(), 1, "probe supports one Q35 DRHD");
    let phys = dmar.drhd_iter().next().unwrap().register_base();
    drop(dmar);
    let blocker = VirtAddr::new(VTD_MMIO_VIRT_BASE);
    if scenario == "constructor" {
        let mut allocator = mm::FrameAllocator::new();
        unsafe {
            mm::map_mmio(blocker, PhysAddr::new(phys), 4096, &mut allocator).unwrap();
            mm::with_current_manager(VirtAddr::new(0), |manager| {
                let (_, flags) = manager.translate_with_flags(blocker).unwrap();
                manager
                    .update_flags(
                        Page::containing_address(blocker),
                        flags & !PageTableFlags::WRITABLE,
                    )
                    .unwrap();
            });
        }
    }
    klog::klog_always!("KSA-001-INIT BEGIN case={}", scenario);
    assert_eq!(crate::init(rsdp_phys), Err(IommuError::HardwareInitFailed));
    assert!(!crate::is_enabled());
    assert_eq!(crate::unit_count(), 0);
    assert!(!crate::IOMMU_ENABLED.load(Ordering::Acquire));
    assert!(crate::IOMMU_INIT_FAILED.load(Ordering::Acquire));
    assert_eq!(crate::FAULT_UNIT_COUNT.load(Ordering::Acquire), 0);
    assert!(crate::FAULT_UNIT_PTRS
        .iter()
        .all(|ptr| ptr.load(Ordering::Acquire).is_null()));
    {
        let units = crate::IOMMU_UNITS.read();
        if scenario == "constructor" {
            assert!(units.is_empty());
            assert_eq!(REJECTIONS.load(Ordering::Acquire), 0);
            assert!(VTD_MMIO_SLOTS.lock().iter().all(Option::is_none));
            unsafe {
                mm::with_current_manager(VirtAddr::new(0), |manager| {
                    let (mapped, flags) = manager.translate_with_flags(blocker).unwrap();
                    assert_eq!(mapped.as_u64(), phys);
                    assert!(!flags.contains(PageTableFlags::WRITABLE));
                });
            }
        } else {
            assert_eq!(REJECTIONS.load(Ordering::Acquire), 1);
            assert_eq!(units.len(), 1);
            assert_retained(&units[0], scenario == "te");
        }
    }
    let domains = crate::DOMAINS.read();
    assert_eq!(domains.len(), usize::from(scenario == "te"));
    if scenario == "te" {
        assert_ne!(domains[0].page_table_root(), 0);
    }
    drop(domains);
    assert!(matches!(
        mm::dma::alloc_dma_buffer(4096),
        Err(mm::dma::DmaError::IommuMapRejected)
    ));
    assert_eq!(
        crate::attach_device(PciDeviceId::new(0, 0, 2, 0)),
        Err(IommuError::NotInitialized)
    );
    assert_eq!(crate::init(rsdp_phys), Err(IommuError::NotInitialized));
    assert_eq!(
        REJECTIONS.load(Ordering::Acquire),
        u32::from(scenario != "constructor")
    );
    klog::klog_always!("KSA-001-INIT PASS case={} published=0 snapshot=0 dma_rejected=1 attach_rejected=1 sticky=1 retained=1", scenario);
    // Keep all possibly active owners alive. The host must discard this VM.
    unsafe {
        x86_64::instructions::port::Port::<u32>::new(0xf4).write(0x10);
    }
    loop {
        x86_64::instructions::hlt();
    }
}
