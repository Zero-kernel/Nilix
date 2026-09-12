//! P3-2 terminal Q35/EDU oracle. Default off; all resources retained to VM exit.

use super::*;
use crate::interrupt::{Irte, IrteHandle};
use klog::klog_always;
use x86_64::instructions::{interrupts, port::Port};

const DEV: PciDeviceId = PciDeviceId::new(0, 0, 5, 0);
const MMIO: u64 = 0xffff_ffff_6200_0000;
const PAGE: usize = 4096;
const BYTES: usize = 64;
const EDU_BUFFER: u64 = 0x40000;
const POLLS: usize = 2_000_000;

fn config_read(offset: u8) -> u32 {
    interrupts::without_interrupts(|| {
        let _guard = crate::PCI_CONFIG_LOCK.lock();
        crate::pci_cfg_read32(0, 5, 0, offset)
    })
}

fn config_write(offset: u8, value: u32) {
    interrupts::without_interrupts(|| {
        let _guard = crate::PCI_CONFIG_LOCK.lock();
        unsafe {
            Port::<u32>::new(0xcf8).write(crate::pci_cfg_address(0, 5, 0, offset));
            Port::<u32>::new(0xcfc).write(value);
        }
    });
}

fn config_write16(offset: u8, value: u16) {
    interrupts::without_interrupts(|| {
        let _guard = crate::PCI_CONFIG_LOCK.lock();
        // A 16-bit port write must not echo PCI status W1C bits in the high half.
        unsafe {
            Port::<u32>::new(0xcf8).write(crate::pci_cfg_address(0, 5, 0, offset));
            Port::<u16>::new(0xcfc + u16::from(offset & 2)).write(value);
        }
    });
}

fn bus_master(enable: bool) {
    let command = config_read(4) as u16;
    config_write16(4, if enable { command | 4 } else { command & !4 });
    assert_eq!(config_read(4) & 4 != 0, enable);
}

fn reg32(offset: u64) -> u32 {
    unsafe { read_volatile((MMIO + offset) as *const u32) }
}

fn write32(offset: u64, value: u32) {
    unsafe { write_volatile((MMIO + offset) as *mut u32, value) };
}

fn dma(address: u64, write_to_ram: bool) {
    unsafe {
        assert_eq!(read_volatile((MMIO + 0x98) as *const u64) & 1, 0);
        let (src, dst) = if write_to_ram {
            (EDU_BUFFER, address)
        } else {
            (address, EDU_BUFFER)
        };
        write_volatile((MMIO + 0x80) as *mut u64, src);
        write_volatile((MMIO + 0x88) as *mut u64, dst);
        write_volatile((MMIO + 0x90) as *mut u64, BYTES as u64);
        core::sync::atomic::fence(Ordering::SeqCst);
        write_volatile((MMIO + 0x98) as *mut u64, if write_to_ram { 3 } else { 1 });
        for _ in 0..POLLS {
            if read_volatile((MMIO + 0x98) as *const u64) & 1 == 0 {
                core::sync::atomic::fence(Ordering::SeqCst);
                return;
            }
            core::hint::spin_loop();
        }
    }
    panic!("P3-2 EDU DMA did not complete");
}

fn fill(phys: u64, value: u8) {
    let p = phys_to_virt(PhysAddr::new(phys)).as_mut_ptr::<u8>();
    for i in 0..PAGE {
        unsafe { write_volatile(p.add(i), value) };
    }
}

fn all(phys: u64, value: u8, length: usize) -> bool {
    let p = phys_to_virt(PhysAddr::new(phys)).as_ptr::<u8>();
    (0..length).all(|i| unsafe { read_volatile(p.add(i)) == value })
}

fn context_present(unit: &VtdUnit) -> bool {
    let _guard = unit.table_lock.lock();
    let root = unit.root_table_phys.load(Ordering::Acquire);
    assert!(valid_context_table_phys(root));
    let root_ptr = phys_to_virt(PhysAddr::new(root)).as_ptr::<u64>();
    let entry = unsafe { read_volatile(root_ptr) };
    assert_ne!(entry & 1, 0);
    let ctx = entry & !0xfff;
    assert!(valid_context_table_phys(ctx));
    let ctx_ptr = phys_to_virt(PhysAddr::new(ctx)).as_ptr::<u64>();
    unsafe { read_volatile(ctx_ptr.add(usize::from(DEV.source_id()) * 2)) & 1 != 0 }
}

fn fault(unit: &VtdUnit, iova: u64, reason: u8, write: bool) {
    // No callbacks are installed in this profile: inspect before production W1C.
    let mut raw = None;
    for i in 0..unit.num_fault_regs() {
        let lo = unsafe { VtdUnit::read_reg64(unit.reg_base, unit.fault_offset + i * 16) };
        let hi = unsafe { VtdUnit::read_reg64(unit.reg_base, unit.fault_offset + i * 16 + 8) };
        if hi >> 63 != 0 {
            assert!(raw.replace((lo, hi)).is_none());
        }
    }
    let (lo, hi) = raw.expect("P3-2 missing device-generated FRCD");
    assert_eq!(lo & !0xfff, iova);
    assert_eq!(hi as u16, DEV.source_id());
    assert_eq!(((hi >> 32) & 0xff) as u8, reason);
    assert_eq!(hi & (1 << 62) == 0, write);
    let decoded = FaultRecord::from_raw(lo, hi).unwrap();
    assert_eq!(decoded.fault_reason, crate::FaultReason::from_code(reason));
    assert_eq!(decoded.is_write, write);
    klog_always!(
        "KSA-P3-FAULT sid={:04x} iova={:#x} reason={} write={} lo={:#x} hi={:#x}",
        DEV.source_id(),
        iova,
        reason,
        write,
        lo,
        hi
    );
    assert!(crate::capture_dma_faults_irq());
    assert!(unit.pending_faults.detail(DEV.source_id()).is_some());
    assert_eq!(crate::drain_dma_fault_work(), 1);
    assert!(!context_present(unit));
    assert_eq!(config_read(4) & 4, 0);
    assert!(!unit.has_pending_fault_work());
}

fn no_stale_fault(unit: &VtdUnit) {
    assert_eq!(
        unsafe { VtdUnit::read_reg32(unit.reg_base, VTD_REG_FSTS) } & (3 | QI_ERROR_MASK),
        0,
        "P3-2 fault and QI status must be empty before a denied request"
    );
    assert!(!unit.has_pending_fault_work());
    for i in 0..unit.num_fault_regs() {
        assert_eq!(
            unsafe { VtdUnit::read_reg64(unit.reg_base, unit.fault_offset + i * 16 + 8) } >> 63,
            0
        );
    }
}

fn acknowledge_msi_fault(unit: &VtdUnit, index: usize, reason: u8) {
    // QEMU 8.2 records rejected MSI requests in FRCD; QEMU 6.2 only logs
    // the rejection. In this terminal probe MSI is disabled, DMA has completed,
    // and no production fault callbacks exist. Validate the entire record set
    // before acknowledging only this expected IR fault. Leaving it live would
    // compress the next rejection (or DMA fault) from the same EDU requester.
    interrupts::without_interrupts(|| {
        let status = unsafe { VtdUnit::read_reg32(unit.reg_base, VTD_REG_FSTS) };
        assert_eq!(status & (1 | QI_ERROR_MASK), 0);
        assert!(!unit.has_pending_fault_work());
        let mut fault = None;
        for slot in 0..unit.num_fault_regs() {
            let offset = unit.fault_offset + slot * 16;
            let lo = unsafe { VtdUnit::read_reg64(unit.reg_base, offset) };
            let hi = unsafe { VtdUnit::read_reg64(unit.reg_base, offset + 8) };
            if hi >> 63 == 0 {
                continue;
            }
            assert_eq!(lo, (index as u64) << 48, "P3-2 unexpected IR fault index");
            assert_eq!(
                hi,
                (1 << 63) | (u64::from(reason) << 32) | u64::from(DEV.source_id()),
                "P3-2 unexpected MSI fault reason, requester or flags"
            );
            assert!(fault.replace((offset, lo, hi)).is_none());
        }
        assert_eq!(status & 2 != 0, fault.is_some());
        if let Some((offset, lo, hi)) = fault {
            klog_always!(
                "KSA-P3-MSI-FAULT sid={:04x} index={} reason={} lo={:#x} hi={:#x}",
                DEV.source_id(),
                index,
                reason,
                lo,
                hi
            );
            core::sync::atomic::fence(Ordering::SeqCst);
            // W1C only the validated FRCD F bit; PPF follows the live records.
            unsafe { VtdUnit::write_reg64(unit.reg_base, offset + 8, 1 << 63) };
        }
        no_stale_fault(unit);
    });
}

fn disable_msi(cap: u8, control: u16) {
    config_write16(cap + 2, control & !1);
    assert_eq!(
        (config_read(cap) >> 16) & 1,
        0,
        "P3-2 MSI disable not acknowledged"
    );
}

fn msi(unit: &VtdUnit, irq_count: fn() -> u64, source_iova: u64) {
    no_stale_fault(unit);
    let mut cap = (config_read(0x34) & 0xfc) as u8;
    let mut found = None;
    for _ in 0..48 {
        if cap < 0x40 {
            break;
        }
        let value = config_read(cap);
        if value & 0xff == 5 {
            found = Some((cap, (value >> 16) as u16));
            break;
        }
        cap = ((value >> 8) & 0xfc) as u8;
    }
    let (cap, control) = found.expect("P3-2 EDU MSI capability missing");
    assert!(control & 0x80 != 0, "P3-2 requires EDU 64-bit MSI");
    let table = unit.interrupt_remapping_table().unwrap();
    let index = table.allocate_index().unwrap();
    let handle = IrteHandle::new(index, DEV.source_id(), 0x31);
    disable_msi(cap, control);
    config_write(cap + 4, handle.msi_address_lo());
    config_write(cap + 8, handle.msi_address_hi());
    config_write16(cap + 12, handle.msi_data() as u16);
    let valid = Irte::new_msi(0x31, 0, DEV.source_id());
    table.set_entry(index, valid);
    unit.invalidate_interrupt_entry_cache().unwrap();
    assert_ne!(
        unsafe { VtdUnit::read_reg32(unit.reg_base, VTD_REG_GSTS) } & (1 << 24),
        0,
        "P3-2 IRTA pointer was not acknowledged"
    );
    config_write16(cap + 2, control | 1);
    interrupts::enable();
    let mut expected = irq_count();
    let positive = |expected: &mut u64| {
        *expected += 1;
        write32(0x60, 1);
        for _ in 0..POLLS {
            if irq_count() == *expected {
                break;
            }
            core::hint::spin_loop();
        }
        assert_eq!(irq_count(), *expected, "P3-2 remapped MSI delivery");
        assert_eq!(reg32(0x24), 1);
        write32(0x64, 1);
    };
    positive(&mut expected);
    table.set_entry(index, Irte::new_msi(0x31, 0, DEV.source_id() ^ 8));
    unit.invalidate_interrupt_entry_cache().unwrap();
    write32(0x60, 1);
    dma(source_iova, false); // A completed 100ms EDU operation bounds non-delivery.
    assert_eq!(irq_count(), expected, "wrong SID delivered an interrupt");
    write32(0x64, 1);
    disable_msi(cap, control);
    acknowledge_msi_fault(unit, index, 0x26);
    assert!(table
        .free_index_with_iec(index, || unit.invalidate_interrupt_entry_cache())
        .unwrap());
    config_write16(cap + 2, control | 1);
    write32(0x60, 1);
    dma(source_iova, false);
    assert_eq!(irq_count(), expected, "retired IRTE delivered an interrupt");
    write32(0x64, 1);
    disable_msi(cap, control);
    acknowledge_msi_fault(unit, index, 0x22);
    assert_eq!(table.allocate_index(), Some(index));
    table.set_entry(index, valid);
    unit.invalidate_interrupt_entry_cache().unwrap();
    config_write16(cap + 2, control | 1);
    positive(&mut expected);
    disable_msi(cap, control);
    assert!(table
        .free_index_with_iec(index, || unit.invalidate_interrupt_entry_cache())
        .unwrap());
    klog_always!("KSA-P3-DEVICE PASS case=msi delivered=2 wrong_sid=denied retired=denied reused=true index={} lo={:#x} hi={:#x}",
        index, valid.lo, valid.hi);
}

fn exercise(rsdp: u64, irq_count: fn() -> u64, apic: u32) -> IommuResult<()> {
    assert_eq!(apic, 0, "P3-2 BSP destination must be APIC 0");
    klog_always!("KSA-P3-DEVICE BEGIN version=1");
    let dmar = crate::dmar::parse_dmar_table(rsdp).map_err(|_| IommuError::NoDmarTable)?;
    assert_eq!(dmar.drhd_count(), 1);
    assert_eq!(
        config_read(0),
        0x11e8_1234,
        "P3-2 fixed EDU endpoint missing"
    );
    bus_master(false);
    let bar = config_read(0x10);
    assert_eq!(bar & 15, 0, "P3-2 requires 32-bit nonprefetchable BAR0");
    assert_ne!(bar, 0);
    // Size BAR0 with decoding disabled; restore it before validating the result.
    let command = config_read(4) as u16;
    config_write16(4, command & !6);
    assert_eq!(
        config_read(4) & 6,
        0,
        "P3-2 BAR sizing requires MSE/BME off"
    );
    config_write(0x10, u32::MAX);
    let mask = config_read(0x10) & !15;
    config_write(0x10, bar);
    assert_eq!(config_read(0x10), bar, "P3-2 BAR restore not acknowledged");
    assert_eq!(mask, 0xfff0_0000, "P3-2 requires EDU's 1MiB aperture");
    assert_eq!(bar & 0x000f_ffff, 0);
    assert!(u64::from(bar) >= 256 * 1024 * 1024 && u64::from(bar) + 0x10_0000 <= 1u64 << 32);
    config_write16(4, (config_read(4) as u16 | 2 | (1 << 10)) & !4);
    assert_eq!(config_read(4) & (6 | (1 << 10)), 2 | (1 << 10));
    unsafe {
        mm::map_mmio(
            VirtAddr::new(MMIO),
            PhysAddr::new(u64::from(bar)),
            PAGE,
            &mut mm::FrameAllocator::new(),
        )
        .unwrap()
    };
    assert_eq!(reg32(0), 0x0100_00ed);
    write32(4, 0x1234_abcd);
    assert_eq!(reg32(4), !0x1234_abcd);
    assert_eq!(crate::init(rsdp)?, 1);
    let unit = crate::resolve_unit(&DEV)?;
    klog_always!(
        "KSA-P3-SETUP sid={:04x} bar={:#x} cap={:#x} ecap={:#x} gsts={:#x}",
        DEV.source_id(),
        bar,
        unit.cap,
        unit.ecap,
        unsafe { VtdUnit::read_reg32(unit.reg_base, VTD_REG_GSTS) }
    );
    let scratch = buddy_allocator::alloc_physical_pages(4).expect("P3-2 scratch pages");
    let c = scratch.start_address().as_u64();
    assert!(c + (4 * PAGE) as u64 <= 256 * 1024 * 1024);
    let (a, b, input) = (c + 4096, c + 8192, c + 12288);
    let source_iova = a;
    fill(c, 0x33);
    fill(a, 0x11);
    fill(b, 0x22);
    fill(input, 0xa5);
    let domain = crate::create_domain(DomainType::PageTable)?;
    crate::map_range(domain, c, a, PAGE, true)?;
    crate::map_range(domain, source_iova, input, PAGE, false)?;
    klog_always!("KSA-P3-ATTACH BEGIN domain={}", domain);
    crate::attach_device_to_domain(DEV, domain)?;
    assert!(context_present(&unit));
    bus_master(true);
    dma(source_iova, false);
    dma(c, true);
    assert!(all(a, 0xa5, BYTES) && all(c, 0x33, PAGE) && all(b, 0x22, PAGE));
    klog_always!("KSA-P3-DEVICE PASS case=translated iova={:#x} gpa={:#x} source_iova={:#x} source_gpa={:#x} bytes=64 canary=unchanged", c,a,source_iova,input);
    crate::unmap_range(domain, c, PAGE)?;
    crate::map_range(domain, c, b, PAGE, true)?;
    fill(a, 0x11);
    fill(input, 0x5a);
    dma(source_iova, false);
    dma(c, true);
    assert!(all(b, 0x5a, BYTES) && all(a, 0x11, PAGE) && all(c, 0x33, PAGE));
    klog_always!(
        "KSA-P3-DEVICE PASS case=replacement iova={:#x} old_gpa={:#x} new_gpa={:#x} old=unchanged",
        c,
        a,
        b
    );
    msi(&unit, irq_count, source_iova);
    interrupts::disable();
    crate::set_fault_config(crate::FaultConfig {
        isolate_devices: true,
        ..crate::FaultConfig::default()
    });
    crate::unmap_range(domain, c, PAGE)?;
    crate::map_range(domain, c, b, PAGE, false)?;
    fill(b, 0x22);
    no_stale_fault(&unit);
    klog_always!("KSA-P3-DEVICE CASE readonly");
    dma(c, true);
    assert!(all(b, 0x22, PAGE) && all(a, 0x11, PAGE) && all(c, 0x33, PAGE));
    fault(&unit, c, 5, true);
    klog_always!("KSA-P3-DEVICE PASS case=readonly canary=unchanged context=quarantined bme=off");
    crate::detach_device_from_domain(DEV, domain)?;
    crate::unmap_range(domain, c, PAGE)?;
    crate::attach_device_to_domain(DEV, domain)?;
    bus_master(true);
    no_stale_fault(&unit);
    klog_always!("KSA-P3-DEVICE CASE unmapped");
    dma(c, false);
    fault(&unit, c, 6, false);
    assert!(all(b, 0x22, PAGE) && all(a, 0x11, PAGE) && all(c, 0x33, PAGE));
    klog_always!("KSA-P3-DEVICE PASS case=unmapped canary=unchanged context=quarantined bme=off");
    crate::detach_device_from_domain(DEV, domain)?;
    assert!(!context_present(&unit));
    assert_eq!(config_read(4) & 4, 0);
    // Test-only: re-enable EDU requests against a retired context. All scratch
    // frames are still owned and never returned for allocation/reuse.
    bus_master(true);
    no_stale_fault(&unit);
    klog_always!("KSA-P3-DEVICE CASE detach");
    dma(c, true);
    fault(&unit, c, 2, true);
    assert!(all(b, 0x22, PAGE) && all(a, 0x11, PAGE) && all(c, 0x33, PAGE));
    klog_always!("KSA-P3-DEVICE PASS case=detach reenabled=probe_only canary=unchanged context=absent bme=off");
    klog_always!("KSA-P3-DEVICE COMPLETE cases=6 scratch=retained physical=false");
    Ok(())
}

/// # Safety
/// Terminal BSP/CPL0 profile on disposable Q35/EDU VM, before IOMMU callbacks or
/// normal DMA drivers. CPU0 owns the fixed EDU slot and the reserved MMIO page.
pub unsafe fn run(rsdp: u64, irq_count: fn() -> u64, apic: u32) -> ! {
    let code = match exercise(rsdp, irq_count, apic) {
        Ok(()) => 0x10,
        Err(error) => {
            klog_always!("KSA-P3-DEVICE FAIL error={:?}", error);
            0x11
        }
    };
    interrupts::disable();
    Port::<u32>::new(0xf4).write(code);
    loop {
        x86_64::instructions::hlt();
    }
}
