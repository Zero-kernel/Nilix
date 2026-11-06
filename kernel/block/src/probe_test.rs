//! Bare-metal regression for optional MMIO probes. Enabled only by block_probe.

use super::*;
use x86_64::{PhysAddr, VirtAddr};

/// Exercise the real probe with an absent PML4 slot, a mismatched translation,
/// and a present non-device page. No live direct-map mapping is removed.
pub unsafe fn run_mmio_access_self_test() {
    let absent = mm::with_current_manager(VirtAddr::new(0), |manager| {
        (480u64..=509)
            .map(|index| 0xffff_0000_0000_0000 | (index << 39))
            .find(|address| manager.pml4_slot_is_unused(VirtAddr::new(*address)))
            .expect("block-probe requires an unused high-half fixture slot")
    });
    const HINT: u64 = 0x1000_1000;
    assert!(matches!(
        virtio::VirtioBlkDevice::probe_mmio(HINT, absent - HINT, "probe-absent"),
        Err(BlockError::NotFound)
    ));
    klog_force!("BLOCK-MMIO-PROBE PASS absent mapping refused before volatile read");

    let mut allocator = mm::FrameAllocator::new();
    let frame = allocator
        .allocate_frame()
        .expect("block-probe fixture frame");
    let phys = frame.start_address().as_u64();
    let address = mm::phys_to_virt(PhysAddr::new(phys)).as_u64();
    core::ptr::write_bytes(address as *mut u8, 0, 4096);
    let other_phys = phys.checked_add(4096).expect("fixture physical successor");
    assert!(matches!(
        virtio::VirtioBlkDevice::probe_mmio(other_phys, address - other_phys, "probe-alias"),
        Err(BlockError::NotFound)
    ));
    assert!(matches!(
        virtio::VirtioBlkDevice::probe_mmio(phys, mm::PHYSICAL_MEMORY_OFFSET, "probe-present"),
        Err(BlockError::NotFound)
    ));
    allocator.deallocate_frame(frame);
    klog_force!(
        "BLOCK-MMIO-PROBE PASS physical identity checked; mapped non-device read completed"
    );
}
