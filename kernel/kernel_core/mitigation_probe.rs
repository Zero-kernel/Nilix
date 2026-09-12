//! Test-profile observations of the actual dual roots at construction.
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use x86_64::PhysAddr;

// Only the mitigation_probe profile contains this debugger rendezvous. The
// collector validates both relocated symbols before releasing the first root
// constructor; ordinary kernel profiles never wait for a debugger.
#[no_mangle]
pub static ZERO_MITIGATION_PROBE_RELEASE: AtomicU8 = AtomicU8::new(0);
static RENDEZVOUS_STARTED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
#[inline(never)]
pub extern "C" fn zero_mitigation_probe_anchor() {
    // A retained leaf whose first bytes contain no relocation-dependent operand.
    unsafe {
        core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const USER: u64 = 4;
const HUGE: u64 = 1 << 7;

/// Caller owns both roots and their stable table hierarchy through this read.
/// Volatile loads also tolerate hardware updates of the accessed/dirty bits.
unsafe fn word(table: u64, index: usize) -> u64 {
    let pointer = mm::phys_to_virt(PhysAddr::new(table & ADDRESS)).as_ptr::<u64>();
    core::ptr::read_volatile(pointer.add(index))
}

fn translate(
    mut root: u64,
    address: u64,
    mut read: impl FnMut(u64, usize) -> u64,
) -> Option<(u64, bool)> {
    let mut accessible = true;
    for shift in [39, 30, 21, 12] {
        let entry = read(root, ((address >> shift) & 511) as usize);
        if entry & PRESENT == 0 {
            return None;
        }
        accessible &= entry & USER != 0;
        if shift == 12 || ((shift == 30 || shift == 21) && entry & HUGE != 0) {
            let offset_mask = (1u64 << shift) - 1;
            return Some((
                (entry & ADDRESS & !offset_mask) | (address & offset_mask),
                accessible,
            ));
        }
        root = entry & ADDRESS;
    }
    None
}

/// Inspect roots before publication, while the constructor still owns their
/// allocation and the shared hierarchy has the constructor's existing lifetime.
/// No pointer, table borrow or physical ownership escapes this observation.
pub(crate) unsafe fn inspect(kernel: u64, user: u64) {
    assert!(kernel != user && kernel & 4095 == 0 && user & 4095 == 0);
    for index in 0..256 {
        // Accessed/dirty are hardware state, not mapping identity.
        assert_eq!(word(kernel, index) & !0x60, word(user, index) & !0x60);
    }
    for index in 256..511 {
        assert_eq!(word(user, index) & PRESENT, 0);
    }
    let kernel_island = word(kernel, 511);
    let user_island = word(user, 511);
    assert_ne!(kernel_island & ADDRESS, user_island & ADDRESS);
    assert_eq!(user_island & (PRESENT | USER), PRESENT);
    for index in 0..508 {
        assert_eq!(word(user_island, index) & PRESENT, 0);
    }
    for index in 508..512 {
        assert_eq!(
            word(user_island, index) & !(USER | 0x60),
            word(kernel_island, index) & !(USER | 0x60)
        );
        assert_eq!(word(user_island, index) & USER, 0);
    }
    let layout = security::get_kernel_layout();
    let stack_sample = 0u8;
    let samples = [
        layout.text_start,
        layout.data_start,
        layout.heap_start,
        &stack_sample as *const u8 as u64,
    ];
    for address in samples {
        let original = translate(kernel, address, |table, index| word(table, index));
        let retained = translate(user, address, |table, index| word(table, index));
        assert!(original.is_some() && retained.is_some());
        assert_eq!(original.unwrap().0, retained.unwrap().0);
        assert!(
            !retained.unwrap().1,
            "retained kernel sample became user accessible"
        );
    }
    let low_mapping = translate(user, 0x10_0000, |table, index| word(table, index));
    assert!(
        !low_mapping.is_some_and(|(_, accessible)| accessible),
        "low identity alias became user accessible"
    );
    let low_alias = low_mapping.is_some();
    klog::klog_always!("MITIGATION-MAP PASS kernel={:x} user={:x} shared_user=true recursive_absent=true private_island=true lower_island_absent=true text_retained=true data_retained=true heap_retained=true stack_retained=true low_alias={} full_isolation=false", kernel, user, low_alias);
    if !RENDEZVOUS_STARTED.swap(true, Ordering::AcqRel) {
        zero_mitigation_probe_anchor();
        klog::klog_always!(
            "MITIGATION-ANCHOR symbol=zero_mitigation_probe_anchor runtime={:#x} release={:#x}",
            zero_mitigation_probe_anchor as *const () as usize,
            &ZERO_MITIGATION_PROBE_RELEASE as *const AtomicU8 as usize,
        );
        while ZERO_MITIGATION_PROBE_RELEASE.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_permissions_include_every_level() {
        let read = |table, _| match table {
            0x1000 => 0x2000 | PRESENT | USER,
            0x2000 => 0x3000 | PRESENT,
            0x3000 => 0x4000 | PRESENT | USER,
            _ => 0x5000 | PRESENT | USER,
        };
        assert_eq!(translate(0x1000, 123, read), Some((0x5000 + 123, false)));
    }

    #[test]
    fn missing_level_is_not_a_mapping() {
        assert_eq!(translate(0x1000, 0, |_, _| 0), None);
    }

    #[test]
    fn huge_leaf_uses_its_actual_page_offset() {
        assert_eq!(
            translate(0x1000, 0x203456, |table, _| if table == 0x1000 {
                0x2000 | 5
            } else {
                0x4000_0000 | 5 | HUGE
            }),
            Some((0x4020_3456, true))
        );
    }
}
