#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum PageTableOp {
    Map { va: u64, flags: u8 },
    Unmap { va: u64 },
    ChangeProtection { va: u64, new_flags: u8 },
    Lookup { va: u64 },
}

#[derive(Arbitrary, Debug)]
struct PageTableFuzzInput {
    operations: Vec<PageTableOp>,
}

fuzz_target!(|input: PageTableFuzzInput| {
    let mut pt_harness = mm::test_harness::PageTableHarness::new();

    // Limit to 500 operations to prevent timeout
    for op in input.operations.iter().take(500) {
        match op {
            PageTableOp::Map { va, flags } => {
                // Canonicalize address to user space (lower half)
                let va_canonical = *va & 0x0000_7FFF_FFFF_FFFF;
                let va_aligned = va_canonical & !0xFFF;

                // Parse flags (R/W/X/U)
                let readable = flags & 0x01 != 0;
                let writable = flags & 0x02 != 0;
                let executable = flags & 0x04 != 0;
                let user = flags & 0x08 != 0;

                // At least one of R/W/X must be set for valid mapping
                if !readable && !writable && !executable {
                    continue;
                }

                let _ = pt_harness.map_page(va_aligned, readable, writable, executable, user);
            }
            PageTableOp::Unmap { va } => {
                let va_canonical = *va & 0x0000_7FFF_FFFF_FFFF;
                let va_aligned = va_canonical & !0xFFF;
                let _ = pt_harness.unmap_page(va_aligned);
            }
            PageTableOp::ChangeProtection { va, new_flags } => {
                let va_canonical = *va & 0x0000_7FFF_FFFF_FFFF;
                let va_aligned = va_canonical & !0xFFF;

                let readable = new_flags & 0x01 != 0;
                let writable = new_flags & 0x02 != 0;
                let executable = new_flags & 0x04 != 0;
                let user = new_flags & 0x08 != 0;

                // At least one permission needed
                if !readable && !writable && !executable {
                    continue;
                }

                let _ = pt_harness.change_protection(va_aligned, readable, writable, executable, user);
            }
            PageTableOp::Lookup { va } => {
                let va_canonical = *va & 0x0000_7FFF_FFFF_FFFF;
                let _ = pt_harness.lookup(va_canonical);
            }
        }
    }

    // Verify: no dangling PTEs, W^X enforced, all addresses canonical
    pt_harness.verify_integrity();
});
