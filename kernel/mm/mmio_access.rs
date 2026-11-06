//! Validate optional MMIO probe mappings before their first volatile access.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioAccessError {
    InvalidRange,
    InvalidTable,
    NotPresent,
    NotKernelWritable,
    WrongPhysicalAddress,
}

fn mapped_address<R>(root: u64, virt: u64, read: &R) -> Result<u64, MmioAccessError>
where
    R: Fn(u64, usize) -> Option<u64>,
{
    let mut table = root;
    for (level, shift) in [(4, 39), (3, 30), (2, 21), (1, 12)] {
        if table & 0xfff != 0 || table >= DIRECT_MAP_LIMIT {
            return Err(MmioAccessError::InvalidTable);
        }
        let raw =
            read(table, ((virt >> shift) & 0x1ff) as usize).ok_or(MmioAccessError::InvalidTable)?;
        let flags = PageTableFlags::from_bits_truncate(raw);
        if !flags.contains(PageTableFlags::PRESENT) {
            return Err(MmioAccessError::NotPresent);
        }
        // The driver writes registers after probing. Check parent permissions
        // too; a writable leaf under a read-only parent still faults on writes.
        if !flags.contains(PageTableFlags::WRITABLE)
            || flags.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return Err(MmioAccessError::NotKernelWritable);
        }
        let huge = flags.contains(PageTableFlags::HUGE_PAGE);
        if level == 4 && huge {
            return Err(MmioAccessError::InvalidTable);
        }
        if level == 1 || huge {
            let offset_mask = (1u64 << shift) - 1;
            // Huge-page PAT is bit 12, not part of the physical base. Other
            // low address bits in a huge leaf are reserved and must be zero.
            if huge && level != 1 && raw & PTE_ADDR_MASK & offset_mask & !(1 << 12) != 0 {
                return Err(MmioAccessError::InvalidTable);
            }
            return Ok((raw & PTE_ADDR_MASK & !offset_mask) | (virt & offset_mask));
        }
        table = raw & PTE_ADDR_MASK;
    }
    Err(MmioAccessError::InvalidTable)
}

fn validate_mapping<R>(
    root: u64,
    virt: u64,
    phys: u64,
    len: usize,
    read: &R,
) -> Result<(), MmioAccessError>
where
    R: Fn(u64, usize) -> Option<u64>,
{
    // This helper admits at most one page of registers, possibly straddling
    // two leaves. It is not an unbounded user-supplied range walker.
    if len == 0 || len > 4096 || virt < USER_HALF_END || virt & 0xfff != phys & 0xfff {
        return Err(MmioAccessError::InvalidRange);
    }
    let last = virt
        .checked_add(len as u64 - 1)
        .ok_or(MmioAccessError::InvalidRange)?;
    let last_phys = phys
        .checked_add(len as u64 - 1)
        .ok_or(MmioAccessError::InvalidRange)?;
    if VirtAddr::try_new(virt).is_err() || VirtAddr::try_new(last).is_err() || last_phys >= 1 << 52
    {
        return Err(MmioAccessError::InvalidRange);
    }
    let mut cursor = virt;
    loop {
        if mapped_address(root, cursor, read)? != phys + (cursor - virt) {
            return Err(MmioAccessError::WrongPhysicalAddress);
        }
        let page_end = cursor | 0xfff;
        if page_end >= last {
            return Ok(());
        }
        cursor = page_end + 1;
    }
}

/// Access an already-mapped MMIO register window only after proving that the
/// active CR3 maps every covered page to the expected physical address with
/// supervisor RW permissions. No mapping is created or repaired.
///
/// PT_LOCK and interrupt exclusion cover both validation and the callback, so
/// a concurrent page-table edit cannot race the initial volatile probe.
///
/// # Safety
/// The active page-table frames must be accessible through the kernel direct
/// map. `access` must perform only bounded register accesses: no allocation,
/// page-table operations, or callbacks that acquire PT_LOCK. A transport kept
/// after this call still requires the caller to keep its mapping alive.
pub unsafe fn with_kernel_mmio_mapping<T>(
    virt: u64,
    phys: u64,
    len: usize,
    access: impl FnOnce() -> T,
) -> Result<T, MmioAccessError> {
    let _guard = lock_pt();
    interrupts::without_interrupts(|| {
        validate_mapping(active_root(), virt, phys, len, &read_direct_map_entry)?;
        Ok(access())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u64 = PHYSICAL_MEMORY_OFFSET + 0x1000_1000;
    const PA: u64 = 0x1000_1000;
    const RW: u64 = PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits();

    fn entry(table: u64, index: usize) -> Option<u64> {
        match (table, index) {
            (0x1000, 511) => Some(0x2000 | RW),
            (0x2000, 510) => Some(0x3000 | RW),
            (0x3000, 128) => Some(0x4000 | RW),
            (0x4000, 1) => Some(PA | RW),
            (0x4000, 2) => Some((PA + 4096) | RW),
            _ => Some(0),
        }
    }

    #[test]
    fn accepts_complete_4k_and_huge_register_mappings() {
        assert_eq!(validate_mapping(0x1000, VA, PA, 4096, &entry), Ok(()));
        for (table, index, base) in [(0x2000, 510, 0), (0x3000, 128, 0x1000_0000)] {
            let huge = |t, i| {
                if (t, i) == (table, index) {
                    Some(base | RW | PageTableFlags::HUGE_PAGE.bits() | (1 << 12))
                } else {
                    entry(t, i)
                }
            };
            assert_eq!(validate_mapping(0x1000, VA, PA, 4096, &huge), Ok(()));
        }
    }

    #[test]
    fn rejects_absent_or_inaccessible_entries_at_every_level() {
        for key in [(0x1000, 511), (0x2000, 510), (0x3000, 128), (0x4000, 1)] {
            for flags in [
                0,
                PageTableFlags::PRESENT.bits(),
                RW | PageTableFlags::USER_ACCESSIBLE.bits(),
            ] {
                let altered = |t, i| {
                    if (t, i) == key {
                        Some((entry(t, i).unwrap() & PTE_ADDR_MASK) | flags)
                    } else {
                        entry(t, i)
                    }
                };
                assert!(validate_mapping(0x1000, VA, PA, 4096, &altered).is_err());
            }
        }
    }

    #[test]
    fn checks_second_page_and_physical_identity_without_dereferencing_mmio() {
        assert_eq!(
            validate_mapping(0x1000, VA + 4092, PA + 4092, 8, &entry),
            Ok(())
        );
        let absent_tail = |t, i| {
            if (t, i) == (0x4000, 2) {
                Some(0)
            } else {
                entry(t, i)
            }
        };
        assert_eq!(
            validate_mapping(0x1000, VA + 4092, PA + 4092, 8, &absent_tail),
            Err(MmioAccessError::NotPresent)
        );
        assert_eq!(
            validate_mapping(0x1000, VA, PA + 4096, 4096, &entry),
            Err(MmioAccessError::WrongPhysicalAddress)
        );
        for (virt, phys, len) in [
            (VA, PA, 0),
            (VA, PA, 4097),
            (VA + 1, PA, 4),
            (PA, PA, 4),
            (u64::MAX - 3, 0xffc, 8),
        ] {
            assert_eq!(
                validate_mapping(0x1000, virt, phys, len, &entry),
                Err(MmioAccessError::InvalidRange)
            );
        }
    }

    #[test]
    fn rejects_unreachable_tables_and_reserved_huge_page_bits() {
        let bad_table = |t, i| {
            if (t, i) == (0x1000, 511) {
                Some(DIRECT_MAP_LIMIT | RW)
            } else {
                entry(t, i)
            }
        };
        assert_eq!(
            validate_mapping(0x1000, VA, PA, 4096, &bad_table),
            Err(MmioAccessError::InvalidTable)
        );
        let reserved = |t, i| {
            if (t, i) == (0x3000, 128) {
                Some(0x1000_2000 | RW | PageTableFlags::HUGE_PAGE.bits())
            } else {
                entry(t, i)
            }
        };
        assert_eq!(
            validate_mapping(0x1000, VA, PA, 4096, &reserved),
            Err(MmioAccessError::InvalidTable)
        );
    }
}
