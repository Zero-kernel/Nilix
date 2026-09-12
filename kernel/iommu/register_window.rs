pub(crate) const PAGE_BYTES: usize = 4096;
pub(crate) const MAX_WINDOW_BYTES: usize = 5 * PAGE_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RegisterWindow {
    pub version: (u8, u8),
    pub iotlb_offset: usize,
    pub fault_offset: usize,
    pub mapped_bytes: usize,
}

pub(crate) fn decode(version: u32, capability: u64, extended: u64) -> Option<RegisterWindow> {
    if version & !0xff != 0 || version >> 4 != 1 || capability == 0 || capability == u64::MAX {
        return None;
    }
    let iotlb_offset = ((extended >> 8) & 0x3ff) as usize * 16;
    let fault_offset = ((capability >> 24) & 0x3ff) as usize * 16;
    let fault_count = ((capability >> 40) & 0xff) as usize + 1;
    let iotlb_end = iotlb_offset.checked_add(16)?;
    let fault_end = fault_offset.checked_add(fault_count.checked_mul(16)?)?;
    if extended == u64::MAX
        || iotlb_offset < 0xc0
        || fault_offset < 0xc0
        || (iotlb_offset < fault_end && fault_offset < iotlb_end)
    {
        return None;
    }
    let mapped_bytes = iotlb_end
        .max(fault_end)
        .max(PAGE_BYTES)
        .checked_add(PAGE_BYTES - 1)?
        & !(PAGE_BYTES - 1);
    if mapped_bytes > MAX_WINDOW_BYTES {
        return None;
    }
    Some(RegisterWindow {
        version: ((version >> 4) as u8, (version & 0xf) as u8),
        iotlb_offset,
        fault_offset,
        mapped_bytes,
    })
}

pub(crate) fn ranges_overlap(first: u64, first_len: usize, second: u64, second_len: usize) -> bool {
    let Some(first_end) = first.checked_add(first_len as u64) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_len as u64) else {
        return true;
    };
    first < second_end && second < first_end
}

pub(crate) fn address_width_encoding(address_bits: u8) -> Option<u8> {
    match address_bits {
        39 => Some(1),
        48 => Some(2),
        57 => Some(3),
        _ => None,
    }
}

/// Select the widest common width implemented by Domain's 3/4-level tables.
pub(crate) fn common_kernel_address_width(widths: impl IntoIterator<Item = u8>) -> Option<u8> {
    let common = widths.into_iter().reduce(|left, right| left & right)?;
    [48u8, 39].into_iter().find(|&width| {
        address_width_encoding(width).is_some_and(|encoding| common & (1u8 << encoding) != 0)
    })
}

pub(crate) fn translated_context(
    domain_id: u16,
    root: u64,
    address_bits: u8,
) -> Option<(u64, u64)> {
    let width = address_width_encoding(address_bits)?;
    if root == 0 || root & 0xfff != 0 || root >> 52 != 0 {
        return None;
    }
    Some((root | 1, (u64::from(domain_id) << 8) | u64::from(width)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(fault_offset: usize, count: usize) -> u64 {
        ((fault_offset as u64 / 16) << 24) | (((count - 1) as u64) << 40) | 1
    }

    fn extended(iotlb_offset: usize) -> u64 {
        (iotlb_offset as u64 / 16) << 8
    }

    #[test]
    fn q35_window_fits_one_page() {
        let window = decode(0x10, capability(0x220, 1), extended(0xf0)).unwrap();
        assert_eq!(window.version, (1, 0));
        assert_eq!(window.iotlb_offset, 0xf0);
        assert_eq!(window.fault_offset, 0x220);
        assert_eq!(window.mapped_bytes, PAGE_BYTES);
    }

    #[test]
    fn rejects_fixed_register_and_variable_window_overlap() {
        assert!(decode(0x10, capability(0x80, 1), extended(0xf0)).is_none());
        assert!(decode(0x10, capability(0x220, 1), extended(0x80)).is_none());
        assert!(decode(0x10, capability(0x220, 2), extended(0x230)).is_none());
        assert!(decode(0x10, capability(0x220, 2), extended(0x240)).is_some());
    }

    #[test]
    fn maps_every_fault_record_with_page_rounding() {
        let window = decode(0x10, capability(0xff0, 2), extended(0x100)).unwrap();
        assert_eq!(window.mapped_bytes, 2 * PAGE_BYTES);
        let largest = decode(0x10, capability(0x3ff0, 256), extended(0x100)).unwrap();
        assert_eq!(largest.mapped_bytes, MAX_WINDOW_BYTES);
    }

    #[test]
    fn maps_complete_iotlb_register_pair() {
        let window = decode(0x10, capability(0x220, 1), extended(0x3ff0)).unwrap();
        assert_eq!(window.mapped_bytes, 4 * PAGE_BYTES);
    }

    #[test]
    fn rejects_absent_or_unsupported_registers() {
        for version in [0, 0x20, 0x110, u32::MAX] {
            assert!(decode(version, capability(0x220, 1), extended(0xf0)).is_none());
        }
        assert!(decode(0x10, 0, extended(0xf0)).is_none());
        assert!(decode(0x10, u64::MAX, extended(0xf0)).is_none());
        assert!(decode(0x10, capability(0x220, 1), u64::MAX).is_none());
    }

    #[test]
    fn reservations_reject_aliases_and_overflow_not_adjacent_ranges() {
        assert!(ranges_overlap(0x1000, 0x2000, 0x2000, 0x1000));
        assert!(ranges_overlap(0x2000, 0x1000, 0x1000, 0x2000));
        assert!(!ranges_overlap(0x1000, 0x1000, 0x2000, 0x1000));
        assert!(ranges_overlap(u64::MAX - 10, 20, 0x1000, 0x1000));
    }

    #[test]
    fn legacy_context_places_width_in_upper_word_without_device_iotlb() {
        for (bits, encoding) in [(39, 1), (48, 2), (57, 3)] {
            let (lower, upper) = translated_context(0x1234, 0x5678_9000, bits).unwrap();
            assert_eq!(lower, 0x5678_9001);
            assert_eq!(upper, 0x1234_00 | encoding);
            assert_eq!(address_width_encoding(bits), Some(encoding as u8));
        }
        assert!(translated_context(1, 0x1000, 32).is_none());
        assert!(translated_context(1, 0, 48).is_none());
        assert!(translated_context(1, 0x1001, 48).is_none());
        assert!(translated_context(1, 1 << 52, 48).is_none());
    }

    #[test]
    fn sagaw_capabilities_use_the_address_width_encoding() {
        assert_eq!(1u8 << address_width_encoding(39).unwrap(), 0x02);
        assert_eq!(1u8 << address_width_encoding(48).unwrap(), 0x04);
        assert_eq!(1u8 << address_width_encoding(57).unwrap(), 0x08);
    }

    #[test]
    fn single_unit_widths_follow_the_capability_bits() {
        assert_eq!(common_kernel_address_width([0x02]), Some(39));
        assert_eq!(common_kernel_address_width([0x04]), Some(48));
        assert_eq!(common_kernel_address_width([0x06]), Some(48));
    }

    #[test]
    fn domain_width_requires_support_on_every_unit() {
        assert_eq!(common_kernel_address_width([0x06, 0x02, 0x06]), Some(39));
        assert_eq!(common_kernel_address_width([0x06, 0x04]), Some(48));
        assert_eq!(common_kernel_address_width([0x02, 0x04]), None);
    }

    #[test]
    fn absent_or_unimplemented_domain_widths_fail_closed() {
        assert_eq!(common_kernel_address_width([]), None);
        assert_eq!(common_kernel_address_width([0]), None);
        assert_eq!(common_kernel_address_width([0x01]), None);
        assert_eq!(common_kernel_address_width([0x08]), None);
    }
}
