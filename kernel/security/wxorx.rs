//! W^X (Write XOR Execute) Policy Enforcement
//!
//! This module validates that no memory pages are simultaneously writable and executable,
//! either directly on a single leaf PTE or indirectly via live physical-frame aliases
//! across virtual mappings (e.g. `PML4[0]` identity map vs `PML4[511]` high-half map).
//!
//! # Security Rationale
//!
//! The W^X (also written W⊕X or "Write XOR Execute") policy ensures:
//! - Code pages are read-only and executable (R-X)
//! - Data pages are writable but not executable (RW-)
//! - No page can be both writable AND executable (RWX)
//! - No supervisor-executable physical frame has a live writable alias anywhere
//!   in the active page table hierarchy (U55-6)
//!
//! # Implementation
//!
//! The validator walks the 4-level x86_64 page table hierarchy in two bounded,
//! allocation-free passes:
//! 1. Compute effective permissions (AND of `WRITABLE`, AND of `!NO_EXECUTE`,
//!    AND of `USER_ACCESSIBLE` across PML4/PDPT/PD/PT), report direct RWX leaves,
//!    count low-identity (`PML4[0]`) executable pages, and collect coalesced
//!    executable physical ranges.
//! 2. Verify no writable leaf (`eff_w && !eff_x`) overlaps any executable
//!    physical range (for supervisor-executable ranges, no writable alias at all;
//!    for user-executable ranges, no user-writable alias).

use mm::page_table::{self, RECURSIVE_INDEX};
use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageTable, PageTableFlags},
    PhysAddr, VirtAddr,
};

/// Maximum coalesced executable physical ranges tracked without heap allocation.
const MAX_EXEC_RANGES: usize = 128;

/// Kind of W^X policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// A single leaf mapping is effectively both writable and executable.
    DirectRwx,
    /// A writable leaf aliases a physical frame mapped executable elsewhere.
    CrossAliasWx,
}

/// Summary of W^X validation
#[derive(Debug, Clone, Copy)]
pub struct ValidationSummary {
    /// Total page table entries scanned
    pub scanned_entries: usize,
    /// Total number of W^X violations found (direct RWX + cross-alias W+X)
    pub violations: usize,
    /// Number of cross-alias W+X violations found (subset of `violations`)
    pub alias_violations: usize,
    /// Number of effectively executable 4 KiB pages under `PML4[0]` (identity map)
    pub low_identity_exec_pages: usize,
    /// First concrete violation observed during the walk. Keeping the full
    /// count and one location gives callers actionable diagnostics without
    /// changing the fixed-size summary contract for subsequent entries.
    pub first_violation: Option<Violation>,
}

/// Details about a W^X violation
#[derive(Debug, Clone, Copy)]
pub struct Violation {
    /// Virtual base address of the violating region
    pub virt_base: VirtAddr,
    /// Physical address of the page
    pub phys: PhysAddr,
    /// Page table level where violation was found
    pub level: PageLevel,
    /// Page flags that caused the violation
    pub flags: PageTableFlags,
    /// Whether this violation was a direct RWX leaf or a writable alias of an executable frame
    pub kind: ViolationKind,
}

/// Page table hierarchy level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLevel {
    /// PML4 - 512 GB per entry
    P4,
    /// PDPT - 1 GB per entry
    P3,
    /// PD - 2 MB per entry
    P2,
    /// PT - 4 KB per entry
    P1,
    /// 1 GB huge page (PDPT level)
    Huge1G,
    /// 2 MB huge page (PD level)
    Huge2M,
}

/// W^X validation errors
#[derive(Debug)]
pub enum WxorxError {
    /// A W^X violation was detected
    Violation(Violation),
    /// X-3 FIX: One or more violations detected (includes full scan summary)
    PolicyViolation(ValidationSummary),
    /// Page table walk failed
    IncompleteWalk(&'static str),
    /// Invalid page table structure
    InvalidStructure,
}

#[derive(Debug, Clone, Copy)]
struct ExecRange {
    start: u64,
    end: u64,
    user: bool,
}

impl ExecRange {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        user: false,
    };
}

struct ExecRangeSet {
    ranges: [ExecRange; MAX_EXEC_RANGES],
    len: usize,
}

impl ExecRangeSet {
    const fn new() -> Self {
        Self {
            ranges: [ExecRange::EMPTY; MAX_EXEC_RANGES],
            len: 0,
        }
    }

    fn insert(&mut self, start: u64, end: u64, user: bool) -> Result<(), WxorxError> {
        if start >= end {
            return Ok(());
        }

        // Fast-path merge with existing adjacent or overlapping range of the
        // same privilege domain so contiguous `.text` collapses to one entry.
        for existing in &mut self.ranges[..self.len] {
            if existing.user == user && start <= existing.end && existing.start <= end {
                existing.start = existing.start.min(start);
                existing.end = existing.end.max(end);
                return Ok(());
            }
        }

        if self.len >= MAX_EXEC_RANGES {
            return Err(WxorxError::IncompleteWalk(
                "Executable physical range table overflow during cross-alias W^X check",
            ));
        }
        self.ranges[self.len] = ExecRange { start, end, user };
        self.len += 1;
        Ok(())
    }

    fn overlaps_writable(&self, start: u64, end: u64, writable_is_user: bool) -> bool {
        if start >= end {
            return false;
        }
        for existing in &self.ranges[..self.len] {
            if start < existing.end && existing.start < end {
                // Supervisor-executable frames may NEVER have a writable alias
                // (neither supervisor nor user). User-executable frames may not
                // have a user-writable alias (the kernel's high-half physmap is
                // supervisor-only and does not grant Ring-3 write access).
                if !existing.user || writable_is_user {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy)]
struct EffectivePerms {
    writable: bool,
    executable: bool,
    user: bool,
}

impl EffectivePerms {
    const ROOT: Self = Self {
        writable: true,
        executable: true,
        user: true,
    };

    #[inline]
    fn combine(self, flags: PageTableFlags) -> Self {
        Self {
            writable: self.writable && flags.contains(PageTableFlags::WRITABLE),
            executable: self.executable && !flags.contains(PageTableFlags::NO_EXECUTE),
            user: self.user && flags.contains(PageTableFlags::USER_ACCESSIBLE),
        }
    }
}

/// Validate W^X policy (direct RWX + cross-alias W+X) on the currently active page tables.
///
/// Reads CR3 directly and walks all present mappings excluding `RECURSIVE_INDEX`.
///
/// # Returns
///
/// - `Ok(summary)` if zero direct RWX and zero cross-alias W+X violations exist.
/// - `Err(WxorxError::PolicyViolation(summary))` if any violations are found.
pub fn validate_active(phys_offset: VirtAddr) -> Result<ValidationSummary, WxorxError> {
    let (cr3, _) = Cr3::read();
    let root_phys = cr3.start_address();
    validate_hierarchy(root_phys, |phys| {
        let virt = phys_offset + phys.as_u64();
        Ok(unsafe { &*(virt.as_u64() as *const PageTable) })
    })
}

/// Pure, testable page-table W^X and cross-alias validator.
pub fn validate_hierarchy<'a, F>(
    root_phys: PhysAddr,
    read_table: F,
) -> Result<ValidationSummary, WxorxError>
where
    F: Fn(PhysAddr) -> Result<&'a PageTable, WxorxError>,
{
    let pml4 = read_table(root_phys)?;
    let mut summary = ValidationSummary {
        scanned_entries: 0,
        violations: 0,
        alias_violations: 0,
        low_identity_exec_pages: 0,
        first_violation: None,
    };
    let mut exec_ranges = ExecRangeSet::new();

    let mut scanned_entries = 0usize;
    // Pass 1: Check direct RWX, count low-identity executable pages, and collect
    // coalesced executable physical ranges across the active hierarchy.
    walk_pml4(
        pml4,
        &read_table,
        true,
        &mut |pml4_idx, virt_base, phys, size, level, flags, eff| {
            if eff.executable && pml4_idx == 0 {
                let pages = (size / 4096) as usize;
                summary.low_identity_exec_pages =
                    summary.low_identity_exec_pages.saturating_add(pages);
            }

            if eff.writable && eff.executable {
                record_violation(
                    &mut summary,
                    Violation {
                        virt_base: VirtAddr::new(virt_base),
                        phys,
                        level,
                        flags,
                        kind: ViolationKind::DirectRwx,
                    },
                );
            }

            if eff.executable {
                let phys_start = phys.as_u64();
                let phys_end = phys_start.saturating_add(size);
                exec_ranges.insert(phys_start, phys_end, eff.user)?;
            }
            Ok(())
        },
        &mut scanned_entries,
    )?;
    summary.scanned_entries = scanned_entries;

    // Pass 2: Check every writable non-executable leaf against all collected
    // executable physical ranges to catch live cross-alias W+X mappings.
    if exec_ranges.len > 0 {
        let mut ignored_count = 0usize;
        walk_pml4(
            pml4,
            &read_table,
            false,
            &mut |_pml4_idx, virt_base, phys, size, level, flags, eff| {
                if eff.writable && !eff.executable {
                    let phys_start = phys.as_u64();
                    let phys_end = phys_start.saturating_add(size);
                    if exec_ranges.overlaps_writable(phys_start, phys_end, eff.user) {
                        summary.alias_violations = summary.alias_violations.saturating_add(1);
                        record_violation(
                            &mut summary,
                            Violation {
                                virt_base: VirtAddr::new(virt_base),
                                phys,
                                level,
                                flags,
                                kind: ViolationKind::CrossAliasWx,
                            },
                        );
                    }
                }
                Ok(())
            },
            &mut ignored_count,
        )?;
    }

    if summary.violations > 0 {
        return Err(WxorxError::PolicyViolation(summary));
    }

    Ok(summary)
}

fn walk_pml4<'a, F, V>(
    pml4: &'a PageTable,
    read_table: &F,
    count_entries: bool,
    visit_leaf: &mut V,
    scanned_entries: &mut usize,
) -> Result<(), WxorxError>
where
    F: Fn(PhysAddr) -> Result<&'a PageTable, WxorxError>,
    V: FnMut(
        usize,
        u64,
        PhysAddr,
        u64,
        PageLevel,
        PageTableFlags,
        EffectivePerms,
    ) -> Result<(), WxorxError>,
{
    for (pml4_idx, pml4_entry) in pml4.iter().enumerate() {
        // Skip recursive page table slot (PML4[510]): intermediate page-table
        // entries exposed through recursion are not memory leaves.
        if pml4_idx == RECURSIVE_INDEX {
            continue;
        }

        let flags = pml4_entry.flags();
        if pml4_entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        if count_entries {
            *scanned_entries += 1;
        }

        let p4_perms = EffectivePerms::ROOT.combine(flags);
        let virt_base = canonicalize(pml4_idx as u64 * (512 * 1024 * 1024 * 1024));
        let pdpt = read_table(pml4_entry.addr())?;

        walk_pdpt(
            pml4_idx,
            pdpt,
            virt_base,
            p4_perms,
            read_table,
            count_entries,
            visit_leaf,
            scanned_entries,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_pdpt<'a, F, V>(
    pml4_idx: usize,
    pdpt: &'a PageTable,
    base: u64,
    parent_perms: EffectivePerms,
    read_table: &F,
    count_entries: bool,
    visit_leaf: &mut V,
    scanned_entries: &mut usize,
) -> Result<(), WxorxError>
where
    F: Fn(PhysAddr) -> Result<&'a PageTable, WxorxError>,
    V: FnMut(
        usize,
        u64,
        PhysAddr,
        u64,
        PageLevel,
        PageTableFlags,
        EffectivePerms,
    ) -> Result<(), WxorxError>,
{
    for (pdpt_idx, pdpt_entry) in pdpt.iter().enumerate() {
        let flags = pdpt_entry.flags();
        if pdpt_entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        if count_entries {
            *scanned_entries += 1;
        }

        let perms = parent_perms.combine(flags);
        let virt_base = base + (pdpt_idx as u64 * 1024 * 1024 * 1024);

        if flags.contains(PageTableFlags::HUGE_PAGE) {
            visit_leaf(
                pml4_idx,
                virt_base,
                pdpt_entry.addr(),
                1024 * 1024 * 1024,
                PageLevel::Huge1G,
                flags,
                perms,
            )?;
            continue;
        }

        let pd = read_table(pdpt_entry.addr())?;
        walk_pd(
            pml4_idx,
            pd,
            virt_base,
            perms,
            read_table,
            count_entries,
            visit_leaf,
            scanned_entries,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_pd<'a, F, V>(
    pml4_idx: usize,
    pd: &'a PageTable,
    base: u64,
    parent_perms: EffectivePerms,
    read_table: &F,
    count_entries: bool,
    visit_leaf: &mut V,
    scanned_entries: &mut usize,
) -> Result<(), WxorxError>
where
    F: Fn(PhysAddr) -> Result<&'a PageTable, WxorxError>,
    V: FnMut(
        usize,
        u64,
        PhysAddr,
        u64,
        PageLevel,
        PageTableFlags,
        EffectivePerms,
    ) -> Result<(), WxorxError>,
{
    for (pd_idx, pd_entry) in pd.iter().enumerate() {
        let flags = pd_entry.flags();
        if pd_entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        if count_entries {
            *scanned_entries += 1;
        }

        let perms = parent_perms.combine(flags);
        let virt_base = base + (pd_idx as u64 * 2 * 1024 * 1024);

        if flags.contains(PageTableFlags::HUGE_PAGE) {
            visit_leaf(
                pml4_idx,
                virt_base,
                pd_entry.addr(),
                2 * 1024 * 1024,
                PageLevel::Huge2M,
                flags,
                perms,
            )?;
            continue;
        }

        let pt = read_table(pd_entry.addr())?;
        walk_pt(
            pml4_idx,
            pt,
            virt_base,
            perms,
            count_entries,
            visit_leaf,
            scanned_entries,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_pt<V>(
    pml4_idx: usize,
    pt: &PageTable,
    base: u64,
    parent_perms: EffectivePerms,
    count_entries: bool,
    visit_leaf: &mut V,
    scanned_entries: &mut usize,
) -> Result<(), WxorxError>
where
    V: FnMut(
        usize,
        u64,
        PhysAddr,
        u64,
        PageLevel,
        PageTableFlags,
        EffectivePerms,
    ) -> Result<(), WxorxError>,
{
    for (pt_idx, pt_entry) in pt.iter().enumerate() {
        let flags = pt_entry.flags();
        if pt_entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        if count_entries {
            *scanned_entries += 1;
        }

        let perms = parent_perms.combine(flags);
        let virt_addr = base + (pt_idx as u64 * 4096);
        visit_leaf(
            pml4_idx,
            virt_addr,
            pt_entry.addr(),
            4096,
            PageLevel::P1,
            flags,
            perms,
        )?;
    }

    Ok(())
}

#[inline]
fn record_violation(summary: &mut ValidationSummary, violation: Violation) {
    summary.violations = summary.violations.saturating_add(1);
    if summary.first_violation.is_none() {
        summary.first_violation = Some(violation);
    }
}

/// Check if page flags violate W^X policy
///
/// A violation occurs when a page is both:
/// - WRITABLE (bit 1 set)
/// - EXECUTABLE (NO_EXECUTE bit NOT set, i.e., bit 63 = 0)
#[inline]
fn is_wxorx_violation(flags: PageTableFlags) -> bool {
    let writable = flags.contains(PageTableFlags::WRITABLE);
    let executable = !flags.contains(PageTableFlags::NO_EXECUTE);
    writable && executable
}

/// Canonicalize a 64-bit address for x86_64
///
/// x86_64 requires addresses to be in canonical form:
/// - Bits 48-63 must match bit 47 (sign extension)
#[inline]
fn canonicalize(addr: u64) -> u64 {
    if addr & (1 << 47) != 0 {
        addr | 0xFFFF_0000_0000_0000
    } else {
        addr & 0x0000_FFFF_FFFF_FFFF
    }
}

/// Check a single virtual address for W^X compliance
pub fn check_address(virt_addr: VirtAddr, phys_offset: VirtAddr) -> Result<bool, WxorxError> {
    unsafe {
        page_table::with_current_manager(phys_offset, |manager| {
            match manager.translate_with_flags(virt_addr) {
                Some((_phys, flags)) => Ok(!is_wxorx_violation(flags)),
                None => Ok(true), // Unmapped pages don't violate W^X
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    struct MockHierarchy {
        tables: Vec<(u64, Box<PageTable>)>,
    }

    impl MockHierarchy {
        fn new() -> Self {
            Self { tables: Vec::new() }
        }

        fn alloc(&mut self) -> (PhysAddr, usize) {
            let idx = self.tables.len();
            let phys = ((idx as u64) + 1) * 0x1000;
            self.tables.push((phys, Box::new(PageTable::new())));
            (PhysAddr::new(phys), idx)
        }

        fn table_mut(&mut self, idx: usize) -> &mut PageTable {
            &mut self.tables[idx].1
        }

        fn read(&self, phys: PhysAddr) -> Result<&PageTable, WxorxError> {
            self.tables
                .iter()
                .find(|(p, _)| *p == phys.as_u64())
                .map(|(_, t)| &**t)
                .ok_or(WxorxError::InvalidStructure)
        }
    }

    #[test]
    fn test_is_wxorx_violation() {
        let rx = PageTableFlags::PRESENT;
        assert!(!is_wxorx_violation(rx));

        let rw = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        assert!(!is_wxorx_violation(rw));

        let rwx = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        assert!(is_wxorx_violation(rwx));
    }

    #[test]
    fn test_canonicalize() {
        assert_eq!(canonicalize(0x1234), 0x1234);
        assert_eq!(canonicalize(0x0000_8000_0000_0000), 0xFFFF_8000_0000_0000);
    }

    #[test]
    fn test_clean_boot_handoff_hierarchy_passes() {
        let mut h = MockHierarchy::new();
        let (pml4_phys, pml4) = h.alloc();
        let (pdpt_low_phys, pdpt_low) = h.alloc();
        let (pd_low_phys, pd_low) = h.alloc();
        let (pt_low_phys, pt_low) = h.alloc();
        let (pdpt_hi_phys, pdpt_hi) = h.alloc();
        let (pd_hi_phys, pd_hi) = h.alloc();
        let (pt_hi_phys, pt_hi) = h.alloc();

        let rw_parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let rx = PageTableFlags::PRESENT;
        let ro_nx = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
        let rw_nx = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        h.table_mut(pml4)[0].set_addr(pdpt_low_phys, rw_parent);
        h.table_mut(pml4)[511].set_addr(pdpt_hi_phys, rw_parent);
        h.table_mut(pml4)[RECURSIVE_INDEX].set_addr(pml4_phys, rw_nx);

        h.table_mut(pdpt_low)[0].set_addr(pd_low_phys, rw_parent);
        h.table_mut(pd_low)[0].set_addr(pt_low_phys, rw_parent);
        // Transition stub at 0x9000: R-X in PML4[0], R-- in PML4[511]
        h.table_mut(pt_low)[9].set_addr(PhysAddr::new(0x9000), rx);
        // Kernel .text at 0x100000 (PTE 256): R-- in PML4[0], R-X in PML4[511]
        h.table_mut(pt_low)[256].set_addr(PhysAddr::new(0x10_0000), ro_nx);
        // Kernel .data at 0x101000 (PTE 257): RW- in both
        h.table_mut(pt_low)[257].set_addr(PhysAddr::new(0x10_1000), rw_nx);

        h.table_mut(pdpt_hi)[510].set_addr(pd_hi_phys, rw_parent);
        h.table_mut(pd_hi)[0].set_addr(pt_hi_phys, rw_parent);
        h.table_mut(pt_hi)[9].set_addr(PhysAddr::new(0x9000), ro_nx);
        h.table_mut(pt_hi)[256].set_addr(PhysAddr::new(0x10_0000), rx);
        h.table_mut(pt_hi)[257].set_addr(PhysAddr::new(0x10_1000), rw_nx);

        let summary = validate_hierarchy(pml4_phys, |p| h.read(p))
            .expect("clean handoff hierarchy must pass W^X + alias audit");
        assert_eq!(summary.violations, 0);
        assert_eq!(summary.alias_violations, 0);
        assert_eq!(summary.low_identity_exec_pages, 1);
    }

    #[test]
    fn test_detects_cross_alias_writable_kernel_text_in_identity_map() {
        let mut h = MockHierarchy::new();
        let (pml4_phys, pml4) = h.alloc();
        let (pdpt_low_phys, pdpt_low) = h.alloc();
        let (pd_low_phys, pd_low) = h.alloc();
        let (pdpt_hi_phys, pdpt_hi) = h.alloc();
        let (pd_hi_phys, pd_hi) = h.alloc();
        let (pt_hi_phys, pt_hi) = h.alloc();

        let rw_parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let rx = PageTableFlags::PRESENT;
        let rw_nx_huge = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::HUGE_PAGE
            | PageTableFlags::NO_EXECUTE;

        h.table_mut(pml4)[0].set_addr(pdpt_low_phys, rw_parent);
        h.table_mut(pml4)[511].set_addr(pdpt_hi_phys, rw_parent);
        h.table_mut(pdpt_low)[0].set_addr(pd_low_phys, rw_parent);
        // Buggy identity map: 0..2 MiB is RW+NX (writable alias of kernel .text!)
        h.table_mut(pd_low)[0].set_addr(PhysAddr::new(0), rw_nx_huge);

        h.table_mut(pdpt_hi)[510].set_addr(pd_hi_phys, rw_parent);
        h.table_mut(pd_hi)[0].set_addr(pt_hi_phys, rw_parent);
        h.table_mut(pt_hi)[256].set_addr(PhysAddr::new(0x10_0000), rx);

        let err = validate_hierarchy(pml4_phys, |p| h.read(p))
            .expect_err("writable identity alias of kernel .text must fail");
        match err {
            WxorxError::PolicyViolation(summary) => {
                assert_eq!(summary.violations, 1);
                assert_eq!(summary.alias_violations, 1);
                assert_eq!(
                    summary.first_violation.expect("violation").kind,
                    ViolationKind::CrossAliasWx
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_detects_cross_alias_smp_trampoline_high_half_writable() {
        let mut h = MockHierarchy::new();
        let (pml4_phys, pml4) = h.alloc();
        let (pdpt_low_phys, pdpt_low) = h.alloc();
        let (pd_low_phys, pd_low) = h.alloc();
        let (pt_low_phys, pt_low) = h.alloc();
        let (pdpt_hi_phys, pdpt_hi) = h.alloc();
        let (pd_hi_phys, pd_hi) = h.alloc();
        let (pt_hi_phys, pt_hi) = h.alloc();

        let rw_parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let rx = PageTableFlags::PRESENT;
        let rw_nx = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        h.table_mut(pml4)[0].set_addr(pdpt_low_phys, rw_parent);
        h.table_mut(pml4)[511].set_addr(pdpt_hi_phys, rw_parent);
        h.table_mut(pdpt_low)[0].set_addr(pd_low_phys, rw_parent);
        h.table_mut(pd_low)[0].set_addr(pt_low_phys, rw_parent);
        // 0x8000 is R-X in PML4[0]
        h.table_mut(pt_low)[8].set_addr(PhysAddr::new(0x8000), rx);

        h.table_mut(pdpt_hi)[510].set_addr(pd_hi_phys, rw_parent);
        h.table_mut(pd_hi)[0].set_addr(pt_hi_phys, rw_parent);
        // Buggy high-half alias: 0xffffffff80008000 is RW+NX while 0x8000 is R-X
        h.table_mut(pt_hi)[8].set_addr(PhysAddr::new(0x8000), rw_nx);

        let err = validate_hierarchy(pml4_phys, |p| h.read(p))
            .expect_err("writable high-half alias of R-X trampoline must fail");
        match err {
            WxorxError::PolicyViolation(summary) => {
                assert_eq!(summary.violations, 1);
                assert_eq!(summary.alias_violations, 1);
                assert_eq!(summary.low_identity_exec_pages, 1);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_user_text_allows_supervisor_physmap_but_rejects_user_writable_alias() {
        let mut h = MockHierarchy::new();
        let (pml4_phys, pml4) = h.alloc();
        let (pdpt_u_phys, pdpt_u) = h.alloc();
        let (pd_u_phys, pd_u) = h.alloc();
        let (pt_u_phys, pt_u) = h.alloc();
        let (pdpt_hi_phys, pdpt_hi) = h.alloc();
        let (pd_hi_phys, pd_hi) = h.alloc();
        let (pt_hi_phys, pt_hi) = h.alloc();

        let u_parent =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let k_parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let u_rx = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        let u_rw_nx = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;
        let k_rw_nx =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        h.table_mut(pml4)[1].set_addr(pdpt_u_phys, u_parent);
        h.table_mut(pdpt_u)[0].set_addr(pd_u_phys, u_parent);
        h.table_mut(pd_u)[0].set_addr(pt_u_phys, u_parent);
        h.table_mut(pt_u)[0].set_addr(PhysAddr::new(0x20_0000), u_rx);

        h.table_mut(pml4)[511].set_addr(pdpt_hi_phys, k_parent);
        h.table_mut(pdpt_hi)[510].set_addr(pd_hi_phys, k_parent);
        h.table_mut(pd_hi)[1].set_addr(pt_hi_phys, k_parent);
        // Supervisor-only physmap for the user frame is expected.
        h.table_mut(pt_hi)[0].set_addr(PhysAddr::new(0x20_0000), k_rw_nx);

        assert!(validate_hierarchy(pml4_phys, |p| h.read(p)).is_ok());

        // Adding a user-writable alias of the same user-executable frame must fail.
        h.table_mut(pt_u)[1].set_addr(PhysAddr::new(0x20_0000), u_rw_nx);
        let err = validate_hierarchy(pml4_phys, |p| h.read(p))
            .expect_err("user-writable alias of user-executable frame must fail");
        match err {
            WxorxError::PolicyViolation(summary) => {
                assert_eq!(summary.alias_violations, 1);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
