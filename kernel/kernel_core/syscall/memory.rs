//! Syscall family module: `mm` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

/// ST-K2-P2a: page-table state of one user page (retained for hosted preflight tests).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UserPageState {
    /// Present, user-accessible and, for a write, writable or copy-on-write.
    Ready,
    /// No present translation; a demand fault may still resolve it.
    NotPresent,
    /// Present but not usable as requested; no fault resolution changes that.
    Denied,
}

/// Classify one page from its leaf translation flags (`None`: not mapped).
#[cfg(test)]
pub(super) fn classify_user_page(
    flags: Option<PageTableFlags>,
    require_write: bool,
) -> UserPageState {
    let Some(flags) = flags else {
        return UserPageState::NotPresent;
    };
    if !flags.contains(PageTableFlags::PRESENT) {
        return UserPageState::NotPresent;
    }
    // 检查页是否用户可访问（低端恒等映射是 supervisor-only 的）
    if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        return UserPageState::Denied;
    }
    // 如果需要写入权限，检查 WRITABLE 或 BIT_9 (COW) 标志
    // COW 页面标记为只读但有 BIT_9，写入时会触发 #PF 并由 COW 处理器创建可写副本
    // 真正的只读页面（如代码段）没有这两个标志，应该拒绝写入
    if require_write
        && !flags.contains(PageTableFlags::WRITABLE)
        && !flags.contains(PageTableFlags::BIT_9)
    {
        return UserPageState::Denied;
    }
    UserPageState::Ready
}

/// ST-K2-P2a: the bounded preflight loop over the pages of `[start, end)`.
#[cfg(test)]
pub(super) fn preflight_user_pages(
    start: usize,
    end: usize,
    require_write: bool,
    mut first_unready: impl FnMut(usize, bool) -> Result<Option<usize>, SyscallError>,
    mut fault_in: impl FnMut(usize, bool) -> Result<(), ()>,
) -> Result<(), SyscallError> {
    let mut page = start & !0xfff;
    let mut resolved = None;
    while let Some(missing) = first_unready(page, require_write)? {
        if missing < page || missing >= end || missing & 0xfff != 0 || resolved == Some(missing) {
            return Err(SyscallError::EFAULT);
        }
        fault_in(missing, require_write).map_err(|_| SyscallError::EFAULT)?;
        resolved = Some(missing);
        page = missing;
    }
    Ok(())
}

/// Issue #90 follow-up (P0): Iterate every 4 KiB page intersecting `[start, start + len)`
/// and invoke `probe(page_base)` fail-closed.
pub(super) fn probe_user_page_span(
    start: usize,
    len: usize,
    mut probe: impl FnMut(usize) -> Result<(), ()>,
) -> Result<(), SyscallError> {
    if len == 0 {
        return Err(SyscallError::EFAULT);
    }
    let end = start.checked_add(len).ok_or(SyscallError::EFAULT)?;
    let mut page = start & !0xfff;
    while page < end {
        probe(page).map_err(|()| SyscallError::EFAULT)?;
        match page.checked_add(0x1000) {
            Some(next) => page = next,
            None => break,
        }
    }
    Ok(())
}

/// 验证用户空间地址是否已映射且具备所需权限
///
/// Issue #90 follow-up (P0): Uses hardware SMAP + exception-table guarded probes
/// ([`crate::usercopy::fault_in_user_page`]) instead of acquiring exclusive
/// `AS_PT_LOCKS[shard]` (`with_current_manager`) for a software page-table walk.
///
/// Security invariants preserved:
/// - `validate_user_ptr` rejects zero/overflow/kernel-half (`>= USER_HALF_END`) ranges.
/// - `UserAccessGuard::try_new_for_usercopy()` fails closed on `BOOT_CR3`, and
///   D0-ISO-1 guarantees user address spaces contain zero supervisor-only lower-half
///   mappings.
/// - `CR0.WP = 1` + `lock cmpxchg 0, 0` (when `require_write`) enforces write
///   permission, breaks CoW, demand-installs shared-anonymous pages, and returns
///   `EFAULT` on `PROT_READ` / `PROT_NONE` / unmapped pages without modifying data.
/// - Runs with zero page-table lock acquisitions and interrupts enabled, eliminating
///   16-vCPU same-AS `AS_PT_LOCKS` contention on `sys_futex` and thread-creation syscalls.
pub(super) fn verify_user_memory(
    ptr: *const u8,
    len: usize,
    require_write: bool,
) -> Result<(), SyscallError> {
    validate_user_ptr(ptr, len)?;
    probe_user_page_span(ptr as usize, len, |page| {
        crate::usercopy::fault_in_user_page(crate::usercopy::UserAddr::new(page), require_write)
    })
}

/// LEAD-MREMAP-MIGRATE-1: while a growing mremap is in flight, the migration
/// snapshot (`compute_cgroup_charged_bytes`: every non-PROT_NONE entry minus the
/// uncharged lane) equals exactly what the call has charged.
#[cfg(test)]
mod r192_res_2_mremap_tests {
    use super::{mremap_uncharged_reserve, relocation_table_bound, StagedTables};
    use alloc::vec::Vec;
    use x86_64::structures::paging::{FrameAllocator, PhysFrame};
    use x86_64::PhysAddr;

    const MIB: usize = 1 << 20;
    const GIB: usize = 1 << 30;

    #[test]
    fn r192_res_2a_relocation_table_bound_covers_every_region() {
        assert_eq!(relocation_table_bound(0x10_0000_0000, 0), 0);
        // One page: its PT, PD and PDPT.
        assert_eq!(relocation_table_bound(0x10_0000_0000, 0x1000), 3);
        // An aligned 2 MiB region, then the same length straddling a 2 MiB line.
        assert_eq!(relocation_table_bound(0x10_0000_0000, 2 * MIB), 3);
        assert_eq!(relocation_table_bound(0x10_0010_0000, 2 * MIB), 4);
        // 1 GiB aligned: 512 PTs, one PD, one PDPT; off by a page: one more PT and PD.
        assert_eq!(relocation_table_bound(0x10_0000_0000, GIB), 514);
        assert_eq!(relocation_table_bound(0x10_0000_1000, GIB), 516);
        // Across a 512 GiB line as well: the worst case for 1 GiB.
        assert_eq!(relocation_table_bound(0x80_0000_0000 - 0x1000, GIB), 517);
        // 512 MiB at a page-aligned base inside one 1 GiB region (the large guest leg).
        assert_eq!(
            relocation_table_bound(0x10_0000_1000, 512 * MIB),
            257 + 1 + 1
        );
    }

    #[test]
    fn r192_res_2a_staged_tables_hand_out_each_frame_once_and_record_it() {
        let frame = |n: u64| PhysFrame::containing_address(PhysAddr::new(n * 0x1000));
        let mut pool = [Some(frame(1)), None, Some(frame(2)), Some(frame(3))];
        let mut recorded = Vec::with_capacity(2);
        let mut tables = StagedTables::new(&mut pool, &mut recorded);
        assert_eq!(tables.allocate_frame(), Some(frame(1)));
        assert_eq!(tables.allocate_frame(), Some(frame(2)));
        // The record is full: refuse rather than hand out an unrecorded table.
        assert_eq!(tables.allocate_frame(), None);
        assert_eq!(recorded, [frame(1), frame(2)]);
        assert_eq!(pool, [None, None, None, Some(frame(3))]);

        let mut recorded = Vec::with_capacity(4);
        let mut tables = StagedTables::new(&mut pool, &mut recorded);
        assert_eq!(tables.allocate_frame(), Some(frame(3)));
        // The pool is empty.
        assert_eq!(tables.allocate_frame(), None);
        assert_eq!(recorded, [frame(3)]);
    }

    #[test]
    fn lead_mremap_migrate_1_snapshot_counts_only_charged_bytes() {
        let (old_len, new_len) = (0x3000usize, 0x8000usize);
        let tail_len = new_len - old_len;
        for prot_none in [false, true] {
            for moved in [false, true] {
                let reserved_len = if moved { new_len } else { tail_len };
                // The claimed source counts unless it is a PROT_NONE entry; the
                // reservation is plain PENDING_MAP and always counts.
                let counted = if prot_none { 0 } else { old_len } + reserved_len;
                let charged = if prot_none { 0 } else { old_len + tail_len };
                assert_eq!(
                    counted - mremap_uncharged_reserve(reserved_len, tail_len, prot_none),
                    charged,
                    "moved={moved} prot_none={prot_none}"
                );
            }
        }
    }

    #[test]
    fn lazy_anon_mmap_entry_flag_invariants() {
        use super::{
            mmap_prot_to_flags, validate_mmap_flags, MmapEntry, MmapShape, MAP_ANONYMOUS,
            MAP_FIXED_NOREPLACE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MMAP_REGION_FLAG_LAZY_ANON,
            MMAP_REGION_FLAG_PENDING_MAP, MMAP_REGION_FLAG_UNFAULTED, PROT_READ, PROT_WRITE,
        };
        assert_eq!(
            validate_mmap_flags(MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE),
            Ok(MmapShape {
                shared: false,
                exact: false,
                populate: true,
            })
        );
        assert_eq!(
            validate_mmap_flags(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE),
            Ok(MmapShape {
                shared: false,
                exact: true,
                populate: true,
            })
        );
        assert!(validate_mmap_flags(MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE).is_err());

        let mut entry = MmapEntry::from_len_flags(
            0x20_0000,
            mmap_prot_to_flags(PROT_READ | PROT_WRITE)
                | MMAP_REGION_FLAG_LAZY_ANON
                | MMAP_REGION_FLAG_UNFAULTED,
        );
        assert!(entry.is_lazy_anon());
        assert!(entry.is_unfaulted());
        assert!(entry.prot_read() && entry.prot_write() && !entry.prot_exec());
        assert_eq!(entry.perms(), *b"rw-p");

        // mprotect Path C display-bit update preserves LAZY_ANON | UNFAULTED.
        entry.rewrite_prot_bits(mmap_prot_to_flags(PROT_READ));
        assert!(entry.is_lazy_anon());
        assert!(entry.is_unfaulted());
        assert!(entry.prot_read() && !entry.prot_write());

        // fork_stripped preserves LAZY_ANON | UNFAULTED while clearing transients.
        let transient =
            MmapEntry::from_len_flags(entry.len(), entry.flags() | MMAP_REGION_FLAG_PENDING_MAP);
        let stripped = transient.fork_stripped();
        assert!(!stripped.has_transient());
        assert!(stripped.is_lazy_anon() && stripped.is_unfaulted());

        // First page fault clears UNFAULTED while keeping LAZY_ANON.
        entry.clear_unfaulted();
        assert!(entry.is_lazy_anon());
        assert!(!entry.is_unfaulted());

        // Demotion to PROT_NONE clears both LAZY_ANON and UNFAULTED.
        let none = MmapEntry::prot_none(entry.len());
        assert!(none.is_prot_none());
        assert!(!none.is_lazy_anon() && !none.is_unfaulted());
    }
}

#[cfg(test)]
mod st_k2_p2a_preflight_tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    const PAGE: usize = 0x1000;
    const BASE: usize = 0x10_0000_0000;

    /// One page of a modeled address space and what resolving it does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Page {
        Ready,
        /// Present but supervisor-only (the low identity map, before Approach A).
        Supervisor,
        /// Present, user, read-only and not copy-on-write.
        ReadOnly,
        /// Not present; resolving it installs a writable user page.
        Lazy,
        /// Not present; the access succeeds but a racing unmap removes it again.
        Vanishing,
        /// Not present; the access faults (nothing is mapped).
        Unmapped,
        /// Not present; resolving it installs a page the walk then denies.
        LazySupervisor,
        /// Not present, in a read-only region: resolving it installs a
        /// read-only page, and a write probe then faults on it.
        LazyReadOnly,
    }

    fn flags_of(page: Page) -> Option<PageTableFlags> {
        let user = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        match page {
            Page::Ready => Some(user | PageTableFlags::WRITABLE),
            Page::Supervisor => Some(PageTableFlags::PRESENT | PageTableFlags::WRITABLE),
            Page::ReadOnly => Some(user),
            _ => None,
        }
    }

    /// Run the preflight loop over `pages` (page 0 at `BASE`) with the real
    /// classifier. Both callbacks act on the intent the loop hands them, not
    /// on `write`. Returns the result, the probed addresses and the final pages.
    fn run(
        pages: &[Page],
        start: usize,
        len: usize,
        write: bool,
    ) -> (Result<(), SyscallError>, Vec<usize>, Vec<Page>) {
        let space = RefCell::new(pages.to_vec());
        let probes = RefCell::new(Vec::new());
        let end = start + len;
        let result = preflight_user_pages(
            start,
            end,
            write,
            |from, intent| {
                let space = space.borrow();
                let mut page = from;
                while page < end {
                    match classify_user_page(flags_of(space[(page - BASE) / PAGE]), intent) {
                        UserPageState::Ready => {}
                        UserPageState::NotPresent => return Ok(Some(page)),
                        UserPageState::Denied => return Err(SyscallError::EFAULT),
                    }
                    page += PAGE;
                }
                Ok(None)
            },
            |page, intent| {
                probes.borrow_mut().push(page);
                let mut space = space.borrow_mut();
                let slot = &mut space[(page - BASE) / PAGE];
                match *slot {
                    Page::Lazy => *slot = Page::Ready,
                    Page::LazySupervisor => *slot = Page::Supervisor,
                    Page::LazyReadOnly => {
                        *slot = Page::ReadOnly;
                        if intent {
                            return Err(());
                        }
                    }
                    Page::Vanishing => {}
                    Page::Unmapped => return Err(()),
                    present => panic!("probed a present page: {:?}", present),
                }
                Ok(())
            },
        );
        (result, probes.into_inner(), space.into_inner())
    }

    #[test]
    fn page_classification_matches_the_access_contract() {
        let user = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        for write in [false, true] {
            assert_eq!(classify_user_page(None, write), UserPageState::NotPresent);
            assert_eq!(
                classify_user_page(Some(PageTableFlags::USER_ACCESSIBLE), write),
                UserPageState::NotPresent
            );
            assert_eq!(
                classify_user_page(
                    Some(PageTableFlags::PRESENT | PageTableFlags::WRITABLE),
                    write
                ),
                UserPageState::Denied
            );
            assert_eq!(
                classify_user_page(Some(user | PageTableFlags::WRITABLE), write),
                UserPageState::Ready
            );
            assert_eq!(
                classify_user_page(Some(user | PageTableFlags::BIT_9), write),
                UserPageState::Ready
            );
        }
        assert_eq!(classify_user_page(Some(user), false), UserPageState::Ready);
        assert_eq!(classify_user_page(Some(user), true), UserPageState::Denied);
    }

    #[test]
    fn present_pages_are_never_probed() {
        let (result, probes, _) = run(&[Page::Ready; 3], BASE + 0x10, 2 * PAGE, true);
        assert_eq!(result, Ok(()));
        assert!(probes.is_empty());
        // A denied page fails before any later lazy page is touched.
        for denied in [Page::Supervisor, Page::ReadOnly] {
            let pages = [Page::Ready, denied, Page::Lazy];
            let (result, probes, _) = run(&pages, BASE, 3 * PAGE, true);
            assert_eq!(result, Err(SyscallError::EFAULT));
            assert!(probes.is_empty());
        }
    }

    #[test]
    fn lazy_pages_are_resolved_once_at_their_page_base() {
        let pages = [Page::Ready, Page::Lazy, Page::Lazy];
        let (result, probes, space) = run(&pages, BASE + PAGE - 8, PAGE + 16, true);
        assert_eq!(result, Ok(()));
        assert_eq!(probes, [BASE + PAGE, BASE + 2 * PAGE]);
        assert_eq!(space, [Page::Ready; 3]);
        // A buffer starting mid-page probes that page's base word.
        let (result, probes, _) = run(&[Page::Lazy], BASE + 0x123, 4, false);
        assert_eq!(result, Ok(()));
        assert_eq!(probes, [BASE]);
        // The probe count is bounded by the page count.
        let (result, probes, _) = run(&[Page::Lazy; 64], BASE, 64 * PAGE, false);
        assert_eq!(result, Ok(()));
        assert_eq!(probes.len(), 64);
    }

    #[test]
    fn pages_outside_the_range_are_never_probed() {
        let (result, probes, _) = run(&[Page::Ready, Page::Unmapped], BASE, PAGE, true);
        assert_eq!(result, Ok(()));
        assert!(probes.is_empty());
    }

    #[test]
    fn unresolved_or_denied_pages_fail_after_one_probe() {
        for (pages, expected_probes) in [
            ([Page::Lazy, Page::Vanishing, Page::Lazy], 2),
            ([Page::Unmapped, Page::Lazy, Page::Lazy], 1),
            ([Page::LazySupervisor, Page::Lazy, Page::Lazy], 1),
        ] {
            let (result, probes, _) = run(&pages, BASE, 3 * PAGE, true);
            assert_eq!(result, Err(SyscallError::EFAULT));
            assert_eq!(probes.len(), expected_probes);
        }
    }

    #[test]
    fn the_probe_carries_the_requested_access() {
        // A read-only region resolves for a read and stays EFAULT for a write.
        let (result, probes, space) = run(&[Page::LazyReadOnly, Page::Lazy], BASE, 2 * PAGE, false);
        assert_eq!(result, Ok(()));
        assert_eq!(probes, [BASE, BASE + PAGE]);
        assert_eq!(space, [Page::ReadOnly, Page::Ready]);
        let (result, probes, space) = run(&[Page::LazyReadOnly, Page::Lazy], BASE, 2 * PAGE, true);
        assert_eq!(result, Err(SyscallError::EFAULT));
        assert_eq!(probes, [BASE]);
        assert_eq!(space, [Page::ReadOnly, Page::Lazy]);
        // Both callbacks receive the caller's intent on every call.
        for write in [false, true] {
            let seen = RefCell::new(Vec::new());
            let lazy = core::cell::Cell::new(true);
            let result = preflight_user_pages(
                BASE,
                BASE + PAGE,
                write,
                |_, intent| {
                    seen.borrow_mut().push(intent);
                    Ok(lazy.get().then_some(BASE))
                },
                |_, intent| {
                    seen.borrow_mut().push(intent);
                    lazy.set(false);
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
            assert_eq!(seen.into_inner(), [write; 3]);
        }
    }

    #[test]
    fn walker_answers_outside_the_range_fail_closed() {
        let end = BASE + 2 * PAGE;
        for bogus in [BASE - PAGE, end, BASE + 8] {
            let mut probes = 0;
            let result = preflight_user_pages(
                BASE,
                end,
                true,
                |_, _| Ok(Some(bogus)),
                |_, _| {
                    probes += 1;
                    Ok(())
                },
            );
            assert_eq!(result, Err(SyscallError::EFAULT));
            assert_eq!(probes, 0);
        }
    }

    #[test]
    fn probe_user_page_span_covers_exact_pages_and_fails_closed() {
        use super::probe_user_page_span;
        use alloc::vec::Vec;

        // Zero length and arithmetic overflow fail closed without probing.
        let mut count = 0;
        assert_eq!(
            probe_user_page_span(BASE, 0, |_| {
                count += 1;
                Ok(())
            }),
            Err(SyscallError::EFAULT)
        );
        assert_eq!(
            probe_user_page_span(usize::MAX - 8, 16, |_| {
                count += 1;
                Ok(())
            }),
            Err(SyscallError::EFAULT)
        );
        assert_eq!(count, 0);

        // Single-page aligned and unaligned spans probe exactly one page.
        let mut visited = Vec::new();
        assert_eq!(
            probe_user_page_span(BASE + 64, 4, |p| {
                visited.push(p);
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(visited, alloc::vec![BASE]);

        // Unaligned cross-page span probes every intersecting 4 KiB page.
        visited.clear();
        assert_eq!(
            probe_user_page_span(BASE + PAGE - 8, 16, |p| {
                visited.push(p);
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(visited, alloc::vec![BASE, BASE + PAGE]);

        // Probe error aborts immediately and returns EFAULT.
        visited.clear();
        assert_eq!(
            probe_user_page_span(BASE, 3 * PAGE, |p| {
                visited.push(p);
                if p == BASE + PAGE {
                    Err(())
                } else {
                    Ok(())
                }
            }),
            Err(SyscallError::EFAULT)
        );
        assert_eq!(visited, alloc::vec![BASE, BASE + PAGE]);
    }
}

/// 从用户态缓冲区安全复制数据到内核缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// # Arguments
/// * `dest` - 内核缓冲区（目标）
/// * `user_src` - 用户空间缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射返回 EFAULT
pub(super) fn copy_from_user(dest: &mut [u8], user_src: *const u8) -> Result<(), SyscallError> {
    if dest.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_src, dest.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    crate::usercopy::copy_from_user_safe(dest, user_src).map_err(|_| SyscallError::EFAULT)
}

/// 将内核缓冲区的数据安全复制到用户态缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// 注意：COW 页面会在写入时触发页错误，由 COW 处理器创建可写副本。
///
/// # Arguments
/// * `user_dst` - 用户空间缓冲区（目标）
/// * `src` - 内核缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射或不可写返回 EFAULT
// M0 #1 (auxv): widened to pub(crate) so the shared initial-user-stack builder
// (crate::user_stack::build_initial_user_stack) can perform its single bulk copy
// into the target address space. Still kernel_core-internal.
pub(crate) fn copy_to_user(user_dst: *mut u8, src: &[u8]) -> Result<(), SyscallError> {
    if src.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_dst as *const u8, src.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    // COW 页面会在 usercopy 过程中触发 #PF，由 COW 处理器处理
    crate::usercopy::copy_to_user_safe(user_dst, src).map_err(|_| SyscallError::EFAULT)
}

/// C3 (#90): write a TID to a user `pid_t` word (`CLONE_PARENT_SETTID`,
/// `CLONE_CHILD_SETTID`) as one store; see `process::store_user_tid_word`.
pub(super) fn store_user_tid(user_dst: *mut i32, tid: ProcessId) -> Result<(), SyscallError> {
    validate_user_ptr(user_dst as *const u8, mem::size_of::<i32>())?;
    crate::process::store_user_tid_word(user_dst as usize, tid as u32)
        .map_err(|()| SyscallError::EFAULT)
}

/// 从用户空间复制以 '\0' 结尾的 C 字符串到内核缓冲区
///
/// V-2 fix: 使用 usercopy 容错拷贝机制，防止 TOCTOU 攻击。
/// 如果用户在验证后取消映射内存，copy_from_user_safe 会安全返回错误
/// 而不是导致内核 panic。
///
// R164-3 FIX: Fallible String construction from &str. The infallible
// .to_string() panics under OOM via alloc_error_handler. All path
// syscalls (open, stat, openat, fstatat) use this instead.
#[inline]
pub(super) fn try_str_to_string(s: &str) -> Result<String, SyscallError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(s.len())
        .map_err(|_| SyscallError::ENOMEM)?;
    owned.push_str(s);
    Ok(owned)
}

/// 逐字节读取直到遇到 NUL 终止符，限制最大长度防止恶意无限字符串。
pub(super) fn copy_user_cstring(ptr: *const u8) -> Result<Vec<u8>, SyscallError> {
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R160-2 FIX: Pre-reserve capacity for the cstring buffer. The old code
    // used infallible push() per byte, up to MAX_ARG_STRLEN (4096) iterations.
    // Under OOM, any push could trigger alloc_error_handler → kernel panic.
    let mut buf = Vec::new();
    buf.try_reserve(256).map_err(|_| SyscallError::ENOMEM)?;

    for i in 0..=MAX_ARG_STRLEN {
        let mut byte = [0u8; 1];
        let src_addr = (ptr as usize).wrapping_add(i) as *const u8;
        crate::usercopy::copy_from_user_safe(&mut byte, src_addr)
            .map_err(|_| SyscallError::EFAULT)?;

        if byte[0] == 0 {
            return Ok(buf);
        }
        if buf.try_reserve(1).is_err() {
            return Err(SyscallError::ENOMEM);
        }
        buf.push(byte[0]);
    }

    // 字符串超过最大长度限制
    Err(SyscallError::E2BIG)
}

/// 将用户空间的字符串指针数组（以 NULL 结尾）复制到内核
///
/// V-2 fix: 使用 usercopy 容错拷贝机制读取指针数组，防止 TOCTOU 攻击。
///
/// 用于 exec 的 argv 和 envp 参数
pub(super) fn copy_user_str_array(
    list_ptr: *const *const u8,
) -> Result<Vec<Vec<u8>>, SyscallError> {
    // NULL 指针表示空数组
    if list_ptr.is_null() {
        return Ok(Vec::new());
    }

    let word = mem::size_of::<usize>();
    let base = list_ptr as usize;
    // R160-2 FIX: Fallible allocation for argument list. The old infallible
    // push could panic under OOM with up to MAX_ARG_COUNT (256) entries.
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;

    for idx in 0..MAX_ARG_COUNT {
        let entry_addr = base.checked_add(idx * word).ok_or(SyscallError::EFAULT)?;

        let mut raw_ptr = [0u8; core::mem::size_of::<usize>()];
        crate::usercopy::copy_from_user_safe(&mut raw_ptr, entry_addr as *const u8)
            .map_err(|_| SyscallError::EFAULT)?;
        let entry = usize::from_ne_bytes(raw_ptr) as *const u8;

        if entry.is_null() {
            break;
        }

        let s = copy_user_cstring(entry)?;
        total = total.checked_add(s.len() + 1).ok_or(SyscallError::E2BIG)?;
        if total > MAX_ARG_TOTAL {
            return Err(SyscallError::E2BIG);
        }

        items.try_reserve(1).map_err(|_| SyscallError::ENOMEM)?;
        items.push(s);
    }

    // 检查是否超过最大参数数量（没有遇到 NULL 终止）
    if items.len() == MAX_ARG_COUNT {
        return Err(SyscallError::E2BIG);
    }

    Ok(items)
}

// ============================================================================
// 内存管理系统调用
// ============================================================================

/// 页大小
pub(super) const PAGE_SIZE: usize = 0x1000;

// ST-K2: mmap flag values and the supported private/shared-anonymous shapes.
// Keep these values in one place so the syscall, its oracle, and the userspace
// ABI agree on the fail-closed boundary. R192-RES-3: `addr != 0` is a hint
// that falls back to automatic placement when it cannot be used, and
// MAP_FIXED_NOREPLACE places exactly or fails; MAP_FIXED replacement is
// deliberately not enabled, alone or combined.
pub(super) const MAP_SHARED: i32 = 0x01;
pub(super) const MAP_PRIVATE: i32 = 0x02;
pub(super) const MAP_FIXED: i32 = 0x10;
pub(super) const MAP_ANONYMOUS: i32 = 0x20;
pub(super) const MAP_POPULATE: i32 = 0x8000;
pub(super) const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
pub(super) const MAP_SHARED_VALIDATE: i32 = 0x03;
pub(super) const SUPPORTED_MMAP_FLAGS: i32 = MAP_PRIVATE | MAP_ANONYMOUS;
pub(super) const SUPPORTED_SHARED_MMAP_FLAGS: i32 = MAP_SHARED | MAP_ANONYMOUS;

/// The mapping a supported flag word asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MmapShape {
    pub(super) shared: bool,
    /// `MAP_FIXED_NOREPLACE`: exactly at `addr`, or fail.
    pub(super) exact: bool,
    /// `MAP_POPULATE`: eagerly back private anonymous pages before returning.
    pub(super) populate: bool,
}

#[inline]
pub(super) fn validate_mmap_flags(flags: i32) -> Result<MmapShape, SyscallError> {
    let exact = flags & MAP_FIXED_NOREPLACE != 0;
    let populate = flags & MAP_POPULATE != 0;
    match flags & !(MAP_FIXED_NOREPLACE | MAP_POPULATE) {
        SUPPORTED_MMAP_FLAGS => Ok(MmapShape {
            shared: false,
            exact,
            populate,
        }),
        SUPPORTED_SHARED_MMAP_FLAGS if !populate => Ok(MmapShape {
            shared: true,
            exact,
            populate: false,
        }),
        _ => Err(SyscallError::EOPNOTSUPP),
    }
}

/// ST-K2-P1: pure flag contract oracle used by the hosted/integration gates.
/// The production path invokes the same validator after the LSM hook, before
/// any address-space state is changed.
pub fn run_mmap_flags_self_test() {
    for (flags, shared, exact, populate) in [
        (MAP_PRIVATE | MAP_ANONYMOUS, false, false, false),
        (
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
            false,
            false,
            true,
        ),
        (MAP_SHARED | MAP_ANONYMOUS, true, false, false),
        (
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            false,
            true,
            false,
        ),
        (
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE,
            false,
            true,
            true,
        ),
        (
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            true,
            true,
            false,
        ),
    ] {
        assert_eq!(
            validate_mmap_flags(flags),
            Ok(MmapShape {
                shared,
                exact,
                populate,
            }),
            "supported mmap flags: {flags:#x}"
        );
    }
    for flags in [
        0,
        MAP_PRIVATE,
        MAP_SHARED,
        MAP_SHARED_VALIDATE,
        MAP_FIXED_NOREPLACE,
        MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
        MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        MAP_PRIVATE | MAP_ANONYMOUS | 0x4000,
        -1,
    ] {
        assert_eq!(
            validate_mmap_flags(flags),
            Err(SyscallError::EOPNOTSUPP),
            "unsupported mmap flags must fail closed: {flags:#x}"
        );
    }
    // R192-RES-3: what each placement arm does with a range it cannot use.
    use MmapRangeError::{BelowMin, Corrupt, Occupied, PastTop, Unaligned};
    for (arm, error, expected) in [
        (MmapArm::Auto, PastTop, Some(SyscallError::EFAULT)),
        (MmapArm::Auto, Unaligned, Some(SyscallError::EINVAL)),
        (MmapArm::Auto, BelowMin, Some(SyscallError::EPERM)),
        (MmapArm::Auto, Occupied, Some(SyscallError::EINVAL)),
        (MmapArm::Auto, Corrupt, Some(SyscallError::EFAULT)),
        (MmapArm::Hint, PastTop, None),
        (MmapArm::Hint, Unaligned, None),
        (MmapArm::Hint, BelowMin, None),
        (MmapArm::Hint, Occupied, None),
        (MmapArm::Hint, Corrupt, Some(SyscallError::EFAULT)),
        (MmapArm::Exact, PastTop, Some(SyscallError::ENOMEM)),
        (MmapArm::Exact, Unaligned, Some(SyscallError::EINVAL)),
        (MmapArm::Exact, BelowMin, Some(SyscallError::EPERM)),
        (MmapArm::Exact, Occupied, Some(SyscallError::EEXIST)),
        (MmapArm::Exact, Corrupt, Some(SyscallError::EFAULT)),
    ] {
        assert_eq!(
            mmap_range_errno(arm, error),
            expected,
            "{arm:?} placement of a {error:?} range"
        );
    }
    assert_ne!(MAP_FIXED, 0);
}

// ST-K2-MREMAP: mremap flag values and the supported relocation shape.
// Only "resize this VMA, moving it if you must" is supported. The address
// replacement surface (MREMAP_FIXED) is deliberately not enabled, mirroring
// the MAP_FIXED boundary above: enabling it here would offer a strictly wider
// capability than the mmap ABI this kernel exposes.
pub(super) const MREMAP_MAYMOVE: i32 = 0x1;
pub(super) const MREMAP_FIXED: i32 = 0x2;
#[allow(dead_code)]
pub(super) const MREMAP_DONTUNMAP: i32 = 0x4;

/// ST-K2-MREMAP: whole-flags contract for `sys_mremap`.
///
/// `0` (in-place only) and `MREMAP_MAYMOVE` are the implemented shapes.
/// `MREMAP_FIXED`, `MREMAP_DONTUNMAP`, any unknown bit and any negative word
/// are rejected before the VMA/page-table/cgroup transaction begins, so an
/// unsupported request can never leave partial state behind.
#[inline]
pub(super) fn validate_mremap_flags(flags: i32) -> Result<(), SyscallError> {
    if flags == 0 || flags == MREMAP_MAYMOVE {
        Ok(())
    } else {
        Err(SyscallError::EOPNOTSUPP)
    }
}

/// ST-K2-MREMAP: pure flag contract oracle used by the integration gate.
/// The production path invokes the same validator before any address-space
/// state is read or changed.
pub fn run_mremap_flags_self_test() {
    assert!(
        validate_mremap_flags(0).is_ok(),
        "in-place mremap is supported"
    );
    assert!(
        validate_mremap_flags(MREMAP_MAYMOVE).is_ok(),
        "MREMAP_MAYMOVE is supported"
    );
    for flags in [
        MREMAP_FIXED,
        MREMAP_DONTUNMAP,
        MREMAP_MAYMOVE | MREMAP_FIXED,
        MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
        0x8,
        0x4000,
        -1,
    ] {
        assert_eq!(
            validate_mremap_flags(flags),
            Err(SyscallError::EOPNOTSUPP),
            "unsupported mremap flags must fail closed: {flags:#x}"
        );
    }
    // The address-replacement flag stays distinct from MAYMOVE; enabling one
    // must never be read as enabling the other.
    assert_ne!(MREMAP_FIXED & MREMAP_MAYMOVE, MREMAP_FIXED);
}

/// ST-K2-MREMAP: where a growing mapping goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MremapPlacement {
    /// Grow at the existing base; the free-VA probe already succeeded.
    InPlace,
    /// Relocate to a newly chosen base (`MREMAP_MAYMOVE`).
    Relocate,
    /// No free space above the mapping and relocation is not permitted.
    Refuse,
}

/// ST-K2-MREMAP: pure placement decision for a growing mapping.
///
/// Relocation is licensed only by `MREMAP_MAYMOVE`; without it an in-place
/// failure is `ENOMEM`, never a silent move.
#[inline]
pub(crate) fn decide_mremap_placement(in_place_free: bool, may_move: bool) -> MremapPlacement {
    if in_place_free {
        MremapPlacement::InPlace
    } else if may_move {
        MremapPlacement::Relocate
    } else {
        MremapPlacement::Refuse
    }
}

/// ST-K2-MREMAP: the byte delta a resize moves between two page-aligned
/// lengths — `Some((grows, bytes))`, or `None` for an equal-size (no-op)
/// resize.  This is the single source of the charge/uncharge magnitude, so a
/// shrink cannot uncharge fewer bytes than the grow charged.
#[inline]
pub(crate) fn mremap_byte_delta(old_len: usize, new_len: usize) -> Option<(bool, usize)> {
    if new_len == old_len {
        None
    } else if new_len > old_len {
        Some((true, new_len - old_len))
    } else {
        Some((false, old_len - new_len))
    }
}

/// ST-K2-MREMAP: the byte length this call must newly materialize, or `None`
/// when the resize has no growth tail.
///
/// A shrink has no tail.  Naively computing `new_len - old_len` there
/// underflows: in a release build it wraps to a colossal page count and drives
/// the fault allocator into OOM before the call fails.  That defect was found by
/// the Ring-3 guest oracle and is pinned here so it cannot return silently.
#[inline]
pub(crate) fn mremap_tail_len(old_len: usize, new_len: usize) -> Option<usize> {
    new_len.checked_sub(old_len).filter(|len| *len != 0)
}

/// LEAD-MREMAP-MIGRATE-1: bytes of a growing `mremap`'s in-flight
/// `mmap_regions` entries that carry no charge.  Phase 1 reserves
/// `reserved_len` (the tail in place, the whole new length for a move) while
/// the claimed source keeps counting its length, but charges only the tail,
/// and nothing for a PROT_NONE mapping (whose source does not count either).
#[inline]
pub(crate) fn mremap_uncharged_reserve(
    reserved_len: usize,
    tail_len: usize,
    prot_none: bool,
) -> usize {
    if prot_none {
        reserved_len
    } else {
        reserved_len.saturating_sub(tail_len)
    }
}

/// ST-K2-MREMAP: pure oracle for the resize decision logic and the page-flag
/// reconstruction the live path uses.
///
/// The grow/shrink/relocate *page-table and refcount* legs need a live user
/// address space (a real CR3 plus `MmState`), which the boot integration gate
/// has no current process for; they are exercised by the guest runtime gate.
/// Everything here is the SAME code the syscall runs, not a restatement of it.
pub fn run_mremap_geometry_self_test() {
    use MremapPlacement::{InPlace, Refuse, Relocate};

    // Placement: in-place wins whenever the VA probe succeeded...
    assert_eq!(decide_mremap_placement(true, false), InPlace);
    assert_eq!(decide_mremap_placement(true, true), InPlace);
    // ...and relocation happens ONLY when the caller asked for it.
    assert_eq!(decide_mremap_placement(false, true), Relocate);
    assert_eq!(
        decide_mremap_placement(false, false),
        Refuse,
        "a grow with no free VA and no MREMAP_MAYMOVE must be refused, never moved"
    );

    // Byte delta: magnitude is symmetric, direction is not.
    assert_eq!(mremap_byte_delta(0x1000, 0x1000), None);
    assert_eq!(mremap_byte_delta(0x1000, 0x3000), Some((true, 0x2000)));
    assert_eq!(mremap_byte_delta(0x3000, 0x1000), Some((false, 0x2000)));

    // Materialization tail: ONLY a grow has one. This is the guard that keeps a
    // shrink from underflowing `new_len - old_len` into a colossal page count.
    assert_eq!(
        mremap_tail_len(0x4000, 0x1000),
        None,
        "a shrink must not report a growth tail"
    );
    assert_eq!(
        mremap_tail_len(0x1000, 0x1000),
        None,
        "an equal-size resize has no tail"
    );
    assert_eq!(mremap_tail_len(0x1000, 0x4000), Some(0x3000));
    assert_eq!(mremap_tail_len(0, 0x1000), Some(0x1000));
    // Round-tripping a resize must not create or destroy charge.
    for &(old_len, new_len) in &[
        (0x1000usize, 0x4000usize),
        (0x4000, 0x1000),
        (0x2000, 0x2000),
        (0x1000, 0x20_0000),
    ] {
        let up = mremap_byte_delta(old_len, new_len);
        let down = mremap_byte_delta(new_len, old_len);
        match (up, down) {
            (None, None) => assert_eq!(old_len, new_len),
            (Some((up_grows, up_bytes)), Some((down_grows, down_bytes))) => {
                assert_eq!(up_grows, !down_grows, "directions must be opposite");
                assert_eq!(
                    up_bytes, down_bytes,
                    "the grow and the matching shrink must move the SAME byte count"
                );
            }
            _ => panic!("asymmetric resize delta for {old_len:#x} -> {new_len:#x}"),
        }
    }

    // Page-flag reconstruction: a grown tail inherits the VMA's protection.
    for &(read, write, exec) in &[
        (true, false, false),
        (true, true, false),
        (true, false, true),
        (false, true, false),
    ] {
        let mut committed = 0usize;
        let mut prot = 0u32;
        if read {
            committed |= MMAP_REGION_FLAG_PROT_READ;
            prot |= PROT_READ as u32;
        }
        if write {
            committed |= MMAP_REGION_FLAG_PROT_WRITE;
            prot |= PROT_WRITE as u32;
        }
        if exec {
            committed |= MMAP_REGION_FLAG_PROT_EXEC;
            prot |= PROT_EXEC as u32;
        }

        // The LSM destination hook must see the mapping's real protection.
        assert_eq!(mmap_flags_to_prot(committed), prot);
        assert_eq!(mmap_flags_to_prot(mmap_prot_to_flags(prot as i32)), prot);

        let flags = mremap_page_flags(committed);
        use x86_64::structures::paging::PageTableFlags as F;
        assert!(flags.contains(F::PRESENT) && flags.contains(F::USER_ACCESSIBLE));
        assert_eq!(flags.contains(F::WRITABLE), write);
        assert_eq!(
            flags.contains(F::NO_EXECUTE),
            !exec,
            "a non-executable mapping must stay NX"
        );
        // W^X holds for every reconstructed tail.
        assert!(
            !(flags.contains(F::WRITABLE) && !flags.contains(F::NO_EXECUTE)),
            "a grown page must never be writable and executable: {flags:?}"
        );
    }

    // The live path never materializes a tail for a PROT_NONE reservation (it
    // grows the VA record only), so this pins the HELPER's robustness rather
    // than a reached path: for any input it must never yield W^X.
    let prot_none_tail = mremap_page_flags(MMAP_REGION_FLAG_PROT_NONE);
    assert!(prot_none_tail.contains(x86_64::structures::paging::PageTableFlags::NO_EXECUTE));
    assert!(!prot_none_tail.contains(x86_64::structures::paging::PageTableFlags::WRITABLE));
}

/// ST-K2-MREMAP hosted oracle: executes the production flag contract, the
/// placement decision and the byte-delta arithmetic on the host target.  The
/// page-table/refcount legs need a live user address space and run only in the
/// guest runtime gate.
#[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
mod mremap_oracle_tests {
    use super::*;

    #[test]
    fn mremap_flags_fail_closed_outside_the_supported_shape() {
        run_mremap_flags_self_test();
    }

    #[test]
    fn mremap_placement_and_byte_delta_are_symmetric() {
        run_mremap_geometry_self_test();
    }
}

/// 页对齐向上取整
#[inline]
pub(super) fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// R121-4 FIX: mmap_regions encodes transient state in the low bits of the
// stored length. All committed lengths are page-aligned (4 KiB), so the
// low 12 bits are available for flags.
//
// Transient (in-flight) flags — cleared when operation completes:
//   PENDING_MAP   — address range reserved, page table mapping in progress
//   PENDING_UNMAP — region marked for removal, page table unmap in progress
//
// Persistent (committed) flags — survive into committed entry:
//   PROT_NONE — pure address reservation, no physical frames allocated/charged
//
// R122-1: Made pub(crate) so fork.rs can check for transient state.
pub(crate) const MMAP_REGION_FLAG_MASK: usize = 0xfff;
pub(crate) const MMAP_REGION_FLAG_PENDING_MAP: usize = 1 << 0;
pub(super) const MMAP_REGION_FLAG_PENDING_UNMAP: usize = 1 << 1;
// R123-1 FIX: Committed flag indicating PROT_NONE reservation (no frames/charge).
// R124-1 FIX: Made pub(crate) so process exit/exec cleanup can skip uncharge for PROT_NONE.
pub(crate) const MMAP_REGION_FLAG_PROT_NONE: usize = 1 << 2;

// R144-2 FIX: Protection bit flags stored in mmap_regions entries so that
// /proc/[pid]/maps can display accurate permissions instead of hardcoded "rw-p".
// Public so that VFS procfs can decode permission strings via mmap_flags_to_perms().
pub const MMAP_REGION_FLAG_PROT_READ: usize = 1 << 3;
pub const MMAP_REGION_FLAG_PROT_WRITE: usize = 1 << 4;
pub const MMAP_REGION_FLAG_PROT_EXEC: usize = 1 << 5;
/// ST-K2-P2: committed shared-anonymous mapping.  Bit 7 is outside the
/// existing transient/protection flags and is preserved across fork.
pub(crate) const MMAP_REGION_FLAG_SHARED: usize = 1 << 7;
/// Lazy private-anonymous demand-paged mapping (`MAP_PRIVATE | MAP_ANONYMOUS`
/// without `MAP_POPULATE`). Absent leaf PTEs inside this VMA are materialized
/// on first access by `handle_private_anon_page_fault`. Preserved across fork
/// and `mprotect` Path C; cleared on `real -> PROT_NONE` demotion.
pub(crate) const MMAP_REGION_FLAG_LAZY_ANON: usize = 1 << 8;
/// Fast-path proof bit: set on a fresh lazy private-anonymous VMA before any
/// page has ever been faulted in or eagerly populated. Cleared under `MmState`
/// lock BEFORE inserting the first PTE (or before growing via `mremap`), so
/// `sys_munmap` can safely skip `PT_LOCK` / page-table walk / TLB shootdown
/// whenever this bit is still set.
pub(crate) const MMAP_REGION_FLAG_UNFAULTED: usize = 1 << 9;
/// R149-6 / R168-1 FIX: Transient ownership token for an mprotect operation
/// that drops the MmState lock for page-table work. Path A (PROT_NONE → real)
/// holds it while allocating + mapping frames; Path B (real → PROT_NONE) holds
/// it while unmapping + freeing frames. Set under the lock before the PT ops
/// and cleared on commit/rollback. Concurrent munmap / mprotect / fork observe
/// it via the transient mask and fail closed (EBUSY / skip / EAGAIN) instead of
/// racing cgroup bookkeeping against the in-flight page-table side effects —
/// preventing both the permanent charge leak (Path A) and the double-uncharge
/// isolation bypass (Path B).
pub(super) const MMAP_REGION_FLAG_PENDING_MPROTECT: usize = 1 << 6;

/// Mask of transient in-flight flags. Only these are stripped on fork/clone;
/// persistent committed flags (e.g. PROT_NONE) are preserved.
pub(crate) const MMAP_REGION_FLAG_TRANSIENT_MASK: usize = MMAP_REGION_FLAG_PENDING_MAP
    | MMAP_REGION_FLAG_PENDING_UNMAP
    | MMAP_REGION_FLAG_PENDING_MPROTECT;

/// D2-MMAP-LIFECYCLE Phase 2: typed newtype for `mmap_regions` VALUES.
///
/// A `#[repr(transparent)]` newtype over the packed `usize` (bits [63:12] =
/// page-aligned length, bits [11:0] = flags — see the encoding contract on
/// `MmState::mmap_regions`). `Copy` + `repr(transparent)` guarantees that the
/// `FallibleOrderedMap<usize, MmapEntry>` backing store (next-phase #11) holds
/// values VERBATIM — bit-identical to the previous packed `usize`. Every
/// method body is written in terms of the existing `MMAP_REGION_FLAG_*`
/// constants, so it is provably bit-equivalent to the prior inline bit-ops.
///
/// This formalizes the transient-state encoding contract (Phase 2): the magic
/// low-bit arithmetic is replaced by named, intention-revealing accessors and
/// constructors, while the on-the-wire representation is unchanged.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::len_without_is_empty)]
pub struct MmapEntry(usize);

#[allow(clippy::len_without_is_empty)]
impl MmapEntry {
    /// Wrap a raw packed word (migration / escape hatch). Identity, bit-identical.
    #[inline]
    pub const fn from_raw(raw: usize) -> Self {
        MmapEntry(raw)
    }

    /// Pack a page-aligned length with a precomputed flag word.
    /// Precondition (same as the prior code): `len` is page-aligned (low 12 bits
    /// zero) and `flags` ⊆ `MMAP_REGION_FLAG_MASK`, so the OR is non-overlapping.
    #[inline]
    pub const fn from_len_flags(len: usize, flags: usize) -> Self {
        MmapEntry(len | flags)
    }

    /// Pure PROT_NONE reservation — `len | PROT_NONE`, NO other flags retained.
    /// Caller MUST pass an already-extracted length (`entry.len()` / `region_len`),
    /// never a raw packed word, or stale flag/length bits would leak in.
    #[inline]
    pub const fn prot_none(len: usize) -> Self {
        MmapEntry(len | MMAP_REGION_FLAG_PROT_NONE)
    }

    /// The raw packed word.
    #[inline]
    pub const fn raw(self) -> usize {
        self.0
    }

    /// Page-aligned length (all flag bits stripped). Equals the old `mmap_region_len`.
    #[inline]
    pub const fn len(self) -> usize {
        self.0 & !MMAP_REGION_FLAG_MASK
    }

    /// Low-12 flag bits — the FULL `& 0xfff` committed-flags capture (NOT a
    /// transient-stripped or persistent-only subset).
    #[inline]
    pub const fn flags(self) -> usize {
        self.0 & MMAP_REGION_FLAG_MASK
    }

    /// PROT_NONE (bit 2): pure reservation, no physical frames charged.
    #[inline]
    pub const fn is_prot_none(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_NONE != 0
    }

    /// Individual POSIX prot-bit accessors (bits 3/4/5).
    #[inline]
    pub const fn prot_read(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_READ != 0
    }
    #[inline]
    pub const fn prot_write(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_WRITE != 0
    }
    #[inline]
    pub const fn prot_exec(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_EXEC != 0
    }

    #[inline]
    pub const fn is_shared(self) -> bool {
        self.0 & MMAP_REGION_FLAG_SHARED != 0
    }

    #[inline]
    pub const fn is_lazy_anon(self) -> bool {
        self.0 & MMAP_REGION_FLAG_LAZY_ANON != 0
    }

    #[inline]
    pub const fn is_unfaulted(self) -> bool {
        self.0 & MMAP_REGION_FLAG_UNFAULTED != 0
    }

    #[inline]
    pub fn clear_unfaulted(&mut self) {
        self.0 &= !MMAP_REGION_FLAG_UNFAULTED;
    }

    /// 4-char Linux-style "rwxp"/"rwxs" permission string for /proc/[pid]/maps.
    /// Shared-anonymous entries use `s`; private entries use `p`.
    #[inline]
    pub fn perms(self) -> [u8; 4] {
        [
            if self.prot_read() { b'r' } else { b'-' },
            if self.prot_write() { b'w' } else { b'-' },
            if self.prot_exec() { b'x' } else { b'-' },
            if self.is_shared() { b's' } else { b'p' },
        ]
    }

    /// Any transient in-flight flag (PENDING_MAP|PENDING_UNMAP|PENDING_MPROTECT) set.
    #[inline]
    pub const fn has_transient(self) -> bool {
        self.0 & MMAP_REGION_FLAG_TRANSIENT_MASK != 0
    }

    /// Raw transient subset (for debug validation).
    #[inline]
    pub const fn transient_flags(self) -> usize {
        self.0 & MMAP_REGION_FLAG_TRANSIENT_MASK
    }

    /// PENDING_MPROTECT (bit 6) ownership-token test (R149-6 / R164-2 race guard).
    #[inline]
    pub const fn is_pending_mprotect(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PENDING_MPROTECT != 0
    }

    /// Set PENDING_MPROTECT in place. FAITHFUL to the prior bare
    /// `*entry |= MMAP_REGION_FLAG_PENDING_MPROTECT` (no pre-clear of other
    /// transient bits) — bit-identical regardless of preconditions.
    #[inline]
    pub fn set_pending_mprotect(&mut self) {
        self.0 |= MMAP_REGION_FLAG_PENDING_MPROTECT;
    }

    /// Clear PENDING_MPROTECT in place, preserving every other bit.
    #[inline]
    pub fn clear_pending_mprotect(&mut self) {
        self.0 &= !MMAP_REGION_FLAG_PENDING_MPROTECT;
    }

    /// Arm PENDING_UNMAP (munmap Phase-1 marker). FAITHFUL literal OR — matches
    /// `recorded_length | committed_flags | PENDING_UNMAP` (committed_flags is
    /// transient-free at the only call site, guarded by `has_transient`).
    #[inline]
    pub const fn with_pending_unmap(self) -> Self {
        MmapEntry(self.0 | MMAP_REGION_FLAG_PENDING_UNMAP)
    }

    /// mprotect Path A "preserved" flags: committed flags minus
    /// PROT_NONE | PROT_RWX | PENDING_MPROTECT (mask `!0x7c`).
    #[inline]
    pub const fn committed_flags_excluding_prot(self) -> usize {
        (self.0 & MMAP_REGION_FLAG_MASK)
            & !(MMAP_REGION_FLAG_PROT_NONE
                | MMAP_REGION_FLAG_PROT_READ
                | MMAP_REGION_FLAG_PROT_WRITE
                | MMAP_REGION_FLAG_PROT_EXEC
                | MMAP_REGION_FLAG_PENDING_MPROTECT)
    }

    /// mprotect Path D in-place display-bit sync: clear exactly R|W|X (0x38),
    /// OR the new prot bits, leaving length + PROT_NONE + transient bits untouched.
    #[inline]
    pub fn rewrite_prot_bits(&mut self, new_prot_flags: usize) {
        let prot_mask =
            MMAP_REGION_FLAG_PROT_READ | MMAP_REGION_FLAG_PROT_WRITE | MMAP_REGION_FLAG_PROT_EXEC;
        self.0 = (self.0 & !prot_mask) | new_prot_flags;
    }

    /// Fork transient-strip: clear PENDING_* (bits 0,1,6), preserve PROT_* + length.
    /// PRESERVING PROT_NONE (bit 2) is load-bearing for the child's cgroup-charge skip.
    #[inline]
    pub const fn fork_stripped(self) -> Self {
        MmapEntry(self.0 & !MMAP_REGION_FLAG_TRANSIENT_MASK)
    }

    /// Debug invariant check: page-aligned length + at most one transient flag.
    #[inline]
    pub fn debug_validate(self) {
        if cfg!(debug_assertions) {
            let length = self.len();
            debug_assert!(
                length & (PAGE_SIZE - 1) == 0,
                "mmap_regions: length {:#x} is not page-aligned",
                length,
            );
            let transient = self.transient_flags();
            debug_assert!(
                transient == 0
                    || transient == MMAP_REGION_FLAG_PENDING_MAP
                    || transient == MMAP_REGION_FLAG_PENDING_UNMAP
                    || transient == MMAP_REGION_FLAG_PENDING_MPROTECT,
                "mmap_regions: multiple transient flags set: {:#x}",
                transient,
            );
        }
    }
}

/// Extract the actual page-aligned length from an mmap_regions entry.
/// Thin shim over [`MmapEntry::len`] (retained so existing call sites that pass
/// the entry value compile unchanged after the newtype migration).
#[inline]
pub(crate) fn mmap_region_len(entry: MmapEntry) -> usize {
    entry.len()
}

// D2-MMAP-LIFECYCLE: Validation helper for mmap_regions entries (debug builds).
// Thin shim over [`MmapEntry::debug_validate`].
#[inline]
pub(crate) fn debug_validate_mmap_entry(entry: MmapEntry) {
    entry.debug_validate();
}

/// R144-2 FIX: Encode POSIX prot bits (PROT_READ/WRITE/EXEC) into mmap region
/// flags for storage in `mmap_regions`.  Used by `generate_maps()` in procfs
/// to display accurate permission strings.
#[inline]
pub(super) fn mmap_prot_to_flags(prot: i32) -> usize {
    let mut flags = 0usize;
    if prot & PROT_READ != 0 {
        flags |= MMAP_REGION_FLAG_PROT_READ;
    }
    if prot & PROT_WRITE != 0 {
        flags |= MMAP_REGION_FLAG_PROT_WRITE;
    }
    if prot & PROT_EXEC != 0 {
        flags |= MMAP_REGION_FLAG_PROT_EXEC;
    }
    flags
}

/// R144-2: Decode mmap region flags back to a 4-char Linux-style permission
/// string ("rwxp"/"rwxs"/etc.).
pub fn mmap_flags_to_perms(flags: usize) -> [u8; 4] {
    [
        if flags & MMAP_REGION_FLAG_PROT_READ != 0 {
            b'r'
        } else {
            b'-'
        },
        if flags & MMAP_REGION_FLAG_PROT_WRITE != 0 {
            b'w'
        } else {
            b'-'
        },
        if flags & MMAP_REGION_FLAG_PROT_EXEC != 0 {
            b'x'
        } else {
            b'-'
        },
        if flags & MMAP_REGION_FLAG_SHARED != 0 {
            b's'
        } else {
            b'p'
        },
    ]
}

/// R165-1/R165-2 FIX (D2-MM-BRK-RESV): RAII reservation that serializes
/// concurrent `brk()` operations on a shared `MmState`.
///
/// `sys_brk` drops the `MmState` lock across irreversible page-table work
/// (frame alloc/free, map/unmap) because that work acquires the page-table
/// manager and frame-allocator locks — never `MmState` — so holding `MmState`
/// across it would invert the established lock order. The previous post-hoc
/// `mm.brk == old_brk` re-check could only *detect* a racing sibling `brk()`,
/// not undo the page-table side effects already committed. This guard instead
/// *prevents* the race: while held, `brk_in_progress` is set and every other
/// `brk()` on the shared address space returns the current break unchanged, so
/// `mm.brk` cannot move and the lock-dropped PT work stays consistent with the
/// eventual commit.
///
/// The flag is cleared on `Drop`, which covers every early-return / error path.
/// The normal commit path clears it under the same `MmState` lock it already
/// holds and then disarms the guard. `Drop` only ever runs at `sys_brk` scope
/// exit — after every inner `mm_arc.lock()` scope has ended — so re-locking
/// `MmState` here cannot self-deadlock.
pub(super) struct BrkReservation {
    pub(super) mm: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>>,
    pub(super) armed: bool,
}

impl Drop for BrkReservation {
    fn drop(&mut self) {
        if self.armed {
            // R172-16: clear the brk-grow VA reservation together with brk_in_progress on
            // EVERY early-return / error path. (The clean commit disarms this guard and
            // clears both fields explicitly under its own MmState lock, so Drop is the
            // catch-all for the abort paths only.)
            let mut mm = self.mm.lock();
            mm.brk_in_progress = false;
            mm.brk_grow_resv_lo = 0;
            mm.brk_grow_resv_hi = 0;
        }
    }
}

/// M0-7 item7 SLICE 4: RAII reservation serializing `try_grow_user_stack` against
/// sibling grows, fork, and cgroup migration — the stack-lane twin of
/// `BrkReservation`. While `armed`, `MmState.stack_grow_in_progress` is set; the
/// grow drops the Process lock across the irreversible page-table work, so this
/// guard guarantees the flag is cleared on EVERY abort / early-return path (a bad
/// floor, a cgroup-charge reject, a map-failure rollback). The clean commit clears
/// the flag under its own held `MmState` lock and disarms the guard, so `Drop` is
/// the catch-all for the abort paths only. `Drop` runs only at `try_grow_user_stack`
/// scope exit — after every inner `mm_arc.lock()` scope has ended — so re-locking
/// `MmState` here cannot self-deadlock (mirrors `BrkReservation`).
///
/// `stack_grow_pending_bytes` is intentionally NOT cleared here: it is armed and then
/// explicitly subtracted in the SAME arm (commit or rollback) with no early-return in
/// between, exactly like `brk_pending_growth` — so the guard never needs to undo it.
pub(super) struct StackGrowReservation {
    pub(super) mm: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>>,
    pub(super) armed: bool,
}

impl Drop for StackGrowReservation {
    fn drop(&mut self) {
        if self.armed {
            self.mm.lock().stack_grow_in_progress = false;
        }
    }
}

/// sys_brk - 改变数据段大小（堆管理）
///
/// # Arguments
///
/// * `addr` - 新的 program break 地址，0 表示查询当前值
///
/// # Returns
///
/// 成功返回新的 brk 值，失败返回旧的 brk 值（符合 Linux 语义）
///
/// # Behavior
///
/// - brk(0) 返回当前 program break
/// - brk(addr < brk_start) 返回当前 brk（拒绝缩小到起始点以下）
/// - brk(addr > current) 扩展堆，分配匿名页
/// - brk(addr < current) 收缩堆，释放页面
pub(super) fn sys_brk(addr: usize) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1040); // sys_brk entry
    }

    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    let mut proc = process.lock();
    // D3-ARC-MM-SHARED: Clone mm Arc before dropping process lock for PT ops.
    let mm_arc = Arc::clone(&proc.mm);

    // 查询模式：返回当前 brk
    if addr == 0 {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1041); // sys_brk query path
        }
        return Ok(mm_arc.lock().brk);
    }

    // F.2 Cgroup: Cache cgroup_id for memory accounting
    let cgroup_id = proc.cgroup_id;

    // R131-1 FIX: Use lsm_process_ctx_from() instead of ProcessCtx::from_current()
    // to avoid deadlock. from_current() calls current_credentials() which re-acquires
    // the same Process mutex we already hold → deterministic self-deadlock.
    let ctx = lsm_process_ctx_from(&proc)?;
    if lsm::hook_memory_brk(&ctx, addr as u64).is_err() {
        return Err(SyscallError::EPERM);
    }

    // D3-ARC-MM-SHARED: Lock mm once for validation + setup phase.
    // R165-1/R165-2 FIX: Read old_brk AND acquire the brk reservation under the
    // SAME lock acquisition, so no sibling brk() can change mm.brk between the
    // read and the reservation. While `brk_resv` is held (brk_in_progress=true),
    // mm.brk is pinned to old_brk until this call commits, making the existing
    // post-PT re-checks provably true rather than best-effort recovery.
    //
    // R174-B4 FIX: Merge mmap overlap check and VA reservation arming into this
    // SAME lock acquisition. The previous code checked mmap overlap in a SECOND
    // lock (lines 9481-9503), creating a TOCTOU window where a CLONE_VM sibling's
    // sys_mmap could place a mapping after the first lock but before the reservation
    // was armed, leading to double VMA ownership (brk-grow adopts mmap's pages).
    // By doing check+arm atomically under ONE lock, sys_mmap's Phase-1 overlap
    // check (which also takes mm.lock()) is guaranteed to see EITHER the armed
    // reservation (rejects with EINVAL) OR an unarmed state (proceeds, then this
    // brk's overlap check below detects it and fails). No interleaving possible.
    let (old_brk, old_top, new_top, mut brk_resv) = {
        let mut mm = mm_arc.lock();
        // 拒绝缩小到 brk_start 以下
        if addr < mm.brk_start {
            return Ok(mm.brk);
        }
        // 检查用户空间边界
        if addr >= USER_SPACE_TOP {
            return Ok(mm.brk);
        }
        // M0-7 slice 2 (SLICE 1): a brk grow must never enter the reserved user-stack
        // window [stack_base, USER_STACK_TOP) (guard-INCLUSIVE). sys_brk previously bounded
        // ONLY on USER_SPACE_TOP (0x2000 ABOVE the window) — runtime-blind to the stack
        // ceiling the elf_loader OverlapWithStack segment guards already enforce. The
        // page-aligned new break (same `page_align_up(addr)` used to compute new_top below)
        // must not exceed the window base. Refusal contract: return the break UNCHANGED
        // (Linux brk-on-failure semantics), matching the USER_SPACE_TOP arm above.
        if page_align_up(addr) > crate::elf_loader::user_stack_window().0 {
            return Ok(mm.brk);
        }
        // A fork owns the shared metadata→PTE snapshot transaction. Linux
        // brk() reports the unchanged break on this retryable exclusion.
        if mm.fork_in_progress {
            return Ok(mm.brk);
        }
        // A sibling brk() on this shared MmState is mid-flight. Linux brk()
        // returns the current break on failure, so report it unchanged and let
        // the caller retry instead of racing the page tables.
        if mm.brk_in_progress {
            return Ok(mm.brk);
        }

        let old_brk_val = mm.brk;
        let old_top_val = page_align_up(mm.brk);
        let new_top_val = page_align_up(addr);

        // R174-B4 FIX: If this is a grow operation, check mmap overlap and arm
        // the VA reservation ATOMICALLY under this SAME lock, before setting
        // brk_in_progress. This closes the TOCTOU window where a CLONE_VM sibling's
        // sys_mmap could race between the old two-lock sequence.
        if new_top_val > old_top_val {
            // Check for overlap with existing mmap regions
            for (&region_base, &region_len_with_flags) in mm.mmap_regions.iter() {
                let region_end = region_base.saturating_add(mmap_region_len(region_len_with_flags));
                if old_top_val < region_end && new_top_val > region_base {
                    // Overlap detected - return current brk unchanged (Linux semantics)
                    return Ok(old_brk_val);
                }
            }
            // R192-2/R192-3 FIX (D0-ISO-1): the heap starts in the ELF window
            // (4-6 MiB) and the identity map's supervisor 2 MiB leaves begin
            // right above it. The grow loop used to skip their present pages as
            // "already mapped", adopting kernel leaves into the heap (a later
            // shrink unmapped them) and walking up to 4 GiB of identity pages
            // under PT_LOCK with interrupts off. Refuse a grow that reaches any
            // translation the VMA check above did not account for (kernel
            // leaves, ELF pages): unchanged break, as for an overlap.
            if mm::page_table::first_occupied_user_page(
                old_top_val as u64,
                (new_top_val - old_top_val) as u64,
            )
            .is_some()
            {
                return Ok(old_brk_val);
            }
            // R172-16 + R174-B4: No overlap detected; arm the VA reservation atomically.
            // sys_mmap's Phase-1 overlap check will reject any [base,end) intersecting
            // this reservation, preventing double VMA ownership.
            mm.brk_grow_resv_lo = old_top_val;
            mm.brk_grow_resv_hi = new_top_val;
        }

        mm.brk_in_progress = true;
        (
            old_brk_val,
            old_top_val,
            new_top_val,
            BrkReservation {
                mm: Arc::clone(&mm_arc),
                armed: true,
            },
        )
    };

    // 堆扩展
    if new_top > old_top {
        let grow_size = new_top - old_top;

        // R174-B4 FIX: The mmap overlap check and VA reservation arming have been
        // moved into the first lock acquisition above (lines 9431-9508) to make
        // check+arm atomic. This eliminates the TOCTOU window where a CLONE_VM
        // sibling's sys_mmap could place a mapping between the two locks.
        // The redundant second lock block has been removed.

        // F.2 Cgroup: Charge memory before heap expansion.
        // R169-1 FIX (CRITICAL self-deadlock): Reuse the `cgroup_id` cached at
        // the top of sys_brk instead of re-locking the Process mutex here. The
        // `proc` guard acquired at function entry is held CONTINUOUSLY until
        // `drop(proc)` below (only the separate `mm` lock is taken/released in
        // between — never the Process lock), and every cgroup-migration path
        // (sys_cgroup_attach and the cgroupfs task-move) takes that same Process
        // lock before it writes `proc.cgroup_id`. No migration can therefore
        // occur in this window, so the cached value is provably
        // current. The prior R162-12 `process.lock()` re-acquired the
        // already-held, non-reentrant `spin::Mutex` on the SAME CPU →
        // deterministic self-deadlock on every paging brk() growth (the common
        // glibc-malloc path). Any genuinely-fresh post-PT read must happen only
        // AFTER `drop(proc)`, mirroring the shrink (6791) and rollback (6682)
        // paths which re-read only once the guard is released.
        if cgroup::try_charge_memory(cgroup_id, grow_size as u64).is_err() {
            return Ok(old_brk); // Quota exceeded, return current brk
        }

        // R144-1 FIX: Record the pending brk growth so that
        // compute_cgroup_charged_bytes() includes it even though brk
        // hasn't been updated yet. This closes the TOCTOU window where
        // cgroup migration could read stale brk during the lock drop.
        // R163-9 FIX: Use saturating_add instead of overwrite to prevent
        // concurrent CLONE_VM sys_brk calls from clobbering each other's
        // pending growth (same pattern as R162-3 for mprotect_pending_bytes).
        {
            let mut mm = mm_arc.lock();
            mm.brk_pending_growth = mm.brk_pending_growth.saturating_add(grow_size as u64);
        }

        // 释放 Process 锁后进行映射操作
        drop(proc);

        // R192-RES-2: populate the grow in bounded holds (frames allocated and
        // zeroed with no lock held, at most POPULATE_CHUNK_PAGES pages per
        // PT_LOCK hold, a fatal signal aborts between chunks). R192-3: every heap
        // page is backed eagerly, so the driver refuses a grow larger than the
        // free frames before the first allocation instead of draining the
        // allocator and rolling back. Phase 1 proved the window empty and the
        // reservation keeps it so: a page `map_page` finds occupied fails the
        // grow (unchanged break) instead of being adopted into the heap.
        // M2-1 SLICE-4b: the populator records the intermediate PT/PD/PDPT frames
        // for the Step-3 charge + ledger fold; DATA frames are not recorded.
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;
        let map_result =
            EagerPopulator::new("brk", &process, old_top, grow_size / PAGE_SIZE, flags).run();

        // M2-1 SLICE-4b: bind the recorded PT-frame identities on success.
        let pt_frames = match map_result {
            Err(failed) => {
                // 分配失败，返回旧值并回滚内存计费
                // R144-1 FIX: Clear brk_pending_growth under lock BEFORE
                // uncharging, and use the *current* cgroup_id (migration may
                // have changed it while we held no lock).  Clearing pending
                // first prevents a concurrent sys_cgroup_attach from migrating
                // a charge that is about to be rolled back.
                let rollback_cgroup_id = {
                    let proc = process.lock();
                    // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
                    let mut mm = mm_arc.lock();
                    mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
                    // R192-RES-2: settle the rolled-back grow's tables under this
                    // same hold (free-after-remove; see FailedPopulate).
                    failed.settle(&mut mm, proc.cgroup_id);
                    proc.cgroup_id
                };
                cgroup::uncharge_memory(rollback_cgroup_id, grow_size as u64);
                drop(failed);
                // brk reports failure, a fatal signal included, as the old break.
                return Ok(old_brk);
            }
            Ok(frames) => frames,
        };
        // M2-1 SLICE-4b: the PT-frame charge is exactly the recorded PT/PD/PDPT frame
        // count (DATA frames went through allocate_data_frame, unrecorded).
        let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

        // D3-ARC-MM-SHARED: Update brk and charge counters in shared MmState.
        // R162-2 FIX: Re-verify mm.brk == old_brk at commit.
        // M2-1 SLICE-4b: hold BOTH the Process and MmState locks across the PT-frame
        // charge fold (canonical Process -> MmState order, exactly like sys_mmap Phase-3
        // and mprotect Path-A Step-3). cgroup migration snapshots
        // compute_cgroup_charged_bytes — which folds pt_charged_bytes — under the Process
        // lock (R155-5), so charging under mm-only would race sys_cgroup_attach and
        // strand the PT charge on a stale cgroup. `proc` (the entry guard) was dropped
        // before the lock-free PT work; this re-acquires a fresh Process lock — no
        // self-deadlock (the PT work ran with no Process lock held).
        {
            let proc = process.lock();
            let mut mm = mm_arc.lock();
            if mm.brk != old_brk {
                // DEAD under the brk reservation: brk_in_progress pins mm.brk to old_brk
                // for the whole lock-dropped window (a sibling brk early-returns on the
                // brk_in_progress guard; exec rejects shared-VM; fork is EAGAIN mid-brk).
                // Retained as R162-2 defense-in-depth — charge NOTHING for PT (Template-C
                // ride-to-teardown, over-count-safe) and uncharge only the stale DATA
                // growth. Capture brk + cgroup_id BEFORE drop(mm) (no second MmState
                // lock); do NOT disarm brk_resv (let BrkReservation::Drop clear the flag).
                debug_assert!(
                    false,
                    "brk moved under reservation — impossible (brk_in_progress pins it)"
                );
                // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
                mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
                let current_brk = mm.brk;
                let rollback_cgroup_id = proc.cgroup_id;
                drop(mm);
                cgroup::uncharge_memory(rollback_cgroup_id, grow_size as u64);
                return Ok(current_brk);
            }
            mm.brk = addr;
            // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
            mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(grow_size as u64);
            // M2-1 SLICE-4b: SOFT/forced PT-frame kmem charge, after-the-fact (the PT
            // count is knowable only after map_page ran — IM-15), migration-atomic under
            // this Process+MmState hold. record_pt_charge does the per-AS frame-identity
            // ledger insert + INVARIANT-I' bookkeeping (with OOM fallback to
            // pt_inherited_bytes). charge_memory_forced/uncharge_memory take only
            // CGROUP_REGISTRY + atomics (never Process/MmState), so this is deadlock-free
            // under the held locks (same as sys_mmap Phase-3). The live tables reclaim via
            // the 4c shrink prune+reconcile or last-exit teardown.
            if pt_bytes > 0 {
                cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
                mm.record_pt_charge(&pt_frames);
            }
            // R165-1/R165-2 FIX: release the brk reservation under the commit lock.
            // R172-16: also clear the brk-grow VA reservation here — the commit disarms
            // brk_resv, so its Drop will NOT run; clear both fields explicitly.
            mm.brk_in_progress = false;
            mm.brk_grow_resv_lo = 0;
            mm.brk_grow_resv_hi = 0;
            brk_resv.armed = false;
        }

        // D3-ARC-MM-SHARED: sync_vm_siblings_brk is no longer needed — all
        // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

        Ok(addr)
    }
    // 堆收缩
    else if new_top < old_top {
        let shrink_size = old_top - new_top;

        // 释放锁后进行解映射操作
        drop(proc);

        // R126-1 FIX: 3-phase unmap matching sys_munmap() pattern for COW safety
        // M2-1 SLICE-4c: the closure now ALSO yields the reclaimed empty PT/PD TABLE
        // frames (NOT freed here) so the folded commit below can remove them from the
        // per-AS ledger BEFORE they are published to the buddy (free-after-remove),
        // mirroring sys_munmap Phase-2/3. This pairs with SLICE-4b: a brk-grown ledgered
        // PT frame is now debited here on shrink instead of riding to teardown.
        // SAFETY: the brk reservation pins this range in the current address
        // space. with_current_manager holds PT_LOCK; removed leaves are flushed
        // on all participating CPUs before any last-reference frame is freed.
        let table_frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame> = unsafe {
            use x86_64::structures::paging::PhysFrame;
            with_current_manager(VirtAddr::new(0), |manager| -> alloc::vec::Vec<PhysFrame> {
                let mut frame_alloc = FrameAllocator::new();
                // R159-2 + Issue #109 §1.1 (H1): collect ALL unmapped leaf frames first,
                // complete the cross-CPU TLB shootdown BEFORE releasing PAGE_REF_COUNT,
                // and only then decrement refcounts and free last-reference frames.
                // Releasing before flush under split PT_LOCK would allow a peer AS to
                // claim unique COW ownership or free a frame while a sibling CPU still
                // holds a stale TLB entry.
                let mut unmapped_frames = Vec::new();
                let _ = unmapped_frames.try_reserve(shrink_size / PAGE_SIZE);

                #[cfg(feature = "syscall_test")]
                let flushes_before = mm::tlb_shootdown::get_stats();
                let mut removed_leaf = false;
                for offset in (0..shrink_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((new_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // R142-2 FIX: Mirror sys_munmap() fallback for non-present PTEs.
                    let frame_opt = match manager.unmap_page(page) {
                        Ok(frame) => Some(frame),
                        Err(mm::page_table::UnmapError::PageNotMapped) => {
                            manager.take_nonpresent_leaf_frame(page)
                        }
                        Err(_) => None,
                    };

                    if let Some(frame) = frame_opt {
                        removed_leaf = true;
                        if unmapped_frames.try_reserve(1).is_ok() {
                            unmapped_frames.push(frame);
                        } else {
                            // OOM fallback: flush this page FIRST, then release & free.
                            mm::flush_current_as_page(page.start_address());
                            let phys_addr = frame.start_address().as_u64() as usize;
                            if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                    }
                }

                // Every removed translation must be invalidated before PAGE_REF_COUNT
                // release, including COW leaves retained by another address space.
                if removed_leaf {
                    if !unmapped_frames.is_empty() {
                        mm::flush_current_as_range(VirtAddr::new(new_top as u64), shrink_size);
                        for frame in unmapped_frames {
                            let phys_addr = frame.start_address().as_u64() as usize;
                            if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                    }
                }

                #[cfg(feature = "syscall_test")]
                if removed_leaf {
                    let after = mm::tlb_shootdown::get_stats();
                    assert!(
                        after.pages_flushed > flushes_before.pages_flushed
                            || after.range_flushes > flushes_before.range_flushes
                            || after.full_flushes > flushes_before.full_flushes,
                        "brk removed a leaf without completing a cross-CPU flush"
                    );
                }

                // M2-1 SLICE-4c: reclaim the now-empty intermediate PT/PD tables this
                // shrink emptied — but DO NOT free them here. prune clears the parent
                // entries + issues the all-CPU paging-structure shootdown under PT_LOCK
                // (clear -> flush stays in this phase); the carried frames are published
                // to the buddy strictly AFTER the folded commit removes them from the
                // per-AS ledger (free-after-remove).
                let mut table_frames: alloc::vec::Vec<PhysFrame> = alloc::vec::Vec::new();
                let _ = table_frames.try_reserve((shrink_size / 0x20_0000) + 2);
                manager.prune_empty_tables_in_range(
                    VirtAddr::new(new_top as u64),
                    shrink_size,
                    &mut table_frames,
                );
                table_frames
            })
        };

        // M2-1 SLICE-4c: a leak-safe carrier for the reclaimed PT/PD table frames. They
        // are published to the buddy ONLY after the folded commit removes them from the
        // per-AS ledger (free-after-remove); on any early-return/panic before the explicit
        // drain, Drop frees them so a carried frame can never leak (mirrors sys_munmap).
        struct TableFrameReclaim {
            frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
            drained: bool,
        }
        impl Drop for TableFrameReclaim {
            fn drop(&mut self) {
                if !self.drained && !self.frames.is_empty() {
                    let mut fa = mm::memory::FrameAllocator::new();
                    for f in self.frames.drain(..) {
                        fa.deallocate_frame(f);
                    }
                }
            }
        }
        let mut reclaim = TableFrameReclaim {
            frames: table_frames,
            drained: false,
        };

        // R164-1 FIX: Re-verify mm.brk == old_brk at shrink commit, matching
        // the grow path (R162-2).
        // M2-1 SLICE-4c: fold the DATA uncharge AND the per-AS PT-ledger reconcile into
        // ONE Process+MmState critical section (canonical Process -> MmState order, exactly
        // like sys_munmap Phase-3) so both land atomically w.r.t. cgroup migration (which
        // snapshots compute_cgroup_charged_bytes — including pt_charged_bytes — under the
        // Process lock, R155-5). The prior code uncharged DATA in a SEPARATE process.lock()
        // AFTER the mm-only commit, leaving a migration split; folding both closes it.
        // cgroup uncharge runs with PT_LOCK already dropped (sanctioned under the Process
        // lock; never under PT_LOCK).
        {
            let proc = process.lock();
            let mut mm = mm_arc.lock();
            let cgroup_id = proc.cgroup_id;
            // PT leg (computed once, applied in whichever arm runs): reconcile the ledger
            // with the frames prune reclaimed — debit a reclaimed frame IFF this AS charged
            // it (frame-identity provenance; an UNCHARGED inherited frame is correctly NOT
            // debited). Skipped while the ledger is non-authoritative (a forked child's
            // inherited basis rides to teardown). The ledger removal happens HERE, strictly
            // before the frames are published to the buddy below (free-after-remove).
            let pt_freed = if mm.pt_ledger_authoritative {
                let freed = mm
                    .reclaim_pt_charges(reclaim.frames.iter().map(|f| f.start_address().as_u64()));
                if freed > 0 {
                    mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(freed);
                }
                freed
            } else {
                0
            };
            if mm.brk != old_brk {
                // Concurrent brk changed mm.brk while we were unmapping. Our unmapped pages
                // were in [new_top, old_top) below old_brk, so they don't overlap concurrent
                // growth. The DATA charge for these freed pages must still be released (the
                // frames were already deallocated). reclaim stays armed; its Drop publishes
                // the table frames to the buddy AFTER this ledger removal (free-after-remove).
                mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(shrink_size as u64);
                let current_brk = mm.brk;
                cgroup::uncharge_memory(cgroup_id, shrink_size as u64);
                if pt_freed > 0 {
                    cgroup::uncharge_memory(cgroup_id, pt_freed);
                }
                return Ok(current_brk);
            }
            mm.brk = addr;
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(shrink_size as u64);
            cgroup::uncharge_memory(cgroup_id, shrink_size as u64);
            if pt_freed > 0 {
                cgroup::uncharge_memory(cgroup_id, pt_freed);
            }
            // R165-1 FIX: release the brk reservation under the commit lock.
            mm.brk_in_progress = false;
            brk_resv.armed = false;
        }

        // M2-1 SLICE-4c: NOW publish the reclaimed table frames to the buddy — strictly
        // AFTER the ledger removal above (free-after-remove). In the window a frame becomes
        // buddy-reusable it is already gone from the ledger and pt_charged_bytes, so a
        // concurrent re-allocator that obtains it re-records it fresh.
        {
            let mut fa = FrameAllocator::new();
            for f in reclaim.frames.drain(..) {
                fa.deallocate_frame(f);
            }
            reclaim.drained = true;
        }

        Ok(addr)
    }
    // 同一页内调整，只更新 brk 值
    else {
        let mut mm = mm_arc.lock();
        mm.brk = addr;
        // R165-1 FIX: release the brk reservation under the same lock.
        mm.brk_in_progress = false;
        brk_resv.armed = false;
        Ok(addr)
    }
}

/// M0-7 item7 SLICE 4: 3-phase rollback for a partially-mapped user-stack grow — a
/// mirror of the `sys_brk` grow rollback. Unmaps the pages mapped so far (reverse
/// order), issues the cross-CPU flush, frees the DATA frames, then prunes the
/// now-empty intermediate PT/PD tables of the whole request. `frame_alloc` is the SAME
/// `RecordingFrameAllocator` the grow used, so `deallocate_frame` returns DATA frames
/// to the buddy WITHOUT perturbing the recorded `pt_frames`. `[grow_lo,
/// grow_lo+grow_size)` spans the whole request; `mapped_pages` is SPARSE (already-mapped
/// pages skipped), and `prune_empty_tables_in_range`'s `table_empty()` guard leaves a
/// table still pinned by a skipped sibling leaf untouched.
///
/// LEAD-ROLLBACK-PRUNE-LEDGER-1 FIX: the pruned tables are returned, not freed. An empty
/// table under the stack window's 2 MiB span can be another mapping's ledgered table
/// (mprotect Path B leaves those), so it reaches the buddy only after the caller's
/// error arm removed it from the ledger (`FailedPopulate::settle`).
///
/// # Safety
/// Must run inside `with_current_manager` (PT_LOCK held, interrupts off, current CR3).
pub(super) unsafe fn rollback_stack_grow_pages(
    manager: &mut mm::page_table::PageTableManager,
    frame_alloc: &mut RecordingFrameAllocator,
    mapped_pages: &[x86_64::structures::paging::Page<x86_64::structures::paging::Size4KiB>],
    grow_lo: usize,
    grow_size: usize,
) -> Vec<x86_64::structures::paging::PhysFrame> {
    use x86_64::structures::paging::PhysFrame;
    use x86_64::VirtAddr;

    let mut frames_to_free: Vec<PhysFrame> = Vec::new();
    let _ = frames_to_free.try_reserve(mapped_pages.len());
    for &rollback_page in mapped_pages.iter().rev() {
        if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
            if frames_to_free.try_reserve(1).is_ok() {
                frames_to_free.push(freed_frame);
            } else {
                // R158-6 FIX pattern: immediate free on tracking-Vec OOM.
                mm::flush_current_as_page(rollback_page.start_address());
                frame_alloc.deallocate_frame(freed_frame);
            }
        }
    }
    if !frames_to_free.is_empty() {
        mm::flush_current_as_range(VirtAddr::new(grow_lo as u64), grow_size);
        for frame in frames_to_free {
            frame_alloc.deallocate_frame(frame);
        }
    }
    let mut tables: Vec<PhysFrame> = Vec::new();
    let _ = tables.try_reserve(grow_size / 0x20_0000 + 2);
    manager.prune_empty_tables_in_range(VirtAddr::new(grow_lo as u64), grow_size, &mut tables);
    tables
}

/// LEAD-ROLLBACK-PRUNE-LEDGER-1: the failure carrier of a rolled-back stack grow, so
/// its error arm settles the pruned tables like a failed population.
pub(super) fn stack_grow_failure(
    stage: crate::populate::PopulateStage,
    pruned: Vec<x86_64::structures::paging::PhysFrame>,
    frame_alloc: &mut RecordingFrameAllocator,
) -> FailedPopulate {
    FailedPopulate::new(
        crate::populate::PopulateError::NoMemory(stage),
        pruned,
        mem::take(&mut frame_alloc.pt_frames),
    )
}

/// M0-7 item7 SLICE 4: the charge-correct user main-stack demand-grow PRIMITIVE.
///
/// Lowers the committed stack floor to `new_floor` (page-aligned), mapping
/// `[new_floor, stack_floor_committed)` with zeroed `USER|WRITABLE|NX` pages, HARD-
/// charging the DATA bytes to the process cgroup and SOFT-charging the page-table-frame
/// kmem — a faithful mirror of `sys_brk` grow (RAII reservation, `RecordingFrameAllocator`
/// DATA/PT split, 3-phase prune-on-rollback, migration-atomic `Process -> MmState`
/// commit) BUT with the **FA-04 fix**: the grow DATA commits to `elf_charged_bytes`
/// (the bucket teardown + `compute_cgroup_charged_bytes` + fork all read), NOT
/// `vm_charged_bytes` (read by neither → would strand `mem_pinned>0` at exit →
/// `delete_cgroup` fail-closed forever). See `MmState::commit_stack_grow`.
///
/// Process-context ONLY — it acquires blocking Process/MmState/PT/frame-allocator locks
/// and is NOT callable from a `#PF` / IRQ context (SLICE 5 adds a deferred-charge `#PF`
/// arm that calls this from a process-context safepoint). There is NO production caller
/// yet: today a user `#PF` is fatal (`interrupts.rs`), so on a default process
/// `stack_grow_floor() == stack_floor_committed` (the whole window-minus-guard is already
/// eager-mapped) and this returns ENOMEM — it is reachable only via the imperative
/// self-test until SLICE 5 splits the geometry.
///
/// Returns `Ok(())` on a committed grow; `EAGAIN` if a sibling grow holds the reservation;
/// `ENOMEM` on a cgroup-limit reject or an allocation failure (FULLY rolled back, no
/// charge / mapping leaked); `EINVAL` on a malformed floor (not page-aligned, not below
/// the current floor, or no user image installed).
/// M0-7 SLICE 5 / RF178-12: synchronous fail-closed demand-grow handler for #PF.
///
/// # Arguments
///
/// * `pid` - Faulting process
/// * `fault_addr` - Faulting address
///
/// # Returns
///
/// `Ok(())` if a complete top-down prefix was committed, `Err` otherwise.
///
/// # Design (synchronous hard charge, IRQs-off safe)
///
/// 1. Check if fault_addr is in lazy stack region [usable_base, eager_floor)
/// 2. Compute grow target: page-align-down fault_addr
/// 3. Hard-charge the complete DATA batch before mapping
/// 4. Precharge and pre-zero every intermediate PT frame before publication
/// 5. Commit the mapped top-down prefix and all published PT bytes before return
///
/// Any partial publication is charged and folded into `MmState` before `Err` is
/// returned; the sole architectural caller then terminates the current task.
/// The handler never allocates rollback metadata, unmaps a published frame, or
/// performs a cross-CPU shootdown. x86 needs no invalidation for P=0 -> P=1;
/// `map_page` retains its bounded local `invlpg`.
pub fn try_demand_grow_user_stack(
    pid: crate::process::ProcessId,
    fault_addr: usize,
) -> Result<(), SyscallError> {
    use crate::elf_loader::user_stack_layout;
    use cgroup::{FaultChargeError, FaultMemoryCharge};
    use mm::page_table::try_with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    const MAX_GROW_PAGES: usize = 8;
    const MAX_GROW_PT_PAGES: usize = MAX_GROW_PAGES * 3;

    // RF178-12: PROCESS_TABLE, PCB, and MmState are all nonblocking on #PF.
    let process_arc = match crate::process::try_get_process(pid) {
        Some(Some(p)) => p,
        Some(None) => return Err(SyscallError::ESRCH),
        None => return Err(SyscallError::EAGAIN),
    };
    let proc = process_arc.try_lock().ok_or(SyscallError::EAGAIN)?;
    if current_pid() != Some(proc.pid) || proc.pid != pid {
        return Err(SyscallError::EINVAL);
    }

    let (_, usable_base, eager_floor, _) = user_stack_layout();
    if fault_addr < usable_base || fault_addr >= eager_floor {
        return Err(SyscallError::EINVAL);
    }
    let fault_page_base = fault_addr & !(PAGE_SIZE - 1);
    let (stack_window_base, stack_window_top) = crate::elf_loader::user_stack_window();
    if fault_page_base < stack_window_base || fault_page_base >= stack_window_top {
        return Err(SyscallError::EINVAL);
    }

    let cgroup_id = proc.cgroup_id;
    let rlim_cur = proc.rlimits[crate::process::RLIMIT_STACK].rlim_cur;
    let mm_arc = Arc::clone(&proc.mm);
    let mut mm = mm_arc.try_lock().ok_or(SyscallError::EAGAIN)?;
    let old_floor = mm.stack_floor_committed;
    if old_floor == 0 || fault_page_base >= old_floor {
        return Err(SyscallError::EINVAL);
    }
    if fault_page_base < crate::elf_loader::stack_grow_floor(rlim_cur) {
        return Err(SyscallError::ENOMEM);
    }
    if mm.fork_in_progress || mm.stack_grow_in_progress {
        return Err(SyscallError::EAGAIN);
    }
    mm.stack_grow_in_progress = true;

    let pages_needed = (old_floor - fault_page_base + PAGE_SIZE - 1) / PAGE_SIZE;
    let pages_to_map = pages_needed.min(MAX_GROW_PAGES);
    let grow_size = pages_to_map * PAGE_SIZE;

    // Hard-charge the complete DATA reservation before any leaf or parent PTE
    // can become present. All guards are try-only; the fixed receipt allocates
    // nothing and carries the captured ancestry into the PT section.
    let mut charge = match FaultMemoryCharge::try_new(cgroup_id, grow_size as u64) {
        Ok(receipt) => receipt,
        Err(error) => {
            mm.stack_grow_in_progress = false;
            return Err(match error {
                FaultChargeError::Contended => SyscallError::EAGAIN,
                FaultChargeError::NotFound => SyscallError::ESRCH,
                FaultChargeError::Invalid => SyscallError::EINVAL,
                FaultChargeError::LimitExceeded
                | FaultChargeError::Overflow
                | FaultChargeError::Invariant => SyscallError::ENOMEM,
            });
        }
    };

    // The PCB and MmState guards remain held through the bounded PT operation.
    // This is canonical Process -> MmState -> PT ordering and makes cgroup identity,
    // reservation, and floor a single transaction without any blocking re-lock.
    let mapped = unsafe {
        try_with_current_manager(VirtAddr::new(0), |manager| {
            mm::buddy_allocator::try_with_allocator(|buddy| {
                let mut frame_alloc =
                    FaultStackFrameAllocator::new(buddy, &mut charge, MAX_GROW_PT_PAGES);
                let mut outcome = FaultStackMapOutcome::new();
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::NO_EXECUTE;

                // Publish only a top-down prefix. A fatal partial mapping can
                // therefore lower the committed floor by exactly k pages; it
                // never leaves a mapped island below an unmapped hole.
                for page_index in 0..pages_to_map {
                    let vaddr = VirtAddr::new((old_floor - (page_index + 1) * PAGE_SIZE) as u64);
                    let page = Page::containing_address(vaddr);
                    if manager.translate_addr(vaddr).is_some() {
                        outcome.error = Some(SyscallError::EINVAL);
                        break;
                    }
                    let Some(frame) = frame_alloc.allocate_data_frame() else {
                        outcome.error = Some(SyscallError::ENOMEM);
                        break;
                    };

                    // The direct map is required under SMAP and makes zero-before-
                    // publication explicit to both the compiler and x86 hardware.
                    let direct = mm::phys_to_virt(frame.start_address());
                    core::ptr::write_bytes(direct.as_mut_ptr::<u8>(), 0, PAGE_SIZE);
                    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

                    if manager
                        .map_page(page, frame, flags, &mut frame_alloc)
                        .is_err()
                    {
                        frame_alloc.deallocate_frame(frame);
                        outcome.error = frame_alloc.take_error().or(Some(SyscallError::ENOMEM));
                        break;
                    }
                    outcome.mapped_data_pages += 1;
                }
                outcome.charged_pt_pages = frame_alloc.charged_pt_pages();
                if outcome.error.is_none() {
                    outcome.error = frame_alloc.take_error();
                }
                outcome
            })
        })
    };

    let mut outcome = match mapped {
        Some(Some(outcome)) => outcome,
        Some(None) | None => {
            mm.stack_grow_in_progress = false;
            return Err(SyscallError::EAGAIN);
        }
    };

    let data_bytes = (outcome.mapped_data_pages as u64) * PAGE_SIZE as u64;
    let pt_bytes = (outcome.charged_pt_pages as u64) * PAGE_SIZE as u64;
    if data_bytes == 0 && pt_bytes == 0 {
        mm.stack_grow_in_progress = false;
        return Err(outcome.error.unwrap_or(SyscallError::EIO));
    }

    // Return the unused DATA suffix. If the exact release invariant itself is
    // broken, retain and ledger the full DATA reservation (safe over-accounting)
    // and force the fatal path instead of creating an unowned cgroup charge.
    let unused_data = (grow_size as u64).saturating_sub(data_bytes);
    let committed_data = if charge.refund(unused_data).is_ok() {
        data_bytes
    } else {
        outcome.error = Some(SyscallError::EIO);
        grow_size as u64
    };
    let committed_floor = old_floor - outcome.mapped_data_pages * PAGE_SIZE;
    mm.commit_fault_stack_grow(committed_data, pt_bytes, committed_floor);
    debug_assert_eq!(
        charge.charged_bytes(),
        committed_data.saturating_add(pt_bytes),
        "fault receipt and MmState commit must transfer the same byte total"
    );
    charge.commit();

    match outcome.error {
        Some(error) => Err(error),
        None if outcome.mapped_data_pages == pages_to_map => Ok(()),
        None => Err(SyscallError::EIO),
    }
}

#[derive(Clone, Copy)]
pub(super) struct FaultStackMapOutcome {
    pub(super) mapped_data_pages: usize,
    pub(super) charged_pt_pages: usize,
    pub(super) error: Option<SyscallError>,
}

impl FaultStackMapOutcome {
    pub(super) const fn new() -> Self {
        Self {
            mapped_data_pages: 0,
            charged_pt_pages: 0,
            error: None,
        }
    }
}

/// RF178-12: stack-only allocator used exclusively by synchronous #PF growth.
/// Every PT frame is hard-charged and zeroed before `map_to` may publish it.
pub(super) struct FaultStackFrameAllocator<'a, 'charge> {
    pub(super) inner: &'a mut mm::buddy_allocator::BuddyAllocator,
    pub(super) charge: &'charge mut cgroup::FaultMemoryCharge,
    pub(super) charged_pt_pages: usize,
    pub(super) max_pt_pages: usize,
    pub(super) error: Option<SyscallError>,
}

impl<'a, 'charge> FaultStackFrameAllocator<'a, 'charge> {
    pub(super) fn new(
        inner: &'a mut mm::buddy_allocator::BuddyAllocator,
        charge: &'charge mut cgroup::FaultMemoryCharge,
        max_pt_pages: usize,
    ) -> Self {
        Self {
            inner,
            charge,
            charged_pt_pages: 0,
            max_pt_pages,
            error: None,
        }
    }

    pub(super) fn allocate_data_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
        self.inner.alloc_pages(0)
    }

    pub(super) fn deallocate_frame(&mut self, frame: x86_64::structures::paging::PhysFrame) {
        self.inner.free_pages(frame, 0);
    }

    pub(super) fn charged_pt_pages(&self) -> usize {
        self.charged_pt_pages
    }

    pub(super) fn take_error(&mut self) -> Option<SyscallError> {
        self.error.take()
    }
}

unsafe impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>
    for FaultStackFrameAllocator<'_, '_>
{
    fn allocate_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
        if self.charged_pt_pages == self.max_pt_pages {
            self.error = Some(SyscallError::ENOMEM);
            return None;
        }

        if self.charge.try_add(PAGE_SIZE as u64).is_err() {
            self.error = Some(SyscallError::ENOMEM);
            return None;
        }
        self.charged_pt_pages += 1;

        let Some(frame) = self.inner.alloc_pages(0) else {
            if self.charge.refund(PAGE_SIZE as u64).is_ok() {
                self.charged_pt_pages -= 1;
            } else {
                self.error = Some(SyscallError::EIO);
                return None;
            }
            self.error = Some(SyscallError::ENOMEM);
            return None;
        };

        // x86_64's mapper links the returned parent before its own zero pass.
        // Pre-zeroing closes that transient page-table exposure.
        let direct = mm::phys_to_virt(frame.start_address());
        unsafe { core::ptr::write_bytes(direct.as_mut_ptr::<u8>(), 0, PAGE_SIZE) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        Some(frame)
    }
}

/// M0-7 SLICE 5: Pre-grow helper for Ring-0 user-stack writers
///
/// Ensures that [target_va, stack_floor_committed) is fully mapped before a
/// Ring-0 write (sigframe, initial stack, IRQ sigframe). If the target falls
/// in the lazy region, triggers demand-grow.
///
/// # Arguments
///
/// * `pid` - Target process
/// * `target_va` - Lowest VA that will be written
///
/// # Returns
///
/// Ok(()) if region is backed, Err if grow fails
pub(super) fn ensure_stack_backed(
    pid: crate::process::ProcessId,
    target_va: usize,
) -> Result<(), SyscallError> {
    let process_arc = match crate::process::get_process(pid) {
        Some(p) => p,
        None => return Err(SyscallError::ESRCH),
    };

    let proc = process_arc.lock();
    let mm = proc.mm.lock();
    let floor = mm.stack_floor_committed;
    drop(mm);
    drop(proc);

    // If target is at or above floor, already backed
    if target_va >= floor {
        return Ok(());
    }

    // Need to grow: page-align-down target
    let new_floor = target_va & !(PAGE_SIZE - 1);

    // Use the process-context try_grow_user_stack
    try_grow_user_stack(&process_arc, new_floor)
}

pub fn try_grow_user_stack(
    process: &crate::process::ProcessArc,
    new_floor: usize,
) -> Result<(), SyscallError> {
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
    use x86_64::VirtAddr;

    // ── Phase 0: validate + acquire the reservation under the entry Process lock ──
    let proc = process.lock();
    // Codex SLICE-4 review (current-task-only contract): the page-table work below runs
    // through with_current_manager, which mutates the RUNNING CPU's CR3 — so a caller
    // passing a NON-current process would map pages into the WRONG address space while
    // charging THIS process's cgroup (a confused deputy). SLICE 5's #PF arm always passes
    // the faulting (current) task; this HARD guard kills the class for any future caller
    // (mirrors the exec_from_bytes current-task assertion, but fail-closed in release too).
    if current_pid() != Some(proc.pid) {
        return Err(SyscallError::EINVAL);
    }
    let cgroup_id = proc.cgroup_id;
    let mm_arc = Arc::clone(&proc.mm);
    let rlim_cur = proc.rlimits[crate::process::RLIMIT_STACK].rlim_cur;

    let (old_floor, grow_size, mut grow_resv) = {
        let mut mm = mm_arc.lock();
        let old_floor = mm.stack_floor_committed;
        // Sentinel: no user image installed yet (MmState::new) — nothing to grow.
        if old_floor == 0 {
            return Err(SyscallError::EINVAL);
        }
        // Must descend (grow is downward) to a page boundary strictly below the floor.
        if new_floor >= old_floor || (new_floor & (PAGE_SIZE - 1)) != 0 {
            return Err(SyscallError::EINVAL);
        }
        // Bound by RLIMIT_STACK clamped to the architectural window (the load-bearing
        // min() lives in stack_grow_floor). A request past the limit is ENOMEM (Linux
        // delivers SIGSEGV for an over-limit auto-grow; the primitive's caller — SLICE 5
        // — maps ENOMEM to the fatal fault).
        let grow_floor = crate::elf_loader::stack_grow_floor(rlim_cur);
        if new_floor < grow_floor {
            return Err(SyscallError::ENOMEM);
        }
        // A sibling grow on this shared MmState is mid-flight — fail-closed EAGAIN
        // (mirror brk_in_progress; the caller retries). brk_in_progress / a mid-flight
        // brk does not block a stack grow and vice-versa: they touch disjoint VA ranges
        // and DISJOINT charge lanes (brk_pending_growth vs stack_grow_pending_bytes), so
        // a single shared MmState can have at most one of each in flight without aliasing.
        if mm.fork_in_progress || mm.stack_grow_in_progress {
            return Err(SyscallError::EAGAIN);
        }
        mm.stack_grow_in_progress = true;
        (
            old_floor,
            old_floor - new_floor,
            StackGrowReservation {
                mm: Arc::clone(&mm_arc),
                armed: true,
            },
        )
    };

    // ── Phase 1: HARD-charge the grow DATA to the snapshot cgroup ──
    // try_charge_memory enforces memory.max (rejects → ENOMEM). cgroup_id is the value
    // snapshotted while holding `proc`; the commit re-reads proc.cgroup_id for the PT
    // charge, and the DATA (tracked below in stack_grow_pending_bytes) telescopes via a
    // migration's compute-transfer if one races (the sys_cgroup_attach EAGAIN gate makes
    // the syscall path mutually exclusive; the cgroupfs path relies on the pending lane).
    if cgroup::try_charge_memory(cgroup_id, grow_size as u64).is_err() {
        return Err(SyscallError::ENOMEM); // grow_resv Drop clears stack_grow_in_progress
    }
    // Record the in-flight DATA so compute_cgroup_charged_bytes counts it while the
    // Process lock is dropped for PT work (mirror brk_pending_growth, R144-1; saturating
    // for a defensively-concurrent CLONE_VM sibling, though the reservation serializes).
    {
        let mut mm = mm_arc.lock();
        mm.stack_grow_pending_bytes = mm.stack_grow_pending_bytes.saturating_add(grow_size as u64);
    }

    // Release the Process lock for the irreversible page-table work (lock order:
    // MmState/PT/frame-allocator locks sit BELOW Process; holding Process across them
    // would invert the established order — the brk-grow contract).
    drop(proc);

    // ── Phase 2: map [new_floor, old_floor) — zeroed USER|WRITABLE|NX pages ──
    // RecordingFrameAllocator: DATA frames via allocate_data_frame (UNrecorded — stack
    // data is not page-table kmem); intermediate PT/PD frames via the trait allocate_frame
    // (recorded by identity for record_pt_charge). Single 3-phase rollback on any error.
    let map_result: Result<Vec<PhysFrame<Size4KiB>>, FailedPopulate> = unsafe {
        with_current_manager(
            VirtAddr::new(0),
            |manager| -> Result<Vec<PhysFrame<Size4KiB>>, FailedPopulate> {
                let mut frame_alloc = RecordingFrameAllocator::new();
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::NO_EXECUTE;
                let mut mapped_pages: Vec<Page<Size4KiB>> = Vec::new();

                for offset in (0..grow_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((new_floor + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // Defensive skip (the lazy window should be unmapped); mirrors brk.
                    if manager.translate_addr(vaddr).is_some() {
                        continue;
                    }

                    // DATA frame via the inherent (UNrecorded) method.
                    let frame = match frame_alloc.allocate_data_frame() {
                        Some(f) => f,
                        None => {
                            let pruned = rollback_stack_grow_pages(
                                manager,
                                &mut frame_alloc,
                                &mapped_pages,
                                new_floor,
                                grow_size,
                            );
                            return Err(stack_grow_failure(
                                crate::populate::PopulateStage::DataFrame,
                                pruned,
                                &mut frame_alloc,
                            ));
                        }
                    };

                    // Issue #109 §1.3 (Invariant S2): `allocate_data_frame()` ->
                    // `mm::buddy_allocator::alloc_physical_pages(1)` guarantees
                    // a 4 KiB pre-zeroed frame before it can be mapped.
                    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

                    if manager
                        .map_page(page, frame, flags, &mut frame_alloc)
                        .is_err()
                    {
                        frame_alloc.deallocate_frame(frame);
                        let pruned = rollback_stack_grow_pages(
                            manager,
                            &mut frame_alloc,
                            &mapped_pages,
                            new_floor,
                            grow_size,
                        );
                        return Err(stack_grow_failure(
                            crate::populate::PopulateStage::MapPage,
                            pruned,
                            &mut frame_alloc,
                        ));
                    }

                    // R158-6 FIX pattern: fallible push — unmap+free this page then roll back.
                    if mapped_pages.try_reserve(1).is_err() {
                        if let Ok(freed) = manager.unmap_page(page) {
                            mm::flush_current_as_page(page.start_address());
                            frame_alloc.deallocate_frame(freed);
                        }
                        let pruned = rollback_stack_grow_pages(
                            manager,
                            &mut frame_alloc,
                            &mapped_pages,
                            new_floor,
                            grow_size,
                        );
                        return Err(stack_grow_failure(
                            crate::populate::PopulateStage::MapPage,
                            pruned,
                            &mut frame_alloc,
                        ));
                    }
                    mapped_pages.push(page);
                }
                // Yield the recorded PT-frame identities for the Step-3 charge fold (every
                // Err arm above freed its own DATA leaves and carries its pruned tables).
                Ok(frame_alloc.take_pt_frames())
            },
        )
    };

    // ── Phase 3: commit or roll back the cgroup accounting ──
    let pt_frames = match map_result {
        Err(failed) => {
            // Roll back the DATA charge + the pending lane. Clear pending FIRST (so a
            // concurrent migration cannot transfer a charge about to be rolled back),
            // then uncharge the CURRENT cgroup_id (migration may have re-homed it during
            // the lock-drop) — mirror brk's rollback. The PT work already freed its own
            // DATA leaves; LEAD-ROLLBACK-PRUNE-LEDGER-1: the tables it pruned are settled
            // here (one may be another mapping's ledgered table) and freed after.
            let rollback_cgroup_id = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                mm.stack_grow_pending_bytes =
                    mm.stack_grow_pending_bytes.saturating_sub(grow_size as u64);
                failed.settle(&mut mm, proc.cgroup_id);
                proc.cgroup_id
            };
            cgroup::uncharge_memory(rollback_cgroup_id, grow_size as u64);
            drop(failed);
            return Err(SyscallError::ENOMEM); // grow_resv Drop clears stack_grow_in_progress
        }
        Ok(frames) => frames,
    };
    let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

    // Migration-atomic commit fold under Process -> MmState (canonical order). cgroup
    // migration snapshots compute_cgroup_charged_bytes — which sums stack_grow_pending_bytes
    // AND pt_charged_bytes — under the Process lock (R155-5), so charging under mm-only
    // would race sys_cgroup_attach and strand the charge on a stale cgroup. `proc` (the
    // entry guard) was dropped before the lock-free PT work; re-acquire a fresh Process
    // lock — no self-deadlock (the PT work held no Process lock).
    {
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        // Defense-in-depth tripwire (DEAD under the reservation): stack_grow_in_progress
        // pins stack_floor_committed for the whole lock-dropped window — a sibling grow
        // EAGAINs, fork EAGAINs, sys_cgroup_attach EAGAINs, exec rejects shared-VM and
        // cannot run concurrently single-threaded. If it somehow moved we STILL COMMIT
        // (NOT uncharge): the pages ARE mapped and the DATA IS charged, so committing keeps
        // memory_current consistent with the live frames — the conservative, never-
        // under-count direction (Codex SLICE-4 review: an uncharge-but-leave-mapped arm was
        // an UNDER-count / memory.max bypass, the WRONG direction). Only the watermark could
        // be stale, and it is consumed solely by this primitive. Mirrors brk's mm.brk==old_brk
        // tripwire but resolves to a balanced commit rather than a stale-DATA uncharge.
        debug_assert!(
            mm.stack_floor_committed == old_floor,
            "stack floor moved under reservation — impossible (stack_grow_in_progress pins it)"
        );
        // FA-04 commit: move the DATA from the pending lane into elf_charged_bytes +
        // advance the watermark + clear the reservation (pure, unit-tested helper).
        mm.commit_stack_grow(grow_size as u64, new_floor);
        // SOFT/forced PT-frame kmem charge (the count is knowable only after map_page ran
        // — IM-15), migration-atomic under this hold. record_pt_charge does the per-AS
        // frame-identity ledger insert + INVARIANT-I' bookkeeping (OOM-fallback to
        // pt_inherited_bytes). charge_memory_forced takes only CGROUP_REGISTRY + atomics
        // (never Process/MmState), so this is deadlock-free under the held locks.
        if pt_bytes > 0 {
            cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
            mm.record_pt_charge(&pt_frames);
        }
        grow_resv.armed = false;
    }

    Ok(())
}

/// R171-CG1x0 FIX (M2-1 SLICE-0; hoisted to module scope by M2-1 SLICE-4a): a
/// frame-allocator shim that RECORDS THE IDENTITY of every intermediate
/// PT/PD/PDPT frame `map_to`/`map_page` pulls via `create_next_table`, so the
/// per-AS provenance ledger (`MmState.pt_charged_frames`) can later uncharge a
/// reclaimed page-table frame IFF the AS charged it (defeating the cross-origin
/// `memory.max` bypass).
///
/// Hoisted from a `sys_mmap`-local definition so every EAGER PT-building syscall
/// path (mmap; mprotect Path-A; later brk/exec) shares ONE audited shim. The
/// DATA/PT split is by CALL PATH, not a counter: the explicit per-page DATA frame
/// the caller pulls goes through the INHERENT `allocate_data_frame` (never
/// recorded — it is not page-table memory); the PT/PD/PDPT frames `map_to` pulls
/// go through the TRAIT `allocate_frame` (recorded by physical address). `map_to`
/// allocates an intermediate frame ONLY for an `is_unused()` level (the
/// `create_next_table` guard), so `pt_frames` is EXACTLY the newly-built
/// page-table frames — frame identity, not a fungible count. The trait body
/// RESERVES the ledger slot BEFORE pulling from the buddy: on `try_reserve`
/// failure it returns None WITHOUT allocating, so `map_to` fails and the caller's
/// existing rollback fires — there is never an unrecorded LIVE PT frame
/// (fail-closed). `deallocate_frame` never touches `pt_frames` (rollback frees
/// must not perturb the recorded set; `pt_frames` is consumed only on the Ok
/// path). Both allocate bodies delegate to `self.inner` (never
/// `Self::allocate_frame`) to avoid inherent/trait recursion. `inner` is spelled
/// fully-qualified `mm::memory::FrameAllocator` so it cannot silently resolve to
/// a different ambient type after the hoist.
pub(crate) struct RecordingFrameAllocator {
    pub(super) inner: mm::memory::FrameAllocator,
    pub(super) pt_frames: vec::Vec<x86_64::structures::paging::PhysFrame>,
}
impl RecordingFrameAllocator {
    /// Construct over a fresh buddy frame allocator with an empty PT-frame record.
    pub(crate) fn new() -> Self {
        Self {
            inner: mm::memory::FrameAllocator::new(),
            pt_frames: vec::Vec::new(),
        }
    }
    /// Explicit DATA-frame allocation (per-page in a map loop): NOT recorded —
    /// data frames are not page-table kmem and must not enter the ledger.
    /// M2-1 SLICE-4d: pub(crate) so the ELF loader (a sibling module) can pull DATA
    /// frames through the SAME audited shim and keep the DATA/PT split intact.
    pub(crate) fn allocate_data_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
        self.inner.allocate_frame()
    }
    /// M2-1 SLICE-4d: pub(crate) so the ELF loader's map-fail rollback can free a DATA
    /// frame through the shim (never perturbs the recorded `pt_frames`).
    pub(crate) fn deallocate_frame(&mut self, frame: x86_64::structures::paging::PhysFrame) {
        self.inner.deallocate_frame(frame);
    }
    /// M2-1 SLICE-4d: consume the recorder and return the recorded PT/PD/PDPT frame
    /// identities. A cross-module accessor (the `pt_frames` field stays private) so the
    /// ELF loader can fold the recorded frames into ElfLoadResult without touching the
    /// field directly. Call ONLY on the Ok path — every helper frees its own DATA frames
    /// on error and, on exec failure, the whole new AS (incl. these tables) is torn down
    /// by free_address_space, so the dropped recorder leaks nothing.
    pub(crate) fn take_pt_frames(self) -> vec::Vec<x86_64::structures::paging::PhysFrame> {
        self.pt_frames
    }
}
unsafe impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>
    for RecordingFrameAllocator
{
    fn allocate_frame(
        &mut self,
    ) -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>> {
        // Reserve the ledger slot BEFORE pulling a frame from the buddy. On OOM
        // return None without allocating: `map_to` then fails and the caller's
        // existing rollback runs — no unrecorded live PT frame can exist (fail-closed).
        if self.pt_frames.try_reserve(1).is_err() {
            return None;
        }
        let f = self.inner.allocate_frame();
        if let Some(frame) = f {
            self.pt_frames.push(frame); // cannot fail: capacity reserved above
        }
        f
    }
}

/// M2-1 SLICE-4b: regression guard for the LOAD-BEARING DATA/PT split in
/// `RecordingFrameAllocator`. The inherent `allocate_data_frame` must NOT record (heap /
/// ELF-segment / stack DATA pages are not page-table kmem), while the trait
/// `allocate_frame` (the path `map_page` pulls for intermediate tables) MUST record by
/// frame identity. A mis-wire routing a DATA pull through the trait would record every
/// data page as a PT frame (~512x over-charge + a corrupt ledger whose data-frame keys a
/// later `pt_ledger_reconcile` would debit as PT). This guards the brk-grow / exec
/// DATA/PT swap — the single most error-prone seam of M2-1 SLICE-4. Lives in `syscall.rs`
/// because it touches the module-private `allocate_data_frame` / `pt_frames`.
pub fn run_recording_frame_allocator_split_self_test() {
    let mut fa = RecordingFrameAllocator::new();
    // DATA frame via the inherent method: must NOT be recorded.
    let d = fa
        .allocate_data_frame()
        .expect("buddy frame for DATA self-test");
    assert_eq!(
        fa.pt_frames.len(),
        0,
        "DATA frame must NOT enter the PT ledger"
    );
    // PT frame via the trait method `map_page` uses: must be recorded by identity.
    let p = <RecordingFrameAllocator as x86_64::structures::paging::FrameAllocator<
        x86_64::structures::paging::Size4KiB,
    >>::allocate_frame(&mut fa)
    .expect("buddy frame for PT self-test");
    assert_eq!(
        fa.pt_frames.len(),
        1,
        "trait allocate_frame MUST record the PT frame"
    );
    assert_eq!(
        fa.pt_frames[0], p,
        "recorded PT frame identity must match the allocation"
    );
    // Cleanup: return both frames to the buddy (deallocate_frame never perturbs pt_frames).
    fa.deallocate_frame(d);
    fa.deallocate_frame(p);
}

/// R192-RES-2: populations of at least this many pages print one summary line
/// in `syscall_test` builds; the ring3-mm oracle reads it.
#[cfg(feature = "syscall_test")]
pub(super) const POPULATE_REPORT_PAGES: usize = 16384;

/// R192-RES-2 test knob: once armed, the next population of exactly this many
/// pages fails the data-frame allocation of its last page. That allocation
/// stages the last, three-page chunk, so the guest drives a rollback of the
/// 16384 pages mapped by the 256 chunks before it.
#[cfg(feature = "syscall_test")]
pub const POPULATE_FAULT_PROBE_PAGES: usize = 16384 + 3;

#[cfg(feature = "syscall_test")]
pub(super) static POPULATE_FAULT_PROBE_ARMED: AtomicBool = AtomicBool::new(false);

/// R192-RES-2 test knob: once armed, the first population of
/// [`POPULATE_FAULT_PROBE_PAGES`] pages after the fault probe fired stages no
/// spare page tables, so every table it needs goes through `map_hold`'s
/// starvation path.
#[cfg(feature = "syscall_test")]
pub(super) static POPULATE_STARVE_PROBE_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm the one-shot population fault and starvation probes (`syscall_test`
/// builds only).
#[cfg(feature = "syscall_test")]
pub fn arm_populate_fault_probe() {
    POPULATE_FAULT_PROBE_ARMED.store(true, AtomicOrdering::Release);
    POPULATE_STARVE_PROBE_ARMED.store(true, AtomicOrdering::Release);
}

/// R192-RES-2: page-table frames staged for one chunk. Its 64 pages cross at
/// most one 2 MiB, one 1 GiB and one 512 GiB boundary, so `map_page` builds at
/// most two new PTs, two PDs and two PDPTs for it.
pub(super) const POPULATE_TABLE_POOL: usize = 6;

/// R192-RES-2: room for the tables a rollback over `pages` pages can prune: one
/// PT per 2 MiB and one PD per 1 GiB, plus the edges. A short reserve only
/// makes `prune_empty_tables_in_range` grow the list under the lock.
pub(super) fn populate_prune_reserve(pages: usize) -> usize {
    pages / 512 + pages / (512 * 512) + 4
}

/// R192-RES-2: the syscall errno of a failed population.
pub(super) fn populate_errno(error: crate::populate::PopulateError) -> SyscallError {
    match error {
        crate::populate::PopulateError::NoMemory(_) => SyscallError::ENOMEM,
        crate::populate::PopulateError::Interrupted => SyscallError::EINTR,
    }
}

/// R192-RES-2: the kernel backend of [`crate::populate::populate`] for one
/// private, eagerly backed user range (`brk` grow, private `mmap`, `mprotect`
/// Path A, the `mremap` grow tail).
///
/// Every frame the population needs comes from the buddy with no lock held:
/// data frames are allocated and zeroed outside the hold, and the page-table
/// frames a chunk can need are staged before it (`tables`), so the allocator's
/// OOM handling never runs under `PT_LOCK`. Spare table frames are staged
/// without it; only a table a chunk actually needs is allocated with it. Every
/// hold is one
/// `with_current_manager` over at most one chunk. The page-table frames
/// `map_page` takes are recorded by identity for the commit's charge and ledger
/// fold, as before, and the tables a rollback prunes are carried to the
/// caller's error arm ([`FailedPopulate`]) instead of being freed under the
/// lock. The caller's reservation keeps the range exclusive while the lock is
/// dropped between holds, and fork refuses every such reservation, so the data
/// frames stay private and are freed without a refcount transition.
pub(crate) struct EagerPopulator {
    pub(super) process: crate::process::ProcessArc,
    pub(super) base: usize,
    pub(super) pages: usize,
    pub(super) flags: PageTableFlags,
    pub(super) recorder: RecordingFrameAllocator,
    pub(super) tables: [Option<x86_64::structures::paging::PhysFrame>; POPULATE_TABLE_POOL],
    pub(super) pruned: Vec<x86_64::structures::paging::PhysFrame>,
    #[cfg(feature = "syscall_test")]
    pub(super) site: &'static str,
    #[cfg(feature = "syscall_test")]
    pub(super) allocated: usize,
    #[cfg(feature = "syscall_test")]
    pub(super) fail_at: Option<usize>,
    /// The starvation probe: stage no spare page tables.
    #[cfg(feature = "syscall_test")]
    pub(super) starve_probe: bool,
    /// Holds that ended because a table was needed and none was staged.
    #[cfg(feature = "syscall_test")]
    pub(super) starved: usize,
    #[cfg(feature = "syscall_test")]
    pub(super) holds: usize,
    #[cfg(feature = "syscall_test")]
    pub(super) max_pages_per_hold: usize,
    /// Data frames allocated and not yet freed: every page on success, zero
    /// after a rollback.
    #[cfg(feature = "syscall_test")]
    pub(super) live: usize,
}

impl EagerPopulator {
    /// A population of `pages` pages at `base` with leaf `flags`, for the
    /// current task `process`. `site` names the syscall in test reports.
    pub(crate) fn new(
        site: &'static str,
        process: &crate::process::ProcessArc,
        base: usize,
        pages: usize,
        flags: PageTableFlags,
    ) -> Self {
        let mut pruned = Vec::new();
        if pages != 0 {
            let _ = pruned.try_reserve(populate_prune_reserve(pages));
        }
        // ST-K2-P2(d) adds a re-armable failure of an exact smaller size.
        #[cfg(feature = "syscall_test")]
        let fail_at = ((pages == POPULATE_FAULT_PROBE_PAGES
            && POPULATE_FAULT_PROBE_ARMED.swap(false, AtomicOrdering::AcqRel))
            || crate::fork::shared_fault_test::take_population_failure(pages))
        .then(|| pages - 1);
        Self {
            process: process.clone(),
            base,
            pages,
            flags,
            recorder: RecordingFrameAllocator::new(),
            tables: [None; POPULATE_TABLE_POOL],
            pruned,
            #[cfg(feature = "syscall_test")]
            site,
            #[cfg(feature = "syscall_test")]
            allocated: 0,
            #[cfg(feature = "syscall_test")]
            fail_at,
            #[cfg(feature = "syscall_test")]
            starve_probe: fail_at.is_none()
                && pages == POPULATE_FAULT_PROBE_PAGES
                && POPULATE_STARVE_PROBE_ARMED.swap(false, AtomicOrdering::AcqRel),
            #[cfg(feature = "syscall_test")]
            starved: 0,
            #[cfg(feature = "syscall_test")]
            holds: 0,
            #[cfg(feature = "syscall_test")]
            max_pages_per_hold: 0,
            #[cfg(feature = "syscall_test")]
            live: 0,
        }
    }

    /// Populate the whole range. `Ok` carries the recorded page-table frames
    /// for the commit; on `Err` nothing of the range is mapped any more.
    pub(crate) fn run(
        mut self,
    ) -> Result<Vec<x86_64::structures::paging::PhysFrame>, FailedPopulate> {
        match self.populate() {
            Ok(()) => Ok(self.into_commit()),
            Err(error) => Err(self.into_failure(error)),
        }
    }

    /// Populate the whole range, keeping the populator for a caller that maps
    /// more of the same operation in its own hold (mremap).
    pub(crate) fn populate(&mut self) -> Result<(), crate::populate::PopulateError> {
        let pages = self.pages;
        crate::populate::populate(self, pages)
    }

    /// Unmap the whole, fully populated range again in bounded holds.
    pub(crate) fn rollback_all(&mut self) {
        let pages = self.pages;
        crate::populate::rollback(self, pages);
    }

    /// The recorder and the pruned-table carrier, for a caller's own hold that
    /// maps or rolls back more of the same operation (mremap relocation).
    pub(crate) fn parts(
        &mut self,
    ) -> (
        &mut RecordingFrameAllocator,
        &mut Vec<x86_64::structures::paging::PhysFrame>,
    ) {
        (&mut self.recorder, &mut self.pruned)
    }

    /// The recorded page-table frames of a successful operation.
    pub(crate) fn into_commit(mut self) -> Vec<x86_64::structures::paging::PhysFrame> {
        #[cfg(feature = "syscall_test")]
        self.report("ok", 0, 0, self.live.abs_diff(self.pages));
        mem::take(&mut self.recorder.pt_frames)
    }

    /// Hand a rolled-back operation's tables to its caller's error arm.
    pub(crate) fn into_failure(mut self, error: crate::populate::PopulateError) -> FailedPopulate {
        let failed = FailedPopulate::new(
            error,
            mem::take(&mut self.pruned),
            mem::take(&mut self.recorder.pt_frames),
        );
        #[cfg(feature = "syscall_test")]
        self.report(
            match error {
                crate::populate::PopulateError::Interrupted => "eintr",
                crate::populate::PopulateError::NoMemory(_) => "enomem",
            },
            failed.pruned.len(),
            failed.survivors,
            self.live,
        );
        failed
    }

    /// Whether `map_hold` stages spare page tables before a hold.
    pub(super) fn stages_spares(&self) -> bool {
        #[cfg(feature = "syscall_test")]
        {
            !self.starve_probe
        }
        #[cfg(not(feature = "syscall_test"))]
        {
            true
        }
    }

    #[cfg(feature = "syscall_test")]
    pub(super) fn note_hold(&mut self, pages: usize) {
        self.holds += 1;
        self.max_pages_per_hold = self.max_pages_per_hold.max(pages);
    }

    #[cfg(feature = "syscall_test")]
    pub(super) fn report(&self, result: &str, pruned: usize, survivors: usize, leaked: usize) {
        if self.pages >= POPULATE_REPORT_PAGES {
            klog_always!(
                "R192-RES-2 populate site={} pages={} holds={} max_pages_per_hold={} result={} pruned={} survivors={} leaked={} starved={}",
                self.site,
                self.pages,
                self.holds,
                self.max_pages_per_hold,
                result,
                pruned,
                survivors,
                leaked,
                self.starved
            );
        }
    }
}

impl Drop for EagerPopulator {
    /// Return the staged page-table frames no chunk used; as a leak guard, also
    /// tables still carried when the populator is dropped without
    /// `into_failure`.
    fn drop(&mut self) {
        for frame in self.tables.iter_mut().filter_map(Option::take) {
            self.recorder.deallocate_frame(frame);
        }
        for frame in self.pruned.drain(..) {
            self.recorder.deallocate_frame(frame);
        }
    }
}

impl crate::populate::PopulateBackend for EagerPopulator {
    type Frame = x86_64::structures::paging::PhysFrame;

    fn free_pages(&mut self) -> Option<usize> {
        mm::buddy_allocator::get_allocator_stats().map(|stats| stats.free_pages)
    }

    fn fatal_signal_pending(&mut self) -> bool {
        // Every fatal source (SIGKILL or a fatal default action, exit_group,
        // the OOM killer, an exec drain) sets `pending_kill`. A plain load: the
        // syscall epilogue consumes the flag.
        self.process
            .lock()
            .pending_kill
            .load(AtomicOrdering::Acquire)
    }

    fn alloc_zeroed(&mut self) -> Option<Self::Frame> {
        #[cfg(feature = "syscall_test")]
        {
            if self.fail_at == Some(self.allocated) {
                // ST-K2-P2(d): a re-armed failure may pause here first.
                crate::fork::shared_fault_test::before_population_failure();
                return None;
            }
            self.allocated += 1;
        }
        let frame = self.recorder.allocate_data_frame()?;
        #[cfg(feature = "syscall_test")]
        {
            self.live += 1;
        }
        // Issue #109 §1.3 (Invariant S2): `allocate_data_frame()` ->
        // `mm::buddy_allocator::alloc_physical_pages(1)` returns a frame that
        // was already scrubbed to all zeros on free or cold buddy refill, so
        // no second 4 KiB memset is needed before publishing to userspace.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        Some(frame)
    }

    fn alloc_zeroed_batch(&mut self, out: &mut [Self::Frame]) -> usize {
        if out.is_empty() {
            return 0;
        }
        // Preserve exact per-frame fault injection ordering when a test probe
        // is armed.
        #[cfg(feature = "syscall_test")]
        if self.fail_at.is_some() {
            for (index, slot) in out.iter_mut().enumerate() {
                match self.alloc_zeroed() {
                    Some(frame) => *slot = frame,
                    None => return index,
                }
            }
            return out.len();
        }
        let filled = mm::buddy_allocator::alloc_physical_pages_batch(out);
        #[cfg(feature = "syscall_test")]
        {
            self.allocated += filled;
            self.live += filled;
        }
        // Issue #109 §1.3 (Invariant S2): all frames returned by the batch
        // allocator are already scrubbed to zero before publication.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        filled
    }

    fn free_unmapped(&mut self, frame: Self::Frame) {
        #[cfg(feature = "syscall_test")]
        {
            self.live -= 1;
        }
        self.recorder.deallocate_frame(frame);
    }

    fn map_hold(&mut self, first: usize, frames: &[Self::Frame]) -> Result<(), usize> {
        use x86_64::structures::paging::Page;

        let start = self.base + first * PAGE_SIZE;
        let flags = self.flags;
        let use_batch = flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE)
            && !flags.contains(PageTableFlags::HUGE_PAGE);
        let mut done = 0;
        let failed = loop {
            // Stage spare page tables, and the record slots for them, before
            // the hold, so nothing inside it allocates. Spares come without the
            // buddy's OOM handling: most chunks need none, and reclaim (or a
            // kill) for a frame nobody uses would be worse than the old path.
            if self.stages_spares() {
                for slot in self.tables.iter_mut().filter(|slot| slot.is_none()) {
                    *slot = mm::buddy_allocator::try_with_allocator(|buddy| buddy.alloc_pages(0))
                        .flatten();
                }
            }
            let _ = self.recorder.pt_frames.try_reserve(POPULATE_TABLE_POOL);

            #[cfg(feature = "syscall_test")]
            self.note_hold(frames.len() - done);
            let mut tables = StagedTables::new(&mut self.tables, &mut self.recorder.pt_frames);
            let data = &mut self.recorder.inner;
            let pruned = &mut self.pruned;
            // SAFETY: the pages are this operation's reservation in the
            // current address space; the closure runs under PT_LOCK with
            // interrupts off.
            let outcome = unsafe {
                mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
                    if use_batch {
                        let staged = tables.pool.iter().flatten().count();
                        let start_page = Page::containing_address(VirtAddr::new(
                            (start + done * PAGE_SIZE) as u64,
                        ));
                        match manager.map_user_pages_no_flush(
                            start_page,
                            &frames[done..],
                            flags,
                            staged,
                            &mut tables,
                        ) {
                            Ok(()) => return MapHold::Done,
                            Err(mm::BatchMapUserError::Starved { mapped, shortfall }) => {
                                return MapHold::Starved(done + mapped, shortfall);
                            }
                            Err(mm::BatchMapUserError::Failed { mapped, .. }) => {
                                let index = done + mapped;
                                let freed = unmap_populated_pages(
                                    manager,
                                    data,
                                    start,
                                    index,
                                    index + 1,
                                    pruned,
                                );
                                return MapHold::Failed(index, freed);
                            }
                        }
                    }
                    for index in done..frames.len() {
                        let page = Page::containing_address(VirtAddr::new(
                            (start + index * PAGE_SIZE) as u64,
                        ));
                        // Never start a table chain the pool cannot finish:
                        // an empty table left linked while the lock is
                        // dropped could be pruned and freed by a sibling and
                        // then ledgered by our commit.
                        let staged = tables.pool.iter().flatten().count();
                        let missing = manager.missing_tables(page);
                        if missing > staged {
                            // Pages before `index` stay mapped; the
                            // reservation keeps them ours until we return.
                            return MapHold::Starved(index, missing - staged);
                        }
                        if manager
                            .map_page(page, frames[index], flags, &mut tables)
                            .is_err()
                        {
                            // Undo this chunk before the lock is released,
                            // pruning the failing page too: map_page may have
                            // built its tables.
                            let freed = unmap_populated_pages(
                                manager,
                                data,
                                start,
                                index,
                                index + 1,
                                pruned,
                            );
                            return MapHold::Failed(index, freed);
                        }
                    }
                    MapHold::Done
                })
            };
            match outcome {
                MapHold::Done => return Ok(()),
                MapHold::Failed(index, freed) => break (index, freed),
                MapHold::Starved(index, shortfall) => {
                    done = index;
                    #[cfg(feature = "syscall_test")]
                    {
                        self.starved += 1;
                    }
                    // The page needs tables that were not staged: take them
                    // with the buddy's OOM handling, still with no lock held,
                    // and map the rest of the chunk in another hold. A
                    // sibling may change the walk meanwhile; the next hold
                    // counts again, and the pool (6) covers any page (3).
                    let mut filled = 0;
                    for slot in self.tables.iter_mut().filter(|slot| slot.is_none()) {
                        if filled == shortfall {
                            break;
                        }
                        *slot = self.recorder.inner.allocate_frame();
                        if slot.is_none() {
                            break;
                        }
                        filled += 1;
                    }
                    if filled == shortfall {
                        continue;
                    }
                    #[cfg(feature = "syscall_test")]
                    self.note_hold(index);
                    let data = &mut self.recorder.inner;
                    let pruned = &mut self.pruned;
                    // SAFETY: as above; pages `..index` were mapped by this
                    // population.
                    let freed = unsafe {
                        mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
                            unmap_populated_pages(manager, data, start, index, index + 1, pruned)
                        })
                    };
                    break (index, freed);
                }
            }
        };
        let (index, _freed) = failed;
        #[cfg(feature = "syscall_test")]
        {
            self.live -= _freed;
        }
        Err(index)
    }

    fn unmap_hold(&mut self, first: usize, count: usize) {
        #[cfg(feature = "syscall_test")]
        self.note_hold(count);
        let start = self.base + first * PAGE_SIZE;
        let data = &mut self.recorder.inner;
        let pruned = &mut self.pruned;
        // SAFETY: as in `map_hold`; every page was mapped by this population.
        let _freed = unsafe {
            mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
                unmap_populated_pages(manager, data, start, count, count, pruned)
            })
        };
        #[cfg(feature = "syscall_test")]
        {
            self.live -= _freed;
        }
    }
}

/// R192-RES-2: how one `map_hold` hold ended.
pub(super) enum MapHold {
    Done,
    /// `map_page` failed at this index and the chunk was rolled back; the
    /// number of data frames freed.
    Failed(usize, usize),
    /// The page at this index needs this many more tables than were staged;
    /// nothing was built for it.
    Starved(usize, usize),
}

/// R192-RES-2: the page-table frame source of one `map_hold`. It hands out the
/// frames staged before the hold and records each one it hands out, into
/// capacity reserved before the hold; it never allocates, so the buddy's OOM
/// handling cannot run under `PT_LOCK`. `map_page` zeroes each frame before
/// `map_to` links it (LEAD-PT-ZERO-LINK-1).
pub(super) struct StagedTables<'a> {
    pub(super) pool: &'a mut [Option<x86_64::structures::paging::PhysFrame>],
    /// Slots before this index are spent (R192-RES-2a: O(1) per frame for the
    /// relocation's pool of hundreds).
    pub(super) next: usize,
    pub(super) recorded: &'a mut Vec<x86_64::structures::paging::PhysFrame>,
}

impl<'a> StagedTables<'a> {
    pub(super) fn new(
        pool: &'a mut [Option<x86_64::structures::paging::PhysFrame>],
        recorded: &'a mut Vec<x86_64::structures::paging::PhysFrame>,
    ) -> Self {
        Self {
            pool,
            next: 0,
            recorded,
        }
    }
}

unsafe impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>
    for StagedTables<'_>
{
    fn allocate_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
        // Record before the frame can become a live table, like
        // `RecordingFrameAllocator`: no unrecorded table may exist.
        if self.recorded.len() == self.recorded.capacity() {
            return None;
        }
        while let Some(slot) = self.pool.get_mut(self.next) {
            self.next += 1;
            if let Some(frame) = slot.take() {
                self.recorded.push(frame);
                return Some(frame);
            }
        }
        None
    }
}

/// R192-RES-2: inside a hold, unmap the first `count` pages at `start`, all
/// mapped by this population, flush them on every CPU, free their data frames,
/// then prune the tables of the first `prune` pages into `pruned`. Returns the
/// number of data frames freed. Pruned tables are carried, not freed: one may
/// still be in the ledger (LEAD-ROLLBACK-PRUNE-LEDGER-1), so it reaches the
/// buddy only after the caller's settlement removed it.
///
/// # Safety
/// The caller holds PT_LOCK (inside `with_current_manager`), `count` is at most
/// one chunk and the pages belong to this population's reservation.
pub(super) unsafe fn unmap_populated_pages(
    manager: &mut mm::page_table::PageTableManager,
    _data: &mut mm::memory::FrameAllocator,
    start: usize,
    count: usize,
    prune: usize,
    pruned: &mut Vec<x86_64::structures::paging::PhysFrame>,
) -> usize {
    use x86_64::structures::paging::PhysFrame;
    use x86_64::PhysAddr;

    debug_assert!(count <= crate::populate::POPULATE_CHUNK_PAGES);
    let mut frames =
        [PhysFrame::containing_address(PhysAddr::new(0)); crate::populate::POPULATE_CHUNK_PAGES];
    let mut removed = 0usize;
    if count != 0 {
        manager.unmap_user_range_no_flush(
            VirtAddr::new(start as u64),
            count * PAGE_SIZE,
            |_page, frame| {
                if removed < frames.len() {
                    frames[removed] = frame;
                    removed += 1;
                }
            },
        );
    }
    let pruned_any = manager.prune_empty_tables_in_range_no_flush(
        VirtAddr::new(start as u64),
        prune * PAGE_SIZE,
        pruned,
    );
    if pruned_any {
        mm::flush_current_as_all();
    } else if removed != 0 {
        mm::flush_current_as_range(VirtAddr::new(start as u64), count * PAGE_SIZE);
    }
    if removed != 0 {
        mm::buddy_allocator::free_physical_pages_batch(&frames[..removed]);
    }
    removed
}

/// R192-RES-2: what a failed population leaves for its caller's error arm:
/// the error, the table frames its rollback detached (still out of the buddy)
/// and how many page-table frames it built and did not prune.
pub(crate) struct FailedPopulate {
    pub(crate) error: crate::populate::PopulateError,
    pub(super) pruned: Vec<x86_64::structures::paging::PhysFrame>,
    pub(super) survivors: usize,
}

impl FailedPopulate {
    /// Count the survivors here, outside the caller's locks (the stack grow,
    /// at most 512 pages, calls it inside its hold): sorting keeps it
    /// `O(n log n)` for a population of any size.
    pub(super) fn new(
        error: crate::populate::PopulateError,
        mut pruned: Vec<x86_64::structures::paging::PhysFrame>,
        mut recorded: Vec<x86_64::structures::paging::PhysFrame>,
    ) -> Self {
        let survivors = crate::populate::count_unpruned(&mut recorded, &mut pruned);
        Self {
            error,
            pruned,
            survivors,
        }
    }

    /// Account the population's page tables under the caller's
    /// `Process -> MmState` hold (`MmState::settle_failed_populate`): debit the
    /// ledgered tables it pruned, force-charge the ones it built and did not
    /// prune. The pruned frames are freed when `self` drops, which the caller
    /// does after releasing that hold (free-after-remove, as in munmap).
    pub(crate) fn settle(&self, mm: &mut crate::process::MmState, cgroup_id: cgroup::CgroupId) {
        let (debit, charge) = mm.settle_failed_populate(&self.pruned, self.survivors);
        if debit > 0 {
            cgroup::uncharge_memory(cgroup_id, debit);
        }
        if charge > 0 {
            cgroup::charge_memory_forced(cgroup_id, charge);
        }
    }
}

impl Drop for FailedPopulate {
    fn drop(&mut self) {
        let mut allocator = mm::memory::FrameAllocator::new();
        for frame in self.pruned.drain(..) {
            allocator.deallocate_frame(frame);
        }
    }
}

/// M0-7 slice 2 (SLICE 1): resolve an AUTO-selected (`addr==0`) mmap base so it SKIPS the
/// reserved stack window instead of failing inside it. If `[candidate, candidate+length)`
/// intersects `[win_start, win_end)`, advance to `win_end` (the tail gap above the window);
/// otherwise keep the candidate. Pure → the boot self-test pins it without a live process.
/// (Reachable via one large PROT_NONE reservation driving `next_mmap_addr` to the window —
/// Codex impl-diff.)
pub(super) fn resolve_auto_mmap_base(
    candidate: usize,
    length: usize,
    win_start: usize,
    win_end: usize,
) -> usize {
    if candidate < win_end && candidate.saturating_add(length) > win_start {
        win_end
    } else {
        candidate
    }
}

/// R192-RES-3: how `sys_mmap` chooses its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MmapArm {
    /// `addr == 0`: the bump pointer `next_mmap_addr`.
    Auto,
    /// `addr != 0` without `MAP_FIXED_NOREPLACE`: try the hint's page, else
    /// place automatically.
    Hint,
    /// `MAP_FIXED_NOREPLACE`: exactly `addr`, never replacing anything.
    Exact,
}

/// R192-RES-3: why `[base, base + len)` cannot take a new mapping, in the
/// order Linux checks a fixed address (`__get_unmapped_area`, then the
/// `MAP_FIXED_NOREPLACE` overlap in `do_mmap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MmapRangeError {
    /// The end overflows or passes `USER_SPACE_TOP`.
    PastTop,
    Unaligned,
    /// Below `MMAP_MIN_ADDR`.
    BelowMin,
    /// The stack window, a VMA (pending ones too), an in-flight `brk` grow
    /// or an untracked translation.
    Occupied,
    /// A VMA record whose end overflows: never a fallback.
    Corrupt,
}

/// R192-RES-3: the errno of an arm whose candidate failed, or `None` when a
/// hint falls back to automatic placement. Pure, so the boot oracle pins it.
pub(super) fn mmap_range_errno(arm: MmapArm, error: MmapRangeError) -> Option<SyscallError> {
    use MmapRangeError::{BelowMin, Corrupt, Occupied, PastTop, Unaligned};
    Some(match (arm, error) {
        (_, Corrupt) => SyscallError::EFAULT,
        (MmapArm::Hint, _) => return None,
        // The automatic arm's errors predate R192-RES-3 (Linux: ENOMEM for no room).
        (MmapArm::Auto, PastTop) => SyscallError::EFAULT,
        (MmapArm::Auto, BelowMin) => SyscallError::EPERM,
        (MmapArm::Auto, Unaligned | Occupied) => SyscallError::EINVAL,
        (MmapArm::Exact, PastTop) => SyscallError::ENOMEM,
        (MmapArm::Exact, Unaligned) => SyscallError::EINVAL,
        (MmapArm::Exact, BelowMin) => SyscallError::EPERM,
        (MmapArm::Exact, Occupied) => SyscallError::EEXIST,
    })
}

/// The automatic arm's candidate: the bump pointer, page aligned, at least
/// `MMAP_MIN_ADDR` (R65-11), moved past the reserved stack window.
pub(super) fn auto_mmap_base(
    mm: &crate::process::MmState,
    length: usize,
) -> Result<usize, SyscallError> {
    let candidate = mm
        .next_mmap_addr
        .checked_add(0xfff)
        .ok_or(SyscallError::EINVAL)?
        & !0xfff;
    let candidate = candidate.max(crate::usercopy::MMAP_MIN_ADDR);
    // M0-7 slice 2 (SLICE 1): auto-placement must SKIP the reserved stack window,
    // not fail INSIDE it. A single large PROT_NONE reservation (no RAM, no cgroup
    // charge) can advance next_mmap_addr up to the window base in ONE VMA (Codex
    // impl-diff: reachable, not the theoretical 128-TiB case), so without this a
    // later small auto-mmap would get a FALSE ENOMEM while the tail gap
    // [USER_STACK_TOP, USER_SPACE_TOP) is still free. Jump past the window; an
    // over-large request is still rejected by the USER_SPACE_TOP check.
    let (win_start, win_end) = crate::elf_loader::user_mapping_reserved_window();
    Ok(resolve_auto_mmap_base(
        candidate, length, win_start, win_end,
    ))
}

/// R192-RES-3: whether `[base, base + len)` can take a new mapping; its end.
/// Called under the `MmState` lock of Phase 1, so the answer holds until the
/// caller's `PENDING_MAP` insert.
pub(super) fn check_mmap_range(
    mm: &crate::process::MmState,
    base: usize,
    len: usize,
) -> Result<usize, MmapRangeError> {
    let end = base
        .checked_add(len)
        .filter(|&end| end <= USER_SPACE_TOP)
        .ok_or(MmapRangeError::PastTop)?;
    if base & 0xfff != 0 {
        return Err(MmapRangeError::Unaligned);
    }
    // R65-11 FIX: no mapping below MMAP_MIN_ADDR (NULL dereference exploitation).
    if base < crate::usercopy::MMAP_MIN_ADDR {
        return Err(MmapRangeError::BelowMin);
    }

    // M0-7 slice 2 (SLICE 1): the reserved user-stack window [stack_base,
    // USER_STACK_TOP) (guard-INCLUSIVE) is the "third door": USER_SPACE_TOP lies
    // 0x2000 ABOVE it, and the stack is NEVER in `mmap_regions` (that would
    // make free_address_space/munmap double-free it, R123-1). A mapping there
    // would alias the stack. Half-open intersection with a fixed VA range
    // (TOCTOU-free); the automatic candidate has already skipped it.
    let (win_start, win_end) = crate::elf_loader::user_mapping_reserved_window();
    if base < win_end && end > win_start {
        return Err(MmapRangeError::Occupied);
    }

    // Existing mappings; pending entries count as occupied.
    for (&region_base, &region_len_with_flags) in mm.mmap_regions.iter() {
        let region_end = region_base
            .checked_add(mmap_region_len(region_len_with_flags))
            .ok_or(MmapRangeError::Corrupt)?;
        if base < region_end && end > region_base {
            return Err(MmapRangeError::Occupied);
        }
    }

    // R172-16: a sibling sys_brk grow on this shared MmState (CLONE_VM /
    // CLONE_THREAD) reserves its in-flight [old_top, new_top) heap-grow range
    // while it drops the MmState lock for page-table work; a mapping there
    // would be adopted into the heap. Inactive ⇔ lo == hi.
    if mm.brk_grow_resv_lo < mm.brk_grow_resv_hi
        && base < mm.brk_grow_resv_hi
        && end > mm.brk_grow_resv_lo
    {
        return Err(MmapRangeError::Occupied);
    }

    // R192-2 FIX (D0-ISO-1) + LEAD-MMAP-OWN-1: nothing in mmap_regions records
    // the ELF image or the committed heap. A VMA over either would let
    // munmap/mprotect/mremap/exit treat those pages as this mapping's (a
    // PROT_NONE reservation followed by munmap removed the task's own text). The
    // checks above passed, so any translation in the range belongs to one of
    // them. Lock-free walk (see `first_occupied_user_page`).
    if mm::page_table::first_occupied_user_page(base as u64, len as u64).is_some() {
        return Err(MmapRangeError::Occupied);
    }
    Ok(end)
}

/// M0-7 slice 2 (SLICE 1) self-test: pin the third-door stack-window exclusion logic used
/// by `sys_mmap` (half-open `[base,end)` intersection) and `sys_brk` (`page_align_up(addr)
/// > window_start`). PURE — it exercises the SAME `user_stack_window()` const + the SAME
/// `page_align_up` the live paths use, so it cannot pass while the runtime checks drift
/// (e.g. to the guard_top floor) or get the half-open boundary off-by-one (which would
/// spuriously reject a legal mmap exactly at `USER_STACK_TOP`). It does NOT call sys_mmap /
/// sys_brk (those need a live process + MmState; a boot self-test has neither schedulably).
pub fn run_stack_window_exclusion_self_test() {
    let (win_start, win_end) = crate::elf_loader::user_stack_window();
    let page = 0x1000usize;

    // The window is the GUARD-INCLUSIVE architectural range, never the guard_top floor.
    let (stack_base, usable_base, eager_floor, _eager_page_count) =
        crate::elf_loader::user_stack_layout();
    assert_eq!(
        win_start, stack_base,
        "window base MUST be the guard-INCLUSIVE stack_base, not guard_top/usable_base"
    );
    assert!(
        win_start < usable_base,
        "the guard page [stack_base, usable_base) MUST be inside the excluded window"
    );
    assert_eq!(
        win_end,
        crate::elf_loader::USER_STACK_TOP as usize,
        "window end MUST be USER_STACK_TOP"
    );

    // sys_mmap half-open intersection: [base,end) is excluded iff base < win_end && end > win_start.
    let mmap_excluded = |base: usize, end: usize| base < win_end && end > win_start;
    // INSIDE the window: the guard page (stack_base), guard_top, and the topmost eager page.
    assert!(
        mmap_excluded(win_start, win_start + page),
        "mmap AT stack_base (window low edge / guard page) must be excluded"
    );
    assert!(
        mmap_excluded(usable_base, usable_base + page),
        "mmap at guard_top (first mapped eager page) must be excluded"
    );
    assert!(
        mmap_excluded(win_end - page, win_end),
        "mmap at the topmost eager page must be excluded"
    );
    // BOUNDARY half-open exactness: a mapping ENDING exactly at stack_base (entirely below)
    // and one STARTING exactly at USER_STACK_TOP (entirely above) are BOTH legal.
    assert!(
        !mmap_excluded(win_start - page, win_start),
        "mmap ending exactly at stack_base (below the window) must be allowed"
    );
    assert!(
        !mmap_excluded(win_end, win_end + page),
        "mmap starting exactly at USER_STACK_TOP (above the window) must be allowed"
    );

    // R172-X-F3: sys_mprotect is the third page-permission door; pin it to the SAME
    // single-sourced window const and the SAME half-open predicate as sys_mmap so it
    // cannot drift to guard_top or flip the boundary independently.
    let mprotect_rejects = |addr: usize, end: usize| addr < win_end && end > win_start;
    assert!(
        mprotect_rejects(win_start, win_start + page),
        "mprotect AT stack_base (guard page) must be rejected"
    );
    assert!(
        mprotect_rejects(usable_base, usable_base + page),
        "mprotect at guard_top (first mapped eager page) must be rejected"
    );
    assert!(
        mprotect_rejects(win_end - page, win_end),
        "mprotect at the topmost eager page must be rejected"
    );
    assert!(
        mprotect_rejects(win_start, win_end),
        "mprotect spanning the whole window must be rejected"
    );
    assert!(
        !mprotect_rejects(win_start - page, win_start),
        "mprotect ending exactly at stack_base (below the window) must be allowed"
    );
    assert!(
        !mprotect_rejects(win_end, win_end + page),
        "mprotect starting exactly at USER_STACK_TOP (above the window) must be allowed"
    );

    // sys_brk ceiling: page_align_up(new_break) > window_start is rejected; == is allowed.
    let brk_rejects = |addr: usize| page_align_up(addr) > win_start;
    assert!(
        !brk_rejects(win_start),
        "brk grow to exactly window_start (heap entirely below the window) must be allowed"
    );
    assert!(
        brk_rejects(win_start + 1),
        "brk grow that page-rounds INTO the window must be rejected"
    );
    assert!(
        brk_rejects(win_end - page),
        "brk grow deep into the window must be rejected"
    );

    // Auto-placement (addr==0) SKIPS the window to the tail gap rather than a false ENOMEM
    // inside it (the PROT_NONE-reservation reachability Codex flagged).
    assert_eq!(
        resolve_auto_mmap_base(win_start, page, win_start, win_end),
        win_end,
        "an auto base AT stack_base must skip to win_end (USER_STACK_TOP), not fail inside the window"
    );
    assert_eq!(
        resolve_auto_mmap_base(win_start - page, page, win_start, win_end),
        win_start - page,
        "an auto base whose range stays entirely below the window is unchanged"
    );
    assert_eq!(
        resolve_auto_mmap_base(win_end, page, win_start, win_end),
        win_end,
        "an auto base already AT the tail (== win_end) is unchanged (no double-skip)"
    );
    // A range starting below but CROSSING into the window also skips (large auto request).
    assert_eq!(
        resolve_auto_mmap_base(win_start - page, page * 4, win_start, win_end),
        win_end,
        "an auto range crossing into the window from below must skip to win_end"
    );

    // R172-16: the brk-grow VA reservation uses the SAME half-open intersection predicate
    // as the mmap-overlap check, with `lo < hi` gating an ACTIVE reservation.
    let resv_intersects =
        |lo: usize, hi: usize, base: usize, end: usize| lo < hi && base < hi && end > lo;
    let (r_lo, r_hi) = (0x1000_0000usize, 0x1000_4000usize); // a 4-page in-flight grow window
    assert!(
        resv_intersects(r_lo, r_hi, r_lo, r_lo + page),
        "mmap at the reservation low edge must intersect (rejected)"
    );
    assert!(
        resv_intersects(r_lo, r_hi, r_hi - page, r_hi),
        "mmap at the reservation high edge must intersect (rejected)"
    );
    assert!(
        !resv_intersects(r_lo, r_hi, r_lo - page, r_lo),
        "mmap ending exactly at the reservation low edge is allowed"
    );
    assert!(
        !resv_intersects(r_lo, r_hi, r_hi, r_hi + page),
        "mmap starting exactly at the reservation high edge is allowed"
    );
    assert!(
        !resv_intersects(0, 0, r_lo, r_hi),
        "an inactive reservation (lo == hi) never intersects"
    );

    // RF178-12 FIX: mapped and usable floors are distinct. The committed floor
    // starts at the eager mapping; RLIMIT_STACK spans down to guard_top.
    let floor = crate::elf_loader::user_stack_mapped_floor();
    assert_eq!(
        floor as usize, eager_floor,
        "mapped_floor() MUST equal user_stack_layout().2 (eager_floor)"
    );
    assert_eq!(
        crate::elf_loader::user_stack_usable_floor() as usize,
        win_start + crate::elf_loader::USER_STACK_GUARD_SIZE,
        "usable_floor() MUST equal window_start + USER_STACK_GUARD_SIZE"
    );
    // The RLIMIT_STACK magnitude is exactly TOP - usable_floor.
    assert_eq!(
        crate::elf_loader::USER_STACK_TOP - crate::elf_loader::user_stack_usable_floor(),
        (crate::elf_loader::USER_STACK_SIZE - crate::elf_loader::USER_STACK_GUARD_SIZE) as u64,
        "RLIMIT_STACK magnitude (TOP - usable_floor) MUST equal SIZE - GUARD"
    );
}

/// sys_mmap - 内存映射
///
/// 使用当前进程的地址空间进行映射，确保进程隔离
pub(super) fn sys_mmap(
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    _offset: i64,
) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1050); // sys_mmap entry
    }

    use x86_64::structures::paging::PageTableFlags;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证参数
    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    // R30-2 FIX: Enforce W^X policy - reject PROT_WRITE | PROT_EXEC
    // PROT_WRITE = 0x2, PROT_EXEC = 0x4
    // Mirrors the check in sys_mprotect for consistency
    if (prot & 0x2 != 0) && (prot & 0x4 != 0) {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1051); // sys_mmap W^X violation
        }
        return Err(SyscallError::EPERM);
    }

    // R29-3 FIX: Call the LSM hook before the ST-K2 flag boundary so policy
    // audit records survive rejected MAP_SHARED/MAP_FIXED/unknown requests.
    // R192-5 FIX: a missing subject fails closed, never skips the hook.
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
    if lsm::hook_memory_mmap(&ctx, addr as u64, length as u64, prot as u32, flags as u32).is_err() {
        return Err(SyscallError::EPERM);
    }

    // ST-K2 FIX: reject every flag shape whose semantics are not implemented.
    // This includes MAP_SHARED without MAP_ANONYMOUS, MAP_SHARED_VALIDATE,
    // MAP_FIXED, missing MAP_ANONYMOUS, and unknown bits. The check is before
    // any VMA/cgroup/page-table mutation and after the LSM hook above.
    let shape = match validate_mmap_flags(flags) {
        Ok(shape) => shape,
        Err(error) => {
            #[cfg(feature = "kcov")]
            {
                coverage::trace_pc(1052); // sys_mmap unsupported flags
            }
            return Err(error);
        }
    };

    // File-backed mappings remain outside this phase even when the flag word is
    // otherwise valid.  Keep the stable EOPNOTSUPP boundary after LSM/flags.
    if fd >= 0 {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1053); // sys_mmap file-backed unsupported
        }
        return Err(SyscallError::EOPNOTSUPP);
    }

    let is_shared = shape.shared;

    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1054); // sys_mmap anonymous mapping path
    }

    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    let is_prot_none = prot == PROT_NONE;
    if is_shared && is_prot_none {
        // A shared PROT_NONE reservation needs the demand-fault region object
        // from the full Phase-2 design; reject it until that object exists.
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R32-SC-1 FIX: PROT_NONE (prot=0) should create non-present mapping
    // that faults on access (guard page behavior). Mirror sys_mprotect.
    let mut page_flags = if is_prot_none {
        PageTableFlags::empty()
    } else {
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
    };

    // PROT_WRITE
    if prot & 0x2 != 0 {
        page_flags |= PageTableFlags::WRITABLE;
    }

    // PROT_EXEC (x86_64使用NX位表示不可执行)
    if prot & 0x4 == 0 {
        page_flags |= PageTableFlags::NO_EXECUTE;
    }

    // R121-4 FIX (was R65-9): Three-phase mmap to respect documented lock
    // ordering (PT_LOCK before Process::inner in lock_ordering.rs) while still
    // preventing address-space races.
    //
    // Phase 1 (Process lock): select/validate address, reserve in mmap_regions
    //   with a PENDING_MAP flag so concurrent mmap/munmap see it as occupied.
    // Phase 2 (no Process lock): populate through EagerPopulator, whose bounded
    //   with_current_manager() holds acquire PT_LOCK (R192-RES-2).
    // Phase 3 (Process lock): commit (clear pending flag), or rollback on failure.
    let arm = if shape.exact {
        MmapArm::Exact
    } else if addr == 0 {
        MmapArm::Auto
    } else {
        MmapArm::Hint
    };

    // D3-ARC-MM-SHARED: Phase 1 operates on shared MmState via mm Arc.
    let (base, end, update_next, cgroup_id, old_next_mmap_addr, mm_arc, shared_region) = {
        let mut proc = process.lock();
        let mm_arc: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>> =
            Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        if mm.fork_in_progress {
            return Err(SyscallError::EAGAIN);
        }

        // R130-1 FIX: Bound mmap_regions to prevent kernel heap exhaustion DoS.
        // Without this check, unlimited PROT_NONE (or normal) mmaps can grow
        // the BTreeMap until alloc_error_handler panics the kernel. R192-RES-3:
        // checked before placement for every arm, as Linux checks map_count
        // before choosing the address.
        if mm.mmap_regions.len() >= MAX_MAP_COUNT {
            // ST-K3 Phase D: permanent debug-build site tag (E1). No addresses,
            // no data beyond the requested size — R159-17 gating style.
            #[cfg(debug_assertions)]
            kprintln!(
                "[ST-K3] mmap ENOMEM site=E1 stage=max_map_count len={} regions={}",
                length_aligned,
                mm.mmap_regions.len()
            );
            return Err(SyscallError::ENOMEM);
        }

        // R192-RES-3: place the mapping. A hint is tried at its page (rounded
        // down, as Linux's round_hint_to_min) and, when that range is unusable,
        // the mapping is placed automatically instead; MAP_FIXED_NOREPLACE
        // takes exactly `addr` or fails without touching anything. Only the
        // automatic placement moves the bump pointer in this phase.
        let first = match arm {
            MmapArm::Auto => auto_mmap_base(&mm, length_aligned)?,
            MmapArm::Hint => addr & !0xfff,
            MmapArm::Exact => addr,
        };
        let (base, end, update_next) = match check_mmap_range(&mm, first, length_aligned) {
            Ok(end) => {
                #[cfg(feature = "kcov")]
                if arm == MmapArm::Exact {
                    coverage::trace_pc(1056); // sys_mmap exact placement
                }
                (first, end, arm == MmapArm::Auto)
            }
            Err(error) => {
                if let Some(errno) = mmap_range_errno(arm, error) {
                    #[cfg(feature = "kcov")]
                    if arm == MmapArm::Exact {
                        coverage::trace_pc(1057); // sys_mmap exact placement refused
                    }
                    return Err(errno);
                }
                #[cfg(feature = "kcov")]
                {
                    coverage::trace_pc(1055); // sys_mmap hint fallback
                }
                let base = auto_mmap_base(&mm, length_aligned)?;
                let end = check_mmap_range(&mm, base, length_aligned).map_err(|error| {
                    mmap_range_errno(MmapArm::Auto, error).unwrap_or(SyscallError::EINVAL)
                })?;
                (base, end, true)
            }
        };

        // ST-K2-P2: shared mappings reserve only bounded region metadata here;
        // their DATA charge is taken by the first page fault. Private mappings
        // retain the eager whole-range cgroup charge so memory.max / OOM / exact
        // return-to-baseline accounting remain unchanged, while default
        // `MAP_PRIVATE | MAP_ANONYMOUS` (without `MAP_POPULATE`) defers physical
        // frame allocation and PTE installation to first page fault.
        let is_lazy_private = !is_prot_none && !is_shared && !shape.populate;
        if is_lazy_private {
            let pages = length_aligned / 0x1000;
            if mm::buddy_allocator::get_allocator_stats()
                .is_some_and(|stats| pages > stats.free_pages)
            {
                return Err(SyscallError::ENOMEM);
            }
            mm.reserve_shared_fault_pt(Some((base, length_aligned)))
                .map_err(|_| SyscallError::ENOMEM)?;
            if let Err(_charge_err) =
                cgroup::try_charge_memory(proc.cgroup_id, length_aligned as u64)
            {
                mm.reclaim_empty_shared_fault_pt_capacity();
                #[cfg(debug_assertions)]
                kprintln!(
                    "[ST-K3] mmap ENOMEM site=E2 stage=cgroup_charge cgroup={} len={} err={:?}",
                    proc.cgroup_id,
                    length_aligned,
                    _charge_err
                );
                return Err(SyscallError::ENOMEM);
            }
            let prot_flags = mmap_prot_to_flags(prot);
            let committed_entry = MmapEntry::from_len_flags(
                length_aligned,
                prot_flags | MMAP_REGION_FLAG_LAZY_ANON | MMAP_REGION_FLAG_UNFAULTED,
            );
            debug_validate_mmap_entry(committed_entry);
            if mm.mmap_regions.try_insert(base, committed_entry).is_err() {
                cgroup::uncharge_memory(proc.cgroup_id, length_aligned as u64);
                mm.reclaim_empty_shared_fault_pt_capacity();
                return Err(SyscallError::ENOMEM);
            }
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(length_aligned as u64);
            if mm.next_mmap_addr < end {
                mm.next_mmap_addr = end;
            }
            drop(mm);
            drop(proc);
            return Ok(base);
        }

        let shared_region = if is_shared {
            let region = crate::fork::SharedAnonRegion::try_new(base, length_aligned, prot)
                .map_err(|_| SyscallError::ENOMEM)?;
            mm.reserve_shared_fault_pt(Some((base, length_aligned)))
                .map_err(|_| SyscallError::ENOMEM)?;
            Some(region)
        } else {
            None
        };

        // R147-I1 FIX: Charge cgroup memory BEFORE inserting PENDING_MAP entry.
        if !is_prot_none && !is_shared {
            // ST-K3 Phase D: bind the error so the E2 tag names the variant;
            // the early-return semantics are unchanged.
            if let Err(_charge_err) =
                cgroup::try_charge_memory(proc.cgroup_id, length_aligned as u64)
            {
                #[cfg(debug_assertions)]
                kprintln!(
                    "[ST-K3] mmap ENOMEM site=E2 stage=cgroup_charge cgroup={} len={} err={:?}",
                    proc.cgroup_id,
                    length_aligned,
                    _charge_err
                );
                return Err(SyscallError::ENOMEM);
            }
        }

        // Reserve the region with PENDING_MAP flag before dropping locks.
        let phase1_flags = MMAP_REGION_FLAG_PENDING_MAP
            | if is_prot_none {
                MMAP_REGION_FLAG_PROT_NONE
            } else {
                0
            }
            | if is_shared {
                MMAP_REGION_FLAG_SHARED
            } else {
                0
            };
        // next-phase #11: fallible insert. `base` is a new key (overlap-checked
        // above), so this allocates a slot. On OOM, roll back the cgroup charge
        // made for the non-PROT_NONE case before returning ENOMEM — otherwise the
        // charge would leak with no region to account for it.
        if mm
            .mmap_regions
            .try_insert(
                base,
                MmapEntry::from_len_flags(length_aligned, phase1_flags),
            )
            .is_err()
        {
            if !is_prot_none && !is_shared {
                cgroup::uncharge_memory(proc.cgroup_id, length_aligned as u64);
            }
            drop(shared_region);
            mm.reclaim_empty_shared_fault_pt_capacity();
            // ST-K3 Phase D: site tag (E3) — Phase-1 VMA-map heap admission.
            #[cfg(debug_assertions)]
            kprintln!(
                "[ST-K3] mmap ENOMEM site=E3 stage=phase1_admission len={} regions={}",
                length_aligned,
                mm.mmap_regions.len()
            );
            return Err(SyscallError::ENOMEM);
        }

        if let Some(region) = shared_region.as_ref() {
            if mm
                .shared_regions
                .try_insert(base, Arc::clone(region))
                .is_err()
            {
                mm.mmap_regions.remove(&base);
                drop(shared_region);
                mm.reclaim_empty_shared_fault_pt_capacity();
                return Err(SyscallError::ENOMEM);
            }
        }

        // Advance next_mmap_addr early so concurrent auto-mmaps don't collide.
        let old_next_mmap_addr = mm.next_mmap_addr;
        if update_next && mm.next_mmap_addr < end {
            mm.next_mmap_addr = end;
        }

        let cgroup_id = proc.cgroup_id;
        drop(mm);
        (
            base,
            end,
            update_next,
            cgroup_id,
            old_next_mmap_addr,
            mm_arc,
            shared_region,
        )
    }; // Process lock + MmState lock dropped here — Phase 1 complete

    // R123-1 FIX: PROT_NONE is a pure address reservation per POSIX semantics.
    // No physical frames are allocated and no cgroup memory is charged until
    // protections are elevated (e.g. via mprotect) and a page fault triggers
    // demand allocation. The mmap_regions entry is committed with the
    // PROT_NONE flag so munmap/exit know not to uncharge or free frames.
    if is_prot_none {
        let len_with_flags = MmapEntry::prot_none(length_aligned);
        {
            let mut mm = mm_arc.lock();
            debug_validate_mmap_entry(len_with_flags);
            // next-phase #11: `base` is still present from Phase 1 (its
            // PENDING_MAP marker makes concurrent munmap/mprotect/fork bail), so
            // this is an in-place replace that never allocates; map_err keeps the
            // path total even in the impossible-realloc case.
            // ST-K3 Phase D: site tag (E4) — annotated-unreachable; the tag
            // exists to FALSIFY that annotation if it ever fires.
            mm.mmap_regions
                .try_insert(base, len_with_flags)
                .map_err(|_| {
                    #[cfg(debug_assertions)]
                    kprintln!(
                        "[ST-K3] mmap ENOMEM site=E4 stage=prot_none_commit len={}",
                        length_aligned
                    );
                    SyscallError::ENOMEM
                })?;
            if mm.next_mmap_addr < end {
                mm.next_mmap_addr = end;
            }
        }

        // D3-ARC-MM-SHARED: sync_vm_siblings_add_mmap is no longer needed — all
        // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

        // R159-17 FIX: Gate address-revealing log behind debug_assertions.
        #[cfg(debug_assertions)]
        kprintln!(
            "sys_mmap: pid={}, reserved {} bytes at 0x{:x} (PROT_NONE, no frames)",
            pid,
            length_aligned,
            base
        );

        return Ok(base);
    }

    // R147-I1 FIX: Cgroup charge moved into Phase 1 (under process lock, before
    // PENDING_MAP insert). This eliminates the window where migration could
    // snapshot an uncharged PENDING_MAP entry. The old standalone charge call
    // and its rollback are no longer needed.

    // R192-RES-2: populate the range in bounded holds. Frames are allocated and
    // zeroed with no lock held, at most POPULATE_CHUNK_PAGES pages are mapped
    // per PT_LOCK hold, and a fatal signal between chunks aborts the call. A
    // failure unmaps the range again and hands its tables to the error arm.
    // J2-9 / R171-CG1x0: on success the populator yields the IDENTITIES of the
    // page-table frames it built, charged and ledgered in Phase 3 after PT_LOCK
    // is dropped (never a cgroup charge under PT_LOCK).
    // ST-K2-P2: shared-anonymous mappings are demand-paged. The VMA and side
    // map were committed in Phase 1; leaf PTEs stay absent until a first
    // access invokes `handle_shared_page_fault`.
    let map_result = if is_shared {
        Ok(vec::Vec::new())
    } else {
        EagerPopulator::new("mmap", &process, base, length_aligned / 0x1000, page_flags).run()
    };

    // F.2 Cgroup: If mapping fails, rollback the memory charge and Phase 1
    // reservation to maintain correct accounting.
    // R148-2 FIX: Remove reservation under process lock AND capture current
    // cgroup_id, then uncharge with the fresh id. The cached cgroup_id from
    // Phase 1 may be stale if cgroup migration occurred during PT operations.
    let pt_frames = match map_result {
        Err(failed) => {
            // ST-K3 Phase D: site tags. E5 is data-frame exhaustion (including
            // the free-frame precheck), E6 page-table material.
            #[cfg(debug_assertions)]
            match failed.error {
                crate::populate::PopulateError::NoMemory(
                    crate::populate::PopulateStage::MapPage,
                ) => kprintln!(
                    "[ST-K3] mmap ENOMEM site=E6 stage=map_page len={}",
                    length_aligned
                ),
                crate::populate::PopulateError::NoMemory(stage) => kprintln!(
                    "[ST-K3] mmap ENOMEM site=E5 stage=frame_alloc len={} cause={:?}",
                    length_aligned,
                    stage
                ),
                crate::populate::PopulateError::Interrupted => {}
            }
            // Only a private mapping populates, so only it can fail here.
            let rollback_cgroup_id = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                mm.mmap_regions.remove(&base);
                if update_next && mm.next_mmap_addr == end {
                    mm.next_mmap_addr = old_next_mmap_addr;
                }
                // R192-RES-2: debit the ledgered tables the rollback pruned and
                // charge the ones it built and could not prune, migration-atomic
                // under this Process + MmState hold.
                failed.settle(&mut mm, proc.cgroup_id);
                proc.cgroup_id
            };
            cgroup::uncharge_memory(rollback_cgroup_id, length_aligned as u64);
            let error = populate_errno(failed.error);
            // Free-after-remove: the pruned tables reach the buddy only now.
            drop(failed);
            drop(shared_region);
            return Err(error);
        }
        Ok(frames) => frames,
    };

    // R171-CG1x0 FIX (M2-1 SLICE-0): the page-table-frame charge is exactly the
    // number of recorded PT/PD/PDPT frame identities — `RecordingFrameAllocator`
    // records only the frames `map_to` pulled for intermediate tables; the leaf
    // DATA frame went through `allocate_data_frame` (unrecorded). No data-page
    // subtraction is needed (the count is already PT-only, by identity).
    let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

    // Phase 3: Commit the reservation (clear PENDING_MAP) AND record the
    // page-table-frame kmem in the SAME Process-lock critical section. Doing both
    // under the Process lock — the sanctioned Process → MmState → cgroup order,
    // exactly like the Phase-1 DATA charge at the top of this fn — makes this
    // mutually exclusive with cgroup migration, which holds the Process lock
    // across compute_cgroup_charged_bytes + the cgroup_id update (R155-5). So the
    // forced pt charge and the pt_charged_bytes mirror land atomically w.r.t.
    // migration, and no transient mirror field is needed.
    //
    // J2-9: the pt charge is a SOFT / forced charge (charge_memory_forced), NOT a
    // hard try_charge_memory. The page-table-frame count is knowable only AFTER
    // map_to has run (IM-14: "delta known only after the mutation ⇒ soft cap"),
    // and by then the frames physically exist. A hard reject here would have to
    // free the already-built intermediate PT tables (a leak-prone rollback that
    // would ORPHAN them uncharged → a partial memory.max bypass); instead we KEEP
    // and CHARGE them, accepting a bounded overshoot (≤ this one mapping's pt
    // delta, ~1/512 of the data that already passed the Phase-1 HARD gate). The
    // HARD gate on the NEXT allocation re-enforces memory.max, so this is the
    // over-count-safe / never-under-count direction — it cannot bypass memory.max.
    // R144-2 FIX: Store protection bits so procfs /proc/[pid]/maps shows accurate perms.
    let prot_flags = mmap_prot_to_flags(prot);
    let committed_len_with_flags = MmapEntry::from_len_flags(
        length_aligned,
        prot_flags
            | if is_shared {
                MMAP_REGION_FLAG_SHARED
            } else {
                0
            },
    );
    {
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        // next-phase #11: `base` is still present from Phase 1 (PENDING_MAP), so
        // this is an in-place replace clearing the flag — no allocation.
        // ST-K3 Phase D: site tag (E8) — the Phase-3 commit `?` has NO rollback
        // (PENDING entry, cgroup charge, next_mmap_addr, and mapped frames all
        // survive an error here); annotated-unreachable, and the tag exists to
        // falsify that annotation — if it EVER fires, the stuck-PENDING entry
        // will also fail every later fork via ForkMmReservation.
        mm.mmap_regions
            .try_insert(base, committed_len_with_flags)
            .map_err(|_| {
                #[cfg(debug_assertions)]
                kprintln!(
                    "[ST-K3] mmap ENOMEM site=E8 stage=phase3_commit len={}",
                    length_aligned
                );
                SyscallError::ENOMEM
            })?;
        // R131-6 FIX: Track per-address-space cgroup DATA charge. Shared
        // anonymous bytes are charged per materialized page by the fault
        // receipt and released by the region owner, so they never enter this
        // eager VMA-length scalar.
        if !is_shared {
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(length_aligned as u64);
        }
        if mm.next_mmap_addr < end {
            mm.next_mmap_addr = end;
        }
        // J2-9: record the page-table-frame kmem (forced soft charge) under this
        // same Process lock so the cgroup counter and the per-AS mirror move
        // together and stay consistent with proc.cgroup_id (migration-atomic).
        //
        // R171-CG1x0 FIX (M2-1 SLICE-0): BEFORE charging, record each PT frame's
        // physical identity in the per-AS provenance ledger so a later munmap-prune
        // uncharges a reclaimed frame IFF this mmap charged it — defeating the
        // cross-origin memory.max bypass. The ledger insert runs under THIS same
        // MmState lock that any concurrent munmap of this shared AS must also take,
        // so a sibling cannot remove an entry mid-install. Reserve up front; on a
        // reserve OOM (or the never-firing aliasing safety net) fall back to the
        // untracked `pt_inherited_bytes` basis: those frames then reclaim only at
        // teardown (over-count-safe — restricts the tenant further, never a bypass),
        // and INVARIANT I' (pt_charged_bytes == pt_inherited_bytes +
        // pt_charged_frames.len()*0x1000) is preserved on every branch.
        if pt_bytes > 0 {
            let ledgered = if mm.pt_charged_frames.try_reserve(pt_frames.len()).is_ok() {
                let mut all_fresh = true;
                for f in &pt_frames {
                    match mm
                        .pt_charged_frames
                        .try_insert(f.start_address().as_u64(), ())
                    {
                        Ok(None) => {}
                        Ok(Some(_)) => {
                            // A frame the allocator just handed out as is_unused()
                            // CANNOT already be ledgered unless free-after-remove
                            // (munmap step) were violated — a never-firing safety
                            // net, NEVER a silent in-place replace.
                            debug_assert!(
                                false,
                                "pt ledger frame aliased — free-after-remove invariant violated"
                            );
                            all_fresh = false;
                        }
                        // Unreachable after a successful try_reserve(len); defensive.
                        Err(_) => {
                            all_fresh = false;
                            break;
                        }
                    }
                }
                all_fresh
            } else {
                false
            };
            cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
            mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_add(pt_bytes);
            if ledgered {
                // This AS now authoritatively tracks its own PT charges by frame.
                if !mm.pt_ledger_authoritative {
                    mm.pt_ledger_authoritative = true;
                }
            } else {
                // OOM / aliasing fallback: drop any partial inserts and carry the
                // bytes in the untracked basis so the ledger stays consistent with
                // INVARIANT I' (these frames reclaim wholesale at teardown).
                for f in &pt_frames {
                    mm.pt_charged_frames.remove(&f.start_address().as_u64());
                }
                mm.pt_inherited_bytes = mm.pt_inherited_bytes.saturating_add(pt_bytes);
            }
        }
    }

    // D3-ARC-MM-SHARED: sync_vm_siblings_add_mmap is no longer needed — all
    // The side-map owns the committed Arc; release this phase-local handle so
    // unmap/exit can observe the precise last-owner transition.
    drop(shared_region);

    // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

    // Note: Memory is already atomically charged via try_charge_memory() above.
    // R77-2 FIX: No separate accounting call needed - charge/uncharge model is complete.

    // R102-10 + R159-17 FIX: Gate address-revealing log behind debug_assertions.
    #[cfg(debug_assertions)]
    kprintln!(
        "sys_mmap: pid={}, mapped {} bytes at 0x{:x}",
        pid,
        length_aligned,
        base
    );

    Ok(base)
}

/// sys_munmap - 取消内存映射
///
/// 使用当前进程的地址空间进行取消映射，确保进程隔离
pub(super) fn sys_munmap(addr: usize, length: usize) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1060); // sys_munmap entry
    }

    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::Page;
    use x86_64::VirtAddr;

    // 验证参数
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1061); // sys_munmap validation passed
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // R121-4 FIX (was R65-9): Three-phase munmap to respect documented lock
    // ordering while preventing concurrent munmap double-free.
    //
    // Phase 1 (Process lock): validate region, mark as PENDING_UNMAP so
    //   concurrent mmap/munmap can't race the PT operations.
    // Phase 2 (no Process lock): perform PT unmap via with_current_manager().
    // Phase 3 (Process lock): remove PCB record and uncharge cgroup.
    // D3-ARC-MM-SHARED: Phase 1 operates on shared MmState via mm Arc.
    let (recorded_length, committed_flags, mm_arc) = {
        let mut proc = process.lock();
        let mm_arc: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>> =
            Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        if mm.fork_in_progress {
            return Err(SyscallError::EAGAIN);
        }

        // 检查该区域是否在 mmap 记录中
        let recorded_len_with_flags = *mm.mmap_regions.get(&addr).ok_or(SyscallError::EINVAL)?;

        // Reject if another operation is already in progress on this region.
        if recorded_len_with_flags.has_transient() {
            return Err(SyscallError::EBUSY);
        }

        let recorded_length = mmap_region_len(recorded_len_with_flags);
        // R123-1 FIX: Capture committed per-region flags (e.g. PROT_NONE) so
        // we can skip cgroup uncharge for regions that were never charged.
        let committed_flags = recorded_len_with_flags.flags();

        // 验证长度匹配
        if recorded_length != length_aligned {
            return Err(SyscallError::EINVAL);
        }

        // R131-2 FIX: Use lsm_process_ctx_from() instead of ProcessCtx::from_current()
        // to avoid deadlock.
        let ctx = lsm_process_ctx_from(&proc)?;
        if lsm::hook_memory_munmap(&ctx, addr as u64, length_aligned as u64).is_err() {
            return Err(SyscallError::EPERM);
        }

        // Fast path for untouched lazy private-anonymous mappings: UNFAULTED is
        // cleared under `MmState` lock BEFORE inserting any PTE (or growing via
        // mremap), so zero leaf PTEs and zero PT frames exist for this VMA.
        // Removing and uncharging here skips PT_LOCK, page-table walk, and TLB
        // shootdown completely while remaining linearizable with concurrent #PF.
        if (committed_flags & MMAP_REGION_FLAG_UNFAULTED) != 0
            && (committed_flags & (MMAP_REGION_FLAG_PROT_NONE | MMAP_REGION_FLAG_SHARED)) == 0
        {
            let was_present = mm.mmap_regions.remove(&addr).is_some();
            if was_present {
                mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(recorded_length as u64);
                cgroup::uncharge_memory(proc.cgroup_id, length_aligned as u64);
            }
            mm.reclaim_empty_shared_fault_pt_capacity();
            drop(mm);
            drop(proc);
            return Ok(0);
        }

        // Mark as pending-unmap so concurrent mmap/munmap can't race the PT ops.
        // Preserve committed per-region flags (e.g. PROT_NONE) through the operation.
        // next-phase #11: `addr` is the region being unmapped (already present),
        // so setting its PENDING_UNMAP flag is an in-place replace — no alloc.
        mm.mmap_regions
            .try_insert(
                addr,
                MmapEntry::from_len_flags(recorded_length, committed_flags).with_pending_unmap(),
            )
            .map_err(|_| SyscallError::ENOMEM)?;

        // R145-1 FIX: Do NOT capture cgroup_id here — it may change during
        // the lock-drop window (migration).  Re-read under lock in Phase 3.
        drop(mm);
        (recorded_length, committed_flags, mm_arc)
    }; // Process lock + MmState lock dropped here — Phase 1 complete

    // 使用基于当前 CR3 的页表管理器进行取消映射
    // R23-3 / R159-1 / Issue #109 §1.1 (H1) + R171-CG1x0 FIX (M2-1 SLICE-0):
    // Clear all leaf PTEs (batched per 2 MiB PT, zero per-page invlpg) and
    // detach any now-empty PT/PD tables under PT_LOCK, perform ONE combined
    // cross-CPU TLB/paging-structure shootdown BEFORE dropping PT_LOCK, then
    // release PAGE_REF_COUNT and batch-free last-reference data frames OUTSIDE
    // PT_LOCK (with interrupts enabled). Reclaimed PT/PD frames are published
    // to the buddy strictly AFTER Phase 3 removes them from the per-AS ledger.
    const UNMAP_INLINE_CAP: usize = crate::populate::POPULATE_CHUNK_PAGES;
    struct UnmappedFrameBuf {
        inline: [x86_64::structures::paging::PhysFrame; UNMAP_INLINE_CAP],
        inline_len: usize,
        overflow: alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
    }

    let unmap_result: Result<
        (
            UnmappedFrameBuf,
            alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
            usize,
        ),
        SyscallError,
    > = unsafe {
        with_current_manager(
            VirtAddr::new(0),
            |manager| -> Result<
                (
                    UnmappedFrameBuf,
                    alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
                    usize,
                ),
                SyscallError,
            > {
                use alloc::vec::Vec;
                use x86_64::structures::paging::PhysFrame;
                use x86_64::PhysAddr;

                let mut frame_alloc = FrameAllocator::new();
                let pages = length_aligned / 0x1000;
                let mut unmapped = UnmappedFrameBuf {
                    inline: [PhysFrame::containing_address(PhysAddr::new(0)); UNMAP_INLINE_CAP],
                    inline_len: 0,
                    overflow: Vec::new(),
                };
                if pages > UNMAP_INLINE_CAP {
                    let _ = unmapped.overflow.try_reserve(pages - UNMAP_INLINE_CAP);
                }

                let mut removed_leaf = false;
                let mut removed_leaf_count = 0usize;
                manager.unmap_user_range_no_flush(
                    VirtAddr::new(addr as u64),
                    length_aligned,
                    |page, frame| {
                        removed_leaf = true;
                        removed_leaf_count += 1;
                        if unmapped.inline_len < UNMAP_INLINE_CAP {
                            unmapped.inline[unmapped.inline_len] = frame;
                            unmapped.inline_len += 1;
                        } else if unmapped.overflow.try_reserve(1).is_ok() {
                            unmapped.overflow.push(frame);
                        } else {
                            // OOM fallback: flush this page FIRST, then release & free.
                            mm::flush_current_as_page(page.start_address());
                            let phys_addr = frame.start_address().as_u64() as usize;
                            if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                    },
                );

                // Detach now-empty PT/PD tables BEFORE the flush so that when a
                // table is collapsed, ONE `flush_current_as_all()` invalidates
                // both the cleared leaves and the cleared parent PDE/PDPTEs.
                let mut table_frames: Vec<PhysFrame> = Vec::new();
                let pruned_any = manager.prune_empty_tables_in_range_no_flush(
                    VirtAddr::new(addr as u64),
                    length_aligned,
                    &mut table_frames,
                );

                // Shared and COW leaves retain peer references, so every removed leaf
                // and detached table must be invalidated across all participating CPUs
                // BEFORE releasing PAGE_REF_COUNT or dropping any Phase-3 pin.
                if removed_leaf || pruned_any {
                    // ST-K2-P2(b): the remote-holder oracle pauses here, holding
                    // the AS PT lock, until a sibling's IF=0 shared fault is spinning.
                    #[cfg(feature = "syscall_test")]
                    crate::fork::shared_fault_test::before_unmap_flush(pid, addr);
                    if pruned_any {
                        mm::flush_current_as_all();
                    } else {
                        mm::flush_current_as_range(VirtAddr::new(addr as u64), length_aligned);
                    }
                    #[cfg(feature = "syscall_test")]
                    crate::fork::shared_fault_test::after_unmap_flush(pid, addr);
                }

                Ok((unmapped, table_frames, removed_leaf_count))
            },
        )
    };

    let (unmapped_frames, table_frames, removed_leaf_count) = match unmap_result {
        Ok(pair) => pair,
        Err(e) => {
            // Roll back the PENDING_UNMAP marker so the region remains usable.
            // Preserve committed per-region flags (e.g. PROT_NONE).
            // next-phase #11: `addr` still carries its PENDING_UNMAP marker here, so
            // this is an in-place replace that cannot allocate; ignore the result so
            // the original unmap error `e` is the one returned.
            let _ = mm_arc.lock().mmap_regions.try_insert(
                addr,
                MmapEntry::from_len_flags(recorded_length, committed_flags),
            );
            return Err(e);
        }
    };

    // Release PAGE_REF_COUNT and batch-scrub/free last-reference data frames
    // OUTSIDE PT_LOCK (with interrupts enabled), strictly after the cross-CPU
    // TLB shootdown completed above.
    {
        use x86_64::structures::paging::PhysFrame;
        use x86_64::PhysAddr;

        let mut free_batch = [PhysFrame::containing_address(PhysAddr::new(0)); UNMAP_INLINE_CAP];
        let mut free_len = 0usize;
        for &frame in unmapped_frames.inline[..unmapped_frames.inline_len]
            .iter()
            .chain(unmapped_frames.overflow.iter())
        {
            let phys_addr = frame.start_address().as_u64() as usize;
            if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                free_batch[free_len] = frame;
                free_len += 1;
                if free_len == UNMAP_INLINE_CAP {
                    mm::buddy_allocator::free_physical_pages_batch(&free_batch);
                    free_len = 0;
                }
            }
        }
        if free_len > 0 {
            mm::buddy_allocator::free_physical_pages_batch(&free_batch[..free_len]);
        }
    }

    // R171-CG1x0 FIX (M2-1 SLICE-0): a leak-safe carrier for the reclaimed PT/PD
    // table frames. The frames are published to the buddy ONLY after Phase 3 removes
    // them from the per-AS ledger (free-after-remove). On any early-return/panic
    // before the explicit drain, Drop frees them so a carried frame can never leak.
    struct TableFrameReclaim {
        frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
        drained: bool,
    }
    impl Drop for TableFrameReclaim {
        fn drop(&mut self) {
            if !self.drained && !self.frames.is_empty() {
                let mut fa = mm::memory::FrameAllocator::new();
                for f in self.frames.drain(..) {
                    fa.deallocate_frame(f);
                }
            }
        }
    }
    let mut reclaim = TableFrameReclaim {
        frames: table_frames,
        drained: false,
    };
    let shared_region_to_drop = {
        // D3-ARC-MM-SHARED + R145-1 + R171-CG1x0 FIX (M2-1 SLICE-0): folded Phase 3 —
        // ONE Process→MmState critical section (canonical order, matching sys_mmap
        // Phase 3) so the region removal, the DATA uncharge, AND the per-AS PT-ledger
        // reconcile all land atomically w.r.t. cgroup migration (which snapshots
        // compute_cgroup_charged_bytes under the Process lock, R155-5). The cgroup
        // uncharges run here with PT_LOCK already dropped — lock_ordering sanctions
        // cgroup helpers under the Process lock; never under PT_LOCK.
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        // Re-read cgroup_id under the lock — migration may have moved us during the
        // lock-free Phase 2 PT work.
        let cgroup_id = proc.cgroup_id;

        // Under shared MmState the first remover wins; a racing CLONE_VM sibling
        // sees the entry gone (the shared Mutex serializes; no double-remove).
        let was_present = mm.mmap_regions.remove(&addr).is_some();
        let shared_region = if committed_flags & MMAP_REGION_FLAG_SHARED != 0 {
            mm.shared_regions.remove(&addr)
        } else {
            None
        };

        // DATA leg: uncharge the region bytes only on the first remove and only for
        // a charged (non-PROT_NONE) region.
        if was_present
            && (committed_flags & (MMAP_REGION_FLAG_PROT_NONE | MMAP_REGION_FLAG_SHARED)) == 0
        {
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(recorded_length as u64);
            if (committed_flags & MMAP_REGION_FLAG_LAZY_ANON) != 0 && removed_leaf_count > 0 {
                mm.lazy_anon_resident_bytes = mm
                    .lazy_anon_resident_bytes
                    .saturating_sub((removed_leaf_count as u64).saturating_mul(0x1000));
            }
            cgroup::uncharge_memory(cgroup_id, length_aligned as u64);
        }

        // PT leg: reconcile the ledger with the frames prune reclaimed. Uncharge a
        // reclaimed frame IFF this AS charged it (on mmap or mprotect Path-A;
        // frame-identity provenance) — never a guessed constant, so an UNCHARGED
        // brk/ELF frame that prune happened to reclaim is correctly NOT debited (defeats the
        // cross-origin memory.max bypass). Skipped while the ledger is
        // non-authoritative (a forked child's inherited basis: empty ledger →
        // nothing to remove; the basis rides to teardown, over-count-safe).
        if mm.pt_ledger_authoritative {
            let pt_freed =
                mm.reclaim_pt_charges(reclaim.frames.iter().map(|f| f.start_address().as_u64()));
            if pt_freed > 0 {
                mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(pt_freed);
                cgroup::uncharge_memory(cgroup_id, pt_freed);
            }
        }
        shared_region
    };

    // R171-CG1x0 FIX (M2-1 SLICE-0): NOW publish the reclaimed table frames to the
    // buddy — STRICTLY AFTER the ledger removal above. In the window a frame becomes
    // buddy-reusable it is already gone from the ledger and from pt_charged_bytes, so
    // a concurrent re-allocator that obtains it re-records it fresh (mmap Phase-3
    // try_insert ⇒ Ok(None)); there is no window where a live table is
    // buddy-free-and-charged or live-and-uncharged. The free runs lock-free (buddy
    // internal lock only) — zero new lock-ordering edge.
    {
        let mut fa = FrameAllocator::new();
        for f in reclaim.frames.drain(..) {
            fa.deallocate_frame(f);
        }
        reclaim.drained = true;
    };

    // Drop the region outside Process/MmState locks and only after the PT
    // transaction has removed every present leaf. Its Drop releases the region
    // pin and first-toucher cgroup charges.
    drop(shared_region_to_drop);

    // R102-10 + R159-17 FIX: Gate address-revealing log behind debug_assertions.
    #[cfg(debug_assertions)]
    kprintln!(
        "sys_munmap: pid={}, unmapped {} bytes at 0x{:x}",
        pid,
        length_aligned,
        addr
    );

    Ok(0)
}

/// mprotect 保护标志
pub(super) const PROT_READ: i32 = 0x1;
pub(super) const PROT_WRITE: i32 = 0x2;
pub(super) const PROT_EXEC: i32 = 0x4;
pub(super) const PROT_NONE: i32 = 0x0;

/// RF178-31: reconcile requested permissions with the two COW states.
/// BIT_9 means a shared page whose current protection permits writes after a
/// private copy; BIT_10 tracks a shared read-only page with no write entitlement.
pub(super) fn reconcile_cow_mprotect_flags(
    current: PageTableFlags,
    mut requested: PageTableFlags,
) -> PageTableFlags {
    let tracked = current.contains(cow_flag()) || current.contains(cow_readonly_flag());
    if !tracked {
        return requested;
    }

    if requested.contains(PageTableFlags::WRITABLE) {
        requested.remove(PageTableFlags::WRITABLE);
        requested.remove(cow_readonly_flag());
        requested.insert(cow_flag());
    } else {
        requested.remove(cow_flag());
        requested.insert(cow_readonly_flag());
    }
    requested
}

/// Focused permission-state checks for forked read-only and write-entitled COW
/// mappings. Arithmetic/table rollback is covered by fork's companion test.
pub fn run_cow_mprotect_self_test() {
    let read =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;
    let write = read | PageTableFlags::WRITABLE;

    let promoted = reconcile_cow_mprotect_flags(read | cow_readonly_flag(), write);
    assert!(promoted.contains(cow_flag()));
    assert!(!promoted.contains(cow_readonly_flag()));
    assert!(!promoted.contains(PageTableFlags::WRITABLE));

    let demoted = reconcile_cow_mprotect_flags(read | cow_flag(), read);
    assert!(demoted.contains(cow_readonly_flag()));
    assert!(!demoted.contains(cow_flag()));
    assert!(!demoted.contains(PageTableFlags::WRITABLE));

    let exclusive = reconcile_cow_mprotect_flags(read, write);
    assert!(exclusive.contains(PageTableFlags::WRITABLE));
    assert!(!exclusive.contains(cow_flag()));
    assert!(!exclusive.contains(cow_readonly_flag()));
}

/// sys_mprotect - 设置内存区域保护属性
///
/// # Arguments
/// * `addr` - 起始地址（必须页对齐）
/// * `len` - 区域长度
/// * `prot` - 保护标志 (PROT_READ, PROT_WRITE, PROT_EXEC)
///
/// # Returns
/// 成功返回 0，失败返回错误码
pub(super) fn sys_mprotect(addr: usize, len: usize, prot: i32) -> SyscallResult {
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 验证地址页对齐
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 长度为 0 时直接返回成功
    if len == 0 {
        return Ok(0);
    }

    // 对齐长度到页边界
    let len_aligned = len.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // R28-7 Fix: Validate that addr + len_aligned doesn't overflow or exceed user space
    let end = addr.checked_add(len_aligned).ok_or(SyscallError::EINVAL)?;
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EINVAL);
    }

    // R172-X-F3: mprotect is the THIRD page-permission door. brk (sys_brk) and mmap
    // (sys_mmap) both consume `user_stack_window()` to bar the reserved user-stack window
    // [stack_base, USER_STACK_TOP) (guard-INCLUSIVE), but mprotect did NOT — its only stack
    // protection was INCIDENTAL: the stack is mapped directly and intentionally never
    // inserted into mmap_regions (R123-1 double-free avoidance), so the Phase-0 coverage
    // loop below happens to hit coverage<end -> ENOMEM. That is an emergent side effect of
    // two unrelated invariants, not an architectural guarantee — a future coverage
    // relaxation, or any non-stack mmap_regions entry overlapping the window, would let
    // mprotect flip stack/guard PTEs to PROT_EXEC-only or PROT_NONE (the W^X reject below
    // blocks only literal W+X, not EXEC-only / PROT_NONE on the stack). Make stack/guard
    // permission immutability STRUCTURAL via the SAME single-sourced half-open window
    // sys_mmap refuses (its exact arm as occupied, a hint by falling back), with EINVAL:
    // an architecturally-reserved invalid VA, never a missing-mapping ENOMEM. TOCTOU-free
    // (a fixed VA range, not mmap_regions state); `addr` is page-aligned and
    // `end == addr + len_aligned`, both computed above; `len == 0` already returned
    // Ok(0). Complementary to (not redundant with) the Phase-0 coverage<end ENOMEM
    // gap-reject below.
    {
        let (win_start, win_end) = crate::elf_loader::user_stack_window();
        if addr < win_end && end > win_start {
            return Err(SyscallError::EINVAL);
        }
    }

    // W^X 安全检查：禁止同时可写可执行
    if (prot & PROT_WRITE != 0) && (prot & PROT_EXEC != 0) {
        return Err(SyscallError::EPERM);
    }

    // R29-3 FIX: Call LSM hook for mprotect operations
    // R192-5 FIX: a missing subject fails closed, never skips the hook.
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
    if lsm::hook_memory_mprotect(&ctx, addr as u64, len_aligned as u64, prot as u32).is_err() {
        return Err(SyscallError::EPERM);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let is_target_prot_none = prot == PROT_NONE;

    // Phase 0: Under process lock, classify each mmap_regions entry in
    // [addr, end) by its current PROT_NONE status.  This determines whether
    // we need frame allocation (PROT_NONE → real) or frame deallocation
    // (real → PROT_NONE).
    // D3-ARC-MM-SHARED: Phase 0 operates on shared MmState via mm Arc.
    let (prot_none_regions, real_regions, mm_arc) = {
        let proc = process.lock();
        let mm_arc: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>> =
            Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        if mm.fork_in_progress {
            return Err(SyscallError::EAGAIN);
        }

        // ST-K2-P2 boundary: shared-anonymous permissions are immutable in
        // this slice. Reject before any boundary split so a failed mprotect
        // cannot leave partially rewritten shared metadata.
        if mm.mmap_regions.iter().any(|(&base, &entry)| {
            let region_len = mmap_region_len(entry);
            let region_end = base.saturating_add(region_len);
            entry.is_shared() && base < end && region_end > addr
        }) {
            return Err(SyscallError::EOPNOTSUPP);
        }

        // R161-10 FIX: Split regions that partially overlap [addr, end) at the
        // boundary points. This ensures the classification loop below only sees
        // entries fully contained within the mprotect range, so Path A/B process
        // exactly the correct pages and bookkeeping updates find entries by key.
        // R162-2-1 FIX: Check MAX_MAP_COUNT before splitting to prevent unbounded
        // region growth via repeated partial-range mprotect calls.
        if mm.mmap_regions.len() + 2 >= MAX_MAP_COUNT {
            return Err(SyscallError::ENOMEM);
        }

        // RF180-5 FIX: classification metadata is fallible, so reserve it before
        // the first boundary insertion. Count every VMA keyed in [addr, end) plus
        // a preceding VMA whose tail overlaps `addr`; two extra slots cover the
        // maximum boundary-split headroom. Either vector may receive every entry,
        // so each gets the full upper bound.
        let preceding = mm
            .mmap_regions
            .range(..addr)
            .next_back()
            .map(|(&base, &lf)| (base, lf));
        let preceding_overlaps = preceding
            .as_ref()
            .map(|(base, lf)| {
                let region_len = mmap_region_len(*lf);
                region_len > 0 && (*base).saturating_add(region_len) > addr
            })
            .unwrap_or(false);
        let overlapping_region_count = mm
            .mmap_regions
            .range(addr..end)
            .count()
            .checked_add(usize::from(preceding_overlaps))
            .ok_or(SyscallError::ENOMEM)?;
        let classification_capacity = overlapping_region_count
            .checked_add(2)
            .ok_or(SyscallError::ENOMEM)?;
        let mut prot_none_regions: Vec<(usize, usize)> = Vec::new();
        let mut real_regions: Vec<(usize, usize)> = Vec::new();
        prot_none_regions
            .try_reserve(classification_capacity)
            .map_err(|_| SyscallError::ENOMEM)?;
        real_regions
            .try_reserve(classification_capacity)
            .map_err(|_| SyscallError::ENOMEM)?;

        // next-phase #11: the two split blocks below add at most two new boundary
        // keys (`addr`, `end`) — every other insert is an in-place replace of an
        // existing region base. Pre-reserve that capacity so the subsequent
        // try_insert calls cannot fail mid-sequence and leave a half-split map.
        // (Matches the `+ 2` headroom asserted by the MAX_MAP_COUNT check above.)
        mm.mmap_regions
            .try_reserve(2)
            .map_err(|_| SyscallError::ENOMEM)?;
        // Splitting up to two boundary lazy VMAs can create up to 2 extra
        // boundary PT/PD/PDPT overlaps (6 ledger slots); reserve BEFORE splits
        // so concurrent CLONE_VM page faults retain guaranteed ledger capacity.
        if mm
            .mmap_regions
            .values()
            .any(|e| e.is_lazy_anon() && !e.is_prot_none() && !e.is_shared())
        {
            mm.reserve_shared_fault_pt_extra(None, 6)
                .map_err(|_| SyscallError::ENOMEM)?;
        }

        // Split preceding region whose tail extends into [addr, end).
        // next-phase #11: `preceding` was copied into an owned Option above, so
        // the immutable range borrow ended before the mutations below.
        if let Some((prev_base, prev_lf)) = preceding {
            let prev_len = mmap_region_len(prev_lf);
            let prev_end = prev_base.saturating_add(prev_len);
            if prev_end > addr && prev_len > 0 {
                if prev_lf.has_transient() {
                    return Err(SyscallError::EBUSY);
                }
                let prev_flags = prev_lf.flags();
                let left_len = addr - prev_base;
                mm.mmap_regions
                    .try_insert(prev_base, MmapEntry::from_len_flags(left_len, prev_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
                let tail_end = prev_end.min(end);
                let tail_len = tail_end - addr;
                mm.mmap_regions
                    .try_insert(addr, MmapEntry::from_len_flags(tail_len, prev_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
                if prev_end > end {
                    let right_len = prev_end - end;
                    mm.mmap_regions
                        .try_insert(end, MmapEntry::from_len_flags(right_len, prev_flags))
                        .map_err(|_| SyscallError::ENOMEM)?;
                }
            }
        }

        // Split trailing region that starts in [addr, end) but extends past end.
        // next-phase #11: same as above — hoist the range lookup into an owned
        // Option so the immutable borrow ends before the try_insert mutations.
        let trailing = mm
            .mmap_regions
            .range(addr..end)
            .next_back()
            .map(|(&base, &lf)| (base, lf));
        if let Some((last_base, last_lf)) = trailing {
            let last_len = mmap_region_len(last_lf);
            let last_end = last_base.saturating_add(last_len);
            if last_end > end && last_len > 0 {
                if last_lf.has_transient() {
                    return Err(SyscallError::EBUSY);
                }
                let last_flags = last_lf.flags();
                let in_range_len = end - last_base;
                let right_len = last_end - end;
                mm.mmap_regions
                    .try_insert(
                        last_base,
                        MmapEntry::from_len_flags(in_range_len, last_flags),
                    )
                    .map_err(|_| SyscallError::ENOMEM)?;
                mm.mmap_regions
                    .try_insert(end, MmapEntry::from_len_flags(right_len, last_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
            }
        }

        // R158-17 FIX: Track coverage to detect unmapped gaps in [addr, end).
        let mut coverage = addr;

        for (&region_base, &len_with_flags) in mm.mmap_regions.range(addr..end) {
            let region_len = mmap_region_len(len_with_flags);

            if region_len > 0 && region_base > coverage {
                return Err(SyscallError::ENOMEM);
            }

            if len_with_flags.has_transient() {
                return Err(SyscallError::EBUSY);
            }

            if region_len == 0 {
                continue;
            }

            let region_end = region_base.saturating_add(region_len);
            if region_end > coverage {
                coverage = region_end;
            }

            if len_with_flags.is_prot_none() {
                prot_none_regions.push((region_base, region_len));
            } else {
                real_regions.push((region_base, region_len));
            }
        }

        // R158-17: Verify full coverage of [addr, end).
        if coverage < end {
            return Err(SyscallError::ENOMEM);
        }

        drop(mm);
        (prot_none_regions, real_regions, mm_arc)
    };

    // D3-ARC-MM-SHARED: sync_vm_siblings_split_region is no longer needed — all
    // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

    // 构建页表标志
    // R24-4 fix: PROT_NONE 需要清除 PRESENT 标志，使页面不可访问
    let flags = if prot == PROT_NONE {
        // 不可访问：清除 PRESENT，页存在但任何访问都会触发 #PF
        PageTableFlags::empty()
    } else {
        let mut f = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if prot & PROT_WRITE != 0 {
            f |= PageTableFlags::WRITABLE;
        }
        if prot & PROT_EXEC == 0 {
            // 如果没有 EXEC 权限，设置 NX 位
            f |= PageTableFlags::NO_EXECUTE;
        }
        f
    };

    let new_prot_flags = mmap_prot_to_flags(prot);

    // ---------------------------------------------------------------
    // Path A — PROT_NONE → real permissions:
    // Allocate frames, charge cgroup, clear PROT_NONE flag.
    //
    // R146-3 NOTE: If mprotect spans multiple PROT_NONE regions and a later
    // region fails (cgroup charge exhaustion or frame allocation failure),
    // earlier regions that were successfully committed are NOT rolled back.
    // POSIX mprotect(2) allows indeterminate state on error ("if the call
    // fails, some of the address space may have been changed"), so this is
    // not a spec violation. Callers MUST NOT assume all-or-nothing atomicity
    // for multi-region mprotect operations.
    // ---------------------------------------------------------------
    if !is_target_prot_none && !prot_none_regions.is_empty() {
        for &(region_base, region_len) in &prot_none_regions {
            // Step 1: Charge cgroup for the reservation being materialized.
            //
            // R147-1 FIX: Record the in-flight charge under the process lock so
            // compute_cgroup_charged_bytes() includes it during cgroup migration.
            // Read cgroup_id fresh (not from Phase 0) in case migration occurred.
            {
                let proc = process.lock();
                let cgroup_id = proc.cgroup_id;
                if cgroup::try_charge_memory(cgroup_id, region_len as u64).is_err() {
                    return Err(SyscallError::ENOMEM);
                }
                let mut mm = mm_arc.lock();
                if mm.fork_in_progress {
                    drop(mm);
                    drop(proc);
                    cgroup::uncharge_memory(cgroup_id, region_len as u64);
                    return Err(SyscallError::EAGAIN);
                }
                // R162-3 FIX: Accumulate instead of overwrite to prevent concurrent
                // mprotect operations from clobbering each other's pending charge.
                mm.mprotect_pending_bytes =
                    mm.mprotect_pending_bytes.saturating_add(region_len as u64);
                // R149-6 FIX: Set transient flag so concurrent munmap sees
                // the in-flight mprotect and returns EBUSY.
                // R164-2 FIX: Check if PENDING_MPROTECT is already set by a
                // concurrent mprotect on the same region. Without this, two
                // CLONE_VM threads can both charge cgroup and proceed to PT
                // ops, then one's rollback clears the flag, causing the
                // other's commit check to fail — leaking frames.
                if let Some(entry) = mm.mmap_regions.get_mut(&region_base) {
                    if entry.is_pending_mprotect() {
                        mm.mprotect_pending_bytes =
                            mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                        drop(mm);
                        let cgroup_id = proc.cgroup_id;
                        drop(proc);
                        cgroup::uncharge_memory(cgroup_id, region_len as u64);
                        return Err(SyscallError::EBUSY);
                    }
                    // next-phase #11 (symmetric with R168 Path B / IM-12): the
                    // MmState lock was FREE between Phase-0 classification and this
                    // claim, so a concurrent op on a CLONE_VM sibling may have
                    // (a) demoted this region away from PROT_NONE, (b) marked it
                    // transient — a racing munmap's PENDING_UNMAP or mmap's
                    // PENDING_MAP — or (c) split/resized it so the live length no
                    // longer matches the stale Phase-0 `region_len`. Committing
                    // Path A with that stale length would rewrite a wrong-length
                    // entry (overlapping a neighbour) AND over-charge the cgroup.
                    // Re-validate the live entry against the snapshot exactly as
                    // Path B does; on any mismatch roll back THIS region's charge
                    // and skip it (POSIX mprotect permits partial application).
                    // After we set PENDING_MPROTECT, concurrent split/munmap both
                    // bail on has_transient() for the entire Step 2 window, so
                    // `region_len` is guaranteed to remain the live length through
                    // the Step 3 commit below.
                    if !entry.is_prot_none() || entry.has_transient() || entry.len() != region_len {
                        mm.mprotect_pending_bytes =
                            mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                        drop(mm);
                        drop(proc);
                        cgroup::uncharge_memory(cgroup_id, region_len as u64);
                        continue;
                    }
                    entry.set_pending_mprotect();
                } else {
                    // Region vanished between Phase 0 classification and here;
                    // roll back the charge and fail.
                    // R162-3 FIX: Decrement instead of zeroing to preserve
                    // other concurrent mprotect operations' pending charges.
                    mm.mprotect_pending_bytes =
                        mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                    drop(mm);
                    drop(proc);
                    cgroup::uncharge_memory(cgroup_id, region_len as u64);
                    return Err(SyscallError::EFAULT);
                }
            }

            // Step 2: Allocate zeroed frames + map pages.
            // R192-RES-2: bounded holds, as sys_mmap; the free-frame precheck
            // refuses a region larger than the free frames before allocating.
            // M2-1 SLICE-4a: the populator records the intermediate PT/PD frames
            // map_to builds for this PROT_NONE -> real materialization; they are
            // charged + ledgered at the Step-3 commit, mirroring sys_mmap.
            let map_result = EagerPopulator::new(
                "mprotect",
                &process,
                region_base,
                region_len / 0x1000,
                flags,
            )
            .run();

            // M2-1 SLICE-4a: capture the recorded PT-frame identities on success
            // (consumed by the Step-3 commit fold).
            let pt_frames = match map_result {
                Err(failed) => {
                    // R146-2 FIX: Re-read cgroup_id under lock before rollback uncharge.
                    // R147-1 FIX: Clear mprotect_pending_bytes before uncharge.
                    let rollback_cgroup_id = {
                        let proc = process.lock();
                        let mut mm = mm_arc.lock();
                        mm.mprotect_pending_bytes =
                            mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                        // R149-6 FIX: Clear the transient mprotect flag on rollback.
                        if let Some(entry) = mm.mmap_regions.get_mut(&region_base) {
                            entry.clear_pending_mprotect();
                        }
                        // R192-RES-2: settle the rolled-back region's tables
                        // under this same hold (free-after-remove).
                        failed.settle(&mut mm, proc.cgroup_id);
                        proc.cgroup_id
                    };
                    cgroup::uncharge_memory(rollback_cgroup_id, region_len as u64);
                    let error = populate_errno(failed.error);
                    drop(failed);
                    return Err(error);
                }
                Ok(frames) => frames,
            };

            // Step 3: Commit bookkeeping — clear PROT_NONE, set prot bits,
            // track charge.
            //
            // R149-6 FIX: Verify the entry still exists and has our transient
            // PENDING_MPROTECT flag. If the entry was removed (e.g., by a
            // concurrent munmap that raced before we set the flag — should be
            // impossible with the flag, but defensive), roll back the charge
            // instead of silently re-inserting a ghost entry.
            // M2-1 SLICE-4a: the PT-frame kmem charge for the frames map_to built
            // for this region (frame identity, recorded above by
            // RecordingFrameAllocator). The fold runs in the committing arm below,
            // under BOTH the Process and MmState locks (canonical Process -> MmState
            // order). The PRE-SLICE-4a commit took ONLY mm_arc.lock(); folding a
            // cgroup charge there would race a concurrent sys_cgroup_attach (which
            // snapshots compute_cgroup_charged_bytes — INCLUDING pt_charged_bytes —
            // under the Process lock) and strand the PT charge + its mem_pinned pin
            // on a stale cgroup. Holding the Process lock across the fold closes that
            // window — exactly as sys_mmap Phase-3 does.
            let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);
            let commit_result: Result<MmapEntry, ()> = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                match mm.mmap_regions.get(&region_base).copied() {
                    Some(old) if old.is_pending_mprotect() => {
                        // Entry present with our transient flag — commit.
                        // Clear PROT_NONE + old prot bits + transient mprotect flag.
                        let preserved = old.committed_flags_excluding_prot();
                        let new_entry =
                            MmapEntry::from_len_flags(region_len, preserved | new_prot_flags);
                        // next-phase #11: `region_base` is present (matched just
                        // above under this same lock hold), so replace in place —
                        // get_mut cannot allocate, keeping this commit infallible.
                        if let Some(slot) = mm.mmap_regions.get_mut(&region_base) {
                            *slot = new_entry;
                        }
                        mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(region_len as u64);
                        // R147-1 FIX: Charge is now reflected in mmap_regions.
                        mm.mprotect_pending_bytes =
                            mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                        // M2-1 SLICE-4a: charge + ledger the PT-frame kmem this
                        // PROT_NONE -> real materialization built, under the SAME
                        // Process + MmState hold (migration-atomic). charge_memory_forced
                        // is the SOFT/forced charge (the PT delta is knowable only after
                        // map_to ran; a hard reject would orphan already-built tables
                        // uncharged = a worse bypass). record_pt_charge does the per-AS
                        // ledger + INVARIANT-I' bookkeeping (the unit-tested mirror of
                        // the sys_mmap Phase-3 fold). Reclaim rides this region's
                        // eventual munmap Phase-3 fold (pt_ledger_reconcile, frame
                        // identity) or last-exit teardown.
                        if pt_bytes > 0 {
                            cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
                            mm.record_pt_charge(&pt_frames);
                        }
                        Ok(new_entry)
                    }
                    _ => {
                        // Entry gone or flag cleared — concurrent munmap removed it
                        // (defensive: PENDING_MPROTECT blocks that). Roll back the DATA
                        // charge below. M2-1 SLICE-4a: charge + ledger NOTHING for PT
                        // here — the map_to-built frames were never ledgered, so a
                        // concurrent munmap's reconcile debits 0 (no bypass) and they
                        // ride to teardown (over-count-safe). `pt_frames` is dropped.
                        mm.mprotect_pending_bytes =
                            mm.mprotect_pending_bytes.saturating_sub(region_len as u64);
                        Err(())
                    }
                }
            };

            let committed = match commit_result {
                Ok(entry) => entry,
                Err(()) => {
                    // R149-6 FIX: Rollback charge — entry was removed during PT ops.
                    let rollback_cgroup_id = process.lock().cgroup_id;
                    cgroup::uncharge_memory(rollback_cgroup_id, region_len as u64);
                    // Continue with remaining regions (POSIX allows partial success).
                    continue;
                }
            };

            // D3-ARC-MM-SHARED: sync_vm_siblings_mprotect_flags is no longer
            // needed — all CLONE_VM siblings share the same MmState.
            let _ = committed; // suppress unused variable warning
        }
    }

    // ---------------------------------------------------------------
    // Path B — real permissions → PROT_NONE:
    // Unmap/free frames, uncharge cgroup, set PROT_NONE flag.
    // ---------------------------------------------------------------
    if is_target_prot_none && !real_regions.is_empty() {
        for &(region_base, region_len) in &real_regions {
            // R168-1 FIX (found during the D2-MMAP-LIFECYCLE Phase 2 re-land
            // audit): Path B demotes a real region to PROT_NONE by unmapping its
            // frames with the shared MmState lock DROPPED for the page-table
            // work. The previous code set NO transient marker over that window,
            // so a concurrent munmap (or mprotect) on the same MmState (a
            // CLONE_VM sibling) could interleave: capture the region as still
            // real+charged, mark PENDING_UNMAP, drop its lock — and this path's
            // commit would then transition to PROT_NONE and uncharge the cgroup,
            // after which the racing munmap's Phase 3 would uncharge the SAME
            // bytes a SECOND time (cgroup memory_current driven below true usage
            // → memory.max isolation bypass / container DoS). Mirror Path A's
            // proven protocol: claim the entry with PENDING_MPROTECT under the
            // lock BEFORE the unmap, so concurrent munmap / mprotect / fork fail
            // closed on has_transient() for the whole window. The claim is
            // released by the prot_none() commit in Step 3.
            //
            // Path B does NOT touch mprotect_pending_bytes: unlike Path A it does
            // not pre-charge — the region stays charged across the claim window
            // (still non-PROT_NONE, so compute_cgroup_charged_bytes() keeps
            // counting it) and the charge is removed exactly once, at commit.
            //
            // Step 1: Claim the live entry under the lock, re-validating against
            // the Phase-0 snapshot (the lock was free since classification, so a
            // racing op may have demoted / removed / split it in between).
            let claimed = {
                let mut mm = mm_arc.lock();
                if mm.fork_in_progress {
                    return Err(SyscallError::EAGAIN);
                }
                match mm.mmap_regions.get_mut(&region_base) {
                    Some(entry) => {
                        if entry.is_prot_none() {
                            // A concurrent mprotect already demoted + uncharged it.
                            false
                        } else if entry.has_transient() {
                            // Another in-flight op (munmap / mprotect) owns it and
                            // will account for it. POSIX permits partial success.
                            false
                        } else if entry.len() != region_len {
                            // R168-2 FIX: region was split/resized in the window;
                            // the stale Phase-0 length no longer matches the live
                            // entry. Skip rather than rewrite a mismatched length.
                            false
                        } else {
                            entry.set_pending_mprotect();
                            true
                        }
                    }
                    None => false, // a concurrent munmap removed + uncharged it.
                }
            };
            if !claimed {
                continue;
            }

            // ---------------------------------------------------------------
            // M2-1 SLICE-4e (DEFERRED — intentional, NOT an oversight): this
            // real -> PROT_NONE demotion deliberately does NOT prune the now-empty
            // intermediate PT/PD tables. The region stays in mmap_regions as
            // PROT_NONE and its tables stay charged in the per-AS ledger; they are
            // reclaimed + frame-identity-reconciled later by sys_munmap Phase-3 (the
            // common path) or wholesale at last-exit / exec teardown
            // (process::free_process_resources). Pruning here would only churn tables a
            // later Path-A re-materialization rebuilds. This is OVER-COUNT-SAFE
            // (charged-but-reserved): never a memory.max bypass and never a leak —
            // reclamation is by page-table-STRUCTURE walk (prune_empty_tables_in_range)
            // + frame-identity reconcile (pt_ledger_reconcile), NOT by mmap_regions
            // membership. See docs/next-phase-plan.md (M2-1 SLICE-4e) for the full
            // 5-path reclamation proof, incl. the forked-child non-authoritative case
            // (pt_ledger_authoritative=false skips the munmap-time debit; the inherited
            // basis rides to wholesale teardown, process.rs free_process_resources).
            // The DEFER adds zero code under PT_LOCK and zero ledger writes under the
            // Step-3 Process+MmState hold — migration-atomicity is untouched.
            // ---------------------------------------------------------------
            // Step 2: Unmap pages and free frames (COW-aware).
            // R158-7 FIX: fallible deferred frame collection with immediate flush+free on OOM.
            // Issue #109 §1.1 (H1): Always complete TLB shootdown BEFORE calling
            // `PAGE_REF_COUNT.release` so a concurrent process on another PT lock
            // shard cannot observe refcount 2->1 and perform an in-place writable
            // CoW upgrade (or frame reuse) while a sibling CPU still holds a stale TLB.
            let removed_leaf_count = unsafe {
                use mm::memory::FrameAllocator;

                with_current_manager(VirtAddr::new(0), |manager| -> usize {
                    use alloc::vec::Vec;
                    use x86_64::structures::paging::PhysFrame;

                    let mut frame_alloc = FrameAllocator::new();
                    let mut unmapped_frames: Vec<PhysFrame> = Vec::new();
                    let _ = unmapped_frames.try_reserve(region_len / 0x1000);
                    let mut removed_count = 0usize;

                    for offset in (0..region_len).step_by(0x1000) {
                        let page =
                            Page::containing_address(VirtAddr::new((region_base + offset) as u64));

                        let frame_opt = match manager.unmap_page(page) {
                            Ok(frame) => Some(frame),
                            Err(mm::page_table::UnmapError::PageNotMapped) => {
                                manager.take_nonpresent_leaf_frame(page)
                            }
                            Err(_) => None,
                        };

                        if let Some(frame) = frame_opt {
                            removed_count += 1;
                            if unmapped_frames.try_reserve(1).is_ok() {
                                unmapped_frames.push(frame);
                            } else {
                                // OOM fallback: flush this page before releasing refcount.
                                mm::flush_current_as_page(page.start_address());
                                let phys_addr = frame.start_address().as_u64() as usize;
                                if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                                    frame_alloc.deallocate_frame(frame);
                                }
                            }
                        }
                    }

                    // Batch TLB shootdown BEFORE releasing any refcount or freeing frames.
                    if !unmapped_frames.is_empty() {
                        mm::flush_current_as_range(VirtAddr::new(region_base as u64), region_len);
                        for frame in unmapped_frames {
                            let phys_addr = frame.start_address().as_u64() as usize;
                            if PAGE_REF_COUNT.release(phys_addr).should_free_unmapped() {
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                    }
                    removed_count
                })
            };

            // Step 3: Commit real→PROT_NONE in the shared MmState, releasing the
            // PENDING_MPROTECT claim (prot_none() clears every flag but
            // PROT_NONE). Because we held the claim across the unmap window, the
            // entry is guaranteed present, still our claim, and unchanged in
            // length. Read cgroup_id under the SAME Process→MmState critical
            // section as the vm_charged_bytes decrement (R146-2 pattern) so a
            // concurrent cgroup migration can never split the decrement from its
            // uncharge target. Write the LIVE entry length (R168-2), not the
            // stale Phase-0 region_len.
            let transition = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                match mm.mmap_regions.get(&region_base).copied() {
                    Some(old) if old.is_pending_mprotect() => {
                        let live_len = old.len();
                        // next-phase #11: `region_base` is present (matched just
                        // above under this same lock hold), so replace in place —
                        // get_mut cannot allocate, keeping this commit infallible.
                        if let Some(slot) = mm.mmap_regions.get_mut(&region_base) {
                            *slot = MmapEntry::prot_none(live_len);
                        }
                        if old.is_lazy_anon() && removed_leaf_count > 0 {
                            mm.lazy_anon_resident_bytes = mm
                                .lazy_anon_resident_bytes
                                .saturating_sub((removed_leaf_count as u64).saturating_mul(0x1000));
                        }
                        mm.reclaim_empty_shared_fault_pt_capacity();
                        mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(live_len as u64);
                        Some((proc.cgroup_id, live_len))
                    }
                    _ => {
                        // Unreachable while we hold the claim (munmap / mprotect /
                        // fork all fail closed on has_transient). If the claim
                        // were somehow lost, fail toward OVER-counting (skip the
                        // uncharge) rather than risk the double-uncharge isolation
                        // bypass this fix exists to prevent — the frames were
                        // already freed in Step 2.
                        debug_assert!(
                            false,
                            "mprotect Path B: lost PENDING_MPROTECT claim at {:#x}",
                            region_base
                        );
                        None
                    }
                }
            };

            if let Some((uncharge_cgroup_id, uncharge_len)) = transition {
                cgroup::uncharge_memory(uncharge_cgroup_id, uncharge_len as u64);
            }
        }
    }

    // R180-19: Path C used to change PTEs first and only later rewrite VMA
    // protection metadata. A CLONE_VM sibling could fork in that gap and clone
    // new PTEs with old metadata. Claim every covered VMA before PT_LOCK and
    // retain the claim through the metadata commit.
    struct MprotectPteReservation {
        mm: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>>,
        start: usize,
        end: usize,
        armed: bool,
    }
    impl Drop for MprotectPteReservation {
        fn drop(&mut self) {
            if self.armed {
                let mut mm = self.mm.lock();
                for (_, entry) in mm.mmap_regions.range_mut(self.start..self.end) {
                    if entry.is_pending_mprotect() {
                        entry.clear_pending_mprotect();
                    }
                }
            }
        }
    }

    // Reserve rollback storage before claiming metadata or touching a PTE.
    let page_count = len_aligned / 0x1000;
    let mut previous_pte_flags: Vec<(Page, PageTableFlags)> = Vec::new();
    previous_pte_flags
        .try_reserve_exact(page_count)
        .map_err(|_| SyscallError::ENOMEM)?;

    let mut pte_reservation = {
        let mut mm = mm_arc.lock();
        if mm.fork_in_progress {
            return Err(SyscallError::EAGAIN);
        }
        let mut coverage = addr;
        for (&region_base, entry) in mm.mmap_regions.range(addr..end) {
            if entry.has_transient() {
                return Err(SyscallError::EBUSY);
            }
            if region_base > coverage {
                return Err(SyscallError::ENOMEM);
            }
            coverage = coverage.max(region_base.saturating_add(entry.len()));
        }
        if coverage < end {
            return Err(SyscallError::ENOMEM);
        }
        for (_, entry) in mm.mmap_regions.range_mut(addr..end) {
            entry.set_pending_mprotect();
        }
        MprotectPteReservation {
            mm: Arc::clone(&mm_arc),
            start: addr,
            end,
            armed: true,
        }
    };

    let result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            for offset in (0..len_aligned).step_by(0x1000) {
                let vaddr = VirtAddr::new((addr + offset) as u64);
                let page = Page::containing_address(vaddr);
                let Some((_phys, current_flags)) = manager.translate_with_flags(vaddr) else {
                    continue;
                };
                previous_pte_flags.push((page, current_flags));
                let new_flags = reconcile_cow_mprotect_flags(current_flags, flags);
                if manager.update_flags(page, new_flags).is_err() {
                    // Restore every page already touched before releasing the
                    // VMA claim. Capacity was reserved up front, so rollback
                    // itself cannot allocate or fail for lack of bookkeeping.
                    for &(rollback_page, rollback_flags) in previous_pte_flags.iter().rev() {
                        let _ = manager.update_flags(rollback_page, rollback_flags);
                    }
                    mm::flush_current_as_range(VirtAddr::new(addr as u64), len_aligned);
                    return Err(SyscallError::EFAULT);
                }
            }
            Ok(())
        })
    };

    result?;

    // 刷新 TLB
    mm::flush_current_as_range(VirtAddr::new(addr as u64), len_aligned);

    // R145-2 FIX: Update mmap_regions protection display bits to match the
    // new PTE flags.  Path A/B already handled PROT_NONE transitions above;
    // this block updates the prot display bits (READ/WRITE/EXEC) for all
    // regions in [addr, end) so /proc/[pid]/maps shows accurate permissions.
    // For Path A/B regions this is a harmless no-op (bits already correct).
    //
    // R146-8 FIX: Also propagate display-bit updates to CLONE_VM siblings
    // so their /proc/[pid]/maps shows consistent permissions. Collect
    // updated entries and sync after releasing the process lock.
    // D3-ARC-MM-SHARED: Update display bits directly in shared MmState.
    // sync_vm_siblings_mprotect_flags is no longer needed — all CLONE_VM
    // siblings share the same MmState via Arc<Mutex<MmState>>.
    {
        let mut mm = mm_arc.lock();
        for (&_region_base, len_with_flags) in mm.mmap_regions.range_mut(addr..end) {
            debug_assert!(len_with_flags.is_pending_mprotect());
            len_with_flags.rewrite_prot_bits(new_prot_flags);
            len_with_flags.clear_pending_mprotect();
        }
        pte_reservation.armed = false;
    }

    Ok(0)
}

/// ST-K2-MREMAP: page flags for frames this call materializes for a grown
/// anonymous tail.  Reconstructed from the committed per-region prot bits, so
/// the tail matches the rest of the VMA.  A freshly materialized page has
/// never been shared, so it is plain writable rather than COW — exactly what
/// `sys_mmap` would have produced for the same range.
#[inline]
pub(super) fn mremap_page_flags(
    committed_flags: usize,
) -> x86_64::structures::paging::PageTableFlags {
    use x86_64::structures::paging::PageTableFlags;

    let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if committed_flags & MMAP_REGION_FLAG_PROT_WRITE != 0 {
        page_flags |= PageTableFlags::WRITABLE;
    }
    if committed_flags & MMAP_REGION_FLAG_PROT_EXEC == 0 {
        page_flags |= PageTableFlags::NO_EXECUTE;
    }
    page_flags
}

/// ST-K2-MREMAP: reconstruct a POSIX `prot` word from committed region flags
/// for the LSM destination hook.
#[inline]
pub(super) fn mmap_flags_to_prot(committed_flags: usize) -> u32 {
    let mut prot = 0u32;
    if committed_flags & MMAP_REGION_FLAG_PROT_READ != 0 {
        prot |= PROT_READ as u32;
    }
    if committed_flags & MMAP_REGION_FLAG_PROT_WRITE != 0 {
        prot |= PROT_WRITE as u32;
    }
    if committed_flags & MMAP_REGION_FLAG_PROT_EXEC != 0 {
        prot |= PROT_EXEC as u32;
    }
    prot
}

/// ST-K2-MREMAP: the prepared transaction for one `mremap` call.
///
/// Built entirely inside ONE `Process → MmState` critical section, so the
/// source VMA is claimed (`PENDING_UNMAP`) and the destination reserved
/// (`PENDING_MAP`) atomically with respect to every other mutator and to
/// `fork`'s snapshot.  Phase 2 then runs with both locks dropped.
pub(super) struct MremapTx {
    /// Source VMA base — the key the caller passed.
    pub(super) old_base: usize,
    /// Destination base; equal to `old_base` unless the VMA is relocated.
    pub(super) new_base: usize,
    pub(super) old_len: usize,
    pub(super) new_len: usize,
    /// Committed per-region flags captured from the source entry.
    pub(super) committed_flags: usize,
    /// The VMA is being relocated to `new_base`.
    pub(super) moved: bool,
    /// Key of the temporary `PENDING_MAP` entry reserving the growth window
    /// (`old_base + old_len` for an in-place grow, `new_base` for a move).
    /// `0` when the operation only releases address space.
    pub(super) reserved_base: usize,
    pub(super) old_next_mmap_addr: usize,
    /// This call advanced `next_mmap_addr` and must restore it on rollback.
    pub(super) next_advanced: bool,
    /// LEAD-MREMAP-MIGRATE-1: what this call added to
    /// `MmState::mremap_uncharged_reserve_bytes`; removed again by the commit or
    /// the rollback that replaces the reservation.
    pub(super) uncharged_reserve: usize,
}

/// ST-K2-MREMAP: undo a failed relocation install.
///
/// `installed` counts the relocated pages, mapped in order from `base`.  The
/// destination range is always built from scratch by this call, so unmapping
/// it cannot disturb any pre-existing mapping; that is precisely why the whole
/// install step runs before the source is touched.  A relocated frame's
/// reference travelled with its PTE and is still held by the untouched source
/// PTE, so it is deliberately NOT released here.  (The fresh growth tail is
/// populated before this hold and rolled back by its populator.)
///
/// LEAD-MREMAP-ROLLBACK-FLUSH-1 FIX: another CPU may cache a destination
/// translation, so the destination is flushed on every CPU whenever a leaf was
/// removed; once the source is later unmapped and its frames freed, no stale
/// destination entry can reach them.  The tables pruned here are carried to
/// the error arm (LEAD-ROLLBACK-PRUNE-LEDGER-1) instead of being freed under
/// the lock.
///
/// # Safety
/// Caller must hold `PT_LOCK` (i.e. be inside `with_current_manager`).
pub(super) unsafe fn mremap_rollback_install(
    manager: &mut mm::page_table::PageTableManager,
    base: usize,
    installed: usize,
    len: usize,
    pruned: &mut vec::Vec<x86_64::structures::paging::PhysFrame>,
) {
    use x86_64::structures::paging::{Page, Size4KiB};
    use x86_64::VirtAddr;

    // R192-RES-2a: the install maps pages in order from `base`, so a count
    // names them (it used to be a heap list built under the lock).
    let mut removed_leaf = false;
    for index in 0..installed {
        let page =
            Page::<Size4KiB>::containing_address(VirtAddr::new((base + index * 0x1000) as u64));
        removed_leaf |= manager.unmap_page(page).is_ok();
    }
    if removed_leaf {
        mm::flush_current_as_range(VirtAddr::new(base as u64), len);
    }

    // Reclaim intermediate tables the install pulled and then emptied.  A table
    // that still backs live leaves (the populated tail) is not empty and is
    // correctly left alone.
    manager.prune_empty_tables_in_range(VirtAddr::new(base as u64), len, pruned);
}

/// R192-RES-2a: the most page tables `map_page` can create for `[dst, dst +
/// len)`: one PT per 2 MiB region, one PD per 1 GiB region and one PDPT per
/// 512 GiB region it touches. Under `PT_LOCK` nothing prunes a table between
/// the pages of one hold, so this bounds the hold whatever already exists.
pub(super) fn relocation_table_bound(dst: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let last = dst + (len - 1);
    let spans = |shift: u32| (last >> shift) - (dst >> shift) + 1;
    spans(21) + spans(30) + spans(39)
}

/// R192-RES-2a: free-list entries a shrink reserves before its hold. A full
/// list is flushed and freed as one batch inside the hold and then reused, so
/// a shrink of N pages takes about N / 512 range flushes.
pub(super) const MREMAP_FREE_RESERVE: usize = 512;

/// R192-RES-2a: what the mremap PTE hold uses, all taken before it.
pub(super) struct MremapHoldStage {
    /// Retained through Drop so detached tables lose their ledger entries
    /// before their physical addresses can be reused. Drop runs outside PT_LOCK.
    pub(super) process: crate::process::ProcessArc,
    /// Page-table frames for a relocation, `relocation_table_bound` of them.
    pub(super) tables: vec::Vec<Option<x86_64::structures::paging::PhysFrame>>,
    /// A shrink's frames to free after the flush (capped).
    pub(super) frames_to_free: vec::Vec<x86_64::structures::paging::PhysFrame>,
    /// Tables the source removal prunes.
    pub(super) reclaimed: vec::Vec<x86_64::structures::paging::PhysFrame>,
}

impl MremapHoldStage {
    /// Give back the staged tables the hold did not take. They were never
    /// linked, so they need no flush. Returns how many.
    pub(super) fn return_unused(&mut self) -> usize {
        let mut allocator = mm::memory::FrameAllocator::new();
        let mut returned = 0;
        for frame in self.tables.drain(..).flatten() {
            allocator.deallocate_frame(frame);
            returned += 1;
        }
        returned
    }
}

impl Drop for MremapHoldStage {
    fn drop(&mut self) {
        // Ordinarily these lists are drained/transferred by step 2. Cover a
        // future early exit too: leaves may not yet have had their final flush,
        // and a detached table may still be named in the address-space ledger.
        if !self.frames_to_free.is_empty() || !self.reclaimed.is_empty() {
            mm::flush_current_as_all();
            if !self.reclaimed.is_empty() {
                let proc = self.process.lock();
                let mut space = proc.mm.lock();
                if space.pt_ledger_authoritative {
                    let bytes = space.reclaim_pt_charges(
                        self.reclaimed.iter().map(|f| f.start_address().as_u64()),
                    );
                    space.pt_charged_bytes = space.pt_charged_bytes.saturating_sub(bytes);
                    cgroup::uncharge_memory(proc.cgroup_id, bytes);
                }
            }
            let mut allocator = mm::memory::FrameAllocator::new();
            for frame in self
                .frames_to_free
                .drain(..)
                .chain(self.reclaimed.drain(..))
            {
                allocator.deallocate_frame(frame);
            }
        }
        self.return_unused();
    }
}

/// R192-RES-2a: stage the mremap hold. A relocation of `[dst, dst + len)`
/// takes every page table the move can need (with the allocator's OOM
/// handling: the single hold cannot retry), their record slots and its prune
/// lists here, so the hold allocates nothing. It never frees a moved frame
/// (LEAD-MREMAP-RELOC-UAF-1), so it needs no free list. An in-place shrink
/// keeps its best-effort lists.
pub(super) fn stage_mremap_hold(
    process: &crate::process::ProcessArc,
    frame_alloc: &mut RecordingFrameAllocator,
    carried: &mut vec::Vec<x86_64::structures::paging::PhysFrame>,
    relocation: Option<(usize, usize)>,
    removed_len: usize,
    tail_pages: usize,
) -> Result<MremapHoldStage, SyscallError> {
    let removed_pages = removed_len / 0x1000;
    let mut stage = MremapHoldStage {
        process: Arc::clone(process),
        tables: vec::Vec::new(),
        frames_to_free: vec::Vec::new(),
        reclaimed: vec::Vec::new(),
    };
    let Some((dst, len)) = relocation else {
        if removed_len != 0 {
            let _ = stage
                .frames_to_free
                .try_reserve_exact(removed_pages.min(MREMAP_FREE_RESERVE));
            let _ = stage
                .reclaimed
                .try_reserve_exact(populate_prune_reserve(removed_pages));
        }
        return Ok(stage);
    };
    if process.lock().pending_kill.load(AtomicOrdering::Acquire) {
        return Err(SyscallError::EINTR);
    }
    let bound = relocation_table_bound(dst, len);
    // RES-2 decision 2b: an impossible request never wakes the OOM killer.
    if mm::buddy_allocator::get_allocator_stats().is_some_and(|stats| stats.free_pages < bound) {
        return Err(SyscallError::ENOMEM);
    }
    // The install rollback prunes the destination and the tail rollback after
    // it the tail, into the same carried list: reserve both, as `try_reserve`
    // counts from the current length.
    let carry = populate_prune_reserve(len / 0x1000) + populate_prune_reserve(tail_pages);
    if stage.tables.try_reserve_exact(bound).is_err()
        || stage
            .reclaimed
            .try_reserve_exact(populate_prune_reserve(removed_pages))
            .is_err()
        || carried.try_reserve(carry).is_err()
        || frame_alloc.pt_frames.try_reserve(bound).is_err()
    {
        return Err(SyscallError::ENOMEM);
    }
    for _ in 0..bound {
        let frame = frame_alloc
            .inner
            .allocate_frame()
            .ok_or(SyscallError::ENOMEM)?;
        stage.tables.push(Some(frame));
    }
    Ok(stage)
}

/// mremap(2) - remap a virtual memory address
///
/// ST-K2-MREMAP: resizes an anonymous private VMA, relocating it when
/// `MREMAP_MAYMOVE` is given and there is no free address space directly above
/// the mapping.  See `docs/review/design/st-k2-mremap-anonymous-design.md` for
/// the transaction, the ownership argument and the fail-closed boundary.
///
/// Supported: private anonymous and private `PROT_NONE` VMAs, resized in place
/// or relocated.  `old_size` must match the live VMA exactly — a sub-range
/// resize would require splitting the VMA and is rejected.  Shared-anonymous
/// VMAs, `MREMAP_FIXED`, `MREMAP_DONTUNMAP` and unknown flag bits return a
/// stable errno before any VMA/page-table/cgroup state changes.
///
/// `new_addr` is meaningful only with `MREMAP_FIXED`, which is not supported.
/// With `MREMAP_MAYMOVE` alone a C caller reaches this through a varargs ABI
/// and leaves the register undefined (musl's `realloc` calls
/// `mremap(old, o, n, MREMAP_MAYMOVE)`), so the argument is deliberately not
/// read — that is the documented meaning of the argument, not a dropped
/// request.
///
/// # Arguments
/// - `old_addr`: current mapping address
/// - `old_size`: current mapping size (must match the VMA exactly)
/// - `new_size`: desired new size
/// - `flags`: `MREMAP_MAYMOVE` or 0
/// - `new_addr`: unused (see above)
pub(super) fn sys_mremap(
    old_addr: u64,
    old_size: usize,
    new_size: usize,
    flags: i32,
    _new_addr: u64,
) -> Result<usize, SyscallError> {
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PhysFrame};
    use x86_64::VirtAddr;

    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1130); // sys_mremap entry
    }

    let old_base = old_addr as usize;

    // ---- Argument validation.  Nothing below reads or writes VMA,
    // page-table or cgroup state until every one of these has passed. ----
    if old_size == 0 || new_size == 0 {
        return Err(SyscallError::EINVAL);
    }
    if old_base & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }
    if let Err(error) = validate_mremap_flags(flags) {
        #[cfg(feature = "kcov")]
        {
            coverage::trace_pc(1131); // sys_mremap unsupported flags
        }
        return Err(error);
    }

    let old_len = old_size.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;
    let new_len = new_size.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // ---- Phase 1: validate, then claim the source and reserve the
    // destination under ONE Process → MmState critical section. ----
    let (tx_opt, mm_arc) = {
        let mut proc = process.lock();
        let mm_arc: Arc<crate::owner_lock::OwnerCpuMutex<crate::process::MmState>> =
            Arc::clone(&proc.mm);
        // A second handle for the post-Phase-1 lock-free window: `mm` below
        // borrows `mm_arc`, so this clone is what leaves the block.
        let mm_arc_out = Arc::clone(&mm_arc);
        let mut mm = mm_arc.lock();

        if mm.fork_in_progress {
            return Err(SyscallError::EAGAIN);
        }

        let entry = *mm.mmap_regions.get(&old_base).ok_or(SyscallError::EINVAL)?;

        if entry.has_transient() {
            // Another operation owns this VMA right now (mmap commit, munmap,
            // mprotect Path A/B).  Fail closed rather than race it.
            return Err(SyscallError::EBUSY);
        }
        if entry.is_shared() {
            // A shared-anonymous VMA's region object is snapshotted into every
            // fork child, so resizing it here would let a child observe — and
            // re-fault — a range the parent no longer owns, silently splitting
            // shared memory.  Fail closed until a region-identity model exists.
            #[cfg(feature = "kcov")]
            {
                coverage::trace_pc(1132); // sys_mremap shared VMA unsupported
            }
            return Err(SyscallError::EOPNOTSUPP);
        }
        if entry.len() != old_len {
            return Err(SyscallError::EINVAL);
        }

        let committed_flags = entry.flags();
        let prot_none = committed_flags & MMAP_REGION_FLAG_PROT_NONE != 0;

        // R131-2 style: build the LSM subject from the held guard, never via a
        // pid-keyed lookup that would re-take this lock.
        let ctx = lsm_process_ctx_from(&proc)?;
        if lsm::hook_memory_munmap(&ctx, old_base as u64, old_len as u64).is_err() {
            return Err(SyscallError::EPERM);
        }

        // Is [base, end) free of every other VMA, the user-stack window, the
        // R172-16 brk-grow reservation, and the user-space bounds?
        let range_is_free =
            |mm: &crate::process::MmState, base: usize, end: usize| -> Result<bool, SyscallError> {
                if base < crate::usercopy::MMAP_MIN_ADDR || end > USER_SPACE_TOP {
                    return Ok(false);
                }
                let (win_start, win_end) = crate::elf_loader::user_mapping_reserved_window();
                if base < win_end && end > win_start {
                    return Ok(false);
                }
                if mm.brk_grow_resv_lo < mm.brk_grow_resv_hi
                    && base < mm.brk_grow_resv_hi
                    && end > mm.brk_grow_resv_lo
                {
                    return Ok(false);
                }
                for (&region_base, &region_entry) in mm.mmap_regions.iter() {
                    let region_end = region_base
                        .checked_add(mmap_region_len(region_entry))
                        .ok_or(SyscallError::EFAULT)?;
                    if base < region_end && end > region_base {
                        return Ok(false);
                    }
                }
                // R192-2 FIX (D0-ISO-1) + LEAD-MMAP-OWN-1: nor may it reach a
                // translation no VMA records: the identity map, the ELF image
                // or the heap (see sys_mmap).
                if mm::page_table::first_occupied_user_page(
                    base as u64,
                    end.saturating_sub(base) as u64,
                )
                .is_some()
                {
                    return Ok(false);
                }
                Ok(true)
            };

        let old_next_mmap_addr = mm.next_mmap_addr;

        let result = if new_len == old_len {
            // Resize to the current size: fully validated, nothing to change.
            None
        } else if new_len < old_len {
            // ---- Shrink: claim the source; Phase 2 removes the tail. ----
            mm.mmap_regions
                .try_insert(
                    old_base,
                    MmapEntry::from_len_flags(old_len, committed_flags).with_pending_unmap(),
                )
                .map_err(|_| SyscallError::ENOMEM)?;

            Some(MremapTx {
                old_base,
                new_base: old_base,
                old_len,
                new_len,
                committed_flags,
                moved: false,
                reserved_base: 0,
                old_next_mmap_addr,
                next_advanced: false,
                // A shrink reserves nothing; the claimed source stays charged.
                uncharged_reserve: 0,
            })
        } else {
            // ---- Grow: choose the destination, then reserve it. ----
            let old_end = old_base.checked_add(old_len).ok_or(SyscallError::EFAULT)?;
            let tail_len = new_len - old_len;
            let tail_end = old_end.checked_add(tail_len).ok_or(SyscallError::EFAULT)?;

            // The source entry ends exactly at `old_end`, so the half-open
            // overlap test below never reports the source against itself.
            let in_place = range_is_free(&mm, old_end, tail_end)?;
            let (new_base, reserved_base, reserved_len) =
                match decide_mremap_placement(in_place, flags & MREMAP_MAYMOVE != 0) {
                    MremapPlacement::InPlace => (old_base, old_end, tail_len),
                    MremapPlacement::Refuse => {
                        // Cannot grow in place and the caller forbade relocation.
                        return Err(SyscallError::ENOMEM);
                    }
                    MremapPlacement::Relocate => {
                        // Auto-place exactly like sys_mmap's hint-less arm.
                        let candidate = mm
                            .next_mmap_addr
                            .checked_add(0xfff)
                            .ok_or(SyscallError::EINVAL)?
                            & !0xfff;
                        let candidate = if candidate < crate::usercopy::MMAP_MIN_ADDR {
                            crate::usercopy::MMAP_MIN_ADDR
                        } else {
                            candidate
                        };
                        let (win_start, win_end) =
                            crate::elf_loader::user_mapping_reserved_window();
                        let base = resolve_auto_mmap_base(candidate, new_len, win_start, win_end);
                        let end = base.checked_add(new_len).ok_or(SyscallError::EFAULT)?;
                        if !range_is_free(&mm, base, end)? {
                            return Err(SyscallError::ENOMEM);
                        }
                        (base, base, new_len)
                    }
                };

            // Compute the final end address BEFORE any mutation: a `?` after
            // the reservation/charge/claim below would strand all three.
            let new_end = new_base.checked_add(new_len).ok_or(SyscallError::EFAULT)?;

            if lsm::hook_memory_mmap(
                &ctx,
                new_base as u64,
                new_len as u64,
                mmap_flags_to_prot(committed_flags),
                (MAP_PRIVATE | MAP_ANONYMOUS) as u32,
            )
            .is_err()
            {
                return Err(SyscallError::EPERM);
            }

            // R130-1 style bound: the transient peak is the live map plus the
            // growth-window reservation (a relocation to a NEW key adds one
            // more slot, so require room for it explicitly).
            if mm.mmap_regions.len() + 1 >= MAX_MAP_COUNT {
                return Err(SyscallError::ENOMEM);
            }

            // If growing/relocating a lazy private-anonymous VMA, run the
            // physical-RAM precheck for the grown tail and reserve demand-fault
            // PT ledger capacity for the destination range before committing.
            if (committed_flags & MMAP_REGION_FLAG_LAZY_ANON) != 0 && !prot_none {
                let tail_pages = tail_len / 0x1000;
                if mm::buddy_allocator::get_allocator_stats()
                    .is_some_and(|stats| tail_pages > stats.free_pages)
                {
                    return Err(SyscallError::ENOMEM);
                }
                mm.reserve_shared_fault_pt(Some((new_base, new_len)))
                    .map_err(|_| SyscallError::ENOMEM)?;
            }

            // Reserve the growth window BEFORE claiming the source, so a
            // concurrent mmap cannot take it during Phase 2.  `reserved_base`
            // is always a new key here (a growth tail, or a relocation
            // destination), so this is the fallible insert.
            // Preserve LAZY_ANON on lazy growth reservations so concurrent
            // Phase-2 OOM snapshots do not count unpopulated tail bytes as RSS
            // (while cgroup accounting still counts them via `mremap_uncharged_reserve`).
            let is_lazy_grow = (committed_flags & MMAP_REGION_FLAG_LAZY_ANON) != 0;
            let reserve_flags = MMAP_REGION_FLAG_PENDING_MAP
                | if is_lazy_grow {
                    MMAP_REGION_FLAG_LAZY_ANON
                } else {
                    0
                };
            if mm
                .mmap_regions
                .try_insert(
                    reserved_base,
                    MmapEntry::from_len_flags(reserved_len, reserve_flags),
                )
                .is_err()
            {
                return Err(SyscallError::ENOMEM);
            }

            // Charge the delta under the same lock, exactly like sys_mmap's
            // Phase-1 DATA charge.  A PROT_NONE reservation is never charged.
            if !prot_none && cgroup::try_charge_memory(proc.cgroup_id, tail_len as u64).is_err() {
                mm.mmap_regions.remove(&reserved_base);
                return Err(SyscallError::ENOMEM);
            }

            // Claim the source.  `old_base` is still present, so this is an
            // in-place replace that cannot allocate; the rollback is defensive.
            if mm
                .mmap_regions
                .try_insert(
                    old_base,
                    MmapEntry::from_len_flags(old_len, committed_flags).with_pending_unmap(),
                )
                .is_err()
            {
                mm.mmap_regions.remove(&reserved_base);
                if !prot_none {
                    cgroup::uncharge_memory(proc.cgroup_id, tail_len as u64);
                }
                return Err(SyscallError::ENOMEM);
            }

            // LEAD-MREMAP-MIGRATE-1 FIX: the reservation and the claimed source
            // overstate what was just charged; compute_cgroup_charged_bytes
            // subtracts the difference until the commit or rollback.
            let uncharged_reserve = mremap_uncharged_reserve(reserved_len, tail_len, prot_none);
            mm.mremap_uncharged_reserve_bytes = mm
                .mremap_uncharged_reserve_bytes
                .saturating_add(uncharged_reserve as u64);
            if is_lazy_grow {
                mm.mremap_lazy_uncharged_reserve_bytes = mm
                    .mremap_lazy_uncharged_reserve_bytes
                    .saturating_add(uncharged_reserve as u64);
            }

            let moved = new_base != old_base;
            let mut next_advanced = false;
            // Keep the auto-placement cursor at or past the new end for EVERY
            // grow, in place or relocated.  sys_mmap advances it to each
            // auto-placed region's end, so a grow that left it behind the grown
            // region would make the NEXT hint-less mmap select an address that
            // overlaps this mapping and fail spuriously with EINVAL.
            if mm.next_mmap_addr < new_end {
                mm.next_mmap_addr = new_end;
                next_advanced = true;
            }

            Some(MremapTx {
                old_base,
                new_base,
                old_len,
                new_len,
                committed_flags,
                moved,
                reserved_base,
                old_next_mmap_addr,
                next_advanced,
                uncharged_reserve,
            })
        };
        (result, mm_arc_out)
    }; // Process lock + MmState lock dropped here — Phase 1 complete

    let Some(tx) = tx_opt else {
        // Resize to the current size: validated, no state to change.
        return Ok(old_base);
    };

    let prot_none = tx.committed_flags & MMAP_REGION_FLAG_PROT_NONE != 0;

    // ---- Phase 2: page-table work with both locks dropped. ----
    //
    // R192-RES-2: the fresh growth tail is populated first, in bounded holds
    // (allocation and zeroing outside PT_LOCK, at most POPULATE_CHUNK_PAGES
    // pages per hold, a fatal signal aborts between chunks).  The tail lies
    // only in the reserved destination, so the source is untouched and a
    // failure undoes just the tail.  The relocation install and the source
    // removal then run in ONE hold: between holds a sibling's COW fault on the
    // still-live source could split it from an already-installed destination
    // PTE.  That hold maps no fresh data frames and allocates nothing:
    // R192-RES-2a stages its page tables and lists before it
    // (`stage_mremap_hold`).  It is bounded by `old_len`; the syscall_test
    // marker measures it.
    //
    // Ordering matters.  A relocation installs every destination PTE BEFORE
    // any source PTE is touched, so a failure here rolls back by undoing only
    // what this call installed and the source mapping is still fully intact.
    //
    // A PROT_NONE reservation owns no frames, so growing it extends the VA
    // record only, exactly as sys_mmap's PROT_NONE arm creates no page tables.
    let is_lazy_anon = (tx.committed_flags & MMAP_REGION_FLAG_LAZY_ANON) != 0;
    let tail_pages = if prot_none || is_lazy_anon {
        0
    } else {
        // GUARD: only a grow has a tail.  A shrink would underflow
        // `new_len - old_len` into a colossal page count.
        mremap_tail_len(tx.old_len, tx.new_len).map_or(0, |len| len / 0x1000)
    };
    let mut populator = EagerPopulator::new(
        "mremap",
        &process,
        tx.new_base + tx.old_len,
        tail_pages,
        mremap_page_flags(tx.committed_flags),
    );
    let phase2: Result<MremapPhase2, (SyscallError, FailedPopulate)> = match populator.populate() {
        Err(error) => Err((populate_errno(error), populator.into_failure(error))),
        Ok(()) => 'phase2: {
            let relocating = tx.moved && !prot_none;
            // The range step 2 removes: the whole source of a move, the tail of
            // a shrink.
            let (removed_start, removed_len) = if tx.moved {
                (tx.old_base, tx.old_len)
            } else if tx.new_len < tx.old_len {
                (tx.old_base + tx.new_len, tx.old_len - tx.new_len)
            } else {
                (0, 0)
            };
            // The relocation's tables are recorded with the tail's, and any it
            // prunes are carried with them. R192-RES-2a: they, their record
            // slots and the prune lists are all taken before the hold.
            let (frame_alloc, carried) = populator.parts();
            let staged = stage_mremap_hold(
                &process,
                frame_alloc,
                carried,
                relocating.then_some((tx.new_base, tx.old_len)),
                removed_len,
                tail_pages,
            );
            let mut stage = match staged {
                Ok(stage) => stage,
                Err(error) => {
                    #[cfg(feature = "syscall_test")]
                    if relocating && tx.old_len / 0x1000 >= POPULATE_REPORT_PAGES {
                        klog_always!(
                            "R192-RES-2a mremap relocation pages={} staged=0 used=0 returned=0 hold_tsc=0 cycles_per_ms=0 hold_us~=0 result={}",
                            tx.old_len / 0x1000,
                            if error == SyscallError::EINTR { "eintr" } else { "enomem" }
                        );
                    }
                    populator.rollback_all();
                    let cause = if error == SyscallError::EINTR {
                        crate::populate::PopulateError::Interrupted
                    } else {
                        crate::populate::PopulateError::NoMemory(
                            crate::populate::PopulateStage::MapPage,
                        )
                    };
                    let failed = populator.into_failure(cause);
                    break 'phase2 Err((error, failed));
                }
            };
            #[cfg(feature = "syscall_test")]
            let staged_tables = stage.tables.len();
            // Every table the hold takes is recorded here, so the growth of
            // this list counts the used ones independently of the returns.
            #[cfg(feature = "syscall_test")]
            let recorded_before = frame_alloc.pt_frames.len();
            #[cfg(feature = "syscall_test")]
            let mut hold_tsc = 0u64;
            let hold = unsafe {
                with_current_manager(
                    VirtAddr::new(0),
                    |manager| -> Result<(vec::Vec<PhysFrame>, usize), SyscallError> {
                        #[cfg(feature = "syscall_test")]
                        let hold_start = crate::time::read_tsc();
                        let result = (|| -> Result<(vec::Vec<PhysFrame>, usize), SyscallError> {
                            // ---- Step 1: install the relocated pages. ----
                            //
                            // Relocate: reuse each source frame verbatim, flags
                            // included, so protection and COW state travel with
                            // the PTE and NO refcount transition occurs.
                            let mut installed = 0usize;
                            if relocating {
                                // R192-RES-2a: every table comes from the stage;
                                // if it ever ran short, `map_page` fails and the
                                // rollback below prunes the partial chain.
                                let mut tables = StagedTables::new(
                                    &mut stage.tables,
                                    &mut frame_alloc.pt_frames,
                                );
                                let is_lazy_anon =
                                    (tx.committed_flags & MMAP_REGION_FLAG_LAZY_ANON) != 0;
                                for offset in (0..tx.old_len).step_by(0x1000) {
                                    let src_page =
                                    Page::<x86_64::structures::paging::Size4KiB>::containing_address(
                                        VirtAddr::new((tx.old_base + offset) as u64),
                                    );
                                    let dst_page = Page::containing_address(VirtAddr::new(
                                        (tx.new_base + offset) as u64,
                                    ));

                                    let Some((phys, leaf_flags)) =
                                        manager.translate_with_flags(src_page.start_address())
                                    else {
                                        if is_lazy_anon {
                                            // Unfaulted lazy page: remains unfaulted at dst_page.
                                            continue;
                                        }
                                        // The VMA and the page table disagree about a
                                        // page inside the mapping.
                                        mremap_rollback_install(
                                            manager,
                                            tx.new_base,
                                            offset / 0x1000,
                                            tx.old_len,
                                            carried,
                                        );
                                        return Err(SyscallError::EFAULT);
                                    };
                                    let frame = PhysFrame::containing_address(phys);

                                    if manager
                                        .map_page(dst_page, frame, leaf_flags, &mut tables)
                                        .is_err()
                                    {
                                        mremap_rollback_install(
                                            manager,
                                            tx.new_base,
                                            offset / 0x1000,
                                            tx.old_len,
                                            carried,
                                        );
                                        return Err(SyscallError::ENOMEM);
                                    }
                                    let _ = &mut installed;
                                    installed += 1;
                                }
                            }

                            // ---- Step 2: remove the source range. ----
                            //
                            // Runs only after every destination PTE is in place.
                            // Removal mirrors sys_munmap's sweep: a pending/unmapped
                            // leaf yields its frame, and the reference is released
                            // through the one ownership ledger. R192-RES-2a: its
                            // lists were reserved before the hold and never grow
                            // here.
                            let mut removed_leaf = false;
                            // Counts every leaf the sweep reclaimed, present or not,
                            // for both the PROT_NONE assertion and lazy-anon RSS debit.
                            let mut removed_frames: usize = 0;

                            if removed_len != 0 {
                                for offset in (0..removed_len).step_by(0x1000) {
                                    let page = Page::containing_address(VirtAddr::new(
                                        (removed_start + offset) as u64,
                                    ));
                                    // R141-9 shape: a PROT_NONE leaf keeps its frame in
                                    // a non-present entry, so fall back to the raw PTE.
                                    let frame_opt = match manager.unmap_page(page) {
                                        Ok(frame) => Some(frame),
                                        Err(mm::page_table::UnmapError::PageNotMapped) => {
                                            manager.take_nonpresent_leaf_frame(page)
                                        }
                                        Err(_) => None,
                                    };

                                    if let Some(frame) = frame_opt {
                                        removed_leaf = true;
                                        removed_frames += 1;
                                        // LEAD-MREMAP-RELOC-UAF-1 FIX: a RELOCATED
                                        // frame's reference moved to the destination
                                        // PTE in step 1; it is neither released nor
                                        // freed here (this test used to read
                                        // `relocated || release`, freeing every moved
                                        // frame while the destination still mapped
                                        // it).  A PROT_NONE reservation never
                                        // relocates (its range is rebuilt as a bare
                                        // reservation with no destination PTEs), so
                                        // any stray leaf it owns is released, keeping
                                        // the refcount ledger consistent with the
                                        // buddy even for the defensive non-present
                                        // case.
                                        let relocated = tx.moved && !prot_none;
                                        if !relocated {
                                            // Issue #109 rollup audit (ASTRA-1 / H1):
                                            // Always complete TLB shootdown BEFORE calling
                                            // `PAGE_REF_COUNT.release` so a fork peer on
                                            // another PT lock shard cannot observe refcount
                                            // 2->1 and perform an in-place writable CoW
                                            // upgrade (or frame reuse) while a sibling CPU
                                            // still caches the old translation.
                                            let batch = &mut stage.frames_to_free;
                                            if batch.capacity() == 0 {
                                                // Pre-hold reservation failed: flush this
                                                // page first, then release and free if last.
                                                mm::flush_current_as_page(page.start_address());
                                                if PAGE_REF_COUNT
                                                    .release(
                                                        frame.start_address().as_u64() as usize,
                                                    )
                                                    .should_free_unmapped()
                                                {
                                                    frame_alloc.deallocate_frame(frame);
                                                }
                                            } else {
                                                if batch.len() == batch.capacity() {
                                                    // R192-RES-2a + ASTRA-1: full batch:
                                                    // flush every page removed so far first,
                                                    // then release refs & free last-ref frames.
                                                    mm::flush_current_as_range(
                                                        VirtAddr::new(removed_start as u64),
                                                        offset,
                                                    );
                                                    for unmapped in batch.drain(..) {
                                                        if PAGE_REF_COUNT
                                                            .release(
                                                                unmapped.start_address().as_u64()
                                                                    as usize,
                                                            )
                                                            .should_free_unmapped()
                                                        {
                                                            frame_alloc.deallocate_frame(unmapped);
                                                        }
                                                    }
                                                }
                                                batch.push(frame);
                                            }
                                        }
                                    }
                                }

                                // A relocated leaf is not freed, but another CPU may
                                // still cache the source translation of a frame that
                                // now lives at the destination: flush whenever a leaf
                                // was removed, BEFORE releasing any refcount or freeing.
                                if removed_leaf {
                                    mm::flush_current_as_range(
                                        VirtAddr::new(removed_start as u64),
                                        removed_len,
                                    );
                                }
                                for frame in stage.frames_to_free.drain(..) {
                                    if PAGE_REF_COUNT
                                        .release(frame.start_address().as_u64() as usize)
                                        .should_free_unmapped()
                                    {
                                        frame_alloc.deallocate_frame(frame);
                                    }
                                }

                                manager.prune_empty_tables_in_range(
                                    VirtAddr::new(removed_start as u64),
                                    removed_len,
                                    &mut stage.reclaimed,
                                );
                            }

                            // Falsify the "a PROT_NONE reservation owns no frames"
                            // premise with the REAL sweep above — it sees present and
                            // non-present leaves alike, so a demoted region that ever
                            // left a frame behind makes this fire instead of leaking
                            // silently.
                            #[cfg(debug_assertions)]
                            debug_assert!(
                                !prot_none || removed_frames == 0,
                                "PROT_NONE reservation owned {removed_frames} leaf frame(s)"
                            );

                            let shrunk_leaf_count = if !tx.moved && tx.new_len < tx.old_len {
                                removed_frames
                            } else {
                                0
                            };
                            Ok((core::mem::take(&mut stage.reclaimed), shrunk_leaf_count))
                        })();
                        #[cfg(feature = "syscall_test")]
                        {
                            hold_tsc = crate::time::read_tsc().wrapping_sub(hold_start);
                        }
                        result
                    },
                )
            };
            // Unused staged tables go back now, outside the lock.
            let _returned = stage.return_unused();
            #[cfg(feature = "syscall_test")]
            if relocating && tx.old_len / 0x1000 >= POPULATE_REPORT_PAGES {
                let per_ms = crate::time::tsc_since_boot() / crate::time::get_ticks().max(1);
                klog_always!(
                    "R192-RES-2a mremap relocation pages={} staged={} used={} returned={} hold_tsc={} cycles_per_ms={} hold_us~={} result={}",
                    tx.old_len / 0x1000,
                    staged_tables,
                    frame_alloc.pt_frames.len() - recorded_before,
                    _returned,
                    hold_tsc,
                    per_ms,
                    hold_tsc.saturating_mul(1000) / per_ms.max(1),
                    match &hold {
                        Ok(_) => "ok",
                        Err(SyscallError::EFAULT) => "efault",
                        Err(_) => "enomem",
                    }
                );
            }
            match hold {
                Ok((reclaimed_tables, shrunk_leaf_count)) => Ok(MremapPhase2 {
                    new_pt_frames: populator.into_commit(),
                    reclaimed_tables,
                    shrunk_leaf_count,
                }),
                Err(error) => {
                    // The relocation failed after the tail was populated:
                    // unmap the tail again in bounded holds.
                    populator.rollback_all();
                    let failed = populator.into_failure(crate::populate::PopulateError::NoMemory(
                        crate::populate::PopulateStage::MapPage,
                    ));
                    Err((error, failed))
                }
            }
        }
    };

    let phase2 = match phase2 {
        Ok(outcome) => outcome,
        Err((error, failed)) => {
            // Roll back the whole transaction.  Phase 2 already undid any
            // partial destination install and the tail and left the source
            // untouched, so here we restore the VMA records and the cgroup
            // charge and settle the page tables.
            {
                let proc = process.lock();
                let mut mm = mm_arc.lock();

                if tx.reserved_base != 0 {
                    mm.mmap_regions.remove(&tx.reserved_base);
                }
                // Clear the source claim, restoring the pre-call entry verbatim.
                // `old_base` is still present, so this is an in-place replace.
                let _ = mm.mmap_regions.try_insert(
                    tx.old_base,
                    MmapEntry::from_len_flags(tx.old_len, tx.committed_flags),
                );
                if tx.next_advanced {
                    mm.next_mmap_addr = tx.old_next_mmap_addr;
                }
                // LEAD-MREMAP-MIGRATE-1: the reservation is gone with its lane.
                mm.mremap_uncharged_reserve_bytes = mm
                    .mremap_uncharged_reserve_bytes
                    .saturating_sub(tx.uncharged_reserve as u64);
                if is_lazy_anon {
                    mm.mremap_lazy_uncharged_reserve_bytes = mm
                        .mremap_lazy_uncharged_reserve_bytes
                        .saturating_sub(tx.uncharged_reserve as u64);
                }
                if !prot_none && tx.new_len > tx.old_len {
                    cgroup::uncharge_memory(proc.cgroup_id, (tx.new_len - tx.old_len) as u64);
                }
                // R192-RES-2: debit the ledgered tables the rollback pruned and
                // charge the ones it built and could not prune.
                failed.settle(&mut mm, proc.cgroup_id);
            }
            // Free-after-remove: the pruned tables reach the buddy only now.
            drop(failed);
            return Err(error);
        }
    };

    // Tables this call emptied (shrink tail / relocation source) are published
    // to the buddy only AFTER Phase 3 removes them from the per-AS ledger.
    // The guard frees them if any early return skips the explicit drain.
    struct TableFrameReclaim {
        frames: vec::Vec<PhysFrame>,
        drained: bool,
    }
    impl Drop for TableFrameReclaim {
        fn drop(&mut self) {
            if !self.drained && !self.frames.is_empty() {
                let mut allocator = mm::memory::FrameAllocator::new();
                for frame in self.frames.drain(..) {
                    allocator.deallocate_frame(frame);
                }
            }
        }
    }
    let mut reclaim = TableFrameReclaim {
        frames: phase2.reclaimed_tables,
        drained: false,
    };
    let pt_frames = phase2.new_pt_frames;
    let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

    // ---- Phase 3: commit the VMA record and the accounting in ONE
    // Process → MmState critical section, so it is atomic with respect to
    // cgroup migration (which snapshots compute_cgroup_charged_bytes under the
    // Process lock).  Every insert below targets a key that already exists, so
    // this section cannot allocate and cannot fail. ----
    {
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        let cgroup_id = proc.cgroup_id;

        // An eager grow populated its tail; a lazy grow keeps its tail lazy
        // (preserving UNFAULTED when the base mapping was untouched).
        let final_flags = if !is_lazy_anon && tx.new_len > tx.old_len && !prot_none {
            tx.committed_flags & !MMAP_REGION_FLAG_UNFAULTED
        } else {
            tx.committed_flags
        };
        let committed = MmapEntry::from_len_flags(tx.new_len, final_flags);
        debug_validate_mmap_entry(committed);
        // LEAD-MREMAP-MIGRATE-1: the committed entry counts exactly the charged
        // bytes again, so the lane goes in this section, before the inserts
        // below: if one ever failed, the stuck entries would over-count, never
        // under-count.
        mm.mremap_uncharged_reserve_bytes = mm
            .mremap_uncharged_reserve_bytes
            .saturating_sub(tx.uncharged_reserve as u64);
        if is_lazy_anon {
            mm.mremap_lazy_uncharged_reserve_bytes = mm
                .mremap_lazy_uncharged_reserve_bytes
                .saturating_sub(tx.uncharged_reserve as u64);
        }

        // Both arms below replace a key that Phase 1 already inserted, so they
        // cannot allocate and cannot fail.  ST-K3 Phase D style: the tag exists
        // to FALSIFY that annotation — if it ever fires, the VMA is left in its
        // transient state with no rollback, exactly like sys_mmap's E8 site.
        if tx.moved {
            // The destination key is already present (Phase-1 reservation).
            mm.mmap_regions
                .try_insert(tx.new_base, committed)
                .map_err(|_| {
                    #[cfg(debug_assertions)]
                    kprintln!("[ST-K2-MREMAP] ENOMEM site=M1 stage=commit_move dest");
                    SyscallError::ENOMEM
                })?;
            mm.mmap_regions.remove(&tx.old_base);
        } else {
            mm.mmap_regions
                .try_insert(tx.old_base, committed)
                .map_err(|_| {
                    #[cfg(debug_assertions)]
                    kprintln!("[ST-K2-MREMAP] ENOMEM site=M2 stage=commit_in_place base");
                    SyscallError::ENOMEM
                })?;
            if tx.reserved_base != 0 {
                mm.mmap_regions.remove(&tx.reserved_base);
            }
        }
        // DATA leg: move the delta between the two lengths.  A PROT_NONE
        // reservation carries no byte charge in either direction.
        if !prot_none {
            match mremap_byte_delta(tx.old_len, tx.new_len) {
                None => {}
                Some((true, bytes)) => {
                    mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(bytes as u64);
                }
                Some((false, bytes)) => {
                    mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(bytes as u64);
                    if is_lazy_anon && phase2.shrunk_leaf_count > 0 {
                        mm.lazy_anon_resident_bytes = mm.lazy_anon_resident_bytes.saturating_sub(
                            (phase2.shrunk_leaf_count as u64).saturating_mul(0x1000),
                        );
                    }
                    cgroup::uncharge_memory(cgroup_id, bytes as u64);
                }
            }
        }

        // PT leg (removal): uncharge a reclaimed intermediate table IFF this
        // address space charged it — frame-identity provenance, never a guessed
        // constant.  A forked child's inherited basis is not in the ledger, so
        // the scan is skipped while the AS is non-authoritative.
        if mm.pt_ledger_authoritative {
            let pt_freed =
                mm.reclaim_pt_charges(reclaim.frames.iter().map(|f| f.start_address().as_u64()));
            if pt_freed > 0 {
                mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(pt_freed);
                cgroup::uncharge_memory(cgroup_id, pt_freed);
            }
        }

        // PT leg (addition): the growth tail's page-table frames.  The count is
        // knowable only after `map_page` ran, so this is the same forced soft
        // charge sys_mmap uses (bounded overshoot, never an under-count).
        if pt_bytes > 0 {
            let ledgered = if mm.pt_charged_frames.try_reserve(pt_frames.len()).is_ok() {
                let mut all_fresh = true;
                for frame in &pt_frames {
                    match mm
                        .pt_charged_frames
                        .try_insert(frame.start_address().as_u64(), ())
                    {
                        Ok(None) => {}
                        Ok(Some(_)) => {
                            debug_assert!(
                                false,
                                "pt ledger frame aliased — free-after-remove invariant violated"
                            );
                            all_fresh = false;
                        }
                        Err(_) => {
                            all_fresh = false;
                            break;
                        }
                    }
                }
                all_fresh
            } else {
                false
            };
            cgroup::charge_memory_forced(cgroup_id, pt_bytes);
            mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_add(pt_bytes);
            if ledgered {
                mm.pt_ledger_authoritative = true;
            } else {
                for frame in &pt_frames {
                    mm.pt_charged_frames.remove(&frame.start_address().as_u64());
                }
                mm.pt_inherited_bytes = mm.pt_inherited_bytes.saturating_add(pt_bytes);
            }
        }
    }

    // Free-after-remove: the reclaimed tables enter the buddy only now, when
    // they are already gone from the ledger and from pt_charged_bytes.
    {
        let mut allocator = mm::memory::FrameAllocator::new();
        for frame in reclaim.frames.drain(..) {
            allocator.deallocate_frame(frame);
        }
        reclaim.drained = true;
    }

    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1133); // sys_mremap committed
    }

    // R159-17 style: keep address-revealing detail behind debug_assertions.
    #[cfg(debug_assertions)]
    kprintln!(
        "sys_mremap: pid={}, {} bytes at 0x{:x} -> {} bytes at 0x{:x}",
        pid,
        tx.old_len,
        tx.old_base,
        tx.new_len,
        tx.new_base
    );

    Ok(tx.new_base)
}

/// ST-K2-MREMAP: page-table outcome of a `mremap` Phase 2.
pub(super) struct MremapPhase2 {
    /// Page-table frames this call materialized for a grown tail (charged).
    pub(super) new_pt_frames: vec::Vec<x86_64::structures::paging::PhysFrame>,
    /// Intermediate tables this call emptied (freed after the ledger removal).
    pub(super) reclaimed_tables: vec::Vec<x86_64::structures::paging::PhysFrame>,
    /// Present leaf pages unmapped by an in-place shrink (for lazy-anon RSS).
    pub(super) shrunk_leaf_count: usize,
}
