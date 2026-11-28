//! ELF 装载器
//!
//! 负责解析并加载 ELF64 可执行文件到用户地址空间
//!
//! 功能：
//! - 验证 ELF64 格式（x86_64, Executable）
//! - 按 PT_LOAD 段映射用户地址空间
//! - 处理 BSS（memsz > filesz 部分清零）
//! - 返回入口点和用户栈顶

use alloc::vec::Vec;
use core::{cmp, ptr};
use mm::memory::FrameAllocator;
use mm::{page_table, phys_to_virt};
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

// R93-6 FIX: Import cgroup module for memory accounting
use crate::cgroup;
use crate::syscall::SyscallError;

/// 用户地址空间起始（4MB）
///
/// 用户程序加载在 4MB 处，这是经典的 Linux 用户空间起始地址。
/// 注意：bootloader 建立的恒等映射使用 2MB 大页，在映射用户空间前
/// 需要将冲突的大页拆分为 4KB 页（通过 ensure_pte_level）。
pub const USER_BASE: usize = 0x0040_0000;

/// 用户栈顶地址：用户栈区间的固定（非随机化）独占上界。M0 无栈 ASLR，该 VA 是
/// 确定的——正因可被预测，才需要低端守护页。真正的 4 KiB 守护页由
/// `allocate_user_stack_tracked` 在窗口低端 [stack_base, stack_base+USER_STACK_GUARD_SIZE)
/// 划出，永不映射。
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// 用户栈保留窗口大小（默认 2MB，含低端 1 页守护）
pub const USER_STACK_SIZE: usize = 0x20_0000;

/// M0-7 SLICE 5: Eager-mapped top region size (16 KB = 4 pages).
///
/// The top of the user stack is eagerly mapped to back initial stack usage
/// (argc/argv/envp/auxv in build_initial_user_stack, signal frames in
/// maybe_deliver_signal, IRQ signal delivery). The rest of the stack window
/// grows on-demand via #PF.
///
/// Rationale for 16KB:
/// - Enough for typical initial stack usage (few KB)
/// - Small enough to make lazy region useful
/// - Page-aligned for clean geometry
pub const USER_STACK_EAGER_SIZE: usize = 16 * 1024; // 16 KB = 4 pages

/// M0-7: 用户栈低端永久未映射的守护页大小（1×4 KiB）。
///
/// 栈向下溢出落入该页 → not-present 的用户态写缺页 → 经 `interrupts.rs` 既有的
/// 用户 SIGSEGV 路径终止进程，而非静默破坏其下的 brk/堆。守护页必须是「完全
/// 未使用」的 PTE（加载循环从不访问它，addr=0），绝不能是显式的 non-present
/// PTE——否则 `free_address_space` 的 R123-1 叶子回收会对幻象帧二次释放。
pub const USER_STACK_GUARD_SIZE: usize = 0x1000;

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// N2.1: Maximum executable image size accepted by `execve(59)` and `spawn_image(517)`.
///
/// Raised from 256 KiB to 16 MiB by backing images larger than
/// `EXEC_IMAGE_HEAP_FAST_BYTES` with physical 4 KiB frames (`ExecImage::Paged`),
/// keeping kernel heap usage bounded to ~32 KiB of frame descriptors for a full
/// 16 MiB static binary (such as unmodified static BusyBox).
pub const MAX_EXEC_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// Small-image threshold that stays on the kernel heap before spilling to
/// physical 4 KiB frames (`ExecImage::Paged`). Fits easily inside the 2 MiB
/// kernel heap alongside argv/envp/stack staging.
pub const EXEC_IMAGE_HEAP_FAST_BYTES: usize = 64 * 1024;

/// N2.1: Maximum pages per single ELF `PT_LOAD` segment.
///
/// Raised from 256 pages (1 MiB) to 4096 pages (16 MiB). Rollback tracking now
/// records one `MappedRange` per segment (O(segments), <= 528 bytes total)
/// instead of a per-page `Vec<(Page, PhysFrame)>`, eliminating the heap pressure
/// that originally forced the 1 MiB cap.
pub const MAX_ELF_SEGMENT_PAGES: usize = 4096;

/// N2.1: Aggregate ceiling on mapped `PT_LOAD` pages across all segments in one
/// ELF binary (8192 pages = 32 MiB) so a crafted binary with `MAX_ELF_LOAD_SEGMENTS`
/// max-sized segments cannot exhaust physical memory in a single exec.
pub const MAX_ELF_TOTAL_PAGES: usize = 8192;

/// Maximum `PT_LOAD` segments permitted in one ELF binary.
pub const MAX_ELF_LOAD_SEGMENTS: usize = 32;

/// ELF64 ABI constants used by the panic-free direct header/phdr parser.
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const ELF64_CLASS_64: u8 = 2;
const ELF64_DATA_LSB: u8 = 1;
const ELF64_ET_EXEC: u16 = 2;
const ELF64_EM_X86_64: u16 = 62;
const ELF64_PT_LOAD: u32 = 1;
const ELF64_PT_PHDR: u32 = 6;
const ELF64_PF_X: u32 = 1;
const ELF64_PF_W: u32 = 2;

/// Z-10 / N2.1: O(segments) mapped-range record used for rollback on ELF load
/// failure. Each entry covers `[page_base, page_base + page_count * PAGE_SIZE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappedRange {
    page_base: usize,
    page_count: usize,
}

/// N2.1: Executable image buffer backing `execve(59)` and `spawn_image(517)`.
///
/// Images up to `EXEC_IMAGE_HEAP_FAST_BYTES` (64 KiB) use a regular heap `Vec<u8>`.
/// Larger images up to `MAX_EXEC_IMAGE_BYTES` (16 MiB) are backed by individual
/// 4 KiB physical frames (`Paged`), consuming only 8 bytes of kernel heap per
/// 4 KiB page and requiring zero contiguous physical memory.
pub enum ExecImage {
    Heap(Vec<u8>),
    Paged {
        frames: Vec<PhysFrame<Size4KiB>>,
        len: usize,
    },
}

impl core::fmt::Debug for ExecImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Heap(v) => f
                .debug_struct("ExecImage::Heap")
                .field("len", &v.len())
                .finish(),
            Self::Paged { frames, len } => f
                .debug_struct("ExecImage::Paged")
                .field("len", len)
                .field("frames", &frames.len())
                .finish(),
        }
    }
}

impl Default for ExecImage {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecImage {
    /// Create an empty executable image buffer.
    #[inline]
    pub const fn new() -> Self {
        Self::Heap(Vec::new())
    }

    /// Wrap an existing heap byte vector as an `ExecImage`.
    #[inline]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self::Heap(bytes)
    }

    /// Total byte length of the image.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Heap(v) => v.len(),
            Self::Paged { len, .. } => *len,
        }
    }

    /// True if the image contains zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True if backed by physical 4 KiB frames instead of the kernel heap.
    #[inline]
    pub fn is_paged(&self) -> bool {
        matches!(self, Self::Paged { .. })
    }

    /// Zero-copy slice of up to `min(max_len, PAGE_SIZE, self.len())` leading bytes.
    ///
    /// Covers ELF magic (`\x7FELF`), shebang (`#!` up to 256 B), and the LSM
    /// `EXEC_HASH_WINDOW` (4096 B) without allocating or copying.
    pub fn prefix_slice(&self, max_len: usize) -> &[u8] {
        let want = cmp::min(self.len(), cmp::min(max_len, PAGE_SIZE));
        if want == 0 {
            return &[];
        }
        match self {
            Self::Heap(v) => &v[..want],
            Self::Paged { frames, .. } => {
                let first = frames[0];
                // SAFETY: frame 0 is owned by `self` for the lifetime of `&self`
                // and mapped through the direct physical map.
                unsafe {
                    core::slice::from_raw_parts(
                        phys_to_virt(first.start_address()).as_ptr::<u8>(),
                        want,
                    )
                }
            }
        }
    }

    /// Bounds-checked read of `dst.len()` bytes starting at `offset`.
    pub fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), ElfLoadError> {
        let end = offset
            .checked_add(dst.len())
            .ok_or(ElfLoadError::OutOfBounds)?;
        if end > self.len() {
            return Err(ElfLoadError::OutOfBounds);
        }
        if dst.is_empty() {
            return Ok(());
        }
        match self {
            Self::Heap(v) => {
                dst.copy_from_slice(&v[offset..end]);
                Ok(())
            }
            Self::Paged { frames, .. } => {
                let mut pos = offset;
                let mut written = 0usize;
                while written < dst.len() {
                    let page_idx = pos / PAGE_SIZE;
                    let page_off = pos % PAGE_SIZE;
                    let copy_len = cmp::min(PAGE_SIZE - page_off, dst.len() - written);
                    let frame = *frames.get(page_idx).ok_or(ElfLoadError::OutOfBounds)?;
                    // SAFETY: `frame` is owned by `self` and `page_off + copy_len <= PAGE_SIZE`.
                    unsafe {
                        let src = phys_to_virt(frame.start_address())
                            .as_ptr::<u8>()
                            .add(page_off);
                        ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(written), copy_len);
                    }
                    pos += copy_len;
                    written += copy_len;
                }
                Ok(())
            }
        }
    }

    /// Append `chunk` to this image, enforcing `max_len` (`E2BIG`) and spilling
    /// transparently to physical 4 KiB frames above `EXEC_IMAGE_HEAP_FAST_BYTES`.
    pub fn try_append(&mut self, chunk: &[u8], max_len: usize) -> Result<(), SyscallError> {
        let cur_len = self.len();
        let new_len = cur_len
            .checked_add(chunk.len())
            .ok_or(SyscallError::E2BIG)?;
        if new_len > max_len {
            return Err(SyscallError::E2BIG);
        }
        if chunk.is_empty() {
            return Ok(());
        }

        #[cfg(any(test, feature = "host_harness"))]
        {
            match self {
                Self::Heap(v) => {
                    v.try_reserve(chunk.len())
                        .map_err(|_| SyscallError::ENOMEM)?;
                    v.extend_from_slice(chunk);
                    Ok(())
                }
                Self::Paged { .. } => Err(SyscallError::ENOMEM),
            }
        }

        #[cfg(not(any(test, feature = "host_harness")))]
        {
            if matches!(self, Self::Heap(_)) && new_len <= EXEC_IMAGE_HEAP_FAST_BYTES {
                if let Self::Heap(v) = self {
                    v.try_reserve(chunk.len())
                        .map_err(|_| SyscallError::ENOMEM)?;
                    v.extend_from_slice(chunk);
                    return Ok(());
                }
            }

            if let Self::Heap(v) = self {
                let mut paged = Self::Paged {
                    frames: Vec::new(),
                    len: 0,
                };
                if !v.is_empty() {
                    paged.append_to_paged(v)?;
                }
                *self = paged;
            }
            self.append_to_paged(chunk)
        }
    }

    /// Construct an `ExecImage` of exact size `len` by pulling chunks from
    /// `fill_chunk(offset, dst)`. Spills directly to physical frames above
    /// `EXEC_IMAGE_HEAP_FAST_BYTES` so large `spawn_image` calls never touch the
    /// 2 MiB kernel heap for payload bytes.
    pub fn try_from_reader<F>(
        len: usize,
        max_len: usize,
        mut fill_chunk: F,
    ) -> Result<Self, SyscallError>
    where
        F: FnMut(usize, &mut [u8]) -> Result<(), SyscallError>,
    {
        if len > max_len {
            return Err(SyscallError::E2BIG);
        }
        if len == 0 {
            return Ok(Self::new());
        }

        #[cfg(not(any(test, feature = "host_harness")))]
        if len > EXEC_IMAGE_HEAP_FAST_BYTES {
            let needed_frames = (len + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut img = Self::Paged {
                frames: Vec::new(),
                len: 0,
            };
            img.reserve_paged_frames(needed_frames)?;
            if let Self::Paged {
                ref frames,
                len: ref mut img_len,
            } = img
            {
                for (page_idx, frame) in frames.iter().enumerate() {
                    let off = page_idx * PAGE_SIZE;
                    let chunk_len = cmp::min(PAGE_SIZE, len - off);
                    // SAFETY: frame is freshly allocated and exclusively owned by `img`.
                    let dst = unsafe {
                        core::slice::from_raw_parts_mut(
                            phys_to_virt(frame.start_address()).as_mut_ptr::<u8>(),
                            chunk_len,
                        )
                    };
                    fill_chunk(off, dst)?;
                    *img_len = off + chunk_len;
                }
            }
            return Ok(img);
        }

        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| SyscallError::ENOMEM)?;
        buf.resize(len, 0);
        fill_chunk(0, &mut buf)?;
        Ok(Self::Heap(buf))
    }

    #[cfg(not(any(test, feature = "host_harness")))]
    fn reserve_paged_frames(&mut self, needed_frames: usize) -> Result<(), SyscallError> {
        let Self::Paged { frames, .. } = self else {
            return Err(SyscallError::EINVAL);
        };
        if frames.len() >= needed_frames {
            return Ok(());
        }
        frames
            .try_reserve(needed_frames - frames.len())
            .map_err(|_| SyscallError::ENOMEM)?;
        let mut batch = [PhysFrame::containing_address(x86_64::PhysAddr::new(0)); 32];
        while frames.len() < needed_frames {
            let want = cmp::min(batch.len(), needed_frames - frames.len());
            let got = mm::buddy_allocator::alloc_physical_pages_batch(&mut batch[..want]);
            if got == 0 {
                return Err(SyscallError::ENOMEM);
            }
            frames.extend_from_slice(&batch[..got]);
        }
        Ok(())
    }

    #[cfg(not(any(test, feature = "host_harness")))]
    fn append_to_paged(&mut self, chunk: &[u8]) -> Result<(), SyscallError> {
        let cur_len = self.len();
        let new_len = cur_len
            .checked_add(chunk.len())
            .ok_or(SyscallError::E2BIG)?;
        let needed_frames = (new_len + PAGE_SIZE - 1) / PAGE_SIZE;
        self.reserve_paged_frames(needed_frames)?;
        if let Self::Paged { frames, len } = self {
            let mut pos = *len;
            let mut written = 0usize;
            while written < chunk.len() {
                let page_idx = pos / PAGE_SIZE;
                let page_off = pos % PAGE_SIZE;
                let copy_len = cmp::min(PAGE_SIZE - page_off, chunk.len() - written);
                let frame = frames[page_idx];
                // SAFETY: `frame` is owned by `self` and `page_off + copy_len <= PAGE_SIZE`.
                unsafe {
                    let dst = phys_to_virt(frame.start_address())
                        .as_mut_ptr::<u8>()
                        .add(page_off);
                    ptr::copy_nonoverlapping(chunk.as_ptr().add(written), dst, copy_len);
                }
                pos += copy_len;
                written += copy_len;
            }
            *len = new_len;
        }
        Ok(())
    }
}

impl Drop for ExecImage {
    fn drop(&mut self) {
        if let Self::Paged { frames, .. } = self {
            #[cfg(not(any(test, feature = "host_harness")))]
            if !frames.is_empty() {
                mm::buddy_allocator::free_physical_pages_batch(frames);
            }
            frames.clear();
        }
    }
}

/// Abstract read-only view over an ELF image (contiguous slice or frame-backed `ExecImage`).
trait ElfImageSource {
    fn len(&self) -> usize;
    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), ElfLoadError>;
    /// Optional raw base address alignment check for contiguous byte slices (R172-02 parity).
    fn base_align_mod8(&self) -> usize {
        0
    }
}

impl ElfImageSource for [u8] {
    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), ElfLoadError> {
        let end = offset
            .checked_add(dst.len())
            .ok_or(ElfLoadError::OutOfBounds)?;
        let src = self.get(offset..end).ok_or(ElfLoadError::OutOfBounds)?;
        dst.copy_from_slice(src);
        Ok(())
    }

    #[inline]
    fn base_align_mod8(&self) -> usize {
        (self.as_ptr() as usize) & 7
    }
}

impl ElfImageSource for ExecImage {
    #[inline]
    fn len(&self) -> usize {
        ExecImage::len(self)
    }

    #[inline]
    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), ElfLoadError> {
        ExecImage::read_at(self, offset, dst)
    }
}

/// Parsed fields of an ELF64 executable header.
#[derive(Debug, Clone, Copy)]
struct Elf64Header {
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

/// Parsed fields of an ELF64 program header entry.
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

impl Elf64Phdr {
    #[inline]
    const fn is_write(self) -> bool {
        (self.p_flags & ELF64_PF_W) != 0
    }

    #[inline]
    const fn is_execute(self) -> bool {
        (self.p_flags & ELF64_PF_X) != 0
    }
}

fn parse_and_validate_elf64_header<S: ElfImageSource + ?Sized>(
    source: &S,
) -> Result<Elf64Header, ElfLoadError> {
    let mut hdr = [0u8; ELF64_EHDR_SIZE];
    source
        .read_at(0, &mut hdr)
        .map_err(|_| ElfLoadError::InvalidMagic)?;

    if hdr[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfLoadError::InvalidMagic);
    }
    if hdr[4] != ELF64_CLASS_64 {
        return Err(ElfLoadError::UnsupportedClass);
    }
    if hdr[5] != ELF64_DATA_LSB {
        return Err(ElfLoadError::NotLittleEndian);
    }

    let e_type = u16::from_le_bytes([hdr[16], hdr[17]]);
    let e_machine = u16::from_le_bytes([hdr[18], hdr[19]]);
    if e_machine != ELF64_EM_X86_64 {
        return Err(ElfLoadError::UnsupportedMachine);
    }
    if e_type != ELF64_ET_EXEC {
        return Err(ElfLoadError::UnsupportedType);
    }

    let entry = u64::from_le_bytes([
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
    ]);
    let phoff = u64::from_le_bytes([
        hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ]);
    let phentsize = u16::from_le_bytes([hdr[54], hdr[55]]);
    let phnum = u16::from_le_bytes([hdr[56], hdr[57]]);

    // R172-02 FIX: bound and 8-byte align the program-header table before
    // iterating program headers.
    if phnum != 0 {
        if phentsize as usize != ELF64_PHDR_SIZE {
            return Err(ElfLoadError::OutOfBounds);
        }
        let table_bytes = (phnum as u64)
            .checked_mul(ELF64_PHDR_SIZE as u64)
            .ok_or(ElfLoadError::OutOfBounds)?;
        let table_end = phoff
            .checked_add(table_bytes)
            .ok_or(ElfLoadError::OutOfBounds)?;
        if table_end > source.len() as u64 {
            return Err(ElfLoadError::OutOfBounds);
        }
        if ((source.base_align_mod8()).wrapping_add(phoff as usize)) & 7 != 0 {
            return Err(ElfLoadError::OutOfBounds);
        }
    }

    Ok(Elf64Header {
        entry,
        phoff,
        phentsize,
        phnum,
    })
}

fn read_elf64_phdr<S: ElfImageSource + ?Sized>(
    source: &S,
    hdr: &Elf64Header,
    index: u16,
) -> Result<Elf64Phdr, ElfLoadError> {
    let off = hdr
        .phoff
        .checked_add((index as u64) * (ELF64_PHDR_SIZE as u64))
        .ok_or(ElfLoadError::OutOfBounds)? as usize;
    let mut raw = [0u8; ELF64_PHDR_SIZE];
    source.read_at(off, &mut raw)?;
    Ok(Elf64Phdr {
        p_type: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        p_flags: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        p_offset: u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]),
        p_vaddr: u64::from_le_bytes([
            raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
        ]),
        p_filesz: u64::from_le_bytes([
            raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39],
        ]),
        p_memsz: u64::from_le_bytes([
            raw[40], raw[41], raw[42], raw[43], raw[44], raw[45], raw[46], raw[47],
        ]),
    })
}

/// Pure segment-budget policy helper (unit-testable on host without page tables).
#[inline]
pub(crate) fn check_segment_page_budget(
    segment_pages: usize,
    accumulated_pages: usize,
) -> Result<usize, ElfLoadError> {
    if segment_pages > MAX_ELF_SEGMENT_PAGES {
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    let next_total = accumulated_pages
        .checked_add(segment_pages)
        .ok_or(ElfLoadError::SegmentOutOfRange)?;
    if next_total > MAX_ELF_TOTAL_PAGES {
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    Ok(next_total)
}

/// ELF 加载错误
#[derive(Debug, Clone, Copy)]
pub enum ElfLoadError {
    /// ELF 魔数无效
    InvalidMagic,
    /// 不支持的 ELF 类型（非 64 位）
    UnsupportedClass,
    /// 不支持的机器架构（非 x86_64）
    UnsupportedMachine,
    /// 不支持的文件类型（非可执行文件）
    UnsupportedType,
    /// 非小端格式
    NotLittleEndian,
    /// 段地址超出允许范围
    SegmentOutOfRange,
    /// 同时可写可执行的段被拒绝（W^X 安全策略）
    WritableExecutableSegment,
    /// 段与栈区域重叠
    OverlapWithStack,
    /// 页映射失败
    MapFailed,
    /// 段数据越界
    OutOfBounds,
    /// 物理内存不足
    OutOfMemory,
    /// R93-6 FIX: Cgroup memory limit exceeded
    CgroupLimitExceeded,
    /// R154-5 FIX: Too many PT_LOAD segments (DoS prevention)
    TooManySegments,
    /// R154-12 FIX: PT_LOAD segments have overlapping virtual address ranges
    OverlappingSegments,
    /// R155-16 FIX: Segment vaddr+memsz arithmetic overflow
    InvalidSegment,
}

/// ELF 加载结果
pub struct ElfLoadResult {
    /// 程序入口点地址
    pub entry: u64,
    /// 用户栈顶地址
    pub user_stack_top: u64,
    /// 堆起始地址（BSS 末尾，页对齐）
    ///
    /// 这是 brk(0) 的初始返回值，也是 brk_start 的初始值。
    /// 计算为所有 PT_LOAD 段中 (vaddr + memsz) 的最大值，向上对齐到页边界。
    pub brk_start: usize,
    /// R125-1 FIX: Total bytes charged to the process's cgroup during ELF
    /// loading (segments + stack, page-aligned).  The caller uses this to
    /// roll back cgroup accounting if exec fails after load_elf() succeeds.
    pub charged_bytes: u64,
    /// M2-1 SLICE-4d: the intermediate PT/PD/PDPT frame identities the ELF loader built
    /// for this fresh address space (segments + stack), recorded by
    /// `RecordingFrameAllocator`. sys_exec folds these into the new AS's
    /// `pt_charged_frames` ledger + a forced cgroup PT-kmem charge AT THE SUCCESS COMMIT
    /// (after the old image's ledger is cleared). On any pre-commit failure the whole new
    /// AS is torn down by free_address_space and this Vec is simply dropped (the frames
    /// were never charged). The OTHER load_elf consumer (kernel/src/usermode_test.rs, a
    /// root-cgroup boot diagnostic) ignores this field — it field-accesses entry/stack.
    pub pt_frames: Vec<PhysFrame<Size4KiB>>,
    /// M0 #1 (auxv): user-space virtual address of the `Elf64_Phdr` array (AT_PHDR).
    ///
    /// `0` is a sentinel meaning "no usable program-header table" — the auxv builder
    /// then OMITS the entire AT_PHDR/AT_PHENT/AT_PHNUM triple (musl static tolerates
    /// its absence; only TLS-via-phdr is skipped). Computed by [`compute_phdr_va`].
    pub phdr: u64,
    /// M0 #1 (auxv): `e_phentsize` (AT_PHENT) — size of one program-header entry
    /// (56 for ELF64). Read directly from the ELF header.
    pub phent: u16,
    /// M0 #1 (auxv): `e_phnum` (AT_PHNUM) — number of program-header entries.
    pub phnum: u16,
}

/// 为当前进程地址空间加载 ELF 映像
///
/// # 前置条件
///
/// - 调用方已切换到目标进程的地址空间（当前 CR3 是目标进程的页表）
/// - 用户空间未被映射（除内核高半区外）
///
/// # Arguments
///
/// * `image` - ELF 文件的原始字节
/// * `cgroup_id` - R149-3 FIX: Cgroup ID for memory accounting, captured by
///   the caller under process lock to avoid TOCTOU with concurrent migration.
///
/// # Returns
///
/// 成功返回入口点和用户栈顶，失败返回错误码
pub fn load_elf(image: &[u8], cgroup_id: cgroup::CgroupId) -> Result<ElfLoadResult, ElfLoadError> {
    load_elf_source(image, cgroup_id)
}

/// N2.1: Load an ELF64 executable from an [`ExecImage`] (either heap-backed or
/// physical-frame-backed up to `MAX_EXEC_IMAGE_BYTES` = 16 MiB).
pub fn load_elf_image(
    image: &ExecImage,
    cgroup_id: cgroup::CgroupId,
) -> Result<ElfLoadResult, ElfLoadError> {
    load_elf_source(image, cgroup_id)
}

fn load_elf_source<S: ElfImageSource + ?Sized>(
    source: &S,
    cgroup_id: cgroup::CgroupId,
) -> Result<ElfLoadResult, ElfLoadError> {
    let hdr = parse_and_validate_elf64_header(source)?;

    // Z-10 / N2.1: Track mapped page ranges (O(segments), <= 33 entries = 528 B)
    // for rollback on any error, eliminating per-page heap tracking vectors.
    let mut all_mappings: Vec<MappedRange> = Vec::new();
    let mut highest_segment_end: usize = 0;
    let mut charged_bytes: u64 = 0;
    let mut pt_frames_acc: Vec<PhysFrame<Size4KiB>> = Vec::new();
    let mut load_segment_count: usize = 0;
    let mut total_segment_pages: usize = 0;
    let mut loaded_ranges: Vec<(usize, usize)> = Vec::new();

    for idx in 0..hdr.phnum {
        let ph = match read_elf64_phdr(source, &hdr, idx) {
            Ok(p) => p,
            Err(e) => {
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(e);
            }
        };
        if ph.p_type == ELF64_PT_LOAD {
            load_segment_count += 1;
            if load_segment_count > MAX_ELF_LOAD_SEGMENTS {
                klog!(
                    Error,
                    "ELF loader: too many PT_LOAD segments ({} > {})",
                    load_segment_count,
                    MAX_ELF_LOAD_SEGMENTS
                );
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(ElfLoadError::TooManySegments);
            }

            let vaddr = ph.p_vaddr as usize;
            let memsz = ph.p_memsz as usize;
            if memsz > 0 {
                let segment_end = match vaddr.checked_add(memsz) {
                    Some(end) => end,
                    None => {
                        klog!(
                            Debug,
                            "ELF loader: PT_LOAD segment vaddr {:#x} + memsz {:#x} overflows",
                            vaddr,
                            memsz
                        );
                        rollback_all_mappings(&mut all_mappings, cgroup_id);
                        return Err(ElfLoadError::InvalidSegment);
                    }
                };

                let page_mask: usize = 0xFFF;
                let page_start = vaddr & !page_mask;
                let page_end = segment_end.saturating_add(page_mask) & !page_mask;
                for &(prev_start, prev_end) in loaded_ranges.iter() {
                    let prev_page_start = prev_start & !page_mask;
                    let prev_page_end = prev_end.saturating_add(page_mask) & !page_mask;
                    if page_start < prev_page_end && prev_page_start < page_end {
                        klog!(Debug,
                            "ELF loader: PT_LOAD segment [{:#x}, {:#x}) overlaps with [{:#x}, {:#x}) at page level",
                            vaddr, segment_end, prev_start, prev_end
                        );
                        rollback_all_mappings(&mut all_mappings, cgroup_id);
                        return Err(ElfLoadError::OverlappingSegments);
                    }
                }
                if loaded_ranges.try_reserve(1).is_err() {
                    rollback_all_mappings(&mut all_mappings, cgroup_id);
                    return Err(ElfLoadError::OutOfMemory);
                }
                loaded_ranges.push((vaddr, segment_end));

                if segment_end > highest_segment_end {
                    highest_segment_end = segment_end;
                }
            }

            let (seg_charged, seg_pages, seg_pt) = match load_segment_tracked(
                source,
                &ph,
                total_segment_pages,
                &mut all_mappings,
                cgroup_id,
            ) {
                Ok(v) => v,
                Err(e) => {
                    rollback_all_mappings(&mut all_mappings, cgroup_id);
                    return Err(e);
                }
            };
            total_segment_pages = total_segment_pages.saturating_add(seg_pages);
            charged_bytes = charged_bytes.saturating_add(seg_charged);
            if pt_frames_acc.try_reserve(seg_pt.len()).is_err() {
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(ElfLoadError::OutOfMemory);
            }
            pt_frames_acc.extend(seg_pt);
        }
    }

    let (stack_charged, stack_pt) = match allocate_user_stack_tracked(&mut all_mappings, cgroup_id)
    {
        Ok(v) => v,
        Err(e) => {
            rollback_all_mappings(&mut all_mappings, cgroup_id);
            return Err(e);
        }
    };
    charged_bytes = charged_bytes.saturating_add(stack_charged);
    if pt_frames_acc.try_reserve(stack_pt.len()).is_err() {
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::OutOfMemory);
    }
    pt_frames_acc.extend(stack_pt);

    let brk_start = (highest_segment_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    if brk_start > user_stack_window().0 {
        klog!(
            Debug,
            "ELF loader: brk_start 0x{:x} overlaps with stack at 0x{:x}",
            brk_start,
            stack_base
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::OverlapWithStack);
    }

    kprintln!(
        "ELF loaded: entry=0x{:x}, brk_start=0x{:x}",
        hdr.entry,
        brk_start
    );

    let entry = hdr.entry;
    if entry < USER_BASE as u64 || entry >= USER_STACK_TOP {
        klog!(
            Debug,
            "ELF loader: invalid entry point 0x{:x} (valid range: 0x{:x}-0x{:x})",
            entry,
            USER_BASE,
            USER_STACK_TOP
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    let sign_extended = ((entry as i64) >> 47) as u64;
    if sign_extended != 0 && sign_extended != 0x1FFFF {
        klog!(Debug, "ELF loader: non-canonical entry point");
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    let entry_in_segment = loaded_ranges
        .iter()
        .any(|&(start, end)| (entry as usize) >= start && (entry as usize) < end);
    if !entry_in_segment {
        klog!(
            Debug,
            "ELF loader: entry point 0x{:x} not within any loaded segment",
            entry
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    let initial_rsp = USER_STACK_TOP - 16;
    let phdr = compute_phdr_va_from_source(source, &hdr);
    let phent = hdr.phentsize;
    let phnum = hdr.phnum;

    Ok(ElfLoadResult {
        entry,
        user_stack_top: initial_rsp,
        brk_start,
        charged_bytes,
        pt_frames: pt_frames_acc,
        phdr,
        phent,
        phnum,
    })
}

/// M0 #1 (auxv): compute the user-space VA of the program-header table (AT_PHDR).
///
/// Returns `0` (the "omit AT_PHDR/AT_PHENT/AT_PHNUM" sentinel) whenever no *validated*
/// user-space mapping exists. The returned VA is ALWAYS a canonical user address whose
/// whole `[va, va + e_phentsize*e_phnum)` range is file-backed by a mapped `PT_LOAD`.
///
/// Step 1 — derive a candidate VA:
/// - **Tier 1** — an explicit `PT_PHDR` program header (its `p_vaddr`). `musl-gcc
///   -static` always emits `PT_PHDR`, so the M0 gate takes this path.
/// - **Tier 2** — the `PT_LOAD` whose FILE range *fully* contains the table
///   `[e_phoff, e_phoff + e_phnum*e_phentsize)`; then `va = p_vaddr + (e_phoff -
///   p_offset)`. The full-table coverage check (not just the start) avoids pointing at
///   unmapped/zero-filled bytes.
///
/// Step 2 — VALIDATE (Codex `019ee8d1` finding 2): a `PT_PHDR` `p_vaddr` is
/// attacker-controlled, so the candidate is accepted ONLY if its whole VA range lies
/// inside the file-backed VA range of some mapped `PT_LOAD` AND inside the user image
/// window `[USER_BASE, USER_STACK_TOP - USER_STACK_SIZE)`. Otherwise the triple is
/// omitted (return `0`) — a crafted ELF can never push a non-user/unmapped VA into
/// AT_PHDR. A well-formed static binary keeps its phdrs in the first `PT_LOAD`, so this
/// rejects only malformed images (musl then merely skips TLS-via-phdr).
///
/// `ET_DYN` is rejected by [`validate_elf_header`], so the load bias is always `0` for
/// accepted images; if PIE support is added, this is the single site that needs
/// `+ load_bias`.
fn compute_phdr_va_from_source<S: ElfImageSource + ?Sized>(source: &S, hdr: &Elf64Header) -> u64 {
    let e_phoff = hdr.phoff;
    let table_bytes = match (hdr.phentsize as u64).checked_mul(hdr.phnum as u64) {
        Some(b) if b != 0 => b,
        _ => return 0,
    };

    let mut candidate: u64 = 0;
    for idx in 0..hdr.phnum {
        let Ok(ph) = read_elf64_phdr(source, hdr, idx) else {
            return 0;
        };
        if ph.p_type == ELF64_PT_PHDR {
            candidate = ph.p_vaddr;
            break;
        }
    }
    if candidate == 0 {
        if let Some(table_end) = e_phoff.checked_add(table_bytes) {
            for idx in 0..hdr.phnum {
                let Ok(ph) = read_elf64_phdr(source, hdr, idx) else {
                    return 0;
                };
                if ph.p_type != ELF64_PT_LOAD {
                    continue;
                }
                let seg_off = ph.p_offset;
                let seg_file_end = match seg_off.checked_add(ph.p_filesz) {
                    Some(e) => e,
                    None => continue,
                };
                if seg_off <= e_phoff && table_end <= seg_file_end {
                    candidate = ph.p_vaddr.checked_add(e_phoff - seg_off).unwrap_or(0);
                    break;
                }
            }
        }
    }
    if candidate == 0 {
        return 0;
    }

    let cand_end = match candidate.checked_add(table_bytes) {
        Some(e) => e,
        None => return 0,
    };
    let user_floor = USER_BASE as u64;
    let user_ceiling = user_stack_window().0 as u64;
    if candidate < user_floor || cand_end > user_ceiling {
        return 0;
    }
    for idx in 0..hdr.phnum {
        let Ok(ph) = read_elf64_phdr(source, hdr, idx) else {
            return 0;
        };
        if ph.p_type != ELF64_PT_LOAD {
            continue;
        }
        let seg_va = ph.p_vaddr;
        let seg_va_file_end = match seg_va.checked_add(ph.p_filesz) {
            Some(e) => e,
            None => continue,
        };
        if seg_va <= candidate && cand_end <= seg_va_file_end {
            return candidate;
        }
    }

    0
}

fn validate_elf_source<S: ElfImageSource + ?Sized>(source: &S) -> Result<(), ElfLoadError> {
    let hdr = parse_and_validate_elf64_header(source)?;
    for idx in 0..hdr.phnum {
        let _ = read_elf64_phdr(source, &hdr, idx)?;
    }
    let _ = compute_phdr_va_from_source(source, &hdr);
    Ok(())
}

/// Pure, host-safe ELF pre-flight validation — the exact parse [`load_elf`] runs
/// on untrusted bytes BEFORE it maps anything, with NO page-table, frame-allocator,
/// or cgroup work.
pub fn validate_elf_image(image: &[u8]) -> Result<(), ElfLoadError> {
    validate_elf_source(image)
}

/// N2.1: Pure pre-flight validation for an [`ExecImage`] (heap or frame-backed).
pub fn validate_exec_image(image: &ExecImage) -> Result<(), ElfLoadError> {
    validate_elf_source(image)
}

/// Z-10 / N2.1: Load a single `PT_LOAD` segment, zeroing and populating each
/// allocated frame directly before mapping so no per-page tracking vector is
/// allocated on the kernel heap.
fn load_segment_tracked<S: ElfImageSource + ?Sized>(
    source: &S,
    ph: &Elf64Phdr,
    accumulated_pages: usize,
    tracked: &mut Vec<MappedRange>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(u64, usize, Vec<PhysFrame<Size4KiB>>), ElfLoadError> {
    let vaddr = ph.p_vaddr as usize;
    let memsz = ph.p_memsz as usize;
    let filesz = ph.p_filesz as usize;
    let offset = ph.p_offset as usize;

    if memsz == 0 {
        return Ok((0, 0, Vec::new()));
    }
    if filesz > memsz {
        return Err(ElfLoadError::OutOfBounds);
    }

    let end = vaddr.checked_add(memsz).ok_or(ElfLoadError::OutOfBounds)?;
    if vaddr < USER_BASE {
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    if end > user_stack_window().0 {
        return Err(ElfLoadError::OverlapWithStack);
    }
    if offset.checked_add(filesz).is_none_or(|e| e > source.len()) {
        return Err(ElfLoadError::OutOfBounds);
    }

    let writable = ph.is_write();
    let executable = ph.is_execute();
    if writable && executable {
        return Err(ElfLoadError::WritableExecutableSegment);
    }

    let page_base = vaddr & !(PAGE_SIZE - 1);
    let page_offset = vaddr - page_base;
    let map_len = page_offset
        .checked_add(memsz)
        .ok_or(ElfLoadError::OutOfBounds)?;
    let page_count = map_len
        .checked_add(PAGE_SIZE - 1)
        .ok_or(ElfLoadError::OutOfBounds)?
        / PAGE_SIZE;

    // N2.1: enforce both per-segment (16 MiB) and per-binary aggregate (32 MiB)
    // page ceilings before touching cgroup charges or allocating frames.
    let _ = check_segment_page_budget(page_count, accumulated_pages)?;

    // Reserve the single O(1) rollback slot before pre-charging or mapping.
    if tracked.try_reserve(1).is_err() {
        return Err(ElfLoadError::OutOfMemory);
    }

    let charge_bytes = (page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        klog!(
            Error,
            "ELF loader: cgroup memory limit exceeded for segment (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    let mut frame_alloc = crate::syscall::RecordingFrameAllocator::new();
    kprintln!(
        "  load_segment: vaddr=0x{:x}, memsz={}, filesz={}, pages={}",
        vaddr,
        memsz,
        filesz,
        page_count
    );
    kprintln!(
        "    flags: R={} W={} X={} => PTFlags: 0x{:x}",
        true,
        writable,
        executable,
        flags.bits()
    );

    let mut mapped_in_segment: usize = 0;
    let mut remaining_copy = filesz;
    let mut src_off = offset;

    let map_result = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((page_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_data_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                // Zero and populate the frame via direct physical map before mapping.
                let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
                ptr::write_bytes(base, 0, PAGE_SIZE);
                if remaining_copy > 0 {
                    let start = if i == 0 { page_offset } else { 0 };
                    let copy_len = cmp::min(PAGE_SIZE - start, remaining_copy);
                    let dst = core::slice::from_raw_parts_mut(base.add(start), copy_len);
                    if let Err(e) = source.read_at(src_off, dst) {
                        frame_alloc.deallocate_frame(frame);
                        return Err(e);
                    }
                    remaining_copy -= copy_len;
                    src_off += copy_len;
                }

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    klog!(
                        Debug,
                        "ELF loader: map_page FAILED for va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                mapped_in_segment += 1;
            }
            Ok(())
        })
    };

    if mapped_in_segment > 0 {
        // Capacity was reserved above -> infallible.
        tracked.push(MappedRange {
            page_base,
            page_count: mapped_in_segment,
        });
    }

    if let Err(e) = map_result {
        let unmapped_bytes = charge_bytes.saturating_sub((mapped_in_segment * PAGE_SIZE) as u64);
        if unmapped_bytes > 0 {
            cgroup::uncharge_memory(cgroup_id, unmapped_bytes);
        }
        return Err(e);
    }

    Ok((charge_bytes, page_count, frame_alloc.take_pt_frames()))
}

/// M0-7 SLICE 5: the user-stack map geometry — SINGLE source of truth for BOTH the
/// loader (`allocate_user_stack_tracked`) and tests.
///
/// Returns `(stack_base, usable_base, eager_floor, eager_page_count)`:
/// * `stack_base`        — architectural low boundary of the reserved window
///   (`USER_STACK_TOP - USER_STACK_SIZE`); brk/segments are barred below it.
/// * `usable_base`       — `stack_base + USER_STACK_GUARD_SIZE`, the lowest VA that
///   COULD be mapped (guard is unmapped); the lazy region base.
/// * `eager_floor`       — `USER_STACK_TOP - USER_STACK_EAGER_SIZE`, the lowest
///   EAGERLY-mapped VA; the eager region base.
/// * `eager_page_count`  — `USER_STACK_EAGER_SIZE / PAGE_SIZE` (4 pages = 16KB)
///   eagerly mapped downward from `USER_STACK_TOP`.
///
/// Geometry:
/// ```
/// [stack_base, usable_base)         — UNMAPPED guard page (4KB)
/// [usable_base, eager_floor)        — LAZY region (demand-grow on #PF)
/// [eager_floor, USER_STACK_TOP)     — EAGER region (mapped at exec)
/// ```
pub(crate) const fn user_stack_layout() -> (usize, usize, usize, usize) {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    let usable_base = stack_base + USER_STACK_GUARD_SIZE;
    let eager_floor = USER_STACK_TOP as usize - USER_STACK_EAGER_SIZE;
    let eager_page_count = USER_STACK_EAGER_SIZE / PAGE_SIZE;
    (stack_base, usable_base, eager_floor, eager_page_count)
}

/// M0-7 slice 2 (SLICE 1+2): the SINGLE SOURCE of the architectural user-stack window
/// `[stack_base, USER_STACK_TOP)` — **guard-INCLUSIVE** (`stack_base = USER_STACK_TOP -
/// USER_STACK_SIZE`, the SAME ceiling the `OverlapWithStack` segment guards at
/// `:323`/`:495`/`:597` already enforce, NOT the `guard_top`/`usable_base` floor).
///
/// Returned as the half-open `(window_start, window_end)`. Consumed by the runtime
/// stack-window exclusion in `sys_mmap` and `sys_brk` (the "third door": today both bound
/// only on `USER_SPACE_TOP`, which is `0x2000` ABOVE the window, so a hinted/MAP_FIXED
/// mmap or a brk grow can land INSIDE the reserved stack region and alias it). Routing both
/// through this one const fn keeps the exclusion bound from drifting to `guard_top` (which
/// would re-open `[stack_base, guard_top)` and the guard page itself to aliasing).
pub(crate) const fn user_stack_window() -> (usize, usize) {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    (stack_base, USER_STACK_TOP as usize)
}

/// M0-7 / R172-X-F2 / R178-13 FIX: the lowest ACTUALLY-MAPPED user-stack VA after exec.
///
/// Returns the eager region floor (`USER_STACK_TOP - USER_STACK_EAGER_SIZE`), which is
/// the lowest VA that `allocate_user_stack_tracked` actually maps. This is the correct
/// initial value for `MmState.stack_floor_committed` — setting it to the usable_base
/// (guard-exclusive but below the eager floor) would make the first lazy #PF fault
/// rejected at `try_grow_user_stack:10795` because `fault_page_base >= old_floor`.
///
/// The eager region is 16KB (4 pages) at the top of the stack window, mapped to back
/// initial stack usage (argc/argv/envp/auxv, signal frames). The rest of the usable
/// region `[usable_base, eager_floor)` grows on-demand via #PF, which lowers
/// `stack_floor_committed` incrementally.
///
/// Derived from `user_stack_layout().2` (eager_floor) — the SINGLE source for both
/// the loader's map loop and this committed-floor seed.
///
/// `pub` (not `pub(crate)`) so the boot `usermode_test` AS-install path (in the binary
/// crate) can seed `MmState.stack_floor_committed` to the same mapped floor the exec
/// image-install commit uses — M0-7 item7 SLICE 4.
pub const fn user_stack_mapped_floor() -> u64 {
    let (_stack_base, _usable_base, eager_floor, _eager_page_count) = user_stack_layout();
    eager_floor as u64
}

/// GAP-5 exec step 2: the range user mappings (`mmap`, `mremap`) must stay
/// out of: the stack window plus the page just above it, where a non-leader
/// exec maps the leader's trampoline (`syscall.rs`, `EXEC_STUB_VA`).
pub const fn user_mapping_reserved_window() -> (usize, usize) {
    let (start, end) = user_stack_window();
    (start, end + PAGE_SIZE)
}

/// R178-13 FIX: the lowest VA that COULD be mapped (guard-exclusive, the usable base).
///
/// This is the absolute lower bound for `try_grow_user_stack` — a fault below this
/// would alias the guard page or the brk heap. The grow logic at `syscall.rs:10800`
/// uses `stack_grow_floor(rlim_cur)` which is typically higher (respecting RLIMIT_STACK),
/// but this const provides the architectural hard floor for validation.
///
/// Equals `user_stack_window().0 + USER_STACK_GUARD_SIZE` (the usable_base from
/// `user_stack_layout().1`). This is NOT the same as `user_stack_mapped_floor()` —
/// the latter is the eager floor (actually mapped at exec), while this is the
/// architectural floor (the lowest VA that could EVER be mapped, including lazy region).
pub const fn user_stack_usable_floor() -> u64 {
    user_stack_window().0 as u64 + USER_STACK_GUARD_SIZE as u64
}

/// M0-7 item7 SLICE 4 / R178-13 FIX: the lowest VA a user main-stack demand-grow may
/// descend to, derived from the soft `RLIMIT_STACK` `rlim_cur` (bytes). Used by
/// `try_grow_user_stack` to bound a grow request.
///
/// The growable extent is `min(rlim_cur, USER_STACK_SIZE - USER_STACK_GUARD_SIZE)`:
/// the `min()` clamp is LOAD-BEARING because `RLIMIT_STACK.rlim_max` is infinite, so a
/// process can `setrlimit` `rlim_cur` arbitrarily high — but the architectural window
/// only backs `SIZE - GUARD` bytes above the unmapped guard page, and a grow must NEVER
/// descend below `user_stack_usable_floor()` (that would alias the guard or the brk
/// heap below the window). The extent is page-aligned DOWN, which makes the returned
/// floor `== page_align_up(USER_STACK_TOP - min(...))` (the conservative direction: a
/// partial-page limit yields a SMALLER growable region) and page-aligned because
/// `USER_STACK_TOP` and the aligned extent are both page multiples.
///
/// R178-13: Returned floor is in `[user_stack_usable_floor(), USER_STACK_TOP]` and is
/// clamped to never go below the architectural usable floor (guard-exclusive). With the
/// default `rlim_cur == SIZE - GUARD`, it equals `user_stack_usable_floor()` exactly.
pub(crate) fn stack_grow_floor(rlim_cur: u64) -> usize {
    let max_extent = (USER_STACK_SIZE - USER_STACK_GUARD_SIZE) as u64;
    let extent = if rlim_cur < max_extent {
        rlim_cur
    } else {
        max_extent
    };
    let extent_pages = extent & !((PAGE_SIZE as u64) - 1);
    let computed_floor = (USER_STACK_TOP - extent_pages) as usize;

    // R178-13 FIX: Clamp to architectural hard floor (guard-exclusive usable base).
    // Prevents RLIMIT_STACK from pushing below the guard page or into brk heap.
    let hard_floor = user_stack_usable_floor() as usize;
    if computed_floor < hard_floor {
        hard_floor
    } else {
        computed_floor
    }
}

/// M0-7 self-test: pin the eager user-stack map geometry so a regression to the `+1`
/// "anti-guard" (a page above `USER_STACK_TOP`) or a forgotten guard carve fails
/// `make test`. Pure — exercises the loader's own `user_stack_layout` helper.
pub fn run_user_stack_guard_range_self_test() {
    let (stack_base, usable_base, eager_floor, eager_page_count) = user_stack_layout();
    // The guard is exactly ONE page at the window's low end.
    assert_eq!(
        usable_base - stack_base,
        USER_STACK_GUARD_SIZE,
        "guard page must be exactly USER_STACK_GUARD_SIZE at the window low end"
    );
    // M0-7 SLICE 5: Exactly USER_STACK_EAGER_SIZE / PAGE_SIZE pages are eagerly mapped (4 pages = 16KB).
    assert_eq!(
        eager_page_count,
        USER_STACK_EAGER_SIZE / PAGE_SIZE,
        "eager page_count must be USER_STACK_EAGER_SIZE / PAGE_SIZE"
    );
    // M0-7 SLICE 5: The topmost eager page ends EXACTLY at USER_STACK_TOP.
    // The eager region is [eager_floor, USER_STACK_TOP).
    assert_eq!(
        eager_floor + eager_page_count * PAGE_SIZE,
        USER_STACK_TOP as usize,
        "top eager page must end exactly at USER_STACK_TOP (no page above the window)"
    );
    // M0-7 SLICE 5: The eager map stays strictly inside the reserved window.
    // The eager region [eager_floor, USER_STACK_TOP) is above the guard and below USER_STACK_TOP.
    assert!(
        usable_base == stack_base + USER_STACK_GUARD_SIZE
            && eager_floor >= usable_base
            && eager_floor + eager_page_count * PAGE_SIZE <= USER_STACK_TOP as usize,
        "eager stack map must lie within (stack_base+guard .. USER_STACK_TOP]"
    );
}

/// Z-10 fix: 分配用户栈并追踪映射，便于失败时全局回滚
///
/// # Arguments
///
/// * `tracked` - 全局映射追踪向量，成功映射的页会被追加到此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory accounting
///
/// # Returns
///
/// 成功返回 Ok(charged_bytes)，失败时调用方负责使用 tracked 进行全局回滚。
/// R125-1 FIX: Returns the number of bytes charged to the cgroup for the
/// stack so the caller can accumulate the total for exec rollback.
fn allocate_user_stack_tracked(
    tracked: &mut Vec<MappedRange>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(u64, Vec<PhysFrame<Size4KiB>>), ElfLoadError> {
    let (_, usable_base, eager_floor, eager_page_count) = user_stack_layout();

    if tracked.try_reserve(1).is_err() {
        return Err(ElfLoadError::OutOfMemory);
    }

    let charge_bytes = (eager_page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        klog!(
            Error,
            "ELF loader: cgroup memory limit exceeded for stack (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    let mut frame_alloc = crate::syscall::RecordingFrameAllocator::new();
    let mut mapped_stack: usize = 0;

    let map_result = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..eager_page_count {
                let va = VirtAddr::new((eager_floor + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_data_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                // Zero stack frame via direct physical map before mapping.
                let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
                ptr::write_bytes(base, 0, PAGE_SIZE);

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    klog!(
                        Debug,
                        "ELF loader: map_page FAILED for stack va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                mapped_stack += 1;
            }
            debug_assert!(
                mgr.translate_addr(VirtAddr::new((usable_base - USER_STACK_GUARD_SIZE) as u64))
                    .is_none(),
                "user-stack guard page must be unmapped"
            );
            Ok(())
        })
    };

    if mapped_stack > 0 {
        tracked.push(MappedRange {
            page_base: eager_floor,
            page_count: mapped_stack,
        });
    }

    if let Err(e) = map_result {
        let unmapped_bytes = charge_bytes.saturating_sub((mapped_stack * PAGE_SIZE) as u64);
        if unmapped_bytes > 0 {
            cgroup::uncharge_memory(cgroup_id, unmapped_bytes);
        }
        return Err(e);
    }

    debug_assert_eq!(
        mapped_stack, eager_page_count,
        "stack mapped-page count must equal page_count (charge/zero lockstep)"
    );

    Ok((charge_bytes, frame_alloc.take_pt_frames()))
}

fn rollback_all_mappings(tracked: &mut Vec<MappedRange>, cgroup_id: cgroup::CgroupId) {
    if tracked.is_empty() {
        return;
    }

    let page_count: usize = tracked.iter().map(|r| r.page_count).sum();
    klog!(Warn, "ELF loader: rolling back {} mapped pages", page_count);

    let uncharge_bytes = (page_count * PAGE_SIZE) as u64;
    cgroup::uncharge_memory(cgroup_id, uncharge_bytes);

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            while let Some(range) = tracked.pop() {
                for i in (0..range.page_count).rev() {
                    let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(
                        (range.page_base + i * PAGE_SIZE) as u64,
                    ));
                    match mgr.unmap_page(page) {
                        Ok(unmapped_frame) => {
                            frame_alloc.deallocate_frame(unmapped_frame);
                        }
                        Err(e) => {
                            klog!(
                                Warn,
                                "ELF rollback: unmap_page failed for va=0x{:x}: {:?}",
                                page.start_address().as_u64(),
                                e
                            );
                        }
                    }
                }
            }
        });
    }
}

/// 打印 ELF 文件信息（调试用）
// R163-21 FIX: Use Debug level — Info-level VA disclosure aids ASLR bypass.
pub fn print_elf_info(image: &[u8]) {
    if let Ok(hdr) = parse_and_validate_elf64_header(image) {
        klog!(Debug, "=== ELF Info ===");
        klog!(Debug, "Entry point: 0x{:x}", hdr.entry);
        klog!(Debug, "Program headers: {}", hdr.phnum);

        for idx in 0..hdr.phnum {
            if let Ok(ph) = read_elf64_phdr(image, &hdr, idx) {
                if ph.p_type == ELF64_PT_LOAD {
                    klog!(
                        Debug,
                        "  Segment {}: vaddr=0x{:x}, memsz=0x{:x}, filesz=0x{:x}",
                        idx,
                        ph.p_vaddr,
                        ph.p_memsz,
                        ph.p_filesz
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_elf64(
        file_len: usize,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    ) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; file_len];
        // ELF64 header
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = ELF64_CLASS_64;
        buf[5] = ELF64_DATA_LSB;
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&ELF64_ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&ELF64_EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&(p_vaddr + 0x100).to_le_bytes()); // e_entry
        buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        buf[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        buf[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        // One PT_LOAD at offset 64
        let ph = &mut buf[64..64 + ELF64_PHDR_SIZE];
        ph[0..4].copy_from_slice(&ELF64_PT_LOAD.to_le_bytes());
        ph[4..8].copy_from_slice(&(4u32 | ELF64_PF_X).to_le_bytes()); // PF_R | PF_X
        ph[8..16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        ph[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
        ph[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
        ph[32..40].copy_from_slice(&p_filesz.to_le_bytes());
        ph[40..48].copy_from_slice(&p_memsz.to_le_bytes());
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        buf
    }

    #[test]
    fn n2_1_exec_image_append_read_and_e2big_limits() {
        assert_eq!(MAX_EXEC_IMAGE_BYTES, 16 * 1024 * 1024);
        assert!(MAX_EXEC_IMAGE_BYTES > 256 * 1024);

        let mut img = ExecImage::new();
        assert!(img.is_empty());
        assert_eq!(img.prefix_slice(16), &[]);

        // Append 300 KiB (> legacy 256 KiB ceiling) across chunk boundaries.
        let chunk = [0xA5u8; 4096];
        for _ in 0..75 {
            img.try_append(&chunk, MAX_EXEC_IMAGE_BYTES)
                .expect("300 KiB image must fit within N2.1 ceiling");
        }
        assert_eq!(img.len(), 300 * 1024);
        assert_eq!(img.prefix_slice(4096).len(), 4096);
        assert_eq!(img.prefix_slice(8192).len(), 4096);

        let mut probe = [0u8; 64];
        img.read_at(300 * 1024 - 64, &mut probe)
            .expect("tail read succeeds");
        assert!(probe.iter().all(|&b| b == 0xA5));
        assert!(matches!(
            img.read_at(300 * 1024 - 32, &mut probe),
            Err(ElfLoadError::OutOfBounds)
        ));

        // Exceeding max_len returns E2BIG without mutating length.
        assert_eq!(img.try_append(&[1u8], 300 * 1024), Err(SyscallError::E2BIG));
        assert_eq!(img.len(), 300 * 1024);

        // try_from_reader enforces E2BIG before allocating.
        assert!(matches!(
            ExecImage::try_from_reader(MAX_EXEC_IMAGE_BYTES + 1, MAX_EXEC_IMAGE_BYTES, |_, _| Ok(
                ()
            )),
            Err(SyscallError::E2BIG)
        ));
    }

    #[test]
    fn n2_1_elf_segment_and_total_page_budgets() {
        assert_eq!(MAX_ELF_SEGMENT_PAGES, 4096);
        assert_eq!(MAX_ELF_TOTAL_PAGES, 8192);

        // 2 MiB (512 pages) and 16 MiB (4096 pages) segments are now accepted.
        assert_eq!(check_segment_page_budget(512, 0).unwrap(), 512);
        assert_eq!(
            check_segment_page_budget(MAX_ELF_SEGMENT_PAGES, 0).unwrap(),
            MAX_ELF_SEGMENT_PAGES
        );
        // Two 16 MiB segments fit within the 32 MiB aggregate cap.
        assert_eq!(
            check_segment_page_budget(MAX_ELF_SEGMENT_PAGES, MAX_ELF_SEGMENT_PAGES).unwrap(),
            MAX_ELF_TOTAL_PAGES
        );
        // Single segment > 16 MiB is rejected.
        assert!(matches!(
            check_segment_page_budget(MAX_ELF_SEGMENT_PAGES + 1, 0),
            Err(ElfLoadError::SegmentOutOfRange)
        ));
        // Aggregate > 32 MiB is rejected.
        assert!(matches!(
            check_segment_page_budget(1, MAX_ELF_TOTAL_PAGES),
            Err(ElfLoadError::SegmentOutOfRange)
        ));
    }

    #[test]
    fn n2_1_validate_large_elf_and_phdr_bounds() {
        let len = 300 * 1024;
        let bytes = build_synthetic_elf64(len, USER_BASE as u64, len as u64, 2 * 1024 * 1024);
        let img = ExecImage::from_vec(bytes);
        validate_exec_image(&img).expect("300 KiB ELF with 2 MiB PT_LOAD must validate");

        let hdr = parse_and_validate_elf64_header(&img).expect("header parses");
        let phdr_va = compute_phdr_va_from_source(&img, &hdr);
        assert_eq!(phdr_va, USER_BASE as u64 + 64);

        // R172-02: bad e_phentsize and unaligned e_phoff still fail closed.
        let mut bad_entsize = build_synthetic_elf64(256, USER_BASE as u64, 256, 4096);
        bad_entsize[54..56].copy_from_slice(&52u16.to_le_bytes());
        assert!(matches!(
            validate_elf_image(&bad_entsize),
            Err(ElfLoadError::OutOfBounds)
        ));

        let mut bad_align = build_synthetic_elf64(256, USER_BASE as u64, 256, 4096);
        bad_align[32..40].copy_from_slice(&66u64.to_le_bytes());
        assert!(matches!(
            validate_elf_image(&bad_align),
            Err(ElfLoadError::OutOfBounds)
        ));
    }
}
