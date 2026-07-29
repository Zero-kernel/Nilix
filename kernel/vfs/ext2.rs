//! Ext2 filesystem implementation with write support
//!
//! Provides ext2 filesystem support:
//! - Mount and validate superblock
//! - Directory traversal and lookup
//! - File reading with page cache integration
//! - In-place writes to already-mapped blocks
//! - Ordered-data JBD2 transactions for direct-block allocation on Ext3 images
//!
//! Based on ext2 specification (https://www.nongnu.org/ext2-doc/)

use crate::traits::{FileHandle, FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use block::BlockDevice;
use core::any::Any;
use core::cmp;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_core::FileDescriptor;
use kernel_crypto::sha256::Sha256;
use mm::{
    buddy_allocator, page_cache, HeapClass, HeapReservation, PageCacheEntry, PAGE_CACHE, PAGE_SIZE,
    PHYSICAL_MEMORY_OFFSET,
};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Ext2 magic number
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock offset from partition start
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// Root inode number
pub const EXT2_ROOT_INO: u32 = 2;

/// Number of direct blocks in inode
pub const EXT2_NDIR_BLOCKS: usize = 12;

/// Indirect block index
pub const EXT2_IND_BLOCK: usize = 12;

/// Double indirect block index
pub const EXT2_DIND_BLOCK: usize = 13;

/// Triple indirect block index
pub const EXT2_TIND_BLOCK: usize = 14;

const EXT2_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0000_0002;
const EXT3_FEATURE_INCOMPAT_RECOVER: u32 = 0x0000_0004;
const EXT2_SUPPORTED_INCOMPAT: u32 = EXT2_FEATURE_INCOMPAT_FILETYPE | EXT3_FEATURE_INCOMPAT_RECOVER;
const EXT3_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0000_0004;
const EXT2_FEATURE_COMPAT_RESIZE_INODE: u32 = 0x0000_0010;
const EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0000_0001;
const EXT2_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0000_0002;
const EXT2_FEATURE_RO_COMPAT_BTREE_DIR: u32 = 0x0000_0004;
const EXT3_SUPPORTED_RO_COMPAT: u32 = EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER
    | EXT2_FEATURE_RO_COMPAT_LARGE_FILE
    | EXT2_FEATURE_RO_COMPAT_BTREE_DIR;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V2: u32 = 4;

const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0000_0001;
/// Zero-OS private writer-intent format. Active transactions without this bit
/// are rejected because standard JBD2 post-images contain no trustworthy old
/// state from which to validate a torn checkpoint.
const JBD2_FEATURE_INCOMPAT_ZERO_INTENT: u32 = 0x8000_0000;
const JBD2_SUPPORTED_INCOMPAT: u32 =
    JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_ZERO_INTENT;

const JBD2_FLAG_ESCAPE: u16 = 0x0001;
const JBD2_FLAG_SAME_UUID: u16 = 0x0002;
const JBD2_FLAG_LAST_TAG: u16 = 0x0008;

const JOURNAL_MAX_METADATA_BLOCKS: usize = 4;
const JOURNAL_TRANSACTION_BLOCKS: u32 = 1 + JOURNAL_MAX_METADATA_BLOCKS as u32 + 1;
const MAX_JOURNAL_BLOCKS: usize = 16 * 1024;

// RF180-13 FIX: hostile-but-geometrically-valid images must not turn mount or
// recovery into an effectively unbounded metadata walk.  These budgets are
// derived from the already-supported 64K-group geometry rather than from file
// size: resize-inode validation may inspect and retain at most 64 pointer-owned
// blocks per group (16 MiB each of on-disk work and u32 ownership state).
// Recovery of a newly published
// indirect tree is bounded by the same 16 MiB metadata-work envelope and a
// 4 MiB reference vector.  Images exceeding a budget fail closed at mount;
// ordinary file-size/read limits are unchanged.
const MAX_EXT2_GROUPS: u32 = 65_536;
const MAX_RESIZE_POINTER_WORDS: usize = MAX_EXT2_GROUPS as usize * 64;
const MAX_RESIZE_RESERVED_BLOCKS: usize = MAX_RESIZE_POINTER_WORDS;
const MAX_RECOVERY_MAPPING_SCAN_BYTES: usize = MAX_EXT2_GROUPS as usize * 256;
const MAX_RECOVERY_REFERENCED_BLOCKS: usize = MAX_JOURNAL_BLOCKS * 64;
const MAX_RECOVERY_CHANGED_BITMAPS: usize = JOURNAL_MAX_METADATA_BLOCKS;
const MAX_OWNERSHIP_REFERENCES: usize = MAX_EXT2_GROUPS as usize * 64;
const MAX_OWNERSHIP_INODES: u32 = MAX_EXT2_GROUPS * 64;
const MAX_OWNERSHIP_BITMAP_BYTES: usize = MAX_EXT2_GROUPS as usize * 1024;
const MAX_OWNERSHIP_MAPPING_BYTES: usize = MAX_EXT2_GROUPS as usize * 1024;
const MAX_OWNERSHIP_INODE_TABLE_BYTES: usize = MAX_EXT2_GROUPS as usize * 1024;
const MAX_SPARSE_GAP_MAPPING_NODES: usize = 4096;
// RF180-34 FIX: this is a retained-plan limit, not a logical-gap limit.  The
// plan retains only compact u32 physical IDs; at most two partial-block ranges
// live in stack-side boundary records.  This preserves the original 65,536
// actual-target contract within HeapClass::FilesystemIo's byte envelope.
const MAX_SPARSE_GAP_DATA_BLOCKS: usize = 65_536;
// RF180-34 FIX: the validation/count and exact-collection passes must observe
// the same ordered pointer graph.  Allocation-bitmap revalidation alone cannot
// distinguish a same-count substitution with another inode's allocated block.
const SPARSE_GAP_TRANSCRIPT_DOMAIN: &[u8] = b"Zero-OS ext2 sparse-gap transcript v1\0";

const JBD2_HEADER_BYTES: usize = 12;
const JBD2_TAG_BYTES: usize = 8;
const JBD2_SUPER_BLOCKSIZE_OFFSET: usize = 12;
const JBD2_SUPER_MAXLEN_OFFSET: usize = 16;
const JBD2_SUPER_FIRST_OFFSET: usize = 20;
const JBD2_SUPER_SEQUENCE_OFFSET: usize = 24;
const JBD2_SUPER_START_OFFSET: usize = 28;
const JBD2_SUPER_ERRNO_OFFSET: usize = 32;
const JBD2_SUPER_FEATURE_COMPAT_OFFSET: usize = 36;
const JBD2_SUPER_FEATURE_INCOMPAT_OFFSET: usize = 40;
const JBD2_SUPER_FEATURE_RO_COMPAT_OFFSET: usize = 44;
const JBD2_SUPER_UUID_OFFSET: usize = 48;
const JBD2_SUPER_NR_USERS_OFFSET: usize = 64;

const ZERO_INTENT_MAGIC: [u8; 4] = *b"ZJ01";
const ZERO_INTENT_VERSION: u16 = 1;
const ZERO_INTENT_KIND_INODE_UPDATE: u8 = 1;
const ZERO_INTENT_KIND_DIRECT_ALLOCATION: u8 = 2;
const ZERO_INTENT_MAGIC_OFFSET: usize = JBD2_HEADER_BYTES;
const ZERO_INTENT_VERSION_OFFSET: usize = 16;
const ZERO_INTENT_KIND_OFFSET: usize = 18;
const ZERO_INTENT_COUNT_OFFSET: usize = 19;
const ZERO_INTENT_INODE_OFFSET: usize = 20;
const ZERO_INTENT_FILE_BLOCK_OFFSET: usize = 24;
const ZERO_INTENT_PHYSICAL_OFFSET: usize = 28;
const ZERO_INTENT_PREIMAGE_HASHES_OFFSET: usize = 32;
const ZERO_INTENT_PREIMAGE_HASH_BYTES: usize = JOURNAL_MAX_METADATA_BLOCKS * 32;
const ZERO_INTENT_OLD_INODE_OFFSET: usize =
    ZERO_INTENT_PREIMAGE_HASHES_OFFSET + ZERO_INTENT_PREIMAGE_HASH_BYTES;
const ZERO_INTENT_DIGEST_OFFSET: usize = ZERO_INTENT_OLD_INODE_OFFSET + size_of::<Ext2InodeRaw>();
const ZERO_INTENT_END: usize = ZERO_INTENT_DIGEST_OFFSET + 32;
const ZERO_INTENT_HASH_DOMAIN: &[u8] = b"Zero-OS ext3 journal intent v1\0";
const _: () = assert!(size_of::<Ext2InodeRaw>() == 128);
const _: () = assert!(ZERO_INTENT_END <= 1024);

/// R180-6 FIX: validate the complete half-open write range before Ext2 can
/// modify any block. The caller decides whether each mapped or direct-hole
/// block is supported; this keeps an unsupported indirect hole from appearing
/// after an earlier chunk has already reached persistent storage.
fn preflight_write_range<F>(
    offset: u64,
    len: usize,
    block_size: u64,
    mut is_mapped: F,
) -> Result<u64, FsError>
where
    F: FnMut(u32) -> Result<bool, FsError>,
{
    if block_size == 0 || block_size > u32::MAX as u64 {
        return Err(FsError::Invalid);
    }
    let len = u64::try_from(len).map_err(|_| FsError::Invalid)?;
    let end_offset = offset.checked_add(len).ok_or(FsError::Invalid)?;
    if len == 0 {
        return Ok(end_offset);
    }

    let first_block = u32::try_from(offset / block_size).map_err(|_| FsError::Invalid)?;
    let last_block = u32::try_from((end_offset - 1) / block_size).map_err(|_| FsError::Invalid)?;
    for file_block in first_block..=last_block {
        if !is_mapped(file_block)? {
            return Err(FsError::NotSupported);
        }
    }
    Ok(end_offset)
}

/// RF178-39 FIX: one reusable block-sized allocation for an entire ext2
/// write/append mutation. Every metadata/data RMW after the first persistent
/// write borrows this buffer instead of allocating another Vec.
struct Ext2MutationScratch {
    block: Vec<u8>,
    // Field order is load-bearing: the backing allocation is destroyed before
    // its transient heap reservation is released.
    _reservation: Option<HeapReservation>,
}

impl Ext2MutationScratch {
    fn validated_block_size(block_size: u32) -> Result<usize, FsError> {
        if !(1024..=65536).contains(&block_size) || size_of::<Ext2Superblock>() > 1024 {
            return Err(FsError::Invalid);
        }
        Ok(block_size as usize)
    }

    fn try_new(block_size: u32) -> Result<Self, FsError> {
        let block_size = Self::validated_block_size(block_size)?;
        let mut block = Vec::new();
        block
            .try_reserve_exact(block_size)
            .map_err(|_| FsError::NoSpace)?;
        block.resize(block_size, 0);
        Ok(Self {
            block,
            _reservation: None,
        })
    }

    /// RF180-34: reserve the allocator footprint before runtime filesystem I/O
    /// allocates its block scratch.  Hosted/early construction retains
    /// `try_new`; production mutation paths use this admitted constructor.
    fn try_new_admitted(block_size: u32) -> Result<Self, FsError> {
        let block_size = Self::validated_block_size(block_size)?;
        let estimated = mm::vec_charge_bytes::<u8>(block_size).map_err(|_| FsError::NoMem)?;
        let mut reservation =
            mm::try_reserve_heap(HeapClass::FilesystemIo, estimated).map_err(|_| FsError::NoMem)?;
        let mut block = Vec::new();
        block
            .try_reserve_exact(block_size)
            .map_err(|_| FsError::NoMem)?;
        let actual = mm::vec_charge_bytes::<u8>(block.capacity()).map_err(|_| FsError::NoMem)?;
        reservation.resize(actual).map_err(|_| FsError::NoMem)?;
        block.resize(block_size, 0);
        Ok(Self {
            block,
            _reservation: Some(reservation),
        })
    }

    #[inline]
    fn block(&self) -> &[u8] {
        &self.block
    }

    #[inline]
    fn block_mut(&mut self) -> &mut [u8] {
        &mut self.block
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.block.capacity()
    }
}

#[derive(Clone, Copy)]
enum Ext2WriteMode {
    Positioned(u64),
    Append,
}

#[derive(Clone, Copy)]
struct InodeWriteTarget {
    block: u32,
    start: usize,
    copy_len: usize,
}

/// Boot-time boundary probes for the allocation-free write preflight.
#[doc(hidden)]
pub fn run_ext2_direct_write_preflight_self_test() {
    const BLOCK_SIZE: u64 = 4096;
    const DIRECT_LIMIT: u64 = BLOCK_SIZE * EXT2_NDIR_BLOCKS as u64;

    let mut mapped_blocks = 0u32;
    assert_eq!(
        preflight_write_range(0, DIRECT_LIMIT as usize, BLOCK_SIZE, |block| {
            assert_eq!(block, mapped_blocks);
            mapped_blocks += 1;
            Ok(true)
        }),
        Ok(DIRECT_LIMIT)
    );
    assert_eq!(mapped_blocks, EXT2_NDIR_BLOCKS as u32);
    assert_eq!(
        preflight_write_range(DIRECT_LIMIT - 1, 1, BLOCK_SIZE, |block| Ok(block == 11)),
        Ok(DIRECT_LIMIT)
    );
    assert_eq!(
        preflight_write_range(DIRECT_LIMIT - 1, 2, BLOCK_SIZE, |block| Ok(block == 11)),
        Err(FsError::NotSupported)
    );
    assert_eq!(
        preflight_write_range(11 * BLOCK_SIZE, 1, BLOCK_SIZE, |_| Ok(false)),
        Err(FsError::NotSupported)
    );
    assert_eq!(
        preflight_write_range(
            DIRECT_LIMIT - BLOCK_SIZE / 2,
            BLOCK_SIZE as usize,
            BLOCK_SIZE,
            |block| Ok(block == 11),
        ),
        Err(FsError::NotSupported)
    );
    assert_eq!(
        preflight_write_range(u64::MAX - 1, 2, BLOCK_SIZE, |_| Ok(true)),
        Err(FsError::Invalid)
    );
    assert_eq!(
        preflight_write_range(0, 1, u64::MAX, |_| Ok(true)),
        Err(FsError::Invalid)
    );
    assert_eq!(
        preflight_write_range(DIRECT_LIMIT, 1, BLOCK_SIZE, |block| Ok(block == 12)),
        Ok(DIRECT_LIMIT + 1)
    );
    assert_eq!(
        preflight_write_range(DIRECT_LIMIT, BLOCK_SIZE as usize + 1, BLOCK_SIZE, |block| {
            Ok(block != 13)
        }),
        Err(FsError::NotSupported)
    );
}

/// Boot-time probes for RF178-39's allocation discipline and fallible lossy
/// directory-name decoder. Pointer/capacity stability proves buffer reuse does
/// not grow the Vec after the pre-mutation allocation succeeds.
#[doc(hidden)]
pub fn run_ext2_mutation_scratch_self_test() {
    assert!(matches!(
        Ext2MutationScratch::try_new(1023),
        Err(FsError::Invalid)
    ));
    assert!(matches!(
        Ext2MutationScratch::try_new(65537),
        Err(FsError::Invalid)
    ));

    for block_size in [1024u32, 4096, 65536] {
        let mut scratch = Ext2MutationScratch::try_new(block_size).expect("ext2 mutation scratch");
        let ptr = scratch.block.as_ptr();
        let capacity = scratch.block.capacity();
        scratch.block_mut().fill(0xA5);
        assert_eq!(scratch.block().len(), block_size as usize);
        assert_eq!(scratch.block.as_ptr(), ptr);
        assert_eq!(scratch.block.capacity(), capacity);
        scratch.block_mut().fill(0);
        assert_eq!(scratch.block.as_ptr(), ptr);
        assert_eq!(scratch.block.capacity(), capacity);
        scratch.block_mut().fill(u8::MAX);
        assert_eq!(
            Ext2Fs::bitmap_free_count(scratch.block(), block_size * 8),
            Ok(0)
        );
        scratch.block_mut()[block_size as usize - 1] &= 0x7F;
        assert_eq!(
            Ext2Fs::bitmap_free_count(scratch.block(), block_size * 8),
            Ok(1)
        );
    }

    assert_eq!(
        fallible_lossy_name("zero-OS".as_bytes()).expect("valid UTF-8 name"),
        "zero-OS"
    );
    assert_eq!(
        fallible_lossy_name("零-OS".as_bytes()).expect("valid multibyte UTF-8 name"),
        "零-OS"
    );
    assert_eq!(
        fallible_lossy_name(&[b'a', 0xF0, b'(', 0x8C, b'(', b'z']).expect("invalid UTF-8 name"),
        "a\u{FFFD}(\u{FFFD}(z"
    );
    assert_eq!(
        fallible_lossy_name(&[0xE2, 0x82]).expect("truncated UTF-8 name"),
        "\u{FFFD}"
    );
    assert_eq!(
        fallible_lossy_name(&[0x80, 0x80]).expect("consecutive invalid UTF-8 bytes"),
        "\u{FFFD}\u{FFFD}"
    );

    // RF180-35: the trace oracle and the journal crash oracle each own device
    // images plus filesystem Arcs.  Bound the trace oracle's lifetime so its
    // retained allocations are destroyed before the crash suite constructs a
    // second filesystem.  Runtime tests must exercise production allocation
    // behavior without manufacturing an impossible co-residency peak.
    {
        struct TraceBlockDevice {
            bytes: Mutex<Vec<u8>>,
            writes: AtomicU64,
        }

        impl BlockDevice for TraceBlockDevice {
            fn name(&self) -> &str {
                "ext2-rf178-39-trace"
            }

            fn sector_size(&self) -> u32 {
                512
            }

            fn capacity_sectors(&self) -> u64 {
                (self.bytes.lock().len() / 512) as u64
            }

            fn submit_bio(&self, _bio: block::Bio) -> Result<(), block::BlockError> {
                Err(block::BlockError::NotSupported)
            }

            fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, block::BlockError> {
                let start = usize::try_from(sector)
                    .ok()
                    .and_then(|sector| sector.checked_mul(512))
                    .ok_or(block::BlockError::Invalid)?;
                let end = start
                    .checked_add(buf.len())
                    .ok_or(block::BlockError::Invalid)?;
                let bytes = self.bytes.lock();
                let source = bytes.get(start..end).ok_or(block::BlockError::Invalid)?;
                buf.copy_from_slice(source);
                Ok(buf.len())
            }

            fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, block::BlockError> {
                let start = usize::try_from(sector)
                    .ok()
                    .and_then(|sector| sector.checked_mul(512))
                    .ok_or(block::BlockError::Invalid)?;
                let end = start
                    .checked_add(buf.len())
                    .ok_or(block::BlockError::Invalid)?;
                let mut bytes = self.bytes.lock();
                let target = bytes
                    .get_mut(start..end)
                    .ok_or(block::BlockError::Invalid)?;
                target.copy_from_slice(buf);
                self.writes
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |writes| {
                        writes.checked_add(1)
                    })
                    .expect("ext2 trace write counter overflow");
                Ok(buf.len())
            }

            fn flush(&self) -> Result<(), block::BlockError> {
                Ok(())
            }
        }

        let mut device_bytes = Vec::new();
        device_bytes
            .try_reserve_exact(8 * 1024)
            .expect("trace block-device bytes");
        device_bytes.resize(8 * 1024, 0);
        device_bytes[2 * 1024] |= 1 << 1;
        let inode2_tail_start = 3 * 1024 + 256 + size_of::<Ext2InodeRaw>();
        device_bytes[inode2_tail_start..inode2_tail_start + 128].fill(0xA5);
        let device = Arc::try_new(TraceBlockDevice {
            bytes: Mutex::new(device_bytes),
            writes: AtomicU64::new(0),
        })
        .expect("trace block device");
        let dev: Arc<dyn BlockDevice> = device.clone();

        // SAFETY: Ext2Superblock contains only integer fields and byte arrays.
        let mut superblock: Ext2Superblock = unsafe { core::mem::zeroed() };
        superblock.inodes_count = 8;
        superblock.blocks_count = 8;
        superblock.free_blocks_count = 2;
        superblock.first_data_block = 1;
        superblock.blocks_per_group = 8;
        superblock.inodes_per_group = 8;
        let mut group_descs = Vec::new();
        group_descs
            .try_reserve_exact(1)
            .expect("trace group descriptor");
        group_descs.push(Ext2GroupDesc {
            inode_bitmap: 2,
            inode_table: 3,
            free_blocks_count: 2,
            ..Ext2GroupDesc::default()
        });
        let fs = Arc::try_new(Ext2Fs {
            fs_id: u64::MAX - 179,
            dev,
            superblock: RwLock::new(superblock),
            group_descs: RwLock::new(group_descs),
            block_size: 1024,
            sector_size: 512,
            blocks_count: 8,
            blocks_per_group: 8,
            inodes_per_group: 8,
            inode_size: 256,
            root: RwLock::new(None),
            inode_cache: WeakArcCache::new(),
            meta_lock: Mutex::new(()),
            journal: Mutex::new(None),
            resize_reserved_blocks: RwLock::new(Vec::new()),
            io_faulted: AtomicBool::new(false),
            self_ref: Mutex::new(None),
        })
        .expect("trace ext2 filesystem");
        let mut raw = Ext2InodeRaw::default();
        raw.mode = EXT2_S_IFREG | 0o644;
        raw.size_lo = 1;
        raw.links_count = 1;
        raw.blocks_lo = 2;
        raw.block[0] = 5;
        let inode = fs
            .inode_cache
            .get_or_try_insert_with(2, || fs.new_inode_from_raw(2, raw))
            .expect("trace canonical inode");

        let inode_target = fs.inode_write_target(2).expect("trace inode target");
        let mut inode_scratch =
            Ext2MutationScratch::try_new(1024).expect("trace inode mutation scratch");
        fs.write_inode_raw_locked(inode_target, &raw, &mut inode_scratch)
            .expect("first trace inode RMW");
        let mut next_raw = raw;
        next_raw.size_lo = 2;
        fs.write_inode_raw_locked(inode_target, &next_raw, &mut inode_scratch)
            .expect("second trace inode RMW");
        assert_eq!(device.writes.load(Ordering::Relaxed), 2);
        assert_eq!(inode.write_at(0, b"A"), Err(FsError::ReadOnly));
        assert_eq!(inode.append_write(b"B"), Err(FsError::ReadOnly));
        assert_eq!(device.writes.load(Ordering::Relaxed), 2);
        assert_eq!(inode.raw.read().block, raw.block);
        assert_eq!(inode.raw.read().blocks_lo, raw.blocks_lo);
        assert!(
            device.bytes.lock()[inode2_tail_start..inode2_tail_start + 128]
                .iter()
                .all(|&byte| byte == 0xA5)
        );

        // RF180-13: recovery may update only the base inode record.  A valid
        // mapped-inode after-image passes, but changing one byte in the 128-byte
        // implementation-specific tail fails before any device write.
        let mut journal_blocks = Vec::new();
        journal_blocks
            .try_reserve_exact(1)
            .expect("trace journal block map");
        journal_blocks.push(6);
        let trace_journal = Ext2Journal {
            blocks: journal_blocks,
            mapping_blocks: Vec::new(),
            owned_blocks: Vec::new(),
            max_len: 1,
            first: 0,
            next_sequence: 0,
            start: 0,
            uuid: [0xA5; 16],
            feature_incompat: 0,
        };
        let entry = JournalOverlayEntry {
            home: 3,
            log: 0,
            flags: JBD2_FLAG_LAST_TAG,
            order: 0,
            image_offset: 0,
        };
        {
            let mut bytes = device.bytes.lock();
            let home = bytes[3 * 1024..4 * 1024].to_vec();
            bytes[6 * 1024..7 * 1024].copy_from_slice(&home);
            let mut logged = next_raw;
            logged.size_lo = 3;
            logged.ctime = 7;
            logged.mtime = 7;
            let logged_bytes = unsafe {
                core::slice::from_raw_parts(
                    &logged as *const Ext2InodeRaw as *const u8,
                    size_of::<Ext2InodeRaw>(),
                )
            };
            bytes[6 * 1024 + 256..6 * 1024 + 256 + logged_bytes.len()]
                .copy_from_slice(logged_bytes);
        }
        let mut entries = [entry];
        let post_images = fs
            .freeze_recovery_post_images(&trace_journal, &mut entries)
            .expect("freeze trace recovery image");
        let mut preimage_hashes = [[0u8; 32]; JOURNAL_MAX_METADATA_BLOCKS];
        preimage_hashes[0] = Sha256::digest(&device.bytes.lock()[3 * 1024..4 * 1024]);
        let intent = JournalCommitIntent {
            kind: ZERO_INTENT_KIND_INODE_UPDATE,
            metadata_count: 1,
            inode_number: 2,
            file_block: u32::MAX,
            physical: 0,
            preimage_hashes,
            old_inode: next_raw,
        };
        let writes_before_recovery_validation = device.writes.load(Ordering::Relaxed);
        assert!(fs
            .validate_recovery_grammar(&entries, &post_images, Some(&intent))
            .is_ok());
        device.bytes.lock()[6 * 1024 + 256 + size_of::<Ext2InodeRaw>()] ^= 1;
        assert!(
            fs.validate_recovery_grammar(&entries, &post_images, Some(&intent))
                .is_ok(),
            "validation must keep consuming the frozen post-image"
        );
        let mut hostile_entries = [entry];
        let hostile_post_images = fs
            .freeze_recovery_post_images(&trace_journal, &mut hostile_entries)
            .expect("freeze hostile trace recovery image");
        assert!(fs
            .validate_recovery_grammar(&hostile_entries, &hostile_post_images, Some(&intent))
            .is_err());
        assert_eq!(
            device.writes.load(Ordering::Relaxed),
            writes_before_recovery_validation
        );

        let mut hole_raw = raw;
        hole_raw.size_lo = 1024;
        let hole_inode = fs
            .inode_cache
            .get_or_try_insert_with(3, || fs.new_inode_from_raw(3, hole_raw))
            .expect("trace hole inode");
        let writes_before_reject = device.writes.load(Ordering::Relaxed);
        let bytes_before_reject = device.bytes.lock().clone();
        assert_eq!(hole_inode.write_at(1023, b"XY"), Err(FsError::ReadOnly));
        assert_eq!(
            device.writes.load(Ordering::Relaxed),
            writes_before_reject,
            "plain-Ext2 rejection must occur before any device write"
        );
        assert_eq!(*device.bytes.lock(), bytes_before_reject);
        assert_eq!(hole_inode.raw.read().block, hole_raw.block);
        assert_eq!(hole_inode.raw.read().blocks_lo, hole_raw.blocks_lo);

        // An ambiguous inode-table-block write poisons the whole mount: regular
        // data and metadata entry points must not keep trusting neighbor inodes.
        fs.io_faulted.store(true, Ordering::Release);
        let inode_dyn: Arc<dyn Inode> = inode.clone();
        assert!(matches!(inode.stat(), Err(FsError::Io)));
        assert!(matches!(
            inode.clone().open(
                OpenFlags::new(OpenFlags::O_RDONLY),
                PreparedFileHandle::try_new().expect("poisoned-open descriptor preparation"),
            ),
            Err(FsError::Io)
        ));
        assert!(matches!(inode.readdir(0), Err(FsError::Io)));
        assert!(matches!(fs.lookup(&inode_dyn, "missing"), Err(FsError::Io)));
        assert!(matches!(inode.read_at(0, &mut [0u8; 1]), Err(FsError::Io)));
        assert!(matches!(inode.write_at(0, b"Z"), Err(FsError::Io)));
        fs.io_faulted.store(false, Ordering::Release);
    }

    run_ext2_journal_transaction_self_test();
}

/// Hosted/boot-time crash probes for R180-6's ordered-data JBD2 transaction.
#[doc(hidden)]
pub fn run_ext2_journal_transaction_self_test() {
    const BLOCK_SIZE: usize = 1024;
    const BLOCKS: usize = 32;
    const FILE_INO: u32 = 12;
    const JOURNAL_INO: u32 = 8;
    const JOURNAL_FIRST_PHYS: u32 = 8;
    const FIRST_FREE_BLOCK: u32 = 16;
    const MUTATION_OPS: u64 = 19;

    struct CrashState {
        live: Vec<u8>,
        durable: Vec<u8>,
    }

    struct CrashBlockDevice {
        state: Mutex<CrashState>,
        read_only: bool,
        operation: AtomicU64,
        fail_at: AtomicU64,
        persist_write_at: AtomicU64,
        error_after_write_at: AtomicU64,
        torn_write_at: AtomicU64,
        torn_write_len: AtomicU64,
        torn_observed_sector: AtomicU64,
        short_read_sector: AtomicU64,
        failed: AtomicBool,
    }

    impl CrashBlockDevice {
        fn new(image: Vec<u8>) -> Self {
            Self::with_read_only(image, false)
        }

        fn new_read_only(image: Vec<u8>) -> Self {
            Self::with_read_only(image, true)
        }

        fn with_read_only(image: Vec<u8>, read_only: bool) -> Self {
            Self {
                state: Mutex::new(CrashState {
                    live: image.clone(),
                    durable: image,
                }),
                read_only,
                operation: AtomicU64::new(0),
                fail_at: AtomicU64::new(0),
                persist_write_at: AtomicU64::new(0),
                error_after_write_at: AtomicU64::new(0),
                torn_write_at: AtomicU64::new(0),
                torn_write_len: AtomicU64::new(0),
                torn_observed_sector: AtomicU64::new(u64::MAX),
                short_read_sector: AtomicU64::new(u64::MAX),
                failed: AtomicBool::new(false),
            }
        }

        fn arm(&self, fail_at: u64, persist_write_at: u64) {
            self.operation.store(0, Ordering::Release);
            self.fail_at.store(fail_at, Ordering::Release);
            self.persist_write_at
                .store(persist_write_at, Ordering::Release);
            self.error_after_write_at.store(0, Ordering::Release);
            self.torn_write_at.store(0, Ordering::Release);
            self.torn_write_len.store(0, Ordering::Release);
            self.torn_observed_sector.store(u64::MAX, Ordering::Release);
            self.short_read_sector.store(u64::MAX, Ordering::Release);
            self.failed.store(false, Ordering::Release);
        }

        fn arm_write_then_error(&self, operation: u64, persist: bool) {
            self.operation.store(0, Ordering::Release);
            self.fail_at.store(0, Ordering::Release);
            self.persist_write_at
                .store(if persist { operation } else { 0 }, Ordering::Release);
            self.error_after_write_at
                .store(operation, Ordering::Release);
            self.torn_write_at.store(0, Ordering::Release);
            self.torn_write_len.store(0, Ordering::Release);
            self.torn_observed_sector.store(u64::MAX, Ordering::Release);
            self.failed.store(false, Ordering::Release);
        }

        fn arm_torn_write(&self, operation: u64, durable_prefix: usize) {
            assert!(operation != 0);
            assert!(durable_prefix < BLOCK_SIZE);
            self.operation.store(0, Ordering::Release);
            self.fail_at.store(0, Ordering::Release);
            self.persist_write_at.store(0, Ordering::Release);
            self.error_after_write_at.store(0, Ordering::Release);
            self.torn_write_at.store(operation, Ordering::Release);
            self.torn_write_len.store(
                u64::try_from(durable_prefix).expect("torn-write prefix fits u64"),
                Ordering::Release,
            );
            self.torn_observed_sector.store(u64::MAX, Ordering::Release);
            self.short_read_sector.store(u64::MAX, Ordering::Release);
            self.failed.store(false, Ordering::Release);
        }

        fn observed_torn_sector(&self) -> Option<u64> {
            match self.torn_observed_sector.load(Ordering::Acquire) {
                u64::MAX => None,
                sector => Some(sector),
            }
        }

        fn arm_short_read(&self, sector: u64) {
            self.short_read_sector.store(sector, Ordering::Release);
        }

        fn begin_mutation(&self) -> Result<u64, block::BlockError> {
            if self.failed.load(Ordering::Acquire) {
                return Err(block::BlockError::Io);
            }
            let operation = self
                .operation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| block::BlockError::Io)?
                + 1;
            let fail_at = self.fail_at.load(Ordering::Acquire);
            if fail_at != 0 && operation == fail_at {
                self.failed.store(true, Ordering::Release);
                return Err(block::BlockError::Io);
            }
            Ok(operation)
        }

        fn durable_snapshot(&self) -> Vec<u8> {
            self.state.lock().durable.clone()
        }
    }

    impl BlockDevice for CrashBlockDevice {
        fn name(&self) -> &str {
            "ext3-r180-6-crash"
        }

        fn sector_size(&self) -> u32 {
            512
        }

        fn capacity_sectors(&self) -> u64 {
            (self.state.lock().live.len() / 512) as u64
        }

        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn submit_bio(&self, _bio: block::Bio) -> Result<(), block::BlockError> {
            Err(block::BlockError::NotSupported)
        }

        fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, block::BlockError> {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(block::BlockError::Invalid)?;
            let end = start
                .checked_add(buf.len())
                .ok_or(block::BlockError::Invalid)?;
            let state = self.state.lock();
            buf.copy_from_slice(
                state
                    .live
                    .get(start..end)
                    .ok_or(block::BlockError::Invalid)?,
            );
            if sector == self.short_read_sector.load(Ordering::Acquire) {
                Ok(buf.len().saturating_sub(1))
            } else {
                Ok(buf.len())
            }
        }

        fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, block::BlockError> {
            if self.read_only {
                return Err(block::BlockError::ReadOnly);
            }
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(block::BlockError::Invalid)?;
            let end = start
                .checked_add(buf.len())
                .ok_or(block::BlockError::Invalid)?;
            let operation = self.begin_mutation()?;
            let mut state = self.state.lock();
            if operation == self.torn_write_at.load(Ordering::Acquire) {
                self.torn_observed_sector.store(sector, Ordering::Release);
                let prefix = usize::try_from(self.torn_write_len.load(Ordering::Acquire))
                    .map_err(|_| block::BlockError::Invalid)?;
                let live = state
                    .live
                    .get_mut(start..start + prefix)
                    .ok_or(block::BlockError::Invalid)?;
                live.copy_from_slice(buf.get(..prefix).ok_or(block::BlockError::Invalid)?);
                let durable = state
                    .durable
                    .get_mut(start..start + prefix)
                    .ok_or(block::BlockError::Invalid)?;
                durable.copy_from_slice(buf.get(..prefix).ok_or(block::BlockError::Invalid)?);
                self.failed.store(true, Ordering::Release);
                return Ok(prefix);
            }
            state
                .live
                .get_mut(start..end)
                .ok_or(block::BlockError::Invalid)?
                .copy_from_slice(buf);
            if operation == self.persist_write_at.load(Ordering::Acquire) {
                state
                    .durable
                    .get_mut(start..end)
                    .ok_or(block::BlockError::Invalid)?
                    .copy_from_slice(buf);
            }
            if operation == self.error_after_write_at.load(Ordering::Acquire) {
                self.failed.store(true, Ordering::Release);
                return Err(block::BlockError::Io);
            }
            Ok(buf.len())
        }

        fn flush(&self) -> Result<(), block::BlockError> {
            if self.read_only {
                return Err(block::BlockError::ReadOnly);
            }
            self.begin_mutation()?;
            let mut state = self.state.lock();
            let CrashState { live, durable } = &mut *state;
            durable.copy_from_slice(live);
            Ok(())
        }
    }

    struct SecondReadMutationDevice {
        inner: Arc<CrashBlockDevice>,
        target_sector: u64,
        target_reads: AtomicU64,
        enabled: AtomicBool,
        mutation_offset: usize,
        replacement: u32,
    }

    impl BlockDevice for SecondReadMutationDevice {
        fn name(&self) -> &str {
            "ext3-frozen-recovery-probe"
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn capacity_sectors(&self) -> u64 {
            self.inner.capacity_sectors()
        }

        fn is_read_only(&self) -> bool {
            self.inner.is_read_only()
        }

        fn submit_bio(&self, bio: block::Bio) -> Result<(), block::BlockError> {
            self.inner.submit_bio(bio)
        }

        fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, block::BlockError> {
            let read = self.inner.read_sync(sector, buf)?;
            if self.enabled.load(Ordering::Acquire)
                && sector == self.target_sector
                && buf.len() == BLOCK_SIZE
            {
                // lint-fetch-add: allow (bounded test-only fault-injection read counter)
                let prior = self.target_reads.fetch_add(1, Ordering::AcqRel);
                if prior != 0 {
                    let end = self
                        .mutation_offset
                        .checked_add(size_of::<u32>())
                        .ok_or(block::BlockError::Invalid)?;
                    buf.get_mut(self.mutation_offset..end)
                        .ok_or(block::BlockError::Invalid)?
                        .copy_from_slice(&self.replacement.to_le_bytes());
                }
            }
            Ok(read)
        }

        fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, block::BlockError> {
            self.inner.write_sync(sector, buf)
        }

        fn flush(&self) -> Result<(), block::BlockError> {
            self.inner.flush()
        }
    }

    struct JournalReadCountDevice {
        inner: Arc<CrashBlockDevice>,
        logical_reads: Mutex<[u64; 8]>,
    }

    impl JournalReadCountDevice {
        fn reads(&self) -> [u64; 8] {
            *self.logical_reads.lock()
        }
    }

    impl BlockDevice for JournalReadCountDevice {
        fn name(&self) -> &str {
            "ext3-private-journal-read-count"
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn capacity_sectors(&self) -> u64 {
            self.inner.capacity_sectors()
        }

        fn is_read_only(&self) -> bool {
            self.inner.is_read_only()
        }

        fn submit_bio(&self, bio: block::Bio) -> Result<(), block::BlockError> {
            self.inner.submit_bio(bio)
        }

        fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, block::BlockError> {
            let read = self.inner.read_sync(sector, buf)?;
            if buf.len() == BLOCK_SIZE {
                let byte_offset = sector.checked_mul(512).ok_or(block::BlockError::Invalid)?;
                if byte_offset % BLOCK_SIZE as u64 == 0 {
                    let physical = byte_offset / BLOCK_SIZE as u64;
                    let first = JOURNAL_FIRST_PHYS as u64;
                    if let Some(logical) = physical.checked_sub(first).filter(|value| *value < 8) {
                        let mut reads = self.logical_reads.lock();
                        let slot = reads
                            .get_mut(
                                usize::try_from(logical).map_err(|_| block::BlockError::Invalid)?,
                            )
                            .ok_or(block::BlockError::Invalid)?;
                        *slot = slot.checked_add(1).ok_or(block::BlockError::Io)?;
                    }
                }
            }
            Ok(read)
        }

        fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, block::BlockError> {
            self.inner.write_sync(sector, buf)
        }

        fn flush(&self) -> Result<(), block::BlockError> {
            self.inner.flush()
        }
    }

    fn copy_struct<T>(image: &mut [u8], offset: usize, value: &T) {
        let bytes =
            unsafe { core::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) };
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn read_struct<T: Copy>(image: &[u8], offset: usize) -> T {
        unsafe { core::ptr::read_unaligned(image[offset..].as_ptr() as *const T) }
    }

    fn journal_logical_offset(logical: u32) -> usize {
        assert!(logical < 8);
        usize::try_from(JOURNAL_FIRST_PHYS + logical)
            .expect("journal physical block fits usize")
            .checked_mul(BLOCK_SIZE)
            .expect("journal byte offset fits usize")
    }

    fn journal_sequence(image: &[u8]) -> u32 {
        read_be_u32(
            image,
            journal_logical_offset(0) + JBD2_SUPER_SEQUENCE_OFFSET,
        )
        .expect("journal sequence")
    }

    fn resign_private_transaction(image: &mut [u8], metadata_count: usize) {
        assert!(metadata_count == 1 || metadata_count == JOURNAL_MAX_METADATA_BLOCKS);
        let sequence = journal_sequence(image);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(
            &image[journal_logical_offset(0) + JBD2_SUPER_UUID_OFFSET
                ..journal_logical_offset(0) + JBD2_SUPER_UUID_OFFSET + 16],
        );

        let mut hasher = Sha256::new();
        hasher.update(ZERO_INTENT_HASH_DOMAIN);
        hasher.update(&uuid);
        hasher.update(&sequence.to_be_bytes());
        hasher.update(&image[journal_logical_offset(1)..journal_logical_offset(1) + BLOCK_SIZE]);
        for index in 0..metadata_count {
            let logical = u32::try_from(index + 2).expect("transaction logical block fits u32");
            let offset = journal_logical_offset(logical);
            hasher.update(&image[offset..offset + BLOCK_SIZE]);
        }

        let commit_logical =
            u32::try_from(metadata_count + 2).expect("commit logical block fits u32");
        let commit_offset = journal_logical_offset(commit_logical);
        hasher.update(&image[commit_offset..commit_offset + ZERO_INTENT_DIGEST_OFFSET]);
        hasher.update(&[0u8; 32]);
        hasher.update(&image[commit_offset + ZERO_INTENT_END..commit_offset + BLOCK_SIZE]);
        let digest = hasher.finalize();
        image[commit_offset + ZERO_INTENT_DIGEST_OFFSET..commit_offset + ZERO_INTENT_END]
            .copy_from_slice(&digest);
    }

    fn resequence_private_transaction(image: &mut [u8], metadata_count: usize, sequence: u32) {
        assert!(metadata_count == 1 || metadata_count == JOURNAL_MAX_METADATA_BLOCKS);
        write_be_u32(
            image,
            journal_logical_offset(0) + JBD2_SUPER_SEQUENCE_OFFSET,
            sequence,
        )
        .expect("journal superblock sequence");
        write_be_u32(image, journal_logical_offset(1) + 8, sequence)
            .expect("journal descriptor sequence");
        let commit_logical =
            u32::try_from(metadata_count + 2).expect("commit logical block fits u32");
        write_be_u32(image, journal_logical_offset(commit_logical) + 8, sequence)
            .expect("journal commit sequence");
        resign_private_transaction(image, metadata_count);
    }

    fn relocate_private_transaction(
        image: &mut [u8],
        metadata_count: usize,
        start: u32,
        wrap: bool,
    ) {
        assert!(metadata_count == 1 || metadata_count == JOURNAL_MAX_METADATA_BLOCKS);
        assert!((1..8).contains(&start));
        let transaction_blocks = metadata_count + 2;
        let source_start = journal_logical_offset(1);
        let source_end = source_start + transaction_blocks * BLOCK_SIZE;
        // lint-fallible: BOUNDED(journal self-test scaffold; transaction_blocks <= JOURNAL_MAX_METADATA_BLOCKS+2, fixed)
        let source = image[source_start..source_end].to_vec();
        image[journal_logical_offset(1)..journal_logical_offset(0) + 8 * BLOCK_SIZE].fill(0);
        for index in 0..transaction_blocks {
            let index = u32::try_from(index).expect("transaction index fits u32");
            let logical = if wrap {
                1 + (start - 1 + index) % 7
            } else {
                start.checked_add(index).expect("relocated logical block")
            };
            assert!(logical < 8);
            let destination = journal_logical_offset(logical);
            let source_offset =
                usize::try_from(index).expect("transaction source index") * BLOCK_SIZE;
            image[destination..destination + BLOCK_SIZE]
                .copy_from_slice(&source[source_offset..source_offset + BLOCK_SIZE]);
        }
        write_be_u32(
            image,
            journal_logical_offset(0) + JBD2_SUPER_START_OFFSET,
            start,
        )
        .expect("relocated journal start");
    }

    fn mark_block_allocated(image: &mut [u8], block: u32) {
        let bit = block.checked_sub(1).expect("group-zero filesystem block");
        assert_eq!(
            image[3 * BLOCK_SIZE + (bit / 8) as usize] & (1u8 << (bit % 8)),
            0,
            "synthetic block must start free"
        );
        image[3 * BLOCK_SIZE + (bit / 8) as usize] |= 1u8 << (bit % 8);
        let mut superblock: Ext2Superblock = read_struct(image, SUPERBLOCK_OFFSET as usize);
        superblock.free_blocks_count -= 1;
        copy_struct(image, SUPERBLOCK_OFFSET as usize, &superblock);
        let mut desc: Ext2GroupDesc = read_struct(image, 2 * BLOCK_SIZE);
        desc.free_blocks_count -= 1;
        copy_struct(image, 2 * BLOCK_SIZE, &desc);
    }

    fn bitmap_allocated(image: &[u8], block: u32) -> bool {
        let bit = block.checked_sub(1).expect("group-zero filesystem block");
        image[3 * BLOCK_SIZE + (bit / 8) as usize] & (1u8 << (bit % 8)) != 0
    }

    fn bitmap_block_allocated(bitmap: &[u8], block: u32) -> bool {
        let bit = block.checked_sub(1).expect("group-zero filesystem block");
        bitmap[(bit / 8) as usize] & (1u8 << (bit % 8)) != 0
    }

    fn journal_start(image: &[u8]) -> u32 {
        read_be_u32(
            image,
            JOURNAL_FIRST_PHYS as usize * BLOCK_SIZE + JBD2_SUPER_START_OFFSET,
        )
        .expect("journal start")
    }

    fn synthetic_image() -> Vec<u8> {
        let mut image = Vec::new();
        image
            .try_reserve_exact(BLOCKS * BLOCK_SIZE)
            .expect("R180-6 synthetic image");
        image.resize(BLOCKS * BLOCK_SIZE, 0);

        let uuid = [0x5Au8; 16];
        let mut superblock: Ext2Superblock = unsafe { core::mem::zeroed() };
        superblock.inodes_count = 16;
        superblock.blocks_count = BLOCKS as u32;
        superblock.free_blocks_count = 16;
        superblock.free_inodes_count = 5;
        superblock.first_data_block = 1;
        superblock.blocks_per_group = BLOCKS as u32;
        superblock.frags_per_group = BLOCKS as u32;
        superblock.inodes_per_group = 16;
        superblock.magic = EXT2_SUPER_MAGIC;
        superblock.state = 1;
        superblock.rev_level = 1;
        superblock.first_ino = 11;
        superblock.inode_size = size_of::<Ext2InodeRaw>() as u16;
        superblock.feature_compat = EXT3_FEATURE_COMPAT_HAS_JOURNAL;
        superblock.feature_incompat = EXT2_FEATURE_INCOMPAT_FILETYPE;
        superblock.feature_ro_compat = EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER;
        superblock.uuid = [0xA5; 16];
        superblock.journal_uuid = uuid;
        superblock.journal_inum = JOURNAL_INO;
        copy_struct(&mut image, SUPERBLOCK_OFFSET as usize, &superblock);

        let group_desc = Ext2GroupDesc {
            block_bitmap: 3,
            inode_bitmap: 4,
            inode_table: 5,
            free_blocks_count: 16,
            free_inodes_count: 5,
            used_dirs_count: 1,
            ..Ext2GroupDesc::default()
        };
        copy_struct(&mut image, 2 * BLOCK_SIZE, &group_desc);

        for block in 1..FIRST_FREE_BLOCK {
            let bit = block - 1;
            image[3 * BLOCK_SIZE + (bit / 8) as usize] |= 1u8 << (bit % 8);
        }
        for ino in (1..=10).chain(core::iter::once(FILE_INO)) {
            let bit = ino - 1;
            image[4 * BLOCK_SIZE + (bit / 8) as usize] |= 1u8 << (bit % 8);
        }

        let mut root = Ext2InodeRaw::default();
        root.mode = EXT2_S_IFDIR | 0o755;
        root.size_lo = BLOCK_SIZE as u32;
        root.links_count = 2;
        root.blocks_lo = 2;
        root.block[0] = 7;
        copy_struct(
            &mut image,
            5 * BLOCK_SIZE + size_of::<Ext2InodeRaw>(),
            &root,
        );

        let mut file = Ext2InodeRaw::default();
        file.mode = EXT2_S_IFREG | 0o644;
        file.links_count = 1;
        copy_struct(
            &mut image,
            5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>(),
            &file,
        );

        let mut journal_inode = Ext2InodeRaw::default();
        journal_inode.mode = EXT2_S_IFREG | 0o600;
        journal_inode.size_lo = (8 * BLOCK_SIZE) as u32;
        journal_inode.blocks_lo = 16;
        for logical in 0..8usize {
            journal_inode.block[logical] = JOURNAL_FIRST_PHYS + logical as u32;
        }
        copy_struct(
            &mut image,
            5 * BLOCK_SIZE + (JOURNAL_INO as usize - 1) * size_of::<Ext2InodeRaw>(),
            &journal_inode,
        );

        let journal_super = &mut image[JOURNAL_FIRST_PHYS as usize * BLOCK_SIZE
            ..(JOURNAL_FIRST_PHYS as usize + 1) * BLOCK_SIZE];
        write_be_u32(journal_super, 0, JBD2_MAGIC).expect("journal magic");
        write_be_u32(journal_super, 4, JBD2_SUPERBLOCK_V2).expect("journal type");
        write_be_u32(
            journal_super,
            JBD2_SUPER_BLOCKSIZE_OFFSET,
            BLOCK_SIZE as u32,
        )
        .expect("journal block size");
        write_be_u32(journal_super, JBD2_SUPER_MAXLEN_OFFSET, 8).expect("journal maxlen");
        write_be_u32(journal_super, JBD2_SUPER_FIRST_OFFSET, 1).expect("journal first");
        write_be_u32(journal_super, JBD2_SUPER_SEQUENCE_OFFSET, 1).expect("journal sequence");
        write_be_u32(journal_super, JBD2_SUPER_START_OFFSET, 0).expect("journal start");
        write_be_u32(
            journal_super,
            JBD2_SUPER_FEATURE_INCOMPAT_OFFSET,
            JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_ZERO_INTENT,
        )
        .expect("journal features");
        journal_super[JBD2_SUPER_UUID_OFFSET..JBD2_SUPER_UUID_OFFSET + 16].copy_from_slice(&uuid);
        write_be_u32(journal_super, JBD2_SUPER_NR_USERS_OFFSET, 1).expect("journal users");

        image
    }

    fn mount_image(image: Vec<u8>) -> (Arc<CrashBlockDevice>, Arc<Ext2Fs>, Arc<Ext2Inode>) {
        let device = Arc::try_new(CrashBlockDevice::new(image)).expect("crash block device");
        let (fs, file) = mount_device(&device).expect("mount synthetic Ext3 image");
        (device, fs, file)
    }

    fn mount_device(
        device: &Arc<CrashBlockDevice>,
    ) -> Result<(Arc<Ext2Fs>, Arc<Ext2Inode>), FsError> {
        let dev: Arc<dyn BlockDevice> = device.clone();
        let fs = Ext2Fs::mount(dev)?;
        let file = fs.load_inode(FILE_INO)?;
        Ok((fs, file))
    }

    // RF180-35 FIX: the boot oracle executes many independent 64 KiB crash
    // scenarios inside the 1 MiB kernel heap. Each scenario explicitly drops
    // its device image and filesystem/inode Arcs at its last assertion so the
    // test measures production allocation behavior instead of accumulating an
    // impossible whole-suite co-residency peak.

    fn assert_recovered_state(
        fs: &Arc<Ext2Fs>,
        file: &Arc<Ext2Inode>,
        payload: &[u8],
        allocated_blocks: usize,
    ) {
        assert_recovered_state_with_tail(fs, file, payload, allocated_blocks, true);
    }

    fn assert_recovered_state_with_tail(
        fs: &Arc<Ext2Fs>,
        file: &Arc<Ext2Inode>,
        payload: &[u8],
        allocated_blocks: usize,
        require_zero_tail: bool,
    ) {
        let raw = *file.raw.read();
        assert_eq!(raw.size_lo as usize, payload.len());
        assert_eq!(raw.size_high_or_dir_acl, 0);
        assert_eq!(file.size.load(Ordering::Acquire) as usize, payload.len());
        assert_eq!(raw.blocks_lo as usize, allocated_blocks * 2);
        for index in 0..EXT2_NDIR_BLOCKS {
            let expected = if index < allocated_blocks {
                FIRST_FREE_BLOCK + index as u32
            } else {
                0
            };
            assert_eq!(raw.block[index], expected);
        }
        assert_eq!(
            fs.superblock.read().free_blocks_count,
            16 - allocated_blocks as u32
        );
        assert_ne!(
            fs.superblock.read().feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER,
            0
        );
        assert_eq!(
            fs.group_descs.read()[0].free_blocks_count,
            16 - allocated_blocks as u16
        );
        assert_eq!(fs.journal.lock().as_ref().expect("journal").start, 0);

        let mut metadata =
            Ext2MutationScratch::try_new(BLOCK_SIZE as u32).expect("metadata verification scratch");
        fs.read_physical_block(3, metadata.block_mut())
            .expect("read recovered block bitmap");
        for index in 0..2usize {
            assert_eq!(
                bitmap_block_allocated(metadata.block(), FIRST_FREE_BLOCK + index as u32),
                index < allocated_blocks
            );
        }
        fs.read_physical_block(JOURNAL_FIRST_PHYS, metadata.block_mut())
            .expect("read recovered journal superblock");
        assert_eq!(
            read_be_u32(metadata.block(), JBD2_SUPER_START_OFFSET).expect("journal start"),
            0
        );

        for block_index in 0..allocated_blocks {
            let mut block =
                Ext2MutationScratch::try_new(BLOCK_SIZE as u32).expect("verification scratch");
            fs.read_block(FIRST_FREE_BLOCK + block_index as u32, block.block_mut())
                .expect("read allocated data block");
            let start = block_index * BLOCK_SIZE;
            let end = cmp::min(start + BLOCK_SIZE, payload.len());
            assert_eq!(&block.block()[..end - start], &payload[start..end]);
            if require_zero_tail {
                assert!(block.block()[end - start..].iter().all(|byte| *byte == 0));
            }
        }
    }

    fn assert_unallocated(fs: &Arc<Ext2Fs>, file: &Arc<Ext2Inode>) {
        assert_recovered_state(fs, file, &[], 0);
    }

    fn assert_retry_then_clean_mount(
        image: Vec<u8>,
        payload: &[u8],
        allocated_blocks: usize,
        require_zero_tail: bool,
    ) {
        let (retry_device, retry_fs, retry_file) = mount_image(image);
        assert_recovered_state_with_tail(
            &retry_fs,
            &retry_file,
            payload,
            allocated_blocks,
            require_zero_tail,
        );
        let converged = retry_device.durable_snapshot();
        assert_eq!(journal_start(&converged), 0);
        drop(retry_file);
        drop(retry_fs);
        drop(retry_device);

        let (clean_device, clean_fs, clean_file) = mount_image(converged.clone());
        assert_recovered_state_with_tail(
            &clean_fs,
            &clean_file,
            payload,
            allocated_blocks,
            require_zero_tail,
        );
        assert_eq!(
            clean_device.operation.load(Ordering::Acquire),
            0,
            "a third mount of the converged image must not write"
        );
        assert_eq!(clean_device.durable_snapshot(), converged);
    }

    let base = synthetic_image();
    for group in [0, 1, 3, 5, 7, 9, 25, 27, 49] {
        assert!(Ext2Fs::group_has_superblock(group, true));
    }
    for group in [2, 4, 6, 8, 10, 11, 13, 17] {
        assert!(!Ext2Fs::group_has_superblock(group, true));
    }
    assert!(Ext2Fs::group_has_superblock(65_535, false));

    // RF180-49: stock e2fsprogs internal journals leave s_journal_uuid zero
    // and copy the filesystem UUID into the JBD2 superblock.  Mount must bind
    // that form before upgrading the clean legacy journal to the private
    // intent grammar and marking the filesystem as recovery-aware.
    let mut standard_internal = base.clone();
    let mut standard_super: Ext2Superblock =
        read_struct(&standard_internal, SUPERBLOCK_OFFSET as usize);
    standard_super.journal_uuid = [0; 16];
    let standard_uuid = standard_super.uuid;
    copy_struct(
        &mut standard_internal,
        SUPERBLOCK_OFFSET as usize,
        &standard_super,
    );
    let journal_super_offset = JOURNAL_FIRST_PHYS as usize * BLOCK_SIZE;
    standard_internal[journal_super_offset + JBD2_SUPER_UUID_OFFSET
        ..journal_super_offset + JBD2_SUPER_UUID_OFFSET + 16]
        .copy_from_slice(&standard_uuid);
    write_be_u32(
        &mut standard_internal,
        journal_super_offset + JBD2_SUPER_FEATURE_INCOMPAT_OFFSET,
        JBD2_FEATURE_INCOMPAT_REVOKE,
    )
    .expect("standard internal journal feature field");
    let standard_device = Arc::try_new(CrashBlockDevice::new(standard_internal))
        .expect("standard internal journal device");
    let dev: Arc<dyn BlockDevice> = standard_device.clone();
    let standard_fs = Ext2Fs::mount(dev).expect("mount standard internal journal identity");
    let standard_durable = standard_device.durable_snapshot();
    let durable_super: Ext2Superblock = read_struct(&standard_durable, SUPERBLOCK_OFFSET as usize);
    assert_eq!(durable_super.journal_uuid, [0; 16]);
    assert_ne!(
        durable_super.feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER,
        0
    );
    assert_eq!(
        read_be_u32(
            &standard_durable[journal_super_offset..journal_super_offset + BLOCK_SIZE],
            JBD2_SUPER_FEATURE_INCOMPAT_OFFSET,
        )
        .expect("upgraded standard journal feature"),
        JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_ZERO_INTENT
    );
    drop(standard_fs);
    drop(standard_durable);
    drop(standard_device);

    // A cleared explicit field is not permission to accept an unrelated or
    // absent journal identity.  All rejection variants must occur pre-write.
    let mut fallback_mismatch = base.clone();
    let mut mismatch_super: Ext2Superblock =
        read_struct(&fallback_mismatch, SUPERBLOCK_OFFSET as usize);
    mismatch_super.journal_uuid = [0; 16];
    copy_struct(
        &mut fallback_mismatch,
        SUPERBLOCK_OFFSET as usize,
        &mismatch_super,
    );
    let mismatch_device = Arc::try_new(CrashBlockDevice::new(fallback_mismatch))
        .expect("fallback UUID mismatch device");
    let dev: Arc<dyn BlockDevice> = mismatch_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(mismatch_device.operation.load(Ordering::Acquire), 0);
    drop(mismatch_device);

    let mut zero_identity = base.clone();
    let mut zero_super: Ext2Superblock = read_struct(&zero_identity, SUPERBLOCK_OFFSET as usize);
    zero_super.uuid = [0; 16];
    zero_super.journal_uuid = [0; 16];
    copy_struct(&mut zero_identity, SUPERBLOCK_OFFSET as usize, &zero_super);
    zero_identity[journal_super_offset + JBD2_SUPER_UUID_OFFSET
        ..journal_super_offset + JBD2_SUPER_UUID_OFFSET + 16]
        .fill(0);
    let zero_device =
        Arc::try_new(CrashBlockDevice::new(zero_identity)).expect("zero journal identity device");
    let dev: Arc<dyn BlockDevice> = zero_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(zero_device.operation.load(Ordering::Acquire), 0);
    drop(zero_device);

    let mut zero_jbd_uuid = base.clone();
    zero_jbd_uuid[journal_super_offset + JBD2_SUPER_UUID_OFFSET
        ..journal_super_offset + JBD2_SUPER_UUID_OFFSET + 16]
        .fill(0);
    let zero_jbd_device =
        Arc::try_new(CrashBlockDevice::new(zero_jbd_uuid)).expect("zero JBD2 UUID device");
    let dev: Arc<dyn BlockDevice> = zero_jbd_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(zero_jbd_device.operation.load(Ordering::Acquire), 0);
    drop(zero_jbd_device);

    let mut explicit_mismatch = base.clone();
    explicit_mismatch[journal_super_offset + JBD2_SUPER_UUID_OFFSET
        ..journal_super_offset + JBD2_SUPER_UUID_OFFSET + 16]
        .fill(0xC3);
    let explicit_device = Arc::try_new(CrashBlockDevice::new(explicit_mismatch))
        .expect("explicit UUID mismatch device");
    let dev: Arc<dyn BlockDevice> = explicit_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(explicit_device.operation.load(Ordering::Acquire), 0);
    drop(explicit_device);

    // RF180-13: plain Ext2 cannot make data+inode persistence atomic.  A
    // writable device therefore fails at mount, while an explicitly read-only
    // export remains inspectable and rejects mutation before device I/O.
    let mut plain = base.clone();
    let mut plain_super: Ext2Superblock = read_struct(&plain, SUPERBLOCK_OFFSET as usize);
    plain_super.feature_compat &= !EXT3_FEATURE_COMPAT_HAS_JOURNAL;
    plain_super.feature_incompat &= !EXT3_FEATURE_INCOMPAT_RECOVER;
    plain_super.journal_uuid = [0; 16];
    plain_super.journal_inum = 0;
    // R186-7 REGRESSION: clearing HAS_JOURNAL alone does not produce a valid
    // plain ext2 image.  The synthetic journal inode has zero links and still
    // owns blocks 8 through 15, so the complete ownership scan correctly rejects it.
    // Model journal removal fully: retain inode 8's reserved bitmap bit, clear
    // its inode contents, release its data blocks, and reconcile both free-block
    // counters.  Free-block contents need not be erased by ext2.
    const SYNTHETIC_JOURNAL_BLOCKS: u32 = 8;
    let journal_inode_offset =
        5 * BLOCK_SIZE + (JOURNAL_INO as usize - 1) * size_of::<Ext2InodeRaw>();
    copy_struct(&mut plain, journal_inode_offset, &Ext2InodeRaw::default());
    for block in JOURNAL_FIRST_PHYS..JOURNAL_FIRST_PHYS + SYNTHETIC_JOURNAL_BLOCKS {
        let bit = block - 1;
        plain[3 * BLOCK_SIZE + (bit / 8) as usize] &= !(1u8 << (bit % 8));
    }
    plain_super.free_blocks_count = plain_super
        .free_blocks_count
        .checked_add(SYNTHETIC_JOURNAL_BLOCKS)
        .expect("plain ext2 free-block count");
    copy_struct(&mut plain, SUPERBLOCK_OFFSET as usize, &plain_super);
    let mut plain_desc: Ext2GroupDesc = read_struct(&plain, 2 * BLOCK_SIZE);
    plain_desc.free_blocks_count = plain_desc
        .free_blocks_count
        .checked_add(SYNTHETIC_JOURNAL_BLOCKS as u16)
        .expect("plain ext2 group free-block count");
    copy_struct(&mut plain, 2 * BLOCK_SIZE, &plain_desc);
    let writable_plain =
        Arc::try_new(CrashBlockDevice::new(plain.clone())).expect("writable plain Ext2 device");
    let dev: Arc<dyn BlockDevice> = writable_plain;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));

    let read_only_plain = Arc::try_new(CrashBlockDevice::new_read_only(plain.clone()))
        .expect("read-only plain Ext2 device");
    let before = read_only_plain.durable_snapshot();
    let dev: Arc<dyn BlockDevice> = read_only_plain.clone();
    let read_only_fs = Ext2Fs::mount(dev).expect("mount read-only plain Ext2");
    let read_only_file = read_only_fs
        .load_inode(FILE_INO)
        .expect("load read-only plain Ext2 file");
    assert_eq!(read_only_file.write_at(0, b"X"), Err(FsError::ReadOnly));
    assert_eq!(read_only_plain.operation.load(Ordering::Acquire), 0);
    assert_eq!(read_only_plain.durable_snapshot(), before);
    drop(read_only_file);
    drop(read_only_fs);
    drop(read_only_plain);
    drop(before);

    // R186-7: plain read-only ext2 is not exempt from ownership validation.
    // Make the ordinary file alias the root directory's allocated data block;
    // the mount must reject the duplicate owner before exposing either inode.
    let file_offset = 5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>();
    let mut aliased_file: Ext2InodeRaw = read_struct(&plain, file_offset);
    aliased_file.size_lo = 1;
    aliased_file.blocks_lo = (BLOCK_SIZE / 512) as u32;
    aliased_file.block[0] = 7;
    copy_struct(&mut plain, file_offset, &aliased_file);
    let aliased_plain = Arc::try_new(CrashBlockDevice::new_read_only(plain))
        .expect("aliased read-only plain Ext2 device");
    let dev: Arc<dyn BlockDevice> = aliased_plain.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(aliased_plain.operation.load(Ordering::Acquire), 0);
    drop(aliased_plain);

    // A clean journal does not make ordinary inode mappings trustworthy.  A
    // free, structural, or journal-owned target must fail the full ownership
    // scan before mounting marks RECOVER on this initially clean image.
    for physical in [FIRST_FREE_BLOCK, 3, JOURNAL_FIRST_PHYS] {
        let mut hostile = base.clone();
        let file_offset = 5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>();
        let mut hostile_file: Ext2InodeRaw = read_struct(&hostile, file_offset);
        hostile_file.size_lo = 1;
        hostile_file.blocks_lo = (BLOCK_SIZE / 512) as u32;
        hostile_file.block[0] = physical;
        copy_struct(&mut hostile, file_offset, &hostile_file);
        let device = Arc::try_new(CrashBlockDevice::new(hostile.clone()))
            .expect("hostile clean-mount ownership device");
        let dev: Arc<dyn BlockDevice> = device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
        assert_eq!(device.operation.load(Ordering::Acquire), 0);
        assert_eq!(device.durable_snapshot(), hostile);
    }

    // An allocated bitmap bit with no graph owner is equally invalid: free
    // counters alone cannot justify handing the block to no inode at all.
    let mut unowned_bitmap = base.clone();
    mark_block_allocated(&mut unowned_bitmap, FIRST_FREE_BLOCK);
    let unowned_device =
        Arc::try_new(CrashBlockDevice::new(unowned_bitmap.clone())).expect("unowned bitmap device");
    let dev: Arc<dyn BlockDevice> = unowned_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(unowned_device.operation.load(Ordering::Acquire), 0);
    assert_eq!(unowned_device.durable_snapshot(), unowned_bitmap);
    drop(unowned_device);
    drop(unowned_bitmap);

    // Device-special inode block words encode a device number, not filesystem
    // ownership.  The complete scan must accept the word even when it equals a
    // structural block and leave the existing structural owner unique.
    let mut special_file = base.clone();
    let file_offset = 5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>();
    let mut special: Ext2InodeRaw = read_struct(&special_file, file_offset);
    special.mode = 0x2000 | 0o600;
    special.block[0] = 3;
    copy_struct(&mut special_file, file_offset, &special);
    let special_device =
        Arc::try_new(CrashBlockDevice::new(special_file)).expect("special-file ownership device");
    mount_device(&special_device).expect("mount special-file ownership image");
    assert_eq!(special_device.operation.load(Ordering::Acquire), 2);
    drop(special_device);

    // Ordinary single-indirect provenance covers the mapping node and every
    // child.  A fully allocated tree mounts; structural, journal, and free
    // children all fail before RECOVER is written.
    let mut valid_indirect = base.clone();
    mark_block_allocated(&mut valid_indirect, FIRST_FREE_BLOCK);
    mark_block_allocated(&mut valid_indirect, FIRST_FREE_BLOCK + 1);
    valid_indirect
        [FIRST_FREE_BLOCK as usize * BLOCK_SIZE..FIRST_FREE_BLOCK as usize * BLOCK_SIZE + 4]
        .copy_from_slice(&(FIRST_FREE_BLOCK + 1).to_le_bytes());
    let mut indirect_file: Ext2InodeRaw = read_struct(&valid_indirect, file_offset);
    indirect_file.size_lo = (13 * BLOCK_SIZE) as u32;
    indirect_file.blocks_lo = (2 * BLOCK_SIZE / 512) as u32;
    indirect_file.block[EXT2_IND_BLOCK] = FIRST_FREE_BLOCK;
    copy_struct(&mut valid_indirect, file_offset, &indirect_file);
    let valid_indirect_device = Arc::try_new(CrashBlockDevice::new(valid_indirect))
        .expect("valid ordinary indirect device");
    let (valid_indirect_fs, _) =
        mount_device(&valid_indirect_device).expect("mount valid ordinary indirect image");
    let mut indirect_scratch =
        Ext2MutationScratch::try_new(BLOCK_SIZE as u32).expect("ordinary indirect scratch");
    assert_eq!(
        valid_indirect_fs.map_file_block_with_scratch(
            &indirect_file,
            EXT2_NDIR_BLOCKS as u32,
            &mut indirect_scratch,
        ),
        Ok(Some(FIRST_FREE_BLOCK + 1))
    );
    assert_eq!(valid_indirect_device.operation.load(Ordering::Acquire), 2);
    drop(indirect_scratch);
    drop(valid_indirect_fs);
    drop(valid_indirect_device);

    for child in [3, JOURNAL_FIRST_PHYS, FIRST_FREE_BLOCK + 1] {
        let mut hostile_indirect = base.clone();
        mark_block_allocated(&mut hostile_indirect, FIRST_FREE_BLOCK);
        hostile_indirect
            [FIRST_FREE_BLOCK as usize * BLOCK_SIZE..FIRST_FREE_BLOCK as usize * BLOCK_SIZE + 4]
            .copy_from_slice(&child.to_le_bytes());
        let mut raw: Ext2InodeRaw = read_struct(&hostile_indirect, file_offset);
        raw.size_lo = (13 * BLOCK_SIZE) as u32;
        raw.blocks_lo = (2 * BLOCK_SIZE / 512) as u32;
        raw.block[EXT2_IND_BLOCK] = FIRST_FREE_BLOCK;
        copy_struct(&mut hostile_indirect, file_offset, &raw);
        let device = Arc::try_new(CrashBlockDevice::new(hostile_indirect.clone()))
            .expect("hostile ordinary indirect device");
        let dev: Arc<dyn BlockDevice> = device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
        assert_eq!(device.operation.load(Ordering::Acquire), 0);
        assert_eq!(device.durable_snapshot(), hostile_indirect);
    }

    // Exercise double-indirect journal mapping ownership without constructing
    // a hundreds-of-block journal: both mapping levels must be retained as
    // journal-owned metadata, and a structural root must fail immediately.
    let (mapping_device, mapping_fs, _mapping_file) = mount_image(base.clone());
    {
        let mut state = mapping_device.state.lock();
        state.live[17 * BLOCK_SIZE..17 * BLOCK_SIZE + 4].copy_from_slice(&18u32.to_le_bytes());
        state.live[18 * BLOCK_SIZE..18 * BLOCK_SIZE + 4].copy_from_slice(&19u32.to_le_bytes());
    }
    let mut mapping_inode = Ext2InodeRaw::default();
    mapping_inode.block[EXT2_DIND_BLOCK] = 17;
    let mut mapping_scratch =
        Ext2MutationScratch::try_new(BLOCK_SIZE as u32).expect("journal mapping scratch");
    let mut mapping_blocks = Vec::new();
    mapping_blocks
        .try_reserve_exact(2)
        .expect("double-indirect ownership vector");
    assert_eq!(
        mapping_fs.map_journal_file_block(
            &mapping_inode,
            EXT2_NDIR_BLOCKS as u32 + (BLOCK_SIZE / 4) as u32,
            &mut mapping_scratch,
            &mut mapping_blocks,
        ),
        Ok(19)
    );
    assert_eq!(mapping_blocks, [17, 18]);
    mapping_inode.block[EXT2_DIND_BLOCK] = 3;
    mapping_blocks.clear();
    assert_eq!(
        mapping_fs.map_journal_file_block(
            &mapping_inode,
            EXT2_NDIR_BLOCKS as u32 + (BLOCK_SIZE / 4) as u32,
            &mut mapping_scratch,
            &mut mapping_blocks,
        ),
        Err(FsError::Invalid)
    );
    let journal_guard = mapping_fs.journal.lock();
    let journal = journal_guard.as_ref().expect("mapping test journal");
    let mut recovery_scratch =
        JournalRecoveryScratch::try_new(BLOCK_SIZE as u32).expect("mapping recovery scratch");
    let mut recovery_references = Vec::new();
    let mut recovery_mapping_blocks = Vec::new();
    let mut exhausted_scan = MAX_RECOVERY_MAPPING_SCAN_BYTES;
    assert!(matches!(
        mapping_fs.collect_recovery_mapping_tree(
            journal,
            &[],
            &[],
            17,
            1,
            &mut exhausted_scan,
            &mut recovery_references,
            &mut recovery_mapping_blocks,
            &mut recovery_scratch,
        ),
        Err(FsError::NotSupported)
    ));
    drop(journal_guard);
    drop(recovery_mapping_blocks);
    drop(recovery_references);
    drop(recovery_scratch);
    drop(mapping_blocks);
    drop(mapping_scratch);
    drop(_mapping_file);
    drop(mapping_fs);
    drop(mapping_device);

    // A clean allocation establishes the exact fixed operation sequence used
    // by the exhaustive crash-boundary loop below.
    let (device, fs, file) = mount_image(base.clone());
    device.arm(0, 0);
    let payload = b"ordered-data";
    assert_eq!(file.write_at(0, payload), Ok(payload.len()));
    assert_eq!(device.operation.load(Ordering::Acquire), MUTATION_OPS);
    assert_recovered_state(&fs, &file, payload, 1);
    assert_eq!(journal_start(&device.durable_snapshot()), 0);
    let allocated_base = device.durable_snapshot();
    drop(file);
    drop(fs);
    drop(device);

    // A huge logical gap with absent indirect roots retains only its one
    // mapped direct target.  The explicit caps apply to actual retained nodes
    // and targets, and reject the next retention once the cap is full.
    let (budget_device, budget_fs, budget_file) = mount_image(allocated_base.clone());
    budget_device.arm(0, 0);
    let budget_raw = *budget_file.raw.read();
    let ptrs = (BLOCK_SIZE / 4) as u64;
    let supported_blocks = EXT2_NDIR_BLOCKS as u64 + ptrs + ptrs * ptrs;
    let journal_guard = budget_fs.journal.lock();
    let journal = journal_guard.as_ref().expect("sparse budget journal");
    let mut sparse_mapping_scratch =
        Ext2MutationScratch::try_new_admitted(BLOCK_SIZE as u32).expect("sparse mapping scratch");
    let sparse_targets = budget_fs
        .preflight_sparse_gap(
            &budget_raw,
            payload.len() as u64,
            supported_blocks * BLOCK_SIZE as u64,
            journal,
            &mut sparse_mapping_scratch,
        )
        .expect("actual-target sparse preflight");
    assert_eq!(sparse_targets.targets.len(), 1);
    assert_eq!(sparse_targets.targets[0], FIRST_FREE_BLOCK);
    assert_eq!(
        sparse_targets.boundaries[0],
        Some(SparseGapTarget {
            physical: FIRST_FREE_BLOCK,
            start: payload.len() as u32,
            end: BLOCK_SIZE as u32,
        })
    );
    assert_eq!(sparse_targets.boundaries[1], None);
    drop(sparse_targets);

    // RF180-34: exercise both retained-plan boundaries without constructing
    // cap-sized vectors in the 2 MiB boot heap.  The charge helper is pure and
    // also proves the maximum block-size transaction fits its dedicated class.
    let mut saturated = SparseGapCounts {
        mapping_nodes: MAX_SPARSE_GAP_MAPPING_NODES,
        branch_nodes: MAX_SPARSE_GAP_MAPPING_NODES,
        data_targets: MAX_SPARSE_GAP_DATA_BLOCKS,
        boundary_targets: 2,
    };
    assert_eq!(saturated.account_mapping_node(None), Err(FsError::NoMem));
    assert_eq!(
        saturated.account_data_target(
            SparseGapTarget {
                physical: FIRST_FREE_BLOCK,
                start: 0,
                end: BLOCK_SIZE as u32,
            },
            BLOCK_SIZE as u32,
        ),
        Err(FsError::NoMem)
    );
    assert!(matches!(
        sparse_gap_plan_charge_bytes(SparseGapCounts {
            mapping_nodes: MAX_SPARSE_GAP_MAPPING_NODES + 1,
            branch_nodes: 0,
            data_targets: 0,
            boundary_targets: 0,
        }),
        Err(FsError::NoMem)
    ));
    assert!(matches!(
        sparse_gap_plan_charge_bytes(SparseGapCounts {
            mapping_nodes: 0,
            branch_nodes: 0,
            data_targets: MAX_SPARSE_GAP_DATA_BLOCKS + 1,
            boundary_targets: 0,
        }),
        Err(FsError::NoMem)
    ));
    let maximum_sparse_charge =
        sparse_gap_max_live_charge_bytes(65_536).expect("maximum sparse-gap live charge");
    assert_eq!(
        HeapClass::FilesystemIo.limit_bytes() - maximum_sparse_charge,
        8_128
    );
    assert_eq!(budget_device.operation.load(Ordering::Acquire), 0);
    drop(journal_guard);
    drop(sparse_mapping_scratch);
    drop(budget_file);
    drop(budget_fs);
    drop(budget_device);

    // RF180-34: the two sparse-gap passes must commit to the exact same
    // ordered pointer graph, not merely the same counts.  Block 16 contains
    // this inode's live first-block data.  After the clean mount, simulate a
    // faulty or mutable device that presents a newly allocated 17 -> 18
    // indirect mapping on pass one and substitutes live block 16 on pass two.
    // The old count-only check would accept and zero block 16.
    let substitution_inner = Arc::try_new(CrashBlockDevice::new(allocated_base.clone()))
        .expect("sparse substitution inner device");
    let substitution_device = Arc::try_new(SecondReadMutationDevice {
        inner: substitution_inner.clone(),
        target_sector: ((FIRST_FREE_BLOCK as u64 + 1) * BLOCK_SIZE as u64) / 512,
        target_reads: AtomicU64::new(0),
        enabled: AtomicBool::new(false),
        mutation_offset: 0,
        replacement: FIRST_FREE_BLOCK,
    })
    .expect("sparse substitution device");
    let dev: Arc<dyn BlockDevice> = substitution_device.clone();
    let substitution_fs = Ext2Fs::mount(dev).expect("mount sparse substitution image");
    let substitution_file = substitution_fs
        .load_inode(FILE_INO)
        .expect("load sparse substitution file");
    {
        let mut state = substitution_inner.state.lock();
        let CrashState { live, durable } = &mut *state;
        for image in [live, durable] {
            mark_block_allocated(image, FIRST_FREE_BLOCK + 1);
            mark_block_allocated(image, FIRST_FREE_BLOCK + 2);
            image[(FIRST_FREE_BLOCK as usize + 1) * BLOCK_SIZE
                ..(FIRST_FREE_BLOCK as usize + 1) * BLOCK_SIZE + size_of::<u32>()]
                .copy_from_slice(&(FIRST_FREE_BLOCK + 2).to_le_bytes());
            image[(FIRST_FREE_BLOCK as usize + 2) * BLOCK_SIZE
                ..(FIRST_FREE_BLOCK as usize + 3) * BLOCK_SIZE]
                .fill(0xA5);
        }
    }
    substitution_inner.arm(0, 0);
    substitution_device.target_reads.store(0, Ordering::Release);
    substitution_device.enabled.store(true, Ordering::Release);
    let before_substitution = substitution_inner.durable_snapshot();
    let mut substitution_raw = *substitution_file.raw.read();
    substitution_raw.size_lo = (EXT2_NDIR_BLOCKS * BLOCK_SIZE) as u32;
    substitution_raw.blocks_lo = (3 * BLOCK_SIZE / 512) as u32;
    substitution_raw.block[EXT2_IND_BLOCK] = FIRST_FREE_BLOCK + 1;
    let _substitution_meta = substitution_fs.meta_lock.lock();
    let substitution_journal_guard = substitution_fs.journal.lock();
    let substitution_journal = substitution_journal_guard
        .as_ref()
        .expect("sparse substitution journal");
    let mut substitution_scratch = Ext2MutationScratch::try_new_admitted(BLOCK_SIZE as u32)
        .expect("sparse substitution scratch");
    assert!(matches!(
        substitution_fs.preflight_sparse_gap(
            &substitution_raw,
            (EXT2_NDIR_BLOCKS * BLOCK_SIZE) as u64,
            ((EXT2_NDIR_BLOCKS + 1) * BLOCK_SIZE) as u64,
            substitution_journal,
            &mut substitution_scratch,
        ),
        Err(FsError::Invalid)
    ));
    assert_eq!(
        substitution_device.target_reads.load(Ordering::Acquire),
        2,
        "sparse transcript mismatch must stop before bitmap revalidation"
    );
    assert_eq!(substitution_inner.operation.load(Ordering::Acquire), 0);
    assert_eq!(substitution_inner.durable_snapshot(), before_substitution);
    assert!(substitution_inner.state.lock().live
        [FIRST_FREE_BLOCK as usize * BLOCK_SIZE..(FIRST_FREE_BLOCK as usize + 1) * BLOCK_SIZE]
        .iter()
        .eq(before_substitution[FIRST_FREE_BLOCK as usize * BLOCK_SIZE
            ..(FIRST_FREE_BLOCK as usize + 1) * BLOCK_SIZE]
            .iter()));
    drop(substitution_scratch);
    drop(substitution_journal_guard);
    drop(_substitution_meta);
    drop(substitution_file);
    drop(substitution_fs);
    drop(substitution_device);
    drop(substitution_inner);

    // Sparse-gap discovery must finish before zeroing its first target.  The
    // first direct mapping is valid, but a later structural target poisons the
    // complete request without issuing data or journal I/O.
    let (device, _fs, file) = mount_image(allocated_base.clone());
    file.raw.write().block[1] = 3;
    device.arm(0, 0);
    assert_eq!(
        file.write_at((2 * BLOCK_SIZE) as u64, b"Z"),
        Err(FsError::Invalid)
    );
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    drop(file);
    drop(_fs);
    drop(device);

    // A journal makes direct holes allocatable, but an indirect hole anywhere
    // in the range still rejects the whole request before its first write.
    let mut indirect_hole = base.clone();
    let file_offset = 5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>();
    let mut sparse_file: Ext2InodeRaw = read_struct(&indirect_hole, file_offset);
    sparse_file.size_lo = (13 * BLOCK_SIZE) as u32;
    copy_struct(&mut indirect_hole, file_offset, &sparse_file);
    let (device, _fs, file) = mount_image(indirect_hole);
    device.arm(0, 0);
    let mut cross_direct_limit = Vec::new();
    cross_direct_limit
        .try_reserve_exact(BLOCK_SIZE + 1)
        .expect("direct/indirect boundary payload");
    cross_direct_limit.resize(BLOCK_SIZE + 1, 0xCC);
    assert_eq!(
        file.write_at(11 * BLOCK_SIZE as u64, &cross_direct_limit),
        Err(FsError::NotSupported)
    );
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    drop(cross_direct_limit);
    drop(file);
    drop(_fs);
    drop(device);

    // Every write/flush boundary before the durable commit recovers to no
    // allocation; every boundary after it recovers all four metadata images.
    for fail_at in 1..=MUTATION_OPS {
        let (device, _fs, file) = mount_image(base.clone());
        device.arm(fail_at, 0);
        let result = file.write_at(0, payload);
        if fail_at <= 12 {
            assert_eq!(result, Err(FsError::Io));
        } else {
            assert_eq!(result, Ok(payload.len()));
        }
        let crashed = device.durable_snapshot();
        let (_recovery_device, recovered_fs, recovered_file) = mount_image(crashed);
        if fail_at <= 12 {
            assert_unallocated(&recovered_fs, &recovered_file);
        } else {
            assert_recovered_state(&recovered_fs, &recovered_file, payload, 1);
        }
    }

    // A failed commit flush is ambiguous: the commit block may already have
    // reached stable media. The syscall reports no bytes, the live mount is
    // poisoned, and remount recovery is authoritative.
    let (device, _fs, file) = mount_image(base.clone());
    device.arm(12, 11);
    assert_eq!(file.write_at(0, payload), Err(FsError::Io));
    let ambiguous_commit = device.durable_snapshot();
    assert_ne!(journal_start(&ambiguous_commit), 0);
    let active_allocation_log = ambiguous_commit.clone();
    let (_device, recovered_fs, recovered_file) = mount_image(ambiguous_commit);
    assert_recovered_state(&recovered_fs, &recovered_file, payload, 1);
    drop(recovered_file);
    drop(recovered_fs);
    drop(_device);
    drop(file);
    drop(_fs);
    drop(device);

    // Persist exactly the first checkpoint home write, then fail the second.
    // The crash image is intentionally inconsistent before recovery.
    let (device, _fs, file) = mount_image(base.clone());
    device.arm(14, 13);
    assert_eq!(file.write_at(0, payload), Ok(payload.len()));
    let partial_home = device.durable_snapshot();
    assert!(bitmap_allocated(&partial_home, FIRST_FREE_BLOCK));
    let partial_inode: Ext2InodeRaw = read_struct(
        &partial_home,
        5 * BLOCK_SIZE + (FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>(),
    );
    assert_eq!(partial_inode.block[0], 0);
    assert_ne!(journal_start(&partial_home), 0);
    let (_device, recovered_fs, recovered_file) = mount_image(partial_home);
    assert_recovered_state(&recovered_fs, &recovered_file, payload, 1);
    drop(recovered_file);
    drop(recovered_fs);
    drop(_device);
    drop(file);
    drop(_fs);
    drop(device);

    // Both the clear write and its flush can fail after checkpoint. The
    // durable start pointer keeps the committed transaction replayable.
    for fail_at in [18u64, 19] {
        let (device, _fs, file) = mount_image(base.clone());
        device.arm(fail_at, 0);
        assert_eq!(file.write_at(0, payload), Ok(payload.len()));
        let uncleared = device.durable_snapshot();
        assert_ne!(journal_start(&uncleared), 0);
        let (_device, recovered_fs, recovered_file) = mount_image(uncleared);
        assert_recovered_state(&recovered_fs, &recovered_file, payload, 1);
    }

    // A second transaction that dies before its commit returns the exact first
    // block prefix. Recovery retains the first mapping and discards the second.
    let mut two_blocks = Vec::new();
    two_blocks
        .try_reserve_exact(2 * BLOCK_SIZE)
        .expect("two-block payload");
    two_blocks.resize(2 * BLOCK_SIZE, 0x31);
    two_blocks[BLOCK_SIZE..].fill(0x52);
    let (device, _fs, file) = mount_image(base.clone());
    device.arm(MUTATION_OPS + 11, 0);
    assert_eq!(file.write_at(0, &two_blocks), Ok(BLOCK_SIZE));
    let second_uncommitted = device.durable_snapshot();
    assert_ne!(journal_start(&second_uncommitted), 0);
    let (_device, recovered_fs, recovered_file) = mount_image(second_uncommitted);
    assert_recovered_state(&recovered_fs, &recovered_file, &two_blocks[..BLOCK_SIZE], 1);
    drop(recovered_file);
    drop(recovered_fs);
    drop(_device);
    drop(file);
    drop(_fs);
    drop(device);
    drop(two_blocks);

    // Mapped-block appends must journal the inode-table after-image as well;
    // otherwise a power cut can tear i_size or a neighboring inode even though
    // the data block itself was ordered. One metadata image yields 13 mutation
    // operations with the same commit-flush PONR at operation 9.
    const MAPPED_MUTATION_OPS: u64 = 13;
    let mut mapped_payload = Vec::new();
    mapped_payload
        .try_reserve_exact(payload.len() + 1)
        .expect("mapped append payload");
    mapped_payload.extend_from_slice(payload);
    mapped_payload.push(b'!');
    let (device, fs, file) = mount_image(allocated_base.clone());
    device.arm(0, 0);
    assert_eq!(
        file.append_write(b"!"),
        Ok((1, mapped_payload.len() as u64))
    );
    assert_eq!(
        device.operation.load(Ordering::Acquire),
        MAPPED_MUTATION_OPS
    );
    assert_recovered_state(&fs, &file, &mapped_payload, 1);
    drop(file);
    drop(fs);
    drop(device);

    let mut sparse_payload = Vec::new();
    sparse_payload
        .try_reserve_exact(101)
        .expect("sparse extension payload");
    sparse_payload.resize(101, 0);
    sparse_payload[..payload.len()].copy_from_slice(payload);
    sparse_payload[100] = b'Z';
    let (device, fs, file) = mount_image(allocated_base.clone());
    device.arm(0, 0);
    assert_eq!(file.write_at(100, b"Z"), Ok(1));
    assert_recovered_state(&fs, &file, &sparse_payload, 1);
    assert_eq!(device.operation.load(Ordering::Acquire), 15);
    drop(file);
    drop(fs);
    drop(device);
    for fail_at in 1..=15u64 {
        let (device, _fs, file) = mount_image(allocated_base.clone());
        device.arm(fail_at, 0);
        let result = file.write_at(100, b"Z");
        if fail_at <= 11 {
            assert_eq!(result, Err(FsError::Io));
        } else {
            assert_eq!(result, Ok(1));
        }
        let crashed = device.durable_snapshot();
        let (_device, recovered_fs, recovered_file) = mount_image(crashed);
        if fail_at <= 11 {
            assert_recovered_state_with_tail(&recovered_fs, &recovered_file, payload, 1, false);
        } else {
            assert_recovered_state(&recovered_fs, &recovered_file, &sparse_payload, 1);
        }
    }
    drop(sparse_payload);

    for fail_at in 1..=MAPPED_MUTATION_OPS {
        let (device, _fs, file) = mount_image(allocated_base.clone());
        device.arm(fail_at, 0);
        let result = file.append_write(b"!");
        if fail_at <= 9 {
            assert_eq!(result, Err(FsError::Io));
        } else {
            assert_eq!(result, Ok((1, mapped_payload.len() as u64)));
        }
        let crashed = device.durable_snapshot();
        let (_device, recovered_fs, recovered_file) = mount_image(crashed);
        if fail_at <= 9 {
            assert_recovered_state_with_tail(&recovered_fs, &recovered_file, payload, 1, false);
        } else {
            assert_recovered_state(&recovered_fs, &recovered_file, &mapped_payload, 1);
        }
    }

    // A block driver may complete a commit write to stable media and still
    // return EIO. Recovery, not the syscall return, owns that ambiguity.
    let (device, _fs, file) = mount_image(allocated_base.clone());
    device.arm_write_then_error(8, true);
    assert_eq!(file.append_write(b"!"), Err(FsError::Io));
    let committed_after_error = device.durable_snapshot();
    assert_ne!(journal_start(&committed_after_error), 0);
    let (_device, recovered_fs, recovered_file) = mount_image(committed_after_error);
    assert_recovered_state(&recovered_fs, &recovered_file, &mapped_payload, 1);
    drop(recovered_file);
    drop(recovered_fs);
    drop(_device);
    drop(file);
    drop(_fs);
    drop(device);

    // Build an active, committed mapped-inode transaction and inject every
    // recovery-side home/flush/clear failure. The active tail must survive and
    // make the next mount converge to the committed state.
    let (device, _fs, file) = mount_image(allocated_base.clone());
    device.arm(9, 8);
    assert_eq!(file.append_write(b"!"), Err(FsError::Io));
    let active_mapped_log = device.durable_snapshot();
    assert_ne!(journal_start(&active_mapped_log), 0);
    drop(file);
    drop(_fs);
    drop(device);
    for recovery_fail_at in 1..=4u64 {
        let recovery_device = Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone()))
            .expect("recovery device");
        recovery_device.arm(recovery_fail_at, 0);
        let dev: Arc<dyn BlockDevice> = recovery_device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
        let retry_image = recovery_device.durable_snapshot();
        let (_device, recovered_fs, recovered_file) = mount_image(retry_image);
        assert_recovered_state(&recovered_fs, &recovered_file, &mapped_payload, 1);
    }
    let recovery_device =
        Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone())).expect("recovery device");
    recovery_device.arm_write_then_error(1, true);
    let dev: Arc<dyn BlockDevice> = recovery_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
    let retry_image = recovery_device.durable_snapshot();
    let (_device, recovered_fs, recovered_file) = mount_image(retry_image);
    assert_recovered_state(&recovered_fs, &recovered_file, &mapped_payload, 1);
    drop(recovered_file);
    drop(recovered_fs);
    drop(_device);
    drop(recovery_device);

    // A short device completion can persist any strict prefix of a home block.
    // Exercise the bytes immediately before/inside/after the changed inode
    // field and both sides of the 512-byte sector boundary.  The first remount
    // fails at the torn write, the second converges from the still-active
    // private transaction, and a third mount must be entirely read-only.
    let inode_offset_in_block = ((FILE_INO as usize - 1) * size_of::<Ext2InodeRaw>()) % BLOCK_SIZE;
    let inode_size_offset = inode_offset_in_block
        .checked_add(core::mem::offset_of!(Ext2InodeRaw, size_lo))
        .expect("inode size offset");
    for durable_prefix in [
        inode_size_offset,
        inode_size_offset + 1,
        inode_size_offset + size_of::<u32>(),
        511,
        512,
        513,
        BLOCK_SIZE - 1,
    ] {
        let torn_device = Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone()))
            .expect("torn inode-home device");
        torn_device.arm_torn_write(1, durable_prefix);
        let dev: Arc<dyn BlockDevice> = torn_device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
        assert_eq!(
            torn_device.observed_torn_sector(),
            Some((6 * BLOCK_SIZE / 512) as u64),
            "inode-home fault injection must hit the inode-table home"
        );
        let torn = torn_device.durable_snapshot();
        assert_ne!(journal_start(&torn), 0);
        assert_retry_then_clean_mount(torn, &mapped_payload, 1, true);
    }

    // Repeat the torn-home proof for every home in the four-image allocation
    // transaction.  Each row straddles the field changed in that home plus the
    // sector boundary, so bitmap, descriptor, superblock, and inode-table
    // checkpoints are all covered independently.
    let allocation_boundaries = [
        [1usize, 2, 3, 511, 512, 513, BLOCK_SIZE - 1],
        [
            core::mem::offset_of!(Ext2GroupDesc, free_blocks_count),
            core::mem::offset_of!(Ext2GroupDesc, free_blocks_count) + 1,
            core::mem::offset_of!(Ext2GroupDesc, free_blocks_count) + size_of::<u16>(),
            511,
            512,
            513,
            BLOCK_SIZE - 1,
        ],
        [
            core::mem::offset_of!(Ext2Superblock, free_blocks_count),
            core::mem::offset_of!(Ext2Superblock, free_blocks_count) + 1,
            core::mem::offset_of!(Ext2Superblock, free_blocks_count) + size_of::<u32>(),
            511,
            512,
            513,
            BLOCK_SIZE - 1,
        ],
        [
            inode_size_offset,
            inode_size_offset + 1,
            inode_size_offset + size_of::<u32>(),
            511,
            512,
            513,
            BLOCK_SIZE - 1,
        ],
    ];
    let allocation_home_blocks = [3u32, 2, 1, 6];
    for (home_index, boundaries) in allocation_boundaries.iter().enumerate() {
        for durable_prefix in boundaries.iter().copied() {
            let torn_device = Arc::try_new(CrashBlockDevice::new(active_allocation_log.clone()))
                .expect("torn allocation-home device");
            torn_device.arm_torn_write(
                u64::try_from(home_index + 1).expect("recovery home operation fits u64"),
                durable_prefix,
            );
            let dev: Arc<dyn BlockDevice> = torn_device.clone();
            assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
            assert_eq!(
                torn_device.observed_torn_sector(),
                Some(
                    u64::from(allocation_home_blocks[home_index])
                        * u64::try_from(BLOCK_SIZE / 512).expect("sectors per block fit u64")
                ),
                "allocation-home fault injection must hit the claimed writer-order home"
            );
            let torn = torn_device.durable_snapshot();
            assert_ne!(journal_start(&torn), 0);
            assert_retry_then_clean_mount(torn, payload, 1, true);
        }
    }

    // Recovery has already flushed the checkpoint before it clears the
    // journal superblock.  Tear that clear around both big-endian state words
    // and sector boundaries.  Whether the durable prefix still describes the
    // old active tail or the fully cleared one, the next mount must converge
    // and the following clean mount must issue no writes.
    for durable_prefix in [
        1usize,
        JBD2_SUPER_SEQUENCE_OFFSET,
        JBD2_SUPER_SEQUENCE_OFFSET + 3,
        JBD2_SUPER_SEQUENCE_OFFSET + 4,
        JBD2_SUPER_START_OFFSET + 3,
        JBD2_SUPER_START_OFFSET + 4,
        511,
        512,
        513,
        BLOCK_SIZE - 1,
    ] {
        let torn_device = Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone()))
            .expect("torn journal-clear device");
        torn_device.arm_torn_write(3, durable_prefix);
        let dev: Arc<dyn BlockDevice> = torn_device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
        assert_eq!(
            torn_device.observed_torn_sector(),
            Some(u64::from(JOURNAL_FIRST_PHYS) * (BLOCK_SIZE / 512) as u64),
            "journal-clear fault injection must hit the journal superblock"
        );
        assert_retry_then_clean_mount(torn_device.durable_snapshot(), &mapped_payload, 1, true);
    }

    // A sequence increment can carry across every byte of the big-endian word.
    // Re-sign the complete active transaction at 0x00ff_ffff, then tear each
    // strict interior prefix while recovery publishes 0x0100_0000.  The mixed
    // sequence no longer authenticates the old tail, but checkpointed homes are
    // already durable; retry must clear it safely and a third mount stays clean.
    const CARRY_SEQUENCE: u32 = 0x00FF_FFFF;
    const CARRIED_SEQUENCE: u32 = 0x0100_0000;
    for sequence_prefix in 1..size_of::<u32>() {
        let mut carry_image = active_mapped_log.clone();
        resequence_private_transaction(&mut carry_image, 1, CARRY_SEQUENCE);
        let durable_prefix = JBD2_SUPER_SEQUENCE_OFFSET + sequence_prefix;
        let torn_device = Arc::try_new(CrashBlockDevice::new(carry_image))
            .expect("sequence-carry journal-clear device");
        torn_device.arm_torn_write(3, durable_prefix);
        let dev: Arc<dyn BlockDevice> = torn_device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));
        assert_eq!(
            torn_device.observed_torn_sector(),
            Some(u64::from(JOURNAL_FIRST_PHYS) * (BLOCK_SIZE / 512) as u64),
            "sequence-carry fault injection must hit the journal superblock"
        );
        let torn = torn_device.durable_snapshot();
        let mut expected = CARRY_SEQUENCE.to_be_bytes();
        expected[..sequence_prefix]
            .copy_from_slice(&CARRIED_SEQUENCE.to_be_bytes()[..sequence_prefix]);
        let observed_sequence = read_be_u32(
            &torn,
            journal_logical_offset(0) + JBD2_SUPER_SEQUENCE_OFFSET,
        )
        .expect("torn carried sequence");
        assert_eq!(observed_sequence, u32::from_be_bytes(expected));
        assert_ne!(observed_sequence, CARRY_SEQUENCE);
        assert_ne!(observed_sequence, CARRIED_SEQUENCE);
        assert_ne!(journal_start(&torn), 0);
        assert_retry_then_clean_mount(torn, &mapped_payload, 1, true);
    }

    // The checkpoint validator is byte-granular, including sector boundaries.
    // Exercise differences that straddle 511/512/513 independently of the
    // synthetic filesystem's naturally early metadata fields.
    let pre_boundary = [0u8; BLOCK_SIZE];
    let mut post_boundary = pre_boundary;
    post_boundary[511..514].copy_from_slice(&[0xA1, 0xB2, 0xC3]);
    for split in [511usize, 512, 513, 514] {
        let mut current = pre_boundary;
        current[..split].copy_from_slice(&post_boundary[..split]);
        assert!(Ext2Fs::checkpoint_matches_single_prefix(
            &current,
            &pre_boundary,
            &post_boundary,
        ));
    }
    let mut impossible_boundary = pre_boundary;
    impossible_boundary[700] = 1;
    assert!(!Ext2Fs::checkpoint_matches_single_prefix(
        &impossible_boundary,
        &pre_boundary,
        &post_boundary,
    ));

    // Every private-transaction control/data block is captured exactly once.
    // For the four-image case logical block 3 is both the one-image commit
    // candidate and the second raw image; the captured candidate must be reused.
    let counted_inner = Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone()))
        .expect("one-image read-count inner device");
    let counted_device = Arc::try_new(JournalReadCountDevice {
        inner: counted_inner,
        logical_reads: Mutex::new([0; 8]),
    })
    .expect("one-image read-count device");
    let dev: Arc<dyn BlockDevice> = counted_device.clone();
    let counted_fs = Ext2Fs::mount(dev).expect("mount one-image read-count probe");
    let counted_file = counted_fs
        .load_inode(FILE_INO)
        .expect("load one-image read-count file");
    assert_recovered_state(&counted_fs, &counted_file, &mapped_payload, 1);
    assert_eq!(&counted_device.reads()[1..7], &[1, 1, 1, 0, 0, 0]);
    drop(counted_file);
    drop(counted_fs);
    drop(counted_device);

    let counted_inner = Arc::try_new(CrashBlockDevice::new(active_allocation_log.clone()))
        .expect("four-image read-count inner device");
    let counted_device = Arc::try_new(JournalReadCountDevice {
        inner: counted_inner,
        logical_reads: Mutex::new([0; 8]),
    })
    .expect("four-image read-count device");
    let dev: Arc<dyn BlockDevice> = counted_device.clone();
    let counted_fs = Ext2Fs::mount(dev).expect("mount four-image read-count probe");
    let counted_file = counted_fs
        .load_inode(FILE_INO)
        .expect("load four-image read-count file");
    assert_recovered_state(&counted_fs, &counted_file, payload, 1);
    assert_eq!(&counted_device.reads()[1..7], &[1, 1, 1, 1, 1, 1]);
    drop(counted_file);
    drop(counted_fs);
    drop(counted_device);

    // After the 32-bit sequence wraps, the unused four-image commit slot can
    // contain a fully formed historical commit with the same sequence.  Its
    // digest belongs to a different descriptor/data set and must neither make
    // the current one-image transaction ambiguous nor cause logical block 6 to
    // be read once the exact one-image descriptor and digest have validated.
    let mut wrapped_one = active_mapped_log.clone();
    resequence_private_transaction(&mut wrapped_one, 1, 0);
    let mut stale_four = active_allocation_log.clone();
    resequence_private_transaction(&mut stale_four, JOURNAL_MAX_METADATA_BLOCKS, 0);
    let stale_commit =
        stale_four[journal_logical_offset(6)..journal_logical_offset(6) + BLOCK_SIZE].to_vec();
    wrapped_one[journal_logical_offset(6)..journal_logical_offset(6) + BLOCK_SIZE]
        .copy_from_slice(&stale_commit);
    let counted_inner =
        Arc::try_new(CrashBlockDevice::new(wrapped_one)).expect("wrapped one-image inner device");
    let counted_device = Arc::try_new(JournalReadCountDevice {
        inner: counted_inner,
        logical_reads: Mutex::new([0; 8]),
    })
    .expect("wrapped one-image read-count device");
    let dev: Arc<dyn BlockDevice> = counted_device.clone();
    let wrapped_fs = Ext2Fs::mount(dev).expect("mount wrapped one-image transaction");
    let wrapped_file = wrapped_fs
        .load_inode(FILE_INO)
        .expect("load wrapped one-image file");
    assert_recovered_state(&wrapped_fs, &wrapped_file, &mapped_payload, 1);
    assert_eq!(&counted_device.reads()[1..7], &[1, 1, 1, 0, 0, 0]);
    drop(wrapped_file);
    drop(wrapped_fs);
    drop(counted_device);
    drop(stale_commit);
    drop(stale_four);

    // A block device that changes a journal data block on its second read must
    // not substitute an unvalidated image between validation and replay.  The
    // accepted post-image is captured once, then all validators and replay use
    // that immutable copy.
    let mutation_inner = Arc::try_new(CrashBlockDevice::new(active_mapped_log.clone()))
        .expect("frozen recovery inner device");
    let mutation_offset = inode_offset_in_block
        .checked_add(core::mem::offset_of!(Ext2InodeRaw, block))
        .expect("frozen recovery mutation offset");
    let mutation_device = Arc::try_new(SecondReadMutationDevice {
        inner: mutation_inner,
        target_sector: ((JOURNAL_FIRST_PHYS as u64 + 2) * BLOCK_SIZE as u64) / 512,
        target_reads: AtomicU64::new(0),
        enabled: AtomicBool::new(true),
        mutation_offset,
        replacement: JOURNAL_FIRST_PHYS,
    })
    .expect("frozen recovery mutation device");
    let dev: Arc<dyn BlockDevice> = mutation_device.clone();
    let frozen_fs = Ext2Fs::mount(dev).expect("mount with second-read mutation probe");
    let frozen_file = frozen_fs
        .load_inode(FILE_INO)
        .expect("load frozen recovery file");
    assert_recovered_state(&frozen_fs, &frozen_file, &mapped_payload, 1);
    assert_eq!(
        mutation_device.target_reads.load(Ordering::Acquire),
        1,
        "journal post-image must be read exactly once"
    );
    drop(frozen_file);
    drop(frozen_fs);
    drop(mutation_device);

    // The private writer always places the descriptor at `s_first` and never
    // wraps.  Preserve a fully signed one- or four-image transaction while
    // relocating its bytes; mount must reject the superblock location before
    // issuing any home or journal write.
    for (mut relocated, metadata_count, start, wrap) in [
        (active_mapped_log.clone(), 1usize, 4u32, false),
        (
            active_allocation_log.clone(),
            JOURNAL_MAX_METADATA_BLOCKS,
            2u32,
            false,
        ),
        (
            active_allocation_log.clone(),
            JOURNAL_MAX_METADATA_BLOCKS,
            5u32,
            true,
        ),
    ] {
        relocate_private_transaction(&mut relocated, metadata_count, start, wrap);
        let before = relocated.clone();
        let device = Arc::try_new(CrashBlockDevice::new(relocated))
            .expect("relocated private transaction device");
        let dev: Arc<dyn BlockDevice> = device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
        assert_eq!(device.operation.load(Ordering::Acquire), 0);
        assert_eq!(device.durable_snapshot(), before);
    }

    // A journal with the required tear-safe `s_first == 1` must still reserve
    // enough logical blocks for the writer's maximum four-image transaction.
    // Keep the inode size and s_maxlen consistent at six blocks: descriptor +
    // four images + commit would end at logical block 6, outside [0, 6).
    let mut too_short = active_mapped_log.clone();
    write_be_u32(
        &mut too_short,
        journal_logical_offset(0) + JBD2_SUPER_MAXLEN_OFFSET,
        6,
    )
    .expect("short journal maxlen");
    let journal_inode_offset =
        5 * BLOCK_SIZE + (JOURNAL_INO as usize - 1) * size_of::<Ext2InodeRaw>();
    let mut short_journal_inode: Ext2InodeRaw = read_struct(&too_short, journal_inode_offset);
    short_journal_inode.size_lo = (6 * BLOCK_SIZE) as u32;
    short_journal_inode.blocks_lo = 12;
    short_journal_inode.block[6] = 0;
    short_journal_inode.block[7] = 0;
    copy_struct(&mut too_short, journal_inode_offset, &short_journal_inode);
    let before = too_short.clone();
    let device =
        Arc::try_new(CrashBlockDevice::new(too_short)).expect("too-short private journal device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    // A bit flip in any authenticated component makes the commit
    // unauthoritative.  With unchanged homes, recovery discards the tail and
    // retains the old inode state; ordered data beyond i_size is not exposed.
    let commit_offset = journal_logical_offset(3);
    let authenticated_corruptions = [
        journal_logical_offset(1) + JBD2_HEADER_BYTES + JBD2_TAG_BYTES + 16,
        commit_offset + ZERO_INTENT_INODE_OFFSET + 3,
        journal_logical_offset(2) + inode_size_offset,
        commit_offset + ZERO_INTENT_DIGEST_OFFSET,
    ];
    for corruption in authenticated_corruptions {
        let mut corrupted = active_mapped_log.clone();
        corrupted[corruption] ^= 1;
        let (device, recovered_fs, recovered_file) = mount_image(corrupted);
        assert_recovered_state_with_tail(&recovered_fs, &recovered_file, payload, 1, false);
        assert_eq!(journal_start(&device.durable_snapshot()), 0);
    }

    // Exercise every authenticated region of the four-image allocation form,
    // including each independent post-image.  An unauthenticated bit flip must
    // discard the tail without exposing the ordered data block through an inode
    // or partially applying any of the four metadata homes.
    let four_commit_offset = journal_logical_offset(6);
    let four_image_corruptions = [
        journal_logical_offset(1) + JBD2_HEADER_BYTES,
        journal_logical_offset(2) + 17,
        journal_logical_offset(3) + 17,
        journal_logical_offset(4) + 17,
        journal_logical_offset(5) + inode_size_offset,
        four_commit_offset + ZERO_INTENT_PHYSICAL_OFFSET,
        four_commit_offset + ZERO_INTENT_DIGEST_OFFSET,
    ];
    for corruption in four_image_corruptions {
        let mut corrupted = active_allocation_log.clone();
        corrupted[corruption] ^= 1;
        let (device, recovered_fs, recovered_file) = mount_image(corrupted);
        assert_unallocated(&recovered_fs, &recovered_file);
        assert_eq!(journal_start(&device.durable_snapshot()), 0);
    }

    // A hostile image author can recompute the transaction digest.  Duplicate
    // two descriptor homes in a four-image allocation and re-sign it; exact tag
    // grammar and home uniqueness must reject it before any persistent write.
    let mut duplicate_four_home = active_allocation_log.clone();
    let first_home = read_be_u32(
        &duplicate_four_home,
        journal_logical_offset(1) + JBD2_HEADER_BYTES,
    )
    .expect("first four-image descriptor home");
    let second_tag = journal_logical_offset(1) + JBD2_HEADER_BYTES + JBD2_TAG_BYTES + 16;
    write_be_u32(&mut duplicate_four_home, second_tag, first_home)
        .expect("duplicate four-image descriptor home");
    resign_private_transaction(&mut duplicate_four_home, JOURNAL_MAX_METADATA_BLOCKS);
    let before = duplicate_four_home.clone();
    let device = Arc::try_new(CrashBlockDevice::new(duplicate_four_home))
        .expect("duplicate four-image home device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    // Likewise, re-signing a semantically impossible post-image cannot bypass
    // the per-home preimage proof.  Change the logged group free count without
    // changing its committed preimage hash and require fail-closed recovery.
    let mut forged_four_post = active_allocation_log.clone();
    let group_free_offset =
        journal_logical_offset(3) + core::mem::offset_of!(Ext2GroupDesc, free_blocks_count);
    let forged_free = u16::from_le_bytes(
        forged_four_post[group_free_offset..group_free_offset + size_of::<u16>()]
            .try_into()
            .expect("logged group free-count bytes"),
    )
    .checked_sub(1)
    .expect("synthetic logged free count is nonzero");
    forged_four_post[group_free_offset..group_free_offset + size_of::<u16>()]
        .copy_from_slice(&forged_free.to_le_bytes());
    resign_private_transaction(&mut forged_four_post, JOURNAL_MAX_METADATA_BLOCKS);
    let before = forged_four_post.clone();
    let device = Arc::try_new(CrashBlockDevice::new(forged_four_post))
        .expect("forged four-image post-image device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    // The digest is an integrity check, not an authenticity oracle.  An image
    // author can recompute it, so unchanged bytes in a whole-block log image
    // must still agree with the actual checkpoint home.  Forge a neighboring
    // allocated inode's uid in both the claimed pre- and post-image while the
    // real home remains untouched; exact checkpoint validation must reject it
    // before replay can overwrite that neighbor.
    let mut forged_neighbor = active_mapped_log.clone();
    let neighbor_offset = ((10usize - 1) * size_of::<Ext2InodeRaw>()) % BLOCK_SIZE;
    let neighbor_uid =
        journal_logical_offset(2) + neighbor_offset + core::mem::offset_of!(Ext2InodeRaw, uid);
    forged_neighbor[neighbor_uid..neighbor_uid + size_of::<u16>()]
        .copy_from_slice(&1u16.to_le_bytes());
    let intent_old_inode: Ext2InodeRaw = read_struct(
        &forged_neighbor,
        commit_offset + ZERO_INTENT_OLD_INODE_OFFSET,
    );
    let mut forged_preimage =
        forged_neighbor[journal_logical_offset(2)..journal_logical_offset(2) + BLOCK_SIZE].to_vec();
    copy_struct(
        &mut forged_preimage,
        inode_offset_in_block,
        &intent_old_inode,
    );
    let forged_hash = Sha256::digest(&forged_preimage);
    forged_neighbor[commit_offset + ZERO_INTENT_PREIMAGE_HASHES_OFFSET
        ..commit_offset + ZERO_INTENT_PREIMAGE_HASHES_OFFSET + 32]
        .copy_from_slice(&forged_hash);
    resign_private_transaction(&mut forged_neighbor, 1);
    let before = forged_neighbor.clone();
    let device = Arc::try_new(CrashBlockDevice::new(forged_neighbor))
        .expect("re-signed neighboring-inode forgery device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);
    drop(forged_preimage);

    // By contrast, recomputing the private digest around a non-writer grammar
    // does not authorize it.  This is the hostile-fixture case: the transaction
    // is structurally committed, but non-zero descriptor padding remains an
    // impossible writer output and fails before the first persistent write.
    let mut hostile_descriptor = active_mapped_log.clone();
    hostile_descriptor[journal_logical_offset(1) + JBD2_HEADER_BYTES + JBD2_TAG_BYTES + 16] = 1;
    resign_private_transaction(&mut hostile_descriptor, 1);
    let before = hostile_descriptor.clone();
    let device = Arc::try_new(CrashBlockDevice::new(hostile_descriptor))
        .expect("hostile signed descriptor device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    // A signed intent for a different inode is likewise not enough: the
    // canonical inode transition and descriptor home must agree exactly.
    let mut hostile_intent = active_mapped_log.clone();
    write_be_u32(
        &mut hostile_intent,
        commit_offset + ZERO_INTENT_INODE_OFFSET,
        FILE_INO + 1,
    )
    .expect("hostile intent inode");
    resign_private_transaction(&mut hostile_intent, 1);
    let before = hostile_intent.clone();
    let device =
        Arc::try_new(CrashBlockDevice::new(hostile_intent)).expect("hostile signed intent device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    // Active legacy JBD2 has no immutable preimage proof and is rejected
    // without writes.  A clean writable legacy journal is upgraded, flushed,
    // reread, and thereafter mounts without another upgrade write.
    let feature_offset = journal_logical_offset(0) + JBD2_SUPER_FEATURE_INCOMPAT_OFFSET;
    let mut active_legacy = active_mapped_log.clone();
    let active_features = read_be_u32(&active_legacy, feature_offset).expect("active features");
    write_be_u32(
        &mut active_legacy,
        feature_offset,
        active_features & !JBD2_FEATURE_INCOMPAT_ZERO_INTENT,
    )
    .expect("active legacy features");
    let before = active_legacy.clone();
    let device =
        Arc::try_new(CrashBlockDevice::new(active_legacy)).expect("active legacy journal device");
    let dev: Arc<dyn BlockDevice> = device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
    assert_eq!(device.operation.load(Ordering::Acquire), 0);
    assert_eq!(device.durable_snapshot(), before);
    drop(device);
    drop(before);

    let mut clean_legacy = base.clone();
    let clean_features = read_be_u32(&clean_legacy, feature_offset).expect("clean features");
    write_be_u32(
        &mut clean_legacy,
        feature_offset,
        clean_features & !JBD2_FEATURE_INCOMPAT_ZERO_INTENT,
    )
    .expect("clean legacy features");
    let (upgrade_device, upgrade_fs, upgrade_file) = mount_image(clean_legacy);
    assert_unallocated(&upgrade_fs, &upgrade_file);
    assert!(upgrade_device.operation.load(Ordering::Acquire) != 0);
    let upgraded = upgrade_device.durable_snapshot();
    assert_ne!(
        read_be_u32(&upgraded, feature_offset).expect("upgraded features")
            & JBD2_FEATURE_INCOMPAT_ZERO_INTENT,
        0
    );
    drop(upgrade_file);
    drop(upgrade_fs);
    drop(upgrade_device);
    let (clean_device, clean_fs, clean_file) = mount_image(upgraded.clone());
    assert_unallocated(&clean_fs, &clean_file);
    assert_eq!(clean_device.operation.load(Ordering::Acquire), 0);
    assert_eq!(clean_device.durable_snapshot(), upgraded);
    drop(clean_file);
    drop(clean_fs);
    drop(clean_device);
    drop(upgraded);

    // Both an already-private journal and a legacy journal awaiting upgrade
    // must reject a nontrivial `s_first`.  Clearing a multi-byte big-endian
    // start can tear into a value that is neither zero nor `s_first`.
    for legacy in [false, true] {
        let mut unsafe_first = base.clone();
        write_be_u32(
            &mut unsafe_first,
            journal_logical_offset(0) + JBD2_SUPER_FIRST_OFFSET,
            2,
        )
        .expect("unsafe journal first");
        if legacy {
            let features =
                read_be_u32(&unsafe_first, feature_offset).expect("unsafe-first features");
            write_be_u32(
                &mut unsafe_first,
                feature_offset,
                features & !JBD2_FEATURE_INCOMPAT_ZERO_INTENT,
            )
            .expect("unsafe-first legacy features");
        }
        let before = unsafe_first.clone();
        let device =
            Arc::try_new(CrashBlockDevice::new(unsafe_first)).expect("unsafe-first journal device");
        let dev: Arc<dyn BlockDevice> = device.clone();
        assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
        assert_eq!(device.operation.load(Ordering::Acquire), 0);
        assert_eq!(device.durable_snapshot(), before);
    }

    // Corrupt the committed inode after-image so it points into the journal.
    // Exact grammar validation must reject it before changing the home inode
    // block or clearing the active tail.
    let mut corrupt_overlay = active_mapped_log.clone();
    let inode_log_offset = (JOURNAL_FIRST_PHYS as usize + 2) * BLOCK_SIZE;
    let mut corrupt_inode: Ext2InodeRaw =
        read_struct(&corrupt_overlay, inode_log_offset + inode_offset_in_block);
    corrupt_inode.block[0] = JOURNAL_FIRST_PHYS;
    copy_struct(
        &mut corrupt_overlay,
        inode_log_offset + inode_offset_in_block,
        &corrupt_inode,
    );
    resign_private_transaction(&mut corrupt_overlay, 1);
    let home_before = corrupt_overlay[6 * BLOCK_SIZE..7 * BLOCK_SIZE].to_vec();
    let corrupt_device =
        Arc::try_new(CrashBlockDevice::new(corrupt_overlay)).expect("corrupt overlay device");
    let dev: Arc<dyn BlockDevice> = corrupt_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
    assert_eq!(corrupt_device.operation.load(Ordering::Acquire), 0);
    let rejected = corrupt_device.durable_snapshot();
    assert_eq!(&rejected[6 * BLOCK_SIZE..7 * BLOCK_SIZE], &home_before);
    assert_ne!(journal_start(&rejected), 0);
    drop(rejected);
    drop(corrupt_device);
    drop(home_before);

    // A newly published indirect root is not safe merely because the root
    // word itself is in range and allocated.  Validate the mapping block's
    // contents under level-1 provenance before replay: a child pointer into
    // the block bitmap must leave both the home inode and active tail intact.
    let mut corrupt_indirect = active_mapped_log.clone();
    let indirect_root = FIRST_FREE_BLOCK + 1;
    let root_bit = indirect_root - 1;
    corrupt_indirect[3 * BLOCK_SIZE + (root_bit / 8) as usize] |= 1u8 << (root_bit % 8);
    let mut indirect_super: Ext2Superblock =
        read_struct(&corrupt_indirect, SUPERBLOCK_OFFSET as usize);
    indirect_super.free_blocks_count -= 1;
    copy_struct(
        &mut corrupt_indirect,
        SUPERBLOCK_OFFSET as usize,
        &indirect_super,
    );
    let mut indirect_desc: Ext2GroupDesc = read_struct(&corrupt_indirect, 2 * BLOCK_SIZE);
    indirect_desc.free_blocks_count -= 1;
    copy_struct(&mut corrupt_indirect, 2 * BLOCK_SIZE, &indirect_desc);
    corrupt_indirect[indirect_root as usize * BLOCK_SIZE..indirect_root as usize * BLOCK_SIZE + 4]
        .copy_from_slice(&3u32.to_le_bytes());

    // Make the indirect root part of both the real preimage and the committed
    // postimage.  The inode-update intent may then change only size/timestamps,
    // so rejection below necessarily comes from walking the unchanged mapping
    // tree rather than the earlier pointer-transition gate.
    let mut old_indirect_inode: Ext2InodeRaw =
        read_struct(&corrupt_indirect, 6 * BLOCK_SIZE + inode_offset_in_block);
    old_indirect_inode.block[EXT2_IND_BLOCK] = indirect_root;
    old_indirect_inode.blocks_lo += 2;
    copy_struct(
        &mut corrupt_indirect,
        6 * BLOCK_SIZE + inode_offset_in_block,
        &old_indirect_inode,
    );
    let mut indirect_inode: Ext2InodeRaw =
        read_struct(&corrupt_indirect, inode_log_offset + inode_offset_in_block);
    indirect_inode.block[EXT2_IND_BLOCK] = indirect_root;
    indirect_inode.blocks_lo += 2;
    copy_struct(
        &mut corrupt_indirect,
        inode_log_offset + inode_offset_in_block,
        &indirect_inode,
    );
    copy_struct(
        &mut corrupt_indirect,
        commit_offset + ZERO_INTENT_OLD_INODE_OFFSET,
        &old_indirect_inode,
    );
    let indirect_preimage_hash = Sha256::digest(&corrupt_indirect[6 * BLOCK_SIZE..7 * BLOCK_SIZE]);
    corrupt_indirect[commit_offset + ZERO_INTENT_PREIMAGE_HASHES_OFFSET
        ..commit_offset + ZERO_INTENT_PREIMAGE_HASHES_OFFSET + 32]
        .copy_from_slice(&indirect_preimage_hash);
    resign_private_transaction(&mut corrupt_indirect, 1);
    let mut checkpointed_indirect = corrupt_indirect.clone();
    copy_struct(
        &mut checkpointed_indirect,
        6 * BLOCK_SIZE + inode_offset_in_block,
        &indirect_inode,
    );
    let indirect_home_before = corrupt_indirect[6 * BLOCK_SIZE..7 * BLOCK_SIZE].to_vec();
    let indirect_device = Arc::try_new(CrashBlockDevice::new(corrupt_indirect))
        .expect("corrupt indirect overlay device");
    let dev: Arc<dyn BlockDevice> = indirect_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(indirect_device.operation.load(Ordering::Acquire), 0);
    let rejected = indirect_device.durable_snapshot();
    assert_eq!(
        &rejected[6 * BLOCK_SIZE..7 * BLOCK_SIZE],
        &indirect_home_before
    );
    assert_ne!(journal_start(&rejected), 0);
    drop(rejected);
    drop(indirect_device);
    drop(indirect_home_before);

    // The same proof is required if the inode-table checkpoint reached stable
    // media before the crash and therefore already equals the after-image.
    // Recovery must not mistake equality for evidence that the indirect tree
    // predates the transaction.
    let checkpointed_device = Arc::try_new(CrashBlockDevice::new(checkpointed_indirect))
        .expect("checkpointed corrupt indirect device");
    let dev: Arc<dyn BlockDevice> = checkpointed_device.clone();
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Invalid)));
    assert_eq!(checkpointed_device.operation.load(Ordering::Acquire), 0);
    assert_ne!(journal_start(&checkpointed_device.durable_snapshot()), 0);
    drop(checkpointed_device);

    // Unsupported checksum-era Ext4 and JBD2 feature bits fail closed before
    // the filesystem object can be published.
    let mut ext4_ro = base.clone();
    let mut superblock: Ext2Superblock = read_struct(&ext4_ro, SUPERBLOCK_OFFSET as usize);
    superblock.feature_ro_compat |= 0x0000_0400;
    copy_struct(&mut ext4_ro, SUPERBLOCK_OFFSET as usize, &superblock);
    let device = Arc::try_new(CrashBlockDevice::new(ext4_ro)).expect("unsupported Ext4 device");
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));

    let mut plain_ext4_ro = synthetic_image();
    let mut superblock: Ext2Superblock = read_struct(&plain_ext4_ro, SUPERBLOCK_OFFSET as usize);
    superblock.feature_compat &= !EXT3_FEATURE_COMPAT_HAS_JOURNAL;
    superblock.feature_ro_compat |= 0x0000_0400;
    superblock.journal_uuid = [0; 16];
    superblock.journal_inum = 0;
    copy_struct(&mut plain_ext4_ro, SUPERBLOCK_OFFSET as usize, &superblock);
    let device =
        Arc::try_new(CrashBlockDevice::new(plain_ext4_ro)).expect("plain unsupported Ext4 device");
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));

    let mut orphaned_plain = synthetic_image();
    let mut superblock: Ext2Superblock = read_struct(&orphaned_plain, SUPERBLOCK_OFFSET as usize);
    superblock.feature_compat &= !EXT3_FEATURE_COMPAT_HAS_JOURNAL;
    superblock.journal_uuid = [0; 16];
    superblock.journal_inum = 0;
    superblock.last_orphan = FILE_INO;
    copy_struct(&mut orphaned_plain, SUPERBLOCK_OFFSET as usize, &superblock);
    let device =
        Arc::try_new(CrashBlockDevice::new(orphaned_plain)).expect("orphaned plain Ext2 device");
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));

    // A resize inode can describe a geometrically valid double-indirect tree
    // whose hostile sparse walk would otherwise inspect hundreds of millions
    // of words.  The claimed ownership count is rejected against the explicit
    // mount budget before any pointer block is followed or retained.
    let mut oversized_resize = synthetic_image();
    let mut resize_super: Ext2Superblock =
        read_struct(&oversized_resize, SUPERBLOCK_OFFSET as usize);
    resize_super.feature_compat |= EXT2_FEATURE_COMPAT_RESIZE_INODE;
    resize_super.reserved_gdt_blocks = 0;
    copy_struct(
        &mut oversized_resize,
        SUPERBLOCK_OFFSET as usize,
        &resize_super,
    );
    let mut resize_inode = Ext2InodeRaw::default();
    resize_inode.mode = EXT2_S_IFREG | 0o600;
    resize_inode.links_count = 1;
    resize_inode.blocks_lo = u32::try_from(MAX_RESIZE_RESERVED_BLOCKS + 1)
        .expect("resize budget fits u32")
        .checked_mul((BLOCK_SIZE / 512) as u32)
        .expect("resize block count fits i_blocks");
    copy_struct(
        &mut oversized_resize,
        5 * BLOCK_SIZE + (7usize - 1) * size_of::<Ext2InodeRaw>(),
        &resize_inode,
    );
    let device = Arc::try_new(CrashBlockDevice::new(oversized_resize))
        .expect("oversized resize-inode device");
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));

    // The BGDT is sector-padded, but a successful short read must never be
    // parsed as a complete descriptor table. The synthetic 1 KiB image places
    // its primary BGDT at block 2, which begins at 512-byte sector 4.
    let device =
        Arc::try_new(CrashBlockDevice::new(synthetic_image())).expect("short-BGDT-read device");
    device.arm_short_read(4);
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::Io)));

    let mut unsupported_jbd2 = base;
    write_be_u32(
        &mut unsupported_jbd2,
        JOURNAL_FIRST_PHYS as usize * BLOCK_SIZE + JBD2_SUPER_FEATURE_INCOMPAT_OFFSET,
        JBD2_FEATURE_INCOMPAT_REVOKE | 0x0000_0008,
    )
    .expect("unsupported JBD2 feature");
    let device =
        Arc::try_new(CrashBlockDevice::new(unsupported_jbd2)).expect("unsupported JBD2 device");
    let dev: Arc<dyn BlockDevice> = device;
    assert!(matches!(Ext2Fs::mount(dev), Err(FsError::NotSupported)));
}

#[cfg(test)]
mod hosted_journal_tests {
    #[test]
    fn r180_6_ordered_data_crash_boundaries() {
        // Hosted filtering may run this test in isolation, before any sibling
        // publishes the kernel's whole-heap admission budgets.  Keep the crash
        // oracle independent of test order so allocation failure cannot mask a
        // journal invariant failure.
        mm::publish_heap_budgets();
        super::run_ext2_journal_transaction_self_test();
    }

    #[test]
    fn rf180_34_sparse_gap_plan_is_budget_bounded_without_cap_allocation() {
        mm::publish_heap_budgets();
        let mut traversal =
            super::SparseGapTraversalScratch::try_new(4096).expect("RF180-35 traversal scratch");
        assert_eq!(
            traversal.branches.capacity(),
            0,
            "direct/single-indirect writes must not allocate the double-indirect cap"
        );
        traversal
            .prepare_branches(3)
            .expect("RF180-35 exact branch allocation");
        assert!(traversal.branches.capacity() >= 3);
        assert!(traversal.branches.capacity() < super::MAX_SPARSE_GAP_MAPPING_NODES);
        traversal
            .prepare_branches(0)
            .expect("RF180-35 branch backing release");
        assert_eq!(traversal.branches.capacity(), 0);
        drop(traversal);

        let maximum = super::SparseGapCounts {
            mapping_nodes: super::MAX_SPARSE_GAP_MAPPING_NODES,
            branch_nodes: super::MAX_SPARSE_GAP_MAPPING_NODES,
            data_targets: super::MAX_SPARSE_GAP_DATA_BLOCKS,
            boundary_targets: 2,
        };
        assert!(super::sparse_gap_plan_charge_bytes(maximum).is_ok());
        assert!(matches!(
            super::sparse_gap_plan_charge_bytes(super::SparseGapCounts {
                mapping_nodes: maximum.mapping_nodes,
                branch_nodes: maximum.branch_nodes,
                data_targets: maximum.data_targets + 1,
                boundary_targets: maximum.boundary_targets,
            }),
            Err(crate::types::FsError::NoMem)
        ));
        let maximum_live = super::sparse_gap_max_live_charge_bytes(65_536)
            .expect("maximum sparse-gap live charge");
        assert_eq!(
            mm::HeapClass::FilesystemIo.limit_bytes() - maximum_live,
            8_128
        );

        let target = super::SparseGapTarget {
            physical: 23,
            start: 0,
            end: 4096,
        };
        let mut first = super::SparseGapTranscript::new(4096, 0, 8192);
        first.mapping_node(17, Some(3));
        first.data_target(4, target);
        let expected = first.finish();
        let mut identical = super::SparseGapTranscript::new(4096, 0, 8192);
        identical.mapping_node(17, Some(3));
        identical.data_target(4, target);
        assert_eq!(identical.finish(), expected);
        let mut substituted = super::SparseGapTranscript::new(4096, 0, 8192);
        substituted.mapping_node(17, Some(3));
        substituted.data_target(
            4,
            super::SparseGapTarget {
                physical: 29,
                ..target
            },
        );
        assert_ne!(substituted.finish(), expected);
        let mut relocated = super::SparseGapTranscript::new(4096, 0, 8192);
        relocated.mapping_node(17, Some(3));
        relocated.data_target(5, target);
        assert_ne!(relocated.finish(), expected);

        let boundaries = [
            Some(super::SparseGapTarget {
                physical: 7,
                start: 123,
                end: 4096,
            }),
            Some(super::SparseGapTarget {
                physical: 11,
                start: 0,
                end: 65_535,
            }),
        ];
        assert_eq!(
            super::sparse_gap_target_bounds(&boundaries, 7, 65_536),
            (123, 4096)
        );
        assert_eq!(
            super::sparse_gap_target_bounds(&boundaries, 11, 65_536),
            (0, 65_535)
        );
        assert_eq!(
            super::sparse_gap_target_bounds(&boundaries, 19, 65_536),
            (0, 65_536)
        );

        let mut boundary_counts = super::SparseGapCounts::default();
        boundary_counts
            .account_data_target(boundaries[0].expect("first boundary"), 65_536)
            .expect("first partial boundary");
        boundary_counts
            .account_data_target(boundaries[1].expect("second boundary"), 65_536)
            .expect("second partial boundary");
        assert_eq!(boundary_counts.boundary_targets, 2);
        assert_eq!(
            boundary_counts.account_data_target(
                super::SparseGapTarget {
                    physical: 13,
                    start: 1,
                    end: 2,
                },
                65_536,
            ),
            Err(crate::types::FsError::Invalid)
        );
    }
}

/// File type in mode field
pub const EXT2_S_IFMT: u16 = 0xF000;
pub const EXT2_S_IFREG: u16 = 0x8000;
pub const EXT2_S_IFDIR: u16 = 0x4000;
pub const EXT2_S_IFLNK: u16 = 0xA000;

/// Directory entry file types
pub const EXT2_FT_REG_FILE: u8 = 1;
pub const EXT2_FT_DIR: u8 = 2;
pub const EXT2_FT_CHRDEV: u8 = 3;
pub const EXT2_FT_BLKDEV: u8 = 4;
pub const EXT2_FT_FIFO: u8 = 5; // R133-7 FIX
pub const EXT2_FT_SOCK: u8 = 6; // R133-7 FIX
pub const EXT2_FT_SYMLINK: u8 = 7;

/// Inode flags
pub const EXT2_IMMUTABLE_FL: u32 = 0x00000010;
pub const EXT2_APPEND_FL: u32 = 0x00000020;
const EXT2_COMPR_FL: u32 = 0x0000_0004;
const EXT3_JOURNAL_DATA_FL: u32 = 0x0000_4000;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
const EXT2_UNSUPPORTED_WRITE_LAYOUT_FL: u32 =
    EXT2_COMPR_FL | EXT3_JOURNAL_DATA_FL | EXT4_EXTENTS_FL | EXT4_INLINE_DATA_FL;

/// Global filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(100);

// ============================================================================
// Safe On-Disk Data Access Helpers
// ============================================================================

/// Read a little-endian u32 from a byte buffer at the given index.
///
/// Ext2 on-disk structures store multi-byte integers in little-endian format.
/// This function avoids creating an unaligned `&[u32]` view over a `Vec<u8>`
/// buffer, which would be undefined behavior in Rust (Vec<u8> only guarantees
/// 1-byte alignment).
///
/// # Arguments
///
/// * `buf` - The byte buffer to read from
/// * `index` - The u32 index (not byte offset) within the buffer
///
/// # Returns
///
/// * `Ok(u32)` - The value at the given index
/// * `Err(FsError::Invalid)` - Index out of bounds or overflow
///
/// # R96-1 Fix
///
/// This replaces unsafe `slice::from_raw_parts(buf.as_ptr() as *const u32, ...)`
/// patterns that created UB from unaligned access.
#[inline]
fn read_u32_le(buf: &[u8], index: usize) -> Result<u32, FsError> {
    let offset = index
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(FsError::Invalid)?;
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(FsError::Invalid)?;
    let bytes = buf.get(offset..end).ok_or(FsError::Invalid)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_be_u16(buf: &[u8], offset: usize) -> Result<u16, FsError> {
    let bytes = buf
        .get(offset..offset.checked_add(2).ok_or(FsError::Invalid)?)
        .ok_or(FsError::Invalid)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_be_u32(buf: &[u8], offset: usize) -> Result<u32, FsError> {
    let bytes = buf
        .get(offset..offset.checked_add(4).ok_or(FsError::Invalid)?)
        .ok_or(FsError::Invalid)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn write_be_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    let end = offset.checked_add(2).ok_or(FsError::Invalid)?;
    buf.get_mut(offset..end)
        .ok_or(FsError::Invalid)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[inline]
fn write_be_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<(), FsError> {
    let end = offset.checked_add(4).ok_or(FsError::Invalid)?;
    buf.get_mut(offset..end)
        .ok_or(FsError::Invalid)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// RF178-39 FIX: fallible lossy UTF-8 conversion for ext2 directory names.
/// Capacity is reserved before any push, so malformed ext2 names return
/// `NoSpace` on OOM instead of reaching an infallible String growth path.
fn fallible_lossy_name(bytes: &[u8]) -> Result<String, FsError> {
    if let Ok(valid) = core::str::from_utf8(bytes) {
        let mut out = String::new();
        out.try_reserve_exact(valid.len())
            .map_err(|_| FsError::NoSpace)?;
        out.push_str(valid);
        return Ok(out);
    }

    let worst_case = bytes.len().checked_mul(3).ok_or(FsError::Invalid)?;
    let mut out = String::new();
    out.try_reserve_exact(worst_case)
        .map_err(|_| FsError::NoSpace)?;
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(err) => {
                let valid_len = err.valid_up_to();
                if valid_len != 0 {
                    // SAFETY: Utf8Error guarantees the prefix through valid_up_to
                    // is valid UTF-8.
                    out.push_str(unsafe { core::str::from_utf8_unchecked(&rest[..valid_len]) });
                }
                out.push('\u{FFFD}');
                let invalid_len = err
                    .error_len()
                    .unwrap_or_else(|| rest.len().saturating_sub(valid_len));
                rest = &rest[valid_len + invalid_len..];
            }
        }
    }
    Ok(out)
}

// ============================================================================
// On-disk structures
// ============================================================================

/// Ext2 superblock (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_frag_size: i32,
    pub blocks_per_group: u32,
    pub frags_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: i16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    // Rev 1 fields
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algo_bitmap: u32,
    pub prealloc_blocks: u8,
    pub prealloc_dir_blocks: u8,
    pub reserved_gdt_blocks: u16,
    pub journal_uuid: [u8; 16],
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub last_orphan: u32,
    // Padding to 1024 bytes
    _padding: [u8; 788],
}

const _: () = assert!(size_of::<Ext2Superblock>() == 1024);

/// Block group descriptor (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2GroupDesc {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
    pub free_blocks_count: u16,
    pub free_inodes_count: u16,
    pub used_dirs_count: u16,
    pub pad: u16,
    pub reserved: [u8; 12],
}

/// Ext2 inode (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2InodeRaw {
    pub mode: u16,
    pub uid: u16,
    pub size_lo: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; 15],
    pub generation: u32,
    pub file_acl: u32,
    pub size_high_or_dir_acl: u32,
    pub faddr: u32,
    pub osd2: [u8; 12],
}

/// Directory entry header (on-disk format)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2DirEntryHead {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

#[derive(Clone, Copy)]
struct GroupDescWriteTarget {
    block: u32,
    offset: usize,
}

struct Ext2Journal {
    /// Logical journal block -> physical filesystem block.
    blocks: Vec<u32>,
    /// Indirect blocks that make the journal inode's logical mapping possible.
    /// They are journal-owned metadata too and must never be allocated as file
    /// data or accepted as replay homes, even if a corrupt bitmap marks them
    /// free.
    mapping_blocks: Vec<u32>,
    /// Sorted union of data and mapping blocks for bounded binary membership
    /// checks and group-local reserved-bit validation.
    owned_blocks: Vec<u32>,
    max_len: u32,
    first: u32,
    next_sequence: u32,
    start: u32,
    uuid: [u8; 16],
    feature_incompat: u32,
}

impl Ext2Journal {
    /// Empty ownership context for a plain, explicitly read-only ext2 image.
    /// Virtual reads fall through to physical blocks and no blocks are reserved
    /// as journal-owned, while the same complete ownership graph is still built.
    fn plain_image() -> Self {
        Self {
            blocks: Vec::new(),
            mapping_blocks: Vec::new(),
            owned_blocks: Vec::new(),
            max_len: 0,
            first: 0,
            next_sequence: 0,
            start: 0,
            uuid: [0; 16],
            feature_incompat: 0,
        }
    }

    #[inline]
    fn physical(&self, logical: u32) -> Result<u32, FsError> {
        if logical >= self.max_len {
            return Err(FsError::Invalid);
        }
        self.blocks
            .get(logical as usize)
            .copied()
            .ok_or(FsError::Invalid)
    }

    #[inline]
    fn advance(&self, logical: u32, count: u32) -> Result<u32, FsError> {
        if logical < self.first || logical >= self.max_len || self.first >= self.max_len {
            return Err(FsError::Invalid);
        }
        let span = self.max_len - self.first;
        let relative = logical - self.first;
        let advanced = relative.checked_add(count % span).ok_or(FsError::Invalid)? % span;
        self.first.checked_add(advanced).ok_or(FsError::Invalid)
    }

    #[inline]
    fn contains_physical(&self, block: u32) -> bool {
        self.owned_blocks.binary_search(&block).is_ok()
    }
}

struct JournalRecoveryScratch {
    control: Ext2MutationScratch,
    data: Ext2MutationScratch,
}

impl JournalRecoveryScratch {
    fn try_new(block_size: u32) -> Result<Self, FsError> {
        Ok(Self {
            control: Ext2MutationScratch::try_new(block_size)?,
            data: Ext2MutationScratch::try_new(block_size)?,
        })
    }
}

#[derive(Clone, Copy)]
struct JournalOverlayEntry {
    home: u32,
    log: u32,
    flags: u16,
    order: u32,
    image_offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryHomeKind {
    Superblock,
    GroupDescriptors,
    BlockBitmap(usize),
    InodeTable(usize),
}

struct JournalRecoveryPlan {
    next_sequence: u32,
    overlay: Vec<JournalOverlayEntry>,
    /// Immutable, block-sized post-images indexed by `image_offset`.
    /// The accepted writer grammar contains at most four metadata blocks, so
    /// this remains a small, explicitly bounded recovery allocation.
    post_images: Vec<u8>,
    intent: Option<JournalCommitIntent>,
}

#[derive(Clone, Copy)]
struct JournalCommitIntent {
    kind: u8,
    metadata_count: u8,
    inode_number: u32,
    file_block: u32,
    physical: u32,
    preimage_hashes: [[u8; 32]; JOURNAL_MAX_METADATA_BLOCKS],
    old_inode: Ext2InodeRaw,
}

struct OwnershipWork {
    owners: Vec<u32>,
    mapping_bytes: usize,
    inode_count: u32,
    bitmap_bytes: usize,
    inode_table_bytes: usize,
}

impl OwnershipWork {
    fn try_new() -> Result<Self, FsError> {
        let mut owners = Vec::new();
        owners.try_reserve_exact(1024).map_err(|_| FsError::NoMem)?;
        Ok(Self {
            owners,
            mapping_bytes: 0,
            inode_count: 0,
            bitmap_bytes: 0,
            inode_table_bytes: 0,
        })
    }

    fn push_owner(&mut self, physical: u32) -> Result<(), FsError> {
        if self.owners.len() >= MAX_OWNERSHIP_REFERENCES {
            return Err(FsError::NotSupported);
        }
        if self.owners.len() == self.owners.capacity() {
            self.owners.try_reserve(1).map_err(|_| FsError::NoMem)?;
        }
        self.owners.push(physical);
        Ok(())
    }

    fn account_mapping_block(&mut self, block_size: usize) -> Result<(), FsError> {
        self.mapping_bytes = self
            .mapping_bytes
            .checked_add(block_size)
            .filter(|bytes| *bytes <= MAX_OWNERSHIP_MAPPING_BYTES)
            .ok_or(FsError::NotSupported)?;
        Ok(())
    }

    fn account_bitmap(&mut self, bytes: usize) -> Result<(), FsError> {
        self.bitmap_bytes = self
            .bitmap_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_OWNERSHIP_BITMAP_BYTES)
            .ok_or(FsError::NotSupported)?;
        Ok(())
    }

    fn account_inode_table(&mut self, bytes: usize) -> Result<(), FsError> {
        self.inode_table_bytes = self
            .inode_table_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_OWNERSHIP_INODE_TABLE_BYTES)
            .ok_or(FsError::NotSupported)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SparseGapTarget {
    physical: u32,
    start: u32,
    end: u32,
}

const _: () = assert!(size_of::<SparseGapTarget>() == 12);

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct SparseGapCounts {
    mapping_nodes: usize,
    branch_nodes: usize,
    data_targets: usize,
    boundary_targets: usize,
}

impl SparseGapCounts {
    #[inline]
    fn account_mapping_node(&mut self, branch: Option<u16>) -> Result<(), FsError> {
        if self.mapping_nodes >= MAX_SPARSE_GAP_MAPPING_NODES {
            return Err(FsError::NoMem);
        }
        self.mapping_nodes += 1;
        if branch.is_some() {
            self.branch_nodes = self.branch_nodes.checked_add(1).ok_or(FsError::NoMem)?;
        }
        Ok(())
    }

    #[inline]
    fn account_data_target(
        &mut self,
        target: SparseGapTarget,
        block_size: u32,
    ) -> Result<(), FsError> {
        if self.data_targets >= MAX_SPARSE_GAP_DATA_BLOCKS {
            return Err(FsError::NoMem);
        }
        self.data_targets += 1;
        if target.start != 0 || target.end != block_size {
            if self.boundary_targets >= 2 {
                return Err(FsError::Invalid);
            }
            self.boundary_targets += 1;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SparseGapBranch {
    index: u32,
    physical: u32,
}

const _: () = assert!(size_of::<SparseGapBranch>() == 8);

fn checked_heap_charge_sum(left: usize, right: usize) -> Result<usize, FsError> {
    left.checked_add(right).ok_or(FsError::NoMem)
}

fn sparse_gap_backing_charge_bytes(
    mapping_capacity: usize,
    target_capacity: usize,
    branch_capacity: usize,
) -> Result<usize, FsError> {
    let nodes = mm::vec_charge_bytes::<u32>(mapping_capacity).map_err(|_| FsError::NoMem)?;
    let targets = mm::vec_charge_bytes::<u32>(target_capacity).map_err(|_| FsError::NoMem)?;
    let branches = mm::vec_charge_bytes::<u16>(branch_capacity).map_err(|_| FsError::NoMem)?;
    checked_heap_charge_sum(checked_heap_charge_sum(nodes, targets)?, branches)
}

fn sparse_gap_plan_charge_bytes(counts: SparseGapCounts) -> Result<usize, FsError> {
    if counts.branch_nodes > counts.mapping_nodes || counts.boundary_targets > 2 {
        return Err(FsError::Invalid);
    }
    if counts.mapping_nodes > MAX_SPARSE_GAP_MAPPING_NODES
        || counts.data_targets > MAX_SPARSE_GAP_DATA_BLOCKS
    {
        return Err(FsError::NoMem);
    }
    sparse_gap_backing_charge_bytes(
        counts.mapping_nodes,
        counts.data_targets,
        counts.branch_nodes,
    )
}

fn sparse_gap_max_live_charge_bytes(block_size: u32) -> Result<usize, FsError> {
    let block_size = Ext2MutationScratch::validated_block_size(block_size)?;
    let block = mm::vec_charge_bytes::<u8>(block_size).map_err(|_| FsError::NoMem)?;
    let validation_branches = mm::vec_charge_bytes::<SparseGapBranch>(MAX_SPARSE_GAP_MAPPING_NODES)
        .map_err(|_| FsError::NoMem)?;
    let validation = checked_heap_charge_sum(
        block.checked_mul(2).ok_or(FsError::NoMem)?,
        validation_branches,
    )?;
    let collection = checked_heap_charge_sum(
        block,
        sparse_gap_plan_charge_bytes(SparseGapCounts {
            mapping_nodes: MAX_SPARSE_GAP_MAPPING_NODES,
            branch_nodes: MAX_SPARSE_GAP_MAPPING_NODES,
            data_targets: MAX_SPARSE_GAP_DATA_BLOCKS,
            boundary_targets: 2,
        })?,
    )?;
    Ok(validation.max(collection))
}

/// Traversal-only storage.  The bitmap backing is admitted at construction;
/// double-indirect branch backing is admitted and allocated only after the
/// validated root block reveals the exact number of present branches.  The
/// backing fields are dropped before the reservation.
struct SparseGapTraversalScratch {
    bitmap: Ext2MutationScratch,
    branches: Vec<SparseGapBranch>,
    reservation: HeapReservation,
}

impl SparseGapTraversalScratch {
    fn try_new(block_size: u32) -> Result<Self, FsError> {
        let block_size_usize = Ext2MutationScratch::validated_block_size(block_size)?;
        let block_charge =
            mm::vec_charge_bytes::<u8>(block_size_usize).map_err(|_| FsError::NoMem)?;
        // Declare the reservation first so every subsequently allocated local
        // is destroyed before rollback on an error return.
        let mut reservation = mm::try_reserve_heap(HeapClass::FilesystemIo, block_charge)
            .map_err(|_| FsError::NoMem)?;
        let bitmap = Ext2MutationScratch::try_new(block_size).map_err(|_| FsError::NoMem)?;
        let actual_blocks =
            mm::vec_charge_bytes::<u8>(bitmap.capacity()).map_err(|_| FsError::NoMem)?;
        reservation
            .resize(actual_blocks)
            .map_err(|_| FsError::NoMem)?;
        Ok(Self {
            bitmap,
            branches: Vec::new(),
            reservation,
        })
    }

    /// RF180-35 FIX: reserve the worst allocator footprint before requesting
    /// backing, but request only the exact number of live double-indirect
    /// branches.  Eagerly allocating all 4,096 entries made a direct-block
    /// write request a contiguous 32 KiB allocation and panicked late in the
    /// runtime suite despite correct aggregate admission.
    fn prepare_branches(&mut self, count: usize) -> Result<(), FsError> {
        if count > MAX_SPARSE_GAP_MAPPING_NODES {
            return Err(FsError::NoMem);
        }

        self.branches.clear();
        let bitmap_charge =
            mm::vec_charge_bytes::<u8>(self.bitmap.capacity()).map_err(|_| FsError::NoMem)?;
        if count == 0 {
            // A scratch object is currently single-use, but make reuse exact:
            // release any old branch backing before releasing its admission.
            self.branches = Vec::new();
            self.reservation
                .resize(bitmap_charge)
                .map_err(|_| FsError::NoMem)?;
            return Ok(());
        }

        let maximum_branch_charge =
            mm::vec_charge_bytes::<SparseGapBranch>(MAX_SPARSE_GAP_MAPPING_NODES)
                .map_err(|_| FsError::NoMem)?;
        let maximum_charge = checked_heap_charge_sum(bitmap_charge, maximum_branch_charge)?;
        self.reservation
            .resize(maximum_charge)
            .map_err(|_| FsError::NoMem)?;

        self.branches
            .try_reserve_exact(count)
            .map_err(|_| FsError::NoMem)?;
        if self.branches.capacity() > MAX_SPARSE_GAP_MAPPING_NODES {
            return Err(FsError::NoMem);
        }
        let actual_branch_charge =
            mm::vec_charge_bytes::<SparseGapBranch>(self.branches.capacity())
                .map_err(|_| FsError::NoMem)?;
        let actual_charge = checked_heap_charge_sum(bitmap_charge, actual_branch_charge)?;
        if actual_charge > maximum_charge {
            return Err(FsError::NoMem);
        }
        self.reservation
            .resize(actual_charge)
            .map_err(|_| FsError::NoMem)
    }
}

struct SparseGapPlan {
    targets: Vec<u32>,
    boundaries: [Option<SparseGapTarget>; 2],
    _reservation: HeapReservation,
}

#[inline]
fn sparse_gap_target_bounds(
    boundaries: &[Option<SparseGapTarget>; 2],
    physical: u32,
    block_size: u32,
) -> (usize, usize) {
    boundaries
        .iter()
        .flatten()
        .find(|boundary| boundary.physical == physical)
        .map_or((0, block_size as usize), |boundary| {
            (boundary.start as usize, boundary.end as usize)
        })
}

trait SparseGapVisitor {
    fn mapping_node(&mut self, physical: u32, branch: Option<u16>) -> Result<(), FsError>;
    fn data_target(&mut self, file_block: u32, target: SparseGapTarget) -> Result<(), FsError>;
}

/// Allocation-free, domain-separated commitment to one ordered sparse-gap
/// traversal.  The transcript binds physical IDs, logical file positions,
/// partial-block bounds, and double-indirect branch identity.  Comparing the
/// two pass digests prevents a mutable or faulty block device from replacing a
/// validated pointer tree with a same-shape tree before persistence begins.
struct SparseGapTranscript {
    hasher: Sha256,
}

impl SparseGapTranscript {
    fn new(block_size: u32, gap_start: u64, gap_end: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SPARSE_GAP_TRANSCRIPT_DOMAIN);
        hasher.update(&block_size.to_le_bytes());
        hasher.update(&gap_start.to_le_bytes());
        hasher.update(&gap_end.to_le_bytes());
        Self { hasher }
    }

    fn mapping_node(&mut self, physical: u32, branch: Option<u16>) {
        self.hasher.update(&[b'M']);
        self.hasher.update(&physical.to_le_bytes());
        match branch {
            Some(branch) => {
                self.hasher.update(&[1]);
                self.hasher.update(&branch.to_le_bytes());
            }
            None => {
                self.hasher.update(&[0]);
                self.hasher.update(&0u16.to_le_bytes());
            }
        }
    }

    fn data_target(&mut self, file_block: u32, target: SparseGapTarget) {
        self.hasher.update(&[b'D']);
        self.hasher.update(&file_block.to_le_bytes());
        self.hasher.update(&target.physical.to_le_bytes());
        self.hasher.update(&target.start.to_le_bytes());
        self.hasher.update(&target.end.to_le_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

struct SparseGapCountVisitor {
    counts: SparseGapCounts,
    block_size: u32,
    transcript: SparseGapTranscript,
}

impl SparseGapVisitor for SparseGapCountVisitor {
    fn mapping_node(&mut self, physical: u32, branch: Option<u16>) -> Result<(), FsError> {
        self.counts.account_mapping_node(branch)?;
        self.transcript.mapping_node(physical, branch);
        Ok(())
    }

    fn data_target(&mut self, file_block: u32, target: SparseGapTarget) -> Result<(), FsError> {
        self.counts.account_data_target(target, self.block_size)?;
        self.transcript.data_target(file_block, target);
        Ok(())
    }
}

struct SparseGapCollectVisitor<'a> {
    mapping_nodes: &'a mut Vec<u32>,
    branch_indices: &'a mut Vec<u16>,
    targets: &'a mut Vec<u32>,
    boundaries: &'a mut [Option<SparseGapTarget>; 2],
    block_size: u32,
    expected: SparseGapCounts,
    transcript: SparseGapTranscript,
}

impl SparseGapVisitor for SparseGapCollectVisitor<'_> {
    // lint-fallible-fn: PREALLOCATED(mapping_nodes/branch_indices reserved to self.expected.* in the plan phase; len bound-checked before each push)
    fn mapping_node(&mut self, physical: u32, branch: Option<u16>) -> Result<(), FsError> {
        if self.mapping_nodes.len() >= self.expected.mapping_nodes {
            return Err(FsError::Invalid);
        }
        self.mapping_nodes.push(physical);
        if let Some(branch) = branch {
            if self.branch_indices.len() >= self.expected.branch_nodes {
                return Err(FsError::Invalid);
            }
            self.branch_indices.push(branch);
        }
        self.transcript.mapping_node(physical, branch);
        Ok(())
    }

    // lint-fallible-fn: PREALLOCATED(targets reserved to self.expected.data_targets in the plan phase; len bound-checked before push)
    fn data_target(&mut self, file_block: u32, target: SparseGapTarget) -> Result<(), FsError> {
        if self.targets.len() >= self.expected.data_targets {
            return Err(FsError::Invalid);
        }
        self.targets.push(target.physical);
        if target.start != 0 || target.end != self.block_size {
            let slot = self
                .boundaries
                .iter_mut()
                .find(|boundary| boundary.is_none())
                .ok_or(FsError::Invalid)?;
            *slot = Some(target);
        }
        self.transcript.data_target(file_block, target);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DirectAllocationPlan {
    inode_number: u32,
    file_block: u32,
    phys_block: u32,
    bitmap_block: u32,
    bitmap_byte: usize,
    bitmap_mask: u8,
    group: usize,
    group_desc_target: GroupDescWriteTarget,
    old_group_desc: Ext2GroupDesc,
    new_group_desc: Ext2GroupDesc,
    old_superblock: Ext2Superblock,
    new_superblock: Ext2Superblock,
    inode_target: InodeWriteTarget,
    old_inode: Ext2InodeRaw,
    new_inode: Ext2InodeRaw,
}

#[derive(Clone, Copy)]
enum JournalMetadataPlan {
    DirectAllocation(DirectAllocationPlan),
    InodeUpdate {
        inode_number: u32,
        inode_target: InodeWriteTarget,
        old_inode: Ext2InodeRaw,
        new_inode: Ext2InodeRaw,
    },
}

impl JournalMetadataPlan {
    #[inline]
    fn metadata_blocks(self) -> usize {
        match self {
            Self::DirectAllocation(_) => JOURNAL_MAX_METADATA_BLOCKS,
            Self::InodeUpdate { .. } => 1,
        }
    }
}

#[derive(Clone, Copy)]
struct JournalTxFailure {
    error: FsError,
    committed: bool,
    poison: bool,
}

// ============================================================================
// Ext2 Filesystem
// ============================================================================

/// R106-6 FIX: Centralized sector-size validation.
///
/// Returns the device sector size as `u64` after verifying:
/// - Non-zero (prevents division-by-zero in `read_super`, `read_block`, etc.)
/// - Power-of-two (hardware sector sizes are always powers of two)
///
/// This replaces ad-hoc inline checks that were present only in `read_bgdt`
/// while `read_super`, `read_block`, `write_block`, and `write_superblock`
/// divided by sector_size without any validation.
#[inline]
fn validated_sector_size(dev: &dyn BlockDevice) -> Result<u64, FsError> {
    let sector_size = dev.sector_size() as u64;
    if sector_size == 0 || sector_size > 65536 || !sector_size.is_power_of_two() {
        return Err(FsError::Invalid);
    }
    Ok(sector_size)
}

/// RF178-37 FIX: per-filesystem canonical object cache.
///
/// The cache holds only `Weak` references, so inode lifetimes remain driven by
/// VFS users. A separate miss mutex serializes load/construct/publish without
/// holding the cache lock across disk I/O. Growth is allocation-fallible and
/// stale entries are compacted in place before publication.
struct WeakArcCache<T> {
    entries: RwLock<mm::fallible_map::FallibleOrderedMap<u32, Weak<T>>>,
    miss: Mutex<()>,
}

impl<T> WeakArcCache<T> {
    fn new() -> Self {
        Self {
            entries: RwLock::new(mm::fallible_map::FallibleOrderedMap::new()),
            miss: Mutex::new(()),
        }
    }

    #[inline]
    fn get(&self, key: u32) -> Option<Arc<T>> {
        self.entries
            .read()
            .get(&key)
            .and_then(|weak| weak.upgrade())
    }

    fn get_or_try_insert_with<F>(&self, key: u32, loader: F) -> Result<Arc<T>, FsError>
    where
        F: FnOnce() -> Result<Arc<T>, FsError>,
    {
        if let Some(existing) = self.get(key) {
            return Ok(existing);
        }

        let _miss = self.miss.lock();
        if let Some(existing) = self.get(key) {
            return Ok(existing);
        }

        {
            let mut entries = self.entries.write();
            entries.retain(|_, weak| weak.strong_count() != 0);
        }

        // No cache guard spans the loader: ext2 inode reads acquire filesystem
        // metadata/device locks below the serialized miss lane.
        let candidate = loader()?;

        let mut entries = self.entries.write();
        if let Some(existing) = entries.get(&key).and_then(|weak| weak.upgrade()) {
            return Ok(existing);
        }
        entries.retain(|_, weak| weak.strong_count() != 0);
        entries.try_reserve_exact(1).map_err(|_| FsError::NoMem)?;
        entries
            .try_insert(key, Arc::downgrade(&candidate))
            .map_err(|_| FsError::NoMem)?;
        Ok(candidate)
    }
}

/// Cache lifecycle probes plus a deterministic production `Ext2Inode::open`
/// identity check. The latter uses the exact constructor helper and cache owned
/// by `Ext2Fs`; it does not depend on an ext2 image being mounted at boot.
#[doc(hidden)]
pub fn run_ext2_inode_cache_self_test() {
    struct CacheNode {
        value: AtomicU64,
    }

    let cache: WeakArcCache<CacheNode> = WeakArcCache::new();
    let mut loads = 0usize;
    let first = cache
        .get_or_try_insert_with(7, || {
            loads += 1;
            assert!(
                cache.miss.try_lock().is_none(),
                "inode cache misses must be serialized"
            );
            assert!(
                cache.entries.try_read().is_some(),
                "cache guard must not span inode loader I/O"
            );
            Arc::try_new(CacheNode {
                value: AtomicU64::new(11),
            })
            .map_err(|_| FsError::NoMem)
        })
        .expect("first canonical cache load");
    let second = cache
        .get_or_try_insert_with(7, || panic!("cache hit must not invoke loader"))
        .expect("second canonical cache lookup");
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(
        loads, 1,
        "canonical inode loader must run once per live key"
    );
    first.value.store(29, Ordering::Release);
    assert_eq!(second.value.load(Ordering::Acquire), 29);

    let other = cache
        .get_or_try_insert_with(8, || {
            Arc::try_new(CacheNode {
                value: AtomicU64::new(8),
            })
            .map_err(|_| FsError::NoMem)
        })
        .expect("distinct inode cache load");
    assert!(!Arc::ptr_eq(&first, &other));

    let stale = Arc::downgrade(&other);
    drop(other);
    assert!(stale.upgrade().is_none());
    let replacement = cache
        .get_or_try_insert_with(8, || {
            Arc::try_new(CacheNode {
                value: AtomicU64::new(80),
            })
            .map_err(|_| FsError::NoMem)
        })
        .expect("stale cache replacement");
    assert_eq!(replacement.value.load(Ordering::Acquire), 80);

    let retry_cache: WeakArcCache<CacheNode> = WeakArcCache::new();
    assert!(matches!(
        retry_cache.get_or_try_insert_with(9, || Err(FsError::Io)),
        Err(FsError::Io)
    ));
    assert!(
        retry_cache.get(9).is_none(),
        "loader error must publish nothing"
    );
    assert!(retry_cache
        .get_or_try_insert_with(9, || {
            Arc::try_new(CacheNode {
                value: AtomicU64::new(9),
            })
            .map_err(|_| FsError::NoMem)
        })
        .is_ok());

    struct CacheTestDevice;

    impl BlockDevice for CacheTestDevice {
        fn name(&self) -> &str {
            "ext2-cache-self-test"
        }

        fn capacity_sectors(&self) -> u64 {
            1
        }

        fn submit_bio(&self, _bio: block::Bio) -> Result<(), block::BlockError> {
            Err(block::BlockError::NotSupported)
        }
    }

    let concrete_dev = Arc::try_new(CacheTestDevice).expect("cache test block device");
    let dev: Arc<dyn BlockDevice> = concrete_dev;
    // SAFETY: Ext2Superblock contains only integer fields and byte arrays, for
    // which the all-zero bit pattern is valid. The synthetic filesystem never
    // performs disk I/O or consults this placeholder superblock.
    let superblock: Ext2Superblock = unsafe { core::mem::zeroed() };
    let fs = Arc::try_new(Ext2Fs {
        fs_id: u64::MAX - 178,
        dev,
        superblock: RwLock::new(superblock),
        group_descs: RwLock::new(Vec::new()),
        block_size: 4096,
        sector_size: 512,
        blocks_count: 1,
        blocks_per_group: 1,
        inodes_per_group: 1,
        inode_size: size_of::<Ext2InodeRaw>() as u16,
        root: RwLock::new(None),
        inode_cache: WeakArcCache::new(),
        meta_lock: Mutex::new(()),
        journal: Mutex::new(None),
        resize_reserved_blocks: RwLock::new(Vec::new()),
        io_faulted: AtomicBool::new(false),
        self_ref: Mutex::new(None),
    })
    .expect("synthetic ext2 filesystem");

    let mut raw = Ext2InodeRaw::default();
    raw.mode = EXT2_S_IFREG | 0o644;
    raw.links_count = 1;
    let canonical = fs
        .inode_cache
        .get_or_try_insert_with(42, || fs.new_inode_from_raw(42, raw))
        .expect("publish canonical production inode");
    let same = fs
        .inode_cache
        .get_or_try_insert_with(42, || panic!("live production cache hit must not reload"))
        .expect("retrieve canonical production inode");
    assert!(Arc::ptr_eq(&canonical, &same));

    let first_open = canonical
        .clone()
        .open(
            OpenFlags::new(OpenFlags::O_RDONLY),
            PreparedFileHandle::try_new().expect("first ext2 open preparation"),
        )
        .expect("first canonical production open");
    let second_open = same
        .open(
            OpenFlags::new(OpenFlags::O_RDONLY),
            PreparedFileHandle::try_new().expect("second ext2 open preparation"),
        )
        .expect("second canonical production open");
    let first_handle = first_open
        .as_any()
        .downcast_ref::<FileHandle>()
        .expect("first ext2 open must return FileHandle");
    let second_handle = second_open
        .as_any()
        .downcast_ref::<FileHandle>()
        .expect("second ext2 open must return FileHandle");
    let canonical_inode: Arc<dyn Inode> = canonical.clone();
    assert!(Arc::ptr_eq(&first_handle.inode, &canonical_inode));
    assert!(Arc::ptr_eq(&second_handle.inode, &canonical_inode));
    assert!(Arc::ptr_eq(&first_handle.inode, &second_handle.inode));

    let rogue = fs
        .new_inode_from_raw(42, raw)
        .expect("construct duplicate wrapper for rejection probe");
    assert!(matches!(
        rogue.open(
            OpenFlags::new(OpenFlags::O_RDONLY),
            PreparedFileHandle::try_new().expect("rogue ext2 open preparation"),
        ),
        Err(FsError::Invalid)
    ));
}

/// Ext2 filesystem instance
pub struct Ext2Fs {
    fs_id: u64,
    dev: Arc<dyn BlockDevice>,
    /// Superblock (protected for write updates)
    superblock: RwLock<Ext2Superblock>,
    /// Block group descriptor table
    group_descs: RwLock<Vec<Ext2GroupDesc>>,
    block_size: u32,
    /// R106-6 FIX: Cached validated sector size.  Validated once at mount time
    /// to be non-zero and power-of-two.  Instance methods use this instead of
    /// calling `dev.sector_size()` directly, eliminating division-by-zero risk.
    sector_size: u64,
    /// R99-4 FIX: Cached immutable copy of `blocks_count` for lock-free block
    /// validation.  In ext2 the total block count is fixed at mkfs time.
    blocks_count: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    root: RwLock<Option<Arc<Ext2Inode>>>,
    /// Canonical `(filesystem, inode-number) -> Arc<Ext2Inode>` identity.
    inode_cache: WeakArcCache<Ext2Inode>,
    /// Serialize metadata updates requiring read-modify-write
    meta_lock: Mutex<()>,
    /// Validated internal JBD2 journal. `None` is rigorously read-only: no
    /// data write may begin without a redo-log transaction for its inode home.
    journal: Mutex<Option<Ext2Journal>>,
    /// Validated block set owned by the resize inode (including its indirect
    /// mapping nodes). These remain reserved even if a corrupt block bitmap
    /// advertises them as free.
    resize_reserved_blocks: RwLock<Vec<u32>>,
    /// Sticky same-boot fail-stop after an ambiguous in-place write result.
    /// Fallible metadata and data operations are rejected until remount instead
    /// of trusting stale inode/page-cache state.
    io_faulted: AtomicBool,
    self_ref: Mutex<Option<Weak<Ext2Fs>>>,
}

impl Ext2Fs {
    #[inline]
    fn ensure_io_healthy(&self) -> Result<(), FsError> {
        if self.io_faulted.load(Ordering::Acquire) {
            Err(FsError::Io)
        } else {
            Ok(())
        }
    }

    /// Mount an ext2 filesystem from a block device
    pub fn mount(dev: Arc<dyn BlockDevice>) -> Result<Arc<Self>, FsError> {
        // Read superblock
        let (superblock, block_size) = Self::read_super(&dev)?;

        // R106-6 FIX: Validate sector size early and cache it.
        // This ensures all subsequent I/O methods can divide by sector_size safely.
        let sector_size = validated_sector_size(&*dev)?;
        if (block_size as u64) % sector_size != 0 {
            return Err(FsError::Invalid);
        }
        let device_bytes = dev
            .capacity_sectors()
            .checked_mul(sector_size)
            .ok_or(FsError::Invalid)?;
        let filesystem_bytes = (superblock.blocks_count as u64)
            .checked_mul(block_size as u64)
            .ok_or(FsError::Invalid)?;
        if device_bytes < filesystem_bytes {
            return Err(FsError::Invalid);
        }

        // Load block group descriptors
        let group_descs = Self::load_group_descs(&dev, &superblock, block_size)?;

        let inode_size = if superblock.rev_level >= 1 {
            let raw = superblock.inode_size;
            let raw32 = raw as u32;

            // R100-3 FIX: Validate on-disk inode_size from untrusted superblock.
            //  - Must be at least the base on-disk inode structure (128 bytes)
            //  - Must not exceed block_size (inodes cannot span blocks)
            //  - block_size must be evenly divisible by inode_size (no partial
            //    inodes at end of inode-table block)
            if raw32 < size_of::<Ext2InodeRaw>() as u32
                || raw32 > block_size
                || block_size % raw32 != 0
            {
                return Err(FsError::Invalid);
            }

            raw
        } else {
            128 // Rev 0 uses fixed 128-byte inodes
        };

        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| FsError::NoSpace)?;

        let fs = Arc::try_new(Self {
            fs_id,
            dev,
            superblock: RwLock::new(superblock),
            group_descs: RwLock::new(group_descs),
            block_size,
            sector_size,
            blocks_count: superblock.blocks_count,
            blocks_per_group: superblock.blocks_per_group,
            inodes_per_group: superblock.inodes_per_group,
            inode_size,
            root: RwLock::new(None),
            inode_cache: WeakArcCache::new(),
            meta_lock: Mutex::new(()),
            journal: Mutex::new(None),
            resize_reserved_blocks: RwLock::new(Vec::new()),
            io_faulted: AtomicBool::new(false),
            self_ref: Mutex::new(None),
        })
        .map_err(|_| FsError::NoMem)?;

        // Store self reference
        *fs.self_ref.lock() = Some(Arc::downgrade(&fs));

        fs.initialize_resize_inode_reservations()?;

        // R180-6 FIX: recover an active internal journal before the root inode
        // or filesystem object can be published to VFS callers.
        fs.initialize_journal()?;

        // Load root inode
        let root = fs.load_inode(EXT2_ROOT_INO)?;
        *fs.root.write() = Some(root);

        Ok(fs)
    }

    /// Read and validate superblock
    fn read_super(dev: &Arc<dyn BlockDevice>) -> Result<(Ext2Superblock, u32), FsError> {
        // R106-6 FIX: Use validated_sector_size() instead of raw cast.
        let sector_size = validated_sector_size(&**dev)?;
        let start_sector = SUPERBLOCK_OFFSET / sector_size;
        let offset_in_sector =
            usize::try_from(SUPERBLOCK_OFFSET % sector_size).map_err(|_| FsError::Invalid)?;
        let bytes_needed = offset_in_sector
            .checked_add(size_of::<Ext2Superblock>())
            .ok_or(FsError::Invalid)?;
        let sector_size_usize = usize::try_from(sector_size).map_err(|_| FsError::Invalid)?;
        let sectors_needed = bytes_needed
            .checked_add(sector_size_usize - 1)
            .ok_or(FsError::Invalid)?
            / sector_size_usize;
        let read_len = sectors_needed
            .checked_mul(sector_size_usize)
            .ok_or(FsError::Invalid)?;

        // R178-29 FIX: Fallible superblock buffer allocation (1024 bytes).
        // Mount is a recoverable path — OOM here returns FsError::NoSpace instead of aborting.
        let mut buf = Vec::new();
        buf.try_reserve_exact(read_len)
            .map_err(|_| FsError::NoSpace)?;
        buf.resize(read_len, 0u8);
        let read = dev
            .read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;
        if read != buf.len() {
            return Err(FsError::Io);
        }

        // Parse superblock
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        // Vec<u8> only guarantees 1-byte alignment, not the 4-byte alignment
        // that Ext2Superblock requires.
        let super_bytes = buf
            .get(offset_in_sector..bytes_needed)
            .ok_or(FsError::Invalid)?;
        let sb: Ext2Superblock =
            unsafe { core::ptr::read_unaligned(super_bytes.as_ptr() as *const _) };

        // Validate magic
        if sb.magic != EXT2_SUPER_MAGIC {
            return Err(FsError::Invalid);
        }
        if sb.feature_incompat & !EXT2_SUPPORTED_INCOMPAT != 0 {
            return Err(FsError::NotSupported);
        }
        let has_journal = (sb.feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0;
        if (sb.feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER) != 0 && !has_journal {
            return Err(FsError::Invalid);
        }
        if !dev.is_read_only() && !has_journal {
            // RF180-13 FIX: plain Ext2 has no redo log with which to make the
            // ordered data write and the following inode-table update one
            // crash-consistent operation.  Same-boot poisoning cannot repair
            // an already durable data mutation after power loss, so writable
            // devices fail closed at mount.  A block device explicitly
            // exported read-only remains fully usable for inspection.
            return Err(FsError::NotSupported);
        }
        if !dev.is_read_only() && sb.feature_ro_compat & !EXT3_SUPPORTED_RO_COMPAT != 0 {
            // RO_COMPAT means an implementation that does not understand the
            // bit may inspect the image read-only, but must never update it.
            // This applies equally to plain Ext2 and journaled Ext3 images.
            return Err(FsError::NotSupported);
        }
        if sb.last_orphan != 0 {
            // An outstanding orphan chain represents an interrupted truncate
            // or unlink.  This implementation does not yet own that recovery
            // protocol, so even a journaled image must fail closed.
            return Err(FsError::NotSupported);
        }
        if has_journal && (sb.rev_level < 1 || sb.journal_inum == 0 || sb.journal_dev != 0) {
            // Only the standard internal journal inode is supported. External
            // journals require a second independently ordered block device.
            return Err(FsError::NotSupported);
        }

        // R96-2 FIX: Use checked_shl to prevent overflow on crafted log_block_size.
        // A malicious superblock with log_block_size >= 22 would cause panic.
        let block_size = 1024u32
            .checked_shl(sb.log_block_size)
            .ok_or(FsError::Invalid)?;

        // Validate block size (1K-64K)
        if block_size < 1024 || block_size > 65536 {
            return Err(FsError::Invalid);
        }

        // R97-2 FIX: Validate first_data_block consistency with block_size.
        //
        // Per ext2 specification:
        // - For 1KiB block size: first_data_block MUST be 1 (boot block + superblock occupy block 0-1)
        // - For larger block sizes: first_data_block MUST be 0 (superblock fits in block 0)
        //
        // Mismatched values indicate either corruption or a malicious image attempting
        // to exploit block-group geometry calculations.
        let expected_first_data_block = if block_size == 1024 { 1 } else { 0 };
        if sb.first_data_block != expected_first_data_block {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-1 FIX: Validate critical superblock fields to prevent DoS.
        //
        // A malicious superblock can cause:
        // - Division by zero if blocks_per_group or inodes_per_group is 0
        // - Massive allocation if groups_count is unbounded
        // - Out-of-bounds access via crafted group descriptors
        //
        // Minimum reasonable values:
        // - blocks_per_group: at least 8 blocks (8 * 1024 = 8KB minimum)
        // - inodes_per_group: at least 1 inode
        // - blocks_count: at least 1 block
        if sb.blocks_per_group == 0 || sb.blocks_per_group < 8 {
            return Err(FsError::Invalid);
        }
        if sb.inodes_per_group == 0 || sb.inodes_count < EXT2_ROOT_INO {
            return Err(FsError::Invalid);
        }
        if sb.blocks_count == 0 {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-4 FIX: Validate blocks_per_group/inodes_per_group against bitmap capacity.
        //
        // Each block bitmap and inode bitmap is exactly one block in size.
        // A block can only describe block_size * 8 entries (1 bit per entry).
        // Values beyond this limit describe on-disk bitmaps inconsistently and
        // can drive later metadata readers beyond their validated buffers.
        let max_bitmap_entries = block_size.saturating_mul(8);
        if sb.blocks_per_group > max_bitmap_entries || sb.inodes_per_group > max_bitmap_entries {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-2 FIX: Bound groups_count to prevent memory exhaustion.
        //
        // Maximum practical limit: 64K groups (each group desc is 32 bytes = 2MB total).
        // This allows filesystems up to 64K * 128MB = 8TB (with 128MB per group).
        //
        // R96-2 FIX: Use checked arithmetic to prevent overflow on crafted blocks_count.
        // A malicious superblock with blocks_count near u32::MAX could overflow.
        let groups_count = sb
            .blocks_count
            .checked_sub(sb.first_data_block)
            .ok_or(FsError::Invalid)?
            .checked_add(sb.blocks_per_group - 1)
            .ok_or(FsError::Invalid)?
            / sb.blocks_per_group;
        let inode_groups = sb
            .inodes_count
            .checked_add(sb.inodes_per_group - 1)
            .ok_or(FsError::Invalid)?
            / sb.inodes_per_group;
        if groups_count == 0 || groups_count > MAX_EXT2_GROUPS || inode_groups > groups_count {
            return Err(FsError::Invalid);
        }

        Ok((sb, block_size))
    }

    fn initialize_journal(self: &Arc<Self>) -> Result<(), FsError> {
        let sb = *self.superblock.read();
        if (sb.feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) == 0 {
            // R186-7: an explicitly read-only plain ext2 image still needs the
            // same complete ownership proof. Otherwise two allocated inodes may
            // alias data/metadata blocks and disclose another object's contents.
            let plain = Ext2Journal::plain_image();
            return self.validate_block_ownership(&plain, &[], &[]);
        }

        let journal_inode = self.read_inode_raw(sb.journal_inum)?;
        let mut journal = self.load_internal_journal(&sb, &journal_inode)?;
        let active_recovery = journal.start != 0;
        if active_recovery {
            if journal.feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT == 0 {
                return Err(FsError::NotSupported);
            }
            if sb.feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER == 0 {
                return Err(FsError::Invalid);
            }
        } else if !self.dev.is_read_only()
            && journal.feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT == 0
        {
            let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
            self.ensure_journal_intent_feature(&mut journal, &mut scratch)?;
        }
        let recovery = self.plan_internal_journal_recovery(&journal)?;
        let (overlay, post_images) = recovery.as_ref().map_or((&[][..], &[][..]), |plan| {
            (plan.overlay.as_slice(), plan.post_images.as_slice())
        });
        let intent = recovery.as_ref().and_then(|plan| plan.intent.as_ref());

        // RF180-13 FIX: journal discovery is read-only until the exact writer
        // grammar and the complete virtual post-image ownership graph pass.
        // In particular, neither marking RECOVER nor replaying a home block is
        // allowed to make an untrusted image more authoritative first.  The
        // recovery plan freezes its accepted journal bytes, closing the local
        // validation-to-replay gap.  BlockDevice still lacks an exclusive
        // mount claim, so privileged concurrent raw-device writes remain a
        // broader device/VFS contract issue rather than a recovery guarantee.
        let mut verification = JournalRecoveryScratch::try_new(self.block_size)?;
        let pre_images = self.validate_recovery_grammar(overlay, post_images, intent)?;
        self.validate_checkpoint_homes(overlay, &pre_images, post_images, &mut verification)?;
        self.validate_recovery_overlay(&journal, overlay, post_images, intent, &mut verification)?;
        // R186-7 FIX: validate block ownership for READ-ONLY mounts too.
        //
        // The scan was gated on writability, on the assumption that only writes
        // can do damage. That is wrong in two ways for a crafted image:
        //
        //   - Reads expose confidentiality. Without an ownership graph, one
        //     inode's data blocks may alias another inode's — or the journal's,
        //     or the inode table's — so an unprivileged read through a crafted
        //     directory entry can disclose metadata it has no claim to.
        //   - "Read-only" is a property of the current mount, not of the image.
        //     Admitting an unvalidated image read-only and validating it only if
        //     it is later mounted writable leaves the ownership proof optional.
        //
        // The scan is pure validation over the post-replay virtual image (it
        // performs no writes), so running it for a read-only mount is sound. A
        // failure now refuses the mount outright: an image whose blocks cannot be
        // proven singly-owned is not admitted at all.
        if !pre_images.is_empty() {
            self.validate_block_ownership(&journal, overlay, &pre_images)?;
        }
        self.validate_block_ownership(&journal, overlay, post_images)?;
        if !active_recovery {
            self.ensure_recovery_feature()?;
        }

        if let Some(plan) = recovery {
            self.apply_internal_journal_recovery(&plan)?;
            self.reload_recovered_metadata(&sb)?;
            let recovered_super = *self.superblock.read();
            let recovered_inode = self.read_inode_raw(recovered_super.journal_inum)?;
            let mut recovered_journal =
                self.load_internal_journal(&recovered_super, &recovered_inode)?;
            if recovered_journal.start != journal.start
                || recovered_journal.next_sequence != journal.next_sequence
                || recovered_journal.blocks != journal.blocks
                || recovered_journal.mapping_blocks != journal.mapping_blocks
                || recovered_journal.owned_blocks != journal.owned_blocks
                || recovered_journal.max_len != journal.max_len
                || recovered_journal.first != journal.first
                || recovered_journal.uuid != journal.uuid
                || recovered_journal.feature_incompat != journal.feature_incompat
            {
                return Err(FsError::NotSupported);
            }
            self.revalidate_overlay_homes(&plan.overlay, &plan.post_images, &mut verification)?;
            self.validate_recovery_overlay(
                &recovered_journal,
                &plan.overlay,
                &plan.post_images,
                plan.intent.as_ref(),
                &mut verification,
            )?;
            self.clear_recovered_journal(&mut recovered_journal, &plan)?;
            journal = recovered_journal;
        }
        *self.journal.lock() = Some(journal);
        Ok(())
    }

    fn ensure_recovery_feature(&self) -> Result<(), FsError> {
        if self.dev.is_read_only() {
            return Ok(());
        }
        let current = *self.superblock.read();
        if current.feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER != 0 {
            return Ok(());
        }

        let mut marked = current;
        marked.feature_incompat |= EXT3_FEATURE_INCOMPAT_RECOVER;
        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        self.write_primary_superblock(&marked, &mut scratch)?;
        self.flush_device()?;
        *self.superblock.write() = marked;
        Ok(())
    }

    fn reload_recovered_metadata(&self, original: &Ext2Superblock) -> Result<(), FsError> {
        let (recovered, block_size) = Self::read_super(&self.dev)?;
        let recovered_inode_size = if recovered.rev_level >= 1 {
            recovered.inode_size
        } else {
            size_of::<Ext2InodeRaw>() as u16
        };
        let unsupported_geometry_change = block_size != self.block_size
            || recovered_inode_size != self.inode_size
            || recovered.inodes_count != original.inodes_count
            || recovered.blocks_count != original.blocks_count
            || recovered.first_data_block != original.first_data_block
            || recovered.blocks_per_group != self.blocks_per_group
            || recovered.frags_per_group != original.frags_per_group
            || recovered.inodes_per_group != original.inodes_per_group
            || recovered.rev_level != original.rev_level
            || recovered.first_ino != original.first_ino
            || recovered.feature_compat != original.feature_compat
            || recovered.feature_ro_compat != original.feature_ro_compat
            || (recovered.feature_incompat ^ original.feature_incompat)
                & !EXT3_FEATURE_INCOMPAT_RECOVER
                != 0
            || recovered.uuid != original.uuid
            || recovered.journal_uuid != original.journal_uuid
            || recovered.journal_inum != original.journal_inum
            || recovered.journal_dev != original.journal_dev;
        if unsupported_geometry_change {
            return Err(FsError::NotSupported);
        }

        let recovered_descs = Self::load_group_descs(&self.dev, &recovered, block_size)?;
        {
            let current_descs = self.group_descs.read();
            if current_descs.len() != recovered_descs.len()
                || current_descs
                    .iter()
                    .zip(recovered_descs.iter())
                    .any(|(current, recovered)| {
                        current.block_bitmap != recovered.block_bitmap
                            || current.inode_bitmap != recovered.inode_bitmap
                            || current.inode_table != recovered.inode_table
                    })
            {
                return Err(FsError::NotSupported);
            }
        }

        *self.superblock.write() = recovered;
        *self.group_descs.write() = recovered_descs;
        Ok(())
    }

    fn initialize_resize_inode_reservations(&self) -> Result<(), FsError> {
        let sb = *self.superblock.read();
        if sb.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE == 0 {
            return Ok(());
        }

        const EXT2_RESIZE_INO: u32 = 7;
        let raw = self.read_inode_raw(EXT2_RESIZE_INO)?;
        if raw.mode & EXT2_S_IFMT != EXT2_S_IFREG || raw.block[EXT2_TIND_BLOCK] != 0 {
            return Err(FsError::NotSupported);
        }
        let sectors_per_block = self.block_size / 512;
        if sectors_per_block == 0 || raw.blocks_lo % sectors_per_block != 0 {
            return Err(FsError::Invalid);
        }
        let claimed_blocks =
            usize::try_from(raw.blocks_lo / sectors_per_block).map_err(|_| FsError::Invalid)?;
        if claimed_blocks > MAX_RESIZE_RESERVED_BLOCKS {
            return Err(FsError::NotSupported);
        }
        let mut first = Ext2MutationScratch::try_new(self.block_size)?;
        let mut second = Ext2MutationScratch::try_new(self.block_size)?;
        let mut reserved = Vec::new();
        reserved
            .try_reserve_exact(claimed_blocks)
            .map_err(|_| FsError::NoMem)?;
        let mut record = |physical: u32| -> Result<(), FsError> {
            let physical = self.validate_block(physical)?.ok_or(FsError::Invalid)?;
            if reserved.len() >= claimed_blocks || reserved.len() >= MAX_RESIZE_RESERVED_BLOCKS {
                return Err(FsError::Invalid);
            }
            reserved.push(physical);
            Ok(())
        };
        let ptrs_per_block = self.block_size as usize / 4;
        let mut pointer_words = EXT2_NDIR_BLOCKS;
        if pointer_words > MAX_RESIZE_POINTER_WORDS {
            return Err(FsError::NotSupported);
        }

        for &physical in &raw.block[..EXT2_NDIR_BLOCKS] {
            if physical != 0 {
                record(physical)?;
            }
        }
        if raw.block[EXT2_IND_BLOCK] != 0 {
            let indirect = raw.block[EXT2_IND_BLOCK];
            record(indirect)?;
            self.read_block(indirect, first.block_mut())?;
            pointer_words = pointer_words
                .checked_add(ptrs_per_block)
                .filter(|words| *words <= MAX_RESIZE_POINTER_WORDS)
                .ok_or(FsError::NotSupported)?;
            for index in 0..ptrs_per_block {
                let physical = read_u32_le(first.block(), index)?;
                if physical != 0 {
                    record(physical)?;
                }
            }
        }
        if raw.block[EXT2_DIND_BLOCK] != 0 {
            let double = raw.block[EXT2_DIND_BLOCK];
            record(double)?;
            self.read_block(double, first.block_mut())?;
            pointer_words = pointer_words
                .checked_add(ptrs_per_block)
                .filter(|words| *words <= MAX_RESIZE_POINTER_WORDS)
                .ok_or(FsError::NotSupported)?;
            for branch in 0..ptrs_per_block {
                let indirect = read_u32_le(first.block(), branch)?;
                if indirect == 0 {
                    continue;
                }
                record(indirect)?;
                self.read_block(indirect, second.block_mut())?;
                pointer_words = pointer_words
                    .checked_add(ptrs_per_block)
                    .filter(|words| *words <= MAX_RESIZE_POINTER_WORDS)
                    .ok_or(FsError::NotSupported)?;
                for index in 0..ptrs_per_block {
                    let physical = read_u32_le(second.block(), index)?;
                    if physical != 0 {
                        record(physical)?;
                    }
                }
            }
        }
        drop(record);
        reserved.sort_unstable();
        if reserved.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }
        if reserved.len() != claimed_blocks {
            return Err(FsError::Invalid);
        }
        self.validate_sorted_allocated_blocks(&reserved, &mut first)?;
        *self.resize_reserved_blocks.write() = reserved;
        Ok(())
    }

    fn record_journal_mapping_block(
        &self,
        block: u32,
        mapping_blocks: &mut Vec<u32>,
    ) -> Result<(), FsError> {
        let block = self.validate_block(block)?.ok_or(FsError::Invalid)?;
        if self.is_structural_metadata_block(block)? {
            return Err(FsError::Invalid);
        }
        if !mapping_blocks.contains(&block) {
            if mapping_blocks.len() == mapping_blocks.capacity() {
                mapping_blocks.try_reserve(1).map_err(|_| FsError::NoMem)?;
            }
            mapping_blocks.push(block);
        }
        Ok(())
    }

    fn map_journal_file_block(
        &self,
        raw: &Ext2InodeRaw,
        file_block: u32,
        scratch: &mut Ext2MutationScratch,
        mapping_blocks: &mut Vec<u32>,
    ) -> Result<u32, FsError> {
        if file_block < EXT2_NDIR_BLOCKS as u32 {
            return self
                .validate_block(raw.block[file_block as usize])?
                .ok_or(FsError::Invalid);
        }

        let ptrs_per_block = self.block_size / 4;
        let file_block = file_block - EXT2_NDIR_BLOCKS as u32;
        if file_block < ptrs_per_block {
            let indirect = self
                .validate_block(raw.block[EXT2_IND_BLOCK])?
                .ok_or(FsError::Invalid)?;
            self.record_journal_mapping_block(indirect, mapping_blocks)?;
            self.read_physical_block(indirect, scratch.block_mut())?;
            return self
                .validate_block(read_u32_le(scratch.block(), file_block as usize)?)?
                .ok_or(FsError::Invalid);
        }

        let file_block = file_block - ptrs_per_block;
        let double_limit = ptrs_per_block
            .checked_mul(ptrs_per_block)
            .ok_or(FsError::Invalid)?;
        if file_block >= double_limit {
            // MAX_JOURNAL_BLOCKS is deliberately below the triple-indirect
            // threshold even for the minimum 1 KiB filesystem block.
            return Err(FsError::NotSupported);
        }

        let double = self
            .validate_block(raw.block[EXT2_DIND_BLOCK])?
            .ok_or(FsError::Invalid)?;
        self.record_journal_mapping_block(double, mapping_blocks)?;
        self.read_physical_block(double, scratch.block_mut())?;
        let indirect = self
            .validate_block(read_u32_le(
                scratch.block(),
                (file_block / ptrs_per_block) as usize,
            )?)?
            .ok_or(FsError::Invalid)?;
        self.record_journal_mapping_block(indirect, mapping_blocks)?;
        self.read_physical_block(indirect, scratch.block_mut())?;
        self.validate_block(read_u32_le(
            scratch.block(),
            (file_block % ptrs_per_block) as usize,
        )?)?
        .ok_or(FsError::Invalid)
    }

    /// Validate an already sorted, duplicate-free ownership set with at most
    /// one bitmap read per touched group.  This replaces the former one-read
    /// per journal/resize block behavior and gives journal-map validation
    /// O(owned blocks + touched groups) work.
    fn validate_sorted_allocated_blocks(
        &self,
        blocks: &[u32],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if blocks.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(FsError::Invalid);
        }
        let sb = *self.superblock.read();
        let descs = self.group_descs.read();
        let mut loaded_group = None;
        for &block in blocks {
            let relative = block
                .checked_sub(sb.first_data_block)
                .ok_or(FsError::Invalid)?;
            let group = relative / sb.blocks_per_group;
            let bit = relative % sb.blocks_per_group;
            if loaded_group != Some(group) {
                let desc = descs.get(group as usize).copied().ok_or(FsError::Invalid)?;
                self.read_physical_block(desc.block_bitmap, scratch.block_mut())?;
                loaded_group = Some(group);
            }
            let byte = scratch
                .block()
                .get((bit / 8) as usize)
                .copied()
                .ok_or(FsError::Invalid)?;
            if byte & (1u8 << (bit % 8)) == 0 {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }

    fn load_internal_journal(
        &self,
        ext_super: &Ext2Superblock,
        raw: &Ext2InodeRaw,
    ) -> Result<Ext2Journal, FsError> {
        if raw.mode & EXT2_S_IFMT != EXT2_S_IFREG {
            return Err(FsError::Invalid);
        }
        let file_size = ((raw.size_high_or_dir_acl as u64) << 32) | raw.size_lo as u64;
        if file_size == 0 || file_size % self.block_size as u64 != 0 {
            return Err(FsError::Invalid);
        }
        let inode_blocks = file_size / self.block_size as u64;
        if inode_blocks < 2 || inode_blocks > MAX_JOURNAL_BLOCKS as u64 {
            return Err(FsError::NotSupported);
        }

        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        let journal_super_phys = self
            .map_file_block_with_scratch(raw, 0, &mut scratch)?
            .ok_or(FsError::Invalid)?;
        self.read_physical_block(journal_super_phys, scratch.block_mut())?;
        let super_bytes = scratch.block();

        if read_be_u32(super_bytes, 0)? != JBD2_MAGIC
            || read_be_u32(super_bytes, 4)? != JBD2_SUPERBLOCK_V2
        {
            return Err(FsError::NotSupported);
        }
        if read_be_u32(super_bytes, JBD2_SUPER_BLOCKSIZE_OFFSET)? != self.block_size {
            return Err(FsError::Invalid);
        }

        let max_len = read_be_u32(super_bytes, JBD2_SUPER_MAXLEN_OFFSET)?;
        let first = read_be_u32(super_bytes, JBD2_SUPER_FIRST_OFFSET)?;
        let next_sequence = read_be_u32(super_bytes, JBD2_SUPER_SEQUENCE_OFFSET)?;
        let start = read_be_u32(super_bytes, JBD2_SUPER_START_OFFSET)?;
        let errno = read_be_u32(super_bytes, JBD2_SUPER_ERRNO_OFFSET)?;
        let feature_compat = read_be_u32(super_bytes, JBD2_SUPER_FEATURE_COMPAT_OFFSET)?;
        let feature_incompat = read_be_u32(super_bytes, JBD2_SUPER_FEATURE_INCOMPAT_OFFSET)?;
        let feature_ro_compat = read_be_u32(super_bytes, JBD2_SUPER_FEATURE_RO_COMPAT_OFFSET)?;
        let nr_users = read_be_u32(super_bytes, JBD2_SUPER_NR_USERS_OFFSET)?;

        if errno != 0
            || feature_compat != 0
            || feature_ro_compat != 0
            || feature_incompat & !JBD2_SUPPORTED_INCOMPAT != 0
        {
            return Err(FsError::NotSupported);
        }
        // The private writer rewrites `s_start` in-place.  Only `s_first == 1`
        // has a tear-safe big-endian representation: every strict prefix of a
        // clear from 1 to 0 still decodes as either 1 or 0.  Multi-byte values
        // can tear into a third, unrecoverable start.  Reject them before this
        // implementation can recover or emit private transactions.
        if feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT != 0 && first != 1 {
            return Err(FsError::NotSupported);
        }
        if nr_users != 1
            || max_len
                < first
                    .checked_add(JOURNAL_TRANSACTION_BLOCKS)
                    .ok_or(FsError::Invalid)?
            || max_len as u64 != inode_blocks
            || max_len as usize > MAX_JOURNAL_BLOCKS
            || first == 0
            || (start != 0 && start != first)
        {
            return Err(FsError::Invalid);
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(
            super_bytes
                .get(JBD2_SUPER_UUID_OFFSET..JBD2_SUPER_UUID_OFFSET + 16)
                .ok_or(FsError::Invalid)?,
        );
        // RF180-49 FIX: e2fsprogs leaves s_journal_uuid clear for a standard
        // internal journal and binds the JBD2 superblock to the filesystem
        // UUID.  A nonzero s_journal_uuid is an explicit override used by
        // existing supported images.  In either form, reject an unbound or
        // mismatched journal before any recovery or feature-upgrade write.
        let expected_uuid = if ext_super.journal_uuid == [0; 16] {
            ext_super.uuid
        } else {
            ext_super.journal_uuid
        };
        if expected_uuid == [0; 16] || uuid == [0; 16] || uuid != expected_uuid {
            return Err(FsError::Invalid);
        }

        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(max_len as usize)
            .map_err(|_| FsError::NoMem)?;
        let mut mapping_blocks = Vec::new();
        mapping_blocks
            .try_reserve_exact(128)
            .map_err(|_| FsError::NoMem)?;
        for logical in 0..max_len {
            let physical =
                self.map_journal_file_block(raw, logical, &mut scratch, &mut mapping_blocks)?;
            if self.is_structural_metadata_block(physical)? {
                return Err(FsError::Invalid);
            }
            blocks.push(physical);
        }
        if blocks.first().copied() != Some(journal_super_phys) {
            return Err(FsError::Invalid);
        }

        // A duplicate physical mapping lets one log write overwrite another.
        // Validate uniqueness with a bounded mount-time copy, then retain only
        // the logical-order map used by the transaction path.
        let mut unique = Vec::new();
        unique
            .try_reserve_exact(
                blocks
                    .len()
                    .checked_add(mapping_blocks.len())
                    .ok_or(FsError::Invalid)?,
            )
            .map_err(|_| FsError::NoMem)?;
        unique.extend_from_slice(&blocks);
        unique.extend_from_slice(&mapping_blocks);
        unique.sort_unstable();
        if unique.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }
        self.validate_sorted_allocated_blocks(&unique, &mut scratch)?;

        Ok(Ext2Journal {
            blocks,
            mapping_blocks,
            owned_blocks: unique,
            max_len,
            first,
            next_sequence,
            start,
            uuid,
            feature_incompat,
        })
    }

    #[inline]
    fn group_has_superblock(group: u32, sparse_super: bool) -> bool {
        if !sparse_super || group == 0 || group == 1 {
            return true;
        }

        fn is_power(mut value: u32, base: u32) -> bool {
            while value > 1 && value % base == 0 {
                value /= base;
            }
            value == 1
        }

        is_power(group, 3) || is_power(group, 5) || is_power(group, 7)
    }

    fn is_structural_metadata_block(&self, block: u32) -> Result<bool, FsError> {
        let sb = *self.superblock.read();
        let group_descs = self.group_descs.read();
        if block >= self.blocks_count {
            return Err(FsError::Invalid);
        }
        if block < sb.first_data_block {
            return Ok(true);
        }
        let desc_bytes = group_descs
            .len()
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let desc_blocks = desc_bytes
            .checked_add(self.block_size as usize - 1)
            .ok_or(FsError::Invalid)?
            / self.block_size as usize;
        let desc_blocks = u32::try_from(desc_blocks).map_err(|_| FsError::Invalid)?;
        let sparse_super = sb.feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER != 0;
        let reserved_gdt = if sb.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE != 0 {
            sb.reserved_gdt_blocks as u32
        } else {
            0
        };

        // RF180-13 FIX: FLEX_BG is unsupported, so a block's owner group is
        // derivable directly from geometry.  Inspecting that one descriptor
        // avoids the former O(65K groups) scan for every journal pointer.
        let relative = block - sb.first_data_block;
        let group = relative / sb.blocks_per_group;
        let group_index = usize::try_from(group).map_err(|_| FsError::Invalid)?;
        let desc = group_descs
            .get(group_index)
            .copied()
            .ok_or(FsError::Invalid)?;
        let group_start = sb
            .first_data_block
            .checked_add(
                group
                    .checked_mul(sb.blocks_per_group)
                    .ok_or(FsError::Invalid)?,
            )
            .ok_or(FsError::Invalid)?;
        if Self::group_has_superblock(group, sparse_super) {
            let metadata_end = group_start
                .checked_add(1)
                .and_then(|value| value.checked_add(desc_blocks))
                .and_then(|value| value.checked_add(reserved_gdt))
                .ok_or(FsError::Invalid)?
                .min(self.blocks_count);
            if block < metadata_end {
                return Ok(true);
            }
        }

        let inode_table_bytes = (self.inodes_per_group as u64)
            .checked_mul(self.inode_size as u64)
            .ok_or(FsError::Invalid)?;
        let inode_table_blocks = inode_table_bytes
            .checked_add(self.block_size as u64 - 1)
            .ok_or(FsError::Invalid)?
            / self.block_size as u64;
        if block == desc.block_bitmap || block == desc.inode_bitmap {
            return Ok(true);
        }
        let inode_end = (desc.inode_table as u64)
            .checked_add(inode_table_blocks)
            .ok_or(FsError::Invalid)?;
        if block as u64 >= desc.inode_table as u64 && (block as u64) < inode_end {
            return Ok(true);
        }
        Ok(self
            .resize_reserved_blocks
            .read()
            .binary_search(&block)
            .is_ok())
    }

    fn read_journal_block(
        &self,
        journal: &Ext2Journal,
        logical: u32,
        buf: &mut [u8],
    ) -> Result<(), FsError> {
        self.read_physical_block(journal.physical(logical)?, buf)
    }

    fn write_journal_block(
        &self,
        journal: &Ext2Journal,
        logical: u32,
        buf: &[u8],
    ) -> Result<(), FsError> {
        self.write_physical_block(journal.physical(logical)?, buf)
    }

    fn write_journal_state(
        &self,
        journal: &Ext2Journal,
        sequence: u32,
        start: u32,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if journal.first != 1 || (start != 0 && start != journal.first) {
            return Err(FsError::NotSupported);
        }
        self.read_journal_block(journal, 0, scratch.block_mut())?;
        let block = scratch.block_mut();
        if read_be_u32(block, 0)? != JBD2_MAGIC || read_be_u32(block, 4)? != JBD2_SUPERBLOCK_V2 {
            return Err(FsError::Invalid);
        }
        write_be_u32(block, JBD2_SUPER_SEQUENCE_OFFSET, sequence)?;
        write_be_u32(block, JBD2_SUPER_START_OFFSET, start)?;
        self.write_journal_block(journal, 0, block)
    }

    fn ensure_journal_intent_feature(
        &self,
        journal: &mut Ext2Journal,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if journal.first != 1 {
            return Err(FsError::NotSupported);
        }
        if journal.feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT != 0 {
            return Ok(());
        }
        if journal.start != 0 || self.dev.is_read_only() {
            return Err(FsError::NotSupported);
        }
        self.read_journal_block(journal, 0, scratch.block_mut())?;
        let block = scratch.block_mut();
        if read_be_u32(block, 0)? != JBD2_MAGIC
            || read_be_u32(block, 4)? != JBD2_SUPERBLOCK_V2
            || read_be_u32(block, JBD2_SUPER_START_OFFSET)? != 0
        {
            return Err(FsError::Invalid);
        }
        let current = read_be_u32(block, JBD2_SUPER_FEATURE_INCOMPAT_OFFSET)?;
        if current != journal.feature_incompat || current & !JBD2_SUPPORTED_INCOMPAT != 0 {
            return Err(FsError::NotSupported);
        }
        let upgraded = current | JBD2_FEATURE_INCOMPAT_ZERO_INTENT;
        write_be_u32(block, JBD2_SUPER_FEATURE_INCOMPAT_OFFSET, upgraded)?;
        self.write_journal_block(journal, 0, block)?;
        self.flush_device()?;
        self.read_journal_block(journal, 0, scratch.block_mut())?;
        if read_be_u32(scratch.block(), JBD2_SUPER_FEATURE_INCOMPAT_OFFSET)? != upgraded
            || read_be_u32(scratch.block(), JBD2_SUPER_START_OFFSET)? != 0
        {
            return Err(FsError::Io);
        }
        journal.feature_incompat = upgraded;
        Ok(())
    }

    fn frozen_overlay_image<'a>(
        &self,
        post_images: &'a [u8],
        entry: JournalOverlayEntry,
    ) -> Result<&'a [u8], FsError> {
        let end = entry
            .image_offset
            .checked_add(self.block_size as usize)
            .ok_or(FsError::Invalid)?;
        post_images
            .get(entry.image_offset..end)
            .ok_or(FsError::Invalid)
    }

    fn read_overlay_image(
        &self,
        post_images: &[u8],
        entry: JournalOverlayEntry,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let image = self.frozen_overlay_image(post_images, entry)?;
        scratch.block_mut().copy_from_slice(image);
        Ok(())
    }

    fn freeze_recovery_post_images(
        &self,
        journal: &Ext2Journal,
        overlay: &mut [JournalOverlayEntry],
    ) -> Result<Vec<u8>, FsError> {
        if !overlay.is_empty() && overlay.len() != 1 && overlay.len() != JOURNAL_MAX_METADATA_BLOCKS
        {
            return Err(FsError::NotSupported);
        }
        let image_bytes = overlay
            .len()
            .checked_mul(self.block_size as usize)
            .ok_or(FsError::Invalid)?;
        let mut post_images = Vec::new();
        post_images
            .try_reserve_exact(image_bytes)
            .map_err(|_| FsError::NoMem)?;
        post_images.resize(image_bytes, 0);

        for (index, entry) in overlay.iter_mut().enumerate() {
            let offset = index
                .checked_mul(self.block_size as usize)
                .ok_or(FsError::Invalid)?;
            let end = offset
                .checked_add(self.block_size as usize)
                .ok_or(FsError::Invalid)?;
            entry.image_offset = offset;
            self.read_journal_block(
                journal,
                entry.log,
                post_images.get_mut(offset..end).ok_or(FsError::Invalid)?,
            )?;
            if entry.flags & JBD2_FLAG_ESCAPE != 0 {
                post_images[offset..offset + 4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
            }
        }
        Ok(post_images)
    }

    fn read_virtual_block(
        &self,
        _journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        home: u32,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        match overlay.binary_search_by_key(&home, |entry| entry.home) {
            Ok(index) => self.read_overlay_image(post_images, overlay[index], scratch),
            Err(_) => self.read_physical_block(home, scratch.block_mut()),
        }
    }

    fn read_virtual_superblock(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<Ext2Superblock, FsError> {
        let (home, offset) = self.superblock_home_target();
        self.read_virtual_block(journal, overlay, post_images, home, scratch)?;
        let end = offset
            .checked_add(size_of::<Ext2Superblock>())
            .ok_or(FsError::Invalid)?;
        let bytes = scratch.block().get(offset..end).ok_or(FsError::Invalid)?;
        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) })
    }

    fn read_virtual_group_desc(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        group: usize,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<Ext2GroupDesc, FsError> {
        let target = self.group_desc_write_target(group)?;
        if overlay
            .binary_search_by_key(&target.block, |entry| entry.home)
            .is_err()
        {
            return self
                .group_descs
                .read()
                .get(group)
                .copied()
                .ok_or(FsError::Invalid);
        }
        self.read_virtual_block(journal, overlay, post_images, target.block, scratch)?;
        let end = target
            .offset
            .checked_add(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let bytes = scratch
            .block()
            .get(target.offset..end)
            .ok_or(FsError::Invalid)?;
        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) })
    }

    fn push_ordinary_owner(
        &self,
        journal: &Ext2Journal,
        work: &mut OwnershipWork,
        physical: u32,
    ) -> Result<u32, FsError> {
        let physical = self.validate_block(physical)?.ok_or(FsError::Invalid)?;
        if journal.contains_physical(physical) || self.is_structural_metadata_block(physical)? {
            return Err(FsError::Invalid);
        }
        work.push_owner(physical)?;
        Ok(physical)
    }

    fn collect_owned_mapping_tree(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        root: u32,
        level: u8,
        logical_base: u64,
        logical_blocks: u64,
        work: &mut OwnershipWork,
        inode_blocks: &mut u64,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if !(1..=3).contains(&level) || logical_base >= logical_blocks {
            return Err(FsError::Invalid);
        }
        let root = self.push_ordinary_owner(journal, work, root)?;
        *inode_blocks = inode_blocks.checked_add(1).ok_or(FsError::Invalid)?;
        work.account_mapping_block(self.block_size as usize)?;
        self.read_virtual_block(journal, overlay, post_images, root, scratch)?;

        let pointers = self.block_size as usize / 4;
        let mut children = Vec::new();
        children
            .try_reserve_exact(pointers)
            .map_err(|_| FsError::NoMem)?;
        for index in 0..pointers {
            children.push(read_u32_le(scratch.block(), index)?);
        }
        let child_span = (self.block_size as u64 / 4)
            .checked_pow((level - 1) as u32)
            .ok_or(FsError::Invalid)?;
        for (index, child) in children.into_iter().enumerate() {
            if child == 0 {
                continue;
            }
            let child_base = logical_base
                .checked_add(
                    (index as u64)
                        .checked_mul(child_span)
                        .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            if child_base >= logical_blocks {
                return Err(FsError::Invalid);
            }
            if level == 1 {
                self.push_ordinary_owner(journal, work, child)?;
                *inode_blocks = inode_blocks.checked_add(1).ok_or(FsError::Invalid)?;
            } else {
                self.collect_owned_mapping_tree(
                    journal,
                    overlay,
                    post_images,
                    child,
                    level - 1,
                    child_base,
                    logical_blocks,
                    work,
                    inode_blocks,
                    scratch,
                )?;
            }
        }
        Ok(())
    }

    fn collect_inode_owners(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        raw: &Ext2InodeRaw,
        work: &mut OwnershipWork,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if raw.mode == 0 || raw.dtime != 0 || raw.links_count == 0 || raw.faddr != 0 {
            return Err(FsError::Invalid);
        }
        if raw.flags & EXT2_UNSUPPORTED_WRITE_LAYOUT_FL != 0 {
            return Err(FsError::NotSupported);
        }

        let inode_type = raw.mode & EXT2_S_IFMT;
        let inline_symlink = inode_type == EXT2_S_IFLNK
            && raw.size_lo as usize <= core::mem::size_of_val(&raw.block);
        let mapped =
            matches!(inode_type, EXT2_S_IFREG | EXT2_S_IFDIR | EXT2_S_IFLNK) && !inline_symlink;
        let size = if inode_type == EXT2_S_IFREG {
            ((raw.size_high_or_dir_acl as u64) << 32) | raw.size_lo as u64
        } else {
            if raw.size_high_or_dir_acl != 0 {
                return Err(FsError::NotSupported);
            }
            raw.size_lo as u64
        };
        let logical_blocks = if size == 0 {
            0
        } else {
            size.checked_add(self.block_size as u64 - 1)
                .ok_or(FsError::Invalid)?
                / self.block_size as u64
        };
        let ptrs = self.block_size as u64 / 4;
        let single_base = EXT2_NDIR_BLOCKS as u64;
        let double_base = single_base.checked_add(ptrs).ok_or(FsError::Invalid)?;
        let triple_base = double_base
            .checked_add(ptrs.checked_mul(ptrs).ok_or(FsError::Invalid)?)
            .ok_or(FsError::Invalid)?;
        let capacity = triple_base
            .checked_add(
                ptrs.checked_mul(ptrs)
                    .and_then(|value| value.checked_mul(ptrs))
                    .ok_or(FsError::Invalid)?,
            )
            .ok_or(FsError::Invalid)?;
        if mapped && logical_blocks > capacity {
            return Err(FsError::Invalid);
        }

        let mut inode_blocks = 0u64;
        if raw.file_acl != 0 {
            self.push_ordinary_owner(journal, work, raw.file_acl)?;
            inode_blocks = inode_blocks.checked_add(1).ok_or(FsError::Invalid)?;
        }
        if mapped {
            for index in 0..EXT2_NDIR_BLOCKS {
                let physical = raw.block[index];
                if physical == 0 {
                    continue;
                }
                if index as u64 >= logical_blocks {
                    return Err(FsError::Invalid);
                }
                self.push_ordinary_owner(journal, work, physical)?;
                inode_blocks = inode_blocks.checked_add(1).ok_or(FsError::Invalid)?;
            }
            for (index, level, base) in [
                (EXT2_IND_BLOCK, 1u8, single_base),
                (EXT2_DIND_BLOCK, 2u8, double_base),
                (EXT2_TIND_BLOCK, 3u8, triple_base),
            ] {
                let root = raw.block[index];
                if root == 0 {
                    continue;
                }
                self.collect_owned_mapping_tree(
                    journal,
                    overlay,
                    post_images,
                    root,
                    level,
                    base,
                    logical_blocks,
                    work,
                    &mut inode_blocks,
                    scratch,
                )?;
            }
        }
        let sectors = inode_blocks
            .checked_mul((self.block_size / 512) as u64)
            .ok_or(FsError::Invalid)?;
        if sectors != raw.blocks_lo as u64 {
            return Err(FsError::Invalid);
        }
        Ok(())
    }

    /// RF180-13 FIX: establish one complete block-ownership graph before the
    /// filesystem is admitted.  Every allocated bitmap bit must have
    /// exactly one structural, journal, resize, inode-data, mapping-node, or
    /// ACL owner, and every owner must be allocated.  The scan operates on the
    /// virtual post-replay image so a recovery plan is proven before any home
    /// block or RECOVER feature write occurs.
    ///
    /// R186-7: renamed from `validate_writable_ownership`. The old name encoded
    /// the bug — it was only ever called for writable mounts, leaving read-only
    /// mounts with no ownership proof at all. This scan performs no writes and is
    /// now a precondition of ADMITTING the image, in either mode.
    ///
    /// Note that skipping bitmap-clear inode slots (below) is sound only because
    /// `read_inode_raw` refuses to load an inode whose bitmap bit is clear; the
    /// two checks compose into "a reachable inode is allocated and owns every
    /// block it exposes" (INV-VFS-01). Neither half is sufficient alone.
    fn validate_block_ownership(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
    ) -> Result<(), FsError> {
        let mut scratch = JournalRecoveryScratch::try_new(self.block_size)?;
        let proposed =
            self.read_virtual_superblock(journal, overlay, post_images, &mut scratch.control)?;
        if proposed.inodes_count > MAX_OWNERSHIP_INODES {
            return Err(FsError::NotSupported);
        }
        let groups = self.group_descs.read().len();
        let inode_table_blocks = (self.inodes_per_group as u64)
            .checked_mul(self.inode_size as u64)
            .and_then(|bytes| bytes.checked_add(self.block_size as u64 - 1))
            .ok_or(FsError::Invalid)?
            / self.block_size as u64;
        let desc_bytes = groups
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let desc_blocks = u32::try_from(
            desc_bytes
                .checked_add(self.block_size as usize - 1)
                .ok_or(FsError::Invalid)?
                / self.block_size as usize,
        )
        .map_err(|_| FsError::Invalid)?;
        let sparse_super = proposed.feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER != 0;
        let mut work = OwnershipWork::try_new()?;

        for group in 0..groups {
            let desc = self.read_virtual_group_desc(
                journal,
                overlay,
                post_images,
                group,
                &mut scratch.control,
            )?;
            let current = self
                .group_descs
                .read()
                .get(group)
                .copied()
                .ok_or(FsError::Invalid)?;
            if desc.block_bitmap != current.block_bitmap
                || desc.inode_bitmap != current.inode_bitmap
                || desc.inode_table != current.inode_table
            {
                return Err(FsError::Invalid);
            }
            let group_u32 = u32::try_from(group).map_err(|_| FsError::Invalid)?;
            let group_start = proposed
                .first_data_block
                .checked_add(
                    group_u32
                        .checked_mul(proposed.blocks_per_group)
                        .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            let group_end = group_start
                .checked_add(cmp::min(
                    proposed.blocks_per_group,
                    proposed
                        .blocks_count
                        .checked_sub(group_start)
                        .ok_or(FsError::Invalid)?,
                ))
                .ok_or(FsError::Invalid)?;
            if Self::group_has_superblock(group_u32, sparse_super) {
                let fixed_end = group_start
                    .checked_add(1)
                    .and_then(|value| value.checked_add(desc_blocks))
                    .ok_or(FsError::Invalid)?;
                if fixed_end > group_end {
                    return Err(FsError::Invalid);
                }
                for physical in group_start..fixed_end {
                    work.push_owner(physical)?;
                }
            }
            work.push_owner(desc.block_bitmap)?;
            work.push_owner(desc.inode_bitmap)?;
            for offset in 0..inode_table_blocks {
                let physical = (desc.inode_table as u64)
                    .checked_add(offset)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(FsError::Invalid)?;
                work.push_owner(physical)?;
            }
        }
        for &physical in &journal.owned_blocks {
            work.push_owner(physical)?;
        }
        for &physical in self.resize_reserved_blocks.read().iter() {
            work.push_owner(physical)?;
        }

        let mut inode_bitmap = Ext2MutationScratch::try_new(self.block_size)?;
        let mut inode_block = Ext2MutationScratch::try_new(self.block_size)?;
        let inodes_per_block = self.block_size as usize / self.inode_size as usize;
        let sectors_per_block = self.block_size / 512;
        let mut free_inodes_total = 0u64;
        let mut saw_root = false;
        let has_journal = proposed.feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0;
        let mut saw_journal = !has_journal;
        let mut saw_resize = proposed.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE == 0;

        for group in 0..groups {
            let desc = self.read_virtual_group_desc(
                journal,
                overlay,
                post_images,
                group,
                &mut scratch.control,
            )?;
            self.read_virtual_block(
                journal,
                overlay,
                post_images,
                desc.inode_bitmap,
                &mut inode_bitmap,
            )?;
            work.account_bitmap(self.block_size as usize)?;
            let first_inode = u32::try_from(group)
                .map_err(|_| FsError::Invalid)?
                .checked_mul(proposed.inodes_per_group)
                .ok_or(FsError::Invalid)?;
            let group_inodes = cmp::min(
                proposed.inodes_per_group,
                proposed.inodes_count.saturating_sub(first_inode),
            );
            let free_inodes = Self::bitmap_free_count(inode_bitmap.block(), group_inodes)?;
            if free_inodes != desc.free_inodes_count as u32 {
                return Err(FsError::Invalid);
            }
            free_inodes_total = free_inodes_total
                .checked_add(free_inodes as u64)
                .ok_or(FsError::Invalid)?;
            let mut used_dirs = 0u32;
            for table_offset in 0..inode_table_blocks {
                work.account_inode_table(self.block_size as usize)?;
                let physical = (desc.inode_table as u64)
                    .checked_add(table_offset)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(FsError::Invalid)?;
                self.read_virtual_block(journal, overlay, post_images, physical, &mut inode_block)?;
                for slot in 0..inodes_per_block {
                    let local = usize::try_from(table_offset)
                        .ok()
                        .and_then(|block| block.checked_mul(inodes_per_block))
                        .and_then(|value| value.checked_add(slot))
                        .ok_or(FsError::Invalid)?;
                    if local >= group_inodes as usize {
                        break;
                    }
                    let allocated = inode_bitmap
                        .block()
                        .get(local / 8)
                        .copied()
                        .ok_or(FsError::Invalid)?
                        & (1u8 << (local % 8))
                        != 0;
                    if !allocated {
                        continue;
                    }
                    work.inode_count = work
                        .inode_count
                        .checked_add(1)
                        .filter(|count| *count <= MAX_OWNERSHIP_INODES)
                        .ok_or(FsError::NotSupported)?;
                    let ino = first_inode
                        .checked_add(u32::try_from(local).map_err(|_| FsError::Invalid)?)
                        .and_then(|value| value.checked_add(1))
                        .ok_or(FsError::Invalid)?;
                    let start = slot
                        .checked_mul(self.inode_size as usize)
                        .ok_or(FsError::Invalid)?;
                    let end = start
                        .checked_add(size_of::<Ext2InodeRaw>())
                        .ok_or(FsError::Invalid)?;
                    let bytes = inode_block
                        .block()
                        .get(start..end)
                        .ok_or(FsError::Invalid)?;
                    let raw: Ext2InodeRaw =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
                    if ino == EXT2_ROOT_INO {
                        if raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR {
                            return Err(FsError::Invalid);
                        }
                        saw_root = true;
                    }
                    if ino == proposed.journal_inum {
                        if raw.mode & EXT2_S_IFMT != EXT2_S_IFREG
                            || raw.file_acl != 0
                            || raw.blocks_lo as usize
                                != journal
                                    .owned_blocks
                                    .len()
                                    .checked_mul(sectors_per_block as usize)
                                    .ok_or(FsError::Invalid)?
                        {
                            return Err(FsError::Invalid);
                        }
                        saw_journal = true;
                        continue;
                    }
                    if proposed.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE != 0 && ino == 7 {
                        if raw.mode & EXT2_S_IFMT != EXT2_S_IFREG
                            || raw.file_acl != 0
                            || raw.blocks_lo as usize
                                != self
                                    .resize_reserved_blocks
                                    .read()
                                    .len()
                                    .checked_mul(sectors_per_block as usize)
                                    .ok_or(FsError::Invalid)?
                        {
                            return Err(FsError::Invalid);
                        }
                        saw_resize = true;
                        continue;
                    }
                    if raw.mode == 0 {
                        if ino >= proposed.first_ino {
                            return Err(FsError::Invalid);
                        }
                        continue;
                    }
                    if raw.mode & EXT2_S_IFMT == EXT2_S_IFDIR {
                        used_dirs = used_dirs.checked_add(1).ok_or(FsError::Invalid)?;
                    }
                    self.collect_inode_owners(
                        journal,
                        overlay,
                        post_images,
                        &raw,
                        &mut work,
                        &mut scratch.data,
                    )?;
                }
            }
            if used_dirs != desc.used_dirs_count as u32 {
                return Err(FsError::Invalid);
            }
        }
        if !saw_root
            || !saw_journal
            || !saw_resize
            || free_inodes_total != proposed.free_inodes_count as u64
        {
            return Err(FsError::Invalid);
        }

        work.owners.sort_unstable();
        if work.owners.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }
        if work
            .owners
            .iter()
            .any(|physical| *physical < proposed.first_data_block || *physical >= self.blocks_count)
        {
            return Err(FsError::Invalid);
        }

        let mut owner_index = 0usize;
        let mut free_blocks_total = 0u64;
        for group in 0..groups {
            let desc = self.read_virtual_group_desc(
                journal,
                overlay,
                post_images,
                group,
                &mut scratch.control,
            )?;
            self.read_virtual_block(
                journal,
                overlay,
                post_images,
                desc.block_bitmap,
                &mut inode_bitmap,
            )?;
            work.account_bitmap(self.block_size as usize)?;
            let group_start = proposed
                .first_data_block
                .checked_add(
                    u32::try_from(group)
                        .map_err(|_| FsError::Invalid)?
                        .checked_mul(proposed.blocks_per_group)
                        .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            let group_blocks = cmp::min(
                proposed.blocks_per_group,
                proposed
                    .blocks_count
                    .checked_sub(group_start)
                    .ok_or(FsError::Invalid)?,
            );
            let free = Self::bitmap_free_count(inode_bitmap.block(), group_blocks)?;
            if free != desc.free_blocks_count as u32 {
                return Err(FsError::Invalid);
            }
            free_blocks_total = free_blocks_total
                .checked_add(free as u64)
                .ok_or(FsError::Invalid)?;
            for bit in 0..group_blocks {
                let physical = group_start.checked_add(bit).ok_or(FsError::Invalid)?;
                let bitmap_owned = inode_bitmap
                    .block()
                    .get((bit / 8) as usize)
                    .copied()
                    .ok_or(FsError::Invalid)?
                    & (1u8 << (bit % 8))
                    != 0;
                let graph_owned = work.owners.get(owner_index).copied() == Some(physical);
                if bitmap_owned != graph_owned {
                    return Err(FsError::Invalid);
                }
                if graph_owned {
                    owner_index += 1;
                }
            }
        }
        if owner_index != work.owners.len()
            || free_blocks_total != proposed.free_blocks_count as u64
        {
            return Err(FsError::Invalid);
        }
        Ok(())
    }

    fn validate_intent_inode_transition(
        &self,
        intent: &JournalCommitIntent,
        new: &Ext2InodeRaw,
    ) -> Result<(), FsError> {
        let old = &intent.old_inode;
        if old.mode & EXT2_S_IFMT != EXT2_S_IFREG
            || new.mode & EXT2_S_IFMT != EXT2_S_IFREG
            || old.mode != new.mode
            || old.uid != new.uid
            || old.atime != new.atime
            || old.dtime != 0
            || new.dtime != 0
            || old.gid != new.gid
            || old.links_count == 0
            || old.links_count != new.links_count
            || old.flags != new.flags
            || old.flags & (EXT2_IMMUTABLE_FL | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL) != 0
            || old.osd1 != new.osd1
            || old.generation != new.generation
            || old.file_acl != new.file_acl
            || old.faddr != new.faddr
            || old.osd2 != new.osd2
            || new.ctime != new.mtime
        {
            return Err(FsError::NotSupported);
        }
        let old_size = ((old.size_high_or_dir_acl as u64) << 32) | old.size_lo as u64;
        let new_size = ((new.size_high_or_dir_acl as u64) << 32) | new.size_lo as u64;
        if new_size < old_size {
            return Err(FsError::NotSupported);
        }
        match intent.kind {
            ZERO_INTENT_KIND_INODE_UPDATE => {
                if old.block != new.block || old.blocks_lo != new.blocks_lo {
                    return Err(FsError::NotSupported);
                }
            }
            ZERO_INTENT_KIND_DIRECT_ALLOCATION => {
                let index = usize::try_from(intent.file_block).map_err(|_| FsError::Invalid)?;
                if index >= EXT2_NDIR_BLOCKS
                    || old.block[index] != 0
                    || new.block[index] != intent.physical
                    || intent.physical == 0
                    || new.blocks_lo
                        != old
                            .blocks_lo
                            .checked_add(self.block_size / 512)
                            .ok_or(FsError::Invalid)?
                    || new_size
                        <= (index as u64)
                            .checked_mul(self.block_size as u64)
                            .ok_or(FsError::Invalid)?
                {
                    return Err(FsError::NotSupported);
                }
                for pointer in 0..old.block.len() {
                    if pointer != index && old.block[pointer] != new.block[pointer] {
                        return Err(FsError::NotSupported);
                    }
                }
            }
            _ => return Err(FsError::Invalid),
        }
        Ok(())
    }

    fn validate_recovery_grammar(
        &self,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        intent: Option<&JournalCommitIntent>,
    ) -> Result<Vec<u8>, FsError> {
        if overlay.is_empty() {
            if intent.is_some() || !post_images.is_empty() {
                return Err(FsError::Invalid);
            }
            return Ok(Vec::new());
        }
        let intent = intent.ok_or(FsError::Invalid)?;
        if overlay.len() != usize::from(intent.metadata_count)
            || (overlay.len() != 1 && overlay.len() != JOURNAL_MAX_METADATA_BLOCKS)
            || post_images.len()
                != overlay
                    .len()
                    .checked_mul(self.block_size as usize)
                    .ok_or(FsError::Invalid)?
        {
            return Err(FsError::NotSupported);
        }
        for entry in overlay {
            let order = usize::try_from(entry.order).map_err(|_| FsError::Invalid)?;
            if order >= overlay.len() {
                return Err(FsError::NotSupported);
            }
            let expected = if order == 0 { 0 } else { JBD2_FLAG_SAME_UUID }
                | if order + 1 == overlay.len() {
                    JBD2_FLAG_LAST_TAG
                } else {
                    0
                };
            if entry.flags & !JBD2_FLAG_ESCAPE != expected {
                return Err(FsError::NotSupported);
            }
        }

        let inode_target = self.inode_write_target(intent.inode_number)?;
        let inode_entry = overlay
            .iter()
            .copied()
            .find(|entry| entry.order as usize + 1 == overlay.len())
            .ok_or(FsError::Invalid)?;
        if inode_entry.home != inode_target.block {
            return Err(FsError::NotSupported);
        }
        let inode_image = self.frozen_overlay_image(post_images, inode_entry)?;
        let inode_end = inode_target
            .start
            .checked_add(size_of::<Ext2InodeRaw>())
            .ok_or(FsError::Invalid)?;
        let new_inode: Ext2InodeRaw = unsafe {
            core::ptr::read_unaligned(
                inode_image
                    .get(inode_target.start..inode_end)
                    .ok_or(FsError::Invalid)?
                    .as_ptr() as *const Ext2InodeRaw,
            )
        };
        self.validate_intent_inode_transition(intent, &new_inode)?;

        let mut pre_images = Vec::new();
        pre_images
            .try_reserve_exact(post_images.len())
            .map_err(|_| FsError::NoMem)?;
        pre_images.extend_from_slice(post_images);

        match intent.kind {
            ZERO_INTENT_KIND_INODE_UPDATE => {
                if overlay.len() != 1 || inode_entry.order != 0 {
                    return Err(FsError::NotSupported);
                }
                let pre = pre_images
                    .get_mut(
                        inode_entry.image_offset
                            ..inode_entry
                                .image_offset
                                .checked_add(self.block_size as usize)
                                .ok_or(FsError::Invalid)?,
                    )
                    .ok_or(FsError::Invalid)?;
                Self::replace_inode_in_block(pre, inode_target, &intent.old_inode)?;
            }
            ZERO_INTENT_KIND_DIRECT_ALLOCATION => {
                if overlay.len() != JOURNAL_MAX_METADATA_BLOCKS {
                    return Err(FsError::NotSupported);
                }
                let sb = *self.superblock.read();
                let relative = intent
                    .physical
                    .checked_sub(sb.first_data_block)
                    .ok_or(FsError::Invalid)?;
                let group = usize::try_from(relative / sb.blocks_per_group)
                    .map_err(|_| FsError::Invalid)?;
                let bit = relative % sb.blocks_per_group;
                let desc = self
                    .group_descs
                    .read()
                    .get(group)
                    .copied()
                    .ok_or(FsError::Invalid)?;
                let desc_target = self.group_desc_write_target(group)?;
                let expected_homes = [
                    desc.block_bitmap,
                    desc_target.block,
                    self.superblock_home_target().0,
                    inode_target.block,
                ];
                for order in 0..JOURNAL_MAX_METADATA_BLOCKS {
                    let entry = overlay
                        .iter()
                        .find(|entry| entry.order as usize == order)
                        .ok_or(FsError::Invalid)?;
                    if entry.home != expected_homes[order] {
                        return Err(FsError::NotSupported);
                    }
                }

                let bitmap_entry = overlay
                    .iter()
                    .find(|entry| entry.order == 0)
                    .ok_or(FsError::Invalid)?;
                let bitmap = pre_images
                    .get_mut(
                        bitmap_entry.image_offset
                            ..bitmap_entry
                                .image_offset
                                .checked_add(self.block_size as usize)
                                .ok_or(FsError::Invalid)?,
                    )
                    .ok_or(FsError::Invalid)?;
                let byte = bitmap.get_mut((bit / 8) as usize).ok_or(FsError::Invalid)?;
                let mask = 1u8 << (bit % 8);
                if *byte & mask == 0 {
                    return Err(FsError::NotSupported);
                }
                *byte &= !mask;

                let desc_entry = overlay
                    .iter()
                    .find(|entry| entry.order == 1)
                    .ok_or(FsError::Invalid)?;
                let desc_image = pre_images
                    .get_mut(
                        desc_entry.image_offset
                            ..desc_entry
                                .image_offset
                                .checked_add(self.block_size as usize)
                                .ok_or(FsError::Invalid)?,
                    )
                    .ok_or(FsError::Invalid)?;
                let desc_offset = desc_target
                    .offset
                    .checked_add(core::mem::offset_of!(Ext2GroupDesc, free_blocks_count))
                    .ok_or(FsError::Invalid)?;
                let after = u16::from_le_bytes(
                    desc_image
                        .get(desc_offset..desc_offset + 2)
                        .ok_or(FsError::Invalid)?
                        .try_into()
                        .map_err(|_| FsError::Invalid)?,
                );
                desc_image[desc_offset..desc_offset + 2]
                    .copy_from_slice(&after.checked_add(1).ok_or(FsError::Invalid)?.to_le_bytes());

                let super_entry = overlay
                    .iter()
                    .find(|entry| entry.order == 2)
                    .ok_or(FsError::Invalid)?;
                let super_image = pre_images
                    .get_mut(
                        super_entry.image_offset
                            ..super_entry
                                .image_offset
                                .checked_add(self.block_size as usize)
                                .ok_or(FsError::Invalid)?,
                    )
                    .ok_or(FsError::Invalid)?;
                let super_offset = self
                    .superblock_home_target()
                    .1
                    .checked_add(core::mem::offset_of!(Ext2Superblock, free_blocks_count))
                    .ok_or(FsError::Invalid)?;
                let after = u32::from_le_bytes(
                    super_image
                        .get(super_offset..super_offset + 4)
                        .ok_or(FsError::Invalid)?
                        .try_into()
                        .map_err(|_| FsError::Invalid)?,
                );
                super_image[super_offset..super_offset + 4]
                    .copy_from_slice(&after.checked_add(1).ok_or(FsError::Invalid)?.to_le_bytes());

                let inode_pre = pre_images
                    .get_mut(
                        inode_entry.image_offset
                            ..inode_entry
                                .image_offset
                                .checked_add(self.block_size as usize)
                                .ok_or(FsError::Invalid)?,
                    )
                    .ok_or(FsError::Invalid)?;
                Self::replace_inode_in_block(inode_pre, inode_target, &intent.old_inode)?;
            }
            _ => return Err(FsError::Invalid),
        }

        for entry in overlay {
            let order = usize::try_from(entry.order).map_err(|_| FsError::Invalid)?;
            let image = pre_images
                .get(
                    entry.image_offset
                        ..entry
                            .image_offset
                            .checked_add(self.block_size as usize)
                            .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            if Sha256::digest(image) != intent.preimage_hashes[order] {
                return Err(FsError::Invalid);
            }
        }
        Ok(pre_images)
    }

    fn recovery_home_kind(
        &self,
        home: u32,
        inode_table_blocks: u64,
    ) -> Result<Option<RecoveryHomeKind>, FsError> {
        if home >= self.blocks_count {
            return Err(FsError::Invalid);
        }
        if home == self.superblock_home_target().0 {
            return Ok(Some(RecoveryHomeKind::Superblock));
        }

        let sb = *self.superblock.read();
        let descs = self.group_descs.read();
        let desc_bytes = descs
            .len()
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let desc_blocks = u32::try_from(
            desc_bytes
                .checked_add(self.block_size as usize - 1)
                .ok_or(FsError::Invalid)?
                / self.block_size as usize,
        )
        .map_err(|_| FsError::Invalid)?;
        let first_desc: u32 = if self.block_size == 1024 { 2 } else { 1 };
        let desc_end = first_desc
            .checked_add(desc_blocks)
            .ok_or(FsError::Invalid)?;
        if home >= first_desc && home < desc_end {
            return Ok(Some(RecoveryHomeKind::GroupDescriptors));
        }

        let relative = match home.checked_sub(sb.first_data_block) {
            Some(relative) => relative,
            None => return Ok(None),
        };
        let group = relative / sb.blocks_per_group;
        let group = usize::try_from(group).map_err(|_| FsError::Invalid)?;
        let desc = descs.get(group).copied().ok_or(FsError::Invalid)?;
        if home == desc.block_bitmap {
            return Ok(Some(RecoveryHomeKind::BlockBitmap(group)));
        }
        let inode_end = (desc.inode_table as u64)
            .checked_add(inode_table_blocks)
            .ok_or(FsError::Invalid)?;
        if home as u64 >= desc.inode_table as u64 && (home as u64) < inode_end {
            return Ok(Some(RecoveryHomeKind::InodeTable(group)));
        }
        Ok(None)
    }

    fn bitmap_free_count(bitmap: &[u8], valid_bits: u32) -> Result<u32, FsError> {
        let full_bytes = usize::try_from(valid_bits / 8).map_err(|_| FsError::Invalid)?;
        let remainder = valid_bits % 8;
        let required = full_bytes
            .checked_add(usize::from(remainder != 0))
            .ok_or(FsError::Invalid)?;
        if required > bitmap.len() {
            return Err(FsError::Invalid);
        }
        let mut allocated = 0u32;
        for &byte in &bitmap[..full_bytes] {
            allocated = allocated
                .checked_add(byte.count_ones())
                .ok_or(FsError::Invalid)?;
        }
        if remainder != 0 {
            let mask = (1u8 << remainder) - 1;
            allocated = allocated
                .checked_add((bitmap[full_bytes] & mask).count_ones())
                .ok_or(FsError::Invalid)?;
        }
        valid_bits.checked_sub(allocated).ok_or(FsError::Invalid)
    }

    fn push_recovery_reference(blocks: &mut Vec<u32>, block: u32) -> Result<(), FsError> {
        if blocks.len() >= MAX_RECOVERY_REFERENCED_BLOCKS {
            return Err(FsError::NotSupported);
        }
        if blocks.len() == blocks.capacity() {
            blocks.try_reserve(1).map_err(|_| FsError::NoMem)?;
        }
        blocks.push(block);
        Ok(())
    }

    fn collect_recovery_mapping_tree(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        root: u32,
        level: u8,
        scanned_bytes: &mut usize,
        references: &mut Vec<u32>,
        mapping_blocks: &mut Vec<u32>,
        scratch: &mut JournalRecoveryScratch,
    ) -> Result<(), FsError> {
        if !(1..=3).contains(&level) {
            return Err(FsError::Invalid);
        }
        let root = self.validate_block(root)?.ok_or(FsError::Invalid)?;
        if journal.contains_physical(root) || self.is_structural_metadata_block(root)? {
            return Err(FsError::Invalid);
        }
        *scanned_bytes = scanned_bytes
            .checked_add(self.block_size as usize)
            .filter(|bytes| *bytes <= MAX_RECOVERY_MAPPING_SCAN_BYTES)
            .ok_or(FsError::NotSupported)?;
        Self::push_recovery_reference(references, root)?;
        Self::push_recovery_reference(mapping_blocks, root)?;
        self.read_virtual_block(journal, overlay, post_images, root, &mut scratch.control)?;

        let pointers = self.block_size as usize / 4;
        let mut children = Vec::new();
        children
            .try_reserve_exact(pointers)
            .map_err(|_| FsError::NoMem)?;
        for index in 0..pointers {
            children.push(read_u32_le(scratch.control.block(), index)?);
        }
        for child in children {
            if child == 0 {
                continue;
            }
            if level == 1 {
                let child = self.validate_block(child)?.ok_or(FsError::Invalid)?;
                Self::push_recovery_reference(references, child)?;
            } else {
                self.collect_recovery_mapping_tree(
                    journal,
                    overlay,
                    post_images,
                    child,
                    level - 1,
                    scanned_bytes,
                    references,
                    mapping_blocks,
                    scratch,
                )?;
            }
        }
        Ok(())
    }

    fn validate_recovery_references(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        references: &mut Vec<u32>,
        mapping_blocks: &mut Vec<u32>,
        scratch: &mut JournalRecoveryScratch,
    ) -> Result<(), FsError> {
        mapping_blocks.sort_unstable();
        if mapping_blocks.windows(2).any(|pair| pair[0] == pair[1]) {
            // A mapping node reused at two levels/branches destroys provenance
            // and can turn a later pointer update into a cross-tree mutation.
            return Err(FsError::Invalid);
        }
        references.sort_unstable();
        if references.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }

        let sb = *self.superblock.read();
        let mut loaded_group = None;
        for &physical in references.iter() {
            if journal.contains_physical(physical) || self.is_structural_metadata_block(physical)? {
                return Err(FsError::Invalid);
            }
            let relative = physical
                .checked_sub(sb.first_data_block)
                .ok_or(FsError::Invalid)?;
            let group = relative / sb.blocks_per_group;
            let bit = relative % sb.blocks_per_group;
            if loaded_group != Some(group) {
                let desc = self
                    .group_descs
                    .read()
                    .get(group as usize)
                    .copied()
                    .ok_or(FsError::Invalid)?;
                self.read_virtual_block(
                    journal,
                    overlay,
                    post_images,
                    desc.block_bitmap,
                    &mut scratch.data,
                )?;
                loaded_group = Some(group);
            }
            let allocated = scratch
                .data
                .block()
                .get((bit / 8) as usize)
                .copied()
                .ok_or(FsError::Invalid)?
                & (1u8 << (bit % 8))
                != 0;
            if !allocated {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }

    fn validate_recovery_overlay(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        intent: Option<&JournalCommitIntent>,
        scratch: &mut JournalRecoveryScratch,
    ) -> Result<(), FsError> {
        for pair in overlay.windows(2) {
            if pair[0].home >= pair[1].home {
                return Err(FsError::Invalid);
            }
        }

        let inode_table_blocks = (self.inodes_per_group as u64)
            .checked_mul(self.inode_size as u64)
            .and_then(|bytes| bytes.checked_add(self.block_size as u64 - 1))
            .ok_or(FsError::Invalid)?
            / self.block_size as u64;
        let mut changed_bitmap_groups = Vec::new();
        changed_bitmap_groups
            .try_reserve_exact(MAX_RECOVERY_CHANGED_BITMAPS)
            .map_err(|_| FsError::NoMem)?;
        for entry in overlay {
            match self.recovery_home_kind(entry.home, inode_table_blocks)? {
                Some(RecoveryHomeKind::BlockBitmap(group)) => {
                    if changed_bitmap_groups.len() >= MAX_RECOVERY_CHANGED_BITMAPS {
                        return Err(FsError::NotSupported);
                    }
                    changed_bitmap_groups.push(group);
                }
                Some(
                    RecoveryHomeKind::Superblock
                    | RecoveryHomeKind::GroupDescriptors
                    | RecoveryHomeKind::InodeTable(_),
                ) => {}
                None => {
                    // RF180-13 FIX: this implementation never journals file
                    // data, directory data, or indirect mapping blocks.  Such
                    // homes have no bounded ownership proof at mount, so they
                    // are not replayed speculatively.  Newly published mapping
                    // trees are instead validated from their inode roots below.
                    return Err(FsError::NotSupported);
                }
            }
        }
        changed_bitmap_groups.sort_unstable();
        changed_bitmap_groups.dedup();

        let original = *self.superblock.read();
        let (super_home, super_offset) = self.superblock_home_target();
        self.read_virtual_block(
            journal,
            overlay,
            post_images,
            super_home,
            &mut scratch.control,
        )?;
        let end = super_offset
            .checked_add(size_of::<Ext2Superblock>())
            .ok_or(FsError::Invalid)?;
        let super_bytes = scratch
            .control
            .block()
            .get(super_offset..end)
            .ok_or(FsError::Invalid)?;
        let proposed: Ext2Superblock =
            unsafe { core::ptr::read_unaligned(super_bytes.as_ptr() as *const _) };
        let immutable_super_changed = proposed.magic != EXT2_SUPER_MAGIC
            || proposed.inodes_count != original.inodes_count
            || proposed.blocks_count != original.blocks_count
            || proposed.first_data_block != original.first_data_block
            || proposed.log_block_size != original.log_block_size
            || proposed.blocks_per_group != original.blocks_per_group
            || proposed.frags_per_group != original.frags_per_group
            || proposed.inodes_per_group != original.inodes_per_group
            || proposed.rev_level != original.rev_level
            || proposed.inode_size != original.inode_size
            || proposed.first_ino != original.first_ino
            || proposed.feature_compat != original.feature_compat
            || proposed.feature_ro_compat != original.feature_ro_compat
            || (proposed.feature_incompat ^ original.feature_incompat)
                & !EXT3_FEATURE_INCOMPAT_RECOVER
                != 0
            || proposed.uuid != original.uuid
            || proposed.journal_uuid != original.journal_uuid
            || proposed.journal_inum != original.journal_inum
            || proposed.journal_dev != original.journal_dev
            || proposed.last_orphan != 0
            || proposed.free_blocks_count > proposed.blocks_count;
        if immutable_super_changed
            || (journal.start != 0
                && !self.dev.is_read_only()
                && proposed.feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER == 0)
        {
            return Err(FsError::Invalid);
        }

        let current_descs = self.group_descs.read();
        let resize_reserved = self.resize_reserved_blocks.read();
        let desc_bytes = current_descs
            .len()
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let desc_blocks = u32::try_from(
            desc_bytes
                .checked_add(self.block_size as usize - 1)
                .ok_or(FsError::Invalid)?
                / self.block_size as usize,
        )
        .map_err(|_| FsError::Invalid)?;
        let sparse_super = proposed.feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER != 0;
        let reserved_gdt = if proposed.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE != 0 {
            proposed.reserved_gdt_blocks as u32
        } else {
            0
        };
        let mut descriptor_free_total = 0u64;
        let mut loaded_desc_block = None;

        for group in 0..current_descs.len() {
            let target = self.group_desc_write_target(group)?;
            let current_desc = current_descs[group];
            let desc_home_changed = overlay
                .binary_search_by_key(&target.block, |entry| entry.home)
                .is_ok();
            let desc = if desc_home_changed {
                if loaded_desc_block != Some(target.block) {
                    self.read_virtual_block(
                        journal,
                        overlay,
                        post_images,
                        target.block,
                        &mut scratch.control,
                    )?;
                    loaded_desc_block = Some(target.block);
                }
                let desc_end = target
                    .offset
                    .checked_add(size_of::<Ext2GroupDesc>())
                    .ok_or(FsError::Invalid)?;
                let desc_bytes = scratch
                    .control
                    .block()
                    .get(target.offset..desc_end)
                    .ok_or(FsError::Invalid)?;
                unsafe { core::ptr::read_unaligned(desc_bytes.as_ptr() as *const _) }
            } else {
                current_desc
            };
            if desc.block_bitmap != current_desc.block_bitmap
                || desc.inode_bitmap != current_desc.inode_bitmap
                || desc.inode_table != current_desc.inode_table
            {
                return Err(FsError::Invalid);
            }

            let group_u32 = u32::try_from(group).map_err(|_| FsError::Invalid)?;
            let group_start = proposed
                .first_data_block
                .checked_add(
                    group_u32
                        .checked_mul(proposed.blocks_per_group)
                        .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            let group_blocks = cmp::min(
                proposed.blocks_per_group,
                proposed
                    .blocks_count
                    .checked_sub(group_start)
                    .ok_or(FsError::Invalid)?,
            );
            if desc.free_inodes_count != current_desc.free_inodes_count
                || desc.used_dirs_count != current_desc.used_dirs_count
            {
                // Inode allocation/deallocation is outside this driver's
                // journal writer and would require inode-bitmap provenance.
                return Err(FsError::NotSupported);
            }
            descriptor_free_total = descriptor_free_total
                .checked_add(desc.free_blocks_count as u64)
                .ok_or(FsError::Invalid)?;

            let bitmap_changed = changed_bitmap_groups.binary_search(&group).is_ok();
            if bitmap_changed || desc.free_blocks_count != current_desc.free_blocks_count {
                if desc.free_blocks_count != current_desc.free_blocks_count && !bitmap_changed {
                    return Err(FsError::Invalid);
                }
                self.read_virtual_block(
                    journal,
                    overlay,
                    post_images,
                    desc.block_bitmap,
                    &mut scratch.data,
                )?;
                let bitmap = scratch.data.block();
                let free = Self::bitmap_free_count(bitmap, group_blocks)?;
                if free != desc.free_blocks_count as u32 {
                    return Err(FsError::Invalid);
                }

                let group_end = group_start
                    .checked_add(group_blocks)
                    .ok_or(FsError::Invalid)?;
                let require_allocated = |physical: u32| -> Result<(), FsError> {
                    if physical < group_start || physical >= group_end {
                        return Ok(());
                    }
                    let bit = physical - group_start;
                    let allocated = bitmap
                        .get((bit / 8) as usize)
                        .copied()
                        .ok_or(FsError::Invalid)?
                        & (1u8 << (bit % 8))
                        != 0;
                    if allocated {
                        Ok(())
                    } else {
                        Err(FsError::Invalid)
                    }
                };
                require_allocated(desc.block_bitmap)?;
                require_allocated(desc.inode_bitmap)?;
                for offset in 0..inode_table_blocks {
                    let physical = (desc.inode_table as u64)
                        .checked_add(offset)
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or(FsError::Invalid)?;
                    require_allocated(physical)?;
                }
                if Self::group_has_superblock(group_u32, sparse_super) {
                    let reserved_end = group_start
                        .checked_add(1)
                        .and_then(|value| value.checked_add(desc_blocks))
                        .and_then(|value| value.checked_add(reserved_gdt))
                        .ok_or(FsError::Invalid)?
                        .min(proposed.blocks_count);
                    for physical in group_start..reserved_end {
                        require_allocated(physical)?;
                    }
                }
                let owned_start = journal
                    .owned_blocks
                    .partition_point(|physical| *physical < group_start);
                for &physical in &journal.owned_blocks[owned_start..] {
                    if physical >= group_end {
                        break;
                    }
                    require_allocated(physical)?;
                }
                let resize_start =
                    resize_reserved.partition_point(|physical| *physical < group_start);
                for &physical in &resize_reserved[resize_start..] {
                    if physical >= group_end {
                        break;
                    }
                    require_allocated(physical)?;
                }
            }
        }
        drop(resize_reserved);
        drop(current_descs);
        if descriptor_free_total != proposed.free_blocks_count as u64 {
            return Err(FsError::Invalid);
        }

        // Validate every changed inode-table block before it can reach home.
        // In addition to the root words, every newly published indirect tree
        // is walked under an explicit work/memory budget and every non-zero
        // child is proven allocated and disjoint from journal/structural homes.
        let mut recovery_mapping_scan_bytes = 0usize;
        for &entry in overlay {
            let group = match self.recovery_home_kind(entry.home, inode_table_blocks)? {
                Some(RecoveryHomeKind::InodeTable(group)) => group,
                _ => continue,
            };
            let desc = self
                .group_descs
                .read()
                .get(group)
                .copied()
                .ok_or(FsError::Invalid)?;
            self.read_overlay_image(post_images, entry, &mut scratch.data)?;
            let inodes_per_block = self.block_size as usize / self.inode_size as usize;
            let table_block = entry
                .home
                .checked_sub(desc.inode_table)
                .ok_or(FsError::Invalid)? as usize;
            let mut changes = Vec::new();
            changes
                .try_reserve_exact(inodes_per_block)
                .map_err(|_| FsError::NoMem)?;
            for slot in 0..inodes_per_block {
                let start = slot
                    .checked_mul(self.inode_size as usize)
                    .ok_or(FsError::Invalid)?;
                let end = start
                    .checked_add(size_of::<Ext2InodeRaw>())
                    .ok_or(FsError::Invalid)?;
                let new = scratch
                    .data
                    .block()
                    .get(start..end)
                    .ok_or(FsError::Invalid)?;
                let inode_number = group
                    .checked_mul(self.inodes_per_group as usize)
                    .and_then(|value| value.checked_add(table_block * inodes_per_block))
                    .and_then(|value| value.checked_add(slot + 1))
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(FsError::Invalid)?;
                let new_raw: Ext2InodeRaw =
                    unsafe { core::ptr::read_unaligned(new.as_ptr() as *const _) };
                let changed = intent.is_some_and(|intent| intent.inode_number == inode_number);
                let old_raw = if changed {
                    intent.ok_or(FsError::Invalid)?.old_inode
                } else {
                    new_raw
                };
                if changed || new_raw.mode != 0 {
                    changes.push((inode_number, old_raw, new_raw, changed));
                }
            }

            for (inode_number, old_raw, raw, changed) in changes {
                if inode_number == proposed.journal_inum
                    || (proposed.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE != 0
                        && inode_number == 7)
                {
                    if changed {
                        return Err(FsError::NotSupported);
                    }
                    continue;
                }
                if raw.mode == 0 {
                    // This writer has no truncate/unlink transaction.  Losing
                    // the last roots without a matched free protocol leaks
                    // persistent allocations, so deletion-style replay is not
                    // guessed at mount.
                    if changed {
                        return Err(FsError::NotSupported);
                    }
                    continue;
                }
                let inode_type = raw.mode & EXT2_S_IFMT;
                let inline_symlink = inode_type == EXT2_S_IFLNK
                    && raw.size_lo as usize <= core::mem::size_of_val(&raw.block);
                if inline_symlink
                    || !matches!(inode_type, EXT2_S_IFREG | EXT2_S_IFDIR | EXT2_S_IFLNK)
                {
                    continue;
                }
                if changed && (old_raw.mode == 0 || old_raw.mode & EXT2_S_IFMT != inode_type) {
                    return Err(FsError::NotSupported);
                }

                let mut roots = 0u32;
                let mut references = Vec::new();
                references
                    .try_reserve_exact(EXT2_NDIR_BLOCKS + 3)
                    .map_err(|_| FsError::NoMem)?;
                let mut mapping_blocks = Vec::new();
                mapping_blocks
                    .try_reserve_exact(3)
                    .map_err(|_| FsError::NoMem)?;
                for index in 0..EXT2_NDIR_BLOCKS {
                    let physical = raw.block[index];
                    if physical != 0
                        && (journal.contains_physical(physical)
                            || self.is_structural_metadata_block(physical)?)
                    {
                        return Err(FsError::Invalid);
                    }
                    if changed
                        && old_raw.block[index] != physical
                        && (old_raw.block[index] != 0 || physical == 0)
                    {
                        return Err(FsError::NotSupported);
                    }
                    if physical == 0 {
                        continue;
                    }
                    roots = roots.checked_add(1).ok_or(FsError::Invalid)?;
                    let physical = self.validate_block(physical)?.ok_or(FsError::Invalid)?;
                    Self::push_recovery_reference(&mut references, physical)?;
                }

                for (index, level) in [
                    (EXT2_IND_BLOCK, 1u8),
                    (EXT2_DIND_BLOCK, 2u8),
                    (EXT2_TIND_BLOCK, 3u8),
                ] {
                    let physical = raw.block[index];
                    let old_physical = old_raw.block[index];
                    if physical != 0
                        && (journal.contains_physical(physical)
                            || self.is_structural_metadata_block(physical)?)
                    {
                        return Err(FsError::Invalid);
                    }
                    if changed && old_physical != physical && (old_physical != 0 || physical == 0) {
                        return Err(FsError::NotSupported);
                    }
                    if physical == 0 {
                        continue;
                    }
                    roots = roots.checked_add(1).ok_or(FsError::Invalid)?;
                    if changed && old_physical == physical {
                        let physical = self.validate_block(physical)?.ok_or(FsError::Invalid)?;
                        Self::push_recovery_reference(&mut references, physical)?;
                    } else {
                        self.collect_recovery_mapping_tree(
                            journal,
                            overlay,
                            post_images,
                            physical,
                            level,
                            &mut recovery_mapping_scan_bytes,
                            &mut references,
                            &mut mapping_blocks,
                            scratch,
                        )?;
                    }
                }
                self.validate_recovery_references(
                    journal,
                    overlay,
                    post_images,
                    &mut references,
                    &mut mapping_blocks,
                    scratch,
                )?;
                let validated_blocks =
                    u32::try_from(references.len()).map_err(|_| FsError::Invalid)?;
                let minimum_blocks = roots.max(validated_blocks);
                let minimum_sectors = minimum_blocks
                    .checked_mul(self.block_size / 512)
                    .ok_or(FsError::Invalid)?;
                if raw.blocks_lo < minimum_sectors {
                    return Err(FsError::Invalid);
                }
            }
        }
        Ok(())
    }

    fn revalidate_overlay_homes(
        &self,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
        scratch: &mut JournalRecoveryScratch,
    ) -> Result<(), FsError> {
        for &entry in overlay {
            self.read_overlay_image(post_images, entry, &mut scratch.data)?;
            self.read_physical_block(entry.home, scratch.control.block_mut())?;
            if scratch.control.block() != scratch.data.block() {
                return Err(FsError::Io);
            }
        }
        Ok(())
    }

    /// Accept exactly the durable states produced by one prefix-torn block
    /// checkpoint: a prefix from the post-image followed by a suffix from the
    /// canonical pre-image.  This also requires every byte unchanged by the
    /// writer to match the actual home, preventing an attacker from re-signing
    /// unrelated neighbor metadata into a logged whole-block image.
    fn checkpoint_matches_single_prefix(
        current: &[u8],
        pre_image: &[u8],
        post_image: &[u8],
    ) -> bool {
        if current.len() != pre_image.len() || current.len() != post_image.len() {
            return false;
        }

        let mut suffix_mismatches = current
            .iter()
            .zip(pre_image)
            .filter(|(current, pre)| current != pre)
            .count();
        if suffix_mismatches == 0 {
            return true;
        }

        let mut prefix_matches = true;
        for index in 0..current.len() {
            prefix_matches &= current[index] == post_image[index];
            if current[index] != pre_image[index] {
                suffix_mismatches -= 1;
            }
            if prefix_matches && suffix_mismatches == 0 {
                return true;
            }
        }
        false
    }

    fn validate_checkpoint_homes(
        &self,
        overlay: &[JournalOverlayEntry],
        pre_images: &[u8],
        post_images: &[u8],
        scratch: &mut JournalRecoveryScratch,
    ) -> Result<(), FsError> {
        for &entry in overlay {
            let pre_image = self.frozen_overlay_image(pre_images, entry)?;
            let post_image = self.frozen_overlay_image(post_images, entry)?;
            self.read_physical_block(entry.home, scratch.control.block_mut())?;
            if !Self::checkpoint_matches_single_prefix(
                scratch.control.block(),
                pre_image,
                post_image,
            ) {
                return Err(FsError::NotSupported);
            }
        }
        Ok(())
    }

    fn decode_commit_intent(block: &[u8]) -> Result<JournalCommitIntent, FsError> {
        if block.len() < ZERO_INTENT_END
            || block[ZERO_INTENT_MAGIC_OFFSET..ZERO_INTENT_MAGIC_OFFSET + 4] != ZERO_INTENT_MAGIC
            || read_be_u16(block, ZERO_INTENT_VERSION_OFFSET)? != ZERO_INTENT_VERSION
            || block[ZERO_INTENT_END..].iter().any(|byte| *byte != 0)
        {
            return Err(FsError::Invalid);
        }
        let kind = block[ZERO_INTENT_KIND_OFFSET];
        let metadata_count = block[ZERO_INTENT_COUNT_OFFSET];
        let inode_number = read_be_u32(block, ZERO_INTENT_INODE_OFFSET)?;
        let file_block = read_be_u32(block, ZERO_INTENT_FILE_BLOCK_OFFSET)?;
        let physical = read_be_u32(block, ZERO_INTENT_PHYSICAL_OFFSET)?;
        let valid_update = kind == ZERO_INTENT_KIND_INODE_UPDATE
            && metadata_count == 1
            && file_block == u32::MAX
            && physical == 0;
        let valid_direct = kind == ZERO_INTENT_KIND_DIRECT_ALLOCATION
            && metadata_count == JOURNAL_MAX_METADATA_BLOCKS as u8
            && file_block < EXT2_NDIR_BLOCKS as u32
            && physical != 0;
        if inode_number == 0 || (!valid_update && !valid_direct) {
            return Err(FsError::Invalid);
        }
        let mut preimage_hashes = [[0u8; 32]; JOURNAL_MAX_METADATA_BLOCKS];
        for (index, digest) in preimage_hashes.iter_mut().enumerate() {
            let start = ZERO_INTENT_PREIMAGE_HASHES_OFFSET + index * 32;
            digest.copy_from_slice(&block[start..start + 32]);
        }
        if metadata_count == 1
            && preimage_hashes[1..]
                .iter()
                .any(|digest| *digest != [0u8; 32])
        {
            return Err(FsError::Invalid);
        }
        let old_inode: Ext2InodeRaw = unsafe {
            core::ptr::read_unaligned(
                block[ZERO_INTENT_OLD_INODE_OFFSET..ZERO_INTENT_DIGEST_OFFSET].as_ptr()
                    as *const Ext2InodeRaw,
            )
        };
        Ok(JournalCommitIntent {
            kind,
            metadata_count,
            inode_number,
            file_block,
            physical,
            preimage_hashes,
            old_inode,
        })
    }

    fn commit_candidate(
        block: &[u8],
        sequence: u32,
        expected_count: u8,
    ) -> Option<JournalCommitIntent> {
        if read_be_u32(block, 0).ok() != Some(JBD2_MAGIC)
            || read_be_u32(block, 4).ok() != Some(JBD2_COMMIT_BLOCK)
            || read_be_u32(block, 8).ok() != Some(sequence)
        {
            return None;
        }
        Self::decode_commit_intent(block)
            .ok()
            .filter(|intent| intent.metadata_count == expected_count)
    }

    fn plan_recovery_candidate(
        &self,
        journal: &Ext2Journal,
        descriptor: &[u8],
        raw_images: &[u8],
        commit: &[u8],
        expected_count: u8,
    ) -> Result<Option<JournalRecoveryPlan>, FsError> {
        if expected_count != 1 && expected_count != JOURNAL_MAX_METADATA_BLOCKS as u8 {
            return Err(FsError::Invalid);
        }
        let Some(intent) = Self::commit_candidate(commit, journal.next_sequence, expected_count)
        else {
            return Ok(None);
        };
        let expected_bytes = usize::from(expected_count)
            .checked_mul(self.block_size as usize)
            .ok_or(FsError::Invalid)?;
        if raw_images.len() != expected_bytes {
            return Err(FsError::Invalid);
        }

        let mut hasher = Self::transaction_hasher(journal, journal.next_sequence, descriptor);
        for image in raw_images.chunks_exact(self.block_size as usize) {
            hasher.update(image);
        }
        let actual = Self::finish_transaction_digest(hasher, commit)?;
        if commit[ZERO_INTENT_DIGEST_OFFSET..ZERO_INTENT_END] != actual {
            // A matching header can be stale after the 32-bit sequence wraps,
            // or can be a raw metadata image that happens to resemble a commit
            // block.  It is not authoritative until the complete transaction
            // digest matches the current descriptor and post-images.
            return Ok(None);
        }

        // The descriptor grammar is part of candidate selection, not a check
        // deferred until after two possible commit slots have been declared
        // ambiguous.  Exact LAST_TAG placement and zero padding make the one-
        // and four-image forms mutually exclusive.
        let (overlay, post_images) =
            self.collect_linear_overlay(journal, descriptor, raw_images, intent)?;
        Ok(Some(JournalRecoveryPlan {
            next_sequence: journal.next_sequence.wrapping_add(1),
            overlay,
            post_images,
            intent: Some(intent),
        }))
    }

    fn collect_linear_overlay(
        &self,
        journal: &Ext2Journal,
        descriptor: &[u8],
        raw_images: &[u8],
        intent: JournalCommitIntent,
    ) -> Result<(Vec<JournalOverlayEntry>, Vec<u8>), FsError> {
        if descriptor.len() != self.block_size as usize
            || raw_images.len()
                != usize::from(intent.metadata_count)
                    .checked_mul(self.block_size as usize)
                    .ok_or(FsError::Invalid)?
            || read_be_u32(descriptor, 0)? != JBD2_MAGIC
            || read_be_u32(descriptor, 4)? != JBD2_DESCRIPTOR_BLOCK
            || read_be_u32(descriptor, 8)? != journal.next_sequence
        {
            return Err(FsError::Invalid);
        }
        let count = usize::from(intent.metadata_count);
        let mut overlay = Vec::new();
        overlay
            .try_reserve_exact(count)
            .map_err(|_| FsError::NoMem)?;
        let mut post_images = Vec::new();
        post_images
            .try_reserve_exact(raw_images.len())
            .map_err(|_| FsError::NoMem)?;
        post_images.extend_from_slice(raw_images);

        let mut offset = JBD2_HEADER_BYTES;
        for index in 0..count {
            let tag_end = offset.checked_add(JBD2_TAG_BYTES).ok_or(FsError::Invalid)?;
            if tag_end > descriptor.len() {
                return Err(FsError::Invalid);
            }
            let home = read_be_u32(descriptor, offset)?;
            if read_be_u16(descriptor, offset + 4)? != 0
                || home >= self.blocks_count
                || journal.contains_physical(home)
                || overlay
                    .iter()
                    .any(|entry: &JournalOverlayEntry| entry.home == home)
            {
                return Err(FsError::Invalid);
            }
            let flags = read_be_u16(descriptor, offset + 6)?;
            let expected = if index == 0 { 0 } else { JBD2_FLAG_SAME_UUID }
                | if index + 1 == count {
                    JBD2_FLAG_LAST_TAG
                } else {
                    0
                };
            if flags & !JBD2_FLAG_ESCAPE != expected {
                return Err(FsError::NotSupported);
            }
            offset = tag_end;
            if index == 0 {
                let uuid_end = offset.checked_add(16).ok_or(FsError::Invalid)?;
                if descriptor.get(offset..uuid_end) != Some(journal.uuid.as_slice()) {
                    return Err(FsError::Invalid);
                }
                offset = uuid_end;
            }
            let image_offset = index
                .checked_mul(self.block_size as usize)
                .ok_or(FsError::Invalid)?;
            let first_word = read_be_u32(&post_images, image_offset)?;
            if flags & JBD2_FLAG_ESCAPE != 0 {
                if first_word != 0 {
                    return Err(FsError::Invalid);
                }
                post_images[image_offset..image_offset + 4]
                    .copy_from_slice(&JBD2_MAGIC.to_be_bytes());
            } else if first_word == JBD2_MAGIC {
                return Err(FsError::Invalid);
            }
            overlay.push(JournalOverlayEntry {
                home,
                log: journal
                    .first
                    .checked_add(1)
                    .and_then(|logical| logical.checked_add(index as u32))
                    .filter(|logical| *logical < journal.max_len)
                    .ok_or(FsError::Invalid)?,
                flags,
                order: index as u32,
                image_offset,
            });
        }
        if descriptor[offset..].iter().any(|byte| *byte != 0) {
            return Err(FsError::NotSupported);
        }
        overlay.sort_unstable_by_key(|entry| entry.home);
        Ok((overlay, post_images))
    }

    fn plan_internal_journal_recovery(
        &self,
        journal: &Ext2Journal,
    ) -> Result<Option<JournalRecoveryPlan>, FsError> {
        if journal.start == 0 {
            return Ok(None);
        }
        if journal.first != 1
            || journal.start != journal.first
            || journal.feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT == 0
        {
            return Err(FsError::NotSupported);
        }
        let one_commit_logical = journal.first.checked_add(2).ok_or(FsError::Invalid)?;
        let four_commit_logical = journal.first.checked_add(5).ok_or(FsError::Invalid)?;
        if four_commit_logical >= journal.max_len {
            return Err(FsError::Invalid);
        }

        // Capture every block used for candidate selection once. Logical block
        // 3 is either the one-image commit or the second post-image of a four-
        // image transaction. A fully validated one-image candidate returns
        // before logical blocks 4..6 are read, so a stale commit in the distant
        // slot cannot create an ambiguity after sequence wrap.
        let mut descriptor = Ext2MutationScratch::try_new(self.block_size)?;
        let mut one_commit = Ext2MutationScratch::try_new(self.block_size)?;
        self.read_journal_block(journal, journal.first, descriptor.block_mut())?;
        let raw_block_bytes = self.block_size as usize;
        let raw_bytes = JOURNAL_MAX_METADATA_BLOCKS
            .checked_mul(raw_block_bytes)
            .ok_or(FsError::Invalid)?;
        let mut raw_images = Vec::new();
        raw_images
            .try_reserve_exact(raw_block_bytes)
            .map_err(|_| FsError::NoMem)?;
        raw_images.resize(raw_block_bytes, 0);
        let first_image_logical = journal
            .first
            .checked_add(1)
            .filter(|logical| *logical < journal.max_len)
            .ok_or(FsError::Invalid)?;
        self.read_journal_block(
            journal,
            first_image_logical,
            &mut raw_images[..raw_block_bytes],
        )?;
        self.read_journal_block(journal, one_commit_logical, one_commit.block_mut())?;

        let one_error = match self.plan_recovery_candidate(
            journal,
            descriptor.block(),
            &raw_images,
            one_commit.block(),
            1,
        ) {
            Ok(Some(plan)) => return Ok(Some(plan)),
            Ok(None) => None,
            Err(error @ (FsError::Invalid | FsError::NotSupported)) => Some(error),
            Err(error) => return Err(error),
        };

        // The one-image form was not authoritative. Reuse its candidate block
        // as post-image 1, then capture only the remaining four-image blocks.
        raw_images
            .try_reserve_exact(
                raw_bytes
                    .checked_sub(raw_block_bytes)
                    .ok_or(FsError::Invalid)?,
            )
            .map_err(|_| FsError::NoMem)?;
        raw_images.resize(raw_bytes, 0);
        let second_image_end = raw_block_bytes.checked_mul(2).ok_or(FsError::Invalid)?;
        raw_images
            .get_mut(raw_block_bytes..second_image_end)
            .ok_or(FsError::Invalid)?
            .copy_from_slice(one_commit.block());
        for index in 2..JOURNAL_MAX_METADATA_BLOCKS {
            let index_u32 = u32::try_from(index).map_err(|_| FsError::Invalid)?;
            let logical = journal
                .first
                .checked_add(1)
                .and_then(|value| value.checked_add(index_u32))
                .filter(|value| *value < journal.max_len)
                .ok_or(FsError::Invalid)?;
            let start = index.checked_mul(raw_block_bytes).ok_or(FsError::Invalid)?;
            let end = start.checked_add(raw_block_bytes).ok_or(FsError::Invalid)?;
            self.read_journal_block(
                journal,
                logical,
                raw_images.get_mut(start..end).ok_or(FsError::Invalid)?,
            )?;
        }
        let mut four_commit = Ext2MutationScratch::try_new(self.block_size)?;
        self.read_journal_block(journal, four_commit_logical, four_commit.block_mut())?;
        match self.plan_recovery_candidate(
            journal,
            descriptor.block(),
            &raw_images,
            four_commit.block(),
            JOURNAL_MAX_METADATA_BLOCKS as u8,
        ) {
            Ok(Some(plan)) => Ok(Some(plan)),
            Ok(None) => {
                if let Some(error) = one_error {
                    return Err(error);
                }
                // Neither slot contains an authoritative commit. The caller
                // validates the current filesystem before clearing the tail.
                Ok(Some(JournalRecoveryPlan {
                    next_sequence: journal.next_sequence,
                    overlay: Vec::new(),
                    post_images: Vec::new(),
                    intent: None,
                }))
            }
            Err(error) => Err(error),
        }
    }

    fn apply_internal_journal_recovery(&self, plan: &JournalRecoveryPlan) -> Result<(), FsError> {
        let mut scratch = JournalRecoveryScratch::try_new(self.block_size)?;
        let overlay = plan.overlay.as_slice();
        for order in 0..overlay.len() {
            let entry = overlay
                .iter()
                .copied()
                .find(|entry| entry.order as usize == order)
                .ok_or(FsError::Invalid)?;
            let image = self.frozen_overlay_image(&plan.post_images, entry)?;
            self.write_physical_block(entry.home, image)?;
        }
        if !overlay.is_empty() {
            self.flush_device()?;
        }
        self.revalidate_overlay_homes(overlay, &plan.post_images, &mut scratch)?;
        Ok(())
    }

    fn clear_recovered_journal(
        &self,
        journal: &mut Ext2Journal,
        plan: &JournalRecoveryPlan,
    ) -> Result<(), FsError> {
        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        self.write_journal_state(journal, plan.next_sequence, 0, &mut scratch)?;
        self.flush_device()?;
        self.read_journal_block(journal, 0, scratch.block_mut())?;
        let superblock = scratch.block();
        if read_be_u32(superblock, 0)? != JBD2_MAGIC
            || read_be_u32(superblock, 4)? != JBD2_SUPERBLOCK_V2
            || read_be_u32(superblock, JBD2_SUPER_SEQUENCE_OFFSET)? != plan.next_sequence
            || read_be_u32(superblock, JBD2_SUPER_START_OFFSET)? != 0
            || read_be_u32(superblock, JBD2_SUPER_BLOCKSIZE_OFFSET)? != self.block_size
            || read_be_u32(superblock, JBD2_SUPER_MAXLEN_OFFSET)? != journal.max_len
            || read_be_u32(superblock, JBD2_SUPER_FIRST_OFFSET)? != journal.first
            || read_be_u32(superblock, JBD2_SUPER_FEATURE_INCOMPAT_OFFSET)?
                != journal.feature_incompat
            || superblock.get(JBD2_SUPER_UUID_OFFSET..JBD2_SUPER_UUID_OFFSET + 16)
                != Some(journal.uuid.as_slice())
        {
            return Err(FsError::Io);
        }
        journal.next_sequence = plan.next_sequence;
        journal.start = 0;
        Ok(())
    }

    /// Load block group descriptor table.
    ///
    /// # R99-2 FIX: Defense-in-depth checked arithmetic and BGDT bounds
    ///
    /// Although `read_super()` already validates `blocks_per_group >= 8` and
    /// `blocks_count > 0`, this function re-derives `groups_count` from the
    /// superblock.  Using checked arithmetic here guards against any future
    /// caller that bypasses `read_super()` validation, and validates that the
    /// BGDT itself fits within the filesystem.
    fn load_group_descs(
        dev: &Arc<dyn BlockDevice>,
        sb: &Ext2Superblock,
        block_size: u32,
    ) -> Result<Vec<Ext2GroupDesc>, FsError> {
        // R99-2 FIX: Calculate number of block groups using checked arithmetic.
        // ceil_div(blocks_count, blocks_per_group) without overflow.
        let bpg_minus_one = sb.blocks_per_group.checked_sub(1).ok_or(FsError::Invalid)?;
        let groups_count = sb
            .blocks_count
            .checked_sub(sb.first_data_block)
            .ok_or(FsError::Invalid)?
            .checked_add(bpg_minus_one)
            .ok_or(FsError::Invalid)?
            / sb.blocks_per_group;

        // BGDT starts at block 2 for 1K blocks, block 1 for larger blocks
        let bgdt_block: u32 = if block_size == 1024 { 2 } else { 1 };

        // R99-2 FIX: Validate that the BGDT start block is within filesystem bounds.
        if bgdt_block >= sb.blocks_count {
            return Err(FsError::Invalid);
        }

        let bgdt_offset = bgdt_block as u64 * block_size as u64;

        // Read BGDT
        let bgdt_size = (groups_count as usize)
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        // R106-6 FIX: Use validated_sector_size() — replaces ad-hoc inline zero check.
        let sector_size = validated_sector_size(&**dev)? as usize;
        let sectors_needed = bgdt_size
            .checked_add(sector_size - 1)
            .ok_or(FsError::Invalid)?
            / sector_size;
        let read_len = sectors_needed
            .checked_mul(sector_size)
            .ok_or(FsError::Invalid)?;

        // R99-2 FIX: Ensure the BGDT does not extend beyond the filesystem.
        let fs_byte_size = (sb.blocks_count as u64)
            .checked_mul(block_size as u64)
            .ok_or(FsError::Invalid)?;
        let bgdt_end = bgdt_offset
            .checked_add(read_len as u64)
            .ok_or(FsError::Invalid)?;
        if bgdt_end > fs_byte_size {
            return Err(FsError::Invalid);
        }

        // MEDIUM-7 FIX: Use fallible allocation to prevent OOM panic during mount
        let mut buf = Vec::new();
        buf.try_reserve_exact(read_len)
            .map_err(|_| FsError::NoMem)?;
        buf.resize(read_len, 0);

        let start_sector = bgdt_offset / sector_size as u64;
        let read = dev
            .read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;
        if read != buf.len() {
            return Err(FsError::Io);
        }

        // Parse group descriptors
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        // MEDIUM-7 FIX: Use fallible allocation to prevent OOM panic during mount
        let mut descs = Vec::new();
        descs
            .try_reserve_exact(groups_count as usize)
            .map_err(|_| FsError::NoMem)?;
        for i in 0..groups_count as usize {
            let offset = i * size_of::<Ext2GroupDesc>();
            let gd: Ext2GroupDesc =
                unsafe { core::ptr::read_unaligned(buf[offset..].as_ptr() as *const _) };
            descs.push(gd);
        }

        // Without FLEX_BG (an unsupported incompat feature), every bitmap and
        // inode table must be wholly owned by the group whose descriptor names
        // it. Validate that layout before resize/journal inode reads can follow
        // attacker-controlled metadata pointers.
        let inode_table_blocks = (sb.inodes_per_group as u64)
            .checked_mul(if sb.rev_level >= 1 {
                sb.inode_size as u64
            } else {
                size_of::<Ext2InodeRaw>() as u64
            })
            .and_then(|bytes| bytes.checked_add(block_size as u64 - 1))
            .ok_or(FsError::Invalid)?
            / block_size as u64;
        let desc_blocks = u32::try_from(
            bgdt_size
                .checked_add(block_size as usize - 1)
                .ok_or(FsError::Invalid)?
                / block_size as usize,
        )
        .map_err(|_| FsError::Invalid)?;
        let sparse_super = sb.feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER != 0;
        let reserved_gdt = if sb.feature_compat & EXT2_FEATURE_COMPAT_RESIZE_INODE != 0 {
            sb.reserved_gdt_blocks as u32
        } else {
            0
        };
        for (group, desc) in descs.iter().copied().enumerate() {
            let group = u32::try_from(group).map_err(|_| FsError::Invalid)?;
            let group_start = sb
                .first_data_block
                .checked_add(
                    group
                        .checked_mul(sb.blocks_per_group)
                        .ok_or(FsError::Invalid)?,
                )
                .ok_or(FsError::Invalid)?;
            let group_blocks = cmp::min(
                sb.blocks_per_group,
                sb.blocks_count
                    .checked_sub(group_start)
                    .ok_or(FsError::Invalid)?,
            );
            let group_end = group_start
                .checked_add(group_blocks)
                .ok_or(FsError::Invalid)?;
            let inode_table_end = (desc.inode_table as u64)
                .checked_add(inode_table_blocks)
                .ok_or(FsError::Invalid)?;
            if desc.block_bitmap < group_start
                || desc.block_bitmap >= group_end
                || desc.inode_bitmap < group_start
                || desc.inode_bitmap >= group_end
                || desc.block_bitmap == desc.inode_bitmap
                || desc.inode_table < group_start
                || inode_table_end > group_end as u64
                || (desc.block_bitmap as u64 >= desc.inode_table as u64
                    && (desc.block_bitmap as u64) < inode_table_end)
                || (desc.inode_bitmap as u64 >= desc.inode_table as u64
                    && (desc.inode_bitmap as u64) < inode_table_end)
                || desc.free_blocks_count as u32 > group_blocks
            {
                return Err(FsError::Invalid);
            }

            let first_inode = group
                .checked_mul(sb.inodes_per_group)
                .ok_or(FsError::Invalid)?;
            let group_inodes = cmp::min(
                sb.inodes_per_group,
                sb.inodes_count.saturating_sub(first_inode),
            );
            if desc.free_inodes_count as u32 > group_inodes
                || desc.used_dirs_count as u32 > group_inodes
            {
                return Err(FsError::Invalid);
            }

            if Self::group_has_superblock(group, sparse_super) {
                let reserved_end = group_start
                    .checked_add(1)
                    .and_then(|value| value.checked_add(desc_blocks))
                    .and_then(|value| value.checked_add(reserved_gdt))
                    .ok_or(FsError::Invalid)?;
                if reserved_end > group_end
                    || (desc.block_bitmap >= group_start && desc.block_bitmap < reserved_end)
                    || (desc.inode_bitmap >= group_start && desc.inode_bitmap < reserved_end)
                    || (desc.inode_table < reserved_end && inode_table_end > group_start as u64)
                {
                    return Err(FsError::Invalid);
                }
            }
        }

        Ok(descs)
    }

    /// Read a block from the device.
    ///
    /// # R99-1 FIX: Defense-in-depth bounds validation
    ///
    /// Mirror `write_block()` by calling `validate_block()` before issuing I/O.
    /// Block 0 is treated as a sparse block (zero-filled) rather than performing
    /// a device read at offset 0.
    fn read_block(&self, block_no: u32, buf: &mut [u8]) -> Result<(), FsError> {
        if buf.len() < self.block_size as usize {
            return Err(FsError::Invalid);
        }

        // R99-1 FIX: Validate block number against filesystem bounds.
        // validate_block returns None for block 0 (sparse), Some(n) for valid,
        // or Err for out-of-bounds.  Deadlock-safe (R99-4: uses cached blocks_count).
        let block_no = match self.validate_block(block_no)? {
            Some(b) => b,
            None => {
                // Sparse block: zero-fill the buffer instead of reading
                buf[..self.block_size as usize].fill(0);
                return Ok(());
            }
        };

        self.read_physical_block(block_no, buf)
    }

    /// Read an actual filesystem block, including physical block zero. This is
    /// reserved for filesystem metadata and JBD2 recovery; file block zero
    /// continues to mean a sparse mapping through [`read_block`].
    fn read_physical_block(&self, block_no: u32, buf: &mut [u8]) -> Result<(), FsError> {
        if buf.len() < self.block_size as usize || block_no >= self.blocks_count {
            return Err(FsError::Invalid);
        }

        // R106-6 FIX: Use cached, pre-validated sector_size.
        let sector_size = self.sector_size;
        let block_offset = block_no as u64 * self.block_size as u64;
        let start_sector = block_offset / sector_size;

        let read = self
            .dev
            .read_sync(start_sector, &mut buf[..self.block_size as usize])
            .map_err(|_| FsError::Io)?;
        if read != self.block_size as usize {
            return Err(FsError::Io);
        }
        Ok(())
    }

    /// Write a block to the device
    fn write_block(&self, block_no: u32, data: &[u8]) -> Result<(), FsError> {
        if data.len() < self.block_size as usize {
            return Err(FsError::Invalid);
        }
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        // Validate block number is within bounds
        let block_no = self.validate_block(block_no)?.ok_or(FsError::Invalid)?;

        self.write_physical_block(block_no, data)
    }

    /// Write an actual filesystem block, including physical block zero, after
    /// the caller has validated that it is metadata rather than a sparse file
    /// mapping.
    fn write_physical_block(&self, block_no: u32, data: &[u8]) -> Result<(), FsError> {
        if data.len() < self.block_size as usize || block_no >= self.blocks_count {
            return Err(FsError::Invalid);
        }
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        // R106-6 FIX: Use cached, pre-validated sector_size.
        let sector_size = self.sector_size;
        let block_offset = block_no as u64 * self.block_size as u64;
        let start_sector = block_offset / sector_size;

        let written = self
            .dev
            .write_sync(start_sector, &data[..self.block_size as usize])
            .map_err(|_| FsError::Io)?;
        if written != self.block_size as usize {
            return Err(FsError::Io);
        }
        Ok(())
    }

    /// R180-6 FIX: order and stabilize each in-place data/inode commit.
    /// A flush failure is treated as an ambiguous durability result and
    /// poisons later file I/O until remount.
    fn flush_device(&self) -> Result<(), FsError> {
        self.dev.flush().map_err(|_| FsError::Io)
    }

    /// R186-7: is `ino`'s inode-bitmap bit set?
    ///
    /// This is the authority that binds an on-disk inode NUMBER to an actually
    /// ALLOCATED object. Callers that resolve an inode number originating from
    /// untrusted on-disk data (directory entries) must consult it before treating
    /// the inode-table slot as an object.
    ///
    /// `bitmap_block` and `blocks_count` are passed in so the caller's already-read
    /// group descriptor and superblock snapshot are reused rather than re-locked.
    fn inode_is_allocated_in(
        &self,
        ino: u32,
        bitmap_block: u32,
        blocks_count: u32,
    ) -> Result<bool, FsError> {
        // A bitmap outside the filesystem cannot be consulted; refusing is the
        // only fail-closed answer (never "assume allocated").
        if bitmap_block == 0 || bitmap_block >= blocks_count {
            return Err(FsError::Invalid);
        }

        let (_group, index) = self.inode_group_index(ino);

        let mut bitmap_buf = Vec::new();
        bitmap_buf
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| FsError::NoSpace)?;
        bitmap_buf.resize(self.block_size as usize, 0u8);
        self.read_block(bitmap_block, &mut bitmap_buf)?;

        let byte = bitmap_buf.get(index / 8).copied().ok_or(FsError::Invalid)?;
        Ok(byte & (1u8 << (index % 8)) != 0)
    }

    /// R186-7: allocation check that resolves the bitmap block itself.
    ///
    /// Used by the cache-hit assertion, which has no descriptor snapshot in hand.
    fn inode_is_allocated(&self, ino: u32) -> Result<bool, FsError> {
        let sb = self.superblock.read();
        if ino == 0 || ino > sb.inodes_count {
            return Err(FsError::NotFound);
        }
        let blocks_count = sb.blocks_count;
        drop(sb);

        let (group, _index) = self.inode_group_index(ino);
        let bitmap_block = {
            let descs = self.group_descs.read();
            descs.get(group).ok_or(FsError::Invalid)?.inode_bitmap
        };
        self.inode_is_allocated_in(ino, bitmap_block, blocks_count)
    }

    /// Read raw inode from disk
    fn read_inode_raw(&self, ino: u32) -> Result<Ext2InodeRaw, FsError> {
        self.ensure_io_healthy()?;
        let sb = self.superblock.read();
        if ino == 0 || ino > sb.inodes_count {
            return Err(FsError::NotFound);
        }
        let blocks_count = sb.blocks_count;
        drop(sb);

        // Calculate group and index
        let (group, index) = self.inode_group_index(ino);

        // Get inode table block and bitmap block
        // R65-EXT2-3 FIX: Bounds check group descriptor access to prevent OOB read.
        let group_descs = self.group_descs.read();
        if group >= group_descs.len() {
            return Err(FsError::Invalid);
        }
        let inode_table_block = group_descs[group].inode_table;
        let inode_bitmap_block = group_descs[group].inode_bitmap;
        drop(group_descs);

        // Validate inode table block is within filesystem bounds
        if inode_table_block == 0 || inode_table_block >= blocks_count {
            return Err(FsError::Invalid);
        }

        // R186-7 FIX: Check the inode bitmap allocation bit before loading.
        //
        // Directory lookup passes any nonzero inode number here, and the only
        // prior check was numeric range. A crafted image could therefore point a
        // directory entry at a FREE inode-table slot carrying permissive metadata
        // whose block pointers alias blocks owned by a different inode — a DAC and
        // block-ownership bypass. It also slipped past the mount ownership scan,
        // which deliberately skips bitmap-clear slots.
        //
        // Binding on-disk identity to allocation state closes both: a free slot is
        // not an object, so it cannot be loaded, and the ownership scan's skip
        // becomes correct rather than a hole.
        if !self.inode_is_allocated_in(ino, inode_bitmap_block, blocks_count)? {
            return Err(FsError::NotFound);
        }

        // Calculate offset within inode table
        let inode_offset = index as u64 * self.inode_size as u64;
        let block_offset = inode_offset / self.block_size as u64;
        let offset_in_block = inode_offset % self.block_size as u64;

        // R65-EXT2-5 FIX: Use checked arithmetic to prevent overflow and validate bounds.
        // A malicious inodes_per_group/inode_size could cause block_offset to overflow u32
        // or push the computed block past filesystem bounds.
        if block_offset > u32::MAX as u64 {
            return Err(FsError::Invalid);
        }
        let inode_block = inode_table_block
            .checked_add(block_offset as u32)
            .filter(|b| *b < blocks_count)
            .ok_or(FsError::Invalid)?;

        // R178-29 FIX: Fallible inode block buffer allocation (up to 64 KiB).
        // Inode lookup is a recoverable path — OOM here returns FsError::NoSpace.
        let mut block_buf = Vec::new();
        block_buf
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| FsError::NoSpace)?;
        block_buf.resize(self.block_size as usize, 0u8);
        self.read_block(inode_block, &mut block_buf)?;

        // R95-3 FIX: Bounds check inode read to prevent OOB access.
        // A crafted inode_size or offset could cause reading past block boundary.
        let start = offset_in_block as usize;
        let end = start
            .checked_add(size_of::<Ext2InodeRaw>())
            .ok_or(FsError::Invalid)?;
        if end > block_buf.len() {
            return Err(FsError::Invalid);
        }

        // Parse inode
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        let inode: Ext2InodeRaw =
            unsafe { core::ptr::read_unaligned(block_buf[start..].as_ptr() as *const _) };

        Ok(inode)
    }

    /// Resolve and validate the immutable inode-table target before mutation.
    fn inode_write_target(&self, ino: u32) -> Result<InodeWriteTarget, FsError> {
        let sb = self.superblock.read();
        if ino == 0 || ino > sb.inodes_count {
            return Err(FsError::NotFound);
        }
        let blocks_count = sb.blocks_count;
        drop(sb);

        let (group, index) = self.inode_group_index(ino);
        // R65-EXT2-3 FIX: Bounds check group descriptor access to prevent OOB read.
        let group_descs = self.group_descs.read();
        if group >= group_descs.len() {
            return Err(FsError::Invalid);
        }
        let inode_table_block = group_descs[group].inode_table;
        drop(group_descs);

        // Validate inode table block is within filesystem bounds
        if inode_table_block == 0 || inode_table_block >= blocks_count {
            return Err(FsError::Invalid);
        }

        let inode_offset = index as u64 * self.inode_size as u64;
        let block_offset = inode_offset / self.block_size as u64;
        let offset_in_block = inode_offset % self.block_size as u64;

        // R65-EXT2-5 FIX: Use checked arithmetic to prevent overflow and validate bounds.
        if block_offset > u32::MAX as u64 {
            return Err(FsError::Invalid);
        }
        let inode_block = inode_table_block
            .checked_add(block_offset as u32)
            .filter(|b| *b < blocks_count)
            .ok_or(FsError::Invalid)?;

        // R178-29 FIX: Fallible inode write buffer allocation (up to 64 KiB).
        // Inode write is a recoverable path — OOM here returns FsError::NoSpace.
        let copy_len = cmp::min(self.inode_size as usize, size_of::<Ext2InodeRaw>());
        let start = offset_in_block as usize;
        let end = start
            .checked_add(self.inode_size as usize)
            .ok_or(FsError::Invalid)?;
        if end > self.block_size as usize {
            return Err(FsError::Invalid);
        }

        Ok(InodeWriteTarget {
            block: inode_block,
            start,
            copy_len,
        })
    }

    /// R180-6 FIX: inode RMW primitive for callers that already retain
    /// `meta_lock` across the complete in-place write commit.
    fn write_inode_raw_locked(
        &self,
        target: InodeWriteTarget,
        raw: &Ext2InodeRaw,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let block_buf = scratch.block_mut();
        self.read_block(target.block, block_buf)?;

        let raw_bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(raw as *const _ as *const u8, target.copy_len) };
        block_buf[target.start..target.start + target.copy_len].copy_from_slice(raw_bytes);
        // Preserve bytes beyond the 128-byte base inode.  Revision-1 images
        // commonly use a 256-byte inode whose tail stores i_extra_isize,
        // creation time, and checksum fields owned by the on-disk format.

        self.write_block(target.block, block_buf)
    }

    fn group_desc_write_target(&self, group: usize) -> Result<GroupDescWriteTarget, FsError> {
        let descs_per_block = self.block_size as usize / size_of::<Ext2GroupDesc>();
        if descs_per_block == 0 {
            return Err(FsError::Invalid);
        }
        let first: u32 = if self.block_size == 1024 { 2 } else { 1 };
        let block = first
            .checked_add(u32::try_from(group / descs_per_block).map_err(|_| FsError::Invalid)?)
            .ok_or(FsError::Invalid)?;
        let offset = (group % descs_per_block)
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        if offset
            .checked_add(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?
            > self.block_size as usize
            || block >= self.blocks_count
        {
            return Err(FsError::Invalid);
        }
        Ok(GroupDescWriteTarget { block, offset })
    }

    #[inline]
    fn superblock_home_target(&self) -> (u32, usize) {
        if self.block_size == 1024 {
            (1, 0)
        } else {
            (0, SUPERBLOCK_OFFSET as usize)
        }
    }

    fn write_primary_superblock(
        &self,
        superblock: &Ext2Superblock,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let (home, offset) = self.superblock_home_target();
        self.read_physical_block(home, scratch.block_mut())?;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                superblock as *const Ext2Superblock as *const u8,
                size_of::<Ext2Superblock>(),
            )
        };
        let end = offset.checked_add(bytes.len()).ok_or(FsError::Invalid)?;
        scratch
            .block_mut()
            .get_mut(offset..end)
            .ok_or(FsError::Invalid)?
            .copy_from_slice(bytes);
        self.write_physical_block(home, scratch.block())
    }

    fn metadata_home_block(&self, plan: JournalMetadataPlan, index: usize) -> Result<u32, FsError> {
        match plan {
            JournalMetadataPlan::DirectAllocation(plan) => match index {
                0 => Ok(plan.bitmap_block),
                1 => Ok(plan.group_desc_target.block),
                2 => Ok(self.superblock_home_target().0),
                3 => Ok(plan.inode_target.block),
                _ => Err(FsError::Invalid),
            },
            JournalMetadataPlan::InodeUpdate { inode_target, .. } => {
                if index == 0 {
                    Ok(inode_target.block)
                } else {
                    Err(FsError::Invalid)
                }
            }
        }
    }

    fn build_metadata_image(
        &self,
        plan: JournalMetadataPlan,
        index: usize,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<u32, FsError> {
        let home = self.metadata_home_block(plan, index)?;
        self.read_physical_block(home, scratch.block_mut())?;
        let block = scratch.block_mut();
        match plan {
            JournalMetadataPlan::DirectAllocation(plan) => match index {
                0 => {
                    let byte = block.get_mut(plan.bitmap_byte).ok_or(FsError::Invalid)?;
                    *byte |= plan.bitmap_mask;
                }
                1 => {
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &plan.new_group_desc as *const _ as *const u8,
                            size_of::<Ext2GroupDesc>(),
                        )
                    };
                    let end = plan
                        .group_desc_target
                        .offset
                        .checked_add(bytes.len())
                        .ok_or(FsError::Invalid)?;
                    block
                        .get_mut(plan.group_desc_target.offset..end)
                        .ok_or(FsError::Invalid)?
                        .copy_from_slice(bytes);
                }
                2 => {
                    let (_, offset) = self.superblock_home_target();
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &plan.new_superblock as *const _ as *const u8,
                            size_of::<Ext2Superblock>(),
                        )
                    };
                    let end = offset.checked_add(bytes.len()).ok_or(FsError::Invalid)?;
                    block
                        .get_mut(offset..end)
                        .ok_or(FsError::Invalid)?
                        .copy_from_slice(bytes);
                }
                3 => Self::replace_inode_in_block(block, plan.inode_target, &plan.new_inode)?,
                _ => return Err(FsError::Invalid),
            },
            JournalMetadataPlan::InodeUpdate {
                inode_target,
                new_inode,
                ..
            } => {
                if index != 0 {
                    return Err(FsError::Invalid);
                }
                Self::replace_inode_in_block(block, inode_target, &new_inode)?;
            }
        }
        Ok(home)
    }

    fn hash_block_replacement(
        block: &[u8],
        start: usize,
        replacement: &[u8],
    ) -> Result<[u8; 32], FsError> {
        let end = start
            .checked_add(replacement.len())
            .filter(|end| *end <= block.len())
            .ok_or(FsError::Invalid)?;
        let mut hasher = Sha256::new();
        hasher.update(&block[..start]);
        hasher.update(replacement);
        hasher.update(&block[end..]);
        Ok(hasher.finalize())
    }

    fn inode_bytes(inode: &Ext2InodeRaw) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                inode as *const Ext2InodeRaw as *const u8,
                size_of::<Ext2InodeRaw>(),
            )
        }
    }

    fn metadata_preimage_hash(
        &self,
        plan: JournalMetadataPlan,
        index: usize,
        post_image: &[u8],
    ) -> Result<[u8; 32], FsError> {
        if post_image.len() != self.block_size as usize {
            return Err(FsError::Invalid);
        }
        match plan {
            JournalMetadataPlan::DirectAllocation(plan) => match index {
                0 => {
                    let after = *post_image.get(plan.bitmap_byte).ok_or(FsError::Invalid)?;
                    if after & plan.bitmap_mask == 0 || plan.bitmap_mask.count_ones() != 1 {
                        return Err(FsError::Invalid);
                    }
                    let before = after & !plan.bitmap_mask;
                    Self::hash_block_replacement(post_image, plan.bitmap_byte, &[before])
                }
                1 => Self::hash_block_replacement(
                    post_image,
                    plan.group_desc_target.offset,
                    unsafe {
                        core::slice::from_raw_parts(
                            &plan.old_group_desc as *const Ext2GroupDesc as *const u8,
                            size_of::<Ext2GroupDesc>(),
                        )
                    },
                ),
                2 => Self::hash_block_replacement(
                    post_image,
                    self.superblock_home_target().1,
                    unsafe {
                        core::slice::from_raw_parts(
                            &plan.old_superblock as *const Ext2Superblock as *const u8,
                            size_of::<Ext2Superblock>(),
                        )
                    },
                ),
                3 => Self::hash_block_replacement(
                    post_image,
                    plan.inode_target.start,
                    &Self::inode_bytes(&plan.old_inode)[..plan.inode_target.copy_len],
                ),
                _ => Err(FsError::Invalid),
            },
            JournalMetadataPlan::InodeUpdate {
                inode_target,
                old_inode,
                ..
            } => {
                if index != 0 {
                    return Err(FsError::Invalid);
                }
                Self::hash_block_replacement(
                    post_image,
                    inode_target.start,
                    &Self::inode_bytes(&old_inode)[..inode_target.copy_len],
                )
            }
        }
    }

    fn intent_for_plan(
        plan: JournalMetadataPlan,
        preimage_hashes: [[u8; 32]; JOURNAL_MAX_METADATA_BLOCKS],
    ) -> JournalCommitIntent {
        match plan {
            JournalMetadataPlan::DirectAllocation(plan) => JournalCommitIntent {
                kind: ZERO_INTENT_KIND_DIRECT_ALLOCATION,
                metadata_count: JOURNAL_MAX_METADATA_BLOCKS as u8,
                inode_number: plan.inode_number,
                file_block: plan.file_block,
                physical: plan.phys_block,
                preimage_hashes,
                old_inode: plan.old_inode,
            },
            JournalMetadataPlan::InodeUpdate {
                inode_number,
                old_inode,
                ..
            } => JournalCommitIntent {
                kind: ZERO_INTENT_KIND_INODE_UPDATE,
                metadata_count: 1,
                inode_number,
                file_block: u32::MAX,
                physical: 0,
                preimage_hashes,
                old_inode,
            },
        }
    }

    fn encode_commit_intent(block: &mut [u8], intent: &JournalCommitIntent) -> Result<(), FsError> {
        if block.len() < ZERO_INTENT_END {
            return Err(FsError::Invalid);
        }
        block[ZERO_INTENT_MAGIC_OFFSET..ZERO_INTENT_MAGIC_OFFSET + 4]
            .copy_from_slice(&ZERO_INTENT_MAGIC);
        write_be_u16(block, ZERO_INTENT_VERSION_OFFSET, ZERO_INTENT_VERSION)?;
        block[ZERO_INTENT_KIND_OFFSET] = intent.kind;
        block[ZERO_INTENT_COUNT_OFFSET] = intent.metadata_count;
        write_be_u32(block, ZERO_INTENT_INODE_OFFSET, intent.inode_number)?;
        write_be_u32(block, ZERO_INTENT_FILE_BLOCK_OFFSET, intent.file_block)?;
        write_be_u32(block, ZERO_INTENT_PHYSICAL_OFFSET, intent.physical)?;
        for (index, digest) in intent.preimage_hashes.iter().enumerate() {
            let start = ZERO_INTENT_PREIMAGE_HASHES_OFFSET + index * 32;
            block[start..start + 32].copy_from_slice(digest);
        }
        block[ZERO_INTENT_OLD_INODE_OFFSET..ZERO_INTENT_DIGEST_OFFSET]
            .copy_from_slice(Self::inode_bytes(&intent.old_inode));
        block[ZERO_INTENT_DIGEST_OFFSET..ZERO_INTENT_END].fill(0);
        Ok(())
    }

    fn transaction_hasher(journal: &Ext2Journal, sequence: u32, descriptor: &[u8]) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(ZERO_INTENT_HASH_DOMAIN);
        hasher.update(&journal.uuid);
        hasher.update(&sequence.to_be_bytes());
        hasher.update(descriptor);
        hasher
    }

    fn finish_transaction_digest(mut hasher: Sha256, commit: &[u8]) -> Result<[u8; 32], FsError> {
        if commit.len() < ZERO_INTENT_END {
            return Err(FsError::Invalid);
        }
        hasher.update(&commit[..ZERO_INTENT_DIGEST_OFFSET]);
        hasher.update(&[0u8; 32]);
        hasher.update(&commit[ZERO_INTENT_END..]);
        Ok(hasher.finalize())
    }

    fn replace_inode_in_block(
        block: &mut [u8],
        target: InodeWriteTarget,
        inode: &Ext2InodeRaw,
    ) -> Result<(), FsError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(inode as *const _ as *const u8, target.copy_len) };
        let end = target
            .start
            .checked_add(bytes.len())
            .ok_or(FsError::Invalid)?;
        block
            .get_mut(target.start..end)
            .ok_or(FsError::Invalid)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn plan_direct_allocation(
        &self,
        inode_number: u32,
        committed_raw: &Ext2InodeRaw,
        mut next_raw: Ext2InodeRaw,
        file_block: u32,
        inode_target: InodeWriteTarget,
        journal: &Ext2Journal,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<DirectAllocationPlan, FsError> {
        if file_block >= EXT2_NDIR_BLOCKS as u32 || committed_raw.block[file_block as usize] != 0 {
            return Err(FsError::NotSupported);
        }
        next_raw.blocks_lo = committed_raw
            .blocks_lo
            .checked_add(self.block_size / 512)
            .ok_or(FsError::Invalid)?;

        let sb = *self.superblock.read();
        if sb.free_blocks_count == 0 {
            return Err(FsError::NoSpace);
        }
        let group_descs = self.group_descs.read();
        let groups_count = sb
            .blocks_count
            .checked_sub(sb.first_data_block)
            .ok_or(FsError::Invalid)?
            .checked_add(sb.blocks_per_group - 1)
            .ok_or(FsError::Invalid)?
            / sb.blocks_per_group;
        if groups_count as usize > group_descs.len() {
            return Err(FsError::Invalid);
        }

        for group in 0..groups_count as usize {
            let desc = group_descs[group];
            if desc.free_blocks_count == 0 {
                continue;
            }
            if desc.block_bitmap == 0 || desc.block_bitmap >= self.blocks_count {
                return Err(FsError::Invalid);
            }
            self.read_physical_block(desc.block_bitmap, scratch.block_mut())?;

            let group_offset = u32::try_from(group)
                .map_err(|_| FsError::Invalid)?
                .checked_mul(sb.blocks_per_group)
                .ok_or(FsError::Invalid)?;
            let group_start = sb
                .first_data_block
                .checked_add(group_offset)
                .ok_or(FsError::Invalid)?;
            let group_blocks = cmp::min(
                sb.blocks_per_group,
                sb.blocks_count
                    .checked_sub(group_start)
                    .ok_or(FsError::Invalid)?,
            );
            if Self::bitmap_free_count(scratch.block(), group_blocks)?
                != desc.free_blocks_count as u32
            {
                return Err(FsError::Invalid);
            }

            let bitmap_bytes =
                usize::try_from((group_blocks + 7) / 8).map_err(|_| FsError::Invalid)?;
            for byte_idx in 0..bitmap_bytes {
                let valid_bits = if byte_idx + 1 == bitmap_bytes && group_blocks % 8 != 0 {
                    group_blocks % 8
                } else {
                    8
                };
                let valid_mask = if valid_bits == 8 {
                    u8::MAX
                } else {
                    (1u8 << valid_bits) - 1
                };
                let byte = scratch
                    .block()
                    .get(byte_idx)
                    .copied()
                    .ok_or(FsError::Invalid)?;
                let free_bits = !byte & valid_mask;
                if free_bits != 0 {
                    let bit_in_byte = free_bits.trailing_zeros();
                    let bit = u32::try_from(byte_idx)
                        .ok()
                        .and_then(|byte| byte.checked_mul(8))
                        .and_then(|base| base.checked_add(bit_in_byte))
                        .ok_or(FsError::Invalid)?;
                    let bit_mask = 1u8 << bit_in_byte;
                    let phys_block = group_start.checked_add(bit).ok_or(FsError::Invalid)?;
                    if phys_block == 0
                        || phys_block >= self.blocks_count
                        || committed_raw.block.contains(&phys_block)
                        || journal.contains_physical(phys_block)
                        || self.is_structural_metadata_block(phys_block)?
                    {
                        return Err(FsError::Invalid);
                    }

                    let mut new_desc = desc;
                    new_desc.free_blocks_count = new_desc
                        .free_blocks_count
                        .checked_sub(1)
                        .ok_or(FsError::Invalid)?;
                    let mut new_super = sb;
                    new_super.free_blocks_count = new_super
                        .free_blocks_count
                        .checked_sub(1)
                        .ok_or(FsError::Invalid)?;
                    next_raw.block[file_block as usize] = phys_block;

                    let plan = DirectAllocationPlan {
                        inode_number,
                        file_block,
                        phys_block,
                        bitmap_block: desc.block_bitmap,
                        bitmap_byte: byte_idx,
                        bitmap_mask: bit_mask,
                        group,
                        group_desc_target: self.group_desc_write_target(group)?,
                        old_group_desc: desc,
                        new_group_desc: new_desc,
                        old_superblock: sb,
                        new_superblock: new_super,
                        inode_target,
                        old_inode: *committed_raw,
                        new_inode: next_raw,
                    };
                    let mut homes = [0u32; JOURNAL_MAX_METADATA_BLOCKS];
                    let metadata_plan = JournalMetadataPlan::DirectAllocation(plan);
                    for index in 0..JOURNAL_MAX_METADATA_BLOCKS {
                        homes[index] = self.metadata_home_block(metadata_plan, index)?;
                        if journal.contains_physical(homes[index]) {
                            return Err(FsError::Invalid);
                        }
                        for prior in 0..index {
                            if homes[prior] == homes[index] {
                                return Err(FsError::Invalid);
                            }
                        }
                    }
                    return Ok(plan);
                }
            }
        }
        Err(FsError::NoSpace)
    }

    fn abort_uncommitted_journal(
        &self,
        journal: &mut Ext2Journal,
        sequence: u32,
        original: FsError,
        scratch: &mut Ext2MutationScratch,
    ) -> JournalTxFailure {
        let cleared = self
            .write_journal_state(journal, sequence, 0, scratch)
            .and_then(|_| self.flush_device());
        if cleared.is_ok() {
            journal.start = 0;
            JournalTxFailure {
                error: original,
                committed: false,
                poison: false,
            }
        } else {
            JournalTxFailure {
                error: FsError::Io,
                committed: false,
                poison: true,
            }
        }
    }

    fn commit_metadata_transaction(
        &self,
        journal: &mut Ext2Journal,
        plan: JournalMetadataPlan,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), JournalTxFailure> {
        let metadata_blocks = plan.metadata_blocks();
        let transaction_blocks = u32::try_from(metadata_blocks)
            .ok()
            .and_then(|blocks| blocks.checked_add(2))
            .ok_or(JournalTxFailure {
                error: FsError::Invalid,
                committed: false,
                poison: true,
            })?;
        if journal.feature_incompat & JBD2_FEATURE_INCOMPAT_ZERO_INTENT == 0
            || journal.first != 1
            || journal.start != 0
            || journal
                .first
                .checked_add(transaction_blocks)
                .is_none_or(|end| end > journal.max_len)
        {
            return Err(JournalTxFailure {
                error: FsError::Invalid,
                committed: false,
                poison: true,
            });
        }

        let sequence = journal.next_sequence;
        let mut escaped = [false; JOURNAL_MAX_METADATA_BLOCKS];
        let mut homes = [0u32; JOURNAL_MAX_METADATA_BLOCKS];
        let mut preimage_hashes = [[0u8; 32]; JOURNAL_MAX_METADATA_BLOCKS];
        for index in 0..metadata_blocks {
            homes[index] = self
                .build_metadata_image(plan, index, scratch)
                .map_err(|error| JournalTxFailure {
                    error,
                    committed: false,
                    poison: false,
                })?;
            escaped[index] = read_be_u32(scratch.block(), 0).ok() == Some(JBD2_MAGIC);
            preimage_hashes[index] = self
                .metadata_preimage_hash(plan, index, scratch.block())
                .map_err(|error| JournalTxFailure {
                    error,
                    committed: false,
                    poison: false,
                })?;
        }

        if let Err(error) = self.write_journal_state(journal, sequence, journal.first, scratch) {
            return Err(JournalTxFailure {
                error,
                committed: false,
                poison: true,
            });
        }
        journal.start = journal.first;
        if let Err(error) = self.flush_device() {
            return Err(JournalTxFailure {
                error,
                committed: false,
                poison: true,
            });
        }

        let descriptor = scratch.block_mut();
        descriptor.fill(0);
        write_be_u32(descriptor, 0, JBD2_MAGIC).map_err(|error| JournalTxFailure {
            error,
            committed: false,
            poison: true,
        })?;
        write_be_u32(descriptor, 4, JBD2_DESCRIPTOR_BLOCK).map_err(|error| JournalTxFailure {
            error,
            committed: false,
            poison: true,
        })?;
        write_be_u32(descriptor, 8, sequence).map_err(|error| JournalTxFailure {
            error,
            committed: false,
            poison: true,
        })?;
        let mut offset = JBD2_HEADER_BYTES;
        for index in 0..metadata_blocks {
            let home = homes[index];
            let escape = escaped[index];
            let mut flags = if escape { JBD2_FLAG_ESCAPE } else { 0 };
            if index != 0 {
                flags |= JBD2_FLAG_SAME_UUID;
            }
            if index + 1 == metadata_blocks {
                flags |= JBD2_FLAG_LAST_TAG;
            }
            write_be_u32(descriptor, offset, home).map_err(|error| JournalTxFailure {
                error,
                committed: false,
                poison: true,
            })?;
            write_be_u16(descriptor, offset + 4, 0).map_err(|error| JournalTxFailure {
                error,
                committed: false,
                poison: true,
            })?;
            write_be_u16(descriptor, offset + 6, flags).map_err(|error| JournalTxFailure {
                error,
                committed: false,
                poison: true,
            })?;
            offset += JBD2_TAG_BYTES;
            if index == 0 {
                descriptor[offset..offset + 16].copy_from_slice(&journal.uuid);
                offset += 16;
            }
        }

        if let Err(error) = self.write_journal_block(journal, journal.first, descriptor) {
            return Err(self.abort_uncommitted_journal(journal, sequence, error, scratch));
        }
        let mut transaction_hasher = Self::transaction_hasher(journal, sequence, descriptor);
        for (index, escape) in escaped[..metadata_blocks].iter().copied().enumerate() {
            if let Err(error) = self.build_metadata_image(plan, index, scratch) {
                return Err(self.abort_uncommitted_journal(journal, sequence, error, scratch));
            }
            if escape {
                scratch.block_mut()[..4].fill(0);
            }
            transaction_hasher.update(scratch.block());
            let logical = journal
                .advance(journal.first, index as u32 + 1)
                .map_err(|error| JournalTxFailure {
                    error,
                    committed: false,
                    poison: true,
                })?;
            if let Err(error) = self.write_journal_block(journal, logical, scratch.block()) {
                return Err(self.abort_uncommitted_journal(journal, sequence, error, scratch));
            }
        }
        if let Err(error) = self.flush_device() {
            return Err(self.abort_uncommitted_journal(journal, sequence, error, scratch));
        }

        let commit_logical = match journal.advance(journal.first, metadata_blocks as u32 + 1) {
            Ok(logical) => logical,
            Err(error) => {
                return Err(JournalTxFailure {
                    error,
                    committed: false,
                    poison: true,
                })
            }
        };
        let commit = scratch.block_mut();
        commit.fill(0);
        if write_be_u32(commit, 0, JBD2_MAGIC)
            .and_then(|_| write_be_u32(commit, 4, JBD2_COMMIT_BLOCK))
            .and_then(|_| write_be_u32(commit, 8, sequence))
            .is_err()
        {
            return Err(JournalTxFailure {
                error: FsError::Invalid,
                committed: false,
                poison: true,
            });
        }
        let intent = Self::intent_for_plan(plan, preimage_hashes);
        if let Err(error) = Self::encode_commit_intent(commit, &intent) {
            return Err(JournalTxFailure {
                error,
                committed: false,
                poison: true,
            });
        }
        let digest = match Self::finish_transaction_digest(transaction_hasher, commit) {
            Ok(digest) => digest,
            Err(error) => {
                return Err(JournalTxFailure {
                    error,
                    committed: false,
                    poison: true,
                })
            }
        };
        commit[ZERO_INTENT_DIGEST_OFFSET..ZERO_INTENT_END].copy_from_slice(&digest);
        if let Err(error) = self.write_journal_block(journal, commit_logical, commit) {
            return Err(JournalTxFailure {
                error,
                committed: false,
                poison: true,
            });
        }
        if let Err(error) = self.flush_device() {
            return Err(JournalTxFailure {
                error,
                committed: false,
                poison: true,
            });
        }

        for index in 0..metadata_blocks {
            let home = match self.build_metadata_image(plan, index, scratch) {
                Ok(home) => home,
                Err(error) => {
                    return Err(JournalTxFailure {
                        error,
                        committed: true,
                        poison: true,
                    })
                }
            };
            if let Err(error) = self.write_physical_block(home, scratch.block()) {
                return Err(JournalTxFailure {
                    error,
                    committed: true,
                    poison: true,
                });
            }
        }
        if let Err(error) = self.flush_device() {
            return Err(JournalTxFailure {
                error,
                committed: true,
                poison: true,
            });
        }

        let next_sequence = sequence.wrapping_add(1);
        if let Err(error) = self.write_journal_state(journal, next_sequence, 0, scratch) {
            return Err(JournalTxFailure {
                error,
                committed: true,
                poison: true,
            });
        }
        if let Err(error) = self.flush_device() {
            return Err(JournalTxFailure {
                error,
                committed: true,
                poison: true,
            });
        }
        journal.next_sequence = next_sequence;
        journal.start = 0;
        Ok(())
    }

    /// Construct one in-memory wrapper from validated on-disk inode state.
    /// All production construction and deterministic identity tests use this
    /// single allocation site; publication remains the cache's responsibility.
    fn new_inode_from_raw(
        self: &Arc<Self>,
        ino: u32,
        raw: Ext2InodeRaw,
    ) -> Result<Arc<Ext2Inode>, FsError> {
        let size = if raw.mode & EXT2_S_IFREG != 0 {
            // Regular file: use size_high for large files.
            ((raw.size_high_or_dir_acl as u64) << 32) | raw.size_lo as u64
        } else {
            // Directories and symlinks use size_lo in the current ext2 slice.
            raw.size_lo as u64
        };

        Arc::try_new(Ext2Inode {
            fs: Arc::downgrade(self),
            fs_id: self.fs_id,
            ino,
            raw: RwLock::new(raw),
            size: AtomicU64::new(size),
            write_lock: Mutex::new(()),
        })
        .map_err(|_| FsError::NoMem)
    }

    /// RF178-37 FIX: load or return the canonical in-memory inode wrapper.
    ///
    /// R186-7: the bitmap-allocation gate lives in `read_inode_raw`, which only
    /// runs on a cache MISS. A cache hit therefore bypasses it. That is safe today
    /// and the reasoning is recorded here because it is a load-bearing precondition
    /// rather than an accident:
    ///
    ///   - The cache starts empty at mount, so the FIRST load of any inode goes
    ///     through `read_inode_raw` and is bitmap-checked. A crafted directory
    ///     entry pointing at a bitmap-free inode is rejected there.
    ///   - Nothing in this driver ever frees an inode: the `FileSystem` impl
    ///     exposes only `fs_id`/`fs_type`/`root_inode`/`lookup`, and `Inode`
    ///     exposes no unlink/rmdir/create. No code path clears an inode bitmap
    ///     bit, so a cached entry cannot outlive its allocation.
    ///
    /// If an inode-free path is ever added it MUST invalidate this cache entry
    /// atomically with clearing the bitmap bit, otherwise a subsequent lookup
    /// through a stale or aliasing directory entry would resolve to a freed inode
    /// and write through it into blocks that have been reallocated to another
    /// file. `debug_assert_inode_allocated` below exists to catch exactly that
    /// regression in checked builds.
    fn load_inode(self: &Arc<Self>, ino: u32) -> Result<Arc<Ext2Inode>, FsError> {
        let cached = self.inode_cache.get_or_try_insert_with(ino, || {
            let raw = self.read_inode_raw(ino)?;
            self.new_inode_from_raw(ino, raw)
        })?;
        self.debug_assert_inode_allocated(ino);
        Ok(cached)
    }

    /// R186-7: re-verify the bitmap bit for an inode served from the cache.
    ///
    /// Compiled out of release builds — the release-path guarantee is the
    /// no-free-path argument documented on `load_inode`, not a per-lookup block
    /// read (which would cost one device read per path component). In checked
    /// builds this turns "someone added an inode-free path and forgot to
    /// invalidate the cache" from a silent cross-file corruption primitive into an
    /// immediate, located failure.
    #[inline]
    fn debug_assert_inode_allocated(&self, ino: u32) {
        #[cfg(debug_assertions)]
        {
            match self.inode_is_allocated(ino) {
                Ok(true) => {}
                Ok(false) => panic!(
                    "R186-7: ext2 inode {} served from cache but its bitmap bit is \
                     CLEAR — an inode-free path must invalidate the inode cache \
                     atomically with clearing the bitmap",
                    ino
                ),
                // An I/O or bounds failure here is not evidence of the violation
                // this assertion targets; the ordinary error paths cover it.
                Err(_) => {}
            }
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = ino;
        }
    }

    /// Calculate group and index for an inode number
    fn inode_group_index(&self, ino: u32) -> (usize, usize) {
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as usize;
        (group, index)
    }

    /// R28-5 Fix: Validate block number against filesystem bounds.
    ///
    /// # R99-4 FIX: Lock-free block validation via cached `blocks_count`
    ///
    /// The cached immutable block count avoids taking the superblock lock from
    /// data and inode I/O validation paths.
    #[inline]
    fn validate_block(&self, block: u32) -> Result<Option<u32>, FsError> {
        if block == 0 {
            Ok(None)
        } else if block >= self.blocks_count {
            Err(FsError::Invalid)
        } else {
            Ok(Some(block))
        }
    }

    /// Map a file block number to physical block number
    fn map_file_block(&self, raw: &Ext2InodeRaw, file_block: u32) -> Result<Option<u32>, FsError> {
        // Preserve the allocation-free direct-block fast path for reads.
        if file_block < EXT2_NDIR_BLOCKS as u32 {
            return self.validate_block(raw.block[file_block as usize]);
        }
        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        self.map_file_block_with_scratch(raw, file_block, &mut scratch)
    }

    /// RF178-39 FIX: map direct/indirect blocks using a caller-owned scratch.
    /// Mutation callers allocate it once before their first persistent write.
    fn map_file_block_with_scratch(
        &self,
        raw: &Ext2InodeRaw,
        file_block: u32,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<Option<u32>, FsError> {
        let ptrs_per_block = self.block_size / 4; // 4 bytes per u32 pointer

        // Direct blocks (0-11)
        if file_block < EXT2_NDIR_BLOCKS as u32 {
            let block = raw.block[file_block as usize];
            return self.validate_block(block);
        }

        let file_block = file_block - EXT2_NDIR_BLOCKS as u32;

        // Single indirect (block 12)
        if file_block < ptrs_per_block {
            // R28-5 Fix: Validate indirect block pointer
            let ind_block = match self.validate_block(raw.block[EXT2_IND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            self.read_block(ind_block, scratch.block_mut())?;

            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ptr = read_u32_le(scratch.block(), file_block as usize)?;
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptr);
        }

        let file_block = file_block - ptrs_per_block;

        // Double indirect (block 13)
        // R156-11 FIX: Use checked_mul to prevent overflow with crafted superblocks.
        let double_indirect_limit = ptrs_per_block
            .checked_mul(ptrs_per_block)
            .ok_or(FsError::Invalid)?;
        if file_block < double_indirect_limit {
            // R28-5 Fix: Validate double indirect block pointer
            let dind_block = match self.validate_block(raw.block[EXT2_DIND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            self.read_block(dind_block, scratch.block_mut())?;

            let ind_index = file_block / ptrs_per_block;
            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ind_ptr = read_u32_le(scratch.block(), ind_index as usize)?;
            // R28-5 Fix: Validate indirect block pointer from double indirect table
            let ind_block = match self.validate_block(ind_ptr)? {
                Some(b) => b,
                None => return Ok(None),
            };

            self.read_block(ind_block, scratch.block_mut())?;

            let block_index = file_block % ptrs_per_block;
            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ptr = read_u32_le(scratch.block(), block_index as usize)?;
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptr);
        }

        // Triple indirect would go here, but for simplicity we return an error
        Err(FsError::Invalid)
    }

    fn validate_sparse_gap_identity(
        &self,
        journal: &Ext2Journal,
        physical: u32,
    ) -> Result<u32, FsError> {
        let physical = self.validate_block(physical)?.ok_or(FsError::Invalid)?;
        if self.is_structural_metadata_block(physical)? || journal.contains_physical(physical) {
            return Err(FsError::Invalid);
        }
        Ok(physical)
    }

    fn validate_sparse_gap_block(
        &self,
        journal: &Ext2Journal,
        physical: u32,
        bitmap_scratch: &mut Ext2MutationScratch,
        loaded_bitmap_group: &mut Option<usize>,
    ) -> Result<u32, FsError> {
        let physical = self.validate_sparse_gap_identity(journal, physical)?;

        let sb = *self.superblock.read();
        let relative = physical
            .checked_sub(sb.first_data_block)
            .ok_or(FsError::Invalid)?;
        let group =
            usize::try_from(relative / sb.blocks_per_group).map_err(|_| FsError::Invalid)?;
        let bit = relative % sb.blocks_per_group;
        if *loaded_bitmap_group != Some(group) {
            let desc = self
                .group_descs
                .read()
                .get(group)
                .copied()
                .ok_or(FsError::Invalid)?;
            self.read_physical_block(desc.block_bitmap, bitmap_scratch.block_mut())?;
            *loaded_bitmap_group = Some(group);
        }
        let allocated = bitmap_scratch
            .block()
            .get((bit / 8) as usize)
            .copied()
            .ok_or(FsError::Invalid)?
            & (1u8 << (bit % 8))
            != 0;
        if !allocated {
            return Err(FsError::Invalid);
        }
        Ok(physical)
    }

    fn visit_sparse_gap_mapping_node<V: SparseGapVisitor>(
        &self,
        journal: &Ext2Journal,
        physical: u32,
        branch: Option<u16>,
        bitmap_scratch: &mut Ext2MutationScratch,
        loaded_bitmap_group: &mut Option<usize>,
        visitor: &mut V,
    ) -> Result<u32, FsError> {
        let physical =
            self.validate_sparse_gap_block(journal, physical, bitmap_scratch, loaded_bitmap_group)?;
        visitor.mapping_node(physical, branch)?;
        Ok(physical)
    }

    fn visit_sparse_gap_target<V: SparseGapVisitor>(
        &self,
        journal: &Ext2Journal,
        physical: u32,
        file_block: u32,
        gap_start: u64,
        gap_end: u64,
        bitmap_scratch: &mut Ext2MutationScratch,
        loaded_bitmap_group: &mut Option<usize>,
        visitor: &mut V,
    ) -> Result<(), FsError> {
        let physical =
            self.validate_sparse_gap_block(journal, physical, bitmap_scratch, loaded_bitmap_group)?;
        visitor.data_target(
            file_block,
            self.sparse_gap_target(physical, file_block, gap_start, gap_end)?,
        )
    }

    fn sparse_gap_target(
        &self,
        physical: u32,
        file_block: u32,
        gap_start: u64,
        gap_end: u64,
    ) -> Result<SparseGapTarget, FsError> {
        let block_start = (file_block as u64)
            .checked_mul(self.block_size as u64)
            .ok_or(FsError::Invalid)?;
        let block_end = block_start
            .checked_add(self.block_size as u64)
            .ok_or(FsError::Invalid)?;
        let covered_start = gap_start.max(block_start);
        let covered_end = gap_end.min(block_end);
        if covered_start >= covered_end {
            return Err(FsError::Invalid);
        }
        let start = u32::try_from(covered_start - block_start).map_err(|_| FsError::Invalid)?;
        let end = u32::try_from(covered_end - block_start).map_err(|_| FsError::Invalid)?;
        if end > self.block_size {
            return Err(FsError::Invalid);
        }
        Ok(SparseGapTarget {
            physical,
            start,
            end,
        })
    }

    /// Walk every present sparse-gap mapping and data target without retaining
    /// logical holes.  The caller supplies either the allocation-free counting
    /// visitor or the exact-capacity collection visitor.
    fn walk_sparse_gap<V: SparseGapVisitor>(
        &self,
        raw: &Ext2InodeRaw,
        gap_start: u64,
        gap_end: u64,
        journal: &Ext2Journal,
        mapping: &mut Ext2MutationScratch,
        scratch: &mut SparseGapTraversalScratch,
        visitor: &mut V,
    ) -> Result<(), FsError> {
        if gap_start >= gap_end {
            return Ok(());
        }
        let block_size = self.block_size as u64;
        let first = u32::try_from(gap_start / block_size).map_err(|_| FsError::Invalid)?;
        let last = u32::try_from((gap_end - 1) / block_size).map_err(|_| FsError::Invalid)?;
        let ptrs = self.block_size / 4;
        let single_first = EXT2_NDIR_BLOCKS as u32;
        let double_first = single_first.checked_add(ptrs).ok_or(FsError::Invalid)?;
        let double_span = ptrs.checked_mul(ptrs).ok_or(FsError::Invalid)?;
        let supported_end = double_first
            .checked_add(double_span)
            .ok_or(FsError::Invalid)?;
        if last >= supported_end {
            return Err(FsError::NotSupported);
        }

        scratch.branches.clear();
        let mut loaded_bitmap_group = None;
        let direct_last = last.min(EXT2_NDIR_BLOCKS as u32 - 1);
        if first <= direct_last {
            for file_block in first..=direct_last {
                let physical = raw.block[file_block as usize];
                if physical != 0 {
                    self.visit_sparse_gap_target(
                        journal,
                        physical,
                        file_block,
                        gap_start,
                        gap_end,
                        &mut scratch.bitmap,
                        &mut loaded_bitmap_group,
                        visitor,
                    )?;
                }
            }
        }

        if last >= single_first && first < double_first && raw.block[EXT2_IND_BLOCK] != 0 {
            let start = first.max(single_first);
            let end = last.min(double_first - 1);
            let indirect = self.visit_sparse_gap_mapping_node(
                journal,
                raw.block[EXT2_IND_BLOCK],
                None,
                &mut scratch.bitmap,
                &mut loaded_bitmap_group,
                visitor,
            )?;
            self.read_physical_block(indirect, mapping.block_mut())?;
            for file_block in start..=end {
                let index =
                    usize::try_from(file_block - single_first).map_err(|_| FsError::Invalid)?;
                let physical = read_u32_le(mapping.block(), index)?;
                if physical != 0 {
                    self.visit_sparse_gap_target(
                        journal,
                        physical,
                        file_block,
                        gap_start,
                        gap_end,
                        &mut scratch.bitmap,
                        &mut loaded_bitmap_group,
                        visitor,
                    )?;
                }
            }
        }

        if last >= double_first && raw.block[EXT2_DIND_BLOCK] != 0 {
            let start = first.max(double_first);
            let end = last;
            let first_branch = (start - double_first) / ptrs;
            let last_branch = (end - double_first) / ptrs;
            let double = self.visit_sparse_gap_mapping_node(
                journal,
                raw.block[EXT2_DIND_BLOCK],
                None,
                &mut scratch.bitmap,
                &mut loaded_bitmap_group,
                visitor,
            )?;
            self.read_physical_block(double, mapping.block_mut())?;
            let mut present_branches = 0usize;
            for branch in first_branch..=last_branch {
                if read_u32_le(mapping.block(), branch as usize)? != 0 {
                    present_branches = present_branches.checked_add(1).ok_or(FsError::NoMem)?;
                    if present_branches > MAX_SPARSE_GAP_MAPPING_NODES {
                        return Err(FsError::NoMem);
                    }
                }
            }
            scratch.prepare_branches(present_branches)?;
            for branch in first_branch..=last_branch {
                let indirect = read_u32_le(mapping.block(), branch as usize)?;
                if indirect == 0 {
                    continue;
                }
                let indirect = self.visit_sparse_gap_mapping_node(
                    journal,
                    indirect,
                    Some(u16::try_from(branch).map_err(|_| FsError::Invalid)?),
                    &mut scratch.bitmap,
                    &mut loaded_bitmap_group,
                    visitor,
                )?;
                if scratch.branches.len() >= MAX_SPARSE_GAP_MAPPING_NODES
                    || scratch.branches.len() == scratch.branches.capacity()
                {
                    return Err(FsError::Invalid);
                }
                // lint-fallible: PREALLOCATED(capacity re-checked at the guard just above; branches reserved by prepare_branches)
                scratch.branches.push(SparseGapBranch {
                    index: branch,
                    physical: indirect,
                });
            }
            if scratch.branches.len() != present_branches {
                return Err(FsError::Invalid);
            }
            for branch in scratch.branches.iter().copied() {
                self.read_physical_block(branch.physical, mapping.block_mut())?;
                let branch_first = double_first
                    .checked_add(branch.index.checked_mul(ptrs).ok_or(FsError::Invalid)?)
                    .ok_or(FsError::Invalid)?;
                let branch_last = branch_first.checked_add(ptrs - 1).ok_or(FsError::Invalid)?;
                for file_block in start.max(branch_first)..=end.min(branch_last) {
                    let index =
                        usize::try_from(file_block - branch_first).map_err(|_| FsError::Invalid)?;
                    let physical = read_u32_le(mapping.block(), index)?;
                    if physical != 0 {
                        self.visit_sparse_gap_target(
                            journal,
                            physical,
                            file_block,
                            gap_start,
                            gap_end,
                            &mut scratch.bitmap,
                            &mut loaded_bitmap_group,
                            visitor,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Re-walk the fully validated tree into exact-capacity compact plans.
    /// The first pass already proved allocation-bit ownership while the inode,
    /// filesystem metadata, and journal locks were held.  This pass rechecks
    /// pointer geometry plus structural/journal identity and requires exact
    /// count agreement, but deliberately does not retain a second 64 KiB
    /// bitmap scratch alongside the 65,536-entry target plan.
    fn collect_sparse_gap(
        &self,
        raw: &Ext2InodeRaw,
        gap_start: u64,
        gap_end: u64,
        journal: &Ext2Journal,
        mapping: &mut Ext2MutationScratch,
        collector: &mut SparseGapCollectVisitor<'_>,
    ) -> Result<(), FsError> {
        if gap_start >= gap_end {
            return Ok(());
        }
        let block_size = self.block_size as u64;
        let first = u32::try_from(gap_start / block_size).map_err(|_| FsError::Invalid)?;
        let last = u32::try_from((gap_end - 1) / block_size).map_err(|_| FsError::Invalid)?;
        let ptrs = self.block_size / 4;
        let single_first = EXT2_NDIR_BLOCKS as u32;
        let double_first = single_first.checked_add(ptrs).ok_or(FsError::Invalid)?;
        let double_span = ptrs.checked_mul(ptrs).ok_or(FsError::Invalid)?;
        let supported_end = double_first
            .checked_add(double_span)
            .ok_or(FsError::Invalid)?;
        if last >= supported_end {
            return Err(FsError::NotSupported);
        }

        let direct_last = last.min(EXT2_NDIR_BLOCKS as u32 - 1);
        if first <= direct_last {
            for file_block in first..=direct_last {
                let physical = raw.block[file_block as usize];
                if physical != 0 {
                    let physical = self.validate_sparse_gap_identity(journal, physical)?;
                    collector.data_target(
                        file_block,
                        self.sparse_gap_target(physical, file_block, gap_start, gap_end)?,
                    )?;
                }
            }
        }

        if last >= single_first && first < double_first && raw.block[EXT2_IND_BLOCK] != 0 {
            let start = first.max(single_first);
            let end = last.min(double_first - 1);
            let indirect = self.validate_sparse_gap_identity(journal, raw.block[EXT2_IND_BLOCK])?;
            collector.mapping_node(indirect, None)?;
            self.read_physical_block(indirect, mapping.block_mut())?;
            for file_block in start..=end {
                let index =
                    usize::try_from(file_block - single_first).map_err(|_| FsError::Invalid)?;
                let physical = read_u32_le(mapping.block(), index)?;
                if physical != 0 {
                    let physical = self.validate_sparse_gap_identity(journal, physical)?;
                    collector.data_target(
                        file_block,
                        self.sparse_gap_target(physical, file_block, gap_start, gap_end)?,
                    )?;
                }
            }
        }

        if last >= double_first && raw.block[EXT2_DIND_BLOCK] != 0 {
            let start = first.max(double_first);
            let end = last;
            let first_branch = (start - double_first) / ptrs;
            let last_branch = (end - double_first) / ptrs;
            let double = self.validate_sparse_gap_identity(journal, raw.block[EXT2_DIND_BLOCK])?;
            collector.mapping_node(double, None)?;
            self.read_physical_block(double, mapping.block_mut())?;
            let node_base = collector.mapping_nodes.len();
            let branch_base = collector.branch_indices.len();
            for branch in first_branch..=last_branch {
                let indirect = read_u32_le(mapping.block(), branch as usize)?;
                if indirect == 0 {
                    continue;
                }
                let indirect = self.validate_sparse_gap_identity(journal, indirect)?;
                let branch = u16::try_from(branch).map_err(|_| FsError::Invalid)?;
                collector.mapping_node(indirect, Some(branch))?;
            }
            let branch_count = collector
                .branch_indices
                .len()
                .checked_sub(branch_base)
                .ok_or(FsError::Invalid)?;
            if collector
                .mapping_nodes
                .len()
                .checked_sub(node_base)
                .ok_or(FsError::Invalid)?
                != branch_count
            {
                return Err(FsError::Invalid);
            }
            for index in 0..branch_count {
                let branch = collector.branch_indices[branch_base + index] as u32;
                let indirect = collector.mapping_nodes[node_base + index];
                self.read_physical_block(indirect, mapping.block_mut())?;
                let branch_first = double_first
                    .checked_add(branch.checked_mul(ptrs).ok_or(FsError::Invalid)?)
                    .ok_or(FsError::Invalid)?;
                let branch_last = branch_first.checked_add(ptrs - 1).ok_or(FsError::Invalid)?;
                for file_block in start.max(branch_first)..=end.min(branch_last) {
                    let pointer =
                        usize::try_from(file_block - branch_first).map_err(|_| FsError::Invalid)?;
                    let physical = read_u32_le(mapping.block(), pointer)?;
                    if physical != 0 {
                        let physical = self.validate_sparse_gap_identity(journal, physical)?;
                        collector.data_target(
                            file_block,
                            self.sparse_gap_target(physical, file_block, gap_start, gap_end)?,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// RF180-13/RF180-34: validate and count the complete sparse gap before
    /// reserving exact retained storage, then re-walk under the same inode,
    /// metadata, and journal locks.  No allocation or validation can occur
    /// after the first persistent zeroing write.
    fn preflight_sparse_gap(
        &self,
        raw: &Ext2InodeRaw,
        gap_start: u64,
        gap_end: u64,
        journal: &Ext2Journal,
        mapping_scratch: &mut Ext2MutationScratch,
    ) -> Result<SparseGapPlan, FsError> {
        if gap_start >= gap_end {
            let reservation =
                mm::try_reserve_heap(HeapClass::FilesystemIo, 0).map_err(|_| FsError::NoMem)?;
            return Ok(SparseGapPlan {
                targets: Vec::new(),
                boundaries: [None, None],
                _reservation: reservation,
            });
        }

        let mut traversal = SparseGapTraversalScratch::try_new(self.block_size)?;
        let mut counter = SparseGapCountVisitor {
            counts: SparseGapCounts::default(),
            block_size: self.block_size,
            transcript: SparseGapTranscript::new(self.block_size, gap_start, gap_end),
        };
        self.walk_sparse_gap(
            raw,
            gap_start,
            gap_end,
            journal,
            mapping_scratch,
            &mut traversal,
            &mut counter,
        )?;
        let counts = counter.counts;
        let expected_transcript = counter.transcript.finish();
        // The full allocation-bitmap validation is complete.  Its bitmap and
        // branch scratch must be deallocated before the exact retained plan is
        // admitted, so the two bounded phases never stack their maxima.
        drop(traversal);
        let estimated = sparse_gap_plan_charge_bytes(counts)?;
        // Reservation precedes all allocations.  Local reverse-drop order and
        // the returned plan's field order release backing before accounting.
        let mut reservation =
            mm::try_reserve_heap(HeapClass::FilesystemIo, estimated).map_err(|_| FsError::NoMem)?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(counts.data_targets)
            .map_err(|_| FsError::NoMem)?;
        let mut mapping_nodes = Vec::new();
        mapping_nodes
            .try_reserve_exact(counts.mapping_nodes)
            .map_err(|_| FsError::NoMem)?;
        let mut branch_indices = Vec::new();
        branch_indices
            .try_reserve_exact(counts.branch_nodes)
            .map_err(|_| FsError::NoMem)?;
        let actual = sparse_gap_backing_charge_bytes(
            mapping_nodes.capacity(),
            targets.capacity(),
            branch_indices.capacity(),
        )?;
        reservation.resize(actual).map_err(|_| FsError::NoMem)?;

        let mut boundaries = [None, None];
        let collected_transcript = {
            let mut collector = SparseGapCollectVisitor {
                mapping_nodes: &mut mapping_nodes,
                branch_indices: &mut branch_indices,
                targets: &mut targets,
                boundaries: &mut boundaries,
                block_size: self.block_size,
                expected: counts,
                transcript: SparseGapTranscript::new(self.block_size, gap_start, gap_end),
            };
            self.collect_sparse_gap(
                raw,
                gap_start,
                gap_end,
                journal,
                mapping_scratch,
                &mut collector,
            )?;
            collector.transcript.finish()
        };
        if mapping_nodes.len() != counts.mapping_nodes
            || branch_indices.len() != counts.branch_nodes
            || targets.len() != counts.data_targets
            || boundaries.iter().flatten().count() != counts.boundary_targets
            || collected_transcript != expected_transcript
        {
            return Err(FsError::Invalid);
        }

        // Revalidate the transcript-matched collected set against allocation
        // bitmaps before sorting or persistence.  The caller's mapping scratch
        // is no longer needed for pointer traversal, so this closes both
        // pointer-graph and allocation-bit TOCTOU without another allocation or
        // a higher heap peak.
        let mut loaded_bitmap_group = None;
        for &physical in mapping_nodes.iter().chain(targets.iter()) {
            self.validate_sparse_gap_block(
                journal,
                physical,
                mapping_scratch,
                &mut loaded_bitmap_group,
            )?;
        }

        mapping_nodes.sort_unstable();
        if mapping_nodes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }
        targets.sort_unstable();
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FsError::Invalid);
        }
        let mut node_index = 0usize;
        let mut target_index = 0usize;
        while node_index < mapping_nodes.len() && target_index < targets.len() {
            match mapping_nodes[node_index].cmp(&targets[target_index]) {
                cmp::Ordering::Less => node_index += 1,
                cmp::Ordering::Greater => target_index += 1,
                cmp::Ordering::Equal => return Err(FsError::Invalid),
            }
        }
        for boundary in boundaries.iter().flatten() {
            if boundary.start >= boundary.end
                || boundary.end > self.block_size
                || targets.binary_search(&boundary.physical).is_err()
            {
                return Err(FsError::Invalid);
            }
        }
        drop(mapping_nodes);
        drop(branch_indices);
        let target_charge =
            mm::vec_charge_bytes::<u32>(targets.capacity()).map_err(|_| FsError::NoMem)?;
        reservation
            .resize(target_charge)
            .map_err(|_| FsError::NoMem)?;
        Ok(SparseGapPlan {
            targets,
            boundaries,
            _reservation: reservation,
        })
    }

    fn zero_sparse_gap(
        &self,
        plan: &SparseGapPlan,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        for &physical in &plan.targets {
            let (start, end) =
                sparse_gap_target_bounds(&plan.boundaries, physical, self.block_size);
            debug_assert!(start < end && end <= self.block_size as usize);
            if start != 0 || end != self.block_size as usize {
                self.read_block(physical, scratch.block_mut())?;
            } else {
                scratch.block_mut().fill(0);
            }
            scratch.block_mut()[start..end].fill(0);
            self.write_block(physical, scratch.block())?;
        }
        if !plan.targets.is_empty() {
            self.flush_device()?;
        }
        Ok(())
    }
}

impl FileSystem for Ext2Fs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "ext2"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.read().as_ref().unwrap().clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        self.ensure_io_healthy()?;
        // Downcast to Ext2Inode
        let parent = parent
            .as_any()
            .downcast_ref::<Ext2Inode>()
            .ok_or(FsError::Invalid)?;

        if !parent.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        // Search directory entries
        parent.dir_lookup(name)
    }
}

// ============================================================================
// Ext2 Inode
// ============================================================================

/// Ext2 inode wrapper
pub struct Ext2Inode {
    fs: Weak<Ext2Fs>,
    fs_id: u64,
    ino: u32,
    /// On-disk inode data (protected for write updates)
    raw: RwLock<Ext2InodeRaw>,
    /// File size (atomic for concurrent reads)
    size: AtomicU64,
    /// Serialize writes to this inode
    write_lock: Mutex<()>,
}

impl Ext2Inode {
    /// Boot/integration proof that this inode belongs to a mount with a fully
    /// validated internal journal. Production tests use this to ensure the
    /// shipped image exercises the transactional path instead of silently
    /// falling back to plain-Ext2 mapped writes.
    #[doc(hidden)]
    pub fn uses_internal_journal(&self) -> Result<bool, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        let journaled = fs.journal.lock().is_some();
        Ok(journaled)
    }

    /// Check if this is a directory
    fn is_dir_inner(&self) -> bool {
        (self.raw.read().mode & EXT2_S_IFMT) == EXT2_S_IFDIR
    }

    /// Check if this is a regular file
    fn is_file_inner(&self) -> bool {
        (self.raw.read().mode & EXT2_S_IFMT) == EXT2_S_IFREG
    }

    /// Look up a name in this directory
    fn dir_lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;

        let mut offset = 0u64;
        let file_size = self.size.load(Ordering::Acquire);
        let raw = *self.raw.read();
        // R178-29 FIX: Fallible directory listing buffer allocation (up to 64 KiB).
        let mut block_buf = Vec::new();
        block_buf
            .try_reserve_exact(fs.block_size as usize)
            .map_err(|_| FsError::NoSpace)?;
        block_buf.resize(fs.block_size as usize, 0u8);

        while offset < file_size {
            // Calculate which block to read
            let file_block_u64 = offset / fs.block_size as u64;
            // R97-3 FIX: Use try_from instead of truncating cast to prevent wraparound
            let file_block = u32::try_from(file_block_u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = offset % fs.block_size as u64;

            // Map to physical block
            let phys_block = fs.map_file_block(&raw, file_block)?;
            if let Some(phys) = phys_block {
                fs.read_block(phys, &mut block_buf)?;
            } else {
                // Hole - zero-filled
                block_buf.fill(0);
            }

            // Parse directory entry
            let data = &block_buf[offset_in_block as usize..];
            if data.len() < size_of::<Ext2DirEntryHead>() {
                break;
            }

            // R96-8 Fix: Use read_unaligned to avoid UB from unaligned access.
            // Vec<u8> only guarantees 1-byte alignment, but Ext2DirEntryHead
            // contains u32/u16 fields that may require higher alignment.
            let head: Ext2DirEntryHead =
                unsafe { core::ptr::read_unaligned(data.as_ptr() as *const _) };

            if head.rec_len == 0 {
                break;
            }

            // R28-4 Fix: Validate rec_len and name_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            let min_rec = size_of::<Ext2DirEntryHead>();
            if rec_len < min_rec || (offset_in_block as usize) + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }
            if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                return Err(FsError::Invalid);
            }

            if head.inode != 0 && head.name_len > 0 {
                let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                if let Ok(entry_name) = core::str::from_utf8(name_bytes) {
                    if entry_name == name {
                        // RF178-37: every lookup of this `(fs, ino)` returns the
                        // same wrapper, including its raw/size/write state.
                        return Ok(fs.load_inode(head.inode)?);
                    }
                }
            }

            offset += head.rec_len as u64;
        }

        Err(FsError::NotFound)
    }

    /// Read file data at offset using page cache
    ///
    /// This implementation routes all file reads through the global page cache,
    /// providing caching and reducing disk I/O for repeated accesses.
    fn read_file_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        let file_size = self.size.load(Ordering::Acquire);
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = fs.block_size as usize;

        // Create unique inode_id for page cache: combine fs_id and ino
        // Use upper 32 bits for fs_id, lower 32 bits for ino
        let cache_inode_id = (self.fs_id << 32) | (self.ino as u64);
        // Writers retain `raw.write()` through their page-cache publication.
        // Hold the matching read guard through every cached-page copy so an
        // Uptodate fast-path reader cannot alias a concurrent raw-pointer write.
        let raw_guard = self.raw.read();
        // A writer may have poisoned the mount while this reader waited for
        // the raw-inode lock.  Recheck under the serialization edge before
        // trusting either inode metadata or cached page bytes.
        fs.ensure_io_healthy()?;
        let raw_inode = *raw_guard;

        let to_read = buf.len().min((file_size - offset) as usize);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let page_index = file_offset / PAGE_SIZE as u64;
            let offset_in_page = (file_offset % PAGE_SIZE as u64) as usize;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let copy_len = cmp::min(remaining_in_page, to_read - bytes_read);

            // RF178-11 FIX: bind each cache miss to the cgroup current for this
            // page's admission. A multi-page read may straddle a concurrent
            // migration; operation-start identity would mischarge later pages.
            let page_cache_owner = kernel_core::process::current_cgroup_id().unwrap_or(0);

            // Clone fs for the I/O closure
            let fs_for_io = fs.clone();

            // Allocate physical frame for new page
            let alloc_pfn = || -> Option<u64> {
                let frame = buddy_allocator::alloc_physical_pages(1)?;
                Some(frame.start_address().as_u64() / PAGE_SIZE as u64)
            };

            // Read page from cache, or load from disk if not cached
            let page = page_cache::read_page(
                cache_inode_id,
                page_index,
                page_cache_owner,
                |cgroup_id, bytes| kernel_core::cgroup::try_charge_memory(cgroup_id, bytes).is_ok(),
                kernel_core::cgroup::uncharge_memory,
                alloc_pfn,
                |page_entry: &PageCacheEntry| {
                    // This closure populates the page from disk
                    let page_phys = page_entry.physical_address();
                    let page_virt = (page_phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;

                    // Zero the page first (handles sparse files and EOF)
                    unsafe {
                        core::ptr::write_bytes(page_virt, 0, PAGE_SIZE);
                    }

                    // Calculate file offset for this page
                    let page_start_offset = page_entry.index * PAGE_SIZE as u64;
                    let mut filled = 0usize;

                    // Fill the page from disk blocks
                    while filled < PAGE_SIZE {
                        let global_offset = page_start_offset + filled as u64;

                        // Stop at end of file
                        if global_offset >= file_size {
                            break;
                        }

                        // Calculate which file block and offset within block
                        // R97-3 FIX: Use try_from instead of truncating cast
                        let file_block =
                            u32::try_from(global_offset / block_size as u64).map_err(|_| ())?;
                        let offset_in_block = (global_offset % block_size as u64) as usize;

                        // R178-29 FIX: Fallible block buffer allocation inside page cache loader (up to 64 KiB).
                        let mut block_buf = Vec::new();
                        if block_buf.try_reserve_exact(block_size).is_err() {
                            return Err(());
                        }
                        block_buf.resize(block_size, 0u8);
                        let phys_block = match fs_for_io.map_file_block(&raw_inode, file_block) {
                            Ok(Some(b)) => Some(b),
                            Ok(None) => None, // Hole in file
                            Err(_) => return Err(()),
                        };

                        if let Some(phys) = phys_block {
                            if fs_for_io.read_block(phys, &mut block_buf).is_err() {
                                return Err(());
                            }
                        }
                        // For holes, block_buf is already zeroed

                        // Calculate how much to copy from this block
                        let bytes_left_in_block = block_size.saturating_sub(offset_in_block);
                        let bytes_left_in_page = PAGE_SIZE - filled;
                        let bytes_left_in_file = (file_size - global_offset) as usize;
                        let chunk = cmp::min(
                            cmp::min(bytes_left_in_block, bytes_left_in_page),
                            bytes_left_in_file,
                        );

                        if chunk == 0 {
                            break;
                        }

                        // Copy data to page
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                block_buf.as_ptr().add(offset_in_block),
                                page_virt.add(filled),
                                chunk,
                            );
                        }

                        filled += chunk;
                    }

                    Ok(())
                },
            )
            .ok_or(FsError::Io)?;

            // Copy data from cached page to user buffer
            let page_virt = (page.physical_address() + PHYSICAL_MEMORY_OFFSET) as *const u8;
            let src =
                unsafe { core::slice::from_raw_parts(page_virt.add(offset_in_page), copy_len) };
            buf[bytes_read..bytes_read + copy_len].copy_from_slice(src);

            // R36-FIX: Balance the page cache refcount so shrink() can reclaim this page.
            // find_get_page increments refcount, we must call put() when done using the page.
            page.put();

            bytes_read += copy_len;
        }

        drop(raw_guard);
        Ok(bytes_read)
    }

    fn publish_cached_write(&self, cursor: u64, data: &[u8]) {
        let inode_id = (self.fs_id << 32) | self.ino as u64;
        let mut remaining = data.len();
        let mut cache_cursor = cursor;
        let mut data_pos = 0usize;
        while remaining > 0 {
            let page_index = cache_cursor / PAGE_SIZE as u64;
            let offset_in_page = (cache_cursor % PAGE_SIZE as u64) as usize;
            let page_room = PAGE_SIZE - offset_in_page;
            let chunk = cmp::min(remaining, page_room);
            if let Some(page) = PAGE_CACHE.find_get_page(inode_id, page_index) {
                // Serialize with a concurrent cache-miss fill or writeback.
                // Without the page I/O lock, a loader can overwrite these
                // committed bytes and leave a stale Uptodate cache page.
                let _io_lock = page.lock_io();
                if page.is_uptodate() {
                    let page_virt = (page.physical_address() + PHYSICAL_MEMORY_OFFSET) as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data[data_pos..].as_ptr(),
                            page_virt.add(offset_in_page),
                            chunk,
                        );
                    }
                }
            }
            remaining -= chunk;
            cache_cursor += chunk as u64;
            data_pos += chunk;
        }
    }

    /// R180-6 FIX: mapped blocks retain the ordered in-place update path, while
    /// direct holes on a validated Ext3/JBD2 image use one ordered-data
    /// transaction per allocated block. Unsupported indirect holes are found
    /// before the first write. Earlier durable chunks are returned as a POSIX
    /// short-write prefix if a later chunk fails.
    fn write_mutation(&self, mode: Ext2WriteMode, data: &[u8]) -> Result<(usize, u64), FsError> {
        if !self.is_file_inner() {
            return Err(FsError::IsDir);
        }
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        if data.is_empty() {
            let offset = match mode {
                Ext2WriteMode::Positioned(offset) => offset,
                Ext2WriteMode::Append => self.size.load(Ordering::Acquire),
            };
            return Ok((0, offset));
        }

        if fs.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        let mut scratch = Ext2MutationScratch::try_new_admitted(fs.block_size)?;
        let _inode_guard = self.write_lock.lock();
        let mut raw_guard = self.raw.write();
        // Different inodes can share one inode-table block.  Retaining the
        // filesystem metadata gate across preflight and every inode RMW avoids
        // both pointer-block TOCTOU and lost updates between those inodes.
        let _meta = fs.meta_lock.lock();
        fs.ensure_io_healthy()?;
        let current_size = self.size.load(Ordering::Acquire);
        let offset = match mode {
            Ext2WriteMode::Positioned(offset) => offset,
            Ext2WriteMode::Append => current_size,
        };

        if (raw_guard.flags & EXT2_IMMUTABLE_FL) != 0 {
            return Err(FsError::PermDenied);
        }
        if raw_guard.flags & EXT2_UNSUPPORTED_WRITE_LAYOUT_FL != 0 {
            return Err(FsError::NotSupported);
        }
        if (raw_guard.flags & EXT2_APPEND_FL) != 0
            && matches!(mode, Ext2WriteMode::Positioned(_))
            && offset != current_size
        {
            return Err(FsError::PermDenied);
        }
        let inode_target = fs.inode_write_target(self.ino)?;
        let journal_inum = fs.superblock.read().journal_inum;
        let mut journal_guard = fs.journal.lock();
        let journaled = journal_guard.is_some();
        if !journaled {
            // Defense in depth for any future in-memory constructor that does
            // not pass through `read_super`: refusing before preflight/data I/O
            // is what makes the plain-Ext2 read-only contract real.
            return Err(FsError::ReadOnly);
        }
        if journaled && self.ino == journal_inum {
            return Err(FsError::PermDenied);
        }
        let preflight_raw = *raw_guard;
        preflight_write_range(
            offset,
            data.len(),
            fs.block_size as u64,
            |file_block| match fs.map_file_block_with_scratch(
                &preflight_raw,
                file_block,
                &mut scratch,
            )? {
                Some(physical) => {
                    if fs.is_structural_metadata_block(physical)?
                        || journal_guard
                            .as_ref()
                            .is_some_and(|journal| journal.contains_physical(physical))
                    {
                        return Err(FsError::Invalid);
                    }
                    Ok(true)
                }
                None => Ok(journaled && file_block < EXT2_NDIR_BLOCKS as u32),
            },
        )?;
        let sparse_gap = fs.preflight_sparse_gap(
            &preflight_raw,
            current_size,
            offset,
            journal_guard.as_ref().ok_or(FsError::ReadOnly)?,
            &mut scratch,
        )?;
        fs.zero_sparse_gap(&sparse_gap, &mut scratch)?;
        // The target backing has served its only purpose.  Destroy it before
        // releasing admission and before the ordinary data/journal loop starts.
        drop(sparse_gap);

        let block_size = fs.block_size as usize;
        let mut written = 0usize;
        let mut cursor = offset;
        while written < data.len() {
            let fail = |error: FsError, committed: usize| {
                if committed == 0 {
                    Err(error)
                } else {
                    Ok((committed, offset + committed as u64))
                }
            };
            let file_block =
                u32::try_from(cursor / fs.block_size as u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = (cursor % fs.block_size as u64) as usize;
            let to_copy = cmp::min(block_size - offset_in_block, data.len() - written);
            let committed_raw = *raw_guard;
            let phys_block =
                match fs.map_file_block_with_scratch(&committed_raw, file_block, &mut scratch) {
                    Ok(block) => block,
                    Err(error) => return fail(error, written),
                };
            let chunk_end = cursor.checked_add(to_copy as u64).ok_or(FsError::Invalid)?;
            let published_size = self.size.load(Ordering::Acquire).max(chunk_end);
            let mut next_raw = committed_raw;
            next_raw.size_lo = published_size as u32;
            next_raw.size_high_or_dir_acl = (published_size >> 32) as u32;
            let now = TimeSpec::now();
            next_raw.mtime = now.sec as u32;
            next_raw.ctime = now.sec as u32;

            if let Some(phys_block) = phys_block {
                let block_buf = scratch.block_mut();
                if to_copy != block_size {
                    if let Err(error) = fs.read_block(phys_block, block_buf) {
                        return fail(error, written);
                    }
                }
                block_buf[offset_in_block..offset_in_block + to_copy]
                    .copy_from_slice(&data[written..written + to_copy]);
                if let Err(error) = fs.write_block(phys_block, block_buf) {
                    fs.io_faulted.store(true, Ordering::Release);
                    return fail(error, written);
                }
                if let Err(error) = fs.flush_device() {
                    fs.io_faulted.store(true, Ordering::Release);
                    return fail(error, written);
                }
                let journal = journal_guard.as_mut().ok_or(FsError::ReadOnly)?;
                let transaction_failure = match fs.commit_metadata_transaction(
                    journal,
                    JournalMetadataPlan::InodeUpdate {
                        inode_number: self.ino,
                        inode_target,
                        old_inode: committed_raw,
                        new_inode: next_raw,
                    },
                    &mut scratch,
                ) {
                    Ok(()) => None,
                    Err(failure) if failure.committed => Some(failure),
                    Err(failure) => {
                        // Ordered data is already durable. Even a cleanly
                        // aborted metadata transaction can leave an
                        // existing-size overwrite visible on disk while the
                        // page cache still contains old bytes, so continuing
                        // the mount would be incoherent.
                        fs.io_faulted.store(true, Ordering::Release);
                        return fail(failure.error, written);
                    }
                };
                debug_assert_eq!(next_raw.block, committed_raw.block);
                debug_assert_eq!(next_raw.blocks_lo, committed_raw.blocks_lo);

                *raw_guard = next_raw;
                self.size.store(published_size, Ordering::Release);
                self.publish_cached_write(cursor, &data[written..written + to_copy]);
                written += to_copy;
                cursor += to_copy as u64;
                if let Some(failure) = transaction_failure {
                    if failure.poison {
                        fs.io_faulted.store(true, Ordering::Release);
                    }
                    return fail(failure.error, written);
                }
                continue;
            }

            // Preflight permits a hole only when it is direct and an internal
            // journal is present. Both conditions remain stable under the
            // inode, metadata, and journal locks held for this mutation.
            let Some(journal) = journal_guard.as_mut() else {
                return fail(FsError::NotSupported, written);
            };
            if file_block >= EXT2_NDIR_BLOCKS as u32 {
                return fail(FsError::NotSupported, written);
            }
            let plan = match fs.plan_direct_allocation(
                self.ino,
                &committed_raw,
                next_raw,
                file_block,
                inode_target,
                journal,
                &mut scratch,
            ) {
                Ok(plan) => plan,
                Err(error) => return fail(error, written),
            };
            debug_assert_eq!(plan.file_block, file_block);
            debug_assert_eq!(plan.new_inode.block[file_block as usize], plan.phys_block);

            // Ordered-data rule: initialize and durably flush the complete new
            // block before any metadata transaction can make it reachable.
            let block_buf = scratch.block_mut();
            block_buf.fill(0);
            block_buf[offset_in_block..offset_in_block + to_copy]
                .copy_from_slice(&data[written..written + to_copy]);
            if let Err(error) = fs.write_block(plan.phys_block, block_buf) {
                return fail(error, written);
            }
            if let Err(error) = fs.flush_device() {
                return fail(error, written);
            }

            let transaction_failure = match fs.commit_metadata_transaction(
                journal,
                JournalMetadataPlan::DirectAllocation(plan),
                &mut scratch,
            ) {
                Ok(()) => None,
                Err(failure) if failure.committed => Some(failure),
                Err(failure) => {
                    if failure.poison {
                        fs.io_faulted.store(true, Ordering::Release);
                    }
                    return fail(failure.error, written);
                }
            };

            // The commit is durable at this point even when checkpoint or log
            // clearing subsequently failed. Publish exactly the state recovery
            // will reconstruct, count this chunk, then fail-stop the mount.
            *fs.superblock.write() = plan.new_superblock;
            fs.group_descs.write()[plan.group] = plan.new_group_desc;
            *raw_guard = plan.new_inode;
            self.size.store(published_size, Ordering::Release);
            self.publish_cached_write(cursor, &data[written..written + to_copy]);
            written += to_copy;
            cursor += to_copy as u64;

            if let Some(failure) = transaction_failure {
                if failure.poison {
                    fs.io_faulted.store(true, Ordering::Release);
                }
                return fail(failure.error, written);
            }
        }
        Ok((written, cursor))
    }

    /// Convert raw mode to FileType
    fn file_type(&self) -> FileType {
        match self.raw.read().mode & EXT2_S_IFMT {
            EXT2_S_IFREG => FileType::Regular,
            EXT2_S_IFDIR => FileType::Directory,
            EXT2_S_IFLNK => FileType::Symlink,
            _ => FileType::Regular, // Default
        }
    }
}

impl Inode for Ext2Inode {
    fn ino(&self) -> u64 {
        self.ino as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        let raw = *self.raw.read();
        let size = self.size.load(Ordering::Acquire);

        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino as u64,
            mode: FileMode::new(self.file_type(), raw.mode & 0o7777),
            nlink: raw.links_count as u32,
            uid: raw.uid as u32,
            gid: raw.gid as u32,
            rdev: 0,
            size,
            blksize: fs.block_size,
            blocks: raw.blocks_lo as u64,
            atime: TimeSpec::new(raw.atime as i64, 0),
            mtime: TimeSpec::new(raw.mtime as i64, 0),
            ctime: TimeSpec::new(raw.ctime as i64, 0),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        let canonical = fs.inode_cache.get(self.ino).ok_or(FsError::Invalid)?;
        if !Arc::ptr_eq(&self, &canonical) {
            // Every Ext2Inode entering VFS must be the cache's canonical object.
            // Fail closed instead of manufacturing another stale wrapper.
            return Err(FsError::Invalid);
        }
        drop(canonical);

        // Directories can only be opened for read-only operations (getdents64)
        if self.is_dir_inner() {
            if flags.is_writable() {
                return Err(FsError::IsDir);
            }
            let inode: Arc<dyn Inode> = self;
            return Ok(prepared.finalize(inode, flags, false));
        }

        // RF178-17 FIX: regular files must use the shared-offset FileHandle so
        // O_APPEND reaches Ext2Inode::append_write.
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn is_dir(&self) -> bool {
        self.is_dir_inner()
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.ensure_io_healthy()?;
        if !self.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        let file_size = self.size.load(Ordering::Acquire);
        let raw = *self.raw.read();
        let block_size = fs.block_size as u64;
        // R178-29 FIX: Fallible directory lookup buffer allocation (up to 64 KiB).
        let mut block_buf = Vec::new();
        block_buf
            .try_reserve_exact(fs.block_size as usize)
            .map_err(|_| FsError::NoSpace)?;
        // lint-fallible: PREALLOCATED(exact try_reserve_exact on the line above)
        block_buf.resize(fs.block_size as usize, 0u8);
        let min_rec = size_of::<Ext2DirEntryHead>();

        // R165-21 FIX: read the inode count ONCE here instead of re-acquiring the
        // superblock read lock for every candidate entry (previously O(N) lock
        // acquisitions per call, O(N^2) across a full enumeration).
        let inodes_count = fs.superblock.read().inodes_count;

        // R165-21 FIX: `offset` is now an OPAQUE BYTE OFFSET into the directory
        // file (the resume cookie), not a logical entry index. Each call resumes
        // near `target` instead of rescanning from byte 0, turning a full
        // enumeration from O(N^2) into O(N) (bounded per call by one block's
        // worth of records). The cookie stays internal: `sys_getdents64` writes
        // `d_off` as the in-buffer position and persists this cookie as the dir
        // fd offset, so no userspace ABI changes.
        let target = offset as u64;
        if target >= file_size {
            return Ok(None);
        }

        // Begin parsing at the START of the block CONTAINING `target` and walk
        // records forward. ext2 directory records never cross block boundaries,
        // so the first record of every block sits at offset 0. Walking from the
        // block boundary lets us (a) reject a malicious `lseek` to a mid-record
        // offset (it will not coincide with any record boundary -> Invalid)
        // rather than misparsing arbitrary bytes as a directory entry, and
        // (b) keep the per-call cost bounded to a single block.
        let mut current_offset = target - (target % block_size);
        let mut loaded_block: Option<u32> = None;

        while current_offset < file_size {
            let file_block_u64 = current_offset / block_size;
            // R97-3 FIX: Use try_from instead of truncating cast
            let file_block = u32::try_from(file_block_u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = (current_offset % block_size) as usize;

            // (Re)load the block only when we enter a new one.
            if loaded_block != Some(file_block) {
                match fs.map_file_block(&raw, file_block)? {
                    Some(phys) => fs.read_block(phys, &mut block_buf)?,
                    None => block_buf.fill(0),
                }
                loaded_block = Some(file_block);
            }

            let data = &block_buf[offset_in_block..];
            if data.len() < min_rec {
                break;
            }

            // R96-8 Fix: Use read_unaligned to avoid UB from unaligned access.
            // Vec<u8> only guarantees 1-byte alignment, but Ext2DirEntryHead
            // contains u32/u16 fields that may require higher alignment.
            let head: Ext2DirEntryHead =
                unsafe { core::ptr::read_unaligned(data.as_ptr() as *const _) };

            // R165-21 FIX: a zero rec_len inside file_size is malformed (a
            // well-formed ext2 directory pads the last record of each block to
            // the block end, so current_offset reaches file_size exactly). With
            // byte-offset cookies, treating it as silent EOF would let a crafted
            // image / malicious lseek into a zero-filled block truncate the
            // enumeration; reject it instead. Only `target >= file_size`
            // (checked above) legitimately ends iteration.
            if head.rec_len == 0 {
                return Err(FsError::Invalid);
            }

            // R28-4 Fix: Validate rec_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            if rec_len < min_rec || offset_in_block + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }

            let next_offset = current_offset + head.rec_len as u64;

            // R165-21 FIX: records before the resume point are only walked to
            // validate that `target` lands on a real record boundary. If `target`
            // falls strictly inside this record, the cookie is mid-record (e.g. a
            // crafted lseek) and is rejected rather than misparsed.
            if current_offset < target {
                if next_offset > target {
                    return Err(FsError::Invalid);
                }
                current_offset = next_offset;
                continue;
            }

            // R162-24 FIX: validate inode against inodes_count to reject crafted
            // images with out-of-range inode numbers. inode==0 marks a deleted
            // slot; both cases are skipped (advance to the next record).
            if head.inode != 0 && head.inode <= inodes_count && head.name_len > 0 {
                // Validate name_len before accessing
                if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                    return Err(FsError::Invalid);
                }
                let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                let name = fallible_lossy_name(name_bytes)?;

                let file_type = match head.file_type {
                    // R134-6 FIX: EXT2_FT_UNKNOWN — fall back to inode mode
                    // when the filetype feature is absent.  Without this,
                    // legacy ext2 images report everything as Regular.
                    0 => {
                        match fs.read_inode_raw(head.inode) {
                            Ok(raw_inode) => match raw_inode.mode & EXT2_S_IFMT {
                                EXT2_S_IFREG => FileType::Regular,
                                EXT2_S_IFDIR => FileType::Directory,
                                EXT2_S_IFLNK => FileType::Symlink,
                                0x2000 => FileType::CharDevice, // S_IFCHR
                                0x6000 => FileType::BlockDevice, // S_IFBLK
                                0x1000 => FileType::Fifo,       // S_IFIFO
                                0xC000 => FileType::Socket,     // S_IFSOCK
                                _ => FileType::Regular,
                            },
                            Err(_) => FileType::Regular,
                        }
                    }
                    EXT2_FT_REG_FILE => FileType::Regular,
                    EXT2_FT_DIR => FileType::Directory,
                    EXT2_FT_SYMLINK => FileType::Symlink,
                    EXT2_FT_CHRDEV => FileType::CharDevice,
                    EXT2_FT_BLKDEV => FileType::BlockDevice,
                    // R133-7 FIX: Map FIFO/SOCK to correct FileType variants
                    // instead of silently defaulting to Regular.
                    EXT2_FT_FIFO => FileType::Fifo,
                    EXT2_FT_SOCK => FileType::Socket,
                    _ => return Err(FsError::Invalid),
                };

                // R165-21 FIX: return the byte offset of the NEXT record as the
                // resume cookie; the next call starts exactly here.
                return Ok(Some((
                    usize::try_from(next_offset).map_err(|_| FsError::Invalid)?,
                    DirEntry {
                        name,
                        ino: head.inode as u64,
                        file_type,
                    },
                )));
            }

            current_offset = next_offset;
        }

        Ok(None)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.is_file_inner() {
            return Err(FsError::IsDir);
        }
        self.read_file_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        self.write_mutation(Ext2WriteMode::Positioned(offset), data)
            .map(|(written, _)| written)
    }

    fn append_write(&self, data: &[u8]) -> Result<(usize, u64), FsError> {
        self.write_mutation(Ext2WriteMode::Append, data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
