//! Device filesystem (devfs)
//!
//! Provides /dev virtual filesystem with device files:
//! - /dev/null - Discards all writes, returns EOF on read
//! - /dev/zero - Returns infinite zeros on read, discards writes
//! - /dev/console - Kernel console (serial output)
//! - /dev/vdX - Block devices (virtio-blk, etc.)

use crate::traits::{FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FsError, OpenFlags, Stat, TimeSpec};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::BlockDevice;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileDescriptor;
use mm::fallible_map::FallibleOrderedMap;
use mm::{arc_charge_bytes, try_reserve_heap, vec_charge_bytes, HeapCharge, HeapClass};
use spin::{Mutex, RwLock};

/// Device filesystem
pub struct DevFs {
    fs_id: u64,
    root: Arc<DevDirInode>,
}

impl DevFs {
    /// Create a new device filesystem with standard devices
    pub fn new() -> Arc<Self> {
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = crate::identity::allocate_fs_id().expect("devfs: filesystem IDs exhausted");

        // R172-22-FOLLOWON: directory entries use the allocation-fallible FallibleOrderedMap
        // (like ramfs) so a runtime insert (register_block_device) returns NoSpace instead of
        // aborting the kernel via handle_alloc_error. DevFs::new() registers a FIXED 3-device
        // boot set in an infallible constructor, so an OOM here is boot-fatal by policy (the
        // `.expect` mirrors the NEXT_FS_ID `.expect` above) — NOT closure of the OOM-abort class.
        let mut devices: FallibleOrderedMap<String, Arc<dyn Inode>> = FallibleOrderedMap::new();
        // R180-27 FIX: reserve all runtime block-node slots before any device can
        // reach DRIVER_OK. Later publication uses insert_unique_reserved and is
        // therefore allocator-independent.
        devices
            .try_reserve_exact(3 + block::MAX_BLOCK_DEVICES)
            .expect("devfs: boot block-node slot reservation OOM");

        let null_inode = Arc::new(NullDevInode::new(fs_id));
        devices
            .try_insert("null".into(), null_inode)
            .expect("devfs: boot device registration OOM");

        let zero_inode = Arc::new(ZeroDevInode::new(fs_id));
        devices
            .try_insert("zero".into(), zero_inode)
            .expect("devfs: boot device registration OOM");

        let console_inode = Arc::new(ConsoleDevInode::new(fs_id));
        devices
            .try_insert("console".into(), console_inode)
            .expect("devfs: boot device registration OOM");

        let root = Arc::new(DevDirInode {
            fs_id,
            ino: 1,
            entries: RwLock::new(devices),
        });

        Arc::new(Self { fs_id, root })
    }

    /// Register a block device in devfs.
    ///
    /// Creates a device node at /dev/{name} for the given block device.
    pub fn register_block_device(
        &self,
        name: &str,
        device: Arc<dyn BlockDevice>,
    ) -> Result<(), FsError> {
        // Assign a unique inode number
        // R112-2: overflow-safe inode allocation
        static NEXT_BLOCK_INO: AtomicU64 = AtomicU64::new(100);
        let ino = NEXT_BLOCK_INO
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| FsError::NoSpace)?;

        let estimated_heap_bytes = arc_charge_bytes::<BlockDevInode>()
            .and_then(|arc_bytes| {
                vec_charge_bytes::<u8>(name.len()).and_then(|key_bytes| {
                    arc_bytes
                        .checked_add(key_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .map_err(|_| FsError::NoSpace)?;
        let mut reservation = try_reserve_heap(HeapClass::Device, estimated_heap_bytes)
            .map_err(|_| FsError::NoSpace)?;

        // R180-27 FIX: prepare every heap-backed publication object before
        // mutating devfs. BlockDevInode embeds its RMW lock directly, so this is
        // the sole inode allocation and can fail recoverably.
        let mut key = String::new();
        key.try_reserve(name.len()).map_err(|_| FsError::NoSpace)?;
        key.push_str(name);
        let actual_heap_bytes = arc_charge_bytes::<BlockDevInode>()
            .and_then(|arc_bytes| {
                vec_charge_bytes::<u8>(key.capacity()).and_then(|key_bytes| {
                    arc_bytes
                        .checked_add(key_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .map_err(|_| FsError::NoSpace)?;
        reservation
            .resize(actual_heap_bytes)
            .map_err(|_| FsError::NoSpace)?;
        let heap_charge = reservation.commit().map_err(|_| FsError::NoSpace)?;

        let inode = Arc::try_new(BlockDevInode::new(self.fs_id, ino, device, heap_charge))
            .map_err(|_| FsError::NoSpace)?;

        let mut entries = self.root.entries.write();
        if entries.contains_key(name) {
            return Err(FsError::Exists);
        }
        entries
            .insert_unique_reserved(key, inode)
            .map_err(|_| FsError::NoSpace)?;

        Ok(())
    }

    /// Unregister a block device from devfs.
    pub fn unregister_block_device(&self, name: &str) -> Result<(), FsError> {
        let mut entries = self.root.entries.write();
        entries.remove(name).ok_or(FsError::NotFound)?;
        Ok(())
    }
}

impl FileSystem for DevFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "devfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        Arc::clone(&self.root) as Arc<dyn Inode>
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Only root directory lookup supported
        if parent.ino() != 1 {
            return Err(FsError::NotDir);
        }

        let entries = self.root.entries.read();
        entries.get(name).cloned().ok_or(FsError::NotFound)
    }
}

/// Device directory inode (/dev)
struct DevDirInode {
    fs_id: u64,
    ino: u64,
    entries: RwLock<FallibleOrderedMap<String, Arc<dyn Inode>>>,
}

impl Inode for DevDirInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::directory(0o755),
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let entries = self.entries.read();
        let mut iter = entries.iter();

        // Skip to offset
        for _ in 0..offset {
            if iter.next().is_none() {
                return Ok(None);
            }
        }

        // Return next entry
        if let Some((name, inode)) = iter.next() {
            let stat = inode.stat()?;
            Ok(Some((
                offset + 1,
                DirEntry {
                    // R186-8: fallible name copy (was an infallible String::clone).
                    name: crate::types::try_dirent_name(name)?,
                    ino: inode.ino(),
                    file_type: stat.mode.file_type,
                },
            )))
        } else {
            Ok(None)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /dev/null implementation
// ============================================================================

/// /dev/null inode
struct NullDevInode {
    fs_id: u64,
    ino: u64,
}

impl NullDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 2 }
    }
}

impl Inode for NullDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 3), // major 1, minor 3 = /dev/null
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/null always returns EOF
        Ok(0)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/null discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /dev/zero implementation
// ============================================================================

/// /dev/zero inode
struct ZeroDevInode {
    fs_id: u64,
    ino: u64,
}

impl ZeroDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 3 }
    }
}

impl Inode for ZeroDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 5), // major 1, minor 5 = /dev/zero
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/zero returns infinite zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/zero discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /dev/console implementation
// ============================================================================

/// /dev/console inode
struct ConsoleDevInode {
    fs_id: u64,
    ino: u64,
}

impl ConsoleDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 4 }
    }
}

impl Inode for ConsoleDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o620),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(5, 1), // major 5, minor 1 = /dev/console
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Console read: read from keyboard input buffer (non-blocking)
        Ok(drivers::keyboard_read(buf))
    }

    fn read_at_with_commit(
        &self,
        _offset: u64,
        buf: &mut [u8],
        commit: &mut dyn FnMut(&[u8]) -> Result<(), FsError>,
    ) -> Result<usize, FsError> {
        drivers::keyboard_read_with_commit(buf, commit)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Write to console via print
        if let Ok(s) = core::str::from_utf8(data) {
            print!("{}", s);
        } else {
            // Write raw bytes
            for &b in data {
                print!("{}", b as char);
            }
        }
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create device number from major and minor
#[inline]
fn make_dev(major: u32, minor: u32) -> u32 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & 0xFFF00) << 12)
}

// ============================================================================
// Block device implementation
// ============================================================================

/// Block device inode (/dev/vdX, /dev/sdX, etc.)
struct BlockDevInode {
    fs_id: u64,
    ino: u64,
    device: Arc<dyn BlockDevice>,
    /// Lock for serializing read-modify-write operations
    rw_lock: Mutex<()>,
    /// Aggregate charge for the inode Arc and its devfs-owned key. Kept last so
    /// inode state is destroyed before admission is released.
    _heap_charge: HeapCharge,
}

impl BlockDevInode {
    fn new(fs_id: u64, ino: u64, device: Arc<dyn BlockDevice>, heap_charge: HeapCharge) -> Self {
        Self {
            fs_id,
            ino,
            device,
            rw_lock: Mutex::new(()),
            _heap_charge: heap_charge,
        }
    }
}

impl Inode for BlockDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let geometry = self.device.geometry().map_err(|_| FsError::Invalid)?;
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::block_device(0o660),
            nlink: 1,
            uid: 0,
            gid: 6,                                     // disk group
            rdev: make_dev(8, (self.ino - 100) as u32), // major 8 = sd, minor = device index
            size: geometry.capacity_bytes(),
            blksize: geometry.sector_size(),
            blocks: geometry.stat_blocks(),
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let geometry = self.device.geometry().map_err(|_| FsError::Invalid)?;
        let sector_size = u64::from(geometry.sector_size());
        let capacity_bytes = geometry.capacity_bytes();

        // Check bounds and empty buffer
        if offset >= capacity_bytes || buf.is_empty() {
            return Ok(0); // EOF
        }

        let mut file_offset = offset;
        let mut buf_pos = 0usize;
        let mut sector_buf = Vec::new();
        sector_buf
            .try_reserve_exact(sector_size as usize)
            .map_err(|_| FsError::NoMem)?;
        sector_buf.resize(sector_size as usize, 0);
        let limit = (capacity_bytes - offset) as usize;
        let to_read = buf.len().min(limit);

        while buf_pos < to_read && file_offset < capacity_bytes {
            let sector_idx = file_offset / sector_size;
            let sector_off = (file_offset % sector_size) as usize;
            let bytes_until_eof = (capacity_bytes - file_offset) as usize;
            let available = (sector_size as usize - sector_off)
                .min(to_read - buf_pos)
                .min(bytes_until_eof);

            // If sector-aligned and have at least one whole sector, batch the read
            if sector_off == 0
                && available == sector_size as usize
                && (to_read - buf_pos) >= sector_size as usize
            {
                let max_full = (to_read - buf_pos).min(bytes_until_eof);
                let full_len = max_full - (max_full % sector_size as usize);
                if full_len > 0 {
                    let aligned_buf = &mut buf[buf_pos..buf_pos + full_len];
                    self.device
                        .read_sync(sector_idx, aligned_buf)
                        .map_err(|_| FsError::Io)?;
                    buf_pos += full_len;
                    file_offset += full_len as u64;
                    continue;
                }
            }

            // Handle partial sector read
            self.device
                .read_sync(sector_idx, &mut sector_buf)
                .map_err(|_| FsError::Io)?;
            buf[buf_pos..buf_pos + available]
                .copy_from_slice(&sector_buf[sector_off..sector_off + available]);

            buf_pos += available;
            file_offset += available as u64;
        }

        Ok(buf_pos)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let geometry = self.device.geometry().map_err(|_| FsError::Invalid)?;
        let sector_size = u64::from(geometry.sector_size());
        let capacity_bytes = geometry.capacity_bytes();

        // Check bounds
        if offset >= capacity_bytes {
            return Err(FsError::NoSpace);
        }

        let max_write = (capacity_bytes - offset) as usize;
        let to_write = data.len().min(max_write);
        if to_write == 0 {
            return Ok(0);
        }

        // Serialize RMW operations to prevent data corruption
        let _guard = self.rw_lock.lock();
        let mut file_offset = offset;
        let mut data_pos = 0usize;
        let mut sector_buf = Vec::new();
        sector_buf
            .try_reserve_exact(sector_size as usize)
            .map_err(|_| FsError::NoMem)?;
        sector_buf.resize(sector_size as usize, 0);

        while data_pos < to_write && file_offset < capacity_bytes {
            let sector_idx = file_offset / sector_size;
            let sector_off = (file_offset % sector_size) as usize;
            let bytes_until_eof = (capacity_bytes - file_offset) as usize;
            let available = (sector_size as usize - sector_off)
                .min(to_write - data_pos)
                .min(bytes_until_eof);

            // If sector-aligned and have at least one whole sector, batch the write
            if sector_off == 0
                && available == sector_size as usize
                && (to_write - data_pos) >= sector_size as usize
            {
                let max_full = (to_write - data_pos).min(bytes_until_eof);
                let full_len = max_full - (max_full % sector_size as usize);
                if full_len > 0 {
                    let aligned_data = &data[data_pos..data_pos + full_len];
                    self.device
                        .write_sync(sector_idx, aligned_data)
                        .map_err(|_| FsError::Io)?;
                    data_pos += full_len;
                    file_offset += full_len as u64;
                    continue;
                }
            }

            // Handle partial sector with read-modify-write
            self.device
                .read_sync(sector_idx, &mut sector_buf)
                .map_err(|_| FsError::Io)?;

            sector_buf[sector_off..sector_off + available]
                .copy_from_slice(&data[data_pos..data_pos + available]);

            self.device
                .write_sync(sector_idx, &sector_buf)
                .map_err(|_| FsError::Io)?;

            data_pos += available;
            file_offset += available as u64;
        }

        Ok(data_pos)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
pub(crate) mod block_geometry_tests {
    use super::*;
    use block::{Bio, BlockError, BlockGeometry};

    pub(crate) struct GeometryDevice {
        sector_size: u32,
        sectors: u64,
        bytes: Mutex<Vec<u8>>,
        calls: Mutex<Vec<(bool, u64, usize)>>,
        read_only: bool,
    }

    impl GeometryDevice {
        fn new(bytes: Vec<u8>, read_only: bool) -> Self {
            let geometry = BlockGeometry::from_virtio((bytes.len() / 512) as u64, 4096).unwrap();
            Self {
                sector_size: geometry.sector_size(),
                sectors: geometry.capacity_sectors(),
                bytes: Mutex::new(bytes),
                calls: Mutex::new(Vec::new()),
                read_only,
            }
        }
    }

    impl BlockDevice for GeometryDevice {
        fn name(&self) -> &str {
            "geometry-test"
        }
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
        fn capacity_sectors(&self) -> u64 {
            self.sectors
        }
        fn is_read_only(&self) -> bool {
            self.read_only
        }
        fn submit_bio(&self, bio: Bio) -> Result<(), BlockError> {
            bio.complete(Err(BlockError::NotSupported));
            Err(BlockError::NotSupported)
        }
        fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
            // lint-fallible: INFALLIBLE-OK(test fixture recorder; OOM fails the hosted test)
            self.calls.lock().push((false, sector, buf.len()));
            let start = self.geometry()?.request_start(sector, buf.len())? as usize;
            let bytes = self.bytes.lock();
            buf.copy_from_slice(
                bytes
                    .get(start..start + buf.len())
                    .ok_or(BlockError::Invalid)?,
            );
            Ok(buf.len())
        }
        fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
            // lint-fallible: INFALLIBLE-OK(test fixture recorder; OOM fails the hosted test)
            self.calls.lock().push((true, sector, buf.len()));
            if self.read_only {
                return Err(BlockError::ReadOnly);
            }
            let start = self.geometry()?.request_start(sector, buf.len())? as usize;
            self.bytes
                .lock()
                .get_mut(start..start + buf.len())
                .ok_or(BlockError::Invalid)?
                .copy_from_slice(buf);
            Ok(buf.len())
        }
    }

    fn inode(device: Arc<dyn BlockDevice>) -> BlockDevInode {
        let charge = try_reserve_heap(HeapClass::Vfs, 0)
            .unwrap()
            .commit()
            .unwrap();
        BlockDevInode::new(1, 100, device, charge)
    }

    #[test]
    fn block_inode_4k_stat_eof_and_last_sector_round_trip() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let device = Arc::new(GeometryDevice::new(alloc::vec![0; 16 * 4096], false));
        let inode = inode(device.clone());
        let stat = inode.stat().unwrap();
        assert_eq!((stat.size, stat.blksize, stat.blocks), (65536, 4096, 128));
        let mut output = [0u8; 4096];
        assert_eq!(inode.write_at(15 * 4096, &[0x71; 4096]), Ok(4096));
        assert_eq!(inode.read_at(15 * 4096, &mut output), Ok(4096));
        assert_eq!(output, [0x71; 4096]);
        assert_eq!(
            device.calls.lock().as_slice(),
            &[(true, 15, 4096), (false, 15, 4096)]
        );
        assert_eq!(inode.read_at(65536, &mut output), Ok(0));
        assert_eq!(inode.write_at(65536, &[1]), Err(FsError::NoSpace));
        assert_eq!(device.calls.lock().len(), 2);
        assert_eq!(inode.write_at(65535, &[0x33, 0x44]), Ok(1));
        let mut tail = [0xff; 2];
        assert_eq!(inode.read_at(65535, &mut tail), Ok(1));
        assert_eq!(tail, [0x33, 0xff]);
        assert_eq!(device.bytes.lock()[65534], 0x71);
    }

    #[test]
    fn block_inode_rejects_invalid_geometry_before_device_access() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        for (sector_size, sectors) in [(0, 1), (513, 1), (4096, u64::MAX)] {
            let device = Arc::new(GeometryDevice {
                sector_size,
                sectors,
                bytes: Mutex::new(Vec::new()),
                calls: Mutex::new(Vec::new()),
                read_only: false,
            });
            let inode = inode(device.clone());
            assert!(matches!(inode.stat(), Err(FsError::Invalid)));
            assert_eq!(inode.read_at(0, &mut [0; 1]), Err(FsError::Invalid));
            assert_eq!(inode.write_at(0, &[1]), Err(FsError::Invalid));
            assert!(device.calls.lock().is_empty());
        }
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn ext2_geometry_image() -> Vec<u8> {
        use crate::ext2::{Ext2GroupDesc, Ext2InodeRaw, Ext2Superblock};
        use core::mem::offset_of;
        // lint-fallible: BOUNDED(fixed 64 KiB hosted Ext2 fixture; no runtime caller)
        let mut image = alloc::vec![0u8; 16 * 4096];
        for (offset, value) in [
            (offset_of!(Ext2Superblock, inodes_count), 16),
            (offset_of!(Ext2Superblock, blocks_count), 16),
            (offset_of!(Ext2Superblock, free_blocks_count), 10),
            (offset_of!(Ext2Superblock, free_inodes_count), 15),
            (offset_of!(Ext2Superblock, log_block_size), 2),
            (offset_of!(Ext2Superblock, blocks_per_group), 16),
            (offset_of!(Ext2Superblock, frags_per_group), 16),
            (offset_of!(Ext2Superblock, inodes_per_group), 16),
            (offset_of!(Ext2Superblock, rev_level), 1),
            (offset_of!(Ext2Superblock, first_ino), 11),
            (offset_of!(Ext2Superblock, feature_incompat), 2),
            (offset_of!(Ext2Superblock, feature_ro_compat), 1),
        ] {
            put32(&mut image, 1024 + offset, value);
        }
        put16(&mut image, 1024 + offset_of!(Ext2Superblock, magic), 0xef53);
        put16(&mut image, 1024 + offset_of!(Ext2Superblock, state), 1);
        put16(
            &mut image,
            1024 + offset_of!(Ext2Superblock, inode_size),
            128,
        );
        for (offset, value) in [
            (offset_of!(Ext2GroupDesc, block_bitmap), 2),
            (offset_of!(Ext2GroupDesc, inode_bitmap), 3),
            (offset_of!(Ext2GroupDesc, inode_table), 4),
        ] {
            put32(&mut image, 4096 + offset, value);
        }
        put16(
            &mut image,
            4096 + offset_of!(Ext2GroupDesc, free_blocks_count),
            10,
        );
        put16(
            &mut image,
            4096 + offset_of!(Ext2GroupDesc, free_inodes_count),
            15,
        );
        put16(
            &mut image,
            4096 + offset_of!(Ext2GroupDesc, used_dirs_count),
            1,
        );
        image[2 * 4096] = 0x3f; // super/BGDT/bitmaps/inode table/root directory
        image[3 * 4096] = 2; // root inode 2
        let root = 4 * 4096 + 128;
        put16(&mut image, root + offset_of!(Ext2InodeRaw, mode), 0o040755);
        put16(&mut image, root + offset_of!(Ext2InodeRaw, links_count), 2);
        put32(&mut image, root + offset_of!(Ext2InodeRaw, size_lo), 4096);
        put32(&mut image, root + offset_of!(Ext2InodeRaw, blocks_lo), 8);
        put32(&mut image, root + offset_of!(Ext2InodeRaw, block), 5);
        let dir = &mut image[5 * 4096..6 * 4096];
        put32(dir, 0, 2);
        put16(dir, 4, 12);
        dir[6] = 1;
        dir[7] = 2;
        dir[8] = b'.';
        put32(dir, 12, 2);
        put16(dir, 16, 4084);
        dir[18] = 2;
        dir[19] = 2;
        dir[20..22].copy_from_slice(b"..");
        image
    }

    /// Reuse the real 4K Ext2 memory image/device, adding one empty regular file.
    /// Empty read still upgrades Ext2Inode's Weak<Ext2Fs> before checking EOF.
    pub(crate) fn namespace_fixture(
    ) -> (Arc<crate::ext2::Ext2Fs>, alloc::sync::Weak<GeometryDevice>) {
        use crate::ext2::{Ext2GroupDesc, Ext2InodeRaw, Ext2Superblock};
        use core::mem::offset_of;
        let mut image = ext2_geometry_image();
        put32(
            &mut image,
            1024 + offset_of!(Ext2Superblock, free_inodes_count),
            14,
        );
        put16(
            &mut image,
            4096 + offset_of!(Ext2GroupDesc, free_inodes_count),
            14,
        );
        image[3 * 4096] |= 1 << 2; // inode 3
        let file = 4 * 4096 + 2 * 128;
        put16(&mut image, file + offset_of!(Ext2InodeRaw, mode), 0o100644);
        put16(&mut image, file + offset_of!(Ext2InodeRaw, links_count), 1);
        let directory = &mut image[5 * 4096..6 * 4096];
        put16(directory, 16, 12); // shorten '..' to leave the final record
        put32(directory, 24, 3);
        put16(directory, 28, 4096 - 24);
        directory[30] = 4;
        directory[31] = 1;
        directory[32..36].copy_from_slice(b"held");
        let device = Arc::try_new(GeometryDevice::new(image, true)).unwrap();
        let weak = Arc::downgrade(&device);
        let fs = crate::ext2::Ext2Fs::mount(device).unwrap();
        (fs, weak)
    }

    impl GeometryDevice {
        pub(crate) fn read_count(&self) -> usize {
            self.calls
                .lock()
                .iter()
                .filter(|(write, _, _)| !write)
                .count()
        }
    }

    #[test]
    fn ext2_4k_mount_reads_superblock_and_rejects_oversized_geometry() {
        use crate::ext2::{Ext2Fs, Ext2Superblock};
        use core::mem::offset_of;
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let image = ext2_geometry_image();
        // lint-fallible: INFALLIBLE-OK(single hosted fixture device; OOM fails the test)
        let device = Arc::new(GeometryDevice::new(image, true));
        let fs = Ext2Fs::mount(device.clone()).expect("valid 4K ext2 geometry");
        assert_eq!(fs.root_inode().readdir(0).unwrap().unwrap().1.name, ".");
        assert_eq!(
            &device.calls.lock()[..2],
            &[(false, 0, 4096), (false, 1, 4096)]
        );
        drop(fs);
        device.calls.lock().clear();
        put32(
            &mut device.bytes.lock(),
            1024 + offset_of!(Ext2Superblock, blocks_count),
            17,
        );
        assert!(matches!(
            Ext2Fs::mount(device.clone()),
            Err(FsError::Invalid)
        ));
        assert_eq!(device.calls.lock().as_slice(), &[(false, 0, 4096)]);
    }
}
