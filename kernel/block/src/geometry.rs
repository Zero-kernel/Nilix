//! Checked logical-sector geometry. Virtio uses 512-byte units only on the wire.

use crate::BlockError;

pub const VIRTIO_SECTOR_BYTES: u64 = 512;
pub const MAX_LOGICAL_SECTOR_BYTES: u32 = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockGeometry {
    sector_size: u32,
    capacity_bytes: u64,
}

impl BlockGeometry {
    pub fn from_logical(sector_size: u32, sectors: u64) -> Result<Self, BlockError> {
        if !(512..=MAX_LOGICAL_SECTOR_BYTES).contains(&sector_size)
            || !sector_size.is_power_of_two()
        {
            return Err(BlockError::Invalid);
        }
        let capacity_bytes = sectors
            .checked_mul(u64::from(sector_size))
            .ok_or(BlockError::Invalid)?;
        Ok(Self {
            sector_size,
            capacity_bytes,
        })
    }

    /// Decode virtio's fixed-unit capacity without exposing those units to callers.
    pub fn from_virtio(sectors_512: u64, sector_size: u32) -> Result<Self, BlockError> {
        let empty = Self::from_logical(sector_size, 0)?;
        let capacity_bytes = sectors_512
            .checked_mul(VIRTIO_SECTOR_BYTES)
            .ok_or(BlockError::Invalid)?;
        if capacity_bytes % u64::from(sector_size) != 0 {
            return Err(BlockError::Invalid);
        }
        Ok(Self {
            capacity_bytes,
            ..empty
        })
    }

    pub fn sector_size(self) -> u32 {
        self.sector_size
    }

    pub fn capacity_sectors(self) -> u64 {
        self.capacity_bytes / u64::from(self.sector_size)
    }

    pub fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }

    /// Linux stat blocks always count 512-byte units, including on 4K devices.
    pub fn stat_blocks(self) -> u64 {
        self.capacity_bytes / VIRTIO_SECTOR_BYTES
    }

    /// Validate a nonempty whole-sector transfer and return its byte offset.
    pub fn request_start(self, logical_sector: u64, len: usize) -> Result<u64, BlockError> {
        let len = u64::try_from(len).map_err(|_| BlockError::Invalid)?;
        if len == 0 || len % u64::from(self.sector_size) != 0 {
            return Err(BlockError::Invalid);
        }
        let start = logical_sector
            .checked_mul(u64::from(self.sector_size))
            .ok_or(BlockError::Invalid)?;
        let end = start.checked_add(len).ok_or(BlockError::Invalid)?;
        if end > self.capacity_bytes {
            return Err(BlockError::Invalid);
        }
        Ok(start)
    }

    /// The only logical-LBA to virtio wire-sector conversion.
    pub fn virtio_header_sector(self, logical_sector: u64, len: usize) -> Result<u64, BlockError> {
        self.request_start(logical_sector, len)
            .map(|start| start / VIRTIO_SECTOR_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_capacity_preserves_bytes_for_512_and_4k() {
        let small = BlockGeometry::from_virtio(128, 512).unwrap();
        let large = BlockGeometry::from_virtio(128, 4096).unwrap();
        assert_eq!(small.capacity_bytes(), 65536);
        assert_eq!(large.capacity_bytes(), small.capacity_bytes());
        assert_eq!(small.capacity_sectors(), 128);
        assert_eq!(large.capacity_sectors(), 16);
        assert_eq!(large.stat_blocks(), 128);
        assert_ne!(
            small, large,
            "reset must reject a changed logical sector size"
        );
    }

    #[test]
    fn last_logical_sector_and_header_conversion_are_exact() {
        for size in [512, 4096] {
            let geometry = BlockGeometry::from_virtio(128, size).unwrap();
            let last = geometry.capacity_sectors() - 1;
            assert_eq!(geometry.virtio_header_sector(0, size as usize), Ok(0));
            assert_eq!(
                geometry.virtio_header_sector(1, size as usize),
                Ok(u64::from(size) / 512)
            );
            assert_eq!(
                geometry.virtio_header_sector(last, size as usize),
                Ok(128 - u64::from(size) / 512)
            );
            assert_eq!(
                geometry.request_start(last + 1, size as usize),
                Err(BlockError::Invalid)
            );
            assert_eq!(
                geometry.request_start(last, 2 * size as usize),
                Err(BlockError::Invalid)
            );
        }
    }

    #[test]
    fn malformed_geometry_and_transfer_sizes_fail_closed() {
        for size in [0, 1, 256, 513, 3072, 131072, u32::MAX] {
            assert_eq!(
                BlockGeometry::from_virtio(128, size),
                Err(BlockError::Invalid)
            );
        }
        assert_eq!(
            BlockGeometry::from_virtio(9, 4096),
            Err(BlockError::Invalid)
        );
        assert_eq!(
            BlockGeometry::from_virtio(u64::MAX, 512),
            Err(BlockError::Invalid)
        );
        assert_eq!(
            BlockGeometry::from_logical(4096, u64::MAX),
            Err(BlockError::Invalid)
        );
        let geometry = BlockGeometry::from_virtio(128, 4096).unwrap();
        for (sector, len) in [(0, 0), (0, 512), (u64::MAX, 4096)] {
            assert_eq!(
                geometry.request_start(sector, len),
                Err(BlockError::Invalid)
            );
        }
        let empty = BlockGeometry::from_virtio(0, 4096).unwrap();
        assert_eq!(empty.capacity_bytes(), 0);
        assert_eq!(empty.request_start(0, 4096), Err(BlockError::Invalid));
    }
}
