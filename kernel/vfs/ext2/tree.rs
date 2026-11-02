//! Bounded traversal and typed edits of the classic Ext2 block tree.
//! Each attach/detach changes one edge, one bitmap bit and the matching counts.
//! Empty mapping chains are valid durable intermediate states, including at EOF.

use super::*;

pub(super) const ATTACH: u8 = 15;
pub(super) const DETACH: u8 = 16;
pub(super) const DIR_GROW: u8 = 17;
pub(super) const RENAME: u8 = 18;
pub(super) const INTENT_END: usize = ZERO_INTENT_END + 1;

pub(super) fn is_kind(kind: u8) -> bool {
    matches!(kind, ATTACH | DETACH | DIR_GROW)
}

#[derive(Clone, Copy, Default, Debug)]
pub(super) struct BlockPath {
    pub root: usize,
    pub depth: u8,
    pub indices: [usize; 3],
}

#[derive(Clone, Copy, Default, Debug)]
pub(super) struct TreeEdge {
    pub logical: u32,
    /// Zero for data, one through three for mapping blocks.
    pub level: u8,
    pub root: usize,
    /// None means that the edge is an inode root word.
    pub parent: Option<(u32, usize)>,
    pub physical: u32,
}

#[derive(Clone, Copy)]
pub(super) struct TreePlan<'a> {
    pub block: &'a DirectAllocationPlan,
    pub edge: TreeEdge,
    pub kind: u8,
}

impl TreePlan<'_> {
    pub fn metadata_blocks(&self) -> usize {
        if self.edge.parent.is_some() {
            5
        } else {
            4
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Frame {
    edge: TreeEdge,
    next: i32,
}

/// Fixed-depth DFS. Returning an edge never retains a borrowed block buffer.
/// The cursor survives metadata commits, so reclamation does not restart scans.
pub(super) struct TreeCursor {
    frames: [Frame; 3],
    depth: usize,
    root: i32,
    reverse: bool,
    first: u64,
    end: u64,
    nodes: usize,
    cached: Option<u32>,
}

impl TreeCursor {
    pub fn new(first: u64, end: u64, reverse: bool) -> Self {
        Self {
            frames: [Frame::default(); 3],
            depth: 0,
            root: if reverse { 14 } else { 0 },
            reverse,
            first,
            end,
            nodes: 0,
            cached: None,
        }
    }

    /// Mutators borrow the traversal scratch for journal/data I/O between events.
    pub fn invalidate_buffer(&mut self) {
        self.cached = None;
    }

    fn intersects(&self, edge: TreeEdge, pointers: u64) -> bool {
        let start = u64::from(edge.logical);
        start < self.end && start + pointers.pow(u32::from(edge.level)) > self.first
    }

    /// `true` means an exiting mapping node; data leaves have a single event.
    pub fn next(
        &mut self,
        fs: &Ext2Fs,
        raw: &Ext2InodeRaw,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<Option<(TreeEdge, bool)>, FsError> {
        let pointers = u64::from(fs.block_size / 4);
        let step = if self.reverse { -1 } else { 1 };
        loop {
            let edge = if self.depth == 0 {
                if !(0..15).contains(&self.root) {
                    return Ok(None);
                }
                let root = self.root as usize;
                self.root += step;
                let (base, level) = fs.tree_root_geometry(root)?;
                TreeEdge {
                    logical: u32::try_from(base).map_err(|_| FsError::NotSupported)?,
                    level,
                    root,
                    parent: None,
                    physical: raw.block[root],
                }
            } else {
                let frame = &mut self.frames[self.depth - 1];
                if frame.next < 0 || frame.next >= pointers as i32 {
                    let edge = frame.edge;
                    self.depth -= 1;
                    return Ok(Some((edge, true)));
                }
                if self.cached != Some(frame.edge.physical) {
                    fs.read_block(frame.edge.physical, scratch.block_mut())?;
                    self.cached = Some(frame.edge.physical);
                }
                let mut child = None;
                while frame.next >= 0 && frame.next < pointers as i32 {
                    let index = frame.next as usize;
                    frame.next += step;
                    let physical = read_u32_le(scratch.block(), index)?;
                    if physical == 0 {
                        continue;
                    }
                    let base = u64::from(frame.edge.logical)
                        + (index as u64) * pointers.pow(u32::from(frame.edge.level - 1));
                    if base > u64::from(u32::MAX) {
                        return Err(FsError::NotSupported);
                    }
                    child = Some(TreeEdge {
                        logical: base as u32,
                        level: frame.edge.level - 1,
                        root: frame.edge.root,
                        parent: Some((frame.edge.physical, index)),
                        physical,
                    });
                    break;
                }
                let Some(child) = child else {
                    continue;
                };
                child
            };
            if edge.physical == 0 || !self.intersects(edge, pointers) {
                continue;
            }
            fs.validate_block(edge.physical)?.ok_or(FsError::Invalid)?;
            if edge.level != 0 {
                self.nodes = self.nodes.checked_add(1).ok_or(FsError::Invalid)?;
                if self.nodes > MAX_OWNERSHIP_MAPPING_BYTES / fs.block_size as usize {
                    return Err(FsError::NotSupported);
                }
                if self.depth == self.frames.len() {
                    return Err(FsError::Invalid);
                }
                self.frames[self.depth] = Frame {
                    edge,
                    next: if self.reverse { pointers as i32 - 1 } else { 0 },
                };
                self.depth += 1;
            }
            return Ok(Some((edge, false)));
        }
    }
}

impl Ext2Fs {
    /// Writers and recovery must admit the same live parent shape. Reject
    /// malformed directories before publishing an intent recovery would refuse.
    pub(super) fn check_directory_shape(&self, raw: &Ext2InodeRaw) -> Result<(), FsError> {
        if raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR
            || raw.links_count < 2
            || raw.dtime != 0
            || raw.size_lo == 0
            || raw.size_lo % self.block_size != 0
            || raw.size_high_or_dir_acl != 0
        {
            return Err(FsError::NotSupported);
        }
        Ok(())
    }

    pub(super) fn validate_legacy_create_contents(
        &self,
        intent: &JournalCommitIntent,
        overlay: &[JournalOverlayEntry],
        pre: &[u8],
        post: &[u8],
        home: u32,
    ) -> Result<(), FsError> {
        let parent = &intent.old_inode;
        if self.check_directory_shape(parent).is_err()
            || parent.size_lo / self.block_size > 12
            || parent.flags & (EXT2_IMMUTABLE_FL | EXT2_INDEX_FL | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL)
                != 0
            || intent.new_ino == intent.parent_ino
        {
            return Err(FsError::Invalid);
        }
        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        let target = self.inode_write_target(intent.parent_ino)?;
        self.read_tree_block(overlay, post, target.block, &mut scratch)?;
        // SAFETY: the target validates the complete integer-only inode slice.
        let new: Ext2InodeRaw =
            unsafe { core::ptr::read_unaligned(scratch.block()[target.start..].as_ptr().cast()) };
        let mut expected = *parent;
        expected.mtime = new.mtime;
        expected.ctime = new.mtime;
        if Self::inode_bytes(&expected) != Self::inode_bytes(&new) {
            return Err(FsError::Invalid);
        }
        let target = self.inode_write_target(intent.new_ino)?;
        self.read_tree_block(overlay, post, target.block, &mut scratch)?;
        // SAFETY: inode_write_target checked the slot within this block.
        let child: Ext2InodeRaw =
            unsafe { core::ptr::read_unaligned(scratch.block()[target.start..].as_ptr().cast()) };
        if child.mode & EXT2_S_IFMT != EXT2_S_IFREG {
            return Err(FsError::Invalid);
        }
        let creator = self.superblock.read().creator_os;
        let (uid, gid) = child.owner_ids(creator);
        if parent.mode & 0o2000 != 0 && gid != parent.owner_ids(creator).1 {
            return Err(FsError::Invalid);
        }
        let mut expected = Ext2InodeRaw::default();
        expected.mode = child.mode;
        expected.set_owner_ids(creator, uid, gid)?;
        expected.links_count = 1;
        expected.atime = new.mtime;
        expected.mtime = new.mtime;
        expected.ctime = new.mtime;
        if Self::inode_bytes(&expected) != Self::inode_bytes(&child)
            || scratch.block()
                [target.start + size_of::<Ext2InodeRaw>()..target.start + self.inode_size as usize]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(FsError::Invalid);
        }
        self.read_tree_block(overlay, post, home, &mut scratch)?;
        let mut name = [0u8; 255];
        let mut name_len = 0;
        let mut source_offset = 0;
        let mut off = 0;
        while off < scratch.block().len() {
            let bytes = scratch.block();
            let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
            let len = usize::from(u16::from_le_bytes([head[4], head[5]]));
            let n = usize::from(head[6]);
            if len < 8 || len % 4 != 0 || off + len > bytes.len() || n + 8 > len {
                return Err(FsError::Invalid);
            }
            if read_u32_le(head, 0)? == intent.new_ino {
                if name_len != 0
                    || n == 0
                    || head[7] != self.disk_dirent_type(EXT2_FT_REG_FILE)
                    || off + len != bytes.len()
                    || bytes[off + 8 + n..off + len].iter().any(|b| *b != 0)
                {
                    return Err(FsError::Invalid);
                }
                name_len = n;
                name[..n].copy_from_slice(&bytes[off + 8..off + 8 + n]);
                source_offset = off;
            }
            off += len;
        }
        let name = &name[..name_len];
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.iter().any(|b| *b == 0 || *b == b'/')
        {
            return Err(FsError::Invalid);
        }
        for (images, expected_count) in [(pre, 0), (post, 1)] {
            let mut count = 0;
            for logical in 0..parent.size_lo / self.block_size {
                let physical = self
                    .map_tree_block(parent, logical, overlay, images, &mut scratch)?
                    .ok_or(FsError::Invalid)?;
                self.read_tree_block(overlay, images, physical, &mut scratch)?;
                let bytes = scratch.block();
                let mut off = 0;
                while off < bytes.len() {
                    let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
                    let len = usize::from(u16::from_le_bytes([head[4], head[5]]));
                    let end = off + 8 + usize::from(head[6]);
                    if len < 8 || len % 4 != 0 || off + len > bytes.len() || end > off + len {
                        return Err(FsError::Invalid);
                    }
                    let ino = read_u32_le(head, 0)?;
                    if ino != 0 && (bytes[off + 8..end] == *name || ino == intent.new_ino) {
                        if ino != intent.new_ino
                            || physical != home
                            || off != source_offset
                            || bytes[off + 8..end] != *name
                        {
                            return Err(FsError::Invalid);
                        }
                        count += 1;
                    }
                    off += len;
                }
            }
            if count != expected_count {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }

    pub(super) fn validate_rename_contents(
        &self,
        intent: &JournalCommitIntent,
        overlay: &[JournalOverlayEntry],
        pre: &[u8],
        post: &[u8],
        home: u32,
    ) -> Result<(), FsError> {
        let parent = &intent.old_inode;
        if self.check_directory_shape(parent).is_err()
            || parent.size_lo / self.block_size > MAX_OWNERSHIP_REFERENCES as u32
            || parent.flags
                & (EXT2_IMMUTABLE_FL
                    | EXT2_APPEND_FL
                    | EXT2_INDEX_FL
                    | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL)
                != 0
        {
            return Err(FsError::Invalid);
        }
        let mut scratch = Ext2MutationScratch::try_new(self.block_size)?;
        self.read_tree_block(overlay, post, home, &mut scratch)?;
        let offset = intent.rename_dir_off as usize;
        let length = usize::from(intent.rename_rec_len);
        let slot = scratch
            .block()
            .get(offset..offset + length)
            .ok_or(FsError::Invalid)?;
        let source = read_u32_le(slot, 0)?;
        let count = usize::from(slot[6]);
        let old_name = &intent.rename_old_name[..usize::from(intent.rename_old_name_len)];
        let valid_name = |name: &[u8]| {
            !name.is_empty()
                && name != b"."
                && name != b".."
                && !name.iter().any(|byte| *byte == 0 || *byte == b'/')
        };
        if source == 0
            || length % 4 != 0
            || slot[4..6] != intent.rename_rec_len.to_le_bytes()
            || count + 8 > length
            || !valid_name(old_name)
            || intent.rename_old_name[old_name.len()..]
                .iter()
                .any(|b| *b != 0)
            || slot[count + 8..if intent.kind == RENAME {
                (8 + count).max(8 + old_name.len())
            } else {
                length
            }]
                .iter()
                .any(|b| *b != 0)
            || !valid_name(&slot[8..8 + count])
            || slot[8..8 + count] == *old_name
            || (slot[7] != 0 && slot[7] != self.disk_dirent_type(EXT2_FT_REG_FILE))
        {
            return Err(FsError::Invalid);
        }
        let mut new_name = [0u8; 255];
        new_name[..count].copy_from_slice(&slot[8..8 + count]);
        let new_name = &new_name[..count];
        let target = self.inode_write_target(source)?;
        self.read_tree_block(overlay, pre, target.block, &mut scratch)?;
        // SAFETY: inode_write_target bounds this integer-only inode within the block.
        let source_raw: Ext2InodeRaw = unsafe {
            core::ptr::read_unaligned(
                scratch.block()[target.start..]
                    .as_ptr()
                    .cast::<Ext2InodeRaw>(),
            )
        };
        if source_raw.mode & EXT2_S_IFMT != EXT2_S_IFREG
            || source_raw.links_count == 0
            || source_raw.flags & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL) != 0
        {
            return Err(FsError::Invalid);
        }
        for (images, expected) in [(pre, (1, 0)), (post, (0, 1))] {
            let mut found = (0, 0);
            for logical in 0..parent.size_lo / self.block_size {
                let physical = self
                    .map_tree_block(parent, logical, overlay, images, &mut scratch)?
                    .ok_or(FsError::Invalid)?;
                self.read_tree_block(overlay, images, physical, &mut scratch)?;
                let bytes = scratch.block();
                let mut off = 0;
                while off < bytes.len() {
                    let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
                    let len = usize::from(u16::from_le_bytes([head[4], head[5]]));
                    let name_end = off + 8 + usize::from(head[6]);
                    if len < 8 || len % 4 != 0 || off + len > bytes.len() || name_end > off + len {
                        return Err(FsError::Invalid);
                    }
                    let ino = read_u32_le(head, 0)?;
                    if ino != 0 {
                        let name = &bytes[off + 8..name_end];
                        if name == old_name || name == new_name {
                            if ino != source || physical != home || off != offset {
                                return Err(FsError::Invalid);
                            }
                            found.0 += usize::from(name == old_name);
                            found.1 += usize::from(name == new_name);
                        }
                    }
                    off += len;
                }
            }
            if found != expected {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }

    pub(super) fn validate_tree_transition(
        &self,
        intent: &JournalCommitIntent,
        new: &Ext2InodeRaw,
    ) -> Result<(), FsError> {
        let old = &intent.old_inode;
        let path = self.block_path(intent.file_block)?;
        let level = intent.tree_level;
        if level > path.depth || intent.physical == 0 {
            return Err(FsError::Invalid);
        }
        let kind = old.mode & EXT2_S_IFMT;
        let freeing = intent.kind == DETACH;
        let directory = kind == EXT2_S_IFDIR;
        if !matches!(kind, EXT2_S_IFREG | EXT2_S_IFDIR | EXT2_S_IFLNK)
            || (kind == EXT2_S_IFLNK && old.links_count != 0)
            || (freeing && directory && old.links_count != 0)
            || old.flags & (EXT2_IMMUTABLE_FL | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL) != 0
            || (freeing && old.flags & EXT2_APPEND_FL != 0)
            || (directory && (old.flags & EXT2_INDEX_FL != 0 || old.size_high_or_dir_acl != 0))
            || (old.links_count != 0 && old.dtime != 0)
            || new.mtime != new.ctime
        {
            return Err(FsError::NotSupported);
        }
        let old_size = u64::from(old.size_lo) | (u64::from(old.size_high_or_dir_acl) << 32);
        let new_size = u64::from(new.size_lo) | (u64::from(new.size_high_or_dir_acl) << 32);
        self.check_tree_size(new, new_size)?;
        let start = u64::from(intent.file_block) * u64::from(self.block_size);
        if intent.kind == DIR_GROW {
            if self.check_directory_shape(old).is_err()
                || level != 0
                || self.block_size > u16::MAX as u32
                || old_size == 0
                || old_size % u64::from(self.block_size) != 0
                || start != old_size
                || new_size != old_size + u64::from(self.block_size)
            {
                return Err(FsError::Invalid);
            }
        } else if freeing {
            if new_size > old_size || (level == 0 && new_size > start) {
                return Err(FsError::Invalid);
            }
        } else if (level != 0 && new_size != old_size)
            || (level == 0 && (new_size < old_size || new_size <= start || directory))
        {
            return Err(FsError::Invalid);
        }
        let mut expected = *old;
        expected.mtime = new.mtime;
        expected.ctime = new.ctime;
        expected.size_lo = new.size_lo;
        expected.size_high_or_dir_acl = new.size_high_or_dir_acl;
        let sectors = self.block_size / 512;
        expected.blocks_lo = if freeing {
            old.blocks_lo.checked_sub(sectors)
        } else {
            old.blocks_lo.checked_add(sectors)
        }
        .ok_or(FsError::Invalid)?;
        if level == path.depth {
            if old.block[path.root] != if freeing { intent.physical } else { 0 } {
                return Err(FsError::Invalid);
            }
            expected.block[path.root] = if freeing { 0 } else { intent.physical };
        }
        if Self::inode_bytes(&expected) != Self::inode_bytes(new) {
            return Err(FsError::Invalid);
        }
        Ok(())
    }

    pub(super) fn tree_metadata_plan<'a>(
        &self,
        block: &'a DirectAllocationPlan,
        edge: TreeEdge,
        kind: u8,
        journal: &Ext2Journal,
    ) -> Result<TreePlan<'a>, FsError> {
        let plan = TreePlan { block, edge, kind };
        let homes = plan.metadata_blocks();
        if journal.max_len - journal.first < (homes + 2) as u32 {
            return Err(FsError::NoSpace);
        }
        if let Some((parent, index)) = edge.parent {
            if index >= (self.block_size / 4) as usize
                || parent == block.phys_block
                || self.is_structural_metadata_block(parent)?
                || journal.contains_physical(parent)
            {
                return Err(FsError::Invalid);
            }
        }
        Ok(plan)
    }

    /// The caller holds inode/raw -> metadata -> journal locks. Every mapping
    /// block is fully initialized before attaching it; published size stays put.
    #[inline(never)]
    pub(super) fn ensure_tree_path(
        &self,
        inode: &Ext2Inode,
        raw: &mut Ext2InodeRaw,
        logical: u32,
        journal: &mut Ext2Journal,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let path = self.block_path(logical)?;
        let target = self.inode_write_target(inode.ino)?;
        let p = u64::from(self.block_size / 4);
        for level in (1..=path.depth).rev() {
            let (root_base, _) = self.tree_root_geometry(path.root)?;
            let span = p.pow(u32::from(level));
            let base = root_base + (u64::from(logical) - root_base) / span * span;
            let edge = self.tree_edge(raw, base as u32, level, &[], &[], scratch)?;
            if edge.physical != 0 {
                continue;
            }
            let mut next = *raw;
            next.mtime = TimeSpec::now().sec as u32;
            next.ctime = next.mtime;
            let block = self.plan_direct_allocation(
                inode.ino,
                raw,
                next,
                base as u32,
                edge.parent.is_none().then_some(edge.root),
                target,
                journal,
                scratch,
            )?;
            let plan = self.tree_metadata_plan(&block, edge, ATTACH, journal)?;
            let metadata = if path.depth == 1 && raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR {
                JournalMetadataPlan::IndirectRootAllocation(&block)
            } else {
                JournalMetadataPlan::Tree(&plan)
            };
            scratch.block_mut().fill(0);
            self.write_block(block.phys_block, scratch.block())?;
            self.flush_device()?;
            let result = self.commit_metadata_transaction(journal, metadata, scratch);
            self.publish_tree_step(raw, &block, result)?;
        }
        Ok(())
    }

    pub(super) fn publish_tree_step(
        &self,
        raw: &mut Ext2InodeRaw,
        plan: &DirectAllocationPlan,
        result: Result<(), JournalTxFailure>,
    ) -> Result<(), FsError> {
        if let Err(failure) = result {
            if failure.poison {
                self.io_faulted.store(true, Ordering::Release);
            }
            if !failure.committed {
                return Err(failure.error);
            }
        }
        self.superblock.write().free_blocks_count = plan.new_super_free_blocks;
        self.group_descs.write()[plan.group] = plan.new_group_desc;
        *raw = plan.new_inode;
        result.map_err(|failure| failure.error)
    }

    #[inline(never)]
    pub(super) fn grow_directory(
        &self,
        parent: &Ext2Inode,
        raw: &mut Ext2InodeRaw,
        journal: &mut Ext2Journal,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        self.check_directory_shape(raw)?;
        if raw.flags & (EXT2_INDEX_FL | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL) != 0
            || self.block_size > u16::MAX as u32
        {
            return Err(FsError::NotSupported);
        }
        let size = raw
            .size_lo
            .checked_add(self.block_size)
            .ok_or(FsError::NoSpace)?;
        self.check_tree_size(raw, u64::from(size))?;
        let logical = raw.size_lo / self.block_size;
        self.ensure_tree_path(parent, raw, logical, journal, scratch)?;
        let edge = self.tree_edge(raw, logical, 0, &[], &[], scratch)?;
        if edge.physical != 0 {
            return Err(FsError::Invalid);
        }
        let mut next = *raw;
        next.size_lo = size;
        next.mtime = TimeSpec::now().sec as u32;
        next.ctime = next.mtime;
        let block = self.plan_direct_allocation(
            parent.ino,
            raw,
            next,
            logical,
            edge.parent.is_none().then_some(edge.root),
            self.inode_write_target(parent.ino)?,
            journal,
            scratch,
        )?;
        let plan = self.tree_metadata_plan(&block, edge, DIR_GROW, journal)?;
        scratch.block_mut().fill(0);
        scratch.block_mut()[4..6].copy_from_slice(&(self.block_size as u16).to_le_bytes());
        self.write_block(block.phys_block, scratch.block())?;
        self.flush_device()?;
        let result =
            self.commit_metadata_transaction(journal, JournalMetadataPlan::Tree(&plan), scratch);
        let result = self.publish_tree_step(raw, &block, result);
        parent.size.store(u64::from(raw.size_lo), Ordering::Release);
        result
    }

    pub(super) fn tree_root_geometry(&self, root: usize) -> Result<(u64, u8), FsError> {
        let p = u64::from(self.block_size / 4);
        Ok(match root {
            0..=11 => (root as u64, 0),
            12 => (12, 1),
            13 => (12 + p, 2),
            14 => (12 + p + p * p, 3),
            _ => return Err(FsError::Invalid),
        })
    }

    pub(super) fn tree_block_limit(&self) -> u64 {
        let p = u64::from(self.block_size / 4);
        // The VFS block mapper uses u32 logical indices. Larger geometries are
        // capped explicitly instead of wrapping a triple-indirect index.
        (12 + p + p * p + p * p * p).min(u64::from(u32::MAX) + 1)
    }

    pub(super) fn check_tree_size(&self, raw: &Ext2InodeRaw, size: u64) -> Result<(), FsError> {
        if size > self.tree_block_limit() * u64::from(self.block_size)
            || (raw.mode & EXT2_S_IFMT != EXT2_S_IFREG && size > u64::from(u32::MAX))
            || (raw.mode & EXT2_S_IFMT == EXT2_S_IFREG
                && size > i32::MAX as u64
                && self.superblock.read().feature_ro_compat & EXT2_FEATURE_RO_COMPAT_LARGE_FILE
                    == 0)
        {
            return Err(FsError::NotSupported);
        }
        Ok(())
    }

    pub(super) fn block_path(&self, logical: u32) -> Result<BlockPath, FsError> {
        let p = u64::from(self.block_size / 4);
        let logical = u64::from(logical);
        if logical >= self.tree_block_limit() {
            return Err(FsError::NotSupported);
        }
        if logical < 12 {
            return Ok(BlockPath {
                root: logical as usize,
                ..BlockPath::default()
            });
        }
        for root in 12..=14 {
            let (base, depth) = self.tree_root_geometry(root)?;
            if logical >= base + p.pow(u32::from(depth)) {
                continue;
            }
            let mut remaining = logical - base;
            let mut path = BlockPath {
                root,
                depth,
                indices: [0; 3],
            };
            for level in 0..usize::from(depth) {
                let span = p.pow(u32::from(depth) - 1 - level as u32);
                path.indices[level] = (remaining / span) as usize;
                remaining %= span;
            }
            return Ok(path);
        }
        Err(FsError::NotSupported)
    }

    /// Read metadata from the candidate image when present, including mapping
    /// ancestors. This is also usable before journal admission with empty slices.
    pub(super) fn read_tree_block(
        &self,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        physical: u32,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        self.validate_block(physical)?.ok_or(FsError::Invalid)?;
        if let Some(entry) = overlay.iter().find(|entry| entry.home == physical) {
            scratch
                .block_mut()
                .copy_from_slice(self.frozen_overlay_image(images, *entry)?);
            Ok(())
        } else {
            self.read_block(physical, scratch.block_mut())
        }
    }

    pub(super) fn map_tree_block(
        &self,
        raw: &Ext2InodeRaw,
        logical: u32,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<Option<u32>, FsError> {
        let path = self.block_path(logical)?;
        let mut physical = raw.block[path.root];
        for &index in &path.indices[..usize::from(path.depth)] {
            if physical == 0 {
                return Ok(None);
            }
            self.read_tree_block(overlay, images, physical, scratch)?;
            physical = read_u32_le(scratch.block(), index)?;
        }
        self.validate_block(physical)
    }

    /// Derive the edited edge from the inode and canonical logical subtree base;
    /// an untrusted physical address in an intent is never used as a path proof.
    pub(super) fn tree_edge(
        &self,
        raw: &Ext2InodeRaw,
        logical: u32,
        level: u8,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<TreeEdge, FsError> {
        let path = self.block_path(logical)?;
        if level > path.depth {
            return Err(FsError::Invalid);
        }
        let hops = usize::from(path.depth - level);
        if path.indices[hops..usize::from(path.depth)]
            .iter()
            .any(|i| *i != 0)
        {
            return Err(FsError::Invalid);
        }
        let mut edge = TreeEdge {
            logical,
            level,
            root: path.root,
            parent: None,
            physical: raw.block[path.root],
        };
        for &index in &path.indices[..hops] {
            if edge.physical == 0 {
                return Err(FsError::Invalid);
            }
            self.read_tree_block(overlay, images, edge.physical, scratch)?;
            edge.parent = Some((edge.physical, index));
            edge.physical = read_u32_le(scratch.block(), index)?;
        }
        Ok(edge)
    }
}
