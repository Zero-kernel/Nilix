//! Journaled namespace edits and durable orphan reclamation.
//!
//! Namespace changes never free storage while a live inode can still use it.
//! Every namespace intent has an exact, reversible set of metadata edits; the
//! existing digest, checkpoint and whole-filesystem ownership proofs still apply.

use super::*;
use core::mem::size_of_val;

pub(super) const UNLINK: u8 = 11;
pub(super) const INODE_FREE: u8 = 12;
pub(super) const ORPHAN_ALLOC: u8 = 13;
pub(super) const PUBLISH: u8 = 14;
const CHILD_OFFSET: usize = ZERO_INTENT_FILE_RENAME_END;
const HEAD_OFFSET: usize = CHILD_OFFSET + size_of::<Ext2InodeRaw>();
const PREDECESSOR_OFFSET: usize = HEAD_OFFSET + 4;
const PREVIOUS_OFFSET: usize = PREDECESSOR_OFFSET + 4;
const PREVIOUS_LENGTH_OFFSET: usize = PREVIOUS_OFFSET + 4;
const TYPE_OFFSET: usize = PREVIOUS_LENGTH_OFFSET + 2;
const TAIL_OFFSET: usize = TYPE_OFFSET + 1;
pub(super) const INTENT_END: usize = TAIL_OFFSET + 128;
const MAX_ORPHANS: usize = 1024;
const NO_PREVIOUS: u32 = u32::MAX;
const _: () = assert!(INTENT_END <= 1024);

pub(super) fn is_kind(kind: u8) -> bool {
    matches!(kind, UNLINK | INODE_FREE | ORPHAN_ALLOC | PUBLISH)
}

#[derive(Clone, Copy)]
pub(super) struct NamespaceExtra {
    pub old_child: Ext2InodeRaw,
    pub old_head: u32,
    pub predecessor: u32,
    pub previous_offset: u32,
    pub previous_length: u16,
    pub file_type: u8,
    pub old_tail: [u8; 128],
}

impl Default for NamespaceExtra {
    fn default() -> Self {
        Self {
            old_child: Ext2InodeRaw::default(),
            old_head: 0,
            predecessor: 0,
            previous_offset: 0,
            previous_length: 0,
            file_type: 0,
            old_tail: [0; 128],
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct NamespacePlan {
    pub intent: JournalCommitIntent,
    new_child: Ext2InodeRaw,
    new_parent: Ext2InodeRaw,
    old_group_free: u16,
    old_used_dirs: u16,
    old_super_free: u32,
    homes: [u32; JOURNAL_MAX_METADATA_BLOCKS],
}

fn inode_from(bytes: &[u8], offset: usize) -> Result<Ext2InodeRaw, FsError> {
    let end = offset
        .checked_add(size_of::<Ext2InodeRaw>())
        .ok_or(FsError::Invalid)?;
    let bytes = bytes.get(offset..end).ok_or(FsError::Invalid)?;
    // SAFETY: the checked slice contains exactly the integer-only on-disk inode;
    // read_unaligned does not require Vec<u8> to have the inode's alignment.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Ext2InodeRaw>()) })
}

fn change(
    bytes: &mut [u8],
    offset: usize,
    before: &[u8],
    after: &[u8],
    forward: bool,
) -> Result<(), FsError> {
    if before.len() != after.len() {
        return Err(FsError::Invalid);
    }
    let end = offset.checked_add(before.len()).ok_or(FsError::Invalid)?;
    let slot = bytes.get_mut(offset..end).ok_or(FsError::Invalid)?;
    let (expected, replacement) = if forward {
        (before, after)
    } else {
        (after, before)
    };
    if slot != expected {
        return Err(FsError::Invalid);
    }
    slot.copy_from_slice(replacement);
    Ok(())
}

pub(super) fn decode_extra(bytes: &[u8]) -> Result<NamespaceExtra, FsError> {
    if bytes.len() < INTENT_END || bytes[INTENT_END..].iter().any(|b| *b != 0) {
        return Err(FsError::Invalid);
    }
    Ok(NamespaceExtra {
        old_child: inode_from(bytes, CHILD_OFFSET)?,
        old_head: read_be_u32(bytes, HEAD_OFFSET)?,
        predecessor: read_be_u32(bytes, PREDECESSOR_OFFSET)?,
        previous_offset: read_be_u32(bytes, PREVIOUS_OFFSET)?,
        previous_length: read_be_u16(bytes, PREVIOUS_LENGTH_OFFSET)?,
        file_type: bytes[TYPE_OFFSET],
        old_tail: bytes[TAIL_OFFSET..INTENT_END]
            .try_into()
            .map_err(|_| FsError::Invalid)?,
    })
}

pub(super) fn encode_extra(bytes: &mut [u8], intent: &JournalCommitIntent) -> Result<(), FsError> {
    if bytes.len() < INTENT_END {
        return Err(FsError::Invalid);
    }
    let extra = intent.namespace;
    bytes[CHILD_OFFSET..HEAD_OFFSET].copy_from_slice(Ext2Fs::inode_bytes(&extra.old_child));
    write_be_u32(bytes, HEAD_OFFSET, extra.old_head)?;
    write_be_u32(bytes, PREDECESSOR_OFFSET, extra.predecessor)?;
    write_be_u32(bytes, PREVIOUS_OFFSET, extra.previous_offset)?;
    write_be_u16(bytes, PREVIOUS_LENGTH_OFFSET, extra.previous_length)?;
    bytes[TYPE_OFFSET] = extra.file_type;
    bytes[TAIL_OFFSET..INTENT_END].copy_from_slice(&extra.old_tail);
    bytes[INTENT_END..].fill(0);
    Ok(())
}

impl NamespacePlan {
    fn new(intent: JournalCommitIntent, new_child: Ext2InodeRaw, new_parent: Ext2InodeRaw) -> Self {
        Self {
            intent,
            new_child,
            new_parent,
            old_group_free: 0,
            old_used_dirs: 0,
            old_super_free: 0,
            homes: [0; JOURNAL_MAX_METADATA_BLOCKS],
        }
    }

    fn inode_delta(&self) -> i32 {
        match self.intent.kind {
            INODE_FREE => 1,
            ORPHAN_ALLOC => -1,
            _ => 0,
        }
    }

    fn directory_delta(&self) -> i32 {
        let raw = if self.intent.kind == ORPHAN_ALLOC {
            self.new_child
        } else {
            self.intent.namespace.old_child
        };
        if raw.mode & EXT2_S_IFMT == EXT2_S_IFDIR {
            -self.inode_delta()
        } else {
            0
        }
    }

    fn new_head(&self) -> u32 {
        let extra = self.intent.namespace;
        match self.intent.kind {
            ORPHAN_ALLOC => self.intent.new_ino,
            UNLINK if self.new_child.links_count == 0 => self.intent.new_ino,
            INODE_FREE | PUBLISH if extra.predecessor == 0 => extra.old_child.dtime,
            _ => extra.old_head,
        }
    }

    fn calculate_homes(&mut self, fs: &Ext2Fs) -> Result<(), FsError> {
        let mut count = 0usize;
        let mut add = |home: u32| -> Result<(), FsError> {
            if self.homes[..count].contains(&home) {
                return Ok(());
            }
            *self.homes.get_mut(count).ok_or(FsError::NotSupported)? = home;
            count += 1;
            Ok(())
        };
        let i = &self.intent;
        if matches!(i.kind, INODE_FREE | ORPHAN_ALLOC) {
            let group = fs.inode_group_index(i.new_ino).ok_or(FsError::Invalid)?.0;
            add(fs
                .group_descs
                .read()
                .get(group)
                .ok_or(FsError::Invalid)?
                .inode_bitmap)?;
            add(fs.group_desc_write_target(group)?.block)?;
        }
        add(fs.superblock_home_target().0)?;
        add(fs.inode_write_target(i.new_ino)?.block)?;
        if i.parent_ino != 0 {
            add(fs.inode_write_target(i.parent_ino)?.block)?;
        }
        if i.physical != 0 {
            add(i.physical)?;
        }
        if i.namespace.predecessor != 0 {
            add(fs.inode_write_target(i.namespace.predecessor)?.block)?;
        }
        self.intent.metadata_count = u8::try_from(count).map_err(|_| FsError::Invalid)?;
        Ok(())
    }

    pub(super) fn home(&self, index: usize) -> Result<u32, FsError> {
        if index >= usize::from(self.intent.metadata_count) {
            return Err(FsError::Invalid);
        }
        self.homes.get(index).copied().ok_or(FsError::Invalid)
    }

    fn validate(&self, fs: &Ext2Fs) -> Result<(), FsError> {
        let i = &self.intent;
        let x = &i.namespace;
        let sb = fs.superblock.read();
        if !is_kind(i.kind)
            || i.file_block != u32::MAX
            || i.new_ino < sb.first_ino
            || i.new_ino > sb.inodes_count
            || i.new_ino == sb.journal_inum
            || i.new_ino == i.parent_ino
            || i.parent_ino > sb.inodes_count
            || i.parent_ino == sb.journal_inum
            || x.old_head > sb.inodes_count
            || x.predecessor == i.new_ino
            || x.predecessor > sb.inodes_count
            || i.inode_number
                != if i.parent_ino == 0 {
                    i.new_ino
                } else {
                    i.parent_ino
                }
            || i.rename_old_name[usize::from(i.rename_old_name_len)..]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(FsError::Invalid);
        }
        drop(sb);
        let tail_len = fs.namespace_tail_len()?;
        if x.old_tail[tail_len..].iter().any(|b| *b != 0)
            || (!matches!(i.kind, ORPHAN_ALLOC | INODE_FREE) && x.old_tail.iter().any(|b| *b != 0))
        {
            return Err(FsError::Invalid);
        }
        let zero = Ext2InodeRaw::default();
        if matches!(i.kind, ORPHAN_ALLOC | INODE_FREE) {
            if i.parent_ino != 0
                || i.physical != 0
                || i.rename_dir_off != 0
                || i.rename_rec_len != 0
                || i.rename_old_name_len != 0
                || x.previous_offset != 0
                || x.previous_length != 0
                || x.file_type != 0
                || Ext2Fs::inode_bytes(&i.old_inode) != Ext2Fs::inode_bytes(&zero)
            {
                return Err(FsError::Invalid);
            }
            if i.kind == ORPHAN_ALLOC {
                if x.predecessor != 0 {
                    return Err(FsError::Invalid);
                }
                fs.check_reclaim_layout(&self.new_child)?;
                let n = &self.new_child;
                let mut expected = zero;
                expected.mode = n.mode;
                let (uid, gid) = n.owner_ids(fs.superblock.read().creator_os);
                expected.set_owner_ids(fs.superblock.read().creator_os, uid, gid)?;
                expected.dtime = x.old_head;
                expected.atime = n.atime;
                expected.mtime = n.atime;
                expected.ctime = n.atime;
                if n.mode & EXT2_S_IFMT == EXT2_S_IFLNK {
                    if n.size_lo as usize >= size_of_val(&n.block) {
                        return Err(FsError::Invalid);
                    }
                    expected.size_lo = n.size_lo;
                    expected.block = n.block;
                    let data = inline_bytes(n);
                    if data[..n.size_lo as usize].contains(&0)
                        || data[n.size_lo as usize..].iter().any(|b| *b != 0)
                    {
                        return Err(FsError::Invalid);
                    }
                }
                if Ext2Fs::inode_bytes(&expected) != Ext2Fs::inode_bytes(n) {
                    return Err(FsError::Invalid);
                }
            } else {
                fs.check_reclaim_layout(&x.old_child)?;
                let inline = is_inline(&x.old_child);
                if x.old_child.links_count != 0
                    || x.old_child.blocks_lo != 0
                    || (!inline
                        && (x.old_child.size_lo != 0 || x.old_child.block.iter().any(|b| *b != 0)))
                    || (x.predecessor == 0 && x.old_head != i.new_ino)
                    || Ext2Fs::inode_bytes(&self.new_child) != Ext2Fs::inode_bytes(&zero)
                {
                    return Err(FsError::Invalid);
                }
            }
            return Ok(());
        }
        fs.check_reclaim_layout(&x.old_child)?;
        if i.parent_ino == 0
            || i.physical == 0
            || x.predecessor != 0
            || i.old_inode.mode & EXT2_S_IFMT != EXT2_S_IFDIR
            || i.old_inode.links_count < 2
            || i.old_inode.flags
                & (EXT2_IMMUTABLE_FL
                    | EXT2_UNSUPPORTED_WRITE_LAYOUT_FL
                    | if i.kind == UNLINK { EXT2_APPEND_FL } else { 0 })
                != 0
            || x.old_child.flags & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL) != 0
            || !i.old_inode.block[..EXT2_NDIR_BLOCKS].contains(&i.physical)
            || fs.is_structural_metadata_block(i.physical)?
            || i.rename_old_name_len == 0
        {
            return Err(FsError::Invalid);
        }
        let name = &i.rename_old_name[..usize::from(i.rename_old_name_len)];
        if name == b"." || name == b".." || name.iter().any(|b| *b == 0 || *b == b'/') {
            return Err(FsError::Invalid);
        }
        let dir = x.old_child.mode & EXT2_S_IFMT == EXT2_S_IFDIR;
        let expected_type = fs.disk_dirent_type(match x.old_child.mode & EXT2_S_IFMT {
            EXT2_S_IFREG => EXT2_FT_REG_FILE,
            EXT2_S_IFDIR => EXT2_FT_DIR,
            EXT2_S_IFLNK => EXT2_FT_SYMLINK,
            _ => return Err(FsError::Invalid),
        });
        if x.file_type != expected_type && !(i.kind == UNLINK && x.file_type == 0) {
            return Err(FsError::Invalid);
        }
        let mut child = x.old_child;
        let mut parent = i.old_inode;
        if i.kind == UNLINK {
            if child.links_count == 0 || child.dtime != 0 || (dir && child.links_count != 2) {
                return Err(FsError::Invalid);
            }
            child.links_count = if dir { 0 } else { child.links_count - 1 };
            child.dtime = if child.links_count == 0 {
                x.old_head
            } else {
                0
            };
            if dir {
                parent.links_count = parent.links_count.checked_sub(1).ok_or(FsError::Invalid)?;
            }
        } else {
            if child.links_count != 0 || x.old_head != i.new_ino {
                return Err(FsError::Invalid);
            }
            child.links_count = if dir { 2 } else { 1 };
            child.dtime = 0;
            if dir {
                if child.size_lo != fs.block_size
                    || child.blocks_lo != fs.block_size / 512
                    || child.block[0] == 0
                    || child.block[1..].iter().any(|b| *b != 0)
                {
                    return Err(FsError::Invalid);
                }
                parent.links_count = parent.links_count.checked_add(1).ok_or(FsError::NoSpace)?;
            }
        }
        child.ctime = self.new_child.ctime;
        parent.mtime = self.new_parent.mtime;
        parent.ctime = parent.mtime;
        if child.ctime != parent.ctime
            || Ext2Fs::inode_bytes(&child) != Ext2Fs::inode_bytes(&self.new_child)
            || Ext2Fs::inode_bytes(&parent) != Ext2Fs::inode_bytes(&self.new_parent)
        {
            return Err(FsError::Invalid);
        }
        let off = i.rename_dir_off as usize;
        let len = usize::from(i.rename_rec_len);
        if off % 4 != 0
            || len % 4 != 0
            || len < 8 + name.len()
            || off
                .checked_add(len)
                .is_none_or(|end| end > fs.block_size as usize)
        {
            return Err(FsError::Invalid);
        }
        if x.previous_offset == NO_PREVIOUS {
            if x.previous_length != 0 {
                return Err(FsError::Invalid);
            }
        } else {
            let previous = x.previous_offset as usize;
            let previous_len = usize::from(x.previous_length);
            if previous % 4 != 0
                || previous_len < 8
                || previous_len % 4 != 0
                || previous >= off
                || (i.kind == UNLINK && previous.checked_add(previous_len) != Some(off))
                || (i.kind == PUBLISH && previous.checked_add(previous_len) != off.checked_add(len))
            {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }

    fn rewrite(
        &self,
        fs: &Ext2Fs,
        home: u32,
        bytes: &mut [u8],
        forward: bool,
    ) -> Result<(), FsError> {
        let i = &self.intent;
        let x = i.namespace;
        let directory_home = matches!(i.kind, UNLINK | PUBLISH) && home == i.physical;
        if directory_home {
            validate_dir_edit(self, bytes, !forward)?;
        }
        let target = fs.inode_write_target(i.new_ino)?;
        if home == target.block {
            change(
                bytes,
                target.start,
                Ext2Fs::inode_bytes(&x.old_child),
                Ext2Fs::inode_bytes(&self.new_child),
                forward,
            )?;
        }
        if matches!(i.kind, INODE_FREE | ORPHAN_ALLOC) && home == target.block {
            let tail_len = fs.namespace_tail_len()?;
            change(
                bytes,
                target.start + size_of::<Ext2InodeRaw>(),
                &x.old_tail[..tail_len],
                &[0; 128][..tail_len],
                forward,
            )?;
        }
        if i.parent_ino != 0 {
            let target = fs.inode_write_target(i.parent_ino)?;
            if home == target.block {
                change(
                    bytes,
                    target.start,
                    Ext2Fs::inode_bytes(&i.old_inode),
                    Ext2Fs::inode_bytes(&self.new_parent),
                    forward,
                )?;
            }
        }
        if x.predecessor != 0 {
            let target = fs.inode_write_target(x.predecessor)?;
            if home == target.block {
                change(
                    bytes,
                    target.start + core::mem::offset_of!(Ext2InodeRaw, dtime),
                    &i.new_ino.to_le_bytes(),
                    &x.old_child.dtime.to_le_bytes(),
                    forward,
                )?;
            }
        }
        let (super_home, super_offset) = fs.superblock_home_target();
        let delta = self.inode_delta();
        if home == super_home {
            change(
                bytes,
                super_offset + core::mem::offset_of!(Ext2Superblock, last_orphan),
                &x.old_head.to_le_bytes(),
                &self.new_head().to_le_bytes(),
                forward,
            )?;
            if delta != 0 {
                change(
                    bytes,
                    super_offset + core::mem::offset_of!(Ext2Superblock, free_inodes_count),
                    &self.old_super_free.to_le_bytes(),
                    &adjust(self.old_super_free, delta)?.to_le_bytes(),
                    forward,
                )?;
            }
        }
        if delta != 0 {
            let (group, index) = fs.inode_group_index(i.new_ino).ok_or(FsError::Invalid)?;
            let bitmap = fs
                .group_descs
                .read()
                .get(group)
                .ok_or(FsError::Invalid)?
                .inode_bitmap;
            if home == bitmap {
                let byte = bytes.get_mut(index / 8).ok_or(FsError::Invalid)?;
                let mask = 1u8 << (index % 8);
                if (*byte & mask != 0) != (forward == (delta > 0)) {
                    return Err(FsError::Invalid);
                }
                *byte ^= mask;
            }
            let target = fs.group_desc_write_target(group)?;
            if home == target.block {
                change(
                    bytes,
                    target.offset + core::mem::offset_of!(Ext2GroupDesc, free_inodes_count),
                    &self.old_group_free.to_le_bytes(),
                    &adjust16(self.old_group_free, delta)?.to_le_bytes(),
                    forward,
                )?;
                change(
                    bytes,
                    target.offset + core::mem::offset_of!(Ext2GroupDesc, used_dirs_count),
                    &self.old_used_dirs.to_le_bytes(),
                    &adjust16(self.old_used_dirs, self.directory_delta())?.to_le_bytes(),
                    forward,
                )?;
            }
        }
        if matches!(i.kind, UNLINK | PUBLISH) && home == i.physical {
            let off = i.rename_dir_off as usize;
            let mut present = [0u8; 263];
            let len = 8 + usize::from(i.rename_old_name_len);
            present[..4].copy_from_slice(&i.new_ino.to_le_bytes());
            present[4..6].copy_from_slice(&i.rename_rec_len.to_le_bytes());
            present[6] = i.rename_old_name_len;
            present[7] = x.file_type;
            present[8..len].copy_from_slice(&i.rename_old_name[..len - 8]);
            let mut empty = [0u8; 263];
            if x.previous_offset == NO_PREVIOUS {
                empty[4..6].copy_from_slice(&i.rename_rec_len.to_le_bytes());
            }
            change(
                bytes,
                off,
                &present[..len],
                &empty[..len],
                forward == (i.kind == UNLINK),
            )?;
            if x.previous_offset != NO_PREVIOUS {
                let next = if i.kind == UNLINK {
                    x.previous_length.checked_add(i.rename_rec_len)
                } else {
                    u16::try_from(i.rename_dir_off - x.previous_offset).ok()
                }
                .ok_or(FsError::Invalid)?;
                change(
                    bytes,
                    x.previous_offset as usize + 4,
                    &x.previous_length.to_le_bytes(),
                    &next.to_le_bytes(),
                    forward,
                )?;
            }
        }
        if directory_home {
            validate_dir_edit(self, bytes, forward)?;
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        fs: &Ext2Fs,
        journal: &Ext2Journal,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if matches!(self.intent.kind, INODE_FREE | ORPHAN_ALLOC) {
            let target = fs.inode_write_target(self.intent.new_ino)?;
            fs.read_physical_block(target.block, scratch.block_mut())?;
            let len = fs.namespace_tail_len()?;
            self.intent.namespace.old_tail[..len].copy_from_slice(
                &scratch.block()[target.start + size_of::<Ext2InodeRaw>()
                    ..target.start + size_of::<Ext2InodeRaw>() + len],
            );
        }
        self.validate(fs)?;
        self.calculate_homes(fs)?;
        if self.inode_delta() != 0 {
            let group = fs
                .inode_group_index(self.intent.new_ino)
                .ok_or(FsError::Invalid)?
                .0;
            let desc = fs.group_descs.read()[group];
            self.old_group_free = desc.free_inodes_count;
            self.old_used_dirs = desc.used_dirs_count;
            self.old_super_free = fs.superblock.read().free_inodes_count;
        }
        if journal
            .first
            .checked_add(u32::from(self.intent.metadata_count) + 2)
            .is_none_or(|end| end > journal.max_len)
        {
            return Err(FsError::NotSupported);
        }
        for index in 0..usize::from(self.intent.metadata_count) {
            let home = self.home(index)?;
            if journal.contains_physical(home) {
                return Err(FsError::Invalid);
            }
            fs.read_physical_block(home, scratch.block_mut())?;
            self.intent.preimage_hashes[index] = Sha256::digest(scratch.block());
            self.rewrite(fs, home, scratch.block_mut(), true)?;
        }
        Ok(())
    }

    fn publish_counts(&self, fs: &Ext2Fs) -> Result<(), FsError> {
        let mut sb = fs.superblock.write();
        sb.last_orphan = self.new_head();
        if self.inode_delta() != 0 {
            let group = fs
                .inode_group_index(self.intent.new_ino)
                .ok_or(FsError::Invalid)?
                .0;
            sb.free_inodes_count = adjust(self.old_super_free, self.inode_delta())?;
            let mut descs = fs.group_descs.write();
            descs[group].free_inodes_count = adjust16(self.old_group_free, self.inode_delta())?;
            descs[group].used_dirs_count = adjust16(self.old_used_dirs, self.directory_delta())?;
        }
        Ok(())
    }

    pub(super) fn build(
        &self,
        fs: &Ext2Fs,
        index: usize,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<u32, FsError> {
        let home = self.home(index)?;
        fs.read_physical_block(home, scratch.block_mut())?;
        if Sha256::digest(scratch.block()) != self.intent.preimage_hashes[index] {
            return Err(FsError::Invalid);
        }
        self.rewrite(fs, home, scratch.block_mut(), true)?;
        Ok(home)
    }
}

fn validate_dir_edit(plan: &NamespacePlan, bytes: &[u8], post: bool) -> Result<(), FsError> {
    let i = &plan.intent;
    let x = &i.namespace;
    let present = post == (i.kind == PUBLISH);
    let mut offset = 0usize;
    let mut previous = NO_PREVIOUS;
    let mut previous_length = 0u16;
    let mut matched = false;
    while offset < bytes.len() {
        let head = bytes.get(offset..offset + 8).ok_or(FsError::Invalid)?;
        let ino = u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
        let length = u16::from_le_bytes(head[4..6].try_into().map_err(|_| FsError::Invalid)?);
        let name_end = offset
            .checked_add(8 + usize::from(head[6]))
            .ok_or(FsError::Invalid)?;
        let end = offset
            .checked_add(usize::from(length))
            .ok_or(FsError::Invalid)?;
        if length < 8 || length % 4 != 0 || end > bytes.len() || name_end > end {
            return Err(FsError::Invalid);
        }
        if present && offset == i.rename_dir_off as usize {
            if ino != i.new_ino
                || length != i.rename_rec_len
                || head[6] != i.rename_old_name_len
                || head[7] != x.file_type
                || &bytes[offset + 8..name_end]
                    != &i.rename_old_name[..usize::from(i.rename_old_name_len)]
            {
                return Err(FsError::Invalid);
            }
            if i.kind == UNLINK
                && (previous != x.previous_offset || previous_length != x.previous_length)
            {
                return Err(FsError::Invalid);
            }
            matched = true;
        } else if !present
            && x.previous_offset == NO_PREVIOUS
            && offset == i.rename_dir_off as usize
        {
            if ino != 0 || head[6] != 0 || length != i.rename_rec_len {
                return Err(FsError::Invalid);
            }
            matched = true;
        } else if !present && offset == x.previous_offset as usize {
            let minimum = (8 + usize::from(head[6]) + 3) & !3;
            if offset + minimum > i.rename_dir_off as usize
                || end != i.rename_dir_off as usize + usize::from(i.rename_rec_len)
            {
                return Err(FsError::Invalid);
            }
            matched = true;
        } else if ino != 0
            && &bytes[offset + 8..name_end]
                == &i.rename_old_name[..usize::from(i.rename_old_name_len)]
        {
            return Err(FsError::Invalid);
        }
        previous = offset as u32;
        previous_length = length;
        offset = end;
    }
    if !matched {
        return Err(FsError::Invalid);
    }
    Ok(())
}

fn adjust(value: u32, delta: i32) -> Result<u32, FsError> {
    u32::try_from(i64::from(value) + i64::from(delta)).map_err(|_| FsError::Invalid)
}

fn adjust16(value: u16, delta: i32) -> Result<u16, FsError> {
    u16::try_from(i32::from(value) + delta).map_err(|_| FsError::Invalid)
}

fn is_inline(raw: &Ext2InodeRaw) -> bool {
    raw.mode & EXT2_S_IFMT == EXT2_S_IFLNK
        && raw.blocks_lo == 0
        && (raw.size_lo as usize) < size_of_val(&raw.block)
}

fn inline_bytes(raw: &Ext2InodeRaw) -> &[u8] {
    // SAFETY: [u32; 15] is a contiguous initialized 60-byte integer array.
    unsafe { core::slice::from_raw_parts(raw.block.as_ptr().cast::<u8>(), size_of_val(&raw.block)) }
}

impl Ext2Fs {
    fn namespace_tail_len(&self) -> Result<usize, FsError> {
        usize::from(self.inode_size)
            .checked_sub(size_of::<Ext2InodeRaw>())
            .filter(|len| *len <= 128)
            .ok_or(FsError::NotSupported)
    }

    fn check_reclaim_layout(&self, raw: &Ext2InodeRaw) -> Result<(), FsError> {
        if raw.mode & EXT2_S_IFMT == EXT2_S_IFLNK && raw.size_lo >= self.block_size {
            return Err(FsError::Invalid);
        }

        if !matches!(
            raw.mode & EXT2_S_IFMT,
            EXT2_S_IFREG | EXT2_S_IFDIR | EXT2_S_IFLNK
        ) || raw.file_acl != 0
            || raw.faddr != 0
            || raw.flags & EXT2_UNSUPPORTED_WRITE_LAYOUT_FL != 0
        {
            return Err(FsError::NotSupported);
        }
        let inline = raw.mode & EXT2_S_IFMT == EXT2_S_IFLNK
            && raw.blocks_lo == 0
            && (raw.size_lo as usize) < size_of_val(&raw.block);
        if !inline
            && (raw.block[EXT2_DIND_BLOCK..].iter().any(|b| *b != 0)
                || ((raw.size_high_or_dir_acl as u64) << 32 | raw.size_lo as u64)
                    > self.single_indirect_block_limit() * self.block_size as u64)
        {
            return Err(FsError::NotSupported);
        }
        Ok(())
    }

    pub(super) fn validate_namespace_grammar(
        &self,
        intent: &JournalCommitIntent,
        overlay: &[JournalOverlayEntry],
        post_images: &[u8],
    ) -> Result<Vec<u8>, FsError> {
        let inode_image = |ino| -> Result<Ext2InodeRaw, FsError> {
            let target = self.inode_write_target(ino)?;
            let entry = overlay
                .iter()
                .find(|entry| entry.home == target.block)
                .ok_or(FsError::Invalid)?;
            inode_from(
                self.frozen_overlay_image(post_images, *entry)?,
                target.start,
            )
        };
        let child = inode_image(intent.new_ino)?;
        let parent = if intent.parent_ino == 0 {
            Ext2InodeRaw::default()
        } else {
            inode_image(intent.parent_ino)?
        };
        let mut plan = NamespacePlan::new(*intent, child, parent);
        plan.validate(self)?;
        plan.calculate_homes(self)?;
        if plan.intent.metadata_count != intent.metadata_count {
            return Err(FsError::Invalid);
        }
        if plan.inode_delta() != 0 {
            let group = self
                .inode_group_index(intent.new_ino)
                .ok_or(FsError::Invalid)?
                .0;
            let target = self.group_desc_write_target(group)?;
            let entry = overlay
                .iter()
                .find(|entry| entry.home == target.block)
                .ok_or(FsError::Invalid)?;
            let bytes = self.frozen_overlay_image(post_images, *entry)?;
            let read16 = |offset| -> Result<u16, FsError> {
                Ok(u16::from_le_bytes(
                    bytes
                        .get(offset..offset + 2)
                        .ok_or(FsError::Invalid)?
                        .try_into()
                        .map_err(|_| FsError::Invalid)?,
                ))
            };
            plan.old_group_free = adjust16(
                read16(target.offset + core::mem::offset_of!(Ext2GroupDesc, free_inodes_count))?,
                -plan.inode_delta(),
            )?;
            plan.old_used_dirs = adjust16(
                read16(target.offset + core::mem::offset_of!(Ext2GroupDesc, used_dirs_count))?,
                -plan.directory_delta(),
            )?;
            let (home, offset) = self.superblock_home_target();
            let entry = overlay
                .iter()
                .find(|entry| entry.home == home)
                .ok_or(FsError::Invalid)?;
            let bytes = self.frozen_overlay_image(post_images, *entry)?;
            plan.old_super_free = adjust(
                read_u32_le(
                    bytes.get(offset..).ok_or(FsError::Invalid)?,
                    core::mem::offset_of!(Ext2Superblock, free_inodes_count) / 4,
                )?,
                -plan.inode_delta(),
            )?;
        }
        let mut pre = Vec::new();
        pre.try_reserve_exact(post_images.len())
            .map_err(|_| FsError::NoMem)?;
        pre.extend_from_slice(post_images);
        for entry in overlay {
            let order = entry.order as usize;
            if plan.home(order)? != entry.home {
                return Err(FsError::Invalid);
            }
            let image = pre
                .get_mut(entry.image_offset..entry.image_offset + self.block_size as usize)
                .ok_or(FsError::Invalid)?;
            plan.rewrite(self, entry.home, image, false)?;
            if Sha256::digest(image) != intent.preimage_hashes[order] {
                return Err(FsError::Invalid);
            }
        }
        Ok(pre)
    }
}

#[derive(Clone, Copy)]
struct DirectorySlot {
    home: u32,
    offset: u32,
    previous: u32,
    previous_length: u16,
    inode: u32,
    length: u16,
    file_type: u8,
}

fn valid_name(name: &str) -> Result<(), FsError> {
    if name.len() > 255 {
        return Err(FsError::NameTooLong);
    }
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().iter().any(|b| *b == 0 || *b == b'/')
    {
        return Err(FsError::Invalid);
    }
    Ok(())
}

impl Ext2Fs {
    /// Old directory records have a 16-bit name length and no type byte.
    pub(super) fn disk_dirent_type(&self, kind: u8) -> u8 {
        if self.superblock.read().feature_incompat & EXT2_FEATURE_INCOMPAT_FILETYPE != 0 {
            kind
        } else {
            0
        }
    }

    fn walk_namespace_directory<F>(
        &self,
        raw: &Ext2InodeRaw,
        scratch: &mut Ext2MutationScratch,
        mut visit: F,
    ) -> Result<(), FsError>
    where
        F: FnMut(DirectorySlot, &[u8]) -> Result<(), FsError>,
    {
        if raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR {
            return Err(FsError::NotDir);
        }
        let blocks = u64::from(raw.size_lo) / u64::from(self.block_size);
        if raw.size_high_or_dir_acl != 0
            || raw.size_lo == 0
            || raw.size_lo % self.block_size != 0
            || blocks > EXT2_NDIR_BLOCKS as u64
            || raw.block[EXT2_NDIR_BLOCKS..].iter().any(|b| *b != 0)
        {
            return Err(FsError::NotSupported);
        }
        for index in 0..blocks as usize {
            let home = self
                .validate_block(raw.block[index])?
                .ok_or(FsError::Invalid)?;
            if self.is_structural_metadata_block(home)? {
                return Err(FsError::Invalid);
            }
            self.read_block(home, scratch.block_mut())?;
            let bytes = scratch.block();
            let mut offset = 0usize;
            let mut previous = NO_PREVIOUS;
            let mut previous_length = 0u16;
            while offset < bytes.len() {
                let head = bytes.get(offset..offset + 8).ok_or(FsError::Invalid)?;
                let inode = u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
                let length =
                    u16::from_le_bytes(head[4..6].try_into().map_err(|_| FsError::Invalid)?);
                let end = offset
                    .checked_add(usize::from(length))
                    .ok_or(FsError::Invalid)?;
                let name_end = offset
                    .checked_add(8 + usize::from(head[6]))
                    .ok_or(FsError::Invalid)?;
                if length < 8
                    || length % 4 != 0
                    || end > bytes.len()
                    || name_end > end
                    || inode > self.superblock.read().inodes_count
                {
                    return Err(FsError::Invalid);
                }
                visit(
                    DirectorySlot {
                        home,
                        offset: offset as u32,
                        previous,
                        previous_length,
                        inode,
                        length,
                        file_type: head[7],
                    },
                    &bytes[offset + 8..name_end],
                )?;
                previous = offset as u32;
                previous_length = length;
                offset = end;
            }
        }
        Ok(())
    }

    fn find_namespace_entry(
        &self,
        raw: &Ext2InodeRaw,
        name: &str,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<DirectorySlot, FsError> {
        let mut found = None;
        self.walk_namespace_directory(raw, scratch, |slot, bytes| {
            if slot.inode != 0 && bytes == name.as_bytes() {
                if found.is_some() {
                    return Err(FsError::Invalid);
                }
                found = Some(slot);
            }
            Ok(())
        })?;
        found.ok_or(FsError::NotFound)
    }

    fn require_empty_directory(
        &self,
        ino: u32,
        parent: u32,
        raw: &Ext2InodeRaw,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let mut dot = false;
        let mut dotdot = false;
        self.walk_namespace_directory(raw, scratch, |slot, name| {
            if slot.inode == 0 {
                return Ok(());
            }
            if name == b"." && slot.inode == ino && !dot {
                dot = true;
            } else if name == b".." && slot.inode == parent && !dotdot {
                dotdot = true;
            } else {
                return Err(FsError::NotEmpty);
            }
            Ok(())
        })?;
        if !dot || !dotdot {
            return Err(FsError::Invalid);
        }
        Ok(())
    }

    pub(super) fn read_orphan_chain(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<mm::AdmittedVec<u32>, FsError> {
        let sb = self.read_virtual_superblock(journal, overlay, images, scratch)?;
        let mut chain = mm::AdmittedVec::new(HeapClass::FilesystemIo);
        let mut ino = sb.last_orphan;
        while ino != 0 {
            if chain.len() == MAX_ORPHANS
                || chain.as_slice().contains(&ino)
                || ino < sb.first_ino
                || ino > sb.inodes_count
                || ino == sb.journal_inum
            {
                return Err(FsError::Invalid);
            }
            let (group, index) = self.inode_group_index(ino).ok_or(FsError::Invalid)?;
            let bitmap = self
                .group_descs
                .read()
                .get(group)
                .ok_or(FsError::Invalid)?
                .inode_bitmap;
            self.read_virtual_block(journal, overlay, images, bitmap, scratch)?;
            if scratch
                .block()
                .get(index / 8)
                .copied()
                .ok_or(FsError::Invalid)?
                & (1u8 << (index % 8))
                == 0
            {
                return Err(FsError::Invalid);
            }
            let target = self.inode_write_target(ino)?;
            self.read_virtual_block(journal, overlay, images, target.block, scratch)?;
            let raw = inode_from(scratch.block(), target.start)?;
            if raw.links_count != 0 {
                return Err(FsError::Invalid);
            }
            self.check_reclaim_layout(&raw)?;
            chain.try_push(ino).map_err(|_| FsError::NoMem)?;
            ino = raw.dtime;
        }
        chain.as_mut_slice().sort_unstable();
        Ok(chain)
    }

    /// Link counts are untrusted disk input. Before removing a name, prove
    /// that the count represents every live directory reference; otherwise a
    /// corrupt low count could free an inode still reachable by another name.
    fn validate_namespace_link_count(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        target: u32,
        expected: u16,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        let sb = self.read_virtual_superblock(journal, overlay, images, scratch)?;
        if sb.inodes_count > MAX_OWNERSHIP_INODES {
            return Err(FsError::NotSupported);
        }
        let mut bitmap = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        let mut table = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        let mut references = 0u32;
        let mut last_table = None;
        for group in 0..self.group_descs.read().len() {
            let desc = self.group_descs.read()[group];
            self.read_virtual_block(journal, overlay, images, desc.inode_bitmap, &mut bitmap)?;
            let first = (group as u32)
                .checked_mul(self.inodes_per_group)
                .ok_or(FsError::Invalid)?;
            let count = self
                .inodes_per_group
                .min(sb.inodes_count.saturating_sub(first));
            for local in 0..count {
                if bitmap.block()[local as usize / 8] & (1 << (local % 8)) == 0 {
                    continue;
                }
                let ino = first + local + 1;
                let location = self.inode_write_target(ino)?;
                if last_table != Some(location.block) {
                    self.read_virtual_block(journal, overlay, images, location.block, &mut table)?;
                    last_table = Some(location.block);
                }
                let raw = inode_from(table.block(), location.start)?;
                if raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR || raw.links_count == 0 {
                    continue;
                }
                if raw.size_lo % self.block_size != 0 || raw.size_high_or_dir_acl != 0 {
                    return Err(FsError::Invalid);
                }
                let blocks = raw.size_lo / self.block_size;
                if blocks > MAX_OWNERSHIP_REFERENCES as u32 {
                    return Err(FsError::NotSupported);
                }
                for index in 0..blocks {
                    let physical = self
                        .map_file_block_with_scratch(&raw, index, scratch)?
                        .ok_or(FsError::Invalid)?;
                    self.read_virtual_block(journal, overlay, images, physical, scratch)?;
                    let bytes = scratch.block();
                    let mut off = 0;
                    while off < bytes.len() {
                        let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
                        let child =
                            u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
                        let len = usize::from(u16::from_le_bytes(
                            head[4..6].try_into().map_err(|_| FsError::Invalid)?,
                        ));
                        if len < 8
                            || len % 4 != 0
                            || off.checked_add(len).is_none_or(|end| end > bytes.len())
                            || usize::from(head[6]) + 8 > len
                            || (self.disk_dirent_type(EXT2_FT_DIR) == 0 && head[7] != 0)
                        {
                            return Err(FsError::Invalid);
                        }
                        if child == target {
                            references = references.checked_add(1).ok_or(FsError::Invalid)?;
                        }
                        off += len;
                    }
                }
            }
        }
        if references != u32::from(expected) {
            return Err(FsError::Invalid);
        }
        Ok(())
    }

    pub(super) fn validate_orphan_directory_references(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        images: &[u8],
        ino: u32,
        raw: &Ext2InodeRaw,
        orphans: &[u32],
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR {
            return Ok(());
        }
        let is_orphan = orphans.binary_search(&ino).is_ok();
        let inode_count = self
            .read_virtual_superblock(journal, overlay, images, scratch)?
            .inodes_count;
        let mut bitmap = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        let mut bitmap_home = None;
        if is_orphan && raw.size_lo == 0 {
            return Ok(());
        }
        let count = u64::from(raw.size_lo).div_ceil(u64::from(self.block_size));
        if count > MAX_OWNERSHIP_REFERENCES as u64 {
            return Err(FsError::NotSupported);
        }
        for index in 0..count {
            // Directory trees are immutable to the existing writer except for
            // namespace data homes. Map the accepted inode, then read the overlay.
            let physical = self
                .map_file_block_with_scratch(raw, index as u32, scratch)?
                .ok_or(FsError::Invalid)?;
            self.read_virtual_block(journal, overlay, images, physical, scratch)?;
            let bytes = scratch.block();
            let mut offset = 0usize;
            while offset < bytes.len() {
                let head = bytes.get(offset..offset + 8).ok_or(FsError::Invalid)?;
                let child = u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
                let len = usize::from(u16::from_le_bytes(
                    head[4..6].try_into().map_err(|_| FsError::Invalid)?,
                ));
                let end = offset.checked_add(len).ok_or(FsError::Invalid)?;
                let name_end = offset
                    .checked_add(8 + usize::from(head[6]))
                    .ok_or(FsError::Invalid)?;
                if len < 8 || len % 4 != 0 || end > bytes.len() || name_end > end {
                    return Err(FsError::Invalid);
                }
                let name = &bytes[offset + 8..name_end];
                if child != 0 {
                    if self.disk_dirent_type(EXT2_FT_DIR) == 0 && head[7] != 0 {
                        return Err(FsError::Invalid);
                    }
                    if !is_orphan {
                        if child > inode_count {
                            return Err(FsError::Invalid);
                        }
                        let (group, bit) = self.inode_group_index(child).ok_or(FsError::Invalid)?;
                        let home = self
                            .group_descs
                            .read()
                            .get(group)
                            .ok_or(FsError::Invalid)?
                            .inode_bitmap;
                        if bitmap_home != Some(home) {
                            self.read_virtual_block(journal, overlay, images, home, &mut bitmap)?;
                            bitmap_home = Some(home);
                        }
                        if bitmap
                            .block()
                            .get(bit / 8)
                            .copied()
                            .ok_or(FsError::Invalid)?
                            & (1 << (bit % 8))
                            == 0
                        {
                            return Err(FsError::Invalid);
                        }
                    }
                    if orphans.binary_search(&child).is_ok()
                        && !(is_orphan && ((child == ino && name == b".") || name == b".."))
                    {
                        return Err(FsError::Invalid);
                    }
                    if is_orphan && name != b"." && name != b".." {
                        return Err(FsError::Invalid);
                    }
                }
                offset = end;
            }
        }
        Ok(())
    }

    pub(super) fn unlink_namespace(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        expected_ino: u64,
        must_be_dir: Option<bool>,
    ) -> Result<(), FsError> {
        valid_name(name)?;
        self.ensure_io_healthy()?;
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        let parent = parent
            .as_any()
            .downcast_ref::<Ext2Inode>()
            .ok_or(FsError::Invalid)?;
        if parent.fs_id != self.fs_id {
            return Err(FsError::CrossDev);
        }
        let ino = u32::try_from(expected_ino).map_err(|_| FsError::Invalid)?;
        if ino == parent.ino || ino < self.superblock.read().first_ino {
            return Err(FsError::PermDenied);
        }
        let fs = parent.fs.upgrade().ok_or(FsError::Invalid)?;
        let child = fs.load_inode(ino)?;
        let _orphan = fs.orphan_lock.lock();
        let mut scratch = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        let _parent_write = parent.write_lock.lock();
        let mut parent_raw = parent.raw.write();
        let _child_write = child.write_lock.lock();
        let mut child_raw = child.raw.write();
        let _meta = self.meta_lock.lock();
        self.ensure_io_healthy()?;
        if parent_raw.links_count == 0 || child_raw.links_count == 0 {
            return Err(FsError::NotFound);
        }
        if (parent_raw.flags | child_raw.flags) & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL) != 0 {
            return Err(FsError::PermDenied);
        }
        let slot = self.find_namespace_entry(&parent_raw, name, &mut scratch)?;
        if slot.inode != ino {
            return Err(FsError::Again);
        }
        let directory = child_raw.mode & EXT2_S_IFMT == EXT2_S_IFDIR;
        match must_be_dir {
            Some(true) if !directory => return Err(FsError::NotDir),
            Some(false) if directory => return Err(FsError::IsDir),
            _ => {}
        }
        if directory {
            self.require_empty_directory(ino, parent.ino, &child_raw, &mut scratch)?;
        }
        self.check_reclaim_layout(&child_raw)?;
        self.namespace_tail_len()?;
        let mut journal = self.journal.lock();
        let journal = journal.as_mut().ok_or(FsError::ReadOnly)?;
        self.validate_namespace_link_count(
            journal,
            &[],
            &[],
            ino,
            child_raw.links_count,
            &mut scratch,
        )?;
        let chain = self.read_orphan_chain(journal, &[], &[], &mut scratch)?;
        if chain.len() == MAX_ORPHANS {
            return Err(FsError::NoSpace);
        }
        drop(chain);
        let old_head = self.superblock.read().last_orphan;
        let now = TimeSpec::now().sec as u32;
        let mut next_child = *child_raw;
        next_child.links_count = if directory {
            0
        } else {
            next_child
                .links_count
                .checked_sub(1)
                .ok_or(FsError::Invalid)?
        };
        next_child.dtime = if next_child.links_count == 0 {
            old_head
        } else {
            0
        };
        next_child.ctime = now;
        let mut next_parent = *parent_raw;
        next_parent.mtime = now;
        next_parent.ctime = now;
        if directory {
            next_parent.links_count = next_parent
                .links_count
                .checked_sub(1)
                .ok_or(FsError::Invalid)?;
        }
        let mut old_name = [0u8; 255];
        old_name[..name.len()].copy_from_slice(name.as_bytes());
        let intent = JournalCommitIntent {
            kind: UNLINK,
            metadata_count: 0,
            inode_number: parent.ino,
            file_block: u32::MAX,
            physical: slot.home,
            preimage_hashes: [[0; 32]; JOURNAL_MAX_METADATA_BLOCKS],
            old_inode: *parent_raw,
            new_ino: ino,
            parent_ino: parent.ino,
            rename_dir_off: slot.offset,
            rename_rec_len: slot.length,
            rename_old_name_len: name.len() as u8,
            rename_old_name: old_name,
            namespace: NamespaceExtra {
                old_child: *child_raw,
                old_head,
                predecessor: 0,
                previous_offset: slot.previous,
                previous_length: slot.previous_length,
                file_type: slot.file_type,
                ..NamespaceExtra::default()
            },
        };
        let mut plan = NamespacePlan::new(intent, next_child, next_parent);
        plan.prepare(self, journal, &mut scratch)?;
        let result = self.commit_metadata_transaction(
            journal,
            JournalMetadataPlan::Namespace(&plan),
            &mut scratch,
        );
        if let Err(failure) = result {
            if failure.poison {
                self.io_faulted.store(true, Ordering::Release);
            }
            if !failure.committed {
                return Err(failure.error);
            }
        }
        *parent_raw = next_parent;
        *child_raw = next_child;
        child
            .unlinked
            .store(next_child.links_count == 0, Ordering::Release);
        self.superblock.write().last_orphan = plan.new_head();
        match result {
            Ok(()) => Ok(()),
            Err(failure) => Err(failure.error),
        }
    }
}

impl Ext2Fs {
    /// Reclaim only orphan objects with no external references. Chain edits are
    /// serialized independently of inode writes; metadata is never held while
    /// waiting for an inode lock. try_lock also makes final-reference Drop safe.
    pub(super) fn reap_orphans(self: &Arc<Self>) -> Result<(), FsError> {
        if self.superblock.read().last_orphan == 0 {
            return Ok(());
        }
        self.ensure_io_healthy()?;
        let Some(_orphans) = self.orphan_lock.try_lock() else {
            return Ok(());
        };
        let mut scratch = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        for _ in 0..MAX_ORPHANS {
            let (child, predecessor) = {
                let Some(_meta) = self.meta_lock.try_lock() else {
                    return Ok(());
                };
                self.ensure_io_healthy()?;
                let mut ino = self.superblock.read().last_orphan;
                let mut predecessor = 0;
                let mut selected = None;
                for _ in 0..MAX_ORPHANS {
                    if ino == 0 {
                        break;
                    }
                    let raw = self.read_inode_raw(ino)?;
                    if raw.links_count != 0 {
                        return Err(FsError::Invalid);
                    }
                    if self.inode_cache.get(ino).is_none() {
                        let child = self
                            .inode_cache
                            .get_or_try_insert_with(ino, || self.new_inode_from_raw(ino, raw))?;
                        selected = Some((child, predecessor));
                        break;
                    }
                    predecessor = ino;
                    ino = raw.dtime;
                }
                let Some(selected) = selected else {
                    return Ok(());
                };
                selected
            };
            // No public lookup can acquire an orphan. The preceding absence
            // check and cache publication occurred under the allocation gate.
            let previous = if predecessor == 0 {
                None
            } else {
                let _meta = self.meta_lock.lock();
                Some(self.inode_cache.get_or_try_insert_with(predecessor, || {
                    self.new_inode_from_raw(predecessor, self.read_inode_raw(predecessor)?)
                })?)
            };
            let _previous_write = previous.as_ref().map(|inode| inode.write_lock.lock());
            let mut previous_raw = previous.as_ref().map(|inode| inode.raw.write());
            let raw = *child.raw.read();
            let inline = raw.mode & EXT2_S_IFMT == EXT2_S_IFLNK
                && raw.blocks_lo == 0
                && (raw.size_lo as usize) < size_of_val(&raw.block);
            if !inline && (raw.size_lo != 0 || raw.blocks_lo != 0) {
                child.truncate_mutation_inner(0, true)?;
            }
            let _write = child.write_lock.lock();
            let mut raw = child.raw.write();
            let _meta = self.meta_lock.lock();
            self.ensure_io_healthy()?;
            if previous_raw
                .as_ref()
                .is_some_and(|raw| raw.dtime != child.ino || raw.links_count != 0)
            {
                return Err(FsError::Invalid);
            }
            let intent = JournalCommitIntent {
                kind: INODE_FREE,
                metadata_count: 0,
                inode_number: child.ino,
                file_block: u32::MAX,
                physical: 0,
                preimage_hashes: [[0; 32]; JOURNAL_MAX_METADATA_BLOCKS],
                old_inode: Ext2InodeRaw::default(),
                new_ino: child.ino,
                parent_ino: 0,
                rename_dir_off: 0,
                rename_rec_len: 0,
                rename_old_name_len: 0,
                rename_old_name: [0; 255],
                namespace: NamespaceExtra {
                    old_child: *raw,
                    old_head: self.superblock.read().last_orphan,
                    predecessor,
                    ..NamespaceExtra::default()
                },
            };
            let group = self.inode_group_index(child.ino).ok_or(FsError::Invalid)?.0;
            let desc = self.group_descs.read()[group];
            let mut plan =
                NamespacePlan::new(intent, Ext2InodeRaw::default(), Ext2InodeRaw::default());
            plan.old_group_free = desc.free_inodes_count;
            plan.old_used_dirs = desc.used_dirs_count;
            plan.old_super_free = self.superblock.read().free_inodes_count;
            let mut journal = self.journal.lock();
            let journal = journal.as_mut().ok_or(FsError::ReadOnly)?;
            plan.prepare(self, journal, &mut scratch)?;
            let result = self.commit_metadata_transaction(
                journal,
                JournalMetadataPlan::Namespace(&plan),
                &mut scratch,
            );
            if let Err(failure) = result {
                if failure.poison {
                    self.io_faulted.store(true, Ordering::Release);
                }
                if !failure.committed {
                    return Err(failure.error);
                }
            }
            {
                let mut sb = self.superblock.write();
                sb.last_orphan = plan.new_head();
                sb.free_inodes_count = plan.old_super_free + 1;
                let mut descs = self.group_descs.write();
                descs[group].free_inodes_count = plan.old_group_free + 1;
                if raw.mode & EXT2_S_IFMT == EXT2_S_IFDIR {
                    descs[group].used_dirs_count = plan.old_used_dirs - 1;
                }
            }
            if let Some(previous) = previous_raw.as_mut() {
                previous.dtime = raw.dtime;
            }
            *raw = Ext2InodeRaw::default();
            child.size.store(0, Ordering::Release);
            self.inode_cache.entries.write().remove(&child.ino);
            if let Err(failure) = result {
                return Err(failure.error);
            }
        }
        Ok(())
    }
}

impl Ext2Fs {
    fn insertion_slot(
        &self,
        parent: &Ext2InodeRaw,
        name: &str,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<DirectorySlot, FsError> {
        let needed = (8 + name.len() + 3) & !3;
        let mut selected = None;
        self.walk_namespace_directory(parent, scratch, |slot, bytes| {
            if slot.inode != 0 && bytes == name.as_bytes() {
                return Err(FsError::Exists);
            }
            if selected.is_none() {
                if slot.inode == 0 && bytes.is_empty() && usize::from(slot.length) >= needed {
                    selected = Some(DirectorySlot {
                        previous: NO_PREVIOUS,
                        previous_length: 0,
                        ..slot
                    });
                } else if slot.inode != 0 {
                    let minimum = (8 + bytes.len() + 3) & !3;
                    if usize::from(slot.length) >= minimum + needed {
                        selected = Some(DirectorySlot {
                            home: slot.home,
                            offset: slot.offset + minimum as u32,
                            previous: slot.offset,
                            previous_length: slot.length,
                            inode: 0,
                            length: slot.length - minimum as u16,
                            file_type: 0,
                        });
                    }
                }
            }
            Ok(())
        })?;
        let slot = selected.ok_or(FsError::NoSpace)?;
        self.read_block(slot.home, scratch.block_mut())?;
        let mut expected = [0u8; 263];
        if slot.previous == NO_PREVIOUS {
            expected[4..6].copy_from_slice(&slot.length.to_le_bytes());
        }
        let off = slot.offset as usize;
        if scratch
            .block()
            .get(off..off + 8 + name.len())
            .ok_or(FsError::Invalid)?
            != &expected[..8 + name.len()]
        {
            return Err(FsError::NotSupported);
        }
        Ok(slot)
    }

    fn vacant_namespace_inode(
        &self,
        parent: u32,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(u32, Ext2InodeRaw), FsError> {
        let sb = *self.superblock.read();
        let groups = self.group_descs.read().len();
        let first = self.inode_group_index(parent).ok_or(FsError::Invalid)?.0;
        for step in 0..groups {
            let group = (first + step) % groups;
            let desc = self.group_descs.read()[group];
            if desc.free_inodes_count == 0 {
                continue;
            }
            for index in 0..self.inodes_per_group {
                let ino = (group as u32)
                    .checked_mul(self.inodes_per_group)
                    .and_then(|base| base.checked_add(index + 1))
                    .ok_or(FsError::Invalid)?;
                if ino > sb.inodes_count {
                    break;
                }
                if ino < sb.first_ino || ino == sb.journal_inum {
                    continue;
                }
                self.read_block(desc.inode_bitmap, scratch.block_mut())?;
                if scratch.block()[index as usize / 8] & (1u8 << (index % 8)) != 0 {
                    continue;
                }
                let target = self.inode_write_target(ino)?;
                self.read_block(target.block, scratch.block_mut())?;
                self.namespace_tail_len()?;
                return Ok((ino, inode_from(scratch.block(), target.start)?));
            }
        }
        Err(FsError::NoSpace)
    }

    pub(super) fn create_namespace(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
        target: Option<&str>,
        context: &crate::topology::MutationContext<'_>,
    ) -> Result<Arc<dyn Inode>, FsError> {
        valid_name(name)?;
        let parent = parent
            .as_any()
            .downcast_ref::<Ext2Inode>()
            .ok_or(FsError::Invalid)?;
        if parent.fs_id != self.fs_id {
            return Err(FsError::CrossDev);
        }
        let fs = parent.fs.upgrade().ok_or(FsError::Invalid)?;
        fs.reap_orphans()?;
        let result = fs.create_namespace_locked(parent, name, mode, target, context);
        if result.is_err() {
            let _ = fs.reap_orphans();
        }
        result
    }

    fn create_namespace_locked(
        self: &Arc<Self>,
        parent: &Ext2Inode,
        name: &str,
        mode: FileMode,
        target: Option<&str>,
        context: &crate::topology::MutationContext<'_>,
    ) -> Result<Arc<dyn Inode>, FsError> {
        self.ensure_io_healthy()?;
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        let directory = mode.is_dir();
        if !directory && !mode.is_symlink() {
            return Err(FsError::NotSupported);
        }
        if let Some(target) = target {
            if target.is_empty() || target.as_bytes().contains(&0) {
                return Err(FsError::Invalid);
            }
            if target.len() >= self.block_size as usize || target.len() >= 4096 {
                return Err(FsError::NameTooLong);
            }
        } else if !directory {
            return Err(FsError::Invalid);
        }
        let mut scratch = Ext2MutationScratch::try_new_admitted(self.block_size)?;
        let _orphans = self.orphan_lock.lock();
        let _parent_write = parent.write_lock.lock();
        let mut parent_raw = parent.raw.write();
        if parent_raw.mode & EXT2_S_IFMT != EXT2_S_IFDIR {
            return Err(FsError::NotDir);
        }
        if parent_raw.links_count == 0 {
            return Err(FsError::NotFound);
        }
        if parent_raw.flags & EXT2_IMMUTABLE_FL != 0 {
            return Err(FsError::PermDenied);
        }
        if parent_raw.flags & EXT2_UNSUPPORTED_WRITE_LAYOUT_FL != 0 {
            return Err(FsError::NotSupported);
        }
        if directory && parent_raw.links_count == u16::MAX {
            return Err(FsError::NoSpace);
        }
        let (child, slot) = {
            let _meta = self.meta_lock.lock();
            self.ensure_io_healthy()?;
            let mut journal = self.journal.lock();
            let journal = journal.as_mut().ok_or(FsError::ReadOnly)?;
            let chain = self.read_orphan_chain(journal, &[], &[], &mut scratch)?;
            if chain.len() == MAX_ORPHANS {
                return Err(FsError::NoSpace);
            }
            drop(chain);
            let slot = self.insertion_slot(&parent_raw, name, &mut scratch)?;
            let (ino, old_child) = self.vacant_namespace_inode(parent.ino, &mut scratch)?;
            let sb = *self.superblock.read();
            let mut raw = Ext2InodeRaw::default();
            raw.mode = if directory {
                EXT2_S_IFDIR | (mode.perm & 0o7777) | (parent_raw.mode & 0o2000)
            } else {
                EXT2_S_IFLNK | 0o777
            };
            let gid = if parent_raw.mode & 0o2000 != 0 {
                parent_raw.owner_ids(sb.creator_os).1
            } else {
                context.gid
            };
            raw.set_owner_ids(sb.creator_os, context.uid, gid)?;
            raw.atime = TimeSpec::now().sec as u32;
            raw.mtime = raw.atime;
            raw.ctime = raw.atime;
            raw.dtime = sb.last_orphan;
            if let Some(target) = target.filter(|target| target.len() < 60) {
                raw.size_lo = target.len() as u32;
                for (index, byte) in target.bytes().enumerate() {
                    raw.block[index / 4] |= u32::from(byte) << ((index % 4) * 8);
                }
            }
            let intent = JournalCommitIntent {
                kind: ORPHAN_ALLOC,
                metadata_count: 0,
                inode_number: ino,
                file_block: u32::MAX,
                physical: 0,
                preimage_hashes: [[0; 32]; JOURNAL_MAX_METADATA_BLOCKS],
                old_inode: Ext2InodeRaw::default(),
                new_ino: ino,
                parent_ino: 0,
                rename_dir_off: 0,
                rename_rec_len: 0,
                rename_old_name_len: 0,
                rename_old_name: [0; 255],
                namespace: NamespaceExtra {
                    old_child,
                    old_head: sb.last_orphan,
                    ..NamespaceExtra::default()
                },
            };
            let mut plan = NamespacePlan::new(intent, raw, Ext2InodeRaw::default());
            plan.prepare(self, journal, &mut scratch)?;
            // Reserve the canonical object and cache entry before durable edits.
            let child = self
                .inode_cache
                .get_or_try_insert_with(ino, || self.new_inode_from_raw(ino, raw))?;
            let result = self.commit_metadata_transaction(
                journal,
                JournalMetadataPlan::Namespace(&plan),
                &mut scratch,
            );
            if let Err(failure) = result {
                if failure.poison {
                    self.io_faulted.store(true, Ordering::Release);
                }
                if !failure.committed {
                    return Err(failure.error);
                }
            }
            plan.publish_counts(self)?;
            if let Err(failure) = result {
                return Err(failure.error);
            }
            (child, slot)
        };
        if directory {
            let bytes = scratch.block_mut();
            bytes.fill(0);
            bytes[..4].copy_from_slice(&child.ino.to_le_bytes());
            bytes[4..6].copy_from_slice(&12u16.to_le_bytes());
            bytes[6] = 1;
            bytes[7] = self.disk_dirent_type(EXT2_FT_DIR);
            bytes[8] = b'.';
            bytes[12..16].copy_from_slice(&parent.ino.to_le_bytes());
            bytes[16..18].copy_from_slice(
                &u16::try_from(self.block_size - 12)
                    .map_err(|_| FsError::NotSupported)?
                    .to_le_bytes(),
            );
            bytes[18] = 2;
            bytes[19] = self.disk_dirent_type(EXT2_FT_DIR);
            bytes[20..22].copy_from_slice(b"..");
            let written = child
                .write_mutation_inner(Ext2WriteMode::Positioned(0), bytes, true)?
                .0;
            if written != bytes.len() {
                return Err(FsError::Io);
            }
        } else if let Some(target) = target.filter(|target| target.len() >= 60) {
            if child
                .write_mutation_inner(Ext2WriteMode::Positioned(0), target.as_bytes(), true)?
                .0
                != target.len()
            {
                return Err(FsError::Io);
            }
        }
        let _child_write = child.write_lock.lock();
        let mut child_raw = child.raw.write();
        let _meta = self.meta_lock.lock();
        self.ensure_io_healthy()?;
        let mut journal = self.journal.lock();
        let journal = journal.as_mut().ok_or(FsError::ReadOnly)?;
        let mut name_bytes = [0; 255];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());
        let intent = JournalCommitIntent {
            kind: PUBLISH,
            metadata_count: 0,
            inode_number: parent.ino,
            file_block: u32::MAX,
            physical: slot.home,
            preimage_hashes: [[0; 32]; JOURNAL_MAX_METADATA_BLOCKS],
            old_inode: *parent_raw,
            new_ino: child.ino,
            parent_ino: parent.ino,
            rename_dir_off: slot.offset,
            rename_rec_len: slot.length,
            rename_old_name_len: name.len() as u8,
            rename_old_name: name_bytes,
            namespace: NamespaceExtra {
                old_child: *child_raw,
                old_head: self.superblock.read().last_orphan,
                predecessor: 0,
                previous_offset: slot.previous,
                previous_length: slot.previous_length,
                file_type: self.disk_dirent_type(if directory {
                    EXT2_FT_DIR
                } else {
                    EXT2_FT_SYMLINK
                }),
                ..NamespaceExtra::default()
            },
        };
        let now = TimeSpec::now().sec as u32;
        let mut next_child = *child_raw;
        next_child.links_count = if directory { 2 } else { 1 };
        next_child.dtime = 0;
        next_child.ctime = now;
        let mut next_parent = *parent_raw;
        next_parent.mtime = now;
        next_parent.ctime = now;
        if directory {
            next_parent.links_count = next_parent
                .links_count
                .checked_add(1)
                .ok_or(FsError::NoSpace)?;
        }
        let mut plan = NamespacePlan::new(intent, next_child, next_parent);
        plan.prepare(self, journal, &mut scratch)?;
        let result = self.commit_metadata_transaction(
            journal,
            JournalMetadataPlan::Namespace(&plan),
            &mut scratch,
        );
        if let Err(failure) = result {
            if failure.poison {
                self.io_faulted.store(true, Ordering::Release);
            }
            if !failure.committed {
                return Err(failure.error);
            }
        }
        *parent_raw = next_parent;
        *child_raw = next_child;
        child.unlinked.store(false, Ordering::Release);
        plan.publish_counts(self)?;
        if let Err(failure) = result {
            return Err(failure.error);
        }
        Ok(child.clone() as Arc<dyn Inode>)
    }
}

impl Ext2Fs {
    /// Bind publication/removal to actual directory records and initialized
    /// child contents, including homes outside this transaction's overlay.
    pub(super) fn validate_namespace_contents(
        &self,
        journal: &Ext2Journal,
        overlay: &[JournalOverlayEntry],
        pre: &[u8],
        post: &[u8],
        intent: &JournalCommitIntent,
        scratch: &mut Ext2MutationScratch,
    ) -> Result<(), FsError> {
        if !matches!(intent.kind, UNLINK | PUBLISH) {
            return Ok(());
        }
        if intent.kind == UNLINK {
            self.validate_namespace_link_count(
                journal,
                overlay,
                pre,
                intent.new_ino,
                intent.namespace.old_child.links_count,
                scratch,
            )?;
        }
        let parent = &intent.old_inode;
        let count = parent.size_lo / self.block_size;
        if parent.size_lo == 0
            || parent.size_lo % self.block_size != 0
            || count as usize > EXT2_NDIR_BLOCKS
            || parent.block[EXT2_NDIR_BLOCKS..].iter().any(|p| *p != 0)
        {
            return Err(FsError::Invalid);
        }
        for (images, expected) in [
            (pre, usize::from(intent.kind == UNLINK)),
            (post, usize::from(intent.kind == PUBLISH)),
        ] {
            let mut found = 0;
            for physical in &parent.block[..count as usize] {
                if *physical == 0 {
                    return Err(FsError::Invalid);
                }
                self.read_virtual_block(journal, overlay, images, *physical, scratch)?;
                let bytes = scratch.block();
                let mut off = 0;
                while off < bytes.len() {
                    let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
                    let ino =
                        u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
                    let len = usize::from(u16::from_le_bytes(
                        head[4..6].try_into().map_err(|_| FsError::Invalid)?,
                    ));
                    let end = off.checked_add(len).ok_or(FsError::Invalid)?;
                    let name_end = off
                        .checked_add(8 + usize::from(head[6]))
                        .ok_or(FsError::Invalid)?;
                    if len < 8 || len % 4 != 0 || end > bytes.len() || name_end > end {
                        return Err(FsError::Invalid);
                    }
                    if ino != 0
                        && bytes[off + 8..name_end]
                            == intent.rename_old_name[..usize::from(intent.rename_old_name_len)]
                    {
                        if ino != intent.new_ino
                            || *physical != intent.physical
                            || off != intent.rename_dir_off as usize
                        {
                            return Err(FsError::Invalid);
                        }
                        found += 1;
                    }
                    off = end;
                }
            }
            if found != expected {
                return Err(FsError::Invalid);
            }
        }
        let child = &intent.namespace.old_child;
        if child.mode & EXT2_S_IFMT == EXT2_S_IFDIR {
            let mut dot = false;
            let mut dotdot = false;
            if child.size_lo == 0
                || child.size_lo % self.block_size != 0
                || child.size_lo / self.block_size > EXT2_NDIR_BLOCKS as u32
            {
                return Err(FsError::Invalid);
            }
            for physical in &child.block[..(child.size_lo / self.block_size) as usize] {
                self.read_virtual_block(journal, overlay, pre, *physical, scratch)?;
                let bytes = scratch.block();
                let mut off = 0;
                while off < bytes.len() {
                    let head = bytes.get(off..off + 8).ok_or(FsError::Invalid)?;
                    let ino =
                        u32::from_le_bytes(head[..4].try_into().map_err(|_| FsError::Invalid)?);
                    let len = usize::from(u16::from_le_bytes(
                        head[4..6].try_into().map_err(|_| FsError::Invalid)?,
                    ));
                    let end = off.checked_add(len).ok_or(FsError::Invalid)?;
                    let name_end = off
                        .checked_add(8 + usize::from(head[6]))
                        .ok_or(FsError::Invalid)?;
                    if len < 8 || len % 4 != 0 || end > bytes.len() || name_end > end {
                        return Err(FsError::Invalid);
                    }
                    let name = &bytes[off + 8..name_end];
                    if ino != 0 {
                        if name == b"." && ino == intent.new_ino && !dot {
                            dot = true;
                        } else if name == b".." && ino == intent.parent_ino && !dotdot {
                            dotdot = true;
                        } else {
                            return Err(FsError::Invalid);
                        }
                    }
                    off = end;
                }
            }
            if !dot || !dotdot {
                return Err(FsError::Invalid);
            }
        } else if intent.kind == PUBLISH && child.mode & EXT2_S_IFMT == EXT2_S_IFLNK {
            let len = child.size_lo as usize;
            if len == 0 || len >= self.block_size as usize {
                return Err(FsError::Invalid);
            }
            let bytes = if is_inline(child) {
                inline_bytes(child)
            } else {
                if child.blocks_lo != self.block_size / 512
                    || child.block[0] == 0
                    || child.block[1..].iter().any(|p| *p != 0)
                {
                    return Err(FsError::Invalid);
                }
                self.read_virtual_block(journal, overlay, pre, child.block[0], scratch)?;
                scratch.block()
            };
            if bytes[..len].contains(&0) || bytes[len] != 0 {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }
}
