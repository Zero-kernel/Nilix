use super::*;
use crate::HEAP_TEST_LOCK;
use mm::heap_admission::{set_current_owner, HeapOwner, OWNER_NON_EXEC_BYTES};

fn file_charge(file: &RamFsInode) -> usize {
    match &file.kind {
        NodeKind::File { state } => state.read().heap_charge.bytes(),
        _ => panic!("expected file"),
    }
}

#[test]
fn shared_file_growth_is_paid_by_writer_even_when_creator_is_full() {
    let _serial = HEAP_TEST_LOCK.lock();
    mm::publish_heap_budgets();
    let baseline = mm::heap_admission::snapshot();
    {
        let creator = HeapOwner::try_new_for_uid(51001).unwrap();
        let writer = HeapOwner::try_new_for_uid(51002).unwrap();
        set_current_owner(Some(creator.clone()));
        let file = RamFsInode::new_file(0x5152, 1, 0o600, 0, 0).unwrap();
        file.write_at(0, &[0x51; 4096]).unwrap();
        let original = file_charge(&file);
        let full = mm::try_reserve_heap(HeapClass::Pipe, OWNER_NON_EXEC_BYTES - original).unwrap();
        assert_eq!(creator.snapshot().used_bytes, OWNER_NON_EXEC_BYTES);
        let inherited = file.clone();
        set_current_owner(Some(writer.clone()));
        inherited.append_write(&[0x52; 4096]).unwrap();
        assert_eq!(
            creator.snapshot().used_bytes,
            OWNER_NON_EXEC_BYTES - original
        );
        assert_eq!(writer.snapshot().used_bytes, file_charge(&file));
        let mut data = [0; 2];
        file.read_at(4095, &mut data).unwrap();
        assert_eq!(data, [0x51, 0x52]);
        let live = mm::heap_admission::snapshot();
        let owned = writer.snapshot();
        assert_eq!(file.truncate(480 * 1024), Err(FsError::NoSpace));
        assert_eq!(writer.snapshot(), owned);
        assert_eq!(mm::heap_admission::snapshot(), live);
        assert_eq!(file.stat().unwrap().size, 8192);
        set_current_owner(None);
        drop((file, inherited, full));
        assert_eq!(creator.snapshot().used_bytes, 0);
        assert_eq!(writer.snapshot().used_bytes, 0);
    }
    assert_eq!(mm::heap_admission::snapshot(), baseline);
}

#[test]
fn boot_file_adoption_includes_existing_capacity_and_failure_changes_nothing() {
    let _serial = HEAP_TEST_LOCK.lock();
    mm::publish_heap_budgets();
    set_current_owner(None);
    let baseline = mm::heap_admission::snapshot();
    {
        let file = RamFsInode::new_file(0x5153, 1, 0o600, 0, 0).unwrap();
        file.write_at(0, &[0x61; 16 * 1024]).unwrap();
        let existing = file_charge(&file);
        let owner = HeapOwner::try_new_for_uid(51003).unwrap();
        let held = mm::heap_admission::try_reserve_owned(
            HeapClass::Pipe,
            OWNER_NON_EXEC_BYTES - existing + 1,
            Some(owner.clone()),
        )
        .unwrap();
        set_current_owner(Some(owner.clone()));
        let live = mm::heap_admission::snapshot();
        let owned = owner.snapshot();
        assert_eq!(file.write_at(0, b"x"), Err(FsError::NoSpace));
        assert_eq!(mm::heap_admission::snapshot(), live);
        assert_eq!(owner.snapshot(), owned);
        let mut byte = [0];
        file.read_at(0, &mut byte).unwrap();
        assert_eq!(byte, [0x61]);
        assert_eq!(file.stat().unwrap().size, 16 * 1024);
        drop(held);
        let live = mm::heap_admission::snapshot();
        file.write_at(0, b"x").unwrap();
        assert_eq!(owner.snapshot().used_bytes, existing);
        assert_eq!(mm::heap_admission::snapshot(), live);
        // Replacement frees the old boot buffer from the correct owner; it
        // must not mistakenly refund newly acquired bytes of the replacement.
        file.truncate(32 * 1024).unwrap();
        assert_eq!(owner.snapshot().used_bytes, file_charge(&file));
        set_current_owner(None);
        drop(file);
        assert_eq!(owner.snapshot().used_bytes, 0);
    }
    assert_eq!(mm::heap_admission::snapshot(), baseline);
}

#[test]
fn boot_directory_adopts_metadata_and_contents_then_changes_growth_owner() {
    let _serial = HEAP_TEST_LOCK.lock();
    mm::publish_heap_budgets();
    set_current_owner(None);
    let baseline = mm::heap_admission::snapshot();
    {
        let fs = RamFs::try_new().unwrap();
        let root = fs.root_inode();
        fs.create(
            &root,
            "boot-entry",
            FileMode::regular(0o600),
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        let inode = fs.downcast_inode(&root).unwrap();
        let old_contents = inode.dir_entries().unwrap().read().heap_charge.bytes();
        let old_metadata = inode.allocation_owner.as_ref().unwrap().lock().bytes();
        assert!(old_contents > 0 && old_metadata > 0);
        let a = HeapOwner::try_new_for_uid(51004).unwrap();
        let b = HeapOwner::try_new_for_uid(51005).unwrap();
        set_current_owner(Some(a.clone()));
        fs.create(
            &root,
            "user-entry",
            FileMode::regular(0o600),
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        let contents = inode.dir_entries().unwrap().read().heap_charge.bytes();
        assert!(contents > old_contents);
        assert!(a.snapshot().used_bytes >= old_metadata + contents);
        let before_a = a.snapshot().used_bytes;
        set_current_owner(Some(b.clone()));
        fs.create(
            &root,
            "second-user-entry",
            FileMode::regular(0o600),
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        assert_eq!(a.snapshot().used_bytes, before_a - contents);
        let state = inode.dir_entries().unwrap().read();
        assert!(Arc::ptr_eq(&state.heap_charge.owner().unwrap(), &b));
        assert!(b.snapshot().used_bytes >= state.heap_charge.bytes());
        drop(state);
        set_current_owner(None);
        drop((root, fs));
        assert_eq!(a.snapshot().used_bytes, 0);
        assert_eq!(b.snapshot().used_bytes, 0);
    }
    assert_eq!(mm::heap_admission::snapshot(), baseline);
}

#[test]
fn cross_owner_rename_is_atomic_on_denial_and_keeps_unlink_available() {
    let _serial = HEAP_TEST_LOCK.lock();
    mm::publish_heap_budgets();
    set_current_owner(None);
    let baseline = mm::heap_admission::snapshot();
    {
        let fs = RamFs::try_new().unwrap();
        let root = fs.root_inode();
        let a = HeapOwner::try_new_for_uid(51006).unwrap();
        let b = HeapOwner::try_new_for_uid(51007).unwrap();
        set_current_owner(Some(a.clone()));
        let source = fs
            .create(
                &root,
                "from",
                FileMode::regular(0o600),
                &crate::topology::write().setup(0, 0),
            )
            .unwrap();
        let dest = fs
            .create(
                &root,
                "dest",
                FileMode::directory(0o700),
                &crate::topology::write().setup(0, 0),
            )
            .unwrap();
        fs.create(
            &dest,
            "seed",
            FileMode::regular(0o600),
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        set_current_owner(Some(b.clone()));
        let full = mm::try_reserve_heap(HeapClass::Pipe, OWNER_NON_EXEC_BYTES).unwrap();
        let live = mm::heap_admission::snapshot();
        assert_eq!(
            fs.rename(
                &root,
                "from",
                &dest,
                "to",
                false,
                source.ino(),
                None,
                &crate::topology::write().setup(0, 0)
            ),
            Err(FsError::NoSpace)
        );
        assert_eq!(mm::heap_admission::snapshot(), live);
        assert!(fs.lookup(&root, "from").is_ok());
        assert!(fs.lookup(&dest, "to").is_err());
        drop(full);
        fs.rename(
            &root,
            "from",
            &dest,
            "to",
            false,
            source.ino(),
            None,
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        // Same-parent rename also transfers storage before removing its source.
        set_current_owner(Some(a.clone()));
        fs.rename(
            &dest,
            "to",
            &dest,
            "renamed",
            false,
            source.ino(),
            None,
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        set_current_owner(Some(b.clone()));
        let full = mm::try_reserve_heap(
            HeapClass::Pipe,
            OWNER_NON_EXEC_BYTES - b.snapshot().used_bytes,
        )
        .unwrap();
        fs.unlink(
            &dest,
            "renamed",
            source.ino(),
            Some(false),
            &crate::topology::write().setup(0, 0),
        )
        .unwrap();
        drop(full);
        set_current_owner(None);
        drop((source, dest, root, fs));
        assert_eq!(a.snapshot().used_bytes, 0);
        assert_eq!(b.snapshot().used_bytes, 0);
    }
    assert_eq!(mm::heap_admission::snapshot(), baseline);
}
