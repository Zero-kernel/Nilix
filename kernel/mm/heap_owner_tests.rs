use super::*;

#[test]
fn uid_budget_survives_fork_exit_and_retained_shared_objects() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    {
        let a = HeapOwner::try_new_for_uid(41001).unwrap();
        let b = HeapOwner::try_new_for_uid(41001).unwrap();
        let victim = HeapOwner::try_new_for_uid(41002).unwrap();
        let first = try_reserve_owned(HeapClass::Pipe, UID_NON_EXEC_BYTES / 2, Some(a.clone()))
            .unwrap()
            .commit()
            .unwrap();
        let second = try_reserve_owned(HeapClass::Pipe, UID_NON_EXEC_BYTES / 2, Some(b.clone()))
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(a.uid_snapshot().unwrap().used_bytes, UID_NON_EXEC_BYTES);
        drop((a, b)); // retained allocations still pin the UID identity
        let child = HeapOwner::try_new_for_uid(41001).unwrap();
        let full = snapshot();
        assert!(matches!(
            try_reserve_owned(HeapClass::Vfs, 1, Some(child.clone())),
            Err(HeapAdmissionError::UidLimit)
        ));
        assert_eq!(child.snapshot().used_bytes, 0);
        assert_eq!(snapshot(), full);
        let progress = try_reserve_owned(HeapClass::Vfs, 4096, Some(victim)).unwrap();
        drop(first);
        let retry = try_reserve_owned(HeapClass::Pipe, 4096, Some(child)).unwrap();
        drop((second, progress, retry));
    }
    assert_eq!(snapshot(), before);
}

#[test]
fn uid_class_and_io_limits_roll_back_every_ledger() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    {
        let a = HeapOwner::try_new_for_uid(41003).unwrap();
        let b = HeapOwner::try_new_for_uid(41003).unwrap();
        let c = HeapOwner::try_new_for_uid(41003).unwrap();
        let io_a = try_reserve_owned(
            HeapClass::BlockingIo,
            OWNER_BLOCKING_IO_BYTES,
            Some(a.clone()),
        )
        .unwrap();
        let io_b = try_reserve_owned(
            HeapClass::BlockingIo,
            OWNER_BLOCKING_IO_BYTES,
            Some(b.clone()),
        )
        .unwrap();
        let full = snapshot();
        assert!(matches!(
            try_reserve_owned(HeapClass::BlockingIo, 1, Some(c.clone())),
            Err(HeapAdmissionError::BlockingIoUidLimit)
        ));
        assert_eq!(snapshot(), full);
        assert_eq!(c.snapshot().used_bytes, 0);
        assert_eq!(c.uid_snapshot().unwrap().used_bytes, UID_BLOCKING_IO_BYTES);
        drop((io_a, io_b));
        let half = HeapClass::RamFs.limit_bytes() / 16 * 7;
        let fs_a = try_reserve_owned(HeapClass::RamFs, half, Some(a)).unwrap();
        let fs_b = try_reserve_owned(HeapClass::RamFs, half, Some(b)).unwrap();
        let full = snapshot();
        assert!(matches!(
            try_reserve_owned(HeapClass::RamFs, 1, Some(c.clone())),
            Err(HeapAdmissionError::UidClassLimit)
        ));
        assert_eq!(snapshot(), full);
        assert_eq!(c.snapshot().used_bytes, 0);
        drop((fs_a, fs_b));
        // Global failure must release the already-reserved UID counters too.
        let all =
            try_reserve_owned(HeapClass::Futex, HeapClass::Futex.limit_bytes(), None).unwrap();
        assert!(matches!(
            try_reserve_owned(HeapClass::Futex, 1, Some(c.clone())),
            Err(HeapAdmissionError::ClassLimit)
        ));
        assert_eq!(c.uid_snapshot().unwrap().used_bytes, 0);
        drop(all);
    }
    assert_eq!(snapshot(), before);
}

#[test]
fn concurrent_groups_cannot_overdraw_a_uid_budget() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let admitted = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let mut threads = std::vec::Vec::new();
    let observer = HeapOwner::try_new_for_uid(41004).unwrap();
    for _ in 0..8 {
        let barrier = barrier.clone();
        let admitted = admitted.clone();
        threads.push(std::thread::spawn(move || {
            let owner = HeapOwner::try_new_for_uid(41004).unwrap();
            barrier.wait();
            let held = try_reserve_owned(HeapClass::Pipe, 128 * 1024, Some(owner));
            if held.is_ok() {
                admitted.fetch_add(1, Ordering::SeqCst);
            } else {
                assert!(matches!(held, Err(HeapAdmissionError::UidLimit)));
            }
            barrier.wait();
            barrier.wait();
            drop(held);
        }));
    }
    barrier.wait();
    barrier.wait();
    assert_eq!(admitted.load(Ordering::SeqCst), 6);
    assert_eq!(
        observer.uid_snapshot().unwrap().used_bytes,
        UID_NON_EXEC_BYTES
    );
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(observer.uid_snapshot().unwrap().used_bytes, 0);
    drop(observer);
    assert_eq!(snapshot(), before);
}

#[test]
fn uid_registry_is_bounded_and_reuses_only_unpinned_slots() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    let mut owners = std::vec::Vec::new();
    for uid in 0..uid::MAX_UID_DOMAINS {
        owners.push(HeapOwner::try_new_for_uid(42000 + uid as u32).unwrap());
    }
    assert!(matches!(
        HeapOwner::try_new_for_uid(43000),
        Err(HeapAdmissionError::UidDomainLimit)
    ));
    let retained = try_reserve_owned(HeapClass::Vfs, 4096, Some(owners.pop().unwrap())).unwrap();
    assert!(matches!(
        HeapOwner::try_new_for_uid(43000),
        Err(HeapAdmissionError::UidDomainLimit)
    ));
    // Joining a present UID still works when the registry is full.
    drop(HeapOwner::try_new_for_uid(42000).unwrap());
    drop(retained);
    drop(HeapOwner::try_new_for_uid(43000).unwrap());
    drop(owners);
    assert_eq!(snapshot(), before);
}

#[test]
fn owner_transfer_adopts_all_boot_bytes_and_releases_exactly() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    {
        let owner = HeapOwner::try_new_for_uid(41005).unwrap();
        let mut charge = try_reserve_owned(HeapClass::RamFs, 4096, None)
            .unwrap()
            .commit()
            .unwrap();
        let live = snapshot();
        let transfer = charge.prepare_owner_transfer(Some(owner.clone())).unwrap();
        assert_eq!(owner.snapshot().used_bytes, 4096);
        assert_eq!(
            snapshot(),
            live,
            "adoption must not double-charge global capacity"
        );
        drop(transfer);
        assert_eq!(owner.snapshot().used_bytes, 0);
        assert!(charge.owner().is_none());
        charge
            .prepare_owner_transfer(Some(owner.clone()))
            .unwrap()
            .commit(&mut charge)
            .unwrap();
        let growth = charge.try_reserve_more(2048).unwrap();
        charge.absorb(growth).unwrap();
        assert_eq!(owner.snapshot().used_bytes, 6144);
        assert_eq!(owner.uid_snapshot().unwrap().used_bytes, 6144);
        charge.release_after_deallocation(5000).unwrap();
        assert_eq!(owner.snapshot().used_bytes, 1144);
        drop(charge);
        assert_eq!(owner.uid_snapshot().unwrap().used_bytes, 0);
    }
    assert_eq!(snapshot(), before);
}

#[test]
fn owner_transfer_failure_and_stale_preparation_preserve_both_owners() {
    let _serial = TEST_LEDGER_LOCK.lock();
    publish();
    let before = snapshot();
    {
        let a = HeapOwner::try_new().unwrap();
        let b = HeapOwner::try_new().unwrap();
        let mut charge = try_reserve_owned(HeapClass::RamFs, 4096, Some(a.clone()))
            .unwrap()
            .commit()
            .unwrap();
        let full =
            try_reserve_owned(HeapClass::Pipe, OWNER_NON_EXEC_BYTES, Some(b.clone())).unwrap();
        let live = snapshot();
        assert!(matches!(
            charge.prepare_owner_transfer(Some(b.clone())),
            Err(HeapAdmissionError::OwnerLimit)
        ));
        assert_eq!(snapshot(), live);
        assert_eq!(a.snapshot().used_bytes, 4096);
        drop(full);
        let transfer = charge.prepare_owner_transfer(Some(b.clone())).unwrap();
        // Model changed aggregate state between preparation and revalidation.
        charge.release_after_deallocation(1024).unwrap();
        assert_eq!(
            transfer.commit(&mut charge),
            Err(HeapAdmissionError::CorruptState)
        );
        assert_eq!(b.snapshot().used_bytes, 0);
        assert_eq!(a.snapshot().used_bytes, 3072);
        charge
            .prepare_owner_transfer(Some(b.clone()))
            .unwrap()
            .commit(&mut charge)
            .unwrap();
        assert_eq!(a.snapshot().used_bytes, 0);
        assert_eq!(b.snapshot().used_bytes, 3072);
        assert!(matches!(
            charge.prepare_owner_transfer(None),
            Err(HeapAdmissionError::CorruptState)
        ));
        drop(charge);
        assert_eq!(b.snapshot().used_bytes, 0);
    }
    assert_eq!(snapshot(), before);
}
