//! Exercise real cgroupfs inode operations and current-process UID mapping.
//! This integration binary owns its process table (no parallel unit fixtures).
#![cfg(feature = "host_harness")]

use kernel_core::cgroup::{self, CgroupControllers, CgroupLimits};
use kernel_core::process::{self, Process, ProcessNameSnapshot, PROCESS_TABLE};
use kernel_core::user_namespace::{UidGidMapping, UserNamespace, ROOT_USER_NAMESPACE};
use std::sync::Arc;
use vfs::cgroupfs::CgroupFs;
use vfs::traits::{FileHandle, FileSystem, Inode, PreparedFileHandle};
use vfs::types::{FsError, OpenFlags};

fn mapped_namespace(host_uid: u32) -> Arc<UserNamespace> {
    let ns = UserNamespace::new_child(ROOT_USER_NAMESPACE.clone()).unwrap();
    ns.set_uid_map_from_parent(
        vec![UidGidMapping {
            ns_id: 65534,
            host_id: host_uid,
            count: 1,
        }],
        &ROOT_USER_NAMESPACE,
        0,
        true,
        true,
    )
    .unwrap();
    ns
}

fn open(
    fs: &Arc<CgroupFs>,
    inode: &Arc<dyn Inode>,
) -> Result<kernel_core::FileDescriptor, FsError> {
    inode.clone().open(
        OpenFlags::new(OpenFlags::O_RDONLY),
        PreparedFileHandle::try_new()
            .unwrap()
            .bind_filesystem(fs.clone()),
    )
}

fn read(inode: &Arc<dyn Inode>) -> Result<String, FsError> {
    let mut buf = [0; 128];
    let len = inode.read_at(0, &mut buf)?;
    Ok(String::from_utf8(buf[..len].to_vec()).unwrap())
}

#[test]
fn control_files_enforce_live_delegation_and_mapped_identity() {
    mm::publish_heap_budgets();
    process::force_init_current_pid();
    let task = Process::try_new_pcb(
        1,
        0,
        ProcessNameSnapshot::from_parts("cgroup-access", ""),
        120,
    )
    .unwrap();
    {
        let mut table = PROCESS_TABLE.lock();
        assert!(table.is_empty());
        table.try_reserve_exact(2).unwrap();
        assert!(table.push_reserved(None).is_ok());
        assert!(table.push_reserved(Some(task.clone())).is_ok());
    }
    process::set_current_pid(Some(1));
    assert_eq!(process::current_host_euid(), Some(65534));
    assert!(!process::current_has_cap_rights(
        kernel_core::CapRights::ADMIN
    ));

    let controllers = CgroupControllers::all();
    let parent = cgroup::create_cgroup(0, controllers).unwrap();
    let child = cgroup::create_cgroup(parent.id(), controllers).unwrap();
    let foreign = cgroup::create_cgroup(0, controllers).unwrap();
    child
        .set_limit(CgroupLimits {
            memory_max: Some(8192),
            ..Default::default()
        })
        .unwrap();
    let fs = CgroupFs::new();
    let parent_dir = fs
        .lookup(&fs.root_inode(), &parent.id().to_string())
        .unwrap();
    let child_dir = fs.lookup(&parent_dir, &child.id().to_string()).unwrap();
    let foreign_dir = fs
        .lookup(&fs.root_inode(), &foreign.id().to_string())
        .unwrap();
    let names = [
        "memory.current",
        "pids.current",
        "io.stat",
        "memory.max",
        "pids.max",
        "files.current",
        "ports.current",
        "vfs_dir.current",
        "cgroup.controllers",
    ];
    let controls: Vec<_> = names
        .iter()
        .map(|name| fs.lookup(&child_dir, name).unwrap())
        .collect();
    let memory_max = fs.lookup(&child_dir, "memory.max").unwrap();

    // Non-delegates cannot open or read even when they already hold the inode.
    for inode in &controls {
        assert_eq!(read(inode), Err(FsError::PermDenied));
        assert_eq!(inode.stat().unwrap().mode.perm, 0);
        assert_eq!(open(&fs, inode).err(), Some(FsError::PermDenied));
    }
    assert_eq!(memory_max.write_at(0, b"4096"), Err(FsError::PermDenied));

    // Real host UID 65534 remains a valid delegate, inherited by descendants.
    cgroup::delegate_cgroup(parent.id(), Some(65534), true).unwrap();
    for inode in &controls {
        assert_ne!(inode.stat().unwrap().mode.perm & 0o444, 0);
        assert!(open(&fs, inode).is_ok());
        assert!(!read(inode).unwrap().is_empty());
    }
    assert_eq!(read(&memory_max).unwrap(), "8192\n");
    assert_eq!(memory_max.write_at(0, b"4096").unwrap(), 4);
    let foreign_stats = fs.lookup(&foreign_dir, "memory.current").unwrap();
    assert_eq!(read(&foreign_stats), Err(FsError::PermDenied));
    let fd = open(&fs, &controls[0]).unwrap();
    let handle = fd.as_any().downcast_ref::<FileHandle>().unwrap();

    // An empty uid_map must not borrow the real nobody user's delegation.
    task.lock().user_ns = UserNamespace::new_child(ROOT_USER_NAMESPACE.clone()).unwrap();
    assert_eq!(process::current_host_euid(), None);
    assert!(!process::current_is_host_root());
    for inode in &controls {
        assert_eq!(open(&fs, inode).err(), Some(FsError::PermDenied));
        assert_eq!(read(inode), Err(FsError::PermDenied));
    }
    let mut buf = [0xa5; 16];
    assert_eq!(handle.read(&mut buf), Err(FsError::PermDenied));
    assert_eq!(buf, [0xa5; 16], "denied reads must not copy content");
    assert_eq!(memory_max.write_at(0, b"2048"), Err(FsError::PermDenied));
    assert_eq!(child.limits().memory_max, Some(4096));

    // Mapping to a different host UID still cannot read the delegated subtree.
    task.lock().user_ns = mapped_namespace(1000);
    assert_eq!(process::current_host_euid(), Some(1000));
    assert_eq!(read(&controls[0]), Err(FsError::PermDenied));
    task.lock().user_ns = mapped_namespace(65534);
    assert_eq!(process::current_host_euid(), Some(65534));
    assert!(handle.read(&mut buf).unwrap() > 0);

    // Revocation affects existing descriptors, including EOF and empty reads.
    cgroup::delegate_cgroup(parent.id(), None, true).unwrap();
    assert_eq!(handle.read(&mut buf), Err(FsError::PermDenied));
    assert_eq!(controls[0].read_at(100, &mut []), Err(FsError::PermDenied));
    assert_eq!(memory_max.write_at(0, b"2048"), Err(FsError::PermDenied));

    task.lock().user_ns = mapped_namespace(0);
    assert!(process::current_is_host_root());
    assert_eq!(read(&memory_max).unwrap(), "4096\n");
    assert!(read(&foreign_stats).is_ok());
    assert_eq!(controls[0].stat().unwrap().mode.perm, 0o444);
    assert_eq!(controls[0].write_at(0, b"0"), Err(FsError::PermDenied));

    // ADMIN is an independent grant, including for a task without a UID map.
    let authority = task.lock().capability_table_authority();
    let credentials = task.lock().shared_credentials();
    let reservation = task
        .lock()
        .prepare_capability_allocation_authorized(&authority, credentials.begin_authorization())
        .unwrap();
    reservation
        .install(cap::CapEntry::new(
            cap::CapObject::Process(1),
            cap::CapRights::ADMIN,
        ))
        .audit();
    for ns in [
        mapped_namespace(1000),
        UserNamespace::new_child(ROOT_USER_NAMESPACE.clone()).unwrap(),
    ] {
        task.lock().user_ns = ns;
        assert!(!process::current_is_host_root());
        assert!(process::current_has_cap_rights(
            kernel_core::CapRights::ADMIN
        ));
        assert!(open(&fs, &foreign_stats).is_ok());
        assert!(read(&foreign_stats).is_ok());
        assert_eq!(memory_max.write_at(0, b"2048").unwrap(), 4);
        assert_eq!(read(&memory_max).unwrap(), "2048\n");
    }

    process::set_current_pid(None);
    assert_eq!(read(&controls[0]), Err(FsError::PermDenied));
    *PROCESS_TABLE.lock().get_mut(1).unwrap() = None;
    cgroup::delete_cgroup(child.id()).unwrap();
    cgroup::delete_cgroup(parent.id()).unwrap();
    cgroup::delete_cgroup(foreign.id()).unwrap();
}
