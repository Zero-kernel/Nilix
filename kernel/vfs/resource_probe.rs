//! Default-off VFS ownership/retirement proof on a not-yet-admitted syscall stack.
use super::*;
use crate::path::ResolvedPath;
use crate::topology;
use mm::{AdmittedVec, HeapClass};

const DEPTH: usize = 600;
const COMPONENT: &str = "branch";
const COVERED: &str = "/__ksa_vfs_resource_probe";
const POISON: u8 = 0xa5;

fn resources() -> [(usize, usize); 3] {
    [HeapClass::Vfs, HeapClass::RamFs, HeapClass::CoreProcess].map(|class| {
        let value = mm::heap_class_snapshot(class);
        (value.committed_bytes, value.reserved_bytes)
    })
}

fn frames() -> Result<usize, FsError> {
    mm::buddy_allocator::get_allocator_stats()
        .map(|stats| stats.free_pages)
        .ok_or(FsError::Invalid)
}

fn exhaust(class: HeapClass) -> Result<mm::HeapReservation, FsError> {
    let current = mm::heap_class_snapshot(class);
    let remaining = current
        .capacity_bytes
        .checked_sub(current.committed_bytes + current.reserved_bytes)
        .ok_or(FsError::Invalid)?;
    mm::try_reserve_heap(class, remaining).map_err(|_| FsError::NoMem)
}

fn workload(detached: bool) -> Result<(), FsError> {
    let namespace =
        MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).map_err(|_| FsError::NoMem)?;
    VFS.materialize_namespace(&namespace)?;
    let fs = RamFs::try_new()?;
    VFS.mount_in_namespace(&namespace, COVERED, fs.clone())?;
    let mut nodes = AdmittedVec::new(HeapClass::Vfs);
    nodes
        .try_reserve_exact(DEPTH + 1)
        .map_err(|_| FsError::NoMem)?;
    nodes
        .push_reserved(fs.root_inode())
        .map_err(|_| FsError::NoMem)?;
    for _ in 0..DEPTH {
        let parent = nodes.last().ok_or(FsError::Invalid)?;
        let child = fs.create(
            parent,
            COMPONENT,
            FileMode::directory(0o755),
            &topology::write().setup(0, 0),
        )?;
        nodes.push_reserved(child).map_err(|_| FsError::NoMem)?;
    }
    let cwd = if detached {
        let table = VFS
            .mount_tables
            .read()
            .get(&namespace.id())
            .cloned()
            .ok_or(FsError::Invalid)?;
        let view = table.view.read();
        let epoch = view.epoch;
        let mount = view
            .mounts
            .values()
            .find(|mount| mount.fs.fs_id() == fs.fs_id())
            .cloned()
            .ok_or(FsError::Invalid)?;
        drop(view);
        drop(table);
        let path = ResolvedPath {
            mount,
            inode: nodes.last().ok_or(FsError::Invalid)?.clone(),
            epoch,
        };
        Some(path.directory_handle()?)
    } else {
        None
    };

    // Exhaust class credit at retirement entry. Deallocation releases credit;
    // the hosted probe independently counts raw allocator requests throughout
    // retirement to prove that those newly released credits are never needed.
    let vfs_exhausted = exhaust(HeapClass::Vfs)?;
    let ramfs_exhausted = exhaust(HeapClass::RamFs)?;
    if detached {
        for index in (1..nodes.len()).rev() {
            fs.unlink(
                &nodes[index - 1],
                COMPONENT,
                nodes[index].ino(),
                Some(true),
                &topology::write().setup(0, 0),
            )?;
        }
    }
    drop(nodes);
    drop(fs);
    drop(namespace); // Real exact-ID callback removes the last table owner.
    drop(cwd); // Real opaque directory handle releases the retained-parent chain.
    drop(ramfs_exhausted);
    drop(vfs_exhausted);
    Ok(())
}

fn run_checks() -> Result<(), FsError> {
    match VFS.create_trusted(COVERED, FileMode::directory(0o755)) {
        Ok(_) | Err(FsError::Exists) => {}
        Err(error) => return Err(error),
    }
    workload(true)?;
    workload(false)?;
    let baseline = resources();
    let baseline_frames = frames()?;
    let baseline_tables = VFS.mount_tables.read().len();
    for detached in [true, false] {
        workload(detached)?;
        if resources() != baseline
            || frames()? != baseline_frames
            || VFS.mount_tables.read().len() != baseline_tables
        {
            return Err(FsError::Io);
        }
    }
    Ok(())
}

struct Outcome {
    result: Result<(), FsError>,
}

extern "sysv64" fn body(output: *mut core::ffi::c_void) {
    // SAFETY: run supplies its exclusive, still-live Outcome on the original
    // stack. That allocation is disjoint from the borrowed syscall stack.
    unsafe {
        (*output.cast::<Outcome>()).result = run_checks();
    }
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global zero_vfs_probe_stack_call",
    ".type zero_vfs_probe_stack_call,@function",
    "zero_vfs_probe_stack_call:",
    "push r12",
    "pushfq",
    "cli",
    "mov r12, rsp",
    "mov rsp, rdi",
    "and rsp, -16",
    "mov rdi, rdx",
    "call rsi",
    "mov rsp, r12",
    "popfq",
    "pop r12",
    "ret",
    ".size zero_vfs_probe_stack_call, .-zero_vfs_probe_stack_call",
);

#[cfg(target_os = "none")]
unsafe extern "sysv64" {
    fn zero_vfs_probe_stack_call(
        top: usize,
        callback: extern "sysv64" fn(*mut core::ffi::c_void),
        output: *mut core::ffi::c_void,
    );
}

/// Run only at main's audited pre-admission boundary.
///
/// # Safety
/// The PCB must never have been passed to reserve/add/resume on any scheduler
/// queue. No CPU may run it or access its kernel stack until this call returns.
/// Process-table presence alone does not meet or violate that queue precondition.
#[cfg(target_os = "none")]
pub unsafe fn run(process: &kernel_core::process::ProcessArc) {
    let (base, top) = {
        let proc = process.lock();
        proc.owned_probe_stack_bounds()
            .expect("VFS probe requires the pending task's owned idle stack")
    };
    let size = top
        .checked_sub(base)
        .expect("VFS probe stack bounds reversed");
    assert!(base != 0 && base & 4095 == 0 && top & 4095 == 0);
    assert!(
        (16 * 1024..=64 * 1024).contains(&size),
        "VFS probe usable stack range is outside its admitted bound"
    );
    // The temporary immutable slice ends at this statement; no slice into the
    // borrowed stack exists while the assembly wrapper executes on it.
    let saved = AdmittedVec::try_copy_from_slice(
        HeapClass::Vfs,
        core::slice::from_raw_parts(base as *const u8, size),
    )
    .expect("VFS probe stack-save admission/allocation failed");
    core::ptr::write_bytes(base as *mut u8, POISON, size);
    let before_if: usize;
    core::arch::asm!("pushfq", "pop {}", out(reg) before_if, options(preserves_flags));
    let mut outcome = Outcome {
        result: Err(FsError::Again),
    };
    zero_vfs_probe_stack_call(top, body, (&mut outcome as *mut Outcome).cast());
    let after_if: usize;
    core::arch::asm!("pushfq", "pop {}", out(reg) after_if, options(preserves_flags));
    let touched = {
        let observed = core::slice::from_raw_parts(base as *const u8, size);
        size - observed
            .iter()
            .position(|byte| *byte != POISON)
            .unwrap_or(size)
    };
    // Restore on every returning workload result, before validating that result.
    core::ptr::copy_nonoverlapping(saved.as_ptr(), base as *mut u8, size);
    let restored = core::slice::from_raw_parts(base as *const u8, size) == saved.as_slice();
    drop(saved);
    assert!(
        restored,
        "VFS probe changed the pending task's launch stack"
    );
    assert_eq!(
        before_if & (1 << 9),
        after_if & (1 << 9),
        "VFS probe did not restore IF"
    );
    assert_eq!(
        outcome.result,
        Ok(()),
        "VFS probe resource/retirement workload failed"
    );
    assert!(
        touched > 0 && touched <= size - 4096,
        "VFS probe exceeded its stack headroom: {touched}/{size}"
    );
    klog_always!("KSA-VFS-RESOURCE PASS depth={} path_bytes={} cases=last-cwd,final-namespace stack_bytes={} stack_touched={} stack_restored=true tables=exact heap_vfs=exact heap_ramfs=exact heap_core=exact frames=exact admission_exhausted_at_entry=true", DEPTH, DEPTH * (COMPONENT.len() + 1), size, touched);
}

#[cfg(not(target_os = "none"))]
pub unsafe fn run(_process: &kernel_core::process::ProcessArc) {
    panic!("VFS syscall-stack probe requires the actual kernel target");
}
