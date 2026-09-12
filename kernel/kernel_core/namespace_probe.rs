//! Default-off allocation and four-CPU namespace tests before Ring-3 admission.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc_namespace::{IpcNamespace, IpcNsError};
use crate::mount_namespace::namespace_accounting::{NamespaceCreateContext, NamespaceCreateStage};
use crate::mount_namespace::{MountNamespace, MountNsError};
use crate::user_namespace::{UserNamespace, UserNsError};

const LIMIT: u32 = 4;
const ROUNDS: u32 = 8;
static COUNT: AtomicU32 = AtomicU32::new(1);
// Factories replace this with their production ID source before reserving an ID.
static UNUSED_IDS: AtomicU64 = AtomicU64::new(1);
static STARTED: AtomicBool = AtomicBool::new(false);
static FAULT_OBSERVED: AtomicBool = AtomicBool::new(false);
static PHASE: AtomicU32 = AtomicU32::new(0);
static KIND: AtomicU32 = AtomicU32::new(0);
static EXPECTED: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
static SUCCEEDED: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);
static LAST_PHASE: [AtomicU32; cpu_local::MAX_CPUS] =
    [const { AtomicU32::new(0) }; cpu_local::MAX_CPUS];
static OWNERS: [Mutex<Option<Object>>; cpu_local::MAX_CPUS] =
    [const { Mutex::new(None) }; cpu_local::MAX_CPUS];

#[derive(Clone)]
enum Object {
    Mount(Arc<MountNamespace>),
    Ipc(Arc<IpcNamespace>),
    User(Arc<UserNamespace>),
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Allocation,
    Limit,
}

fn context() -> NamespaceCreateContext {
    NamespaceCreateContext::new(&COUNT, &UNUSED_IDS, LIMIT)
}

fn create(kind: u32, context: NamespaceCreateContext) -> Result<Object, Failure> {
    match kind {
        0 => MountNamespace::probe_child(context)
            .map(Object::Mount)
            .map_err(|error| match error {
                MountNsError::NoMemory => Failure::Allocation,
                MountNsError::MaxCountExceeded => Failure::Limit,
                other => panic!("unexpected mount probe error: {other:?}"),
            }),
        1 => IpcNamespace::probe_child(context)
            .map(Object::Ipc)
            .map_err(|error| match error {
                IpcNsError::OutOfMemory => Failure::Allocation,
                IpcNsError::MaxNamespaces => Failure::Limit,
                other => panic!("unexpected IPC probe error: {other:?}"),
            }),
        2 => UserNamespace::probe_child(context)
            .map(Object::User)
            .map_err(|error| match error {
                UserNsError::OutOfMemory => Failure::Allocation,
                UserNsError::MaxNamespaces => Failure::Limit,
                other => panic!("unexpected user probe error: {other:?}"),
            }),
        _ => panic!("invalid namespace probe kind"),
    }
}

fn resources() -> (usize, usize) {
    let snapshot = mm::heap_class_snapshot(mm::HeapClass::CoreProcess);
    (snapshot.committed_bytes, snapshot.reserved_bytes)
}

fn serial_checks(kind: u32) {
    let baseline = resources();
    let live = create(kind, context()).expect("probe sibling");
    let live_resources = resources();
    assert_eq!(COUNT.load(Ordering::Acquire), 2);
    let stages = [
        NamespaceCreateStage::RootPath,
        NamespaceCreateStage::ArcLayout,
        NamespaceCreateStage::HeapReserve,
        NamespaceCreateStage::ArcAllocation,
        NamespaceCreateStage::HeapCommit,
    ];
    for stage in stages {
        if kind != 0 && stage == NamespaceCreateStage::RootPath {
            continue;
        }
        for _ in 0..4 {
            FAULT_OBSERVED.store(false, Ordering::Release);
            assert_eq!(
                create(kind, context().with_fault(stage, &FAULT_OBSERVED)).err(),
                Some(Failure::Allocation)
            );
            assert!(
                FAULT_OBSERVED.load(Ordering::Acquire),
                "requested constructor injection did not fire"
            );
            assert_eq!(COUNT.load(Ordering::Acquire), 2);
            assert_eq!(
                resources(),
                live_resources,
                "constructor failure leaked a heap charge"
            );
        }
    }
    let retained = live.clone();
    drop(live);
    assert_eq!(COUNT.load(Ordering::Acquire), 2);
    assert_eq!(resources(), live_resources);
    drop(retained);
    assert_eq!(COUNT.load(Ordering::Acquire), 1);
    assert_eq!(resources(), baseline);

    // Actual class admission failure, distinct from boundary/Arc injection.
    let limit = mm::HeapClass::CoreProcess.limit_bytes();
    let headroom = limit.checked_sub(baseline.0 + baseline.1).unwrap();
    let pressure = mm::try_reserve_heap(mm::HeapClass::CoreProcess, headroom)
        .expect("probe must reserve the remaining class budget");
    assert_eq!(resources(), (baseline.0, baseline.1 + headroom));
    assert_eq!(resources().0 + resources().1, limit);
    assert_eq!(create(kind, context()).err(), Some(Failure::Allocation));
    assert_eq!(COUNT.load(Ordering::Acquire), 1);
    assert_eq!(resources(), (baseline.0, baseline.1 + headroom));
    drop(pressure);
    assert_eq!(resources(), baseline);
    klog::klog_always!("KSA-003-RESOURCE PASS kind={} boundaries={} attempts=4 rejected_arc=1 admission_pressure=1 last_reference=1 counts=exact heap=exact",
        kind, if kind == 0 { 5 } else { 4 });
}

/// One bounded step, called only by BSP controller or IRQ-enabled AP idle loop.
pub fn step() {
    let phase = PHASE.load(Ordering::Acquire);
    if phase == 0 {
        return;
    }
    assert!(x86_64::instructions::interrupts::are_enabled());
    let cpu = cpu_local::current_cpu_id();
    let bit = 1u64
        .checked_shl(cpu as u32)
        .expect("probe CPU outside mask");
    assert_ne!(EXPECTED.load(Ordering::Acquire) & bit, 0);
    if LAST_PHASE[cpu].load(Ordering::Acquire) == phase {
        return;
    }
    LAST_PHASE[cpu].store(phase, Ordering::Release);
    if phase & 1 != 0 {
        assert!(OWNERS[cpu].lock().is_none());
        match create(KIND.load(Ordering::Acquire), context()) {
            Ok(owner) => {
                *OWNERS[cpu].lock() = Some(owner);
                SUCCEEDED.fetch_or(bit, Ordering::Release);
            }
            Err(Failure::Limit) => {
                REJECTED.fetch_or(bit, Ordering::Release);
            }
            Err(other) => panic!("unexpected parallel namespace error: {other:?}"),
        }
    } else {
        let owner = OWNERS[cpu].lock().take();
        drop(owner);
    }
    // Final shared-state action: all guards/temporaries are gone and payload
    // ownership has transferred or been released before the controller observes ACK.
    COMPLETED.fetch_or(bit, Ordering::Release);
}

fn phase(phase: u32, mask: u64, wake: fn()) {
    COMPLETED.store(0, Ordering::Relaxed);
    PHASE.store(phase, Ordering::Release);
    wake();
    let started = crate::time::current_timestamp_ms();
    for _ in 0..10_000_000 {
        step();
        if COMPLETED.load(Ordering::Acquire) == mask {
            return;
        }
        assert!(
            crate::time::current_timestamp_ms().wrapping_sub(started) < 5000,
            "namespace probe CPU acknowledgement timed out"
        );
        core::hint::spin_loop();
    }
    panic!("namespace probe CPU acknowledgement exceeded finite spin budget");
}

/// Run once after AP deferred acknowledgements and before scheduling Ring 3.
pub fn run(mask: u64, wake: fn()) {
    assert!(!STARTED.swap(true, Ordering::AcqRel));
    assert!(x86_64::instructions::interrupts::are_enabled());
    assert_eq!(
        mask.count_ones(),
        4,
        "namespace probe requires four actual CPUs"
    );
    assert_ne!(mask & (1u64 << cpu_local::current_cpu_id()), 0);
    EXPECTED.store(mask, Ordering::Release);
    for kind in 0..3 {
        drop(create(kind, context()).expect("warm namespace roots"));
    }
    assert_eq!(COUNT.load(Ordering::Acquire), 1);
    for kind in 0..3 {
        serial_checks(kind);
        let baseline = resources();
        KIND.store(kind, Ordering::Relaxed);
        for round in 0..ROUNDS {
            let acquire = 1 + (kind * ROUNDS + round) * 2;
            SUCCEEDED.store(0, Ordering::Relaxed);
            REJECTED.store(0, Ordering::Relaxed);
            phase(acquire, mask, wake);
            let successes = SUCCEEDED.load(Ordering::Acquire);
            let rejected = REJECTED.load(Ordering::Acquire);
            assert_eq!(successes.count_ones(), LIMIT - 1);
            assert_eq!(rejected.count_ones(), 1);
            assert_eq!(successes & rejected, 0);
            assert_eq!(successes | rejected, mask);
            assert_eq!(COUNT.load(Ordering::Acquire), LIMIT);
            phase(acquire + 1, mask, wake);
            assert_eq!(COUNT.load(Ordering::Acquire), 1);
            assert!(OWNERS.iter().all(|slot| slot.lock().is_none()));
            assert_eq!(
                resources(),
                baseline,
                "SMP namespace heap charges did not restore"
            );
        }
        klog::klog_always!("KSA-003-SMP PASS kind={} cpu_mask={:#x} rounds={} limit=4 winners=3 rejected=1 counts=exact heap=exact", kind, mask, ROUNDS);
    }
    PHASE.store(0, Ordering::Release);
    assert_eq!(
        UNUSED_IDS.load(Ordering::Acquire),
        1,
        "factory failed to use production IDs"
    );
    klog::klog_always!("KSA-003-PROBES PASS types=3 cpus=4 rounds=24 counts=exact heap=exact");
}
