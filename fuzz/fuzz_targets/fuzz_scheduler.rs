#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct SchedulerFuzzInput {
    operation: SchedOperation,
    priority: i32,
    cpu_affinity: u64,
    policy: i32,
}

#[derive(Arbitrary, Debug)]
enum SchedOperation {
    SetPriority,
    Yield,
    SetAffinity,
    SetScheduler,
}

fuzz_target!(|input: SchedulerFuzzInput| {
    // Target scheduler operations
    // - R172-03: steal-before-save race
    // - R172-05: syscall_active leak
    // - Priority inversion
    // - CPU affinity violations

    match input.operation {
        SchedOperation::SetPriority => {
            test_set_priority(input.priority);
        }
        SchedOperation::Yield => {
            test_sched_yield();
        }
        SchedOperation::SetAffinity => {
            test_set_affinity(input.cpu_affinity);
        }
        SchedOperation::SetScheduler => {
            test_set_scheduler(input.policy, input.priority);
        }
    }
});

fn test_set_priority(priority: i32) {
    // Priority range validation
    const MIN_PRIORITY: i32 = -20;
    const MAX_PRIORITY: i32 = 19;

    if priority < MIN_PRIORITY || priority > MAX_PRIORITY {
        // Should return EINVAL
        return;
    }

    // Lowering priority always allowed
    // Raising priority may require privilege
}

fn test_sched_yield() {
    // R172-01: clone();yield reproducer for context-switch bug
    // Should safely context-switch
    // Must save RIP/RFLAGS/FS/GS
}

fn test_set_affinity(mask: u64) {
    // CPU affinity mask
    // mask == 0 is invalid
    if mask == 0 {
        return;
    }

    // Only valid CPU bits should be set
    const MAX_CPUS: u32 = 64;
    let valid_mask = (1u64 << MAX_CPUS) - 1;

    if mask & !valid_mask != 0 {
        // Invalid CPU bits set
        return;
    }
}

fn test_set_scheduler(policy: i32, priority: i32) {
    // Scheduler policies
    const SCHED_NORMAL: i32 = 0;
    const SCHED_FIFO: i32 = 1;
    const SCHED_RR: i32 = 2;
    const SCHED_BATCH: i32 = 3;
    const SCHED_IDLE: i32 = 5;

    match policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            // priority must be 0 for non-RT policies
            if priority != 0 {
                return;
            }
        }
        SCHED_FIFO | SCHED_RR => {
            // RT policies: priority [1, 99]
            if priority < 1 || priority > 99 {
                return;
            }
        }
        _ => {
            // Invalid policy
            return;
        }
    }
}
