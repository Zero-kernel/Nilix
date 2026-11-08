//! PR86-1: witness actual last-Arc destruction, not merely child exit.
//! Compiled only into the syscall-test image. No observer retains a region Arc.

use super::SharedAnonRegion;

const IDLE: u64 = 0;
const ARMED: u64 = 2;
const RUNNING: u64 = 3;
const PAUSED: u64 = 4;
const RELEASED: u64 = 5;
const COMPLETE: u64 = 6;
const FAILED: u64 = 7;
const CANCELLED: u64 = 8;
const CHURN_ROUNDS: u64 = 4;
const PAUSE_TSC: u64 = 10_000_000_000;

struct Probe {
    epoch: u64,
    state: u64,
    owner: (usize, u64),
    root: usize,
    owner_cpu: usize,
    region: usize,
    reaper: (usize, u64),
    reaper_cpu: usize,
    churn: u64,
    window_open: bool,
    in_flight: bool,
    abandoned: bool,
}

static PROBE: spin::Mutex<Probe> = spin::Mutex::new(Probe {
    epoch: 0,
    state: IDLE,
    owner: (0, 0),
    root: 0,
    owner_cpu: 0,
    region: 0,
    reaper: (0, 0),
    reaper_cpu: 0,
    churn: 0,
    window_open: false,
    in_flight: false,
    abandoned: false,
});

// Never allocate, look up a process, take another lock, or wait in this closure.
// Masking IRQs also prevents teardown on this CPU from reentering the probe lock.
fn with_probe<T>(f: impl FnOnce(&mut Probe) -> T) -> T {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut PROBE.lock()))
}

/// Called with the owner's MmState held, so the observed Arc cannot disappear
/// between validating its two resident pages and publishing its raw identity.
pub fn arm(region: &SharedAnonRegion, pid: usize, generation: u64, root: usize) -> Result<u64, ()> {
    if root == 0
        || cpu_local::current_cpu_id() != 0
        || region.page_count != 2
        || region.resident_pages() != 2
    {
        return Err(());
    }
    with_probe(|p| {
        if p.state != IDLE {
            return Err(());
        }
        let epoch = p.epoch.checked_add(1).ok_or(())?;
        *p = Probe {
            epoch,
            state: ARMED,
            owner: (pid, generation),
            root,
            owner_cpu: cpu_local::current_cpu_id(),
            region: region as *const SharedAnonRegion as usize,
            reaper: (0, 0),
            reaper_cpu: 0,
            churn: 0,
            window_open: false,
            in_flight: false,
            abandoned: false,
        };
        Ok(epoch)
    })
}

/// PR_SHARED_FAULT_TEST: 10=arm(base), 11=state(epoch), 12=churn bracket
/// (epoch, 0=begin/1=end), 13=release(epoch), 14=cancel(epoch), 15=disarm(epoch),
/// 16=register reaper(epoch). All commands after arm carry the same epoch.
pub fn command(
    op: u64,
    epoch: u64,
    arg: u64,
    pid: usize,
    generation: u64,
    root: usize,
) -> Result<u64, ()> {
    with_probe(|p| {
        if p.state == IDLE || epoch != p.epoch || root != p.root {
            return Err(());
        }
        if op == 16 {
            let cpu = cpu_local::current_cpu_id();
            if p.state != ARMED || p.reaper != (0, 0) || pid == p.owner.0 || cpu != 1 {
                return Err(());
            }
            p.reaper = (pid, generation);
            p.reaper_cpu = cpu;
            return Ok(0);
        }
        if p.owner != (pid, generation) || cpu_local::current_cpu_id() != p.owner_cpu {
            return Err(());
        }
        match op {
            11 => Ok(p.state),
            12 if p.state == PAUSED && arg <= 1 && p.window_open == (arg == 1) => {
                if arg == 1 {
                    p.churn = p.churn.checked_add(1).ok_or(())?;
                }
                p.window_open = arg == 0;
                Ok(0)
            }
            13 if p.state == PAUSED && p.churn == CHURN_ROUNDS && !p.window_open => {
                p.state = RELEASED;
                Ok(0)
            }
            14 => {
                p.state = if p.in_flight { CANCELLED } else { FAILED };
                Ok(0)
            }
            15 if !p.in_flight && matches!(p.state, COMPLETE | FAILED) => {
                p.state = IDLE;
                Ok(0)
            }
            _ => Err(()),
        }
    })
}

/// Entered only by a region's actual last-Arc destructor. A pointer is compared,
/// never dereferenced; IDLE/rearm is forbidden until an in-flight hook finishes.
pub fn begin(region: usize) -> Option<u64> {
    with_probe(|p| {
        if p.state != ARMED || p.region != region {
            return None;
        }
        if crate::process::current_pid() != Some(p.reaper.0)
            || p.reaper.0 == 0
            || cpu_local::current_cpu_id() != p.reaper_cpu
        {
            p.state = FAILED;
            return None;
        }
        p.in_flight = true;
        p.state = RUNNING;
        Some(p.epoch)
    })
}

/// First DATA frame has actually been returned and its charge released. No PT,
/// buddy, cgroup-registry or probe lock is held while waiting. Only the detached
/// victim PCB and its exclusively dying region's page slots remain locked.
pub fn midpoint(epoch: u64, freed: bool) {
    let paused = with_probe(|p| {
        if p.epoch != epoch || p.state != RUNNING || !freed {
            return false;
        }
        p.state = PAUSED;
        true
    });
    if !paused {
        return;
    }
    let start = crate::time::read_tsc();
    loop {
        if !with_probe(|p| p.epoch == epoch && p.state == PAUSED) {
            return;
        }
        if crate::time::read_tsc().wrapping_sub(start) >= PAUSE_TSC {
            with_probe(|p| {
                if p.epoch == epoch && p.state == PAUSED {
                    p.state = FAILED;
                }
            });
            return;
        }
        core::hint::spin_loop();
    }
}

/// COMPLETE means both DATA frames and charges were released, after four
/// successful churn brackets in the middle of this exact destructor epoch.
pub fn complete(epoch: u64, freed: usize) {
    with_probe(|p| {
        if p.epoch != epoch || !p.in_flight {
            return;
        }
        p.in_flight = false;
        p.state = if p.abandoned {
            IDLE
        } else if p.state == RELEASED && freed == 2 {
            COMPLETE
        } else {
            FAILED
        };
    });
}

/// Teardown winner, before PID reuse. A vanished owner cancels the wait but
/// cannot make its slot reusable until the old hook has finished. A reaper that
/// exits after COMPLETE leaves the verdict available to the owner.
pub fn clear(pid: usize, generation: u64) {
    with_probe(|p| {
        if p.state == IDLE {
            return;
        }
        if p.owner == (pid, generation) {
            p.abandoned = true;
            p.state = if p.in_flight { CANCELLED } else { IDLE };
        } else if p.reaper == (pid, generation) && !matches!(p.state, COMPLETE | FAILED) {
            p.state = if p.in_flight { CANCELLED } else { FAILED };
        }
    });
}
