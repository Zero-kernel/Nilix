# Safety Documentation

This directory contains IRQ safety analysis, lock ordering documentation, and sync primitive migration guides for the Zero-OS kernel.

## IRQ Safety

- **[IRQ_SAFETY_AUDIT.md](IRQ_SAFETY_AUDIT.md)** - Comprehensive IRQ safety audit across all kernel subsystems
- **[IRQ_SAFETY_PROPAGATION_PLAN.md](IRQ_SAFETY_PROPAGATION_PLAN.md)** - Plan for propagating IRQ-safe primitives throughout the codebase
- **[IRQ_LOCK_SITE_INVENTORY.md](IRQ_LOCK_SITE_INVENTORY.md)** - Inventory of all lock sites requiring IRQ safety analysis
- **[R173_IRQ_SAFETY_FIXES_SUMMARY.md](R173_IRQ_SAFETY_FIXES_SUMMARY.md)** - Summary of R173 IRQ safety fixes

## Sync Primitive Migration

- **[SYNC_SAFE_MIGRATION_GUIDE.md](SYNC_SAFE_MIGRATION_GUIDE.md)** - Guide for migrating to IRQ-safe synchronization primitives

## IRQ Safety Overview

### What is IRQ Safety?

IRQ (Interrupt Request) safety ensures that code paths can be safely executed in interrupt context without causing:
- **Deadlocks**: Interrupt handler tries to acquire a lock already held by interrupted code
- **Data races**: Interrupt handler accesses shared data without proper synchronization
- **Invalid operations**: Sleeping/blocking operations in interrupt context

### IRQ Safety Requirements

Code executed in IRQ context must:
1. **Never sleep** - No blocking operations (sleep, wait, block_on)
2. **Use IRQ-safe locks** - Locks that disable interrupts when acquired
3. **Be preemption-aware** - Handle preemption correctly
4. **Avoid long critical sections** - Keep interrupt handlers fast

### IRQ-Safe Primitives

The Zero-OS kernel provides IRQ-safe alternatives to standard sync primitives:

| Standard Primitive | IRQ-Safe Alternative | Use Case |
|-------------------|---------------------|----------|
| `Mutex<T>` | `IrqSafeLock<T>` | Shared data accessed from IRQ context |
| `RwLock<T>` | `IrqSafeRwLock<T>` | Read-heavy data in IRQ paths |
| `SpinLock<T>` | `IrqSpinLock<T>` | Low-contention IRQ-safe locks |

### Migration Strategy

1. **Identify IRQ paths** - Trace all interrupt handlers and their call chains
2. **Audit lock sites** - Find all locks acquired in IRQ-reachable code
3. **Replace primitives** - Migrate to IRQ-safe alternatives
4. **Verify correctness** - Test for deadlocks and races
5. **Document changes** - Update safety invariants

See [SYNC_SAFE_MIGRATION_GUIDE.md](SYNC_SAFE_MIGRATION_GUIDE.md) for detailed migration instructions.

## Lock Hierarchy

Zero-OS enforces a strict lock ordering hierarchy to prevent deadlocks:

### Level 0 (Leaf Locks)
- No locks held while acquiring these
- Examples: per-CPU data structures, statistics counters

### Level 1 (Resource Locks)
- Process/thread state locks
- File descriptor locks
- Socket locks

### Level 2 (Subsystem Locks)
- VFS locks (inode, dentry)
- Network protocol locks
- Memory allocator locks

### Level 3 (Global Locks)
- Process table lock
- Cgroup hierarchy lock
- Mount namespace lock

**Rule**: Always acquire locks in increasing level order. Never acquire a lower-level lock while holding a higher-level lock.

## Common IRQ Safety Issues

### Issue 1: Timer IRQ Deadlock
```rust
// BAD: Non-IRQ-safe lock in timer path
fn on_timer_interrupt() {
    let proc = PROCESS_TABLE.lock(); // Can deadlock if lock already held
    // ...
}
```

**Fix**: Use IRQ-safe lock or defer work to process context.

### Issue 2: Lock Acquired in Both Contexts
```rust
// BAD: Same lock used in IRQ and process context
fn process_context() {
    let data = SHARED_DATA.lock(); // Regular lock
    // ... interrupted by IRQ here ...
}

fn irq_handler() {
    let data = SHARED_DATA.lock(); // Deadlock!
}
```

**Fix**: Replace with `IrqSafeLock` or refactor to avoid shared state.

### Issue 3: Sleeping in IRQ Context
```rust
// BAD: Blocking operation in IRQ
fn irq_handler() {
    block_on(async_operation()); // Panic!
}
```

**Fix**: Defer async work to a dedicated task/thread.

## Verification Methods

1. **Static Analysis**: Grep for non-IRQ-safe primitives in IRQ paths
2. **Code Review**: Manual review with Codex convergence gate
3. **Runtime Testing**: Boot with IRQ stress tests
4. **Lockdep**: Runtime lock ordering verification (future work)

## Related Documentation

- **[../review/audits/](../review/audits/)** - Security audits covering IRQ safety
- **[../review/fixes/r173-*.md](../review/fixes/)** - R173 IRQ safety fix implementation
- **[../architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md)** - Subsystem architecture and dependencies
- **[../../kernel/sync_safe/](../../kernel/sync_safe/)** - IRQ-safe primitive implementations

## R173 IRQ Safety Campaign

The R173 audit identified systematic IRQ safety violations across the codebase. Key fixes:

- **Timer IRQ paths**: Converted to IRQ-safe locks
- **FPU state management**: Fixed timer IRQ FPU state leaks
- **Process table locking**: Migrated to `IrqSafeLock`
- **Lock site inventory**: Documented all 100+ lock sites

See [R173_IRQ_SAFETY_FIXES_SUMMARY.md](R173_IRQ_SAFETY_FIXES_SUMMARY.md) for the complete fix summary.
