# Fuzz Infrastructure: Next Steps

**Date:** 2026-07-04  
**Current Status:** libFuzzer working for parsers, AFL++ infrastructure complete but incompatible with bare-metal kernel

---

## Current State

### ✅ Working libFuzzer Targets (Real Kernel Code)

| Target | Corpus | Exec/sec | Status |
|--------|--------|----------|--------|
| `fuzz_elf_loader` | 961 units | 406,825 | ✅ Working |
| `fuzz_network_packet` | 703 units | 176,331 | ✅ Working |
| `fuzz_vfs_path` | 1,115 units | 105,142 | ✅ Working |

**Why they work:** These targets call **real kernel parsers** that are stateless validators. No kernel state machine required.

### ❌ Broken libFuzzer Targets (Hitting Stubs)

All show <60 coverage paths, "no interesting inputs" warnings:
- `fuzz_syscall`
- `fuzz_signal_delivery`
- `fuzz_memory_ops`
- `fuzz_ipc_message`
- `fuzz_scheduler`
- `fuzz_cgroup_ops`
- `fuzz_futex_ops`

**Root cause:** These subsystems are **stateful** and require kernel context (process tables, memory manager, VFS root, signal queues). The `host_harness` feature gates make them empty shells.

### ✅ AFL++ Infrastructure (Complete but Incompatible)

**What's ready:**
- ✅ AFL++ built with QEMU mode (`afl-fuzz++4.00c`, `afl-qemu-trace`)
- ✅ Seed generation (10 binary syscall traces)
- ✅ Scripts: `afl_fuzz.sh`, `afl_parallel.sh`, `afl_triage.sh`
- ✅ CI workflow: `.github/workflows/afl_fuzz.yml`
- ✅ Makefile targets: `make afl-fuzz`, `make afl-fuzz-parallel`
- ✅ Documentation: `fuzz/afl/README.md`

**Why it can't run:**
- ❌ Your kernel is `x86_64-unknown-none` (bare-metal UEFI boot)
- ❌ AFL++ QEMU mode fuzzes `x86_64-linux-gnu` userspace binaries
- ❌ Kernel has no `main()`, no `fork()`, no Linux syscalls
- ❌ QEMU userspace mode fails: "Unable to request new process from fork server"

**Viable paths forward:**
1. QEMU **system** mode (boot full kernel, 100-1000x slower)
2. Extract components as Linux userspace test programs
3. Focus on libFuzzer (recommended)

---

## Recommended Plan: Fix libFuzzer Targets

### Phase 1: Mark Broken Targets (Immediate)

Add `#[ignore]` to broken targets with clear TODO comments:

```rust
#[ignore = "Hitting stub: needs mock kernel context (process table, mm, vfs)"]
#[cfg(fuzzing)]
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    // TODO: Implement stateful mock harness
    // See: docs/fuzz/NEXT_STEPS.md Phase 2
    0
}
```

**Result:** CI won't report false positives, broken targets are documented.

### Phase 2: Implement Mock Kernel Context (Short-term)

Create `kernel/fuzz_harness/mock_kernel.rs`:

```rust
pub struct MockKernelContext {
    process_table: BTreeMap<Pid, MockProcess>,
    memory_manager: MockMemoryManager,
    vfs_root: MockVfsRoot,
    signal_queues: BTreeMap<Pid, VecDeque<Signal>>,
}

impl MockKernelContext {
    pub fn new() -> Self { /* minimal valid state */ }
    
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> Result<u64, SyscallError> {
        // Dispatch to REAL kernel syscall handlers
        // but with mock backing stores
        match nr {
            SYS_READ => self.sys_read(args[0], args[1], args[2]),
            SYS_OPEN => self.sys_open(args[0], args[1]),
            // ... delegate to real handlers
        }
    }
}
```

**Key principle:** Reuse **real kernel code**, only mock the backing stores (process table, page tables, file handles).

### Phase 3: Rewrite Broken Targets (Medium-term)

Example: `fuzz_syscall`

```rust
#[cfg(fuzzing)]
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if size < 56 { return 0; } // Need syscall_nr + 6 args
    
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    let mut ctx = MOCK_KERNEL.lock();
    
    // Parse syscall from fuzz input
    let nr = u64::from_le_bytes(slice[0..8].try_into().unwrap());
    let args = [
        u64::from_le_bytes(slice[8..16].try_into().unwrap()),
        u64::from_le_bytes(slice[16..24].try_into().unwrap()),
        // ... parse all 6 args
    ];
    
    // Call REAL kernel syscall handler
    let _ = ctx.syscall(nr, args);
    
    0
}
```

**Result:** Fuzzer exercises real kernel logic, not stubs.

### Phase 4: Add Stateful Sequences (Long-term)

Create `fuzz_syscall_sequence` that maintains context across calls:

```rust
#[cfg(fuzzing)]
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    let syscalls = parse_syscall_sequence(data, size);
    let mut ctx = MockKernelContext::new();
    
    for (nr, args) in syscalls {
        let _ = ctx.syscall(nr, args);
        // Context persists: open() returns fd, read() uses that fd
    }
    
    0
}
```

**Result:** Deep testing of syscall interactions (open→read→close, fork→exec, mmap→write→munmap).

---

## Alternative: Extract Components for AFL++

If you want to use AFL++ QEMU mode:

### Create Userspace Test Programs

Example: `fuzz_targets/afl_elf_parser.rs`

```rust
// Compile with: --target x86_64-unknown-linux-gnu
use std::env;
use std::fs;

fn main() {
    let input = env::args().nth(1).expect("Usage: afl_elf_parser <input>");
    let data = fs::read(input).expect("Failed to read input");
    
    // Call REAL kernel ELF parser
    unsafe {
        kernel::elf_loader::parse_elf(&data);
    }
}
```

**Build:**
```bash
cargo build --target x86_64-unknown-linux-gnu --bin afl_elf_parser
```

**Fuzz:**
```bash
make afl-fuzz --kernel=target/x86_64-unknown-linux-gnu/release/afl_elf_parser
```

**Pros:** Full AFL++ power, stateless parsers work great  
**Cons:** Can't fuzz stateful kernel interactions, need separate build

---

## Timeline Estimates

| Phase | Effort | Impact |
|-------|--------|--------|
| Mark broken targets | 1 hour | Stops false CI signals |
| Mock kernel context | 2-3 days | Unblocks all broken targets |
| Rewrite 7 broken targets | 3-5 days | Full syscall coverage |
| Stateful sequences | 1-2 days | Deep interaction testing |
| AFL++ userspace wrappers | 2-3 days | Optional, for parsers only |

---

## Recommendation

**Focus on libFuzzer Phase 1-3:**

1. ✅ **Today:** Mark broken targets as `#[ignore]` with TODO comments
2. ✅ **This week:** Implement `MockKernelContext` with minimal process/mm/vfs state
3. ✅ **Next week:** Rewrite `fuzz_syscall` to use mock context, verify it works
4. ✅ **Following week:** Port remaining 6 broken targets

**AFL++ infrastructure stays ready for:**
- Future userspace test programs
- Full-kernel QEMU system mode (if needed)
- Documentation reference

**Why this approach:**
- ✅ Fixes the actual problem (stubs → real code)
- ✅ Faster than AFL++ QEMU system mode (100-1000x)
- ✅ Better coverage than isolated userspace wrappers
- ✅ Reuses real kernel code (not reimplementing logic)

---

## References

- **Current implementation:** `kernel/fuzz/lib.rs`
- **Working targets:** `fuzz_elf_loader`, `fuzz_network_packet`, `fuzz_vfs_path`
- **AFL++ docs:** `fuzz/afl/README.md`, `docs/fuzz/IMPLEMENTATION.md`
- **CI results:** `.github/workflows/fuzz.yml` (now generates reports)
