# Nilix Fuzzing Infrastructure Documentation Index

**Project:** Nilix (formerly Zero-OS) Kernel  
**Goal:** syzkaller-style coverage-guided fuzzing infrastructure  
**Status:** 🚧 KCOV primitives and cargo-fuzz targets are active; the host-driven QEMU loop is not yet connected

---

## Current implementation status

The phase documents below record the intended seven-phase architecture and historical milestones.
They are not all active in the current CI data path. Today, GitHub Actions runs three host-safe
cargo-fuzz targets that call kernel parsers on pushes, all 10 registered targets on scheduled/manual
runs, and a separate KCOV build/pipeline smoke. Seven of the 10 targets are self-contained model
harnesses. The smoke simulator executes no kernel input and is intentionally unable to create crash
evidence. Host-driven mutation and coverage feedback for a QEMU Nilix guest remain future work.

- **7,460+ lines of code** across 20 modules
- **33,000+ words of documentation** across 28 files
- **CI integration** for cargo-fuzz and KCOV build validation
- **Opaque private-candidate triage** and security-aware public pointers
- **Architecture prototypes** for the future syzkaller-style guest loop

---

## Quick Navigation

### 📖 Read First
- **This index and the live [workflow](../../.github/workflows/fuzz.yml)** are the current operational reference.
- Retired CI integration/refactoring notes are intentionally not operational references; their
  simulator, public-artifact, and reproducer-upload flows are unsafe.
- **[PHASE7_COMPLETE.md](PHASE7_COMPLETE.md)** - Historical completion report, not current CI behavior
- **[phase7-architecture.md](phase7-architecture.md)** - Historical CI integration design
- **[PHASE6_COMPLETE.md](PHASE6_COMPLETE.md)** - Phase 6 completion report
- **[PHASE5_COMPLETE.md](PHASE5_COMPLETE.md)** - Phase 5 completion report
- **[PHASE4_COMPLETE.md](PHASE4_COMPLETE.md)** - Phase 4 completion report
- **[PHASE3_COMPLETE.md](PHASE3_COMPLETE.md)** - Phase 3 completion report
- **[PHASE2_COMPLETE.md](PHASE2_COMPLETE.md)** - Phase 2 completion report

### 🏗️ Architecture & Design
- **[syzkaller-architecture.md](syzkaller-architecture.md)** - Complete 7-phase architecture (13,000+ words)
  - Phase 1: Minimal KCOV ✅
  - Phase 2: Multi-syscall executor ✅
  - Phase 3: Syscall descriptions ✅
  - Phase 4: Coverage-guided mutation ✅
  - Phase 5: Resource tracking ✅
  - Phase 6: Stateful fuzzing ✅
  - Phase 7: CI integration 🚧 partially integrated; the QEMU feedback loop remains future work
- **[phase7-architecture.md](phase7-architecture.md)** - Phase 7 detailed design ⭐ NEW
- **[phase6-architecture.md](phase6-architecture.md)** - Phase 6 detailed design
- **[phase5-architecture.md](phase5-architecture.md)** - Phase 5 detailed design
- **[phase4-architecture.md](phase4-architecture.md)** - Phase 4 detailed design

### 📝 Implementation Reports
- **[phase1-implementation.md](phase1-implementation.md)** - Phase 1 tracking (historical)
- **[phase2-completion.md](phase2-completion.md)** - Phase 2 technical deep-dive
- **[PHASE3_COMPLETE.md](PHASE3_COMPLETE.md)** - Phase 3 syscall descriptions
- **[PHASE4_COMPLETE.md](PHASE4_COMPLETE.md)** - Phase 4 coverage-guided mutation
- **[PHASE5_COMPLETE.md](PHASE5_COMPLETE.md)** - Phase 5 resource-aware fuzzing
- **[PHASE6_COMPLETE.md](PHASE6_COMPLETE.md)** - Phase 6 stateful fuzzing
- **[PHASE7_COMPLETE.md](PHASE7_COMPLETE.md)** - Phase 7 CI integration ⭐ NEW

---

## Phase 7 design artifacts (partially integrated)

### CI Integration & Continuous Fuzzing
```
userspace/fuzzer/
├── continuous.rs                   Continuous fuzzing loop (280 lines)
├── crash_triage.rs                 Crash deduplication (260 lines)
├── corpus_sync.rs                  Corpus synchronization (240 lines)
└── dashboard.rs                    Performance dashboard (220 lines)

.github/workflows/
└── fuzzing.yml                     GitHub Actions pipeline (150 lines)

Total: ~1,150 lines
```

### Active CI features
- **Push fuzzing:** Short runs of VFS, network, and ELF targets that call real kernel parser code
- **Scheduled fuzzing:** All 10 cargo-fuzz targets
- **Private candidate triage:** Raw inputs/logs remain inside the ephemeral runner; public metadata
  contains only a keyed HMAC ID
- **Corpus caching:** Per-target corpora are saved only after clean runs and are never public artifacts
- **Security-aware issue creation:** Opaque candidates get a workflow pointer, never an automatic reproducer disclosure
- **KCOV/pipeline smoke:** Build validation and dashboard plumbing, explicitly excluded from fuzz evidence

---

## Phase 6 Deliverables

### Stateful Fuzzing Modules
```
userspace/fuzzer/
├── transactions.rs                 Transaction model (280 lines)
├── state_machine.rs                State machine framework (320 lines)
├── stateful_coverage.rs            Stateful coverage tracking (260 lines)
├── ipc_coordinator.rs              IPC coordination (300 lines)
└── minimizer.rs                    Input minimization (280 lines)

Total: ~1,440 lines
```

### Key Features
- **Transaction model:** 5 types (FileIO, MemoryOp, ProcessLifecycle, NetworkIO, Custom)
- **State machines:** 3 pre-defined (FileDescriptor, MemoryRegion, ProcessLifecycle)
- **Stateful coverage:** 3 types (edge, state transition, transaction)
- **IPC coordination:** 3 patterns (fork-exec-wait, pipe, shared memory)
- **Input minimization:** 4 strategies with delta debugging

---

## Phase 5 Deliverables
```

### Key Features
- **Resource tracking:** 4 types (fd, memory, port, pid)
- **Constraint system:** 7 types, 11 syscalls with full constraints
- **Grammar-based generator:** Respects resource dependencies
- **Resource-aware mutation:** 7 strategies with fix-up algorithm
- **Leak detection:** 3 types (NeverClosed, UsedAfterFree, DoubleFree)

---

## Phase 4 Deliverables

### Coverage-Guided Fuzzer
```
userspace/fuzzer/
├── Cargo.toml                      Package manifest
├── main.rs                         Main fuzzer loop (220 lines)
├── mod.rs                          Module declarations
├── corpus.rs                       Corpus management (250 lines)
├── mutator.rs                      Mutation engine (230 lines)
├── executor.rs                     KCOV integration (150 lines)
└── seeds.rs                        Seed corpus (80 lines)

Total: ~900 lines
```

### Key Features
- **Corpus management:** Stores test cases with new coverage (max 1000 entries)
- **8 mutation strategies:** Bit flip, arithmetic, interesting values, insert/delete/duplicate/reorder
- **Energy scheduling:** Prioritizes promising inputs
- **Seed corpus:** 5 hand-crafted test cases (~19 edges baseline)
- **Saturation detection:** Stops early if no new coverage in 2000 iterations

### Phase 3 Deliverables

### Syscall Grammar
```
docs/fuzzing/
└── syscall-grammar.toml            TOML-based descriptions (10 syscalls, 600+ lines)
```

### Random Sequence Generator
```
userspace/
└── syscall_fuzzer.rs               Multi-syscall executor (2-5 chains, 350+ lines)
```

### Instrumented Syscalls
```
kernel/kernel_core/
└── syscall.rs                      +10 instrumented syscalls (24 new edges)
    - sys_read (4 edges)
    - sys_write (4 edges)
    - sys_open (2 edges)
    - sys_close (3 edges)
    - sys_brk (2 edges)
    - sys_mmap (4 edges)
    - sys_munmap (2 edges)
    - sys_fork (1 edge)
    - sys_execve (1 edge)
    - sys_exit (1 edge)
```

---

## Phase 2 Deliverables

### Core Code
```
kernel/coverage/lib.rs              KCOV implementation (500+ lines)
kernel/kernel_core/syscall.rs       5 KCOV syscalls + 6 instrumented syscalls
kernel/kernel_core/process.rs       coverage_buffer field
kernel/src/main.rs                  KCOV init + conditional SMAP
Makefile                            build-kcov target
```

### Tests
```
userspace/kcov_test.rs              Full lifecycle test program
```

### Documentation
```
docs/fuzzing/syzkaller-architecture.md    13,000+ words (all phases)
docs/fuzzing/phase2-completion.md         Technical decisions
docs/fuzzing/phase2-summary.md            Executive summary
docs/fuzzing/phase2-status.md             Status and metrics
docs/fuzzing/README.md                    This index
```

---

## Key Features

### ✅ KCOV Infrastructure
- Per-task coverage buffers (4KB, 32K edges)
- IRQ-safe operation (try_lock, no allocations)
- SMAP-compliant userspace access
- Zero overhead when disabled

### ✅ Syscall Interface
```c
// Initialize coverage for current task
sys_kcov_init(size_t buf_size) → 0 on success

// Start/stop collection
sys_kcov_enable() → 0 on success
sys_kcov_disable() → 0 on success

// Extract data
sys_kcov_dump(u32 *buf, size_t len) → edge_count

// Reset for next iteration
sys_kcov_reset() → 0 on success
```

### ✅ Manual Instrumentation
6 syscalls with 13 edges:
- `sys_getpid` (3 edges)
- `sys_getppid` (5 edges)
- `sys_getuid`, `sys_geteuid`, `sys_getgid`, `sys_getegid` (1 edge each)

---

## 🚀 How to Use the CI Integration

### Automatic Runs

Cargo-fuzz targets run automatically on schedule and on relevant pushes. Three targets call real
kernel parser code; the other seven registered targets are self-contained model harnesses:

**KCOV build and pipeline smoke:**
- Schedule: Weekly
- Executes: CI plumbing only (zero kernel fuzz inputs)
- Output: A clearly labelled smoke log/dashboard; never crash evidence

**Cargo-fuzz targets:**
- Schedule: Daily at 2 AM UTC
- Duration: 600 seconds per target
- Targets: All 10 registered fuzzers (3 kernel parsers plus 7 model harnesses)
- Output: Public result status plus opaque HMAC candidate IDs; raw findings stay private to the runner

**Push quick targets:**
- Duration: 60 seconds per target
- Targets: `fuzz_vfs_path`, `fuzz_network_packet`, and `fuzz_elf_loader`
- Output: The same public-safe result metadata as scheduled target runs

### Manual Runs

Trigger manually via GitHub Actions:

```
Actions → Comprehensive Kernel Fuzzing → Run workflow

Mode:
  - targets: Cargo-fuzz targets only
  - smoke: KCOV build and CI plumbing only (not fuzz evidence)
  - both: Run targets and smoke

Timeout: 600 (seconds per target, for cargo-fuzz)
```

### View Results

**Crashes:**
- Automatically filed as opaque GitHub triage markers when private fingerprinting is configured
- Tagged with the `[Fuzzing]` prefix and `bug` label
- Public body links the workflow run but omits target, stack, payload, and ordinary payload hashes
- Maintainers classify the candidate under [SECURITY.md](../../SECURITY.md) before sharing details
- Configure a stable random `FUZZ_FINGERPRINT_KEY` repository secret (at least 32 bytes); findings
  fail closed and publish nothing if it is missing
- An existing open Issue with the same opaque ID is reused; a matching closed Issue is reopened and
  receives a new workflow pointer. The lookup covers the full open/closed Issue history.

**Dashboards:**
- Download artifacts from workflow run
- `fuzz-smoke-dashboard/dashboard.html` for visual smoke status
- `fuzz-smoke-dashboard/dashboard.json` for programmatic smoke status
- These dashboards report zero kernel executions and are not coverage evidence

**Aggregate stats:**
- Visible in workflow step summary
- Download `aggregate-report.md` artifact
- Reports distinguish targets that were not requested, failed/incomplete matrices, private
  candidates, and complete clean runs; a missing manifest is never reported as clean

**Corpus:**
- Clean-run cargo-fuzz corpora are cached per target between runs
- Corpora and raw fuzzer output are never uploaded as public artifacts
- A run that observes any finding is not saved back to the corpus cache

### See Also

- Historical CI integration/refactoring notes are retired; use this index and the live workflow.

---

## Quick Start

### Build KCOV Kernel
```bash
cd /home/dev/workspace/project/rsproject/Zero-os
make build-kcov
```

### Run on QEMU
```bash
timeout 45 qemu-system-x86_64 \
  -M q35 -m 512M -cpu qemu64 -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:esp-kcov \
  -serial stdio -display none -no-reboot
```

### Verify Boot
```bash
grep "KCOV" serial-kcov-phase2.txt
# Expected output:
# [KCOV] Coverage infrastructure initialized
# ! SMAP requirement SKIPPED (kcov fuzzing mode)
```

### Use from Userspace
```rust
// See userspace/kcov_test.rs for complete example
syscall(SYS_KCOV_INIT, 4096);
syscall(SYS_KCOV_ENABLE);
getpid();  // Coverage collected
syscall(SYS_KCOV_DISABLE);
let count = syscall(SYS_KCOV_DUMP, buf, len);
```

---

## Design Decisions

### Why Manual Instrumentation?
- LLVM `-C instrument-coverage` conflicts with `-Z build-std`
- Matches Linux KCOV design (manual `-fsanitize-coverage=trace-pc`)
- Explicit and reviewable
- Zero overhead when disabled
- Comparable performance to LLVM callbacks

### Why Per-Task Buffers?
- Prevents cross-task contamination
- Enables parallel fuzzing
- Matches proven Linux design
- Scales to many processes

### Why Dedicated Syscalls (not ioctl)?
- Better ergonomics than ioctl
- Type-safe interface
- More idiomatic for Rust kernel
- Easier to document and use

---

## Comparison to Linux KCOV

| Feature | Linux KCOV | Nilix KCOV | Status |
|---------|-----------|-----------|--------|
| Per-task buffers | ✓ | ✓ | Match |
| Edge tracking | ✓ | ✓ | Match |
| IRQ-safe | ✓ | ✓ | Match |
| Manual instrumentation | ✓ `-fsanitize-coverage` | ✓ `record_edge()` | Match |
| Interface | ioctl | syscalls | Better |
| Comparison mode | ✓ | Phase 4 | Planned |
| Remote collection | ✓ debugfs | Phase 7 | Planned |

**Verdict:** Architecturally equivalent with better syscall ergonomics.

---

## Metrics

| Metric | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Phase 6 | Total |
|--------|---------|---------|---------|---------|---------|-------|
| **Phase** | 2 of 7 | 3 of 7 | 4 of 7 | 5 of 7 | 6 of 7 | 6/7 ✅ |
| **Lines of code** | 1,800+ | +1,000+ | +900+ | +1,320+ | +1,440+ | 6,460+ |
| **Documentation** | 20,000 words | +3,000 words | +1,000 words | +3,000 words | +3,000 words | 30,000+ |
| **KCOV syscalls** | 5 (520-524) | 5 (same) | 5 (same) | 5 (same) | 5 (same) | 5 |
| **Instrumented syscalls** | 6 (13 edges) | 16 (37 edges) | 16 (same) | 16 (same) | 16 (same) | 16 |
| **Grammar syscalls** | 0 | 10 | 10 (same) | 11 | 11 (same) | 11 |
| **Fuzzer modules** | 0 | 0 | 5 | 10 | 15 | 15 |
| **Mutation strategies** | 0 | 0 | 8 | 7 (resource-aware) | 0 (state-aware) | 15 |
| **Resource types** | 0 | 0 | 0 | 4 | 4 (same) | 4 |
| **Transaction patterns** | 0 | 0 | 0 | 0 | 5 | 5 |
| **State machines** | 0 | 0 | 0 | 0 | 3 | 3 |
| **Test programs** | 1 | 2 | 3 | 3 | 3 | 3 |
| **Build time** | ~1min 17s | ~1min 20s | ~1min 30s | ~1min 30s | ~1min 30s | ~1min 30s |
| **Expected coverage** | 13 edges | 15-20 edges | >25 edges | >30 edges | >40 edges | >90% |

---

## Timeline

| Phase | Status | Date |
|-------|--------|------|
| Phase 1: Minimal KCOV | ✅ Complete | 2026-07-21 |
| Phase 2: Multi-syscall | ✅ Complete | 2026-07-21 |
| Phase 3: Descriptions | ✅ Complete | 2026-07-21 |
| Phase 4: Mutation | ✅ Complete | 2026-07-21 |
| Phase 5: Resources | ✅ Complete | 2026-07-21 |
| Phase 6: Stateful | ✅ Complete | 2026-07-21 |
| Phase 7: CI | 🚧 Partial: cargo-fuzz + smoke only | 2026-08-03 |

---

## Remaining Phase 7 Work

### Goal
Connect the existing prototypes to a real, host-driven QEMU feedback loop without weakening the
private disclosure boundary.

### Deliverables
1. A real kernel input transport and execution oracle for the QEMU guest
2. Host-driven mutation informed by guest KCOV feedback
3. A durable private channel for verified reproducers and diagnostic output
4. Corpus synchronization for the real guest executor
5. Performance dashboards based on measured kernel executions rather than simulation

### Success Criteria
- Fuzzer runs continuously in CI
- Crashes automatically triaged and deduplicated
- Corpus shared across fuzzing instances
- Dashboard shows real-time fuzzing progress
- Integration with existing CI/CD pipeline

---

## Resources

### Code
- Kernel source: `/home/dev/workspace/project/rsproject/Zero-os/kernel/`
- Coverage module: `kernel/coverage/lib.rs`
- Syscalls: `kernel/kernel_core/syscall.rs`
- Fuzzer: `userspace/fuzzer/`
- Userspace tests: `userspace/kcov_test.rs`, `userspace/syscall_fuzzer.rs`

### Documentation
- This directory: `docs/fuzzing/`
- Architecture: `syzkaller-architecture.md`
- Phase 6: `PHASE6_COMPLETE.md` ⭐ NEW
- Phase 5: `PHASE5_COMPLETE.md`
- Phase 4: `PHASE4_COMPLETE.md`
- Phase 3: `PHASE3_COMPLETE.md`
- Phase 2: `phase2-status.md`
- Grammar: `syscall-grammar.toml`

### Build
- Makefile: `/home/dev/workspace/project/rsproject/Zero-os/Makefile`
- Target: `build-kcov`
- Output: `esp-kcov/`

---

## Contact / Questions

For questions about the fuzzing infrastructure:
1. Read the architecture document (syzkaller-architecture.md)
2. Check Phase 6 completion (PHASE6_COMPLETE.md) ⭐ NEW
3. Check Phase 5 completion (PHASE5_COMPLETE.md)
4. Check Phase 4 completion (PHASE4_COMPLETE.md)
5. Review Phase 3 completion (PHASE3_COMPLETE.md)
6. Review the syscall grammar (syscall-grammar.toml)
7. Check Phase 2 status (phase2-status.md)

---

**Last Updated:** 2026-08-03

**Current Phase:** Phase 7 partially integrated (cargo-fuzz + pipeline smoke)

**Next Milestone:** Real host-driven QEMU execution and KCOV feedback loop
