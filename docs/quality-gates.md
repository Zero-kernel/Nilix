# Quality Gates & Continuous Integration

Nilix enforces correctness, style, and boot health automatically — the same gates run in
CI, and contributors can run them locally (the maintainer's Windows mirror offloads to a
Linux build host). This is the detail behind [README §Quality](../README.md); the
top-level README carries only a pointer. For the fuzzing deep docs see
[`docs/fuzzing/`](fuzzing/) and [`docs/overview/05-fuzzing/`](overview/05-fuzzing/).

---

## 1. GitHub Actions (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`, with in-progress runs on the same ref
cancelled. Four parallel jobs:

| Job | Runs | Asserts |
|-----|------|---------|
| **rustfmt + clippy** | `make fmt-check` · `make clippy` | All crates rustfmt-clean; clippy reports no errors |
| **build** | `make build` | Bootloader + kernel compile (PIE / build-std / hardened flags) |
| **custom lints** | `make lint` | Four structural source lints plus VFS fallibility and ABI-layout gates pass (below) |
| **boot + test + musl** | `make boot-check` · `make test` · `make musl-check` | Kernel boots clean to user space, runtime suite scores clean, and a static-musl binary runs end-to-end |

## 2. Boot & conformance gates

These QEMU gates have **real exit codes** read from the serial log and the QEMU `-d int`
interrupt log — never from QEMU's own exit code (`-no-reboot -no-shutdown` makes a timeout
the normal end of a healthy run).

- **`make boot-check`** (`scripts/boot_check.sh`) — boots under QEMU and fails unless the
  kernel reaches user space / its idle loop **and** zero NX-violation instruction-fetch
  page faults occurred (the `v=0e e=0011` signature from the D1-BOOT-NX-KASLR-LAYOUT class
  of bugs).
- **`make test`** (`scripts/kernel_test.sh`, P1-C VT-2 / Gate #4) — boots the default
  `make build` image and asserts a parseable in-kernel
  `=== Test Summary: N passed, M deferred (...), K failed ===` with `K == 0`, plus zero
  `KERNEL PANIC` and zero NX-violation #PF. Exit polarity: **0 PASS / 1 FAILED / 2 NOT-RUN**
  (missing summary or missing OVMF/ESP is NOT-RUN, not a silent green). Deferred/warning
  counts are informational only.
- **`make musl-check`** (`scripts/musl_check.sh`) — builds with `--features musl_test` so
  the embedded `hello_musl.elf` is the Ring-3 init program, then asserts **all** of: the
  libc-attributable `printf` marker (`42 * 2 = 84`), the `musl libc test passed!` success
  line, a clean `exit code 0`, zero NX-violation #PF, and no kernel panic. The gate is
  bidirectional and fail-closed — the default (native-Rust) kernel, which also exits 0,
  never prints the libc marker and therefore fails the gate.

## 3. Custom source lints (`make lint`)

Six repository-specific gates catch invariants the compiler cannot prove:

| Gate | Enforces |
|------|----------|
| `lint-release` | No ungated `println!` in kernel code (only `drivers/`, `klog/`); use `kprintln!` / `klog!` / `klog_force!` |
| `lint-smap` | Only `usercopy.rs` may instantiate `UserAccessGuard` (SMAP-window minimization) |
| `lint-fetch-add` | No bare `fetch_add(1)` for IDs/refcounts in core/VFS paths — use `fetch_update` + `checked_add` (or an explicit `// lint-fetch-add: allow`) |
| `lint-repr-c-copy` | Every `from_raw_parts` / `copy_nonoverlapping` / `transmute` on a `#[repr(C)]` struct at the user boundary must carry a padding-safety annotation |
| `lint-fallible` | Recoverable VFS paths, especially `readdir`, must use fallible name/allocation staging; its fixture self-test must catch 22 candidates with 0 false positives |
| `abi-check` | Kernel Rust `#[repr(C)]` layouts must match the cited Linux x86-64 UAPI oracle (11 structs, 100 values, 17 tripwires, with a C compiler cross-check) |

## 4. Extended test suite

Nilix has sustained stability, performance, and extended SMP tests beyond the core CI
gates:

- **QEMU stability soaks** (`scripts/stress_test.sh`) — six repeated boot/runtime profiles
  covering constrained memory, single/multi-vCPU, SMP, attached storage, and combined
  configurations over 60–300 seconds. These are stability profiles, not dedicated in-guest
  pressure workloads. Invoke via `make stress-test` or `make stress-test-extended`.
- **Extended SMP** (`scripts/extended_smp_test.sh`) — validates 8-core and 16-core boot,
  IPI broadcast, and multi-CPU lock contention. Run via `make test-smp-extended`.
- **Performance regression gate** (`scripts/perf_regression_test.sh`) — framework for
  detecting syscall latency, context-switch, and page-fault regressions. Invoked via
  `make test-perf` (benchmarks pending).
- **Security tests** (`kernel/security/tests.rs`) — nine runtime tests validating W^X, RNG,
  kptr guard, Spectre V1/V2, SMAP, and SMEP mitigations. Integrated into the standard
  `make test` suite.
- **Melting tests** (`scripts/melting_test.sh`) — sustained maximum-load scenarios (10+
  minutes) for bare-metal thermal validation. Framework in place; requires real hardware.

Full documentation lives in [`docs/testing/`](testing/).

## 5. Fuzzing infrastructure

Nilix has two complementary fuzzing approaches: (1) **Syzkaller-style host-driven fuzzing**
with a standalone mutation engine and QEMU executor, and (2) **Cargo-fuzz integration** with
both mock-based parser targets and QEMU-based syscall execution.

### 5.1 Syzkaller-style fuzzing (Phase 7)

Host-driven coverage-guided fuzzing with mutation, corpus management, and real kernel
execution:

- **Host fuzzer** (`userspace/nilix-syz-fuzzer/`) — Rust-based mutation engine with 5
  strategies (insert, delete, modify, duplicate, reorder), energy-based corpus scheduling,
  and crash classification.
- **Guest executor** (`userspace/nilix_syz_executor.c`) — C binary that deserializes syscall
  programs, executes them in Ring 3, and collects KCOV coverage.
- **Syscall grammar** — 600+ line `.syz` format descriptions covering 40+ syscalls with type
  constraints, resource tracking (fd, pid, addr), and dependency relationships.
- **Crash detection** — classifies kernel panic, page fault, triple fault, timeout, and
  hang scenarios with HMAC-based deduplication.
- **CI workflow** — weekly scheduled runs in GitHub Actions with corpus caching.
- **Performance** — 5-10 executions/sec, 50-200 new edges/hour (early phase).

### 5.2 Cargo-fuzz integration

Integrated libFuzzer targets for both fast parser iteration and deep kernel testing.

**Mock-based targets (10 targets)** — fast iteration on parsers without kernel execution:
VFS path normalization, network packet parsing, ELF loader, signal handling, ext2
structures, TCP segment processing, capability operations, syscall argument validation,
firewall rules, procfs entries. **Performance:** 50,000+ exec/sec, ideal for rapid
development feedback.

**QEMU-based targets (3 targets)** — real kernel execution with KCOV coverage feedback:
`fuzz_buddy_allocator` (alloc/free/split/coalesce), `fuzz_page_table_ops`
(map/unmap/COW/protection), `fuzz_syscall_qemu` (syscall execution against KCOV-enabled
kernel with a safe 19-syscall allowlist).

```text
┌──────────────────┐
│   libfuzzer      │  Generates inputs, tracks coverage
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ fuzz target      │  Parses input → SyscallProgram
└────────┬─────────┘
         │
         v
┌──────────────────┐
│  syz_bridge.rs   │  Shells out to nilix-syz-fuzzer --single-shot
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ nilix-syz-fuzzer │  QEMU orchestration, coverage extraction
└────────┬─────────┘
         │
         v
┌──────────────────┐
│   QEMU + kernel  │  Executes syscalls, records KCOV edges
└──────────────────┘
```

**Makefile targets:**

```bash
make build-fuzz-qemu-deps    # Build KCOV kernel + fuzzer binary
make fuzz-qemu-smoke          # 5-minute smoke test
make fuzz-qemu-campaign       # 1-hour campaign
make fuzz-qemu-overnight      # 8-hour overnight run
make fuzz-qemu-parallel       # 4-worker parallel fuzzing
make fuzz-list                # List all 13 cargo-fuzz targets
make fuzz-clean               # Clean artifacts/corpus
```

**Performance comparison:**

| Fuzzer Type | Exec/sec | Coverage | Memory | Use Case |
|-------------|----------|----------|--------|----------|
| Mock-based parser | 50,000 | Logic only | 100 MB | Fast iteration |
| QEMU syscall (shell) | 5-10 | Real KCOV | 512 MB | Deep testing |
| QEMU syscall (vendored) | 50-100 | Real KCOV | 512 MB | Production (future) |
| Standalone syzkaller | 8-12 | Real KCOV | 512 MB | Long campaigns |

### 5.3 KCOV infrastructure

- **Per-task coverage tracking** — IRQ-skipping, non-blocking edge recording with manual
  syscall tracepoints. KCOV is a host-global privileged surface: authority is
  **host-root-only** (the reserved `CapRights::KCOV` bit is retained for ABI stability but
  does not authorize access until a reviewed identity-bound issuance protocol exists).
- **Management syscalls** — `kcov_init`, `kcov_enable`, `kcov_disable`, `kcov_dump`,
  `kcov_reset` for coverage lifecycle control from Ring 3.
- **Deterministic E2E gate** — QEMU guest executor validates KCOV enable/disable/reset/
  dump, bitmap counts, program differentiation, and repeat stability.

### 5.4 Fuzzing architecture (summary)

- **KCOV coverage tracking** — per-task edge coverage via IRQ-skipping, non-blocking
  current-task recording and selected manual syscall tracepoints, with five management
  syscalls.
- **Syscall descriptions** — TOML-based type-safe definitions with constraints (ranges,
  flags, enums) and resource relationships (fd → file, pid → process). 20+ core syscalls
  described in `fuzz/syscall_descriptions/`.
- **Coverage-guided mutation** — genetic algorithm with 8 mutation strategies (flip order,
  insert, remove, mutate args, splice, cross over, havoc, dictionary-based). Corpus
  management tracks "interesting" inputs that expand coverage.
- **Resource-aware fuzzing** — tracks five resource types (fd, pid, addr, port, cap_id)
  with constraint validation, dependency tracking (exec clears fds, fork duplicates), and
  leak detection.
- **Stateful fuzzing** — protocol-aware fuzzing with state machines (FileDescriptor:
  CLOSED ↔ OPEN, MemoryRegion: UNMAPPED → MAPPED → PROTECTED, ProcessLifecycle: INIT →
  FORKED → EXEC → ZOMBIE), an IPC coordinator, and an input minimizer (delta debugging,
  70%+ size reduction).
- **Hybrid path** — a real QEMU guest E2E executes two deterministic syscall programs and
  validates KCOV enable/disable/reset/dump, bitmap counts, program differentiation, and
  repeat stability. Ten specialized cargo-fuzz targets (VFS, ELF, signal, etc.) provide
  host-safe parser and model checks.

### 5.5 CI integration

The `.github/workflows/fuzz.yml` workflow runs:

- **Push mode** — 60-second runs of the VFS path, network packet, and ELF loader targets,
  each of which calls real kernel parser code.
- **Scheduled target mode** — all 10 libFuzzer targets, daily at 2 AM UTC.
- **KCOV QEMU executor E2E** — rebuilds the static guest runner from source, boots
  `esp-kcov`, runs fixed syscall programs in Ring 3, and fails closed on missing markers,
  inconsistent coverage, panic, NX fault, early QEMU exit, or timeout.
- **Pipeline simulator smoke** — a separate dashboard/report plumbing check with an
  explicit zero-kernel-execution manifest; never treated as coverage or crash evidence.
- **Private candidate triage** — raw libFuzzer output and finding inputs stay inside the
  ephemeral runner. Candidate artifacts and Issue bodies contain only a stable keyed HMAC
  identifier and a workflow pointer; they omit payloads, stack traces, ordinary hashes,
  and target names. Public matrix job names and result manifests still identify the target
  that ran and its candidate count.
- **Corpus cache** — clean-run cargo-fuzz corpora are cached across runs but never
  published as artifacts; a run with any finding is not saved back to the cache.

Pushes to `main` affecting `kernel/**`, `userspace/fuzzer/**`, or `fuzz/**` run the three
real-kernel parser targets. Manual `smoke` runs both the deterministic guest E2E and the
independent zero-execution simulator; `both` adds cargo-fuzz targets. Only target runs can
produce fuzz findings. Candidate reporting requires a stable, randomly generated repository
secret named `FUZZ_FINGERPRINT_KEY` (at least 32 bytes); a finding fails closed if that
private channel is not configured.

Full documentation lives in [`docs/fuzzing/`](fuzzing/) (7 phase guides, 33,000+ words,
architectural deep-dive).

### 5.6 Invoking fuzzing locally

```bash
# Syzkaller-style coverage-guided fuzzing (Phase 7)
make build-kcov build-syz-executor build-syz-fuzzer  # Build all components
make test-syz                                         # 60-second smoke test
make run-syz-fuzz DURATION=3600 WORKERS=4            # Full fuzzing campaign

# Cargo-fuzz QEMU syscall fuzzing
make build-fuzz-qemu-deps                            # Build KCOV kernel + fuzzer
make fuzz-qemu-smoke                                 # 5-minute smoke test
make fuzz-qemu-campaign                              # 1-hour campaign
make fuzz-qemu-overnight                             # 8-hour overnight run
make fuzz-qemu-parallel                              # 4-worker parallel

# Deterministic KCOV guest E2E (legacy)
make test-kcov

# Cargo-fuzz targets for parsers
cd fuzz && cargo +nightly fuzz run fuzz_elf_loader -- -max_total_time=60
cd fuzz && cargo +nightly fuzz run fuzz_buddy_allocator --features qemu-executor
cd fuzz && ./run_all_fuzz.sh
```

**Phase 7 complete (2026-08-04):** the host-driven syzkaller-style fuzzing infrastructure
is fully operational. A Rust-based host fuzzer mutates programs using 5 strategies,
manages an energy-based corpus, and executes programs in QEMU with timeout enforcement. A
C-based guest executor deserializes programs, executes syscalls, and collects KCOV
coverage. The fuzzer detects and classifies crashes with HMAC-based deduplication. GitHub
Actions CI runs weekly fuzzing campaigns with corpus caching. See
[`docs/fuzzing/QUICKSTART.md`](fuzzing/QUICKSTART.md) and
[`docs/fuzzing/phase7-implementation.md`](fuzzing/phase7-implementation.md).

**Cargo-fuzz QEMU integration (2026-08-05):** extended cargo-fuzz with QEMU-based syscall
execution. The `fuzz_syscall_qemu` target uses a bridge module (`syz_bridge.rs`) to shell
out to the standalone fuzzer, enabling libFuzzer's mutation strategies with real kernel
coverage feedback. See [`docs/FUZZING_SUMMARY.md`](FUZZING_SUMMARY.md).

## 6. Style gates & pre-push hook

- **`make fmt-check`** — `cargo fmt --all --check` across the workspace and userspace.
  `rustfmt.toml` pins `newline_style = "Windows"` because the repo stores CRLF blobs.
- **`make clippy`** — clippy across all three build units (bootloader, kernel, userspace)
  in isolated target dirs; deny-by-default correctness errors fail the build.
- **`.githooks/pre-push`** — opt-in (`make hooks`). The hook is **local-first**: it runs
  `make fmt-check` + `make clippy` locally when a Rust toolchain is present, and can
  offload over SSH for a toolchain-less mirror (`git config zeroos.remote`/`zeroos.remoteDir`).
  Bypass a single push with `SKIP_PREPUSH=1 git push`. A pre-commit-framework equivalent
  (`.pre-commit-config.yaml`) is also provided — see
  [CONTRIBUTING.md](../CONTRIBUTING.md).
