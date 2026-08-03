# Contributing to Nilix

Thanks for your interest in Nilix — a security-first hybrid microkernel written in
Rust for x86_64. This guide gets you from a fresh clone to a green local check run
and a pull request. For an architectural tour, see the [README](README.md).

**Design principle:** Security > Correctness > Efficiency > Performance. When a
change trades safety for speed, safety wins; aggressive restructuring is welcome
when it removes a hazard.

## Start with the right channel

- Read [SUPPORT.md](SUPPORT.md) before filing a build or usage question.
- Use the structured bug form for a reproducible public defect. Include the exact
  revision, QEMU or hardware environment, command, serial evidence, and the
  smallest source reproducer you can provide.
- Open a feature/RFC issue before implementing architecture, trust-boundary,
  syscall/ABI, dependency, or cross-subsystem changes. Agree on goals, non-goals,
  ownership, failure handling, and verification before sending a large patch.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do
  not publish exploit details, crash reproducers, or embargoed audit findings.
- Community decisions and maintainer responsibilities are described in
  [GOVERNANCE.md](GOVERNANCE.md); participation is governed by
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Focused bug fixes, tests, documentation corrections, and mechanical cleanup can
go directly to a pull request when their scope and safety impact are clear.

---

## 1. Development environment

Everything builds and runs on Linux (CI uses `ubuntu-latest`); macOS and WSL with
the toolchain installed work too.

- **Rust** — the nightly toolchain is pinned in `rust-toolchain.toml` (with
  `rust-src` + `llvm-tools-preview` and the `x86_64-unknown-none` /
  `x86_64-unknown-uefi` targets; `rustup` installs them automatically). Clippy and
  rustfmt are **not** pinned — add them once:
  ```bash
  rustup component add clippy rustfmt
  ```
- **QEMU + OVMF** — `qemu-system-x86_64` and the OVMF UEFI firmware (for boot/run).
- **GNU Make**.
- **musl toolchain** — `musl-tools` (`musl-gcc`), only for the musl conformance gate.

On Debian/Ubuntu the non-Rust deps match what CI installs:
```bash
sudo apt-get install -y qemu-system-x86 ovmf musl-tools make
```

> Maintainer note: the project is also developed from a Windows mirror that has **no**
> local Rust toolchain and offloads builds to a Linux host. That setup is described in
> §5 — contributors do not need it.

---

## 2. Build & run

```bash
make build           # build bootloader + kernel into the EFI System Partition (esp/)
make run-serial      # run in QEMU with the serial console on your terminal
make run             # run in QEMU (graphical VGA window)
make run-smp         # multi-core boot (SMP_CPUS=N, default 2)
make help            # full target list
```

See [README §4](README.md#4-build-and-run) for the complete list.

---

## 3. Core checks

| Command | What it checks |
|---------|----------------|
| `make fmt-check` | `cargo fmt --check` across the workspace + userspace |
| `make clippy`    | clippy across all three build units (deny-by-default correctness) |
| `make lint`      | grep-based source gates (println, SMAP, fetch_add, repr(C) copies) |
| `make boot-check`| boots the kernel under QEMU; asserts zero NX-violation page faults |
| `make test`      | fail-closed in-kernel runtime test summary, panic, and NX gate |
| `make test-hosted-subcrates` | count-pinned hosted tests and compile checks |
| `make musl-check`| static-musl libc conformance gate |

CI (`.github/workflows/ci.yml`) runs these directly — there is no hidden remote
machinery. If they pass locally, CI should be green.

---

## 4. Select checks by risk

Every code change should run `make fmt-check`, `make clippy`, `make lint`, and
`make build`. Add the focused gates implied by the change:

| Change area | Required evidence |
|-------------|-------------------|
| Kernel behavior or bug fix | `make boot-check` and `make test` |
| Syscall, layout, usercopy, ELF, or userspace ABI | `make abi-check` and `make musl-check` |
| Hosted-safe kernel logic | `make test-hosted-subcrates` plus the affected crate tests |
| IRQ, locking, scheduler, RCU, TLB, or SMP | `make test-smp` and normally `make test-smp-4core` |
| VFS, ext2/ext3, journal, or block I/O | `make test-ext3` |
| Parser or attacker-controlled structured input | affected cargo-fuzz target or KCOV runner |
| Performance | repeated baseline/candidate data with variance and unchanged safety gates |
| Hardware-specific code | QEMU evidence plus real-hardware evidence when the behavior cannot be modeled |

If a required environment is unavailable, say exactly what was not run and why.
CI success does not turn untested hardware, timing, or security assumptions into
verified claims.

---

## 5. Pre-push hooks (optional, but recommended — pick **one**)

The repo ships two ways to run `fmt-check` + `clippy` automatically before each
push. They are **mutually exclusive**: enabling the shell hook points Git's
`core.hooksPath` away from `.git/hooks`, where the pre-commit framework installs —
so only one mechanism can be active at a time.

### Option A — shell hook (no extra dependencies)

```bash
make hooks      # sets core.hooksPath=.githooks
```

`.githooks/pre-push` is **local-first**: it runs the checks locally when a Rust
toolchain is present, offloads over SSH when one is configured (see below),
otherwise warns and leaves enforcement to CI. Bypass a single push with
`SKIP_PREPUSH=1 git push`.

### Option B — pre-commit framework

```bash
pip install pre-commit
git config --unset core.hooksPath 2>/dev/null || true   # only if you ran `make hooks` before
pre-commit install                  # wires the pre-commit + pre-push stages
```

Runs `make fmt-check` at commit time and `make clippy` at push time
(`.pre-commit-config.yaml`). Bypass with `git push --no-verify` (or `SKIP=clippy
git push`). If `core.hooksPath` is still set to `.githooks`, Git ignores
`.git/hooks` and this hook silently won't run — unset it first.

### Remote offload (toolchain-less mirror only)

If you develop on a machine with no local toolchain, the shell hook can run the
checks on a remote build host instead. Configure **both**:

```bash
git config zeroos.remote     <ssh-host-alias>
git config zeroos.remoteDir  <repo-path-on-that-host>
```

(`ZEROOS_REMOTE` / `ZEROOS_REMOTE_DIR` env vars override these.) Caveat: offload
validates the **remote** working tree — keep it in sync with your local tree
before pushing.

---

## 6. Kernel engineering standards

- `no_std` throughout the kernel; match the style, naming, and comment density of
  the surrounding code.
- Keep `unsafe` blocks narrow. Each new or materially changed block must document
  the local `SAFETY` preconditions, lifetime/aliasing assumptions, and why callers
  uphold them. Treat MMIO, page tables, context switches, virtqueues, and usercopy
  as explicit trust boundaries.
- Bound all attacker-controlled loops, queues, retries, recursion, parsing, and
  allocation. Use reserve-before-commit admission and make rollback conserve the
  same counters/resources as the success path.
- Preserve fail-closed behavior. Missing evaluators, corrupt state, partial device
  initialization, and failed authorization must not silently widen privilege.
- For IRQ-reachable code, do not sleep or wait on a lock whose owner may require
  the current CPU. Document interrupt/preemption state and follow the enforced
  lock hierarchy. Exercise SMP paths, not only single-core QEMU.
- Keep SMAP windows inside the audited usercopy helpers. Validate every user
  pointer, length, alignment, integer conversion, and `#[repr(C)]` layout before
  crossing the kernel/userspace boundary.
- Use checked atomics and explicit ordering arguments. Explain ordering and
  publication when it is stronger than relaxed statistics.
- Keep changes bisectable: a commit must build and preserve its claimed
  invariants without depending on a later cleanup commit.
- The custom lints (`make lint`) are not optional — they reject ungated `println!`,
  unminimized SMAP windows, bare `fetch_add(1)` on IDs/refcounts, and unannotated
  `#[repr(C)]` user-boundary copies. Add the documented `// lint-…: allow` escape
  hatch only with a clear reason.
- New behavior needs documentation updates. Every bug or security finding should
  have a regression test that fails before the fix and passes after it, unless the
  pull request explains why automation is not practical.

---

## 7. Commits, pull requests, and review

1. Branch from current `main`. Keep each commit focused, reviewable, and usable on
   its own; split unrelated refactoring, generated artifacts, and dependency
   changes.
2. Use `type(scope): imperative summary`, for example
   `fix(mm): reject VMA growth before metadata commit`. Common types are `feat`,
   `fix`, `perf`, `refactor`, `docs`, `test`, `ci`, and `chore`.
3. Link the public issue or audit finding. For regressions, identify the
   introducing change with `Fixes: <sha> (<subject>)` when known.
4. Run the core and risk-selected checks above. Record exact commands, outcomes,
   environment, deferred validation, and concise serial/benchmark evidence in the
   pull request.
5. Open a draft PR for early design or CI feedback. Mark it ready only when the
   description is complete, the patch is internally coherent, and applicable
   local gates pass.
6. During review, answer questions with evidence and add follow-up commits so the
   review history remains understandable. Avoid rebasing or force-pushing while
   review is active unless a maintainer requests it.
7. All required CI jobs and maintainer review must pass before merge. A green CI
   run is necessary but does not replace architecture, safety, or threat-model
   review.

Maintainers may ask for a smaller patch series, a preceding RFC, additional
failure-path tests, a lock/resource proof, specification references, or hardware
validation. Pull requests may be squash-merged, so keep the final title suitable
for history and generated release notes.

Commits are **manual** — repository automation never commits or pushes contributor
code.

Welcome aboard, and thanks for helping make Nilix better.
