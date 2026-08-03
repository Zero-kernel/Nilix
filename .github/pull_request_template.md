<!--
Thank you for contributing to Nilix.

Use a focused title in the form `type(scope): imperative summary`, for example:
  fix(mm): reject VMA growth before committing page-table metadata

Common types: feat, fix, perf, refactor, docs, test, ci, chore.
Useful scopes include boot, arch, mm, process, abi, sched, ipc, vfs, net,
security, iommu, drivers, userspace, fuzz, and ci.
-->

## Problem and outcome

<!-- What concrete defect, limitation, or invariant does this address? Describe behavior and impact, not a file list. -->

## Related issue or audit finding

<!-- Use `Fixes #123`, `Related: #123`, or an audit/finding ID. For regressions, add `Fixes: <introducing commit subject/SHA>`. -->

Related: #

## Design and scope

<!-- Explain the chosen design, ownership/lifetime model, important interfaces, migration, and explicit non-goals. Keep unrelated cleanup separate. -->

## Kernel safety and invariants

<!-- Address every relevant item; write "Not applicable" only after considering it. -->

- Trust boundaries and attacker-controlled inputs:
- `unsafe` / MMIO / page-table / usercopy justification:
- IRQ, preemption, lock ordering, and SMP behavior:
- Fallible allocation, quotas, and rollback/commit ordering:
- ABI/layout/syscall compatibility:
- Fail-closed and error-path behavior:

## Validation evidence

<!-- List exact commands and outcomes. Do not claim checks you did not run. Attach concise serial logs, test summaries, benchmarks, or hardware details when useful. -->

```text
make fmt-check
make clippy
make lint
make build
make boot-check
make test
```

Additional focused checks:

<!-- Examples: make musl-check, make test-ext3, make test-smp, make test-smp-4core, make test-hosted-subcrates, cargo-fuzz target, hardware validation. -->

## Compatibility, performance, and rollout

<!-- Note public ABI changes, changed boot/hardware requirements, performance or memory impact, compatibility risks, and staged rollout/backout options. -->

## Checklist

- [ ] The change is focused, bisectable, and free of unrelated refactoring.
- [ ] I added a regression test or explained why an automated test is not practical.
- [ ] I ran the relevant formatting, lint, build, runtime, ABI, SMP, storage, or fuzz gates listed above.
- [ ] New `unsafe` blocks have local `SAFETY` reasoning and a minimized unsafe scope.
- [ ] I preserved IRQ/lock-order rules, bounded attacker-controlled work, and reserve-before-commit accounting.
- [ ] I updated architecture, safety, testing, roadmap, or user documentation when behavior changed.
- [ ] New fixtures/artifacts are minimal, reproducible, redistributable, and contain no confidential data.
- [ ] Breaking behavior, residual risk, deferred validation, and untested hardware are called out explicitly.
