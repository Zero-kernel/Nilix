# C3 E1 validation

Source: counters `e66288b8d641226267ee94d0d4e06648c68efb59` on `2e09191` (main after #99), plus `5ec5792`, which raises the hosted coverage pin and changes no kernel code.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/4428f515bf16b212d8d0a4d09cab07fbf8f78731/validation/c3-e1) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/12)

## Recorded results and limits

- **Local.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass, 641 tests including the new `PT_LOCK` test. Removing the `contended` increment or the hold-time accumulation fails that test.
  - All Python harness tests pass except one `iommu_device_probe_test` import error under plain unittest, which is unrelated; CI runs pytest.
- **Dev host, QEMU 8.2.**
  - The runtime group is GATE-QUALIFIED, and runtime at 4 vCPUs is QUALIFIED (3) with passed=46.
  - The strict group still FAILs on the remaining deferrals, with no undeclared scope.
  - `schedstat_event_counters` reports `not_applicable scope=needs_cpus:2` at 1 vCPU and passes at 4 and 16.
  - With the IPI handlers' counting removed, it fails (`handled 0->0`), as a negative control should.
- **ring3-mm.**
  - It passes at 1, 4 and 8 vCPUs, including `syscall_test`'s 2 KiB `/proc/schedstat` read.
  - At 16 vCPUs it hit its 900-second deadline while running beside a 16-vCPU stress guest. Run beside its parent `2e09191`, E1 completed in 820.6 s while the parent hit the deadline; at 8 vCPUs it took 210.7 s against 259.4 s. No slowdown from E1 is visible.
  - Every source tried is marginal against 900 s on this host when a second 16-vCPU guest runs.
- **Format.**
  - A 300-second `thread` run at 16 vCPUs is QUALIFIED (3) and shows the four new `/proc/schedstat` lines: 296 of the file's 876 bytes.
  - That sample is the stress runner's round-1 copy. It is a format check, not a C3 measurement.

None of these results is a strict pass. E2–E4 (#90) do the measurements. Ordinary builds and public CI do not require the private archive.

The local-checks, gates and paired-run receipts have aggregate status 1, from the unrelated unittest import error, the remaining strict deferrals, and the 16-vCPU deadlines respectively. Individual statuses and log hashes are preserved.

## Interpreting IPI samples

`ipis_sent` and `ipis_handled` are independent cumulative event counts for each CPU, not a coherent snapshot. A target can handle an IPI before the sender records its ICR write, and events can occur between procfs reads. A sample with `sent=10` and `handled=11` is therefore valid. LAPIC coalescing also prevents the difference from measuring pending or dropped IPIs, even after send accounting catches up.

E2–E4 analysis should compare each CPU's send and handler counts over an interval separately, using unsigned 64-bit wrapping deltas for samples from the same boot and resetting the baseline after a reboot. Neither a single sample's difference nor the difference of the two interval deltas is an exact backlog or loss metric. Readers must accept `handled > sent` without unsigned underflow, a fabricated backlog, or a delivery-failure verdict.

Existing readers retain the raw counters and do not subtract them. This clarification changes only documentation and Rust doc comments; the recorded runtime results above remain bound to their original sources.
