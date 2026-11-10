# QEMU completion and stability scopes

Functional gates default to `QEMU_GATE_MODE=completion`. Boot/runtime,
SMP, musl, Ring-3 and IOMMU activation use the same owned QEMU supervisor. Their
existing timeout (normally 900 seconds, up to 2700 for the 16-vCPU final-owner
gate) is a maximum deadline, not a mandatory sleep. The regular CI workflow
selects this mode by default. Its manual dispatch input `qemu_gate_mode=window`
runs the former full scope, including musl.

Regular CI has an independent 32-vCPU SMP lane that reuses the normal build
image. Its default and maximum guest timeout is 3600 seconds; the 8/16-vCPU
suite retains 900 seconds per topology. It requires all 32 CPUs online and exactly one 31/31 AP acknowledgement;
a partial topology fails even when the general runtime result is QUALIFIED.
Both the 8/16-vCPU suite and the 32-vCPU gate run once, without an automatic
retry after a failure or stall. The 8/16-vCPU suite's two 900-second windows
plus the 16-vCPU 200-round final-owner gate (2700-second completion ceiling)
leave the rest of its 120-minute Extended job for build, analysis and upload;
retrying those windows would consume that entire budget before this overhead.
This single-attempt policy also applies in the combined local `extended` group.
Extended has a separate 32-vCPU lane on each Ubuntu image with the full
3600-second window. Regular and Extended 32-vCPU jobs allow 90 and 120 minutes,
respectively, leaving time for setup/build, final log analysis and upload.
These are QEMU guest vCPUs sharing the runner's host CPUs, so the results cover
functional correctness, not physical 32-core throughput. The original 8/16-vCPU
suite and its qualification rules are unchanged.

The supervisor waits for the runtime summary, the appropriate fixture's final
result, PID 1's exit record, and exactly one matching
`CI-EXIT pid=1 code=N stage=teardown-complete` record. The kernel emits that
record only after synchronous PID 1 teardown, parent notification and local
guard/Arc drops. The earlier `exited` and `terminated` messages are insufficient.
The new record does not claim that scheduler retirement, every deferred callback
or the entire machine is quiescent. It changes logging only, not lifecycle state.

After that witness, the supervisor observes two additional seconds within the
deadline, sends QMP `quit`, waits for QEMU to exit and closes diagnostics. Every
gate then applies its complete existing workload checks to the final logs,
including fatal output after the completion witness. Input hashes are still
verified. The collection trigger is not a passing verdict: failed assertions,
missing markers and qualifications retain their final gate classification.

`<serial>.run.json` records the completion profile, observed completion/stop
times, deadline, actual QEMU status, stop method, cancellation, forced kill and
a SHA-256 of the UTF-8/replacement-decoded, newline-normalized serial text.
Verification binds this receipt to the final serial stream. A spontaneous QEMU
exit, missing/malformed witness, deadline, cancellation, failed QMP shutdown or
forced kill cannot produce a successful completion receipt. QMP EOF after a
sent quit is allowed; a returned QMP error is rejected. Failure cleanup signals
only the supervisor's own live child process group and reaps that child.

`QEMU_GATE_MODE=window` retains the GNU `timeout` contract: full configured
observation, status 124, one TERM and no KILL. The Extended workflow explicitly
selects this mode, preserving its SMP/ext3/IOMMU stability coverage. The stress
profiles keep their own complete 900-second window after READY in either mode.
Completion-mode results do **not** claim the old 900-second post-completion
observation coverage. Old images without the cleanup witness must use window
mode; they cannot silently qualify completion mode.

The `strict` group runs boot, runtime at 1 and 4 vCPUs and SMP-4 with
`ZERO_OS_STRICT_TESTS=1`, where any warning, deferred test or skip fails the
gate (STRICT-Q, #64). It never accepts exit 3 and never retries. Until the
declared strict scope lands, every current deferral fails it, so Extended runs
it as a separate diagnostic job in completion mode: the job is not a lane, the
aggregate result does not depend on it, and its failure does not fail the run.
`make test-strict` and `make test-strict-smp4` run the strict runtime gate locally.

Examples:

```sh
# Default finite functional check; collect when the fixture has finished.
bash scripts/gates/boot/boot_check.sh esp

# Explicit stability observation with the same final assertions.
QEMU_GATE_MODE=window bash scripts/gates/boot/boot_check.sh esp

# Ring-3 uses its own fault-tolerant assertions and completion profile.
QEMU_GATE_MODE=completion make test-ring3-mm

# Build and run only the 32-vCPU SMP functional check.
make test-smp-32core

# Use an existing normal image; defaults remain the 8/16-vCPU suite.
EXTENDED_SMP_CPUS=32 bash scripts/gates/boot/extended_smp_test.sh esp
```

`record_gate.py` retains logs during execution and hashes evidence after the gate
returns. Actions' existing `if: always()` upload steps collect it after either
success or failure, provided the runner is still available. A lost/forcibly
stopped runner cannot guarantee an upload.

## Interrupt trace policy

Stress profiles and the Ring-3 oracle default to phased tracing: QEMU starts
with `int,cpu_reset` and switches to `cpu_reset` only after the expected AP
acknowledgement marker. Boot interrupt evidence and triple-fault logging remain
available. All `gate_log.py` verdicts require full tracing for acceptance; their
phased runs are diagnostic (QUALIFIED, or FAIL in strict mode). The Ring-3
oracle uses its own serial verdict, even when its shared runtime harness reports
a diagnostic result. `NILIX_QEMU_TRACE=full` restores full tracing for diagnosis.

The trace receipt binds the switch to the final serial prefix. Missing receipts
block acceptance and mismatches fail. A connection/negotiation failure before
the command, or a confirmed QEMU rejection, retains full scope. If command
delivery was attempted but its reply is lost, malformed or late, the receipt
records `switch-unknown` and every phased consumer fails: a timeout does not
prove QEMU kept tracing interrupts. QMP waits are bounded by the completion
deadline and do not count toward the post-witness observation interval.

`trace_phase_probe.py` checks fault evidence in bounded log blocks and retains
only a bounded interrupt-log tail. Its test-only kernel feature is disabled in
normal images. The probe changes no workload, heartbeat bound or gate verdict.

The extended SMP gates (8, 16 and 32 vCPUs) keep the full trace but store it
compressed (`QEMU_TRACE_COMPRESS=zstd`, #63): QEMU logs into a FIFO, and one
`zstd -1` stream at the `-D` path holds the complete content. A full 3600-second
32-vCPU window previously filled the runner disk. `gate_log.py` recognizes the
zstd magic and decompresses as it scans. A truncated or corrupt stream, or a
compressor that failed (its output is kept as `*.partial`), leaves the gate
unable to read its trace, so it reports INCOMPLETE rather than passing. Read a
retained trace with `zstd -dc tmp.XXXXXX.zst`.
