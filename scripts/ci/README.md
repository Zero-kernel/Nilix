# QEMU completion and stability scopes

Functional gates default to `QEMU_GATE_MODE=completion`. Boot/runtime, 2/4-core
SMP, musl, Ring-3 and IOMMU activation use the same owned QEMU supervisor. Their
existing timeout (normally 900 seconds) is a maximum deadline, not a mandatory
sleep. The regular CI workflow selects this mode by default. Its manual dispatch
input `qemu_gate_mode=window` runs the former full scope, including musl.

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

Examples:

```sh
# Default finite functional check; collect when the fixture has finished.
bash scripts/gates/boot/boot_check.sh esp

# Explicit stability observation with the same final assertions.
QEMU_GATE_MODE=window bash scripts/gates/boot/boot_check.sh esp

# Ring-3 uses its own fault-tolerant assertions and completion profile.
QEMU_GATE_MODE=completion make test-ring3-mm
```

`record_gate.py` retains logs during execution and hashes evidence after the gate
returns. Actions' existing `if: always()` upload steps collect it after either
success or failure, provided the runner is still available. A lost/forcibly
stopped runner cannot guarantee an upload.
