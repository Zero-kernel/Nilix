# Host-cut parser validation

Detailed command, environment and evidence-hash receipts are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/32d7062ab675ecd0f6a224bf3b019beff9627528/validation/stress-host-cut) · [Audit and archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/8)

The original implementation was `1c65dfe19b353bd78bd364798cc5fa168d01820e`; its historical unit-test receipt reports 41 tests. The audit repair additionally preserves complete logical lines, terminal markers and interleaved protocol prefixes when a host stop cuts the final output.

The historical offline replay compared parsers against the same retained artifacts but used a reconstructed end timestamp (last ledger event plus one second) and a reduced minimum-heartbeat count. It demonstrates the fragment parsing difference only. It does not requalify freshness through the original 900-second window.

No workload, heartbeat bound or failure/qualification mapping is changed. The scheduler stall in [#92](https://github.com/Zero-kernel/Nilix/issues/92) and STRESS-7 remain open. Ordinary builds and public CI do not require the private archive.
