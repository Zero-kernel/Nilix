# ST-K2-P2 validation evidence

Each gate has `<rev>-<lane>-<step>.command`, `.status` (the command's exit code) and `.identity.json` (revision, environment,
log and serial SHA-256, notes). Logs and serials stay on the dev host under `/tmp/nilix-evidence/st-k2-p2/<rev>/`.

- `99267d9-*`: the branch head. L0/L1 (formatting, clippy, lint, build, hosted debug/release, quality, license).
- `8f9d736-*`: guest gates. The bare-metal kernels are byte-identical to the head's (`kernel-identity.sha256`).
- `fa4b588-*`: the first version, whose owner record read the LAPIC over MMIO, and the 16-vCPU diagnostics that led to the
  MSR token.
- `cf032d4-*`: the (a) negative control (fail-stop disabled). The fail-stop code is unchanged since then.

`make` exits 2 when a gate it runs exits 1, 2 or 3; `RING3-MM OK` / `QUALIFIED` lines in the logs give the gate verdict.
