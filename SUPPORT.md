# Support

Nilix is a research and development kernel maintained on a best-effort basis.
The project does not currently provide a guaranteed response time, compatibility
support contract, or private consulting channel.

## Choose the right entry point

- Use the [kernel bug form](https://github.com/Zero-kernel/Nilix/issues/new?template=bug_report.yml)
  for reproducible defects on current `main`.
- Use the [feature/RFC form](https://github.com/Zero-kernel/Nilix/issues/new?template=feature_request.yml)
  before implementing architecture, ABI, dependency, hardware, or cross-subsystem
  changes.
- Use the [performance form](https://github.com/Zero-kernel/Nilix/issues/new?template=performance_regression.yml)
  for controlled baseline/candidate measurements.
- Use the [documentation form](https://github.com/Zero-kernel/Nilix/issues/new?template=documentation.yml)
  for stale, missing, contradictory, or unclear documentation.
- Use the [question form](https://github.com/Zero-kernel/Nilix/issues/new?template=question.yml)
  for a focused build, QEMU/OVMF, test, architecture, or userspace question.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Before filing

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), the
[documentation index](docs/README.md), and the [roadmap and threat model](docs/roadmap.md).
Search open and closed issues, update to current `main`, and reduce the problem to
the smallest repeatable case.

Include the exact commit, clean/modified tree state, host and target environment,
QEMU/OVMF or hardware details, command, feature flags, expected result, actual
result, and concise serial diagnostics. State what you already tried.

Do not upload credentials, private firmware, confidential disk images, unrelated
memory dumps, or embargoed crash reproducers. Build minimized synthetic inputs
whenever possible.

Questions or reports awaiting requested reproduction details may be closed after
an extended period of inactivity. Confirmed kernel defects, accepted tracking
issues, and pull requests are not automatically closed merely because they are
old.
