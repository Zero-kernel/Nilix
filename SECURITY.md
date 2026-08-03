# Security policy

Nilix is a pre-1.0 kernel that processes hostile userspace, network, storage,
device, and ABI inputs. Potential vulnerabilities must be reported privately so
maintainers can reproduce, remediate, and coordinate disclosure before details
become public.

## Supported versions

Security work targets the current `main` branch. Nilix does not currently offer
a stable supported release series or backport commitment.

| Version | Supported |
| --- | --- |
| Current `main` | Yes |
| Older commits, forks, or modified trees | Reproduce on `main` first |

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/Zero-kernel/Nilix/security/advisories/new).
Do not open a public issue, pull request, discussion, or CI artifact containing
exploit details or a security reproducer.

If the private form is temporarily unavailable, open a public issue that asks a
maintainer for a private contact channel without describing the vulnerability.

## Required evidence

A useful report contains:

- the exact affected commit and whether the tree is clean;
- a concise description of the violated trust boundary and concrete impact;
- attacker prerequisites, privileges, configuration, timing, and hardware/VM
  conditions;
- a minimal source or script reproducer and a reliable confirmation oracle;
- relevant serial, exception, register, QEMU, GDB, or test output;
- suspected files/functions and an introducing commit or version range when
  known;
- mitigations and a tested fix proposal, if available;
- the reporter's disclosure and credit preferences.

Prefer source and reproducible construction steps over opaque binaries. Remove
credentials, host identifiers, personal data, and unrelated memory contents.
Remain available to answer questions and test candidate fixes.

AI-assisted findings are welcome only when the reporter has independently read
the affected code, verified the reproducer on current `main`, removed speculative
impact, and can discuss and test the report. A tool-generated hypothesis without
a working reproduction or trust-boundary analysis is not actionable evidence.

## What qualifies

Reports should demonstrate an unintended capability or impact across Nilix's
documented threat boundaries, including:

- memory corruption, invalid aliasing/lifetimes, or unsafe-boundary violations;
- privilege escalation, capability/LSM/seccomp/DAC bypass, or namespace escape;
- kernel/usercopy, syscall ABI, signal-frame, or `#[repr(C)]` validation flaws;
- attacker-triggerable panic, deadlock, livelock, unbounded work, allocation, or
  resource-accounting bypass;
- network, filesystem, ELF, device, DMA/IOMMU, or virtqueue input validation that
  compromises kernel integrity or isolation;
- cryptographic, audit-chain, redaction, livepatch, RNG, KASLR, W^X, SMEP/SMAP,
  or fail-closed enforcement failures;
- rollback/publication races or partial initialization that expose unauthorized
  state or resources.

The current threat model and explicit residual gaps are documented in
[docs/roadmap.md](docs/roadmap.md#32-threat-model).

## Usually not a vulnerability

Use the public bug or RFC forms for:

- unsupported architectures, incomplete roadmap features, or documented
  pre-1.0 non-goals without a boundary bypass;
- crashes that require already-trusted kernel modification or unrestricted host
  control and do not affect a supported boundary;
- theoretical dependency advisories without a reachable Nilix impact;
- performance differences without attacker-controlled denial of service;
- correctness or compatibility defects with no security impact;
- certification, Secure Boot, KPTI, IPv6, or other explicitly documented gaps
  unless the report demonstrates behavior beyond the stated model.

When uncertain, report privately. Maintainers can redirect an ordinary bug to
the public tracker after removing sensitive details.

## Response and coordinated disclosure

Maintainers will acknowledge and assess reports on a best-effort basis, invite
only the subsystem expertise needed for an embargoed fix, and coordinate testing,
advisory publication, credit, and release timing with the reporter. Do not set a
public disclosure date without first discussing the remediation scope and user
risk.

Accepted reports should gain a regression test whenever doing so does not expose
an unfixed exploit. Security fixes must preserve the project's normal build,
lint, runtime, SMP, ABI, and fail-closed gates appropriate to the affected code.
