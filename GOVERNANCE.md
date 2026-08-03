# Nilix governance

Nilix currently uses a maintainer-led model suited to a small contributor base
and a security-sensitive kernel. This document makes decision rights and review
expectations explicit without inventing committees that do not yet exist.

## Principles

Project decisions follow the declared priority order:

1. Security
2. Correctness
3. Efficiency
4. Performance

Changes should minimize the trusted computing base, preserve fail-closed
behavior, keep resource use bounded and accounted, and make verification
evidence part of the decision rather than an afterthought.

## Roles

### Contributors

Anyone may report issues, propose designs, review public changes, write tests or
documentation, and submit pull requests. Contributors are responsible for
understanding what they submit, answering review questions, and accurately
reporting what they did and did not test.

### Reviewers

Reviewers are contributors with demonstrated subsystem knowledge who provide
technical feedback. A review is advisory unless the reviewer is also a
maintainer or has been explicitly delegated merge authority for that area.

### Maintainers

Maintainers triage issues, protect security embargoes, decide whether an RFC is
accepted, request appropriate reviewers, define release gates, merge or close
changes, and keep project-wide architecture coherent. The current primary
maintainer is represented by `.github/CODEOWNERS`.

### Security response

The primary maintainer coordinates private reports and may invite only the
reviewers needed for the affected subsystem. Participants must preserve embargo
confidentiality until a coordinated disclosure is ready.

## Decision process

### Routine changes

Focused fixes, tests, documentation, and local refactoring are decided through
pull request review. Acceptance requires applicable CI, sufficient regression
evidence, and maintainer approval.

### Significant changes

Architecture, trust-boundary, syscall/ABI, dependency, hardware-support,
cross-subsystem, or long-lived compatibility changes begin as a feature/RFC
issue. An RFC should define:

- the problem, goals, and non-goals;
- interfaces, ownership, lifecycle, and failure behavior;
- threat boundaries, attacker-controlled inputs, and TCB impact;
- IRQ/lock/SMP and resource-accounting implications;
- alternatives, including userspace placement or deferral;
- verification, migration, rollback, and documentation plans.

The maintainer records a decision in the issue as accepted, needs revision,
deferred, or declined. Silence is not acceptance. Implementation should not
begin at large scale until the direction is recorded.

### Security-sensitive changes

Unpublished vulnerabilities are handled under [SECURITY.md](SECURITY.md), not a
public RFC. Once disclosure is safe, the public history should explain the
invariant and fix without exposing users of unfixed revisions unnecessarily.

### Emergencies

For an actively exploitable vulnerability, repository compromise, or release
artifact problem, the maintainer may temporarily bypass the normal public RFC
sequence. Normal CI and independent review should still be preserved whenever
time permits, and the decision must be documented after the embargo ends.

## Review and merge policy

- Authors do not approve their own external contribution on behalf of the
  project. At least one maintainer approval is required when branch rules apply.
- Security, unsafe, ABI, concurrency, memory-accounting, and hardware changes
  may require focused review beyond the path owner.
- Reviewers may require a patch series to be split so each commit is buildable,
  bisectable, and independently justified.
- A green CI run is necessary but does not prove unmodeled hardware, timing,
  threat-model, or unsafe-code assumptions.
- Unresolved substantive review comments block merge. Style preferences alone
  should not override documented project conventions or measured evidence.
- Squash merge is appropriate for a single logical change; a carefully ordered,
  bisectable series may retain multiple commits at maintainer discretion.

## Issue lifecycle and priority

Maintainers classify new issues by subsystem, evidence, risk, and priority.
CRITICAL and HIGH findings follow the definitions in
[docs/review/remediation/README.md](docs/review/remediation/README.md) and block
the applicable release gate. Accepted multi-step work uses a tracking issue with
explicit dependencies and completion criteria.

Only questions and reports explicitly waiting for reproduction are eligible for
inactivity automation. Confirmed defects, accepted RFCs/tracking issues, and
pull requests do not expire solely with time.

## Releases

Release readiness follows the current gates in [docs/roadmap.md](docs/roadmap.md):
no unresolved release-blocking security findings, green required CI and runtime
gates, coherent documentation, and recorded residual risks. Scheduled stress,
fuzzing, or hardware evidence supplements but does not silently weaken a failed
required gate.

## Conduct and conflicts

All project spaces follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Technical
disagreement should be resolved with explicit invariants, reproductions,
measurements, specifications, and threat-model reasoning. If consensus is not
possible, the primary maintainer makes and records the decision, including
material tradeoffs and dissent when useful.

## Changing governance

Governance changes use a public RFC and pull request. As the maintainer group
grows, this document and CODEOWNERS should be updated together to define
delegation, succession, quorum, and security-response membership explicitly.
