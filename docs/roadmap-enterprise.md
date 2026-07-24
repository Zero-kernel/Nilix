# Zero-OS / Nilix Enterprise Roadmap — Superseded

> **Superseded on 2026-07-23.** The enterprise architecture, threat model, trust boundaries,
> security posture, gap-analysis-vs-Linux, phase history, release-gate status, and long-term
> planning that this file used to carry are now maintained in a single unified document:
>
> ### → [`docs/roadmap.md`](roadmap.md)
>
> This file is **no longer a current status source**. It previously described the project as
> "network: not started / SMP: not started" (v3.2, 2025-12-23) — a snapshot that is ~160 audit
> rounds and six completed phases out of date. All of that content, updated and reconciled against
> the actual source tree, lives in the unified roadmap above.

## Why this was merged

The project historically kept two overlapping roadmaps — a development roadmap (`roadmap.md`) and
this enterprise roadmap (`roadmap-enterprise.md`). They drifted out of sync and duplicated large
sections. As of the 2026-07-23 unification, there is **one** canonical roadmap. It absorbs every
unique element this file contributed:

- **Threat model & attacker profiles** → `roadmap.md` §3.2
- **Trust boundaries** → `roadmap.md` §3.1–§3.2
- **Gap analysis vs Linux** → `roadmap.md` §6
- **Security-first phase ordering & rationale** → `roadmap.md` §2, §7
- **Enterprise readiness / release gate** → `roadmap.md` §8
- **Hardening profiles (Secure/Balanced/Performance)** → `roadmap.md` §5.4
- **Compliance & FIPS posture** → `roadmap.md` §5.4, §14

Git history preserves the former full content of this file.

---

*Kept as a stable redirect so external links to `roadmap-enterprise.md` do not break.
For anything current, read [`roadmap.md`](roadmap.md).*
