# VT-d support and validation matrix

**Active continuation, 2026-09-12:** QEMU EDU endpoint DMA/MSI, queued invalidation, fault containment and initialization failure profiles pass on the exact-final v3 manifest. The QEMU endpoint slice is accepted; physical rows remain pending. See the [device-probe design](review/design/p3-2-qemu-device-probe-design.md) and [P3-2 evidence](review/fixes/p3-2-qemu-device-evidence-2026-09-12.md).
The earlier claim that only physical verification remained is superseded.

**Current disposition, 2026-09-11:** The matrix and artifact-backed Q35/failure/
mitigation CI are implemented and independently reviewed; v51 final identity/build/
mitigation validation passes on the current source. Physical translated-DMA, remapped-interrupt, invalidation and teardown rows remain verification pending; their QEMU endpoint counterparts are accepted in the scoped v3 evidence.
Rows marked unsupported or not qualified describe capability boundaries outside the
accepted P3-2 implementation slice; they are not relabeled as hardware passes.

Updated 2026-09-10. This is the P3-2 support record. The current kernel has scoped
Q35 initialization/failure-retention evidence. General physical-device isolation is
**not yet qualified**. Rows below distinguish implemented code from tested behavior.

| Environment or mode | Current disposition | Evidence and limits |
|---|---|---|
| QEMU Q35, one legacy DRHD, PCI segment 0 | Scoped initialization/failure handling validated | KSA-001 positive boot and constructor/IR/TE probes; qualified runtime summaries do not establish strict security qualification |
| Legacy VER major 1, 39/48-bit common domain width, 4KiB pages | Implemented; Q35 encoding scope reviewed | Checked register windows and context words; common-width/encoding hosted tests do not prove every hardware mode |
| QEMU translated endpoint DMA | Scoped QEMU PASS | EDU endpoint profile v3 proves nonidentity translated DMA and replacement; physical qualification remains pending |
| Modern virtio requiring ACCESS_PLATFORM | Unsupported by current negotiation | No ACCESS_PLATFORM feature negotiation in current block/network drivers; needs reviewed implementation before a mandatory-IOMMU virtio test |
| Remapped MSI/MSI-X and IRTE reuse | Scoped QEMU MSI PASS | EDU MSI delivery, wrong-SID/nonpresent rejection, IEC retirement and index reuse pass; MSI-X and physical rows remain pending |
| Fault capture and deferred containment | Scoped QEMU PASS | EDU read-only/unmapped/absent-context requests produce raw FRCD records and production quarantine; no dedicated fault-vector or physical claim |
| Physical legacy VT-d, supported simple endpoint topology | Verification pending | Requires named hardware, specification revision and mapped/denied DMA, invalidation, fault and teardown evidence |
| Multiple DRHD units / overlapping include-all and explicit scopes | Not qualified | Initialization requires all units, but endpoint routing uses first match; include-all precedence/topology needs review and actual evidence |
| Bridge or multi-hop device scopes | Unsupported/incomplete | Scope path traversal and bridge sub-hierarchy matching are TODO; current VT-d construction flattens to start bus plus last device/function |
| Devices requiring RMRR identity regions | Unsupported/incomplete | RMRR entries are logged; required mappings are not installed |
| Nonzero PCI segments | Not qualified | Legacy PCI bus-master control supports segment 0; context-retirement fallback is not broad hardware qualification |
| VT-d scalable mode, ATS/PASID, 57-bit domains | Unsupported | Register gate accepts legacy major 1; Domain implements 39/48-bit page-table widths |
| Unrestricted identity pass-through | Debug-only, unsupported for release | `unsafe_identity_passthrough` is rejected in release builds |

The earlier [KSA-001 design](review/design/ksa-001-vtd-mmio-design.md) records comparison
against QEMU `v10.0.0` `hw/i386/intel_iommu_internal.h`, SHA-256
`a884db5e7859bb34abcae2bd09fc9ac2d06d261a51ba37e684eb408d8682bd7e`.
That is an encoding reference for the emulator. It is not proof that every historical
guest used that binary version, nor a substitute for an Intel hardware specification.
Actual gate command/tool/image records determine the tested emulator instance.

The current scope and completed KSA-001 evidence are in the
[audit](review/audits/qa-2026-09-06.md),
[repair ledger](review/fixes/ksa-2026-09-06-progress.md) and
[independent review](review/fixes/ksa-2026-09-06-independent-review.md).
Some older design status paragraphs predate accepted repair probes; the current ledger
and per-finding audit disposition take precedence over those historical paragraphs.

To qualify a new row, retain source revision/dirty manifest, build/command statuses,
kernel/bootloader/firmware hashes, emulator version or physical hardware identifiers,
DMAR/capability observations, serial/QEMU diagnostics, machine-readable outcome counts
and row-specific positive/negative evidence. Physical qualification includes actual
device DMA, checked invalidation, raw faults and quiescence before ownership release.
Missing evidence stays pending; injected errors are labeled as injected errors.

Implementation details and exact oracles are in the
[P3-2 design](review/design/p3-2-vtd-evidence-design.md). This matrix was a draft
support record awaiting independent review at the earlier snapshot; the current
scoped implementation/review status is recorded above and creates no new physical-
hardware pass.
