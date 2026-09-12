# Livepatch support

Livepatch is **unsupported** in the current kernel. Every `kpatch` syscall returns
`ENOSYS`, and the kernel refuses registration of livepatch operations. Boot reports
this capability explicitly. The experimental source does not establish production
patching or rollback support.

Enabling support requires reviewed kernel hooks, provisioned production trust keys,
authenticated patch/dependency/rollback tests, cross-core instruction synchronization
and tamper-evident audit validation. No production support feature is currently offered.

This is the unsupported branch of P1-4/KSA-009 in the
[current plan](review/nextplan/next-phase-plan-2026-09-06.md).
