# Gate parser fixtures

These are synthetic, minimal fixtures based on the current serial emitters, not
captured QEMU runs. `failed-netns-rx-pool.serial` reconstructs the KSA-006 failure
shape around the exact summary supplied by the parent on 2026-09-07:

`=== Test Summary: 37 passed, 36 deferred (awaiting syscall infrastructure), 1 failed ===`

The retained host stdout is `/tmp/zero-os-audit-2873c14-smp-fresh.log`. The parent
also reports online_cpus=4, deferred_summary=1/1, pid1_exit=1/1,
qemu_exceptions=0, smp_online_PASS=1, r175_d0_cross_PASS=3, then harness success.
Only the summary/counts have that provenance; surrounding serial lines and the
FAIL message are a synthetic reconstruction, not the original (possibly deleted)
serial log. The short excerpt intentionally omits unrelated tests.

- `clean-smp.serial`: complete four-core boot with no failures or qualifications.
- `failed-netns-rx-pool.serial`: all SMP success markers coexist with a failed test
  and an authoritative failed=1 summary; must return failure.
- `qualified-smp.serial`: security Warning is counted as deferred by the current
  runtime emitter; must never satisfy a strict gate.
- `failed-q35-active.serial`: synthetic excerpt reproducing the parent's
  2026-09-07 Q35 result in isolated `.validation/q35-v2.serial`: IOMMU active,
  enabled and PID 1 exit 0 coexist with 28 passed, 45 deferred, 1 failed. These
  parent-reported counts are not locally verified full serial contents. This
  fixture intentionally has no FAIL marker, so the summary alone must reject it.

The tests derive two-core and extended-core variants and inject process, summary,
warning and late-fault defects. Parent validation may add a real failed fixture
with its command/tree provenance, but synthetic coverage is not real boot evidence.
