# Architecture Documentation

This directory contains architectural documentation for the Zero-OS kernel.

## Contents

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Comprehensive map covering all 25 kernel crates, their responsibilities, key abstractions, and interdependencies

## Related Documentation

- **Design Findings**: See [../../review/remediation/](../../review/remediation/) for open design findings and remediation roadmap
- **Implementation Status**: See [../reports/](../reports/) for implementation status and completion summaries
- **Safety Analysis**: See [../06-security/safety/](../06-security/safety/) for IRQ safety audits and lock hierarchy documentation

## Overview

The Zero-OS kernel architecture follows a modular design with clear subsystem boundaries:

- **Core**: `arch`, `mm`, `sched`, `ipc` - fundamental primitives
- **Kernel Services**: `kernel_core`, `vfs`, `net`, `security` - high-level abstractions
- **Device Layer**: `block`, `virtio`, `iommu` - hardware interaction
- **Security**: `lsm`, `cap`, `seccomp` - access control and sandboxing
- **Observability**: `livepatch`, `trace`, `audit`, `compliance` - runtime inspection

### R186 COW fault lock model

```text
#PF entry (IF=0)
  -> try_lock(PT_LOCK)
       -> acquired: resolve COW and return a typed outcome
       -> contended: return Busy, IRETQ, service pending IPIs, retry instruction
```

R186-10 removed the redundant `COW_FAULT_LOCK`. The page-fault path must never block on
`PT_LOCK` with interrupts disabled because the lock holder may be waiting for this CPU's TLB
shootdown acknowledgement.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed subsystem documentation.
