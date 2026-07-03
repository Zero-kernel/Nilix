# Architecture Documentation

This directory contains architectural documentation for the Zero-OS kernel.

## Contents

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Comprehensive subsystem map covering all 23 kernel subsystems, their responsibilities, key abstractions, and interdependencies

## Related Documentation

- **Design Findings**: See [../review/remediation/](../review/remediation/) for open design findings and remediation roadmap
- **Implementation Status**: See [../reports/](../reports/) for implementation status and completion summaries
- **Safety Analysis**: See [../safety/](../safety/) for IRQ safety audits and lock hierarchy documentation

## Overview

The Zero-OS kernel architecture follows a modular design with clear subsystem boundaries:

- **Core**: `arch`, `mm`, `sched`, `ipc` - fundamental primitives
- **Kernel Services**: `kernel_core`, `vfs`, `net`, `security` - high-level abstractions
- **Device Layer**: `block`, `virtio`, `iommu` - hardware interaction
- **Security**: `lsm`, `cap`, `seccomp` - access control and sandboxing
- **Observability**: `livepatch`, `trace`, `audit`, `compliance` - runtime inspection

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed subsystem documentation.
