NEG=1: sed SharedFaultResult::Reentry(which) -> SharedFaultResult::Busy in kernel/kernel_core/fork.rs; make build; python3 scripts/gates/qemu/shared_fault_reentry_probe.py --cases mm --timeout 300
