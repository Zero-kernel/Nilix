#!/bin/bash
# Capture kernel serial from a normal boot and show the IOMMU init lines.
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
OVMF="${OVMF_PATH:-/usr/share/qemu/OVMF.fd}"
ser=$(mktemp)
timeout 22 qemu-system-x86_64 -bios "$OVMF" \
  -drive format=raw,file=fat:rw:"$ROOT/esp" \
  -m 256M -vga std -no-reboot -no-shutdown \
  -cpu qemu64,+smep,+smap,+umip,+rdrand \
  -display none -serial "file:$ser" >/dev/null 2>&1
echo "=== IOMMU / DMAR / 7.53 lines ==="
grep -anE 'IOMMU|DMAR|DMA isolation|7\.53' "$ser"
echo "=== reached userspace? ==="
grep -anE 'Hello from Ring 3|Process 1 exited|All Component Tests Passed' "$ser" | tail -3
