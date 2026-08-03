#!/bin/bash
# R171-G5-01-B positive test: boot q35 WITH a vIOMMU so a real DMAR table appears
# in ACPI, and observe whether find_dmar_table discovers it (IOMMU active).
# NOTE: q35 places some BARs >4GiB which can break Zero-OS's bootloader identity
# map (see Makefile), so this may not boot to userspace — we only need to see how
# far IOMMU init gets.
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
OVMF="${OVMF_PATH:-/usr/share/qemu/OVMF.fd}"
ser=$(mktemp)
timeout 25 qemu-system-x86_64 -bios "$OVMF" \
  -machine q35 \
  -device intel-iommu,intremap=on \
  -drive format=raw,file=fat:rw:"$ROOT/esp" \
  -m 256M -vga std -no-reboot -no-shutdown \
  -cpu qemu64,+smep,+smap,+umip,+rdrand \
  -display none -serial "file:$ser" >/dev/null 2>&1
echo "=== IOMMU / DMAR lines ==="
grep -anE 'IOMMU|DMAR|DMA isolation|7\.53|InvalidDmar|InvalidStructure|unit' "$ser" | head -20
echo "=== last 20 serial lines (how far it booted) ==="
tail -20 "$ser"
