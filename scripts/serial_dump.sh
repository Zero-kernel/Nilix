#!/bin/bash
# Dump kernel serial + interrupt log from a normal boot.
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
OVMF="${OVMF_PATH:-/usr/share/qemu/OVMF.fd}"
ser=$(mktemp); intlog=$(mktemp)
timeout 20 qemu-system-x86_64 -bios "$OVMF" \
  -drive format=raw,file=fat:rw:"$ROOT/esp" \
  -m 256M -vga std -no-reboot -no-shutdown \
  -cpu qemu64,+smep,+smap,+umip,+rdrand \
  -display none -serial "file:$ser" \
  -d int,cpu_reset -D "$intlog" >/dev/null 2>&1
echo "=== serial line count: $(wc -l < "$ser") ==="
echo "=== last 35 serial lines ==="
tail -35 "$ser"
echo "=== faults (#PF/reset) ==="
grep -anE 'v=0e|cpu_reset|check_exception|v=08' "$intlog" | tail -8
