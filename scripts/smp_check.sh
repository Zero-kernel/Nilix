#!/bin/bash
# R171 AP boot-wiring verification: boot 2 cores, confirm APs come online and
# reach userspace/idle with zero write-protection / NX #PF during AP bring-up.
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
OVMF="${OVMF_PATH:-/usr/share/qemu/OVMF.fd}"
ser=$(mktemp); intlog=$(mktemp)
timeout 25 qemu-system-x86_64 -bios "$OVMF" \
  -drive format=raw,file=fat:rw:"$ROOT/esp" \
  -m 256M -vga std -no-reboot -no-shutdown \
  -cpu qemu64,+smep,+smap,+umip,+rdrand \
  -smp cpus=2 \
  -display none -serial "file:$ser" \
  -d int,cpu_reset -D "$intlog" >/dev/null 2>&1
echo "=== reached-userspace/idle markers ==="
grep -anE 'Hello from Ring 3|Process 1 exited|All Component Tests Passed' "$ser" | tail -5
echo "=== AP / SMP / online markers ==="
grep -aniE 'AP |online|SMP|secondary|processor|cpu_idx|bring|core ' "$ser" | tail -25
echo "=== NX #PF count (e=0011) ==="; grep -c 'e=0011' "$intlog"
echo "=== page-fault #PF v=0e total ==="; grep -c 'v=0e' "$intlog"
echo "=== cpu_reset / triple-fault count ==="; grep -c 'cpu_reset' "$intlog"
echo "=== fault sample (v=0e or reset) ==="
grep -anE 'v=0e|cpu_reset' "$intlog" | head -15
echo "=== serial tail ==="; tail -28 "$ser"
