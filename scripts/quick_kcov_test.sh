#!/bin/bash
# Quick KCOV boot test - runs for 5 seconds and captures output
# Returns 0 if KCOV message found, 1 otherwise

set -e

ESP_DIR="${1:-esp-kcov}"
OUTPUT_FILE="/tmp/kcov-boot-output.txt"

echo "=== Quick KCOV Boot Test ==="

# Run QEMU for 5 seconds and capture serial output
timeout 5 qemu-system-x86_64 \
    -bios "${OVMF_PATH:-/usr/share/OVMF/OVMF_CODE.fd}" \
    -drive format=raw,file=fat:rw:$ESP_DIR \
    -m 256M \
    -vga std \
    -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -nographic \
    > "$OUTPUT_FILE" 2>&1 || true

echo ""
echo "=== Checking for KCOV initialization ==="

if grep -q "KCOV" "$OUTPUT_FILE"; then
    echo "✓ SUCCESS: KCOV message detected"
    grep -i "kcov\|coverage" "$OUTPUT_FILE" || true
    exit 0
else
    echo "✗ No KCOV message found"
    echo "Last 30 lines:"
    tail -30 "$OUTPUT_FILE"
    exit 1
fi
