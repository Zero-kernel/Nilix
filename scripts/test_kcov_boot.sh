#!/bin/bash
# Test script to verify KCOV initialization during boot
# Checks for "[KCOV] Coverage infrastructure initialized" in serial output

set -e

ESP_DIR="${1:-esp-kcov}"
TIMEOUT=30
SERIAL_LOG=$(mktemp)

echo "=== Testing KCOV Boot ==="
echo "ESP directory: $ESP_DIR"
echo "Serial log: $SERIAL_LOG"

# Run QEMU with a timeout
timeout $TIMEOUT qemu-system-x86_64 \
    -bios "${OVMF_PATH:-/usr/share/OVMF/OVMF_CODE.fd}" \
    -drive format=raw,file=fat:rw:$ESP_DIR \
    -m 256M \
    -vga std \
    -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -nographic \
    -serial file:$SERIAL_LOG \
    2>&1 | head -100 &

QEMU_PID=$!

# Wait for boot to complete
sleep 10

# Kill QEMU
kill $QEMU_PID 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true

echo ""
echo "=== Checking for KCOV initialization ==="

if grep -q "\[KCOV\] Coverage infrastructure initialized" "$SERIAL_LOG"; then
    echo "✓ SUCCESS: KCOV initialization detected"
    echo ""
    echo "=== KCOV-related log entries ==="
    grep -i "kcov\|coverage" "$SERIAL_LOG" || echo "(no coverage messages)"
    rm -f "$SERIAL_LOG"
    exit 0
else
    echo "✗ FAILED: KCOV initialization NOT found"
    echo ""
    echo "=== Last 50 lines of serial output ==="
    tail -50 "$SERIAL_LOG"
    rm -f "$SERIAL_LOG"
    exit 1
fi
