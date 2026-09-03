#!/bin/sh
# ST-5 FIX: copy the source ESP into a throwaway directory before QEMU boots.
#
# QEMU's writable virtual FAT (-drive fat:rw:<dir>) lets OVMF write NvVars back
# into the tree, and that write-back corrupted esp-stress/EFI/BOOT/BOOTX64.EFI
# in place (docs/stress-gate-status.md §3.3: first boot after a build works,
# every later boot dies in firmware). scripts/stress_test.sh already carries
# this fix; this script applies the same recipe to every Makefile target that
# uses QEMU_COMMON.
#
# Usage: sh scripts/esp_run_copy.sh <source-esp-dir>
# Prints the throwaway copy's path on stdout (consumed by command substitution
# inside QEMU_COMMON). The copy lives under /tmp so the tree is never touched.
set -eu

src="$1"
if [ ! -d "$src" ]; then
    echo "esp_run_copy: source ESP '$src' does not exist" >&2
    exit 1
fi

dst="/tmp/nilix-esp-run/$(basename "$src")"
rm -rf "$dst"
mkdir -p "$dst"
cp -a "$src/." "$dst/"
# Drop stale firmware variable stores so OVMF starts clean each boot.
rm -f "$dst/NvVars"

printf '%s' "$dst"
