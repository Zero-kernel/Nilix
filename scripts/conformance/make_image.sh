#!/usr/bin/env bash
# Package built conformance test binaries and list.txt into a fresh 256 MiB ext3
# disk image without touching disk-ext2.img (N2.2, #66).
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $0 <bin_dir> <manifest_txt> <output_img> [size_mb]" >&2
    exit 2
fi

BIN_DIR="$1"
MANIFEST="$2"
OUT_IMG="$3"
SIZE_MB="${4:-256}"

for tool in mkfs.ext3 debugfs dd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "CONFORMANCE-IMAGE ERROR: $tool not found in PATH" >&2
        exit 2
    fi
done

if [ ! -d "$BIN_DIR" ] || [ ! -f "$MANIFEST" ]; then
    echo "CONFORMANCE-IMAGE ERROR: missing bin_dir or manifest ($BIN_DIR, $MANIFEST)" >&2
    exit 2
fi

mkdir -p "$(dirname "$OUT_IMG")"
TMP_IMG="${OUT_IMG}.tmp.$$"
CMD_FILE="$(mktemp)"
cleanup() {
    rm -f "$TMP_IMG" "$CMD_FILE"
}
trap cleanup EXIT

dd if=/dev/zero of="$TMP_IMG" bs=1M count="$SIZE_MB" status=none
mkfs.ext3 -q -F -b 4096 -I 256 -J size=4 -L "nilix-conf" "$TMP_IMG"

{
    echo "mkdir /test"
    echo "mkdir /test/conformance"
    echo "mkdir /test/conformance/bin"
    echo "mkdir /test/conformance/work"
    echo "write $MANIFEST /test/conformance/list.txt"
    while read -r _suite name _guest_path; do
        case "${_suite:-}" in
            ""|\#*) continue ;;
        esac
        host_bin="$BIN_DIR/$name"
        if [ ! -f "$host_bin" ]; then
            echo "CONFORMANCE-IMAGE ERROR: missing binary $host_bin" >&2
            exit 2
        fi
        echo "write $host_bin /test/conformance/bin/$name"
    done < "$MANIFEST"
} > "$CMD_FILE"

debugfs -w -f "$CMD_FILE" "$TMP_IMG" >/dev/null
mv -f "$TMP_IMG" "$OUT_IMG"
trap - EXIT

echo "CONFORMANCE-IMAGE OK path=$OUT_IMG size_mb=$SIZE_MB entries=$(grep -vcE '^[[:space:]]*(#|$)' "$MANIFEST")"
