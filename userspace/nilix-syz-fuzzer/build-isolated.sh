#!/bin/bash
# Isolated build for nilix-syz-fuzzer
# Must run outside kernel build context

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building Nilix Syzkaller-Style Fuzzer (Isolated) ==="

# Clean any kernel build artifacts
rm -rf target

# Temporarily rename parent .cargo to avoid config inheritance
PARENT_CARGO="../.cargo"
if [ -d "$PARENT_CARGO" ]; then
    mv "$PARENT_CARGO" "${PARENT_CARGO}.disabled"
    RESTORED_PARENT=1
else
    RESTORED_PARENT=0
fi

# Cleanup function to restore parent config
cleanup() {
    if [ "$RESTORED_PARENT" -eq 1 ]; then
        mv "${PARENT_CARGO}.disabled" "$PARENT_CARGO"
    fi
}
trap cleanup EXIT

# Clear any build-std environment variables
unset CARGO_BUILD_STD
unset CARGO_UNSTABLE_BUILD_STD
export RUSTFLAGS=""

# Build for Linux host with nightly (stable doesn't support all our deps)
source ~/.cargo/env
cargo +nightly-2025-12-08 build --release --target x86_64-unknown-linux-gnu

echo "=== Build Complete ==="
ls -lh target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer
