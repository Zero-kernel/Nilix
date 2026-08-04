#!/bin/bash
# Isolated build for nilix-syz-fuzzer
# Must run outside kernel build context

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building Nilix Syzkaller-Style Fuzzer (Isolated) ==="

# Clean any kernel build artifacts
rm -rf target

# Explicitly use stable Rust and standard library (not build-std)
export CARGO_BUILD_STD=""
export RUSTFLAGS=""

# Build for Linux host
source ~/.cargo/env
cargo +stable build --release --target x86_64-unknown-linux-gnu

echo "=== Build Complete ==="
ls -lh target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer
