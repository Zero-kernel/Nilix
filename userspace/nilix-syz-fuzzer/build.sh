#!/bin/bash
# Build script for nilix-syz-fuzzer (runs on Linux host, not bare-metal)

set -e

cd "$(dirname "$0")"

echo "=== Building Nilix Syzkaller-Style Fuzzer ==="

# Use stable Rust for host tools
if command -v rustup &> /dev/null; then
    rustup default stable
fi

# Build with standard library (not -Zbuild-std)
cargo build --release

echo "=== Build Complete ==="
ls -lh target/release/nilix-syz-fuzzer
