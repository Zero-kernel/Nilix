#!/bin/bash
# Run all fuzz targets in parallel
# Usage: ./run_all_fuzz.sh [timeout_seconds] [jobs]

set -e

TIMEOUT=${1:-300}  # Default 5 minutes per target
JOBS=${2:-4}       # Default 4 parallel jobs

TARGETS=(
    fuzz_syscall
    fuzz_vfs_path
    fuzz_signal_delivery
    fuzz_memory_ops
    fuzz_ipc_message
    fuzz_scheduler
    fuzz_network_packet
    fuzz_cgroup_ops
    fuzz_elf_loader
    fuzz_futex_ops
)

echo "Running ${#TARGETS[@]} fuzz targets with ${JOBS} parallel jobs"
echo "Timeout: ${TIMEOUT}s per target"
echo "=========================================="

# Create artifacts directory
mkdir -p artifacts

# Function to run a single fuzz target
run_fuzz() {
    local target=$1
    echo "[$(date +%H:%M:%S)] Starting ${target}..."

    if cargo +nightly fuzz run "${target}" -- \
        -max_total_time="${TIMEOUT}" \
        -rss_limit_mb=4096 \
        -print_final_stats=1 \
        > "artifacts/${target}.log" 2>&1; then
        echo "[$(date +%H:%M:%S)] ✓ ${target} completed"
    else
        echo "[$(date +%H:%M:%S)] ✗ ${target} found issues (check artifacts/)"
    fi
}

export -f run_fuzz
export TIMEOUT

# Run targets in parallel using xargs
printf '%s\n' "${TARGETS[@]}" | xargs -P "${JOBS}" -I {} bash -c 'run_fuzz "$@"' _ {}

echo "=========================================="
echo "All fuzz targets completed"
echo "Logs: fuzz/artifacts/*.log"
echo "Crashes: fuzz/artifacts/*/crash-*"

# Check for crashes
CRASH_COUNT=0
for target in "${TARGETS[@]}"; do
    crashes=$(find "artifacts/${target}" -name 'crash-*' 2>/dev/null | wc -l || echo 0)
    if [ "$crashes" -gt 0 ]; then
        echo "⚠️  ${target}: ${crashes} crashes found"
        CRASH_COUNT=$((CRASH_COUNT + crashes))
    fi
done

if [ "$CRASH_COUNT" -gt 0 ]; then
    echo ""
    echo "❌ Total crashes found: ${CRASH_COUNT}"
    echo "Run 'cargo +nightly fuzz run <target> <crash-file>' to reproduce"
    exit 1
else
    echo ""
    echo "✅ No crashes found"
    exit 0
fi
