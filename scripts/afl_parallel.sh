#!/bin/bash
# AFL++ Parallel Fuzzer Manager for Nilix Kernel
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
KERNEL_BIN=""
INPUT_DIR="$PROJECT_ROOT/fuzz/afl_seeds"
OUTPUT_DIR="$PROJECT_ROOT/fuzz/afl_findings"
INSTANCES=4
TIMEOUT_MS=5000
MEMORY_LIMIT="2G"
PIN_CORES=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run multiple AFL++ fuzzer instances in parallel.

OPTIONS:
    --kernel PATH          Path to kernel binary (required)
    --instances N         Number of parallel fuzzers (default: 4)
    --input DIR           Input seed directory (default: fuzz/afl_seeds)
    --output DIR          Output findings directory (default: fuzz/afl_findings)
    --timeout MS          Execution timeout in ms (default: 5000)
    --memory LIMIT        Memory limit per instance (default: 2G)
    --pin-cores           Pin each fuzzer to a dedicated CPU core
    -h, --help            Show this help

EXAMPLES:
    # Run 8 parallel fuzzers
    $0 --kernel kernel.elf --instances 8

    # Pin to cores for better performance
    $0 --kernel kernel.elf --instances $(nproc) --pin-cores
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --kernel)
            KERNEL_BIN="$2"
            shift 2
            ;;
        --instances)
            INSTANCES="$2"
            shift 2
            ;;
        --input)
            INPUT_DIR="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT_MS="$2"
            shift 2
            ;;
        --memory)
            MEMORY_LIMIT="$2"
            shift 2
            ;;
        --pin-cores)
            PIN_CORES=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate
if [[ -z "$KERNEL_BIN" ]]; then
    echo "Error: --kernel is required"
    usage
fi

if [[ ! -f "$KERNEL_BIN" ]]; then
    echo "Error: Kernel binary not found: $KERNEL_BIN"
    exit 1
fi

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Error: Input directory not found: $INPUT_DIR"
    exit 1
fi

# Check AFL++
if ! command -v afl-fuzz &> /dev/null; then
    echo "Error: afl-fuzz not found"
    exit 1
fi

# Prepare output
mkdir -p "$OUTPUT_DIR"

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_FAST_CAL=1

echo "========================================="
echo "AFL++ Parallel Fuzzer for Nilix Kernel"
echo "========================================="
echo "Kernel:    $KERNEL_BIN"
echo "Instances: $INSTANCES"
echo "Input:     $INPUT_DIR"
echo "Output:    $OUTPUT_DIR"
echo "Timeout:   ${TIMEOUT_MS}ms"
echo "Memory:    $MEMORY_LIMIT per instance"
echo "Core pin:  $([ $PIN_CORES -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "========================================="
echo ""

# Launch fuzzers
PIDS=()

for i in $(seq 0 $((INSTANCES - 1))); do
    if [[ $i -eq 0 ]]; then
        # First instance is master (-M)
        INSTANCE_FLAG="-M"
        INSTANCE_NAME="fuzzer00"
    else
        # Others are secondary (-S)
        INSTANCE_FLAG="-S"
        INSTANCE_NAME=$(printf "fuzzer%02d" "$i")
    fi

    AFL_CMD=(
        afl-fuzz
        $INSTANCE_FLAG "$INSTANCE_NAME"
        -i "$INPUT_DIR"
        -o "$OUTPUT_DIR"
        -t "$TIMEOUT_MS"
        -m "$MEMORY_LIMIT"
        -Q
        --
        "$KERNEL_BIN"
    )

    if [[ $PIN_CORES -eq 1 ]]; then
        CORE_ID=$i
        echo "Launching $INSTANCE_NAME on core $CORE_ID..."
        taskset -c "$CORE_ID" "${AFL_CMD[@]}" &> "$OUTPUT_DIR/${INSTANCE_NAME}.log" &
    else
        echo "Launching $INSTANCE_NAME..."
        "${AFL_CMD[@]}" &> "$OUTPUT_DIR/${INSTANCE_NAME}.log" &
    fi

    PIDS+=($!)
    sleep 1  # Stagger startup
done

echo ""
echo "All fuzzers launched. PIDs: ${PIDS[*]}"
echo ""
echo "Monitor progress with:"
echo "  afl-whatsup $OUTPUT_DIR"
echo ""
echo "Stop all fuzzers with:"
echo "  kill ${PIDS[*]}"
echo ""
echo "Press Ctrl+C to stop all fuzzers and exit."

# Wait for all
trap "kill ${PIDS[*]} 2>/dev/null; exit" SIGINT SIGTERM

for pid in "${PIDS[@]}"; do
    wait "$pid"
done

echo "All fuzzers exited."
