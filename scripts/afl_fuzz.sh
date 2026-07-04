#!/bin/bash
# AFL++ Single-Instance Fuzzer for Nilix Kernel
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
KERNEL_BIN=""
INPUT_DIR="$PROJECT_ROOT/fuzz/afl_seeds"
OUTPUT_DIR="$PROJECT_ROOT/fuzz/afl_findings"
TIMEOUT_MS=5000
MEMORY_LIMIT="2G"
QEMU_MODE=1
INSTANCE_NAME="default"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

AFL++ fuzzer for Nilix kernel.

OPTIONS:
    --kernel PATH          Path to kernel binary (required)
    --input DIR           Input seed directory (default: fuzz/afl_seeds)
    --output DIR          Output findings directory (default: fuzz/afl_findings)
    --timeout MS          Execution timeout in ms (default: 5000)
    --memory LIMIT        Memory limit (default: 2G)
    --no-qemu             Use instrumented binary instead of QEMU mode
    --name NAME           Fuzzer instance name (default: default)
    -h, --help            Show this help

EXAMPLES:
    # QEMU mode (no kernel modification needed)
    $0 --kernel target/x86_64-unknown-none/release/kernel

    # Instrumented mode (faster, requires AFL++-compiled kernel)
    $0 --kernel target/afl/kernel --no-qemu

    # Custom timeout and memory
    $0 --kernel kernel.elf --timeout 10000 --memory 4G
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
        --no-qemu)
            QEMU_MODE=0
            shift
            ;;
        --name)
            INSTANCE_NAME="$2"
            shift 2
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
    echo "Run: ./scripts/generate_afl_seeds.sh to create seeds"
    exit 1
fi

# Check AFL++ installation
AFL_FUZZ_BIN=""
if command -v afl-fuzz &> /dev/null; then
    AFL_FUZZ_BIN="afl-fuzz"
elif [ -f /tmp/AFLplusplus/afl-fuzz ]; then
    AFL_FUZZ_BIN="/tmp/AFLplusplus/afl-fuzz"
else
    echo "Error: afl-fuzz not found. Install AFL++:"
    echo "  sudo apt-get install afl++"
    echo "  OR build from: https://github.com/AFLplusplus/AFLplusplus"
    exit 1
fi

if [[ $QEMU_MODE -eq 1 ]]; then
    AFL_QEMU_BIN=""
    if command -v afl-qemu-trace &> /dev/null; then
        AFL_QEMU_BIN="afl-qemu-trace"
    elif [ -f /tmp/AFLplusplus/afl-qemu-trace ]; then
        AFL_QEMU_BIN="/tmp/AFLplusplus/afl-qemu-trace"
    else
        echo "Error: afl-qemu-trace not found. QEMU mode requires:"
        echo "  cd AFLplusplus/qemu_mode"
        echo "  ./build_qemu_support.sh"
        exit 1
    fi
fi

# Prepare output directory
mkdir -p "$OUTPUT_DIR"

# AFL++ environment
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_FAST_CAL=1

# Set AFL_PATH if using /tmp/AFLplusplus
if [ -d /tmp/AFLplusplus ]; then
    export AFL_PATH=/tmp/AFLplusplus
fi

if [[ $QEMU_MODE -eq 1 ]]; then
    export AFL_QEMU_PERSISTENT_ADDR=""  # TODO: Set if kernel supports persistent mode
fi

# Build command
AFL_CMD=(
    "$AFL_FUZZ_BIN"
    -i "$INPUT_DIR"
    -o "$OUTPUT_DIR"
    -t "$TIMEOUT_MS"
    -m "$MEMORY_LIMIT"
)

if [[ $QEMU_MODE -eq 1 ]]; then
    AFL_CMD+=(-Q)
    export AFL_QEMU_PERSISTENT_ADDR=""
fi

AFL_CMD+=(
    --
    "$KERNEL_BIN"
)

# Add QEMU wrapper if needed
if [[ $QEMU_MODE -eq 1 ]]; then
    # AFL++ will handle QEMU invocation
    :
fi

echo "========================================="
echo "AFL++ Fuzzer for Nilix Kernel"
echo "========================================="
echo "Kernel:   $KERNEL_BIN"
echo "Mode:     $([ $QEMU_MODE -eq 1 ] && echo 'QEMU' || echo 'Instrumented')"
echo "Input:    $INPUT_DIR"
echo "Output:   $OUTPUT_DIR"
echo "Timeout:  ${TIMEOUT_MS}ms"
echo "Memory:   $MEMORY_LIMIT"
echo "Instance: $INSTANCE_NAME"
echo "========================================="
echo ""
echo "Starting fuzzer in 3 seconds..."
sleep 3

# Run AFL++
"${AFL_CMD[@]}"
