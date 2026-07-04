#!/bin/bash
# Triage AFL++ crash findings
set -euo pipefail

CRASH_DIR="${1:-}"

usage() {
    cat <<EOF
Usage: $0 <crash_directory>

Triage AFL++ crash artifacts and categorize them.

ARGUMENTS:
    crash_directory    Path to AFL++ crashes directory
                       (e.g., fuzz/afl_findings/default/crashes)

EXAMPLES:
    $0 fuzz/afl_findings/default/crashes
    $0 fuzz/afl_findings/fuzzer00/crashes
EOF
    exit 0
}

if [[ -z "$CRASH_DIR" ]] || [[ "$CRASH_DIR" == "-h" ]] || [[ "$CRASH_DIR" == "--help" ]]; then
    usage
fi

if [[ ! -d "$CRASH_DIR" ]]; then
    echo "Error: Crash directory not found: $CRASH_DIR"
    exit 1
fi

echo "========================================="
echo "AFL++ Crash Triage"
echo "========================================="
echo "Directory: $CRASH_DIR"
echo ""

# Count crashes
CRASHES=$(find "$CRASH_DIR" -name 'id:*' -type f 2>/dev/null | wc -l)

if [[ $CRASHES -eq 0 ]]; then
    echo "✅ No crashes found!"
    exit 0
fi

echo "Found $CRASHES crash(es)"
echo ""

# Categorize by type (if AFL++ added classification)
echo "Crash Types:"
for crash in "$CRASH_DIR"/id:*; do
    filename=$(basename "$crash")

    # Extract classification from filename (AFL++ format)
    if [[ "$filename" =~ sig:([0-9]+) ]]; then
        sig="${BASH_REMATCH[1]}"
        case $sig in
            11) sig_name="SIGSEGV (segmentation fault)" ;;
            6)  sig_name="SIGABRT (abort)" ;;
            8)  sig_name="SIGFPE (floating point exception)" ;;
            4)  sig_name="SIGILL (illegal instruction)" ;;
            7)  sig_name="SIGBUS (bus error)" ;;
            *)  sig_name="Signal $sig" ;;
        esac
    else
        sig_name="Unknown"
    fi

    size=$(stat -c%s "$crash" 2>/dev/null || stat -f%z "$crash" 2>/dev/null)
    echo "  - $filename ($size bytes): $sig_name"
done

echo ""
echo "========================================="
echo "Deduplication"
echo "========================================="

# Simple hash-based deduplication
UNIQUE_DIR="$CRASH_DIR/unique"
mkdir -p "$UNIQUE_DIR"

declare -A seen_hashes

for crash in "$CRASH_DIR"/id:*; do
    hash=$(sha256sum "$crash" | cut -d' ' -f1)

    if [[ -z "${seen_hashes[$hash]:-}" ]]; then
        seen_hashes[$hash]="$crash"
        cp "$crash" "$UNIQUE_DIR/"
    fi
done

UNIQUE_COUNT=${#seen_hashes[@]}
echo "Unique crashes: $UNIQUE_COUNT (of $CRASHES total)"
echo "Unique crashes saved to: $UNIQUE_DIR/"
echo ""

echo "========================================="
echo "Next Steps"
echo "========================================="
echo "1. Reproduce crashes with:"
echo "   ./scripts/reproduce_crash.sh <crash_file>"
echo ""
echo "2. Debug with GDB:"
echo "   gdb --args kernel.elf < <crash_file>"
echo ""
echo "3. Generate detailed report:"
echo "   ./scripts/analyze_crashes.sh $UNIQUE_DIR"
