#!/usr/bin/env bash
# Real-QEMU deterministic KCOV guest executor integration test.

set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
QEMU="${QEMU:-qemu-system-x86_64}"
ESP="${1:-$ROOT/esp-kcov}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac
TEST_TIMEOUT="${KERNEL_TEST_TIMEOUT:-90}"

if ! [[ "$TEST_TIMEOUT" =~ ^[1-9][0-9]*$ ]] ||
   [ "$TEST_TIMEOUT" -lt 5 ] || [ "$TEST_TIMEOUT" -gt 300 ]; then
    echo "KCOV-E2E BLOCKED: KERNEL_TEST_TIMEOUT must be an integer from 5 to 300"
    exit 2
fi

if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    OVMF="$(find /usr/share/OVMF/ -type f -name 'OVMF_CODE*.fd' 2>/dev/null | head -n 1 || true)"
    if [ -z "$OVMF" ]; then
        echo "KCOV-E2E BLOCKED: OVMF firmware not found"
        exit 2
    fi
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "KCOV-E2E BLOCKED: $ESP/kernel.elf missing"
    exit 2
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "KCOV-E2E BLOCKED: $QEMU not found in PATH"
    exit 2
fi

temp_dir="$(mktemp -d)"
serial_log="$temp_dir/serial.log"
normalized_log="$temp_dir/serial.normalized.log"
interrupt_log="$temp_dir/qemu-interrupt.log"
qemu_stderr="$temp_dir/qemu.stderr.log"
qemu_pid=""
qemu_exit_code=""

stop_qemu() {
    if [ -z "${qemu_pid:-}" ]; then
        return
    fi

    if kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$qemu_pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$qemu_pid" 2>/dev/null; then
            kill -KILL "$qemu_pid" 2>/dev/null || true
        fi
    fi

    set +e
    wait "$qemu_pid" 2>/dev/null
    qemu_exit_code=$?
    set -e
    qemu_pid=""
}

cleanup() {
    stop_qemu
    rm -f "$serial_log" "$normalized_log" "$interrupt_log" "$qemu_stderr"
    rmdir "$temp_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

failure_log() {
    local message="$1"
    echo "KCOV-E2E FAIL: $message"
    echo "--- serial output (last 80 lines) ---"
    if [ -f "$normalized_log" ]; then
        tail -n 80 "$normalized_log" 2>/dev/null || true
    else
        tail -n 80 "$serial_log" 2>/dev/null || true
    fi
    if [ -s "$qemu_stderr" ]; then
        echo "--- QEMU stderr (last 20 lines) ---"
        tail -n 20 "$qemu_stderr" 2>/dev/null || true
    fi
    exit 1
}

count_regex() {
    local pattern="$1"
    local count
    count=$(grep -Ec "$pattern" "$normalized_log" 2>/dev/null || true)
    printf '%s' "$count"
}

require_one_regex() {
    local pattern="$1"
    local description="$2"
    local count
    count="$(count_regex "$pattern")"
    if [ "$count" -ne 1 ]; then
        failure_log "$description marker count was $count, expected 1"
    fi
}

require_one_fixed() {
    local marker="$1"
    local description="$2"
    local count
    count=$(grep -Fxc "$marker" "$normalized_log" 2>/dev/null || true)
    if [ "$count" -ne 1 ]; then
        failure_log "$description marker count was $count, expected 1"
    fi
}

PARSED_COUNT=""
PARSED_POPCOUNT=""
PARSED_HASH=""
parse_sequence() {
    local name="$1"
    local iteration="$2"
    local line
    local pattern

    pattern="^NILIX_KCOV_E2E_SEQ name=${name} iteration=${iteration} ops=2 count=[1-9][0-9]* popcount=[1-9][0-9]* hash=[0-9a-f]{16}$"
    require_one_regex "$pattern" "sequence ${name}/${iteration}"
    line=$(grep -E "$pattern" "$normalized_log" | head -n 1 || true)

    if [[ "$line" =~ count=([1-9][0-9]*)[[:space:]]popcount=([1-9][0-9]*)[[:space:]]hash=([0-9a-f]{16})$ ]]; then
        PARSED_COUNT="${BASH_REMATCH[1]}"
        PARSED_POPCOUNT="${BASH_REMATCH[2]}"
        PARSED_HASH="${BASH_REMATCH[3]}"
    else
        failure_log "sequence ${name}/${iteration} marker was malformed"
    fi

    if [ "$PARSED_COUNT" -ne "$PARSED_POPCOUNT" ]; then
        failure_log "sequence ${name}/${iteration} count did not equal bitmap popcount"
    fi
}

echo "=== Nilix KCOV Guest Executor E2E ==="
echo "Kernel:  $ESP/kernel.elf"
echo "OVMF:    $OVMF"
echo "Timeout: ${TEST_TIMEOUT}s"

"$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -accel tcg -smp 1 -m 512M \
    -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -monitor none -serial "file:$serial_log" \
    -d int,cpu_reset -D "$interrupt_log" \
    >/dev/null 2>"$qemu_stderr" &
qemu_pid=$!

deadline=$((SECONDS + TEST_TIMEOUT))
run_state=""
while true; do
    if grep -Fq 'NILIX_KCOV_E2E_FAIL ' "$serial_log" 2>/dev/null ||
       grep -Eq 'KERNEL PANIC|kernel panicked|panicked at' "$serial_log" 2>/dev/null; then
        run_state="guest-failure"
        break
    fi
    if grep -Eiq 'triple[ -]?fault' "$interrupt_log" "$qemu_stderr" 2>/dev/null; then
        run_state="triple-fault"
        break
    fi
    if grep -Fq 'NILIX_KCOV_E2E_PASS' "$serial_log" 2>/dev/null; then
        run_state="complete"
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        run_state="early-exit"
        break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        run_state="timeout"
        break
    fi
    sleep 0.2
done

stop_qemu
tr -d '\r' < "$serial_log" > "$normalized_log"

case "$run_state" in
    complete) ;;
    guest-failure)
        failure_log "guest emitted a failure or panic marker"
        ;;
    triple-fault)
        failure_log "QEMU reported a triple fault"
        ;;
    early-exit)
        failure_log "QEMU exited before PASS (exit ${qemu_exit_code:-unknown})"
        ;;
    timeout)
        failure_log "QEMU exceeded the ${TEST_TIMEOUT}s hard timeout"
        ;;
    *)
        failure_log "internal runner state was invalid"
        ;;
esac

if grep -Eq 'KERNEL PANIC|kernel panicked|panicked at' "$normalized_log"; then
    failure_log "kernel panic detected"
fi
if grep -Eiq 'triple[ -]?fault' "$interrupt_log" "$qemu_stderr" 2>/dev/null; then
    failure_log "QEMU triple-fault marker detected"
fi
if grep -q '^NILIX_KCOV_E2E_FAIL ' "$normalized_log"; then
    failure_log "guest failure marker detected"
fi

nx_count=$(grep -cF 'v=0e e=0011' "$interrupt_log" 2>/dev/null || true)
if [ "$nx_count" -ne 0 ]; then
    failure_log "$nx_count NX violation(s) detected"
fi

if ! grep -Fq '[KCOV] Coverage infrastructure initialized' "$normalized_log"; then
    failure_log "kernel KCOV initialization marker missing"
fi

marker_count=$(grep -c '^NILIX_KCOV_E2E_' "$normalized_log" 2>/dev/null || true)
if [ "$marker_count" -ne 10 ]; then
    failure_log "guest emitted $marker_count E2E markers, expected exactly 10"
fi

require_one_fixed 'NILIX_KCOV_E2E_BEGIN version=1' 'begin'
parse_sequence A 1
a1_count="$PARSED_COUNT"
a1_popcount="$PARSED_POPCOUNT"
a1_hash="$PARSED_HASH"

disabled_pattern='^NILIX_KCOV_E2E_DISABLED count=([1-9][0-9]*) popcount=([1-9][0-9]*) hash=([0-9a-f]{16}) stable=1$'
require_one_regex "$disabled_pattern" 'disabled-coverage'
disabled_line=$(grep -E "$disabled_pattern" "$normalized_log" | head -n 1 || true)
if [[ "$disabled_line" =~ $disabled_pattern ]]; then
    disabled_count="${BASH_REMATCH[1]}"
    disabled_popcount="${BASH_REMATCH[2]}"
    disabled_hash="${BASH_REMATCH[3]}"
else
    failure_log "disabled-coverage marker was malformed"
fi
if [ "$disabled_count" -ne "$a1_count" ] ||
   [ "$disabled_popcount" -ne "$a1_popcount" ] ||
   [ "$disabled_hash" != "$a1_hash" ]; then
    failure_log "coverage changed while KCOV was disabled"
fi

require_one_fixed 'NILIX_KCOV_E2E_RESET count=0 popcount=0' 'reset'
parse_sequence B 1
b_count="$PARSED_COUNT"
b_hash="$PARSED_HASH"
if [ "$b_hash" = "$a1_hash" ]; then
    failure_log "programs A and B reported identical coverage hashes"
fi
require_one_fixed 'NILIX_KCOV_E2E_DIFF value=1' 'coverage-difference'

parse_sequence A 2
a2_count="$PARSED_COUNT"
a2_hash="$PARSED_HASH"
if [ "$a2_count" -ne "$a1_count" ] || [ "$a2_hash" != "$a1_hash" ]; then
    failure_log "repeated program A coverage was unstable"
fi
require_one_fixed 'NILIX_KCOV_E2E_REPEAT name=A stable=1' 'repeatability'
require_one_fixed 'NILIX_KCOV_E2E_FINAL_RESET count=0 popcount=0' 'final-reset'
require_one_fixed 'NILIX_KCOV_E2E_PASS' 'pass'

echo "KCOV-E2E PASS: QEMU executed two distinct deterministic syscall programs"
echo "  A: $a1_count edges, stable across repetition"
echo "  B: $b_count edges, distinct bitmap"
echo "  reset: zero coverage; disabled execution: unchanged coverage"
