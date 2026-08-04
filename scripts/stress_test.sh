#!/usr/bin/env bash
# Zero-OS stress-v2 host orchestrator.
#
# Exit codes:
#   0 - every selected profile satisfied the guest, QMP, and storage contracts
#   1 - at least one selected profile failed
#   3 - a required host prerequisite or suite setting is invalid

set -uo pipefail

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
PROTOCOL="$ROOT/scripts/stress_protocol.py"
QEMU="${QEMU:-qemu-system-x86_64}"
PYTHON="${PYTHON:-python3}"
ESP="${1:-$ROOT/esp-stress}"
case "$ESP" in /*) ;; *) ESP="$ROOT/$ESP" ;; esac

STRESS_DURATION="${STRESS_DURATION:-60}"
STRESS_CPUS="${STRESS_CPUS:-4}"
STRESS_MEM="${STRESS_MEM:-256M}"
STRESS_CONSTRAINED_MEM="${STRESS_CONSTRAINED_MEM:-192M}"
STRESS_DISK_IMAGE="${STRESS_DISK_IMAGE:-$ROOT/disk-ext2.img}"
STRESS_PROFILE_LIMIT="${STRESS_PROFILE_LIMIT:-6}"
STRESS_PROFILES="${STRESS_PROFILES:-memory,cpu,smp,process,block,combined}"
STRESS_BOOT_TIMEOUT="${STRESS_BOOT_TIMEOUT:-90}"
STRESS_SHUTDOWN_GRACE="${STRESS_SHUTDOWN_GRACE:-10}"
STRESS_HEARTBEAT_MAX_MS="${STRESS_HEARTBEAT_MAX_MS:-15000}"
STRESS_HEARTBEAT_GRACE_MS="${STRESS_HEARTBEAT_GRACE_MS:-3000}"
STRESS_MIN_HEARTBEATS="${STRESS_MIN_HEARTBEATS:-2}"
STRESS_ACCEL="${STRESS_ACCEL:-tcg,thread=multi}"
STRESS_CPU_MODEL="${STRESS_CPU_MODEL:-qemu64,+smep,+smap,+umip,+rdrand}"
STRESS_KEEP_ARTIFACTS="${STRESS_KEEP_ARTIFACTS:-0}"

STRESS_MEMORY_LIMIT_DELTA="${STRESS_MEMORY_LIMIT_DELTA:-33554432}"
STRESS_MEMORY_CHUNK_BYTES="${STRESS_MEMORY_CHUNK_BYTES:-1048576}"
STRESS_CPU_ITERATIONS="${STRESS_CPU_ITERATIONS:-500000}"
STRESS_CONTENTION_ITERATIONS="${STRESS_CONTENTION_ITERATIONS:-20000}"
STRESS_CHURN_FANOUT="${STRESS_CHURN_FANOUT:-8}"
STRESS_CHURN_WAVES="${STRESS_CHURN_WAVES:-4}"
STRESS_IO_SLOTS="${STRESS_IO_SLOTS:-12}"
STRESS_IO_WRITES_PER_ROUND="${STRESS_IO_WRITES_PER_ROUND:-64}"
STRESS_RECLAIM_PERCENT="${STRESS_RECLAIM_PERCENT:-100}"

STRESS_COMBINED_MEMORY_LIMIT_DELTA="${STRESS_COMBINED_MEMORY_LIMIT_DELTA:-16777216}"
STRESS_COMBINED_MEMORY_CHUNK_BYTES="${STRESS_COMBINED_MEMORY_CHUNK_BYTES:-524288}"
STRESS_COMBINED_CPU_ITERATIONS="${STRESS_COMBINED_CPU_ITERATIONS:-200000}"
STRESS_COMBINED_CONTENTION_ITERATIONS="${STRESS_COMBINED_CONTENTION_ITERATIONS:-5000}"
STRESS_COMBINED_CHURN_FANOUT="${STRESS_COMBINED_CHURN_FANOUT:-4}"
STRESS_COMBINED_CHURN_WAVES="${STRESS_COMBINED_CHURN_WAVES:-2}"
STRESS_COMBINED_IO_WRITES_PER_ROUND="${STRESS_COMBINED_IO_WRITES_PER_ROUND:-16}"

STRESS_BLOCK_CRASH_ATTEMPTS="${STRESS_BLOCK_CRASH_ATTEMPTS:-12}"
STRESS_BLOCK_KILL_OFFSETS_MS="${STRESS_BLOCK_KILL_OFFSETS_MS:-0,1,2,3,4,6,8,12,16,24,32,48}"
STRESS_BLOCK_ACTIVE_WAIT_MS="${STRESS_BLOCK_ACTIVE_WAIT_MS:-20000}"
STRESS_BLOCK_ACTIVE_POLL_US="${STRESS_BLOCK_ACTIVE_POLL_US:-250}"

TEST_PASS=0
TEST_FAIL=1
ACTIVE_PID=""
ACTIVE_MONITOR_PID=""
VM_STATUS=0
MONITOR_STATUS=0
RUN_END_NS=0
SUITE_TMP=""

blocked() {
    echo "STRESS-TEST BLOCKED: $*" >&2
    exit 3
}

require_positive() {
    local name="$1" value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || blocked "$name must be a positive integer"
}

require_nonnegative() {
    local name="$1" value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || blocked "$name must be a non-negative integer"
}

safe_remove_suite_tmp() {
    [ -n "${SUITE_TMP:-}" ] || return 0
    [ -d "$SUITE_TMP" ] || return 0
    local resolved base_resolved
    resolved="$(realpath "$SUITE_TMP" 2>/dev/null)" || return 1
    base_resolved="$(realpath "${TMPDIR:-/tmp}" 2>/dev/null)" || return 1
    case "$resolved" in
        "$base_resolved"/nilix-stress-v2.*) rm -rf -- "$resolved" ;;
        *) echo "Refusing to remove unexpected temporary path: $resolved" >&2; return 1 ;;
    esac
}

stop_monitor() {
    MONITOR_STATUS=0
    if [ -n "${ACTIVE_MONITOR_PID:-}" ]; then
        kill -TERM "$ACTIVE_MONITOR_PID" 2>/dev/null || true
        wait "$ACTIVE_MONITOR_PID" 2>/dev/null || MONITOR_STATUS=$?
        ACTIVE_MONITOR_PID=""
    fi
}

stop_vm() {
    local requested_signal="${1:-TERM}"
    VM_STATUS=0
    if [ -n "${ACTIVE_PID:-}" ]; then
        kill -"$requested_signal" -- "-$ACTIVE_PID" 2>/dev/null \
            || kill -"$requested_signal" "$ACTIVE_PID" 2>/dev/null \
            || true
        local remaining=$((STRESS_SHUTDOWN_GRACE * 10))
        while kill -0 "$ACTIVE_PID" 2>/dev/null && [ "$remaining" -gt 0 ]; do
            sleep 0.1
            remaining=$((remaining - 1))
        done
        if kill -0 "$ACTIVE_PID" 2>/dev/null; then
            kill -KILL -- "-$ACTIVE_PID" 2>/dev/null \
                || kill -KILL "$ACTIVE_PID" 2>/dev/null \
                || true
        fi
        wait "$ACTIVE_PID" 2>/dev/null || VM_STATUS=$?
        ACTIVE_PID=""
    fi
    stop_monitor
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_vm TERM
    if [ "$STRESS_KEEP_ARTIFACTS" = 1 ] && [ -n "${SUITE_TMP:-}" ]; then
        echo "Stress artifacts retained at: $SUITE_TMP" >&2
    else
        safe_remove_suite_tmp || status=1
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for numeric in \
    STRESS_DURATION STRESS_CPUS STRESS_PROFILE_LIMIT STRESS_BOOT_TIMEOUT \
    STRESS_SHUTDOWN_GRACE STRESS_HEARTBEAT_MAX_MS STRESS_MIN_HEARTBEATS \
    STRESS_MEMORY_LIMIT_DELTA STRESS_MEMORY_CHUNK_BYTES STRESS_CPU_ITERATIONS \
    STRESS_CONTENTION_ITERATIONS STRESS_CHURN_FANOUT STRESS_CHURN_WAVES \
    STRESS_IO_SLOTS STRESS_IO_WRITES_PER_ROUND STRESS_RECLAIM_PERCENT \
    STRESS_COMBINED_MEMORY_LIMIT_DELTA STRESS_COMBINED_MEMORY_CHUNK_BYTES \
    STRESS_COMBINED_CPU_ITERATIONS STRESS_COMBINED_CONTENTION_ITERATIONS \
    STRESS_COMBINED_CHURN_FANOUT STRESS_COMBINED_CHURN_WAVES \
    STRESS_COMBINED_IO_WRITES_PER_ROUND STRESS_BLOCK_CRASH_ATTEMPTS \
    STRESS_BLOCK_ACTIVE_WAIT_MS STRESS_BLOCK_ACTIVE_POLL_US; do
    require_positive "$numeric" "${!numeric}"
done
require_nonnegative STRESS_HEARTBEAT_GRACE_MS "$STRESS_HEARTBEAT_GRACE_MS"
[[ "$STRESS_MEM" =~ ^[1-9][0-9]*[KMG]?$ ]] \
    || blocked "STRESS_MEM must be a QEMU memory size such as 256M"
[[ "$STRESS_CONSTRAINED_MEM" =~ ^[1-9][0-9]*[KMG]?$ ]] \
    || blocked "STRESS_CONSTRAINED_MEM must be a QEMU memory size such as 192M"
[ "$STRESS_CPUS" -le 64 ] || blocked "STRESS_CPUS must not exceed 64"
[ "$STRESS_PROFILE_LIMIT" -le 6 ] || blocked "STRESS_PROFILE_LIMIT must not exceed 6"
[ "$STRESS_KEEP_ARTIFACTS" = 0 ] || [ "$STRESS_KEEP_ARTIFACTS" = 1 ] \
    || blocked "STRESS_KEEP_ARTIFACTS must be 0 or 1"

for tool in "$QEMU" "$PYTHON" timeout mktemp realpath debugfs e2fsck sha256sum stat cp grep tail sed; do
    command -v "$tool" >/dev/null 2>&1 || blocked "$tool is required"
done
[ -f "$PROTOCOL" ] || blocked "$PROTOCOL is missing"
[ -f "$ESP/kernel.elf" ] || blocked "$ESP/kernel.elf is missing; run 'make build-stress'"
[ -f "$STRESS_DISK_IMAGE" ] \
    || blocked "$STRESS_DISK_IMAGE is missing; run 'make ensure-ext3-image'"

if [ -n "${OVMF_PATH:-}" ] && [ -f "$OVMF_PATH" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    OVMF="$(find /usr/share/OVMF -type f -name 'OVMF_CODE*.fd' 2>/dev/null | head -n 1)"
    [ -n "$OVMF" ] || blocked "OVMF firmware not found (set OVMF_PATH)"
fi

TMP_BASE="${TMPDIR:-/tmp}"
SUITE_TMP="$(mktemp -d "$TMP_BASE/nilix-stress-v2.XXXXXXXX")" \
    || blocked "unable to create suite temporary directory"
case "$SUITE_TMP" in *[[:space:]]*) blocked "temporary path contains whitespace unsupported by debugfs" ;; esac

IFS=',' read -r -a REQUESTED_PROFILES <<< "$STRESS_PROFILES"
SELECTED_PROFILES=()
declare -A SEEN_PROFILES=()
for profile in "${REQUESTED_PROFILES[@]}"; do
    case "$profile" in memory|cpu|smp|process|block|combined) ;; *) blocked "unknown profile: $profile" ;; esac
    [ -z "${SEEN_PROFILES[$profile]:-}" ] || blocked "duplicate profile: $profile"
    SEEN_PROFILES[$profile]=1
    SELECTED_PROFILES+=("$profile")
    [ "${#SELECTED_PROFILES[@]}" -ge "$STRESS_PROFILE_LIMIT" ] && break
done
[ "${#SELECTED_PROFILES[@]}" -gt 0 ] || blocked "no stress profiles selected"
if [ "$STRESS_CPUS" -lt 2 ]; then
    for profile in "${SELECTED_PROFILES[@]}"; do
        case "$profile" in smp|combined) blocked "$profile requires STRESS_CPUS >= 2" ;; esac
    done
fi

IFS=',' read -r -a BLOCK_KILL_OFFSETS <<< "$STRESS_BLOCK_KILL_OFFSETS_MS"
[ "${#BLOCK_KILL_OFFSETS[@]}" -ge "$STRESS_BLOCK_CRASH_ATTEMPTS" ] \
    || blocked "STRESS_BLOCK_KILL_OFFSETS_MS has fewer entries than crash attempts"
declare -A SEEN_OFFSETS=()
for offset in "${BLOCK_KILL_OFFSETS[@]}"; do
    require_nonnegative STRESS_BLOCK_KILL_OFFSETS_MS "$offset"
    [ "$offset" -le 1000 ] || blocked "block kill offsets must be at most 1000 ms"
    [ -z "${SEEN_OFFSETS[$offset]:-}" ] || blocked "block kill offsets must be distinct"
    SEEN_OFFSETS[$offset]=1
done

echo "=== Zero-OS Stress-v2 Suite ==="
echo "Kernel:    $ESP/kernel.elf"
echo "Disk:      $STRESS_DISK_IMAGE (fresh disposable copy per profile/attempt)"
echo "OVMF:      $OVMF"
echo "Profiles:  ${SELECTED_PROFILES[*]}"
echo "Duration:  ${STRESS_DURATION}s after READY"
echo "vCPUs:     $STRESS_CPUS"
echo "Artifacts: $SUITE_TMP"

random_hex64() {
    "$PYTHON" -c 'import secrets; print(secrets.token_hex(8))'
}

profile_vcpus() {
    case "$1" in memory|process) echo 1 ;; block) echo 2 ;; *) echo "$STRESS_CPUS" ;; esac
}

profile_workers() {
    case "$1" in memory|process|block) echo 1 ;; *) echo "$STRESS_CPUS" ;; esac
}

profile_memory() {
    case "$1" in memory) echo "$STRESS_CONSTRAINED_MEM" ;; *) echo "$STRESS_MEM" ;; esac
}

create_config() {
    local profile="$1" output="$2" run_id="$3" seed="$4"
    local vcpus workers digest
    vcpus="$(profile_vcpus "$profile")"
    workers="$(profile_workers "$profile")"
    local args=(
        "$PROTOCOL" make-config --output "$output" --profile "$profile"
        --run-id "$run_id" --seed "$seed" --vcpus "$vcpus" --workers "$workers"
        --heartbeat-max-ms "$STRESS_HEARTBEAT_MAX_MS" --rounds-per-heartbeat 1
    )
    case "$profile" in
        memory)
            args+=(--memory-limit-delta "$STRESS_MEMORY_LIMIT_DELTA"
                --memory-chunk-bytes "$STRESS_MEMORY_CHUNK_BYTES"
                --reclaim-percent "$STRESS_RECLAIM_PERCENT")
            ;;
        cpu) args+=(--cpu-iterations "$STRESS_CPU_ITERATIONS") ;;
        smp) args+=(--contention-iterations "$STRESS_CONTENTION_ITERATIONS") ;;
        process)
            args+=(--churn-fanout "$STRESS_CHURN_FANOUT" --churn-waves "$STRESS_CHURN_WAVES")
            ;;
        block)
            args+=(--io-block-bytes 4096 --io-slots "$STRESS_IO_SLOTS"
                --io-writes-per-round "$STRESS_IO_WRITES_PER_ROUND")
            ;;
        combined)
            args+=(--memory-limit-delta "$STRESS_COMBINED_MEMORY_LIMIT_DELTA"
                --memory-chunk-bytes "$STRESS_COMBINED_MEMORY_CHUNK_BYTES"
                --cpu-iterations "$STRESS_COMBINED_CPU_ITERATIONS"
                --contention-iterations "$STRESS_COMBINED_CONTENTION_ITERATIONS"
                --churn-fanout "$STRESS_COMBINED_CHURN_FANOUT"
                --churn-waves "$STRESS_COMBINED_CHURN_WAVES"
                --io-block-bytes 4096 --io-slots "$STRESS_IO_SLOTS"
                --io-writes-per-round "$STRESS_COMBINED_IO_WRITES_PER_ROUND"
                --reclaim-percent "$STRESS_RECLAIM_PERCENT")
            ;;
    esac
    digest="$("$PYTHON" "${args[@]}")" || return 1
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

fsck_repair_safe() {
    local image="$1" status=0
    e2fsck -pf "$image" >/dev/null 2>&1 || status=$?
    [ "$status" -le 1 ]
}

debugfs_remove_if_present() {
    local image="$1" guest_path="$2"
    local listing
    listing="$(LC_ALL=C debugfs -R "stat $guest_path" "$image" 2>&1)"
    if printf '%s\n' "$listing" | grep -q 'Type:[[:space:]]*regular'; then
        debugfs -w -R "rm $guest_path" "$image" >/dev/null 2>&1 || return 1
    elif ! printf '%s\n' "$listing" | grep -q 'File not found'; then
        printf '%s\n' "$listing" >&2
        return 1
    fi
}

inject_config() {
    local image="$1" config="$2" empty_file="$3" log="$4"
    : > "$empty_file" || return 1
    local test_stat
    test_stat="$(LC_ALL=C debugfs -R 'stat /test' "$image" 2>&1)" || return 1
    printf '%s\n' "$test_stat" | grep -q 'Type:[[:space:]]*directory' || return 1
    debugfs_remove_if_present "$image" /test/stress.cfg || return 1
    debugfs_remove_if_present "$image" /test/stress-data.bin || return 1
    debugfs -w -R "write $config /test/stress.cfg" "$image" >"$log" 2>&1 || return 1
    debugfs -w -R "write $empty_file /test/stress-data.bin" "$image" >>"$log" 2>&1 || return 1
    fsck_repair_safe "$image" || return 1

    local config_stat data_stat
    config_stat="$(LC_ALL=C debugfs -R 'stat /test/stress.cfg' "$image" 2>&1)" || return 1
    data_stat="$(LC_ALL=C debugfs -R 'stat /test/stress-data.bin' "$image" 2>&1)" || return 1
    printf '%s\n' "$config_stat" | grep -q 'Type:[[:space:]]*regular' || return 1
    printf '%s\n' "$config_stat" | grep -Eq 'Size:[[:space:]]*256([[:space:]]|$)' || return 1
    printf '%s\n' "$data_stat" | grep -q 'Type:[[:space:]]*regular' || return 1
    printf '%s\n' "$data_stat" | grep -Eq 'Size:[[:space:]]*0([[:space:]]|$)' || return 1
}

prepare_profile_disk() {
    local profile="$1" directory="$2"
    mkdir -p "$directory" || return 1
    local run_id seed digest
    run_id="$(random_hex64)" || return 1
    seed="$(random_hex64)" || return 1
    cp -- "$STRESS_DISK_IMAGE" "$directory/disk.img" || return 1
    digest="$(create_config "$profile" "$directory/stress.cfg" "$run_id" "$seed")" || return 1
    inject_config "$directory/disk.img" "$directory/stress.cfg" \
        "$directory/empty.bin" "$directory/debugfs.log" || return 1
    printf '%s\n' "$run_id" > "$directory/run-id"
    printf '%s\n' "$seed" > "$directory/seed"
    printf '%s\n' "$digest" > "$directory/config-sha256"
    "$PYTHON" "$PROTOCOL" journal-probe --image "$directory/disk.img" \
        --output "$directory/disk-identity.json" >/dev/null || return 1
}

start_vm() {
    local workdir="$1" disk="$2" memory="$3" vcpus="$4" guard_seconds="$5"
    mkdir -p "$workdir" || return 1
    SERIAL_LOG="$workdir/serial.log"
    INTERRUPT_LOG="$workdir/interrupt.log"
    QEMU_STDERR="$workdir/qemu.stderr"
    EVENT_LOG="$workdir/events.jsonl"
    QMP_SOCKET="$workdir/qmp.sock"
    QMP_BEFORE="$workdir/qmp-before.json"
    QMP_AFTER="$workdir/qmp-after.json"
    : > "$SERIAL_LOG"
    : > "$INTERRUPT_LOG"
    : > "$QEMU_STDERR"
    : > "$EVENT_LOG"
    rm -f -- "$QMP_SOCKET"

    local accel_args=()
    [ -z "$STRESS_ACCEL" ] || accel_args=(-accel "$STRESS_ACCEL")
    timeout --signal=TERM --kill-after="${STRESS_SHUTDOWN_GRACE}s" "${guard_seconds}s" \
        "$QEMU" -bios "$OVMF" "${accel_args[@]}" \
        -drive "format=raw,file=fat:rw:$ESP" \
        -drive "if=none,file=$disk,format=raw,id=stressdisk,cache=writeback,discard=unmap" \
        -device virtio-blk-pci,drive=stressdisk \
        -netdev user,id=stressnet \
        -device virtio-net-pci,netdev=stressnet,romfile= \
        -m "$memory" -smp "$vcpus" -cpu "$STRESS_CPU_MODEL" \
        -vga std -display none -no-reboot -no-shutdown \
        -serial "file:$SERIAL_LOG" -qmp "unix:$QMP_SOCKET,server=on,wait=off" \
        -d int,cpu_reset -D "$INTERRUPT_LOG" >/dev/null 2>"$QEMU_STDERR" &
    ACTIVE_PID=$!
    "$PYTHON" "$PROTOCOL" monitor --serial "$SERIAL_LOG" --events "$EVENT_LOG" \
        --poll-ms 50 >/dev/null 2>"$workdir/monitor.stderr" &
    ACTIVE_MONITOR_PID=$!
    return 0
}

wait_marker() {
    local regex="$1" timeout_seconds="$2"
    "$PYTHON" "$PROTOCOL" wait-marker --serial "$SERIAL_LOG" --regex "$regex" \
        --timeout "$timeout_seconds" --poll-ms 50 --pid "$ACTIVE_PID" >/dev/null
}

wait_soak_window() {
    local duration="$1" deadline=$((SECONDS + duration))
    while [ "$SECONDS" -lt "$deadline" ]; do
        kill -0 "$ACTIVE_PID" 2>/dev/null || return 1
        if grep -q '^NILIX_STRESS_V2_FAIL ' "$SERIAL_LOG" 2>/dev/null; then
            return 1
        fi
        sleep 0.25
    done
    kill -0 "$ACTIVE_PID" 2>/dev/null
}

capture_qmp() {
    local output="$1"
    "$PYTHON" "$PROTOCOL" qmp-snapshot --socket "$QMP_SOCKET" --output "$output" \
        --timeout "$STRESS_BOOT_TIMEOUT" >/dev/null
}

record_run_end() {
    RUN_END_NS="$("$PYTHON" "$PROTOCOL" now-ns)" || RUN_END_NS=0
}

show_failure_logs() {
    local label="$1"
    echo "--- $label stress markers ---"
    grep '^NILIX_STRESS_V2_' "$SERIAL_LOG" 2>/dev/null | tail -n 80 | sed 's/^/    /' || true
    echo "--- $label serial tail ---"
    tail -n 40 "$SERIAL_LOG" 2>/dev/null | sed 's/^/    /' || true
    echo "--- $label QEMU stderr tail ---"
    tail -n 20 "$QEMU_STDERR" 2>/dev/null | sed 's/^/    /' || true
}

validate_current_log() {
    local config="$1" mode="$2" minimum_heartbeats="$3" qmp_required="$4"
    local args=(
        "$PROTOCOL" validate-log --config "$config" --serial "$SERIAL_LOG"
        --mode "$mode" --minimum-heartbeats "$minimum_heartbeats"
        --interrupt-log "$INTERRUPT_LOG" --qemu-stderr "$QEMU_STDERR"
    )
    if [ "$mode" != writer ]; then
        args+=(--events "$EVENT_LOG" --end-ns "$RUN_END_NS"
            --heartbeat-grace-ms "$STRESS_HEARTBEAT_GRACE_MS")
    fi
    if [ "$qmp_required" = 1 ]; then
        args+=(--qmp-before "$QMP_BEFORE" --qmp-after "$QMP_AFTER")
    fi
    "$PYTHON" "${args[@]}"
}

run_normal_profile() {
    local profile="$1" directory="$SUITE_TMP/$profile"
    local vcpus workers memory run_id digest qmp_required=0 result=$TEST_PASS
    vcpus="$(profile_vcpus "$profile")"
    workers="$(profile_workers "$profile")"
    memory="$(profile_memory "$profile")"
    case "$profile" in cpu|smp|combined) qmp_required=1 ;; esac

    echo
    echo "=== PROFILE: $profile ==="
    if ! prepare_profile_disk "$profile" "$directory"; then
        echo "  FAIL: unable to create and validate the configured Ext3 image"
        return "$TEST_FAIL"
    fi
    run_id="$(<"$directory/run-id")"
    digest="$(<"$directory/config-sha256")"
    local guard=$((STRESS_BOOT_TIMEOUT + STRESS_DURATION + STRESS_SHUTDOWN_GRACE + 30))
    if ! start_vm "$directory/run" "$directory/disk.img" "$memory" "$vcpus" "$guard"; then
        echo "  FAIL: unable to start QEMU"
        return "$TEST_FAIL"
    fi
    local ready_re="^NILIX_STRESS_V2_READY run=$run_id profile=$profile mode=normal$"
    if ! wait_marker "$ready_re" "$STRESS_BOOT_TIMEOUT"; then
        echo "  FAIL: guest did not reach the exact normal READY marker"
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ] && [ "$qmp_required" = 1 ]; then
        if ! capture_qmp "$QMP_BEFORE"; then
            echo "  FAIL: unable to capture the post-READY QMP vCPU snapshot"
            result=$TEST_FAIL
        fi
    fi
    if [ "$result" -eq "$TEST_PASS" ] && ! wait_soak_window "$STRESS_DURATION"; then
        echo "  FAIL: QEMU exited or the guest failed before the full post-READY window"
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ] && [ "$qmp_required" = 1 ]; then
        if ! capture_qmp "$QMP_AFTER"; then
            echo "  FAIL: unable to capture the final QMP vCPU snapshot"
            result=$TEST_FAIL
        fi
    fi
    stop_vm TERM
    record_run_end
    if [ "$MONITOR_STATUS" -ne 0 ]; then
        echo "  FAIL: marker monitor exited unexpectedly (status=$MONITOR_STATUS)"
        result=$TEST_FAIL
    fi
    if ! validate_current_log "$directory/stress.cfg" normal "$STRESS_MIN_HEARTBEATS" "$qmp_required"; then
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ]; then
        echo "  PASS: profile=$profile run=$run_id config_sha256=$digest duration=${STRESS_DURATION}s"
    else
        show_failure_logs "$profile"
    fi
    return "$result"
}

run_block_profile() {
    echo
    echo "=== PROFILE: block (real JBD2 crash + exact-disk recovery) ==="
    local accepted="" attempt offset directory run_id result
    for ((attempt = 1; attempt <= STRESS_BLOCK_CRASH_ATTEMPTS; attempt++)); do
        offset="${BLOCK_KILL_OFFSETS[attempt - 1]}"
        directory="$SUITE_TMP/block-attempt-$attempt"
        echo "  Writer attempt $attempt/$STRESS_BLOCK_CRASH_ATTEMPTS (kill offset ${offset}ms)"
        if ! prepare_profile_disk block "$directory"; then
            echo "    rejected: unable to prepare disposable image"
            continue
        fi
        run_id="$(<"$directory/run-id")"
        local guard=$((STRESS_BOOT_TIMEOUT + (STRESS_BLOCK_ACTIVE_WAIT_MS / 1000) + 60))
        if ! start_vm "$directory/writer" "$directory/disk.img" "$STRESS_MEM" 2 "$guard"; then
            echo "    rejected: unable to start writer QEMU"
            continue
        fi
        if ! wait_marker "^NILIX_STRESS_V2_READY run=$run_id profile=block mode=writer$" \
            "$STRESS_BOOT_TIMEOUT"; then
            echo "    rejected: writer did not become READY"
            record_run_end
            stop_vm TERM
            continue
        fi
        if ! wait_marker "^NILIX_STRESS_V2_BLOCK_CRASH_ARMED run=$run_id generation=[1-9][0-9]{0,19}$" \
            "$STRESS_BOOT_TIMEOUT"; then
            echo "    rejected: writer did not arm crash injection"
            record_run_end
            stop_vm TERM
            continue
        fi
        if ! "$PYTHON" "$PROTOCOL" wait-journal-active --image "$directory/disk.img" \
            --timeout-ms "$STRESS_BLOCK_ACTIVE_WAIT_MS" --poll-us "$STRESS_BLOCK_ACTIVE_POLL_US" \
            >/dev/null; then
            echo "    rejected: no active journal window was observed"
            record_run_end
            stop_vm KILL
            continue
        fi
        "$PYTHON" -c 'import sys,time; time.sleep(int(sys.argv[1]) / 1000.0)' "$offset"
        record_run_end
        stop_vm KILL

        result=$TEST_PASS
        if [ "$MONITOR_STATUS" -ne 0 ]; then
            echo "    rejected: marker monitor failed (status=$MONITOR_STATUS)"
            result=$TEST_FAIL
        fi
        if ! "$PYTHON" "$PROTOCOL" assert-identity --image "$directory/disk.img" \
            --identity "$directory/disk-identity.json" >/dev/null; then
            echo "    rejected: disposable disk identity changed"
            result=$TEST_FAIL
        fi
        if ! "$PYTHON" "$PROTOCOL" journal-probe --image "$directory/disk.img" \
            --require-active --output "$directory/active-journal.json" >/dev/null; then
            echo "    rejected: SIGKILL missed the active RECOVER/Zero-Intent/s_start tail"
            result=$TEST_FAIL
        fi
        if ! validate_current_log "$directory/stress.cfg" writer 0 0 >/dev/null; then
            echo "    rejected: writer marker/runtime contract failed"
            result=$TEST_FAIL
        fi
        if [ "$result" -eq "$TEST_PASS" ]; then
            accepted="$directory"
            echo "    accepted: captured a genuinely active JBD2 transaction"
            break
        fi
    done
    if [ -z "$accepted" ]; then
        echo "  FAIL: no bounded crash attempt captured an active journal tail"
        return "$TEST_FAIL"
    fi

    directory="$accepted"
    run_id="$(<"$directory/run-id")"
    if ! "$PYTHON" "$PROTOCOL" assert-identity --image "$directory/disk.img" \
        --identity "$directory/active-journal.json" >/dev/null; then
        echo "  FAIL: recovery disk is not the exact file captured from writer boot"
        return "$TEST_FAIL"
    fi
    local guard=$((STRESS_BOOT_TIMEOUT + STRESS_DURATION + STRESS_SHUTDOWN_GRACE + 30))
    if ! start_vm "$directory/recovery" "$directory/disk.img" "$STRESS_MEM" 2 "$guard"; then
        echo "  FAIL: unable to start recovery QEMU"
        return "$TEST_FAIL"
    fi
    result=$TEST_PASS
    if ! wait_marker "^NILIX_STRESS_V2_READY run=$run_id profile=block mode=recovery$" \
        "$STRESS_BOOT_TIMEOUT"; then
        echo "  FAIL: exact crash disk did not select recovery mode"
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ] && \
        ! wait_marker "^NILIX_STRESS_V2_PASS run=$run_id profile=block cycles=[1-9][0-9]{0,19} ops=[1-9][0-9]{0,19} checksum=[0-9a-f]{16}$" \
            "$STRESS_BOOT_TIMEOUT"; then
        echo "  FAIL: recovery did not verify a successor record and PASS"
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ] && \
        ! wait_marker "^NILIX_STRESS_V2_HEARTBEAT run=$run_id profile=block seq=1 cycles=[1-9][0-9]{0,19} ops=[1-9][0-9]{0,19} checksum=[0-9a-f]{16}$" \
            "$STRESS_BOOT_TIMEOUT"; then
        echo "  FAIL: recovery did not emit its first verified heartbeat"
        result=$TEST_FAIL
    fi
    local recovery_hash_before="" recovery_hash_after=""
    if [ "$result" -eq "$TEST_PASS" ]; then
        recovery_hash_before="$(sha256sum "$directory/disk.img" | sed 's/[[:space:]].*$//')" || result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ] && ! wait_soak_window "$STRESS_DURATION"; then
        echo "  FAIL: recovery boot did not remain healthy for the full post-PASS window"
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ]; then
        recovery_hash_after="$(sha256sum "$directory/disk.img" | sed 's/[[:space:]].*$//')" || result=$TEST_FAIL
        if [ "$recovery_hash_before" != "$recovery_hash_after" ]; then
            echo "  FAIL: recovery guest continued writing after the successor proof"
            result=$TEST_FAIL
        fi
    fi
    stop_vm TERM
    record_run_end
    if [ "$MONITOR_STATUS" -ne 0 ]; then
        echo "  FAIL: recovery marker monitor failed (status=$MONITOR_STATUS)"
        result=$TEST_FAIL
    fi
    if ! "$PYTHON" "$PROTOCOL" assert-identity --image "$directory/disk.img" \
        --identity "$directory/active-journal.json" >/dev/null; then
        echo "  FAIL: recovery did not use the exact captured disk file"
        result=$TEST_FAIL
    fi
    if ! "$PYTHON" "$PROTOCOL" journal-probe --image "$directory/disk.img" \
        --require-clean --output "$directory/clean-journal.json" >/dev/null; then
        echo "  FAIL: JBD2 s_start/Ext3 RECOVER were not cleared after recovery"
        result=$TEST_FAIL
    fi
    if ! validate_current_log "$directory/stress.cfg" recovery "$STRESS_MIN_HEARTBEATS" 0; then
        result=$TEST_FAIL
    fi
    if [ "$result" -eq "$TEST_PASS" ]; then
        echo "  PASS: active journal recovered on the exact disk; post-recovery writes stopped"
    else
        show_failure_logs block-recovery
    fi
    return "$result"
}

total=0
passed=0
failed=0
for profile in "${SELECTED_PROFILES[@]}"; do
    total=$((total + 1))
    if [ "$profile" = block ]; then
        run_block_profile
    else
        run_normal_profile "$profile"
    fi
    case $? in
        "$TEST_PASS") passed=$((passed + 1)) ;;
        *) failed=$((failed + 1)) ;;
    esac
done

echo
echo "=== Stress-v2 Summary ==="
echo "Total:  $total"
echo "Passed: $passed"
echo "Failed: $failed"
if [ "$failed" -ne 0 ]; then
    echo "STRESS-TEST UNSTABLE: $failed profile(s) failed"
    exit 1
fi
echo "STRESS-TEST STABLE: $passed passed"
exit 0
