#!/usr/bin/env bash
# Shared execution only; every caller keeps its complete final workload oracle.

# THREAD-HB C1: print the interrupt-trace policy for a gate whose default is $1.
# NILIX_QEMU_TRACE=full|phased overrides it (scripts/ci/qemu_trace.py).
qemu_trace_policy() {
    local policy="${NILIX_QEMU_TRACE:-$1}"
    case "$policy" in
        full|phased) printf '%s\n' "$policy" ;;
        *) echo "QEMU-RUN BLOCKED: NILIX_QEMU_TRACE must be full or phased" >&2; return 2 ;;
    esac
}

# Print an interrupt trace written by run_gate_qemu, decompressing a zstd one.
qemu_trace_cat() {
    if [ "${QEMU_TRACE_COMPRESS:-none}" = zstd ]; then zstd -dcq -- "$1"; else cat -- "$1"; fi
}

# A phased caller sets QEMU_TRACE_POLICY=phased, QEMU_TRACE_INTLOG and
# QEMU_TRACE_CPUS; the switch receipt is written to $ser.trace.json.
#
# QEMU_TRACE_COMPRESS=zstd (full policy only) streams the caller's
# `-D "$QEMU_TRACE_INTLOG"` through a FIFO into one zstd stream at that path: the
# full trace of a 32-vCPU window filled the runner disk (#63). Its content and
# every verdict are unchanged; qemu_trace_cat and gate_log.py decompress it. A
# failed compressor leaves only "$QEMU_TRACE_INTLOG.partial", which no gate reads.
run_gate_qemu() {
    case "${QEMU_TRACE_COMPRESS:-none}" in
        none) run_gate_qemu_traced "$@"; return ;;
        zstd) ;;
        *) echo "QEMU-RUN BLOCKED: QEMU_TRACE_COMPRESS must be none or zstd"; return 2 ;;
    esac
    if [ "${QEMU_TRACE_POLICY:-full}" != full ]; then
        echo "QEMU-RUN BLOCKED: a compressed interrupt trace needs the full trace policy"
        return 2
    fi
    if ! command -v zstd >/dev/null 2>&1; then
        echo "QEMU-RUN BLOCKED: zstd is required for QEMU_TRACE_COMPRESS=zstd"
        return 2
    fi
    local args=("$@") index target=0 found=0 control writer reader compressor status compressed
    for ((index = 2; index + 1 < ${#args[@]}; index++)); do
        if [ "${args[index]}" = -D ] && [ "${args[index + 1]}" = "${QEMU_TRACE_INTLOG:-}" ]; then
            found=$((found + 1))
            target=$((index + 1))
        fi
    done
    if [ "$found" -ne 1 ]; then
        echo 'QEMU-RUN BLOCKED: QEMU_TRACE_COMPRESS needs exactly one -D "$QEMU_TRACE_INTLOG"'
        return 2
    fi
    control="$(mktemp -d /tmp/nilix-trace-XXXXXX)" || return 2
    if ! mkfifo "$control/intlog"; then rm -rf -- "$control"; return 2; fi
    # Open both ends here so neither zstd nor QEMU can block in open(2). The
    # read-write end is the writer zstd waits on until QEMU has exited, and no
    # child inherits it.
    exec {writer}<>"$control/intlog"
    exec {reader}<"$control/intlog"
    zstd -q -1 -c <&"$reader" >"$QEMU_TRACE_INTLOG" {reader}<&- {writer}>&- &
    compressor=$!
    exec {reader}<&-
    args[target]="$control/intlog"
    run_gate_qemu_traced "${args[@]}" {writer}>&-
    status=$?
    # Both supervisors reap QEMU before returning, so zstd now reaches EOF.
    exec {writer}>&-
    wait "$compressor"
    compressed=$?
    rm -rf -- "$control"
    if [ "$compressed" -ne 0 ]; then
        echo "QEMU-RUN TRACE-COMPRESS FAILED: zstd status $compressed; partial trace at $QEMU_TRACE_INTLOG.partial"
        mv -f -- "$QEMU_TRACE_INTLOG" "$QEMU_TRACE_INTLOG.partial" 2>/dev/null || rm -f -- "$QEMU_TRACE_INTLOG"
    fi
    return "$status"
}

run_gate_qemu_traced() {
    local window="$1" profile="$2"
    shift 2
    local phased=0
    [ "${QEMU_TRACE_POLICY:-full}" = phased ] && phased=1
    case "${QEMU_GATE_MODE:-completion}" in
        completion)
            local trace_args=()
            [ "$phased" = 0 ] || trace_args=(--trace-policy phased --intlog "$QEMU_TRACE_INTLOG"
                --trace-cpus "$QEMU_TRACE_CPUS" --trace-receipt "$ser.trace.json")
            python3 "$ROOT/scripts/ci/qemu_run.py" --serial "$ser" --qemu-stderr "$qemuerr" \
                --receipt "$ser.run.json" --profile "$profile" --timeout "$window" "${trace_args[@]}" -- "$@" \
                2>"$timeoutlog"
            ;;
        window)
            # GNU timeout stays the parent, so the window contract (status 124,
            # one TERM, no KILL) is unchanged; a sidecar owns the QMP switch.
            local qmp_args=() control="" sidecar="" status
            if [ "$phased" = 1 ]; then
                control="$(mktemp -d /tmp/nilix-qmp-XXXXXX)" || return 2
                qmp_args=(-qmp "unix:$control/qmp,server=on,wait=off")
                python3 "$ROOT/scripts/ci/qemu_trace.py" switch --qmp "$control/qmp" --serial "$ser" \
                    --intlog "$QEMU_TRACE_INTLOG" --cpus "$QEMU_TRACE_CPUS" --receipt "$ser.trace.json" \
                    --timeout "$window" --watch-parent >/dev/null &
                sidecar=$!
            fi
            LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$window" \
                bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$@" "${qmp_args[@]}" \
                >/dev/null 2>"$timeoutlog"
            status=$?
            if [ -n "$sidecar" ]; then
                kill -TERM "$sidecar" 2>/dev/null || true
                wait "$sidecar" 2>/dev/null || true
                rm -rf -- "$control"
            fi
            return "$status"
            ;;
        *) echo "QEMU-RUN BLOCKED: QEMU_GATE_MODE must be completion or window"; return 2 ;;
    esac
}

verify_gate_termination() {
    if [ "${QEMU_GATE_MODE:-completion}" = completion ]; then
        python3 "$ROOT/scripts/ci/qemu_run.py" --serial "$ser" --receipt "$ser.run.json" \
            --verify-status "$qemu_status"
    elif [ "${QEMU_GATE_MODE:-completion}" = window ]; then
        local terms kills
        terms=$(grep -acF 'timeout: sending signal TERM to command' "$timeoutlog" || true)
        kills=$(grep -acF 'timeout: sending signal KILL to command' "$timeoutlog" || true)
        [ "$qemu_status" -eq 124 ] && [ "$terms" -eq 1 ] && [ "$kills" -eq 0 ]
    else
        return 1
    fi
}
