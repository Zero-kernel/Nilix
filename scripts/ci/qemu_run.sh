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

# A phased caller sets QEMU_TRACE_POLICY=phased, QEMU_TRACE_INTLOG and
# QEMU_TRACE_CPUS; the switch receipt is written to $ser.trace.json.
run_gate_qemu() {
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
