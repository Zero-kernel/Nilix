#!/usr/bin/env bash
# Shared execution only; every caller keeps its complete final workload oracle.
run_gate_qemu() {
    local window="$1" profile="$2"
    shift 2
    case "${QEMU_GATE_MODE:-completion}" in
        completion)
            python3 "$ROOT/scripts/ci/qemu_run.py" --serial "$ser" --qemu-stderr "$qemuerr" \
                --receipt "$ser.run.json" --profile "$profile" --timeout "$window" -- "$@" \
                2>"$timeoutlog"
            ;;
        window)
            LC_ALL=C timeout --foreground --verbose --signal=TERM --kill-after=10s -- "$window" \
                bash -c 'qemuerr=$1; shift; exec "$@" 2>"$qemuerr"' _ "$qemuerr" "$@" \
                >/dev/null 2>"$timeoutlog"
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
