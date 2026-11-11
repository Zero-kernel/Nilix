#!/usr/bin/env bash
# Shared local/Actions entrypoint. Each group owns a single artifact directory.
set -euo pipefail
cd "$(dirname "$0")/../.."
group="${1:?usage: bash scripts/ci/entrypoint.sh quality|license|hosted|tools|build|runtime|strict|smp-32|musl|iommu|mitigation|qemu-fuzz|extended|extended-smp|extended-smp-32|extended-ext3|extended-stress}"
out_root="${CI_ARTIFACTS:-target/ci/$group}"
mkdir -p "$out_root"
out="$(mktemp -d "$out_root/run.XXXXXX")"
failed=0
guest_retries="${CI_GUEST_RETRIES:-1}"
stress_cpus="${CI_STRESS_CPUS:-4}"
case "$group" in
    extended|extended-*) export QEMU_GATE_MODE="${QEMU_GATE_MODE:-window}" ;;
    *) export QEMU_GATE_MODE="${QEMU_GATE_MODE:-completion}" ;;
esac
finish() {
    local status=$?
    trap - EXIT
    if python3 scripts/ci/ci_report.py "$out"; then
        cp "$out/summary.md" "$out_root/summary.md" || status=1
    else
        status=1
    fi
    exit "$status"
}
trap finish EXIT
if [[ ! "$guest_retries" =~ ^(0|1)$ ]]; then
    echo "CI_GUEST_RETRIES must be 0 or 1" >&2
    exit 2
fi
if [[ "$QEMU_GATE_MODE" != completion && "$QEMU_GATE_MODE" != window ]]; then
    echo "QEMU_GATE_MODE must be completion or window" >&2
    exit 2
fi
case "$group" in
    extended|extended-stress)
        if [[ ! "$stress_cpus" =~ ^(4|16)$ ]]; then
            echo "CI_STRESS_CPUS must be 4 or 16" >&2
            exit 2
        fi
        ;;
esac

gate() {
    local name="$1"
    shift
    gate_named "$name" "$name" "$@"
}
gate_named() {
    local artifact_name="$1"
    local display_name="$2"
    shift 2
    python3 scripts/ci/record_gate.py --name "$display_name" --artifacts "$out/$artifact_name" "$@"
}
check() {
    # Continue independent checks, but preserve failure in this group's exit.
    if ! gate "$@"; then failed=1; fi
}
retry_event() {
    local gate_name="$1"
    local attempt="$2"
    local status="$3"
    local action="$4"
    printf 'CI-RETRY gate=%s attempt=%s/2 status=%s action=%s\n' \
        "$gate_name" "$attempt" "$status" "$action" | tee -a "$out/retry.log"
}
check_guest() {
    local name="$1"
    shift
    local first_status second_status
    if gate "$name" "$@"; then
        return 0
    else
        first_status=$?
    fi
    # Retry only an actual guest failure/incomplete result. A qualified result
    # (exit 3) and host/build failures remain single-shot and visible.
    if [[ "$guest_retries" != 1 || ( "$first_status" != 1 && "$first_status" != 2 ) ]]; then
        failed=1
        return 0
    fi
    retry_event "$name" 1 "$first_status" retry
    if gate_named "$name" "$name (retry 1)" "$@"; then
        retry_event "$name" 2 0 recovered
        return 0
    else
        second_status=$?
    fi
    retry_event "$name" 2 "$second_status" final-failure
    failed=1
    return 0
}

extended_smp() {
    # Two full 900-second windows plus the 16-vCPU 200-round final-owner gate
    # fit the 120-minute job budget; keep every first result and leave time for
    # build, log analysis and upload.
    check smp-8-16 --allow-qualified -- bash scripts/gates/boot/extended_smp_test.sh esp
    # PR86-1 runs after the runtime lane so its focused rebuild cannot replace
    # the normal image used above. Keep a private copy for the focused guest,
    # then restore the normal image before any later gate in the combined
    # `extended` group. Completion mode stops at the verdict.
    gate final-owner-build -- env NILIX_ST_K2_FINAL_OWNER_FOCUSED=1 NILIX_ST_K2_FINAL_OWNER_ITERS=200 \
        make build-syscall-test
    focused_esp="$(mktemp -d "$out/focused-esp.XXXXXX")" || exit 2
    cp -a esp/. "$focused_esp/" || exit 2
    check final-owner-16 --allow-qualified -- env KERNEL_TEST_CPUS=16 KERNEL_TEST_TIMEOUT=2700 \
        NILIX_ST_K2_FINAL_OWNER_ITERS=200 bash scripts/gates/boot/shared_final_owner.sh "$focused_esp"
    rm -rf -- "$focused_esp"
    gate restore-build -- make build
}
smp_32() {
    # Preserve the first 32-vCPU result; a stalled probe must not repeat a
    # second 3600-second run automatically.
    check smp-32 --allow-qualified -- env EXTENDED_SMP_CPUS=32 bash scripts/gates/boot/extended_smp_test.sh esp
}
extended_ext3() {
    check_guest ext3 --allow-qualified -- bash -c '
        make ensure-ext3-image || exit
        image=$(mktemp "$PWD/.ci-ext3.XXXXXX") || exit
        trap '\''rm -f -- "$image"'\'' EXIT
        cp disk-ext2.img "$image" || exit
        KERNEL_TEST_DISK="$image" bash scripts/gates/boot/kernel_test.sh esp
    '
}
extended_stress() {
    # Extra `NAME=value` arguments narrow the profile set for one job.
    local name="$1"
    shift
    check_guest "$name" --allow-qualified -- env "$@" STRESS_DURATION="${CI_STRESS_SECONDS:-900}" STRESS_CPUS="$stress_cpus" \
        STRESS_KEEP_ARTIFACTS=1 bash scripts/gates/stress/stress_test.sh esp-stress
}

case "$group" in
    quality)
        check lint -- make lint
        check python -- python3 -m pytest scripts/tests -q --durations=15 \
            --junitxml="$out/python.junit.xml" --cov=scripts \
            --cov-report=term-missing --cov-report="xml:$out/coverage.xml" \
            --cov-report="json:$out/coverage.json" --cov-report="html:$out/coverage-html"
        check shell-syntax -- bash -c 'while IFS= read -r -d "" script; do bash -n "$script" || exit; done < <(find scripts .githooks -type f -name "*.sh" -print0)'
        # The tracked Ext3 fixture must stay host-checkable. A copy that a kernel
        # mounted read-write carries the private journal incompat bit (RF180-50)
        # and breaks ensure-ext3-image, the ext3 gate and every stress profile.
        check ext3-fixture -- e2fsck -fn disk-ext2.img
        ;;
    license)
        # Every file must have a license and copyright rule (REUSE.toml, COPYRIGHT).
        check reuse -- reuse lint
        ;;
    hosted)
        export HOSTED_TEST_LOG_DIR="$out/suites"
        check hosted -- make test-hosted-subcrates
        ;;
    tools)
        check fuzzer-tests -- cargo test --locked --manifest-path userspace/fuzzer/Cargo.toml --all-targets --target x86_64-unknown-linux-gnu
        check fuzzer-clippy -- cargo clippy --locked --manifest-path userspace/fuzzer/Cargo.toml --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
        check fuzz-features -- cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets --all-features --target x86_64-unknown-linux-gnu
        check executor -- cargo test --locked --manifest-path userspace/nilix-syz-fuzzer/Cargo.toml --all-targets --target x86_64-unknown-linux-gnu
        ;;
    build)
        gate build -- make build
        check usercopy -- python3 kernel/tests/usercopy_exception_table_test.py --runtime --kernel-elf esp/kernel.elf
        ;;
    runtime)
        # The CI job downloads the normal ESP built by the build group. Local
        # callers run the build group first; gate_inputs verifies fresh copies.
        check_guest boot --allow-qualified -- bash scripts/gates/boot/boot_check.sh esp
        check_guest runtime --allow-qualified -- bash scripts/gates/boot/kernel_test.sh esp
        check_guest smp --allow-qualified -- bash scripts/gates/boot/smp_test_4core.sh esp
        ;;
    strict)
        # STRICT-Q: boot, runtime at 1 and 4 vCPUs and SMP-4 under
        # ZERO_OS_STRICT_TESTS=1, where a warning, deferral or skip fails the
        # gate. Diagnostic until the declared strict scope lands (#64): exit 3
        # is not accepted, and each first result is kept without a retry.
        export ZERO_OS_STRICT_TESTS=1
        gate build -- make build
        check strict-boot -- bash scripts/gates/boot/boot_check.sh esp
        check strict-runtime -- bash scripts/gates/boot/kernel_test.sh esp
        check strict-runtime-4 -- env KERNEL_TEST_CPUS=4 bash scripts/gates/boot/kernel_test.sh esp
        check strict-smp-4 -- bash scripts/gates/boot/smp_test_4core.sh esp
        ;;
    smp-32)
        # Like runtime, consume the normal ESP from the build job.
        smp_32
        ;;
    musl)
        gate build -- make build-musl-test
        for cpus in 1 4; do
            check_guest "musl-$cpus" -- env MUSL_CHECK_CPUS="$cpus" MUSL_CHECK_TIMEOUT=900 \
                bash scripts/gates/boot/musl_check.sh kernel-target/musl/esp
        done
        ;;
    iommu)
        gate build -- make build
        python3 - "$out/inputs.sha256" <<'PY'
import hashlib, pathlib, subprocess, sys
names = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
pathlib.Path(sys.argv[1]).write_text(''.join(
    hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() + '  ' + name + '\n'
    for name in names if name and pathlib.Path(name).is_file()))
PY
        revision="$(git rev-parse HEAD)"
        check_guest activation --allow-qualified -- bash scripts/gates/qemu/iommu_q35_check.sh esp
        check_guest failures -- python3 scripts/gates/qemu/iommu_failure_probe.py --input-manifest "$out/inputs.sha256" --revision "$revision" --artifacts "$out/failure-probes"
        check_guest device -- python3 scripts/gates/qemu/iommu_device_probe.py --input-manifest "$out/inputs.sha256" --revision "$revision" --artifacts "$out/device-probe"
        ;;
    mitigation)
        mitigation_timeout="${MITIGATION_TIMEOUT:-900}"
        if [[ ! "$mitigation_timeout" =~ ^([1-9]|[1-9][0-9]|[1-8][0-9][0-9]|900)$ ]]; then
            echo "MITIGATION_TIMEOUT must be an integer from 1 to 900" >&2
            exit 2
        fi
        check unsupported-retpoline -- bash -c '
            if cargo check --manifest-path kernel/security/Cargo.toml --target x86_64-unknown-linux-gnu --features retpoline,mm/host_harness,cpu_local/host_harness --locked > "$1" 2>&1; then
                echo "unsupported retpoline unexpectedly compiled"; exit 1
            fi
            grep -F "retpoline is unsupported: no verified compiler transformation" "$1"
        ' -- "$out/retpoline-negative.log"
        gate build -- make build-mitigation-probe
        check_guest runtime -- python3 scripts/gates/qemu/mitigation_check.py --runtime --smp 4 --timeout "$mitigation_timeout" \
            --kernel-elf kernel-target/mitigation/x86_64-unknown-none/release/kernel \
            --esp kernel-target/mitigation/esp --build-command-json kernel-target/mitigation/build-command.json \
            --artifacts "$out/proof"
        ;;
    qemu-fuzz)
        check adapter -- cargo test --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --locked --features qemu-executor --lib qemu_executor::tests
        check kcov-host -- cargo test --locked --manifest-path kernel/coverage/Cargo.toml --features kcov
        check_guest kcov-guest -- env KERNEL_TEST_TIMEOUT=900 KCOV_KEEP_LOGS=1 make test-kcov
        gate executor-build -- make build-fuzz-qemu-deps
        check_guest executor-guest -- python3 scripts/gates/qemu/qemu_fuzz_smoke.py --kernel esp-syz/kernel.elf \
            --artifacts "$out/executor-evidence"
        ;;
    extended)
        # Every extended gate in series, for local use. The workflow runs the
        # extended-* groups below as parallel jobs with their own timeouts.
        gate build -- make build
        extended_smp
        extended_ext3
        gate stress-build -- make build-stress
        extended_stress stress
        ;;
    extended-smp)
        gate build -- make build
        extended_smp
        ;;
    extended-smp-32)
        gate build -- make build
        smp_32
        ;;
    extended-ext3)
        gate build -- make build
        extended_ext3
        ;;
    extended-stress)
        # EXT-CI: one profile per job. A failed 900-second soak is reported as it
        # is: a retry would double the job and mix two runs' evidence.
        profile="${CI_STRESS_PROFILE:-}"
        case "$profile" in
            memory|cpu|smp|thread|process|block|combined) ;;
            *)
                echo "CI_STRESS_PROFILE must be one of memory, cpu, smp, thread, process, block, combined" >&2
                exit 2
                ;;
        esac
        guest_retries=0
        gate stress-build -- make build-stress
        extended_stress "stress-$profile" STRESS_PROFILES="$profile" STRESS_PROFILE_LIMIT=1
        ;;
    *) echo "Unknown CI group: $group" >&2; exit 2 ;;
esac
exit "$failed"
