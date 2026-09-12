#!/usr/bin/env bash
# Shared local/Actions entrypoint. Each group owns a single artifact directory.
set -euo pipefail
cd "$(dirname "$0")/../.."
group="${1:?usage: bash scripts/ci/entrypoint.sh quality|hosted|tools|build|runtime|musl|iommu|mitigation|qemu-fuzz|extended}"
out_root="${CI_ARTIFACTS:-target/ci/$group}"
mkdir -p "$out_root"
out="$(mktemp -d "$out_root/run.XXXXXX")"
failed=0
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

gate() {
    local name="$1"
    shift
    python3 scripts/ci/record_gate.py --name "$name" --artifacts "$out/$name" "$@"
}
check() {
    # Continue independent checks, but preserve failure in this group's exit.
    if ! gate "$@"; then failed=1; fi
}

case "$group" in
    quality)
        check lint -- make lint
        check python -- python3 -m pytest scripts/tests -q --durations=15 \
            --junitxml="$out/python.junit.xml" --cov=scripts \
            --cov-report=term-missing --cov-report="xml:$out/coverage.xml" \
            --cov-report="json:$out/coverage.json" --cov-report="html:$out/coverage-html"
        check shell-syntax -- bash -c 'while IFS= read -r -d "" script; do bash -n "$script" || exit; done < <(find scripts .githooks -type f -name "*.sh" -print0)'
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
        check boot --allow-qualified -- bash scripts/gates/boot/boot_check.sh esp
        check runtime --allow-qualified -- bash scripts/gates/boot/kernel_test.sh esp
        check smp --allow-qualified -- bash scripts/gates/boot/smp_test_4core.sh esp
        ;;
    musl)
        gate build -- make build-musl-test
        for cpus in 1 4; do
            check "musl-$cpus" -- env MUSL_CHECK_CPUS="$cpus" MUSL_CHECK_TIMEOUT=900 \
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
        check activation --allow-qualified -- bash scripts/gates/qemu/iommu_q35_check.sh esp
        check failures -- python3 scripts/gates/qemu/iommu_failure_probe.py --input-manifest "$out/inputs.sha256" --revision "$revision" --artifacts "$out/failure-probes"
        check device -- python3 scripts/gates/qemu/iommu_device_probe.py --input-manifest "$out/inputs.sha256" --revision "$revision" --artifacts "$out/device-probe"
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
        check runtime -- python3 scripts/gates/qemu/mitigation_check.py --runtime --smp 4 --timeout "$mitigation_timeout" \
            --kernel-elf kernel-target/mitigation/x86_64-unknown-none/release/kernel \
            --esp kernel-target/mitigation/esp --build-command-json kernel-target/mitigation/build-command.json \
            --artifacts "$out/proof"
        ;;
    qemu-fuzz)
        check adapter -- cargo test --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --locked --features qemu-executor --lib qemu_executor::tests
        check kcov-host -- cargo test --locked --manifest-path kernel/coverage/Cargo.toml --features kcov
        check kcov-guest -- env KERNEL_TEST_TIMEOUT=900 KCOV_KEEP_LOGS=1 make test-kcov
        gate executor-build -- make build-fuzz-qemu-deps
        check executor-guest -- python3 scripts/gates/qemu/qemu_fuzz_smoke.py --kernel esp-syz/kernel.elf \
            --artifacts "$out/executor-evidence"
        ;;
    extended)
        gate build -- make build
        check smp-8-16 --allow-qualified -- bash scripts/gates/boot/extended_smp_test.sh esp
        check ext3 --allow-qualified -- bash -c '
            make ensure-ext3-image || exit
            image=$(mktemp "$PWD/.ci-ext3.XXXXXX") || exit
            trap '\''rm -f -- "$image"'\'' EXIT
            cp disk-ext2.img "$image" || exit
            KERNEL_TEST_DISK="$image" bash scripts/gates/boot/kernel_test.sh esp
        '
        gate stress-build -- make build-stress
        check stress --allow-qualified -- env STRESS_DURATION="${CI_STRESS_SECONDS:-900}" STRESS_CPUS=4 \
            STRESS_KEEP_ARTIFACTS=1 bash scripts/gates/stress/stress_test.sh esp-stress
        ;;
    *) echo "Unknown CI group: $group" >&2; exit 2 ;;
esac
exit "$failed"
