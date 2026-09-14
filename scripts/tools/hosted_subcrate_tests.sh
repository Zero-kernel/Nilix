#!/usr/bin/env bash
# Hosted kernel sub-crate CI gate.
#
# This is intentionally an allowlist, not `cargo test --workspace`: most kernel
# crates are no_std and some test modules execute privileged instructions or
# require the boot allocator. Every suite listed here has an explicit hosted
# contract and an exact-count oracle so a filter/configuration regression cannot
# silently turn a green job into a zero-test no-op.

set -euo pipefail

# The devbox's non-interactive SSH environment does not load rustup's Cargo
# export.  Keep this gate self-contained so `make test-hosted-subcrates` is
# reproducible without an out-of-band wrapper; the branch is inert on the
# Windows mirror and other hosts that do not have the rustup env file.
if [[ -f /home/dev/.cargo/env ]]; then
    # shellcheck disable=SC1091
    . /home/dev/.cargo/env
fi
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:${PATH:-}"

if [[ -n "${RUST_TEST_THREADS:-}" ]]; then
    echo "ERROR: RUST_TEST_THREADS is set; hosted CI must exercise Rust's default-parallel scheduler." >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_root="${HOSTED_SUBCRATE_TARGET_DIR:-${CARGO_TARGET_DIR:-${repo_root}/hosted-subcrate-target}}"
if [[ "${target_root}" != /* ]]; then
    target_root="${repo_root}/${target_root}"
fi
if [[ -n "${HOSTED_TEST_LOG_DIR:-}" ]]; then
    mkdir -p "$HOSTED_TEST_LOG_DIR"
    log_root="$(cd "$HOSTED_TEST_LOG_DIR" && pwd)"
else
    log_root="$(mktemp -d "${TMPDIR:-/tmp}/zero-os-hosted-tests.XXXXXX")"
    trap 'rm -rf -- "${log_root}"' EXIT
fi
profile_flags=()
rustc_flags=()
case "${HOSTED_TEST_PROFILE:-debug}" in
    debug) ;;
    release) profile_flags=(--release); rustc_flags=(-O) ;;
    *) echo "Unknown HOSTED_TEST_PROFILE" >&2; exit 2 ;;
esac
: > "$log_root/hosted-summary.tsv"

mkdir -p "${target_root}"
cd "${repo_root}"

passed_unit_tests=0

run_suite() {
    local name="$1"
    local expected_passed="$2"
    local expected_filtered="$3"
    shift 3

    local log_file="${log_root}/${name}.log"
    local suite_target="${target_root}/${name}"

    echo "=== hosted sub-crate: ${name} (expected ${expected_passed} passed; default parallelism) ==="
    if ! CARGO_TARGET_DIR="${suite_target}" \
        cargo +nightly-2025-12-08 test "${profile_flags[@]}" "$@" 2>&1 | tee "${log_file}"; then
        echo "ERROR: hosted sub-crate suite '${name}' failed." >&2
        return 1
    fi

    local -a summaries=()
    mapfile -t summaries < <(grep -E '^test result: ' "${log_file}" || true)
    local expected_prefix="test result: ok. ${expected_passed} passed; 0 failed; 0 ignored; 0 measured; ${expected_filtered} filtered out; finished in "
    if [[ ${#summaries[@]} -ne 1 || "${summaries[0]:-}" != "${expected_prefix}"?* ]]; then
        echo "ERROR: hosted sub-crate suite '${name}' produced an unexpected summary." >&2
        echo "Expected exactly one summary with prefix: ${expected_prefix}" >&2
        printf 'Observed summaries (%s):\n' "${#summaries[@]}" >&2
        printf '  %s\n' "${summaries[@]:-<missing>}" >&2
        return 1
    fi

    passed_unit_tests=$((passed_unit_tests + expected_passed))
    printf '%s\t%s\t%s\n' "$name" "$expected_passed" "$expected_filtered" >> "$log_root/hosted-summary.tsv"
    echo "OK: ${name} matched its ${expected_passed}-test fail-closed oracle."
}

run_check() {
    local name="$1"
    shift

    local suite_target="${target_root}/${name}"
    echo "=== hosted test-code compile check: ${name} ==="
    if ! CARGO_TARGET_DIR="${suite_target}" \
        cargo +nightly-2025-12-08 check "${profile_flags[@]}" "$@" 2>&1 | tee "$log_root/$name.log"; then
        echo "ERROR: hosted test-code compile check '${name}' failed." >&2
        return 1
    fi
    echo "OK: ${name} hosted test code compiled."
}

run_standalone_rust_suite() {
    local name="$1"
    local expected_passed="$2"
    local expected_filtered="$3"
    local source_dir="$4"
    local source_file="$5"

    local log_file="${log_root}/${name}.log"
    local suite_target="${target_root}/${name}"
    local test_binary="${suite_target}/${name}"

    mkdir -p "${suite_target}"
    echo "=== hosted standalone Rust suite: ${name} (expected ${expected_passed} passed; default parallelism) ==="
    if ! (
        cd "${repo_root}/${source_dir}"
        NILIX_TEST_TOTAL=74 rustc +nightly-2025-12-08 \
            --edition=2021 "${rustc_flags[@]}" --test "${source_file}" -o "${test_binary}"
        "${test_binary}"
    ) 2>&1 | tee "${log_file}"; then
        echo "ERROR: hosted standalone Rust suite '${name}' failed." >&2
        return 1
    fi

    local -a summaries=()
    mapfile -t summaries < <(grep -E '^test result: ' "${log_file}" || true)
    local expected_prefix="test result: ok. ${expected_passed} passed; 0 failed; 0 ignored; 0 measured; ${expected_filtered} filtered out; finished in "
    if [[ ${#summaries[@]} -ne 1 || "${summaries[0]:-}" != "${expected_prefix}"?* ]]; then
        echo "ERROR: hosted standalone Rust suite '${name}' produced an unexpected summary." >&2
        echo "Expected exactly one summary with prefix: ${expected_prefix}" >&2
        printf 'Observed summaries (%s):\n' "${#summaries[@]}" >&2
        printf '  %s\n' "${summaries[@]:-<missing>}" >&2
        return 1
    fi

    passed_unit_tests=$((passed_unit_tests + expected_passed))
    printf '%s\t%s\t%s\n' "$name" "$expected_passed" "$expected_filtered" >> "$log_root/hosted-summary.tsv"
    echo "OK: ${name} matched its ${expected_passed}-test fail-closed oracle."
}

run_suite audit 15 0 \
    --manifest-path kernel/audit/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --lib --locked

run_suite cpu-local 11 0 \
    --manifest-path kernel/cpu_local/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --lib --locked

# Includes the compile-fail oracle preventing a borrowed local slot from escaping.
CARGO_TARGET_DIR="${target_root}/cpu-local" cargo +nightly-2025-12-08 test "${profile_flags[@]}" \
    --manifest-path kernel/cpu_local/Cargo.toml \
    --target x86_64-unknown-linux-gnu --features host_harness --doc --locked

run_suite livepatch 3 0 \
    --manifest-path kernel/livepatch/Cargo.toml \
    --target x86_64-unknown-linux-gnu --lib --locked

run_suite mm 26 0 \
    --manifest-path kernel/mm/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --lib --locked

run_suite block 22 0 \
    --manifest-path kernel/block/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked

run_suite seccomp 14 0 \
    --manifest-path kernel/seccomp/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked

# The complete cap test binary still contains an older privileged-interrupt
# test that is invalid in a hosted process. Keep the security-relevant RF186
# allocator lifecycle pair executable and count-pinned until that legacy test
# receives an explicit host-harness conversion.
run_suite cap-rf186 2 10 \
    --manifest-path kernel/cap/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked -- rf186_23_

run_suite cap-cloexec 1 11 \
    --manifest-path kernel/cap/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked -- ksa005_

run_suite net 118 0 \
    --manifest-path kernel/net/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked

run_suite ipc-robust 4 17 \
    --manifest-path kernel/ipc/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked -- robust_

run_suite vfs 63 0 \
    --manifest-path kernel/vfs/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --lib --locked

run_suite kernel-core 72 0 \
    --manifest-path kernel/kernel_core/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --lib --locked

# Source-discovery/placeholder polarity oracle.  This is intentionally a
# separate integration target: it validates the same 74 RuntimeTest
# implementations reported by kernel/build.rs and fails closed on stale P0/P1
# placeholders or scanner drift.
# This scanner is pure std source analysis and does not import the kernel.
# Compile it directly so Cargo never tries to link the no_std kernel binary's
# panic/allocation handlers into a hosted std test process.
run_standalone_rust_suite kernel-coverage 3 0 kernel tests/test_coverage.rs
run_standalone_rust_suite iommu-register-window 11 0 kernel/iommu register_window.rs
run_standalone_rust_suite iommu-init-state 5 0 kernel/iommu init_state.rs

# Legacy VT-d encodings, QI completion/error handling and fault ownership are
# pure hosted tests. The MM host harness supplies the hosted allocator contract.
run_suite iommu 67 0 \
    --manifest-path kernel/iommu/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --lib --locked

run_suite mitigation-status 3 13 \
    --manifest-path kernel/security/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness,cpu_local/host_harness \
    --lib --locked -- spectre::status_tests

run_suite mitigation-mappings 3 72 \
    --manifest-path kernel/kernel_core/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness,mitigation_probe \
    --lib --locked -- mitigation_probe::tests

run_check ipc-tests \
    --manifest-path kernel/ipc/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features mm/host_harness \
    --tests --locked

run_check kernel-core-tests \
    --manifest-path kernel/kernel_core/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --tests --locked

run_check kernel-tests \
    --manifest-path kernel/Cargo.toml \
    --target x86_64-unknown-linux-gnu \
    --features host_harness \
    --tests --locked

echo "OK: hosted kernel sub-crate CI gate passed (${passed_unit_tests} unit tests; CpuLocal doctests; 3 test-code compile checks; default parallelism)."
