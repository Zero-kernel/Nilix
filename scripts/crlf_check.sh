#!/bin/bash
# Resolve the repo root from this script's own location so it runs from any CWD
# (no `cd`): git runs against $ROOT via -C, file paths are anchored to $ROOT.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
CR=$(printf '\r')
echo "smp.rs CR lines:    $(grep -c "$CR" "$ROOT/kernel/arch/smp.rs")"
echo "syscall.rs CR lines: $(grep -c "$CR" "$ROOT/kernel/arch/syscall.rs")"
echo "untouched gdt.rs CR: $(grep -c "$CR" "$ROOT/kernel/arch/gdt.rs")"
echo "untouched process.rs CR: $(grep -c "$CR" "$ROOT/kernel/kernel_core/process.rs")"
echo "git autocrlf: $(git -C "$ROOT" config core.autocrlf)"
echo "--- diff --stat (my 2 files) ---"
git -C "$ROOT" diff --stat -- kernel/arch/smp.rs kernel/arch/syscall.rs
echo "--- diff --stat (untouched dirty file process.rs) ---"
git -C "$ROOT" diff --stat -- kernel/kernel_core/process.rs | tail -1
echo "--- diff --numstat (ignore whitespace+eol) my 2 files ---"
git -C "$ROOT" diff --numstat --ignore-all-space -- kernel/arch/smp.rs kernel/arch/syscall.rs
