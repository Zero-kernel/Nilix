#!/bin/bash
# Normalize the two R171 AP-fix files' line endings to match their HEAD blob,
# so `git diff` shows only the real content change (not a CRLF whole-file flip).
# Runs from any CWD (no `cd`): repo root resolved from this script's location.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
CR=$(printf '\r')
for f in kernel/arch/smp.rs kernel/arch/syscall.rs; do
  if git -C "$ROOT" show HEAD:"$f" | grep -q "$CR"; then
    echo "$f: HEAD is CRLF -> normalizing working copy to CRLF"
    sed -i "s/${CR}*\$/${CR}/" "$ROOT/$f"
  else
    echo "$f: HEAD is LF -> stripping CR from working copy"
    sed -i "s/${CR}\$//" "$ROOT/$f"
  fi
done
echo "--- diff --stat after normalize ---"
git -C "$ROOT" diff --stat -- kernel/arch/smp.rs kernel/arch/syscall.rs
