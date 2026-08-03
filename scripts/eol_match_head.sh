#!/bin/bash
# Normalize each given file's line endings to match its HEAD blob, so `git diff`
# shows only real content changes (the repo has mixed CRLF/LF files).
# Runs from any CWD (no `cd`): repo root is resolved from this script's location,
# git uses -C, and file args (repo-relative or absolute) are anchored to it.
ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
CR=$(printf '\r')
for f in "$@"; do
  case "$f" in /*) p="$f" ;; *) p="$ROOT/$f" ;; esac
  if git -C "$ROOT" show HEAD:"$f" | grep -q "$CR"; then
    echo "$f: HEAD is CRLF -> converting working copy to CRLF"
    sed -i "s/${CR}*\$/${CR}/" "$p"
  else
    echo "$f: HEAD is LF -> stripping CR from working copy"
    sed -i "s/${CR}\$//" "$p"
  fi
done
echo "--- diff --numstat after normalize ---"
git -C "$ROOT" diff --numstat -- "$@"
