#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")")"
PYTHON="${PYTHON:-python3}"

"$PYTHON" "$ROOT/scripts/stress_protocol_test.py"
bash -n "$ROOT/scripts/stress_test.sh"
echo "stress-v2 host self-tests passed"
