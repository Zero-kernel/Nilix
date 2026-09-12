#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
PYTHON="${PYTHON:-python3}"

"$PYTHON" "$ROOT/scripts/tests/stress_protocol_test.py"
bash -n "$ROOT/scripts/gates/stress/stress_test.sh"
echo "stress-v2 host self-tests passed"
