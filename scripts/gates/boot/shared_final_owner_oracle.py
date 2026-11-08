#!/usr/bin/env python3
"""Require the real release-window witness on SMP; UP proves accounting only."""
import argparse
from pathlib import Path


def validate(serial: str, cpus: int, iterations: int) -> list[str]:
    mode = "release-window" if cpus > 1 else "sequential"
    expected = [
        f"ST-K2-FINAL-OWNER PASS variant=process iterations={iterations} mode={mode}",
        f"ST-K2-FINAL-OWNER PASS variant=nonlast-thread iterations={iterations}",
    ]
    seen = [line for line in serial.splitlines() if "ST-K2-FINAL-OWNER" in line]
    errors = []
    for marker in expected:
        if seen.count(marker) != 1:
            errors.append(f"expected exactly one '{marker}'")
    if len(seen) != len(expected):
        errors.append("unexpected final-owner markers")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", type=Path)
    parser.add_argument("--cpus", type=int, required=True)
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()
    if args.cpus < 1 or not 1 <= args.iterations <= 1000:
        parser.error("invalid CPU or iteration count")
    errors = validate(args.serial.read_text(errors="replace"), args.cpus, args.iterations)
    for error in errors:
        print(f"FINAL-OWNER FAIL: {error}")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
