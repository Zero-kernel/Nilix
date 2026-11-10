#!/usr/bin/env python3
"""STRICT-Q (#64): scripts/ci/strict_scope.txt must equal the kernel's TestScope declarations."""
from pathlib import Path
import re
import unittest

from scripts.ci import gate_log

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "RuntimeTest": [ROOT / "kernel/src/runtime_tests.rs", *sorted((ROOT / "kernel/src/runtime_tests").glob("*.rs"))],
    "SecurityTest": [ROOT / "kernel/security/tests.rs"],
}
SUITES = {"RuntimeTest": ("RUNTIME",), "SecurityTest": ("SECURITY", "SECURITY-BOOT")}
# A CoveredBy gate names the oracle whose output must contain its marker.
COVERING_ORACLES = {"ring3-mm": ROOT / "scripts/gates/boot/ring3_mm_oracle.sh"}

IMPL = re.compile(r"^impl (RuntimeTest|SecurityTest) for (\w+) \{$", re.MULTILINE)
NAME = re.compile(r"fn name\(&self\) -> &'static str \{\s*\"([^\"]+)\"\s*\}")
SCOPE = re.compile(r"fn scope\(&self\) -> TestScope \{(.*?)\n    \}", re.DOTALL)
NEEDS_CPUS = re.compile(r"\s*TestScope::NeedsCpus\(([1-9][0-9]*)\)\s*")
OUT_OF_SCOPE = re.compile(r'\s*TestScope::OutOfScope \{\s*milestone: "(\S+)",\s*reason: "[^"]+",?\s*\}\s*')
COVERED_BY = re.compile(r'\s*TestScope::CoveredBy \{\s*gate: "(\S+)",\s*marker: "([^"]+)",?\s*\}\s*')


def declarations() -> list[tuple[str, str, str, str, str | None]]:
    """(trait, test name, status, scope token, covered marker) for every non-default scope."""
    found = []
    for trait, paths in SOURCES.items():
        for path in paths:
            text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            for match in IMPL.finditer(text):
                if match[1] != trait:
                    continue
                block = text[match.end():text.index("\n}\n", match.end())]
                name = NAME.search(block)
                scope = SCOPE.search(block)
                if scope is None:
                    continue
                if name is None:
                    raise AssertionError(f"{path.name}: {match[2]} declares a scope without a literal name")
                body = scope[1]
                if needs := NEEDS_CPUS.fullmatch(body):
                    found.append((trait, name[1], "not_applicable", f"needs_cpus:{needs[1]}", None))
                elif out := OUT_OF_SCOPE.fullmatch(body):
                    found.append((trait, name[1], "out_of_scope", f"out_of_scope:{out[1]}", None))
                elif covered := COVERED_BY.fullmatch(body):
                    found.append((trait, name[1], "covered", f"covered_by:{covered[1]}", covered[2]))
                elif body.strip() != "TestScope::InScope":
                    raise AssertionError(f"{path.name}: unrecognized scope declaration for {name[1]}")
    return found


class StrictScopeTests(unittest.TestCase):
    def test_list_equals_kernel_declarations(self):
        expected = {
            (suite, name, status, scope)
            for trait, name, status, scope, _ in declarations()
            for suite in SUITES[trait]
        }
        self.assertTrue(expected)
        self.assertEqual(gate_log.load_strict_scope(), frozenset(expected))

    def test_covered_markers_appear_in_their_oracle(self):
        for _, name, _, scope, marker in declarations():
            if marker is None:
                continue
            gate = scope.removeprefix("covered_by:")
            with self.subTest(test=name, gate=gate):
                self.assertIn(gate, COVERING_ORACLES)
                self.assertIn(marker, COVERING_ORACLES[gate].read_text(encoding="utf-8"))

    def test_parser_sees_the_trait_defaults_but_no_undeclared_impl(self):
        # Both traits default to InScope; an impl that overrides scope() must be parsed above.
        for trait, paths in SOURCES.items():
            impls = sum(len(re.findall(rf"^impl {trait} for ", path.read_text(encoding="utf-8"), re.MULTILINE))
                        for path in paths)
            with self.subTest(trait=trait):
                self.assertGreater(impls, 0)
        self.assertEqual(len({(trait, name) for trait, name, *_ in declarations()}), len(declarations()))


if __name__ == "__main__":
    unittest.main()
