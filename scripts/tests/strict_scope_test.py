#!/usr/bin/env python3
"""STRICT-Q (#64): scripts/ci/strict_scope.txt must equal the kernel's TestScope declarations."""
from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

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
TRAIT = re.compile(r"^pub trait (RuntimeTest|SecurityTest) \{$", re.MULTILINE)
SCOPE_METHOD = re.compile(r"\bfn\s+scope\b")
RELATED_IMPL = re.compile(r"^\s*impl\b[^{};]*\b(?:RuntimeTest|SecurityTest)\b[^{};]*\bfor\b", re.MULTILINE)
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
            methods = {match.start() for match in SCOPE_METHOD.finditer(text)}
            consumed = set()
            for match in TRAIT.finditer(text):
                if match[1] != trait:
                    continue
                block = text[match.end():text.index("\n}\n", match.end())]
                default = SCOPE.search(block)
                if default is None or default[1].strip() != "TestScope::InScope":
                    raise AssertionError(f"{path.name}: {trait} must default to InScope")
                consumed.add(match.end() + default.start())
            for match in IMPL.finditer(text):
                if match[1] != trait:
                    continue
                block = text[match.end():text.index("\n}\n", match.end())]
                name = NAME.search(block)
                scope = SCOPE.search(block)
                if scope is None:
                    continue
                consumed.add(match.end() + scope.start())
                if name is None:
                    raise AssertionError(f"{path.name}: {match[2]} declares a scope without a literal name")
                body = scope[1]
                if needs := NEEDS_CPUS.fullmatch(body):
                    if not gate_log.valid_declared_scope("not_applicable", f"needs_cpus:{needs[1]}"):
                        raise AssertionError(f"{path.name}: invalid CPU scope for {name[1]}")
                    found.append((trait, name[1], "not_applicable", f"needs_cpus:{needs[1]}", None))
                elif out := OUT_OF_SCOPE.fullmatch(body):
                    found.append((trait, name[1], "out_of_scope", f"out_of_scope:{out[1]}", None))
                elif covered := COVERED_BY.fullmatch(body):
                    found.append((trait, name[1], "covered", f"covered_by:{covered[1]}", covered[2]))
                elif body.strip() != "TestScope::InScope":
                    raise AssertionError(f"{path.name}: unrecognized scope declaration for {name[1]}")
            # Unsupported signatures, qualified/generic/inline impls, and
            # additional methods must fail closed instead of looking default.
            if methods != consumed:
                raise AssertionError(f"{path.name}: unrecognized scope method or impl")
    # The declaration registry is intentionally small. Moving/adding an impl
    # in another kernel module must not silently remove it from this check.
    scanned = {path.resolve() for paths in SOURCES.values() for path in paths}
    for path in (ROOT / "kernel").rglob("*.rs"):
        if path.resolve() in scanned:
            continue
        text = path.read_text(encoding="utf-8")
        if SCOPE_METHOD.search(text) or RELATED_IMPL.search(text):
            raise AssertionError(f"{path.relative_to(ROOT)}: unscanned scope declaration or test impl")
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

    def test_unrecognized_scope_methods_never_look_like_the_default(self):
        body = '''impl RuntimeTest for Extra {
    fn name(&self) -> &'static str { "extra" }
    fn scope(&self) -> TestScope {
        TestScope::NeedsCpus(2)
    }
}
'''
        variants = (
            body.replace("-> TestScope", "-> crate::runtime_tests::TestScope"),
            body.replace("impl RuntimeTest", "impl crate::runtime_tests::RuntimeTest"),
            body.replace("impl RuntimeTest for Extra", "impl<T> RuntimeTest for Extra<T>"),
            body.replace("\n", " "),
            body.replace("    fn scope", "    fn\n    scope"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "extra.rs"
            sources = {**SOURCES, "RuntimeTest": [*SOURCES["RuntimeTest"], path]}
            for source in variants:
                with self.subTest(source=source), patch.dict(SOURCES, sources):
                    path.write_text(source, encoding="utf-8")
                    with self.assertRaisesRegex(AssertionError, "unrecognized scope"):
                        declarations()

    def test_trait_scope_default_must_remain_in_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.rs"
            source = SOURCES["RuntimeTest"][0].read_text(encoding="utf-8")
            path.write_text(source.replace("TestScope::InScope", "TestScope::NeedsCpus(2)", 1), encoding="utf-8")
            sources = {**SOURCES, "RuntimeTest": [path, *SOURCES["RuntimeTest"][1:]]}
            with patch.dict(SOURCES, sources):
                with self.assertRaisesRegex(AssertionError, "must default to InScope"):
                    declarations()

    def test_new_kernel_modules_cannot_escape_the_scope_inventory(self):
        variants = (
            "impl RuntimeTest for Extra { fn scope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
            "impl crate::runtime_tests::RuntimeTest for Extra { fn name(&self) -> &'static str { \"extra\" } }",
            "impl<T> RuntimeTest for Extra<T> { fn name(&self) -> &'static str { \"extra\" } }",
            "mod nested { impl Alias for Extra { fn scope(&self) -> TestScope { TestScope::NeedsCpus(2) } } }",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "kernel/src/new_tests/nested.rs"
            path.parent.mkdir(parents=True)
            for source in variants:
                with self.subTest(source=source), patch.dict(globals(), {"ROOT": root}):
                    path.write_text(source, encoding="utf-8")
                    with self.assertRaisesRegex(AssertionError, "unscanned scope"):
                        declarations()


if __name__ == "__main__":
    unittest.main()
