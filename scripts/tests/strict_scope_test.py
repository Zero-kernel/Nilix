#!/usr/bin/env python3
"""STRICT-Q (#64): scripts/ci/strict_scope.txt must equal the kernel's TestScope declarations."""
from __future__ import annotations

from functools import lru_cache
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

RAW_STRING = re.compile(r'(?:br|cr|r)(#*)"')
IMPL = re.compile(r"^impl (RuntimeTest|SecurityTest) for (\w+) \{$", re.MULTILINE)
TRAIT = re.compile(r"^pub trait (RuntimeTest|SecurityTest) \{$", re.MULTILINE)
NAME = re.compile(r"fn name\(&self\) -> &'static str \{\s*\"([^\"]+)\"\s*\}")
SCOPE = re.compile(r"fn scope\(&self\) -> TestScope \{(.*?)\n    \}", re.DOTALL)
NEEDS_CPUS = re.compile(r"\s*TestScope::NeedsCpus\(([1-9][0-9]*)\)\s*")
OUT_OF_SCOPE = re.compile(r'\s*TestScope::OutOfScope \{\s*milestone: "(\S+)",\s*reason: "[^"]+",?\s*\}\s*')
COVERED_BY = re.compile(r'\s*TestScope::CoveredBy \{\s*gate: "(\S+)",\s*marker: "([^"]+)",?\s*\}\s*')


def rust_tokens(text):
    """Yield (token, offset), skipping comments and hiding literal contents.

    Comments may separate `fn` from its name. Literals and punctuation remain
    tokens and break that adjacency. Offsets address the original source.
    """
    def ident_end(start):
        end = start
        while end < len(text) and (text[end] == "_" or ("a" + text[end]).isidentifier()):
            end += 1
        return end

    index = 0
    while index < len(text):
        start = index
        char = text[index]
        # Rust's Pattern_White_Space includes LRM/RLM, which Python excludes.
        if char.isspace() or char in "\u200e\u200f":
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", index):
            depth, index = 1, index + 2
            while depth and index < len(text):
                if text.startswith("/*", index):
                    depth, index = depth + 1, index + 2
                elif text.startswith("*/", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            if depth:
                raise AssertionError("unterminated Rust block comment")
            continue
        raw = RAW_STRING.match(text, index)
        if raw:
            delimiter = '"' + raw[1]
            end = text.find(delimiter, raw.end())
            if end < 0:
                raise AssertionError("unterminated Rust raw string")
            index = end + len(delimiter)
            yield "<literal>", start
            continue
        quote = index + 1 if char in "bc" and text[index + 1:index + 2] == '"' else index
        if text[quote:quote + 1] == '"':
            index = quote + 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise AssertionError("unterminated Rust string")
            yield "<literal>", start
            continue
        quote = index + 1 if text.startswith("b'", index) else index
        if text[quote:quote + 1] == "'":
            # A char has one code point or escape, then a closing quote.
            # Without that closing quote, `'a`/`'static` is a lifetime/label.
            end = quote + 1
            if text[end:end + 1] == "\\":
                end += 1
                if text[end:end + 2] == "u{":
                    close = text.find("}", end + 2)
                    if close < 0:
                        raise AssertionError("unterminated Rust character escape")
                    end = close + 1
                elif text[end:end + 1] == "x":
                    end += 3
                else:
                    end += 1
            else:
                end += 1
            if text[end:end + 1] == "'":
                index = end + 1
                yield "<literal>", start
                continue
            if quote == index and text[index + 1:index + 2].isidentifier():
                index = ident_end(index + 1)
                yield "<lifetime>", start
                continue
        ident = index + 2 if text.startswith("r#", index) else index
        if text[ident:ident + 1].isidentifier():
            index = ident_end(ident)
            yield text[start:index], start
        else:
            index += 1
            yield char, start


@lru_cache(maxsize=128)
def rust_scope_inventory(text):
    """Locate actual methods/impls, never comment or string lookalikes."""
    methods, functions, impls, publics, related = set(), set(), set(), set(), set()
    previous = (None, -1)
    header, has_trait, has_for = None, False, False
    for token, position in rust_tokens(text):
        if token in ("scope", "r#scope") and previous[0] == "fn":
            methods.add(previous[1])
        if token == "fn":
            functions.add(position)
        elif token == "pub":
            publics.add(position)
        elif token == "impl":
            impls.add(position)
            header, has_trait, has_for = position, False, False
        if header is not None:
            has_trait |= token in ("RuntimeTest", "SecurityTest", "r#RuntimeTest", "r#SecurityTest")
            has_for |= token == "for"
            if token in ("{", ";"):
                if has_trait and has_for:
                    related.add(header)
                header = None
        previous = token, position
    return tuple(frozenset(values) for values in (methods, functions, impls, publics, related))


def real_match(pattern, block, offset, positions):
    return next((match for match in pattern.finditer(block) if offset + match.start() in positions), None)


def declarations() -> list[tuple[str, str, str, str, str | None]]:
    """(trait, test name, status, scope token, covered marker) for every non-default scope."""
    found = []
    for trait, paths in SOURCES.items():
        for path in paths:
            text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            methods, functions, impls, publics, _ = rust_scope_inventory(text)
            consumed = set()
            for match in TRAIT.finditer(text):
                if match[1] != trait or match.start() not in publics:
                    continue
                block = text[match.end():text.index("\n}\n", match.end())]
                default = real_match(SCOPE, block, match.end(), methods)
                if default is None or default[1].strip() != "TestScope::InScope":
                    raise AssertionError(f"{path.name}: {trait} must default to InScope")
                consumed.add(match.end() + default.start())
            for match in IMPL.finditer(text):
                if match[1] != trait or match.start() not in impls:
                    continue
                block = text[match.end():text.index("\n}\n", match.end())]
                name = real_match(NAME, block, match.end(), functions)
                scope = real_match(SCOPE, block, match.end(), methods)
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
        if not any(token in text for token in ("scope", "RuntimeTest", "SecurityTest")):
            continue
        methods, _, _, _, related = rust_scope_inventory(text)
        if methods or related:
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
            body.replace("fn scope", "fn r#scope"),
            body.replace("fn scope", "fn /* policy */ scope"),
            body.replace("fn scope", "fn // policy\n    scope"),
            body.replace("fn scope", "fn /* outer /* nested */ tail */ scope"),
            body.replace("fn scope", "fn /* outer /* nested */ tail */ r#scope"),
            body.replace("fn scope", "fn // policy\n    r#scope"),
            body.replace("fn scope", "fn scope /* policy */"),
            body.replace("fn scope", "fn\u200escope"),
            body.replace("fn scope", "fn\u200fscope"),
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
            "impl Alias for Extra { fn r#scope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
            "impl Alias for Extra { fn /* outer /* inner */ tail */ scope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
            "impl Alias for Extra { fn // policy\n r#scope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
            "impl Alias for Extra { fn\u200escope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
            "impl Alias for Extra { fn\u200fscope(&self) -> TestScope { TestScope::NeedsCpus(2) } }",
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


    def test_comment_and_literal_lookalikes_are_not_declarations(self):
        decoys = r'''// fn scope(&self) -> TestScope { TestScope::NeedsCpus(2) }
/* outer fn scope /* nested fn r#scope */ tail */
const TEXT: &str = "fn scope /* not a comment */ // not a comment";
const ESCAPED: &str = "\"fn scope\"";
const BYTES: &[u8] = b"fn scope //";
const RAW: &str = r##"fn scope /* \" */"##;
const RAW_BYTES: &[u8] = br###"fn r#scope //"###;
const CSTR: &core::ffi::CStr = c"fn scope //";
const RAW_CSTR: &core::ffi::CStr = cr##"fn scope /*"##;
const SLASH: char = '/'; const STAR: char = '*'; const QUOTE: char = '\'';
const ESCAPE: char = '\u{27}'; const HEX: u8 = b'\x2f';
fn borrowed<'a>(value: &'a str) -> &'a str { value }
const FAKE_IMPL: &str = r####"
impl RuntimeTest for Fake {
    fn name(&self) -> &'static str { "fake" }
    fn scope(&self) -> TestScope {
        TestScope::NeedsCpus(2)
    }
}
"####;
'''
        methods, _, _, _, related = rust_scope_inventory(decoys)
        self.assertFalse(methods)
        self.assertFalse(related)
        expected = declarations()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "kernel/src/decoys.rs"
            path.parent.mkdir(parents=True)
            path.write_text(decoys, encoding="utf-8")
            sources = {**SOURCES, "RuntimeTest": [*SOURCES["RuntimeTest"], path]}
            with patch.dict(SOURCES, sources):
                self.assertEqual(declarations(), expected)
            with patch.dict(globals(), {"ROOT": root}):
                self.assertEqual(declarations(), expected)

    def test_literal_comment_text_cannot_hide_a_real_override(self):
        prefixes = (
            'const NOTE: &str = "//"; ',
            'const NOTE: &str = "/* fn scope */"; ',
            'const NOTE: &str = "\\\"// fn scope"; ',
            'const NOTE: &str = r###"// fn scope"###; ',
            'const NOTE: &[u8] = b"// fn scope"; ',
            'const NOTE: &[u8] = br##"/* fn scope */"##; ',
            'const NOTE: &core::ffi::CStr = c"// fn scope"; ',
            'const NOTE: &core::ffi::CStr = cr##"/* fn scope */"##; ',
            "const QUOTE: char = '\\''; const SLASH: u8 = b'/'; ",
            "fn borrowed<'a>(value: &'a str) -> &'a str { value } ",
            "/* outer fn scope /* nested fn r#scope */ tail */ ",
        )
        body = "impl RuntimeTest for Extra { fn r#scope(&self) -> TestScope { TestScope::NeedsCpus(2) } }"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "kernel/src/adjacent.rs"
            path.parent.mkdir(parents=True)
            sources = {**SOURCES, "RuntimeTest": [*SOURCES["RuntimeTest"], path]}
            for prefix in prefixes:
                with self.subTest(prefix=prefix):
                    text = prefix + body
                    self.assertEqual(rust_scope_inventory(text)[0], {len(prefix) + body.index("fn r#scope")})
                    path.write_text(text, encoding="utf-8")
                    with patch.dict(SOURCES, sources):
                        with self.assertRaisesRegex(AssertionError, "unrecognized scope"):
                            declarations()
                    # An imported alias in an otherwise unscanned module still
                    # exposes its real method to the same lexical inventory.
                    path.write_text(text.replace("impl RuntimeTest", "impl Alias"), encoding="utf-8")
                    with patch.dict(globals(), {"ROOT": root}):
                        with self.assertRaisesRegex(AssertionError, "unscanned scope"):
                            declarations()

    def test_unterminated_lexical_trivia_fails_closed(self):
        for source in ('/* scope', '/* outer /* inner */ scope', '"fn scope', 'r###"fn scope"##'):
            with self.subTest(source=source):
                with self.assertRaisesRegex(AssertionError, "unterminated Rust"):
                    rust_scope_inventory(source)




if __name__ == "__main__":
    unittest.main()
