#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin the shared cfg item finder: which construct an attribute marks, where
it ends, and how each gate's safe side resolves what the parser cannot know.

Runs with the gates' own environment (scripts/gate-env), which has tree-sitter.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-orphan-test-modules.py"


def load():
    spec = importlib.util.spec_from_file_location("orphan_cfg_items", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = load()
LONG = G.SafeSide.LEAN_LONG
SHORT = G.SafeSide.LEAN_SHORT


def lines(text: str, side=LONG) -> list[tuple[int, int]]:
    """(first line, last line) of each test item in `text`."""
    return [(i.first_line, i.last_line) for i in G.cfg_items(text, side).items]


def lines_at(text: str, side, path: str) -> list[tuple[int, int]]:
    return [(i.first_line, i.last_line) for i in G.cfg_items(text, side, path=path).items]


class Owner(unittest.TestCase):
    """The construct each attribute marks, both sides agreeing when certain."""

    CASES = {
        "fn": ("#[cfg(test)]\nfn h() {\n  x();\n}\nfn p() {}\n", [(1, 4)]),
        "comment between": ("#[cfg(test)]\n// note\nfn h() {\n  x();\n}\nfn p() {}\n", [(1, 5)]),
        "stacked attributes": ("#[cfg(test)]\n#[inline]\nfn h() {\n}\nfn p() {}\n", [(1, 4)]),
        "braced const generic": ("#[cfg(test)]\nfn h() -> P<{ 8 >> 1 }> {\n  x();\n}\nfn p() {}\n", [(1, 4)]),
        "where commas": ("#[cfg(test)]\npub(crate) async fn h<T>()\nwhere\n  T: Send,\n  T: Sync,\n{\n}\nfn p() {}\n", [(1, 7)]),
        "struct field": ("struct S {\n #[cfg(test)]\n a: u8,\n b: u8,\n}\n", [(2, 3)]),
        "pub tuple field": ("struct S(\n #[cfg(test)]\n pub(crate)\n [u8; { 2 }],\n u16,\n);\n", [(2, 4)]),
        "enum variant": ("enum E {\n #[cfg(test)]\n A(u8),\n B,\n}\n", [(2, 3)]),
        "struct literal field": ("fn p() { let c = C {\n #[cfg(test)]\n probe: make(\n 1),\n t: 50,\n }; }\n", [(2, 4)]),
        "shorthand field": ("fn p() { let c = C {\n #[cfg(test)]\n probe,\n t: 50,\n }; }\n", [(2, 3)]),
        "match arm": ("fn p(x: u8) { match x {\n #[cfg(test)]\n 0 => {\n probe()\n }\n _ => (),\n } }\n", [(2, 5)]),
        "let with a range": ("fn p() {\n #[cfg(test)]\n let r = { 0 }\n   .. f();\n g();\n}\n", [(2, 4)]),
        "comparison statement": ("fn p() {\n #[cfg(test)]\n if 1 < 2 { probe(); }\n product();\n}\n", [(2, 3)]),
        "compound cfg": ('#[cfg(all(test, feature = "x"))]\nmod t {\n}\nfn p() {}\n', [(1, 3)]),
    }

    def test_each_construct(self):
        for name, (text, want) in self.CASES.items():
            for side in (LONG, SHORT):
                with self.subTest(construct=name, side=side):
                    self.assertEqual(lines(text, side), want, text)

    def test_a_cfg_mentioned_inside_another_attribute_marks_nothing(self):
        text = "#[doc = stringify!(#[cfg(test)])]\nfn product() {\n  x();\n}\n"
        for side in (LONG, SHORT):
            with self.subTest(side=side):
                self.assertEqual(lines(text, side), [], text)

    def test_another_attribute_taking_test_as_its_argument_marks_nothing(self):
        text = "#[my_attr(test)]\nfn product() {\n  x();\n}\n"
        self.assertEqual(lines(text), [], text)

    def test_a_comment_between_a_tuple_fields_visibility_and_type(self):
        text = "struct S(\n #[cfg(test)]\n pub(crate) /* why */\n [u8; { 2 }],\n u16,\n);\n"
        self.assertEqual(lines(text), [(2, 4)], text)

    def test_a_cfg_that_builds_outside_tests_marks_nothing(self):
        for cfg in ("any(test, unix)", "not(test)", 'feature = "test"'):
            with self.subTest(cfg=cfg):
                self.assertEqual(lines(f"#[cfg({cfg})]\nfn h() {{}}\n"), [])


class Inner(unittest.TestCase):
    """An inner attribute marks the item whose body holds it."""

    def test_the_file(self):
        self.assertEqual(lines("#![cfg(test)]\nfn a() {}\nfn b() {}\n"), [(1, 3)])

    def test_a_module(self):
        self.assertEqual(lines("mod m {\n #![cfg(test)]\n fn t() {}\n}\nfn p() {}\n"), [(1, 4)])

    def test_a_function(self):
        self.assertEqual(lines("fn f() {\n #![cfg(test)]\n x();\n}\nfn p() {}\n"), [(1, 4)])


class Offsets(unittest.TestCase):
    def test_spans_are_character_offsets_after_non_ascii_text(self):
        text = 'const S: &str = "żółw ✓";\n// é\n#[cfg(test)]\nfn h() {}\nfn p() {}\n'
        (item,) = G.cfg_items(text, LONG).items
        self.assertEqual(text[item.start : item.end], "#[cfg(test)]\nfn h() {}")
        self.assertEqual((item.first_line, item.last_line), (3, 4))


class Unsure(unittest.TestCase):
    """What the parser cannot know resolves by the caller's named side."""

    # A struct pattern with a cfg on a field: a grammar gap of the pinned
    # tree-sitter-rust, outside any listed file.
    BROKEN = (
        "fn p(s: S) {\n let S {\n #[cfg(feature = \"x\")]\n a,\n b,\n } = s;\n}\n"
        "#[cfg(test)]\nmod t {\n fn c() {}\n}\nfn q() {}\n"
    )

    def test_a_file_with_unlisted_errors_is_unsure_as_a_whole(self):
        found = G.cfg_items(self.BROKEN, LONG)
        self.assertTrue(found.parse_errors)
        self.assertEqual(lines(self.BROKEN, LONG), [(1, 12)], "lean long: the whole file is test code")
        self.assertEqual(lines(self.BROKEN, SHORT), [], "lean short: every item is product code")
        self.assertTrue(G.cfg_items(self.BROKEN, SHORT).unsure)

    def test_an_unclosed_item_is_unsure(self):
        text = "fn p() {}\n#[cfg(test)]\nmod tests {\n  fn t() {\n"
        self.assertEqual(lines(text, LONG), [(1, 4)])
        self.assertEqual(lines(text, SHORT), [])

    def test_a_macro_body_holding_only_a_non_test_cfg_is_read(self):
        text = 'fn p() {}\nm! {\n #[cfg(feature = "x")] fn f() {}\n}\n#[cfg(test)]\nfn t() {}\n'
        self.assertEqual(lines(text, LONG), [(5, 6)], text)
        self.assertEqual(G.cfg_items(text, SHORT).unsure, ())

    def test_a_macro_body_holding_a_cfg_is_opaque(self):
        for body in ("#[cfg(test)] fn t() {}", "# [ cfg ( test ) ] fn t() {}", "mod m { #![cfg(test)] fn t() {} }"):
            text = f"fn p() {{}}\nm! {{\n {body}\n}}\nfn q() {{}}\n"
            with self.subTest(body=body):
                self.assertEqual(lines(text, LONG), [(2, 4)], text)
                self.assertEqual(lines(text, SHORT), [], text)
                self.assertTrue(G.cfg_items(text, SHORT).unsure)


class KnownGaps(unittest.TestCase):
    """Each listed grammar gap leaves the items around it their extents."""

    SHAPES = {
        "binding with a path pattern": "fn p(v: V) {\n match v {\n Some(raw @ V::S(_)) => {}\n _ => {}\n }\n}\n",
        "cfg on a struct pattern field": "fn p(s: S) {\n let S {\n #[cfg(feature = \"x\")]\n a,\n b,\n } = s;\n}\n",
    }

    # A listed file whose errors are exactly its listed ones: its items keep
    # their extents, and only an item touching an error is unsure.
    LISTED = "src/gateway/authz.rs"
    GAP = "fn p(v: Value) {\n match v {\n Some(raw @ Value::String(_)) => {\n f()\n }\n _ => {}\n }\n}\n"

    def test_a_listed_file_keeps_its_items_extents(self):
        text = self.GAP + "#[cfg(test)]\nfn t() {\n  x();\n}\nfn q() {}\n"
        found = G.cfg_items(text, SHORT, path=self.LISTED)
        self.assertTrue(found.parse_errors and found.known_gap, found)
        self.assertEqual([(i.first_line, i.last_line) for i in found.items], [(9, 12)])
        self.assertEqual(found.unsure, ())

    def test_the_same_errors_in_an_unlisted_file_are_unsure_as_a_whole(self):
        text = self.GAP + "#[cfg(test)]\nfn t() {\n  x();\n}\nfn q() {}\n"
        found = G.cfg_items(text, SHORT, path="src/elsewhere.rs")
        self.assertFalse(found.known_gap)
        self.assertEqual(found.items, ())

    def test_an_item_touching_a_listed_error_is_unsure(self):
        text = "#[cfg(test)]\n" + self.GAP + "fn q() {}\n"
        self.assertEqual(lines_at(text, SHORT, self.LISTED), [])
        self.assertTrue(G.cfg_items(text, SHORT, path=self.LISTED).unsure)
        # Lean long covers at least the item; recovery may run it further.
        ((first, last),) = lines_at(text, LONG, self.LISTED)
        self.assertEqual(first, 1)
        self.assertGreaterEqual(last, 9)

    def test_an_item_in_the_same_function_as_a_listed_error_is_unsure(self):
        # Recovery can move extents anywhere inside the broken function.
        text = (
            "fn p(v: Value) {\n match v {\n Some(raw @ Value::String(_)) => {\n f()\n }\n _ => {}\n }\n"
            " #[cfg(test)]\n probe();\n}\nfn q() {}\n"
        )
        found = G.cfg_items(text, SHORT, path=self.LISTED)
        self.assertTrue(found.known_gap, found)
        self.assertEqual(found.items, ())
        self.assertTrue(found.unsure)

    def test_a_listed_error_repeated_is_not_the_known_gap(self):
        text = self.GAP + self.GAP.replace("fn p(", "fn p2(")
        self.assertFalse(G.cfg_items(text, SHORT, path=self.LISTED).known_gap)

    def test_each_real_listed_file_still_matches_its_entry(self):
        root = SCRIPT.parent.parent.parent
        for path in sorted(G.KNOWN_GAPS):
            with self.subTest(path=path):
                text = (root / path).read_text(encoding="utf-8")
                found = G.cfg_items(text, SHORT, path=path)
                self.assertTrue(found.parse_errors and found.known_gap, f"{path}: the listed gap no longer matches")

    def test_an_item_right_after_each_gap_keeps_its_extent(self):
        for name, gap in self.SHAPES.items():
            text = gap + "#[cfg(test)]\nfn t() {\n  x();\n}\nfn q() {}\n"
            start = gap.count("\n") + 1
            with self.subTest(gap=name):
                self.assertEqual(G.item_extents_ignoring_errors(text), [(start, start + 3)], text)


class Robust(unittest.TestCase):
    def test_a_deeply_nested_file_does_not_exhaust_the_stack(self):
        depth = 3000
        text = "fn p() " + "{ " * depth + "}" * depth + "\n#[cfg(test)]\nfn t() {}\n"
        self.assertEqual(lines(text, LONG), [(2, 3)])

    def test_a_missing_tree_sitter_names_the_sync_command(self):
        import sys as _sys
        saved = {k: _sys.modules.get(k) for k in ("tree_sitter", "tree_sitter_rust")}
        module = load()
        try:
            _sys.modules["tree_sitter"] = None
            _sys.modules["tree_sitter_rust"] = None
            with self.assertRaises(SystemExit) as raised:
                module.cfg_items("fn a() {}\n", LONG)
            self.assertIn("uv sync --locked --project scripts/gate-env", str(raised.exception))
        finally:
            for k, v in saved.items():
                if v is None:
                    _sys.modules.pop(k, None)
                else:
                    _sys.modules[k] = v


class Report(unittest.TestCase):
    """Each gate prints how many files it parsed with errors."""

    def test_the_summary_counts_errors_and_known_gaps(self):
        report: dict = {}
        G.cfg_items("fn a() {}\n", LONG, path="src/clean.rs", report=report)
        G.cfg_items(Unsure.BROKEN, LONG, path="src/broken.rs", report=report)
        G.cfg_items(KnownGaps.SHAPES["binding with a path pattern"], LONG, path="src/other.rs", report=report)
        self.assertEqual(
            G.parse_error_summary(report),
            "cfg items: 3 files parsed, 2 with parse errors (0 on the known-gap list): "
            "unsure as a whole: src/broken.rs, src/other.rs",
        )


if __name__ == "__main__":
    unittest.main()
