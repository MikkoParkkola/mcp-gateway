#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check_cfg_reader_copies.py (MIK-9387.TCFG.2): a new private copy of
the test-only cfg judgement fails; listed copies may only shrink."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_cfg_reader_copies.py"


def load():
    spec = importlib.util.spec_from_file_location("copies", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load()
READER_RS = 'fn judge(a: &syn::Attribute) -> bool {\n    a.path().is_ident("test")\n}\n'
ROW = "src/a.rs\tjudge\t1\tlegacy scanner\n"


class Tree(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def problems(self, listed="", base=None):
        self.write(C.LIST, C.HEADER + listed)
        return C.problems(self.root, base_list=base)


class Detection(Tree):
    def test_each_rust_idiom_is_a_copy(self):
        for body in (
            'fn judge(a: &A) -> bool { a.path().is_ident("test") }',
            'fn judge(t: &str) -> bool { contains_word(t, "test") }',
            'fn judge(l: &str) -> bool { l.trim() == "#[cfg(test)]" }',
            'fn judge(l: &str) -> bool { l.starts_with("#[cfg(test)]") }',
            'fn judge(t: &str) -> bool { t.match_indices("#[cfg(test)]\\nmod ").count() > 0 }',
        ):
            with self.subTest(body=body):
                self.write("src/a.rs", body + "\n")
                self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_a_const_mark_is_a_module_level_copy(self):
        self.write("src/a.rs", 'const MARK: &str = "#[cfg(test)]";\n')
        self.assertEqual(self.problems(), ["new copy: src/a.rs <module> (1, listed 0)"])

    def test_each_python_idiom_is_a_copy(self):
        for body in (
            'import re\nTEST_MOD = re.compile(r"#\\[cfg\\((?:all\\()?test\\b")\n',
            "def names_test(node):\n    return node == ('flag', 'test')\n",
        ):
            with self.subTest(body=body):
                self.write("scripts/x.py", body)
                scope = "<module>" if "TEST_MOD" in body else "names_test"
                self.assertEqual(self.problems(), [f"new copy: scripts/x.py {scope} (1, listed 0)"])

    def test_input_text_and_prose_are_not_copies(self):
        self.write("src/a_tests.rs", '#[test]\nfn row() {\n    let src = "#[cfg(test)]\\nfn f() {}";\n}\n')
        self.write("scripts/x.py", '"""Blanks every `#[cfg(test)]` module."""\nSRC = "#[cfg(test)]\\nmod t;\\n"\n')
        self.write("src/b.rs", '// cfg(test) helper\nconst REASON: &str = "cfg(test) scanner; no secret";\n')
        self.assertEqual(self.problems(), [])

    def test_an_operative_idiom_in_a_test_fn_is_a_copy(self):
        self.write("src/a_tests.rs", '#[test]\nfn row() {\n    let _ = a.path().is_ident("test");\n}\n')
        self.assertEqual(self.problems(), ["new copy: src/a_tests.rs row (1, listed 0)"])

    def test_the_shared_readers_and_the_checker_are_exempt(self):
        for rel in C.EXEMPT:
            self.write(rel, "x = ('flag', 'test')\n" if rel.endswith(".py") else READER_RS)
        self.assertEqual(self.problems(), [])


class Allowances(Tree):
    def test_a_listed_copy_passes_and_a_second_in_its_scope_fails(self):
        self.write("src/a.rs", READER_RS)
        self.assertEqual(self.problems(ROW), [])
        self.write("src/a.rs", READER_RS.replace('is_ident("test")', 'is_ident("test") || a.path().is_ident("test")'))
        self.assertEqual(self.problems(ROW), ["new copy: src/a.rs judge (2, listed 1)"])

    def test_a_same_named_copy_in_a_sibling_module_fails(self):
        self.write("src/a.rs", READER_RS + "mod other {\n" + READER_RS + "}\n")
        self.assertEqual(self.problems(ROW), ["new copy: src/a.rs other::judge (1, listed 0)"])

    def test_a_removed_copy_must_be_unlisted(self):
        self.write("src/a.rs", "fn judge() {}\n")
        self.assertEqual(self.problems(ROW), ["stale allowance: src/a.rs judge (listed 1, found 0)"])

    def test_a_malformed_or_doubled_line_is_refused(self):
        self.write("src/a.rs", READER_RS)
        for listed in ("src/a.rs\tjudge\tone\treason\n", "src/a.rs\tjudge\t1\t\n", ROW + ROW):
            with self.subTest(listed=listed), self.assertRaises(ValueError):
                self.problems(listed)


class ShrinkOnly(Tree):
    def test_an_allowance_may_not_grow_against_the_base(self):
        self.write("src/a.rs", READER_RS)
        self.assertEqual(self.problems(ROW, base=C.HEADER), ["allowance grew: src/a.rs judge (base 0, now 1)"])

    def test_an_allowance_equal_to_the_base_passes(self):
        self.write("src/a.rs", READER_RS)
        self.assertEqual(self.problems(ROW, base=C.HEADER + ROW), [])


class Cli(unittest.TestCase):
    def run_script(self, *args):
        return subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True)

    def test_a_missing_base_exits_2(self):
        self.assertEqual(self.run_script("--base", "no-such-rev-9387").returncode, 2)

    def test_the_real_tree_passes(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
