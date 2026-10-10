#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin how the move checkers read code (MIK-8273).

A move checker that reads a literal wrongly can call a changed literal
unchanged. Each case below is one the checkers once got wrong: a raw string
with any number of `#`, a `//` or a quote inside a raw string when comments
are stripped, and a `super::` chain longer than two in a moved file.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


statements = load("check_moved_statements")
items = load("check_moved_items")


class RawStrings(unittest.TestCase):
    def test_every_delimiter_length_is_one_token(self) -> None:
        # Without `#` a raw string cannot hold a quote, and a backslash does not
        # escape one: `r"a \"` ends at that quote.
        self.assertIn('r"a \\"', statements.TOKEN.findall('let s = r"a \\";'))
        for n in (1, 2, 3, 7, 255):
            h = "#" * n
            text = f'let s = r{h}"a "{h[:-1]} b"{h};'
            self.assertIn(f'r{h}"a "{h[:-1]} b"{h}', statements.TOKEN.findall(text), n)

    def test_a_changed_payload_is_a_change(self) -> None:
        # Only a change between the inner quotes: a reader that splits the raw
        # string there sees `q` and `x` as code and drops the extra space.
        for n in (1, 3):
            h = "#" * n
            a = items.items(f'const S: &str = r{h}"a "q x" b"{h};', False)
            b = items.items(f'const S: &str = r{h}"a "q  x" b"{h};', False)
            self.assertNotEqual(a, b, n)


class Comments(unittest.TestCase):
    def test_a_comment_marker_inside_a_raw_string_is_kept(self) -> None:
        text = 'let s = r#"a // b "q" c"#; // gone\nlet t = 1; /* gone */'
        self.assertEqual(
            statements.strip_comments(text),
            'let s = r#"a // b "q" c"#; \nlet t = 1; ')

    def test_a_changed_raw_payload_is_a_change(self) -> None:
        a = statements.normalise('let s = r#"a "q" // b"#;')
        b = statements.normalise('let s = r#"a "q" // c"#;')
        self.assertNotEqual(a, b)
        a = statements.normalise('let s = r#"a "q x" b"#;')
        b = statements.normalise('let s = r#"a "q  x" b"#;')
        self.assertNotEqual(a, b)


class SuperChains(unittest.TestCase):
    def test_a_moved_file_loses_exactly_one_level(self) -> None:
        for k in (2, 3, 4):
            moved = items.items(f"fn f() {{ {'super::' * k}x() }}", True)
            stayed = items.items(f"fn f() {{ {'super::' * (k - 1)}x() }}", False)
            self.assertEqual(moved, stayed, k)

    def test_one_super_is_left_alone(self) -> None:
        self.assertEqual(
            items.items("fn f() { super::x() }", True),
            items.items("fn f() { super::x() }", False))


if __name__ == "__main__":
    unittest.main()
