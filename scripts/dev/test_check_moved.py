#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin how the move checkers read code and what check_moved_items.py proves
(MIK-8271).

A move checker that reads a literal wrongly can call a changed literal
unchanged. The lexing cases are ones the checkers once got wrong: a raw
string with any number of `#`, a `//` or a quote inside a raw string when
comments are stripped, and a `super::` chain longer than two in a moved file.
The end-to-end cases run the real script over a throwaway git repository: a
move out of any file, methods of a named impl type, a destination that already
existed, a string with a space in a moved file, and a one-token change.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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
            'let s = r#"a // b "q" c"#;  \nlet t = 1;  ')

    def test_a_changed_raw_payload_is_a_change(self) -> None:
        a = statements.normalise('let s = r#"a "q" // b"#;')
        b = statements.normalise('let s = r#"a "q" // c"#;')
        self.assertNotEqual(a, b)
        a = statements.normalise('let s = r#"a "q x" b"#;')
        b = statements.normalise('let s = r#"a "q  x" b"#;')
        self.assertNotEqual(a, b)


class StripperRegressions(unittest.TestCase):
    """Rows for what #3727's own first version got wrong (gpt review)."""

    def test_a_block_comment_keeps_its_neighbours_apart(self) -> None:
        self.assertNotEqual(statements.normalise("m!(a/**/b);"),
                            statements.normalise("m!(ab);"))

    def test_a_continued_string_is_one_token(self) -> None:
        literal = '"x\\\n // p"'
        self.assertIn(literal, statements.TOKEN.findall(f"let s = {literal};"))

    def test_a_continued_string_is_one_literal(self) -> None:
        a = statements.normalise('let s = "x\\\n // p";')
        b = statements.normalise('let s = "x\\\n // q";')
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


BASE_SRC = """impl Foo {
    fn keep(&self) {}
    fn moved(&self, a: u8, b: u8) -> bool {
        let t = ["x", "y"].join(", ");
        a > b && !t.is_empty()
    }
}
"""
BASE_DEST = """impl Foo {
    fn already(&self) { super::super::x() }
}
"""
HEAD_SRC = """impl Foo {
    fn keep(&self) {}
}
"""


def head_dest(op: str, already: str = "super::super::x()") -> str:
    return f"""impl Foo {{
    fn already(&self) {{ {already} }}
    pub(super) fn moved(&self, a: u8, b: u8) -> bool {{
        let t = ["x", "y"].join(", ");
        a {op} b && !t.is_empty()
    }}
}}
"""


class EndToEnd(unittest.TestCase):
    """The real script over a two-commit repository: src/a.rs moves `moved`
    into src/a/b.rs, which already holds another method of `impl Foo`."""

    def run_checker(self, op: str, *flags: str,
                    dest_already: str = "super::super::x()") -> subprocess.CompletedProcess:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args: str) -> None:
                subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

            def commit(src: str, dest: str) -> None:
                (repo / "src/a").mkdir(parents=True, exist_ok=True)
                (repo / "src/a.rs").write_text(src)
                (repo / "src/a/b.rs").write_text(dest)
                git("add", "-A")
                git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")

            git("init", "-q")
            commit(BASE_SRC, BASE_DEST)
            commit(HEAD_SRC, head_dest(op, dest_already))
            return subprocess.run(
                [sys.executable, "-I", str(HERE / "check_moved_items.py"),
                 "--source", "src/a.rs", *flags, "HEAD~1", "HEAD", "a/b.rs"],
                cwd=tmp, capture_output=True, text=True)

    def test_a_move_into_an_existing_file_of_a_named_impl_is_equal(self) -> None:
        done = self.run_checker(">", "--impl", "Foo")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("items equal", done.stdout)

    def test_a_one_token_change_is_reported(self) -> None:
        done = self.run_checker(">=", "--impl", "Foo")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("only at base", done.stdout)
        self.assertIn("only at head", done.stdout)

    def test_a_changed_item_already_in_the_destination_is_reported(self) -> None:
        # `already` keeps its place but now reaches one module less far up;
        # reading it one module up would make both spellings `super::x`.
        done = self.run_checker(">", "--impl", "Foo", dest_already="super::x()")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("only at head", done.stdout)

    def test_a_level_added_to_an_item_already_in_the_destination_is_reported(self) -> None:
        # The other direction: one module further up. Reading the head form one
        # module up would turn it back into the base form.
        done = self.run_checker(">", "--impl", "Foo", dest_already="super::super::super::x()")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("only at head", done.stdout)

    def test_without_the_impl_type_a_split_impl_is_a_difference(self) -> None:
        done = self.run_checker(">")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)


class RootSource(unittest.TestCase):
    def test_a_source_at_the_repository_root_names_root_destinations(self) -> None:
        with TemporaryDirectory() as tmp:
            def git(*args: str) -> None:
                subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

            def commit(files: dict[str, str]) -> None:
                for name, text in files.items():
                    (Path(tmp) / name).write_text(text)
                git("add", "-A")
                git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")

            git("init", "-q")
            commit({"a.rs": "fn kept() {}\nfn moved() {}\n"})
            commit({"a.rs": "fn kept() {}\n", "b.rs": "fn moved() {}\n"})
            done = subprocess.run(
                [sys.executable, "-I", str(HERE / "check_moved_items.py"),
                 "--source", "a.rs", "HEAD~1", "HEAD", "b.rs"],
                cwd=tmp, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
