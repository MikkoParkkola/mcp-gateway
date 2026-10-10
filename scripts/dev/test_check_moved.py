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


BASE_SRC = """impl Foo {
    fn keep(&self) {}
    fn moved(&self, a: u8, b: u8) -> bool {
        let t = ["x", "y"].join(", ");
        a > b && !t.is_empty()
    }
}
"""
BASE_DEST = """impl Foo {
    fn already(&self) {}
}
"""
HEAD_SRC = """impl Foo {
    fn keep(&self) {}
}
"""


def head_dest(op: str) -> str:
    return f"""impl Foo {{
    fn already(&self) {{}}
    pub(super) fn moved(&self, a: u8, b: u8) -> bool {{
        let t = ["x", "y"].join(", ");
        a {op} b && !t.is_empty()
    }}
}}
"""


class EndToEnd(unittest.TestCase):
    """The real script over a two-commit repository: src/a.rs moves `moved`
    into src/a/b.rs, which already holds another method of `impl Foo`."""

    def run_checker(self, op: str, *flags: str) -> subprocess.CompletedProcess:
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
            commit(HEAD_SRC, head_dest(op))
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

    def test_without_the_impl_type_a_split_impl_is_a_difference(self) -> None:
        done = self.run_checker(">")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)


class DirectoryModule(unittest.TestCase):
    """src/a.rs becomes src/a/mod.rs: an inline `mod tests` moves to a/tests.rs,
    an item to a/b.rs, and the child src/a_extra.rs is renamed a/extra.rs."""

    BASE = {
        "src/a.rs": """pub fn kept() -> u8 { super::super::x() }
fn moved(a: u8) -> bool { a > 1 }
#[path = "a_extra.rs"]
mod extra;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() { assert!(moved(2)); }
}
""",
        "src/a_extra.rs": "pub(super) fn extra() -> &'static str { \"x, y\" }\n",
    }

    def head(self, op: str) -> dict[str, str]:
        return {
            "src/a/mod.rs": """pub fn kept() -> u8 { super::super::x() }
mod b;
mod extra;
#[cfg(test)]
mod tests;
""",
            "src/a/b.rs": f"pub(super) fn moved(a: u8) -> bool {{ a {op} 1 }}\n",
            "src/a/extra.rs": "pub(super) fn extra() -> &'static str { \"x, y\" }\n",
            "src/a/tests.rs": """use super::*;
#[test]
fn t() { assert!(moved(2)); }
""",
        }

    def run_checker(self, op: str, also: bool = True) -> subprocess.CompletedProcess:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args: str) -> None:
                subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

            def commit(files: dict[str, str]) -> None:
                git("rm", "-rqf", "--ignore-unmatch", "src")
                for name, text in files.items():
                    (repo / name).parent.mkdir(parents=True, exist_ok=True)
                    (repo / name).write_text(text)
                git("add", "-A")
                git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")

            git("init", "-q")
            commit(self.BASE)
            commit(self.head(op))
            flags = ["--also", "src/a_extra.rs"] if also else []
            return subprocess.run(
                [sys.executable, "-I", str(HERE / "check_moved_items.py"),
                 "--source", "src/a.rs", *flags, "HEAD~1", "HEAD",
                 "a/mod.rs", "a/b.rs", "a/extra.rs", "a/tests.rs"],
                cwd=tmp, capture_output=True, text=True)

    def test_the_split_into_a_directory_is_equal(self) -> None:
        done = self.run_checker(">")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("items equal: 4 items", done.stdout)

    def test_a_one_token_change_is_reported(self) -> None:
        done = self.run_checker(">=")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)

    def test_a_renamed_child_needs_also(self) -> None:
        done = self.run_checker(">", also=False)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("only at head", done.stdout)


if __name__ == "__main__":
    unittest.main()
