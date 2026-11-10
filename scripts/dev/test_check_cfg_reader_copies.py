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

    def test_comments_and_docstrings_are_prose(self):
        self.write("src/a.rs", '// judge with a.path().is_ident("test") here\nfn judge() {}\n')
        self.write("scripts/x.py", '"""Matches cfg\\\\(test spellings."""\n# also ("flag", "test")\nX = 1\n')
        self.assertEqual(self.problems(), [])

    def test_a_slash_pair_inside_a_raw_string_is_no_comment(self):
        self.write(
            "src/a.rs",
            'fn judge(l: &str) -> bool {\n    let _r = r#"say "//" here"#; l == "#[cfg(test)]"\n}\n',
        )
        self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_a_unicode_docstring_keeps_the_copy_after_it_and_its_scope(self):
        self.write(
            "scripts/x.py",
            'class A:\n    def judge(self, line):\n        """' + "ä" * 40 + '"""\n'
            '        return line == "#[cfg(test)]"\n',
        )
        self.assertEqual(self.problems(), ["new copy: scripts/x.py A.judge (1, listed 0)"])

    def test_a_continued_string_and_a_block_comment_are_no_line_comment(self):
        for body in (
            'fn judge(l: &str) -> bool {\n    let _s = "a\\\n // b"; l == "#[cfg(test)]"\n}\n',
            'fn judge(l: &str) -> bool {\n    /* // */ l == "#[cfg(test)]"\n}\n',
            # Block comments nest: the copy after the outer `*/` is code.
            'fn judge(l: &str) -> bool {\n    /* outer /* inner */ // */ l == "#[cfg(test)]"\n}\n',
            # Raw C strings are literals too (the shared lexer reads them).
            'fn judge(l: &str) -> bool {\n    let _s = cr#"say "//" here"#; l == "#[cfg(test)]"\n}\n',
            'fn judge(l: &str) -> bool {\n    let _s = cr#"say "/*" here"#; l == "#[cfg(test)]"\n}\n',
        ):
            with self.subTest(body=body):
                self.write("src/a.rs", body)
                self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_a_function_after_a_nested_comment_is_code(self):
        self.write("src/a.rs", '/* /* */ // */ fn judge(a: &A) -> bool { a.path().is_ident("test") }\n')
        self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_a_comment_between_an_idioms_tokens_hides_nothing(self):
        for body in (
            'fn judge(l: &str) -> bool { l == /* marker */ "#[cfg(test)]" }\n',
            'fn judge(a: &A) -> bool { a.is_ident(/* flag */ "test") }\n',
        ):
            with self.subTest(body=body):
                self.write("src/a.rs", body)
                self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_an_idiom_split_by_a_comment_from_unrelated_code_is_no_copy(self):
        self.write("src/a.rs", '/* contains_word( */ fn unrelated() { let _ = "test"; }\n')
        self.assertEqual(self.problems(), [])

    def test_unterminated_input_is_scanned_raw(self):
        # The lexer cannot read it, so every idiom in it counts (fails closed).
        for tail in ("/* never closed", '"never closed', 'r#"never closed'):
            with self.subTest(tail=tail):
                self.write("src/a.rs", 'fn judge(a: &A) -> bool { a.path().is_ident("test") }\n' + tail + "\n")
                self.assertEqual(self.problems(), ["new copy: src/a.rs judge (1, listed 0)"])

    def test_a_docstring_only_function_leaves_the_next_scope_intact(self):
        self.write(
            "scripts/x.py",
            'def empty():\n    """Only a docstring."""\n\n\ndef judge(line):\n    return line == "#[cfg(test)]"\n',
        )
        self.assertEqual(self.problems(), ["new copy: scripts/x.py judge (1, listed 0)"])

    def test_reversed_and_python_comparisons_are_copies(self):
        for rel, body, scope in (
            ("src/a.rs", 'fn judge(l: &str) -> bool { "#[cfg(test)]" == l.trim() }\n', "judge"),
            ("scripts/x.py", 'def judge(line):\n    return line.strip() == "#[cfg(test)]"\n', "judge"),
            ("scripts/x.py", 'def judge(line):\n    return line.startswith("#[cfg(test)]")\n', "judge"),
        ):
            with self.subTest(body=body):
                for old in ("src/a.rs", "scripts/x.py"):
                    (self.root / old).unlink(missing_ok=True)
                self.write(rel, body)
                self.assertEqual(self.problems(), [f"new copy: {rel} {scope} (1, listed 0)"])


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


class BaseRevision(unittest.TestCase):
    """--base reads the given revision itself, and falls back to that tree's own
    matches when it has no list yet."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.old_root = C.ROOT
        C.ROOT = self.root
        self.addCleanup(setattr, C, "ROOT", self.old_root)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def commit(self, files):
        for rel, text in files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "c")

    def test_a_base_without_a_list_allows_its_own_copies(self):
        self.commit({"src/a.rs": READER_RS})
        listed, found = C.base_allowances("HEAD")
        self.assertIsNone(listed)
        self.assertEqual(dict(found), {("src/a.rs", "judge"): 1})

    def test_a_base_with_a_list_is_read_from_that_revision(self):
        self.commit({"src/a.rs": READER_RS, C.LIST: C.HEADER + ROW})
        self.commit({C.LIST: C.HEADER})
        listed, found = C.base_allowances("HEAD")
        self.assertEqual(listed, C.HEADER)
        self.assertIsNone(found)
        listed, _ = C.base_allowances("HEAD~1")
        self.assertEqual(listed, C.HEADER + ROW)

    def test_an_allowance_the_base_dropped_after_the_branch_point_stays_dropped(self):
        self.commit({"src/a.rs": READER_RS, C.LIST: C.HEADER + ROW})
        self.git("branch", "-M", "line")
        self.git("checkout", "-q", "-b", "feature")
        self.git("checkout", "-q", "line")
        self.commit({C.LIST: C.HEADER})
        self.git("checkout", "-q", "feature")
        listed, _ = C.base_allowances("line")
        self.assertEqual(listed, C.HEADER)

    # Merge-base mode (pull requests, lanes): a branch is judged on its own change. The tip dropped
    # the row after the branch was cut; the branch never touched it, so the branch point's list is
    # the one it is compared with. Base mode (above) keeps the tip's.
    def test_merge_base_mode_reads_the_list_at_the_branch_point(self):
        self.commit({"src/a.rs": READER_RS, C.LIST: C.HEADER + ROW})
        self.git("branch", "-M", "line")
        self.git("checkout", "-q", "-b", "feature")
        self.git("checkout", "-q", "line")
        self.commit({C.LIST: C.HEADER})
        self.git("checkout", "-q", "feature")
        listed, _ = C.base_allowances("line", C.Compare.MERGE_BASE)
        self.assertEqual(listed, C.HEADER + ROW)
        # When HEAD contains the base, both modes read the same list.
        self.git("merge", "-q", "line")
        self.assertEqual(C.base_allowances("line", C.Compare.MERGE_BASE), C.base_allowances("line"))

    def test_an_unknown_base_or_no_branch_point_refuses(self):
        self.commit({"src/a.rs": READER_RS, C.LIST: C.HEADER + ROW})
        self.git("branch", "-M", "line")
        with self.assertRaisesRegex(RuntimeError, "not in this clone"):
            C.base_allowances("no-such-rev", C.Compare.MERGE_BASE)
        self.git("checkout", "-q", "--orphan", "unrelated")
        self.git("rm", "-rq", "--cached", ".")
        self.commit({C.LIST: C.HEADER})
        self.git("checkout", "-q", "-f", "line")
        with self.assertRaisesRegex(RuntimeError, "fetch full history"):
            C.base_allowances("unrelated", C.Compare.MERGE_BASE)


if __name__ == "__main__":
    unittest.main()
