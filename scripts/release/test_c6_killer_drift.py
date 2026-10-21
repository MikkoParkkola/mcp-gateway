#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for c6_killer_drift.py (MIK-8565).

    test_c6_killer_drift.py

Unit tests for extract_fn plus an end-to-end CLI run on a temporary git repo.
Standard library only.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from c6_killer_drift import extract_fn


class ExtractFnTests(unittest.TestCase):
    def test_plain_body(self) -> None:
        text = "fn foo() {\n    1\n}\n"
        self.assertEqual(extract_fn(text, text.index("fn foo")), "fn foo() {\n    1\n}")

    def test_nested_braces(self) -> None:
        text = "fn foo() {\n    if x {\n        1\n    }\n}\n"
        self.assertEqual(extract_fn(text, 0), "fn foo() {\n    if x {\n        1\n    }\n}")

    def test_brace_in_string(self) -> None:
        text = 'fn foo() {\n    let s = "}";\n    1\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = "}";\n    1\n}')

    def test_brace_in_raw_string(self) -> None:
        text = 'fn foo() {\n    let s = r#"}"#;\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = r#"}"#;\n}')

    def test_brace_in_line_comment(self) -> None:
        text = "fn foo() {\n    // }\n    1\n}\n"
        self.assertEqual(extract_fn(text, 0), "fn foo() {\n    // }\n    1\n}")

    def test_brace_in_block_comment(self) -> None:
        text = "fn foo() {\n    /* } */\n    1\n}\n"
        self.assertEqual(extract_fn(text, 0), "fn foo() {\n    /* } */\n    1\n}")

    def test_brace_in_char_literal(self) -> None:
        text = "fn foo() {\n    let c = '}';\n}\n"
        self.assertEqual(extract_fn(text, 0), "fn foo() {\n    let c = '}';\n}")

    def test_brace_in_raw_byte_string(self) -> None:
        text = 'fn foo() {\n    let s = br#"}"#;\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = br#"}"#;\n}')

    def test_brace_in_byte_string(self) -> None:
        text = 'fn foo() {\n    let s = b"}";\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = b"}";\n}')

    def test_brace_in_c_string(self) -> None:
        text = 'fn foo() {\n    let s = c"}";\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = c"}";\n}')

    def test_brace_in_raw_c_string(self) -> None:
        text = 'fn foo() {\n    let s = cr"}";\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = cr"}";\n}')

    def test_brace_in_byte_char(self) -> None:
        text = "fn foo() {\n    let c = b'}';\n}\n"
        self.assertEqual(extract_fn(text, 0), "fn foo() {\n    let c = b'}';\n}")

    def test_abr_prefix_is_not_a_raw_string(self) -> None:
        text = 'fn foo() {\n    let s = abr"x";\n}\n'
        self.assertEqual(extract_fn(text, 0), 'fn foo() {\n    let s = abr"x";\n}')

    def test_doc_comment_and_attribute_included(self) -> None:
        text = "/// Does foo.\n#[test]\nfn foo() {\n    1\n}\n"
        self.assertEqual(
            extract_fn(text, text.index("fn foo")),
            "/// Does foo.\n#[test]\nfn foo() {\n    1\n}",
        )


class CliTests(unittest.TestCase):
    def test_changed_missing_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "repo")
            repo.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.update(
                GIT_AUTHOR_NAME="t",
                GIT_AUTHOR_EMAIL="t@example.invalid",
                GIT_COMMITTER_NAME="t",
                GIT_COMMITTER_EMAIL="t@example.invalid",
                GIT_CONFIG_GLOBAL=os.devnull,
                GIT_CONFIG_NOSYSTEM="1",
            )

            def git(*args: str) -> str:
                done = subprocess.run(
                    ["git", *args], cwd=repo, env=env, capture_output=True, text=True
                )
                if done.returncode != 0:
                    raise AssertionError(f"git {' '.join(args)}: {done.stderr.strip()}")
                return done.stdout.strip()

            git("init", "-q", "-b", "main", str(repo))
            src = repo / "src"
            src.mkdir()
            base = (
                "#[test]\nfn alpha_test() {\n    assert_eq!(1, 1);\n}\n"
                "\n#[test]\nfn beta_test() {\n    assert_eq!(1, 1);\n}\n"
                "\n#[test]\nfn gamma_test() {\n    assert_eq!(1, 1);\n}\n"
            )
            (src / "lib.rs").write_text(base, encoding="utf-8")
            git("add", "src/lib.rs")
            git("commit", "-q", "-m", "base")
            base_rev = git("rev-parse", "HEAD")
            head = (
                "#[test]\nfn alpha_test() {\n    assert_eq!(1, 1);\n}\n"
                "\n#[test]\nfn beta_test() {\n    assert_eq!(1, 2);\n}\n"
                "\n#[test]\nfn gamma_renamed() {\n    assert_eq!(1, 1);\n}\n"
            )
            (src / "lib.rs").write_text(head, encoding="utf-8")
            git("commit", "-q", "-am", "head")
            head_rev = git("rev-parse", "HEAD")

            manifest = repo / "manifest.tsv"
            manifest.write_text(
                f"head_sha\t{head_rev}\n"
                "ALPHA\tlinux\ta.patch\tcargo test --exact tests::alpha_test\n"
                "BETA\tlinux\tb.patch\tcargo test --exact tests::beta_test\n"
                "GAMMA\tlinux\tc.patch\tcargo test --exact tests::gamma_test\n",
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parent / "c6_killer_drift.py"
            done = subprocess.run(
                [sys.executable, str(script), "--base", base_rev, "--head", head_rev, str(manifest)],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(done.returncode, 1, msg=done.stderr)
            self.assertIn("ALPHA\tUNCHANGED\tsrc/lib.rs", done.stdout.splitlines())
            self.assertIn("BETA\tCHANGED\tsrc/lib.rs", done.stdout.splitlines())
            self.assertIn("GAMMA\tMISSING\t-", done.stdout.splitlines())
            self.assertIn("killer drift: 1 changed, 1 missing/ambiguous, of 3 rows", done.stdout)

    def test_trailing_whitespace_inside_string_counts_as_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "repo")
            repo.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.update(
                GIT_AUTHOR_NAME="t",
                GIT_AUTHOR_EMAIL="t@example.invalid",
                GIT_COMMITTER_NAME="t",
                GIT_COMMITTER_EMAIL="t@example.invalid",
                GIT_CONFIG_GLOBAL=os.devnull,
                GIT_CONFIG_NOSYSTEM="1",
            )

            def git(*args: str) -> str:
                done = subprocess.run(
                    ["git", *args], cwd=repo, env=env, capture_output=True, text=True
                )
                if done.returncode != 0:
                    raise AssertionError(f"git {' '.join(args)}: {done.stderr.strip()}")
                return done.stdout.strip()

            git("init", "-q", "-b", "main", str(repo))
            src = repo / "src"
            src.mkdir()
            base = (
                "#[test]\nfn ws_test() {\n"
                '    let s = "alpha   \nbeta";\n'
                "    assert!(!s.is_empty());\n}\n"
            )
            (src / "lib.rs").write_text(base, encoding="utf-8")
            git("add", "src/lib.rs")
            git("commit", "-q", "-m", "base")
            base_rev = git("rev-parse", "HEAD")
            head = (
                "#[test]\nfn ws_test() {\n"
                '    let s = "alpha \nbeta";\n'
                "    assert!(!s.is_empty());\n}\n"
            )
            (src / "lib.rs").write_text(head, encoding="utf-8")
            git("commit", "-q", "-am", "head")
            head_rev = git("rev-parse", "HEAD")

            manifest = repo / "manifest.tsv"
            manifest.write_text(
                f"head_sha\t{head_rev}\n"
                "WS\tlinux\tw.patch\tcargo test --exact tests::ws_test\n",
                encoding="utf-8",
            )
            script = Path(__file__).resolve().parent / "c6_killer_drift.py"
            done = subprocess.run(
                [sys.executable, str(script), "--base", base_rev, "--head", head_rev, str(manifest)],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(done.returncode, 1, msg=done.stderr)
            self.assertIn("WS\tCHANGED\tsrc/lib.rs", done.stdout.splitlines())
            self.assertIn("killer drift: 1 changed, 0 missing/ambiguous, of 1 rows", done.stdout)


if __name__ == "__main__":
    unittest.main()
