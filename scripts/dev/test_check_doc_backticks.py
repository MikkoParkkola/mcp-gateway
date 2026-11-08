#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the doc-backtick check flags and what it leaves alone.

The check is a cheap pre-filter for clippy's `doc_markdown` lint, which needs
a build. Each case below is a doc comment shape clippy treats one way. The
hits are what clippy flags; the misses are what it accepts, so a false
positive would block a push that clippy lets through.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-doc-backticks.py"


def load():
    spec = importlib.util.spec_from_file_location("doc_backticks", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hits(source: str) -> list[tuple[int, str]]:
    """The gate hits in one file's text, as (line, word)."""
    return [(line, word) for line, word, gate in load().scan_text(source) if gate]


def warnings(source: str) -> list[tuple[int, str]]:
    return [(line, word) for line, word, gate in load().scan_text(source) if not gate]


class Hits(unittest.TestCase):
    def test_a_bare_underscore_word_is_a_hit(self):
        self.assertEqual(hits("/// Calls start_entry first.\nfn f() {}\n"), [(1, "start_entry")])

    def test_a_bare_path_with_an_underscore_is_a_hit(self):
        src = "/// Raised in (backend/lifecycle/entry_start.rs), so a call\nfn f() {}\n"
        self.assertEqual(hits(src), [(1, "backend/lifecycle/entry_start.rs")])

    def test_a_double_colon_path_is_a_hit(self):
        self.assertEqual(hits("/// See crate::clock for the source.\nfn f() {}\n"), [(1, "crate::clock")])

    def test_a_hit_in_a_test_file_counts(self):
        # Clippy lints test code too (--all-targets): a test's doc is checked.
        src = "#[test]\n/// The binary compiles src/mutant_macro.rs again.\nfn t() {}\n"
        self.assertEqual(hits(src), [(2, "src/mutant_macro.rs")])

    def test_the_line_of_a_hit_on_a_continuation_line(self):
        src = "/// A field of the error (its http_status, its\n/// schema_version, or text).\nfn f() {}\n"
        self.assertEqual(hits(src), [(1, "http_status"), (2, "schema_version")])


class Misses(unittest.TestCase):
    def test_a_backticked_word_is_not_a_hit(self):
        self.assertEqual(hits("/// Calls `start_entry` first.\nfn f() {}\n"), [])

    def test_backticks_wrapping_across_lines_are_not_a_hit(self):
        src = "/// So the pin belongs beside `tests::per_user_fetch\n/// _and_shared`, the control.\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_link_is_not_a_hit(self):
        self.assertEqual(hits("/// See [the doc](crate::clock_source) here.\nfn f() {}\n"), [])

    def test_a_link_reference_definition_is_not_a_hit(self):
        src = "/// Uses [`RETENTION_SECS`].\n///\n/// [`RETENTION_SECS`]: crate::idempotency::RETENTION_SECS\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_fenced_block_is_not_a_hit(self):
        src = "/// Example:\n///\n/// ```\n/// let start_entry = 1;\n/// ```\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_word_joined_to_a_hyphen_is_not_a_hit(self):
        # Clippy passes these: a line range after a path, a hyphenated suffix.
        src = "/// At (watch_source/hold.rs:65-68) it cannot be spawn_blocking-ed.\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_url_is_not_a_hit(self):
        self.assertEqual(hits("/// See https://example.com/a_b/c_d for it.\nfn f() {}\n"), [])

    def test_a_plain_comment_and_an_inner_doc_are_not_checked(self):
        # `//!` inner docs of out-of-line modules carry underscore words clippy
        # passes on today's tree, so the check reads outer `///` docs only.
        src = "//! The build_mcp_headers rows.\n// a plain start_entry note\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_doc_on_a_module_declaration_is_not_checked(self):
        src = "/// Secret injection through gateway_invoke.\n#[cfg(test)]\nmod secret_injection_tests;\n"
        self.assertEqual(hits(src), [])


class CamelCase(unittest.TestCase):
    def test_camel_case_is_a_warning_not_a_hit(self):
        src = "/// Require the resource to match this ETag.\nfn f() {}\n"
        self.assertEqual((hits(src), warnings(src)), ([], [(1, "ETag")]))

    def test_an_acronym_or_a_lowercase_start_is_no_warning(self):
        src = "/// URLs, IDs, mTLS and gVisor stay words.\nfn f() {}\n"
        self.assertEqual(warnings(src), [])


class Cli(unittest.TestCase):
    def run_check(self, root: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", str(SCRIPT), *args], cwd=root, capture_output=True, text=True, check=False
        )

    def test_base_mode_checks_only_files_changed_since_the_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "t")
            (root / "src").mkdir()
            (root / "src/old.rs").write_text("/// An old bare start_entry.\nfn f() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
            (root / "src/new.rs").write_text("/// A new bare publish_started.\nfn g() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "change")
            out = self.run_check(root, "--base", base)
            self.assertEqual(out.returncode, 1, out)
            self.assertIn("src/new.rs:1: publish_started", out.stdout)
            self.assertNotIn("old.rs", out.stdout)
            self.assertIn("put it in backticks", out.stdout)

    def test_a_clean_tree_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/a.rs").write_text("/// Calls `start_entry`.\nfn f() {}\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            out = self.run_check(root)
            self.assertEqual(out.returncode, 0, out)


if __name__ == "__main__":
    unittest.main()
