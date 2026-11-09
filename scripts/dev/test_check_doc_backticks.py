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


class ClippyMarkdown(unittest.TestCase):
    """Markdown shapes clippy's parser treats as code or skips: each must not
    block, since a false block stops every push."""

    def test_a_double_backtick_span_is_not_a_hit(self):
        self.assertEqual(hits("/// Uses ``start_entry`` here.\nfn f() {}\n"), [])

    def test_a_tilde_fence_is_not_a_hit(self):
        src = "/// Example:\n///\n/// ~~~\n/// let start_entry = 1;\n/// ~~~\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_an_indented_code_block_is_not_a_hit(self):
        src = "/// Example:\n///\n///     let start_entry = 1;\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_html_code_and_a_blockquote_skip_the_paragraph(self):
        self.assertEqual(hits("/// Uses <code>start_entry</code>.\nfn f() {}\n"), [])
        self.assertEqual(hits("/// > quoted start_entry\nfn f() {}\n"), [])

    def test_a_reference_definition_without_a_space_is_not_a_hit(self):
        self.assertEqual(hits("/// See [x].\n///\n/// [x]:crate::a_b\nfn f() {}\n"), [])

    def test_a_doc_attribute_beside_the_run_skips_it(self):
        src = '#[doc = "```"]\n/// let start_entry = 1;\n#[doc = "```"]\nfn f() {}\n'
        self.assertEqual(hits(src), [])

    def test_lines_in_a_raw_string_are_not_docs(self):
        src = 'const SRC: &str = r#"\n/// a start_entry note\nnot an item\n"#;\n'
        self.assertEqual(hits(src), [])

    def test_a_doc_on_a_field_or_variant_is_checked(self):
        src = "struct S {\n    /// The start_entry flag.\n    pub flag: bool,\n}\nenum E {\n    /// A publish_started case.\n    Started,\n}\n"
        self.assertEqual(hits(src), [(2, "start_entry"), (6, "publish_started")])


class ClippyMarkdownRound2(unittest.TestCase):
    """Second-round shapes: each is code or text clippy accepts."""

    def test_a_longer_fence_is_not_closed_by_a_shorter_one(self):
        src = "/// ````\n/// ```\n/// let start_entry = 1;\n/// ````\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_indented_code_without_a_space_or_with_a_tab(self):
        self.assertEqual(hits("///Example:\n///\n///    start_entry();\nfn f() {}\n"), [])
        self.assertEqual(hits("/// Example:\n///\n///\tstart_entry();\nfn f() {}\n"), [])

    def test_an_escaped_backtick_skips_the_paragraph(self):
        self.assertEqual(hits("/// Uses \\` and `start_entry` here.\nfn f() {}\n"), [])

    def test_a_four_slash_comment_does_not_end_the_item_search(self):
        src = "/// The start_entry flag.\n//// a plain note\nfn f() {}\n"
        self.assertEqual(hits(src), [(1, "start_entry")])

    def test_a_doc_attribute_two_attributes_above_skips_the_run(self):
        src = '#[doc = "```"]\n#[inline]\n/// let start_entry = 1;\n#[doc = "```"]\nfn f() {}\n'
        self.assertEqual(hits(src), [])

    def test_a_plain_comment_inside_a_code_span_does_not_split_it(self):
        src = "/// Beside `per_user_fetch\n// a plain note\n/// _and_shared` here.\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_item_shaped_lines_inside_a_raw_string_are_not_docs(self):
        src = 'const SRC: &str = r#"\n/// Uses start_entry\nfn example() {}\n"#;\nfn f() {}\n'
        self.assertEqual(hits(src), [])

    def test_lines_inside_a_block_comment_are_not_docs(self):
        src = "/*\n/// Uses start_entry\nfn example() {}\n*/\nfn f() {}\n"
        self.assertEqual(hits(src), [])

    def test_a_string_with_an_escaped_quote_does_not_hide_later_docs(self):
        src = 'const A: &str = "say \\"hi\\"";\n/// The start_entry flag.\nfn f() {}\n'
        self.assertEqual(hits(src), [(2, "start_entry")])

    def test_a_doc_after_a_raw_string_late_in_the_file_is_flagged(self):
        # The raw string's end must be found from where it starts, however far
        # into the file that is: a scan that jumps past it reads later lines as
        # string text and hides the doc.
        pad = "// " + "x" * 120 + "\n"
        filler = "".join("// filler line without any quote characters\n" for _ in range(6))
        src = pad + 'const R: &str = r#"raw"#;\n' + filler + "/// The start_entry flag.\nfn f() {}\n" + filler
        self.assertEqual(hits(src), [(9, "start_entry")])

    def test_a_doc_after_a_backslash_continued_string_is_flagged(self):
        # Each continued line must count: a lagging line count shifts a later
        # string's marks onto the doc above it.
        src = (
            'const A: &str = "one \\\ntwo \\\nthree \\\nfour";\n'
            "fn g() {}\n"
            "/// The start_entry flag.\n"
            "fn f() {}\n"
            'const B: &str = "\nx\ny";\n'
        )
        self.assertEqual(hits(src), [(6, "start_entry")])


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
            # A false block must cost seconds: the message names the workaround
            # and asks for a report.
            self.assertIn("If clippy accepts the line", out.stdout)
            self.assertIn("report", out.stdout)

    def test_base_mode_checks_a_renamed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "t")
            (root / "src").mkdir()
            body = "".join(f"/// Line {i} of a long, unchanged doc.\n" for i in range(30))
            (root / "src/old.rs").write_text(body + "fn f() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
            git("mv", "src/old.rs", "src/new.rs")
            (root / "src/new.rs").write_text(body + "/// A bare start_entry.\nfn g() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "rename")
            out = self.run_check(root, "--base", base)
            self.assertEqual(out.returncode, 1, out)
            self.assertIn("src/new.rs:31: start_entry", out.stdout)

    def test_a_non_utf8_file_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/bad.rs").write_bytes(b"/// \xff\xfe start_entry\nfn f() {}\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            out = self.run_check(root)
            self.assertEqual(out.returncode, 0, out)
            self.assertIn("src/bad.rs: skipped, not UTF-8", out.stdout)

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
