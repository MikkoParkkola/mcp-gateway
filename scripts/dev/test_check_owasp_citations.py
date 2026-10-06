#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The OWASP citation check fails on a stale citation and passes on the real doc."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-owasp-citations.py"


def load():
    spec = importlib.util.spec_from_file_location("owasp_citations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwaspCitations(unittest.TestCase):
    def problems_in(self, doc: str) -> list[str]:
        guard = load()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "security").mkdir(parents=True)
            (root / "src" / "security" / "policy.rs").write_text(
                "#[test]\nfn deny_pattern_blocks_exec() {}\nfn helper_only() {}\n// #[test]\n// fn commented_out_test() {}\n/* outer /* #[test] fn nested_comment_test() {} */ still */\nconst S: &str = \"/*\";\n#[test]\nfn after_string_test() {}\n", encoding="utf-8"
            )
            (root / "tests").mkdir()
            path = root / "doc.md"
            path.write_text(doc, encoding="utf-8")
            return guard.problems(path, root)

    def test_a_missing_path_is_reported(self):
        found = self.problems_in("Policy (`src/security/ssrf.rs`).\n")
        self.assertEqual(found, ["cited path does not exist: src/security/ssrf.rs"])

    def test_a_validation_command_matching_no_test_is_reported(self):
        found = self.problems_in("```bash\ncargo test --lib no_such_test\n```\n")
        self.assertEqual(found, ["validation command matches no test: cargo test --lib no_such_test"])

    def test_lib_does_not_accept_a_test_that_lives_only_under_tests(self):
        # `cargo test --lib NAME` runs the library target: an integration test
        # of that name is not run, and the command would pass on 0 tests.
        guard = load()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "tests" / "it.rs").write_text("#[test]\nfn only_in_tests() {}\n", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text("```bash\ncargo test --lib only_in_tests\ncargo test only_in_tests\n```\n", encoding="utf-8")
            self.assertEqual(
                guard.problems(doc, root),
                ["validation command matches no test: cargo test --lib only_in_tests"],
            )

    def test_a_helper_that_is_not_a_test_does_not_satisfy_a_command(self):
        found = self.problems_in("```bash\ncargo test helper_only\n```\n")
        self.assertEqual(found, ["validation command matches no test: cargo test helper_only"])

    def test_an_unreadable_command_form_is_reported(self):
        found = self.problems_in("```bash\ncargo test -p other deny_pattern_blocks -- --exact\n```\n")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("validation command form not checkable"), found)

    def test_a_commented_out_test_does_not_satisfy_a_command(self):
        found = self.problems_in("```bash\ncargo test commented_out_test\n```\n")
        self.assertEqual(found, ["validation command matches no test: cargo test commented_out_test"])

    def test_an_unsupported_flag_is_reported(self):
        found = self.problems_in("```bash\ncargo test --release deny_pattern_blocks\n```\n")
        self.assertTrue(found and found[0].startswith("validation command form not checkable"), found)

    def test_a_test_inside_a_nested_block_comment_does_not_count(self):
        found = self.problems_in("```bash\ncargo test nested_comment_test\n```\n")
        self.assertEqual(found, ["validation command matches no test: cargo test nested_comment_test"])

    def test_a_string_containing_a_comment_opener_hides_no_test(self):
        self.assertEqual(self.problems_in("```bash\ncargo test after_string_test\n```\n"), [])

    def test_a_tab_separated_command_is_reported(self):
        found = self.problems_in("```bash\ncargo\ttest\t--release deny_pattern_blocks\n```\n")
        self.assertTrue(found and found[0].startswith("validation command form not checkable"), found)

    def test_existing_citations_pass(self):
        doc = (
            "Policy (`src/security/policy.rs`, `src/security/`).\n"
            "```bash\ncargo test deny_pattern_blocks\n```\n"
        )
        self.assertEqual(self.problems_in(doc), [])

    def test_the_published_self_assessment_is_current(self):
        guard = load()
        self.assertEqual(guard.problems(guard.DOC, guard.ROOT), [])

    MATRIX = (
        "| ASI01 | Goal | COVERED | a | b |\n"
        "| ASI02 | Tools | PARTIAL | a | b |\n"
        "| ASI03 | Identity | PARTIAL | a | b |\n"
    )

    def test_counts_that_match_the_rows_pass(self):
        doc = (
            "Current mapping: **1/3 COVERED, 2/3 PARTIAL** here.\n" + self.MATRIX
            + "| COVERED | 1/3 | ASI01 |\n| PARTIAL | 2/3 | ASI02, ASI03 |\n| GAP | 0/3 | - |\n"
        )
        self.assertEqual(self.problems_in(doc), [])

    def test_a_header_count_the_rows_disagree_with_is_reported(self):
        doc = "Current mapping: **2/3 COVERED, 1/3 PARTIAL** here.\n" + self.MATRIX
        self.assertEqual(
            self.problems_in(doc),
            [
                "header says 2/3 COVERED; the matrix rows give 1/3",
                "header says 1/3 PARTIAL; the matrix rows give 2/3",
            ],
        )

    def test_a_summary_row_the_rows_disagree_with_is_reported(self):
        doc = "**1/3 COVERED, 2/3 PARTIAL**\n" + self.MATRIX + "| COVERED | 2/3 | ASI01, ASI02 |\n| PARTIAL | 1/3 | ASI03 |\n"
        self.assertEqual(
            self.problems_in(doc),
            [
                "summary COVERED says 2/3 ASI01, ASI02; the matrix rows give 1/3 ASI01",
                "summary PARTIAL says 1/3 ASI03; the matrix rows give 2/3 ASI02, ASI03",
            ],
        )


    def test_counts_with_extra_spacing_are_still_checked(self):
        doc = "**2/3 COVERED,  1 / 3 PARTIAL**\n" + self.MATRIX + "| COVERED | 2 / 3 | ASI01 |\n"
        self.assertEqual(
            self.problems_in(doc),
            [
                "header says 2/3 COVERED; the matrix rows give 1/3",
                "header says 1/3 PARTIAL; the matrix rows give 2/3",
                "summary COVERED says 2/3 ASI01; the matrix rows give 1/3 ASI01",
            ],
        )

    def test_an_unreadable_count_is_reported(self):
        doc = "**one COVERED, 2/3 PARTIAL**\n" + self.MATRIX + "| COVERED | one | ASI01 |\n"
        self.assertEqual(
            self.problems_in(doc),
            [
                "header count not readable: one COVERED, 2/3 PARTIAL",
                "summary COVERED count not readable: one",
            ],
        )

    def test_summary_risks_in_another_order_pass(self):
        doc = (
            "**1/3 COVERED, 2/3 PARTIAL**\n" + self.MATRIX
            + "| COVERED | 1/3 | ASI01 |\n| PARTIAL | 2/3 | ASI03,ASI02 |\n"
        )
        self.assertEqual(self.problems_in(doc), [])

    def test_counts_without_matrix_rows_are_reported(self):
        doc = "**1/3 COVERED, 2/3 PARTIAL**\n| COVERED | 1/3 | ASI01 |\n"
        self.assertEqual(self.problems_in(doc), ["counts are claimed but no matrix rows were found"])

    def test_matrix_rows_without_a_header_count_are_reported(self):
        self.assertEqual(self.problems_in(self.MATRIX), ["no header count found for the matrix rows"])

if __name__ == "__main__":
    unittest.main()
