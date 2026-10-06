#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_security_fragments.py."""

import importlib.util
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("csf", HERE / "check_security_fragments.py")
csf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csf)


def run(files):
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            (pathlib.Path(d) / name).write_text(text, encoding="utf-8")
        return csf.problems(d)


GOOD = ("- **A guard.** It refuses X.\n"
        "  Affects: 4.0.0 pre-releases only; 3.x unaffected. Operator action: none.\n")


class CheckSecurityFragments(unittest.TestCase):
    def test_a_bullet_with_both_clauses_passes(self):
        self.assertEqual(run({"1.security.md": GOOD}), [])

    def test_a_missing_affects_clause_fails(self):
        self.assertEqual(len(run({"1.security.md": "- **A guard.** Operator action: none.\n"})), 1)

    def test_a_missing_operator_action_fails(self):
        out = run({"1.security.md": "- **A guard.** Affects: 3.x up to 3.5.1.\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("Operator action", out[0])

    def test_unverified_fails(self):
        out = run({"1.security.md": "- X.\n  Affects: UNVERIFIED. Operator action: none.\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("UNVERIFIED", out[0])

    def test_every_bullet_of_a_file_is_checked(self):
        out = run({"1.security.md": GOOD + "- **Another.** No clauses.\n"})
        self.assertEqual(len(out), 2)
        self.assertTrue(all("bullet 2" in line for line in out))

    def test_other_fragment_types_are_ignored(self):
        self.assertEqual(run({"1.fixed.md": "- **A fix.** No clauses.\n"}), [])

    def test_a_security_bullet_outside_a_security_fragment_fails(self):
        # MIK-7865: the filename picks the release-notes subsection, so a
        # Security bullet in a .fixed fragment would be filed under Fixed.
        for bullet in ("- Security: X.\n", "- **Security:** X.\n", "- **Security**: X.\n"):
            out = run({"1.fixed.md": bullet, "2.added.md": "- A.\n" + bullet})
            self.assertEqual(len(out), 2, bullet)
            self.assertIn("1.fixed.md bullet 1", out[0])
            self.assertIn("2.added.md bullet 2", out[1])
            self.assertIn(".security.md", out[0])

    def test_a_bullet_that_only_mentions_security_passes(self):
        text = "- Security counters: X.\n- **Fixes a security gap.** Y.\n"
        self.assertEqual(run({"1.added.md": text}), [])

    def test_a_clause_split_across_continuation_lines_counts(self):
        text = "- **A guard.** Text.\n  Affects: 3.x up to\n  3.5.1. Operator action: set `a.b`.\n"
        self.assertEqual(run({"1.security.md": text}), [])

    def test_an_empty_value_fails(self):
        self.assertEqual(len(run({"1.security.md": "- X. Affects: . Operator action: .\n"})), 2)

    def test_a_label_does_not_count_as_the_previous_value(self):
        out = run({"1.security.md": "- X. Affects: Operator action: none.\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("empty 'Affects'", out[0])

    def test_a_whitespace_or_emphasis_only_value_fails(self):
        self.assertEqual(len(run({"1.security.md": "- X. Affects: ** . Operator action: none.\n"})), 1)

    def test_a_punctuation_only_value_fails(self):
        # MIK-7946 finding 1: a value must say something, in letters or digits.
        for value in ("--", "??", "-- ...", "(!)"):
            text = f"- X. Affects: {value}. Operator action: none.\n"
            out = run({"1.security.md": text})
            self.assertEqual(len(out), 1, text)
            self.assertIn("empty 'Affects'", out[0])
        # Control: a short real value passes.
        self.assertEqual(run({"1.security.md": "- X. Affects: 3.x. Operator action: none.\n"}), [])

    def test_unverified_anywhere_in_any_affects_clause_fails(self):
        for text in ("- X. Affects: **UNVERIFIED**. Operator action: none.\n",
                     "- X. Affects: 3.x. Affects: still unverified. Operator action: none.\n",
                     "- X. Affects: _UNVERIFIED_. Operator action: none.\n",
                     "- X. Affects: __UNVERIFIED__. Operator action: none.\n"):
            out = run({"1.security.md": text})
            self.assertEqual(len(out), 1, text)
            self.assertIn("UNVERIFIED", out[0])

    def test_a_value_without_a_closing_period_is_named(self):
        out = run({"1.security.md": "- X. Affects: 3.x up to 3.5.1 Operator action: none.\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("no closing period", out[0])

    def test_trailing_text_after_a_period_fails(self):
        out = run({"1.security.md": "- X. Affects: 3.x. Operator action: Upgrade. Restart the service\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("no closing period", out[0])

    def test_a_value_may_start_with_a_dot(self):
        text = "- X. Affects: .NET clients on 3.x. Operator action: .env files need `a`.\n"
        self.assertEqual(run({"1.security.md": text}), [])

    def test_a_path_that_is_not_a_directory_fails(self):
        with tempfile.TemporaryDirectory() as d:
            missing = pathlib.Path(d) / "absent"
            self.assertEqual(len(csf.problems(missing)), 1)
            (pathlib.Path(d) / "file").write_text("x", encoding="utf-8")
            self.assertEqual(len(csf.problems(pathlib.Path(d) / "file")), 1)

    def test_an_empty_directory_passes_and_a_bulletless_file_fails(self):
        self.assertEqual(run({}), [])
        out = run({"1.security.md": "No bullet here.\n"})
        self.assertEqual(len(out), 1)
        self.assertIn("no bullet", out[0])

    def test_main_exits_one_on_problems_and_zero_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(csf.main(["x", d]), 0)
            (pathlib.Path(d) / "1.security.md").write_text("- X.\n", encoding="utf-8")
            self.assertEqual(csf.main(["x", d]), 1)


if __name__ == "__main__":
    unittest.main()
