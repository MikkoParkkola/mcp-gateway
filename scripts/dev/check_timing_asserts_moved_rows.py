#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Moved-row cases for the timing-assert guard tests (MIK-8291)."""

from __future__ import annotations

import unittest

from check_timing_asserts_fixtures import guard, ScratchGit


class MovedRows(unittest.TestCase):
    """MIK-8291 timing half (design r4): a new row (P, F, A) is carried only
    when F's whole fn text moved byte-exact from a donor D that held (D, F, A)
    at base, the donor's allowance is consumed, P did not already hold F at
    base, and A's window resolves to equal seconds at both revisions.

    Every row runs the real `main --base` over a scratch git tree: the base
    commit holds the donor file and the base allowlist, the working tree is
    the head. Red rows (T1, T5, T6) fail until the matcher lands; the rest
    are guards that must pass before and after. T14 is a historical
    own-assert regression for nested-identical destination cardinality, not
    an initial preimplementation red row.
    """

    DONOR = "src/donor_tests.rs"
    DEST = "src/dest_tests.rs"
    OTHER = "fn other() {}\n"

    @staticmethod
    def fn_text(window="Duration::from_secs(1)", binding="Instant::now()"):
        return (
            "fn case() {\n"
            f"    let start = {binding};\n"
            f"    assert!(start.elapsed() < {window});\n"
            "}\n"
        )

    def setUp(self):
        self.scratch = ScratchGit()
        self.dir = self.scratch.dir
        self.root = self.scratch.root
        self.saved = self.scratch.saved
        self.git = self.scratch.git
        guard.ALLOWLIST.parent.mkdir(parents=True)
        (self.root / "src").mkdir()
        self.git("init", "-q")

    def tearDown(self):
        self.scratch.close()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_rows(self, rows):
        guard.ALLOWLIST.write_text("".join(guard.format_row(r) + "\n" for r in rows), encoding="utf-8")

    def assertion(self, path, text):
        found = guard.scan_text(path, text, {})
        self.assertEqual(len(found), 1, found)
        return found[0].assertion

    def row(self, path, assertion):
        return guard.Row(path, "case", assertion, "kept (MIK-8291)")

    def commit_base(self, files, rows):
        """Commit `files` (and the allowlist, unless `rows` is None: cutover)."""
        for rel, text in files.items():
            self.write(rel, text)
        if rows is not None:
            self.write_rows(rows)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")
        return self.git("rev-parse", "HEAD")

    def head(self, files, rows):
        for rel, text in files.items():
            self.write(rel, text)
        if rows is not None:
            self.write_rows(rows)

    def run_main(self, *args):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = guard.main(list(args))
        return code, out.getvalue()

    @staticmethod
    def new_rows(out):
        return [line for line in out.splitlines() if line.startswith("NEW ROW")]

    def move(self, base_files, base_rows, head_files, head_rows):
        """Commit the base, lay down the head, run `main --base`."""
        base = self.commit_base(base_files, base_rows)
        self.head(head_files, head_rows)
        return self.run_main("--base", base)

    def plain_move(self, dest_text=None, donor_head=None, base_donor=None, base_rows="donor", head_rows="dest"):
        """The T1 shape with one knob turned per row: donor holds the fn and
        its row at base; at head the fn sits at DEST and the donor row is gone."""
        moved = self.fn_text()
        # Every plain-move variant keeps this normalised assertion (T2's donor
        # holds no assert at all, so it cannot be read from the donor text).
        a = self.assertion(self.DONOR, moved)
        base_files = {self.DONOR: base_donor if base_donor is not None else moved, self.DEST: self.OTHER}
        rows_base = [self.row(self.DONOR, a)] if base_rows == "donor" else base_rows
        rows_head = [self.row(self.DEST, a)] if head_rows == "dest" else head_rows
        head_files = {self.DONOR: donor_head if donor_head is not None else self.OTHER,
                      self.DEST: dest_text if dest_text is not None else moved}
        return self.move(base_files, rows_base, head_files, rows_head)

    def test_t1_a_moved_fn_carries_its_row(self):
        code, out = self.plain_move()
        self.assertEqual(self.new_rows(out), [], out)
        self.assertEqual(code, 0, out)

    def test_t2_a_fn_never_in_the_donor_is_a_new_row(self):
        # The base list holds (D, case, A) but D never held the fn text.
        _, out = self.plain_move(base_donor=self.OTHER)
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(self.DEST, self.new_rows(out)[0], out)

    def test_t3_an_assert_respelled_in_the_move_is_a_new_row(self):
        # Same normalised assertion, different bytes inside the fn text.
        respelled = self.fn_text().replace(") < Duration", ")  <  Duration")
        _, out = self.plain_move(dest_text=respelled)
        self.assertEqual(len(self.new_rows(out)), 1, out)

    def test_t4_a_body_edited_in_the_move_is_a_new_row(self):
        # The timer binding changed; the assertion text did not.
        _, out = self.plain_move(dest_text=self.fn_text(binding="begun()"))
        self.assertEqual(len(self.new_rows(out)), 1, out)

    def test_t5_one_donor_carries_only_one_of_two_copies(self):
        first, second = "src/aaa_tests.rs", "src/bbb_tests.rs"
        moved = self.fn_text()
        a = self.assertion(self.DONOR, moved)
        _, out = self.move(
            {self.DONOR: moved, first: self.OTHER, second: self.OTHER},
            [self.row(self.DONOR, a)],
            {self.DONOR: self.OTHER, first: moved, second: moved},
            [self.row(first, a), self.row(second, a)],
        )
        rows = self.new_rows(out)
        self.assertEqual(len(rows), 1, out)
        self.assertIn(second, rows[0], out)

    def test_t6_a_carried_assert_on_added_lines_has_no_floor_error(self):
        _, out = self.plain_move()
        self.assertNotIn(guard.FLOOR, out, out)

    def test_t7_a_row_covered_added_assert_with_nothing_carried_keeps_the_floor(self):
        # The row is already in the base list (no new row, nothing carried);
        # the assert line is added at head, so the floor still judges it.
        moved = self.fn_text()
        a = self.assertion(self.DEST, moved)
        before = "fn case() {\n    let start = Instant::now();\n}\n"
        _, out = self.move(
            {self.DEST: before},
            [self.row(self.DEST, a)],
            {self.DEST: moved},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(self.new_rows(out), [], out)
        self.assertIn(guard.FLOOR, out, out)

    def test_t8_a_window_tightened_by_its_const_is_refused(self):
        # Identical fn text, but BOUND resolves to 2 s at base and 1 s at head.
        body = self.fn_text(window="BOUND")
        donor_base = "const BOUND: Duration = Duration::from_secs(2);\n" + body
        dest_head = "const BOUND: Duration = Duration::from_secs(1);\n" + body
        a = self.assertion(self.DONOR, donor_base)
        _, out = self.move(
            {self.DONOR: donor_base, self.DEST: self.OTHER},
            [self.row(self.DONOR, a)],
            {self.DONOR: self.OTHER, self.DEST: dest_head},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(len(self.new_rows(out)), 1, out)

    def test_t8_an_unresolved_window_on_either_side_is_refused(self):
        moved = self.fn_text(window="window()")
        a = self.assertion(self.DONOR, moved)
        _, out = self.move(
            {self.DONOR: moved, self.DEST: self.OTHER},
            [self.row(self.DONOR, a)],
            {self.DONOR: self.OTHER, self.DEST: moved},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(len(self.new_rows(out)), 1, out)

    def test_t9_a_donor_still_holding_the_fn_at_head_is_a_new_row(self):
        _, out = self.plain_move(donor_head=self.fn_text())
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(self.DEST, self.new_rows(out)[0], out)

    def test_t10_an_unlisted_fn_moved_is_a_new_row_with_a_floor_error(self):
        # The fn moved byte-exact, but no base row ever allowed it.
        _, out = self.plain_move(base_rows=[])
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(guard.FLOOR, out, out)

    def test_t11_a_donor_fn_edited_by_one_byte_still_keeping_the_assert_is_a_new_row(self):
        # The exact fn text left the donor, but a fn named `case` there still
        # holds the assert on the raw text (b2).
        edited = self.fn_text().replace("let start", "let  start")
        _, out = self.plain_move(donor_head=edited)
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(self.DEST, self.new_rows(out)[0], out)

    def test_t12_a_donor_row_kept_in_the_head_list_is_a_new_row(self):
        # Everything moved, except the donor's allowance was not spent: its
        # row is still in the head allowlist (b2).
        moved = self.fn_text()
        a = self.assertion(self.DONOR, moved)
        _, out = self.move(
            {self.DONOR: moved, self.DEST: self.OTHER},
            [self.row(self.DONOR, a)],
            {self.DONOR: self.OTHER, self.DEST: moved},
            [self.row(self.DONOR, a), self.row(self.DEST, a)],
        )
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(self.DEST, self.new_rows(out)[0], out)

    def test_t13_a_fn_already_at_the_destination_under_a_paused_clock_is_a_new_row(self):
        # DEST already held the identical fn at base, exempt under
        # `start_paused`; at head it loses the attribute and gains a row (c2).
        body = (
            "async fn case() {\n"
            "    let start = tokio::time::Instant::now();\n"
            "    assert!(start.elapsed() < Duration::from_secs(1));\n"
            "}\n"
        )
        donor_base = "#[tokio::test]\n" + body
        a = self.assertion(self.DONOR, donor_base)
        _, out = self.move(
            {self.DONOR: donor_base, self.DEST: "#[tokio::test(start_paused = true)]\n" + body},
            [self.row(self.DONOR, a)],
            {self.DONOR: self.OTHER, self.DEST: donor_base},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertIn(self.DEST, self.new_rows(out)[0], out)

    def test_t14_nested_identical_destination_is_a_new_row(self):
        # DEST holds the moved fn twice at head: standalone, plus a
        # byte-identical copy nested in a `start_paused` outer fn. The
        # scanner sees only the standalone case, but r4(c) exactly-once
        # refuses the carry because the raw destination count is two.
        body = (
            "async fn case() {\n"
            "    let start = tokio::time::Instant::now();\n"
            "    assert!(start.elapsed() < std::time::Duration::from_secs(1));\n"
            "}\n"
        )
        donor_base = "#[tokio::test]\n" + body
        dest_head = (
            "#[tokio::test]\n" + body
            + "#[tokio::test(start_paused = true)]\nasync fn outer() {\n"
            + body + "    case().await;\n}\n"
        )
        a = self.assertion(self.DONOR, donor_base)
        base = self.commit_base(
            {self.DONOR: donor_base, self.DEST: self.OTHER},
            [self.row(self.DONOR, a)],
        )
        self.head(
            {self.DONOR: self.OTHER, self.DEST: dest_head},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(dest_head.count(body), 2)
        self.assertEqual(len(guard.scan_text(self.DEST, dest_head, {})), 1)
        code, out = self.run_main("--base", base)
        self.assertEqual(len(self.new_rows(out)), 1, out)
        self.assertEqual(code, 1, out)

    def test_c1_the_cutover_carries_nothing_and_still_judges_added_lines(self):
        # The base tree has no allowlist (`read_base` None): shrink-only is
        # skipped, carried is empty, and `judge_new` still runs.
        moved = self.fn_text()
        a = self.assertion(self.DONOR, moved)
        code, out = self.move(
            {self.DONOR: moved, self.DEST: self.OTHER},
            None,
            {self.DONOR: self.OTHER, self.DEST: moved},
            [self.row(self.DEST, a)],
        )
        self.assertEqual(self.new_rows(out), [], out)
        self.assertIn(guard.FLOOR, out, out)
        self.assertEqual(code, 1, out)

    def test_c0_tree_only_runs_no_new_code_rules_and_does_not_crash(self):
        moved = self.fn_text()
        a = self.assertion(self.DEST, moved)
        self.write(self.DEST, moved)
        self.write_rows([self.row(self.DEST, a)])
        code, out = self.run_main()
        self.assertEqual(code, 0, out)
        self.assertIn("No --base", out, out)
        self.assertNotIn(guard.FLOOR, out, out)
