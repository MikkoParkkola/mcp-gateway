#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check_clock_baseline.py (MIK-8202)."""

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_clock_baseline as ccb  # noqa: E402


def tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class Counting(unittest.TestCase):
    def test_every_raw_form_is_counted_and_the_clock_module_is_exempt(self):
        root = tree(
            {
                "src/a.rs": "let a = SystemTime::now(); let b = chrono::Utc::now();\n"
                "let c = Local::now(); let d = UNIX_EPOCH . elapsed();\n"
                "let e = jsonwebtoken::get_current_timestamp();\n"
                "let f = Utc :: now (); let g = Arc::new(SystemTime::now);\n"
                "let epoch = std::time::UNIX_EPOCH;\n",
                "src/clock.rs": "SystemTime::now()",
                "tests/t.rs": "Utc::now ()",
                "src/clean.rs": "let i = Instant::now(); clock::utc_now();",
            }
        )
        self.assertEqual(ccb.counts(root), {"src/a.rs": 8, "tests/t.rs": 1})


class Aliasing(unittest.TestCase):
    def test_every_alias_form_is_refused_outside_the_clock_module(self):
        root = tree(
            {
                "src/a.rs": "use chrono::Utc as U;\nfn f() { U::now(); }\n",
                "src/b.rs": "use chrono::{DateTime, Utc as Clock};\n",
                "src/c.rs": "use std::time::SystemTime as St;\n",
                "tests/d.rs": "type Now = chrono::Utc;\n",
                "src/e.rs": "use std::time::UNIX_EPOCH as E;\nfn f() { E.elapsed(); }\n",
                "src/f.rs": "const E: SystemTime = UNIX_EPOCH;\n",
                "src/g.rs": "use jsonwebtoken::get_current_timestamp as t;\n",
                "src/clock.rs": "use chrono::Utc as U;\n",
                "src/ok.rs": "use chrono::{DateTime, Utc};\ntype When = DateTime<Utc>;\n",
            }
        )
        found = ccb.aliases(root)
        self.assertEqual(
            [f.split(":")[0] for f in found],
            ["src/a.rs", "src/b.rs", "src/c.rs", "src/e.rs", "src/f.rs", "src/g.rs", "tests/d.rs"],
        )


class Checking(unittest.TestCase):
    def test_a_count_may_fall_but_never_rise(self):
        self.assertEqual(ccb.violations({"src/a.rs": 1}, {"src/a.rs": 2}), [])
        self.assertTrue(ccb.violations({"src/a.rs": 3}, {"src/a.rs": 2}))

    def test_an_unlisted_file_may_hold_no_read(self):
        problems = ccb.violations({"src/new.rs": 1}, {"src/a.rs": 2})
        self.assertEqual(len(problems), 1)
        self.assertIn("src/new.rs", problems[0])

    def test_the_baseline_only_shrinks_against_the_base(self):
        base = {"src/a.rs": 2, "src/b.rs": 1}
        self.assertEqual(ccb.grown({"src/a.rs": 1}, base), [])
        # A swap: b's allowance moved to a new file c.
        self.assertTrue(ccb.grown({"src/a.rs": 2, "src/c.rs": 1}, base))
        self.assertTrue(ccb.grown({"src/a.rs": 3}, base))

    def test_reads_are_the_trimmed_lines_once_per_read(self):
        text = "fn a() {\n    let t = SystemTime::now(); let u = Utc::now();\n}\nlet e = UNIX_EPOCH"
        line = "let t = SystemTime::now(); let u = Utc::now();"
        self.assertEqual(ccb.reads(text), [line, line, "let e = UNIX_EPOCH"])


    def test_render_and_parse_round_trip(self):
        rows = {"src/b.rs": 1, "src/a.rs": 4}
        self.assertEqual(ccb.parse(ccb.render(rows)), rows)


class Moving(unittest.TestCase):
    """MIK-8283: a split may carry reads to a new file; nothing else may."""

    A = ["let t = SystemTime::now();", "let u = Utc::now();", "let e = UNIX_EPOCH;"]

    def test_a_whole_file_split_carries_its_reads(self):
        base = {"src/old.rs": 3, "src/b.rs": 1}
        head = {"src/old/durable.rs": 3, "src/b.rs": 1}
        lines = ({"src/old.rs": self.A}, {"src/old/durable.rs": self.A})
        self.assertEqual(ccb.grown(head, base, *lines), [])

    def test_a_partial_split_carries_the_reads_that_moved(self):
        base = {"src/old.rs": 3}
        head = {"src/old.rs": 1, "src/old_part.rs": 2}
        lines = ({"src/old.rs": self.A}, {"src/old.rs": self.A[:1], "src/old_part.rs": self.A[1:]})
        self.assertEqual(ccb.grown(head, base, *lines), [])

    def test_a_new_file_with_reads_and_no_shrink_fails(self):
        base = {"src/a.rs": 2}
        head = {"src/a.rs": 2, "src/new.rs": 1}
        lines = ({"src/a.rs": self.A[:2]}, {"src/a.rs": self.A[:2], "src/new.rs": self.A[2:]})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any("src/new.rs" in p for p in problems), problems)

    def test_a_listed_file_that_grows_fails(self):
        base = {"src/a.rs": 1, "src/b.rs": 2}
        head = {"src/a.rs": 2, "src/b.rs": 1}
        lines = ({"src/a.rs": self.A[:1], "src/b.rs": self.A[1:]}, {"src/a.rs": self.A[:2], "src/b.rs": self.A[2:]})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any(p.startswith("src/a.rs:") for p in problems), problems)

    def test_a_transfer_bigger_than_what_moved_fails(self):
        base = {"src/old.rs": 3}
        head = {"src/old.rs": 2, "src/new.rs": 2}
        lines = ({"src/old.rs": self.A}, {"src/old.rs": self.A[:2], "src/new.rs": self.A[1:]})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any("src/new.rs" in p for p in problems), problems)

    def test_migrating_reads_in_one_file_and_adding_others_in_a_new_file_fails(self):
        # The swap MIK-8202 refuses: a.rs moves 2 reads to crate::clock, and a
        # new file adds 2 different raw reads within the freed total.
        base = {"src/a.rs": 2}
        head = {"src/new.rs": 2}
        added = ["let x = Local::now();", "let y = get_current_timestamp();"]
        lines = ({"src/a.rs": self.A[:2]}, {"src/new.rs": added})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any("src/new.rs" in p for p in problems), problems)

    def test_a_rewritten_file_cannot_free_more_than_it_shrank(self):
        # old.rs drops 2 reads and adds 1 new one (3 -> 2): two lines are gone
        # but only one read was given up, so a new file may carry one, not two.
        base = {"src/old.rs": 3}
        head = {"src/old.rs": 2, "src/new.rs": 2}
        rewritten = [self.A[2], "let z = Local::now();"]
        lines = ({"src/old.rs": self.A}, {"src/old.rs": rewritten, "src/new.rs": self.A[:2]})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any("total" in p for p in problems), problems)

    def test_a_negative_row_is_refused_so_it_cannot_cancel_the_total(self):
        # old.rs is rewritten to 2 new raw reads, new.rs carries 2 moved ones,
        # and a -1 row would bring the total back to 3: 4 reads on 3 allowed.
        with self.assertRaises(ValueError):
            ccb.parse("src/old.rs\t2\nsrc/new.rs\t2\nsrc/phantom.rs\t-1\n")

    def test_one_moved_line_is_spent_once(self):
        # Two new files may not both carry the single line old.rs gave up.
        base = {"src/old.rs": 2}
        head = {"src/old.rs": 1, "src/n1.rs": 1, "src/n2.rs": 1}
        lines = ({"src/old.rs": self.A[:2]}, {"src/old.rs": self.A[:1], "src/n1.rs": self.A[1:2], "src/n2.rs": self.A[1:2]})
        problems = ccb.grown(head, base, *lines)
        self.assertTrue(any("src/n2.rs" in p for p in problems), problems)

    def test_identical_lines_from_several_files_move_as_a_multiset(self):
        # Two files each give up one copy of the same line; two new files
        # may take one copy each, and a third copy would have nowhere to come from.
        same = "let e = UNIX_EPOCH;"
        base = {"src/a.rs": 1, "src/b.rs": 1}
        ok_head = {"src/n1.rs": 1, "src/n2.rs": 1}
        lines = ({"src/a.rs": [same], "src/b.rs": [same]}, {"src/n1.rs": [same], "src/n2.rs": [same]})
        self.assertEqual(ccb.grown(ok_head, base, *lines), [])
        bad_head = {"src/n1.rs": 2, "src/n2.rs": 1}
        bad = ({"src/a.rs": [same], "src/b.rs": [same]}, {"src/n1.rs": [same, same], "src/n2.rs": [same]})
        self.assertTrue(ccb.grown(bad_head, base, *bad))

    def test_a_read_whose_text_changed_in_the_move_fails_safe(self):
        base = {"src/old.rs": 1}
        head = {"src/new.rs": 1}
        lines = ({"src/old.rs": ["let t = std::time::SystemTime::now();"]}, {"src/new.rs": ["let t = SystemTime::now();"]})
        self.assertTrue(ccb.grown(head, base, *lines))


class TheTree(unittest.TestCase):
    def test_the_committed_baseline_holds_for_this_tree(self):
        baseline = ccb.parse((ccb.ROOT / ccb.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(ccb.violations(ccb.counts(ccb.ROOT), baseline), [])


if __name__ == "__main__":
    unittest.main()
