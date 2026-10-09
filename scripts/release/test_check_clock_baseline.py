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
                "let e = jsonwebtoken::get_current_timestamp();\n",
                "src/clock.rs": "SystemTime::now()",
                "tests/t.rs": "Utc::now ()",
                "src/clean.rs": "let i = Instant::now(); clock::utc_now();",
            }
        )
        self.assertEqual(ccb.counts(root), {"src/a.rs": 5, "tests/t.rs": 1})


class Aliasing(unittest.TestCase):
    def test_every_alias_form_is_refused_outside_the_clock_module(self):
        root = tree(
            {
                "src/a.rs": "use chrono::Utc as U;\nfn f() { U::now(); }\n",
                "src/b.rs": "use chrono::{DateTime, Utc as Clock};\n",
                "src/c.rs": "use std::time::SystemTime as St;\n",
                "tests/d.rs": "type Now = chrono::Utc;\n",
                "src/clock.rs": "use chrono::Utc as U;\n",
                "src/ok.rs": "use chrono::{DateTime, Utc};\ntype When = DateTime<Utc>;\n",
            }
        )
        found = ccb.aliases(root)
        self.assertEqual(
            [f.split(":")[0] for f in found],
            ["src/a.rs", "src/b.rs", "src/c.rs", "tests/d.rs"],
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

    def test_render_and_parse_round_trip(self):
        rows = {"src/b.rs": 1, "src/a.rs": 4}
        self.assertEqual(ccb.parse(ccb.render(rows)), rows)


class TheTree(unittest.TestCase):
    def test_the_committed_baseline_holds_for_this_tree(self):
        baseline = ccb.parse((ccb.ROOT / ccb.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(ccb.violations(ccb.counts(ccb.ROOT), baseline), [])


if __name__ == "__main__":
    unittest.main()
