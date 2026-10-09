#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the timing-assert guard refuses (MIK-8222, family timing-flakes).

Each rule has a case here that goes red when the rule is removed: the 5 s
threshold, fail-closed on an unresolvable window, equality judging, and the
allowlist's stale, ambiguous and shrink-only checks.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-timing-asserts.py"
SPEC = importlib.util.spec_from_file_location("guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

PATH = "src/x_tests.rs"


def wrap(body: str, prelude: str = "") -> str:
    return f"{prelude}\nfn case() {{\n    let start = Instant::now();\n{body}\n}}\n"


def scan(body: str, prelude: str = "", consts=None):
    return guard.scan_text(PATH, wrap(body, prelude), consts or {})


class Windows(unittest.TestCase):
    def assertRefused(self, body, prelude="", consts=None, rule=None):
        found = scan(body, prelude, consts)
        self.assertEqual(len(found), 1, found)
        if rule:
            self.assertEqual(found[0].rule, rule, found)

    def assertPasses(self, body, prelude="", consts=None):
        self.assertEqual(scan(body, prelude, consts), [])

    def test_the_threshold_is_five_seconds(self):
        self.assertRefused("assert!(start.elapsed() < Duration::from_millis(4900));", rule="under 5 s")
        self.assertPasses("assert!(start.elapsed() < Duration::from_millis(5000));")
        self.assertPasses("assert!(start.elapsed() <= Duration::from_secs(5));")

    def test_a_millisecond_count_is_a_window(self):
        self.assertRefused("assert!(start.elapsed().as_millis() < 100);")
        self.assertRefused("assert!(start.elapsed().as_secs() < 1);")
        self.assertPasses("assert!(start.elapsed().as_secs() < 30);")

    def test_a_reversed_comparison_is_an_upper_bound(self):
        self.assertRefused("assert!(Duration::from_secs(2) > start.elapsed());")

    def test_a_let_bound_window_is_followed(self):
        self.assertRefused("let bound = Duration::from_secs(1);\nassert!(start.elapsed() < bound);")
        self.assertPasses("let bound = Duration::from_secs(30);\nassert!(start.elapsed() < bound);")

    def test_a_measured_binding_is_followed(self):
        self.assertRefused("let took = start.elapsed();\nassert!(took < Duration::from_secs(3));")

    def test_any_deadline_name_is_traced(self):
        refused = "let settled = Instant::now() + Duration::from_secs(2);\nassert!(Instant::now() < settled);"
        self.assertRefused(refused)
        passes = "let settled = Instant::now() + Duration::from_secs(10);\nassert!(Instant::now() < settled);"
        self.assertPasses(passes)

    def test_a_const_in_the_file_is_followed(self):
        prelude = "const FAST: Duration = Duration::from_secs(1);"
        self.assertRefused("assert!(start.elapsed() < FAST);", prelude)

    def test_a_crate_const_is_followed_one_level(self):
        consts = {
            "ROW_LIMIT": [("src/support.rs", "Duration::from_secs(5)")],
            "SHORT": [("src/support.rs", "Duration::from_millis(200)")],
        }
        self.assertPasses("assert!(start.elapsed() < crate::support::ROW_LIMIT);", consts=consts)
        self.assertRefused("assert!(start.elapsed() < SHORT * 2 + Duration::from_secs(1));", consts=consts)

    def test_the_nearest_module_defines_a_tree_const(self):
        consts = {"BOUND": [("src/x_tests/fixture.rs", "Duration::from_secs(10)"), ("src/far/y.rs", "Duration::from_millis(200)")]}
        self.assertPasses("assert!(start.elapsed() < fixture::BOUND);", consts=consts)
        consts = {"BOUND": [("src/a.rs", "Duration::from_secs(10)"), ("src/b.rs", "Duration::from_millis(200)")]}
        self.assertRefused("assert!(start.elapsed() < BOUND);", consts=consts, rule="unresolvable window")

    def test_arithmetic_is_evaluated(self):
        body = "let bound = Duration::from_millis(200);\nassert!(start.elapsed() < bound * 5);"
        self.assertRefused(body)
        body = "let bound = Duration::from_millis(200);\nassert!(start.elapsed() < bound * 25);"
        self.assertPasses(body)

    def test_an_unresolvable_window_fails_closed(self):
        self.assertRefused("assert!(start.elapsed() < window());", rule="unresolvable window")
        retry = "let retry = due();\nassert!(retry + Duration::from_secs(1) >= Instant::now() + RETRY);"
        self.assertRefused(retry, rule="unresolvable window")
        self.assertRefused("assert!(tokio::time::Instant::now() < given);", rule="unresolvable window")
        self.assertPasses("assert!(Instant::now() + Duration::from_millis(1) > given);")

    def test_equality_against_a_short_duration_is_a_window(self):
        body = "let moved = start.elapsed();\nassert_eq!(moved, Duration::ZERO);"
        self.assertRefused(body, rule="under 5 s")

    def test_a_lower_bound_passes(self):
        self.assertPasses("assert!(start.elapsed() >= Duration::from_millis(100));")
        self.assertPasses("assert!(Duration::from_millis(100) <= start.elapsed());")

    def test_comments_strings_and_unrelated_names_pass(self):
        self.assertPasses("// assert!(start.elapsed() < Duration::from_millis(1));")
        self.assertPasses('assert!(ok, "elapsed() < Duration::from_millis(1)");')
        self.assertPasses('assert!(r#"start.elapsed() < Duration::from_millis(1)"#.len() > 1);')
        self.assertPasses("let elapsed = 3;\nassert!(elapsed < 4);")

    def test_a_value_built_from_a_timestamp_is_not_a_measured_time(self):
        body = (
            "let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();\n"
            "let token = Token { exp: now + 3600 };\nlet scope = format(&token);\n"
            'assert_eq!(scope, "");\nassert!(now < 10);'
        )
        self.assertPasses(body)
        self.assertRefused("let took = start.elapsed();\nlet ms = took.as_millis();\nassert!(ms < 100);")


class Allowlist(unittest.TestCase):
    def setUp(self):
        self.found = scan("assert!(start.elapsed() < Duration::from_secs(1));")
        self.row = guard.Row(PATH, "case", self.found[0].assertion, "converted in PR2 (MIK-8222)")

    def test_a_listed_assert_passes(self):
        self.assertEqual(guard.judge(self.found, [self.row], None), [])

    def test_an_unlisted_assert_fails(self):
        self.assertEqual(len(guard.judge(self.found, [], None)), 1)

    def test_a_stale_row_fails(self):
        errors = guard.judge([], [self.row], None)
        self.assertEqual(len(errors), 1)
        self.assertIn("STALE", errors[0])

    def test_an_ambiguous_row_fails(self):
        errors = guard.judge(self.found * 2, [self.row], None)
        self.assertTrue(any("AMBIGUOUS" in e for e in errors), errors)

    def test_the_list_may_shrink_against_its_base(self):
        self.assertEqual(guard.judge(self.found, [self.row], [self.row, self.row._replace(fn="other")]), [])

    def test_the_list_may_not_grow_against_its_base(self):
        errors = guard.judge(self.found, [self.row], [])
        self.assertTrue(any("NEW ROW" in e for e in errors), errors)

    def test_a_row_round_trips_through_the_file_format(self):
        self.assertEqual(guard.parse_allowlist(guard.format_row(self.row) + "\n"), [self.row])


if __name__ == "__main__":
    unittest.main()
