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
import os
import subprocess
import tempfile
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

    def test_a_qualifier_names_the_defining_module_or_nothing_resolves(self):
        consts = {"BOUND": [("src/pins.rs", "Duration::from_secs(10)")]}
        self.assertPasses("assert!(start.elapsed() < crate::pins::BOUND);", consts=consts)
        # A qualifier that names another module must not borrow this one's value.
        self.assertRefused("assert!(start.elapsed() < crate::other::BOUND);", consts=consts, rule="unresolvable window")

    def test_an_imported_const_is_evaluated_in_its_own_file(self):
        # `B = A` in pins.rs means pins.rs's 100 ms `A`, not the caller's 10 s `A`.
        consts = {
            "A": [("src/pins.rs", "Duration::from_millis(100)"), (PATH, "Duration::from_secs(10)")],
            "B": [("src/pins.rs", "A")],
        }
        prelude = "const A: Duration = Duration::from_secs(10);"
        self.assertRefused("assert!(start.elapsed() < pins::B);", prelude, consts=consts, rule="under 5 s")

    def test_an_unqualified_name_resolves_only_through_an_import_or_an_ancestor(self):
        consts = {"BOUND": [("src/far/y.rs", "Duration::from_secs(10)")]}
        self.assertRefused("assert!(start.elapsed() < BOUND);", consts=consts, rule="unresolvable window")
        self.assertPasses("assert!(start.elapsed() < BOUND);", "use crate::far::y::BOUND;", consts=consts)
        self.assertPasses("assert!(start.elapsed() < BOUND);", "use crate::far::y::{OTHER, BOUND};", consts=consts)
        ancestor = {"BOUND": [("src/lib.rs", "Duration::from_secs(10)")]}
        self.assertPasses("assert!(start.elapsed() < BOUND);", consts=ancestor)

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


class BaseRef(unittest.TestCase):
    """`--base` reads the list at a commit; only a commit without one skips."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.saved = guard.ROOT, guard.ALLOWLIST
        guard.ROOT, guard.ALLOWLIST = root, root / "scripts/dev/timing-asserts-allowlist.tsv"

        def git(*args):
            env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                   "GIT_COMMITTER_EMAIL": "t@t", "PATH": os.environ["PATH"], "HOME": self.dir.name}
            return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True, env=env).stdout.strip()

        git("init", "-q")
        (root / "README").write_text("x\n")
        git("add", "README")
        git("commit", "-q", "-m", "no list yet")
        self.cutover = git("rev-parse", "HEAD")
        guard.ALLOWLIST.parent.mkdir(parents=True)
        self.row = guard.Row(PATH, "case", "assert!(x)", "reason")
        guard.ALLOWLIST.write_text(guard.format_row(self.row) + "\n")
        git("add", ".")
        git("commit", "-q", "-m", "list")
        self.listed = git("rev-parse", "HEAD")

    def tearDown(self):
        guard.ROOT, guard.ALLOWLIST = self.saved
        self.dir.cleanup()

    def test_the_list_at_the_base_is_read(self):
        self.assertEqual(guard.read_base(self.listed), [self.row])

    def test_a_base_without_the_list_is_the_cutover(self):
        self.assertIsNone(guard.read_base(self.cutover))

    def test_an_unreadable_base_fails_rather_than_skipping(self):
        with self.assertRaises(SystemExit):
            guard.read_base("no-such-ref")


class Lexer(unittest.TestCase):
    """The literal and comment blanking the scan stands on (MIK-8222)."""

    blank = staticmethod(guard.blank_strings_and_comments)

    def test_strings_and_comments_blank_and_code_survives(self):
        self.assertEqual(self.blank('a("x") // c\nb'), 'a("") \nb')
        self.assertEqual(self.blank("a /* x\ny */ b"), "a \n b")

    def test_an_escaped_quote_does_not_end_the_string(self):
        self.assertEqual(self.blank(r'f("a\"elapsed()\"b"); g'), 'f(""); g')

    def test_raw_and_raw_byte_strings_blank_to_their_closing_hashes(self):
        self.assertEqual(self.blank('x(r#"a "q" elapsed()"#); y'), 'x(""); y')
        self.assertEqual(self.blank('x(br"elapsed()"); y'), 'x(""); y')

    def test_an_identifier_ending_in_r_is_not_a_raw_prefix(self):
        # `bar` then a plain string, not a raw string opened by its last `r`.
        self.assertEqual(self.blank('bar"x" + y'), 'bar"" + y')

    def test_a_lifetime_is_not_a_char_literal(self):
        self.assertEqual(self.blank("fn f<'a>(s: &'a str) { g('x') }"), "fn f<'a>(s: &'a str) { g(' ') }")

    def test_line_numbers_survive_multiline_literals(self):
        code = 'let s = "one\ntwo";\n/* a\nb */\nassert!(start.elapsed() < Duration::from_millis(1));'
        found = guard.scan_text(PATH, "fn case() {\n    let start = Instant::now();\n" + code + "\n}\n", {})
        self.assertEqual([f.line for f in found], [7])


if __name__ == "__main__":
    unittest.main()
