#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the timing-assert guard refuses (MIK-8222, family timing-flakes).

Each rule has a case here that goes red when the rule is removed: the 5 s
threshold, fail-closed on an unresolvable window, equality judging, and the
allowlist's stale, ambiguous and shrink-only checks. `NewCode` pins PR-C
(MIK-8247, MIK-8288): the 10 s floor on new spans, the sleep and
expected-elapse shapes, the reason tags, the oracle annotation, the loop and
poll-budget rules, and the short product timer.
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


class Timeouts(unittest.TestCase):
    """A timeout whose expiry fails the test is a window too (MIK-8247)."""

    def scan(self, body, path="src/x_tests.rs", prelude="", consts=None, includers=None):
        text = f"{prelude}\nasync fn case() {{\n{body}\n}}\n"
        return guard.scan_timeouts(path, text, consts or {}, includers or {})

    def assertRefused(self, body, rule="under 5 s", **kw):
        found = self.scan(body, **kw)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0].rule, rule, found)

    def assertPasses(self, body, **kw):
        self.assertEqual(self.scan(body, **kw), [])

    def test_each_consumption_that_fails_the_test_is_judged(self):
        for tail in ('.expect("arrives")', ".unwrap()", "?", '.unwrap_or_else(|_| panic!("late"))'):
            with self.subTest(tail=tail):
                self.assertRefused(f"let x = timeout(Duration::from_millis(4900), rx.recv()).await{tail};")
                self.assertPasses(f"let x = timeout(Duration::from_secs(5), rx.recv()).await{tail};")

    def test_a_bound_result_consumed_later_is_judged(self):
        self.assertRefused('let got = timeout(Duration::from_millis(10), probe()).await;\nlet v = got.expect("in time");')
        self.assertRefused("let got = tokio::time::timeout(Duration::from_millis(10), probe()).await;\nlet v = got?;")
        self.assertRefused(
            "let got = timeout(Duration::from_millis(10), probe()).await;\n"
            'let v = got.unwrap_or_else(|_| panic!("late"));'
        )

    def test_the_rustfmt_layout_is_seen(self):
        self.assertRefused('tokio::time::timeout(\n    Duration::from_millis(500),\n    child.wait(),\n)\n.await\n.expect("exits");')

    def test_an_unresolved_window_fails_closed(self):
        self.assertRefused('timeout(window(), f()).await.expect("x");', rule="unresolvable window")

    def test_a_timeout_whose_expiry_does_not_fail_the_test_passes(self):
        self.assertPasses("let elapsed = timeout(Duration::from_millis(50), f()).await;\nassert!(elapsed.is_err());")
        self.assertPasses("let _ = timeout(Duration::from_millis(50), f()).await;")

    def test_an_expect_inside_the_timed_future_is_not_the_consumption(self):
        self.assertPasses('let r = timeout(Duration::from_millis(50), async { rx.recv().await.expect("x") }).await;')

    def test_a_paused_clock_is_virtual_time_and_not_judged(self):
        body = 'timeout(Duration::from_millis(1), l.admit()).await.expect("waited");'
        text = f"#[tokio::test(start_paused = true)]\nasync fn paused() {{\n{body}\n}}\n"
        self.assertEqual(guard.scan_timeouts("src/x_tests.rs", text, {}, {}), [])
        text = f"#[tokio::test]\nasync fn paused() {{\ntokio::time::pause();\n{body}\n}}\n"
        self.assertEqual(guard.scan_timeouts("src/x_tests.rs", text, {}, {}), [])
        # The next function is on the real clock again.
        text = f"#[tokio::test(start_paused = true)]\nasync fn paused() {{}}\n#[tokio::test]\nasync fn real() {{\n{body}\n}}\n"
        self.assertEqual([f.fn for f in guard.scan_timeouts("src/x_tests.rs", text, {}, {})], ["real"])

    def test_the_handshake_shape_of_mik_8253_is_refused(self):
        self.assertRefused('timeout(Duration::from_millis(500), t.start()).await.expect("handshake").unwrap();')

    def test_the_quiet_window_shape_of_mik_8252_is_refused(self):
        prelude = "const QUIET: Duration = Duration::from_millis(1500);"
        self.assertRefused('timeout(QUIET, events.recv()).await.expect("event");', prelude=prelude)

    def test_a_const_from_the_including_file_resolves(self):
        consts = {"READ_TIMEOUT": [("tests/root.rs", "Duration::from_secs(15)")]}
        body = 'timeout(READ_TIMEOUT, r.next()).await.expect("frame");'
        self.assertPasses(body, path="tests/sub/rows.rs", consts=consts, includers={"tests/sub/rows.rs": "tests/root.rs"})
        self.assertRefused(body, path="tests/sub/rows.rs", consts=consts, rule="unresolvable window")

    def test_product_code_is_not_judged(self):
        body = 'timeout(Duration::from_millis(100), f()).await.expect("x");'
        self.assertPasses(body, path="src/backend/era.rs")
        self.assertRefused(body, path="src/accounts/wire_tests/fixture.rs")
        text = f"async fn product() {{\n{body}\n}}\n#[cfg(test)]\nmod tests {{\nasync fn t() {{\n{body}\n}}\n}}\n"
        found = guard.scan_timeouts("src/backend/era.rs", text, {}, {})
        self.assertEqual([f.fn for f in found], ["t"], found)


HANG = {"HANG_BOUND": [("src/gateway/mod.rs", "Duration::from_secs(30)")]}


class NewCode(unittest.TestCase):
    """The 10 s floor and the PR-C rules judge only new or changed spans (MIK-8247, MIK-8288)."""

    def scan(self, body, added="all", attrs="#[tokio::test]", prelude="", consts=None):
        text = f"{prelude}\n{attrs}\nasync fn case() {{\n{body}\n}}\n"
        lines = set(range(1, text.count("\n") + 2)) if added == "all" else set(added)
        return guard.scan_new("src/x_tests.rs", text, consts if consts is not None else HANG, {}, lines)

    def assertRefused(self, body, rule, **kw):
        found = self.scan(body, **kw)
        self.assertTrue(found, f"nothing refused:\n{body}")
        self.assertIn(rule, [f.rule for f in found], found)

    def assertPasses(self, body, **kw):
        self.assertEqual(self.scan(body, **kw), [])

    # A. The floor.
    def test_a_new_window_under_ten_seconds_is_refused(self):
        self.assertRefused('timeout(Duration::from_secs(9), rx.recv()).await.expect("x");', guard.FLOOR)
        self.assertRefused("assert!(start.elapsed() < Duration::from_secs(9));", guard.FLOOR)

    def test_a_const_under_the_floor_is_refused(self):
        prelude = "const BOUND: Duration = Duration::from_secs(5);"
        self.assertRefused('timeout(BOUND, rx.recv()).await.expect("x");', guard.FLOOR, prelude=prelude)

    def test_an_unchanged_window_is_not_judged(self):
        self.assertPasses('timeout(Duration::from_secs(9), rx.recv()).await.expect("x");', added=())

    def test_the_hang_bound_and_ten_seconds_pass(self):
        for name in ("HANG_BOUND", "test_helpers::HANG_BOUND", "crate::test_wait::HANG_BOUND"):
            with self.subTest(name=name):
                self.assertPasses(f'timeout({name}, rx.recv()).await.expect("x");')
                self.assertPasses(f'timeout({name}, rx.recv()).await.expect("x");', consts={})
        self.assertPasses('timeout(Duration::from_secs(10), rx.recv()).await.expect("x");')

    def test_an_assert_added_after_an_old_sleep_makes_the_span_new(self):
        body = "tokio::time::sleep(Duration::from_millis(1500)).await;\nassert!(cancels() == 1);"
        # Text line 4 is the sleep, line 5 the assert.
        self.assertRefused(body, guard.SLEEP, added={5})
        self.assertPasses(body, added=())

    # C. The kept-oracle annotation.
    def test_a_well_formed_oracle_annotation_keeps_a_short_window(self):
        for note in ("vs 30 s STDIO_DRAIN_TIMEOUT (MIK-8247)", "vs 4.5 s backend timeout (MIK-8285)", "vs DRAIN_TIMEOUT (MIK-1)"):
            with self.subTest(note=note):
                self.assertPasses(f'// timing-oracle: {note}\ntimeout(Duration::from_secs(5), run()).await.expect("x");')
        prelude = "// timing-oracle: vs 150 ms SESSION_TTL (MIK-8280)\nconst ORACLE: Duration = Duration::from_millis(100);"
        self.assertPasses('timeout(ORACLE, run()).await.expect("x");', prelude=prelude)

    def test_a_malformed_oracle_annotation_is_refused(self):
        for note in ("vs 30 s STDIO_DRAIN_TIMEOUT", "vs the timeout (MIK-8247)", "30 s (MIK-8247)", "vs 30 s (8247)"):
            with self.subTest(note=note):
                self.assertRefused(f'// timing-oracle: {note}\ntimeout(Duration::from_secs(5), run()).await.expect("x");', guard.ORACLE)

    # v2. A sleep used as a window, and a timeout expected to elapse.
    def test_a_short_sleep_then_an_assert_is_refused(self):
        self.assertRefused("tokio::time::sleep(Duration::from_millis(1500)).await;\nassert!(cancels() == 1);", guard.SLEEP)
        self.assertRefused("std::thread::sleep(Duration::from_millis(200));\nassert!(done());", guard.SLEEP)
        self.assertPasses("tokio::time::sleep(Duration::from_millis(200)).await;\nlet _ = done();")

    def test_a_timeout_expected_to_elapse_then_an_assert_is_refused(self):
        body = "let r = timeout(Duration::from_millis(200), f()).await;\nassert!(r.is_err());\nassert!(done());"
        self.assertRefused(body, guard.ELAPSE)

    def test_a_closed_reason_tag_passes_and_anything_else_is_refused(self):
        sleep = "tokio::time::sleep(Duration::from_millis(200)).await;\nassert!(done());"
        for tag in ("absence", "lower-bound", "first-poll", "fixture", "precondition"):
            with self.subTest(tag=tag):
                self.assertPasses(f"// timing: {tag}\n{sleep}")
        for tag in ("lower-bound because", "whatever", "Absence"):
            with self.subTest(tag=tag):
                self.assertRefused(f"// timing: {tag}\n{sleep}", guard.TAG)
                # A bad tag also leaves the sleep unexcused.
                self.assertRefused(f"// timing: {tag}\n{sleep}", guard.SLEEP)

    def test_a_paused_clock_is_not_judged(self):
        self.assertPasses("tokio::time::sleep(Duration::from_millis(200)).await;\nassert!(done());", attrs="#[tokio::test(start_paused = true)]")

    # A (v3.2). The absence tag binds to an absence collector.
    def test_the_absence_tag_on_a_positive_collector_is_refused(self):
        self.assertRefused("// timing: absence\nlet got = s.drain(Duration::from_millis(300)).await;\nassert!(got.is_empty());", guard.ABSENCE)
        self.assertPasses("// timing: absence\nlet got = s.collect_for_absence(Duration::from_millis(300)).await;\nassert!(got.is_empty());")
        self.assertPasses(
            'let (seen, _) = s.read_until(|f| has_id(f, 3)).await;\n// timing: absence\n'
            "tokio::time::sleep(Duration::from_millis(300)).await;\nassert!(seen.len() == 1);"
        )

    # B. Loops: a poll is exempt, a paced loop is judged.
    def test_a_fixed_count_paced_loop_is_refused(self):
        body = "for _ in 0..12 {\n    tokio::time::sleep(Duration::from_millis(40)).await;\n    assert!(resumes());\n}"
        self.assertRefused(body, guard.SLEEP)

    def test_a_condition_exit_poll_passes(self):
        self.assertPasses("while !done() {\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}\nassert!(ok());")
        self.assertPasses("loop {\n    if done() {\n        break;\n    }\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}\nassert!(ok());")

    def test_a_poll_that_asserts_before_its_exit_is_paced(self):
        body = "loop {\n    assert!(alive());\n    if done() {\n        break;\n    }\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}"
        self.assertRefused(body, guard.SLEEP)

    def test_a_deadline_assert_in_a_poll_is_a_hang_guard(self):
        body = (
            "let deadline = Instant::now() + HANG_BOUND;\nloop {\n    assert!(Instant::now() < deadline);\n"
            "    if done() {\n        break;\n    }\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}"
        )
        self.assertPasses(body)

    # G. A count-bounded poll followed by a failure has a budget of N x W.
    def test_a_bounded_poll_under_the_floor_is_refused(self):
        brk = "for _ in 0..500 {\n    if done() {\n        break;\n    }\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}\nassert!(done());"
        self.assertRefused(brk, guard.BUDGET)
        ret = "for _ in 0..500 {\n    if done() {\n        return;\n    }\n    std::thread::sleep(Duration::from_millis(2));\n}\npanic!(\"never\");"
        self.assertRefused(ret, guard.BUDGET)
        self.assertPasses(brk.replace("0..500", "0..1000"))

    def test_an_unresolved_poll_budget_fails_closed(self):
        body = "for _ in 0..n {\n    if done() {\n        break;\n    }\n    tokio::time::sleep(Duration::from_millis(10)).await;\n}\nassert!(done());"
        self.assertRefused(body, guard.BUDGET)

    # D. A short product timer slept against on the real clock.
    def test_a_short_product_timer_on_the_real_clock_is_refused(self):
        body = (
            "let config = Config {\n    session_ttl: Duration::from_millis(150),\n    ..Config::default()\n};\n"
            "// timing: lower-bound\ntokio::time::sleep(Duration::from_millis(40)).await;\nlet _ = config;"
        )
        self.assertRefused(body, guard.TIMER)
        self.assertPasses(body, attrs="#[tokio::test(start_paused = true)]")
        self.assertPasses(body.replace("from_millis(150)", "from_secs(10)"))

    # Code review of #3746 (gpt): ways around the rules, each pinned.
    def test_a_changed_duration_line_inside_a_multiline_timeout_is_new(self):
        body = 'tokio::time::timeout(\n    Duration::from_secs(1),\n    rx.recv(),\n)\n.await\n.expect("x");'
        # Text line 4 opens the call; line 5 holds the window.
        self.assertRefused(body, guard.FLOOR, added={5})

    def test_a_changed_const_makes_its_window_new(self):
        prelude = "const BOUND: Duration = Duration::from_secs(1);"
        # Line 1 is the const; the timeout on line 5 is unchanged.
        self.assertRefused('timeout(BOUND, rx.recv()).await.expect("x");', guard.FLOOR, prelude=prelude, added={1})

    def test_a_later_shadow_does_not_excuse_an_earlier_sleep(self):
        body = (
            "let w = Duration::from_millis(100);\ntokio::time::sleep(w).await;\nassert!(done());\n"
            "let w = Duration::from_secs(30);\nlet _ = w;"
        )
        self.assertRefused(body, guard.SLEEP)

    def test_a_changed_collector_under_an_old_absence_tag_is_judged(self):
        body = "// timing: absence\nlet got = s.drain(Duration::from_millis(300)).await;\nassert!(got.is_empty());"
        # Line 4 is the old tag; line 5, the collector, changed.
        self.assertRefused(body, guard.ABSENCE, added={5})

    def test_an_oracle_on_a_const_covers_an_elapsed_bound(self):
        prelude = "// timing-oracle: vs 150 ms SESSION_TTL (MIK-8280)\nconst ORACLE: Duration = Duration::from_millis(100);"
        self.assertPasses("assert!(start.elapsed() < ORACLE);", prelude=prelude)


class JudgeNew(unittest.TestCase):
    """How the new-code rules and the 5 s rule share one report (#3746 review)."""

    PATH = "src/x_tests.rs"

    def judge(self, body, rows=(), prelude=""):
        text = f"{prelude}\n#[tokio::test]\nasync fn case() {{\n{body}\n}}\n"
        texts = {self.PATH: text}
        found = guard.scan_text(self.PATH, text, {}) + guard.scan_timeouts(self.PATH, text, {}, {})
        added = {self.PATH: set(range(1, text.count("\n") + 2))}
        return guard.judge_new(found, list(rows), texts, {}, {}, added)

    def test_a_well_formed_oracle_excuses_a_new_window_under_five_seconds(self):
        body = '// timing-oracle: vs 30 s STDIO_DRAIN_TIMEOUT (MIK-8247)\ntimeout(Duration::from_secs(1), run()).await.expect("x");'
        found, errors = self.judge(body)
        self.assertEqual(errors, [], errors)
        self.assertEqual(found, [], "the excused window must not reach the 5 s rule either")

    def test_an_allowlisted_site_in_a_changed_span_is_still_judged_as_new(self):
        body = 'timeout(Duration::from_secs(1), run()).await.expect("x");'
        text = f"\n#[tokio::test]\nasync fn case() {{\n{body}\n}}\n"
        legacy = guard.scan_timeouts(self.PATH, text, {}, {})
        row = guard.Row(self.PATH, "case", legacy[0].assertion, "kept")
        _, errors = self.judge(body, rows=[row])
        self.assertTrue(any(guard.FLOOR in e for e in errors), errors)


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
            return subprocess.run(["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args], cwd=root, check=True, capture_output=True, text=True, env=env).stdout.strip()

        self.git = git

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

    def test_added_lines_are_read_against_the_base(self):
        rs = Path(self.dir.name) / "src/x_tests.rs"
        rs.parent.mkdir(parents=True)
        rs.write_text("fn a() {}\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "rust")
        base = self.git("rev-parse", "HEAD")
        rs.write_text("fn a() {}\nfn b() {}\n")
        self.assertEqual(guard.added_lines(base), {"src/x_tests.rs": {2}})


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
