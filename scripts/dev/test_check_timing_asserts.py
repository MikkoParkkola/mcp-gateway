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

import unittest
from pathlib import Path

from check_timing_asserts_fixtures import PATH, guard, scan, ScratchGit
from check_timing_asserts_moved_rows import MovedRows


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

    def test_a_paused_clock_exempts_an_assert_on_tokio_time_only(self):
        # MIK-8360: the exemption the docstring promises for asserts, not only
        # for timeouts. A tokio `Instant` is virtual on a paused clock; a
        # std one is not, and a real clock is judged whatever the instant.
        bound = "assert!(start.elapsed() < Duration::from_secs(1));"
        tokio_start = "let start = tokio::time::Instant::now();"
        cases = {
            "paused by attribute, tokio instant": (
                f"#[tokio::test(start_paused = true)]\nasync fn t() {{\n{tokio_start}\n{bound}\n}}\n",
                [],
            ),
            "paused by call, tokio instant": (
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\n{tokio_start}\n{bound}\n}}\n",
                [],
            ),
            "paused, bare instant imported from tokio": (
                "use tokio::time::{sleep, Instant};\n"
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\nlet start = Instant::now();\n{bound}\n}}\n",
                [],
            ),
            "paused, through an alias": (
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\n{tokio_start}\nlet took = start.elapsed();\n"
                "assert!(took < Duration::from_secs(1));\n}\n",
                [],
            ),
            "real clock, tokio instant": (
                f"#[tokio::test]\nasync fn t() {{\n{tokio_start}\n{bound}\n}}\n",
                ["under 5 s"],
            ),
            "paused, std instant": (
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\nlet start = std::time::Instant::now();\n{bound}\n}}\n",
                ["under 5 s"],
            ),
            "paused, bare instant from std": (
                "use std::time::Instant;\n"
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\nlet start = Instant::now();\n{bound}\n}}\n",
                ["under 5 s"],
            ),
            # A stated miss, on the safe side: an aliased tokio import is not
            # followed, so the assert is judged (refused), never exempted.
            "paused, aliased tokio import": (
                "use tokio::time::Instant as T;\n"
                f"#[tokio::test]\nasync fn t() {{\ntokio::time::pause();\nlet start = T::now();\n{bound}\n}}\n",
                ["under 5 s"],
            ),
            # A file naming both clocks leaves a bare `Instant` ambiguous.
            "paused, bare instant, std imported in the fn": (
                "use tokio::time::Instant;\n"
                f"#[tokio::test]\nasync fn t() {{\nuse std::time::Instant;\ntokio::time::pause();\nlet start = Instant::now();\n{bound}\n}}\n",
                ["under 5 s"],
            ),
        }
        for name, (text, rules) in cases.items():
            with self.subTest(name):
                found = guard.scan_text("src/x_tests.rs", text, {})
                self.assertEqual([f.rule for f in found], rules, found)

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


class RequestTimeouts(unittest.TestCase):
    """An HTTP client's `.timeout(D)` bounds the request on the real clock:
    a slow answer under load fails the test, as `timeout(W, f)` does."""

    scan, assertRefused, assertPasses = Timeouts.scan, Timeouts.assertRefused, Timeouts.assertPasses

    BUILDER = 'let c = reqwest::Client::builder().timeout({w}).build().expect("client");'
    REQUEST = 'let r = client.get(&url).timeout({w}).send().await.expect("answers");'

    def test_a_short_request_timeout_is_judged(self):
        for shape in (self.BUILDER, self.REQUEST, 'let r = gateway\n    .client\n    .post(&url)\n    .timeout({w})\n    .send();'):
            with self.subTest(shape=shape):
                self.assertRefused(shape.format(w="Duration::from_millis(500)"))
                self.assertPasses(shape.format(w="Duration::from_secs(5)"))

    def test_a_named_window_resolves_as_for_timeout(self):
        prelude = "const PROBE: Duration = Duration::from_secs(2);"
        (found,) = self.scan(self.BUILDER.format(w="PROBE"), prelude=prelude)
        self.assertEqual((found.rule, found.window), ("under 5 s", 2.0))

    def test_an_unresolved_request_window_fails_closed(self):
        self.assertRefused(self.BUILDER.format(w="window()"), rule="unresolvable window")

    def test_a_timeout_method_not_known_as_a_request_is_listed_at_any_window(self):
        for w in ("Duration::from_millis(500)", "Duration::from_secs(60)"):
            with self.subTest(w=w):
                self.assertRefused(f"let s = events.timeout({w});", rule=guard.NOT_A_REQUEST)

    def test_the_receiver_is_read_within_its_own_statement(self):
        body = self.BUILDER.format(w="Duration::from_secs(30)") + "\nlet s = events.timeout(Duration::from_secs(30));"
        self.assertRefused(body, rule=guard.NOT_A_REQUEST)

    def test_spacing_or_a_comment_before_the_parenthesis_is_read(self):
        for call in (".timeout (Duration::from_millis(500))", ".timeout /* why */ (Duration::from_millis(500))"):
            with self.subTest(call=call):
                (found,) = self.scan(f'let c = reqwest::Client::builder(){call}.build().expect("client");')
                # One allowlist key whatever the spacing.
                self.assertEqual(found.assertion, ".timeout(Duration::from_millis(500))")

    def test_reqwest_inside_an_argument_does_not_make_a_request(self):
        self.assertRefused(
            "let s = tokio_stream::iter([reqwest::Client::new()]).timeout(Duration::from_secs(60));",
            rule=guard.NOT_A_REQUEST,
        )
        self.assertRefused("let s = wrap(client.get(&url)).timeout(Duration::from_secs(60));", rule=guard.NOT_A_REQUEST)

    def test_a_named_client_or_an_imported_builder_is_a_request(self):
        for shape in (
            'let r = http_client.get(&url).timeout({w}).send();',
            'let c = Client::builder().timeout({w}).build().expect("client");',
        ):
            with self.subTest(shape=shape):
                self.assertPasses(shape.format(w="Duration::from_secs(30)"))
                self.assertRefused(shape.format(w="Duration::from_millis(500)"))

    def test_a_timeout_getter_is_not_a_bound(self):
        self.assertPasses("let d = config.timeout();")

    def test_a_range_before_the_timeout_function_is_not_a_method(self):
        self.assertPasses("let r = 0.. timeout(Duration::from_secs(5), f()).await.expect(\"x\");")

    def test_a_request_timeout_in_product_code_is_not_judged(self):
        # Beside a test item, so the file holds test code and is scanned.
        text = "fn product() {\n" + self.BUILDER.format(w="Duration::from_millis(500)") + "\n}\n#[cfg(test)]\nfn helper() {}\n"
        self.assertEqual(guard.scan_timeouts("src/x.rs", text, {}, {}), [])

    def test_a_paused_clock_is_not_judged(self):
        text = "#[tokio::test(start_paused = true)]\nasync fn paused() {\n" + self.BUILDER.format(w="Duration::from_millis(1)") + "\n}\n"
        self.assertEqual(guard.scan_timeouts("src/x_tests.rs", text, {}, {}), [])

    def test_a_new_request_timeout_meets_the_floor(self):
        text = "#[tokio::test]\nasync fn case() {\n" + self.BUILDER.format(w="Duration::from_secs(5)") + "\n}\n"
        found = guard.scan_new("src/x_tests.rs", text, HANG, {}, set(range(1, 6)))
        self.assertEqual([f.rule for f in found], [guard.FLOOR], found)


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

    def test_an_oracle_annotation_may_give_a_reason_instead_of_a_ticket(self):
        # New lines cannot carry a ticket id (the public-repo check refuses them), so a reason
        # stands in its place; the timer the window is measured against is still required.
        for note in ("vs 30 s STDIO_DRAIN_TIMEOUT (why: the drain must outlast this read)",
                     "vs DRAIN_TIMEOUT (why:x)"):
            with self.subTest(note=note):
                self.assertPasses(f'// timing-oracle: {note}\ntimeout(Duration::from_secs(5), run()).await.expect("x");')
        prelude = "// timing-oracle: vs 150 ms SESSION_TTL (why: expiry is what this asserts)\nconst ORACLE: Duration = Duration::from_millis(100);"
        self.assertPasses('timeout(ORACLE, run()).await.expect("x");', prelude=prelude)
        for note in ("vs DRAIN_TIMEOUT (why:)", "vs DRAIN_TIMEOUT (why:   )", "vs the timeout (why: it is short)",
                     "vs DRAIN_TIMEOUT why: no brackets", "vs DRAIN_TIMEOUT (because: x)",
                     "vs DRAIN_TIMEOUT (why: a) b)", "vs the timeout (why: vs 30 s DRAIN_TIMEOUT)"):
            with self.subTest(note=note):
                self.assertRefused(f'// timing-oracle: {note}\ntimeout(Duration::from_secs(5), run()).await.expect("x");', guard.ORACLE)

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
        self.scratch = ScratchGit()
        self.dir = self.scratch.dir
        root = self.scratch.root
        self.saved = self.scratch.saved
        git = self.scratch.git
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
        self.scratch.close()

    def test_the_list_at_the_base_is_read(self):
        self.assertEqual(guard.read_base(self.listed), [self.row])

    def test_a_base_without_the_list_is_the_cutover(self):
        self.assertIsNone(guard.read_base(self.cutover))

    def test_an_unreadable_base_fails_rather_than_skipping(self):
        with self.assertRaises(SystemExit):
            guard.read_base("no-such-ref")

    # Merge-base mode (pull requests, lanes): the tip dropped the row after the branch was cut,
    # and the branch never touched it, so the branch point's list is the comparison; base mode
    # keeps the tip's.
    def test_merge_base_mode_reads_the_list_at_the_branch_point(self):
        self.git("branch", "-M", "line")
        self.git("branch", "feature")
        guard.ALLOWLIST.write_text("")
        self.git("commit", "-q", "-am", "the tip shrinks the list")
        self.git("checkout", "-q", "feature")
        pin = guard.comparison_commit(guard.ROOT, "line", guard.Compare.MERGE_BASE)
        self.assertEqual(pin, self.listed)
        self.assertEqual(guard.read_base(pin), [self.row])
        self.assertEqual(guard.read_base(guard._pinned_base("line")), [])

    def test_merge_base_mode_without_a_branch_point_refuses(self):
        self.git("branch", "-M", "line")
        self.git("checkout", "-q", "--orphan", "unrelated")
        self.git("commit", "-q", "-m", "unrelated history")
        self.git("checkout", "-q", "-f", "line")
        with self.assertRaisesRegex(SystemExit, "fetch full history"):
            guard.main(["--base", "unrelated", "--compare", "merge-base"])

    def test_added_lines_are_read_against_the_base(self):
        rs = Path(self.dir.name) / "src/x_tests.rs"
        rs.parent.mkdir(parents=True)
        rs.write_text("fn a() {}\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "rust")
        base = self.git("rev-parse", "HEAD")
        rs.write_text("fn a() {}\nfn b() {}\n")
        self.assertEqual(guard.added_lines(base), {"src/x_tests.rs": {2}})


class TimeoutRowsAreShrinkOnly(unittest.TestCase):
    """A `.timeout(` row added since the base is NEW like any other row."""

    def test_a_new_timeout_row_is_refused(self):
        row = guard.Row(PATH, "case", ".timeout(Duration::from_millis(120))", "the expiry is the behaviour under test")
        found = [guard.Finding(PATH, "case", row.assertion, 3, 0.12, "under 5 s")]
        errors = guard.judge(found, [row], [])
        self.assertTrue(any(e.startswith("NEW ROW") for e in errors), errors)
        self.assertEqual(guard.judge(found, [row], [row]), [])


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


class Members(unittest.TestCase):
    """MIK-8360.TABLE.1: each flaky-under-load member's ORIGINAL code, quoted
    verbatim from the release line before its fix (c5e432970 unless noted),
    and the rule that refuses it, or the stated miss it falls under."""

    # The new-code helpers, borrowed so NewCode's own rows do not run twice.
    scan = NewCode.scan
    assertRefused = NewCode.assertRefused
    assertPasses = NewCode.assertPasses

    def test_collusion_elapsed_bound(self):
        # src/security/firewall/collusion_seam_tests.rs:201-208
        body = (
            "let start = std::time::Instant::now();\n"
            "let seams = det.seam_fingerprints(&parts);\n"
            "assert!(!seams.is_empty());\n"
            'assert!(\n    start.elapsed() < std::time::Duration::from_secs(5),\n    "{:?}",\n    start.elapsed()\n);'
        )
        self.assertRefused(body, guard.FLOOR)

    def test_prompts_builder_window(self):
        # src/gateway/meta_mcp/tests/backend_lists.rs:399
        body = "let meta = MetaMcp::new(registry).with_prompts_resources_fetch_timeout(Duration::from_secs(1));"
        self.assertRefused(body, guard.SETTER)

    def test_sub4_timeout_field(self):
        # src/gateway/router/direct_adr012_tests.rs, in the assert-free helper `backend_for`
        body = (
            "let config = BackendConfig {\n    enabled: true,\n    stop_when_idle_for: None,\n"
            "    timeout: Duration::from_millis(300),\n    env: HashMap::default(),\n    ..BackendConfig::default()\n};"
        )
        self.assertRefused(body, guard.FIELD, attrs="")

    def test_early_exit_fail_fast_timeout(self):
        # src/transport/stdio_early_exit_tests.rs:14-15, :32-35
        prelude = "const ROW_LIMIT: Duration = Duration::from_secs(5);"
        body = (
            "tokio::time::timeout(ROW_LIMIT, t.start())\n    .await\n"
            '    .expect("start must fail fast, not wait out the request timeout")\n'
            '    .expect_err("a child that died before initialize cannot start")\n    .to_string();'
        )
        self.assertRefused(body, guard.FLOOR, prelude=prelude)

    def test_child_tree_deadline_bound(self):
        # src/transport/stdio_child_tree_tests.rs:555-558
        prelude = "const REAP_DEADLINE: Duration = Duration::from_secs(5);"
        body = (
            "assert!(\n    at.elapsed() < REAP_DEADLINE + Duration::from_millis(500),\n"
            '    "a tree waited behind the others"\n);'
        )
        self.assertRefused(body, guard.FLOOR, prelude=prelude)

    def test_env_poll_sleep_window(self):
        # src/config_reload/env_poll_e2e_tests.rs:144-149
        body = (
            "tokio::time::sleep(Duration::from_secs(5)).await;\n"
            "let attempts = counts.attempts.load(Ordering::SeqCst);\n"
            'assert!(\n    attempts >= 3,\n    "an unchanged failing file must be retried; {attempts} reloads ran"\n);'
        )
        self.assertRefused(body, guard.SLEEP)

    def test_fanout_sleep_window(self):
        # src/events/fanout_tests.rs:309-319 (from evcore's report)
        body = (
            "tokio::time::sleep(std::time::Duration::from_millis(200)).await;\n"
            'std::fs::set_permissions(&unlock, std::fs::Permissions::from_mode(0o700)).expect("unlock");\n'
            'assert!(\n    crate::test_log_capture::count(&records, "WARN", "startup reconcile could not remove") >= 1,\n'
            '    "a failed attempt is logged: {records:?}"\n);'
        )
        self.assertRefused(body, guard.SLEEP)

    def test_t35_is_ok_wait(self):
        # src/events/upstream_session_wake_tests.rs:71-82 (MIK-8359, e2etests fixes it)
        body = (
            "let contacted = tokio::time::timeout(Duration::from_secs(5), async {\n"
            "    while hits.load(Ordering::SeqCst) == 0 {\n"
            "        tokio::time::sleep(Duration::from_millis(20)).await;\n    }\n})\n.await;\n"
            "shared.stop.cancel();\n"
            'assert!(\n    contacted.is_ok(),\n    "the revived backend is contacted at once, not at the 30 s timer"\n);'
        )
        self.assertRefused(body, guard.IS_OK)


class NamedShapeSpans(unittest.TestCase):
    """MIK-8360 review: R3a, R3b and R1b judge the whole statement and the
    window's binding, not only the call's opening line, and a typed literal
    is read as a number."""

    scan = NewCode.scan
    assertRefused = NewCode.assertRefused
    assertPasses = NewCode.assertPasses

    def test_a_changed_argument_line_of_a_multiline_setter_is_judged(self):
        body = "let c = Config::default()\n    .with_request_timeout(\n        Duration::from_millis(300),\n    );"
        self.assertRefused(body, guard.SETTER, added={6})
        self.assertPasses(body, added=())

    def test_a_changed_binding_of_the_window_is_judged(self):
        body = "let w = Duration::from_millis(300);\nlet c = Config::default().with_request_timeout(w);"
        self.assertRefused(body, guard.SETTER, added={4})

    def test_a_newly_added_is_ok_assert_is_judged(self):
        body = "let r = timeout(Duration::from_millis(300), f()).await;\nassert!(r.is_ok());"
        self.assertRefused(body, guard.IS_OK, added={5})
        self.assertPasses(body, added=())

    def test_a_typed_literal_field_is_a_number(self):
        self.assertRefused("let c = C { timeout_ms: 300_u64 };", guard.FIELD, attrs="")
        self.assertPasses("let c = C { timeout_ms: 30_000_u64 };", attrs="")


class TestSection(unittest.TestCase):
    """Test code in a product file is the `#[cfg(test)]` item that holds it,
    not everything after the file's first `#[cfg(test)]` line: product code
    after an early test-only item is product code, and code inside a test
    item is still judged."""

    WINDOW = 'timeout(Duration::from_millis(100), f()).await.expect("x");'

    def product_after(self, early: str) -> str:
        return f"{early}\n\nasync fn product() {{\n{self.WINDOW}\n}}\n"

    # Each layout puts product code after an early test-only item.
    EARLY = {
        "test-only fn": "#[cfg(test)]\nfn helper() {}",
        "test-only const fn": "#[cfg(test)]\nconst fn helper() -> u8 {\n    0\n}",
        "test-only use": "#[cfg(test)]\nuse crate::fixture::Probe;",
        "path module": '#[cfg(test)]\n#[path = "x_tests.rs"]\nmod tests;',
        "inline module": "#[cfg(test)]\nmod tests {\n    fn helper() {}\n}",
    }

    def timeouts(self, text):
        return guard.scan_timeouts("src/x.rs", text, {}, {})

    def new(self, text):
        lines = set(range(1, text.count("\n") + 2))
        return guard.scan_new("src/x.rs", text, HANG, {}, lines)

    def test_product_code_after_an_early_test_item_is_not_test_code(self):
        for name, early in self.EARLY.items():
            with self.subTest(layout=name):
                text = self.product_after(early)
                self.assertEqual(self.timeouts(text), [], text)
                self.assertEqual(self.new(text), [], text)

    def test_code_inside_a_test_module_is_judged(self):
        text = f"fn product() {{}}\n\n#[cfg(test)]\nmod tests {{\n    async fn case() {{\n{self.WINDOW}\n    }}\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)
        self.assertTrue(self.new(text), text)

    def test_code_inside_a_test_only_fn_is_judged(self):
        text = f"fn product() {{}}\n\n#[cfg(test)]\nasync fn helper() {{\n{self.WINDOW}\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)
        self.assertTrue(self.new(text), text)

    def test_a_test_module_that_never_closes_holds_the_rest_of_the_file(self):
        text = f"#[cfg(test)]\nmod tests {{\n    fn helper() {{}}\n\nasync fn case() {{\n{self.WINDOW}\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)
        self.assertTrue(self.new(text), text)

    # A comma in a generic header or a `where` clause is inside the item: the
    # item ends at its block, so code in its body is still judged.
    GENERIC = {
        "generic params": "#[cfg(test)]\nasync fn helper<T, U>(t: T, u: U) {{\n{w}\n}}\n",
        "generic return": "#[cfg(test)]\nasync fn helper() -> Result<u8, String> {{\n{w}\nOk(0)\n}}\n",
        "where clause": "#[cfg(test)]\nasync fn helper<T>(t: T)\nwhere\n    T: Send,\n    T: Sync,\n{{\n{w}\n}}\n",
        "braced const generic": "#[cfg(test)]\nasync fn helper() -> Probe<{{ N }}> {{\n{w}\nProbe\n}}\n",
        "braced const generic impl": "#[cfg(test)]\nimpl Probe<{{ 1 + 1 }}> {{\n    async fn helper() {{\n{w}\n    }}\n}}\n",
        "shift in a const generic": "#[cfg(test)]\nasync fn helper() -> Probe<{{ 8 >> 1 }}> {{\n{w}\nProbe\n}}\n",
        "comparison in a const generic": "#[cfg(test)]\nasync fn helper() -> Probe<{{ if A > B {{ 1 }} else {{ 2 }} }}> {{\n{w}\nProbe\n}}\n",
        "generic impl": "#[cfg(test)]\nimpl<T, U> Probe<T, U> {{\n    async fn helper() {{\n{w}\n    }}\n}}\n",
    }

    def test_a_comma_in_a_generic_header_does_not_end_the_item(self):
        for name, shape in self.GENERIC.items():
            with self.subTest(shape=name):
                text = "fn product() {}\n\n" + shape.format(w=self.WINDOW)
                self.assertEqual(len(self.timeouts(text)), 1, text)
                self.assertTrue(self.new(text), text)

    def test_a_test_only_let_is_judged_to_its_semicolon(self):
        window = self.WINDOW.rstrip(";")
        text = f"async fn product() {{\n    #[cfg(test)]\n    let x = {{ 0 }} + {window};\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_test_only_let_runs_past_a_cast_after_its_block(self):
        window = self.WINDOW.rstrip(";")
        text = f"async fn product() {{\n    #[cfg(test)]\n    let x = {{ 0 }} as u64\n        + {window};\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_test_only_let_runs_past_a_range_after_its_block(self):
        window = self.WINDOW.rstrip(";")
        text = f"async fn product() {{\n    #[cfg(test)]\n    let r = {{ 0 }}\n        .. {window};\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_an_outer_test_cfg_makes_the_whole_file_test_code(self):
        text = f"#![cfg(test)]\n\nfn first() {{}}\n\nasync fn helper() {{\n{self.WINDOW}\n}}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)

    ELAPSED = "assert!(start.elapsed() < Duration::from_secs(9));"

    def test_new_code_judges_an_elapsed_assert_only_in_test_code(self):
        product = f"#[cfg(test)]\nfn helper() {{}}\n\nfn product() {{\n{self.ELAPSED}\n}}\n"
        self.assertEqual(self.new(product), [], product)
        inside = f"#[cfg(test)]\nmod tests {{\n    fn case() {{\n{self.ELAPSED}\n    }}\n}}\n"
        self.assertIn(guard.FLOOR, [f.rule for f in self.new(inside)], inside)

    def test_full_mode_still_judges_an_elapsed_assert_anywhere(self):
        text = "fn product() {\nassert!(start.elapsed() < Duration::from_millis(100));\n}\n"
        self.assertEqual(len(guard.scan_text("src/x.rs", text, {})), 1, text)

    def test_a_restricted_visibility_fn_with_a_where_comma_is_judged(self):
        text = (
            "fn product() {}\n\n#[cfg(test)]\npub(crate) async fn helper<T>()\nwhere\n    T: Send,\n    T: Sync,\n{\n"
            + self.WINDOW + "\n}\n"
        )
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_test_only_field_runs_past_a_cast_after_its_block(self):
        window = self.WINDOW.rstrip(";").removesuffix('.expect("x")')
        text = (
            "fn product() {\n    let c = C {\n        #[cfg(test)]\n        x: { 0 } as u64\n"
            f'            + {window}.expect("x"),\n        y: 1,\n    }};\n}}\n'
        )
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_comparison_in_a_test_only_statement_does_not_hold_product_code(self):
        text = (
            "async fn product() {\n    #[cfg(test)]\n    if 1 < 2 {\n        probe();\n    }\n"
            f"{self.WINDOW}\n}}\n"
        )
        self.assertEqual(self.timeouts(text), [], text)

    def test_a_test_only_field_with_nested_generics_ends_at_its_comma(self):
        text = (
            "fn product() {\n    let c = C {\n        #[cfg(test)]\n"
            "        probe: make::<Map<A, B>>(),\n        timeout_ms: 50,\n    };\n}\n"
        )
        self.assertEqual(self.new(text), [], text)

    def test_a_line_shared_by_a_test_item_and_product_code_is_judged(self):
        text = f"#[cfg(test)] fn a() {{}} async fn product() {{ {self.WINDOW} }}\n"
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_nested_block_comment_does_not_end_a_test_module(self):
        text = (
            "fn product() {}\n\n#[cfg(test)]\nmod tests {\n    /* outer /* inner */ } */\n"
            f"    async fn case() {{\n{self.WINDOW}\n    }}\n}}\n"
        )
        self.assertEqual(len(self.timeouts(text)), 1, text)
        self.assertTrue(self.new(text), text)

    def test_a_nested_comment_inside_a_test_fn_keeps_its_whole_body(self):
        text = (
            "#[cfg(test)]\nmod tests {\n    #[tokio::test]\n    async fn case() {\n"
            "        /* outer /* inner */ } */\n"
            "        tokio::time::sleep(Duration::from_millis(1500)).await;\n"
            "        assert!(cancels() == 1);\n    }\n}\n"
        )
        self.assertIn(guard.SLEEP, [f.rule for f in self.new(text)], text)

    SLEEP_WINDOW = "tokio::time::sleep(Duration::from_millis(1500)).await;\nassert!(cancels() == 1);"

    def test_the_sleep_shape_is_judged_in_a_generic_headed_test_fn(self):
        for header in ("async fn case() -> Probe<{ 1 + 1 }>", "async fn case<T, U>()", "async fn case() -> Probe<{ 8 >> 1 }>"):
            with self.subTest(header=header):
                text = f"#[cfg(test)]\nmod tests {{\n    #[tokio::test]\n    {header} {{\n{self.SLEEP_WINDOW}\n    }}\n}}\n"
                self.assertIn(guard.SLEEP, [f.rule for f in self.new(text)], text)

    def test_a_quote_inside_a_nested_comment_hides_no_code(self):
        text = (
            "#[cfg(test)]\nmod tests {\n    async fn case() {\n"
            '        /* outer /* inner */ " */\n'
            f"{self.WINDOW}\n    }}\n}}\n"
        )
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_second_test_item_after_product_code_is_judged(self):
        text = (
            "#[cfg(test)]\nfn early() {}\n\nasync fn product() {\n" + self.WINDOW + "\n}\n\n"
            "#[cfg(test)]\nmod tests {\n    async fn case() {\n" + self.WINDOW + "\n    }\n}\n"
        )
        self.assertEqual([f.fn for f in self.timeouts(text)], ["case"], text)
        self.assertEqual({f.fn for f in self.new(text)} - {""}, {"case"}, text)

    # A compound cfg is test-only when a bare `test` sits under `all(..)` alone
    # (no `any` or `not` above it): the item is compiled only in tests.
    TEST_ONLY_CFGS = (
        '#[cfg(all(test, feature = "firewall"))]',
        "#[cfg(all(unix, test))]",
        "#[cfg(all(unix, all(test, feature = \"webui\")))]",
        "#[cfg( test )]",
        "#[cfg(all( test ,unix ))]",
        "#[cfg(any(all(test, unix), all(test, windows)))]",
    )
    NOT_TEST_ONLY_CFGS = (
        '#[cfg(any(test, feature = "firewall"))]',
        "#[cfg(all(not(test), unix))]",
        "#[cfg(not(test))]",
        "#[cfg(all(unix, any(test, windows)))]",
        "#[cfg(feature = \"test\")]",
        "#[cfg(any(all(test, unix), windows))]",
    )

    def test_an_item_under_a_test_only_compound_cfg_is_judged(self):
        for cfg in self.TEST_ONLY_CFGS:
            with self.subTest(cfg=cfg):
                text = f"fn product() {{}}\n\n{cfg}\nmod tests {{\n    async fn case() {{\n{self.WINDOW}\n    }}\n}}\n"
                self.assertEqual(len(self.timeouts(text)), 1, text)
                self.assertTrue(self.new(text), text)

    def test_product_code_after_a_test_only_compound_cfg_item_is_not_test_code(self):
        for cfg in self.TEST_ONLY_CFGS:
            with self.subTest(cfg=cfg):
                text = self.product_after(f"{cfg}\nfn helper() {{}}")
                self.assertEqual(self.timeouts(text), [], text)
                self.assertEqual(self.new(text), [], text)

    def test_an_item_under_a_cfg_that_also_builds_outside_tests_is_product_code(self):
        for cfg in self.NOT_TEST_ONLY_CFGS:
            with self.subTest(cfg=cfg):
                text = f"{cfg}\nmod m {{\n    async fn product() {{\n{self.WINDOW}\n    }}\n}}\n"
                self.assertEqual(self.timeouts(text), [], text)
                self.assertEqual(self.new(text), [], text)

    def test_an_unsure_file_is_judged_as_test_code_throughout(self):
        # The parser cannot read this file cleanly (a cfg on a struct-pattern
        # field), so it is unsure as a whole; this gate looks for test code,
        # so all of it is judged (LEAN_LONG).
        text = (
            "fn p(s: S) {\n    let S {\n        #[cfg(feature = \"x\")]\n        a,\n        b,\n    } = s;\n}\n"
            f"#[cfg(test)]\nfn helper() {{}}\n\nasync fn product() {{\n{self.WINDOW}\n}}\n"
        )
        self.assertEqual(len(self.timeouts(text)), 1, text)

    def test_a_product_file_without_test_items_has_no_test_code(self):
        self.assertEqual(self.timeouts(self.product_after("fn other() {}")), [])


if __name__ == "__main__":
    unittest.main()
