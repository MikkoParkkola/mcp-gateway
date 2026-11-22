# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for bounds written from a product budget, and for the binding a window
sees (the visible one, not the file's last of that name).

A product budget here is a non-test `const NAME: Duration` of one
`Duration::from_secs` / `from_millis`, or a Duration a test passes to a product
fn named like `x_within`. Each refused row uses a 30 s budget, so the 10 s
new-code floor never decides it.
"""

from __future__ import annotations

import unittest

from check_timing_asserts_fixtures import PATH, guard

PRODUCT_PATH = "src/x.rs"
PRODUCT = """\
pub(crate) const DRAIN: Duration = Duration::from_secs(30);
pub(crate) const STD_DRAIN: Duration = std::time::Duration::from_secs(30);
pub(crate) const TOKIO_DRAIN: Duration = tokio::time::Duration::from_secs(30);
pub(crate) const SHORT: Duration = Duration::from_secs(5);
pub(crate) async fn run_within(x: &X, budget: Duration, f: F) -> R {
    f.await
}
pub(crate) async fn mutate_and_reload_within(p: &P, budget: Duration, e: E) -> R {
    e.await
}
pub(crate) async fn pair_within(first: Duration, second: Duration) -> R {
    todo!()
}
"""
# The test hang bound, defined where the resolver reads it from source.
HANG = {"HANG_BOUND": [("src/gateway/mod.rs", "Duration::from_secs(30)")]}


def test_file(body: str, attrs: str = "#[tokio::test]", prelude: str = "") -> str:
    return f"{prelude}\n{attrs}\nasync fn case() {{\n{body}\n}}\n"


def scan(text: str, added="all", product: str = PRODUCT, path: str = PATH):
    texts = {PRODUCT_PATH: product, path: text}
    lines = set(range(1, text.count("\n") + 2)) if added == "all" else set(added)
    consts = {**HANG, **guard.tree_consts(texts)}
    return guard.scan_new(path, text, consts, {}, lines, budgets=guard.budgets_of(texts))


def listed(text: str, product: str = PRODUCT, path: str = PATH) -> list[str]:
    texts = {PRODUCT_PATH: product, path: text}
    consts = {**HANG, **guard.tree_consts(texts)}
    return guard.budget_list(path, text, consts, {}, guard.budgets_of(texts))


def line_of(text: str, needle: str) -> int:
    """1-based line of the first line holding `needle`."""
    return next(n for n, line in enumerate(text.splitlines(), 1) if needle in line)


class ProductBudgets(unittest.TestCase):
    """A bound named from a product budget is refused in new code."""

    def refused(self, text, name, **kw):
        found = [f for f in scan(text, **kw) if f.rule.startswith(guard.PRODUCT_BUDGET)]
        self.assertTrue(found, f"no product-budget finding:\n{text}")
        self.assertIn(name, found[0].rule, found)

    def passes(self, text, **kw):
        self.assertEqual(scan(text, **kw), [], text)

    def test_p1_p3_a_window_named_from_the_budget_is_refused(self):
        for window in ("DRAIN + Duration::from_secs(10)", "DRAIN", "DRAIN * 2"):
            with self.subTest(window=window):
                self.refused(test_file(f'timeout({window}, rx.recv()).await.expect("drained");'), "DRAIN")

    def test_p4_an_elapsed_bound_named_from_the_budget_is_refused(self):
        body = "let t = Instant::now();\nsettle().await;\nassert!(t.elapsed() < DRAIN + Duration::from_secs(10));"
        self.refused(test_file(body), "DRAIN")

    def test_p5_p7_test_local_constants_the_hang_bound_and_a_literal_pass(self):
        local = "const WAIT: Duration = Duration::from_secs(30);"
        self.passes(test_file('timeout(WAIT, rx.recv()).await.expect("w");', prelude=local))
        self.passes(test_file('timeout(HANG_BOUND, rx.recv()).await.expect("w");'))
        self.passes(test_file('timeout(Duration::from_secs(30), rx.recv()).await.expect("w");'))

    def test_p8_a_paused_clock_is_skipped(self):
        body = 'timeout(DRAIN + Duration::from_secs(10), rx.recv()).await.expect("w");'
        self.passes(test_file(body, attrs="#[tokio::test(start_paused = true)]"))

    def test_p9_an_unchanged_line_is_listed_not_refused(self):
        text = test_file('timeout(DRAIN + Duration::from_secs(10), rx.recv()).await.expect("w");')
        self.passes(text, added=())
        self.assertTrue(any("named DRAIN" in line for line in listed(text)), listed(text))

    def test_p10_p14_a_local_of_the_same_name_shadows_the_budget(self):
        local = "const DRAIN: Duration = Duration::from_secs(30);"
        self.passes(test_file('timeout(DRAIN, rx.recv()).await.expect("w");', prelude=local))
        self.passes(test_file('let DRAIN = Duration::from_secs(30);\ntimeout(DRAIN, rx.recv()).await.expect("w");'))

    def test_p11_a_well_formed_oracle_excuses_it(self):
        body = '// timing-oracle: vs DRAIN (why: the row measures the drain)\ntimeout(DRAIN + Duration::from_secs(10), rx.recv()).await.expect("w");'
        self.passes(test_file(body))

    def test_p12_a_deadline_named_from_the_budget_is_refused(self):
        body = "let deadline = Instant::now() + DRAIN;\nsettle().await;\nassert!(Instant::now() < deadline);"
        self.refused(test_file(body), "DRAIN")

    def test_p13_std_time_reads_real_time_on_a_paused_clock(self):
        body = "let t = std::time::Instant::now();\nsettle().await;\nassert!(t.elapsed() < DRAIN + Duration::from_secs(10));"
        self.refused(test_file(body, attrs="#[tokio::test(start_paused = true)]"), "DRAIN")

    def test_p15_a_qualified_name_reaches_the_product_budget_past_a_local(self):
        local = "const DRAIN: Duration = Duration::from_secs(30);"
        body = 'timeout(super::DRAIN + Duration::from_secs(10), rx.recv()).await.expect("w");'
        self.refused(test_file(body, prelude=local), "DRAIN")

    def test_p16_fully_qualified_duration_spellings_are_budgets(self):
        for name in ("STD_DRAIN", "TOKIO_DRAIN"):
            with self.subTest(name=name):
                self.refused(test_file(f'timeout({name}, rx.recv()).await.expect("w");'), name)

    def test_p17_p18_a_bound_at_most_an_explicit_budget_on_its_carrier_is_refused(self):
        for bound in (30, 20):
            with self.subTest(bound=bound):
                body = (
                    "let h = tokio::spawn(async move { run_within(&x, Duration::from_secs(30), f).await });\n"
                    f'timeout(Duration::from_secs({bound}), h).await.expect("w");'
                )
                self.refused(test_file(body), "run_within")

    def test_p19_a_within_fn_defined_in_test_code_is_no_budget(self):
        helper = "async fn run_within(x: &X, budget: Duration, f: F) -> R {\n    f.await\n}"
        body = (
            "let h = tokio::spawn(async move { run_within(&x, Duration::from_secs(30), f).await });\n"
            'timeout(Duration::from_secs(30), h).await.expect("w");'
        )
        self.passes(test_file(body, prelude=helper), product="pub(crate) const DRAIN: Duration = Duration::from_secs(30);\n")

    def test_p20_the_hang_bound_or_a_long_literal_on_the_carrier_passes(self):
        for bound in ("HANG_BOUND", "Duration::from_secs(120)"):
            with self.subTest(bound=bound):
                body = (
                    "let h = tokio::spawn(async move { run_within(&x, Duration::from_secs(30), f).await });\n"
                    f'timeout({bound}, h).await.expect("w");'
                )
                self.passes(test_file(body))

    def test_p21_the_reload_row_shape_is_refused(self):
        body = (
            "let h = tokio::spawn(async move {\n"
            "    ctx.mutate_and_reload_within(&path, std::time::Duration::from_secs(30), edit).await\n"
            "});\n"
            'tokio::time::timeout(std::time::Duration::from_secs(30), h).await.expect("w");'
        )
        self.refused(test_file(body), "mutate_and_reload_within")

    def test_p22_a_wait_on_other_work_in_the_same_fn_passes(self):
        body = (
            "run_within(&x, Duration::from_secs(30), f).await;\n"
            'timeout(Duration::from_secs(30), other()).await.expect("w");'
        )
        self.passes(test_file(body))

    def test_p23_p36_a_spawned_or_async_carrier_through_a_let_is_refused(self):
        for value in (
            "tokio::spawn(async move { run_within(&x, Duration::from_secs(30), f).await })",
            "async { run_within(&x, Duration::from_secs(30), g).await }",
            "async move { run_within(&x, Duration::from_secs(30), g).await }",
        ):
            with self.subTest(value=value):
                body = f'let writer = {value};\ntimeout(Duration::from_secs(30), writer).await.expect("w");'
                self.refused(test_file(body), "run_within")

    def test_p24_p32_p33_a_plain_block_is_never_a_carrier(self):
        block = "{ run_within(&x, Duration::from_secs(30), f).await; other() }"
        for body in (
            f'let f = {block};\ntimeout(Duration::from_secs(30), f).await.expect("w");',
            f'timeout(Duration::from_secs(30), {block}).await.expect("w");',
            f'let h = tokio::spawn({block});\ntimeout(Duration::from_secs(30), h).await.expect("w");',
        ):
            with self.subTest(body=body):
                self.passes(test_file(body))

    def test_p27_the_call_itself_as_the_future_is_refused(self):
        body = 'timeout(Duration::from_secs(30), run_within(&x, Duration::from_secs(30), f)).await.expect("w");'
        self.refused(test_file(body), "run_within")

    def test_p25_p26_p34_a_budget_one_or_more_bindings_away_is_named(self):
        for prelude, body in (
            ("", "let wait = DRAIN + Duration::from_secs(10);\ntimeout(wait, rx.recv()).await.expect(\"w\");"),
            ("", "let a = DRAIN;\nlet b = a * 2;\ntimeout(b, rx.recv()).await.expect(\"w\");"),
            ("const WAIT: Duration = DRAIN + Duration::from_secs(10);", 'timeout(WAIT, rx.recv()).await.expect("w");'),
        ):
            with self.subTest(body=body):
                self.refused(test_file(body, prelude=prelude), "DRAIN")

    def test_p29_p30_an_initializer_reads_the_binding_visible_where_it_is_written(self):
        hidden = 'let a = DRAIN;\nlet b = a * 2;\nlet a = Duration::from_secs(30);\ntimeout(b, rx.recv()).await.expect("w");'
        self.refused(test_file(hidden), "DRAIN")
        added_later = 'let a = Duration::from_secs(30);\nlet b = a * 2;\nlet a = DRAIN;\ntimeout(b, rx.recv()).await.expect("w");'
        self.passes(test_file(added_later))

    def test_p31_a_change_up_the_chain_makes_the_site_new(self):
        text = test_file('let a = DRAIN;\nlet b = a * 2;\ntimeout(b, rx.recv()).await.expect("w");')
        self.refused(text, "DRAIN", added={line_of(text, "let a = DRAIN")})

    def test_p35_a_binding_the_window_never_reads_is_not_judged(self):
        self.passes(test_file('let unused = DRAIN;\ntimeout(Duration::from_secs(30), rx.recv()).await.expect("w");'))

    def test_p37_p38_a_let_cannot_see_itself(self):
        self.refused(test_file('let a = DRAIN;\nlet a = a * 2;\ntimeout(a, rx.recv()).await.expect("w");'), "DRAIN")
        body = 'let wait = DRAIN + Duration::from_secs(10);\nlet wait = timeout(wait, rx.recv()).await.expect("w");'
        self.refused(test_file(body), "DRAIN")


class CodeReviewRows(unittest.TestCase):
    """Rows added with the first code review of the rule (both counting seats)."""

    refused = ProductBudgets.refused
    passes = ProductBudgets.passes

    def test_c1_a_path_qualified_call_is_a_carrier(self):
        body = 'timeout(Duration::from_secs(30), crate::run_within(&x, Duration::from_secs(30), f)).await.expect("w");'
        self.refused(test_file(body), "run_within")

    def test_c2a_any_duration_argument_of_the_carried_call_counts(self):
        one_call = 'timeout(Duration::from_secs(30), pair_within(Duration::from_secs(60), Duration::from_secs(10))).await.expect("w");'
        self.refused(test_file(one_call), "pair_within")

    def test_c2b_any_carried_call_counts(self):
        two_calls = (
            "let h = async {\n    run_within(&x, Duration::from_secs(10), f).await;\n"
            "    run_within(&x, Duration::from_secs(60), g).await\n};\n"
            'timeout(Duration::from_secs(30), h).await.expect("w");'
        )
        self.refused(test_file(two_calls), "run_within")

    def test_c3a_a_name_given_to_spawn_is_not_followed(self):
        through_spawn = (
            "let fut = run_within(&x, Duration::from_secs(30), f);\nlet h = tokio::spawn(fut);\n"
            'timeout(Duration::from_secs(30), h).await.expect("w");'
        )
        self.passes(test_file(through_spawn))

    def test_c3b_a_chain_of_lets_is_not_followed(self):
        chained = (
            "let a = async { run_within(&x, Duration::from_secs(30), f).await };\nlet b = a;\n"
            'timeout(Duration::from_secs(30), b).await.expect("w");'
        )
        self.passes(test_file(chained))

    def test_c4_only_the_async_blocks_own_body_is_read(self):
        body = 'timeout(Duration::from_secs(30), async { other().await }.then(|_| run_within(&x, Duration::from_secs(30), f))).await.expect("w");'
        self.passes(test_file(body))

    def test_c5_an_explicit_budget_is_resolved_where_the_call_is(self):
        body = (
            "let b = Duration::from_secs(30);\n"
            "let h = tokio::spawn(async move { run_within(&x, b, f).await });\n"
            "let b = Duration::from_secs(5);\n"
            'timeout(Duration::from_secs(20), h).await.expect("w");'
        )
        self.refused(test_file(body), "run_within")

    def test_c6a_a_deadline_window_is_read_where_the_deadline_is_built(self):
        hidden = (
            "let w = DRAIN;\nlet deadline = Instant::now() + w;\nlet w = Duration::from_secs(30);\n"
            "settle().await;\nassert!(Instant::now() < deadline);"
        )
        self.refused(test_file(hidden), "DRAIN")

    def test_c6b_a_later_binding_invents_no_budget_for_a_deadline(self):
        invented = (
            "let w = Duration::from_secs(30);\nlet deadline = Instant::now() + w;\nlet w = DRAIN;\n"
            "settle().await;\nassert!(Instant::now() < deadline);"
        )
        self.passes(test_file(invented))

    def test_c10_only_the_deadline_the_condition_compares_moves_the_reading(self):
        body = (
            "let w = DRAIN;\nlet deadline = Instant::now() + w;\nlet w = Duration::from_secs(30);\n"
            'let t = Instant::now();\nsettle().await;\nassert!(t.elapsed() < w, "{:?}", deadline);'
        )
        self.passes(test_file(body))

    def test_c11_a_budget_bound_inside_the_carried_block_is_read(self):
        body = (
            "let h = tokio::spawn(async move { let b = Duration::from_secs(30); run_within(&x, b, f).await });\n"
            'timeout(Duration::from_secs(20), h).await.expect("w");'
        )
        self.refused(test_file(body), "run_within")

    def test_c7_an_edit_after_a_semicolon_inside_the_timed_block_is_new(self):
        body = 'let r = timeout(Duration::from_secs(5), async {\n    a().await;\n    b().await;\n}).await.expect("x");'
        text = test_file(body)
        found = scan(text, added={line_of(text, "b().await;")})
        self.assertIn(guard.FLOOR, [f.rule for f in found], found)

    def test_c8_a_const_with_disagreeing_definitions_in_its_file_is_no_budget(self):
        product = "pub(crate) const T: Duration = Duration::from_secs(30);\nmod m {\n    pub(crate) const T: u64 = 5;\n}\n"
        self.assertNotIn("T", guard.budgets_of({PRODUCT_PATH: product}).consts)

    def test_c9_an_edit_inside_a_multiline_carrier_makes_the_timeout_new(self):
        body = (
            "let h = tokio::spawn(async move {\n    run_within(&x, Duration::from_secs(30), f).await\n});\n"
            'timeout(Duration::from_secs(30), h).await.expect("w");'
        )
        text = test_file(body)
        self.refused(text, "run_within", added={line_of(text, "run_within(&x")})


class BudgetList(unittest.TestCase):
    """The whole-tree mode lists old sites of each shape, without failing."""

    def test_l1_one_named_and_one_value_equal_literal_are_listed(self):
        body = (
            'timeout(DRAIN + Duration::from_secs(10), rx.recv()).await.expect("w");\n'
            'timeout(Duration::from_secs(5), rx.recv()).await.expect("w");'
        )
        lines = listed(test_file(body))
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(any("named DRAIN" in line for line in lines), lines)
        self.assertTrue(any("equals SHORT in scope" in line for line in lines), lines)

    def test_l2_l3_a_coincidence_or_a_non_literal_is_not_listed(self):
        self.assertEqual(listed(test_file('timeout(Duration::from_secs(30), rx.recv()).await.expect("w");')), [])
        local = "const WAIT: Duration = Duration::from_secs(5);"
        self.assertEqual(listed(test_file('timeout(WAIT, rx.recv()).await.expect("w");', prelude=local)), [])

    def test_l4_a_product_code_assert_is_neither_refused_nor_listed(self):
        text = "fn product() {\n    let t = Instant::now();\n    assert!(t.elapsed() < DRAIN + Duration::from_secs(10));\n}\n"
        self.assertEqual(scan(text, path="src/y.rs"), [])
        self.assertEqual(listed(text, path="src/y.rs"), [])

    def test_l5_a_fully_qualified_literal_equal_to_a_budget_is_listed(self):
        body = 'timeout(std::time::Duration::from_secs(5), rx.recv()).await.expect("w");'
        self.assertTrue(any("equals SHORT in scope" in line for line in listed(test_file(body))))

    def test_l6_an_explicit_budget_site_is_listed(self):
        body = (
            "let h = tokio::spawn(async move { run_within(&x, Duration::from_secs(30), f).await });\n"
            'timeout(Duration::from_secs(30), h).await.expect("w");'
        )
        self.assertTrue(any("<= explicit budget passed to run_within" in line for line in listed(test_file(body))))


class Docstring(unittest.TestCase):
    def test_s1_the_limits_and_misses_are_stated(self):
        doc = " ".join(guard.__doc__.split())
        for phrase in (
            "reads Rust test code only",
            "scripts/ci/test_*.py",
            "a literal equal in value to a product budget",
            "two bindings up",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, doc)


def two_fns(a: str, b: str, prelude: str = "") -> str:
    return f"{prelude}\n#[tokio::test]\nasync fn a() {{\n{a}\n}}\n\n#[tokio::test]\nasync fn b() {{\n{b}\n}}\n"


def scan_lines(text: str, added: set[int]):
    return guard.scan_new(PATH, text, HANG, {}, added)


class VisibleBinding(unittest.TestCase):
    """A window is new through the binding visible at it, for every new-code rule."""

    def rules(self, text, *needles):
        return [f.rule for f in scan_lines(text, {line_of(text, n) for n in needles})]

    def test_b1_another_fns_same_named_let_does_not_make_a_window_new(self):
        text = two_fns('let wait = Duration::from_secs(5);\ntimeout(wait, rx.recv()).await.expect("a");', "let wait = Duration::from_secs(30);")
        self.assertEqual(self.rules(text, "let wait = Duration::from_secs(30)"), [])

    def test_b2_a_keyword_is_never_a_name(self):
        text = two_fns('timeout(Duration::from_secs(5), &mut child).await.expect("a");', "let mut y = 1;")
        self.assertEqual(self.rules(text, "let mut y"), [])

    def test_b3_b4_the_windows_own_binding_changing_makes_it_new(self):
        text = two_fns('let wait = Duration::from_secs(5);\ntimeout(wait, rx.recv()).await.expect("a");', "work();")
        self.assertIn(guard.FLOOR, self.rules(text, "let wait"))
        text = two_fns('timeout(WAIT, rx.recv()).await.expect("a");', "work();", prelude="const WAIT: Duration = Duration::from_secs(5);")
        self.assertIn(guard.FLOOR, self.rules(text, "const WAIT"))

    def test_b5_a_later_shadowing_let_is_not_the_visible_one(self):
        a = 'let wait = Duration::from_secs(5);\ntimeout(wait, rx.recv()).await.expect("a");\nlet wait = Duration::from_secs(30);'
        self.assertEqual(self.rules(two_fns(a, "work();"), "Duration::from_secs(30)"), [])

    def test_b6_a_let_in_a_closed_block_is_not_the_visible_one(self):
        a = '{\n    let wait = Duration::from_secs(30);\n    work(wait);\n}\nlet wait = Duration::from_secs(5);\ntimeout(wait, rx.recv()).await.expect("a");'
        self.assertEqual(self.rules(two_fns(a, "work();"), "Duration::from_secs(30)"), [])

    def test_b7_the_visible_let_changing_counts_beside_a_later_one(self):
        a = 'let wait = Duration::from_secs(5);\ntimeout(wait, rx.recv()).await.expect("a");\nlet wait = Duration::from_secs(30);'
        text = two_fns(a, "work();")
        self.assertIn(guard.FLOOR, self.rules(text, "Duration::from_secs(5)", "Duration::from_secs(30)"))

    def test_b8_an_inner_const_shadows_an_outer_let(self):
        a = 'let WAIT = Duration::from_secs(4);\n{\n    const WAIT: Duration = Duration::from_secs(5);\n    timeout(WAIT, rx.recv()).await.expect("a");\n}'
        self.assertIn(guard.FLOOR, self.rules(two_fns(a, "work();"), "const WAIT"))

    def test_b9_b10_a_setter_is_new_through_its_visible_binding_only(self):
        a = "let wait = Duration::from_millis(500);\nc.with_read_timeout(wait);"
        text = two_fns(a, "let wait = Duration::from_secs(30);")
        self.assertEqual(self.rules(text, "let wait = Duration::from_secs(30)"), [])
        self.assertIn(guard.SETTER, self.rules(text, "Duration::from_millis(500)"))
