# Cluster A — does every blocking row have a component test, and can each named test fail?

Audit only. It writes no test, decides no gap, and touches nothing under `src/`.
Read against `docs/design/2026-09-02-mrtr-test-plan.md` (the plan, which assigns each
row its level) and `tests/mik_7212_mrtr_component_acs.rs` (the component batch).

**Observed at `9b0643d4`.** No commit has touched `src/` or `tests/` between that
revision and `b35b744f`; the commits since are documentation. The working tree
*currently* carries uncommitted edits under `src/gateway/` belonging to another
session — `handlers.rs` +12 and `meta_mcp/tests.rs` +71. Nothing here was observed
against those edits and nothing here touches them.

## The row set reconciles

The rollup counts 22 blocking rows in cluster A. The MRTR table contributes 17
(`1a`,`1b`,`3a`,`3b`,`4a`,`4b`,`5a`-`5d`,`6`,`7a`,`7b`,`8a`,`8b`,`9a`,`10a`); the
remaining five are `NFR.SEC.2/3/4`, `NFR.OBS.4`, `NFR.PERF.3`, which sit outside this
map. Derived from the table's own `blocking` column, not from `status != MET`, and the
two rules agree. A first pass read `7a` and `7b` as carrying a conditional flag,
`retry_params` rather than `yes`; that was a parsing artifact. Their evidence cells
quote an `rg` pattern containing escaped pipes (`"to_legacy_client\ | retry_params\ |
…"`, `docs/requirements/RELEASE-4.0.0-criteria-status.md:123-124`), which shifts the
column count by two. Both rows read `blocking = yes`, and the MRTR.7 parent row in
`docs/requirements/audit-notes/criteria-mrtr.md:9` reads `Yes` independently. There is
no conditional: all seventeen are unconditionally blocking.

## The matrix

A row is **covered** when a test exists at the level the plan assigns it. A test at a
*lower* level than the plan asks for is recorded as a gap, because that is precisely
the substitution the plan's own self-QA section rejected.

| row | plan level | test | verdict |
|---|---|---|---|
| 1a, 1b | component | `ac_mrtr_1_a_retry_reaches_the_backend_carrying_what_it_continued` | covered — one table-driven case asserts **both** fields, parameterised over `with_state`, so the pair is not half-covered |
| 3a | unit + component | `ac_mrtr_3_every_forged_presentation_is_refused_by_the_continuation_guard` + the genuine-handle control | covered by inference: "verified before use" is read off the pair (forgeries refused, genuine accepted), never asserted directly. Sound, and worth knowing it is indirect |
| 3b | unit + component | same | covered |
| 4a, 4b | component | `..._one_principal_is_refused_for_another`, `..._one_tool_is_refused_for_another` | covered |
| 5a, 5b, 5c | component | `ac_mrtr_5a/5b/5c_*` | covered |
| 5d | **integration** | `ac_mrtr_5d_a_handle_minted_by_another_process_is_refused` | **level mismatch.** The plan puts 5d at integration and says why: single-use must hold across replicas. The test runs in one process against a foreign-key envelope, and its own doc comment concedes the proxy — a refusal for the same reason a tampered handle is refused, not evidence of cross-replica enforcement |
| 6 | **integration** | none in the component batch. Four `ac_mrtr_6_*` cases live in `tests/mik_7212_acs.rs` (`:400`, `:408`, `:427`, `:473`) at unit | **gap at the assigned level, and worse — see below.** One of the four asserts the mechanism the plan says we do not deploy |
| 7a, 7b | component | none in the component batch. Seven `ac_mrtr_7_*` cases in `tests/mik_7212_acs.rs` (`:516`-`:637`) at unit | **gap at the assigned level.** Unconditionally blocking; the `retry_params` reading was a parsing artifact, corrected above |
| 8a | component | `ac_mrtr_8_an_exchange_the_gateway_opened_occupies_a_slot` — red | covered |
| 8b | component | `ac_mrtr_8_a_call_that_finished_holds_no_slot` — green | **partial.** 8b is *bounded in lifetime **and** reclaimed on abandonment*. A call that finished is not a call that was abandoned. The reclamation half is held only at `tests/mik_7212_acs.rs:457`, against the type; at component level it is unproved |
| 9a | component, at the wire | **none anywhere.** The `ac_mrtr_9_*` cases all test the declared *type*; nothing drives a *mode* | **hard gap.** The plan records that 9a's exemption "did not survive", so a test is owed by the plan's own finding |
| 10a | unit | `ac_mrtr_10_different_answers_derive_different_keys`, `..._different_backend_state_derives_a_different_key`, `..._the_two_fields_cannot_be_transposed` | covered at the level the plan assigns |

Three tests in the component batch prove no row and are not counted as coverage —
`production_still_raises_the_retry_unavailable_sentence`,
`fixture_control_a_fresh_call_reaches_the_backend`, and the two negative controls
`ac_mrtr_4_the_handle_it_was_minted_for_is_not_refused` and
`ac_mrtr_3_a_genuine_handle_is_still_accepted`. All four are labelled as controls in
the file. A fifth, `ac_mrtr_2_the_backends_own_state_is_never_relayed_to_the_client`,
covers `2a`/`2b`, which are **MET and non-blocking** — the plan asks for it as the
anti-passthrough negative, so this is deliberate, not a misspent case.

## Can the three green tests fail?

The batch is a tests-first specification: twelve red is the specification, not breakage.
Three are green, and green is where a test plan hides its vacuity.

**`fixture_control_a_fresh_call_reaches_the_backend` — falsifiable, by construction.**
The recorder starts empty and the assertion is `assert_eq!(calls.len(), 1)`; a gateway
that routes nowhere records zero and the control goes red. `register_fixture_backend`
carries its own `assert!` that registration took (`:509`), so the control cannot pass
by silently failing to register. Conclusive from reading; no probe needed. This
matters beyond its own row — every "the backend received nothing" assertion in the file
rests on it.

**`production_still_raises_the_retry_unavailable_sentence` — falsifiable, and it
expires.** It greps `src/gateway/router/handlers.rs` through `include_str!` for the
literal `retry forwarding is not available`, and exists because
`assert_not_refused_by_the_continuation_guard` *negates* that literal: reword the
production sentence and the negation silently becomes true. That is a real defect class
and this catches it. But note what it is: a source-text canary, not a behavioural test,
and **the implementation this batch specifies deletes the sentence it pins.** It turns
red the moment MRTR.1 lands. That is the correct signal — someone must then re-point
both the constant and the negation — provided nobody reads the red as breakage and
deletes the canary along with the guard it protects. Worth stating in the plan, because
neither "already true" nor "staged" describes it.

**`ac_mrtr_8_a_call_that_finished_holds_no_slot` — green in a world where no slot can
exist.** Its sibling `..._occupies_a_slot` is red because nothing in `src/` calls
`InFlight::hold`, so the table is never written. This test asserts the table holds
zero. It would hold zero with the call deleted. The doc comment concedes exactly this
("Green today, and for the same reason everything about this table is green today —
nothing is ever written to it") and states what it earns once the table is wired: it
refuses an implementation that holds a slot for *every* call. So the test is honest and
correctly staged, and its green is not a false claim. The consequence is still worth
naming plainly: **8b's component evidence is currently zero, and the only green test
carrying an 8b name is the reason that is easy to miss.**

## What this audit does not decide

Which of `5d`, `6`, `7a`, `7b`, `8b`-reclamation and `9a` are real gaps and which the
design intends to prove elsewhere. `9a` is the one with no test at any level; the other
five each have a test somewhere, at a level below the one the plan assigns.

One thing worth weighing alongside that decision: the test plan itself carries a single
vendor verdict. Its second leg failed with `API error (status 402 Payment Required):
Grok Build usage balance exhausted`, so the dual gate on the plan is open by the plan's
own admission. That does not touch the row 6 finding, which now rests on the design doc
at source rather than on the plan's matrix cell — but every *level assignment* in the
matrix above comes from a plan one reviewer never saw.

## Row 6's existing test asserts the design that was rejected

The plan's review section records that MRTR.5's draft fixture assumed two replicas over a
shared store, that the accepted design says the opposite in terms — key material is per
process and never shared — and that **"MRTR.6 carried the same assumption and is
corrected the same way"**: refusal, not routing. The plan's matrix cell for row 6 now
reads *the accepted design refuses rather than routes*.

`tests/mik_7212_acs.rs:408`, `ac_mrtr_6_a_retry_landing_elsewhere_is_sent_to_the_holder`,
asserts `Routing::Elsewhere { replica: "gw-1" }` — that a retry arriving at the wrong
replica is **routed to the holder**. Its comment defends the routing on its merits. That
is the corrected-away mechanism, still asserted, still green.

The accepted design forecloses routing at source, not only key-sharing, and the two are
separable enough to be worth checking: a per-process key makes a foreign envelope
unreadable, which is a reason routing is *pointless*, not by itself a decision not to
route. `docs/design/2026-08-30-shared-continuation-state.md:116` closes that gap in the
sentence itself — MRTR.5's cross-replica clause holds "cryptographically, with no shared
store, no new dependency and **no affinity**". Affinity is the mechanism `Routing::Elsewhere`
implements, and it is named as a thing the design does without. `:103-104` then records
the operational consequence the design accepts in its place: a client retrying against a
round-robin service "is refused on every replica but the minting one, so a retry is a
coin flip rather than a rare miss". Refusal, written down as the cost, is what routing
would have avoided had it been kept.

This is the same defect the plan caught in the MRTR.5 draft and states the cost of: a
test that passes against a design nobody agreed to build, whose passing is evidence of
nothing. It was caught there because the row was being written; row 6's cases already
existed and were never re-read against the correction. `Routing::Elsewhere` is a
production variant, so the divergence is not confined to the test — but what happens to
either is a decision, not an audit finding, and nothing here touches `src/`.
