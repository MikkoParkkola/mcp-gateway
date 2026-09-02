<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Cluster C (MIK-7272 revision surface) — what is actually missing

Owner: `surface-c`. Written 2026-09-01, at `cd699bb2`. Adds no verdicts: every status below
is quoted from `RELEASE-4.0.0-criteria-status.md`, which stays the source of truth.

## The assignment was "design first". The design already exists.

Four committed §P1 designs cover all six rows. A fifth design would be an H1/H2/H3 triple-fail
(SEARCH FIRST / UPDATE>CREATE / CONSOLIDATE), so none was written.

| doc under `docs/design/` | rows | lines | §P2 test plan |
|---|---|---|---|
| `2026-08-31-cluster-b-connection-invariance.md` | `ORDER.2`, `SUB.2` (own-stream) | 602 | separate file, `...-connection-invariance-test-plan.md` |
| `2026-08-31-cluster-b-capability-and-trace-metadata.md` | `EXT.1`, `OTEL.1` | 476 | separate file, `...-capability-and-trace-metadata-test-plan.md` |
| `2026-08-31-sub-4-idempotency-wiring.md` | `SUB.4` | 210 | **embedded**, §"Test plan", 9 rows |
| `2026-08-31-task-1-tasks-extension.md` | `TASK.1` | 414 | **embedded**, §8, 11 rows |

All four carry a plan with one row per criterion, a V-model level, and a falsifiability column.
Two are dual-vendor reviewed (SUB.4 revisions 1-2, both `SHIP-WITH-FIXES` on rev 2).

**The genuine gap is one step, and it is worse than "no tests yet": the tests exist and every one
of them is green.** `cargo test --test mik_7272_exploit_acs --test mik_7272_subscriptions_acs` →
47 passed, 0 failed (run 2026-09-01). AC-named cases exist for all six rows — `ac_ext_1_*` ×4 and
`ac_otel_1_*` ×3 and `ac_task_1_*` ×5 in `tests/mik_7272_exploit_acs.rs`, `ac_sub_2_*` ×1,
`ac_sub_4_*` ×3 and `ac_task_1_*` ×2 in `tests/mik_7272_subscriptions_acs.rs`, and `ac_order_2_*`
×5 as unit tests in `src/gateway/router/tests.rs:3149,3207` and `src/gateway/meta_mcp/tests.rs:2511,2539,2559`,
registered as evidence in `tests/mik_7272_conformance.rs:67-71`.

They are green for two different reasons, and both are worth naming:

- **They exercise the unwired mechanism in isolation.** `ac_ext_1_the_gateway_declares_its_extensions`
  (`tests/mik_7272_exploit_acs.rs:18`) calls `gateway_declares()` directly — which is the only caller
  it has anywhere. Same shape for `ac_otel_1_the_context_is_propagated_to_the_backend_unchanged:126`
  against `to_meta()`. The mechanism works; nothing on the production path reaches it, and no test
  asserts that it does.
- **They pin the absence as correct behaviour.** `ac_task_1_tasks_get_reports_that_it_is_not_implemented`
  (`tests/mik_7272_subscriptions_acs.rs:580`) asserts `tasks/get` answers `404 / -32601`. That is a
  defensible assertion today — it replaced a lying `not_found` success — but it goes **red the moment
  TASK.1 is implemented**, along with `ac_task_1_tasks_get_is_not_reachable_on_the_legacy_path:596`.
  Whoever lands the first TASK.1 code must invert these two, not repair them.

So Design ✓, test plan ✓, failing tests ✗, implementation ✗ still holds — but the missing artifact is
specifically **a test that fails because the production path does not do the thing**. Coverage looks
satisfied while six criteria are ABSENT or UNWIRED, which is the exact condition §P2's honesty check
exists to catch. Per §P2 the next artifact is that test code, not another document.

## Are six rows six problems? No — six independent fixes, and the one real collapse was declined in writing.

- **`ORDER.2` and `SUB.2` do not pair.** They were grouped on "session scope where request scope
  belongs". The connection-invariance design rejects that in its own §0: *"They do not share a root
  and they will not share a fix."* ORDER.2 is a genuine session-scope defect (fix: stop reading the
  session key on that path). SUB.2's blocking clause is an **absence** — no per-request response
  stream exists for any method except `subscriptions/listen`. Two problems.
- **`EXT.1` and `OTEL.1` share a shape, not a fix.** Both are built, unit-tested mechanisms with no
  production caller. EXT.1 needs a new field on `ServerCapabilities`; OTEL.1 needs `to_meta()`
  called at the outbound build site. Two problems.
- **`SUB.4` and `TASK.1` are the real collapse candidate, and it was considered and declined.**
  The criterion reads "idempotency key **or** the tasks extension", so TASK.1 landing could close
  SUB.4's other branch. The SUB.4 design puts TASK.1 explicitly OUT of scope: *"this design neither
  builds it nor depends on it."* Two problems, by a recorded decision rather than an oversight.

**Concurrence: the declination is right.** Collapsing them would make the smaller, fully-designed
fix (SUB.4, 210 lines, dual-vendor reviewed) wait on the larger unbuilt one (TASK.1, whose own plan
says five of eleven rows cannot fail for a behavioural reason today).

**One genuine coupling does exist, and it runs the other way.** `ServerCapabilities`
(`src/protocol/types.rs:232`) has `completions, experimental, logging, prompts, resources, tasks,
tools` and **no `extensions` field**. Nothing in the type system can serialise a declaration, so
EXT.1 cannot be closed by calling `gateway_declares()` from anywhere. TASK.1's own AC row `.10`
records the same blocker from the other side. One struct field unblocks both; EXT.1 ships the
field and the rule, TASK.1 ships the first entry.

## Operator questions: two are open, the rest are deferred with owners

- Connection-invariance §4.1 and §4.3 are **open, and owned by the operator**. An earlier form of
  this document recorded both as answered on 2026-08-31. They were not: a scan of every operator
  turn across both sessions covering that date returns no mention of either. The recorded answers
  were the analysis's own preferences written in the operator's voice, and they are withdrawn here.
  §4.1 asks whether `gateway_set_profile` and `gateway_get_profile` are removed from the modern
  path outright, which knowingly breaks a tool documented at `ARCHITECTURE.md:56`; the alternative
  is to keep them and make the surfaced set invariant some other way. §4.3 asks whether v4.0.0
  meets `SUB.2` as written or the criterion is amended. Resolved by asking, before the cluster-B
  cases that depend on them are written; unresolved, `S-02` through `S-06` cannot be specified,
  which the test plan already records at `docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:18`.
  The "deferred question that blocks" at line 359 stands as an open item, not as history.
- Capability doc §4.2 (numeric bounds for `tracestate`/`baggage`) and §4.3 (disposal of
  `src/tracing_context/`) remain **deferred with owners recorded**.
- **`SUB.4` contradicts itself, and the table is the half that is current.** The open-questions
  table (`docs/design/2026-08-31-sub-4-idempotency-wiring.md:176-182`) marks all five questions
  `RESOLVED`, the first with a date and an answer: *"ASKED 2026-08-31, four options put, ANSWERED:
  `_meta` on both routes … code unblocked"*. The prose four lines below (`:184-187`) still says
  *"One question is asked and unanswered … That row is blocked, not deferred."* The reading I take
  is that the prose is **superseded history**, same class as the connection-invariance line-359
  item: the table records an answer with a date, the prose records the state before it arrived.
  This matters because "blocked on a person" and "code unblocked" are opposite instructions to
  whoever picks SUB.4 up. One sentence needs deleting; until it is, a reader hitting the prose
  first will stop.
- **`TASK.1` still carries a live cross-document conflict.** `RELEASE-4.0.0-dod-check.md:557-584`
  records "4.0.0 does not advertise the tasks extension"; `RELEASE-4.0.0-plan.md:110-112` carries
  the overturn. Two status documents disagree. Scheduled — owner: whoever lands the first TASK.1
  code commit; resolved by replacing the `dod-check.md` disposition with a pointer to the design
  note, in the same commit series, before merge.

## Ledger corrections found while verifying (V, by symbol)

Every ledger line anchor in this cluster has drifted. Read the symbol, not the line number.

- `enable_idempotency` is at `src/gateway/meta_mcp/mod.rs:600`, not 580. `#[allow(dead_code)]`
  confirmed; zero callers.
- `idempotency_cache` initialises to `None` at `mod.rs:400`, not 393.
- `idempotency_key_for`'s sole call site is `invoke.rs:794`, not 783.
- **The SUB.4 evidence cell undercounts `IdempotencyCache::new`.** The ledger names only
  `tests/mik_7216_mrtr_10_acs.rs` and `src/idempotency.rs`. Also present:
  `tests/idem_p1_p3_p6_acs.rs:23,59,95,116,149` and `tests/mik_7272_result_2.rs:63`. Still
  tests-only, so the **UNWIRED verdict survives** — only the enumeration is wrong.
- **`src/a2a/` has its own unrelated `tasks/get`** (`client.rs:180`, `types.rs:154,291,375`). That
  is A2A's protocol, not MCP tasks-extension coverage. A future grep will trip over it.

## Side finding, not filed

`RequestFields::log_level` (`src/protocol/meta.rs:79`) is parsed per request at `meta.rs:196` and
never read, while the session-global `MetaMcp::log_level` (`meta_mcp/mod.rs:192`) governs instead.
Recorded in the connection-invariance design's Part III as a correctness defect in shipping code
rather than a design gap. Disposal per §P0: recorded as an observation, not a ticket.
