<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Family-fix perf-per-call (MIK-8014)

Status: closed at r5 after review (lead stop rule), 2026-10-09. Tickets: MIK-8014 (family fix), MIK-8060 (merged in #3573), MIK-7799, MIK-7536. Implemented in two PRs: argument copies (A), then the per-call timing gate (B).

## Cause (one rule applied in N places)
4.0 adds per-call bookkeeping on the HTTP `tools/call` path in separate layers, each doing its own copies and
wrappers, and nothing in CI measures per-call cost, so each feature's cost lands unseen. Evidence: caller-graph
run 37736492879, CPU/call v3.5.1 305 µs vs head 377 µs (+72); own-code +52 µs over ~30 fns; the largest coherent
block is the stacked dispatch wrappers (~16 µs self). MIK-8060 is the same rule in another place (in-flight table
walked per call under a lock; fixed in #3573, 141 ns vs 6.36 µs).

## Members
MIK-8014 (fix), MIK-8060 (#3573, staged), MIK-7799 (tenant_read record folded per call), MIK-7536 (NFR outcome;
closes only by a graded run on bench-host). Re-tag proposed: MIK-7931 -> release-measurement.

## Change (pure overhead only; audit, accounting and error shape unchanged)
1. Tool arguments deep-copied 3-4 times per call: `helpers.rs:242` (extract_tools_call_params), `meta_mcp_helpers.rs:662`
 (parse_tool_arguments), `invoke.rs:475`, `relay.rs:107` (relay egress, when active). Pass `&Value` down; clone once
 where the outgoing message is built. `invoke.rs:585,624,684` read arguments after dispatch: keep a borrow.
2. `dispatch_below_gate` (`call_dispatch.rs:292-311`) is a pass-through layer: call `dispatch_below_gate_shaped` directly.
3. Grant-slot wrapper on HTTP (`grant_audit.rs:585-589`, `:478`): the slot is already open from `handlers.rs:466-480`;
 skip the second box and id clone when `GRANT_SLOT.try_with` sees an open slot (keep it for the task-worker path,
 `watch_poll.rs:100`).
4. `caller_key` built up to 3x and `lifecycle.track` twice in the handler (`handlers.rs:1393/1406` inside the target loop,
 `:1598/1606`): compute once; keep the empty-key session fallback.
5. Small strings rebuilt per call: `server:tool` formatted twice (`invoke.rs:222,320`), metric labels copy `server`
 twice (`dispatch.rs:142,148`), tool name copied and re-extracted (`handlers.rs:1034,1262`), trace id cloned
 (`policy.rs:240`; `TRACE_ID` as `Arc<str>`).
6. MIK-7799: fold the tenant_read record into the delivery record (ticket's own design, lead ruling 2026-10-05).

## Gate (the part that stops new members)
Criterion bench `dispatch/tools_call_meta` driving `meta_mcp_dispatch` for one `gateway_invoke` against an in-process
backend (no network), plus the existing `continuation/inflight_route_full`. A CI job runs base and head on one runner
(same-run A/B, as #3573's bench did) and fails when head exceeds base by more than a budget (proposed: 5% or 2 µs,
whichever is larger) on any row. One row per stage enumerated in a table, so a new per-call stage adds a row or fails.

## Tests
- Behaviour: existing dispatch, audit and accounting suites stay green (no expected-output changes).
- Red rows: an allocation-count row (`alloc_count_patch.py` exists in the perf-prof harness) asserting the argument
 `Value` is deep-copied at most once per call — red today (3-4 copies).
- The gate's own negative control: a deliberately slowed stage makes the job fail (shown once, then removed).

## Open questions for review
- Budget numbers and runner noise: a shared CI host is not a benchmark host; the gate compares same-run arms only.
- Whether 4 (caller_key once) holds: `control_identity(k, ..) == k` for a non-empty key is inferred, not read.

## r2: gate rules (lead ruling) and coordination (2026-10-09)
- Gate, replacing the 5%/2 µs sketch above:
 - Paired and interleaved on ONE runner: base and head builds alternate in blocks (ABAB...), so host drift hits both arms equally.
 - Variance check first. If either arm's run-to-run spread exceeds the budget, the job reports VOID (rerun), never FAIL. A shared CI host is not a benchmark host.
 - The budget is sized from measured spread, not picked: run base against base (an A/A null arm) N times on the CI runner class. The budget is the largest per-row difference the null arm produces, plus margin. The null arm stays in the job as a negative control; if it "fails", the run is VOID.
 - FAIL only when the paired head-minus-base difference exceeds the budget AND the null arm is within it.
- Rows: one per per-call stage enumerated in a table, so a new stage either adds a row or fails the enumeration check. Plus continuation/inflight_route_full (#3573).
- Coordination: splitlane's MIK-8143 step B moves meta_mcp_dispatch's body into handlers/dispatch_*.rs. 8014's in-body edits (caller_key once, the tool-name copy) land after that, in dispatch_tools_call.rs. The wrapper-chain edits (call_dispatch.rs, grant_audit.rs) do not collide.
- Seats: seat 1 + seat 2 (lead ruling), after this r2.

## r3 amendments ( SHIP-WITH-FIXES; seat 2 pending)
- H1 HIGH (some branches parse stringified-JSON arguments or mutate them before hashing, so "borrow until one clone" is wrong there). Arguments travel as `Cow<'_, Value>`: borrowed on read-only branches; owned exactly where a branch parses a string argument or mutates (those sites are enumerated in the PR with file:line). The row asserts at most one deep copy on the read-only path and is exempt on the enumerated mutating paths; a behavioural row per exception pins the hashed and forwarded value.
- M2 (benchmarking `meta_mcp_dispatch` directly skips the HTTP grant-slot opener). The bench drives the full HTTP handler stack in-process (the router via `tower::ServiceExt::oneshot`, slot opener included), so the open-slot fast path is what gets measured.
- M3 (the max A/A difference has no defined false-alarm rate). Run K A/A pairs per row; the budget is the largest of them, giving a false-alarm rate of about 1/(K+1) (K = 19 → 5%). The job also prints each row's minimum detectable effect (that budget), so sensitivity is visible, not assumed.
- M4 (fixed ABAB confounds arm with order). Counterbalanced ABBA blocks, with the starting arm seeded per run and printed.
- M5 (VOID behaviour unspecified). VOID reruns automatically up to twice. Three VOIDs in a row FAIL with "gate inconclusive", which needs a lead waiver, so noise can never pass silently.
- M6 (the response cache can short-circuit repeated identical calls). The bench config disables the response cache, and each sample asserts the backend dispatch counter moved by exactly one.
- M7 (alloc_count_patch.py counts process-wide). The deep-copy row uses a large argument (1 MiB) and asserts bytes allocated per call below 2x its size inside a thread-scoped counting window: a deep copy is visible as a whole extra argument-size block.
- Improvements taken: a behavioural witness for the open-slot fast path (the audit record and accounting are identical with and without it); attribution by single-change ablations, each measured alone, with a deliberately slowed stage kept as the gate's negative control.
- WHERE THE GATE RUNS (lead ruling; supersedes "a CI job" above): shared CI runners are not benchmark hosts (6 runners on 20 CPUs voided a past bench). The timing gate (paired ABBA, A/A null arm, VOID/FAIL rules) runs on the bench host via `spark-run --bg`, with no other bench running at the same time (checked at start; VOID if one appears). CI checks only that the bench builds and that the allocation counter works (the deep-copy row, which counts bytes, not time).

## r4 amendments ( SHIP-WITH-FIXES; FINAL design round under the stop rule)
- K-H1 (a noisy run PASSes blind). Each row has an absolute sensitivity ceiling: if its budget (the minimum detectable effect from the A/A arm) exceeds 4 µs (a quarter of the 16 µs wrapper class this family exists to stop), the run is VOID for that row, never PASS.
- K-H2 (the exempt mutating paths ARE the gateway_invoke hot path). No exemption. The copy row covers the hot path with an exact bound per path: read-only paths at most 1 deep copy; paths that strip `_full`/`_claim` or inject at most 2 (one owned working value, one outgoing). Today they make 3-4, so the row is red now.
- K-H3 (exclusivity checked only at start). The whole the bench host job runs under one bench lock on the bench host. Every bench in this family takes the same lock, so two cannot overlap.
- K-H4 (false-alarm rate is per row, the job fails on any row). A row over budget triggers one confirmation run, and the job FAILs only if the same row is over budget again. Family-wise rate is about R/(K+1)^2 for R rows (K = 19, R = 8: about 2%). Both numbers are printed.
- K-H5 (a thread-scoped allocation window is unsound on a work-stealing runtime). The copy row runs on a dedicated `current_thread` runtime and measures a slope, not a total: the same call with a 1 MiB argument and with a 1 KiB argument. (bytes difference) / (argument size difference) is the number of deep copies, and fixed costs such as body parsing cancel.
- K-M6 (no artifact enforces "one row per stage"). A `STAGES` table in the bench file plus `scripts/ci/check_per_call_stages.py`. Any new function on the tools/call wrapper path (handlers dispatch_tools_call.rs after MIK-8143, grant_audit.rs, call_dispatch.rs, invoke/dispatch.rs, invoke.rs) must be in `STAGES` or in an allowlist with a reason, in the same shape as the COV.3 inventory check.
- K-M7 (a kept negative control sits on both arms and cannot fail). The slowed stage is behind a `bench-negative-control` cargo feature, built only as a third arm. Every run expects that arm to FAIL, so a run where it doesn't is VOID: the gate checks itself.
- Improvements, all taken: reuse the existing `extract_tools_call_params_ref` / `merge_client_meta_ref` Cow helpers (no second Cow type); `control_identity` returns a non-empty key unchanged, so one `caller_key` is computed and shared (the open question is closed); reuse `tool_key` (invoke.rs:223) at the idempotency fingerprint (:322) and pass `&str` to the metric macros (dispatch.rs:142,148); publish the single-change ablation table from the bench host as PR evidence, with MIK-7799 included.
- Reuse (found after r4, no design change): K-H5's copy row is built on the existing `src/gateway/server/tests/alloc_meter.rs` (a cfg(test) global allocator that counts on one thread while a scope is open; inactive cost is one thread-local bool) with `measure_async`, plus `signing_nonce_allocations_support::isolate`, which re-runs the test alone in a child process on a current-thread runtime. `input_key_allocations.rs` (#613) is the differential pattern: the same call with a tiny and a 64 KiB input, where a clone shows as the size difference. No new allocator or harness.

## r5 (narrow delta : 2 HIGH reopened per lead rule; MEDIUM recorded)
- D-H1 (a borrowed `&str` for metric labels cannot compile: metrics 0.24.6 requires owned, shared or 'static label values). That improvement is WITHDRAWN. Metric labels stay as they are. Removing a per-call string copy there is not worth a second label type.
- D-H2 (bytes measure size-dependent allocation, not copy count; a cloned numeric array takes far more heap than its serialised size). The copy row calibrates its own unit and uses an argument whose clone cost is predictable:
 - The argument is ONE large string field (1 MiB vs 1 KiB), so its heap size tracks its length.
 - In the same isolated child, the row first measures one explicit `arguments.clone` of each size. The copy count is then (dispatch bytes large − small) / (clone bytes large − small), rounded, and asserted against the per-path bounds (≤1 read-only, ≤2 strip/inject).
 - A numeric-array witness asserts the same COUNT, not the same bytes.
- D-M3 recorded, not re-rounded: the ~2% family-wise false-alarm figure assumes independent exceedances. To reduce shared-calibration dependence, the confirmation run recalibrates its own A/A arm (a fresh null), and the printed figure is labelled an approximation under that assumption.
- Improvement taken: check_per_call_stages.py also verifies that every `STAGES` entry maps to a bench row that executed in the run (a stage with no measured row fails the check).
- CLOSED at r5 (lead ruling). PR requirement: the copy row's self-calibrated count (Δdispatch / Δclone) must be shown reporting 3-4 copies on today's code (red on base) before the fix lands, so the formula is proven against the real cost, not only against the bound.
