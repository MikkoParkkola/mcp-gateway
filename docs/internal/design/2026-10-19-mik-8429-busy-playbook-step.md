# MIK-8429: a playbook step that failed is recorded as completed

Status: P1a ratified (round 4, merged scope). P1b under review.
Family: busy-settlement (MIK-8430, not merged). MIK-8329 (playbook-error-
semantics) was merged into this ticket by the lead on 2026-10-19 23:45 UTC,
after rounds 1-2 of this note were written; rounds 1-2 reviewed the narrower
Busy-only scope.
Base: origin/docs/ranking-1-release-line at b51f53140.

## P1a: problem

### What goes wrong, for whom

Root cause (merged scope): the playbook step loop
(`src/playbook/engine/mod.rs`, `execute_definition` and `dispatch`) matches
only `Ok`/`Err` from the invoker. MCP tools report failure in the success
channel (`{"isError": true, ..}`), and the gateway folds its own dispatch
errors into that shape too (`invoke/errors.rs` `dispatch_error_result`). Such
a step is recorded completed, `on_error` is never consulted, and successors
run and may interpolate the error payload as data. The lead's decision
(MIK-8429 merged scope, PBERR): in 4.0.0 an `isError` result is a failed step
that follows `on_error`; an UPGRADING note tells operators who relied on "a
result is a result".

The transient custody Busy is the sharpest instance:

A playbook (`gateway_run_playbook`) runs its steps through the ordinary
`MetaMcp::invoke_tool` (`src/gateway/meta_mcp/playbook_invoker.rs`, `invoke`).
When a step's managed account custody is busy (a held custody lock, a
transient state; `CustodyError::Busy` mapped to `MintError::Busy`), the gateway
builds one sealed retryable error, `refusal::transient_retry_error`
(`src/personal_accounts/refusal.rs:146`): -32603, "temporarily unavailable,
retry", `data.retryable`, sealed so only a gateway-built one is read as such.
By construction it is built only where nothing has reached the backend yet
(the PRE-SEND list in its doc comment, held by `error_pre_send_scan_tests`).

On route 1 below a direct call answers that error and the client retries
(rows P8406u, R1, R8 pin it). A playbook step loses it on two routes, both
confirmed by the red rows on b51f53140:

1. **Caller view / mint Busy** (`invoke.rs:228-236`, `caller_verdict.rs:286`):
   `invoke_tool` returns `Err(sealed transient)`. The engine
   (`src/playbook/engine/mod.rs`, `dispatch` and the step loop) treats it as
   any error: `retry` re-sends it at once up to `max_retries`; `continue` and
   `retry` then record the step failed, null-fill its result and start the
   next step. Only `abort` ends the plan.
2. **In-backend lease recheck Busy** (`CapabilityBackend` /
   executor / `inject_auth` rechecks): the error comes back from dispatch,
   `settle_dispatch_error` releases the key (pre-dispatch) and returns
   `Ok(dispatch_error_result(..))` (`invoke/post_dispatch.rs:139`), an
   `isError` tool value (for a direct call too; see Exclusions). Up to that
   line the typed error `e` is still in hand; only the returned value loses
   it, so treating `isError` as a failure in the step loop alone cannot tell
   this Busy from any tool error: the type must survive to the engine. The engine never reads `isError`, so the step is
   recorded **completed** under every policy, `abort` included, its error
   value becomes the step's result, and successors interpolate it as data.

Who feels it: any operator or agent whose playbook step's tool fails (an
`isError` result: a vendor 4xx/5xx through a capability, an MCP tool error,
a gateway dispatch error), and most sharply one running over a managed
account while its custody is briefly busy. The plan answers a result that
reads as success or partial success; successors ran on a step that never
reached its vendor. A client cannot tell it should simply retry.

### Why now

Lead triage 2026-10-19 moved it into v4.0.0 (class B2: wrong result). The
retryable Busy contract was added in this release line (MIK-8392 Busy parity,
MIK-8428); playbooks are the one plan surface that drops it
(`gateway_execute` chains already stop their successors on both an `Err` and
an `isError` step, `search/chain_exec.rs:250-255`; a plain chain's wrapper
does drop the sealed retry data, so chains are cited for stopping only).

### Measured constraints

C1, C1b, C2 are code facts; C3, C4, C4b are the ticket's ACs and the lead's
merged-scope decision (MIK-8429, 2026-10-19); C5 is the lead's lane
assignment for this release.

- C1. The sealed transient is pre-send by construction; `Error::is_pre_dispatch`
  reads its seal (`src/error.rs:412`). Any layer reading the plan's final error
  as unsent may free a key or a nonce. After an earlier step completed, the
  plan as a whole is not unsent.
- C2. Two separate settlements guard a partial run. The signing nonce is
  refunded only if a step asked and no step dispatched: a sticky flag set by
  `nonce_settle::mark_dispatched` (`nonce_settle.rs:70`, `signing.rs:136,178`),
  which nothing clears. The outer execution lease counts dispatches
  (`admission.rs:60-75`): `withdraw_dispatch` undoes only the current step's
  mark and keeps an earlier step's. So an earlier step's send keeps both the
  nonce and the outer key protected; the residual exposure is the plan's
  final error reading as unsent (C1) on the wire and to any reader of
  `is_pre_dispatch`.
- C3. Ticket AC STEP.3 (ratified with the ticket, not a design choice here): no new public `Error` variant or trait; Busy recognised from the
  seal (its type marker), never from message text. A same-text unsealed error
  is an ordinary error.
- C4. Ordinary step errors (`Err`, not the sealed transient) keep today's
  handling (STEP.2): `Forbidden` and `ResponseFirewallRefused` are terminal,
  every other `Err` is retried under `retry` (some of those follow a send,
  e.g. a post-response screening refusal raised as `Error::JsonRpc`). An
  `isError` result changes from "completed" to "failed, following
  `on_error`" (PBERR.1, the lead's decision). The NEW exposure is retrying
  `isError` results: most dispatch failures after a send are folded into
  `Ok(isError)` (`settle_dispatch_error`), so under `retry` an unkeyed
  playbook will now re-send a step whose tool failed, which can repeat a
  vendor side effect. A keyed run should replay the step's stored failure
  instead (the step key is scoped per step and the failure is committed after
  the fold): inferred, pinned by a row. The UPGRADING note says both.
  **Superseded by the operator hold (D1, last section): an `isError` step is
  never re-sent, keyed or not; this exposure no longer exists.**
- C4b. (Derived reading; approved by the lead 2026-10-19, and the ticket's
  PBERR.1 text now says STEP.1 narrows it.) PBERR.1 says a Busy
  "fails the step retryably"; STEP.1 says it "ends the plan as a retryable
  failure: no null fill, no successor" for a step that meets it "before any
  vendor send". Read together: a Busy step fails and the plan ends there
  under every policy, `continue` included. The answer is the retryable error
  only when no earlier attempt in the plan produced an outcome other than the
  sealed transient; otherwise it is non-retryable (C1, C1b). The engine
  cannot see whether an earlier attempt actually dispatched, so any
  non-Busy outcome counts (a pre-send refusal included): a conservative
  over-approximation that can only withhold a retry label, never grant a
  wrong one. STEP.1 is the stricter and governs.
- C1b. "Before any vendor send" is per plan, not per step: an earlier
  attempt of the same step (under `retry`) or an earlier step may already
  have reached a backend.
- C5. Lane boundaries: `invoke.rs` belongs to decomp-8488 this week; edits there
  need the lead first.

### Acceptance signal (from the ticket, merged)

- PBERR.1: an `isError` step result is a failed step under every `on_error`
  (abort stops; continue null-fills with its reason in `step_errors` and runs
  the successor; retry re-invokes up to `max_retries`, then as continue),
  each with a red-first row; a Busy fails the step retryably (C4b).
  **Superseded for retry by the operator hold (D1): an `isError` step is not
  re-invoked; under retry it is handled as under continue after one call.**
- PBERR.2: the UPGRADING note names the change for existing playbooks
  (after the hold: that `retry` does not re-send a tool-reported error).
- After the hold (D1): a `retry` step whose tool answers `isError` reaches the
  vendor once, keyed or not (row).
- A completed step's gateway write notes are still carried onto the
  playbook's answer when another step, or an earlier attempt, failed with
  `isError`; notes of failed attempts are discarded (row).
- An `isError` attempt followed by a successful retry records the step
  completed with the retry's result (row).

- STEP.1: a step whose dispatch meets a transient custody Busy before any vendor
  send ends the plan as a retryable failure: no null fill, no successor step
  starts. Red first.
- STEP.2: ordinary step errors keep Abort/Continue/Retry. Negative control.
- STEP.3: as C3.

Also observable: a Busy step after an earlier step that may have reached its
backend (completed, or failed after its send) ends the plan with an error
that does not read as unsent (`is_pre_dispatch()` false, no retryable data).

Observable, for a Busy on the plan's first attempted step:
`gateway_run_playbook` answers JSON-RPC -32603 with `data.retryable: true`
(and `retry_after_ms` when the sealed error carries one); the successor's custody lookups and the vendor's
request count do not move. A vendor 400 inside a step (an `isError` result)
is a failed step under its policy (PBERR.1); an unsealed look-alike `Err`
keeps today's handling (STEP.2/STEP.3).

### Exclusions

- MIK-8430 (listing `NoView` marker on busy custody): different mechanism.
- The direct `gateway_invoke` answer for an in-backend recheck Busy (inferred
  from the same `post_dispatch.rs:139` read to be an `isError` value, not the
  retryable error; no row asserts its shape today): a separate parity
  question, noted for the lead, not changed here.
- Busy nested inside a `gateway_execute` chain run as a playbook step.

### P1a ratified, round 4 (merged scope)

gpt SHIP-WITH-FIXES (gpt-20261019T002036Z-41952) and agy SHIP-WITH-FIXES
(agy-20261019T002037Z-41953). Fixes applied above: C4 history corrected (no
blanket "never re-sent"; terminal refusals named); C4b labelled derived, with
the conservative "attempted" rule stated; write-note discard and
retry-then-success rows added to the acceptance signal; the keyed-retry
replay goes in UPGRADING once its row confirms it.

### P1a review dispositions, round 3 (merged scope)

gpt SHIP (gpt-20261019T001315Z-47522): same-step isError-then-Busy row
(added); UPGRADING on unkeyed re-sends (added to PBERR.2); write-attribution
row (added); permalinks: the lead's decision is the MIK-8429 description's
"Merged scope" block and its 2026-10-18T23:45 comment.
agy DO-NOT-SHIP (agy-20261019T001315Z-47524): C4b pre-send boundary
(accepted, reworded); C4 "today's exposure" (accepted: the claim was wrong,
rewritten as new exposure); route 2 needs the typed error (accepted,
stated); post-send Busy under `continue` (accepted: ends the plan,
non-retryable). Suggestions to gate `isError` retries on recovery hints:
declined, the hint is classified from detail text (`classify_from_detail`),
and the lead ruled "follow on_error"; the exposure is documented instead.
Shared chain/playbook helper: the predicate is shared in spirit (same
`isError == true` rule); the two engines' error shapes differ, not merged.

### P1a review dispositions (rounds 1-2, narrower scope)

Round 2: agy SHIP (agy-20261019T000546Z-20118); gpt SHIP-WITH-FIXES
(gpt-20261019T000545Z-20115): same-step earlier attempt (C1b, applied);
merged scope (this rewrite); router-level keyed partial-run evidence (added
to the acceptance rows).

### Round 1

gpt SHIP-WITH-FIXES (gpt-20261019T000136Z-96163): C2 corrected (separate nonce
flag), partial-run signal added (earlier failed step included), chain cited
for successor stopping only, constraint provenance stated. All applied.

agy DO-NOT-SHIP (agy-20261019T000137Z-96529):
- "Route 2 cannot be resolved without text": disputed. `settle_dispatch_error`
  (`post_dispatch.rs:75-140`) holds the typed `e` until its last line; the
  seal is readable there, and that file is not `invoke.rs` (C5).
- "Direct calls answer the sealed error on route 2": accepted as wording;
  the claim now covers route 1 only and route 2's direct shape is excluded.
- "Retryable after an earlier dispatch violates C1": accepted; the
  acceptance signal now splits first-attempted-step and partial-run cases.
- "C3 smuggles design": disputed; it is the ticket's AC STEP.3.
- Backoff guidance: the sealed error's `retry_after_ms` passes through unchanged.
- Shared step-result helper across chain and playbook: MIK-8329's scope.

## P1b: solution (merged scope)

### Chosen

One predicate for the Busy, "this error is the gateway-sealed transient",
`refusal::transient_data(&e).is_some()` (the check `Error::is_pre_dispatch`
uses); one predicate for a tool error, `result["isError"] == true` (a JSON
boolean; the predicate `chain_exec::chain_step_result` already applies). No
new `Error` variant or trait (STEP.3).

1. **Engine** (`src/playbook/engine/mod.rs`), the step's outcome classified
   in one place, `dispatch`:
   - `Ok(v)` with `isError: true` becomes an ordinary step error, spelled as
     the chain spells it: `Error::json_rpc(-32603, "step '<name>' failed:
     <first text content, at most 2048 chars>")`. It then follows `on_error`
     like any other ordinary error: retried under `retry`, null-filled with
     its reason under `continue`/`retry`, returned under `abort` (PBERR.1).
     *Superseded by the hold: the message is fixed and the text, capped at
     256, is in the error's data (D3); the step is never retried (D1).*
   - A sealed transient returns at once, as a refusal does (no in-plan
     retry: an immediate re-send meets the same held lock, and each attempt
     writes an `idp_refuse` record).
   - One plan-wide flag, `attempted`, is set by every invoker outcome that is
     not the sealed transient (a served, failed, refused or tool-error
     attempt, of any step, earlier attempts of the same step included: C1b).
   - Step loop: before the `on_error` arms, a sealed transient ends the
     plan. With `attempted` unset the sealed error is returned unchanged:
     retryable, pre-send (STEP.1). With it set, an earlier attempt may have
     reached its backend, so the error is returned as
     `Error::Transport("after an earlier step ran: ..")`: not pre-dispatch,
     no retry data (C1), the mapping `mcp_rounds::after_dispatch` applies
     between rounds of one call.
2. **Fold point** (`invoke/post_dispatch.rs`, `settle_dispatch_error`): when
   the call is a playbook step (`crate::playbook::current_step().is_some()`)
   and the dispatch error is the sealed transient, return `Err(e)` after the
   key release and dispatch withdrawal already done above it, instead of
   folding it into `Ok(dispatch_error_result)`. Without this the folded Busy
   would be an ordinary `isError` failure, null-filled under `continue`. A
   direct `gateway_invoke` keeps today's answer. The reservation is already
   `None` (`take()`), so the `?` at `invoke.rs:568` settles nothing further;
   `invoke.rs` is not edited (C5).
3. **Invoker** (`playbook_invoker.rs`): a step's gateway notes are kept for
   `carry_writes` only for a result the engine records completed, so an
   `isError` result is not pushed (otherwise the completed/kept counts differ
   and every member of the answer falls back to receipted). The tool-error
   predicate is one `pub(crate)` function in `crate::playbook`, used by both.
4. **UPGRADING** (`upgrading.d/8429.md`) and a changelog fragment
   (`changelog.d/8429.changed.md`): an `isError` step is now failed and
   follows `on_error`; a busy custody ends the plan with the retryable error.

### Alternatives rejected

- **Classify in `MetaMcpInvoker` instead of the engine.** The engine is the
  one `ToolInvoker` consumer and owns `on_error`; a second invoker (tests, a
  future one) would silently keep the old semantics.
- **Recognise the folded Busy from its `isError` text or recovery hint.**
  Text-based (violates STEP.3).
- **Return the sealed transient as `Err` for every caller at the fold
  point.** Changes direct `gateway_invoke`'s wire shape; excluded in P1a.
- **Retry a Busy step in-loop under `retry`.** No backoff exists in the
  engine; the retries meet the same lock and add audit noise.
- **Per-step or per-playbook opt-out key** (MIK-8329's option). The lead
  decided the automatic default with no new key.
- **Track `attempted` per step only (completed/failed lists).** Misses an
  earlier attempt of the same step under `retry` (round-2 finding).

### Acceptance map

| AC | Rows (engine `busy_tests.rs`; router `playbook_busy_tests.rs`) |
|---|---|
| STEP.1 first attempt | `a_busy_first_step_*` (3 policies); `a_recheck_busy_step_ends_an_abort_plan_retryable`; `a_view_busy_step_ends_a_continue_plan_before_its_successor` |
| STEP.1 partial run (C1, C1b) | `a_busy_step_after_a_completed_one_*`, `a_busy_step_after_a_failed_one_*`, `a_busy_retry_after_a_transport_failure_*` (pre-hold: `..._after_a_tool_error_attempt_*`); router keyed `a_busy_step_after_a_served_one_*` (no retry label, same key does not re-send `s0`) |
| STEP.2 | `an_ordinary_step_error_keeps_its_policy` (unsealed look-alike, 3 policies) |
| STEP.3 | the look-alike row (same code, text, data; no seal) |

P1b review (gpt-20261019T002844Z-17630, agy-20261019T002844Z-17633), both
SHIP-WITH-FIXES: harness idempotency cache enabled for the keyed rows; the
keyed recovery asserts the replayed answer; direct-invoke exclusion control
added; write row reclassified red-first; first-step row asserts
`is_pre_dispatch()`. Declined: one shared chain/playbook text extractor (the
engine sits below `gateway`, so sharing would invert the dependency; the
2048-char rule is copied with a comment naming its twin). *Superseded by
the hold (D3): the cap is 256, and the text is kept out of the message.*

| PBERR.1 | `a_tool_error_step_*` (abort, continue, retry); `a_tool_error_step_is_not_resent_under_retry` and control `a_transport_failure_then_a_served_retry_*` (pre-hold: `a_tool_error_attempt_then_a_served_retry_*`); control `a_result_without_is_error_true_*`; router `a_vendor_error_step_is_a_failed_step`, `a_tool_error_step_is_sent_once_under_retry_keyed_or_not` (D1; it replaced the pre-hold `..._resent_only_when_unkeyed`); writes `a_failed_tool_error_step_leaves_the_completed_steps_notes_carried` (red on the line at its `steps_failed` premise, then a guard for the invoker filter: red under its mutant); exclusion control `a_direct_invoke_recheck_busy_keeps_its_folded_answer` |
| PBERR.2 | `upgrading.d/8429.md` |

Mutants, each shown red on Spark before the PR: drop the loop's Busy check;
drop the fold-point check; map the Busy unconditionally; never map it; set
`attempted` only on completed steps; match the Busy on its message text;
drop the `isError` classification; treat `"isError": "true"` (a string) as an
error.

### Evidence (Spark, 2026-10-19)

- Red first: with the four production files at the base, 13 rows fail
  (every STEP.1 and PBERR.1 row) and the 4 controls pass.
- Green: the focused run (`playbook busy scheduler chain`) passes 634 rows
  after one pre-existing row, `sub4_playbook_dispatch_uses_admitted_definition`,
  was moved to `on_error: continue`: its absent backend's answer is now a
  failed step, and the row observes the second step's target.
- Keyed `retry` replay verified before the hold: the vendor received a
  failed keyed step once and an unkeyed one three times. After the hold (D1)
  both receive it once.
- Mutants, each killed: M1 drop the loop's Busy stop (6 rows); M2 drop the
  fold point (2); M3 always map (3); M4 never map (4); M5 `attempted` on
  success only (2); M6 Busy by text (1); M7 no `isError` classification (7);
  M8 string `"true"` (1); M9 invoker keeps failed notes (1).

## Operator hold (2026-10-19): D1 and D3

The operator held the merge for two fixes; the design was reviewed by the
lead before the tests, and the tests were red before the code.

- D1: a step whose tool reported an error (`isError: true`) is never re-sent,
  under any `on_error`, keyed or not. The tool ran and answered, so a second
  call could repeat its side effect. Under `retry` the step is handled as
  under `continue` after one call. A step whose call ended in an error the
  gateway raised is still re-sent, as before (STEP.2); a keyed call replays
  its stored failure (ADR-012). The unkeyed re-send after a send is the
  remaining exposure, filed as MIK-8532 (v4.1.0; gap-finder G3, lead ruling
  2026-10-19: retrying only pre-dispatch errors here would rewrite STEPFW.2b,
  the route-matrix flaky driver and ADR-012's rows). No idempotent-step
  marker: that would be a new playbook key.
- G8 (gap-finder), kept: the invoker drops a failed step's `gateway_writes`
  notes. Those notes mark fields the gateway itself wrote into the answer
  value (`_cost_warnings`, `trace_id`), not writes a backend made; a failed
  step's output is null, so they have nothing to attach to (lead ruling).
- G4 (gap-finder), accepted: the JSON-RPC renderer forwards `tool_text` from
  any error's data, a backend's on a direct call included, only as a string
  of at most 256 characters plus a cut marker. Row
  `a_backend_tool_text_is_forwarded_only_within_the_cap`.
- D3: the step failure's message is fixed, `step '<name>' failed: the tool
  reported an error`, so the tool's text never reaches a log line that prints
  the error. The text, capped at 256 characters plus a cut marker, travels
  in the error's `data.tool_text`, and `step_errors` carries it capped the
  same way (caller output, not a log). The cap was 2,048.
- D4: a busy custody is `Err` inside a playbook and the folded `isError` value
  on a direct call, as documented above (unchanged).

Rows, red on the code before this change: `a_tool_error_step_is_not_resent_under_retry`,
`a_long_tool_text_is_capped_and_kept_out_of_the_message`,
`a_tool_error_step_aborts_an_abort_plan` (now checks the message and data),
`a_tool_error_step_is_sent_once_under_retry_keyed_or_not`. Controls, green
throughout: `a_transport_failure_then_a_served_retry_completes_the_step`,
`a_busy_retry_after_a_transport_failure_ends_the_plan_as_possibly_sent`.
