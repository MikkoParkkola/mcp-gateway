# Release 4.0.0 — readiness gaps and the plan to close them

Measured at `a0d9acbc` on `work/v4-audit-adjudication`. Every count below is a
command run in this tree, not a recollection; where a number is inferred or
assumed the row says so.

## MIK-7387: what the census settles, and what it does not

Two claims were tangled together on this ticket. They have different strengths
and only one of them is settled, so they are separated here.

**Settled — the plain results are manufactured by the gateway (V).** The fixture
backend returns `input_required` for every call that arrives without
`inputResponses` (`tests/mik_7212_mrtr7_stdio_acs.rs:147-172`), so a plain
success result cannot originate at the backend. The census closes on the call
counts: 7a is 58 + 7 = 65, 7b is 58 + 966 + 2 = 1026. A dispatch parked on an
admission permit emits *nothing* — it is still waiting — so it cannot be the
source of a plain result either. The only site that manufactures one is the empty
`NoSession` arm at `src/gateway/meta_mcp/invoke.rs:2271-2274`, falling through to
the minted continuation at `:2358`. This leg needs no argument about counting
semantics, and it re-promotes the silent downgrade from candidate to likely
cause. The consequence the ticket cares about follows from it: a caller that
asked for a bridged elicitation is answered with a continuation envelope instead.

**Settled — 7a is the downgrade, and nothing on 7a is parked (V).** CI run
`35254650457` re-ran the census and the split moved: 59 asks, 6 plain results,
59 refusals against the same 65 calls. Decomposed by role rather than by count,
`elicitation/create` are gateway-to-client requests while `results` and `errors`
are the responses to the 65 tool calls, so the discriminator is
responses-versus-calls: 6 + 59 = 65, and the run before it 7 + 58 = 65. Every
call was answered. A dispatch starved of an admission permit emits nothing
inside the window, so a cap-driven deficit would leave responses *short* of
calls; on 7a it is exact, twice, at two different split points. The cap is
therefore ruled out **on 7a only**, the deficit is wholly the manufactured
result, and the moving split point is the race.

**Newly separated — 7b loses calls outright (V).** The same subtraction on 7b
does not balance. The loop sends `FIRST_CALL_ID..=last_over_cap`, which is
`2..=1027` for `INFLIGHT_CAP` 1024, so 1026 calls
(`tests/mik_7212_mrtr7_stdio_acs.rs:895-899`). Responses are 964 + 20 + 2 = 986,
leaving 40 calls that produced no response line at all; the earlier run leaves
47. That is the parked population the cap hypothesis predicts, so 7b is a
distinct defect from 7a and the cap remains live on it.

**Retired — the CI probe was inert (V).** The throwaway branch carried two
`tracing::warn!` calls at the empty arm and the mint (`ccd7669f`). Neither fired
in CI, and not because the arm was cold: no test installs a `tracing`
subscriber and the workflow sets no `RUST_LOG`, so the macros had nowhere to
emit. Zero hits is no evidence either way. The census already histograms error
codes *and* error messages, which is a working instrument, so the fix carries
its own measurement and no second probe branch is needed.

**Corrected — the guard named in the source comment does not hold.** The comment
at `src/gateway/meta_mcp/invoke.rs:2247-2264` argues stdio can never reach the
empty arm because `stdio_caller_context` declares `Declared::NONE`, so `plan`
refuses one step before delivery. That helper
(`src/gateway/server/mod.rs:3665`) has one caller, a test at `:4287`. The live
stdio dispatch uses `build_stdio_caller_context` (`:3142`, called from
`dispatch_tools_call` at `:3303`), which declares
`request_shape.declared_capabilities()` or the client's handshake capabilities.
So on the live path the ask does go out, and a delivery that finds no session
does reach the empty arm. The 59 asks observed over stdio are that.

**Historical — what the deficit was thought to be (A).** `prompts_in`
(`:749-755`) filters the entire captured buffer and never decrements, so 58 is a
count of *cumulative emissions*. That was read as ruling out the 64-permit cap,
on the grounds that a permit delays a frame rather than suppressing it. The
reading does not hold, because the observation window is bounded:
`COLLECT_BUDGET` is 30s (`:734`) and the bridge's `per_prompt` timeout is also
30s (`src/gateway/input_bridge.rs:280`). At a 1:1 ratio, a dispatch starved of a
permit held for a full prompt timeout can never emit inside the window, and
delay becomes indistinguishable from suppression in the count. So
cumulative-versus-concurrent does not discriminate here, and the cap remains a
live explanation for the deficit alongside the downgrade.

**Open — which `NoSession` this is (I).** The obvious fix, erroring whenever the
caller declared the input capability, is wrong: the two production paths that
declare are the HTTP handlers
(`src/gateway/router/handlers.rs:1471,1561,1593,1902`) and live stdio
(`src/gateway/server/mod.rs:3184`), and a stateless HTTP caller declaring
elicitation with no session is the legitimate case the continuation exists to
serve. Splitting on the channel does not work either. `NoClientChannel`
(`src/gateway/input_bridge.rs:350-362`) returns `DeliveryError::NoSession`
unconditionally, so one variant carries both "there is nowhere to send this"
and "a real channel, but the session is gone" — yet both callers that matter
hold a *real* channel: HTTP takes `state.proxy_manager.as_ref()`
(`handlers.rs:1602`) and the stdio serve loop takes the pipe it already reads
(`server/mod.rs:3198`).

What is left is timing. 65 identical calls travel one path and split 59/6, then
58/7, and six consecutive macOS runs never split at all. That is the signature
of a race on bridge-session registration: a call arriving before the session is
registered gets `NoSession` and is minted a continuation, and one arriving after
is asked. Locating the registration point relative to the dispatcher accepting
calls is the next measurement, and it is not yet made.

**Therefore:** the two rows split. 7a is the silent downgrade, and the arm must
stop minting whatever the cause — a caller that asked for a bridged elicitation
and cannot be reached must fail loudly, which also removes the round-two replay
hazard the arm's own note describes. But the discriminator that lets it keep
serving stateless HTTP callers is not settled, so the edit is not made here.
The falsifier is stated in advance: post-fix 7a should read 64 asks, 1
admission refusal, 0 plain results. If it reads 65 asks, admission is not
refusing at the cap — a different defect. 7b carries its own ticket for the 40
unanswered calls; a fix at the arm is not expected to close it.

Also required in the same edit, per review: the comment at
`invoke.rs:2247-2264` asserts a guard that does not hold on the live path and
must be replaced by the actual rule, and the new error needs a stable distinct
message so the census histogram discriminates it inside `-32003` without a new
protocol code.

Unexplained either way: why six consecutive macOS runs never lose the race.

## Gap inventory

| # | Gap | Measured state | Blocks release? |
|---|---|---|---|
| 1 | Acceptance criteria ledger | 177 MET, 2 PARTIAL, 2 N/A (`RELEASE-4.0.0-criteria-status.md`) | the 2 PARTIAL do |
| 2 | Two red CI rows | `ac_mrtr_7a_*` / `ac_mrtr_7b_*` red in CI, 6/6 green on macOS | yes |
| 3 | DoD gate sheet | 51 distinct gates, 31 carrying a non-pass verdict somewhere. Row counts are higher (27 PARTIAL, 18 NOT EVALUATED, 3 OUTSTANDING) because ten gates carry a verdict in two sections and are counted twice | the FAIL and the unmeasured do |
| 4 | 800-LOC ceiling | 57 production files breach, ~80,845 LOC; deviation accepted via MIK-7478, ratchet not in CI | no (accepted), ratchet does |
| 5 | Housekeeping | 45 worktrees, ~20.7 GB of build dirs, disk 94.8% | no |

The two PARTIAL criteria are the release-gating half of gap 1:

- **NFR.SEC.7** — merged-versus-listening drift detection: the detector half is
  MET as of 2026-09-11, the "listening build carries every merged control" half
  is open.
- **NFR.PERF.1** — latency not regressed >5% P50 / >10% P99 against 3.5.0: last
  measured on Spark 2026-09-03 against a tree that is no longer the candidate.
  The measurement is stale, not failing.

Gap 3 splits three ways, and the split is what makes it tractable:

- **Cheap and mechanical** (no build, no operator): D13b EFFORT-LOGGED, D13c
  DEPS-UNBLOCKED, D13d LABELED, D17 LEARNINGS, D28 API-SURFACE, D29 DEBT-TRAJ,
  H7 no-redundant-docs, H8 no-temp-files.
- **Needs a measurement run**: D1 TESTED, D3 MEASURED, D4 DRY, D5 CONTRACTS, D6
  E2E, D8 OBSERVABLE, D10 0-BUG, D11 OPTIMIZED, D15 CLEAN, B3 DURABLE, T1c
  PQC-READINESS, H6 no-orphans, H9 no-duplicate-functions (the `ops.rs:318`
  versus `:456` 17-line duplicate is the known instance), plus §5 coverage
  no-drop, which needs coverage on both sides of the merge-base.
- **Operator acts only**: D18 MERGED (PR #528 is a draft), D21 CANARY (no rc
  published, so no exposure staged), D20 ROLLBACK execution.

## The plan

Ordered so that nothing waits on anything it does not have to. Waves 0-2 need no
operator decision; wave 3 is the part only the operator can do.

### Wave 0 — no build, no operator

1. **Land the LOC ratchet** (MIK-7478 AC 1). Add the fail-fast one-liner as a
   `release-criteria` step asserting the breach count is `<= 57` and
   monotonically decreasing. This turns gap 4 from an open FAIL into a measured,
   bounded deviation, which is what the DoD asks of an accepted deviation.
2. **Fix the H9 duplicate** at `src/gateway/ops.rs:318` and `:456` — 17
   duplicated lines, one extraction, and H9 stops being PARTIAL on its one known
   instance.
3. **Clear the mechanical gates** by recording the evidence each one asks for:
   effort, dependency state, labels, learnings, API surface delta, debt
   trajectory, doc redundancy, temp files. These are NOT EVALUATED because
   nobody ran them — an assumption, not a measurement. Running them may turn
   some into FAILs, and the wave-0 size depends on that going the other way.
4. **Post the consolidated DoD comment** on the tracking issue, closing the §1
   PARTIAL.

### Wave 1 — the red rows

5. **Establish the cause in the environment that fails.** Push a throwaway
   branch carrying only the two `warn!` probes (the `NoSession` arm and the
   continuation mint), read the CI run, then retire the branch. The probes must
   not land on `work/v4-audit-adjudication`. This is the only step that can
   settle the mechanism, because the failure does not occur locally.
6. **Fix the `NoSession` arm** once the probe settles it: a dispatch that cannot
   reach a live session must fail loudly rather than fall through to a minted
   continuation, and the arm must stop being empty. Write the
   `MIK-7212.WIRE.10` row the source comment at `invoke.rs:2247` already names
   as missing, so the invariant is pinned by a test rather than by a comment.
7. **Re-run both rows in CI** and require green there, not locally. A local pass
   proves nothing about these two rows — that is the whole finding.

### Wave 2 — the measurements

8. **Re-measure NFR.PERF.1** against the actual candidate on Spark, under the
   compute-routing rule. Stale is not failing, but a stale number cannot close a
   gate.
9. **Close the NFR.SEC.7 first half**: show the listening build carries every
   merged security control, not just that drift would be detected.
10. **Run the gates that were never run**: coverage on both sides of the
    merge-base for §5 no-drop, the §6 measurement instead of an observation, and
    the §8 remainder — STRIDE, DAST, privacy and licensing, none of which has
    been evaluated at all.

### Wave 3 — operator acts

11. **Publish `v4.0.0-rc.1`** to the opt-in channels only. D21 stays OUTSTANDING
    until exposure is actually staged; the mechanism exists and is tested, but no
    rc has been published, and claiming the gate off a workflow edit is the
    fabrication the gate exists to catch.
12. **Observe the five stable pointers unmoved**, per
    `docs/release/v4.0.0-prerelease-channel.md`.
13. **Exercise the rollback path** once, so D20 stops resting on documentation
    alone.
14. **Take PR #528 out of draft and merge** — D18, and the last gate.

Housekeeping (gap 5) runs whenever a reclaim candidate goes cold. Nothing was
freed this pass: every candidate was touched within hours by a live peer build,
so 0 bytes are safely reclaimable right now.
