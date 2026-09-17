# Release 4.0.0 — readiness gaps and the plan to close them

Measured at `a0d9acbc` on `work/v4-audit-adjudication`. Every count below is a
command run in this tree, not a recollection; where a number is inferred or
assumed the row says so.

## The counter that changes the MIK-7387 ruling

`prompts_in` (`tests/mik_7212_mrtr7_stdio_acs.rs:749-755`) filters the *entire*
captured line buffer for `elicitation/create` frames and never decrements. The
58 both red rows observe is therefore **cumulative emissions**, not
concurrently-outstanding prompts. That distinction settles the open question and
inverts the argument recorded in
`docs/design/2026-09-13-mik-7387-stdio-concurrent-dispatch-review.md`:

- A 64-permit semaphore **cannot** hold a cumulative count below 64. A permit
  delays a dispatch; it does not suppress the frame the dispatch eventually
  writes. So `MAX_CONCURRENT_STDIO_DISPATCHES` is ruled out as the bound on this
  number, and the "pinned at 58 under a 16x load change is the signature of a
  cap" reading is wrong for a cumulative counter — a cap plateaus concurrency,
  it does not create a deficit in emissions.
- A cumulative deficit means 6 dispatches reached the bridge and wrote something
  other than an outbound elicitation. The census closes on exactly that: 7a is
  58 + 7 = 65 calls, 7b is 58 + 966 + 2 = 1026, and the only site that
  manufactures a plain `result` for a call the fixture answered with
  `input_required` is the empty `NoSession` arm at
  `src/gateway/meta_mcp/invoke.rs:2271-2274`, which falls through to the minted
  continuation at `:2358`.

**Consequence:** the silent-downgrade mechanism is re-promoted from candidate to
likely cause, there is **no** separate 58-to-64 cap defect to file, and the
operator's standing "include MIK-7387 and fix the `NoSession` arm" ruling is
re-validated rather than undermined. A fix at that arm can turn both rows green,
because the 6 missing questions are questions those calls should have asked.

Still unexplained, and marked as such: why the deficit lands near 58 rather than
some other value, and why six consecutive macOS runs never lose the race. Load
dependence (6 downgrades at 65 calls, 968 at 1026) is consistent with a race the
Mac simply wins every time.

## Gap inventory

| # | Gap | Measured state | Blocks release? |
|---|---|---|---|
| 1 | Acceptance criteria ledger | 177 MET, 2 PARTIAL, 2 N/A (`RELEASE-4.0.0-criteria-status.md`) | the 2 PARTIAL do |
| 2 | Two red CI rows | `ac_mrtr_7a_*` / `ac_mrtr_7b_*` red in CI, 6/6 green on macOS | yes |
| 3 | DoD gate sheet | 36 PASS, 27 PARTIAL, 18 NOT EVALUATED, 3 OUTSTANDING, 12 N/A | the FAIL and the unmeasured do |
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
   nobody ran them, not because they fail.
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
