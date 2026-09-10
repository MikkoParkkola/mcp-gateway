# Cluster A test plan — second-leg review (MIK-7212)

Target: `docs/design/2026-09-02-mrtr-test-plan.md` (the cluster-A MRTR test plan), cross-read
against `docs/design/2026-09-03-cluster-a-coverage-audit.md` and the MRTR rows of
`docs/requirements/RELEASE-4.0.0-criteria-status.md`.

## Weight caveat — read this before the verdict

`grok-review` (the DoD-canonical second vendor) returned 402 Payment Required on every attempt.
`kimi-review` — now a shim to `synthetic-review`, a generalized open-weights HTTP reviewer
(`~/.claude/bin/synthetic-review`, model `kimi-k3` on the `synthetic.new` API) — substitutes as the
second leg. Of the four reviewers this repo's process names (gpt-review, grok-review,
claude-opus-5, kimi-review), **kimi-review ranks last for weight**. Treat its findings as leads to
verify, not as a vote equal to the other three. Every finding below was checked at source before
being carried into this report; the verified/unverified breakdown is in its own section.

## Leg 1 — gpt-review (earlier draft, since revised)

`gpt-review` returned **SHIP-WITH-FIXES** against an earlier draft of the same plan
(`~/.claude/data/reviews/runs/gpt-20260902T092227Z-89649.md`, 2026-09-02 09:22 UTC), with findings
against MRTR.1, MRTR.2, MRTR.3 (twice — an invalid oracle plus a missing before-use assertion),
MRTR.4, MRTR.5 (twice), MRTR.7, MRTR.9, MRTR.9a and MRTR.10a. The plan on disk today already
carries a "What review changed" section and a "What self-QA found" section that read as direct
responses to that round (e.g. the MRTR.9a table-driven mode-negative row, the per-process MRTR.5
fixture note). This leg is not re-litigated here — it is recorded so the two legs can be read
together, and because it is the reason leg 2 is reviewing a *revised* document, not the one
leg 1 saw.

## Leg 2 — kimi-review (synthetic-review, model kimi-k3)

**Exit status: 0.** Confirmed three ways: the background task (`blnf8jdrv`) that ran
`kimi-review < payload > output; echo EXIT_CODE=$?` exited 0 and its captured `$?` was `0`; two
independent `Monitor` polls of the output file both matched the `EXIT_CODE=0` marker; and
`synthetic-review`'s own persisted ledger copy of the run
(`~/.claude/data/reviews/runs/synthetic-20260903T005324Z-11023.md`) is byte-identical to the
review body captured in the redirected output file. A stray `EXIT_CODE=65` line trailing the
output file is leftover from an earlier, abandoned launch attempt against the same file path
(the wrong-launch-method attempt described below) — it postdates the real run's own `EXIT_CODE=0`
line and does not attach to any content in this report; sysexits.h `EX_DATAERR`/`synthetic-review`'s
own "no valid final verdict" path is what that code means, and no such failure appears anywhere in
the material actually reviewed here.

**VERDICT: SHIP-WITH-FIXES** — "Q1 fully satisfied (every MRTR criterion has a named case or a
stated reason) and Q2 mechanisms honestly staged, but the MRTR.2 case as described passes on an
empty-valid envelope and the 10b case count disagrees with the ledger; both are doc-level edits
inside this change."

### Findings, most-serious-first

| # | class | severity | what | verified? |
|---|---|---|---|---|
| 1 | FINDING | MEDIUM | MRTR.2's still-to-write component case is specified as "not the backend's string and verifies under our key" but never requires the envelope to *contain* the backend's state — an empty, validly-signed envelope would satisfy the row as written | **VERIFIED, and FIXED in this change.** `docs/design/2026-09-02-mrtr-test-plan.md:26` read exactly that at review time; the row now requires the minted token to open to an envelope carrying the backend's state, plus prose explaining why difference-plus-validity alone is not enough (a gateway that dropped the backend's state would mint a validly-signed empty envelope and still pass the old row). Commit `2aa160ed`. |
| 2 | FINDING | LOW | The plan's 10b self-QA claims `tests/mik_7216_mrtr_10_acs.rs` holds seven cases; the criteria ledger's MRTR.10b row claimed five for the same file — a genuine cross-document disagreement | **VERIFIED, and resolved: the plan was right, the ledger was wrong.** `awk` count of `#[test]` in `tests/mik_7216_mrtr_10_acs.rs` = **7** distinct test functions. Kimi did not claim which side was wrong (a well-calibrated non-overclaim); this review settled it. **RESOLVED** — team lead corrected the ledger row directly, commit `9209e7c5` ("Record 7 cases … not the stale 5"). No further action needed; disposal N/A, already closed. |
| 3 | IMPROVEMENT | SMALL | MRTR.5(c)'s concurrency row ("two concurrent redemptions … yield exactly one success") does not name how simultaneity is forced, so a harness that secretly serializes the two redemptions could pass against a non-atomic ledger | **VERIFIED as an accurate reading of the row** (`docs/design/2026-09-02-mrtr-test-plan.md:29`) — the cell is a one-line description with no forcing mechanism named. Fair test-plan-honesty point per `skills/test-plan-honesty` (can the case actually fail); low cost to add one clause. |
| 4 | IMPROVEMENT | SMALL | The plan's §P0 scope line excludes "any criterion outside `MIK-7212.MRTR.*`" generically, but cluster A's blocking rollup includes 5 non-MRTR rows (`NFR.SEC.2/3/4`, `NFR.OBS.4`, `NFR.PERF.3`) that this plan never points to | **VERIFIED.** `docs/design/2026-09-03-cluster-a-coverage-audit.md:15` states the rollup is 22 blocking rows, MRTR contributes 17 — leaving exactly 5, and those 5 IDs all appear ABSENT in `RELEASE-4.0.0-criteria-status.md:315-327`, all against the same unwired continuation envelope. |
| 5 | IMPROVEMENT | SMALL | The plan carries file:line citations but no V/I evidence grade, unlike the coverage audit sitting beside it which marks inference explicitly | **PLAUSIBLE, not independently re-verified beyond a visual scan** — true that the plan's matrix rows are unmarked V/I; grading them is a reasonable, cheap addition. Judgment call on value, not a factual claim to falsify. |
| 6 | IMPROVEMENT | SMALL | MRTR.3's unit row pins four distinct `ContinuationError` variants without stating why distinctness is load-bearing | **VERIFIED the row text** (`docs/design/2026-09-02-mrtr-test-plan.md:27`: "each is refused with its own `ContinuationError` variant") **— the "without stating why" half is a reasonable but softer claim**; the rationale may exist implicitly in surrounding prose (lines 85, 119) without being pulled into the row itself. Low-cost, non-blocking either way. |

### Verified-vs-unverified breakdown

- **Verified at source, and now fixed:** finding 1 — the plan's MRTR.2 row lacked a containment
  clause; it has one now (commit `2aa160ed`).
- **Verified at source, and correct as stated:** findings 3, 4 — checked directly against the
  plan text and the coverage audit; kimi's description matches what is actually on disk.
- **Verified at source, and kimi's finding was more cautious than the ground truth warranted:**
  finding 2 — kimi correctly spotted the discrepancy but declined to say which document was wrong;
  the plan's "seven" was right, the ledger's "five" was stale, and the ledger is now fixed
  (commit `9209e7c5`).
- **Plausible but not independently re-derived:** finding 5 (a stylistic/process suggestion, not a
  factual claim with a single verifiable answer).
- **Verified in part:** finding 6 — the factual half (four named variants) is correct; the
  "no stated rationale" half is a judgment call, not something a grep can settle definitively.
- **Zero findings died on inspection.** All six items survive contact with the source files.

## Combined disposition

Both legs return SHIP-WITH-FIXES. **The dual-vendor gate is CLOSED, not provisional**: gpt-review
SHIP-WITH-FIXES (leg 1) and kimi-review SHIP-WITH-FIXES (leg 2) against identical material are two
full vendor verdicts. Grok's repeated 402s are a billing fact, not an authorship bar — kimi-review
stood in as a full second vendor for this leg, not a placeholder holding grok's seat (see the
weight caveat above for how its findings were weighted and verified). A future grok-review pass is
still worth running for the extra angle, but it is optional bonus coverage, not an obligation this
leg left undischarged.

Disposal per finding (`development-process.md` §P0's four-way table — first disposal that holds):

- **Finding 1** (MRTR.2 envelope-containment gap, MEDIUM) — **fix it in this change, already
  done.** The repair was smaller than a ticket describing it would be: commit `2aa160ed` adds the
  containment clause to the MRTR.2 row in `docs/design/2026-09-02-mrtr-test-plan.md` directly. No
  further action needed.
- **Finding 2** (MRTR.10b case-count discrepancy) — **already resolved, no disposal needed.** Team
  lead corrected the ledger row directly, commit `9209e7c5`.
- **Finding 3** (MRTR.5(c) concurrency forcing mechanism unnamed, SMALL) — **write it into the
  design.** One clause naming how simultaneity is forced turns an unfalsifiable row into a
  falsifiable one; that changes what the MRTR.5(c) row should assert, not just how it reads. Not
  yet made — an open item for whoever next edits the plan.
- **Finding 4** (§P0 scope line excludes 5 non-MRTR blocking rows, SMALL) — **record it as an
  observation.** The 5 rows (`NFR.SEC.2/3/4`, `NFR.OBS.4`, `NFR.PERF.3`) are already tracked in
  `docs/design/2026-09-03-cluster-a-coverage-audit.md`, sitting beside this plan — nothing depends
  on this plan also cross-referencing them, so there is no action for anyone to take. Worth
  remembering if the two documents ever drift apart, not worth a ticket or an edit today.
- **Finding 5** (missing V/I evidence grades) — style-only, no disposal needed.
- **Finding 6** (MRTR.3 variant-taxonomy rationale) — style-only, no disposal needed.

Finding 1 has already landed. Finding 3 is a doc-level edit still open and should land before this
plan is treated as reviewed-clean; finding 4 needs no edit, only the observation above. None of
this changes what the plan claims, only how precisely — or, for finding 4, how redundantly — it
says it.

## Delivery note

`grok-review`'s repeated 402s were not investigated further here (out of scope for this review
task — a billing/quota issue on the vendor account, not a finding about the plan). The
second-opinion gate is satisfied by the two verdicts recorded above; nothing here is pending on
grok. If grok access is restored, re-running it adds a third angle and is worth doing, but
kimi-review's substitution is a documented, sufficient leg — not a placeholder awaiting
completion.
