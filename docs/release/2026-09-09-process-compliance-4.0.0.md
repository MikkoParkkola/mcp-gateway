# Process compliance of the 4.0.0 increments

Audit date: 2026-09-09. Audit ref: `origin/fix/mrtr2-continuation-handle`
(2047 commits in `origin/main..origin/fix/mrtr2-continuation-handle`).
Local `HEAD` is 36 commits behind that ref and was **not** used; an audit built
on it would have missed the last day of landed work, including `de7c5e2d`.

## Verdict

The declared process — reviewed design, then reviewed test plan, then failing
tests, then implementation, then a recorded two-leg review verdict — was
followed end to end on **none** of the eleven increments below.

Three increments (MRTR, NFR, GH475) put a design document in the tree before or
on the day of their first implementing commit. Four (CONTROL/STATELESS,
RESULT/ERROR/ORDER, CONFIRM, NFR) opened with a failing-test commit before any
implementation commit. Only one increment — RESULT/ERROR/ORDER — did both, and
even there the design document landed six days *after* the code. Every other
design document in `docs/design/` for this release was written after the code it
describes; on this branch the design corpus is a record of what was built, not a
gate that preceded it.

Review verdicts are worse. Exactly one increment carries a labelled verdict pair,
and that pair does not authorise its own merge. Ten of eleven increments merged
with no attributable review record of any kind.

The merge `de7c5e2d` is the sharpest instance: an 18-file merge including a
242-line change to the Meta-MCP core, landed with its design document created in
the same merge, no test-first commit, and no verdict.

## Method

Increments are the ticket groups of `docs/requirements/RELEASE-4.0.0-criteria-status.md`,
the shipped-scope authority (146 criteria, 183 rows). Per-criterion rows were not
used: the ledger records shipped scope at group granularity.
(`docs/requirements/RELEASE-4.0.0-scope-status.json` marks every criterion
`pending` and is explicitly "not yet graded against the approved scope update";
it is not a scope authority and was excluded.)

Per increment, three facts were derived mechanically from the audit ref:

- **Design**: `git log --diff-filter=A` over `docs/design/*.md` — the commit that
  first added the document, not its filename date.
- **First code**: oldest `feat(` / `fix(` commit whose scope tag matches the increment.
- **First test**: oldest `test(` commit whose scope tag matches the increment.

Commit scope tags (`feat(mrtr)`, `test(gh475)`, `docs(design)`) are the join key.
An increment whose implementation landed under an untagged or differently tagged
subject will under-report; those cells are marked accordingly rather than guessed.

Review verdicts follow `docs/release/v4.0.0-merge-queue-state.md` §"Review verdicts
(authority: run file + process exit status)". Verdict authority is a labelled run
file plus its process exit status. Timestamp attribution against the review ledger
was tried, was wrong, and has been withdrawn — see Gap 3.

## Per-increment compliance

All timestamps are committer dates on the audit ref.

| Increment (ledger group) | Design doc added | First code | First test | Design before code | Tests before code | Review verdict |
|---|---|---|---|---|---|---|
| MIK-7213/7214 CACHE, HEADER | 2026-08-31 `cluster-f-response-cache-keying.md`; 2026-09-03 `header-9-era-conditional-outbound.md`; 2026-09-06 `cache4-policy-epoch.md` | 2026-08-29T12:12 `2c774d4c fix(headers)` | 2026-08-29T12:29 `28585647 test(headers)` | **No** — earliest design is 2 days after first code | **No** — test lands 17 min after the fix it covers | None found |
| MIK-7212 MRTR | 2026-08-30 `2026-08-30-mrtr-wiring.md` | 2026-08-31T03:12 `c484e8c9 feat(mrtr)` | 2026-09-02T14:06 `da3c4f6e test(mrtr)` | **Yes** | **No** — 2 days after implementation | None found |
| IDENT, SCHEMA, SURFACE, TENANT | 2026-09-07 `schema-1c-forwarded-schema-bounds.md` | none under these tags (9 commits, oldest `01651e3f style(tenant_guard)` 2026-08-31T22:19) | 2026-09-01T13:24 `17699a9e test(schema)` | **No** — design is the last artifact of the group | Not determinable — no tagged implementing commit | None found |
| MIK-7215 CONTROL, STATELESS | 2026-09-08 `control4-session-lifecycle-wiring.md` | none under these tags (5 commits) | 2026-09-04T13:27 `4e383958 test(stateless)` | **No** — design is 4 days after the failing test | **Yes** — group opens with a test | None found |
| MIK-7272 RESULT, ERROR, ORDER | 2026-09-06 `order-2-per-connection-list-variance.md` | 2026-08-31T21:46 `6da65738 fix(order2)` | 2026-08-31T21:40 `e57680c9 test(order2)` | **No** — 6 days after the fix | **Yes** — 6 min before the fix | ORDER.2 only — see below |
| MIK-7272 SUB, OAUTH, EXT, OTEL, TASK | 2026-08-29 `subscriptions-listen-stream.md` (same day as first code; intraday order not established) | 2026-08-29T05:33 `a0ad5567 feat(oauth)` | 2026-08-30T16:37 `33ee4a67 test(oauth)` | **No** for OAUTH — no OAuth design doc predates it (`oauth-transport-requires-tls.md` lands 2026-09-06) | **No** — 35 h after implementation | None found |
| MIK-7246 CONFIRM | 2026-09-06 `confirm-2-destructive-confirmation.md` | none under this tag (38 commits) | 2026-08-31T13:56 `6f04b808 test(confirm)` | **No** — 6 days after the failing test | **Yes** — group opens with a test | None found |
| MIK-7217 DISCOVER | 2026-08-31 `discover-outbound-era-probe.md` | 2026-08-30T03:50 `9ec00727 fix(discovery)` | **none** — no `test(discover*)` commit on the audit ref | **No** — 1 day after the fix | **No** — no test commit at all under this tag | None found |
| NFR (22 criteria) | 2026-09-01 `nfr-perf3-reclamation.md` | none under this tag (9 commits) | 2026-09-01T18:45 `69f2616f test(nfr-sec1)` | Same day as first test | **Yes** — group opens with a test | None found |
| GH475 (RL, CFG, VAL, OBS, MIG, NOTICE) | 2026-09-06 `gh475-rl10-capability-rate-limit-classification.md` | none under this tag (25 commits) | 2026-09-06T02:28 `2ecc6e5f test(gh475)` | Test plan repaired first: 2026-09-05T23:28 `b9b8d804 docs(gh475)` | **Yes** — group opens with docs then a test | None found |
| `de7c5e2d` merge — "land the working-tree increments on the release branch" | `2026-09-09-era-enum-reconciliation.md` **added by this same merge** | this merge (2026-09-09T14:47, parents `dc604088` `47dd46a9`) | none | **No** — design and code are the same commit | **No** | None found |

### The one increment with verdicts

ORDER.2 is the only increment with labelled run files
(`docs/release/v4.0.0-merge-queue-state.md`, ORDER.2 table):

- `gpt-20260831T190123Z-40438.md` — exit 0, `SHIP-WITH-FIXES`
- `grok-20260831T190327Z-50955.md` — exit 0, `SHIP`

That same document states that `SHIP-WITH-FIXES` does not authorise a merge on its
own and that the confirmation pass has not run. So the only increment carrying
verdicts still fails the chain — it merged on an unconfirmed conditional verdict.
It also records that no other branch in the queue has a labelled verdict.

## Gaps

**Gap 1 — design documents are written after the code, as a rule.**
Nine of eleven increments have their design document added after the first
implementing or first failing-test commit; the median lag is about five days.
The two partial exceptions (MRTR, GH475) predate their code by one day at most.
`docs/design/` currently reads as a post-hoc record. A design document that
lands after the implementation cannot have gated it, cannot have been reviewed
before it, and cannot have caught a wrong approach.

**Gap 2 — tests-first was applied to four increments out of eleven.**
CONTROL/STATELESS, RESULT/ERROR/ORDER, CONFIRM and NFR each open with a failing
test. CACHE/HEADER's first test lands seventeen minutes after the fix it covers —
the letter of the artifact without the function. MRTR's arrives two days late.
DISCOVER has no `test(discover*)` commit on the audit ref at all: three commits
under that tag, none of them a test.

**Gap 3 — the verdict record cannot be joined to the work it reviewed.**
`docs/release/v4.0.0-merge-queue-state.md` §"Review verdicts" is the process
authority, and it establishes that a verdict is a labelled run file plus its exit
status. The review ledger rows under `~/.claude/data/` carry `label: null`, so no
ledger row can be tied to a cluster. Attribution by timestamp was attempted, was
wrong — it produced a `DO-NOT-SHIP` belonging to unrelated work — and has been
withdrawn. Consequently "None found" in the verdict column above is a statement
about the record, not a claim that no review happened: for ten of eleven
increments there is no artifact in or out of the repository that can be shown to
belong to that increment.

**Gap 4 — verdict artifacts live outside the repository.**
Every run file cited by the merge-queue document is a path under
`~/.claude/data/reviews/runs/`. Nothing under that path is in the tree, in CI, or
reachable by anyone auditing from a clone. The release's only merge-authorising
evidence is unverifiable from the repository.

**Gap 5 — the one labelled verdict pair is internally inconsistent.**
In the ORDER.2 table (`v4.0.0-merge-queue-state.md:16-19`) the second leg is
labelled `Claude Opus 5` while its run file is named `grok-20260831T190327Z-50955.md`.
One of the two is wrong. Since the leg identity is what makes a two-leg review
independent, a mislabelled leg is not a cosmetic defect — it is the difference
between two reviewers and one.

**Gap 6 — a second verdict record exists in prose only.**
§"Confirmation pass — both legs returned, both SHIP-WITH-FIXES" (line 398)
records two verdicts with no run file and no exit status for either leg. By the
document's own rule — verdict authority is the run file plus process exit status,
never a string scraped from prose — that section is not a verdict record. It is
also for a different change (the Code Mode exposure hatch) than ORDER.2, so it
does not close ORDER.2's missing confirmation pass.

**Gap 7 — `de7c5e2d` merged the release branch with no gate satisfied.**
The merge (parents `dc604088`, `47dd46a9`) lands eighteen files, including
`src/gateway/meta_mcp/mod.rs` (+242 lines), `src/gateway/router/handlers.rs`,
`src/gateway/destructive_confirmation.rs`, and two new test modules. Its design
document, `docs/design/2026-09-09-era-enum-reconciliation.md`, is created *by the
same merge* — the design and the code it governs are one commit. There is no
preceding failing-test commit, and no verdict of any kind.
It was reported to this audit that the merge took the branch from one red check
to six, and that roughly 4,141 tests were affected. Those two figures are recorded
here **as reported and not independently verified** — no CI artifact establishing
either was found in the tree. What the commit itself establishes is sufficient
for the finding: a merge of this size and reach entered the release branch with
design, tests, and review all absent.

## Remedies

1. **Stop the design-after-code pattern at the branch.** Require that the commit
   adding `docs/design/<slug>.md` be an ancestor of the first commit touching the
   `src/` paths that document names. This is checkable in CI from the commit graph
   alone and needs no new record-keeping.

2. **Give the review ledger a label.** Gap 3 is a schema defect, not a discipline
   defect: rows are written with `label: null`, so nothing can ever be joined to
   them. Populating the label at write time makes every future verdict
   attributable; nothing else in this audit becomes fixable until it is.

3. **Move run files into the tree.** Commit run files under `docs/release/verify/`
   alongside the verdict tables that cite them, or record their content hash in
   the citing table. An out-of-tree merge authorisation cannot be audited by
   anyone but the machine that produced it.

4. **Reconcile the ORDER.2 leg labels before ORDER.2 is treated as reviewed**, and
   run its confirmation pass — the step the merge-queue document says terminates
   a review, and which has not run.

5. **Give `de7c5e2d` a retrospective gate.** The merge is landed; the remedy is not
   to revert it but to produce, now, what should have preceded it: a review of
   `era-enum-reconciliation` against the code that shipped with it, and a recorded
   two-leg verdict with run files in-tree. Until that exists, the release branch
   contains a change to the Meta-MCP core that no process step has examined.

6. **Do not treat the remaining eight increments as reviewed.** The honest reading
   of the verdict column is that their review state is unestablished. Any release
   decision that assumes those increments were reviewed is assuming a fact this
   audit could not find evidence for.

## What this audit does not cover

Test outcomes, criterion-level pass/fail, and CI history. No test was run and no
CI artifact was read; `cargo` was not invoked. The join between commit and
increment is the commit scope tag, so work that landed under an untagged subject
is invisible to this audit and would only make the compliance picture worse, never
better. Increments are ledger groups, not individual criteria — a group marked
compliant on an axis means the group's first artifact satisfied it, not that all
146 criteria did.
