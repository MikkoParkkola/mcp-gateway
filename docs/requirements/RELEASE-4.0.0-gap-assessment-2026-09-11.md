# v4.0.0 release gap assessment — 2026-09-11

Measured against `origin/feat/sub2b-outbound-mint` (PR #528) and
`origin/codex/v4-next-integration`. Every count below is from a command run for this
document. The commands are listed at the foot of this document so each count can be re-derived
rather than trusted.

## Headline

The release is not one deploy away. The "1 blocking criterion" figure describes the
baseline ledger only. A second status file holds **30 pending criteria** from a scope
expansion that the requirements document records as approved, and the publishing gate
already refuses 4.0.0 on all of them.

| Ledger | Entries | Graded | Gate |
|---|---|---|---|
| `RELEASE-4.0.0-criteria-status.md` | 149 criteria / 189 rows | 188 met or non-blocking, 1 blocking | `count-release-criteria.py`, every push |
| `RELEASE-4.0.0-scope-status.json` | 32 | 1 met, 1 resolved, **30 pending** | `check_scope_acceptance.py`, publish-time |

Both are enforced. `check_scope_acceptance.py --check` runs on every push in `ci.yml:274`,
`docker.yml:55` and `release.yml:92` and passes while work is pending by design;
`--publish-check` additionally requires completed acceptance once the context is a 4.0.0 tag
push or manual dispatch. Run today, `--release` refuses and names all 30 pending criteria
plus `NFR.SEC.7`. That behaviour is itself the criterion `NFR.RELEASEGATE.1`, which is
graded met: "Every automated 4.0.0 publishing path rejects unresolved baseline and
supplemental criteria and decisions; plan consistency can still pass while work is pending."

The governance is therefore sound. What is missing is the work, not the gate: 4.0.0 cannot
publish today, and the reason is 30 ungraded criteria rather than the single deploy that the
baseline headline implies.

## Why the second file is in scope, not stale

`RELEASE-4.0.0-scope-update.md:7` states it **supersedes the deferral** of MIK-6744/6745.
`RELEASE-4.0.0-requirements.md:361` agrees: "MIK-6744/6745 fallback consent/storage is now
in 4.0". `RELEASE-4.0.0-scope-update.md:63` lists the inclusion under Boundaries. There is
no descope decision for it in `RELEASE-4.0.0-operator-decisions.md`.

`docs/release/verify/RELEASE-4.0.0-CLOSE-PLAN.md:405` records the opposite reading — that the `codex/v4-*` PRs
map to "no blocking row or 4.0.0 ticket". That is true of the baseline ledger and false of
the approved scope, which the publishing gate enforces. The CLOSE-PLAN line should be read
as scoped to the baseline, not as a disposition for the scope expansion.

## The 30 pending criteria

| Cluster | Criteria | Count |
|---|---|---|
| Accounts | MIK-6744.STORE.1/2, MIK-6745.JOURNEY.1/2/3, MIK-6746.CONTRACT.1 | 6 |
| Task lifecycle | MIK-7311.LIFECYCLE.1–5 | 5 |
| Validation NFRs | NFR.CONFORMANCE.1, NFR.WORKLOAD.1, NFR.UPGRADE.1, NFR.DEMO.1, NFR.BUILD.1 | 5 |
| Stdio bridging | MIK-7387.STDIO.1/2/3 | 3 |
| Discovery / ranking | MIK-3274.RANKING.1/2/3, MIK-7332.DISCOVERY.1, MIK-7334.CATALOGUE.1 | 5 |
| Other | GH462.CONFIG.1, GH452.SESSION.1, MIK-7377.SIGNING.1, MIK-7388.CANCEL.1, MIK-7235.PIN.1, MIK-6710.AUDIT.1 | 6 |

Each carries the same note: "Not yet graded against the approved scope update." Pending is
therefore an **ungraded** state, not a failed one. Some of these may already be satisfied by
code on `feat/sub2b-outbound-mint`; none has been measured.

## The two lineages

The 4.0.0 work is split across two branches that diverged at `c3626cf8` (2026-09-04).

| | `feat/sub2b-outbound-mint` (#528) | `codex/v4-next-integration` |
|---|---|---|
| Commits since fork | 205 | 1,963 |
| Last commit | 2026-09-11 | 2026-09-08 |
| CI | green | 16 of 42 checks failing on PR #512 |
| Mergeable vs main | clean | CONFLICTING / DIRTY |
| Counted ledger work | yes | no |

At module granularity `codex/v4-next-integration` carries one subsystem that #528 does not
have at all, and one submodule of a file both branches already have.

| Module | #528 | codex |
|---|---|---|
| `src/personal_accounts/` | absent entirely | **44 files** |
| `src/idempotency.rs` | 1,426 lines | 1,046 lines |
| `src/idempotency/` (`mod admission`) | absent | 6 files |

The idempotency row is the one that is easy to misread. Both branches have
`src/idempotency.rs`; #528's copy is the **newer and larger** of the two, carrying the
`MIK-7272.SUB.4` dispatched-failure work. The codex `src/idempotency/` directory is a
submodule of that same file, not a replacement for it.

`src/personal_accounts/` is a real subsystem, not scaffolding: it carries `commit.rs`,
`consent.rs`, `identity.rs`, `config/adapters.rs` and dedicated `authority_tests.rs`,
`bounds_tests.rs`, `commit_tests.rs`, `crash_tests.rs`, `fence_tests.rs`, `fifo_tests.rs`
plus JSON fixtures. It is the implementation surface for the six Accounts criteria, none of
which can be graded on #528 because the code is not there.

The 205 commits on #528 since the fork are newer work inside the shared modules, so neither
branch is a strict ancestor of the other in content terms.

## Gap list

| # | Gap | Evidence | Disposition |
|---|---|---|---|
| 1 | `NFR.SEC.7` deploy half | running process is `3.4.0-f30539af`, built before `5d25f104` added the control | operator decision; independent of everything below |
| 2 | 30 criteria never graded | `RELEASE-4.0.0-scope-status.json`, all "not yet graded" | grade them; some are likely already met |
| 3 | Accounts implementation absent from the release line | `src/personal_accounts/` exists only on the codex lineage | land, re-cut or descope |
| 4 | `idempotency` **not** a missing module | #528's `src/idempotency.rs` is 1,426 lines to codex's 1,046 and is the newer copy; only the `mod admission` submodule is codex-only | graft `admission.rs` after grading MIK-7311; never copy codex's `idempotency.rs` over it |
| 5 | Two ledgers, one headline | the widely-quoted "188 met, 1 blocking" omits the 30 | quote both figures together, or report the `--release` refusal instead |
| 6 | 16 open PRs, none merged | 13 stacked `codex/v4-*` drafts plus #528, #521 and #516 | #521 is fully contained in #528; #516 is separately decidable; the codex stack follows gap 3 |

## Plan

Ordered so that each step's output is what makes the next step decidable.

**1 — Stop quoting the baseline headline alone.** The gate is correct; the reporting is
not. "188 met, 1 blocking" is a true statement about one of two ledgers and has been used as
if it described the release. The single honest readiness figure is the output of
`check_scope_acceptance.py --release`, which today refuses and names 31 items. Any status
comment, DoD record or release note should quote that, not the baseline headline. No code
change is required for this step.

**2 — Grade the 30.** They are ungraded, not failed. Grading is measurement against the
existing tree and needs no merge. Expect three outcomes per row: already met on #528,
needs the codex code, or genuinely unbuilt. Only after this is the size of the remaining
release known. Start with `GH452.SESSION.1` and `GH462.CONFIG.1`: #528 already carries
`tests/gh452_session_owner.rs` and `tests/gh462_config_preservation.rs`, so those two rows have
named tests to grade against rather than a module-presence argument. The discovery/ranking rows
come next, because `src/discovery/` and `src/ranking/` are present on both lineages.

**3 — Decide the lineage on evidence from step 2.** The choice is not "merge 1,963
commits". Both extra modules are self-contained directories absent from #528, so the
options are:

- **re-cut** `src/personal_accounts/` onto the release line as a fresh PR, taking the code but
  not the 1,963-commit history; conflicts are then limited to the wiring points rather than the
  whole tree, and it lands behind the normal review gate. `mod admission` is a separate, smaller
  graft onto #528's existing `src/idempotency.rs` — not part of the re-cut, and not a file copy;
- **land** `codex/v4-next-integration` by rebasing it onto #528, which is the honest option
  only if step 2 shows the codex line also carries graded work inside the shared modules;
- **descope** MIK-6744/6745/6746 to 4.1, which requires an operator decision that reverses
  `scope-update.md:7` and updates `requirements.md:361`.

Re-cut is the recommendation. It is the only option that puts the accounts subsystem on a
green, reviewable line without importing a divergent three-day-stale history, and it keeps
the deploy in gap 1 unblocked.

**4 — Close what is already decided.** PR #521 has zero commits that #528 does not have — it is
fully contained and can close with that evidence. #516 is the other separately decidable one and
is not part of the codex stack. The 13 `codex/v4-*` drafts stay open until step 3 rules, but the
leaf drafts are not the only copy of the accounts work: #512 alone carries all 44
`src/personal_accounts/` files, so the stack can be parked without losing the subsystem.

**5 — Then** the formal DoD check, the improvement cycle and the tracker currency pass. All
three measure the release tree, so all three are worth running only once steps 1–3 have
settled what that tree contains.

## What this does not change

The `NFR.SEC.7` deploy recommendation stands on its own merits and is unaffected. It is a
security control in a running process and should not wait for the scope question.

## Re-deriving the counts

Every measured figure above came from one of these. A reader who suspects drift should re-run
them rather than trust the numbers, which are true as of 2026-09-11 and not maintained.

| Figure | Command |
|---|---|
| Commits since fork | `git rev-list --count c3626cf8..<branch>` |
| Module presence and file counts | `git ls-tree -r --name-only <branch> \| rg <module>` |
| `idempotency.rs` sizes | `git show <branch>:src/idempotency.rs \| wc -l` |
| Open PR census | `gh pr list --state open --limit 30` |
| `codex/v4-next-integration` CI | `gh pr view 512 --json mergeable,mergeStateStatus,statusCheckRollup` |
| Baseline ledger | `python3 scripts/release/count-release-criteria.py` |
| Release readiness | `python3 scripts/release/check_scope_acceptance.py --release` |
