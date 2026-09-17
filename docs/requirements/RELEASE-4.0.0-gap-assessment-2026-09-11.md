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
| 6 | 16 open PRs, none merged | 13 stacked `codex/v4-*` drafts plus #528, #521 and #516 | #521 is fully contained in #528; #516 is 6 own commits on top of the codex lineage; the codex stack follows gap 3 |

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
fully contained and can close with that evidence.

#516 closes as superseded, and the commit counts are what make that hard to see. It forks from
`main` at the same `c3626cf8` the codex line does, so it reports 1,699 commits ahead of `main` —
but only **6** of those are its own (`origin/codex/v4-next-integration` is 270 commits ahead of it;
it is 6 ahead of codex). Those 6 are the MIK-7215 CONTROL.4 idle-session reaper. That feature is
already on the release line: all four `tests/mik_7215_control4_*.rs` files exist on `main` and on
`feat/sub2b-outbound-mint`, and each is **byte-identical** to #516's copy (compared by blob SHA,
2026-09-11). `MIK-7215.CONTROL.4` reads MET accordingly. Nothing needs re-cutting from #516; it
closes citing its own criterion, which is the disposition
[`RELEASE-4.0.0-CLOSE-PLAN.md:404`](../release/verify/RELEASE-4.0.0-CLOSE-PLAN.md) already
recorded. The count is a lineage artefact, not unlanded work.

The 13 `codex/v4-*` drafts stay open until step 3 rules, but the
leaf drafts are not the only copy of the accounts work: #512 alone carries all 44
`src/personal_accounts/` files, so the stack can be parked without losing the subsystem.

**5 — Then** the formal DoD check, the improvement cycle and the tracker currency pass. All
three measure the release tree, so all three are worth running only once steps 1–3 have
settled what that tree contains.

## PR triage outcome — 2026-09-11

Step 4 executed for everything decidable without the step-2 grading.

| PR | Verdict | Evidence |
|---|---|---|
| #528 `feat/sub2b-outbound-mint` | the release line | carries the counted ledger work; CI green; MERGEABLE |
| #522 `fix/windows-stdio-appdata` | **merged** 2026-09-11 13:07Z | no `src/` delta; the cheapest merge on the board |
| #521 `fix/gh517-protocol-negotiation` | **closed** — fully contained | zero commits `#528..#521`; GH #517 landed separately as #520 |
| #516 `fix/mik-7215-control4-reaper` | **closed** — superseded | its four CONTROL.4 suites are byte-identical on `main` and #528 |
| #499–#513 (13 `codex/v4-*` drafts) | held | disposition follows the lineage decision in step 3, which needs step 2 |

Open PRs fell from 16 to 14. The remaining 13 drafts are one decision, not
thirteen: they are the accounts/OpenWebUI/task-signing stack on the codex
lineage, and #512 alone carries all 44 `src/personal_accounts/` files, so
parking the leaves loses nothing.

## Step 2 outcome: the DISCOVERY package is graded — 2026-09-11

The plan's step 2 was to grade the five discovery-package criteria on the release line before
deciding anything about the codex lineage. That grading is done and recorded in
`RELEASE-4.0.0-scope-status.json`. **None reaches MET**, and the five rows stay `pending` with
the grade and its citations now in the note rather than "not yet graded".

| ID | Grade | Why it does not reach MET |
|---|---|---|
| MIK-3274.RANKING.1 | ABSENT | `score_text_relevance` is substring plus a 20-group synonym table (`src/ranking/scoring.rs:190`, `:17`); no edit distance, acronym or word-boundary matching in `src/ranking/`, and none of the 56 ranking tests covers abbreviation, word boundary, Unicode or Code Mode glob |
| MIK-3274.RANKING.2 | UNTESTED | Both invariants are implemented and citable — authorization filters before collection (`search.rs:200`), ranking precedes truncation (`:763`), usage is multiplicative so 0.0 stays 0.0 (`ranking/mod.rs:396`) — but no test asserts either ordering |
| MIK-3274.RANKING.3 | NEEDS-MEASUREMENT | No corpus, baseline or frozen threshold exists; the performance contract freezes the workload rows only. The freeze was never recorded, and cannot now be produced as written because ranking already shipped |
| MIK-7332.DISCOVERY.1 | ABSENT | Tiered disclosure exists (`src/gateway/search_disclosure.rs:40`) but neither positive control from the test row does; `discovery_tests.rs` covers auto-discovery and shadow scan only |
| MIK-7334.CATALOGUE.1 | ABSENT | `tools_cache` is one `CachedMetadata<Vec<Tool>>` per backend with no identity key (`src/backend/mod.rs:81`), beside a pool that *is* per-identity (`:47`) |

The grades are static evidence: every citation is a read line, no test was run. That is enough to
establish absence, which is what step 2 asked; it is not enough to promote anything to MET.

`MIK-7334.CATALOGUE.1` is the row worth reading twice. MIK-6735 made transport sessions
per-identity and left tool metadata on a single shared cache, so an identity-dependent catalogue
crosses callers by construction rather than under a race — it needs no timing to reproduce.

**What this settles for step 3.** The release line does not deliver these five. That is now a
measured fact rather than an assumption, so the lineage question is no longer "does mint already
have this" but "does the codex stack deliver any of the five, and at what merge cost" — the same
grading, run against `codex/v4-next-integration`. Nothing about the 13 held drafts changes until
that second grading exists.

## Step 3 outcome: the codex lineage delivers none of the five — 2026-09-11

Step 2 established that the release line does not meet the discovery package. Step 3 asked the
only question that could still justify merging 1,963 commits: does `origin/codex/v4-next-integration`
deliver any of them? Graded the same way, against the construct rather than the ticket id.

| ID | codex grade | vs release line | decisive evidence |
|---|---|---|---|
| MIK-3274.RANKING.1 | ABSENT | EQUAL | `src/ranking/{scoring.rs,mod.rs,tests.rs}` are byte-identical on both refs (blobs `a5d786ac`, `e351b088`, `e55c15fe`); the fuzzy/abbreviation/word-boundary grep is empty on both. The only `levenshtein` on either ref is the invoke-time "did you mean" at `src/gateway/meta_mcp_helpers.rs:47` |
| MIK-3274.RANKING.2 | UNTESTED | **BEHIND** | Same implementation sites (`search.rs:200` filter, `:762` rank, `:767` truncate) and still no test — `git grep -ln backend_allowed origin/codex/v4-next-integration -- tests/` is empty. The file differs by 2 insertions and 6 deletions, all of them codex dropping the release line's step-index argument on `invoke_tool` |
| MIK-3274.RANKING.3 | NEEDS-MEASUREMENT | EQUAL | The `benchmarks/` tree object is identical on both refs; its only content is one unrelated live-agent result file |
| MIK-7332.DISCOVERY.1 | ABSENT | EQUAL | `src/gateway/search_disclosure.rs`, its tests, the e2e file, `tests/discovery_tests.rs` and `tests/tool_list_tests.rs` are byte-identical on both refs. Codex covers tiers only, never the four conjuncts together |
| MIK-7334.CATALOGUE.1 | ABSENT | EQUAL | Codex has the same construction at `src/backend/mod.rs:64` — `tools_cache: CachedMetadata<Vec<Tool>>` with no identity key, beside a per-identity `pool` at `:51`. No `CachedMetadata` keyed by any identity type anywhere on the branch |

**Nothing to salvage for this package, and one regression to avoid.** Four of five rows rest on
blob-identity rather than on a search, which is the stronger evidence: a matcher cannot hide in a
file whose bytes are equal. The fifth is behind. The codex-only work is real but it is elsewhere —
`personal_accounts/`, `task_service/`, `message_signing/`, `idempotency/`, `admission/`, `openwebui`,
roughly 160 codex-only files under `src/`, none under ranking, discovery or disclosure.

**Disposition of the 13 held `codex/v4-*` drafts.** They stay open and stay out of 4.0.0. Closing
them would discard the accounts and task-service work they carry, which no ruling has rejected —
it is simply not in this release's scope, and `#512` alone holds all 44 `src/personal_accounts/`
files. They are held, not abandoned: the condition for revisiting is a scope decision about
accounts for a later release, not anything about the discovery package, which they do not affect.

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
| #516's own commits | `git rev-list --count origin/codex/v4-next-integration..origin/fix/mik-7215-control4-reaper` |
| #516 superseded | `git rev-parse <branch>:tests/mik_7215_control4_reap_count_acs.rs` on both branches |
| Baseline ledger | `python3 scripts/release/count-release-criteria.py` |
| Release readiness | `python3 scripts/release/check_scope_acceptance.py --release` |
