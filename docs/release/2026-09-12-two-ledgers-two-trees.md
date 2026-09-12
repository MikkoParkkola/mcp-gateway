# The release is graded by two criteria sets on two trees (2026-09-12)

Measured this date against `origin/main` (`bd1adbb4`) and
`fix/v4-integration-ci-green` (`d5f1c273`).

## The two sets are disjoint and live on different trees

| Set | File | `origin/main` | `fix/v4-integration-ci-green` |
|---|---|---|---|
| Protocol / NFR | `RELEASE-4.0.0-criteria-status.md` | **144 / 151 MET** | 126 / 149 MET (stale copy) |
| Account + security scope | `RELEASE-4.0.0-scope-status.json` | 1 met / 30 pending | **9 met / 22 pending** |

Counts recognise `MET (structural)` and `MET (caveat)` as MET; a regex matching
only the bare token `MET` under-reports main by nine rows.

## The branch ledger is strictly stale, not independently graded

Row-by-row diff of the two copies of `RELEASE-4.0.0-criteria-status.md`:
eighteen rows are MET on main and not on the branch; **zero rows are MET on the
branch and not on main**. Every burndown row published from the branch copy
before this date therefore measured the branch's stale ledger, not the release
line. The "56 -> 46 open" figure is withdrawn.

## What is genuinely open

- `NFR.PERF.1` — PARTIAL on both trees. `session_sandbox/check_tool_denied`
  regressed +6.07% against the >5% P50 bound (criterion's own interval
  `[+5.05%, +7.11%]`), measured on `spark` 2026-09-03.
- 22 of the 31 supplemental scope criteria — pending on the branch, and
  ungradeable on main because the code they grade is not there.

Not open, despite reading as open:
- `MIK-7272.ORDER.3b`, `NFR.COMPAT.3` — N/A.
- `NFR.SEC.7` — phantom; recorded in `RELEASE-4.0.0-blocking-rollup.md`.
- `MIK-7214.HEADER.7-9`, `MIK-7217.DISCOVER`, `MIK-7246.CONFIRM` — rows in the
  audit summary table, not criteria rows. A regex anchored on `| MIK-` picks
  them up and inflates both numerator and denominator.

## The two trees diverged bidirectionally

`src/personal_accounts` is 44 files on the branch and absent from main, so main
cannot satisfy the scope set at all. In the other direction main is ahead on
files the branch also touched — `src/protocol/trace.rs` carries 29 lines on main
that the branch lacks.

`git merge-tree HEAD origin/main` reports **415 conflicted paths**, many
`add/add`: both lines built the same protocol work independently. Across `src`
and `tests` 375 files differ, 232 of them by 100 lines or more. PR #512
(`codex/v4-next-integration` -> `main`) is `CONFLICTING/DIRTY` on this same
divergence, with CodeQL red.

`fix/v4-integration-ci-green` is 45 commits ahead of `codex/v4-next-integration`
and 1 behind it (`47f2c23d`), so the CI-green work sits on top of the release
PR's head and is not itself on any open PR.

## Resolution: the branch now grades against the release line (2026-09-12)

The stale copies were replaced with `origin/main`'s, so the branch and the
release line answer "how much is done" from one ledger:

- `RELEASE-4.0.0-criteria-status.md`, `RELEASE-4.0.0-blocking-rollup.md` and the
  surrounding scope documents are taken from `origin/main`.
- `count-release-criteria.py` is taken with them. The branch copy's criterion-id
  regex had no ` (clause: <word>)` arm, so it read main's two split
  `MIK-7272.EXT.1` rows as malformed. A clause suffix is part of a row's
  identity; the older regex cannot see rows the release line already splits.
- `check_scope_acceptance.py --check` reported **19 baseline blocking rows** off
  the stale copy against main's **1**. Eighteen of those nineteen were rows main
  had already resolved. `NFR.SEC.7` is the one that survives, and it is the
  phantom recorded above.

The two scope-contract gradings were disjoint rather than contradictory. The
branch graded the account and lifecycle rows; main graded `MIK-3274.RANKING.2`,
`.3`, `MIK-7332.DISCOVERY.1` and `MIK-7334.CATALOGUE.1`. The contract now holds
the union. `MIK-3274.RANKING.1` keeps the branch note, which withdraws the
2026-09-12 MET grade; the supplemental set therefore reads 8 met, not 9.

`scripts/release/check_tag_manifest.py` and its two test files stay on the
release line. They assert against `.github/workflows/release.yml` and
`docker.yml` as main ships them, and six of their checks fail on this branch's
older workflows — evidence that the branch trails the release line on release
tooling as well, not a defect to fix here.
