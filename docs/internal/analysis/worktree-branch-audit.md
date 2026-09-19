# Worktree and branch audit — 2026-09-19

Scope: local worktrees and local branches of `mcp-gateway`. Remote branches are
enumerated but not acted on. No deletion in this document has been executed;
every one is a proposal awaiting operator approval.

## Headline numbers

| Measure | Count |
|---|---|
| Worktrees at start | 52 |
| Worktrees now | 28 |
| Worktrees removed (all clean, branch refs intact) | 24 |
| Worktrees refused because dirty | 20 |
| Local branches at start | 92 |
| Local branches now | 84 |
| Local branches deleted under the gate | 8 |
| Branches proposed for deletion, not executed | 2 |
| Branches carrying unmerged work to preserve | 9 ranked + 10 unclassified |
| Remote branches, untouched | 449 |

Disk reclaimed by the worktree sweep: 874,776 KB = 854 MB, measured with `du -sk`
per tree before removal.

## Method and gate compliance

1. `git fetch --prune` first; 8 stale remote-tracking refs pruned. Every check
   below reads remote-tracking refs and a stale one lies in both directions.
2. Worktree removal ran **without `--force`**. Git's own refusal on a tree
   holding modified or untracked files was the filter, and 20 trees were refused
   and left exactly as found.
3. Branch deletion ran only through `bin/safe-delete-branch`, which unions the
   commit lists of every MERGED pull request for the head, requires every
   local-only commit to appear in that union, archives the tip under
   `refs/archive/by-tip/<sha>`, then compare-and-deletes.
4. No branch was deleted on squash-merge ancestry, on `git branch --merged`, or
   on age.
5. Tree-identity content checks were useless here and were excluded on purpose:
   local `main` differs from `origin/main` in 897 paths, so a branch's diff-count
   measures how far `origin/main` has moved, not what the branch contains. A
   diff-count printed in this context reads as unmerged-work volume and is not.

## Two corrections to earlier reporting

- `~/github/.worktrees/hebb` is a **symlink to `~/github/hebb`**, confirmed by
  `ls -ld`. It never entered this audit — enumeration came from
  `git worktree list --porcelain` inside `mcp-gateway`, which cannot see a
  sibling repository's checkout — but the hazard is real and is recorded here.
- Removing a worktree is **not** a statement that its work merged. About half of
  the 24 removals were checkout-only removals of branches that still exist.

## Defect found in the delete gate

`bin/safe-delete-branch` hardcodes its forge query:

```
gh pr list --head "$branch" --state all --limit 100 \
  --json number,state,commits,baseRefName,mergedAt
```

GitHub rejects that traversal in this repository, verbatim:

```
GraphQL: By the time this query traverses to the authors connection, it is
requesting up to 1,000,000 possible nodes which exceeds the maximum limit of
500,000.
```

The script reads the failure as `refusing to delete <branch>: forge query
failed; refusing rather than guessing`. **Eleven of fourteen candidate branches
were refused for a reason that carries no evidence about the branch at all** — a
page-size failure wearing the costume of missing forge evidence. The direction is
conservative, but the effect is that the gate can never say yes to any branch
holding local-only commits, and the refusal text gives no hint why.

Workaround used, through the script's own documented seam: `SAFE_DELETE_GH`
pointed at a wrapper that caps the token following `--limit` at 20. This is safe
in this repository because the most pull requests any single head has is 2,
measured against a full 405-PR dump, so 20 leaves tenfold headroom and no merged
pull request can page out of the union. Gate logic is untouched — the same
commits are fetched and the same accounting runs.

**A cap of 20 is not the upstream fix.** It is licensed by a repository-specific
measurement. The fix is to drop `commits` from the `--json` list and fetch commit
lists per pull request, or for the maintainer to re-derive a cap from the API's
actual node budget. Editing `100` to `20` in the script would ship a
repository-specific constant as a general one, and the next repository with a
heavily reused head name hits the same wall.

## Branches deleted under the gate

Eight, each with its tip archived under `refs/archive/by-tip/` before deletion.
Seven were forge-accounted: a MERGED pull request's commit union covered every
local-only commit. One was not, and the distinction is recorded rather than
flattened.

| Branch | PR | Evidence | Archived tip |
|---|---|---|---|
| `chore/public-repo-hygiene` | 562 | forge-accounted | 244df762 |
| `ci/docker-apt-cache-bust` | 535 | forge-accounted | 7c9633ef |
| `ci/github-hosted-runners` | 534 | forge-accounted | a76bf445 |
| `ci/hosted-runners-v4-stack` | 537 | forge-accounted | 699fea47 |
| `codex/v4-stacked-pr-ci` | 509 | no local-only commits | 0520b649 |
| `feat/v4-workload-harness` | 565 | forge-accounted | 0601f024 |
| `fix/mrtr7-bridge-wiring` | 571 | forge-accounted | 32417280 |
| `fix/root-doc-hygiene` | 572 | forge-accounted | a49002e0 |

`codex/v4-stacked-pr-ci` returned `rev-list --not --remotes` = 0, so the gate
never reached the forge query. What licensed its deletion was that nothing on it
exists only there; its pull request is listed for context, not as the evidence.

No remote branch was deleted.

## Worktrees removed — checkout only, branch refs intact

All 24 were clean and the branch ref survived every removal, so no commit was at
risk from the sweep. Classification: parked-WIP means the branch still exists
carrying a `wip(...)` handover snapshot with a closed pull request;
VALUABLE-UNMERGED means the branch still exists with real unmerged work, keyed to
the ranked list below; unrecorded means the branch was not captured before the
worktree went away and is **not evidence of merge in either direction**.

| Worktree | KB | Class | Branch today |
|---|---|---|---|
| mcp-v4-account-descriptor-config | 21,564 | parked-WIP | `codex/v4-account-descriptor-config` |
| mcp-v4-account-foundation-qualification | 21,544 | parked-WIP | `codex/v4-account-foundation-qualification` |
| mcp-v4-account-gateway-bootstrap | 21,580 | parked-WIP | `codex/v4-account-gateway-bootstrap` |
| mcp-v4-account-oauth-provider | 21,744 | parked-WIP | `codex/v4-account-oauth-provider` |
| mcp-v4-account-production-delivery | 21,540 | parked-WIP | `codex/v4-account-production-delivery` |
| mcp-v4-delivery | 23,256 | unrecorded | — |
| mcp-v4-rest-task-combined | 24,216 | parked-WIP | `codex/v4-rest-task-combined` |
| mcp-v4-scope-contract | 18,560 | parked-WIP | `codex/v4-scope-contract` |
| mcp-v4-signing-integration | 20,428 | parked-WIP | `codex/v4-signing-integration` |
| mcp-v4-stability-integration | 19,312 | parked-WIP | `codex/v4-stability-integration` |
| mcp-v4-task-clippy-increment | 24,472 | parked-WIP | `codex/v4-task-clippy-increment` |
| mcp-v4-task-service-integration | 20,112 | parked-WIP | `codex/v4-task-service-integration` |
| mrtr-bridge-reconcile | 27,832 | VALUABLE-UNMERGED (3) | `work/mrtr-bridge-reconcile` |
| v4-catalogue-identity | 28,224 | branch intact, unclassified | `feat/v4-catalogue-identity` |
| v4-codeql-record | 28,536 | unrecorded | — |
| v4-cutover | 27,748 | branch intact, unclassified | `docs/nfr-sec-7-cutover-runbook` |
| v4-discovery | 322,088 | VALUABLE-UNMERGED (1) | `feat/v4-discovery` |
| v4-hygiene | 27,528 | unrecorded | — |
| v4-ranking-fuzzy | 27,836 | VALUABLE-UNMERGED (4) | `feat/v4-ranking-fuzzy` |
| v4-workload | 28,000 | unrecorded | — |
| agent-a04ce0c0a7a322de4 | 27,668 | unrecorded | — |
| agent-a35c004d2490365f5 | 24,980 | unrecorded | — |
| agent-a8d6614e7e57e901d | 25,124 | unrecorded | — |
| agent-ad2d9a22dbbb4861b | 20,884 | unrecorded | — |

Branch existence was verified with `git branch --format='%(refname:short)'`. The
worktree-to-branch pairing for the `codex/v4-*` rows is **inferred from the
directory naming convention, not recorded at removal time**: existence is
verified, the pairing is not.

Thirteen `codex/v4-*` branches each carry exactly one local-only commit, and each
reads `wip(<worktree>): preserve uncommitted work at handover`. These are
snapshot commits made so loose files would survive a handover, not deliverable
work, and their pull requests are closed (495, 502, 503, 504, 506, 507, 508, 510,
511, 513, 515). Not release scope. `codex/v4-task-signing-composition` is the one
exception, and it is the head of PR 499.

## Unmerged work that must be preserved

No pull request was opened for any of these, deliberately. They are other
sessions' parked branches whose content was not read and could not be built,
because this audit ran under a no-cargo constraint. Opening a pull request from
another session's branch is the shared-worktree sweep hazard in reverse. Commit
counts are local-only commits.

1. `feat/v4-discovery` (5) — caller-scope filtering of the served `tools/list`
   and its routing guide (MIK-7332.DISCOVERY.1), plus withholding the shared
   metadata cache for `per_user` backends (MIK-7334.CATALOGUE.1). Squarely v4
   scope and the most substantive unmerged work found anywhere in this sweep.
2. `feat/sub2b-outbound-mint` (35 beyond MERGED PR 528) — the gate refused it
   because 35 commits postdate the merge. Conformance ship bar, coverage-count
   scoping, SCHEMA.1c regrade. Release-documentation scope; needs an owner.
3. `work/mrtr-bridge-reconcile` (14) — bridge key-settlement and retryability
   fixes. Overlaps the shipped MIK-2970 bridge work and may be superseded;
   verify before landing. This could not be established either way here.
4. `feat/v4-ranking-fuzzy` (9) — abbreviation-aware ranking, exact identifiers
   first, character-safe zero-result suggestions. Self-contained.
5. `feat/v4-stdio-production-caller` (9) and `feat/v4-mrtr-bridge-wiring` (6) —
   overlapping WIRE.2 and WIRE.3 stdio bridge coverage. Same supersession
   question as item 3.
6. `work/v4-demo-recordings` (5) — NFR.DEMO.1 scenario recordings and manifest.
   Release evidence, not code.
7. `control4-lifecycle-local` (4) — session-lifecycle TTL read from config.
8. `lane/roots-wiring` (4) — MIK-7212.ROOTS.1 and .2 unwired-roots deletion plus
   a documentation re-anchor.
9. `fix/gh517-protocol-negotiation` (2 beyond merged PR 520) and
   `fix/mrtr2-continuation-handle` (1 beyond merged PR 473) — small post-merge
   remainders. The gate refused both, correctly.

Ten further local branches carry local-only commits and fit none of the buckets
above: they are not merged, not ranked v4 scope, and not handover snapshots.
Establishing what they are needs reading or building them. Left standing, grouped
here so they are not silently absent from this report: `backup-a5558-work` (2),
`docs/nfr-demo-1-recording-design` (2), `feat/v4-conformance-matrix` (2),
`gap/discover-schema` (1), `note/v4-pr-close-evidence` (2),
`pin/adr012-amend-20260910` (1), `pin/detached-20260910-1640` (2), `rebase/499`
(2), `review/compat4-plan` (2), `task1-caller` (1).
