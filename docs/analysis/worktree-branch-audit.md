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

## Supersession verdicts — four unmerged branches (2026-09-19)

Verified read-only against `origin/main`. Patch-id matching (`git cherry`) is
useless here: every commit came back unmatched because the work was rebased and
redesigned before it landed, so each row below rests on symbol and behaviour
comparison instead.

| Branch | Verdict | Evidence | PR |
|---|---|---|---|
| `work/mrtr-bridge-reconcile` | SUPERSEDED except one commit | bridge + idempotency on main; EXT.1 parser fix was not | #NNN |
| `feat/v4-stdio-production-caller` | SUPERSEDED | bridge half on main; stdio half is MIK-7387, deliberately parked | — |
| `feat/v4-mrtr-bridge-wiring` | SUPERSEDED | wiring on main under renamed symbols | — |
| `lane/roots-wiring` | SUPERSEDED | both ROOTS commits merged to main | — |

### `feat/v4-mrtr-bridge-wiring` — SUPERSEDED

The deliverable is on main under renamed symbols: the branch's `BridgeDispatch`
and `BridgeMetrics` are `BridgeDispatcher` (`src/gateway/meta_mcp/invoke.rs:820`)
and `TracingBridgeObserver` (`:899`), called from `invoke_tool_traced` at
`:2051`. The branch's session-declaration store — `record_session_declaration`,
`session_declaration`, `clear_session_declaration` — appears nowhere on main:
main reads the declaration off `caller.input_capabilities` and the channel off
`caller.channel` instead. That store is the design main dropped, so the branch's
plumbing for it is not missing work, it is abandoned work.

Staleness confirms it: merge base 2026-09-12, main has gained 281 commits since,
and the two-dot diff is dominated by deletions the branch would reintroduce
(`invoke.rs` −785, `mod.rs` −490, `streaming.rs` −375).

### `lane/roots-wiring` — SUPERSEDED

Both halves are on main:

- ROOTS.1 (delete the unwired forward) — `e0cd61b5 fix(proxy): delete the
  unanswerable roots/list forward`
- ROOTS.2 (forward as an answerable request) — `05a65489 feat(roots): correlate
  a roots/list request with the client's reply`, live at
  `src/gateway/proxy.rs:394`

The 134-file / 12,405-line diff is not this branch's content. Merge base is
2026-09-08 and main has gained 385 commits since; the large test files in the
diff (`mik_7215_control3b_acs.rs`, `nfr_perf3_soak.rs`,
`mik_7272_sub4_three_routes.rs`) belong to other lanes and are swept in by the
old base. Nothing here should be carried forward.

### `feat/v4-stdio-production-caller` — SUPERSEDED

The bridge half is superseded for the same reason as
`feat/v4-mrtr-bridge-wiring`: it carries the same declaration-store design
(`invoke.rs` −598 against main).

The stdio half is genuinely absent from main, and that absence is deliberate,
not an oversight. `stdio_caller_context` (`src/gateway/server/mod.rs:3313`) sets
`input_capabilities: Declared::NONE` and `channel: &NoClientChannel`, and the
bridge call site documents the refusal it produces and names what lifts it:

> That is what keeps the deliberate stdio refusal documented on
> `NoClientChannel` intact, and MIK-7387 the only thing that lifts it.
> — `src/gateway/meta_mcp/invoke.rs:2114`

So this branch is an unlanded attempt at MIK-7387 built on the design main
replaced. Its one independently interesting piece — dispatching stdio requests
off the reader loop behind a single writer task — is not on main (main's stdio
loop is still sequential), but it is entangled with the dead declaration store
and overlaps `codex/v4-stdio-account-wiring`, which a peer owns. Redo MIK-7387
against main's caller-context design rather than rebasing this.

### `work/mrtr-bridge-reconcile` — SUPERSEDED except `bbe5da15e`

Superseded, with proof at three levels:

- `tests/mik_7212_mrtr7_bridge_acs.rs` and `tests/mik_7212_mrtr7_stdio_acs.rs`
  both give an **empty** `git diff origin/main work/mrtr-bridge-reconcile`.
  The acceptance rows are byte-identical to main.
- The four `fix(bridge):` idempotency commits are all answered on main's
  `match bridge.run(...)` error arm (`src/gateway/meta_mcp/invoke.rs:2129-2156`),
  at finer granularity: `BackendFailed { dispatch: MayHaveActed }` settles the
  key with `withheld_side_effect()`, while `Deadline`,
  `RequestBudgetExhausted`, `Refused`, `Delivery` and `RoundsExhausted` keep the
  release-on-drop default because a backend parked on a question has not acted.
  A round that never left the gateway is separated by `Dispatch::NeverReached`,
  derived from `e.is_pre_dispatch()` at `:875`.
- `src/gateway/streaming.rs` (+150) adds `declaration_owner`,
  `set_declaration_owner` and a `session_gone` hook that calls
  `clear_session_declaration`. Main has no declaration store to clear, so this
  is plumbing for the abandoned design.

**The exception is `bbe5da15e` — MIK-7272.EXT.1 phase 2 — which is live.** It
fixes a defect that is still present on main. Two parsers read the same client
declaration and disagree:

- `declares_tasks_extension` (`src/gateway/router/handlers.rs:182`, gating at
  `:1034`) ends in `.is_some_and(|ext| ext.get(TASKS_EXTENSION).is_some())` —
  presence only.
- `ExtensionSet::from_capabilities` (`src/protocol/extensions.rs:88-98`) filters
  on `settings.is_object()`, its own comment reading "presence is not
  agreement."

So a client declaring `{"extensions": {"io.modelcontextprotocol/tasks": 3}}`
passes the live tasks gate on main while the canonical parser refuses the same
bytes, and enters task behaviour it never validly negotiated. The fix deletes
the hand-rolled reader, has `RequestShape::Modern` carry the `ExtensionSet` the
classifier parses once, and points the gate at `declared_extensions()`.

Falsifier, observed rather than predicted: disabling the gate turns
`ac_ext_1_e6_a_non_object_settings_value_does_not_declare_the_extension` red at
`left: 200, right: 400`, which matches the failing-first observation recorded in
the original commit. The row drives the real in-process router, so a parse-level
assertion cannot pass while the gate disagrees.

### Ledger rows for central update

Not edited here. `docs/requirements/RELEASE-4.0.0-scope-status.json` was
reverted out of the PR and `docs/requirements/RELEASE-4.0.0-criteria-status.md`
was never touched.

- **NFR.CONFORMANCE.1** — the EXT.1 PR empties `TRACKED_GAPS` in
  `tests/mik_7272_conformance.rs` and takes the conformance matrix to 21 of 21
  COVERED, 0 UNCOVERED. The ledger row still reads `pending`; it is the lead's
  call whether that becomes `met`.

### Safe to delete (lead executes behind the archive gate)

All four, once the EXT.1 PR lands. `feat/v4-mrtr-bridge-wiring` also holds an
agent worktree at `.claude/worktrees/agent-af357ba01f09a457f`.
