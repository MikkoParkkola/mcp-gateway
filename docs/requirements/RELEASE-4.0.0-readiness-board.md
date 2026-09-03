# 4.0.0 readiness board

One row per cluster, one question per column: **what has to happen next, and who
does it.** The cluster definitions, criterion lists and the reasons each row is
open live in `RELEASE-4.0.0-blocking-rollup.md`; the ordered work queue lives in
`RELEASE-4.0.0-execution-plan.md`. Neither answers *how far is each cluster
actually along*, which is the only thing this file is for. Nothing here is
restated from those two — where a cell needs a reason it names the file that
carries it.

Verified 2026-09-03 against the worktree at `fix/mrtr2-continuation-handle`
(`69faf515`). A cell reading **no** means a search found nothing, not that
nobody intends to do it.

| # | cluster | rows | design | test plan | plan reviewed | code | the one thing blocking |
|---|---|---|---|---|---|---|---|
| A | continuation envelope (MIK-7212) | 22 | yes — `2026-08-30-mrtr-wiring.md`, `2026-08-30-shared-continuation-state.md`, `2026-09-01-continuation-telemetry.md` | yes — `2026-09-02-mrtr-test-plan.md` | yes | **partial** — 85 files, +13,532/−623 vs `main`; the envelope, keyring, ledger and 19 component cases exist, the route that uses them does not | `src/gateway/router/handlers.rs:1048-1065` still answers every retry with *"retry forwarding is not available on this build"*. 15 of the 19 cases are red on that one cause, and no PR can make a row true that the code refuses |
| B | era detection (MIK-7217) | 5 | partial — `2026-08-31-discover-outbound-era-probe.md` covers `DISCOVER.4`; **`NFR.OBS.3` appears in no design document** | no | no | no | a design that covers all five rows, not four |
| C | revision surface (MIK-7272) | 7 | scattered across five files (`sub-4-idempotency-wiring`, `sub-1-3-get-mcp-era-gate`, `task-1-tasks-extension`, `cluster-b-*`) | no | no | no | five half-wirings with no single owner and no plan that reads as one change |
| D | response-cache keying (MIK-7213) | 2 | yes — `2026-08-31-cluster-f-response-cache-keying.md` | yes — same stem, `-test-plan.md` | no | no | the test plan has never been through the dual-vendor gate |
| E | performance measurement | 2 | n/a — this is a measurement, not a design | no | no | n/a | a run against 3.5.0 **on Spark**. A Mac number is worse than none |
| F | compatibility facts | 2 | `NFR.COMPAT.4` only — `2026-09-02-conformance-matrix.md` | no | no | no | `NFR.COMPAT.1` is a one-line default flip that cannot land before cluster A merges |
| G | stdio dispatch | 3 | yes — `2026-09-02-cluster-g-stdio-dispatch-parity.md` | yes — `2026-09-02-cluster-g-test-plan.md` | **round 5, unresolved** | no | the gate itself: see the reviewer state below |
| — | residue | 10 | mixed | no | no | no | ten independent rows, each needing its own decision |

53 blocking rows. **One cluster has code.** Six have no branch, no worktree and
no commit — verified against `git worktree list` and `git branch`, which show
`fix/mrtr2-continuation-handle` (cluster A) plus two unrelated gap branches.

## The gate is the binding constraint, not the writing

Cluster G's test plan is at review round 5 and the reason it has not converged
is no longer the document. Reviewer state, 2026-09-02:

| vendor | state | why |
|---|---|---|
| Codex / GPT | **was hard-down all afternoon** | `codex` 0.151.0 refuses every directory as untrusted under `--ephemeral`, because ephemeral discards the persisted trust list. Fixed in `~/.claude/bin/gpt-review` by adding `--skip-git-repo-check`; the read-only sandbox already bounds the blast radius |
| Grok | ERROR | xAI balance exhausted (HTTP 402) |
| GLM-5.3 | ERROR | `finish_reason='length'` on three consecutive attempts — the Flash distillation cannot hold a 26 KB payload |
| Kimi K3 | ERROR | returns prose with no parseable verdict line |

Every vendor failed for its own reason on the same day, and the wrapper defect
made the primary reviewer look like a fourth outage. That is the honest state of
the gate; per §PA a nonzero exit is `ERROR`, never a scraped verdict.

## Readiness order — every cluster, none dropped

The queue is `RELEASE-4.0.0-execution-plan.md`, whose item 1 is already this
wiring increment. What follows is the readiness view of the same order: where
each of the seven clusters and the residue enters it, so that no group of rows
is left without a next step.

1. **Wire the retry-forwarding route** at `src/gateway/router/handlers.rs:1048-1065`
   — the location the execution plan's item 1 does not name. One route, and the
   stated cause of **all 22 rows of cluster A**: the whole `MRTR` set,
   `NFR.SEC.2/3/4` (nothing mints or opens on the live path, so the eight named
   security fixtures have nothing to exercise), `NFR.OBS.4` (no counters to emit)
   and `NFR.PERF.3` (no in-flight state to soak). It also turns 15 red cluster-A
   cases green, and it **deletes** the pinned-count header section in
   `tests/mik_7212_mrtr_component_acs.rs`, whose scaffolding describes only the
   pre-wiring tree.
2. **Then land cluster A.** Open the PR, run the gates at the head that will be
   tagged. Merging before step 1 ships 22 rows that the code still refuses.
3. **Put D through the gate.** Cluster D is the cheapest pair of rows on the
   board: design and test plan both exist and neither has been reviewed. It needs
   a dual-vendor pass and the implementation that follows, and it waits on nothing.
4. **Give B and C a design each.** B needs `NFR.OBS.3` covered — that row is
   cluster B's, verifying `DISCOVER.4-5`, and the era detector is what makes it
   observable. C needs its five half-wirings written as one change with one owner.
5. **Book the Spark run for E.** It depends on nothing and nobody has started it.
   `NFR.PERF.4` is residue rather than cluster E, and a separate cheaper fix:
   `benchmarks/public_claims.json:4-6` records 14/16/17 against a drifted README.
6. **Close G's gate** now that the reviewer is reachable again.
7. **Triage the residue as one pass.** Ten rows, each independent, each needing a
   decision rather than an increment — `HEADER.9` waits on B's per-backend era, so
   it cannot come first. One session, one line of disposition per row, and the ones
   that turn out to be code queue behind whichever cluster owns their file.

Order is dependency, not preference: everything in cluster A waits on step 1 and
F waits on A, while steps 3, 5 and 7 wait on nothing at all. Steps 1, 3 and 5 are
independent and can run at the same time.
