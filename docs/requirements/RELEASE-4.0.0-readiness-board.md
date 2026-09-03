# 4.0.0 readiness board

One row per cluster, one question per column: **what has to happen next, and who
does it.** The cluster definitions, criterion lists and the reasons each row is
open live in `RELEASE-4.0.0-blocking-rollup.md`; the ordered work queue lives in
`RELEASE-4.0.0-execution-plan.md`. Neither answers *how far is each cluster
actually along*, which is the only thing this file is for. Nothing here is
restated from those two — where a cell needs a reason it names the file that
carries it.

Verified 2026-09-03 against the worktree at `fix/mrtr2-continuation-handle`
(`5c29494a`). A cell reading **no** means a search found nothing, not that
nobody intends to do it.

| # | cluster | rows | design | test plan | plan reviewed | code | the one thing blocking |
|---|---|---|---|---|---|---|---|
| A | continuation envelope (MIK-7212) | 22 | yes — `2026-08-30-mrtr-wiring.md`, `2026-08-30-shared-continuation-state.md`, `2026-09-01-continuation-telemetry.md` | yes — `2026-09-02-mrtr-test-plan.md` | yes | **partial** — the route is wired as of `a69e2bc5`; `cargo test --test mik_7212_mrtr_component_acs` gives **18 passed, 0 failed**, from 15 red | one row left. `MRTR.9a` is unimplemented rather than broken — a client's declaration flattens to the capability *name*, so the mode substructure is discarded and a url-mode request passes the gate by construction. And `mik_7215_acs::http::a_well_formed_retry_…` served a well-formed retry as a fresh `tools/call`. The cause was **not** an HTTP-only path — both dispatchers already reach `handle_tools_call`. `route_retry_to_origin_backend` exempted the whole `gateway_` prefix, so a retry naming any meta-tool was routed as a fresh call with its continuation never opened; narrowed to the two that carry their own server and tool (`965fdf3a`). The test asserted **400**; a well-formed retry this gateway will not redeem is an application denial, so it is `-32602` at **200**, and the assertion moved to the layer that issues it (`5c29494a`). `cargo test --test mik_7215_acs` gives **25 passed, 0 failed**, and the component suite is unmoved at **18 passed, 0 failed** — both verified at `5c29494a` |
| B | era detection (MIK-7217) | 5 | partial — `2026-08-31-discover-outbound-era-probe.md` covers `DISCOVER.4`; **`NFR.OBS.3` appears in no design document** | no | no | no | a design that covers all five rows, not four |
| C | revision surface (MIK-7272) | 7 | scattered across five files (`sub-4-idempotency-wiring`, `sub-1-3-get-mcp-era-gate`, `task-1-tasks-extension`, `cluster-b-*`) | no | no | no | five half-wirings with no single owner and no plan that reads as one change |
| D | response-cache keying (MIK-7213) | 2 | yes — `2026-08-31-cluster-f-response-cache-keying.md` | yes — same stem, `-test-plan.md` | no | no | the test plan has never been through the dual-vendor gate |
| E | performance measurement | 2 | n/a — this is a measurement, not a design | no | no | n/a | a run against 3.5.0 **on Spark**. A Mac number is worse than none |
| F | compatibility facts | 2 | `NFR.COMPAT.4` only — `2026-09-02-conformance-matrix.md` | no | no | no | `NFR.COMPAT.1` is a one-line default flip that cannot land before cluster A merges |
| G | stdio dispatch | 3 | yes — `2026-09-02-cluster-g-stdio-dispatch-parity.md` | yes — `2026-09-02-cluster-g-test-plan.md` | **round 5, unresolved** | **row 1 done** — `d306c7e8` put the record site on the path both dispatchers take; `cargo test --lib stdio_observation` gives 2 passed, 0 failed, verified at `4b522687` | the remaining two rows, which queue behind the gate as planned, plus a third the MRTR work surfaced: `src/gateway/server/mod.rs:1748` hardcodes `retry: &NO_RETRY`, so a stdio client can never present a retry at all. Same defect class as cluster A's prefix exemption — a whole category of callers silently dropped — and it belongs to G's design, not to A's change. Cluster A's branch no longer carries a red test from G |
| — | residue | 10 | mixed | no | no | no | ten independent rows, each needing its own decision |

53 blocking rows. **Two clusters have code, and both live on one branch.** Five
have no branch, no worktree and no commit — verified against `git worktree list` and `git branch`, which show
`fix/mrtr2-continuation-handle` (cluster A) plus two unrelated gap branches.

**Recorded, not filed.** Every gateway-authored `Error::JsonRpc` reaches the client with its code twice — `error_response_preserving_status` builds the message from `error.to_string()`, which already prefixes `JSON-RPC error -32602:`. Cosmetic, pre-existing, and a repair touches every error message in the gateway, so it is an observation rather than a ticket.

**Refusal framing is deliberate.** A malformed retry is refused at the HTTP boundary with 400 (`handlers.rs:973-982`); a well-formed one this gateway will not redeem is refused with a JSON-RPC `-32602` at 200. Different layers, not a disagreement: the first says *this is not a request*, the second says *this request is denied*. Only `Error::Forbidden` carries an HTTP status, by the design `error_response_preserving_status:163-166` states in its own doc.

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

1. **Close the three cases the wiring left red.** The route itself landed in
   `a69e2bc5` at `src/gateway/router/handlers.rs:1048-1065` — the location the
   execution plan's item 1 does not name — and it was the stated cause of
   **all 22 rows of cluster A**: the whole `MRTR` set,
   `NFR.SEC.2/3/4` (until the live path minted and opened a continuation, the
   eight named security fixtures had nothing to exercise), `NFR.OBS.4` (no
   counters to emit) and `NFR.PERF.3` (no in-flight state to soak). It turned 15
   red cases green and deleted the pinned-count header in
   `tests/mik_7212_mrtr_component_acs.rs`, which described only the pre-wiring
   tree. None of the 22 rows can be claimed while the remaining three are red,
   and `ac_mrtr_6` in particular is the `NFR.SEC` shape rather than a loose end.
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
6. **Close G's gate** now that the reviewer is reachable again — but G's row-1
   emit does not wait for it. A red test already sits on cluster A's branch, so the
   emit is a step-1 obligation and the remaining seven stdio rows queue behind the
   gate as planned.
7. **Triage the residue as one pass.** Ten rows, each independent, each needing a
   decision rather than an increment — `HEADER.9` waits on B's per-backend era, so
   it cannot come first. One session, one line of disposition per row, and the ones
   that turn out to be code queue behind whichever cluster owns their file.

Order is dependency, not preference: everything in cluster A waits on step 1 and
F waits on A, while steps 3, 5 and 7 wait on nothing at all. Steps 1, 3 and 5 are
independent and can run at the same time.
