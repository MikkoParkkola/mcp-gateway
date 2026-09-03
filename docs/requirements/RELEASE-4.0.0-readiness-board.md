# 4.0.0 readiness board

One row per cluster, one question per column: **what has to happen next, and who
does it.** The cluster definitions, criterion lists and the reasons each row is
open live in `RELEASE-4.0.0-blocking-rollup.md`; the ordered work queue lives in
`RELEASE-4.0.0-plan.md` under "Order of work". (`RELEASE-4.0.0-execution-plan.md`
says of itself that it is a superseded historical record and the authority for
nothing; it is not a work queue.) Neither answers *how far is each cluster
actually along*, which is the only thing this file is for. Nothing here is
restated from those two — where a cell needs a reason it names the file that
carries it.

Verified 2026-09-03 against the worktree at `fix/mrtr2-continuation-handle`
(`5c29494a`), except cluster A, re-verified at `b5d4ce7f` and stamped in its own
row. A cell reading **no** means a search found nothing, not that nobody intends
to do it.

| # | cluster | rows | design | test plan | plan reviewed | code | the one thing blocking |
|---|---|---|---|---|---|---|---|
| A | continuation envelope (MIK-7212) | 14 | yes — `2026-08-30-mrtr-wiring.md`, `2026-08-30-shared-continuation-state.md`, `2026-09-01-continuation-telemetry.md`, `2026-09-03-mrtr-9a-declared-modes.md` | yes — `2026-09-02-mrtr-test-plan.md` | yes | **yes** — the route is wired and redeemed on the tool-invoke path (`redeem_retry`, `src/gateway/meta_mcp/invoke.rs:529`, called at `:1301`); `cargo test --test mik_7212_mrtr_component_acs` gives **18 passed, 0 failed** and `--test mik_7215_acs` **25 passed, 0 failed**, both at `b5d4ce7f` | evidence, not mechanism. `MRTR.4`, `MRTR.5`, `MRTR.6` and `MRTR.9` are met and have left the cluster — `MRTR.9a` last, once a client's declaration stopped flattening to the capability *name* and carried its elicitation modes, so a url-mode request is refused rather than passing the gate by construction. What remains is the observability and performance evidence over a path that already exists: `NFR.SEC.2-4`, `NFR.OBS.4`, `NFR.PERF.3`, and the `MRTR.1/3/7/8/10a` rows that need their own recorded runs |
| B | era detection (MIK-7217) | 5 | **yes, since `40470449`** — `2026-08-31-discover-outbound-era-probe.md` covers `DISCOVER.4`, and `2026-09-03-nfr-obs-3-era-observability.md` now covers `NFR.OBS.3` | no | **yes** — 4 rounds each vendor, all SHIP-WITH-FIXES | no | a test plan, then the code. The design's own correction is the thing to carry forward: the seam is the store branch in `resolve_with` (`src/protocol/era.rs:163-171`), not the `commit_if` the first draft cited, and the observation must be written on **both** sides of that branch or the `no_answer` state the criterion exists to expose is erased |
| C | revision surface (MIK-7272) | 7 | **yes — four committed designs**, enumerated in `RELEASE-4.0.0-cluster-c-readiness.md` (six criteria over seven ledger rows: `ORDER.2` splits into `ORDER.2a` and `ORDER.2b`, and of `SUB.2` only `SUB.2b` still blocks — `SUB.2a` is MET, so every blocking row has a design): `2026-08-31-cluster-b-connection-invariance.md` (`ORDER.2`, `SUB.2`), `-cluster-b-capability-and-trace-metadata.md` (`EXT.1`, `OTEL.1`), `-sub-4-idempotency-wiring.md` (`SUB.4`), `-task-1-tasks-extension.md` (`TASK.1`) | yes — two standalone files, two embedded, each a row per criterion with a V-model level and a falsifiability column | `SUB.4` only — dual-vendor, revision 2, both SHIP-WITH-FIXES | no | owner `surface-c`. **A fifth design would be an H1/H2/H3 triple-fail; the missing artifact is code.** `cargo test --test mik_7272_exploit_acs --test mik_7272_subscriptions_acs` gives 47 passed, 0 failed (run 2026-09-01) while every row is still ABSENT or UNWIRED — the cases exercise the mechanism in isolation (`gateway_declares()` has no caller but its own test) or pin the absence as correct (`ac_task_1_tasks_get_reports_that_it_is_not_implemented` goes red the day TASK.1 lands, and must be inverted rather than repaired). One coupling is real and runs against the grain: `ServerCapabilities` (`src/protocol/types.rs:232`) carries no `extensions` field, so EXT.1 cannot close without it and TASK.1 records the same blocker from the other side |
| D | response-cache keying (MIK-7213) | 2 | yes — `2026-08-31-cluster-f-response-cache-keying.md` | yes — same stem, `-test-plan.md` | **yes, 2026-09-03** — both legs `process_status: ok`, both SHIP-WITH-FIXES (codex-default 14:36:33Z, Kimi-K3 14:43:16Z) | no | **implementation, which has not started.** Nine findings were raised, verified at source and repaired in `c9aba700`; both vendors converged on one class — an authorization denial bypassed, or unproven, on a cached hit. The confirmation round found three defects the repair itself introduced (a stale row count, a duplicated row identifier, two rows missing a column), repaired in `acd7ba2a`. Kimi confirmed all nine closed; GPT's confirmation leg is `ERROR` on a vendor outage and sits under the finder-unavailability clock, which does not reopen a gate both vendors passed |
| E | performance measurement | 1 | n/a — this is a measurement, not a design | n/a | n/a | n/a | **run on Spark 2026-09-03**, `32f135a6` against `5c29494a`, recorded in `RELEASE-4.0.0-performance.md`. `NFR.PERF.2` is MET. `NFR.PERF.1` stays open as PARTIAL: no shared case regressed near either budget, but criterion measures in-process component work, so the P50 and P99 the clause names have no value. Closing it needs an end-to-end client-to-backend comparison against a 3.5.0 binary, which exists at no version of this repository |
| F | compatibility facts | 2 | `NFR.COMPAT.4` only — `2026-09-02-conformance-matrix.md` | no | no | no | `NFR.COMPAT.1` is a one-line default flip that cannot land before **both** cluster A and cluster C merge — default-on turns every unwired gap in the revision surface into a first-run defect, exactly as it does for the continuation path |
| G | stdio dispatch | 3 | yes — `2026-09-02-cluster-g-stdio-dispatch-parity.md` | yes — `2026-09-02-cluster-g-test-plan.md` | **round 5, unresolved** | **row 1 done** — `d306c7e8` put the record site on the path both dispatchers take; `cargo test --lib stdio_observation` gives 2 passed, 0 failed, verified at `4b522687` | the remaining two rows, which queue behind the gate as planned, plus a third the MRTR work surfaced: `src/gateway/server/mod.rs:1748` hardcodes `retry: &NO_RETRY`, so a stdio client can never present a retry at all. Same defect class as cluster A's prefix exemption — a whole category of callers silently dropped — and it belongs to G's design, not to A's change. Cluster A's branch no longer carries a red test from G |
| — | residue | 10 | **triaged `591194c2`** into DESIGN 5 / TEST 3 / CODE 2 (`RELEASE-4.0.0-residue-triage.md`); `CONTROL.3a`+`CONTROL.4` designed in `7159cdfd` | no | **yes** for the caller-identity design — both legs SHIP-WITH-FIXES, 9 findings repaired | no | `HEADER.9a/9b` has no design and no owner — the `mrtr-9a-*` agents own **MRTR.9a**, a different criterion. The reaper TTL that blocked `CONTROL.4` is ruled: 300s, sharing `PER_USER_IDLE_TTL` (`src/gateway/server/mod.rs:1988`) rather than a second retention number |

The `rows` column sums to the ledger's blocking count, which
`scripts/release/count-release-criteria.py --check` verifies against the status
doc's own tables and against the rollup this file summarises. **Two clusters have code, and both live on one branch.** Five
have no branch, no worktree and no commit — verified against `git worktree list` and `git branch`, which show
`fix/mrtr2-continuation-handle` (cluster A) plus two unrelated gap branches.

**Recorded, not filed.** Every gateway-authored `Error::JsonRpc` reaches the client with its code twice — `error_response_preserving_status` builds the message from `error.to_string()`, which already prefixes `JSON-RPC error -32602:`. Cosmetic, pre-existing, and a repair touches every error message in the gateway, so it is an observation rather than a ticket.

**Refusal framing is deliberate.** A malformed retry is refused at the HTTP boundary with 400 (`handlers.rs:973-982`); a well-formed one this gateway will not redeem is refused with a JSON-RPC `-32602` at 200. Different layers, not a disagreement: the first says *this is not a request*, the second says *this request is denied*. Only `Error::Forbidden` carries an HTTP status, by the design `error_response_preserving_status:163-166` states in its own doc.

## The gate is the binding constraint, not the writing

Cluster G's test plan is at review round 5 and the reason it has not converged
is no longer the document. Reviewer state, 2026-09-02:

| vendor | state | why |
|---|---|---|
| Codex / GPT | **works, then a separate outage** | the `--ephemeral` trust defect is fixed in `~/.claude/bin/gpt-review` with `--skip-git-repo-check`. A distinct failure appeared 2026-09-03: `404` at both `wss://` and `https://chatgpt.com/backend-api/codex/responses` across five reconnects each, on two attempts twelve minutes apart. Vendor-side, not the wrapper — and the wrapper still exits 0 with the error in its body, which is exactly why §PA reads the ledger row and never the text |
| Grok | ERROR | xAI balance exhausted (HTTP 402) |
| GLM-5.3 | ERROR | `finish_reason='length'` on three consecutive attempts — the Flash distillation cannot hold a 26 KB payload |
| Kimi K3 | **works** | the entry above was stale. Two runs on 2026-09-03 returned parseable `VERDICT:` lines and wrote `process_status: ok` rows. Kimi is the second leg for Claude-authored work, since `grok-review` is unpaid and `claude-review` would be the author reviewing the author |

Every vendor failed for its own reason on that day, and the wrapper defect
made the primary reviewer look like a fourth outage. Two of those four entries have
since been falsified by running them — a reviewer recorded as broken stays recorded as
broken until somebody retries it, and cluster D's gate was waiting on one of them. That is the honest state of
the gate; per §PA a nonzero exit is `ERROR`, never a scraped verdict.

## Readiness order — every cluster, none dropped

The queue is `RELEASE-4.0.0-plan.md` under "Order of work"; the execution plan says of
itself that it is superseded and is read here only as the historical record of how item 1 —
this wiring increment — was framed. What follows is the readiness view of that order: where
each cluster and the residue enters it, so that no group of rows
is left without a next step.

1. **Close the three cases the wiring left red.** The route itself landed in
   `a69e2bc5` at `src/gateway/router/handlers.rs:1048-1065` — the location the
   execution plan's item 1 does not name — and it was the stated cause of
   **all 22 rows cluster A then had**: the whole `MRTR` set,
   `NFR.SEC.2/3/4` (until the live path minted and opened a continuation, the
   eight named security fixtures had nothing to exercise), `NFR.OBS.4` (no
   counters to emit) and `NFR.PERF.3` (no in-flight state to soak). It turned 15
   red cases green and deleted the pinned-count header in
   `tests/mik_7212_mrtr_component_acs.rs`, which described only the pre-wiring
   tree. The suite is now **18 passed, 0 failed**, and `ac_mrtr_6` — the case that
   was the `NFR.SEC` shape rather than a loose end — carries the criterion it
   names since `a89f21c8`. `MRTR.6` is met; the cluster has shrunk, as this file's own cluster-A row and the rollup both record.
2. **Then land cluster A.** Open the PR, run the gates at the head that will be
   tagged. Merging before step 1 ships rows the code still refuses.
3. **D is through the gate; what remains is the code.** Both legs ran on
   2026-09-03 and both returned SHIP-WITH-FIXES; the findings are repaired in
   `c9aba700` and `acd7ba2a`. Both rows still need the implementation the plan
   describes, and that waits on nothing. The gate turned out not to be the
   expensive part — a stale reviewer-state table was, because it recorded two
   working vendors as broken and nobody retried them.
4. **Both B and C have their designs; neither needs another.** `NFR.OBS.3` was covered on
   2026-09-03 (`40470449`, four review rounds per vendor), so B's next step is a test plan.
   C's four designs and their plans were already committed and were misread here as scattered
   half-work — `RELEASE-4.0.0-cluster-c-readiness.md` names each one against the rows it covers.
   C's next step is a test that fails because the production path does not do the thing, and
   then the code. Writing a fifth C design would be the H1/H2/H3 triple-fail its owner declined.
5. **Cluster E is measured.** Spark run 2026-09-03, `v3.5.0` (`32f135a6`) against `5c29494a`,
   one clone and one criterion session; results and verdicts in `RELEASE-4.0.0-performance.md`.
   `NFR.PERF.2` is MET — header-first routing did not ship, which is the row's own remedy.
   `NFR.PERF.1` is PARTIAL: nothing regressed near either budget, and the harness produces
   neither of the two estimators the clause names, which is stated there rather than papered over.
   `NFR.PERF.4` is residue rather than cluster E, and **there is no documentation drift**:
   `cargo test --test public_claims_validation` is 8 passed / 0 failed at `5c29494a`, and
   `canonical_meta_tool_counts_match_live_runtime` computes 14/16/17 from a live `MetaMcp`,
   so `benchmarks/public_claims.json:4-6` and `README.md:264` both match the code. What remains
   on that row is the 17th tool against the 14-16 ceiling, which is a surface decision, not a
   stale number.
6. **Close G's gate** now that the reviewer is reachable again. Row 1's emit is
   done — `d306c7e8`, verified at `4b522687` — so it is no longer a step-1
   obligation and cluster A's branch no longer carries a red test from G. The
   remaining two rows queue behind the gate as planned, and the `NO_RETRY`
   hardcode the MRTR work surfaced (`src/gateway/server/mod.rs:1748`) is named in
   the rollup's cluster G as a design input, not as a ninth criterion row.
7. **Triage the residue as one pass.** No shared mechanism across them, most needing a
   decision rather than an increment. `HEADER.9` no longer waits on B: per-backend era
   classification has landed (`src/backend/era.rs:61`, resolved on the start path at
   `src/backend/lifecycle.rs:232`), and what remains is that the outbound header builder
   cannot see it — a gap inside the residue, not a dependency on another cluster. Its
   design is committed (`9a296e78`) and its next step is a reviewed test plan. One
   session, one line of disposition per row, and the ones
   that turn out to be code queue behind whichever cluster owns their file.

Order is dependency, not preference: everything in cluster A waits on step 1, and
F waits on A **and** C, which is why the default flip is the last thing to land.
Steps 3, 5 and 7 wait on nothing at all, so steps 1, 3 and 5 can run at the same time.

## One question is open, and it is the operator's

`ORDER.2` removes per-session routing profiles — the mechanism where a client sets a
filter on its connection and later listings come back narrowed. The operator approved
removing it from the modern path. The cluster-placement work reads the option under
consideration as removing it for **every** protocol era, which also deletes
`gateway_set_profile` and `gateway_get_profile` for 2025-era clients. That is wider
than what was approved and it is user-visible, so it is not an engineering call.

| field | |
|---|---|
| owner | the operator; put to them 2026-09-03, no answer yet |
| what would resolve it | the answer itself — an asked question, not a checkable one. No inspection of the tree settles what the product should do for a 2025-era client |
| when | before cluster C's PR opens. No other C row waits on it row-wise, but C ships as one PR (`RELEASE-4.0.0-plan.md:383`) and F waits on C, so an unanswered question holds the default flip and the release behind it |
| what if it resolves badly | narrow to the modern path only. `ORDER.2` is a 2026-protocol conformance criterion, so meeting it on the modern path alone still closes the row; the cost is an era branch and a connection-invariance property that holds on one path of two |

Recommendation on record: **remove it for every era.** One behaviour, the mechanism
leaves the tree, and no era condition survives for a later change to get wrong — the
elimination the repair protocol prefers over a patch, taken at the major version where
a break is cheapest. It needs a migration note either way.

`ORDER.2a` and `ORDER.2b` are the only rows that depend on this. That is a row-level
statement and it is weaker than it sounds: cluster C ships as a single PR, so the two
rows carry the other five with them, and cluster F's default flip waits on C. The other
five — `EXT.1`, `OTEL.1`, `TASK.1`, `SUB.4`, `SUB.2b` — can be built while the question
is open, and `EXT.1` is the one to start on: the `extensions` field it needs on `ServerCapabilities`
(`src/protocol/types.rs:232`) is also `TASK.1`'s blocker from the other side.

`TASK.1` additionally carries an unrepaired cross-principal leak, raised CRITICAL and
recorded as `MIK-7272.TASK.1.9`: filtering a task-scoped stream by notification kind
alone broadcasts every principal's task status to every listener. It must filter by the
requested task ids **and** the authenticated owner. Owned by `TASK.1`'s own increment,
not by the placement map that found it.

## Cluster D covers one row of CACHE.4 and declares the rest uncovered

`tests/mik_7213_acs.rs:363-367` carries a header naming exactly what it covers — test
plan row `4.b` — and enumerating what it does not: backend pair `4.a`, behavioural
identity `4.c`, routing profile `4.d`, protocol revision `4.e`, policy epoch
`4.f.1`-`4.f.3`. `ac_cache_4_two_principals_do_not_share_an_entry` (:371) calls
`ResponseCache::response_key` — production, not a helper — asserts two authorization
identities do not collide, and carries two controls: a determinism assertion, so it
cannot pass on a key that is merely different every time, and `key(None) == key(None)`,
so unidentified callers are not split into a key that can never hit. It can go red.

An earlier revision of this section said the file "contains no case for `CACHE.4a` or
`CACHE.4b`". The `4.b` half was false and is corrected here; verified at source
2026-09-03, and `ac_cache_4_two_principals_do_not_share_an_entry` is the only
`CACHE.4` case in the tree.

D's real gap is `4.a` and `4.c`-`4.f`, and it is a **declared** gap — enumerated in a
comment, visible to anyone opening the file, producing no false coverage signal. That
is what §P2 asks for: an empty evidence cell that reads as the finding. Those rows
still need a red test written before the implementation, because a test written after
the code agrees with the code. The file's own header is the model for how to record
what a test does not reach.

## EXT.1 must not declare the extension it currently knows about

`ExtensionSet::gateway_declares()` (`src/protocol/extensions.rs:60`) returns a set
containing `io.modelcontextprotocol/tasks`, and its own doc comment says advertising
that identifier before the task model is fixed "would break a client that trusted it"
— the model is short of the extension specification by two statuses, two required
fields and the shape of the failure payload.

So wiring `EXT.1` by calling `gateway_declares()` into the capabilities response
would ship the exact bug the function's author wrote a paragraph to prevent. The
disabled call is a guard, not an oversight.

`EXT.1` asks for the `extensions` field to be declared and for a client that does not
support an extension to be honoured. It does not ask for `tasks` specifically. So the
increment splits cleanly:

- wire the `extensions` field onto `ServerCapabilities` (`src/protocol/types.rs:232`,
  which has no such field today) and run the negotiation on the way in
- the gateway's declared set excludes `tasks` until `TASK.1` lands; `TASK.1`'s own
  increment adds it, in the same change that makes it true

That ordering is the same one the placement map arrived at from the other direction,
for an independent reason, which is some comfort that it is right.

## Cluster C has tests that cannot fail for the criterion they are named for

Recorded first as a two-cluster class alongside cluster D. That was wrong: D's gap is
declared in its own file header and produces no false coverage signal, which is the
behaviour we want more of, not an instance of the defect. Merging the two inverted the
sign on the honest one. The class stands at n=1, and the case below is it.

All four `ac_ext_1_*` cases in `tests/mik_7272_exploit_acs.rs:18-60` call
`ExtensionSet::gateway_declares()` directly. None constructs or serializes a
`ServerCapabilities`. But `EXT.1`'s subject is the `extensions` field on the wire, and
`ServerCapabilities` (`src/protocol/types.rs:231-253`) cannot carry that field at all —
it has `completions`, `experimental`, `logging`, `prompts`, `resources`, `tasks`,
`tools`, and nothing else. That absence is precisely what a real `EXT.1` test would trip
over today. Two of the four go further and assert the post-`TASK.1` world:
`ac_ext_1_the_gateway_declares_its_extensions` asserts the declared set contains
`Tasks`, and `ac_ext_1_a_shared_extension_is_negotiated` asserts the gateway negotiates
it. Both are green with zero production wiring and stay green through `EXT.1`'s entire
increment.

So the defect is: **a test file named for a criterion, exercising a mechanism the
criterion does not turn on.** It passes, it reads as coverage, and it cannot go red for
the increment it belongs to — the §P2 Q2 failure, found only by reading the tests as
tests rather than counting them. What makes it the silent form is that the filename and
the green tick both say covered while nothing declares the gap.

The discriminating check is cheap and mechanical, and is what cleared cluster D: for
each criterion, name the observable the criterion is about, then confirm some test
touches *that* rather than a helper beneath it. Worth running over the other clusters —
but on one instance, not on a count of two.

The four `ac_ext_1_*` cases cite `RELEASE-4.0.0-test-plan.md` §"Increment 10" in their
own header, so the repair belongs to whoever owns that plan.

## PR #473 is the wrong shape for the merge strategy already chosen

`ORDER.2`'s recorded answer is a sequence of per-cluster PRs, cluster A first. The branch
this work sits on has one open PR against `main` — **#473**, `feat(protocol): v4.0.0
multi-round tool result readiness`, opened 2026-09-01 — carrying the whole release effort.
Against `origin/HEAD` that is **213 files and 55,661 insertions**; 57 commits are still
unpushed, and against the branch's own upstream those are 28 files and 3,006 insertions.

That size is a verdict-integrity problem, not a preference. A reviewer handed 55K
insertions dies partway through and exits nonzero, and a nonzero exit is precisely when a
verdict scraped from surviving prose looks like a real one — §PA, arriving by a side door.

It is not fixable by pointing the tooling somewhere narrower. `bin/review --base` defaults
to `origin/HEAD` (`:398`, `:437`) and can be narrowed per increment, which is correct and
costs nothing. The ratification gate cannot: `hooks/PreToolUse/ratification-gate.py:882-919`
pins the base to `origin/HEAD` and takes the merge-base from it (`:2091`), because the stamp
certifies *the diff that would merge*. #473 merges to `main`, so the merging diff really is
213 files. Overriding `RATIFY_DIFF_BASE` to the branch tip would mint a stamp over a diff
that is not the one landing — defeating the gate rather than configuring it.

So the gate is right and the branch is too big. Deciding what to do about #473 is the
operator's, and it is on the release critical path because nothing pushes until it is
settled. Recorded here rather than filed: the decision is one a human makes, and a ticket
would only restate this paragraph.
