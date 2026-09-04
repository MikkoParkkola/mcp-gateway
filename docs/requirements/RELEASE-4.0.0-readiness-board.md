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
| A | continuation envelope (MIK-7212) | 8 | yes — `2026-08-30-mrtr-wiring.md`, `2026-08-30-shared-continuation-state.md`, `2026-09-01-continuation-telemetry.md`, `2026-09-03-mrtr-9a-declared-modes.md` | yes — `2026-09-02-mrtr-test-plan.md` | yes | **yes** — the route is wired and redeemed on the tool-invoke path (`redeem_retry`, `src/gateway/meta_mcp/invoke.rs:529`, called at `:1301`); `cargo test --test mik_7212_mrtr_component_acs` gives **18 passed, 0 failed** and `--test mik_7215_acs` **25 passed, 0 failed**, both at `b5d4ce7f` | evidence, not mechanism. `MRTR.4`, `MRTR.5`, `MRTR.6` and `MRTR.9` are met and have left the cluster — `MRTR.9a` last, once a client's declaration stopped flattening to the capability *name* and carried its elicitation modes, so a url-mode request is refused rather than passing the gate by construction. What remains is the observability and performance evidence over a path that already exists: `NFR.SEC.2-4`, `NFR.OBS.4`, `NFR.PERF.3`, and the `MRTR.7a/7b` legacy-client bridge, which is the one row group in this cluster that is still unwired |
| B | era detection (MIK-7217) | 3 | **yes, since `40470449`** — `2026-08-31-discover-outbound-era-probe.md` covers `DISCOVER.4`, and `2026-09-03-nfr-obs-3-era-observability.md` now covers `NFR.OBS.3` | no | **yes** — 4 rounds each vendor, all SHIP-WITH-FIXES | `DISCOVER.4a/4b/5a/5b` landed (`src/backend/era.rs`); `NFR.OBS.3` not started | a test plan, then the observability code. The design's own correction is the thing to carry forward: the seam is the store branch in `resolve_with` (`src/protocol/era.rs:163-171`), not the `commit_if` the first draft cited, and the observation must be written on **both** sides of that branch or the `no_answer` state the criterion exists to expose is erased |
| C | revision surface (MIK-7272) | 8 | **yes — four committed designs**, enumerated in `RELEASE-4.0.0-cluster-c-readiness.md` (six criteria over seven ledger rows: `ORDER.2` splits into `ORDER.2a` and `ORDER.2b`, and of `SUB.2` only `SUB.2b` still blocks — `SUB.2a` is MET, so every blocking row has a design): `2026-08-31-cluster-b-connection-invariance.md` (`ORDER.2`, `SUB.2`), `-cluster-b-capability-and-trace-metadata.md` (`EXT.1`, `OTEL.1`), `-sub-4-idempotency-wiring.md` (`SUB.4`), `-task-1-tasks-extension.md` (`TASK.1`) | yes — two standalone files, two embedded, each a row per criterion with a V-model level and a falsifiability column | `SUB.4` only — dual-vendor, revision 2, both SHIP-WITH-FIXES | no | owner `surface-c`. **A fifth design would be an H1/H2/H3 triple-fail; the missing artifact is code.** `cargo test --test mik_7272_exploit_acs --test mik_7272_subscriptions_acs` gives 47 passed, 0 failed (run 2026-09-01) while every row is still ABSENT or UNWIRED — the cases exercise the mechanism in isolation (`gateway_declares()` has no caller but its own test) or pin the absence as correct (`ac_task_1_tasks_get_reports_that_it_is_not_implemented` goes red the day TASK.1 lands, and must be inverted rather than repaired). One coupling is real and runs against the grain: `ServerCapabilities` (`src/protocol/types.rs:232`) carries no `extensions` field, so EXT.1 cannot close without it and TASK.1 records the same blocker from the other side |
| D | response-cache keying (MIK-7213) | 2 | yes — `2026-08-31-cluster-f-response-cache-keying.md` | yes — same stem, `-test-plan.md` | **yes, 2026-09-03** — both legs `process_status: ok`, both SHIP-WITH-FIXES (codex-default 14:36:33Z, Kimi-K3 14:43:16Z) | no | **implementation, which has not started.** Nine findings were raised, verified at source and repaired in `c9aba700`; both vendors converged on one class — an authorization denial bypassed, or unproven, on a cached hit. The confirmation round found three defects the repair itself introduced (a stale row count, a duplicated row identifier, two rows missing a column), repaired in `acd7ba2a`. Kimi confirmed all nine closed; GPT's confirmation leg is `ERROR` on a vendor outage and sits under the finder-unavailability clock, which does not reopen a gate both vendors passed |
| E | performance measurement | 1 | n/a — this is a measurement, not a design | n/a | n/a | n/a | **run on Spark 2026-09-03**, `32f135a6` against `5c29494a`, recorded in `RELEASE-4.0.0-performance.md`. `NFR.PERF.2` is MET. `NFR.PERF.1` stays open as PARTIAL: no shared case regressed near either budget, but criterion measures in-process component work, so the P50 and P99 the clause names have no value. Closing it needs an end-to-end client-to-backend comparison against a 3.5.0 binary, which exists at no version of this repository |
| F | compatibility facts | 2 | `NFR.COMPAT.4` only — `2026-09-02-conformance-matrix.md` | no | no | no | `NFR.COMPAT.1` is a one-line default flip that cannot land before **both** cluster A and cluster C merge — default-on turns every unwired gap in the revision surface into a first-run defect, exactly as it does for the continuation path |
| G | stdio dispatch | 3 | yes — `2026-09-02-cluster-g-stdio-dispatch-parity.md` | yes — `2026-09-02-cluster-g-test-plan.md` | **round 5, unresolved** | **row 1 REOPENED 2026-09-03** — `d306c7e8` put the record site on the path, but the evidence behind it cannot see the defect it is supposed to exclude. `cargo test --lib stdio_observation` gives 2 passed **in isolation**; the same binary on the same machine running `cargo test --lib` gives `3897 passed; 1 failed`, and the one failure is `ac_obs_1_stdio_records_the_revision_and_that_meta_carried_it` panicking on its own message — *no record site is reached from the stdio dispatcher*. The test is **flaky under parallelism**, not order-dependent: the same binary gives `--test-threads=1` green, a repeat parallel run green, and one parallel run red. A module-scoped run cannot observe that, so the row has no evidence — and no single green run can supply it, whatever the mechanism turns out to be | the remaining two rows, which queue behind the gate as planned, plus a third the MRTR work surfaced: `src/gateway/server/mod.rs:1748` hardcodes `retry: &NO_RETRY`, so a stdio client can never present a retry at all. Same defect class as cluster A's prefix exemption — a whole category of callers silently dropped — and it belongs to G's design, not to A's change. Cluster A's branch no longer carries a red test from G |
| — | residue | 10 | **triaged `591194c2`** into DESIGN 5 / TEST 3 / CODE 2 (`RELEASE-4.0.0-residue-triage.md`); `CONTROL.3a`+`CONTROL.4` designed in `7159cdfd` | no | **yes** for the caller-identity design — both legs SHIP-WITH-FIXES, 9 findings repaired | no | `HEADER.9a/9b` is **designed and owned** — `2026-09-03-header-9-era-conditional-outbound.md`, owner `design-residue`, on `fix/mrtr2-continuation-handle` (unpushed, parent `20ff255f`). Round 3 was declared VOID under §PA when a commit moved the tree mid-read; the re-run at `11e9b613` is valid and both legs are SHIP-WITH-FIXES. It does not close: a CONFIRMED HIGH says the mechanism cannot activate — `resolve_with` holds the era mutex across the probe await (`src/protocol/era.rs:150-161`) while the probe's own request reaches `request_with_headers`, which is where the design puts its `cached()` read, so the probe blocks on its own guard, times out at 2s and resolves Legacy forever. The repair is an elimination and a fresh round, not a patch. Still true and still worth stating: the `mrtr-9a-*` agents own **MRTR.9a**, a different criterion. The reaper TTL that blocked `CONTROL.4` is ruled: 300s, sharing `PER_USER_IDLE_TTL` (`src/gateway/server/mod.rs:1988`) rather than a second retention number |

The `rows` column sums to the ledger's blocking count, which
`scripts/release/count-release-criteria.py --check` verifies against the status
doc's own tables and against the rollup this file summarises. **Two clusters have code, and both live on one branch.** Five
have no branch, no worktree and no commit — verified against `git worktree list` and `git branch`, which show
`fix/mrtr2-continuation-handle` (cluster A) plus two unrelated gap branches.

**Recorded, not filed.** Every gateway-authored `Error::JsonRpc` reaches the client with its code twice — `error_response_preserving_status` builds the message from `error.to_string()`, which already prefixes `JSON-RPC error -32602:`. Cosmetic, pre-existing, and a repair touches every error message in the gateway, so it is an observation rather than a ticket.

**Recorded, not filed — two outbound-error observations.** `reqwest::Error`'s `Display` appends `" for url (...)"` verbatim (`reqwest-0.13.4/src/error.rs:279-280`), so any site logging a raw one emits the backend URL and whatever credential its query string carries. The site CodeQL flagged is repaired (`redact_url`, `src/capability/executor/mod.rs`); the wider class is not swept. The OAuth client logs errors at `src/oauth/client/mod.rs:338,608,621,1048,1060` — these are wrapped errors, not raw `reqwest::Error`, and **whether the chain preserves reqwest's URL-bearing `Display` was not traced**. Worth a sweep because the URL there is a token endpoint; not a finding until someone reads the error type.

**Reopened, and the gap is narrower than the alert.** Code-scanning alerts #90 and #91 (`rust/cleartext-transmission`, `src/transport/http/mod.rs`) were dismissed `won't fix` on 2026-09-03 with the reason *"plain-http local backends are supported by design"*. That reason was **not verified and does not hold**, so both alerts are back to `open`. What a source pass since established is that CodeQL's own claim — an attacker-reachable sink — is a false positive, while the gap underneath it is real and has an in-repo precedent. The sink's provenance is operator-only: `http_url` arrives from the config file, the CLI, the admin web UI or the curated server registry, never from a request. The one genuinely backend-supplied input, the SSE `message_url`, is pinned by `resolve_message_url` through `same_origin`, which compares `a.scheme()` (`src/transport/http/mod.rs:49`, called at `:796`), so a backend can move the credential neither to another origin nor from `https` down to `http`. The real defect is upstream of both: `validate_backend_urls` (`src/config/mod.rs:946-963`) checks non-empty and parseable and nothing else, so `http://internal-host:8080` with `oauth.enabled` is accepted and sends `Authorization: Bearer` in cleartext to a non-loopback host. The same repository already refuses exactly this on the OIDC path — `key_server/oidc.rs:377` and `:592` both require `https://`. That asymmetry is the finding, and closing it is a design event under §P3, not a dismissal: refusing outright would break a loopback backend that plain HTTP serves correctly today, so the choice between a refusal, a loopback carve-out and an explicit opt-in belongs to the operator. The alerts stay open as the record of an unclosed gap until that call is made.
**`security.message_signing` is a config option that enables nothing.** A search for every consumer returns tests only: `enable_message_signing` (`src/gateway/meta_mcp/mod.rs:652`) has one caller, `src/gateway/meta_mcp/authz_tests.rs:708`; `MessageSigner::new` is constructed at that same test callsite, in `message_signing.rs`'s own tests and in a doc example, nowhere else; and `security.message_signing.enabled` appears outside its own config struct only in four doc comments (`meta_mcp/mod.rs:319`, `:325`, `:345`, `:651`) that describe when it *would* be `Some`. `validate_secret`, which `:651` tells the caller it must call, has no caller at all. An operator who sets `security.message_signing.enabled = true` therefore gets no signing and no warning, which is worse than the feature being absent: the config surface asserts a security control the binary does not apply. This is a §2 WIRED and D7 failure, and both honest repairs — wire it to the config, or delete the feature and its config key — change a security surface, so the choice is the operator's rather than a cleanup.


**Recorded, not filed — the policy-epoch row count wants a mechanical check.** Plan row `4.g` was dropped from **five** independent hand-written summaries of the CACHE.4 section (the test's declared-gap comment, two board sites, `criteria-status.md:80`, and the plan's own decomposition sentence), and repairing four of them did not surface the fifth. Every one of those summaries restates a fact the plan already carries in its rows' first column, so the drift is structural, not careless. The suggestion, from the review that found it: assert mechanically that every plan row labelled `CACHE.4 · policy epoch` appears in the release-status summaries — `scripts/release/count-release-criteria.py --check` is the existing home. Not built: it is a new mechanism with its own design and test plan, and nobody has asked for it. Named here so the next drift is a known recurrence rather than a discovery.

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

## Cluster D covers one plan row of CACHE.4a and declares the rest uncovered

The `MIK-7213.CACHE.4` header in `tests/mik_7213_acs.rs` names exactly what it covers — test
plan row `4.b` — and stating that every other CACHE.4 row is uncovered, pointing at
the plan rather than copying the list. It copied it until 2026-09-04, and the copy
dropped `4.g` twice. `ac_cache_4_two_principals_do_not_share_an_entry` (:371) calls
`ResponseCache::response_key` — production, not a helper — asserts two authorization
identities do not collide, and carries two controls: a determinism assertion, so it
cannot pass on a key that is merely different every time, and `key(None) == key(None)`,
so unidentified callers are not split into a key that can never hit. It can go red.

**The plan-row numbering and the criterion suffixes are different namespaces, and
conflating them reversed this section once already.** The plan does not number its rows
by criterion suffix at all — it names the criterion in each row's **first column**, and
that label is the authority, not the row letter. Four rows read `CACHE.4 · policy epoch`
and therefore serve `MIK-7213.CACHE.4b`: `4.f.1`, `4.f.2`, `4.f.3` and **`4.g`** (the
revocation race, plan `:117`). A row *range* cannot express this — `4.a`-`4.f` reads as
containing `4.f.1`-`4.f.3`, which are `CACHE.4b`, and it silently drops `4.g`. The one
row this board asserts anything about is `4.b`, whose column reads `CACHE.4 · auth
binding` and which therefore sits under `MIK-7213.CACHE.4a` (keyed on every
response-varying input). It makes that criterion
PARTIAL — matching `RELEASE-4.0.0-criteria-status.md:79`, which records the same
falsification. `CACHE.4b` has **no case at all** (`criteria-status.md:80`, ABSENT: no
policy epoch participates in `ResponseCache::response_key`).

A revision dated 2026-09-03 claimed the reverse — that a prior "no case for `CACHE.4b`"
statement was false — and that claim was itself wrong, verified at source 2026-09-04
against both the requirements table (`RELEASE-4.0.0-requirements.md:153-154`) and the
test file's own header. `ac_cache_4_two_principals_do_not_share_an_entry` is the only
`CACHE.4` case in the tree, and it is a `CACHE.4a` case.

D's real gap is every CACHE.4 plan row but `4.b`, and it is a **declared** gap — stated in a
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
touches *that* rather than a helper beneath it.

Running it one level up found the second instance, and it is the more consequential of
the two. `tests/mik_7272_conformance.rs:177-186` carries a `MINOR` row for
`MIK-7272.EXT.1` whose evidence cell names exactly the two `ac_ext_1_*` cases above —
the ones that do not exercise the criterion. So the row is already false, before anyone
touches it. The cell's type is `&'static [&'static str]`: nothing resolves a name to a
test function, and the file's own assertion (`:298-303`) filters on
`row.evidence.is_empty()`, which requires only that a name was *written*. A manifest
that checks for the presence of a string cannot tell a citation from a typo, and cannot
tell either from a test that exists and proves something else. Deleting or relocating
those two cases leaves both strings passing while pointing at an address that no longer
exists.

That matters beyond one row because four release documents cite this file as the
conformance evidence — `RELEASE-4.0.0-gap-plan.md`, `-criteria-status.md`,
`-dod-check.md` and `-cluster-c-readiness.md`. The chain is: a criterion is marked met
because the manifest cites a test, and the manifest cites a test because a string was
typed into an array. At no point does anything read the test.

So the class has two forms, and the check that finds them differs. The first form is a
test that runs and asserts the wrong observable — found by reading tests as tests. The
second is a citation nobody dereferences — found by resolving every evidence string to
the function it names and reading that function against its criterion. The second check
has not been run over the remaining rows of that manifest; until it is, no row in it is
evidence of anything, including the rows that are almost certainly fine.

Disposal of the four `ac_ext_1_*` cases is assigned. They are the only coverage
`negotiate()`, `from_capabilities()` and `contains()` have — `src/protocol/extensions.rs`
is 117 lines with zero `#[test]` — so the answer is to move them into the module as unit
tests and drop the criterion header that is the actual defect, not to delete them. The
red-on-HEAD cases for EXT.1 already exist as E1-E5 in
`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md` §3, which
has been through dual review; writing more would duplicate them. `MINOR` row 1's
evidence cell has no honest value until those are written, and blanking it fails the
file's own assertion by design.

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

## The release's real blocker is the evidence rule, not any one cluster

Four rows in three clusters were recorded MET or covered on evidence that could
not have caught the thing the criterion forbids. They were found separately, by
different means, and they are one defect:

| where | what the evidence named | why it could not fail |
|---|---|---|
| C, `EXT.1` | four `ac_ext_1_*` cases, `tests/mik_7272_exploit_acs.rs:18-60` | they call `gateway_declares()`; the criterion is about the `extensions` field on `ServerCapabilities` (`src/protocol/types.rs:231-253`), which has no such field. The tests exercise a helper beneath the subject |
| D, `CACHE.4b` | `tests/mik_7213_acs.rs` | the file contains no case for it — the policy epoch (plan rows `4.f.1`-`4.f.3` **and `4.g`**, the revocation race) is unimplemented and unkeyed. `CACHE.4a` is **not** in this row: one of its plan rows (`4.b`, authorization binding) has a falsified case, which makes it PARTIAL rather than uncovered |
| G, `OBS.1` row 1 | `cargo test --lib stdio_observation`, 2 passed at `4b522687` | module-scoped, and the test is flaky under parallelism — one full `--lib` run on that binary fails it, two others pass |
| the matrix itself | `matrix_has_no_empty_cells`, `tests/mik_7272_conformance.rs:183` | it asserts a cell is *non-empty*. Not that the named test exists; not that it asserts the criterion |

Both vendors reached the fourth row independently on 2026-09-03 (`process_status:
ok`, identical 10176-byte material, both SHIP-WITH-FIXES). GPT rates it HIGH and
CERTAIN: *EXT.1 can remain untested while the release gate appears purposeful.*
Kimi reaches the same place from the other side: *a requirement can claim coverage
from miscited or nonexistent tests and stay green — the exact failure this change
found by hand.*

**Making evidence strings resolve to real test names is a patch, and both vendors
proposed it.** Apply the repair-protocol test — after the fix, can the finding
still be stated? Yes: a test that exists, compiles and passes while asserting
nothing about its criterion satisfies a name-resolution check exactly as well as a
real one. Three of the four rows above would have survived it. Only the D row,
where the named test is simply absent, would have been caught.

What eliminates it is a rule about **observation**, not about names: a row's
evidence is an observation that the criterion could have come out the other way.
The row carries the observation; the test name is a pointer to it.

**The observation that counts is the one the criterion's own `Verify` column asks
for.** `RELEASE-4.0.0-requirements.md` declares a method per criterion — `T` test,
`M` measurement, `I` inspection, `D` documentation — and a universal red-test rule
would fail every non-`T` row by construction, which is a defect in the rule rather
than in the row. Of the criteria carrying a method, 12 are `T`, 3 `M`, 4 `I`, 1 `D`.

| method | what the row records | what makes it falsifiable |
|---|---|---|
| `T` | the revision the test was observed **red**, the assertion that fired, the revision it is **green** at, and the run count behind the green | the red. `development-process.md` §P2: a test written first "fails because the implementation does not exist — that failure is free and real"; for a test retrofitted to existing code it prescribes the falsifier probe, restoring pre-fix content and showing the test "must FAIL, on the assertion you expect" |
| `M` | the command, the revision, the numbers, and the budget or baseline compared against | a stated threshold the measurement could have missed. A number with no threshold is a reading, not evidence |
| `I` | what was inspected, at which revision, and the property checked | a counter-example the inspection would have found. `NFR.PERF.4`'s ceiling is 14–16 tools: a count of 17 is the counter-example |
| `D` | the document, the revision, and the claim it carries | the claim being absent or contradicted elsewhere |

Two consequences the rows above depend on. **A green alone re-derives nothing** — a
`T` row names both revisions or it is unverified, because a test passing today is
consistent with a test that has never been able to fail. And **editing an evidence
test invalidates its recorded red**: the assertion that fired at the old revision is
no longer the assertion the row rests on, so the row owes a fresh red or a falsifier
probe before it may be re-marked MET. `1b13b255` edited `OBS.1`'s assertion, and that
row's transcript (`audit-notes/2026-09-04-obs1-flake-transcript.md`) records what it
may claim under this rule and why.

Also raised by both, and separable: `a_shared_extension_is_negotiated`
(`src/protocol/extensions.rs:169`) negotiates a set with itself, so a `negotiate`
that ignored its peer argument entirely would still pass all three cases. The
oracle both vendors propose is the same one — an empty gateway set against a peer
holding the recognised Tasks extension must negotiate to empty.

### What this changes about the order of work

**The blocking count is provisional until step 1 runs.** Rows recorded MET on
evidence of this shape are unverified, not met, so the count can only rise, and by
an amount this document cannot state in advance — that is what step 1 is for. No new
engineering is implied; the release simply cannot be assessed against a number
derived from unverifiable rows. That is a cheap pass over recorded rows, not new
engineering, and it comes before the remaining clusters because every cluster
still to land will otherwise record its evidence the same way.

**A re-derivation is itself a measurement, so it states its run count.** The suite
has been demonstrably non-deterministic: `OBS.1` failed 2 of 8 full runs at
`2b1f2690`, transcript in `audit-notes/2026-09-04-obs1-flake-transcript.md`. Each
re-derived row records how many runs it rests on, against this threshold:

- **No recorded non-determinism for that test: one clean run at the exact head**, after
  a verified red at the earlier revision. The red is what carries the weight; a second
  green adds nothing a deterministic test can fail to provide.
- **A test with a recorded flake: the flake is closed first, then twelve consecutive
  clean full-suite runs.** Twelve is not a ritual — at the 25% rate actually measured
  here it puts a surviving flake at `0.75^12 = 0.0317`, under 5%. A test with a
  different measured rate takes the run count that reaches the same bar.
- **A row whose test is known flaky and unclosed has no evidence at any run count.** A
  green run of an intermittent test is a coin, and averaging coins does not produce a
  criterion.

**Each disposition line names an owner** — a cluster, an agent, or a ticket. "Whoever
picks it up" is how the ten residue rows went a release without one.

The three steps below are **dispositions, not a second work queue**. The order of
work has one home, `RELEASE-4.0.0-plan.md` under "Order of work", and the
re-derivation gate is recorded there as preceding every wave. What follows is what
each step means — the rule, the threshold, the owners — which is this file's job and
not that one's.

1. **Re-derive the recorded rows.** For every row currently MET, name the test, the
   revision at which it was observed red, and the number of runs behind the green.
   No observation on record -> the row returns to open. This is the pass that tells
   us the real blocking count. **Cluster A's seven remaining rows belong in this step,
   not after it** — `NFR.SEC.2/3/4`, `NFR.OBS.4`, `NFR.PERF.3` and `MRTR.7a/7b`
   are the first rows that will be recorded under the new rule, and recording them
   under the old one is the defect this step exists to stop repeating.
2. **Fix the four known rows.** Owners in brackets.
   - **G row 1 is closed [cluster G].** The diagnostic assertion (`1b13b255`) said
     `0 record(s) captured` on both failures — the capture, not the record site — and
     the cause was `tracing`'s process-wide callsite-interest cache: a sibling test
     reaching the emit site with no subscriber caches the callsite as `never` and every
     later capture is skipped. `b6836a02` keeps it interested; 12 of 12 clean full-suite
     runs. Diagnosed and eliminated, so §4's quarantine-or-serialise path does not
     arise — it is the route for a flake left open, and this one is not. Transcript:
     `audit-notes/2026-09-04-obs1-flake-transcript.md`.
   - **C's `EXT.1` needs the `extensions` field on `ServerCapabilities` [cluster C].**
     That is a protocol-surface change, not a step-2 patch: it lands under cluster C's
     own gates — DoR `C14` protocol-first (schema and version before implementation)
     and DoD `D2` compatibility — and this step only records that the row cannot be
     honest until it does. `TASK.1` records the same blocker from the other side.
   - **D needs its two cases written [cluster D]**, and the matrix needs the
     observation column [cluster C, with the conformance matrix].
   - **`a_shared_extension_is_negotiated` needs its oracle [cluster C, with `EXT.1`].**
     Both vendors reached it independently: `src/protocol/extensions.rs:169` negotiates
     a set with itself, so a `negotiate` ignoring its peer argument passes all three
     cases. AC: an empty gateway set against a peer holding the recognised Tasks
     extension MUST negotiate to empty. It was named in this document and scheduled
     nowhere, which is the absent-row failure this section exists to stop.
3. **Then the outstanding clusters**, in the dependency order already recorded: B
   and C code, D code, the residue's `HEADER.9` — whose design is CONFIRMED unable
   to activate (`resolve_with` holds the era mutex across the probe await,
   `src/protocol/era.rs:150-161`) and needs an elimination and a fresh round, not a
   patch — and `NFR.COMPAT.1` last, since the default flip cannot precede A and C.

### Three blocking items the order above did not carry

They are listed apart because each was absent, not deprioritised, and an absent row
is the failure mode this whole section is about.

**`NFR.PERF.1` is deferred, with the four fields a deferral owes.** It has sat as
PARTIAL against an end-to-end 3.5.0 comparison that exists at no version of this
repository, which is a residual-risk paragraph, and §P1 says that is not a state.
Owner: `perf-e2e`, an agent to be dispatched, with MIK-7213's performance work as its
handoff trigger — "cluster E" names a row in this table, not anybody accountable, and
that is how this row spent a release unowned. What resolves it: build the
client-to-backend harness against the 3.5.0 tag and measure P50 and P99, which is the
only thing that resolves it. When: before the tag, after cluster A merges, since the
path it would measure is A's.

If it resolves badly, **the criterion stays open and blocks the tag**. `NFR.PERF.1` is
an `M` row with a stated threshold — 5% at P50, 10% at P99 — and a measurement that
misses a threshold is the criterion working, not the criterion being wrong. Rewriting
it to whatever the current harness can produce would be changing the obligation to fit
the result. Repair-protocol step 0 permits eliminating a *mechanism* freely and a
*requirement* only with the requester's recorded agreement, before the fact. So the
fallback is not a rewrite: it is **an operator decision, requested with the measurement
in hand**, recorded in `RELEASE-4.0.0-operator-decisions.md` — ship with the regression
named, hold the tag, or restate the criterion. None of the three is this document's to
take.

**The residue is ten rows and only `HEADER.9` had a step.** The triage
(`591194c2`, `RELEASE-4.0.0-residue-triage.md`) split them DESIGN 5 / TEST 3 / CODE 2.
`CONTROL.3a` and `CONTROL.4` are designed and reviewed (`7159cdfd`, nine findings
repaired) and need test plans; the reaper TTL that blocked `CONTROL.4` is ruled at
300s sharing `PER_USER_IDLE_TTL`. `NFR.PERF.4` is a surface decision — the 17th meta
tool against the documented 14-16 ceiling — not a measurement. The three TEST rows
queue behind whichever cluster owns their file. Each remaining row gets one line of
disposition in the same pass as step 1; a row with no line is open, not silent.

**Cluster F's second row.** `NFR.COMPAT.4` has a design
(`2026-09-02-conformance-matrix.md`) and no test plan, and it does not wait on A or C
the way `NFR.COMPAT.1` does. Owner: `surface-c`, which already owns the conformance
matrix the criterion is about; trigger: immediately, since it blocks on nothing.

**Three residue rows that are code, not documents.** They sit outside the triage's
DESIGN/TEST/CODE split above because each needs its own scheduling sentence rather
than a queue position. `NFR.SEC.6` — the four open security defects MIK-7249,
MIK-7256, MIK-7262 and MIK-7222 — depends on no cluster and starts now [owner:
`sec-defects`]. `CONFIRM.2` follows cluster A, since the confirmation path it binds is
the one A wires [owner: cluster A]. `NFR.SEC.1` needs both a test and an operator
ruling on which 3.5.0 controls are in scope; the ruling is requested first, because the
test's population depends on the answer [owner: `sec-controls`, blocked on the
operator].
