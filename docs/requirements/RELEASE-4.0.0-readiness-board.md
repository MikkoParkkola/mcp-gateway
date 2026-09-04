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
| A | continuation envelope (MIK-7212) | 6 | yes — `2026-08-30-mrtr-wiring.md`, `2026-08-30-shared-continuation-state.md`, `2026-09-01-continuation-telemetry.md`, `2026-09-03-mrtr-9a-declared-modes.md` | yes — `2026-09-02-mrtr-test-plan.md` | yes | **yes** — the route is wired and redeemed on the tool-invoke path (`redeem_retry`, `src/gateway/meta_mcp/invoke.rs:529`, called at `:1301`); `cargo test --test mik_7212_mrtr_component_acs` gives **18 passed, 0 failed** and `--test mik_7215_acs` **25 passed, 0 failed**, both at `b5d4ce7f` | evidence, not mechanism. `MRTR.4`, `MRTR.5`, `MRTR.6` and `MRTR.9` are met and have left the cluster — `MRTR.9a` last, once a client's declaration stopped flattening to the capability *name* and carried its elicitation modes, so a url-mode request is refused rather than passing the gate by construction. `NFR.SEC.2` and `NFR.SEC.4` left it on 2026-09-04 — the fixtures existed and now assert the reason each refusal gives, and the confidentiality test reads the decoded envelope instead of the base64 text. What remains is the observability and performance evidence over a path that already exists: `NFR.SEC.3`, `NFR.OBS.4`, `NFR.PERF.3`, and the `MRTR.7a/7b` legacy-client bridge, which is the one row group in this cluster that is still unwired |
| B | era detection (MIK-7217) | 2 | **yes, since `40470449`** — `2026-08-31-discover-outbound-era-probe.md` covers `DISCOVER.4`, and `2026-09-03-nfr-obs-3-era-observability.md` covers `NFR.OBS.3` | no | **yes** — 4 rounds each vendor, all SHIP-WITH-FIXES | `DISCOVER.4a/4b/5a/5b` landed (`src/backend/era.rs`); `NFR.OBS.3` landed 2026-09-04 (`src/protocol/era.rs`, `src/gateway/meta_mcp/surfaced.rs`, `tests/nfr_obs_3_era_observability.rs`) | `DISCOVER.5` is what remains: the discard record for an era determination that a mid-probe transport swap has already contradicted |
| C | revision surface (MIK-7272) | 8 | **yes — four committed designs**, enumerated in `RELEASE-4.0.0-cluster-c-readiness.md` (six criteria over seven ledger rows: `ORDER.2` splits into `ORDER.2a` and `ORDER.2b`, and of `SUB.2` only `SUB.2b` still blocks — `SUB.2a` is MET, so every blocking row has a design): `2026-08-31-cluster-b-connection-invariance.md` (`ORDER.2`, `SUB.2`), `-cluster-b-capability-and-trace-metadata.md` (`EXT.1`, `OTEL.1`), `-sub-4-idempotency-wiring.md` (`SUB.4`), `-task-1-tasks-extension.md` (`TASK.1`) | yes — two standalone files, two embedded, each a row per criterion with a V-model level and a falsifiability column | `SUB.4` only — dual-vendor, revision 2, both SHIP-WITH-FIXES | no | owner `surface-c`. **A fifth design would be an H1/H2/H3 triple-fail; the missing artifact is code.** `cargo test --test mik_7272_exploit_acs --test mik_7272_subscriptions_acs` gives 47 passed, 0 failed (run 2026-09-01) while every row is still ABSENT or UNWIRED — the cases exercise the mechanism in isolation (`gateway_declares()` has no caller but its own test) or pin the absence as correct (`ac_task_1_tasks_get_reports_that_it_is_not_implemented` goes red the day TASK.1 lands, and must be inverted rather than repaired). One coupling is real and runs against the grain: `ServerCapabilities` (`src/protocol/types.rs:232`) carries no `extensions` field, so EXT.1 cannot close without it and TASK.1 records the same blocker from the other side |
| D | response-cache keying (MIK-7213) | 2 | yes — `2026-08-31-cluster-f-response-cache-keying.md` | yes — same stem, `-test-plan.md` | **yes, 2026-09-03** — both legs `process_status: ok`, both SHIP-WITH-FIXES (codex-default 14:36:33Z, Kimi-K3 14:43:16Z) | no | **implementation, which has not started.** Nine findings were raised, verified at source and repaired in `c9aba700`; both vendors converged on one class — an authorization denial bypassed, or unproven, on a cached hit. The confirmation round found three defects the repair itself introduced (a stale row count, a duplicated row identifier, two rows missing a column), repaired in `acd7ba2a`. Kimi confirmed all nine closed; GPT's confirmation leg is `ERROR` on a vendor outage and sits under the finder-unavailability clock, which does not reopen a gate both vendors passed |
| E | performance measurement | 1 | n/a — this is a measurement, not a design | n/a | n/a | n/a | **run on Spark 2026-09-03**, `32f135a6` against `5c29494a`, recorded in `RELEASE-4.0.0-performance.md`. `NFR.PERF.2` is MET. `NFR.PERF.1` stays open as PARTIAL: no shared case regressed near either budget, but criterion measures in-process component work, so the P50 and P99 the clause names have no value. Closing it needs an end-to-end client-to-backend comparison against a 3.5.0 binary, which exists at no version of this repository |
| F | compatibility facts | 3 | `NFR.COMPAT.4` only — `2026-09-02-conformance-matrix.md`; `NFR.OBS.5` test plan `2026-09-04-nfr-obs5-test-plan.md` | no | no | no | `NFR.COMPAT.1` is a default change that cannot land before **both** cluster A and cluster C merge — default-on turns every unwired gap in the revision surface into a first-run defect, exactly as it does for the continuation path. `NFR.OBS.5` joined this cluster on 2026-09-04 and is gated on the same flip: the operator retired its `default off` clause on 2026-09-03, so its test file is rewritten around default-on and RED on purpose until cluster A and cluster C land |
| G | stdio dispatch | 2 | yes — `2026-09-02-cluster-g-stdio-dispatch-parity.md` | yes — `2026-09-02-cluster-g-test-plan.md` | **round 5, unresolved** | **row 1 STILL OPEN, narrowed 2026-09-05** — `d306c7e8` put the record site on the path and `b6836a02` made its evidence readable, but dual review found the record itself incomplete: a legacy stdio request after `initialize` records `absent`/`none` because no session state carries the negotiated revision, so the criterion's *per request* clause fails on the transport this cluster exists for. The reopening on 2026-09-03 was correct at the time and its cause is now named: `tracing` caches each callsite's interest process-wide, so a sibling test reaching the emit site with no subscriber cached the callsite as `never` and every later capture was skipped — the capture was blind, not the record site, which the diagnostic assertion (`1b13b255`) showed by reporting `0 record(s) captured` on both failures. 12 of 12 clean full-suite runs after the fix; transcript `audit-notes/2026-09-04-obs1-flake-transcript.md`. Diagnosed and eliminated, so §4's quarantine-or-serialise path does not arise **Row 2, `NFR.OBS.2`, closed 2026-09-05 by `f7781df8` and left the cluster.** `81c0a8ad` had already put the `tools/list` surface record on the stdio path (`src/gateway/server/mod.rs:1727-1735`) with two tests beside the dispatcher — those tests sit in the source file, not under `tests/`, which is why a search of `tests/` reported them missing — so the site half is genuinely closed. Review then found the content half open: the record writes `profile = "none"` as a stdio invariant, but `active_profile` (`src/gateway/meta_mcp/mod.rs:1053-1063`) resolves a profile from `session_profiles` by session id and falls back to the registry default, so a bound or defaulted profile filters the list while the record denies one exists. `code_mode` and `query_present` record declared inputs rather than filters that ran. `f7781df8` built the one record where the list is built (`shadow_tools_list_assembly`, `src/gateway/meta_mcp/mod.rs:1236-1266`), reporting the profile actually resolved, and deleted the stdio site with its duplication | the one remaining row, which queues behind the gate as planned, plus a second gap the MRTR work surfaced: `src/gateway/server/mod.rs:1748` hardcodes `retry: &NO_RETRY`, so a stdio client can never present a retry at all. Same defect class as cluster A's prefix exemption — a whole category of callers silently dropped — and it belongs to G's design, not to A's change. Cluster A's branch no longer carries a red test from G |
| — | residue | 10 | **triaged `591194c2`** into DESIGN 5 / TEST 3 / CODE 2 (`RELEASE-4.0.0-residue-triage.md`); `CONTROL.3a`+`CONTROL.4` designed in `7159cdfd` | no | **yes** for the caller-identity design — both legs SHIP-WITH-FIXES, 9 findings repaired | no | `HEADER.9a/9b` is **designed and owned** — `2026-09-03-header-9-era-conditional-outbound.md`, owner `design-residue`, on `fix/mrtr2-continuation-handle` (unpushed, parent `20ff255f`). Round 3 was declared VOID under §PA when a commit moved the tree mid-read; the re-run at `11e9b613` is valid and both legs are SHIP-WITH-FIXES. It does not close: a CONFIRMED HIGH says the mechanism cannot activate — `resolve_with` holds the era mutex across the probe await (`src/protocol/era.rs:150-161`) while the probe's own request reaches `request_with_headers`, which is where the design puts its `cached()` read, so the probe blocks on its own guard, times out at 2s and resolves Legacy forever. The repair is an elimination and a fresh round, not a patch. Still true and still worth stating: the `mrtr-9a-*` agents own **MRTR.9a**, a different criterion. The reaper TTL that blocked `CONTROL.4` is ruled: 300s, sharing `PER_USER_IDLE_TTL` (`src/gateway/server/mod.rs:1988`) rather than a second retention number |

The `rows` column sums to the ledger's blocking count, which
`scripts/release/count-release-criteria.py --check` verifies against the status
doc's own tables and against the rollup this file summarises. **Two clusters have code, and both live on one branch.** Five
have no branch, no worktree and no commit — verified against `git worktree list` and `git branch`, which show
`fix/mrtr2-continuation-handle` (cluster A) plus two unrelated gap branches.

**Recorded, not filed.** Every gateway-authored `Error::JsonRpc` reaches the client with its code twice — `error_response_preserving_status` builds the message from `error.to_string()`, which already prefixes `JSON-RPC error -32602:`. Cosmetic, pre-existing, and a repair touches every error message in the gateway, so it is an observation rather than a ticket.

**Recorded, not filed — two outbound-error observations.** `reqwest::Error`'s `Display` appends `" for url (...)"` verbatim (`reqwest-0.13.4/src/error.rs:279-280`), so any site logging a raw one emits the backend URL and whatever credential its query string carries. The site CodeQL flagged is repaired (`redact_url`, `src/capability/executor/mod.rs`); the wider class is not swept. The OAuth client logs errors at `src/oauth/client/mod.rs:338,608,621,1048,1060` — these are wrapped errors, not raw `reqwest::Error`, and **whether the chain preserves reqwest's URL-bearing `Display` was not traced**. Worth a sweep because the URL there is a token endpoint; not a finding until someone reads the error type.

**Reopened, and the gap is narrower than the alert.** Code-scanning alerts #90 and #91 (`rust/cleartext-transmission`, `src/transport/http/mod.rs`) were dismissed `won't fix` on 2026-09-03 with the reason *"plain-http local backends are supported by design"*. That reason was **not verified and does not hold**, so both alerts are back to `open`. What a source pass since established is that CodeQL's own claim — an attacker-reachable sink — is a false positive, while the gap underneath it is real and has an in-repo precedent. The sink's provenance is operator-only: `http_url` arrives from the config file, the CLI, the admin web UI or the curated server registry, never from a request. The one genuinely backend-supplied input, the SSE `message_url`, is pinned by `resolve_message_url` through `same_origin`, which compares `a.scheme()` (`src/transport/http/mod.rs:49`, called at `:796`), so a backend can move the credential neither to another origin nor from `https` down to `http`. The real defect is upstream of both: `validate_backend_urls` (`src/config/mod.rs:946-963`) checks non-empty and parseable and nothing else, so `http://internal-host:8080` with `oauth.enabled` is accepted and sends `Authorization: Bearer` in cleartext to a non-loopback host. The same repository already refuses plain `http` off-loopback in `resource_origin` (`src/gateway/router/well_known.rs:151-176`), with a loopback carve-out and a userinfo rejection — closing this gap aligns with that policy rather than inventing one. Closing it is a design event under §P3, not a dismissal, because a configuration that starts today stops starting. **Decided** — refuse a credential on a plain-`http` non-loopback backend, with a loopback carve-out and a per-backend opt-in; see the decision record and its two corrections later in this document. The alerts stay open as the record of the gap until the guard lands.
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

---

## 2026-09-04 — recount, and three corrections to what this board said

Everything below was counted or read at source today. Where it contradicts a cell
above, this section is the later reading, not a second opinion.

### The blocking count is 38, and five of them were invisible to every prior count

`RELEASE-4.0.0-criteria-status.md` holds 158 criterion rows (plus 12 rows belonging
to the setter table and the group summary, which are not criteria and are excluded
here). Parsed by the column the header names `blocking`, not by transcription:

| status | blocking rows |
|---|---|
| ABSENT | 17 |
| PARTIAL | 9 |
| UNWIRED | 7 |
| UNTESTED | 4 |
| REVISED, NOT MET | 1 |
| **total open and blocking** | **38** |

No blocking row is MET: the `blocking` column is maintained as *still blocking* and
flipped to `no` on close, so `blocking=yes` and *open* are the same set. 109 rows
read `blocking=no`; 99 of those are plain `MET`, 2 are `N/A`, 7 carry a qualified
MET (`MET (structural)` x3, `MET (I)` x2, `MET (caveat)`, `MET (residual)`), and one
— `NFR.OBS.5` — reads `REVISED, NOT MET` while marked non-blocking.

**The count was 37 and is now 38: `NFR.OBS.5` was open and flagged non-blocking.**
Its status cell reads `REVISED, NOT MET` — a spelling outside the file's stated
vocabulary — and its own evidence cell ends *"This row is unmet until
`tests/nfr_obs5_flag.rs` is rewritten around the new default and re-probed"*, while
the `blocking` column read `no`. `RELEASE-4.0.0-gap-plan.md:930-938` agrees: the
operator's 2026-09-03 ruling retired the `default off` clause and "the row moves from
MET to unmet". Self-declared open work with a `no` in the blocking column is not a
judgement call, so the flag is flipped rather than referred upward.

Two things travelled with it. `RELEASE-4.0.0-requirements.md:294` still carried the
retired `defaulting off until the conformance matrix is complete` clause, so the
authority document asserted a requirement the operator had withdrawn the day before —
a §P4a failure in the change that made the ruling, not a new decision here. The row
text is now the revised criterion with the ruling cited. And flipping the flag
introduced, for one edit, exactly the unescaped-pipe column shift described below;
it was caught by counting the row's fields against the header rather than by reading
it. Any edit to a cell in that table gets the same field count afterwards.

**Four blocking rows do not survive a naive column parse.** `MIK-7212.MRTR.7a`,
`MIK-7212.MRTR.7b`, `MIK-7272.EXT.1` (all `UNWIRED`) and `MIK-7246.CONFIRM.1a`
(`PARTIAL`) carry an unescaped `|` inside their evidence cell, which shifts every
column to its right. A count that reads a fixed column index reports 33 and is
wrong by exactly these four. This reconciles the 37-vs-31 disagreement recorded
earlier: neither number was a miscount of the same set, they were counts of
different sets. Any future recount must compare each row's field count against its
header's before trusting a column index.

The seven qualified-MET spellings are a second hazard of the same kind — they are
not in the file's stated status vocabulary, and a filter written for `MET` alone
either drops them or, worse, a filter for `!= MET` promotes seven closed rows back
into the gap list. They are all `blocking=no`; that is the only reason the count
above is unaffected.

### Corrections to items this board and the working plan carried

- **The `MIK-7217` §1 DoD evidence comment was already posted**, at
  `2026-09-04T11:05:01Z`, verified against the Linear API rather than recalled. It
  was carried as outstanding work. It is not.
- **`/tmp/body.md` is not the `MIK-7217` evidence body.** It is the
  operator/consumer-plane-split problem statement behind GitHub issue 449. Posting
  it as DoD evidence would have attached the wrong document to the wrong ticket.
- **The four `UNWIRED`/`PARTIAL` `MIK-7217.DISCOVER` rows** were re-evidenced against
  the live probe path and flipped to MET on 2026-09-04. No code changed; the
  citations were re-verified and the status text replaced. They are inside the 99
  above, not the 38.

### Machine state, and why it stopped the work

A disk exhaustion halted every build for part of the session and is worth recording
because the diagnosis was wrong twice before it was right. Deleting 15 GiB of cargo
target directories moved free space *down*, from 3.0 G to 121 MB, and the harness
itself began failing with `ENOSPC`. There was no runaway writer — top CPU was a
0.9% Python process. Local APFS snapshots were pinning the freed blocks, three from
OS updates and one from the Arq backup agent. `tmutil thinlocalsnapshots / 21474836480 4`
took free space from 121 MB to 19.5 G in one call, with no root and no mount
juggling. Apparent size is not reclaimable space, and a delete that appears to do
nothing may have worked perfectly.

Consequence for anyone building here: `~/.cargo/registry` was cleared, so the first
build after this re-downloads the whole dependency tree. A build that looks hung is
probably fetching. 32.6 G free as of this entry; `cargo clippy --lib` exits 0.

### Two agents share this worktree

`cache-keying-tests` (holding `src/cache.rs`, `src/gateway/meta_mcp/invoke.rs`,
`src/gateway/meta_mcp/support.rs`, `tests/mik_7213_acs.rs`) and `obs3-tests`
(holding `tests/nfr_obs_3_era_observability.rs`) are both editing this tree and
therefore share one git index. Their files are disjoint by luck, not isolation.
Both have been told: stage by explicit path only, never `-a`/`-A`/`stash`/`reset`,
and never bare `cargo fmt` — a whole-tree format rewrites the other agent's
half-written file. **A full green baseline is unobtainable here until both commit**,
and stashing is not available in a shared tree. `--all-targets` and `fmt --check`
are deferred until their work lands rather than re-attempted.

`obs3-tests` also carries a GPT review verdict of SHIP-WITH-FIXES on the OBS.3
design and the conformance test — one HIGH (the design claims probe serialization
prevents staleness, which is false: a detached re-probe can outlive `force_restart`)
and one MEDIUM (the tracked-gap guard accepts zero matching rows, so deleting the
exempted row leaves both coverage tests green).

### Sequencing constraint that must not be lost

The cluster order is **D → G → A → C → F**, and `NFR.COMPAT.1` in cluster F requires
**both A and C merged** before it can be closed. Merging F earlier does not fail
loudly; it produces a criterion closed against a tree that does not yet contain what
it asserts.

### The CodeQL `#90`/`#91` policy question — decided by the agent, under a stated assumption

Asked of the operator twice, in plain language, with four options and a
recommendation. Unanswered both times. Taken under §P1's *ask, then proceed*: the
work below is delivered on the assumption recorded here, and the assumption is
stated rather than buried so that reversing it costs one paragraph.

**Decision: refuse a plain-`http` backend URL when a credential would ride on it,
except when the host is loopback.** Loopback is `127.0.0.0/8`, `::1`, and the name
`localhost` — the same set browsers treat as a secure context under RFC 6761. The
name is included knowingly: `/etc/hosts` or DNS can point `localhost` elsewhere, and
accepting it anyway is the cost of not breaking every local development setup and
the part of the test suite that speaks plain HTTP to a local server.

Why this option over the other three. Refusing outright breaks a loopback backend
that plain HTTP serves correctly today, which is the deployment shape the original
`won't fix` dismissal was reaching for and got wrong only in its scope. Warning and
sending anyway leaves the credential in cleartext and leaves both alerts open, so it
does not reach a clean release. Accepting the risk ships 4.0.0 with a documented way
to leak a bearer token while the same repository already refuses a plain-`http`
JWKS URI outright (`src/key_server/oidc.rs:592`, `InsecureJwksUri`) — shipping that
asymmetry is harder to defend than closing it.

**Correction to this section's first draft.** It cited `oidc.rs:377` and `:592` as
two refusals. Verified at source: `:377` only `warn!`s that an OIDC issuer is not
HTTPS and proceeds; `:592` is the sole refusal. The precedent is one refusal and one
warning, not two — weaker than claimed, and still sufficient, because the refusal
that does exist is the closer analogue. Worth recording against our own decision:
`:592` carries **no loopback carve-out** and refuses plain `http` everywhere, so the
policy chosen here is the more permissive of the two. That is deliberate — a JWKS
URI is remote-fetched by nature, whereas an MCP backend on loopback is an ordinary
deployment — but the difference is written down rather than smoothed over. Caught by
the implementing agent while verifying this brief's citations.

**Second correction: the precedent cited above is not the closest one, and the
closest one is nearly this guard already.** Both drafts reached for
`key_server/oidc.rs` because the search was for a plain-`http` refusal. The search
should have been for a plain-`http`-with-a-loopback-carve-out refusal, and one
exists: `resource_origin` in `src/gateway/router/well_known.rs:151-176` refuses
`scheme == "http" && !is_loopback_host(host)`, cites RFC 9728 §1.2 for why loopback
is the sole exception, rejects `parsed.username()` and `parsed.password()` outright,
and carries a faithful-host guard that rejects any value whose host the parser
rewrote — alternate or decimal IPv4, IDNA/punycode, percent-encoding. Three
consequences, none cosmetic. The policy decided here is **aligned with an existing
in-repo policy** rather than a weakening of the OIDC one, so the permissiveness noted
in the correction above is the house style and not a concession. The credential-in-URL
path both design reviewers found independently is already refused at that site, which
is corroboration from the code rather than from a reviewer. And the faithful-host
guard is hardening this guard would otherwise have had to invent — `http://2130706433/`
is `127.0.0.1` in decimal and must not be waved through as loopback by a classifier
that only compares strings.

The loopback classifier has **one owner**: `well_known::is_loopback_host`
(`src/gateway/router/well_known.rs:63-76`), re-exported `pub` as
`crate::gateway::router::is_loopback_bind`. Nothing in this change may write a second
one. `src/discovery/shadow/helpers.rs:341-349` already did, and gets repaired in the
same change rather than filed — see the disposal ruling below.

Method note, because this is the second correction to the same passage. Both errors
were the same error: a precedent recalled by shape rather than located by search, then
cited without reading the lines. `rg` for the policy predicate, not for the module
you expect to hold it.

**Where it goes: `validate_backend_urls` (`src/config/mod.rs:946-963`), not the
transport.** The board's own source pass established that the two flagged sinks are
operator-provenanced and that the one backend-supplied input is already pinned by
`same_origin`. A transport-layer guard would therefore sit downstream of the real
defect and fire after the operator has already been told the configuration is valid.
Config validation is where an operator finds out. Neither cited precedent lives
there — `oidc.rs:592` validates a fetched discovery document and `well_known.rs:155`
parses a request-time identifier — so the placement is argued from where the operator
learns the configuration is wrong, not from precedent.

This is a §P3 design event and is named as one. It changes behaviour outside what
the release scope declared FOR: a configuration that starts today will refuse to
start after it. That is the point, and it is also why the escape hatch matters — an
operator who genuinely wants cleartext on a trusted internal network needs a way to
say so out loud rather than by accident, and the implementation carries an explicit
opt-in for exactly that.

If the operator later prefers another option, the reversal is this section plus one
guard, not a redesign.

### Two plan defects found by the workers, ruled on rather than re-litigated

Both surfaced while orienting, both are defects in the work plan rather than in the
work, and both are settled here so the next session does not re-open them.

**Cluster C's commit 1 is an extension, not an introduction.** The plan's "replace
both inline key sites" step is already done upstream: `response_cache_key_for`
(`src/gateway/meta_mcp/support.rs:56`) is the one shared finished-key function and
both invoke sites already call it, at `:1197` and `:1763` — not the plan's `:843`
and `:1296`, which are wrong line numbers for work already landed. No second key
function is to be created.

**`policy_epoch: u64` and `protocol_revision: Option<&str>` are decisions the design
did not make.** A monotonic `u64` is the right shape for a value whose job is to
invalidate on a grant or profile change, so it is taken — but named as a §P3 design
event rather than picked silently. Nothing in `src/` produces a policy epoch today
(the only `epoch` matches are `epoch_millis_now` in `failsafe/circuit_breaker.rs`),
and `declared_version` lives only at `src/gateway/router/handlers.rs:569` and never
reaches the meta-MCP cache layer, so `None` is the honest value at every call site.
Both fields land inert on purpose.

**Consequence that must not be lost: the seam commit closes no criterion.** Accepting
a `KeyContext` without mixing it into the key satisfies neither "keyed on every
request-derived input that varies the response" nor "carries a policy epoch that
invalidates it on a grant or profile change". A seam logged as progress toward MET is
how a row gets closed against a tree that does not contain what it asserts — which is
the same failure the four column-shifted rows above represent, arrived at from the
other direction.

**NFR.OBS.3's stepped clock is a production seam, ruled in.** The reviewed test plan
requires the transition cases to assert equality against a stepped clock value.
Presence-and-different is rejected: `era_probed_at` is second-precision, so two probes
inside one second stamp identically and the assertion is flaky at best. Sleeping is
worse. The seam is to be the narrowest one that works — a timestamp on the
era-observation construction path in preference to an injection point on `Backend` —
must not be `#[cfg(test)]`, since integration tests compile against the lib without
that cfg and could not reach it, and is to be named as a §P3 design event where it is
made.

### A second defect found under that guard, and why it was fixed instead of filed

The agent building the credential guard found a second defect and disposed it as
*file a ticket*, explicitly offering the overrule. Overruled: it is fixed in the same
change.

**What it is.** `is_loopback_url` (`src/discovery/shadow/helpers.rs:341-349`) decides
loopback with `host == "localhost" || host == "::1" || host.starts_with("127.")`. Both
halves are wrong in opposite directions. `starts_with("127.")` matches any registrable
DNS name beginning `127.` — one an attacker can register. And `url::Url` yields the
IPv6 host **with brackets**, so `host == "::1"` never matches and `http://[::1]:8080/`
is never recognised.

**Why that is not cosmetic.** `local_only` feeds `auth_exposure`, which feeds
`classify_severity`'s `network_exposed` (`src/discovery/shadow.rs:826`, `:835`,
`:941`). The permissive half therefore **downgrades the severity** of exactly the
ungoverned network-exposed server shadow discovery exists to flag; the strict half
raises a false alarm on a genuine local one.

**Why not a ticket.** §P0 reserves that disposal for findings where a human must
decide something. Tracing `local_only` to a severity downgrade *made* the decision, so
nothing was left to refer upward, and a DoR-compliant ticket would have been larger
than the repair. The repair is also the repair protocol's elimination move rather than
a patch: *two components can disagree about X* is closed by *one owner of X*, not by a
check that detects the disagreement. Three loopback classifiers were about to exist —
the correct one, this one, and whichever the new guard wrote. Both the guard and the
shadow helper now delegate to `is_loopback_bind`, and one owner remains.

Two commits, separately scoped, so the classifier fix stands if the guard needs
another round. Regression cases: a `127.`-prefixed DNS name must classify
network-exposed; `http://[::1]:8080/` must classify loopback.

**Landed, with one correction to this ruling.** The classifier is not reachable as
`is_loopback_bind` outside the gateway: `src/gateway/mod.rs` declares `mod router`
privately, so the `pub` on the function only ever meant *within `gateway`*, which is
why `server/support.rs` can call it and config validation cannot. A reviewer caught
that before it became a failed build. It is now re-exported crate-internally as
`pub(crate) use router::is_loopback_bind as is_loopback_host` — aliased back to the
truthful name, since both new callers classify a backend host rather than a bind
address, and crate-internal so no public surface widens. Four commits: the design, the
inert `allow_cleartext_credentials` field, the twenty-one plan rows red, the guard
turning them green, and the shadow classifier delegating to the same owner with two
regressions verified against the pre-fix code.

## Sequencing — what gates what

The cluster table above says what each cluster *is*. It does not say what order the
clusters can be worked in, and that order is not derivable from the rows: two clusters
are gates, three are independent, and one cannot start until two others finish.

| cluster | blocked by | blocks | shape of the remaining work |
|---|---|---|---|
| A continuation envelope | nothing | F | four mechanisms, three evidence rows (below) |
| B era detection | nothing | nothing | tests only; the path is wired |
| C revision surface | nothing | F | code; four designs already exist |
| D response-cache keying | nothing | nothing | reviewed, implementation in flight |
| E performance | nothing | nothing | one re-measurement (`NFR.PERF.1`) |
| F compatibility facts | **A and C** | nothing | a two-part default change plus six doc updates, last |

F is the only ordered work. A, B, C, D and E are mutually independent and can run in
parallel; F is a single line that cannot move until both A and C close, because the flip
makes the gateway serve a modern frame it must first be able to produce (C) and continue
(A).

### Cluster A is not one mechanism plus evidence

The rollup's "what remains" sentence names the legacy-client bridge and then treats
`NFR.SEC.2-4`, `NFR.OBS.4` and `NFR.PERF.3` as observation over a path that already
exists. Read against the ledger rows, that holds for three of them and not for the other
two, and it omits `MRTR.8b` entirely.

| row | what it actually needs |
|---|---|
| `MRTR.7a`, `.7b` | mechanism — the legacy-client bridge, no production call site |
| `MRTR.8b` | mechanism — the count bound is enforced, the **lifetime** bound is not |
| `NFR.SEC.3` | mechanism — key rotation and a verification-key retention window do not exist |
| `NFR.OBS.4` | mechanism — no mint/redeem/expiry/rejection counters exist |
| `NFR.SEC.2`, `.4` | evidence — the path is wired; eight named fixtures are absent |
| `NFR.PERF.3` | evidence — a soak showing reclamation, over a path that reclaims |

Four mechanisms, not one. Sequencing A as a single owner's work underestimates it by the
three rows the rollup sentence does not mention.

### The compatibility flip is not one line

`modern_protocol` carries `#[serde(default)]` (`src/config/mod.rs:1181`). Serde's
field-level default is `bool::default()`, which is `false` — it does not consult
`ServerConfig::default()`. Flipping the struct default alone therefore leaves every
deployment whose config file contains a `server:` section still modern-off, which is
every real deployment. A test written against `Config::default()` goes green while the
operator-facing default stays off.

The repair is a DELETION, not a new default function. `ServerConfig` already carries a
container-level `#[serde(default)]` (`src/config/mod.rs:1166`) which resolves a missing
field to `ServerConfig::default()`. The field-level attribute is redundant and shadows
it. So: delete `#[serde(default)]` at `:1181`, flip the struct default at `:1229` (every
doc citing `1174` or `1127` is stale), and add a deserialization case proving a `server:`
mapping that omits the flag comes back `true`.

Six operator-facing documents state that modern is off by default: `README.md:355`,
`docs/DEPLOYMENT.md:135`, `RELEASE-4.0.0-pr-body.md:6`, `execution-plan.md:39`,
`dod-check.md:950`, and `blocking-rollup.md:285`. They are true today and must not be
edited before the flip. §P4a puts them inside the flip's own change, carried by whoever
owns it.

Found by `gpt-review` against the test plan for `NFR.OBS.5`, confirmed at source, before
any flip was attempted.

A seventh surface sits in the code, not in that list: the doc comment on the field
(`src/config/mod.rs:1168-1172`) states the revision is off by default and that turning it
on is one switch. The flip falsifies both sentences and must rewrite them.

## Expected-red suites on `fix/mrtr2-continuation-handle`

Two suites fail on this branch on purpose, and a third party cannot tell them from rot
without this table. A suite is listed here only while the criterion it pins is genuinely
unmet; when the criterion closes, the suite goes green and its row is deleted. A red
suite that is NOT listed here is a regression and blocks under stop-the-line.

| suite | failures | pins | goes green when |
|---|---|---|---|
| `nfr_obs5_flag` | 3 of 6 | `NFR.OBS.5` clause (c) — the latest revision is not served by default | the default change lands, behind clusters A and C |
| `nfr_obs_3_era_observability` | 15 | `NFR.OBS.3` — era detection emits nothing observable | the era-detection counters land |

The branch does not merge while any row here is still red, which is the same condition as
"clusters A and C have landed". Nothing is quarantined and nothing is skipped: the
failures are true, and hiding them behind `#[ignore]` would trade a true signal for an
invisible one on a branch four sessions share.

## MRTR.7a/7b is a transport increment, not wiring

The rollup and this board both described the legacy-client bridge as the one unwired
mechanism in cluster A, which reads as a missing call site. The approved design
(`docs/design/2026-09-01-mrtr7-legacy-client-bridge.md`) mandates considerably more, all
inside this increment:

| part | why it is not optional |
|---|---|
| closed `ServerRequest` enum with per-variant answer projection | the design rejects a method-string forwarder outright — it would let a backend reach any client method on the gateway's authority |
| `ClientChannel` over SSE **and** stdio | `send_to_session` (`src/gateway/streaming.rs:254`) is SSE-only, and every server-initiated request goes through it |
| per-session client-capability store built at `initialize` | `rg 'ClientChannel|session_capabilities|SessionCapabilit' src/` returns zero hits; nothing retains `ClientCapabilities` today |
| five bounds constants | — |
| concurrency refactor of the stdio serve loop (`src/gateway/server/mod.rs:1564`) | the loop reads one line and dispatches to completion, so awaiting a client reply inside dispatch blocks the only reader that could deliver it — a deadlock until timeout, not a slowdown |

Roughly 800-1500 lines across `src/protocol/`, `src/gateway/server/`, `streaming.rs` and
the invoke path. Its bridge site is `invoke_tool_traced`
(`src/gateway/meta_mcp/invoke.rs:525`), which cluster D currently holds. Attaching one
level up at `handle_tools_call` does not avoid the collision: the interim classification
at `invoke.rs:1471` is entangled with the local idempotency reservation, which leaves an
interim result deliberately unsettled so a retry can be served.

Review status is also thinner than `gap-plan.md:654` reads — one vendor, `SHIP`, on a
head the design has since moved past by six commits. Under §12 that is not a passed dual
gate on the current head.

## MRTR.8b — reclamation is capacity-triggered, not time-triggered

The PARTIAL on row 133 has a specific cause. `reclaim_abandoned` is called from exactly
one place: inside the `held.len() >= self.capacity` branch of `InFlight::hold`
(`src/protocol/continuation.rs:659-680`). `InFlight::reap` has no production caller at
all — the `reap` matches elsewhere belong to a different type in `session_lifecycle.rs`.

So a table below capacity never reclaims. The count bound holds (that is `8a`, MET), but
an entry past its `expires_at` is dropped only when a new hold arrives while the table is
full. If traffic stops, expired state persists indefinitely. The requirement
(`requirements.md:183`) demands bounded **lifetime** and reclamation on abandonment: the
abandonment arm holds under pressure, the lifetime arm does not hold at rest. `NFR.PERF.3`
records the same gap and adds that no soak exists to observe it.

## RESOLVED — the revision IS on by default in 4.0.0

**Corrected 2026-09-04.** This was never open. The operator ruled on 2026-09-02 that
4.0.0 serves 2026-07-28 out of the box, and on 2026-09-03 retired `NFR.OBS.5`'s
`default off` clause on the same ground. Both rulings are recorded in
`RELEASE-4.0.0-blocking-rollup.md` cluster F. Re-asking a settled question and then
reading the absence of a second answer as a block held clusters A, C and F behind a
decision that already existed.

What actually gates the flip is engineering, not a ruling: default-on makes every
unwired gap in the continuation path a first-run defect, so cluster A must land first.
Parking the legacy bridge is NOT an available reduction either — default-on is exactly
what makes `Bridge::to_legacy_client` reachable. The text below is kept as the record of
the error, not as a live question.

### Superseded text

Put to the operator on 2026-09-04 and not yet answered. Recorded here as a deferred
question under the design process rather than settled by whoever needs an answer first:
parking the bridge work is a reduction in release scope, and that needs the requester's
recorded agreement.

| field | value |
|---|---|
| owner | the operator; nobody else may settle it |
| what would resolve it | a choice between shipping the revision opt-in with the default flip deferred, and building the transport increment so that 4.0.0 flips it |
| when | before cluster F is scheduled, and before any second-vendor review of the bridge design is commissioned |
| if it resolves the other way | if the answer is "on by default in 4.0.0", the bridge becomes the release's critical path: a transport increment behind a file that cluster D holds, with its design review restarting on the current head |

Nothing depending on it is being implemented. `MIK-7212.MRTR.7a` and `7b` are parked, not
abandoned; `NFR.COMPAT.1` and `NFR.OBS.5` stay blocked behind them. Every cluster that does
not depend on the answer continues meanwhile.

The recommendation on the table is to ship opt-in and defer the flip. The increment is the
single riskiest change in the backlog — it refactors the stdio serve loop, which today
deadlocks if a dispatch awaits a client reply — and what it buys is a default value. The
six operator-facing documents stating that the revision is off by default are true under
that option and need no edits.
