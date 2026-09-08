# GH475.RL.10 delivery closure — design and test plan

Status: design/test-plan, separate tests-as-tests and final paired code gates are
closed. The reason-phrase repair passes all 34 focused cases and critical mapped
line/mutation thresholds. The independent functional leg, integrated static/CI
gates, final housekeeping and release delivery remain coordinator-owned or pending.
The 100% changed-region target is not achieved; exact coverage limits appear below.
Issue: #481, criterion GH475.RL.10. This completes the inherited O1 design in
`2026-09-06-capability-rate-limit-budget-participation.md` and its companion test
plan. The current source and execution details below supersede stale completion
claims in those documents. Their option analysis and 429-only decision stand.

## Scope and readiness

FOR: retain an upstream capability HTTP 429 as a typed status through REST,
JSON-RPC and GraphQL execution; classify it without parsing text; preserve its
error-budget exclusion, rate-limit recovery category and backend JSON-RPC code.
Keep query credentials and backend URLs out of the returned error and new logs.

OUT: MCP-backend dispatch/failsafe logic, predicate phrase changes, retries,
Retry-After support, unrelated budgets, authorization or SSRF changes, and
coordinator/signing work near the touched classification functions. The CLI and
external crate callers share the executor's changed 429 error text; they do not
gain error-budget participation. This is an intentional diagnostic change, not
an excluded consumer silently assumed to be unaffected.

DoR applicability and evidence are recorded gate by gate in
`2026-09-06-gh475-rl10-dor.md`; no blanket ready verdict is claimed. Value is
preventing a harmless formatting change from charging throttled capability calls
to failure budgets. No new enum variant, production public API, config, storage,
network destination or migration is needed. The change is reversible by reverting
the narrow source delta; rollback restores the text dependency. Requirements,
source callers, risks, discriminating tests and build ownership are named here.
UI design, database migration and new service provisioning are not applicable.
The owner mandated this release repair; no financial return is invented and no
new product choice needs another user decision. The review and
tests-before-behavior gates remain mandatory execution gates, not implied passes.

## Pre-implementation source and inherited evidence

| Symbol/site | Current behavior and caller proof |
|---|---|
| `CapabilityExecutor::handle_response`, `executor/params.rs:38` | REST delegates through `execute_rest`, which calls this at `executor/mod.rs:494`; non-success responses become `Error::Protocol`, including 429. `params.rs`, not `rest.rs`, owns this return site. |
| `ProtocolExecutor::execute`, `executor/jsonrpc.rs:133` and `graphql.rs:189` | Shared `CapabilityExecutor::dispatch_protocol` calls both. Their non-success branches also destroy the status into `Protocol` text. |
| `BudgetOutcome::of`, `gateway/meta_mcp/invoke.rs:2975` | Called on the actual dispatch result at `:1387`; every error currently goes through `is_rate_limited(error.to_string())`. Its recorder excludes an ignored rate limit from both windows. |
| `classify_dispatch_error`, `invoke.rs:2941` | Called by `invoke_tool_traced` for the same dispatch error; `Protocol` scans text, while `Http` currently falls through to `BackendError`. |
| `Error::to_rpc_code`, `error.rs:193` | Public conversion also called by `error_response_preserving_status`; `Http` currently falls through to -32603. The inherited operator ruling selects -32000 only for status 429. The invoke tool-result path separately uses recovery metadata. |

The coordinator's all-feature lib run compiled and reported 4,077 passed, one
failed, four ignored. The sole failure was the inherited
`a_capability_429_is_a_typed_http_error_at_every_protocol_site`, whose first REST
assertion got `Protocol`. That red is valid for the return-site gap; it does not
test the downstream typed arms or all planned controls. It is not sufficient
evidence to implement only the three return sites.

The old design's 06:55 Kimi and 07:01 Grok receipts say SHIP-WITH-FIXES; the
document explicitly says confirmation never ran. Receipt inspection additionally
found different submitted materials: Kimi 57,689 bytes, Grok 144 bytes containing
a path prompt. Those reviews supply findings, not a current paired gate. The
prevention plan still labels itself unreviewed. Fresh GPT/Grok reviews will bind
the same actual design/plan/source bytes; separate tests-as-tests reviews follow
after the full discriminating tests have run red.

Required GitNexus checks on `mcp-gateway-v4-delivery` found HIGH impact for each
protocol executor: `dispatch_protocol` is the direct caller, across four modules.
This warning was reported before edits. `classify_dispatch_error`, `to_rpc_code`,
the REST response handler and the `BudgetOutcome` impl are LOW. The graph misses
some Rust method calls; static source supplies the REST and budget caller proof
above. The public code conversion has 29 graph transitive hits, so its guard must
remain 429-only. No signature changes are planned.

## Completion design and contract events

O1 remains the least change: reuse `Error::Http` and `reqwest::Error::status()`.
Adding another error enum variant or a side channel is unnecessary. Leaving the
executor typed but the classifiers textual fails the criterion and degrades
recovery; converting every non-success status breaks 504/403/500 compatibility.

One private helper in `executor/mod.rs` owns the 429 status gate, existing
`redact_url` / `without_url` call, metadata-only WARN event and `Error::Http`
construction. All three response sites call it before body consumption. Only
status 429 is handled; other statuses continue through their existing `Protocol`
string and body-fragment path. Successful parsing and transport failures remain
untouched. A missing error from `error_for_status_ref()` must not panic; the
existing error path remains available, and the 429 tests pin the actual library
behavior. The helper adds no public API.

**Diagnostic contract repair:** the 429 body is omitted from both the returned
error and logs. The WARN names only the protocol and status; it never logs the
body, full reqwest error, URL or request metadata. Upstream bodies are untrusted
and may echo credentials or personal data, so moving them from an error into a
persistent log would introduce a privacy regression. Dropping the body also
avoids downloading it just for diagnostics. CLI operators and library callers
receive status-based 429 diagnostics; access to the upstream body is intentionally
removed. Non-429 diagnostics keep their prior contract. No Retry-After claim is
made; the chosen error carrier does not retain headers.

`BudgetOutcome::of` explicitly classifies status-bearing `Error::Http` from its
status: 429 is `IgnoredRateLimit`; any other typed status is `Failure`, with no
fallback into the text predicate. A status-less `Http` error retains the existing
generic path, preserving unrelated transport behavior. This explicit typed
branch is essential: a guarded 429 arm followed by text scanning could pass even
when the typed discriminator was wrong. The existing MCP text/envelope handling
is unchanged.

`classify_dispatch_error` maps only typed 429 to `RateLimited`; its detail is the
already redacted error text. Other branches remain unchanged. `to_rpc_code`
maps only typed 429 to -32000; other `Http` errors still map to -32603. These
match arms land with the executor change, not in a later partial increment.

## Test plan and placement

The existing executor test file is already 1,418 lines and invoke.rs is 4,690.
New focused test modules will contain the RL10 additions instead of growing
those files. Move the inherited RL10 cases and their fixture into an executor
RL10 module where practical, retaining their assertions; leave unrelated tests
alone. A `pub(crate)` associated fixture on `CapabilityExecutor`, compiled only
under `cfg(test)`, lets the private invoke test module obtain errors produced by all real executor sites,
without widening production visibility or fabricating `Error` strings. Fixture
construction is not an alternate production path.

The fixture uses a real loopback HTTP server and the established test client's
resolver arrangement to reach it. Production protocol execution, response
formatting and classification run normally. This does not validate production
SSRF/DNS or reachability policy; those existing controls are not disabled in
production or claimed as covered here. Servers are scoped to each test and
aborted when their fixture is dropped. No environment/global subscriber mutation
or sleeps establish the result. Async WARN capture uses a future-bound scoped
subscriber, retaining a positive event canary and protocol marker. REST enters
through `RestExecutor::execute`, matching the other two protocol entry points;
the direct `handle_response` inherited detection case remains a lower-level
compatibility control.

| Clause | Level / type | Actual planned acceptance and discriminating control |
|---|---|---|
| C1–C3 | component / positive typed boundary | At all three real format sites, 429 returns `Error::Http` with status 429. Keep an independent case per protocol so a REST failure cannot prevent execution of the other cases. The inherited aggregate test is retained or split without losing its assertions. |
| C4 | component integration + mutation / discrimination | Obtain the actual executor error and pass it to the private `BudgetOutcome::of`; assert ignored outcome and unchanged backend/capability windows through the recorder. Mandatory copied-tree probe changes only typed `Some(429)` to `Some(430)` in this branch: the case must fail despite unchanged 429 text. |
| C5 | component integration / negative control | Real executor 500 is Failure and records one failure in both windows. A real status-bearing `Http(500)` is separately Failure in `BudgetOutcome::of` and BackendError in `classify_dispatch_error`, guarding both typed arms against widening. Construct this control from a real reqwest 500 response using error_for_status/without_url and Error::Http, independently of the production 429 helper, because executors intentionally keep non-429 responses as Protocol. |
| C5b | component / negative and Unicode boundary | Table of 403, 500 and 504 at every protocol site: assert `Protocol` and the complete expected error string, including the established protocol prefix, status/reason and exactly the first 500 Unicode characters of an overlong body. A character on the truncation boundary discriminates character count from byte slicing. Compare the `Error::Protocol` payload, with `API returned`, `JSON-RPC endpoint returned` or `GraphQL endpoint returned` prefixes respectively; a Display comparison must also include `Protocol error: `. Status/body containment is insufficient. |
| C5c | unit at consumer / regression | Actual executor 504 recovery is Timeout and 500 is BackendError; unchanged exact text is pinned at the source return sites. No claim of byte-for-byte category identity is substituted for checking the relevant observable value. |
| C6 | unit / inherited regression | Rerun the three inherited detection cases using the shared predicate. They demonstrate error-string compatibility, not a capability circuit breaker or the actual capability recorder. C4/C5 separately pin the actual budget effect. |
| C7 | component / observability positive and privacy negative | Each 429 execution site emits a WARN with protocol and numeric status; body/response-secret canaries are absent from both error and captured log output. An event canary proves capture is live. Include an upstream body that echoes URL/query credentials so suppressing request metadata alone cannot pass. |
| C7b | component / privacy negative | Each protocol uses a URL with a distinctive query-secret canary: returned `Display` omits canary, host and path, and `reqwest::Error::url()` is None. New WARN output also excludes the URL/query canary. |
| C8/C9 | unit / positive and negative | Real typed 429 maps to -32000. Real status-bearing Http(500), and a status-less Http transport error, remain -32603. |
| C10 | component integration + mutation / discrimination | Actual executor 429 is RateLimited with retry-capable recovery metadata. A mandatory copied-tree probe changes the typed recovery guard from 429 to 430; this must fail despite unchanged 429 text. A status-bearing Http(500) remains BackendError. |
| C11 | unit / compatibility regression | Existing recovery predicate tests, success handling and MCP envelope budget tests remain green. Their source is unchanged. A status-less Http control pins existing generic handling. |

Commands are scheduled through the coordinator: focused all-feature RL10 tests
first (red, then reviewed tests, then green); existing capability and budget/
recovery tests next; full lib and static gates remain release gates. Coverage
targets changed lines/functions at 100%; actual mutation evidence targets at
least 85% for the critical classification decisions. Manual discriminating
probes for C4 and the typed recovery arm are required even if automatic mutant
generation misses them. Full logs, commands, actual exits and per-mutant outcomes
are retained outside the repository.

A fresh non-author driver must exercise a real capability-backed request and
observe 429 recovery plus an ordinary-failure control. The coordinator owns its
isolated runtime setup; a local fixture-only check is not relabeled as a complete
production SSRF/dispatch drive. Remaining blockers and configuration limitations
must be reported. Final dual code review, documentation, CI and release delivery
still follow; passing the inherited test alone does not close #481.

## Current review repair record

Run `mcp-v4-rl10-design-20260906-r1` produced GPT SHIP-WITH-FIXES and Grok
SHIP. Receipts are `gpt-20260906T143754Z-23941.md` and
`grok-20260906T143754Z-23942.md` under
`/Users/mikko/.claude/data/reviews/runs/`. Both authoritative process statuses
are `ok` and actual wrapper exits are 0. The same material digest is
`3b9f7009d873665d9d358a720adc48ee48b030428ebba94a595a4a39a8edb204`,
288,873 bytes including scope plus NUL plus 287,895 stdin bytes. The initial
local launcher sidecar labeled the stdin byte count as material bytes; this
record corrects the label using the authoritative rows, without rewriting the
original receipt or changing the submitted bytes.

| Finding / improvement | Disposition and source check |
|---|---|
| Untrusted body in new WARN violates confidentiality (GPT HIGH). | **Fix in this change.** Body logging is deleted from the live contract, not truncated or redacted heuristically. C7 includes body and echoed-credential absence from both error and logs, with a positive event capture control. |
| Blanket DoR claim lacks evidence (GPT MEDIUM; Grok improvement). | **Fix in this change.** Remove that claim and assess every named canonical gate in the companion DoR audit. Actual #481 metadata absence is recorded as coordinator-owned B2, not invented as complete. Confirmation reviews the completed matrix; implementation waits for the named action. |
| Typed Http(500) not applied to all consumers (GPT MEDIUM). | **Fix in this change.** C5 now explicitly asserts both Failure and BackendError for a real status-bearing Http(500). Protocol(500) remains a separate real-executor control. |
| Containment does not prove promised exact non-429 text (GPT LOW). | **Fix in this change.** C5b compares complete strings for 403/500/504 at every site, including the exact 500-Unicode-character boundary. |
| Three copies of 429 security policy (both improvements). | **Adopted.** One private response helper owns the status check, URL stripping and safe diagnostic; all three production sites call it. |
| Test fixture visibility, full REST entry, and typed recovery probe (Grok improvements). | **Adopted.** The cfg(test)-only associated fixture is explicitly pub(crate), REST enters RestExecutor::execute, and C10 mandates a typed 429-to-430 probe. |
| Competing live plans (GPT improvement). | **Adopted.** The closure matrix is the sole live execution plan; the inherited prevention draft is marked historical and points here. |
| Sample or aggregate the new per-call WARN (GPT improvement). | **Observation.** The chosen event contains fixed protocol/status metadata and adds no state, timer or retry policy. No log-volume benchmark or global rate-limit guarantee is claimed; introducing sampling would add an operational policy outside this narrow error-contract repair. |

No production or test source changed before these design/plan repairs. A focused
confirmation on the repaired material is still required, followed by the
separate tests-as-tests gate.

R2 confirmation (`mcp-v4-rl10-design-20260906-r2`) returned Grok SHIP
(`grok-20260906T145642Z-72594.md`) and GPT SHIP-WITH-FIXES
(`gpt-20260906T145641Z-72593.md`), both process `ok` and actual exits 0,
with equal 212,345-byte material and SHA
`8801a8ad53a4f90d935b7986391b22cd0200a77b8a8fa257b80a86b142af266d`.
The technical/privacy/matrix repairs were accepted. GPT's sole remaining finding
was B4/B5 tracker readiness. The coordinator then added the exact unchecked
`GH475.RL.10` typed/no-text AC and placed #481 in milestone 4.0.0; saved readback
`gh481-updated-readback.json` also proves B2's assignee/labels. The DoR matrix now
records completed tracker state, and a narrow finder confirmation is required.

R2 optional clarifications were adopted without changing the contract: C5b names
the Error::Protocol payload and all three prefixes; typed Http(500) is obtained
independently from a real reqwest response; DoR describes compatibility as
specified rather than already tested. The superseded prevention matrix is
removed, leaving its index and git history. Repeated log-sampling advice retains
the prior observation disposition; no extra logging policy is introduced.

R3 finder confirmation (`mcp-v4-rl10-design-20260906-r3`) returned GPT
SHIP with no improvements: `gpt-20260906T151234Z-17970.md`, authoritative
process `ok`, actual wrapper exit 0, 70,214-byte material SHA
`1d694971b80b8ae942454a0ada83acf188323ead1ea63172ab60f6919fe6cb11`.
It explicitly accepts the exact AC and actual milestone readback, closing the
sole remaining r2 finding under the repair protocol. The wrapper ran from the
workspace parent (ledger repo `/Users/mikko/github`, empty live head); the frozen
manifest records worktree HEAD and exact document hashes. This was a tracker/doc
closure, not a source-head or runtime approval. Paired r2 technical approval
stands. Missing tests may now be written and run red; behavior waits for their
separate review gate.

## Written tests and compiled red

The inherited aggregate typed test is split into independent REST, JSON-RPC and
GraphQL cases entering the full protocol executor. Its URL/body absence checks
now cover all three sites, and its Protocol500 control is strengthened to exact
403/500/504 payload equality with a Unicode truncation boundary. Three inherited
shared-predicate detection tests retain their assertions in
`executor_rl10_regression_tests.rs`, with scoped server cleanup. New executor
checks live in `executor_rl10_tests.rs`; actual private budget/recovery consumers
are checked in `gateway/meta_mcp/invoke_rl10_tests.rs`. Their associated fixture is
compiled only in the cfg(test) executor module, not a production public API.

The coordinator ran `cargo test --all-features --lib rl10 --jobs 4 -- --nocapture`
on Spark. Both red rounds compiled and reported **13 passed, 7 assertion failures**
with actual Cargo exit 101. R2 binds the final WARN-scoped capture and is retained
as `mcp-gateway-v4-rl10-red-r2.log` in the scope-review directory. Failed cases are
three typed carrier boundaries, three missing safe WARN records and the backend
RPC conversion. Exact non-429, typed500/status-less and budget/recovery controls
pass. Old Protocol text still provides budget/recovery compatibility; those
passes do not prove typed classification, which requires the planned post-fix
429-to430 probes. Two compilation warnings belong to the coordinator's in-flight
continuation-cleanup code and are not silently counted as a clean static gate.

Self-QA narrowed event capture to the new WARN contract while retaining the WARN
positive canary. An existing REST DEBUG request event logs its URL; source at
`executor/mod.rs:431` and the first red log confirm that separate observation.
It was reported to the coordinator for release triage; this increment neither
changes that event nor claims all existing debug diagnostics are safe. R2's
WARN-only capture does not exclude any event this increment promises to secure.

Separate paired tests-as-tests approval remains required before behavior edits.

## Separate tests-as-tests review and focused improvements

Run `mcp-v4-rl10-tests-20260906-r1` returned **SHIP from both vendors**:
`gpt-20260906T152734Z-55990.md` and `grok-20260906T152734Z-55991.md`.
Both authoritative processes are `ok`, actual wrapper exits 0, worktree HEAD
`0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf`, with equal material SHA
`bb574716c1595e0e810a4d5d57e9909ade450716ffd512ad7aa3f7af56041eab`,
276,379 bytes. No NOW finding was raised. Grok's LATER finding correctly notes
that ordinary consumer outcomes alone cannot distinguish typed429 from leftover
text matching: the existing required430 probes remain a final acceptance gate.
No fake error carrier is introduced to pretend otherwise.

| Suggestion | Disposition |
|---|---|
| Automate both typed429-to430 probes (GPT). | **Adopted.** External evidence runner `gh475-rl10-typed-probes.py` requires a marked isolated copy and pinned source hash, runs a green baseline, requires the exact three independent semantic assertion failures for each probe, restores bytes in finally and reruns green. It is syntax checked only; no mutation result is claimed yet. |
| Typed Http403 alongside500 at budget, recovery and public RPC conversion (Grok). | **Adopted.** Both real typed statuses are asserted explicitly and must retain ordinary-error handling. A broad is_client_error patch can no longer pass. |
| Recovery body/query canaries and typed429 preconditions (Grok). | **Adopted.** Each actual executor error must be Http429 before consumption; detail and RecoveryHint.message must omit a reflected URL/query/body canary. These strengthen C4/C10 without changing the production contract. |
| Independent protocol cases in RPC/budget/recovery (Grok). | **Adopted.** Positive429 and ordinary-error consumer families now run independently for REST, JSON-RPC and GraphQL. A failed REST assertion does not skip another protocol. |
| Never-ending429 response-body fixture (GPT). | **Observation.** The chosen helper's source ordering will return before body consumption; these tests pin the error/log omission contract, with no runtime claim about a stalled response body. A dedicated transport-liveness assertion would extend the present boundary tests. This is not substituted for the required typed430 discrimination. |
| Formatted WARN sink including inherited span fields (GPT). | **Observation for the component fixture.** The planned helper creates no span and owns event-local protocol/status fields. Current REST provider span explicitly records capability name and provider service; the separate existing DEBUG URL event is already reported to the coordinator. The independent runtime driver captures actual formatted logs, but no component test claims to certify all existing ancestor-span logging. |

The small adopted test changes are being rerun red and receive a focused reviewer
confirmation before behavior edits. The initial paired tests-as-tests approval is
retained as evidence; no new source behavior was introduced after it.

The coordinator's r3 red run compiled the strengthened **30 cases** and exited
101 with **15 passed, 15 assertion failures**, 4,123 filtered, no compiler error.
The added typed preconditions now independently expose the carrier gap at both
consumer families; the three separate RPC cases expose their own mapping failures.
Full log: `mcp-gateway-v4-rl10-red-r3.log`. Nine compiler warnings are shared
continuation/serving-context/personal-account scaffolds owned by other increments,
not RL10 test compilation failures. A narrow Grok finder confirmation now checks
the adopted test delta against the prior paired approval.

## Test confirmation and applied implementation

The narrow r2 finder confirmation returned Grok **SHIP**, with no findings:
`grok-20260906T155439Z-25882.md`, run
`mcp-v4-rl10-tests-20260906-r2`. Authoritative process is `ok`, actual wrapper
exit 0, material SHA
`894148c5d1e52aeefe5052a426c96ae63d67b2a63309d7a167c4ae45a2294360`,
110,837 bytes, on the same worktree HEAD. Together with paired r1 approval this
closes the tests-as-tests gate for the strengthened 30-case suite. Its optional
RPC-carrier precondition is an **observation**: C1–C3 independently require the
same fixture's typed carrier, and no overall gate accepts only the RPC cases.
Alternative as_u16 discriminator parsing in the probe runner is also an
**observation**: the actual implementation uses the pinned StatusCode constant;
token mismatch correctly refuses to claim a caught mutation. No generic probe
framework is introduced.

After those gates, the author applied the six-site change and one private helper.
`rate_limited_response_error` returns only for 429, strips the URL with the existing
helper, emits protocol/status-only WARN, and returns before body consumption.
All three production response sites call it inside their existing non-success
branch; exact non-429 formatters are unchanged. `BudgetOutcome::of` branches on
status-bearing Http before the existing fallback:429 is ignored and other typed
statuses fail, with no text fallback inside that branch. Status-less errors retain
the old predicate. Recovery and RPC add only 429 guards. The recovery detail uses
the already-redacted outer error Display.

Self-QA inspected the full delta against pinned pre-behavior files and confirmed
only these owned decisions changed. Source search proves all three helper callers,
actual BudgetOutcome::of consumption by record_error_budget, and the recovery
classification in invoke_tool_traced. GitNexus was refreshed before edits: both
protocol executors remain HIGH through dispatch_protocol across four modules;
other symbols are LOW, with 29 transitive to_rpc_code hits and the documented Rust
method graph gaps. The warning was reported before editing. The new private
helper adds no state, retry, dependency, public API, request/body allocation or
untrusted diagnostic field. The scoped return ordering is source evidence; no
stalled-body runtime test is claimed.

Owned source delta and hashes are retained as
`gh475-rl10-implementation.diff`, `gh475-rl10-implementation-source-hashes.json`
and `gh475-rl10-pre-implementation/` outside the repository. Focused rustfmt and
`git diff --check` pass. The coordinator is scheduling the real Spark green run;
no green, final code review, mutation/coverage, independent driver or release
completion is inferred from these static checks. Other agents' redeem_retry and
ResponseFirewallRefused work was preserved; no response-finalizer behavior is
owned by this increment.


## Compiled green and isolated verification

The first green attempt stopped at an unrelated compiler error in the
coordinator's new server builder test adapters: three E0433 diagnostics for a
missing CleanupRuntime import. No RL10 test ran in that attempt; its retained log
is `mcp-gateway-v4-rl10-green-r1.log`. After the coordinator repaired that import,
`cargo test --all-features --lib rl10 --jobs 4 -- --nocapture` compiled and exited
0: **30 passed, 0 failed, 4,143 filtered**, 0.25 seconds. Evidence is
`mcp-gateway-v4-rl10-green-r2.log`. Seven shared in-flight scaffold warnings remain
visible; this is a focused runtime pass, not a zero-warning static gate.

The implementation improvement pass consolidated the three identical 429
privacy/status decisions in one private helper, reused the existing URL
redaction, and preserved the outer Error Display for recovery consistency. It
introduced no configuration, dependency or extra retry. The actual green suite,
full before/after diff, source callers and focused formatter check constitute
the author's validation pass; final reviewers are still required.

For quantitative checks, a dedicated Spark source/target/TMPDIR snapshot is
pinned in `gh475-rl10-spark-snapshot.json`. Its nine implementation/test hashes
match the local files. All probe mutations operate only on the marked copied
source; the active delivery worktree is never mutated. Existing regression
filters, typed430 probes, coverage and cargo-mutants results are pending here,
and no independent runtime-driver outcome is inferred from component tests.

The isolated existing regression filters all exited 0: capability executor **101**,
recovery **13**, error-budget **9**, and RPC-code **1** cases. Full commands and
logs are retained in `gh475-rl10-regressions-r1/`.

Both required typed429-to430 probes are now **caught**. Each produced the required
three protocol-specific semantic assertion failures (Cargo101), with budget
Failure versus IgnoredRateLimit and recovery BackendError versus RateLimited.
The automated runner exited 0, verified original source restoration by SHA256,
and reran the unmodified **30-case green**. Baseline also passed all30. Evidence:
`gh475-rl10-typed-probes-r1/outcomes.json` and full logs. These deliberate faults
are expected test evidence, not failures remaining in the restored code. They
are mechanism probes; a separate cargo-mutants score and coverage remain pending.


## Reason-phrase privacy repair — plan before tests or behavior

After the first final code pair, source inspection found another carrier for the
already-forbidden URL/query diagnostics. The pinned reqwest **0.13.4** copies
`hyper::ext::ReasonPhrase` into its status error (`async_impl/response.rs:409–415`)
and prints that phrase (`error.rs:266–275`). `without_url()` removes only the
separate URL field. An initial registry citation used0.12.28; inspection of the
actual Cargo.lock and0.13.4 source corrected that citation and confirmed the same
behavior before this finding was accepted.

A standalone real-wire probe links the exact built reqwest/tokio rlibs and sends
an HTTP429 whose custom reason phrase echoes a synthetic URL/query canary.
Both rustc and runtime exit0. Actual output retains `status=Some(429)`, `url=None`
and nevertheless displays
`http://127.0.0.1:35841/rl10-private-path?api_key=rl10-query-canary`.
Full source, commands and logs: `gh475-rl10-reason-phrase-probe.rs`,
`reason-phrase-process.json`, `reason-phrase-{build,run}.log`. This is dependency
boundary reproduction plus source wiring proof, not yet an executor regression
test. The old SHIP pair and mutation results do not approve the repair.

**FOR/OUT and readiness remain unchanged.** The existing URL/query privacy
requirement covers an upstream that reflects those values in a custom reason
phrase. No new endpoint, authentication, SSRF, retry, public API, dependency or
configuration policy is introduced. DoR risk is narrow response metadata removal
at the already-terminal429 branch; rollback is the same six-site increment.
The actual three callers are `handle_response` in params.rs, JSON-RPC execute and
GraphQL execute. The repair owns only their response bindings and helper call,
the private helper and the scoped tests/documentation.

Chosen repair: recognize429 first, then clear the response extension map before
creating its reqwest status error, and retain existing `without_url()` redaction.
The private helper accepts a mutable Response reference; the three local response
bindings become mutable. Clearing occurs only on429 immediately before a terminal
return, so no remaining response consumer observes the removed metadata. It
removes the untrusted ReasonPhrase without adding a direct hyper dependency.
Headers/body are never consumed or altered by this step; non429 still returns
before any mutation and retains its exact existing format.

Alternatives: leave `without_url()` alone is refuted by the real response; remove
only ReasonPhrase would add a direct hyper dependency for metadata never consumed
after this terminal branch; synthesize a fresh HTTP error would needlessly replace
the genuine response carrier. Clearing terminal-only extensions is the smallest
repair with no additional dependency or counterfeit error construction.

| ID | Discriminating assertion and expected pre-repair result |
|---|---|
| GH475.RL10.C12 | A raw HTTP fixture sends a custom429 reason containing URL/query canaries. The direct reqwest control must call `error_for_status().unwrap_err().without_url()`, assert `url().is_none()`, and still observe the exact canary in Display. This proves that the reason phrase survives URL removal, independently of the original URL field. This control passes before and after production repair. |
| GH475.RL10.C13.R / .J / .G | Independent real REST/JSON-RPC/GraphQL execute cases use C12's raw custom-reason status line and require Http429 with no URL or reflected phrase in Error Display, recovery detail or hint. They also retain RateLimited/retry, RPC-32000 and both untouched budgets. Before repair each fails at a diagnostic-canary assertion. |
| GH475.RL10.C14.R / .J / .G | The same C12 raw custom-reason429 fixture advertises a nonempty body but never completes it. Each execute call must return within a bounded two-second test deadline while retaining the typed/privacy contract; the fixture task is aborted on drop. These also close the earlier optional no-body-await improvement without a performance-percentile claim. |

C13 and C14 share C12's real adversarial raw status-line fixture per protocol: the test
must assert both the bounded return and diagnostic omission, never treat timeout
as expected success. The raw server is test-owned loopback, with bounded header
read and abort-on-drop; no production resolver/SSRF policy is changed. Existing
30 cases remain, including all ordinary-status, statusless and WARN positive
controls. Any fixture refactor must preserve their exact entry methods and values.
The previously planned typed430 probes are updated only for the actual total case
count and pinned restored source hash, then rerun on the final source.

Before behavior: obtain narrow paired plan approval, write real executor failing
tests, compile the strengthened suite red, and obtain separate tests-as-tests
confirmation. After the small repair, rerun green, relevant regressions and
quantitative evidence, then request final code finder closure and the independent
runtime leg. First-final-review comment repairs are included: inherited Failsafe
comments must state Http Display compatibility, not typed discrimination; retry
rustdoc must attach to send_with_retry. The proposed public/shared429 predicate
is an observation: three explicit one-line comparisons remain cheap and the
existing typed probes guard their semantic distinction, with no new API needed.


### Approved reason repair tests — compiled red

The repaired reason-plan gate is closed: original GPT SHIP plus Grok finder SHIP
`grok-20260906T171201Z-46309.md`, actual wrapper exit0 and processok, authoritative
bound SHA `70c7f04452501e7df027f6f431873bcd996a5ba7fd70fcec1bb1ec0cd020a064`,
66,946 bytes. `gh475-rl10-reason-plan-review-r2.verified.json` records that the
first newline-based sidecar digest was rejected and corrected to the wrapper's
actual scope+NUL+material digest. The authoritative ledger remains the binding.

The new shared raw fixture and three protocol cases implement C12–C14. The direct
control strips the URL field before asserting the reflected reason remains;
protocol cases use that identical pending-body fixture and a two-second execute
deadline. They check real Http429, URL removal, RPC/recovery and privacy, then both
budget windows. All original30 cases remain. GitNexus did not index the new
fixture symbols; static caller proof confines them to the two cfg(test) modules.
The inherited Failsafe comment repair has LOW impact/no production caller and
changes commentary only, explicitly withdrawing its stale typed-falsifier claim.

Actual isolated run `cargo test --all-features --lib rl10 --jobs 4 -- --nocapture`
compiled and exited101: **31 passed, 3 assertion failures**, 4,143 filtered,
0.24seconds. Each new protocol case failed on the reflected URL/query diagnostic;
none timed out. The direct C12 control and original30 cases pass. Full evidence:
`gh475-rl10-reason-red-r1/{run.log,process.json}`. No production extension clear
has been applied. Separate tests-as-tests review is pending before behavior.


### Reason tests review and logging repair

The initial paired tests review binds identical SHA
`e223ba0d67c158c465698cb72d9e1d2a10f2182975f6a92eeaf8f8934bb67cc7`,
220,431 bytes. GPT `gpt-20260906T173424Z-23394.md` returned SHIP-WITH-FIXES;
Grok `grok-20260906T173425Z-23399.md` returned SHIP. Both actual wrapper exits0,
processok. GPT's required NOW finding is accepted: the raw reason cases must
check WARN output, not only returned diagnostics. Grok independently suggested
that improvement and found two remaining stale Failsafe comment claims.

The test repair reuses one scoped WARN collector for both original and raw-reason
cases. Each capture requires a positive canary and the actual protocol/status429
WARN event; the raw cases reject the fixture's exact reflected URL and shared
query canary in those captured fields before checking returned diagnostics.
The fixture owns a small test-only outcome carrying that actual URL/secret/log
snapshot, so a canary rename cannot leave consumer tests checking an old value.
The raw control and production-entry fixture explicitly disable environment
proxy discovery. JSON-RPC/GraphQL Failsafe comments now say Http Display
compatibility and delegate typed discrimination to the sibling carrier/probe
cases. All reviewer suggestions are adopted; the source extension clear remains
unimplemented during this tests-only stage.

The exact three repaired test files compiled on the isolated lane with Cargo101:
**31 passed, 3 expected diagnostic assertion failures**, 4,143 filtered,
0.23seconds. Positive WARN capture/protocol/status checks passed; the raw protocol
cases still fail on the returned reason-phrase canary, with no deadline failure.
Evidence: `gh475-rl10-reason-red-r2/{run.log,process.json}` includes every current
test-file hash. Focused GPT finder confirmation of the NOW logging gap is pending;
the original Grok SHIP and its source-verified comment/improvement dispositions
remain part of this tests-as-tests gate.


### Test finder closed and reason repair applied

GPT finder `gpt-20260906T174800Z-57308.md` returned **SHIP**, no improvements,
actual process exit0/processok. Exact bound SHA
`5c7bbbd557f9b936e4af4774074c5bf64cd3da6e79f80d76e818a01082635b2d`,
125,008 bytes, was verified against the wrapper's scope+NUL+material binding in
`gh475-rl10-reason-tests-review-r2.verified.json`. Together with retained Grok r1
SHIP this closes the repaired tests gate before behavior.

Only then, the helper was changed to accept a mutable response and clear its
extension map after the exact429 guard, before `error_for_status_ref`. The three
real response sites pass mutable local references. The genuine typed reqwest
error and existing URL stripping remain; other statuses leave extensions and
existing body handling untouched. Retry documentation now attaches to
send_with_retry; no retry or redaction helper body changed.

Self-QA inspected the full four-file delta against the pinned pre-reason snapshot,
verified exactly three helper calls and the terminal return ordering, and ran
focused formatting plus diff whitespace checks. Refreshed GitNexus reports HIGH
for JSON-RPC/GraphQL through dispatch_protocol; that warning was reported before
editing. Retry/redaction symbols are also HIGH, but only their attached rustdoc
was moved. The new helper has a documented graph gap and three static callers.
The improvement pass reused the scoped WARN collector and shared fixture canary,
avoided a new dependency or synthesized error, and fixed all stale Failsafe
comment claims. No original criterion was removed.

Actual isolated green exited0: **34 passed, 0 failed**, 4,143 filtered, 0.21seconds.
Evidence: `gh475-rl10-reason-green-r1/{run.log,process.json}`; the exact four source
and three test hashes match the compiled result. C12 remains positive against raw
reqwest; all three actual protocol cases now pass returned/log privacy,
RateLimited/retry, RPC mapping, budget exclusion and the pending-body deadline.
Original30 controls remain green. Final code review, refreshed quantitative
coverage/mutation and the independent functional leg remain required.


### Final reason-repair code review and disposition

Both reviewers returned **SHIP**, actual exit 0/process ok, on identical bound
SHA `a5a4dae84593ed8f7401ed1d48eac745f4c208f68e8834990a7d21807e28df8d`,
218,011 bytes: `gpt-20260906T175457Z-73181.md` and
`grok-20260906T175457Z-73186.md`. The ledger and actual process binding are saved
in `gh475-rl10-reason-code-review-r1.verified.json`. GPT had no improvements.
Grok's two optional observations are disposed explicitly:

- **Fix in this change:** helper rustdoc now says that reason-phrase metadata is
  removed before constructing the typed error. This comment-only post-review
  change is recorded in `gh475-rl10-final-rustdoc-delta.json`: reviewed/compiled
  module SHA `1a7222611763ea6532c561a7751dc463e54660a55a47be2bb0ac98530ae186b6`,
  final SHA `70164c214cb564b324271a1bb0c62ec03509dcd727829b4cc6fd8f4014930638`.
  Runtime evidence binds the former; no behavior/test changed and no runtime
  rerun is claimed for this comment.
- **Record as an observation:** the helper's `err()?` could theoretically fall
  through to body handling if a future reqwest changed status-error semantics.
  Pinned reqwest 0.13.4 returns Err for every client/server error status, so the
  guarded 429 residual is unreachable now. C12 and the actual pending-body
  executor cases pin the dependency behavior. Introducing a synthesized error,
  panic or dependency for hypothetical semantics would expand this repair with
  no current defect. No new ticket or behavioral change is warranted.

### Refreshed regression and quantitative evidence

All paths below are in the external scope-review evidence directory, with full
commands, source hashes, real exits and untruncated logs retained.

| Check | Actual result | Evidence |
|---|---|---|
| All-feature focused `--lib rl10 --jobs 4` | 34 passed, 0 failed | `gh475-rl10-reason-green-r1/` |
| Existing `capability::executor` regressions | 102 passed, exit 0 | `gh475-rl10-regressions-reason-r1/` |
| Existing recovery / invoke budget / RPC regressions | 13 / 9 / 1 passed, each exit 0 | Same regression directory |
| Copied-source typed budget 429→430 probe | Three expected semantic failures, exit 101; restored 34 green | `gh475-rl10-typed-probes-reason-r1/` |
| Copied-source typed recovery 429→430 probe | Three expected semantic failures, exit 101; restored 34 green | Same typed probe directory |
| Remove terminal extension clear only | Three returned-diagnostic canary failures, exit 101 | `gh475-rl10-reason-security-probes-r1/outcomes.json` |
| Add original URL to WARN only | Three WARN-canary failures, exit 101 | Same security probe directory |
| Security-probe restoration | Exact source restored, 34 green, runner exit 0 | Same directory; `restored-green.log` |
| Refreshed cargo-mutants | 22 candidates: 16 caught, 2 missed, 4 unviable; actual exit 2 | `gh475-rl10-cargo-mutants-reason-r2/` |
| Clean LLVM instrumentation and export | Focused 34 + budget 9 + RPC 1 passed; JSON/LCOV export exit 0 | `gh475-rl10-coverage-reason-r1/` |

Cargo-mutants' raw viable score is **16/18 = 88.89%**, above the critical 85%
threshold. Exit 2 truthfully denotes two survivors; it is not relabeled exit 0.
Both survivors replace `BudgetOutcome::of`'s `status().is_some()` guard with a
constant. The false variant falls back to the established text predicate; the
true variant retains the tested generic statusless outcome. Neither survivor is
excluded or claimed equivalent. The distinct mandatory 430 probes prove that
the actual typed budget and recovery decisions cannot silently use text as their
oracle. Four unviable candidates ask types without `Default` implementations to
use Default; full compiler diagnostics remain in the tool output. Manual privacy
probes are additional evidence, not folded into the automatic score.

LLVM's exact absolute-source-path summary is
`gh475-rl10-reason-coverage-summary.json`: **22/23 mapped executable lines =
95.65%**, **34/37 mapped source regions = 91.89%**. The critical mapped-line
threshold passes; the 100% changed-region target does not. No branch coverage
claim is made. The three zero regions are the unreachable Option residual after
the exact 429 guard and two tracing status-expression macro regions, despite
live protocol/status WARN assertions. async_trait supplies no added-body region
mapping for JSON-RPC/GraphQL; their actual execute entry counts are 14 each and
are not substituted for covered-line counts. Full JSON and LCOV are retained so
these limits remain independently inspectable.

The first refreshed mutation discovery attempt exited 5 before any baseline:
its historical diff named `&response` while final source uses `&mut response`.
The rejected input and stderr are preserved in
`gh475-rl10-cargo-mutants-reason-r1-rejected/`; it has **no mutation score**.
Rebuilding the exact four-file scope fixed discovery without production changes.
Local process creation also intermittently reported `Too many open files`;
reaping completed review sessions and retrying the read/copy succeeded. These
infrastructure failures are distinct from intentional semantic red tests.

### Remaining delivery boundary

The coordinator built a real CLI successfully and launched an isolated AC-only
functional driver against pinned SHA
`43a4b5ec439d0c96f9e48a02edaff13d3f4291131835c30b18646133fda18ce1`.
The r2 driver process exited0 but graded overall **FAIL**, so it contributes no
functional acceptance (`rl10-independent-driver-r2/result.md` and
`evidence/report.md`). Its REST/JSON-RPC calls saw402 and GraphQL lacked a query.
The coordinator's four controlled direct requests reproduced HTTPBingo429 with
a User-Agent and402 without one; the gateway default sends none. The original
brief also incorrectly placed GraphQL's query under provider.config.query,
whereas the supported provider mapping consumes body.query. A corrected AC-only
r3 run used an explicit synthetic User-Agent and the supported query carrier,
on the same pinned binary. It finished with actual process exit0 and **all four
public ACs PASS**. The full report and machine checks were read; evidence is
`rl10-independent-driver-r3/driver-evidence-20260906T185421Z/`.

| Evidence boundary | Observed result |
|---|---|
| REST, JSON-RPC and GraphQL429 | Two actual uncached dispatches per protocol, each RATE_LIMITED/retry=true and exactly one fresh protocol/status WARN |
| Failure budgets | All six429 dispatches leave capability/server active; public stats show6 invocations and0 cache hits |
| Non429 control | One isolated500 returns BACKEND_ERROR and exhausts the configured one-sample backend/capability budget, visibly disabling the fixture |
| Public privacy and delivery | Current request IDs returned; URL, method/query and synthetic canaries absent from the accepted response/log slices; same executable SHA verified |
| Boundaries retained | Upstream bodies were empty. Rust variants, nonempty-body suppression and private exact window counts remain component evidence, not UAT claims |
| Setup and cleanup | Initial cached retry detected and excluded; accepted matrix rerun with cache disabled.12 evidence-accounted public transactions; all driver-owned processes stopped |

Canonical artifact files are `report.md`, `outcomes.json`, `checks.json`,
`artifact-sha256.txt` and the raw `spark-run/` directory. Earlier failed and
superseded setup evidence is retained. This closes the isolated functional leg;
it does not close integrated release acceptance.

The coordinator imported the original inherited design history through commit
`08535d7`. That history already described string-based rate-limit detection.
This delivery's approved typed429 classification, safe diagnostics and red/green
falsifiers are the increment established above; importing old documents does
not turn their historical behavior into evidence for this implementation.

The isolated Spark source predates some concurrent firewall/clock/signing edits;
owned RL10 implementation hashes are pinned, but this is not an integrated
all-release pass. Main-tree static checks, zero-warning enforcement, SCA,
coverage-target reconciliation, issue/PR AC comments, CI, merge and deployment
remain release gates. Root owns the release ledger and driver. The author keeps
its isolated build cache only while subsequent authorized compilation needs it;
final H8 cleanup remains required. The standalone reason probe binary was removed
with a receipt in `gh475-rl10-reason-phrase-binary-cleanup.json`. No commit, push,
issue closure or release completion is claimed by this handoff.
