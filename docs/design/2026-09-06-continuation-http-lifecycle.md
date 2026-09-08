# Continuation cleanup through the real HTTP serving lifecycle

Stage: P2 closed; common shutdown-owner repair and focused quantitative checks green.
Final code review and independent functional acceptance remain open.
Owner: release lead. Parent: `2026-09-06-continuation-scheduled-expiry.md`,
EXPIRY.4 and EXPIRY.5. The already reviewed worker and builder tests remain valid.
This increment does not claim full MRTR.8b or NFR.PERF.3 acceptance.

FOR: prove that the production HTTP/TLS entry point owns cleanup during service
and stops it on graceful shutdown, cancellation and startup failure. OUT for this
increment: stdio's shared loop (BRIDGE owns it), rotation, durable tasks, numerical
performance claims and changes to authentication or shutdown policy. Those remain
release obligations. Value: catch an owner dropped between the tested builder and
the actual network service, a gap that component-only tests cannot expose.

## Existing facts and chosen seam

- `Gateway::run` constructs the real builder, retains `HttpServeContext`, builds
  `AppState` and the router, binds one listener, serves HTTP or TLS, then drains.
  The indexed impact is LOW with no indexed callers, but static inspection finds
  the actual CLI caller at `src/main.rs:647`; this is not a zero-caller guarantee.
- The only production shutdown source is `support::shutdown_signal`, which
  awaits Ctrl+C/SIGTERM and broadcasts once. `serve_tls` already accepts a shutdown
  future. Plain HTTP accepts that future through Axum's graceful-shutdown API.
- The actual builder now supports an internal trusted clock. Its public entry
  point still supplies the real epoch, so a separate HTTP fixture cannot observe
  deterministic deadlines unless the entry point forwards this existing seam.
- The TLS helper currently discards the join handle of its shutdown bridge task.
  A cancellation test will establish whether this leaves the provided shutdown
  future alive. The existing `AbortOnDrop` pattern can own that task if needed;
  no separate shutdown framework is justified.
- Existing `cert_manager` unit fixtures build valid temporary CA/server material
  and validate `MtlsConfig` with `require_client_cert: false`. Tests will reuse
  that PKI construction pattern and trust only their generated CA. The URL host
  is `localhost`; the reqwest client uses `.resolve("localhost", bound_addr)`
  and `.no_proxy()` so certificate SAN validation and loopback routing agree.
  This selects the TLS branch without changing gateway authentication policy.

Keep the public `Gateway::run(self)` signature and its caller unchanged. It will
forward to one private production method taking the existing cleanup runtime and
a shutdown-future factory. The factory receives the existing broadcast sender;
production passes the existing signal function unchanged. Tests provide a bounded
oneshot-controlled future that broadcasts the same shutdown message. The current
HTTP initialization, router creation, one bind, warm-start, serving and drain body
moves into this method without a parallel implementation.

The private method is named `Gateway::run_with_runtime<F, S>`. It consumes
`self`, `cleanup_runtime: CleanupRuntime`, and `shutdown: S`, and returns
`Result<()>` asynchronously. Bounds are `S: FnOnce(broadcast::Sender<()>) -> F
+ Send + 'static` and `F: Future<Output = ()> + Send + 'static`. A final parameter,
`lifecycle_events: Option<mpsc::UnboundedSender<HttpLifecycleEvent>>`, exists only
under `cfg(test)`; the public wrapper passes `None` in test builds. Production
passes `CleanupRuntime::default()` and the existing `shutdown_signal` function.
The factory is invoked once immediately before selecting the serving branch,
after successful bind, using the same sender held by the existing background workers. No public
constructor/configuration accepts a runtime clock or observer.

A cfg(test)-only lifecycle observer reports the actual built continuation Arc and
the address returned by the actual listener's `local_addr()`. It does not replace
state, inject requests, prune the table or alter production configuration. The Arc
lets a test retain state after early failure or cancellation; ownership of that
Arc must not keep the cleanup task running. Port-zero fixtures use the observed
bound address, avoiding a reserve/drop/rebind race. The early bind-failure fixture
instead holds an occupied listener and requires the real run method to return an
address-in-use error after it has published the built state.

`HttpLifecycleEvent` is a cfg(test)-only enum with exactly
`Built(Arc<ContinuationState>)` and `Bound(SocketAddr)`. Publish `Built` immediately
after constructing `HttpServeContext` and cloning its actual MetaMcp, before any
subsequent startup operation can return. Publish `Bound` immediately after the
single successful `TcpListener::bind`, using that listener's `local_addr()`, before
the startup banner and warm-start. Each event is emitted at most once, in that
order; a common bind error yields only `Built`, while a TLS material error yields
both. Observation receiver closure is ignored and never changes runtime behavior.
The channel is unbounded only under cfg(test) and emits at most two events.

The TLS-specific startup-error case uses valid generated paths through
`Gateway::new`, then replaces the server PEM with a known malformed fixture before
running. It requires both events and the actual certificate-loader/config error
from `serve_tls`/`build_tls_config`, followed by idle-cleanup termination. The
existing config validator does not parse these PEM files; a constructor rejection
or failure before the Bound event is a fixture failure, not TLS coverage.

The library-only constructors remain runtime-independent. The private runtime
method remains production code, used by the CLI-facing method; only observation
is test-only. Public HTTP, TLS, signal handling and shutdown timeouts are unchanged.
The common serving entry point retains the signal-task owner described below,
so cancellation owns both cleanup and the shutdown future it started.

### Observed cancellation defect and ownership refinement

The eight real-server cases now compile and execute. At the pinned r3 snapshot,
six pass and both abort cases fail specifically with `shutdown future survived
the completed serving task`. Their real HTTP/TLS requests and serving-task
cancellation prerequisites succeed; this is not a fixture or compiler failure.
Both retain a caller-provided shutdown future: the TLS bridge above discards its
task handle, and Axum 0.8.9 also spawns its shutdown future internally. Cleanup
itself stops in these cases; its stopped clock and retained raw state are checked
before the shutdown-future assertion.

Refine the anticipated ownership repair at the common serving entry point:
after the successful bind, retain one existing `AbortOnDrop` guard for the task
that owns the supplied shutdown future. That task awaits the unchanged signal
and sends completion through a oneshot. The selected HTTP or TLS serving helper
receives a future awaiting that receiver. Canceling the owning run aborts the
actual signal task; dropping its sender wakes the framework's bridge as well.
Normal shutdown still broadcasts through the existing signal implementation
before completing the server's graceful-shutdown future. A startup error drops
the owner and listener. No new shutdown framework, timeout or public API.

This replaces the tentative TLS-only guard mechanism above with one common
owner because the same observed defect exists on both transports. The FOR/OUT,
HTTP.1–HTTP.5 acceptance cases, signals and shutdown policy are unchanged. The
P2 packet included this refinement and the observed-red tests. Source-backed impact: the new private method is
not indexed (UNKNOWN), the indexed public `Gateway::run` is LOW, and direct
inspection finds its CLI caller and the private method's wrapper/test callers.

P2 closed with retained Grok r1 SHIP and GPT finder r2 SHIP (both actual zero
exit, unique authoritative ledger rows and bound source/material hashes).
GPT's sole NOW finding was repaired by seeding and snapshotting a live record
before serving exit, asserting its preservation on return, then checking that
same record after the three stopped-clock ticks. The revised baseline still
executes eight tests with six passes and two semantic abort failures. A temporary
real-runtime clear after serve makes both graceful tests fail on the new record
preservation assertion; the runtime was restored byte-for-byte afterward.
External receipts are `http-lifecycle-tests-review-r1.verified.json`,
`http-lifecycle-tests-review-r2.verified.json`,
`http-lifecycle-red-r4-source-manifest.json` and
`mcp-gateway-v4-http-survivor-fault-r1.json` in the release evidence directory.
Optional watchdog consolidation and diagnostic refinements are deferred under
the operator's bounded incremental-delivery plan. The common owner now uses the
existing `AbortOnDrop`, keeps its named local alive through serve/drain, and
passes only oneshot completion to the two serving frameworks. Final code review
and independent functional acceptance remain open.

### Implemented repair and focused validation

The production serving entry now retains the named signal-task owner through
serving and drain. The repaired eight-case suite passes, as do the three builder
and nine cleanup-worker regressions. Removing only `AbortOnDrop` from this new
task reproduces both transport abort failures on the shutdown-future assertion;
restoring the source returns all eight HTTP cases to green. The generated
`cargo mutants --in-diff` inventory contains one viable whole-method replacement;
the tool catches it (1 caught, 0 missed, 0 timeout, 0 unviable). That small inventory
does not replace the targeted ownership and record-preservation falsifiers.

Coverage uses the actually executed instrumented binary, SHA256
`97c1efd4bb5ece95410c58576e9964ccbfb7fdbcabf6a57f716a68373a8fe0d6`:
cleanup module 50/50 lines and 50/50 regions; ownership context 9/9 lines and
6/6 regions; all nine new executable shutdown-owner lines have positive
execution counts. These are scoped measurements, not whole-gateway coverage.
The default combined export also loaded older binaries with duplicate zero-count
functions at the same source path; it is retained for diagnosis and superseded
by the direct current-binary export, without dropping uncovered current code.

Evidence in the release directory: `http-shutdown-owner-validation-r1.json`,
`http-owner-quant-r1/summary.json`,
`http-owner-quant-r1/current-binary-export.json`,
`http-owner-generated-mutants-r1/mutants.out/outcomes.json` and
`mcp-gateway-v4-http-owner-detached-fault-r1.json`. Source restoration is hashed;
the final restored suite is `mcp-gateway-v4-http-owner-restored-green-r1.log`.
The three existing stdio/account scaffold warnings remain separate release work.
No commit, full MRTR.8b grade or release-readiness claim follows from these checks.

## Acceptance cases and falsifiers

All cases run in the existing isolated-child harness: temporary HOME/XDG, exact
test name, completion marker, 45-second real watchdog. Disable automatic external
backends and use loopback only. Paused Tokio time controls only explicit test ticks;
observations use the existing non-auto-advancing helper and its real watchdog.
Only the test epoch advances continuation deadlines. No sleep-based pass oracle.

| Case | Required observation | Level/type | Broken behavior it rejects |
|---|---|---|---|
| HTTP.1 plain and TLS | Start the actual run method on port0, receive its state/address, and complete a real Meta-MCP request with matching JSON-RPC ID and no error. Seed two different live deadlines in that actual state. Advance epoch past one and explicitly tick once; raw snapshot has only the live neighbor, with no follow-up request or public table observer. | integration/lifecycle/parity | Wrong state, dropped owner, ignored clock, absent scan or clear-all fails. |
| HTTP.2 plain and TLS | Witness two scans during service; keep a MetaMcp/continuation clone and a live record. Trigger the injected graceful shutdown, await successful run completion, then advance epoch and three ticks. Clock-call count stays fixed and the now-expired raw record remains untouched. | integration/shutdown | Detached cleanup, clone-dependent shutdown or stop-on-idle-only fails. |
| HTTP.3 plain and TLS | After a successful real request and witnessed scan, abort and join the actual run task. The result is cancelled; three later ticks leave calls and raw state unchanged. The supplied shutdown future's drop witness must also fire, including TLS. | integration/cancellation/resource ownership | Cleanup or the TLS shutdown bridge surviving cancellation fails. |
| HTTP.4 common bind failure | Hold the desired port, run the actual entry path, observe only Built, and require the actual I/O AddrInUse error rather than a readiness timeout. Retain state and advance epoch/ticks after the returned error: no cleanup calls occur. | integration/fault injection | A worker leaked by a common early return remains observable even though no server was ready. |
| HTTP.5 TLS startup failure after bind | Build with valid PKI, corrupt only the server PEM, then run and observe Built followed by Bound. Require the actual TLS certificate-loader/config error; retain state, seed a live record, advance epoch/ticks and verify no scans or reclamation. | integration/TLS fault injection | TLS-specific startup returns that leak the worker are detected independently of common bind behavior. |

The request is POST `/mcp`, JSON-RPC method `tools/list`, a unique integer ID and
`params._meta` containing `io.modelcontextprotocol/protocolVersion: "2026-07-28"`
and `io.modelcontextprotocol/clientCapabilities: {}`. Headers are
`Content-Type: application/json`, `Accept: application/json, text/event-stream`,
`mcp-protocol-version: 2026-07-28` and `mcp-method: tools/list`. No session,
`mcp-name`, Origin or authentication override is supplied. The TLS certificate CN
and DNS SAN are `localhost`, and the URL is `https://localhost:<bound-port>`;
`OriginPolicy::host_allowed` permits that actual loopback spelling. The plain URL
uses the observed numeric loopback address. No public URL or unauthenticated
network-bind escape hatch is configured. A successful request is a prerequisite to
HTTP.1-.3; a handshake, auth or metadata failure is a fixture failure, not an expiry
red. After every completed run, assert the event channel closes with no extra or
out-of-order events. After HTTP.5, rebind the observed address to prove listener
release as well as worker termination. The raw state snapshot is the same cfg(test) non-reclaiming map observation
used by the reviewed builder tests. Counters support, rather than replace, the
state and task-termination assertions. TLS PKI/handshake and plain HTTP startup are
fail-fast controls before interpreting any lifecycle result.

## Sequencing, risks and validation

Review this clarification against canonical DoR before adding the seam/test code.
The minimal scaffold exposes the actual run body with the named clock/signal
inputs and observer; its production wrapper supplies the existing defaults, and
it makes no lifetime repair. Existing builder/worker behavior may already satisfy
HTTP cases. Preserve the prior reviewed A+C behavioral reds and record each new
case honestly: the TLS abort case must expose the detached shutdown future at an
assertion, while wrong-clock/dropped-owner falsifiers must be exercised with valid
compiled mutations. Review the compiled tests before repairing TLS ownership.
Compiler failures, handshake failures and unrelated startup errors never count
as behavior reds.

After implementation: run these eight cases, existing 3 builder +9 worker +23
observer +3 builder-caller +constructor tests, and the existing TLS support tests.
Use scoped fmt/diff checks first; then critical source coverage and valid mutation
probes for dropped owner, default-clock substitution and detached TLS bridge.
Run the final paired code review with the actual source and independent real-client
lifecycle drive; private raw-map assertions are named as component-only clauses.
Full stdio EOF/cancellation and the already frozen performance matrix still block
combined Change C acceptance. No source or test semantics in the parent worker
increment are silently narrowed by this clarification.

Principal risk is refactoring the long production run method while signing and
firewall modify shared construction. Only root edits its wrapper/body/lifecycle
hooks and `support::serve_tls`; other agents retain their exact builder/security
hunks. Before sync, re-read and pin the dependency-complete snapshot. No original
Claude checkout edits, service restart, persistent deployment or user-data change
is required for these fixtures.


## P1 review dispositions

The first GPT review's three NOW findings are adopted: exact method/event contract,
a real TLS-only startup error after bind, and explicit SAN/URL/resolver alignment.
The total remains eight cases: three parity pairs plus common bind and TLS startup
errors. Cleanup scan events will be reused for ordering where useful; the existing
bounded non-auto-advancing poll helper remains necessary to prevent paused Tokio
from silently advancing periodic timers while waiting for network I/O. No new
unbounded busy-wait loop is introduced. The PKI recipe uses the existing public
CertGenerator API in one lifecycle-fixture helper; moving the certificate-manager
unit helper would widen a test-only refactor without changing the lifecycle
oracle and is not required for this increment.


### Shared test support

Mechanically move the existing `isolated_child` and
`observed_without_time_advance` helpers into one cfg(test)-only
`server::test_support` module, retaining their current watchdog/clock semantics.
Builder and HTTP tests both call it. Add only a cfg(test)
`CleanupRuntime::with_events(epoch, events)` constructor and make `CleanupEvent`
visible to sibling server tests; keep the runtime fields private. Existing worker
and builder cases remain regression controls for this observation refactor.

### Scoped DoR ledger (P1 readiness, not release acceptance)

Evidence keys: **A** is this design/HTTP.1–HTTP.5 and the parent EXPIRY.4/.5/.8
contract; **B** is live Linear MIK-7212, refreshed 2026-09-06 18:52 UTC; **C** is
`server/mod.rs` (`run`, builder, AbortOnDrop), `server/support.rs` (`serve_tls`,
shutdown_signal), and `router/origin_guard.rs` (host_allowed); **D** is the existing
builder/worker/source coverage and compiled-fault evidence recorded in the parent;
**E** is lockfile-pinned upstream API documentation/source: Tokio1.53.1
`runtime/task/join.rs:18,227`, Axum0.8.9 `serve::WithGracefulShutdown`, and
axum-server0.8.0 `src/handle.rs:70`. The latter two task/handle sources were read
from the Cargo registry when the browser could not fetch their exact versions.
Axum's [published API](https://docs.rs/axum/0.8.9/axum/serve/struct.WithGracefulShutdown.html)
also confirms the shutdown-future bound and bound-address observation.
**F** is external `http-expiry-design-review-r2.verified.json`, exact bound
74,233-byte material, actual exits0/SWF; its findings are adopted below.

| Gates | Disposition and evidence |
|---|---|
| G0 | I/E2: highest remaining unassigned lead-owned security prerequisite in the current release delivery allocation. MIK-7212 is Urgent; bridge, accounts, tasks, signing, response enforcement and rotation already have concurrent owners. This closes the proven owner-lifetime evidence gap without pre-empting those increments. B, delivery ownership plan. |
| G1,G3 | Mandate-justified security work, with reliability benefit: abandoned continuation state consumes a bounded security-sensitive capacity table, and detached cleanup/shutdown work outlives its serving owner. Mandate: the operator explicitly instructed full4.0 release delivery under development-process/DoD. Deadline: before publishing v4.0.0, as recorded in B; calendar dueDate is null and no calendar promise is invented. The canonical security path skips monetary NPV/ROI ratios. Confidence is high in the obligation, not in a financial-return estimate. A,B. |
| G2 | I/E3: planning allocation, not a measured forecast: author/test12,000 tokens + context reacquisition2,000 + review/finder reserve200,000 =214,000 tokens for the next increment. The large review reserve is grounded in actual R2 GPT147,882 and R3 GPT89,902 reported tokens; earlier review cost is sunk and not hidden. Log actual usage separately; exceeding this allocation triggers a narrower review packet/checkpoint, never omitted validation. Planning split: author10,000 input+2,000 output; context2,000 input; review180,000 input+20,000 output. Total192,000 input+22,000 output=214,000 tokens. Canonical Opus4 accounting rates ($15/M input+$75/M output) give192,000×15/1,000,000 +22,000×75/1,000,000 =$4.53. This is the required planning budget under the local gate formula, not actual vendor billing, a current market price or observed usage. F and R3/R4 process/output receipts. |
| G4,G5 | E1/E4: eight specific lifecycle cases; the production ownership gap cannot be closed by builder-only results. No separate server implementation. A,C. |
| B1 | E2: live MIK-7212 retains original MCP728.MRTR.3 and now includes unchecked stable release criterion MIK-7212.MRTR.8b with an explicit HTTP mapping. HTTP.1 (plain/TLS) proves idle lifetime reclamation; HTTP.2 (both) graceful ownership; HTTP.3 (both) cancellation/shutdown-future ownership; HTTP.4 common bind failure; HTTP.5 TLS startup failure/listener release. These eight cases map to parent EXPIRY.4/.5; stdio, performance and final delivery gates remain separate. Exact write/readback: external http-lifecycle-acceptance-update.request.json, .response.json and .readback.json. |
| B2 | E3: B is In Progress, Urgent,8points, assigned to Mikko, labeled mcp-gateway, project mcp-gateway, team Mikko, milestone v4.0.0, parent MIK-7211. The team has no active cycle (live query returned[]), so a cycle assignment is N/A. Field repair/readback: external http-lifecycle-metadata-update.json and http-lifecycle-linear-fields-20260906.json. |
| B3,B4,B5 | E2/E4: MIK-7388 remains the parent bridge blocker; this HTTP increment depends only on the reviewed builder/worker, not unfinished stdio. Stable parent/child ACs map to the eight tests in A. Milestone/Urgent positioning is B; no new floating issue is created. |
| T0 | E4: security integration (mandate path), with reliability benefit. Failure is a detached cleanup/shutdown task retaining work after the service ends; success requires zero later scans in every named exit path. A. |
| T1,T1b | I/E2: use existing Rust/Tokio/Axum ownership. Considered Loom/model checking for task interleavings; it cannot replace actual HTTP/TLS entry-point evidence and adds a dependency/model here. No new emerging-tech advantage or moat claim. C,E. |
| T1c | N/A: no new cryptographic primitive/key agreement; fixtures call the existing certificate generator and production TLS policy is unchanged. C. |
| T2,T3,T4,T5 | E2/E4: existing builder, AbortOnDrop, worker events and child/watchdog helpers reused. The run wrapper, bind/serve/drain and TLS handle are the exact integration points. One clock/state owner serves both transports. A,C,D,E. |
| T6 | N/A: no ML numerics, quantization or distributed collective. Async task ownership does not introduce a numerical algorithm. |
| G6,G7,G8,G9 | E4: options are builder-only proof, a parallel test server, and the selected actual production seam. The first misses owner drop; the second can drift. Risks are wrong TLS host, timer auto-advance and shared construction edits; resolved fixture/clock/ownership contracts address them. A,C,F. |
| G10,G11,G12 | E2/E3: highest fixture risks (SAN/Host policy, real bind location, shutdown future bounds) checked at C/E before scaffold. D establishes the worker/builder primitives. The actual TLS cancellation outcome remains scheduled to P2 before any ownership repair; a constructor/handshake failure stops that test and cannot pass a lifecycle gate. |
| G13,G14 | N/A moat analysis: this reliability increment makes no novel-capability or optimization moat claim. Platform synergy is reuse of the existing continuation owner, recorded under T5. |
| G15 | E4: pre-mortem: wrong-host handshake/refusal hides missing cleanup; time auto-advance fabricates expiry; retained MetaMcp clone hides detached ownership. Require real request success first, explicit ticks/nonadvancing waits, and retained-state/no-later-scan assertions. A. |
| G16 | E2: three upstream implementations in E establish prior art for owned tasks, graceful shutdown and TLS handles. An arXiv/market survey is N/A to this existing-stack test seam; no new scheduler/server is proposed. |
| G17 | E1: reversible local source/test change; no migration, deployment or one-way data action in this increment. |
| G18 | E4: stop on an invalid real request, unexpected error stage or wrong event order; repair the fixture before interpreting expiry. Success floor is all eight cases plus retained controls. No emerging-tech bet/timebox waiver is used. |
| G19 | I/E2: operators gain a gateway whose continuation cleanup stops with HTTP/TLS service lifetime; measurable outcome is no scans after each named terminal path while idle live service still reclaims expired entries. A,B. |
| G20,G21 | N/A: no numerical performance improvement or novelty claim here. Parent EXPIRY.8 still requires the frozen benchmark before combined cleanup acceptance. |
| C1,C2,C3,C4,C5 | E1/E2: one actual run body, shared test helpers, named private signature/events, eight falsifiers; public run and production defaults preserved. C,A. |
| C6 | E4 STRIDE: no new caller-controlled clock/observer/config input (spoof/tamper/elevation); events stay cfgtest and contain no key material (information disclosure); exact run receipts support attribution (repudiation); bounded watchdogs/channel events and owned tasks address resource denial. Existing authentication/TLS remain in the exercised path. |
| C7,C8,C9,C10 | E1: reuse ownership primitives, no production observer allocation, no duplicate serve loop. Runtime changes are private forwarding plus a TLS task guard only if its test exposes the leak. Parent scan/perf obligations remain. |
| C11,C12 | E1: target a reviewable production patch under60 net lines and shared tests around300 lines; split review units if larger without dropping ACs. Exact protocol and lifecycle contracts above; all retained parent tests run. |
| C13 | N/A at DoR: canonical mutation threshold moved to DoD; critical coverage≥95% and viable mutations≥85% remain final gates. |
| C14,C15 | E4/E1: existing versioned MCP2026-07-28 over actual loopback HTTP/TLS; no new wire schema. Test endpoints are local unauthenticated fixtures behind existing Host/TLS guards; no real accounts/data or cross-region store. |
| C16,C17 | E1/E4: one serving owner, weak worker reference, one expiry predicate and one clock. Cancellation joins the run task; graceful and startup errors have explicit postconditions. No cross-service retry/fallback policy changes. |
| P1,P2,P3,P4 | E1: test-only events plus existing observability; reverting this increment restores prior source. No feature flag needed for invariant task ownership; worker's4096-entry cap stays fixed. Broader NFR.OBS.4 work remains a release dependency. |
| P5 | N/A new-service SLO: this starts no new service. Existing gateway SLO and parent performance contract still apply. |
| P6,P7,P8 | E1: no migration; add cases to existing Cargo test execution, run fmt/clippy and critical quantification, then final code/independent functional review. No new alert channel; release CI and operational evidence remain required. |
| L1,L5 | E2: no new dependency/license; existing MIT/PolyForm file notices retained and fixtures use pinned crates. Release SBOM/SCA remains mandatory, not claimed complete here. Cargo.lock and CLAUDE.md license matrix. |
| L2,L4 | N/A new personal-data/cross-border processing: synthetic in-memory deadlines and generated ephemeral PKI only, temporary HOME/XDG removed by harness; no new production data fields or transfers. |
| L3,L6,L7 | N/A: no AI feature/device contribution/new crypto or ML distribution in this increment. Existing release-wide security/legal obligations are unchanged. |
| O1,O2,O3,O4 | E1/E2: existing server modules plus bounded cfgtest support; no generated logs/checkpoints in repo. This doc links to its parent. No irreversible architecture change, so a new ADR is N/A. |

The ledger establishes readiness of this bounded increment; it does not assert
that planned HTTP cases, final reviews, benchmarks, CI or release gates have run.
R2 fixes also require one real loopback hostname across SAN/URL/Host, exact modern
request metadata, shared helper reuse, no extra lifecycle events, and listener
rebind after TLS startup failure. Scope and acceptance remain unchanged.
