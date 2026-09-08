# Continuation scheduled expiry — mandatory Change C

Status: worker implemented and code-reviewed; production builder clock/owner
wiring is in focused validation after separately reviewed assertion-red tests.
Actual HTTP/stdio I/O lifecycle, quantitative gates and performance remain open.
Owner: release lead.
Paired r7 finder closure: both SHIP, actual exits0/process ok, bound SHA256
acf01d60b5f9b65607d5dc1324b1ebfe62bb48fd0b895af0e9db66fb43822bbd,
15918 bytes. Earlier r6 findings remain in review history as repaired, not ignored.
FOR: reclaim abandoned continuation state on an idle gateway, closing the lifetime
half of MRTR.8b alongside the observer prerequisite (Change A). An observer-only
fix does not meet that requirement. OUT: distributed state, task persistence,
changing continuation wire deadlines or pretending cancellation undoes a write.

Value/acceptance: an expired record disappears without a request, admission or
public observer. Existing live records remain usable; full-capacity admission
continues to reclaim inline. Prove both HTTP and stdio production construction
starts cleanup and every service exit stops it. No numerical improvement is
claimed before the bounded workload measurements.

## Mechanism and ownership

Reuse the server's `AbortOnDrop` pattern, already used for stdio backend cleanup,
and the existing `Arc<ContinuationState>` shared with the actual invoke path.
Add a focused `server/continuation_cleanup.rs` module with one task function.
The async `Gateway::build_meta_mcp` takes an internal `CleanupRuntime` containing
the epoch callback and creates a cleanup guard together with the
built meta gateway. A nonoptional serving owner keeps the meta gateway and guard
in one lifetime; `BuiltMetaMcp` carries that owner rather than a guard that a `..`
destructuring can silently drop. HTTP moves it into an owner-required
`HttpServeContext` retained until serving/draining ends;
stdio moves it into the shared `StdioServeContext` described below. Dropping any
startup failure, cancellation or shutdown path aborts the task. Every destructuring
site must name and retain the serving owner explicitly; a cloned meta handle alone
cannot satisfy ownership. A constructor
test must reject a guard dropped immediately after building. Library-only
`InFlight` and `ContinuationState` constructors remain runtime-independent.

**One real stdio seam, coordinated with BRIDGE.** Extract the production loop as
`async fn serve_stdio<R, W>(context: StdioServeContext, reader: R, writer: W) -> Result<()>`,
where `R: AsyncBufRead + Unpin + Send + 'static` and
`W: AsyncWrite + Unpin + Send + 'static`. `run_stdio` builds the same context and
calls it with `BufReader<Stdin>` and `Stdout`. Context owns the serving owner,
proxy/multiplexer, policies, limits and telemetry sink. Root supplies the cleanup
clock callback and a test observation handle to the actual continuation state;
BRIDGE owns the single reader/dispatch/writer loop. Both `Gateway::run` and
`run_stdio` pass the trusted production `CleanupRuntime` through that builder.
In-crate tests pass their controlled epoch through the exact same builder and
retain its owner in the same serving contexts. No parallel test-only builder or loop.
EXPIRY.4/.5 invoke that function with Tokio duplex streams and paused time, send
real initialize/initialized/call frames, and close/drop/cancel those exact I/O
handles to exercise EOF and failures. The clock/observation seam is internal and
never an untrusted protocol argument. This resolves GPT r4's NOW finding: a real
subprocess need not share the test process clock, because the production serving
function itself accepts controlled I/O and the owned runtime context.

The task keeps a weak state reference across waits, upgrades only for the bounded
scan, and does not keep the gateway alive. It uses one 1-second Tokio interval
with missed ticks skipped. Consume the immediate first tick without scanning;
the first scan occurs one interval after startup. On subsequent ticks obtain the
trusted epoch callback and call crate-visible `InFlight::reclaim_now(now)`. It
locks `held` once and calls existing `reclaim_abandoned`, amended to return the
before-length minus after-length. Change A's guard calls that same helper and
ignores the count. Never infer removals from a post-reclaim guard or invoke `len`
for its side effect. Do not create a second expiry predicate or copy the 300-second continuation lifetime. Expiry is
strict (`now > deadline`), including on a tick exactly at the deadline. This
gives at most one tick of idle residency after a deadline is observed passed,
plus runtime scheduling delay; it is not a hard real-time guarantee. Clock jumps
remain explicit: deadlines use the existing trusted wall-clock epoch, while
scheduling uses monotonic Tokio time. A backwards wall-clock jump can defer
epoch expiry and must be documented and tested as that existing clock contract.

The loop accepts an internal clock callback for deterministic tests; production
passes the existing trusted clock function. Tests use a controlled epoch and
Tokio paused time (`#[tokio::test(start_paused = true)]` and `test-util` enabled
only by the Tokio dev-dependency), never a real sleep as proof.
The worker returns its `JoinHandle`, wrapped by the serving owner in `AbortOnDrop`.
Keep the owner fields private and expose the meta handle by borrowing; both
serving contexts retain the owner rather than transferring only a cloned meta handle.
Do not add a public opt-out flag or a manual cleanup method that production
never calls. Separate blocking file I/O is not involved.

Targets: the new focused server module, `BuiltMetaMcp` construction/destructuring,
the two serving lifetimes, and a crate-visible continuation cleanup boundary.
Signing also touches the builder; bridge touches stdio. The release lead must
serialize those shared hunks. Run GitNexus impact before symbol edits and
inspect real caller sites because the Rust graph misses some references.

## Tests before behavior implementation

| ID | Acceptance / decisive assertion | Level / type | Could fail because |
|---|---|---|---|
| EXPIRY.1 | Insert two live records with different deadlines, then advance only the worker's epoch/tick past one deadline; inspect the private map through a non-reclaiming test snapshot. Expired absent, live present, no public observer before snapshot. | unit, lifecycle | Missing worker scan or clearing all state fails one half. |
| EXPIRY.2 | At deadline equality, tick retains the record; next tick with epoch deadline+1 removes it. | unit, boundary | `>=` expiry and wall-clock reads ignoring the injected epoch fail distinctly. |
| EXPIRY.3 | Build through actual `Gateway::build_meta_mcp`, create state through the built gateway's continuation path, advance tick, inspect non-reclaiming occupancy. Guard still lives after constructor returns. | component, wiring | A helper-only implementation or immediately dropped guard leaves residue. |
| EXPIRY.4 | In-crate beside the constructors, start real HTTP and stdio serving fixtures with controlled runtime. Insert two live records with different deadlines into their actual continuation state, advance epoch past one and tick with no client follow-up. Non-reclaiming snapshot must show expired key absent and live key retained. Counters are supporting evidence only. | integration, route parity | Wiring only one transport, or reaping a different table, fails. |
| EXPIRY.5 | Drop/cancel serving ownership before the next tick; await task termination and verify no subsequent clock/scan callback. Repeat early startup failure, HTTP shutdown, stdio EOF and stdio task cancellation. | component + integration, lifecycle | A detached task, strong-reference cycle or EOF-only cleanup keeps running. |
| EXPIRY.6 | Race tick cleanup with hold/route/complete under a controlled barrier; retain live records, never exceed capacity and never route an expired key as live. Keep Change A's full/live/equality controls. | unit, concurrency | A second inconsistent predicate or unlocked scan loses state. |
| EXPIRY.7 | Move injected wall clock backward, keep monotonic ticks advancing, then restore it beyond deadline. Confirm documented epoch behavior and eventual cleanup; no timer freeze or busy loop. | unit, clock | Coupling interval scheduling to wall time or ignoring supplied epoch fails. |
| EXPIRY.8 | Empty, half-full, full tables with active invoke traffic and idle intervals: measure p50/p95/p99 latency, occupancy and lock wait against pre-change baseline using existing NFR budgets. | performance, bounded work | Unconditional scans can regress request latency despite bounded memory. |

The non-reclaiming observation is `#[cfg(test)] pub(crate) InFlight::snapshot()`:
copy keys and deadlines while holding `held` directly, without `guard`, reclaim
or a time argument. It is the sole occupancy oracle for idle-expiry tests.
Calling `len(now)` would repair the
defect being tested and is forbidden as an idle-expiry oracle. Production
instrumentation may record scan count/reclaimed count without input or key data.
Do not grade runtime absence or compilation failure as an assertion-level red.
Author the smallest real failing worker/builder tests after plan review; review
those tests separately before implementing. The same files run after the fix.
EXPIRY.8 is a release performance measurement, not an assertion-red unit gate.

## Risks, validation and closure

### Frozen performance contract for EXPIRY.8

Before measurement, archive immutable baseline/candidate trees and builds.
Baseline is `0d4df3c0` plus reviewed Change A and no scheduler; candidate is that
same snapshot plus Change C. Record complete patch SHA256, source-file manifest,
binary SHA256, Rust version, features and commands before running either build.
Candidate hashes do not exist before implementation: populating those fields is
a pre-run gate, never a choice of favorable revision after seeing measurements.
The separate release-wide NFR.PERF.1 comparison still uses v3.5.0
`32f135a61fb50c20a044fb4c2347bc1cf8015d89` and the final release candidate.

Use the same Spark host, optimized all-feature builds, response cache disabled
and a deterministic local backend. Freeze two workloads: ordinary real meta HTTP
calls returning 1 KiB, and real meta HTTP continuation mint/redeem cycles. The
second backend returns one valid InputRequired challenge on an initial call and
one 1 KiB completed result on the bound answered retry. Use verified synthetic
principals, capable-client initialization and a fresh explicit idempotency key
for each new logical operation. Preserve the returned opaque handle unchanged.
Every completed cycle must enter production `hold`, `route` and `complete` on
the SAME InFlight table scanned by the worker; record per-method sample counts.
No substitute no-op tools/call traffic can satisfy the contention workload.

Run both workloads at concurrency 1/16/64 with initial occupancy 0/2048/4096.
For nonempty continuation fixtures, reserve N of those slots for the N primed
live client exchanges; redeem each before minting its replacement, so capacity
refusal is not a workload accident. Zero occupancy means an initially empty
fixture; active cycles can hold up to N entries. Record actual occupancy instead
of claiming it remains exactly the initial count. Half the background records
expire in the first interval; live active handles have the normal lifetime.
After active traffic, re-seed the fixed initial occupancy with paired synthetic
live/expiring records through the fixture-only state handle and run the 5 s idle
phase. The occupancy oracle remains the raw non-reclaiming snapshot.

Each run has 10 s warmup and 60 s active measurement, followed by that 5 s idle
phase. Require FIVE VALID paired repetitions for EVERY workload/concurrency/
occupancy combination, alternating baseline/candidate order. Require at least
10,000 successful calls (or completed continuation cycles) per active run and
actual tick overlap. Capture client-to-response P50/P95/P99, throughput and
occupancy. Instrument foreground lock-acquisition wait immediately before
`held.lock().await` until guard acquisition, tagging `hold`, `route`, `complete`;
use identical instrumentation in both immutable builds. Record worker scan hold
duration separately, never call it foreground wait. Continuation runs require
nonzero samples for all three methods during overlapping worker activity.
Do not substitute Criterion confidence intervals for request percentiles.

Pass: each workload's median paired P50 increase <=5%, P99 <=10% (existing
NFR.PERF.1 budgets); continuation foreground P99 lock wait <=1 ms, separately
for all three methods; all five candidate idle snapshots remove expired keys
and retain live keys. Missing source/binary identity, insufficient successful
calls/cycles or method samples, changed workload/backend/cache, no tick overlap,
request errors or measured host swapping/throttling during either member voids
a pair. Retain each voided pair and its reason and REPLACE it under the unchanged
contract until five valid pairs exist for that combination. Missing replacements
mean incomplete evidence, not pass. Nonzero allocated swap alone does not void
a run. Keep every valid repetition; do not discard slow results or increase
thresholds after measuring a valid failure.

The HTTP lifecycle increment has a gate-by-gate scoped DoR ledger in
[its design](2026-09-06-continuation-http-lifecycle.md#scoped-dor-ledger-p1-readiness-not-release-acceptance).

DoR applicability: accepted MRTR8b/NFRPERF3 scope/owner; alternatives (lazy-only
versus lifecycle worker) resolved; runtime/clock ownership and targets explicit;
trusted time and no key-data telemetry; testability via EXPIRY real-constructor
matrix; bounded4096-entry scan cost and frozen contention measurement. No new
dependency, wire schema, credential, external action or user decision. Candidate
identity and lifecycle seams are scheduled pre-run/pre-test checks, not runtime
evidence. Critical coverage/mutation, paired code review and independent driving
remain required before delivery.

One owner guard prevents forgotten shutdown; weak references prevent lifetime
cycles; one expiry predicate prevents timer/observer drift. The fixed tick adds
a bounded idle scan (at most 4096 entries) and must pass EXPIRY.8 before release.
Do not raise latency thresholds after measurement. Restoring a background worker
is a design correction from the r3 review, not evidence that the old callerless
reaper was wired.

Fail-fast: verify `BuiltMetaMcp` ownership and both destructuring sites, then
review plan, compile-only scaffolding, assertion-red EXPIRY.1/.3, separate test
review, implementation and green controls. Follow with transport lifecycle
fixtures, formatter/Clippy, critical coverage/mutation, dual code review and an
independent driver. MRTR.8b remains PARTIAL and NFR.PERF.3 remains blocking until
combined A+C evidence is recorded at the integrated revision.


### Execution sequencing receipt

Keep the reviewed full Change C contract. Stage the worker/reclaim unit tests
first (EXPIRY.1/.2/.6/.7 and isolated worker lifetime portion of .5), using only
signature/no-op task scaffolding and a raw test snapshot. The first compiled run
must report actual assertion failures, not a missing API or premature readiness
claim. Separately review those tests before changing their target behavior.
Production builder and HTTP/stdio ownership tests (.3/.4 and serving .5) follow
the shared BRIDGE serving extraction; they get their own assertion-red/test
review before wiring behavior. This sequences dependent work, not a release
scope reduction: helper tests do not close any serving construction criterion,
and MRTR.8b/NFR.PERF.3 remain blocking until combined lifecycle and performance
proof. Root owns the cleanup module; BRIDGE owns stdio extraction and loop.


Worker implementation checkpoint (2026-09-06): reviewed r2 tests closure SHIP
from GPT (actualexit0/processok, boundSHA256
b67716f71c937a0189e2545369889dc4d7ebbe4c13f930c777a52b1c7fc4cb52,
48088bytes) plus retained Grok r1 SHIP. Nine compiled assertion-red tests preceded
the worker implementation. The exact1second Skip loop now calls the one-lock
reclaim method; all9focused tests and all23observer lifetime regressions pass.
The separately reviewed three real-builder tests then preceded production
wiring: the builder now creates the actual continuation state with its shared
trusted clock, starts the weak cleanup worker, and retains a nonoptional serving
owner. The three invoke clock reads use that state clock. All three builder
tests pass, including two witnessed scans before owner drop, a retained MetaMcp
clone, three later ticks with no scans, and an expired record left untouched
after shutdown. The child harness has a bounded 45-second failure watchdog.
The nine worker tests, 23 observer tests, three existing builder callers,
constructor parity and 19 MRTR caller tests also pass.

An isolated LLVM profile covers the current cleanup module's 46/46 regions and
40/40 lines, and the owner methods' 6/6 regions. This is source coverage, not
branch coverage. Two additional compiled faults (remove guard reclamation;
expire deadline equality) both fail the observer assertions; restoring the exact
source returns all 23 observer, nine worker and three builder tests to green.
Evidence is in `root-expiry-quant-r1` under the external release evidence folder.
No release criterion grade changes. Final wiring code review, actual HTTP/stdio
I/O ownership, independent functional drive and performance remain mandatory.
