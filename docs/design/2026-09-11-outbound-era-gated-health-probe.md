<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->
# Design — an era-gated backend health probe (MIK-7217.OUTBOUND.1, .2)

Status: design, awaiting review. Governs cluster **L** of
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md`. Supersedes nothing.
Prior art it must not re-litigate: `docs/design/2026-08-31-discover-outbound-era-probe.md`,
which wired the **start-path** era probe (DISCOVER.4/.5). This design is about the
**recurring** health probe, a different call site with different constraints.

## 1. The two requirements, and why today's code meets neither

`MIK-7217.OUTBOUND.1` — the gateway MUST NOT send a peer a method that peer's era
removed. `MIK-7217.OUTBOUND.2` — a health probe MUST distinguish a served response
from a refusal, and MUST record neither as the other.

The probe is `Backend::health_probe` (`src/backend/lifecycle.rs:1016`), driven every
`failsafe.interval` (default 10s, `src/config/features/failsafe.rs:151`) from the
scheduler at `src/gateway/server/mod.rs:2204`, over every backend that is running or
circuit-tripped.

**OUTBOUND.1 fails by construction.** The call is
`transport.request("ping", None)` at `:1053`, with no era read anywhere on the path.
`ping` is in `REMOVED_IN_2026_07_28` (`src/protocol/meta.rs:253`), and the comment two
lines above names this very probe as the reason the gateway still *serves* `ping`
inbound. The era is available — it is attached to the transport at `lifecycle.rs:380` —
but every reader of `outbound_era` shapes headers or notifications; none gates a method.

**OUTBOUND.2 fails in two opposite directions at once**, because `:1053` matches on the
transport `Result` and never inspects the body. The same `-32601` refusal is classified
by how the peer carried it:

| carriage | path | today's outcome | why it is wrong |
| --- | --- | --- | --- |
| in-band (200 + error body; every stdio refusal — `src/transport/stdio.rs:620-625`) | `Ok(Ok(_))` `:1054` | success, and **resets a tripped breaker** `:1055-1061` | a probe that cannot fail measures the socket, not the service |
| as a status (HTTP non-2xx → `Err`, `src/transport/http/mod.rs:1275-1295`; 404 is the shape `MIK-7215.STATELESS.5b` obliges a conformant peer to use, and `.6a` names `ping` among the methods the modern path must refuse) | `Ok(Err(e))` `:1064` | failure, and **`force_restart()`** `:1066` | rebuilds the transport of a working backend every 10s |

Both are conditional on a peer classified `Era::Modern`. `protocol::era::classify`
(`src/protocol/era.rs:93`) requires positive evidence, so the population may be empty
today; this arms itself when the first modern peer appears.

They must be fixed together. Gating the method alone leaves the outcome check broken for
whatever replaces `ping`. Fixing the outcome check alone converts a silent false-healthy
into a permanent false-unhealthy on HTTP.

## 2. Ruling 1 — the modern liveness method is `server/discover`

The readiness board recorded this as the open decision. Ruled here.

**Candidates considered.**

- **`tools/list`.** Defined in 2026-07-28, read-only, and already survives the probe's
  empty-permitted-set predicate (`src/transport/http/mod.rs:1409-1417` names it as one of
  the two methods that legitimately reach that entry point). Rejected on cost: it returns
  every tool's full schema. The measured local gateway answers `tools/list` with the whole
  registry; making that a 10s heartbeat over every backend buys nothing a small document
  does not.
- **Transport-level liveness only** (drop the request, check the socket). Rejected because
  it is the defect: it is precisely what today's `Ok(Ok(_))` degenerates into, and it
  cannot see a backend that is connected and not serving — the failure
  `a-health-signal-from-request-outcomes-cannot-see-a-dead-component` describes.
- **`server/discover`.** Selected.

**Why `server/discover`.**

1. It already exists and is already issued against every backend on the start path, so
   this adds no new outbound surface — only a second call site for one that is proven.
2. Its response is a small fixed-shape metadata document, not a registry dump. At a 10s
   interval this is the same order of cost as `ping`.
3. It is the one method a 2026 peer must implement. That makes a refusal *informative*
   rather than expected: a `-32601` to `server/discover` says the peer is not modern,
   which is a classification error to correct, not a health verdict.
4. Its outcome is already modelled. `ProbeOutcome` and `classify` (`src/protocol/era.rs:93`)
   exist and distinguish `Result`, a recognised modern `Error`, and everything else —
   the classification OUTBOUND.2 needs has a home rather than a new enum.

**Legacy peers keep `ping`.** `Era::Legacy` (including unknown/unreachable, which
`classify` deliberately folds into legacy) still gets `ping`: it is defined for them, and
sending `server/discover` to a 2025 peer is the mirror-image conformance defect.

**Per-tick load is asserted, not measured, and the design says so.** The claim above is
a shape argument (small document, existing call site), not a benchmark. The test plan
below carries a measurement obligation; if it shows the per-tick discover is too heavy,
that data reopens this ruling rather than selecting a contingency drafted blind. An
earlier revision named one - serve the probe from "the existing `EraCache` TTL" and
re-probe on expiry - and it was wrong twice over: `EraCache` has no TTL and no expiry
(`src/protocol/era.rs`), and a probe that sends nothing between expiries would suspend
both arms of OUTBOUND.2 for modern peers, leaving no transport fault observable and a
tripped breaker with no path back. Found by adversarial review, 2026-09-11.

## 3. Ruling 2 - a reset needs positive evidence of service

Replace the two-arm match at `:1053` with a three-way classification that reads the body
on both transports. The organising rule: **reviving a tripped breaker is a claim that the
backend is serving, and only a served result is evidence for it.**

| observation | verdict | breaker | transport |
| --- | --- | --- | --- |
| a JSON-RPC **result** | serving | reset if tripped | keep |
| a JSON-RPC **error**, any code, in-band *or* carried as a status | **answered, not served**: the peer parsed the request and declined to fulfil it | **unchanged** - neither reset nor tripped; counts toward the escalation bound below | keep |
| transport fault or timeout | not serving | trip | `force_restart()` |

**The middle row arrives in two shapes, and the match must cover both.** A JSON-RPC
error carried in band is not an `Err` at all: `Transport::request` returns
`Ok(JsonRpcResponse)` with the `error` field populated, and the stdio and WebSocket
transports both do this (`src/transport/stdio.rs:589`, `src/transport/websocket.rs:501`).
A status-carried one, after the change below, arrives as `Err(Error::JsonRpc { .. })` from
the HTTP transport. So the classification cannot be written as a match on `Result` alone:
the `Ok` arm must inspect `response.error` before calling it a served result, and the
`Err` arm must separate `Error::JsonRpc` from every other error. An implementation that
covers only the `Ok` shape restarts every HTTP backend that declines a probe - the exact
behaviour this ruling removes - while passing any row driven by a stdio fixture. Found by
reading the transports, 2026-09-11.

The middle row is the whole point of OUTBOUND.2, and it is deliberately wider than
`-32601`. An earlier draft of this design ruled that any error *other than*
method-not-found proved the peer was serving, on the reasoning that a peer which parses
and answers is alive. That is the defect restated: a backend wedged into answering
`-32603 Internal error` to every probe would revive its own tripped breaker every tick,
and the probe would again be measuring the parser rather than the service. Found by
adversarial review, 2026-09-11.

The opposite over-correction - trip on `-32603` - is the other half of the same defect.
A backend whose `server/discover` handler is broken while `tools/call` works would be
restarted every tick for a fault that never touched the traffic path. Neither reading is
safe, which is exactly why the outcome belongs in a third arm rather than being forced
into health or fault. Because the arm is code-agnostic, no table of JSON-RPC code ranges
has to be maintained or re-litigated at implementation time.

**A refusal additionally invalidates the era.** `-32601` to `server/discover` is not just
an unserved answer; it is evidence the era classification was wrong, and
`protocol::era::classify` already reads that code as legacy evidence
(`src/protocol/era.rs:120-126`). So the refusal case also invalidates the cached era, **to
unknown, which §2 folds into legacy** - so the next tick sends `ping`, not another
`server/discover`. An earlier revision said the next tick "re-runs `server/discover`",
which would have put a removed-in-reverse method on the wire to a peer the gateway had
just reclassified as legacy - the mirror image of the OUTBOUND.1 defect this design
exists to close. Found by adversarial review, 2026-09-11. Re-classification back to
modern comes only from positive evidence on the ordinary path (a discovery document, or
one of the three recognised modern error codes), never from an absence, which is
`classify`'s existing rule and not one this design may relax. Every middle-row
outcome also emits a `warn!` and a `mcp_health_probe_unserved_total{backend,code}` counter
carrying the JSON-RPC code and the era the gateway believed, so the new state is
triageable per backend without log archaeology.

**The invalidation is an existing mechanism, not a new one.**
`Backend::reprobe_if_contradicted` (`src/backend/era.rs:110-145`) already does exactly what
the paragraph above rules: it reads an ordinary response's error, drops the cached verdict
when `contradicts_modern(method, code)` holds - which is `-32601` against `server/discover`
and nothing else (`src/backend/era.rs:72`) - and spawns one detached re-probe. It is
symmetric, so it also covers the return path row 9b pins: a `Legacy` verdict contradicted
by one of the three modern-only codes is dropped the same way. **The probe does not call
it**, because `health_probe` reaches `transport.request` directly (`:1053`) rather than
through the dispatch path that does. So the implementation here is one call, not a second
invalidation path, and building a second one would duplicate a rule that already has an
owner.

Two consequences follow and both are behavioural, which is how rows 9 and 9b assert them.
First, the re-probe is detached and sends `server/discover` of its own accord; that is the
*classification* probe, not the liveness tick, and it is the positive-evidence path §2
requires. Whether it has finished by the next tick does not change what that tick sends: a
completed re-probe leaves `Legacy`, an unfinished one leaves the era unresolved, and §2
folds both onto `ping`. Second, `reprobe_if_contradicted` takes a `&JsonRpcResponse`, which
the in-band shape has and the status-carried shape does not. Row 6b's carriage therefore
needs the code lifted out of `Error::JsonRpc` and offered to the same judgment rather than
a parallel one - the one piece of new plumbing this ruling actually adds. Found by reading
`src/backend/era.rs`, 2026-09-11.

**The middle arm is bounded - an unserved answer cannot be permanent.** Left unbounded,
the third arm is a new failure mode: a backend wedged into answering errors would never
trip a breaker, never rebuild, and its only trace would be a counter nobody reads. So:

1. **Each unserved answer** - record neither; warn; increment the counter; on `-32601`,
   invalidate the cached era so the next tick re-classifies.
2. **Consecutive unserved answers** are counted per backend, in the same per-backend
   state that holds the `EraCache` (`src/backend/lifecycle.rs:134`), and updated only on
   the probe task's own path. A tick that outlasts the interval does not start a second
   probe for the same backend; the next tick observes the run in flight and skips, so
   "consecutive" means consecutive answers, never overlapping ones. The counter resets on
   any outcome that is not an unserved answer - a served result, a transport fault, or a
   `force_restart()` - so the count only ever measures an uninterrupted run of them, and
   a rebuilt backend starts from zero.
3. **Three consecutive** (30s at the default interval) escalate to the fault arm: trip the
   breaker and `force_restart()`.

Three is justified twice over, once per half of the arm. **For a refusal** it is the
smallest count that cannot be reached without a completed re-classification: probe
(`server/discover` refused, era invalidated) -> probe (`ping`, the liveness method of the
era the peer was just re-classified into, refused) -> probe (refused again). A peer that
refuses the modern liveness method *and* the legacy one is not serving under either
reading, which is a stronger statement than either probe makes alone. An earlier revision
described tick 2 as a second `server/discover`; §3's invalidation rule forbids that, and
the bound is sounder without it. **For every other error code** there is no re-classification to wait for, so the
count carries the whole argument on its own: three consecutive unserved answers span 30s
at the default interval, which separates a handler that threw once from one that is
wedged, and the reset on a served result means a backend that flaps between errors and
results never escalates at all. The threshold is a constant, not a config knob - no
requirement asks for one, and an unbounded arm is the defect, not a tuning surface.

**This requires the HTTP transport to stop flattening a refusal into a string, and that
change is shared.** A non-2xx response whose body is a JSON-RPC error is currently
`Err(safe_http_status_error(..))` (`src/transport/http/mod.rs:1275-1295`), which discards
the code. The existing `ProtocolVersionRejected` branch immediately above is the
precedent: that code path was added for exactly this reason - a version refusal carried as
a status had its body dropped before anyone could read it. The same treatment, one branch
wider: parse the body for a JSON-RPC error object before falling back to the status
string.

`transport.request` has ten callers besides the probe, so the shape and the blast radius
are named here rather than discovered at implementation time. Found by adversarial review,
2026-09-11.

- **The shape is the existing `Error::JsonRpc { code, message }`**, not a new variant. A
  status-carried error is the same thing as an in-band one; giving it a second
  representation would oblige every caller to learn both.
- **Admitted only on three signals together**, the same discipline the
  `ProtocolVersionRejected` branch above already applies: the body parses as JSON, it
  carries a JSON-RPC `error` object, and its `id` echoes the request's. Anything else -
  a proxy error page, a truncated body, a forged id - stays `safe_http_status_error`, so
  the status string remains the fallback rather than the exception.
- **`classify_dispatch_error` is unaffected in category, improved in detail.** Both
  `Error::Transport(msg)` and `Error::JsonRpc { message, .. }` already map to
  `ErrorCategory::BackendError` (`src/gateway/meta_mcp/invoke.rs:3427` and the arm three
  lines below it), so a caller's recovery hint keeps its category and gains the peer's own
  message in place of the string `HTTP 404`.
- **Retryability changes, deliberately.** `Error::Transport(_)` is retryable in both
  classifiers (`src/chains/retry.rs:188`, `src/failsafe/retry.rs:99`); `Error::JsonRpc` is
  in neither. A status-carried peer error therefore stops being retried. That is the
  correct reading - a peer that parsed the request and declined it will decline the retry
  identically, and `retry.rs:180-185` states the rule this follows: plain `Transport`
  is retryable because it means "failed, cause unknown", which a JSON-RPC error is not -
  but it is a behaviour change on every non-probe caller and row 16 pins it.

**Two independent reviews disagree on this arm, and the wider rule is the one that
ships.** One held that any error other than method-not-found proves the peer is serving,
so only a refusal belongs in the middle; the other held that a peer wedged into
`-32603` would revive its own breaker forever under that rule. Both describe a real
failure, and they are not symmetric: the narrow rule's failure mode is a tripped breaker
revived by a backend that never served anything, which is silent and unbounded; the wide
rule's failure mode is a modern backend whose liveness method errors being restarted
after three ticks, which is loud, bounded, and correct if the liveness method really is
broken. The wide rule plus the bound is therefore the shipping rule, and this paragraph
is the record that the narrow one was considered and rejected rather than missed.

**Residual (recorded, not fixed here).** Three sit outside this design's scope:

- *A legacy peer that refuses `ping` restarts every third tick, where today it passes.*
  The 2025 revision obliges a receiver to answer `ping`, so such a peer is
  non-conformant - but it exists, and today's "any answer is health" rule hides it. Under
  this design its refusal is an unserved answer on the legacy arm and it escalates. That
  is the intended trade: the escalation is loud and bounded, where the status quo is a
  silent false-healthy, and a peer that answers no liveness method has no liveness signal
  to preserve. Recorded rather than exempted, because exempting `-32601` on the legacy arm
  would re-open the wedged-backend hole the bound exists to close.

- *An intermediary can forge the middle row* - **closed in this design, not deferred.** A
  proxy or load balancer answering a non-2xx with its own JSON-RPC-shaped body would be
  read as the peer declining, masking a dead origin behind a live intermediary, and a
  forged `-32601` would additionally poison a modern peer's era. The id-echo condition in
  §3's transport rule is the mitigation and it ships here: a body whose JSON-RPC `id` does
  not echo the request's is not honoured. An earlier revision left this as future work
  while row 12 already asserted it - three places disagreeing about whether the check
  existed. Found by adversarial review, 2026-09-11.
- *A modern peer that omits `server/discover` is classified legacy and then sent `ping`.*
  That is `classify`'s existing rule (`src/protocol/era.rs:120-126`, ruled 2026-08-29 and
  reviewed with `docs/design/2026-08-31-discover-outbound-era-probe.md`), not a rule this
  design introduces, and §5 keeps it out of scope. The escalation bound limits the damage:
  such a peer trips after three ticks rather than looping silently in the wrong era.

## 4. Ruling 3 - the same gate covers the other three outbound removals

An earlier revision deferred this: it said `ping` was "the only unconditional outbound use
of a removed method found on this path" and left a sweep as separate work. The sweep has
since been run, and that deferral cannot stand - OUTBOUND.1 says the gateway MUST NOT send
a peer a method that peer's era removed, so a criterion graded on `ping` alone would go MET
while three removed methods still reach modern backends ungated. Found by adversarial
review, 2026-09-11.

`REMOVED_IN_2026_07_28` (`src/protocol/meta.rs:253-261`) lists five methods.
`notifications/roots/list_changed` has no outbound sender: the one function that builds it,
`Proxy::broadcast_roots_changed` (`src/gateway/proxy.rs:457`), hands it to
`StreamingManager::broadcast`, which iterates *client* sessions, not backends
(`src/gateway/streaming.rs`), and the whole repository contains no caller of it outside its
own unit test. Its doc comment said "to all backends" and was wrong about its own
behaviour; corrected in this change rather than deferred, because a comment claiming a
backend fan-out of a removed method is exactly what a reader auditing OUTBOUND.1 would
trust. Not a send. The other
four methods are all genuinely sent to backends:

| method | outbound call site | shape today | with the gate |
| --- | --- | --- | --- |
| `ping` | `src/backend/lifecycle.rs:1053` | health probe, every 10s | §2: `server/discover` on the modern arm |
| `logging/setLevel` | `src/gateway/meta_mcp/protocol.rs:310` | fan-out over backends, `warn!` on error | skip the modern backend, one `warn!` per skipped backend per call, with the era named |
| `resources/subscribe` | `src/gateway/meta_mcp/resources.rs:389` | forwarded per client request | refuse in the gateway with `-32601` |
| `resources/unsubscribe` | `src/gateway/meta_mcp/resources.rs:423` | forwarded per client request | refuse in the gateway with `-32601` |

**The client-visible error *code* does not change, which is what makes this mechanical -
and the rest of the answer does.** The gateway's refusal carries the same `-32601` the
peer would have sent, but its `message` and `data` are gateway-authored rather than
relayed, and it arrives one round trip earlier. A client keying on the code is unaffected;
a client keying on the peer's prose is not, which is the real delta and the level any
compatibility assessment has to start from. Found by adversarial review, 2026-09-11. A
modern peer that receives one of these three answers `-32601` by definition - that is what
"the revision removed it" means - and both resource call sites already surface a backend
error object straight back to the caller (`resources.rs:391-395`, `:425-429`). Refusing in
the gateway produces the same code the peer would have produced, one round trip earlier and
without putting a removed method on the wire. The `logging/setLevel` site already tolerates
a per-backend failure without failing the request, so skipping a backend is the same
outcome its `warn!` arm produces today.

Each gateway-side refusal or skip emits
`mcp_gateway_removed_method_refused_total{backend,method,era}`, the §4 counterpart to §3's
`mcp_health_probe_unserved_total`. Without it the only trace of a newly refused method is
a support ticket, and these four sites are where a wrong era classification turns into
client-visible behaviour.

The gate is one read of the era already attached to the transport (`lifecycle.rs:380`),
the same read §2 adds to the probe. No new state, no new config.

**Which era, explicitly: the backend's.** Two different eras are in scope at these call
sites. The one that governs is the peer's, held in the backend's `EraCache`
(`src/backend/lifecycle.rs:134`) and reached through the `Backend` the call site already
has. The other is the *client*-facing era on the meta-MCP context
(`src/gateway/meta_mcp/mod.rs:177`), which says what the caller speaks and says nothing
about what the peer accepts. Gating on it would be silent and wrong in both directions: a
legacy client talking to a modern backend would still put `resources/subscribe` on the
wire, and a modern client talking to a legacy backend would be refused a method that
backend supports. The `Backend` exposes no era accessor today; adding one is part of this
change.

**Constructing a modern-era backend in a test.** `EraCache` has no setter - an era is
committed only by a completed classification - so rows 13 to 15 drive the fixture rather
than assigning to it: a mock transport whose `server/discover` answer is
positive evidence leaves the cache `Probed`/`Modern`. Two shapes qualify and both are
cheap: a discovery document naming a modern revision in `supportedVersions`, or an error
carrying one of `UNSUPPORTED_PROTOCOL_VERSION`, `HEADER_MISMATCH` or
`MISSING_REQUIRED_CLIENT_CAPABILITY` (`src/protocol/era.rs:93-121`). Not `-32601`: that is
`classify`'s legacy evidence, and a fixture built on it would classify the backend
`Legacy` and pass rows 13 to 15 without ever exercising the gate. Stated here because a row that cannot construct its own
precondition fails for a setup reason and reads as the gate working.

## 5. What this does not do

- It does not touch the **inbound** `ping` the gateway serves. `MIK-7215.STATELESS.6a`
  governs that, and `src/protocol/meta.rs:253` keeps `ping` served for legacy clients.
- It does not change the start-path era probe or `EraCache` semantics, beyond invalidating
  a cached era that a refusal proves wrong.
- It does not translate `resources/subscribe` into the `subscriptions/listen` that
  replaced it. Gating stops the removed method reaching a modern peer; giving modern peers
  a working subscription path is `MIK-7272.SUB.*` work, governed elsewhere.
- It does not touch the legacy path for any of the four methods. A 2025 peer is served
  exactly as today.

## 6. Test plan (to be reviewed as a test plan before any implementation)

The **fail-first** column records whether the row can fail against `HEAD`. A row that
passes today guards behaviour this change must *preserve*; calling it fail-first would be
false, and an earlier draft of this plan claimed all of rows 1-8 were - four of them were
regression guards. Found by adversarial review, 2026-09-11. Only the fail-first rows are
evidence that the fix did anything; only the regression rows are evidence it broke nothing.

Two conventions apply to every row rather than being repeated in each. **Carriage:**
rows 4 and 5 run the classification assertions on both carriages explicitly, and
"both carriages" means the two *shapes* named in section 3 - an `Ok(JsonRpcResponse)`
carrying an `error` field, and an `Err(Error::JsonRpc { .. })` - not two fixtures that
differ only in a label; rows 6
through 12 use the in-band (stdio) carriage unless the row names HTTP, and their
fail-first half is the counter assertion, which no carriage satisfies at HEAD.
**Observability:** every row asserting a middle-arm outcome also asserts the `warn!` and
the `mcp_health_probe_unserved_total{backend,code}` labels the outcome is supposed to
carry, including the era the gateway believed; row 13 asserts §4's per-skipped-backend
`warn!` and row 15b the `mcp_gateway_removed_method_refused_total` labels. A counter
without its labels is not the triage surface §3 and §4 promise, and would otherwise pass
the suite. Found by adversarial review, 2026-09-11.

| # | what it pins | fail-first against HEAD | why |
| --- | --- | --- | --- |
| 1 | `Era::Modern` backend is probed with `server/discover`; `ping` never reaches the wire | **yes** | HEAD sends `ping` unconditionally (`lifecycle.rs:1053`) |
| 2 | `Era::Legacy` backend is probed with `ping` | no - regression guard | HEAD already sends `ping` to everything, so it passes for the wrong reason; it exists to catch the mirror-image defect after row 1 lands |
| 3 | unreachable/unclassified backend takes the legacy arm | no - regression guard | same; pins `classify`'s "silence is not modern" rule at this call site |
| 4 | in-band `-32601` (stdio): tripped breaker **unchanged**, no restart | **yes** | HEAD reads `Ok(Ok(_))` as success and resets the breaker (`:1054-1061`). The counter assertion this cell used to carry is deferred to rows 10 to 11b: the consecutive-unserved count does not exist at HEAD, and a test that fails to compile records no fail-first evidence |
| 5 | `-32601` carried as an HTTP 404 body: same assertions as row 4 | **yes** | HEAD reads `Ok(Err(_))` as a fault and calls `force_restart()` (`:1064-1066`). Same counter deferral as row 4 |
| 6 | `-32603` on a tripped breaker: breaker **unchanged**, no restart, **and `cached_era()` still `Some(Era::Modern)`** | **yes** | HEAD resets on any in-band answer; this is the row that pins §3's widened middle arm, and the one an implementation narrowing it back to `-32601` would break. The era assertion is what stops the widened arm from widening invalidation with it: only method-not-found is evidence about era, so an implementation wiring invalidation to "any unserved answer" must fail here. The era half is a **second-stage pin**: the row fails at HEAD on the breaker assertion - row 4's defect - and HEAD has no invalidation path to get the era wrong, so the era assertion only starts discriminating once the widened arm lands. The same holds for row 6b, which fails at HEAD on the restart. Recorded from the fail-first run, 2026-09-11 |
| 6b | a `-32603` carried as an HTTP 500 with a JSON-RPC error body and an echoing `id`: **unserved**, same three assertions as row 6, **no restart**, and **`cached_era()` still `Some(Era::Modern)`** | **yes** | HEAD reads every non-2xx as a fault and restarts (`:1064-1066`). This is the cell where the two halves of §3 meet - the widened arm *and* the status carriage - and an implementation that faults on any parsed code except `-32601` passes every other row while restarting backends §3 says not to restart. The era half is the second intersection: §3 invalidates on `-32601` only, and an implementation wiring invalidation to any parsed status-carried error passes rows 6, 9 and the first half of this one. Found by adversarial review, 2026-09-11 |
| 7 | closed socket / timeout still trips and restarts | no - regression guard | current behaviour; guards against fixing 4-6 by making everything healthy. It is also the **control for the restart observable**: every "no restart" cell above is a negative, and this is the only row that makes the observable move. Counting `Transport::close()` calls does not work and the first draft of these rows did - the probe holds an internal-activity lease for its whole duration, so `force_restart` always takes its busy branch and defers the close to a task gated on `Arc::strong_count`, which a test holding the mock keeps above the threshold forever. The rows read the pool slot instead, which `force_restart` empties before any branch. Found by this row failing, 2026-09-11 |
| 8 | a `ping` result on the legacy arm resets a tripped breaker | no - regression guard | current behaviour for a result; guards against fixing rows 4 to 6 by making nothing healthy |
| 8b | a valid `server/discover` result on the modern arm resets a tripped breaker too | **yes** | HEAD never sends `server/discover` from the probe, so this half cannot pass today and marking it a regression guard alongside row 8 gave one row two before-states. It stops an implementation from wiring the reset into the legacy branch only. Found by adversarial review, 2026-09-11 |
| 9 | after a `-32601` to `server/discover`, **`cached_era()` is no longer `Some(Era::Modern)`**; the next tick sending `ping` rather than `server/discover` is pinned as a second assertion, not the first | **yes** | no invalidation path exists on this call site, and naming the method is what makes the re-classification rule falsifiable rather than implied. The accessor is the fail-first half and the method is not: HEAD sends `ping` unconditionally, so "the next tick sends `ping`" is already true at HEAD and would mark this row fail-first on an assertion that is green before any fix. It becomes a real pin only once row 1 lands. The judgment itself lives in `reprobe_if_contradicted`, which the probe must be wired to rather than reimplement. Found by adversarial review, 2026-09-11 |
| 9b | re-classification is possible in both directions, **and the evidence arrives off the probe path**: after the row 9 invalidation, the start path's `resolve_era` answers `server/discover` with a document naming a modern revision, `cached_era()` returns to `Some(Era::Modern)`, and the following health tick sends `server/discover` again - with **no probe-side `server/discover` on the wire between the invalidation and the re-classification** | **yes** | the invalidation path does not exist at HEAD, so neither does its inverse. The driver is named because the obvious fixture - re-probing through the health tick - contradicts row 9 and would teach the suite the mirror-image OUTBOUND.1 defect. Found by adversarial review, 2026-09-11. Without this row an implementation that invalidates and never re-classifies leaves every peer permanently legacy and still passes rows 1 through 9 |
| 9c | a served `ping` after the row 9 invalidation leaves `cached_era()` not `Some(Era::Modern)` and the following tick still sends `ping` | **yes** | §3 rules that re-classification comes only from positive evidence and never from an absence. A `ping` result is an absence of evidence about the era, and an implementation reading any successful probe as "the peer is fine, restore what we thought" sends the modern liveness method to a peer just reclassified as legacy. No row otherwise closes it. Found by adversarial review, 2026-09-11 |
| 9d | the escalation sequence §3 uses to justify the bound, end to end: `server/discover` refused `-32601` (era invalidated, count 1), `ping` refused (count 2), `ping` refused (count 3, trip and `force_restart()`) | **yes** | the bound's own worked example, and the one sequence that crosses an era invalidation. An implementation that resets the unserved count when it invalidates the era leaves a refuse-everything backend permanently wedged and green, and passes rows 10 through 11b unchanged. Found by adversarial review, 2026-09-11 |
| 10 | escalation: unserved answers 1 and 2 leave the breaker unchanged, the third trips and restarts | **yes** | no counter exists |
| 10b | `force_restart()` resets the count: after an escalation, two further unserved answers must **not** trip a second time | **yes** | no counter exists. §3 rule 2 makes "a rebuilt backend starts from zero" load-bearing for the three-count arithmetic, and an implementation that never clears the counter restarts every tick after the first escalation |
| 10c | a probe whose answer is delayed past one full interval: exactly one request is in flight on the wire, the tick that lands during it is skipped, and the escalation count advances by one - not two | **yes** | no counter and no in-flight guard exist. §3 rule 2 defines "consecutive" over answers rather than ticks, and an implementation counting ticks escalates a healthy-but-slow backend to a restart every 30s |
| 11 | escalation counter resets on a served result: two unserved answers, one served result, two more unserved answers must **not** trip, **and `mcp_health_probe_unserved_total` for that backend reads 4, while the consecutive-unserved count reads 0** - the lifetime counter and the consecutive count are two values and rows 11 and 11b assert both, through a test accessor for the latter | **yes** | the counter assertion is what makes this fail at HEAD. "Must not trip" is vacuously true of HEAD, which resets on every in-band answer and never trips - an earlier revision marked this row fail-first on that vacuous half alone. Found by adversarial review, 2026-09-11 |
| 11b | escalation counter resets on a **transport fault** too: two unserved answers, then a closed socket, which trips and restarts per row 7 - and on the rebuilt backend two further unserved answers must **not** trip, **with the consecutive-unserved count reading 2, not 4, while `mcp_health_probe_unserved_total` reads 4** | **yes** | §3 rule 2 lists three reset paths and an implementation resetting only on a served result passes rows 10 and 11 while violating it. An earlier revision of this row asserted the socket fault itself must not trip, which contradicts §3's fault arm and would have failed against a correct implementation. Found by adversarial review, 2026-09-11 |
| 12 | HTTP non-2xx whose body is absent, not JSON, valid JSON carrying no `error` member, or carries an `id` that does not echo the probe's: **transport fault** - trip and `force_restart()` | no - regression guard | HEAD already trips and restarts on every non-2xx, so this row passes today and would be a false fail-first claim; it exists to catch the new body-parsing branch widening past what it was scoped to. Without it, an implementation that reads a proxy's 502 text page as an unserved answer stops restarting dead backends, and this row is also what pre-pins the `id`-echo mitigation named in the residual |
| 13 | `logging/setLevel` fan-out skips a modern backend and forwards to a legacy one in the same call | **yes** | `protocol.rs:310` forwards to every backend with no era read |
| 14 | `resources/subscribe` against a modern backend is refused by the gateway with `-32601` and **never reaches the transport**; against a legacy backend it is forwarded unchanged | **yes** | `resources.rs:389` forwards unconditionally |
| 15 | `resources/unsubscribe`, same two assertions | **yes** | `resources.rs:423` forwards unconditionally |
| 15b | rows 13 to 15 with a **legacy client** talking to a **modern** backend: still skipped or refused | **yes** | no gate exists at all, so this half fails today. §4 names two eras in scope at these call sites; an implementation gating on the meta-MCP client era (`src/gateway/meta_mcp/mod.rs:177`) instead of the backend's `EraCache` passes rows 13 to 15 unchanged and is wrong in both directions. Found by adversarial review, 2026-09-11 |
| 15c | rows 13 to 15 with a **modern client** talking to a **legacy** backend: still forwarded, before and after | no - regression guard | the mirror half, and it passes at HEAD, which forwards everything. Split from 15b so neither verdict masks the other: a row mixing a must-fail assertion with a must-pass one has no honest before-state. Found by adversarial review, 2026-09-11 |
| 16 | a **non-probe** caller of `transport.request` receiving a status-carried JSON-RPC error sees `Error::JsonRpc` with the peer's code, `ErrorCategory::BackendError` unchanged, and **no retry** | **yes** | the shared half of §3's transport change. This is the row that makes the blast radius on the other ten callers a decision rather than an accident. Its assertions read the variant and the retry decision, never the message: `Error::JsonRpc` and `Error::Transport` render identically on purpose (`src/error.rs:159`), so a row comparing rendered errors would pass whichever branch ran. It does assert the `message` *field* carries the peer's own message rather than `HTTP 404`, which is the improvement §3 claims and would otherwise ship unobserved |
| 16b | the same caller receiving a non-2xx whose body is absent, unparseable, or carries a foreign `id` still sees `Error::Transport` and is still retried | no - regression guard | the other half of the same branch, and it passes today. Split from row 16 so each half has one verdict: a single row mixing a must-fail assertion with a must-pass one has no honest before-state |
| M | per-probe wall time and response size for `server/discover` against a real backend, against `ping`, at the default interval | measurement, not a gate | the evidence for §2's load claim, which is asserted there and unproven until this exists. Emit it as a histogram rather than a one-off reading, so the claim stays verified and the `EraCache` fallback decision has data on every release |

Rows 1, 4, 5, 6, 6b, 8b, 9, 9b, 9c, 9d, 10, 10b, 10c, 11, 11b, 13, 14, 15, 15b and 16 must be observed failing against `HEAD` before the
implementation lands - a test that passes before the fix is testing something else, see
`a-test-first-suite-can-encode-an-inverted-oracle`. Rows 2, 3, 7, 8, 12, 15c and 16b must pass both
before and after.
