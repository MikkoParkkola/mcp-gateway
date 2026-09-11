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
the fallback is to serve the probe from the existing `EraCache` TTL and re-probe only on
expiry — trading liveness freshness for load. That fallback must not be taken on
assumption.

## 3. Ruling 2 - a reset needs positive evidence of service

Replace the two-arm match at `:1053` with a three-way classification that reads the body
on both transports. The organising rule: **reviving a tripped breaker is a claim that the
backend is serving, and only a served result is evidence for it.**

| observation | verdict | breaker | transport |
| --- | --- | --- | --- |
| a JSON-RPC **result** | serving | reset if tripped | keep |
| a JSON-RPC **error**, any code, in-band *or* carried as a status | **answered, not served**: the peer parsed the request and declined to fulfil it | **unchanged** - neither reset nor tripped; counts toward the escalation bound below | keep |
| transport fault or timeout | not serving | trip | `force_restart()` |

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

**The middle arm is bounded - an unserved answer cannot be permanent.** Left unbounded,
the third arm is a new failure mode: a backend wedged into answering errors would never
trip a breaker, never rebuild, and its only trace would be a counter nobody reads. So:

1. **Each unserved answer** - record neither; warn; increment the counter; on `-32601`,
   invalidate the cached era so the next tick re-classifies.
2. **Consecutive unserved answers** are counted per backend. The counter resets on
   any outcome that is not an unserved answer - a served result, a transport fault, or a
   `force_restart()` - so the count only ever measures an uninterrupted run of them, and
   a rebuilt backend starts from zero.
3. **Three consecutive** (30s at the default interval) escalate to the fault arm: trip the
   breaker and `force_restart()`.

Three is justified twice over, once per half of the arm. **For a refusal** it is the
smallest count that cannot be reached without a completed re-classification: probe
(refuse, invalidate) -> probe (re-classified era, refuse) -> probe (refuse again). A peer
that will not serve the liveness method of the era it was *just* re-classified into is not
serving. **For every other error code** there is no re-classification to wait for, so the
count carries the whole argument on its own: three consecutive unserved answers span 30s
at the default interval, which separates a handler that threw once from one that is
wedged, and the reset on a served result means a backend that flaps between errors and
results never escalates at all. The threshold is a constant, not a config knob - no
requirement asks for one, and an unbounded arm is the defect, not a tuning surface.

**This requires the HTTP transport to stop flattening a refusal into a string.** A non-2xx
response whose body is a JSON-RPC error is currently `Err(safe_http_status_error(..))`
(`src/transport/http/mod.rs:1275-1295`), which discards the code. The existing
`ProtocolVersionRejected` branch immediately above is the precedent: that code path was
added for exactly this reason - a version refusal carried as a status had its body dropped
before anyone could read it. The same treatment, one branch wider: parse the body for a
JSON-RPC error object before falling back to the status string.

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

**Residual (recorded, not fixed here).** Two sit outside this design's scope:

- *An intermediary can forge the middle row.* A proxy or load balancer that answers a
  non-2xx with its own JSON-RPC-shaped body would be read as the peer declining, masking a
  dead origin behind a live intermediary. The mitigation when this is implemented is to
  honour a parsed body only when its JSON-RPC `id` echoes the probe's request id.
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
`notifications/roots/list_changed` the gateway never sends outbound. The other four all do:

| method | outbound call site | shape today | with the gate |
| --- | --- | --- | --- |
| `ping` | `src/backend/lifecycle.rs:1053` | health probe, every 10s | §2: `server/discover` on the modern arm |
| `logging/setLevel` | `src/gateway/meta_mcp/protocol.rs:310` | fan-out over backends, `warn!` on error | skip the modern backend, `warn!` once with the era named |
| `resources/subscribe` | `src/gateway/meta_mcp/resources.rs:389` | forwarded per client request | refuse in the gateway with `-32601` |
| `resources/unsubscribe` | `src/gateway/meta_mcp/resources.rs:423` | forwarded per client request | refuse in the gateway with `-32601` |

**The client-visible result does not change, which is what makes this mechanical.** A
modern peer that receives one of these three answers `-32601` by definition - that is what
"the revision removed it" means - and both resource call sites already surface a backend
error object straight back to the caller (`resources.rs:391-395`, `:425-429`). Refusing in
the gateway produces the same code the peer would have produced, one round trip earlier and
without putting a removed method on the wire. The `logging/setLevel` site already tolerates
a per-backend failure without failing the request, so skipping a backend is the same
outcome its `warn!` arm produces today.

The gate is one read of the era already attached to the transport (`lifecycle.rs:380`),
the same read §2 adds to the probe. No new state, no new config.

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

| # | what it pins | fail-first against HEAD | why |
| --- | --- | --- | --- |
| 1 | `Era::Modern` backend is probed with `server/discover`; `ping` never reaches the wire | **yes** | HEAD sends `ping` unconditionally (`lifecycle.rs:1053`) |
| 2 | `Era::Legacy` backend is probed with `ping` | no - regression guard | HEAD already sends `ping` to everything, so it passes for the wrong reason; it exists to catch the mirror-image defect after row 1 lands |
| 3 | unreachable/unclassified backend takes the legacy arm | no - regression guard | same; pins `classify`'s "silence is not modern" rule at this call site |
| 4 | in-band `-32601` (stdio): tripped breaker **unchanged**, counter increments, no restart | **yes** | HEAD reads `Ok(Ok(_))` as success and resets the breaker (`:1054-1061`) |
| 5 | `-32601` carried as an HTTP 404 body: same three assertions | **yes** | HEAD reads `Ok(Err(_))` as a fault and calls `force_restart()` (`:1064-1066`) |
| 6 | `-32603` on a tripped breaker: breaker **unchanged**, no restart, **and the cached era unchanged** | **yes** | HEAD resets on any in-band answer; this is the row that pins §3's widened middle arm, and the one an implementation narrowing it back to `-32601` would break. The era assertion is what stops the widened arm from widening invalidation with it: only method-not-found is evidence about era, so an implementation wiring invalidation to "any unserved answer" must fail here |
| 7 | closed socket / timeout still trips and restarts | no - regression guard | current behaviour; guards against fixing 4-6 by making everything healthy |
| 8 | a valid `server/discover` result on a tripped breaker resets it, **and a `ping` result on the legacy arm resets it too** | no - regression guard | current behaviour for a result; guards against fixing 4-6 by making nothing healthy. The legacy half stops an implementation from wiring the reset into the modern branch only |
| 9 | after a `-32601`, the cached era for that backend is no longer `Modern`, and the **next tick sends `ping`** - `server/discover` must not appear on the wire again until positive evidence reclassifies the peer | **yes** | no invalidation path exists on this call site, and naming the method is what makes the re-classification rule falsifiable rather than implied |
| 10 | escalation: unserved answers 1 and 2 leave the breaker unchanged, the third trips and restarts | **yes** | no counter exists |
| 11 | escalation counter resets: two unserved answers, one served result, two more unserved answers must **not** trip | **yes** | same |
| 12 | HTTP non-2xx whose body is absent, not JSON, or carries an `id` that does not echo the probe's: **transport fault** - trip and `force_restart()` | **yes** | the fallback half of §3's new body-parsing branch. Without it, an implementation that reads a proxy's 502 text page as an unserved answer stops restarting dead backends, and this row is also what pre-pins the `id`-echo mitigation named in the residual |
| 13 | `logging/setLevel` fan-out skips a modern backend and forwards to a legacy one in the same call | **yes** | `protocol.rs:310` forwards to every backend with no era read |
| 14 | `resources/subscribe` against a modern backend is refused by the gateway with `-32601` and **never reaches the transport**; against a legacy backend it is forwarded unchanged | **yes** | `resources.rs:389` forwards unconditionally |
| 15 | `resources/unsubscribe`, same two assertions | **yes** | `resources.rs:423` forwards unconditionally |
| M | per-probe wall time and response size for `server/discover` against a real backend, against `ping`, at the default interval | measurement, not a gate | the evidence for §2's load claim, which is asserted there and unproven until this exists. Emit it as a histogram rather than a one-off reading, so the claim stays verified and the `EraCache` fallback decision has data on every release |

Rows 1, 4, 5, 6 and 9 through 15 must be observed failing against `HEAD` before the
implementation lands - a test that passes before the fix is testing something else, see
`a-test-first-suite-can-encode-an-inverted-oracle`. Rows 2, 3, 7 and 8 must pass both
before and after.
