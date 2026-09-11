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
| as a status (HTTP non-2xx → `Err`, `src/transport/http/mod.rs:1275-1295`; 404 is the shape `MIK-7215.STATELESS.5a` obliges a conformant peer to use) | `Ok(Err(e))` `:1064` | failure, and **`force_restart()`** `:1066` | rebuilds the transport of a working backend every 10s |

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

## 3. Ruling 2 — the probe classifies the answer, not the envelope

Replace the two-arm match at `:1053` with a three-way classification that reads the body
on both transports:

| observation | verdict | breaker | transport |
| --- | --- | --- | --- |
| a JSON-RPC **result** | serving | reset if tripped | keep |
| a JSON-RPC **error other than method-not-found** | serving — the peer parsed and answered | reset if tripped | keep |
| **method-not-found** (`-32601`), in-band *or* carried as a status | **neither**: the probe is mis-specified for this peer | **unchanged** — neither reset nor tripped | keep |
| transport fault or timeout | not serving | trip | `force_restart()` |

The third row is the whole point of OUTBOUND.2. A refusal is evidence about the *probe*,
not about the backend. Recording it as health hides a probe that can never fail;
recording it as death restarts a working peer. It must be surfaced instead: a
`warn!` naming the method and the era the gateway believed, plus a
`mcp_health_probe_unsupported_total{backend,method}` counter, and — because a `-32601`
to `server/discover` means the era classification was wrong — an invalidation of the
cached era so the next start-path probe re-classifies.

**This requires the HTTP transport to stop flattening a refusal into a string.** A 404
whose body is a `-32601` JSON-RPC error is currently `Err(safe_http_status_error(..))`
(`src/transport/http/mod.rs:1275-1295`), which discards the code. The existing
`ProtocolVersionRejected` branch immediately above is the precedent: that code path was
added for exactly this reason — a version refusal carried as a status had its body
dropped before anyone could read it. The same treatment, one branch wider: parse the body
for a JSON-RPC error object before falling back to the status string.

## 4. What this does not do

- It does not touch the **inbound** `ping` the gateway serves. `MIK-7215.STATELESS.6a`
  governs that, and `src/protocol/meta.rs:253` keeps `ping` served for legacy clients.
- It does not change the start-path era probe or `EraCache` semantics, beyond invalidating
  a cached era that a refusal proves wrong.
- It does not generalise to "no era-removed method is ever sent". `ping` is the only
  unconditional outbound use of a removed method found on this path; a sweep for others is
  separate work and is not claimed here.

## 5. Test plan (to be reviewed as a test plan before any implementation)

1. **OUTBOUND.1, modern.** A backend classified `Era::Modern` is probed; the recorded
   outbound method is `server/discover` and `ping` never appears on the wire.
2. **OUTBOUND.1, legacy.** A backend classified `Era::Legacy` is probed; the outbound
   method is `ping`. Guards the mirror-image defect.
3. **OUTBOUND.1, unknown.** An unreachable/unclassified backend takes the legacy arm —
   pins `classify`'s "silence is not modern" rule at this call site.
4. **OUTBOUND.2, in-band refusal.** A stdio peer answering `-32601`: the breaker's tripped
   state is **unchanged**, the counter increments, no restart. Fails against today's code
   (which resets the breaker).
5. **OUTBOUND.2, status refusal.** An HTTP peer answering 404 with a `-32601` body: same
   three assertions. Fails against today's code (which calls `force_restart`).
6. **OUTBOUND.2, genuine fault.** A closed socket / timeout still trips and restarts —
   the regression guard for fixing 4 and 5 by making everything healthy.
7. **OUTBOUND.2, served result.** A valid `server/discover` result on a tripped breaker
   resets it, as today.
8. **Era invalidation.** After a `-32601` to `server/discover`, the cached era for that
   backend is no longer `Modern`.
9. **Measurement (M).** Per-probe wall time and response size for `server/discover`
   against a real backend, compared with `ping`, at the default interval. This is the
   evidence for §2's load claim; the claim is unproven until it exists.

Every one of 1–8 must fail against `HEAD` before the implementation lands. A test that
passes before the fix is testing something else — see
`a-test-first-suite-can-encode-an-inverted-oracle`.
