# RFC-0061 — Release scope: MCP 2026-07-28, client and server

**Status**: DRAFT for review. Design only — no code until reviewed.
**Date**: 2026-08-29
**Builds on**: `RFC-0060-dual-generation-mcp.md` (portfolio-wide dual-generation strategy, twice reviewed 2026-08-22)
**Scope owner**: mcp-gateway
**Tickets**: MIK-7272 (parent), MIK-7212, MIK-7213, MIK-7214, MIK-7215, MIK-7217, MIK-7218

RFC-0060 answers *how the portfolio survives two protocol generations*. This RFC answers a
narrower question: **what ships in mcp-gateway's next release, and what it buys.** Where the
two disagree, the disagreement is stated, not smoothed.

## §P0 SCOPE — declared before review

**FOR**: mcp-gateway speaks MCP revision **2026-07-28** completely, as a **server** to its
clients and as a **client** to its backends, while continuing to serve peers that speak
2025-11-25 and 2025-06-18 — and uses the revision's new affordances where they make the
gateway measurably better rather than merely compliant.

**OUT** (labelled, not dropped):
- Other portfolio surfaces (hebb, throttla, fulcrum, botnaut-client, pithy). RFC-0060 owns them; this release is the gateway alone. It goes first because it is the only surface that must speak *both* eras simultaneously by construction.
- The Skills-over-MCP and MCP Apps extensions. Not stable specifications.
- Adopting `rmcp` inside the gateway. Decided below, with reasons.
- Retiring 2025-03-26 and 2024-11-05. Requires U1 telemetry; the window stays as-is this release.
- Everything in the mcp-gateway backlog not named here — the ~70 other open tickets are untouched by protocol work and stay untouched.

## Correction to the record, verified at source

Three claims currently steering this work are wrong, and the third changes the release's size.

**1. The gateway is one revision behind, not two.** The 2026-07-28 changelog opens: *"changes
made to the Model Context Protocol (MCP) specification since the previous revision,
[2025-11-25]"*. The spec site lists exactly five revisions. MIK-7272's title should be corrected;
the work it describes is unaffected.

**2. `rmcp` 3.1.4 models the new revision but does not default to it.** `ProtocolVersion::LATEST`
is `V_2025_11_25`; `V_2026_07_28` exists alongside a separate `STANDARD_HEADERS` constant
(docs.rs, read 2026-08-29). The types are real — `ListToolsResult` carries
`{result_type, meta, next_cursor, ttl_ms, cache_scope, tools}`, and `DiscoverRequest`,
`DiscoverResult`, `InputRequiredResult`, `ResultType` and the tasks extension are all present.
RFC-0060's U4 conclusion stands on the type surface. But *"the migration buys dual-generation
support rather than building it"* overstates it: adopting rmcp buys the **vocabulary**, not the
default behaviour.

**3. Per-caller tool lists are LEGAL, and this is the important one.** MIK-7272 calls the list
requirement *"the architectural one"* and RFC-0060 builds a cache hazard on top of it. The full
sentence in `server/tools` (read 2026-08-29):

> The set … **MUST NOT** vary per-connection or as a side effect of other requests on the
> connection. The set **MAY** vary by the authorization presented on the request — for example,
> returning only the tools the caller's granted scopes permit — **since credentials are
> per-request input, not connection state.**

The prohibition is on **connection state**, not on **caller identity**. Every filter the gateway
runs that is derived from the credential on the request is explicitly sanctioned. What is
forbidden is variation the request itself does not carry.

That converts the headline finding from *"the projection must move or we knowingly diverge"* into
a classification exercise with a much smaller residue. It does not make the work free: each of
the five known filters must be classified, and the ones that are connection-derived must become
request-derived or be dropped in modern mode.

| Filter | Source | Verdict |
|---|---|---|
| API-key scope | credential on the request | **legal**, `cacheScope: private` |
| Routing profile | `active_profile(session_id)` → `session_profiles.get_profile_name(sid, …)` | **illegal in modern mode** — must arrive per request |
| Surfaced tools | `resolve_surfaced_tool(surfaced, session_id)`, filtered by the routing profile above | **illegal only through the profile.** The configured set is static; it inherits the defect rather than owning one. Fixing the profile fixes this. |
| Session-promoted tools | `promoted_tools_for_session(session_id)`, `spec-preview` only | **illegal in modern mode** — the clearest case in the spec's own words |
| Code Mode | `self.code_mode_enabled` (server config, set once) OR `url_override` (from the request URL) | **legal.** Server-wide configuration is not connection state, and the URL is per-request input. |
| Spec-preview query | query parameter on the request | **legal** — it is request input |

Verified at source 2026-08-29: `src/gateway/meta_mcp/mod.rs:1002-1062` (list assembly),
`mod.rs:1101` (`effective_code_mode`), `mod.rs:152/437` (`code_mode_enabled` as config),
`src/gateway/meta_mcp/surfaced.rs:101-116`, `active_profile` in `mod.rs`.

**Two of the five filters named by the 2026-08-22 review are not defects.** Code Mode was
recorded there as a connection toggle; it is server configuration plus a request URL, and both are
permitted. The residue is **one** mechanism — the session-keyed routing profile — plus the
`spec-preview` promotion list. That is the whole of the "architectural" finding.

`cacheScope` then stops being a hazard and becomes the correct label: `"private"` means *"cacheable
only within the same authorization context; caches MUST NOT be shared across authorization
contexts"* (schema, read 2026-08-29). An auth-varying list is not a compliance problem with a
workaround — it is a first-class case the revision has vocabulary for.

## Why this revision is the gateway's, specifically

The strategic case is not "stay compliant". It is that 2026-07-28 was designed around
intermediaries, and the gateway is one. From the transport binding:

> The Streamable HTTP transport mirrors selected JSON-RPC body fields into HTTP headers **so that
> intermediaries (load balancers, gateways, observability tooling) can route and inspect requests
> without parsing the body.**

Four consequences, each of which retires gateway-specific machinery rather than adding to it:

| The revision adds | The gateway gets |
|---|---|
| `Mcp-Method` / `Mcp-Name` required on every POST | **Routing** from headers, with the body parsed only where the gateway acts on it. Closes RFC-0060's U5 without the rmcp latency prototype it scheduled — for routing. Authorization still validates header against body (§3.1). |
| Per-request `_meta`: `protocolVersion`, `clientCapabilities`, `clientInfo` | Caller **context** on every request, by protocol. MIK-6704 (P0, identity propagation) and MIK-6207 stop being gateway inventions and become plumbing — on top of the authenticated credential, never instead of it. |
| Statelessness — no `initialize`, no sessions | No sticky routing, no session affinity, horizontal scale for free. Also removes the class MIK-7250 lives in: self-asserted session ids compared against attacker input. |
| MRTR replaces server-initiated requests | MIK-7251 (sampling/elicitation broadcast to every session) becomes **structurally impossible** — there is no server-initiated channel left to broadcast on. |
| `ttlMs` / `cacheScope` on five endpoints | The gateway is the "shared intermediary" the fields exist for. It can cache backend lists correctly instead of guessing. |
| `extensions` on client and server capabilities | A sanctioned home for attestation and provenance receipts (MIK-6904) instead of bespoke fields. |
| OTel `traceparent`/`tracestate`/`baggage` in `_meta` | Standard distributed tracing across the hop the gateway owns. |

**Four open tickets are closed by adopting the protocol rather than by writing gateway code.**
That is the argument for doing this now and doing it completely.

## Decision 1 — the gateway stays hand-rolled; rmcp is not adopted here

RFC-0060 Decision 1 chose option C, *"everything onto official rmcp 3.x"*, while flagging the
gateway as the open question (U5): rmcp is built for servers, and the gateway is a proxy that must
forward a request whose generation it did not choose.

**U5 is closed, and it closes against adoption for this surface.** The spec puts the routing key
in the headers precisely so an intermediary need not deserialise. A proxy built on server-shaped
model types pays a deserialise-reserialise per hop to obtain what two header reads already give it.
rmcp remains right for every surface that *is* a server — RFC-0060's Decision 1 holds everywhere
else, unchanged.

**What we take from rmcp instead of taking rmcp**: its wire vocabulary is the reference
implementation of the new schema, and conformance-testing against an rmcp client and an rmcp
server is the cheapest way to answer U6 ("does the wire behaviour match the type surface"). It
becomes a dev-dependency in the conformance harness, not a runtime dependency.

## Decision 2 — dual-era, both roles, on one endpoint

The spec sanctions this explicitly: *"A dual-era server MAY serve both eras concurrently on the
same endpoint or process,"* selecting behaviour from how the client opens — `initialize` means
legacy, per-request `_meta` means modern.

The gateway must be dual-era **twice**, and this is the part no other surface faces:

```
legacy client ─┐                      ┌─ legacy backend   (initialize, sessions, ping)
               ├─ mcp-gateway ────────┤
modern client ─┘   (dual-era server    └─ modern backend   (stateless, discover, MRTR)
                    + dual-era client)
```

All four combinations must work. Three are mechanical. The fourth — **modern client, legacy
backend, mid-elicitation** — is the design's open problem, below.

**This is the product position.** Every backend in the wild is legacy today and most will be for a
year; every client will move. A gateway that bridges the eras is the only way a modern client
reaches a legacy tool, and that is a capability, not a compatibility burden.

## Decision 3 — MRTR continuation: the gateway wraps, never forwards

RFC-0060 leaves this open and both 2026-08-22 reviewers named it the blocking gap. The contract:

A backend returns `InputRequiredResult { inputRequests, requestState }`. The gateway must reach the
client, and on retry must reach *the same backend* with *that backend's* `requestState` — while the
client is forbidden from inspecting or modifying what it echoes.

**The gateway MUST NOT forward a backend's `requestState` verbatim.** It mints its own,
integrity-protected, carrying the backend's opaque blob inside:

```
gatewayRequestState = v1 ‖ kid ‖ nonce ‖ AEAD( key[kid], nonce, aad = v1‖kid,
    { backend_id, backend_request_state, principal_fingerprint,
      original_request_digest, origin_replica, issued_at, expires_at, jti } )
```

Five properties, each earning its place:

1. **Integrity.** The spec: *"servers MUST treat `requestState` as attacker-controlled input … MUST protect its integrity (e.g. HMAC or AEAD) and MUST reject state that fails verification."* The gateway is a server to its client; the duty is the gateway's.
2. **Confidentiality.** A backend's state may encode its own authorization. Forwarding it verbatim hands the client a token it should never hold. AEAD, not a signature alone.
3. **Binding to principal.** Without it, one caller replays another's continuation — the hazard `src/idempotency.rs` already creates by keying on `server:tool:hash(arguments)` (2026-08-22 review, confirmed at source).
4. **Binding to the original request.** The spec confines these fields to the retry of the original request: *"They MUST NOT be used for any other request."*
5. **Expiry and single use.** The spec's replay guidance; a continuation is not a bearer token with an unbounded life.

### Encryption alone does not make it single-use

Property 5 does not follow from properties 1–3, and the first draft of this design asserted that it
did. AEAD proves a blob was minted by us and never altered; it says nothing about how many times it
has been presented. The spec is explicit: *"Servers for which a given `requestState` must be
consumed at most once (e.g., one-time redemptions) **MUST** enforce that invariant server-side."*

**A consumed-`jti` ledger is therefore part of the mechanism, not an optimisation:**
- redemption is **atomic** — check-and-consume in one operation, or two concurrent retries of a destructive continuation both succeed
- **bounded**, evicting on `expires_at`, so it cannot grow without limit
- **shared across replicas**, or continuations are only single-use per instance, which is not single-use
- its retention **matches or exceeds** `expires_at` and the idempotency window, since a ledger that forgets before the token expires is a replay window with extra steps

### The envelope is a wire format, and wire formats need versions

`v1` and `kid` are outside the ciphertext and authenticated as associated data, because a key must
be rotatable without invalidating every continuation in flight. The keyring retains **verification**
keys for at least the maximum continuation lifetime after a key stops being used for **minting**.
Absent that, key rotation silently breaks every open elicitation, and a restart or a redeploy looks
identical to an attack.

### The legacy backend, and the replica that holds it

For a legacy backend holding the RPC open, the envelope carries an in-flight table key instead of a
backend blob. The stateless client sees one contract; the gateway absorbs the legacy backend's
statefulness. That is the bridge earning its keep, and it is the one place the gateway is permitted
to hold state.

**But a stateless client's retry may land on any replica, and the open RPC lives on exactly one.**
`origin_replica` is in the envelope for this reason: the retry is routed back to the replica that
holds the exchange, and a gateway that cannot reach it fails the continuation explicitly rather than
silently starting a second one. Single-instance deployments are unaffected; multi-replica ones would
otherwise fail behind an ordinary round-robin load balancer, which is the default deployment.

The table is **bounded** — a maximum count, a per-entry deadline, and cleanup on client abandonment,
which is the common case since the spec explicitly permits a client never to retry: *"Servers MUST
NOT assume that clients will fulfill the `inputRequests` or retry the original request."* An
unbounded table keyed on abandonment is a memory-exhaustion vector reachable by any client that
starts elicitations and walks away.

### The reverse direction is not mechanical

A **modern backend** returning `InputRequiredResult` to a **legacy client** that expects a
server-initiated `elicitation/create` needs the symmetric translation: hold the modern backend's
continuation, issue the legacy server-initiated request on the client's connection, and retry the
backend with the collected `inputResponses`. This direction was previously waved through as
mechanical. It is the same state machine mirrored, it needs the same bounded table, and it is the
path most likely to exist in practice — modern backends will arrive before every client moves.

**Fail-fast before any of this is built** (grok's, adopted, extended): run one `gateway_invoke` from
a 2026 client against a 2025 backend that elicits, then the reverse pair. Two runs. If the pairs
cannot be constructed, the contract is unimplementable as written and this decision reopens.

## Decision 4 — versioning

**4.0.0.** Sessions disappear from the modern path, `Mcp-Session-Id` stops being emitted to modern
clients, five error codes are renumbered, and connection-derived tool filtering changes meaning.
Semver does not let that be a minor. The legacy path is preserved, so an existing client sees no
break — but the contract the version communicates is about what *may* change, and this changes it.

## What ships — three slices, in dependency order

Each slice is independently shippable and independently useful. A slice that cannot ship alone is
mis-drawn.

### Slice 1 — Speak it (conformance floor)

**Slice 1 is a conformance floor, not a support claim.** It does not entitle the gateway to
advertise 2026-07-28 to real peers: sessions still exist, MRTR is unbridged, and
`subscriptions/listen` is absent until slice 2. Modern advertisement is gated on slice 2's exit,
and the flag stays off until then. The earlier framing of all three slices as independently
advertisable was wrong.

| # | Item | Why it is first |
|---|---|---|
| 1.1 | `server/discover` on every transport | A **MUST**. Additive, breaks no client, and it is the only probe that works in both directions once `initialize` and `ping` are gone. RFC-0060 calls it the keystone; nothing argues otherwise. Ticket: MIK-7217. |
| 1.2 | Per-request `_meta` dispatch: `protocolVersion`, `clientCapabilities`, `clientInfo`; `serverInfo` on results | The stateless core. Everything else assumes it. |
| 1.3 | Header contract per the spec's own matrix: `MCP-Protocol-Version` on every POST; `Mcp-Method` on every request; `Mcp-Name` **only** for `tools/call`, `resources/read`, `prompts/get`; Base64 sentinel encoding for values not representable in ASCII; `x-mcp-header` custom headers from tool parameters; `HeaderMismatch` (-32020) on disagreement | Required for compliance, and the routing key slice 3 spends. Treating `Mcp-Name` as universal would reject valid requests; omitting the sentinel breaks every non-ASCII tool name. Ticket: MIK-7214. |
| 1.4 | Error code renumbering (-32001→-32020, -32003→-32021, -32004→-32022); resource-not-found -32002→-32602 | Mechanical, breaking, cheap now and expensive later. |
| 1.5 | `resultType` on every result; treat a missing field from an older peer as `"complete"` | A **MUST** on the client side. One field, and omitting it silently mis-reads every legacy backend. |
| 1.6 | `ttlMs` + `cacheScope` on the five cacheable endpoints, with the classification table above | **Required**, not an optimisation. Tickets: MIK-7213, MIK-7218. |
| 1.7 | Deterministic tool ordering | One `sort_by`. Raises client prompt-cache hit rates — the same overhead the Meta-MCP surface budget exists to protect. |
| 1.8 | **Removed methods refused on the modern path**: `ping`, `logging/setLevel`, `notifications/roots/list_changed`. Log level per request via `_meta` `logLevel`, and **no** `notifications/message` for a request that did not ask for one | Version-gated: still served on the legacy path, refused on the modern one. A modern peer that can still call `ping` is not speaking this revision, whatever the version string says. |
| 1.9 | **Authorization requirements of this revision**: validate `iss` on the authorization response against the recorded issuer (RFC 9207) before redeeming the code; send `application_type` on Dynamic Client Registration; key persisted client credentials by issuer, never reuse across issuers, re-register when the authorization server changes | The revision's own **MUST**s, and the only ones in it with a credential-confusion failure mode. Omitted entirely from the first draft of this scope. |


### Slice 2 — Bridge it (the part only a gateway must do)

| # | Item | Why |
|---|---|---|
| 2.1 | Session-keyed behaviour inventory, then rebinding to ADR-008 `Principal` | RFC-0060's U7, and the largest risk in the whole design. **The inventory is now done — see below — and it is four times larger than previously recorded.** Ticket: MIK-7215. |
| 2.2 | MRTR proxying per Decision 3, including `inputResponses`/`requestState` in `extract_tools_call_params` | Today the gateway silently drops both (`src/gateway/router/helpers.rs:178`), so a modern client's elicitation never completes **and** `gateway_kill_server` runs without the confirmation `destructive_confirmation.rs` exists to enforce. Ticket: MIK-7212, CRITICAL. |
| 2.3 | Idempotency keys extended to cover `inputResponses` and `requestState`; `InputRequired` never cached as a completion | `src/idempotency.rs:10` would cache an interim result as a replayable success. |
| 2.4 | Backend era detection: probe with `server/discover`, treat **any** non-modern outcome — arbitrary error, silence, timeout — as legacy, then fall back to `initialize`; warm-start retry schedule retained | RFC-0060 U3, corrected twice. A legacy backend does not answer `server/discover` with a polite "I am legacy"; the spec's own matrix says *"the probe returns a non-modern error or times out"*. Only a recognised modern error (e.g. `UnsupportedProtocolVersionError`) proves a modern peer. Discover makes each probe cheaper; it does not make an unbound port answer, and it does not make a silent one legible without a timeout budget. |
| 2.5 | `subscriptions/listen` replacing the GET endpoint and `resources/subscribe` | Follows 2.1 — it is the session-free replacement for the stream the multiplexer owns. |
| 2.6 | Re-issue safety: side-effecting calls carry idempotency keys or route through Tasks | SSE resumability is gone; a broken stream forces a re-issue with a new id. Without this, irreversible actions duplicate. |

### U7 RESOLVED — the session-keyed inventory, and what it costs

Run 2026-08-29: `rg -c session_id src/ --type rust` returns **32 source files**. The 2026-08-22
review named six behaviours; the true surface is a different order of magnitude, and several of the
unnamed ones are **security controls that fail silently** rather than features that fail loudly.

Every entry needs a stateless replacement named before its session key is removed. A control that
keeps compiling while its state disappears does not report that it has stopped working.

| Behaviour | Where | What breaks when sessions vanish | Replacement |
|---|---|---|---|
| **Destructive-operation confirmation** | `gateway/destructive_confirmation.rs:81-92` — takes the session id *"from the `Mcp-Session-Id` header"*, then `forward_elicitation_with_response(session_id, …)` | Both halves are deleted by this revision: the header **and** server-initiated elicitation. The human-confirmation gate on `gateway_kill_server` has no channel left. | **Rebuild on MRTR**: return `InputRequiredResult` carrying `elicitation/create`, resume from the continuation envelope on retry. This is the same mechanism as Decision 3, and it is why MIK-7212 is CRITICAL rather than cosmetic. |
| **Anomaly scoring** | `security/firewall/anomaly.rs:41-88` — `last_tool: session_id → "server:tool"`, `score_transition` | Every request looks like a first request, so no transition is ever anomalous. The firewall keeps returning scores; they are all meaningless. | Key on `Principal` + a bounded recent-activity window. **Fail loudly if the key is absent** rather than scoring zero. |
| **Firewall budgets** | `security/firewall/mod.rs:311-351` | Per-session budgets reset on every request — an attacker gets an unlimited budget by never reusing a session, which under statelessness is the default. | `Principal`-keyed budgets with an explicit window. |
| **Transparency log correlation** | `security/transparency_log.rs:224-240,578` — `session_id` is a logged field and a query key | Audit entries lose their correlation key; `entries whose session_id matches` returns nothing. | **OTel `traceparent` from `_meta`**, which this revision standardises — a better key than the one being removed, and one that spans the whole hop rather than one connection. |
| **Cost accounting** | `cost_accounting/mod.rs:14,118-136` — `per_session: DashMap<session_id, SessionCost>` | Per-session buckets degenerate to one bucket per request; aggregation is lost. | `Principal` + `clientInfo` as an unauthenticated sub-label for display only. |
| **Session lifecycle cleanup** | `gateway/session_lifecycle.rs:46-54` — `on_disconnect` callback fan-out | There is no disconnect in a stateless transport, so cleanup **never fires** and everything it reaped leaks. | TTL reaping. Every registered handler must be re-expressed as an expiry, not an event. |
| **Projection A/B stickiness** | `projection/mode.rs:81-118` — `projection_decision(mode, session_id)`, arm in the cache key | Arm assignment flaps per request; the experiment measures noise. | Hash the `Principal` for a stable arm; state plainly that anonymous callers cannot be in a sticky experiment. |
| **Prompt-cache partitioning** | `meta_mcp/prompt_cache.rs:107-111` (`from_session_and_user`), `simhash.rs:376-394` (partition assignment) | Cache keys lose a component; partitions churn and hit rates fall — a performance regression, not a correctness one. | Drop the session component, keep the user/principal component. |
| **Transition tracking** | `transition.rs:11,59-79` — `session_id → last_invoked_tool` | Same failure as anomaly scoring, feeding it. | Same replacement; one store, not two. |
| **Streaming session reaping** | `gateway/streaming.rs:137-159`, `gateway/proxy.rs` multiplexer | The SSE stream this manages is replaced wholesale by `subscriptions/listen`. | Item 2.5, keyed on `subscriptionId`. |
| **Cached-token stats** | `stats.rs:62-74` | Optional attribution silently narrows to nothing. | Optional by `Principal`; acceptable to drop. |
| **Routing profile** | `routing_profile/mod.rs`, `meta_mcp/mod.rs::active_profile` | The list-projection defect above. | Per-request selection; see the correction table. |

**Two conclusions this changes.** First, `destructive_confirmation` moves from "a caller of the MRTR
work" to **a dependent of it** — the confirmation gate cannot be ported until Decision 3 is built,
so MIK-7212 is a prerequisite of slice 2, not a peer. Second, three of these are security controls
whose failure mode is *silence*: anomaly scoring, firewall budgets, and the transparency log will
each keep running and stop protecting. Each needs a test that asserts the control **refuses** when
its key is missing, not merely that it computes something.

### Slice 3 — Exploit it (why the release is worth more than compliance)

| # | Item | Value |
|---|---|---|
| 3.1 | Header-first **routing**: dispatch on `Mcp-Method`/`Mcp-Name`, parse the body only where the gateway acts on it — and validate header against body **before** authorizing or executing | The hot path stops parsing JSON it does not need. See the correctness bound below; this is routing, never authorization. |
| 3.2 | `Principal` derived from the **authenticated** credential, enriched — never replaced — by `_meta.clientInfo`, and propagated to backends | Closes MIK-6704 (P0) and MIK-6207 with protocol-carried context, without trusting a self-asserted name. |
| 3.3 | Shared list cache keyed on **every** request-derived projection input | The gateway becomes a correct shared cache instead of a cache that must not exist. Key composition below. |
| 3.4 | OTel `traceparent`/`tracestate`/`baggage` propagation through `_meta` | One standard tracing story across the hop nobody can currently see through. |
| 3.5 | `extensions` capability, declaring the gateway's own (attestation, provenance receipts) | MIK-6904 gets a sanctioned home and a negotiation story instead of a bespoke field. |
| 3.6 | Tasks extension (`io.modelcontextprotocol/tasks`) for long-running backend calls | Also the clean answer to 2.6 for operations that cannot be made idempotent. |

### 3.1 is routing, and routing is not authorization

The first draft said "dispatch **and authorize** on the headers, body opaque". That is the exact
vulnerability the spec's own rationale describes:

> Servers **that process the request body** **MUST** reject requests where the values specified in
> the headers do not match the corresponding values in the request body. This prevents potential
> security vulnerabilities when different components in the network rely on different sources of
> truth (e.g., a load balancer routing on the header value while the MCP server executes based on
> the body value).

Note the condition — *that process the request body*. A pure relay is not bound by it. **The gateway
is not a pure relay**: it executes at the Meta-MCP chokepoint, so the obligation is squarely ours.

The rule that survives: **route and pre-filter on headers; validate header against body, and only
then authorize or execute.** Forward the original bytes rather than reserialising — the saving is
the reserialise, not the parse. Where the gateway genuinely only relays, header dispatch alone
stands, and that case must be identified explicitly rather than assumed.

### 3.2 — a name a caller types is not an identity

`io.modelcontextprotocol/clientInfo` is **self-asserted**: the spec says clients *SHOULD identify
themselves*, which is identification, not authentication. Promoting it into the security `Principal`
would let any caller claim any identity — the same defect class as MIK-7250, where self-asserted
session ids are compared against attacker input.

**The authenticated OIDC subject or API-key digest remains the sole authority for authorization.**
`clientInfo` is display and diagnostic metadata, carried alongside and labelled untrusted.
`clientCapabilities` is negotiation input, honoured for what a client can *receive* and never for
what it may *reach*.

### 3.3 — the cache key is the whole projection, not just the credential

Keying on authorization context alone is insufficient while any other request-derived input varies
the result. The key covers: authorization binding, routing profile, Code Mode state, spec-preview
query, pagination cursor, backend identity, negotiated protocol revision, and a policy epoch that
invalidates every entry when grants or profiles are reconfigured. Anything not in the key must not
vary the response — and if it does and cannot be keyed, that response is not cacheable. `cacheScope`
follows the same analysis: `private` whenever any authorization-derived input participates.

## Unknowns, each with a scheduled check (§P1)

| # | Question | Check | Blocks | State |
|---|---|---|---|---|
| **U1** | Which revisions do our clients actually speak? | Log `_meta.protocolVersion` and `initialize.params.protocolVersion` for one week, count by client; shadow-log the `cacheScope` that *would* be emitted. | Retiring 2025-03-26 / 2024-11-05 — **not this release**. | Open, MIK-7218. Does not block slices 1-3. |
| **U6** | Does the wire behaviour of the new schema match its type surface? | Conformance harness: gateway against an rmcp client and an rmcp server, covering discover, MRTR both directions, caching, header validation and session-free behaviour — across **every revision in the compatibility window**, which is five, not three. | Slice 1 exit. | Open. **Scheduled inside slice 1** — it is the slice's test plan, not a separate project. |
| **U7** | What else is keyed by session? | Inventory across the gateway before any removal. | Slice 2 start. | Open, item 2.1. |
| **U8** | Can the four era-combinations actually be constructed for test? | Two `gateway_invoke` runs, modern↔legacy both ways, one eliciting. | Decision 3. | Open. **Cheapest check in the document; run it first.** |
| **U9** | Is header-first routing worth its complexity? | Benchmark narrow header validation plus raw-byte forwarding against today's full-parse path, on the same workload. | Slice 3.1 only. | Open. A performance item without a number does not ship. |
| ~~U5~~ | ~~Can rmcp model types carry a proxy pass-through?~~ | — | — | **Closed** by Decision 1 — but narrowly: the headers remove the need to parse for *routing*, not for *authorization*. See 3.1. |

`U2` (hebb's session patch) belongs to RFC-0060 and hebb, not to this release.

## What this design does not answer

- **Whether legacy mode is ever removed.** Not this release, and the spec's twelve-month minimum deprecation window means it need not be decided now. Recording it so a later reader does not mistake silence for a plan.
- **Which slice-3 items survive contact with measurement.** 3.1 and 3.3 are performance claims. They ship with numbers or they do not ship — a claim without a benchmark is a slice-3 item that belongs in slice 1's honest scope.
- **The Meta-MCP surface budget under `server/discover`.** Settled in RFC-0060: discover is a protocol RPC, never enumerated to the model, and costs zero surface tokens. Restated only because the compact-surface rule is exactly the kind of locked decision that gets cited against a MUST.

## Test plan shape (§P2) — the matrix comes before the tests

Reviewer improvement, adopted: the acceptance criteria for this release are **derivable
mechanically** from the changelog, and writing them any other way guarantees an omission.

One row per normative statement in the 2026-07-28 changelog, each crossed with:
role (server ‖ client), transport (stdio ‖ Streamable HTTP), revision (all five in the window), and
outcome (positive ‖ negative). A row whose evidence cell is empty **is** the finding — an untested
MUST is an unimplemented MUST that happens to compile.

Two suites earn separate mention because coverage tools cannot see their absence:

- **Continuation envelope vectors**: deterministic fixtures for tamper, expiry, replay of a consumed `jti`, wrong principal, wrong original request, key rotation across the overlap window, oversized state, and arrival at a replica that does not hold the exchange. Each must **fail closed**, and each must fail for the *stated* reason rather than incidentally.
- **Era-combination matrix**: all four client×backend era pairs, each with an elicitation in flight. This is U8 promoted from a probe to a permanent suite.

## Adversarial review — round 1, 2026-08-29

GPT-5.6: **SHIP-WITH-FIXES**, 13 findings (4 CRITICAL, 5 HIGH). Grok and Kimi were both
rate-limited; this design carries **one vendor**, not the two the gate requires, and that is a
stated gap rather than a satisfied condition. Re-run before implementation begins.

Every CRITICAL was verified at source before being accepted, and all four were real:

| Finding | Verified how | Where it landed |
|---|---|---|
| `clientInfo` promoted into the security `Principal` lets any caller claim any identity | The spec says clients *SHOULD identify themselves* — identification, not authentication | 3.2 rewritten: authenticated credential stays authoritative |
| "Authorize on headers, body opaque" contradicts mandatory header↔body validation | Spec, Server Validation: servers *that process the request body* MUST reject mismatches, with a load-balancer-versus-server rationale that describes this gateway exactly | 3.1 rewritten: route on headers, validate before authorizing |
| AEAD does not deliver the single-use property the design claimed | Spec, MRTR: one-time redemption MUST be enforced server-side | Decision 3: consumed-`jti` ledger, atomic, shared, bounded |
| The revision's OAuth requirements were absent from the scope entirely | Changelog minor changes 7–9 (`iss` per RFC 9207, DCR `application_type`, issuer-keyed credentials) | New slice-1 item 1.9 |

The HIGH findings produced: cross-replica continuation routing (`origin_replica`), the reverse
MRTR contract as its own state machine, bounded in-flight tables with abandonment cleanup, the
honest restatement that slice 1 cannot advertise 2026-07-28 alone, era detection that treats
silence and arbitrary errors as legacy, and a versioned envelope with key rotation. The MEDIUMs
produced the full cache key, the corrected header matrix, the removed-method item 1.8, and U6
widened to every revision in the window.

**What was rejected**: nothing. On a design this size that is itself a signal — it means round 2
should be adversarial about the *fixes*, which are now the least-reviewed part of the document.

---

# The 4.0.0 release manifest

Every open mcp-gateway ticket in Backlog, Ready, Blocked or DoR Triage was classified — 71 of them.
This section is the answer, and the reasons. **Nothing is cut for being large; things are cut for
not belonging.**

Baseline: **3.5.0, released 2026-08-28.** Six of its fixes were unlisted in its own release notes
and have since been written up. Several tickets below are closed by that release rather than by this
one, which is the cheapest possible resolution and the easiest to miss.

## A. Protocol core — the release itself (7)

| Ticket | P | Slice | What it is |
|---|---|---|---|
| MIK-7272 | P2 | — | Parent. Correct its title: one revision behind, not two. |
| MIK-7217 | P1 | 1 | `server/discover` — a **MUST**, and the keystone. Purely additive; if it needs to touch the old handshake path, the implementation is wrong. |
| MIK-7214 | P2 | 1 | `Mcp-Method` / `Mcp-Name` header contract, per the spec's matrix. |
| MIK-7213 | P1 | 1 | `ttlMs` / `cacheScope`, and the decision table for which endpoints may ever be `public`. |
| MIK-7218 | P2 | 1 | Revision telemetry + shadow-logging the `cacheScope` that would have been emitted. Feeds 7213 and the compatibility window. |
| MIK-7215 | P1 | 2 | Session inventory then removal. **Inventory resolved above: 32 files.** |
| MIK-7212 | P1 | 2 | MRTR continuation contract. **A prerequisite of slice 2, not a peer** — the destructive-confirmation gate cannot be ported until it exists. |

## B. Ride-along — the release edits this code anyway (6)

Doing these separately means a second pass through a function this release has already rewritten.

| Ticket | P | Slice | Why it rides |
|---|---|---|---|
| MIK-7116 | **P0** | 2 | Cross-tenant guard and data minimisation. Note the ticket **specifies its own mechanism in terms of sessions** — *"blocks accessing sensitive data about multiple customers within one session"* — and this release deletes the session. Its design must be rebound to `Principal` as part of slice 2, or it will be built on the substrate being removed. Fixing the guard while the target moves beats fixing it against a target that has already moved. |
| MIK-6704 | **P0** | 3 | End-user identity propagation to backends (OAuth on-behalf-of / token exchange). The first real consumer of the seam slice 3 builds. Shipping the seam with no consumer means reopening the same path immediately. |
| MIK-7252 | P1 | 3 | Playbook steps run with no caller identity, bypassing per-client scoping. Same `MetaMcpInvoker::invoke` chain slice 3 rewires — one extra parameter now, a second audit later. |
| MIK-7246 | P3 → **blocking** | 2 | **The migration turns this from a gap into a universal bypass, and the ticket's own evidence says so.** `destructive_confirmation.rs:19-21`: the action proceeds after a `WARN` when elicitation is unsupported **or there is no session**. 2026-07-28 has no sessions, so in modern mode *every* destructive call takes the fail-open branch. Filed P3 because an attacker had to opt out by omitting a capability; after this release nobody has to opt out of anything. It ships with slice 2 or slice 2 does not ship. Its AC also wants the tool set derived from the `destructiveHint` annotation rather than a hardcoded `gateway_kill_server` arm, which is the same annotation work as MIK-2982. |
| MIK-7084 | P2 | 1 | Tiered tool disclosure (L0/L1/L2), and stop emitting the ranking blob — measured at ~60% of a `gateway_search` payload, 13 of 16 signals the constant `1.0`. **Honest reason: this is a response-shape change, and 4.0.0 is the breaking release.** The earlier claim that it shares code with the `tools/list` rewrite was overstated — `gateway_search` is a meta-tool result, not a list endpoint. It rides on the version boundary, not on shared lines, and it sits directly on the token-savings differentiator. |
| MIK-6865 | P2 | 1 | Nested tool-schema hardening. This revision loosens `inputSchema`/`outputSchema` to full JSON Schema 2020-12 and adds `$ref` resolution and composition bounds — the schema-emission code is open on the bench either way. |

## C. Unblocked by the protocol, not by us (5)

These waited on per-request caller identity. The protocol now carries it, so the blocker is gone.

| Ticket | P | Verdict |
|---|---|---|
| MIK-6207 | P2 | **In scope.** Its plumbing *is* slice 3. Re-triage after landing: likely closed as superseded rather than implemented. |
| MIK-6729 | **P0** | **Largely built already, and nobody closed it.** `src/identity_propagation/token_exchange.rs` opens with *"RFC 8693 OAuth 2.0 Token Exchange identity-propagation strategy (MIK-6729)"*, and `src/gateway/server/mod.rs:1053` constructs it at startup behind the `TokenExchange` strategy (verified 2026-08-29). A P0 sitting in Blocked, with no recorded blocker, describing work that has shipped. Verify against its acceptance criteria and close — the same shape as the six tickets 3.5.0 already fixed. |
| MIK-6744 / 6745 / 6746 | P2 | **Fast-follow, 4.1.0.** Identity-keyed token store, per-user consent binding, credential passthrough. Each is a *consumer* of the seam, not part of it, and each has its own consent and storage design. Bounded reason for deferring, not a shrug. |

## D. Security — what would otherwise ship as a known hole (4)

| Ticket | P | Why it cannot wait |
|---|---|---|
| MIK-7249 | P2 | Enabling authentication by config reload reports success and applies nothing. 3.5.0 documented this rather than fixing it. A false "protected now" is worse than the gap it claims to close. |
| MIK-7256 | P2 | A **failed** reload has already applied the config's `env_files` to the process environment before validation ran. Also documented, not fixed, in 3.5.0 — and it silently defeats 7249's fix once that exists. |
| MIK-7262 | P3 | An explicit `registers_external_callback` declaration is overruled in three code paths while a comment claims the declaration wins. Latent only because no shipped capability sets the flag — which is exactly how it stays undetected until one does. |
| MIK-7222 | P2 | Credential-disclosure sweep. MIK-7221 fixed this class in one transport; a three-vendor review confirmed it in six more files. Independent of the protocol, and the release ships the same binary. |

## E. Already fixed — close, do not work (6)

**Verified against the 3.5.0 notes and, for the first, against the code.** These are open tickets
describing a state the repository has left behind. Closing them is the highest-value hour in this
document.

| Ticket | Resolution |
|---|---|
| MIK-7258 | Empty/short HS256 secret is refused at config validation — `src/config/mod.rs:398,442-451`, with the reason spelled out in the error. Shipped in 3.5.0. |
| MIK-7257 | Dashboard locality now comes from the connection's peer address, not the caller-controlled `Host`; a request carrying a forwarding header is refused. Shipped in 3.5.0. |
| MIK-7243 | `mcp-gateway init` provisions an admin credential and writes `auth.public_paths`. Shipped in 3.5.0. |
| MIK-7245 | Config files are written `0600` on every path that writes one; an existing wide file is reported with the `chmod` to fix it. Shipped in 3.5.0. |
| MIK-7244 | The gateway refuses to bind when its tool surface is reachable without a credential, before the listener opens. Shipped in 3.5.0. |
| MIK-7265 | Resolved by **deploying 3.5.0**. The running build was `3.4.0-f30539af` (2026-08-16), missing both `24f144c7` and `5d25f104`. No code required. |

## F. Resolved by migration — re-scope, do not implement (3)

Work aimed at code this release deletes. Implementing them is spending twice to end in the same place.

| Ticket | Why |
|---|---|
| MIK-7251 | Sampling and elicitation broadcast to every session. There is no server-initiated channel in 2026-07-28 and no session to broadcast to; MRTR replaces the substrate. Re-scope onto `subscriptions/listen` after slice 2. |
| MIK-7250 | Self-asserted session ids let a caller read another session's cost report. Slice 2 removes the header and the session. Close as resolved-by-migration once slice 2 ships — do not write checks against code being deleted. |
| MIK-7042 | No alert on idle-stop close failures. Idle-stop is session machinery; re-scope after slice 2 rather than instrumenting a mechanism scheduled for removal. |

## G. Deferred, with the reason stated

- **K8s operator GA** (MIK-6672 + 6680–6684, 6692) — its own dependency chain, orthogonal to the protocol. **But**: MIK-6672 and MIK-6680 sit in Blocked with no stated technical blocker; 6672 reads as "large and unscheduled". Re-label rather than leave them looking gated.
- **MIK-6209** — **unblocked now**: its blocker was that the work was dispatched to the wrong repository. Administrative, not architectural.
- **MIK-6158** — genuinely blocked by MIK-6156, **but** its description names a different blocker than the relation Linear records. One of the two is stale; resolve before re-triaging.
- **Framework-mapping tickets** (MIK-7236, 3031, 3293, 3444) — four tickets doing one shape of work against the same capability inventory. Run as a single pass, after the release, when the inventory has stopped moving.
- **Everything else** — ops, tooling, research and unrelated features. Untouched by the protocol work and no cheaper to do now than later.

## Evidence quality — which verdicts are soft

The classification read full descriptions for 52 of 71 tickets; 19 were judged from title, priority,
state and labels alone. Verdicts resting on a title are weaker than verdicts resting on evidence, and
pretending otherwise is how a manifest becomes fiction.

Where a verdict mattered, the description was read before acting. That check changed three entries:
MIK-7246 moved from a deferred P3 to a slice-2 blocker, MIK-6865 moved from deferred to ride-along,
and MIK-7084's stated reason was wrong and has been rewritten. **Two of those three moved *into*
scope** — the soft verdicts were biased toward deferring, so the remaining title-only deferrals
should be read before 4.1.0 is planned, not before 4.0.0 starts.

Separately: the classification was produced from ticket text written **before 3.5.0 shipped**, which
is why five of its nine "security must" items are in section E instead. Any ticket describing the
state of this repository before 2026-08-28 deserves the same suspicion.

## Release totals

| Bucket | Count |
|---|---|
| Protocol core | 7 |
| Ride-along | 6 |
| Unblocked, in scope | 2 |
| Security | 4 |
| **Implemented in 4.0.0** | **19** |
| Closed without work (fixed in 3.5.0, or by deploying it) | 6 |
| Re-scoped after the migration | 3 |
| Deferred with a reason | 43 |

Nineteen tickets implemented, nine resolved without implementation. The nine are worth as much as
several of the nineteen and cost an hour: a ticket that describes a fixed defect is a standing
invitation to fix it twice.
