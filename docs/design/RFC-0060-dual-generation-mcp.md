# RFC-0060 — Dual-generation MCP support (2026-07-28 + compatibility window)

**Status**: DRAFT, unreviewed. Design only — no code exists and none should until this is reviewed.
**Date**: 2026-08-22
**Scope owner**: mcp-gateway (anchor), applies portfolio-wide.

## §P0 SCOPE — declared before review

**FOR**: every MCP server and client this portfolio ships speaks protocol revision **2026-07-28** natively and completely, while continuing to interoperate with peers that only speak **2025-11-25** and **2025-06-18**.

**OUT** (labelled, not dropped):
- Rewriting any product's feature set to exploit new capabilities. Capability adoption is separate work, tracked separately.
- 2025-03-26 and 2024-11-05. See the compatibility-window decision below.
- Any MCP client we consume but do not ship.
- The Skills-over-MCP and MCP Apps extensions. Not yet stable specifications.

## The problem is not the protocol change

**We do not have one MCP implementation. We have three, at five different versions** (V, inspected 2026-08-22):

| Surface | Implementation | Pinned | Current upstream |
|---|---|---|---|
| **mcp-gateway** | hand-rolled on axum + tower, no SDK | — | — |
| **hebb** | `rust-mcp-sdk` 0.9 — a **third-party** SDK, **vendored and patched** | 0.9 | not the official SDK |
| **throttla** | `rmcp` (official) | 1.5 | **3.1.4** |
| **fulcrum** | `rmcp` | 0.1 | **3.1.4** |
| **botnaut-client, pithy** | `rmcp`, workspace-inherited | unpinned here | **3.1.4** |

Supporting two protocol generations costs **three implementations of the same negotiation logic**, not one. That is the actual decision this RFC exists to make, and it must be made before any migration begins.

**hebb's position is the sharpest.** Its SDK is a vendored fork carrying a patch described in-tree as *"auto-reconnect patch for -32016 session resilience"* (MIK-5232). **The patch exists to make sessions survive; the new revision deletes sessions.** That patch is either obsolete or it is load-bearing for a reason unrelated to the protocol, and nobody currently knows which.

## Decision 1 — converge on one implementation, or accept 3x

Three options. **Recommendation was B; U4 resolved it to C.** The original reasoning and why it was wrong are kept below, because a design that hides its reversals teaches nothing.

| | Approach | Cost | Consequence |
|---|---|---|---|
| **A** | Each surface migrates independently | 3 implementations of version negotiation, forever | Cheapest first step, most expensive third year. Divergence is guaranteed — it already happened. |
| **B** | **One shared negotiation crate**, consumed by all Rust surfaces; SDKs sit beneath it | One implementation, one test suite; each surface adopts on its own schedule | The gateway is hand-rolled anyway, so the crate has a natural first home. hebb's fork is the hard case and forces the vendoring question to be answered. |
| **C** | **Everything onto official `rmcp` 3.x**, delete the hand-rolled and vendored paths | Largest single migration | **CHOSEN.** rmcp already models all five revisions; the migration buys dual-generation support rather than building it. |

**Why B was wrong.** It assumed the SDK could not dual-speak, so the negotiation logic had to live somewhere we controlled. U4 shows rmcp models every revision we care about, including the two-generation dispatch that is the entire difficulty. Building a shared crate would mean maintaining a worse copy of a solved problem.

**The gateway remains the open question**, and it is a genuine one: rmcp is built for *servers*, and the gateway is a *proxy* that must forward a request whose protocol generation it did not choose. Whether rmcp's model types can be used for pass-through routing without paying a full deserialise-reserialise on every call is **U5**, below — and if the answer is no, the gateway alone stays hand-rolled while everything else converges.

## Decision 2 — the compatibility window

**Support 2026-07-28, 2025-11-25 and 2025-06-18. Drop everything older.**

Rationale: 2025-06-18 and 2025-11-25 are the two revisions currently in wide client use; 2025-03-26 and 2024-11-05 predate Streamable HTTP's stabilisation and their transport (HTTP+SSE) is now formally Deprecated in the spec itself. Carrying them means carrying a transport the specification has scheduled for removal.

**This is a decision, not a fact — it needs the unknown below resolved before it is frozen.**

### U1 measurement (MIK-7218) — instrumentation prepared 2026-09-04

Instrumentation in `src/protocol_revision_telemetry.rs` counts parsed inbound
requests, the only comparable unit because protocol-level sessions do not exist
in 2026-07-28. Attribution comes from three sources:

- modern per-request `_meta`;
- the legacy HTTP `MCP-Protocol-Version` header; or
- bounded, normalized attribution learned at `initialize` for legacy stdio
  follow-ups.

Client, revision, and transport labels have fixed families. A missing revision
lands in a separate unattributed series. `tools/list` uses fixed counters for
the real filter set and the `cacheScope` the decision table would emit. Raw
client names never become labels; only hashes for up to 4,096 legacy session IDs
are retained.

Use one-week counter increases, reduced to scalars, for attribution:

```promql
sum(increase(mcp_protocol_revision_observations_total[1w]))
/
(
  sum(increase(mcp_protocol_revision_observations_total[1w]))
  + sum(increase(mcp_protocol_revision_unattributed_observations_total[1w]))
)
```

The pre-registered 2% decision is evaluated only after seven elapsed days and
the 80% attribution floor. For each revision, every unattributed observation is
added to its count before testing the threshold. This conservative upper bound
prevents uncertainty from making a revision look safe to remove. Revisions with
zero observations are still evaluated from the gateway's explicit
`SUPPORTED_VERSIONS` table.

**Production window: not started.** Record these fields after deployment:

- start timestamp and the timestamp seven full days later;
- Prometheus counter increases over that exact interval; and
- process restarts copied from deployment events.

No distribution can be claimed until the result comment contains that live
evidence.

**Pre-registered 2% rule: not applied.** The stop criterion forbids narrowing
on partial data. Decision 2 stays unfrozen. No revision is retired.

## Unknowns, each with a fail-fast (§P1)

An unknown without a scheduled check is a defect. Five; one resolved, four outstanding:

| # | Question | The check | Blocks |
|---|---|---|---|
| **U1** | What revisions do the clients we actually serve speak? | Log `io.modelcontextprotocol/protocolVersion` (new) and `initialize.params.protocolVersion` (old) at the gateway for one week; count by client. | Decision 2. Do not freeze the window on a guess. |
| **U2** | Does hebb's `-32016` session patch survive statelessness, or was it always a workaround for a protocol wart now deleted? | Read the patch, then run hebb's suite against a stateless transport with the patch reverted. | Whether hebb migrates or first de-forks. |
| ~~U3~~ | ~~Does warm-start exist for protocol or availability reasons?~~ | **RESOLVED 2026-08-22** — see below | ~~Whether `server/discover` retires it~~ |
| ~~U4~~ | ~~Does `rmcp` 3.x support more than one generation?~~ | **RESOLVED 2026-08-22** — see below | ~~Decisions 1 and 3~~ |
| **U6** | Does rmcp's *wire behaviour* match its type surface across all three revisions? U4 concluded from an enum and module names, not from bytes on the wire. | Three-revision conformance spike: client, server, transport, discovery, MRTR, caching, removed-session behaviour. | Whether U4's resolution holds. Raised by adversarial review 2026-08-22. |
| **U7** | What else is keyed by session besides hebb's patch and the list caches — auth, subscriptions, progress, cancellation, backend affinity? | Inventory every session-keyed behaviour across all six surfaces; name each replacement. | Everything. Removing sessions without this is the largest risk in the design. |
| **U5** | Can rmcp's model types carry a **proxy** pass-through, or do they force a full deserialise-reserialise per hop? | Prototype one gateway route on rmcp 3.1.4; measure added latency and allocations against the current hand-rolled path. | Whether the gateway converges with everything else or stays hand-rolled alone. **Now the load-bearing unknown.** |

### U3 — RESOLVED: `server/discover` does NOT retire warm-start

`src/gateway/server/warmstart.rs` states its own rationale, and it is availability, not protocol:

> *"a sibling daemon launched in the same second as the gateway that has not finished binding its port"* … *"nothing else in the gateway ever revisits an empty tool cache, and a backend with an empty cache is invisible to `gateway_search` for the whole process lifetime."*

Two phases, fast then slow, retrying until a backend's tools are cached. **The problem is a backend that is not listening yet, or comes back minutes later.** A handshake-free discovery RPC does not make an unbound port answer.

**What `server/discover` actually buys**: each retry attempt gets cheaper and needs no session setup, and a cold backend can be probed for versions and capabilities in one request instead of a handshake sequence. The retry *schedule* stays. **This is an optimisation inside warm-start, not a replacement for it** — and the earlier framing of it as "retiring 151 references" was wrong.

### U4 — RESOLVED, and it inverts Decision 1

`rmcp` 3.1.4 models **all five revisions** as a first-class enum — `V_2024_11_05`, `V_2025_03_26`, `V_2025_06_18`, `V_2025_11_25`, `V_2026_07_28` — parsed from the wire string, with unknown versions preserved rather than rejected (`ProtocolVersion(Cow::Owned(s))`). `SUPPORTED_PROTOCOL_VERSIONS` is referenced from the server handler, the router, the service layer and the Streamable HTTP tower transport. The new surfaces each have their own module: `mrtr.rs`, `request_state.rs`, `task.rs`, `meta.rs`, `extension.rs`.

**The official SDK already solves the problem this RFC was written to solve.** Every hour spent building a shared negotiation crate is an hour spent reimplementing `rmcp::model::ProtocolVersion`, worse and alone.

## Decision 3 — how a server tells the generations apart

Sketch. rmcp implements this dispatch already; what follows is the behaviour we must verify it produces, not something to build:

- **Old client**: sends `initialize` as its first call. That method no longer exists in 2026-07-28, so its presence *is* the version signal. Reply with the old handshake and serve that connection in legacy mode.
- **New client**: sends any method with `_meta["io.modelcontextprotocol/protocolVersion"]`. No handshake. Dispatch per request.
- **Either**: may call `server/discover` first. We **MUST** implement it, and it is the only negotiation surface that works for both — the spec explicitly sanctions it as *"a backward-compatibility probe on STDIO."*

**`server/discover` is therefore the migration's keystone, not a feature.** Implement it first, everywhere, before touching anything else. It is additive, breaks no existing client, and gives every peer a way to discover what we speak.

### `server/discover` does not spend the Meta-MCP surface budget

This repository's own locked decision keeps the Meta-MCP surface compact — 14 to 16 tools — because the context-token saving *is* the value proposition, and its anti-pattern list names "bloating the Meta-MCP surface" first.

**`server/discover` is not a tool.** It is a protocol RPC, alongside `tools/list` and `resources/read`, and it is never enumerated to the model. Implementing it costs zero tokens on the surface budget. Stating this here so the compact-surface rule is not later cited as a reason to skip a MUST.

The reverse deserves a flag too: **the `tools/list` cache fields make the compact-surface argument stronger, not weaker.** `ttlMs` lets a client stop re-listing, and deterministic ordering raises prompt-cache hit rates on whatever it does list — both of which cut exactly the overhead the surface budget exists to protect.

### The cache hazard

Legacy mode must keep per-connection list responses. Modern mode requires that `tools/list` **not** vary per connection, and now carries `ttlMs` and `cacheScope`. **Serving both from one code path risks emitting a `cacheScope: "public"` response computed under session-scoped state** — a correctness bug that presents as a cache poisoning across tenants. **Verify rmcp makes this unrepresentable** before trusting it — a type that prevents attaching a `CacheableResult` to a session-scoped computation, not a convention. If it does not, that guard is ours to add and belongs in the migration, not after it.

## Sequencing

Revised 2026-08-22 after adversarial review found three contradictions in the previous ordering.

1. **Resolve U1, U2, U5.** Nothing else starts. U5 first — it decides whether the gateway is in scope for convergence at all. (U3 already resolved; U4 resolved but see U6 below.)
2. **Session-state inventory (U7).** Before removing anything, enumerate every behaviour currently keyed by connection or `Mcp-Session-Id` across all six surfaces — authentication, subscriptions, progress, cancellation, backend affinity — and name each one's stateless replacement. The previous version of this design removed sessions having inventoried only hebb's reconnect patch and the list caches, which is not an inventory.
3. **`server/discover` on every surface** — additive, no breakage, immediate compatibility benefit.
4. **`CacheableResult` and deterministic ordering, in the baseline — not deferred.** `ttlMs` and `cacheScope` are **required** by the specification on five endpoints. Deferring them to "capability adoption" while claiming complete 2026-07-28 support is a contradiction: a surface that omits them is non-compliant, not merely unoptimised. Their safe computation (step 5) ships with them.
5. **Split legacy and modern list-result construction.** Not one path with a flag. Each cache scope is permitted only where the computation is provably invariant within that scope.
6. **Retry and idempotency rules for side-effecting requests.** SSE resumability is gone, so a broken stream forces the client to re-issue with a new request ID. Without deduplication, that duplicates irreversible tool actions. Define idempotency keys, or route side-effecting operations through Tasks, before enabling 2026-07-28 anywhere.
7. **MRTR continuation design** — see the open problem below. Blocks the gateway specifically.
8. **Per-surface adoption behind a flag**, legacy mode default until U1's telemetry says otherwise.
9. **Remaining capability adoption** (OTel `_meta`, Tasks) — separate work, separate review. This step is genuinely optional; step 4 was not.

## Adversarial review, 2026-08-22 — both vendors SHIP-WITH-FIXES

Reviewed before any code existed, which is the only moment this costs a paragraph instead of a branch. GPT returned 7 findings (2 CRITICAL); grok returned 7 findings (2 CRITICAL) and read the gateway source rather than the write-up. **The design was materially wrong in five places.** Confirmed findings below; the sequencing above is already rewritten.

### CONFIRMED AT SOURCE — the proxy drops MRTR fields

`extract_tools_call_params` returns exactly `(name, arguments)`; its own doc comment says *"Extract the `tools/call` parameters (tool name and arguments)"* and returns `("", {})` when fields are absent (`src/gateway/router/helpers.rs:178`, read 2026-08-22). **An MRTR retry carries `inputResponses` and `requestState` as siblings of `name` and `arguments`. The gateway would silently drop both**, so a 2026 client's elicitation never completes and `gateway_kill_server` runs without the human confirmation `src/gateway/destructive_confirmation.rs` exists to enforce.

This is not a gap in the design. It is a defect the design would have shipped.

### The header contract answers U5 without a prototype

Grok's sharpest point, and it inverts the plan. 2026 Streamable HTTP **requires `Mcp-Method` and `Mcp-Name` on every POST** and rejects disagreement as `HeaderMismatch` (-32020) — SEP-2243, which this RFC filed under "minor changes" and never mentioned again.

**Those headers exist so a gateway can route without parsing the body.** U5 asked whether rmcp's types can carry a proxy pass-through without deserialise-reserialise per hop; the specification already answered it by putting the routing key in the headers. Dispatch from `Mcp-Method`/`Mcp-Name`, keep the JSON body opaque except at the Meta-MCP chokepoint, and the question closes without building anything.

### `tools/list` already varies per connection, five ways

The cache hazard is worse than stated. The gateway's list varies by API-key scope, routing profile, session-promoted tools, Code Mode, and spec-preview query (`src/gateway/meta_mcp/mod.rs:999`, `src/gateway/auth.rs:355`). So the modern requirement that lists not vary per connection has two failure modes, not one: emit `cacheScope: "public"` and leak one tenant's filtered view to another, or drop the filters to comply and **leak the full catalog to restricted keys**. The mitigation must be a gateway-owned decision table — private unless the list is the unfiltered meta-tool skeleton — with `ResponseCache` keyed on authorization context.

### Existing idempotency will break MRTR

`src/idempotency.rs:10` keys on `server:tool:hash(arguments)`. An `InputRequired` result would be cached as a completed replayable success, so an MRTR tool either never finishes or a later caller replays another principal's `requestState`. **`InputRequired` is neither cacheable nor an idempotent completion**, and retry keys must include `inputResponses` and `requestState`.

### U3 was incomplete

Warm-start and health probing depend on `initialize` and `ping` (`src/backend/lifecycle.rs:369`, `:1034`) — both removed in 2026. The earlier correction established that the retry *schedule* survives; it did not say how a 2026 backend gets probed at all. It does not, today. `server/discover` replaces the probe, with `initialize` used only where discover reports a pre-2026 peer.

### Session-keyed product features, named

Beyond hebb's patch and the list caches: SSE multiplexer, firewall budgets, session sandbox, projection stickiness, initialize-time profiles and last-event-id resume (`src/gateway/router/handlers.rs:160`, `src/session_sandbox.rs`). Per-request ephemeral sessions reset sandbox and firewall budgets silently. **Rebind to the ADR-008 `Principal`** and treat protocol sessions as a 2025-only transport adapter.

## What this design still does not answer

Mixed-generation MRTR: a 2026 client eliciting through this gateway against a 2025 backend that holds the original RPC open. That cannot be stateless on the backend side, and grok proposes an HMAC-wrapped, `requestState`-keyed in-flight table. **No contract is written yet.** Both reviewers converged on this as the blocking gap, and grok's recommended fail-fast is the cheapest available: run one `gateway_invoke` from a 2026 client against a 2025 backend that elicits, then the reverse pair, before spending anything on rmcp latency measurement.
