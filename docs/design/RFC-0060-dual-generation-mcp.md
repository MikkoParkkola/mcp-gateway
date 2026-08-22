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

## Unknowns, each with a fail-fast (§P1)

An unknown without a scheduled check is a defect. Five; one resolved, four outstanding:

| # | Question | The check | Blocks |
|---|---|---|---|
| **U1** | What revisions do the clients we actually serve speak? | Log `io.modelcontextprotocol/protocolVersion` (new) and `initialize.params.protocolVersion` (old) at the gateway for one week; count by client. | Decision 2. Do not freeze the window on a guess. |
| **U2** | Does hebb's `-32016` session patch survive statelessness, or was it always a workaround for a protocol wart now deleted? | Read the patch, then run hebb's suite against a stateless transport with the patch reverted. | Whether hebb migrates or first de-forks. |
| ~~U3~~ | ~~Does warm-start exist for protocol or availability reasons?~~ | **RESOLVED 2026-08-22** — see below | ~~Whether `server/discover` retires it~~ |
| ~~U4~~ | ~~Does `rmcp` 3.x support more than one generation?~~ | **RESOLVED 2026-08-22** — see below | ~~Decisions 1 and 3~~ |
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

1. Resolve U1, U2, U3, U5. Nothing else starts. U5 first — it decides whether the gateway is in scope for convergence at all.
2. `server/discover` on every surface — additive, no breakage, immediate compatibility benefit.
3. Shared negotiation crate; gateway first as the reference consumer.
4. Per-surface adoption behind a flag, legacy mode default until U1's telemetry says otherwise.
5. Capability adoption (`CacheableResult`, deterministic ordering, OTel `_meta`, Tasks) — separate work, separate review.

## What this design does not answer

MRTR replaces server-initiated requests, which means every elicitation path is a rewrite rather than a port, and this RFC does not describe that rewrite. Whether the gateway can proxy MRTR at all — a client retrying an original request through a stateless proxy, with `requestState` correlation the proxy must not lose — is unexamined and may be the hardest single problem in the migration.
