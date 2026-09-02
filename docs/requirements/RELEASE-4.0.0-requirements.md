# mcp-gateway 4.0.0 — Requirements

**Status**: DRAFT for review
**Date**: 2026-08-29
**Baseline**: 3.5.0 (released 2026-08-28)
**Design**: `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md` — decisions, rationale and the
ticket manifest live there and are **not** restated here.
**Portfolio strategy**: `docs/design/RFC-0060-dual-generation-mcp.md`

This document states **what must be true** for 4.0.0 to ship. It does not say how. Where a
requirement and the design disagree, the requirement is the one that was agreed and the design is
wrong until re-reviewed.

Acceptance-criterion identifiers follow the house convention `<TICKET>.<COMPONENT>.<N>` so closure
comments remain checkable by `hooks/lib/ac_evidence.py`. Every requirement carries a **source** —
either a normative statement in the MCP 2026-07-28 specification, or a defect verified in this
repository. **A requirement with no source is not a requirement; it is a preference, and it is not
in this document.**

---

## 1. Why this release exists

MCP revision **2026-07-28** removes the `initialize` handshake, protocol sessions, `ping`,
server-initiated requests and stream resumability, and adds `server/discover`, per-request metadata,
multi-round-trip requests, cacheability fields and required routing headers. mcp-gateway speaks
**2025-11-25** today.

The revision was written for intermediaries. Its transport binding says so directly — headers exist
*"so that intermediaries (load balancers, gateways, observability tooling) can route and inspect
requests without parsing the body."* A gateway is the intermediary in that sentence.

**The release therefore has two jobs, and the second is the one that matters:**

1. Speak the revision completely, in both roles — as a server to clients, as a client to backends.
2. Be the **bridge between generations**, so a client that has moved can reach a backend that has
   not. Every backend in the wild is pre-2026 today; most will be for a year. Nothing but a gateway
   can close that gap, and closing it is a capability rather than a compatibility burden.

### What "done" means

4.0.0 is done when a client speaking 2026-07-28 can reach every backend this gateway serves —
whichever revision that backend speaks — without the client knowing which, and without any control
that protected a 2025 caller having silently stopped protecting a 2026 one.

That second clause is half the work. Three security controls in this repository are keyed on a
session that this revision deletes, and each **fails silently** rather than loudly.

---

## 2. Stakeholders and outcomes

| Stakeholder | Outcome they get | How they notice |
|---|---|---|
| Operator running a gateway | Upgrades without editing config; existing clients keep working | No action required on upgrade; startup log states the era served |
| A client that has moved to 2026-07-28 | Reaches every backend, including pre-2026 ones, with elicitation and confirmation intact | Tool calls succeed; a destructive call still asks |
| A client still on 2025-11-25 / 2025-06-18 | Nothing changes | No observable difference from 3.5.0 |
| Backend author on any revision | Reachable without adapting to the gateway | The gateway probes and adapts; the backend does not |
| Multi-tenant operator | One tenant's tool list, cache entry or continuation cannot reach another | Cache and continuation tests, and the audit trail |
| The project | A defensible claim of complete 2026-07-28 support, and four long-open tickets closed by protocol rather than by bespoke code | The conformance matrix |

---

## 3. Functional requirements

Verification codes: **T** automated test · **M** measurement · **I** inspection of source ·
**D** demonstration against a live peer.

### 3.1 Discovery and version negotiation

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7217.DISCOVER.1a | The gateway MUST implement `server/discover` on every transport over which it **serves MCP** — today stdio and Streamable HTTP. Its WebSocket listener echoes frames and serves no MCP (`src/gateway/ws_listener.rs:6,27,70`, verified 2026-08-29), so it is out of scope until it does. | Spec: *"servers MUST implement this RPC"* | T, D |
| MIK-7217.DISCOVER.1b | The discovery document MUST advertise supported protocol versions, capabilities and identity. | Spec: *"servers MUST implement this RPC"* | T, D |
| MIK-7217.DISCOVER.2 | `server/discover` MUST be answerable without any prior handshake, session or credential exchange beyond the transport's own authentication. | Spec: usable as a pre-request probe | T |
| MIK-7217.DISCOVER.3 | Adding discovery MUST NOT alter the behaviour of the existing handshake path. Given a 2025 client, When it sends `initialize`, Then its result is byte-identical to 3.5.0's. | Ticket stop-the-line: additive or the implementation is wrong | T |
| MIK-7217.DISCOVER.4a | As a client, the gateway MUST determine each backend's era by probing `server/discover` first. | Spec compatibility matrix: *"the probe returns a non-modern error or times out"* | T, D |
| MIK-7217.DISCOVER.4b | As a client, the gateway MUST treat **any** non-modern probe outcome — arbitrary error, silence, timeout — as legacy, falling back to `initialize`. Only a recognised modern error proves a modern peer. | Spec compatibility matrix: *"the probe returns a non-modern error or times out"* | T, D |
| MIK-7217.DISCOVER.5a | Era determination MUST be cached per backend for the lifetime of the process. | Spec: *"Clients SHOULD cache the result for the lifetime of the server process"* | T |
| MIK-7217.DISCOVER.5b | A cached era determination MUST be re-probed when the cached assumption fails. | Spec: *"Clients SHOULD cache the result for the lifetime of the server process"* | T |
| MIK-7217.DISCOVER.6 | Backend warm-start MUST continue to retry on its existing schedule. Discovery makes each probe cheaper; it does not make an unbound port answer. | `src/gateway/server/warmstart.rs`; RFC-0060 U3 | T |
| MIK-7217.DISCOVER.7a | The advertised version list MUST contain only revisions the specification defines. | Verified 2026-08-29: introduced by `e12431a0` (2026-01-26), whose own message claims *"Support 2024-11-05 (latest) and 2024-10-07 versions"*. The specification has never defined `2024-10-07`. | T, I |
| MIK-7217.DISCOVER.7b | `2024-10-07` MUST be removed from `SUPPORTED_VERSIONS`, its tests and `docs/ARCHITECTURE.md`. | Verified 2026-08-29: introduced by `e12431a0` (2026-01-26), whose own message claims *"Support 2024-11-05 (latest) and 2024-10-07 versions"*. The specification has never defined `2024-10-07`. | T, I |

### 3.2 Stateless request handling

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7215.STATELESS.1a | The gateway MUST accept a request carrying `io.modelcontextprotocol/protocolVersion` in `_meta` with no prior handshake. | Spec §2 major change | T |
| MIK-7215.STATELESS.1b | The gateway MUST dispatch on that `_meta` protocol version per request. | Spec §2 major change | T |
| MIK-7215.STATELESS.2 | The gateway MUST include `io.modelcontextprotocol/serverInfo` in each result's `_meta`. | Spec: servers SHOULD identify themselves — adopted as MUST for this release, since a gateway that will not name itself is unusable to an operator debugging a chain | T |
| MIK-7215.STATELESS.3a | The gateway MUST NOT emit `Mcp-Session-Id` on the modern path. | Spec §1 major change | T |
| MIK-7215.STATELESS.3b | The gateway MUST continue to emit `Mcp-Session-Id` on the legacy path. | Spec §1 major change | T |
| MIK-7215.STATELESS.4a | Version mismatch MUST return `UnsupportedProtocolVersionError` listing supported versions. | Spec, Streamable HTTP binding | T |
| MIK-7215.STATELESS.4b | That version-mismatch response MUST carry HTTP 400. | Spec, Streamable HTTP binding | T |
| MIK-7215.STATELESS.5a | An unimplemented method MUST return JSON-RPC `-32601`. | Spec, Streamable HTTP binding | T |
| MIK-7215.STATELESS.5b | That response MUST carry HTTP 404, distinguishable from a legacy transport's bare 404. | Spec, Streamable HTTP binding | T |
| MIK-7215.STATELESS.6a | On the modern path the gateway MUST refuse `ping`, `logging/setLevel` and `notifications/roots/list_changed`. | Spec §5 major change | T |
| MIK-7215.STATELESS.6b | The gateway MUST continue to serve `ping`, `logging/setLevel` and `notifications/roots/list_changed` on the legacy path. | Spec §5 major change | T |
| MIK-7215.STATELESS.7 | The gateway MUST NOT emit `notifications/message` for a request that did not carry `io.modelcontextprotocol/logLevel` in `_meta`. | Spec §5: *"servers MUST NOT emit"* | T |
| MIK-7215.STATELESS.8a | A dual-era server MUST serve both eras on one endpoint, with `initialize` selecting the legacy era. | Spec: *"A dual-era server MAY serve both eras concurrently"* — adopted as MUST because the alternative is a second port operators must know about | T, D |
| MIK-7215.STATELESS.8b | A dual-era server MUST serve both eras on one endpoint, with per-request `_meta` selecting the modern era. | Spec: *"A dual-era server MAY serve both eras concurrently"* — adopted as MUST because the alternative is a second port operators must know about | T, D |
| MIK-7215.STATELESS.9a | `io.modelcontextprotocol/protocolVersion` is **required** in a modern request's `_meta`; a request missing it is malformed and MUST be rejected with JSON-RPC `-32602`. | Spec, `_meta` per-request fields: *"A request missing any required field is malformed; the server MUST reject it with … `-32602` … the response status MUST be `400 Bad Request`"* | T |
| MIK-7215.STATELESS.9b | `io.modelcontextprotocol/clientCapabilities` is **required** in a modern request's `_meta`; a request missing it is malformed and MUST be rejected with JSON-RPC `-32602`. | Spec, `_meta` per-request fields: *"A request missing any required field is malformed; the server MUST reject it with … `-32602` … the response status MUST be `400 Bad Request`"* | T |
| MIK-7215.STATELESS.9c | On the HTTP path that rejection MUST carry HTTP `400 Bad Request`. | Spec, `_meta` per-request fields: *"A request missing any required field is malformed; the server MUST reject it with … `-32602` … the response status MUST be `400 Bad Request`"* | T |
| MIK-7215.STATELESS.10a | The gateway MUST NOT rely on a capability the client did not declare. | Spec: *"A server MUST NOT rely on capabilities the client has not declared"* | T |
| MIK-7215.STATELESS.10b | Where processing needs an undeclared capability, the gateway MUST return `MissingRequiredClientCapabilityError` (`-32021`) whose `data.requiredCapabilities` lists what was missing. | Spec: *"A server MUST NOT rely on capabilities the client has not declared"* | T |
| MIK-7215.STATELESS.10c | That missing-capability response MUST carry HTTP 400. | Spec: *"A server MUST NOT rely on capabilities the client has not declared"* | T |

### 3.3 Headers

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7214.HEADER.1a | Every modern POST MUST carry `MCP-Protocol-Version`. | Spec, Protocol Version Header | T |
| MIK-7214.HEADER.1b | The `MCP-Protocol-Version` value MUST equal `_meta.protocolVersion` in the body. | Spec, Protocol Version Header | T |
| MIK-7214.HEADER.2a | `Mcp-Method` MUST be required on every modern request. | Spec, Standard Request Headers table | T |
| MIK-7214.HEADER.2b | `Mcp-Name` MUST be required for `tools/call`, `resources/read` and `prompts/get`. | Spec, Standard Request Headers table | T |
| MIK-7214.HEADER.2c | `Mcp-Name` MUST be required **for no other method**. | Spec, Standard Request Headers table | T |
| MIK-7214.HEADER.3a | Where a header and its body field disagree, the gateway MUST reject with `HeaderMismatch` (-32020). | Spec, Server Validation | T |
| MIK-7214.HEADER.3b | That header-mismatch rejection MUST carry HTTP 400. | Spec, Server Validation | T |
| MIK-7214.HEADER.4a | A `Mcp-Name` value not representable in ASCII MUST be emitted per the Base64 sentinel format. | Spec, Value Encoding | T |
| MIK-7214.HEADER.4b | An inbound `Mcp-Name` in the Base64 sentinel format MUST be decoded per that format. | Spec, Value Encoding | T |
| MIK-7214.HEADER.5 | Where a backend tool's `inputSchema` annotates a property with `x-mcp-header`, the gateway MUST mirror that argument's value into an `Mcp-Param-{name}` header on the outbound Streamable HTTP request. The annotation is a server-side schema declaration, not a caller-supplied parameter. | Spec `server/tools.mdx:334-344` | T |
| MIK-7214.HEADER.7a | The gateway MUST reject an `x-mcp-header` value that is empty. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.7b | The gateway MUST reject an `x-mcp-header` value that is not HTTP field-name token syntax (RFC 9110 §5.1). | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.7c | The gateway MUST reject an `x-mcp-header` value containing control characters, including CR or LF. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.7d | The gateway MUST reject `x-mcp-header` values that are not case-insensitively unique across the `inputSchema`. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.7e | The gateway MUST reject `x-mcp-header` on a property that is not `integer`, `string` or `boolean` — `number` never qualifies. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.7f | The gateway MUST reject an `x-mcp-header` integer outside the IEEE-754 safe range. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.8 | A tool violating any HEADER.7 constraint MUST be excluded from `tools/list` and SHOULD be logged as a warning. Exclusion changes the surfaced tool set, so it shares the tool-metadata path with the destructive-annotation gate. | Spec `server/tools.mdx:346-359` | T |
| MIK-7214.HEADER.9a | Outbound requests MUST carry the modern `_meta` envelope and the standard headers only where the peer negotiated a modern protocol era; emitting them to a legacy-negotiated peer is a regression. | Spec, Protocol Version Header; derived from HEADER.1 applied to the client role | T |
| MIK-7214.HEADER.9b | Outbound header values MUST be derived from the negotiated envelope, not from the legacy handshake version. | Spec, Protocol Version Header; derived from HEADER.1 applied to the client role | T |
| MIK-7214.HEADER.6 | The gateway MUST validate header against body **before** authorizing or executing any request whose body it processes. Routing on an unvalidated header is permitted only where the gateway relays without acting. | Spec, Server Validation, and its stated load-balancer-versus-server rationale | T, I |

### 3.4 Results and errors

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7272.RESULT.1 | Every modern result MUST carry `resultType`, `"complete"` for ordinary results. | Spec §8 | T |
| MIK-7272.RESULT.2 | As a client, the gateway MUST treat a result from an earlier-protocol server that omits `resultType` as `"complete"`. | Spec §8: *"Clients MUST treat…"* | T |
| MIK-7272.ERROR.1 | Error codes MUST be renumbered: `HeaderMismatch` -32001→-32020, `MissingRequiredClientCapability` -32003→-32021, `UnsupportedProtocolVersion` -32004→-32022. | Spec §12 minor | T |
| MIK-7272.ERROR.2 | Resource-not-found MUST return `-32602`, not `-32002`. | Spec §6 minor | T |

### 3.5 Cacheability

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7213.CACHE.1a | `ttlMs` MUST be returned on `tools/list`, `prompts/list`, `resources/list`, `resources/read` and `resources/templates/list`. | Spec §5 minor, SEP-2549 | T |
| MIK-7213.CACHE.1b | `cacheScope` MUST be returned on `tools/list`, `prompts/list`, `resources/list`, `resources/read` and `resources/templates/list`. | Spec §5 minor, SEP-2549 | T |
| MIK-7213.CACHE.2 | A list response whose content depends on **any** authorization-derived input MUST carry `cacheScope: "private"`. Given two callers with different credentials, When each lists tools, Then neither may be served the other's cached response. | Spec: private = *"MUST NOT be shared across authorization contexts"* | T |
| MIK-7213.CACHE.3a | `cacheScope: "public"` MUST be emitted only where the response is provably invariant across all authorization contexts. | Ticket stop-the-line | T, I |
| MIK-7213.CACHE.3b | A decision table naming which endpoints may ever be public MUST exist and be referenced from the code that emits the field. | Ticket stop-the-line | T, I |
| MIK-7213.CACHE.4a | Any shared cache the gateway keeps MUST be keyed on every request-derived input that varies the response — authorization binding, routing profile, Code Mode, preview query, cursor, backend, protocol revision. A response varying on an unkeyed input MUST NOT be cached. | Defect class confirmed in review 2026-08-22 | T, I |
| MIK-7213.CACHE.4b | Any shared cache the gateway keeps MUST carry a policy epoch that invalidates it on a grant or profile change. | Defect class confirmed in review 2026-08-22 | T, I |
| MIK-7272.ORDER.1 | `tools/list` MUST return tools in a deterministic order across requests when the underlying set has not changed. | Spec §3 minor | T |
| MIK-7272.ORDER.2 | The tool set MUST NOT vary per connection, nor as a side effect of other requests on the connection. It MAY vary by the authorization presented on the request. | Spec, server/tools | T |
| MIK-7272.ORDER.3 | Every existing list filter MUST be classified as authorization-derived (retained) or connection-derived (moved to per-request input, or disabled in modern mode). The session-keyed routing profile and the `spec-preview` promotion list are known connection-derived cases. | Verified at source 2026-08-29 — see RFC-0061 correction table | T, I |

### 3.6 Multi-round-trip requests, and the bridge

This is the release's hardest requirement and the one no other portfolio surface faces.

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7212.MRTR.1a | The gateway MUST carry `inputResponses` on a `tools/call` retry. They are currently dropped: `extract_tools_call_params` returns only `(name, arguments)`. | `src/gateway/router/helpers.rs:178`, confirmed at source | T |
| MIK-7212.MRTR.1b | The gateway MUST carry `requestState` on a `tools/call` retry. It is currently dropped: `extract_tools_call_params` returns only `(name, arguments)`. | `src/gateway/router/helpers.rs:178`, confirmed at source | T |
| MIK-7212.MRTR.2a | The gateway MUST NOT forward a backend's `requestState` to a client verbatim. | Spec: requestState is *"meaningful only to the server"*; the gateway is a server to its client | T, I |
| MIK-7212.MRTR.2b | The gateway MUST mint its own integrity-protected value carrying the backend's opaque state inside. | Spec: requestState is *"meaningful only to the server"*; the gateway is a server to its client | T, I |
| MIK-7212.MRTR.3a | A `requestState` presented by a client MUST be treated as attacker-controlled and verified before use. | Spec: *"servers MUST treat requestState as attacker-controlled input"* | T |
| MIK-7212.MRTR.3b | A `requestState` presented by a client MUST be rejected when that verification fails. | Spec: *"servers MUST treat requestState as attacker-controlled input"* | T |
| MIK-7212.MRTR.4a | A continuation MUST be bound to the principal, and MUST NOT be usable by a different caller. | Spec: *"They MUST NOT be used for any other request"* | T |
| MIK-7212.MRTR.4b | A continuation MUST be bound to the original request, and MUST NOT be usable for a different request. | Spec: *"They MUST NOT be used for any other request"* | T |
| MIK-7212.MRTR.5a | A continuation MUST be single-use. | Spec: *"MUST enforce that invariant server-side"* | T |
| MIK-7212.MRTR.5b | A continuation MUST expire. | Spec: *"MUST enforce that invariant server-side"* | T |
| MIK-7212.MRTR.5c | Single-use enforcement MUST be atomic. Integrity protection alone does not satisfy this. | Spec: *"MUST enforce that invariant server-side"* | T |
| MIK-7212.MRTR.5d | Single-use enforcement MUST hold across every replica that can receive the retry. | Spec: *"MUST enforce that invariant server-side"* | T |
| MIK-7212.MRTR.6 | Given a modern client and a **legacy** backend holding an open request, When the client retries with its inputs, Then the retry MUST reach the replica holding that exchange, or fail explicitly. It MUST NOT silently start a second exchange. | Multi-replica deployment is the default behind a load balancer | T, D |
| MIK-7212.MRTR.7a | Given a **modern backend** returning `InputRequiredResult` and a **legacy client**, When the gateway bridges, Then it MUST issue the equivalent server-initiated request on the client's connection. | The likelier direction in practice: backends move first | T, D |
| MIK-7212.MRTR.7b | Given a **modern backend** returning `InputRequiredResult` and a **legacy client**, When the gateway bridges, Then it MUST retry the backend with the responses collected from that client. | The likelier direction in practice: backends move first | T, D |
| MIK-7212.MRTR.8a | State held for an in-flight exchange MUST be bounded in count. | Spec: *"Servers MUST NOT assume that clients will fulfill…"* | T, M |
| MIK-7212.MRTR.8b | State held for an in-flight exchange MUST be bounded in lifetime, and MUST be reclaimed when a client abandons a continuation — the expected case, since the spec permits a client never to retry. | Spec: *"Servers MUST NOT assume that clients will fulfill…"* | T, M |
| MIK-7212.MRTR.9 | The gateway MUST NOT include an `inputRequest` of a type the client has not declared support for. | Spec: *"Servers MUST NOT send an inputRequests that the client has not declared support for"* | T |
| MIK-7212.MRTR.10a | Idempotency keys MUST include `inputResponses` and `requestState`. | `src/idempotency.rs:10` keys on `server:tool:hash(arguments)` | T |
| MIK-7212.MRTR.10b | An `InputRequired` result MUST NOT be cached as a completed call. | `src/idempotency.rs:10` keys on `server:tool:hash(arguments)` | T |

### 3.7 Controls that must survive the migration

**A control that keeps compiling while its state disappears does not report that it has stopped
working.** Each requirement below therefore demands a *refusal*, not a computation.

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7246.CONFIRM.1 | The destructive-operation confirmation gate MUST refuse when it cannot obtain confirmation. It MUST NOT proceed on a warning. Today it proceeds when elicitation is unsupported **or there is no session** — and after this release there is never a session. | `src/gateway/destructive_confirmation.rs:19-21` | T |
| MIK-7246.CONFIRM.2 | The gate MUST be reachable through the MRTR path, so a modern client can confirm. | Depends on MIK-7212 | T, D |
| MIK-7246.CONFIRM.3 | The governed tool set MUST derive from the `destructiveHint` annotation, not a hardcoded match on `gateway_kill_server`. | Ticket AC MIK.CONF.3 | T |
| MIK-7116.TENANT.1 | The cross-tenant data-minimisation guard MUST key on the authenticated principal, not on a session. | `Mcp-Session-Id` is removed; the ticket's own design says "within one session" | T |
| MIK-7215.CONTROL.1 | Anomaly scoring MUST key on the principal and MUST refuse — not score zero — when no key is available. Today it keys `session_id → last tool`, so under statelessness every request looks like a first request. | `src/security/firewall/anomaly.rs:41-88` | T |
| MIK-7215.CONTROL.2 | Firewall budgets MUST key on the principal over an explicit window. A per-session budget under statelessness is an unlimited budget. | `src/security/firewall/mod.rs:311-351` | T |
| MIK-7215.CONTROL.3 | The transparency log MUST retain a correlation key across the removal of sessions; the OpenTelemetry trace identifier from `_meta` MUST be used where present. | `src/security/transparency_log.rs:224-240,578` | T |
| MIK-7215.CONTROL.4 | Every behaviour reclaimed by session-disconnect cleanup MUST be re-expressed as an expiry. There is no disconnect in a stateless transport, so nothing registered there fires. | `src/gateway/session_lifecycle.rs:46-54` | T, M |
| MIK-7215.CONTROL.5 | No session-keyed behaviour may be removed before its row in the inventory names a replacement or states that none is needed. | Ticket stop-the-line; inventory in RFC-0061 | I |

### 3.8 Identity

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-6704.IDENT.1 | Authorization MUST derive from the authenticated credential — OIDC subject or API-key digest. `io.modelcontextprotocol/clientInfo` is self-asserted and MUST NOT influence any authorization decision. | Spec says clients *SHOULD identify themselves* — identification, not authentication | T, I |
| MIK-6704.IDENT.2 | `clientInfo` and `clientCapabilities` MUST be carried as diagnostic and negotiation context, labelled untrusted. | Same | I |
| MIK-6704.IDENT.3 | The authenticated end-user identity MUST be propagatable to a backend that requires its own authorization, by token exchange (RFC 8693). **Already built** — `src/identity_propagation/token_exchange.rs` implements it and `src/gateway/server/mod.rs:1053-1061` wires it into production startup as the `TokenExchange` strategy (verified 2026-08-29). The release verifies rather than implements it. | MIK-6704, MIK-6729; ADR-007 | T, D |
| MIK-7252.IDENT.4 | Playbook steps MUST execute under the caller's identity, subject to the same per-client backend scoping as a direct call. They currently run with none. | MIK-7252 | T |
| MIK-6704.IDENT.5 | Where the gateway cannot establish an identity a backend requires, it MUST refuse rather than fall back to a shared credential. | Confused-deputy avoidance | T |

### 3.9 Subscriptions and streams

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7272.SUB.1 | `subscriptions/listen` MUST replace the HTTP GET endpoint and `resources/subscribe`/`unsubscribe` on the modern path, with opt-in by notification type and notifications tagged `io.modelcontextprotocol/subscriptionId`. | Spec §4 major | T |
| MIK-7272.SUB.2 | Request-scoped notifications (`notifications/progress`, `notifications/message`) MUST flow on the response stream of their own request, not on the subscription stream. | Spec §4 | T |
| MIK-7272.SUB.3 | SSE resumability MUST be removed from the modern path: no `Last-Event-ID`, no event ids, no redelivery. | Spec §9 major | T |
| MIK-7272.SUB.4 | Because a broken stream forces re-issue with a new request id, a side-effecting call MUST be protected by an idempotency key or routed through the tasks extension. | Spec §9; irreversible duplication otherwise | T |

### 3.10 Authorization-server requirements of this revision

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7272.OAUTH.1 | As an OAuth client, the gateway MUST validate a present `iss` on the authorization response against the recorded issuer before redeeming the code. | Spec §7 minor, RFC 9207 | T |
| MIK-7272.OAUTH.2 | Dynamic Client Registration MUST send an appropriate `application_type`. | Spec §8 minor | T |
| MIK-7272.OAUTH.3 | Persisted client credentials MUST be keyed by issuer, MUST NOT be reused across issuers, and MUST trigger re-registration when the authorization server changes. | Spec §9 minor | T |

### 3.11 Capabilities the release exploits

| ID | Requirement | Source | Verify |
|---|---|---|---|
| MIK-7272.EXT.1 | The gateway MUST declare its own extensions through the `extensions` field of server capabilities, and MUST honour a client that does not support one by reverting to core behaviour or refusing. | Spec §1 minor; §Extensions | T |
| MIK-7272.OTEL.1 | `traceparent`, `tracestate` and `baggage` MUST be propagated through `_meta` across the gateway hop. | Spec §2 minor, SEP-414 | T |
| MIK-7272.TASK.1 | The tasks extension (`io.modelcontextprotocol/tasks`) MUST be supported for long-running backend calls, with `tasks/get` polling and `tasks/update`. | Spec §6 major | T |
| MIK-7084.SURFACE.1 | `gateway_search` MUST support tiered disclosure and MUST NOT emit ranking telemetry the caller cannot act on. Measured at ~60% of a lean payload, 13 of 16 signals the constant `1.0`. | MIK-7084, measured 2026-07-31 | T, M |
| MIK-6865.SCHEMA.1 | Tool schemas exposed by the gateway MUST avoid the nested-object-in-array shapes that induce key invention in current models, and MUST remain valid under JSON Schema 2020-12 with the revision's `$ref` and composition bounds. | MIK-6865; spec §10 minor | T, M |

---

## 4. Non-functional requirements

### 4.1 Compatibility

| ID | Requirement | Verify |
|---|---|---|
| NFR.COMPAT.1 | 2026-07-28, 2025-11-25 and 2025-06-18 MUST be served. 2025-03-26 and 2024-11-05 MUST NOT be dropped in this release — the telemetry that would justify dropping them has not been collected. | T |
| NFR.COMPAT.2 | A client that worked against 3.5.0 MUST work against 4.0.0 with no configuration change. | T, D |
| NFR.COMPAT.3 | An operator upgrading MUST NOT be required to edit configuration for existing behaviour to continue. | D |
| NFR.COMPAT.4 | Every requirement above MUST be verified in **both** roles — gateway-as-server and gateway-as-client — and on every transport that implements it. A requirement verified in one role is verified at half. Role and transport are two of the conformance matrix's axes (§9 acceptance 2); this row states the obligation and the matrix carries the evidence. | T |

### 4.2 Security

| ID | Requirement | Verify |
|---|---|---|
| NFR.SEC.1 | No control that constrained a caller under 3.5.0 may become inoperative for a modern caller. Each MUST have a test that asserts refusal when its input is absent. | T |
| NFR.SEC.2 | Continuation state MUST be confidential to the gateway: a client MUST NOT be able to read a backend's state from what it echoes. | T |
| NFR.SEC.3 | The continuation envelope MUST be versioned and its key rotatable, retaining verification keys for at least the maximum continuation lifetime. | T |
| NFR.SEC.4 | Deterministic fixtures MUST cover tamper, expiry, replay, wrong principal, wrong original request, key rotation, oversized state and arrival at a replica that does not hold the exchange — each failing closed, and failing for the stated reason. | T |
| NFR.SEC.5 | `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo audit` and the secret scan MUST be clean. `#![deny(unsafe_code)]` MUST hold. | T |
| NFR.SEC.6 | The four open security defects in the manifest — MIK-7249, MIK-7256, MIK-7262, MIK-7222 — MUST be closed in this release. | T |

### 4.3 Performance

| ID | Requirement | Verify |
|---|---|---|
| NFR.PERF.1 | Tool-call latency through the gateway MUST NOT regress by more than 5% at P50 or 10% at P99 against 3.5.0 on the same workload. | M |
| NFR.PERF.2 | Header-first routing MUST be justified by measurement against the current full-parse path, or MUST NOT ship. A performance change without a number is not a performance change. | M |
| NFR.PERF.3 | Memory MUST NOT grow unboundedly with abandoned continuations; a soak with abandonment MUST show reclamation. | M |
| NFR.PERF.4 | The Meta-MCP surface MUST remain 14–16 tools. `server/discover` is a protocol RPC, never enumerated to a model, and does not count against it. | I |

### 4.4 Observability and operability

| ID | Requirement | Verify |
|---|---|---|
| NFR.OBS.1 | The gateway MUST record, per request, the protocol revision observed and whether it arrived by `_meta` or by handshake. | T |
| NFR.OBS.2 | For every `tools/list`, the gateway MUST record which filters ran and the `cacheScope` that would be emitted, before that field is advertised to any real client. | T |
| NFR.OBS.3 | Era detection per backend MUST be observable — which era, by what evidence, and when re-probed. | T |
| NFR.OBS.4 | Continuation mint, redeem, expiry and rejection MUST be counted, with reason. | T |
| NFR.OBS.5 | Modern-protocol serving MUST be behind a flag, defaulting off until the conformance matrix is complete, and MUST be revertible without a downgrade. | T, D |

### 4.5 Documentation

| ID | Requirement | Verify |
|---|---|---|
| NFR.DOC.1 | Every document this release makes untrue MUST be updated within the release: README, ARCHITECTURE, DEPLOYMENT, capability docs and the CHANGELOG. | I |
| NFR.DOC.2 | The upgrade note MUST state what changes for an operator, what changes for a client author, and what does not change. | I |
| NFR.DOC.3 | Any deliberate divergence from the specification MUST be recorded with its reason. | I |

---

## 5. Constraints

| ID | Constraint |
|---|---|
| CON.1 | The gateway stays hand-rolled; `rmcp` is a development dependency for conformance testing only. Rationale in RFC-0061 Decision 1. |
| CON.2 | The Meta-MCP surface budget is a locked decision and is not reopened by this release. |
| CON.3 | Capability definitions remain SHA-256 pinned. |
| CON.4 | Mixed per-file licensing (MIT core, PolyForm Noncommercial for enterprise paths) is unchanged. |
| CON.5 | The specification's twelve-month deprecation window means no legacy removal is forced by this release, and none is taken. |

### 3.1.1 A version we invented and have been advertising

`src/protocol/mod.rs:23` lists `2024-10-07` among supported protocol versions. The specification
defines five revisions — `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28` — and
that is not one of them. It has been advertised to every client since 2026-01-26 and is repeated in
`src/protocol/negotiate.rs`, `src/transport/http/tests.rs` and `docs/ARCHITECTURE.md`.

**Removing it cannot break a conforming client**, because no conforming client can request a revision
that does not exist. It matters now for one reason: `server/discover` publishes this list as the
gateway's own statement of what it speaks, so a fabricated entry stops being an unused constant and
becomes a claim made in a protocol response.

Two things this is not. It is not a compatibility decision — there is nothing on the other side to be
compatible with. And it is not evidence that negotiation is broken: `negotiate_version` returns the
requested version only on an exact match, so the entry has been inert for everything except the list
the gateway shows the world.

## 6. Assumptions

| ID | Assumption | If wrong |
|---|---|---|
| ASM.1 | 2026-07-28 remains current for the release window. | A newer revision restarts negotiation work; discovery and per-request dispatch survive regardless. |
| ASM.2 | `rmcp` 3.1.4 is a faithful reference for the wire format. Its `LATEST` is still `V_2025_11_25`, so it is a vocabulary reference, not a conformance oracle. | Conformance must be judged against the specification text, and the matrix rebuilt from it. |
| ASM.3 | Most backends will be pre-2026 for the release's life. | If backends move first, requirement MIK-7212.MRTR.7 becomes the common path rather than the rarer one — it is required either way. |
| ASM.4 | No client we serve depends on SSE resumability. | Re-issue safety (MIK-7272.SUB.4) becomes load-bearing rather than precautionary. |

## 7. Out of scope, with reasons

| Excluded | Reason |
|---|---|
| Other portfolio surfaces (hebb, throttla, fulcrum, botnaut-client, pithy) | RFC-0060 owns them. The gateway goes first because it is the only surface that must speak both eras at once. |
| Retiring 2025-03-26 and 2024-11-05 | Needs one week of revision telemetry. Retiring a revision on a guess breaks a client nobody knew was connecting. |
| Skills-over-MCP, MCP Apps extensions | Not stable specifications. |
| OAuth consumer slices MIK-6744 / 6745 / 6746 | Consumers of the identity seam, each with its own consent and storage design. 4.1.0. |
| Kubernetes operator GA | Its own dependency chain, orthogonal to the protocol. |
| MIK-7251, MIK-7250, MIK-7042 | Aimed at code this release deletes; re-scoped after slice 2 rather than written twice. |

## 8. Open questions

Each has a check that can return "no". A question without one is a risk paragraph, and there are
none here. Full statements in RFC-0061 §Unknowns.

| ID | Question | Resolved by | Blocks |
|---|---|---|---|
| U1 | Which revisions do our clients actually speak? | One week of NFR.OBS.1 telemetry | Only the compatibility window — **not this release** |
| U6 | Does the wire behaviour match the specification's type surface, across every revision in the window? | The conformance matrix, which is this release's test plan | Release acceptance |
| U7 | What else is keyed by session? | **Resolved 2026-08-29**: 32 files, tabulated in RFC-0061 | — |
| U8 | Can all four client×backend era pairs be constructed for test? | Two runs, both directions, one eliciting | MIK-7212 design; **run first, it is the cheapest** |
| U9 | Is header-first routing worth its complexity? | NFR.PERF.2 measurement | Only that item |

## 9. Release acceptance

4.0.0 may be tagged when **all** hold:

1. Every MUST above is verified, or is recorded as N/A **with its reason** — an N/A without a reason is a skipped requirement wearing a label.
2. The conformance matrix — one row per normative statement, crossed with role, transport, revision and outcome — has no empty evidence cell. An empty cell is the finding.
3. The four era pairs pass with an elicitation in flight, in both directions.
4. Every control in §3.7 has a test proving it **refuses** without its key.
5. NFR.PERF.1 measured, not asserted.
6. Two independent frontier-model reviews, from different vendors, recorded against the final change.
7. The nineteen manifest tickets carry per-criterion verdicts; the six already-fixed tickets are closed; the three superseded tickets are re-scoped.
8. `cargo clippy -D warnings`, `cargo fmt --check` and the full suite are green.

**Explicitly not acceptance**: that the code compiles and the existing suite passes. This release's
failure mode is a control that still runs and no longer protects, and an existing suite written
against sessions cannot see it.
