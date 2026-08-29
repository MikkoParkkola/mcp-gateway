# mcp-gateway 4.0.0 — Test plan

**Status**: DRAFT for review. Written before any test code exists, per `development-process.md` §P2.
**Requirements**: `docs/requirements/RELEASE-4.0.0-requirements.md`
**Design**: `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md`

A test plan exists so the tests inherit the *requirements'* coverage instead of the design's happy
path. One row per acceptance criterion. **An empty evidence cell is the finding**, not an oversight
to be filled in later.

Reviewed against two questions, and no others:

1. Does every acceptance criterion have a case, or a stated reason it has none?
2. **Can each named case actually fail?** A case whose fixture makes its own assertion true, or whose
   staging removes the condition it observes, passes every coverage tool ever built.

V-model levels: **U** unit · **C** component (one module, real collaborators) · **I** integration
(gateway process, real transport) · **S** system (gateway + live peer).

---

## Increment 1 — Discovery and era detection

Chosen first because `server/discover` is additive: it breaks no existing client, and it is the only
negotiation surface that works in both directions once `initialize` and `ping` are gone. If
implementing it requires touching the legacy handshake path, the implementation is wrong — that is
the ticket's own stop-the-line, and row D3.b is what enforces it.

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| DISCOVER.1 | `server/discover` over **stdio** returns a result naming supported versions, capabilities and server identity | I | positive | Yes — no handler exists; the dispatcher returns method-not-found |
| DISCOVER.1 | `server/discover` over **Streamable HTTP** returns the same document as stdio for the same gateway | I | equivalence | Yes — two dispatchers, `server/mod.rs:1636` and `handlers.rs:528`, are separate `match` arms and drift is the default |
| DISCOVER.1 | ~~`server/discover` over WebSocket~~ | — | **N/A, with reason** | The gateway serves no MCP over WebSocket. `src/gateway/ws_listener.rs:6` *"echoes text messages back"*; `src/transport/websocket.rs` is the **outbound client** transport, not a dispatcher. The original row would have exercised the client while the listener still served nothing — a green row proving nothing. Reinstate when the listener serves MCP. |
| DISCOVER.7 | The advertised version list equals `SUPPORTED_VERSIONS`, and every entry is a revision the specification defines | U | negative | Yes — **it fails today**: `src/protocol/mod.rs:23` advertises `2024-10-07`, which is not one of the five revisions the specification lists |
| DISCOVER.7 | The invented version is removed from its four sites: `src/protocol/mod.rs`, `src/protocol/negotiate.rs`, `src/transport/http/tests.rs`, `docs/ARCHITECTURE.md` | U | inspection | Yes — a change that fixes the constant and leaves the documentation claiming `2024-10-07 through 2025-11-25` fails it |
| DISCOVER.2 | Discovery answers on a connection that has sent no `initialize` and holds no session | I | positive | Yes — the HTTP path currently mints a session id for every request |
| DISCOVER.2 | Discovery answers before any credential exchange beyond transport authentication | I | positive | Yes — if discovery is placed behind the admin gate it fails |
| DISCOVER.3 | Given a 2025 client, When it sends `initialize`, Then the result is byte-identical to the same request against 3.5.0 | C | regression | Yes — golden captured in-process from the unchanged tree (which *is* 3.5.0 on this branch), so any field added to the handshake path breaks it. **This is the row that enforces "additive"** |
| DISCOVER.4 | Backend answering `DiscoverResult` → classified modern | C | positive | Yes — nothing classifies today |
| DISCOVER.4 | Backend answering `UnsupportedProtocolVersionError` → classified **modern** (a recognised modern error proves a modern peer) | C | boundary | Yes — the tempting implementation treats any error as legacy, and this row is the one that catches it |
| DISCOVER.4 | Backend answering `-32601 method not found` → classified legacy | C | positive | Yes |
| DISCOVER.4 | Backend answering an arbitrary application error → classified legacy | C | negative | Yes |
| DISCOVER.4 | Backend answering **nothing** until the probe deadline → classified legacy | C | timeout | Yes — needs a stalling fixture and a bounded deadline; an implementation that waits forever hangs the test rather than passing it |
| DISCOVER.4 | A backend classified legacy is then probed with `initialize` and serves normally | I | positive | **Deferred to increment 2, deliberately** — see below |
| DISCOVER.5 | Era is resolved once per backend and reused; a second call issues no second probe | C | positive | Yes — assert on a probe counter in the fixture transport, not on elapsed time |
| DISCOVER.5 | When a cached era assumption produces a failure, the backend is re-probed | C | recovery | Yes — the naive cache never invalidates, so this fails against it |
| DISCOVER.6 | Warm-start retries on its existing schedule when discovery finds nothing listening | C | regression | Yes — an implementation that replaces the retry loop with a single discovery probe fails it |

### The two questions, answered

**Every AC has a case.** Seven criteria, sixteen rows: fifteen with a case, one N/A **with its reason stated** (WebSocket, which serves no MCP). An N/A without a reason is a skipped criterion wearing a label; this one carries the file and line that justify it.

**Every case can fail, and four are worth naming:**

- **The `2024-10-07` row fails on today's code.** That is not a defect in the plan; it is the plan finding a defect before the feature is written. The gateway advertises a protocol revision the specification has never defined. Either it is a typo for `2024-11-05` that has been advertised to every client since, or it is a private extension nobody documented. Resolve before implementing, because the discovery document repeats whatever this list says.
- **DISCOVER.3's golden fixture is captured, not written by hand.** A hand-written expectation of the handshake is a second implementation of it, and it agrees with whatever the author believed rather than with what shipped. Capture happens before the first line of discovery code, from the unchanged tree, and pins its Cargo feature set.
- **The timeout row needs a stalling fixture with a bounded deadline.** A backend that never answers and a test that waits forever are indistinguishable from a passing test that hangs CI.
- **DISCOVER.5 asserts a probe counter, never elapsed time.** Timing assertions are the classic flaky test, and a cache that is merely slow would pass one.

### A design decision this increment made, named rather than absorbed

**The era probe is built but not yet issued at backend startup.** The classifier and its cache ship
here; the call site does not.

Wiring it into `Backend::start()` now would add one `server/discover` request to every backend
start. Against the 32 backends on the operator's own gateway that is 32 extra requests, every one of
which a legacy backend answers with an error — cost, log noise and a new startup failure mode, in
exchange for an answer **nothing currently consumes**. Nothing consumes it because the gateway
cannot yet speak modern to a backend; that is increment 2.

So the era is resolved **when a caller first needs it**, which is the increment that gives it a
consumer. The requirement is unchanged — the gateway determines a peer's era by probing
`server/discover` first, and only a recognised modern answer proves a modern peer. What is deferred
is the moment of the call, not the rule.

Stated here because a decision taken during implementation and left unwritten reaches no review.
The integration row above moves with it.

### Fixtures — what they may not do

A fixture that reimplements the production path tests the fixture. Two rules for this increment:

1. The backend fixture is a **transport**, answering bytes. It does not import the era classifier.

   **And it does not use the production serializers to produce those bytes.** A fixture that
   serialises with the same types the code under test parses proves only that the gateway agrees
   with itself: a self-consistent but nonconforming wire format passes every such test. Discovery
   frames are committed as **literal JSON, transcribed from the specification**, so a wrong field
   name fails rather than round-trips.
2. The golden handshake fixture is **captured output**, committed as data, never generated by the code under test at assertion time.

### Deliberately not covered in this increment

- Discovery's content beyond structure — the capability list is not stable until slice 3 defines `extensions`. Row: version list and identity only.
- Discovery over the deprecated HTTP+SSE transport. It is Deprecated in the specification and the gateway need not add new surface to it.

---

## Increment 2 — Stateless request handling

Second because everything after it assumes a request can be understood on its own. The gateway
becomes a **dual-era server**: `initialize` still selects legacy semantics; per-request `_meta`
selects modern. Both on one endpoint, which the specification sanctions explicitly.

The risk here is not the modern path — it is the legacy one. Every row that begins "given a 2025
client" exists because this increment is where a working client silently stops working.

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| STATELESS.1 | A request carrying `_meta.protocolVersion` and `_meta.clientCapabilities`, with no prior `initialize`, is served | I | positive | Yes — nothing reads `_meta` today |
| STATELESS.1 | Two requests on one connection declaring **different** versions are each served under their own | I | boundary | Yes — a per-connection implementation would serve the second under the first's version, which is the whole point of "per request" |
| STATELESS.2 | Every modern result carries `_meta["io.modelcontextprotocol/serverInfo"]` with name and version | I | positive | Yes |
| STATELESS.2 | A **legacy** result does not gain the field | C | regression | Yes — the tempting implementation adds it to the shared result builder and changes the 2025 wire format, which the increment-1 goldens then catch |
| STATELESS.3 | A modern request's response carries no `Mcp-Session-Id` header | I | negative | Yes — the HTTP path mints and emits one on every response today (verified live 2026-08-28) |
| STATELESS.3 | A legacy request's response still carries it | I | regression | Yes — a change that strips the header unconditionally breaks every 2025 client |
| STATELESS.4 | A modern request naming an unsupported version gets `UnsupportedProtocolVersionError` and HTTP 400, listing supported versions | I | negative | Yes — `negotiate_version` currently falls back to the latest instead of refusing, so this fails against today's behaviour |
| STATELESS.5 | An unimplemented method returns HTTP 404 with `-32601`, body distinguishable from a legacy transport's bare 404 | I | negative | Yes |
| STATELESS.6 | `ping`, `logging/setLevel`, `notifications/roots/list_changed` are refused on the modern path | I | negative | Yes |
| STATELESS.6 | The same three still work on the legacy path | I | regression | Yes — a version-blind removal fails this and is the likeliest implementation |
| STATELESS.7 | No `notifications/message` for a request that carried no `_meta.logLevel` | C | negative | Yes — needs a notification sink to observe absence; a test that merely calls the handler proves nothing |
| STATELESS.8 | `initialize` selects legacy for that connection; a `_meta`-bearing request selects modern — both against one endpoint | I | equivalence | Yes |
| STATELESS.9 | A modern request missing `protocolVersion` is rejected `-32602` / HTTP 400 | I | negative | Yes |
| STATELESS.9 | A modern request missing `clientCapabilities` is rejected the same way | I | negative | Yes — this is the one an implementer skips, because the field looks optional and nothing breaks without it |
| STATELESS.9 | A request with **neither** is legacy, not malformed — it is a 2025 client | I | boundary | **The row that decides the design.** Absence of `_meta` cannot mean both "malformed modern" and "legacy"; the discriminator must be something else. See below. |
| STATELESS.10 | A request needing a capability the client did not declare gets `-32021` with `data.requiredCapabilities` naming it | I | negative | Yes |

### The discriminator, named before it is coded

STATELESS.9's last row is a genuine contradiction if the era is inferred from "does `_meta` carry
protocol fields". A 2025 client sends no `_meta` at all; so does a 2026 client that forgot a
required field. One must be served, the other refused, and they look identical under that rule.

The specification resolves it and the resolution is not symmetric with discovery's:

- **`initialize` present** → legacy, for that connection. That method does not exist in 2026, so its presence *is* the signal.
- On **HTTP**, the `MCP-Protocol-Version` header is required on every modern POST, so a request carrying the header but missing the `_meta` field is a broken modern request; one carrying neither is legacy.
- On **stdio** there is no header. A request with no `_meta` and no prior `initialize` is treated as legacy, because refusing it would break every 2025 stdio client, and the cost of the other error is that a broken 2026 client is told "unknown method" instead of "malformed request".

That asymmetry is a decision, not a derivation, and it is written here so the review sees it before
the code does.

### Fixtures

Same rules as increment 1, plus one: **the modern request frames are transcribed from the
specification's examples**, not built from the gateway's own types. Increment 1 shipped a
nonconforming document that every test passed, because the tests asserted the same invented names.
That is the failure this rule exists to prevent, and it has already happened once here.

---

## Increment 3 — Standard request headers

The revision mirrors selected body fields into headers **so an intermediary can route without
parsing the body**. This gateway is that intermediary, so the headers are the increment with the
most upside — and the one with a security rule attached, because the spec's own rationale for
validating them describes a load balancer and a server disagreeing about what a request is.

Two halves, and only the first is about speed:

- **Routing** may read a header without parsing the body.
- **Authorizing or executing** may not. *"Servers that process the request body MUST reject requests where the values specified in the headers do not match."* This gateway processes the body.

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| HEADER.1 | `MCP-Protocol-Version` matching `_meta.protocolVersion` is accepted | I | positive | Yes — nothing reads the header today |
| HEADER.1 | Header and body disagreeing → `-32020`, HTTP 400 | I | negative | Yes — and this is the vulnerability row: without it a permitted header routes an unauthorized body |
| HEADER.1 | A modern POST with no `MCP-Protocol-Version` is refused | I | negative | Yes |
| HEADER.2 | `Mcp-Method` disagreeing with `method` → `-32020` | I | negative | Yes |
| HEADER.2 | `Mcp-Name` required for `tools/call`, `resources/read`, `prompts/get` | I | negative | Yes |
| HEADER.2 | `Mcp-Name` **not** required for any other method | I | boundary | Yes — treating it as universal rejects valid requests, which is the likelier implementation |
| HEADER.4 | A sentinel-encoded `Mcp-Name` is decoded before comparison | U | positive | Yes — comparing raw would reject every non-ASCII tool name |
| HEADER.4 | Each row of the specification's encoding table round-trips | U | table | Yes — transcribed from the spec, so an encoder that agrees with our decoder but not the spec fails |
| HEADER.4 | A plain-ASCII value matching the sentinel pattern is decoded, not taken literally | U | boundary | Yes — the ambiguity the spec calls out by name |
| HEADER.4 | A malformed sentinel is a mismatch, not a panic and not a silent pass | U | negative | Yes — an attacker controls this string |
| HEADER.6 | A request whose header and body disagree never reaches authorization or dispatch | C | security | Yes — needs an observable dispatch, so the assertion is that the handler was **not** entered |
| HEADER.1-2 | A legacy request with no headers is unaffected | I | regression | Yes — a version-blind check breaks every 2025 client |

### The comparison is the security boundary, so it is one function

Every one of these rows compares a header against a body value. Doing that in three places is how
two of them end up subtly different — and the difference is a bypass, not a bug. One function, and
the rows above exercise it through the transport rather than around it.

### Fixtures

The encoding table is transcribed from the specification, not generated. A `base64` round-trip
through our own encoder proves our encoder matches our decoder, which is the property that was
already worth nothing once this release.

---

## Increment 4 — Results, errors and cacheability

`resultType` and the renumbered error codes are mechanical. `cacheScope` is not: it is the field
MIK-7213 is filed against, and getting it wrong is a cross-tenant leak rather than a compliance
finding.

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| RESULT.1 | Every modern result carries `resultType: "complete"` | I | positive | Yes |
| RESULT.1 | A legacy result carries none | I | regression | Yes — adding it in the shared builder changes the 2025 wire format |
| RESULT.2 | As a client, a backend result with no `resultType` is read as `"complete"` | U | positive | Yes — the alternative is treating every legacy backend's answer as unknown |
| ERROR.1 | The three renumbered codes are emitted at their new numbers | U | table | Yes — pinned as literals, so a rename that keeps the old number fails |
| ERROR.2 | Resource-not-found is `-32602`, not `-32002` | U | negative | Yes |
| CACHE.1 | `ttlMs` and `cacheScope` present on the five cacheable results | I | positive | Yes |
| CACHE.2 | A list whose content depends on the caller is `private` | I | **security** | Yes |
| CACHE.3 | **No `public` is emitted from a filtered assembly, anywhere** | C | security | Yes — the ticket's own stop-the-line |
| CACHE.4 | Two callers with different credentials are never served each other's cached list | I | security | Yes — needs two principals and a live cache to be a real test, not one |
| ORDER.1 | `tools/list` order is stable across repeated calls | I | positive | Yes |
| ORDER.1 | Order is stable across two *different* callers when the tool set is the same | I | boundary | Yes — a `HashMap` iteration order passes the first row and fails this one |
| ORDER.2 | A modern list does not vary with anything session-derived | I | security | Yes |

### `cacheScope` starts at `private`, and the burden of proof runs the other way

`public` means *"any client or intermediary MAY cache this and serve it across authorization
contexts"*. That is a statement about every future caller, made by a server that has seen one.

This gateway's `tools/list` varies by the credential presented — legally, since credentials are
per-request input — so its list is `private` by construction today. **The release therefore emits
`private` and never `public`**, and the path to `public` is a proof of invariance across
authorization contexts, not a default that a filtered assembly can fall into. That is the ticket's
stop-the-line stated as a rule the code can hold: *no `cacheScope: "public"` from a scoped assembly
ships, anywhere.*

Cost of the conservative choice, stated: a shared intermediary cannot reuse one caller's tool list
for another. That is the correct answer while the list varies by caller, and the wrong answer only
once the decision table proves a case where it does not.

---

## U8 — RESOLVED: the era pairs are constructible

**Checked 2026-08-29.** The design made this the first thing to run, because a continuation
contract that cannot be exercised is a contract nobody can hold.

`Transport` is a four-method trait, two of them defaulted (`src/transport/mod.rs:20`), and the repo
already builds fixtures against it — `MockTransport` and `RecoveryMock` in `src/backend/tests.rs`
are eleven lines each. A backend that answers with an `InputRequiredResult` is the same shape with a
different constant. Both client eras are constructible against the real router, which increments 2
and 3 already demonstrate: a legacy request is a bare JSON-RPC body, a modern one is the same body
with the protocol fields and the mirrored headers.

So all four pairs can be built in-process, with no live peer and no network. **The contract stands
and this increment proceeds.**

What the check does *not* say, stated so it is not read as more than it is: that the pairs are
constructible is not that the bridge is correct. It removes the reason to stop, and nothing else.

---

## Later increments — planned, not yet detailed

Listed so the shape of the whole is visible and so no increment is quietly dropped. Each gets its own
row set before its code is written, not before the release ends.

| Increment | Requirements | Note |
|---|---|---|
| 2 — Stateless dispatch | STATELESS.1–8 | Needs the dual-era fixture pair from increment 1 |
| 3 — Headers | HEADER.1–6 | HEADER.6 is a security case: a mismatched header must not reach authorization |
| 4 — Results, errors, cache fields | RESULT.\*, ERROR.\*, CACHE.\*, ORDER.\* | CACHE.2 needs two principals and a shared cache to be a real test |
| 5 — MRTR and the bridge | MRTR.1–10 | The largest. U8 runs first: if the four era pairs cannot be constructed, the design reopens |
| 6 — Controls that must survive | CONFIRM.\*, TENANT.\*, CONTROL.1–5 | Every case asserts a **refusal**, never a computed value |
| 7 — Identity | IDENT.1–5 | IDENT.1 is negative-first: a forged `clientInfo` must change no authorization outcome |
| 8 — Subscriptions | SUB.1–4 | Follows increment 6; the multiplexer is session-keyed today |
| 9 — Authorization server | OAUTH.1–3 | Independent of the rest; can run in parallel |
| 10 — Exploitation | EXT.1, OTEL.1, TASK.1, SURFACE.1, SCHEMA.1 | SURFACE.1 and PERF.2 are measurements, not tests |

## Cross-cutting suites

Two suites that no per-increment row set can express, because their subject is the interaction:

- **Conformance matrix** — one row per normative statement in the 2026-07-28 changelog, crossed with role (server ‖ client), transport, revision, and outcome (positive ‖ negative). Requirement NFR.COMPAT.4 means each row is verified in both roles; a matrix filled in one role is half a matrix.
- **Era-combination matrix** — all four client×backend era pairs, each with an elicitation in flight. U8 promoted from a one-off probe to a permanent suite, because the pairs are exactly what regresses silently.

## What would make this plan wrong

Stated so a reviewer has something to disagree with:

- If `server/discover` cannot be answered before a session exists on the HTTP path without restructuring request handling, increment 1 is not additive and its ordering is wrong.
- ~~If the 3.5.0 golden fixture cannot be captured — because the handshake response embeds a timestamp, a session id or any per-run value — DISCOVER.3 needs a normalising comparison.~~ **Checked 2026-08-29, and it is capturable.** `handle_initialize` (`src/gateway/meta_mcp/mod.rs:955-996`) returns `build_initialize_result(negotiated_version, &instructions)`; the instructions derive from the backend registry's tool counts, and nothing in the path reads a clock, a session id or a random source. Given a fixed registry the response is deterministic.

  Two consequences, both simplifications. The golden does **not** need capturing from a built 3.5.0 binary: this branch carries no code change yet, so the current tree *is* 3.5.0 for this purpose, and the fixture is captured in-process from `handle_initialize` before the first line of discovery code is written.

  **But it moves with Cargo features.** Under `spec-preview` the handshake advertises `capabilities.tools.filtering` and `.resolve` (`src/gateway/meta_mcp/spec_preview.rs`), so one golden is one feature set. The fixture MUST pin the feature set it was captured under, and the test MUST fail rather than pass when run under a different one — otherwise the regression row silently stops comparing, which is the failure mode this row exists to prevent.
