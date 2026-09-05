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
| DISCOVER.7 | The advertised version list equals `SUPPORTED_VERSIONS`, and every entry is a revision the specification defines | U | negative | Yes — **it fails today**: `SUPPORTED_VERSIONS` (`src/protocol/mod.rs`) advertises `2024-10-07`, which is not one of the five revisions the specification lists |
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
| CACHE.4 | **Superseded in detail** by [`docs/design/2026-08-31-cluster-f-response-cache-keying-test-plan.md`](../design/2026-08-31-cluster-f-response-cache-keying-test-plan.md) — one row per response-varying input, plus the hit-control/miss-half fixture doctrine the single row above cannot carry | I, U | security | Yes — see that document's per-row column |
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

## Increment 5 — Multi-round-trip tool calls (MIK-7325)

The branch's headline feature, and today it is declined at the door: a retry's `inputResponses` and
`requestState` are extracted and then deliberately not forwarded (`handlers.rs:834-859`), so a
backend that asks a question cannot complete a call. Design reviewed to SHIP over three rounds:
`docs/design/2026-08-30-mrtr-wiring.md`.

### The fixture this increment cannot start without

**No backend in the tree returns `input_required`.** `rg 'input_required'` finds only `mrtr.rs`,
`handlers.rs`, two acceptance-criteria test files, and the A2A translator's unrelated
`TaskState::InputRequired`. Every response-side row below would otherwise assert against a shape
nothing emits — a suite that passes because the condition it observes never occurs. The fixture
backend is therefore the increment's first commit, not a detail inside a later one, and it must be
able to answer twice: once with `input_required`, then with a completed result once the answers
arrive.

It needs a **second mode** as well, and the reason is a row further down. The one-round-trip cap is
observed only by a backend that asks *again* on the retry — against a fixture specified to complete
on its second call, that row either never reaches its condition or stays red against a correct
implementation. So the fixture is parameterised by how many times it asks: once (the ordinary
exchange) and twice (the cap).

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| MRTR.1 | A legacy result with **no** `resultType` passes through byte-identical, and nothing is minted | I | regression | Yes — this is the regression the design calls the one that matters most, and it is the row that fails a discriminator which mints on every `tools/call`. Without it, an ordinary tool call growing a `requestState` is invisible to the whole suite |
| MRTR.1 | A result whose `resultType` is `complete` passes through byte-identical, and nothing is minted | I | regression | Yes — the second half of the same guard: a discriminator that branches on the field's *presence* rather than its value passes the row above and fails this one |
| MRTR.1 | A retry carries the client's answers to the backend as siblings of `arguments`, not merged into it | I | positive | Yes — the current code forwards neither |
| MRTR.1 | A tool with an argument literally named `requestState` is not overwritten by the retry plumbing | I | boundary | Yes — this is the failure the first attempt shipped |
| MRTR.2 | The `requestState` returned to the client does not **contain** the backend's value, which the fixture pins to a distinctive literal | I | security | Yes — asserting only that the two strings differ passes an envelope that embeds the backend's state verbatim, which is the leak the AC is about |
| MRTR.2 | The backend receives its **own** state back on the retry, not the gateway's envelope | I | positive | Yes |
| MRTR.4 | A retry whose token was minted for a different caller is refused, run once per authentication scheme the fingerprint table names — API key, agent JWT, mTLS | I | security | Yes — the current code constructs no fingerprint at all |
| MRTR.4 | A token minted under one scheme is refused under another, with identity material chosen so the two **collide** if the scheme tag is dropped — an API key whose bytes are also a valid `sub`, presented as an agent JWT | I | security | Yes, and *only* this row can fail that way. Running the wrong-caller case separately inside each scheme never presents a token from one scheme to a caller from another, so a fingerprint that omits its domain tag passes all three of those and fails this one |
| MRTR.2 | A backend that answers `input_required` while returning no `requestState` of its own completes, and its retry carries none either | I | positive | Yes — `InputRequired::request_state` is optional (mrtr.rs:125) and `Payload::backend_request_state` is not (continuation.rs:68), so the tempting adapter substitutes an empty string and hands the backend state it never issued |
| MRTR.3 | A retry whose token has one byte flipped is refused, and the HTTP response body is the `client_message` literal — naming no key id, no version, no `jti` | I | security | Yes — at U level this can only re-read `ContinuationError::client_message`, which is already a constant; the leak the row is about is what the wired handler puts on the wire |
| MRTR.4 | A token minted for tool A is refused when presented on a call to tool B | I | security | Yes — this is what `original_request_digest` exists for, and it is currently constructed nowhere |
| MRTR.4 | A token minted for `book_flight` with `{"seat": "12A"}` is refused when presented with `{"seat": "14B"}` | I | security | Yes — a digest over the tool name alone passes the tool-A/tool-B row above and fails this one, and the AC says bound to *the original request*, not to the tool |
| MRTR.4 | A caller with no credential gets **no continuation at all**; the interim result is refused, not minted | I | security | Yes — the tempting implementation mints against a shared constant and passes every other row |
| MRTR.5 | A token redeemed once is refused the second time | I | security | Yes |
| MRTR.5 | A token minted by one `AppState` is refused by a second one built through the **production constructor from the same configuration**, the refusal is `NotAuthentic`, and it is decided before any ledger lookup | I | security | Yes, and it is the row the whole cross-replica claim rests on: it is simultaneously the **restart** and the **other replica** row of the design's outcome matrix, since the two differ only in whether the processes overlap in time. Any implementation that derives key material from configuration or reads it from the environment gives both processes the same key, and fails here while passing every single-process row. But only at this level. The unit version (build keyring A, mint, build keyring B, fail to open) proves AES key separation and nothing about the restart, because the two keyrings are chosen by the fixture. The case has to go through the path that actually constructs the pair, since the property under test is that *no* path builds one without the other. What this row witnesses is precisely **restart kills continuations** — regenerated keys make the envelope fail to open *before* the spent-list is consulted, so it cannot also witness keys outliving the ledger. That invariant is carried by the single `AppState` owner, not by this test |
| MRTR.5 | A token past its `expires_at` is refused **on the replica that minted it**, with the clock advanced rather than the payload hand-edited | I | security | Yes — the expiry check exists (continuation.rs:401), the *derivation* of `expires_at` from the mint does not, and the row is stated on the origin because an implementation that treats "this process minted it" as sufficient turns the origin path into an early accept and passes every cross-replica row |
| MRTR.5 | Two retries of one token dispatched concurrently: exactly one reaches the backend | I | security | Yes — the AC says enforcement MUST be atomic, and a check-then-insert ledger passes every sequential row in this table while failing this one |
| MRTR.5 | A continuation minted with an injected `now` expires at exactly `now + 300` | U | boundary | Yes, but only through the production construction path. `Keyring::mint` takes a whole `Payload` (continuation.rs:316) and seals whatever `expires_at` it is handed, so a test that fills a `Payload` in itself asserts its own arithmetic and goes green against a response side that derives nothing. The case mints the way the handler does. The row the design's clamp implied — "a mint requesting more than 300 seconds gets 300" — could not be written, because there is no request parameter to over-ask with, which is why the lifetime became a constant instead |
| MRTR.5 | Two retries of one token dispatched concurrently at **two** `AppState`s: exactly one reaches a backend, and the two ledgers never consult each other | I | security | Yes — an implementation that shares key material to make cross-replica redemption "work" turns this into the double-spend the AC forbids, and no sequential row detects it |
| MRTR.6 | A retry presented to a non-origin replica is refused with a **typed** refusal, distinct from expired and from already-spent, and that replica makes **no** backend call | I | security | Yes — the "no backend call" half is what MRTR.6 actually forbids, and a refusal that first opens an exchange to discover the mismatch passes a refusal-only assertion |
| MRTR.6 | A continuation minted against a live `InFlight` hold, redeemed on the **origin** after that hold has gone — deadline passed or connection dropped — is refused rather than dispatched | I | security | Yes — the token still opens and the ledger still has it unspent, so without the pin the gateway opens a second exchange with a legacy backend, which is the one outcome the AC names |
| MRTR.7a | A modern backend returns an `InputRequiredResult` carrying one `elicitation` request; a legacy client on an SSE session receives an `elicitation/create` request on its own connection, with the backend's params deserialized **whole** — `mode`, `message`, `requestedSchema` and `url` all present on the wire | I | functional | Yes. This is the criterion. It fails against a bridge that copies `message` and `requestedSchema` and drops `mode`, which is the failure the design names: a `url`-mode question rendered as a form asks the user to type what they were meant to go and do |
| MRTR.7a | A backend `inputRequest` naming a method outside `{sampling, elicitation, roots}` is refused, and **nothing is sent to the client** | I | security | Yes. The closed `ServerRequest` type is the whole §1 argument; a test asserting only the refusal code passes against a `forward_request_with_response(method: &str)` that also forwards. Assert the client transport saw zero frames |
| MRTR.7a | Each variant's outgoing wire method and pending-id prefix come from the enum, and the ingress gate (`handlers.rs:633`) admits exactly the prefixes the enum names | U | functional | Yes — the drift this guards is `roots-` existing on the mint side and not the admit side, which fails as a caller timeout rather than an error. Test the two sets are equal, not that `roots-` appears in both |
| MRTR.7a | A client that declared only `elicitation` is not asked for `sampling`, even when the per-request slice is empty | I | security | Yes. §6's store is the ceiling; the per-request slice may only narrow. A test with a populated slice passes against an implementation that reads the slice alone, which is the shipped state |
| MRTR.7a | A stdio client is asked and answers **while the serve loop keeps reading** | I | functional | Yes, and it is the row §2 exists for: `server/mod.rs:1564` is a single sequential reader, so a bridge that blocks inside dispatch deadlocks the only task that could deliver the reply. Fails by hanging, so it needs a bounded timeout and an assertion on the answer, not merely on completion |
| MRTR.7b | The client accepts; the backend is re-invoked with the answer filed under the backend's own key in `inputResponses` | I | functional | Yes. This is the criterion. Assert the key, not just that a retry happened |
| MRTR.7b | The client replies `{"action":"decline"}`; the call fails, the backend is **not** re-invoked, and the reason distinguishes the user's refusal from a transport fault | I | functional | Yes — a successful JSON-RPC result carrying a decline is the §1 failure that arrives through a door §4 does not cover. A test asserting only "no retry" passes against a bridge that treats every non-accept as a transport error, losing the distinction `NFR.OBS.4`'s counter needs |
| MRTR.7b | The client replies with a JSON-RPC `error` member; the call fails as `ClientRefused` carrying the client's code, and the backend is not re-invoked | I | functional | Yes — `proxy.rs:278` resolves an error reply through the success arm today, so this fails against the shipped helper |
| MRTR.7b | The client accepts with `content` absent, or with a body that is not an object; the call fails as `Malformed` and the backend is not re-invoked | I | functional | Yes |
| MRTR.7b | The client accepts with `content` that does **not** satisfy the `requestedSchema` the backend sent; the answer is forwarded unchanged | I | functional | Yes, and it is deliberately the opposite of the row above. The design refuses to second-guess the backend's own contract; without this row an implementer reads the `Malformed` row and adds a validator |
| MRTR.7b | A backend that keeps asking is cut off after 3 retries — at most 4 backend invocations — and the client sees a bounded failure | I | reliability | Yes |
| MRTR.7b | A backend that asks in large batches is cut off at 8 requests in total, **before** any request of the batch that would exceed it is sent | I | reliability | Yes — "before sending any request of a batch" is the testable half; a check applied after each send passes a 3-then-6 sequence that this row fails |
| MRTR.7b | A prompt no human answers is abandoned at `min(remaining, 30s)`, and the aggregate 120s deadline ends the whole call regardless of how the rounds divide it | I | reliability | Yes. Two bounds, one row only if the fixture drives both; otherwise split it |
| MRTR.7a/7b | Each bridged round emits the `NFR.OBS.4` counter with `phase="bridge"`, and **no answer body appears in any record** | I | security | Yes — the absence half is the one that rots silently, and it is asserted against the captured records, not by reading the emit sites |
| MRTR.8 | Minting a continuation that is never retried adds **nothing** to any gateway-side collection | I | resource | Yes — and the row it replaces could not fail. `ConsumedLedger` records *spent* tokens, so an abandoned one was never in it: there was nothing for a deadline to reclaim, and consuming the token to get an entry stops it being abandoned. The honest property is that abandonment costs nothing because minting stores nothing, and a design that later parked per-mint state would fail this |
| MRTR.8 | A consumed token's ledger entry does not outlive its expiry | U | resource | Yes — this is the growth the ledger *can* have, since an entry is only added on redemption |
| MRTR.8 | The ledger at capacity refuses rather than forgetting a live entry | U | security | Yes — the opposite implementation is the natural one and it reopens replay |
| MRTR.8 | The production request path — not a test harness — constructs the bounded structures and reclaims them, so a gateway built from `main` holds bounded in-flight state | I | wiring | Yes, and it is the only row here that can. The three rows above exercise `InFlight` and `ConsumedLedger` directly and they pass today: `ac_mrtr_8_the_table_is_bounded` (`tests/mik_7212_acs.rs:439`) proves the count bound and `ac_mrtr_8_an_abandoned_exchange_is_reclaimed` (`:457`) proves the lifetime bound, both against a table the test itself builds with `InFlight::new`. That is why `MIK-7212.8a` and `8b` are UNWIRED rather than failing — the mechanism is correct and nothing in the request path calls it, which no test that constructs its own table can detect. This row fails until a production call site exists, and passes for the wrong reason if it is ever written to build its own |
| MRTR.3 | A retry carrying malformed retry fields returns 400 and never reaches dispatch | I | regression | Yes — the refusal exists at `handlers.rs:884` today and this increment deletes it. A malformed retry that falls through to dispatch becomes a *fresh* call, which for a destructive tool means running it twice |
| MRTR.9 | An input request of a type the client did not declare is refused before anything is minted | I | security | COVERED by `e1713f64` — `an_undeclared_input_request_is_refused_at_the_gateway` and `a_declared_input_request_passes_the_gateway_gate` (`src/gateway/meta_mcp/tests.rs`), over six protocol cases in `tests/mik_7212_acs.rs` (`mod capability_gate`). The pair is what makes the row falsifiable: a gate that refused every interim result would pass the refusal case alone. Deleting the guard failed the refusal case on its own assertion and left the declared case green |
| MRTR.9 | End to end: a supported `inputRequests` reaches the client unchanged, the client answers, and the retry returns the backend's completed result | E | positive | Yes — every other row checks one edge of the exchange; this is the only one that fails if the pieces are individually right and do not compose |
| MRTR.10 | An `input_required` result leaves **no** idempotency entry — not `Completed`, and not a live `InFlight` | I | security | Yes — declining to complete while leaving `InFlight` passes a naive version of this row, so the case asserts the entry is *absent* |
| MRTR.10 | Two retries differing only in `requestState` derive different idempotency keys, and a retry's key differs from its originating call's | U | positive | Yes — `derive_key` hashes `arguments` (idempotency.rs:296) and the retry fields are siblings of it, so a key built from `arguments` alone collides across both pairs |
| MRTR.10 | A second caller with identical arguments reaches the backend rather than the first caller's interim answer | I | security | Yes |
| MRTR.10 | A backend answering `input_required` a *second* time, on the retry, is refused rather than minted again | I | boundary | Yes — the payload carries no round counter, so the cap exists only if this refusal does |

### What the map deliberately leaves out

Four notes, so that absences read as decisions rather than oversights.

- The continuation keyring and the `ConsumedLedger` are constructed **together, as one owner in
  `AppState`**, and that construction is part of the first commit beside the asking backend. Two
  independently built halves is the failure the keyring row above exists to detect, and it is
  cheaper to make unbuildable than to test for.
- `tests/mik_7212_acs.rs` is already green. It is **pre-existing U evidence** about the envelope
  primitives, not coverage of this increment: every row above is red against `handlers.rs` today,
  and a map that counted the existing file would be ticked off by a suite with no production call
  site behind it.
- A malformed retry still returns 400 and never reaches the backend. That refusal exists at
  `handlers.rs:884` today and this increment **deletes** it, so the row moves rather than
  disappearing: the guard against a destructive call running twice has to survive its own
  replacement.
- **stdio is N/A for this increment**, for the reason the discover rows already give: the modern
  path is streamable HTTP. The second dispatcher also calls `extract_tools_call_params` and will
  not carry `RetryFields`, and saying so makes it a stated limit rather than a silent gap.

### The three limits that became requirements

Three cells once read NOT YET, each naming a requirement this increment did not meet and what would
fill it. They were written as limits — stated before the tests, destined for the release notes — and the confirmation pass showed
that reading would not hold: all three requirements say **MUST**, and a limit against a MUST is an
unmet requirement in better clothes. So the operator was asked, and on 2026-08-30 held the release
for all three.

They are therefore no longer this increment's business, and neither are they gaps. Each is filled by
work that lands **before** this suite is called complete. MRTR.5 and MRTR.6 are now covered by the
rows above: MIK-7312's design settles them with per-process key material rather than a shared
ledger, so a continuation opens only on the replica that minted it and every other replica refuses
without evaluating. MRTR.7 remains NOT YET, filled by wiring the legacy bridge, which gets its own
design, review and test plan. The
distinction that matters is unchanged — a limit is written down before the tests are, a gap is
discovered by whoever deploys it. These three were written down, and that is what let them be
questioned before anyone deployed anything.

### What would make this increment's suite dishonest

Two shapes, both cheap to build by accident:

- **A fixture that answers the question itself.** If the fixture backend completes on the first
  call rather than asking, every response-side row goes green while the feature does nothing. The
  fixture must be asserted to have asked — a test on the test.
- **A binding test whose two callers are the same caller.** The MRTR.4 rows compare a token
  against a principal; if the harness builds both from one credential, the comparison is between a
  value and itself and no binding is being checked at all. Each of those rows needs two genuinely
  different principals constructed independently. MRTR.3 is the tamper case and does not have this
  problem — it flips a byte.

---

## Later increments — planned, not yet detailed

Listed so the shape of the whole is visible and so no increment is quietly dropped. Each gets its own
row set before its code is written, not before the release ends.

| Increment | Requirements | Note |
|---|---|---|
| 2 — Stateless dispatch | STATELESS.1–8 | Needs the dual-era fixture pair from increment 1 |
| 3 — Headers | HEADER.1–6 | HEADER.6 is a security case: a mismatched header must not reach authorization |
| 4 — Results, errors, cache fields | RESULT.\*, ERROR.\*, CACHE.\*, ORDER.\* | CACHE.2 needs two principals and a shared cache to be a real test |
| 5 — MRTR and the bridge | MRTR.1–10 | **Detailed below.** Design: `docs/design/2026-08-30-mrtr-wiring.md`, reviewed to SHIP |
| 6 — Controls that must survive | CONFIRM.\*, TENANT.\*, CONTROL.1–5 | Every case asserts a **refusal**, never a computed value |
| 7 — Identity | IDENT.1–5 | IDENT.1 is negative-first: a forged `clientInfo` must change no authorization outcome |
| 8 — Subscriptions | SUB.1–4 | Follows increment 6; the multiplexer is session-keyed today |
| 9 — Authorization server | OAUTH.1–3 | Independent of the rest; can run in parallel |
| 10 — Exploitation | EXT.1, OTEL.1, TASK.1, SURFACE.1, SCHEMA.1 | SURFACE.1 and PERF.2 are measurements, not tests |

## Cross-cutting suites

Two suites that no per-increment row set can express, because their subject is the interaction:

- **Conformance matrix** — one row per normative statement, crossed with role (server ‖ client), transport, revision, and outcome (positive ‖ negative). Requirement NFR.COMPAT.4 means each row is verified in both roles; a matrix filled in one role is half a matrix. The population is every normative statement in the requirements, per §9 acceptance 2 — **not** only the statements the 2026-07-28 changelog introduces, which this line previously said. That narrowing would have dropped NFR.COMPAT.1 and NFR.COMPAT.2 from the matrix entirely: both are about revisions *older* than 2026-07-28, so neither is a statement the changelog contains, and backward compatibility in both roles is exactly where a missing cell costs most.
- **Era-combination matrix** — all four client×backend era pairs, each with an elicitation in flight. U8 promoted from a one-off probe to a permanent suite, because the pairs are exactly what regresses silently.

## What would make this plan wrong

Stated so a reviewer has something to disagree with:

- If `server/discover` cannot be answered before a session exists on the HTTP path without restructuring request handling, increment 1 is not additive and its ordering is wrong.
- ~~If the 3.5.0 golden fixture cannot be captured — because the handshake response embeds a timestamp, a session id or any per-run value — DISCOVER.3 needs a normalising comparison.~~ **Checked 2026-08-29, and it is capturable.** `handle_initialize` (`src/gateway/meta_mcp/mod.rs:955-996`) returns `build_initialize_result(negotiated_version, &instructions)`; the instructions derive from the backend registry's tool counts, and nothing in the path reads a clock, a session id or a random source. Given a fixed registry the response is deterministic.

  Two consequences, both simplifications. The golden does **not** need capturing from a built 3.5.0 binary: this branch carries no code change yet, so the current tree *is* 3.5.0 for this purpose, and the fixture is captured in-process from `handle_initialize` before the first line of discovery code is written.

  **But it moves with Cargo features.** Under `spec-preview` the handshake advertises `capabilities.tools.filtering` and `.resolve` (`src/gateway/meta_mcp/spec_preview.rs`), so one golden is one feature set. The fixture MUST pin the feature set it was captured under, and the test MUST fail rather than pass when run under a different one — otherwise the regression row silently stops comparing, which is the failure mode this row exists to prevent.
