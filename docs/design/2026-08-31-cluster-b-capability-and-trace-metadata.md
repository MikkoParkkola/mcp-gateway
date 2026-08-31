# Cluster B — extension declaration and trace metadata (MIK-7272 EXT.1, OTEL.1)

Status: §P1 design, awaiting dual-vendor review. No code. No test plan (§P2 follows review).

Evidence base: every `file:line` below is read from commit `5c7e64f4` (`git show 5c7e64f4:<path>`),
not from the working tree — four other sessions hold uncommitted edits in this checkout, so a
line read live may be someone's unmerged change. Spec citations are the MCP core schema for
protocol revision `2026-07-28`, fetched 2026-08-31 from
`raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.json`
(181,835 bytes) and queried by parsing `$defs`.

## 1. Problem

Two acceptance criteria, both `UNWIRED` in `docs/requirements/RELEASE-4.0.0-criteria-status.md:158-159` @ `5c7e64f4`:

- **EXT.1** — the gateway MUST declare its own extensions through server capabilities'
  `extensions` field, honouring a client that does not support one.
- **OTEL.1** — `traceparent`, `tracestate` and `baggage` MUST be propagated through `_meta`
  across the gateway hop.

Both follow the pattern `docs/requirements/RELEASE-4.0.0-criteria-status.md:162` already names: a working, unit-tested mechanism
with a comment admitting it has no production caller. The mechanisms exist; nothing calls them.

**EXT.1 today.** `src/protocol/extensions.rs` (117 lines) is complete and unreachable:
`Extension::Tasks` maps to `"io.modelcontextprotocol/tasks"` (:19-34), `gateway_declares()`
(:60) builds the declaration, `from_capabilities()` (:71) parses a peer's, `negotiate()` (:107)
intersects the two. Its own doc comment says nothing calls `gateway_declares()` in 4.0.0 and to
wire it as part of MIK-7311. Confirmed at the commit, not the dirty tree:
`git grep gateway_declares 5c7e64f4 -- src` matches only `extensions.rs` itself.

The blocking gap is one field. `ServerCapabilities` (`src/protocol/types.rs:232`) has
`completions`, `experimental`, `logging`, `prompts`, `resources`, `tasks`, `tools` — and **no
`extensions` field**. Nothing in the type system can serialise a declaration, so EXT.1 cannot be
closed by calling `gateway_declares()` from anywhere; the wire struct has nowhere to put it.

**OTEL.1 today.** `src/protocol/trace.rs` (80 lines) reads `traceparent` from an inbound `_meta`
(:32), strictly validating the four hex parts, copies `tracestate` verbatim with no validation
and no length bound, and re-emits both unchanged in `to_meta()` (:71). Its module comment states
the invariant: propagated, never re-minted, because a gateway that started a fresh trace would
make its own hop the root and hide the caller. `baggage` appears nowhere in `src` at the commit.
Nothing calls `TraceContext` from the request path, and the outbound backend call
(`dispatch_to_backend`, `src/gateway/meta_mcp/invoke.rs:1812`+) writes exactly one `_meta` key —
the prompt cache key (:1936-1938) — so no trace metadata crosses the hop today.

## 2. Measured constraints

### 2.1 The core schema settles the shape of a declaration

Queried against the `2026-07-28` schema `$defs`:

- `ServerCapabilities.properties` = `completions, experimental, extensions, logging, prompts,
  resources, tools`. **There is no `tasks` member.**
- `ClientCapabilities.properties` = `elicitation, experimental, extensions, roots, sampling`.
  **There is no `tasks` member.**
- `ServerCapabilities.extensions` is `{"type":"object","additionalProperties":{"$ref":"#/$defs/JSONObject"}}`,
  described as: keys are extension identifiers (the example given is `io.modelcontextprotocol/tasks`),
  values are per-extension settings objects, an empty object indicates support with no settings,
  and keys MUST follow the `_meta` key naming rules **with a mandatory prefix**.

Three consequences, all load-bearing:

1. Extension support is declared **only** through `extensions`. The gateway's `extensions.rs`
   already encodes exactly this shape — object-valued entries keyed by reverse-DNS id.
2. `ServerCapabilities.tasks` (`types.rs:250`, struct at :262) and `ClientCapabilities.tasks`
   (`types.rs:346`, struct at :374) are **not in the spec**. They are a locally invented second
   declaration surface for the same capability the `tasks` extension declares. Neither has a user
   beyond its own definition at the commit.
3. Presence of a key is not agreement. `from_capabilities()` requiring object values matches the
   schema; a client that omits the key has not agreed to anything.

### 2.2 The core schema does not name the trace keys

`traceparent`, `tracestate` and `baggage` occur **zero times** in the `2026-07-28` schema. The
key spelling therefore comes from SEP-414, which `trace.rs:1-13` cites, not from the core schema.

Related and settled: the schema's `MetaObject` definition makes a `_meta` prefix **optional** in
general (`Prefix: Optional — if specified, MUST be a series of labels…`); the mandatory-prefix
rule quoted in 2.1 is specific to `extensions` keys. So the bare `traceparent` key that
`trace.rs:32` reads is a legal `_meta` key. It is inconsistent with this gateway's own convention
— every other `_meta` key in the tree is reverse-DNS (`src/protocol/meta.rs:41-50`) — but that is
a convention choice, not a spec violation. Which spelling the wire actually carries is §4.1.

### 2.3 One capabilities builder feeds two entry points

`build_initialize_result(negotiated_version, instructions)`
(`src/gateway/meta_mcp_helpers.rs:144-176`) is the single place `ServerCapabilities` is
constructed. Its result is returned by `initialize` and is also embedded verbatim as the
`capabilities` member of the `server/discover` response (`src/gateway/meta_mcp/mod.rs:989`,
emitted at :1014-1021). Declaring in one and not the other is not reachable from here: both read
the same builder.

### 2.4 Per-request client capabilities are already read

`src/protocol/meta.rs:44` defines `KEY_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"`,
and `classify_request` (:117, reading it at :137) already extracts it from an inbound request
body. The gateway therefore already performs the read that per-request extension gating needs;
it discards the extensions half.

### 2.5 Two further trace implementations exist, with conflicting invariants

`src/tracing_context/` (663 lines, "Distributed tracing for tool call chains — Issue #63") is an
HTTP-header trace stack: `TraceParent::new_root()`, `parse()`, `to_header_value()`,
`SpanContext::new_root()`, `child_of()`, `inject_headers()`. It **mints** root and child spans —
the exact opposite of `trace.rs`'s stated invariant. It is unwired: the only reference at the
commit is `src/lib.rs:84 pub mod tracing_context;`.

A **third** trace surface is live on the meta-MCP path: `augment_with_trace`
(`src/gateway/meta_mcp/support.rs:266`, called from `src/gateway/meta_mcp/invoke.rs:812`, `:856`
and `:1347`) inserts a top-level `"trace_id"` into the result returned **to the client**. That id
is minted by the gateway as a correlation handle — its own comment records that the `trace_id` is
always inserted. It is neither W3C-formatted nor `_meta`-carried, so it is not a competing
implementation of OTEL.1's carrier, but it is a third place the word "trace" means something
different. OTEL.1 must state which of the three owns the wire format, or the next reader picks
one at random.

### 2.6 The second route does not carry `_meta` at all

`POST /mcp/{name}` (registered `src/gateway/router/mod.rs:236`, handler
`src/gateway/router/backend_handlers.rs:432`) bypasses
`invoke_tool_traced` entirely. SUB.4's design already recorded this bypass and the fact that no
ADR sanctions it. OTEL.1 inherits it: any `_meta`-carried trace context covers the meta-MCP route
and not the direct route.

## 3. Options considered

### 3.1 EXT.1 — where the declaration lives

| option | verdict |
|---|---|
| **A. Add `extensions` to `ServerCapabilities`; populate from `gateway_declares()` in `build_initialize_result`; retire the non-spec `tasks` capability structs.** | **Chosen.** One builder (2.3) means one edit covers both `initialize` and `server/discover`. The spec has exactly one declaration surface (2.1), so a second one cannot be right. |
| B. Add `extensions`, keep `ServerCapabilities.tasks` as well. | Rejected. Two surfaces declaring one capability is the defect §P0's repair protocol says to eliminate, not to patch: a client reading `tasks` and a client reading `extensions` can be told different things, and nothing keeps them equal. `tasks` is also not in the schema, so it is unreadable by a conforming client. |
| C. Declare only in `server/discover`, per TASK.1 §3.5. | Rejected as under-specified rather than wrong. Both entry points share `build_initialize_result` (2.3), so "declare in discover" and "declare in initialize" are the same edit. Declaring only in discover would require *removing* the field for the `initialize` path, leaving a legacy client blind to an extension the gateway supports. |
| D. `experimental` instead of `extensions`. | Rejected. `extensions` is the field the criterion names and the field the schema defines for this purpose. |

### 3.2 EXT.1 — honouring a client that does not support an extension

`extensions.rs:9-13` already records the intended stance: the spec requires the supporting party
either to revert to core behaviour or to reject, and this gateway reverts, because rejecting
would refuse a conforming client. The design adopts that recorded intent unchanged.

| option | verdict |
|---|---|
| **A. Intersect the gateway's declaration with the peer's, per connection at `initialize` and per request from `KEY_CLIENT_CAPABILITIES`; absent extension ⇒ core behaviour.** | **Chosen.** `negotiate()` (:107) is exactly this intersection and already exists; the per-request read already exists (2.4). Absent key ⇒ empty set ⇒ core path, which is the revert branch. |
| B. Reject a request that uses an extension the client did not declare. | Rejected. Contradicts the recorded stance in `extensions.rs:9-13` and refuses conforming clients. |
| C. Connection-scoped negotiation only. | Rejected. The gateway's modern path is per-request (`classify_request`); a stateless HTTP client never performs `initialize`, so connection-only negotiation is unreachable for it. |

### 3.3 OTEL.1 — carrier

`_meta` is already the decided protocol-native carrier for gateway-internal metadata (SUB.4,
`docs/design/2026-08-31-sub-4-idempotency-wiring.md`): it survives stdio, and it adds nothing to
any backend tool's advertised schema. OTEL.1 reuses that decision rather than re-opening it. The
alternative of a tool argument was rejected there for the same reason it would be rejected here,
and an HTTP header cannot work on the stdio transport.

### 3.4 OTEL.1 — what crosses the hop, and what does not

The criterion says all three fields MUST be propagated. Dropping `baggage` would be an unmet MUST
presented as an honest limit, so the design propagates it — **opaque, bounded, and inert**.

**Trust boundary, stated explicitly.** `traceparent`, `tracestate` and `baggage` arrive on an
inbound request. They are attacker-influenced input, from any client that can reach the gateway.
Everything below follows from that:

- **Forwarded:** the three W3C fields, byte-for-byte as received, into the outbound request's
  `_meta`, alongside the existing cache key (2.6 names the one write site).
- **Never interpreted:** no value from any of the three may reach routing, backend selection,
  tool selection, authorisation, policy evaluation, cache keys, budget accounting, or any log
  field used as an identifier for those decisions. They are transport-visible only.
- **Never minted:** absent or malformed inbound context yields *no* outbound trace `_meta` — not
  a fresh root. This is `trace.rs`'s stated invariant and it is also a security property: a
  gateway that minted a root would launder unauthenticated input into a trusted-looking identity.
- **Validated on the way in:** `traceparent` is already strictly parsed (:32-63). `tracestate`
  is currently copied verbatim with no validation and **no length bound** — the same defect the
  new `baggage` field would otherwise introduce. Both get a bounded, charset-checked read; a
  field that fails the check is **dropped**, not repaired, and its absence does not fail the
  request. Concrete bounds are §4.2.
- **Not forwarded:** any other inbound `_meta` key. The gateway already strips peer-supplied
  `_meta.provenance` from backend responses (`src/gateway/meta_mcp/invoke.rs:472`), which is the
  in-tree precedent for refusing to relay what a peer put in `_meta`.

| option | verdict |
|---|---|
| **A. Propagate all three, opaque and bounded, never interpreted.** | **Chosen.** Meets the MUST; the bound and the no-interpretation rule are what make relaying attacker input safe. |
| B. Propagate `traceparent`/`tracestate`, drop `baggage`. | Rejected. Unmet MUST. Dropping a criterion needs the requester's recorded agreement in advance, which does not exist. |
| C. Parse `baggage` into typed pairs and expose them to policy. | Rejected. Turns attacker-controlled key/value pairs into inputs to gateway decisions — the injection surface this section exists to close. |
| D. Re-mint a span per hop for a clean parent/child tree. | Rejected. Contradicts `trace.rs:12-13`, hides the caller, and is the launder-the-input failure above. |

### 3.5 OTEL.1 — one owner of trace identity

Two of the three surfaces in 2.5 hold opposite invariants about minting, and the repair
protocol's default on an architecture finding is elimination, not a patch. The third,
`augment_with_trace`, is not a competing propagation implementation and survives — but only if
OTEL.1 says so, because its field is also called `trace_id`.

| option | verdict |
|---|---|
| **A. `src/protocol/trace.rs` is the sole owner of W3C trace propagation for the gateway hop; `src/tracing_context/` is deleted; `augment_with_trace` is documented as a gateway-minted correlation id, explicitly not W3C propagation.** | **Chosen, subject to §4.3.** `tracing_context` is unwired (one `pub mod` line), header-based where the criterion says `_meta`, and mints roots where the protocol path must not. `augment_with_trace` is live and client-facing, so it is renamed in documentation rather than in code, which would be a behaviour change outside this ticket. |
| B. Keep both, one for headers and one for `_meta`. | Rejected. Two modules that disagree about whether a hop may create a trace identity will eventually be called from the same request, and the answer will depend on which one ran. |
| C. Build OTEL.1 on `tracing_context` instead. | Rejected. Wrong carrier, wrong invariant. |

## 4. Unknowns

Each is either resolved with a recorded answer, or deferred with an owner, a resolving action, a
trigger and a bad-resolution consequence. Nothing is left as a risk paragraph.

### 4.1 Resolved

| question | what was run | what came back | what it changed |
|---|---|---|---|
| Does `2026-07-28` `ServerCapabilities` define `extensions`? | Fetched the schema, parsed `$defs.ServerCapabilities.properties` | Yes — `extensions`, object-valued, keys are prefixed extension ids | Made option 3.1.A the only spec-conforming answer and fixed the field's exact shape |
| Does it define `ServerCapabilities.tasks`? | Same query | **No.** `completions, experimental, extensions, logging, prompts, resources, tools` | Turned `types.rs:250/262` from "existing capability" into a non-spec second surface, and made its retirement part of EXT.1 rather than a separate cleanup |
| Does `ClientCapabilities` carry `extensions`? | Same query | Yes; and it has no `tasks` member either | Confirmed 3.2.A reads the peer's declaration from the field `from_capabilities()` already parses |
| Does the core schema name `traceparent`/`tracestate`/`baggage`? | Substring count over the fetched schema | Zero occurrences of all three | Established that key spelling comes from SEP-414, not the core schema → 4.2 |
| Is a bare (unprefixed) `_meta` key legal? | Read `$defs.MetaObject.description` | Prefix is **optional** in general; mandatory only for `extensions` keys | `trace.rs:32`'s bare `traceparent` is spec-legal, so the spelling question is a convention/SEP question, not a violation |
| Are `gateway_declares` / `ServerTasksCapability` / `tracing_context` genuinely unwired, or does the dirty tree hide a caller? | `git grep` for each at `5c7e64f4`, not in the working tree | Matches only in their own defining files, their tests, and `lib.rs:84` | Confirmed the three "no production caller" claims against the commit rather than against four sessions' uncommitted edits |

### 4.2 Deferred — exact wire spelling and bounds for the trace fields

| field | value |
|---|---|
| owner | this ticket's implementer, before any emit-side constant is written |
| what would resolve it | read SEP-414 itself for the `_meta` key spelling (bare vs `io.modelcontextprotocol/`-prefixed) and for whether `baggage` is named there; take the W3C `tracestate`/`baggage` limits (member count and total length) as the bound |
| when | at the start of §P2, before the test plan fixes expected keys — a test that pins the wrong key passes and proves nothing |
| what if it resolves badly | if SEP-414 mandates prefixed keys, `trace.rs:32`'s bare read is wrong on the wire and the read side changes with it; the design's fail-safe is to **accept both spellings on read and pin exactly one on emit**, so a mis-resolved spelling costs a constant, not a redesign |

Nothing in this design depends on that answer beyond the value of two string constants and the
numeric bounds; the trust boundary in 3.4 holds under either spelling.

### 4.3 Deferred — disposal of `src/tracing_context/`

| field | value |
|---|---|
| owner | this ticket's implementer; deletion needs the operator's agreement (see 4.4.2) |
| what would resolve it | confirm at merge time that the module still has no caller outside `lib.rs:84`, and that Issue #63's intent is either dead or subsumed by the `_meta` path |
| when | before OTEL.1's implementation commit, so the tree never holds two live trace owners |
| what if it resolves badly | if a caller appears or the operator keeps it, OTEL.1 still ships on `trace.rs`, and `tracing_context` must gain a comment naming `trace.rs` as the owner for the gateway hop and itself as header-scoped only — the ambiguity is what must not survive, not necessarily the code |

### 4.4 Operator-only — collected, not answered

These cannot be settled by running anything. They are reported, not assumed, and no answer has
been invented for any of them.

1. **Is retiring `ServerCapabilities.tasks` / `ClientCapabilities.tasks` (`types.rs:250`, `:346`)
   in scope for EXT.1?** They are not in the `2026-07-28` schema, they have no users, and they
   compete with the `extensions` declaration TASK.1 depends on. Removing a public type is an API
   change; keeping it means shipping two answers to one question. This blocks 3.1.A's third clause.
2. **May `src/tracing_context/` be deleted (4.3)?** 663 lines, unwired, attached to Issue #63,
   with an invariant opposite to the protocol path's.
3. **Does the direct route `POST /mcp/{name}` need trace propagation in this ticket, or does
   OTEL.1 close on the meta-MCP route alone?** This is the same two-route question SUB.4 already
   put to the operator and which is still unanswered; OTEL.1 inherits it rather than re-asking it.
   If the answer for SUB.4 is "both routes", OTEL.1's scope grows with it.
4. **Is `baggage` propagation acceptable at all, given 3.4?** The design propagates it because the
   criterion says MUST. If the operator would rather not relay attacker-influenced key/value pairs
   to backends, that is a criterion change and needs recording before implementation, not a
   limitation noted afterwards.

## 5. Explicitly out of scope

- **Building the tasks extension itself.** TASK.1 owns `tasks/*` behaviour. EXT.1 owns only the
  declaration surface it is announced through.
- **Trace propagation on `POST /mcp/{name}`** until 4.4.3 is answered. The bypass is recorded
  (2.6), not designed around.
- **Any tracing backend, exporter, sampler or span emission.** OTEL.1 is propagation of three
  fields across one hop, nothing more. No OpenTelemetry SDK is introduced.
- **Interpreting trace metadata anywhere in the gateway** (3.4) — permanently out, not deferred.
- **Header-based tracing between gateway and backend.** `_meta` is the carrier; headers are a
  separate question that dies with 4.3 if `tracing_context` goes.
- **Extensions other than `io.modelcontextprotocol/tasks`.** `Extension` (`extensions.rs:19`) has
  one variant; adding more is a later change.
- **Changing `_meta` conventions repo-wide.** The bare-vs-prefixed inconsistency (2.2) is stated
  as a finding; harmonising every other key is not this change.
- **The test plan.** §P2 follows this review.

## 6. Findings raised, not designed around

Recorded here so they survive between revisions of this document.

| # | finding | disposal |
|---|---|---|
| F1 | `ServerCapabilities.tasks` / `ClientCapabilities.tasks` (`types.rs:250`, `:262`, `:346`, `:374`) are **not in the `2026-07-28` schema** and are a second declaration surface competing with `extensions`. TASK.1's design is silent on them. | Fix inside this change if the operator agrees (4.4.1); otherwise write into TASK.1's design as an accepted duplicate with a named owner. Not silently kept. |
| F2 | TASK.1 §3.5 says `gateway_declares()` is called from `server/discover`, "which is EXT.1's job". Both `initialize` and `server/discover` are fed by one builder (2.3), so the stated call site is narrower than the real one. | Under-specification, not a contradiction. Fixed in this design by declaring in `build_initialize_result`, which satisfies TASK.1's dependency for both entry points. TASK.1 needs a one-line correction. |
| F3 | Three surfaces use "trace" with different meanings: `src/protocol/trace.rs` (forwards, never mints, `_meta`), `src/tracing_context/` (mints roots, HTTP headers, unwired), and `augment_with_trace` (`support.rs:266`, mints a client-facing correlation `trace_id`, live). | 4.3 — eliminate `tracing_context`, or make ownership explicit in code. `augment_with_trace` stays but is named as correlation-only, not W3C propagation. Operator decision at 4.4.2. |
| F4 | `tracestate` is copied verbatim with no validation and no length bound (`trace.rs:56`+), today, before `baggage` exists. | Fixed inside this change: 3.4 bounds both fields, not just the new one. |
| F5 | The bare `traceparent` / `tracestate` `_meta` keys are inconsistent with every other `_meta` key in the tree, which is reverse-DNS (`meta.rs:41-50`). Legal per `MetaObject`, but a convention split. | 4.2 resolves the emit spelling from SEP-414; the read side accepts both. Repo-wide harmonisation is out of scope (§5). |
| F6 | `POST /mcp/{name}` carries no `_meta` and bypasses `invoke_tool_traced`, with no ADR sanctioning it — inherited from SUB.4, whose carrier question is still unanswered. | Inherited dependency, not re-asked. Recorded at 4.4.3. |

## 7. What closing these criteria requires

EXT.1: `ServerCapabilities` gains `extensions`; `build_initialize_result` populates it from
`gateway_declares()`; the per-request path intersects it with the client's declaration via
`negotiate()` and falls back to core behaviour when an extension is absent; F1 is disposed of.

OTEL.1: the three W3C fields are read from the inbound `_meta`, bounded and validated, and
written unchanged into the outbound `_meta` at the one site that already writes it, never minted,
never interpreted; F3 and F4 are disposed of.

Both are wiring plus one struct field plus one deletion. Neither is new machinery — which is the
same observation `docs/requirements/RELEASE-4.0.0-criteria-status.md:162` makes about this whole
cluster, and the reason the estimate should not grow beyond it.
