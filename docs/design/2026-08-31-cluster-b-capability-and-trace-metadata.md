# Cluster B — extension declaration and trace metadata (MIK-7272 EXT.1, OTEL.1)

Status: §P1 design, awaiting dual-vendor review. No code. No test plan (§P2 follows review).

Evidence base: every `file:line` below is read from commit `5c7e64f4` (`git show 5c7e64f4:<path>`),
not from the working tree — four other sessions hold uncommitted edits in this checkout, so a
line read live may be someone's unmerged change. Spec citations are the MCP core schema for
protocol revision `2026-07-28`, fetched 2026-08-31 from
`raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.json`
(181,835 bytes) and queried by parsing `$defs`. `main` is mutable; the bytes reviewed are pinned by
that size and by the `$defs` extracts quoted in 2.1. SEP-414 is cited at its immutable permalink
(4.1), not at a branch tip.

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
(:32), checking the four hex parts against a predicate that is looser than the W3C grammar in
three places and stricter in one (3.4b), copies `tracestate` verbatim with no validation
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
a convention choice, not a spec violation. SEP-414 settles which spelling the wire carries: bare.
See 4.1.

### 2.3 One capabilities builder feeds two entry points

`build_initialize_result(negotiated_version, instructions)`
(`src/gateway/meta_mcp_helpers.rs:144-176`) is the single place `ServerCapabilities` is
constructed. It has two production callers: `discover_document`
(`src/gateway/meta_mcp/mod.rs:1003`) and `handle_initialize` (`mod.rs:1084`). Its result is
returned by `initialize` and is also embedded verbatim as the `capabilities` member of the
`server/discover` response (assigned `mod.rs:1037`). Declaring in one and not the other is not
reachable from here: both read the same builder. Line anchors in this section were re-read at
`fb994c43`; the file has moved twice during this review, so the symbol names are the durable
part and the numbers are a convenience.

### 2.4 Per-request client capabilities are already read

`src/protocol/meta.rs:44` defines `KEY_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"`,
and `classify_request` (:117, reading it at :137) already extracts it from an inbound request
body. The read exists; **its product does not carry what negotiation needs.** At `:186-190`
`classify_request` reduces the capabilities object to `declared_capabilities`, a list of
top-level *names* — `.filter(|(_, value)| !value.is_null()).map(|(name, _)| name.clone())` —
discarding every value. An `ExtensionSet` lives inside a capability's object value, so it cannot
be reconstructed from `declared_capabilities` at any later point: the data is gone before it
reaches the classifier's caller.

Consequence for 3.2: negotiation must run `from_capabilities()` against the **raw**
`_meta[KEY_CLIENT_CAPABILITIES]` object on the request body, not against
`declared_capabilities`. Treating presence of the name `extensions` in that list as agreement is
precisely the presence-is-not-agreement bug `from_capabilities()` was written to prevent (2.1,
consequence 3).

Connection-scoped negotiation is separately unavailable today: `ClientCapabilities`
(`types.rs:331-347`) has no `extensions` field, and `handle_initialize`
(`meta_mcp/mod.rs:1026-1067`) reads only the client version (:1033) and an optional profile
string (:1041-1045) — it never inspects a capabilities member of `params` at all. Wiring that
would mean a new struct field plus a new per-connection store; the per-request path needs
neither.

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
| **A. Add `extensions` to `ServerCapabilities`; populate it from the extensions this gateway can actually honour today — which is none — so the wire carries `"extensions": {}`. `gateway_declares()` stays TASK.1's payload.** | **Chosen.** One builder (2.3) means one edit covers both `initialize` and `server/discover`. The spec has exactly one declaration surface (2.1), so a second one cannot be right. An empty object is a declaration: it says *this gateway speaks the extensions mechanism and currently supports none*, which is different from omitting the field. See 3.1a for why `gateway_declares()` is not the source. |
| B. Add `extensions`, keep `ServerCapabilities.tasks` as well. | Rejected. Two surfaces declaring one capability is the defect §P0's repair protocol says to eliminate, not to patch: a client reading `tasks` and a client reading `extensions` can be told different things, and nothing keeps them equal. `tasks` is also not in the schema, so it is unreadable by a conforming client. |
| C. Declare only in `server/discover`, per TASK.1 §3.5. | Rejected as under-specified rather than wrong. Both entry points share `build_initialize_result` (2.3), so "declare in discover" and "declare in initialize" are the same edit. Declaring only in discover would require *removing* the field for the `initialize` path, leaving a legacy client blind to an extension the gateway supports. |
| D. `experimental` instead of `extensions`. | Rejected. `extensions` is the field the criterion names and the field the schema defines for this purpose. |

#### 3.1a Why not call `gateway_declares()` — the declaration must be honourable

`gateway_declares()` (`extensions.rs:60-63`) returns `supported: vec![Extension::Tasks]`
unconditionally, and its own doc comment (:51-58) says to wire it *as part of MIK-7311, not
before*. Populating `ServerCapabilities.extensions` from it would advertise
`io.modelcontextprotocol/tasks` to every client while `tasks/*` behaviour does not exist: a
client that trusts the declaration sends task-augmented calls and receives ordinary
`tools/call` results. That is a worse failure than the unwired field this criterion is about,
because it is a lie the client cannot detect.

**The invariant EXT.1 establishes, and TASK.1 inherits:** the `extensions` map is populated from
*implemented and enabled* extension handlers, never from a static list of known identifiers.
Today that set is empty. TASK.1 adds `Tasks` to it in the same change that makes the behaviour
real, and `gateway_declares()` becomes the natural source at that point — its current content is
correct for a future in which the extension is honoured, and wrong for today. EXT.1 therefore
ships the field and the rule; TASK.1 ships the first entry.

Both reviewers raised this independently, from different anchors — the module's own "not before
MIK-7311" comment and the client-facing consequence. Two vendors converging on one defect is the
signal that the mechanism was wrong, not that the citation needed tightening.

#### 3.1b The wire shape, and the one case that is red today

Only the parse side of `ExtensionSet` exists (`extensions.rs:71-90`), so the emit shape is pinned
here rather than invented by the builder: a JSON object keyed by extension identifier, each value
an object. With Tasks honoured that is `{"io.modelcontextprotocol/tasks": {}}`; today it is `{}`.

The four states this criterion has to keep apart, and what each selects:

| gateway declares | client declares | selected behaviour |
|---|---|---|
| absent (today, before this change) | anything | core; client cannot tell the mechanism is understood |
| `{}` | anything | core, and the client knows it asked a gateway that speaks the mechanism |
| identifier present | identifier absent or no `_meta` capabilities | core fallback — 3.2 |
| identifier present | identifier present | extension behaviour, after `negotiate()` |

Row two is what this change ships and row one is what it replaces, which is why the honest
red-on-HEAD case is a serialisation check: `build_initialize_result`
(`meta_mcp_helpers.rs:144`) and `discover_document` (`mod.rs:1002`) emit no `extensions` key at
all, because `ServerCapabilities` (`types.rs:232-254`) has no such field. The existing
`ac_ext_1_*` tests stay green either way, so they cannot prove EXT.1 — a test plan that only
extends them proves nothing new.

Adding the field is not the same as wiring it. `build_initialize_result` ends in
`..Default::default()` (`meta_mcp_helpers.rs:164`), so a newly added `extensions` field arrives
at its default on every response until the builder assigns it explicitly. That is a
silent-success shape: the struct change compiles, the key appears on the wire, and the value is
empty. The populate is the work; the struct change on its own closes nothing, and a test that
only asserts the key is present would pass against it.

### 3.2 EXT.1 — honouring a client that does not support an extension

`extensions.rs:9-13` already records the intended stance: the spec requires the supporting party
either to revert to core behaviour or to reject, and this gateway reverts, because rejecting
would refuse a conforming client. The design adopts that recorded intent unchanged.

| option | verdict |
|---|---|
| **A. Intersect the gateway's declaration with the peer's, per request, by running `from_capabilities()` on the raw `_meta[KEY_CLIENT_CAPABILITIES]` object; absent extension ⇒ core behaviour.** | **Chosen.** `negotiate()` (:107) is exactly this intersection and already exists. Per-request only: `classify_request`'s `declared_capabilities` cannot carry the set (2.4), and connection-scoped negotiation has neither a struct field nor a reader today. Absent key ⇒ empty set ⇒ core path, which is the revert branch. |
| B. Reject a request that uses an extension the client did not declare. | Rejected. Contradicts the recorded stance in `extensions.rs:9-13` and refuses conforming clients. |
| C. Connection-scoped negotiation at `initialize`. | Rejected, and now on stronger grounds than the original "modern path is per-request": a stateless HTTP client never performs `initialize`, *and* the code to support it does not exist — `ClientCapabilities` has no `extensions` member and `handle_initialize` never reads client capabilities (2.4). Adding both is a larger change than EXT.1 needs, and TASK.1 can add it if per-connection caching turns out to matter. |

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
  `_meta`, alongside the existing cache key. **The write must be unconditional** — see 3.4a.
- **Never interpreted:** no value from any of the three may reach routing, backend selection,
  tool selection, authorisation, policy evaluation, cache keys, budget accounting, or any log
  field used as an identifier for those decisions. They are transport-visible only.
- **Never minted:** absent or malformed inbound context yields *no* outbound trace `_meta` for
  the affected field — not a fresh root. This is `trace.rs`'s stated invariant and it is also a
  security property: a gateway that minted a root would launder unauthenticated input into a
  trusted-looking identity.
- **Per-field, not all-or-nothing.** `tracestate` is defined by W3C as an annotation *on* a
  `traceparent` and is dropped with it. `baggage` is a **separate W3C specification** with no
  dependency on trace context, so a request carrying valid `baggage` and no `traceparent` must
  still propagate its `baggage`. Suppressing all three on a missing or malformed `traceparent`
  would drop valid data from baggage-only clients — an unmet MUST reached by over-strictness
  rather than by omission.
- **One deliberate exception to "never interpreted", for the next ticket:** CONTROL.3's
  transparency-log correlation may read `TraceContext::trace_id()` as a *correlation key*
  (`docs/requirements/RELEASE-4.0.0-criteria-status.md:115` currently falls back to a hardcoded
  placeholder string when `session_id` is absent). Correlating a log line is not a trust
  decision: the id names a request, it does not authorise one. The prohibition above stands for
  routing, authorisation, policy, cache keys and budget — that list is exhaustive on purpose, and
  this carve-out is written here so CONTROL.3 does not have to argue with this design to use it.
- **Validated on the way in:** `traceparent`'s existing parse (:38-51) is *structural*, not W3C
  conformant, and this design must not describe it as strict — see 3.4b. `tracestate` is
  currently copied verbatim with no validation and **no length bound** — the same defect the new
  `baggage` field would otherwise introduce. All three get a bounded, charset-checked read; a
  field that fails the check is **dropped**, not repaired, and its absence does not fail the
  request. Numeric bounds are 4.2.
- **Not forwarded:** any other inbound `_meta` key. The gateway already strips peer-supplied
  `_meta.provenance` from backend responses (`src/gateway/meta_mcp/invoke.rs:472`), which is the
  in-tree precedent for refusing to relay what a peer put in `_meta`.

#### 3.4a The write site is conditional today — a design decision, named

`dispatch_to_backend` writes `_meta` in exactly one place, and only when a prompt cache key
exists (`invoke.rs:1934-1938`): the `None` arm passes `base_params` through with no `_meta` key
at all. Specifying OTEL.1 as "write at the site that already writes `_meta`" would therefore
propagate traces only on requests that happen to carry a cache key — a minority path — and OTEL.1
would read as met while most hops carried nothing.

The decision: inject trace `_meta` unconditionally at `dispatch_to_backend`, merging the cache
key into the same `_meta` object when one is present. Concretely, one sibling function beside
`inject_cache_key`, called on both arms.

Honest sizing: this follows the module's existing shape rather than forcing a new one —
`inject_cache_key` already takes `Option<Value>` and returns params with `_meta` populated, and
it already has four unit tests at `invoke.rs:474-503` that a sibling can be tested the same way.
It is a named decision because it changes when the gateway writes `_meta` on the backend hop, not
because it needs new machinery.

What this change can and cannot falsify, said as two claims because they have two owners. The
write site itself can go red on HEAD: a unit case beside `invoke.rs:474-503` that calls
`dispatch_to_backend` with no cache key and asserts the outbound params carry the three trace
keys fails today, for the reason 3.4a names. What is genuinely absent is an end-to-end case —
client sends `traceparent`, a real backend receives it over HTTP — because no backend-capture
harness exists in this tree. That second gap is not this cluster's to price alone: cluster B1's
stream-isolation work reaches the same missing harness. If both designs name it, it stops being
a per-cluster cost and becomes an item with an owner. Recorded here so the second discovery
happens in a design rather than in an implementation.

Also corrected here: an earlier draft pointed at §2.6 for the write site. §2.6 is the direct
route, which carries no `_meta` at all. The write site is `dispatch_to_backend` on the meta-MCP
route (§1).

#### 3.4b The existing `traceparent` parse is structural, not W3C-compliant

Verified against `trace.rs:38-51` at the commit. The parser splits on `-`, requires exactly four
parts, checks each part's length and `is_ascii_hexdigit()`, and rejects an all-zero `trace_id`.
Four consequences, each read from the code:

| input | W3C says | this parser does |
|---|---|---|
| uppercase hex | invalid — lowercase only | accepts (`is_ascii_hexdigit` matches both cases) |
| version `ff` | invalid — reserved | accepts (only length and hex are checked) |
| all-zero `parent-id` (span id) | invalid | accepts (only `trace_id` is zero-checked, :49-51) |
| future version with more than four fields | valid — read the first four, ignore the rest | rejects (`if parts.len() != 4`) |

So it forwards two classes of invalid context and drops a class of valid future context. This is
not a defect OTEL.1 introduces, but OTEL.1's drop-not-repair rule depends on the check being
right: a parser that accepts garbage propagates garbage, and one that rejects valid input
silently deletes real traces. It is therefore mine, not separable.

Disposal: fixed inside this change, not deferred. Lowercase-only; reject `ff`; reject an all-zero
`parent-id`; accept four-or-more fields, reading the first four and ignoring the rest. Four
predicate changes in one function, one test row each.

| option | verdict |
|---|---|
| **A. Propagate all three, opaque and bounded, never interpreted; `baggage` independent of trace context.** | **Chosen.** Meets the MUST; the bound and the no-interpretation rule are what make relaying attacker input safe. |
| B. Propagate `traceparent`/`tracestate`, drop `baggage`. | Rejected. Unmet MUST. Dropping a criterion needs the requester's recorded agreement in advance, which does not exist. |
| E. Propagate all three, but suppress every field when `traceparent` is absent or rejected. | Rejected. Simpler to state and wrong: `baggage` is its own W3C spec with no trace-context dependency, so this drops valid data from baggage-only clients — an unmet MUST reached by over-strictness. |
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
| Does the core schema name `traceparent`/`tracestate`/`baggage`? | Substring count over the fetched schema | Zero occurrences of all three | Established that key spelling comes from SEP-414, not the core schema; settled by the SEP-414 row above |
| Is a bare (unprefixed) `_meta` key legal? | Read `$defs.MetaObject.description` | Prefix is **optional** in general; mandatory only for `extensions` keys | `trace.rs:32`'s bare `traceparent` is spec-legal, so the spelling question is a convention/SEP question, not a violation |
| What key spelling does SEP-414 mandate for the three trace fields, and is `baggage` named there? | Read SEP-414 itself, at its merged permalink `github.com/modelcontextprotocol/modelcontextprotocol/blob/622a9b4aa58113abcac1782c31c72af3f2819f7c/seps/414-request-meta.md` (PR #414, labelled `SEP, final`, closed) | Status **Final**. All three keys are named, and the text makes them "an exception to the DNS prefixing convention for keys in `_meta`" — **bare** `traceparent`, `tracestate`, `baggage`, following W3C value formats | Resolved the spelling this design had deferred: emit bare keys, matching what `trace.rs:32` already reads. The accept-both-spellings fallback is deleted — there is no second spelling to accept |
| Is `trace.rs`'s `traceparent` parse actually W3C-strict, as an earlier draft claimed? | Read `trace.rs:38-51` at the commit and compared each predicate against the W3C rules | No. Accepts uppercase hex, accepts version `ff`, accepts an all-zero span id; rejects valid future versions carrying more than four fields | Turned "already strictly parsed" into 3.4b, and moved the fix inside this change rather than leaving a check OTEL.1's drop rule depends on |
| Are `gateway_declares` / `ServerTasksCapability` / `tracing_context` genuinely unwired, or does the dirty tree hide a caller? | `git grep` for each at `5c7e64f4`, not in the working tree | Matches only in their own defining files, their tests, and `lib.rs:84` | Confirmed the three "no production caller" claims against the commit rather than against four sessions' uncommitted edits |

### 4.2 Deferred — numeric bounds for `tracestate` and `baggage`

The key spelling is no longer open: 4.1 records SEP-414 as Final and the keys as bare. What
remains is the size limit each bounded read enforces.

| field | value |
|---|---|
| owner | this ticket's implementer, before the first bounded-read constant is written |
| what would resolve it | take the limits from the W3C specs SEP-414 defers to — `tracestate` member count and total length, `baggage` total length — and pin each as a named constant carrying its provenance |
| when | with the test plan, so the boundary rows assert a real number rather than a placeholder |
| what if it resolves badly | a bound set too low drops valid context from a conforming client; too high, it relays more attacker-influenced bytes than needed. Both are one constant, and the drop-not-repair rule means neither can fail a request |

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
- **The rest of the W3C `traceparent` grammar.** The four predicates in 3.4b came into scope with F7, and that is a scope move recorded here: the drop-rather-than-forward rule depends on rejecting the right input, so the check that decides it belongs to this change. Everything else in `trace.rs` stays out — later versions carrying more than four parts, and `tracestate` grammar beyond the length bound (4.2).
- **The test plan.** §P2 follows this review.

## 6. Findings raised, not designed around

Recorded here so they survive between revisions of this document.

| # | finding | disposal |
|---|---|---|
| F1 | `ServerCapabilities.tasks` / `ClientCapabilities.tasks` (`types.rs:250`, `:262`, `:346`, `:374`) are **not in the `2026-07-28` schema** and are a second declaration surface competing with `extensions`. TASK.1's design is silent on them. | Not a condition of closing EXT.1 (see 7). Fix inside this change only if the operator answers 4.4.1 yes; otherwise write into TASK.1's design as an accepted duplicate with a named owner. Not silently kept. |
| F2 | TASK.1 §3.5 says `gateway_declares()` is called from `server/discover`, "which is EXT.1's job". Both `initialize` and `server/discover` are fed by one builder (2.3), so the stated call site is narrower than the real one. | Under-specification, not a contradiction. Fixed in this design by declaring in `build_initialize_result`, which satisfies TASK.1's dependency for both entry points. TASK.1 needs a one-line correction. |
| F3 | Three surfaces use "trace" with different meanings: `src/protocol/trace.rs` (forwards, never mints, `_meta`), `src/tracing_context/` (mints roots, HTTP headers, unwired), and `augment_with_trace` (`support.rs:266`, mints a client-facing correlation `trace_id`, live). | 4.3 — make ownership explicit in code; deleting `tracing_context` stays operator-gated and is not a condition of closing OTEL.1 (see 7). `augment_with_trace` stays but is named as correlation-only, not W3C propagation. Operator decision at 4.4.2. |
| F4 | `tracestate` is copied verbatim with no validation and no length bound (`trace.rs:56`+), today, before `baggage` exists. | Fixed inside this change: 3.4 bounds both fields, not just the new one. |
| F5 | The bare `traceparent` / `tracestate` `_meta` keys are inconsistent with every other `_meta` key in the tree, which is reverse-DNS (`meta.rs:41-50`). Legal per `MetaObject`, but a convention split. | 4.1 resolves it: SEP-414 is Final and makes these keys an explicit exception to the reverse-DNS convention. One spelling on both sides, bare. Repo-wide alignment of the other keys is out of scope (§5). |
| F6 | `POST /mcp/{name}` carries no `_meta` and bypasses `invoke_tool_traced`, with no ADR sanctioning it — inherited from SUB.4, whose carrier question is still unanswered. | Inherited dependency, not re-asked. Recorded at 4.4.3. |
| F7 | `trace.rs:38-51` accepts uppercase hex, version `ff`, and an all-zero `parent-id`, and rejects any future-version `traceparent` carrying more than four fields. An earlier draft of this design called that parse strict. | Fixed inside this change (3.4b). OTEL.1's drop-not-forward rule is only as good as the predicate that decides what is invalid, so this is not separable from the criterion. |
| F8 | The one site that writes outbound `_meta` (`invoke.rs:1934-1938`) writes it only when a prompt-cache key is present; the other arm sends no `_meta` at all. | Fixed inside this change (3.4a): the trace write is unconditional and merges with the cache key rather than depending on it. |

### 6.1 Review leads that died as stated and survived as repairs

Recorded in their corrected form, because the reviewer's wording would send a later reader to
the wrong conclusion.

| as raised | what was actually wrong |
|---|---|
| "the exact OTEL wire contract is deferred and the cited §4.1 does not exist" (gpt) | §4.1 exists, at line 206, as the resolved-questions table. The defect was a cross-reference pointing there for the key spelling, which at the time was deferred in §4.2. The reference is corrected, and the SEP-414 read now settles the spelling in §4.1, so the deferral is gone rather than re-pointed. |

## 7. What closing these criteria requires

EXT.1 closes when `ServerCapabilities` gains an `extensions` field, the shared builder (2.3)
populates it from the extensions the gateway can honour today, and the per-request path recovers
the client's `ExtensionSet` from the raw `_meta` capabilities object via `from_capabilities()`,
intersects it with `negotiate()`, and falls back to core behaviour when an extension is absent.
That is the whole criterion. Retiring `ServerCapabilities.tasks` / `ClientCapabilities.tasks` is
NOT part of it: 4.4.1 is an open operator question, and deleting a public wire type without that
answer is an API break this ticket does not need. Answered yes, F1 is fixed here; answered no or
unanswered, F1 goes to TASK.1 as an accepted duplicate with a named owner.

Today the field is populated from an empty set, because the only extension the module names is
Tasks and TASK.1 has not landed (3.1a). An empty `extensions` object is the honest declaration,
and it is not the same wire value as omitting the field.

OTEL.1 closes when the three W3C fields are read from the inbound `_meta`, bounded, validated by
a predicate that matches the W3C grammar (3.4b), and written unchanged into the outbound `_meta`
at `dispatch_to_backend` unconditionally (3.4a) — never minted, never interpreted, subject to the
CONTROL.3 carve-out in 3.4. Deleting `src/tracing_context/` is NOT part of it: 4.3 already says a
comment recording ownership is enough if the module stays, and 4.4.2 is the operator's call. F4,
F7 and F8 are fixed inside this change; F3 is disposed of by the comment or the deletion,
whichever the operator picks.

On effort: the estimate moves for one reason only, and it is Q3 — whether the second route
(`POST /mcp/{name}`, 4.4.3) must also carry trace `_meta`. 3.4a and F7 are bounded, not free: making the
write unconditional is a sibling function beside `inject_cache_key`, which already takes an
optional params object and already has unit tests at `invoke.rs:474-503`, so the seam exists;
F7 is four predicates with one test row each. Neither is large enough to move the estimate. Otherwise this stays what
`docs/requirements/RELEASE-4.0.0-criteria-status.md:162` says it is: wiring plus one struct field.
