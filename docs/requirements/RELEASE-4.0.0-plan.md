# v4.0.0 release plan — closing the 27 blocking criteria

Companion to `docs/requirements/RELEASE-4.0.0-criteria-status.md`, which is the status SSOT.
This file is the ORDER OF WORK, not a second status table. When the two disagree, the status
doc wins.

Standing as of 2026-08-31: 45 MET, plus 3 qualified MET (1 `MET (I)`, 1 residual, 1 caveat). 27
criteria are blocking — 16 UNWIRED (code exists, nothing calls it), 10 ABSENT (nothing implements
it), 1 UNTESTED. Every number here is counted from the blocking column of the status doc's tables,
never carried forward by hand; an earlier revision of this paragraph said 26 blocking and split it
17/12/0, which sums to 29.

That 27 is now known to be INCOMPLETE, not conservative. The status doc it is counted
from carries no row for any of the 22 non-functional requirements in section 4 of
`docs/requirements/RELEASE-4.0.0-requirements.md` (lines 204-253): NFR.COMPAT.1-4,
NFR.SEC.1-6, NFR.PERF.1-4, NFR.OBS.1-5, NFR.DOC.1-3. Each carries a verification method
in the requirements table (T test, M measurement, D demonstration, I inspection), so each
is a criterion, not a wish. Three are already known unmet: NFR.SEC.5 fails today because
`cargo fmt --check` fails at `src/idempotency.rs:305`, `:566` and `src/protocol/mrtr.rs:113`,
and NFR.PERF.1-2 require measurement against 3.5.0 that has not been run. An audit of the
block is in flight; until it lands, treat 27 as a floor. Discovered 2026-08-31 by an audit
of `tests/mik_7212_acs.rs`, which cites NFR.SEC.3 and NFR.SEC.4 as criteria it satisfies
while the ledger holds neither.

## The shape of the problem

Two thirds of the blocking set is not missing code. It is code that exists and is not
reachable. That changes the plan: for UNWIRED criteria the expensive part is deciding *where*
the wiring belongs and what it changes for existing deployments, and the cheap part is the
edit. Every one of those decisions is a §P1 design event and none of them is an edit.

## Clusters, in dependency order

### A. MRTR continuation state — MIK-7212, 10 criteria — CRITICAL PATH

MRTR.1 through MRTR.10a: sealed continuation envelopes minted by the gateway, principal and
request binding, single-use with expiry holding across replicas, replica affinity on retry,
the modern-to-legacy `InputRequiredResult` bridge, bounded in-flight state, and never sending
an `inputRequest` type the client has not declared.

Largest cluster, deepest security surface, and it gates two other clusters. Already in flight
in another session (`src/protocol/continuation.rs`, `tests/mik_7212_acs.rs`).
Blocks: cluster H, and MRTR.10a feeds cluster B's SUB.4 key contents.

### B. MCP 2026 protocol semantics — MIK-7272, 10 of 17 criteria

Not one job. It splits by size:

- **Small, self-contained**: ERROR.2 (resource-not-found returns `-32602`, not `-32002`),
  RESULT.2 (a missing `resultType` defaults to complete when the gateway reads a backend
  reply). Each is a narrow change with a test that is red today.
- **Design-first**: SUB.4 (idempotency wiring — design at revision 4, see
  `docs/design/2026-08-31-sub-4-idempotency-wiring.md`. Larger than it looked: seven verified
  implementation defects are prerequisites, and no advertised way exists for a client to send a
  retry key at all. The tool-surface question that blocked all code is decided PROVISIONALLY:
  both the meta-MCP surface and the direct `POST /mcp/{name}` route are in scope. The operator
  was asked on 2026-08-31 and was away; the call is the team lead's, made on the full-scope
  direction recorded at the foot of this file, and it is not operator-confirmed),
  ORDER.2 (tool set must not vary per connection), SUB.2 (request-scoped notifications on the
  request's own response stream), EXT.1 (declare extensions through server capabilities),
  OTEL.1 (`traceparent`/`tracestate`/`baggage` through `_meta`).
- **Whole feature**: TASK.1, the `io.modelcontextprotocol/tasks` extension for long-running
  backend calls. Largest single item outside cluster A. It is also SUB.4's alternative
  branch, so a decision to build it changes SUB.4's scope.

### C. Backend era detection — MIK-7217, 7 criteria

DISCOVER.4 (detect a backend's protocol era by probing, never by trusting a version string)
and DISCOVER.5 (cache the detected era per backend, re-probe when a cached assumption fails)
are the two named. One coherent design covers the cluster.
Blocks: cluster D's HEADER.9, which is conditioned on what the peer negotiated.

### D. Header forwarding — MIK-7214, 4 criteria

HEADER.5 (`x-mcp-header` mirroring an argument into `Mcp-Param-{name}` outbound, SEP-2243)
plus HEADER.7-9. HEADER.9 sends the modern `_meta` envelope only where the peer negotiated it,
so it cannot be finished before cluster C.

### E. Principal-keyed security — MIK-7116 + MIK-7215, 4 criteria

TENANT.1 (cross-tenant data-minimisation keyed on authenticated principal, not session),
CONTROL.2 (principal-keyed budget), CONTROL.3 (transparency-log correlation on the OTel trace
id, not session id), CONTROL.4 (session-lifecycle TTL reaping owning cleanup that disconnect
used to do). One theme: session identity is the wrong key everywhere it is still used.
In flight in another session (`src/security/firewall/principal_window.rs`, `tenant_guard.rs`).

### F. Response-cache keying — MIK-7213, 2 criteria

CACHE.3 (public scope only, with proof and a decision table) and CACHE.4 (shared cache keyed
on all eight response-varying inputs plus a policy epoch). Both are correctness-of-caching
questions, independent of everything above, and safe to run in parallel.

### G. Schema validity — MIK-6865.SCHEMA.1

Tool schemas must remain valid under JSON Schema 2020-12. There is no validator in the
dependency tree, so this is a dependency decision before it is a test: which crate, what it
costs at startup, and whether validation runs at load time or in CI only. Supply-chain gate
(DoD D30) applies. Design first; the criterion cannot be closed by a hand-rolled check.

### H. Confirmation gate reachability — MIK-7246.CONFIRM.2

The destructive-action confirmation gate must be reachable through the MRTR path so a modern
client can actually confirm. CONFIRM.1 closed 2026-08-31; this is the other half and it cannot
be built before cluster A lands.

## Order of work

**Wave 1 — designs only, no code, all parallel.** C, F, G, and the design-first half of B.
Each is a §P1 note reviewed by two vendors before an edit. This is the wave that decides
things, and it is the one most likely to be skipped under release pressure.

**Wave 2 — the small self-contained items.** B's ERROR.2 and RESULT.2, and D's HEADER.5.
Failing test first, then the change. These need no wave-1 output and can start immediately.

**Wave 3 — implementation of wave 1.** Plus D's HEADER.7-9 once C lands.

**Wave 4 — the two long poles.** Cluster A (in flight) and B's TASK.1. H follows A.

Clusters A and E are owned by other sessions. Coordinate before touching
`src/protocol/continuation.rs`, `src/security/firewall/`, or their test files.

## Open for the operator

Four decisions are the requester's, not the team lead's, and are recorded here rather than in the
design that raised each one so they survive a session boundary. None blocks the work that does not
turn on it. Each names what changes either way, so an answer costs a sentence.

**1. SUB.2's second clause — RESOLVED against amending it; what remains is scheduling.** The
question was put to the operator on 2026-08-31 and came back as a question: what does the standard
require. It was checkable, and the check was a spec read. Answer, quoted from
`https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http`: a
server "**MAY** send JSON-RPC *notifications* — for example, `notifications/progress` or
`notifications/message` — before the final response", those notifications "**MUST** relate to the
originating client request", and "the final JSON-RPC *response* **SHOULD** terminate the stream".
The stdio page carries the same provision and no revision of the spec, in any of the three we
serve, permits a receiver to discard a message because it has no `id`.

That makes our two transports non-conforming today, independently of SUB.2's wording. `http/mod.rs:929-944`
returns the first `data:` line of an SSE response and discards the rest, so a conforming backend that
emits a progress notification before its result has that **notification returned as the `tools/call`
result**. `stdio.rs:416-431` drops every message without an `id`, which is every notification. Amending
SUB.2 would not make either legal; it would only stop the criterion from mentioning it. A stated limit
against a MUST is an unmet requirement, and here the MUST is the protocol's, not ours.

The work is smaller than "rewrite the transports". Revision 2026-07-28 **removed** server-to-client
requests from the stream entirely — "the server **MUST NOT** send independent JSON-RPC *requests* on
this stream", with sampling, elicitation and list-roots now embedded in an `InputRequiredResult`
(the MRTR pattern, cluster A). So no bidirectional request routing is needed on the response stream:
read to the final response instead of stopping at the first event, and stop discarding id-less
messages. Two reads and a routing rule, not a redesign.

It also **eliminates** SUB.2's routing design rather than patching it. Correlation is by the stream,
which is scoped one-to-one to the request that opened it — there is no request key to route by, and
building one would invent a mechanism the protocol already provides. Cluster B's design must drop
that clause, not shrink it.

Both follow-on questions were checked on 2026-08-31 and only one of them was a worry.
`Last-Event-ID` resumability is implemented and already gated correctly: `get_era_refusal` runs first
in `mcp_sse_handler` (`handlers.rs:262-264`) and returns `405` to any caller declaring the modern era,
so the replay code at `streaming.rs:241-386` is unreachable from a 2026-07-28 peer, and the modern
`subscriptions/listen` stream carries no event ids at all (`streaming.rs:416-459`). Nothing to do.

The compatibility question is the real one, and it is larger than "read past the first line". A
server-to-client *request* — which 2025-06-18 and 2025-11-25 both permit and we serve both — does not
fail to parse. It parses **successfully into an empty response**. `JsonRpcResponse`
(`src/protocol/messages.rs:44-56`) carries no `deny_unknown_fields` and holds `result` and `error` as
bare `Option<Value>`, so `{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{...}}`
deserializes into `JsonRpcResponse{id:Some(5), result:None, error:None}` with `method` and `params`
silently discarded. On HTTP the mis-parsed request is returned to the caller as the answer to their
call. On stdio it is worse: `handle_response` looks the id up in `self.pending`
(`stdio.rs:210-219`, `:416-434`), so an unrelated in-flight caller that happens to hold that id is
**completed with an empty result**. No test on either transport exercises a line carrying both a
`method` and an `id` (`stdio.rs:628-700`).

That relocates the fix. The defect is not two independent transport bugs but one permissive type
used as a parse target on every read path, so a guard added in each transport would leave every
other caller of `JsonRpcResponse` still able to swallow a request. Dispatch by message shape before
parsing as a response, once, where all readers pass through.

**2. SCHEMA.1 — what happens to a backend that publishes an invalid schema.** The criterion says
tool schemas MUST remain valid under JSON Schema 2020-12, unqualified, and the gateway republishes
proxied backend schemas. Three postures: refuse the backend, publish and flag, or degrade the
schema. Cluster G scoped backend-supplied schemas OUT, which leaves a stated limit against a MUST —
an unmet requirement, not a design choice, until this is answered.

**3. ~~Whether 2025-11-25 clients are still served.~~ RESOLVED against the code, and it moved the
release gate.** The `tasks` capability types are dead, not a hazard: `ServerCapabilities.tasks` is
`None` in every response the gateway builds, so a 2025-11-25 client is told "no task support", which
is what capability negotiation is for. Nothing mis-serves anyone and deleting them buys nothing this
release needs.

The audit found the real gap one level up. `SUPPORTED_VERSIONS` (`src/protocol/mod.rs:43`) lists four
legacy revisions and **deliberately omits `2026-07-28`** — the constant's own comment says why:
listing it "would make `initialize` negotiate a revision the gateway cannot serve, and the client
would be told yes and then served 2025 semantics — a worse failure than refusing, because it is
silent. It is added in the increment that makes it true." That increment is this release. Until the
constant gains the string, `negotiate_version` (`mod.rs:48-57`) falls back to `PROTOCOL_VERSION`, so
a client declaring the pinned revision is answered `2025-11-25` at `initialize` and NFR.COMPAT.1's
first clause is unmet.

So the flip is a release gate with an order: it is the LAST commit, not an early one, and it is only
truthful once the modern request path is complete. Note the two constants are read by different
sites — `MODERN_VERSIONS` (`src/protocol/meta.rs:219`) already contains `2026-07-28` and drives
method availability on `POST /mcp`, while `SUPPORTED_VERSIONS` drives `initialize`. The modern path
can therefore be fully working while `initialize` still denies it, which is exactly today's state.

The interim behaviour is conforming, checked rather than assumed. Both 2025-06-18 and 2025-11-25
carry identical version-negotiation text: "If the server supports the requested protocol version, it
MUST respond with the same version. Otherwise, the server MUST respond with another protocol version
it supports. This SHOULD be the latest version supported by the server", and separately, "If the
client does not support the version in the server's response, it SHOULD disconnect"
(https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#version-negotiation).
`negotiate_version` echoes on an exact match and otherwise returns `PROTOCOL_VERSION`, which is the
newest entry of `SUPPORTED_VERSIONS` — both halves satisfied, and the mismatch burden sits with the
client by design. So a 2026-07-28 client today is told `2025-11-25` and should disconnect: the
gateway refuses the revision it cannot serve instead of silently mis-serving it, which is the
outcome the constant's comment was protecting. Nothing to fix before the flip.

Within the legacy tier the compatibility question is smaller than it looked. `build_initialize_result`
(`meta_mcp_helpers.rs:144`) uses the negotiated version for the `protocol_version` string and nothing
else; `handle_tools_list_with_url_override` and `handle_tools_call` (`meta_mcp/mod.rs:1222`, `:1252`)
take no version parameter at all. One behaviour is served to all four legacy revisions. The hard fork
is legacy-versus-modern in `classify_request` (`handlers.rs:660-920`), not per-revision.

**4. What the direct route needs, now that reachability is settled.** The two-route question was
half a code fact and nobody had read the code. `backend_handlers.rs:724` says the direct
`POST /mcp/{name}` route bypasses `invoke_tool_traced`, and `:594` says it keeps no per-user cache,
so the cache, idempotency and chokepoint machinery sits on the meta-MCP surface alone and the second
door is out of reach by construction, not by assumption. That half needed a source read, not an
operator. Two clauses survive it and are genuinely yours: whether the direct route should get its
own instrumentation rather than merely being out of the shared path, and whether CACHE.1-4 bind on
HTTP only or across all transports — the second moves where stdio exits and nothing else.

**5. ORDER.2 — RESOLVED by adopting the issue-449 design; the release absorbs it.** The question
looked like "may per-session routing profiles be removed", and it was asked in that form on
2026-08-31. That framing was wrong, and the operator caught it: the work already exists.
`docs/design/2026-08-31-meta-tool-exposure.md` answers GitHub issue 449 (Bruce-Poating, open,
"allow operators to trim the exposed `gateway_*` meta-tool surface"), and both vendors reviewed it
and rejected its first shape — an operator-configured allow-list — in favour of an
**authorization-derived** surface. Its `449.EXPOSE.1-7` are superseded; `449.DERIVE.1-9` replace
them.

That shape is what `ORDER.2` permits in its own text: the tool set MUST NOT vary per connection but
MAY vary by the authorization presented on the request
(`docs/requirements/RELEASE-4.0.0-requirements.md:128`). So the conforming answer and the answer a
user asked for are the same answer, and it is already designed and reviewed.

**Decision (operator, 2026-08-31): implement `449.DERIVE.1-9` inside v4.0.0.** Profiles are not
removed — `449.DERIVE.5` lists the profile tools only when routing profiles are configured. The two
options this closes off are recorded so they are not re-proposed: shipping the modern path
profile-blind while legacy keeps profiles (leaves two behaviours and a restatable finding), and
holding `ORDER.2` open (ships a knowingly non-conforming release).

*What this costs, stated plainly:* nine acceptance criteria move into the release, and `tools/list`
has no caller context today, so that plumbing is real work standing between here and the version
flip. *What it retires:* the `gateway_set_profile` stale-list defect — a profile change never fires
`notifications/tools/list_changed`, so clients are handed a stale list today.

## One commit's history is wrong, and it is staying that way

`b55116d1 docs(cluster-f): plan the response-cache keying tests as tests` contains, besides its
cluster-F plan, four `src/` changes that belong to the protocol mis-parse repair: the extraction of
`parse_sse_response` (`src/transport/http/mod.rs:273`) and the three tests that fail against the
current deserializer — `response_deser_rejects_frame_carrying_method`,
`message_enum_still_classifies_both_frame_shapes` and
`handle_response_rejects_inbound_request_and_leaves_caller_pending`. They were swept in by a
whole-tree stage from a session that did not own them. Nothing was lost and the fix is not in that
commit, so the branch is red between `b55116d1` and the repair commit that follows it.

The history is not being rewritten. Several sessions hold this branch checked out, and rebasing
underneath them costs more than a wrong commit message does. What the rewrite would have bought is
bought here instead: a reader who bisects into the red window, or who wonders why tests for a
protocol defect arrived inside a caching plan, has the answer without having to reconstruct it. The
repair commit names the same thing from the other end.

Staging by explicit path — never `git add -A`, never `git commit -a` — is now the rule for every
session on this branch, and `git status --porcelain` before each commit is what enforces it: a
modified file you did not touch is somebody's work in progress, and committing it is not tidiness.

## What would make this plan wrong

- ~~If TASK.1 is dropped from v4.0.0, SUB.4 loses its alternative branch.~~ CLOSED: the operator
  directed the full scope on 2026-08-31, so TASK.1 ships in v4.0.0 and SUB.4 keeps both routes.
  The design says how the two coexist, not which one wins.
- ~~If the two-route assumption is wrong, OTEL.1 and SUB.4 both shrink.~~ CLOSED for reachability
  on 2026-08-31 by reading the source rather than asking: the direct `POST /mcp/{name}` route
  bypasses `invoke_tool_traced` (`backend_handlers.rs:724`) and holds no per-user cache (`:594`),
  so the shared machinery cannot reach it whatever the scope decision says. The assumption had been
  carried through three designs unread. What is still open is narrower and is item 4 above: whether
  that route deserves its own instrumentation, and whether CACHE.1-4 are HTTP-only.
- If the era cache should be keyed per pool slot rather than per backend name, cluster C's
  DISCOVER.5 changes by one field, one lookup and one section. It is keyed per backend NAME on the
  team lead's call, provisional and not operator-confirmed: era is a property of the peer process,
  and every slot of one named backend dials the same command or URL, so per-slot keying means one
  probe per user slot against the same remote. The named residual is that one slot's mis-detection
  reaches its siblings; DISCOVER.5's re-probe half is what pays for it, and per-slot has no
  equivalent.
- If cluster A slips, H slips with it and MRTR.10a's key contents stay open, which leaves
  SUB.4 implementable but not fully specified.
