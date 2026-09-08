# MRTR.7 — production legacy bridge, including stdio

Status: amended design awaiting fresh design and test-plan review. No new
implementation or executed acceptance evidence is claimed by this document.
Worktree: `mcp-v4-delivery`; source inspection on 2026-09-06 at `0d4df3c0` plus
concurrent delivery changes. Symbol names below are authoritative over old line
numbers. Companion: [test plan](2026-09-05-mrtr7-test-plan.md).

## Scope receipt update — 2026-09-06

FOR: make the existing `InputBridge::run` reachable from real legacy HTTP and
stdio calls, preserving declarations, caller isolation, raw question delivery,
cancellation cleanup, retry accounting and the final response contract.

The 2026-09-05 HTTP-only increment was a sequencing decision. The operator has
now approved full stdio bridging in 4.0.0; see the [recorded capability
expansion](../requirements/RELEASE-4.0.0-scope-decisions-2026-09-06.md) and
[scope acceptance rows](../requirements/RELEASE-4.0.0-scope-update.md).
`MIK-7387.STDIO.1`–`.3` and `MIK-7388.CANCEL.1` are release obligations.
An HTTP-only success cannot close MRTR.7a/7b for this release. The old WIRE.10
assertion that every initialized stdio client must be refused is superseded;
refusal remains required for undeclared capabilities and unavailable channels.
This is a scope-move receipt, not a reset of the change's review history.

OUT of this increment:

- Rebuilding `InputBridge`, its bounds, protocol parsing or the 23 existing
  component tests; adapt the typed backend-result and delivery-progress seams
  specified below. Preserve their intent and names; the pinned-spec correction
  below supersedes content-only elicitation payload expectations.
- Inventing another continuation store, grant system, session declaration map,
  or typed forwarding layer. Existing platform owners remain authoritative.
- General chat/model proxying, transparent multi-replica recovery, or automatic
  replay after a connection dies. These are not bridge mechanisms.
- The modern destructive-confirmation implementation. It remains required for
  4.0.0 under [CONFIRM.2](2026-09-06-confirm-2-destructive-confirmation.md),
  coordinated as a dependency below; this document does not narrow that scope.

## Review provenance and Definition of Ready

Earlier revisions carry rounds 2–6 findings in Git history. The useful decisions
are consolidated below so historical HTTP-only instructions cannot be mistaken
for current implementation directions. The latest Grok receipt's
`material_sha256` covered a **134-byte stub**, not the full reviewed material.
Its source-verifiable findings informed the design, but that receipt does not
approve this document or the release expansion. Fresh reviews must receive the
same full design, test plan, scope delta and applicable canonical DoR, and bind
the ledger row to those bytes with successful process status. A verdict string
or a nonzero reviewer exit is not approval. Root owns that review before source
or test implementation starts.

DoR for this documentation increment: approved user outcome is answering legacy
client questions on both transports; target files are this design and its
existing test plan. Reuse and in-flight work were inspected first. Risks are
blocked reader/writer progress, permission widening, lost pending state, and
unaccounted retries. Acceptance is a single coherent contract with each release
row mapped to a falsifiable test, plus a fresh review gate. Validation is the
source-symbol inventory, test-name coverage, link resolution and `git diff
--check`; these checks do not establish runtime correctness. No dependency or
license changes are proposed by this documentation increment.

Policy read for this increment:
`/Users/mikko/.claude/rules-source/workflows/development-process.md`,
`/Users/mikko/.claude/rules-source/workflows/quality-gates-dor.md`, and
`/Users/mikko/.claude/rules-source/workflows/quality-gates-dod.md`.
For the later code increment, source impact analysis and the reviewed red tests
remain prerequisites; document checks cannot satisfy them.

### Applicable DOCS DoR verdicts

| Gate | Verdict | Evidence / reason |
|---|---|---|
| G0 priority | PASS | E1: operator approved full 4.0 scope; E2: `MIK-7212.MRTR.7a`/`.7b` and the supplementary stdio rows are release blockers. Unblocking their design precedes their implementation. |
| G4 clear requirements | PASS | E4: this scope receipt; companion canonical criterion-to-case matrix identifies positive and negative outcomes. |
| G5 minimum coherent scope | PASS | E2: existing `InputBridge::run`, pending-map guard and 23 component tests are reused. E4: one shared session owner and one writer; historical HTTP-only instructions consolidated in their original files. |
| L1 licenses/IP | PASS | Documentation changes preserve existing project licensing and cite protocol sources; no dependency, copied implementation, or license change. Code-package SBOM review is not performed or claimed by this DOCS increment. |
| O1 structure | PASS | Both primary amendments stay in existing `docs/design` files; the root-authorized confirmation edit is limited to the conflicting transport contract. |
| O2 no clutter | PASS | E3: `git diff --check` and local-link/test-name inventory passed; review packets live in the external Codex review archive, not the repository. |
| O3 naming | PASS | Existing filenames and stable canonical MRTR/STDIO/CANCEL IDs remain; new WIRE rows are supporting cases, never replacement canonical criteria. |

DoR: NPV/Cost/ROI N/A under canonical DOCS applicability; **7/84 applicable
DOCS gates PASS, 77 N/A because this increment edits documents only**. E1:
[operator scope record](../requirements/RELEASE-4.0.0-scope-decisions-2026-09-06.md);
E2: [canonical release criteria](../requirements/RELEASE-4.0.0-requirements.md);
E3: recorded diff and inventory checks; E4: this design and its test plan.
This summary does not waive the larger code increment's DoR, reviewed red tests,
source impact analysis, or runtime DoD. Fresh review closure is still pending.

## Measured constraints and reuse

Source observations are **I (one source)**, not runtime measurements:

| Existing owner | Observation and consequence |
|---|---|
| `src/gateway/input_bridge.rs` | `InputBridge::run` already owns round/request/aggregate bounds and raw prompt planning. `ClientChannel` has only a test fake; `BackendInvoker::invoke` returns bare `Value`. Add adapters and a typed error seam, not another bridge loop. |
| `src/gateway/proxy.rs` | `register_pending`, `resolve_pending`, `cancel_pending`, `PendingSampleGuard` and `send_to_session` forwarding already exist. `resolve_pending` binds a response to its originating session and does not consume another session's waiter. |
| `src/gateway/streaming.rs` | `ClientSession` lives in the multiplexer map and already has an authenticated owner. DELETE and the TTL reaper remove that same map entry; owner-authorized reconnect reuses it. No declaration field exists yet. |
| `src/gateway/server/mod.rs` | `build_meta_mcp` is shared, but the multiplexer/proxy are currently constructed only in HTTP `run`. `run_stdio` awaits dispatch inline and exclusively owns stdout. Moving dispatch alone leaves the writer blocked. |
| `src/gateway/meta_mcp/mod.rs` | Both transport initialize paths reach `MetaMcp::handle_initialize`; no capability capture exists. `MetaMcpCallerContext` currently describes only per-request declarations. |
| `src/gateway/router/handlers.rs` | HTTP reply ingress recognizes bridge IDs and calls `resolve_pending`; the normal stdio request parser does not provide this reply path. |
| `src/gateway/meta_mcp/invoke.rs` | MRTR.9 precedes continuation minting; the paid dispatch is surrounded by governance, accounting and final-result gates. A direct retry would bypass them. |

The old claim that session-id secrecy alone protects declarations is obsolete:
`ClientSession::owner` already exists. Preserve that owner boundary, including
[GH452 DELETE ownership](2026-09-06-gh452-session-delete-ownership.md), rather
than reintroducing a bearer-session assumption.

Protocol anchors: legacy [2025-11-25 transport framing](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
were read on 2026-09-06. The gateway's new transport sends newline-delimited
JSON-RPC, keeps logs on stderr, and observes the initialize/initialized barrier.
Modern requests keep the [2026-07-28 MRTR contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr):
per-request capabilities, input responses keyed to the original questions and
opaque backend state on retries. The bridge is compatibility translation for a
legacy client, never permission to send old server requests to a modern client.

## One shared runtime and declaration owner

1. Construct one `Arc<NotificationMultiplexer>` and its one `Arc<ProxyManager>`
   in `Gateway::build_meta_mcp`, returning the same handles in `BuiltMetaMcp` to
   either transport. HTTP stops constructing a second pair. `MetaMcp` receives
   that proxy through a builder/setter; the proxy owns the multiplexer already,
   so it is the sole route to session declaration reads/writes and channel
   construction. Do not store `Arc<AppState>` in `MetaMcp` (reference cycle).
   Test-only `MetaMcp` construction without this runtime remains fail-closed.
2. Add `Declared` plus handshake readiness to **`ClientSession` itself**, behind
   the existing session owner's synchronization. Access through narrow
   multiplexer methods; `ProxyManager` delegates access for `MetaMcp`. Do not add
   a second session-keyed map. Missing session, failed handshake or absent
   capability yields `Declared::NONE`, never all capabilities.
3. Expose `Declared::from_initialize` over the existing capabilities-map parser.
   At shared `MetaMcp::handle_initialize`, capture the successful handshake's
   capabilities in the already admitted session. This write creates no session
   and bypasses no owner check. Read **`params.capabilities`**, never request
   `_meta`. Admit initialization exactly once under the session-state lock and
   keep its declaration immutable thereafter. Reject reinitialization of an
   already initialized session with `-32600`; changing declarations requires a
   fresh owned HTTP session or a new stdio process. This eliminates the
   active-call/reinitialization race instead of coordinating two counters. A
   concurrent second initialize cannot win a second write under that lock.
4. `notifications/initialized` marks the same session ready on both transports.
   The stdio writer acknowledges the flushed initialize response before any
   prompt-capable dispatch is released. Capability capture alone is not channel
   readiness. A pipelined legacy tool request waits behind that barrier in a
   bounded queue; a capability that was never declared still refuses.
5. HTTP uses its authenticated session creation/lookup, owner checks, DELETE and
   reaper. Stdio creates one process-private session and subscribes its writer
   before initialization. Its identifier is generated per runtime, not a shared
   global `"stdio-session"` value. Its owner is `stdio-local:<runtime UUID>`,
   created only by the stdio runtime and never by the HTTP owner mapper, which
   emits `credential:` or `unauthenticated:` domains. Never create it through
   the `anonymous` compatibility helper. HTTP GET, POST and DELETE presenting
   even the exact stdio ID cannot resume, read, answer or delete it.
   EOF/cancellation removes it. This separation holds even in a fixture hosting
   both transports with the same multiplexer.
6. Both transports classify the request before constructing caller context.
   For **Legacy**, effective capabilities come from that session and an optional
   slice may only narrow them. For **Modern**, capabilities come only from this
   request's well-formed `_meta`; session capabilities never widen it. Carry the
   shape explicitly; malformed modern declarations cannot become Legacy.

| Request shape / input support | Backend asks | Result |
|---|---|---|
| Legacy, ready session, declared method/mode | supported question | bridge on HTTP or stdio |
| Legacy, no declaration or unavailable channel | any question | bounded refusal, zero prompts/retries |
| Modern, this request declares the method/mode | supported question | existing continuation, zero legacy prompts |
| Modern, only a session declaration or malformed `_meta` | question | MRTR.9 / existing malformed-request refusal |

Session removal also cancels pending requests bound to that session, so a later
session cannot inherit either permission or unanswered prompts. An ordinary HTTP
stream disconnect does not revoke a still-valid session declaration; if an
exchange cannot be delivered, fail that exchange rather than manufacture input.

### HTTP control ingress at request capacity

`router/handlers.rs` currently acquires `AppState::inflight` before identifying
reply envelopes or initialization notifications. A normal call holds that
permit while waiting on its bridge; filling the normal lane can therefore
prevent the replies that would release it. Keep the normal drain/admission
semaphore, and add a separate **32-permit control lane** owned by AppState.
Classification follows bounded body parsing and the existing authentication,
protocol and session-owner checks; it does not bypass any of those checks.

Validated response envelopes and `initialize`, `notifications/initialized`
and cancellation control messages use this lane without waiting for a normal
permit. The dispatcher validates the exact control shape and method before
choosing it; arbitrary tools, unknown methods, malformed envelopes, or a result
member attached to a tools/call request cannot smuggle normal dispatch through
the lane. Use non-blocking admission: at control capacity refuse with HTTP 503;
an initialize request retains its ID in a `-32000` capacity error, while replies
and notifications receive no new JSON-RPC response envelope. Their transport
refusal must not consume a pending ID. Count admitted controls in graceful
drain while keeping them available to finish already admitted normal calls.

For a batch, validate and process eligible controls under one bounded control
admission, then **drop that control permit before normal-member admission or
dispatch**. Non-blocking-admit each normal member on the normal semaphore;
if it is full, return that member's `-32000` capacity error without waiting or
holding control occupancy. Reuse `dispatch_batch_with_sink` for common batch
result assembly and per-member error behavior, adapting its admission/sink
boundary for both transports rather than creating a second HTTP assembler.
A mixed batch is not permission for tools/call members to bypass admission.
As on stdio, an initialize-plus-prompt batch returns the initialize result and
`-32600` for the prompt-capable member without awaiting an initialized
notification the client cannot yet send. Separately pipelined normal calls
retain the bounded readiness barrier. A pure control batch never waits behind
normal work. Reply, initialized and cancellation progress at normal capacity,
mixed batches while unrelated calls fill the normal lane, and control-lane
saturation require distinct production HTTP cases. No mixed batch may pin a
control permit while waiting on a normal tool handler.

## Raw production `ClientChannel`

Implement `ClientChannel` for `ProxyManager` in `proxy.rs`, where the private
`PendingSampleGuard` is available. The same adapter serves HTTP and stdio;
transport selection belongs to the session's live delivery path. Factor the
register/guard/send/receive sequence into one private exact-ID exchange helper
used by the raw adapter and existing typed forwarders; the typed forwarders
retain their own payload construction and IDs for their existing consumers.
The shared exact-ID helper returns the **raw JSON-RPC envelope**, including its
result/error discriminator. The raw bridge consumes it as-is; each existing
typed forwarder extracts its expected result exactly once and retains its
existing error contract. Never nest the envelope inside a second result.

For each bridge-minted ID, register that **exact ID** with its session, establish
`PendingSampleGuard` before any await, then use the session request primitive
described below with raw JSON-RPC containing the supplied method and supplied
`Option<Value>` params. Omit absent params; preserve present params exactly,
including unknown fields and nested values, except the explicitly required
legacy URL `elicitationId` adaptation below. Await the registered receiver without
a competing adapter timeout: the existing
`InputBridge::ask` owns `min(per_prompt, remaining aggregate)` and drops that
future when the prompt expires. A second timer returning `DeliveryError::TimedOut`
would fail the whole call instead of preserving the approved abandoned-round
behavior. Add a per-prompt `DeliveryProgress` shared with the channel: on its
outer timeout the bridge checks whether writer handoff occurred and whether the
transport is known closed. Before handoff or after known transport closure it
returns `NoSession`; only a handed-off, still-live unanswered prompt takes the
existing omitted-answer retry. This progress parameter is the narrow channel
interface change needed to distinguish delivery failure from silence. The guard
removes the entry on success, error, no receiver, outer prompt timeout, outer
future cancellation and task abort. Session-close cleanup removes all waiters
for that session and closes their receivers.

Do not wrap `forward_sampling_with_response` or
`forward_elicitation_with_response`: they mint a second ID and serialize typed
params that can drop fields. They retain their existing consumers. `roots/list`
uses the same raw path with its own ID prefix; no sibling typed forwarder is
needed. Keep the admission set closed to `elicitation/create`,
`sampling/createMessage` and `roots/list`.

Inbound responses are recognized before normal method parsing and correlated
by exact ID **and session**. Unknown, duplicate, late and wrong-session replies
never consume another waiter and never get mistaken for tool requests. A
JSON-RPC error remains `ClientRefused` when `InputBridge::project` examines the
raw response; the bridge-owned prompt timeout abandons only that answer. A lost
receiver or unavailable delivery returns `NoSession`, a delivery failure, never
`TimedOut`, human refusal or accepted empty input. Unknown methods/modes fail
before any frame.

Reuse the existing kind-aware `InputBridge::project` (MIK-7388.BRIDGE.5): an
`action` field on sampling or roots is ordinary result data. Preserve the
approved abandoned-round contract (MIK-7388.BRIDGE.4): timeout omits that answer
key on a bounded retry; it does not insert `{}` or imply approval. For destructive
confirmation, silence is never labelled affirmative acceptance; the explicit
era-by-transport policy below decides the unconfirmable outcome.

### Pinned-spec elicitation correction — same bridge, valid results

Source inspection after R2 found that the old component expectation is not a
valid modern backend response. The pinned [MRTR InputResponses contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)
files the complete client result, so an accepted form response contains both
`action` and `content`. [2026 URL elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
accepts an action-only result. Today's `InputBridge::project` instead strips
`action` and rejects URL acceptance because it requires object content. The
existing row 308 fixture hides this by combining URL mode with a fabricated
form answer. This is a conformance correction under canonical MRTR.7a/7b,
superseding that old design/fixture payload contract, not a new bridge loop.

Keep the existing kind discriminator. Pass the planned elicitation mode to
`project` using the existing `protocol::meta::ElicitationMode` and
`from_params`; retain it on `Prompt` rather than deducing mode from a reply.
Correct that parser's existing null equivalence: only an absent mode defaults
to form. A present null, nonstring or unrecognized string is invalid and must
refuse the whole planned batch before any client frame, even for a caller that
declared form. Reuse the parser with that correction rather than adding a
second mode classifier. This follows the pinned schema's string-valued mode.
Mode classification is not request validation: before whole-batch admission,
require an elicitation `params` object and a string `message`. Form requires
object `requestedSchema` with `type:"object"` and object `properties`; URL
requires a string `url` accepted by the existing `url::Url::parse` as an
absolute URL. Missing/null/scalar/array params, missing or incorrectly typed
required fields, invalid URLs and malformed required form-schema structure
refuse before any frame in a mixed batch. Run this structural validation on
the raw value without typed reserialization, defaults, URL normalization or
dropping unknown fields. It returns the already validated mode for `Prompt`.
Do not use `ElicitationCreateParams` alone as the validator: its schema and URL
fields are optional today. The legacy `elicitationId` rule below then applies
to an already valid URL request; its absence is the one permitted adaptation.

Form-schema validation covers the **complete restricted elicitation subset**,
not just the top-level object. Each property must be a supported string,
number/integer, boolean, single-select string enum (plain enum or titled
oneOf), or multi-select string enum (the specified enum/anyOf items variants).
Check the pinned subset's required and optional field types, supported string
formats, numeric/length/item bounds, default types and enum option shapes;
`required`, when present, is a string list naming declared properties exactly
once each; duplicate names are malformed. Accept
the empty object schema and every specified enum variant. Refuse nested object
properties, arrays of objects, arbitrary non-enum arrays, unknown property
types and advanced schema constructs such as references or general composition
before any batch member is sent. Do not resolve schema references or fetch
resources. Preserve annotation/extension data that does not introduce an
unsupported validation construct, without rewriting the admitted raw schema.
The pinned [form schema subset](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation#requested-schema)
defines this finite validator; use its full examples as positive fixtures and
nested/unsupported/mistyped variants as zero-frame falsifiers. This checks the
request's schema shape, **not the client's content against it**: the existing
component case forwarding schema-invalid object content remains required.

For form acceptance require object `content`; for URL acceptance require
`content` to be absent. On either valid acceptance return the **whole result**,
including `action`, object content where applicable and unknown result fields.
Sampling and roots results remain whole irrespective of any `action` member.
Missing/unknown elicitation action, malformed form content and content-bearing
URL acceptance refuse. Existing explicit decline/cancel and client-error
policies remain terminal refusals; timeout remains omitted input on a bounded
retry. This correction does not turn refusal or silence into acceptance.

Use one crate-private mode-aware ElicitResult validator in the protocol layer
for the bridge and legacy destructive-confirmation parser. It validates the
raw result and returns the recognized action without altering that value;
accepted form/URL content rules are identical in both consumers. Consumers
retain their own terminal decline/cancel/error policy and the bridge files
the original whole accepted result. Confirmation selects Form explicitly.

There is one necessary legacy wire adaptation to otherwise exact params:
[2025-11-25 URL elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
requires `elicitationId`, which is absent from the 2026 request shape. The
`ClientChannel` interface still receives the backend's exact raw params. Its
production legacy adapter clones only a URL params object and inserts a missing
`elicitationId` equal to this prompt's unique bridge ID; the JSON-RPC ID is
unchanged. Preserve an already present nonempty string ID and every other field
exactly. Do not serialize through typed forwarders, synthesize form content,
change the URL or insert an ID into any other mode/method. Planning rejects a
present invalid legacy ID before the first prompt in the batch, so a later bad
entry cannot cause a partially delivered batch. The adapter does not store a
second ID map or interpret backend state.

URL acceptance means consent to navigate, not completion of the out-of-band
operation. Retry with the exact action-only result and backend state; only the
backend's final result establishes completion. Existing round and aggregate
bounds still apply if the backend asks again. Optional legacy completion
notifications are not fabricated by this bridge because it cannot observe the
external operation's completion.

### Single-recipient request delivery (U5 design decision)

Direct `send_to_session` cannot carry bridge requests: its broadcast sends the
same request to every subscriber. Keep that method for notifications. Add one
private `send_request_to_session` primitive over bounded per-writer request
queues registered **inside `ClientSession`**; do not add another session map.
Each live SSE body and the stdio writer registers a unique writer ID with a
bounded sender and removes it on drop. Choose one live writer in stable
registration order and enqueue the frame exactly once. A failed `try_send`
proves non-delivery and may select another live writer; a successful enqueue
must never be replayed to another writer after delivery becomes uncertain.

The queued request carries its exact bridge ID and the per-prompt
`DeliveryProgress` object created by `InputBridge::ask`. The production writer
marks handoff; queue rejection/drop or stream closure marks delivery failure.
The channel future waits for handoff and then the correlated reply under the
existing bridge-owned prompt deadline. The shared progress survives cancellation
of that future so `ask` can distinguish timeout-before-handoff from a genuinely
unanswered prompt. Cancelling before handoff prevents a queued frame from being
handed off later; handoff and cancellation use one synchronized transition.
Preserve whether handoff occurred when recording later cancellation, and record
known transport failure separately from the bridge abandoning a timed-out wait. A dropped/rejected frame before
handoff, a writer I/O error or a closed selected stream returns `NoSession`
and cancels that waiter; it cannot turn into a timeout-driven answerless retry.
No live writer means immediate `NoSession`. Once any JSON-RPC response arrives,
the response itself proves delivery and remains authoritative.

The acknowledgement boundary is explicit: stdio acknowledges after `flush`;
HTTP acknowledges when its response body yields the complete encoded SSE frame
to the HTTP transport, **not merely when the queue accepts it**. HTTP body yield
cannot prove peer receipt or TCP flush; do not claim that guarantee. A guard on
the selected response body cancels its still-pending exchanges when the stream
drops, including drop before handoff. If the stream stays live and no answer
arrives, the existing unanswered-prompt policy applies. Acceptance must stage
both pre-handoff drop and post-handoff disconnect; neither retries the backend.
There is no blind retransmission on another stream.

`ClientChannel::send_request` receives `Arc<DeliveryProgress>` as its final
argument. `DeliveryProgress` is an opaque public handle because external
implementers of the public channel trait must acknowledge actual handoff;
`mark_handed_off()` returns whether that transition was admitted. Its one
synchronized phase enum remains internal, with the following transitions.
Tests' fake clients acknowledge only after recording their observed frame;
production enqueue never supplies that acknowledgement. Implement the channel
trait directly on the existing `ProxyManager`, preserving its current pending
map and `PendingSampleGuard`. Existing typed forwarders remain independent.

The crate-private writer seam is
`NotificationMultiplexer::register_request_writer(session_id) -> Option<RequestWriter>`.
`RequestWriter::recv`/`try_recv` yield a `QueuedRequest` carrying the complete
encoded JSON-RPC `json` and the same `delivery` handle. The registration owns
the selected writer's lifetime; dropping it fails its outstanding deliveries.
Its crate-private `queued_count` reports the underlying receiver's item count
so tests can establish a full or unreceived queue without consuming a frame.
The HTTP body and stdio loop both consume this seam. Unit integration fixtures
may control a real registration, but this cannot replace tests of HTTP body
yield, stdio flush or transport shutdown.

Terminal states
retain whether handoff occurred and the failure cause; resetting those facts
would confuse failed delivery with a live unanswered prompt.

| Current state / event | Next state / obligation |
|---|---|
| Queued / writer claims frame | Writing for stdio; HTTP remains queued until one atomic complete-frame body yield. Only that registered writer may claim it. |
| Queued / HTTP body yields the complete frame while exchange remains live | HandedOff. Check cancellation and record this handoff in the same synchronized transition as yielding the frame. |
| Queued / cancellation or deadline | Cancelled, with no handoff; dequeue must suppress the frame. Remove pending ID; no backend retry. |
| Queued / rejected queue or selected stream drop | Failed, with no handoff; return NoSession and remove pending ID. |
| Writing / flush completes while exchange remains live | HandedOff. The writer acknowledges the complete frame exactly once. |
| Writing / cancellation or deadline before flush | Cancelled, with no acknowledged handoff. Remove pending ID and do not retry. Bytes already written cannot be recalled: finish this one frame within the bounded output/shutdown deadline or close the transport. Do not start another frame in its middle or acknowledge the cancelled exchange. |
| Queued or Writing / correlated client response wins | Answered; the response proves delivery even if writer acknowledgement has not yet run. Validate that response normally. |
| HandedOff / correlated response | Answered; resolve exactly one waiter. |
| HandedOff / live prompt deadline | Cancelled, with handoff retained and no known transport failure; only this timeout takes the existing omitted-answer retry. |
| Writing or HandedOff / selected transport failure | Failed; preserve handoff history, return NoSession, remove pending ID and do not retry. |
| Any nonterminal state / outer caller cancellation | Cancelled; remove pending ID and end the bridge without retry. Queued frames are suppressed; already-started writes follow the complete-frame-or-close rule above. |
| Answered, Failed or Cancelled / late reply, handoff or duplicate close | Remain terminal; never restore pending state, emit a suppressed frame or consume another exchange's reply. |

The writer's bounded output/shutdown handling is transport lifetime control,
not a second prompt timeout. Tests stage each side of the claim, flush,
response and cancellation transitions, including a partially written stdio
frame. They distinguish a valid response that wins from a late response after
terminal cancellation.

Tests separate exact raw roundtrip/ID preservation from single-recipient delivery
and acknowledgement failures. A controlled real writer/HTTP-body seam proves
the failure boundary; a real two-stream system case proves the primitive is
actually wired. Existing broadcast notification tests must remain green.

## Stdio: continuous reader, bounded dispatch, single writer

Use exactly one internal serving seam, called by production `run_stdio`:
`async fn serve_stdio<R, W>(context: StdioServeContext, reader: R, writer: W)
-> Result<()>`, with `R: AsyncBufRead + Unpin + Send + 'static` and
`W: AsyncWrite + Unpin + Send + 'static`. Production passes `BufReader<Stdin>`
and `Stdout`; deterministic tests pass duplex and controlled short-writing
adapters. No second test-only dispatch loop is allowed.

`StdioServeContext` owns the shared `MetaMcp`, proxy/multiplexer, policies,
limits and telemetry sink. The separately owned scheduled-expiry change supplies
the production continuation state/clock handle and cleanup guard moved into
this context; root owns their concrete types, lifecycle and clock injection.
The bridge owns only reader/admission/dispatch/writer logic. The same root clock
hook drives expiry tests; do not invent a second bridge cleanup timer or clock.
Owning context inside `serve_stdio` makes EOF, writer error and task cancellation
end the same lifetime that owns the scheduled-expiry guard. Root's lifetime
suite can therefore exercise production cleanup through this seam. The normal
`run_stdio` preparation/shutdown of backend warm-start and health tasks stays
integrated with this one serving call.

The transport owns three coordinated activities, with cancellation owned by
that serving lifetime rather than detached tasks:

- **Reader:** continuously reads/decodes lines, routes response envelopes to the
  shared proxy before request dispatch, handles cancellation notifications, and
  admits normal requests to a bounded in-flight set. It never awaits a backend
  call, a prompt answer, or a dispatch permit. Reply and cancellation ingress
  remains usable at request capacity. Duplicate active client request IDs refuse
  without replacing the original cancellation handle.
- **Dispatch:** tracked tasks invoke the existing shared dispatch path and send
  complete response values to the writer queue. Do not clone a durable telemetry
  sink into tasks: observe/persist each inbound message in the reader before
  dispatch can await, preserving NFR.OBS.1, and split the existing observation
  prologue from dispatch. Batch requests retain envelope semantics; members
  cannot bypass the barrier
  or lose correlation. Reject prompt-capable members batched with `initialize`
  using `-32600`, rather than queueing them behind an initialized notification
  that a client may send only after receiving the whole batch response. The
  initialize member still receives its response. Separately pipelined calls
  remain bounded behind the barrier.
- **Writer:** one task owns stdout and serializes whole JSON values plus newline
  and flush. The generic writer seam is production code, so controlled flush
  and short-write tests exercise this same writer rather than a fixture copy.
  It consumes the bounded response queue, the selected request queue and the
  session's broadcast notification receiver, writing raw request data rather
  than an SSE wrapper.
  All responses, server prompts and protocol notifications use this writer.
  Initialize carries a flush acknowledgement that opens the first barrier;
  receipt of `notifications/initialized` opens the second. Neither permission
  is inferred from task spawning or enqueue order.

U2 inventory is resolved at source: `ServerConfig::shutdown_timeout` defaults to
30 seconds, `max_body_size` to 10 MiB and `StreamingConfig::buffer_size` to 100;
there is no stdio admission limit. HTTP's 10,000-permit drain semaphore is not a
suitable new stdio default. Set explicit private stdio bounds: **32 active
requests**, **8 pre-initialize queued requests**, **32 queued response frames**;
per-writer request queues reuse the configured positive streaming buffer size.
Reject zero buffer size as configuration error, not by silent clamping. Bound
input frame reads incrementally using `server.max_body_size` so newline-free
input cannot grow before a late size check. Use the configured shutdown timeout
as the maximum drain deadline, then abort and join remaining tasks.

On admission saturation, enqueue JSON-RPC `-32000` with `Gateway is at capacity`
without waiting in the reader; if even the bounded output queue cannot accept
that error, close admission and terminate the session as output saturation.
These are engineering limits, not claimed performance measurements; WIRE.12/13
must measure them before the stdio implementation is accepted. On output queue saturation, multiplexer lag, stdout failure, EOF or
outer cancellation, close admission, cancel and join active dispatch, drop
pending guards, stop/join the writer, remove the stdio session, then run the
existing warm-start/reaper/health-loop/backend shutdown sequence. Do not reinterpret
lost output as the ordinary unanswered-prompt retry. Cleanup on outer cancellation
needs RAII as a backstop in addition to the awaited normal shutdown path.
A closed pipe is not a trigger to replay a write against the backend.

Keep pre-initialize `server/discover` compatibility probes and ordinary ping
behavior. The new barrier applies to operations that could emit input prompts;
it is not permission to silently change unrelated discovery semantics.

## One accounted backend attempt and one final-result decision

Before bridge retries are wired, extract the existing paid-attempt boundary from
`invoke.rs`: authorization/security context, governance check, dispatch,
statistics and epilogue. Both the initial call and the bridge adapter call that
same path exactly once per backend attempt. Preserve existing conditional
emissions rather than adding an approximate second counter.

| Existing operation | Required treatment |
|---|---|
| `enforcer.check(tool, api_key_name)` | Before each paid attempt; preserve `-32003` and the block reason on refusal. No backend or spend after denial. |
| `stats.record_invocation`, `ranker.record_use` | Preserve current pre-governance placement: attempted invocation/rank use increments even when that attempt is then budget-denied. These are not paid-dispatch counters. |
| `mcp_tool_invocations_total`, `mcp_tool_invocation_duration_seconds` | Observe every actual dispatched attempt exactly once. |
| `stats.record_cached_tokens` | Record successful cached-token usage under the existing condition. |
| `record_error_budget(BudgetOutcome::of(...))` | Observe every dispatch outcome exactly once. |
| `cost_tracker.record`, `enforcer.record_spend` | Record successful attempts according to existing feature gates/conditions. |

Change `BackendInvoker::invoke` to return the existing typed `Result<Value,
Error>` and propagate that failure through `InputBridge::run`. Add a backend
failure variant carrying the original `Error`; the invoke boundary unwraps it
without changing its code, status or data. `Error` is not `Clone`/`Eq`, so the
bridge error enum cannot retain those derives unchanged: existing tests use
variant/field assertions for bridge failures after this seam change. Preserve
their expected outcomes. A governance refusal must not become success-shaped
JSON or a generic bridge error. Component backend fakes return `Ok`; this is an
interface adaptation, not permission to rewrite their fixtures or semantics.
Preserve the firewall owner's typed `Error::ResponseFirewallRefused` provenance
through this path too. Never flatten it to text or infer it from a backend's
code/message; the external adapter retains that server-only identity when
projecting the generic refusal and avoiding breaker success/failure updates.

`Bridge::retry_params` produces an overlay, not a complete tool call. Reuse
`OutboundRetry::apply` so `requestState` and `inputResponses` are siblings of the
original `name` and `arguments`. Preserve a user tool argument named
`requestState`. Do not run `redeem_retry` on backend-owned state; no gateway
continuation was minted for a legacy call held open by the bridge. Every retry
gets a fresh backend request ID while its original request and caller remain
bound. Bridge bounds stay owned by `InputBridge::run`. Source inspection found
that its current aggregate check only surrounds rounds/prompts: the awaited
backend retry itself is not deadline-wrapped. Bound that await by the same
remaining aggregate budget and return `BridgeError::Deadline` when it expires;
never retry after this deadline. This repairs enforcement of the existing bound,
not its value. A timeout does not prove a backend write had no effect, so the
terminal result must not invite automatic replay. WIRE.6 needs a stalled-backend
fixture as well as prompt/round exhaustion.

Place bridging after per-attempt response admission and MRTR.9, and before
continuation minting. A legacy bridge mints no redeemable continuation for its
already completed exchange. The admission path applies to the first backend
result and every retry result, never only to the final result.

Extract one common per-attempt processing path from `invoke_tool_traced`:
classify the raw backend completion claim; preserve the existing completed-effect
idempotency checkpoint for a completed result before any post-dispatch policy
can refuse it; run the applicable response policies; only then expose an
admitted challenge to the bridge or continuation minting. An input_required
attempt must not be checkpointed as a completed effect. The accounted retry
adapter uses this same path, without another policy finalizer or reservation
owner. A final policy refusal must never release a completed effect for replay.

The existing D1 response-contract gate and D2 anomaly screening are currently
below the proposed bridge hook in `invoke.rs`. Move their decision into this
shared per-attempt admission, preserving action/observe settings, annotations
and refusal error families. For a challenge, their inspection text is canonical
JSON of **inputRequests**, including every raw method/params/unknown question
field, excluding the backend's opaque requestState. The existing
`response_inspect::extract_text_from_result` returns empty for a bare
InputRequired and cannot supply this text. Preserve the complete typed challenge
separately; the serialized inspection view never replaces its params. D1
fail_closed/no contract still refuses; a declared contract's forbidden patterns
and max_bytes must inspect the question, not silently skip an empty string.

Existing context-integrity enforcement must also decide before a challenge
can reach the client. Observe/Allow may retain outer diagnostics while leaving
client-visible inputRequests unchanged. If an enforced transform/redaction or
withholding would change a question, refuse it instead of silently rewriting
the backend's request. This same rule applies to the firewall's challenge
inspection. No raw prompt, answer, opaque state or finding fragment is added to
refusal text or logs by the new path.

The separately owned [response firewall](2026-09-06-firewall-response-enforcement.md)
supplies reusable scanner/enforcement code. An interim challenge is a distinct
artifact inspected exactly once before emission; it is not a final tool result.
The agreed crate-private seam is
`MetaMcp::enforce_firewall_challenge(&self, challenge: &serde_json::Value,
targets: &[ResponsePolicyTarget], correlation: &ResponseCorrelation<'_>)
-> crate::Result<()>`. The firewall owner owns `response_security.rs` and the
always-available `meta_mcp` re-exports: `ResponsePolicyTarget { server: String,
tool: String }` and `ResponseCorrelation<'a> { session_id: &'a str,
caller: &'a str, external_server: &'a str, external_tool: &'a str }`.
Bridge passes the full client-visible inputRequests Value, not the surrounding
opaque state. The helper scans a clone using the shared configured firewall;
Block or any redaction/mutation refuses generically, while Warn/Allow passes the
unchanged question. Audit the final combined decision once, tagged by the
server as `bridge_challenge`; do not audit Warn and then secretly refuse.
Feature-off uses the same signature as a no-op. No signing or transport
delivery-attempt log belongs in this helper.

This helper covers internally consumed **legacy bridge** questions. A modern
InputRequired returned externally uses only the firewall owner's external
response boundary, tagged `final_response`; do not scan it through this helper
and again at that wrapper. At that one external boundary, inputRequests and
opaque requestState are immutable: Block or a firewall redaction that changes
either must produce generic refusal before the one final Block audit. Allowed
modern output preserves both exactly. The firewall owner implements this
specialization; it is not another bridge scan. Common D1/D2/context admission remains before
bridge/mint in both cases. Tests filter the relevant artifact kind.
The actual final tool result retains its own D1/D2/context processing and the
firewall owner's one external final-response inspection/signing boundary. Do
not route the interim through a finalizer that changes its wire kind, and do
not use final-only FWR-02 evidence to claim challenge coverage. WIRE.21 stages
both an immediately refused challenge and a later refused challenge after a
permitted round, with zero emission/retry for the refused artifact.

Derive `interim`/`stopped_to_ask`, idempotency settlement and response-cache
eligibility from the **final** result. The first interim only selects the
bridge; retain each raw attempt's completion claim for its checkpoint before
policy transformation. Policy and accounting apply to every attempt and final
delivery retains its separate result-level gates. Invoke-loop duplication and direct unaccounted dispatch were
rejected: both create a second owner for bounds or budgets.

## Confirmation dependency and observability

CONFIRM.2 owns gateway-originated modern `InputRequired`, continuation
binding/single-use and cache-before-redeem behavior. Its implementation must
reuse the same initialized session and production channel for legacy HTTP and
stdio, and retain the central admin/authorization gate. A generic bridge timeout,
absent input or backend retry is never affirmative confirmation. The explicitly
preserved legacy HTTP warning fallback remains a different, named policy outcome.
The confirmation owner coordinates caller-context edits with the bridge owner;
root authorized the conflicting transport-contract amendments and the R2
atomic-redemption test-plan row in the confirmation package; its implementation
and audit decisions retain their owner.

Follow the era-by-transport [confirmation matrix](2026-09-06-confirm-2-destructive-confirmation.md#current-era-by-transport-contract--full-stdio-scope-amendment),
including the deliberately preserved legacy HTTP warning fallback and the
existing refusal floor for legacy stdio when confirmation fails.

Use the existing `BridgeObserver` seam for NFR.OBS.4; record request kind,
outcome and bounded count/duration, never answer bodies, prompt payloads,
credentials, or unbounded session-ID labels. Confirmation-specific audit
requirements remain with CONFIRM.2. Remove the existing full reply-body debug
field at `router/handlers.rs` (`Received sampling/elicitation response POST-back`);
WIRE.17 captures logs as well as observer records. Session/ID correlation may
remain in debug logs where already supported, never raw prompts or responses.
No new meta-tools are needed.

## Unknowns and fail-fast schedule

| ID / state | Owner | Check or answer | Trigger / bad outcome |
|---|---|---|---|
| U0 resolved (askable) | Mikko Parkkola | Accepted full stdio expansion recorded in the linked scope decision. | Removes the old include/exclude question; HTTP-only cannot close release. |
| U1 resolved (checkable, I) | MIK-7212 | Read `proxy.rs` register/resolve/guard and both typed forwarders; raw ID + params can use existing primitives. | Select raw adapter; reject typed-forwarder wrapper. Runtime cancellation remains WIRE.11, not measured by this read. |
| U2 limits resolved (checkable, I); red fixture deferred | MIK-7387 | Read `src/config/mod.rs` and `src/config/features/streaming.rs`: defaults above, no stdio concurrency setting. The explicit 32/8/32 limits, positive configured request buffer, `-32000` saturation error and configured shutdown deadline above are the selected design. Run the saturation/reply-progress fixture. | After plan approval, before stdio source implementation. If the fixture cannot keep reply ingress live at capacity, revise the admission mechanism; do not raise limits to hide the defect. |
| U3 executable cancellation result deferred | MIK-7388 | Red `WIRE.11`: stage a real pending ID, abort its owner, await cancellation and assert removal; wrong-session/late reply cannot complete the next exchange. | First executable new test after plan review; before runtime adapter implementation. If primitives cannot uphold it, amend the adapter boundary before dependent wiring. |
| U4 transport contract resolved; audit/implementation evidence deferred | MIK-7246, coordinated with MIK-7212 | Root authorized the full stdio confirmation amendment on 2026-09-06; the linked confirmation matrix is now the common contract. Its U2 owns the separate pending operator audit decision. | Shared interface agreement before shared-symbol edits; cross-transport confirmation and required audit evidence before deployment. Missing audit policy does not authorize omitting a required record. |
| U5 mechanism selected; executable handoff result deferred | MIK-7212 | Single-recipient request queue + writer acknowledgement + stream-drop cleanup specified above; ordinary notifications remain broadcast. Run separated raw-roundtrip, two-stream, pre-handoff drop and post-handoff disconnect cases. | After design/plan review, before production HTTP delivery implementation. If the actual HTTP body cannot expose the named handoff/drop boundary, revise that mechanism before dependent wiring; do not call enqueue a flush. |
| U6 protocol mismatch resolved at source; executable conformance result deferred | MIK-7212 / MIK-7388 | Pinned modern MRTR/Elicitation and legacy URL elicitation specs contradict content-only projection and the URL fixture's invented form content. Root approved complete ElicitResult and the narrow legacy ID adaptation. WIRE.20 plus corrected existing component assertions must fail the old implementation. | After plan approval, before production bridge changes. A form-only fixture or fake adapter cannot establish URL compatibility; preserve raw fields and exact IDs while proving the action-only backend retry. |
| U7 admission order resolved; executable refusal evidence deferred | MIK-7212 with MIK-7407 | Root approved shared per-attempt D1/D2/context ordering and firewall owner agreed the exact challenge helper above. WIRE.21 observes meaningful challenge text and zero frames/retries for a refused artifact, plus completed-effect replay prevention. | After plan approval, before hook implementation. Final-only scanning or empty challenge extraction is not acceptance; preserve current configured action/observe behavior. |
| U8 HTTP control capacity resolved; executable progress deferred | MIK-7212 / MIK-7388 | Source confirms normal semaphore is acquired before response routing. Separate 32-permit control lane, bounded batch control dispatch and normal-member admission are specified above. WIRE.22 fills real normal capacity, proves mixed batches release control permits before normal admission/dispatch, and separately exhausts controls. | Before production HTTP bridge acceptance. If control traffic still waits for the normal permit, repair ordering rather than increase its capacity. |

No deferred row is a pass; no dependent source implementation starts before its
specified precondition. The three stdio ACs remain ignored in the current tree;
that is unresolved implementation evidence, not an accepted release exclusion.
The 23-test component count was inspected, not re-run for this docs amendment.
A speculative `.../2026-07-28/client/input` URL failed to open; the authoritative
MRTR page linked above was reached from the pinned changelog instead. Incorrect
local policy/helper paths were corrected to the files cited above; no source
claim depends on the missing paths.

## R1 review evidence and disposition — closure recheck pending

Run `mcp-v4-bridge-design-20260906-r1` submitted identical frozen material to
`gpt-review` and `grok-review`. Both wrapper processes exited **0**; both
canonical ledger rows have `process_status=ok`, material size **390419** and
SHA-256 `f9258f751483faad6ff21ca10116cc31c9d6593812c80e0587147abe23ba54f1`
(scope + NUL + stdin). Both verdicts were **SHIP-WITH-FIXES**, not approval.
Their output paths are `gpt-20260906T132324Z-31996.md` and
`grok-20260906T132325Z-31997.md` under
`/Users/mikko/.claude/data/reviews/runs/`; frozen copies, manifest and receipts
are in the external `mcp-v4-bridge-design-20260906-r1` review archive.
The following repairs are documentation changes awaiting closure verification;
no runtime defect is claimed fixed by writing its intended behavior.

| Finding | Source verification and disposal |
|---|---|
| GPT.1 reply-body log leaks answers | Confirmed `handlers.rs` logs `%request` on the POST-back path. Design requires removing that field; WIRE.17 now captures debug logs as well as observer output. |
| GPT.2 / Grok.2 stdio confirmation contradicts C5 | Confirmed. Root authorized only the conflicting confirmation passages to change; one era-by-transport matrix now governs WIRE.16 and the companion confirmation cases. Preserve canonical legacy HTTP warning policy. Grok's suggested removal of positive stdio coverage is rejected because it would cut approved scope. |
| GPT.3 reinit/admission race | Confirmed the design had no atomic transition. Eliminate mutable post-handshake declarations: one lock admits initialize once, then changing support needs a new owned session/process; WIRE.15 tests it. |
| GPT.4 enqueue is not writer delivery | Confirmed `send_to_session` is only broadcast enqueue. Specify per-writer request delivery and progress/handoff/drop state; WIRE.18 tests pre-handoff timeout and both disconnect boundaries. Explicitly do not promise peer receipt from an HTTP body yield. |
| GPT.5 gateway initialize delay not exercised | Confirmed the old fixture delays backend initialize while the gateway response is local. Require controlled gateway writer flush on the same generic production serving seam. |
| GPT.6 probabilistic framing test | Confirmed large writes alone do not force scheduling. Add deterministic short-write/interleaving falsifier at the production writer seam, retaining the real-process test. |
| GPT.7 canonical MRTR IDs absent | Confirmed. Companion now maps every canonical MRTR criterion to bridge cases or its separately owned evidence with a reason. |
| GPT.8 unnamed deferred owners | Confirmed. U2–U5 now name stable MIK tickets. |
| GPT.9 DOCS DoR evidence incomplete | Confirmed. Applicable DOCS gates and reasoned N/A summary are recorded above. |
| Grok.1 existing stdio fixture is Modern and skips initialized | Confirmed `asking_call` sets protocol `_meta` keys and the process tests omit initialized. Plan explicitly repairs those helpers/handshakes and asserts Legacy classification, without weakening production classification. |
| Grok.3 stdio owner domain unspecified | Confirmed compatibility `get_or_create_session` uses anonymous ownership. Require an internal `stdio-local:` owner domain outside HTTP mappings; WIRE.19 exercises exact-ID GET/POST/DELETE isolation. |
| Reviewer improvements | Selected single-recipient primitive; separated WIRE.8 from WIRE.18; pinned `params.capabilities`; preserve pre-governance attempt statistics; reject same-batch prompt requests during initialize; share one private exact-ID exchange helper. |

## R2 review evidence and disposition — closure recheck pending

Run `mcp-v4-bridge-design-20260906-r2` submitted identical frozen material to
both vendors. Authoritative ledgers show **395687** material bytes and SHA-256
`4cac6bc863390a6e097ceb492126f88d87a37fac175287d0cab90f8463b817df`;
both wrapper exits were **0**, both process statuses **ok**, and both verdicts
**SHIP-WITH-FIXES**. Actual output files are
`gpt-20260906T134951Z-699.md` and `grok-20260906T134951Z-700.md` in the canonical
review output directory; the external R2 archive holds exact frozen material,
outputs and receipts. These results do not approve the repaired bytes below.

| R2 finding / improvement | Source disposition and repair |
|---|---|
| GPT NOW: confirmation MRTR.5c incorrectly called replica-only | Confirmed against the canonical requirement. Root authorized a narrow test-plan correction: a fresh-key concurrent retry of the same continuation cannot reach the held destructive dispatch twice; dedicated atomicity race case retains the real ledger. |
| Grok NOW: initialize-plus-prompt batch has no falsifier | Confirmed. WIRE.14 now stages that exact batch, expects initialize success plus member `-32600` and zero prompts, then proves a separately initialized call succeeds. |
| GPT optional state/queue/case specificity | Added DeliveryProgress transition table and partial-write rule; concrete zero-buffer/per-writer-capacity cases; separately named WIRE.11/16 outcomes. |
| Grok optional ownership/bounds/observer/mapping specificity | WIRE.19 explicitly depends on GH452.SESSION.1; WIRE.12 covers 8/32/configured queue bounds; WIRE.17 requires bridge phase; WIRE.14 maps to canonical MRTR.7a and stdio closure. A full response queue cannot emit an extra refusal frame and instead exercises the specified bounded shutdown. |
| Independently discovered pinned-spec elicitation defect | Root approved the evidence-backed correction after both R2 reviews. U6, the mode-aware whole-result contract and WIRE.20 replace obsolete payload expectations while retaining the existing run loop and component case names. Fresh review must include this scope receipt and the exact pinned spec evidence. |

Inventory validation now keys only canonical criterion table rows: **21 MRTR
criteria**, all mapped. An earlier 22-ID tally included the bare MRTR.7 prose
shorthand; it was not an extra criterion. All 23 existing component names and
24 production supporting AC IDs were accounted for at R3 freeze. No runtime test result
is claimed by this correction.

## R3 review evidence and disposition — closure recheck pending

Run `mcp-v4-bridge-design-20260906-r3` supplied the same frozen **472454**
material bytes to both wrappers, SHA-256
`e68f9e8dd15695146caf40cbb198ef2660c45fbca14d39d2b102a6a0314e743e`.
Both exits were 0 and both authoritative ledger process statuses were ok.
Grok returned **SHIP**; GPT returned **SHIP-WITH-FIXES**. Grok reported truncated
stdin display and read the full live docs/specs; all four owned documents were
verified to still match the R3 frozen hashes when its result arrived. These
receipts are in the external R3 archive, not approval of the R4 repairs.

| R3 item | Source verification / disposition |
|---|---|
| GPT NOW: response-contract gate bypassed by early bridge | Confirmed D1 below mint in invoke.rs; existing extraction is empty for bare inputRequests. Root approved common per-attempt admission before exposure, preserving D1/D2/context enforcement, completed-effect checkpoint and the firewall owner's single challenge helper. WIRE.21 covers both missing contract and declared-contract dangerous prompt, not just the empty-extraction case. |
| GPT NOW: HTTP normal semaphore starves bridge controls | Confirmed acquisition before response routing in handlers.rs. Dedicated bounded control lane and WIRE.22 cover response/initialized/cancellation progress and mixed-batch admission without permission bypass. |
| GPT NOW: reused legacy confirmation form invalid | Confirmed constructor omits requestedSchema and parser accepts action-only form. The authorized transport contract now requires valid empty-object form schema and object-content ElicitResult; WIRE.16 and confirmation composition cases terminally refuse malformed/error replies while preserving unavailable-channel policy. |
| GPT NOW: explicit null mode accepted as omitted | Confirmed in ElicitationMode::from_params. Shared parser now requires a recognized string when present; WIRE.20 contrasts omitted-form success with null/nonstring/unknown-mode zero-frame refusal. |
| GPT/Grok optional small consistency repairs | Exact-ID helper returns the raw JSON-RPC envelope; tests pin fresh backend retry IDs; DeliveryProgress is one named enum; U2–U8 decisions and deferred executable evidence are distinguished. Root authorized synchronizing the two old release-test-plan oracle cells with the already reviewed URL/result contract. |
| GPT optional serialized-byte queue budgets | Deferred optimization owned by MIK-7387's runtime capacity validation; no new default output-size restriction is added here. Current explicit item/input-frame bounds remain required and are not represented as a low-RSS guarantee. Record queued serialized bytes and their return to zero alongside counts. Retained bytes after completed drain fail the existing cleanup requirement; a further default payload budget needs its own measured compatibility decision. |

At R4 the supporting matrix had 26 IDs (WIRE.1–22, STDIO.1–3, CANCEL.1),
mapped to unchanged canonical criteria. R4 scope remains design/test-plan
correction; all source and executable evidence is still owned by later gates.

## R4 review evidence and focused repair disposition

Run `mcp-v4-bridge-design-20260906-r4` supplied identical frozen **308249**
material bytes, SHA-256
`9db0c1c96c65b23d69416505971bee3d6e76a3ad234b5e2e8098b7c2c38d7e04`.
Both authoritative ledgers report process status ok, both wrapper exits were
0, and both verdicts were **SHIP-WITH-FIXES**. Actual outputs are
`gpt-20260906T144843Z-53447.md` and `grok-20260906T144843Z-53448.md`;
the external R4 archive includes these outputs and verified receipts. Five
owned documents still matched frozen hashes when both outputs arrived.

| R4 finding / improvement | Source-verified disposition |
|---|---|
| GPT NOW: WIRE.21 can miss the bridged completed-effect path | Require admitted prompt, valid answer, completed side-effecting retry, policy refusal, then same-key resubmission with exactly one effect and no extra prompt/dispatch. A direct-call checkpoint test cannot close this case. |
| GPT NOW: mode parser is not required-request validation | Require raw params object, message string, required form schema structure or valid absolute URL before whole-batch admission. Keep the raw value and unknown fields; only the pinned legacy URL ID adaptation is permitted. WIRE.20 contains positive neighbours and each malformed field case. |
| Grok NOW: mixed batches can hold control occupancy while waiting on normal work | Drop control permit immediately after controls; non-blocking-admit normal members with per-member capacity refusal. WIRE.22 fills normal capacity with unrelated pending prompts and submits enough mixed batches to expose pinned control permits, then proves an unrelated reply succeeds. |
| Small consistency improvements | Shared protocol ElicitResult validator; repaired confirmation table rendering; WIRE.16 named malformed/error splits; invert the old null-mode unit oracle; WIRE.20/21/22 appear at their fail-fast preconditions; common dispatch_batch_with_sink assembly. |
| Shared firewall dependency clarification | Modern external InputRequired also preserves immutable questions/state at its one external final_response scan. The firewall owner owns its specialization and real-wire test; no duplicate legacy helper scan. |
| Repeated optional serialized-byte budget | Same named deferred optimization and measured-capacity owner as R3; no new compatibility restriction or memory guarantee is inferred. |

Root directs focused finder closure under canonical repair item 6: each finder
checks its own repaired findings, without reopening unchanged full design.
The repaired bytes remain pending that closure; no runtime pass is claimed.

## Capability advertisement delta — strict modern backend, review pending

This is a source-backed completion of MRTR.7/MRTR.9 within the approved full
bridge, not a new client-facing feature. Component design closure is recorded
externally in `bridge-design-closure.json`; its approved contract remains
unchanged. Source inspection while deriving real stdio tests found
`transport/http/mod.rs::with_modern_meta` unconditionally overwrites
`io.modelcontextprotocol/clientCapabilities` with `{}`. The pinned modern MRTR
spec forbids a backend from asking for an undeclared input type. A permissive
fixture that ignores that envelope would certify a bridge a conforming backend
cannot enter. This delta must be reviewed before its dependent source changes. WIRE.23 adds
one supporting ID (27 total), mapped to the unchanged canonical criteria.

Carry a fixed, copied `protocol::meta::Declared` down the existing accounted
attempt. Add `Backend::request_with_capabilities` and the matching `Transport`
method, with the existing request-with-headers arguments plus this declaration.
Existing APIs delegate with `Declared::NONE`. The exact delegation is:
Backend request → request_with_headers → request_with_capabilities(NONE), then
the single backend body calls Transport::request_with_capabilities. Its default
implementation calls request_with_headers so existing transport overrides retain
headers/identity; the default request_with_headers calls request. HTTP overrides
request_with_capabilities with its single request body; its request_with_headers
delegates to that override with NONE, and request delegates to request_with_headers.
The HTTP override never delegates back into an old wrapper. Move each
existing backend/HTTP implementation body into that one new entry rather than
copying accounting, retries, identity propagation or session recovery. This is
per-call data, never stored on a backend, transport, pooled entry or global.

At the gateway dispatcher, derive the value from the capabilities that this
attempt can actually service: a ready legacy session's immutable declaration,
intersected with its per-request narrowing slice, or the modern request's own
validated declaration. An absent legacy declaration, unready legacy session or
explicit empty slice advertises nothing. A declaration for one client cannot
be reused for another. Do not infer support from arbitrary `_meta`, nested tool
arguments, method names or the existence of a proxy. Independent dispatchers
that have no input-handling path keep the default NONE. The same effective
value applies to every bridge retry, including retries after omitted answers;
there is no capability escalation to make a later question succeed. Derive one
effective Declared using a helper next to its parser; use that same value for
outbound advertisement, MRTR.9 admission and InputBridge planning (passing no
second narrowing slice to the production run). The existing slice contains
capability names only: it removes whole kinds, not individual elicitation modes.

Add a bounded projection method on `Declared`, next to its parser, into protocol
capabilities: only the three supported kinds. Elicitation is present only when
form or URL is set, as the exact supported mode objects. If both mode flags are
false, omit elicitation entirely, even when the broad elicitation flag is true
from an unknown-only or malformed-mode source declaration. Never emit an empty
elicitation object for such a value: inbound parsing gives that shape form
support. Unknown declaration fields are never copied. The HTTP metadata builder keeps
unrelated caller metadata and overwrites both protocol version and capability
keys from trusted per-attempt facts. Notifications, probes and legacy handshakes
retain their existing NONE behavior. Legacy outbound peers are unaffected;
only requests to an already classified modern backend gain the trusted
capability envelope. The strict server/discover/probe fixture must classify the
peer modern while accepting NONE; it may demand input kinds only on tools/call. Do not use ambient task-local state or preserve an
untrusted capability blob to avoid the explicit parameter.

The strict HTTP backend fixture must classify as modern through real
`server/discover`, require the expected protocol/capability envelope before
returning InputRequired, and record each actual tools/call. It must refuse an
undeclared question, so deleting the propagation cannot leave the bridge test
green. Its success checks exact original name/arguments, sibling-only
inputResponses/requestState, whole accepted results, unchanged backend state,
and a fresh backend JSON-RPC ID on retries. A user argument named requestState
is preserved independently. Client calls in the legacy fixture carry no modern
protocol metadata and must classify as Legacy after a real initialize and
initialized barrier. Concurrent callers with disjoint declarations and reversed
answers demonstrate that both advertisement and retry correlation remain local.

Fail-fast unknown U9: the current transport's empty declaration is source-
confirmed; exact strict-fixture wire behavior is still unmeasured. First review
this delta and its WIRE.23 tests, then run that fixture against current transport:
it must report the missing required declaration before any question, rather than
silently fall through to a timeout. Only then implement and prove the full
question/answer/retry journey. Root reserved the narrow `backend/ops.rs` and
`transport/mod.rs` API hunks, `transport/http/mod.rs` metadata/request hunks and
our existing invoke attempt seam. No additional backend lifecycle owner or
accounting path is introduced. Root continues to serialize Spark compilation.

## Handoff order and ownership

1. Root obtains fresh dual design/plan review against these full documents;
   then reviews newly written failing tests as tests before implementation.
2. Bridge owner: `input_bridge.rs`, `proxy.rs`, `streaming.rs`,
   `protocol/meta.rs` and corresponding bridge tests. Reuse the 23 existing
   component cases and three real-process stdio fixtures. No test-only runtime.
3. Shared-boundary owner assigned by root: `server/mod.rs` (including the single
   internal generic `serve_stdio` seam),
   `router/handlers.rs`, `meta_mcp/mod.rs` and `meta_mcp/invoke.rs`. Coordinate
   with active confirmation, catalogue/auth and discovery work; these are not
   independent edit surfaces. Extract accounted attempts and preserve their
   regressions before connecting bridge retries.
4. Execute raw-channel cleanup, declaration/shape/accounting tests, real stdio
   and HTTP journeys, then the cross-transport confirmation integration.
5. Run applicable DoD coverage/mutation, formatting, clippy, security and full
   regression gates; obtain independent code and functional review, CI and
   deployment evidence. Keep MRTR.7/MIK-7387/MIK-7388 pending until their actual
   evidence is posted. Local docs, green fakes, review intent and ignored tests
   do not satisfy those delivery gates.
