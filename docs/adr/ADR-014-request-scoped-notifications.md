# ADR-014: A request-scoped notification rides its own request's response

- **Status**: Proposed, 2026-09-10
- **Criterion**: MIK-7272.SUB.2b — *request-scoped notifications MUST flow on
  the response stream of their own request*
- **Scope**: the outbound leg — how a `notifications/message` or
  `notifications/progress` caused by one request reaches that request's caller
  and no other. Out of scope, deliberately and stated again below: the
  `subscriptions/listen` stream (SUB.2a), idempotency (SUB.4), and websocket.

## Context

The ledger records this row as ABSENT and blocking
(`docs/requirements/RELEASE-4.0.0-criteria-status.md:230`), with the reason
stated precisely: *"ABSENT on the outbound leg, which is what keeps the
criterion unmet; the inbound leg has since been built and is scaffold, not
absent"*, and *"The verdict stays ABSENT because `SseExchange.notifications`
has NO production consumer"*. The same row: *"A parsed field with no reader is
a placeholder, not a half-implementation."*

Three inbound halves exist and three consumers do not.

1. **HTTP capture, dropped at the only call site.** `SseExchange`
   (`src/transport/http/mod.rs:283`) carries `response: JsonRpcResponse`
   (`:285`) beside `notifications: Vec<JsonRpcNotification>` (`:298`), the
   latter under `#[allow(dead_code)]` (`:297`). Its doc names the consumer that
   has not landed: *"the `Accept`-negotiated event-stream body in
   `gateway::router::handlers::meta_mcp_handler` — is the outbound half of
   `MIK-7272.SUB.2b` and lands next"* (`:288-296`). The sole call site discards
   the vector on the spot: `parse_sse_response(&text).map(|e| e.response)`
   (`:1345`), inside `send_request_with_headers` (`:1219`).

2. **stdio capture, with nothing registering a token.** `captured_notifications:
   DashMap<String, Vec<JsonRpcNotification>>` (`src/transport/stdio.rs:104`)
   is filled by `capture_notification` (`:463`) keyed on
   `params["progressToken"]` (`:467`), and drained by
   `take_captured_notifications` (`:448`) after `register_progress_token`
   (`:441`) — both `#[allow(dead_code)]` (`:440`).

3. **The per-request log level, parsed and never read.**
   `RequestFields::log_level: Option<String>`
   (`src/protocol/meta.rs:80`), from
   `KEY_LOG_LEVEL = "io.modelcontextprotocol/logLevel"` (`:49`), parsed at
   `:225-228`. The only production reader of `RequestShape` at all is
   `src/gateway/router/handlers.rs:810` (malformed → `-32602`) and `:841`
   (protocol version and `Mcp-Name` mirror). **No production code reads
   `fields.log_level`.** The similarly-named
   `log_level: RwLock<LoggingLevel>` (`src/gateway/meta_mcp/mod.rs:266`),
   written by `logging/setLevel` (`src/gateway/meta_mcp/protocol.rs:295`) and
   read by `current_log_level` (`protocol.rs:325-330`, itself
   `#[allow(dead_code)]`), is session state and a different lifetime.

A fourth fact, found by sweep in this session and not previously recorded:
**no code in `src/protocol`, `src/gateway` or `src/backend` mentions
`progressToken` in any spelling.** `src/protocol/meta.rs` declares five `_meta`
keys (`:43-51`) and none of them is a progress token. So the client's token is
never extracted from the inbound `_meta` and never forwarded on the outbound
backend request; `register_progress_token` has no value it could be called
with today. The stdio capture keys on a token the gateway never plumbs.

## Decision

**The sink is ambient to the request's own task, and the response body is the
stream.** Five parts.

### 1. Sink: a task-local, bounded, per-request buffer

The sink is a `tokio::task_local!` holding an `Arc` of a bounded
`tokio::sync::mpsc::Sender<JsonRpcNotification>` — the same shape and the same
mechanism the trace id already uses. `src/gateway/trace.rs:32` declares
`tokio::task_local! { pub static TRACE_ID: String; }`, `with_trace_id`
(`:64-69`) enters the scope with `TRACE_ID.scope(trace_id, future).await`, and
`current()` (`:57`) reads it back with `TRACE_ID.try_with(...)`. Production
enters that scope at `src/gateway/meta_mcp/invoke.rs:981`, inside `invoke_tool`
(`:972`), and reads it back two layers down inside the transport at
`src/transport/http/mod.rs:994`. That is the whole proof the mechanism reaches:
the handler, the invoke layer, the backend and the transport are **one tokio
task**, so a task-local sink needs no change to the `Transport` trait and
cannot bleed into another request. The ledger's claim that no trait change is
needed is true, and this is why.

The receiver end is held by the response body — the axum `Response` the handler
returns — and by nothing else. When the body is dropped the receiver is
dropped, the sender's sends start failing, and the buffer is gone. There is no
map keyed by request id anywhere in this design; see §5.

**The body is produced concurrently with the dispatch, not after it.** The
handler returns the response as soon as the stream exists, and the dispatch
future is driven by polls of that stream, so the receiver is alive for the
whole life of the dispatch. Awaiting the dispatch to completion and then
draining the buffer into a batched body would satisfy every ordering word
below by making it vacuous — nothing could arrive after the response, so
acceptance row 11 would assert nothing.

**A notification whose owner cannot be established is dropped and logged at
debug, never raised as an error.** This is not a new decision. stdio already
does exactly this in `capture_notification`'s `None` arm
(`src/transport/stdio.rs:474`), and says why (`:455-462`): *"A notification
with no token, or one whose token no caller supplied, is dropped exactly as
before — on a multiplexed stdout there is nothing else to attribute it to, and
inventing an owner is the failure this guards."* Erroring would let a chatty or
hostile peer fail a caller's otherwise-successful call. Over HTTP the case does
not arise: a notification arriving on the response body of a request *is* that
request's, which is why `parse_sse_response` (`src/transport/http/mod.rs:312`)
needs no key at all — it does, separately, refuse a peer *request* on that
stream (`"Peer sent request '{}' on the response stream"`), and that refusal
stands.

### 2. Correlation, per transport

| Transport | Key | Why |
|---|---|---|
| HTTP | none needed — the connection is the key | The backend's notifications arrive interleaved on the response body of the very request that opened it (`src/transport/http/mod.rs:1335`, `content_type.contains("text/event-stream")`). Attribution is structural. |
| stdio | the client-supplied progress token | One stdout is multiplexed across every in-flight call, so a key is the only attribution available (`src/transport/stdio.rs:104,467`). |
| websocket | **out of scope** | The test plan rows this criterion is verified by name two transports and no more: S-02 is *"over stdio and over HTTP"* (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:58`) and S-03 is per-request isolation on one connection (`:59`). Adding a third transport to the acceptance surface is a scope change, not an omission. |

Over stdio the gateway **never mints a token**. It passes a backend's own token
through only when it matches one the caller supplied — the rule already written
at `src/transport/stdio.rs:431-435` (*"MIK-7272.SUB.2b, §II.6 option (i)"*).
Because nothing today parses a progress token out of `_meta`, that plumbing is
**part of this change and not pre-existing**: an inbound `_meta` progress token
must be captured beside `log_level` in `RequestFields`, forwarded on the
outbound backend request, and handed to `register_progress_token`
(`src/transport/stdio.rs:441`) before dispatch. Without it the stdio leg has a
capture path that can never fire.

`notifications/message` stays unattributable over stdio when it comes *from a
backend*, as the existing note says: token-less methods have no owner on a
multiplexed stdout. A `notifications/message` the **gateway itself** emits
(§3) is deliverable on both transports, because the gateway knows whose
request it is inside.

### 3. The outbound emitter: who reads `log_level`, and where

Two producers feed the sink, and both write into the same task-local.

**Pass-through.** The transport is already the capture point. HTTP's
`send_request_with_headers` (`src/transport/http/mod.rs:1219`) stops discarding
`SseExchange.notifications` at `:1345` and instead pushes each captured
notification into the ambient sink before returning the response; the
`#[allow(dead_code)]` at `:297` is deleted, which is exactly what the ponytail
note at `:300-301` says the outbound consumer landing means. stdio's drain
(`take_captured_notifications`, `src/transport/stdio.rs:448`) does the same for
the registered token, and loses its `#[allow(dead_code)]` too. This carries the
backend's `notifications/progress` and, over HTTP, its
`notifications/message`.

**Gateway-generated.** `RequestFields::log_level` acquires its first production
reader here. The rule: **a `tracing` event the gateway raises while inside a
request's sink scope, at or above that request's declared level, is also
emitted as a `notifications/message` into the sink.** The verified anchor for
this is the refusal inside `invoke_tool_traced`
(`src/gateway/meta_mcp/invoke.rs:1074`) at `:1330` — `tracing::warn!(server =
%server, "refused: multi-user gateway would serve a gateway-held OAuth token
that is not isolated per user (ADR-008 INV-2)")`, immediately before the
`-32001` return. That is a message about *this* call, currently visible only in
the gateway's own log, which the caller has asked to see. Dual-emitting it is
the smallest change that gives `log_level` a reader and gives the acceptance
suite something observable to assert.

The second anchor is the ordinary one: `tracing::info!(agent_id, server, tool,
trace_id, "tool invoked")` at `src/gateway/meta_mcp/invoke.rs:1502`, in the
same function, on the success path. It fires on every `tools/call`, so a caller
that asked for `logLevel: "info"` sees a notification without having to provoke
a refusal. Two sites, both inside `invoke_tool_traced`, both pinned by the
acceptance rows.

Deliberately *not* a `tracing_subscriber::Layer`. A layer sees every event in
the process and would have to filter by task-local anyway, and this repo's
sizing note is explicit that this row is *"not a wiring job"*
(`docs/requirements/RELEASE-4.0.0-criteria-status.md:230`). Two explicit
dual-emit sites that the acceptance rows pin beat a global interceptor whose
blast radius is every log line the gateway writes.

### 4. Level filtering: the per-request value wins, and absence means silence

The precedence is already settled at source and only needs quoting.
`src/protocol/meta.rs:78-79` documents `log_level` as *"The minimum level to
emit `notifications/message` at for this request. `None` means emit none at
all."*

So:

1. `_meta` carries `logLevel` → that level governs this request's stream, and
   only this request's.
2. `_meta` carries no `logLevel` → this request's stream carries **no**
   `notifications/message` at all. It does **not** fall back to the session
   value.
3. The session-scoped `logging/setLevel` (`src/gateway/meta_mcp/mod.rs:266`,
   written at `src/gateway/meta_mcp/protocol.rs:295`) is untouched by this ADR.
   It governs the session-wide path and has a different lifetime; a request is
   not a session, and reading session state to decide a per-request stream is
   the conflation that ADR-008/INV-2 and `subscription_registry.rs`'s module
   doc both exist to prevent.

`notifications/progress` is not level-filtered. It has no level.

### 5. Lifetime, bounds, and the leak that is not built

The stated risk is precise: *an unbounded buffer keyed on request id is a
memory leak with a backend-controlled key*. This design has neither the map nor
the unbounded buffer.

- **No key, no map.** The sink is task-local. It is created when the request's
  task enters the scope and destroyed when that task's future is dropped. There
  is nothing to reap, nothing to key, and no entry that can outlive its request
  — the same property `subscription_registry.rs:16-19` relies on for listeners
  (*"a design needing reclamation is a design that leaks"*).
- **Bounded depth.** The channel is bounded. The producer is the transport and
  the consumer is a socket; a slow or vanished client must not let a chatty
  backend grow the gateway's heap. On overflow the notification is **dropped
  with a debug line, and the response is unaffected** — a lost log line is not
  a failed tool call. `SubscriptionRegistry` chose to disconnect a lagging
  reader instead (`CHANNEL_DEPTH = 256`, `src/gateway/subscription_registry.rs:41`);
  that is right for a subscription whose only purpose is the notifications, and
  wrong here, where the response is the purpose and the notifications are
  commentary.
- **The request never completes / the backend streams forever.** Nothing new is
  needed: the existing per-request deadline and the backend's own timeout still
  end the dispatch future, and the stream ends with it. This design adds no
  waiting of its own — it never blocks the dispatch on a send.
- **The client disconnects mid-stream.** axum drops the response body, which
  drops the receiver. Sends then fail and are dropped at debug. The dispatch
  future is dropped too, which is ordinary cancellation for this codebase, but
  see the ADR-012 note in Consequences.

**The no-spawn invariant.** Every claim above rests on one thing: nothing
between entering the sink scope and the transport read may move the work to a
different task. A `tokio::spawn` there silently empties the sink and no unit
test built on a hand-made channel would notice. Swept in this session:

- `src/backend/ops.rs:218` — `with_retry`'s closure returns an awaited async
  block, not a spawn. Safe.
- `src/gateway/router/handlers.rs:419` — spawns `multiplexer.auto_subscribe`
  for a GET SSE session stream, not on the POST dispatch path. Safe.
- `src/gateway/router/handlers.rs:1421` — **is** on the dispatch path, and is
  the exception. It spawns a task-mode `tools/call` so the handle can be
  answered immediately; the comment (`:1400-1403`) says *"The tool runs on a
  task of its own, so the handle can be answered now rather than after it
  finishes."* A task-mode call's response is the handle, not the tool result,
  so its request-scoped notifications belong to the task, not to that response.
  **Task-mode calls are out of scope for this criterion** and must not silently
  behave as though the sink were reachable.
- `src/transport/http/mod.rs:650` — an OAuth-flow spawn (comment at `:642`).
  Whether it can sit inside a `tools/call` dispatch was **not traced to a
  conclusion in this session: unverified.** Acceptance row 7 exists to catch it
  either way.

Because the invariant is what makes the design correct, the acceptance rows
must run through the real handler path. A test that constructs a channel by
hand asserts nothing about it.

### The response shape, and why the default does not change

A `tools/call` returns JSON today. It becomes an event-stream **only** when
both hold: the client's `Accept` includes `text/event-stream` (the header the
gateway already negotiates — it sets exactly this on its own outbound requests
at `src/transport/http/mod.rs:911,915`), **and** the request declared something
request-scoped in `_meta` (a `logLevel`, or a progress token). Otherwise the
response is byte-identical to today's and captured notifications are dropped
with a debug line. This is also the shape the test plan already states: row S-01 is *"POST
`tools/call` honours `Accept`: JSON when no stream offered, SSE when
offered"* (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:57`).
It matches the posture the repo already takes on optional
features — *"payloads stay byte-identical with the feature off"*
(`src/gateway/meta_mcp/invoke.rs:991-992`).

The stream itself is not a new mechanism: `subscription_stream`
(`src/gateway/streaming.rs:449`) already returns an
`axum::response::Response` carrying SSE events for a POST, with its
acknowledgement riding the stream as the first event. The response event
carrying the `JsonRpcResponse` is the last event on the stream, after any
notifications that preceded it.

## Explicitly out of scope

- **SUB.2a, the subscription stream.** `src/protocol/subscriptions.rs:12-16`
  and `src/gateway/subscription_registry.rs:50-59` exclude request-scoped
  notifications *by design*: *"They belong to the request that caused them and
  travel on that request's own response stream; putting them on the
  subscription stream would deliver them to a client that never made the
  request."* That exclusion is this criterion's premise, not an obstacle to it.
  Nothing in `subscription_registry.rs` or `protocol/subscriptions.rs` changes,
  and the test at `subscription_registry.rs:200` must stay green.
- **Idempotency / SUB.4.** ADR-012 owns it; a peer is implementing it now.
- **Websocket.** §2.
- **Task-mode `tools/call`** (`src/gateway/router/handlers.rs:1421`). §5.

## Consequences

**Merge constraint.** The inbound scaffold lands with the outbound leg or not
at all. The ledger row flips on the acceptance rows going green, not on the
inbound code existing — *"A parsed field with no reader is a placeholder, not a
half-implementation."*

**Cancellation touches ADR-012.** Dropping the SSE response body drops the
dispatch future mid-call, which is exactly the uncertain-outcome case ADR-012's
`Failed` terminal governs. That interaction is **out of scope here** and named
so it is not discovered later.

**Rejected: a session-wide notification channel.** It is the mechanism already
present (`NotificationMultiplexer`, keyed by session id) and it is the wrong
one for the same reason `subscription_registry.rs:9-13` refused it: *"a
session-free path bolted into a session-keyed table conflates two lifetimes"*.
A request is not a session, and a session-keyed channel cannot answer *which
request* without re-inventing the correlation key this design does not need.

**Rejected: a `DashMap<request_id, Vec<Notification>>` in the handler.** This
is the leak the criterion's sizing note warns about: an entry whose key comes
from the wire and whose removal depends on a path that may never run. The
task-local has no such failure mode because its destructor is the request's.

**Rejected: a `tracing_subscriber` layer.** §3.

## Acceptance

Numbered; each must fail against the current tree unless marked otherwise.

1. **Emitter exists.** A successful `tools/call` over HTTP with `Accept:
   text/event-stream` and `_meta` `logLevel: "info"` receives the `"tool
   invoked"` line (`invoke.rs:1502`) as a `notifications/message` event on its
   own response stream, before the response event. The refusal at
   `invoke.rs:1330` is the second site and needs the ADR-008 multi-user setup;
   the success path needs none. Fails today: `RequestFields::log_level` has no
   reader.
2. **Absence means silence.** The identical call with no `logLevel` in `_meta`
   receives zero `notifications/message`, even with the session's
   `logging/setLevel` set to `debug`. Fails today for the same reason, and
   pins the precedence in §4.
3. **Negative control — isolation.** Two `tools/call`s in flight on one
   connection, each with its own event-stream response. A notification caused
   by call A appears on A's stream and **never** on B's. This is test-plan row
   S-03 (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:59`).
4. **The criterion, in its own words.** A test named for it asserting that a
   request-scoped notification flows *on the response stream of its own
   request* — a `notifications/progress` raised by the backend during call A
   is read off A's response stream, and the same assertion is repeated over
   stdio and over HTTP (test-plan row S-02, `:58`).
5. **Backend pass-through, HTTP.** `SseExchange.notifications`
   (`src/transport/http/mod.rs:298`) reaches the caller instead of being
   discarded at `:1345`, and `#[allow(dead_code)]` at `:297` is gone. Fails
   today by construction.
6. **Token plumbing, stdio.** A client-supplied `_meta` progress token is
   parsed, forwarded on the outbound request, registered via
   `register_progress_token` (`src/transport/stdio.rs:441`), and the backend's
   matching `notifications/progress` reaches that call. Fails today: no code
   outside `src/transport` mentions a progress token at all.
7. **Negative control — no invented owner, through the real path.** A backend
   `notifications/progress` carrying a token no caller supplied reaches no
   caller's stream and fails no call. The unit-level form is already green
   (`src/transport/stdio.rs:1148`); this row runs it end to end through
   `meta_mcp_handler`, which also makes it the row that catches a
   `tokio::spawn` between scope entry and the transport read — including the
   unverified OAuth spawn at `src/transport/http/mod.rs:650`.
8. **The bound holds.** A backend emitting more notifications than the
   channel's depth during one call does not grow the buffer without limit; the
   excess is dropped and the response still arrives intact.
9. **SUB.2a stays excluded.** `a_request_scoped_notification_never_rides_this_stream`
   (`src/gateway/subscription_registry.rs:200`) still passes unchanged.
   *Regression guard: this row passes today and must keep passing; it is listed
   because the easiest way to make rows 1-8 green is to publish into the
   subscription registry, which this ADR forbids.*
10. **Negotiation prerequisite.** A POST `tools/call` returns JSON when no
    stream is offered and an event-stream when one is — test-plan row S-01
    (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:57`).
    This is the row that pins the default staying byte-identical.
11. **Late notification.** A notification arriving after the response has been
    written is dropped and counted, not delivered to whatever occupies the
    slot next — test-plan row S-04 (`:60`). This is the sink-lifetime row and
    the one that fails loudest if the sink is ever hoisted out of the task.
