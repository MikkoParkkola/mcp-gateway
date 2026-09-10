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
| stdio | a **gateway-minted** token, translated back to the caller's | One stdout is multiplexed across every in-flight call, so a key is the only attribution available (`src/transport/stdio.rs:104,467`) — and the caller's own token is not fit to be that key. See below. |
| websocket | **out of scope — unreachable in production** | `WebSocketTransport` has no production construction site: it is named only in `src/transport/websocket.rs` and `src/transport/websocket_tests.rs`, and `src/backend/lifecycle.rs:335` builds exactly three variants — `Stdio` (`:336`), `Http` (`:352`), `A2a` (`:384`). No configured backend can reach it. The test plan agrees, naming two transports and no more (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:58-59`). **Re-opens when** a production construction site appears or a websocket row lands in the test plan, whichever comes first. |

**Superseded: "the gateway never mints a token."** The rule written at
`src/transport/stdio.rs:431-435` (*"MIK-7272.SUB.2b, §II.6 option (i)"*) is to
register the caller's own token and pass a backend's token through only when it
matches. Read against the map it guards, that rule is unsound, for three reasons
all visible at source:

1. **The keyspace collapses types.** `capture_notification`
   (`src/transport/stdio.rs:469-471`) maps `Value::Number(n)` through
   `n.to_string()` into the same `String` key as `Value::String(s)`. Numeric
   token `7` and string token `"7"` are one entry.
2. **Registration overwrites a live owner.** `register_progress_token`
   (`src/transport/stdio.rs:441-443`) is a bare `insert`. Two calls in flight
   that supplied the same token — clients are free to; the token is theirs —
   leave one draining the other's notifications.
3. **A token outlives its request.** A caller may reuse a token on its next
   call, and a late notification from the finished call lands in the live one's
   buffer. Task-local sink isolation cannot prevent this: the mis-attribution
   happens in the transport's map, one layer below the sink.

**So the gateway mints, and translates back.** For each outbound backend request
that carries progress, the gateway mints a fresh token in a namespace of its own
— a non-numeric string, `gw-<uuid>` — registers **that**, and holds one entry
for the life of the call. **The entry is `minted → (the caller's token, the
request's bounded sender)`** — both halves are needed at capture, one to
translate the token back and one to deliver it; an entry holding only the token
would leave §3 with nothing to send on. On capture the
minted token is translated back before the notification reaches the caller, so
**the token the client sees is byte-identical to the one it sent**. That
identity is the property option (i) existed to protect, and it survives intact;
what changes is only the key the backend and the map see. This closes all three:

- A minted token is unique per request, so no two live registrations can alias,
  and a completed request's token is never live again — a late notification
  carries a retired key, matches nothing, and is dropped by the existing `None`
  arm (`src/transport/stdio.rs:474`).
- The map holds only gateway-minted keys, and a minted key is never numeric, so
  the `Number`/`String` collapse at `:469-471` cannot alias two registrations.
  Preserving the token's JSON type in the key would work too; the minted
  namespace is smaller and needs no new key type.
- **Registration is owned by the request.** A guard created beside the minted
  token removes exactly its own key on drop — completion, error, timeout,
  cancellation alike. Without it the registration outlives the sink: dropping
  the task-local drops the receiver, while the transport's map entry keeps
  accepting. Nothing reaps, so §5's *"a design needing reclamation is a design
  that leaks"* holds for the map as well as for the sink.

A caller that supplies **no** progress token gets no minted token and no
progress capture, exactly as today. Progress is correlated by a token the client
chose; with none there is nothing to translate back to, and handing the client a
token it never sent is the invented owner that `src/transport/stdio.rs:455-462`
guards against.

**The inbound half is still new work.** Nothing today parses a progress token
out of `_meta` (`src/protocol/meta.rs:43-51` declares five keys, none a token),
so the caller's token must be captured beside `log_level` in `RequestFields` as
part of this change. The comment at `src/transport/stdio.rs:431-435` is
superseded by this ADR and must be rewritten when the code lands.

`notifications/message` stays unattributable over stdio when it comes *from a
backend*: it carries no progress token, so no key exists for it, minted or
otherwise. A `notifications/message` the **gateway itself** emits (§3) is
deliverable on both transports, because the gateway knows whose request it is
inside.

### 3. The outbound emitter: who reads `log_level`, and where

Two producers feed the sink, and both write into the same task-local.

**Pass-through, and it must be live.** The transport is already the capture
point, but both capture paths today *accumulate a `Vec` and hand it over when
the call ends*. Forwarding that `Vec` into the sink at the end would deliver
every notification after the result — progress that arrives only once there is
nothing left to progress. **The sender goes to the capture site; the `Vec` goes
away.** Concretely:

- **HTTP.** `send_request_with_headers` (`src/transport/http/mod.rs:1219`)
  stops discarding `SseExchange.notifications` at `:1345`, and stops
  accumulating them: each notification is pushed into the ambient sink as the
  SSE body is parsed incrementally, so a notification reaches the client while
  the call is still running. The `#[allow(dead_code)]` at `:297` is deleted,
  which is what the note at `:300-301` says the outbound consumer landing
  means.
- **stdio.** The background reader owns the capture, and it is a **different
  task** from the request — which is exactly why the map in §2 exists, and why
  the sink alone cannot serve here. So the map entry holds the request's
  bounded `Sender`, not a `Vec`: `register_progress_token` takes the sender,
  `capture_notification` (`src/transport/stdio.rs:463`) translates the minted
  token back and sends, and `take_captured_notifications`
  (`src/transport/stdio.rs:448`) — the end-of-call drain — is deleted rather
  than given a caller. One bounded channel per request is then the only buffer
  on either transport, which is what makes §5's bound true at the capture site
  and not merely downstream of it.

This carries the backend's `notifications/progress` and, over HTTP, its
`notifications/message`.

**Gateway-generated.** `RequestFields::log_level` acquires its first production
reader here. The rule is a **per-site opt-in, not a blanket promise**:
**a named site, and only a named site, dual-emits its `tracing` event as a
`notifications/message` into the sink when the request's declared level admits
it. Adding a site requires an acceptance row.** A general "every qualifying
event is forwarded" rule would be unfalsifiable and would need the very
process-wide interceptor rejected below. The verified anchor for
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

One filter, both producers. A backend's `notifications/message` arriving by
pass-through (§3) is filtered by the same per-request level as a
gateway-generated one, at the sink. There is no second policy for relayed
messages: below the declared level they are dropped, and with no declared level
the request's stream carries none at all, whoever raised them.

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
- **Bounded depth, at a named constant.** The channel is bounded at
  `REQUEST_NOTIFICATION_DEPTH: usize = 64`. One buffer exists per in-flight
  request rather than one per session, so it is deliberately shallower than
  `SubscriptionRegistry`'s 256; 64 is the number acceptance row 8 is written
  against, and changing it changes that row. The producer is the transport and
  the consumer is a socket; a slow or vanished client must not let a chatty
  backend grow the gateway's heap. On overflow the notification is **dropped
  with a debug line and a counter increment, and the response is unaffected** —
  a lost log line is not a failed tool call. The counter is one monotonic
  per-drop metric, which is what makes the *"dropped and counted"* half of
  test-plan row S-04 assertable at all; without it row 11 is half an assertion.
  `SubscriptionRegistry` chose to disconnect a lagging
  reader instead (`CHANNEL_DEPTH = 256`, `src/gateway/subscription_registry.rs:41`);
  that is right for a subscription whose only purpose is the notifications, and
  wrong here, where the response is the purpose and the notifications are
  commentary.
- **The bound binds at capture, not downstream of it.** A bounded outbound
  channel does nothing if the transport has already accumulated an unbounded
  `Vec` upstream of it, which is what both capture paths do today
  (`SseExchange.notifications`, and the stdio map's `Vec<JsonRpcNotification>`
  at `src/transport/stdio.rs:104`). §3 removes both: the bounded sender reaches
  the capture site itself, so the channel is the only buffer. The same applies
  to the HTTP body — it must be parsed incrementally with bounded frame
  storage, not read whole and then split, or the bound is defeated by the read
  that precedes it.
- **The request never completes / the backend streams forever.** Nothing new is
  needed: the existing per-request deadline and the backend's own timeout still
  end the dispatch future, and the stream ends with it. This design adds no
  waiting of its own — it never blocks the dispatch on a send.
- **The client disconnects mid-stream.** axum drops the response body, which
  drops the receiver. Sends then fail and are dropped at debug. The dispatch
  future is dropped too, which is ordinary cancellation for this codebase, but
  see the ADR-012 note in Consequences.

**Two invariants, not one.**

*One task per in-flight request at the handler.* Concurrent requests must never
share a task, or they share a task-local and the sink stops being per-request.
This is a premise the whole design rests on and the spawn sweep does not check
— the sweep asks whether work *moves* tasks, not whether two requests *start*
on one. It is *believed* to hold because axum drives each connection's request future
independently, but **that mechanism was not traced to a conclusion in this
session: unverified.** It is listed so a future sweep knows both halves to
check, and so the premise is falsifiable rather than assumed.

*No spawn between the sink scope and the transport read.* A `tokio::spawn`
there silently empties the sink, and no unit test built on a hand-made channel
would notice. This binds the HTTP leg and the gateway-generated leg, which
capture on the request's own task. It does **not** bind stdio: stdio's reader is
a different task by construction, which is precisely why §2's map exists and why
stdio's correlation is the minted token rather than the task-local. Swept in
this session:

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
  conclusion in this session: unverified.** The rows that catch it are the
  **positive** ones — 1, 4 and 6 — which assert a notification *arrives*; a lost
  task-local makes them fail loudly. Row 7 cannot: a spawn drops every
  notification, which satisfies a negative assertion perfectly.

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
with a debug line. This **narrows** the test plan rather than restating it. Row S-01 says *"POST
`tools/call` honours `Accept`: JSON when no stream offered, SSE when
offered"* (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:57`)
— negotiation on `Accept` alone, with nothing said about `_meta`. The extra
condition is deliberate: an `Accept`-yes / `_meta`-nothing request would get a
stream that can never carry anything, so it keeps today's JSON body instead.
Anyone reading S-01 literally should read this paragraph as the amendment.
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

Thirteen rows. Ten must fail against the current tree; rows 2, 7 and 9 are
marked and pass today. The three that pass are controls, and each says so in
its own text: a row that asserts only an absence cannot distinguish a correct
implementation from an empty one, so it is labelled rather than counted.

1. **Emitter exists.** A successful `tools/call` over HTTP with `Accept:
   text/event-stream` and `_meta` `logLevel: "info"` receives the `"tool
   invoked"` line (`invoke.rs:1502`) as a `notifications/message` event on its
   own response stream, before the response event. The refusal at
   `invoke.rs:1330` is the second site and needs the ADR-008 multi-user setup;
   the success path needs none. Fails today: `RequestFields::log_level` has no
   reader.
2. **Absence means silence.** *Passes vacuously today — the gateway emits
   nothing at all — so it is a control on §4's precedence, meaningful only once
   row 1 is green, not a row that fails against the current tree.* The
   identical call with no `logLevel` in `_meta`
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
   stdio and over HTTP (test-plan row S-02, `:58`). **The fixture releases the
   result only after the client has read the notification**, which is what
   makes this a liveness assertion rather than an ordering one: a design that
   buffers and flushes at the end deadlocks here instead of passing.
5. **Backend pass-through, HTTP.** `SseExchange.notifications`
   (`src/transport/http/mod.rs:298`) reaches the caller instead of being
   discarded at `:1345`, and `#[allow(dead_code)]` at `:297` is gone. Fails
   today by construction. The accumulating `Vec` is gone with it: the assertion
   is that the notification arrives before the body has been read to its end.
6. **Mint, map, translate back — stdio.** A client-supplied `_meta` progress
   token is parsed; a *different*, gateway-minted token goes out on the backend
   request and is what `register_progress_token`
   (`src/transport/stdio.rs:441`) registers; the backend's matching
   `notifications/progress` reaches that call **carrying the client's original
   token, byte-identical**. Fails today twice over: no code outside
   `src/transport` mentions a progress token at all, and nothing mints.
7. **Negative control — no invented owner, through the real path.** *Passes
   today, like row 2, and for the same reason: it asserts an absence.* A backend
   `notifications/progress` carrying a token no caller supplied reaches no
   caller's stream and fails no call. The unit-level form is already green
   (`src/transport/stdio.rs:1148`); this row runs it end to end through
   `meta_mcp_handler`. *It is a pure control and detects nothing else* — an
   implementation that drops every notification passes it. Spawn detection
   belongs to rows 1, 4 and 6 (§5).
8. **The bound holds, at 64.** A backend emitting more than
   `REQUEST_NOTIFICATION_DEPTH` (64) notifications during one call, with the
   client not reading, does not grow gateway memory without limit; the excess is
   dropped, the drop counter advances, and the response still arrives intact.
   Asserted on both transports, because the buffer that could defeat it is a
   different one in each (`SseExchange.notifications` for HTTP, the map's `Vec`
   for stdio) and §3 removes both.
9. **SUB.2a stays excluded.** `a_request_scoped_notification_never_rides_this_stream`
   (`src/gateway/subscription_registry.rs:200`) still passes unchanged.
   *Regression guard: this row passes today and must keep passing; it is listed
   because the easiest way to make rows 1-8 green is to publish into the
   subscription registry, which this ADR forbids.*
10. **Negotiation prerequisite, as narrowed.** A POST `tools/call` returns JSON
    when no stream is offered, and an event-stream when one is offered **and
    the request declared something request-scoped in `_meta`** — test-plan row
    S-01 (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:57`)
    with the narrowing above. The third case is the one that matters here:
    `Accept` offers a stream, `_meta` declares nothing, and the body is still
    byte-identical JSON. This is the row that pins the default not changing.
11. **Late notification.** A notification arriving after the response has been
    written is dropped and **the drop counter advances by exactly one**, and it
    is not delivered to whatever occupies the slot next — test-plan row S-04
    (`:60`). This is the sink-lifetime row and the one that fails loudest if
    the sink is ever hoisted out of the task.
12. **A reused token does not cross requests.** Call A supplies token `t` and
    completes. Call B then supplies the same `t`. A's backend emits a late
    `notifications/progress` for A's *minted* token — it reaches no one, and in
    particular no part of B — **and B still receives its own
    `notifications/progress`, carrying `t`**. Both halves belong to one test:
    the positive half is what stops the row passing on a tree that delivers
    nothing to anyone, and the negative half is what a caller-keyed map fails.
13. **Registration dies with the request.** For a `tools/call` over stdio, the
    entry for its minted token is **present in `captured_notifications` while
    the call is in flight** and **absent once the call is cancelled**, and a
    backend notification arriving for that token afterwards is dropped rather
    than accumulated. The before-and-after pair is the row; an absence-only
    assertion passes on today's never-populated map. This is what fails if the
    cleanup guard in §2 is omitted and only the sink is dropped.

## Amendment 1 — the client-facing stdio sink, 2026-09-10

- **Status**: Proposed. Amends §2, §3 and the Acceptance list. The reviewed
  body above is not reopened; only what this section names changes.
- **Reviewed**: `gpt-review` and `kimi-review`, 2026-09-10, both
  SHIP-WITH-FIXES on the first draft. Every finding is answered in place; the
  one that changed the decision is answered in *"What S-03 can and cannot
  discriminate over stdio"*, below.

### The gap

§2's correlation table has a `stdio` row and §3 has a `stdio` bullet, but both
describe the **backend-facing** leg — the subprocess transport
(`src/transport/stdio.rs`), where a notification *arrives from* a backend. The
**client-facing** leg — how it then reaches an AI client that is itself
connected to the gateway over stdin/stdout — is named nowhere in this ADR.
Every delivery paragraph, *"The response shape, and why the default does not
change"* included, describes an SSE body over HTTP.

The two legs are independent, and this amendment governs only the second:

| Client ↔ gateway | Gateway ↔ backend | Governed by |
|---|---|---|
| HTTP | HTTP | ADR body, unchanged |
| HTTP | stdio subprocess | ADR body, unchanged — never enters `run_stdio` |
| **stdio** | HTTP | **this amendment** |
| **stdio** | stdio subprocess | **this amendment**, plus §2's minted token |

The client-facing leg is `Server::run_stdio` (`src/gateway/server/mod.rs`,
currently `:1566`). Verified by reading it: the loop reads one line
(`reader.next_line()`), dispatches it (`dispatch_single_with_sink`, or
`dispatch_batch_with_sink` for an array), and only then writes, through
`Self::write_response`, to a `tokio::io::Stdout` owned by the loop frame and
exclusively borrowed for the duration of each write.

### Two consequences, both fatal to the PR bar as the ADR stands

**(i) The sink has no writer, so Acceptance row 4 cannot pass over stdio.**
Row 4 requires the assertion *"repeated over stdio and over HTTP"*, with a
fixture that *"releases the result only after the client has read the
notification"*. `write_response` is reached only after dispatch has returned,
and nothing else can write to that stdout, because the loop holds it. A
notification raised during dispatch therefore cannot precede the response.
Row 4's own words for this shape are *"a design that buffers and flushes at
the end deadlocks here instead of passing"*, and that is the outcome.

**(ii) The loop is sequential, so no second call can be in flight.**
Test-plan row S-03 requires *"two concurrent calls on one connection, both
proven in flight … for both notification methods and both transports"*
(`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:59`).
The loop awaits each dispatch to completion before reading the next line.

Both are properties of the client-facing loop alone. Neither touches the
backend-facing discard sites the ADR body already names, and neither affects
an HTTP client calling a stdio backend.

### Decision

Both are fixed rather than recorded as limitations. A `MUST` with an honest
note explaining why it is unmet is still unmet.

**1. A bounded per-request channel, drained by a writer task.** The loop's
`tokio::io::Stdout` becomes an `Arc<tokio::sync::Mutex<Stdout>>` — the async
mutex specifically, because the guard is held across an `.await` inside a
spawned task. One clone stays with the loop; one reaches the §1 sink.

The sink does **not** write inline. Pushing a notification is a non-blocking
`try_send` into a channel of capacity `REQUEST_NOTIFICATION_DEPTH` (64); on a
full channel the notification is dropped and counted, which is §5's existing
overflow policy unchanged, and is why *"the bound of 64"* still means what
row 8 says it means. A per-request writer task drains that channel to the
shared stdout, one newline-delimited JSON-RPC notification object per line,
each written and flushed under a single lock acquisition so lines never
interleave byte-wise. No SSE and no envelope: over stdio a message is a line,
and lines are already the protocol.

Dispatch never awaits the client. When dispatch returns, the loop drops the
sender, awaits the writer task, then writes the response line under the same
mutex — so every notification the sink accepted is on the wire before the
result, and (i) is closed. A wedged client stalls only its own call's
response, which it was not reading anyway.

**2. Concurrent dispatch.** Each request is spawned onto a `JoinSet` instead of
being awaited inline, with completed tasks reaped by `join_next` on each pass
so finished work is not retained for the life of the session, and a cap on
concurrent in-flight requests so a client cannot spawn without bound. At EOF
the set is drained under `self.config.server.shutdown_timeout` — the same
bound the HTTP path already applies to its drain — and aborted if it expires,
so shutdown latency does not hinge on the slowest backend call. Entries inside
a **batch** line keep today's inline, ordered gathering: a batch is one line in
and one line out, and splitting it would change the batch response contract,
which this criterion does not ask for. This closes (ii).

### What S-03 can and cannot discriminate over stdio

Both reviewers found the first draft's *"this closes (ii)"* overclaimed, from
opposite directions, and they are right. Recorded plainly rather than fixed by
wording:

Over HTTP the response body **is** the per-request stream, so *"reaches the
provoking call's stream and no other"* is a real discriminator. Over
client-facing stdio there is one client and one stdout. There is no other
*caller* to leak to, so the leak S-03 names cannot occur; the failure that can
occur is **misattribution between two in-flight calls of the same client**.
Whether S-03 detects it depends on the notification method:

- **`notifications/progress` — discriminating.** It carries the client's own
  progress token back byte-identically (row 6). With A and B both in flight,
  A's token present and B's absent is a genuine failure detector, and a
  gateway that mixed the two fails it.
- **`notifications/message` — not discriminating, and cannot be made so here.**
  MCP defines no per-request relation on a logging notification, and this
  repository has none: verified this session, `rg -n` over `src/protocol/`
  returns no `relatedRequestId` and no `progressToken`. A bare
  `notifications/message` line on a shared stdout carries nothing a client
  could attribute to one of its two calls. Inventing a `_meta` key would be an
  unrequested protocol extension of exactly the kind this ADR already declines
  for gateway-originated progress.

**Therefore, stated as a limitation and not as a pass: the
`notifications/message` half of S-03 is UNMET over client-facing stdio.** The
mechanism is the absence of a linkage field in the protocol, not a gap in the
implementation. Over stdio that half asserts liveness and per-request level
filtering — real properties, and the ones §4 cares about — but not isolation.
The discriminating instance of S-03 for `notifications/message` is **HTTP
only**, and the test must be named and commented so that no later reader
mistakes the stdio instance for evidence of isolation. S-02 is unaffected: it
asserts arrival before the result, which is discriminating on both transports.

### Cost

The first draft claimed the change was *"confined to `run_stdio`,
`write_response`, and the sink's writer field"*. That was wrong, and both
reviewers caught it. Traced, the surface is:

- `dispatch_single_with_sink` takes `&Arc<MetaMcp>`, `&Arc<ToolPolicy>` and
  `&Arc<MtlsPolicy>` (`src/gateway/server/mod.rs:1832-1835`), so spawning
  costs three `Arc::clone`s and no ownership rework. That part held.
- `protocol_telemetry_sink` is threaded as `&mut` (`:1628`, `:1743`, `:2038`)
  and did not. Putting it behind a lock held across dispatch would re-serialise
  exactly what step 2 parallelises. It does not need to be: its only use inside
  dispatch is `record` plus `persist_global` at the **top** of the function
  (`:1863-1884`), before any tool execution. The observation is therefore
  hoisted into the loop and recorded before the spawn, and the spawned task
  never touches the sink. That removes the parameter from
  `dispatch_single_with_sink` and from `dispatch_batch_with_sink`'s forwarding
  at `:2038`, and touches the two in-file test call sites.

So: `run_stdio`, `write_response`, the two dispatch helpers' signatures, their
test call sites, and the sink's writer field. Larger than the first draft said,
still confined to one file plus §1's sink type.

### Correction to Acceptance row 1

Row 1 cites the `"tool invoked"` emission site as `invoke.rs:1502`. It is
**`src/gateway/meta_mcp/invoke.rs:1518`** as of this amendment, verified by
reading the file — the ADR's reference has drifted sixteen lines. The refusal
site at `invoke.rs:1330` and the sink scope at `invoke.rs:981`, inside
`invoke_tool` (`:972`), are correct as written. Line numbers throughout this
ADR are perishable in the same way; where this amendment cites one it names
the symbol beside it, and a reader should trust the symbol.

### What does not change

The HTTP leg in whole: negotiation on `Accept` plus `_meta`, the SSE response
shape, and the byte-identical default when neither is present. §2's websocket
exclusion. The out-of-scope list. §5's bound of 64 and its drop-and-count
overflow policy. Acceptance rows 2, 7 and 9 remain controls.

Rows 10-13 are **not** extended to the client-facing stdio leg by this
amendment. Row 13 in particular assumes a cancellation path, and the stdio
dispatcher has none — it does not act on `notifications/cancelled`. Building
one is a separate increment; claiming row 13 over stdio without it would be
the precise failure this amendment exists to avoid.
