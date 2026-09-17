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

   **Superseded 2026-09-11 — rows 5 and 6 both state a "fails today" that is no
   longer true, and each names a symbol the tree has moved past.** Read them as
   dated, not current. Row 6: the mint landed. `mint_progress_token`
   (`src/transport/notification_sink.rs:214`) issues a `gw-`-prefixed token, the
   backend funnel calls it at `src/backend/ops.rs:674` and translates back at
   `:761`, with `starts_with("gw-")` unit rows at `ops.rs:714` and
   `src/gateway/router/backend_handlers.rs:1426`. So "nothing mints" is false
   against the tree, and so is "no code outside `src/transport`". Row 5: the
   `SseExchange` type it names no longer exists at all -- `fbca1bc9` replaced it
   with incremental decoding in `src/transport/http/sse_decoder.rs`, so the
   `:298`/`:1345`/`:297` citations resolve to nothing.

   The cost of leaving these uncorrected was paid once already. Row 6's
   acceptance assertion, `assert_ne!` on the minted token at
   `tests/mik_7272_sub2b_acs.rs:539`, sat behind a release assertion that could
   never pass on stdio, so the ledger carried the criterion red from `6fc9471b`
   onward without the mint ever being the reason. When the fixture gained an
   out-of-band release (`364f4373`), the row reached the assertion for the first
   time and passed. A criterion can be recorded red for months by an assertion
   that never runs; a "fails today" line in a decision record is evidence about
   the day it was written and nothing else.
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
currently `:1614`). Verified by reading it: the loop reads one line
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
  (`:1877-1884`), before any tool execution. The observation is therefore
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

## Amendment 2 — the SSE read on both legs, 2026-09-11

- **Status**: amends Amendment 1's Cost and §1's implementation status. Reviewed
  three times by two external reviewers (SHIP-WITH-FIXES each round); revised
  2026-09-11 to carry their fixes and to re-verify every line cite against this
  tree — (a) is restated as landed, (d)'s rationale is corrected from loss to
  liveness and its read specified at byte level, the shared layer is narrowed to
  framing with JSON-RPC classification kept above it, the byte bound is moved
  from the incomplete tail to the whole pending event, (e) is widened to the four
  rows its own test file scopes, **(f) is added** because two of those rows
  cannot pass while the client-facing leg stays batched — row 4's "over HTTP"
  being the client leg is established from the test plan and from the Acceptance
  section's own row split, and (f) is specified down to the status-before-stream
  cut it has to make — and Acceptance row 5 is
  resolved rather than held both ways.

### The gap Amendment 1's Cost leaves

Amendment 1's Cost ends "and the sink's writer field", presuming §1's sink
exists in `src/`. SUB.2b is **six** pieces, not two.

**(a) The sink — landed, and in the shape §1 asks for.** An earlier draft of
this amendment claimed `rg 'notification_sink|task_local!' src/` finds only
`src/gateway/trace.rs`. That is false against this tree and is corrected here.
`src/transport/notification_sink.rs` exists — 182 lines, untracked, not in
`HEAD` — and it is wired, not greenfield: exported at `src/transport/mod.rs:6`,
scoped in production by `meta_mcp_handler` (`src/gateway/router/handlers.rs:599`),
feeding `request_scoped_event_stream` (`src/gateway/streaming.rs:604`), and
published to from `forward_sse_exchange` (`src/transport/http/mod.rs:368`) and
`StdioTransport` (`src/transport/stdio.rs:621`). The re-shape this amendment
first prescribed has already happened: the payload is `tokio::task_local!` over
`mpsc::Sender<JsonRpcNotification>` (`:34-35`) at `REQUEST_NOTIFICATION_DEPTH`
= 64 (`:32`), `scope` hands back the receiver so a caller can drain while the
future still runs (`:48`), and `publish` does per-notification `try_send` with
a dropped-counter and a warn (`:87`) — §5's drop-and-count, not the salvaged
`Arc<Mutex<Vec<_>>>` collected after completion. Four tests, not the salvaged
two: `publish_outside_a_scope_is_dropped_not_panicked`,
`concurrent_scopes_do_not_cross`,
`a_notification_is_readable_before_its_request_finishes` (`:146`) and
`an_overfull_sink_drops_and_counts_instead_of_blocking` (`:168`) — §1 and §5
respectively.

**The sink being the right shape is not the whole path being the right shape.**
`collect` survives (`:64`) as a compatibility drain over the receiver — "not a
return to collect-then-emit" in its own doc — and `handlers.rs:599` is a
`collect`, handing `request_scoped_event_stream` a completed
`Vec<JsonRpcNotification>` (`streaming.rs:604-607`). That leg therefore still
delivers after the future finishes. **Decision:** (d) changes the
backend-facing producer only; the client-facing leg is component **(f)**
below. `collect`, the `handlers.rs:599` scope and `request_scoped_event_stream`
stand unchanged *under (d)* — but not across the amendment, because two of
(e)'s four rows cannot pass while that leg stays batched. (f) is therefore a
prerequisite of (e), not a later increment.

**(b)** Amendment 1 step 1, reviewed, unchanged. **(c)** Amendment 1 step 2,
reviewed, unchanged; `JoinSet` confirmed absent from `src/gateway/server/mod.rs`.
Neither is optional for any existing row: all four acceptance tests in
`tests/mik_7272_sub2b_acs.rs` spawn the shipped binary with `--stdio`
(`StdioSession::spawn`, `:240`) against an SSE fixture backend (`slow_stream`,
`:161`), and none is `#[ignore]`d — so (b), (c) and (d) all sit on the critical
path of `s02_stdio_progress_reaches_its_own_call_before_the_result` (`:405`),
`s02_stdio_message_reaches_its_own_call_before_the_result` (`:478`),
`stdio_without_request_scoped_meta_delivers_no_notification` (`:534`) and
`s03_progress_stdio_each_call_sees_only_its_own_token` (`:569`).

### (d) The backend-facing SSE read

**The defect is liveness, not loss.** An earlier draft of this section said the
backend-facing read discards the notifications. It does not.
`send_request_with_headers` calls `forward_sse_exchange(&text)`
(`src/transport/http/mod.rs:1392`), and `forward_sse_exchange` (`:366-371`)
publishes them to the ambient sink before handing back the response. Nothing is
thrown away. What is wrong is *when*: on the SSE branch
(`content_type.contains("text/event-stream")`, `:1385`) the whole body is read
to its end by `response.text().await` (`:1386-1388`) before `parse_sse_response`
(`:329`) sees a byte of it, so every notification is published after the result
it is required to precede. Amendment 1's "the HTTP leg in whole" covers the
*client*-facing leg; this is a fourth surface it does not reach.

That is Acceptance row 5's property in row 5's own words — "the assertion is
that the notification arrives before the body has been read to its end"
(`:458-462`) — which makes row 5, in substance, the acceptance row for (d). The
claim is not academic: `tests/mik_7272_sub2b_acs.rs` gates
`slow_notifier`'s result on `Semaphore::new(0)`, released only by a second call
the client makes after reading the notification. Under `text()` the
notification surfaces after the body ends, so nothing releases the gate and the
row dies at `READ_TIMEOUT` (15s) instead of asserting — row 4's "deadlocks here
instead of passing", reached by the transport rather than by the design.

Replace the `text()` branch (`:1385-1392`) with an incremental scan of
`response.bytes_stream()`. The handshake scan in `establish_sse_connection`
(`:1089`; scan body `:1111-1176`) is the shape to follow, **not** the code to
copy: four of its choices are harmless for an ASCII endpoint URL and wrong for
arbitrary `data:` payloads.

**Bytes, not lossy strings.** `buffer.push_str(&String::from_utf8_lossy(&chunk))`
(`:1126`) decodes each *raw chunk*, so a multi-byte codepoint straddling a chunk
boundary becomes U+FFFD. The handshake carries an ASCII URL and never sees it;
tool results carry arbitrary Unicode. Accumulate raw `Bytes` in a `Vec<u8>`,
split on `b'\n'`, and decode each **complete line** with `String::from_utf8` — a
split codepoint then always lands intact inside one line. Required test: a
fixture containing non-ASCII (e.g. `é`) fed in fragments split at *every* byte
boundary, asserting results byte-identical to the whole-body feed.

**Bound the whole pending event, after the drain — not the accumulated buffer
before it, and not the partial line alone.** The 64 KiB cap (`:1128`) is
checked *before* the complete-line loop (`:1135`), so one chunk coalescing many
small complete events trips it although nothing retained is large; its own
comment sizes it for "a single short SSE line", i.e. the handshake's endpoint
event. But moving the check after the drain and applying it to the leftover
bytes is **not sufficient**, and this is the subtler half: every completed
`data:` line *leaves* the byte buffer and joins the pending event's
accumulating string, so a backend sending a million short `data:` lines and
never a blank line stays under a leftover-bytes bound forever while the pending
event grows without limit. The quantity to bound is the **whole retained
pending event — joined data lines plus the partial line — enforced before the
join allocates, and reset when an event dispatches.** Nothing in the tree
protects this today: `a_long_stream_of_small_events_never_exceeds_the_pending_bound`
(`src/transport/http/sse_decoder_tests.rs:53`) measures *completed* events and
cannot see it, so the fixture that proves it is a stream of `data:` lines with
no blank line at all.

No max-message or max-frame constant exists in `src/` to inherit — there is
none to name. **The constant is `MAX_PENDING_SSE_BYTES`** (`sse_decoder.rs:33`,
10 MiB), whose name is the right one now that the quantity is the pending event
rather than a frame. Its rationale, however, is settled here against its own
doc comment: it does **not** mirror `ServerConfig::max_body_size`
(`src/config/mod.rs:1267`, default 10 MiB `:1304`). That value is an
operator-tunable limit on the gateway's own inbound listener, so a backend's
response frame bound to it breaks the moment an operator lowers it — the
scaffold's comment already half-concedes this by calling it "an analogue rather
than the same budget". The ADR's rationale is simpler and does not decay: a
fixed bound, chosen at the same order of magnitude so no legitimate payload is
newly refused, independent of configuration. It is generous on purpose — a
legitimate JSON-RPC response frame is **one long line**, so while it arrives it
*is* the pending event, and a bound tightened toward "a pending event should be
small" reintroduces the bug this finding names.

**Framing: take the decoder.** The handshake scan splits only on `'\n'` and
classifies each `data:` line on its own, so bare-CR streams never dispatch and
SSE-legal multi-line `data:` frames fail as a JSON parse error. A third count
is easier to miss and (d) would inherit it unaddressed: `parse_sse_response`
hands *every* `data:` payload to `serde_json::from_str` and converts any
failure into a hard transport error (`:335-336`), so an empty `data:` line or a
keep-alive — both SSE-legal, both ordinary on a stream held open — kills the
call. The decoder must therefore skip what carries no message before it parses:
comment lines (`:`-prefixed) and frames whose joined data is empty. A
*non-empty* payload that will not parse stays an error; silence there would
hide real corruption, which is the defect above in the other direction.

The cost is one helper, so specify a stateful event decoder handling LF, CRLF
and CR, joining a frame's `data:` fields with `\n` and classifying only at the
terminating blank line — **and at EOF, which terminates a pending event exactly
as a blank line does**. That clause is load-bearing: both parsers classify
immediately today (`parse_sse_response` iterates `text.lines()` with no
blank-line dependency, `:329`), so a blank-line-only decoder would silently
drop the final frame of any body ending `data: {...}\n` — the handshake
included. Fixtures: fragmented across chunk boundaries, multi-line `data:`,
CRLF and CR framing, and a keep-alive comment plus an empty `data:` line
interleaved with real frames.

**A cursor, not a reallocation per line.**
`buffer = buffer[newline_pos + 1..].to_string()` (`:1137`) rebuilds the whole
remaining buffer once per line, which is quadratic in the number of lines a
chunk carries. A handshake that ends on its first event never pays it; a
response stream carrying many short events does. Advance a cursor index and
compact the buffer occasionally instead.

**One framer, three consumers — and the framer does not know what JSON-RPC
is.** Line splitting, chunk-boundary handling and event assembly are factored
into a single helper serving the handshake scan, the new request scan, and the
ported unit tests, so those semantics are fixed in exactly one place and two SSE
readers cannot drift apart again. **The shared layer stops at framing.** What it
yields is an event — an optional `event` name plus the joined `data` lines
(`SseEvent`, `src/transport/http/sse_decoder.rs:37`) — and nothing more. It must
not attempt JSON-RPC classification, because its two callers do not agree that
an event carries JSON-RPC at all: the handshake's `endpoint` event carries a
**bare URL**, not a JSON document, and a framer that parses every event as
JSON-RPC turns the handshake's normal case into a parse error. The handshake
consumes the endpoint URL on its own terms; JSON-RPC classification belongs to
the request reader alone (`decode_sse_exchange`, `:81`). The scaffold is already
built this way — sans-io framing below, classification above — and this
paragraph is the specification it already satisfies, not a change to it.

Classification, in the request reader only, dispatches as follows — Response:
return it, dropping the rest of the stream; Notification: `publish` to the
ambient sink and `debug!(method = %notification.method, "Notification on
response stream")`; Request: `Err(Error::Transport(format!("Peer sent request
'{}' on the response stream", request.method)))`. EOF with no response frame is
`Error::Transport("No data in SSE response")`.

**Resolution of Acceptance row 5.** This amendment first held two incompatible
positions: its limitation 1 kept both `#[allow(dead_code)]` and the
accumulating `Vec` while calling row 5 satisfied "by removal from the live
path", and "What does not change" asserted that every Acceptance row's text
stands. Row 5 (`:458-462`) and §1 (`:196-198`) each say the attribute is
*deleted* and that the accumulating `Vec` goes with it. Both positions cannot
be true. The resolution is **deletion, not reinterpretation** — amending a
reviewed acceptance row is a design change and would have to be written as one.

"Removal from the live path" is in any case no longer available as a reading:
the live path *reads* that field now (`forward_sse_exchange`, `:366-371`), so
removing it from there would re-orphan a field currently consumed — a
regression wearing the word cleanup. (d) instead deletes `SseExchange`, its
`#[allow(dead_code)]` (`:314`), `parse_sse_response` (`:329`) and the
`forward_sse_exchange` shim that wraps it (`:366-371`) outright — the streaming
decoder publishes as it classifies, so the shim has nothing left to do — and
ports their five unit tests (`src/transport/http/tests.rs:1642, 1658, 1828,
1864, 1894`), plus the three `forward_sse_exchange` tests, onto the production
decoder. Two whole-text SSE parsers in one crate is the divergence this
amendment exists to prevent. Until that port lands row 5 is **not met**, and
nothing may report it as met.

**Row 5's own citations have drifted**, and a reader will take them literally.
It cites `SseExchange` at `:298` (now `:300`), the attribute at `:297` (now
`:314`), and a discard "at `:1345`" — nothing is discarded anywhere any more.
(`forward_sse_response` no longer exists in `src/` either.) The symbols are the
durable part; the numbers are this tree's.

**The doc comment above the attribute is stale, and stale is worse than
absent.** `SseExchange.notifications` still reads "SCAFFOLD, and labelled one:
no production path reads this yet. The only caller of `parse_sse_response` —
`send_request_with_headers` — maps it away" (`:303-313`), with a trailing note
offering the attribute as "evidence that SUB.2b is still half-built". The
consumer has landed. A reader who trusts that comment concludes the opposite of
the truth, so it is not merely obsolete prose but a false input to the next
reader. It goes with the struct under (d); until then it describes a tree that
no longer exists.

**Posture, not a priced regression — connection reuse.** Returning on the first
response frame abandons the remainder of the body where today's `text()` reads
to its end. **Decision: close the connection; reuse is not guaranteed.** The
response frame is protocol-terminal, and a bounded drain after it reintroduces
the very wait row 4 exists to detect. Against the case that motivates the worry
the early return is the *repair*, not the cost: a backend that holds its stream
open past the terminal frame hangs `text()` until the peer closes, while the
early return answers at once. What it costs is a connection that a
promptly-closing backend might have let us reuse — and the asymmetry is
protocol-dependent, since an abandoned body forecloses reuse on HTTP/1.1 but is
only a stream reset on HTTP/2. Unmeasured either way: no magnitude is claimed
here and none should be read in.

### (e) The HTTP instance of S-03, message half, does not exist — nor do the other three HTTP rows

Amendment 1 records the `notifications/message` half of S-03 as unmet over
client-facing stdio on the correct ground that MCP defines no per-request
linking field for it, and discharges that by asserting the discriminating
instance is HTTP-only. The HTTP instance was never written.
`rg 's03_message_http_isolates_by_stream' tests/ src/` returns exactly two
hits, both doc comments inside `tests/mik_7272_sub2b_acs.rs` itself — the
module doc (`:11`) and the note above `message_frame` (`:97`), which says in
so many words that the stdio row "does not exist" and forwards to the HTTP one.
Both are intra-doc links to an item that is not defined anywhere, so the
forward reference resolves to nothing and must resolve once (e) lands.

With no instance on either transport, that half of S-03 has no discriminating
test at all: a stated limit against a MUST is an unmet requirement, not a
priced one. (e) is the row itself — two concurrent `tools/call` POSTs on the
client-facing HTTP leg, each with its own `text/event-stream` response, a
`notifications/message` raised by the backend during call A read off A's
stream and **never** off B's. It is the only row in the file that would
exercise the client-facing HTTP leg; today no row does, which is the same hole
as the backend-facing one (d) closes.

**(e) is four rows, not one.** S-03 has four method×transport cells:
progress×stdio exists
(`s03_progress_stdio_each_call_sees_only_its_own_token`, `:569`),
message×stdio is protocol-impossible for Amendment 1's reason, message×HTTP is
the row above — and **progress×HTTP belonged to nobody**. Nor is S-03 the whole
gap: Acceptance row 4 requires S-02 repeated over stdio *and* over HTTP, and
only the stdio half has tests. `tests/mik_7272_sub2b_acs.rs` states the scope
in its own words at `:666-670` — "Four rows belong here: the progress and
message halves of `S-02`, and both halves of `S-03`" — and both S-03 halves
have since been written there against the harness that follows it. (e) is
those four rows and the harness they share, not the single message×HTTP row it
first named.

**Residual, inherited rather than introduced.** S-03's wording demands
isolation for both notification methods and both transports. (e) discharges the
HTTP instance only: the client-facing stdio instance of the message half is
protocol-impossible for the reason Amendment 1 gives, so even with (e) green
S-03 as written stays unsatisfied for that half. The residual comes from
Amendment 1, not from this amendment — but it has gone unstated, and an
unstated residual is how a row goes green over an open gap. The stake is
concrete, and the ledger row makes it worse by stating its own flip condition
twice in two different widths: `docs/requirements/RELEASE-4.0.0-criteria-status.md:230`
says both that SUB.2b "flips on S-02/S-03 going green" and, narrowed later in
the same row, that it flips on "S-02 plus the `notifications/progress` half of
S-03". The second excludes `notifications/message` isolation on every
transport. A later reader will use whichever half they reach first, and under
the narrow one SUB.2b flips to MET while the gap it names stays open. That
contradiction is the ledger's to fix, not this ADR's, but (e) is what makes the
wide reading achievable.

**Two of the four rows are blocked on (f), not merely unwritten.** The two
S-03×HTTP isolation rows are observable in a fully buffered body: the assertion
is *which* stream a notification landed on, and that reads the same whether the
bytes arrive early or all at once at the end — which is why the two landed
rows (`s03_message_http_isolates_by_stream`,
`tests/mik_7272_sub2b_acs.rs:1011`, and
`s03_progress_http_isolates_by_stream`, `:1065`)
pass against today's batched consumer. The two S-02×HTTP rows are not. The test
file draws the same conclusion independently at `:672-686`, citing
`handlers.rs:599` and `streaming.rs:604` and naming the same four-step
deadlock.
Acceptance row 4's fixture releases the result only after the client has read
the notification, and on HTTP that is a deadlock with the current shape: the
client waits for a notification, the gateway waits for the dispatch future to
finish before emitting a byte, the dispatch waits for the backend, and the
backend waits for the client. No test authored under (e) can break that cycle;
only (f) can.

**Row 4's "over HTTP" is the client leg, and the Acceptance section settles it
by construction.** The deadlock above depends on that reading, so it is cited
rather than assumed. Test-plan row S-02
(`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:58`)
requires that the backend's notification "reaches that call's response stream,
before the result, over **stdio** and over **HTTP**" — the call is the client's
`tools/call` and its response stream is the client leg. The section's own
vocabulary agrees: row 1 says "its own response stream" under `Accept:
text/event-stream` and row 3 says "each with its own event-stream response",
both unambiguously client-facing, and a row cannot switch senses mid-section.
And the two legs are split **by row**: row 5 is separately titled "Backend
pass-through, HTTP" and is the backend half, which leaves row 4 as the client
half. So `handlers.rs:599` collecting the whole dispatch before
`streaming.rs:604` sees a finished `Vec` does block row 4 over HTTP. (f) is in
scope.

**The S-02×HTTP rows must gate the result on the assertion, or they do not
discriminate.** A row that requires only an incremental read passes against a
gateway that buffers the entire backend response, provided the backend closes
having sent notification-then-result in client-facing order — which is to say
it passes without (d) and without (f), and is therefore evidence for neither.
The acceptance text for both S-02×HTTP rows carries the gate explicitly: **the
backend fixture withholds the result until the assertion on the notification
has run**. Row 4 already says exactly this (`:454-457`) — "the fixture releases
the result only after the client has read the notification… a design that
buffers and flushes at the end deadlocks here instead of passing" — but says it
once, in a row whose stdio instance is the one that exists. The HTTP instances
inherit the gate rather than settling for an incremental read. Under it a
batching implementation deadlocks instead of passing, which is the row's
purpose.

### (f) The client-facing HTTP consumer streams

**The defect is the same one as (d)'s, on the other leg.** `handlers.rs:599`
wraps the *entire* dispatch in `notification_sink::collect(...)`, so the
`Vec<JsonRpcNotification>` that reaches `request_scoped_event_stream`
(`streaming.rs:604-607`) is complete before the response body begins. Every
notification a backend raised during the call is therefore delivered after the
call it belongs to has already produced its result. For the progress
notifications S-02 exists to cover, a progress report that arrives only once
the work is done is not a progress report.

**Shape.** Replace collect-then-frame with a body that emits each notification
as it is published while the dispatch is still in flight: keep the
`task_local!` sink scope around the dispatch future, but hold the *receiver*
outside it and drive dispatch and body together. **The dispatch future is
polled by the body, not spawned.** The distinction is load-bearing rather than
stylistic: a spawned dispatch outlives the client that asked for it, so a
client disconnect leaves the backend call running against a receiver nobody
reads, and §5's deadline stops governing the work it was written to govern.
Polled from inside the stream, the dispatch is dropped when the body is
dropped, client disconnect cancels the call, and socket backpressure propagates
into the dispatch rather than accumulating behind it. The SSE body therefore
yields each `JsonRpcNotification` off the receiver as it arrives and the
response frame when the polled dispatch resolves.
`REQUEST_NOTIFICATION_DEPTH = 64`
(`src/transport/notification_sink.rs:32`) already gives the channel its bound,
and `publish` (`:87`) already does the per-request routing; what changes is
only who reads the receiver and when. `collect` (`:64`) stays for callers that
genuinely want a finished `Vec` — the stdio path and the existing tests — so
this is an added consumer of the same sink, not a rewrite of it.

**The status is computed from the finished response, so streaming must not
begin before the refusals have run.** This is the component's central problem,
not a detail of it. `refusal_status(&response).unwrap_or(StatusCode::OK)`
(`src/gateway/router/handlers.rs:1883`) derives the HTTP status *from the
completed dispatch response*, and `:1890` refines it again — 404 rather than
200-with-error for an unimplemented method on the modern era. `handlers.rs:599`
computes `offers_event_stream` from `Accept` up front but branches on it only
after `collect(...)` resolves (`:605-611`), precisely because a request that
offers `text/event-stream` may still resolve to a refusal, a 404, or a non-JSON
response. The comment at `:1878-1882` names the stake: a refusal only the
dispatch chokepoint can see "arrives here as a JSON-RPC error, and answering it
200 tells every caller and intermediary the call succeeded". Committing a
status line before that code has run would surrender it.

**Resolution: split preparation from execution — and the cut exists.** Every
phase that can refuse runs to completion and yields the status; only then are
headers committed and the stream started, with the backend call — the sole
phase that emits notifications — running inside the body. `meta_mcp_dispatch`
admits this cut, verified at source rather than assumed:

- All pre-method refusals precede the method dispatch. `let response = match
  method.as_str()` is `handlers.rs:1095`; auth, body limit, in-flight permit,
  session, era and task-extension checks all early-return above it.
- Within the `tools/call` arm (`:1212`), every refusal precedes the only
  notification-emitting call. `handle_tools_call` is invoked at `:1610` on the
  direct path and `:1478` on the task path; the authorization chokepoint and
  its audit sit above both.
- The refusals that carry a status carry it structurally, not positionally:
  `refusal_status` (`:2003`) reads `authz::HTTP_STATUS_DATA_KEY` out of the
  error's `data`, and that key is set by the authorization layer, which runs
  pre-invocation. The `-32601` 404 is likewise decided by the method match, not
  by the backend.
- The pattern already exists in this function. `subscriptions/listen`
  (`:1096`) returns **early with an SSE body** instead of falling through to
  the ordinary response builder, for the same reason (f) needs to.

So (f) does not require carving a preparation phase out of the whole
lint-exempt function (`#[allow(clippy::too_many_lines)]`, `:613`). It requires
the `tools/call` arm to commit its own stream and return early, as
`subscriptions/listen` does, leaving every other arm's status path untouched.
**The cost this does carry** is the tail an early return skips: `:1868-1876`
records client success/failure against the breaker and the response tail counts
every JSON-RPC answer, and the function already documents that hazard in its
own words at `:1059-1064` — "the early return skips the tail that counts every
other JSON-RPC answer, so the refusal is counted here or it is invisible". A
streaming arm must replicate that bookkeeping or it silently stops counting
`tools/call`.

**Rejected: commit 200 on any streaming request and carry late refusals
in-band.** The smaller shape — since `offers_event_stream` is known before
dispatch, answer 200 immediately and deliver any refusal as a JSON-RPC error
frame on the stream — is rejected. It surrenders exactly the property
`:1878-1882` was written to protect: a chokepoint refusal would reach every
caller and every intermediary as a successful call, and the `-32601` 404 that
distinguishes "this server lacks that method" from "this is not a modern
endpoint" would collapse to 200 for streaming callers only, making the status a
function of the `Accept` header. It would save perhaps 40 lines. It is not
available at that price, and it is named here so it is not re-proposed as an
optimisation.

**Ordering guarantee to pin.** A notification published before the response
must be framed before the response frame, and no notification published after
the response resolves may be framed at all; the response frame ends the body.
Two fixtures state it: one backend that publishes, then answers — the client
must see the notification frame before the response frame — and one that
answers, then publishes, where the late notification is dropped rather than
appended after the terminal frame. A third fixture pins the race the first two
leave open: a queued notification and the dispatch's completion become ready in
the **same poll**, and the notification must still be framed first. Without it
a body that checks the dispatch before draining the receiver passes both
ordering fixtures and truncates under load. The fixture asserts on a
notification that was accepted by the channel, so it does not conflict with
§5's deliberate drops — an overflow past `REQUEST_NOTIFICATION_DEPTH` stays a
legal drop-and-count; a notification the channel accepted and the body then
raced past does not.

**Size, re-derived.** The earlier ~80–120 line figure is withdrawn: it was
computed before the status problem above was on the table. The work is the
handler seam (`handlers.rs:599-611`), an early-returning streaming branch in
the `tools/call` arm modelled on `subscriptions/listen` (`:1096`), the
bookkeeping that branch must replicate from the skipped tail (`:1868-1876` and
the answer counter), the body constructor replacing
`request_scoped_event_stream` (`streaming.rs:604-607`), and three fixtures.
Call it **~180–230 lines** of source and test.

That is the same order as (d)'s ~200, not materially above it, so (f) stays
priced inside this amendment and sequenced before (e)'s two S-02×HTTP rows. The
figure assumes the cut point holds as verified — refusals above
`handle_tools_call` (`:1478`, `:1610`), status carried structurally by
`refusal_status` (`:2003`). If an implementer finds a refusal that only the
backend call can raise *and* that must set a non-200 status, the cut moves and
the number moves with it.

### Cost

(a) is **spent, not pending**: `src/transport/notification_sink.rs` is in-tree
with four tests (`publish_outside_a_scope_is_dropped_not_panicked`,
`concurrent_scopes_do_not_cross`,
`a_notification_is_readable_before_its_request_finishes`,
`an_overfull_sink_drops_and_counts_instead_of_blocking`), and three
`forward_sse_exchange` tests sit in `src/transport/http/tests.rs`
(`http_forwards_both_notification_methods_to_the_callers_sink`,
`http_never_crosses_a_notification_between_two_calls_in_flight`,
`http_leaves_the_sink_empty_when_the_backend_raises_nothing`). Nothing remains
to price on the sink itself. What is **not** spent is the client-facing
consumer: `handlers.rs:599` still `collect`s. That re-shape is component (f),
priced below rather than left unpriced. (b) and (c)
are as Amendment 1 priced them.

(d) grew past its first estimate. Roughly 80 lines of streaming read in
`src/transport/http/mod.rs`, plus the single shared helper — line splitting,
LF/CRLF/CR framing and per-frame classification — plus reworking
`establish_sse_connection`'s scan (`:1111-1176`) onto that helper, cursor and
compaction replacing the per-line reallocation at `:1137`, plus deleting
`SseExchange`, `parse_sse_response` and the `forward_sse_exchange` shim and
porting their eight unit tests — the five whole-text ones plus the three sink
ones — onto the decoder, plus the new fixtures: non-ASCII split at every byte
boundary, multi-line `data:`, CR and CRLF framing, a keep-alive comment and an
empty `data:` line, a retained pending event bounded after the drain, a stream
of `data:` lines with no blank line at all (which a completed-event bound
cannot see), EOF dispatching a pending event that never got its blank line, and
a terminal response frame followed by a stream that stays open indefinitely —
the read must return on the response, not on the close. Call it ~200
lines of source and test, not 80. The shared helper and the port are the
growth, and they are what keeps a second SSE parser from surviving to diverge.

(e) is **four** acceptance rows, not one — the progress and message halves of
S-02 and both halves of S-03. Two of the four have since landed, so what (e)
owes has shrunk and the inventory is restated against the current file
(1098 lines): `s03_message_http_isolates_by_stream` (`:1011`) and
`s03_progress_http_isolates_by_stream` (`:1065`) both exist and pass. The cost
estimate that called the client-facing HTTP harness
"new work, not a variant of the existing one" and "the larger half of (e)'s
cost" **no longer holds: that harness is in the tree.** `write_http_config`
(`:690`) starts the child in HTTP mode, `post_sse` (`:811`) issues the POST
carrying `Accept: text/event-stream`, `sse_frames` (`:837`) reads the body into
frames and `parked_slow_calls` (`:848`) holds calls open.

**What (e) still owes is the two S-02×HTTP rows and two harness capabilities**,
and the test file has already reached the same conclusion in its own words
(`:678-686`): "the two `S-02` × HTTP rows land when the consumer streams…
`post_sse` below reads the body to its end. When the two `S-02` rows land they
will need an incremental-read variant of it, which this harness does not have."
The first capability is that incremental read, so that "the notification
arrived before the body was read to its end" is an observation rather than an
assumption — `sse_frames` takes a `&str` body and splits `data: ` lines out of
it, so by construction it runs only after the body is complete, which is why
it can carry the
S-03 isolation rows and not the S-02 ordering ones. The second is the
result-gating backend fixture row 4 specifies (`:454-457`) — a plain
incremental read passes against a buffering gateway and so proves nothing about
(d) or (f). `parked_slow_calls` is the nearest existing piece, but it parks the
*call*, not the result behind an
assertion. Both increments are small,
but they are (f)'s prerequisite twins: without a streaming body on the gateway
side there is nothing for an incremental reader to observe.

(f) is the smallest of the three unspent components: one handler seam
(`handlers.rs:599`), one body constructor (`streaming.rs:604-607`), and two
ordering fixtures — roughly 80–120 lines, against (d)'s ~200 and (e)'s three
rows plus the incremental-read capability. The deferral question the size might
have raised does not arise; (f) is sequenced before (e)'s two S-02×HTTP rows
because those rows deadlock without it.

Line numbers here are this tree's and perish on the next edit; the symbols
beside them do not.

### What does not change

§4's precedence, §5's bound of 64, and every
Acceptance row's text. Amendment 1's Correction to row 1 stands. The
client-facing HTTP leg is no longer on this list: (f) re-shapes it, because two
of (e)'s rows cannot pass while it stays batched. Row 5 is
discharged as written rather than reworded, so that claim holds — but its line
numbers have drifted and the Resolution above supplies the current ones.
