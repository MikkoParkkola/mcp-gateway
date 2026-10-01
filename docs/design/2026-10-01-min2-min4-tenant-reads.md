# MIN.2 and MIN.4: cross-tenant read verdict at a type-enforced outbound writer

Status: DRAFT until the lead confirms (design option C). Criteria:
MIK-7116.MIN.2 and MIK-7116.MIN.4
(docs/requirements/RELEASE-4.0.0-scope-update.md:132-133). Decision
`mik_7116_min_kill_gate` sets the frame: 4.0.0 ships observe-first, and
blocking by default waits for the MIN.KILL week (MIK-7627). Citations marked `REL:` (and the older `PR:`) refer to
`origin/docs/ranking-1-release-line:src/security/firewall/tenant_guard.rs`,
where PR #2593 is merged. The line numbers are the same as on the PR branch.

**Why this design.** Rounds 1-6 placed the check at writers, then at route
boundaries, then at stream yields. Each round found one more channel that
bypassed it. This design puts the check in the one place every frame must
pass through, and lets the compiler enforce that.

## 1. Threat model

- **Asset:** content attributed to a tenant through `arg_keys`. This covers
  request arguments and backend output, including output that has been
  transformed, cached or stored.
- **Actor:** an authenticated principal (API key, OAuth or OIDC subject, mTLS
  identity, or the stdio client). It may call any method it is authorised
  for, retry, replay, run playbooks, and hold several sessions.
- **Channels:** every JSON-RPC frame the gateway writes to the principal,
  whether result, error, notification or server-to-client request, on every
  transport. Sampling and elicitation forward backend text (proxy.rs:226-420),
  so they are in scope.
- **Out of scope, with reasons:**
  - `roots/list` (proxy.rs:425): a gateway-originated request carrying no
    backend content.
  - HTTP headers and status codes: the gateway sets these and copies no
    backend payload into them.
  - Timing and size channels: the criterion is about attributed content, not
    inference.
  - Operator logs and metrics: they reach the operator, not the actor.
  - Ids under keys outside `arg_keys`: the operator's configuration defines
    tenant data.
  - Non-MCP HTTP APIs (`/health`, `/api/costs`, accounts, the web UI,
    key-server routes; router/mod.rs:444-470): they serve no backend tool
    content.
  - `src/a2a`: a backend-side client (client.rs, provider.rs), not an inbound
    transport.

## 2. What exists

- **Attribution (MIN.1).**
  - `TenantGuard::scan_response` makes one private walk that returns tenants
    and `uninspected` (PR:181-188). `response_tenants` and
    `response_uninspected` (PR:163-177) each call it.
  - `request_tenants` walks request params (PR:154-158).
  - Attribution is off when `arg_keys` is empty (PR:168-170, :182-184).
- **`PrincipalWindow`** (principal_window.rs) drops the oldest observation at
  4,096 (:109-112) and evicts a whole principal when full (:173-180). Both
  fail open, so it is not reused.
- **Caller key.** `identity::caller_key` (identity.rs:350) is the canonical
  key. HTTP is stateless under 2026-07-28 (handlers.rs:602-606), and a
  `SessionOwner` is credential-specific (session_id.rs:31-35). One principal
  can therefore hold several sessions and credentials, and only `caller_key`
  joins them.
- **stdio already has one writer.** `run_stdout_writer`
  (stdio_writer.rs:17-27) is the only consumer of the frame queue
  (server/mod.rs:2435-2436). Its producers are `send_frame`
  (server/mod.rs:147-152; called at :2510, :2568, :2844),
  `stdio_channel.rs:140` (bridged requests; :68 only resolves a waiter), and
  `stdio_dispatches.rs:48`.
- **HTTP has no single writer.** Every place that builds an MCP body is listed
  in §4.1.
- **Late replacers.**
  - On HTTP, `slot_http` can swap the answer after the handler
    (grant_audit.rs:303-323).
  - On stdio, `slot_rpc` can swap it (grant_audit.rs:285-301, called at
    server/mod.rs:2978), and so can finalization (server/mod.rs:3050).
  - HTTP finalization (handlers.rs:1826-1828;
    response_security.rs:168-276) can refuse through the response firewall,
    a signing failure, or the fail-closed delivery event.

## 3. The rule

- Inside `window_secs`, the frames committed to one `caller_key` may name at
  most one tenant, and the frame being judged counts toward that.
- A frame that is `uninspected` adds a fresh unknown tenant `U`. `U` is
  distinct from everything, including another `U`, so it conflicts in either
  order.
- Not configured (`arg_keys` empty) or mode `off` means no judgement.
- "Sensitive" means attributed to a tenant. `data_classes` are not used,
  because the kernel reports `public` when it finds nothing
  (kernel.rs:437-438).

**Config.** `tenant_guard.cross_tenant_reads: off | observe | block`, a
lowercase serde enum on `TenantGuardConfig` (PR:56-69), default `observe`.
`block` is opt-in (`mik_7116_min_kill_gate`). The unknown-key check
(UPGRADING-4.0.md §29, :778) must accept the new key.

## 4. Design: `OutboundFrame`, built only by `judge_frame`

```rust
// src/gateway/outbound.rs: the type, its constructors and its sinks
pub(crate) enum Payload {                // typed, as built today; never converted to a Value tree
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
    Request(Value),                      // server-to-client request
    Batch(Vec<OutboundFrame>),           // stdio JSON-RPC array (server/mod.rs:2568); items judged one by one
}
pub(crate) enum OutboundReply {          // what every MCP HTTP handler returns (closed)
    Http(OutboundHttp),                  // JSON body, or POST-SSE via H5/H6
    Stream(OutboundStream),              // subscriptions/listen: a stream of OutboundFrame (H8)
}
pub(crate) struct OutboundFrame {        // private fields; no accessor returns the payload
    payload: Payload,
    assessment: Option<Assessment>,      // immutable: verdict, hashed tenants, uninspected
    ticket: Option<ReadTicket>,          // history reservation, committed by the sink
}
enum FrameOrigin<'a> {                   // private: callers cannot pick an origin
    Delivered { request: Option<&'a Value>, hidden: Option<&'a ReadAttribution> },
    Gateway { replaces: Option<Assessment> }, // gateway-built; never itself refused
}
// Gateway frames come only from fixed constructors in outbound.rs:
// gateway_error(id, code, message), replacement(original, refusal),
// sse_connected(), sse_lagged(n), stdio_busy(id), origin_forbidden(message).
// A backend-derived payload has no route to a Gateway origin.
pub(crate) fn judge_frame(reads: &ReadHistory, guard: &TenantGuard, key: Option<&str>,
    payload: Payload, origin: FrameOrigin<'_>) -> OutboundFrame
// sinks, all private to outbound.rs: to_http(OutboundHttp) -> Response,
// sse_event(OutboundFrame) -> String, stdio_write(&mut W, OutboundFrame) -> bool
```

`judge_frame` is the only constructor of `OutboundFrame`. Only the sinks in
`outbound.rs` can consume one, and there is no `into_parts`, so judged content
cannot be detached and changed. `OutboundHttp` does not implement
`IntoResponse`. `judge_frame` is public only through `delivered(..)`, which
sets the `Delivered` origin, and through the fixed `Gateway` constructors
listed above. Every MCP body, SSE event and stdio write takes an
`OutboundFrame`, so a path that skips the judge does not compile. These move
into `outbound.rs` and become private:

- the response helpers (helpers.rs:18-128);
- `message_frame` and `UNFRAMEABLE_FRAME` (streaming.rs:762-781);
- `terminal_frame` (:783);
- the string assembly in `request_scoped_event_stream` (:735-757).

**What is judged: the finalized value.** On every route, finalization runs
first. Finalization is the response firewall, the scope clamp, the
chain-strip, the origin link and signing (response_security.rs:176-262). Then
`judge_frame` runs, and nothing changes content after it. The
delivery-attempt event (response_security.rs:263-276) moves out of
finalization to after the judge, so it records the verdict for the bytes
actually sent (§4.6). The steps:

- **Fast path.** When `arg_keys` is empty or the mode is `off`, the result is
  `OutboundFrame { payload, assessment: None, ticket: None }`. That is a move
  of the typed payload, with no new allocation, no lock and no walk. Today the
  POST answer is serialized straight from `JsonRpcResponse`
  (helpers.rs:18-29, `Json<T: Serialize>`), and that does not change. The
  direct route already calls `to_value_lossy` today (helpers.rs:115), so it
  adds nothing.
- **Configured.** The steps run in order:
  1. One walk through a new `frame_attribution`, which wraps the private
     `scan_response`. On the release line, `scan_response` walks every object
     key, array and string, decoding JSON carried in any string
     (REL:tenant_guard.rs:181-212, with strings at :209). It covers only the
     payload fields `result`, `error.message`, `error.data` and `params`. The
     correlation fields `id`, `jsonrpc` and `method` are never scanned.
  2. For `Delivered`, the request-params tenants (REL:154-158) and the hidden
     attribution (§4.4) are added.
  3. `assess_read_at` runs (§4.5). On `Blocked`, `judge_frame` builds the
     delivery refusal itself, with `assessment` = blocked plus the denied
     attribution and no ticket. The evidence survives the replacement.
  4. A `Gateway` frame is assessed on its own payload only, and it is never
     `Blocked`. Its verdict is recorded but never applied. This guarantees
     termination: a refusal that keeps a JSON-shaped id cannot refuse itself,
     and `id` is not scanned anyway.

**Commit rule.** A ticket commits only when an `outbound.rs` sink writes the
frame:
- the HTTP body is built (`to_http`);
- an SSE event string is yielded;
- `write_response` returns `true` (stdio_writer.rs:22).

A late replacer (`slot_http`, `slot_rpc`, or a fail-closed event write) can
only build `judge_frame(.., Gateway { replaces: Some(original.assessment) })`.
That drops the original ticket and keeps its assessment as evidence.

### 4.1 Inventory of HTTP delivery paths

Every place that builds an MCP JSON-RPC body today, and how it routes:

| # | Today (file:line) | Frames | Routed through the writer by |
|---|---|---|---|
| H1 | `build_session_response` (helpers.rs:18-29), used by `build_json_response` :57, `build_response` :66, `build_error_response` :75, `build_error_response_with_data` :95 | POST `/mcp` answers and gateway errors | The helpers take `OutboundFrame`; `Json(...)` moves into `outbound.rs` |
| H2 | handlers.rs:1876 `(status, axum::Json(response))` and :1878 | the final POST answer | `meta_mcp_dispatch` (handlers.rs:476) returns `OutboundReply`. The answer is judged right after finalization's content steps (handlers.rs:1826-1828, response_security.rs:176-262). Its delivery event is written after `slot_http` (§4.6) |
| H3 | `slot_http` replacement (grant_audit.rs:303-323) | grant-audit failure answer | Takes and returns `OutboundHttp`. The replacement is `judge_frame(.., Gateway)` and drops the original ticket. Re-parsing the body (:309-313) goes away, because the id is on the typed frame |
| H4 | `meta_mcp_handler` (handlers.rs:443-472), buffered arm :466-470 | POST answer without SSE | The single entry. After `slot_http` it calls `outbound::emit_http`, which writes the delivery event, builds the body and commits |
| H5 | `first_event_wins_stream` (streaming.rs:812-874): `message_frame` :762, `terminal_frame` :783, yields at :838, :845, :854, :857 | POST-SSE notifications and the terminal answer | The notification channel carries `OutboundFrame` (judged in `publish`, stream scopes only, §4.3); the terminal frame is `OutboundHttp`; each yield goes through the private `sse_event` sink and commits. `message_frame`, `terminal_frame` and `UNFRAMEABLE_FRAME` (streaming.rs:762-797) move into `outbound.rs` |
| H6 | `request_scoped_event_stream` (streaming.rs:711-759), notification loop :736, result bytes :729 | dispatch-first fallback: drained notifications, then the result | Takes `Vec<OutboundFrame>` plus `OutboundHttp`, not bytes. This is the round-6 CRITICAL path |
| H7 | `create_sse_response` (streaming.rs:466-529): events at :487, :498, :502, :521. Fan-out via `send_to_session`, `broadcast` and `broadcast_to_backend` (:381, :401, :304) from proxy.rs:250-559 and webhooks/mod.rs:605 | GET session stream: notifications and server-to-client requests | Judged at enqueue, per session, in all three fan-out functions, with that session's stored `caller_key`. The payload is clamped (`clamp_response_envelope`, cacheable.rs:160-168) before judging, and `sse_event` only serializes it. The `message_event_data` re-clamp and clone at yield (streaming.rs:498-500) goes away. `Refused` completes a request's waiter (proxy.rs:153-201). The ticket stays live until emission (§4.5). `connected` and `lagged` come from fixed `Gateway` constructors |
| H8 | `subscription_stream` (streaming.rs:540-600), ack :556, events :579 | `subscriptions/listen` | Dispatch returns `OutboundReply::Stream`. Each listener event is judged with the `caller_key` captured at open (handlers.rs:1089), before the yield, and emitted through `sse_event` |
| H9 | Direct route `Answer` (direct_audit.rs:23); `build_http_response` / `build_http_error_response` (helpers.rs:111-128); `audited_call` single return (direct_audit.rs:114-118) | every `/mcp/{name}` answer | `Answer` becomes `OutboundHttp`, judged in `audited_call` for every method. Its notifications are drained and discarded (backend_handlers.rs:425-430) |
| H10 | http_error.rs:12-19 `json_body` / `json_response` | plain HTTP errors | Kept for non-MCP bodies; an MCP use moves to H1 |
| H11 | origin middleware `forbidden` (origin_guard.rs:416-424), returned at :408 | JSON-RPC `-32600` refusal before authentication | Built by an `outbound.rs` constructor as `judge_frame(.., key: None, Gateway)` and written through `to_http`. No key exists before authentication; a `Gateway` frame is never refused |
| H12 | `jsonrpc_error_body` (http_error.rs:40) via `jsonrpc_error_response` (middleware/errors.rs:33-42), for example `circuit_open_response` (:28-30) | middleware JSON-RPC errors | Built by `outbound::gateway_error` and written through `to_http` |
| S1 | stdio batch array (server/mod.rs:2568) | batch answers | `Payload::Batch` of individually judged frames. `stdio_write` serializes the array inside `outbound.rs` and commits every item's ticket after the array is written |
| S2 | stdio busy refusal, `try_send` (server/mod.rs:2588-2600) | overload refusal | `outbound::stdio_busy(id)` builds the frame; `try_send` takes an `OutboundFrame` |

**Enforcement: the type plus module privacy.** `outbound` is a private
module. Its frame types are sealed, and their fields are private, so they
cannot be built outside it. The MCP routes (`/mcp` POST and GET, and
`/mcp/{name}`; router/mod.rs:454-464) are registered through one
`outbound::mcp_route(handler)` adapter. That adapter accepts only handlers
returning `OutboundReply`, and it alone turns an `OutboundReply` into a
`Response`. The stdio queue is typed `Sender<OutboundFrame>`.

What the compiler guarantees:
- every value an MCP route handler returns, and every frame stdio writes, is
  an `OutboundFrame` built by `judge_frame`;
- nothing outside `outbound` can change a judged payload or skip a commit.

What it does not guarantee:
- code that builds a JSON-RPC-shaped body on a non-MCP route;
- a tower middleware layered after the MCP routes that answers with its own
  body. Today these are `origin_guard` (H11), the circuit-breaker middleware
  (H12) and `CatchPanicLayer`, the last of which carries no backend content
  (§9);
- a handler that returns a stream of raw strings through some other route.

Those cases are covered by a secondary tripwire: `clippy.toml`
`disallowed_methods` and `disallowed_types`, with negative fixtures. It bans
direct construction of `axum::Json`, `axum::response::sse::Event` and
`axum::body::Body::from` outside `outbound.rs` and a named non-MCP allowlist,
so `Json<Value>` and raw bodies are covered as well as typed ones. It runs in
the existing `cargo clippy -D warnings` gate. clippy cannot select generic
instantiations or argument types, so the ban works at the constructor level
and the allowlist is reviewed.

### 4.2 Keys

Every writer instance holds the canonical `caller_key` (identity.rs:350),
captured once when its stream opens. It is never a `SessionOwner` (round 6,
CRITICAL), and it is never revalidated mid-stream.

| Path | Where the key is captured |
|---|---|
| POST `/mcp` (H1-H6) | `caller_key` formed from `grant_subject`, certificate and client at the first identity resolution in `meta_mcp_dispatch` (handlers.rs:538-544), before any `build_error_response` return. It replaces the later computation at handlers.rs:1499-1503. Frames returned before that point (the refusal at :543) are `Gateway` frames with no key |
| GET stream (H7) | `mcp_sse_handler` keeps the `GrantSubject` that `request_session_owner` returns (today discarded as `Ok((_, owner))`, handlers.rs:216-218), computes `identity::caller_key` from the same subject, certificate and client as POST, and stores it on the `ClientSession` before `create_sse_response` (:285). The session's `owner` (streaming.rs:72) stays an ownership check only |
| `subscriptions/listen` (H8) | the `caller_key` in scope at handlers.rs:1089, passed into `subscription_stream` |
| Direct (H9) | `identity::caller_key` over the request's subject, certificate and client (backend_handlers.rs:515) |
| stdio | the constant `stdio`: one process serves one client (stdio_nonce.rs:4-10) |

An empty key is `Unattributable` (refused in block mode). The session-id and
per-backend fallbacks are never used (handlers.rs:1295-1302;
backend_handlers.rs:59-73). Two sessions, or two stateless requests, under
one `caller_key` share one history.

### 4.3 Notifications and server-to-client requests

- **POST-scoped notifications.** These go through
  `notification_sink::publish` (transport/notification_sink.rs:109) into the
  scope opened by `meta_mcp_handler` (`scope` :64, `collect` :86). The scope
  now also carries the guard and `caller_key`, so `publish` builds an
  `OutboundFrame` through `judge_frame(.., Delivered{request: None, hidden:
  None})`. The H5 stream and the H6 fallback consume them, and commit as they
  write. The scope has a mode, `NotificationScope::{Stream, Discard}`. In the
  buffered arm (handlers.rs:466-470), the mode is `Discard` and `publish`
  drops each notification before judging it. A notification that is never
  written therefore reserves nothing, and it cannot get the delivered answer
  refused.
- **Session-stream items** (H7). These come from proxy.rs (sampling and
  elicitation, :226-420; list-changed, :482) and webhooks (webhooks/mod.rs:605),
  and are judged at enqueue (H7) with the session's stored key. In block mode
  a notification is not enqueued, and a request makes `send_to_session`
  return `Refused`, so the proxy completes its pending waiter with a
  `Gateway` refusal (proxy.rs:153-201) rather than waiting for a timeout. The
  ticket commits at the stream's yield (`sse_event`). With several
  subscribers it commits once, on the first write.
- **stdio.** The queue type (server/mod.rs:2435) becomes
  `mpsc::Sender<OutboundFrame>`, so every producer must judge:
  - `send_frame` (:147);
  - `StdioClientChannel::send_request` (stdio_channel.rs:91-140). On
    `Blocked` it never enqueues. Instead it removes its pending entry and
    returns the `Gateway` refusal to its own awaiting caller, which is the
    backend bridge;
  - stdio_dispatches.rs:48.

  stdio_channel.rs:68 is not a producer: it hands a client answer to a
  waiter (`resolve`, :62-70).

  The writer commits after `write_response` returns `true`
  (stdio_writer.rs:22-26).

### 4.4 Hidden attribution (what the frame does not show)

A delivered response frame's `FrameOrigin::Delivered.hidden` comes from a
non-wire field, `#[serde(skip)] pub(crate) read: Option<ReadAttribution>` on
`JsonRpcResponse`, so it is never on the wire nor in the HMAC over delivered
bytes. It sits
beside `discovery_inspected` and `chain_source` (messages.rs:78-81). A
gateway-built response starts as `None`. The field is filled from four
sources:

- **Inner dispatches.**
  - Each dispatch's request tenants, raw pre-gate response tenants (noted at
    audit.rs:93) and `uninspected` flag are collected in a request-scoped
    task-local, shaped like `DispatchNotes` (audit.rs:75-78, :147-156).
  - A dispatch contributes only if its own outcome was delivered into the
    caller's result (`Ok` after its gates). A refused step under
    `ErrorStrategy::Continue` adds nothing (round 6, MEDIUM).
  - The collection happens before `audit_invocation`'s no-logger return
    (audit.rs:338).
  - Playbook steps call `invoke_tool` on the request's own task
    (support.rs:391-398).
- **Caches.** Each of these keeps the pre-transform `read` beside its value:
  - the response cache: set at invoke.rs:2543, hit at :1903;
  - `StoredDelivery` (admission.rs:100-108);
  - the inner idempotency store: idempotency.rs:729, hit at invoke.rs:1787;
  - the direct idempotency store: hit at backend_handlers.rs:1118.

  A hit restores the stored `read`. An entry without one restores `U`.
- **Stored task results.** The task row stores `read_tenants` and
  `read_uninspected` in the same write as the payload. A version bump goes
  next to `TARGET_VERSION` (record.rs:35-38; precedent
  store_targets.rs:118-196). Settlement stops passing the empty set it
  passes today (audit.rs:475). A row without the fields restores `U`.
- **Request params.** These are always passed as `Delivered.request` by the
  frame's builder, on stdio too, including `prompts/get` paths that bypass
  `invoke_tool`. This takes the round-6 improvement.

### 4.5 History (`ReadHistory`)

There is one `Arc<ReadHistory>` per process, not one per `TenantGuard`.
Production builds two `Firewall`s, both through `response_firewall`
(server/mod.rs:511-528): one is installed on `MetaMcp` (server/mod.rs:1258),
and the other becomes `AppState.firewall` (server/mod.rs:1803-1805;
router/mod.rs:201). A history held inside `TenantGuard` would therefore split
one caller across `/mcp` and `/mcp/{name}`. Instead, the `Gateway` creates
the `Arc` once. `response_firewall` passes it to both through a
`Firewall::with_read_history` builder, the same shape as `with_env`
(server/mod.rs:519-522). It is also held on `AppState` for the stream
writers. `judge_frame` borrows it. The only lock on the path is a `DashMap`
shard lock, taken only when a frame carries a tenant or `U`. For each
principal it keeps:
- `committed: HashMap<TenantHash, Instant>`, which leaves by expiry only;
- `pending: HashMap<TenantHash, u32>`, a reference count per open ticket;
- `pending_overflow: u32`;
- `overflow_until: Option<Instant>`.

A ticket owns the hashes it incremented. Commit decrements its counts and
upserts `committed`. Drop decrements only its own counts. The bound is 256
distinct hashes per principal, counting committed and pending together. Past
it, only `pending_overflow` grows: block mode refuses, and observe mode
flags. The principal map is capped at 100,000. Expired entries are swept
first; if the map is still full, a new principal is `Unattributable`. Live
history is never evicted.

**Delayed delivery: the ticket stays live until emission.** A frame that is
queued but not yet written holds its pending reservation until its last copy
is written or dropped. This applies to a GET-stream copy waiting in a slow
subscriber's broadcast buffer, a POST-SSE notification, and a stdio frame in
the queue. A shared ticket is an `Arc` (one allocation, configured path
only). Each write upserts `committed` at that write's time. Dropping the last
copy, including a broadcast slot overwritten on `Lagged`, releases the
reservation.

Why this fails closed: pending entries count as live in step 4 of the judge.
So whenever a B frame is judged, every A frame not yet written to that
principal is in `distinct`, and B is flagged. Expiry is measured from the
last emission, never from enqueue, so a late copy of A cannot reach the
caller after the window has let B through. Reservations are bounded by the
existing per-session broadcast capacity and the stdio queue depth
(server/mod.rs:2435).

**Batch.** A stdio batch (`Payload::Batch`) holds individually judged items
and is written as one array. Its tickets commit together after the write.

The judge (`assess_read_at`) checks in this order:
1. Off or unconfigured: no verdict.
2. Empty and complete: no verdict.
3. No key: `Unattributable`.
4. Under the entry lock, `distinct` over committed, pending, overflow, the
   frame's tenants and a fresh `U`. `distinct > 1` gives `Flagged` or
   `Blocked`.
5. Unless `Blocked`, reserve the frame's entries under a ticket.

Ids are hashed once with `hash_argument` (data_flow.rs:139).

### 4.6 Ordering against late replacers

| Route | Replacers, in order | Where `judge_frame` runs | Commit |
|---|---|---|---|
| HTTP POST | finalization content steps (response_security.rs:176-262), then `slot_http` (grant_audit.rs:303-323), then the delivery event, which moves out of :263-276 into `outbound::emit_http` | after the content steps | `emit_http`, after the event is written |
| stdio | `slot_rpc` (grant_audit.rs:285-301, server/mod.rs:2978), then finalization (server/mod.rs:3050) | after the finalization content steps, before the delivery event and the enqueue | writer, after `write_response` (stdio_writer.rs:22) |
| Direct | `record`'s fail-closed write (direct_audit.rs:194-203) | `audited_call`, before `record` | `audited_call`'s single return (:116-118), on every `record` path |

Content is final when it is judged: finalization's mutating steps (scope
clamp, chain-strip, origin link, signing) all run before `judge_frame`, and
nothing writes to the payload afterwards. The payload is private, and no
`into_parts` exists. Later steps can only replace the whole frame, through
`judge_frame(.., Gateway { replaces })`. That drops the original ticket and
carries its assessment forward.

The delivery event is split out of finalization and written by the sink,
after every replacer. On HTTP that is after `slot_http`, so its hash names
the bytes actually emitted, including a replacement refusal. It records the
verdict, and on a replacement it records the original assessment.

**Terminal audit failure.** If the event write fails under `FailClosed`, the
sink builds `replacement(original, refusal)`, makes one attempt to append
that refusal's event, and then writes the refusal whether or not the append
succeeded. A refusal carries no backend content, so emitting it without an
event withholds nothing. No path audits a replacement more than once, so the
sequence always terminates, even under a logger that keeps failing. A refusal is unsigned,
as RESPONSE.4 requires (scope-update.md:125).

### 4.7 Records

Each judged frame that has tenants, `U` or a verdict writes one event:
- a response on meta or stdio: the existing `response_delivery_attempt`
  (response_security.rs:263, :284-330);
- any other frame on any route: a `tenant_read` event through `append_event`
  (response_security.rs:325-326);
- the direct route: one `tenant_read` event in `audited_call`'s common path
  for every method, independent of `DirectCall::of`, which skips everything
  except `tools/call` (direct_audit.rs:47, :117) (round 6, HIGH).

Each event carries the `caller_key` beside the display name, `tenants`
(hashed), `attribution` (`uninspected` when it applies) and
`cross_tenant_read` (`flagged` | `blocked` | `unattributable`). Events honour
`FailClosed`: a failed write turns the frame into a refusal through
`judge_frame(.., Gateway)`, which drops the ticket. Tenant ids are compared
across all backends and keys (§6).

### 4.8 Performance (NFR.WORKLOAD.1 already shows an 8% p50 regression)

- **No new task, channel or `Mutex`.** The writer is a type and a function
  call at each existing sink. stdio keeps its existing queue
  (server/mod.rs:2435); HTTP adds nothing per session.
- **Fast path.** When `arg_keys` is empty or the mode is `off`,
  `judge_frame` is one branch plus a move of the typed `Payload`: zero
  allocations and zero locks per frame. That is the default deployment.
  - The POST answer stays a `JsonRpcResponse`, serialized by the sink as it is
    today (helpers.rs:18-29). There is no `to_value` tree.
  - The direct route's `to_value_lossy` (helpers.rs:115) already runs today
    and is unchanged.
- **Configured path.**
  - One walk per frame through `frame_attribution`, replacing the second walk
    `response_tenants` and `response_uninspected` would make.
  - A walk allocates only for parsed JSON-in-text and for found ids.
  - The only lock is one `DashMap` shard lock, taken only when the frame
    carries a tenant or `U`.
- **H3 gets cheaper.** It drops a full body re-parse
  (grant_audit.rs:309-313).

The test plan (§6) measures all of this:
- a counting global allocator and a lock counter wrap the whole handler-side
  conversion: payload construction, `judge_frame` and the sink. On the fast
  path they assert zero extra allocations and zero lock acquisitions
  compared with today's path. On the configured path they count the whole
  ticket lifecycle (reserve, plus commit or drop) as at most two shard-lock
  acquisitions per tenant frame;
- a `criterion` bench row runs `judge_frame` on and off;
- the NFR.WORKLOAD.1 k6 run (tests/load/k6_gateway.js) is repeated at the
  tip, with the default config, before merge.

### 4.9 Increment split

The task-row fields (§4.4) can ship later without a bypass, because their
absence restores `U`. The type, the inventory routing, the keys, the history
and the records ship together.

## 5. MIN.4: fixture corpus and false-positive measurement

**Corpus.** `tests/fixtures/tenant-reads-corpus.jsonl` holds one line per
outbound frame: `session`, `caller_key`, `t_secs`, `pattern`, the incoming
request params (for answers), and the full outbound frame (result, error,
notification or server-to-client request). The test runs each line through
`judge_frame`, the writer's own check, so a regression in extraction moves
the measurement. Labels come from the generating pattern, never from the
guard. A header line gives each pattern's session count.

Patterns, with their label:
- **Legitimate:** `single_tenant`, `retry_same_tenant`, `mixed_workload`,
  `opaque_only` (one opaque frame), `support_handoff_slow`,
  `window_boundary`.
- **Legitimate, known false positives:** `opaque_only_multi` (several opaque
  frames in one session: the price of failing closed under the fresh-`U`
  rule), `support_handoff_fast`,
  `admin_sweep`, `large_single_tenant`.
- **Cross-tenant:**
  - `a_then_b`;
  - `a_then_b_request_only`;
  - `a_then_opaque` / `opaque_then_b`;
  - `a_result_then_b_notification`;
  - `a_then_b_error_data`;
  - `two_sessions_one_key` (both sessions carry explicit session labels,
    and the denominator counts the principal once).

**Measurement.** `src/security/firewall/tenant_read_corpus_tests.rs` is an
ordinary unit test with no network, built from `TenantGuardConfig { arg_keys,
..Default::default() }`. It counts per principal-session (the MIN.KILL unit)
and asserts three gates:
1. Zero flags on the legitimate patterns. The known-false-positive group,
   `opaque_only_multi` included, is excluded from this gate.
2. Every cross-tenant session is flagged.
3. Exact pinned counts and FP rate, following
   tests/provenance_eval_binary.rs:26-32.

There is no FP-rate ceiling. The known-FP patterns are flagged by
construction, the deployment number comes from the MIN.KILL week, and the
remedy is MIN.3 (MIK-7627).

## 6. Tests (red first)

Every row is written and seen failing before its code exists, and goes red
under its mutant. Row 1 opens the plan.

| # | Test | Asserts | Mutant |
|---|---|---|---|
| 1 | `dispatch_first_post_b_notification_after_a_result` | POST with `Accept: text/event-stream` and dispatch finishing first (H6): an A result, then a B notification drained into the fallback body. Observe: B frame flagged, event written. Block: B notification absent from the body | fallback serializes raw notifications (streaming.rs:736) |
| 2 | `concurrent_stateless_and_two_sessions_one_key` | Concurrent stateless POSTs plus two GET sessions under one `caller_key`, reading A and B: exactly the B side flagged. Counting allocator and lock counter: fast path 0/0; configured path one shard lock per tenant frame | key taken from `SessionOwner` or session id; a second `ReadHistory`; a per-frame allocation or lock on the fast path |
| 2a | `get_stream_subject_key_matches_post` | an OIDC subject reads A on POST and B on the GET stream: flagged | GET key formed without the `GrantSubject` (handlers.rs:216-218) |
| 2b | `meta_and_direct_share_history` | A on `/mcp`, B on `/mcp/{name}`, same key: flagged | history held per `TenantGuard` |
| 2c | `blocked_sampling_completes_waiter` | blocked sampling/elicitation on the GET stream and on stdio: the backend waiter gets a refusal at once, with no timeout, and nothing is queued to the client | refusal enqueued instead of resolving the waiter |
| 2d | `buffered_notification_reserves_nothing` | buffered POST: a B notification is discarded, and the delivered A answer is not refused | judging in `Discard` scopes |
| 2e | `judged_bytes_are_sent_bytes` | the signed, clamped final payload is what is judged; the event hash equals the bytes written | judge before finalization content steps |
| 2f | `blocked_evidence_survives_replacement` | a blocked B frame then a `slot_http` failure: the event still carries `blocked` and `h(B)` | assessment lost on replacement |
| 2g | `refusal_with_json_id_terminates` | a request id that is a JSON string naming B, refused after A: exactly one refusal, which is never re-refused | scanning `id`; `Gateway` frames refusable |
| 2h | `origin_refusal_built_by_outbound` | a Host-mismatch refusal is produced through `outbound.rs` | `forbidden` keeps its own `Json` (origin_guard.rs:416-424) |
| 2i | `delayed_subscriber_copy_fails_closed` | A queued to a stalled GET subscriber; the window passes; B judged; then the A copy is written: B flagged (A still pending), and the A write upserts at emission time. A `Lagged` drop releases the reservation | commit at first copy, or commit time taken at enqueue |
| 2j | `stdio_batch_items_judged` | a stdio batch answering A then B: B item flagged/refused, the array written once, all tickets committed after the write | the batch as `Request(Value)` or unjudged |
| 2k | `listen_is_a_stream_reply` | `subscriptions/listen` returns `OutboundReply::Stream`; its B event after A is flagged | listen kept on `Event::data` |
| 2l | `event_hash_is_after_slot_http` | a `slot_http` failure after a judged A answer: the delivery event hashes the refusal that was sent and carries A's original assessment | event written before `slot_http` |
| 2m | `terminal_audit_failure_terminates` | a logger that always fails under `FailClosed`: exactly one refusal is written, after one replacement-audit attempt | recursive replacement audit |
| 2n | `gateway_constructors_closed` | compile-fail (trybuild): a backend payload cannot be given a `Gateway` origin; `OutboundFrame` cannot be built outside `outbound`; a route handler returning a `Response` cannot be registered with `mcp_route` | the origin or a constructor made public |
| 2o | `middleware_errors_through_outbound` | the circuit-open and busy refusals come from `outbound` constructors (H12, S2) | `jsonrpc_error_body` kept raw |
| 2p | `broadcast_to_backend_judged_per_session` | list-changed fan-out to two keys: each judged with its own key | one judged frame reused across keys |
| 2q | `sse_bytes_equal_judged_payload` | GET-stream message bytes equal the judged, clamped payload, with no second clamp | `message_event_data` at yield |
| 3 | `a_then_b_two_events` (POST JSON, POST-SSE, GET stream, listen, stdio, direct) | A event with `tenants=[h(A)]` and no verdict; B event with `cross_tenant_read=flagged` | a sink built without `judge_frame` |
| 4 | `a_then_b_block_refuses` (each transport) | B replaced by the refusal (response) or dropped (notification); event `blocked` | verdict computed but not applied |
| 5 | `request_only_tenant_any_method` | `prompts/get` with `customer_id: B` in args and an unkeyed result, after A: flagged (HTTP and stdio) | request params not passed to `Delivered` |
| 6 | `error_data_is_a_read` | backend error whose `error.data` names B, after A: flagged and committed | only `result` scanned |
| 7 | `gateway_refusal_charges_nothing` | refused B request, then A: not flagged | refusal built as `Delivered` |
| 8 | `grant_slot_replacement_commits_nothing` | `slot_http`/`slot_rpc` failure on a B answer, then A: not flagged | ticket committed before the slot |
| 9 | `finalization_replacement_commits_nothing` | firewall, signing or fail-closed event refusal on B (HTTP, stdio), then A: not flagged; the stdio event hashes the refusal sent | commit at judge time; stdio event before judge |
| 10 | `sampling_request_is_judged` | elicitation/sampling text naming B on the GET stream after A: flagged; block answers the waiter with a refusal | session-stream items unjudged |
| 11 | `listen_keyed_on_caller_key` | `subscriptions/listen` event naming B after a POST read of A under the same key: flagged | listen keyed on its listener |
| 12 | `direct_every_method_event` | `completion/complete` naming B on `/mcp/{name}` after A: flagged, `tenant_read` written | event tied to `DirectCall` |
| 13 | `playbook_continue_refused_step` | a refused B step under `ErrorStrategy::Continue`, then A: not flagged; a delivered B step: flagged | collecting refused steps |
| 14 | `cache_hit_restores_pre_transform` | B cached after a key-stripping transform, hit after A: flagged; an entry without `read` gives `U` | cache without `read` |
| 15 | `task_request_only_tenant` / legacy row | a B-only-in-request task read after A: flagged; a row without fields gives `U` | empty set at settlement |
| 16 | `uninspected_both_orders` | A then opaque, and opaque then B: flagged; a lone opaque frame: none | `U` not distinct |
| 17 | `history_bounds_and_ownership` | 10,000 tenants: hashes stay at 256 or fewer; overlapping tickets; a drop keeps a committed A | eviction; a drop clearing others |
| 18 | `hidden_attribution_without_logger` | no transparency log: a playbook step naming B after A is flagged | collection after audit.rs:338 |
| 19 | clippy tripwire negative fixtures | seeded `axum::Json(json!({"jsonrpc":..}))`, `Json<JsonRpcResponse>`, `Event::default().data(..)` and `Body::from(String)` outside `outbound.rs` each fail the clippy gate | rule removed, or allowlist widened |
| 20 | `unconfigured_is_noop` / `config_mode` | `arg_keys` empty: no fields, no refusal; `observe` default; bool rejected | judge before the attribution check |
| 21 | `tenant_read_corpus_fp_measurement` | §5 gates 1-3 | window, threshold or default changed |
| 22 | bench `judge_frame_fast_path` plus the NFR.WORKLOAD.1 k6 run | no regression beyond the NFR.WORKLOAD.1 budget at the default config | per-frame work on the fast path |

Rows 1 and 2 are the gate for the design: they must be red on the release tip
before any implementation lands.

## 7. UPGRADING-4.0.md

Add one row next to row 110 (UPGRADING-4.0.md:137); its number is assigned at
merge. Proposed text:

> With `tenant_guard.arg_keys` set, every frame the gateway sends a caller
> (results, errors, notifications and server requests, on every transport) is
> checked. A caller whose frames name more than one tenant inside
> `window_secs` is marked `cross_tenant_read: flagged`, or `unattributable`
> without an identity. An unreadable response counts as an unknown tenant.
> The new key `tenant_guard.cross_tenant_reads` takes `off|observe|block` and
> defaults to `observe`. Ids are compared across backends, so namespace any
> that backends reuse. No action is needed; set `off` to silence it.

## 8. Decisions

1. Security findings are fixed in 4.0, and the guard fails closed (lead,
   2026-10-01).
2. The task-row fields are accepted. The 256 cap is a constant.
   `large_single_tenant` is a measured, deliberate false positive.
3. **Option C** (merge lane, confirmed by both cross-checks): a type-enforced
   last hop. `judge_frame` is the only constructor of an outbound MCP JSON
   body or SSE event. It is keyed on `caller_key`, with no session channel.
4. **No automatic fallback to option B.** MIN.2 stays an open release gate.
   If the design is not reviewed and red tests are not in by 2026-10-04 12:00,
   the lane reports B to the lead with a written reason, as a proposal for the
   operator. A lane checkpoint does not narrow a security criterion.
5. The threshold is fixed at 1.

**Open for the lead:**
- (a) Should the `tenant_read` event stay a new event name, or extend
  `response_delivery_attempt` to non-response frames?
- (b) Test 19 is lexical. Accept it as a tripwire behind the type, or
  require a dedicated `clippy` `disallowed_methods` rule instead?
- (c) Confirm that no middleware layered after the handlers rewrites MCP
  bodies (router/mod.rs:360 auth layer); verify at implementation.

## 9. Superseded

Rounds 1-6 reviewed earlier placements of the check (writers, route
boundaries, stream yields). Their findings are closed by construction here:
every frame is an `OutboundFrame`. The history is in git, up to commit
9f55c2e2e.

**Draft decisions (merge lane):** `tenant_read` stays a separate event, so `response_delivery_attempt` keeps its response-only meaning. The tripwire behind the type is a clippy `disallowed_methods` rule (constructing an MCP body or SSE event outside the outbound module), not a text scan. No middleware after the handlers rewrites MCP bodies: auth, agent-auth and the OpenWebUI adapter do not map response bodies, `CompressionLayer` preserves content, and `CatchPanicLayer` answers a panic with a gateway-built 500 that carries no backend content (src/gateway/router/mod.rs:350-360, :501-502).

### Review dispositions (C design, two seats)

| Finding | Disposition |
|---|---|
| Two `Firewall`s, so two histories (CRITICAL) | Fixed: one `Arc<ReadHistory>` per process (server/mod.rs:511-528, :1258, :1803-1805), §4.5. Test 2b |
| Judged before finalization mutates (HIGH) | Fixed: content steps first, then judge, then the delivery event (§4, §4.6). Test 2e |
| Blocked evidence lost on replacement (HIGH) | Fixed: an immutable `assessment` separate from the ticket, carried by `Gateway { replaces }`. Test 2f |
| Refusal loop on a JSON id (HIGH) | Fixed: `id`, `jsonrpc` and `method` are never scanned, and `Gateway` frames are never refused. Test 2g |
| `into_parts` detaches the ticket (HIGH) | Fixed: removed; sinks are private to `outbound.rs` |
| H7 cannot reach the waiter (HIGH) | Fixed: judged at enqueue (streaming.rs:381, :401); `Refused` completes the waiter (proxy.rs:153-201). Test 2c |
| GET drops `GrantSubject` (HIGH) | Fixed: subject kept (handlers.rs:216-218), so the key matches POST. Test 2a |
| `Value` payload allocates on the fast path (HIGH) | Fixed: typed `Payload`; POST serializes `JsonRpcResponse` as today (helpers.rs:18-29); the direct route's existing `to_value_lossy` is at helpers.rs:115 |
| `frame_attribution` sees only `content[].text` (HIGH) | Refuted: on the release line `walk_response` walks every key, array and string, decoding JSON in any string (REL:tenant_guard.rs:190-212, strings at :209). The `texts()` cited is not in it |
| Buffered notifications reserve history (MEDIUM) | Fixed: a `Discard` scope drops them before judging. Test 2d |
| stdio request refusal not resolving its waiter (MEDIUM) | Fixed: `send_request` (stdio_channel.rs:91-140) returns the refusal to its caller, with nothing enqueued. Test 2c. stdio_channel.rs:68 is `resolve`, not a producer, and is corrected in §2 |
| Origin middleware refusal outside the type (MEDIUM) | Fixed by routing: H11, built in `outbound.rs` (origin_guard.rs:416-424). Test 2h |
| Improvements | Taken: `message_frame`, `UNFRAMEABLE_FRAME` and SSE assembly moved into `outbound.rs`; no `IntoResponse` for `OutboundHttp`; `caller_key` hoisted to handlers.rs:538-544; allocation and lock counts around the full conversion and the ticket lifecycle; multi-frame opaque-only and labelled two-session corpus patterns |

### Review dispositions (C design, round 2)

| Finding | Disposition |
|---|---|
| Delayed GET subscriber emits A after expiry (CRITICAL) | Fixed: the ticket stays live until the last copy is emitted or dropped, and commit time is the emission time (§4.5). Test 2i |
| clippy cannot enforce the boundary (HIGH) | Fixed: enforcement is the type plus module privacy, with MCP routes registered only through `mcp_route` returning `OutboundReply`. What the compiler does and does not guarantee is stated in §4.1. clippy is a secondary constructor-level tripwire covering `Json<Value>`, `Event` and raw bodies. Tests 2n, 19 |
| No batch inhabitant (HIGH, both seats) | Fixed: `Payload::Batch` (S1, server/mod.rs:2568). Test 2j |
| Delivery event before `slot_http` (HIGH) | Fixed: the event is written by the sink after `slot_http` (§4.6). Test 2l |
| Listen has no `OutboundHttp` form (HIGH) | Fixed: `OutboundReply::Stream` (H8, handlers.rs:1089). Test 2k |
| `opaque_only_multi` in the zero-flag gate (MEDIUM and HIGH) | Fixed: moved to the known-false-positive group and excluded from gate 1 |
| `jsonrpc_error_body` and busy `try_send` outside the type (MEDIUM) | Fixed by routing: H12 (http_error.rs:40, middleware/errors.rs:28-42) and S2 (server/mod.rs:2588-2600). Test 2o |
| Improvements | Taken: fixed `Gateway` constructors with a private `FrameOrigin`; a terminal audit-failure path (one replacement-audit attempt); clippy covering `Json<Value>`; `broadcast_to_backend` (streaming.rs:304) judged per session; `sse_event` serializes the payload clamped before judging, with no `message_event_data` re-clamp (cacheable.rs:160-168, streaming.rs:498-500); `#[serde(skip)]` on `read`, as on `discovery_inspected` (messages.rs:78-79) |
