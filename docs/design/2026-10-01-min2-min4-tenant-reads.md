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
- **Channels:** event deliveries to the principal's HTTPS callback (MIK-7630,
  E1 in §4.1), and every JSON-RPC frame the gateway writes to the principal,
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
  - On the release line, `TenantGuard::scan_response` makes one private walk
    (REL:tenant_guard.rs:181, with `walk_response` at :190-212) that returns tenants
    and `uninspected`. `response_tenants` and `response_uninspected`
    (REL:163-177) each call it. This worktree's base predates the merge: its
    tenant_guard.rs:152-218 still has `texts()` at :184. The implementation
    targets the release line, and `frame_attribution` wraps `scan_response`
    there.
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
    Request(Value),                      // server-to-client request, incl. proxy_request envelopes
    Event(Value),                        // the SSE document actually emitted: webhook bodies
                                         // (webhooks/mod.rs:598-610), session-stream items whose
                                         // data is not JSON-RPC (streaming.rs:497-504)
    Callback(Value),                     // a MIK-7630 event body for an HTTPS callback
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
// gateway_error(id, GatewayError), replacement(original, GatewayError),
// sse_connected(), sse_lagged(n), stdio_busy(id), origin_forbidden(OriginRefusal).
// GatewayError and OriginRefusal are closed enums. Their text is rendered inside
// outbound.rs from fixed strings, and no constructor takes a String or a Value.
// A backend-derived diagnostic (for example a backend error message) is a
// Delivered frame and is judged.
pub(crate) fn judge_frame(reads: &ReadHistory, guard: &TenantGuard, key: Option<&str>,
    payload: Payload, origin: FrameOrigin<'_>) -> OutboundFrame
// sinks, all private to outbound.rs: to_http(OutboundHttp) -> Response,
// sse_event(OutboundFrame) -> String, stdio_write(&mut W, OutboundFrame) -> bool
// Stream frames also carry SseMeta { event: &'static str | backend event type,
// id: Option<String> }, so sse_event keeps connected / message / lagged /
// webhook event names and Last-Event-ID (streaming.rs:487-524).
```

`judge_frame` is the only constructor of `OutboundFrame`. Only the sinks in
`outbound.rs` can consume one, and there is no `into_parts`, so judged content
cannot be detached and changed. `OutboundHttp` does not implement
`IntoResponse`. Each frame records the `caller_key` it was assessed for. A
sink accepts it only if that key equals the key bound to its destination:
the stream's key, the stdio constant, or the callback subscription's
principal. A mismatch is a debug assertion and, in release builds, a drop
with a `tenant_read` rejection. A frame judged for one principal can
therefore never be written to another's stream. `judge_frame` is public
only through `delivered(..)`, which
sets the `Delivered` origin, and through the fixed `Gateway` constructors
listed above. Every MCP body, SSE event and stdio write takes an
`OutboundFrame`, so a path that skips the judge does not compile. These move
into `outbound.rs` and become private:

- the response helpers (helpers.rs:18-128);
- `create_sse_response` and `subscription_stream` (streaming.rs:466-601),
  with their `Event` yield loops, so `streaming.rs` needs no `Event`
  allowlist entry;
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
     (REL:tenant_guard.rs:181-212, with strings at :209). The projection is a
     **deny-list**: the walk covers the whole emitted document of every
     payload variant, minus only the top-level `jsonrpc` and `id`. It
     therefore covers notification and request `method` strings, which a
     backend controls; webhook, proxy and event bodies; callback `data`; and
     the `SseMeta` event name and SSE id. A new field or a new variant is
     scanned by default, so there is no allow-list to keep in sync. Excluding
     `id` keeps refusal construction terminating (test 2g).
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
| H3 | `slot_http` replacement (grant_audit.rs:303-323) | grant-audit failure answer | Takes and returns the full `OutboundReply`: `Stream` (listen) passes through unchanged, and only the `Http` arm can be replaced, by `replacement(original, GatewayError::AuditUnavailable)`, which drops the ticket. Re-parsing the body (:309-313) goes away, because the id is on the typed frame |
| H4 | `meta_mcp_handler` (handlers.rs:443-472), buffered arm :466-470 | POST answer without SSE | The single entry. After `slot_http` it calls `outbound::emit_http`, which writes the delivery event, builds the body and commits |
| H5 | `first_event_wins_stream` (streaming.rs:812-874): `message_frame` :762, `terminal_frame` :783, yields at :838, :845, :854, :857 | POST-SSE notifications and the terminal answer | The notification channel carries `OutboundFrame` (judged in `publish`, stream scopes only, §4.3); the terminal frame is `OutboundHttp`; each yield goes through the private `sse_event` sink and commits. `message_frame`, `terminal_frame` and `UNFRAMEABLE_FRAME` (streaming.rs:762-797) move into `outbound.rs` |
| H6 | `request_scoped_event_stream` (streaming.rs:711-759), notification loop :736, result bytes :729 | dispatch-first fallback: drained notifications, then the result | Takes `Vec<OutboundFrame>` plus `OutboundHttp`, not bytes. This is the round-6 CRITICAL path |
| H7 | `create_sse_response` (streaming.rs:466-529): events at :487, :498, :502, :521. Fan-out via `send_to_session`, `broadcast` and `broadcast_to_backend` (:381, :401, :304) from proxy.rs:250-559 and webhooks/mod.rs:605 | GET session stream: notifications and server-to-client requests | Judged at enqueue, per session, in all three fan-out functions, with that session's stored `caller_key`. The payload is clamped (`clamp_response_envelope`, cacheable.rs:160-168) before judging, and `sse_event` only serializes it. The `message_event_data` re-clamp and clone at yield (streaming.rs:498-500) goes away. `Refused` completes a request's waiter (proxy.rs:153-201). The ticket stays live until emission (§4.5). `connected` and `lagged` come from fixed `Gateway` constructors |
| H8 | `subscription_stream` (streaming.rs:540-600), ack :556, events :579 | `subscriptions/listen` | Dispatch returns `OutboundReply::Stream`. Each listener event is judged with the `caller_key` captured at open (handlers.rs:1089), before the yield, and emitted through `sse_event` |
| H9 | Direct route `Answer` (direct_audit.rs:23); `build_http_response` / `build_http_error_response` (helpers.rs:111-128); `audited_call` single return (direct_audit.rs:114-118) | every `/mcp/{name}` answer | `Answer` becomes `OutboundHttp`, judged in `audited_call` for every method. Its notifications are drained and discarded (backend_handlers.rs:425-430) |
| H10 | http_error.rs:12-19 `json_body` / `json_response` | plain HTTP errors | Kept for non-MCP bodies; an MCP use moves to H1 |
| H11 | origin middleware `forbidden` (origin_guard.rs:416-424), returned at :408 | JSON-RPC `-32600` refusal before authentication | Built by an `outbound.rs` constructor as `judge_frame(.., key: None, Gateway)` and written through `to_http`. No key exists before authentication; a `Gateway` frame is never refused |
| H12 | `jsonrpc_error_body` (http_error.rs:40) via `jsonrpc_error_response` (middleware/errors.rs:33-42), for example `circuit_open_response` (:28-30) | middleware JSON-RPC errors | Built by `outbound::gateway_error` and written through `to_http` |
| H13 | GET `/mcp` refusals: `get_era_refusal` (handlers.rs:157-197, returned at :211-212), the owner refusal (:218), and `build_http_error_response` (:222, :238) in `mcp_sse_handler` (:200-205) | GET-stream refusals | `mcp_sse_handler` returns `OutboundReply`. Each refusal is an `outbound::gateway_error(..)` `Http` frame, and the era refusal's `Allow` header is set inside `outbound.rs`. The handler can then be registered through `mcp_route` |
| S1 | stdio batch array (server/mod.rs:2568) | batch answers | `Payload::Batch` of individually judged frames. `stdio_write` serializes the array inside `outbound.rs` and commits every item's ticket after the array is written |
| S2 | stdio busy refusal, `try_send` (server/mod.rs:2588-2600) | overload refusal | `outbound::stdio_busy(id)` builds the frame; `try_send` takes an `OutboundFrame` |
| E1 | MIK-7630 event deliveries to HTTPS callbacks, designed in docs/design/2026-10-01-mik-7630-mcp-events.md:300-312 (scope-update.md:165-167), not yet in source | event `data` delivered to the subscription principal | The sender takes an `OutboundFrame` built by `outbound::callback_frame` (`Payload::Callback`, `Delivered`) with the subscription principal's `caller_key`, on the same process `Arc<ReadHistory>` rather than an events-own window. Attribution is captured before the event firewall's redaction and carried on the outbox record (§4.4). **The ticket commits when the finalized body is handed to the HTTP client for sending,** whatever the response status, because a recipient can read the body and then fail. A send that never leaves the process (DNS or connect refused before any byte is written) releases without committing. A block dead-letters with reason `tenant`, and the rejection audit is that design's SAFETY.2 attempt record, written through `append_bounded` |

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
`axum::body::Body::from` and `axum::body::Body::from_stream` (today's POST-SSE
builder, streaming.rs:864) outside `outbound.rs` and a named non-MCP allowlist,
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

- **Request-scoped notifications.** Both delivery paths, the batched
  `publish` (transport/notification_sink.rs:109) and the backend-reader
  `DeliveryHandle::deliver` (:191, which snapshots the sink), end in one
  funnel: `send_or_count` (:131-134; the comment at :124-129 states this). The
  sink channel becomes `mpsc::Sender<OutboundFrame>`, so `send_or_count` is
  where `judge_frame(.., Delivered{request: None, hidden: None})` runs. The
  guard, `caller_key` and mode travel with the scope, including into the
  `DeliveryHandle` snapshot. The mode is `NotificationScope::{Stream,
  Discard}`.
  - `scope` (:64) is `Stream`. The H5 stream and the H6 fallback consume the
    frames and commit as they write.
  - `collect` (:86) is `Discard` by construction. That covers both of its
    production sites: the buffered POST arm (handlers.rs:466-470) and the
    direct route's `dispatch_in_scope` (backend_handlers.rs:449), whose
    notifications are discarded. In `Discard` mode `send_or_count` drops the
    notification before judging it, so a frame that is never written reserves
    nothing.
- **Session-stream items** (H7). These come from proxy.rs (sampling and
  elicitation, :226-420; list-changed, :482) and webhooks (webhooks/mod.rs:605),
  and are judged at enqueue (H7) with the session's stored key. In block mode
  a notification is not enqueued, and a request makes `send_to_session`
  return `Refused`, so the proxy completes its pending waiter with a
  `Gateway` refusal (proxy.rs:153-201) rather than waiting for a timeout. The
  ticket follows the single lifecycle rule in §4.5.
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
- **Before transformations.** A webhook's attribution is taken from the raw
  inbound payload, before `transform_payload` (webhooks/mod.rs:574-606) maps
  or drops fields. A MIK-7630 event's attribution is taken before the event
  firewall's redaction (SAFETY.1, scope-update.md:165). Either way it is
  carried privately on the frame, and for events on the outbox record. An
  outbox record or stored frame without it restores `U`.
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
the `Arc` once. `response_firewall` passes it to both as a **required**
`Firewall::from_config(cfg, tracker, reads: Arc<ReadHistory>)` argument
(today `from_config(fw_cfg, tt)` at server/mod.rs:519-520), so no
constructor call can build a second window. It is also held on `AppState` for the stream
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

**Ticket lifecycle: one rule.** A ticket's reservation stays pending until
its last copy is written or dropped. Every copy-write refreshes the tenants'
last-seen time in `committed`. Only the write of the last copy, the moment
the `Arc` strong count reaches zero after a write, releases the pending
counts. If the last copy is dropped unwritten instead, the counts are released
with no commit, unless an earlier copy was written, in which case that write's
last-seen time stands. There is no first-write commit.

This applies to every frame:
- a single-copy frame (POST answer, stdio frame), whose one write is its last;
- POST-SSE notifications;
- GET-stream copies held in several subscribers' broadcast buffers, where a
  `Lagged` overwrite drops a copy.

A shared ticket is an `Arc` (one allocation, on the configured path only).

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
4. Take the principal's `DashMap` entry (`entry().or_default()`) and hold
   that one guard across steps 4 and 5. Count `distinct` over committed,
   pending, overflow, the frame's tenants and a fresh `U`. `distinct > 1`
   gives `Flagged` or `Blocked`.
5. Still under the same guard, unless `Blocked`, reserve the frame's entries
   under a ticket. Two concurrent stateless reads, A and B, under one key
   therefore serialize on the entry, and the second one sees the first's
   reservation.

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

**Rejection audit.** Some blocked frames are never written: a blocked
notification is not enqueued, and a blocked bridged request resolves its
waiter (H7; stdio `send_request`).

The synchronous `judge_frame` does no I/O. It returns `RejectionEvidence`:
the verdict and the hashed denied tenants, never the content. The audit
goes through the existing bounded asynchronous boundary, `append_bounded`
(security/transparency_log_bounded.rs:99), which also bounds the invocation
and delivery-event writes. There are two cases:

- **Async producers** (the proxy's `forward_*_with_response`, stdio
  `send_request`, the callback sender) await `append_bounded` before they
  complete the waiter or dead-letter.
- **Sync producers** (`send_or_count`, notification_sink.rs:131-134) hand the
  evidence to one detached `append_bounded` task. That allocates only on
  rejection, and the producer is never blocked on audit I/O.

A failed or timed-out append is logged. It changes nothing the caller
receives, because the content is already withheld, and the waiter's refusal
goes out regardless.

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
  compared with today's path. On the configured path, lock acquisitions are
  counted per phase:
  - assess plus reserve: one;
  - each copy-write refresh: one per copy (fan-out to n subscribers costs
    n);
  - last-copy release or drop: one;
- a `criterion` bench row runs `judge_frame` on and off;
- lock accounting covers the whole shared-ticket lifecycle: cloned tickets,
  repeated copy-writes, last-copy commit, and last-copy cancellation;
- the NFR.WORKLOAD.1 k6 run (tests/load/k6_gateway.js) runs twice, once with
  the default config and once with `arg_keys` set in observe mode, at the tip
  before merge.

**Cost gate (blocks implementation past the red tests).** NFR.WORKLOAD.1 is
already about 19 µs per call over budget, and the deny-list walks every
field. `judge_frame` is therefore priced before any implementation lands
beyond rows 1-6 of the red-test order (§6.1).

- **Harness:** the `criterion` suite `benches/gateway_benchmarks.rs`
  (Cargo.toml:293-295, `harness = false`). New groups sit beside the
  existing per-path checks it already prices: `bench_mcp_frame` (:232),
  `bench_input_scanner` (:259) and `bench_redactor` (:310).
- **Groups:** `judge_frame/{off, configured_no_tenant, configured_one_tenant,
  configured_uninspected}`, over a 2 KB `tools/call` result, a 64 KB result
  with JSON in text, and a notification. The baseline is today's per-path
  attribution, `response_tenants` + `response_uninspected` (two walks).
- **Pass threshold:**
  - At the default config (`arg_keys` empty), zero added p50: within the
    `criterion` noise band of a plain move, and zero allocations or locks
    (test 2).
  - With `arg_keys` set, a stated per-call cost, recorded in the PR: the
    p50 for the 2 KB and 64 KB cases. It must not exceed today's two-walk
    baseline plus one shard lock. The deny-list walk replaces the two walks
    rather than adding to them.
- If either threshold fails, implementation stops at the red tests and the
  lane reports to the lead.

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
  - `a_then_b_webhook` (B only in the raw webhook body, mapped away by the
    transform);
  - `a_then_b_proxy_request` (B in a sampling envelope);
  - `a_then_b_event_callback` (B in event `data`, redacted before sending);
  - `a_then_b_method_string` (B in a backend notification `method`);
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

### 6.1 Red-test order

1. `dispatch_first_post_b_notification_after_a_result` (row 1):
   src/gateway/streaming_request_scoped_tests.rs.
2. `concurrent_stateless_and_two_sessions_one_key` (row 2):
   src/gateway/router/tests/tenant_reads.rs (new).
3. `meta_and_direct_share_history` (2b): same new file.
4. `delayed_subscriber_copy_fails_closed` (2i):
   src/gateway/streaming_tests.rs.
5. `webhook_and_event_scan_root` (2x): src/gateway/webhooks/tests.rs, plus
   the MIK-7630 lane's events tests.
6. `judge_frame` cost bench (2z): benches/gateway_benchmarks.rs. This is
   the cost gate above.


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
| 2i | `delayed_subscriber_copy_fails_closed` | Two subscribers under one key: one fast, one stalled. A is written to the fast one; the window passes; B is judged while the stalled A copy is pending: B flagged. The stalled A write then refreshes last-seen, and only it releases the pending counts. A `Lagged` drop of the last copy releases without a commit | first-write commit; commit time taken at enqueue |
| 2j | `stdio_batch_items_judged` | a stdio batch answering A then B: B item flagged/refused, the array written once, all tickets committed after the write | the batch as `Request(Value)` or unjudged |
| 2k | `listen_is_a_stream_reply` | `subscriptions/listen` returns `OutboundReply::Stream`; its B event after A is flagged | listen kept on `Event::data` |
| 2l | `event_hash_is_after_slot_http` | a `slot_http` failure after a judged A answer: the delivery event hashes the refusal that was sent and carries A's original assessment | event written before `slot_http` |
| 2m | `terminal_audit_failure_terminates` | a logger that always fails under `FailClosed`: exactly one refusal is written, after one replacement-audit attempt | recursive replacement audit |
| 2n | `gateway_constructors_closed` | compile-fail (trybuild): a backend payload cannot be given a `Gateway` origin; `OutboundFrame` cannot be built outside `outbound`; a route handler returning a `Response` cannot be registered with `mcp_route` | the origin or a constructor made public |
| 2o | `middleware_errors_through_outbound` | the circuit-open and busy refusals come from `outbound` constructors (H12, S2) | `jsonrpc_error_body` kept raw |
| 2p | `broadcast_to_backend_judged_per_session` | list-changed fan-out to two keys: each judged with its own key | one judged frame reused across keys |
| 2q | `sse_bytes_equal_judged_payload` | GET-stream message bytes equal the judged, clamped payload, with no second clamp | `message_event_data` at yield |
| 2r | `gateway_text_is_closed` | compile-fail: `gateway_error` and `origin_forbidden` reject a `String`; a backend error message is a `Delivered` frame and is judged | a constructor taking free text |
| 2s | `rejection_is_audited` | a blocked notification and a blocked bridged request each write one `tenant_read` event (blocked, `h(B)`) before discard or waiter resolution; under a failing logger the waiter still gets its refusal | no audit on rejection |
| 2t | `direct_notifications_discarded_unjudged` | a backend notification naming B on `/mcp/{name}` after A: no flag, no reservation | `collect` judging |
| 2u | `reader_task_deliver_is_judged` | a subprocess-reader notification via `DeliveryHandle::deliver` naming B on a POST-SSE stream after A: flagged, with the scope's key | `deliver` bypassing the judge |
| 2v | `events_share_history` (with MIK-7630) | A via `tools/call`, then an event delivery naming B to the same principal's callback: flagged (observe) or dead-lettered `tenant` (block) | events with their own window |
| 2w | `sse_meta_preserved` | `connected`, `lagged` and webhook event names and `Last-Event-ID` unchanged after the move | `SseMeta` dropped |
| 2x | `webhook_and_event_scan_root` | B only in a webhook body that `transform_payload` drops, in a `proxy_request` envelope, in event `data`, or in a notification `method`, each after A: flagged (block: not delivered, or dead-lettered) | allow-list projection; attribution taken after the transform |
| 2y | `callback_commits_at_send` | a callback recipient that reads A and returns 410, then B: flagged. A connect refusal before any byte: A not committed | commit on 2xx |
| 2z | `judge_frame` cost bench (cost gate) | §4.8 thresholds on benches/gateway_benchmarks.rs | per-frame work on the fast path; deny-list cost above the two-walk baseline |
| 2aa | `slot_http_passes_stream` / `get_refusals_typed` | listen survives `slot_http` as `Stream`; GET era, owner and streaming-off refusals are `outbound` frames (compile-time via `mcp_route`) | `slot_http` typed on `OutboundHttp` only |
| 2ab | `frame_bound_to_destination_key` | a frame judged for key K offered to a writer bound to K' is dropped with a `tenant_read` rejection | no key binding |
| 2ac | `rejection_audit_never_blocks_producer` | a stalled transparency log: `send_or_count` returns at once, and the waiter gets its refusal within the `append_bounded` bound | synchronous audit in the judge |
| 2ad | `firewall_requires_read_history` | compile-fail: `Firewall::from_config` without an `Arc<ReadHistory>` | optional builder |
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
| Refusal loop on a JSON id (HIGH) | Fixed: `id` and `jsonrpc` are never scanned (`method` is scanned since round 4), and `Gateway` frames are never refused. Test 2g |
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

### Review dispositions (C design, round 3)

| Finding | Disposition |
|---|---|
| First-write commit contradicts the last-copy reservation (CRITICAL, HIGH) | Fixed: one lifecycle rule (§4.5); first-write commit removed everywhere. Test 2i now has a fast and a stalled subscriber |
| Message-taking `Gateway` constructors (CRITICAL) | Fixed: closed `GatewayError` / `OriginRefusal` enums rendered in `outbound.rs`; backend diagnostics are `Delivered`. Test 2r |
| Blocked notifications and requests unaudited (HIGH) | Fixed: rejection audit (§4.7). Test 2s |
| MIK-7630 event deliveries unjudged (HIGH) | Fixed by routing: E1 on the shared `ReadHistory` (mik-7630-mcp-events.md:300-312 already makes each delivery a MIN.2 read). Test 2v |
| Direct notifications judged (MEDIUM) | Fixed: `collect` is `Discard` at both sites (handlers.rs:466-470, backend_handlers.rs:449). Test 2t |
| `scan_response` cited but absent (improvement) | Partly refuted: it is present on the release line at REL:tenant_guard.rs:181 (`walk_response` :190-212). This worktree's older base has `texts()` at :184, and §2 now says so |
| Other improvements | Taken: `DeliveryHandle::deliver` covered through `send_or_count` (notification_sink.rs:131-134, :191); full ticket-lifecycle lock accounting; `SseMeta` for event type and id; k6 with `arg_keys` set |

### Review dispositions (C design, round 4)

| Finding | Disposition |
|---|---|
| Projection omits webhook, callback and SSE metadata, and method strings (CRITICAL, both seats) | Fixed: a deny-list over the whole emitted document minus `jsonrpc`/`id`, and new `Event` / `Callback` payloads (§4). Tests 2x, corpus rows |
| Attribution lost through webhook transform and event redaction (CRITICAL) | Fixed: taken before `transform_payload` (webhooks/mod.rs:574-606) and before redaction; carried on the frame and the outbox record; `U` when missing (§4.4) |
| Callback commits on 2xx (CRITICAL) | Fixed: commits when the body is handed to the HTTP client, and released only if nothing left the process (E1). Test 2y |
| Rejection audit in the sync judge (HIGH) | Fixed: the judge returns evidence; the audit goes through `append_bounded` (transparency_log_bounded.rs:99), awaited by async producers and detached for `send_or_count` (§4.7). Test 2ac |
| `slot_http` cannot carry `Stream` (HIGH) | Fixed: `slot_http` takes `OutboundReply`; `Stream` passes through (H3). Test 2aa |
| GET refusals still raw `Response` (HIGH) | Fixed by routing: H13 (handlers.rs:157-244), so the handler returns `OutboundReply`. Test 2aa |
| Improvements | Taken: entry held across count and reserve; `create_sse_response` / `subscription_stream` moved into `outbound.rs`; `Arc<ReadHistory>` a required `from_config` argument (2ad); clippy covers `Body::from_stream` (streaming.rs:864); per-phase lock accounting with per-copy refresh; frame-to-destination key binding (2ab); webhook, proxy and event rows in the corpus and tests |

### Design freeze (lead rule)

This is the last design round. From here, any finding becomes a red test and
is fixed in implementation. Only a new path that sends an MCP frame outside
`OutboundFrame` reopens the design. Implementation starts with §6.1, and
it does not pass the red tests until the cost gate (§4.8) has passed.
