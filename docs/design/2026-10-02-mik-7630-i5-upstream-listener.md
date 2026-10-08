# MIK-7630 I5 — the upstream listener (detailed design)

Status: implemented in #2767 (`src/events/upstream_listener.rs`,
`src/events/upstream_session.rs`); the text below is the design as reviewed.
Parent: `docs/design/2026-10-01-mik-7630-mcp-events.md` (§3.3 b2, §4, §11 I5, row T39).
Depends on: I2 (outbox, fan-out, `EventsHub::emit`) and I4 (the refcounted
`on_first_subscriber` / `on_last_subscriber` hooks and the `BackendNotification`
source that carries b1). I5 adds b2 to that source; it adds no new send site.

Where this document and the parent disagree, this one wins for I5, and the
parent's §3.3 gets a pointer here when I5 merges. The disagreements are listed
in §11.

## 1. What I5 delivers

Three event types per eligible backend `x` (§6 says which are eligible):

| Event | Argument | `data` | Upstream notification |
|---|---|---|---|
| `backend.x.resource_updated` | `uri` (required, exact) | `{"uri": <uri>}` | `notifications/resources/updated` |
| `backend.x.resources_changed` | none | `{}` | `notifications/resources/list_changed` |
| `backend.x.prompts_changed` | none | `{}` | `notifications/prompts/list_changed` |

`data` is built by the gateway from the one field it needs. Nothing else the
backend sends (`_meta`, `title`, extra keys) is copied, so the firewall scan in
I2 sees at most a URI.

The connection that receives these notifications is opened only while at least
one live event subscription needs it, and closed when the last one goes.

## 2. Sources of truth (read at base `d80e2cfd2`)

Spec, MCP 2026-07-28 `basic/patterns/subscriptions` (fetched 2026-10-02):

- `subscriptions/listen` "replaces the former `resources/subscribe` RPC and the
  HTTP GET endpoint". The filter is `params.notifications` with
  `toolsListChanged`, `promptsListChanged`, `resourcesListChanged` (booleans) and
  `resourceSubscriptions` (URI list).
- "The server MUST send `notifications/subscriptions/acknowledged` as the first
  message", tagged `_meta["io.modelcontextprotocol/subscriptionId"]` = the listen
  request's JSON-RPC id, and its `notifications` field "reflects the subset the
  server agreed to honor".
- Every notification on the stream carries the same tag. On stdio "clients MUST
  use this field to correlate".
- A JSON-RPC **response** to the listen request means the server ended the
  subscription gracefully; a transport close without one is a disconnect.
- Client cancel: close the SSE stream (HTTP), or send `notifications/cancelled`
  naming the listen request id (stdio).
- "On stdio, if the connection is terminated and then re-established, the client
  MUST re-send `subscriptions/listen`."

Code:

- No transport delivers an out-of-request notification anywhere. stdio drops it
  (`src/transport/stdio.rs:538-540`, "Ignoring peer notification"); WebSocket
  the same (`src/transport/websocket.rs:497-513`, `route_progress`). HTTP request SSE stops at the
  first response frame (`src/transport/http/sse_decoder.rs:246-297`), and the
  legacy GET is read only up to the `endpoint` event and dropped
  (`src/transport/http/mod.rs:1188-1290`).
- `SseDecoder` (`sse_decoder.rs:66`, `push`/`finish`) parses frames
  incrementally with a byte cap. I5 reuses it with a smaller cap.
- The gateway never sends `subscriptions/listen` or `resources/subscribe`
  upstream. The direct route `/mcp/{name}` forwards a client's own
  `resources/subscribe` and discards what comes back
  (`src/gateway/router/backend_handlers.rs:431,449`).
- Era: `Backend::cached_era()` (`src/backend/era.rs:136`), resolved once per
  start for every transport. WebSocket backends are legacy only
  (`src/config/ws_backend.rs:37`).
- Idle stop refuses while the shared slot's `in_flight > 0`
  (`src/backend/pool.rs:712`). `begin_internal_activity()` (`pool.rs:670`) takes
  such a lease without touching the idle clock. `force_restart` closes a busy
  slot's old transport only when its `Arc` strong count reaches one
  (`src/backend/lifecycle.rs:918-930`, `close_after_last_owner`). No hook
  announces a start, restart or stop.
- Resource access on `/mcp`: no per-URI policy exists. `resources/read` is
  allowed when the caller may reach the backend **and** the URI is in the
  catalogue that caller is served (`find_resource_owner`,
  `src/gateway/meta_mcp/resources.rs:452`; exact match, templates not matched).
  The catalogue admission is `catalogue_credential_for`
  (`src/gateway/meta_mcp/discovery_fetch.rs:143`).

## 3. Per-era handling

One listener per backend, holding the **union** of what that backend's live
event subscriptions need: a set of kinds (`resources_changed`,
`prompts_changed`) and a refcounted set of URIs. The way it talks upstream
depends on the transport and on `cached_era()` read at each (re)connect:

| Backend | Era | Upstream channel | Resource interest | Close |
|---|---|---|---|---|
| HTTP, `streamable_http: true` | Modern | `POST subscriptions/listen`, SSE body read until it ends | `resourceSubscriptions` in the filter | drop the body stream |
| HTTP, `streamable_http: true` | Legacy | `GET` on the base URL with `Accept: text/event-stream` and the shared bucket's `Mcp-Session-Id` (a new `HeaderMode::SessionStream`; the existing `HeaderMode::Sse` deliberately omits the session, `http/mod.rs:1078`) | `resources/subscribe` per URI on that same session | `resources/unsubscribe` per URI, then drop the GET |
| stdio | Modern | `subscriptions/listen` written as a request; the reader routes frames tagged with its id to the listener | `resourceSubscriptions` in the filter | `notifications/cancelled` naming the listen id |
| stdio | Legacy | the reader's out-of-request notifications | `resources/subscribe` per URI | `resources/unsubscribe` per URI |
| WebSocket | Legacy only | as stdio legacy | as stdio legacy | as stdio legacy |
| HTTP without `streamable_http: true` (the SSE handshake path, `http/mod.rs:765`), A2A | — | none: no b2 descriptors (§6) | — | — |

**Filter changes.** Modern: the filter is fixed per listen request, so a change
(first subscriber of a new URI or kind, last subscriber of one) opens a new
listen with the new filter, waits for its acknowledgement, then closes the old
one (make before break). Overlap rule: while both are open, frames from
**both** are accepted, and the old stream is drained until it ends. Nothing
is lost to the switch; a change sent on both streams may be emitted twice if
the copies fall in different coalescing windows. That is the chosen trade: a
change event means "re-read the resource", so a duplicate costs one extra read
and a gap costs a missed change. Legacy: one
`resources/subscribe` or `resources/unsubscribe` on the existing channel; the
list-changed kinds need nothing upstream, they are filtered locally.

**Legacy HTTP session order.** A session-bound GET must name a session that
exists, so the listener first makes one request on the shared bucket
(`resources/subscribe` for the first URI, or `resources/list` when only list
kinds are needed), then opens the GET with the bucket's `Mcp-Session-Id`, or
without one when the backend assigned none (sessionless servers are
conforming). A 404 on the GET or on a subscribe means the session expired:
the transport re-establishes it as it does today for requests, and the listener
reopens the GET and re-sends the whole URI set.

**Acknowledgement (modern).** The first frame tagged with the listen id must be
`notifications/subscriptions/acknowledged` within 10 s, or the attempt fails.
A kind or URI the acknowledgement omits is recorded as unsupported for that
backend (counter + one `warn` per change of the acknowledged set); the listener
stays open for what was honoured and does not reconnect to retry the omission.
A peer that acknowledges with a JSON-RPC success response as its first frame
is accepted as acknowledged with the full filter only in the exact shape this
gateway sends today (§11): `id` equal to the listen id, a result holding only
`_meta` with that subscription id, and no `resultType: "complete"`. Any other
response, and any later response, is the graceful end; a first-frame response
in that shape is the acknowledgement only and does not end the stream. This
keeps a gateway behind a gateway working without a reconnect loop.

**Request shape (modern).** The listen request carries the modern
`_meta` envelope (`protocolVersion`, `clientCapabilities`; `clientInfo` is deliberately omitted, `http/mod.rs:422`) the
transport already adds to every 2026 request (`with_modern_meta`,
`http/mod.rs:430`); the mock peers refuse a listen without it.

**Legacy refusals.** `resources/subscribe` answered `-32601` (or the backend
lacks `resources.subscribe`) marks that backend's resource interest
unsupported; list-changed delivery continues. A `GET` answered 405 marks the
whole backend unsupported until its next restart.

**Tagged frames only.** On a modern stream every notification must carry the
listen id; an untagged or wrongly tagged frame is dropped and counted. Only the
three methods of §1 (plus the acknowledgement) are accepted; anything else is
dropped. A `notifications/resources/updated` whose `uri` the listener did not ask
for is dropped before it reaches the hub.

## 4. Transport additions

Two new methods, on a crate-private side trait `UpstreamListen` (in
`src/transport/upstream_tap.rs`), **not** on the public `Transport` trait
(ruling B, lead, 2026-10-02: no public API widening, so `UpstreamNote`,
`KindSet` and the other tap types stay `pub(crate)`). `StdioTransport`,
`WebSocketTransport` and `HttpTransport` implement it; A2A and any other
transport do not, and §6 eligibility never reaches them, so no refusing default
and no new `Error` variant is needed:

```rust
/// Open `subscriptions/listen` with `filter` and yield every frame of that
/// subscription until it ends. Dropping the stream cancels it upstream.
async fn listen(&self, filter: Value) -> Result<FrameStream>;

/// The peer's out-of-request notifications (legacy peers): the reader-loop tap
/// on stdio and WebSocket, the session GET stream on HTTP.
async fn unsolicited(&self) -> Result<FrameStream>;
```

`FrameStream` is a bounded `tokio::sync::mpsc::Receiver<UpstreamNote>`
(capacity 64) plus a drop guard that performs the cancel of §3. The channel
never carries a backend frame; the producer classifies and projects first:

```rust
enum UpstreamNote {
    /// The acknowledgement, already intersected with what this listen asked
    /// for, so its size is bounded by the gateway's own URI budget.
    Ack { kinds: KindSet, uris: Vec<String> },
    /// One of the three §1 notifications; `uri` only for `resource_updated`.
    Notice { kind: Kind, uri: Option<String> },
    /// A validated terminal response to this listen (graceful end).
    End,
}
```

The subscription id is checked by the producer against the locally minted
listen id and not carried; a legacy frame never has one.

- **HTTP.** Both methods clone the transport's own `reqwest::Client`, so the
  backend's destination pinning and redirect policy apply unchanged, and run
  the body read on a spawned task that holds no `Arc` of the transport. The
  transport owns a cancellation token those tasks select on, and `close()`
  cancels it, so a restart or stop ends the streams at once instead of waiting
  for the server or the hourly recycle.
  Headers come from `build_mcp_headers` (+ `finalise_modern_headers` for
  `listen`), shared bucket only (`identity_key = None`). The body is decoded
  with `SseDecoder::new(64 KiB)`, not the 10 MiB request cap: a notification
  is small, and a frame over the cap ends the stream (and reconnects). The
  client's total timeout would cut a long stream, so these requests set a
  per-request timeout of 1 h: the stream is recycled hourly. Modern recycles
  make before break. Legacy keeps one GET at a time (a legacy server sends each
  message on one stream only, so two GETs would split them): the recycle is an
  ordinary reconnect with a gap of one round trip, inside the emit-only
  contract. The session's subscriptions are server-side, so nothing is re-sent
  unless the session expired.
- **What crosses a channel.** Only `UpstreamNote`. A `Notice` whose `uri`
  exceeds 2 048 bytes is dropped and counted, so 64 queued notes stay small
  whatever the backend sends.
- **stdio / WebSocket.** The reader loop gains one routing step before the
  "Ignoring" arm: a frame tagged with a registered listen id goes to that
  listen's sender; otherwise one of the three §1 methods goes to the
  `unsolicited` sender if one is registered. Both sends are `try_send`: the
  reader is the only reader of the peer's output and must never park
  (the rule `capture_notification` already follows); a full channel drops and
  counts. The senders live in the reader task's state, so the receiver sees
  `Closed` when the process exits or the socket drops. `listen` writes the
  request with a minted id from the transport's own id counter and does **not**
  register it as a pending request, so no request timeout fires on it; a
  response with that id ends the listen: the reader `try_send`s `End` and then
  removes the listen's sender whether or not `End` fit, so a full channel
  still reports the end as `Closed`.

**Reaching the side trait (ruling B).** The backend slot already builds the
concrete transport before erasing it to `Arc<dyn Transport>`
(`src/backend/lifecycle.rs`, the `match &self.config.transport` arms). It keeps
a second handle in the pool entry, `Option<Weak<dyn UpstreamListen>>`, set in the
same write as `entry.transport` for the three implementing arms and `None` for
anything else. It is a `Weak`, not an `Arc`, so the slot's strong count stays
one and `close_after_last_owner`'s wait on `strong_count > 1` (restart, stop,
failed replacement startup) is unchanged: the extra handle can never keep a
retired transport alive. The listener upgrades it only for the duration of one
`listen`/`unsolicited` call, under the same lock that `ensure_entry_started`
takes, and drops the upgraded `Arc` as soon as the stream is open (the stream's
tasks hold no `Arc` of the transport, §4 HTTP and stdio/WebSocket). A failed
upgrade means the transport is gone and is treated as a restart (§5). The
WebSocket arm today
receives an already-erased `Arc` from its start helper: the crate-private
helper returns the concrete `Arc<WebSocketTransport>` (the public `start`
keeps its return type through coercion), so the arm can build both handles.
Consequences: no
downcasting, no `Any`, no public item added; a transport added later is
ineligible until its arm sets the field; and a test double implements the side
trait directly. The transport-side pieces (`upstream_tap.rs`, the reader tap
step, `http/listen.rs`) are unchanged by the ruling, apart from the two
methods moving from the `Transport` impl blocks to `UpstreamListen` impl blocks.

These are the only changes to `src/transport/`. Progress routing, the
request-scoped sink and every existing request path are unchanged.

## 5. Lifecycle and refcount

**Ownership.** `src/events/upstream.rs` (new) owns an `UpstreamListeners` map
`backend name → ListenerHandle`. I4's `BackendNotification` source (the one
source of that `SourceKind`, since I2's fan-out looks sources up by kind) gains
a field pointing at it and delegates the three b2 names to it; b1
(`tools_changed`) is untouched. The backend-facing part, which needs
`pub(super)` items of `crate::backend`, is one new file
`src/backend/listen.rs` exposing a single `pub(crate)` entry point; no
existing item's visibility is widened.

**Refcount.** The core (I4) refcounts subscriptions per `lifecycle_key`
(default: JCS of `[name, arguments]`, shared across principals) and calls the
hooks on 0→1 and 1→0. I5 keeps a second, per-backend count beneath it:

```text
Need(backend) = { kinds: {resources_changed?, prompts_changed?},
                  uris:  map uri → number of live lifecycle keys naming it }
```

`on_first_subscriber(key, …, name, arguments)` parses `(backend, kind, uri)`
from the name and arguments, adds it to `Need`, and, if `Need` went from empty
to non-empty, starts the listener task. `on_last_subscriber(key)` re-parses the
key (it is the JCS of name and arguments, so nothing extra is stored; the
name is split as `backend.` + backend + `.` + one of the three known kind
suffixes, so a dotted backend name round-trips), removes
it, and, when `Need` is empty, stops the task. Each change in `Need` is sent to
the task on a `watch` channel; the task applies it as in §3 (make before break,
or one subscribe/unsubscribe). With the default key two principals subscribing
to the same URI share one lifecycle key, so the backend sees one upstream
subscription for the URI, which is T39's "exactly one".

`on_first_subscriber` never fails because the backend is down: it records the
need and returns `Ok`, as the parent §3.3 says. It fails only for policy
(§7): an ineligible backend, a URI the principal may not read, or the URI cap.

**Restart of the gateway.** The core replays `on_first_subscriber` once per
live key on load (parent §4), which rebuilds `Need` and starts the listeners.

**The task.** One tokio task per backend with a non-empty `Need`:

```text
loop {
  wait for backoff (0 on the first attempt);
  backend = registry.get(name)  // gone → park until Need changes or the key is deleted (F10)
  lease = backend.begin_internal_activity()   // held while connected (below)
  transport = backend.ensure_entry_started(Shared) // in listen.rs; may start a stopped child
  era = backend.cached_era()
  stream = open per §3 (listen | unsolicited + resources/subscribe per URI)
  drop(transport)                             // never hold the Arc across the read
  read frames → coalesce → emit, applying Need changes, until the stream ends
  // each control RPC (a new listen, resources/(un)subscribe) re-acquires the
  // transport through ensure_entry_started for that call only
}
```

**Lease, and why the `Arc` is dropped.** While connected the task holds an
internal activity lease on the shared slot. It keeps the idle reaper from
stopping a backend that has live event subscribers (`stop_if_idle` refuses while
`in_flight > 0`) without moving the idle clock, so the backend is stopped as
usual once the last subscription ends. An event subscription therefore counts
as use of the backend; that is deliberate, and bounded by the subscription TTL
(max 24 h, refreshed by the client). The task does **not** keep the transport
`Arc` while reading: `force_restart` closes a busy slot's old transport only
when its strong count reaches one, so a held `Arc` would keep a wedged process
alive for ever. The read side holds only the `FrameStream`, which closes when
the old process or session dies, and the loop reconnects to the new one.

**Shutdown.** The hub cancels every listener task (one `CancellationToken`)
before backends stop. A task that loses the race finds `ensure_started`
refusing (`stopping` latched) and exits.

## 6. Which backends offer b2 events

A backend offers the three descriptors when all hold:

1. Its transport is stdio, WebSocket, or HTTP with `streamable_http: true`.
   Any other `http_url` backend takes the SSE handshake path
   (`http/mod.rs:765`, whatever the URL suffix); listening there needs the
   handshake GET kept open (§11 D2). A2A has no MCP notifications. Neither
   gets descriptors in 4.0.
2. It has no `identity_propagation` block at all (`required: false`
   included) and is not isolated per caller on the meta route
   (`meta_route_isolation_refused_for_caller`). Both are read from config
   explicitly, not inferred from what an identity-free caller is admitted to.
   The listener runs on the shared slot under the gateway's own upstream
   credential; for such a backend that is not the subscriber's credential, and
   notifications seen under it could name resources the subscriber cannot
   read. Those backends get no b2 descriptors (stated limit, §11 D3).
3. The events source config `sources.backend_notifications` is true (parent §9).

**Refusal, not silence (lead ruling on D2/D3).** A subscription to one of the
three names on a configured backend that fails 1 or 2 answers
`-32014 Unsupported` with `data = {"feature": "backendEvents", "value": <name>,
"reason": <r>}`, `r` one of `sse_handshake_transport`, `a2a_transport`,
`identity_propagation`, `per_user_credential` (a per-user OAuth login or a
personal account on a multi-user gateway, the config form of the meta-route
isolation check). It is answered at step 2 of the subscribe order, only to a
caller who passes the backend's visibility check (anyone else gets `-32011`),
so it cannot probe the config and costs no callback traffic. Account
references are compiled first, so the reason is judged on the configuration the
backend runs with. Shipped ahead of the listener in #2691
(`src/events/upstream.rs`, `tests/mik_7630_events_refusal.rs`). Whether SOURCE.1
("any backend") is met with these named exclusions is an operator decision.

Eligibility is computed from config, not from the backend's runtime
capabilities, so `events/list` never starts a backend. A backend that turns out
not to support a kind is reported as unsupported (§3); its subscriptions
succeed and stay silent, the emit-only contract.

## 7. Security

**Who may subscribe and receive.** `authorize` (called at subscribe and at
every fan-out, parent §4) for a b2 name:

- the principal passes I2's backend admission (`services.admits`, the
  `admits_backend` predicate `events/list` uses); otherwise the name is
  invisible and the core answers `-32011`;
- for `resource_updated`, the `uri` is in the backend's shared resource
  catalogue (`get_resources_for_binding(None, &[])`, the cached list
  `resources/list` serves), by exact match: the same rule `resources/read` on
  `/mcp` applies (`find_resource_owner`). Otherwise `-32012`. URIs reachable
  only through a resource template are refused, as `resources/read` refuses
  them.

Subscribe-time `authorize` reads the catalogue, filling it if needed (it runs
on the subscribe request, bounded by the fill budget). If the catalogue cannot
be read (the backend is down), the subscribe is admitted, as the parent's
offline rule requires (§3.3); if it is read and lacks the URI, `-32012`. The
listener emits no `resource_updated` for a backend until it holds a good
snapshot, so a URI
admitted while the backend was down is checked before any event is sent, and
revoked then if absent: on its first complete snapshot the listener revokes
every live `resource_updated` key whose URI is absent, which frees `Need` and the
URI budget at once instead of at the next occurrence. The fan-out re-check never does: a fill
can start the backend and wait on `resources/list`, and fan-out is one task for
every source, so a slow backend would stall webhook and task events too.
Instead the listener keeps the backend's last successfully read URI set (read
off the fan-out path on connect and after each `resources/list_changed`), and
fan-out reads only that snapshot:

- URI in a successfully read snapshot → deliver;
- no snapshot yet, or the last read failed → skip this occurrence, keep the
  subscription (an error is not absence);
- a successfully read **complete** snapshot that lacks the URI → revoke
  (parent F9). A read cut short by the page cap (`drain_list_pages` reports
  truncation; `LIST_MAX_PAGES = 32`) proves nothing about absence: an absent
  URI is skipped and its subscription kept.

A transient catalogue failure therefore never deletes subscriptions. The
snapshot gates `resource_updated` only; `resources_changed` and
`prompts_changed` carry no URI and are emitted whether or not the catalogue
can be read.

**Keeping the snapshot current.** Whenever a backend has any `resource_updated`
interest the listener asks upstream for `resources/list_changed` too, whether
or not anyone subscribed to `resources_changed` (that event is emitted only
when someone did), re-reads the catalogue on each one, and also re-reads it
every catalogue cache TTL. A re-read after a list change first invalidates the
shared slot's resource cache (`invalidate_if`, `cached_metadata.rs:162`), so
it reaches the backend instead of returning the still-fresh old list. A failed re-read is retried with the listener's
backoff and keeps the previous snapshot, so a removal takes effect at the next
successful read.

**Every attempt, not only fan-out.** The parent design re-runs the access check
before every delivery attempt (§3.2 step 7), `EventSource::authorize` included.
I2's worker checks backend admission only, because `authorize` arrives with
I4. I5 requires the attempt path to call `authorize` (I4 wiring, coordinated
with L8), and b2's `authorize` reads the same snapshot synchronously: URI
absent from a complete snapshot cancels the subscription's pending records.
The parent's binary `authorize -> Result<(), Refusal>` is enough; no defer
state is needed. `matches` returns false while no good snapshot exists (skip,
keep), `authorize` errs only on confirmed absence from a complete snapshot,
and a failed or truncated re-read never replaces a good snapshot's verdict
with a refusal. A record is enqueued only after a good snapshot listed its
URI, so at attempt time a snapshot always exists, and the check (placed in the
worker's dispatch before the record is claimed, `worker.rs:102-118`) is
either Ok or a confirmed revoke.

**What I5 needs from I4** (coordination with L8, stated here so I4 builds it):
`authorize` and `matches` on the trait as in the parent §4, with `authorize`
called at subscribe, at fan-out and in the worker before each claim;
`on_first_subscriber` / `on_last_subscriber` refcounted per `lifecycle_key`
and replayed once per live key on restart; and a way for the one
`BackendNotification` source to delegate the three b2 names to
`src/events/upstream.rs` while keeping b1 its own (a field on that source is
enough; no second source of the same kind).

**Kept out of `SubscriptionRegistry`.** b2 notifications go only to
`EventsHub::emit`; nothing in I5 calls `publish` or `publish_for_backend`, so
a downstream `subscriptions/listen` client never sees them (parent §3.3, T39
last clause). A unit test pins that the listener module has no path to the
registry (it does not import it).

**Payload path.** b2 enters I2's pipeline at `EventsHub::emit` like every
source. Fan-out then applies, unchanged: the per-occurrence access re-check,
the firewall scan of `data` (`ResponseArtifactKind::EventPayload`), tenant
attribution before redaction for the tenant guard, and the single send site.
The tenant verdict is the MIN.2 outbound frame once L1 converts that send site
(MIN.2 row E1); until then I2's observe-only path applies, exactly as for
webhook events. I5 adds no send site, no scan and no tenant logic of its own.
`data` is `{"uri"}` or `{}`, so there is little to scan, but the scan runs
anyway: a URI is backend-controlled text.

**Upstream requests.** The listener sends only `subscriptions/listen`,
`resources/subscribe`, `resources/unsubscribe` and `notifications/cancelled`,
on the shared slot, through the backend's existing transport with its
destination policy. The URIs it sends were already checked against the
backend's own catalogue, so it tells the backend nothing the backend did not
list.

**Limits.**

| Limit | Value | Over it |
|---|---|---|
| URIs per backend listener | 1 024 and 32 KiB encoded (consts) | subscribe answers `-32013`, `data.limit = "upstream_uris"` |
| URI length | 2 048 bytes | `-32602`, `data.field = "arguments.uri"` |
| Listeners | one per eligible backend | — (bounded by config) |
| SSE frame | 64 KiB (twice the URI budget, so an acknowledgement echoing the whole filter always fits) | stream ends, reconnect |
| Tap channel | 64 frames | drop and count |

Per-principal and global subscription caps (I1) already bound how many keys
can exist; the URI cap stops a few principals from making one backend track an
unbounded URI set.

## 8. Backpressure and coalescing

From backend to outbox, no stage blocks the one before it except where
blocking is free:

1. **stdio / WebSocket reader → tap:** `try_send`; full drops and counts
   (per-backend drop counter, §9). The reader never parks.
2. **HTTP body task → listener:** `send().await`. Waiting here only stops
   reading the socket, so TCP flow control pushes back on the backend and
   no memory grows.
3. **Listener → coalescer:** one entry per `(kind, uri)`, at most 2 + 1 024 per
   backend. Window 1 s, trailing edge: the first notification opens the window,
   later ones inside it are absorbed, one event is emitted when it closes. A
   burst becomes one event with at most 1 s of delay, and the event always
   follows the last change it stands for. This is the parent's F11 rule; if
   I4 lands a coalescer for `tools_changed`, I5 uses that one.
4. **Coalescer → hub:** `EventsHub::emit`, I2's non-blocking `try_send` into
   the bounded source queue; a full queue drops and counts there.

So a backend in a notification storm costs the gateway parsing time and at
most `2 + uris` events per second, never memory.

`upstream_id` for the event id (parent §3.6) is a gateway-minted UUID per
emitted event: upstream notifications carry no stable id.

## 9. Failure and reconnect

| Event | What the listener does |
|---|---|
| Backend not running / start fails / circuit open | attempt fails; backoff |
| Stream ends without a listen response, transport error, frame over cap | reconnect after backoff |
| Graceful listen response (modern) | reconnect after backoff |
| No acknowledgement within 10 s | sole stream: close; backoff. Replacement listen during a filter change: drop only the replacement, keep reading the old stream, retry the replacement with backoff |
| `-32601` / 405 / omitted in acknowledgement | mark unsupported (§3); no fast retry |
| Backend restarted (new process or session) | old stream closes; reconnect re-sends the whole `Need` (the spec: the server keeps no subscription state across reconnects) |
| Backend removed from config | the core deletes its subscriptions (parent F10) → `on_last_subscriber` → task stops |
| Hourly recycle | modern: make before break; legacy: ordinary reconnect, one GET at a time; no backoff |
| Backend restarted while the old transport is kept alive for a busy caller | the task holds a `Weak` of the transport it opened on and compares it with the slot's current one every 5 s and on every frame; on a change it drops its stream and reconnects. The `Weak` does not count toward the strong count `force_restart` waits on |

Backoff is jittered exponential, 1 s doubling to a 5 min cap (`backon`, as
`src/failsafe/retry.rs` uses it), reset once a stream has been acknowledged
(modern) or has stayed open 60 s (legacy). Unsupported waits at the cap.

Notifications sent while disconnected are lost: the emit-only contract
(parent F3). Modern filter changes and the modern hourly recycle avoid a
self-inflicted gap (at the price of a possible duplicate, §3); the legacy
recycle and every reconnect have one.

Observability: per backend, plain `AtomicU64` counters beside I2's runtime drop
counters (connected flag, reconnects, drops by reason: `tap_full`, `untagged`,
`unrequested`, `oversize`; unsupported kinds), and one `info` per connect and
disconnect with the era and the reason. A URI value is never logged above
`debug`. No new metrics dependency.

## 10. Test plan (T39, split by era)

All rows drive the shipped binary through the I2 harness
(`tests/mik_7630_events/gateway.rs`, HTTPS receiver `receiver.rs`), so they run
where the receiver rows run (Linux, parent §15). New file
`tests/mik_7630_events_upstream.rs` plus one fixture module
`tests/mik_7630_events/upstream_peer.rs` with three mock peers, each recording
every frame it receives and exposing a `push(notification)` control:

- **HTTP peer** (axum), era by flag: modern answers `server/discover` and
  serves `subscriptions/listen` as an SSE body (acknowledgement first, tagged
  frames after); legacy answers `initialize`, mints `Mcp-Session-Id`, serves
  `resources/subscribe|unsubscribe` and a GET SSE stream for that session.
  Both serve `resources/list` with `file:///a`, `file:///b`, `file:///c`.
- **stdio peer**: a `python3` script (stdlib only), era by argument, the same
  methods over lines; `push` writes a trigger file it polls, it logs every line
  it reads.
- **WebSocket peer**: the existing `tests/sub2b/websocket_backend.rs` shape,
  legacy only.

Principals: alice and bob may reach backend `x`; carol may not. There is no
per-principal URI policy (§2), so the URI refusal is driven by a URI absent
from `x`'s shared catalogue (`file:///secret`), which every principal is
refused. The row does not pretend to test a per-principal URI policy.

| Row | Era / transport | Clauses (each a separate assertion) |
|---|---|---|
| T39a | modern HTTP | (1) subscribe `resource_updated {uri: a}` → peer sees exactly one `subscriptions/listen` whose filter names `a`; (2) a second principal subscribing to `a` → still one live listen naming `a`; (3) push `resources/updated a` → one event per subscription, `data == {"uri": a}`; push `…updated b` → none; (4) subscribe `b` → the peer's log shows a new listen naming `a` and `b`, acknowledged before the old stream closes, and a push of `a` after the change is delivered (at least once; §3 allows a duplicate across the switch, the overlap rule is a unit row); (5) unsubscribe all → the peer sees the stream close and no listen remains; (6) `resources/list_changed` and `prompts/list_changed` with matching subscriptions → one `resources_changed` and one `prompts_changed` event; (7) a frame without the listen tag → no event |
| T39b | legacy HTTP | (1) one `resources/subscribe a` and one GET stream on the same session id; (2) as T39a(3); (3) last unsubscribe → `resources/unsubscribe a`, GET closed; (4) as T39a(6) |
| T39c | modern stdio | as T39a (1), (3), (5) with close seen as `notifications/cancelled` naming the listen id, (6), (7) on the shared stdio channel |
| T39d | legacy stdio | as T39b (1)–(4), channel = stdout lines |
| T39e | WebSocket | as T39d |
| T39f | any (modern HTTP) | `resource_updated {uri: file:///secret}` (not in the catalogue) → `-32012`; carol → `-32011`; the peer sees no listen for either |
| T39g | modern HTTP + legacy stdio | a downstream `subscriptions/listen` client of the gateway (alice's key, filter naming `a` and both list kinds) receives none of the pushed notifications while event subscribers do |
| T39h | modern HTTP | the peer drops the SSE stream → the gateway reopens a listen with the same filter within the backoff floor; a push after the reconnect is delivered |
| T39i | legacy stdio | the peer process exits → restarted on reconnect, `resources/subscribe a` re-sent, and a push after the restart is delivered |
| T39j | config | an identity-propagating HTTP backend, an `/sse` backend and the modern peer side by side → `events/list` lists b2 names for the modern peer only |
| T39k | modern HTTP | five `resources/updated a` within 200 ms → exactly one event, delivered after the last push |

**Fails first because:** on the I2/I4 base no b2 descriptor exists, so each
row's first subscribe answers `-32011` and the row fails at its own "subscribe
accepted" or "listed" assertion, after the gateway and the peer have started
(the implementation PR's first commit adds a precondition that each peer saw its handshake, `server/discover` or `initialize`, so a row cannot pass its early steps without a live peer). T39g's
"receives none" clause would pass vacuously on that base, so it is asserted
only after the same row has seen the event subscriber receive the push.

**Unit rows (in `src/`, not red-first, landing with the code):** refcount
algebra of `Need` (two keys sharing a URI, last-unsubscribe order); key
re-parse round trip; coalescer window; the tag filter; the overlap rule (both streams accepted until the old one ends); the projection to `UpstreamNote` and its 2 048-byte URI drop; the acknowledgement intersected with the request; `End` on a full stdio channel still closes it; a truncated catalogue never revokes; a list change invalidates the resource cache before the re-read; the transport-generation check (a replaced slot transport ends the stream while the old `Arc` is still held elsewhere); a full tap does not delay an ordinary request's response or a progress notification on the same transport; the acknowledgement
check including the response-as-ack compatibility rule and its exact shape; `force_restart` reaching strong count one while a listener holds its lease and an open `FrameStream`; key parse for a dotted backend name; the tap's `try_send`
never blocking a full channel; the snapshot rule of §7 (error keeps, read-and-
absent revokes); and the idle lease, driven in-crate rather than through the
reaper's 60 s sweep (`SWEEP_INTERVAL`, `src/gateway/server/mod.rs` ~3648):
with `stop_when_idle_for: 1s` and the listener's lease held,
`Backend::stop_if_idle()` returns false; after the lease drops it returns true.

**Mutation targets:** the tag check, the `Need` decrement, the URI catalogue
check in `authorize`, make-before-break ordering, and the lease release on
last unsubscribe.

## 11. Known limits and departures from the parent design

| # | Item | Why |
|---|---|---|
| D1 | Modern stdio uses `subscriptions/listen`, not `resources/subscribe` (parent §3.3 said stdio uses `resources/subscribe`) | 2026-07-28 removed `resources/subscribe` (`src/protocol/meta.rs:297`); the era decides, not the transport |
| D2 | **Ruled (lead, 2026-10-02 interim): typed refusal.** HTTP backends without `streamable_http: true` (the SSE handshake path, `/sse` or not) and A2A backends offer no b2 events | A2A has no MCP notifications. For the handshake path the cheaper route exists: keep reading the transport's own handshake GET (today dropped after the `endpoint` event, `http/mod.rs:1188-1290`) and feed it to the tap. Its cost is a behaviour change for every handshake-path backend (one held connection each, and the existing fixtures return a finite handshake body, so stream end cannot mean "disconnected"). Impact today: the operator's live config has 34 backends, 26 stdio and 8 streamable HTTP, **0** on the handshake path, 0 A2A. Proposed: ship without it, grade SOURCE.1 with that exclusion named; the lead may instead require the held-GET route in I5 |
| D3 | **Ruled (lead, 2026-10-02 interim): typed refusal.** Backends with identity propagation or per-caller catalogue isolation offer no b2 events | the shared-slot listener would observe under the gateway's credential, not the subscriber's (§6). Per-principal listeners are a larger design. Impact today: **0** of the operator's 34 backends propagate identity |
| D4 | URI access = shared catalogue membership, exact match; template-only URIs refused | the rule `/mcp` `resources/read` already applies; no new policy model |
| D5 | A live event subscription keeps its backend from being idle-stopped | otherwise reaper and listener fight; bounded by the subscription TTL |
| D6 | Lost while disconnected; a modern filter change may duplicate | emit-only (parent F3); a duplicate change event is harmless, a gap is not |
| D7 | Unsupported kinds are silent, not refused at subscribe | eligibility comes from config so `events/list` never starts a backend; the refusal would need a live probe at subscribe |

**Finding outside I5 (for the lead):** the gateway's own downstream
`subscriptions/listen` acknowledges with a JSON-RPC success response
(`src/gateway/router/handlers.rs:1081-1087`, sent first by
`src/gateway/streaming.rs:549-555`). The spec makes the first message the
`notifications/subscriptions/acknowledged` notification and a response the
graceful end (filed as MIK-7766). A conformant client therefore reads the gateway's
acknowledgement as "closed". I5 tolerates it upstream (§3); fixing the
downstream side is a separate ticket.

## 12. Delivery

Branch `feat/mik-7630-i5-upstream`, stacked on I2 (and on I4 once it exists),
one PR:

1. this document (review frozen after at most two rounds);
2. red commit: `tests/mik_7630_events_upstream.rs` + `upstream_peer.rs` (T39a–k),
   seen red on CI at the rows' own assertions;
3. transport taps (`listen`, `unsolicited`) with their unit rows;
4. `src/backend/listen.rs` and `src/events/upstream.rs` (listener task,
   `Need`, coalescer), b2 in the `BackendNotification` source;
5. changelog fragment; parent §3.3 pointer to this document.

Implementation starts only after I2 and I4 merge: the hooks this design hangs
on are I4's, and the source it extends is I4's.

## 13. Review record

| Round | Seat | Verdict | Disposition |
|---|---|---|---|
| 1 | gpt-review | SHIP-WITH-FIXES | 9 findings, all accepted: snapshot kept current through an internal `resources/list_changed` plus TTL re-read; per-attempt `authorize` (I4 wiring); eligibility reads identity config explicitly; transport-generation check for restarts; URI budget in bytes under the frame cap; overlap accepts both streams (duplicate allowed, no gap); legacy keeps one GET, recycle has a stated gap; sessionless legacy GET; `UpstreamNote` projection bounds the taps. Improvements taken: modern `_meta` on listen (mocks refuse without it), tap-full regression row, exact response-as-ack shape |
| 1 | grok-review | SHIP-WITH-FIXES | 6 findings, all accepted, verified at source: eligibility is `streamable_http: true` (any other `http_url` takes the handshake path, `http/mod.rs:765`); offline subscribe admits and the listener checks before first emit; control RPCs re-acquire the transport; new `HeaderMode::SessionStream` (`Sse` omits the session, `http/mod.rs:1078`); first-frame ack does not end the stream; T39a(4) no longer asserts "once". Improvements taken: `close()` cancels listen body tasks, T39c untagged clause, dotted-name key parse, `force_restart` strong-count unit row |
| 2 | gpt-review | SHIP-WITH-FIXES | 6 findings, all accepted: `UpstreamNote` is an enum (ack intersected with the request, notice, end) and carries no backend subscription id; complete-read rule against page truncation; `End` closes a full stdio channel; list change invalidates the resource cache before the re-read; snapshot gates `resource_updated` only. Improvement (mutable-catalogue and partial-ack fixtures) taken into the implementation PR's unit rows |
| 2 | grok-review | SHIP-WITH-FIXES | 1 finding, accepted: a slow replacement listen no longer closes the old stream. Improvements taken: typed `FrameStream`, revoke absent URIs at the first complete snapshot, `clientInfo` struck, deferral before claim |

Frozen after round 2 (two rounds, per the lane rule). Both round-2 verdicts were
SHIP-WITH-FIXES with every finding local to a stated mechanism; all are applied
above and none changed the design's scope. No third round.

Amendment (ruling B, 2026-10-02): §4 moves `listen`/`unsolicited` to a crate-private side trait. gpt-review SHIP-WITH-FIXES (a second `Arc` would pin a retired transport; WebSocket arm holds an erased `Arc`) and grok-review SHIP-WITH-FIXES (same pin; proposed a `Weak`). Both applied: the pool entry holds a `Weak`, the WebSocket start helper returns the concrete type.

## 14. I5b: a backend's own tools/list_changed (2026-10-03, lead ruling)

`backend.<x>.tools_changed` (I4) fires on the gateway's own tool-set announcements (a reload). A subscriber also expects a backend's own `notifications/tools/list_changed` to produce it, and SOURCE.1 names tools beside resources and prompts, so the listener carries it too. A `tools_changed` subscription counts as interest `ToolsChanged` in the same per-backend `Need` (its `on_first`/`on_last` hooks, only for a backend that offers upstream events, §6); the filter gains `toolsListChanged`, and the legacy unsolicited tap and the legacy session GET pass the fourth method. A tools notice does not take the coalescer or `emit`: the listener calls the existing `EventsHub::backend_tools_changed(backend)`, so authorization (backend visibility), fan-out, the 500 ms per-backend debounce and the event shape are exactly I4's. Dedup follows from that: a reload and a backend notice within one quiet window are one event; further apart they are two, each a real change and each meaning "re-read the tool list". A backend that is excluded (§6) keeps the gateway-announced event only; its upstream notices are not heard, which the supported matrix states. No `Transport` or trait change.

Round 1 (gpt SHIP-WITH-FIXES, grok SHIP). Applied: the listener drops the shared slot's cached tool list (`invalidate_tools`) when a notice arrives and before the hub is told, so a subscriber's re-read reaches the backend; the hub handoff is at most one call per 250 ms tick per backend (a flag, not a queue), so the debounce spawns a bounded number of sleeping tasks whatever the backend sends; acceptance rows are T39l (modern HTTP, filter carries `toolsListChanged`), T39m (legacy stdio), the filter and projection rows in `upstream_tap_tests.rs`, and the `Need` rows; the excluded-backend limit is stated in the supported matrix. Not done: a filtering-ack-omits-tools row and a dedup row for a reload plus a notice (the merge is the hub's existing, tested debounce).

