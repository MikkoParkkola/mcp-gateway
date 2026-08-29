# Design — `subscriptions/listen` as a real stream

**Status**: proposed, for review before implementation
**Scope item**: RFC-0061 item 2.5 · requirements §3.9 · MIK-7272
**Date**: 2026-08-29

## The problem

`subscriptions/listen` currently parses its filter, mints the right identifier, and returns an
ordinary JSON-RPC response. The specification's response is **an SSE stream that stays open** and
delivers the opted-in notifications until the client cancels it. So a client reads the
acknowledgement as a live subscription and waits forever for notifications nothing will send.

This is the last piece of construction in the release scope, and the reason
`server.modern_protocol` defaults off.

## Constraints, measured rather than assumed

- **There is no session.** 2026-07-28 removed them, so the notification multiplexer — whose entire key is the session id — cannot own these listeners. Its per-session SSE stream is the thing this replaces (RFC-0060 §"Streaming session reaping").
- **There is no resumability.** The revision removed it. No `Last-Event-ID` handling, and no event-id bookkeeping.
- **The subscription id is the request's own JSON-RPC id**, string or number, already implemented and tested.
- **The filter nests under `params.notifications`**, and `resourceSubscriptions` is a list of URIs, already implemented and tested.
- **A client may abandon a stream**, and the specification says a server MUST NOT assume otherwise.

## What is being built

### 1. A subscriber registry, separate from the multiplexer

A process-wide `tokio::sync::broadcast` channel of notifications, plus a count of live listeners.
Each listener holds a receiver and its own filter.

**Why not extend `NotificationMultiplexer`**: its key is the session id, and the whole point of this
work is that there is none. Adding a session-free code path to a session-keyed structure conflates
two lifetimes in one table — which is exactly the defect this branch already fixed once, when a
stateless request was minting a session per call.

**Why a broadcast channel rather than a registry of senders**: a listener that goes away must cost
nothing. Dropping the SSE stream drops its receiver, and the channel reclaims it with no reaper, no
deadline and no cleanup callback. That matters here specifically: the mechanism that would have
reclaimed per-caller state is not wired to anything (MIK-7291), so a design that needs reclamation
is a design that leaks.

### 2. The handler returns a stream instead of a body

On `subscriptions/listen`, with the modern path enabled:

1. Parse the filter. No `notifications` key → `-32602`, unchanged.
2. Refuse if the live-listener count is at capacity — a bound, for the same reason the in-flight table and the consumed ledger have one: a client may open streams and walk away.
3. Subscribe to the broadcast, take the request's id as the subscription id.
4. Return SSE whose **first event is the acknowledgement** — the JSON-RPC result carrying `_meta.io.modelcontextprotocol/subscriptionId` — followed by each matching notification.

### 3. Filtering, at the listener

For each notification, deliver it only if the client asked for that kind:

| Kind | Delivered when |
|---|---|
| `notifications/tools/list_changed` | `toolsListChanged` is true |
| `notifications/prompts/list_changed` | `promptsListChanged` is true |
| `notifications/resources/list_changed` | `resourcesListChanged` is true |
| `notifications/resources/updated` | its `params.uri` appears in `resourceSubscriptions` |

Anything else — `notifications/progress`, `notifications/message` — is **never** delivered here.
Those are request-scoped and travel on the response stream of the request that caused them. The
existing `NotificationKind::from_method` already refuses to map them, and there is a test for it.

An empty filter is valid: the stream opens, acknowledges, and delivers nothing.

### 4. Tagging

Every delivered notification gets `params._meta.io.modelcontextprotocol/subscriptionId`, via the
existing `SubscriptionId::tag`, which is already correct and tested.

## What is deliberately NOT built

- **No resumability.** Removed by the revision.
- **No replacement for the legacy GET SSE endpoint.** It keeps working for 2025 clients; this is the modern path's own stream. Retiring the GET endpoint is a separate decision with its own compatibility cost.
- **No cross-replica fan-out.** A notification raised on one replica reaches listeners on that replica. This is the same shared-state gap the continuation ledger and mint counter already carry, and it is recorded with them rather than solved here.
- **No producer changes in this step.** Nothing currently raises `tools/list_changed` on the modern path; wiring producers is a follow-on. **This is the honest limit of this change**: it builds the stream and proves it carries what it is given, and until a producer feeds the channel the stream is correct and quiet.

## Open questions, each with the check that answers it

| Question | How it is answered |
|---|---|
| Does the SSE response type compose with the existing handler return type, which is a single `Response`? | Build it. `Sse` implements `IntoResponse`; the handler already returns `Response` for the legacy GET stream, so the shape exists. |
| What capacity for concurrent listeners? | Follow the existing bounds in this module rather than invent a number: the in-flight table and consumed ledger take theirs from config. Same pattern, same config surface. |
| Does an SSE body on a POST break the existing test harness, which reads the whole body? | It will block on a stream that stays open. The tests must read a bounded prefix, or the stream must close when the sender is dropped. Checked by writing the first test before the handler. |

## How this will be proved

Tests first, and each must be able to fail:

1. A listen request receives an acknowledgement carrying the request's own id, on a stream.
2. A notification of a kind the client asked for arrives, tagged under `params._meta`.
3. A notification of a kind the client did **not** ask for never arrives.
4. A `resources/updated` for a URI the client did not name never arrives.
5. A request-scoped notification never arrives on this stream.
6. At capacity, a new listen request is refused rather than accepted and starved.
7. Dropping the stream releases the listener, so capacity comes back.
