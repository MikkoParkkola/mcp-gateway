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

## Producing something to carry — the part the first draft got wrong

The first draft listed "no producer changes" as out of scope. Review called that what it was: a
registry nothing feeds is not the feature, however correct its plumbing. Corrected here.

**Nothing in this gateway emits `notifications/tools/list_changed` today.** Searched: the string
appears only as the `listChanged: true` capability declaration and in the removed-methods list. So
the gateway advertises a capability it has never honoured — a defect this change closes rather than
inherits.

The tool surface changes when a backend is added, removed or revived
(`gateway/ui/backends.rs`). Those three paths publish `notifications/tools/list_changed` to the
registry. That is one real producer proved end to end: add a backend, and a listening modern client
receives the notification on its open stream.

Other kinds — `prompts/list_changed`, `resources/list_changed`, `resources/updated` — have no
producer in this gateway either. They are **filtered correctly and never delivered**, because
nothing raises them. That is stated here rather than implied by silence, and it is the honest
boundary of this change: the transport is complete and one producer is real.

## Admission is a permit, not a count

A count checked before subscribing is two operations, so concurrent requests can both see room and
both take it. The ceiling is a resource bound against a caller who opens streams and abandons them,
so a bound that can be raced is not a bound.

Each listener holds a **semaphore permit owned by the SSE body**. Admission is the permit
acquisition; release is the body being dropped. The same structure `AppState` already uses for
in-flight request limiting, so it is the house pattern rather than a new one.

## A lagging client is disconnected, not silently starved

A bounded broadcast channel drops messages for a receiver that falls behind, and the receiver is
told it lagged. Delivering the remainder as though nothing happened leaves a client holding stale
state with no way to learn it — the failure shape that reads as success.

On lag the stream **closes**. The client sees its subscription end and re-subscribes, which is the
recovery the revision leaves available now that resumability is gone. Recorded in a log line with
the count missed.

## What is deliberately NOT built

- **No resumability.** Removed by the revision.
- **No replacement for the legacy GET SSE endpoint.** It keeps working for 2025 clients; retiring it is a separate decision with its own compatibility cost.
- **No cross-replica fan-out.** A notification raised on one replica reaches only listeners on that replica. Same shared-state gap as the continuation ledger and the mint counter, recorded with them, and it binds before multi-replica production rather than before merge.
- **No producers for the other three kinds**, because this gateway raises none of those events at all. Named above rather than buried.

## How this will be proved

Tests first, and each must be able to fail:

1. A listen request receives an acknowledgement carrying the request's own id, on a stream.
2. A notification of a kind the client asked for arrives, tagged under `params._meta`.
3. A notification of a kind the client did **not** ask for never arrives.
4. A `resources/updated` for a URI the client did not name never arrives.
5. A request-scoped notification never arrives on this stream.
6. At capacity, a new listen request is refused rather than accepted and starved.
7. Dropping the stream releases the permit, so capacity comes back.
8. Two simultaneous listeners with different filters and different request ids each receive only their own kinds, tagged with their own id.
9. Adding a backend delivers `tools/list_changed` to a listener that asked for it — the producer path, end to end.
10. A receiver that falls behind has its stream closed rather than being silently starved.
