<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->
# MIK-7272.SUB.2b (d) — liveness on both HTTP legs

Status: design, awaiting review. Supersedes nothing; completes ADR-014 Acceptance
rows 4 and 5, which fail today by construction.

## The requirement, and why today's code cannot meet it

ADR-014 Acceptance row 4 (`docs/adr/ADR-014-request-scoped-notifications.md:450-457`)
asserts **liveness**, not ordering, and says so in its own words: *"The fixture
releases the result only after the client has read the notification … a design
that buffers and flushes at the end deadlocks here instead of passing."* Row 5
(`:459-463`) adds that the accumulating `Vec` must be gone and that *"the
notification arrives before the body has been read to its end."*

Test-plan row **S-02** (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:58`)
requires that assertion over stdio **and** over HTTP, and **neither holds today**.
An earlier reading of this document claimed stdio already did, on the strength of
`Gateway::dispatch_with_notifications` and the assertion at
`src/gateway/server/mod.rs:4097`. That assertion is a `#[tokio::test]` driving the
sink directly; it proves the client leg streams and says nothing about where the
notification comes from. Measured end to end at `66d1fc23`, three of the six
`mik_7272_sub2b_acs` rows fail and **all three are stdio** — including the `S-03`
isolation row, which needs no liveness at all. The child's own logs show why: the
backend's headers arrive, then nothing until the fixture releases, because the
gateway is inside `response.text().await`.

The path buffers **twice**, and gap A sits on the leg both transports share:

| # | Leg | Site | What buffers |
|---|-----|------|--------------|
| A | backend → gateway | `src/transport/http/mod.rs:1387-1392` | `response.text().await` reads the backend's whole SSE body, then `forward_sse_exchange` publishes. No notification exists until the backend has finished answering. |
| B | gateway → client | `src/gateway/router/handlers.rs:599` | `notification_sink::collect(async { dispatch })` awaits the entire dispatch; `request_scoped_event_stream` (`src/gateway/streaming.rs:604`) is then handed a finished `Vec<JsonRpcNotification>`. No byte reaches the client until dispatch has returned. |

Either one alone defeats row 4. A fixture that withholds its result until the
client reads the notification deadlocks in four steps — client waits on the
notification, gateway waits on dispatch, dispatch waits on the backend, backend
waits on the client. **This is why the two `S-02` × HTTP rows cannot pass, and
why `MIK-7272.SUB.2b` cannot flip without this work.** It is an implementation
gap, not a harness limitation.

`S-03` (isolation) is unaffected **over HTTP**, and both its HTTP rows pass:
which stream carried which notification is fully observable in a buffered body.
Its stdio row fails for a different reason — the shared fixture withholds its
result behind the same gate, so a buffered backend leg never yields a
notification for the isolation assertion to read. Fixing gap A is expected to
take that row with it; that expectation is checked by re-running the file, not
asserted here.

## Gap A — backend leg

`src/transport/http/sse_decoder.rs` is **scaffolding**: `bc3c56db` landed the
module with its contract written out at `:5-30`, the `SseEvent`/`SseDecoder`
types declared, and every function `unimplemented!()` behind `#[expect(dead_code)]`.
Its three tests in `sse_decoder_tests.rs` are written against the intended
behaviour. The module doc is target-state, not a description of running code.

Work: implement `SseDecoder::{push, finish}` and `decode_sse_exchange` to the
contract already pinned at `:12-30` — SSE field parsing (one optional leading
space stripped, not `str::trim`), LF/CRLF/bare-CR terminators, multi-`data:`
join with `\n`, comment and colon-less lines skipped, empty-`data` blocks
skipped, `MAX_PENDING_SSE_BYTES` measured over the **whole retained event**, and
`finish` flushing a final block with no trailing blank line. Then replace the
buffered read at `mod.rs:1387-1392` with `decode_sse_exchange(response.bytes_stream())`,
mapping `reqwest::Error` to `Error::Transport` at the call site as the doc at
`:98-99` specifies, and drop the three `#[expect(dead_code)]` attributes.

No new contract is invented here: the contract is read from the module doc.

Once the stream drives the decoder, the buffered path it replaces has no
production caller: `SseExchange`, `parse_sse_response` and `forward_sse_exchange`
go with it rather than being gated behind `#[cfg(test)]`. Two implementations of
one contract is the shape where a fixture proves a behaviour the shipped path
does not have, so the eight rows that exercised the buffered parse are
retargeted at `decode_sse_exchange` instead of deleted: the same acceptance,
asserted against the code that runs. Capture becomes a sink assertion there,
because publishing is now what the caller observes.

## Gap B — client leg, and the one real tension

Today the decision to stream is made **after** dispatch: `request_scoped_event_stream`
returns the response untouched when its content-type is not `application/json`
(`streaming.rs:613-619`), because `subscriptions/listen` already answered with a
stream of its own and a refusal that never reached dispatch has no result to
frame. A streaming design must commit to SSE response headers **before** dispatch
finishes, so it cannot consult the finished response to make that decision.

**Design: first-event-wins.** In the `offers_event_stream` branch, use
`notification_sink::scope` (`src/transport/notification_sink.rs:48`) — which
already returns `(scoped_future, rx)`; `collect` is only its draining wrapper —
and race the two:

- **Dispatch completes first.** Nothing was published. Fall through to exactly
  today's behaviour: hand the finished response and the drained notifications to
  `request_scoped_event_stream`. Non-JSON passes through unchanged. Every request
  that publishes nothing is byte-identical to today.
- **A notification arrives first.** Commit to SSE: emit headers, write that
  notification's frame immediately, keep forwarding from `rx`, and write the
  result frame when dispatch resolves. Body built with `async-stream`
  (already a dependency, `Cargo.toml:103`) so the dispatch future is driven by
  the stream that consumes it.

**Why the commit is safe.** Committing to SSE is only wrong if a request that
publishes could answer non-JSON. It cannot: the sole production publisher is
`forward_sse_exchange` (`src/transport/http/mod.rs:368`), reached only from
`send_request_with_headers` (`:1392`) — a backend tool call, which answers JSON.
The only other `notification_sink::publish` call site, `src/gateway/server/mod.rs:4103`,
is inside a `#[tokio::test]`. `subscriptions/listen` answers with its own stream
and invokes no backend tool, so it never publishes.

**Response-head policy.** Committing headers early also fixes the HTTP status,
so the streaming arm must answer `200 text/event-stream` before it knows how
dispatch ends. That is sound here, and for a checkable reason rather than a
convention: every non-200 status on this path is decided in request validation
and routing — the last of them at `src/gateway/router/handlers.rs:1371` — all of
which precede the `tools/call` dispatch block at `:1475-1713`, and it is only
inside that block that a backend call can publish. A request that ends non-200
therefore never publishes, so it always takes the buffered arm and keeps its
status exactly as today.

A refusal decided *after* the backend has answered is the reachable case, and it
is not a status at all: a response-phase firewall block builds a JSON-RPC error
into the body (`:1704-1709`) and leaves the status alone. Carrying that under a
200 is ordinary JSON-RPC-over-HTTP, and is what the buffered arm does today.

**Fail-safe.** Those are properties of today's call graph, not invariants the
compiler holds, so the streaming arm does not assume them. Its condition for
framing a result is **JSON *and* 200**; if dispatch resolves to anything else
after we have committed to SSE,
emit a terminal JSON-RPC error frame — internal error, *"response not frameable
over event stream"* — and end the stream, rather than framing a body we cannot
parse. The terminal frame matters: ending the stream silently would leave the
client with neither a result nor an error, which is a worse failure than the one
being guarded against, and the client already parses framed results so this adds
no machinery. Unreachable on the call graph above; it exists so that a future
publisher cannot turn a wrong assumption into a truncated response.

**No content-type ambiguity.** Both arms answer `text/event-stream` when the
client offered it: the buffered arm reaches it through
`request_scoped_event_stream`, which sets that header for any JSON response
(`src/gateway/streaming.rs:641-642`). Which arm wins a race therefore changes
liveness only, never the response's shape — and the row-4 fixture cannot take
the buffered arm, since it withholds its result until the client has read the
notification, so dispatch cannot resolve first.

## Risks

- **Ordering.** The result frame must be last on the stream. `rx` is drained to
  empty after dispatch resolves and before the result frame is written —
  `collect` already does this at `notification_sink.rs:74-76` and the streaming
  arm must keep it, or a notification published late is lost or lands after the
  result.
- **Bounded channel.** `eaa95617` made the sink a bounded channel, and `publish`
  drops-and-counts rather than blocking (`:84-86`). Streaming does not change
  that contract; it makes the drop rarer, since a live consumer drains.
- **Cancellation.** A client that disconnects mid-stream drops the body, which
  drops the dispatch future with it. That is today's behaviour for
  `create_sse_response` and is not new here.

## Acceptance

1. The four `S-03` × HTTP and `S-02` × HTTP rows in `tests/mik_7272_sub2b_acs.rs`
   pass, with the two `S-02` rows using a fixture that withholds the result until
   the client has read the notification — the row-4 liveness shape, which
   deadlocks against today's code. Each such row carries a timeout, so the
   deadlock it is built to detect fails the run instead of hanging it.
2. A row with **two separately gated** notifications: the client must read the
   first before the backend emits the second. One gate proves a flush happened;
   two prove flushing is per-event rather than a single buffer drained once.
3. `sse_decoder_tests.rs`'s **twelve** tests pass — nine `#[test]` and three
   `#[tokio::test]`, not the three async ones alone — and no `#[expect(dead_code)]`
   remains in `sse_decoder.rs`.
4. A request that publishes nothing produces a byte-identical response to today,
   JSON and SSE alike.
5. No buffered SSE parse survives beside the decoder, and the lib build carries
   no new dead-code warning — the evidence that the replacement is a replacement
   and not an addition.

## Measured outcome — acceptance 2 is not met, and not by gap A

Points 1, 3, 4 and 5 hold: 81 `transport::http` lib rows, the 12 decoder rows and
the four HTTP acceptance rows pass, and no buffered parse survives.

Point 2 does not, and the cause is downstream of this leg. A row driving a fixture
that emits its second notification only after the client has read the first and
released receives one notification and then stalls. Instrumented at
`src/transport/http/sse_decoder.rs:199`, the decoder logs both notifications, the
second ~174 ms after the first, and publishes each to a request-scoped sink that is
present and not shedding. A variant of the same row with the second notification on
a timer and no intervening client call passes, so the decoder emits both and the
stream leg forwards both.

The loss is therefore specific to the two-gate shape, where the second notification
does not exist until an intervening client call lands. Which layer drops it is not
identified. `first_event_wins_stream` (`src/gateway/streaming.rs:727-752`) publishes
inside its loop, drains on dispatch and emits a terminal frame, so the mechanism the
client leg was said to lack is present; the timer variant exercises it and passes.
The two-gate row differs on two axes at once — a second POST arrives on the session
mid-stream, and the backend's second frame is causally gated on that POST reaching
the fixture — and the evidence here does not separate them.

Gap A cannot close point 2 and the row is therefore not carried here. Point 2 remains
open, against an unidentified layer. The two reproduction rows in
`tests/mik_7272_sub2b_acs.rs` are `#[ignore]`d and unrun; their PROBE labels separate
"the intervening call was never serviced" (PROBE-A) from "it was serviced and no frame
followed" (PROBE-B), which is the measurement that names the layer.
