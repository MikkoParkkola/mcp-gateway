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
requires that assertion over stdio **and** over HTTP. Over stdio it already holds:
`Gateway::dispatch_with_notifications` streams, and
`src/gateway/server/mod.rs:4097` asserts a notification reaches stdout before its
own dispatch resolves. Over HTTP nothing does, because the path buffers **twice**:

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

`S-03` (isolation) is unaffected: which stream carried which notification is
fully observable in a buffered body. Buffering breaks liveness, not isolation.

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

**Fail-safe.** That argument is a property of today's call graph, not an
invariant the compiler holds, so the streaming arm does not assume it: if
dispatch resolves to a non-JSON response after we have already committed to SSE,
emit the notification frames already written and end the stream rather than
framing a body we cannot parse. This is unreachable on the call graph above and
exists so that a future publisher cannot turn a wrong assumption into a corrupt
body.

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
   deadlocks against today's code.
2. `sse_decoder_tests.rs`'s three tests pass; no `#[expect(dead_code)]` remains in
   `sse_decoder.rs`.
3. A request that publishes nothing produces a byte-identical response to today,
   JSON and SSE alike.
