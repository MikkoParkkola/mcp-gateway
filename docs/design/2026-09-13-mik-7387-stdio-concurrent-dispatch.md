<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MIK-7387 — stdio concurrent dispatch and the stdio `ClientChannel`

Reviewed before implementation. Two independent reviews returned
SHIP-WITH-FIXES; §1, §4, §5, §6 and the acceptance section below are the
revision, and the findings that produced each are named in place.

## What this is for

Three acceptance rows in `tests/mik_7212_mrtr7_stdio_acs.rs` are `#[ignore]`d
against today's stdio transport and are the spec for this change:

| Row | Test | Requires |
|---|---|---|
| 312 | `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` (`:355`) | the serve loop keeps reading while a dispatch waits on the client, and the client's reply is routed back to that waiting dispatch |
| 323 | `ac_mrtr_7a_bridged_request_follows_the_initialize_response` (`:420`) | an outbound bridged request is written **after** the `initialize` response, when both inbound requests were sent back to back |
| 324 | `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` (`:470`) | two concurrent bridged calls produce two outbound `elicitation/create` frames, each a whole line of JSON |

Out of scope, explicitly: HTTP dispatch, the `confirmation` channel (stdio keeps
refusing there — no operator to reach), batch-request concurrency, and any
change to `NoClientChannel` itself, which stays the null object for the
contexts at `src/gateway/router/handlers/tasks.rs:305` and the test sites.

## Today

`run_stdio` (`src/gateway/server/mod.rs:2301-2360`) is a single sequential
loop: read a line, `await` the dispatch, write the response, read the next
line. The caller context it builds carries `channel: &NoClientChannel`
(`src/gateway/server/mod.rs:2738` and `:3204`), so `InputBridge::ask` returns
`DeliveryError::NoSession` and no question is ever asked.

Both properties have to change together. Wiring a real channel into the
sequential loop deadlocks it: the reply can only arrive on the same pipe the
reader is blocked inside, so the dispatch waits for a line the loop will never
read.

## The change

### 1. One writer, owning stdout

An `mpsc::UnboundedSender<Value>` feeding a single task that owns
`tokio::io::stdout()` and writes one serialized frame plus `\n` per message.
Every producer — responses and outbound requests alike — sends on that channel
and never touches stdout. This is what makes row 324's framing assertion true
by construction rather than by luck: with a shared unlocked writer, two tasks
serializing into the same handle can interleave mid-frame.

Unbounded is deliberate, and the honest reason is not deadlock: the writer only
writes and never waits on a dispatch task, so a bounded queue could not deadlock
against it. The tradeoff is unbounded memory against backpressure that has
nowhere to go — the only producer worth throttling is a client that has already
been served, and slowing the writer would not slow it. For one spawned client,
memory wins.

### 2. `initialize` stays inline; everything else is spawned

The loop reads a line, and:

- if the frame's method is `initialize`, dispatch and enqueue the response
  **before** reading the next line;
- otherwise spawn the dispatch onto a task that sends its response to the
  writer when it completes.

Row 323 is the reason for the split. The test sends `initialize` and the asking
call back to back without waiting between them. With `initialize` dispatched
inline, its response is in the writer's FIFO queue before line 2 is even read,
so no frame produced by line 2's dispatch can precede it. A barrier ("park the
channel until initialized") would also satisfy the row, and is rejected as the
larger mechanism: it adds a state flag, a notify, and a wake path, to enforce an
ordering the read loop already has for free.

The narrower alternative — spawn only methods that can bridge — is rejected too:
whether a call bridges is a property of the backend's response, not of the
request, so it cannot be decided at dispatch time without the answer it is
gating.

Consequence, stated rather than hidden: responses to non-`initialize` stdio
requests may now be written out of request order. JSON-RPC correlates by `id`
and the MCP specification permits it. Three test files drive the stdio
transport — `tests/stdio_tests.rs`, `tests/nfr_compat_2_stdio_client_session.rs`
and `tests/mik_7212_mrtr7_stdio_acs.rs`; the first two read replies by `id` and
assert nothing positional, and the third's only ordering assertion is row 323
itself, which this design preserves.

### 3. Inbound classification

A frame with an `id` and **no** `method` is a reply to one of our outbound
requests, not a request. It is routed to the pending map and the loop continues;
it is never dispatched. Everything else dispatches as today. A reply whose `id`
matches nothing pending is dropped with a `debug!` — a late answer to a
timed-out prompt is the expected cause and is not an error.

### 4. `StdioClientChannel`

```
pending: DashMap<String, oneshot::Sender<JsonRpcResponse>>
writer:  mpsc::UnboundedSender<Value>
```

`send_request` registers the oneshot under `id` behind
`PendingRequestGuard::new(&self.pending, id)` (`src/transport/mod.rs:151`,
already `pub(crate)` and therefore reachable from the gateway module with no
visibility widening), enqueues the request frame, then awaits the receiver.

The guard is not stylistic. `InputBridge::ask` wraps every call in
`tokio::time::timeout`; on expiry the future is dropped and neither the success
nor the error path runs, so a hand-rolled map leaks one entry per timed-out
prompt for the life of the session. Reusing the guard means reusing the map type
it is written against, which is why `pending` holds `JsonRpcResponse` and the
reply is parsed into that type before delivery rather than passed as a raw
`Value`. `cancelled_request_does_not_strand_pending_entry`
(`src/transport/stdio.rs:815`) already pins the guard's behaviour.

The channel is an `Arc<StdioClientChannel>` created before the loop and **cloned
into each spawned dispatch task**, which builds its caller context from `&*arc`
inside the task. A borrow of the loop's own `Arc` cannot cross `tokio::spawn` —
the context holds `&'a dyn ClientChannel` and the task needs `'static`, so the
clone is what makes the lifetime work, not a convenience. The builders at
`src/gateway/server/mod.rs:2738` and `:3204` take the channel as a parameter;
the HTTP and test call sites keep passing `&NoClientChannel`.

Ids: outbound requests are minted by the bridge as strings (`elicit-<uuid>` and
friends — the test at `tests/mik_7212_mrtr7_stdio_acs.rs:337` matches on method
precisely because the gateway's ids are not the client's integers). The pending
map is keyed by `String`. A reply frame's `id` may arrive as a JSON number or a
JSON string, so the loop normalises it the same way `send_request` registered
it: `as_str()` if a string, else the number rendered with `to_string()`. Routing
on a mismatched key is the silent failure this paragraph exists to prevent.

### 5. Shared state the spawn forces

Less than the first draft of this design claimed. `BuiltMetaMcp`
(`src/gateway/server/mod.rs:332-335`) already yields `Arc<MetaMcp>`,
`Arc<ToolPolicy>` and `Arc<MtlsPolicy>`: those three are **cloned** into each
task, not wrapped. One local genuinely changes shape:

- `protocol_telemetry_sink` (`src/gateway/server/mod.rs:2202`) is
  `&mut Option<DurableTelemetrySink>` today, written by every dispatch. It
  becomes `Arc<std::sync::Mutex<Option<…>>>`.

The lock is **never held across an `.await`**. `persist_stdio_protocol_telemetry`
(`:2391`) and `parse_and_observe` (`:2473`) are both synchronous; each takes the
lock, does its work, and drops the guard before the task awaits the dispatch. A
guard held across the await would be worse than slow: it would make the future
`!Send` and serialise exactly the two bridged calls row 324 needs concurrent —
the single mechanism this whole change exists to provide.

### 6. EOF drains; it does not abort

Both design reviews found the same defect in the first draft, independently:
holding the dispatch tasks in an `AbortOnDrop` guard and letting EOF tear them
down loses a response to a request the loop had already read and accepted.
Today's sequential loop answers every request it reads. Concurrency must not
quietly weaken that.

On **normal EOF** the order is: stop reading; fail every still-pending client
reply (the client that would have answered them is gone, so
`DeliveryError::NoSession` is the truth again); await the dispatch `JoinSet` to
completion under a bounded timeout; close the writer channel and await the
writer task, which flushes what is queued; only then drop the backend guards.

`AbortOnDrop` stays, demoted to what it is good at: the cancellation path, where
`run_stdio`'s own future is dropped and there is no one left to flush to.

Completed tasks are reaped from the `JoinSet` as the loop runs, not only at
shutdown — otherwise a long session accumulates task records and a panicking
dispatch stays invisible until EOF.

## What could go wrong

| Risk | Mitigation |
|---|---|
| Unbounded spawn under a flood of inbound lines | Accepted for stdio: one client, which spawned this process. Noted, not defended — a bound belongs with a real producer |
| A dispatch that never finishes stalls the EOF drain | The drain is bounded; past the bound the abort guards fire, which is strictly today's behaviour and no worse |
| Telemetry lock contention | One `std::sync::Mutex` around a synchronous persist, never held across an await (§5) |
| Out-of-order responses break an unknown consumer | Searched the three stdio test files; only row 323 asserts ordering, and §2 preserves it |

## Acceptance

The three rows above with their `#[ignore]` attributes removed, plus the two
existing stdio suites unchanged and still green — `tests/stdio_tests.rs` and
`tests/nfr_compat_2_stdio_client_session.rs`, which are the regression evidence
that concurrency did not cost sequential correctness — plus `cargo fmt --check`
and `cargo clippy --all-targets -- -D warnings` clean.

One test is added beyond the three rows, for the §6 behaviour they do not cover:
a request in flight when stdin closes still receives its response. Nothing in
the acceptance rows exercises EOF, so without it the drain is unpinned and the
next refactor re-introduces the abort.

## Blast radius

`gitnexus_impact` on `stdio_caller_context`, upstream: **LOW risk, 17 impacted,
all inside `src/gateway/server/mod.rs`** (module `Server`; 2 direct, 4 at d=2,
11 at d=3). `run_stdio` itself has 0 upstream callers — it is an entry point.

Two consequences for the plan:

- The channel parameter threads through `dispatch_single_with_sink`,
  `dispatch_single`, `dispatch_batch_with_sink` and `dispatch_batch`. Eight of
  the eleven d=3 entries are unit tests in the same file and update to
  `&NoClientChannel` unchanged.
- `run_playbook_over_stdio` is the second consumer of this dispatch path and is
  **not** the serve loop. It keeps `NoClientChannel`: a playbook run has no
  interactive client on the other end of the pipe, so there is nowhere for a
  question to go. Stated because the impact graph surfaced it, not because the
  acceptance rows ask for it.
