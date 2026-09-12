# Stdio inbound request bridging

Status: design, not implemented.

## 1. What is required

`docs/requirements/RELEASE-4.0.0-scope-update.md:33-35`:

> | MIK-7387.STDIO.1 | A declared client input request reaches a legacy stdio client, whose answer reaches the backend while the gateway continues reading. | BRIDGE |
> | MIK-7387.STDIO.2 | An input request cannot overtake the initialize response on legacy stdio. | BRIDGE |
> | MIK-7387.STDIO.3 | Concurrent stdio requests and replies emit complete, non-interleaved JSON frames. | BRIDGE |

`docs/requirements/RELEASE-4.0.0-scope-tests.md:15-17`:

> | MIK-7387.STDIO.1 | Enable the existing real-stdio AC in tests/mik_7212_mrtr7_stdio_acs.rs; assert the client's answer reaches the backend, not merely that a timeout returns. |
> | MIK-7387.STDIO.2 | Hold initialize write completion while a bridge request becomes ready; observe initialize first, then the input request. |
> | MIK-7387.STDIO.3 | Concurrent peer exchanges share the real writer; parse each emitted line independently and assert expected complete frames and correlation. |

Nothing beyond these six lines is required by this design.

## 2. Which stdio this is, and which it is not

Two unrelated things in this tree are called stdio, and an earlier revision of
this document designed against the wrong one.

`src/transport/stdio.rs` is the **outbound backend transport**: it spawns an MCP
server as a child process (`Command::new`, `:161`; `cmd.spawn()`, `:178`) and
dials out to it. Its writer mutex (`write_message`, `:532-553`), its
pending-response map, its `next_id` counter (`:561`, `:633`) and its
`handle_response` refusal arm (`:499-511`) all belong to that direction. None of
them sits on the path this requirement names, and none of them is edited here.
They are re-scoped, not cited: the only thing this design takes from that module
is the *shape* of `PendingRequestGuard` (§6), not its instance.

The inbound path — the gateway answering the client that spawned it — is
`Gateway::run_stdio` (`src/gateway/server/mod.rs:1566`). It owns
`tokio::io::stdin()` and `tokio::io::stdout()` (`:1638-1643`), reads one line at
a time through `BufReader::new(stdin).lines()`, and dispatches each through
`dispatch_single_with_sink` (`:1876`) or `dispatch_batch_with_sink` (`:2047`).
That loop is where all three requirements live.

## 3. What is actually missing

The bridge is not unwired. `src/gateway/meta_mcp/invoke.rs:1842` constructs an
`InputBridge` inside `invoke_tool_traced` (`:1079`) and `:1853` calls
`bridge.run(...)`; neither is under `#[cfg(test)]`. Three separate things stop a
stdio caller from reaching it, and **all three must change** — a channel alone
leaves every one of the three ACs red.

1. **No channel.** `InputBridge` is constructed with `channel: caller.channel`,
   and the one production stdio site (`stdio_caller_context`,
   `src/gateway/server/mod.rs:2306`, field at `:2339`) passes `&NoClientChannel`,
   which returns `DeliveryError::NoSession` unconditionally. `ProxyManager`
   implements `ClientChannel` (`src/gateway/proxy.rs:529`) but is HTTP-only.
2. **No declaration.** `stdio_caller_context` pins
   `input_capabilities: Declared::NONE` (`:2328`). Two gates read that field
   before any channel is consulted: the MRTR.9 gate at `invoke.rs:1781`
   (`interim.undeclared(caller.input_capabilities)`) returns
   `undeclared_input_request` outright, and `InputBridge::plan`
   (`src/gateway/input_bridge.rs:427`) refuses on the same predicate. With
   `NONE`, no `elicitation/create` frame is ever written — which is exactly what
   all three ACs assert on (`tests/mik_7212_mrtr7_stdio_acs.rs:377`, `:441`,
   `:491`).
3. **Wrong era.** The bridge branch is gated on `caller.era == Era::Legacy`
   (`invoke.rs:1821`). `stdio_caller_context` is handed `shape.era()` (`:2002`),
   and the ACs' `tools/call` carries `_meta` with
   `io.modelcontextprotocol/protocolVersion` and
   `io.modelcontextprotocol/clientCapabilities`
   (`tests/mik_7212_mrtr7_stdio_acs.rs:318-321`), which
   `protocol::meta::classify_request` (`src/protocol/meta.rs:150`) classifies as
   `RequestShape::Modern` — that arm is entered on *any* declared revision
   string, not only a modern one (`:180-186`, `:213-220`). So the caller's era is
   `Modern`, and the bridge branch is skipped in favour of the continuation mint
   even once the declaration is read.

A per-request `_meta` slice cannot rescue (2): `run`'s third argument narrows and
may only narrow the value passed as its second (`InputBridge::prompt`,
`src/gateway/input_bridge.rs:451`, and the doc above it). The declaration has to
arrive as `caller.input_capabilities` itself.

## 4. The writer

`run_stdio` owns `stdout` by value and lends `&mut stdout` to each write
(`write_response`, `:1747`; `write_notification`, `:1808`). That is sound today
because the loop is strictly sequential: one line in, one dispatch, one frame
out. There is no mutex on this path and none is needed — until requests are
dispatched concurrently, at which point three writer classes exist at once:

- per-request responses written by the loop after each dispatch (`:1708`);
- streaming notifications written from inside an in-flight dispatch by
  `dispatch_streaming_notifications` (`:1783`), which already interleaves
  notification writes with the dispatch future through `select!`;
- bridge request frames written by the channel of §6, from inside a dispatch
  that is still awaiting its own answer.

So the single-writer property must be **introduced**, not inherited. The minimum
that gets it: `run_stdio` wraps its stdout in `Arc<tokio::sync::Mutex<Stdout>>`
and hands clones to the spawned dispatches and to the channel. Every writer takes
the lock, serialises one value, writes payload and newline, flushes, then
releases — the frame is whole before the lock is. `write_response` and
`write_notification` keep their `&mut W` signatures and their generic bound, so
their own blast radius stays nil; the lock is taken by their callers. Only
`dispatch_streaming_notifications` changes shape, from `stdout: &mut W` to a
shared handle it locks once per notification, and its `W` bound gains
`Send + 'static` — satisfied by `Stdout` and by the `tokio::io::duplex` halves its
three test call sites pass.

**The lock alone is not enough, and this is the subtle part.** `InputBridge::ask`
wraps its `send_request` call in an outer `tokio::time::timeout` and drops the
future on expiry (`src/gateway/input_bridge.rs:492-520`). If that expiry lands
while the channel is inside `write_all`, the future is dropped mid-frame, the
`MutexGuard` drops with it, and the next writer appends to a partial line — a
torn frame, which is precisely what STDIO.3 forbids, produced by the one
mechanism meant to prevent it. A slow-reading client makes this reachable.

So a started frame must not be cancellable. Each write runs in its own
`tokio::spawn`ed task that takes the lock, writes the whole frame and returns;
the caller awaits the `JoinHandle`. Dropping the handle cancels only the wait, not
the task, so the frame finishes either way. `Arc<Mutex<Stdout>>` is `'static`, so
the task needs nothing else moved into it. A write error terminates the loop the
same way a write error terminates it today — a stdout that cannot be written is
not a transport.

Spawning every write also settles the question a shared writer always raises on
this path: **no writer holds the guard across a poll of the dispatch future.**
`dispatch_streaming_notifications` does not lock stdout for the life of its
`select!` — it awaits a spawned write per notification, and the guard lives and
dies inside that task. So the bridge frame written from inside `scoped` and the
notification written from the arm beside it are two independent tasks queueing on
the same mutex, not one task waiting on a lock it already holds. Holding the
guard across the `select!` instead would deadlock `tokio::sync::Mutex`, which is
not reentrant: the arm would own the lock while the only future that can release
the bridge's `ask` waits for it. That is the shape to keep out of the
implementation, and it is why the lock is described per write rather than per
loop.

Nothing here is a second synchronisation mechanism. It is the only one on this
path.

## 5. The read loop

Three changes, all inside `run_stdio`.

**Route reply frames.** After the existing `serde_json::from_str` (`:1652-1666`),
a frame that carries no `method` and whose `id` matches a pending bridge entry is
delivered to that entry's `oneshot` and the loop continues; it is never
dispatched. Everything else is dispatched exactly as today. This is the only
place a client reply can be recognised, because on stdio the reply arrives on the
same pipe as the next request.

A method-less frame today reaches `dispatch_single_with_sink`, whose
`parse_request` (`src/gateway/router/helpers.rs:276-280`) answers
`-32600 "Missing method"` against the client's own id. That behaviour is kept for
an unmatched id: only a frame whose id is a live bridge key is diverted, so a
stray response still gets the same `-32600` it gets today. Nothing observable
changes for any frame that is not an answer to a question this gateway asked.

The match is on `id.as_str()` against the minted key, not on `id.to_string()`:
the mint is always a string (`§6`), `to_string` would quote it, and a client that
answers with a number or any other JSON type has not answered a question this
gateway asked. Such a frame falls through to the existing `-32600`, which is the
correct answer to it.

**Malformed lines stay log-and-continue.** The `-32700` arm (`:1656-1665`) and the
empty-line `continue` are untouched. A line that does not parse as JSON is not a
reply and cannot be matched against anything; the routing check above runs only
on a `Value` that already parsed.

**Spawn per request, after initialize.** The loop keeps a flag that starts unset
and is set once an `initialize` request has been dispatched *and* its response
written by the loop. While it is unset, every request is dispatched inline on the
loop exactly as today — so the initialize response is on the wire before any
concurrent dispatch exists, and STDIO.2 holds structurally rather than by timing.
Once set, each subsequent single request is `tokio::spawn`ed; the spawned task
runs the same `dispatch_streaming_notifications` wrapper and writes its own
response through the shared writer. A batch is spawned as one task, its members
still dispatched sequentially inside `dispatch_batch_with_sink`: no requirement
asks for concurrency *across* a batch, but leaving the batch on the loop would
block the only reader that can deliver an answer to a bridged call inside it — or
to one already in flight from an earlier request.

Backpressure is `InputBridge`'s own, not a queue: `BridgeBounds::DEFAULT` bounds
each exchange with a per-prompt and an aggregate timeout
(`src/gateway/input_bridge.rs:492-520`), so a spawned dispatch cannot outlive its
bounds and the number in flight is bounded by how fast a client can ask. Bounding
the spawn itself instead — a semaphore the loop waits on — reintroduces exactly
the stall STDIO.1 forbids, because the loop would block on capacity while the
answer it is waiting for is the next line to read. If an admission bound is wanted
later it must be a non-blocking check that *refuses* over capacity, never one that
stalls the reader; it is not proposed here because the stdio client is the process
that spawned this one and already holds whatever the operator holds (the same
reasoning that makes stdio `is_admin: true`, `src/gateway/server/mod.rs:2317-2326`),
so it can exhaust this process far more directly than by queueing requests.

**EOF.** The loop's existing exit path persists telemetry, drops the idle reaper
and the health loop, awaits `warm_start_tasks.cancel()` and calls
`backends.stop_all()` (`:1713-1729`). Spawned dispatches are not visible to any of
that today because none exist. They are held in a `JoinSet` and awaited before
teardown, so a client that closes stdin after issuing work still gets its
responses rather than having its backends stopped out from under it. The wait
inherits the same `BridgeBounds` ceiling every dispatch already has, so it is
bounded without a second timeout.

Two consequences worth naming rather than discovering:

- A `tools/call` that arrives *before* `initialize` runs inline. If that call
  bridges, the loop is inside a dispatch that is waiting for an answer it cannot
  read, and the exchange ends at the bridge's own timeout with the same refusal a
  silent client gets. No real client does this, and the alternative — spawning
  before initialize — is what item 2 of the prior review forbids. A batch that
  arrives before `initialize` is the same case for the same reason: it runs
  inline, so a bridging member stalls the reader until its bounds expire. After
  initialize the batch is spawned and the stall is gone; the residual is confined
  to the window where no client has yet been told the protocol version.
  <!-- ponytail: bounded by BridgeBounds; per-request init gating if a client ever needs it -->
- `protocol_telemetry_sink` is passed as `Option<&mut DurableTelemetrySink>`
  (`:1701`), and a `&mut` borrow cannot cross into a spawned task any more than
  `&mut stdout` can. It becomes a shared handle of the same shape as the writer,
  and `persist_stdio_protocol_telemetry` (`:1731`) runs at the end of each
  spawned dispatch rather than on the loop. This is the second `'static` blocker
  and the reason the spawn is not a one-line change.

## 6. How the client is reached

`InputBridge` (`src/gateway/input_bridge.rs:361-370`) reaches a client through a
`&dyn ClientChannel`. It is already transport-agnostic: `run`, `plan` and `ask`
need no change, and no new trait method is added. What is added is one
implementer.

`StdioClientChannel` holds two things: a clone of the shared writer from §4, and
a `DashMap<String, oneshot::Sender<Value>>` of questions awaiting an answer. Its
`send_request(session_id, id, method, params)`:

1. refuses `DeliveryError::NoSession` unless `session_id` is `STDIO_SESSION_ID` —
   one process, one session, and a mismatch means the caller is not this
   transport's;
2. registers `id` in the pending map and takes a drop guard over that entry
   *before* writing anything;
3. writes `{"jsonrpc":"2.0","id":<id>,"method":<method>,"params":<params>}`
   through the shared writer, one whole frame under one lock;
4. awaits the `oneshot` and returns the reply frame **whole**, because
   `InputBridge::project` reads `reply.get("error")` and `reply.get("result")` off
   the envelope, not off a pre-extracted result.

**Ids need no namespacing mechanism.** `InputBridge::ask` mints the id itself —
`format!("{}{}", prompt.kind.prefix(), uuid::Uuid::new_v4())`
(`src/gateway/input_bridge.rs:492`), with prefixes `sampling-`, `elicitation-`,
`roots-`. The channel never mints one; it registers the id it is handed and
matches the reply against it. The `next_id` counter named in the earlier revision
of this item belongs to the outbound transport (`src/transport/stdio.rs:561`) and
is not on this path at all, so there is no counter here to stay disjoint from.

What actually keeps a client's own ids out of the bridge is the routing rule in
§5, not the id format: a frame is a candidate answer only if it carries no
`method` **and** its id is currently in the pending map. A client request reusing
a bridge id still carries a `method` and is dispatched normally; a client response
to some other gateway request carries an id that was never registered and gets
today's `-32600`. The prefixed-UUID shape makes a collision vanishingly unlikely
on top of that, but it is the second line of defence, not the first.

**The guard is the cancellation contract, not an optimisation.** `ask` wraps every
`send_request` in an outer `tokio::time::timeout` and abandons the future on
expiry (`src/gateway/input_bridge.rs:271-296`). An implementation that registers
pending state before awaiting must release it on drop or the map grows one entry
per timed-out question for the life of the process, and a late answer finds a
sender nobody is listening on. `PendingRequestGuard`
(`src/transport/mod.rs:185-208`) is the right shape and the wrong type — it is
`pub(crate)` over `DashMap<String, oneshot::Sender<JsonRpcResponse>>`, and the
bridge's replies are `Value` envelopes, not `JsonRpcResponse`. Mirror the shape
locally in the channel's module; do not generalise the existing guard for one new
caller. Recorded as MIK-7388 on the trait's own doc.

**Wiring.** `stdio_caller_context` (`src/gateway/server/mod.rs:2306`) takes the
channel by reference alongside `era` and `retry`, and three of its fields change:

- `channel` — the `StdioClientChannel` instead of `&NoClientChannel`;
- `input_capabilities` — `shape.declared_capabilities()`, the same value the HTTP
  path passes (`src/gateway/router/handlers.rs:877`, used at `:1506` and `:1636`).
  The claim it replaces, "stdio carries no per-request capability declaration to
  read", is false: `_meta` is transport-independent and `classify_and_observe` is
  already called on the stdio path (`src/gateway/server/mod.rs:1903`) — its result
  is used for the era and the log level and then the declaration half is thrown
  away;
- `era` — pinned to `Era::Legacy` rather than taken from `shape`. Stdio has no
  modern path wired: `server/discover` returns the legacy document
  unconditionally on this transport, and the stateless revision is specified over
  streamable HTTP. A stdio caller is therefore legacy whatever its `_meta`
  declares, which is also how the requirement words it — "a legacy stdio client".
  `caller.era` has exactly one production reader, the bridge branch at
  `invoke.rs:1821`, so this changes nothing else; the `initialize` arm keeps
  advertising against `shape.era()` directly (`:1945`) and is not routed through
  the caller context.

`dispatch_single_with_sink` (`:1876`) passes the channel down to that helper. The
batch path reaches the same helper (`dispatch_batch_with_sink`, `:2047`), so one
parameter covers both.

## 7. Impact analysis

`gitnexus_impact`, direction upstream, repo `mcp-gateway`, run against every
symbol this design proposes to edit. **No target returned HIGH or CRITICAL; every
one is LOW.**

| Symbol | Impacted | d=1 | Processes | Risk |
|---|---|---|---|---|
| `run_stdio` | 0 | 0 | 0 | LOW |
| `dispatch_single_with_sink` | 21 | 4 | 1 (`run_stdio`, earliest broken step 1) | LOW |
| `stdio_caller_context` | 17 | 2 | 1 (`run_stdio`, earliest broken step 1) | LOW |
| `write_response` | 1 | 1 | 1 (`run_stdio`) | LOW |
| `invoke_tool_traced` | 1 | 1 | 0 | LOW |

The d=1 sets are small and entirely in-file. `dispatch_single_with_sink` breaks
`run_stdio`, `dispatch_single` (`#[cfg(test)]`, `:1827`), `dispatch_batch_with_sink`
and one named test; `stdio_caller_context` breaks `dispatch_single_with_sink` and
`stdio_caller_context_carries_the_clients_idempotency_key`; `write_response`
breaks only `run_stdio`, and this design does not change its signature at all —
it is listed because its call sites move under a lock. `invoke_tool_traced`'s only
caller is `invoke_tool`, and the change proposed there is comment text (§8), not
behaviour.

Two symbols this design touches are **absent from the index**:
`dispatch_streaming_notifications` and `write_notification` both return
`Target not found`. Recorded rather than skipped. Their call sites, verified by
grep instead: `dispatch_streaming_notifications` has five —
`src/gateway/server/mod.rs:1674` and `:1695` in `run_stdio`, and `:2382`, `:2418`,
`:2434` inside `#[cfg(test)] mod stdio_forward_path_tests` (`:2354-2355`);
`write_notification` has two, both inside `dispatch_streaming_notifications`
(`:1793`, `:1801`). Re-run `npx gitnexus analyze` before implementation so the
index covers them.

One more signature-shape guard to keep green: `stdio_dispatch_builds_its_retry_fields_from_the_request`
(`:3983`) locates `fn stdio_caller_context<'a>(` by string and then scans the next
2000 characters for the `retry` field. Adding parameters leaves the search string
intact, but the field moves further down the body — check the window still
reaches it.

## 8. The production comments this makes stale

`src/gateway/meta_mcp/invoke.rs:1884-1895` documents why the bridge's
`NoSession` arm cannot be reached from stdio, and asks to be re-read if either
half moves:

> …`plan` — which refuses requests that are *present and undeclared*… then
> refuses every one of them, because `stdio_caller_context` declares
> `Declared::NONE`. `run` calls `plan` before `ask`, so that refusal lands as
> `Refused` one step before any delivery is attempted, never as `NoSession`.…
> change `Declared::NONE` or `plan`'s position and re-read this arm.

This design changes `Declared::NONE`, so the arm is stale by its own terms and
must be rewritten in the same change. It is also **already inaccurate in one
respect**, independent of this design: with `Declared::NONE`, the MRTR.9 gate at
`:1781` refuses the interim result before the bridge branch at `:1821` is
evaluated at all, so `plan` is not what refuses a stdio caller today — nothing on
the stdio path ever reaches `plan`. Proposed replacement:

> This arm does not reach stdio, and the reason is worth naming because no test
> enforces it. A stdio caller now arrives with a real declaration
> (`stdio_caller_context` passes `shape.declared_capabilities()`) and a real
> channel (`StdioClientChannel`), so the bridge is the right messenger for it.
> What this arm needs is `NoSession`, and the stdio channel produces that only
> when the session id is not `STDIO_SESSION_ID` — which the one caller that
> builds it cannot get wrong. Every other stdio failure is some other variant:
> `Refused` when the client declared nothing, or nothing of the kind asked for,
> or a mode it did not declare; `Delivery { TimedOut }` or `Deadline` when the
> client does not answer; a projection error when it answers something
> unreadable. Change the stdio session id or give that channel a second caller
> and re-read this arm.

The missing `MIK-7212.WIRE.10` row in the MRTR.7 test plan — named in the current
comment as the thing that joins the two halves, and still absent — is superseded
rather than filled: `MIK-7387.STDIO.1` is the row that pins the stdio bridging
behaviour end to end, and the two halves it was to join no longer exist as a pair.

Two field comments on `MetaMcpCallerContext` go stale in the same change, and
both are the kind that quietly restore the old value if left standing.

`input_capabilities` (`src/gateway/meta_mcp/mod.rs:143-145`) reads "On stdio there
is no per-request declaration to read, so this is `Declared::NONE`". That is the
claim §6 refutes: the declaration is in the same `_meta` the HTTP path already
parses, and `classify_and_observe` is already called on this path. Replacement:

> Every transport that dispatches supplies this from the request's own
> classification: both the HTTP handler and the stdio loop read it off the
> `RequestShape` they already hold, via `RequestShape::declared_capabilities`. A
> caller that declared nothing is still never sent a continuation — absent means
> absent — but absent is now a fact about the request, not about the transport.

`era` (`:171-176`) reads "until it does, nothing on the production path reads this
field". That is already false before this design: the bridge branch at
`invoke.rs:1821` reads it. Replacement:

> Read on the production path by the bridge branch in `meta_mcp::invoke`, which
> takes the in-band route only for `Legacy`. Stdio pins `Legacy` at
> `stdio_caller_context` because it has no modern continuation path to fall back
> to; `initialize` keeps `shape.era()`, because what it advertises must be what
> the client declared.

That pin is the one place this design writes an era that is not the era the
client declared, and it is worth naming as a risk rather than a detail: a second
production reader of `caller.era`, added later for any purpose other than
choosing between in-band and continuation, would read `Legacy` for a stdio caller
that declared a modern revision. The narrower alternative — gate the bridge
branch on the channel rather than the era — was not taken because it edits a
condition shared with HTTP to fix a stdio-only fact, and the blast radius runs
the wrong way. The mitigation is the doc comment above, which says what the pin
means and what it does not.

## 9. Explicitly out of scope

- The outbound backend transport `src/transport/stdio.rs` in every part:
  `handle_response`'s refusal arm and its pinning test, `write_message`'s mutex,
  the `next_id` counter, `PendingRequestGuard`'s existing instances (§2).
- `InputBridge::run`, `plan`, `ask`, `project`, and the
  `ClientChannel`/`BackendInvoker`/`BridgeObserver` trait definitions — unchanged;
  one new implementer is added and `NoClientChannel` stays for every caller that
  still has no channel.
- The HTTP `ClientChannel` implementation, `ProxyManager`, and anything under
  `src/transport/http/`.
- Concurrency across a batch: batches stay sequential (§5).
- `NFR.COMPAT.1`'s stdio protocol-revision question and the `is_admin: true`
  stdio grant — both out under
  `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md`'s OUT list and not
  reopened here. Pinning `era` to `Legacy` in the caller context (§6) is not that
  question: it changes one predicate with one production reader and does not touch
  what `initialize` advertises.
- Making a capability declared at `initialize` durable for the rest of the
  session (§11.4). Gateway-wide, both transports, no row in this scope.
- Widening the three acceptance tests. `RELEASE-4.0.0-scope-tests.md:15-17` names
  the surface; the rows are satisfied by the three existing ACs with `#[ignore]`
  removed (§10), and this work package is design-only — it adds no test and edits
  none.
- `ConfirmationChannel::Unavailable` on stdio. Destructive-call confirmation is a
  different capability with its own row; a channel that can carry
  `elicitation/create` for MRTR does not automatically become the operator asker,
  and no requirement here asks for it.

## 10. The three ignored tests

All three are in `tests/mik_7212_mrtr7_stdio_acs.rs`, each with
`#[ignore = "MIK-7387: stdio concurrent dispatch is a separate work package; this
row is its spec"]` one line above the `fn`. **This design satisfies all three;
none is reported as unsatisfiable.**

- `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` (`fn` at `:356`) —
  MIK-7387.STDIO.1. Needs the declaration (§3.2), the era (§3.3) and the channel
  (§6) to emit `elicitation/create`, and the reply-routing arm (§5) to take the
  client's `{"id":<question id>,"result":{…}}` off the same pipe while the loop
  keeps reading. The backend then re-runs with `inputResponses` present and the
  fixture returns `answered` (`:150-155`), which is what `/result/content/0/text`
  is asserted against. The fixture asks in `form` mode (`:162`) and the client
  declares `{"elicitation": {}}`, which `Declared::parse` reads as form
  (`src/protocol/meta.rs:416-419`), so the mode arm of `Refusal` passes too.
- `ac_mrtr_7a_bridged_request_follows_the_initialize_response` (`fn` at `:421`) —
  MIK-7387.STDIO.2. Guaranteed by the init gate in §5, not by timing: the
  initialize response is written by the loop before any dispatch is spawned, so no
  bridge frame can precede it even though the test sends both requests without
  waiting.
- `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` (`fn` at `:471`) —
  MIK-7387.STDIO.3. Two spawned dispatches each emit one `elicitation/create`
  through the shared writer of §4; exactly two frames, and every emitted line is a
  whole JSON value because a frame is written under one lock. Neither question is
  answered, so both end at `BridgeBounds::DEFAULT` — the test asserts on the
  frames, not on the outcome.

## 11. Findings

Three corrections to the record, each verified at source.

1. **There is one production `NoClientChannel` stdio site, not two.** The brief
   and the previous revision of this document both name
   `src/gateway/server/mod.rs:2339` and `:2933`. `#[cfg(test)]` is at `:2445` and
   `mod tests {` at `:2446`, so `:2933` is inside the test module — a hand-built
   context in `ac_confirm_1a_the_refusal_marker_never_reaches_the_wire`. The only
   production wiring is `stdio_caller_context` (`:2306`, field at `:2339`), called
   once at `:2002`. This is the "test-only call site described as production
   wiring" the sixth pending revision named.
2. **The test line numbers in circulation are wrong in both directions.** The
   brief cites `:354/:419/:469` and the previous revision `:356/:420/:470`. The
   `fn` lines are `356`, `421` and `471`; the `#[ignore]` attributes are at `355`,
   `420` and `470`. §10 cites the `fn` lines.
3. **A channel alone would not have passed a single AC.** The declaration and the
   era (§3.2, §3.3) are each independently fatal, and both sit upstream of any
   channel call. Had this design shipped as "implement `ClientChannel` and wire it
   at the `NoClientChannel` sites", all three tests would have failed with no
   `elicitation/create` frame emitted and no channel method ever invoked.
4. **A capability declared only at `initialize` is still not read, and that is
   gateway-wide, not stdio's.** `caller.input_capabilities` is per-request
   everywhere: HTTP derives it from `shape.declared_capabilities()`
   (`src/gateway/router/handlers.rs:877`) and nothing stores the `initialize`
   handshake's `capabilities` object for later requests to inherit — no session
   capability store exists in this tree. A legacy client that declares
   `elicitation` on the handshake and omits `_meta` on its `tools/call` is refused
   by the MRTR.9 gate on HTTP today and will be refused on stdio after this
   change, identically. The ACs are written to match that contract — the fixture
   declares in both places and says so
   (`tests/mik_7212_mrtr7_stdio_acs.rs:293-296`). Making the handshake's
   declaration durable for a session is a real question, applies to both
   transports, and is not this requirement: none of STDIO.1-3 mentions it and
   changing it here would alter HTTP behaviour under a stdio row. Out of scope
   (§9), recorded so the next reader does not mistake it for an oversight.
