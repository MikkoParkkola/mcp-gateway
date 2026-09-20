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

An `mpsc::Sender<Value>` bounded at `STDOUT_QUEUE_DEPTH` (1024) feeding a single
task that owns `tokio::io::stdout()` and writes one serialized frame plus `\n`
per message.
Every producer — responses and outbound requests alike — sends on that channel
and never touches stdout. This is what makes row 324's framing assertion true
by construction rather than by luck: with a shared unlocked writer, two tasks
serializing into the same handle can interleave mid-frame.

The queue was unbounded when this document was first ratified, on the argument
that the writer only writes and never waits on a dispatch task, so a bounded
queue could not deadlock against it, and that the only producer worth throttling
is a client that has already been served. That argument still holds for
deadlock. It was superseded on memory: an unbounded queue lets a client that
stops reading stdout grow the process without limit, and "one spawned client"
is not a trust boundary — a buggy client reaches the same state as a hostile
one. `STDOUT_QUEUE_DEPTH` (1024) is the bound that replaced it, and the cost is
that a producer can now park on a full queue. `close` racing that park is a
known defect, tracked against `src/gateway/server/stdio_channel.rs:124`.

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
pending: DashMap<String, oneshot::Sender<Value>>
writer:  mpsc::Sender<Value>            // bounded, STDOUT_QUEUE_DEPTH
```

`send_request` registers the oneshot under `id` behind
`PendingRequestGuard::new(&self.pending, id)` (`src/transport/mod.rs:151`,
already `pub(crate)` and therefore reachable from the gateway module with no
visibility widening), enqueues the request frame, then awaits the receiver.

The guard is not stylistic. `InputBridge::ask` wraps every call in
`tokio::time::timeout`; on expiry the future is dropped and neither the success
nor the error path runs, so a hand-rolled map leaks one entry per timed-out
prompt for the life of the session.
`cancelled_request_does_not_strand_pending_entry`
(`src/transport/stdio.rs:815`) already pins the guard's behaviour.

The map carries the **raw reply frame** as a `Value`, not a `JsonRpcResponse`.
That is what the only other `ClientChannel` implementation returns
(`ProxyManager::send_request`, `src/gateway/proxy.rs:523`); the `result`/`error`
projection happens downstream in `InputBridge::ask`, and projecting here would
give the bridge a different input on stdio than on HTTP. `PendingRequestGuard`
is therefore made generic over its payload — one guard, two maps, rather than a
second copy of the cancellation contract to keep in sync.

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
reply; await the dispatch `JoinSet` to completion under a bounded timeout; close the writer channel and await the
writer task, which flushes what is queued; only then drop the backend guards.

`close` is terminal, and that is what makes the drain bounded in practice
rather than only on paper. Waking the prompts already outstanding lands them as
`DeliveryError::TimedOut` — the dropped sender is the same signal a vanished
HTTP session produces. A prompt raised *after* the close, by a dispatch that
reaches its question inside the drain window, is refused with
`DeliveryError::NoSession`: without the terminal flag it would register an
entry nothing can resolve and wait out the bridge's own timeout, spending the
drain that exists to deliver its response.

`AbortOnDrop` stays, demoted to what it is good at: the cancellation path, where
`run_stdio`'s own future is dropped and there is no one left to flush to.

Completed tasks are reaped from the `JoinSet` as the loop runs, not only at
shutdown — otherwise a long session accumulates task records and a panicking
dispatch stays invisible until EOF.

## What could go wrong

| Risk | Mitigation |
|---|---|
| Unbounded spawn under a flood of inbound lines | A bound was added after ratification: `MAX_CONCURRENT_STDIO_DISPATCHES` (64), held as a semaphore permit for the life of each dispatch. The bound is enforced by awaiting a permit **inside the read loop**, which is itself a defect — see the row below |
| Awaiting an admission permit parks the only stdin reader | OPEN, confirmed at `src/gateway/server/mod.rs:2552`. Past 64 concurrent bridged dispatches the 65th line blocks the reader, and the replies those 64 are waiting for can only be routed by the reader now parked. This is the N=1 deadlock this document exists to remove, relocated to N=65. Admission must become non-blocking |
| A dispatch that never finishes stalls the EOF drain | The drain is bounded; past the bound the abort guards fire, which is strictly today's behaviour and no worse |
| Telemetry lock contention | One `std::sync::Mutex` around a synchronous persist, never held across an await (§5) |
| Out-of-order responses break an unknown consumer | Searched the three stdio test files; only row 323 asserts ordering, and §2 preserves it |

## Acceptance

**Corrected during implementation.** The three rows above are *not* acceptance
for this work package, and the first draft of this section was wrong to claim
them. Each needs an outbound `elicitation/create` frame on the pipe, which needs
a production caller of `InputBridge` — and there is none. `rg -n 'InputBridge'
src/` returns the definition (`src/gateway/input_bridge.rs:348` and `:359`) and
two doc-comments, zero constructions; `rg -n '\.channel\b' src/` returns one
reader, `src/gateway/input_bridge.rs:491`. The interim arm of
`src/gateway/meta_mcp/invoke.rs` never mentions the bridge: `:1779` computes
`InputRequired::from_result` and `:1852` mints a continuation envelope in its
place, which is what goes back to the client. Both design reviews graded the
mechanism; neither asked whether the component under test had a caller.

The rows therefore keep their `#[ignore]`, with a reason naming that line. They
are acceptance for the wiring commit that follows this one, which also unblocks
`MIK-7388.CANCEL.1` (`docs/requirements/RELEASE-4.0.0-scope-update.md:36`) —
cancelling a *real* bridged exchange needs the same caller.

Acceptance for this package, the transport half, is:

- `tests/stdio_tests.rs` and `tests/nfr_compat_2_stdio_client_session.rs`
  unchanged and still green — the regression evidence that concurrency did not
  cost sequential correctness;
- one test added for the §6 behaviour no acceptance row covers,
  `ac_mrtr_7a_request_in_flight_when_stdin_closes_still_gets_its_response`: a
  request in flight when stdin closes still receives its response. Nothing in
  the three rows exercises EOF, so without it the drain is unpinned and the next
  refactor re-introduces the abort;
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean.

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

## Addendum, 2026-09-16: non-blocking admission

Ratified after two independent reviews (gpt, kimi), both SHIP-WITH-FIXES, both
selecting this shape over the alternatives. It replaces the admission step in
§2; nothing else in this document changes.

### The defect it closes

Awaiting a permit inside the read loop parks the only stdin reader. Past
`MAX_CONCURRENT_STDIO_DISPATCHES` concurrent bridged dispatches, the next line
blocks the reader, and the replies those dispatches wait for can only be routed
by the reader now parked. That is the N=1 deadlock this document was written to
remove, relocated to N=65.

### The shape

Two semaphores, one idiom. `admission` (64) keeps its meaning: how many
dispatches may run at once. A second, `MAX_INFLIGHT_STDIO_REQUESTS` (1024,
matching `STDOUT_QUEUE_DEPTH`), bounds accepted-but-unfinished work and is the
one the read loop consults — with `try_acquire_owned`, never an await. The
owned permit moves into the spawned task and is released when it ends. The read
loop never parks on admission again.

Rejected: counting `dispatches.len()` after a drain. Both reviewers flagged it
independently — a `JoinSet` may still hold entries for tasks that have already
finished, so the count over-reports and rejects requests below the real cap. The
existing reap at `src/gateway/server/mod.rs:2451` stays exactly as it is; it
matches on the join result and logs a panicking dispatch, which a bare
`while ... .is_some() {}` drain would have thrown away.

### Four constraints the implementation must satisfy

1. **Stdout death must still exit the loop.** Moving the permit wait into the
   task deletes the loop's only `stdout_died = true; break;`. Without a
   replacement, a dead writer with stdin still open leaves the loop reading
   lines forever and spawning tasks that do nothing. A non-blocking
   `writer.is_closed()` check stays in the loop and breaks.
2. **The refusal must not park the loop either.** Writing the busy error with
   an awaited send on the bounded queue reintroduces the exact defect on the
   rejection path. Use `try_send` and drop on failure — a full queue means the
   answer was undeliverable anyway.
3. **Only requests get a refusal.** A notification carries no `id`, and a
   response to one is protocol-invalid. Saturated notifications are dropped and
   logged.
4. **Start order is NOT preserved, and was never guaranteed.** An earlier
   revision of this section claimed dispatches start in the order their lines
   were read, resting on tokio's `Semaphore` being FIFO. That reasoning is
   wrong and the claim is withdrawn. The semaphore hands out permits in the
   order they were *requested*, and under this design each request is first
   made inside its own spawned task — so the queue is ordered by the
   scheduler's choice of which task to poll first, not by stdin order. The
   superseded version reasoned about the old code, where the reader itself
   awaited the permit in line order; that ordering was a by-product of the
   very await that deadlocked the loop, and it leaves with it.

   Accepted, not merely observed. JSON-RPC pipelining carries no ordering
   guarantee for concurrent requests: a client that sends without waiting has
   asked for concurrency. The one ordering the gateway does owe — the
   `initialize` response before any frame a later line produces — is unaffected,
   because `initialize` is dispatched inline and takes no in-flight slot
   (`tests/mik_7212_mrtr7_stdio_acs.rs`, row 323). Restoring stdin start order
   would mean funnelling every admitted dispatch through one coordinator that
   awaits admission on the client's behalf, which reintroduces a single
   serialising point to buy a property no caller may rely on.

### Acceptance

- 65 pipelined bridge-producing calls, replies withheld until all are sent: no
  deadlock, every call answered.
- More than 1024 pipelined calls: the excess is refused with `-32000`, and the
  loop still routes replies for the accepted ones.
- Stdout closed mid-session with stdin open: the loop exits rather than
  spinning.

## Addendum, 2026-09-17: the acceptance rows above need no new seam

The previous addendum ratified three acceptance rows and none of them was ever
written. The recorded reason was that there is no seam: the read loop is inline
in `run_stdio` (`src/gateway/server/mod.rs:2286`, loop body at `:2457-2653`) on
`BufReader::new(tokio::io::stdin()).lines()` (`:2418`), so nothing in-process can
feed it. That is true of the read side and it is still true today — `rg` over
`src/gateway/server/` finds no generic reader; `run_stdout_writer`
(`mod.rs:2737`) is generic over its writer, and it is the write half only.

The conclusion drawn from it was wrong. The harness this package needs is not
in-process, and it already exists: `StdioSession::spawn`
(`tests/mik_7212_mrtr7_stdio_acs.rs:205-236`) starts the shipped binary with
`Command::new(env!("CARGO_BIN_EXE_mcp-gateway")).arg("serve").arg("--stdio")`
and piped stdin and stdout. It drives the real `run_stdio` over real pipes. Four
acceptance rows already use it; what none of them does is send more than a
handful of requests.

So the gap is the rows, not the machinery, and the work is test-only. That is a
correction to this document's own premise, recorded rather than quietly dropped,
because the release ledger, the blocking rollup and the readiness board all
repeat "the seam is unbuilt" as the thing holding `MIK-7212.MRTR.7a` and `.7b`.

**Why the out-of-process harness is the better one anyway**, not merely the one
that exists. The two properties under test are that the single stdin reader never
parks, and that the refusal path fires at the real cap. An in-process harness
would drive an extracted function past semaphores the test itself constructed; the
child process drives the real constants — `MAX_CONCURRENT_STDIO_DISPATCHES` = 64
(`mod.rs:83`), `MAX_INFLIGHT_STDIO_REQUESTS` = `STDOUT_QUEUE_DEPTH` = 1024
(`mod.rs:76,89`) — through the real `main`. The existing unit rows
(`mod.rs:5019-5060`) already show the weaker shape: they assert
`admit_stdio_request` against a synthetic `Semaphore::new(2)`, which cannot fail
the way the 1024 boundary fails.

### The two rows, as tests

Both go in `tests/mik_7212_mrtr7_stdio_acs.rs` beside the four rows that already
use `StdioSession::spawn`. Both park work by withholding a client answer: a
bridge-producing call makes the gateway send `elicitation/create` on the
client's channel, and a client that never answers holds that dispatch open for
as long as the test needs. Every read is bounded — `read_until_id` is under
`READ_TIMEOUT` (`:62`, 10s) and `collect_lines` takes an explicit window — and
the burst itself goes under a timeout too, so a gateway that stops reading fails
the row instead of hanging CI.

1. **`the_reader_keeps_reading_past_the_admission_cap`**

   Send `initialize` and **wait for its response** before anything else; an
   unsynchronised burst races initialization and produces errors that have
   nothing to do with the caps. Then send 65 bridge-producing calls with
   distinct ids and answer none. Drain stdout and assert exactly 64
   `elicitation/create` frames and no `-32000` for any of the 65.

   Then take the id of a prompt the test has **actually received** — never a
   predetermined one, since dispatch order is not stdin order (`9b0caa1e`) and
   the chosen call may be the one still parked — answer it, and assert two
   things: that call's response arrives, **and a 65th `elicitation/create`
   appears**. The second assertion is the one that matters. Without it a gateway
   that reads the 65th line and silently drops it passes green, which is the
   exact shape a careless "fix" to `d0c68e15` would take. With it, the reverted
   defect fails the row twice over: the parked reader never consumes the answer,
   so neither the response nor the 65th prompt arrives.

2. **`the_excess_past_the_inflight_cap_is_refused_not_queued`**

   Same synchronised `initialize`. Then 1023 bridge-producing calls: assert no
   `-32000` for any of them. Then three more: assert at least one `-32000 server
   busy`, and that **every** `-32000` carries an id from that trailing group.
   Nothing is answered, so no permit is released mid-burst, and the read loop
   consults `inflight` in line order — the first N accepted are the first N
   sent.

   Why 1023 plus a group of three rather than "send 1024, then assert the 1025th
   is refused": `initialize`'s own dispatch takes an inflight permit and releases
   it at `drop(slot)` (`mod.rs:2648`), which is not ordered against the response
   the test waited for. The observable boundary therefore carries one slot of
   slack. Pinning it to the window [1023, 1026] is what the harness can honestly
   assert, and it still fails any regressed cap — 64, 512 — which the weaker
   "at least one `-32000` somewhere in 1025" does not.

### Three traps this plan must not fall into

- **Drain stdout before asserting, and know why.** The recorded reason used to
  be queue overflow; at these sizes that is wrong. Admission is 64, so both rows
  put only about 66 frames on stdout (the `initialize` response, 64 prompts, one
  refusal) — far short of the 1024-slot queue and of the pipe buffer. Neither
  row reaches the dropped-refusal path closed by `fffc5fde`. The drain is still
  mandatory, for the ordinary reason that an undrained pipe shows the test none
  of the frames it asserts on. A row that genuinely fills the queue — answer
  every accepted call — is a different row and is not written here.
- **Stdin blocks too.** `StdioSession::send` has no timeout of its own. Writing
  1026 frames to a child that has stopped reading fills the pipe and parks the
  test, turning a regression into a CI hang instead of a failure. The burst goes
  under a timeout whose message names the frame it was writing.
- **The 65 row asserts acceptance, the 1026 row asserts refusal.** They cross
  different caps and they are not two sizes of one test. Row 1 crosses
  `admission` (64), where the correct behaviour is that work is admitted and
  parks inside its own task. Row 2 crosses `inflight` (1024), where the correct
  behaviour is refusal. A test that expects refusal at 65 would encode the
  rejected design.

Stderr needs no trap: `StdioSession::spawn` inherits it rather than piping it
(`tests/mik_7212_mrtr7_stdio_acs.rs:220-222`, with the reason in a comment).
Keep it that way — piping it for capture without a concurrent drain deadlocks
the child at this volume, which the existing handful-of-request rows never
reach.

### Verifying the rows before the criteria flip

A row that cannot fail proves nothing, and both of these assert against a
gateway that already works. Before `MIK-7212.MRTR.7a` and `.7b` are recorded
met, mutate and re-run: halve `MAX_INFLIGHT_STDIO_REQUESTS` and row 2 must go
red; reintroduce the inline `acquire_owned().await` of `d0c68e15` in the read
loop and row 1 must go red. Green against either mutation means the row does not
pin what it claims, whatever its name says.

### Record follow-through

The release ledger, the blocking rollup and the readiness board all hold
`MIK-7212.MRTR.7a` and `.7b` on "the seam is unbuilt". That premise is
overturned here, and the 2026-09-16 ruling rests on it. The hold itself stands —
the rows are still unwritten — but each of those records gets repointed at this
addendum, so the reason on file is the true one: the work is test-only.

### What this addendum does not change

The semaphore values, the non-blocking `try_acquire_owned` gate, the `try_send`
refusal, the silent refusal of notifications, and the withdrawal of the stdin
start-order claim (`9b0caa1e`) all stand exactly as ratified. The third
acceptance row — stdout closed mid-session with stdin open — is out of scope
here: it needs no saturation and it is not what the MRTR rows block on.

### Review, 2026-09-17

Two independent non-Claude seats on the plan above, before any test code exists:
`glm-5.3` and `deepseek-v4-pro:0813`. Both returned `VERDICT: SHIP-WITH-FIXES`.
(`gpt` is rate-limited until 2026-09-19 and `grok` returns 402, hence this pair.)
Every finding was adjudicated at source rather than taken on the reviewer's
word; the rows above are the revised ones.

Upheld and applied, both seats independently:

- Row 1 asserted nothing about the 65th request, so a gateway that reads it and
  drops it passed green. The row now answers a received prompt and requires the
  65th `elicitation/create` to appear.
- Row 2's "at least one `-32000`" stayed green for any cap between 65 and 1024,
  so it could not tell the real boundary from a regression. The row now pins the
  boundary to a window, with the one-slot slack explained rather than assumed
  away.
- Neither row waited for the `initialize` response before its burst. Both do now.
- Neither row said anything about the child's stderr. Checked at source: it is
  inherited, not piped, so the deadlock the seats warned about cannot happen —
  recorded rather than silently dropped, because a later row that pipes stderr
  for capture would reintroduce it.

Upheld and applied, one seat:

- `glm-5.3`: the answered call must be one the test has actually seen a prompt
  for. Answering a predetermined id assumes the start-order claim withdrawn in
  `9b0caa1e` and hangs whenever that id is the parked one.
- `glm-5.3`: the stdout-drain trap was misstated. At 64 admitted dispatches these
  rows emit ~66 frames and cannot fill a 1024-slot queue, so the mechanism named
  was not the one they face. Restated with its true binding condition; the drain
  stays mandatory for the ordinary reason.
- `glm-5.3`: nothing verified that the rows can fail. Added the mutation check —
  halve the inflight constant, restore the `d0c68e15` inline await — as a gate
  before the criteria flip.
- `glm-5.3`: the ledger, rollup and board still cite the overturned premise.
  Added as explicit follow-through.
- `deepseek-v4-pro`: "the harness reads and writes concurrently" was asserted
  without evidence. It was also false. `StdioSession` sends and reads on one task
  (`send`, `read_until_id`, `collect_lines`); there is no background drain. The
  sentence is gone, and checking it produced a trap neither seat named: `send`
  has no timeout, so a gateway that stops reading parks the test in a pipe write
  and turns a regression into a CI hang. That is the answer to "where does this
  correction overclaim" — there, and nowhere else found.

Recorded, not applied:

- `glm-5.3` proposed a further row: fill the stdout queue by answering every
  accepted call, then assert stdin answers are still consumed. That is the
  invariant's remaining leg and it is worth having, but it belongs with the
  deferred third acceptance row (stdout closed mid-session), not with the two
  rows `MIK-7212.MRTR.7a` and `.7b` block on.
