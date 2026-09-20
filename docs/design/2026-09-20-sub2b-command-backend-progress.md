# MIK-7272.SUB.2b — streaming a subprocess backend's progress

Status: **ratified**. Reviewed before any code, by two independent reviewers:
SHIP and SHIP-WITH-FIXES. The fixes are folded in below and the review record
is the closing section.

## The defect

`MIK-7272.SUB.2b` requires that request-scoped notifications reach the
response stream of their own request. For a `command:` backend — one the
gateway starts as a subprocess and speaks to over its stdin/stdout — they do
not. They arrive after the call settles.

Recovered evidence, on `fix/sub2b-command-backend-progress` at `edb1c0d9`:
`s02_progress_from_a_command_backend_reaches_the_client_before_the_result`
fails three runs out of three. Its companion
`a_command_backend_notification_with_no_client_token_is_not_forwarded`
passes, so the harness is sound and the gap is the path.

## Why it is shaped this way

Not an oversight. Two facts collide:

1. A peer notification carrying a progress token is pushed onto a `Vec`
   (`src/transport/stdio.rs:482`), and that `Vec` is published only from
   `ProgressRegistrationGuard::drop` (`:622-627`) — which runs when the call
   completes. Collect-then-emit, which ADR-014 §1 rejects.
2. The obvious repair — publish at capture time — silently drops everything.
   `notification_sink::publish` resolves its destination from a task-local
   (`SINK.try_with`, `src/transport/notification_sink.rs:113`), established by
   `scope` (`:64-74`) around the *caller's* future. The stdout reader task
   that captures the notification is a different task and has no `SINK` in
   scope. `publish_outside_a_scope_is_dropped_not_panicked` (`:302`) pins
   exactly that.

So the accumulation exists to move the notification from the reader task to
the caller's task, where the destination is reachable. It pays for that with
the latency the criterion forbids.

## Proposal

Carry the destination with the registration instead of carrying the payload
back to the destination.

`register_progress_token` (`src/transport/stdio.rs:451`) already runs on the
caller's task, before the request is written. That is the one point where both
the token and the caller's `SINK` are in scope. Clone the sender there and
store it against the token:

- `captured_notifications: DashMap<String, Vec<JsonRpcNotification>>`
  becomes a map from the minted token to a delivery handle carrying **both**
  the caller's own progress token as a `Value` **and** `Option<Sender>`.
  Carrying the token is not optional — see "the token must travel" below.
- `register_progress_token` reads `SINK.try_with(Sender::clone).ok()` and the
  caller's token from `TRANSLATIONS`, both on the caller's task. A `None`
  sender means the caller has nowhere to stream to; registration still
  happens, so the notification is still recognised as owned and dropped
  deliberately rather than logged as a stray.
- Insert **vacant-only**. A colliding live key must fail closed rather than
  evict the incumbent, or one call's progress reroutes onto another's
  channel.
- The capture site (`:482`) rewrites the token from the snapshot, then sends
  on the stored sender. The level filter does not move with it — see below.
- `ProgressRegistrationGuard::drop` deregisters the token and publishes
  nothing.

## What this changes that is not obvious

- **The token must travel.** This is the defect the review caught, and it
  would have shipped. `translate_back`
  (`src/transport/notification_sink.rs:243-275`) rewrites the gateway's minted
  `gw-<uuid>` progress token back to the token the caller actually sent,
  and it resolves that from the `TRANSLATIONS` task-local — the caller's,
  absent on the reader task. A handle carrying only a `Sender` therefore
  delivers on time but with the wrong token on it, and a caller correlating on
  its own token sees nothing. Snapshot the caller's token `Value` at
  registration and rewrite `params.progressToken` from it at capture.
  ADR-014 §2 already specified this shape; restoring it is not an invention.
- **The level filter is not load-bearing here.** `passes_level_filter`
  (`src/transport/notification_sink.rs`) returns `true` immediately for any
  method that is not `notifications/message`, so a progress frame is never
  filtered and `LEVEL` need not be snapshotted. Cloning it would be cargo.
- **Backpressure.** `publish` uses `try_send` and counts drops against a
  64-deep channel (`REQUEST_NOTIFICATION_DEPTH`). Sending from the reader task
  keeps `try_send` — a blocking send there would park the only stdin reader,
  the same failure the stdio admission gate exists to prevent.
- **Ordering against the response.** Today the notifications are published
  before the guard's owner returns the response, so ordering is incidental.
  Streaming makes it real: a notification must not overtake a response for a
  *different* call, and must precede its own.
- **Lifetime.** A sender outliving its request is a leak with a live channel
  on the end of it, worse than a leaked `Vec`. Deregistration in `Drop` is
  load-bearing and needs the same reuse and overwrite guards the current
  keyspace comment (`:445-450`) already names.

## Acceptance

The two recovered rows, unmodified, both green — and the progress row proven
red against the current tree first, which it already is. Beyond them, four
cases the review asked for, because moving delivery across a task boundary is
where they break: two concurrent calls each see only their own progress; a
cancelled call leaves no live sender behind; a sink filled past its 64-deep
bound counts the drop against `DROPPED` the same way the HTTP path does; and
a caller that sent a numeric progress token gets a numeric one back.

The stdio unit rows that currently assert collect-then-emit
(`src/transport/stdio.rs:1254` and its neighbours) must be rewritten to assert
live, exactly-once delivery. Left as they are they would pass while the client
receives each frame twice — a live send plus the leftover `Drop` publish.

## Rejected

- Publishing at the capture site with the existing task-local. Drops silently.
- Draining on a timer rather than on `Drop`. Turns a deterministic ordering
  bug into a flaky one.
- Widening the criterion to exempt subprocess backends. The transport is not
  the reason the notification matters.

## Review

Two independent reviewers, on the design, before any code.

One returned SHIP. The other returned SHIP-WITH-FIXES on a HIGH finding: the
proposal as first written stored only the sender, leaving the caller's
progress token behind. That was verified at source rather than taken on the
reviewer's word — `translate_back` does resolve the caller's token from a
task-local the reader task does not have — and the proposal above is the
corrected shape. The same reviewer's second point, that the level filter never
runs on a progress frame, was likewise verified and the filter dropped from
the design; the first reviewer had asked for it to be bundled in, which would
have been dead weight.

Both reviewers noted they did not run the failing test. That is accurate and
does not weaken the diagnosis: it was run three times here, and the reviewers
confirmed the mechanism by reading the code.
