# MIK-7272.SUB.2b — streaming a subprocess backend's progress

Status: proposed, unreviewed. No code written against it yet.

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
  becomes a map from token to `mpsc::Sender<JsonRpcNotification>`.
- `register_progress_token` reads `SINK.try_with(Sender::clone).ok()`. `None`
  means the caller has nowhere to stream to; registration still happens, so
  the notification is still recognised as owned and dropped deliberately
  rather than logged as a stray.
- The capture site (`:482`) sends on the stored sender. The level filter and
  `translate_back` currently applied inside `publish` move with it.
- `ProgressRegistrationGuard::drop` deregisters the token and publishes
  nothing.

## What this changes that is not obvious

- **Where the filter runs.** `passes_level_filter` and `translate_back` read
  the `LEVEL` and `TRANSLATIONS` task-locals. Those are the caller's, and the
  reader task does not have them either. Both must be resolved at
  registration alongside the sender, or moved to the receiving end. This is
  the part most likely to be wrong, and it is the reason this is a design and
  not a patch.
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
red against the current tree first, which it already is.

## Rejected

- Publishing at the capture site with the existing task-local. Drops silently.
- Draining on a timer rather than on `Drop`. Turns a deterministic ordering
  bug into a flaky one.
- Widening the criterion to exempt subprocess backends. The transport is not
  the reason the notification matters.
