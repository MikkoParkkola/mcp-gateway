# Idle backend hibernation: making `idle_timeout` real

Status: **BLOCKED on design.** Two attempts, two DO-NOT-SHIP verdicts. Do not
deploy either. The branch is kept for its analysis, not as a candidate fix.
Branch: `fix/idle-timeout-shared-hibernation`
Date: 2026-07-26

## The central tension (read this first)

**Periodic health probing and idle hibernation are fundamentally opposed, and
no amount of reaper or clock tuning reconciles them.**

`health_probe` exists to guarantee a backend is up. It calls `ensure_started()`,
which starts a transport that is not running. Hibernation exists to let an idle
backend's transport die. Run both and the health loop simply restarts whatever
the reaper stopped.

Attempt 2 fixed the *clock* (health probes no longer refresh `last_used`) but
not the *respawn*. The result is worse than the original bug:

1. Reaper hibernates an idle stdio child (60s sweep).
2. Within ~10s the health loop calls `ensure_started()`.
3. The child is respawned and re-initialised.
4. Repeat forever.

That trades one idle long-lived child for **continuous spawn/kill churn every
~10 seconds**. Strictly worse than doing nothing.

Any correct design must first answer: *what does health-checking a
deliberately-hibernated backend mean?* Plausible answers, none yet chosen:

- Health probes skip hibernated backends, and status reports them as
  `hibernated` rather than unhealthy or unknown.
- Health probes become non-starting: observe liveness only if a transport is
  already up, otherwise report "asleep" without starting one.
- Hibernation is opt-in per backend and mutually exclusive with health checks
  for that backend.

Until that question is answered deliberately, this feature cannot ship.

## The bug

Per-backend `idle_timeout` is dead config. It is parsed into `BackendConfig`
(`src/config/mod.rs:723`), documented in `examples/gateway-full.yaml:225` as
"Hibernate after 5 min idle", and then read by exactly one thing in the entire
codebase: a `Debug` formatter.

```
$ rg -n '\.idle_timeout' --glob '!target' --glob '!*_tests.rs' .
./src/config/mod.rs:765:  .field("idle_timeout", &self.idle_timeout)
```

Nothing enforces it. `evict_idle_per_user_entries` runs on a hardcoded
`PER_USER_IDLE_TTL = 300s` and deliberately skips `PoolKey::Shared`, with the
comment "whole-backend hibernation remains future work"
(`src/gateway/server/mod.rs:1275`, pre-change).

A single-tenant stdio backend lives in the Shared slot. Nothing reaps it, so
its child process runs until gateway shutdown.

Observed 2026-07-26: a `trvl mcp` child alive for 3d 7h having burned 10.4
CPU-hours, spinning at 65-87% CPU. `idle_timeout: 10m` was set in
`servers.yaml:288` and had no effect.

## Why the first attempt failed

The first implementation hibernated the Shared slot's *transport* in place
(closing it, terminating the child) while leaving the `PooledEntry` in the
pool, so `shared_entry()`'s `.expect("...never evicted")` invariant held and
the circuit breaker and health metrics survived. `ensure_entry_started`
already treats a `None`-or-disconnected transport as "start it", so the next
request would respawn.

That part of the design is sound and worth keeping. It shipped as a no-op
anyway, for a reason adversarial review caught and direct inspection
confirmed.

### Critical: health probes keep every backend permanently warm

`ensure_entry_started` calls `entry.touch()` unconditionally at the top of
every attempt, *before* the fast-path connected check:

```rust
// src/backend/lifecycle.rs:188-189
self.last_used.store(now_unix_secs(), Ordering::Relaxed);
entry.touch();
```

`health_probe` calls `ensure_started()` (`lifecycle.rs:590`), which is
`ensure_entry_started(&PoolKey::Shared)`. The health loop runs on
`health_config.interval`, defaulting to **10 seconds**
(`src/config/features/failsafe.rs:28`), against a default `idle_timeout` of
300s.

So `now - last_used` never exceeds ~10s and the cutoff is never reached.
Hibernation cannot fire under the default configuration.

This also reframes the original incident. The idle `trvl` child was not merely
un-reaped; the health loop was actively keeping it warm, and `health_probe`
force-restarts it on failure. The process was being deliberately maintained.

**Root cause: `last_used` conflates two different things.** It answers "when
did anything last call `ensure_entry_started`", when hibernation needs "when
did a *client* last use this backend". Internal health traffic and real
traffic are indistinguishable. No amount of reaper tuning fixes this; the
signal itself is wrong.

## Confirmed defects in the first attempt

1. **`last_used` conflation** (above). Blocking. The change is a no-op without
   it.

2. **`start_lock` does not cover the request fast path.** `ensure_entry_started`
   clones a connected transport under a *read* guard before ever acquiring
   `start_lock`. Interleaving: reaper takes `start_lock`, sees idle; request
   fast-path clones the transport; reaper takes and closes it. The caller now
   holds an `Arc` to a closed transport. `Arc` preserves the Rust object, not
   the child process or pipe, so the request fails spuriously and any retry
   reuses the same dead handle rather than re-entering `ensure_entry_started`.

3. **In-flight requests are indistinguishable from idle ones.** `last_used`
   records when a request *started*. A call outliving `idle_timeout` has its
   transport closed mid-flight. The backend semaphore is backend-wide, not a
   per-slot activity count, so the reaper cannot consult it.

4. **`run_stdio` never spawns the reaper.** The idle checker is spawned only in
   the HTTP serve path (`server/mod.rs:~1273`). `run_stdio`
   (`server/mod.rs:1434`) warm-starts backends and enters its read loop with no
   reaper, so stdio-mode deployments get nothing.

5. **Repurposing `idle_timeout` for per-user slots is a semantic change.**
   The first attempt pointed both reaper call sites at `idle_timeout`. An
   operator who set a short value expecting it to control *backend hibernation*
   would also start destroying per-user sessions at that cadence, discarding
   stateful HTTP sessions, OAuth refresh state, and per-user breaker history.

6. **Sub-second `idle_timeout` truncates to immediate expiry.**
   `idle_ttl.as_secs()` makes any value below 1s a cutoff of 0, so every entry
   is eligible on every scan, including one touched in the same wall-clock
   second.

Two review concerns were checked and dismissed with evidence:

- *Guard held across await*: unfounded. The `parking_lot` write guard is
  dropped at the end of the `let` statement. Proven by construction, not by
  reading drop rules: `RwLockWriteGuard` is `!Send` and the reaper body is
  inside `tokio::spawn`, which requires `Send`. Deliberately rewriting the code
  to hold the guard across the await fails to compile with "future is not
  `Send` as this value is used across an await". The shipped form compiles.
- *Lock-order deadlock*: unfounded. `ensure_entry_started` scopes and releases
  its transport read guard before awaiting `start_lock`, then takes the
  transport lock. Same `start_lock -> transport` order both sides.

## Design for the second attempt

**Keep:** hibernate the transport in place, leave the `PooledEntry` in the
pool. That correctly preserves the `shared_entry()` invariant, the circuit
breaker, and health metrics, and it reuses the existing lazy-start path.

**Change:**

1. **Split the activity clock.** `last_used` stops being written by
   `ensure_entry_started`. Client request paths mark activity explicitly;
   `health_probe` does not. Hibernation reads the client clock only. This is
   the load-bearing fix, and every other item is secondary to it.

2. **Count in-flight work per slot.** Add an in-flight counter to
   `PooledEntry`, incremented for the duration of a request. Hibernation
   requires a zero count, closing defect 3.

3. **Synchronise on the transport lock, not `start_lock`.** The request path
   increments the in-flight count while still holding the transport *read*
   guard; hibernation takes the *write* guard and re-checks under it. Read and
   write guards are mutually exclusive, so the fast-path clone and the close
   can no longer interleave. This closes defect 2, which `start_lock` alone
   could not.

4. **Leave `PER_USER_IDLE_TTL` alone.** `idle_timeout` governs shared-slot
   hibernation only. Per-user eviction keeps its existing constant until a
   separate setting is designed for it. Closes defect 5 and shrinks blast
   radius.

5. **Spawn the reaper from one shared helper**, called by both the HTTP serve
   path and `run_stdio`. Closes defect 4.

6. **Clamp the cutoff to a 1s floor** and document it, or validate at config
   load. Closes defect 6.

## Tests the second attempt must carry

The first attempt's tests passed against a no-op implementation, which is the
strongest possible argument that they were testing the wrong things. Required:

- Health probes running against an otherwise idle backend still permit
  hibernation. This is the test that would have caught the critical defect.
- A real respawn round-trip through `ensure_entry_started`, not a manually
  installed mock.
- A genuinely concurrent fast-path clone racing a hibernation, asserting the
  caller never receives a closed transport. The first attempt named such a
  test but arranged no contention.
- A request in flight past the TTL is not torn down.
- The reaper runs in stdio mode.
- Sub-second and short configured timeouts behave sanely.

## Provenance

Adversarial review: `gpt-review` (codex, gpt-5.6-sol), verdict DO-NOT-SHIP,
2026-07-26. Defects 1-6 above are its findings, each re-verified against the
source before being accepted. Defect 1's severity was understated in review
(health interval assumed 30s; actual default is 10s).

Unrelated tooling bug found while running that gate: `~/.claude/bin/gpt-review`
hangs indefinitely when invoked with arguments from a non-interactive context.
The with-args branch calls `codex_exec ... "$prompt"` without redirecting
stdin, so codex inherits a stdin that never reaches EOF. The piped branch
(`< "$INPUT_FILE"`) is unaffected. Fix: add `< /dev/null` to the else branch.

## Round 2 review: still DO-NOT-SHIP

Adversarial review of the second attempt (`gpt-review`, codex/gpt-5.6-sol,
2026-07-26). Round-1 defect status: 2, 5, 6 fixed; 4 partially fixed; 1 and 3
not fixed.

1. **Critical — health probes immediately undo hibernation.** The tension
   described above. Attempt 2's regression test only probes *before*
   hibernating; it never runs the decisive hibernate-then-probe sequence, which
   is why it passed. Same class of mistake as attempt 1: a test that cannot
   observe the failure it claims to cover.

2. **High — per-user eviction still ignores `in_flight`.** `ActivityGuard`'s
   counter is consulted only by `hibernate_shared_if_idle`.
   `evict_idle_per_user_entries` checks `last_used` alone, so a per-user request
   outliving the 5m TTL still gets its transport closed mid-flight. The
   in-flight guard needs to apply to both reapers, not just the new one.

   Related: `request_with_headers` resolves `entry`, may wait on the backend
   semaphore, and only then calls `begin_activity`. If the original entry is
   evicted in that window, the guard attaches to a replacement entry while
   failsafe accounting stays on the old one.

3. **Medium — metadata fetches race hibernation.** `metadata.rs` calls
   `ensure_started()` and then `request_internal()`, which independently calls
   `shared_transport()`. Neither takes an `ActivityGuard`. The reaper can take
   the transport between those two steps, producing a spurious
   `BackendUnavailable`. Metadata rightly does not refresh the *client* clock,
   but it still needs in-flight protection — the two concerns are separate and
   attempt 2 conflated them.

4. **Medium — the stdio reaper never terminates.** `spawn_idle_reaper(.., None)`
   is an endless task holding the backend registry. On EOF `run_stdio` calls
   `stop_all()` and returns, but nothing cancels or joins the reaper, so it can
   sweep concurrently with or after shutdown and race `stop_all()`. Needs a
   shutdown path even in stdio mode.

5. **Low — the respawn test does not test respawn.** It installs a second mock
   by hand rather than driving `ensure_entry_started` against an empty slot.
   The production path *was* separately confirmed to re-initialise correctly
   (`StdioTransport::start` runs the `initialize` handshake inline,
   `stdio.rs:222`), so there is no defect behind it — but the test's claim is
   overstated.

Concurrency work from attempt 2 that reviewed clean and is worth keeping:

- Increment-before-lookup with a `SeqCst` counter plus the transport write lock
  is sufficient for the shared path. Either the reaper observes `in_flight > 0`,
  or it takes the transport first and the caller then observes `None` and
  starts a new one. The write lock excludes a concurrent fast-path clone.
- `ActivityGuard::drop` touches before decrementing; the `SeqCst` decrement
  supplies the release ordering for the preceding relaxed timestamp store.
  Ordinary future cancellation runs `Drop`, so the counter does not leak.
- An error or cancellation inside `ensure_entry_started` drops the guard
  correctly.

## Lesson

Both attempts produced tests that passed against a broken implementation.
Attempt 1's tests passed against a no-op; attempt 2's regression test passed
against a version that respawns the child every 10 seconds. The failure mode is
identical: the test exercised the mechanism in isolation and never reproduced
the *deployed configuration* — reaper and health loop running together against
a real backend.

Whatever ships next needs a test that runs both loops concurrently and asserts
the child process count over time, not one that calls the reaper by hand.
