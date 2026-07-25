# Idle backend hibernation: making `idle_timeout` real

Status: in progress
Branch: `fix/idle-timeout-shared-hibernation`
Date: 2026-07-26

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
