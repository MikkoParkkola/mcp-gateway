# MIK-7217.ERA.1 / ERA.2 — refuse a probe answer from a replaced transport

**Criteria** (`docs/requirements/RELEASE-4.0.0-scope-update.md:151-153`).
ERA.1: when `force_restart` replaces a backend's transport while a re-probe is in flight, the
in-flight probe's answer is refused and the recorded era is unchanged. ERA.2: the refusal writes an
`era_probe_discarded` record naming the reason. ERA.3: without a restart a re-probe is committed as
today (`a_contradiction_reprobes_and_the_whole_read_moves_with_it` stays green).

## What exists, and the gap

`Backend::reprobe_if_code_contradicts` (`src/backend/era.rs`) drops a contradicted verdict, then spawns
a detached task that calls `EraCache::reprobe_with(|| probe(&transport, timeout))`, holding an `Arc`
of the transport it observed. `reprobe_with` holds the era lock across the probe and then writes the
outcome unconditionally.

`force_restart` (`src/backend/lifecycle.rs`) takes the shared slot's transport out, starts a new one
and calls `restart_with`, which waits on the same era lock. So when a restart lands mid-probe the old
peer's answer is written first and only then discarded by the restart's own reset. In between, an
operator read (`gateway_list_servers`) can show an era the current peer never demonstrated, and the
write is never reported. The 2026-08-31 design specified the cure as the transport-identity rule
(§ test row 13): a probe writes only if its transport is still the slot's transport. It was never built,
and `docs/design/2026-09-04-nfr-obs-3-test-plan.md:121` records that `era_probe_discarded` has no
producing path.

## Change

1. `EraCache::reprobe_with(probe, install)`. After the probe returns, still under the era lock, the
   cache calls `install(&mut store)`, where `store` is the synchronous write of the new observation.
   `install` runs `store` only if the probed transport is still installed and returns whether it did.
   `false`: nothing is written, the observation stays as the contradiction left it, and
   `era_probe_discarded` is emitted. Check and write are one step, not two: a bare
   `still_current() -> bool` would let `force_restart` replace the transport between the check and the
   write, because a replacement takes the slot's lock, not the era lock (seat 1, round 1).
2. `Backend` supplies `install`. The detached task cannot borrow `&self`, and the pool is an owned map,
   so ownership is settled at spawn time: `reprobe_if_code_contradicts` finds, synchronously, the
   pool slot (shared or per-user) whose transport is `Arc`-identical to the one it was handed and moves
   that `Arc<PooledEntry>` into the task. No pool scan happens under the era lock and no ownership
   change to `Backend::pool`. If no slot holds the transport any more, nothing is spawned: the
   transport was already replaced, and the start path's own probe gives the era. `install` runs
   `store` while holding that entry's `transport` read guard, so a replacement (a write guard) waits
   for the store or has already happened. An evicted per-user entry that stays alive has had its
   transport taken, so it reads `None` and refuses. This linearises exactly: the answer is committed
   before the replacement (the restart's reset then supersedes it, as today) or refused after it.
   Lock order: era mutex, then one slot read guard, both synchronous. Every writer of
   `PooledEntry::transport` (`start_entry`, `force_restart`, idle eviction, `stop`) swaps under the
   guard synchronously and does not wait on the era lock while holding it; that is a reading of the
   code, verified by grep in the implementation PR, not something the compiler proves.
3. The record. Target `mcp_gateway::observed`, message-less like its siblings, fields: `backend`,
   `reason = "transport_replaced"`, and the probe's own `outcome`, `evidence`, `duration_ms`,
   `trigger` (the shape fixed in `2026-09-03-nfr-obs-3-era-observability.md:286`, minus
   `error_code`). Amendment: `reason` is added so the record names why, as ERA.2 requires; the design's
   set had only the probe's fields.
4. Only the detached re-probe gets the rule. The start path's probes are outside this change: most run
   under the slot's `start_lock`, which `force_restart` also holds, but public `Backend::start` calls
   `start_entry` without it and HTTP probes inside `start_entry`. Those exceptions predate this design
   and are not part of what ERA.1/2 claim.

Not changed: the 2 s probe cap, silence handling, `restart_with`, the operator read, any wire shape.
The operator read is unaffected: a refused answer leaves it exactly as the contradiction left it.

## Test plan (red first)

| # | Where | Case | Red on old code because |
|---|---|---|---|
| 1 | `src/protocol/era.rs` unit | `reprobe_with` whose `install` reports not-current leaves the whole observation untouched and emits one `era_probe_discarded` carrying `backend`, `reason`, `outcome`, `evidence`, `duration_ms`, `trigger=reprobe`; a current one stores | the parameter and the record do not exist, so it fails to compile: the honest red for a new signature; the behavioural red is row 2 |
| 2 | `src/backend/pool_tests.rs`-style, real `force_restart` | Modern cached; a contradiction spawns a re-probe on a gated transport A held mid-probe; `force_restart()` really takes A out (start fails on an unspawnable command, as `health_recovery_does_not_close_...` does); A is released with a modern document; the test awaits the detached task's completion (a completion latch the mock raises after answering plus the task handle's join, never a sleep). Cached era is `None` and exactly one record exists | A's answer is committed |
| 3 | same | the same sequence without `force_restart`: the answer is committed, the era is `Modern`, no record (ERA.3 twin) | passes today; guards the rule |
| 4 | `src/backend` unit | the installer itself: called with a `store` callback that asserts the slot's `try_write()` fails while it runs; a variant of the installer that drops the read guard before `store` makes this assertion fail, so a split check-then-write cannot pass. Run for the shared slot, for a per-user slot, and for a per-user entry evicted but still referenced (refuses) | check-then-write would leave the slot writable during `store` |
| 4b | same as row 2 | replacement by a successful start rather than a failed one: `set_transport_for_test(B)` after A's re-probe began; A's answer is refused, then B's own `resolve_era` fixes the era from B's answer | A's answer is committed |
| 5 | existing | `a_contradiction_reprobes_and_the_whole_read_moves_with_it`, `a_reprobe_that_gets_no_answer_returns_the_era_to_assumed` | unchanged |

Known limit (final review, deferred to 4.0.1): an identity-slot eviction (`evict_identity_slots`) of a busy per-user slot leaves its transport in the removed entry until in-flight work ends, so a re-probe captured on that entry can still store while the peer it probed is alive and unreplaced. That peer's answer is true of a running peer, and ERA.1 concerns `force_restart` replacement, so it is not refused here; a membership check would need the pool shared with the detached task.

Coverage limit, stated rather than hidden: no test drives a per-user slot through the backend or a real idle eviction of the captured entry. Row 4 proves the installer's guard retention and its refusal of an empty slot; the pool scan that captures the entry is slot-kind agnostic by construction (it walks every `PooledEntry`), and an eviction takes the transport out under the same write guard the installer respects.

Rows 1 and 4 prove the method and the boundary; row 2 proves the capture and the lifecycle path.
Asserting the whole `EraObservation` (source, evidence, timestamp) in rows 2 and 4, not only the era.
The `era_probe_discarded` row of the NFR.OBS.3 plan moves from "not executable" to covered.

## Ledger

ERA.1, ERA.2, ERA.3 regrade to `met` in this PR with the test ids and the merge evidence; the ledger
row text is unchanged.
