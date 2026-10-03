<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# MIK-7844: task shutdown follow-ups to MIK-7757

Status: design, for review before code.

## Problem

`task_runtime::shutdown` (HTTP and stdio both call it) drains workers, cancels
the ones that outlast the drain, joins the expiry sweep, then closes the store.
Three holes remain at the tip of the release line:

1. The expiry join and the store close have no bound. A stalled expiry delete
   or a stalled store write holds shutdown, and with it backend teardown, for
   as long as it likes.
2. A drain that ran out cancels the workers, but `all_stopped: false` (a worker
   outlived `budget.cancel`) is only logged. The store is closed under it
   anyway.
3. After a clean drain nothing seals the executor. A handler that starts a task
   after the drain is admitted, and its worker runs against a store about to
   close. The token is only cancelled after a timed-out drain.

## Decisions

1. **Bound the tail.** `ShutdownBudget` gains `close`, the other half of the
   reserve that `cancel` leaves over (`reserve - reserve / 2`). The expiry join
   and the store close run inside one `timeout(budget.close, ..)`, the sweep
   first and the close second, as today. On
   timeout shutdown warns and returns, so backend teardown proceeds; the
   process exit gives the lease back.
2. **No close under a live worker.** When `cancel_remaining` reports
   `stopped == false`, the store is retained: it is not closed, and shutdown
   says so. The sweep is still stopped inside the same bound. Retaining beats
   joining: a worker that did not end inside its cancel budget has no bound on
   when it will, and joining would put an unbounded wait back.
3. **Seal after every drain.** `TaskExecutor::seal()` cancels the shutdown
   token (terminal, as `cancel_remaining` already is): a worker spawned after it
   is dropped before its first step and its `begin` answers `Unavailable`, which
   is the refusal a late start gets. `shutdown` seals after every drain, clean
   or not, through `cancel_remaining`, whose bounded join also catches a task
   that slipped in between the drain and the seal and then retains the store as
   in decision 2. `drain` itself stays a join: its contract (nothing closed, no
   admission refused) is relied on by its callers. No second check is added at
   the worker permit: the token already ends the worker, and a create that is
   inside its commit when the seal lands leaves a `working` row that recovery
   settles at the next start, as after a crash.
4. **Docs.** The `ShutdownBudget::within` comment that says the tail "is not
   bounded here" is corrected.

## Rejected

- **Make `drain` seal.** It would change the documented join contract for every
  caller, and a probe drain after shutdown would refuse nothing it did not
  before; an explicit `seal` is the smaller surface.
- **Join the live worker instead of retaining the store.** See decision 2.
- **Abort the expiry task.** A deletion is atomic in the store and is never
  cut short by design; the bound sits around the join, not inside the sweep.

## Red rows (written first)

- A store write stalled inside a commit hook holds the store close; shutdown
  still returns inside its budget and the stalled call can finish afterwards.
- A worker that outlives the cancel budget: the store is not closed (a second
  open of the directory still finds the lease), and shutdown says so.
- After a clean drain and shutdown, a task start is refused and writes no row.
- `ShutdownBudget::within` splits the window into drain, cancel and close that
  sum to no more than the window.

## Mutants (each must be RED)

Drop the `timeout`; close the store when `stopped` is false; skip `seal`; give
`close` the whole reserve.

## Residual (not in this change)

- Returning from the bounded tail does not by itself end the process: dropping
  the Tokio runtime waits for a stalled blocking write. A bounded runtime
  shutdown at the entry point is a separate change.
- `run_stdio` cancelled before EOF skips `task_runtime::shutdown` (an existing
  drop path), so its workers are not cancelled by this helper.

## Risk and rollback

Shutdown timing only; no data or config change. A store retained after an
incomplete cancel is settled by startup recovery exactly as after a crash.
Revert the commit.
