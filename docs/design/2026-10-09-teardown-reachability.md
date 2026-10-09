# Teardown reachability (family fix, MIK-7923)

Status: implemented (MIK-7839.CANCEL.3, MIK-7923; MIK-8084 and MIK-8157 landed separately).

## Cause and rule

A teardown that runs only when an async path is driven to its end leaves work running when that
path is dropped or its runtime is never driven again, and a teardown wait without a deadline can
hold shutdown. Every teardown therefore has (1) a synchronous backstop that needs no driven runtime
and (2) a deadline on every wait.

## Paths

| Path | Dropped future | Idle runtime | Stalled I/O |
|---|---|---|---|
| Replaced `mcp` child (`stop_all` -> `Backend::retire_now`) | `replaced_child_dies_after_its_runtime_drops` | `replaced_child_dies_on_an_idle_runtime` | `a_reap_step_past_its_deadline_gives_up` |
| stdio task workers (`run_stdio_on`) | `a_dropped_stdio_session_stops_its_task_workers` | `a_sealed_worker_takes_no_step_when_it_wakes` | `stdio_teardown_bound` |
| HTTP shutdown saves | N/A: saves run on detached OS threads | N/A: same | `a_stuck_shutdown_save_is_abandoned_at_the_deadline` |
| Runtime drop, non-stdio modes | N/A: the runtime itself | N/A | MIK-8084 tests |

A new teardown path adds a row here and fills all three cells (a named test, or N/A with the
reason) before its change merges.

## Mechanisms

- Process trees: one reaper thread per process (`transport/stdio_reaper.rs`), created before any
  stdio child is spawned, steps every handed-over tree with `ChildTree::reap_step` in the MIK-8080
  order (close signal, A5 pre-reap signal, reap through the native tokio child). A transport's
  tree leaves its slot only for the reaper; `close` waits, bounded, for every reap the slot
  started. `Backend::retire_now` ends every registered stdio tree synchronously and leaves the pool
  for `stop`.
- Task workers: `run_stdio_on` holds a guard whose `Drop` seals the executor and stops store
  admission (a mutation already admitted finishes; none is admitted after). Workers check
  cancellation before each poll.

## Accepted residual

On Windows a tree counts as ended once its leader is reaped and its Job terminated, not once every
Job process has exited. This matches the release line's earlier async reap; process-wrap exposes no
safe Job-empty query and the crate denies `unsafe` (lead ruling, 2026-10-09).
