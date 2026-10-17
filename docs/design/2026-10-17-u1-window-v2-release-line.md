# U1 v2 window on the 4.0.0 release line (rework of #2469)

**Status**: design, for review. **Refs**: MIK-7211.PARENT.5 and the U1 half of PARENT.1
(waived for 4.0.0 by ruling C7, superseded by MIK-8442). **Base**: release line at e80e75c6e.
**Source design**: `docs/design/2026-09-30-u1-durable-per-transport-window.md` on branch
`fix/mik-7211-u1-window` (#2469). This note keeps that design and records only what the current
code forces to change. Where this note is silent, the source design holds.

## Scope

The operator decided on 2026-10-17 that the instrument lands in 4.0.0. 4.0.0 still ships with no
measured data. All five revisions stay supported, and any retirement decision stays with MIK-8442
(v4.1.0). This PR ships:

- the instrument: per-transport counts, one HTTP segment per `serve` process, the seal, and the
  missing-revision agent breakdown;
- the evaluator, as an ignored in-crate test.

It does not change the RFC-0060 procedure (C7 marks the old setup HISTORICAL; MIK-8442 defines
the redo), the scope JSON, or the PARENT.5 wording.

**Denominator** (lead ruling A, 2026-10-17): one inbound JSON-RPC request, as RFC-0060
pre-registered. 2026-07-28 has no session to count. The wording gap in MIK-8442.U1REDO.1
("sessions opening") is recorded on MIK-8442 (comment 46faa32a).

## Unchanged from the source design

- **Schema v2** (`protocol-revision-telemetry/window.json`): `stdio` is a snapshot that is
  reported but never certified, `http_segments[]` holds one segment per HTTP process,
  `missing_revision_agents` is bounded to 5 named clients + 11 User-Agent families, and
  `tools_list_shadow`. Raw User-Agent strings are never stored (MIK-6704).
- **Writers**: stdio sends deltas from every child under the cross-process lock. Each HTTP
  process rewrites its own segment with its cumulative counts. Concurrency is recorded at open
  time under the lock (`opened_while_another_was_open`). *Superseded by design round 2: overlap
  is judged from sealed timestamps; see adaptation 3.*
- **Seal**: `MetaMcp::window_seal` (per instance). The saver sets it and takes the counts in one
  critical section under the registry lock. The HTTP observe path checks it under the same lock
  before counting. A request that finds it set is answered 503 with its own id and is not served.
  Notifications are never counted, so they are never refused.
- **Evaluator**: the sealed prefix of clean segments. It blocks on `PopulationMismatch`,
  `UncleanSegment`, `ConcurrentHttpWriters`, `ForeignWriter` (declared `U1_LISTEN` and
  `U1_EXE_PREFIX`), `CoverageGap` (300 s) and `NoSealedSegment`. It then runs
  `retire_revisions` over the summed span.
- **v1 file**: refused, never converted, left byte-identical.

## Segment schema and lifecycle (current; supersedes the source design's segment)

```jsonc
{ "listen": "127.0.0.1:39401", "exe": "/abs/path/mcp-gateway",
  "process_started_at_ms": 0,   // crate::clock::unix_millis at saver spawn
  "opened_at": 0,               // unix seconds, at the open
  "last_checkpoint_at": 0,      // unix seconds, at each successful write
  "sealed_at_ms": null,         // unix millis read at the seal; set only by the final write
  "closed_cleanly": false,      // true only in the same rename as the sealed counts
  "snapshot": {}, "missing_revision_agents": {}, "tools_list_shadow": {} }
```

- **Lifecycle.** Open, before serving. Then periodic checkpoints. Then the seal, in memory. Then
  one final write, which sets `sealed_at_ms` and `closed_cleanly` together. After that, nothing
  touches the segment.
- **Validation.** `sealed_at_ms` is present exactly when `closed_cleanly` is true.
- **There is no `opened_while_another_was_open` field.**
- **Overlap.** `ConcurrentHttpWriters` when `next.process_started_at_ms <
  previous.sealed_at_ms`.
- **Coverage.** `CoverageGap` when `next.process_started_at_ms - previous.sealed_at_ms >
  300,000`.
- **Span.** From the first segment's `opened_at` to the last sealed segment's `sealed_at_ms`.

## Adaptations forced by the line

| # | Line change | Adaptation |
|---|---|---|
| 1 | #3728 split the telemetry file into `src/protocol_revision_telemetry/` | `window.rs` holds the schema, I/O, `HttpSegmentSink` and agent keys. `window_decide.rs` is `#[cfg(test)]` and holds the evaluator, `parse_declaration` and the operator test. With that split, no file-wide `allow(dead_code)` is needed. Each has a sibling `*_tests.rs`. |
| 2 | MIK-8364 (#3830): stdio saves through a saver plus a signal-stop persist | `DurableTelemetrySink::persist_global` and `persist_registry` write the registry's **stdio slice** and the agents into the v2 `stdio` and `missing_revision_agents` fields. The cadence is unchanged. |
| 3 | MIK-8157 (#3621): HTTP shutdown saves run on detached threads under a 10 s deadline | The window saver lives in a new file, `src/gateway/server/window_saver.rs`, because `persistence.rs` is already at 767 lines. **Periodic checkpoints** reuse `persistence::spawn_periodic_save`, which runs each write on a detached thread. The sink sits in a `Mutex`. A tick that finds the mutex taken skips (`try_lock`), so a slow write skips ticks rather than piling up. **Close:** on the broadcast, the saver seals and takes the counts on the runtime. Both are in memory with no I/O, so refusals start at once. It then hands the final write to `run_shutdown_saves` under `SHUTDOWN_SAVES_TIMEOUT`. That write takes the same mutex blocking, so it waits behind any checkpoint still in flight and can never be overtaken by one. **Ordering invariant:** the sink holds an in-memory `closed` flag. It is read and set only while the sink mutex is held, and in the same critical section as the write. Once `closed` is set, `checkpoint` writes nothing. Only the final write sets it, and only after its rename succeeds. A stalled periodic write that finishes late therefore cannot reopen the segment or replace the sealed counts. **Poisoned mutex:** the lock is recovered with `PoisonError::into_inner`, as `observe.rs` does, and the panic is logged once. A panicked checkpoint has not set `closed`, so later writes still run. **What cleanliness means:** `closed_cleanly: true` is written only in the same atomic rename as the sealed counts. A final write abandoned at the deadline keeps running on its thread. If it lands before the process exits, the file holds the exact sealed counts, which are correct. If the process exits first, or is SIGKILLed, the rename never happened and the segment reads unclean, so the window blocks. A partial state is impossible. **Open, before serving** (round 3, HIGH): with `record`, `run.rs` opens the segment before `listener::serve` starts. The open runs on a detached named thread that holds the sink mutex, so it never runs on a runtime worker. `run.rs` waits for it for at most `WINDOW_OPEN_STARTUP_BOUND` (2 s, a named constant). Reason: a healthy open is one lock, one read and one fsynced rename on a local disk, well under 100 ms. 2 s bounds a stalled mount while costing a restart no more than the startup it already pays, and it is far inside the 300 s restart budget. On failure or timeout, the gateway logs the existing marker ("HTTP protocol-revision telemetry is not durable; do not start the measurement window"), which un-certifies the window under the runbook, and **serves anyway**. The open never blocks serving past the bound. A timed-out open keeps running on its thread and still holds the mutex. The first periodic tick, at one interval, finds the mutex taken and skips. Once the open finishes, each tick with no sink retries the open, under the same mutex. The bound applies only with `record`; with `off` nothing is opened. **Shutdown cannot race the open:** the seal is in memory and does not touch the sink. The final write takes the sink mutex, so it runs after any open still in flight, and if that open succeeded it writes into it. If the open is still stalled at the deadline, the final write is abandoned, and the segment is absent or unclean. There is still no wait for a predecessor; the old 2 s loop is deleted. **Overlap, judged from sealed evidence** (design round 2): the at-open flag `opened_while_another_was_open` is dropped. A flag set at open cannot tell a slow final write from a live writer. Waiting for the predecessor hid genuine overlap, because both processes may admit requests before the predecessor seals. The evaluator returns `ConcurrentHttpWriters` when a segment's `process_started_at` is earlier than its predecessor's `sealed_at`, compared in milliseconds (round 3). That is a new segment field: the clock read at the seal itself, carried in the final write. It is not the time the write happened to land, so a final write queued behind a stalled checkpoint cannot make a later successor look concurrent. The sealed span also ends at the last segment's `sealed_at`. If the predecessor never closed, the window is already blocked as `UncleanSegment` (or the predecessor is the newest open segment). The check works in whole seconds. A restart within the same second passes, and a backwards wall-clock step can only block, which is fail-safe. **Shutdown never waits for the open:** the seal is in memory and independent of the sink. A final write queued behind a stalled open is bounded by the same deadline, and if it misses it the segment reads unclean. |
| 4 | MIK-8202: the wall clock is read only through `crate::clock` | `crate::clock::unix_secs()`. On `ClockBeforeEpoch` the tick is skipped and logged. The old code wrote a 0 timestamp instead. On a clock error at close, the segment stays unclean (fail-safe). |
| 5 | Router split | `observe_inbound_request_from(.., Some(HttpCaller { user_agent, sealed }))` is called at `router/handlers/dispatch_intake_run.rs:410`, which returns `Err(<503 response>)`, and at `router/backend_handlers/direct_caller.rs:391`, which returns `Err(Rejection)`. The response is built once in `router/helpers.rs` (`window_sealed_response`). Stdio (`server/stdio_single.rs:282`) keeps the public `observe_inbound_request` and is never refused. |
| 6 | The serve path moved to `server/run.rs`; MIK-8156 added an in-process shutdown trigger | The saver is spawned beside the cost saver in `run.rs` and awaited after `listener::serve`. That await is bounded because the final write is. The saver calls `run_shutdown_saves` itself, with its own deadline taken at the broadcast, so `save_state_on_shutdown` keeps its signature. The shutdown test uses `test_seams` (port 0, tempdir data dir, trigger), not a fixed-port binary. The `#![cfg(unix)]` SIGTERM binary test is dropped: the trigger enters the same broadcast that `shutdown_signal` sends (`test_seams.rs:104`). |
| 7 | `ServerConfig` moved to `src/config/server_config.rs` | The field goes there (ruling B, below). |
| 8 | Secret-file population | A new row for `src/protocol_revision_telemetry/window.rs`. |
| 9 | UPGRADING uses `upgrading.d/` fragments | `upgrading.d/<PR>.md`. The startup marker follows `upgrading-startup-grammar.json`. A v1 file now produces a WARN on every stdio start and on every HTTP open while `record` is set, so the marker names the log line and does not say "no notice". |
| 10 | More callers of the v1 items | Listed under ruling B. |

## Ruling B (public API): APPROVED 2026-10-17

The operator delegated the ruling to the release lead, who approved option B. The source design
ships as adapted above. The B-declined plan of the earlier draft is withdrawn.

- **Removed** from `mcp_gateway::protocol_revision_telemetry`:
  - `DurableWindow`;
  - `load_durable_window`;
  - `production_retirement_decision`;
  - `production_retirement_decision_at`;
  - `DURABLE_WINDOW_SCHEMA`;
  - `RetirementBlocked::WindowMisaligned`, which nothing produces once the v1 evaluator is gone.
- **Added:**
  - `mcp_gateway::config::ServerConfig::protocol_revision_window`, a `pub` field;
  - `pub enum mcp_gateway::config::ProtocolRevisionWindow { Off, Record }`, default `Off`.

  With `Off`, no segment is written, nothing is sealed, and shutdown serves as in 3.5.x.
- **Unchanged** public items:
  - `DurableTelemetrySink`, with no new public method;
  - `durable_window_path`, `DURABLE_TELEMETRY_DIR`, `DURABLE_WINDOW_FILE`;
  - `observe_inbound_request`, `Registry::observe_request`;
  - `global_snapshot`, `Registry::snapshot`.
- **Conditions:**
  - The PR body lists every removed and added public item with its path, so the operator can
    veto before merge.
  - An `upgrading.d` note states the removal and the new setting with its default.
- **Callers moved:**
  - `tests/stdio_sigterm_telemetry.rs` drives the real binary over SIGTERM, so it cannot move
    in-crate. It stops calling the removed loader and reads `window.json` as raw JSON
    (`stdio.total`), as `tests/u1_v1_window_grade.rs` already does.
  - `tests/mik_7218_acs.rs`: its two v1 window tests move in-crate, into `window_tests.rs`.
  - The in-crate tests (`stdio_telemetry_save.rs`, `stdio_dispatch.rs`, `durable_tests.rs`,
    `lock_tests.rs`) switch to the `pub(crate)` `window::load`.
- **Build order:**
  - Step 1: the registry's per-transport slices and agent map, `observe_inbound_request_from`
    and `HttpCaller`.
  - Step 2: the window module, the saver, the evaluator, the config field and the v1 removal.

## New `pub(crate)` and test-only items (for the PR body)

- `pub(crate)` in `window.rs`: `WindowV2`, `Segment`, `SegmentCounts`, `WriterIdentity`,
  `HttpSegmentSink::{open, checkpoint}`, `load`, `read_window_v2`, `validate_window_v2`,
  `NAMED_CLIENTS`, `USER_AGENT_FAMILIES`, `missing_revision_agent`, `global_segment_counts`.
- `pub(crate)` in `mod.rs` and `observe.rs`: `Registry::observe_request_from`,
  `Registry::transport_snapshot`, `Registry::missing_revision_agents`, `HttpCaller`,
  `observe_inbound_request_from`.
- `pub(crate)` on `MetaMcp`: the `window_seal` field.
- `pub(super)` in `server/window_saver.rs` and `router/helpers.rs`: `spawn_window_saver` and
  `window_sealed_response`.
- Test-only (`#[cfg(test)]`): the whole of `window_decide.rs` (`Declaration`, `WindowBlocked`,
  `SealedSpan`, `decide`, `parse_declaration`, the ignored operator test).

## Test plan (red first)

The red commit adds `pub(crate)` stubs that compile and return the wrong answer. Every row is
then seen failing on its assertion, not on a missing symbol. Persistence rows reopen the file
and assert exact totals and lifecycle fields. Timeouts follow `check-timing-asserts.py`, which
runs as soon as the rows exist.

Rows 1-10 carry over from the source design:

1. Stdio is never certified: HTTP traffic plus one stdio request returns `PopulationMismatch`,
   and a declaration other than `http` is refused.
2. The elapsed time is the sealed span, not the wall clock. Counts in an open newest segment are
   excluded.
3. An unclean segment that has a successor returns `UncleanSegment`. An overlapping writer
   returns `ConcurrentHttpWriters` (a successor started before its predecessor's sealed close). A
   restart within the same second passes.
4. A foreign listen address or exe returns `ForeignWriter`. A 3,600 s gap returns `CoverageGap`,
   and a 10 s gap passes. A late open still records every count since process start.
5. Persistence faults:
   - an idle tick writes a checkpoint;
   - a close with no new requests lands;
   - an `Internal` observation never reaches a segment;
   - a failed write followed by a success loses nothing;
   - the before-rename and after-rename boundaries are tested separately.
6. Two sink lifetimes keep separate segments, and their sum is exact.
7. Agents:
   - 1,000 raw agents give at most 11 families and at most 16 keys;
   - no raw string reaches the file;
   - an unknown `clientInfo` with a curl agent counts as `curl`;
   - a key outside the set is rejected.
8. A v1 file is refused and left byte-identical.
9. 8% unattributed returns `UnattributedAtOrAboveRetirementThreshold`.
10. Operator command: a missing or unparsable variable fails; success writes `decision.json`; the
    qualified name selects exactly one test.

New rows for the line's changes:

11. **Bounded close (MIK-8157).** A final write stalled past the deadline does not hold the
    shutdown: the saver ends within the deadline. Two separate arms, each reopening the file:
    - The stall is never released. The segment reads unclean.
    - The stall is released after the deadline. The segment reads clean with exactly the sealed
      counts. A late write is correct data.
12. **Refusal starts at the broadcast.** With the final write stalled, a request after the
    broadcast is refused at once and is not counted.
13. **Clock.** With `clock::test_support` forcing a time before the epoch, a tick writes nothing,
    and a close leaves the segment unclean. A 0 timestamp is never written.
14. **Both HTTP routes, in-process** (test seams, port 0).
    - One request on each of `/mcp` and `/mcp/{name}` is admitted and held *before* its count
      point; two more are held *after* their count point.
    - Then the trigger fires, and the test waits for the seal (the flag is observable), not for a
      sleep.
    - Held-before requests are answered 503 with their own id, and are not in the sealed counts.
    - Held-after requests complete 200, and are in them.
    - With `off`, every request is served.
    - Stdio is never refused.
15. **Stdio slice (the MIK-8364 path).** After a saver tick, and after the signal-stop persist,
    `stdio` holds only stdio counts, even when the same process also served HTTP.
16. **Checkpoint versus final write.**
    - A periodic checkpoint is stalled while holding the mutex, with older counts. Shutdown seals,
      and the final write queues behind the checkpoint.
    - The checkpoint is released. It writes its older, unclosed state, then the final write lands
      the sealed counts with `closed_cleanly: true`.
    - A checkpoint run afterwards writes nothing. The file is reopened and asserted at each step.
17. **Overlap from sealed timestamps.**
    - A successor whose `process_started_at` is earlier than its predecessor's sealed close returns
      `ConcurrentHttpWriters`.
    - A successor that starts in the same second as that close passes. So does one that starts
      later, even when the predecessor's final write landed late.
    - A predecessor that never closes, followed by a successor, returns `UncleanSegment`.
18. **Shutdown with a stalled open.** With the open stalled, `run.rs` serves once
    `WINDOW_OPEN_STARTUP_BOUND` passes, and the marker is logged. The broadcast still seals at
    once. The saver ends within the deadline, and the segment is absent or unclean.
19. **Crash in the first interval** (round 3, HIGH). With `record`, the process serves one
    request and is then dropped without shutdown, before any periodic tick. The reopened file
    holds this process's segment, unclean, so the window blocks. It never holds no segment.
20. **Open failure and retry.** The open fails at startup (an unwritable directory). The marker
    is logged and requests are served. Once the directory is made writable, a later tick opens
    the segment, which holds every count since process start.
21. **Sub-second overlap.** A successor started 300 ms before its predecessor's `sealed_at_ms`
    returns `ConcurrentHttpWriters`.

## Risks and falsifiers

- **A 503 during shutdown is user-visible**, with `record` only. Falsifier: row 14's `off` arm.
  Any refusal with `off` means the design is wrong.
- **A final write that never lands blocks the next window.** This is by design.
  - Falsifier, row 11: the segment must read either unclean or clean with exactly the sealed
    counts, never anything else.
  - Falsifier, row 16: a late checkpoint must never reopen a closed segment.
- **A v1 file in the operator's data dir** gives a WARN on every start until it is archived. The
  file is never touched (row 8).

## Resolution of design review round 1 (two seats, both SHIP-WITH-FIXES)

| Finding (seat, severity) | Resolution |
|---|---|
| A timeout does not make a segment unclean; the detached writer can still land `closed_cleanly: true` later (seat 1, MEDIUM) | Accepted. Cleanliness is defined by the atomic rename that carries the sealed counts. A late landing is correct data. Row 11 now has both arms. |
| A late periodic checkpoint could overwrite the final write (seat 1, improvement) | Accepted as a defect. One mutex orders the writes, and `checkpoint` never touches a closed segment. Row 16 added. |
| Hold requests on both sides of the count point and wait on the seal, not on timing (seat 1, improvement) | Adopted in row 14. |
| The 2 s open wait under-covers the 10 s final-write bound (seat 2, MEDIUM) | Accepted in round 1 with a longer wait. That wait was replaced in round 2 by overlap judged from sealed timestamps. |
| "Common to both outcomes" contradicts B-defer (seat 2 LOW; seat 1 improvement) | Accepted. The build order is split into step 1 (every outcome) and step 2 (after the ruling). |
| Reuse `spawn_periodic_save`; say how the final write reaches the deadline (seat 2, improvements) | Adopted (row 3). The saver calls `run_shutdown_saves` itself, so `save_state_on_shutdown` is unchanged (row 6). |

## Resolution of design review round 2 (seat 1 SHIP-WITH-FIXES, seat 2 SHIP)

| Finding (seat, severity) | Resolution |
|---|---|
| The predecessor wait hides genuine overlap when both processes admit requests before the seal (seat 1, MEDIUM) | Accepted. The wait loop and the at-open flag are deleted. Overlap is judged from sealed timestamps (adaptation 3; row 17). |
| Row 16 as written cannot run, because the stalled checkpoint holds the mutex the final write needs (seat 1, improvement) | Rewritten: the checkpoint is released first, then the final write lands, then a later checkpoint is refused. |
| Shutdown must not wait for a stalled open (seat 1, improvement) | Stated in adaptation 3; row 18 added. |
| The closed check must sit under the mutex, against in-memory state (seat 2, improvement) | Stated in adaptation 3. |
| Poisoned-mutex behaviour (seat 2, improvement) | Recovered with `into_inner` and logged (adaptation 3). |
| A false positive when a final write lands after the wait (seat 1 and seat 2, improvements) | Removed along with the wait. Overlap no longer depends on when the final write lands. |

## Resolution of design review round 3 (seat 1 SHIP-WITH-FIXES with one HIGH)

| Finding (seat, severity) | Resolution |
|---|---|
| Opening at the first periodic tick lets a process serve and crash with no segment and no marker (seat 1, HIGH; a regression from round 1's reuse of `spawn_periodic_save`) | Accepted. The open happens before serving, bounded by `WINDOW_OPEN_STARTUP_BOUND`, with the marker on failure and a retry on ticks. Rows 18-20. Reported to the lead first; a round-4 delta pass on this change only. |
| Whole-second comparisons miss sub-second overlap (seat 1, MEDIUM) | Accepted. `process_started_at_ms` and `sealed_at_ms` are in milliseconds (row 21). The primary guarantee is that two listeners cannot bind one address, and other addresses are `ForeignWriter`. Overlap cannot double-count, because each process writes only what it served. |
| Publish one current schema (seat 1, improvement) | Added: "Segment schema and lifecycle". |
