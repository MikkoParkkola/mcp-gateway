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
  time under the lock (`opened_while_another_was_open`).
- **Seal**: `MetaMcp::window_seal` (per instance). The saver sets it and takes the counts in one
  critical section under the registry lock. The HTTP observe path checks it under the same lock
  before counting. A request that finds it set is answered 503 with its own id and is not served.
  Notifications are never counted, so they are never refused.
- **Evaluator**: the sealed prefix of clean segments. It blocks on `PopulationMismatch`,
  `UncleanSegment`, `ConcurrentHttpWriters`, `ForeignWriter` (declared `U1_LISTEN` and
  `U1_EXE_PREFIX`), `CoverageGap` (300 s) and `NoSealedSegment`. It then runs
  `retire_revisions` over the summed span.
- **v1 file**: refused, never converted, left byte-identical.

## Adaptations forced by the line

| # | Line change | Adaptation |
|---|---|---|
| 1 | #3728 split the telemetry file into `src/protocol_revision_telemetry/` | `window.rs` holds the schema, I/O, `HttpSegmentSink` and agent keys. `window_decide.rs` is `#[cfg(test)]` and holds the evaluator, `parse_declaration` and the operator test. With that split, no file-wide `allow(dead_code)` is needed. Each has a sibling `*_tests.rs`. |
| 2 | MIK-8364 (#3830): stdio saves through a saver plus a signal-stop persist | `DurableTelemetrySink::persist_global` and `persist_registry` write the registry's **stdio slice** and the agents into the v2 `stdio` and `missing_revision_agents` fields. The cadence is unchanged. |
| 3 | MIK-8157 (#3621): HTTP shutdown saves run on detached threads under a 10 s deadline | The window saver lives in a new file, `src/gateway/server/window_saver.rs`, because `persistence.rs` is already at 767 lines. **Periodic checkpoints** reuse `persistence::spawn_periodic_save`, which runs each write on a detached thread. The sink sits in a `Mutex`. A tick that finds the mutex taken skips (`try_lock`), so a slow write skips ticks rather than piling up. **Close:** on the broadcast, the saver seals and takes the counts on the runtime. Both are in memory with no I/O, so refusals start at once. It then hands the final write to `run_shutdown_saves` under `SHUTDOWN_SAVES_TIMEOUT`. That write takes the same mutex blocking, so it waits behind any checkpoint still in flight and can never be overtaken by one. **Ordering invariant:** `checkpoint` refuses to touch a segment that is already `closed_cleanly`, and only the final write sets that flag. A stalled periodic write that finishes late therefore cannot reopen the segment or replace the sealed counts. **What cleanliness means:** `closed_cleanly: true` is written only in the same atomic rename as the sealed counts. A final write abandoned at the deadline keeps running on its thread. If it lands before the process exits, the file holds the exact sealed counts, which are correct. If the process exits first, or is SIGKILLed, the rename never happened and the segment reads unclean, so the window blocks. A partial state is impossible. **Open:** the open, including its wait for an unsealed predecessor, runs on the saver's thread and never on a runtime worker. The wait is `SHUTDOWN_SAVES_TIMEOUT` plus 2 s, so a predecessor's slow but healthy final write is not mislabeled as concurrent. The old wait was 2 s. Counts are cumulative from process start, so the wait loses nothing. |
| 4 | MIK-8202: the wall clock is read only through `crate::clock` | `crate::clock::unix_secs()`. On `ClockBeforeEpoch` the tick is skipped and logged. The old code wrote a 0 timestamp instead. On a clock error at close, the segment stays unclean (fail-safe). |
| 5 | Router split | `observe_inbound_request_from(.., Some(HttpCaller { user_agent, sealed }))` is called at `router/handlers/dispatch_intake_run.rs:410`, which returns `Err(<503 response>)`, and at `router/backend_handlers/direct_caller.rs:391`, which returns `Err(Rejection)`. The response is built once in `router/helpers.rs` (`window_sealed_response`). Stdio (`server/stdio_single.rs:282`) keeps the public `observe_inbound_request` and is never refused. |
| 6 | The serve path moved to `server/run.rs`; MIK-8156 added an in-process shutdown trigger | The saver is spawned beside the cost saver in `run.rs` and awaited after `listener::serve`. That await is bounded because the final write is. The saver calls `run_shutdown_saves` itself, with its own deadline taken at the broadcast, so `save_state_on_shutdown` keeps its signature. The shutdown test uses `test_seams` (port 0, tempdir data dir, trigger), not a fixed-port binary. The `#![cfg(unix)]` SIGTERM binary test is dropped: the trigger enters the same broadcast that `shutdown_signal` sends (`test_seams.rs:104`). |
| 7 | `ServerConfig` moved to `src/config/server_config.rs` | The field goes there, if ruling B allows it (below). |
| 8 | Secret-file population | A new row for `src/protocol_revision_telemetry/window.rs`. |
| 9 | UPGRADING uses `upgrading.d/` fragments | `upgrading.d/<PR>.md`. The startup marker follows `upgrading-startup-grammar.json`. A v1 file now produces a WARN on every stdio start and on every HTTP open while `record` is set, so the marker names the log line and does not say "no notice". |
| 10 | More callers of the v1 items | Listed under ruling B. |

## Ruling B (public API), pending the operator: both outcomes

**B approved.** The source design ships as adapted above.
- Removed from `mcp_gateway::protocol_revision_telemetry`: `DurableWindow`, `load_durable_window`,
  `production_retirement_decision`, `production_retirement_decision_at`, `DURABLE_WINDOW_SCHEMA`
  and `RetirementBlocked::WindowMisaligned` (nothing produces it once the evaluator above is gone).
- Added: `pub ServerConfig::protocol_revision_window` and `pub enum ProtocolRevisionWindow
  { Off, Record }`, default `Off`. With `Off`, no segment is written, nothing is sealed, and
  shutdown serves as in 3.5.x.
- Unchanged public items: `DurableTelemetrySink` (no new public method), `durable_window_path`,
  `DURABLE_TELEMETRY_DIR`, `DURABLE_WINDOW_FILE`, `observe_inbound_request`,
  `Registry::observe_request`, `global_snapshot`, `Registry::snapshot`.
- Callers moved:
  - `tests/stdio_sigterm_telemetry.rs` reads `window.json` as raw JSON (`stdio.total`), the way
    `tests/u1_v1_window_grade.rs` already does.
  - `tests/mik_7218_acs.rs`: its two v1 window tests move in-crate (`window_tests.rs`).
  - In-crate tests (`stdio_telemetry_save.rs`, `stdio_dispatch.rs`, `durable_tests.rs`,
    `lock_tests.rs`) switch to the `pub(crate)` `window::load`.

**B declined.** No public item changes, and v1 keeps working.
- `window.json` stays v1 and stdio keeps writing it exactly as today. The v1 items keep working on
  it. They are not deprecated, because a deprecation attribute is itself a public change.
- The v2 data goes to a **second file**, `protocol-revision-telemetry/http-window.json`
  (`mcp_protocol_revision_http_window.v1`, `pub(crate)`). It holds the HTTP segments and the agent
  breakdown. There is no stdio slice in it, because stdio is never certified.
- With no config field, HTTP recording has no switch. Two sub-options, and the lead picks:
  - **B-off**: the writer, the seal and the evaluator ship, reachable only from tests. That is
    dead in production and not useful to MIK-8442 until 4.1 adds a switch.
  - **B-defer**: land only the in-memory per-transport split and the agent breakdown (which feed
    nothing durable), and move the HTTP half to MIK-8442.
  - My recommendation under a decline is B-defer, since dead production code is the worse
    outcome.
  - An environment variable switch would also be a public interface and needs the same approval.

**Build order, so that no work is wasted whichever way the ruling goes.**
- **Step 1**, common to every outcome including B-defer: the registry's per-transport slices and
  agent map, `observe_inbound_request_from` and `HttpCaller`.
- **Step 2**, common to B approved and B-off only: the window module's segment sink and
  validation, the evaluator and the saver. Under B approved and B-off, only the file name, the
  schema constant and the switch differ.
- **Step 2 starts only after the ruling.**

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
   returns `ConcurrentHttpWriters`. A restart within the same second passes.
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
8. A v1 file is refused and left byte-identical. Under B declined: v1 is untouched and v2 goes to
   the second file.
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
    - With `off` (or no switch), every request is served.
    - Stdio is never refused.
15. **Stdio slice (the MIK-8364 path).** After a saver tick, and after the signal-stop persist,
    `stdio` holds only stdio counts, even when the same process also served HTTP.
16. **Checkpoint versus final write.** A periodic checkpoint is stalled holding older counts, then
    shutdown runs. The final write waits behind it and lands. Releasing the stalled checkpoint
    afterwards neither reopens the segment nor replaces the sealed counts.
17. **Slow predecessor.** A predecessor whose final write lands 5 s after the successor starts its
    open is *not* flagged `opened_while_another_was_open`. A predecessor that never closes is
    flagged.

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
| The 2 s open wait under-covers the 10 s final-write bound (seat 2, MEDIUM) | Accepted. The wait is now `SHUTDOWN_SAVES_TIMEOUT` plus 2 s, on the saver thread. Row 17 added. |
| "Common to both outcomes" contradicts B-defer (seat 2 LOW; seat 1 improvement) | Accepted. The build order is split into step 1 (every outcome) and step 2 (after the ruling). |
| Reuse `spawn_periodic_save`; say how the final write reaches the deadline (seat 2, improvements) | Adopted (row 3). The saver calls `run_shutdown_saves` itself, so `save_state_on_shutdown` is unchanged (row 6). |
