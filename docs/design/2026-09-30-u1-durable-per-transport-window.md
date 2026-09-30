# MIK-7211.PARENT.5 / U1: a durable, per-transport measurement window

**Status**: design, for review. **Criteria**: MIK-7211.PARENT.5 (compatibility-window decision in
RFC-0060 backed by U1 data) and the U1 half of MIK-7211.PARENT.1. **Tier**: STANDARD, handled with
FULL-tier care, because this code produces the evidence a retirement decision rests on.

## Why

This design implements the A/B/C decision recorded in RFC-0060 §"U1 measurement: decision
2026-09-30". Production facts (read-only, 2026-09-30):

- **HTTP counts are lost on restart.** They exist only as Prometheus counters, and nothing scrapes
  them.
- **The missing-revision share is about 8%**, against a 2% gate.
- **Every host client connects over HTTP.**
- **The stdio file is stale.** It covers 2026-09-05 to 2026-09-22 and is not aligned with any HTTP
  start.

The current evaluator (`production_retirement_decision_at`, `src/protocol_revision_telemetry.rs:792`)
compares an out-of-band HTTP snapshot with a stdio-only file. It cannot run on this deployment.

## Decisions (from the review, adopted)

A. **The population is declared per deployment, and this version certifies HTTP only.** Stdio is
not in this deployment's population, per the host client configs, so the declaration is `[http]`.
The file must match it exactly: zero HTTP observations, or any stdio observation, returns
`Blocked(PopulationMismatch)`. A stray stdio run therefore blocks rather than changing the decision
silently. Certifying stdio would need per-process loss accounting for stdio children, which record
no segments (see "Writers"). That is not built, so a declaration other than `[http]` is refused.
Stdio counts are still written, for reporting.

B. **Diagnose, don't relabel.** A missing-revision request stays unattributed and counts fully
against the 2% gate. The window gains a bounded breakdown of missing-revision requests by
User-Agent *family*, used to find the callers. Callers get fixed so they declare a revision they
actually implement. There is no "assumed 2025-03-26" bucket (rejected by review: it relabels
ignorance as data). If the gate still fails after seven days, the recorded outcome is BLOCKED.

C. **One durable window per data directory, partitioned by transport, loss-sensitive.**

## Design

### File schema v2 (`protocol-revision-telemetry/window.json`)

```jsonc
{
  "schema_version": "mcp_protocol_revision_window.v2",
  "created_at_unix_seconds": 0,
  "updated_at_unix_seconds": 0,
  "stdio": { /* Snapshot: reported, never certified */ },
  "http_segments": [                  // one per HTTP `serve` process, in open order
    {
      "listen": "127.0.0.1:39401",
      "exe": "/Users/…/.local/libexec/mcp-gateway/4.0.0-…/mcp-gateway",
      "process_started_at": 0,
      "opened_at": 0,
      "last_checkpoint_at": 0,
      "closed_cleanly": false,
      "opened_while_another_was_open": false,
      "snapshot": { /* Snapshot: this process's own counts */ }
    }
  ],
  "missing_revision_agents": { "claude": 0, "python-urllib": 0, "absent": 0 /* bounded */ },
  "tools_list_shadow": { /* unchanged */ }
}
```

- **Counts are per transport, and HTTP counts are per segment.** The `Registry` keeps a `Snapshot`
  per transport (`observe_request` keys by transport). Revision counts are never merged across
  transports. Each HTTP process writes only its own segment's snapshot, so the evaluator can cut
  the window at a segment boundary.
- **`missing_revision_agents` identifies callers.** It is keyed by the client label when that
  label names a known client (`claude`, `codex`, `cursor`, `vscode`, `chatgpt`), and by the
  User-Agent family otherwise, including when the label would be `other` or `unattributed`. An
  unknown `clientInfo` therefore cannot hide a more specific family. The purpose is to prove the
  callers before any operator script is touched; the script fixes go to the release coordinator
  as one list and are not made from this repo. The families are fixed: `python-urllib`,
  `python-requests`, `python-httpx`, `curl`, `xh`, `httpie`, `node`, `go`, `reqwest`, `absent`,
  `other`. Raw User-Agent strings are never stored (MIK-6704: label only). `validate_window`
  rejects any key outside those 5 + 11, so the map holds at most 16 keys.
- **Upgrade.** A v1 file is not converted. Opening one fails the window with an explicit error
  telling the operator to archive the directory; the process keeps serving. Converting a
  stdio-only v1 aggregate into v2 would claim HTTP coverage it never had.

### Writers

- **stdio:** unchanged cadence (a durable write per request under the cross-process lock), now
  writing `stdio`. Stdio children record no segment, which is why stdio is reported but not
  certified.
- **HTTP `serve`, at startup, under the lock:** appends a segment with its bound listen address,
  its executable path and its process start time, and sets `opened_while_another_was_open` on its
  own segment when the previous segment is not `closed_cleanly` (that writer either crashed or is
  still serving; both must block). Lock order decides, not timestamps, so a same-second restart
  cannot look concurrent.
- **HTTP saver** (the `spawn_cost_saver` pattern, `src/gateway/server/persistence.rs:111`):
  rewrites its own segment's snapshot and `last_checkpoint_at` at most every 5 s, off the request
  path. Writes are cumulative for the segment, not deltas, so a failed write loses nothing if a
  later write succeeds; no gap counter is needed. On the shutdown broadcast, when the listener stops
  accepting, the saver writes its final snapshot and sets `closed_cleanly: true`. It does this
  before the grace period, not after the drain.
  - Why not after the drain: `listener::serve` gives open connections `server.shutdown_timeout`
    (30 s by default), and launchd SIGKILLs the operator's gateway after its default 20 s exit
    timeout. The plist sets no `ExitTimeOut`. An open SSE stream would therefore kill every
    post-drain close.
  - Why this is exact: the seal and the count exclude each other. On the shutdown broadcast the
    saver takes the counts and sets `http_sealed` in one critical section under the registry
    lock (`window::global_segment_counts(true)`). The registry refuses any HTTP observation after
    that (`Registry::observe_request_from` returns `false`), and both HTTP handlers answer such a
    request with 503 without serving it (`router/helpers.rs`, `window_sealed_response`). A served
    request is therefore always in the sealed counts. Only the moment of counting matters: a long
    tool call, an SSE stream or a task counted before the seal runs to completion and holds
    nothing open. The seal is immediate, so the operator's always-on callers
    (`periodic-refresh.sh` every 60 s, agents) cannot keep a restart from sealing clean. The cost:
    a request that arrives after shutdown begins is refused and retried against the next
    process. (Final review: a time boundary alone lost post-seal counts, and a pending-request
    gauge could not see requests not yet admitted.)
  - Counter dirtiness and lifecycle metadata are tracked separately, so a shutdown with no new
    requests still writes the close.
- **`Transport::Internal`** is a label that nothing observes in production. A segment's snapshot
  is the HTTP slice of the registry only. An internal observation, if one ever appears, is neither
  certified nor summed into HTTP.
- **Open failure.** A sink that fails to open logs "not durable; do not start the measurement
  window", as stdio does today, and the gateway keeps serving. The saver retries the open on every
  tick. The process's HTTP counts are cumulative from process start, so a late open still records
  everything the process served. Residual risk: a process whose sink never opens during its whole
  life is invisible to the file. The coverage check measures from one segment's close to the next
  segment's `process_started_at`, which catches a long one. For a short one, the runbook greps the
  gateway log over the window for "not durable", and any hit means the window is not certified.
- **New sink methods are `pub(crate)`.** `DurableTelemetrySink` is a public type; nothing public
  is added to it.

### Evaluator: a sealed prefix of clean segments

The decision reads only finished evidence; it never has to prove a process is alive.

- **Evaluated span:** the longest prefix of `http_segments` that are all `closed_cleanly`, from the
  first `opened_at` to the last prefix segment's `last_checkpoint_at` (its close). Elapsed time is
  that span, never the evaluator's wall clock, so an old file cannot age into eligibility. A still
  open newest segment, live or dead, is outside the span with its counts and its time. The
  operator evaluates after one graceful restart past day 7, which seals the day-7 segment.
- **Unclean:** an unclean segment followed by any other segment returns `Blocked(UncleanSegment)`.
- **Concurrency:** a segment with `opened_while_another_was_open` returns
  `Blocked(ConcurrentHttpWriters)`.
- **Provenance comes from the declaration, not the file.** The operator declares the production
  writer: `U1_LISTEN` (for example `127.0.0.1:39401`) and `U1_EXE_PREFIX` (for example
  `~/.local/libexec/mcp-gateway/`, the installed-release directory). Any segment, the first
  included, whose `listen` differs or whose `exe` is outside the prefix returns
  `Blocked(ForeignWriter)`. That catches the compat lane (:39411) and a dev or branch build on
  the production port, which runs from a worktree `target/` directory. The decision output lists
  every segment's writer so the operator can attest to them.
- **Coverage:** more than 300 s between one segment's close and the next segment's
  `process_started_at` returns `Blocked(CoverageGap)`. This is the restart budget.
- **Gates:** `retire_revisions`, unchanged, over the summed prefix snapshots and the span's
  elapsed time, plus the population check (Decision A).
- **Operator command:** an ignored in-crate test (see "Public API"):
  `cargo test --lib protocol_revision_telemetry::window::tests::u1_production_decision -- --ignored --exact --nocapture`
  with `U1_DATA_DIR`, `U1_POPULATION=http`, `U1_LISTEN` and `U1_EXE_PREFIX`. A missing or
  unparsable variable fails it. It prints the distribution
  table, the span and the decision, and writes `decision.json` beside the window. The runbook
  checks the output says `1 passed`, so a filter that selects zero tests cannot pass silently.

### Isolation

Production is the default data directory (verified read-only 2026-09-30: the :39401 process runs
with no `MCP_GATEWAY_CONFIG_DIR`, so `~/.mcp-gateway`). This design does not move it: that would
reconfigure the operator's live gateway. The compat lane (:39411), dev runs and tests must set
`MCP_GATEWAY_CONFIG_DIR` (`src/config_persistence.rs:10-27`), and the provenance check
catches one that does not. The window start procedure in RFC-0060 says to archive the old
directory intact, then deploy, then start. Archiving moves the directory; nothing is edited.

## Public API: narrowing, pending operator approval

`protocol_revision_telemetry` is `pub mod` (`src/lib.rs:68`). Every new item is `pub(crate)`:
- the v2 window type;
- the `Segment` type;
- the new blocked reasons, held in a crate-private `WindowBlocked` wrapper so the public
  `RetirementBlocked` enum does not grow;
- the v2 evaluator.

The existing public v1 items cannot stay as they are. Once the crate writes v2, `load_durable_window`
and `production_retirement_decision[_at]` would fail on every file it produces, which is a shipped
API that no longer works. They become `pub(crate)` or are removed, and `DurableWindow` with them.
That is narrowing in a major release. It is sent to the operator for approval before the
implementation merges, and it goes in the UPGRADING (item 105 or later, also listed in the intro
startup-behaviour lists, since a v1 file is now refused) and changelog entries.
- `tests/mik_7218_acs.rs` (`mcp728_u1_2_stdio_window_survives_process_restart` and
  `mcp728_u1_4_production_decision_intersects_http_and_stdio_windows`) moves those two tests into the
  in-crate test module; the other MIK-7218 tests stay.
- `pub const DURABLE_WINDOW_SCHEMA` (`"…v1"`) joins the narrowing set. The v2 identifier is
  `pub(crate)`.
- Unchanged public items:
  - `observe_inbound_request` and `Registry::observe_request` keep their signatures. A
    `pub(crate)` sibling takes the User-Agent, and each public function delegates to it with no
    agent.
  - `global_snapshot()` and `Registry::snapshot()` stay merged views.
  - `DurableTelemetrySink::open` stays the stdio open. The HTTP segment open is a new `pub(crate)`
    function.

The operator runs the decision with an ignored in-crate test:
`cargo test --lib u1_production_decision -- --ignored` with `U1_DATA_DIR` and `U1_POPULATION=http`.
It prints the distribution table and the decision. It is not pretty, but it adds no CLI or public
surface. If review prefers a public entry point, that is a widening and goes to the operator first.

## Test plan (red first)

The red commit adds `pub(crate)` stubs that compile and return the wrong answer, so CI fails on
assertions, not on missing symbols. Every persistence test reopens the file and asserts exact
totals and lifecycle fields, not just returned errors.

1. **Stdio is never certified.** 10,000 HTTP requests on 2026-07-28 plus one stdio request on
   2025-06-18 returns `PopulationMismatch`. A declaration other than `[http]` is refused.
2. **Sealed span.** Three clean sequential segments over seven days pass, and elapsed time is the
   span, not the wall clock. An open newest segment, whether live or crashed, is excluded along
   with its counts: 500 old-revision requests in it cannot change the decision. A span shorter
   than seven days, read 30 days later, still returns `WindowTooShort`.
3. **Unclean and concurrent writers.** An unclean segment followed by another returns
   `UncleanSegment`. A second writer that opens while the first is open returns
   `ConcurrentHttpWriters`, even if both later close cleanly. A restart within the same second
   passes.
4. **Provenance and coverage.** With `U1_LISTEN=127.0.0.1:39401`, these return `ForeignWriter`:
   - a clean sequential segment on :39411;
   - a first or only segment on :39411;
   - a segment on :39401 whose `exe` is outside `U1_EXE_PREFIX`.

   A 3,600 s gap before the next `process_started_at` returns `CoverageGap`; a 10 s gap passes.
   A sink that fails to open and then opens on a later tick records every count since process
   start.
5. **Persistence faults.**
   - An idle interval still writes a checkpoint.
   - A shutdown with no new requests still writes the close.
   - A shutdown with a stalled in-flight request writes the close on the broadcast, without
     waiting for the request.
   - An `Internal` observation never reaches a segment's snapshot.
   - A failed write followed by a success loses no count.
   - A failure before the rename leaves the previous committed snapshot. A failure after the
     rename, during the directory sync, leaves a visible replacement. The evaluator reads what is
     visible. A crash that undoes the rename reverts to a snapshot whose segment is not closed, so
     the window blocks. Both boundaries are tested separately, and each asserts exact totals after
     reopening.
   - A final write that fails before the rename leaves the segment unclean.
6. **HTTP restart safety.** Two sink lifetimes over one data directory keep separate segment
   counts, and their sum is exact.
7. **Agent keys.**
   - 1,000 distinct raw User-Agents produce at most 11 family keys, and the map never exceeds 16
     keys.
   - No raw string reaches the file.
   - An unknown `clientInfo` with a `curl` agent is counted under `curl`.
   - `validate_window` rejects a key outside the set.
8. **v1 is refused.** A v1 file is left byte-identical and never converted.
9. **Missing revisions stay in the 2% gate.** A span with 8% unattributed returns
   `UnattributedAtOrAboveRetirementThreshold`, whatever the agent breakdown says.
10. **Operator command.** A missing `U1_DATA_DIR`, `U1_LISTEN` or `U1_EXE_PREFIX`, or an
    unparsable `U1_POPULATION`, fails the test. A successful run writes `decision.json`. The
    documented command, with its fully qualified name, selects exactly one test.

## Resolution of the decision-packet reviews

| Finding (seat, severity) | Resolution in this design |
|---|---|
| Stale `window.json` inherited by the new window (seat 2, HIGH) | v1 files are refused, never converted. RFC-0060's start procedure archives the directory before deploy. |
| A1 not executable: stdio `NoObservations` (seat 2, HIGH) | A new evaluator with a declared population. Only declared transports are gated, and a mismatch blocks explicitly. |
| Caller fixes must precede the window (seat 2, HIGH) | Partly resolved. The agent breakdown proves the callers. Whether to fix the operator's candidate scripts *before* the start is an operator decision, raised with the coordinator. |
| Shared data dir pollutes the window (seat 2, HIGH) | Partly resolved. Production's dir is not moved (that would reconfigure :39401). Other gateways must set `MCP_GATEWAY_CONFIG_DIR`, and a writer on another listen address blocks the decision (`ForeignWriter`). |
| Assumed-2025-03-26 bucket relabels ignorance (seat 2, MEDIUM) | Dropped (Decision B). |
| A stray stdio run flips the decision (seat 2, MEDIUM) | It blocks with `PopulationMismatch` rather than silently changing the result. |
| Host facts lack raw evidence (seat 2, LOW) | The raw evidence is attached to the decision record before deploy. |
| Seat 1, ADOPT-WITH-CHANGES | Separate per-transport counts, loss-sensitive segments, and a per-caller breakdown. All adopted. |
| Per-request HTTP fsync instead of a saver (seat 2, improvement) | Not adopted. It puts an fsync on the HTTP hot path. The sealed-prefix evaluator makes saver lag irrelevant. |

## Resolution of design round 1 (two seats, both ADOPT-WITH-CHANGES)

| Finding (seat, severity) | Resolution |
|---|---|
| A live segment can exclude unsaved traffic; a dead newest segment looks live (seats 1 and 2, HIGH) | Sealed-prefix evaluator: only clean, closed segments count, and elapsed time is their span. It never infers liveness. |
| A failure with no later successful write leaves no trace (seats 1 and 2, HIGH) | HTTP writes are cumulative per segment. A failed final write leaves the segment not closed; a failed open leaves a coverage gap. Stdio is not certified. `persistence_gaps` is removed. |
| A clean, sequential non-production writer passes (seat 1, HIGH) | The window binds to `http_listen`; any other address returns `ForeignWriter`. |
| A same-second restart reads as overlap (seat 1 MEDIUM, seat 2 LOW) | Concurrency is recorded at open time, under the lock, not inferred from timestamps. |
| Persistence transitions are untested (seat 1, MEDIUM) | Test 5. |
| The window may start with attribution still unresolved (seat 1, MEDIUM) | Raised with the coordinator as an operator decision. |
| The operator command hides its output or can select zero tests (seat 1, MEDIUM) | `--exact --nocapture`, a `1 passed` check, and `decision.json`. |
| An unknown `clientInfo` masks the agent family (seat 2, MEDIUM) | Only named clients take precedence; otherwise the agent family is used. |

## Resolution of design round 2 (final; two seats, both ADOPT-WITH-CHANGES)

Folded in without a third round. Lane rule: at most two design rounds.

| Finding (seat, severity) | Resolution |
|---|---|
| Provenance is learned from the first writer, and a listen address alone is weak (seats 1 and 2, HIGH) | The operator declares `U1_LISTEN` and `U1_EXE_PREFIX`, and every segment, the first included, must match. The output lists each segment's writer for attestation. |
| A process whose sink never opens serves traffic that goes uncounted (seat 1, HIGH) | The open is retried every tick, and counts are cumulative from process start. Coverage is measured to `process_started_at`. The residual case, a short-lived process that never opens its sink, is caught by the runbook's log check for "not durable". |
| A failed final write can still be visible after the rename (seat 1, MEDIUM) | The phase-specific outcomes are defined, and test 5 covers both boundaries. |
| The operator filter selects zero tests (seat 1, MEDIUM) | The command uses the fully qualified test name; test 10 checks it. |
| The window can start while attribution is still broken (seat 2, MEDIUM) | This is an operator decision and is still open with the coordinator. |
