# NFR.PERF.3 + NFR.OBS.4 — continuation reclamation soak and continuation counters

Design. No code. Reviewed before anything is written.

## The two requirements, verbatim

From `docs/requirements/RELEASE-4.0.0-criteria-status.md`:

> | NFR.PERF.3 | memory does not grow unboundedly with abandoned continuations; a soak shows reclamation | M | ABSENT | verifies bounded in-flight continuation state (MIK-7212.MRTR.8). The count bound is enforced (`MRTR.8a` MET) and reclamation runs inside `InFlight::hold`, but only under capacity pressure (`MRTR.8b` PARTIAL); no soak exists | yes |

> | NFR.OBS.4 | continuation mint, redeem, expiry and rejection counted, with reason | T | ABSENT | envelope now wired (MIK-7212 MRTR); no counters exist | yes |

Two deliverables, one subject. PERF.3 wants EVIDENCE that reclamation happens
under sustained abandonment. OBS.4 wants COUNTERS on the four continuation
events. Neither asks for a new reclamation mechanism — `InFlight::hold` already
reclaims. PERF.3 is a test; OBS.4 is a mechanism plus its test.

## Citations here are WORKTREE state, not HEAD

Six sessions share this checkout. Every line number below is the working tree at
the time of writing, and the working tree does not compile:

`cargo check --lib --tests` = 31 errors, in two unrelated groups.

| group | count | code | where | whose |
|---|---|---|---|---|
| peer's RED tests call an unimplemented `guard(now)` | 15 | `E0061` arity | `src/protocol/continuation.rs:737`, `:751`, `:756` | MRTR.8b, a peer's, RED phase working as designed |
| `AppState.tasks` / `task_store` do not exist | 16 | `E0560`, `E0433` | `tests/nfr_obs5_flag.rs`, `tests/nfr_obs_records.rs`, `tests/mik_7312_continuation_state.rs`, `tests/mik_7217_acs.rs`, `tests/mik_7213_acs.rs` | pre-existing, unrelated to either requirement here |

RED-SIGNAL TRIAGE applies to both: neither group is caused by this change, so
both are REPORTED, not adopted. The second group blocks running the suite at
all, which is why every claim in this document that would need a compiler is
marked as such rather than asserted.

The uncommitted `src/protocol/continuation.rs` delta (148 insertions, 0
deletions, a `#[cfg(test)] mod in_flight_lifetime` citing
`docs/design/2026-09-06-mrtr-8b-lifetime-test-plan.md`) is a PEER'S work, present
before this session's first tool call. It is read-only here.

## Measured constraints

| constraint | value | source |
|---|---|---|
| in-flight capacity | 4096 | `src/protocol/continuation.rs`, `InFlight` capacity constant |
| reclamation trigger | inside `InFlight::hold`, only under capacity pressure | `MRTR.8b` PARTIAL in the criteria table |
| abandonment TTL | > 300s of the injected clock | continuation lifetime constant |
| production call site | `src/gateway/meta_mcp/invoke.rs:384` calls `ContinuationState::begin_exchange` | worktree |
| existing bound coverage | `ac_mrtr_8_the_table_is_bounded` @ `tests/mik_7212_acs.rs:491` | worktree |
| gates | `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo test --quiet`, `#![deny(unsafe_code)]`, 0 TODO/FIXME | repo CLAUDE.md |
| compiler availability | NONE — disk guard blocks all cargo invocations | hook output, below |

The disk guard is a hard blocker on every claim requiring a compiler:

> Disk pressure halt (MIK-4777 fail-fast): root filesystem has 4 GB free, below
> 5 GB threshold. cargo build/test/check would silently fail or partially
> compile, leaving stale binaries.

`duf /` disagrees (9.9G avail, APFS purgeable accounting), the bypass is
operator-only, and the recovery freeze forbids automated cleanup. Everything
below is therefore DESIGN, and its verification is scheduled, not performed.

## NFR.PERF.3 — the soak, and why it asserts on hold count

The requirement names no duration, no abandonment rate and no memory threshold.
A wall-clock soak would have to invent all three, and would not run in the suite.
So the soak is a deterministic test with a SYNTHETIC clock:

1. drive `ContinuationState::begin_exchange` — the exact call
   `src/gateway/meta_mcp/invoke.rs:384` makes, so the test exercises the
   production path rather than a test-only entry point;
2. abandon every continuation (never redeem);
3. advance the injected clock past the abandonment TTL (> 300s) after each batch
   of 4096;
4. run N = 10x capacity = 40,960 exchanges;
5. assert on the count of SUCCESSFUL HOLDS, not on occupancy.

### Why the assertion is hold count and not occupancy

Reclamation fires only under capacity pressure, inside `hold`. That gives the
count a sharp, arithmetic bound with no tolerance to tune:

| reclamation | successful holds over 40,960 attempts |
|---|---|
| working | 40,960 — every abandoned entry is reclaimed when the table fills |
| broken | exactly 4096 — hold #4097 returns `None`, and every later one does too |

Occupancy, by contrast, is whatever the table happens to hold at the instant you
look, needs a tolerance, and would be read through `len()`.

Three properties earn this shape:

- **falsifiable, cheaply**: delete the `reclaim_abandoned` call from `hold` and
  successful holds cap at 4096 — red. Restore it and re-run — green. The
  RE-RUN is the restore check, never `git status`: defect and repair are both
  modifications and `status` reports them identically.
- **immune to the signature churn in flight**: `begin_exchange -> Option<Payload>`
  is not changing. `len()`, `route()` and `complete()` are all growing a `now`
  parameter under MRTR.8b — a soak asserting through any of them would be
  rewritten by a peer's change before it ever ran.
- **runs in the suite**: no wall clock, no sleep, deterministic, and it drives
  the production call site, which is what the MET bar asks for.

A soak that passes whether or not reclamation runs proves nothing, and that is
the failure mode this shape exists to avoid.

## NFR.OBS.4 — where the four counters live

The requirement names four events and a reason: mint, redeem, expiry,
rejection-with-reason. It does not say where the numbers are kept, and that is
the only real design decision here.

**Counters are owned by `ContinuationState`**, the aggregate already `Arc`'d into
the router and held by `invoke.rs`. The bulk lives in a NEW module,
`src/protocol/continuation_telemetry.rs`, mirroring the existing
`src/protocol_revision_telemetry.rs`. The delta to `continuation.rs` — a peer's
file, mid-RED — is then one field, one constructor line, and one accessor.

### Two surfaces, one mechanism — and that is the in-repo precedent

An instance-owned aggregate and the global `telemetry_metrics::counter!` macro
look like competing answers. They are not; `protocol_revision_telemetry.rs`
already ships both, and this adopts that shape verbatim:

| surface | who reads it | gating |
|---|---|---|
| `snapshot()` on the aggregate | the tests — this is what the AC test asserts on | ungated |
| `telemetry_metrics::counter!` emission | operators, through the metrics endpoint | `#[cfg(feature = "metrics")]` |

Asserting on a global registry would make the tests order-dependent and would
couple them to whether the `metrics` feature is on. Asserting on the aggregate
gives one owner, no global state, and a test that runs in the default feature
set. The emission is what makes the numbers reach an operator; without it, OBS.4
has counters nobody can see.

### One stale claim in the earlier telemetry document, corrected

`docs/design/2026-09-01-*` telemetry notes describe the global `counter!` macro
as the whole mechanism. That reading would put the counters out of reach of any
test running without the `metrics` feature. The aggregate is the subject of the
tests; the macro is the operator surface. Both, not either.

## Options considered and rejected

| option | why not |
|---|---|
| a global counter registry keyed by name | tests become order-dependent and feature-gated; no owner; the aggregate is already `Arc`'d exactly where the events happen |
| a second reaper task sweeping abandoned entries | the requirement asks for EVIDENCE of reclamation, not more reclamation. `hold` already reclaims; a second mechanism would need its own bound, its own cadence and its own test, and would make the existing one harder to falsify |
| a wall-clock soak (sleep, real duration, memory watermark) | invents a duration, an abandonment rate and a threshold the requirement does not name; cannot run in the suite; a passing run proves the machine was idle, not that reclamation fired |
| assert against a Prometheus recorder | asserts the EMISSION path, so it fails when the `metrics` feature is off and passes when the counts are wrong but the macro fired |
| assert on `len()` / occupancy | needs a tolerance, reads a momentary value, and `len()` is growing a `now` parameter under MRTR.8b — the assertion would be rewritten by someone else's change |

## Out of scope

- **NFR.PERF.4** — owned by `docs/design/2026-09-02-perf4-meta-tool-ceiling.md`.
- **The MRTR.8 count bound itself** — already MET and already covered by
  `ac_mrtr_8_the_table_is_bounded` @ `tests/mik_7212_acs.rs:491`. PERF.3 adds the
  RECLAMATION evidence the bound test does not provide; it does not restate it.
- **`InFlight::guard(now)`** — a peer's MRTR.8b design, mid-RED. Not implemented
  here, not designed here.

## Open questions — each scheduled, none assumed

| open question | how it resolves | state |
|---|---|---|
| does the disk guard clear, letting anything be compiled? | operator decides; `duf /` shows 9.9G and the hook shows 4G, so the disagreement is the operator's to settle | DEFERRED — owner: operator; trigger: next operator turn; if it resolves badly, nothing here can be verified and the work stops |
| does the peer's uncommitted `continuation.rs` test module get parked or implemented? | team-lead picks (a) park behind `#[cfg(any())]` or (b) implement `guard(now)` | DEFERRED — owner: team-lead; trigger: their reply; under (b) the soak's `begin_exchange` assertion is still unaffected, which is why it was chosen |
| exact name and signature of the reclamation call inside `hold` | read at source once that file is not mid-RED | DEFERRED — owner: this change; trigger: before the falsifier runs; the falsifier needs the exact call to delete |
| does `ContinuationState` already expose a snapshot-shaped accessor? | search before adding one; H2 UPDATE > CREATE | DEFERRED — owner: this change; trigger: before writing the accessor |

## The `continuation.rs` delta is PENDING SEQUENCING

The one field, one constructor line and one accessor OBS.4 needs all land in a
file a peer is actively editing, uncommitted, in a RED phase. That edit does not
happen until their work is committed or parked. Sequencing, not scope: the module
holding the bulk is new and mine, and can be written first.
