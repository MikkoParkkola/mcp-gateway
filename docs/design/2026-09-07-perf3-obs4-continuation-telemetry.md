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
