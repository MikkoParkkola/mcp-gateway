# MRTR.9a — resume state

Written for a session that picks this up cold. Delete at §P5 housekeeping.

## Where this sits in the ask

The operator asked for the **v4.0.0 release-readiness gaps, at full scope**.
Honest position: **1 row in flight, 50 blocking rows still open, 6 clusters
undesigned.** `MRTR.9a` is the last open row of cluster A (21 rows). Nothing
about this document should read as "the release work is nearly done".

## State

- branch `fix/mrtr2-continuation-handle`, worktree
  `/Users/mikko/github/.worktrees/mcp-2026-protocol`
- design and test plan **committed and reviewed**; implementation **not started**
- `ef78864c` repairs from review round 2 · `556bd77c` test plan · `f5e764f7`
  design repairs round 1

## Reviews so far

| leg | material | verdict |
|---|---|---|
| kimi round 1 | design | SHIP-WITH-FIXES, 5 findings, all repaired |
| kimi confirmation | design | **SHIP** |
| gpt round 1 | design | SHIP-WITH-FIXES, 5 findings, all repaired |
| gpt confirmation | design | SHIP-WITH-FIXES, 3 findings, all repaired in `ef78864c` |
| gpt round 1 | test plan | SHIP-WITH-FIXES, 4 HIGH + 1 MED |
| second vendor round 1 | test plan | SHIP-WITH-FIXES, 2 HIGH + 3 improvements |

**Outstanding: a confirmation pass on `ef78864c` has not been run.** Both
test-plan legs are round-1 only. Run it before writing test code.

The second test-plan leg reported itself as `synthetic-review`, not `kimi-review`.
Recorded as a distinct vendor because it was a distinct process and its two HIGH
findings were independent of gpt's, but the vendor label is not verified.

## What the reviews changed, in one line each

- the mode detail is dropped by `error_response_preserving_status`
  (`src/gateway/meta_mcp/mod.rs:179-200`) — it forwards exactly one key
- the refusal message names the capability, which a mode-refused client *did*
  declare
- the `{}`-means-form default must apply before unrecognised keys are dropped
- the url-only client column was missing from the plan; the natural minimal
  patch passed every listed case and violated the criterion there

## Implementation sites, read and unmodified

| what | where |
|---|---|
| the flattening this change replaces | `src/protocol/meta.rs:186-191` |
| the three capability names | `src/protocol/meta.rs:256-263` |
| the gate | `src/protocol/mrtr.rs:296` (`undeclared(&self, declared: &[String])`) |
| the one `declares_capability` call | `src/gateway/router/handlers.rs:781-790` |
| where the vector is built | `src/gateway/router/handlers.rs:693` |
| the only other consumer | `src/gateway/router/handlers.rs:1152` (`input_capabilities:`) |
| the allowlist to widen | `src/gateway/meta_mcp/mod.rs:179-200` |
| the two existing cases | `tests/mik_7212_acs.rs:1759` (RED) and `:1782` (GREEN) |

Keep `declares_capability(&self, cap: &str) -> bool` and map the string to the
enum inside it — `required_capability` returns `&'static str`, so `:781` never
has to change and the diff stays at the parse plus the field.

## Doc sync when the row flips — four sites, not three

| site | change |
|---|---|
| `docs/requirements/RELEASE-4.0.0-criteria-status.md:128` | `MIK-7212.MRTR.9a` ABSENT → MET |
| `docs/requirements/RELEASE-4.0.0-readiness-board.md:17` | the row's narrative names MRTR.9a as cluster A's one open row; that becomes false |
| `docs/requirements/RELEASE-4.0.0-readiness-board.md:26` | `51 blocking rows.` → 50 |
| `scripts/count-release-criteria.py` | expected output moves off 95/51 |

Cluster A goes 21 → 20.
