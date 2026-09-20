# Post-4.0 simplification plan

Execution plan for the simplification passes. Evidence base:
[`simplification-census.md`](simplification-census.md), scanned at `f35cf6e3`.

The census's own headline governs the budget: **mechanical duplication in
production source is near-absent** — a structural-hash scan with identifiers and
string literals masked found zero 15-line blocks repeated across three or more
sites in 151K non-test lines. Total removable lines across every confirmed
bottom-up cleanup is ~708, which is 0.3% of the tree. Spend the budget top-down.

Each pass below is one PR. They are ordered so that no two passes touch the same
file, which is what lets them run concurrently without the criteria-ledger
conflict that has cost this release repeatedly.

## The governing target: no source file over 800 lines

This is a definition-of-done criterion, and it governs a **file**, not a change.
The 4.0 DoD check read it the other way — as a ceiling on diff size — and
recorded §2 Code Quality as `N/A at branch scope`
(`docs/internal/requirements/RELEASE-4.0.0-dod-check.md:356`). Under the per-file
reading the tree is measurably out of compliance:

| Measure | Count |
|---|---|
| Rust files over 800 lines | **91** |
| …in `src/` | 76 |
| …in `tests/` | 15 |
| Lines of excess above the ceiling | **64,284** |

`scripts/dev/check-file-size.py` measures this and gates it in CI. Because 91
files already exceed the ceiling, the gate **ratchets** off
`scripts/dev/file-size-baseline.txt`: a listed file may shrink, it may not
grow, and no file may newly cross 800 lines. Drop a row when the file clears
the ceiling. Regenerate with `--update` only when deliberately re-baselining.

## Sequencing: splits go last

**Do not start the file splits until every other change is merged.** A split
moves thousands of lines between files, so it conflicts with every branch that
touches the same code — and the conflicts are the expensive add/add kind that
cannot be resolved hunk-by-hunk. Land the behaviour work first, get the branch
list to zero, then split against a quiet tree.

Within the splits, `src/gateway/meta_mcp/invoke.rs` is the file every branch
conflicts in: **T2a must not start while any other PR touching `invoke.rs` is
open.** Everything else can run in parallel.

## Bottom-up passes — mechanical, ~708 lines

| ID | Change | Sites | Lines | Risk |
|---|---|---|---|---|
| B1 | Move integration tests onto the existing `tests/common/mod.rs:91` `state(Fixture)` builder instead of hand-building `AppState` | 15 files | ~510 | Low — tests only, and the builder already exists and is used by five files |
| B2 | Collapse the repeated six-field tail across meta-tool definitions | 18 | ~90 | Low |
| B3 | Delete the duplicate `is_retryable`; keep `src/failsafe/retry.rs:96` | 2 | 12 | Low — land with T1, same concept |
| B5 | Extract the repeated router test setup | 9 | ~96 | Low |
| B4 | Hand-written redacting `Debug` impls | ~48 | ~380 | **Excluded from the total.** This is a secret-redaction boundary, not a line-count cleanup — budget it as security work with its own review, or skip it |

B1 is 72% of the bottom-up value and is a half-finished migration rather than a
new abstraction, so it carries no design risk. Do it first and alone.

## Top-down passes — structural

**T1. Two retry loops, not four.** `src/chains/retry.rs` duplicates the role of
`src/failsafe/retry.rs`; `ChainRetryPolicy` (`src/chains/retry.rs:45`) mirrors
`RetryPolicy` (`src/failsafe/retry.rs:16`). `crate::failsafe` is the survivor —
it holds the module-level re-export (`src/failsafe/mod.rs:15`) and is wired into
`FailsafeState` (`:29`, `:41`). Absorbs B3.

- **Leave `src/gateway/server/warmstart.rs` alone.** Its slow phase is
  deliberately separate and the code says why at `:82-98`: `chains::retry_step`'s
  predicate rejects `BackendUnavailable`, the variant `start_entry` returns while
  a backend is mid-lifecycle, and the slow phase runs indefinitely so anything
  unlisted must stop the loop. That is a real boundary with real evidence.
- `src/capability/executor::send_with_retry` (`mod.rs:123`) belongs in the same
  pass but was **not read end to end** — census marks it **A** (assumption).
  Read it before including it.

**T2a. Split `src/gateway/meta_mcp/invoke.rs` (5,996 lines, 124 functions, two
of them public).** The seam is already visible: continuation minting (`:374`)
and redemption (`:594`) are a distinct concern from tool invocation and move to
`src/gateway/meta_mcp/continuation.rs`, alongside the existing
`src/protocol/continuation.rs`. Pure move, no behaviour change; the test is that
`cargo test` is unchanged.

**T2b. Split the 27-method `impl Gateway` in `src/gateway/server/mod.rs`
(5,002 lines, ~2,700 in that one impl).** Split the impl, not the struct.
Follow the precedent already set in the same directory —
`warmstart.rs` (1,086) and `support.rs` (1,028) are prior extractions from this
file. Continuing that pattern is cheaper than inventing a decomposition.

**T2c. The other 88 files over the ceiling.** T2a and T2b clear the two worst
offenders, which is 9,198 of the 64,284 excess lines — 14%. The rest is a
long tail: the next ten files are 2,000–3,986 lines each and most are test
modules (`meta_mcp/tests.rs` 5,986, `router/tests.rs` 3,739,
`config_reload/tests.rs` 2,983, `transport/http/tests.rs` 2,854). Test modules
split cheaply along the behaviour they cover and carry no API risk, so take
them first — they are the largest share of the excess at the lowest cost per
line. Work the baseline file top-down and delete each row as it clears.

## Dropped, recorded so nobody re-derives them

- **T3, the `config/features` mirror layer** — deliberate, census verified.
- **T4, single-implementor traits** — all three checked, all three are real
  seams.
- **T5, name collisions** — cost reading time, not lines. Not worth a rename's
  churn during a release.

## Definition of done per pass

A pass is done when `cargo test --quiet`, `cargo clippy --all-targets -- -D
warnings` and `cargo fmt --check` are clean, and the diff removes lines without
changing behaviour. A simplification pass that needs a new test to prove it did
not break something has changed behaviour and is no longer a simplification —
split the behaviour change into its own reviewed PR.
