# NFR.OBS.4 — count the expiry nobody comes back for

## Problem

`NFR.OBS.4` requires continuation mint, redeem, expiry and rejection to be
counted, with a reason. Three of the four are wired and reasoned
(`src/gateway/meta_mcp/invoke.rs:514`, `:526`, `:680`). Expiry is counted for
one of its two observation points only.

A continuation's expiry is observable in two places. A client presents a stale
envelope and is refused: counted,
`continuation_expiry_total{reason="deadline_passed"}` (`invoke.rs:535`). And
the in-flight table drops the hold when a later reader passes a `now` beyond
its deadline (`reclaim_abandoned`, `src/protocol/continuation.rs:675`): **not
counted**.

The eviction is the one an operator cannot see any other way. A refusal leaves
a trace in the client's own failed call; a hold that ages out of the table
while nobody looks leaves nothing.

**The two are observation points, not disjoint causes.** One continuation can
produce both: a client that returns late is refused (one count) and its hold is
evicted by the next reader that passes a later `now` (a second count). A
continuation whose client never returns at all produces only the eviction. So
the counts are not a partition of expired continuations and must not be
summed as if they were — each names an event that happened, not a population.
The reason labels say what was observed rather than what the client did, which
is all the gateway can honestly know: `deadline_passed` for the refusal,
`hold_evicted` for the eviction.

The comment at `invoke.rs:530` already tells the reader that
`reclaim_abandoned` is "instrumented separately in `continuation.rs` under
NFR.OBS.4". It is not. The comment is false today, and a false comment about
instrumentation is worse than none: it is read as evidence the gap is covered.

## Options

1. **Increment inside `reclaim_abandoned`.** Two lines, no signature change, no
   caller change. Counts where the event happens.
2. **Return the eviction count; count at the caller.** `reclaim_abandoned`
   returns how many holds it dropped and `InFlight::guard` increments by that
   number. Makes the quantity assertable without a metrics recorder, at the
   cost of a signature change and a producer/consumer split.
3. **Delete the false comment and accept the gap.** Cheapest, and fails the
   criterion.

**Chosen: 1.** Option 2 was chosen first on the belief that the emission could
not otherwise be observed — that belief was false. `metrics-exporter-prometheus`
is a default-feature dependency (`Cargo.toml:167`, `metrics = ["dep:..."]`),
`mcp_gateway::metrics::install()` and `render()` are in-tree, and
`tests/metrics_export_test.rs` is the working precedent for exercising them from
an isolated integration-test binary. With the emission directly observable, the
only argument for splitting producer from consumer disappears, and option 1 is
the smaller change.

## Scope

FOR: making the eviction observable, and making the `invoke.rs:530` comment
true.

OUT: the other three counters, which are wired and reasoned already. New metric
names beyond one reason label on the existing `continuation_expiry_total`. Any
change to when reclamation happens — `MIK-7212.MRTR.8b` settled that and this
change must not move it.

## Test

An integration test in its OWN binary, because
`PrometheusBuilder::install_recorder` installs a process-global recorder behind
a `OnceLock` (`src/metrics.rs`) and a second test in the same binary would race
on it — the reason `tests/metrics_export_test.rs` is already isolated.

It drives production reclamation rather than reissuing the macro: hold two
exchanges, then read the table with a `now` past both deadlines, so
`InFlight::guard` runs `reclaim_abandoned` for real. It asserts the metric name
is absent before, and present with `reason="hold_evicted"` and the value `2`
after. Deleting the increment fails it; incrementing by the wrong amount fails
it.

Boundary cases pinned in the same test, each a way the count could be wrong
while still being non-zero: a read at exactly the deadline evicts nothing (the
retain is `now <= deadline`, so equality is live — the same boundary
`MIK-7212.MRTR.8b` settled); a hold completed before it expired is not counted,
since `complete` removed it; and a second read after the eviction adds nothing,
because the entries are gone rather than merely stale.

## Unknowns

- **Does the reason label collide with an existing series?** — checked by
  searching the source for `continuation_expiry_total` — the only emission is
  `invoke.rs:535` with `reason="deadline_passed"` — no collision, the two
  observation points stay separable on one metric.
- **Is `guard` the only caller of `reclaim_abandoned`?** — checked by searching
  the source and the test tree — one call site, `continuation.rs:736` — so a
  single increment cannot miss an eviction path.
- **Is a metrics recorder reachable from a test without a new dependency?** —
  checked against `Cargo.toml:167`, `src/metrics.rs` and
  `tests/metrics_export_test.rs` — yes, on the default `metrics` feature — which
  is what reversed the choice of option.
