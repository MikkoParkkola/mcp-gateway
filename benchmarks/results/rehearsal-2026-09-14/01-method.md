# Rehearsal 2 — NFR.WORKLOAD.1, method and provenance

Second rehearsal of the workload harness. A rehearsal is **not** the scored run:
§4 of the contract admits a gating number only from a post-merge interleaved run,
and `feat/v4-workload-harness` is unmerged. Everything here is evidence about the
harness and about 4.0.0 behaviour, not a release verdict.

## What changed since rehearsal 1 (2026-09-13)

1. `eval_workload.py` void 4 read a k6 key that is never emitted, so every run
   voided before a rep could be graded (fix `339ac7aa`). The digest recorded in
   `docs/requirements/workload-pins-observed.md` now names the fixed file.
2. Rehearsal 1 lost A3 to an ephemeral-port collision on 39420. The cell ports
   (39420-39424) were reserved on the host before this run.

## Host state outside the contract

The port reservation is host state on a shared machine and is **not** recorded in
`pins.json`. A future run on an unreserved host can lose a rep to the same
collision with nothing in the run directory explaining why. This is a gap in the
contract, not in the run.

## Arms

| Cell | Ref | Checkout SHA | Port | Protocol | Scored |
|---|---|---|---|---|---|
| A | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` | 39420 | legacy `2025-06-18` | yes |
| B | `v3.5.1` | `e138680a542b41fa156a94a1ffc9decd9692be77` | 39421 | legacy `2025-06-18` | yes |
| C | `HEAD` | `69ba9e03cc6df0a6a92fdaa813444a61e97cc29e` | 39422 | legacy `2025-06-18` | yes |
| D | `HEAD` | `69ba9e03cc6df0a6a92fdaa813444a61e97cc29e` | 39423 | modern `2026-07-28` | report-only |
| E | `HEAD` | `69ba9e03cc6df0a6a92fdaa813444a61e97cc29e` | 39424 | mixed | report-only |

SHAs are read from each arm's `.checkout_sha`, written by the runner before k6 starts.

k6 image pinned by digest `sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755`
(void 9 forbids an unpinned image or a tag; the local k6 binary is never substituted).
