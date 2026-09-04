# NFR.OBS.3 — test plan

Reviewed as a plan per §P2, before any test is written. No case predates it.

**Criterion.** `NFR.OBS.3` — era detection per backend MUST be observable: which
era, by what evidence, and when re-probed
(`docs/requirements/RELEASE-4.0.0-requirements.md:292`). Design:
`docs/design/2026-09-03-nfr-obs-3-era-observability.md`.

The criterion has three clauses and they are covered separately below, because a
suite that renders the fields and never drives a re-probe satisfies two of the
three while leaving the third — the clause the ticket exists for — unwritten.

## Clause coverage

| clause | what proves it | level | type |
|---|---|---|---|
| which era | `era` and `era_source` on the operator read agree with what the request path acts on, for a probed backend and an unprobed one | system | behaviour |
| by what evidence | every `EraEvidence` variant is reachable from the probe path and renders on the read | component | behaviour |
| when re-probed | `era_probed_at` and `era_probe_trigger` move on a re-probe and not on a discarded outcome | component | behaviour |

No empty cell. The third row is the one with no equivalent in the existing suite.

## The evidence matrix

One case per `EraEvidence` variant, because the closed set is the criterion's
"by what evidence" and a variant with no case is a value the emitter may name
and never produce. Columns are what the read must show afterwards.

| case (probe input) | `era` | `era_source` | `era_evidence` | `era_probed_at` |
|---|---|---|---|---|
| no probe run | `legacy` | `assumed` | `never_probed` | absent |
| discovery doc naming a modern revision | `modern` | `probed` | `discover_modern` | set |
| discovery doc naming no speakable revision | `legacy` | `probed` | `discover_not_modern` | set |
| `UNSUPPORTED_PROTOCOL_VERSION` | `modern` | `probed` | `modern_error_code` | set |
| `-32601` | `legacy` | `probed` | `method_not_found` | set |
| any other error code | `legacy` | `probed` | `other_error` | set |
| deadline expiry, transport failure, unparseable result | `legacy` | `assumed` | `no_answer` | set |

`HEADER_MISMATCH` and `MISSING_REQUIRED_CLIENT_CAPABILITY` collapse into the
`modern_error_code` row deliberately: the design fixes one variant for all three,
so three cases asserting one value would test the fixture, not the mapping. The
raw code rides the event's `error_code` field and is asserted there instead.

**The `no_answer` row is the regression row.** It is the only case where
`era_source` is `assumed` while `era_probed_at` is set, and an implementation
that sets `era_source = probed` whenever a probe completes passes every other row
in this matrix. A suite that collapses it into the error rows cannot see that
defect.

## Transition cases

Three cases the matrix cannot express, because they are about change over time
rather than a single outcome.

| case | asserts |
|---|---|
| start probe, then a contradiction re-probe that answers modern | `era_probe_trigger` moves `start` → `reprobe`, `era` moves `legacy` → `modern`, `era_probed_at` advances |
| a re-probe that gets no answer after a probe that did | `era_source` moves back to `assumed`, `era_probed_at` still advances |
| a stale probe outcome is discarded | no field moves — `era_probe_discarded` is emitted and the observation is byte-identical before and after |

The third is the case most likely to be omitted and the one that catches a
writer placed on the wrong side of the staleness check.

## Can each case fail?

The §P2 honesty question, answered per group rather than per case.

- **The evidence cases drive `classify` through the production probe path**
  (`src/backend/era.rs:32-46` folds the transport outcomes; `src/protocol/era.rs:61-96`
  routes them). A fixture that constructs an `EraObservation` and asserts its own
  field values cannot fail and is not an acceptable form for any row above.
- **The read cases go through the `gateway_list_servers` response**, not through
  the observation struct. Asserting the struct would leave a serialisation gap
  invisible, which is exactly the gap `NFR.OBS.1` and `NFR.OBS.2` were re-opened for.
- **The `never_probed` case must observe a backend that was never probed**, not one
  whose observation was reset. A reset reaches the same field values by a path the
  criterion does not describe.
- **The transition cases assert a before and an after from the same backend.** A
  case that inspects only the after state passes against an implementation that
  never wrote the before state.

## Out of scope

- The restart row of the design's transition table. `invalidate()` has one caller
  and no restart path clears the era
  (`docs/design/2026-09-03-nfr-obs-3-era-observability.md`, the `†` note), so a case
  for it would assert behaviour this change does not add.
- Whether the three modern error codes should separate into three variants. Additive
  if it is ever wanted; nothing here forecloses it.
- Stdio parity. The design records that OBS.3 does not inherit the OBS.1/OBS.2 gap
  because the era read is not emitted from the HTTP router.
