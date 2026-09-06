<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.OBS.4 — test plan for the continuation counters

Plan, not tests. The design is `docs/design/2026-09-01-continuation-telemetry.md`, including its
2026-09-07 receipt update, which decides the counter set, the label sets, and how a test reads the
numbers. Nothing here re-decides any of that; this says what proves it.

## These tests fail freely — no falsifier probe

No continuation counter exists at any revision of this repo (`NFR.OBS.4` = ABSENT in
`docs/requirements/RELEASE-4.0.0-criteria-status.md`). Every case below therefore fails for the
right reason on the day it is written — the counter it reads is not in `render()` output at all —
and the retrofitting exception does not apply. That is the opposite of `NFR.PERF.3`, whose
mechanism is already built and whose soak needs the probe recorded in
`docs/design/2026-09-01-nfr-perf3-reclamation.md`. The two halves of this release slice are at
different points of the same process, and treating them alike would either waste a probe here or
skip one there.

## How every case observes a counter

Fixed once, so no row restates it. `metrics` is a default feature; the case is
`#[cfg(feature = "metrics")]`, calls `crate::metrics::install()`, reads `crate::metrics::render()`
before and after the action, and asserts `after >= before + N` on the parsed series. Precedent and
the reason the assertion is `>=` rather than `==`: the design's 2026-09-07 receipt. A helper that
parses one series out of the Prometheus text is written once and shared; `invoke.rs:4749`
(`suppressed_counter_value_for`) is the shape.

Absolute-value assertions are banned in this plan, in every row, including the ones where a value
of 1 looks safe. The recorder is process-global and these counters have no per-test label to
isolate on.

## The cases

`ID` decomposes one release criterion for tracking inside this plan; the criterion is the row
`NFR.OBS.4` in the criteria table, and these are not new acceptance criteria.

| ID | claim it proves | case | level | type | how it goes red |
|---|---|---|---|---|---|
| OBS.4.1 | mint is counted | one successful mint through the production mint path; assert `mcp_continuation_mint_total` rose by ≥1 | unit (in `src/protocol/`) | functional | counter absent, or minting does not increment it |
| OBS.4.2 | redeem is counted | one envelope minted then successfully redeemed; assert `mcp_continuation_redeem_total` rose by ≥1 | unit | functional | as above, on the redeem path |
| OBS.4.3 | **redeem counts acceptances, not attempts** | one envelope refused at redeem (`not_authentic`); assert `redeem_total` did **not** rise and `rejected_total{reason="not_authentic",phase="redeem"}` did | unit | negative | an implementation that increments on attempt passes 4.2 and fails only here |
| OBS.4.4 | expiry is counted, with who noticed | an envelope presented after its deadline; assert `expired_total{detected="presented",phase="redeem"}` rose | unit | boundary | expiry counted on the wrong counter, or `detected` not carried |
| OBS.4.5 | **an expiry is never also a rejection** | same action as 4.4; assert `rejected_total` did not rise on any `reason` | unit | negative | the mapping books `ContinuationError::Expired` as a reason, which the design forbids by name |
| OBS.4.6 | every `ContinuationError` variant maps to its documented reason | table-driven over the six mapped variants, one refusal each, asserting the exact `reason` value | unit | functional, table-driven | a variant mapped to the wrong label, or to none |
| OBS.4.7 | **the reason set is the refusal set, not one type's variants** | one refusal that has no `ContinuationError` — a mint refused for want of a principal fingerprint — asserting `rejected_total{reason="no_principal_fingerprint",phase="mint"}` | unit | functional | an implementation that derives the enum from `ContinuationError` compiles, passes 4.6, and fails only here. This is the case the design's own §"the reason set is the refusal set" exists to force |
| OBS.4.8 | the label **keys** are the compatibility surface | for each of the four counters, assert the key set on its emitted series is exactly the documented one (values not asserted) | unit | contract | a key added, renamed or dropped — the change the design says breaks consumers |
| OBS.4.9 | cardinality is bounded by construction | assert the arity of the reason and phase enums and their product against the documented ceiling of 30 series | unit | boundary | a label whose values are not a closed enum, which is the D-threat the design mitigates |
| OBS.4.10 | the counters fire from the production path | the mint/redeem cases drive the same entry point production uses (`ContinuationState::begin_exchange`, reached from `src/gateway/meta_mcp/invoke.rs:385`), never a test-only constructor | unit | wiring | counters wired to a path only tests reach — passes every row above and satisfies nothing |

## Criteria with no case, and why — the empty cells

| claim | why no case here | owner |
|---|---|---|
| `detected="awaited"`, and the `round_budget`, `capability_undeclared`, `delivery_failed`, `declined` reasons | all four are `phase="bridge"` and the bridge does not exist: `docs/design/2026-09-01-mrtr7-legacy-client-bridge.md` is a design, `MRTR.7` is out of this slice's scope | MRTR.7. Each of these reasons gets its case in the change that builds the site that raises it, which is also where the site can first be made to raise it |
| `detected="reaped"` | the reaper-side expiry is asserted by the lifetime case in `docs/design/2026-09-01-nfr-perf3-reclamation.md` §"Three cases the uniform-deadline epochs cannot reach", which already asserts `expired_total{detected="reaped"}` advanced by exactly N | `NFR.PERF.3` + MRTR.8b. Duplicating it here would give two owners one assertion |
| `too_large` on the `mint` phase | the reason's `redeem` phase is covered by 4.6; the mint-phase arm needs an oversized mint payload fixture, which is a fixture question, not a coverage gap — added with 4.6's table if the arm exists at implementation time, and recorded as a missing row if it does not | this change |
| the derived quantity *decided redemptions* | it is an arithmetic identity over three counters that 4.2–4.5 each assert, plus a documented dashboard expression. A test would assert addition | none — stated, not deferred |

## What this plan does not prove

An operator can see the numbers. Every case reads `render()` in-process; none scrapes `/metrics`
over HTTP. The endpoint is exercised by `tests/metrics_export_test.rs` for counters that already
exist, and these four ride the same recorder — so the gap is the wiring between `install()` at
server startup and these increments, not the export. Named because "counters nobody can see" is
the failure mode `NFR.OBS.4` exists to prevent, and no row above would notice it.
