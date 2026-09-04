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
| which era | for a probed-modern backend and a never-probed one: issue a request whose result differs by era, and assert the operator read's `era` agrees with the behaviour observed | system | behaviour |
| by what evidence | every `EraEvidence` variant is reachable from the probe path and renders on the read | component | behaviour |
| when re-probed | `era_probed_at` and `era_probe_trigger` move on a re-probe and not on a discarded outcome | component | behaviour |
| per backend | two backends with different eras each show their own `era`, `era_evidence` and `era_probed_at` on one `gateway_list_servers` response | system | behaviour |

No empty cell. The third row is the one with no equivalent in the existing suite.

**The first row asserts agreement, not rendering.** A case that reads the field and
stops proves the field exists; it cannot distinguish a read wired to the request
path from one wired to a constant. So the case must drive a request the two eras
answer differently — a call only a modern peer serves — and assert that the read
and the observed behaviour say the same thing. Without that, the clause passes
against an implementation whose read is decorative.

**The fourth row is what makes `per backend` a claim rather than a word.** Every
other case observes one backend, and a single shared era cell renders identically
to a per-backend one when only one backend exists.

## The evidence matrix

One case per `EraEvidence` variant, because the closed set is the criterion's
"by what evidence" and a variant with no case is a value the emitter may name
and never produce. Columns are what the read must show afterwards.

| case (probe input) | `era` | `era_source` | `era_evidence` | `era_probe_trigger` | `era_probed_at` |
|---|---|---|---|---|---|
| no probe run | `legacy` | `assumed` | `never_probed` | absent | absent |
| discovery doc naming a modern revision | `modern` | `probed` | `discover_modern` | `start` | set |
| discovery doc naming no speakable revision | `legacy` | `probed` | `discover_not_modern` | `start` | set |
| `UNSUPPORTED_PROTOCOL_VERSION` | `modern` | `probed` | `modern_error_code` | `start` | set |
| `-32601` | `legacy` | `probed` | `method_not_found` | `start` | set |
| any other error code | `legacy` | `probed` | `other_error` | `start` | set |
| deadline expiry, transport failure, unparseable result | `legacy` | `assumed` | `no_answer` | `start` | set |

Two assertions ride every row rather than getting rows of their own:

- **the read carries no `error_code` field.** The raw code is an event field. A read
  that leaks it has widened the operator surface past what the design fixed, and no
  positive assertion in this matrix would notice.
- **on the three error rows, the `era_probe` event's `evidence` equals the read's
  `era_evidence`.** The design's "one enum, both readers" property is only a property
  if something compares the two; asserting each against its own literal lets them drift
  apart while both suites stay green.

One read case additionally asserts the serialised shape of `era_probed_at` — RFC 3339,
UTC, second precision, `Z` suffix — once. Asserting it per row tests the fixture; not
asserting it anywhere leaves the design's stated format unenforced.

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

Two cases the matrix cannot express, because they are about change over time
rather than a single outcome.

| case | asserts |
|---|---|
| start probe, then a contradiction re-probe that answers modern | the complete after-snapshot: `era` `modern`, `era_source` `probed`, `era_evidence` `modern_error_code`, `era_probe_trigger` `reprobe`, `era_probed_at` the stepped clock value |
| a re-probe that gets no answer after a probe that did | the complete after-snapshot: `era` `legacy`, `era_source` back to `assumed`, `era_evidence` `no_answer`, `era_probe_trigger` `reprobe`, `era_probed_at` the stepped clock value |

**Both assert a complete wire snapshot, before and after, not the fields that
moved.** A transition case that pins only the moving fields passes while a stale
`era_evidence` or an unchanged `era_probe_trigger` survives beside a correctly
updated `era` — an internally inconsistent read that no per-field assertion sees.
Each snapshot names all five fields and their required presence or absence.

**"Advances" needs a clock the test owns.** `era_probed_at` is wall-clock at second
precision, so two probes inside one second stamp identically and the assertion is
flaky at best and vacuous at worst. The component cases inject a clock and step it
between the two probes; the assertion is then equality against the stepped value,
not a `>` against whatever the machine happened to be doing. Sleeping for a second
is the alternative and is rejected: it buys the same assertion at the cost of a
second per case and still fails on a coarse clock.

## The event contract

The read is one observability surface and the event stream is the other. Four
records are in the design's table; three have producing paths and get cases, on a
captured `mcp_gateway::observed` subscriber rather than on log text.

| record | asserted |
|---|---|
| `era_probe` | target, `backend`, `outcome`, `evidence`, `duration_ms`, `trigger`; `error_code` present only on the three error rows and absent otherwise |
| `era_cache` | target, `backend`, `hit` — `false` on the resolving probe, `true` on the next read of the same backend |
| `era_invalidated` | target, `backend`, `reason` `trigger` on the contradiction path |

Absences are asserted, not assumed: a record carrying a field the design did not
give it has widened the surface as surely as a missing one has narrowed it, and
only a pinned field set sees either.

`era_invalidated` with `reason=restart` has no case for the same reason the restart
row is out of scope below: nothing clears the era on restart.

## Not executable — `era_probe_discarded`

The design's fourth record has no producing path, so the "stale outcome discarded"
case is removed rather than written red.

`ProtocolEra::resolve_with` takes the era mutex and holds it across the probe
(`src/protocol/era.rs:152-163`), so concurrent resolution serialises onto a single
probe and no second outcome can arrive stale. There is no generation or epoch
counter to make one identifiable if it could. The design records the same fact
against the cited event (the `‡` note under its event table).

| field | value |
|---|---|
| owner | `MIK-7217` (era detection), carried forward with the record |
| what would resolve it | a probe identity — generation counter or transport epoch — that makes a late outcome distinguishable from the live one |
| when | when a second concurrent probe path is introduced; not before, because today there cannot be one |
| if it resolves badly | the cited record stays cited and stays marked unreachable; the design's amendment to its field set is withdrawn rather than left describing a branch nothing reaches |

Nothing in this plan depends on it.

## The independence case

One system case, because the criterion says *per backend* and every other case
observes one.

Two backends in one `gateway_list_servers` response: A probed and classified
`modern`, B never probed. Each entry carries its own `era`, `era_source`,
`era_evidence` and `era_probed_at`, and B's `era_probed_at` is absent while A's is
set. A shared cell, a cached first answer, or a fold over all backends renders
identically when only one backend is observed, and this is the only case that
separates them.

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
- **The first clause's case drives a request, not a read.** A case that asserts the
  `era` field alone cannot fail against a read wired to a constant; one that also
  observes era-dependent request behaviour can.
- **The independence case needs two backends with different eras.** With one
  backend, or with two in the same era, a single shared cell renders correctly and
  the case passes against the defect it exists to catch.
- **The event cases pin field sets, including absences.** Asserting only the fields
  the design names leaves an extra field — a leaked `error_code`, a raw version
  string — invisible, and that is the drift between the two surfaces the design
  fixed one enum to prevent.

## Out of scope

- The restart row of the design's transition table. `invalidate()` has one caller
  and no restart path clears the era
  (`docs/design/2026-09-03-nfr-obs-3-era-observability.md`, the `†` note), so a case
  for it would assert behaviour this change does not add.
- Whether the three modern error codes should separate into three variants. Additive
  if it is ever wanted; nothing here forecloses it.
- Stdio parity. The design records that OBS.3 does not inherit the OBS.1/OBS.2 gap
  because the era read is not emitted from the HTTP router.
