<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: MIT -->

# NFR.OBS.3 — era detection is observable

`docs/requirements/RELEASE-4.0.0-requirements.md:292`, verbatim:

> | NFR.OBS.3 | Era detection per backend MUST be observable — which era, by what evidence, and when re-probed. | T |

That row is the last of the five in readiness-board group B and the only one no design document
covers (`docs/requirements/RELEASE-4.0.0-readiness-board.md:21`). This document covers it.

## §P0 SCOPE

**FOR:** the observability contract for era detection — what is recorded, on which target, in which
fields, and which surface answers a per-backend question about the current state.

**OUT:**

- the era probe itself, its cache, its invalidation rules, its identity rule. Owned by
  `docs/design/2026-08-31-discover-outbound-era-probe.md`; this document changes two things in that
  design's event table and nothing else.
- `DISCOVER.4`/`DISCOVER.5` wiring. Neither exists yet; see *Sequencing*.
- the HTTP-only gap in `NFR.OBS.1`/`NFR.OBS.2`. Named below only to record that OBS.3 does not
  inherit it.
- metrics, dashboards, alerting, log retention policy.

## This is a delta, not a new event set

The era design already specifies four events (`2026-08-31-discover-outbound-era-probe.md:626-631`),
quoted here as the thing being audited, **cited not authored**:

| event | fields |
|---|---|
| `era_probe` | `backend`, `outcome` ∈ {`modern`, `legacy`, `no_answer`}, `duration_ms`, `trigger` ∈ {`start`, `reprobe`} |
| `era_cache` | `backend`, `hit` ∈ {`true`, `false`} |
| `era_invalidated` | `backend`, `reason` ∈ {`restart`, `trigger`} |
| `era_probe_discarded` | `backend` |

OBS.3's job is to check that set against the criterion's three clauses. Two of the three are already
answered; one is not.

| clause | answered by | verdict |
|---|---|---|
| which era | `era_probe.outcome`; current state via `cached_era()` | covered |
| when re-probed | `era_probe.trigger=reprobe`, `era_invalidated.reason` | covered as *last*; see the tense decision |
| **by what evidence** | — | **not covered** |

## Finding 1 — `outcome` is the classification, not the evidence

`outcome ∈ {modern, legacy, no_answer}` is what the gateway concluded. The evidence is what it
concluded it *from*, and `classify` (`src/protocol/era.rs:61-96`) reaches each verdict by more than
one route:

| outcome | routes into it |
|---|---|
| `Modern` | a `server/discover` document naming a modern revision, **or** one of `UNSUPPORTED_PROTOCOL_VERSION` / `HEADER_MISMATCH` / `MISSING_REQUIRED_CLIENT_CAPABILITY` |
| `Legacy` | a document naming only 2025 revisions, **or** `-32601 method not found`, **or** an arbitrary application error, **or** silence |

`Legacy` is the one that costs. Four causes, one row, and they do not share a fix: a document naming
only 2025 revisions is a **dual-era peer mid-migration** — the exact case the classifier was
corrected for on 2026-08-29 (`:73-76`) — while `-32601` is a peer that will never be modern and an
arbitrary application error is somebody's bug. An operator watching a fleet cannot separate "three
peers are still migrating" from "three peers are throwing errors at us", and only the first of those
is going to resolve on its own.


The house already has the pattern. `NFR.OBS.1` records `protocol_revision` **and** `revision_source`
(`src/protocol/meta.rs:507-512`) — the value and how it arrived. `NFR.OBS.2` does the same for the
cache scope. Era detection is the one classification in this release that records the value alone.

**Delta:** `era_probe` gains an `evidence` field, a closed set naming which signal produced the
outcome (the discover result, or the specific error code encountered). It is a per-backend label like
the rest and adds no cardinality dimension the era design has not already reasoned about — the error
code appears as a *field on an event*, never as a metric label, which is the distinction that section
exists to protect (`:620-624`).

## Finding 2 — two components disagree about the tracing target

The era design places its four events on "the existing tracing subscriber" (`:626`) and names no
target. `NFR.OBS.1`/`NFR.OBS.2` emit on `mcp_gateway::observed`, and the verification harness filters
on exactly that string (`tests/nfr_obs_records.rs:95`; the collector's own self-test at
`src/gateway/server/mod.rs:3110-3132`). Era events on a module-default target are invisible both to
that harness and to an operator filtering the way OBS.1 and OBS.2 taught them to filter.

Per the repair table — *two components can disagree about X → one owner of X* — this is an
elimination, not a patch: `mcp_gateway::observed` is named as the single target for era events. After
it, "which target do era events use" is not a statable question. The alternative (a second convention
plus a note explaining when each applies) leaves the disagreement describable and merely documented.

This delta belongs to OBS.3 rather than to the era design because the target is an *observability*
contract, and OBS.3 is the row that owns it.

## The tense decision — "when re-probed" means *last*, plus *not before*

The criterion's third clause is ambiguous in English between "when it **was** re-probed" and "when it
**will be**". The second reading has no answer by construction: re-probe in the era design is
trigger-driven, fired by an invalidation (`era_invalidated.reason` ∈ {`restart`, `trigger`}), not
scheduled. There is no future time to report.

Rather than record the ambiguity as an operator question, this design serves the three facts that do
exist and makes the question unstatable:

1. **when it last happened** — the timestamp of the most recent `era_probe`;
2. **why** — its `trigger`, and for an invalidation the `reason`;
3. **not before** — the earliest a re-probe can follow, which is the `max_gap` floor of 30s the retry
   path already imposes (`src/gateway/server/warmstart.rs:47`, cited by the era design at `:610`).

Point 3 is a floor, never a schedule, and the wording of any surfaced field must say so. A field
named `next_probe_at` would be a lie; `probe_not_before` is not.

This is a design decision, recorded here per §P3 because it settles what an acceptance criterion
asserts.

## The surface — options and rejections

| option | verdict |
|---|---|
| the four events alone, target fixed, `evidence` added | **rejected as sufficient, kept as necessary.** An event stream answers "which era is backend X on **right now**" only by log archaeology, and no log-retention policy exists anywhere in this release. Two of the criterion's clauses are current-state questions. |
| a Prometheus gauge via `telemetry_metrics::` (`src/backend/ops.rs:183`) | **rejected.** Duplicates a value `cached_era()` already holds in process, adds a scrape delay, and `/metrics` is unauthenticated (`src/gateway/router/mod.rs:280`) — a per-backend era label puts fleet topology on an open endpoint for no answer the in-process read does not give first. |
| a new `gateway_era_status` meta-tool | **rejected.** Violates the locked decision "Meta-MCP surface is compact" (`CLAUDE.md`), and the operator surface for per-backend state already exists. |
| **extend `BackendStatus`, surfaced through `gateway_list_servers`** | **chosen.** |

`gateway_list_servers` (`src/gateway/meta_mcp/surfaced.rs:166-205`) is already the current-state
operator read: it returns per-backend `running`, `transport`, `tools_count`, `circuit_breaker`,
`status`, built from `BackendStatus` (`src/backend/registry.rs:52-66`) via `Backend::status()`
(`src/backend/ops.rs:481`). Era is the same kind of fact about the same object, and
`Backend::cached_era()` already exists (`src/backend/era.rs:61`) — the era design describes it as
"what makes the classification observable" (`:454`). The read costs a field set, not a tool.

Three fields, matching the three clauses:

| field | value |
|---|---|
| `era` | `modern` \| `legacy` \| `unprobed` — `unprobed` where `cached_era()` is `None`, which is a real state and not the same as `legacy` (`src/protocol/era.rs:164-167`) |
| `era_evidence` | which route produced it, from the closed set in Finding 1; absent when `era` is `unprobed` |
| `era_probed_at` | the last probe's timestamp; absent when never probed |

`probe_not_before` is deliberately **not** a field: it is `era_probed_at + 30s`, derivable by the
reader, and a stored copy is a second owner of the same fact.

**Surface-count drift:** this adds fields, not tools, so the Meta-MCP tool count in `README.md` and
`benchmarks/public_claims.json` is unchanged. Stated because that drift check has fired before, not
because it fires here.

## Stdio parity — OBS.3 does not inherit the OBS.1/OBS.2 gap

`NFR.OBS.1` and `NFR.OBS.2` are PARTIAL for one reason: they observe an HTTP request path and are
silent on stdio (`docs/requirements/RELEASE-4.0.0-criteria-status.md:324-325`, and the summary at
`:347`). Era probing is not at that
seam — it runs on both arms of backend start (`src/backend/lifecycle.rs:336` stdio, `:352` HTTP), and
`BackendStatus` is transport-agnostic. So OBS.3 is not scoped to a transport and must not be
verified only through an HTTP fixture.

## Sequencing — the design is not gated; the emission is

`DISCOVER.4` and `DISCOVER.5` are unwired, so no era event can be emitted or asserted today. That
gates **implementation**, not this document, and the direction matters:

- OBS.3 must be designed **before** DISCOVER.4-5 is built, because both deltas — the `evidence` field
  and the target — are changes to that design's event table. Designing after the build is the
  sunk-cost negotiation §P1 exists to prevent: the table would then be defended rather than amended.
- A test asserting `era_probe` records today fails on **missing symbols**, not on a missing
  assertion. §P2 explicitly disqualifies that as a caught defect, so writing one now would produce a
  red that proves nothing.
- The `Modern` outcome cannot be exercised against a real peer in 4.0.0 at all: `SUPPORTED_VERSIONS` names only 2025 and 2024
  revisions (`src/protocol/mod.rs:48`), and the outbound-header rows that would change that —
  `MIK-7214.HEADER.9a`/`9b` (`docs/requirements/RELEASE-4.0.0-requirements.md:131-132`) — are unwired.
  Fixtures can produce every route in Finding 1's table; a live peer cannot.

## Scheduled unknowns

| unknown | state | record |
|---|---|---|
| does a test fixture exist that starts a backend under a capturing subscriber? | **resolved** | `rg -ln 'Backend::start\|start_entry\|BackendPool' tests/` returned no match; the OBS harness `tests/nfr_obs_records.rs` is router-driven (`state()`, `post_with_headers`), so it observes HTTP requests, not backend starts. Changed the verification plan: OBS.3's tests cannot reuse that harness's driver, only its collector convention. |
| is the tracing collector's target filter reusable outside the router tests? | **resolved** | `src/gateway/server/mod.rs:3058` filters on `mcp_gateway::observed`, and its self-test at `:3110-3132` proves the collector sees a record emitted in its own scope, independent of any request. Reusable; this is what makes Finding 2's single-target rule verifiable. |
| does `evidence` need the specific error code, or only the route class? | **deferred** — owner: this ticket's implementation; resolved by: whether the three modern codes ever need separating in practice, asked of the operator or observed once emission exists; when: at DISCOVER.4 wiring; if it resolves badly: the field widens from a class to a code, which is additive. Nothing depending on it is implemented. |
| does a per-backend era field on an operator read carry an access-control constraint `gateway_list_servers` does not already carry? | **deferred** — owner: this ticket; resolved by: reading the meta-tool's auth path at implementation; when: before the field lands; if it resolves badly: era moves behind whatever gate the rest of `BackendStatus` uses, which is the same gate. |

## Open for the operator

One question. It is not an engineering choice — it turns on how the fleet is actually operated.

> **Is an operator expected to answer "which era is backend X on right now" from a live read, or from
> the logs?**
>
> Recommendation: **a live read** — the `BackendStatus` / `gateway_list_servers` fields above,
> alongside the four events. Reason: no log-retention policy is specified anywhere in this release,
> so a log-only answer is only as good as whatever retention happens to be configured, and two of the
> criterion's three clauses are current-state questions. The cost is three fields on a struct that
> already carries six; `cached_era()` exists, so nothing new is computed.
>
> If the answer is logs-only, Finding 1 and Finding 2 still stand unchanged — the evidence field and
> the single target are what make a log answer possible at all — and the `BackendStatus` section is
> dropped.
