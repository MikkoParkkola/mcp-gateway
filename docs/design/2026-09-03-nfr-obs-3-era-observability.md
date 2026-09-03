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

- the era probe itself, its timing, its invalidation rules, its identity rule. Owned by
  `docs/design/2026-08-31-discover-outbound-era-probe.md`. This document amends that design in two
  places — the `era_probe` field set and the tracing target — and relocates where the classification
  is stored so a synchronous reader can see it. It changes no probing behaviour.
- `DISCOVER.4`/`DISCOVER.5` themselves. Both are wired (`bb3727a2`); OBS.3 observes them and
  changes neither.
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

## Finding 0 — the four events do not exist

The era prober shipped (`bb3727a2 feat(protocol): probe and cache each backend's protocol era`,
`897cfd65`). `DISCOVER.4` and `DISCOVER.5` are wired: `Backend::ensure_started()` probes,
`Backend::cached_era()` reads (`src/backend/era.rs:61`), a contradiction re-probes (`:92-101`), and
`tests/mik_7217_era_probe_acs.rs` asserts all of it against a fixture peer.

The four events did not ship with it:

```
$ rg -n 'era_probe|era_cache|era_invalidated|mcp_gateway::observed' src/backend/*.rs src/protocol/era.rs
(no matches)
```

So the criterion is unmet in the plainest possible way — the detection is complete and emits nothing.
Findings 1 and 2 are amendments to a table that has not been implemented yet, which is the cheapest
moment to amend it.

**This also corrects a stale status.** `docs/requirements/RELEASE-4.0.0-criteria-status.md:326` marks
`NFR.OBS.3` ABSENT and gives the reason as "verifies MIK-7217.DISCOVER.4-5, both unwired; there is no
detection to observe". Both are now wired. The row stays ABSENT, but for a different and much
narrower reason: the detection exists and is silent.

## Finding 1 — `outcome` is the classification, not the evidence

`outcome ∈ {modern, legacy, no_answer}` is what the gateway concluded. The evidence is what it
concluded it *from*, and `classify` (`src/protocol/era.rs:61-96`) reaches each verdict by more than
one route:

| outcome | routes into it |
|---|---|
| `Modern` | a `server/discover` document naming a modern revision, **or** one of `UNSUPPORTED_PROTOCOL_VERSION` / `HEADER_MISMATCH` / `MISSING_REQUIRED_CLIENT_CAPABILITY` |
| `Legacy` | a document naming only 2025 revisions, **or** `-32601 method not found`, **or** an arbitrary application error, **or** silence — but silence is *treated* as legacy and never *remembered* as legacy (`src/protocol/era.rs:163-171`) |

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

The criterion's third clause is ambiguous between "when it **was** re-probed" and "when it **will
be**". The second reading has no answer by construction: re-probe is trigger-driven, fired by a
contradiction (`src/backend/era.rs:92-101`), never scheduled. There is no future time to report.

Rather than record the ambiguity as an operator question, this design serves the three facts that do
exist, which makes the question unstatable:

1. **when it last happened** — the timestamp of the most recent probe;
2. **why** — whether that probe was a `start` or a `reprobe`;
3. **not before** — the era design imposes "at most one re-probe per 30s" per backend
   (`2026-08-31-discover-outbound-era-probe.md:609-610`, reusing `max_gap`,
   `src/gateway/server/warmstart.rs:47`). The anchor is the completion of the last probe, so the
   earliest a re-probe can follow is `era_probed_at + 30s`.

Point 3 is a floor, never a schedule. A field named `next_probe_at` would be a lie;
`probe_not_before` would be true but is not stored — it is derivable from a field the reader already
has, and a stored copy is a second owner of the same fact.

This is a design decision, recorded per §P3 because it settles what an acceptance criterion asserts.

## The surface — options and rejections

| option | verdict |
|---|---|
| the four events alone, target fixed, `evidence` added | **rejected as sufficient, kept as necessary.** An event stream answers "which era is backend X on **right now**" only by log archaeology, and no log-retention policy exists anywhere in this release. Two of the criterion's three clauses are current-state questions. |
| a Prometheus gauge via `telemetry_metrics::` (`src/backend/ops.rs:183`) | **rejected.** Duplicates a value the process already holds, adds a scrape delay, and `/metrics` is unauthenticated (`src/gateway/router/mod.rs:280`) — a per-backend era label puts fleet topology on an open endpoint for no answer the in-process read does not give first. |
| a new `gateway_era_status` meta-tool | **rejected.** Violates the locked decision "Meta-MCP surface is compact" (`CLAUDE.md`), and the per-backend operator read already exists. |
| **extend `BackendStatus`, surfaced through `gateway_list_servers`** | **chosen**, with the state owner below. |

`gateway_list_servers` (`src/gateway/meta_mcp/surfaced.rs:166-205`) is already the current-state
operator read: per backend it returns `running`, `transport`, `tools_count`, `circuit_breaker`,
`status`, built from `BackendStatus` (`src/backend/registry.rs:52-66`) via `Backend::status()`
(`src/backend/ops.rs:481`). Era is the same kind of fact about the same object. The read costs a
field set, not a tool.

### One owner: `EraObservation`

`Backend::status()` is **synchronous** (`src/backend/ops.rs:481`); `Backend::cached_era()` is
**async** (`src/backend/era.rs:61`), because the era sits behind an async lock. A status read cannot
await, and the cache stores neither evidence nor a timestamp — so as the code stands there is nothing
for these fields to be read from.

Bridging the two (a `try_read`, a blocking read, a duplicated copy kept in step) creates a second
owner of the era and a staleness question with it. The elimination instead: **the probe's outcome is
recorded once, in one place, and both readers derive from it.**

```rust
struct EraObservation {
    era: Option<Era>,        // None until a probe has classified one
    evidence: EraEvidence,   // how that era was reached; NeverProbed until then
    probed_at: Option<SystemTime>,   // wall clock: this field is serialised into a JSON read
    trigger: Option<ProbeTrigger>, // Start | Reprobe
}
```

Held in a `std::sync::RwLock` on the same entry the era lock guards today, written at the point
`commit_if` commits (`2026-08-31-discover-outbound-era-probe.md:453`) and at the point a `NoAnswer`
outcome is discarded. It is plain data behind a non-async lock, never held across an await, so
`status()` reads it directly and `cached_era()` reads `.era` from it. The async `EraCache` stops
being the owner of the classification and becomes the thing that serialises probing.

### The fields

| field | value |
|---|---|
| `era` | `modern` \| `legacy` — **what the request path will act on**, which always has an answer: an unclassified backend is treated as legacy (`src/protocol/era.rs:164-167`) |
| `era_source` | `probed` \| `assumed` — whether `era` came from a classification or from that default. The `NFR.OBS.1` `revision_source` pattern (`src/protocol/meta.rs:507-512`) |
| `era_evidence` | how the last probe ended, from the closed set below |
| `era_probed_at` | completion time of the last probe; absent only when never probed |
| `era_probe_trigger` | `start` \| `reprobe` — which kind that last probe was; absent only when never probed |

`era_source` is what makes "never probed" and "probed and got silence" distinguishable, and both are
`era=legacy` because that is what the gateway will actually do to them. Without it the two collapse,
and they have different fixes.

### `EraEvidence` — the closed set, enumerated now

Deferring this to implementation lets the emitter and the test agree on incompatible meanings, so it
is fixed here. One variant per route in `classify` (`src/protocol/era.rs:61-96`):

| variant | route |
|---|---|
| `never_probed` | no probe has completed |
| `discover_modern` | a `server/discover` document naming a modern revision → `Modern` |
| `discover_2025_only` | a document naming only 2025 revisions → `Legacy`, and the dual-era migrating peer |
| `modern_error_code` | `UNSUPPORTED_PROTOCOL_VERSION`, `HEADER_MISMATCH` or `MISSING_REQUIRED_CLIENT_CAPABILITY` → `Modern` |
| `method_not_found` | `-32601` → `Legacy`, the honest legacy answer |
| `other_error` | any other error code → `Legacy`, the sloppy one |
| `no_answer` | the probe deadline expired → nothing cached |

Seven values, no raw error code among them. **One enum, both readers**: `era_probe.evidence` and
`era_evidence` on the operator read render the same `EraEvidence`, so the event stream and the live
read cannot drift into two vocabularies for one route. The specific error code, where it is wanted
for debugging, rides the `era_probe` **event** as a separate optional field; it does not enter the
operator read and never becomes a metric label. Whether the three modern codes ever need separating on the read is the
one thing genuinely deferred, and widening a variant into three is additive.

### Every transition

| from | event | `era` | `era_source` | `era_evidence` | `era_probed_at` | `era_probe_trigger` |
|---|---|---|---|---|---|---|
| fresh backend | — | `legacy` | `assumed` | `never_probed` | absent | absent |
| start probe → modern doc | `era_probe` | `modern` | `probed` | `discover_modern` | set | `start` |
| start probe → `-32601` | `era_probe` | `legacy` | `probed` | `method_not_found` | set | `start` |
| start probe → deadline | `era_probe` | `legacy` | `assumed` | `no_answer` | set | `start` |
| contradiction fires | `era_invalidated` | unchanged until the re-probe commits | | | | |
| re-probe → modern code | `era_probe` | `modern` | `probed` | `modern_error_code` | set | `reprobe` |
| re-probe → deadline | `era_probe` | `legacy` | `assumed` | `no_answer` | set | `reprobe` |
| backend restarts | `era_invalidated` (`reason=restart`) | `legacy` | `assumed` | `never_probed` | cleared | cleared |
| stale outcome discarded | `era_probe_discarded` | unchanged | unchanged | unchanged | unchanged | unchanged |

Two rows carry the whole design: a `no_answer` re-probe moves `era_source` back to `assumed` while
leaving `era_probed_at` set, and a discarded outcome changes nothing at all. Both are directly
testable.

**Why the `no_answer` rows cannot misreport.** `classify` answers `Legacy` for silence, but the cache
stores nothing (`src/protocol/era.rs:163-171`) — treat it as legacy now, do not remember it, or a
briefly unreachable peer is pinned legacy for the process lifetime. So after a silent probe the
request path *does* act legacy, which is what `era` reports. And a re-probe cannot mask a better
prior answer: the contradiction path fires only when the cached era is already `Legacy`
(`src/backend/era.rs:92`), and it invalidates *before* probing, so there is no `modern` value for a
silent re-probe to overwrite.

## Surface-count drift

This adds fields, not tools, so the Meta-MCP tool count in `README.md` and
`benchmarks/public_claims.json` is unchanged. Stated because that drift check has fired before, not
because it fires here.

## Stdio parity — OBS.3 does not inherit the OBS.1/OBS.2 gap

`NFR.OBS.1` and `NFR.OBS.2` are PARTIAL for one reason: they observe an HTTP request path and are
silent on stdio (`docs/requirements/RELEASE-4.0.0-criteria-status.md:324-325`, summarised at `:347`).
Era probing is not at that seam — it runs on both arms of backend start
(`src/backend/lifecycle.rs:336` stdio, `:352` HTTP), and `BackendStatus` is transport-agnostic. So
OBS.3 is not scoped to a transport, and it must not be verified only through an HTTP fixture.

## Sequencing — nothing gates this

An earlier revision of this document claimed OBS.3's implementation was gated on `DISCOVER.4-5`
wiring. **That was wrong**, and it is worth recording why: the claim came from
`criteria-status.md:326`, which still says both are unwired. They landed in `bb3727a2`. The tree, not
the status table, is the source.

So the whole of OBS.3 is buildable and testable today:

- the emission is a change to code that exists and runs;
- the tests extend `tests/mik_7217_era_probe_acs.rs`, which already drives a real backend start
  against a fixture peer (`backend.ensure_started()` at `:153`, `:173`, `:213`, `:316`, `:341`) and
  already produces every route in the `EraEvidence` table above;
- a test asserting an `era_probe` record fails today on a **missing assertion**, not a missing
  symbol — the probe runs, it is simply silent. §P2's free failure is available.

One thing remains unexercisable against a real peer: `SUPPORTED_VERSIONS` names only 2025 and 2024
revisions (`src/protocol/mod.rs:48`), and the outbound-header rows that would change that —
`MIK-7214.HEADER.9a`/`9b` (`docs/requirements/RELEASE-4.0.0-requirements.md:131-132`) — are unwired.
Fixtures produce every `EraEvidence` route; a production peer cannot yet produce `discover_modern`.
That bounds what the events will *show* in this release. It does not gate building them.

## Scheduled unknowns

| unknown | state | record |
|---|---|---|
| is there a fixture that starts a backend, so era events can be asserted at their real seam? | **resolved** | `tests/mik_7217_era_probe_acs.rs` — 360 lines, five tests calling `backend.ensure_started()` against a fixture peer, covering the modern-doc, `-32601`, contradiction-re-probe and never-answered routes. Changed the plan completely: OBS.3 writes no new harness, it adds a capturing subscriber to this one. An earlier search missed the file and concluded the opposite. |
| is the collector convention reusable outside the router tests? | **resolved** | `src/gateway/server/mod.rs:3058` filters on `mcp_gateway::observed`, and its self-test at `:3110-3132` proves the collector sees a record emitted in its own scope, independent of any request. Reusable; this is what makes Finding 2's single-target rule verifiable at all. |
| does the era design's `era_invalidated.reason=trigger` correspond to a real path? | **resolved** | yes — `src/backend/era.rs:92-101`: a contradicting error code invalidates and re-resolves. The `restart` reason is the pool entry being replaced. Both reasons are real; the event table needs no amendment there. |
| does `EraObservation` behind a sync lock disturb the era design's locking argument? | **deferred** — owner: this ticket's implementation; resolved by: re-reading `:490-515`, which reasons about `commit_if` holding the era lock for a pointer comparison and a write, and confirming a second non-async lock taken inside that critical section cannot invert with it; when: before the observation write lands; if it resolves badly: the observation is written *after* `commit_if` returns rather than inside it, which loses atomicity between cache and observation for one instant and is acceptable for a read-only surface. Nothing depending on it is implemented. |
| do the three modern error codes need separating on the operator read? | **deferred** — owner: this ticket; resolved by: observation once the events emit, or by asking the operator; when: after one release with the events live; if it resolves badly: `modern_error_code` widens into three variants, which is additive. |

## Answered by the operator, 2026-09-03

The one question this design could not settle for itself — it turns on how the fleet is
actually operated, not on engineering.

> **Is an operator expected to answer "which era is backend X on right now" from a live read, or
> from the logs?** — asked of the operator, 2026-09-03 — **a live read** — the `BackendStatus` /
> `gateway_list_servers` fields specified above are load-bearing and stay in scope, alongside the
> four events.

What the answer changed: nothing was removed. The logs-only branch would have dropped the
`EraObservation` type and the field section — most of the implementation cost — and left Findings
0, 1 and 2 standing, since the events, the evidence field and the unnamed target are missing
whichever surface answers the question. With a live read the fields are the primary answer and the
events are the audit trail behind them.

Recorded reason for the choice, so it is not re-litigated: no log-retention policy is specified
anywhere in this release, so a log-only answer is only as good as whatever retention happens to be
configured; and two of the criterion's three clauses are current-state questions, which a log
search answers only by inference from the last matching line.
