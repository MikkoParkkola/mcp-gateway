<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MIK-6865.SCHEMA.1c — forwarded tool schemas are inspected before they reach the client

Status: design, for review. Companion test plan:
`2026-09-07-schema-1c-forwarded-schema-bounds-test-plan.md`.

## Problem

The criterion reads: *tool schemas MUST stay within the revision's `$ref` and
composition bounds.* `tests/schema_2020_12_validity.rs` already observes the two
FIRST-PARTY populations — the 19 emitted `gateway_*` schemas and the 110+
capability schemas — for 2020-12 validity, `$ref` resolution and composition.

The population is not closed. `MetaMcp::handle_tools_list_for_session`
(`src/gateway/meta_mcp/mod.rs:1330`) appends surfaced tools resolved by
`Backend::get_cached_tool`, the `spec-preview` promoted-tools loop appends more
(`:1350`), and the direct backend proxy normalises a backend's own reply
(`src/gateway/router/backend_handlers.rs:199`). All of those routes project
through `project_tool_descriptor_trust_card`, which serialises the tool verbatim
and adds a `trustCard` key. Nothing between a third party's schema and the client
looks at it: `a_backend_forwarded_schema_reaches_the_client_uninspected` shows an
`allOf` and a dangling `#/$defs/Absent` arriving intact.

So the repository constrains the schemas it WRITES and says nothing about the
schemas it FORWARDS — and forwarded schemas are the ones it did not author.

## Constraints (measured)

- `project_tool_descriptor_trust_card` is the single choke point for every
  emitting route. `gitnexus impact` (upstream): 4 direct callers, 32 impacted,
  risk HIGH, 3 execution flows.
- `jsonschema` is a **dev-dependency** (`Cargo.toml:176`, below
  `[dev-dependencies]` at `:170`). No JSON Schema meta-validator exists anywhere
  in `src/` (`rg` over `src/` for `2020-12` returns nothing).
- The wire shape is additive: the `trustCard` object already carries
  `evaluationStatus`, and its one existing assertion
  (`src/trust/descriptor.rs:135`) checks named keys, never absence of others.
- U9 in `2026-08-31-cluster-g-tool-schema-2020-12-validity-test-plan.md:410` is
  open. Its own text says it is *"blocking for a SCHEMA.1 closure comment, not
  for implementation"*, and the surviving design's U11 reads it as (c): 2020-12
  validity plus `$ref` resolution, of which the checkable half is P12a,
  unresolved local `$ref`.

## What this change is FOR

Every tool descriptor the gateway emits is INSPECTED for unresolved local `$ref`
before it reaches the client, and the verdict travels with the descriptor.

## What is OUT

- **Changing what the gateway publishes.** No dropping, no rewriting, no
  sanitising of a third party's schema. The descriptor is emitted exactly as
  today; only a verdict is added beside it.
- **Composition as a bound.** `allOf`/`anyOf`/`oneOf`/`not`/`if` are legal
  2020-12. Under reading (c) they are not a bound, and inventing one here would
  assert a bound no design named. The existing composition rows stay
  observations of the current state.
- **2020-12 meta-validation of forwarded schemas.** See the named decision.
- Editing `docs/requirements/RELEASE-4.0.0-criteria-status.md`. Evidence is
  reported; the team lead regrades.

## Options considered

| option | rejected because |
|---|---|
| drop or reject an out-of-bounds forwarded tool | a behaviour change to the live router with real blast radius: a legitimate backend using `$defs` that the resolver mishandles vanishes from `tools/list` with no error a user can see. That is a decision about what the gateway publishes, far larger than the criterion — and not its ask. The criterion is a property of what is published, established by an inspection with an observable verdict. |
| inspect at each call site | an enumeration that must be kept in sync as routes are added; the next route added is uninspected and nothing says so. The choke point closes the population BY CONSTRUCTION. |
| assert the bound only in tests, leave `src` untouched | that is today's state, and it is why the row is PARTIAL: a test can only observe the populations it can enumerate, and the forwarded population does not exist in the tree. |
| promote `jsonschema` to a runtime dependency and meta-validate on the emit path | not rejected on merit — deferred to an owner, see below. |

## Named decision this design does NOT make (§P3)

**2020-12 meta-validation of forwarded schemas needs a runtime dependency.**
Reading (c) has two halves. The `$ref` half (P12a) is checkable with a walker and
no new dependency. The meta-validity half needs a validator in `src/`, which today
means promoting `jsonschema` from dev to runtime — a supply-chain change (DoD §8,
D30) on a release-readiness branch, plus its compile-time cost on every build.

- owner: release team lead
- what would resolve it: a decision to promote the dependency, or a statement
  that first-party meta-validation in tests is the whole of the meta-validity half
- when: before the SCHEMA.1c row is regraded MET
- if it resolves badly (no promotion): the emit path inspects `$ref` resolution
  only, and the meta-validity half of reading (c) stays asserted for first-party
  populations in tests and unasserted for forwarded ones — the state this change
  ships.

## Unknowns

**U9 (askable, carried; blocking for the closure comment, not for
implementation).** Does *"the revision's `$ref` and composition bounds"* name
(a) a numeric limit the 2026-11-25 revision states, (b) the gateway's own limit
on what it will publish, or (c) nothing beyond 2020-12 validity plus resolution?
Asked of: the release owner, as confirm-or-reject of reading (c).
Answer: **not yet recorded.** This change implements against (c) because the
sibling design already reads it that way and U9's own text unblocks
implementation; the row cannot be regraded MET until the answer is recorded.
If it resolves as (a) or (b), the walker stays and a bound is added beside it.

## Mechanism

One inspection inside `project_tool_descriptor_trust_card`, over the tool's
`inputSchema`, recorded as an additive field on the descriptor's `trustCard`.
A schema whose every local `$ref` resolves in its own document is within bounds;
one with an unresolved pointer is out of bounds and the pointers are named. The
`$ref` walker already exists in `tests/schema_2020_12_validity.rs` as
`dangling_refs`; it moves into `src` and the test consumes it, so one walker
decides for both the observing tests and the emit path.
