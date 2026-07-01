# ADR-006: Reuse-first gate on all remaining roadmap tickets

**Date**: 2026-07-01
**Status**: Accepted
**Deciders**: Mikko Parkkola
**References**: MIK-6550 roadmap, ADR-004, ADR-005

---

## Context

The public roadmap (`docs/roadmap/mik-6550-trust-fabric-roadmap.md`) was written
as a feature wishlist. Two of its child tickets, taken at face value, pushed
toward heavy net-new architecture that the codebase did not need:

- MIK-6685 said "Postgres" — but the gateway has no database and already has a
  tamper-evident audit log (`TransparencyLogger`). → ADR-005.
- MIK-6672 said "operator + HA" — but the enterprise need is deploy/upgrade/
  rollback, which Helm delivers, and MIK-6679 already proved rollback on a real
  cluster. → ADR-004.

In both cases the wishlist framing hid existing primitives and led toward
weeks of Spark-bound builds. A code-first "what do we already have / what is the
actual need" pass converted them into days of Mac-buildable reuse.

Two more remaining tickets show the same pattern:
- MIK-6688 (identity feed) is ~80% delivered by MIK-6648: `VerifiedIdentity`
  already carries `groups` and the policy engine already matches on group. It is
  a role-mapping wiring job, not new identity infrastructure.
- MIK-6689 (SIEM export) is a stream of the transparency-log NDJSON, not a new
  export subsystem.

## Decision

**Every remaining roadmap ticket passes a reuse-first gate before
implementation starts. Record the answers in the ticket.**

For each ticket, before writing code, answer:

1. **Does this need to exist at all?** (YAGNI — is there a real user/demand
   signal, or is it speculative maturity theater?)
2. **What existing gateway primitive covers part or all of it?** (transparency
   log, OIDC + policy engine, TrustCard, identity grants, ranking, response
   inspection, config-export — search the codebase, do not assume net-new.)
3. **What portfolio primitive covers it?** (SurrealDB before a new DB; existing
   crates before new dependencies.)
4. **Only then:** the minimum new code, and name any new third-party dependency
   plus its build-cost tier (Mac-buildable vs Spark-bound heavy compile).

A ticket that fails gate 1 (no demand) moves to **Blocked** with a written
demand-gate condition rather than being built on spec.

### Blocked-ticket hygiene (adversarial-review mitigation, GPT-5.5 2026-07-01)

The reuse gate must not become a veto machine, and Blocked must not become a
graveyard. Therefore every Blocked-by-this-gate ticket MUST carry:

- a **named owner**,
- an explicit **unblock condition** (the demand signal that reopens it), and
- a **review cadence** — Blocked-for-demand tickets are revisited on the
  quarterly gate-pruning review, so a capability whose demand only appears after
  it exists is not permanently vetoed.

The gate blocks *speculative* builds, not *necessary platform bets*; when a bet's
value is genuinely pre-demand and strategic, that is recorded as the
justification and the ticket proceeds rather than being blocked.

## Consequences

- Positive: the roadmap's scope is continuously matched to the product and the
  existing codebase; heavy speculative builds are caught before they start.
- Positive: makes the build-vs-integrate reasoning auditable per ticket.
- Negative: a small upfront analysis cost per ticket. Acceptable — it has
  already paid for itself several times over on this roadmap.
- This gate is the generalization of the specific calls in ADR-004 and ADR-005.
