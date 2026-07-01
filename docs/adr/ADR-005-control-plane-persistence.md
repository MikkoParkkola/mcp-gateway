# ADR-005: Control-plane persistence — reuse the transparency log; file-core, no Postgres

**Date**: 2026-07-01
**Status**: Accepted
**Deciders**: Mikko Parkkola
**References**: MIK-6558, MIK-6673 (ControlPlaneUI enterprise), MIK-6685, MIK-6689, issue #133 (transparency log)

---

## Context

The ControlPlaneUI enterprise track (MIK-6673) was scoped with a Postgres
durable store (MIK-6685) backing grants, policies, and audit events, plus a
SIEM/OTel export (MIK-6689). The read-only control-plane view ships today with
its **grants** view wired (MIK-6558) but its **audit-evidence** view empty
because nothing persists governance events.

Two facts reshape this:

1. **The gateway has no database today.** All durable state is local JSON/YAML
   (identity grants, config). Introducing Postgres would bolt a mandatory
   *external service* onto a single-binary, minimal-ops, `#![deny(unsafe_code)]`
   gateway — a heavier product — and would add a *second* database technology to
   the portfolio (hebb already uses SurrealDB).
2. **A tamper-evident audit log already exists.** `TransparencyLogger`
   (`src/security/transparency_log.rs`) is an append-only, hash-chained
   (`prev_hash` → genesis), independently verifiable (`verify_log`) NDJSON log.
   `ControlPlaneAuditEvent` (actor / action / target / reason) maps onto it.

## Decision

**Do not make a database mandatory. Persist behind a backend-agnostic
`ControlPlaneStore` trait; reuse the transparency-log engine for the audit
trail; keep config file-based for free/core; a server-backed durable store is a
demand-gated enterprise choice made per deployment.**

- **Audit events (MIK-6685 audit half, MIK-6689):** reuse the tamper-evident
  append-only hash-chain engine — a governance-scoped log instance alongside the
  invocation log. The audit-evidence view reads from it; SIEM/OTel export
  streams that NDJSON to a sink. No new store for the audit path. (Audit is
  append-only and hash-chained — a genuinely different job from mutable config,
  and the log is the right fit for it.)
- **Grants / policies (small mutable config):** stay file-based (matching the
  existing identity-grants file pattern), behind a `ControlPlaneStore` trait that
  is the seam for later backends and for the mutation routes (MIK-6686/6687).
- **Durable server-backed store:** demand-gated, and the backend is **chosen at
  demand time per deployment, not hardcoded here.** Options, in order of default
  preference: SurrealDB embedded (portfolio-consistent, no external service);
  **Postgres is acceptable when the customer already operates it** and wants
  boring shared durability / backup-restore / retention / SIEM-friendly
  indexing. The trait keeps this swappable. What this ADR rejects is a
  *mandatory* database in the default build — not Postgres as an option.
  (Adversarial-review correction, GPT-5.5 2026-07-01: "never Postgres" was
  ideology; "no mandatory DB, customer-fit backend" is the defensible line.)

### Demand-gate (when to add a server-backed durable store)

- concurrent multi-writer control-plane mutations exceed what atomic file writes
  safely handle, or
- an enterprise deployment requires a shared store across gateway replicas, or
- query / retention / backup-restore requirements exceed the file + log model.

When triggered, evaluate the mutable-config backend independently from the audit
log — they need not share a technology.

## Consequences

- Positive: kills the external-Postgres dependency and keeps the portfolio on
  one database technology; the audit-evidence view becomes real by reusing an
  already-verified engine rather than building persistence from scratch.
- Positive: MIK-6685 shrinks to a Mac-buildable trait + file/in-memory impl +
  audit-view wiring — no heavy dependency.
- Negative: file-based config does not support multi-replica shared state until
  the demand-gated backend lands. Acceptable for single-node/core; the trait
  makes the upgrade non-breaking.
- Reversible: the trait boundary means the backend can change without touching
  callers.
