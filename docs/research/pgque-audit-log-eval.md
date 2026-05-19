# pgque as Audit-Log Substrate for mcp-gateway Enterprise Edition

**Ticket:** MIK-3032 | **Date:** 2026-05-19 | **Author:** Mikko (with Claude) | **Status:** evaluation memo
**Parent:** MIK-3024 (Secure Agent Runtime, EE) | **Companion:** EE-AUDIT-LOG-SUBSTRATE.md (canonical, pending)
**Source:** NikolayS/pgque, Apache-2.0, 1156 stars (https://github.com/NikolayS/pgque)

## 1. pgque architecture (V: upstream README + ticket source)

Pure PL/pgSQL queue. Architecture in one breath:

- **Storage shape:** two (or more) heap tables rotated; producers `INSERT` into the active table, consumers read a snapshot, ACK by advancing a watermark.
- **Bloat control:** rotation + `TRUNCATE` of the inactive table. `TRUNCATE` reclaims pages instantly (no autovacuum dependency, no MVCC tombstones to walk). This is the load-bearing trick — it is what makes "zero bloat under sustained load" honest rather than marketing.
- **Install surface:** SQL only. No C extension, no `shared_preload_libraries`, no background worker, no daemon. Runs on RDS / Aurora / Cloud SQL / AlloyDB / Supabase / Neon / vanilla self-hosted PG ≥ 13.
- **Ordering:** monotonic per-producer; cross-producer ordering is timestamp-based, not strict.
- **Latency:** ~1–2 s producer-to-consumer (snapshot tick interval). Sub-second possible by tightening the tick, at the cost of more empty scans.
- **Throughput:** README cites tens of thousands of msgs/s on commodity Postgres; bounded primarily by `INSERT` cost, not by the rotation overhead.

## 2. mcp-gateway EE audit requirement (V: src/gateway/oauth/audit.rs, EU AI Act Art. 12)

EE needs a **durable, queryable, ordered, append-only log** of tool invocations, auth decisions, and capability mutations, retained for the lifetime required by EU AI Act Article 12 + NIS2 + customer contract (typically 12–24 months hot, longer cold).

Current state (`src/gateway/oauth/audit.rs`): `ToolInvocationAudit` struct emitted via `tracing::info!` — **in-process only**. No durable store, no query API, no retention policy. EE-grade gap is real.

Functional requirements:

| Requirement | Weight | Notes |
|---|---|---|
| ACID enqueue with the invocation TX | hard | audit must commit iff the invocation commits |
| Append-only, tamper-evident | hard | NIS2 + AI Act |
| Queryable (auditor reads logs in month 6) | hard | not just a stream |
| Zero unbounded bloat | hard | volume grows monotonically |
| Managed-PG compatible | hard | EE customers run RDS/Aurora |
| Minimal supply chain | hard | NIS2 SBOM cleanliness |
| Real-time SLA on read-back | soft | auditors are async |
| Cross-row strict ordering | soft | per-trace ordering enough |

## 3. Substrate fit

### Strengths (the case for INTEGRATE)

1. **ACID enqueue is native** — `INSERT INTO audit_log ...` participates in the same transaction as the tool invocation row. No two-phase, no outbox-shim, no eventual-consistency edge case.
2. **Bloat story matches the workload exactly.** Audit volume is monotonic — that is the *worst* shape for `DELETE`-based retention (tombstone explosion, autovacuum chasing its tail). TRUNCATE-rotation sidesteps the entire failure mode.
3. **Managed-PG compatible.** Pure SQL install. Onboarding an EE customer means `psql -f pgque.sql`, not "negotiate a Redis cluster with their SRE."
4. **Supply chain is one .sql file.** NIS2 SBOM auditor opens it and reads it. Compare to dragging in Kafka (ZK/KRaft + brokers + client lib + operator) or Redis Streams (server + client + persistence config + cluster mode).
5. **The 1–2 s latency is a non-issue.** Audit consumers are auditors and incident responders reading logs hours-to-months later. Anything below 60 s is gravy.

### Risks (the case for caution)

1. **Queryability is the actual product, not enqueue speed.** pgque is a *queue*; auditors need a *log*. The TRUNCATE-rotation trick is incompatible with "keep all events queryable for 12 months" — once a table rotates out and truncates, the events are gone unless we copied them somewhere first.
2. **Schema fit.** pgque's payload is opaque (`bytea`/`jsonb`). Our audit row has structured fields (actor, capability, decision, latency, trace_id) that we want to index. We would not store directly in pgque's message column; we would either (a) project to a side table on the consumer or (b) skip pgque's rotation entirely.
3. **Ordering is timestamp-based across producers.** Multi-instance EE deployments + clock skew → audit-event reordering. Solvable (Lamport/HLC stamp at gateway), but the substrate does not give it for free.
4. **Tamper-evidence is not provided.** pgque is a queue; it has no hash chain, no Merkle commitment, no signature. We would layer that on top (see `src/security/transparency_log.rs` — we already have the primitive).

## 4. Comparison (V: rough, full spike pending)

| Substrate | Bloat | Managed-PG | Supply chain | Query | Tamper-evidence | Verdict |
|---|---|---|---|---|---|---|
| pgque as-is | excellent (rotates away) | yes | minimal (.sql) | poor (rotates away) | none | wrong tool, right idea |
| pgque pattern → hypertable | good (chunk-drop) | yes | TimescaleDB ext (not on all managed PG) | good | none | strong candidate |
| Plain PG table + partitioning | good (DROP partition) | yes | zero (built-in) | good | none | **default candidate** |
| SKIP LOCKED queue | poor (bloat under sustained load) | yes | zero | medium | none | rejected |
| Kafka | n/a (compacted topic) | no | heavy | medium (kSQL) | none | rejected — supply chain |
| Redis Streams | n/a (cap'd) | partial | medium | poor (range only) | none | rejected — volatility |

## 5. Verdict — **WAIT (lean: REJECT the substrate, INTEGRATE the architectural idea)**

pgque solves a queue problem with a TRUNCATE-rotation trick. Our problem is a **queryable retained log**, not a queue — the very property that makes pgque excellent (rotating tables away to keep bloat zero) is the property we cannot tolerate (we need the rows queryable in month 6).

The *architectural lesson* from pgque transfers cleanly: **rotate, do not delete.** That maps to native PG declarative partitioning (`PARTITION BY RANGE (created_at)`) with monthly partitions and `DROP PARTITION` for retention. We get bloat-free retention without importing a queue abstraction we then have to subvert.

Recommended path:

1. **Use native PG range-partitioned table** as the EE audit substrate. One .sql migration, zero new dependencies, fully managed-PG compatible.
2. **Cite pgque** in the design memo as the source of the rotation-not-deletion pattern.
3. **Layer tamper-evidence** by reusing `src/security/transparency_log.rs` — append-only Merkle chain over partition contents.
4. **Spike still useful** for the 1M-event sustained-load test (AC #2): run it against the partitioned table, confirm zero bloat, archive numbers.
5. **Revisit pgque** if/when we need an *operational event bus* between gateway instances (different problem; pgque would fit).

Kill gate from the ticket triggered cleanly: schema constraints clash (pgque payload is opaque; our audit row is structured + indexed). Decision documented; alternative chosen.

## 6. Acceptance criteria status

- [x] Substrate fit analysis written (this doc)
- [x] Comparison vs. SKIP-LOCKED queue, hypertable, native partitioning, Kafka, Redis Streams (§4)
- [x] Design proposal direction (native PG partitioning + transparency_log; §5)
- [x] Decision: **WAIT on pgque; INTEGRATE the rotation-not-deletion pattern via native partitioning** (§5)
- [ ] Output memo at canonical path `docs/design/EE-AUDIT-LOG-SUBSTRATE.md` — this doc is the research input; canonical design memo lives in MIK-3024 follow-up
- [ ] Spike: 10K + 1M event measurement runs — deferred; harness lives in `mcp-gateway-enterprise/experiments/pgque-audit-2026-04` per ticket Rollback section

## 7. Cross-refs

- MIK-3024 (parent, EE positioning)
- MIK-3022 (sovereign-attested inbox — pgque was also evaluated there as substrate)
- MIK-3036 (sibling pgque eval)
- `src/gateway/oauth/audit.rs` (current in-process audit emitter; the thing this substrate must replace)
- `src/security/transparency_log.rs` (tamper-evidence primitive to layer on top)
- pgque upstream: https://github.com/NikolayS/pgque
- EU AI Act Article 12: logging + traceability requirement
