# MIK-6273 Mosaic Leakage Egress Guard — Governance Note (AC.6)

## Threat Model
- Adversary model: passive observer of the cumulative outbound query log at the gateway (the single egress chokepoint for web-search/fetch/tool calls).
- Adversary sees only the cumulative query log (keys: session, agent, backend/tool, timestamp, query text, decision). Does not see private document contents, tool responses, or full agent memory.
- Mosaic leakage: individual queries appear benign (public research style) but when reassembled across turns/agents in the log, allow reconstruction of private facts (repo names + keys + internal ids + credentials fragments).
- MosaicLeaks benchmark (inspired by academic work) used here to drive guard design; it is a **controlled benchmark, not a measurement of leakage in deployed systems**.

## Scope and Limitations
- Applies **only** to outbound web-search/fetch-style calls (brave_*, exa_*, parallel, wikipedia, fetch, arxiv, nominatim, etc.) before dispatch.
- Does **not** scan private documents or inbound content.
- Default dev mode: warn + log (fail-open for usability). Fail-closed (block/redact) only for explicitly configured protected sessions.
- Classifier starts deterministic/fixture-based. Local model wiring gated behind config + AC.2 validation.
- Botnaut attestation is companion for signed receipt; gateway enforces independently. If botnaut unavailable, signed JSON fallback is emitted.
- False positives possible on legitimate research queries that use technical terms overlapping private identifiers. Thresholds tunable.
- Recall target >=0.85 on seeded mosaics, benign block FP <=0.05.

## Decision Types
- `allow`: proceed, log decision.
- `warn`: proceed + emit warning, log.
- `redact`: redact sensitive fragment from query before dispatch, log redacted form in history.
- `block`: fail the call before network, return protocol error, log.

Each decision record carries: direct_risk, mosaic_risk, threshold, history_hash, classifier_version, query_hash, session_id_hash, and botnaut_state_content_id or signed_json_fallback.

## Operator Playbook
1. Monitor `mosaic_egress_decision_total`, `mosaic_egress_block_total`, `mosaic_egress_warn_total` (distinct counters).
2. Review audit logs for decisions on protected sessions.
3. For high FP on a workload, add session to allowlist or raise threshold via config.
4. Enable block mode only after traffic study + eval on representative corpus (AC.1/AC.2).
5. After any config change to guard, re-run `cargo test -p mcp-gateway mosaic_*`.
6. Receipts: use botnaut /v1/cognition validation or standalone signed JSON verifier for governance audits.
7. Incident response: if block fires, inspect the history_hash chain, correlate with session/agent.

## Deployment Modes
- `warn_only` (default for non-protected): always log, never block.
- `protected`: for listed sessions/agents, use block/redact when thresholds crossed.
- Telemetry always emitted (B1-IDENT).

## References
- AC.1 traffic study: `MIK-6273-traffic-study.md`
- AC.2 eval: `cargo test -p mcp-gateway mosaic_leakage_classifier_eval`
- Implementation: `src/egress/mosaic_guard.rs`, `src/egress/mosaic_receipt.rs`, wired in meta_mcp invoke dispatch.

**controlled benchmark, not a measurement of leakage in deployed systems**

**adversary sees only the cumulative query log**
