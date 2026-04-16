# OWASP Agentic AI Top 10 Compliance Matrix

**Date**: 2026-04-16
**Standard**: OWASP Agentic Security Initiative (ASI) Top 10 — Sprint 1 first public draft
**Source**: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/initiatives/agent_security_initiative/agentic-top-10
**Scope**: mcp-gateway (`/Users/mikko/github/mcp-gateway`) + Botnaut (`/Users/mikko/github/botnaut-proto`)

---

## Compliance Matrix

| # | OWASP ASI Risk | Status | mcp-gateway Control | Botnaut Control | Gap |
|---|---------------|--------|---------------------|-----------------|-----|
| ASI01 | **Agent Behaviour Hijack** — Adversary overrides agent goals via injected instructions (prompt injection, indirect instruction embedding, tool description poisoning) | COVERED | `src/validator/rules/tool_poisoning.rs`: high-severity pattern detection for `instruction-embed`, `exfiltration`, `filesystem-path` in all tool description fields; unicode-control and whitespace-padding medium patterns; `src/security/firewall/input_scanner.rs`: shell-injection RegexSet on every argument; `src/security/firewall/anomaly.rs`: transition-probability anomaly scoring flags unusual call sequences | `src/botnaut/security/constitution_enforcer.py`: Ed25519-signed `CONSTITUTION.md` verified at startup; `src/botnaut/security/constitutional_firewall.py` + `constitution_guard.py`: runtime rule enforcement; `src/botnaut/security/prompt_injection/` (PROMPT_INJECTION_DEFENSE.md documented) | No runtime prompt-injection detection on LLM *outputs* in mcp-gateway (response scanning is present but pattern-limited) |
| ASI02 | **Tool Misuse and Exploitation** — Attacker chains authorized tools in unintended sequences, or exploits dynamic tool invocation to cause privilege escalation or destructive side-effects | COVERED | `src/security/policy.rs`: `DEFAULT_DENIED_PATTERNS` (write_file, delete_file, shell_exec, eval, drop_table, kill_process, etc.) with configurable allow/deny lists; `src/session_sandbox.rs`: `denied_tools` denylist + `allowed_backends` allowlist per session profile; `src/security/scope_collision.rs`: scope conflict detection; `src/security/firewall/anomaly.rs`: tool-sequence anomaly detection | `src/botnaut/security/capability.py`: unforgeable capability tokens with BFS revocation (#968); `src/botnaut/governance/delegation/chain.py`: `ResponsibilityChain` traces actions back to human grantor (max 3 hops); `src/botnaut/governance/autonomy_limits.py`: agent autonomy constraints | No automated graph-level tool-chaining analysis in mcp-gateway; anomaly detector is statistical, not structural |
| ASI03 | **Identity and Privilege Abuse** — Agent impersonates another agent or user, exploits implicit trust between agents, or escalates privileges through delegation chains | PARTIAL | `src/mtls/cert_manager.rs`: mutual TLS with `rustls` + client certificate verification; `src/oauth/`: OAuth 2.0 + PKCE (RFC 7636) for backend auth; `src/gateway/auth.rs`: bearer token enforcement; no per-agent identity attestation at tool dispatch layer | `src/botnaut/security/constitution_enforcer.py`: Ed25519 owner key embedded — only owner can rotate constitution; `src/botnaut/governance/delegation/`: `DelegationGrant` model with `parent_grant_id` lineage; `src/botnaut/security/compliance/audit_trails.py`: `CAPABILITY_TOKEN_ISSUED/REVOKED/VALIDATED` events | mcp-gateway has no agent-to-agent identity verification; downstream agents calling the gateway are trusted by session token only; no SPIFFE/SVID or agent attestation |
| ASI04 | **Agentic Supply Chain Vulnerabilities** — Malicious or compromised tool servers, capability files, or MCP backends silently alter tool behaviour after initial approval ("rug pull") | COVERED | `src/capability/hash.rs`: SHA-256 capability file pinning — hash computed over raw file bytes excluding the pin line itself; `mcp-gateway cap pin` CLI rewrites pins; `src/capability/watcher.rs`: file-watch hot-reload rejects hash mismatches; `src/capability/backend.rs` (detect_rug_pulls implied via loader validation); `src/validator/rules/tool_poisoning.rs`: oversized-description detection blocks post-approval description bloat | `docs/architecture/FULL_STACK_SOVEREIGNTY.md` (ADR-001): full-stack ownership doctrine prohibits weaponizable external deps; `src/botnaut/security/ml_dsa_signatures.py`: ML-DSA (post-quantum) signing for artifact integrity | No SBOM or third-party MCP server signing verification; hash pinning covers capability YAMLs but not live remote MCP servers |
| ASI05 | **Unexpected Code Execution / RCE** — Agent-triggered tool invocations result in arbitrary code execution through shell injection, path traversal, eval patterns, or unsafe deserialization | COVERED | `src/security/firewall/input_scanner.rs`: `SHELL_PATTERNS` RegexSet (6 patterns: command substitution, backtick exec, pipe-to-shell, chained destructive cmds, system-path redirect, semicolon chains); `PATH_TRAVERSAL_PATTERNS` (6 patterns inc. URL-encoded variants); `src/security/policy.rs`: `run_command`, `execute_command`, `shell_exec`, `eval`, `run_script` in `DEFAULT_DENIED_PATTERNS`; `src/security/ssrf.rs`: all RFC 5735/6890 private/loopback IPv4+IPv6 ranges blocked | `src/botnaut/security/coding_security_ctx.py`; `docs/security/COMMAND_INJECTION_FIX_REPORT.md`; `docs/security/SUBPROCESS_TIMEOUT.md`: subprocess timeout controls | SQL injection detection is medium-severity warn-only (not block) in mcp-gateway; no sandboxed execution environment for tool results |
| ASI06 | **Memory and Context Poisoning** — Attacker injects malicious content into agent short- or long-term memory (vector stores, external knowledge bases, session context), which then influences future agent decisions | PARTIAL | `src/security/firewall/input_scanner.rs`: scans tool arguments including memory-write arguments; `src/security/firewall/redactor.rs`: PII/sensitive data redaction before logging; `src/context_compression.rs`: context management; no dedicated memory-store integrity layer | `src/botnaut/security/adversarial/`: adversarial input detection; `src/botnaut/security/poison_resilience/` (POISON_RESILIENCE_PLAN.md); `src/botnaut/security/constitution_guard.py`: runtime guard against goal drift; Botnaut uses DeltaNet TTT state with CRDT merge semantics — state is append-only and versioned | mcp-gateway has no vector-store or long-term memory protection (it is stateless by design); Botnaut's memory poisoning defence is planned (POISON_RESILIENCE_PLAN) but not fully shipped |
| ASI07 | **Insecure Inter-Agent Communication** — Agent-to-agent messages lack authentication, integrity protection, or confidentiality, enabling MITM, message injection, or replay attacks between agents | PARTIAL | `src/mtls/`: mutual TLS for transport-layer auth between gateway and backends; `src/transport/`: transport abstraction; `src/tracing_context/`: per-request trace propagation; no dedicated agent-message signing or replay-nonce scheme | `src/botnaut/swarm/quantum_safe_consensus.py`: ML-KEM post-quantum consensus with Ed25519 receipts; `src/botnaut/swarm/federation/invitation.py`: federated agent invitation with Ed25519 signatures; `src/botnaut/security/pq_audit.py`: PQC audit; `docs/security/HYBRID_PQ_RATCHET_DESIGN.md` | mcp-gateway assumes TLS is sufficient — no application-layer message signing between agents; replay protection (nonces) not implemented |
| ASI08 | **Cascading Failures** — Failures in one agent propagate to dependent agents or tools, causing system-wide DoS or inconsistent state due to absent circuit breakers, retry storms, or unbounded recursion | COVERED | `src/failsafe/circuit_breaker.rs`: Closed/Open/HalfOpen state machine with configurable failure threshold; `src/failsafe/rate_limiter.rs`: token-bucket rate limiter (governor crate, per-RPS + burst config); `src/failsafe/retry.rs`: retry with backoff; `src/session_sandbox.rs`: `max_calls` (call count cap) + `max_duration` session timeout + `max_payload_bytes` payload limit; `src/cost_accounting/enforcer.rs`: daily micro-USD atomic budget with day-boundary reset | `src/botnaut/governance/constitutional_kill_switch.py`: kill switch for runaway agents; `docs/resilience/RESILIENCE_GUIDE.md`; `src/botnaut/agent/dag_orchestrator.py`: DAG-based orchestration (bounded execution graphs) | mcp-gateway rate limiter is per-gateway-instance (not per-client); no per-client circuit breaker |
| ASI09 | **Human-Agent Trust Exploitation** — Agent manipulates or overwhelms the human-in-the-loop (HITL) mechanism, deceives operators into approving malicious actions, or bypasses human oversight via automation | PARTIAL | `src/kill_switch/`: kill-switch module for emergency agent halt; `src/cost_accounting/enforcer.rs`: `AlertAction` escalations on budget breach (human notification path); `src/gateway/ui/`: operator UI with approval flows | `src/botnaut/security/approval.py` + `auto_approver.py`: explicit human approval gate with `auto_approval` policy; `src/botnaut/governance/consent_tracker.py`: consent tracking; `src/botnaut/security/anti_phishing/`: anti-phishing for agent-to-human communication; `docs/ethics/NO_HIDDEN_COSTS.md`: transparency commitment; `GOVERNANCE.md` §1: PBC dual mandate | No structured HITL confirmation protocol in mcp-gateway for high-risk tool invocations; `kill_switch` halts everything but offers no partial approval flow |
| ASI10 | **Rogue Agents** — An agent defects from its intended objective, acts deceptively, or coordinates with other compromised agents to pursue misaligned goals outside operator control | PARTIAL | `src/security/firewall/anomaly.rs`: transition-probability anomaly scoring detects behavioural drift; `src/kill_switch/`: emergency halt; `src/cost_accounting/enforcer.rs`: spend cap prevents runaway cost; `src/session_sandbox.rs`: `max_calls` + `max_duration` bound session lifetime | `src/botnaut/security/constitution_enforcer.py`: Ed25519-signed constitution with startup enforcement; `src/botnaut/alignment_safety/constitutional.py`: constitutional AI alignment layer; `src/botnaut/alignment_safety/interpretability.py`: interpretability probes; `src/botnaut/governance/constitutional_verifier/`: runtime constitution verification; `src/botnaut/security/agent_anomaly_detector.py`: agent-specific anomaly detection | mcp-gateway's anomaly detector is statistical and retrospective, not predictive; no multi-agent collusion detection in either system |

---

## Summary

| Status | Count | Risks |
|--------|-------|-------|
| **COVERED** | 5/10 | ASI01 (Behaviour Hijack), ASI02 (Tool Misuse), ASI04 (Supply Chain / Rug Pull), ASI05 (Code Execution / RCE), ASI08 (Cascading Failures) |
| **PARTIAL** | 5/10 | ASI03 (Identity Abuse), ASI06 (Memory Poisoning), ASI07 (Inter-Agent Comms), ASI09 (Human Trust Exploitation), ASI10 (Rogue Agents) |
| **GAP** | 0/10 | — |

**Overall**: 5/10 covered, 5/10 partial, 0/10 outright gaps.

---

## Priority Remediation Recommendations

### P0 — Close Partial Gaps

1. **ASI03 — Agent Identity**: Add per-agent SPIFFE/SVID attestation or signed agent-identity tokens at the mcp-gateway dispatch layer. Currently any session token grants trust; agents cannot prove they are who they claim.

2. **ASI07 — Inter-Agent Message Signing**: Add application-layer Ed25519 message signatures and nonce-based replay protection to the mcp-gateway transport layer. mTLS protects the channel but not the message envelope — a compromised gateway node can replay or inject.

3. **ASI06 — Memory Poisoning**: mcp-gateway is stateless so the risk is deferred to callers. Botnaut should ship the POISON_RESILIENCE_PLAN controls (currently documented, not enforced) and add hash verification on DeltaNet state snapshots loaded from disk.

### P1 — Strengthen Partial Controls

4. **ASI09 — HITL Protocol**: Implement a structured high-risk tool confirmation protocol in mcp-gateway: tools matching configurable risk patterns should require an explicit operator acknowledgment token before dispatch, not just a kill-switch.

5. **ASI10 — Rogue Agent Detection**: Promote the anomaly detector from retrospective logging to prospective blocking for sessions that exceed a configurable anomaly score threshold. Add multi-agent coordination detection (shared session fingerprinting).

### P2 — Extend Coverage

6. **ASI01 — Output Scanning**: Extend `response_scanner.rs` / `response_inspect.rs` to detect prompt-injection payloads in LLM tool *responses*, not just in incoming arguments.

7. **ASI04 — Remote MCP Server Signing**: SHA-256 pinning covers local capability YAMLs but not live remote MCP backends. Add a server-identity pin (public key or TLS cert fingerprint) to capability definitions.

---

## Control Reference Map

| mcp-gateway File | Controls |
|-----------------|----------|
| `src/validator/rules/tool_poisoning.rs` | ASI01, ASI02 |
| `src/security/firewall/input_scanner.rs` | ASI01, ASI05, ASI06 |
| `src/security/firewall/anomaly.rs` | ASI01, ASI02, ASI10 |
| `src/security/firewall/audit.rs` | ASI03, ASI09 |
| `src/security/policy.rs` | ASI02, ASI05 |
| `src/security/ssrf.rs` | ASI05 |
| `src/capability/hash.rs` | ASI04 |
| `src/capability/watcher.rs` | ASI04 |
| `src/session_sandbox.rs` | ASI02, ASI08, ASI10 |
| `src/cost_accounting/enforcer.rs` | ASI08, ASI09, ASI10 |
| `src/failsafe/circuit_breaker.rs` | ASI08 |
| `src/failsafe/rate_limiter.rs` | ASI08 |
| `src/mtls/cert_manager.rs` | ASI03, ASI07 |
| `src/oauth/` | ASI03 |
| `src/kill_switch/` | ASI08, ASI09, ASI10 |

| Botnaut File / Doc | Controls |
|-------------------|----------|
| `src/botnaut/security/constitution_enforcer.py` | ASI01, ASI03, ASI10 |
| `src/botnaut/security/capability.py` | ASI02, ASI03 |
| `src/botnaut/governance/delegation/chain.py` | ASI02, ASI03 |
| `src/botnaut/security/compliance/audit_trails.py` | ASI03, ASI09 |
| `src/botnaut/evidence/receipts.py` | ASI03, ASI09 |
| `src/botnaut/swarm/quantum_safe_consensus.py` | ASI07 |
| `src/botnaut/swarm/federation/invitation.py` | ASI07 |
| `src/botnaut/governance/constitutional_kill_switch.py` | ASI08, ASI10 |
| `src/botnaut/security/approval.py` | ASI09 |
| `src/botnaut/governance/consent_tracker.py` | ASI09 |
| `src/botnaut/alignment_safety/constitutional.py` | ASI10 |
| `src/botnaut/security/agent_anomaly_detector.py` | ASI10 |
| `docs/governance/STEALTH_MODE.md` | ASI09 |
| `docs/ethics/NO_HIDDEN_COSTS.md` | ASI09 |
| `GOVERNANCE.md` | ASI09, ASI10 |

---

*Standard reference: OWASP Agentic Security Initiative (ASI) Top 10, Sprint 1 first public draft (2025/2026). See https://genai.owasp.org/initiatives/agentic-security-initiative/ for current status. The ASI Top 10 is distinct from the OWASP LLM Top 10 for 2025 (LLM01–LLM10).*
