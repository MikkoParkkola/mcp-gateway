# OWASP Agentic AI Top 10 Compliance Matrix

**Date**: 2026-04-16
**Standard**: OWASP Agentic Security Initiative (ASI) Top 10 — Sprint 1 first public draft
**Source**: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/initiatives/agent_security_initiative/agentic-top-10
**Scope**: mcp-gateway (`/Users/mikko/github/mcp-gateway`) + Botnaut (`/Users/mikko/github/botnaut-proto`)

---

## Compliance Matrix

| # | OWASP ASI Risk | Status | mcp-gateway Control | Botnaut Control | Gap |
|---|---------------|--------|---------------------|-----------------|-----|
| ASI01 | **Agent Behaviour Hijack** — Adversary overrides agent goals via injected instructions (prompt injection, indirect instruction embedding, tool description poisoning) | COVERED | `src/validator/rules/tool_poisoning.rs`: high-severity pattern detection for `instruction-embed`, `exfiltration`, `filesystem-path` in all tool description fields; unicode-control and whitespace-padding medium patterns; `src/security/firewall/input_scanner.rs`: shell-injection RegexSet on every argument; `src/security/firewall/anomaly.rs`: transition-probability anomaly scoring flags unusual call sequences; `src/security/response_inspect.rs`: MIK-6562 response-inspection action mode — code injection, supply-chain, combined instruction-override+tool-directive detection with configurable block/observe mode | `src/botnaut/security/constitution_enforcer.py`: Ed25519-signed `CONSTITUTION.md` verified at startup; `src/botnaut/security/constitutional_firewall.py` + `constitution_guard.py`: runtime rule enforcement; `src/botnaut/security/prompt_injection/` (PROMPT_INJECTION_DEFENSE.md documented) | Output response inspection hardened in MIK-6562; gap closed |
| ASI02 | **Tool Misuse and Exploitation** — Attacker chains authorized tools in unintended sequences, or exploits dynamic tool invocation to cause privilege escalation or destructive side-effects | COVERED | `src/security/policy.rs`: `DEFAULT_DENIED_PATTERNS` (write_file, delete_file, shell_exec, eval, drop_table, kill_process, etc.) with configurable allow/deny lists; `src/session_sandbox.rs`: `denied_tools` denylist + `allowed_backends` allowlist per session profile; `src/security/scope_collision.rs`: scope conflict detection; `src/security/firewall/anomaly.rs`: tool-sequence anomaly detection | `src/botnaut/security/capability.py`: unforgeable capability tokens with BFS revocation (#968); `src/botnaut/governance/delegation/chain.py`: `ResponsibilityChain` traces actions back to human grantor (max 3 hops); `src/botnaut/governance/autonomy_limits.py`: agent autonomy constraints | No automated graph-level tool-chaining analysis in mcp-gateway; anomaly detector is statistical, not structural |
| ASI03 | **Identity and Privilege Abuse** — Agent impersonates another agent or user, exploits implicit trust between agents, or escalates privileges through delegation chains | COVERED | `src/mtls/cert_manager.rs`: mutual TLS with `rustls` client-certificate verification; `src/gateway/server/support.rs`: extracts the verified TLS peer certificate after handshake and injects `CertIdentity` into request extensions; `src/mtls/identity.rs`: extracts SPIFFE URI SANs from SVID-style X.509 certificates; `src/mtls/access_control/mod.rs`: fail-closed SPIFFE/SVID SAN policy matching at tool dispatch, including deny when policy rules exist but no verified certificate identity is present; `src/oauth/`: OAuth 2.0 + PKCE (RFC 7636) for backend auth; `src/gateway/auth.rs`: bearer token enforcement | `src/botnaut/security/constitution_enforcer.py`: Ed25519 owner key embedded — only owner can rotate constitution; `src/botnaut/governance/delegation/`: `DelegationGrant` model with `parent_grant_id` lineage; `src/botnaut/security/compliance/audit_trails.py`: `CAPABILITY_TOKEN_ISSUED/REVOKED/VALIDATED` events | Hardened profile requires `mtls.enabled` plus a trusted CA/SPIFFE issuer and explicit `match.san_uri` policies. Token-only deployments remain outside the ASI03 hardened profile rather than a coverage claim. |
| ASI04 | **Agentic Supply Chain Vulnerabilities** — Malicious or compromised tool servers, capability files, or MCP backends silently alter tool behaviour after initial approval ("rug pull") | PARTIAL | `src/capability/hash.rs`: SHA-256 capability file pinning — hash computed over raw file bytes excluding the pin line itself; `mcp-gateway cap pin` CLI rewrites pins; `src/capability/watcher.rs`: file-watch hot-reload rejects hash mismatches; `src/security/remote_provenance.rs`: opt-in Ed25519 verification for signed remote MCP backend provenance; `src/config/mod.rs`: fail-closed config validation when remote signing is required or configured; `src/validator/rules/tool_poisoning.rs`: oversized-description detection blocks post-approval description bloat | `docs/architecture/FULL_STACK_SOVEREIGNTY.md` (ADR-001): full-stack ownership doctrine prohibits weaponizable external deps; `src/botnaut/security/ml_dsa_signatures.py`: ML-DSA (post-quantum) signing for artifact integrity | Config-time remote provenance is implemented, but release workflow still publishes SHA-256 checksums without a generated SBOM artifact or Sigstore/cosign signature, and the gateway does not yet fetch a live MCP server attestation document. Tracked by MIK-3361 |
| ASI05 | **Unexpected Code Execution / RCE** — Agent-triggered tool invocations result in arbitrary code execution through shell injection, path traversal, eval patterns, or unsafe deserialization | PARTIAL | `src/security/firewall/input_scanner.rs`: `SHELL_PATTERNS` RegexSet (6 patterns: command substitution, backtick exec, pipe-to-shell, chained destructive cmds, system-path redirect, semicolon chains); `PATH_TRAVERSAL_PATTERNS` (6 patterns inc. URL-encoded variants); `src/security/policy.rs`: `run_command`, `execute_command`, `shell_exec`, `eval`, `run_script` in `DEFAULT_DENIED_PATTERNS`; `src/security/ssrf.rs`: all RFC 5735/6890 private/loopback IPv4+IPv6 ranges blocked | `src/botnaut/security/coding_security_ctx.py`; `docs/security/COMMAND_INJECTION_FIX_REPORT.md`; `docs/security/SUBPROCESS_TIMEOUT.md`: subprocess timeout controls | SQL injection detection is medium-severity warn-only (not block) in mcp-gateway; no sandboxed execution environment for tool results. Tracked by MIK-3364 |
| ASI06 | **Memory and Context Poisoning** — Attacker injects malicious content into agent short- or long-term memory (vector stores, external knowledge bases, session context), which then influences future agent decisions | PARTIAL | `src/security/firewall/input_scanner.rs`: scans tool arguments including memory-write arguments; `src/security/firewall/redactor.rs`: PII/sensitive data redaction before logging; `src/context_compression.rs`: context management; no dedicated memory-store integrity layer | `src/botnaut/security/adversarial/`: adversarial input detection; `src/botnaut/security/poison_resilience/` (POISON_RESILIENCE_PLAN.md); `src/botnaut/security/constitution_guard.py`: runtime guard against goal drift; Botnaut uses DeltaNet TTT state with CRDT merge semantics — state is append-only and versioned | mcp-gateway has no vector-store or long-term memory protection (it is stateless by design); Botnaut's memory poisoning defence is planned (POISON_RESILIENCE_PLAN) but not fully shipped |
| ASI07 | **Insecure Inter-Agent Communication** — Agent-to-agent messages lack authentication, integrity protection, or confidentiality, enabling MITM, message injection, or replay attacks between agents | PARTIAL | `src/security/message_signing.rs`: HMAC-SHA256 `gateway_invoke` response signing (ADR-001); `_signature` block with `alg`, `sig`, `nonce`, `ts`, `key_id` in every signed response; `NonceStore` (DashMap + TTL eviction) rejects replayed request nonces within configurable replay window (default 5 min); opt-in via `security.message_signing.enabled`; key rotation via `previous_secret`; `src/mtls/`: mutual TLS for transport-layer channel auth; `src/tracing_context/`: per-request trace propagation | `src/botnaut/swarm/quantum_safe_consensus.py`: ML-KEM post-quantum consensus with Ed25519 receipts; `src/botnaut/swarm/federation/invitation.py`: federated agent invitation with Ed25519 signatures; `src/botnaut/security/pq_audit.py`: PQC audit; `docs/security/HYBRID_PQ_RATCHET_DESIGN.md` | Application-layer signing covers gateway→client leg; multi-gateway signature chaining (JWS-style) is out of scope per ADR-001 and tracked by MIK-3362. Agent identity attestation remains ASI03 and MIK-3363 |
| ASI08 | **Cascading Failures** — Failures in one agent propagate to dependent agents or tools, causing system-wide DoS or inconsistent state due to absent circuit breakers, retry storms, or unbounded recursion | COVERED | `src/gateway/auth.rs`: authenticated API-key/bearer identity extraction plus per-client `governor` request throttling and opt-in per-client Closed/Open/HalfOpen dispatch circuit breakers (`auth.client_circuit_breaker`); `src/failsafe/circuit_breaker.rs`: shared state machine with configurable failure threshold, success threshold, and reset timeout; `src/failsafe/rate_limiter.rs`: backend token-bucket limiter; `src/failsafe/retry.rs`: retry with backoff; `src/session_sandbox.rs`: `max_calls` + `max_duration` + `max_payload_bytes`; `src/cost_accounting/enforcer.rs`: daily micro-USD budget with day-boundary reset | `src/botnaut/governance/constitutional_kill_switch.py`: kill switch for runaway agents; `docs/resilience/RESILIENCE_GUIDE.md`; `src/botnaut/agent/dag_orchestrator.py`: DAG-based orchestration (bounded execution graphs) | Per-client gateway-layer gap closed by MIK-3365 for a single gateway process. Distributed multi-gateway circuit state remains an architectural scaling question, not an ASI08 public-coverage blocker. Deploy-side nginx mitigation remains related hardening in MIK-3310 |
| ASI09 | **Human-Agent Trust Exploitation** — Agent manipulates or overwhelms the human-in-the-loop (HITL) mechanism, deceives operators into approving malicious actions, or bypasses human oversight via automation | COVERED | `src/gateway/destructive_confirmation.rs`: MCP elicitation-based confirmation gate for destructive meta-tools (`gateway_kill_server`); `src/kill_switch/`: kill-switch module for emergency agent halt; `src/cost_accounting/enforcer.rs`: `AlertAction` escalations on budget breach (human notification path); `src/gateway/ui/`: operator UI with approval flows | `src/botnaut/security/approval.py` + `auto_approver.py`: explicit human approval gate with `auto_approval` policy; `src/botnaut/governance/consent_tracker.py`: consent tracking; `src/botnaut/security/anti_phishing/`: anti-phishing for agent-to-human communication; `docs/ethics/NO_HIDDEN_COSTS.md`: transparency commitment; `GOVERNANCE.md` §1: PBC dual mandate | — |
| ASI10 | **Rogue Agents** — An agent defects from its intended objective, acts deceptively, or coordinates with other compromised agents to pursue misaligned goals outside operator control | PARTIAL | `src/security/firewall/mod.rs`: anomaly scoring with configurable `anomaly_block_threshold` — scores above threshold are blocked (JSON-RPC -32002), scores above `anomaly_threshold` are logged. `FirewallVerdict::is_anomaly_block()` distinguishes anomaly blocks from policy blocks; `src/kill_switch/`: emergency halt; `src/cost_accounting/enforcer.rs`: spend cap prevents runaway cost; `src/session_sandbox.rs`: `max_calls` + `max_duration` bound session lifetime | `src/botnaut/security/constitution_enforcer.py`: Ed25519-signed constitution with startup enforcement; `src/botnaut/alignment_safety/constitutional.py`: constitutional AI alignment layer; `src/botnaut/alignment_safety/interpretability.py`: interpretability probes; `src/botnaut/governance/constitutional_verifier/`: runtime constitution verification; `src/botnaut/security/agent_anomaly_detector.py`: agent-specific anomaly detection | Multi-agent collusion detection not yet implemented; anomaly detector is statistical, not predictive. Tracked by MIK-3360 |

---

## Summary

| Status | Count | Risks |
|--------|-------|-------|
| **COVERED** | 5/10 | ASI01 (Behaviour Hijack), ASI02 (Tool Misuse), ASI03 (Identity Abuse), ASI08 (Cascading Failures), ASI09 (Human Trust Exploitation) |
| **PARTIAL** | 5/10 | ASI04 (Supply Chain / Rug Pull), ASI05 (Code Execution / RCE), ASI06 (Memory Poisoning), ASI07 (Inter-Agent Comms), ASI10 (Rogue Agents) |
| **GAP** | 0/10 | — |

**Overall**: all 10 risks have mapped controls, but five rows remain partial. Four are the remaining MIK-3303 tracked gateway gaps below; ASI06 remains a separate memory-poisoning residual because mcp-gateway is stateless and Botnaut memory hardening is not fully shipped. Do not treat this matrix as an unconditional 10/10 closure claim.

## MIK-3303 Tracked Partial / Out-of-Scope Gaps

| Risk | Tracking issue | Scope |
|------|----------------|-------|
| ASI04 | MIK-3361 | SBOM artifact/release signing and live remote MCP server attestation discovery after config-time provenance |
| ASI05 | MIK-3364 | Sandboxed tool-result handling plus SQL-injection block behavior |
| ASI07 | MIK-3362 | Multi-gateway JWS-style signature chaining |
| ASI10 | MIK-3360 | Multi-agent collusion detection |

---

## ASI04 Remote MCP Server Provenance Boundary (MIK-3361)

### Current SBOM and signing coverage

- Local capability integrity is covered by `src/capability/hash.rs` and the `mcp-gateway cap pin` flow: the loader verifies a SHA-256 hash over raw capability YAML content with the top-level `sha256:` line excluded.
- Release artifacts currently get `SHA256SUMS.txt` in `.github/workflows/release.yml`; that is checksum evidence, not an SBOM and not a publisher signature.
- CI runs dependency audit in `.github/workflows/ci.yml`; no repository workflow currently emits CycloneDX/SPDX SBOM artifacts or signs release assets with Sigstore/cosign.
- Remote MCP server trust is now separate from local dependency metadata: `security.remote_server_signing` verifies signed backend provenance at config validation time before the gateway starts with the configured backend set.

### Accepted remote provenance inputs

`security.remote_server_signing` accepts:

- `require_for_remote_backends`: when `true`, every enabled HTTP/A2A backend must have signed provenance metadata.
- `trusted_keys`: map of `key_id` to `{ algorithm: ed25519, public_key: <base64 raw 32-byte Ed25519 key> }`.
- `backends`: map of backend name to `{ subject, issuer, issued_at, key_id, signature }`.

The signature covers canonical JSON with `backend`, `transport`, `url`, `subject`, `issuer`, and `issued_at`. Binding the transport and URL means a copied signature fails if an operator or attacker changes the remote endpoint.

### Fail-closed behavior and evidence

- If `require_for_remote_backends` is `true`, missing metadata for an enabled HTTP/A2A backend is a `ConfigValidation` error.
- If metadata is present, unknown `key_id`, malformed base64, wrong key length, wrong signature length, or invalid Ed25519 signature is a `ConfigValidation` error, even when the global requirement is disabled.
- CI-safe tests cover accepted signed metadata, rejected unsigned metadata, and rejected tampered URL metadata in `src/config/tests.rs` (`validate_accepts_signed_remote_backend_provenance`, `validate_rejects_required_remote_backend_without_provenance`, `validate_rejects_tampered_remote_backend_provenance_signature`).

Residual boundary: this does not yet define a network discovery protocol for fetching remote attestation documents; operators must provision signed metadata in gateway config. SBOM artifact generation and release asset signing remain separate follow-up hardening.

---

## Priority Remediation Recommendations

### P0 — Close Partial Gaps

1. ~~**ASI03 — Agent Identity (MIK-3363)**~~: Implemented for the mTLS hardened profile. Verified TLS peer certificates are extracted after handshake, SPIFFE URI SANs are available as `CertIdentity`, and mTLS policy rules can fail-closed on accepted or rejected SVID paths. This is transport-bound workload identity, not a claim that token-only deployments provide agent attestation.

2. **ASI07 — Multi-Gateway Message Signing (MIK-3362)**: Add signed-hop provenance for multi-gateway delegation, or explicitly fail closed when a chain would be required. Existing HMAC response signing covers gateway-to-client responses, not multi-gateway JWS-style chaining.

3. ~~**ASI08 — Per-Client Resilience (MIK-3365)**~~: Implemented. Authenticated clients are admitted through per-client rate limits and optional per-client dispatch circuit breakers keyed by resolved bearer/API-key identity, not spoofable forwarded headers.

### P1 — Strengthen Partial Controls

4. ~~**ASI09 — HITL Protocol**~~: ✅ Implemented. `src/gateway/destructive_confirmation.rs` gates destructive meta-tools via MCP elicitation. Status upgraded to COVERED.

5. **ASI05 — Tool Result Isolation (MIK-3364)**: Add sandboxed tool-result handling and fail-closed SQL-injection blocking where a handler has SQL-capable sinks.

6. **ASI10 — Rogue Agent Detection (MIK-3360)**: Promote the anomaly detector from retrospective logging to prospective blocking for sessions that exceed a configurable anomaly score threshold. Add multi-agent coordination detection.

7. **ASI04 — Remote MCP Server Signing (MIK-3361)**: Config-time signed provenance verification is implemented for HTTP/A2A backends via `security.remote_server_signing`. Remaining hardening should add SBOM artifact generation, release asset signing, and a remote attestation discovery protocol before ASI04 can be marked covered.

### P2 — Extend Coverage

8. **ASI01 — Output Scanning**: ✅ Implemented in MIK-6562. `response_inspect.rs` now provides response-inspection action mode — configurable block/observe for code injection, supply-chain, and combined instruction-override+tool-directive payloads in tool results. Configurable via `security.firewall.response_inspection_action_mode`.

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
| `src/security/remote_provenance.rs` | ASI04 |
| `src/session_sandbox.rs` | ASI02, ASI08, ASI10 |
| `src/cost_accounting/enforcer.rs` | ASI08, ASI09, ASI10 |
| `src/failsafe/circuit_breaker.rs` | ASI08 |
| `src/failsafe/rate_limiter.rs` | ASI08 |
| `src/gateway/auth.rs` | ASI03, ASI08 |
| `src/mtls/cert_manager.rs` | ASI03, ASI07 |
| `src/gateway/server/support.rs` | ASI03 |
| `src/oauth/` | ASI03 |
| `src/gateway/destructive_confirmation.rs` | ASI09 |
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
