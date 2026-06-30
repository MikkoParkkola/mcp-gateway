# OWASP Agentic AI Compliance Matrix

**Date**: 2026-06-27
**Standard**: OWASP Agentic Security Initiative Top 10 / Agentic AI Threats and Mitigations
**Sources**: [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/), [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
**Scope**: mcp-gateway repo-local controls at the gateway boundary.

This matrix tracks mcp-gateway only. Older versions mixed in external controls and treated several implemented gateway controls as pending. Current coverage is **10/10 COVERED** for the gateway boundary, with hardening follow-ups listed separately where a downstream tool, multi-gateway mesh, or deployment profile must add its own controls.

## Compliance Matrix

| # | OWASP ASI Risk | Status | mcp-gateway controls | Boundary / hardening |
|---|---|---|---|---|
| ASI01 | Agent Behaviour Hijack | COVERED | Tool-poisoning validator blocks hidden instructions, exfiltration patterns, local-file probes, bidi/zero-width tricks, and oversized descriptions before tool lists reach the client (`src/validator/rules/tool_poisoning.rs`). The request firewall scans arguments for shell and traversal payloads (`src/security/firewall/input_scanner.rs`). Response inspection can scan backend output before return (`src/security/response_inspect.rs`). | Expand response-side prompt-injection patterns as new attack examples appear. |
| ASI02 | Tool Misuse and Exploitation | COVERED | Default deny patterns cover destructive and dynamic execution tools (`src/security/policy.rs`). Session profiles can limit backends, denied tools, payload size, call count, and duration (`src/session_sandbox.rs`). Scope-collision checks detect conflicting grants (`src/security/scope_collision.rs`). Tool-sequence anomaly scoring flags unusual call chains (`src/security/firewall/anomaly.rs`). | Structural graph-level misuse analysis remains hardening beyond the current runtime policy and anomaly layer. |
| ASI03 | Identity and Privilege Abuse | COVERED | mTLS verifies client certificates and extracts SPIFFE/SVID-style identities (`src/mtls/cert_manager.rs`, `src/mtls/identity.rs`, `src/gateway/server/support.rs`). mTLS access rules fail closed when rules exist but no verified identity is present (`src/mtls/access_control/mod.rs`). OAuth 2.0 + PKCE supports backend identity flows (`src/oauth/`). Boundary-call attestation validates signed task tokens, expiry, rotation, and capability grants (`src/attestation/validator.rs`, `src/gateway/meta_mcp/invoke.rs`). Local identity grants load JSON/YAML grant rows and enforce personal capability owner, subject, agent, tool, scope, expiry, and audit decisions before dispatch (`src/identity_grants.rs`, `src/gateway/server/mod.rs`, `src/gateway/meta_mcp/invoke.rs`). | Token-only deployments are outside the hardened ASI03 profile unless paired with mTLS, attestation, or explicit local grants for personal capability exposure. |
| ASI04 | Agentic Supply Chain Vulnerabilities | COVERED | Capability YAML files can be SHA-256 pinned (`src/capability/hash.rs`), and watcher hot reload rejects changed pinned files (`src/capability/watcher.rs`). Remote backend provenance binds backend name, transport, URL, subject, issuer, and issue time to Ed25519 verification at config validation (`src/security/remote_provenance.rs`, `src/config/mod.rs`). Release npm publish uses OIDC provenance in `.github/workflows/release.yml`. | Add generated SBOM artifacts, cosign-style release signing, and live remote attestation discovery for stronger deployment evidence. |
| ASI05 | Unexpected Code Execution / RCE | COVERED | Input firewall blocks high-severity shell injection and path traversal patterns (`src/security/firewall/input_scanner.rs`). Default policy denies dynamic execution tool names (`src/security/policy.rs`). SSRF guard blocks private, loopback, reserved, multicast, and link-local IPv4/IPv6 destinations (`src/security/ssrf.rs`). Configurable firewall rules can fail closed on SQL-injection patterns for execution-like sinks (`tests/firewall_integration.rs`). Runtime-substrate descriptors preflight sandbox limits when that feature is used (`src/runtime/provision.rs`). | Generic search-like tools keep SQL patterns warn-only to avoid false positives; SQL-capable sinks should enable blocking rules. Downstream tool implementations still need least privilege. |
| ASI06 | Memory and Context Poisoning | COVERED | Dedicated memory scanner is enabled by default for memory-write tools and blocks LLM control tokens and role-confusion payloads (`src/security/firewall/memory_scanner.rs`, `src/security/firewall/mod.rs`). ContextIntegrityKernel classifies gateway-routed tool output before privileged context promotion, attaches provenance and audit evidence by default, and can enforce the shared-team baseline from `security.context_integrity.preset: team_shared` (`src/context_integrity/`, `src/config/features/security.rs`, `src/gateway/server/mod.rs`, `src/gateway/meta_mcp/invoke.rs`). Large memory writes and encoded payloads warn. Non-memory tools are intentionally excluded from memory-specific findings. | mcp-gateway does not own a vector store. External memory backends must still enforce store-level integrity and deletion policy. |
| ASI07 | Insecure Inter-Agent Communication | COVERED | HMAC-SHA256 response signing adds `_signature` metadata to signed `gateway_invoke` responses, and nonce replay protection rejects duplicate request nonces inside the configured replay window (`src/security/message_signing.rs`, `src/gateway/meta_mcp/invoke.rs`). mTLS protects transport channels (`src/mtls/`). | Multi-gateway signature chaining is not implemented; deployments that require a signed mesh should add hop-by-hop signatures or fail closed on delegated chains. |
| ASI08 | Cascading Failures | COVERED | Per-client throttling and optional dispatch circuit breakers sit in gateway auth flow (`src/gateway/auth.rs`). Shared circuit breaker, retry, and rate-limit modules isolate failing backends (`src/failsafe/`). Session sandbox limits call count, duration, and payload size (`src/session_sandbox.rs`). Cost accounting enforces daily spend budgets (`src/cost_accounting/enforcer.rs`). | Distributed circuit state across several gateway processes remains deployment architecture, not a single-process coverage gap. |
| ASI09 | Human-Agent Trust Exploitation | COVERED | Destructive meta-tools require MCP elicitation confirmation (`src/gateway/destructive_confirmation.rs`). Cost budget alerts escalate before runaway spend (`src/cost_accounting/enforcer.rs`). Kill-switch modules provide emergency halt controls (`src/kill_switch/`). Transparency log and audit surfaces expose gateway decisions (`src/security/transparency_log.rs`, `src/security/firewall/audit.rs`). | Operators still need clear runbooks for high-risk tool approval in production. |
| ASI10 | Rogue Agents | COVERED | Anomaly blocking rejects tool sequences above configured block threshold (`src/security/firewall/anomaly.rs`, `src/security/firewall/mod.rs`). Session sandbox and cost budgets bound runaway sessions (`src/session_sandbox.rs`, `src/cost_accounting/enforcer.rs`). Kill-switch modules support emergency halt. Boundary-call attestation constrains permitted task capabilities (`src/attestation/validator.rs`). | Multi-agent collusion detection remains future hardening; current controls detect and bound local gateway behavior. |

## Summary

| Status | Count | Risks |
|---|---:|---|
| COVERED | 10/10 | ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10 |
| PARTIAL | 0/10 | - |
| GAP | 0/10 | - |

## Evidence Map

| Control area | Evidence |
|---|---|
| Tool poisoning and prompt-surface hygiene | `src/validator/rules/tool_poisoning.rs`, `src/security/firewall/input_scanner.rs`, `src/security/response_inspect.rs` |
| Policy, sandbox, and misuse limits | `src/security/policy.rs`, `src/session_sandbox.rs`, `src/security/scope_collision.rs` |
| Identity and attestation | `src/mtls/`, `src/oauth/`, `src/identity_grants.rs`, `src/attestation/validator.rs`, `src/gateway/server/mod.rs`, `src/gateway/meta_mcp/invoke.rs` |
| Capability and remote provenance | `src/capability/hash.rs`, `src/capability/watcher.rs`, `src/security/remote_provenance.rs`, `src/config/mod.rs` |
| RCE / SSRF / SQL-sink protection | `src/security/firewall/input_scanner.rs`, `src/security/ssrf.rs`, `tests/firewall_integration.rs`, `src/runtime/provision.rs` |
| Memory and context poisoning | `src/security/firewall/memory_scanner.rs`, `src/security/firewall/mod.rs`, `src/context_integrity/`, `src/config/features/security.rs`, `src/gateway/server/mod.rs`, `src/gateway/meta_mcp/invoke.rs` |
| Message signing and replay protection | `src/security/message_signing.rs`, `src/gateway/meta_mcp/invoke.rs`, `docs/adr/ADR-001-inter-agent-message-signing.md` |
| Resilience and cost containment | `src/gateway/auth.rs`, `src/failsafe/`, `src/session_sandbox.rs`, `src/cost_accounting/enforcer.rs` |
| Human confirmation and audit | `src/gateway/destructive_confirmation.rs`, `src/security/transparency_log.rs`, `src/security/firewall/audit.rs`, `src/kill_switch/` |
| Rogue-agent bounding | `src/security/firewall/anomaly.rs`, `src/security/firewall/mod.rs`, `src/attestation/validator.rs` |

## Validation Commands

These focused tests map directly to the controls most likely to regress:

```bash
cargo test validate_accepts_signed_remote_backend_provenance
cargo test validate_rejects_required_remote_backend_without_provenance
cargo test validate_rejects_tampered_remote_backend_provenance_signature
cargo test sign_response_injects_signature_block
cargo test nonce_store_rejects_replayed_nonce
cargo test memory_write_with_control_token_is_blocked
cargo test memory_write_with_role_confusion_is_blocked
cargo test --lib context_integrity_team_shared
cargo test exec_rule_elevates_sql_injection_to_block
cargo test anomaly_above_block_threshold_is_rejected
```

## Hardening Backlog

These items strengthen deployment evidence but do not change current gateway-boundary coverage:

- Generate and publish SBOM artifacts with releases.
- Add cosign-style release asset signing.
- Define a live remote attestation discovery protocol for remote MCP servers.
- Add signed-hop chaining for multi-gateway deployments.
- Add first-class SQL-sink profiles that default SQL-injection findings to block.
- Add multi-agent collusion detection beyond local anomaly scoring.
- Expand response-side prompt-injection scanning as the OWASP ASI corpus evolves.
