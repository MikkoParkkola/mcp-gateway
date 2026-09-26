# OWASP Agentic AI self-assessment matrix

**Date**: 2026-09-26 (4.0 release line; re-audited against source)
**Standard**: OWASP Agentic Security Initiative Top 10 / Agentic AI Threats and Mitigations
**Sources**: [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/), [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
**Scope**: mcp-gateway repo-local controls at the gateway boundary.

This matrix is a **self-assessment**, not a certification. It tracks mcp-gateway only, and cites only controls that run on the request path; a control that exists only in the CLI or in tests is not counted. Each row says which controls are on by default and which an operator must enable. Current mapping: **3/10 COVERED, 7/10 PARTIAL** for the gateway boundary. CI checks that every path and validation test cited here exists (`scripts/dev/check-owasp-citations.py`).

Companion (different question, same boundary): [MITRE Fight Fraud Framework mapping](compliance/MITRE-F3-MAPPING.md). OWASP ASI is agent-tool risk. F3 is financial-fraud actor behavior. The F3 document is a PARTIAL/GAP mapping, not a coverage badge.

## Compliance Matrix

| # | OWASP ASI Risk | Status | mcp-gateway controls | Boundary / hardening |
|---|---|---|---|---|
| ASI01 | Agent Behaviour Hijack | PARTIAL | On by default: the request firewall scans call arguments and refuses shell-injection and path-traversal payloads (`src/security/firewall/input_scanner.rs`, called from `src/gateway/router/backend_handlers.rs` and `src/gateway/router/handlers.rs`). The response firewall scans backend `tools/list` and results, and redacts and warns (`src/security/firewall/mod.rs`). Response inspection observes by default and blocks only with `action_mode` (`src/security/response_inspect.rs`). | The tool-descriptor validator (`src/validator/rules/tool_poisoning.rs`) runs only from the CLI today, so a poisoned tool description is redacted, not withheld. Wiring it into served tool lists is tracked in GitHub #1441. |
| ASI02 | Tool Misuse and Exploitation | COVERED | On by default: default-deny patterns refuse destructive and dynamic-execution tool names (`src/security/policy.rs`, checked in `src/gateway/router/authorization.rs`). Admin-only meta-tools, log-level changes and callback-registering capabilities are refused to non-admin callers with 403 (`src/gateway/router/authorization.rs`, `src/gateway/meta_mcp/visibility.rs`). API keys reach only their listed backends (`src/gateway/auth.rs`). Arguments carrying keys the tool schema does not declare are refused (`src/gateway/meta_mcp/invoke.rs`). Opt-in: tool-sequence anomaly scoring (`src/security/firewall/anomaly.rs`). | Structural graph-level misuse analysis remains hardening beyond the runtime policy. |
| ASI03 | Identity and Privilege Abuse | PARTIAL | Each caller sees and can invoke only the tools it is entitled to, on every discovery surface (`src/gateway/meta_mcp/visibility.rs`, `src/gateway/meta_mcp/search.rs`); cached results are bound to the caller (`src/identity_propagation/mod.rs`). Admin standing comes only from an admin API key or an explicit issuer-scoped `role_mapping` rule (`src/control_plane/role_mapping.rs`). Identity headers are honoured only from configured trusted proxies (`src/security/caller_identity.rs`; off by default). mTLS verifies client certificates and access rules fail closed when rules exist but no identity is present (`src/mtls/`). Identity grants gate personal capabilities (`src/identity_grants.rs`). Boundary-call attestation refuses a missing or invalid token when `GATEWAY_ATTESTATION_MODE=enforce` (`src/attestation/wiring.rs`); it is off by default. | Token-only deployments are outside the hardened profile unless paired with mTLS, trusted-proxy identity, or explicit grants. |
| ASI04 | Agentic Supply Chain Vulnerabilities | COVERED | A capability file with a `sha256:` pin is refused on load and on hot reload when its content changes (`src/capability/hash.rs`, `src/capability/watcher.rs`); unpinned files load. Remote backend provenance binds name, transport, URL, subject, issuer and issue time to an Ed25519 signature at config validation when required (`src/security/remote_provenance.rs`, `src/config/mod.rs`; opt-in). Container images are signed with cosign and carry an SPDX SBOM attestation, verified in CI on release tags (`.github/workflows/ci.yml`); npm publishes with OIDC provenance (`.github/workflows/release.yml`). | Release binaries carry no signature or SBOM yet; live remote attestation discovery is not implemented. |
| ASI05 | Unexpected Code Execution / RCE | PARTIAL | On by default: the input firewall refuses shell injection and path traversal (`src/security/firewall/input_scanner.rs`), and default-deny refuses dynamic-execution tool names (`src/security/policy.rs`). The SSRF guard refuses private, loopback, link-local, multicast, reserved and CGNAT destinations including IPv4 embedded in IPv6, and pins DNS results against rebinding (`src/security/ssrf/`); capability executors, discovery, OpenAPI import and HTTP redirects call it. Opt-in: firewall rules that block SQL-injection patterns (`tests/firewall_integration.rs`). | Backend URLs from the operator's own config are trusted and not re-checked by default. The runtime-substrate preflight (`src/runtime/provision.rs`) is a CLI check and launches no sandbox. Downstream tools still need least privilege. |
| ASI06 | Memory and Context Poisoning | PARTIAL | On by default: the memory scanner refuses LLM control tokens and role-confusion payloads in memory-write tools (`src/security/firewall/memory_scanner.rs`, `src/security/firewall/mod.rs`). The ContextIntegrityKernel classifies `gateway_invoke` output and attaches provenance metadata (`src/context_integrity/`, `src/gateway/meta_mcp/invoke.rs`); by default it monitors and delivers content unchanged. Opt-in: `security.context_integrity.preset: team_shared` withholds output that fails the baseline (`src/config/features/security.rs`). | Enforcement covers the meta-MCP invoke path only. mcp-gateway owns no vector store; memory backends must enforce their own integrity. |
| ASI07 | Insecure Inter-Agent Communication | PARTIAL | Opt-in: HMAC-SHA256 response signing adds `_signature` to `gateway_invoke` responses, and a nonce a client sends is refused on replay within the window; `require_nonce` makes the nonce mandatory (`src/security/message_signing.rs`, `src/gateway/meta_mcp/signing.rs`). mTLS protects transport when configured (`src/mtls/`). On by default: the gateway mints every HTTP session id and never adopts one a client chooses (`src/gateway/router/handlers.rs`). | Signing and replay protection are off by default; multi-gateway signature chaining is not implemented. |
| ASI08 | Cascading Failures | COVERED | Shared circuit breaker, retry and rate-limit modules isolate failing backends, and an open breaker degrades `/health` (`src/failsafe/`); a backend's own rate-limit refusal does not trip its breaker. Webhook `rate_limit` is enforced (`src/gateway/webhooks/`). Opt-in: per-key throttling and per-client dispatch circuit breakers (`src/gateway/auth.rs`), and daily cost budgets checked on every dispatch and kept across restarts (`src/cost_accounting/enforcer.rs`). | Distributed circuit state across several gateway processes remains deployment architecture. |
| ASI09 | Human-Agent Trust Exploitation | PARTIAL | Destructive meta-tools need elicitation confirmation from a modern client (`src/gateway/destructive_confirmation.rs`); a legacy client that cannot elicit proceeds with a warning. The kill switch halts a backend through admin-only meta-tools (`src/kill_switch/`). With auth on, the transparency log is required: every invocation, refusals included, gets a hash-chained, HMAC-signed record on the meta and direct routes, the log rotates and verifies across segments, and a failed write withholds the result with 503 (`src/security/transparency_log.rs`, `src/security/transparency_log_rotation.rs`, `src/gateway/meta_mcp/invoke/audit.rs`, `src/gateway/router/backend_handlers/direct_audit.rs`). Opt-in: budget alerts (`src/cost_accounting/enforcer.rs`). | Legacy clients bypass destructive confirmation; operators need runbooks for high-risk tool approval. |
| ASI10 | Rogue Agents | PARTIAL | The kill switch and error budgets halt a misbehaving backend (`src/kill_switch/`). Opt-in: anomaly blocking needs both `anomaly_detection` and `anomaly_block_threshold` (`src/security/firewall/anomaly.rs`, `src/security/firewall/mod.rs`); cost budgets bound spend (`src/cost_accounting/enforcer.rs`); attestation `enforce` constrains each call to its signed task scope on every route (`src/attestation/wiring.rs`). | Multi-agent collusion detection remains future hardening; current controls bound local gateway behaviour. |

## Summary

| Status | Count | Risks |
|---|---:|---|
| COVERED | 3/10 | ASI02, ASI04, ASI08 |
| PARTIAL | 7/10 | ASI01, ASI03, ASI05, ASI06, ASI07, ASI09, ASI10 |
| GAP | 0/10 | - |

## Evidence Map

| Control area | Evidence |
|---|---|
| Argument and response firewall | `src/security/firewall/`, `src/security/response_inspect.rs` |
| Policy, admin gates and backend scoping | `src/security/policy.rs`, `src/gateway/router/authorization.rs`, `src/gateway/meta_mcp/visibility.rs`, `src/gateway/auth.rs` |
| Per-caller discovery and cache isolation | `src/gateway/meta_mcp/visibility.rs`, `src/gateway/meta_mcp/search.rs`, `src/identity_propagation/mod.rs` |
| Identity, roles and attestation | `src/mtls/`, `src/oauth/`, `src/security/caller_identity.rs`, `src/control_plane/role_mapping.rs`, `src/identity_grants.rs`, `src/attestation/wiring.rs` |
| Capability and remote provenance | `src/capability/hash.rs`, `src/capability/watcher.rs`, `src/security/remote_provenance.rs`, `src/config/mod.rs` |
| RCE / SSRF / SQL-sink protection | `src/security/firewall/input_scanner.rs`, `src/security/ssrf.rs`, `tests/firewall_integration.rs` |
| Memory and context poisoning | `src/security/firewall/memory_scanner.rs`, `src/context_integrity/`, `src/config/features/security.rs` |
| Message signing and replay protection | `src/security/message_signing.rs`, `src/gateway/meta_mcp/signing.rs`, `docs/adr/ADR-001-inter-agent-message-signing.md` |
| Resilience and cost containment | `src/failsafe/`, `src/gateway/auth.rs`, `src/gateway/webhooks/`, `src/cost_accounting/enforcer.rs` |
| Human confirmation and audit | `src/gateway/destructive_confirmation.rs`, `src/kill_switch/`, `src/security/transparency_log.rs`, `src/security/transparency_log_rotation.rs`, `src/gateway/meta_mcp/invoke/audit.rs` |
| Supply chain (release) | `.github/workflows/ci.yml`, `.github/workflows/release.yml` |

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

These items strengthen coverage; the first is 4.0 scope.

- Withhold tools whose descriptors fail the tool-poisoning validator on every served tool list (GitHub #1441); ASI01 returns to COVERED when it lands.
- Sign release binaries and attach an SBOM to them, as the container images already are.
- Define a live remote attestation discovery protocol for remote MCP servers.
- Add signed-hop chaining for multi-gateway deployments.
- Add first-class SQL-sink profiles that default SQL-injection findings to block.
- Add multi-agent collusion detection beyond local anomaly scoring.
