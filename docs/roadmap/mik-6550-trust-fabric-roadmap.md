# mcp-gateway Trust Fabric Superiority Roadmap

This is the public roadmap for the mcp-gateway trust fabric. It decomposes the trust-fabric vision into 12 implementation-ready child rows (MIK-6551 through MIK-6562), each with canonical Definition of Ready (DoR) fields. The roadmap is machine-checkable: every child row carries a license tier and a build-vs-integrate decision, and the dependency graph is explicit.

## Dependency Ordering

The trust fabric depends on a layered architecture. The dependency graph below encodes the required build order:

```
MIK-6551 (Install UX) ─────────────────────────────────────────────────┐
MIK-6552 (Identity Grants) ── requires MIK-6551 ───────────────────────┤
MIK-6553 (Unmanaged Discovery) ── requires MIK-6551 ───────────────────┤
MIK-6554 (Runtime Isolation) ── requires MIK-6551 ──────────────────────┤
MIK-6555 (TrustCard/CBOM) ── requires MIK-6551, MIK-6552 ──────────────┤
MIK-6556 (Catalog Evaluation) ── requires MIK-6555 ─────────────────────┤
MIK-6557 (ControlPlaneUI) ── requires MIK-6552, MIK-6555 ──────────────┤
MIK-6558 (Context Integrity) ── requires MIK-6551, MIK-6554 ───────────┤
MIK-6559 (Kubernetes HA) ── requires MIK-6554, MIK-6557 ───────────────┤
MIK-6560 (Protocol Imports) ── requires MIK-6551 ──────────────────────┤
MIK-6561 (Adaptive Ranking) ── requires MIK-6553, MIK-6556 ────────────┤
MIK-6562 (Shadow Detection) ── requires MIK-6551, MIK-6553 ────────────┘
```

### Prior-Ticket Disposition (MIK-6207, MIK-6208, MIK-6209)

Before duplicate identity implementation can begin, the following prior tickets must be resolved:

- **MIK-6207** (Identity hook baseline): Disposition: **ABSORB**. The identity hook work from MIK-6207 is subsumed into MIK-6552 (Identity Grants). MIK-6552 will build on the hook interface defined in MIK-6207 and extend it to per-user/per-agent grant semantics. No separate implementation of MIK-6207 should proceed; its scope is merged.
- **MIK-6208** (OAuth 2.1/OIDC integration): Disposition: **PREREQUISITE**. MIK-6208 must be completed before MIK-6552 can begin. MIK-6552 depends on the OAuth 2.1/OIDC/PKCE and protected resource metadata primitives that MIK-6208 delivers. MIK-6208 is a build-vs-integrate "Integrate" decision (established protocols exist).
- **MIK-6209** (Agent identity attestation): Disposition: **COORDINATE**. MIK-6209 and MIK-6552 share the agent-identity domain. MIK-6209 focuses on attestation token issuance and verification; MIK-6552 focuses on grant management and policy enforcement. The two must share a common identity model. Implement MIK-6209 first, then MIK-6552 extends it with grant semantics.

## Child Rows

### MIK-6551: One Install Path

- **User Outcome**: Operators can install mcp-gateway with a single command on macOS, Linux, and Windows, and verify the installation is healthy within 30 seconds.
- **Contribution Class**: Feature implementation with install-script automation.
- **License Tier**: Free/core
- **Build-vs-Integrate**: Build
- **Rationale**: The install UX is gateway-specific and must be owned end-to-end for the trust-fabric story. No existing tool provides a unified MCP gateway install experience.
- **Dependencies**: None (foundational row).
- **Target Code/Docs Areas**: `install.sh`, `install.ps1`, Homebrew formula (`Formula/mcp-gateway.rb`), `src/cli/install.rs`, `docs/QUICKSTART.md`.
- **Threat Model**: Supply-chain: installer must verify binary signatures. Tampering: installer must not execute untrusted payloads. Availability: install must work offline after initial download.
- **Rollback**: Re-run the installer with a prior version tag. Homebrew: `brew install mcp-gateway@<version>`.
- **Risks**: Platform-specific packaging drift (Homebrew vs cargo vs direct download). Mitigation: CI matrix tests all three paths.
- **Fail-Fast Checks**: `mcp-gateway doctor` exits 0 after install. SHA-256 of installed binary matches release manifest.
- **Stable Acceptance Criteria**:
  - Single-command install succeeds on macOS (Homebrew), Linux (cargo/brew), and Windows (direct download).
  - `mcp-gateway doctor` reports all checks green after install.
  - Installer verifies binary integrity before execution.
- **Implementation Plan**: 1) Audit current install paths for gaps. 2) Unify into a single `install.sh` / `install.ps1` entry point. 3) Add binary signature verification. 4) Update Homebrew formula. 5) Add CI matrix for all platforms.
- **Test Plan**: Integration tests for each install path in CI. `mcp-gateway doctor` output validation. Binary hash verification test.

### MIK-6552: Per-User/Per-Agent Identity Grants

- **User Outcome**: Operators can define identity grants that bind specific users or agents to specific tool capabilities, with grant lifecycle management (create, revoke, audit).
- **Contribution Class**: Feature implementation with policy engine integration.
- **License Tier**: Free/core (baseline identity hooks); Enterprise/commercial (durable grant/audit stores, multi-user governance).
- **Build-vs-Integrate**: Build+Integrate
- **Rationale**: Build the grant policy engine and enforcement layer (gateway-specific). Integrate with OAuth 2.1/OIDC/PKCE for identity verification (established protocols per MIK-6208).
- **Dependencies**: MIK-6551 (Install UX), MIK-6208 (OAuth 2.1/OIDC — prerequisite), MIK-6209 (Agent identity attestation — coordinate).
- **Target Code/Docs Areas**: `src/identity/`, `src/security/agent_identity.rs`, `src/policy/`, `docs/OAUTH_CONFIG.md`.
- **Threat Model**: Privilege escalation via grant forgery. Replay attacks on grant tokens. Unauthorized grant modification. Mitigation: signed grants, short-lived tokens, audit log immutability.
- **Rollback**: Revoke all grants issued after a timestamp. Restore grant store from backup.
- **Risks**: Complexity of OAuth 2.1/OIDC integration. Mitigation: phased rollout — baseline identity hooks first, then full OAuth integration.
- **Fail-Fast Checks**: Grant creation fails with invalid identity. Grant enforcement denies access for revoked grants. Audit log records all grant mutations.
- **Stable Acceptance Criteria**:
  - Operators can create, list, and revoke identity grants via CLI and API.
  - Tool invocations are denied when the caller lacks a valid grant.
  - Grant audit trail is append-only and queryable.
  - Free/core tier supports single-user grant management; Enterprise tier supports multi-user governance with durable stores.
- **Implementation Plan**: 1) Define grant schema (identity, capabilities, expiry, issuer). 2) Implement grant store (in-memory for free/core, durable for Enterprise). 3) Integrate with MIK-6208 OAuth primitives. 4) Add grant enforcement to the tool-routing path. 5) Add CLI commands (`mcp-gateway grant create|list|revoke`). 6) Add audit logging.
- **Test Plan**: Unit tests for grant CRUD, enforcement, and expiry. Integration tests for OAuth flow. Audit log integrity tests.

### MIK-6553: Unmanaged MCP Discovery

- **User Outcome**: Operators can discover MCP servers on the local network or in configured namespaces without manually registering each one, and the gateway surfaces discovered servers for on-demand tool access.
- **Contribution Class**: Feature implementation with network discovery protocol.
- **License Tier**: Free/core
- **Build-vs-Integrate**: Build
- **Rationale**: MCP server discovery is gateway-specific. No standard MCP discovery protocol exists; the gateway must define and implement it.
- **Dependencies**: MIK-6551 (Install UX).
- **Target Code/Docs Areas**: `src/discovery/`, `src/gateway/discovery.rs`, `capabilities/`.
- **Threat Model**: Rogue MCP server injection via spoofed discovery announcements. Information disclosure via server metadata. Mitigation: server identity verification, capability hash-pinning on discovered servers, operator approval gate.
- **Rollback**: Disable discovery mode; revert to static server list.
- **Risks**: Network scanning may trigger security tools. Mitigation: passive discovery (listen for announcements) as default; active scanning as opt-in.
- **Fail-Fast Checks**: Discovered servers appear in `gateway_list_servers` output. Rogue server with invalid hash is quarantined. Operator approval required before discovered server tools are routable.
- **Stable Acceptance Criteria**:
  - Gateway discovers MCP servers via mDNS/DNS-SD and/or configured discovery namespaces.
  - Discovered servers are quarantined until operator approval.
  - SHA-256 capability pinning applies to discovered servers.
  - Discovery can be disabled or scoped to specific network interfaces.
- **Implementation Plan**: 1) Define discovery protocol (mDNS/DNS-SD + optional namespace scanning). 2) Implement discovery listener. 3) Add quarantine and approval workflow. 4) Integrate with capability hash-pinning. 5) Add CLI commands (`mcp-gateway discover scan|approve|deny`).
- **Test Plan**: Unit tests for discovery protocol parsing. Integration tests with mock MCP servers. Quarantine/approval workflow tests.

### MIK-6554: Runtime Isolation

- **User Outcome**: Operators can execute tool invocations in isolated runtime sandboxes (gVisor, Apple VM, OCI containers) with configurable resource limits, network egress policies, and attestation requirements.
- **Contribution Class**: Feature implementation with sandbox orchestration.
- **License Tier**: Free/core (local runtime isolation); Enterprise/commercial (managed policy evidence, organization-wide risk inventory).
- **Build-vs-Integrate**: Build+Integrate
- **Rationale**: Build the sandbox orchestration layer and policy engine (gateway-specific). Integrate with OCI/gVisor/Apple containerization/Kubernetes primitives for the actual isolation runtime (established runtimes exist).
- **Dependencies**: MIK-6551 (Install UX).
- **Target Code/Docs Areas**: `src/runtime/`, `src/security/sandbox.rs`, `docs/runtime/`.
- **Threat Model**: Sandbox escape via kernel vulnerability. Resource exhaustion via unbounded sandbox creation. Data exfiltration via network egress. Mitigation: attestation tokens, resource quotas, network egress policies, seccomp profiles.
- **Rollback**: Disable sandbox mode; fall back to process-level isolation.
- **Risks**: Platform-specific sandbox behavior differences. Mitigation: equivalence test matrix across gVisor, Apple VM, and OCI runtimes.
- **Fail-Fast Checks**: Sandbox boot fails closed without valid attestation token. Resource limits are enforced (OOM on exceed). Network egress policy blocks unauthorized outbound connections.
- **Stable Acceptance Criteria**:
  - Tool invocations can be routed to gVisor, Apple VM, or OCI container sandboxes.
  - Sandbox descriptor schema supports resource limits, network egress policies, mounts, and attestation config.
  - Attestation tokens are required for sandbox creation (fail-closed).
  - Free/core supports local sandboxing; Enterprise adds managed policy evidence and risk inventory.
- **Implementation Plan**: 1) Define sandbox descriptor schema. 2) Implement compiler: descriptor → gVisor/Apple VM/OCI bundle. 3) Build sandbox launcher with attestation enforcement. 4) Add resource quota enforcement. 5) Add network egress policy enforcement. 6) Create equivalence test matrix.
- **Test Plan**: Unit tests for descriptor schema, compiler, and launcher. Integration tests for each substrate. Equivalence test matrix (10-task across substrates). Divergence detection tests.

### MIK-6555: TrustCard/CBOM Metadata

- **User Outcome**: Every capability and backend carries a machine-readable TrustCard with cryptographic provenance, a Cryptography Bill of Materials (CBOM), and integrity evidence that operators and automated tooling can verify before routing traffic.
- **Contribution Class**: Feature implementation with metadata schema and verification pipeline.
- **License Tier**: Free/core (basic trust metadata); Enterprise/commercial (catalog certification service).
- **Build-vs-Integrate**: Build+Integrate
- **Rationale**: Build the TrustCard schema, CBOM generation, and verification pipeline (gateway-specific). Integrate with CycloneDX/SPDX/Sigstore-style conventions for CBOM and release trust evidence (established conventions exist).
- **Dependencies**: MIK-6551 (Install UX), MIK-6552 (Identity Grants — for signer identity).
- **Target Code/Docs Areas**: `src/trustcard/`, `src/cbom/`, `src/capability/hash.rs`, `capabilities/`.
- **Threat Model**: TrustCard forgery. CBOM tampering. Replay of stale trust evidence. Mitigation: signed TrustCards, hash-chained CBOM entries, timestamped evidence with expiry.
- **Rollback**: Revert to SHA-256-only pinning; disable TrustCard enforcement.
- **Risks**: CBOM standard fragmentation (CycloneDX vs SPDX). Mitigation: support both formats with a canonical internal representation.
- **Fail-Fast Checks**: Capability without valid TrustCard is quarantined. CBOM hash chain is unbroken. TrustCard signature verifies against known issuer key.
- **Stable Acceptance Criteria**:
  - Every capability YAML can carry an optional TrustCard block with issuer, signature, and evidence links.
  - CBOM is generated for each capability and verified on load.
  - TrustCard verification is enforced in the capability loading path.
  - Free/core supports basic TrustCard verification; Enterprise adds catalog certification service.
- **Implementation Plan**: 1) Define TrustCard schema (issuer, subject, evidence, signature). 2) Define CBOM schema (CycloneDX/SPDX-compatible). 3) Implement TrustCard signer and verifier. 4) Implement CBOM generator and verifier. 5) Integrate into capability loading path. 6) Add CLI commands (`mcp-gateway trustcard sign|verify`).
- **Test Plan**: Unit tests for TrustCard sign/verify, CBOM generate/verify. Integration tests for capability loading with TrustCard enforcement. Forgery detection tests.

### MIK-6556: Continuous Catalog Evaluation

- **User Outcome**: Operators can run automated evaluations of the capability catalog against security policies, freshness requirements, and compatibility matrices, with results surfaced as actionable reports.
- **Contribution Class**: Feature implementation with evaluation engine and reporting.
- **License Tier**: Free/core (local evaluation); Enterprise/commercial (organization-wide risk inventory, managed policy evidence).
- **Build-vs-Integrate**: Build
- **Rationale**: Catalog evaluation is gateway-specific policy and metadata analysis. No existing tool evaluates MCP capability catalogs against trust-fabric policies.
- **Dependencies**: MIK-6555 (TrustCard/CBOM — evaluation targets).
- **Target Code/Docs Areas**: `src/evaluation/`, `src/catalog/`, `src/security/scanner.rs`.
- **Threat Model**: Evaluation bypass via tampered evaluation config. False-negative reports hiding compromised capabilities. Mitigation: evaluation config is hash-pinned; evaluation results are signed.
- **Rollback**: Disable continuous evaluation; rely on point-in-time manual review.
- **Risks**: Evaluation rule false positives causing operational disruption. Mitigation: evaluation severity levels (INFO/WARN/FAIL); only FAIL blocks routing.
- **Fail-Fast Checks**: Evaluation run completes without errors. Stale capability (no update in N days) triggers WARN. Missing TrustCard triggers FAIL.
- **Stable Acceptance Criteria**:
  - `mcp-gateway catalog evaluate` runs all evaluation rules and produces a report.
  - Evaluation rules cover: TrustCard validity, CBOM freshness, SHA-256 pin match, deprecation status, OWASP compliance.
  - Evaluation can run on a schedule (continuous) or on-demand.
  - Free/core supports local evaluation; Enterprise adds organization-wide risk inventory.
- **Implementation Plan**: 1) Define evaluation rule schema. 2) Implement evaluation engine. 3) Add built-in rules (TrustCard, CBOM, hash, deprecation, OWASP). 4) Add scheduled evaluation runner. 5) Add CLI and API for evaluation results.
- **Test Plan**: Unit tests for each evaluation rule. Integration tests for full catalog evaluation. Scheduled evaluation tests.

### MIK-6557: Enterprise Governance UI (ControlPlaneUI)

- **User Outcome**: Enterprise operators can manage multi-user identity grants, audit logs, policy configurations, and organization-wide risk inventory through a web-based control plane.
- **Contribution Class**: Feature implementation with web UI and API.
- **License Tier**: Enterprise/commercial
- **Build-vs-Integrate**: Build
- **Rationale**: The governance UI is gateway-specific and must integrate deeply with the gateway's policy, identity, and audit subsystems. No existing admin UI provides MCP gateway governance.
- **Dependencies**: MIK-6552 (Identity Grants), MIK-6555 (TrustCard/CBOM).
- **Target Code/Docs Areas**: `src/webui/`, `src/controlplane/`, `src/identity/`, `src/audit/`.
- **Threat Model**: Unauthorized access to control plane. CSRF/XSS in web UI. Privilege escalation via API. Mitigation: mTLS, session management, RBAC, CSP headers, API rate limiting.
- **Rollback**: Disable control plane; fall back to CLI-only management.
- **Risks**: Web UI attack surface expansion. Mitigation: CSP, CSRF tokens, input validation, dependency auditing.
- **Fail-Fast Checks**: Control plane requires authentication. API rejects unauthenticated requests. Audit log records all control plane actions.
- **Stable Acceptance Criteria**:
  - Web UI serves on configurable port with mTLS.
  - Operators can manage identity grants, view audit logs, and configure policies via UI.
  - Organization-wide risk inventory is viewable and filterable.
  - All control plane actions are audited.
- **Implementation Plan**: 1) Design control plane API (REST + WebSocket for live updates). 2) Implement authentication and authorization. 3) Build web UI (grant management, audit viewer, policy editor, risk dashboard). 4) Add mTLS support. 5) Add audit logging for all control plane actions.
- **Test Plan**: Unit tests for API endpoints. Integration tests for UI workflows. Security tests (CSRF, XSS, auth bypass). Audit log integrity tests.

### MIK-6558: Context Integrity

- **User Outcome**: Operators can verify that tool descriptions, results, and metadata have not been tampered with in transit between the backend and the AI client, with cryptographic integrity proofs at every hop.
- **Contribution Class**: Feature implementation with integrity verification pipeline.
- **License Tier**: Free/core (local integrity verification); Enterprise/commercial (managed policy evidence).
- **Build-vs-Integrate**: Build
- **Rationale**: Context integrity is gateway-specific — it sits on the trust path for every tool call. No existing tool provides end-to-end integrity verification across MCP tool chains.
- **Dependencies**: MIK-6551 (Install UX), MIK-6554 (Runtime Isolation — integrity in sandboxed contexts).
- **Target Code/Docs Areas**: `src/security/message_signing.rs`, `src/gateway/integrity.rs`, `src/validator/`.
- **Threat Model**: Tool description poisoning in transit. Result tampering by intermediate proxy. Metadata stripping or injection. Mitigation: message signing, hash chaining, attestation tokens.
- **Rollback**: Disable integrity enforcement; log warnings only.
- **Risks**: Performance overhead of per-message signing. Mitigation: batch verification, cached trust chains.
- **Fail-Fast Checks**: Unsigned message from backend requiring integrity is rejected. Hash chain break is detected and logged. Attestation token mismatch blocks routing.
- **Stable Acceptance Criteria**:
  - Tool descriptions and results carry optional integrity proofs.
  - Integrity verification is enforced when backend requires it.
  - Hash chain covers: backend → gateway → client.
  - Free/core supports local verification; Enterprise adds managed policy evidence.
- **Implementation Plan**: 1) Define integrity proof format (message signature + hash chain). 2) Implement signer and verifier. 3) Integrate into tool-routing path. 4) Add integrity policy configuration. 5) Add CLI commands for integrity verification.
- **Test Plan**: Unit tests for sign/verify. Integration tests for end-to-end integrity. Tampering detection tests. Performance benchmark tests.

### MIK-6559: Kubernetes HA

- **User Outcome**: Operators can deploy mcp-gateway in a Kubernetes cluster with high availability, horizontal scaling, and rolling updates without dropping active MCP sessions.
- **Contribution Class**: Feature implementation with Kubernetes operator and Helm chart.
- **License Tier**: Enterprise/commercial
- **Build-vs-Integrate**: Build+Integrate
- **Rationale**: Build the gateway operator, session migration, and HA coordination (gateway-specific). Integrate with Kubernetes primitives (Deployments, Services, ConfigMaps, Secrets) for orchestration (established platform exists).
- **Dependencies**: MIK-6554 (Runtime Isolation), MIK-6557 (ControlPlaneUI).
- **Target Code/Docs Areas**: `src/k8s/`, `deploy/helm/`, `deploy/operator/`, `docs/DEPLOYMENT.md`.
- **Threat Model**: Session hijacking during migration. Secret exposure via ConfigMap. Unauthorized operator access. Mitigation: mTLS between gateway instances, encrypted session state, RBAC for operator.
- **Rollback**: `helm rollback` to previous release. Operator supports graceful degradation to single-instance mode.
- **Risks**: Session state consistency during rolling updates. Mitigation: session affinity with graceful drain; session state replication.
- **Fail-Fast Checks**: Multiple gateway instances form a healthy cluster. Session survives rolling update of one instance. Health check endpoint reports cluster status.
- **Stable Acceptance Criteria**:
  - Helm chart deploys a working multi-instance gateway cluster.
  - Kubernetes operator manages lifecycle (deploy, scale, update, rollback).
  - Active MCP sessions survive rolling updates.
  - Health check endpoint reports per-instance and cluster status.
- **Implementation Plan**: 1) Design session migration protocol. 2) Implement cluster membership and leader election. 3) Build Kubernetes operator. 4) Create Helm chart. 5) Add session affinity and graceful drain. 6) Add cluster health endpoint.
- **Test Plan**: Unit tests for session migration and leader election. Integration tests with kind/minikube. Rolling update survival tests. Operator reconciliation tests.

### MIK-6560: Protocol Imports

- **User Outcome**: Operators can import tool definitions from OpenAPI specs, GraphQL schemas, Postman collections, and OCI package metadata, converting them into validated capability YAMLs automatically.
- **Contribution Class**: Feature implementation with multi-format import pipeline.
- **License Tier**: Free/core
- **Build-vs-Integrate**: Build+Integrate
- **Rationale**: Build the import pipeline, validation, and capability generation (gateway-specific). Integrate with OpenAPI, GraphQL introspection, Postman collections, and OCI package metadata formats (established formats exist).
- **Dependencies**: MIK-6551 (Install UX).
- **Target Code/Docs Areas**: `src/capability/openapi.rs`, `src/capability/graphql.rs`, `src/capability/postman.rs`, `src/capability/oci.rs`, `docs/OPENAPI_IMPORT.md`.
- **Threat Model**: Malicious spec triggering code execution during import. Spec injection adding hidden tool descriptions. Mitigation: spec validation before processing, sandboxed import pipeline, output validation.
- **Rollback**: Delete imported capabilities; re-import from known-good spec.
- **Risks**: Format-specific edge cases in OpenAPI/GraphQL/Postman parsing. Mitigation: comprehensive test suites per format, fuzz testing.
- **Fail-Fast Checks**: Import of valid spec produces valid capability YAMLs. Import of malformed spec fails with clear error. Generated YAMLs pass SHA-256 pinning.
- **Stable Acceptance Criteria**:
  - `mcp-gateway cap import` supports OpenAPI 3.x, GraphQL (introspection), Postman 2.1 collections, and OCI image metadata.
  - Imported capabilities are validated against the capability schema.
  - Imported capabilities are hash-pinnable.
  - Each format has a dedicated test suite.
- **Implementation Plan**: 1) Extend OpenAPI importer (already exists) with edge-case coverage. 2) Implement GraphQL introspection importer. 3) Implement Postman collection importer. 4) Implement OCI metadata importer. 5) Add format auto-detection. 6) Add fuzz tests for each format.
- **Test Plan**: Unit tests per format parser. Integration tests for full import pipeline. Fuzz tests. Regression tests for known edge cases.

### MIK-6561: Adaptive Ranking

- **User Outcome**: The gateway ranks discovered tools by relevance, trust score, and performance history, so the AI client sees the best tool for each query without operator curation.
- **Contribution Class**: Feature implementation with ranking engine and feedback loop.
- **License Tier**: Free/core (adaptive local ranking); Enterprise/commercial (organization-wide ranking models).
- **Build-vs-Integrate**: Build
- **Rationale**: Adaptive ranking is gateway-specific — it depends on gateway telemetry, trust metadata, and invocation history. No existing ranking system understands MCP tool semantics.
- **Dependencies**: MIK-6553 (Unmanaged Discovery), MIK-6556 (Catalog Evaluation).
- **Target Code/Docs Areas**: `src/ranking/`, `src/gateway/search.rs`, `src/cost_accounting/`.
- **Threat Model**: Ranking manipulation via fake invocation history. Trust score gaming. Mitigation: trust score is derived from verifiable evidence (TrustCard, CBOM, hash); invocation history is append-only and signed.
- **Rollback**: Disable adaptive ranking; fall back to alphabetical or static ordering.
- **Risks**: Cold-start problem for new tools. Mitigation: default trust score based on TrustCard evidence; bootstrap from catalog evaluation results.
- **Fail-Fast Checks**: Ranking produces ordered list. Trust score is computable from available evidence. Ranking updates after new invocation data.
- **Stable Acceptance Criteria**:
  - `gateway_search_tools` returns results ranked by relevance + trust score.
  - Trust score incorporates: TrustCard validity, CBOM freshness, invocation success rate, operator approval status.
  - Ranking adapts over time based on invocation history.
  - Free/core supports local ranking; Enterprise adds organization-wide ranking models.
- **Implementation Plan**: 1) Define ranking signal schema (trust, relevance, performance). 2) Implement trust score computation. 3) Implement relevance scoring. 4) Implement ranking engine with feedback loop. 5) Integrate into `gateway_search_tools`. 6) Add ranking transparency (why this tool ranked here).
- **Test Plan**: Unit tests for trust score computation and ranking engine. Integration tests for `gateway_search_tools` ranking. Feedback loop convergence tests.

### MIK-6562: Local Shadow Detection

- **User Outcome**: Operators are alerted when a local MCP server or capability shadows (overrides) another, preventing silent tool conflicts and ensuring the AI client always reaches the intended backend.
- **Contribution Class**: Feature implementation with conflict detection and resolution.
- **License Tier**: Free/core
- **Build-vs-Integrate**: Build
- **Rationale**: Shadow detection is gateway-specific — it requires understanding of the MCP tool namespace and capability routing. No existing tool detects MCP tool shadowing.
- **Dependencies**: MIK-6551 (Install UX), MIK-6553 (Unmanaged Discovery — shadow detection for discovered servers).
- **Target Code/Docs Areas**: `src/gateway/shadow.rs`, `src/capability/namespace.rs`, `src/discovery/`.
- **Threat Model**: Malicious server intentionally shadowing a trusted server. Accidental shadowing causing tool misrouting. Mitigation: shadow detection on every server registration; operator alert with resolution options.
- **Rollback**: Disable shadow detection; rely on manual namespace management.
- **Risks**: False-positive shadow alerts on legitimate multi-server setups. Mitigation: shadow severity levels (INFO for same-capability different-server, WARN for name collision, FAIL for hash mismatch).
- **Fail-Fast Checks**: Registering a server that shadows an existing tool triggers alert. Shadowed tool invocations are logged. Operator can resolve shadows (keep, replace, namespace).
- **Stable Acceptance Criteria**:
  - Gateway detects tool name collisions across registered and discovered servers.
  - Shadow alerts are surfaced in `gateway_list_tools` and logs.
  - Operator can resolve shadows via CLI (`mcp-gateway shadow resolve`).
  - Shadow detection runs on server registration and on discovery events.
- **Implementation Plan**: 1) Define shadow detection rules (name collision, hash mismatch, namespace overlap). 2) Implement shadow detector. 3) Integrate into server registration and discovery paths. 4) Add shadow alerting (logs + tool list annotations). 5) Add CLI commands for shadow resolution.
- **Test Plan**: Unit tests for shadow detection rules. Integration tests for registration-time and discovery-time detection. Resolution workflow tests.

## License Tier Summary

| Child Row | Free/Core | Enterprise/Commercial |
|-----------|-----------|----------------------|
| MIK-6551 (Install UX) | Full | — |
| MIK-6552 (Identity Grants) | Baseline identity hooks, single-user grants | Durable grant/audit stores, multi-user governance |
| MIK-6553 (Unmanaged Discovery) | Full | — |
| MIK-6554 (Runtime Isolation) | Local runtime isolation | Managed policy evidence, org-wide risk inventory |
| MIK-6555 (TrustCard/CBOM) | Basic trust metadata | Catalog certification service |
| MIK-6556 (Catalog Evaluation) | Local evaluation | Organization-wide risk inventory |
| MIK-6557 (ControlPlaneUI) | — | Full |
| MIK-6558 (Context Integrity) | Local integrity verification | Managed policy evidence |
| MIK-6559 (Kubernetes HA) | — | Full |
| MIK-6560 (Protocol Imports) | Full | — |
| MIK-6561 (Adaptive Ranking) | Adaptive local ranking | Organization-wide ranking models |
| MIK-6562 (Shadow Detection) | Full | — |

## Build-vs-Integrate Summary

| Child Row | Decision | Rationale |
|-----------|----------|-----------|
| MIK-6551 (Install UX) | Build | Gateway-specific install experience |
| MIK-6552 (Identity Grants) | Build+Integrate | Build grant engine; integrate OAuth 2.1/OIDC |
| MIK-6553 (Unmanaged Discovery) | Build | No standard MCP discovery protocol exists |
| MIK-6554 (Runtime Isolation) | Build+Integrate | Build sandbox orchestration; integrate OCI/gVisor/Apple VM |
| MIK-6555 (TrustCard/CBOM) | Build+Integrate | Build TrustCard schema; integrate CycloneDX/SPDX/Sigstore |
| MIK-6556 (Catalog Evaluation) | Build | Gateway-specific policy evaluation |
| MIK-6557 (ControlPlaneUI) | Build | Gateway-specific governance UI |
| MIK-6558 (Context Integrity) | Build | Gateway-specific integrity verification |
| MIK-6559 (Kubernetes HA) | Build+Integrate | Build operator; integrate Kubernetes primitives |
| MIK-6560 (Protocol Imports) | Build+Integrate | Build import pipeline; integrate OpenAPI/GraphQL/Postman/OCI |
| MIK-6561 (Adaptive Ranking) | Build | Gateway-specific ranking engine |
| MIK-6562 (Shadow Detection) | Build | Gateway-specific conflict detection |
