# MIK-6550 Trust Fabric Roadmap

Public roadmap for the mcp-gateway trust-fabric initiative. This page decomposes
the trust-fabric epic into implementation-ready child issues with canonical
Definition-of-Ready fields for each.

---

## MIK-6551: Single Install Path

**User Outcome:** Operators can install mcp-gateway with a single command that
configures defaults appropriate for their environment (local dev, CI, production).

**Contribution Class:** Code/docs — install UX and configuration bootstrap.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build
**Rationale:** Install UX is gateway-specific configuration logic; no standard
tool exists for mcp-gateway's configuration model.

**Dependencies:** None (foundation).

**Target Code/Docs Areas:** `src/install.rs`, `docs/QUICKSTART.md`,
`gateway.example.yaml`, `scripts/install.sh`.

**Threat Model:** Supply-chain risk in install scripts (curl-pipe-sh pattern).
Mitigate with checksum verification and signed releases.

**Rollback:** Install path is idempotent; rollback is re-install of prior version.

**Risks:** Platform-specific edge cases (Windows path separators, NixOS).

**Fail-Fast Checks:** Install script exits non-zero when required binaries
(curl, tar) are missing. Config validation runs before gateway starts.

**Stable Acceptance Criteria:**
1. `mcp-gateway install` produces a working config on Linux, macOS, and Windows.
2. Install detects existing config and prompts before overwrite.
3. Checksum verification on downloaded release artifacts.

**Implementation Plan:** Add `install` CLI subcommand; create platform-specific
config templates; wire checksum verification into release pipeline.

**Test Plan:** Integration test running install in a tempdir; assert config file
exists and passes validation; assert checksum mismatch aborts.

---

## MIK-6552: Per-User/Per-Agent Identity Grants

**User Outcome:** Each user and agent authenticating to mcp-gateway receives a
scoped identity grant that determines tool access, with OAuth 2.1/OIDC/PKCE as
the underlying protocol.

**Contribution Class:** Code — identity grant engine and protocol integration.

**License Tier:** Enterprise/commercial

**Build-vs-Integrate Decision:** Build+Integrate
**Rationale:** Integrate OAuth 2.1/OIDC/PKCE and protected resource metadata
(IETF standards); build the grant scope resolution and per-agent identity
binding that is gateway-specific policy.

**Dependencies:** MIK-6551 (install path provides configuration surface).
Prior ticket disposition: MIK-6207 superseded by MIK-6552;
MIK-6208 superseded by MIK-6552; MIK-6209 superseded by MIK-6552.

**Target Code/Docs Areas:** `src/identity/`, `src/auth/`,
`docs/OAUTH_CONFIG.md`, `crates/gateway-core/src/auth.rs`.

**Threat Model:** Token forgery, scope escalation, replay attacks. Mitigate
with PKCE binding, short-lived tokens, and audience validation.

**Rollback:** Identity grants layer is additive; disabling falls back to
single-token auth (existing behavior).

**Risks:** OIDC provider compatibility (Azure AD quirks, Keycloak version skew).

**Fail-Fast Checks:** Gateway refuses to start when identity config references
a non-existent OIDC issuer URL (validated at startup via discovery document fetch).

**Stable Acceptance Criteria:**
1. Per-user grants restrict tool access based on OAuth scopes.
2. Per-agent grants bind agent identity to a specific tool allow-list.
3. PKCE flow works end-to-end with a standards-compliant OIDC provider.
4. Prior identity tickets are formally superseded.

**Implementation Plan:** Implement OAuth 2.1/OIDC discovery; add grant
resolution middleware; persist grants in a configurable store; add per-agent
binding API.

**Test Plan:** Integration test with mock OIDC provider; unit tests for grant
resolution logic; E2E test for PKCE flow.

---

## MIK-6553: Unmanaged MCP Discovery

**User Outcome:** Operators can discover unmanaged MCP servers running on the
local network, with shadow detection that flags servers not registered in the
gateway's catalog.

**Contribution Class:** Code — discovery engine and shadow detection.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build
**Rationale:** MCP discovery and shadow detection are gateway-specific
capabilities; no standard library exists for MCP server enumeration.

**Dependencies:** MIK-6551 (install path provides base configuration).

**Target Code/Docs Areas:** `src/discovery/`, `tests/discovery_tests.rs`,
`docs/COMMUNITY_REGISTRY.md`.

**Threat Model:** Rogue MCP server impersonation; network scanning abuse.
Mitigate with mTLS verification and rate-limited discovery probes.

**Rollback:** Discovery is an opt-in feature; disabling removes the capability
with no impact on existing gateway operation.

**Risks:** Network topology variations (VLANs, firewalls blocking mDNS).

**Fail-Fast Checks:** Discovery aborts when no network interface is available.
Probe timeout is enforced (default 5s).

**Stable Acceptance Criteria:**
1. `mcp-gateway discover` lists reachable MCP servers on the local network.
2. Shadow servers (unregistered) are flagged with a warning.
3. Discovery respects mTLS and refuses unauthenticated servers in strict mode.

**Implementation Plan:** Add `discover` CLI subcommand; implement mDNS/DNS-SD
probes; integrate with the catalog registry for cross-referencing.

**Test Plan:** Unit tests with mock discovery responses; integration test with
local MCP server fixture; assert shadow detection flags unknown servers.

---

## MIK-6555: TrustCard/CBOM Metadata

**User Outcome:** Each MCP backend publishes a TrustCard — a machine-readable
trust metadata document describing its capabilities, data access patterns,
security properties, and CBOM (Cryptography Bill of Materials).

**Contribution Class:** Code/docs — metadata schema and publishing pipeline.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build+Integrate
**Rationale:** Integrate CycloneDX/SPDX conventions for CBOM format; build the
TrustCard schema that extends these with MCP-specific trust fields.

**Dependencies:** MIK-6552 (identity grants define who can read TrustCards).

**Target Code/Docs Areas:** `src/trust/`, `docs/SECURITY_AUDIT.md`,
`capabilities/`.

**Threat Model:** TrustCard spoofing; metadata tampering. Mitigate with
Sigstore-style signing and TrustCard integrity checks at load time.

**Rollback:** TrustCards are optional metadata; absence falls back to current
capability-only discovery.

**Risks:** Schema evolution breaking older clients; migration path needed.

**Fail-Fast Checks:** Gateway rejects malformed TrustCards at config load time.
Unsigned TrustCards in strict mode produce a hard error.

**Stable Acceptance Criteria:**
1. Each backend publishes a TrustCard with capabilities, data access, and CBOM.
2. TrustCards are signed with Sigstore-compatible signatures.
3. CBOM follows CycloneDX format conventions.

**Implementation Plan:** Define TrustCard schema (JSON/YAML); implement signing
pipeline; add TrustCard publishing to backend registration; integrate CBOM
generation into build.

**Test Plan:** Unit tests for TrustCard schema validation; integration test for
sign/verify round-trip; assert CBOM structure against CycloneDX schema.

---

## MIK-6560: Protocol Imports

**User Outcome:** Operators can import MCP backend definitions from OpenAPI
specs, GraphQL introspection results, and Postman collections, converting them
to gateway-compatible backend configurations.

**Contribution Class:** Code — protocol import pipeline and converters.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Integrate
**Rationale:** OpenAPI, GraphQL introspection, and Postman collections are
established standards with mature parsers (openapi-rs, graphql-parser); the
gateway only needs to convert these formats to its backend config model.

**Dependencies:** MIK-6552 (identity grants define who can register imported
backends).

**Target Code/Docs Areas:** `src/import/`, `docs/OPENAPI_IMPORT.md`,
`tests/openapi_import_tests.rs`.

**Threat Model:** Malicious OpenAPI/GraphQL specs causing resource exhaustion
or injection. Mitigate with schema validation, size limits, and sandboxed
parsing.

**Rollback:** Import is a one-time conversion; reverting means deleting the
generated backend config.

**Risks:** Spec version compatibility (OpenAPI 3.0 vs 3.1 differences).

**Fail-Fast Checks:** Import rejects specs that fail validation. Large specs
(>10MB) require explicit opt-in. Circular references abort with error.

**Stable Acceptance Criteria:**
1. `mcp-gateway import openapi <spec>` generates backend config.
2. `mcp-gateway import graphql <endpoint>` generates backend config.
3. `mcp-gateway import postman <collection>` generates backend config.
4. Imported configs pass gateway validation.

**Implementation Plan:** Implement OpenAPI 3.x parser integration; add GraphQL
introspection client; add Postman collection v2.1 parser; wire output to
gateway backend config format.

**Test Plan:** Unit tests with fixture specs; integration test importing and
validating generated config; assert error on malformed specs.

---

## MIK-6554: Runtime Isolation (RuntimeProvider)

**User Outcome:** Each MCP backend runs in an isolated runtime context, preventing
cross-backend resource contention, data leakage, and privilege escalation.

**Contribution Class:** Code — runtime provider abstraction and isolation layer.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build+Integrate
**Rationale:** Integrate OCI container runtimes (gVisor, Firecracker, native
containers) for process isolation; build the RuntimeProvider abstraction that
maps gateway policy to runtime selection.

**Dependencies:** MIK-6555 (TrustCard/CBOM metadata informs isolation level).

**Target Code/Docs Areas:** `src/runtime/`, `crates/gateway-core/src/runtime/`,
`docs/runtime/`.

**Threat Model:** Container escape, shared-kernel vulnerabilities, resource
exhaustion across backends. Mitigate with gVisor sandboxing, cgroup limits,
and per-backend network namespaces.

**Rollback:** RuntimeProvider falls back to in-process execution (current
behavior) when isolation is not configured.

**Risks:** Container runtime availability varies by platform (no gVisor on macOS
native; Docker Desktop overhead).

**Fail-Fast Checks:** Gateway validates container runtime availability at
startup; aborts with clear error when configured provider is unavailable.

**Stable Acceptance Criteria:**
1. Each MCP backend runs in its own isolated context.
2. Resource limits (CPU, memory) are enforced per-backend.
3. Fallback to in-process execution when isolation is not configured.

**Implementation Plan:** Implement RuntimeProvider trait; add OCI descriptor
parsing; wire cgroup/namespace setup; add runtime selection to backend config.

**Test Plan:** Unit tests for RuntimeProvider trait impls; integration test
verifying process isolation; assert resource limits via cgroup inspection.

---

## MIK-6556: Continuous Catalog Evaluation

**User Outcome:** Operators receive continuous assessment of MCP server
catalog health, trustworthiness, and compliance status.

**Contribution Class:** Code — catalog evaluation engine.

**License Tier:** Enterprise/commercial

**Build-vs-Integrate Decision:** Build
**Rationale:** Catalog evaluation is gateway-specific policy logic; no standard
tool exists for MCP catalog health assessment.

**Dependencies:** MIK-6555 (TrustCard/CBOM metadata provides evaluation input).

**Target Code/Docs Areas:** `src/catalog/`, `src/evaluation/`,
`docs/COMMUNITY_REGISTRY.md`.

**Threat Model:** Stale catalog data masking compromised servers. Mitigate
with periodic re-evaluation and TrustCard freshness checks.

**Rollback:** Evaluation is advisory; disabling stops health reports without
affecting gateway routing.

**Risks:** Large catalogs causing evaluation overhead; need batching.

**Fail-Fast Checks:** Evaluation aborts when catalog is empty or unreachable.
Individual server evaluation failure does not block the batch.

**Stable Acceptance Criteria:**
1. Catalog evaluation runs on a configurable schedule.
2. Each server receives a health/trust score based on TrustCard metadata.
3. Results are exportable as JSON for external dashboards.

**Implementation Plan:** Implement evaluation engine with pluggable scoring;
add cron-based scheduling; expose evaluation API and CLI command.

**Test Plan:** Unit tests for scoring logic; integration test with mock catalog;
assert evaluation output schema.

---

## MIK-6558: Context Integrity

**User Outcome:** Operators can verify that MCP tool responses have not been
tampered with in transit and that context windows contain only authorized data
from trusted sources.

**Contribution Class:** Code — context integrity verification layer.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build
**Rationale:** Context integrity is gateway-specific policy enforcement;
existing integrity tools (hash chains, HMAC) are primitives, not solutions.

**Dependencies:** MIK-6554 (RuntimeProvider isolation provides the trust
boundary for integrity verification).

**Target Code/Docs Areas:** `src/integrity/`, `src/proxy/`,
`crates/gateway-core/src/proxy.rs`.

**Threat Model:** Response injection, context poisoning, man-in-the-middle on
backend connections. Mitigate with response signing, HMAC verification, and
source attribution on every tool response.

**Rollback:** Integrity checks are additive; disabling allows raw passthrough
(current behavior).

**Risks:** Performance overhead on high-throughput tool chains.

**Fail-Fast Checks:** Gateway rejects responses with invalid HMAC signatures
in strict mode. Integrity check failure produces a clear error, not silent
passthrough.

**Stable Acceptance Criteria:**
1. Every tool response carries a source attribution header.
2. Response HMAC verification rejects tampered responses.
3. Integrity failures are logged and optionally block the response.

**Implementation Plan:** Add response signing middleware; implement HMAC
generation and verification; add integrity failure policy configuration.

**Test Plan:** Unit tests for HMAC sign/verify; integration test with tampered
response injection; assert integrity failure logging.

---

## MIK-6557: Enterprise Governance UI (ControlPlane)

**User Outcome:** Enterprise administrators have a web-based control plane for
managing trust policies, viewing audit logs, and governing MCP server access
across the organization.

**Contribution Class:** Code — governance web application and policy engine.

**License Tier:** Enterprise/commercial

**Build-vs-Integrate Decision:** Build
**Rationale:** Governance UI and policy engine are gateway-specific; existing
policy engines can be integrated for evaluation but the UI and
policy model are custom.

**Dependencies:** MIK-6554 (RuntimeProvider isolation defines enforcement
points for governance policies).

**Target Code/Docs Areas:** `src/governance/`, `src/webui/`,
`docs/WEBUI_MANAGEMENT.md`.

**Threat Model:** Unauthorized policy changes; audit log tampering. Mitigate
with RBAC on the governance UI, immutable audit log, and policy change
approval workflows.

**Rollback:** Governance UI is an optional overlay; disabling reverts to
file-based policy configuration.

**Risks:** UI complexity growing beyond MVP scope.

**Fail-Fast Checks:** Governance UI refuses to start when backing store is
unreachable. Policy validation rejects malformed rules before persistence.

**Stable Acceptance Criteria:**
1. Web UI displays all registered MCP servers with trust scores.
2. Administrators can create/modify/delete trust policies.
3. Audit log records all policy changes with actor, timestamp, and diff.

**Implementation Plan:** Build governance API endpoints; implement policy CRUD
with validation; add audit log store; build React/web UI for policy management.

**Test Plan:** Unit tests for policy validation; integration tests for CRUD API;
assert audit log entries on policy changes.

---

## MIK-6559: Kubernetes HA/Operator

**User Outcome:** Operators can deploy mcp-gateway as a highly-available
Kubernetes workload with automatic failover, scaling, and policy
synchronization across replicas.

**Contribution Class:** Code — Kubernetes operator and HA coordination.

**License Tier:** Enterprise/commercial

**Build-vs-Integrate Decision:** Build+Integrate
**Rationale:** Integrate Kubernetes primitives (Deployments, Services,
ConfigMaps) for orchestration; build the mcp-gateway operator that manages
gateway-specific resources (trust policies, grant stores, audit logs).

**Dependencies:** MIK-6557 (ControlPlane governance defines the policy model
the operator must reconcile).

**Target Code/Docs Areas:** `packaging/k8s/`, `src/ha/`,
`docs/DEPLOYMENT.md`.

**Threat Model:** Split-brain policy divergence across replicas; etcd
compromise. Mitigate with leader election, policy reconciliation loop, and
encrypted policy store.

**Rollback:** Operator uninstall reverts to standalone gateway deployment.
HA coordination is optional; single-replica mode works without it.

**Risks:** Kubernetes version compatibility; CRD schema evolution.

**Fail-Fast Checks:** Operator validates CRD schema before applying.
Leader election failure halts reconciliation with clear error.

**Stable Acceptance Criteria:**
1. Kubernetes operator deploys mcp-gateway with a single CRD manifest.
2. Multi-replica deployment synchronizes trust policies across instances.
3. Automatic failover on primary replica failure within configurable timeout.

**Implementation Plan:** Implement Kubernetes operator using kube-rs; define
CRDs for gateway configuration; add leader election; implement policy
reconciliation controller.

**Test Plan:** Unit tests for CRD schema validation; integration test with
kind cluster; assert failover behavior under replica kill.

---

## MIK-6561: Adaptive Routing/Ranking

**User Outcome:** The gateway adaptively ranks and routes requests to MCP
backends based on latency, trust score, availability, and operator-defined
weights, optimizing for the best response quality.

**Contribution Class:** Code — adaptive routing engine and ranking algorithm.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build
**Rationale:** Adaptive routing is gateway-specific policy; the ranking
algorithm combines trust metadata, latency metrics, and operator preferences
in a way no generic load balancer supports.

**Dependencies:** MIK-6560 (protocol imports provide backend definitions for
routing; adaptive local ranking uses imported backend metadata).

**Target Code/Docs Areas:** `src/routing/`, `src/ranking/`,
`crates/gateway-core/src/proxy.rs`.

**Threat Model:** Routing manipulation via poisoned latency metrics; trust
score gaming. Mitigate with metric smoothing, trust score immutability from
backend perspective, and operator override.

**Rollback:** Adaptive routing falls back to round-robin (current behavior)
when disabled.

**Risks:** Cold-start ranking (no historical data for new backends).

**Fail-Fast Checks:** Routing aborts when no healthy backend is available for
a tool request. Ranking computation validates input metrics before use.

**Stable Acceptance Criteria:**
1. Requests route to highest-ranked healthy backend by default.
2. Ranking adapts based on latency, trust score, and availability.
3. Operator can override ranking with explicit weights.

**Implementation Plan:** Implement ranking algorithm; add latency tracking
per-backend; integrate TrustCard scores into ranking; add weight override
config; wire into proxy routing layer.

**Test Plan:** Unit tests for ranking computation; integration test with
simulated backends at different latencies; assert weight override behavior.

---

## MIK-6562: Release Trust Evidence

**User Outcome:** Each mcp-gateway release publishes machine-verifiable trust
evidence — signed build provenance, dependency audit results, and a
CBOM-aligned cryptographic inventory.

**Contribution Class:** Code/docs — release pipeline trust evidence generation.

**License Tier:** Free/core

**Build-vs-Integrate Decision:** Build+Integrate
**Rationale:** Integrate Sigstore/SLSA conventions for build provenance;
build the mcp-gateway-specific trust evidence bundle that combines provenance,
dependency audit, and CBOM into a single release artifact.

**Dependencies:** MIK-6555 (TrustCard/CBOM metadata schema defines the CBOM
format used in release evidence).

**Target Code/Docs Areas:** `.github/workflows/`, `scripts/`,
`docs/SECURITY_AUDIT.md`, `CHANGELOG.md`.

**Threat Model:** Supply-chain attacks on release artifacts; build system
compromise. Mitigate with SLSA Level 3 provenance, Sigstore signing, and
dependency audit in CI.

**Rollback:** Trust evidence is additive metadata; absence does not affect
gateway functionality, only trust verification.

**Risks:** Sigstore infrastructure availability; CI pipeline complexity.

**Fail-Fast Checks:** Release pipeline aborts when signing fails. Unsigned
releases are flagged in the release notes.

**Stable Acceptance Criteria:**
1. Each release includes SLSA provenance attestation.
2. Each release includes a signed CBOM in CycloneDX format.
3. Dependency audit (cargo audit / trivy) runs in CI and results are published.

**Implementation Plan:** Add SLSA provenance generation to release workflow;
integrate Sigstore signing; add CBOM generation to build; wire dependency
audit into CI pipeline.

**Test Plan:** Assert provenance attestation structure; verify Sigstore
signature round-trip; assert CBOM schema compliance.

---

## Dependency Graph

The following dependency ordering governs implementation sequencing across the
trust-fabric child issues:

```
Install path (foundation)
├── Identity grants ── links prior tickets
│   ├── TrustCard/CBOM metadata
│   │   ├── RuntimeProvider isolation
│   │   │   ├── ControlPlaneUI governance
│   │   │   │   └── Kubernetes HA
│   │   │   └── Context integrity
│   │   ├── Catalog evaluation
│   │   └── Release trust evidence
│   └── ProtocolImports
│       └── AdaptiveRanking
└── Unmanaged MCP discovery
```

Implementation ordering:
- Identity grants must complete before TrustCard/CBOM metadata,
  ProtocolImports, and subsequent downstream work.
- TrustCard/CBOM metadata must complete before RuntimeProvider
  isolation, Catalog evaluation, and Release trust evidence.
- RuntimeProvider isolation must complete before ControlPlaneUI
  governance and Context integrity.
- ControlPlaneUI governance must complete before Kubernetes HA.
- ProtocolImports must complete before AdaptiveRanking.
- ProtocolImports depends on identity grants for
  imported backend registration authorization.

Prior identity tickets disposition:
- MIK-6207: superseded by identity grants (per-user/per-agent identity grants)
- MIK-6208: superseded by identity grants (OAuth 2.1/OIDC/PKCE integration scope absorbed)
- MIK-6209: superseded by identity grants (protected resource metadata absorbed into identity grants)

No duplicate identity implementation may begin until MIK-6207, MIK-6208, and
MIK-6209 are formally closed with the above disposition.
