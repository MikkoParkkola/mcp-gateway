# MIK-6550 Trust Fabric Public Execution Plan

This public plan describes the implementation surface for MIK-6550 and its
child tickets. It is limited to user outcomes, license tier, integration
choices, dependency order, target areas, and verification plans that are safe
for the public repository.

Non-public planning notes and deployment-specific commercial detail belong
outside tracked public documentation.

## Public Boundaries

- Public docs may describe product behavior, supported deployment surfaces,
  public licenses, and public competitor fit.
- Tracked public docs must not include non-public planning notes or deployment
  specific commercial detail.
- The repository hygiene check enforces ignored internal-doc paths before CI.

## Dependency Order

1. MIK-6551 keeps public documentation clean before product-facing claims grow.
2. MIK-6552 gives operators one install and first-use path before fleet work.
3. MIK-6553 provides identity grants before TrustCard ownership evidence.
4. MIK-6556 TrustCard and CBOM metadata unblock MIK-6557 TrustLab evaluation.
5. MIK-6555 RuntimeProvider isolation strengthens MIK-6557 active evaluation
   and MIK-6560 Kubernetes execution evidence.
6. MIK-6558 ControlPlaneUI depends on identity grants plus catalog, runtime,
   and governance evidence.
7. MIK-6561 ProtocolImports feed MIK-6557 TrustLab and MIK-6562 ranking.
8. MIK-6562 AdaptiveRanking consumes catalog and protocol evidence, while
   local ranking must not require enterprise analytics.

Prior identity-ticket disposition: MIK-6207 caller identity propagation is
reused; MIK-6208 per-user vault precedent is reused; MIK-6209 personal versus
public gating is superseded by the IdentityGrantStore path. No second grant or
ownership model should be introduced.

## Architecture Decisions (updated 2026-07-01)

Implementation surfaced existing primitives and demand questions that revise the
enterprise scope. See the ADRs for full rationale:

- **ADR-004 — Kubernetes: Helm chart over bespoke operator.** The enterprise K8s
  need (templated deploy + upgrade + rollback) is met by a Helm chart; MIK-6679
  already proves apply/upgrade/rollback on a real cluster. The custom operator
  (kube-runtime reconcile loop, HA, admission webhook) is **deferred to a demand
  signal** rather than built on spec.
- **ADR-005 — Control-plane persistence: reuse, no Postgres.** The gateway has
  no database; a tamper-evident hash-chain audit log already exists
  (`TransparencyLogger`). Audit/SIEM reuse it; config stays file-based behind a
  `ControlPlaneStore` trait; a server-backed durable store is demand-gated and,
  if built, uses SurrealDB (portfolio-consistent), not Postgres.
- **ADR-006 — Reuse-first gate.** Every remaining ticket answers "does this need
  to exist / what existing primitive covers it" before implementation; failing
  the demand test moves a ticket to Blocked with a written gate condition.

## Child Rows

## MIK-6551: Public Repo Hygiene

- User outcome: Public users see clean product docs while internal docs remain
  outside the public index.
- Contribution class: Security hygiene and documentation governance.
- License tier: Free/core.
- Build vs integrate: Build - use gitignore, local scripts, and CI checks.
- Dependencies: Blocks all public docs that might expose internal material.
- Target areas: .gitignore, scripts/dev/check-public-repo-hygiene.sh,
  tests/public_repo_hygiene.sh, README, and maintainer docs.
- Threat model: Accidental publication of non-public planning or deployment
  specific material.
- Rollback: Revert the hygiene script or narrow blocked markers if false
  positives block public docs.
- Risks: False positives on valid public comparison docs; false negatives for
  novel wording.
- Fail-fast checks: Hygiene script must name the violating path and pass safe
  public comparison fixtures.
- Acceptance criteria: MIK-6551.HYGIENE.1 ignored internal-doc paths are
  enforced and no tracked file remains under them.
- Implementation plan: Keep path checks fail-closed and content checks focused
  on high-confidence markers.
- Test plan: Run the hygiene shell fixture plus the MIK-6550 roadmap test.

## MIK-6552: Install and First-Use UX

- User outcome: A new local operator installs, configures, serves, and checks a
  gateway with minimal manual work.
- Contribution class: Product UX, packaging, and deployment ergonomics.
- License tier: Free/core for local install and service templates; Enterprise
  for fleet bootstrap and managed enrollment.
- Build vs integrate: Build+Integrate - build gateway-specific init, doctor,
  backup, and client export; integrate Homebrew, Docker, systemd, and launchd.
- Dependencies: Depends on MIK-6551. Feeds MIK-6555, MIK-6558, and MIK-6560.
- Target areas: README, docs/QUICKSTART.md, smoke scripts, service templates,
  setup wizard, config export, and doctor commands.
- Threat model: Unsafe config mutation, protected value exposure, port
  conflicts, and broken first-run state.
- Rollback: Leave imports dry-run first and back up files before writes.
- Risks: Overwriting user config; install docs drifting from actual commands.
- Fail-fast checks: First-use smoke must run in CI and prove setup-to-health.
- Acceptance criteria: MIK-6552.INSTALL.1 init creates a minimal runnable config
  and MIK-6552.INSTALL.4 proves first-use smoke.
- Implementation plan: Keep the local profile small, validate before writing,
  and expose JSON doctor output.
- Test plan: Run first-run smoke, usability smoke, service-template smoke, and
  public-claims checks.

## MIK-6553: Identity Grants

- User outcome: Personal tools only run for the subject and agent that hold a
  valid grant.
- Contribution class: Security and identity platform.
- License tier: Free/core for local grant files and dispatch enforcement;
  Enterprise for SSO, group sync, delegated approvals, and durable storage.
- Build vs integrate: Build+Integrate - build the grant model and evaluator;
  integrate OIDC, trusted edge headers, mTLS, and external IdPs.
- Dependencies: Uses MIK-6207 and MIK-6208; supersedes MIK-6209. Feeds
  MIK-6556, MIK-6558, and MIK-6559.
- Target areas: src/identity_grants.rs, src/gateway/server/mod.rs,
  src/commands/identity.rs, docs/identity_grants.md, and tests.
- Threat model: Cross-user access, spoofed caller identity, expired grants, and
  unowned personal capability execution.
- Rollback: Disable grant enforcement for shared or public capabilities and
  keep personal exposure opt-in.
- Risks: Breaking single-user setups; trusting headers outside a trusted edge.
- Fail-fast checks: Personal capability without caller, owner, or live grant
  must deny before upstream execution.
- Acceptance criteria: MIK-6553.IDENTITY.2 personal capabilities fail closed
  unless identity, owner evidence, and grant match.
- Implementation plan: Load a local grant file, evaluate before dispatch, and
  emit audit events for allow and deny.
- Test plan: Unit and integration tests cover allow, deny, expiry, revocation,
  missing identity, and cross-user access.

## MIK-6554: ShadowRadar

- User outcome: Operators can see unmanaged MCP servers before they become
  policy and audit blind spots.
- Contribution class: Discovery, governance, and risk inventory.
- License tier: Free/core for local passive discovery; Enterprise for fleet
  range scans, scheduled inventory, and SIEM export.
- Build vs integrate: Build+Integrate - build MCP-aware comparison and risk
  evidence; integrate OS process and network inventory where useful.
- Dependencies: Benefits from MIK-6552 and feeds MIK-6558.
- Target areas: src/discovery/shadow.rs, doctor shadow commands,
  docs/REMOTE_BACKENDS.md, and control-plane projections.
- Threat model: Unmanaged servers with unknown tools, unknown owners, or
  untracked auth material.
- Rollback: Disable discovery reporting while leaving gateway routing intact.
- Risks: Misclassifying legitimate local dev servers; collecting too much
  inventory detail.
- Fail-fast checks: Free/core discovery must remain passive and local.
- Acceptance criteria: MIK-6554.SHADOW.1 local inventory reports unmanaged
  assets and MIK-6554.SHADOW.5 preserves enterprise boundaries.
- Implementation plan: Compare configured backends to discovered local assets,
  emit risk summaries, and keep mutation out of discovery.
- Test plan: Discovery tests cover managed, unmanaged, unavailable, and
  enterprise-boundary output.

## MIK-6555: RuntimeProvider

- User outcome: MCP servers launch with explicit isolation, lifecycle, policy,
  and audit evidence instead of ambient privileges.
- Contribution class: Runtime security and infrastructure.
- License tier: Free/core for local process, Docker, and Podman planning;
  Enterprise for Kubernetes, tenant placement, and fleet policy.
- Build vs integrate: Build+Integrate - build provider policy mapping; integrate
  Docker, Podman, systemd, and Kubernetes primitives.
- Dependencies: Depends on MIK-6552. Feeds MIK-6557 and MIK-6560.
- Target areas: src/runtime/provider.rs, src/runtime/provider/planner.rs,
  runtime config, docs/runtime/provider_planner.md, and runtime tests.
- Threat model: Host mounts, unrestricted egress, leaked environment values,
  privileged execution, and lifecycle drift.
- Rollback: Default to local_process compatibility while keeping policy reports.
- Risks: Container command drift across runtimes; disrupting existing stdio
  launches.
- Fail-fast checks: Denied policy gates must stop before a runner executes.
- Acceptance criteria: MIK-6555.RUNTIME.3 Docker or Podman can start a fixture
  with restricted defaults and MIK-6555.RUNTIME.5 audit omits protected values.
- Implementation plan: Keep one canonical policy model and provider-specific
  command adapters.
- Test plan: Run runtime provider unit tests and the live Docker smoke on a
  Docker-enabled host.

## MIK-6556: TrustCard and CBOM

- User outcome: Tools carry reviewable trust and provenance metadata that
  downstream policy, catalog, and ranking can consume.
- Contribution class: Supply-chain trust metadata.
- License tier: Free/core for local TrustCard and CBOM generation; Enterprise
  for signed fleet evidence and policy overlays.
- Build vs integrate: Build+Integrate - build MCP-specific projection and
  validation; integrate CycloneDX, SPDX, and Sigstore-style conventions.
- Dependencies: Depends on MIK-6553 for ownership evidence. Feeds MIK-6557,
  MIK-6558, and MIK-6562.
- Target areas: src/trust, TrustCard CLI, tool-list projection,
  docs/trustcard.md, and related tests.
- Threat model: Unknown provenance, mutable tool schemas, stale metadata, and
  unsupported trust claims.
- Rollback: Remove additive TrustCard projection while keeping existing tool
  responses unchanged.
- Risks: Metadata drift; treating unsigned local evidence as stronger than it
  is.
- Fail-fast checks: Trust metadata must be additive and digest-only at response
  boundaries.
- Acceptance criteria: MIK-6556.TRUST.1 TrustCard schema covers server, tools,
  provenance, runtime, policy, and evidence.
- Implementation plan: Generate, inspect, validate, and project TrustCard data
  without changing the MCP Tool shape.
- Test plan: TrustCard unit tests, CLI parser tests, and tool-list projection
  tests.

## MIK-6557: CatalogTrustLab

- User outcome: Operators can evaluate candidate MCP servers before enabling
  them.
- Contribution class: Evaluation infrastructure and supply-chain governance.
- License tier: Free/core for local one-shot evals; Enterprise for continuous
  schedules, scorecards, approvals, and evidence export.
- Build vs integrate: Build+Integrate - build MCP scoring and policy verdicts;
  integrate scanners, TrustCard, RuntimeProvider, and signature checks.
- Dependencies: Depends on MIK-6555 and MIK-6556. Feeds MIK-6558 and
  MIK-6562.
- Target areas: src/trust/lab.rs, TrustLab CLI, docs/catalog_trust_lab.md,
  baseline registry files, and tests.
- Threat model: Tool poisoning, schema drift, broad permissions, missing
  metadata, and unsafe active fixture calls.
- Rollback: Keep v0 advisory until enough validation data exists.
- Risks: False confidence from a score; unsafe fixture execution.
- Fail-fast checks: Active fixtures require declared safe status and isolated
  runtime evidence.
- Acceptance criteria: MIK-6557.TRUSTLAB.3 active eval invokes only safe
  fixtures in isolated runtime evidence.
- Implementation plan: Produce versioned evaluation records, remediation plans,
  baseline diffs, and policy verdicts.
- Test plan: Fixture tests for benign, missing metadata, tool poisoning, schema
  drift, and overbroad permissions.

## MIK-6558: ControlPlaneUI

- User outcome: Operators can inspect governance, grants, catalog, runtime, and
  audit evidence from a focused control-plane surface.
- Contribution class: Enterprise governance product with free read-only status.
- License tier: Free/core for read-only local status; Enterprise for mutation,
  RBAC, approvals, durable storage, and SIEM export.
- Build vs integrate: Build+Integrate - build MCP domain model and local UI;
  integrate OIDC and reuse the transparency-log engine for audit/SIEM in
  enterprise mode. Persistence is file-based behind a `ControlPlaneStore` trait;
  a server-backed durable store is demand-gated and uses SurrealDB, not Postgres
  (see ADR-005).
- Dependencies: Depends on MIK-6553 and MIK-6556. Benefits from MIK-6554 and
  MIK-6557.
- Target areas: src/control_plane, src/gateway/ui/control_plane.rs, embedded
  UI assets, docs/control_plane.md, and web UI tests.
- Threat model: Unauthorized mutation, overbroad audit exposure, stale risk
  state, and leaking protected values.
- Rollback: Keep the first surface read-only and disable enterprise mutation
  workflows.
- Risks: UI scope growth; mixing read-only free status with enterprise control.
- Fail-fast checks: Auditor and local read-only flows must not mutate state.
- Acceptance criteria: MIK-6558.CONTROL.2 read-only inventory and evidence views
  work before mutation workflows.
- Implementation plan: Project existing domain evidence into a stable API and
  UI tab, then gate mutation workflows separately.
- Test plan: API contract tests, UI rendering tests, and RBAC or mutation
  negative tests when mutation is added.

## MIK-6559: ContextIntegrityKernel

- User outcome: Tool results are classified, policy-checked, and tagged before
  they reach privileged agent context.
- Contribution class: Security boundary and response governance.
- License tier: Free/core for local monitor/enforce policies; Enterprise for
  custom organization policies, DLP, and SIEM export.
- Build vs integrate: Build+Integrate - build the kernel and policy actions;
  integrate existing response inspection, scanner, and provenance modules.
- Dependencies: Benefits from MIK-6553, MIK-6556, and MIK-6562.
- Target areas: src/security/context_integrity.rs,
  src/gateway/meta_mcp/invoke.rs, security config, docs, and security tests.
- Threat model: Indirect prompt injection, sensitive output exposure,
  destructive returned instructions, and self-granted access claims.
- Rollback: Default to monitor-only and keep enforcement opt-in per preset.
- Risks: False positives; cached response bypass; breaking benign payloads.
- Fail-fast checks: High-risk fixtures must classify and enforce before cache
  or final return.
- Acceptance criteria: MIK-6559.AC.1 non-protocol-error tool results carry
  context-integrity metadata without replacing normal content.
- Implementation plan: Attach metadata, policy actions, audit evidence, and
  config presets in the post-dispatch path.
- Test plan: Security tests cover classifier categories, monitor mode, enforce
  mode, cache behavior, and policy actions.

## MIK-6560: Kubernetes Enterprise Alpha

- User outcome: Enterprise teams can run mcp-gateway in Kubernetes with safe
  preflight, rollout, rollback, and evidence.
- Contribution class: Enterprise deployment and infrastructure.
- License tier: Enterprise for HA and fleet policy; Free/core keeps Docker
  Compose and single-node services.
- Build vs integrate: Ship a **Helm chart** as the deployment surface (templated
  deploy + upgrade + rollback; MIK-6679 proves rollback on a real cluster). The
  bespoke operator (kube-runtime reconcile loop, HA, admission webhook) is
  **deferred to a demand signal** — see ADR-004. CRDs remain as typed config.
- Dependencies: Depends on MIK-6552 and MIK-6555. Benefits from MIK-6558.
- Target areas: deploy/kubernetes/enterprise-alpha, src/kubernetes,
  docs/DEPLOYMENT.md, and Kubernetes manifest tests.
- Threat model: Unsafe rollout, weak RBAC, unmanaged network egress, copied
  protected values, and drift overwrite.
- Rollback: Keep dry-run and plan-first flow; use prior resource revision or
  rollout undo only after approval.
- Risks: Cluster variance; CRD scope growth; alpha controller drift.
- Fail-fast checks: Kind or equivalent smoke must install, verify, and roll
  back before full close.
- Acceptance criteria: MIK-6560.K8S.4 upgrade and rollback paths are tested in
  a local cluster fixture.
- Implementation plan: Keep enterprise-alpha manifests, reconcile planning,
  gated execution, evidence export, and controller loops versioned.
- Test plan: Manifest tests, CLI plan/apply tests, kind smoke, and redaction
  checks.

## MIK-6561: ProtocolImports

- User outcome: Developers can turn existing API descriptions into disabled,
  reviewable MCP capability drafts.
- Contribution class: Interoperability and ecosystem growth.
- License tier: Free/core for local OpenAPI, GraphQL, and Postman imports;
  Enterprise for private registry sync, approvals, signed catalog import, and
  bulk migration.
- Build vs integrate: Build+Integrate - build MCP capability generation and
  safety mapping; integrate OpenAPI, GraphQL, Postman, OCI, and JSON Schema
  standards.
- Dependencies: Depends on MIK-6556. Feeds MIK-6557 and MIK-6562.
- Target areas: src/protocol_imports, src/commands/protocol_import.rs,
  docs/OPENAPI_IMPORT.md, and importer tests.
- Threat model: Generated destructive tools, unbounded GraphQL queries,
  ambiguous auth, and unsafe defaults.
- Rollback: Generated outputs stay disabled drafts until reviewed.
- Risks: Over-generating broad tools; non-deterministic output.
- Fail-fast checks: Destructive and open-world generated tools must stay
  disabled until human review.
- Acceptance criteria: MIK-6561.IMPORT.3 GraphQL import enforces depth,
  complexity, and mutation review gates.
- Implementation plan: Normalize source specs into CapabilityDraft, write draft
  files, manifests, rollback handles, and TrustCard stubs.
- Test plan: Golden fixtures for OpenAPI, GraphQL, Postman, safety classes,
  and deterministic output.

## MIK-6562: AdaptiveRanking

- User outcome: Agents get safer, cheaper, and more relevant tool suggestions
  with deterministic explanations.
- Contribution class: Routing intelligence and quality optimization.
- License tier: Free/core for deterministic local ranking and no-payload
  telemetry; Enterprise for org-wide learning, dashboards, A/B tests, and
  policy analytics.
- Build vs integrate: Build+Integrate - build gateway scoring and explanations;
  integrate vector search or metrics libraries only when they show measurable
  lift.
- Dependencies: Depends on MIK-6556 and benefits from MIK-6557, MIK-6559, and
  MIK-6561.
- Target areas: src/ranking, src/commands/ranking.rs,
  docs/adaptive_ranking.md, and ranking tests.
- Threat model: Unsafe suggestions, hidden policy violations, sensitive
  telemetry, and unexplained ranking drift.
- Rollback: Default to deterministic ranking and expose debug explanations.
- Risks: Filtering valid tools; learning from sensitive payloads.
- Fail-fast checks: Unauthorized or high-risk tools are filtered before ranking
  output.
- Acceptance criteria: MIK-6562.RANK.2 deterministic ranker produces
  explainable output for every suggested tool.
- Implementation plan: Define feature schema, score weights, filters,
  explanations, offline eval, and feedback aggregation.
- Test plan: Feature extraction, policy filters, golden ranking fixtures,
  offline evaluation, and privacy tests.

## Public Competitor Comparison

The simple public comparison table lives in README.md under "Public MCP Gateway
Comparison". It links to public sources for Docker MCP Gateway / Toolkit,
MCPJungle, mcpo, and Supergateway and compares user-facing behavior only. Keep
non-public evaluations outside tracked public docs.
