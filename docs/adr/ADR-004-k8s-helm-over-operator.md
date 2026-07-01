# ADR-004: Kubernetes deployment via Helm chart; bespoke operator deferred to demand

**Date**: 2026-07-01
**Status**: Accepted
**Deciders**: Mikko Parkkola
**References**: MIK-6560, MIK-6672 (GA epic), MIK-6679 (kind rollback CI), ADR-002

---

## Context

The enterprise Kubernetes track (MIK-6672) was scoped as a full custom operator:
a `kube-runtime` reconcile loop (MIK-6680), HA leader election (MIK-6681),
status subresource management (MIK-6682), and a validating admission webhook
(MIK-6683). The `enterprise-alpha` package already ships CRDs
(`gateways`, `mcpservers`, `policies`, `runtimeprofiles`, `trustcardreferences`)
plus base manifests, and MIK-6679 added a CI job that proves apply → upgrade →
rollback works on a real `kind` (Kubernetes-in-Docker) cluster.

The stated enterprise need is: **templated, versioned, safe deploy + upgrade +
rollback**. A custom operator delivers that need's *reconciliation* extra —
continuous drift-correction of the custom resources — at the cost of the
heaviest dependency tree in the Rust Kubernetes ecosystem (`kube`,
`kube-runtime`, `k8s-openapi`), plus HA, an admission webhook, and permanent
maintenance. mcp-gateway's value proposition is a compact Meta-MCP tool router
with a strong security posture; it is not a Kubernetes operator.

## Decision

**Ship a Helm chart as the enterprise Kubernetes deployment surface. Defer the
bespoke operator until a customer demand signal requires CRD-driven
reconciliation.**

- Helm natively provides templating, release versioning, `helm upgrade`, and
  `helm rollback` — the entire stated need. MIK-6679 already proves the rollout
  and rollback mechanics on a real cluster.
- The operator adds only continuous reconciliation/drift-correction of the
  custom resources. That is speculative value for an alpha feature with no user
  currently requesting it, so it is not built on spec.
- The CRDs remain in the repo as typed configuration; they are not reconciled by
  an in-cluster controller until the operator is built.

### CRD contract risk (adversarial-review mitigation, GPT-5.5 2026-07-01)

Shipping CRDs with no controller risks a *fake enterprise contract*: users may
treat the CRDs as a reconciled source-of-truth when there is no reconciliation,
status truth, or admission-time guardrail yet. Mitigation:

- The **Helm values file is the supported deployment contract.** The CRDs are
  explicitly `v1alpha1` and are documented as experimental / not-a-stable-API
  until the operator ships — no compatibility guarantee across versions.
- Prefer plain Kubernetes resources (Deployment/Service/ConfigMap via the chart)
  as the primary interface; the CRDs are opt-in and clearly labelled alpha.
- Do not grow CRD surface while the operator is deferred — every new CRD field
  without reconciliation deepens the compatibility debt.
- MIK-6684 (image digest pinning, least-privilege RBAC split, cosign
  verification) is real supply-chain hardening independent of the operator and
  folds into the Helm chart.

### Demand-gate (when to build the operator)

Build MIK-6680–6683 only when at least one of these is true, and record which:
- a customer contractually requires CRD-driven reconciliation / GitOps
  drift-correction of gateway resources, or
- fleet operation across many clusters makes manual `helm upgrade` per cluster
  the actual bottleneck, or
- the CRDs need server-side admission validation that a chart cannot express.

## Consequences

- Positive: weeks of Spark-bound build collapse into a days-long Mac-buildable
  Helm chart; zero new heavy dependencies; scope matches the product.
- Positive: the chart serves non-enterprise single-cluster users too.
- Negative: no automatic drift-correction of custom resources until the operator
  ships. Acceptable — `helm upgrade` is the reconciliation trigger in the
  interim, and there is no user depending on continuous reconciliation.
- Reversible: the CRDs and the alpha planner code remain; the operator can be
  added later behind the demand-gate without rework of the chart.
