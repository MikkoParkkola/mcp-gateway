# mcp-gateway Kubernetes Enterprise Alpha

This package is the first Kubernetes deployment contract for enterprise
mcp-gateway installations. It is intentionally manifest-first: operators can
review, dry-run, and validate the resources before any controller loop exists.

The operator/controller remains future work. This package defines the CRD
shape, Helm-style values, least-privilege base resources, and local validation
tests that an operator implementation must preserve.

## License Boundary

Free/core keeps Docker, Docker Compose, and single-node service templates.
This Kubernetes package is enterprise scope because it covers HA, cluster
policy reconciliation, managed rollout, multi-tenant namespace patterns, and
fleet evidence export.

## Workflow Contract

1. `preflight`: verify kubectl access, namespace ownership, storage class,
   ingress class, cert manager if TLS automation is requested, network policy
   support, Prometheus/OTel endpoints, and RBAC permissions.
2. `plan`: render CRDs and workload resources, show risk, affected resources,
   policy diff, health checks, evidence endpoints, and rollback handles.
3. `apply`: use server-side dry-run first, then apply only after human approval
   for namespace, ingress domain, protected value provider, tenancy, and policy
   exceptions.
4. `verify`: wait for status conditions, probes, service endpoints, policy
   convergence, and gateway health.
5. `explain`: show why every generated resource exists and which acceptance
   criterion it supports.
6. `rollback`: use the previous release revision or previous custom resource
   generation, and require confirmation for destructive namespace changes.

## Included Files

- `crds/*.yaml`: Gateway, MCPServer, Policy, RuntimeProfile, and TrustCard
  reference schemas.
- `base/*.yaml`: service account, RBAC, network policy, service, deployment,
  and example custom resource.
- `values.enterprise.example.yaml`: Helm-style values used by the planner.
- `scripts/preflight.sh`: read-only preflight checks for local clusters.

## Human Gates

Automation should infer everything else. Humans choose only:

- Namespace.
- Ingress domain.
- Protected value provider.
- Tenancy model.
- Explicit policy exceptions.
- Destructive rollback approval.

## Current Gaps

- No controller reconcile loop yet.
- No kind cluster fixture in this slice.
- No live server-side dry-run wrapper yet.
- No external evidence export adapter yet.
