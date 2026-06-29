# mcp-gateway Kubernetes Enterprise Alpha

This package is the first Kubernetes deployment contract for enterprise
mcp-gateway installations. Operators can review, plan, dry-run, and validate
the resources before a long-running controller manager is deployed.

The shipped controller surface is a deterministic reconcile planner:
`mcp-gateway kubernetes plan <resources.yaml>` parses reviewed custom
resources, resolves references, emits status conditions, lists reconcile
actions, and provides server-side dry-run plus rollback handles. A future
controller manager must preserve this contract.

## License Boundary

Free/core keeps Docker, Docker Compose, and single-node service templates.
This Kubernetes package is enterprise scope because it covers HA, cluster
policy reconciliation, managed rollout, multi-tenant namespace patterns, and
fleet evidence export.

## Workflow Contract

1. `preflight`: verify kubectl access, namespace ownership, storage class,
   ingress class, cert manager if TLS automation is requested, network policy
   support, Prometheus/OTel endpoints, and RBAC permissions.
2. `plan`: run `mcp-gateway kubernetes plan base/example-gateway.yaml` to
   render reconcile actions, reference checks, status conditions, dry-run
   command, and rollback handles.
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
- `scripts/server-dry-run.sh`: non-mutating API-server validation wrapper.
- `scripts/kind-smoke.sh`: disposable kind cluster fixture for local smoke
  validation.

## Human Gates

Automation should infer everything else. Humans choose only:

- Namespace.
- Ingress domain.
- Protected value provider.
- Tenancy model.
- Explicit policy exceptions.
- Destructive rollback approval.

## Reconcile Plan

```bash
mcp-gateway kubernetes plan \
  deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml \
  --namespace mcp-gateway \
  --format table
```

The command is local and non-mutating. It returns a blocked plan when required
references such as `runtimeProfileRef`, `policyRef`, or `trustCardRef` do not
resolve within the supplied custom-resource document stream.

## Server-Side Dry-Run

```bash
deploy/kubernetes/enterprise-alpha/scripts/server-dry-run.sh mcp-gateway
```

The wrapper runs preflight first and uses `kubectl apply --server-side
--dry-run=server`. It does not mutate cluster state.

## Kind Fixture

```bash
deploy/kubernetes/enterprise-alpha/scripts/kind-smoke.sh
```

The fixture creates a disposable kind cluster, installs the CRDs in that
cluster, and runs the server-side dry-run wrapper. Set
`MCP_GATEWAY_KIND_KEEP=1` to keep the cluster for inspection.

## Current Gaps

- No long-running controller manager yet; the current controller contract is
  the deterministic reconcile plan.
- No external evidence export adapter yet.
