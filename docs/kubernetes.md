# Kubernetes Deployment Guide

<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
<!-- Enterprise Edition — mcp-gateway Kubernetes deployment documentation -->

## Overview

The **Enterprise Edition** Kubernetes deployment package provides a Helm chart,
CRDs, and an operator for running mcp-gateway in Kubernetes with high
availability, governance policies, and secret management.

> **Free/core users**: Use [Docker Compose](DEPLOYMENT.md#docker-compose) for
> single-node deployments. The Kubernetes operator and Helm chart are Enterprise
> Edition features licensed under PolyForm Noncommercial 1.0.0.

## Enterprise Edition Scope

The following components are **Enterprise Edition** (PolyForm Noncommercial):

- Helm chart (`charts/mcp-gateway/`)
- CRDs: `Gateway`, `MCPServer`, `Policy`, `TrustCardReference`, `RuntimeProfile`
- Operator reconcile controller (`crates/mcp-gateway-operator/`)
- Kind integration scripts (`tests/k8s/`)

The core gateway binary and Docker Compose deployment remain MIT-licensed.

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Kubernetes | 1.28+ |
| Helm | 3.12+ |
| kubectl | 1.28+ |

For local development: [Kind](https://kind.sigs.k8s.io/) 0.20+.

## Quick Start

### 1. Install CRDs

```bash
kubectl apply -f charts/mcp-gateway/crds/
```

### 2. Create Secrets

Secrets are referenced via `secretKeyRef` — never stored in ConfigMaps, logs,
status fields, or Helm NOTES.

```bash
kubectl create secret generic gateway-api-creds \
  --from-literal=api-key='your-key-here' \
  --from-literal=token='your-token-here'
```

For ExternalSecret integration with [external-secrets.io](https://external-secrets.io/):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: gateway-api-creds
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: gateway-api-creds
  data:
    - secretKey: api-key
      remoteRef:
        key: secret/data/mcp-gateway
        property: api-key
```

### 3. Deploy with Helm

```bash
helm install mcp-gateway charts/mcp-gateway \
  --namespace mcp-gateway --create-namespace \
  --set replicaCount=2 \
  --set networkPolicy.enabled=true \
  --set metrics.enabled=true
```

## Custom Resources

### Gateway

The primary resource. Defines replicas, image, config, and secret references.

```yaml
apiVersion: mcp-gateway.io/v1alpha1
kind: Gateway
metadata:
  name: production
spec:
  replicaCount: 3
  secretRefs:
    - name: gateway-api-creds
      key: api-key
      envVar: API_KEY
  config:
    logLevel: info
```

### MCPServer

Defines an upstream MCP backend endpoint.

### Policy

Governance rules for tool access control (allow/deny/redact/audit).

### TrustCardReference

Binds OIDC trust identity cards for caller attestation.

### RuntimeProfile

Resource limits, feature flags, and runtime tuning for a Gateway.

## High Availability

The HA deployment template includes:

- **readinessProbe**, **livenessProbe**, **startupProbe** against `/health`
- Rolling update strategy: `maxUnavailable: 0`, `maxSurge: 1`
- **PodDisruptionBudget** (enabled when `replicaCount >= 2`)
- Resource requests/limits
- Non-root securityContext (`runAsNonRoot: true`)
- **NetworkPolicy** for ingress/egress restriction

## Monitoring

Opt-in ServiceMonitor for Prometheus Operator:

```bash
helm install mcp-gateway charts/mcp-gateway \
  --set metrics.enabled=true \
  --set metrics.serviceMonitor=true
```

Or use Prometheus annotations:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
```

## Rollback Procedures

### Helm Rollback

```bash
# List releases
helm history mcp-gateway -n mcp-gateway

# Rollback to a specific revision
helm rollback mcp-gateway <REVISION> -n mcp-gateway

# Verify rollback
kubectl rollout status deployment/mcp-gateway-mcp-gateway -n mcp-gateway
```

### CRD Rollback

If CRD schema changes cause issues:

```bash
# Re-apply previous CRD version
kubectl apply -f charts/mcp-gateway/crds/

# Restart pods to pick up schema
kubectl rollout restart deployment/mcp-gateway-mcp-gateway -n mcp-gateway
```

### Downgrade Limits

- Downgrading to a version before CRD support (pre-v2.19) requires manual
  removal of CRDs and operator resources.
- CRD `v1alpha1` schema is forward-compatible within the alpha series.
- Rolling back to Docker Compose: uninstall Helm release and follow the
  [Docker Compose guide](DEPLOYMENT.md#docker-compose).

## Debug Runbook

### Health Probe Failures

```bash
# Check pod status
kubectl get pods -n mcp-gateway -l app.kubernetes.io/name=mcp-gateway

# Check readiness/liveness/startup probe logs
kubectl describe pod <POD_NAME> -n mcp-gateway

# Exec into pod and test health endpoint
kubectl exec -it <POD_NAME> -n mcp-gateway -- wget -qO- http://localhost:39400/health
```

### Policy Failures

If `PolicyViolation` condition is True:

```bash
# Check policy status
kubectl get policy -n mcp-gateway -o yaml

# Review policy rules
kubectl get policy <NAME> -n mcp-gateway -o jsonpath='{.spec.rules}'
```

### Secret Reference Errors

If pods fail with `CreateContainerConfigError`:

```bash
# Verify Secret exists
kubectl get secret <SECRET_NAME> -n mcp-gateway

# Verify secretKeyRef in Deployment
kubectl get deployment -n mcp-gateway -o yaml | grep secretKeyRef

# Check for ExternalSecret sync status
kubectl get externalsecret -n mcp-gateway
```

### NetworkPolicy Issues

```bash
# Verify NetworkPolicy is applied
kubectl get networkpolicy -n mcp-gateway

# Test connectivity from within pod
kubectl exec -it <POD_NAME> -n mcp-gateway -- wget -qO- https://mcp.example.com
```

## Secret Management Best Practices

1. **Never** put API keys, tokens, or passwords in ConfigMaps or Helm values.
2. Use `secretKeyRef` in Gateway spec to reference Kubernetes Secrets.
3. For production, use ExternalSecret with a vault backend (HashiCorp Vault,
   AWS Secrets Manager, etc.).
4. The operator never copies secret values into status conditions, events,
   logs, or evidence exports.
5. Audit `kubectl get events` to verify no secret leakage.

## License

- Kubernetes operator, Helm chart, CRDs: **Enterprise Edition** (PolyForm Noncommercial 1.0.0)
- Core gateway: MIT
- See [COMMERCIAL.md](../COMMERCIAL.md) for commercial licensing
- Free/core alternative: [Docker Compose deployment](DEPLOYMENT.md#docker-compose)
