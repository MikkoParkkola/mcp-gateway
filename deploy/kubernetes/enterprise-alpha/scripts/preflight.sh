#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:-mcp-gateway}"
KUBECTL="${KUBECTL:-kubectl}"

failures=0

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'ok: %s\n' "$label"
  else
    printf 'blocker: %s\n' "$label"
    failures=$((failures + 1))
  fi
}

namespace_can_be_read_or_created() {
  "$KUBECTL" get namespace "$NAMESPACE" >/dev/null 2>&1 \
    || "$KUBECTL" auth can-i create namespaces >/dev/null 2>&1
}

printf 'mcp-gateway Kubernetes enterprise preflight\n'
printf 'namespace: %s\n' "$NAMESPACE"

check "kubectl is available" command -v "$KUBECTL"
check "cluster is reachable" "$KUBECTL" version --client=false
check "namespace can be read or created" namespace_can_be_read_or_created
check "deployments can be managed" "$KUBECTL" auth can-i create deployments.apps -n "$NAMESPACE"
check "services can be managed" "$KUBECTL" auth can-i create services -n "$NAMESPACE"
check "configmaps can be managed" "$KUBECTL" auth can-i create configmaps -n "$NAMESPACE"
check "network policies are available" "$KUBECTL" api-resources --api-group=networking.k8s.io
check "custom resource definitions are available" "$KUBECTL" api-resources --api-group=apiextensions.k8s.io

if "$KUBECTL" api-resources --api-group=cert-manager.io >/dev/null 2>&1; then
  printf 'ok: cert-manager API is available\n'
else
  printf 'warn: cert-manager API not found; TLS automation must be disabled or supplied by another issuer\n'
fi

if "$KUBECTL" api-resources | grep -q '^servicemonitors'; then
  printf 'ok: ServiceMonitor API is available\n'
else
  printf 'warn: ServiceMonitor API not found; use scrape annotations or another metrics path\n'
fi

if [ "$failures" -gt 0 ]; then
  printf 'preflight failed with %s blocker(s)\n' "$failures"
  exit 1
fi

printf 'preflight passed\n'
