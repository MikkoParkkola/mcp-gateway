#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${1:-mcp-gateway}"
KUBECTL="${KUBECTL:-kubectl}"

printf 'mcp-gateway Kubernetes server-side dry-run\n'
printf 'namespace: %s\n' "$NAMESPACE"

"$ROOT_DIR/scripts/preflight.sh" "$NAMESPACE"

printf 'dry-run: custom resource definitions\n'
"$KUBECTL" apply --server-side --dry-run=server -f "$ROOT_DIR/crds/mcpgateway.io.yaml"

printf 'dry-run: base namespaced resources\n'
"$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/rbac.yaml"
"$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/configmap.yaml"
"$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/networkpolicy.yaml"
"$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/service.yaml"
"$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/deployment.yaml"

if "$KUBECTL" api-resources --api-group=mcpgateway.io >/dev/null 2>&1; then
  printf 'dry-run: mcp-gateway custom resources\n'
  "$KUBECTL" apply --server-side --dry-run=server -n "$NAMESPACE" -f "$ROOT_DIR/base/example-gateway.yaml"
else
  printf 'warn: mcpgateway.io CRDs are not installed; skipping custom-resource dry-run\n'
fi

printf 'server-side dry-run completed\n'
