#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${MCP_GATEWAY_KIND_CLUSTER:-mcp-gateway-enterprise-smoke}"
NAMESPACE="${MCP_GATEWAY_KIND_NAMESPACE:-mcp-gateway}"
KIND="${KIND:-kind}"
KUBECTL="${KUBECTL:-kubectl}"
KEEP="${MCP_GATEWAY_KIND_KEEP:-0}"

cleanup() {
  if [ "$KEEP" != "1" ]; then
    "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}

command -v "$KIND" >/dev/null 2>&1
command -v "$KUBECTL" >/dev/null 2>&1

if ! "$KIND" get clusters | grep -qx "$CLUSTER"; then
  "$KIND" create cluster --name "$CLUSTER"
  trap cleanup EXIT
fi

"$KUBECTL" config use-context "kind-$CLUSTER" >/dev/null
"$KUBECTL" create namespace "$NAMESPACE" --dry-run=client -o yaml | "$KUBECTL" apply -f -
"$KUBECTL" apply --server-side -f "$ROOT_DIR/crds/mcpgateway.io.yaml"

KUBECTL="$KUBECTL" "$ROOT_DIR/scripts/server-dry-run.sh" "$NAMESPACE"

printf 'kind smoke passed for cluster %s namespace %s\n' "$CLUSTER" "$NAMESPACE"
