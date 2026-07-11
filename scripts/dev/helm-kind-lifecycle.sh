#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Helm release lifecycle on a real kind cluster: install -> upgrade -> rollback,
# asserting convergence at each step (MIK-6694 / HELM.2). Proves the CHART's
# release mechanics (helm upgrade / helm rollback), not just raw kubectl.
#
# ponytail: the gateway image isn't published into the ephemeral cluster, so the
# rollout is driven with a guaranteed-pullable image (registry.k8s.io/pause) and
# probes disabled via the chart's probes.enabled=false. The real chart/manifests
# are still rendered and applied. Upgrade path: swap to the real image+tag once
# a published image exists.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT_DIR/deploy/helm/mcp-gateway"
CLUSTER="${MCP_GATEWAY_KIND_CLUSTER:-mcp-gateway-helm-lifecycle}"
NAMESPACE="${MCP_GATEWAY_HELM_NAMESPACE:-mcp-gateway-helm}"
RELEASE="${MCP_GATEWAY_HELM_RELEASE:-gw}"
KIND="${KIND:-kind}"
HELM="${HELM:-helm}"
KUBECTL="${KUBECTL:-kubectl}"
KEEP="${MCP_GATEWAY_KIND_KEEP:-0}"
TIMEOUT="${MCP_GATEWAY_ROLLOUT_TIMEOUT:-180s}"

# Pullable images used only to drive deterministic rollout convergence.
IMG_REG="registry.k8s.io"
IMG_REPO="pause"
V1="3.10"
V2="3.9"

created_cluster=0
cleanup() {
  if [ "$KEEP" != "1" ] && [ "$created_cluster" = "1" ]; then
    "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
command -v "$KIND" >/dev/null 2>&1
command -v "$HELM" >/dev/null 2>&1
command -v "$KUBECTL" >/dev/null 2>&1

if ! "$KIND" get clusters | grep -qx "$CLUSTER"; then
  "$KIND" create cluster --name "$CLUSTER"
  created_cluster=1
  trap cleanup EXIT
fi
"$KUBECTL" config use-context "kind-$CLUSTER" >/dev/null

# Authoritative Pod Security proof: enforce the built-in `restricted` standard on
# the namespace so the API server REJECTS any pod that violates it at admission.
# If the chart's securityContext regresses, `helm install --wait` fails here —
# far stronger than string-matching the rendered YAML (MIK-6695 / HELM.3).
"$KUBECTL" create namespace "$NAMESPACE" --dry-run=client -o yaml \
  | "$KUBECTL" apply -f -
"$KUBECTL" label --overwrite namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

common_args=(
  --namespace "$NAMESPACE"
  --set image.registry="$IMG_REG"
  --set image.repository="$IMG_REPO"
  --set probes.enabled=false
  --wait --timeout "$TIMEOUT"
)

deploy_name() {
  # Resolve by the release-scoped instance label — robust to any fullname scheme.
  "$KUBECTL" get deployment -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/name=mcp-gateway" \
    -o jsonpath='{.items[0].metadata.name}'
}

deploy_image() {
  "$KUBECTL" get deployment -n "$NAMESPACE" \
    -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/name=mcp-gateway" \
    -o jsonpath='{.items[0].spec.template.spec.containers[0].image}'
}

echo "== install (v1=$V1) =="
"$HELM" upgrade --install "$RELEASE" "$CHART" "${common_args[@]}" --set image.tag="$V1"
[ "$(deploy_image)" = "$IMG_REG/$IMG_REPO:$V1" ] || { echo "FAIL: install image mismatch" >&2; exit 1; }

echo "== helm upgrade (v2=$V2) =="
"$HELM" upgrade "$RELEASE" "$CHART" "${common_args[@]}" --set image.tag="$V2"
[ "$(deploy_image)" = "$IMG_REG/$IMG_REPO:$V2" ] || { echo "FAIL: upgrade image mismatch" >&2; exit 1; }

echo "== helm rollback -> revision 1 =="
"$HELM" rollback "$RELEASE" 1 --namespace "$NAMESPACE" --wait --timeout "$TIMEOUT"
"$KUBECTL" rollout status "deployment/$(deploy_name)" -n "$NAMESPACE" --timeout="$TIMEOUT"
[ "$(deploy_image)" = "$IMG_REG/$IMG_REPO:$V1" ] || { echo "FAIL: rollback did not restore v1 (got $(deploy_image))" >&2; exit 1; }

echo "helm kind lifecycle passed: install($V1) -> upgrade($V2) -> rollback($V1) on $CLUSTER"
