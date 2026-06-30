#!/usr/bin/env bash
# Real apply -> upgrade -> rollback lifecycle smoke on a kind cluster.
#
# Closes MIK-6560.K8S.4 / MIK-6679: proves the enterprise-alpha manifests apply
# to a real API server (stronger than the dry-run smoke) AND that a rolling
# upgrade converges and `rollout undo` restores the prior revision.
#
# ponytail: the gateway image is not published into the ephemeral kind cluster,
# so the rollout-convergence mechanics are driven with a guaranteed-pullable
# lightweight image (registry.k8s.io/pause). The REAL manifests are applied
# first and must be accepted by the API server. Upgrade path: once the operator
# (MIK-6680) and a published image exist, swap PULLABLE_* for the real tags to
# test convergence on the real workload.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${MCP_GATEWAY_KIND_CLUSTER:-mcp-gateway-rollback-smoke}"
NAMESPACE="${MCP_GATEWAY_KIND_NAMESPACE:-mcp-gateway}"
KIND="${KIND:-kind}"
KUBECTL="${KUBECTL:-kubectl}"
KEEP="${MCP_GATEWAY_KIND_KEEP:-0}"
DEPLOY="deployment/mcp-gateway"
ROLLOUT_TIMEOUT="${MCP_GATEWAY_ROLLOUT_TIMEOUT:-120s}"

# Pullable images used only to drive deterministic rollout convergence.
PULLABLE_V1="registry.k8s.io/pause:3.10"
PULLABLE_V2="registry.k8s.io/pause:3.9"

created_cluster=0
cleanup() {
  if [ "$KEEP" != "1" ] && [ "$created_cluster" = "1" ]; then
    "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}

command -v "$KIND" >/dev/null 2>&1
command -v "$KUBECTL" >/dev/null 2>&1

if ! "$KIND" get clusters | grep -qx "$CLUSTER"; then
  "$KIND" create cluster --name "$CLUSTER"
  created_cluster=1
  trap cleanup EXIT
fi

"$KUBECTL" config use-context "kind-$CLUSTER" >/dev/null
"$KUBECTL" create namespace "$NAMESPACE" --dry-run=client -o yaml | "$KUBECTL" apply -f -

# 1. Real apply of CRDs + base manifests (must be accepted by a live API server).
echo "== apply: CRDs + base manifests =="
"$KUBECTL" apply --server-side -f "$ROOT_DIR/crds/mcpgateway.io.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/rbac.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/configmap.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/networkpolicy.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/service.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/deployment.yaml"
"$KUBECTL" apply --server-side -n "$NAMESPACE" -f "$ROOT_DIR/base/example-gateway.yaml"

# 2. v1: pin a pullable image so the rollout actually converges in kind.
#    The real Deployment has HTTP /health probes; the pause image serves no
#    HTTP, so the probes would keep pods un-Ready forever and `rollout status`
#    would time out. Strip the probes for the lifecycle test (we are exercising
#    apply+upgrade+rollback mechanics, not the gateway's health endpoint).
#    ponytail: probe-stripping is test-only; the real workload keeps its probes.
echo "== v1: converge rollout =="
"$KUBECTL" patch -n "$NAMESPACE" "$DEPLOY" --type=strategic -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"gateway","readinessProbe":null,"livenessProbe":null,"startupProbe":null}]}}}}'
"$KUBECTL" set image -n "$NAMESPACE" "$DEPLOY" "gateway=$PULLABLE_V1"
"$KUBECTL" rollout status -n "$NAMESPACE" "$DEPLOY" --timeout="$ROLLOUT_TIMEOUT"

# 3. Upgrade to v2 and assert it converges.
echo "== v2: upgrade =="
"$KUBECTL" set image -n "$NAMESPACE" "$DEPLOY" "gateway=$PULLABLE_V2"
"$KUBECTL" rollout status -n "$NAMESPACE" "$DEPLOY" --timeout="$ROLLOUT_TIMEOUT"
current="$("$KUBECTL" get -n "$NAMESPACE" "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].image}')"
if [ "$current" != "$PULLABLE_V2" ]; then
  echo "FAIL: expected upgraded image $PULLABLE_V2, got $current" >&2
  exit 1
fi

# 4. Rollback and assert it converges back to v1.
echo "== rollback =="
"$KUBECTL" rollout undo -n "$NAMESPACE" "$DEPLOY"
"$KUBECTL" rollout status -n "$NAMESPACE" "$DEPLOY" --timeout="$ROLLOUT_TIMEOUT"
restored="$("$KUBECTL" get -n "$NAMESPACE" "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].image}')"
if [ "$restored" != "$PULLABLE_V1" ]; then
  echo "FAIL: rollback did not restore $PULLABLE_V1, got $restored" >&2
  exit 1
fi

echo "kind rollback smoke passed: apply + upgrade ($PULLABLE_V2) + rollback ($restored) on cluster $CLUSTER"
