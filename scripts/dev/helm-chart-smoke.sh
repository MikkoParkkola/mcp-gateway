#!/usr/bin/env bash
# Helm chart smoke: lint, render the expected Kind set, and prove values.schema
# rejects invalid input. Mac/CI-buildable, no cluster required (MIK-6693 / HELM.1).
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../deploy/helm/mcp-gateway" && pwd)"
HELM="${HELM:-helm}"

echo "== helm lint =="
"$HELM" lint "$CHART"

echo "== default render: exactly ConfigMap/Deployment/Service/ServiceAccount =="
got="$("$HELM" template t "$CHART" | grep '^kind:' | awk '{print $2}' | sort -u | paste -sd, -)"
want="ConfigMap,Deployment,Service,ServiceAccount"
[ "$got" = "$want" ] || { echo "FAIL: default Kinds = [$got], want [$want]" >&2; exit 1; }

echo "== opt-in render adds NetworkPolicy + Role + RoleBinding =="
optin="$("$HELM" template t "$CHART" --set rbac.create=true --set networkPolicy.enabled=true \
  | grep '^kind:' | awk '{print $2}' | sort -u | paste -sd, -)"
for k in NetworkPolicy Role RoleBinding; do
  case ",$optin," in *",$k,"*) : ;; *) echo "FAIL: opt-in missing $k (got [$optin])" >&2; exit 1;; esac
done

echo "== schema rejects invalid values (bad port type) =="
if "$HELM" template t "$CHART" --set service.port=notanumber >/dev/null 2>&1; then
  echo "FAIL: schema accepted a non-integer port" >&2; exit 1
fi

echo "== schema rejects unknown image field =="
if "$HELM" template t "$CHART" --set image.bogus=x >/dev/null 2>&1; then
  echo "FAIL: schema accepted an unknown property" >&2; exit 1
fi

echo "== digest takes precedence over tag =="
"$HELM" template t "$CHART" \
  --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  | grep -q 'mcp-gateway@sha256:' \
  || { echo "FAIL: digest did not override tag" >&2; exit 1; }

echo "== pod selector is release-scoped (immutable-selector + cross-route guard) =="
"$HELM" template rel1 "$CHART" | grep -q 'app.kubernetes.io/instance: rel1' \
  || { echo "FAIL: selector/labels not release-scoped" >&2; exit 1; }

echo "== Pod Security 'restricted' fields present (fast pre-check; kind CI enforces authoritatively) =="
render="$("$HELM" template t "$CHART")"
for field in \
  'runAsNonRoot: true' \
  'seccompProfile:' \
  'type: RuntimeDefault' \
  'allowPrivilegeEscalation: false' \
  'readOnlyRootFilesystem: true' \
  'drop: \["ALL"\]'; do
  echo "$render" | grep -q "$field" \
    || { echo "FAIL: restricted field missing: $field" >&2; exit 1; }
done
# Negative: no privilege-escalating or host-namespace escapes that restricted forbids.
for bad in 'privileged: true' 'hostNetwork: true' 'hostPID: true' 'hostPath:' 'runAsUser: 0' 'allowPrivilegeEscalation: true'; do
  ! echo "$render" | grep -q "$bad" \
    || { echo "FAIL: restricted-forbidden field present: $bad" >&2; exit 1; }
done

echo "== NetworkPolicy is workload-scoped + restrictive with DNS egress (when enabled) =="
np="$("$HELM" template t "$CHART" --set networkPolicy.enabled=true)"
echo "$np" | grep -q 'policyTypes: \["Ingress", "Egress"\]' \
  || { echo "FAIL: NetworkPolicy is not both Ingress+Egress (not restrictive)" >&2; exit 1; }
echo "$np" | grep -q 'port: 53' \
  || { echo "FAIL: NetworkPolicy lacks a DNS (53) egress rule" >&2; exit 1; }

echo "== RBAC is least-privilege: empty Role, namespace-scoped only (no ClusterRole) =="
rbac="$("$HELM" template t "$CHART" --set rbac.create=true)"
echo "$rbac" | grep -q 'rules: \[\]' \
  || { echo "FAIL: RBAC Role is not empty/least-privilege" >&2; exit 1; }
! echo "$rbac" | grep -qE '^kind: ClusterRole' \
  || { echo "FAIL: chart renders a ClusterRole (not namespace-scoped least-priv)" >&2; exit 1; }

echo "helm chart smoke passed"
