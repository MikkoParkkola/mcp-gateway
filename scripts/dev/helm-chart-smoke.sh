#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

echo "== app chart renders ZERO CRDs (CRDs are a separate opt-in chart) =="
# Must use --include-crds: plain `helm template` omits a chart's crds/ dir, so a
# default render would falsely pass even if the app chart wrongly bundled CRDs.
! "$HELM" template t "$CHART" --include-crds | grep -q '^kind: CustomResourceDefinition' \
  || { echo "FAIL: app chart bundles CRDs (should be in mcp-gateway-crds)" >&2; exit 1; }
[ ! -d "$CHART/crds" ] \
  || { echo "FAIL: app chart has a crds/ dir (CRDs belong in mcp-gateway-crds)" >&2; exit 1; }

echo "== separate CRDs chart lints and carries the CRDs =="
CRDS_CHART="$(dirname "$CHART")/mcp-gateway-crds"
"$HELM" lint "$CRDS_CHART" >/dev/null
[ -f "$CRDS_CHART/crds/mcpgateway.io.yaml" ] \
  || { echo "FAIL: crds chart missing the CRD file" >&2; exit 1; }

echo "== CRDs chart copy matches the enterprise-alpha source (drift guard) =="
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deploy/kubernetes/enterprise-alpha/crds/mcpgateway.io.yaml"
diff -q "$SRC" "$CRDS_CHART/crds/mcpgateway.io.yaml" >/dev/null \
  || { echo "FAIL: crds chart CRD drifted from enterprise-alpha source" >&2; exit 1; }

echo "== chart packages to a versioned artifact + schema carries a version marker =="
pkgdir="$(mktemp -d)"
trap 'rm -rf "$pkgdir"' EXIT
"$HELM" package "$CHART" -d "$pkgdir" >/dev/null
ver="$(grep -E '^version:' "$CHART/Chart.yaml" | awk '{print $2}')"
[ -f "$pkgdir/mcp-gateway-$ver.tgz" ] \
  || { echo "FAIL: helm package did not produce mcp-gateway-$ver.tgz" >&2; exit 1; }
grep -q 'schemaVersion:' "$CHART/values.schema.json" \
  || { echo "FAIL: values.schema.json lacks a schemaVersion marker" >&2; exit 1; }

# The chart never started from #292 on: `serve --host` exits 2, a `backends`
# sequence fails the map-typed config, and the task store under a read-only HOME
# is fatal. Each defect hid the next, so these checks collect every failure
# rather than stopping at the first.
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
dep="$("$HELM" template t "$CHART" --show-only templates/deployment.yaml)"
cm="$("$HELM" template t "$CHART" --show-only templates/configmap.yaml)"

echo "== helm_rendered_args_and_config_are_valid =="
# --host/--port are top-level flags; the `serve` subcommand takes only --stdio.
if grep -qE '^ *- "?serve"?$' <<<"$dep"; then
  fail "rendered args carry the serve subcommand; serve --host exits 2"
fi
grep -qE '^ *backends: \{\}$' <<<"$cm" \
  || fail "rendered gateway.yaml backends is not a map; Config.backends is a map"

echo "== helm_renders_writable_state =="
grep -qE '^ *- name: state$' <<<"$dep" && grep -qE '^ *emptyDir: \{\}$' <<<"$dep" \
  || fail "no emptyDir state volume"
grep -qE '^ *mountPath: /var/lib/mcp-gateway$' <<<"$dep" \
  || fail "no writable mount at /var/lib/mcp-gateway"
# Captured, not piped into grep -q: under pipefail an early-exiting reader
# makes the writer's SIGPIPE fail the pipeline on a match.
home_env="$(grep -A1 -E '^ *- name: HOME$' <<<"$dep" || true)"
grep -qE '^ *value: "?/var/lib/mcp-gateway"?$' <<<"$home_env" \
  || fail "HOME is not /var/lib/mcp-gateway; the task store resolves under a read-only home"
grep -qE '^ *readOnlyRootFilesystem: true$' <<<"$dep" \
  || fail "readOnlyRootFilesystem is no longer true"

echo "== helm_metrics_scrape_follows_secret =="
# /metrics answers only server.metrics_token (UPGRADING-4.0 §32). Without a
# Secret nothing advertises the endpoint, so a stock install is not scraped to
# up=0; with one, the annotations, the env reference and the ServiceMonitor's
# bearerTokenSecret all name that Secret.
stock="$("$HELM" template t "$CHART" --set metrics.serviceMonitor.enabled=true)"
grep -q 'prometheus.io/scrape' <<<"$stock" && fail "stock render advertises /metrics with no scrape token"
grep -q '^kind: ServiceMonitor' <<<"$stock" && fail "ServiceMonitor renders with no metrics.existingSecret"
grep -q 'MCP_GATEWAY_METRICS_TOKEN' <<<"$stock" && fail "stock render references a metrics token Secret"
scraped="$("$HELM" template t "$CHART" --set metrics.existingSecret=scrape-sec \
  --set metrics.secretKey=tok --set metrics.serviceMonitor.enabled=true)"
grep -q 'prometheus.io/scrape: "true"' <<<"$scraped" || fail "annotations missing with metrics.existingSecret"
grep -q '^kind: ServiceMonitor' <<<"$scraped" || fail "ServiceMonitor missing with metrics.existingSecret"
monitor="$(awk '/^kind: ServiceMonitor/,0' <<<"$scraped")"
# Captured, not piped into grep -q (SIGPIPE under pipefail, see above).
bts="$(grep -A2 'bearerTokenSecret:' <<<"$monitor" || true)"
grep -q 'name: "\?scrape-sec"\?' <<<"$bts" \
  || fail "ServiceMonitor bearerTokenSecret does not name metrics.existingSecret"
grep -q 'key: "\?tok"\?' <<<"$bts" \
  || fail "ServiceMonitor bearerTokenSecret does not use metrics.secretKey"
menv="$(grep -A4 'name: MCP_GATEWAY_METRICS_TOKEN' <<<"$scraped" || true)"
grep -q 'name: "\?scrape-sec"\?' <<<"$menv" \
  || fail "MCP_GATEWAY_METRICS_TOKEN is not read from metrics.existingSecret"
menv="$(grep -A6 'name: MCP_GATEWAY_METRICS_TOKEN' <<<"$scraped" || true)"
grep -q 'optional: true' <<<"$menv" \
  || fail "a missing metrics Secret must not stop the pod (optional: true)"
grep -q 'metrics_token: env:MCP_GATEWAY_METRICS_TOKEN' <<<"$scraped" \
  || fail "rendered gateway.yaml does not set server.metrics_token"
mesh="$("$HELM" template t "$CHART" --set auth.mode=mesh --set metrics.existingSecret=scrape-sec \
  --show-only templates/configmap.yaml)"
grep -q 'metrics_token: env:MCP_GATEWAY_METRICS_TOKEN' <<<"$mesh" \
  || fail "mesh mode drops server.metrics_token"

[ "$fails" -eq 0 ] || { echo "helm chart smoke: $fails startup check(s) failed" >&2; exit 1; }

echo "helm chart smoke passed"
