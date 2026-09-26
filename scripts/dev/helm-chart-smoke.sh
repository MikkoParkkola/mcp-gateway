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

echo "== default render: exactly ConfigMap/Deployment/NetworkPolicy/Service/ServiceAccount =="
got="$("$HELM" template t "$CHART" | grep '^kind:' | awk '{print $2}' | sort -u | paste -sd, -)"
want="ConfigMap,Deployment,NetworkPolicy,Service,ServiceAccount"
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
grep -qE '^ *- name: state$' <<<"$dep" && grep -qE '^ *emptyDir:' <<<"$dep" \
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
# /metrics answers only server.metrics_token (UPGRADING-4.0 §33). Without a
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

echo "== helm_pod_identity_is_the_images_uid =="
# The image's user and group are both 1001 (Dockerfile groupadd/useradd). Any
# other UID, GID or fsGroup either runs as root or cannot read its own HOME, so
# the chart refuses to render it rather than shipping a pod that fails later.
for k in runAsUser runAsGroup fsGroup; do
  grep -qE "^ *$k: 1001$" <<<"$dep" || fail "default render does not set $k: 1001"
  "$HELM" template t "$CHART" --set "podSecurityContext.$k=1001" >/dev/null 2>&1 \
    || fail "podSecurityContext.$k=1001 does not render"
  for bad in 0 1000; do
    # The schema pins 1001, so lint and schema-only tools refuse it before any
    # template runs; the template guard still holds when validation is skipped.
    err="$("$HELM" template t "$CHART" --set "podSecurityContext.$k=$bad" 2>&1 >/dev/null || true)"
    { grep -q "specifications of the schema" <<<"$err" && grep -q "$k" <<<"$err"; } \
      || fail "podSecurityContext.$k=$bad is not refused by the schema: ${err:-rendered}"
    err="$("$HELM" template t "$CHART" --skip-schema-validation \
      --set "podSecurityContext.$k=$bad" 2>&1 >/dev/null || true)"
    grep -q "podSecurityContext.$k must be 1001" <<<"$err" \
      || fail "podSecurityContext.$k=$bad renders without schema validation: ${err:-rendered}"
  done
done

echo "== helm_every_emptydir_has_a_size_limit =="
# A full HOME (npm/uv caches, task store) must evict this pod, not fill the node.
for args in "" "--set rbac.create=true --set networkPolicy.enabled=true" "--set auth.mode=mesh"; do
  # shellcheck disable=SC2086
  r="$("$HELM" template t "$CHART" $args)"
  unbounded="$(awk '/^ *emptyDir:/ { getline n; if (n !~ /^ *sizeLimit: /) c++ } END { print c+0 }' <<<"$r")"
  [ "$unbounded" = "0" ] || fail "$unbounded emptyDir volume(s) without sizeLimit (args: ${args:-none})"
done
grep -qE '^ *sizeLimit: 1Gi$' <<<"$dep" || fail "state emptyDir default sizeLimit is not 1Gi"
sized="$("$HELM" template t "$CHART" --set stateVolume.sizeLimit=5Gi 2>&1 || true)"
grep -qE '^ *sizeLimit: 5Gi$' <<<"$sized" || fail "stateVolume.sizeLimit does not set the emptyDir sizeLimit"
# Unset, the emptyDir would render unbounded (or `sizeLimit: null`): the schema refuses it.
err="$("$HELM" template t "$CHART" --set stateVolume.sizeLimit=null 2>&1 >/dev/null || true)"
{ grep -q "specifications of the schema" <<<"$err" && grep -q "sizeLimit" <<<"$err"; } \
  || fail "an unset stateVolume.sizeLimit is not refused by the schema: ${err:-rendered}"

echo "== service_account_token_not_mounted =="
# Neither pod calls the Kubernetes API: the gateway has no API client, and the
# `kubernetes` subcommands shell out to kubectl, which the image does not carry.
grep -qE '^ *automountServiceAccountToken: false$' <<<"$dep" \
  || fail "chart mounts a service account token by default"
EA_DEP="$(dirname "$CHART")/../kubernetes/enterprise-alpha/base/deployment.yaml"
grep -qE '^ *automountServiceAccountToken: false$' "$EA_DEP" \
  || fail "enterprise-alpha deployment mounts a service account token"

echo "== helm_replicas_guard_per_process_state =="
# UPGRADING-4.0 §37: key-server tokens, accounts custody and task records live in
# one process, so more than one replica fails the render when any is on. The
# modern protocol (on unless config.server.modern_protocol is false) reaches the
# task store.
grep -qE '^  replicas: 1$' <<<"$dep" || fail "default replicaCount is not 1"
grep -qE '^      replicas: 1$' <<<"$cm" || fail "rendered gateway.yaml does not declare server.replicas: 1"
# Recreate whenever per-process state is on, the default modern protocol
# included: a surge pod holds its own task store, tokens or custody.
grep -qE '^    type: Recreate$' <<<"$dep" || fail "a default install (modern protocol on) does not render Recreate"
grep -q 'rollingUpdate' <<<"$dep" && fail "the default Recreate still renders a rollingUpdate block"
two=(--set replicaCount=2 --set config.server.modern_protocol=false)
for case in "key_server.enabled=true:InMemoryTokenStore" "accounts.enabled=true:single_process"; do
  out="$("$HELM" template t "$CHART" "${two[@]}" --set "config.${case%%:*}" 2>&1)" \
    && fail "config.${case%%:*} with replicaCount=2 rendered"
  grep -q "Error:.*${case##*:}" <<<"$out" || fail "config.${case%%:*} refusal does not name ${case##*:}"
done
out="$("$HELM" template t "$CHART" --set replicaCount=2 2>&1)" \
  && fail "replicaCount=2 with the modern protocol on rendered"
grep -q 'Error:.*task store' <<<"$out" || fail "modern-protocol refusal does not name the task store"
out="$("$HELM" template t "$CHART" --set config.server.replicas=3 2>&1)" \
  && fail "config.server.replicas disagreeing with replicaCount rendered"
multi="$("$HELM" template t "$CHART" "${two[@]}" 2>&1)" \
  || fail "replicaCount=2 with modern_protocol=false did not render"
grep -qE '^      replicas: 2$' <<<"$multi" || fail "server.replicas does not follow replicaCount=2"
grep -qE '^    type: RollingUpdate$' <<<"$multi" || fail "no per-process state, yet no RollingUpdate"
ks="$("$HELM" template t "$CHART" --set config.key_server.enabled=true --show-only templates/deployment.yaml 2>&1)"
grep -qE '^    type: Recreate$' <<<"$ks" || fail "key_server does not render strategy Recreate"
grep -q 'rollingUpdate' <<<"$ks" && fail "Recreate still renders a rollingUpdate block"
acc="$("$HELM" template t "$CHART" --set config.accounts.enabled=true --show-only templates/deployment.yaml 2>&1)"
grep -qE '^    type: Recreate$' <<<"$acc" || fail "accounts does not render strategy Recreate"

echo "== helm_config_file_mode_is_readable_without_a_world_bit =="
# CONFIG.2 refuses a config with a world bit; the projection is root-owned, so
# the gateway reads it through fsGroup. Both defaults render; the mode override
# wins, and an fsGroup other than 1001 is refused by the UID guard above.
grep -qE '^ *fsGroup: 1001$' <<<"$dep" || fail "pod fsGroup default is not 1001"
grep -qE '^ *defaultMode: 288$' <<<"$dep" || fail "config defaultMode default is not 288 (0440)"
over="$("$HELM" template t "$CHART" --show-only templates/deployment.yaml \
  --set configVolume.defaultMode=256)"
grep -qE '^ *defaultMode: 256$' <<<"$over" || fail "configVolume.defaultMode override ignored"

echo "== helm_credential_render_has_writable_audit_path =="
# D1-T20. Credential mode turns auth on, and auth on requires the audit log
# (UPGRADING-4.0), so the chart renders one on a writable `audit` volume:
# an emptyDir by default, the operator's claim with audit.existingClaim.
grep -qE '^ *transparency_log:$' <<<"$cm" || fail "credential render has no transparency_log"
tlog="$(grep -A3 -E '^ *transparency_log:$' <<<"$cm" || true)"
grep -qE '^ *enabled: true$' <<<"$tlog" || fail "transparency_log is not enabled"
grep -qE '^ *path: /var/lib/mcp-gateway/audit/' <<<"$tlog" \
  || fail "transparency_log.path is not under /var/lib/mcp-gateway/audit"
grep -qE '^ *mountPath: /var/lib/mcp-gateway/audit$' <<<"$dep" || fail "no audit mount"
audit_vol="$(grep -A3 -E '^ *- name: audit$' <<<"$dep" || true)"
grep -qE '^ *emptyDir:' <<<"$audit_vol" || fail "default audit volume is not an emptyDir"
grep -qE '^ *sizeLimit: 1Gi$' <<<"$audit_vol" || fail "audit emptyDir has no 1Gi sizeLimit"
claim="$("$HELM" template t "$CHART" --show-only templates/deployment.yaml \
  --set audit.existingClaim=x)"
claim_vol="$(grep -A3 -E '^ *- name: audit$' <<<"$claim" || true)"
grep -qE '^ *claimName: "?x"?$' <<<"$claim_vol" || fail "audit.existingClaim does not mount the claim"
grep -qE '^ *fsGroup: 1001$' <<<"$claim" || fail "existingClaim render lost fsGroup; uid 1001 cannot write the PVC"
moved="$("$HELM" template t "$CHART" --show-only templates/configmap.yaml \
  --set config.security.transparency_log.path=/tmp/elsewhere.jsonl)"
grep -q '/tmp/elsewhere.jsonl' <<<"$moved" && fail "a configured log path moved the log off the audit volume"
mesh_all="$("$HELM" template t "$CHART" --set auth.mode=mesh)"
grep -q 'transparency_log' <<<"$mesh_all" && fail "mesh mode renders an audit log"
grep -qE '^ *- name: audit$' <<<"$mesh_all" && fail "mesh mode renders an audit volume"

# C3: credential mode serves bearer tokens over plain HTTP on 0.0.0.0, which the
# gateway refuses unless server.cleartext_http names who protects them. The
# chart's answer is cluster_internal, honest only while the port stays inside
# the cluster and is reached by its Service name.
echo "== helm_credential_mode_renders_cleartext_value =="
grep -qE '^ *cleartext_http: cluster_internal$' <<<"$cm" \
  || fail "credential mode does not render cleartext_http: cluster_internal"
up="$("$HELM" template t "$CHART" --set server.cleartextHttp=tls_terminated_upstream \
  --set config.server.public_url=https://mcp.example.com --set service.type=LoadBalancer \
  --show-only templates/configmap.yaml 2>&1)" \
  && grep -qE '^ *cleartext_http: tls_terminated_upstream$' <<<"$up" \
  || fail "a tls_terminated_upstream override behind an ingress does not render: $up"
meshcm="$("$HELM" template t "$CHART" --set auth.mode=mesh --show-only templates/configmap.yaml)"
! grep -q 'cleartext_http' <<<"$meshcm" \
  || fail "mesh mode carries no credential, so it must not render cleartext_http"

echo "== cluster_internal_renders_a_network_policy =="
kinds="$("$HELM" template t "$CHART" | grep '^kind:' | awk '{print $2}' | sort -u | paste -sd, -)"
grep -q 'NetworkPolicy' <<<"$kinds" \
  || fail "cluster_internal is the default but no NetworkPolicy renders: [$kinds]"
# Forced by cluster_internal alone, the policy restricts ingress only: backends
# listen on any port, and an egress allow-list nobody asked for would cut them
# off. networkPolicy.enabled keeps the restrictive Ingress+Egress form.
forced="$("$HELM" template t "$CHART" --show-only templates/networkpolicy.yaml)"
grep -qE '^ *policyTypes: \["Ingress"\]$' <<<"$forced" \
  || fail "the cluster_internal NetworkPolicy is not Ingress-only"
! grep -qE '^ *egress:' <<<"$forced" \
  || fail "the cluster_internal NetworkPolicy restricts egress; backends on other ports would break"
optin="$("$HELM" template t "$CHART" --set networkPolicy.enabled=true --show-only templates/networkpolicy.yaml)"
grep -qE '^ *policyTypes: \["Ingress", "Egress"\]$' <<<"$optin" && grep -qE '^ *egress:' <<<"$optin" \
  || fail "networkPolicy.enabled no longer renders the Ingress+Egress policy"

echo "== cluster_internal_requires_this_releases_service_host =="
# The rows the gateway's own test reads (cluster_internal_requires_service_host).
# Rendered as fullname gw in namespace ns, so accepted rows name gw.ns.svc.
# Both directions: an accepted row must render, a rejected one must fail.
accepted=0
while read -r verdict url domain; do
  case "$verdict" in ''|'#'*) continue ;; esac
  args=(--namespace ns --set fullnameOverride=gw --set "config.server.public_url=$url")
  [ "$domain" = "-" ] || args+=(--set "config.server.cluster_domain=$domain")
  if "$HELM" template gw "$CHART" "${args[@]}" --show-only templates/configmap.yaml >/dev/null 2>&1; then
    [ "$verdict" = accept ] || fail "public_url $url (domain $domain) rendered; the gateway refuses it"
    accepted=$((accepted + 1))
  else
    [ "$verdict" = reject ] || fail "public_url $url (domain $domain) failed to render; the gateway accepts it"
  fi
done <"$CHART/../../../tests/fixtures/c3_service_hosts.txt"
[ "$accepted" -ge 3 ] || fail "only $accepted accepted Service-host rows rendered; the fixture lost its acceptances"
# A blank public_url is not a Service name either (the template fills only a missing one).
out="$("$HELM" template gw "$CHART" --namespace ns --set fullnameOverride=gw \
  --set-string 'config.server.public_url= ' 2>&1)" \
  && fail "a blank public_url rendered under cluster_internal"
grep -q 'unset or empty' <<<"$out" || fail "a blank public_url failed without saying so: $out"
# Chart-only: another release's Service is a Service, but not this gateway's.
if "$HELM" template gw "$CHART" --namespace ns --set fullnameOverride=gw \
    --set config.server.public_url=http://other.ns.svc:39400 >/dev/null 2>&1; then
  fail "a public_url naming another release's Service rendered under cluster_internal"
fi

echo "== cluster_internal_refuses_off_cluster_publishing =="
for bad in "service.type=NodePort" "service.type=LoadBalancer" \
    "config.server.public_url=https://mcp.example.com" "server.cleartextHttp=bogus"; do
  if out="$("$HELM" template t "$CHART" --set "$bad" 2>&1)"; then
    fail "--set $bad rendered; cluster_internal must refuse it"
  elif [ "$bad" != "server.cleartextHttp=bogus" ] && ! grep -q 'tls_terminated_upstream' <<<"$out"; then
    fail "--set $bad failed without naming tls_terminated_upstream: $out"
  fi
done

echo "== helm_default_fits_size_limit =="
# D6: the defaults render, and pin the documented values; a retention that
# cannot fit the 1Gi emptyDir must refuse to render.
d6="$("$HELM" template t "$CHART" 2>&1)" || fail "default render fails the audit volume guard: $d6"
grep -qE '^ +retain_segments: 12$' <<<"$d6" || fail "default retain_segments is not 12"
grep -qE '^ +max_segment_bytes: 67108864$' <<<"$d6" || fail "default max_segment_bytes is not 64Mi"
grep -qE '^ +on_disk_full: expire_oldest$' <<<"$d6" || fail "default on_disk_full is not expire_oldest"
if out="$("$HELM" template t "$CHART" --set audit.rotation.retainSegments=20 2>&1)"; then
  fail "retainSegments=20 rendered on a 1Gi emptyDir"
elif ! grep -q 'does not fit' <<<"$out"; then
  fail "retainSegments=20 failed without naming the size guard: $out"
fi
"$HELM" template t "$CHART" --set audit.rotation.retainSegments=20 \
  --set audit.existingClaim=big >/dev/null 2>&1 || fail "a PVC must lift the emptyDir size guard"

[ "$fails" -eq 0 ] || { echo "helm chart smoke: $fails startup check(s) failed" >&2; exit 1; }

echo "helm chart smoke passed"
