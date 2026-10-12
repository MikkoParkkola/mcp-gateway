# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# shellcheck shell=bash
# MIK-7570.CHART.2: auth modes, backend secrets and persistence. Sourced by
# helm-chart-smoke.sh, which defines CHART, HELM and fail().

GOLDEN="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../tests/fixtures/helm-golden" && pwd)"
render() { "$HELM" template t "$CHART" "$@" 2>&1; }
refused() { # name want_text args... : the render must fail and name want_text
  local name="$1" want="$2" out; shift 2
  if out="$(render "$@")"; then
    fail "$name: rendered, want a refusal"
  elif ! grep -q -- "$want" <<<"$out"; then
    fail "$name: refused without naming '$want': $(tail -3 <<<"$out")"
  fi
}
KEYS=(--set auth.mode=api_keys --set auth.existingSecret=keys
      --set 'auth.apiKeys[0].name=ci' --set 'auth.apiKeys[0].secretKey=k0'
      --set 'auth.apiKeys[0].backends[0]=*'
      --set 'auth.apiKeys[1].name=ops' --set 'auth.apiKeys[1].secretKey=k1'
      --set 'auth.apiKeys[1].backends[0]=github' --set 'auth.apiKeys[1].admin=true')
OIDC=(--set auth.mode=oidc
      --set 'auth.oidc.providers[0].issuer=https://idp.example.org'
      --set 'auth.oidc.providers[0].audiences[0]=mcp-gateway'
      --set 'auth.oidc.policies[0].match.issuer=https://idp.example.org'
      --set 'auth.oidc.policies[0].match.domain=example.org'
      --set 'auth.oidc.policies[0].scopes.backends[0]=*')

echo "== helm_default_modes_unchanged =="
for mode in credential mesh; do
  got="$(render --set auth.mode=$mode | sed '/helm.sh\/chart:/d')"
  diff -u "$GOLDEN/$mode.yaml" - <<<"$got" >/dev/null \
    || fail "$mode render drifted from tests/fixtures/helm-golden/$mode.yaml"
done

echo "== helm_api_keys_mode_renders_keys_not_bearer =="
ak="$(render "${KEYS[@]}")" || fail "api_keys mode refused: $(tail -3 <<<"$ak")"
grep -qE '^ +key_sha256: env:GATEWAY_API_KEY_0$' <<<"$ak" || fail "api key 0 is not env:GATEWAY_API_KEY_0"
grep -qE '^ +key_sha256: env:GATEWAY_API_KEY_1$' <<<"$ak" || fail "api key 1 is not env:GATEWAY_API_KEY_1"
grep -qE '^ +(- )?admin: true$' <<<"$ak" || fail "apiKeys[1].admin not rendered"
! grep -q 'bearer_token' <<<"$ak" || fail "api_keys mode renders the master bearer"
akcm="$(render "${KEYS[@]}" --show-only templates/configmap.yaml || true)"
! grep -qE '^ +(- )?key: ' <<<"$akcm" || fail "api_keys mode renders a plaintext key field"

echo "== helm_api_keys_without_backends_fails =="
refused "key without backends" "backends" --set auth.mode=api_keys --set auth.existingSecret=keys \
  --set 'auth.apiKeys[0].name=ci' --set 'auth.apiKeys[0].secretKey=k0'
refused "api_keys with no keys" "apiKeys" --set auth.mode=api_keys --set auth.existingSecret=keys

echo "== helm_oidc_mode_renders_key_server =="
oi="$(render "${OIDC[@]}")" || fail "oidc mode refused: $(tail -3 <<<"$oi")"
grep -qE '^ +issuer: https://idp.example.org$' <<<"$oi" || fail "oidc provider issuer not rendered"
key_server="$(sed -n '/^    key_server:/,/^    [a-z]/p' <<<"$oi")"
grep -qE '^ +enabled: true$' <<<"$key_server" || fail "oidc mode does not enable key_server"
! grep -q 'bearer_token' <<<"$oi" || fail "oidc mode renders the master bearer"
grep -q 'type: Recreate' <<<"$(render "${OIDC[@]}" --set config.server.modern_protocol=false || true)" \
  || fail "oidc mode keeps a rolling strategy (per-process token store)"
refused "oidc with two replicas" "key server" "${OIDC[@]}" --set replicaCount=2 --set config.server.modern_protocol=false
refused "oidc without a provider" "providers" --set auth.mode=oidc

echo "== helm_non_mesh_modes_render_cleartext_and_network_policy =="
for args in "${KEYS[*]}" "${OIDC[*]}"; do
  # shellcheck disable=SC2086 # word-split on purpose: one argv per mode
  out="$(render $args || true)"
  grep -qE '^ +cleartext_http: cluster_internal$' <<<"$out" || fail "no cleartext_http in [$args]"
  grep -q '^kind: NetworkPolicy' <<<"$out" || fail "no forced NetworkPolicy in [$args]"
  grep -qE '^ +- name: audit$' <<<"$out" || fail "no audit volume in [$args]"
done

echo "== helm_extra_env_rejects_gateway_prefix =="
for bad in MCP_GATEWAY_AUTH__ENABLED mcp_gateway_auth__enabled HOME GATEWAY_API_KEY_0 GATEWAY_KS_ADMIN_TOKEN; do
  refused "extraEnv $bad" "extraEnv" --set "extraEnv[0].name=$bad" --set 'extraEnv[0].value=x'
done
ee="$(render --set 'extraEnv[0].name=GITHUB_TOKEN' --set 'extraEnv[0].value=x')" \
  || fail "extraEnv GITHUB_TOKEN refused: $(tail -3 <<<"$ee")"
grep -qE '^ +- name: GITHUB_TOKEN$' <<<"$ee" || fail "extraEnv GITHUB_TOKEN not rendered"

echo "== helm_env_from_requires_safe_prefix =="
refused "envFrom without prefix" "prefix" --set 'envFrom[0].secretRef.name=s'
for p in MCP_GATEWAY_X MCP_ M mcp_gateway_ MCP_GATEWAY; do
  refused "envFrom prefix $p" "prefix" --set 'envFrom[0].secretRef.name=s' --set "envFrom[0].prefix=$p"
done
ef="$(render --set 'envFrom[0].secretRef.name=s' --set 'envFrom[0].prefix=BACKEND_')" \
  || fail "envFrom BACKEND_ refused: $(tail -3 <<<"$ef")"
grep -qE '^ +(- )?prefix: "?BACKEND_"?$' <<<"$ef" || fail "envFrom BACKEND_ not rendered"

echo "== helm_secret_injection_per_mode =="
envnames() { sed -n '/^kind: Deployment/,$p' | { grep -oE 'name: (MCP_GATEWAY_TOKEN|GATEWAY_API_KEY_[0-9]+|GATEWAY_KS_ADMIN_TOKEN)$' || true; } | awk '{print $2}' | sort | paste -sd, - || true; }
[ "$(render | envnames)" = "MCP_GATEWAY_TOKEN" ] || fail "credential env is not exactly MCP_GATEWAY_TOKEN"
[ "$(render "${KEYS[@]}" | envnames)" = "GATEWAY_API_KEY_0,GATEWAY_API_KEY_1" ] || fail "api_keys env is not exactly the two keys"
[ "$(render "${OIDC[@]}" | envnames)" = "" ] || fail "oidc without an admin token injects a secret"
oa="$(render "${OIDC[@]}" --set auth.existingSecret=ks --set auth.oidc.adminTokenSecretKey=admin || true)"
[ "$(envnames <<<"$oa")" = "GATEWAY_KS_ADMIN_TOKEN" ] || fail "oidc admin token env missing"
grep -qE '^ +admin_token: env:GATEWAY_KS_ADMIN_TOKEN$' <<<"$oa" || fail "oidc admin_token not rendered"
[ "$(render --set auth.mode=mesh | envnames)" = "" ] || fail "mesh injects a secret"

echo "== helm_persistence_renders_pvc_recreate_policy =="
pv="$(render --set persistence.enabled=true)" || fail "persistence refused: $(tail -3 <<<"$pv")"
grep -q '^kind: PersistentVolumeClaim' <<<"$pv" || fail "no PVC rendered"
state="$(sed -n '/^ *- name: state$/,/^ *- name: /p' <<<"$pv")"
grep -q 'persistentVolumeClaim:' <<<"$state" || fail "state volume does not use the claim"
grep -q 'type: Recreate' <<<"$(render --set persistence.enabled=true --set config.server.modern_protocol=false || true)" \
  || fail "persistence keeps a rolling strategy"
grep -qE '^ +fsGroupChangePolicy: OnRootMismatch$' <<<"$pv" || fail "no fsGroupChangePolicy: OnRootMismatch"
grep -qE '^ +store_dir: /var/lib/mcp-gateway/control-plane$' <<<"$pv" || fail "control_plane.store_dir not on the claim"
# Checked first: a failed render's error text would let the negated match pass.
default="$(render)" || fail "default render failed: $default"
! grep -q 'store_dir: /var/lib/mcp-gateway/control-plane' <<<"$default" || fail "default render sets control_plane.store_dir"
refused "persistence with two replicas" "persistence" --set persistence.enabled=true --set replicaCount=2 \
  --set config.server.modern_protocol=false
ex="$(render --set persistence.enabled=true --set persistence.existingClaim=mine || true)"
! grep -q '^kind: PersistentVolumeClaim' <<<"$ex" || fail "existingClaim still renders a PVC"
grep -qE 'claimName: "?mine"?' <<<"$ex" || fail "existingClaim not mounted"
refused "oidc policy matching a whole issuer" "match" --set auth.mode=oidc \
  --set 'auth.oidc.providers[0].issuer=https://idp.acme.test' \
  --set 'auth.oidc.policies[0].match.issuer=https://idp.acme.test' \
  --set 'auth.oidc.policies[0].scopes.backends[0]=*'
refused "oidc with a literal admin_token" "admin_token" "${OIDC[@]}" --set config.key_server.admin_token=literal
refused "oidc provider without an audience" "audiences" --set auth.mode=oidc \
  --set 'auth.oidc.providers[0].issuer=https://idp.acme.test' \
  --set 'auth.oidc.policies[0].match.issuer=https://idp.acme.test' \
  --set 'auth.oidc.policies[0].match.domain=acme.test' \
  --set 'auth.oidc.policies[0].scopes.backends[0]=*'
refused "oidc policy for a foreign issuer" "names no" "${OIDC[@]}" \
  --set 'auth.oidc.policies[0].match.issuer=https://other.acme.test'
long="$(render --set persistence.enabled=true --set fullnameOverride="$(printf 'x%.0s' $(seq 1 63))" || true)"
grep -qE '^  name: x{57}-state$' <<<"$long" || fail "state claim name is not truncated to 63 characters"
