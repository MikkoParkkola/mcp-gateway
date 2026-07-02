#!/usr/bin/env bash
# Helm supply-chain smoke: sign the chart + image with cosign and verify the
# exact digests, then generate an SBOM and assert its presence (MIK-6698 /
# HELM.6). Self-contained + deterministic: builds its OWN minimal images (no
# external pulls), uses a local registry, and an EPHEMERAL cosign key with the
# transparency log (Rekor) disabled — no Fulcio/Rekor network dependency. The
# tag-release workflow does keyless (OIDC) signing separately; this proves the
# sign -> verify -> SBOM mechanics.
set -euo pipefail

REGISTRY="${REGISTRY:-localhost:5000}"
HELM="${HELM:-helm}"
COSIGN="${COSIGN:-cosign}"
SYFT="${SYFT:-syft}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT_DIR/deploy/helm/mcp-gateway"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# ── Ephemeral signing key (no keyless / no Rekor upload) ───────────────────────
export COSIGN_PASSWORD=""
"$COSIGN" generate-key-pair
[ -f cosign.key ] && [ -f cosign.pub ] || { echo "FAIL: cosign key-pair not generated" >&2; exit 1; }

SIGN_ARGS=(--yes --key cosign.key --tlog-upload=false --allow-insecure-registry)
VERIFY_ARGS=(--key cosign.pub --insecure-ignore-tlog --allow-insecure-registry)

# ── Build two DISTINCT minimal images locally (no external pulls) ──────────────
build_image() {
  # $1 = tag suffix, $2 = unique marker content
  local dir="$work/img-$1"
  mkdir -p "$dir"
  printf '%s\n' "$2" > "$dir/marker"
  printf 'FROM scratch\nCOPY marker /marker\n' > "$dir/Dockerfile"
  docker build -q -t "$REGISTRY/mcp-gateway-supplychain:$1" "$dir" >/dev/null
  docker push "$REGISTRY/mcp-gateway-supplychain:$1" >/dev/null
  docker inspect --format='{{index .RepoDigests 0}}' "$REGISTRY/mcp-gateway-supplychain:$1" | cut -d@ -f2
}

IMG="$REGISTRY/mcp-gateway-supplychain"
SIGNED_DIGEST="$(build_image signed "signed-marker-content")"
UNSIGNED_DIGEST="$(build_image unsigned "unsigned-marker-content")"
[ -n "$SIGNED_DIGEST" ] && [ -n "$UNSIGNED_DIGEST" ] || { echo "FAIL: image digests not resolved" >&2; exit 1; }
[ "$SIGNED_DIGEST" != "$UNSIGNED_DIGEST" ] \
  || { echo "FAIL: distinct images collided to one digest — negative test would be vacuous" >&2; exit 1; }
SIGNED_REF="$IMG@$SIGNED_DIGEST"

echo "== cosign sign the signed image by digest =="
"$COSIGN" sign "${SIGN_ARGS[@]}" "$SIGNED_REF"

echo "== cosign verify on the EXACT signed digest =="
"$COSIGN" verify "${VERIFY_ARGS[@]}" "$SIGNED_REF" >/dev/null \
  || { echo "FAIL: cosign verify (image) did not validate a signed digest" >&2; exit 1; }

echo "== the UNSIGNED image digest must NOT verify (hard assertion) =="
! "$COSIGN" verify "${VERIFY_ARGS[@]}" "$IMG@$UNSIGNED_DIGEST" >/dev/null 2>&1 \
  || { echo "FAIL: cosign verified an UNSIGNED image digest" >&2; exit 1; }

# ── SBOM (SPDX JSON) of the EXACT pushed digest, present + attested ────────────
echo "== syft SBOM (SPDX JSON) of the pushed digest =="
export SYFT_REGISTRY_INSECURE_USE_HTTP=true
"$SYFT" "registry:$SIGNED_REF" -o spdx-json > sbom.spdx.json
[ -s sbom.spdx.json ] || { echo "FAIL: SBOM is empty" >&2; exit 1; }
grep -q '"spdxVersion"' sbom.spdx.json \
  || { echo "FAIL: SBOM lacks an spdxVersion marker (not valid SPDX)" >&2; exit 1; }

echo "== cosign attest the SBOM to the signed digest, then verify the attestation =="
# `attest` gets its own args (no --tlog-upload on attest across cosign majors).
"$COSIGN" attest --yes --key cosign.key --predicate sbom.spdx.json --type spdxjson \
  --allow-insecure-registry "$SIGNED_REF"
"$COSIGN" verify-attestation "${VERIFY_ARGS[@]}" --type spdxjson "$SIGNED_REF" >/dev/null \
  || { echo "FAIL: SBOM attestation did not verify" >&2; exit 1; }

# ── Sign + verify the Helm chart (OCI artifact) by digest ──────────────────────
echo "== package + push chart, cosign sign + verify by digest =="
"$HELM" package "$CHART" -d "$work" >/dev/null
ver="$(grep -E '^version:' "$CHART/Chart.yaml" | awk '{print $2}')"
push_out="$("$HELM" push "$work/mcp-gateway-$ver.tgz" "oci://$REGISTRY/charts" --plain-http 2>&1)"
CHART_DIGEST="$(printf '%s\n' "$push_out" | grep -oE 'sha256:[0-9a-f]{64}' | head -1)"
[ -n "$CHART_DIGEST" ] || { echo "FAIL: could not resolve chart digest from helm push" >&2; exit 1; }
CHART_REF="$REGISTRY/charts/mcp-gateway@$CHART_DIGEST"
"$COSIGN" sign "${SIGN_ARGS[@]}" "$CHART_REF"
"$COSIGN" verify "${VERIFY_ARGS[@]}" "$CHART_REF" >/dev/null \
  || { echo "FAIL: cosign verify (chart) did not validate" >&2; exit 1; }

echo "helm supply-chain smoke passed: signed+verified image+chart by digest, SBOM present+attested"
