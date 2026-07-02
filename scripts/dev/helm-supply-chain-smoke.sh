#!/usr/bin/env bash
# Helm supply-chain smoke: sign the chart + image with cosign and verify the
# exact digests, then generate an SBOM and assert its presence (MIK-6698 /
# HELM.6). Self-contained + deterministic: uses a local registry and an
# EPHEMERAL cosign key with the transparency log (Rekor) disabled, so there is
# no Fulcio/Rekor network dependency. The tag-release workflow does keyless
# (OIDC) signing separately; this proves the sign→verify→SBOM mechanics.
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

# ── A container image, pushed to the local registry, signed by digest ──────────
# Use a small, guaranteed-pullable image as the release-image stand-in.
IMG="$REGISTRY/mcp-gateway-supplychain"
docker pull registry.k8s.io/pause:3.10
docker tag registry.k8s.io/pause:3.10 "$IMG:smoke"
docker push "$IMG:smoke"
IMG_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMG:smoke" | cut -d@ -f2)"
[ -n "$IMG_DIGEST" ] || { echo "FAIL: could not resolve image digest" >&2; exit 1; }
IMG_REF="$IMG@$IMG_DIGEST"

echo "== cosign sign image by digest =="
"$COSIGN" sign "${SIGN_ARGS[@]}" "$IMG_REF"

echo "== cosign verify image on the EXACT digest =="
"$COSIGN" verify "${VERIFY_ARGS[@]}" "$IMG_REF" >/dev/null \
  || { echo "FAIL: cosign verify (image) did not validate" >&2; exit 1; }

echo "== an unsigned image digest must NOT verify =="
docker pull registry.k8s.io/pause:3.9
docker tag registry.k8s.io/pause:3.9 "$IMG:unsigned"
docker push "$IMG:unsigned" >/dev/null
UNSIGNED_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMG:unsigned" | cut -d@ -f2)"
if [ -n "$UNSIGNED_DIGEST" ] && [ "$UNSIGNED_DIGEST" != "$IMG_DIGEST" ]; then
  ! "$COSIGN" verify "${VERIFY_ARGS[@]}" "$IMG@$UNSIGNED_DIGEST" >/dev/null 2>&1 \
    || { echo "FAIL: cosign verified an UNSIGNED image digest" >&2; exit 1; }
fi

# ── SBOM (SPDX JSON) generated and asserted present ────────────────────────────
echo "== syft SBOM (SPDX JSON) =="
"$SYFT" "registry.k8s.io/pause:3.10" -o spdx-json > sbom.spdx.json
[ -s sbom.spdx.json ] || { echo "FAIL: SBOM is empty" >&2; exit 1; }
grep -q '"spdxVersion"' sbom.spdx.json \
  || { echo "FAIL: SBOM lacks an spdxVersion marker (not valid SPDX)" >&2; exit 1; }

echo "== cosign attest SBOM to the image, then verify the attestation =="
"$COSIGN" attest "${SIGN_ARGS[@]}" --predicate sbom.spdx.json --type spdxjson "$IMG_REF"
"$COSIGN" verify-attestation "${VERIFY_ARGS[@]}" --type spdxjson "$IMG_REF" >/dev/null \
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
