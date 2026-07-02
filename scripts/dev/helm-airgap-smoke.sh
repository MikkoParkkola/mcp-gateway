#!/usr/bin/env bash
# Helm air-gap proof (MIK-6699 / HELM.7): export the signed image + signed chart
# + SBOM attestation to offline media, import them into a SEPARATE registry that
# never talked to the source, then verify signatures and install the chart
# entirely from that offline registry.
#
# Self-contained + deterministic: builds its own scratch image (no external
# pulls), uses two local registries as "connected" (5000) and "air-gapped"
# (5001), and an ephemeral cosign key with the transparency log disabled. The
# offline transport is cosign save/load (which carries signatures + attestations)
# plus the chart tgz — so the air-gap install proves the whole supply chain
# survived the crossing.
set -euo pipefail

SRC="${SRC_REGISTRY:-localhost:5000}"
AIR="${AIRGAP_REGISTRY:-localhost:5001}"
HELM="${HELM:-helm}"
COSIGN="${COSIGN:-cosign}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT_DIR/deploy/helm/mcp-gateway"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

export COSIGN_PASSWORD=""
"$COSIGN" generate-key-pair
SIGN=(--yes --key cosign.key --tlog-upload=false --allow-insecure-registry)
VERIFY=(--key cosign.pub --insecure-ignore-tlog --allow-insecure-registry)

# ── Build + sign + SBOM-attest a scratch image on the SOURCE registry ──────────
mkdir -p img
printf 'airgap-marker\n' > img/marker
printf 'FROM scratch\nCOPY marker /marker\n' > img/Dockerfile
docker build -q -t "$SRC/mcp-gateway-airgap:v1" img >/dev/null
docker push "$SRC/mcp-gateway-airgap:v1" >/dev/null
IMG_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$SRC/mcp-gateway-airgap:v1" | cut -d@ -f2)"
[ -n "$IMG_DIGEST" ] || { echo "FAIL: source image digest not resolved" >&2; exit 1; }
SRC_IMG="$SRC/mcp-gateway-airgap@$IMG_DIGEST"

export SYFT_REGISTRY_INSECURE_USE_HTTP=true
syft "registry:$SRC_IMG" -o spdx-json > sbom.spdx.json
[ -s sbom.spdx.json ] || { echo "FAIL: SBOM empty" >&2; exit 1; }

"$COSIGN" sign "${SIGN[@]}" "$SRC_IMG"
"$COSIGN" attest --yes --key cosign.key --predicate sbom.spdx.json --type spdxjson \
  --allow-insecure-registry "$SRC_IMG"

# ── Package + push + sign the chart on the SOURCE registry ─────────────────────
"$HELM" package "$CHART" -d "$work" >/dev/null
ver="$(grep -E '^version:' "$CHART/Chart.yaml" | awk '{print $2}')"
push_out="$("$HELM" push "$work/mcp-gateway-$ver.tgz" "oci://$SRC/charts" --plain-http 2>&1)"
CHART_DIGEST="$(printf '%s\n' "$push_out" | grep -oE 'sha256:[0-9a-f]{64}' | head -1)"
[ -n "$CHART_DIGEST" ] || { echo "FAIL: source chart digest not resolved" >&2; exit 1; }
SRC_CHART="$SRC/charts/mcp-gateway@$CHART_DIGEST"
"$COSIGN" sign "${SIGN[@]}" "$SRC_CHART"

# ── EXPORT to offline media (carries the image, its signature + attestation) ───
echo "== cosign save image + chart to an offline bundle =="
"$COSIGN" save "$SRC_IMG" --dir bundle/image
"$COSIGN" save "$SRC_CHART" --dir bundle/chart
[ -d bundle/image ] && [ -d bundle/chart ] || { echo "FAIL: offline bundle not created" >&2; exit 1; }

# ── IMPORT into the AIR-GAPPED registry (only the bundle crosses the gap) ───────
echo "== cosign load into the air-gapped registry =="
"$COSIGN" load --dir bundle/image --registry "$AIR" --allow-insecure-registry >/dev/null 2>&1 \
  || "$COSIGN" load --dir bundle/image --registry "$AIR" >/dev/null
"$COSIGN" load --dir bundle/chart --registry "$AIR" --allow-insecure-registry >/dev/null 2>&1 \
  || "$COSIGN" load --dir bundle/chart --registry "$AIR" >/dev/null

AIR_IMG="$AIR/mcp-gateway-airgap@$IMG_DIGEST"
AIR_CHART="$AIR/charts/mcp-gateway@$CHART_DIGEST"

# ── OFFLINE verify: signatures + SBOM attestation from the air-gapped registry ─
echo "== verify signatures + SBOM attestation from the air-gapped registry =="
"$COSIGN" verify "${VERIFY[@]}" "$AIR_IMG" >/dev/null \
  || { echo "FAIL: image signature did not verify from air-gapped registry" >&2; exit 1; }
"$COSIGN" verify-attestation "${VERIFY[@]}" --type spdxjson "$AIR_IMG" >/dev/null \
  || { echo "FAIL: SBOM attestation did not verify from air-gapped registry" >&2; exit 1; }
"$COSIGN" verify "${VERIFY[@]}" "$AIR_CHART" >/dev/null \
  || { echo "FAIL: chart signature did not verify from air-gapped registry" >&2; exit 1; }

# ── OFFLINE install: pull + render the chart from the air-gapped registry ──────
echo "== pull + render the chart from the air-gapped registry (offline install) =="
mkdir -p pulled
"$HELM" pull "oci://$AIR/charts/mcp-gateway" --version "$ver" -d pulled --plain-http
[ -f "pulled/mcp-gateway-$ver.tgz" ] || { echo "FAIL: chart not pulled from air-gapped registry" >&2; exit 1; }
"$HELM" template t "pulled/mcp-gateway-$ver.tgz" \
  --set image.registry="$AIR" \
  --set image.repository="mcp-gateway-airgap" \
  --set image.digest="$IMG_DIGEST" \
  | tee rendered.yaml | grep -q '^kind: Deployment' \
  || { echo "FAIL: air-gapped chart did not render a Deployment" >&2; exit 1; }

# The rendered manifest must reference ONLY the air-gapped registry, never source.
grep -q "$AIR/mcp-gateway-airgap@$IMG_DIGEST" rendered.yaml \
  || { echo "FAIL: rendered image does not point at the air-gapped digest" >&2; exit 1; }
! grep -q "$SRC/" rendered.yaml \
  || { echo "FAIL: rendered manifest still references the SOURCE registry" >&2; exit 1; }

echo "air-gap smoke passed: exported to bundle, imported to isolated registry, verified sigs + SBOM, installed offline"
