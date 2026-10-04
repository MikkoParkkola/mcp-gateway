#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Publish the Helm chart of TAG_COMMIT with image.digest set to the pushed
# release image's digest, then verify it from the registry (MIK-6684).
# The committed chart keeps an empty digest: rule (a) allows no non-docs
# commit after the freeze, so the digest goes into the packaged chart only.
#
# usage: TAG_COMMIT=<sha> publish_pinned_chart.sh <image-ref> <oci-repo>
#   e.g. publish_pinned_chart.sh ghcr.io/mikkoparkkola/mcp-gateway:4.0.0 oci://ghcr.io/mikkoparkkola/charts
set -euo pipefail

image=${1:?image reference}
repo=${2:?oci chart repository}
: "${TAG_COMMIT:?set TAG_COMMIT to the tagged commit}"

digest=$(docker buildx imagetools inspect "$image" --format '{{json .Manifest.Digest}}' | tr -d '"')
if ! [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "not an image digest: $digest" >&2
  exit 1
fi

work=$(mktemp -d)
git archive "$TAG_COMMIT" deploy/helm/mcp-gateway | tar -x -C "$work"
chart="$work/deploy/helm/mcp-gateway"
version=$(yq '.version' "$chart/Chart.yaml") # the chart's own version, not the app's

DIGEST="$digest" yq -i '.image.digest = strenv(DIGEST)' "$chart/values.yaml"
staged=$(yq '.image.digest' "$chart/values.yaml")
[[ $staged == "$digest" ]] || { echo "digest not staged: $staged" >&2; exit 1; }

helm package "$chart" -d "$work/out"
helm push "$work/out/mcp-gateway-$version.tgz" "$repo"

# Verify from the registry, not from the local file.
mkdir -p "$work/pulled"
helm pull "$repo/mcp-gateway" --version "$version" -d "$work/pulled"
published=$(tar -xOzf "$work/pulled/mcp-gateway-$version.tgz" mcp-gateway/values.yaml | yq '.image.digest')
[[ $published == "$digest" ]] || { echo "published chart pins $published, not $digest" >&2; exit 1; }
echo "chart $version pins $digest"
