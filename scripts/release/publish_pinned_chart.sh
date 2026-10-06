#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Publish the Helm chart of TAG_COMMIT with image.digest set to the pushed
# release image's digest, cosign-sign the pushed chart by digest, then verify
# both from the registry (MIK-6684, RFC-0133 HELM.6).
# The committed chart keeps an empty digest: rule (a) allows no non-docs
# commit after the freeze, so the digest goes into the packaged chart only.
#
# usage: TAG_COMMIT=<sha> SIGNER_IDENTITY=<id> SIGNER_ISSUER=<url> CHART_NOTES=<file> \
#          publish_pinned_chart.sh <image-ref> <oci-repo>
#   e.g. publish_pinned_chart.sh ghcr.io/mikkoparkkola/mcp-gateway:4.0.0 oci://ghcr.io/mikkoparkkola/charts
# SIGNER_IDENTITY and SIGNER_ISSUER are the exact certificate identity and OIDC
# issuer the keyless signature must carry; verify pins both, never a regexp.
# On success CHART_NOTES receives the release-notes block users verify against.
set -euo pipefail

image=${1:?image reference}
repo=${2:?oci chart repository}
: "${TAG_COMMIT:?set TAG_COMMIT to the tagged commit}"
: "${SIGNER_IDENTITY:?set SIGNER_IDENTITY to the identity the chart is signed as}"
: "${SIGNER_ISSUER:?set SIGNER_ISSUER to the OIDC issuer of that identity}"
: "${CHART_NOTES:?set CHART_NOTES to the file the release-notes block goes to}"

digest=$(docker buildx imagetools inspect "$image" --format '{{json .Manifest.Digest}}' | tr -d '"')
if ! [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "not an image digest: $digest" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Helm archives file times, so a rerun would publish a new digest under the same
# version. Every staged file gets TAG_COMMIT's commit time, and the chart is
# packaged twice from two extractions: the archives must be identical (MIK-7952).
epoch=$(git show -s --format=%ct "$TAG_COMMIT")
stage() {
  git archive "$TAG_COMMIT" deploy/helm/mcp-gateway | tar -x -C "$1"
  DIGEST="$digest" yq -i '.image.digest = strenv(DIGEST)' "$1/deploy/helm/mcp-gateway/values.yaml"
  python3 - "$epoch" "$1/deploy" <<'PY'
import os, sys
when = int(sys.argv[1])
for root, dirs, files in os.walk(sys.argv[2]):
    for name in [*dirs, *files]:
        os.utime(os.path.join(root, name), (when, when), follow_symlinks=False)
    os.utime(root, (when, when))
PY
}
mkdir -p "$work/a" "$work/b"
stage "$work/a"
stage "$work/b"
chart="$work/a/deploy/helm/mcp-gateway"
version=$(yq '.version' "$chart/Chart.yaml") # the chart's own version, not the app's
staged=$(yq '.image.digest' "$chart/values.yaml")
[[ $staged == "$digest" ]] || { echo "digest not staged: $staged" >&2; exit 1; }

helm package "$chart" -d "$work/out"
helm package "$work/b/deploy/helm/mcp-gateway" -d "$work/again" >/dev/null
cmp -s "$work/out/mcp-gateway-$version.tgz" "$work/again/mcp-gateway-$version.tgz" \
  || { echo "the chart archive is not reproducible; a rerun would publish a new digest" >&2; exit 1; }
# A published version is never replaced: a rerun pushes the same bytes, and
# anything else needs a new version in Chart.yaml. Only Helm's "the tag does
# not resolve" reads as unpublished; any other failure, a missing blob of a
# tag that does resolve included, stops the run.
mkdir -p "$work/existing"
if existing_out=$(helm pull "$repo/mcp-gateway" --version "$version" -d "$work/existing" 2>&1); then
  cmp -s "$work/existing/mcp-gateway-$version.tgz" "$work/out/mcp-gateway-$version.tgz" \
    || { echo "chart $version is already published with other contents; bump the version in Chart.yaml" >&2; exit 1; }
elif ! grep -qE "failed to perform \"FetchReference\" on source: [^ ]+/mcp-gateway:${version//./\\.}: not found\$" <<<"$existing_out"; then
  printf 'could not tell whether chart %s is published:\n%s\n' "$version" "$existing_out" >&2
  exit 1
fi
push_out=$(helm push "$work/out/mcp-gateway-$version.tgz" "$repo" 2>&1) \
  || { printf '%s\n' "$push_out" >&2; exit 1; }
printf '%s\n' "$push_out"
chart_digest=$(printf '%s\n' "$push_out" | grep -oE 'sha256:[0-9a-f]{64}' | head -1)
[[ -n $chart_digest ]] || { echo "no chart digest in helm push output" >&2; exit 1; }
# Sign the exact artifact pushed, by digest, never a tag that can move.
chart_ref="${repo#oci://}/mcp-gateway@$chart_digest"
cosign sign --yes "$chart_ref"
cosign verify --certificate-identity "$SIGNER_IDENTITY" \
  --certificate-oidc-issuer "$SIGNER_ISSUER" "$chart_ref" >/dev/null \
  || { echo "chart signature on $chart_ref did not verify" >&2; exit 1; }

# Verify from the registry, not from the local file.
mkdir -p "$work/pulled"
pull_out=$(helm pull "$repo/mcp-gateway" --version "$version" -d "$work/pulled" 2>&1) \
  || { printf '%s\n' "$pull_out" >&2; exit 1; }
printf '%s\n' "$pull_out"
# The version tag can move between push and pull: check the signed artifact.
pulled_digest=$(printf '%s\n' "$pull_out" | grep -oE 'sha256:[0-9a-f]{64}' | head -1)
[[ $pulled_digest == "$chart_digest" ]] \
  || { echo "pulled chart is '$pulled_digest', not the signed $chart_digest" >&2; exit 1; }
published=$(tar -xOzf "$work/pulled/mcp-gateway-$version.tgz" mcp-gateway/values.yaml | yq '.image.digest')
[[ $published == "$digest" ]] || { echo "published chart pins $published, not $digest" >&2; exit 1; }
# And the Deployment it renders runs that exact image.
want="$(yq '.image.registry' "$chart/values.yaml")/$(yq '.image.repository' "$chart/values.yaml")@$digest"
rendered=$(helm template probe "$work/pulled/mcp-gateway-$version.tgz" | yq 'select(.kind == "Deployment") | .spec.template.spec.containers[0].image')
[[ $rendered == "$want" ]] || { echo "rendered image is $rendered, not $want" >&2; exit 1; }
# Written last, from the values just verified, so only a passed publish has notes.
# shellcheck disable=SC2016 # the backticks are Markdown code spans, not expansions
{
  printf '\n### Helm chart\n\nSigned chart `%s` (version %s, image `%s`).\n\n' "$chart_ref" "$version" "$digest"
  printf 'Verify: `cosign verify --certificate-identity %q --certificate-oidc-issuer %q %s`\n\n' \
    "$SIGNER_IDENTITY" "$SIGNER_ISSUER" "$chart_ref"
  printf 'Pull: `helm pull %s/mcp-gateway --version %s` must print `Digest: %s`.\n' "$repo" "$version" "$chart_digest"
  printf '\nThe chart is signed by the release workflow identity above, the identity that signs the image.\n'
} > "$CHART_NOTES"
echo "chart $version pins $digest, signed as $chart_ref"
