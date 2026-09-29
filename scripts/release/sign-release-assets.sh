#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Sign release binaries and ship an SBOM for each (OWASP ASI04).
#
#   IDENTITY=<certificate identity> ISSUER=<oidc issuer> \
#     scripts/release/sign-release-assets.sh DIR VERSION NAME...
#
# For every binary NAME in DIR: an SPDX SBOM from the crate list cargo
# auditable embedded in it, then SHA256SUMS.txt over binaries and SBOMs, then a
# keyless cosign bundle for every binary, SBOM and SHA256SUMS.txt. Then
# verify-release-assets.sh checks every bundle against IDENTITY and ISSUER and
# runs the asset checker, so a release job never publishes what it could not
# verify. Any failure exits non-zero.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: IDENTITY=... ISSUER=... $0 DIR VERSION NAME..." >&2
  exit 2
fi
: "${IDENTITY:?IDENTITY must name the signing workflow}"
: "${ISSUER:?ISSUER must name the OIDC issuer}"

dir="$1"
version="$2"
shift 2
here="$(cd "$(dirname "$0")" && pwd)"
cd "$dir"

for name in "$@"; do
  test -s "$name"
  syft scan "file:$name" \
    --select-catalogers "+cargo-auditable-binary-cataloger" \
    -o "spdx-json=$name.spdx.json"
done

# Written here, after the SBOMs, so it covers them; nothing may rewrite it
# after the signature below.
for name in "$@"; do
  sha256sum -- "$name" "$name.spdx.json"
done > SHA256SUMS.txt

signed=(SHA256SUMS.txt)
for name in "$@"; do
  signed+=("$name" "$name.spdx.json")
done

for file in "${signed[@]}"; do
  cosign sign-blob --yes --bundle "$file.sigstore.json" "$file" > /dev/null
done

# Verified here, before any release exists, by the same script that checks
# the draft release afterwards.
"$here/verify-release-assets.sh" . "$version" "$@"
