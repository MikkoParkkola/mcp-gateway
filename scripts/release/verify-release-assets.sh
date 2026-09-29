#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Verify a directory of signed release assets (OWASP ASI04).
#
#   IDENTITY=<certificate identity> ISSUER=<oidc issuer> \
#     scripts/release/verify-release-assets.sh DIR VERSION NAME...
#
# Every binary NAME, its SBOM and SHA256SUMS.txt must carry a cosign bundle
# that verifies against IDENTITY and ISSUER, the checksums must match, and the
# asset checker must pass. Run on the freshly signed files and again on what
# the draft release serves, before the release is published.
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

signed=(SHA256SUMS.txt)
for name in "$@"; do
  signed+=("$name" "$name.spdx.json")
done

for file in "${signed[@]}"; do
  cosign verify-blob \
    --bundle "$file.sigstore.json" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$file" > /dev/null
done

sha256sum -c --strict --quiet SHA256SUMS.txt

python3 "$here/check_release_assets.py" . --version "$version" "$@"
