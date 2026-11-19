#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Verify a directory of signed release assets (OWASP ASI04).
#
#   IDENTITY=<certificate identity> ISSUER=<oidc issuer> \
#     scripts/release/verify-release-assets.sh DIR VERSION --doc DOC [--doc DOC]... NAME...
#
# Every binary NAME, its SBOM, every document DOC and SHA256SUMS.txt must carry a cosign bundle
# that verifies against IDENTITY and ISSUER, the checksums must match, and the
# asset checker must pass. Run on the freshly signed files and again on what
# the draft release serves, before the release is published.
set -euo pipefail

usage="usage: IDENTITY=... ISSUER=... $(basename "$0") DIR VERSION --doc NAME [--doc NAME]... BINARY..."
if [ "$#" -lt 2 ]; then
  echo "$usage" >&2
  exit 2
fi
: "${IDENTITY:?IDENTITY must name the signing workflow}"
: "${ISSUER:?ISSUER must name the OIDC issuer}"

dir="$1"
version="$2"
shift 2
docs=()
while [ "$#" -gt 0 ] && [ "$1" = "--doc" ]; do
  if [ "$#" -lt 2 ]; then
    echo "$usage" >&2
    exit 2
  fi
  docs+=("$2")
  shift 2
done
if [ "${#docs[@]}" -eq 0 ] || [ "$#" -eq 0 ]; then
  echo "$usage" >&2
  exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"
cd "$dir"

signed=(SHA256SUMS.txt)
for name in "$@"; do
  signed+=("$name" "$name.spdx.json")
done
signed+=("${docs[@]}")

for file in "${signed[@]}"; do
  if ! cosign verify-blob \
    --bundle "$file.sigstore.json" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$file" > /dev/null; then
    echo "verify-release-assets: $file: signature check failed" >&2
    exit 1
  fi
done

sha256sum -c --strict --quiet SHA256SUMS.txt

doc_args=()
for doc in "${docs[@]}"; do
  doc_args+=(--doc "$doc")
done
python3 "$here/check_release_assets.py" . --version "$version" "${doc_args[@]}" "$@"
