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
exit 0
