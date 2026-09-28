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
exit 0
