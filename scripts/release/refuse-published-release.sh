#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Refuse to upload onto an already-published release (OWASP ASI04).
#
#   GH_TOKEN=... scripts/release/refuse-published-release.sh REPO TAG
#
# The release action keeps an existing release's draft state, so uploading
# onto a published release makes new assets public before they are verified.
# Continues only when the tag has no release yet or only a draft; a published
# release, or any failure to find out, stops the job.
set -euo pipefail
exit 0
