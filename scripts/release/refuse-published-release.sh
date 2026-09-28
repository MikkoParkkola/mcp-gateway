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

if [ "$#" -ne 2 ]; then
  echo "usage: $0 REPO TAG" >&2
  exit 2
fi
repo="$1"
tag="$2"

# The list, not /releases/tags/TAG: that endpoint does not return drafts, so
# it cannot tell "no release" from "only a draft". Under pipefail a failed
# call exits non-zero and stops the job. The tag reaches jq as an argument,
# never as filter text.
states="$(gh api --paginate "repos/$repo/releases" | jq -r --arg tag "$tag" '.[] | select(.tag_name == $tag) | .draft')"

case "$states" in
  "")
    echo "no release for $tag yet"
    ;;
  *false*)
    echo "::error::release $tag is already published; fix forward with a new version (RELEASING.md)" >&2
    exit 1
    ;;
  *)
    echo "release $tag exists only as a draft"
    ;;
esac
