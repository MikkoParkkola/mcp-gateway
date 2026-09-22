#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

IMAGE="${1:?usage: smoke-full-image.sh <image-ref>}"

run_as_gateway() {
  docker run --rm --user 1001:1001 --entrypoint sh "${IMAGE}" -c "$1"
}

fail() {
  echo "::error::${IMAGE}: $1"
  exit 1
}

if ! OUT="$(run_as_gateway 'node --version' 2>&1)"; then
  fail "node is not runnable: ${OUT}"
fi
NODE_MAJOR="$(printf '%s' "${OUT}" | sed -e 's/^v//' -e 's/\..*//')"
case "${NODE_MAJOR}" in
  2[4-9]|[3-9][0-9]) ;;
  *) fail "node major is ${NODE_MAJOR}; this variant ships Node 24" ;;
esac

if ! OUT="$(run_as_gateway 'npx --yes --quiet cowsay@1.6.0 moo' 2>&1)"; then
  fail "npx could not run a package: ${OUT}"
fi
case "${OUT}" in
  *"^__^"*) ;;
  *) fail "npx ran but produced unexpected output: ${OUT}" ;;
esac

if ! OUT="$(run_as_gateway 'uvx --quiet cowsay==6.1 -t moo' 2>&1)"; then
  fail "uvx could not run a package: ${OUT}"
fi
case "${OUT}" in
  *"^__^"*) ;;
  *) fail "uvx ran but produced unexpected output: ${OUT}" ;;
esac

run_as_gateway 'git --version' > /dev/null || fail "git is not runnable"
if ! OUT="$(run_as_gateway 'git ls-remote https://github.com/git/git.git HEAD' 2>&1)"; then
  fail "git could not reach an https remote: ${OUT}"
fi
if [ -z "${OUT}" ]; then
  fail "git reached the remote but resolved no ref"
fi

if ! OUT="$(run_as_gateway 'touch /home/gateway/.npm/.w /home/gateway/.cache/uv/.w' 2>&1)"; then
  fail "cache directories are not writable by uid 1001: ${OUT}"
fi

"$(dirname "$0")/smoke-image.sh" "${IMAGE}"

echo "${IMAGE} spawns npx and uvx backends and its caches are writable by the service user"
