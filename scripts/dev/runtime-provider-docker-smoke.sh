#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# Live Docker smoke for MIK-6555 RuntimeProvider.
# Requires a reachable Docker daemon. The Rust test starts a restricted
# hello-world container through StdRuntimeCommandRunner, then runs inspect,
# logs, restart, and rm through the same RuntimePlan lifecycle contract. It
# also builds a tiny long-running fixture image and proves Docker on-failure
# restart policy recovery after an intentional non-zero process exit.

#
# Usage: runtime-provider-docker-smoke.sh [--prebuilt <dir>]
# With no argument the rows are compiled and run by cargo (a developer's
# machine). CI passes --prebuilt with the folder holding the shared lib test
# part binaries, so nothing compiles there: each row runs from the part binary
# that holds it and must print its own "1 passed" line. There is no skip path:
# no daemon, no folder, a row that selects no test, or a row left ignored all
# end the script non-zero.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

prebuilt=""
case "$#:${1:-}" in
  0:) ;;
  2:--prebuilt)
    prebuilt="$2"
    [ -d "$prebuilt" ] || { echo "runtime provider docker smoke: no part binaries folder at $prebuilt" >&2; exit 2; }
    ;;
  *) echo "usage: $0 [--prebuilt <dir>]" >&2; exit 2 ;;
esac

docker version >/dev/null

export MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1
# Pinned by digest (the multi-arch index), as the restart fixture pins busybox
# 1.36, so the lifecycle row's log check does not follow a moving tag.
: "${MCP_GATEWAY_RUNTIME_DOCKER_IMAGE:=mirror.gcr.io/library/hello-world@sha256:1e4c05b897a751332ce85c7e9449da2d93514ea2dea6dbb0e2753c9e949b2bfa}"
export MCP_GATEWAY_RUNTIME_DOCKER_IMAGE

cleanup_restart_image=false
if [ -z "${MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE:-}" ]; then
  MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE="mcp-gateway/runtime-provider-restart-fixture:local"
  cleanup_restart_image=true
  fixture_dir="$(mktemp -d)"
  trap 'rm -rf "$fixture_dir"; if [ "$cleanup_restart_image" = true ]; then docker image rm "$MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE" >/dev/null 2>&1 || true; fi' EXIT
  cat >"$fixture_dir/Dockerfile" <<'DOCKERFILE'
FROM mirror.gcr.io/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
CMD ["sh", "-c", "echo runtime-provider-restart-fixture-ready; sleep 2; exit 42"]
DOCKERFILE
  docker build -q -t "$MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE" "$fixture_dir" >/dev/null
fi
export MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE

cd "$repo_root"
# One name prefix for both modes, so every Docker provider row a developer runs also runs in CI.
rows=runtime::provider::tests::runtime_provider_real_docker
if [ -z "$prebuilt" ]; then
  cargo test -q "$rows" --lib -- --ignored --nocapture
else
  # run-one refuses unless at least one test sits under the prefix, all on one part.
  # The pass line is required too: at least one passed and none left ignored, since a
  # run without --ignored reports "0 passed; N ignored" and still exits 0.
  rc=0
  out="$(python3 scripts/ci/shard_tests.py run-one --module "$rows" "$prebuilt" -- --ignored --nocapture 2>&1)" || rc=$?
  printf '%s\n' "$out"
  if [ "$rc" != 0 ] || ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored' <<<"$out"; then
    echo "runtime provider docker smoke: the rows under $rows did not pass from the part binaries (exit $rc)" >&2
    exit 1
  fi
fi

echo "runtime provider docker smoke passed with images $MCP_GATEWAY_RUNTIME_DOCKER_IMAGE and $MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE"
