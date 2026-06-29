#!/usr/bin/env bash
set -euo pipefail

# Live Docker smoke for MIK-6555 RuntimeProvider.
# Requires a reachable Docker daemon. The Rust test starts a restricted
# hello-world container through StdRuntimeCommandRunner, then runs inspect,
# logs, restart, and rm through the same RuntimePlan lifecycle contract. It
# also builds a tiny long-running fixture image and proves Docker on-failure
# restart policy recovery after an intentional non-zero process exit.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker version >/dev/null

export MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1
: "${MCP_GATEWAY_RUNTIME_DOCKER_IMAGE:=docker.io/library/hello-world:latest}"
export MCP_GATEWAY_RUNTIME_DOCKER_IMAGE

cleanup_restart_image=false
if [ -z "${MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE:-}" ]; then
  MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE="mcp-gateway/runtime-provider-restart-fixture:local"
  cleanup_restart_image=true
  fixture_dir="$(mktemp -d)"
  trap 'rm -rf "$fixture_dir"; if [ "$cleanup_restart_image" = true ]; then docker image rm "$MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE" >/dev/null 2>&1 || true; fi' EXIT
  cat >"$fixture_dir/Dockerfile" <<'DOCKERFILE'
FROM docker.io/library/busybox:1.36
CMD ["sh", "-c", "echo runtime-provider-restart-fixture-ready; sleep 2; exit 42"]
DOCKERFILE
  docker build -q -t "$MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE" "$fixture_dir" >/dev/null
fi
export MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE

cd "$repo_root"
cargo test -q runtime_provider_real_docker --lib -- --ignored --nocapture

echo "runtime provider docker smoke passed with images $MCP_GATEWAY_RUNTIME_DOCKER_IMAGE and $MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE"
