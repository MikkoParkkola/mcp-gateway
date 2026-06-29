#!/usr/bin/env bash
set -euo pipefail

# Live Docker smoke for MIK-6555 RuntimeProvider.
# Requires a reachable Docker daemon. The Rust test starts a restricted
# hello-world container through StdRuntimeCommandRunner, then runs inspect,
# logs, restart, and rm through the same RuntimePlan lifecycle contract.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker version >/dev/null

export MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1
: "${MCP_GATEWAY_RUNTIME_DOCKER_IMAGE:=docker.io/library/hello-world:latest}"
export MCP_GATEWAY_RUNTIME_DOCKER_IMAGE

cd "$repo_root"
cargo test -q runtime_provider_real_docker_smoke_exercises_lifecycle --lib -- --ignored --nocapture

echo "runtime provider docker smoke passed with image $MCP_GATEWAY_RUNTIME_DOCKER_IMAGE"
