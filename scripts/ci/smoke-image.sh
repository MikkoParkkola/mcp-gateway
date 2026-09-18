#!/usr/bin/env bash
# Start a built image and require it to reach the HEALTHCHECK's own `healthy`
# verdict. Both image publishers call this: docker.yml on every push and PR,
# ci.yml on a release tag. They are separate workflows firing on the same tag
# and neither can block the other, so each gates itself.
#
# Every other check in those workflows inspects the image at rest -- trivy reads
# layers, cosign signs a digest, syft walks a filesystem. None of them start a
# container, so an image that exits on startup passes all of them and ships.
#
# Reading the container's HEALTHCHECK verdict rather than re-probing /health
# here keeps the line the image ships as the line under test: a HEALTHCHECK
# aimed at the wrong port would otherwise stay green forever. `--rm` is
# deliberately absent -- it would delete the container before the failure
# branches read its logs, which are the only diagnostic this produces.
#
# Usage: smoke-image.sh <image-ref>
set -euo pipefail

IMAGE="${1:?usage: smoke-image.sh <image-ref>}"
NAME="smoke-$$"
WORKDIR="${RUNNER_TEMP:-/tmp}"

trap 'docker rm -f "${NAME}" > /dev/null 2>&1 || true' EXIT

# Minimal config: the loopback bind is the gateway's own default posture, and a
# non-loopback bind without auth is refused by design.
printf 'server:\n  host: 127.0.0.1\n  port: 39400\n' > "${WORKDIR}/smoke.yaml"

docker run -d --name "${NAME}" --pull never \
  -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null

for _ in $(seq 1 45); do
  if [ "$(docker inspect -f '{{.State.Health.Status}}' "${NAME}")" = "healthy" ]; then
    echo "${IMAGE} starts and its own HEALTHCHECK reports healthy"
    exit 0
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "${NAME}")" != "true" ]; then
    echo "::error::${IMAGE} exited on startup"
    docker logs "${NAME}"
    exit 1
  fi
  sleep 2
done

echo "::error::${IMAGE} never reported healthy within 90s"
docker logs "${NAME}"
exit 1
