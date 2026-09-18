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

# This gate's verdict IS the image's HEALTHCHECK, so an image that declares none
# has nothing to read: say so in seconds rather than timing out in 90 with a
# message that blames the gateway for a missing Dockerfile line. An inspect that
# fails outright is a different fault -- an image that never loaded, or no daemon
# -- and must not be reported as a missing HEALTHCHECK.
if ! HEALTHCHECK="$(docker inspect -f '{{if .Config.Healthcheck}}declared{{end}}' "${IMAGE}")"; then
  echo "::error::cannot inspect ${IMAGE}: it was never loaded, or the daemon is unreachable"
  exit 1
fi
if [ -z "${HEALTHCHECK}" ]; then
  echo "::error::${IMAGE} declares no HEALTHCHECK, which is the verdict this gate reads"
  exit 1
fi

docker run -d --name "${NAME}" --pull never \
  -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null

for _ in $(seq 1 45); do
  STATUS="$(docker inspect -f '{{.State.Health.Status}}' "${NAME}")"
  if [ "${STATUS}" = "healthy" ]; then
    echo "${IMAGE} starts and its own HEALTHCHECK reports healthy"
    exit 0
  fi
  # `unhealthy` is already the HEALTHCHECK's own verdict after its configured
  # retries, so waiting out the rest of the budget cannot change it.
  if [ "${STATUS}" = "unhealthy" ]; then
    echo "::error::${IMAGE} started but its own HEALTHCHECK reports unhealthy"
    docker logs "${NAME}"
    exit 1
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
