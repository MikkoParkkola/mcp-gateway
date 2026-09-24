#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Start a built image and require it to satisfy NFR.PKG.1, whose wording is
# "the container image the release publishes starts, and serves an MCP request
# from outside the container". Both image publishers call this: docker.yml on
# every push and PR, ci.yml on a release tag. They are separate workflows firing
# on the same tag and neither can block the other, so each gates itself.
#
# Every other check in those workflows inspects the image at rest -- trivy reads
# layers, cosign signs a digest, syft walks a filesystem. None of them start a
# container, so an image that exits on startup passes all of them and ships.
#
# Three legs, because one of them alone is a gate that agrees with itself:
#
#   1. The image's own HEALTHCHECK reaches `healthy`. Reading the shipped line
#      rather than re-probing keeps it under test. But the HEALTHCHECK probes
#      from inside, where a loopback bind answers and a published port reaches
#      nothing -- exactly the defect NFR.PKG.1 records -- so it cannot be the
#      only evidence, and a degenerate one (`CMD true`, or a probe aimed at a
#      port nothing serves) would keep this leg green forever. Hence the
#      assertion on the probe itself before any container starts.
#   2. A real MCP request over a published port, made from the runner. This is
#      the clause the HEALTHCHECK cannot speak to.
#   3. The image as an operator first runs it: no mount, no arguments, the
#      Dockerfile's own CMD. The image ships no `/config.yaml`, so the intended
#      behaviour is a refusal that names the missing file -- a gateway that
#      invented a default config would start with a posture nobody chose. The
#      failure this leg exists to catch is a panic, a silent success, or a
#      message that does not tell the operator what to mount.
#
# `--rm` is deliberately absent -- it would delete the container before the
# failure branches read its logs, which are the only diagnostic this produces.
#
# Usage: smoke-image.sh <image-ref>
set -euo pipefail

IMAGE="${1:?usage: smoke-image.sh <image-ref>}"
NAME="smoke-$$"
EXTERNAL="smoke-ext-$$"
DEFAULTS="smoke-default-$$"
WORKDIR="${RUNNER_TEMP:-/tmp}"
# Published on loopback only: a CI runner is not a place to expose an
# unauthenticated gateway to its network. The port itself is Docker's to choose
# (`-p 127.0.0.1::39400`, read back below): a fixed one is answerable by whatever
# already holds it, and leg 2 cannot tell that apart from the container serving.
# A gateway listening on the host satisfies the assertion while the container
# under test serves nobody -- observed on 39401, where a developer machine's own
# gateway answered `initialize` and the leg passed green. The same collision
# voided a performance run before any rep (RELEASE-4.0.0-performance-contract.md,
# Amendment 3), and two agents running this gate at once would collide too.
# Docker hands out a free port, so only the container's own forward can answer.

trap 'docker rm -f "${NAME}" "${EXTERNAL}" "${DEFAULTS}" > /dev/null 2>&1 || true' EXIT

# Minimal config: the loopback bind is the gateway's own default posture, and a
# non-loopback bind without auth is refused by design.
printf 'server:\n  host: 127.0.0.1\n  port: 39400\n' > "${WORKDIR}/smoke.yaml"
# The external leg has to bind the container's own external interface, and the
# gateway refuses that combination without either authentication or this
# acknowledgement. A throwaway container on a loopback-published port is the
# case the setting exists to name.
printf 'server:\n  host: 0.0.0.0\n  port: 39400\n  allow_unauthenticated_network_bind: true\n' \
  > "${WORKDIR}/smoke-external.yaml"

# This gate's verdict IS the image's HEALTHCHECK, so an image that declares none
# has nothing to read: say so in seconds rather than timing out in 90 with a
# message that blames the gateway for a missing Dockerfile line. An inspect that
# fails outright is a different fault -- an image that never loaded, or no daemon
# -- and must not be reported as a missing HEALTHCHECK.
if ! PROBE="$(docker inspect -f '{{json .Config.Healthcheck.Test}}' "${IMAGE}")"; then
  echo "::error::cannot inspect ${IMAGE}: it was never loaded, or the daemon is unreachable"
  exit 1
fi
if [ -z "${PROBE}" ] || [ "${PROBE}" = "null" ]; then
  echo "::error::${IMAGE} declares no HEALTHCHECK, which is the verdict this gate reads"
  exit 1
fi
# A HEALTHCHECK is only evidence if it probes the thing under test. `CMD true`,
# `NONE`, or a probe aimed at some other endpoint all satisfy "declared" while
# proving nothing, and leg 1 would stay green through every one of them.
case "${PROBE}" in
  *'"NONE"'*)
    echo "::error::${IMAGE} disables its inherited HEALTHCHECK (NONE)"
    exit 1
    ;;
esac
# /livez, not /health: /health fails whenever any backend is down, which is not
# a reason to call the container unhealthy.
if ! printf '%s' "${PROBE}" | grep -q '/livez'; then
  echo "::error::${IMAGE}'s HEALTHCHECK does not probe /livez, so leg 1 proves nothing: ${PROBE}"
  exit 1
fi
if ! printf '%s' "${PROBE}" | grep -q '39400'; then
  echo "::error::${IMAGE}'s HEALTHCHECK does not probe the served port 39400: ${PROBE}"
  exit 1
fi

# Leg 1 -- the image starts and its own HEALTHCHECK agrees.
docker run -d --name "${NAME}" --pull never \
  -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null

HEALTHY=
for _ in $(seq 1 45); do
  STATUS="$(docker inspect -f '{{.State.Health.Status}}' "${NAME}")"
  if [ "${STATUS}" = "healthy" ]; then
    HEALTHY=yes
    break
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
if [ -z "${HEALTHY}" ]; then
  echo "::error::${IMAGE} never reported healthy within 90s"
  docker logs "${NAME}"
  exit 1
fi
docker rm -f "${NAME}" > /dev/null

# Leg 2 -- the clause the HEALTHCHECK cannot speak to: an MCP request crossing
# the container boundary. A loopback-bound gateway passes leg 1 and fails here,
# which is the whole point of running it.
docker run -d --name "${EXTERNAL}" --pull never \
  -p "127.0.0.1::39400" \
  -v "${WORKDIR}/smoke-external.yaml:/config.yaml:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null

# Read back what Docker allocated. An empty readback means the mapping never
# happened, and curling a portless URL would fail for the wrong reason.
HOST_PORT="$(docker port "${EXTERNAL}" 39400/tcp | head -1 | sed 's/.*://')"
: "${HOST_PORT:?docker published no host port for 39400/tcp}"

REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke-image","version":"0"}}}'
ANSWER=
for _ in $(seq 1 30); do
  if [ "$(docker inspect -f '{{.State.Running}}' "${EXTERNAL}")" != "true" ]; then
    echo "::error::${IMAGE} exited when asked to bind a published port"
    docker logs "${EXTERNAL}"
    exit 1
  fi
  # A JSON-RPC envelope is the assertion, not a 200: a version or capability
  # mismatch answers with an `error` member and still proves the image served
  # an MCP request from outside the container, which is what NFR.PKG.1 asks.
  # A connection refused, a hang, or an empty body all fail it.
  if BODY="$(curl -fsS --max-time 5 \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d "${REQUEST}" \
      "http://127.0.0.1:${HOST_PORT}/mcp" 2>/dev/null)" \
     && printf '%s' "${BODY}" | grep -q '"jsonrpc"'; then
    ANSWER="${BODY}"
    break
  fi
  sleep 2
done
if [ -z "${ANSWER}" ]; then
  echo "::error::${IMAGE} never answered an MCP request on published port ${HOST_PORT} within 60s"
  docker logs "${EXTERNAL}"
  exit 1
fi
# The same HEALTHCHECK on a 0.0.0.0 bind with no public_url. There the Host gate
# admits only numeric hosts, so a probe dialling `localhost` drew 403 and the
# image called itself unhealthy while serving the request above.
STATUS=
for _ in $(seq 1 45); do
  STATUS="$(docker inspect -f '{{.State.Health.Status}}' "${EXTERNAL}")"
  [ "${STATUS}" = "starting" ] || break
  sleep 2
done
if [ "${STATUS}" != "healthy" ]; then
  echo "::error::${IMAGE}'s HEALTHCHECK reports ${STATUS} on a 0.0.0.0 bind"
  docker logs "${EXTERNAL}"
  exit 1
fi
docker rm -f "${EXTERNAL}" > /dev/null

# Leg 3 -- the default invocation. No mount, no arguments: whatever the
# Dockerfile's ENTRYPOINT and CMD do on their own.
DEFAULT_LOG="${WORKDIR}/smoke-default.log"
if docker run --name "${DEFAULTS}" --pull never "${IMAGE}" > "${DEFAULT_LOG}" 2>&1; then
  echo "::error::${IMAGE} exited 0 with no config; an operator gets no gateway and no diagnostic"
  cat "${DEFAULT_LOG}"
  exit 1
fi
# The refusal has to name the file the operator must supply. A panic, a stack
# trace, or a bare non-zero exit is the failure this leg catches.
if ! grep -q '/config.yaml' "${DEFAULT_LOG}"; then
  echo "::error::${IMAGE} refused to start without a config but never named /config.yaml"
  cat "${DEFAULT_LOG}"
  exit 1
fi
if grep -qi 'panicked at' "${DEFAULT_LOG}"; then
  echo "::error::${IMAGE} panics when run with no config instead of refusing cleanly"
  cat "${DEFAULT_LOG}"
  exit 1
fi
docker rm -f "${DEFAULTS}" > /dev/null

echo "${IMAGE} starts, reports healthy, serves an MCP request from outside the container, and refuses cleanly with no config"
