#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Six probes, four of them over the network: npx and uvx resolve a package, git
# resolves a remote. Unbounded, a runner whose resolver stops answering does not
# fail this gate -- it waits on the first probe until the job is killed hours
# later, and reports `cancelled` with nothing in the log between the step's first
# line and the cancellation. A gate that hangs is not gating, and it cannot say
# what it waited for.
#
# So every probe runs under `timeout`, which makes a stall bounded and
# self-describing: the probe exits 124, the annotation names the probe and its
# ceiling, and the step goes red in seconds. The budgets are per-probe and
# generous because these solve over the network -- a cold package solve is
# 10-60s when the network answers. A probe hitting its ceiling means the network
# stopped answering, not that the image is wrong.
set -euo pipefail

IMAGE="${1:?usage: smoke-full-image.sh <image-ref>}"

PROBE_TIMEOUT=60
SOLVE_TIMEOUT=180
REMOTE_TIMEOUT=120
PULL_TIMEOUT=300
# The root path's own budget: the install is bounded by INSTALL_TIMEOUT in the
# entrypoint, and a startup step is as slow as the deployment wrote it.
STARTUP_TIMEOUT=300

WORKDIR="${RUNNER_TEMP:-/tmp}"
ROOT_CASE="smoke-full-root-$$"
STOP_CASE="smoke-full-stop-$$"

# Probe output lands here rather than in a command substitution: `fail` has to
# report and exit from this shell, and inside a substitution it would only exit
# the subshell, leaving the caller to report the same fault again with the
# annotation for its own empty capture.
ANSWER="${WORKDIR}/smoke-full-answer.$$"
trap 'rm -f "${ANSWER}"; docker rm -f "${ROOT_CASE}" "${STOP_CASE}" > /dev/null 2>&1 || true' EXIT

# Make the image local before the first probe. On a runner that has not pulled
# this digest, `docker run` writes its pull progress to stderr, and
# run_as_gateway captures stderr as the probe's answer, so `node --version` read
# "Unable to find image ... v24.x" and failed the major check. docker.yml probes
# a locally loaded `:scan-full` tag that no registry has, so pull only when the
# image is absent. smoke-image.sh, run last, also expects the image local
# (`--pull never`). The pull is bounded like every probe, so a registry that
# stops answering fails the step instead of hanging it.
if ! docker image inspect "${IMAGE}" > /dev/null 2>&1 \
  && ! timeout -k 10 "${PULL_TIMEOUT}" docker pull --quiet "${IMAGE}" > /dev/null; then
  echo "::error::${IMAGE}: not present locally and could not be pulled within ${PULL_TIMEOUT}s"
  exit 1
fi

run_as_gateway() {
  docker run --rm --user 1001:1001 --pull never --entrypoint sh "${IMAGE}" \
    -c "timeout -k 10 ${1} ${2}" > "${ANSWER}" 2>&1
}

fail() {
  echo "::error::${IMAGE}: $1"
  exit 1
}

# A timeout and a mutual failure both leave `timeout`'s output empty, so the exit
# code is the only place that distinction survives. Without it the annotation
# reads "node is not runnable: " and sends the reader after the image instead of
# the network.
probe() {
  local rc=0
  run_as_gateway "$1" "$2" || rc=$?
  if [ "${rc}" = 124 ] || [ "${rc}" = 137 ]; then
    fail "$3 did not finish within ${1}s, so the network or the runtime stopped answering: $(cat "${ANSWER}")"
  fi
  return "${rc}"
}

# The root path -- `--user root` with EXTRA_APT_PACKAGES and a mounted startup
# step -- is entrypoint code no other leg reaches: every run above and in
# smoke-image.sh is the image's own user. It installs before it execs, so the
# wait covers the install too.
wait_for_gateway() {
  local name="$1"
  for _ in $(seq 1 $((STARTUP_TIMEOUT / 2))); do
    # Captured and compared, never piped into `grep -q` (pipefail); a
    # container already gone reads as not running.
    running="$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)"
    if [ "${running}" != "true" ]; then
      docker logs "${name}"
      fail "exited during startup"
    fi
    if docker exec "${name}" wget --spider -q http://localhost:39400/health 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  docker logs "${name}"
  fail "never served /health on the root path"
}

if ! probe "${PROBE_TIMEOUT}" 'node --version' node; then
  fail "node is not runnable: $(cat "${ANSWER}")"
fi
NODE_MAJOR="$(sed -e 's/^v//' -e 's/\..*//' "${ANSWER}")"
case "${NODE_MAJOR}" in
  2[4-9]|[3-9][0-9]) ;;
  *) fail "node major is ${NODE_MAJOR}; this variant ships Node 24" ;;
esac

if ! probe "${SOLVE_TIMEOUT}" 'npx --yes --quiet cowsay@1.6.0 moo' npx; then
  fail "npx could not run a package: $(cat "${ANSWER}")"
fi
case "$(cat "${ANSWER}")" in
  *"^__^"*) ;;
  *) fail "npx ran but produced unexpected output: $(cat "${ANSWER}")" ;;
esac

if ! probe "${SOLVE_TIMEOUT}" 'uvx --quiet cowsay==6.1 -t moo' uvx; then
  fail "uvx could not run a package: $(cat "${ANSWER}")"
fi
case "$(cat "${ANSWER}")" in
  *"^__^"*) ;;
  *) fail "uvx ran but produced unexpected output: $(cat "${ANSWER}")" ;;
esac

if ! probe "${PROBE_TIMEOUT}" 'git --version' git; then
  fail "git is not runnable: $(cat "${ANSWER}")"
fi

if ! probe "${REMOTE_TIMEOUT}" 'git ls-remote https://github.com/git/git.git HEAD' 'git ls-remote'; then
  fail "git could not reach an https remote: $(cat "${ANSWER}")"
fi
if [ ! -s "${ANSWER}" ]; then
  fail "git reached the remote but resolved no ref"
fi

if ! probe "${PROBE_TIMEOUT}" 'touch /home/gateway/.npm/.w /home/gateway/.cache/uv/.w' 'the cache write'; then
  fail "cache directories are not writable by uid 1001: $(cat "${ANSWER}")"
fi

"$(dirname "$0")/smoke-image.sh" "${IMAGE}"

# Root path, declared package: the step runs as root and after the install, and
# the gateway it execs is the image's user, not root.
ROOTDIR="${WORKDIR}/smoke-full-root-$$"
mkdir -p "${ROOTDIR}/steps"
cat > "${ROOTDIR}/steps/10-package.sh" <<'STEP'
#!/bin/sh
ip -V > /dev/null 2>&1 || { echo "iproute2 is missing" >&2; exit 1; }
echo "step: ran as uid $(id -u)"
STEP
chmod 0755 "${ROOTDIR}/steps/10-package.sh"
docker run -d --name "${ROOT_CASE}" --pull never --user root \
  -e EXTRA_APT_PACKAGES=iproute2 \
  -v "${ROOTDIR}/steps:/docker-entrypoint.d:ro" \
  -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null
wait_for_gateway "${ROOT_CASE}"
# Matched from a captured string, never through a pipe: under pipefail,
# `grep -q` exits on its first match and the writer's SIGPIPE (141) fails a
# pipeline that did match, once the output outgrows the pipe buffer.
ROOT_LOG="$(docker logs "${ROOT_CASE}" 2>&1)"
grep -q 'step: ran as uid 0' <<< "${ROOT_LOG}" \
  || fail "the startup step did not run as root"
if ! UID_LINE="$(docker exec "${ROOT_CASE}" sh -c 'grep -m1 "^Uid:" /proc/1/status')"; then
  fail "cannot read the uid of the gateway process"
fi
case "${UID_LINE}" in
  *1001*) ;;
  *) fail "the gateway runs as '${UID_LINE}', not the image's user 1001" ;;
esac
docker exec "${ROOT_CASE}" sh -c 'ip -V' > /dev/null \
  || fail "EXTRA_APT_PACKAGES=iproute2 left no ip(8) in the image"
docker rm -f "${ROOT_CASE}" > /dev/null

# Root path, a startup step that fails: the container stops, so a deployment
# hears about it instead of serving from a half-configured start.
FAILDIR="${WORKDIR}/smoke-full-fail-$$"
mkdir -p "${FAILDIR}/steps"
printf '#!/bin/sh\necho "step: refusing to start" >&2\nexit 7\n' \
  > "${FAILDIR}/steps/10-fail.sh"
chmod 0755 "${FAILDIR}/steps/10-fail.sh"
if FAIL_LOG="$(docker run --rm --user root \
      -v "${FAILDIR}/steps:/docker-entrypoint.d:ro" \
      -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
      "${IMAGE}" --config /config.yaml 2>&1)"; then
  fail "a startup step that fails does not stop the container"
fi
grep -q 'step: refusing to start' <<< "${FAIL_LOG}" \
  || fail "the container stopped without running the failing startup step"

# Root path, installed package that does not exist: the install fails and the
# container stops rather than starting without the package it declared. Pointing
# apt at an empty source makes the update fail here rather than at a mirror.
BADDIR="${WORKDIR}/smoke-full-bad-$$"
mkdir -p "${BADDIR}"
printf 'Types: deb\nURIs: file:/nonexistent-smoke-full\nSuites: trixie\nComponents: main\n' \
  > "${BADDIR}/empty.sources"
if BAD_LOG="$(docker run --rm --user root \
      -e EXTRA_APT_PACKAGES=iproute2 \
      -v "${BADDIR}/empty.sources:/etc/apt/sources.list.d/debian.sources:ro" \
      -v /dev/null:/etc/apt/sources.list.d/nodesource.sources:ro \
      -v "${WORKDIR}/smoke.yaml:/config.yaml:ro" \
      "${IMAGE}" --config /config.yaml 2>&1)"; then
  fail "a failed EXTRA_APT_PACKAGES install does not stop the container"
fi
grep -q 'EXTRA_APT_PACKAGES install failed' <<< "${BAD_LOG}" \
  || fail "the container stopped without reporting the failed install"

# Root path, a stop while startup is still running: the entrypoint is PID 1
# then, and PID 1 ignores SIGTERM with no handler installed, so `docker stop`
# would wait out the whole grace period and then SIGKILL. The step stands in for
# an install, which is the same wait.
SLOWDIR="${WORKDIR}/smoke-full-slow-$$"
mkdir -p "${SLOWDIR}/steps"
printf '#!/bin/sh\nsleep 120\n' > "${SLOWDIR}/steps/10-slow.sh"
chmod 0755 "${SLOWDIR}/steps/10-slow.sh"
docker run -d --name "${STOP_CASE}" --pull never --user root \
  -v "${SLOWDIR}/steps:/docker-entrypoint.d:ro" \
  "${IMAGE}" --config /config.yaml > /dev/null
sleep 3
STARTED="$(date +%s)"
docker stop -t 30 "${STOP_CASE}" > /dev/null
ELAPSED="$(( $(date +%s) - STARTED ))"
if [ "${ELAPSED}" -ge 15 ]; then
  fail "docker stop took ${ELAPSED}s during startup: the entrypoint ignored SIGTERM"
fi
STOP_EXIT="$(docker inspect -f '{{.State.ExitCode}}' "${STOP_CASE}")"
[ "${STOP_EXIT}" != "137" ] \
  || fail "the entrypoint was SIGKILLed during startup (exit 137)"
docker rm -f "${STOP_CASE}" > /dev/null

echo "${IMAGE} spawns npx and uvx backends, its caches are writable by the service user, and its root path installs, drops privileges, stops on a failing step or install, and stops promptly on TERM"
