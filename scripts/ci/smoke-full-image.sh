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

# Probe output lands here rather than in a command substitution: `fail` has to
# report and exit from this shell, and inside a substitution it would only exit
# the subshell, leaving the caller to report the same fault again with the
# annotation for its own empty capture.
ANSWER="${RUNNER_TEMP:-/tmp}/smoke-full-answer.$$"
trap 'rm -f "${ANSWER}"' EXIT

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

# The root path of the entrypoint (#729). A deployment starts the container as
# root to get drop-ins and packages; the gateway must still run as uid 1001, and
# a failing drop-in must stop start-up. The `.envsh` drop-in puts a stand-in
# `mcp-gateway` first on PATH, so the process the entrypoint execs reports the
# identity it was given instead of starting a server.
DROPINS="${RUNNER_TEMP:-/tmp}/smoke-full-dropins.$$"
mkdir -p "${DROPINS}/ok" "${DROPINS}/fail"
trap 'rm -f "${ANSWER}"; rm -rf "${DROPINS}"' EXIT
cat > "${DROPINS}/ok/10-mark.sh" <<'DROPIN'
#!/bin/sh
echo "dropin-uid=$(id -u)"
DROPIN
cat > "${DROPINS}/ok/20-shim.envsh" <<'DROPIN'
mkdir -p /tmp/shim
printf '#!/bin/sh\necho "gateway-uid=$(id -u) groups=$(id -G)"\n' > /tmp/shim/mcp-gateway
chmod 0755 /tmp/shim /tmp/shim/mcp-gateway
export PATH="/tmp/shim:${PATH}"
DROPIN
printf '#!/bin/sh\nexit 3\n' > "${DROPINS}/fail/10-fail.sh"
# The shim follows the failing step, so a start that carried on past it would
# exit 0 and say so. Without it the real gateway would refuse for lack of a
# config, and that refusal would pass for the drop-in stopping start-up.
cp "${DROPINS}/ok/20-shim.envsh" "${DROPINS}/fail/20-shim.envsh"
chmod 0755 "${DROPINS}/ok/10-mark.sh" "${DROPINS}/ok/20-shim.envsh" \
  "${DROPINS}/fail/10-fail.sh" "${DROPINS}/fail/20-shim.envsh"

run_as_root() {
  dir="$1"
  shift
  timeout -k 10 "${PROBE_TIMEOUT}" docker run --rm --user root --pull never \
    "$@" -v "${dir}:/docker-entrypoint.d:ro" "${IMAGE}" > "${ANSWER}" 2>&1
}

if ! run_as_root "${DROPINS}/ok"; then
  fail "a root start with drop-ins did not complete: $(cat "${ANSWER}")"
fi
case "$(cat "${ANSWER}")" in
  *"dropin-uid=0"*"gateway-uid=1001 groups=1001"*) ;;
  *) fail "a root start must run drop-ins as root and then exec the gateway as uid 1001 with only its own group: $(cat "${ANSWER}")" ;;
esac

# Exactly the drop-in's own status: a Docker error (125), a probe timeout
# (124) or an unrelated entrypoint failure must not pass for this one.
status=0
run_as_root "${DROPINS}/fail" || status=$?
if [ "${status}" -ne 3 ] || grep -q 'gateway-uid=' "${ANSWER}"; then
  fail "a failing drop-in did not stop start-up with its status 3 (got ${status}): $(cat "${ANSWER}")"
fi

# The install branch itself, in the real image and with no network needed: an
# apt option smuggled into the package list is refused before apt runs.
status=0
run_as_root "${DROPINS}/ok" -e EXTRA_APT_PACKAGES="--simulate iproute2" || status=$?
if [ "${status}" -ne 1 ] || grep -q 'gateway-uid=' "${ANSWER}" \
  || ! grep -q 'EXTRA_APT_PACKAGES' "${ANSWER}"; then
  fail "a root start must refuse an apt option in EXTRA_APT_PACKAGES (got ${status}): $(cat "${ANSWER}")"
fi

"$(dirname "$0")/smoke-image.sh" "${IMAGE}"

echo "${IMAGE} spawns npx and uvx backends and its caches are writable by the service user"
