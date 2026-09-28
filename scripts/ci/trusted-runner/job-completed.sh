#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Job-completed hook for the project's self-hosted runner. Every job must
# start from nothing a previous job left behind:
#   1. no process: anything a job started that is still running (a daemon in
#      its own session can outlive the job) could rewrite the next job's
#      workspace or toolchain, so every process of the runner user except
#      this hook's own ancestry (worker, listener) is killed first;
#   2. no file: a job could replace the cargo or rustup proxies, edit cargo
#      or git configuration, or alter cached action code, so everything the
#      runner user can write is emptied; the next job downloads it again.
# Each phase runs even if an earlier one fails (a job may have deleted a
# directory to trip `set -e`); the hook then exits non-zero.
#
# Kept: the runner's in-use `_work/_temp` (the runner empties it) and its
# current diagnostics logs; anything else in `_diag` is job-written and goes.
set -uo pipefail

readonly HOME_DIR=${HOME:?}
readonly WORK_ROOT=${MCPGW_RUNNER_WORK_ROOT:-$HOME_DIR/_work}
rc=0

case $HOME_DIR in
  /home/ghr-mcpgw) ;;
  *) [[ ${MCPGW_RUNNER_HOOK_TEST:-} == 1 ]] || { echo "refusing to clean home $HOME_DIR" >&2; exit 1; } ;;
esac

# 1. Processes. The keep set is this shell's ancestry, read from /proc, never
# from process names (a job can name a process anything).
kill_strays() {
  local keep=" " pid=$$ uid
  while [[ $pid -gt 1 ]]; do
    keep+="$pid "
    pid=$(awk '/^PPid:/ { print $2 }' "/proc/$pid/status" 2>/dev/null || echo 1)
  done
  uid=$(id -u)
  local _ p
  for _ in 1 2 3; do
    local found=0
    for p in /proc/[0-9]*; do
      p=${p#/proc/}
      [[ $keep == *" $p "* ]] && continue
      [[ $(awk '/^Uid:/ { print $2 }' "/proc/$p/status" 2>/dev/null) == "$uid" ]] || continue
      kill -KILL "$p" 2>/dev/null && found=1
    done
    [[ $found -eq 0 ]] && return 0
    sleep 1
  done
  echo "processes of the runner user survived three kill rounds" >&2
  return 1
}
if [[ -d /proc/self && $(id -un) == ghr-mcpgw ]]; then
  kill_strays || rc=1
fi

# 2. Files.
mkdir -p "$HOME_DIR/tmp" || rc=1
find "$HOME_DIR" -mindepth 1 -maxdepth 1 ! -name _diag ! -name _work ! -name tmp -exec rm -rf -- {} + || rc=1
# `tmp` is the source of the unit's /tmp bind mount: emptied, never removed.
find "$HOME_DIR/tmp" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || rc=1
if [[ -d $WORK_ROOT ]]; then
  find "$WORK_ROOT" -mindepth 1 -maxdepth 1 ! -name _temp -exec rm -rf -- {} + || rc=1
fi
# ponytail: a job can still grow the current Runner_/Worker_ logs within one
# job; they are cleared once older than a day. Split _diag onto its own
# bounded filesystem if that is ever abused.
if [[ -d $HOME_DIR/_diag ]]; then
  find "$HOME_DIR/_diag" -mindepth 1 \( ! -type f -o ! \( -name 'Runner_*.log' -o -name 'Worker_*.log' \) -o -mmin +1440 \) \
    -prune -exec rm -rf -- {} + || rc=1
fi

[[ $rc -eq 0 ]] && echo "trusted runner state cleaned: $HOME_DIR"
exit $rc
