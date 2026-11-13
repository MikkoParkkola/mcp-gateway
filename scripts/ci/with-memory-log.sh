#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# with-memory-log.sh CMD [ARG...]: run CMD and, while it runs, print one line of memory numbers to stderr every
# MEM_LOG_EVERY seconds (default 30), plus a start line and an end line with CMD's exit status. Exits with CMD's
# own status. It never limits time: the step's timeout-minutes does, so a stalled build ends while the runner is
# alive and the step keeps its log (a job cancelled at its own limit keeps none).
#
# Numbers and fixed words only: never a process list, the command or its arguments (they can carry secrets).
# Sources: free -m, /proc/pressure/{memory,io}, /proc/loadavg, the cgroup's memory.current and memory.events;
# "n/a" for any that is missing. MEM_LOG_PROC and MEM_LOG_CGROUP point the reads elsewhere (the tests' stubs).
#
# CMD runs in the background and this shell samples between waits, so no sampler process outlives CMD and
# nothing holds the step's output pipe after it ends. TERM, INT and HUP are passed on to CMD.
# Rows: scripts/ci/test_with_memory_log.py.
set -u
every=${MEM_LOG_EVERY:-30}
case $every in '' | *[!0-9]* | 0) every=30 ;; esac # a whole number of seconds, else the default
proc=${MEM_LOG_PROC:-/proc}
cgroup=${MEM_LOG_CGROUP:-/sys/fs/cgroup}

field() { # field FILE LINE-PREFIX KEY: KEY's value on the line starting with LINE-PREFIX, or n/a
  local v
  v=$(awk -v p="$2" -v k="$3=" '$1 == p { for (i = 2; i <= NF; i++) if (index($i, k) == 1) print substr($i, length(k) + 1) }' "$1" 2>/dev/null)
  echo "${v:-n/a}"
}

sample() { # sample WHAT: one line of numbers on stderr
  local mem swap cg oom load
  mem=$(free -m 2>/dev/null | awk '/^Mem:/ { printf "total %s used %s available %s", $2, $3, $7 }')
  swap=$(free -m 2>/dev/null | awk '/^Swap:/ { printf "total %s used %s", $2, $3 }')
  cg=$(awk '{ printf "%d", $1 / 1048576 }' "$cgroup/memory.current" 2>/dev/null)
  oom=$(awk '$1 == "oom_kill" { print $2 }' "$cgroup/memory.events" 2>/dev/null)
  load=$(awk '{ print $1 }' "$proc/loadavg" 2>/dev/null)
  echo "memory $(date -u +%T) $1: Mem ${mem:-n/a}; Swap ${swap:-n/a};" \
    "pressure mem some $(field "$proc/pressure/memory" some avg10) full $(field "$proc/pressure/memory" full avg10);" \
    "io some $(field "$proc/pressure/io" some avg10); load ${load:-n/a}; cgroup MB ${cg:-n/a} oom_kill ${oom:-n/a}" >&2
}

[ $# -gt 0 ] || { echo "usage: with-memory-log.sh CMD [ARG...]" >&2; exit 2; }
# `wait -n -p` needs bash 5.1. On an older bash, run CMD plainly rather than risk a loop that never ends.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
  echo "memory log: off (bash ${BASH_VERSION} is older than 5.1)" >&2
  exec "$@"
fi
# Any of TERM, INT or HUP reaches CMD as TERM: a command started with & in a non-interactive shell ignores INT
# and cannot trap it, so passing INT on as INT would do nothing. Set before the launch, so no signal falls between.
cmd=
trap '[ -n "$cmd" ] && kill -TERM "$cmd" 2>/dev/null' TERM INT HUP
"$@" &
cmd=$!
sample start
nap=
while :; do
  # One nap at a time: a signal can end the wait below while the nap still runs.
  if [ -z "$nap" ]; then
    sleep "$every" &
    nap=$!
  fi
  done=
  # Wakes when CMD ends (an already-ended CMD counts), when the nap ends, or when a trapped signal arrives
  # (then done is empty and the loop waits again; CMD's own end still wakes it).
  wait -n -p done "$cmd" "$nap" 2>/dev/null
  status=$?
  if [ "${done:-}" = "$cmd" ]; then
    break
  elif [ "${done:-}" = "$nap" ]; then
    nap=
    sample running
  fi
done
if [ -n "$nap" ]; then
  kill "$nap" 2>/dev/null
  wait "$nap" 2>/dev/null
fi
sample "end, exit $status"
exit "$status"
