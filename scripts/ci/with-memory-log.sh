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
case $every in '' | *[!0-9]*) every=30 ;; esac # digits only, else the default
[ "$((10#$every))" -gt 0 ] || every=30         # all zeros ("0", "00") would sample in a tight loop
proc=${MEM_LOG_PROC:-/proc}
cgroup=${MEM_LOG_CGROUP:-/sys/fs/cgroup}

# The sampler holds no command substitution, nor any other form of a nested command (row W19): bash parses a trap's
# action when the signal arrives, and a substitution open at that moment breaks the parse, so the signal was lost or
# bash aborted. Values are read with builtins only.
field() { # field VAR FILE LINE-PREFIX KEY: set VAR to KEY's value on the line starting with LINE-PREFIX, or n/a
  local words word
  printf -v "$1" n/a
  while read -ra words || [ "${#words[@]}" -gt 0 ]; do
    [ "${words[0]-}" = "$3" ] || continue
    for word in "${words[@]:1}"; do
      if [ "${word#"$4="}" != "$word" ] && [ -n "${word#"$4="}" ]; then
        printf -v "$1" %s "${word#"$4="}"
        return 0
      fi
    done
  done 2>/dev/null <"$2"
}

sample() { # sample WHAT: one line of numbers on stderr
  # free runs first in a pipeline whose reader is a subshell: never the wrapper's own process, and nothing is
  # carried back to it, so it needs no substitution and no temporary file.
  free -m 2>/dev/null | (
    mem=n/a swap=n/a load=n/a cg=n/a oom=n/a bytes=
    while read -r name total used free shared cache available rest; do
      case $name in
        Mem:) mem="total $total used $used available $available" ;;
        Swap:) swap="total $total used $used" ;;
      esac
    done
    read -r load rest 2>/dev/null <"$proc/loadavg"
    [ -n "$load" ] || load=n/a
    read -r bytes rest 2>/dev/null <"$cgroup/memory.current"
    case $bytes in '' | *[!0-9]*) ;; *) ((cg = 10#$bytes / 1048576)) ;; esac
    while read -r name value rest; do
      [ "$name" != oom_kill ] || oom=${value:-n/a}
    done 2>/dev/null <"$cgroup/memory.events"
    field some "$proc/pressure/memory" some avg10
    field full "$proc/pressure/memory" full avg10
    field io "$proc/pressure/io" some avg10
    TZ=UTC printf -v now '%(%T)T' -1
    printf '%s %s\n' "memory $now $1: Mem $mem; Swap $swap; pressure mem some $some full $full; io some $io;" \
      "load $load; cgroup MB $cg oom_kill $oom" >&2
  )
}

[ $# -gt 0 ] || { echo "usage: with-memory-log.sh CMD [ARG...]" >&2; exit 2; }
# `wait -n -p` needs bash 5.1. On an older bash, run CMD plainly rather than risk a loop that never ends.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
  echo "memory log: off (bash ${BASH_VERSION} is older than 5.1)" >&2
  exec "$@"
fi
# Any of TERM, INT or HUP reaches CMD as TERM: a command started with & in a non-interactive shell ignores INT
# and cannot trap it, so passing INT on as INT would do nothing. The trap is set before the launch;
# one that lands before CMD's pid is known is held in `pending` and sent on the line after (rows W14, W15).
cmd=
pending=
trap 'if [ -z "$cmd" ]; then pending=1; else kill -TERM "$cmd" 2>/dev/null; fi' TERM INT HUP
"$@" &
# Keep the next line a single simple command: row W14's hook matches its exact text.
cmd=$!
[ -z "$pending" ] || kill -TERM "$cmd" 2>/dev/null
sample start
nap=
while :; do
  # bash 5.1 and 5.2 drop a job a signal killed from the job table as soon as they notice the death, so a CMD killed
  # before the wait below (while a sample runs, say: an out-of-memory kill) is never named by "wait -n", and the loop
  # would wake only for naps until the step limit. Its pid is gone then: collect the status bash saved for it.
  if ! kill -0 "$cmd" 2>/dev/null; then
    wait "$cmd" 2>/dev/null
    status=$?
    break
  fi
  # One nap at a time: a signal can end the wait below while the nap still runs.
  if [ -z "$nap" ]; then
    sleep "$every" &
    nap=$!
  fi
  ended=
  # Wakes when CMD ends (an exited CMD counts even if it ended first; a killed one may be dropped, see above), when
  # the nap ends, or when a trapped signal arrives (then ended is empty and the loop waits again).
  wait -n -p ended "$cmd" "$nap" 2>/dev/null
  status=$?
  if [ "${ended:-}" = "$cmd" ]; then
    break
  elif [ "${ended:-}" = "$nap" ]; then
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
