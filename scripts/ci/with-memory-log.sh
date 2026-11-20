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
every=${MEM_LOG_EVERY:-10}
case $every in '' | *[!0-9]*) every=30 ;; esac # digits only, else the default
[ "$((10#$every))" -gt 0 ] || every=30         # all zeros ("0", "00") would sample in a tight loop
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

# Measurement branch only (never merged): peaks, two stop rules and a kill of the whole tree, so a build that would
# starve the runner ends while the runner can still keep this step's log. Numbers and fixed words only.
started=$(date +%s)
peak_used=0 peak_swap=0 peak_rss=0 min_avail=999999 min_disk=999999 rises=0 last_swap=0 avail=999999 reason=
track() { # one probe line, and the running peaks
  local used swap rss disk
  avail=$(free -m | awk '/^Mem:/ { print $7 }')
  used=$(free -m | awk '/^Mem:/ { print $3 }')
  swap=$(free -m | awk '/^Swap:/ { print $3 }')
  rss=$(awk '/^VmRSS:/ { print $2 }' /proc/[0-9]*/status 2>/dev/null | sort -n | tail -1)
  rss=$(( ${rss:-0} / 1024 ))
  disk=$(df -Pm . | awk 'NR == 2 { print $4 }')
  [ "$used" -gt "$peak_used" ] && peak_used=$used
  [ "$swap" -gt "$peak_swap" ] && peak_swap=$swap
  [ "$rss" -gt "$peak_rss" ] && peak_rss=$rss
  [ "$avail" -lt "$min_avail" ] && min_avail=$avail
  [ "$disk" -lt "$min_disk" ] && min_disk=$disk
  if [ "$swap" -gt "$last_swap" ]; then rises=$((rises + 1)); else rises=0; fi
  last_swap=$swap
  echo "probe $(date -u +%T): largest-process-rss-MB $rss disk-free-MB $disk swap-rises $rises" >&2
}
stop_rule() { # S1: memory nearly gone while swap keeps growing; S2: 45 minutes in
  if [ "$avail" -lt 400 ] && [ "$rises" -ge 3 ]; then echo S1
  elif [ $(( $(date +%s) - started )) -ge 2700 ]; then echo S2; fi
}
kill_tree() { # SIGKILL a pid and every descendant: cargo runs in a session of its own
  local all=$1 level=$1 next p
  while [ -n "$level" ]; do
    next=$(for p in $level; do pgrep -P "$p"; done)
    all="$all $next"
    level=$next
  done
  kill -KILL $all 2>/dev/null
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
track
nap=
while :; do
  # bash 5.1 and 5.2 drop a job a signal killed from the job table as soon as they notice the death, so a CMD killed
  # before the wait below (while a sample runs, say: an out-of-memory kill) is never named by `wait -n`, and the loop
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
    track
    reason=$(stop_rule)
    if [ -n "$reason" ]; then
      echo "probe STOP $reason: killing the build and everything under it" >&2
      kill_tree "$cmd"
      wait "$cmd" 2>/dev/null
      status=137
      break
    fi
  fi
done
if [ -n "$nap" ]; then
  kill "$nap" 2>/dev/null
  wait "$nap" 2>/dev/null
fi
echo "probe PEAK used-MB $peak_used min-available-MB $min_avail swap-used-MB $peak_swap" \
  "largest-process-rss-MB $peak_rss min-disk-free-MB $min_disk elapsed-s $(( $(date +%s) - started ))" \
  "stop ${reason:-none}" >&2
sample "end, exit $status"
exit "$status"
