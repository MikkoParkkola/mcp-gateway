#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Interface and measurement contract:
#   compile-cgroup.sh CMD [ARG...]; no CMD prints usage and exits 2.
#   MEM_VMSTAT defaults to /proc/vmstat; MEM_CGROUP_ROOT to /sys/fs/cgroup;
#   MEM_PAGESIZE to `getconf PAGESIZE`; MEM_SUDO to sudo (empty disables it);
#   MEM_KILL_WAIT_S to 10 seconds; MEM_POLL_S to 0.2 seconds.
# Create $MEM_CGROUP_ROOT/covpart-<pid>. It is usable only when its
# cgroup.controllers lists memory and its cgroup.kill exists. The child shell
# writes its own pid to cgroup.procs, then execs CMD with arguments unchanged.
# The gate stays outside. Creation, controller, kill-file, or move failure must
# prevent CMD from running, report cgroup=inconclusive, and exit non-zero.
# Read vmstat before CMD; after CMD returns count cgroup.procs as leftovers,
# write 1 to cgroup.kill, poll cgroup.procs every MEM_POLL_S until empty or
# MEM_KILL_WAIT_S expires, THEN read vmstat and memory.peak, THEN rmdir.
# Failure to empty or remove the cgroup fails the verdict, with a diagnostic.
# Forward TERM/INT to the child and still clean up and report its exit status.
# Shell constants: SWAP_LIMIT_MIB=256 and PEAK_LIMIT_MIB=14000.
# Swap-out OR swap-in growth >= the swap limit fails; peak bytes strictly above
# the peak limit fails. Compare before rounding to MiB. Zero swap counts/growth
# are valid; page size and memory.peak must be positive. Missing/non-numeric
# deciding readings fail. D3 leaves the peak rule active until runner evidence
# authorizes changing its named rule constant; it is not report-only yet.
# Print a human line and one record beginning `compile-cgroup:` with exactly
# these key=value pairs, in order:
# cgroup page_size swap_out_mib swap_in_mib peak_mib leftovers cmd_status verdict
# swap_free_mib psi_some_avg10 psi_full_avg10 memstat_pswpin memstat_pswpout
# cgroup is own or inconclusive; verdict is pass or names the first failed rule.
# Unreadable values print na: the last five fields are report-only and never
# change the verdict; unreadable deciding fields fail it.
# Return CMD's non-zero status unchanged; otherwise return 1 on a failed verdict,
# or 0 on success. Always print the record, including after a failed/killed CMD.
# Read every cgroup and /proc file through an external command found on PATH (cat, awk, wc, ...), never a bash
# builtin redirect such as $(<file) or `read < file`: the rows observe reads, and their order, through PATH wrappers.
set -u

SWAP_LIMIT_MIB=256
PEAK_LIMIT_MIB=14000
# Keep the peak gate active until runner measurements justify a reviewed change.
PEAK_RULE_ENABLED=1

if (( $# == 0 )); then
  echo "usage: $0 CMD [ARG...]" >&2
  exit 2
fi

vmstat=${MEM_VMSTAT:-/proc/vmstat}
root=${MEM_CGROUP_ROOT:-/sys/fs/cgroup}
group=$root/covpart-$$
kill_wait=${MEM_KILL_WAIT_S:-10}
poll=${MEM_POLL_S:-0.2}
sudo_cmd=()
if [[ -n ${MEM_SUDO-sudo} ]]; then sudo_cmd=("${MEM_SUDO-sudo}"); fi

cgroup=inconclusive
page_size=na
swap_out_mib=na
swap_in_mib=na
peak_mib=na
leftovers=na
cmd_status=na
verdict=pass
child_pid=
interrupted=0
moved=
created=0

fail() {
  if [[ $verdict == pass ]]; then verdict=$1; fi
  printf 'compile cgroup: %s\n' "$2" >&2
}

# Privilege only the write, never the measured command or the gate's reads.
root_write() {
  # The privileged shell expands these positional arguments, not this shell.
  # shellcheck disable=SC2016
  "${sudo_cmd[@]}" bash -c 'printf "%s\n" "$1" > "$2"' bash "$1" "$2"
}

uint() { [[ $1 =~ ^[0-9]+$ ]]; }
positive() { uint "$1" && ! [[ $1 =~ ^0+$ ]]; }
# Parse snapshots in memory; only the external cat calls read kernel files.
field() {
  local key value rest
  while read -r key value rest; do
    if [[ $key == "$2" ]]; then printf '%s\n' "$value"; fi
  done <<< "$1"
}

forward() {
  interrupted=1
  if [[ -n $child_pid ]]; then kill -s "$1" "$child_pid" 2>/dev/null || :; fi
}
trap 'forward TERM' TERM
trap 'forward INT' INT

collect_report() {
  local meminfo pressure memstat
  meminfo=$(cat /proc/meminfo 2>/dev/null) || meminfo=
  pressure=$(cat /proc/pressure/memory 2>/dev/null) || pressure=
  memstat=$(cat "$group/memory.stat" 2>/dev/null) || memstat=
  free=$(field "$meminfo" 'SwapFree:')
  if uint "$free"; then
    free=$(awk -v n="$free" 'BEGIN { printf "%.0f", int(n / 1024) }')
  else free=na; fi
  some=$(awk '$1 == "some" { for (i=2; i<=NF; i++) if ($i ~ /^avg10=/) { sub(/^avg10=/, "", $i); print $i } }' <<< "$pressure")
  full=$(awk '$1 == "full" { for (i=2; i<=NF; i++) if ($i ~ /^avg10=/) { sub(/^avg10=/, "", $i); print $i } }' <<< "$pressure")
  [[ $some =~ ^[0-9]+([.][0-9]+)?$ ]] || some=na
  [[ $full =~ ^[0-9]+([.][0-9]+)?$ ]] || full=na
  sin=$(field "$memstat" pswpin); uint "$sin" || sin=na
  sout=$(field "$memstat" pswpout); uint "$sout" || sout=na
}

report() {
  printf 'compile cgroup: %s; swap out/in %s/%s MiB, peak %s MiB, leftovers %s, command %s, verdict %s\n' \
    "$cgroup" "$swap_out_mib" "$swap_in_mib" "$peak_mib" "$leftovers" "$cmd_status" "$verdict"
  printf 'compile-cgroup: cgroup=%s page_size=%s swap_out_mib=%s swap_in_mib=%s peak_mib=%s leftovers=%s cmd_status=%s verdict=%s swap_free_mib=%s psi_some_avg10=%s psi_full_avg10=%s memstat_pswpin=%s memstat_pswpout=%s\n' \
    "$cgroup" "$page_size" "$swap_out_mib" "$swap_in_mib" "$peak_mib" "$leftovers" "$cmd_status" "$verdict" \
    "$free" "$some" "$full" "$sin" "$sout"
}

remove_group() {
  if (( created )) && ! "${sudo_cmd[@]}" rmdir "$group"; then
    fail cgroup_remove "could not remove cgroup $group"
  fi
}

# The new child's controller list is authoritative. Enable delegation first
# when the parent exposes subtree_control, preserving its other controllers.
setup() {
  local controllers subtree
  if [[ -e $root/cgroup.subtree_control ]]; then
    subtree=$(cat "$root/cgroup.subtree_control" 2>/dev/null) || return 1
    if ! [[ " $subtree " =~ [[:space:]]memory[[:space:]] ]]; then
      root_write +memory "$root/cgroup.subtree_control" || return 1
    fi
  fi
  "${sudo_cmd[@]}" mkdir "$group" || return 1
  created=1
  controllers=$(cat "$group/cgroup.controllers" 2>/dev/null) || return 1
  [[ " $controllers " =~ [[:space:]]memory[[:space:]] ]] || return 1
  [[ -e $group/cgroup.kill ]] || return 1
}

before=$(cat "$vmstat" 2>/dev/null) || before=
raw_page_size=${MEM_PAGESIZE-$(getconf PAGESIZE 2>/dev/null)}
if positive "$raw_page_size"; then page_size=$raw_page_size; fi

if ! setup; then
  fail cgroup_setup "cgroup is unusable; command was not started"
  collect_report
  remove_group
  report
  exit 1
fi

# A separate acknowledgement distinguishes move failure from any CMD exit
# code. It is outside cgroupfs and never contains command arguments.
moved=$(mktemp "${TMPDIR:-/tmp}/compile-cgroup.XXXXXXXX") || {
  fail cgroup_setup "cannot create child acknowledgement; command was not started"
  collect_report
  remove_group
  report
  exit 1
}

# Job control prevents an asynchronous shell from making SIGINT ignored across
# exec. Only the background subshell joins the cgroup; its PID survives exec.
set -m
(
  trap - TERM INT
  root_write "$BASHPID" "$group/cgroup.procs" || exit 1
  printf 'moved\n' > "$moved" || exit 1
  exec "$@"
) &
child_pid=$!
set +m
# A trapped signal interrupts wait before the child has finished. Repeat wait
# until it returns without a trap, retaining the child's actual exit status.
while :; do
  interrupted=0
  wait "$child_pid"
  cmd_status=$?
  (( interrupted )) || break
done
child_pid=
if [[ $(cat "$moved" 2>/dev/null) == moved ]]; then
  cgroup=own
else
  fail cgroup_move "child could not enter the cgroup; command was not started"
fi
rm -f "$moved"

if (( cmd_status != 0 )); then fail command "command exited with status $cmd_status"; fi

# Count before killing; drain before measuring. Even a failed command can leave
# descendants, and neither killing them nor draining can lower the peak.
if procs=$(cat "$group/cgroup.procs" 2>/dev/null); then
  leftovers=$(awk 'NF { n++ } END { print n+0 }' <<< "$procs")
else
  fail cgroup_procs "cannot read remaining cgroup processes"
fi
if ! root_write 1 "$group/cgroup.kill"; then
  fail cgroup_kill "could not kill remaining cgroup processes"
fi
# Bound draining with Bash elapsed seconds, rounding the configured wait up
# to whole seconds. Always poll once, even when the wait is zero.
wait_seconds=$(awk -v n="$kill_wait" 'BEGIN { print int(n) + (n > int(n)) }')
deadline=$((SECONDS + wait_seconds))
drained=0
while :; do
  if procs=$(cat "$group/cgroup.procs" 2>/dev/null) && [[ -z $procs ]]; then
    drained=1
    break
  fi
  (( SECONDS < deadline )) || break
  sleep "$poll"
done
if (( ! drained )); then fail cgroup_drain "cgroup could not be emptied within $kill_wait seconds"; fi

after=$(cat "$vmstat" 2>/dev/null) || after=
peak=$(cat "$group/memory.peak" 2>/dev/null) || peak=
if [[ $page_size == na ]]; then fail page_size "page size is missing, non-numeric or zero"; fi

# Compare bytes before flooring the displayed MiB. Validate both endpoints:
# absent counters and counter resets must never resemble zero swap growth.
measure_swap() {
  local counter=$1 rule=$2 start end result amount exceeded
  start=$(field "$before" "$counter")
  end=$(field "$after" "$counter")
  if ! uint "$start" || ! uint "$end"; then
    fail "$counter" "cannot read numeric $counter counters"
    return
  fi
  if [[ $page_size == na ]]; then return; fi
  result=$(awk -v a="$start" -v b="$end" -v p="$page_size" -v limit="$SWAP_LIMIT_MIB" '
    BEGIN {
      if (b < a) { print "na reset"; exit }
      bytes = (b-a)*p
      printf "%.0f %d\n", int(bytes/1048576), (bytes >= limit*1048576)
    }') || result=
  read -r amount exceeded <<< "$result"
  if ! uint "$amount" || ! [[ $exceeded =~ ^[01]$ ]]; then
    fail "$counter" "cannot calculate $counter growth (invalid result or counter reset)"
    return
  fi
  printf -v "${rule}_mib" '%s' "$amount"
  if [[ $exceeded == 1 ]]; then fail "$rule" "$rule reached the $SWAP_LIMIT_MIB MiB limit"; fi
}
measure_swap pswpout swap_out
measure_swap pswpin swap_in
if positive "$peak"; then
  peak_mib=$(awk -v n="$peak" 'BEGIN { printf "%.0f", int(n/1048576) }')
  if (( PEAK_RULE_ENABLED )) && awk -v n="$peak" -v limit="$PEAK_LIMIT_MIB" 'BEGIN { exit !(n > limit*1048576) }'; then
    fail peak "peak exceeds the $PEAK_LIMIT_MIB MiB limit"
  fi
else
  fail peak "memory.peak is missing, non-numeric or zero"
fi

# Read report-only cgroup files before removal, then print the final verdict
# after removal so a cleanup failure is included in the single record.
collect_report
remove_group
report
if (( cmd_status != 0 )); then exit "$cmd_status"; fi
[[ $verdict == pass ]]
