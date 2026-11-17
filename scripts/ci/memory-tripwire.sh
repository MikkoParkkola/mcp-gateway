#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# memory-tripwire.sh SWAP_LIMIT_MIB [TREND_FILE]: fails the job when it wrote more than SWAP_LIMIT_MIB to swap, read
# from /proc/vmstat's pswpout (pages written to swap since boot; a hosted runner is a fresh VM per job, so the count
# is this job's). On the hosted Linux runner every lib test part writes nothing to swap and a whole lib test build
# about 7 GiB (E1, 2026-11-17), so swap-out past the limit means a whole build came back, however it was launched:
# the swap thrash that starves the runner past its own step timeouts. The kernel keeps the count, so run this as a
# job's last step with `if: always()` and a timed-out step still reports. Fails closed when the count cannot be read.
# The job cgroup's memory.peak is printed for the trend and gates nothing (it counts page cache: parts reach 13.5 GB).
# MEM_VMSTAT and MEM_PEAK_CGROUP point the reads at fixtures (the rows).
set -euo pipefail

limit="${1:?usage: $0 SWAP_LIMIT_MIB [TREND_FILE]}"
trend="${2:-}"
vmstat="${MEM_VMSTAT:-/proc/vmstat}"
dir="${MEM_PEAK_CGROUP:-/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)}"
pages="$(awk '$1 == "pswpout" { print $2 }' "$vmstat" 2>/dev/null || true)"
if ! [[ "$pages" =~ ^[0-9]+$ ]]; then
  echo "::error::memory tripwire: cannot read pswpout from $vmstat, so this job's swap-out is unknown"
  exit 1
fi
swapped=$((pages * $(getconf PAGESIZE) / 1048576))
peak="$(cat "$dir/memory.peak" 2>/dev/null || true)"
if [[ "$peak" =~ ^[0-9]+$ ]]; then peak=$((peak / 1048576)); else peak=unknown; fi
if [ -n "$trend" ]; then
  printf 'swap_out_mib=%s\nmemory_peak_mib=%s\n' "$swapped" "$peak" > "$trend"
fi
echo "memory tripwire: this job wrote $swapped MiB to swap (limit $limit MiB); memory.peak $peak MiB (trend only)"
if [ "$swapped" -gt "$limit" ]; then
  echo "::error::memory tripwire: $swapped MiB written to swap is above $limit MiB; a whole lib test build ran in this job"
  exit 1
fi
