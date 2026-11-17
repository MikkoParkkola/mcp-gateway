#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# memory-tripwire.sh SWAP_LIMIT_MIB [TREND_FILE]: fails the job when it wrote more than SWAP_LIMIT_MIB to swap, read
# from /proc/vmstat's pswpout (pages written to swap since boot; a hosted runner is a fresh VM per job, so the count
# is this job's). On the hosted Linux runner every lib test part writes nothing to swap and a whole lib test build
# about 7 GiB (E1, 2026-11-17), so swap-out past the limit means a whole build came back, however it was launched:
# the swap thrash that starves the runner past its own step timeouts. The kernel keeps the count, so run this as a
# job's last step with `if: always()` and a timed-out step still reports. zswap's writes (zswpout) count too: they
# keep compressed pages off the swap device. Fails closed when the count cannot be read, and when no swap is active
# (a whole build could not swap there, so a zero count would pass it). The job cgroup's memory.peak, the runner's RAM
# and its swap size are printed for the trend and gate nothing (memory.peak counts page cache: parts reach 13.5 GB).
# MEM_VMSTAT, MEM_SWAPS, MEM_MEMINFO and MEM_PEAK_CGROUP point the reads at fixtures (the rows).
set -euo pipefail

limit="${1:?usage: $0 SWAP_LIMIT_MIB [TREND_FILE]}"
trend="${2:-}"
vmstat="${MEM_VMSTAT:-/proc/vmstat}"
swaps="${MEM_SWAPS:-/proc/swaps}"
meminfo="${MEM_MEMINFO:-/proc/meminfo}"
dir="${MEM_PEAK_CGROUP:-/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)}"
pages="$(awk '$1 == "pswpout" { print $2 }' "$vmstat" 2>/dev/null || true)"
if ! [[ "$pages" =~ ^[0-9]+$ ]]; then
  echo "::error::memory tripwire: cannot read pswpout from $vmstat, so this job's swap-out is unknown"
  exit 1
fi
zpages="$(awk '$1 == "zswpout" { print $2 }' "$vmstat" 2>/dev/null || true)"
[[ "$zpages" =~ ^[0-9]+$ ]] || zpages=0
swap_kib="$(awk 'NR > 1 { kib += $3 } END { print kib + 0 }' "$swaps" 2>/dev/null || echo 0)"
if [ "$swap_kib" -eq 0 ]; then
  echo "::error::memory tripwire: no active swap in $swaps, so swap-out cannot tell a whole lib test build from a part"
  exit 1
fi
swapped=$(((pages + zpages) * $(getconf PAGESIZE) / 1048576))
mem_kib="$(awk '$1 == "MemTotal:" { print $2 }' "$meminfo" 2>/dev/null || true)"
[[ "$mem_kib" =~ ^[0-9]+$ ]] || mem_kib=0
peak="$(cat "$dir/memory.peak" 2>/dev/null || true)"
if [[ "$peak" =~ ^[0-9]+$ ]]; then peak=$((peak / 1048576)); else peak=unknown; fi
if [ -n "$trend" ]; then
  printf 'swap_out_mib=%s\nmemory_peak_mib=%s\nmem_total_mib=%s\nswap_total_mib=%s\n' \
    "$swapped" "$peak" "$((mem_kib / 1024))" "$((swap_kib / 1024))" > "$trend"
fi
echo "memory tripwire: this job wrote $swapped MiB to swap (limit $limit MiB); memory.peak $peak MiB (trend only)"
if [ "$swapped" -gt "$limit" ]; then
  echo "::error::memory tripwire: this job wrote $swapped MiB to swap, above $limit MiB; on this runner a lib test part swaps nothing and a whole lib test build about 7 GiB"
  exit 1
fi
