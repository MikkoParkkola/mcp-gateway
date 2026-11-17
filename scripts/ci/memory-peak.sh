#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# memory-peak.sh LIMIT_MIB [TREND_FILE]: the job's peak memory, from its cgroup's memory.peak, which the kernel keeps
# for every process of the job. Fails above LIMIT_MIB: on the hosted Linux runner a whole lib test build peaks near
# 15 GB and each part near 11 GB, so a peak above 13 GB means a whole build came back, however it was launched.
# Fails closed when memory.peak cannot be read. Run it as a job's last step with `if: always()`, so a step timeout
# still reports. MEM_PEAK_CGROUP points the read at a fixture directory (the rows).
set -euo pipefail

limit="${1:?usage: $0 LIMIT_MIB [TREND_FILE]}"
trend="${2:-}"
dir="${MEM_PEAK_CGROUP:-/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)}"
if ! peak_bytes="$(cat "$dir/memory.peak" 2>/dev/null)" || ! [[ "$peak_bytes" =~ ^[0-9]+$ ]]; then
  echo "::error::memory tripwire: cannot read $dir/memory.peak, so this job's peak is unknown"
  exit 1
fi
peak=$((peak_bytes / 1048576))
if [ -n "$trend" ]; then
  echo "memory_peak_mib=$peak" > "$trend"
fi
echo "memory tripwire: this job peaked at $peak MiB (limit $limit MiB)"
if [ "$peak" -gt "$limit" ]; then
  echo "::error::memory tripwire: $peak MiB is above $limit MiB; a whole lib test build ran in this job"
  exit 1
fi
