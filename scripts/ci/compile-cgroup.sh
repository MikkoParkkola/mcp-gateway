#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# RED stub; interface for the implementation to follow:
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
exit 0
