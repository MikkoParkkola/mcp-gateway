#!/bin/bash
# MIK-8408 throwaway: alternating A,B pairs of the replay probe, load logged before each run.
# usage: mik8408_pairs.sh <dir with A.bin and B.bin> <pairs>
set -u
cd "$1" || exit 1
for i in $(seq 1 "$2"); do
  for v in A B; do
    echo "RUN pair=$i v=$v load=$(cut -d' ' -f1 /proc/loadavg)"
    ./$v.bin zz_replay_ab --nocapture --test-threads=1 2>&1 | grep -oE '(PROBEREPLAY|PROBEBAD).*|test result.*|panicked.*'
  done
done
echo DONE
