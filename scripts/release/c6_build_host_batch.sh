#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Release gate day, check C6, on the Linux build host. Usage:
#   FREEZE_SHA=<frozen commit> STAMP=<stamp> SLOT=<batch numbers> c6_build_host_batch.sh
# Every listed batch is cloned from its c6-gate branch into a new directory under HOME and
# judged in turn; the gate-day procedure gives each build-host slot its own list. A batch's
# run.log starts with the host, CPU architecture and toolchain versions, then the harness.
# Exit 1 on a STOP; otherwise the worst harness exit across the list.
# C6_REPO replaces the clone URL; only the offline test sets it.
set -uo pipefail
: "${FREEZE_SHA:?set FREEZE_SHA}" "${STAMP:?set STAMP}" "${SLOT:?set SLOT}"
repo=${C6_REPO:-https://github.com/MikkoParkkola/mcp-gateway.git}
worst=0
export RUSTFLAGS=--cap-lints=warn CARGO_TERM_COLOR=never
for b in $SLOT; do
  n=$STAMP$b; d=$HOME/c6-gate-$n
  [ ! -e "$d" ] || { echo "STOP: $d exists; every attempt gets a fresh directory" >&2; exit 1; }
  # The checkout is $d/src: the harness runs git clean in it after every row, so out/ and
  # run.log stay beside it, outside the clean.
  { git clone -q "$repo" "$d/src" && cd "$d/src" &&
    git fetch -q origin "throwaway/c6-gate-$n" && git switch -q -c "throwaway/mutants-$n" FETCH_HEAD; } ||
    { echo "STOP: batch $b could not be checked out" >&2; exit 1; }
  [ "$(git rev-parse HEAD^)" = "$FREEZE_SHA" ] || { echo "STOP: batch $b does not sit on FREEZE_SHA" >&2; exit 1; }
  # The toolchain is the one the batch's own mutants.yml gives CI: exactly one distinct pin, no default.
  pin=$(sed -n 's/^[[:space:]]*toolchain:[[:space:]]*\([^[:space:]#]*\).*/\1/p' .github/workflows/mutants.yml 2>/dev/null | sort -u)
  [ -n "$pin" ] && [ "$(printf '%s\n' "$pin" | wc -l)" -eq 1 ] ||
    { echo "STOP: mutants.yml must pin exactly one toolchain; found: ${pin:-none}" | tr '\n' ' ' >&2; echo >&2; exit 1; }
  export RUSTUP_TOOLCHAIN=$pin
  rustup toolchain install "$pin" --profile minimal > /dev/null || { echo "STOP: cannot install Rust $pin" >&2; exit 1; }
  case "$(rustc -V)" in "rustc $pin "*) ;; *) echo "STOP: rustc is $(rustc -V), not $pin" >&2; exit 1 ;; esac
  echo "batch $b start $(date -u +%FT%TZ) batch_sha $(git rev-parse HEAD)" | tee "$d/run.log"
  { echo "host $(hostname) arch $(uname -m) cores $(nproc)"; rustc -V; cargo -V; } 2>&1 | tee -a "$d/run.log"
  # plan reads the batch's name from GITHUB_REF; RUNNER_NAME labels the results.
  GITHUB_REF="refs/heads/throwaway/mutants-$n" RUNNER_NAME="build-host-$n" \
    python3 scripts/ci/mutants/run_mutants.py run --platform linux --out "$d/out" 2>&1 | tee -a "$d/run.log"
  rc=${PIPESTATUS[0]}
  echo "batch $b end $(date -u +%FT%TZ) exit $rc" | tee -a "$d/run.log"
  [ "$rc" -le "$worst" ] || worst=$rc
done
exit "$worst"
