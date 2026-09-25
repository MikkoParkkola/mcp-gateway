#!/usr/bin/env bash
set -euo pipefail
source ~/.cargo/env 2>/dev/null || true
# Override any of these; the recorded run used host-specific paths.
WT="${WT:-$HOME/perf-remeasure-4.0.0}"
LOG="${LOG:-$HOME/bench-logs/v4-perf}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/bench-targets/v4-perf}"
cd "$WT"
echo "=== BEFORE: v3.5.0 32f135a6 ==="
git checkout --detach 32f135a61fb50c20a044fb4c2347bc1cf8015d89 --quiet
git rev-parse HEAD
cargo bench --bench gateway_benchmarks 2>&1 | tee "$LOG/before-3.5.0.log"
echo "=== AFTER: main bd1adbb4 ==="
git checkout --detach bd1adbb42fa983a8f93038189707a77e65f83547 --quiet
git rev-parse HEAD
cargo bench --bench gateway_benchmarks 2>&1 | tee "$LOG/after-main.log"
echo "=== BENCH COMPLETE ==="
