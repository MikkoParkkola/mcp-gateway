#!/bin/sh
# MCPGW.SCHEMA.1 — nested-schema invented-key probe (MIK-6865).
# Heavy cargo belongs on Spark: ~/.claude/bin/spark-run -- "$0"
set -eu
cd "$(dirname "$0")/.."
cargo test --lib nested_object_array_probe_accept_rate_is_zero -- --nocapture
