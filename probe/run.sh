#!/usr/bin/env bash
# MIK-6865 MCPGW.SCHEMA.1 fail-fast probe.
# Exits non-zero when invented nested keys are accepted silently.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --quiet --test mik_6865_nested_key_probe -- --include-ignored
