#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# grep_no_test_hook.sh BINARY
#
# Fails unless BINARY is a release build with every debug-only test hook
# compiled out. Each hook below is read only under `cfg(debug_assertions)`,
# so its variable name is in a debug binary and absent from a release one.
# docs/design/surface-4.0.md classifies each as INTERNAL "debug builds only";
# scripts/release/test_grep_no_test_hook.py holds that list and this one
# equal, and fails if a workflow greps for a hook itself instead of calling
# this script.
#
# Fail-closed: the crate name must be found first, so a grep that cannot see
# the binary's content (a wrong path, an archive) fails instead of passing,
# and only grep's "no match" (exit 1) counts as absent; "unreadable" (exit 2)
# fails.

set -uo pipefail

HOOKS=(
  MCP_GATEWAY_TEST_CLOCK
  MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS
  MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN
  MCP_GATEWAY_TEST_HOME_DIR
  MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED
  MCP_GATEWAY_TEST_TRUST_CA
)

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BINARY" >&2
  exit 2
fi
bin=$1

if ! grep -qa -e mcp-gateway "$bin"; then
  echo "::error::$bin could not be inspected: the crate name is not in it"
  exit 1
fi
for hook in "${HOOKS[@]}"; do
  found=0
  grep -qa -e "$hook" "$bin" || found=$?
  if [ "$found" -eq 0 ]; then
    echo "::error::$bin carries the debug-only test hook $hook"
    exit 1
  fi
  if [ "$found" -ne 1 ]; then
    echo "::error::$bin could not be read (grep exit $found)"
    exit 1
  fi
done
echo "$bin: no debug-only test hook (${#HOOKS[@]} checked)"
