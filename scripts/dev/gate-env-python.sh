#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Print the interpreter of the gates' pinned environment (scripts/gate-env),
# or refuse with the command that builds it. Installs nothing: `uv run` would
# sync, so callers run the printed interpreter directly.
# GATE_ENV_DIR overrides the project directory (for this script's tests).
set -euo pipefail
dir="${GATE_ENV_DIR:-$(git rev-parse --show-toplevel)/scripts/gate-env}"
py="$dir/.venv/bin/python"
if ! command -v uv >/dev/null 2>&1 || ! uv sync --locked --check --project "$dir" >/dev/null 2>&1 || [[ ! -x "$py" ]]; then
  echo "FAIL: the gate environment is missing or out of date; run: UV_MALWARE_CHECK=1 uv sync --locked --project scripts/gate-env" >&2
  exit 1
fi
printf '%s\n' "$py"
