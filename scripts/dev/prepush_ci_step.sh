#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# pre-push step "CI script checks" (MIK-8410): runs CI's cargo-free PR-workflow
# checks through run_prepush_ci_checks.py, next to this script. Argument: the
# merge-base pre-push computed. Exits non-zero, naming the step, on any failure.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
if ! python3 "$here/run_prepush_ci_checks.py" --merge-base "${1:?merge-base required}"; then
  echo "FAIL: pre-push step 'CI script checks' failed (MIK-8410); see the lines above"
  exit 1
fi
