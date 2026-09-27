#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Job-completed hook for the project's self-hosted runner: every job starts
# from an empty workspace and an empty target directory. The toolchain and
# the cargo registry (content-addressed) stay under the runner user's home.
set -euo pipefail

readonly WORK_ROOT=${MCPGW_RUNNER_WORK_ROOT:-$HOME/_work}

# GITHUB_WORKSPACE is <work root>/<repo>/<repo>; delete <work root>/<repo>,
# and only when it really sits under the work root.
repo_dir=$(dirname -- "${GITHUB_WORKSPACE:?}")
case $repo_dir in
  "$WORK_ROOT"/?*) ;;
  *) echo "refusing to clean $repo_dir: not under $WORK_ROOT" >&2; exit 1 ;;
esac
case $repo_dir in
  */..|*/../*) echo "refusing to clean $repo_dir: contains .." >&2; exit 1 ;;
  "$WORK_ROOT"/_*) echo "refusing to clean runner-internal $repo_dir" >&2; exit 1 ;;
esac
rm -rf -- "$repo_dir"
echo "trusted runner workspace cleaned: $repo_dir"
