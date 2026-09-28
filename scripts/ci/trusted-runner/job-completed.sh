#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Job-completed hook for the project's self-hosted runner. Every job must
# start from nothing a previous job could have written: not the workspace,
# and not the user's home either (a job could replace the cargo or rustup
# proxies, edit cargo or git configuration, or alter cached action code, and
# so run its code inside a later job or forge its results). So everything the
# runner user can write is emptied after each job; the toolchain and actions
# are downloaded again by the next one.
#
# Kept: the runner's diagnostics directory and its in-use `_work/_temp`,
# which the runner itself empties.
set -euo pipefail

readonly HOME_DIR=${HOME:?}
readonly WORK_ROOT=${MCPGW_RUNNER_WORK_ROOT:-$HOME_DIR/_work}

# Refuse anything but the dedicated runner home: this deletes its contents.
case $HOME_DIR in
  /home/ghr-mcpgw) ;;
  *) [[ ${MCPGW_RUNNER_HOOK_TEST:-} == 1 ]] || { echo "refusing to clean home $HOME_DIR" >&2; exit 1; } ;;
esac

# Top-level entries of the home, minus the kept directories. `tmp` is the
# source of the unit's /tmp bind mount, so it is emptied, never removed.
find "$HOME_DIR" -mindepth 1 -maxdepth 1 ! -name _diag ! -name _work ! -name tmp -exec rm -rf -- {} +
find "$HOME_DIR/tmp" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
# The work root, minus the runner's in-use temp directory.
if [[ -d $WORK_ROOT ]]; then
  find "$WORK_ROOT" -mindepth 1 -maxdepth 1 ! -name _temp -exec rm -rf -- {} +
fi
echo "trusted runner state cleaned: $HOME_DIR"
