#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# pre-push gate — public hygiene + local fmt + lint + lib-test parity with CI.
# Bypass: SKIP_PREPUSH=1 (logged, audit-only).
# Wall-clock budget on warm cache: <60s.
set -euo pipefail

if [[ "${SKIP_PREPUSH:-0}" == "1" ]]; then
  echo "WARN: pre-push bypassed via SKIP_PREPUSH=1" >&2
  exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [[ -f Cargo.toml ]]; then
  echo "[pre-push] public repo hygiene"
  scripts/dev/check-public-repo-hygiene.sh

  echo "[pre-push] cargo fmt --check"
  cargo fmt --all --check 2>&1 | tail -20 || { echo "FAIL: cargo fmt"; exit 1; }

  echo "[pre-push] cargo clippy --lib -D warnings"
  cargo clippy --lib --no-deps --quiet -- -D warnings 2>&1 | tail -20 || { echo "FAIL: clippy"; exit 1; }

  echo "[pre-push] cargo test --lib"
  cargo test --lib --quiet 2>&1 | tail -10 || { echo "FAIL: cargo test --lib"; exit 1; }
fi

tip="$(git rev-parse HEAD)"
if ! git log -1 --pretty=%B | grep -q '^Local-Tested: '; then
  git -c trailer.ifexists=replace commit --amend --no-edit \
    --trailer "Local-Tested: cargo fmt+clippy+test green @ ${tip}" >/dev/null || true
fi

echo "[pre-push] OK"
