#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# pre-push gate — public hygiene, the cheap release-line gates CI enforces,
# and local fmt + lint + lib-test parity with CI.
# Bypass: SKIP_PREPUSH=1 (logged, audit-only).
set -euo pipefail

if [[ "${SKIP_PREPUSH:-0}" == "1" ]]; then
  echo "WARN: pre-push bypassed via SKIP_PREPUSH=1" >&2
  exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [[ -f Cargo.toml ]]; then
  # The cheap gates CI enforces, against the point this branch left the
  # release line (MIK-8328). Each prints its own message and stops the push.
  # They run first: each takes seconds, and the hygiene scan below takes minutes.
  base="$(git merge-base HEAD origin/docs/ranking-1-release-line)"
  echo "[pre-push] changelog fragment"
  python3 scripts/release/changelog_fragments.py check --base "$base" --head HEAD
  echo "[pre-push] file size"
  python3 scripts/dev/check-file-size.py --base "$base"
  echo "[pre-push] inventory rows"
  python3 scripts/release/check_inventory_rows.py "$base" HEAD
  echo "[pre-push] timing asserts"
  python3 scripts/dev/check-timing-asserts.py --base "$base"
  echo "[pre-push] C6 obligations"
  # One line per obligation: show them all only when one is unresolved.
  c6="$(python3 scripts/release/c6_resolve.py --tree HEAD)" || { printf '%s\n' "$c6"; exit 1; }
  printf '%s\n' "${c6##*$'\n'}"

  echo "[pre-push] commit message hygiene"
  # This branch's own commits. With no argument the script falls back to the
  # upstream, else origin/main, which is far behind the release line.
  scripts/dev/check-commit-message-hygiene.sh "$base..HEAD"

  echo "[pre-push] public repo hygiene"
  scripts/dev/check-public-repo-hygiene.sh

  echo "[pre-push] cargo fmt --check"
  cargo fmt --all --check 2>&1 | tail -20 || { echo "FAIL: cargo fmt"; exit 1; }

  echo "[pre-push] cargo clippy --all-targets --all-features -D warnings"
  cargo clippy --all-targets --all-features --quiet -- -D warnings 2>&1 | tail -20 || { echo "FAIL: clippy all-features"; exit 1; }

  echo "[pre-push] cargo clippy --all-targets --no-default-features -D warnings"
  cargo clippy --all-targets --no-default-features --quiet -- -D warnings 2>&1 | tail -20 || { echo "FAIL: clippy no-default-features"; exit 1; }

  echo "[pre-push] cargo test --lib"
  cargo test --lib --quiet 2>&1 | tail -10 || { echo "FAIL: cargo test --lib"; exit 1; }
fi

tip="$(git rev-parse HEAD)"
if ! git log -1 --pretty=%B | grep -q '^Local-Tested: '; then
  git -c trailer.ifexists=replace commit --amend --no-edit \
    --trailer "Local-Tested: cargo fmt+clippy+test green @ ${tip}" >/dev/null || true
fi

echo "[pre-push] OK"
