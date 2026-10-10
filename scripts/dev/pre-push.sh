#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# pre-push gate — public hygiene, the cheap release-line gates CI enforces,
# and local fmt + lint + lib-test parity with CI.
# Cargo steps run `${CARGO:-cargo}`: `CARGO=spark-cargo scripts/dev/pre-push.sh`
# sends the builds to Spark.
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
  base="$(git merge-base HEAD origin/docs/ranking-1-release-line)" || {
    echo "FAIL: no merge-base with origin/docs/ranking-1-release-line; run: git fetch origin docs/ranking-1-release-line"
    exit 1
  }
  # changelog.yml skips this repository's throwaway/ branches (red-first and
  # mutant probes), so the hook does too.
  if [[ "$(git rev-parse --abbrev-ref HEAD)" != throwaway/* ]]; then
    echo "[pre-push] changelog fragment"
    python3 scripts/release/changelog_fragments.py check --base "$base" --head HEAD
  fi
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
  echo "[pre-push] scope acceptance"
  python3 scripts/release/check_scope_acceptance.py --check
  echo "[pre-push] clock baseline"
  python3 scripts/release/check_clock_baseline.py "$base"

  echo "[pre-push] commit message hygiene"
  # This branch's own commits. With no argument the script falls back to the
  # upstream, else origin/main, which is far behind the release line.
  scripts/dev/check-commit-message-hygiene.sh "$base..HEAD"

  echo "[pre-push] public repo hygiene"
  scripts/dev/check-public-repo-hygiene.sh

  # Cargo's own exit code decides, never a pipe's: the full output goes to a
  # log, a failure prints its tail and keeps the log, and every `test result:`
  # summary line is shown either way.
  run_cargo() {
    local name="$1" log rc=0
    shift
    log="$(mktemp "${TMPDIR:-/tmp}/pre-push-cargo.XXXXXX")"
    # No colour: escape codes before `test result:` would hide it from grep.
    CARGO_TERM_COLOR=never "${CARGO:-cargo}" "$@" >"$log" 2>&1 || rc=$?
    grep -E '^test result:' "$log" || true
    if [[ $rc -ne 0 ]]; then
      tail -40 "$log"
      echo "FAIL: $name (exit $rc; full log: $log)"
      exit 1
    fi
    rm -f "$log"
  }

  echo "[pre-push] cargo fmt --check"
  run_cargo "cargo fmt" fmt --all --check

  echo "[pre-push] cargo clippy --all-targets --all-features -D warnings"
  run_cargo "clippy all-features" clippy --all-targets --all-features --quiet -- -D warnings

  echo "[pre-push] cargo clippy --all-targets --no-default-features -D warnings"
  run_cargo "clippy no-default-features" clippy --all-targets --no-default-features --quiet -- -D warnings

  echo "[pre-push] cargo test --lib"
  run_cargo "cargo test --lib" test --lib --quiet
fi

tip="$(git rev-parse HEAD)"
message="$(git log -1 --pretty=%B)"
if ! grep -q '^Local-Tested: ' <<<"$message"; then
  git -c trailer.ifexists=replace commit --amend --no-edit \
    --trailer "Local-Tested: cargo fmt+clippy+test green @ ${tip}" >/dev/null || true
fi

echo "[pre-push] OK"
