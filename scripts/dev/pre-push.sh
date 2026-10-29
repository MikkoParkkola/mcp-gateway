#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# pre-push gate — public hygiene, the cheap release-line gates CI enforces,
# and local fmt + lint + lib-test parity with CI.
# Cargo steps run `${CARGO:-cargo}`: `CARGO=spark-cargo scripts/dev/pre-push.sh`
# sends the builds to Spark.
# Bypass: SKIP_PREPUSH=1 (logged, audit-only).
set -euo pipefail

# Every step names itself; any non-zero exit says which step stopped the push,
# whatever printed last (MIK-8328: a red gate must never read as green).
current_step="setup"
step() {
  current_step="$1"
  echo "[pre-push] $1"
}
trap 'rc=$?; if [[ $rc -ne 0 ]]; then echo "FAIL: pre-push stopped at step: ${current_step} (exit ${rc})" >&2; fi' EXIT

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
  step "merge-base"
  base="$(git merge-base HEAD origin/docs/ranking-1-release-line)" || {
    echo "FAIL: no merge-base with origin/docs/ranking-1-release-line; run: git fetch origin docs/ranking-1-release-line"
    exit 1
  }
  # changelog.yml skips this repository's throwaway/ branches (red-first and
  # mutant probes), so the hook does too.
  if [[ "$(git rev-parse --abbrev-ref HEAD)" != throwaway/* ]]; then
    step "changelog fragment"
    python3 scripts/release/changelog_fragments.py check --base "$base" --head HEAD
  fi
  step "file size"
  python3 scripts/dev/check-file-size.py --base "$base"
  step "inventory rows"
  python3 scripts/release/check_inventory_rows.py "$base" HEAD
  step "timing asserts"
  python3 scripts/dev/check-timing-asserts.py --base "$base"
  step "C6 obligations"
  # One line per obligation: show them all only when one is unresolved.
  c6="$(python3 scripts/release/c6_resolve.py --tree HEAD)" || { printf '%s\n' "$c6"; exit 1; }
  printf '%s\n' "${c6##*$'\n'}"
  step "scope acceptance"
  python3 scripts/release/check_scope_acceptance.py --check

  step "commit message hygiene"
  # This branch's own commits. With no argument the script falls back to the
  # upstream, else origin/main, which is far behind the release line.
  scripts/dev/check-commit-message-hygiene.sh "$base..HEAD"

  step "public repo hygiene"
  scripts/dev/check-public-repo-hygiene.sh --base "$base"

  # MIK-8410: the CI-check scanner's own drift tests first (CI runs them too;
  # the runner's 22.5 s suite runs in CI only), then CI's cargo-free
  # PR-workflow checks, before any cargo step.
  step "CI-check gate self-tests"
  python3 -c 'import yaml' 2>/dev/null || { echo "PyYAML is missing: pip install --user pyyaml (CI pins 6.0.2); pre-push installs nothing"; exit 1; }
  python3 scripts/dev/test_prepush_ci_checks.py

  step "CI script checks"
  bash scripts/dev/prepush_ci_step.sh "$base"

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

  step "cargo fmt --check"
  run_cargo "cargo fmt" fmt --all --check

  step "cargo clippy --all-targets --all-features -D warnings"
  run_cargo "clippy all-features" clippy --all-targets --all-features --quiet -- -D warnings

  step "cargo clippy --all-targets --no-default-features -D warnings"
  run_cargo "clippy no-default-features" clippy --all-targets --no-default-features --quiet -- -D warnings

  # MIK-8387: production code reaches the backend registry only through
  # Registry or a classed statement-level allow. Non-test targets only, from
  # its own config (the repo clippy.toml is untouched); the self-test proves
  # each entry still resolves and bites.
  step "registry ban (production targets, both feature sets)"
  export CLIPPY_CONF_DIR="$REPO_ROOT/scripts/lint/registry-ban"
  run_cargo "registry ban all-features" clippy --lib --bins --all-features --quiet -- -D warnings
  run_cargo "registry ban no-default-features" clippy --lib --bins --no-default-features --quiet -- -D warnings
  # MIK-8733: the release passes, as CI's Registry ban step runs them. They
  # compile cfg(not(debug_assertions)) code the dev passes never see, and some
  # lints fire only there (#4060: assigning_clones).
  step "registry ban, release profile (both feature sets)"
  # Every feature but the test-only ones, as CI's step computes it. Under
  # set -e a failing script stops the push at this step.
  feats=$(python3 scripts/ci/release_features.py)
  run_cargo "registry ban release features" clippy --release --lib --bins --features "$feats" --quiet -- -D warnings
  run_cargo "registry ban release no-default-features" clippy --release --lib --bins --no-default-features --quiet -- -D warnings
  unset CLIPPY_CONF_DIR
  step "registry lint self-test"
  scripts/dev/check_registry_lint.sh --self-test

  step "cargo test --lib"
  run_cargo "cargo test --lib" test --lib --quiet

  # MIK-8410 RUST.1: the integration tests that read docs/ or the CLI
  # definition, --all-features, as CI runs them.
  step "doc/CLI Rust tests (--all-features)"
  CARGO="${CARGO:-cargo}" python3 scripts/dev/run_prepush_ci_checks.py --rust --merge-base "$base"
fi

step "commit metadata"
tip="$(git rev-parse HEAD)"
message="$(git log -1 --pretty=%B)"
if ! grep -q '^Local-Tested: ' <<<"$message"; then
  git -c trailer.ifexists=replace commit --amend --no-edit \
    --trailer "Local-Tested: cargo fmt+clippy+test green @ ${tip}" >/dev/null || true
fi

echo "[pre-push] OK"
