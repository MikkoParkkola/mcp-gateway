#!/usr/bin/env bash
# Quality gate — fmt + clippy (-D warnings) + tests.
#
# Mirrors the CI release gate (.github/workflows/release.yml): formatting check,
# clippy denying all warnings across all features, and the full test suite.
# Exits non-zero on the first failing stage. Network/secret-dependent tests are
# marked `#[ignore]` and are skipped by `cargo test`.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "[check_quality] cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "[check_quality] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy --all-targets --all-features -- -D warnings

echo "[check_quality] cargo test --all-features"
cargo test --all-features

echo "[check_quality] OK"
