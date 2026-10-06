#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Mutation cases for scripts/ci/verify-artifact-licenses.sh: each case breaks
# one licence notice or identifier in a copy of the packaging files and
# requires the check to fail with the message that names it. A weakened check
# passes the broken copy, and this test then fails.
set -euo pipefail

source_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$source_repo" # FILES globs resolve against the repo, whatever the caller's cwd
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

FILES=(
  scripts/ci/verify-artifact-licenses.sh
  LICENSE LICENSE-MIT LICENSE-NONCOMMERCIAL LICENSES.md NOTICE.md
  Cargo.toml crates/*/Cargo.toml npm/package.json Dockerfile
  homebrew/mcp-gateway.rb .github/workflows/release.yml
)

# A fresh copy of the packaging files; prints its path.
make_tree() {
  local tree="$tmp_root/$1"
  local f
  for f in "${FILES[@]}"; do
    mkdir -p "$tree/$(dirname "$f")"
    cp "$source_repo/$f" "$tree/$f"
  done
  printf '%s\n' "$tree"
}

# <file> <perl substitution>: edits the file in place and requires a change.
mutate() {
  local before
  before="$(cat "$1")"
  perl -0pi -e "$2" "$1"
  if [ "$before" = "$(cat "$1")" ]; then
    echo "FAIL: mutation '$2' did not change $1" >&2
    exit 1
  fi
}

check() { bash "$1/scripts/ci/verify-artifact-licenses.sh" >"$1.out" 2>&1; }

assert_pass() {
  local tree
  tree="$(make_tree "$1")"
  if ! check "$tree"; then
    cat "$tree.out" >&2
    echo "FAIL: $1 should pass" >&2
    exit 1
  fi
  echo "ok: $1"
}

# <name> <file> <perl substitution> <expected message>
assert_fail() {
  local tree
  tree="$(make_tree "$1")"
  mutate "$tree/$2" "$3"
  if check "$tree"; then
    echo "FAIL: $1 should fail the check" >&2
    exit 1
  fi
  if ! grep -qF -- "$4" "$tree.out"; then
    cat "$tree.out" >&2
    echo "FAIL: $1 should report: $4" >&2
    exit 1
  fi
  echo "ok: $1"
}

assert_pass "unchanged-tree"

assert_fail "formula-without-caveats" homebrew/mcp-gateway.rb \
  's/\n *def caveats\n.*?\n *end\n//s' \
  "homebrew/mcp-gateway.rb: formula caveats must point to COMMERCIAL.md"

# The caveat loses its pointer; the formula's `# See LICENSES.md /
# COMMERCIAL.md.` comment remains, which users never see on install.
assert_fail "formula-commercial-only-in-comment" homebrew/mcp-gateway.rb \
  's/ See https:\S*COMMERCIAL\.md//' \
  "homebrew/mcp-gateway.rb: formula caveats must point to COMMERCIAL.md"

assert_fail "generated-formula-without-caveats" .github/workflows/release.yml \
  's/\n *def caveats\n.*?\n *end\n//s' \
  ".github/workflows/release.yml: formula caveats must point to COMMERCIAL.md"

assert_fail "generated-formula-caveat-drops-commercial" .github/workflows/release.yml \
  's/ See https:\S*COMMERCIAL\.md//' \
  ".github/workflows/release.yml: formula caveats must point to COMMERCIAL.md"

assert_fail "generated-formula-licence-unrepresentable" .github/workflows/release.yml \
  's/license "PolyForm-Noncommercial-1\.0\.0"/license :cannot_represent/' \
  ".github/workflows/release.yml: generated formula license must be PolyForm-Noncommercial-1.0.0"

assert_fail "formula-licence-unrepresentable" homebrew/mcp-gateway.rb \
  's/license "PolyForm-Noncommercial-1\.0\.0"/license :cannot_represent/' \
  "homebrew/mcp-gateway.rb: license must be PolyForm-Noncommercial-1.0.0"

assert_fail "crate-licence-changed" Cargo.toml \
  's/^license = "PolyForm-Noncommercial-1\.0\.0"$/license = "MIT"/m' \
  "Cargo.toml: license must be PolyForm-Noncommercial-1.0.0"

assert_fail "npm-licence-changed" npm/package.json \
  's/"SEE LICENSE IN LICENSES\.md"/"MIT"/' \
  'npm/package.json: "license" must be "SEE LICENSE IN LICENSES.md"'

echo "ok: artifact licence check mutation cases"
