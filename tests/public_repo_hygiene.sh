#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

source_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$source_repo/scripts/dev/check-public-repo-hygiene.sh"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

make_repo() {
  local name="$1"
  local repo="$tmp_root/$name"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Repo Hygiene Test"
  mkdir -p "$repo/scripts/dev"
  cp "$checker" "$repo/scripts/dev/check-public-repo-hygiene.sh"
  chmod +x "$repo/scripts/dev/check-public-repo-hygiene.sh"
  cat >"$repo/.gitignore" <<'EOF'
docs/strategy/
docs/competitive/
docs/competitive-intelligence/
docs/positioning/
EOF
  printf '%s\n' "$repo"
}

assert_pass() {
  local repo="$1"
  local output="$tmp_root/pass.out"
  if ! (cd "$repo" && scripts/dev/check-public-repo-hygiene.sh >"$output" 2>&1); then
    cat "$output" >&2
    echo "expected hygiene check to pass in $repo" >&2
    exit 1
  fi
}

assert_fail_contains() {
  local repo="$1"
  local expected="$2"
  local output="$tmp_root/fail.out"
  if (cd "$repo" && scripts/dev/check-public-repo-hygiene.sh >"$output" 2>&1); then
    cat "$output" >&2
    echo "expected hygiene check to fail in $repo" >&2
    exit 1
  fi
  if ! grep -F -q "$expected" "$output"; then
    cat "$output" >&2
    echo "expected failure output to contain: $expected" >&2
    exit 1
  fi
}

repo="$(make_repo allowed-public-docs)"
cat >"$repo/README.md" <<'EOF'
# MCP Gateway

## Public competitor comparison

| Project | Public user-facing scope |
|---|---|
| MCPJungle | Self-hosted MCP server aggregation. |
| Docker MCP Gateway / Toolkit | Docker-managed MCP catalog and profiles. |
| mcpo | OpenAPI bridge for MCP servers. |

This public alternatives list explains user-facing product fit and public
comparison context for buyers.

## Install

Run the quickstart, configure a local gateway, and review the OWASP Agentic AI
controls, deployment guide, capability import guide, architecture overview,
release notes, security compliance matrix, and public setup examples.
EOF
git -C "$repo" add .gitignore README.md scripts/dev/check-public-repo-hygiene.sh
assert_pass "$repo"

repo="$(make_repo tracked-private-path)"
mkdir -p "$repo/docs/competitive"
echo "# Competitive scan" >"$repo/docs/competitive/scan.md"
git -C "$repo" add .gitignore scripts/dev/check-public-repo-hygiene.sh
git -C "$repo" add -f docs/competitive/scan.md
assert_fail_contains "$repo" "tracked files remain under private strategy paths"

blocked_markers=(
  "Status: DRAFT. Not ready to publish"
  "competitive scan"
  "competitive intelligence"
  "internal competitor analysis"
  "private strategy"
  "private roadmap reasoning"
  "roadmap reasoning"
  "build-vs-integrate licensing"
  "licensing strategy"
  "Portfolio-Wide Evidence Extract"
  "Positioning summary"
  "patent strategy"
  "OPSEC review"
  "customer-sensitive artifact"
  "protected auth material"
)

for i in "${!blocked_markers[@]}"; do
  repo="$(make_repo "blocked-marker-$i")"
  cat >"$repo/docs-public.md" <<EOF
# Public doc candidate

${blocked_markers[$i]}
EOF
  git -C "$repo" add .gitignore docs-public.md scripts/dev/check-public-repo-hygiene.sh
  assert_fail_contains "$repo" "contains"
done

allowed_cases=(
  "Public competitor comparison table for users"
  "Docker MCP Gateway / Toolkit appears in a public alternatives table"
  "MCPJungle appears in a public alternatives table"
  "mcpo appears in a public alternatives table"
  "OWASP Agentic AI controls are documented for users"
  "Deployment quickstart for local operators"
  "Capability import guide for REST APIs"
  "Architecture overview for maintainers"
  "Release notes for a public feature"
  "Security compliance matrix for public claims"
  "CONTRIBUTING.md may state that competitive intelligence belongs in ignored paths"
)

for i in "${!allowed_cases[@]}"; do
  repo="$(make_repo "allowed-case-$i")"
  target_file="README.md"
  if [[ "${allowed_cases[$i]}" == CONTRIBUTING.md* ]]; then
    target_file="CONTRIBUTING.md"
  fi
  cat >"$repo/$target_file" <<EOF
# Public doc candidate

${allowed_cases[$i]}
EOF
  git -C "$repo" add .gitignore "$target_file" scripts/dev/check-public-repo-hygiene.sh
  assert_pass "$repo"
done

echo "public repo hygiene fixtures OK"
