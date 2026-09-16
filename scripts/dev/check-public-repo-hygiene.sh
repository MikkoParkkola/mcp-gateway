#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard the public repo boundary: internal strategy belongs in ignored paths.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

failures=0

private_dirs=(
  "docs/strategy"
  "docs/competitive"
  "docs/competitive-intelligence"
  "docs/positioning"
)

public_competitive_docs=(
  "docs/competitive/README.md"
  "docs/competitive/willow-enterprise-agent-governance.md"
)

ignore_samples=(
  "docs/strategy/example.md"
  "docs/competitive/example.md"
  "docs/competitive-intelligence/example.md"
  "docs/positioning/example.md"
)

blocked_patterns=(
  "Status:[[:space:]]*DRAFT\\.[[:space:]]*Not ready to publish"
  "competitive[[:space:]-]+scan"
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

blocked_reasons=(
  "unpublished launch draft"
  "competitive scan"
  "competitive intelligence"
  "internal competitor analysis"
  "private strategy"
  "private roadmap reasoning"
  "roadmap reasoning"
  "build-vs-integrate licensing strategy"
  "licensing strategy"
  "portfolio evidence extract"
  "positioning memo"
  "patent strategy"
  "OPSEC launch review"
  "customer-sensitive artifact"
  "protected auth material"
)

# Every tracked file at the repository root. Not filtered by extension: the
# material this rule exists to catch arrives as an agent brief, a generated map
# or an extensionless review prompt, and an extension filter lets each of those
# through. A new root entry is a deliberate act, so it is added here by hand.
root_doc_allowlist=(
  ".dockerignore"
  ".gitignore"
  ".gitleaksignore"
  ".license-scope-exclude"
  ".trivyignore"
  "Cargo.lock"
  "Cargo.toml"
  "Dockerfile"
  "LICENSE"
  "LICENSE-MIT"
  "LICENSE-NONCOMMERCIAL"
  "Makefile"
  "demo.gif"
  "demo.tape"
  "gateway.example.yaml"
  "glama.json"
  "security-controls.toml"
  "server.json"
  "smithery.yaml"
  "ARCHITECTURE.md"
  "AUTHORSHIP.md"
  "CHANGELOG.md"
  "CLA.md"
  "CLAUDE.md"
  "CODE_OF_CONDUCT.md"
  "COMMERCIAL.md"
  "CONTRIBUTING.md"
  "LICENSE-EE.md"
  "LICENSES.md"
  "NOTICE.md"
  "README.md"
  "SECURITY.md"
  # Tracked under protest: the numerical-claim drift check and the MIK-6977
  # acceptance test both read this generated map, so removing it from the tree
  # would silently drop two claim surfaces. Untangle those first.
  "codebase-map.md"
  "llms.txt"
)

# Files a user copies or follows verbatim. An absolute path out of whoever
# authored the line sends them to a directory that exists on one machine.
shipped_surfaces=(
  "gateway.example.yaml"
  "README.md"
  "docs/QUICKSTART.md"
  "docs/DEPLOYMENT.md"
  "docs/OAUTH_CONFIG.md"
  "docs/REMOTE_BACKENDS.md"
  "llms.txt"
)

report_failure() {
  local message="$1"
  printf 'FAIL: %s\n' "$message" >&2
  failures=$((failures + 1))
}

for sample in "${ignore_samples[@]}"; do
  if ! git check-ignore -q "$sample"; then
    report_failure "$sample is not ignored; add the private strategy paths to .gitignore"
  fi
done

is_public_competitive_doc() {
  local file="$1"
  local public_file
  for public_file in "${public_competitive_docs[@]}"; do
    [[ "$file" == "$public_file" ]] && return 0
  done
  return 1
}

tracked_private="$(
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    is_public_competitive_doc "$file" || printf '%s\n' "$file"
  done < <(git ls-files "${private_dirs[@]}" || true)
)"
if [[ -n "$tracked_private" ]]; then
  report_failure "tracked files remain under private strategy paths; move them to ignored local storage or remove them from the public index"
  printf '%s\n' "$tracked_private" >&2
fi

while IFS= read -r file; do
  [[ -f "$file" ]] || continue

  case "$file" in
    CONTRIBUTING.md|scripts/dev/check-public-repo-hygiene.sh|tests/public_repo_hygiene.sh)
      continue
      ;;
    *.md|*.txt|*.adoc|*.rst)
      ;;
    *)
      continue
      ;;
  esac

  for i in "${!blocked_patterns[@]}"; do
    if match="$(grep -E -i -n -m 1 "${blocked_patterns[$i]}" "$file" || true)"; [[ -n "$match" ]]; then
      report_failure "$file contains ${blocked_reasons[$i]} marker: $match"
      printf 'Remediation: move the material to ignored docs/strategy/, docs/positioning/, docs/competitive/, or docs/competitive-intelligence/ as appropriate.\n' >&2
    fi
  done
done < <(git ls-files)

for surface in "${shipped_surfaces[@]}"; do
  [[ -f "$surface" ]] || continue
  if match="$(grep -E -n -m 1 '(/Users|/home)/[a-z][a-z0-9_-]*/' "$surface" || true)"; [[ -n "$match" ]]; then
    report_failure "$surface carries a home-directory path a reader cannot have: $match"
  fi
done

while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  [[ "$file" == */* ]] && continue
  allowed=0
  for permitted in "${root_doc_allowlist[@]}"; do
    [[ "$file" == "$permitted" ]] && allowed=1 && break
  done
  if [[ "$allowed" -eq 0 ]]; then
    report_failure "$file is a top-level file that is not on the root allowlist; move it under docs/ or add it to root_doc_allowlist in this script"
  fi
done < <(git ls-files)

if (( failures > 0 )); then
  printf 'Public repo hygiene failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Public repo hygiene OK: ignored private paths enforced and tracked docs scanned.\n'
