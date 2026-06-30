#!/usr/bin/env bash
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

tracked_private="$(git ls-files "${private_dirs[@]}" || true)"
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

if (( failures > 0 )); then
  printf 'Public repo hygiene failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Public repo hygiene OK: ignored private paths enforced and tracked docs scanned.\n'
