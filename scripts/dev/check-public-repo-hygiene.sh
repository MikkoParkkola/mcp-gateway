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

# A working document narrates how the work was conducted: per-ticket status
# and burndown counts, remaining-plan bookkeeping, review transcripts and
# verdicts, rulings, audits of our own output. It is kept, because the history
# is worth having, but it lives under docs/internal/ and not beside the install
# and architecture pages a reader came for. The markers are matched against the
# headings in the first fifteen lines -- where a working document announces
# itself -- so a design page that merely cites a ruling is not a hit.
internal_heading_markers=(
  "burn-?down"
  "remaining plan|what is left|what (actually )?blocks|close-?out plan|gap[ -](closure|plan|assessment)"
  "next steps"
  "(review|verification) (findings|log|notes)|review (transcript|brief)|(design|test|adversarial|second-leg) review|unreviewed[ -]slice"
  "combined verdict|acceptance-criterion verdicts|reviewer verdict|ac verdicts"
  "adjudicat"
  "team-lead ruling"
  "readiness (board|plan|gaps)|release readiness|what is actually missing"
  "merge queue"
  "resume point"
  "(worktree|branch) (audit|maintenance|survey|criteria)"
  "dod (check|evidence)"
  "triage"
  "shard [0-9]+|shard review|shard:"
  "process compliance"
  "green progress|progress tracker"
  "rederivation"
  "(scope|criteria|ac) (grading|re-?grade|verification)|scope contract"
  "sub-?agent|agent session"
  "done log"
  "work plan|implementation plan|delivery plan|implementation brief|execution plan to"
  "(coverage|partial requirements|upgrade notice) audit|audit notes"
  "pr #?[0-9]+"
  "blocker|blocked:|fix log|drift probe"
  "expected-?red|the residue|mutants"
  "functional pass"
  "census"
)

# The same class of document often announces itself in its name alone, with a
# heading that reads like prose.
internal_path_markers=(
  "(^|/)pr-?[0-9]{3}"
  "(^|/)shard-[0-9]"
  "-triage|-burndown|rederivation|scope-grading|audit-notes/|-blocker|codeql-"
  "resume-|close-plan|close-?out|-recut-|-worktree-audit|worktree-branch-audit"
  "adjudicat|-regrade|-pr-body|-coverage-audit|-notice-audit|-audit-partial|-rollup"
)

# Documents another lane owns at the moment. Each entry is a debt, not a
# carve-out: when the lane lands, the file moves under docs/internal/ and the
# line goes.
internal_doc_allowlist=(
  "docs/analysis/release-4.0-remaining-plan.md"
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
  "RELEASING.md"
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
  "docs/MULTI_USER.md"
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

is_allowlisted_internal() {
  local file="$1"
  local permitted
  for permitted in "${internal_doc_allowlist[@]}"; do
    [[ "$file" == "$permitted" ]] && return 0
  done
  return 1
}

report_internal_doc() {
  local file="$1"
  local evidence="$2"
  report_failure "$file reads as an internal working document ($evidence)"
  printf 'Remediation: git mv it under docs/internal/ keeping its subdirectory, then repoint the links that named it.\n' >&2
}

# docs/internal/ is published, not hidden: the history is worth reading and the
# gate above is satisfied by moving a document there, which only works if the
# destination stays in the index.
if git ls-files --error-unmatch docs/internal >/dev/null 2>&1 || [[ -d docs/internal ]]; then
  if git check-ignore -q docs/internal; then
    report_failure "docs/internal is ignored; the internal-document gate has no tracked destination"
  elif [[ -z "$(git ls-files docs/internal)" ]]; then
    report_failure "docs/internal exists but nothing under it is tracked"
  fi
fi

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

  [[ "$file" == *.md ]] || continue
  [[ "$file" == docs/internal/* ]] && continue
  is_allowlisted_internal "$file" && continue

  headings="$(head -15 "$file" | grep -E '^#{1,3} ' || true)"
  for marker in "${internal_heading_markers[@]}"; do
    if match="$(printf '%s\n' "$headings" | grep -E -i -m 1 -e "$marker" || true)"; [[ -n "$match" ]]; then
      report_internal_doc "$file" "heading marker /$marker/: $match"
      continue 2
    fi
  done
  for marker in "${internal_path_markers[@]}"; do
    if printf '%s\n' "$file" | grep -E -q -i -e "$marker"; then
      report_internal_doc "$file" "path marker /$marker/"
      continue 2
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
