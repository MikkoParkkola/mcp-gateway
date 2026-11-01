#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard the public repo boundary. Internal material lives in the private
# companion repository, cloned into a public checkout at the ignored internal/
# path; nothing it owns is tracked here.
#
#   check-public-repo-hygiene.sh [--base <rev>]
#
# The tree checks read every tracked file. With --base, the change since the
# merge-base with <rev> is also checked for an added tracker id, in a line or
# in a new file's name.
set -euo pipefail

base=""
while (( $# > 0 )); do
  case "$1" in
    --base) base="${2:?--base needs a revision}"; shift 2 ;;
    *) printf 'usage: %s [--base <rev>]\n' "$0" >&2; exit 2 ;;
  esac
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

failures=0

# shellcheck source=scripts/dev/public-hygiene-patterns.sh
source "$(dirname "${BASH_SOURCE[0]}")/public-hygiene-patterns.sh"

# The files that spell the patterns out, to define or to test them.
self_files=(
  "scripts/dev/public-hygiene-patterns.sh"
  "scripts/dev/public-hygiene-debt.tsv"
  "scripts/dev/check-public-repo-hygiene.sh"
  "scripts/dev/check-commit-message-hygiene.sh"
  "scripts/dev/check-pr-body-hygiene.sh"
  "tests/public_repo_hygiene.sh"
  "tests/commit_message_hygiene.sh"
)

# Text that matches a private-content pattern and is public by design. Each
# entry is <path glob>::<check id>::<why it is public>.
content_allowlist=(
  "src/security/ssrf/*::tailnet-ip::the SSRF guard names the shared address range it refuses"
)

# Data that CI reads, kept public under a private directory until it moves to
# a public data path. Exact paths, never directories: everything else under
# those directories is refused. Each file is scrubbed of private lines, and
# the content checks still read it.
public_data_allowlist=(
  "docs/internal/perf/per_call_stages.tsv"
  "docs/internal/perf/per_call_stages_stdio.tsv"
  "docs/requirements/RELEASE-4.0.0-criteria-status.md"
  "docs/requirements/RELEASE-4.0.0-requirements.md"
  "docs/requirements/RELEASE-4.0.0-scope-status.json"
  "docs/requirements/RELEASE-4.0.0-scope-tests.md"
  "docs/requirements/RELEASE-4.0.0-scope-update.md"
  "docs/requirements/RELEASE-4.0.0-workload-contract.md"
  "docs/requirements/nfr-sec1-control-inventory.md"
  "docs/requirements/workload-pins-observed.md"
)

# Debt: hits that exist on the tree today and are being removed. One
# <path or directory/>TAB<check id>[TAB<most hits>] per line. With a count,
# more hits than that under the entry fail: debt covers what is there, not
# what is added. An entry that no longer matches
# anything fails the check, so the list only shrinks.
debt_file="scripts/dev/public-hygiene-debt.tsv"
debt_entries=()
if [[ -f "$debt_file" ]]; then
  while IFS= read -r entry; do
    [[ -z "$entry" || "$entry" == \#* ]] && continue
    debt_entries+=("$entry")
  done <"$debt_file"
fi
declare -A debt_used=() debt_hits=()

ignore_samples=(
  "internal/example.md"
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
)

# Every tracked file at the repository root. Not filtered by extension: the
# material this rule exists to catch arrives as an agent brief, a generated map
# or an extensionless review prompt, and an extension filter lets each of those
# through. A new root entry is a deliberate act, so it is added here by hand.
root_doc_allowlist=(
  ".dockerignore"
  ".gitattributes"
  ".gitignore"
  ".gitleaksignore"
  ".license-scope-exclude"
  ".trivyignore"
  "Cargo.lock"
  "Cargo.toml"
  "clippy.toml"
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

# Whether $1 (a path) is covered for check $2 by a debt entry; marks it used.
is_debt() {
  local file="$1" id="$2" n="${3:-1}" entry where rest
  for entry in ${debt_entries[@]+"${debt_entries[@]}"}; do
    where="${entry%%$'\t'*}"
    rest="${entry#*$'\t'}"
    [[ "${rest%%$'\t'*}" == "$id" ]] || continue
    if [[ "$file" == "$where" || ( "$where" == */ && "$file" == "$where"* ) ]]; then
      debt_used["$entry"]=1
      debt_hits["$entry"]=$(( ${debt_hits["$entry"]:-0} + n ))
      return 0
    fi
  done
  return 1
}

is_content_allowlisted() {
  local file="$1" id="$2" entry glob
  for entry in "${content_allowlist[@]}"; do
    glob="${entry%%::*}"
    entry="${entry#*::}"
    # shellcheck disable=SC2053  # the glob is meant to match
    [[ "${entry%%::*}" == "$id" && "$file" == $glob ]] && return 0
  done
  return 1
}

is_self_file() {
  local file="$1" self
  for self in "${self_files[@]}"; do
    [[ "$file" == "$self" ]] && return 0
  done
  return 1
}

# Files a CI check keys by ticket number: a changelog or UPGRADING fragment
# and an inventory row file are named for their ticket and cite it.
is_ticket_keyed() {
  case "$1" in
    changelog.d/*.md | upgrading.d/*.md | docs/release/inventory.d/*.tsv | src/gateway/meta_mcp/boundary_pins/*.d/*.tsv) return 0 ;;
  esac
  return 1
}

is_private_path() {
  local file="$1" prefix name
  for prefix in "${private_path_prefixes[@]}"; do
    [[ "$file" == "$prefix"* ]] && return 0
  done
  for name in "${private_file_names[@]}"; do
    [[ "$file" == "$name" || "$file" == */"$name" ]] && return 0
  done
  return 1
}

for sample in "${ignore_samples[@]}"; do
  if ! git check-ignore -q "$sample"; then
    report_failure "$sample is not ignored; add /internal/ and the private strategy paths to .gitignore"
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
  printf 'Remediation: move it into the private companion repository (cloned at internal/) keeping its path, git rm it here, and state inline whatever a public link to it was for.\n' >&2
}

is_public_data() {
  local file="$1" permitted
  for permitted in ${public_data_allowlist[@]+"${public_data_allowlist[@]}"}; do
    [[ "$file" == "$permitted" ]] && return 0
  done
  return 1
}

# Literal paths throughout: a quoted name ("tickets/\303\244.md") would slip
# past every prefix comparison.
git_lit() { git -c core.quotePath=false "$@"; }

merge_base=""
declare -A added=()
if [[ -n "$base" ]]; then
  merge_base="$(git merge-base "$base" HEAD)"
  # No rename detection: a file renamed into a private path or a ticket-id
  # name is judged as the addition it is.
  while IFS= read -r -d '' file; do
    added["$file"]=1
  done < <(git_lit diff -z --no-renames --name-only --diff-filter=A "$merge_base" HEAD)
fi

while IFS= read -r -d '' file; do
  is_private_path "$file" || continue
  is_public_data "$file" && continue
  # Debt covers what the tree already carried, never a file this change adds.
  [[ -z "${added[$file]:-}" ]] && is_debt "$file" private-path && continue
  report_failure "$file is a private path; it belongs in the private companion repository"
  printf 'Remediation: move it into the private companion repository (cloned at internal/) keeping its path, then git rm it here.\n' >&2
done < <(git_lit ls-files -z -- "${private_path_prefixes[@]}" "${private_file_names[@]/#/:(glob)**/}")

# One fixed-string git grep finds every candidate line (an ERE grep over the
# tree costs seconds); each candidate is then matched against the checks.
self_skips=("${self_files[@]/#/:(exclude)}")
# --null ends the path and the line number with a NUL, so a path holding a
# colon is read whole.
while IFS= read -r -d '' file && IFS= read -r -d '' lineno && IFS= read -r text; do
  hit="$lineno:$text"
  for check in "${private_content_checks[@]}"; do
    id="${check%%::*}"
    rest="${check#*::}"
    flags="${rest%%::*}"
    rest="${rest#*::}"
    regex="${rest%%::*}"
    reason="${rest#*::}"
    [[ "$flags" == i ]] && shopt -s nocasematch
    # Every occurrence counts against a debt entry, not just the line.
    count=0
    rest="$text"
    while [[ -n "$rest" && "$rest" =~ $regex ]]; do
      count=$((count + 1))
      rest="${rest#*"${BASH_REMATCH[0]}"}"
    done
    shopt -u nocasematch
    (( count > 0 )) || continue
    is_content_allowlisted "$file" "$id" && continue
    is_debt "$file" "$id" "$count" && continue
    report_failure "$file:$hit -- $reason ($id)"
  done
done < <(
  git_lit grep -I -n -i -F --null "${private_content_prefilter[@]/#/-e}" -- . "${self_skips[@]}" || true)

if [[ -n "$base" ]]; then
  # Added lines, as path TAB line TAB text. An id that the same file's removed
  # lines also carry was edited in place, not added.
  while IFS=$'\t' read -r file line text; do
    is_self_file "$file" && continue
    is_ticket_keyed "$file" && continue
    report_failure "$file:$line adds a ticket id: $text"
  done < <(git_lit diff --no-color --no-ext-diff --unified=0 -M "$merge_base" HEAD |
    awk -v re="$ticket_id_regex" '
      # An acceptance-criterion id (MIK-N.AREA.n) is the key tests report
      # evidence under, not a citation, so it is stripped before the search.
      function bare(s) { gsub(/MIK-[0-9]+\.[A-Z0-9]+\.[0-9]+[a-z]?/, "", s); return s }
      function ids(s,   out, m) { s = " " bare(s); out = ""; while (match(s, /[^A-Za-z0-9]MIK-[0-9]+/)) { m = substr(s, RSTART + 1, RLENGTH - 1); out = out " " m; s = substr(s, RSTART + RLENGTH) } return out }
      /^diff --git / { flush(); inhunk = 0; next }
      !inhunk && /^\+\+\+ / { file = substr($0, 7); next }
      !inhunk && /^--- / { next }
      /^@@/ { inhunk = 1; match($0, /\+[0-9]+/); n = substr($0, RSTART + 1, RLENGTH - 1) + 0; next }
      /^-/ { gone = gone ids($0); next }
      /^\+/ { if (match(bare($0), re)) { pend[++np] = file "\t" n "\t" substr($0, 2); pids[np] = ids($0) } n++; next }
      function flush(   i, k, m, kept) {
        for (i = 1; i <= np; i++) {
          m = split(pids[i], k, " "); kept = 0
          for (j = 1; j <= m; j++) if (index(gone " ", " " k[j] " ") == 0) kept = 1
          if (kept) print pend[i]
        }
        np = 0; gone = ""
      }
      END { flush() }')

  # A new file whose name, or whose new directory, carries a tracker id.
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    is_self_file "$file" && continue
    is_ticket_keyed "$file" && continue
    path=""
    remaining="$file"
    while [[ -n "$remaining" ]]; do
      part="${remaining%%/*}"
      [[ "$remaining" == */* ]] && remaining="${remaining#*/}" || remaining=""
      path="${path:+$path/}$part"
      if [[ "$part" =~ (^|[^[:alnum:]])[Mm][Ii][Kk][-_]?[0-9]+ ]] && ! git cat-file -e "$merge_base:$path" 2>/dev/null; then
        report_failure "$file names a ticket id; name it for what it tests or does"
        break
      fi
    done
  done < <(printf '%s\n' "${!added[@]}")
fi

# Each scan below is one git grep or one awk pass over the tracked tree, never
# a process per file: the whole check has to stay fast enough for every push.
doc_specs=('*.md' '*.txt' '*.adoc' '*.rst')
doc_skips=(':(exclude)CONTRIBUTING.md' ':(exclude)scripts/dev/check-public-repo-hygiene.sh' ':(exclude)tests/public_repo_hygiene.sh')
# One grep for every marker; each hit is attributed to the markers it carries,
# reported once per file and marker.
declare -A marker_seen=()
shopt -s nocasematch
while IFS= read -r hit; do
  [[ -n "$hit" ]] || continue
  file="${hit%%:*}"
  text="${hit#*:}"
  text="${text#*:}"
  for i in "${!blocked_patterns[@]}"; do
    [[ -z "${marker_seen["$i:$file"]:-}" && "$text" =~ ${blocked_patterns[$i]} ]] || continue
    marker_seen["$i:$file"]=1
    report_failure "$file contains ${blocked_reasons[$i]} marker: ${hit#*:}"
    printf 'Remediation: move the material into the private companion repository (cloned at internal/).\n' >&2
  done
done < <(git_lit grep -I -n -i -E "${blocked_patterns[@]/#/-e}" -- "${doc_specs[@]}" "${doc_skips[@]}" || true)
shopt -u nocasematch

# A working document announces itself in a heading within its first fifteen
# lines, or in its name. The first marker in list order is the one reported.
md_skips=(':(exclude)docs/internal/' "${doc_skips[@]}")
for permitted in ${internal_doc_allowlist[@]+"${internal_doc_allowlist[@]}"}; do
  md_skips+=(":(exclude)$permitted")
done
heading_list="$(printf '%s\037' "${internal_heading_markers[@]}")"
path_list="$(printf '%s\037' "${internal_path_markers[@]}")"
while IFS=$'\t' read -r file evidence; do
  [[ -n "$file" ]] || continue
  report_internal_doc "$file" "$evidence"
done < <(
  {
    git_lit ls-files -- '*.md' "${md_skips[@]}" | sed 's/^/F\t/'
    git_lit grep -I -n -E -e '^#{1,3} ' -- '*.md' "${md_skips[@]}" | sed 's/^/H\t/' || true
  } | awk -F'\t' -v hm="$heading_list" -v pm="$path_list" '
    BEGIN { nh = split(hm, H, "\037") - 1; np = split(pm, P, "\037") - 1 }
    $1 == "F" { order[++nf] = $2; next }
    $1 == "H" {
      rest = substr($0, 3)
      # path:line:text, and the path itself may hold a colon
      if (match(rest, /:[0-9]+:/)) {
        f = substr(rest, 1, RSTART - 1); ln = substr(rest, RSTART + 1, RLENGTH - 2) + 0
        if (ln <= 15) heads[f] = heads[f] "\n" substr(rest, RSTART + RLENGTH)
      }
    }
    END {
      for (i = 1; i <= nf; i++) {
        f = order[i]; done = 0
        if (f in heads) {
          n = split(substr(heads[f], 2), L, "\n")
          for (m = 1; m <= nh && !done; m++)
            for (k = 1; k <= n; k++)
              if (tolower(L[k]) ~ H[m]) { print f "\theading marker /" H[m] "/: " L[k]; done = 1; break }
        }
        for (m = 1; m <= np && !done; m++)
          if (tolower(f) ~ P[m]) { print f "\tpath marker /" P[m] "/"; done = 1 }
      }
    }')

for surface in "${shipped_surfaces[@]}"; do
  [[ -f "$surface" ]] || continue
  if match="$(grep -E -n -m 1 '(/Users|/home)/[a-z][a-z0-9_-]*/' "$surface" || true)"; [[ -n "$match" ]]; then
    report_failure "$surface carries a home-directory path a reader cannot have: $match"
  fi
done

while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  is_private_path "$file" && continue
  allowed=0
  for permitted in "${root_doc_allowlist[@]}"; do
    [[ "$file" == "$permitted" ]] && allowed=1 && break
  done
  if [[ "$allowed" -eq 0 ]]; then
    report_failure "$file is a top-level file that is not on the root allowlist; move it under docs/ or add it to root_doc_allowlist in this script"
  fi
done < <(git_lit ls-files | awk '!/\//')

# A change may shrink the debt list, never grow it: no new entry, no higher
# count than the base carried.
# A base without the list is the change that introduces it.
if [[ -n "$merge_base" ]] && git cat-file -e "$merge_base:$debt_file" 2>/dev/null; then
  declare -A base_most=()
  while IFS=$'\t' read -r where id most; do
    [[ -z "$where" || "$where" == \#* ]] && continue
    base_most["$where"$'\t'"$id"]="${most:-0}"
  done < <(git show "$merge_base:$debt_file" 2>/dev/null || true)
  for entry in ${debt_entries[@]+"${debt_entries[@]}"}; do
    key="${entry%$'\t'*}"
    [[ "$entry" == *$'\t'*$'\t'* ]] || key="$entry"
    most="${entry##*$'\t'}"
    if [[ -z "${base_most[$key]+set}" ]]; then
      report_failure "debt entry is new in this change; reword or remove the hit instead: ${entry//$'\t'/ }"
    elif [[ "$entry" == *$'\t'*$'\t'* ]] && [[ "$most" =~ ^[0-9]+$ && "${base_most[$key]}" =~ ^[0-9]+$ ]] &&
      (( 10#$most > 10#${base_most[$key]} )); then
      report_failure "debt entry count rose from ${base_most[$key]} to $most in this change: ${entry//$'\t'/ }"
    fi
  done
fi

for entry in ${debt_entries[@]+"${debt_entries[@]}"}; do
  if [[ -z "${debt_used[$entry]:-}" ]]; then
    report_failure "debt entry no longer matches anything; delete it from $debt_file: ${entry//$'\t'/ }"
    continue
  fi
  most="${entry#*$'\t'}"
  if [[ "$most" != *$'\t'* || ! "${most#*$'\t'}" =~ ^(0|[1-9][0-9]*)$ ]]; then
    # Plain decimal only: a leading zero would be read as octal and break the
    # comparisons below.
    report_failure "debt entry has no plain decimal hit count; every entry states how many hits it covers: ${entry//$'\t'/ }"
    continue
  fi
  most="${most#*$'\t'}"
  if (( ${debt_hits[$entry]} > most )); then
    report_failure "debt entry covers ${debt_hits[$entry]} hits, more than its $most; the change adds private material: ${entry//$'\t'/ }"
  elif (( ${debt_hits[$entry]} < most )); then
    report_failure "debt entry covers ${debt_hits[$entry]} hits, fewer than its $most; lower its count to ${debt_hits[$entry]} in $debt_file: ${entry//$'\t'/ }"
  fi
done

if (( failures > 0 )); then
  printf 'Public repo hygiene failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Public repo hygiene OK: private paths and content refused, tracked docs scanned%s.\n' "${base:+, change since $base checked for tracker ids}"
