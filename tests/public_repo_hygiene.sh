#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

source_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$source_repo/scripts/dev/check-public-repo-hygiene.sh"
patterns="$source_repo/scripts/dev/public-hygiene-patterns.sh"
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
  # The shared pattern list travels with the checker. The debt list does not:
  # a fixture repository owes nothing, so every check runs at full strength.
  [[ -f "$patterns" ]] && cp "$patterns" "$repo/scripts/dev/public-hygiene-patterns.sh"
  cat >"$repo/.gitignore" <<'EOF'
/internal/
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
git -C "$repo" add .gitignore README.md scripts/dev
assert_pass "$repo"

repo="$(make_repo tracked-private-path)"
mkdir -p "$repo/docs/competitive"
echo "# Competitive scan" >"$repo/docs/competitive/scan.md"
git -C "$repo" add .gitignore scripts/dev
git -C "$repo" add -f docs/competitive/scan.md
assert_fail_contains "$repo" "is a private path"

# No comparison page is public any more, even one un-ignored by name.
repo="$(make_repo named-comparison-is-refused)"
cat >>"$repo/.gitignore" <<'EOF'
!docs/competitive/
docs/competitive/*
!docs/competitive/README.md
!docs/competitive/example-comparison.md
EOF
mkdir -p "$repo/docs/competitive"
cat >"$repo/docs/competitive/README.md" <<'EOF'
# Public comparisons
EOF
cat >"$repo/docs/competitive/example-comparison.md" <<'EOF'
# Feature comparison for users
EOF
git -C "$repo" add .gitignore scripts/dev
git -C "$repo" add docs/competitive/README.md docs/competitive/example-comparison.md
assert_fail_contains "$repo" "is a private path"

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
  git -C "$repo" add .gitignore docs-public.md scripts/dev
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
  git -C "$repo" add .gitignore "$target_file" scripts/dev
  assert_pass "$repo"
done

repo="$(make_repo internal-doc-in-public-tree)"
mkdir -p "$repo/docs/release"
cat >"$repo/docs/release/v4.0.0-burndown-tracker.md" <<'EOF'
# v4.0.0 release-criteria burndown

| criterion | status |
|---|---|
| NFR.PERF.1 | MET |
EOF
git -C "$repo" add .gitignore docs/release/v4.0.0-burndown-tracker.md scripts/dev
assert_fail_contains "$repo" "reads as an internal working document"

repo="$(make_repo internal-doc-named-by-path)"
mkdir -p "$repo/docs/design"
cat >"$repo/docs/design/pr473-gateway.md" <<'EOF'
# Routing notes

Findings recorded while reading the shard.
EOF
git -C "$repo" add .gitignore docs/design/pr473-gateway.md scripts/dev
assert_fail_contains "$repo" "path marker"

# docs/internal/ is no longer a destination: working documents live in the
# private companion repository, cloned at the ignored internal/ path.
repo="$(make_repo internal-doc-relocated)"
mkdir -p "$repo/docs/internal/release"
cat >"$repo/docs/internal/release/v4.0.0-burndown-tracker.md" <<'EOF'
# v4.0.0 release-criteria burndown
EOF
git -C "$repo" add .gitignore docs/internal/release/v4.0.0-burndown-tracker.md scripts/dev
assert_fail_contains "$repo" "is a private path"

# A product page may cite a ruling or a review in its prose. The marker set
# reads headings, so citing one is not the same as being one.
repo="$(make_repo public-doc-citing-internal-material)"
mkdir -p "$repo/docs/design"
cat >"$repo/docs/design/continuation-envelope.md" <<'EOF'
# Continuation envelope

The team-lead ruling recorded in `docs/internal/release/rulings.md` fixed the
wording. This page describes the envelope the gateway emits, its version field
and the review findings that shaped the retry path.
EOF
git -C "$repo" add .gitignore docs/design/continuation-envelope.md scripts/dev
assert_pass "$repo"

repo="$(make_repo internal-clone-not-ignored)"
sed -i.bak '/^\/internal\/$/d' "$repo/.gitignore" && rm -f "$repo/.gitignore.bak"
git -C "$repo" add .gitignore scripts/dev
assert_fail_contains "$repo" "internal/example.md is not ignored"

# Commit everything staged in $1, so a case can name a base for the diff checks.
commit_all() {
  git -C "$1" add -A
  git -C "$1" commit -q -m "$2"
}

assert_base_fail_contains() {
  local repo="$1" base="$2" expected="$3"
  local output="$tmp_root/fail.out"
  if (cd "$repo" && scripts/dev/check-public-repo-hygiene.sh --base "$base" >"$output" 2>&1); then
    cat "$output" >&2
    echo "expected hygiene check to fail against $base in $repo" >&2
    exit 1
  fi
  if ! grep -F -q "$expected" "$output"; then
    cat "$output" >&2
    echo "expected failure output to contain: $expected" >&2
    exit 1
  fi
}

assert_base_pass() {
  local repo="$1" base="$2"
  local output="$tmp_root/pass.out"
  if ! (cd "$repo" && scripts/dev/check-public-repo-hygiene.sh --base "$base" >"$output" 2>&1); then
    cat "$output" >&2
    echo "expected hygiene check to pass against $base in $repo" >&2
    exit 1
  fi
}

# Every path the private companion repository owns is refused in the index,
# whatever the file is called.
private_path_cases=(
  "docs/internal/notes.md"
  "docs/competitive/notes.md"
  "docs/requirements/RELEASE-9.9.9-plan.md"
  "tickets/backlog.md"
  "CLAUDE.md"
  "AGENTS.md"
  "src/AGENTS.md"
)
for i in "${!private_path_cases[@]}"; do
  repo="$(make_repo "private-path-$i")"
  target="${private_path_cases[$i]}"
  mkdir -p "$repo/$(dirname "$target")"
  printf '# Notes\n' >"$repo/$target"
  git -C "$repo" add .gitignore scripts/dev
  git -C "$repo" add -f "$target"
  assert_fail_contains "$repo" "$target is a private path"
done

# Content that only makes sense on the maintainer's machine or inside a
# private project, planted in a file type the old marker scan never read.
private_content_cases=(
  "src/lib.rs::// Mirrors the hebb recall path.::names a private project"
  "src/lib.rs::let cfg = HebbBridgeConfig { enabled: true };::names a private project"
  "docs/guide.md::Run the botnaut-client wrapper first.::names a private project"
  "scripts/run.sh::cd /Users/mikko/github/mcp-gateway::home-directory path"
  "scripts/run.sh::cat ~/.claude/settings.json::private agent-configuration directory"
  "deploy/values.yaml::host: 100.101.102.103::private-network address"
)
for i in "${!private_content_cases[@]}"; do
  case_spec="${private_content_cases[$i]}"
  target="${case_spec%%::*}"
  rest="${case_spec#*::}"
  line="${rest%%::*}"
  expected="${rest#*::}"
  repo="$(make_repo "private-content-$i")"
  mkdir -p "$repo/$(dirname "$target")"
  printf '%s\n' "$line" >"$repo/$target"
  git -C "$repo" add .gitignore scripts/dev "$target"
  assert_fail_contains "$repo" "$expected"
done

# Known-innocent text that resembles a hit: the published maintainer contact,
# the public capability schema name, a learning-rule term, a version string.
innocent_cases=(
  "SECURITY.md::email **mikko.parkkola@iki.fi** with the report"
  "docs/QUICKSTART.md::fulcrum: \"1.0\""
  "docs/notes.md::a Hebbian learning rule"
  "docs/notes.md::release 1.100.2.3 is current"
)
for i in "${!innocent_cases[@]}"; do
  case_spec="${innocent_cases[$i]}"
  target="${case_spec%%::*}"
  line="${case_spec#*::}"
  repo="$(make_repo "innocent-content-$i")"
  mkdir -p "$repo/$(dirname "$target")"
  printf '# Page\n\n%s\n' "$line" >"$repo/$target"
  git -C "$repo" add .gitignore scripts/dev "$target"
  assert_pass "$repo"
done

# A ticket id already in the tree stays; one added on a line of this change is
# refused, in code and docs alike.
repo="$(make_repo ticket-id-added)"
mkdir -p "$repo/src"
printf '// Guard the reload path (MIK-1234).\n' >"$repo/src/lib.rs"
commit_all "$repo" "seed"
assert_base_pass "$repo" HEAD
printf '// Keep the cache warm (MIK-5678).\n' >>"$repo/src/lib.rs"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "src/lib.rs:2 adds a ticket id"

repo="$(make_repo ticket-id-existing-line-kept)"
mkdir -p "$repo/src"
printf '// Guard the reload path (MIK-1234).\n' >"$repo/src/lib.rs"
commit_all "$repo" "seed"
printf 'fn reload() {}\n' >>"$repo/src/lib.rs"
commit_all "$repo" "change"
assert_base_pass "$repo" HEAD~1

repo="$(make_repo ticket-id-in-new-file-name)"
commit_all "$repo" "seed"
mkdir -p "$repo/tests"
printf 'fn main() {}\n' >"$repo/tests/mik_9999_reload.rs"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "tests/mik_9999_reload.rs names a ticket id"

# A debt entry that no longer matches anything is itself a failure, so the
# list can only shrink.
repo="$(make_repo stale-debt-entry)"
printf 'docs/internal/\tprivate-path\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev
assert_fail_contains "$repo" "debt entry no longer matches"

# A file named in the public-data allowlist passes; its neighbour does not.
repo="$(make_repo public-data-under-private-dir)"
sed -i.bak 's#^public_data_allowlist=($#public_data_allowlist=(\n  "docs/requirements/data.json"#' "$repo/scripts/dev/check-public-repo-hygiene.sh"
rm -f "$repo/scripts/dev/check-public-repo-hygiene.sh.bak"
mkdir -p "$repo/docs/requirements"
printf '{}\n' >"$repo/docs/requirements/data.json"
git -C "$repo" add .gitignore scripts/dev docs/requirements/data.json
assert_pass "$repo"
printf '# Notes\n' >"$repo/docs/requirements/notes.md"
git -C "$repo" add docs/requirements/notes.md
assert_fail_contains "$repo" "docs/requirements/notes.md is a private path"

repo="$(make_repo debt-entry-covers-a-hit)"
mkdir -p "$repo/docs/internal"
printf '# Notes\n' >"$repo/docs/internal/notes.md"
printf 'docs/internal/\tprivate-path\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/internal/notes.md
assert_pass "$repo"
# A debt entry with a count covers that many hits and no more.
repo="$(make_repo debt-count-exceeded)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/a.md"
printf 'docs/a.md\tprivate-name\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/a.md
assert_pass "$repo"
printf 'more hebb notes\n' >>"$repo/docs/a.md"
assert_fail_contains "$repo" "more than its 1"

# Debt on a directory covers what the base already carried, never a file the
# change adds under it.
repo="$(make_repo debt-dir-new-file)"
mkdir -p "$repo/docs/internal"
printf '# Old\n' >"$repo/docs/internal/old.md"
printf 'docs/internal/\tprivate-path\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
commit_all "$repo" "seed"
assert_base_pass "$repo" HEAD
printf '# New\n' >"$repo/docs/internal/new.md"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "docs/internal/new.md is a private path"

# A name git would quote is still compared as the literal path.
repo="$(make_repo private-path-quoted-name)"
mkdir -p "$repo/tickets"
printf '# Notes\n' >"$repo/tickets/ä.md"
git -C "$repo" add .gitignore scripts/dev tickets
assert_fail_contains "$repo" "tickets/ä.md is a private path"

# A clean file renamed to a ticket-id name is judged as an addition.
repo="$(make_repo ticket-id-by-rename)"
mkdir -p "$repo/tests"
printf 'fn main() { let reload = 1; let _ = reload; }\n' >"$repo/tests/reload.rs"
commit_all "$repo" "seed"
git -C "$repo" mv tests/reload.rs tests/mik_9999_reload.rs
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "tests/mik_9999_reload.rs names a ticket id"

# An added line whose text starts with "++ " is content, not a file header.
repo="$(make_repo ticket-id-after-plus-plus)"
mkdir -p "$repo/docs"
printf 'notes\n' >"$repo/docs/n.txt"
commit_all "$repo" "seed"
printf '++ follow MIK-5678\n' >>"$repo/docs/n.txt"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "adds a ticket id"

# Where a CI check keys a file by ticket number, the number is allowed: a
# changelog or UPGRADING fragment and an inventory row file, by name and in
# their text, and an acceptance-criterion id anywhere.
ticket_keyed_cases=(
  "changelog.d/9999.fixed.md::- Refuse a stale handle (MIK-9999)."
  "upgrading.d/9999-handles.md::Handles from before MIK-9999 are refused."
  "docs/release/inventory.d/9999.handles.tsv::src/x.rs	refuse	MIK-9999"
  "src/gateway/meta_mcp/boundary_pins/delivery_refusals.d/9999.tsv::src/x.rs	refuse	MIK-9999"
  "tests/handles.rs::// MIK-9999.HANDLE.1: a stale handle is refused."
)
for i in "${!ticket_keyed_cases[@]}"; do
  case_spec="${ticket_keyed_cases[$i]}"
  target="${case_spec%%::*}"
  line="${case_spec#*::}"
  repo="$(make_repo "ticket-keyed-$i")"
  commit_all "$repo" "seed"
  mkdir -p "$repo/$(dirname "$target")"
  printf '%s\n' "$line" >"$repo/$target"
  commit_all "$repo" "change"
  assert_base_pass "$repo" HEAD~1
done

# The same id as a citation in a docs page is still refused.
repo="$(make_repo ticket-id-in-doc-refused)"
commit_all "$repo" "seed"
mkdir -p "$repo/docs/adr"
printf 'Decided in MIK-9999.\n' >"$repo/docs/adr/ADR-099.md"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "docs/adr/ADR-099.md:1 adds a ticket id"

# Debt counts occurrences: a second name on an indebted line is a new hit.
repo="$(make_repo debt-counts-occurrences)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/b.md"
printf 'docs/b.md\tprivate-name\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/b.md
assert_pass "$repo"
printf 'the hebb and botnaut notes\n' >"$repo/docs/b.md"
assert_fail_contains "$repo" "more than its 1"

# A count above the hits left must come down, or the slack could regrow.
repo="$(make_repo debt-count-must-shrink)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/c.md"
printf 'docs/c.md\tprivate-name\t2\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/c.md
assert_fail_contains "$repo" "lower its count to 1"

# A path holding a colon is read whole, so it cannot pose as an exempt file.
repo="$(make_repo content-in-colon-path)"
mkdir -p "$repo/scripts/dev"
printf 'see the hebb notes\n' >"$repo/scripts/dev/public-hygiene-patterns.sh:extra.md"
git -C "$repo" add .gitignore scripts/dev
assert_fail_contains "$repo" "names a private project"

# Renaming a file does not re-add the ticket ids it already carried.
repo="$(make_repo ticket-id-kept-across-rename)"
mkdir -p "$repo/src"
printf '// Guard the reload path (MIK-1234).\nfn reload() {}\nfn a() {}\nfn b() {}\n' >"$repo/src/old.rs"
commit_all "$repo" "seed"
git -C "$repo" mv src/old.rs src/reload.rs
commit_all "$repo" "change"
assert_base_pass "$repo" HEAD~1

# A removed XMIK-1234 is not the id MIK-1234, so adding the id is refused.
repo="$(make_repo ticket-id-boundary-on-removal)"
mkdir -p "$repo/src"
printf '// token XMIK-1234\n' >"$repo/src/d.rs"
commit_all "$repo" "seed"
printf '// Guard the reload path (MIK-1234).\n' >"$repo/src/d.rs"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "src/d.rs:1 adds a ticket id"

# The private clone's path is refused even when force-added.
repo="$(make_repo internal-clone-force-added)"
mkdir -p "$repo/internal/docs"
printf '# Notes\n' >"$repo/internal/docs/notes.md"
git -C "$repo" add .gitignore scripts/dev
git -C "$repo" add -f internal/docs/notes.md
assert_fail_contains "$repo" "internal/docs/notes.md is a private path"

# A change may not raise a debt count or add a debt entry.
repo="$(make_repo debt-grows-in-change)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/e.md"
printf 'docs/e.md\tprivate-name\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
commit_all "$repo" "seed"
printf 'the hebb notes\nmore hebb notes\n' >"$repo/docs/e.md"
printf 'docs/e.md\tprivate-name\t2\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "count rose from 1 to 2"

repo="$(make_repo debt-entry-added-in-change)"
mkdir -p "$repo/docs"
printf 'notes\n' >"$repo/docs/f.md"
printf '# debt\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
commit_all "$repo" "seed"
printf 'the hebb notes\n' >"$repo/docs/f.md"
printf '# debt\ndocs/f.md\tprivate-name\t1\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
commit_all "$repo" "change"
assert_base_fail_contains "$repo" HEAD~1 "debt entry is new in this change"

# Every debt entry carries its count; dropping it cannot lift the cap.
repo="$(make_repo debt-entry-without-count)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/g.md"
printf 'docs/g.md\tprivate-name\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/g.md
assert_fail_contains "$repo" "no plain decimal hit count"

repo="$(make_repo debt-count-leading-zero)"
mkdir -p "$repo/docs"
printf 'the hebb notes\n' >"$repo/docs/h.md"
printf 'docs/h.md\tprivate-name\t08\n' >"$repo/scripts/dev/public-hygiene-debt.tsv"
git -C "$repo" add .gitignore scripts/dev docs/h.md
assert_fail_contains "$repo" "no plain decimal hit count"

# The whole check runs on every push, so its time on this tree is shown here,
# where a slow regression is visible. Informational: the verdict on the real
# tree is the CI step's job, not this fixture suite's.
start="$(date +%s)"
(cd "$source_repo" && scripts/dev/check-public-repo-hygiene.sh >/dev/null 2>&1) || true
printf 'timing: the full-tree check took %ss on this tree\n' "$(( $(date +%s) - start ))"

echo "public repo hygiene fixtures OK"
