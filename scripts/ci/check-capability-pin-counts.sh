#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Keep the supported-matrix capability-pinning numbers true, and re-check pin
# drift without a Rust build.
#
# Two things go stale independently:
#
#   1. The counts printed in docs/release/v4.0.0-supported-matrix.md. A release
#      criterion (NFR.BUILD.1 C2) is graded against that paragraph, and a count
#      nobody re-measures is worse than no count -- it reads as evidence while
#      being a memory of what was once true. Prose cannot drift silently if a
#      job recomputes it.
#
#   2. A pinned file whose body changed without the pin being re-issued. That
#      is the rug-pull case the pin exists for. tests/capability_pin_policy.rs
#      already asserts it, but only after a full --all-features build; this is
#      the same assertion in two seconds, so a poisoned file is caught on the
#      cheapest job rather than the slowest.
#
# The privilege rule (which capabilities MUST be pinned) is deliberately NOT
# reimplemented here -- tests/capability_pin_policy.rs owns it, and a second
# copy in bash would be a second thing to keep in sync. This script counts and
# verifies; it does not classify.
#
# Hash definition: SHA-256 over the file with its top-level `sha256:` line
# removed, per src/capability/hash.rs.

set -euo pipefail

cd "$(dirname "$0")/../.."

MATRIX="docs/release/v4.0.0-supported-matrix.md"
CAPDIR="capabilities"
TEMPLATE_PREFIX="capabilities/examples/"

fail=0

# The CI runner is ubuntu-latest (sha256sum); this script is also meant to be
# runnable locally on macOS, which ships shasum and not sha256sum. Under
# `set -e` a missing binary would fail the job on a green catalogue, which is
# the inverse of a gate, so pick one up front rather than assuming either.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256; }
else
  echo "FAIL: neither sha256sum nor shasum is on PATH; cannot verify any pin."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 is not on PATH; cannot read the published capability_count."
  exit 1
fi

# while-read rather than mapfile: macOS still ships /bin/bash 3.2, which has no
# mapfile, and this script is meant to be runnable locally before pushing.
files=()
while IFS= read -r f; do
  files+=("$f")
done < <(find "$CAPDIR" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort)

total=${#files[@]}
if [[ $total -eq 0 ]]; then
  echo "FAIL: no capability YAMLs found under $CAPDIR/ -- the glob is wrong, not the catalogue"
  exit 1
fi

templates=0
pinned=0
drifted=()
# `set -u` plus an empty array is an unbound-variable error on bash 3.2, so the
# count is tracked separately rather than read off ${#drifted[@]}.
drift_count=0

for f in "${files[@]}"; do
  case "$f" in
    "$TEMPLATE_PREFIX"*) templates=$((templates + 1)) ;;
  esac

  # Only a top-level `sha256:` is a pin; an indented one is a nested field.
  stored=$(sed -n '/^sha256:/{s/^sha256:[[:space:]]*//;p;q;}' "$f")
  [[ -z $stored ]] && continue

  pinned=$((pinned + 1))
  calc=$(sed '/^sha256:/d' "$f" | sha256 | cut -d' ' -f1)
  if [[ $stored != "$calc" ]]; then
    drifted+=("$f (pinned $stored, actual $calc)")
    drift_count=$((drift_count + 1))
  fi
done

production=$((total - templates))

echo "measured: total=$total production=$production templates=$templates pinned=$pinned"

if [[ $drift_count -gt 0 ]]; then
  echo "FAIL: $drift_count pinned capability file(s) no longer match their pin."
  echo "      Re-issue with \`mcp-gateway cap pin <file>\` if the edit was intended."
  printf '  %s\n' "${drifted[@]}"
  fail=1
fi

# The matrix states the counts as "<pinned> of the <total> files"; both numbers
# are extracted rather than pattern-matched loosely, so a doc that reworded the
# sentence into something unparseable fails here instead of passing vacuously.
claim=$(sed -n 's/.*\*\*: \([0-9]\{1,\}\) of$/\1/p' "$MATRIX" | head -1)
claim_total=$(sed -n 's/^the \([0-9]\{1,\}\) files under `capabilities\/`.*/\1/p' "$MATRIX" | head -1)

if [[ -z $claim || -z $claim_total ]]; then
  echo "FAIL: could not read the pinned-count claim out of $MATRIX."
  echo "      Expected a sentence ending '**: <pinned> of' followed by"
  echo "      'the <total> files under \`capabilities/\`'. Update this script and"
  echo "      the doc together if the wording changed on purpose."
  exit 1
fi

if [[ $claim -ne $pinned || $claim_total -ne $total ]]; then
  echo "FAIL: $MATRIX claims $claim of $claim_total pinned; measured $pinned of $total."
  echo "      Update the paragraph in the same commit as the catalogue change."
  fail=1
fi

# The published capability_count is the SHIPPED catalogue -- total minus the
# templates -- not the file count. v4.0.0-release-notes-DRAFT.md carried these
# as a "live contradiction" because nothing recomputed the denominators; they
# are three consistent numbers, and this is what keeps them that way.
claims_json="benchmarks/public_claims.json"
published=$(python3 -c "import json;print(json.load(open('$claims_json'))['capability_count'])")
if [[ $published -ne $production ]]; then
  echo "FAIL: $claims_json capability_count=$published; measured shipped catalogue=$production"
  echo "      (total $total minus $templates templates under $TEMPLATE_PREFIX)."
  fail=1
fi

# Third copy of the same figure, same denominator. Without this, a new
# capability updates the matrix and public_claims.json and leaves the catalogue
# README quietly one behind.
readme="$CAPDIR/README.md"
readme_count=$(sed -n 's/.*\*\*\([0-9]\{1,\}\) built-in capabilities\*\*.*/\1/p' "$readme" | head -1)
if [[ -z $readme_count ]]; then
  echo "FAIL: could not read the '**N built-in capabilities**' figure out of $readme."
  exit 1
fi
if [[ $readme_count -ne $production ]]; then
  echo "FAIL: $readme says $readme_count built-in capabilities; measured shipped catalogue=$production."
  fail=1
fi

if [[ $fail -eq 0 ]]; then
  echo "OK: $pinned of $total capability files pinned, every pin reproduces,"
  echo "    matrix agrees, published capability_count=$published matches the $production shipped."
fi

exit $fail
