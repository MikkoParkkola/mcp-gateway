#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Ratchet on the DoD "Files <= 800 LOC" gate.
#
# 56 production files in src/ breach the ceiling today. Splitting them is not in
# 4.0.0 (MIK-7478), so the deviation is bounded here instead of left open: the
# count may fall, never rise. When it falls, lower CEILING in the same commit --
# failing on an improvement is what makes this a ratchet rather than a
# high-water mark that quietly admits a 58th breach.
#
# Test sources are excluded because the gate is about production source; the
# exclusion is the same one MIK-7478's fail-fast check uses.
set -euo pipefail

CEILING=54
LIMIT=800

# Count .rs files under $1 whose length exceeds LIMIT, skipping test sources.
# `-exec ... +` runs nothing when nothing matches, so wc never reads stdin.
breaches() {
  find "$1" -name '*.rs' ! -name '*_tests.rs' ! -name 'tests.rs' -exec wc -l {} + |
    awk -v limit="$LIMIT" '$2 != "total" && $1 > limit { n++ } END { print n + 0 }'
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/deep"
  lines() { awk -v n="$1" 'BEGIN { while (i++ < n) print "fn x() {}" }'; }
  lines 801 >"$tmp/over.rs"
  lines 800 >"$tmp/exactly_at.rs"
  lines 801 >"$tmp/deep/also_over.rs"
  lines 801 >"$tmp/over_tests.rs"
  lines 801 >"$tmp/tests.rs"
  got="$(breaches "$tmp")"
  if [ "$got" != "2" ]; then
    echo "self-test: expected 2 breaches, counted $got" >&2
    exit 1
  fi
  echo "self-test: counted 2 -- 800 exactly is not a breach, test sources excluded"
  exit 0
fi

count="$(breaches src)"

if [ "$count" -gt "$CEILING" ]; then
  echo "$count production files exceed $LIMIT lines; the ceiling is $CEILING." >&2
  echo "The 4.0.0 deviation is bounded, so a new breach is not admitted." >&2
  echo "Split the file, or move the new code into a module of its own." >&2
  exit 1
fi

if [ "$count" -lt "$CEILING" ]; then
  echo "$count production files exceed $LIMIT lines, down from $CEILING." >&2
  echo "Lower CEILING to $count in scripts/ci/check-loc-ceiling.sh so the" >&2
  echo "ground gained cannot be given back." >&2
  exit 1
fi

echo "$count production files exceed $LIMIT lines, at the $CEILING ceiling (MIK-7478)"
