#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The crate's futures sit close to rustc's trait-recursion limit (default 128).
# Windows and Kani overflow first, so on Linux a deepened future passes every job
# and then fails those two, late and reading like a platform problem (MIK-7678).
# This type-checks the library and its tests at LIMIT, the lowest value the tree
# passes at, with no slack: the next deepening fails here, on Linux, by name.
#
# Measured 2026-10-06 on 555cedb5d (run of throwaway/recursion-probe-1):
# 127 and 126 pass, 125 fails with E0275. Lower LIMIT when the tree gets
# shallower; never raise it to make a deeper future pass.
#
# usage: check-recursion-margin.sh   (from the repository root; edits and restores src/lib.rs)
set -euo pipefail

LIMIT=126
lib=src/lib.rs
log=$(mktemp)
backup=$(mktemp)
cp "$lib" "$backup"
trap 'cp "$backup" "$lib"; rm -f -- "$backup" "$log"' EXIT
{ printf '#![recursion_limit = "%s"]\n' "$LIMIT"; cat "$backup"; } > "$lib"

if cargo check --all-features --lib --tests 2>&1 | tee "$log"; then
  echo "type-checks at recursion_limit $LIMIT"
  exit 0
fi
if grep -q 'error\[E0275\]' "$log"; then
  echo "::error::A future is now deeper than recursion_limit $LIMIT allows (E0275 above; MIK-7678)." \
    "Windows and Kani overflow on it first. Erase the new future's type at the await that" \
    "deepened it (return Pin<Box<dyn Future + Send>>, as Backend::undeclared_key_refusal does);" \
    "do not raise the crate's recursion limit."
fi
exit 1
