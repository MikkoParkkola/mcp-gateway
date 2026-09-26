#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Verify capability pins with the shipped command, not a copy of its hash.
#
# check-capability-pin-counts.sh recomputes each pin in shell, and the Rust
# tests call compute_capability_hash directly or use fixtures. Neither proves
# that the binary an operator runs, `mcp-gateway cap validate`, accepts the
# pinned files the catalogue ships and refuses one that was edited after it
# was pinned. This script runs that binary against the real files:
#
#   1. every pinned capability under capabilities/ must validate (exit 0);
#   2. a copy of one pinned file with its upstream URL swapped for another
#      host (the rug-pull case the pin exists for) must be refused with the
#      hash-mismatch error;
#   3. the same tampered copy with its pin removed must validate, so the
#      refusal in (2) is known to come from the pin and not from the edit
#      having made the file invalid in some other way.
#
# Usage: check-cap-validate-pins.sh [path-to-mcp-gateway-binary]
#        (default: target/debug/mcp-gateway)

set -euo pipefail

cd "$(dirname "$0")/../.."

BIN="${1:-target/debug/mcp-gateway}"
CAPDIR="capabilities"
TAMPER_SRC="capabilities/communication/slack_post_message.yaml"
TAMPER_FROM="base_url: https://slack.com"
TAMPER_TO="base_url: https://slack.com.attacker.example"
MISMATCH="Capability hash mismatch"

if [[ ! -x "$BIN" ]]; then
  echo "FAIL: $BIN is not an executable; build it first (cargo build --bin mcp-gateway)"
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# while-read rather than mapfile: macOS /bin/bash 3.2 has no mapfile.
pinned=()
while IFS= read -r f; do
  if grep -q '^sha256:' "$f"; then
    pinned+=("$f")
  fi
done < <(find "$CAPDIR" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort)

count=${#pinned[@]}
if [[ $count -eq 0 ]]; then
  echo "FAIL: no pinned capability found under $CAPDIR/ -- the finder is wrong, not the catalogue"
  exit 1
fi

# (1) Every shipped pin verifies through the shipped command.
fail=0
for f in "${pinned[@]}"; do
  if ! "$BIN" cap validate "$f" >"$work/out" 2>&1; then
    echo "FAIL: cap validate rejected shipped pinned file $f:"
    cat "$work/out"
    fail=1
  fi
done
if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "ok: cap validate accepted all $count pinned capability files"

# (2) A tampered copy of a pinned file is refused, for the pin's reason.
if ! grep -q '^sha256:' "$TAMPER_SRC"; then
  echo "FAIL: $TAMPER_SRC is no longer pinned; pick another pinned file to tamper"
  exit 1
fi
if ! grep -qF "$TAMPER_FROM" "$TAMPER_SRC"; then
  echo "FAIL: '$TAMPER_FROM' not found in $TAMPER_SRC; the tamper would be a no-op"
  exit 1
fi
tampered="$work/$(basename "$TAMPER_SRC")"
sed "s|${TAMPER_FROM//./\\.}|$TAMPER_TO|" "$TAMPER_SRC" >"$tampered"
if cmp -s "$TAMPER_SRC" "$tampered"; then
  echo "FAIL: the tampered copy is byte-identical to $TAMPER_SRC"
  exit 1
fi

if "$BIN" cap validate "$tampered" >"$work/out" 2>&1; then
  echo "FAIL: cap validate ACCEPTED a pinned file whose base_url was changed after pinning:"
  cat "$work/out"
  exit 1
fi
if ! grep -qF "$MISMATCH" "$work/out"; then
  echo "FAIL: cap validate refused the tampered file, but not with '$MISMATCH':"
  cat "$work/out"
  exit 1
fi
echo "ok: cap validate refused the tampered copy of $TAMPER_SRC with a hash mismatch"

# (3) Control: without its pin the tampered file is valid, so (2) was the pin.
unpinned="$work/unpinned-$(basename "$TAMPER_SRC")"
grep -v '^sha256:' "$tampered" >"$unpinned"
if ! "$BIN" cap validate "$unpinned" >"$work/out" 2>&1; then
  echo "FAIL: the tampered copy is invalid even without its pin, so (2) does not isolate the pin check:"
  cat "$work/out"
  exit 1
fi
echo "ok: the tampered copy validates once its pin is removed; the refusal came from the pin"
