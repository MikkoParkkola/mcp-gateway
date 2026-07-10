#!/usr/bin/env bash
# deprecate-leaked-3x.sh — withdraw the mis-licensed v3.0.0–v3.2.1 releases
# across channels after the corrected release (v3.3.0) is published.
#
# Honest limit: this removes DISTRIBUTION, it does NOT revoke MIT rights already
# granted on copies people obtained. See NOTICE.md.
#
# DRY-RUN by default. Pass --apply to execute. Requires: the corrected release
# is already published and is "latest" on each channel. Operator-run only.
set -euo pipefail
APPLY=false; [ "${1:-}" = "--apply" ] && APPLY=true
OLD=(3.0.0 3.1.0 3.1.1 3.1.2 3.1.3 3.1.4 3.2.0 3.2.1)  # adjust to the exact published set
run() { echo "+ $*"; $APPLY && "$@"; }
note="Licensing correction: v3.0.0–v3.2.1 shipped enterprise code under MIT by mistake. Deprecated; use >=3.3.0. See NOTICE.md."

echo "== 1. crates.io: yank old versions (blocks new resolution; existing lockfiles unaffected)"
for v in "${OLD[@]}"; do run cargo yank --version "$v" mcp-gateway; done

echo "== 2. npm: deprecate the mis-licensed range"
run npm deprecate "mcp-gateway@>=3.0.0 <3.3.0" "$note"

echo "== 3. ghcr / Docker: delete old container package versions (keep digests documented in NOTICE)"
echo "   Manual/gated — list versions then delete by id:"
echo "   gh api /user/packages/container/mcp-gateway/versions --jq '.[] | select(.metadata.container.tags[]? | test(\"^3\\\\.(0|1|2)\\\\.\")) | .id'"
echo "   gh api --method DELETE /user/packages/container/mcp-gateway/versions/<id>"

echo "== 4. GitHub Releases: add NOTICE banner, remove 'latest' from old (DO NOT delete tags)"
for v in "${OLD[@]}"; do
  echo "   edit release v$v: prepend NOTICE banner, mark --latest=false"
  $APPLY && gh release edit "v$v" --repo MikkoParkkola/mcp-gateway --latest=false \
    --notes "> **DEPRECATED — licensing correction.** $note

$(gh release view "v$v" --repo MikkoParkkola/mcp-gateway --json body -q .body 2>/dev/null)" || true
done

echo "== 5. Homebrew tap: bump formula to 3.3.0 and deprecate! old formulae (manual in the tap repo)"
echo "== 6. Verify: 'latest' everywhere points at the corrected release; NOTICE.md linked from README."
$APPLY || echo "(dry-run — re-run with --apply after the corrected release is published)"
