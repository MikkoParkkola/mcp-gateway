#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
src="$REPO_ROOT/scripts/dev/pre-push.sh"
dst="$REPO_ROOT/.git/hooks/pre-push"
chmod +x "$src"
if [[ -e "$dst" && ! -L "$dst" ]]; then
  mv "$dst" "$dst.bak.$(date +%Y%m%d-%H%M%S)"
fi
ln -sf "$src" "$dst"
echo "installed: $dst -> $src"
