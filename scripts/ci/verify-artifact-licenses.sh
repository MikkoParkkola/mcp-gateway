#!/usr/bin/env bash
# verify-artifact-licenses.sh — every published artifact must carry the license
# files, not just the git repo (counsel: verify license/notice files in the
# crates tarball, npm tarball, container filesystem, and Homebrew output).
#
# This is a static manifest audit: it asserts each channel's packaging config
# references the required files. It is fast and needs no network/build. Where a
# real build is cheap and the tools exist (cargo), it also does a live check.
set -euo pipefail
cd "$(dirname "$0")/../.."

REQUIRED=(LICENSE LICENSE-MIT LICENSE-NONCOMMERCIAL LICENSES.md NOTICE.md)
rc=0
fail() { echo "FAIL: $*" >&2; rc=1; }
ok()   { echo "ok: $*"; }

# 0. The files exist in the repo.
for f in "${REQUIRED[@]}"; do
  [ -f "$f" ] || fail "repo is missing $f"
done

# 1. crates.io tarball — Cargo.toml `include` must list each file (or there must
#    be no `include`, in which case cargo ships everything not git-ignored).
if grep -Eq '^include[[:space:]]*=[[:space:]]*\[' Cargo.toml; then
  inc="$(awk '/^include[[:space:]]*=[[:space:]]*\[/{f=1} f{print} f&&/\]/{exit}' Cargo.toml)"
  for f in "${REQUIRED[@]}"; do
    printf '%s' "$inc" | grep -q "\"$f\"" || fail "Cargo.toml include[] omits $f"
  done
  ok "Cargo.toml include[] lists all license files"
else
  ok "Cargo.toml has no include[] (cargo ships all non-ignored files)"
fi
# Live check when cargo is present (lists the exact tarball contents).
if command -v cargo >/dev/null 2>&1; then
  if listing="$(cargo package --list --allow-dirty 2>/dev/null)"; then
    for f in "${REQUIRED[@]}"; do
      printf '%s\n' "$listing" | grep -qx "$f" || fail "cargo package tarball would omit $f"
    done
    ok "cargo package --list contains all license files"
  fi
fi

# 2. npm tarball — package.json `files` must list each, and prepack copies them
#    into the package dir (they live one level up from npm/).
if [ -f npm/package.json ]; then
  for f in "${REQUIRED[@]}"; do
    grep -q "\"$f\"" npm/package.json || fail "npm/package.json files[] omits $f"
  done
  grep -q '"prepack"' npm/package.json || fail "npm/package.json has no prepack to stage license files"
  ok "npm/package.json files[] + prepack cover all license files"
fi

# 3. container image — Dockerfile must COPY the license files into the final image.
if [ -f Dockerfile ]; then
  for f in "${REQUIRED[@]}"; do
    grep -Eq "COPY([^#]*)\b$f\b" Dockerfile || fail "Dockerfile does not COPY $f into the image"
  done
  ok "Dockerfile copies all license files into the image"
fi

# 4. Homebrew — bare-binary formula can't embed a text file, so require an honest
#    license declaration and a licensing pointer in caveats.
if [ -f homebrew/mcp-gateway.rb ]; then
  grep -q 'license :cannot_represent' homebrew/mcp-gateway.rb \
    || fail "homebrew formula must declare 'license :cannot_represent' (mixed licensing)"
  grep -qi 'COMMERCIAL.md\|Noncommercial' homebrew/mcp-gateway.rb \
    || fail "homebrew formula caveats must point to the license/COMMERCIAL terms"
  ok "homebrew formula: honest license declaration + licensing caveat"
fi

[ "$rc" -eq 0 ] && echo "ok: all packaged artifacts carry the license files"
exit $rc
