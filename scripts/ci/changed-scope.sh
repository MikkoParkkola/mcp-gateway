#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Decides whether a pull request changes documentation only.
#
#   changed-scope.sh <base sha> <pr number> <head sha>   prints docs_only=true|false
#   changed-scope.sh --classify < NUL-separated paths    same, for a path list
#   changed-scope.sh --self-test
#
# docs_only=true only when EVERY changed path is in a closed allowlist:
# anything under docs/, or a Markdown or text file at the repository root.
# A .md anywhere else (tests/, src/, capabilities/, ...) can be a fixture or
# a code input, so it counts as code. Any error, an empty list, or a path
# outside the allowlist gives docs_only=false: the fallback always runs more.
set -euo pipefail

# Reads NUL-separated paths on stdin; prints true/false.
classify() {
  local path any=0
  while IFS= read -r -d '' path; do
    any=1
    case $path in
      docs/?*) ;;
      */*) echo false; return ;;
      *) ;;
    esac
  done
  if [[ $any -eq 1 ]]; then echo true; else echo false; fi
}

from_git() {
  local base=$1 pr=$2 head=$3 repo_url=${REPO_URL:?} probe
  probe=$(mktemp -d)
  trap 'rm -rf -- "$probe"' RETURN
  git init -q "$probe"
  # The head through refs/pull/<n>/head, which the base repository holds for
  # fork pull requests too; checked against the event's head SHA.
  git -C "$probe" fetch -q --depth=1 "$repo_url" "$base" "+refs/pull/$pr/head:refs/probe/head" || return 1
  [[ $(git -C "$probe" rev-parse refs/probe/head) == "$head" ]] || return 1
  # --no-renames: a rename from src/ to docs/ lists both sides.
  # Into a file, not a pipe: classify stops at the first code path, and the
  # writer's SIGPIPE would then read as a failed listing under pipefail.
  git -C "$probe" diff -z --no-renames --name-only "$base" "$head" >"$probe/paths" || return 1
  classify <"$probe/paths"
}

self_test() {
  local rc=0 got
  expect() { # want, description, paths...
    local want=$1 desc=$2; shift 2
    if (($#)); then got=$(printf '%s\0' "$@" | classify); else got=$(classify </dev/null); fi
    if [[ $got != "$want" ]]; then echo "self-test: $desc: expected $want, got $got" >&2; rc=1; fi
  }
  expect true  "docs page"                      docs/guide.md
  expect true  "nested docs asset with a space"  "docs/img/a b.png"
  expect true  "root README and root notes"     README.md NOTES.txt
  expect false "nested README (not docs)"       crates/x/README.md
  expect false "Markdown test fixture"          tests/fixtures/x.md
  expect false "docs plus one source file"      docs/guide.md src/lib.rs
  expect false "root non-doc file"              Cargo.toml
  expect false "workflow"                       .github/workflows/ci.yml
  expect false "rename from src/ into docs/"    src/old.rs docs/old.rs
  expect false "empty list"
  expect true  "filename with a newline"        $'docs/odd\nname.md'
  expect false "newline name hiding a src path" $'docs/x\nsrc/y.rs' src/y.rs
  expect false "bare docs directory name"       docs
  [[ $rc -eq 0 ]] && echo "self-test: 13 path lists classified as expected"
  return $rc
}

case ${1:-} in
  --self-test) self_test ;;
  --classify) echo "docs_only=$(classify)" ;;
  *)
    if out=$(from_git "${1:?base sha}" "${2:?pr number}" "${3:?head sha}"); then
      echo "docs_only=$out"
    else
      echo "docs_only=false"
      echo "could not list changed files; running everything" >&2
    fi
    ;;
esac
