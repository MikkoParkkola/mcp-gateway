#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Decides whether a pull request changes documentation only.
#
#   changed-scope.sh <merge sha> <pr number> <head sha>  prints docs_only=true|false
#     (<merge sha> is github.sha of the pull_request event: GitHub's test-merge
#      commit of the head into the base; see from_git_in)
#   changed-scope.sh --classify < NUL-separated paths    same, for a path list
#   changed-scope.sh --range <base> <head>                same, for two commits of the local repository
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
      *.md | *.txt) ;;
      *) echo false; return ;;
    esac
  done
  if [[ $any -eq 1 ]]; then echo true; else echo false; fi
}

# Reads NUL-separated deleted paths; true when any sits at the repository root.
deletes_root_file() {
  local path
  while IFS= read -r -d '' path; do
    [[ $path == */* ]] || { echo true; return; }
  done
  echo false
}

from_git() {
  local merge=$1 pr=$2 head=$3 repo_url=${REPO_URL:?} probe
  probe=$(mktemp -d)
  from_git_in "$probe" "$merge" "$pr" "$head" "$repo_url"
  local rc=$?
  rm -rf -- "$probe"
  return $rc
}

from_git_in() {
  local probe=$1 merge=$2 head=$4 repo_url=$5
  git init -q "$probe"
  # The event's own test-merge commit (github.sha on a pull_request event):
  # first parent is the base tip it was built on, second the PR head. Diffing
  # it against its first parent lists exactly what the PR changes, however far
  # the base had moved since the PR branched, and it is the very tree this run
  # tests. Unreachable (the merge was recomputed since) or not a merge of this
  # head: the caller falls back to running everything.
  git -C "$probe" fetch -q --depth=2 "$repo_url" "$merge" || return 1
  [[ $(git -C "$probe" rev-parse "$merge^2") == "$head" ]] || return 1
  # --no-renames: a rename from src/ to docs/ lists both sides.
  # Into a file, not a pipe: classify stops at the first code path, and the
  # writer's SIGPIPE would then read as a failed listing under pipefail.
  git -C "$probe" diff -z --no-renames --name-only "$merge^1" "$merge" >"$probe/paths" || return 1
  # Root Markdown/text files are packaging inputs (the Dockerfile copies the
  # licence and notice files; Cargo.toml's include lists README, CHANGELOG and
  # more). Editing one is documentation; deleting one breaks the image or the
  # crate package, so any deleted root file means "run everything".
  git -C "$probe" diff -z --no-renames --name-only --diff-filter=D "$merge^1" "$merge" >"$probe/deleted" || return 1
  if [[ $(deletes_root_file <"$probe/deleted") == true ]]; then echo false; return; fi
  classify <"$probe/paths"
}

# Local mode, for merge-train: the PR mode's listing (--no-renames) and deleted-root-file rule, between two
# commits of the repository in the current directory. merge-train runs it on its own checkout with the
# base copy of this script, to judge a train's docs-only allowance the way the scope job would.
from_range() {
  local base=$1 head=$2 probe rc=0
  probe=$(mktemp -d) || return 1
  if git diff -z --no-renames --name-only "$base" "$head" >"$probe/paths" &&
     git diff -z --no-renames --name-only --diff-filter=D "$base" "$head" >"$probe/deleted"; then
    if [[ $(deletes_root_file <"$probe/deleted") == true ]]; then echo false; else classify <"$probe/paths"; fi
  else
    rc=1
  fi
  rm -rf -- "$probe"
  return $rc
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
  for spec in "true:COMMERCIAL.md" "true:README.md docs/a.md" "false:docs/old.md" "false:"; do
    local want=${spec%%:*} list=${spec#*:} p=()
    [[ -n $list ]] && read -r -a p <<<"$list"
    if ((${#p[@]})); then got=$(printf '%s\0' "${p[@]}" | deletes_root_file); else got=$(deletes_root_file </dev/null); fi
    if [[ $got != "$want" ]]; then echo "self-test: deleted [$list]: expected $want, got $got" >&2; rc=1; fi
  done
  [[ $rc -eq 0 ]] && echo "self-test: 13 path lists and 4 deletion lists classified as expected"
  range_self_test || rc=1
  return $rc
}

# --range on a throwaway repository: the rename and deleted-root-file rules hold in local mode
# too (merge-train runs this mode on its own checkout).
range_self_test() {
  local repo rc=0 base got
  repo=$(mktemp -d) || return 1
  git -C "$repo" init -q && mkdir -p "$repo/src" "$repo/docs" &&
    echo a >"$repo/src/old.rs" && echo r >"$repo/README.md" && echo d >"$repo/docs/x.md" &&
    git -C "$repo" add -A && git -C "$repo" -c user.name=t -c user.email=t@t commit -q -m base || { rm -rf -- "$repo"; return 1; }
  base=$(git -C "$repo" rev-parse HEAD)
  range_case() { # want, description, then a shell edit run inside the repository
    local want=$1 desc=$2 edit=$3
    git -C "$repo" checkout -q --detach "$base" &&
      (cd "$repo" && eval "$edit") && git -C "$repo" add -A &&
      git -C "$repo" -c user.name=t -c user.email=t@t commit -q -m "$desc" || { echo "self-test: --range $desc: setup failed" >&2; rc=1; return; }
    got=$(cd "$repo" && from_range "$base" HEAD)
    [[ $got == "$want" ]] || { echo "self-test: --range $desc: expected $want, got $got" >&2; rc=1; }
  }
  range_case true  "docs edit"                   'echo e >docs/x.md'
  range_case false "rename from src/ into docs/" 'git mv src/old.rs docs/old.rs'
  range_case false "deleted root file"           'git rm -q README.md'
  range_case false "source edit"                 'echo b >src/old.rs'
  rm -rf -- "$repo"
  [[ $rc -eq 0 ]] && echo "self-test: 4 --range cases classified as expected"
  return $rc
}

case ${1:-} in
  --self-test) self_test ;;
  --classify) echo "docs_only=$(classify)" ;;
  --range)
    if out=$(from_range "${2:?base sha}" "${3:?head sha}"); then
      echo "docs_only=$out"
    else
      echo "docs_only=false"
      echo "could not list changed files; running everything" >&2
    fi
    ;;
  *)
    if out=$(from_git "${1:?merge sha}" "${2:?pr number}" "${3:?head sha}"); then
      echo "docs_only=$out"
    else
      echo "docs_only=false"
      echo "could not list changed files; running everything" >&2
    fi
    ;;
esac
