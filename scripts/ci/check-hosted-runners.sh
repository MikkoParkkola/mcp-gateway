#!/usr/bin/env bash
# Fail the build when a workflow schedules a job on anything other than a
# GitHub-hosted runner.
#
# Third-party runner fleets bill per job-minute against a separate account.
# A fleet label that reaches main is invisible in diff review and silent in
# the run logs; the only signal is the invoice. This keeps every `runs-on:`
# and every matrix `os:` value inside the GitHub-hosted namespace, so
# swapping in a fleet has to be a deliberate edit to the allowlist below.
set -euo pipefail

# GitHub-hosted images. `${{ matrix.os }}` is the one expression that passes,
# because the matrix `os:` entries it expands to are checked on their own; any
# other expression could resolve to a fleet label that never appears in a diff.
readonly ALLOWED='^((ubuntu|windows|macos)-[A-Za-z0-9._-]+|\$\{\{[[:space:]]*matrix\.os[[:space:]]*\}\})$'

runner_is_allowed() {
  [[ $1 =~ $ALLOWED ]]
}

# Emits "path:line:value" for every runner label a workflow declares:
# `runs-on:` anywhere, and `os:` only inside a `matrix:` block, so an action
# input that happens to be named `os` is not mistaken for a runner. Handles
# both spellings of a list -- inline (`os: [ubuntu-latest, windows-2025]`)
# and block sequence (`runs-on:` followed by indented `- ` items) -- and skips
# the body of a block scalar, where `runs-on:` is shell text, not YAML.
declared_runners() {
  awk '
    function emit(raw,   n, parts, i, item) {
      gsub(/^\[|\][[:space:]]*$/, "", raw)
      n = split(raw, parts, /,/)
      for (i = 1; i <= n; i++) {
        item = parts[i]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", item)
        gsub(/^["'"'"']|["'"'"']$/, "", item)
        if (item != "")
          print FILENAME ":" FNR ":" item
      }
    }
    FNR == 1 { matrix_indent = -1; pending_indent = -1; block_indent = -1 }
    {
      indent = match($0, /[^[:space:]]/) - 1
      if ($0 ~ /^[[:space:]]*$/) next
      if (block_indent >= 0) {
        if (indent > block_indent) next
        block_indent = -1
      }

      line = $0
      sub(/[[:space:]]+#.*$/, "", line)
      if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) next

      if (matrix_indent >= 0 && indent <= matrix_indent) matrix_indent = -1

      if (pending_indent >= 0) {
        if (indent > pending_indent && line ~ /^[[:space:]]*-[[:space:]]/) {
          value = line
          sub(/^[[:space:]]*-[[:space:]]*/, "", value)
          emit(value)
          next
        }
        pending_indent = -1
      }

      if (line ~ /^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*[|>]/) { block_indent = indent; next }
      if (line ~ /^[[:space:]]*matrix:[[:space:]]*$/) { matrix_indent = indent; next }

      if (line ~ /^[[:space:]]*(-[[:space:]]+)?runs-on:/) ;
      else if (matrix_indent >= 0 && line ~ /^[[:space:]]*(-[[:space:]]+)?os:/) ;
      else next

      value = line
      sub(/^[^:]*:[[:space:]]*/, "", value)
      if (value == "") { pending_indent = indent; next }
      emit(value)
    }
  ' "$@"
}

scan() {
  local dir="${1:-.github/workflows}"
  local -a files=()
  shopt -s nullglob
  files=("$dir"/*.yml "$dir"/*.yaml)
  shopt -u nullglob
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "no workflow files under $dir -- the guard would pass vacuously" >&2
    return 1
  fi

  local entries
  entries=$(declared_runners "${files[@]}") || {
    echo "failed to read runner labels from $dir" >&2
    return 1
  }
  if [[ -z $entries ]]; then
    echo "no runs-on declarations found under $dir -- the guard would pass vacuously" >&2
    return 1
  fi

  local rc=0 entry value
  while IFS= read -r entry; do
    value="${entry#*:*:}"
    if ! runner_is_allowed "$value"; then
      echo "${entry%:*}: job runs on a non-GitHub-hosted runner: $value" >&2
      rc=1
    fi
  done <<<"$entries"
  if [[ $rc -ne 0 ]]; then
    echo "Extend ALLOWED in scripts/ci/check-hosted-runners.sh only for images GitHub bills." >&2
  fi
  return $rc
}

# Proves the scanner reacts to whole workflow files, not just to labels in
# isolation: a fleet label hidden in a matrix, in an inline sequence, or
# behind an expression has to turn the exit status red.
self_test() {
  local rc=0 dir
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN

  cat >"$dir/good.yml" <<'YAML'
jobs:
  a:
    runs-on: ubuntu-latest
  b:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-2025]
        include:
          - os: macos-26
    runs-on: ${{ matrix.os }}
    steps:
      - uses: some/action@v1
        with:
          os: linux-fleet
      - name: A block scalar is shell text, not YAML
        run: |
          echo "runs-on: avrea-ubuntu-latest"
          os: avrea-macos-26-8-vcpu
  c:
    runs-on:
      - ubuntu-latest
YAML
  if ! scan "$dir" >/dev/null 2>&1; then
    echo "self-test: rejected a workflow that only uses GitHub-hosted runners" >&2
    rc=1
  fi

  local case_name body
  for case_name in direct inline matrix sequence matrix-sequence expression; do
    case $case_name in
      direct) body='jobs:
  a:
    runs-on: avrea-ubuntu-latest' ;;
      inline) body='jobs:
  a:
    strategy:
      matrix:
        os: [ubuntu-latest, avrea-macos-26-8-vcpu]
    runs-on: ${{ matrix.os }}' ;;
      matrix) body='jobs:
  a:
    strategy:
      matrix:
        include:
          - os: avrea-windows-2025-4-vcpu
    runs-on: ${{ matrix.os }}' ;;
      sequence) body='jobs:
  a:
    runs-on:
      - avrea-ubuntu-latest-4-vcpu' ;;
      matrix-sequence) body='jobs:
  a:
    strategy:
      matrix:
        os:
          - ubuntu-latest
          - avrea-ubuntu-22.04-4-vcpu
    runs-on: ${{ matrix.os }}' ;;
      expression) body='jobs:
  a:
    runs-on: ${{ vars.RUNNER_LABEL }}' ;;
    esac
    printf '%s\n' "$body" >"$dir/good.yml"
    if scan "$dir" >/dev/null 2>&1; then
      echo "self-test: a fleet label slipped through the $case_name case" >&2
      rc=1
    fi
  done

  rm -f "$dir/good.yml"
  if scan "$dir" >/dev/null 2>&1; then
    echo "self-test: an empty workflow directory passed instead of failing" >&2
    rc=1
  fi

  if [[ $rc -eq 0 ]]; then
    echo "self-test: 8 workflow fixtures classified as expected"
  fi
  return $rc
}

if [[ ${1:-} == --self-test ]]; then
  self_test
else
  scan
fi
