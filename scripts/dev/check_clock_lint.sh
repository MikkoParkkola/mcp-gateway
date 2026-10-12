#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# MIK-8202 AC.9: the wall clock is read only in src/clock.rs, enforced by
# clippy's disallowed_methods (clippy.toml). Clippy does not fail on a
# disallowed path it cannot resolve, so a renamed or mistyped entry would turn
# the lint off without a word. This self-test proves each entry still bites.
#
# Usage: scripts/dev/check_clock_lint.sh --self-test
#
# It checks HEAD out into a scratch worktree, plants one violation per
# entry plus an alias, a function-pointer use and a test-scope boundary in a
# new module, runs clippy once (lib and lib tests, all features) and checks
# the JSON diagnostics: every plant is reported as clippy::disallowed_methods
# at its own file and line, the read inside the allowed test module is not,
# and nothing outside the plant file is (the clean control). It fails closed:
# clippy must exit 0, the build must finish with success, and any error-level
# diagnostic fails the check, so a broken build can never pass as "the lint
# bites". Before any cargo run the checker is itself proven on synthetic
# diagnostics (a clean run passes; an unrelated error, a failed build, a
# missing build completion and a nonzero clippy exit each fail).
# CARGO_TARGET_DIR defaults to this checkout's target/, so compiled
# dependencies are reused; CARGO=spark-cargo runs the clippy pass on the build
# server instead.
set -euo pipefail

if [ "${1:-}" != "--self-test" ]; then
  echo "usage: $0 --self-test" >&2
  exit 2
fi

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
scratch="$tmp/tree"
cleanup() {
  rm -rf "$tmp"
  git -C "$root" worktree prune
}
trap cleanup EXIT

# The checker. Arguments: clippy JSON, plant file, plant path as clippy names
# it, clippy's exit status, clippy's stderr.
checker="$tmp/check.py"
cat > "$checker" <<'PY'
import json, re, sys

out, plant_path, plant, rc, stderr = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
want, allowed = {}, {}
for number, line in enumerate(open(plant_path), 1):
    if m := re.search(r"// PLANT (\w+)", line):
        want[m.group(1)] = number
    if m := re.search(r"// ALLOWED (\w+)", line):
        allowed[m.group(1)] = number

hits, elsewhere, errors, finished = set(), [], [], None
for raw in open(out):
    try:
        msg = json.loads(raw)
    except ValueError:
        continue
    if msg.get("reason") == "build-finished":
        finished = bool(msg.get("success"))
        continue
    if msg.get("reason") != "compiler-message":
        continue
    diag = msg["message"]
    if diag.get("level") in ("error", "error: internal compiler error"):
        errors.append(diag.get("rendered") or diag.get("message", "?"))
        continue
    if (diag.get("code") or {}).get("code") != "clippy::disallowed_methods":
        continue
    for span in diag["spans"]:
        if not span["is_primary"]:
            continue
        if span["file_name"] == plant:
            hits.add(span["line_start"])
        else:
            elsewhere.append(f'{span["file_name"]}:{span["line_start"]}: {diag["message"]}')

failed = []
if rc != 0:
    failed.append(f"clippy exited {rc}: the plants were not linted by a clean build")
if finished is not True:
    failed.append("the build did not finish with success" if finished is False else "no build completion was reported")
if errors:
    failed.append("error-level diagnostics:\n  " + "\n  ".join(e.strip() for e in errors[:5]))
for name, line in want.items():
    if line not in hits:
        failed.append(f"plant {name} ({plant}:{line}) was not reported as clippy::disallowed_methods")
for name, line in allowed.items():
    if line in hits:
        failed.append(f"the allowed {name} read ({plant}:{line}) was reported: the test-scope allow does not hold")
if elsewhere:
    failed.append("clean control failed: disallowed clock reads outside the plants:\n  " + "\n  ".join(sorted(set(elsewhere))))
for line in failed:
    print(f"check_clock_lint: FAIL: {line}")
if failed:
    try:
        print("".join(open(stderr).readlines()[-30:]))
    except OSError:
        pass
    sys.exit(1)
print(f"check_clock_lint: ok: {len(want)} plants reported at their lines, the test-scope allow holds, no other raw clock read")
PY

# The checker's own proof, on synthetic diagnostics: a clean run passes, and
# each way a broken build could pass as "the lint bites" fails.
fake="$tmp/fake"
mkdir -p "$fake"
printf 'x // PLANT one\ny // ALLOWED two\n' > "$fake/plant.rs"
: > "$fake/stderr"
hit='{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::disallowed_methods"},"message":"use of a disallowed method","spans":[{"is_primary":true,"file_name":"src/p.rs","line_start":1}]}}'
unrelated='{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0425"},"message":"unrelated compile error","spans":[]}}'
ok_end='{"reason":"build-finished","success":true}'
bad_end='{"reason":"build-finished","success":false}'
proof() { # name, want (pass|fail), clippy rc, json lines...
  local name=$1 want=$2 rc=$3 got
  shift 3
  printf '%s\n' "$@" > "$fake/out.json"
  if python3 -I "$checker" "$fake/out.json" "$fake/plant.rs" src/p.rs "$rc" "$fake/stderr" > "$fake/log" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "check_clock_lint: FAIL: checker proof '$name' should $want but did $got" >&2
    cat "$fake/log" >&2
    exit 1
  fi
}
proof clean_run pass 0 "$hit" "$ok_end"
proof unrelated_error fail 0 "$hit" "$unrelated" "$ok_end"
proof failed_build fail 0 "$hit" "$bad_end"
proof no_build_completion fail 0 "$hit"
proof clippy_exit_nonzero fail 101 "$hit" "$ok_end"
echo "check_clock_lint: checker proven on 5 synthetic runs"

# A detached worktree, not a tar copy: `CARGO=spark-cargo` needs a git tree.
git -C "$root" worktree add --quiet --detach "$scratch" HEAD

plant=src/clock_lint_plants.rs
cat > "$scratch/$plant" <<'RUST'
//! MIK-8202 clock-lint self-test plants. Never committed.
#![allow(dead_code)]

fn plant_system_time_now() -> std::time::SystemTime {
    std::time::SystemTime::now() // PLANT system_time_now
}

fn plant_system_time_elapsed() -> Option<std::time::Duration> {
    std::time::UNIX_EPOCH.elapsed().ok() // PLANT system_time_elapsed
}

fn plant_utc_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() // PLANT utc_now
}

fn plant_local_now() -> chrono::DateTime<chrono::Local> {
    chrono::Local::now() // PLANT local_now
}

fn plant_jwt_timestamp() -> u64 {
    jsonwebtoken::get_current_timestamp() // PLANT jwt_timestamp
}

fn plant_alias() -> chrono::DateTime<chrono::Utc> {
    use chrono::Utc as U;
    U::now() // PLANT alias
}

fn plant_fn_pointer(at: Option<chrono::DateTime<chrono::Utc>>) -> chrono::DateTime<chrono::Utc> {
    at.unwrap_or_else(chrono::Utc::now) // PLANT fn_pointer
}

fn plant_beside_test_module() -> std::time::SystemTime {
    std::time::SystemTime::now() // PLANT beside_test_module
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "test code reads the host clock (MIK-8202 AC.14)")]
    #[test]
    fn reads_the_clock() {
        let _ = std::time::SystemTime::now(); // ALLOWED test_module
    }
}
RUST
# Declare the plant module in the product build too, so the non-test plants
# are linted where product code is.
printf '\nmod clock_lint_plants;\n' >> "$scratch/src/lib.rs"

out="$scratch/clippy.json"
rc=0
(
  cd "$scratch"
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}" \
    ${CARGO:-cargo} clippy --lib --tests --all-features --message-format=json -- -W clippy::disallowed_methods
) > "$out" 2> "$scratch/clippy.stderr" || rc=$?

python3 -I "$checker" "$out" "$scratch/$plant" "$plant" "$rc" "$scratch/clippy.stderr"
