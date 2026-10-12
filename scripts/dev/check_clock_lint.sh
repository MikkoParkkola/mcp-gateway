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
# and nothing outside the plant file is (the clean control). CARGO_TARGET_DIR
# defaults to this checkout's target/, so compiled dependencies are reused;
# CARGO=spark-cargo runs the clippy pass on the build server instead.
set -euo pipefail

if [ "${1:-}" != "--self-test" ]; then
  echo "usage: $0 --self-test" >&2
  exit 2
fi

root=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d)/tree
# A detached worktree, not a tar copy: `CARGO=spark-cargo` needs a git tree.
cleanup() { rm -rf "${scratch%/tree}"; git -C "$root" worktree prune; }
trap cleanup EXIT
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
#[allow(clippy::disallowed_methods, reason = "test code reads the host clock (MIK-8202 AC.14)")]
mod tests {
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
(
  cd "$scratch"
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}" \
    ${CARGO:-cargo} clippy --lib --tests --all-features --message-format=json -- -W clippy::disallowed_methods
) > "$out" 2> "$scratch/clippy.stderr" || true

python3 -I - "$out" "$scratch/$plant" "$plant" <<'PY'
import json, re, sys

out, plant_path, plant = sys.argv[1], sys.argv[2], sys.argv[3]
want, allowed = {}, {}
for number, line in enumerate(open(plant_path), 1):
    if m := re.search(r"// PLANT (\w+)", line):
        want[m.group(1)] = number
    if m := re.search(r"// ALLOWED (\w+)", line):
        allowed[m.group(1)] = number

hits, elsewhere = set(), []
for raw in open(out):
    try:
        msg = json.loads(raw)
    except ValueError:
        continue
    if msg.get("reason") != "compiler-message":
        continue
    diag = msg["message"]
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
for name, line in want.items():
    if line not in hits:
        failed.append(f"plant {name} ({plant}:{line}) was not reported as clippy::disallowed_methods")
for name, line in allowed.items():
    if line in hits:
        failed.append(f"the allowed {name} read ({plant}:{line}) was reported: the test-scope allow does not hold")
if elsewhere:
    failed.append("clean control failed: disallowed clock reads outside the plants:\n  " + "\n  ".join(sorted(set(elsewhere))))
if not hits and not elsewhere:
    failed.append("clippy reported nothing at all: did it run? (see clippy.stderr)")
for line in failed:
    print(f"check_clock_lint: FAIL: {line}")
if failed:
    print("".join(open(out.replace("clippy.json", "clippy.stderr")).readlines()[-30:]))
    sys.exit(1)
print(f"check_clock_lint: ok: {len(want)} plants reported at their lines, the test-scope allow holds, no other raw clock read")
PY
