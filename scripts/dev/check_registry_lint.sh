#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# MIK-8387 PR-B: the backend-registry ban (scripts/lint/registry-ban/clippy.toml,
# read through CLIPPY_CONF_DIR by a production-only clippy pass) still bites.
# Clippy only warns when a disallowed path does not resolve, so a renamed
# method would switch the ban off without a word. The sibling of
# check_clock_lint.sh (MIK-8202 AC.9).
#
# Usage: scripts/dev/check_registry_lint.sh --self-test
#
# It checks HEAD out into a scratch worktree and plants, in a new module of
# gateway::meta_mcp: one function-item reference per config entry, a method
# call, a fully qualified call, an alias, a raw read inside a local macro, a
# leaf-allowed statement (must not fire), a cfg(test) read (not compiled in a
# --lib pass), and three release-only plants (must fire only in --release).
# Two clippy runs (dev, release), JSON diagnostics: every plant at its own
# line, nothing else anywhere (the clean control: no unclassed production
# read), no unresolved config path, and a clean build. The checker is proven
# on synthetic diagnostics first. CARGO=spark-cargo runs the passes on Spark.
#
# Warm cache: verified on clippy 1.99 (2026-10-18, Spark) that a change of
# CLIPPY_CONF_DIR alone re-lints a crate an earlier plain clippy pass left
# fresh, so the ban steps after CI's and pre-push's ordinary clippy are not
# cache replays. Rerun `--cache-probe` (manual, not in CI) when the toolchain
# pin changes: a plain pass warms the cache, then the dev ban pass must still
# report every plant.
set -euo pipefail

action=${1:-}
if [ "$action" != "--self-test" ] && [ "$action" != "--cache-probe" ]; then
  echo "usage: $0 --self-test | --cache-probe" >&2
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

# The checker. Arguments: mode (dev|release), clippy JSON, plant file, plant
# path as clippy names it, clippy's exit status, clippy's stderr.
checker="$tmp/check.py"
cat > "$checker" <<'PY'
import json, re, sys

mode, out, plant_path, plant, rc, stderr = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6]
want, quiet = {}, {}
for number, line in enumerate(open(plant_path), 1):
    found = re.search(r"// (PLANT|ALLOWED|TESTONLY|RELEASE) (\w+)", line)
    if not found:
        continue
    tag, name = found.groups()
    if tag == "PLANT" or (tag == "RELEASE" and mode == "release"):
        want[name] = number
    else:
        quiet[name] = number

hits, elsewhere, errors, unresolved, finished = set(), [], [], [], None
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
    text = diag.get("message", "")
    if "does not refer to a reachable function" in text or "does not refer to an existing function" in text:
        unresolved.append(text)
        continue
    if diag.get("level") in ("error", "error: internal compiler error"):
        errors.append(diag.get("rendered") or text or "?")
        continue
    if (diag.get("code") or {}).get("code") != "clippy::disallowed_methods":
        continue
    for span in diag["spans"]:
        if not span["is_primary"]:
            continue
        if span["file_name"] == plant:
            hits.add(span["line_start"])
        else:
            elsewhere.append(f'{span["file_name"]}:{span["line_start"]}: {text}')

failed = []
if rc != 0:
    failed.append(f"clippy exited {rc}: the plants were not linted by a clean build")
if finished is not True:
    failed.append("the build did not finish with success" if finished is False else "no build completion was reported")
if errors:
    failed.append("error-level diagnostics:\n  " + "\n  ".join(e.strip() for e in errors[:5]))
if unresolved:
    failed.append("a config entry does not resolve:\n  " + "\n  ".join(unresolved[:5]))
for name, line in want.items():
    if line not in hits:
        failed.append(f"plant {name} ({plant}:{line}) was not reported in the {mode} pass")
for name, line in quiet.items():
    if line in hits:
        failed.append(f"{name} ({plant}:{line}) was reported in the {mode} pass and must not be")
if elsewhere:
    failed.append("clean control failed: unclassed registry reads outside the plants:\n  " + "\n  ".join(sorted(set(elsewhere))[:20]))
for line in failed:
    print(f"check_registry_lint: FAIL: {line}")
if failed:
    try:
        print("".join(open(stderr).readlines()[-30:]))
    except OSError:
        pass
    sys.exit(1)
print(f"check_registry_lint: ok ({mode}): {len(want)} plants reported at their lines, {len(quiet)} quiet, no other registry read")
PY

# The checker's own proof, on synthetic diagnostics: a clean run passes, and
# each way a broken run could pass as "the ban bites" fails.
fake="$tmp/fake"
mkdir -p "$fake"
printf 'x // PLANT one\ny // ALLOWED two\nz // RELEASE three\n' > "$fake/plant.rs"
: > "$fake/stderr"
hit='{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::disallowed_methods"},"message":"use of a disallowed method","spans":[{"is_primary":true,"file_name":"src/p.rs","line_start":1}]}}'
hit3='{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::disallowed_methods"},"message":"use of a disallowed method","spans":[{"is_primary":true,"file_name":"src/p.rs","line_start":3}]}}'
other='{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::disallowed_methods"},"message":"use of a disallowed method","spans":[{"is_primary":true,"file_name":"src/x.rs","line_start":9}]}}'
loose='{"reason":"compiler-message","message":{"level":"warning","code":null,"message":"`a::b` does not refer to a reachable function","spans":[]}}'
unrelated='{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0425"},"message":"unrelated compile error","spans":[]}}'
ok_end='{"reason":"build-finished","success":true}'
bad_end='{"reason":"build-finished","success":false}'
proof() { # name, want (pass|fail), mode, clippy rc, json lines...
  local name=$1 want=$2 mode=$3 rc=$4 got
  shift 4
  printf '%s\n' "$@" > "$fake/out.json"
  if python3 -I "$checker" "$mode" "$fake/out.json" "$fake/plant.rs" src/p.rs "$rc" "$fake/stderr" > "$fake/log" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "check_registry_lint: FAIL: checker proof '$name' should $want but did $got" >&2
    cat "$fake/log" >&2
    exit 1
  fi
}
proof clean_dev pass dev 0 "$hit" "$ok_end"
proof clean_release pass release 0 "$hit" "$hit3" "$ok_end"
proof release_plant_missing fail release 0 "$hit" "$ok_end"
proof release_plant_in_dev fail dev 0 "$hit" "$hit3" "$ok_end"
proof read_elsewhere fail dev 0 "$hit" "$other" "$ok_end"
proof unresolved_entry fail dev 0 "$hit" "$loose" "$ok_end"
proof unrelated_error fail dev 0 "$hit" "$unrelated" "$ok_end"
proof failed_build fail dev 0 "$hit" "$bad_end"
proof no_build_completion fail dev 0 "$hit"
proof clippy_exit_nonzero fail dev 101 "$hit" "$ok_end"
echo "check_registry_lint: checker proven on 10 synthetic runs"

# A detached worktree, not a tar copy: `CARGO=spark-cargo` needs a git tree.
git -C "$root" worktree add --quiet --detach "$scratch" HEAD

plant=src/gateway/meta_mcp/registry_lint_plants.rs
cat > "$scratch/$plant" <<'RUST'
//! MIK-8387 registry-lint self-test plants. Never committed.
#![allow(dead_code, unused_imports, clippy::let_underscore_future)]

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;

/// One function-item reference per config entry: the lint names the path,
/// so no plant depends on a method's signature.
fn every_entry() {
    let _ = BackendRegistry::subscribe_started; // PLANT subscribe_started
    let _ = BackendRegistry::reload_read_slot; // PLANT reload_read_slot
    let _ = BackendRegistry::lock_reload; // PLANT lock_reload
    let _ = BackendRegistry::register; // PLANT register
    let _ = BackendRegistry::observe_breakers; // PLANT observe_breakers
    let _ = BackendRegistry::enforce_destinations; // PLANT enforce_destinations
    let _ = BackendRegistry::set_change_feed; // PLANT set_change_feed
    let _ = BackendRegistry::catalogue_hook; // PLANT catalogue_hook
    let _ = BackendRegistry::nudge_catalogue; // PLANT nudge_catalogue
    let _ = BackendRegistry::nudge_catalogue_scanned; // PLANT nudge_catalogue_scanned
    let _ = BackendRegistry::nudge_surfaced; // PLANT nudge_surfaced
    let _ = BackendRegistry::resolve_unwarmed; // PLANT resolve_unwarmed
    let _ = BackendRegistry::get; // PLANT get
    let _ = BackendRegistry::all; // PLANT all
    let _ = BackendRegistry::statuses; // PLANT statuses
    let _ = BackendRegistry::remove; // PLANT remove
    let _ = BackendRegistry::stop_all; // PLANT stop_all
    let _ = MetaMcp::resolve_propagation_credential; // PLANT propagation_credential
    let _ = MetaMcp::resolve_propagation_headers; // PLANT propagation_headers
}

macro_rules! raw_all {
    ($registry:expr) => {
        $registry.all() // PLANT macro_body
    };
}

macro_rules! raw_release {
    ($registry:expr) => {
        $registry.statuses() // RELEASE macro_release
    };
}

fn shapes(registry: &BackendRegistry) {
    let _ = registry.with_membership(|epoch| epoch); // PLANT with_membership
    let _ = registry.get("x"); // PLANT method_call
    let _ = BackendRegistry::get(registry, "x"); // PLANT fully_qualified
    {
        use crate::backend::BackendRegistry as Alias;
        let _ = Alias::all(registry); // PLANT alias
    }
    let _ = raw_all!(registry);
    #[allow(clippy::disallowed_methods, reason = "Lifecycle: a plant")]
    let _ = registry.get("y"); // ALLOWED leaf_allow
    #[cfg(not(debug_assertions))]
    let _ = registry.get("z"); // RELEASE release_statement
    #[cfg(not(debug_assertions))]
    let _ = raw_release!(registry);
}

#[cfg(any(not(debug_assertions), target_os = "redox"))]
fn release_compound(registry: &BackendRegistry) {
    let _ = registry.all(); // RELEASE release_compound
}

// Documents scope, cannot go red: no pass compiles cfg(test). The ban's reach
// is the passes' target selection (`--lib --bins`), not this config.
#[cfg(test)]
mod tests {
    fn reads(registry: &crate::backend::BackendRegistry) {
        let _ = registry.all(); // TESTONLY test_module
    }
}
RUST
printf '\n#[cfg(not(test))]\nmod registry_lint_plants;\n' >> "$scratch/src/gateway/meta_mcp/mod.rs"

# A config entry with no plant could resolve and still never bite: every
# banned name needs a PLANT line that references or calls it.
entries=$(sed -n 's/.*path = "[^"]*::\([A-Za-z_0-9]*\)".*/\1/p' "$scratch/scripts/lint/registry-ban/clippy.toml")
[[ -n "$entries" ]] || { echo "check_registry_lint: no config entries read" >&2; exit 1; }
for name in $entries; do
  grep -Eq "(::|\.)${name}[^A-Za-z_0-9].*// PLANT " "$scratch/$plant" \
    || { echo "check_registry_lint: config entry $name has no plant" >&2; exit 1; }
done

# `-D warnings` as CI does, `--cap-lints warn` so the plants stay warnings.
run_pass() { # mode, extra cargo args (features included)...
  local mode=$1 out="$scratch/clippy-$1.json" rc=0
  shift
  (
    cd "$scratch"
    CLIPPY_CONF_DIR="$scratch/scripts/lint/registry-ban" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}" \
      ${CARGO:-cargo} clippy --lib "$@" --message-format=json -- \
      -D warnings -W clippy::disallowed_methods --cap-lints warn
  ) > "$out" 2> "$scratch/clippy-$mode.stderr" || rc=$?
  python3 -I "$checker" "$mode" "$out" "$scratch/$plant" "$plant" "$rc" "$scratch/clippy-$mode.stderr"
}

if [ "$action" = "--cache-probe" ]; then
  # The same lint flags as run_pass: clippy re-lints on a flag change, which
  # would make the probe pass for the wrong reason.
  (
    cd "$scratch"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}" \
      ${CARGO:-cargo} clippy --lib --all-features --quiet -- \
      -D warnings -W clippy::disallowed_methods --cap-lints warn
  ) > "$tmp/warm.log" 2>&1 || { cat "$tmp/warm.log" >&2; echo "check_registry_lint: warm-up pass failed" >&2; exit 1; }
  run_pass dev --all-features
  echo "check_registry_lint: cache probe ok: a CLIPPY_CONF_DIR change re-lints a warm cache"
  exit 0
fi
run_pass dev --all-features
# The release pass takes every feature but the test-only ones, which refuse
# to build without debug_assertions, as CI's release clippy does. Its own
# line, so a failing script stops here instead of linting with no features.
feats=$(python3 "$root/scripts/ci/release_features.py")
run_pass release --release --features "$feats"
