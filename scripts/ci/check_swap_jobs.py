#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every Linux-hosted job that compiles the library's test binary adds swap first.

That compile is one rustc of about 15.4 GB on a runner with 16 GB of RAM and
3 GB of swap: measured, it leaves a few hundred MB free and fills the swap,
and a run that tips over loses its runner (exit 143, "shutdown signal"). The
shared action `.github/actions/add-swap` adds 8 GB and fails unless total swap
reaches 10 GB.

This check reads every workflow and refuses:
  - a Linux-hosted job that runs a library-test build with no add-swap step
    before its first such step;
  - an add-swap step whose `if:` is not one of ALLOWED_CONDITIONS (a condition
    that skips a library matrix row would leave that row without swap);
  - a hand-copied swap script (`swapon`/`mkswap` in a workflow `run:`), which
    could drift from the shared action;
  - an in-scope job list that differs from EXPECTED (a job that starts or stops
    building the library must be named here on purpose).

`--self-test` runs the classifier on fixtures. Standard library plus PyYAML,
as the other workflow checks.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ACTION = "./.github/actions/add-swap"
WORKFLOWS = Path(".github/workflows")

# A library-test build: `cargo test` or `cargo llvm-cov` that is not a
# single-target, doc-only or binary-only run, and the repo's wrapper scripts
# around one.
CARGO_RE = re.compile(r"\bcargo\s+(test|llvm-cov)\b([^\n|;&]*)")
SINGLE_TARGET = re.compile(r"--(test|bin|doc|example|bench)\b")
LLVM_COV_NO_COMPILE = re.compile(r"^\s*(clean|report)\b")
WRAPPERS = (
    re.compile(r"scripts/ci/shard_tests\.py\s+run\s+linux\b"),
    re.compile(r"scripts/ci/coverage_shards\.py\s+run\b"),
    re.compile(r"scripts/ci/packaged-tests\.sh\s+(build|run)\b"),
    # The mutant harness, run from the repo or from the copy mutants.yml takes
    # off the release line into $RUNNER_TEMP.
    re.compile(r"run_mutants\.py\"?\s+run\b"),
)
COPIED_SWAP = re.compile(r"\b(swapon|mkswap)\b")

# The add-swap step may be conditional only in these ways: the coverage parts
# run it on every library part and on no integration part.
ALLOWED_CONDITIONS = {
    "startsWith(matrix.part, 'lib-')",
    # A step shared with a self-hosted twin job (mutants.yml keeps its hosted
    # and trusted Linux jobs identical): it runs on every hosted run.
    "runner.environment == 'github-hosted'",
}

# Jobs that go through a wrapper above but compile no library test binary,
# with the measurement that puts them out of scope.
EXEMPT = {
    ("coverage-probe.yml", "linux-sdk"): "builds one integration test; measured peak 6.5 GB",
}

# The jobs in scope, by workflow file and job id. A change to this set is a
# change to which jobs carry the library compile, reviewed as such.
EXPECTED = {
    ("ci.yml", "gws-dry-run"),
    ("ci.yml", "linux-keychain"),
    ("ci.yml", "package-tests"),
    ("ci.yml", "test-shards"),
    ("ci.yml", "test-throwaway-hosted"),
    ("coverage-probe.yml", "linux-part"),
    ("feature-combos.yml", "release-test-compile"),
    ("mutants.yml", "linux-hosted"),
    ("packaged-suite.yml", "packaged-suite"),
    ("release.yml", "verify"),
}


def builds_library(run: str) -> bool:
    """Whether a `run:` script compiles the library's test binary."""
    for m in CARGO_RE.finditer(run):
        sub, args = m.group(1), m.group(2)
        if sub == "llvm-cov" and LLVM_COV_NO_COMPILE.match(args):
            continue
        if SINGLE_TARGET.search(args):
            continue
        return True
    return any(w.search(run) for w in WRAPPERS)


def linux_hosted(job: dict) -> bool:
    runs_on = job.get("runs-on", "")
    return "ubuntu" in (" ".join(runs_on) if isinstance(runs_on, list) else str(runs_on))


def check_job(name: str, job: dict) -> tuple[bool, list[str]]:
    """(in scope, problems) for one job."""
    problems: list[str] = []
    steps = job.get("steps") or []
    for i, step in enumerate(steps):
        if COPIED_SWAP.search(str(step.get("run", ""))):
            problems.append(f"{name}: step {i} copies a swap script; use {ACTION}")
    if not linux_hosted(job):
        return False, problems
    first_build = next((i for i, s in enumerate(steps) if builds_library(str(s.get("run", "")))), None)
    if first_build is None:
        return False, problems
    swap = next((i for i, s in enumerate(steps) if s.get("uses") == ACTION), None)
    if swap is None:
        problems.append(f"{name}: builds the library tests (step {first_build}) with no {ACTION} step")
    elif swap > first_build:
        problems.append(f"{name}: {ACTION} (step {swap}) comes after the library build (step {first_build})")
    else:
        cond = steps[swap].get("if")
        if cond is not None and str(cond).strip() not in ALLOWED_CONDITIONS:
            problems.append(f"{name}: {ACTION} runs only if `{cond}`, which may skip a library row")
    return True, problems


def check_workflow(file: str, doc: dict) -> tuple[set[tuple[str, str]], list[str]]:
    scope: set[tuple[str, str]] = set()
    problems: list[str] = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if (file, name) in EXEMPT:
            continue
        in_scope, found = check_job(f"{file}:{name}", job)
        problems += found
        if in_scope:
            scope.add((file, name))
    return scope, problems


def main() -> int:
    scope: set[tuple[str, str]] = set()
    problems: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        s, p = check_workflow(path.name, yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        scope |= s
        problems += p
    for missing in sorted(EXPECTED - scope):
        problems.append(f"{missing[0]}:{missing[1]} is listed in EXPECTED but builds no library tests")
    for extra in sorted(scope - EXPECTED):
        problems.append(f"{extra[0]}:{extra[1]} builds the library tests but is not in EXPECTED")
    for p in problems:
        print(f"::error::{p}")
    print(f"{len(scope)} jobs build the library tests; {len(problems)} problems")
    return 1 if problems else 0


def action_script() -> str:
    """The run block of the add-swap action's only step."""
    doc = yaml.safe_load(Path(".github/actions/add-swap/action.yml").read_text())
    return doc["runs"]["steps"][0]["run"]


def run_action(before_mb: int, after_mb: int) -> int:
    """Exit status of the action's script on a runner whose total swap is before_mb until swapon, then after_mb.
    sudo, fallocate, chmod, mkswap and swapon are stubs; `free` answers from a counter: its first call (before the
    swap file is made) reports before_mb, later calls after_mb."""
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp)
        for name in ("fallocate", "chmod", "mkswap", "swapon"):
            (fake / name).write_text("#!/bin/sh\nexit 0\n")
        (fake / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
        (fake / "free").write_text(
            "#!/bin/sh\n"
            f'n=$(cat "{tmp}/calls" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "{tmp}/calls"\n'
            f'if [ "$n" -eq 1 ]; then m={before_mb}; else m={after_mb}; fi\n'
            'echo "              total        used        free"; echo "Mem:          15983         891       14431"\n'
            'echo "Swap:         $m           0       $m"\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"}
        return subprocess.run(["bash", "-c", action_script()], env=env, capture_output=True, text=True).returncode


def self_test() -> int:
    def job(*steps: dict, runs_on: str = "ubuntu-latest") -> dict:
        return {"runs-on": runs_on, "steps": list(steps)}

    swap = {"uses": ACTION}
    cases = [
        ("a library test build with no swap step", job({"run": "cargo test --all-features --lib --no-run"}), True, 1),
        ("swap after the build", job({"run": "cargo test --all-features"}, swap), True, 1),
        ("swap before the build", job(swap, {"run": "cargo test --all-features"}), True, 0),
        ("a copied swap script", job({"run": "sudo swapon /swapfile"}, {"run": "cargo test"}), True, 2),
        ("a single integration target is out of scope", job({"run": "cargo test --test public_claims_validation"}), False, 0),
        ("a binary build is out of scope", job({"run": "cargo build --locked --bin mcp-gateway"}), False, 0),
        ("llvm-cov clean and report do not compile", job({"run": "cargo llvm-cov clean --workspace\ncargo llvm-cov report -v"}), False, 0),
        ("the Linux shard wrapper builds the library", job({"run": "python3 scripts/ci/shard_tests.py run linux lib-a"}), True, 1),
        ("packaged-tests.sh build", job({"run": "scripts/ci/packaged-tests.sh build"}), True, 1),
        ("packaged-tests.sh run", job({"run": "scripts/ci/packaged-tests.sh run"}), True, 1),
        ("the mutant harness copied to the runner temp", job({"run": 'python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o'}), True, 1),
        ("the mutant harness plan step does not compile", job({"run": 'python3 "$RUNNER_TEMP/run_mutants.py" plan'}), False, 0),
        ("the repo's mutant runner path", job({"run": "python3 scripts/ci/mutants/run_mutants.py run --platform linux"}), True, 1),
        ("coverage parts gated to every lib part", job({**swap, "if": "startsWith(matrix.part, 'lib-')"}, {"run": "python3 scripts/ci/coverage_shards.py run 4 \"$PART\""}), True, 0),
        ("hosted-only swap shared with a self-hosted twin", job({**swap, "if": "runner.environment == 'github-hosted'"}, {"run": "cargo test --all-features"}), True, 0),
        ("coverage parts gated to one lib part", job({**swap, "if": "matrix.part == 'lib-a'"}, {"run": "python3 scripts/ci/coverage_shards.py run 4 \"$PART\""}), True, 1),
        ("macOS is out of scope", job({"run": "cargo test --all-features"}, runs_on="macos-15"), False, 0),
    ]
    wrong = 0
    # The action must prove that OUR swap file took, whatever swap the runner image brings: runners differ (3 GB already
    # there, 11263 MB total; or none, 8191 MB total, which the old absolute 10 GB floor failed on 2026-11-12).
    for label, before, after, want_rc in (
        ("a runner with 3 GB of swap already there: 3072 -> 11263", 3072, 11263, 0),
        ("a runner with no swap: 0 -> 8191 (the file took)", 0, 8191, 0),
        ("swapon did nothing on a runner with 3 GB: 3072 -> 3072", 3072, 3072, 1),
        ("swapon did nothing on a runner with none: 0 -> 0", 0, 0, 1),
        ("only part of the file took: 0 -> 4096", 0, 4096, 1),
        ("just under the file's size: 0 -> 7999", 0, 7999, 1),
    ):
        rc = run_action(before, after)
        ok = (rc == 0) == (want_rc == 0)
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} add-swap action, {label}: exit {rc}")
    for label, j, want_scope, want_problems in cases:
        in_scope, problems = check_job("fixture", j)
        ok = in_scope == want_scope and len(problems) == want_problems
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: in scope {in_scope}, problems {problems}")
    print(f"self-test: {len(cases) + 6 - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
