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
import tomllib
from pathlib import Path

import yaml

ACTION = "./.github/actions/add-swap"
WORKFLOWS = Path(".github/workflows")
CARGO_CONFIG = Path(".cargo/config.toml")

# A library-test build: `cargo test`, `cargo llvm-cov` or `cargo bench` (the
# library's own bench harness compiles it with cfg(test)) that is not a
# single-target, doc-only or binary-only run; `cargo build` with `--tests`,
# `--all-targets` or `--benches`; and the repo's wrapper scripts around one.
# `cargo check` and `cargo clippy` stay out: check-only, they peak under the
# memory tripwire's limit, so they are not the build the lib test split removes.
CARGO_RE = re.compile(r"\bcargo\s+(test|llvm-cov|bench)\b([^\n|;&]*)")
BUILD_TESTS = re.compile(r"\bcargo\s+build\b[^\n|;&]*\s--(tests|all-targets|benches)\b")
SINGLE_TARGET = re.compile(r"--(test|bin|doc|example|bench)\b")
LLVM_COV_NO_COMPILE = re.compile(r"^\s*(clean|report)\b")
WRAPPERS = (
    re.compile(r"scripts/ci/shard_tests\.py\s+run\s+linux\b"),
    # The shared lib test binary: `export-lib` compiles it once for the run.
    re.compile(r"scripts/ci/shard_tests\.py\s+export-lib\b"),
    # The Linux lib test binary in parts: the helper compiles each part through export-lib.
    re.compile(r"scripts/ci/lib-parts\.sh\s+export\b"),
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
    ("feature-combos.yml", "release-test-compile"): "cargo check only, no test binary; measured peak 12.96 GB",
}

# The jobs in scope, by workflow file and job id. A change to this set is a
# change to which jobs carry the library compile, reviewed as such.
EXPECTED = {
    ("ci.yml", "linux-lib-build"),
    ("ci.yml", "package-tests"),
    ("ci.yml", "test-shards"),
    ("ci.yml", "test-throwaway-hosted"),
    ("coverage-probe.yml", "linux-part"),
    ("mutants.yml", "linux-hosted"),
    ("packaged-suite.yml", "packaged-suite"),
    ("release.yml", "verify"),
}

# The lib test split (SPLIT.6): every in-scope job builds the library tests through scripts/ci/lib-parts.sh, so each
# compile is one part, never the whole binary, or it is listed here with why. Shrink-only: the jobs PR's second half
# converts the first four rows' jobs and deletes their rows; the stage B jobs keep the whole build until then.
HELPER = "scripts/ci/lib-parts.sh"
WHOLE_BUILD_ALLOWED = {
    ("packaged-suite.yml", "packaged-suite"): "converted by the jobs PR's second half (post-merge packaged suite)",
    ("release.yml", "verify"): "converted by the jobs PR's second half (release verify)",
    ("coverage-probe.yml", "linux-part"): "converted by the jobs PR's second half (llvm-cov Linux lib parts)",
    ("ci.yml", "test-throwaway-hosted"): "stage B: the throwaway full-test job",
    ("mutants.yml", "linux-hosted"): "stage B: mutant batches",
    ("ci.yml", "test-shards"): "builds the integration targets only (int-a, int-b): no lib test target",
}


# The packaged crate's build builds by part inside the unpacked crate, where the helper is not shipped: it counts as
# through the helper while its script's build mode holds that shape (packaged_build_problems).
PACKAGED_BUILD = "scripts/ci/packaged-tests.sh build"
PACKAGED_SCRIPT = Path("scripts/ci/packaged-tests.sh")
PART_CALL = re.compile(r"""MCP_GATEWAY_TEST_PART="\$k"\s+cargo\s+test\b.*\s--lib\b""")
REST_CALL = re.compile(r"""cargo\s+test\b.*\s--test\s+'\*'""")
SELECTS_LIB = re.compile(r"\s--(lib|tests|all-targets|benches)\b")


def packaged_build_problems(text: str) -> list[str]:
    """Why the packaged crate's `build` mode does not build the lib tests one part at a time, or nothing: every
    `cargo test` there is either one part (`--lib` with MCP_GATEWAY_TEST_PART set) or the other targets only
    (`--test '*'`, no `--lib`/`--tests`/`--all-targets`/`--benches`), and there is one of each."""
    start = text.find('elif [ "$mode" = build ]')
    if start < 0:
        return ["packaged-tests.sh has no build mode"]
    block = text[start:].split("\nelse", 1)[0]
    calls = [line.strip() for line in block.splitlines() if re.search(r"\bcargo\s+test\b", line)]
    out = [f"`{c}` is neither one part nor the other targets" for c in calls
           if not PART_CALL.search(c) and not (REST_CALL.search(c) and not SELECTS_LIB.search(c))]
    if not any(PART_CALL.search(c) for c in calls):
        out.append("the build mode builds no part")
    if not any(REST_CALL.search(c) and not SELECTS_LIB.search(c) for c in calls):
        out.append("the build mode builds no non-lib test target")
    return out


def census(jobs_in_scope: dict, packaged_by_part: bool) -> list[str]:
    """SPLIT.6: an in-scope job outside WHOLE_BUILD_ALLOWED builds through the helper (or is the packaged build while
    `packaged_by_part`); every allowance names a job still in scope that still does not."""
    problems = []
    marks = (HELPER, PACKAGED_BUILD) if packaged_by_part else (HELPER,)
    through = {key for key, job in jobs_in_scope.items()
               if any(m in str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict)
                      for m in marks)}
    for key in sorted(set(jobs_in_scope) - through - set(WHOLE_BUILD_ALLOWED)):
        problems.append(f"{key[0]}:{key[1]} builds the library tests without {HELPER}, so the whole lib test binary")
    for key in sorted(set(WHOLE_BUILD_ALLOWED) - (set(jobs_in_scope) - through)):
        problems.append(f"{key[0]}:{key[1]} is allowed a whole build but no longer has one; delete its row")
    return problems


def alias_text(table: dict) -> dict[str, str]:
    """A cargo `[alias]` table as name -> expansion text (cargo takes a string or a list of words)."""
    return {name: value if isinstance(value, str) else " ".join(value) for name, value in table.items()}


def repo_aliases() -> dict[str, str]:
    """The repo's own cargo aliases, from `[alias]` in .cargo/config.toml."""
    if not CARGO_CONFIG.is_file():
        return {}
    return alias_text(tomllib.loads(CARGO_CONFIG.read_text(encoding="utf-8")).get("alias", {}))


def builds_library(run: str, aliases: dict[str, str] | None = None) -> bool:
    """Whether a `run:` script compiles the library's test binary. A repo alias is read as what it expands to."""
    for name, expansion in (repo_aliases() if aliases is None else aliases).items():
        run = re.sub(rf"\bcargo\s+{re.escape(name)}\b", lambda _, e=expansion: f"cargo {e}", run)
    if BUILD_TESTS.search(run):
        return True
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


# Every library build line in scope runs through the memory log, and every such step carries its own
# timeout-minutes, so a stalled build ends while the runner is alive and the step keeps its log (a job cancelled at
# its own limit keeps none). Limits come from measured healthy durations; a step with no measurement yet logs
# only, named here per step. Its limit must not be set until it is measured.
MEMLOG = "scripts/ci/with-memory-log.sh"
LOG_ONLY = {
    # A healthy lib-b run took 52 min on 2026-11-13: no limit until the shard suite's tail is measured.
    ("ci.yml", "test-shards", "Shard suite"),
    ("ci.yml", "test-throwaway-hosted", "Run the tests"),
    ("packaged-suite.yml", "packaged-suite", "Run the tests from the packaged crate"),
    ("mutants.yml", "linux-hosted", "Run the linux rows"),
    ("release.yml", "verify", "Test"),
}
# Minutes kept free of step limits in each job: setup, cache, swap and post steps measured at 3 min or less.
RESERVE = 10
JOB_DEFAULT = 360  # GitHub's job limit when timeout-minutes is unset


def whole_step_wrapped(run: str) -> bool:
    """Whether the step is ONE command run through the memory log, its script in a single-quoted `bash -c` body that
    ends the step (the keychain steps: `with-memory-log.sh dbus-run-session -- bash -euo pipefail -c '...'`). Then
    every build line inside it is wrapped. Anything after the closing quote, or a second quote inside, is not."""
    text = run.strip()
    if not text.startswith(MEMLOG + " ") or not text.endswith("'"):
        return False
    first = text.find("'")
    return first < len(text) - 1 and "'" not in text[first + 1:-1]


# What may stand between the start of a command and the build it runs, for the build to count as wrapped: an
# optional loop/branch keyword, the wrapper as the command's first word, an optional interpreter, and the start of
# the build's own word when the match begins inside it (`"$RUNNER_TEMP/run_mutants.py`). No `(` or backtick.
WRAPPED_PREFIX = re.compile(
    r"\s*(?:(?:do|then|else)\s+)?(?:\./)?" + re.escape(MEMLOG) + r"\s+(?:(?:python3?|bash|sh)\s+)?[\w$./{}\"'-]*")
# Characters that end one command and start another (or a substitution's): a build's command starts after the
# last of them.
COMMAND_BREAKS = "\n;&|(`"


def unwrapped_builds(run: str) -> list[str]:
    """Every library build in `run` that does not run through the wrapper. Fail closed, not a shell parser: after
    joining backslash continuations and dropping comment lines, each occurrence of a build (CARGO_RE, WRAPPERS) is
    wrapped only when the text from the start of its command (after the last newline, `;`, `&`, `|`, `(` or
    backtick) to the build is exactly WRAPPED_PREFIX. Anything else counts as bare: a build on the line after a
    mention of the wrapper, after `VAR=`, inside `$( )` or backticks, or in an echo's text (so a phase line must
    not spell out `cargo test`)."""
    text = "\n".join(l for l in run.replace("\\\n", " ").split("\n") if not l.lstrip().startswith("#"))
    starts = []
    for m in CARGO_RE.finditer(text):
        if m.group(1) == "llvm-cov" and LLVM_COV_NO_COMPILE.match(m.group(2)):
            continue
        if not SINGLE_TARGET.search(m.group(2)):
            starts.append(m.start())
    starts += [m.start() for w in WRAPPERS for m in w.finditer(text)]
    bare = []
    for s in sorted(starts):
        command_start = max(text.rfind(c, 0, s) for c in COMMAND_BREAKS) + 1
        if not WRAPPED_PREFIX.fullmatch(text[command_start:s]):
            bare.append(text[s:s + 80].split("\n")[0])
    return bare


def memlog_problems(file: str, name: str, job: dict) -> list[str]:
    """Problems with the memory log and the step limits of one in-scope job."""
    problems: list[str] = []
    limit_total = 0
    for i, step in enumerate(job.get("steps") or []):
        label = step.get("name", f"step {i}")
        limit = step.get("timeout-minutes")
        # Every step's own limit counts against the job's, build or not: they all run before the job limit.
        if isinstance(limit, int):
            limit_total += limit
        run = str(step.get("run", ""))
        if not builds_library("\n".join(l for l in run.split("\n") if not l.lstrip().startswith("#"))):
            continue
        bare = [] if whole_step_wrapped(run) else unwrapped_builds(run)
        if bare:
            problems.append(f"{file}:{name}: '{label}' builds the library without {MEMLOG}: {bare[0][:80]}")
        if (file, name, label) in LOG_ONLY:
            if limit is not None:
                problems.append(f"{file}:{name}: '{label}' is log-only (not measured yet) but sets timeout-minutes")
        elif not isinstance(limit, int):
            problems.append(f"{file}:{name}: '{label}' builds the library with no timeout-minutes of its own")
    job_limit = job.get("timeout-minutes", JOB_DEFAULT)
    if not isinstance(job_limit, int):
        problems.append(f"{file}:{name}: job timeout-minutes is not a number")
    elif limit_total + RESERVE >= job_limit:
        problems.append(f"{file}:{name}: step limits {limit_total} + {RESERVE} reserve must stay under the job's {job_limit}")
    return problems


def check_workflow(file: str, doc: dict, seen: dict | None = None) -> tuple[set[tuple[str, str]], list[str]]:
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
            if seen is not None:
                seen[(file, name)] = job
            problems += memlog_problems(file, name, job)
    return scope, problems


def main() -> int:
    scope: set[tuple[str, str]] = set()
    problems: list[str] = []
    seen: dict = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        s, p = check_workflow(path.name, yaml.safe_load(path.read_text(encoding="utf-8")) or {}, seen)
        scope |= s
        problems += p
    problems += census(seen, packaged_by_part=not packaged_build_problems(PACKAGED_SCRIPT.read_text(encoding="utf-8")))
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
        ("cargo bench compiles the library's own bench harness", job({"run": "cargo bench --all-features --no-run"}), True, 1),
        ("a named bench target never selects the library", job({"run": "cargo bench --bench token_savings --no-run"}), False, 0),
        ("cargo build --tests compiles the library tests", job({"run": "cargo build --all-features --tests"}), True, 1),
        ("cargo build --benches selects the library's bench harness", job({"run": "cargo build --benches"}), True, 1),
        ("a check-only build is out of scope", job({"run": "cargo check --all-targets"}), False, 0),
    ]
    # The repo's own cargo aliases expand before the match.
    alias_cases = [
        ("an alias for cargo test --lib", {"wl": "test --lib"}, "cargo wl --no-run", True),
        ("a list-form alias", {"wl": ["test", "--lib"]}, "cargo wl", True),
        ("an alias for a release build", {"rel": "build --release"}, "cargo rel", False),
    ]
    wrong = 0
    for label, table, run, want in alias_cases:
        got = builds_library(run, alias_text(table))
        wrong += got != want
        print(f"{'ok   ' if got == want else 'WRONG'} alias, {label}: library build {got}")
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
    for label, file, name, j, want_bad in memlog_cases():
        problems = memlog_problems(file, name, j)
        ok = bool(problems) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} memory log, {label}: problems {problems}")
    helper_job = {"steps": [{"run": "scripts/ci/with-memory-log.sh scripts/ci/lib-parts.sh export 1 out"}]}
    whole_job = {"steps": [{"run": "cargo test --all-features --lib --no-run"}]}
    packaged_job = {"steps": [{"run": "scripts/ci/with-memory-log.sh scripts/ci/packaged-tests.sh build"}]}
    allowed = {key: {"steps": []} for key in WHOLE_BUILD_ALLOWED}
    census_cases = [
        ("a new job building the whole binary", {**allowed, ("ci.yml", "new"): whole_job}, True, True),
        ("a new job building through the helper", {**allowed, ("ci.yml", "new"): helper_job}, False, True),
        ("a new job calling export-lib itself, without the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": "python3 scripts/ci/shard_tests.py export-lib out"}]}}, True, True),
        ("an allowed job converted but still listed",
         {**allowed, ("packaged-suite.yml", "packaged-suite"): helper_job}, True, True),
        ("the allowance as it stands", allowed, False, True),
        ("the packaged-crate build, its script building by part",
         {**allowed, ("ci.yml", "package-tests"): packaged_job}, False, True),
        ("the packaged-crate build, its script building the whole binary",
         {**allowed, ("ci.yml", "package-tests"): packaged_job}, True, False),
    ]
    for label, jobs, want_bad, by_part in census_cases:
        found = census(jobs, packaged_by_part=by_part)
        ok = bool(found) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} census, {label}: problems {found}")
    part = 'MCP_GATEWAY_TEST_PART="$k" cargo test --all-features --locked --lib --no-run'
    rest = "cargo test --all-features --locked --no-run --test '*' --bins --examples"
    shape = 'elif [ "$mode" = build ]; then\n  for k in 1 2; do\n    {}\n  done\n  {}\nelse\n  cargo test --all-features\nfi\n'
    packaged_cases = [
        ("by part, then the other targets", shape.format(part, rest), False),
        ("today's whole build", 'elif [ "$mode" = build ]; then\n  cargo test --all-features --locked --no-run\nelse\nfi\n', True),
        ("--tests selects the lib again", shape.format(part, rest.replace("--test '*'", "--tests")), True),
        ("a part without its variable", shape.format(part.replace('MCP_GATEWAY_TEST_PART="$k" ', ""), rest), True),
        ("parts only, the other targets never built", shape.format(part, "true"), True),
    ]
    for label, text, want_bad in packaged_cases:
        found = packaged_build_problems(text)
        ok = bool(found) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} packaged build, {label}: problems {found}")
    print(f"self-test: {len(cases) + len(alias_cases) + 6 + len(memlog_cases()) + len(census_cases) + len(packaged_cases) - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


def memlog_cases() -> list[tuple[str, str, str, dict, bool]]:
    """(label, workflow, job id, job, problems expected) for memlog_problems, from the real step shapes."""
    w = MEMLOG + " "

    def job(*steps: dict, limit: int | None = 60) -> dict:
        return {"runs-on": "ubuntu-latest", "steps": list(steps), **({"timeout-minutes": limit} if limit else {})}

    def step(run: str, limit: int | None = 20, name: str = "Build") -> dict:
        return {"name": name, "run": run, **({"timeout-minutes": limit} if limit else {})}

    feature = ("cargo test --all-targets --no-run --config profile.dev.debug-assertions=false \\\n"
               "  --config profile.test.debug-assertions=false")
    loop = ('for target in "--test a" "--lib b"; do\n  echo "phase compile"\n  cargo test --all-features $target --no-run\n'
            '  echo "phase run"\n  cargo test --all-features $target 2>&1 | tee "$RUNNER_TEMP/a.log"\ndone')
    dbus = ("dbus-run-session -- bash -euo pipefail -c '\n  printf \"ci\" | gnome-keyring-daemon --unlock > /dev/null\n"
            "  cargo test --all-features --lib -- --ignored --exact a15 2>&1 | tee \"$RUNNER_TEMP/a15.log\"\n'")
    cov = 'set -o pipefail\ncargo llvm-cov clean --workspace\npython3 scripts/ci/coverage_shards.py run "$P" "$PART" 2>&1 | tee run.log'
    return [
        ("C1 a bare library build", "ci.yml", "j", job(step("cargo test --all-features --lib --no-run")), True),
        ("C2 a wrapped build with a limit", "ci.yml", "j", job(step(w + "cargo test --all-features --lib --no-run")), False),
        ("C3 the wrapper only in a comment above", "ci.yml", "j",
         job(step(f"# {w}cargo test\ncargo test --all-features --lib --no-run")), True),
        ("C3b the wrapper only in a trailing comment", "ci.yml", "j",
         job(step(f"cargo test --all-features --lib --no-run # {w}")), True),
        ("C4 limits + reserve under the job limit", "ci.yml", "j",
         job(step(w + "cargo test --lib", 25), step(w + "cargo test --lib", 5), step(w + "cargo test --lib", 5), limit=50), False),
        ("C4b limits + reserve equal to the job limit", "ci.yml", "j",
         job(step(w + "cargo test --lib", 25), step(w + "cargo test --lib", 5), step(w + "cargo test --lib", 5), limit=45), True),
        ("C5 no job limit counts as 360", "ci.yml", "j", job(step(w + "cargo test --lib", 340), limit=None), False),
        ("C5b no job limit, steps past 360", "ci.yml", "j", job(step(w + "cargo test --lib", 351), limit=None), True),
        ("C6 a build step with no limit of its own", "ci.yml", "j", job(step(w + "cargo test --lib", None)), True),
        ("C7 a log-only step with no limit", "ci.yml", "test-shards",
         job(step(w + "python3 scripts/ci/shard_tests.py run linux lib-a", None, "Shard suite")), False),
        ("C7b a log-only step that sets a limit", "ci.yml", "test-shards",
         job(step(w + "python3 scripts/ci/shard_tests.py run linux lib-a", 30, "Shard suite")), True),
        ("C8 two build lines, one wrapped", "ci.yml", "j", job(step(w + "cargo test --lib --no-run\ncargo test --lib")), True),
        ("C12 an echo spelling out cargo test counts as a bare build (fail closed)", "ci.yml", "j",
         job(step(f'echo "phase compile: cargo test --lib --no-run at $(date -u +%T)"\n{w}cargo test --all-features --lib --no-run')), True),
        ("C12 the real phase line: names no build, its substitutions run ps, wc and free", "ci.yml", "j",
         job(step('echo "phase compile: the lib test binary at $(date -u +%T), n: $(ps -u "$(id -u)" -o pid= | wc -l), '
                  "m: $(free -m | awk '/^Mem:/ {print $3}')\"\n" + w + "cargo test --all-features --lib --no-run")), False),
        ("C13 a wrapped first command, then a bare build after &&", "ci.yml", "j", job(step(w + "true && cargo test --all-features --lib")), True),
        ("C13 a bare build after ;", "ci.yml", "j", job(step(w + "cargo test --lib --no-run; cargo test --lib")), True),
        ("C13 echo, then a bare build after &&", "ci.yml", "j", job(step("echo start && cargo test --all-features --lib")), True),
        ("C13 an echo whose substitution builds", "ci.yml", "j", job(step('echo "$(cargo test --all-features --lib)"')), True),
        ("C13 a wrapped build piped to tee", "ci.yml", "j", job(step(w + 'cargo test --all-features --lib 2>&1 | tee "$RUNNER_TEMP/x.log"')), False),
        ("C15 a backtick build in an echo", "ci.yml", "j", job(step("echo `cargo test --all-features --lib`")), True),
        ("C15 a build backgrounded after &", "ci.yml", "j", job(step("echo start & cargo test --all-features --lib")), True),
        ("C15 a build in a substitution passed to the wrapper", "ci.yml", "j", job(step(w + 'true "$(cargo test --all-features --lib)"')), True),
        ("C15 a one-line loop running the wrapper", "ci.yml", "j",
         job(step(f"for t in a b; do {w}cargo test --all-features --lib $t; done")), False),
        ("C15 the wrapper on a continued line", "ci.yml", "j", job(step(w + "\\\n  cargo test --all-features --lib --no-run")), False),
        ("C15 the mutant harness through the wrapper", "m.yml", "j",
         job(step(w + 'python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o')), False),
        ("C16 a comment naming cargo test is not a build", "ci.yml", "j",
         job(step(f"# cargo test --all-features --lib runs below\n{w}cargo test --all-features --lib --no-run")), False),
        ("C16 a bare single-target run beside a wrapped library build", "ci.yml", "j",
         job(step(f"{w}cargo test --all-features --lib --no-run\ncargo test --all-features --test one_target")), False),
        ("C17 the wrapper named on the line before a bare build", "ci.yml", "j",
         job(step(f"ls -l {MEMLOG}\ncargo test --all-features --lib")), True),
        ("C17 the wrapper as an assignment's value", "ci.yml", "j", job(step(f"VAR={MEMLOG} cargo test --all-features --lib")), True),
        ("C17 a substitution glued to the wrapper's argument", "ci.yml", "j", job(step(w + '"$(cargo test --all-features --lib)"')), True),
        ("C17 the wrapper after && before a bare build", "ci.yml", "j", job(step(f"test -x {MEMLOG} && cargo test --all-features --lib")), True),
        ("C18 a wrapped build inside a subshell", "ci.yml", "j", job(step(f"({w}cargo test --all-features --lib)")), False),
        ("C18 a wrapped build after a backgrounded command", "ci.yml", "j", job(step(f"sleep 1 & {w}cargo test --all-features --lib")), False),
        ("C18 a wrapped build after &&", "ci.yml", "j", job(step(f"true && {w}cargo test --all-features --lib")), False),
        ("C14 a non-build step's limit counts against the job", "ci.yml", "j",
         job({"name": "Setup", "run": "true", "timeout-minutes": 30}, step(w + "cargo test --lib", 25), limit=60), True),
        ("C11 feature-combos continuation, wrapped", "f.yml", "j", job(step(w + feature)), False),
        ("C11 feature-combos continuation, bare", "f.yml", "j", job(step(feature)), True),
        ("C11 UPGRADING loop, both cargo lines wrapped", "ci.yml", "j",
         job(step(loop.replace("  cargo test", "  " + w + "cargo test"))), False),
        ("C11 UPGRADING loop, the run line bare", "ci.yml", "j",
         job(step(loop.replace("  cargo test --all-features $target --no-run", f"  {w}cargo test --all-features $target --no-run"))), True),
        ("C11 keychain dbus script, inner cargo wrapped", "ci.yml", "j", job(step(dbus.replace("  cargo test", "  " + w + "cargo test"), 5)), False),
        ("C11 keychain dbus script, the whole command wrapped", "ci.yml", "j", job(step(w + dbus, 5)), False),
        ("C11 whole command wrapped, then a bare build after it", "ci.yml", "j",
         job(step(w + dbus + "\ncargo test --all-features --lib", 5)), True),
        ("C11 whole command wrapped, but its body has a second quote", "ci.yml", "j",
         job(step(w + dbus.replace("--exact a15", "--exact 'a15'"), 5)), True),
        ("C11 keychain dbus script, bare", "ci.yml", "j", job(step(dbus, 5)), True),
        ("C11 coverage tee pipeline, wrapped", "c.yml", "j", job(step(cov.replace("python3 scripts", w + "python3 scripts"), 70), limit=180), False),
        ("C11 coverage tee pipeline, bare", "c.yml", "j", job(step(cov, 70), limit=180), True),
    ]


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
