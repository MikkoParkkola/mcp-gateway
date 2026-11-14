#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The lib test binary is built once per run, and a failed build must stay red.

One rustc of that binary peaks about 18.5 GB on a 16 GB runner. Job
linux-lib-build builds it once and uploads the linux-lib-tests artifact; the
lib shards, the gws dry-run and the keychain job run that binary instead of
compiling. Five jobs used to build the same binary.

Fail closed, so a failed or hung shared build turns every consumer red, never
skipped, and no consumer quietly builds its own binary. A job that starts
needing the shared build has to be listed here on purpose. The rollup names
the build and the lib shards, so a red shared build fails the required Tests
check instead of disappearing.

`--self-test` runs these rules on mutated copies of the live ci.yml jobs.
Standard library plus PyYAML, as the other workflow checks.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

BUILD_JOB = "linux-lib-build"
ARTIFACT = "linux-lib-tests"
CONSUMERS = ("test-shards-lib", "gws-dry-run", "linux-keychain")
ROLLUP = "test"

# The build step is this prefix and the export on the same line, adjacent.
# `run ` keeps its trailing space so `run-prebuilt` is not a compile.
PREFIX = "scripts/ci/with-memory-log.sh python3 "
EXPORT = 'scripts/ci/shard_tests.py export-lib "$RUNNER_TEMP/lib-bin"'
UPLOAD_PATH = "${{ runner.temp }}/lib-bin/lib-tests"
DOWNLOAD_PATH = "${{ runner.temp }}/lib-bin"
BINARY = "$RUNNER_TEMP/lib-bin/lib-tests"
GATE_BUILD = "${{ needs.linux-lib-build.result }}"
GATE_RUN = (
    '[ "$BUILD" = success ] || '
    '{ echo "::error::the shared lib test binary was not built (linux-lib-build: $BUILD)"; exit 1; }'
)
CANCELLED = "${{!cancelled()&&"
LIB_SHARDS = "test-shards-lib"

COMPILE_RUN = (
    "cargo test",
    "cargo build",
    "cargo llvm-cov",
    "cargo nextest",
    "shard_tests.py run ",
    "shard_tests.py export-lib",
)
COMPILE_USES = (
    "dtolnay/rust-toolchain",
    "Swatinem/rust-cache",
    "./.github/actions/add-swap",
)

CI = Path(".github/workflows/ci.yml")


def load_jobs() -> dict:
    doc = yaml.safe_load(CI.read_text(encoding="utf-8")) or {}
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def as_minutes(value: object) -> int | None:
    """A timeout-minutes value, when it is a real integer. True is an int in Python and is not a timeout."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def steps_of(job: dict) -> list[dict]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def needs_of(job: dict) -> list[str]:
    needs = job.get("needs")
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list):
        return [item for item in needs if isinstance(item, str)]
    return []


def run_text(step: dict) -> str:
    run = step.get("run")
    return run if isinstance(run, str) else ""


def with_map(step: dict) -> dict:
    body = step.get("with")
    return body if isinstance(body, dict) else {}


def action_base(step: dict) -> str:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return ""
    return uses.split("@", 1)[0]


def uses_action(step: dict, action: str) -> bool:
    return action_base(step) == action


def step_label(index: int, step: dict) -> str:
    name = step.get("name")
    if isinstance(name, str) and name.strip():
        return f"step {index} ({name})"
    return f"step {index}"


def line_exports(run: str) -> tuple[bool, bool]:
    """(export on a line, that same line prefixed by the memory-log wrapper)."""
    found = False
    wrapped = False
    for line in run.splitlines() or [""]:
        if EXPORT not in line:
            continue
        found = True
        if PREFIX + EXPORT in line:
            wrapped = True
    return found, wrapped


def check_export_step(job: dict, steps: list[dict]) -> tuple[list[str], int | None]:
    """B2. Returns problems and the index of the one wrapped export step."""
    problems: list[str] = []
    matched: list[int] = []
    for index, step in enumerate(steps):
        found, wrapped = line_exports(run_text(step))
        if wrapped:
            matched.append(index)
        elif found:
            problems.append(
                f"{BUILD_JOB} {step_label(index, step)}: export-lib is not preceded on the same line "
                f"by `{PREFIX}`"
            )
    if len(matched) != 1:
        problems.append(
            f"{BUILD_JOB} job: expected exactly one export-lib step run through with-memory-log.sh, "
            f"found {len(matched)}"
        )
        return problems, None
    index = matched[0]
    step = steps[index]
    limit = as_minutes(step.get("timeout-minutes"))
    job_limit = as_minutes(job.get("timeout-minutes"))
    label = step_label(index, step)
    if limit is None:
        problems.append(f"{BUILD_JOB} {label}: has no timeout-minutes")
    elif job_limit is None or limit >= job_limit:
        problems.append(
            f"{BUILD_JOB} {label}: timeout-minutes {step.get('timeout-minutes')!r} is not smaller than "
            f"the job's {job.get('timeout-minutes')!r}"
        )
    return problems, index


def check_upload(steps: list[dict], build_at: int | None) -> list[str]:
    """B3. The shared binary is uploaded after it is built, and a missing file is an error."""
    problems: list[str] = []
    found = False
    for index, step in enumerate(steps):
        if not uses_action(step, "actions/upload-artifact"):
            continue
        body = with_map(step)
        if body.get("name") != ARTIFACT:
            continue
        found = True
        label = step_label(index, step)
        if body.get("path") != UPLOAD_PATH:
            problems.append(f"{BUILD_JOB} {label}: path is {body.get('path')!r}, want {UPLOAD_PATH!r}")
        if body.get("if-no-files-found") != "error":
            problems.append(
                f"{BUILD_JOB} {label}: if-no-files-found is {body.get('if-no-files-found')!r}, want 'error'"
            )
        if build_at is not None and index <= build_at:
            problems.append(f"{BUILD_JOB} {label}: upload is not after the export-lib build step")
    if not found:
        problems.append(f"{BUILD_JOB} job: no actions/upload-artifact step named {ARTIFACT}")
    return problems


def check_build_fail_closed(job: dict, steps: list[dict], jobs: dict) -> list[str]:
    """B4. Nothing on the build may swallow a failure, and its `if:` matches the shard job."""
    problems: list[str] = []
    if "continue-on-error" in job:
        problems.append(f"{BUILD_JOB} job: carries continue-on-error")
    for index, step in enumerate(steps):
        label = step_label(index, step)
        if "continue-on-error" in step:
            problems.append(f"{BUILD_JOB} {label}: carries continue-on-error")
        if "if" in step:
            problems.append(f"{BUILD_JOB} {label}: carries if:")
    shards = jobs.get("test-shards")
    shards_if = shards.get("if") if isinstance(shards, dict) else None
    if job.get("if") != shards_if:
        problems.append(f"{BUILD_JOB} job: if: does not equal test-shards if:")
    return problems


def check_build(jobs: dict) -> list[str]:
    """B1-B4."""
    job = jobs.get(BUILD_JOB)
    if not isinstance(job, dict):
        return [f"{BUILD_JOB} job: missing"]
    problems: list[str] = []
    runs_on = job.get("runs-on", "")
    host = " ".join(str(item) for item in runs_on) if isinstance(runs_on, list) else str(runs_on)
    if "ubuntu" not in host:
        problems.append(f"{BUILD_JOB} job: runs-on {runs_on!r} does not contain ubuntu")
    if as_minutes(job.get("timeout-minutes")) is None:
        problems.append(f"{BUILD_JOB} job: has no timeout-minutes")
    steps = steps_of(job)
    export_problems, build_at = check_export_step(job, steps)
    problems += export_problems
    problems += check_upload(steps, build_at)
    problems += check_build_fail_closed(job, steps, jobs)
    return problems


def check_gate(name: str, steps: list[dict]) -> list[str]:
    """C3. The first step fails the job when the shared build did not succeed."""
    if not steps:
        return [f"{name} job: has no steps; the first must gate on {BUILD_JOB}"]
    step = steps[0]
    label = step_label(0, step)
    problems: list[str] = []
    env = step.get("env")
    build = env.get("BUILD") if isinstance(env, dict) else None
    if build != GATE_BUILD:
        problems.append(f"{name} {label}: env.BUILD is {build!r}, want {GATE_BUILD!r}")
    if run_text(step).strip() != GATE_RUN:
        problems.append(f"{name} {label}: run is not the shared-build gate")
    if "if" in step:
        problems.append(f"{name} {label}: carries if:")
    if "continue-on-error" in step:
        problems.append(f"{name} {label}: carries continue-on-error")
    return problems


def check_download(name: str, steps: list[dict]) -> list[str]:
    """C4. The artifact is fetched before any step reads the shared binary."""
    downloads: list[int] = []
    problems: list[str] = []
    for index, step in enumerate(steps):
        if not uses_action(step, "actions/download-artifact"):
            continue
        body = with_map(step)
        if body.get("name") != ARTIFACT:
            continue
        if body.get("path") != DOWNLOAD_PATH:
            problems.append(
                f"{name} {step_label(index, step)}: path is {body.get('path')!r}, want {DOWNLOAD_PATH!r}"
            )
            continue
        downloads.append(index)
    binary = [index for index, step in enumerate(steps) if BINARY in run_text(step)]
    if not downloads:
        where = ""
        if binary:
            where = f"; {step_label(binary[0], steps[binary[0]])} runs {BINARY}"
        problems.append(f"{name} job: no actions/download-artifact step named {ARTIFACT}{where}")
        return problems
    uncovered = [index for index in binary if not any(download < index for download in downloads)]
    if uncovered:
        download = downloads[0]
        ran = uncovered[0]
        problems.append(
            f"{name} {step_label(download, steps[download])}: download-artifact is not before "
            f"{step_label(ran, steps[ran])}, which runs {BINARY}"
        )
    return problems


def check_no_compile(name: str, steps: list[dict]) -> list[str]:
    """C5. A consumer runs the shared binary; it does not build another one."""
    problems: list[str] = []
    for index, step in enumerate(steps):
        label = step_label(index, step)
        run = run_text(step)
        for needle in COMPILE_RUN:
            if needle in run:
                problems.append(f"{name} {label}: run contains {needle!r}")
        base = action_base(step)
        if base in COMPILE_USES:
            problems.append(f"{name} {label}: uses {base}")
    return problems


def check_no_continue(name: str, job: dict, steps: list[dict]) -> list[str]:
    """C6."""
    problems: list[str] = []
    if "continue-on-error" in job:
        problems.append(f"{name} job: carries continue-on-error")
    for index, step in enumerate(steps):
        if "continue-on-error" in step:
            problems.append(f"{name} {step_label(index, step)}: carries continue-on-error")
    return problems


def check_consumer(name: str, job: object) -> list[str]:
    """C1-C6 for one consumer."""
    if not isinstance(job, dict):
        return [f"{name} job: missing"]
    problems: list[str] = []
    if BUILD_JOB not in needs_of(job):
        problems.append(f"{name} job: needs does not contain {BUILD_JOB}")
    condition = job.get("if")
    compact = "".join(condition.split()) if isinstance(condition, str) else ""
    if not compact.startswith(CANCELLED):
        problems.append(f"{name} job: if: does not start with !cancelled(), so a failed build can skip it")
    steps = steps_of(job)
    problems += check_gate(name, steps)
    problems += check_download(name, steps)
    problems += check_no_compile(name, steps)
    problems += check_no_continue(name, job, steps)
    return problems


def downloads_artifact(job: dict) -> bool:
    for step in steps_of(job):
        if uses_action(step, "actions/download-artifact") and with_map(step).get("name") == ARTIFACT:
            return True
    return False


def check_closed(jobs: dict) -> list[str]:
    """C7. A new user of the shared build is named here, and a downloader needs the build."""
    problems: list[str] = []
    allowed = set(CONSUMERS) | {ROLLUP}
    for name, job in jobs.items():
        if not isinstance(job, dict) or name == BUILD_JOB:
            continue
        if BUILD_JOB in needs_of(job) and name not in allowed:
            problems.append(f"{name} job: needs {BUILD_JOB} but is not a listed consumer or {ROLLUP}")
        if downloads_artifact(job) and BUILD_JOB not in needs_of(job):
            problems.append(f"{name} job: downloads {ARTIFACT} but does not need {BUILD_JOB}")
    return problems


def expects_both(job: dict) -> bool:
    for step in steps_of(job):
        env = step.get("env")
        if not isinstance(env, dict):
            continue
        raw = env.get("ROLLUP_EXPECTS")
        if not isinstance(raw, str):
            continue
        named = raw.split()
        if BUILD_JOB in named and LIB_SHARDS in named:
            return True
    return False


def check_rollup(jobs: dict) -> list[str]:
    """R1. The required Tests job waits on the shared build and the lib shards."""
    job = jobs.get(ROLLUP)
    if not isinstance(job, dict):
        return [f"{ROLLUP} job: missing"]
    problems: list[str] = []
    needs = needs_of(job)
    if BUILD_JOB not in needs:
        problems.append(f"{ROLLUP} job: needs does not contain {BUILD_JOB}")
    if LIB_SHARDS not in needs:
        problems.append(f"{ROLLUP} job: needs does not contain {LIB_SHARDS}")
    if not expects_both(job):
        problems.append(f"{ROLLUP} job: no step env.ROLLUP_EXPECTS lists {BUILD_JOB} and {LIB_SHARDS}")
    return problems


def check(jobs: dict) -> list[str]:
    problems = check_build(jobs)
    for name in CONSUMERS:
        problems += check_consumer(name, jobs.get(name))
    problems += check_closed(jobs)
    problems += check_rollup(jobs)
    # C3 and C6 can name the same gate step; one line per problem.
    unique: list[str] = []
    seen: set[str] = set()
    for problem in problems:
        if problem in seen:
            continue
        seen.add(problem)
        unique.append(problem)
    return unique


def main() -> int:
    problems = check(load_jobs())
    for problem in problems:
        print(f"::error::{problem}")
    print(f"{len(problems)} problems")
    return 1 if problems else 0


def _drop_download(job: dict) -> None:
    job["steps"] = [
        step for step in job["steps"]
        if not (uses_action(step, "actions/download-artifact") and with_map(step).get("name") == ARTIFACT)
    ]


def _move_download_after_binary(job: dict) -> None:
    steps = job["steps"]
    download = next(index for index, step in enumerate(steps) if uses_action(step, "actions/download-artifact"))
    step = steps.pop(download)
    ran = next(index for index, candidate in enumerate(steps) if BINARY in run_text(candidate))
    steps.insert(ran + 1, step)


def _cases(live: dict) -> list[tuple[str, dict]]:
    """Each entry is a deep copy of the live jobs with one mutation, except the first."""

    def fresh() -> dict:
        return copy.deepcopy(live)

    gate_if = fresh()
    gate_if["gws-dry-run"]["steps"][0]["if"] = False

    gate_continue = fresh()
    gate_continue["gws-dry-run"]["steps"][0]["continue-on-error"] = True

    drop_gate = fresh()
    drop_gate["gws-dry-run"]["steps"] = drop_gate["gws-dry-run"]["steps"][1:]

    no_cancel = fresh()
    no_cancel["linux-keychain"]["if"] = no_cancel["linux-keychain"]["if"].replace("!cancelled() && ", "", 1)

    lose_needs = fresh()
    del lose_needs["test-shards-lib"]["needs"]

    compiles = fresh()
    compiles["test-shards-lib"]["steps"].append({"run": "cargo test --all-features --lib --no-run"})

    caches = fresh()
    caches["gws-dry-run"]["steps"].append({"uses": "Swatinem/rust-cache@x"})

    no_download = fresh()
    _drop_download(no_download["linux-keychain"])

    late_download = fresh()
    _move_download_after_binary(late_download["test-shards-lib"])

    warn_upload = fresh()
    for step in warn_upload[BUILD_JOB]["steps"]:
        if uses_action(step, "actions/upload-artifact") and with_map(step).get("name") == ARTIFACT:
            step["with"]["if-no-files-found"] = "warn"

    bare_build = fresh()
    for step in bare_build[BUILD_JOB]["steps"]:
        run = step.get("run")
        if isinstance(run, str) and PREFIX in run:
            step["run"] = run.replace(PREFIX, "", 1)

    long_build = fresh()
    for step in long_build[BUILD_JOB]["steps"]:
        if isinstance(step.get("run"), str) and EXPORT in step["run"]:
            step["timeout-minutes"] = long_build[BUILD_JOB]["timeout-minutes"]

    build_continues = fresh()
    build_continues[BUILD_JOB]["continue-on-error"] = True

    extra = fresh()
    extra["extra"] = {"needs": BUILD_JOB, "runs-on": "ubuntu-latest", "steps": []}

    stray_download = fresh()
    stray_download["stray"] = {
        "runs-on": "ubuntu-latest",
        "steps": [{"uses": "actions/download-artifact@x", "with": {"name": ARTIFACT, "path": DOWNLOAD_PATH}}],
    }

    rollup_needs = fresh()
    rollup_needs[ROLLUP]["needs"] = [need for need in rollup_needs[ROLLUP]["needs"] if need != LIB_SHARDS]

    rollup_expects = fresh()
    for step in rollup_expects[ROLLUP]["steps"]:
        env = step.get("env")
        if isinstance(env, dict) and isinstance(env.get("ROLLUP_EXPECTS"), str):
            env["ROLLUP_EXPECTS"] = " ".join(part for part in env["ROLLUP_EXPECTS"].split() if part != BUILD_JOB)

    consumer_continues = fresh()
    consumer_continues["linux-keychain"]["continue-on-error"] = True

    return [
        ("live jobs unchanged", live),
        ("drop the gate step from gws-dry-run", drop_gate),
        ("gate step gets if: false", gate_if),
        ("gate step gets continue-on-error: true", gate_continue),
        ("linux-keychain job if without the !cancelled() prefix", no_cancel),
        ("test-shards-lib loses needs", lose_needs),
        ("a consumer gains a step run: cargo test --all-features --lib --no-run", compiles),
        ("a consumer gains uses: Swatinem/rust-cache@x", caches),
        ("download step removed", no_download),
        ("download moved after the first step that runs the binary", late_download),
        ('upload if-no-files-found "warn"', warn_upload),
        ("build step loses its with-memory-log prefix", bare_build),
        ("build step timeout >= job timeout", long_build),
        ("BUILD_JOB gains continue-on-error at job level", build_continues),
        ("a new job extra that needs BUILD_JOB", extra),
        ("a job downloads the binary without needing the build", stray_download),
        ("ROLLUP drops test-shards-lib from needs", rollup_needs),
        ("ROLLUP_EXPECTS drops linux-lib-build", rollup_expects),
        ("a consumer job gains continue-on-error", consumer_continues),
    ]


def self_test() -> int:
    live = load_jobs()
    cases = _cases(live)
    wrong = 0
    for index, (label, jobs) in enumerate(cases):
        found = check(jobs)
        ok = (not found) if index == 0 else bool(found)
        wrong += not ok
        print(f"{'ok    ' if ok else 'WRONG '}{label}: problems {found}")
    print(f"self-test: {len(cases) - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
