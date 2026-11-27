#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The macOS legs build and run the lib test parts (design: three legs, no handoff).

Static checks on every workflow and on scripts/ci/shard_tests.py, read as data:

- T1: the runner's PARTS["macos"] maps `lib-b`, `lib-c` and `int-lib` to lib test parts that are exactly 1..N
  (N from scripts/dev/test-parts-build.rs), each in one leg; the solo lane (lib-b alone) takes 1..N.
- T2: every lib step of a macOS job runs `shard_tests.py run-prebuilt-parts macos <leg> --build <dir>`,
  naming no part; no macOS step runs `cargo test --lib`, `export-lib`, `wait-lib` or `run macos lib-a`;
  SHARDS["macos"] holds no unsplit `--lib` selection.
- T3: the union job `macos-lib-union` ("macOS lib union") needs macos-shards, runs under `!cancelled()`
  and macos-shards' own guard with no train skip, and runs exactly the expect, lib_union and
  `check_needs.py macos-shards` gates, in that order, nothing able to turn their failure green; macos-check needs it.
- T4: each macOS leg uploads its part lists under `if: !cancelled()` with `overwrite: true`; the union
  job downloads every leg's lists, one folder per leg, so a part listed by two legs stays visible (lib_union.py reads
  pK/list.txt at any depth: a lone matching artifact is unpacked without its folder).
- T5: limits: the job 180, lib-b's and lib-c's lib steps 150 each, int's suite 110 and part step 50.
- T6: the handoff is gone: no `rehearse_macos_lib_fallback` input, no MACOS_LIB_REHEARSE_FALLBACK,
  no `macos-lib-tests` artifact, no macOS PREBUILT entry.
- T7: each leg's lib floor is its parts' recorded macOS counts minus 2%, rounded down.
- T8: the root-row setup steps run on every matrix part leg (lib-b || lib-c, exactly) and before the first part step.

  test_macos_parts.py              check the tree (exit 1 with every problem)
  test_macos_parts.py --self-test  every rule on a fixture of the good layout, and one mutant per switch
"""
from __future__ import annotations

import copy
import glob
import importlib.util
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHARD_JOB, CHECK_JOB, UNION_JOB, UNION_NAME = "macos-shards", "macos-check", "macos-lib-union", "macOS lib union"
TRAIN_SKIP_MARK = "startsWith(github.head_ref, 'train/')"
LIB_STEP = re.compile(r'^python3 scripts/ci/shard_tests\.py run-prebuilt-parts macos (\S+) --build "\$RUNNER_TEMP/parts"$')
FORBIDDEN = ("cargo test --lib", "shard_tests.py export-lib", "shard_tests.py wait-lib", "shard_tests.py run macos lib-a")
EXPECT = "scripts/gate-env/.venv/bin/python scripts/dev/test_parts.py expect aarch64-apple-darwin"
UNION = "python3 scripts/ci/lib_union.py"
# The union's third gate: every leg's own result, so a red, skipped or cancelled leg fails it with complete lists.
NEEDS_GATE = "python3 scripts/ci/check_needs.py macos-shards"
NEEDS_ENV = "${{ toJSON(needs) }}"
LIMITS = {"job": 180, "lib-b": 150, "lib-c": 150, "int-suite": 110, "int-lib": 50}
LISTS = "macos-lib-lists-"
# The steps that let a part's root rows run (local users, a reachable parts folder): on every part leg.
SETUP = ("Local users for the writer's root rows", "mcpg-c can reach the part binaries")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workflows() -> dict[str, dict]:
    return {Path(p).name: yaml.safe_load(Path(p).read_text())
            for p in sorted(glob.glob(str(ROOT / ".github/workflows/*.yml")))}


def macos_jobs(wfs: dict[str, dict]):
    for file, wf in wfs.items():
        for key, job in ((wf or {}).get("jobs") or {}).items():
            if "macos" in str(job.get("runs-on", "")):
                yield file, key, job


def runs(job: dict) -> list[str]:
    return [str(s.get("run", "")).strip() for s in job.get("steps", []) if s.get("run")]


def parts_problems(st, n: int) -> list[str]:
    """T1 and T7."""
    out = []
    parts = getattr(st, "PARTS", {}).get("macos")
    if not parts:
        return ["T1: the runner's PARTS has no macOS legs mapped to lib test parts"]
    if set(parts) != {"lib-b", "lib-c", "int-lib"}:
        out.append(f"T1: PARTS['macos'] maps {sorted(parts)}, want lib-b, lib-c and int-lib")
    taken = sorted(p for ps in parts.values() for p in ps)
    if taken != list(range(1, n + 1)):
        out.append(f"T1: the macOS legs take parts {taken}, want exactly 1..{n}, each once")
    solo = getattr(st, "leg_parts", None)
    if solo is None or list(solo("macos", "lib-b", solo=True)) != list(range(1, n + 1)):
        out.append(f"T1: the solo lane's lib-b does not take parts 1..{n}")
    counts = getattr(st, "MACOS_PART_COUNTS", {})
    for leg, ps in parts.items():
        floors = [f for step, args, _, f in st.SHARDS.get("macos", {}).get(leg, []) if step == "parts"]
        if not counts.get("run") or any(p not in counts for p in ps):
            out.append(f"T7: no recorded macOS count (with its run id) for every part of {leg}")
        elif floors != [sum(counts[p] for p in ps) * 98 // 100]:
            out.append(f"T7: {leg}'s floor {floors} is not its parts' recorded counts minus 2%")
    return out


def steps_problems(wfs: dict[str, dict], st) -> list[str]:
    """T2 and T6."""
    out = []
    for file, key, job in macos_jobs(wfs):
        for r in runs(job):
            for bad in FORBIDDEN:
                if bad in r:
                    out.append(f"T2: {file}:{key} runs `{bad}`")
            if "run-prebuilt-parts" in r and not LIB_STEP.match(r):
                out.append(f"T2: {file}:{key}: `{r}` is not run-prebuilt-parts naming the leg only")
    if any("--lib" in args for steps in st.SHARDS.get("macos", {}).values() for step, args, _, _ in steps if step != "parts"):
        out.append("T2: SHARDS['macos'] holds an unsplit --lib selection")
    for file, wf in wfs.items():
        text = yaml.safe_dump(wf)
        for gone in ("rehearse_macos_lib_fallback", "MACOS_LIB_REHEARSE_FALLBACK", "macos-lib-tests"):
            if gone in text:
                out.append(f"T6: {file} still names {gone}")
    if "macos" in getattr(st, "PREBUILT", {}):
        out.append("T6: the runner still has a macOS PREBUILT entry")
    return out


def bare_guard(job: dict) -> str:
    g = str(job.get("if", "")).strip()
    return g[3:-2].strip() if g.startswith("${{") and g.endswith("}}") else g


def union_problems(jobs: dict) -> list[str]:
    """T3 and the download half of T4."""
    out = []
    union, shard, check = jobs.get(UNION_JOB), jobs.get(SHARD_JOB) or {}, jobs.get(CHECK_JOB) or {}
    if not union:
        return [f"T3: no {UNION_JOB} job"]
    if union.get("name") != UNION_NAME:
        out.append(f"T3: {UNION_JOB} is named {union.get('name')!r}, want {UNION_NAME!r}")
    needs = union.get("needs") or []
    if SHARD_JOB not in ([needs] if isinstance(needs, str) else needs):
        out.append(f"T3: {UNION_JOB} does not need {SHARD_JOB}")
    want_if = "${{ !cancelled() && " + bare_guard(shard) + " }}"
    # Exact equality: an added train skip (or any other clause) breaks it. The shards' own guard names train/
    # branches as an inclusion, so the phrase alone proves nothing.
    if str(union.get("if", "")).replace(" ", "") != want_if.replace(" ", ""):
        out.append(f"T3: {UNION_JOB}'s if must be !cancelled() and {SHARD_JOB}'s guard, exactly, with no train skip")
    check_needs = check.get("needs") or []
    if UNION_JOB not in ([check_needs] if isinstance(check_needs, str) else check_needs):
        out.append(f"T3: {CHECK_JOB} does not need {UNION_JOB}")
    steps = union.get("steps") or []
    kinds = {EXPECT: "expect", UNION: "union", "scripts/ci/check_needs.py": "needs"}
    gates = [i for i, s in enumerate(steps) if any(k in str(s.get("run", "")) for k in kinds)]
    expects = [s for s in steps if str(s.get("run", "")).strip().startswith(EXPECT + " ")]
    unions = [s for s in steps if str(s.get("run", "")).strip().startswith(UNION + " ")]
    needs_steps = [s for s in steps if str(s.get("run", "")).strip() == NEEDS_GATE]
    if len(expects) != 1 or len(unions) != 1 or len(needs_steps) != 1 or len(gates) != 3:
        out.append(f"T3: {UNION_JOB} must run exactly one `{EXPECT} <dir>`, one `{UNION} <lists> <dir>` and one `{NEEDS_GATE}`")
    order = [next(v for k, v in kinds.items() if k in str(steps[i].get("run", ""))) for i in gates]
    if len(gates) == 3 and order != ["expect", "union", "needs"]:
        out.append(f"T3: {UNION_JOB}'s gates run in the order {order}, want expect, union, needs")
    if needs_steps and (needs_steps[0].get("env") or {}).get("NEEDS") != NEEDS_ENV:
        out.append(f"T3: {UNION_JOB}'s needs gate does not read NEEDS from {NEEDS_ENV}")
    for i in gates:
        s, r = steps[i], str(steps[i].get("run", ""))
        if s.get("continue-on-error") or "if" in s or "||" in r or re.search(r";\s*true\b", r) or "\n" in r.strip():
            out.append(f"T3: {UNION_JOB} step {s.get('name')!r} can turn a failure green (continue-on-error, if, ||, ; true or more lines)")
    if gates and any("run" in s for s in steps[max(gates) + 1:]):
        out.append(f"T3: {UNION_JOB} runs a step after its gate")
    downloads = [s for s in steps if "download-artifact" in str(s.get("uses", ""))]
    # One folder per leg's artifact, so a part two legs both list stays two lists (lib_union.py refuses that).
    if not any(str((s.get("with") or {}).get("pattern", "")) == LISTS + "*" and not (s.get("with") or {}).get("merge-multiple")
               for s in downloads):
        out.append(f"T4: {UNION_JOB} does not download every leg's `{LISTS}*` lists, one folder per leg")
    return out


def leg_steps_problems(jobs: dict) -> list[str]:
    """The upload half of T4, and T5."""
    out = []
    shard = jobs.get(SHARD_JOB) or {}
    if shard.get("timeout-minutes") != LIMITS["job"]:
        out.append(f"T5: {SHARD_JOB}'s job limit is {shard.get('timeout-minutes')}, want {LIMITS['job']}")
    uploads = [s for s in shard.get("steps", []) if "upload-artifact" in str(s.get("uses", ""))
               and str((s.get("with") or {}).get("name", "")).startswith(LISTS)]
    if not uploads or any(str(s.get("if", "")).replace(" ", "") not in ("${{!cancelled()}}", "!cancelled()")
                          or (s.get("with") or {}).get("overwrite") is not True for s in uploads):
        out.append(f"T4: {SHARD_JOB} must upload `{LISTS}<leg>` under if: !cancelled() with overwrite: true")
    by_name = {}
    for s in shard.get("steps", []):
        r = str(s.get("run", ""))
        if LIB_STEP.match(r.strip()):
            by_name[LIB_STEP.match(r.strip()).group(1)] = s.get("timeout-minutes")
        elif "shard_tests.py run macos ${{ matrix.shard }}" in r:
            by_name["int-suite"] = s.get("timeout-minutes")
    for key in ("lib-b", "lib-c", "int-suite", "int-lib"):
        if by_name.get(key) != LIMITS[key]:
            out.append(f"T5: {key}'s step limit is {by_name.get(key)}, want {LIMITS[key]}")
    return out


def setup_problems(jobs: dict, st) -> list[str]:
    """T8: each root-row setup step runs on exactly the matrix part legs (an OR of their pins, nothing else), and
    before the first part step: the part that lists root rows can sit in any of them."""
    out = []
    steps = (jobs.get(SHARD_JOB) or {}).get("steps", [])
    legs = [leg for leg in getattr(st, "PARTS", {}).get("macos", {}) if leg != "int-lib"]
    want = " || ".join(f"matrix.shard == '{leg}'" for leg in legs)
    first = next((i for i, s in enumerate(steps) if LIB_STEP.match(str(s.get("run", "")).strip())), len(steps))
    for name in SETUP:
        found = [i for i, s in enumerate(steps) if s.get("name") == name]
        if len(found) != 1:
            out.append(f"T8: {SHARD_JOB} must have exactly one step {name!r}")
            continue
        guard = " ".join(bare_guard(steps[found[0]]).split())
        if guard != want:
            out.append(f"T8: {name!r} runs on `{guard}`, want `{want}`")
        if found[0] > first:
            out.append(f"T8: {name!r} comes after the first part step")
    return out


def problems(wfs: dict[str, dict], st, n: int) -> list[str]:
    jobs = (wfs.get("ci.yml") or {}).get("jobs") or {}
    return (parts_problems(st, n) + steps_problems(wfs, st) + union_problems(jobs) + leg_steps_problems(jobs)
            + setup_problems(jobs, st))


GUARD = "github.event_name != 'pull_request'"


def fixture():
    """The good layout: the design's three legs, the union job, the runner's tables."""
    import types

    def leg_parts(os_kind, leg, solo=False):
        return range(1, 6) if solo and leg == "lib-b" else st.PARTS[os_kind][leg]
    st = types.SimpleNamespace(
        PARTS={"macos": {"lib-b": (1, 3), "lib-c": (2, 4), "int-lib": (5,)}},
        MACOS_PART_COUNTS={"run": "1", 1: 100, 2: 100, 3: 100, 4: 100, 5: 100},
        SHARDS={"macos": {"lib-b": [("parts", ["--lib"], [], 196)],
                          "lib-c": [("parts", ["--lib"], [], 196)],
                          "int": [("suite", ["--bins", "--test", "*"], [], 1600), ("doc", ["--doc"], [], 55)],
                          "int-lib": [("parts", ["--lib"], [], 98)]}},
        PREBUILT={}, leg_parts=leg_parts)
    lib = 'python3 scripts/ci/shard_tests.py run-prebuilt-parts macos {} --build "$RUNNER_TEMP/parts"'
    pin = "matrix.shard == 'lib-b' || matrix.shard == 'lib-c'"
    jobs = {
        SHARD_JOB: {"runs-on": "macos-latest", "if": "${{ " + GUARD + " }}", "timeout-minutes": 180, "steps": [
            {"name": SETUP[0], "if": pin, "uses": "./.github/actions/access-rows-setup"},
            {"name": SETUP[1], "if": pin, "run": "true"},
            {"name": "lib-b", "if": "matrix.shard == 'lib-b'", "timeout-minutes": 150, "run": lib.format("lib-b")},
            {"name": "lib-c", "if": "matrix.shard == 'lib-c'", "timeout-minutes": 150, "run": lib.format("lib-c")},
            {"name": "suite", "if": "matrix.shard == 'int'", "timeout-minutes": 110,
             "run": "python3 scripts/ci/shard_tests.py run macos ${{ matrix.shard }}"},
            {"name": "part 5", "if": "matrix.shard == 'int'", "timeout-minutes": 50, "run": lib.format("int-lib")},
            {"name": "lists", "if": "${{ !cancelled() }}", "uses": "actions/upload-artifact@x",
             "with": {"name": LISTS + "${{ matrix.shard }}", "overwrite": True}}]},
        CHECK_JOB: {"needs": [SHARD_JOB, UNION_JOB]},
        UNION_JOB: {"name": UNION_NAME, "needs": SHARD_JOB, "runs-on": "ubuntu-24.04",
                    "if": "${{ !cancelled() && " + GUARD + " }}", "steps": [
            {"uses": "actions/download-artifact@x", "with": {"pattern": LISTS + "*", "path": "lists"}},
            {"name": "expect", "run": EXPECT + ' "$RUNNER_TEMP/expected"'},
            {"name": "union", "run": UNION + ' "$RUNNER_TEMP/lists" "$RUNNER_TEMP/expected"'},
            {"name": "needs", "env": {"NEEDS": NEEDS_ENV}, "run": NEEDS_GATE}]},
    }
    return {"ci.yml": {"on": {"workflow_dispatch": {"inputs": {}}}, "jobs": jobs}}, st


def mutants():
    """(tag, label, mutate(wfs, st) -> n or None): one per switch site of the rules above."""
    def j(w):
        return w["ci.yml"]["jobs"]

    def step(w, job, name):
        return next(s for s in j(w)[job]["steps"] if s.get("name") == name)

    def add_run(w, run):
        j(w)[SHARD_JOB]["steps"].append({"name": "extra", "run": run})

    def other_workflow(w, s):
        w["other.yml"] = {"jobs": {"mac": {"runs-on": "macos-15", "steps": [{"run": "python3 scripts/ci/shard_tests.py export-lib x"}]}}}

    rows = [
        ("T1", "a part in two legs", lambda w, s: s.PARTS["macos"].update({"int-lib": (4, 5)})),
        ("T1", "a part in no leg", lambda w, s: s.PARTS["macos"].update({"int-lib": ()})),
        ("T1", "N raised to 6 with no leg taking part 6", lambda w, s: 6),
        ("T1", "solo lib-b taking 1-4", lambda w, s: setattr(s, "leg_parts", lambda o, l, solo=False: s.PARTS[o][l])),
        ("T2", "cargo test --lib on a leg", lambda w, s: add_run(w, "cargo test --lib --all-features")),
        ("T2", "export-lib on a leg", lambda w, s: add_run(w, 'python3 scripts/ci/shard_tests.py export-lib "$X"')),
        ("T2", "wait-lib on a leg", lambda w, s: add_run(w, "python3 scripts/ci/shard_tests.py wait-lib a b")),
        ("T2", "the lib-a half on a leg", lambda w, s: add_run(w, "python3 scripts/ci/shard_tests.py run macos lib-a")),
        ("T2", "a part list in the command", lambda w, s: step(w, SHARD_JOB, "lib-b").update(
            {"run": 'python3 scripts/ci/shard_tests.py run-prebuilt-parts macos lib-b --build 1,2,3,4 "$RUNNER_TEMP/parts"'})),
        ("T2", "an unsplit --lib row in SHARDS", lambda w, s: s.SHARDS["macos"]["int"].append(("suite", ["--lib"], [], 1))),
        ("T2", "export-lib in another workflow's macOS job", other_workflow),
        ("T3", "the union job renamed without the macOS prefix", lambda w, s: j(w)[UNION_JOB].update({"name": "lib union"})),
        ("T3", "needs macos-shards removed", lambda w, s: j(w)[UNION_JOB].pop("needs")),
        ("T3", "the train skip added", lambda w, s: j(w)[UNION_JOB].update(
            {"if": "${{ !cancelled() && " + GUARD + " && !(" + TRAIN_SKIP_MARK + ") }}"})),
        ("T3", "its guard differing from the shards'", lambda w, s: j(w)[UNION_JOB].update({"if": "${{ !cancelled() }}"})),
        ("T3", "removed from macos-check's needs", lambda w, s: j(w)[CHECK_JOB].update({"needs": [SHARD_JOB]})),
        ("T3", "the union step replaced by true", lambda w, s: step(w, UNION_JOB, "union").update({"run": "true"})),
        ("T3", "the expect target changed to Linux", lambda w, s: step(w, UNION_JOB, "expect").update(
            {"run": 'python3 scripts/dev/test_parts.py expect x86_64-unknown-linux-gnu "$RUNNER_TEMP/expected"'})),
        ("T3", "a step after the gate", lambda w, s: j(w)[UNION_JOB]["steps"].append({"run": "exit 0"})),
    ]
    for gate in ("expect", "union", "needs"):
        rows += [
            ("T3", f"continue-on-error on {gate}", lambda w, s, g=gate: step(w, UNION_JOB, g).update({"continue-on-error": True})),
            ("T3", f"|| true on {gate}", lambda w, s, g=gate: step(w, UNION_JOB, g).update({"run": step(w, UNION_JOB, g)["run"] + " || true"})),
            ("T3", f"; true on {gate}", lambda w, s, g=gate: step(w, UNION_JOB, g).update({"run": step(w, UNION_JOB, g)["run"] + "; true"})),
            ("T3", f"if: false on {gate}", lambda w, s, g=gate: step(w, UNION_JOB, g).update({"if": "false"})),
        ]
    rows += [
        ("T4", "the upload's if: !cancelled() dropped", lambda w, s: step(w, SHARD_JOB, "lists").pop("if")),
        ("T4", "the upload's overwrite dropped", lambda w, s: step(w, SHARD_JOB, "lists")["with"].pop("overwrite")),
        ("T4", "the download's pattern narrowed", lambda w, s: j(w)[UNION_JOB]["steps"][0]["with"].update({"pattern": LISTS + "lib-b"})),
        ("T4", "the download merged into one folder", lambda w, s: j(w)[UNION_JOB]["steps"][0]["with"].update({"merge-multiple": True})),
        ("T5", "the job limit at 190", lambda w, s: j(w)[SHARD_JOB].update({"timeout-minutes": 190})),
        ("T5", "lib-b's lib step at 165", lambda w, s: step(w, SHARD_JOB, "lib-b").update({"timeout-minutes": 165})),
        ("T5", "int's suite at 120", lambda w, s: step(w, SHARD_JOB, "suite").update({"timeout-minutes": 120})),
        ("T5", "int's part step at 70", lambda w, s: step(w, SHARD_JOB, "part 5").update({"timeout-minutes": 70})),
        ("T6", "the rehearse input back", lambda w, s: w["ci.yml"]["on"]["workflow_dispatch"]["inputs"].update(
            {"rehearse_macos_lib_fallback": {"type": "boolean"}})),
        ("T6", "the rehearse env back", lambda w, s: step(w, SHARD_JOB, "suite").update({"env": {"MACOS_LIB_REHEARSE_FALLBACK": "x"}})),
        ("T6", "the binary artifact back", lambda w, s: j(w)[SHARD_JOB]["steps"].append(
            {"uses": "actions/upload-artifact@x", "with": {"name": "macos-lib-tests"}})),
        ("T6", "a macOS PREBUILT entry back", lambda w, s: s.PREBUILT.update({"macos": {"lib-a": "lib-b"}})),
        ("T7", "a floor lowered by one", lambda w, s: s.SHARDS["macos"].update({"lib-b": [("parts", ["--lib"], [], 195)]})),
        ("T7", "the counts' run id missing", lambda w, s: s.MACOS_PART_COUNTS.pop("run")),
        ("T1", "lib-c dropped from PARTS", lambda w, s: s.PARTS["macos"].pop("lib-c")),
        ("T3", "the needs gate removed", lambda w, s: j(w)[UNION_JOB]["steps"].pop()),
        ("T3", "the needs gate without its NEEDS env", lambda w, s: step(w, UNION_JOB, "needs").pop("env")),
        ("T3", "the needs gate judging another job", lambda w, s: step(w, UNION_JOB, "needs").update(
            {"run": "python3 scripts/ci/check_needs.py macos-lib-union"})),
        ("T3", "the needs gate before the union gate", lambda w, s: j(w)[UNION_JOB]["steps"].insert(
            2, j(w)[UNION_JOB]["steps"].pop())),
        ("T3", "a multi-line needs gate", lambda w, s: step(w, UNION_JOB, "needs").update(
            {"run": NEEDS_GATE + "\nexit 0"})),
        ("T5", "lib-c's lib step at 165, int-lib's right", lambda w, s: step(w, SHARD_JOB, "lib-c").update({"timeout-minutes": 165})),
        ("T8", "setup pinned to lib-b only", lambda w, s: step(w, SHARD_JOB, SETUP[0]).update({"if": "matrix.shard == 'lib-b'"})),
        ("T8", "setup pinned to lib-c only", lambda w, s: step(w, SHARD_JOB, SETUP[1]).update({"if": "matrix.shard == 'lib-c'"})),
        ("T8", "OR turned into AND", lambda w, s: step(w, SHARD_JOB, SETUP[0]).update(
            {"if": "matrix.shard == 'lib-b' && matrix.shard == 'lib-c'"})),
        ("T8", "a pin to a leg that is not a matrix leg", lambda w, s: step(w, SHARD_JOB, SETUP[1]).update(
            {"if": "matrix.shard == 'lib-b' || matrix.shard == 'lib-x'"})),
        ("T8", "setup after the first part step", lambda w, s: j(w)[SHARD_JOB]["steps"].insert(
            3, j(w)[SHARD_JOB]["steps"].pop(0))),
        ("T8", "a setup step missing", lambda w, s: j(w)[SHARD_JOB]["steps"].pop(1)),
    ]
    return rows


def self_test() -> int:
    wrong = 0
    wfs, st = fixture()
    clean = problems(wfs, st, 5)
    if clean:
        print(f"WRONG the good layout fails: {clean}")
        wrong += 1
    for tag, label, mutate in mutants():
        wfs, st = fixture()
        wfs = copy.deepcopy(wfs)
        result = mutate(wfs, st)
        # Only an int is an N override; pop() and update() return other things.
        n = result if isinstance(result, int) and not isinstance(result, bool) else 5
        found = [p for p in problems(wfs, st, n) if p.startswith(tag + ":")]
        if not found:
            print(f"WRONG {tag} {label}: not caught")
            wrong += 1
    total = len(mutants()) + 1
    print(f"test_macos_parts self-test: {total - wrong} of {total} rows hold")
    return 1 if wrong else 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    st = load("shard_tests", ROOT / "scripts/ci/shard_tests.py")
    n = load("lib_union", ROOT / "scripts/ci/lib_union.py").part_count(ROOT / "scripts/dev/test-parts-build.rs")
    found = problems(workflows(), st, n)
    for p in found:
        print(f"::error::macOS parts: {p}")
    print("macOS parts: OK" if not found else f"macOS parts: {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
