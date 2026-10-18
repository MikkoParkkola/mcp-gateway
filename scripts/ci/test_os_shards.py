#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The OS test shards reproduce the suites they replaced (MIK-8482).

Static checks on ci.yml and scripts/ci/shard_tests.py:

- every OS's shards are exact complements: one lib filter and its `--skip`,
  and integration globs that are `*` alone or a class and its negation;
- together they cover the targets the unsharded command ran (Linux, macOS:
  lib, bins, tests, doctests; Windows: `--tests`, which is lib, bins, tests);
- each shard matrix in ci.yml lists exactly that OS's shards;
- the aggregates keep the required names, need their shard jobs, run under
  always() with the shards' own skip guards, and pass the same job ids to
  check_needs.py;
- no shard name equals a required name, every macOS shard name starts with
  `macOS ` (merge tooling treats that prefix as macOS), and none contains
  the word `Tests`.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
JOBS = {  # os: (shard job, aggregate job, aggregate name, shard name prefix)
    "linux": ("test-shards", "test", "Tests", "Linux shard "),
    "windows": ("windows-shards", "windows-check", "Windows check", "Windows shard "),
    "macos": ("macos-shards", "macos-check", "macOS check", "macOS shard "),
}
EXTRA_NEEDS = {"windows-check": ["windows-clippy"]}
COVERS = {"linux": {"lib", "bins", "tests", "doc"}, "macos": {"lib", "bins", "tests", "doc"},
          "windows": {"lib", "bins", "tests"}}


def runner():
    spec = importlib.util.spec_from_file_location("shard_tests", ROOT / "scripts/ci/shard_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def table_problems(st) -> list[str]:
    out = []
    for os_kind, shards in st.SHARDS.items():
        lib_filters, globs, kinds, bins = [], [], set(), 0
        for name, steps in shards.items():
            for step, args, test_args, floor in steps:
                if floor <= 0:
                    out.append(f"{os_kind} {name} {step}: floor must be positive")
                if "--lib" in args:
                    kinds.add("lib")
                    lib_filters.append(tuple(test_args))
                if "--doc" in args:
                    kinds.add("doc")
                if "--bins" in args:
                    kinds.add("bins")
                    bins += 1
                if "--test" in args:
                    kinds.add("tests")
                    globs.append(args[args.index("--test") + 1])
                if "--skip" in args or any(a in st.SKIPS[os_kind] for a in test_args if a != "--skip"):
                    out.append(f"{os_kind} {name} {step}: an OS skip belongs in SKIPS, not the shard")
        if sorted(lib_filters) != sorted([(st.LIB_SPLIT,), ("--skip", st.LIB_SPLIT)]):
            out.append(f"{os_kind}: lib shards {lib_filters} are not one filter and its --skip")
        if sorted(globs) not in ([st.GLOB_ALL], sorted([st.GLOB_A, st.GLOB_B])):
            out.append(f"{os_kind}: integration globs {globs} are not `*` or a class and its negation")
        if st.GLOB_B != "[!" + st.GLOB_A[1:]:
            out.append(f"glob classes {st.GLOB_A} and {st.GLOB_B} are not complements")
        if bins != 1:
            out.append(f"{os_kind}: --bins must be in exactly one shard, found {bins}")
        if kinds != COVERS[os_kind]:
            out.append(f"{os_kind}: shards cover {sorted(kinds)}, the suite ran {sorted(COVERS[os_kind])}")
    return out


def workflow_problems(jobs: dict, st) -> list[str]:
    out = []
    required = {agg_name for _, _, agg_name, _ in JOBS.values()}
    for os_kind, (shard_key, agg_key, agg_name, prefix) in JOBS.items():
        shard, agg = jobs.get(shard_key), jobs.get(agg_key)
        if not shard or not agg:
            out.append(f"{os_kind}: {shard_key} or {agg_key} missing")
            continue
        legs = shard.get("strategy", {}).get("matrix", {}).get("shard")
        if sorted(legs or []) != sorted(st.SHARDS[os_kind]):
            out.append(f"{shard_key}: matrix {legs} is not the runner's {sorted(st.SHARDS[os_kind])}")
        if shard.get("strategy", {}).get("fail-fast") is not False:
            out.append(f"{shard_key}: fail-fast must be false, so one red shard does not cancel the rest")
        name = shard.get("name", "")
        if not name.startswith(prefix) or name in required or "Tests" in name:
            out.append(f"{shard_key}: name {name!r} must start {prefix!r}, not be a required name, not say Tests")
        if agg.get("name") != agg_name:
            out.append(f"{agg_key}: name {agg.get('name')!r} must stay {agg_name!r}")
        needs = agg.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        want = [shard_key, *EXTRA_NEEDS.get(agg_key, [])]
        if sorted(needs) != sorted(want):
            out.append(f"{agg_key}: needs {needs}, want {want}")
        guard = str(shard.get("if", "")).strip()
        if guard.startswith("${{") and guard.endswith("}}"):
            guard = guard[3:-2].strip()
        if str(agg.get("if", "")).replace(" ", "") != ("${{ always() && " + guard + " }}").replace(" ", ""):
            out.append(f"{agg_key}: if must be always() plus the shards' own guard, exactly")
        for extra in EXTRA_NEEDS.get(agg_key, []):
            if str(jobs.get(extra, {}).get("if", "")) != str(shard.get("if", "")):
                out.append(f"{extra}: if must equal {shard_key}'s guard")
        runs = [s.get("run", "") for s in agg.get("steps", [])]
        verdict = [r for r in runs if "scripts/ci/check_needs.py" in r]
        if verdict != [f"python3 scripts/ci/check_needs.py {' '.join(want)}"]:
            out.append(f"{agg_key}: verdict step {verdict} must pass exactly {want}")
        envs = [s.get("env", {}).get("NEEDS") for s in agg.get("steps", []) if "run" in s]
        if "${{ toJSON(needs) }}" not in envs:
            out.append(f"{agg_key}: verdict step must read NEEDS from toJSON(needs)")
    return out


def self_test(jobs: dict, st) -> None:
    """Each wiring rule fails on the mutation that breaks it."""
    import copy

    def broken(mutate) -> bool:
        j = copy.deepcopy(jobs)
        mutate(j)
        return bool(workflow_problems(j, st))

    mutations = {
        "bare always()": lambda j: j["test"].__setitem__("if", "${{ always() }}"),
        "no always()": lambda j: j["macos-check"].__setitem__("if", j["macos-shards"]["if"]),
        "dropped need": lambda j: j["windows-check"].__setitem__("needs", ["windows-shards"]),
        "renamed aggregate": lambda j: j["test"].__setitem__("name", "Tests (all)"),
        "shard named like the check": lambda j: j["macos-shards"].__setitem__("name", "macOS check"),
        "macOS shard without prefix": lambda j: j["macos-shards"].__setitem__("name", "mac shard x"),
        "verdict skips a job": lambda j: j["windows-check"]["steps"][-1].__setitem__(
            "run", "python3 scripts/ci/check_needs.py windows-shards"),
        "leg dropped": lambda j: j["test-shards"]["strategy"]["matrix"].__setitem__("shard", ["lib-a"]),
        "fail-fast": lambda j: j["windows-shards"]["strategy"].__setitem__("fail-fast", True),
        "clippy guard drift": lambda j: j["windows-clippy"].__setitem__("if", "${{ true }}"),
    }
    survived = [n for n, m in mutations.items() if not broken(m)]
    assert not survived, f"wiring mutations not caught: {survived}"
    saved = st.SHARDS["linux"]["lib-b"]
    st.SHARDS["linux"]["lib-b"] = [("suite", ["--lib"], ["--skip", "other::"], 1)]
    try:
        assert table_problems(st), "a lib split that is not a complement passed"
    finally:
        st.SHARDS["linux"]["lib-b"] = saved


def main() -> int:
    st = runner()
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
    problems = table_problems(st) + workflow_problems(jobs, st)
    for p in problems:
        print(f"os-shards: {p}")
    if problems:
        return 1
    self_test(jobs, st)
    print(f"os-shards: {sum(len(s) for s in st.SHARDS.values())} shards on 3 OSes are complete; wiring holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
