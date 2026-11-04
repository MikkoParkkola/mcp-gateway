#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of the coverage grade's test run, for a sharding trial.

The grade's Linux job runs every test target under `cargo llvm-cov` in one
step (`--all-features --tests`, the SDK journey skipped and run alone before
it). A trial splits that step across runners and merges the profiles. Each
shard is the same command over a subset, and the shards of one plan are exact
complements of it:

- the library is split by a libtest filter and the matching `--skip`;
- the bins go whole into one shard;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`).

`check` reads `cargo metadata` and fails when a target that `--tests` builds
falls in no shard or in two, so a new kind of target cannot drop out of the
merged grade unnoticed. Unlike `shard_tests.py`, nothing else is skipped (the
grade runs the full-burst test), and there are no doctests, examples or
TMPDIR guard, as in the single job.

  coverage_shards.py plan <n>              print the plan's shards as JSON
  coverage_shards.py check <n> <metadata>  check the partition (file or -)
  coverage_shards.py run <n> <shard>       run one shard (exit 1 on failure)
  coverage_shards.py --self-test
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shard_tests import SDK, cargo, selected  # noqa: E402

LIB_SPLIT = "gateway::"
GLOB_A, GLOB_B, GLOB_ALL = "[a-l]*", "[!a-l]*", "*"
BASE = ["llvm-cov", "--no-report", "--all-features"]
_LIB_A = (["--lib"], [LIB_SPLIT])
_LIB_B = (["--lib"], ["--skip", LIB_SPLIT])

# shard -> (cargo args after BASE, libtest args before `--skip SDK`)
PLANS: dict[int, dict[str, tuple[list[str], list[str]]]] = {
    3: {
        "lib-a": _LIB_A,
        "lib-b": _LIB_B,
        "int": (["--bins", "--test", GLOB_ALL], []),
    },
    4: {
        "lib-a": _LIB_A,
        "lib-b": _LIB_B,
        "int-a": (["--bins", "--test", GLOB_A], []),
        "int-b": (["--test", GLOB_B], []),
    },
}


def owners(plan: dict[str, tuple[list[str], list[str]]], kind: str, name: str) -> list[str]:
    """The shards that run target `name` of `kind`. The library is split by a
    filter and its complement, so its two shards together are one owner."""
    found = []
    for shard, (args, _test) in plan.items():
        if kind == "lib" and "--lib" in args:
            found.append(shard)
        elif kind == "bin" and "--bins" in args:
            found.append(shard)
        elif kind == "test":
            globs = [args[i + 1] for i, a in enumerate(args) if a == "--test"]
            if any(fnmatch.fnmatchcase(name, g) for g in globs):
                found.append(shard)
    return found


def check(n: int, metadata: dict) -> list[str]:
    """Every target `cargo test --tests` builds, with the shards that own it:
    the problems, empty when the library is split in exactly two shards by a
    filter and its `--skip`, and every other target is in exactly one."""
    plan = PLANS[n]
    problems = []
    # The grade runs without `--workspace`, so cargo builds the workspace's
    # default members; an older cargo that omits them means the root package.
    default = metadata.get("workspace_default_members")
    root_manifest = os.path.join(metadata["workspace_root"], "Cargo.toml")
    packages = [p for p in metadata["packages"]
                if (p["id"] in default if default is not None else p["manifest_path"] == root_manifest)]
    if not packages:
        return ["no package: neither a default member nor the root manifest's"]
    for package in packages:
        for target in package["targets"]:
            kinds = [k for k in target["kind"] if k != "proc-macro"]
            kind = "lib" if any(k in ("lib", "rlib", "cdylib", "staticlib") for k in kinds) else kinds[0]
            # `--tests` builds every target whose `test` flag is set.
            if not target.get("test", kind in ("lib", "bin", "test")):
                continue
            found = owners(plan, kind, target["name"])
            if kind == "lib":
                filters = sorted(" ".join(plan[s][1]) for s in found)
                if filters != sorted([LIB_SPLIT, f"--skip {LIB_SPLIT}"]):
                    problems.append(f"lib {target['name']}: split as {filters}")
            elif len(found) != 1:
                problems.append(f"{kind} {target['name']}: in {found or 'no shard'}")
    return problems


def run(n: int, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    args, test_args = PLANS[n][shard]
    rc, lines = cargo([*BASE, *args, "--", *test_args, "--skip", SDK], program)
    print(f"::notice::coverage {n}/{shard}: selected {selected(lines)}, rc {rc}")
    return rc


def self_test() -> int:
    def target(kind: str, name: str, test: bool = True) -> dict:
        return {"kind": [kind], "name": name, "test": test}

    good = {"workspace_root": "/w", "workspace_default_members": ["gw"], "packages": [
        {"id": "gw", "manifest_path": "/w/Cargo.toml", "targets": [
            target("lib", "mcp_gateway"), target("bin", "mcp-gateway"),
            target("bin", "provenance-eval"), target("test", "audit_trail"),
            target("test", "zz_last"), target("test", "Lower_upper_A"),
            target("bench", "gateway_benchmarks", test=False)]},
        # A workspace member outside the default members is not in the run.
        {"id": "other", "manifest_path": "/w/crates/other/Cargo.toml",
         "targets": [target("lib", "other")]},
    ]}
    # A default member's targets are walked: a testable example in the second
    # package is reported once it is a default member, and only then.
    both = json.loads(json.dumps(good))
    both["packages"][1]["targets"].append(target("example", "other_demo"))
    assert check(4, both) == [], check(4, both)
    both["workspace_default_members"] = ["gw", "other"]
    assert check(4, both) == ["example other_demo: in no shard"], check(4, both)
    # Without the field (an older cargo), the root manifest's package is the run.
    old = json.loads(json.dumps(good))
    del old["workspace_default_members"]
    assert check(4, old) == [], check(4, old)
    for n in PLANS:
        assert check(n, good) == [], (n, check(n, good))
    # A target kind no shard runs (a testable example) is reported, not dropped.
    extra = json.loads(json.dumps(good))
    extra["packages"][0]["targets"].append(target("example", "demo"))
    for n in PLANS:
        assert check(n, extra) == ["example demo: in no shard"], check(n, extra)
    # A glob class that stops being a complement shows up as an unowned target.
    broken = {k: (list(a), list(t)) for k, (a, t) in PLANS[4].items()}
    broken["int-b"] = (["--test", "[m-z]*"], [])
    PLANS[99] = broken
    try:
        assert check(99, good) == ["test Lower_upper_A: in no shard"], check(99, good)
    finally:
        del PLANS[99]
    # Glob classes match case-sensitively, as cargo does: an upper-case first
    # letter falls in [!a-l]* and only there.
    assert owners(PLANS[4], "test", "Lower_upper_A") == ["int-b"]
    print("coverage_shards self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 3 and argv[1] == "plan" and argv[2].isdigit() and int(argv[2]) in PLANS:
        print(json.dumps(sorted(PLANS[int(argv[2])])))
        return 0
    if len(argv) == 4 and argv[1] == "check" and argv[2].isdigit() and int(argv[2]) in PLANS:
        raw = sys.stdin.read() if argv[3] == "-" else open(argv[3], encoding="utf-8").read()
        problems = check(int(argv[2]), json.loads(raw))
        for p in problems:
            print(f"::error::coverage partition: {p}")
        return 1 if problems else 0
    if (len(argv) == 4 and argv[1] == "run" and argv[2].isdigit()
            and argv[3] in PLANS.get(int(argv[2]), {})):
        return run(int(argv[2]), argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
