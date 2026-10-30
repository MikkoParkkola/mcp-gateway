#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Verdict of an aggregate check over its shard jobs (MIK-8482).

`Tests`, `Windows check` and `macOS check` are the names merge tooling and
branch protection read. Each is now an aggregate that `needs:` its shard jobs
and runs under `always()`. Only an exact `success` from every needed job
passes. A skipped or cancelled shard is red, never green: a skipped job is
not evidence that anything ran.

  NEEDS='${{ toJSON(needs) }}' check_needs.py [--allow-skipped job-a,...] job-a job-b ...
  check_needs.py --self-test

--allow-skipped names jobs whose `skipped` result also passes (a docs-only
merge train skips some heavy jobs by design); failed and cancelled stay red.

The listed job ids must all be present in NEEDS, so dropping one from
`needs:` without dropping it here fails too.
"""
from __future__ import annotations

import json
import os
import sys


def verdict(needs: dict, expected: list[str], skippable: frozenset[str] = frozenset()) -> list[str]:
    problems = [f"{job}: not in needs" for job in expected if job not in needs]
    for job, data in sorted(needs.items()):
        result = (data or {}).get("result")
        if result != "success" and not (result == "skipped" and job in skippable):
            problems.append(f"{job}: result {result!r}, not 'success'")
    return problems


def self_test() -> int:
    ok = {"success": {"result": "success"}}
    cases = [
        ({"a": {"result": "success"}, "b": {"result": "success"}}, ["a", "b"], True),
        ({"a": {"result": "success"}, "b": {"result": "failure"}}, ["a", "b"], False),
        ({"a": {"result": "success"}, "b": {"result": "skipped"}}, ["a", "b"], False),
        ({"a": {"result": "cancelled"}, "b": {"result": "success"}}, ["a", "b"], False),
        ({"a": {"result": "success"}}, ["a", "b"], False),
        ({"a": {}}, ["a"], False),
        (ok, ["success"], True),
    ]
    for needs, expected, passes in cases:
        assert (not verdict(needs, expected)) is passes, (needs, expected)
    skip_b = frozenset({"b"})
    for needs, passes in [
        ({"a": {"result": "success"}, "b": {"result": "skipped"}}, True),
        ({"a": {"result": "skipped"}, "b": {"result": "success"}}, False),
        ({"a": {"result": "success"}, "b": {"result": "failure"}}, False),
        ({"a": {"result": "success"}, "b": {"result": "cancelled"}}, False),
    ]:
        assert (not verdict(needs, ["a", "b"], skip_b)) is passes, (needs, "--allow-skipped b")
    print("check_needs self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    skippable: frozenset[str] = frozenset()
    if len(argv) > 2 and argv[1] == "--allow-skipped":
        skippable = frozenset(j for j in argv[2].split(",") if j)
        argv = argv[:1] + argv[3:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    raw = os.environ.get("NEEDS")
    if not raw:
        print("::error::NEEDS is unset: the step must pass NEEDS: ${{ toJSON(needs) }}")
        return 1
    problems = verdict(json.loads(raw), argv[1:], skippable)
    for p in problems:
        print(f"::error::{p}")
    if not problems:
        allowed = f" (skipping allowed: {', '.join(sorted(skippable))})" if skippable else ""
        print(f"every needed job succeeded{allowed}:", ", ".join(argv[1:]))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
