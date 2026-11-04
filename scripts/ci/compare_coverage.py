#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Compare a sharded coverage grade with single-job grades of the same commit.

The sharded pipeline may replace the single job only when, on the same commit:

- the per-function grade tables (critical_function_coverage.py output) are
  identical, the sharded one against every single-job one;
- the executed tests are identical: each `test <name> ... <outcome>` line, as a
  multiset, from the parts' logs against each single job's log;
- every line is in band: covered by the sharded run when every single run
  covers it, and not covered when no single run does. Two single runs differ
  on lines that timing decides (a branch reached once or twice), so a line
  covered by some single runs and not others may go either way.

  compare_coverage.py --table SHARDED_TABLE --table-single T1 [T2 ...]
                      --log SHARDED_LOG [...] --log-single L1 [...]
                      --lcov SHARDED_LCOV --lcov-single C1 C2 C3
  compare_coverage.py --self-test

Each `--log-single` is one single job's logs, comma-separated; the sharded
run's logs are read together. Exit 0 when everything holds, 1 with every
difference listed.
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys
import tempfile

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# libtest's per-test line; a test's own output, or another thread's log line, may
# share it and even start right after the outcome ("... ok2026-11-04T02:58Z
# INFO ..."), so only the name and the outcome word are read, with no boundary.
TEST = re.compile(r"^test (\S.*?) \.\.\. (ok|FAILED|ignored)")


def tests(paths: list[str]) -> collections.Counter:
    found: collections.Counter = collections.Counter()
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = TEST.match(ANSI.sub("", line.rstrip("\r\n")))
                if m:
                    found[(m.group(1), m.group(2))] += 1
    return found


def lines(path: str) -> dict[tuple[str, int], int]:
    """Hits per (file, line) of an lcov report, summed over repeated records.
    Paths are taken relative to the checkout so two runners' reports match."""
    hits: dict[tuple[str, int], int] = {}
    current = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("SF:"):
                name = line[3:].strip()
                current = "src/" + name.split("/src/", 1)[1] if "/src/" in name else name
            elif line.startswith("DA:") and current is not None:
                number, count = line[3:].split(",")[:2]
                key = (current, int(number))
                hits[key] = hits.get(key, 0) + int(count)
    return hits


def compare(table: str, singles_tables: list[str], logs: list[str], single_logs: list[str],
            lcov: str, single_lcovs: list[str]) -> list[str]:
    problems = []
    sharded = open(table, encoding="utf-8").read().splitlines()
    for other in singles_tables:
        theirs = open(other, encoding="utf-8").read().splitlines()
        if sharded != theirs:
            diff = [f"  sharded: {a!r} / single: {b!r}"
                    for a, b in zip(sharded, theirs) if a != b][:5]
            problems.append(f"per-function table differs from {other} "
                            f"({len(sharded)} vs {len(theirs)} lines)\n" + "\n".join(diff))
    ran = tests(logs)
    for other in single_logs:
        # One single job's logs, comma-separated (its SDK step and its main step).
        theirs = tests(other.split(","))
        if ran != theirs:
            extra = sorted((ran - theirs).elements())[:5]
            missing = sorted((theirs - ran).elements())[:5]
            problems.append(f"executed tests differ from {other}: {sum(ran.values())} vs "
                            f"{sum(theirs.values())}; only sharded {extra}; only single {missing}")
    got = lines(lcov)
    runs = [lines(p) for p in single_lcovs]
    keys = set(got).union(*runs)
    below = sorted(k for k in keys if all(r.get(k, 0) > 0 for r in runs) and got.get(k, 0) == 0)
    above = sorted(k for k in keys if all(r.get(k, 0) == 0 for r in runs) and got.get(k, 0) > 0)
    if below:
        problems.append(f"{len(below)} lines covered by every single run but not sharded: {below[:10]}")
    if above:
        problems.append(f"{len(above)} lines covered by no single run but sharded: {above[:10]}")
    if any(set(r) != set(got) for r in runs):
        problems.append("the reports do not hold the same lines (a file or function missing)")
    return problems


def self_test() -> int:
    def write(d: str, name: str, text: str) -> str:
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def lcov(hits: dict[int, int]) -> str:
        body = "".join(f"DA:{n},{c}\n" for n, c in sorted(hits.items()))
        return f"SF:/home/runner/work/x/x/src/a.rs\n{body}end_of_record\n"

    with tempfile.TemporaryDirectory() as d:
        table = write(d, "t", "ok\t100%\tfoo\n")
        log = write(d, "l", "test a::b ... ok\n\x1b[1mtest a::c ... ignored\x1b[0m\ntest x ... ok out\n")
        # Line 1 is covered by every single run, line 2 by none, line 3 by some.
        singles = [write(d, f"c{i}", lcov({1: 2, 2: 0, 3: h})) for i, h in enumerate((1, 0, 1))]
        for shard3 in (0, 1):
            good = write(d, f"g{shard3}", lcov({1: 5, 2: 0, 3: shard3}))
            assert compare(table, [table], [log], [log], good, singles) == [], "in band"
        assert any("not sharded" in p for p in compare(
            table, [table], [log], [log], write(d, "b", lcov({1: 0, 2: 0, 3: 1})), singles))
        assert any("no single run" in p for p in compare(
            table, [table], [log], [log], write(d, "a", lcov({1: 1, 2: 1, 3: 1})), singles))
        assert any("same lines" in p for p in compare(
            table, [table], [log], [log], write(d, "m", lcov({1: 1, 3: 1})), singles))
        other_table = write(d, "t2", "FAIL\t90%\tfoo\n")
        assert any("per-function table" in p for p in compare(
            table, [other_table], [log], [log], singles[0], singles))
        # A test that ran in one pipeline and not the other, or with another outcome.
        less = write(d, "l2", "test a::b ... ok\ntest a::c ... ignored\n")
        failed = write(d, "l3", "test a::b ... FAILED\ntest a::c ... ignored\ntest x ... ok\n")
        for other_log in (less, failed):
            assert any("executed tests" in p for p in compare(
                table, [table], [log], [other_log], singles[0], singles)), other_log
        # The sharded run's logs are read together: a test in either part counts once.
        part1 = write(d, "p1", "test a::b ... ok\n")
        part2 = write(d, "p2", "test a::c ... ignored\ntest x ... ok\n")
        assert compare(table, [table], [part1, part2], [log], singles[0], singles) == []
        # A single job's two logs, comma-separated, are read as one.
        assert compare(table, [table], [log], [f"{part1},{part2}"], singles[0], singles) == []
        # Another thread's log line glued to the outcome still counts the test.
        glued = write(d, "l4", "test a::b ... ok2026-11-04T02:58:24Z  INFO x\n"
                               "test a::c ... ignored\ntest x ... ok\n")
        assert compare(table, [table], [log], [glued], singles[0], singles) == []
    print("compare_coverage self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--table", required=True)
    p.add_argument("--table-single", nargs="+", required=True)
    p.add_argument("--log", nargs="+", required=True)
    p.add_argument("--log-single", nargs="+", required=True)
    p.add_argument("--lcov", required=True)
    p.add_argument("--lcov-single", nargs="+", required=True)
    a = p.parse_args(argv[1:])
    problems = compare(a.table, a.table_single, a.log, a.log_single, a.lcov, a.lcov_single)
    for problem in problems:
        print(f"DIFF {problem}")
    print(f"compare_coverage: {'PASS' if not problems else 'FAIL'} "
          f"({len(a.lcov_single)} single runs)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
