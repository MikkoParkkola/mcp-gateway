#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Compare a sharded coverage grade with single-job grades of the same commit.

The sharded pipeline may replace the single job only when, on the same commit:

- the per-function grade tables (critical_function_coverage.py output) are
  identical, the sharded one against every single-job one;
- the executed tests are identical: each (binary, test, outcome) row of the
  parts' tests.tsv files (coverage_shards.py writes them from libtest's own
  listing, reconciled with the run), as a multiset, against each single job's;
- every line is in band: covered by the sharded run when every single run
  covers it, and not covered when no single run does. Two single runs differ
  on lines that timing decides (a branch reached once or twice), so a line
  covered by some single runs and not others may go either way.

  compare_coverage.py --table SHARDED_TABLE --table-single T1 [T2 ...]
                      --tests SHARDED_TSV [...] --tests-single S1 [...]
                      --lcov SHARDED_LCOV --lcov-single C1 C2 C3
  compare_coverage.py --self-test

Each `--tests-single` is one single job's tests.tsv files, comma-separated
(its SDK part and its main part); the sharded run's files are read together. Exit 0 when everything holds, 1 with every
difference listed.
"""
from __future__ import annotations

import argparse
import collections
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "release"))
from critical_path_coverage import relative  # noqa: E402  (the grader's own path rule)


SINGLES = 3


def tests(paths: list[str]) -> collections.Counter:
    """Each (binary, test, outcome) row of the tests.tsv files, counted."""
    found: collections.Counter = collections.Counter()
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                binary, name, outcome = line.rstrip("\n").split("\t")
                found[(binary, name, outcome)] += 1
    return found


def lines(path: str) -> dict[tuple[str, int], int]:
    """Hits per (file, line) of an lcov report, summed over repeated records.
    Paths are taken relative to the checkout so two runners' reports match."""
    hits: dict[tuple[str, int], int] = {}
    current = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("SF:"):
                current = relative(line[3:].strip())
            elif line.startswith("DA:") and current is not None:
                number, count = line[3:].split(",")[:2]
                key = (current, int(number))
                hits[key] = hits.get(key, 0) + int(count)
    return hits


def compare(table: str, singles_tables: list[str], ran_tsv: list[str], single_tsv: list[str],
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
    ran = tests(ran_tsv)
    for other in single_tsv:
        # One single job's tests.tsv files, comma-separated (its SDK part and its main part).
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
        log = write(d, "l", "lib\ta::b\tok\nlib\ta::c\tignored\nt\tx\tok\n")
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
        # A test that ran in one pipeline and not the other, with another outcome,
        # or under another binary.
        less = write(d, "l2", "lib\ta::b\tok\nlib\ta::c\tignored\n")
        failed = write(d, "l3", "lib\ta::b\tFAILED\nlib\ta::c\tignored\nt\tx\tok\n")
        moved = write(d, "l5", "lib\ta::b\tok\nlib\ta::c\tignored\nu\tx\tok\n")
        for other_log in (less, failed, moved):
            assert any("executed tests" in p for p in compare(
                table, [table], [log], [other_log], singles[0], singles)), other_log
        # The sharded run's files are read together: a test in either part counts once.
        part1 = write(d, "p1", "lib\ta::b\tok\n")
        part2 = write(d, "p2", "lib\ta::c\tignored\nt\tx\tok\n")
        assert compare(table, [table], [part1, part2], [log], singles[0], singles) == []
        # A single job's two files, comma-separated, are read as one.
        assert compare(table, [table], [log], [f"{part1},{part2}"], singles[0], singles) == []
        # A test listed twice (the SDK binary rerun whole) must be twice on both sides.
        twice = write(d, "l6", "lib\ta::b\tok\nlib\ta::b\tok\nlib\ta::c\tignored\nt\tx\tok\n")
        assert any("executed tests" in p for p in compare(
            table, [table], [log], [twice], singles[0], singles))
        # The command line refuses anything but three single runs of each kind.
        args = ["--table", table, "--tests", log, "--lcov", singles[0]]
        three = ["--table-single", table, table, table, "--tests-single", log, log, log,
                 "--lcov-single", *singles]
        assert main(["x", *args, *three]) == 0
        assert main(["x", *args, *three[:-1]]) == 2, "two lcov runs"
        one_tests = ["--table-single", table, table, table, "--tests-single", log,
                     "--lcov-single", *singles]
        assert main(["x", *args, *one_tests]) == 2, "one tests file"
    print("compare_coverage self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--table", required=True)
    p.add_argument("--table-single", nargs="+", required=True)
    p.add_argument("--tests", nargs="+", required=True)
    p.add_argument("--tests-single", nargs="+", required=True)
    p.add_argument("--lcov", required=True)
    p.add_argument("--lcov-single", nargs="+", required=True)
    a = p.parse_args(argv[1:])
    # The band is defined by three single runs of the same commit; fewer would
    # widen nothing and pass as the full comparison.
    counts = (len(a.table_single), len(a.tests_single), len(a.lcov_single))
    if counts != (SINGLES, SINGLES, SINGLES):
        print(f"compare_coverage: need {SINGLES} single runs each of --table-single, "
              f"--tests-single and --lcov-single, got {counts}")
        return 2
    problems = compare(a.table, a.table_single, a.tests, a.tests_single, a.lcov, a.lcov_single)
    for problem in problems:
        print(f"DIFF {problem}")
    print(f"compare_coverage: {'PASS' if not problems else 'FAIL'} "
          f"({len(a.lcov_single)} single runs)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
