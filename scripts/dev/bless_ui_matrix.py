#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Write the per-route fragments in src/gateway/router/ui_access_matrix.d/ from the matrix test's own table.

    scripts/dev/bless_ui_matrix.py [--allow-removed ROUTE]...   run the test on Spark, then write
    scripts/dev/bless_ui_matrix.py --from-log LOG [...]         use a log you already have

The test (`ui_api_access_matrix_is_preserved`) prints every fragment as a block
(`# file: ui_access_matrix.d/<slug>.tsv`, then its `#@` attribute lines and its
rows) between `---- BEGIN MATRIX ----` and `---- END MATRIX ----`, then `cells=N`,
when the table moved. This script writes each block to its fragment and prints,
per route, how many cells were added, removed and changed, so a pull request is
reviewed as "route X: +210" instead of as pasted lines.

It refuses, exit 1 with every file untouched, when the log has no complete table
(a compile error, another panic, a truncated block, a row without 5 fields, a
duplicate key, a block for a file that is not a fragment, a count that differs
from `cells=N`), and when a route in the current fragments lost cells, unless that
exact route is named with `--allow-removed`. The test runs with all features:
without `cost-governance` the costs cells are left out and the table would come
out short.
"""

from __future__ import annotations

import argparse
import collections
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRAGMENTS = ROOT / "src/gateway/router/ui_access_matrix.d"
TEST = "gateway::router::ui_access_matrix_tests::ui_api_access_matrix_is_preserved"
BEGIN, END = "---- BEGIN MATRIX ----", "---- END MATRIX ----"
FILE_MARK = "# file: ui_access_matrix.d/"


class Refused(Exception):
    """The log cannot be blessed; the message says why."""


def run_test() -> tuple[int, str]:
    """Runs the matrix test on Spark through the slot queue; returns (exit code, log)."""
    owner = os.environ.get("BLESS_OWNER") or os.environ.get("USER", "lane")
    cmd = ["spark-slot", "run", "short", owner, "bless-ui-matrix", "--", "spark-cargo", "test",
           "--lib", "--all-features", "--", TEST, "--exact"]
    with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as log:
        rc = subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False).returncode
        print(f"bless-ui-matrix: test log at {log.name}", file=sys.stderr)
    return rc, Path(log.name).read_text(encoding="utf-8", errors="replace")


def rows_of(lines: list[str]) -> list[str]:
    return [line for line in lines if line and not line.startswith("#")]


def extract(log: str, fragments: Path = FRAGMENTS) -> dict[str, list[str]]:
    """The computed fragments in `log`, as file name -> lines; raises Refused unless complete."""
    lines = log.splitlines()
    if lines.count(BEGIN) != 1 or lines.count(END) != 1:
        raise Refused("the log holds no complete computed table (did the test compile and reach the matrix assertion?)")
    start, end = lines.index(BEGIN), lines.index(END)
    after = lines[end + 1] if end + 1 < len(lines) else ""
    if not after.startswith("cells="):
        raise Refused("the table is not followed by its cells=N count")
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in lines[start + 1:end]:
        if line.startswith(FILE_MARK):
            name = line.removeprefix(FILE_MARK)
            if not name.endswith(".tsv") or "/" in name or name.startswith("."):
                raise Refused(f"a block names a file that is not a fragment: {line!r}")
            if name in blocks:
                raise Refused(f"a fragment is listed twice: {name}")
            current = blocks.setdefault(name, [])
        elif current is None:
            raise Refused(f"a line comes before any '# file:' marker: {line!r}")
        else:
            current.append(line)
    seen: set[str] = set()
    total = 0
    for name, block in blocks.items():
        if not (fragments / name).exists():
            raise Refused(f"the table has a block for {name}, which is not a stored fragment")
        for line in rows_of(block):
            fields = line.split("\t")
            if len(fields) != 5:
                raise Refused(f"{name}: a line has {len(fields)} fields, not 5: {line!r}")
            key = line.rsplit("\t", 1)[0]
            if key in seen:
                raise Refused(f"a cell is listed twice: {key}")
            seen.add(key)
            total += 1
    if int(after.removeprefix("cells=")) != total:
        raise Refused(f"the table has {total} rows but the test computed {after}")
    return blocks


def read_fragments(fragments: Path) -> dict[str, str]:
    table = {}
    for path in sorted(fragments.glob("*.tsv")):
        for line in rows_of(path.read_text(encoding="utf-8").splitlines()):
            key, answer = line.rsplit("\t", 1)
            table[key] = answer
    return table


def table_of(blocks: dict[str, list[str]]) -> dict[str, str]:
    table = {}
    for block in blocks.values():
        for line in rows_of(block):
            key, answer = line.rsplit("\t", 1)
            table[key] = answer
    return table


def route(key: str) -> str:
    return key.split("\t", 1)[0]


def summary(old: dict[str, str], new: dict[str, str]) -> dict[str, collections.Counter]:
    per = collections.defaultdict(collections.Counter)
    for key in new.keys() - old.keys():
        per[route(key)]["added"] += 1
    for key in old.keys() - new.keys():
        per[route(key)]["removed"] += 1
    for key in old.keys() & new.keys():
        if old[key] != new[key]:
            per[route(key)]["changed"] += 1
    return per


def check_removals(old: dict[str, str], new: dict[str, str], allowed: set[str]) -> None:
    lost = sorted({route(key) for key in old.keys() - new.keys()} - allowed)
    if lost:
        raise Refused("these routes lost cells; name each deliberate removal with --allow-removed ROUTE: " + ", ".join(lost))


def bless(log: str, rc: int, fragments: Path, allowed: set[str]) -> str:
    """Writes the fragments from `log`; returns what it did. Raises Refused instead of writing a wrong one."""
    if rc == 0 and "1 passed" in log:
        return "matrix unchanged"
    if rc == 65:
        raise Refused("spark-cargo exit 65: the test filter matched nothing or the run was incomplete")
    blocks = extract(log, fragments)
    new = table_of(blocks)
    old = read_fragments(fragments)
    check_removals(old, new, allowed)
    staged = []
    for name, block in blocks.items():
        target = fragments / name
        tmp = target.with_suffix(".tsv.tmp")
        tmp.write_text("\n".join(block) + "\n", encoding="utf-8")
        staged.append((tmp, target))
    for tmp, target in staged:
        tmp.replace(target)
    lines = [f"  {r}: " + ", ".join(f"{n} {kind}" for kind, n in sorted(c.items()))
             for r, c in sorted(summary(old, new).items())]
    return f"wrote {len(new)} cells to {len(blocks)} fragments\n" + "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--allow-removed", action="append", default=[], metavar="ROUTE")
    parser.add_argument("--from-log", type=Path)
    args = parser.parse_args(argv)
    if args.from_log:
        log = args.from_log.read_text(encoding="utf-8", errors="replace")
        rc = 0 if "test result: ok. 1 passed" in log else 1
    else:
        rc, log = run_test()
    try:
        print(bless(log, rc, FRAGMENTS, set(args.allow_removed)))
    except Refused as why:
        print(f"bless-ui-matrix: refused, no fragment touched: {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
